"""
Transform module handles connection to both APIs and the mechanics of pushing
the data between them.
"""

import logging
from typing import TYPE_CHECKING, Dict, List

import arrow
import boto3
from restfly.utils import dict_merge
from tenable.io import TenableIO

from .finding import Finding

if TYPE_CHECKING:
    import botocore


class Processor:  # noqa PLR902
    """
    Main transform processor class.
    """

    aws: 'botocore.session.Session'
    tvm: TenableIO
    aws_finding: Finding
    since: int = 0
    batch: List[Dict]
    config: Dict
    batch_size: int = 100
    states: List[str] = ['open', 'reopened', 'fixed']
    sources: List[str] = ['CloudDiscoveryConnector']
    severity: List[str] = ['high', 'critical']
    asset_fields: List[str] = [
        'ipv4s',
        'ipv6s',
        'aws_region',
        'aws_ec2_instance_id',
        'aws_owner_id',
        'aws_ec2_instance_type',
        'aws_ec2_instance_ami_id',
    ]

    def __init__(self, config: Dict):
        self.batch = []
        self.config = config
        self.since = config.get('since', self.since)
        self.batch_size = config.get('upload_batch_size', 100)
        self.states = config.get('states', self.states)
        self.sources = config.get('sources', self.sources)
        self.severity = config.get('severity', self.severity)
        self.aws = boto3.client('securityhub')
        self.tvm = TenableIO(
            access_key=config.get('access_key'),
            secret_key=config.get('secret_key'),
            url=config.get('tvm_url', 'https://cloud.tenable.com'),
        )
        self.aws_finding = Finding(
            region=config.get('aws_region', self.aws.meta.region_name),
            account_id=config['aws_account_id'],
        )
        self._log = logging.getLogger('Tenb2SecHub')

    def get_trimmed_assets(self):
        """
        Retreives the asset metadata and then trims out the fields that we will
        not be needing to merge into the finding data.  We do this in order to
        ensure that we dont eat up any more memory than we need to.

        Returns:
            dict:
                The dictionary of the trimmed assets.
        """
        assets = self.tvm.exports.assets(
            sources=self.sources, updated_at=arrow.utcnow().shift(days=-30).timestamp()
        )
        trims = self.asset_fields
        return {a['id']: {k: v for k, v in a.items() if k in trims} for a in assets}

    def add(self, finding: Dict):
        """
        Adds the finding to the batch queue to be uploaded.  If the batch
        size exceeds the max size, then a batch import will occur as well.
        """
        self.batch.append(finding)
        if len(self.batch) >= self.batch_size:
            self.commit()

    def commit(self):
        """
        Commit the findings into AWS Security Hub.
        """
        self._log.debug(
            (f'Commiting batch of {len(self.batch)} findings to Security Hub')
        )
        self.aws.batch_import_findings(Findings=self.batch)
        self.batch = []

    def ingest(self):
        """
        Perform the finding ingestion into AWS Security Hub.
        """
        # Update the since parameter stored int he configuration to the current
        # timestamp.
        self.config['since'] = int(arrow.now().timestamp())

        # Initiate the vulnerability export and get the trimmed asset data.
        vulns = self.tvm.exports.vulns(
            since=self.since, state=self.states, severity=self.severity
        )
        assets = self.get_trimmed_assets()

        # For each vulnerability finding, we will merge in the associated
        # asset metadata, then feed the merged information into the AWS
        # finding generator.  If we successfully got a finding generated, then
        # add that finding to the batch queue.
        for vuln in vulns:
            asset_obj = assets.get(vuln['asset']['uuid'])
            if not asset_obj:
                self._log.warning(
                    f'Could not collect the asset metadata for {vuln["asset"]["uuid"]} '
                    f'within asset cache.  Not reporting plugin {vuln["plugin"]["id"]}.'
                )
                continue
            vuln['asset'] = dict_merge(vuln['asset'], asset_obj)
            try:
                finding = self.aws_finding.generate(vuln)
                self.add(finding)
            except KeyError as err:
                self._log.warning(
                    (
                        f'Asset {vuln["asset"]["uuid"]} finding '
                        f'{vuln["plugin"]["id"]} failed transformation '
                        f'with error: {err}'
                    )
                )

        # Commit any remaining findings in the queue to AWS.
        self.commit()
