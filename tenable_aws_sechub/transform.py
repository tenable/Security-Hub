"""
Transform module handles connection to both APIs and the mechanics of pushing
the data between them.
"""

import logging
from typing import Any, Dict, List

import arrow
import boto3
from restfly.utils import dict_flatten, dict_merge
from tenable.io import TenableIO

from .finding import Finding


class Cache:
    """
    AWS Cache Profile
    """

    session: 'boto3.session.Session'
    client: 'boto3.session.Session'
    cache: List[Dict]
    region: str
    finding: Finding
    limit: int
    count: int

    def __init__(self, region: str, profile: str, limit: int = 100):
        self.region = region
        self.finding = Finding(region=region)
        self.cache = []
        self.count = 0
        self.limit = limit
        self.session = boto3.session.Session(
            profile_name=profile,
            region_name=region,
        )
        self.client = self.session.client('securityhub')

    def add(self, finding: Dict):
        """
        Adds the finding to the cache to be uploaded.  If the cache exceeds the max
        size limit, then we will automatically push the cache up to SecurityHub.

        Args:
            finding: Merged TVM finding and asset metadata
        """
        transformed = self.finding.generate(finding)
        self.count += 1
        self.cache.append(transformed)
        if len(self.cache) >= self.limit:
            self.commit()

    def commit(self):
        """
        Flushes the cache of findings up to Security Hub.
        """
        if len(self.cache) > 0:
            self.client.batch_import_findings(Findings=self.cache)
            self.cache = []


class Processor:  # noqa PLR902
    """
    Main transform processor class.
    """

    tvm: TenableIO
    aws_finding: Finding
    since: int = 0
    config: Dict
    accounts: Dict[str, str]
    caches: Dict[str, Cache]
    states: List[str] = ['open', 'reopened', 'fixed']
    sources: List[str] = ['CloudDiscoveryConnector']
    severity: List[str] = ['high', 'critical']

    def __init__(self, config: Dict):
        # We will be maintining caches and boto3 sessions for each profile described
        # within the configuration file.  As many accounts can also exist within a
        # singular profile, we will also have an independent dictionary to store the
        # mapping between account and profile.  This will mean that the "add" method
        # will now automatically refuse any account_ids that arent in the mapping and
        # instead throw a warning log message instead.
        self.caches = {}
        self.accounts = {}
        for profile in config.get('aws_profile', []):
            # For each profile defined, we will be creating a new session, client,
            # cache, and build the account to profile linkages.
            self.caches[profile['name']] = Cache(
                region=profile['region'],
                profile=profile['name'],
                limit=config.get('upload_batch_size', 100),
            )
            for account in profile['accounts']:
                self.accounts[str(account)] = profile['name']

        self.config = config
        self.since = config.get('since', self.since)
        self.states = config.get('states', self.states)
        self.sources = config.get('sources', self.sources)
        self.severity = config.get('severity', self.severity)
        self.tvm = TenableIO(
            access_key=config.get('access_key'),
            secret_key=config.get('secret_key'),
            url=config.get('tvm_url', 'https://cloud.tenable.com'),
        )
        self._log = logging.getLogger('Tenb2SecHub')
        self._log.debug(self.caches)
        self._log.debug(self.accounts)

    def get_trimmed_assets(self):
        """
        Retreives the asset metadata and then trims out the fields that we will
        not be needing to merge into the finding data.  We do this in order to
        ensure that we dont eat up any more memory than we need to.

        Returns:
            dict:
                The dictionary of the trimmed assets.
        """
        ts = arrow.utcnow().shift(days=-30).timestamp()
        if ts > self.since:
            ts = self.since

        assets = self.tvm.exports.assets_v2(since=ts)
        trims = [
            'network.ipv4s',
            'network.ipv6s',
            'cloud.aws.region',
            'cloud.aws.ec2_instance_id',
            'cloud.aws.owner_id',
            'cloud.aws.ec2_instance_type',
            'cloud.aws.ec2_instance_ami_id',
        ]
        trimmed = {}
        for asset in assets:
            a = dict_flatten(asset)
            if a.get('cloud.aws.owner_id', None) not in self.accounts:
                self._log.warning(f'Asset {a["id"]} not found in AWS account listing')
                continue
            trimmed[a['id']] = {k: v for k, v in a.items() if k in trims}
            self._log.debug(f'Adding {a["id"]} to {a["cloud.aws.owner_id"]}')
        return trimmed

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
                    f'No asset data for {vuln["asset"]["uuid"]} within asset cache.  '
                    f'Not reporting plugin {vuln["plugin"]["id"]}.'
                )
                continue
            aws_account = asset_obj['cloud.aws.owner_id']
            profile_id = self.accounts.get(aws_account)
            vuln['asset'] = dict_merge(vuln['asset'], asset_obj)
            try:
                self._log.debug(vuln)
                self.caches[profile_id].add(vuln)
            except Exception as err:
                self._log.warning(
                    (
                        f'Asset {vuln["asset"]["uuid"]} finding '
                        f'{vuln["plugin"]["id"]} failed to add '
                        f'with error: {err}'
                    )
                )

        # Commit any remaining findings in the queues to AWS.
        for _, cache in self.caches.items():
            cache.commit()

        for profile, cache in self.caches.items():
            self._log.info(f'Sent {cache.count} events to profile {profile}')
