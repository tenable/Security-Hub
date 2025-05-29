"""
The findings module handles transforming a TVM vulnerability finding into an
AWS Security Hub finding.
"""

import logging
from typing import Dict, List

import arrow
from restfly.utils import dict_clean, dict_flatten, trunc

log = logging.getLogger('sechub.finding')

SEV_MAP = {
    0: [0, 'INFORMATIONAL'],
    1: [10, 'LOW'],
    2: [40, 'MEDIUM'],
    3: [70, 'HIGH'],
    4: [90, 'CRITICAL'],
}

STATE_MAP = {
    'OPEN': 'ACTIVE',
    'NEW': 'ACTIVE',
    'REOPENED': 'ACTIVE',
    'FIXED': 'ARCHIVED',
}


class Finding:
    """
    Security Hub Finding transformer
    """

    region: str
    start_date: str

    def __init__(
        self,
        region: str,
    ):
        self.region = region
        # self.account_id = account_id
        # self.map_to_asset_account = map_to_asset_account
        self.start_date = arrow.now().isoformat()
        # if allowed_accounts:
        #     self.allowed_accounts = allowed_accounts
        # elif map_to_asset_account and not allowed_accounts:
        #     self.allowed_accounts = [account_id]

    def check_required_params(self, vuln: Dict):
        """
        Checks to see if all of the required attributes exist for the finding
        to be generated.  If validation fails, then a KeyError will be raised
        detailing the missing keys or keys with empty data.

        Args:
            vuln (dict): The vuln object to check
        """
        # We only need to specify the asset fields that are required as these
        # fields must never have a NoneType value in them.
        required_attributes = [
            'asset.cloud.aws.region',
            'asset.cloud.aws.ec2_instance_id',
            'asset.cloud.aws.owner_id',
            'asset.cloud.aws.ec2_instance_type',
            'asset.cloud.aws.ec2_instance_ami_id',
        ]
        failed = []
        for attr in required_attributes:
            if vuln.get(attr) is None:
                failed.append(attr)
        if failed:
            raise KeyError(
                (
                    f'The required asset attributes {",".join(failed)}'
                    f' were not set on asset {vuln["asset.uuid"]}'
                )
            )
        # NOTE: Disabled the account checking as we will always be using the account
        #       owner from the asset moving forward.
        #
        # if (
        #     self.allowed_accounts
        #     and vuln.get('asset.aws_owner_id') not in self.allowed_accounts
        #     and self.map_to_asset_account
        # ):
        #     raise KeyError(
        #         f'asset {vuln["asset.aws_owner_id"]}:{vuln["asset.uuid"]} is not within'
        #         ' one of the allowed accounts.'
        #     )

    def generate(self, vuln: Dict) -> Dict:
        """
        Generates an AWS Security Hub finding based on the TVM asset and vuln
        finding that was inputted

        Args:
            vuln (dict): The vuln object from the vuln export

        Returns:
            dict:
                The transformed AWS Sechub finding
        """
        vuln = dict_flatten(vuln)
        self.check_required_params(vuln)
        normalized, label = SEV_MAP[vuln.get('severity_id', 0)]

        finding = {
            'SchemaVersion': '2018-10-08',
            'FirstObservedAt': vuln['first_found'],
            'LastObservedAt': vuln['last_found'],
            'ProductArn': (
                f'arn:aws:securityhub:{self.region}::product/tenable/vulnerability-management'
            ),
            'AwsAccountId': vuln['asset.cloud.aws.owner_id'],
            'GeneratorId': f'tenable-plugin-{vuln["plugin.id"]}',
            'Id': (
                f'{vuln["asset.cloud.aws.region"]}/'
                f'{vuln["asset.cloud.aws.ec2_instance_id"]}/'
                f'{vuln["plugin.id"]}'
            ),
            'CreatedAt': self.start_date,
            'UpdatedAt': self.start_date,
            'Types': ['Software and Configuration Checks/Vulnerabilities/CVE'],
            'Severity': {
                'Label': label,
                'Normalized': normalized,
                'Original': vuln.get('severity', 'info'),
            },
            # Some plugin names run quite long, we will need to truncate to
            # the max string size that AWS supports.
            'Title': trunc(vuln['plugin.name'], 256),
            # The description cannot exceed 1024 characters in size.
            'Description': trunc(vuln['plugin.description'], 1024),
            'Resources': [
                {
                    'Type': 'AwsEc2Instance',
                    'Id': (
                        'arn:aws:ec2:'
                        f'{vuln["asset.cloud.aws.region"]}:'
                        f'{vuln["asset.cloud.aws.owner_id"]}:'
                        'instance:'
                        f'{vuln["asset.cloud.aws.ec2_instance_id"]}'
                    ),
                    'Region': vuln['asset.cloud.aws.region'],
                    'Details': {
                        'AwsEc2Instance': {
                            'Type': vuln['asset.cloud.aws.ec2_instance_type'],
                            'ImageId': vuln['asset.cloud.aws.ec2_instance_ami_id'],
                            'IpV4Addresses': vuln['asset.network.ipv4s']
                            if vuln.get('asset.network.ipv4s')
                            else None,
                            'IpV6Addresses': vuln['asset.network.ipv6s']
                            if vuln.get('asset.network.ipv6s')
                            else None,
                        },
                    },
                }
            ],
            'ProductFields': {
                'CVE': ', '.join(vuln.get('plugin.cve', [])),
                'Plugin Family': vuln['plugin.family'],
                'Type': vuln['plugin.type'],
            },
            # Have to research if we want to continue to construct direct
            # links into the relevant part of the UI.  This may be more
            # complicated with the export workbenches than they were with the
            # legacy workbenches.
            # 'SourceUrl': 'XXXXXXX',
            'Remediation': {
                'Recommendation': {
                    # The solution cannot exceed 1024 characters in length.
                    'Text': trunc(vuln['plugin.solution'], 512)
                    if vuln.get('plugin.solution')
                    else None,
                    'Url': vuln.get('plugin.see_also')[0]
                    if vuln.get('plugin.see_also')
                    else None,
                }
            },
            'RecordState': STATE_MAP[vuln['state']],
        }
        return dict_clean(finding)
