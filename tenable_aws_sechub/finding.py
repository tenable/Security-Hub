"""
The findings module handles transforming a TVM vulnerability finding into an
AWS Security Hub finding.
"""

from typing import Dict

import arrow
from restfly.utils import dict_clean, dict_flatten, trunc

SEV_MAP = {0: 0, 1: 3, 2: 5, 3: 7, 4: 10}
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
    account_id: str
    start_date: str

    def __init__(self, region: str, account_id: str):
        self.region = region
        self.account_id = account_id
        self.start_date = arrow.now().isoformat()

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
            'asset.aws_region',
            'asset.aws_ec2_instance_id',
            'asset.aws_owner_id',
            'asset.aws_ec2_instance_type',
            'asset.aws_ec2_instance_ami_id',
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

        # Get the base score of the finding.  Amazon prefers that we use the
        # CVSS base scores and fall back to our own severity rating only if
        # necessary.  We start with the CVSSv3 score, then fall back to v2,
        # and lastly fall back to the severity_default_id.
        # FIXME: I don't really like how this nested fallback looks, and I feel
        #        there has to be a cleaner way to implement.
        base_score = vuln.get(
            'plugin.cvss3_base_score',
            vuln.get(
                'plugin.cvss_base_score', SEV_MAP[vuln.get('severity_default_id', 0)]
            ),
        )

        finding = {
            'SchemaVersion': '2018-10-08',
            'FirstObservedAt': vuln['first_found'],
            'LastObservedAt': vuln['last_found'],
            'ProductArn': (
                f'arn:aws:securityhub:{self.region}::product/tenable/vulnerability-management'
            ),
            'AwsAccountId': self.account_id,
            'GeneratorId': f'tenable-plugin-{vuln["plugin.id"]}',
            'Id': (
                f'{vuln["asset.aws_region"]}/'
                f'{vuln["asset.aws_ec2_instance_id"]}/'
                f'{vuln["plugin.id"]}'
            ),
            'CreatedAt': self.start_date,
            'UpdatedAt': self.start_date,
            'Types': ['Software and Configuration Checks/Vulnerabilities/CVE'],
            'Severity': {
                'Product': base_score,
                # AWS' scoring system works differently than Tenable's.  They
                # use a
                'Normalized': int(base_score * 4),
                'Label': vuln['plugin.risk_factor'].upper(),
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
                        f'{vuln["asset.aws_region"]}:'
                        f'{vuln["asset.aws_owner_id"]}:'
                        'instance:'
                        f'{vuln["asset.aws_ec2_instance_id"]}'
                    ),
                    'Region': vuln['asset.aws_region'],
                    'Details': {
                        'AwsEc2Instance': {
                            'Type': vuln['asset.aws_ec2_instance_type'],
                            'ImageId': vuln['asset.aws_ec2_instance_ami_id'],
                            'IpV4Addresses': vuln['asset.ipv4s']
                            if vuln.get('asset.ipv4s')
                            else None,
                            'IpV6Addresses': vuln['asset.ipv6s']
                            if vuln.get('asset.ipv6s')
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
                    'Text': trunc(vuln['plugin.solution'], 512),
                    'Url': vuln.get('plugin.see_also')[0]
                    if vuln.get('plugin.see_also')
                    else None,
                }
            },
            'RecordState': STATE_MAP[vuln['state']],
        }
        return dict_clean(finding)
