#!/usr/bin/env python
'''
MIT License

Copyright (c) 2019 Tenable Network Security, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''
from tenable.io import TenableIO
from restfly.errors import RestflyException as TenableException
import boto3, arrow, logging, os, json

__version__ = '1.0.2'


def trunc(text, limit):
    '''
    Truncates a string to a given number of characters.  If a string extends
    beyond the limit, then truncate and add an ellipses after the truncation.

    Args:
        text (str): The string to truncate
        limit (int): The maximum limit that the string can be.

    Returns:
        str: The truncated string
    '''
    if len(text) >= limit:
        return '{}...'.format(text[:limit - 4])
    return text


class SecHubError(TenableException):
    pass


class SecurityHubIngester(object):
    '''
    Tenable.io to Amazon Security Hub transformer and ingestion model.

    This model will pull the AWS asset data & vulnerability data from Tenable.io
    and then transform it into a format that Amazon's Security Hub understands.
    The resulting data is then fed into Security Hub for interaction within
    Amazon's infrastructure.

    Args:
        region (str): The AWS Region where Security Hib is located
        account_id (str): The AWS account ID
        tio (TenableIO): The authenticated TenableIO object
        aws_access_id (str, optional): AWS Access Key ID
        aws_secret_key (str, optional): AWS Secret Access Key

    Examples:
        >>> hub = SecurityHubIngester('us-east-1', 'AWS_ACCOUNT_ID', tio)
    '''
    _debug = False
    _aws_client = None
    _sechub = None
    _tio = None
    _log = None

    def __init__(self, region, account_id, tio,
                 aws_access_id=None, aws_secret_key=None):
        # Store the logging facility and store
        self._log = logging.getLogger('{}.{}'.format(
            self.__module__, self.__class__.__name__))

        # Configure and setup the AWS SecurityHub instance and store the
        # requisite fields.
        # NOTE: Commented out for now.  While this will get the regions to
        #       validate against, it requires extra permissions.
        #ec2 = boto3.client('ec2')
        #regions = [r['RegionName'] for r in ec2.describe_regions()['Regions']]
        #if region not in regions:
        #    raise SecHubError('{} is not a valid AWS region.'.format(region))
        self._region = region
        self._account_id = account_id
        self._sechub = boto3.client('securityhub',
            region_name=region,
            aws_access_key_id=aws_access_id,
            aws_secret_access_key=aws_secret_key)

        # Place the TenableIO object into it's new home.
        self._tio = tio

    def _trim_asset(self, asset):
        '''
        Asset data trimmer

        Args:
            asset (dict): The asset to attempt to trim
        '''
        fields = [
            'aws_availability_zone',
            'aws_ec2_instance_ami_id',
            'aws_ec2_instance_group_name',
            'aws_ec2_instance_id',
            'aws_ec2_instance_state_name',
            'aws_ec2_instance_type',
            'aws_ec2_name',
            'aws_ec2_product_code',
            'aws_owner_id',
            'aws_region',
            'aws_subnet_id',
            'aws_vpc_id',
            'azure_resource_id',
            'ipv4s',
            'ipv6s',
        ]
        required = [
            'aws_ec2_instance_id',
            'aws_region',
        ]
        trimmed = dict()

        # populate the trimmed asset.
        for key in asset.keys():
            if key in fields:
                trimmed[key] = asset[key]

        # ensure all of the required fields are in the asset.
        for requirement in required:
            if requirement not in trimmed.keys():
                self._log.debug(
                    'ignoring asset {} as it is missing required field {}'.format(
                        asset['id'], requirement))
                return None
        return trimmed

    def _transform_finding(self, vuln):
        '''
        Transform a finding from the Tenable.io export format into the Amazon
        SecurityHub format.

        Args:
            vuln (dict): The Tenable.io vulnerability finding

        Returns:
            dict: Amazon SecurityHub formatted finding
        '''
        # A severity mapping to convert the 5 point severity scale into a
        # number.  This should only be used if the CVSS scoring fails.
        sevmap = {0: 0, 1: 3, 2: 5, 3: 7, 4: 10}
        state = {
            'OPEN': 'ACTIVE',
            'NEW': 'ACTIVE',
            'REOPENED': 'ACTIVE',
            'FIXED': 'ARCHIVED'
        }

        now = arrow.utcnow()
        asset = self._assets[vuln.get('asset').get('uuid')]

        # Construct the URI that points to the specific vulnerability
        # instance.
        uri = '/'.join([
            'https://cloud.tenable.com/app.html#/dashboards/workbench/assets',
            '{}/vulnerabilities/{}'.format(
                vuln.get('asset').get('uuid'),
                vuln.get('plugin').get('id'))])

        # Build the AwsEc2Instance sub-document
        details = dict()
        if asset.get('aws_ec2_instance_type'):
            details['Type'] = asset.get('aws_ec2_instance_type')
        if asset.get('aws_ec2_instance_ami_id'):
            details['ImageId'] = asset.get('aws_ec2_instance_ami_id')
        if len(asset.get('ipv4s')) > 0:
            details['IpV4Addresses'] = asset.get('ipv4s')
        if len(asset.get('ipv6s')) > 0:
            details['IpV6Addresses'] = asset.get('ipv6s')

        # Build the Remediation.Recommendation sub-document
        remediation = dict()
        if vuln.get('plugin').get('solution'):
            remediation['Text'] = vuln.get('plugin').get('solution')
        if vuln.get('plugin').get('see_also'):
            remediation['Url'] = vuln.get('plugin').get('see_also')[0]

        return {
            'SchemaVersion': '2018-10-08',
            'FirstObservedAt': vuln.get('first_found'),
            'LastObservedAt': vuln.get('last_found'),
            'ProductArn': 'arn:aws:securityhub:{}:{}:{}'.format(
                self._region, self._account_id, 'product/tenable/tenable-io'),
            'AwsAccountId': self._account_id,
            'GeneratorId': 'tenable-plugin-{}'.format(
                vuln.get('plugin').get('id')),
            'Id': '{}/{}/{}'.format(
                asset.get('aws_region'),
                asset.get('aws_ec2_instance_id'),
                vuln.get('plugin').get('id')),
            'Types': ['Software and Configuration Checks/Vulnerabilities/CVE'],
            'CreatedAt': now.isoformat(),
            'UpdatedAt': now.isoformat(),
            'Severity': {
                'Product': vuln.get('plugin').get('cvss_base_score',
                                sevmap[vuln.get('severity_default_id', 0)]),
                'Normalized': int(vuln.get('plugin').get('cvss_base_score',
                                sevmap[vuln.get('severity_default_id', 0)]) * 4),
                'Label': vuln.get('severity').upper(),
            },
            'Title': trunc(vuln.get('plugin').get('name'), 256),
            'Description': trunc(vuln.get('plugin').get('description'), 1024),
            'Resources': [{
                'Type': 'AwsEc2Instance',
                'Id': 'arn:aws:ec2:{}:{}:instance:{}'.format(
                    asset.get('aws_region'),
                    self._account_id,
                    asset.get('aws_ec2_instance_id')),
                'Region': asset.get('aws_region'),
                'Details': {'AwsEc2Instance': details},
            }],
            'ProductFields': {
                'CVE': ', '.join(vuln.get('plugin').get('cve', [])),
                'Plugin Family': vuln.get('plugin').get('family'),
                'Type': vuln.get('plugin').get('type', ''),
            },
            'SourceUrl': uri,
            'Remediation': {'Recommendation': remediation},
            'RecordState': state[vuln['state']]
        }

    def ingest(self, observed_since, batch_size=None, severities=None,
        dump_findings=False):
        '''
        Perform the ingestion

        Args:
            observed_since (int):
                The unix timestamp of the age threshhold.  Only vulnerabilities
                observed since this date will be imported.
            batch_size (int, optional):
                The number of findings to send to Security Hub at a time.  If
                nothing is specified, it will default to 100.
            severities (list, optional):
                The criticalities that should be exported and ingested into AWS.
                If nothing is specified, then the default is low, medium, high,
                and critical.
            dump_findings (bool, optional):
                Should findings be dumped to disk along with being transmitted
                to the AWS SecurityHub API?  If left unspecified, the default
                value is False.
        '''
        if not batch_size:
            batch_size = 100

        if not severities:
            severities = ['low', 'medium', 'high', 'critical']

        # The first thing that we need to do here is pull down all of the asset
        # data from TenableIO that pertains to AWS and trim it down to just the
        # fields that we need.
        self._assets = dict()
        self._log.info('initiating asset collection')
        assets = self._tio.exports.assets(sources=['AWS'],
            updated_at=observed_since)
        for asset in assets:
            trimmed = self._trim_asset(asset)
            if trimmed:
                self._assets[asset['id']] = trimmed
        self._log.info('completed asset collection and discovered {} assets'.format(
            len(self._assets)))

        # If no assets were collected, then there is no reason to process any
        # of the vulnerability data.  Throw a log stating that there isn't
        # anything for us to do and bail.
        if len(self._assets) < 1:
            self._log.info('no assets were collected, refusing to continue ingest')
            return

        # Initiate an export of the vulnerability data.  Each vuln will be sent
        # through the tranformer to generate a finding that fits within the
        # Security Hub format.  From there we will store the transformed vuln
        # within the transforms list, and when the transforms list reaches the
        # batch size, we will push that batch of vulns up into Amazon and reset
        # the transforms list.
        self._log.info('initiating vuln ingest and transformation')
        transforms = list()
        openvulns = self._tio.exports.vulns(last_found=observed_since,
            severity=severities, state=['open', 'reopened'])
        fixedvulns = self._tio.exports.vulns(last_fixed=observed_since,
            severity=severities, state=['fixed'])

        for export in [openvulns, fixedvulns]:
            for vuln in export:
                if vuln.get('asset').get('uuid') in self._assets.keys():
                    finding = self._transform_finding(vuln)
                    if dump_findings:
                        with open('{}-{}.json'.format(
                            vuln.get('asset').get('uuid'),
                            vuln.get('plugin').get('id')), 'w') as jfile:
                            json.dump(finding, jfile)
                    transforms.append(finding)
                if len(transforms) >= batch_size:
                    self._sechub.batch_import_findings(Findings=transforms)
                    transforms = list()
        self._log.info('completed processing {} active and {} fixed vulns'.format(
            openvulns.count, fixedvulns.count))

        # If there are any remaining vulnerabilities in a left-over batch, then
        # we should shoot them into Amazon.
        if len(transforms) > 0:
            self._sechub.batch_import_findings(Findings=transforms)
        self._log.info('drained last batch queue of transformed vulns')


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--tio-access-key',
        dest='tio_access_key',
        help='Tenable.io Access Key',
        default=os.getenv('TIO_ACCESS_KEY'))
    parser.add_argument('--tio-secret-key',
        dest='tio_secret_key',
        help='Tenable.io Secret Key',
        default=os.getenv('TIO_SECRET_KEY'))
    parser.add_argument('--batch-size',
        dest='batch_size',
        help='Size of the batches to populate into Security Hub',
        type=int,
        default=100)
    parser.add_argument('--aws-region',
        dest='aws_region',
        help='AWS region for Security Hub',
        default=os.getenv('AWS_REGION'))
    parser.add_argument('--aws-account-id',
        dest='aws_account_id',
        help='AWS Account ID',
        default=os.getenv('AWS_ACCOUNT_ID'))
    parser.add_argument('--aws-access-id',
        dest='aws_access_id',
        help='AWS Access ID',
        default=os.getenv('AWS_ACCESS_ID'))
    parser.add_argument('--aws-secret-key',
        dest='aws_secret_key',
        help='AWS Secret Key',
        default=os.getenv('AWS_SECRET_KEY'))
    parser.add_argument('--log-level',
        dest='log_level',
        help='Log level: available levels are debug, info, warn, error, crit',
        default=os.getenv('LOG_LEVEL'))
    parser.add_argument('--since',
        dest='observed_since',
        help='The unix timestamp of the age threshold',
        type=int,
        default=os.getenv('OBSERVED_SINCE'))
    parser.add_argument('--severities',
        dest='severities',
        help='What Severities should be ingested? Colon delimited',
        default='critical')
    parser.add_argument('--run-every',
        dest='run_every',
        help='How many hours between recurring imports',
        type=int,
        default=os.getenv('RUN_EVERY'))
    args = parser.parse_args()

    # If no log level is set, then lets set to the default of "warn"
    if not args.log_level:
        args.log_level = 'warn'

    # if no age is set, then lets set the default to 0.
    if not args.observed_since:
        args.observed_since = 0

    # Setup the logging for the output of the script.
    log_levels = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warn': logging.WARNING,
        'error': logging.ERROR,
        'crit': logging.CRITICAL,
    }
    logging.basicConfig(level=log_levels[args.log_level.lower()])

    if (not args.tio_access_key
     or not args.tio_secret_key
     or not args.aws_region
     or not args.aws_account_id):
        # If we hit this statement, then one or more required attributes haven't
        # been set.  In this scenario we should print out to the console what
        # attributes have been set and what attributes have not been so that the
        # user can get the feedback necessary to modify their environment vars
        # or their commandline arguments.
        print('\n'.join(['Not all required attributes have been set.',
            'Tenable.io Access Key: {}'.format('SET' if args.tio_access_key else 'NOT SET'),
            'Tenable.io Secret Key: {}'.format('SET' if args.tio_secret_key else 'NOT SET'),
            'AWS Region: {}'.format('SET' if args.aws_region else 'NOT SET'),
            'AWS Account ID: {}'.format('SET' if args.aws_account_id else 'NOT SET'),
            'AWS Access Key ID: {}'.format('SET' if args.aws_access_id else 'NOT SET'),
            'AWS Secret Access Key: {}'.format('SET' if args.aws_secret_key else 'NOT SET'),
        ]))
    else:
        # Initiate the Tenable.io API model, the Ingester model, and start the
        # ingestion and data transformation.
        tio = TenableIO(args.tio_access_key, args.tio_secret_key,
            vendor='Tenable',
            product='AWSSechub',
            build=__version__)
        hub = SecurityHubIngester(args.aws_region, args.aws_account_id, tio,
            args.aws_access_id, args.aws_secret_key)
        hub.ingest(args.observed_since,
            batch_size=args.batch_size,
            severities=args.severities.split(':'))

        # If we are expected to continually re-run the transformer, then we will
        # need to track the passage of time and run every X hours, where X is
        # defined by the user.
        if args.run_every and args.run_every > 0:
            import time
            while True:
                sleeper = args.run_every * 3600
                last_run = int(time.time())
                logging.info(
                    'Sleeping for {}s before next iteration'.format(sleeper))
                time.sleep(sleeper)
                logging.info(
                    'Initiating ingest with observed_since={}'.format(last_run))
                hub.ingest(last_run, args.batch_size)
