'''
MIT License

Copyright (c) 2018 Tenable Network Security, Inc.

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


import boto3
import time
import requests
import json
import datetime


# Enter your 12-digit AWS Account ID and AWS region for SecurityHub
# https://docs.aws.amazon.com/IAM/latest/UserGuide/console_account-alias.html#FindingYourAWSId
AWS_ACCOUNT_ID = '<YOUR_ACCOUNT_ID>'


# Enter your AWS region for SecurityHub
# https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.RegionsAndAvailabilityZones.html
AWS_REGION = '<YOUR_AWS_REGION>'


# Enter your Tenable.io Access Key And Secret Key below.
# These are generated from the "API Keys" tab under the "My Account" page.
# https://cloud.tenable.com/api#/authorization
ACCESS_KEY = '<YOUR_ACCESS_KEY>'
SECRET_KEY = '<YOUR_SECRET_KEY>'


# Script settings
TENABLE_IO_SITE_ID = 'https://cloud.tenable.com'
TENABLE_PLUGINS_URL = 'https://www.tenable.com/plugins/nessus/'
BATCH_SIZE = 100
DATE_RANGE = str(30)
GENERATOR_ID = 'tenable-plugin-'
HEADERS = {
    'X-ApiKeys': 'accessKey=' + ACCESS_KEY + '; secretKey=' + SECRET_KEY
}


# Define endpoints used for looking up asset and vulnerability information
def BASE_URL (url):
    return TENABLE_IO_SITE_ID + '/workbenches/assets' + url

def ASSETS_URL ():
    return BASE_URL('?date_range=' + DATE_RANGE + '&filter.0.quality=set-has&filter.0.filter=sources&filter.0.value=AWS&filter.search_type=and')

def ASSET_URL (asset_id):
    return BASE_URL('/' + asset_id + '/info?date_range=' + DATE_RANGE)

def VULNS_URL (asset_id):
    return BASE_URL('/' + asset_id + '/vulnerabilities?date_range=' + DATE_RANGE)

def PLUGIN_URL (asset_id, plugin_id):
    return BASE_URL('/' + asset_id + '/vulnerabilities/' + plugin_id + '/info?date_range=' + DATE_RANGE)


# Convert CVSS to SecurityHub severity
def normalize_severity (severity):
    if severity == 1:
        return 39
    elif severity == 2:
        return 69
    elif severity == 3:
        return 89
    else:
        return 100


# Generate a finding from an asset vulnerability
def generate_finding (instance_id, region, asset, plugin_id, plugin_info, plugin_cves):
    # Create timestamps for created/updated properties
    now = datetime.datetime.utcnow()
    now = now.strftime('%Y-%m-%dT%H:%M:%S') + now.strftime('.%f')[:4] + 'Z'

    # Get plugin severity, title, and description for finding
    product_severity = plugin_info['plugin_details']['severity']
    title = plugin_info['plugin_details']['name']
    description = plugin_info['description']

    # Finding 'Title' has maxlen; we truncate plugin title here
    if len(title) > 256:
        title = title[0:253] + '...'

    # Finding 'Description' has maxlen; we truncate plugin desc here
    if len(description) > 1024:
        description = description[0:1021] + '...'

    finding = {
        'SchemaVersion': '2018-10-08',
        'ProductArn': 'arn:aws:securityhub:' + AWS_REGION + ':422820575223:product/tenable/tenable-io',
        'AwsAccountId': AWS_ACCOUNT_ID,
        'Id': region + '/' + instance_id + '/' + plugin_id,
        'GeneratorId': GENERATOR_ID + plugin_id,
        'Types': ['Software and Configuration Checks/Vulnerabilities/CVE'],
        'CreatedAt': now,
        'UpdatedAt': now,
        "Severity": {
            "Normalized": normalize_severity(product_severity)
        },
        'Title': title,
        'Description': description,
        'Resources': [{
            'Type': 'AwsEc2Instance',
            'Id': 'arn:aws:ec2:' + region + ':' + AWS_ACCOUNT_ID + ':instance:' + instance_id,
            'Region': region,
            'Details': {
                'AwsEc2Instance': {
                }
            }
        }],
        'ProductFields': {
            'CVE': ', '.join(plugin_cves),
            'Plugin Family': plugin_info['plugin_details']['family'],
            'Type': plugin_info['plugin_details']['type']
        },
        'SourceUrl': TENABLE_PLUGINS_URL + plugin_id,
        'RecordState': 'ACTIVE'
    }

    # Check for CVSS score and map to SecurityHub severity
    if 'risk_information' in plugin_info:
        if 'cvss_base_score' in plugin_info['risk_information']:
            cvss = plugin_info['risk_information']['cvss_base_score']

            if cvss != None:
                finding['Severity']['Product'] = float(cvss)
                finding['Severity']['Normalized'] = int(cvss.replace('.', ''))

    # Check for asset discovery data and add as attributes
    if 'discovery' in plugin_info:
        discovery = plugin_info['discovery']

        if 'seen_first' in discovery:
            finding['FirstObservedAt'] = discovery['seen_first']

        if 'seen_last' in discovery:
            finding['LastObservedAt'] = discovery['seen_last']

    # Check for plugin solution and add it to finding 'Remediations'
    if 'solution' in plugin_info:
        finding['Remediation'] = {
            'Recommendation': {
                'Text': plugin_info['solution'],
            }
        }

    # Get available AWS Instance properties and add to finding
    details = finding['Resources'][0]['Details']['AwsEc2Instance']

    if 'aws_ec2_instance_type' in asset:
        details['Type'] = asset['aws_ec2_instance_type'][0]

    if 'aws_ec2_instance_ami_id' in asset:
        details['ImageId'] = asset['aws_ec2_instance_ami_id'][0]

    if 'ipv4' in asset:
        details['IpV4Addresses'] = asset['ipv4']

    if 'ipv6' in asset:
        details['IpV6Addresses'] = asset['ipv6']

    return finding


def get_assets ():
    ret = []

    # Get list of assets identified as being AWS instances
    resp = requests.get(ASSETS_URL(), headers=HEADERS)

    # If connection error, exit the script
    if resp.status_code != 200:
        print('(' + str(resp.status_code) + ') Error retrieving assets from Tenable.io')
        quit()

    assets = resp.json()

    # If we found no assets, exit the script
    if 'assets' not in assets or len(assets['assets']) == 0:
        print("No AWS assets found.")
        quit()

    # Process each asset for vulnerabilities
    for asset in assets['assets']:
        # No asset id, skip
        if 'id' not in asset:
            continue

        asset_id = asset['id']

        # Get asset info and confirm necessary attributes are present
        resp = requests.get(ASSET_URL(asset_id), headers=HEADERS)

        # If connection error, continue
        if resp.status_code != 200:
            print('(' + str(resp.status_code) + ') Error retrieving asset [' + asset_id + '] information from Tenable.io')
            continue

        info = resp.json()

        # No information for asset, skip
        if 'info' not in info:
            continue

        info = info['info']

        # No AWS instanceId for asset, skip
        if 'aws_ec2_instance_id' not in info:
            continue

        instance_id = info['aws_ec2_instance_id'][0]

        # No AWS region for asset, skip
        if 'aws_region' not in info:
            continue

        region = info['aws_region'][0]

        # No vulnerability count found for asset, skip
        if info['counts']['vulnerabilities']['total'] == 0:
            continue

        # Get vulnerability list for asset
        resp = requests.get(VULNS_URL(asset_id), headers=HEADERS)

        # If connection error, continue
        if resp.status_code != 200:
            print('(' + str(resp.status_code) + ') Error retrieving asset [' + asset_id + '] vulnerabilities from Tenable.io')
            continue

        vulns = resp.json()

        # No vulnerabilities for asset, skip
        if 'vulnerabilities' not in vulns:
            continue

        vulns = vulns['vulnerabilities']
        count = 0

        print('Creating findings for instance: ' + instance_id + '...')

        # Lookup details for each vulnerability and map to a finding
        for vuln in vulns:
            # Vulnerability has no severity (i.e. "Info"), skip
            if vuln['severity'] == 0:
                continue

            plugin_id = str(vuln['plugin_id'])
            count += 1

            # Get plugin details for vulnerability
            resp = requests.get(PLUGIN_URL(asset_id, plugin_id), headers=HEADERS)

            # If connection error, continue
            if resp.status_code != 200:
                print('(' + str(resp.status_code) + ') Error retrieving plugin [' + plugin_id + '] details from Tenable.io')
                continue

            plugin = resp.json()

            # No information for plugin, skip
            if 'info' not in plugin:
                continue

            plugin_info = plugin['info']

            # No reference information object for plugin (i.e. home of CVEs), skip
            if 'reference_information' not in plugin_info:
                continue

            plugin_reference_info = plugin_info['reference_information']
            plugin_cves = []

            for reference in plugin_reference_info:
                if reference['name'] == 'cve':
                    plugin_cves = reference['values']
                    continue

            # No real CVEs found in reference information object, skip
            if len(plugin_cves) == 0:
                continue

            ret.append(generate_finding(instance_id, region, info, plugin_id, plugin_info, plugin_cves))

        print('...' + str(count) + ' findings added.')

    print('Total Findings: ' + str(len(ret)))
    return ret


# Create a SecurityHub client
securityhub = boto3.client("securityhub")


# Collect AWS Instance vulnerabilities from Tenable.io
findings = get_assets()


# Prepare findings for SecurityHub by batching into requests of 100 (per SDK)
batches = [[]]
batch = batches[0]


for finding in findings:
    if len(batch) == BATCH_SIZE:
        batches.append([])
        batch = batches[len(batches) - 1]

    batch.append(finding)


# Send findings to SecurityHub
for batch in batches:
    import_response = securityhub.batch_import_findings(Findings=batch)
