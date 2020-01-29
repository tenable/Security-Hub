import pytest, os
from tenable.errors import *
from tenable.io import TenableIO
from sechubingest import SecurityHubIngester

@pytest.fixture
def asset():
    return {'agent_names': [],
        'agent_uuid': '6e81459f7af24ef49fc5cd53a6930000',
        'aws_availability_zone': 'us-east-1a',
        'aws_ec2_instance_ami_id': 'ami-daf89000',
        'aws_ec2_instance_group_name': None,
        'aws_ec2_instance_id': 'i-00f9e618482900000',
        'aws_ec2_instance_state_name': None,
        'aws_ec2_instance_type': 't2.medium',
        'aws_ec2_name': None,
        'aws_ec2_product_code': None,
        'aws_owner_id': '600832220000',
        'aws_region': 'us-east-1',
        'aws_subnet_id': 'subnet-e68e0000',
        'aws_vpc_id': 'vpc-10fa0000',
        'azure_resource_id': None,
        'azure_vm_id': None,
        'bios_uuid': None,
        'created_at': '2017-12-12T17:51:37.522Z',
        'deleted_at': None,
        'deleted_by': None,
        'first_scan_time': None,
        'first_seen': '2017-12-12T17:51:37.464Z',
        'fqdns': ['ip-10-10-1-58.ec2.internal'],
        'has_agent': False,
        'has_plugin_results': None,
        'hostnames': ['ip-10-10-1-58.ec2.internal'],
        'id': '9cd360e8-e213-414d-9484-000000000000',
        'ipv4s': ['10.10.1.58'],
        'ipv6s': [],
        'last_authenticated_scan_date': None,
        'last_licensed_scan_date': None,
        'last_scan_time': None,
        'last_seen': '2017-12-12T18:21:52.589Z',
        'mac_addresses': ['12:26:9B:BB:CB:FE'],
        'manufacturer_tpm_ids': [],
        'mcafee_epo_agent_guid': None,
        'mcafee_epo_guid': None,
        'netbios_names': ['ip-10-10-1-73'],
        'network_id': None,
        'network_interfaces': [],
        'operating_systems': ['Linux'],
        'qualys_asset_ids': [],
        'qualys_host_ids': [],
        'servicenow_sysid': None,
        'sources': [{'first_seen': '2017-12-12T17:51:37.464Z',
                    'last_seen': '2017-12-12T18:21:52.589Z',
                    'name': 'AWS'}],
        'ssh_fingerprints': [],
        'symantec_ep_hardware_keys': [],
        'system_types': ['x86_64', 'aws-ec2-instance'],
        'tags': [],
        'terminated_at': None,
        'terminated_by': None,
        'updated_at': '2018-11-14T06:59:31.175Z'
    }

@pytest.fixture
def vulnerability():
    return {
        'asset': {
            'agent_uuid': '6e81459f7af24ef49fc5cd53a6930000',
            'bios_uuid': 'EC2A0F13-1D91-2337-3367-ED6E275A90000',
            'device_type': 'general-purpose',
            'fqdn': 'ip-10-10-1-58.ec2.internal',
            'hostname': 'ip-10-10-1-58.ec2.internal',
            'ipv4': '10.10.1.58',
            'last_authenticated_results': '2018-12-14T12:03:00Z',
            'mac_address': '12:26:9B:BB:CB:FE',
            'netbios_name': 'ip-10-10-1-73',
            'operating_system': ['Linux Kernel 3.16.0-4-amd64 on Debian 8.7'],
            'tracked': True,
            'uuid': '9cd360e8-e213-414d-9484-000000000000'
            },
        'first_found': '2018-03-22T13:29:22.070Z',
        'last_found': '2018-12-14T12:07:38.155Z',
        'output': '\n'.join([
            'Remote package installed : cpp-4.9_4.9.2-10',
            'Should be : cpp-4.9_4.9.2-10+deb8u1\n',
            'Remote package installed : gcc-4.9_4.9.2-10',
            'Should be : gcc-4.9_4.9.2-10+deb8u1\n',
            'Remote package installed : gcc-4.9-base_4.9.2-10',
            'Should be : gcc-4.9-base_4.9.2-10+deb8u1\n',
            'Remote package installed : libasan1_4.9.2-10',
            'Should be : libasan1_4.9.2-10+deb8u1\n',
            'Remote package installed : libatomic1_4.9.2-10',
            'Should be : libatomic1_4.9.2-10+deb8u1\n',
            'Remote package installed : libcilkrts5_4.9.2-10',
            'Should be : libcilkrts5_4.9.2-10+deb8u1\n',
            'Remote package installed : libgcc-4.9-dev_4.9.2-10',
            'Should be : libgcc-4.9-dev_4.9.2-10+deb8u1\n',
            'Remote package installed : libgomp1_4.9.2-10',
            'Should be : libgomp1_4.9.2-10+deb8u1\n',
            'Remote package installed : libitm1_4.9.2-10',
            'Should be : libitm1_4.9.2-10+deb8u1\n',
            'Remote package installed : liblsan0_4.9.2-10',
            'Should be : liblsan0_4.9.2-10+deb8u1\n',
            'Remote package installed : libquadmath0_4.9.2-10',
            'Should be : libquadmath0_4.9.2-10+deb8u1\n',
            'Remote package installed : libtsan0_4.9.2-10',
            'Should be : libtsan0_4.9.2-10+deb8u1\n',
            'Remote package installed : libubsan0_4.9.2-10',
            'Should be : libubsan0_4.9.2-10+deb8u1\n']),
        'plugin': {
            'cpe': [
                'p-cpe:/a:debian:debian_linux:gcc-4.9',
                'cpe:/o:debian:debian_linux:8.0'],
            'description': ' '.join([
                'This update doesn\'t fix a vulnerability in GCC',
                'itself, but instead\n',
                'provides support for building retpoline-enabled ',
                'Linux kernel updates.']),
            'family': 'Debian Local Security Checks',
            'family_id': 3,
            'has_patch': True,
            'id': 106875,
            'modification_date': '2018-11-13T00:00:00Z',
            'name': 'Debian DSA-4117-1 : gcc-4.9 - security update',
            'patch_publication_date': '2018-02-17T00:00:00Z',
            'publication_date': '2018-02-20T00:00:00Z',
            'risk_factor': 'High',
            'see_also': [
                'https://security-tracker.debian.org/tracker/source-package/gcc-4.9',
                'https://packages.debian.org/source/jessie/gcc-4.9',
                'https://www.debian.org/security/2018/dsa-4117'
            ],    
            'solution': ' '.join([
                'Upgrade the gcc-4.9 packages.\n\n',
                'For the oldstable distribution (jessie), this problem ',
                'has been fixed in version 4.9.2-10+deb8u1.']),
            'synopsis': 'The remote Debian host is missing a security-related update.',
            'type': 'local',
            'version': '3.3',
            'xrefs': [{'id': '4117', 'type': 'DSA'}]},
        'port': {'port': 0, 'protocol': 'TCP'},
        'scan': {
            'completed_at': '2018-12-14T12:07:38.155Z',
            'schedule_uuid': 'template-b717964c-4bf0-d629-7d8b-86403fead6afd63b62f2944511f8',
            'started_at': '2018-12-14T12:01:00.129Z',
            'uuid': '417fbf84-9725-43ea-b878-81ab1a90de03'
        },
        'severity': 'high',
        'severity_default_id': 3,
        'severity_id': 3,
        'severity_modification_type': 'NONE',
        'state': 'OPEN'}

@pytest.mark.vcr()
@pytest.fixture
def sechub():
    return SecurityHubIngester(
        region='us-east-1',
        account_id='600832220000',
        tio=TenableIO(
            'TIO_TEST_ACCESS_KEY',
            'TIO_TEST_SECRET_KEY'),
        aws_access_id='AWS_ACCESS_ID',
        aws_secret_key='AWS_SECRET_KEY'
    )

def test_asset_trimming(sechub, asset):
    trimmed = sechub._trim_asset(asset)
    assert isinstance(trimmed, dict)
    assert trimmed['aws_availability_zone'] == 'us-east-1a'
    assert trimmed['aws_ec2_instance_ami_id'] == 'ami-daf89000'
    assert trimmed['aws_ec2_instance_group_name'] == None
    assert trimmed['aws_ec2_instance_id'] == 'i-00f9e618482900000'
    assert trimmed['aws_ec2_instance_state_name'] == None
    assert trimmed['aws_ec2_instance_type'] == 't2.medium'
    assert trimmed['aws_ec2_name'] == None
    assert trimmed['aws_ec2_product_code'] == None
    assert trimmed['aws_owner_id'] == '600832220000'
    assert trimmed['aws_region'] == 'us-east-1'
    assert trimmed['aws_subnet_id'] == 'subnet-e68e0000'
    assert trimmed['aws_vpc_id'] == 'vpc-10fa0000'
    assert trimmed['ipv4s'] == ['10.10.1.58']
    assert trimmed['ipv6s'] == []
    assert 'has_agent' not in trimmed
    assert 'servicenow_sysid' not in trimmed

def test_transform_finding(sechub, asset, vulnerability):
    sechub._region = 'us-east-1'
    sechub._account_id = 'abcdef'
    sechub._assets = {asset.get('id'): sechub._trim_asset(asset)}
    f = sechub._transform_finding(vulnerability)
    assert f['SchemaVersion'] == '2018-10-08'
    assert f['FirstObservedAt'] == '2018-03-22T13:29:22.070Z'
    assert f['LastObservedAt'] == '2018-12-14T12:07:38.155Z'
    assert f['ProductArn'] == 'arn:aws:securityhub:us-east-1:422820575223:product/tenable/tenable-io'
    assert f['AwsAccountId'] == '600832220000'
    assert f['GeneratorId'] == 'tenable-plugin-106875'
    assert f['Id'] == 'us-east-1/i-00f9e618482900000/106875'
    assert f['Types'] == ['Software and Configuration Checks/Vulnerabilities/CVE']
    assert f['CreatedAt']
    assert f['UpdatedAt']
    assert f['Severity']['Product'] == 7
    assert f['Severity']['Normalized'] == 28
    assert f['Title'] == 'Debian DSA-4117-1 : gcc-4.9 - security update'
    assert isinstance(f['Description'], str)
    assert f['Resources'][0]['Type'] == 'AwsEc2Instance'
    assert f['Resources'][0]['Id'] == 'arn:aws:ec2:us-east-1:600832220000:instance:i-00f9e618482900000'
    assert f['Resources'][0]['Region'] == 'us-east-1'
    assert f['Resources'][0]['Details']['AwsEc2Instance']['Type'] == 't2.medium'
    assert f['Resources'][0]['Details']['AwsEc2Instance']['ImageId'] == 'ami-daf89000'
    assert f['Resources'][0]['Details']['AwsEc2Instance']['IpV4Addresses'] == ['10.10.1.58']
    assert 'IpV6Addresses' not in f['Resources'][0]['Details']['AwsEc2Instance']
    assert f['ProductFields']['CVE'] == ''
    assert f['ProductFields']['Plugin Family'] == 'Debian Local Security Checks'
    assert f['ProductFields']['Type'] == 'local'
    assert isinstance(f['Remediation']['Recommendation']['Text'], str)
    assert f['Remediation']['Recommendation']['Url'] == 'https://security-tracker.debian.org/tracker/source-package/gcc-4.9'
    assert f['RecordState'] == 'ACTIVE'

    vulnerability['plugin']['cvss_base_score'] = 6.2
    m = sechub._transform_finding(vulnerability)
    assert m['Severity']['Product'] == 6.2
    assert m['Severity']['Normalized'] == 24
