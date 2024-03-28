import pytest
import os
from restfly.utils import dict_flatten, dict_merge

# Setup the dummy AWS environment.
os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
os.environ['AWS_SECURITY_TOKEN'] = 'testing'
os.environ['AWS_SESSION_TOKEN'] = 'testing'
os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'


@pytest.fixture
def asset_local():
    return {
        'id': '01234567-1234-abcd-0987-01234567890a',
        'aws_ec2_instance_ami_id': None,
        'aws_ec2_instance_id': None,
        'aws_owner_id': None,
        'aws_availability_zone': None,
        'aws_region': None,
        'aws_vpc_id': None,
        'aws_ec2_instance_group_name': None,
        'aws_ec2_instance_state_name': None,
        'aws_ec2_instance_type': None,
        'aws_subnet_id': None,
        'aws_ec2_product_code': None,
        'aws_ec2_name': None,
        'ipv4s': ['192.168.0.1', '192.168.0.2'],
        'ipv6s': [],
    }


@pytest.fixture
def asset_aws():
    return {
        'id': '01234567-1234-abcd-0987-01234567890b',
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
        'ipv4s': ['192.168.101.249'],
        'ipv6s': [],
    }


@pytest.fixture
def finding():
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
            'uuid': '01234567-1234-abcd-0987-01234567890b'
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
                ('https://security-tracker.debian.org/'
                 'tracker/source-package/gcc-4.9'),
                'https://packages.debian.org/source/jessie/gcc-4.9',
                'https://www.debian.org/security/2018/dsa-4117'
            ],
            'solution': ' '.join([
                'Upgrade the gcc-4.9 packages.\n\n',
                'For the oldstable distribution (jessie), this problem ',
                'has been fixed in version 4.9.2-10+deb8u1.']),
            'synopsis': ('The remote Debian host is missing '
                         'a security-related update.'
                         ),
            'type': 'local',
            'version': '3.3',
            'xrefs': [{'id': '4117', 'type': 'DSA'}]},
        'port': {'port': 0, 'protocol': 'TCP'},
        'scan': {
            'completed_at': '2018-12-14T12:07:38.155Z',
            'schedule_uuid': ('template-b717964c-4bf0-d629-'
                              '7d8b-86403fead6afd63b62f2944511f8'),
            'started_at': '2018-12-14T12:01:00.129Z',
            'uuid': '417fbf84-9725-43ea-b878-81ab1a90de03'
        },
        'severity': 'high',
        'severity_default_id': 3,
        'severity_id': 3,
        'severity_modification_type': 'NONE',
        'state': 'OPEN'
    }


def composite_finding(asset, finding):
    finding['asset'] = dict_merge(finding['asset'],
                                  asset
                                  )
    finding = dict_flatten(finding)
    finding['asset.uuid'] = finding['asset.id']
    return finding


@pytest.fixture
def finding_local(asset_local, finding):
    return composite_finding(asset_local, finding)


@pytest.fixture
def finding_aws(asset_aws, finding):
    return composite_finding(asset_aws, finding)
