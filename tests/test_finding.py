import pytest

from tenable_aws_sechub.finding import Finding


def test_finding_required_typerror(finding_local):
    """
    Tests the check_required_params method and check to see if all of the
    required params actually fail on this local asset.
    """
    f = Finding('', '')
    with pytest.raises(
        KeyError,
        match=(
            'The required asset attributes '
            'asset.aws_region,'
            'asset.aws_ec2_instance_id,'
            'asset.aws_owner_id,'
            'asset.aws_ec2_instance_type,'
            'asset.aws_ec2_instance_ami_id '
            'were not set on asset '
            '01234567-1234-abcd-0987-01234567890a'
        ),
    ):
        resp = f.check_required_params(finding_local)


def test_finding_generate_finding_keyerror(finding_local, finding_aws):
    """
    Tests the generate finding method and ensures that a key error is thrown
    when an asset or a finding doesn't have the required parameters to generate
    AWS finding.
    """
    f = Finding('', '')
    with pytest.raises(KeyError):
        resp = f.generate(finding_local)

    del finding_aws['plugin.type']
    with pytest.raises(KeyError, match='plugin.type'):
        resp = f.generate(finding_aws)


def test_finding_generate_finding_success(finding_aws):
    """
    Tests the generate finding method on what should be a successful transform.
    From there we will perform some minor checks to ensure that the generated
    finding object looks correct.
    """
    f = Finding('AWS-REGION-1', 'ACCOUNT-ID')
    resp = f.generate(finding_aws)

    # Pulled the asserts from the v1 code and made the minor modifications
    # necessary for the test to pass the new finding obj.
    assert resp['SchemaVersion'] == '2018-10-08'
    assert resp['FirstObservedAt'] == '2018-03-22T13:29:22.070Z'
    assert resp['LastObservedAt'] == '2018-12-14T12:07:38.155Z'
    assert (
        resp['ProductArn']
        == 'arn:aws:securityhub:AWS-REGION-1::product/tenable/tenable-io'
    )
    assert resp['AwsAccountId'] == 'ACCOUNT-ID'
    assert resp['GeneratorId'] == 'tenable-plugin-106875'
    assert resp['Id'] == 'us-east-1/i-00f9e618482900000/106875'
    assert resp['Types'] == ['Software and Configuration Checks/Vulnerabilities/CVE']
    assert resp['CreatedAt']
    assert resp['UpdatedAt']
    assert resp['Severity']['Product'] == 7
    assert resp['Severity']['Normalized'] == 28
    assert resp['Severity']['Label'] == 'HIGH'
    assert resp['Title'] == 'Debian DSA-4117-1 : gcc-4.9 - security update'
    assert isinstance(resp['Description'], str)
    assert resp['Resources'][0]['Type'] == 'AwsEc2Instance'
    assert (
        resp['Resources'][0]['Id']
        == 'arn:aws:ec2:us-east-1:600832220000:instance:i-00f9e618482900000'
    )
    assert resp['Resources'][0]['Region'] == 'us-east-1'
    assert resp['Resources'][0]['Details']['AwsEc2Instance']['Type'] == 't2.medium'
    assert (
        resp['Resources'][0]['Details']['AwsEc2Instance']['ImageId'] == 'ami-daf89000'
    )
    assert resp['Resources'][0]['Details']['AwsEc2Instance']['IpV4Addresses'] == [
        '192.168.101.249'
    ]
    assert resp['Resources'][0]['Details']['AwsEc2Instance']['IpV6Addresses'] == []
    assert resp['ProductFields']['CVE'] == ''
    assert resp['ProductFields']['Plugin Family'] == 'Debian Local Security Checks'
    assert resp['ProductFields']['Type'] == 'local'
    assert isinstance(resp['Remediation']['Recommendation']['Text'], str)
    assert (
        resp['Remediation']['Recommendation']['Url']
        == 'https://security-tracker.debian.org/tracker/source-package/gcc-4.9'
    )
    assert resp['RecordState'] == 'ACTIVE'

    # Also check to make sure that a fixed finding returns an "ARCHIVED"
    # record state.
    finding_aws['state'] = 'FIXED'
    resp = f.generate(finding_aws)
    assert resp['RecordState'] == 'ARCHIVED'


def test_generate_finding_none_url(finding_aws):
    f = Finding('AWS-REGION-1', 'ACCOUNT-ID')

    del finding_aws['plugin.see_also']
    resp = f.generate(finding_aws)

    assert 'Url' not in resp['Remediation']['Recommendation']
