import logging

import pytest
import responses
from moto import mock_aws

from tenable_aws_sechub.transform import Processor


@pytest.fixture
def config():
    return {
        'since': 0,
        'access_key': '1234567890abcdef1234567890',
        'secret_key': '1234567890abcdef1234567890',
        'aws_profile': [
            {
                'name': 'default',
                'region': 'us-east-1',
                'accounts': ['600832220000'],
            }
        ],
    }


@responses.activate
@mock_aws
def test_processor_asset_trim(asset_aws, config):
    id = '12345678-1234-1234-1234-1234567890ab'
    responses.post(
        'https://cloud.tenable.com/assets/v2/export', json={'export_uuid': id}
    )
    responses.get(
        f'https://cloud.tenable.com/assets/export/{id}/status',
        json={'status': 'FINISHED', 'chunks_available': [1]},
    )
    responses.get(
        f'https://cloud.tenable.com/assets/export/{id}/chunks/1', json=[asset_aws]
    )
    p = Processor(config)

    assets = p.get_trimmed_assets()
    asset_id = '01234567-1234-abcd-0987-01234567890b'
    assert isinstance(assets, dict)
    assert asset_id in assets
    assert 'cloud.aws.subnet_id' not in assets[asset_id].keys()
    assert 'cloud.aws.owner_id' in assets[asset_id].keys()


@responses.activate
@mock_aws
def test_processor_ingest_warn(asset_local, finding, config, caplog):
    id = '12345678-1234-1234-1234-1234567890ab'
    finding['asset']['uuid'] = asset_local['id']
    responses.post(
        'https://cloud.tenable.com/assets/v2/export', json={'export_uuid': id}
    )
    responses.get(
        f'https://cloud.tenable.com/assets/export/{id}/status',
        json={'status': 'FINISHED', 'chunks_available': [1]},
    )
    responses.get(
        f'https://cloud.tenable.com/assets/export/{id}/chunks/1', json=[asset_local]
    )
    responses.post('https://cloud.tenable.com/vulns/export', json={'export_uuid': id})
    responses.get(
        f'https://cloud.tenable.com/vulns/export/{id}/status',
        json={'status': 'FINISHED', 'chunks_available': [1]},
    )
    responses.get(
        f'https://cloud.tenable.com/vulns/export/{id}/chunks/1', json=[finding]
    )
    p = Processor(config)
    with caplog.at_level(logging.WARNING, logger='Tenb2SecHub'):
        p.ingest()
    msg = f'Asset {asset_local["id"]} not found in AWS account listing'
    assert msg in [r.message for r in caplog.records]


@pytest.mark.skip(reason='BatchImportFindings is not yet implemented in moto')
@responses.activate
@mock_aws
def test_processor_ingest(asset_aws, finding, config):
    id = '12345678-1234-1234-1234-1234567890ab'
    responses.post('https://cloud.tenable.com/assets/export', json={'export_uuid': id})
    responses.get(
        f'https://cloud.tenable.com/assets/export/{id}/status',
        json={'status': 'FINISHED', 'chunks_available': [1]},
    )
    responses.get(
        f'https://cloud.tenable.com/assets/export/{id}/chunks/1', json=[asset_aws]
    )
    responses.post('https://cloud.tenable.com/vulns/export', json={'export_uuid': id})
    responses.get(
        f'https://cloud.tenable.com/vulns/export/{id}/status',
        json={'status': 'FINISHED', 'chunks_available': [1]},
    )
    responses.get(
        f'https://cloud.tenable.com/vulns/export/{id}/chunks/1', json=[finding]
    )
    p = Processor(config)
    p.ingest()
