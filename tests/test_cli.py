import pytest
from pytest_console_scripts import ScriptRunner
from moto import mock_aws


@pytest.mark.skip(reason='Moto doesnt mock BatchImportFindings yet')
@mock_aws
def test_cli_command(script_runner: ScriptRunner):
    result = script_runner.run(['tvm2aws'])
