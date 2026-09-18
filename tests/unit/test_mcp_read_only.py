import ast
from pathlib import Path

import pytest

MCP_PACKAGE = Path(__file__).resolve().parents[2] / 'mcp_server'

# Any boto3 call whose name begins with one of these changes something.
# start_ is here because ec2:StartInstances restarts a stopped instance.
MUTATING_PREFIXES = (
    'put_', 'delete_', 'create_', 'modify_', 'terminate_', 'stop_', 'start_',
    'revoke_', 'authorize_', 'update_', 'attach_', 'detach_', 'remove_',
    'set_', 'reboot_', 'run_',
)

# logs:StartQuery only begins a read, so it is exempted by name rather than by
# dropping the start_ prefix and letting StartInstances through with it.
READ_CALLS_THAT_LOOK_MUTATING = {'start_query'}

WRITE_SAMPLE = 'def wipe(client):\n    client.delete_bucket(Bucket="x")\n'
RESTART_SAMPLE = 'def go(client):\n    client.start_instances(InstanceIds=["i-1"])\n'
QUERY_SAMPLE = 'def go(client):\n    return client.start_query(queryString="f")\n'
READ_SAMPLE = 'def look(client):\n    return client.describe_instances()\n'


def _called_method_names(path: Path) -> set[str]:
    """Every `something.method(...)` name called in a module."""
    tree = ast.parse(path.read_text(encoding='utf-8'))
    return {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }


def _offenders(path: Path) -> set[str]:
    return {
        name for name in _called_method_names(path)
        if name.startswith(MUTATING_PREFIXES)
    } - READ_CALLS_THAT_LOOK_MUTATING


def _sample(tmp_path: Path, name: str, source: str) -> Path:
    path = tmp_path / name
    path.write_text(source, encoding='utf-8')
    return path


def _package_modules() -> list[Path]:
    return sorted(MCP_PACKAGE.rglob('*.py'))


class TestNoWriteCallsExist:
    def test_there_are_modules_to_check(self):
        # Without this, an empty glob would make the scan below pass by
        # checking nothing at all.
        assert _package_modules(), 'no mcp_server modules found to scan'

    @pytest.mark.parametrize('path', _package_modules(), ids=lambda p: p.name)
    def test_module_calls_no_mutating_method(self, path):
        offenders = _offenders(path)
        assert not offenders, (
            f'{path.name} calls {sorted(offenders)}. This server is read-only '
            'by construction: there is no write path to prompt-inject into.'
        )


class TestTheGuardItselfWorks:
    """Without these, the scan above could pass by finding nothing."""

    def test_a_write_is_caught(self, tmp_path):
        assert _offenders(_sample(tmp_path, 'bad.py', WRITE_SAMPLE)) == {
            'delete_bucket'
        }

    def test_start_instances_is_caught(self, tmp_path):
        # The exemption is for start_query specifically, not every start_.
        assert _offenders(_sample(tmp_path, 'restart.py', RESTART_SAMPLE)) == {
            'start_instances'
        }

    def test_start_query_is_allowed(self, tmp_path):
        assert _offenders(_sample(tmp_path, 'query.py', QUERY_SAMPLE)) == set()

    def test_a_read_is_allowed(self, tmp_path):
        assert _offenders(_sample(tmp_path, 'good.py', READ_SAMPLE)) == set()


class TestClientFactory:
    def test_region_is_passed_explicitly(self):
        from unittest.mock import MagicMock, patch
        from mcp_server.aws_clients import read_only_client

        with patch('boto3.client', return_value=MagicMock()) as make_client:
            read_only_client('cloudwatch', 'us-east-1')

        # Never inherited: the CLI default region differs from the deployed one.
        make_client.assert_called_once_with('cloudwatch', region_name='us-east-1')

    def test_allowlist_contains_only_read_operations(self):
        from mcp_server.aws_clients import READ_ONLY_METHODS

        assert READ_ONLY_METHODS
        for method in READ_ONLY_METHODS:
            assert method.startswith(('describe_', 'get_', 'list_', 'start_query')), (
                f'{method} is in the read-only allowlist but does not read'
            )

    def test_every_call_the_tools_make_is_on_the_allowlist(self):
        from mcp_server.aws_clients import READ_ONLY_METHODS

        # Catches an AWS call added to a tool without being declared.
        boto_like = set()
        for path in _package_modules():
            boto_like |= {
                name for name in _called_method_names(path)
                if name.startswith(('describe_', 'get_bucket', 'get_metric',
                                    'get_public', 'get_query', 'get_resources',
                                    'start_query'))
            }

        undeclared = boto_like - READ_ONLY_METHODS
        assert not undeclared, f'undeclared AWS calls: {sorted(undeclared)}'
