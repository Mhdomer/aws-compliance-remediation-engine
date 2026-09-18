"""The agent loop, with the Anthropic API mocked throughout.

Nothing here makes a network call or spends a token.
"""

from unittest.mock import MagicMock, patch

import pytest


class _Text:
    type = 'text'

    def __init__(self, text):
        self.text = text


class _ToolUse:
    type = 'tool_use'

    def __init__(self, name, tool_input, tool_id='tu-1'):
        self.name = name
        self.input = tool_input
        self.id = tool_id


def _reply(content, stop_reason='end_turn'):
    message = MagicMock()
    message.content = content
    message.stop_reason = stop_reason
    return message


@pytest.fixture(autouse=True)
def region(monkeypatch):
    monkeypatch.setenv('COMPLIANCE_REGION', 'us-east-1')
    monkeypatch.setenv('ANTHROPIC_API_KEY', 'test-key')


@pytest.fixture
def anthropic():
    from mcp_server import agent
    client = MagicMock()
    with patch.object(agent, '_anthropic_client', return_value=client):
        yield client


class TestToolSchemas:
    def test_schemas_are_built_from_the_mcp_server(self):
        from mcp_server.agent import tool_schemas

        names = {t['name'] for t in tool_schemas()}
        # The agent must not maintain a second copy of the tool list.
        assert 'describe_engine_rules' in names
        assert 'get_compliance_posture' in names

    def test_every_schema_has_what_the_api_requires(self):
        from mcp_server.agent import tool_schemas

        for schema in tool_schemas():
            assert schema['name']
            assert schema['description']
            assert schema['input_schema']['type'] == 'object'


class TestAgentLoop:
    def test_a_plain_answer_is_returned(self, anthropic):
        from mcp_server.agent import run_agent
        anthropic.messages.create.return_value = _reply([_Text('All clear.')])

        result = run_agent('how are we doing?')

        assert result['answer'] == 'All clear.'
        assert result['tool_calls'] == []

    def test_a_tool_call_is_executed_and_fed_back(self, anthropic):
        from mcp_server.agent import run_agent
        anthropic.messages.create.side_effect = [
            _reply([_ToolUse('describe_engine_rules', {})], stop_reason='tool_use'),
            _reply([_Text('It checks four things.')]),
        ]

        result = run_agent('what does it check?')

        assert result['answer'] == 'It checks four things.'
        assert result['tool_calls'] == ['describe_engine_rules']
        assert anthropic.messages.create.call_count == 2

    def test_several_tools_compose_into_one_answer(self, anthropic):
        from mcp_server.agent import run_agent
        anthropic.messages.create.side_effect = [
            _reply([_ToolUse('describe_engine_rules', {}, 'a')], stop_reason='tool_use'),
            _reply([_ToolUse('list_exemptions', {}, 'b')], stop_reason='tool_use'),
            _reply([_Text('Two exemptions, both on S3.')]),
        ]

        with patch('mcp_server.agent._call_tool', return_value={'ok': True}):
            result = run_agent('any exemptions?')

        # Triage is composition, not a dedicated tool.
        assert result['tool_calls'] == ['describe_engine_rules', 'list_exemptions']

    def test_a_failing_tool_is_reported_back_to_the_model(self, anthropic):
        from mcp_server.agent import run_agent
        anthropic.messages.create.side_effect = [
            _reply([_ToolUse('get_compliance_posture', {'hours': 24})],
                   stop_reason='tool_use'),
            _reply([_Text('Could not read metrics.')]),
        ]

        with patch('mcp_server.agent._call_tool', side_effect=RuntimeError('boom')):
            result = run_agent('posture?')

        # The model needs to know the tool failed, not receive silence.
        second_call = anthropic.messages.create.call_args_list[1]
        payload = str(second_call.kwargs['messages'])
        assert 'boom' in payload
        assert result['answer'] == 'Could not read metrics.'

    def test_the_loop_is_bounded(self, anthropic):
        from mcp_server.agent import MAX_TURNS, run_agent
        # A model that keeps calling tools must not run forever on the user's
        # money.
        anthropic.messages.create.return_value = _reply(
            [_ToolUse('describe_engine_rules', {})], stop_reason='tool_use'
        )

        result = run_agent('loop forever')

        assert anthropic.messages.create.call_count <= MAX_TURNS
        assert result['stopped_early'] is True

    def test_only_read_only_tools_are_offered(self, anthropic):
        from mcp_server.agent import run_agent
        anthropic.messages.create.return_value = _reply([_Text('ok')])

        run_agent('anything')

        offered = {t['name'] for t in anthropic.messages.create.call_args.kwargs['tools']}
        for name in offered:
            assert not name.startswith(
                ('delete_', 'create_', 'put_', 'remediate_', 'stop_', 'terminate_')
            ), f'{name} looks like it mutates'

    def test_an_unknown_tool_name_is_rejected(self):
        from mcp_server.agent import _call_tool

        with pytest.raises(KeyError, match='not a registered tool'):
            _call_tool('rm_rf', {})


class TestApiKeyHandling:
    def test_a_missing_key_is_explained_not_a_stack_trace(self, monkeypatch):
        monkeypatch.delenv('ANTHROPIC_API_KEY', raising=False)
        from mcp_server.agent import AgentConfigError, run_agent

        with pytest.raises(AgentConfigError, match='ANTHROPIC_API_KEY'):
            run_agent('anything')
