"""The free agent: same tools, no Anthropic key, no cost.

Everything here is mocked. No network call, no API key, no spend.
"""

from unittest.mock import MagicMock, patch

import pytest


class _ToolCall:
    def __init__(self, name, arguments='{}', call_id='tc-1'):
        self.id = call_id
        self.function = MagicMock(name=name)
        self.function.name = name
        self.function.arguments = arguments


def _reply(content=None, tool_calls=None):
    message = MagicMock()
    message.content = content
    message.tool_calls = tool_calls
    response = MagicMock()
    response.choices = [MagicMock(message=message)]
    return response


@pytest.fixture(autouse=True)
def region(monkeypatch):
    monkeypatch.setenv('COMPLIANCE_REGION', 'us-east-1')


@pytest.fixture
def llm():
    from mcp_server import free_agent
    client = MagicMock()
    with patch.object(free_agent, '_openai_client', return_value=(client, 'test-model')):
        yield client


class TestToolSchemas:
    def test_every_mcp_tool_is_offered(self):
        from mcp_server.free_agent import tool_schemas
        from mcp_server.agent import tool_schemas as mcp_schemas

        # Derived from the MCP server, never hand-written. A hand-maintained
        # list is how you end up offering four of six tools and wondering why
        # the model cannot answer "why did sg-123 alert".
        assert {t['function']['name'] for t in tool_schemas()} == {
            s['name'] for s in mcp_schemas()
        }

    def test_all_six_are_present(self):
        from mcp_server.free_agent import tool_schemas
        names = {t['function']['name'] for t in tool_schemas()}
        assert names == {
            'describe_engine_rules', 'get_compliance_posture',
            'search_compliance_logs', 'get_resource_history',
            'get_resource_state', 'list_exemptions',
        }

    def test_schemas_are_in_openai_shape(self):
        from mcp_server.free_agent import tool_schemas
        for schema in tool_schemas():
            assert schema['type'] == 'function'
            assert schema['function']['name']
            assert schema['function']['description']
            assert schema['function']['parameters']['type'] == 'object'


class TestProviderSelection:
    def test_groq_is_used_when_a_key_is_present(self, monkeypatch):
        monkeypatch.setenv('GROQ_API_KEY', 'gsk-test')
        from mcp_server.free_agent import resolve_provider

        name, base_url, _key, model = resolve_provider()
        assert name == 'groq'
        assert 'groq.com' in base_url
        assert model

    def test_ollama_is_the_fallback(self, monkeypatch):
        monkeypatch.delenv('GROQ_API_KEY', raising=False)
        from mcp_server.free_agent import resolve_provider

        name, base_url, _key, _model = resolve_provider()
        # Local, offline, no key. The genuinely free-forever option.
        assert name == 'ollama'
        assert 'localhost' in base_url

    def test_overrides_are_respected(self, monkeypatch):
        monkeypatch.delenv('GROQ_API_KEY', raising=False)
        monkeypatch.setenv('FREE_AGENT_MODEL', 'qwen2.5:14b')
        from mcp_server.free_agent import resolve_provider

        _name, _url, _key, model = resolve_provider()
        assert model == 'qwen2.5:14b'


class TestAgentLoop:
    def test_a_plain_answer_is_returned(self, llm):
        from mcp_server.free_agent import run_agent
        llm.chat.completions.create.return_value = _reply(content='All clear.')

        result = run_agent('how are we doing?')

        assert result['answer'] == 'All clear.'
        assert result['tool_calls'] == []

    def test_a_tool_call_is_executed_and_fed_back(self, llm):
        from mcp_server.free_agent import run_agent
        llm.chat.completions.create.side_effect = [
            _reply(tool_calls=[_ToolCall('describe_engine_rules')]),
            _reply(content='It checks four things.'),
        ]

        result = run_agent('what does it check?')

        assert result['tool_calls'] == ['describe_engine_rules']
        assert result['answer'] == 'It checks four things.'

    def test_a_failing_tool_is_reported_back_not_crashed_on(self, llm):
        from mcp_server.free_agent import run_agent
        llm.chat.completions.create.side_effect = [
            _reply(tool_calls=[_ToolCall('get_compliance_posture', '{"hours": 24}')]),
            _reply(content='Could not read metrics.'),
        ]

        with patch('mcp_server.free_agent._call_tool', side_effect=RuntimeError('boom')):
            result = run_agent('posture?')

        # Silence would leave the model treating a failure as an empty answer.
        sent = str(llm.chat.completions.create.call_args_list[1].kwargs['messages'])
        assert 'boom' in sent
        assert result['answer'] == 'Could not read metrics.'

    def test_malformed_arguments_do_not_crash_the_loop(self, llm):
        from mcp_server.free_agent import run_agent
        # Small local models emit invalid JSON arguments regularly.
        llm.chat.completions.create.side_effect = [
            _reply(tool_calls=[_ToolCall('describe_engine_rules', 'not json{')]),
            _reply(content='recovered'),
        ]

        result = run_agent('anything')
        assert result['answer'] == 'recovered'

    def test_an_unknown_tool_is_reported_not_raised(self, llm):
        from mcp_server.free_agent import run_agent
        llm.chat.completions.create.side_effect = [
            _reply(tool_calls=[_ToolCall('rm_rf')]),
            _reply(content='no such tool'),
        ]

        result = run_agent('do something bad')
        sent = str(llm.chat.completions.create.call_args_list[1].kwargs['messages'])
        assert 'not a registered tool' in sent
        assert result['answer'] == 'no such tool'

    def test_the_loop_is_bounded(self, llm):
        from mcp_server.free_agent import MAX_TURNS, run_agent
        llm.chat.completions.create.return_value = _reply(
            tool_calls=[_ToolCall('describe_engine_rules')]
        )

        result = run_agent('loop forever')

        assert llm.chat.completions.create.call_count <= MAX_TURNS
        assert result['stopped_early'] is True

    def test_only_read_only_tools_are_offered(self, llm):
        from mcp_server.free_agent import run_agent
        llm.chat.completions.create.return_value = _reply(content='ok')

        run_agent('anything')

        offered = {
            t['function']['name']
            for t in llm.chat.completions.create.call_args.kwargs['tools']
        }
        for name in offered:
            assert not name.startswith(
                ('delete_', 'create_', 'put_', 'stop_', 'terminate_', 'remediate_')
            )


class TestConfiguration:
    def test_a_missing_region_is_explained_not_a_stack_trace(self, monkeypatch, llm):
        monkeypatch.delenv('COMPLIANCE_REGION', raising=False)
        from mcp_server.free_agent import AgentConfigError, run_agent

        # The tools raise ConfigError deep inside on the first AWS call. Better
        # to say so up front than to fail three turns in.
        with pytest.raises(AgentConfigError, match='COMPLIANCE_REGION'):
            run_agent('anything')
