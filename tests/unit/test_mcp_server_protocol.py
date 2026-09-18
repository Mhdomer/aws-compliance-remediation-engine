import json

import anyio


def _run(coro_fn):
    """Drive one async call from a sync test. anyio ships with the mcp SDK,
    so this avoids adding pytest-asyncio as a dependency."""
    return anyio.run(coro_fn)


def _tools():
    from mcp_server.server import mcp

    async def go():
        return await mcp.list_tools()

    return _run(go)


class TestToolsAreAdvertised:
    def test_describe_engine_rules_is_listed(self):
        assert 'describe_engine_rules' in {t.name for t in _tools()}

    def test_every_tool_has_a_description(self):
        for tool in _tools():
            # A tool with no description is one the model will not know when to
            # call. It fails silently: nothing errors, the tool is just unused.
            assert tool.description, f'{tool.name} has no description'

    def test_every_tool_has_a_valid_object_schema(self):
        for tool in _tools():
            # A malformed schema makes a tool uncallable at runtime with no
            # error at startup.
            assert tool.input_schema['type'] == 'object', tool.name
            assert 'properties' in tool.input_schema, tool.name


class TestToolsAreCallable:
    def test_describe_engine_rules_runs_through_the_protocol(self):
        from mcp_server.server import mcp

        async def go():
            return await mcp.call_tool('describe_engine_rules', {})

        result = _run(go)
        assert result.is_error is False

        payload = json.loads(result.content[0].text)
        assert {c['event_name'] for c in payload['checks']} == {
            'PutBucketAcl', 'PutBucketEncryption',
            'RunInstances', 'AuthorizeSecurityGroupIngress',
        }

    def test_server_carries_instructions_for_the_model(self):
        from mcp_server.server import mcp
        # The instructions tell the model this server cannot act, which keeps it
        # from proposing remediations it has no tool to perform.
        assert 'read-only' in (mcp.instructions or '').lower()
