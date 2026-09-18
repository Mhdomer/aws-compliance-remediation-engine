"""Optional standalone agent: ask the compliance engine a question, unattended.

Phase 1-3 give you an MCP server you drive from Claude Code, which costs
nothing because it runs on your existing subscription. This module is the other
half of the resume claim: the same tools driven by a loop with no human in it,
so it can run from a schedule or an event.

    python -m mcp_server.agent "anything exempted this week?"

It calls the Anthropic API, so unlike everything else in this repo **running it
costs money per invocation**. Nothing here spends anything at import time or
under test.

The tools are the same read-only ones the MCP server exposes, read from that
server rather than redeclared, so the two cannot drift apart. The agent can no
more change AWS than the server can.
"""

import json
import os
import sys

import anyio

# claude-opus-5 takes adaptive thinking; the older budget_tokens shape is
# rejected with a 400 on this model.
MODEL = 'claude-opus-5'
MAX_TOKENS = 16000
EFFORT = 'medium'

# A model that keeps calling tools must not run indefinitely on someone's
# API budget. Six tools, so a handful of turns is plenty for real questions.
MAX_TURNS = 8

SYSTEM = (
    'You investigate an automated AWS compliance engine on behalf of a security '
    'engineer. Call describe_engine_rules first if you do not already know what '
    'the engine enforces.\n\n'
    'Every tool is read-only. You cannot change anything in AWS, so do not '
    'offer to apply a fix. Report what you find and let the operator act.\n\n'
    'Absence of evidence is not evidence of compliance. An empty result can mean '
    'the engine is not receiving events, is deployed in another region, or never '
    'evaluated the resource. Tools return a warning field when that is possible; '
    'repeat it rather than reporting anything as clean.\n\n'
    'A compliant value of null means undetermined, which is different from false. '
    'Say so rather than rounding it to either.\n\n'
    'Be concise. Lead with the answer, then the evidence.'
)


class AgentConfigError(RuntimeError):
    """Raised when the agent is not configured to run."""


def _anthropic_client():
    # Imported lazily so this module, and its tests, work without the SDK
    # installed. Only running the agent needs it.
    import anthropic

    return anthropic.Anthropic()


def _tool_functions() -> dict:
    from mcp_server.tools.engine_rules import describe_engine_rules
    from mcp_server.tools.exemptions import list_exemptions
    from mcp_server.tools.logs import get_resource_history, search_compliance_logs
    from mcp_server.tools.posture import get_compliance_posture
    from mcp_server.tools.resource_state import get_resource_state

    return {
        'describe_engine_rules': describe_engine_rules,
        'get_compliance_posture': get_compliance_posture,
        'search_compliance_logs': search_compliance_logs,
        'get_resource_history': get_resource_history,
        'get_resource_state': get_resource_state,
        'list_exemptions': list_exemptions,
    }


def tool_schemas() -> list[dict]:
    """Anthropic tool definitions, derived from the MCP server's own tool list.

    Read from the server rather than written out again, so adding a tool there
    makes it available here without a second declaration to keep in sync.
    """
    from mcp_server.server import mcp

    async def _list():
        return await mcp.list_tools()

    return [
        {
            'name': tool.name,
            'description': tool.description,
            'input_schema': tool.input_schema,
        }
        for tool in anyio.run(_list)
    ]


def _call_tool(name: str, arguments: dict):
    functions = _tool_functions()
    if name not in functions:
        raise KeyError(f'{name!r} is not a registered tool')
    return functions[name](**arguments)


def run_agent(question: str, model: str = MODEL) -> dict:
    """Answer one question about the compliance engine, calling tools as needed."""
    if not os.environ.get('ANTHROPIC_API_KEY', '').strip():
        raise AgentConfigError(
            'ANTHROPIC_API_KEY is not set. The MCP server itself needs no key — '
            'only this standalone agent does, because it calls the API directly.'
        )

    client = _anthropic_client()
    tools = tool_schemas()
    messages = [{'role': 'user', 'content': question}]
    tool_calls: list[str] = []

    for _ in range(MAX_TURNS):
        response = client.messages.create(
            model=model,
            max_tokens=MAX_TOKENS,
            system=SYSTEM,
            thinking={'type': 'adaptive'},
            output_config={'effort': EFFORT},
            tools=tools,
            messages=messages,
        )

        if getattr(response, 'stop_reason', None) == 'refusal':
            return {
                'answer': 'The model declined to answer this request.',
                'tool_calls': tool_calls,
                'stopped_early': False,
                'refused': True,
            }

        if response.stop_reason != 'tool_use':
            return {
                'answer': ''.join(
                    block.text for block in response.content if block.type == 'text'
                ),
                'tool_calls': tool_calls,
                'stopped_early': False,
                'refused': False,
            }

        messages.append({'role': 'assistant', 'content': response.content})

        # Every tool_result for one assistant turn goes back in a single user
        # message. Splitting them teaches the model to stop calling tools in
        # parallel.
        results = []
        for block in response.content:
            if block.type != 'tool_use':
                continue

            tool_calls.append(block.name)
            try:
                output = _call_tool(block.name, block.input)
                results.append({
                    'type': 'tool_result',
                    'tool_use_id': block.id,
                    'content': json.dumps(output, default=str),
                })
            except Exception as exc:
                # The model needs to know the tool failed. Silence would leave
                # it guessing, or worse, assuming the answer was empty.
                results.append({
                    'type': 'tool_result',
                    'tool_use_id': block.id,
                    'content': f'Tool failed: {exc}',
                    'is_error': True,
                })

        messages.append({'role': 'user', 'content': results})

    return {
        'answer': (
            f'Stopped after {MAX_TURNS} turns without a final answer. '
            'The question may be too broad, or a tool may be returning nothing useful.'
        ),
        'tool_calls': tool_calls,
        'stopped_early': True,
        'refused': False,
    }


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args:
        print('usage: python -m mcp_server.agent "your question"')
        return 2

    try:
        result = run_agent(' '.join(args))
    except AgentConfigError as exc:
        print(f'Not configured: {exc}')
        return 1

    if result['tool_calls']:
        print(f'Tools called: {", ".join(result["tool_calls"])}\n')
    print(result['answer'])
    return 1 if result['stopped_early'] else 0


if __name__ == '__main__':
    sys.exit(main())
