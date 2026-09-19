"""The same agent, with no Anthropic key and no cost.

    python -m mcp_server.free_agent "anything exempted this week?"

Two providers, both free, both reached through the OpenAI-compatible API so one
implementation covers them:

  Groq    free developer tier, fast, needs GROQ_API_KEY from console.groq.com
  Ollama  fully local and offline, no key, no account, no limits

Groq is used when GROQ_API_KEY is set, otherwise it falls back to Ollama on
localhost. Neither costs anything.

Tool schemas are derived from the MCP server rather than written out here. That
is the whole point: a hand-maintained tool list is how you end up offering four
of six tools and wondering why the model cannot answer "why did sg-123 alert",
which needs the two that were missed.

Caveat worth knowing: small local models are noticeably worse at multi-turn tool
calling than hosted ones. If Ollama gives up early or calls the wrong tool, try a
larger model (FREE_AGENT_MODEL=qwen2.5:14b) before assuming the tools are wrong.
"""

import json
import os
import sys

from mcp_server.agent import MAX_TURNS, tool_schemas as _mcp_tool_schemas
from mcp_server.agent import AgentConfigError, _tool_functions

GROQ_BASE_URL = 'https://api.groq.com/openai/v1'
GROQ_MODEL = 'llama-3.3-70b-versatile'

OLLAMA_BASE_URL = 'http://localhost:11434/v1'
OLLAMA_MODEL = 'llama3.1:8b'

SYSTEM = (
    'You investigate an automated AWS compliance engine on behalf of a security '
    'engineer. Call describe_engine_rules first if you do not already know what '
    'the engine enforces.\n\n'
    'Every tool is read-only. You cannot change anything in AWS, so do not offer '
    'to apply a fix. Report what you find and let the operator act.\n\n'
    'Absence of evidence is not evidence of compliance. An empty result can mean '
    'the engine is not receiving events, is deployed in another region, or never '
    'evaluated the resource. Tools return a warning field when that is possible; '
    'repeat it rather than reporting anything as clean.\n\n'
    'Be concise. Lead with the answer, then the evidence.'
)


def tool_schemas() -> list[dict]:
    """The MCP server's tools, converted to OpenAI function-calling shape."""
    return [
        {
            'type': 'function',
            'function': {
                'name': tool['name'],
                'description': tool['description'],
                'parameters': tool['input_schema'],
            },
        }
        for tool in _mcp_tool_schemas()
    ]


def resolve_provider() -> tuple[str, str, str, str]:
    """Return (name, base_url, api_key, model). Groq if keyed, else local Ollama."""
    model_override = os.environ.get('FREE_AGENT_MODEL', '').strip()

    groq_key = os.environ.get('GROQ_API_KEY', '').strip()
    if groq_key:
        return 'groq', GROQ_BASE_URL, groq_key, model_override or GROQ_MODEL

    # Ollama ignores the key but the OpenAI client requires one to be set.
    return 'ollama', OLLAMA_BASE_URL, 'ollama', model_override or OLLAMA_MODEL


def _openai_client():
    # Imported lazily so this module and its tests work without the SDK
    # installed. Only actually running the agent needs it.
    try:
        from openai import OpenAI
    except ImportError:
        raise AgentConfigError(
            'The openai package is not installed. Run: pip install openai\n'
            'It is the client for both providers here; neither is OpenAI itself.'
        )

    name, base_url, api_key, model = resolve_provider()
    return OpenAI(base_url=base_url, api_key=api_key), model


def _call_tool(name: str, arguments: dict):
    functions = _tool_functions()
    if name not in functions:
        raise KeyError(f'{name!r} is not a registered tool')
    return functions[name](**arguments)


def run_agent(question: str) -> dict:
    """Answer one question about the compliance engine, calling tools as needed."""
    if not os.environ.get('COMPLIANCE_REGION', '').strip():
        # Every AWS-touching tool raises ConfigError on this. Better to say so
        # now than to fail three turns in with a stack trace from inside a tool.
        raise AgentConfigError(
            'COMPLIANCE_REGION is not set. Set it to the region the engine is '
            'deployed in (aws_region in terraform.tfvars), which is not '
            'necessarily your AWS CLI default.'
        )

    client, model = _openai_client()
    tools = tool_schemas()
    messages = [
        {'role': 'system', 'content': SYSTEM},
        {'role': 'user', 'content': question},
    ]
    tool_calls: list[str] = []

    for _ in range(MAX_TURNS):
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            tools=tools,
            tool_choice='auto',
        )
        message = response.choices[0].message

        if not getattr(message, 'tool_calls', None):
            return {
                'answer': message.content or '',
                'tool_calls': tool_calls,
                'stopped_early': False,
            }

        messages.append({
            'role': 'assistant',
            'content': message.content or '',
            'tool_calls': [
                {
                    'id': call.id,
                    'type': 'function',
                    'function': {
                        'name': call.function.name,
                        'arguments': call.function.arguments or '{}',
                    },
                }
                for call in message.tool_calls
            ],
        })

        for call in message.tool_calls:
            name = call.function.name
            tool_calls.append(name)

            try:
                # Small local models emit invalid JSON arguments regularly, so
                # this cannot be allowed to kill the run.
                arguments = json.loads(call.function.arguments or '{}')
                output = json.dumps(_call_tool(name, arguments), default=str)
            except Exception as exc:
                output = f'Tool failed: {exc}'

            messages.append({
                'role': 'tool',
                'tool_call_id': call.id,
                'content': output,
            })

    return {
        'answer': (
            f'Stopped after {MAX_TURNS} turns without a final answer. Small local '
            'models often loop; try GROQ_API_KEY or a larger FREE_AGENT_MODEL.'
        ),
        'tool_calls': tool_calls,
        'stopped_early': True,
    }


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args:
        print('usage: python -m mcp_server.free_agent "your question"')
        return 2

    provider, _url, _key, model = resolve_provider()
    print(f'[{provider}: {model}]\n')

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
