"""MCP server exposing the compliance engine's telemetry, read-only.

Run it directly for stdio, which is how Claude Code launches it:

    python -m mcp_server.server

The tool functions live in mcp_server/tools/ as plain functions and are tested
directly. This module only wires them to the protocol, which keeps the tests
for the tools free of any MCP machinery.
"""

from mcp.server import MCPServer

from mcp_server.tools.engine_rules import describe_engine_rules as _describe_engine_rules
from mcp_server.tools.exemptions import list_exemptions as _list_exemptions
from mcp_server.tools.logs import get_resource_history as _get_resource_history
from mcp_server.tools.logs import search_compliance_logs as _search_compliance_logs
from mcp_server.tools.posture import get_compliance_posture as _get_compliance_posture
from mcp_server.tools.resource_state import get_resource_state as _get_resource_state

mcp = MCPServer(
    name='compliance-engine',
    instructions=(
        'Read-only access to an automated AWS compliance and remediation '
        'engine. Call describe_engine_rules first to learn what the engine '
        'enforces and which metrics it publishes.\n\n'
        'Every tool here is read-only: none can change anything in AWS, so do '
        'not offer to apply a fix. Report findings and let the operator act.\n\n'
        'Absence of evidence is not evidence of compliance. An empty result can '
        'mean the engine is not receiving events, is deployed in another '
        'region, or never evaluated the resource. Several tools return a '
        'warning field saying so; surface it rather than reporting an account '
        'or resource as clean.\n\n'
        'A compliant value of null means undetermined, which is different from '
        'false. Say so rather than rounding it to either.'
    ),
)


@mcp.tool()
def describe_engine_rules() -> dict:
    """Describe every compliance check this engine enforces and how it remediates.

    Start here. Returns each check's violation type, the CloudTrail event that
    triggers it, what it detects and what it does about it, plus the metrics the
    engine publishes. Makes no AWS API calls.
    """
    return _describe_engine_rules()


@mcp.tool()
def get_compliance_posture(hours: int = 24) -> dict:
    """Summarise violations, remediations, exemptions and undetermined checks.

    Reads the engine's CloudWatch metrics over the last `hours` hours and
    returns totals plus a breakdown by violation type. An empty result is
    flagged as ambiguous rather than reported as clean.
    """
    return _get_compliance_posture(hours=hours)


@mcp.tool()
def search_compliance_logs(pattern: str = '', hours: int = 24, limit: int = 50) -> dict:
    """Search the engine's structured logs, optionally filtered by a text pattern.

    Returns records carrying the violation type, the actor who triggered it and
    the resource involved. Use this to answer what happened and who did it.
    """
    return _search_compliance_logs(pattern=pattern, hours=hours, limit=limit)


@mcp.tool()
def get_resource_history(resource_id: str, hours: int = 168) -> dict:
    """Everything the engine has logged about one resource.

    Accepts an EC2 instance id, a security group id or a bucket name. An empty
    history means the resource was never evaluated, not that it is compliant.
    """
    return _get_resource_history(resource_id=resource_id, hours=hours)


@mcp.tool()
def get_resource_state(resource_id: str) -> dict:
    """Read one resource's current compliance state directly from AWS.

    Accepts an EC2 instance id (i-...), a security group id (sg-...) or an S3
    bucket name. Applies the same rules the engine applies. A compliant value of
    null means undetermined.
    """
    return _get_resource_state(resource_id=resource_id)


@mcp.tool()
def list_exemptions() -> dict:
    """List resources currently tagged to bypass compliance checks.

    The exemption tag makes the engine skip a resource entirely, and it is
    granted by ordinary tagging permissions. A count of null means the lookup
    failed, not that there are none.
    """
    return _list_exemptions()


def main() -> None:
    mcp.run(transport='stdio')


if __name__ == '__main__':
    main()
