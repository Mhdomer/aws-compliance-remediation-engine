"""Query the engine's structured logs with CloudWatch Logs Insights.

This works well because the Lambda emits JSON with real fields (violation,
actor, bucket, instance_id, sg_id, check, tag) rather than prose, so Logs
Insights can filter and project on them directly.
"""

import re
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from mcp_server.aws_clients import read_only_client
from mcp_server.config import load_config

# Fields the engine's structured formatter emits. Projecting them explicitly
# keeps the result readable instead of dumping raw @message blobs.
PROJECTED_FIELDS = (
    '@timestamp', 'level', 'message', 'violation', 'check', 'actor',
    'bucket', 'instance_id', 'sg_id', 'cidr', 'action', 'tag', 'reason',
)

MAX_LIMIT = 1000
POLL_ATTEMPTS = 20
POLL_SECONDS = 0.5

# Logs Insights query strings are not parameterised, so anything interpolated
# has to be sanitised. A model can pass arbitrary text here.
_UNSAFE = re.compile(r'[^A-Za-z0-9 _\-:./@*]')


def _client():
    return read_only_client('logs', load_config().region)


def _sanitise(text: str) -> str:
    return _UNSAFE.sub('', text)[:200]


def _run_query(query_string: str, hours: int) -> dict:
    """Start a Logs Insights query and wait for it, without hanging forever."""
    config = load_config()
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    client = _client()

    try:
        query_id = client.start_query(
            logGroupName=config.log_group,
            startTime=int(start.timestamp()),
            endTime=int(end.timestamp()),
            queryString=query_string,
        )['queryId']
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') == 'ResourceNotFoundException':
            return {
                'status': 'LogGroupNotFound',
                'records': [],
                'count': 0,
                'warning': (
                    f'Log group {config.log_group} does not exist in '
                    f'{config.region}. The engine is most likely not deployed '
                    'to this region, or not deployed at all. This is not '
                    'evidence that the account is compliant.'
                ),
            }
        raise

    for _ in range(POLL_ATTEMPTS):
        response = client.get_query_results(queryId=query_id)
        status = response.get('status')

        if status == 'Complete':
            records = [
                {field['field']: field['value'] for field in row}
                for row in response.get('results', [])
            ]
            return {'status': 'Complete', 'records': records, 'count': len(records)}

        if status in ('Failed', 'Cancelled', 'Timeout'):
            return {'status': status, 'records': [], 'count': 0}

        time.sleep(POLL_SECONDS)

    # Better to say the query did not finish than to block the MCP client.
    return {'status': 'Timeout', 'records': [], 'count': 0}


def search_compliance_logs(pattern: str = '', hours: int = 24, limit: int = 50) -> dict:
    """Search the compliance engine's logs, optionally filtered by a text pattern.

    Returns structured records with fields such as violation, actor and the
    resource id. Use this to answer what happened and who did it.
    """
    hours = max(1, min(int(hours), 720))
    limit = max(1, min(int(limit), MAX_LIMIT))

    lines = [f'fields {", ".join(PROJECTED_FIELDS)}']
    cleaned = _sanitise(pattern)
    if cleaned:
        lines.append(f'| filter @message like /{cleaned}/')
    lines.append('| sort @timestamp desc')
    lines.append(f'| limit {limit}')

    result = _run_query('\n'.join(lines), hours)
    result['window_hours'] = hours
    result['pattern'] = cleaned
    return result


def get_resource_history(resource_id: str, hours: int = 168) -> dict:
    """Everything the compliance engine has logged about one resource.

    Accepts an instance id, security group id or bucket name.
    """
    hours = max(1, min(int(hours), 720))
    cleaned = _sanitise(resource_id)

    query = '\n'.join([
        f'fields {", ".join(PROJECTED_FIELDS)}',
        f'| filter @message like /{cleaned}/',
        '| sort @timestamp desc',
        '| limit 200',
    ])

    result = _run_query(query, hours)
    result['resource_id'] = resource_id
    result['window_hours'] = hours

    if result['status'] == 'Complete' and not result['records']:
        result['warning'] = (
            f'The engine has never logged anything about {resource_id} in this '
            'window. That means it was never evaluated, which is not the same '
            'as having been evaluated and found compliant. Check whether the '
            'resource predates the engine, or sits in another region.'
        )

    return result
