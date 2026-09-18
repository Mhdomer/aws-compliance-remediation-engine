"""Which resources are currently bypassing compliance checks.

Pairs with the ExemptionsApplied metric. The metric says exemptions are being
used; this says which resources currently carry one.
"""

from botocore.exceptions import ClientError

from mcp_server.aws_clients import read_only_client
from mcp_server.config import load_config
from mcp_server.engine_source import LAMBDA_SRC  # noqa: F401  (sets sys.path)

from rules import ec2_rules  # noqa: E402
from utils.exemption import evaluate_exemption  # noqa: E402

MAX_PAGES = 20


def _client():
    return read_only_client('resourcegroupstaggingapi', load_config().region)


def _service_from_arn(arn: str) -> str:
    # arn:partition:service:region:account:resource
    parts = arn.split(':')
    return parts[2] if len(parts) > 2 else 'unknown'


def list_exemptions() -> dict:
    """List every resource currently tagged to bypass compliance checks.

    A count of null means the lookup failed, which is not the same as none
    being found.
    """
    client = _client()
    resources = []
    token = ''

    try:
        for _ in range(MAX_PAGES):
            kwargs = {
                'TagFilters': [{
                    'Key': ec2_rules.EXEMPT_TAG_KEY,
                    'Values': [ec2_rules.EXEMPT_TAG_VALUE],
                }],
            }
            if token:
                kwargs['PaginationToken'] = token

            response = client.get_resources(**kwargs)

            for item in response.get('ResourceTagMappingList', []):
                arn = item.get('ResourceARN', '')
                tags = {
                    t.get('Key'): t.get('Value', '')
                    for t in item.get('Tags', [])
                }
                # The tag filter finds anything carrying the tag. Whether it
                # still counts depends on the expiry, and reporting a lapsed
                # exemption as active would overstate the bypass.
                exempt, status = evaluate_exemption(tags)
                resources.append({
                    'arn': arn,
                    'service': _service_from_arn(arn),
                    'exempt': exempt,
                    'status': status,
                    'tags': tags,
                })

            token = response.get('PaginationToken', '')
            if not token:
                break
    except ClientError as exc:
        code = exc.response.get('Error', {}).get('Code', 'Unknown')
        return {
            'count': None,
            'active_count': None,
            'rejected_count': None,
            'resources': [],
            'error': f'{code}: could not list tagged resources',
            'note': (
                'The lookup failed, so this is not evidence that no exemptions '
                'exist. tag:GetResources is required.'
            ),
        }

    active = [r for r in resources if r['exempt']]

    return {
        'count': len(resources),
        'active_count': len(active),
        'rejected_count': len(resources) - len(active),
        'resources': resources,
        'tag': f'{ec2_rules.EXEMPT_TAG_KEY}={ec2_rules.EXEMPT_TAG_VALUE}',
        'note': (
            'This tag makes the engine skip a resource entirely. It is granted '
            'by ordinary tagging permissions (s3:PutBucketTagging, '
            'ec2:CreateTags), which are handed out for cost allocation by '
            'people who may not know they also disable compliance checks. '
            'Treat every entry here as a deliberate bypass that someone should '
            'be able to justify.'
        ),
    }
