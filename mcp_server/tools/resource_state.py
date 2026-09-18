"""Current compliance state of one AWS resource, read directly from AWS.

Applies the same rules the engine applies, imported from the engine's own
modules rather than restated, so this cannot disagree with what the engine
would do. In particular it reproduces the engine's three-state verdict: a
resource whose state cannot be read is undetermined, never compliant.
"""

from botocore.exceptions import ClientError

from mcp_server.aws_clients import read_only_client
from mcp_server.config import load_config
from mcp_server.engine_source import LAMBDA_SRC  # noqa: F401  (sets sys.path)

from rules import ec2_rules, s3_rules, sg_rules  # noqa: E402
from utils.exemption import evaluate_exemption  # noqa: E402

EXEMPT_TAG_KEY = ec2_rules.EXEMPT_TAG_KEY
EXEMPT_TAG_VALUE = ec2_rules.EXEMPT_TAG_VALUE


def _client(service: str):
    return read_only_client(service, load_config().region)


def _exemption(tags: dict) -> tuple[bool, str]:
    """Use the engine's own rule, including expiry.

    A tool that reports "exempt" for a resource the engine would remediate is
    worse than no tool: it argues the opposite of what will happen.
    """
    return evaluate_exemption(tags)


def _instance_state(instance_id: str) -> dict:
    ec2 = _client('ec2')

    try:
        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance = response['Reservations'][0]['Instances'][0]
    except (ClientError, IndexError, KeyError) as exc:
        return {
            'resource_id': instance_id,
            'resource_type': 'ec2_instance',
            'found': False,
            'compliant': None,
            'error': str(exc),
        }

    tags = {t.get('Key'): t.get('Value', '') for t in instance.get('Tags', [])}
    _exempt, _status = _exemption(tags)
    mappings = instance.get('BlockDeviceMappings', [])
    state_name = instance.get('State', {}).get('Name', '')

    result = {
        'resource_id': instance_id,
        'resource_type': 'ec2_instance',
        'found': True,
        'state': state_name,
        'exempt': _exempt,
        'exemption_status': _status,
        'tags': tags,
    }

    if not mappings:
        if state_name in ec2_rules.SETTLED_STATES:
            result['volumes'] = []
            result['compliant'] = True
            result['note'] = 'Settled with no EBS volumes attached.'
        else:
            result['volumes'] = []
            result['compliant'] = None
            result['note'] = (
                f'Instance is {state_name or "in an unknown state"} and has no '
                'block device mappings yet, so encryption is undetermined. '
                'This is not the same as compliant.'
            )
        return result

    volume_ids = [
        m['Ebs']['VolumeId'] for m in mappings if m.get('Ebs', {}).get('VolumeId')
    ]
    volumes = _client('ec2').describe_volumes(VolumeIds=volume_ids).get('Volumes', [])

    result['volumes'] = [
        {'volume_id': v.get('VolumeId'), 'encrypted': v.get('Encrypted')}
        for v in volumes
    ]

    if len(volumes) != len(volume_ids) or any(
        'Encrypted' not in v for v in volumes
    ):
        result['compliant'] = None
        result['note'] = 'Volume encryption undetermined: AWS did not report it.'
    else:
        result['compliant'] = all(v['Encrypted'] for v in volumes)

    return result


def _security_group_state(group_id: str) -> dict:
    ec2 = _client('ec2')

    try:
        group = ec2.describe_security_groups(
            GroupIds=[group_id]
        )['SecurityGroups'][0]
    except (ClientError, IndexError, KeyError) as exc:
        return {
            'resource_id': group_id,
            'resource_type': 'security_group',
            'found': False,
            'compliant': None,
            'error': str(exc),
        }

    open_ports = set()
    for permission in group.get('IpPermissions', []):
        cidrs = (
            [r.get('CidrIp', '') for r in permission.get('IpRanges', [])] +
            [r.get('CidrIpv6', '') for r in permission.get('Ipv6Ranges', [])]
        )
        if not any(c in sg_rules.OPEN_CIDRS for c in cidrs):
            continue

        # -1 carries no port range but reaches every port, which is exactly the
        # case the engine's _port_range() handles by returning None.
        if permission.get('IpProtocol') == sg_rules.ALL_TRAFFIC:
            open_ports.update(sg_rules.RESTRICTED_PORTS)
            continue

        from_port = permission.get('FromPort', 0)
        to_port = permission.get('ToPort', 65535)
        open_ports.update(
            port for port in sg_rules.RESTRICTED_PORTS
            if from_port <= port <= to_port
        )

    return {
        'resource_id': group_id,
        'resource_type': 'security_group',
        'found': True,
        'group_name': group.get('GroupName'),
        'open_restricted_ports': sorted(open_ports),
        'compliant': not open_ports,
    }


def _bucket_state(bucket: str) -> dict:
    s3 = _client('s3')
    result = {
        'resource_id': bucket,
        'resource_type': 's3_bucket',
        'found': True,
    }

    try:
        config = s3.get_public_access_block(Bucket=bucket)
        block = config['PublicAccessBlockConfiguration']
        result['public_access_blocked'] = all([
            block.get('BlockPublicAcls'), block.get('IgnorePublicAcls'),
            block.get('BlockPublicPolicy'), block.get('RestrictPublicBuckets'),
        ])
    except ClientError as exc:
        code = exc.response.get('Error', {}).get('Code', '')
        if code in ('NoSuchPublicAccessBlockConfiguration', 'NoSuchBucket'):
            # Absent means nothing is blocked, which is the permissive default.
            result['public_access_blocked'] = False
            if code == 'NoSuchBucket':
                result['found'] = False
                result['compliant'] = None
                result['error'] = code
                return result
        else:
            result['public_access_blocked'] = None
            result['error'] = str(exc)

    try:
        rules = s3.get_bucket_encryption(
            Bucket=bucket
        )['ServerSideEncryptionConfiguration']['Rules']
        result['sse_algorithm'] = (
            rules[0].get('ApplyServerSideEncryptionByDefault', {})
                    .get('SSEAlgorithm', '')
        )
    except (ClientError, IndexError, KeyError):
        result['sse_algorithm'] = ''

    try:
        tag_set = s3.get_bucket_tagging(Bucket=bucket).get('TagSet', [])
        tags = {t.get('Key'): t.get('Value', '') for t in tag_set}
    except ClientError:
        tags = {}

    exempt, status = _exemption(tags)
    result['tags'] = tags
    result['exempt'] = exempt
    result['exemption_status'] = status

    if result['public_access_blocked'] is None:
        result['compliant'] = None
    else:
        result['compliant'] = bool(
            result['public_access_blocked']
            and result['sse_algorithm'] == s3_rules.REQUIRED_SSE_ALGORITHM
        )

    return result


def get_resource_state(resource_id: str) -> dict:
    """Read one resource's current compliance state directly from AWS.

    Accepts an EC2 instance id (i-...), a security group id (sg-...), or an S3
    bucket name. Applies the same rules the engine applies. A `compliant` value
    of null means undetermined, which is not the same as compliant.
    """
    if resource_id.startswith('i-'):
        return _instance_state(resource_id)
    if resource_id.startswith('sg-'):
        return _security_group_state(resource_id)
    return _bucket_state(resource_id)
