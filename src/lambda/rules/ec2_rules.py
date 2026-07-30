import logging

import boto3
from botocore.exceptions import ClientError

from utils.cloudwatch_utils import publish_violation
from utils.notifier import send_alert

logger = logging.getLogger(__name__)

EXEMPT_TAG_KEY = 'ComplianceExempt'
EXEMPT_TAG_VALUE = 'true'

_ec2_client = None


def _get_client():
    global _ec2_client
    if _ec2_client is None:
        _ec2_client = boto3.client('ec2')
    return _ec2_client


def _get_instance_ids(detail: dict) -> list[str]:
    items = (
        detail.get('responseElements', {})
              .get('instancesSet', {})
              .get('items', [])
    )
    return [item['instanceId'] for item in items]


def _is_exempt(instance_id: str) -> bool:
    try:
        response = _get_client().describe_instances(InstanceIds=[instance_id])
        tags = response['Reservations'][0]['Instances'][0].get('Tags', [])
        tag_map = {t['Key']: t['Value'] for t in tags}
        return tag_map.get(EXEMPT_TAG_KEY, '').lower() == EXEMPT_TAG_VALUE
    except (ClientError, IndexError, KeyError):
        return False


def _has_unencrypted_volume(instance_id: str) -> bool:
    ec2 = _get_client()
    response = ec2.describe_instances(InstanceIds=[instance_id])
    instance = response['Reservations'][0]['Instances'][0]

    for bdm in instance.get('BlockDeviceMappings', []):
        volume_id = bdm['Ebs']['VolumeId']
        vol = ec2.describe_volumes(VolumeIds=[volume_id])['Volumes'][0]
        if not vol.get('Encrypted', False):
            return True
    return False


def handle_run_instances(detail: dict) -> dict:
    actor = detail.get('userIdentity', {}).get('arn', 'unknown')
    instance_ids = _get_instance_ids(detail)

    if not instance_ids:
        logger.error('RunInstances event has no instance IDs in responseElements')
        return {'status': 'error', 'reason': 'no_instances_in_event'}

    results = []
    for instance_id in instance_ids:
        if _is_exempt(instance_id):
            results.append({'instance': instance_id, 'status': 'exempt'})
            continue

        try:
            is_violation = _has_unencrypted_volume(instance_id)
        except Exception as exc:
            logger.error('Could not check volume encryption', extra={
                'instance_id': instance_id,
                'error': str(exc),
            })
            results.append({'instance': instance_id, 'status': 'error', 'reason': str(exc)})
            continue

        if not is_violation:
            results.append({'instance': instance_id, 'status': 'compliant'})
            continue

        violation_type = 'EC2_UNENCRYPTED_EBS'
        logger.warning('Violation detected', extra={
            'violation': violation_type,
            'instance_id': instance_id,
            'actor': actor,
        })

        try:
            _get_client().terminate_instances(InstanceIds=[instance_id])
            remediated = True
            action = 'Instance terminated: unencrypted EBS volume detected'
            logger.info('Remediation applied', extra={
                'instance_id': instance_id,
                'action': action,
            })
        except ClientError as exc:
            remediated = False
            action = f'Termination failed: {exc}'
            logger.error('Remediation failed', extra={
                'instance_id': instance_id,
                'error': str(exc),
            })

        publish_violation(violation_type, instance_id, remediated)
        send_alert(violation_type, instance_id, actor, action, remediated)

        results.append({
            'instance': instance_id,
            'status': 'remediated' if remediated else 'remediation_failed',
            'violation': violation_type,
            'action': action,
        })

    return {'status': 'processed', 'results': results}


_HANDLERS = {
    'RunInstances': handle_run_instances,
}


def evaluate(event_name: str, detail: dict) -> dict:
    handler = _HANDLERS.get(event_name)
    if handler:
        return handler(detail)
    return {'status': 'no_rule', 'event': event_name}
