import json
import logging
import os

import boto3

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is None:
        _client = boto3.client('sns')
    return _client


def send_alert(
    violation_type: str,
    resource_id: str,
    actor: str,
    action_taken: str,
    remediated: bool,
) -> None:
    topic_arn = os.environ.get('SNS_TOPIC_ARN', '')
    if not topic_arn:
        logger.warning('SNS_TOPIC_ARN not set — skipping alert notification')
        return

    status = 'AUTO-REMEDIATED' if remediated else 'REQUIRES MANUAL ACTION'

    payload = {
        'alert_type': 'ComplianceViolation',
        'violation': violation_type,
        'resource': resource_id,
        'triggered_by': actor,
        'action_taken': action_taken,
        'status': status,
    }

    try:
        _get_client().publish(
            TopicArn=topic_arn,
            Subject=f'[{status}] Compliance Violation: {violation_type}',
            Message=json.dumps(payload, indent=2),
        )
    except Exception as exc:
        logger.error('Failed to publish SNS alert', extra={
            'violation_type': violation_type,
            'resource_id': resource_id,
            'error': str(exc),
        })
