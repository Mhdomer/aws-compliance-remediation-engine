import json
import logging
import os

import boto3

from utils.aws_client import make_client

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is None:
        _client = make_client('sns')
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


def send_notice(
    notice_type: str,
    resource_id: str,
    actor: str,
    detail: str,
    status: str,
) -> None:
    """Send an operational notice that is not a compliance finding.

    An applied exemption and an undetermined check both need a human to look,
    but neither is a violation. Routing them through send_alert() would put
    "Compliance Violation" in the subject line for something the engine never
    found, which is the sort of small inaccuracy that teaches people to stop
    reading the mailbox.
    """
    topic_arn = os.environ.get('SNS_TOPIC_ARN', '')
    if not topic_arn:
        logger.warning('SNS_TOPIC_ARN not set — skipping notice notification')
        return

    payload = {
        'alert_type': notice_type,
        'resource': resource_id,
        'triggered_by': actor,
        'detail': detail,
        'status': status,
    }

    try:
        _get_client().publish(
            TopicArn=topic_arn,
            Subject=f'[{status}] {notice_type}: {resource_id}',
            Message=json.dumps(payload, indent=2),
        )
    except Exception as exc:
        logger.error('Failed to publish SNS notice', extra={
            'notice_type': notice_type,
            'resource_id': resource_id,
            'error': str(exc),
        })


NOTICE_ATTEMPT_BLOCKED = 'ComplianceViolationAttemptBlocked'
NOTICE_EXEMPTION = 'ComplianceExemptionApplied'
NOTICE_UNDETERMINED = 'ComplianceCheckUndetermined'
STATUS_EXEMPTION = 'EXEMPTION APPLIED'
STATUS_REVIEW = 'REVIEW REQUIRED'
STATUS_BLOCKED = 'ATTEMPT BLOCKED'
