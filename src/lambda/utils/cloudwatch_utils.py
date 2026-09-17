import logging
from datetime import datetime, timezone

import boto3

from utils.aws_client import make_client

logger = logging.getLogger(__name__)

NAMESPACE = 'ComplianceEngine'

_client = None


def _get_client():
    global _client
    if _client is None:
        _client = make_client('cloudwatch')
    return _client


def publish_violation(violation_type: str, resource_id: str, remediated: bool) -> None:
    now = datetime.now(timezone.utc)
    dimensions = [{'Name': 'ViolationType', 'Value': violation_type}]

    metrics = [
        {
            'MetricName': 'ViolationsDetected',
            'Dimensions': dimensions,
            'Value': 1,
            'Unit': 'Count',
            'Timestamp': now,
        },
        {
            'MetricName': 'RemediationsApplied' if remediated else 'RemediationsFailed',
            'Dimensions': dimensions,
            'Value': 1,
            'Unit': 'Count',
            'Timestamp': now,
        },
    ]

    try:
        _get_client().put_metric_data(Namespace=NAMESPACE, MetricData=metrics)
    except Exception as exc:
        logger.error('Failed to publish CloudWatch metrics', extra={
            'violation_type': violation_type,
            'resource_id': resource_id,
            'error': str(exc),
        })


def publish_detection_undetermined(check_type: str, resource_id: str) -> None:
    """Record that a compliance check could not reach a verdict.

    Deliberately not ViolationsDetected: no finding was made, and counting one
    would overstate what the engine knows. This is its own metric so an alarm
    can watch for checks that are silently declining to answer — the failure
    mode where a control looks healthy because it reports nothing.
    """
    now = datetime.now(timezone.utc)

    metric = {
        'MetricName': 'DetectionsUndetermined',
        'Dimensions': [{'Name': 'CheckType', 'Value': check_type}],
        'Value': 1,
        'Unit': 'Count',
        'Timestamp': now,
    }

    try:
        _get_client().put_metric_data(Namespace=NAMESPACE, MetricData=[metric])
    except Exception as exc:
        logger.error('Failed to publish CloudWatch metrics', extra={
            'check_type': check_type,
            'resource_id': resource_id,
            'error': str(exc),
        })


def publish_exemption(check_type: str, resource_id: str) -> None:
    """Record that a resource bypassed a check via the ComplianceExempt tag.

    The tag is an authorisation boundary handed out by ordinary tagging
    permissions, so its use is exactly the thing that needs a counter. Without
    this the bypass path is quieter than the compliant path, which is backwards:
    a control's exception route needs more visibility than its happy route,
    because that is the route someone evading it will take.
    """
    now = datetime.now(timezone.utc)

    metric = {
        'MetricName': 'ExemptionsApplied',
        'Dimensions': [{'Name': 'CheckType', 'Value': check_type}],
        'Value': 1,
        'Unit': 'Count',
        'Timestamp': now,
    }

    try:
        _get_client().put_metric_data(Namespace=NAMESPACE, MetricData=[metric])
    except Exception as exc:
        logger.error('Failed to publish CloudWatch metrics', extra={
            'check_type': check_type,
            'resource_id': resource_id,
            'error': str(exc),
        })


def publish_throttled(check_type: str, resource_id: str) -> None:
    """Record that AWS refused a remediation because we were going too fast.

    Deliberately not RemediationsFailed. A throttle means the remediation was
    never attempted, so counting it as a failure both overstates the problem and
    hides the real one: the engine is running faster than the account's API
    limits allow. Those need different responses — one is a resource to fix, the
    other is a concurrency setting to lower.
    """
    now = datetime.now(timezone.utc)

    metric = {
        'MetricName': 'RemediationsThrottled',
        'Dimensions': [{'Name': 'CheckType', 'Value': check_type}],
        'Value': 1,
        'Unit': 'Count',
        'Timestamp': now,
    }

    try:
        _get_client().put_metric_data(Namespace=NAMESPACE, MetricData=[metric])
    except Exception as exc:
        logger.error('Failed to publish CloudWatch metrics', extra={
            'check_type': check_type,
            'resource_id': resource_id,
            'error': str(exc),
        })


def publish_exemption_rejected(check_type: str, resource_id: str, reason: str) -> None:
    """Record an exemption someone asked for that did not hold.

    Separate from ExemptionsApplied, and dimensioned by reason, because the
    three reasons need different responses: an expired exemption lapsed and may
    need renewing, a missing expiry predates the requirement and needs
    migrating, a malformed one is a typo somebody has to fix. Rolling them
    together would hide which.

    Without this, a resource someone believed was exempt would quietly start
    being remediated with no explanation.
    """
    now = datetime.now(timezone.utc)

    metric = {
        'MetricName': 'ExemptionsRejected',
        'Dimensions': [
            {'Name': 'CheckType', 'Value': check_type},
            {'Name': 'Reason', 'Value': reason},
        ],
        'Value': 1,
        'Unit': 'Count',
        'Timestamp': now,
    }

    try:
        _get_client().put_metric_data(Namespace=NAMESPACE, MetricData=[metric])
    except Exception as exc:
        logger.error('Failed to publish CloudWatch metrics', extra={
            'check_type': check_type,
            'resource_id': resource_id,
            'error': str(exc),
        })
