import logging
from datetime import datetime, timezone

import boto3

logger = logging.getLogger(__name__)

NAMESPACE = 'ComplianceEngine'

_client = None


def _get_client():
    global _client
    if _client is None:
        _client = boto3.client('cloudwatch')
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
