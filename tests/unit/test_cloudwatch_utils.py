from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def cw():
    from utils import cloudwatch_utils
    client = MagicMock()
    with patch.object(cloudwatch_utils, '_get_client', return_value=client):
        yield client


def _metrics(client) -> dict:
    """Published metrics keyed by name."""
    _, kwargs = client.put_metric_data.call_args
    return {m['MetricName']: m for m in kwargs['MetricData']}


def _namespace(client) -> str:
    _, kwargs = client.put_metric_data.call_args
    return kwargs['Namespace']


class TestPublishViolation:
    def test_remediated_violation_counts_detection_and_success(self, cw):
        from utils.cloudwatch_utils import publish_violation
        publish_violation('S3_PUBLIC_ACL', 'my-bucket', True)

        metrics = _metrics(cw)
        assert set(metrics) == {'ViolationsDetected', 'RemediationsApplied'}
        assert metrics['ViolationsDetected']['Value'] == 1
        assert metrics['ViolationsDetected']['Unit'] == 'Count'

    def test_failed_violation_counts_detection_and_failure(self, cw):
        from utils.cloudwatch_utils import publish_violation
        publish_violation('S3_PUBLIC_ACL', 'my-bucket', False)

        metrics = _metrics(cw)
        assert set(metrics) == {'ViolationsDetected', 'RemediationsFailed'}

    def test_violation_type_is_the_dimension(self, cw):
        from utils.cloudwatch_utils import publish_violation
        publish_violation('SG_OPEN_PORT_3389', 'sg-1', True)

        dimensions = _metrics(cw)['ViolationsDetected']['Dimensions']
        assert dimensions == [{'Name': 'ViolationType', 'Value': 'SG_OPEN_PORT_3389'}]

    def test_namespace_is_the_engine(self, cw):
        from utils.cloudwatch_utils import publish_violation
        publish_violation('S3_PUBLIC_ACL', 'b', True)
        assert _namespace(cw) == 'ComplianceEngine'

    def test_publish_failure_does_not_propagate(self, cw):
        from utils.cloudwatch_utils import publish_violation
        cw.put_metric_data.side_effect = Exception('throttled')

        # Losing a metric must not turn a completed remediation into a failed
        # invocation.
        publish_violation('S3_PUBLIC_ACL', 'b', True)


class TestPublishDetectionUndetermined:
    def test_emits_its_own_metric_not_a_violation(self, cw):
        from utils.cloudwatch_utils import publish_detection_undetermined
        publish_detection_undetermined('EC2_UNENCRYPTED_EBS', 'i-123')

        metrics = _metrics(cw)
        # Counting a violation would claim a finding that was never made.
        assert set(metrics) == {'DetectionsUndetermined'}
        assert metrics['DetectionsUndetermined']['Dimensions'] == [
            {'Name': 'CheckType', 'Value': 'EC2_UNENCRYPTED_EBS'}
        ]

    def test_publish_failure_does_not_propagate(self, cw):
        from utils.cloudwatch_utils import publish_detection_undetermined
        cw.put_metric_data.side_effect = Exception('throttled')
        publish_detection_undetermined('EC2_UNENCRYPTED_EBS', 'i-123')


class TestPublishExemption:
    def test_emits_its_own_metric_not_a_violation(self, cw):
        from utils.cloudwatch_utils import publish_exemption
        publish_exemption('S3_PUBLIC_ACL', 'my-bucket')

        metrics = _metrics(cw)
        assert set(metrics) == {'ExemptionsApplied'}
        assert metrics['ExemptionsApplied']['Dimensions'] == [
            {'Name': 'CheckType', 'Value': 'S3_PUBLIC_ACL'}
        ]

    def test_publish_failure_does_not_propagate(self, cw):
        from utils.cloudwatch_utils import publish_exemption
        cw.put_metric_data.side_effect = Exception('throttled')
        publish_exemption('S3_PUBLIC_ACL', 'b')


class TestClientCaching:
    def test_client_is_built_once_and_reused(self):
        from utils import cloudwatch_utils
        cloudwatch_utils._client = None

        with patch('boto3.client', return_value=MagicMock()) as make_client:
            first = cloudwatch_utils._get_client()
            second = cloudwatch_utils._get_client()

        assert first is second
        from utils.aws_client import CLIENT_CONFIG
        make_client.assert_called_once_with('cloudwatch', config=CLIENT_CONFIG)
