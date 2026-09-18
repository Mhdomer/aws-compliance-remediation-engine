from unittest.mock import MagicMock, patch

import pytest


def _series(label: str, values: list[float]) -> dict:
    return {'Id': 'q', 'Label': label, 'Values': values, 'StatusCode': 'Complete'}


@pytest.fixture
def cw():
    from mcp_server.tools import posture
    client = MagicMock()
    with patch.object(posture, '_client', return_value=client):
        yield client


@pytest.fixture(autouse=True)
def region(monkeypatch):
    monkeypatch.setenv('COMPLIANCE_REGION', 'us-east-1')


class TestGetCompliancePosture:
    def test_totals_are_summed_per_metric(self, cw):
        from mcp_server.tools.posture import get_compliance_posture
        cw.get_metric_data.return_value = {'MetricDataResults': [
            _series('S3_PUBLIC_ACL ViolationsDetected', [2.0, 3.0]),
            _series('EC2_UNENCRYPTED_EBS ViolationsDetected', [1.0]),
            _series('S3_PUBLIC_ACL RemediationsApplied', [5.0]),
        ]}

        result = get_compliance_posture(hours=24)

        assert result['totals']['ViolationsDetected'] == 6
        assert result['totals']['RemediationsApplied'] == 5

    def test_breakdown_is_grouped_by_violation_type(self, cw):
        from mcp_server.tools.posture import get_compliance_posture
        cw.get_metric_data.return_value = {'MetricDataResults': [
            _series('S3_PUBLIC_ACL ViolationsDetected', [2.0]),
            _series('S3_PUBLIC_ACL RemediationsFailed', [1.0]),
            _series('EC2_UNENCRYPTED_EBS ViolationsDetected', [4.0]),
        ]}

        result = get_compliance_posture(hours=24)

        assert result['by_type']['S3_PUBLIC_ACL'] == {
            'ViolationsDetected': 2, 'RemediationsFailed': 1
        }
        assert result['by_type']['EC2_UNENCRYPTED_EBS'] == {'ViolationsDetected': 4}

    def test_window_is_reported_back(self, cw):
        from mcp_server.tools.posture import get_compliance_posture
        cw.get_metric_data.return_value = {'MetricDataResults': []}

        result = get_compliance_posture(hours=6)

        assert result['window_hours'] == 6
        assert result['region'] == 'us-east-1'

    def test_silence_is_flagged_as_ambiguous(self, cw):
        from mcp_server.tools.posture import get_compliance_posture
        cw.get_metric_data.return_value = {'MetricDataResults': []}

        result = get_compliance_posture(hours=24)

        # Zero violations and a broken event pipeline look identical from here.
        # Saying so is the whole point; a model must not report "all clear".
        assert result['totals'] == {}
        assert 'CloudTrail' in result['warning']

    def test_data_present_means_no_warning(self, cw):
        from mcp_server.tools.posture import get_compliance_posture
        cw.get_metric_data.return_value = {'MetricDataResults': [
            _series('S3_PUBLIC_ACL ViolationsDetected', [1.0]),
        ]}

        result = get_compliance_posture(hours=24)

        assert result.get('warning') is None

    def test_queries_the_engines_namespace(self, cw):
        from mcp_server.tools.posture import get_compliance_posture
        from utils.cloudwatch_utils import NAMESPACE
        cw.get_metric_data.return_value = {'MetricDataResults': []}

        get_compliance_posture(hours=24)

        _, kwargs = cw.get_metric_data.call_args
        expressions = ' '.join(q['Expression'] for q in kwargs['MetricDataQueries'])
        assert NAMESPACE in expressions

    def test_all_five_engine_metrics_are_requested(self, cw):
        from mcp_server.tools.posture import get_compliance_posture
        cw.get_metric_data.return_value = {'MetricDataResults': []}

        get_compliance_posture(hours=24)

        _, kwargs = cw.get_metric_data.call_args
        expressions = ' '.join(q['Expression'] for q in kwargs['MetricDataQueries'])
        for metric in ('ViolationsDetected', 'RemediationsApplied',
                       'RemediationsFailed', 'DetectionsUndetermined',
                       'ExemptionsApplied'):
            assert metric in expressions, f'{metric} not queried'

    def test_hours_is_clamped_to_something_sane(self, cw):
        from mcp_server.tools.posture import get_compliance_posture
        cw.get_metric_data.return_value = {'MetricDataResults': []}

        # A model may pass anything; CloudWatch rejects absurd windows with an
        # opaque error, so clamp rather than forwarding it.
        assert get_compliance_posture(hours=0)['window_hours'] == 1
        assert get_compliance_posture(hours=99999)['window_hours'] == 720
