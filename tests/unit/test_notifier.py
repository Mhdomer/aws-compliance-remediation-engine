import json
from unittest.mock import MagicMock, patch

import pytest

TOPIC = 'arn:aws:sns:us-east-1:123456789012:compliance-alerts'


@pytest.fixture
def topic(monkeypatch):
    monkeypatch.setenv('SNS_TOPIC_ARN', TOPIC)


@pytest.fixture
def sns():
    from utils import notifier
    client = MagicMock()
    with patch.object(notifier, '_get_client', return_value=client):
        yield client


def _published(client) -> dict:
    _, kwargs = client.publish.call_args
    return kwargs


class TestSendAlert:
    def test_missing_topic_skips_without_building_a_client(self, monkeypatch):
        monkeypatch.delenv('SNS_TOPIC_ARN', raising=False)
        from utils import notifier

        with patch.object(notifier, '_get_client') as factory:
            notifier.send_alert('S3_PUBLIC_ACL', 'bucket', 'actor', 'did a thing', True)

        # Returning before constructing a client is what keeps local runs and
        # tests off the network.
        factory.assert_not_called()

    def test_remediated_alert_is_labelled_auto_remediated(self, topic, sns):
        from utils import notifier
        notifier.send_alert('S3_PUBLIC_ACL', 'my-bucket', 'arn:aws:iam::1:user/dev',
                            'Blocked all public access', True)

        kwargs = _published(sns)
        assert kwargs['TopicArn'] == TOPIC
        assert 'AUTO-REMEDIATED' in kwargs['Subject']
        assert 'S3_PUBLIC_ACL' in kwargs['Subject']

    def test_failed_alert_asks_for_manual_action(self, topic, sns):
        from utils import notifier
        notifier.send_alert('S3_PUBLIC_ACL', 'my-bucket', 'arn:aws:iam::1:user/dev',
                            'Remediation failed: denied', False)

        assert 'REQUIRES MANUAL ACTION' in _published(sns)['Subject']

    def test_payload_carries_the_actor_and_action(self, topic, sns):
        from utils import notifier
        notifier.send_alert('SG_OPEN_PORT_22', 'sg-123', 'arn:aws:iam::1:user/dev',
                            'Revoked 0.0.0.0/0 access to port 22', True)

        payload = json.loads(_published(sns)['Message'])
        assert payload['alert_type'] == 'ComplianceViolation'
        assert payload['violation'] == 'SG_OPEN_PORT_22'
        assert payload['resource'] == 'sg-123'
        assert payload['triggered_by'] == 'arn:aws:iam::1:user/dev'
        assert payload['action_taken'] == 'Revoked 0.0.0.0/0 access to port 22'

    def test_publish_failure_does_not_propagate(self, topic, sns):
        from utils import notifier
        sns.publish.side_effect = Exception('SNS unavailable')

        # The remediation already happened. Failing to announce it must not
        # turn a successful fix into a failed invocation and a DLQ message.
        notifier.send_alert('S3_PUBLIC_ACL', 'b', 'a', 'action', True)


class TestSendNotice:
    def test_missing_topic_skips_without_building_a_client(self, monkeypatch):
        monkeypatch.delenv('SNS_TOPIC_ARN', raising=False)
        from utils import notifier

        with patch.object(notifier, '_get_client') as factory:
            notifier.send_notice('X', 'r', 'a', 'detail', 'STATUS')

        factory.assert_not_called()

    def test_notice_is_not_labelled_a_violation(self, topic, sns):
        from utils import notifier
        notifier.send_notice(notifier.NOTICE_EXEMPTION, 'my-bucket',
                             'arn:aws:iam::1:user/dev',
                             'S3_PUBLIC_ACL skipped: bucket carries ComplianceExempt=true',
                             notifier.STATUS_EXEMPTION)

        kwargs = _published(sns)
        # An exemption is not a finding; calling it one trains people to ignore
        # the mailbox.
        assert 'Compliance Violation' not in kwargs['Subject']
        assert notifier.STATUS_EXEMPTION in kwargs['Subject']
        assert 'my-bucket' in kwargs['Subject']

    def test_notice_payload_carries_the_actor(self, topic, sns):
        from utils import notifier
        notifier.send_notice(notifier.NOTICE_UNDETERMINED, 'i-123', 'arn:aws:iam::1:user/dev',
                             'Could not determine EBS encryption', notifier.STATUS_REVIEW)

        payload = json.loads(_published(sns)['Message'])
        assert payload['alert_type'] == notifier.NOTICE_UNDETERMINED
        assert payload['resource'] == 'i-123'
        assert payload['triggered_by'] == 'arn:aws:iam::1:user/dev'
        assert payload['status'] == notifier.STATUS_REVIEW

    def test_publish_failure_does_not_propagate(self, topic, sns):
        from utils import notifier
        sns.publish.side_effect = Exception('SNS unavailable')
        notifier.send_notice('X', 'r', 'a', 'detail', 'STATUS')


class TestClientCaching:
    def test_client_is_built_once_and_reused(self):
        from utils import notifier
        notifier._client = None

        with patch('boto3.client', return_value=MagicMock()) as make_client:
            first = notifier._get_client()
            second = notifier._get_client()

        assert first is second
        from utils.aws_client import CLIENT_CONFIG
        make_client.assert_called_once_with('sns', config=CLIENT_CONFIG)
