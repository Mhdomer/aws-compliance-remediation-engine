import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError


def _client_error(code: str) -> ClientError:
    return ClientError({'Error': {'Code': code, 'Message': ''}}, 'Operation')


@pytest.fixture
def run_instances_detail():
    return {
        'eventName': 'RunInstances',
        'userIdentity': {'arn': 'arn:aws:iam::123456789012:user/dev'},
        'responseElements': {
            'instancesSet': {
                'items': [{'instanceId': 'i-0abc1234567890def'}]
            }
        },
    }


def _mock_instance(encrypted: bool, tags: list = None):
    return {
        'Reservations': [{
            'Instances': [{
                'Tags': tags or [],
                'BlockDeviceMappings': [{'Ebs': {'VolumeId': 'vol-0abc123'}}],
            }]
        }]
    }


def _mock_volume(encrypted: bool):
    return {'Volumes': [{'Encrypted': encrypted}]}


class TestHandleRunInstances:
    @patch('rules.ec2_rules.send_alert')
    @patch('rules.ec2_rules.publish_violation')
    @patch('rules.ec2_rules._get_client')
    def test_unencrypted_volume_is_remediated(
        self, mock_factory, mock_metric, mock_alert, run_instances_detail
    ):
        mock_ec2 = MagicMock()
        mock_factory.return_value = mock_ec2
        mock_ec2.describe_instances.return_value = _mock_instance(encrypted=False)
        mock_ec2.describe_volumes.return_value = _mock_volume(encrypted=False)

        from rules.ec2_rules import handle_run_instances
        result = handle_run_instances(run_instances_detail)

        assert result['status'] == 'processed'
        assert result['results'][0]['status'] == 'remediated'
        mock_ec2.stop_instances.assert_called_once_with(
            InstanceIds=['i-0abc1234567890def']
        )
        mock_ec2.terminate_instances.assert_not_called()
        mock_metric.assert_called_once_with('EC2_UNENCRYPTED_EBS', 'i-0abc1234567890def', True)

    @patch('rules.ec2_rules.send_alert')
    @patch('rules.ec2_rules.publish_violation')
    @patch('rules.ec2_rules._get_client')
    def test_encrypted_volume_is_compliant(
        self, mock_factory, mock_metric, mock_alert, run_instances_detail
    ):
        mock_ec2 = MagicMock()
        mock_factory.return_value = mock_ec2
        mock_ec2.describe_instances.return_value = _mock_instance(encrypted=True)
        mock_ec2.describe_volumes.return_value = _mock_volume(encrypted=True)

        from rules.ec2_rules import handle_run_instances
        result = handle_run_instances(run_instances_detail)

        assert result['results'][0]['status'] == 'compliant'
        mock_ec2.terminate_instances.assert_not_called()
        mock_ec2.stop_instances.assert_not_called()
        mock_metric.assert_not_called()

    @patch('rules.ec2_rules._get_client')
    def test_exempt_instance_is_skipped(self, mock_factory, run_instances_detail):
        mock_ec2 = MagicMock()
        mock_factory.return_value = mock_ec2
        mock_ec2.describe_instances.return_value = _mock_instance(
            encrypted=False,
            tags=[
                {'Key': 'ComplianceExempt', 'Value': 'true'},
                {'Key': 'ComplianceExemptUntil', 'Value': '2099-12-31'},
            ],
        )

        from rules.ec2_rules import handle_run_instances
        result = handle_run_instances(run_instances_detail)

        assert result['results'][0]['status'] == 'exempt'
        mock_ec2.terminate_instances.assert_not_called()
        mock_ec2.stop_instances.assert_not_called()

    @patch('rules.ec2_rules._get_client')
    def test_missing_instance_ids_returns_error(self, mock_factory):
        mock_factory.return_value = MagicMock()
        from rules.ec2_rules import handle_run_instances
        result = handle_run_instances({'userIdentity': {'arn': ''}, 'responseElements': {}})
        assert result['status'] == 'error'

    @patch('rules.ec2_rules.send_alert')
    @patch('rules.ec2_rules.publish_violation')
    @patch('rules.ec2_rules._get_client')
    def test_remediation_failure_is_reported(
        self, mock_factory, mock_metric, mock_alert, run_instances_detail
    ):
        mock_ec2 = MagicMock()
        mock_factory.return_value = mock_ec2
        mock_ec2.describe_instances.return_value = _mock_instance(encrypted=False)
        mock_ec2.describe_volumes.return_value = _mock_volume(encrypted=False)
        mock_ec2.stop_instances.side_effect = _client_error('UnauthorizedOperation')

        from rules.ec2_rules import handle_run_instances
        result = handle_run_instances(run_instances_detail)

        assert result['results'][0]['status'] == 'remediation_failed'
        mock_metric.assert_called_once_with('EC2_UNENCRYPTED_EBS', 'i-0abc1234567890def', False)


# ─── remediation action: stop and tag by default ─────────────────────────────

INSTANCE_ID = 'i-0abc1234567890def'


def _violating_client():
    client = MagicMock()
    client.describe_instances.return_value = _mock_instance(encrypted=False)
    client.describe_volumes.return_value = _mock_volume(encrypted=False)
    return client


def _called_operations(client) -> list[str]:
    """Ordered names of the EC2 API calls the module made."""
    return [name for name, _, _ in client.method_calls]


@patch('rules.ec2_rules.send_alert')
@patch('rules.ec2_rules.publish_violation')
@patch('rules.ec2_rules._get_client')
class TestRemediationAction:
    def test_default_stops_rather_than_terminates(
        self, mock_factory, mock_metric, mock_alert, run_instances_detail, monkeypatch
    ):
        monkeypatch.delenv('EC2_REMEDIATION_ACTION', raising=False)
        client = _violating_client()
        mock_factory.return_value = client

        from rules.ec2_rules import handle_run_instances
        result = handle_run_instances(run_instances_detail)

        assert result['results'][0]['status'] == 'remediated'
        client.stop_instances.assert_called_once_with(InstanceIds=[INSTANCE_ID])
        client.terminate_instances.assert_not_called()

    def test_instance_is_tagged_before_it_is_stopped(
        self, mock_factory, mock_metric, mock_alert, run_instances_detail, monkeypatch
    ):
        monkeypatch.delenv('EC2_REMEDIATION_ACTION', raising=False)
        client = _violating_client()
        mock_factory.return_value = client

        from rules.ec2_rules import handle_run_instances
        handle_run_instances(run_instances_detail)

        operations = _called_operations(client)
        # Tag first: if the stop fails, the instance still carries the reason.
        assert operations.index('create_tags') < operations.index('stop_instances')

    def test_tags_record_the_violation_and_the_action(
        self, mock_factory, mock_metric, mock_alert, run_instances_detail, monkeypatch
    ):
        monkeypatch.delenv('EC2_REMEDIATION_ACTION', raising=False)
        client = _violating_client()
        mock_factory.return_value = client

        from rules.ec2_rules import handle_run_instances
        handle_run_instances(run_instances_detail)

        _, kwargs = client.create_tags.call_args
        assert kwargs['Resources'] == [INSTANCE_ID]
        tags = {t['Key']: t['Value'] for t in kwargs['Tags']}
        assert tags['ComplianceViolation'] == 'EC2_UNENCRYPTED_EBS'
        assert tags['ComplianceAction'] == 'stopped'
        assert tags['ComplianceDetectedAt']

    def test_terminate_requires_explicit_opt_in(
        self, mock_factory, mock_metric, mock_alert, run_instances_detail, monkeypatch
    ):
        monkeypatch.setenv('EC2_REMEDIATION_ACTION', 'terminate')
        client = _violating_client()
        mock_factory.return_value = client

        from rules.ec2_rules import handle_run_instances
        result = handle_run_instances(run_instances_detail)

        assert result['results'][0]['status'] == 'remediated'
        client.terminate_instances.assert_called_once_with(InstanceIds=[INSTANCE_ID])
        client.stop_instances.assert_not_called()

    def test_unrecognised_action_falls_back_to_stop(
        self, mock_factory, mock_metric, mock_alert, run_instances_detail, monkeypatch
    ):
        monkeypatch.setenv('EC2_REMEDIATION_ACTION', 'obliterate')
        client = _violating_client()
        mock_factory.return_value = client

        from rules.ec2_rules import handle_run_instances
        handle_run_instances(run_instances_detail)

        # Never fail destructive: an unreadable setting must not terminate.
        client.terminate_instances.assert_not_called()
        client.stop_instances.assert_called_once()

    def test_instance_store_backed_instance_reports_why_stop_failed(
        self, mock_factory, mock_metric, mock_alert, run_instances_detail, monkeypatch
    ):
        monkeypatch.delenv('EC2_REMEDIATION_ACTION', raising=False)
        client = _violating_client()
        client.stop_instances.side_effect = _client_error('UnsupportedOperation')
        mock_factory.return_value = client

        from rules.ec2_rules import handle_run_instances
        result = handle_run_instances(run_instances_detail)

        entry = result['results'][0]
        assert entry['status'] == 'remediation_failed'
        assert 'UnsupportedOperation' in entry['action']
        mock_metric.assert_called_once_with('EC2_UNENCRYPTED_EBS', INSTANCE_ID, False)

    def test_reported_action_names_what_was_done(
        self, mock_factory, mock_metric, mock_alert, run_instances_detail, monkeypatch
    ):
        monkeypatch.delenv('EC2_REMEDIATION_ACTION', raising=False)
        mock_factory.return_value = _violating_client()

        from rules.ec2_rules import handle_run_instances
        result = handle_run_instances(run_instances_detail)

        assert 'stopped' in result['results'][0]['action'].lower()
        assert 'terminated' not in result['results'][0]['action'].lower()


# ─── detection must not fail open ────────────────────────────────────────────

def _instance(block_device_mappings, state='running', tags=None):
    return {
        'Reservations': [{
            'Instances': [{
                'State': {'Name': state},
                'Tags': tags or [],
                'BlockDeviceMappings': block_device_mappings,
            }]
        }]
    }


@patch('rules.ec2_rules.send_notice')
@patch('rules.ec2_rules.publish_detection_undetermined')
@patch('rules.ec2_rules.send_alert')
@patch('rules.ec2_rules.publish_violation')
@patch('rules.ec2_rules._get_client')
class TestDetectionCannotFailOpen:
    def test_pending_instance_with_no_mappings_is_undetermined(
        self, mock_factory, mock_metric, mock_alert, mock_undetermined, mock_notice, run_instances_detail
    ):
        client = MagicMock()
        # A pending instance has not had its volumes attached yet, so an empty
        # list means "cannot tell", not "nothing to check".
        client.describe_instances.return_value = _instance([], state='pending')
        mock_factory.return_value = client

        from rules.ec2_rules import handle_run_instances
        result = handle_run_instances(run_instances_detail)

        assert result['results'][0]['status'] == 'undetermined'

    def test_undetermined_instance_is_not_remediated(
        self, mock_factory, mock_metric, mock_alert, mock_undetermined, mock_notice, run_instances_detail
    ):
        client = MagicMock()
        client.describe_instances.return_value = _instance([], state='pending')
        mock_factory.return_value = client

        from rules.ec2_rules import handle_run_instances
        handle_run_instances(run_instances_detail)

        # We do not know there is a violation, so we must not act on one.
        client.stop_instances.assert_not_called()
        client.terminate_instances.assert_not_called()

    def test_undetermined_is_not_counted_as_a_violation(
        self, mock_factory, mock_metric, mock_alert, mock_undetermined, mock_notice, run_instances_detail
    ):
        client = MagicMock()
        client.describe_instances.return_value = _instance([], state='pending')
        mock_factory.return_value = client

        from rules.ec2_rules import handle_run_instances
        handle_run_instances(run_instances_detail)

        # ViolationsDetected would claim a finding we never made.
        mock_metric.assert_not_called()

    def test_settled_instance_with_no_ebs_volumes_is_compliant(
        self, mock_factory, mock_metric, mock_alert, mock_undetermined, mock_notice, run_instances_detail
    ):
        client = MagicMock()
        # Running and genuinely no EBS volumes: instance-store only.
        client.describe_instances.return_value = _instance([], state='running')
        mock_factory.return_value = client

        from rules.ec2_rules import handle_run_instances
        result = handle_run_instances(run_instances_detail)

        assert result['results'][0]['status'] == 'compliant'

    def test_unknown_state_with_no_mappings_is_undetermined(
        self, mock_factory, mock_metric, mock_alert, mock_undetermined, mock_notice, run_instances_detail
    ):
        client = MagicMock()
        client.describe_instances.return_value = {
            'Reservations': [{'Instances': [{'Tags': [], 'BlockDeviceMappings': []}]}]
        }
        mock_factory.return_value = client

        from rules.ec2_rules import handle_run_instances
        result = handle_run_instances(run_instances_detail)

        # No State field means we cannot rule out that it is still pending.
        assert result['results'][0]['status'] == 'undetermined'

    def test_mapping_without_a_volume_id_is_undetermined(
        self, mock_factory, mock_metric, mock_alert, mock_undetermined, mock_notice, run_instances_detail
    ):
        client = MagicMock()
        client.describe_instances.return_value = _instance([{'DeviceName': '/dev/sda1'}])
        mock_factory.return_value = client

        from rules.ec2_rules import handle_run_instances
        result = handle_run_instances(run_instances_detail)

        assert result['results'][0]['status'] == 'undetermined'

    def test_volume_missing_from_the_response_is_undetermined(
        self, mock_factory, mock_metric, mock_alert, mock_undetermined, mock_notice, run_instances_detail
    ):
        client = MagicMock()
        client.describe_instances.return_value = _instance([
            {'Ebs': {'VolumeId': 'vol-a'}},
            {'Ebs': {'VolumeId': 'vol-b'}},
        ])
        # AWS answered about one of the two volumes we asked about.
        client.describe_volumes.return_value = {'Volumes': [{'Encrypted': True}]}
        mock_factory.return_value = client

        from rules.ec2_rules import handle_run_instances
        result = handle_run_instances(run_instances_detail)

        assert result['results'][0]['status'] == 'undetermined'

    def test_volume_without_an_encrypted_field_is_undetermined(
        self, mock_factory, mock_metric, mock_alert, mock_undetermined, mock_notice, run_instances_detail
    ):
        client = MagicMock()
        client.describe_instances.return_value = _instance([{'Ebs': {'VolumeId': 'vol-a'}}])
        client.describe_volumes.return_value = {'Volumes': [{'VolumeId': 'vol-a'}]}
        mock_factory.return_value = client

        from rules.ec2_rules import handle_run_instances
        result = handle_run_instances(run_instances_detail)

        # Absent is not the same as False, and guessing either way is wrong.
        assert result['results'][0]['status'] == 'undetermined'

    def test_instance_is_described_only_once(
        self, mock_factory, mock_metric, mock_alert, mock_undetermined, mock_notice, run_instances_detail
    ):
        client = MagicMock()
        client.describe_instances.return_value = _instance([{'Ebs': {'VolumeId': 'vol-a'}}])
        client.describe_volumes.return_value = {'Volumes': [{'Encrypted': True}]}
        mock_factory.return_value = client

        from rules.ec2_rules import handle_run_instances
        handle_run_instances(run_instances_detail)

        # The exemption check and the volume check used to fetch it separately.
        assert client.describe_instances.call_count == 1

    def test_all_volumes_are_described_in_one_call(
        self, mock_factory, mock_metric, mock_alert, mock_undetermined, mock_notice, run_instances_detail
    ):
        client = MagicMock()
        client.describe_instances.return_value = _instance([
            {'Ebs': {'VolumeId': 'vol-a'}},
            {'Ebs': {'VolumeId': 'vol-b'}},
        ])
        client.describe_volumes.return_value = {
            'Volumes': [{'Encrypted': True}, {'Encrypted': True}]
        }
        mock_factory.return_value = client

        from rules.ec2_rules import handle_run_instances
        handle_run_instances(run_instances_detail)

        client.describe_volumes.assert_called_once_with(VolumeIds=['vol-a', 'vol-b'])


# ─── an undetermined verdict has to be visible ───────────────────────────────

@patch('rules.ec2_rules.publish_detection_undetermined')
@patch('rules.ec2_rules.send_notice')
@patch('rules.ec2_rules.publish_violation')
@patch('rules.ec2_rules._get_client')
class TestUndeterminedIsReported:
    def test_a_detection_metric_is_published(
        self, mock_factory, mock_metric, mock_notice, mock_undetermined, run_instances_detail
    ):
        client = MagicMock()
        client.describe_instances.return_value = _instance([], state='pending')
        mock_factory.return_value = client

        from rules.ec2_rules import handle_run_instances
        handle_run_instances(run_instances_detail)

        mock_undetermined.assert_called_once_with('EC2_UNENCRYPTED_EBS', INSTANCE_ID)
        # Still not a violation: we never made that finding.
        mock_metric.assert_not_called()

    def test_an_alert_asks_for_manual_review(
        self, mock_factory, mock_metric, mock_notice, mock_undetermined, run_instances_detail
    ):
        client = MagicMock()
        client.describe_instances.return_value = _instance([], state='pending')
        mock_factory.return_value = client

        from rules.ec2_rules import handle_run_instances
        handle_run_instances(run_instances_detail)

        mock_notice.assert_called_once()
        args, _ = mock_notice.call_args
        assert args[1] == INSTANCE_ID
        assert args[4] == 'REVIEW REQUIRED'

    def test_compliant_instance_publishes_no_detection_metric(
        self, mock_factory, mock_metric, mock_notice, mock_undetermined, run_instances_detail
    ):
        client = MagicMock()
        client.describe_instances.return_value = _instance([{'Ebs': {'VolumeId': 'vol-a'}}])
        client.describe_volumes.return_value = {'Volumes': [{'Encrypted': True}]}
        mock_factory.return_value = client

        from rules.ec2_rules import handle_run_instances
        handle_run_instances(run_instances_detail)

        mock_undetermined.assert_not_called()


# ─── the exemption tag is a bypass and has to be audited ─────────────────────

# An exemption now needs an expiry date; without one it is rejected.
EXEMPT_TAG = [
    {'Key': 'ComplianceExempt', 'Value': 'true'},
    {'Key': 'ComplianceExemptUntil', 'Value': '2099-12-31'},
]


@patch('rules.ec2_rules.send_notice')
@patch('rules.ec2_rules.publish_exemption')
@patch('rules.ec2_rules.publish_detection_undetermined')
@patch('rules.ec2_rules.send_alert')
@patch('rules.ec2_rules.publish_violation')
@patch('rules.ec2_rules._get_client')
class TestEc2ExemptionIsAudited:
    def test_exemption_publishes_a_metric(
        self, mock_factory, mock_metric, mock_alert, mock_undetermined,
        mock_exemption, mock_notice, run_instances_detail
    ):
        client = MagicMock()
        client.describe_instances.return_value = _instance([], tags=EXEMPT_TAG)
        mock_factory.return_value = client

        from rules.ec2_rules import handle_run_instances
        result = handle_run_instances(run_instances_detail)

        assert result['results'][0]['status'] == 'exempt'
        mock_exemption.assert_called_once_with('EC2_UNENCRYPTED_EBS', INSTANCE_ID)

    def test_exemption_sends_a_notice_naming_the_actor(
        self, mock_factory, mock_metric, mock_alert, mock_undetermined,
        mock_exemption, mock_notice, run_instances_detail
    ):
        client = MagicMock()
        client.describe_instances.return_value = _instance([], tags=EXEMPT_TAG)
        mock_factory.return_value = client

        from rules.ec2_rules import handle_run_instances
        handle_run_instances(run_instances_detail)

        mock_notice.assert_called_once()
        args, _ = mock_notice.call_args
        assert args[1] == INSTANCE_ID
        assert args[2] == 'arn:aws:iam::123456789012:user/dev'

    def test_describe_failure_is_not_silent(
        self, mock_factory, mock_metric, mock_alert, mock_undetermined,
        mock_exemption, mock_notice, run_instances_detail
    ):
        client = MagicMock()
        # A real failure, not a throttle: throttles now re-raise so the
        # event retries (see tests/unit/test_throttling_behaviour.py).
        client.describe_instances.side_effect = _client_error('UnauthorizedOperation')
        mock_factory.return_value = client

        from rules.ec2_rules import handle_run_instances
        result = handle_run_instances(run_instances_detail)

        # Caught per-instance so one bad instance does not abandon the others,
        # but it must still be visible: we could not assess this resource.
        assert result['results'][0]['status'] == 'error'
        mock_undetermined.assert_called_once_with('EC2_UNENCRYPTED_EBS', INSTANCE_ID)
        mock_notice.assert_called_once()


# ─── volume lookup failure and module entry point ────────────────────────────

@patch('rules.ec2_rules.send_notice')
@patch('rules.ec2_rules.publish_detection_undetermined')
@patch('rules.ec2_rules.send_alert')
@patch('rules.ec2_rules.publish_violation')
@patch('rules.ec2_rules._get_client')
class TestVolumeLookupFailure:
    def test_describe_volumes_failure_is_reported_as_error(
        self, mock_factory, mock_metric, mock_alert, mock_undetermined, mock_notice,
        run_instances_detail
    ):
        client = MagicMock()
        client.describe_instances.return_value = _instance([{'Ebs': {'VolumeId': 'vol-a'}}])
        client.describe_volumes.side_effect = _client_error('UnauthorizedOperation')
        mock_factory.return_value = client

        from rules.ec2_rules import handle_run_instances
        result = handle_run_instances(run_instances_detail)

        # Not remediated: we never established a violation.
        assert result['results'][0]['status'] == 'error'
        client.stop_instances.assert_not_called()
        client.terminate_instances.assert_not_called()


class TestEc2Evaluate:
    def test_unknown_event_returns_no_rule(self):
        from rules.ec2_rules import evaluate
        assert evaluate('TerminateInstances', {})['status'] == 'no_rule'

    def test_client_is_built_once_and_reused(self):
        from unittest.mock import patch as _patch
        from rules import ec2_rules
        ec2_rules._ec2_client = None
        with _patch('boto3.client', return_value=MagicMock()) as make_client:
            first = ec2_rules._get_client()
            second = ec2_rules._get_client()
        assert first is second
        from utils.aws_client import CLIENT_CONFIG
        make_client.assert_called_once_with('ec2', config=CLIENT_CONFIG)
