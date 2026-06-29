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
    def test_unencrypted_volume_terminates_instance(
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
        mock_ec2.terminate_instances.assert_called_once_with(
            InstanceIds=['i-0abc1234567890def']
        )
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
        mock_metric.assert_not_called()

    @patch('rules.ec2_rules._get_client')
    def test_exempt_instance_is_skipped(self, mock_factory, run_instances_detail):
        mock_ec2 = MagicMock()
        mock_factory.return_value = mock_ec2
        mock_ec2.describe_instances.return_value = _mock_instance(
            encrypted=False,
            tags=[{'Key': 'ComplianceExempt', 'Value': 'true'}],
        )

        from rules.ec2_rules import handle_run_instances
        result = handle_run_instances(run_instances_detail)

        assert result['results'][0]['status'] == 'exempt'
        mock_ec2.terminate_instances.assert_not_called()

    @patch('rules.ec2_rules._get_client')
    def test_missing_instance_ids_returns_error(self, mock_factory):
        mock_factory.return_value = MagicMock()
        from rules.ec2_rules import handle_run_instances
        result = handle_run_instances({'userIdentity': {'arn': ''}, 'responseElements': {}})
        assert result['status'] == 'error'

    @patch('rules.ec2_rules.send_alert')
    @patch('rules.ec2_rules.publish_violation')
    @patch('rules.ec2_rules._get_client')
    def test_termination_failure_is_reported(
        self, mock_factory, mock_metric, mock_alert, run_instances_detail
    ):
        mock_ec2 = MagicMock()
        mock_factory.return_value = mock_ec2
        mock_ec2.describe_instances.return_value = _mock_instance(encrypted=False)
        mock_ec2.describe_volumes.return_value = _mock_volume(encrypted=False)
        mock_ec2.terminate_instances.side_effect = _client_error('UnauthorizedOperation')

        from rules.ec2_rules import handle_run_instances
        result = handle_run_instances(run_instances_detail)

        assert result['results'][0]['status'] == 'remediation_failed'
        mock_metric.assert_called_once_with('EC2_UNENCRYPTED_EBS', 'i-0abc1234567890def', False)
