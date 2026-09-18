"""Replaying an event must not manufacture a failure.

Throttles now re-raise, which means Lambda retries the whole event. Any
remediation that already succeeded on the first pass gets attempted again on
the replay. If the second attempt reports failure, the engine alerts a human
about something it already fixed - which is bug 2 arriving through a new door.
"""

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError


def _error(code: str) -> ClientError:
    return ClientError({'Error': {'Code': code, 'Message': ''}}, 'Op')


TWO_RULES = {
    'userIdentity': {'arn': 'arn:aws:iam::1:user/dev'},
    'requestParameters': {
        'groupId': 'sg-1',
        'ipPermissions': {'items': [
            {'ipProtocol': 'tcp', 'fromPort': 22, 'toPort': 22,
             'ipRanges': {'items': [{'cidrIp': '0.0.0.0/0'}]},
             'ipv6Ranges': {'items': []}},
            {'ipProtocol': 'tcp', 'fromPort': 3389, 'toPort': 3389,
             'ipRanges': {'items': [{'cidrIp': '0.0.0.0/0'}]},
             'ipv6Ranges': {'items': []}},
        ]},
    },
}


@patch('rules.sg_rules.publish_throttled')
@patch('rules.sg_rules.send_alert')
@patch('rules.sg_rules.publish_violation')
@patch('rules.sg_rules._get_client')
class TestSecurityGroupReplay:
    def test_a_throttle_part_way_through_leaves_work_done(
        self, factory, metric, alert, throttled
    ):
        ec2 = MagicMock()
        # First rule revokes. Second is throttled, so the event re-raises.
        ec2.revoke_security_group_ingress.side_effect = [
            {'Return': True},
            _error('RequestLimitExceeded'),
        ]
        factory.return_value = ec2

        from rules.sg_rules import handle_authorize_sg_ingress
        with pytest.raises(ClientError):
            handle_authorize_sg_ingress(TWO_RULES)

        assert ec2.revoke_security_group_ingress.call_count == 2

    def test_replaying_an_already_revoked_rule_is_not_a_failure(
        self, factory, metric, alert, throttled
    ):
        ec2 = MagicMock()
        # The replay: rule 1 was already revoked on the first pass, so AWS says
        # it does not exist. The rule is gone, which is the outcome we wanted.
        ec2.revoke_security_group_ingress.side_effect = [
            _error('InvalidPermission.NotFound'),
            {'Return': True},
        ]
        factory.return_value = ec2

        from rules.sg_rules import handle_authorize_sg_ingress
        result = handle_authorize_sg_ingress(TWO_RULES)

        statuses = {r['status'] for r in result['results']}
        assert statuses == {'remediated'}, (
            'a rule that is already gone is the desired end state, not a failure'
        )

    def test_no_manual_action_email_for_an_absent_rule(
        self, factory, metric, alert, throttled
    ):
        ec2 = MagicMock()
        ec2.revoke_security_group_ingress.side_effect = _error(
            'InvalidPermission.NotFound'
        )
        factory.return_value = ec2

        from rules.sg_rules import handle_authorize_sg_ingress
        handle_authorize_sg_ingress(TWO_RULES)

        remediated_flags = [c.args[2] for c in metric.call_args_list]
        assert all(remediated_flags)

    def test_a_real_failure_is_still_a_failure(
        self, factory, metric, alert, throttled
    ):
        ec2 = MagicMock()
        ec2.revoke_security_group_ingress.side_effect = _error('UnauthorizedOperation')
        factory.return_value = ec2

        from rules.sg_rules import handle_authorize_sg_ingress
        result = handle_authorize_sg_ingress(TWO_RULES)

        assert {r['status'] for r in result['results']} == {'remediation_failed'}


EC2_DETAIL = {
    'userIdentity': {'arn': 'arn:aws:iam::1:user/dev'},
    'responseElements': {'instancesSet': {'items': [
        {'instanceId': 'i-1'}, {'instanceId': 'i-2'},
    ]}},
}


@patch('rules.ec2_rules.publish_throttled')
@patch('rules.ec2_rules.send_notice')
@patch('rules.ec2_rules.publish_exemption')
@patch('rules.ec2_rules.publish_detection_undetermined')
@patch('rules.ec2_rules.send_alert')
@patch('rules.ec2_rules.publish_violation')
@patch('rules.ec2_rules._get_client')
class TestEc2Replay:
    def test_replaying_a_stopped_instance_is_still_remediated(
        self, factory, metric, alert, undetermined, exemption, notice, throttled
    ):
        ec2 = MagicMock()
        # The replay sees the instance already stopped from the first pass.
        ec2.describe_instances.return_value = {'Reservations': [{'Instances': [{
            'State': {'Name': 'stopped'}, 'Tags': [],
            'BlockDeviceMappings': [{'Ebs': {'VolumeId': 'vol-a'}}],
        }]}]}
        ec2.describe_volumes.return_value = {'Volumes': [{'Encrypted': False}]}
        factory.return_value = ec2

        from rules.ec2_rules import handle_run_instances
        result = handle_run_instances(EC2_DETAIL)

        # create_tags and stop_instances are both idempotent (verified against
        # moto), so the replay re-applies them without error.
        assert {r['status'] for r in result['results']} == {'remediated'}
