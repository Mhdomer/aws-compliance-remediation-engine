import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError


def _client_error(code: str) -> ClientError:
    return ClientError({'Error': {'Code': code, 'Message': ''}}, 'Operation')


def _make_perm(port: int, cidr: str, protocol: str = 'tcp') -> dict:
    # Real CloudTrail shape (confirmed against a live AuthorizeSecurityGroupIngress
    # event): ipRanges/ipv6Ranges are wrapped in {"items": [...]}, not bare lists.
    return {
        'ipProtocol': protocol,
        'fromPort': port,
        'toPort': port,
        'ipRanges': {'items': [{'cidrIp': cidr}]},
        'ipv6Ranges': {'items': []},
    }


@pytest.fixture
def ssh_open_detail():
    return {
        'eventName': 'AuthorizeSecurityGroupIngress',
        'userIdentity': {'arn': 'arn:aws:iam::123456789012:user/dev'},
        'requestParameters': {
            'groupId': 'sg-0abc1234567890def',
            'ipPermissions': {
                'items': [_make_perm(22, '0.0.0.0/0')]
            },
        },
    }

@pytest.fixture
def rdp_open_detail():
    return {
        'eventName': 'AuthorizeSecurityGroupIngress',
        'userIdentity': {'arn': 'arn:aws:iam::123456789012:user/dev'},
        'requestParameters': {
            'groupId': 'sg-0abc1234567890def',
            'ipPermissions': {
                'items': [_make_perm(3389, '0.0.0.0/0')]
            },
        },
    }

@pytest.fixture
def private_ssh_detail():
    return {
        'eventName': 'AuthorizeSecurityGroupIngress',
        'userIdentity': {'arn': 'arn:aws:iam::123456789012:user/dev'},
        'requestParameters': {
            'groupId': 'sg-0abc1234567890def',
            'ipPermissions': {
                'items': [_make_perm(22, '10.0.0.0/8')]
            },
        },
    }


# ─── is_public_ingress ────────────────────────────────────────────────────────

class TestIsPublicIngress:
    def test_ssh_from_anywhere_is_violation(self):
        from rules.sg_rules import is_public_ingress
        violations = is_public_ingress([_make_perm(22, '0.0.0.0/0')])
        assert len(violations) == 1
        assert violations[0]['port'] == 22

    def test_rdp_from_anywhere_is_violation(self):
        from rules.sg_rules import is_public_ingress
        violations = is_public_ingress([_make_perm(3389, '0.0.0.0/0')])
        assert len(violations) == 1
        assert violations[0]['port'] == 3389

    def test_ssh_from_private_cidr_is_compliant(self):
        from rules.sg_rules import is_public_ingress
        violations = is_public_ingress([_make_perm(22, '10.0.0.0/8')])
        assert violations == []

    def test_http_from_anywhere_is_not_restricted(self):
        from rules.sg_rules import is_public_ingress
        violations = is_public_ingress([_make_perm(80, '0.0.0.0/0')])
        assert violations == []

    def test_ipv6_open_ssh_is_violation(self):
        from rules.sg_rules import is_public_ingress
        perm = {
            'ipProtocol': 'tcp',
            'fromPort': 22,
            'toPort': 22,
            'ipRanges': {'items': []},
            'ipv6Ranges': {'items': [{'cidrIpv6': '::/0'}]},
        }
        violations = is_public_ingress([perm])
        assert len(violations) == 1

    def test_port_range_covering_ssh_is_violation(self):
        from rules.sg_rules import is_public_ingress
        perm = {
            'ipProtocol': 'tcp',
            'fromPort': 0,
            'toPort': 65535,
            'ipRanges': {'items': [{'cidrIp': '0.0.0.0/0'}]},
            'ipv6Ranges': {'items': []},
        }
        violations = is_public_ingress([perm])
        ports = {v['port'] for v in violations}
        assert 22 in ports
        assert 3389 in ports


# ─── handle_authorize_sg_ingress ─────────────────────────────────────────────

class TestHandleAuthorizeSgIngress:
    @patch('rules.sg_rules.send_alert')
    @patch('rules.sg_rules.publish_violation')
    @patch('rules.sg_rules._get_client')
    def test_open_ssh_rule_is_revoked(self, mock_factory, mock_metric, mock_alert, ssh_open_detail):
        mock_ec2 = MagicMock()
        mock_factory.return_value = mock_ec2

        from rules.sg_rules import handle_authorize_sg_ingress
        result = handle_authorize_sg_ingress(ssh_open_detail)

        assert result['status'] == 'processed'
        assert result['results'][0]['status'] == 'remediated'
        mock_ec2.revoke_security_group_ingress.assert_called_once()
        mock_metric.assert_called_once_with('SG_OPEN_PORT_22', 'sg-0abc1234567890def', True)

    @patch('rules.sg_rules.send_alert')
    @patch('rules.sg_rules.publish_violation')
    @patch('rules.sg_rules._get_client')
    def test_open_rdp_rule_is_revoked(self, mock_factory, mock_metric, mock_alert, rdp_open_detail):
        mock_ec2 = MagicMock()
        mock_factory.return_value = mock_ec2

        from rules.sg_rules import handle_authorize_sg_ingress
        result = handle_authorize_sg_ingress(rdp_open_detail)

        assert result['results'][0]['violation'] == 'SG_OPEN_PORT_3389'

    @patch('rules.sg_rules.send_alert')
    @patch('rules.sg_rules.publish_violation')
    @patch('rules.sg_rules._get_client')
    def test_private_ssh_is_compliant(self, mock_factory, mock_metric, mock_alert, private_ssh_detail):
        mock_ec2 = MagicMock()
        mock_factory.return_value = mock_ec2

        from rules.sg_rules import handle_authorize_sg_ingress
        result = handle_authorize_sg_ingress(private_ssh_detail)

        assert result['status'] == 'compliant'
        mock_ec2.revoke_security_group_ingress.assert_not_called()
        mock_metric.assert_not_called()

    @patch('rules.sg_rules.send_alert')
    @patch('rules.sg_rules.publish_violation')
    @patch('rules.sg_rules._get_client')
    def test_revoke_failure_is_reported(self, mock_factory, mock_metric, mock_alert, ssh_open_detail):
        mock_ec2 = MagicMock()
        mock_factory.return_value = mock_ec2
        mock_ec2.revoke_security_group_ingress.side_effect = _client_error('UnauthorizedOperation')

        from rules.sg_rules import handle_authorize_sg_ingress
        result = handle_authorize_sg_ingress(ssh_open_detail)

        assert result['results'][0]['status'] == 'remediation_failed'
        mock_metric.assert_called_once_with('SG_OPEN_PORT_22', 'sg-0abc1234567890def', False)

    @patch('rules.sg_rules._get_client')
    def test_missing_group_id_returns_error(self, mock_factory):
        mock_factory.return_value = MagicMock()
        from rules.sg_rules import handle_authorize_sg_ingress
        result = handle_authorize_sg_ingress({'userIdentity': {'arn': ''}, 'requestParameters': {}})
        assert result['status'] == 'error'


# ─── one revoke per underlying rule ──────────────────────────────────────────

def _aws_like_ec2():
    """An EC2 stub that mirrors how the real API answers a repeated revoke.

    Verified against moto: revoking a rule that is already gone raises
    InvalidPermission.NotFound rather than succeeding quietly.
    """
    sent = []

    def revoke(**kwargs):
        permission = kwargs['IpPermissions'][0]
        if permission in sent:
            raise ClientError(
                {'Error': {
                    'Code': 'InvalidPermission.NotFound',
                    'Message': 'The specified rule does not exist in this security group',
                }},
                'RevokeSecurityGroupIngress',
            )
        sent.append(permission)
        return {'Return': True}

    client = MagicMock()
    client.revoke_security_group_ingress.side_effect = revoke
    client.sent_permissions = sent
    return client


def _detail(permission: dict) -> dict:
    return {
        'eventName': 'AuthorizeSecurityGroupIngress',
        'userIdentity': {'arn': 'arn:aws:iam::123456789012:user/dev'},
        'requestParameters': {
            'groupId': 'sg-0abc1234567890def',
            'ipPermissions': {'items': [permission]},
        },
    }


WIDE_RANGE_PERM = {
    'ipProtocol': 'tcp',
    'fromPort': 0,
    'toPort': 65535,
    'ipRanges': {'items': [{'cidrIp': '0.0.0.0/0'}]},
    'ipv6Ranges': {'items': []},
}

# CloudTrail omits fromPort/toPort entirely when ipProtocol is -1, because an
# all-traffic rule has no port range to report.
ALL_TRAFFIC_PERM = {
    'ipProtocol': '-1',
    'ipRanges': {'items': [{'cidrIp': '0.0.0.0/0'}]},
    'ipv6Ranges': {'items': []},
}


class TestOneRevokePerRule:
    @patch('rules.sg_rules.send_alert')
    @patch('rules.sg_rules.publish_violation')
    @patch('rules.sg_rules._get_client')
    def test_wide_range_rule_sends_exactly_one_revoke(self, mock_factory, mock_metric, mock_alert):
        mock_ec2 = _aws_like_ec2()
        mock_factory.return_value = mock_ec2

        from rules.sg_rules import handle_authorize_sg_ingress
        handle_authorize_sg_ingress(_detail(WIDE_RANGE_PERM))

        # 22 and 3389 both sit inside 0-65535, but they are one ingress rule.
        assert mock_ec2.revoke_security_group_ingress.call_count == 1

    @patch('rules.sg_rules.send_alert')
    @patch('rules.sg_rules.publish_violation')
    @patch('rules.sg_rules._get_client')
    def test_wide_range_rule_reports_every_port_remediated(self, mock_factory, mock_metric, mock_alert):
        mock_factory.return_value = _aws_like_ec2()

        from rules.sg_rules import handle_authorize_sg_ingress
        result = handle_authorize_sg_ingress(_detail(WIDE_RANGE_PERM))

        statuses = {r['status'] for r in result['results']}
        assert statuses == {'remediated'}

    @patch('rules.sg_rules.send_alert')
    @patch('rules.sg_rules.publish_violation')
    @patch('rules.sg_rules._get_client')
    def test_wide_range_rule_publishes_no_failure_metric(self, mock_factory, mock_metric, mock_alert):
        mock_factory.return_value = _aws_like_ec2()

        from rules.sg_rules import handle_authorize_sg_ingress
        handle_authorize_sg_ingress(_detail(WIDE_RANGE_PERM))

        remediated_flags = [call.args[2] for call in mock_metric.call_args_list]
        assert all(remediated_flags), 'a rule that was removed must not report RemediationsFailed'

    @patch('rules.sg_rules.send_alert')
    @patch('rules.sg_rules.publish_violation')
    @patch('rules.sg_rules._get_client')
    def test_wide_range_rule_still_alerts_on_both_ports(self, mock_factory, mock_metric, mock_alert):
        mock_factory.return_value = _aws_like_ec2()

        from rules.sg_rules import handle_authorize_sg_ingress
        handle_authorize_sg_ingress(_detail(WIDE_RANGE_PERM))

        reported = {call.args[0] for call in mock_metric.call_args_list}
        assert reported == {'SG_OPEN_PORT_22', 'SG_OPEN_PORT_3389'}

    @patch('rules.sg_rules.send_alert')
    @patch('rules.sg_rules.publish_violation')
    @patch('rules.sg_rules._get_client')
    def test_all_traffic_rule_sends_exactly_one_revoke(self, mock_factory, mock_metric, mock_alert):
        mock_ec2 = _aws_like_ec2()
        mock_factory.return_value = mock_ec2

        from rules.sg_rules import handle_authorize_sg_ingress
        handle_authorize_sg_ingress(_detail(ALL_TRAFFIC_PERM))

        assert mock_ec2.revoke_security_group_ingress.call_count == 1


class TestAllTrafficProtocol:
    def test_violation_carries_no_synthetic_port_range(self):
        from rules.sg_rules import is_public_ingress
        violations = is_public_ingress([ALL_TRAFFIC_PERM])

        # A -1 rule is every port on every protocol, not TCP 0-65535.
        assert violations, 'all-traffic from 0.0.0.0/0 must be detected'
        assert all(v['from_port'] is None and v['to_port'] is None for v in violations)

    def test_all_restricted_ports_are_reported(self):
        from rules.sg_rules import is_public_ingress
        ports = {v['port'] for v in is_public_ingress([ALL_TRAFFIC_PERM])}
        assert ports == {22, 3389}

    @patch('rules.sg_rules.send_alert')
    @patch('rules.sg_rules.publish_violation')
    @patch('rules.sg_rules._get_client')
    def test_revoke_omits_port_range(self, mock_factory, mock_metric, mock_alert):
        mock_ec2 = _aws_like_ec2()
        mock_factory.return_value = mock_ec2

        from rules.sg_rules import handle_authorize_sg_ingress
        handle_authorize_sg_ingress(_detail(ALL_TRAFFIC_PERM))

        # AWS stores an all-traffic rule with no port range; send it back the
        # same shape rather than inventing 0/65535.
        permission = mock_ec2.sent_permissions[0]
        assert permission['IpProtocol'] == '-1'
        assert 'FromPort' not in permission
        assert 'ToPort' not in permission
