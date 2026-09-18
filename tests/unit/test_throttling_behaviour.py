"""Throttling must not be recorded as a permanent remediation failure.

A RequestLimitExceeded means the remediation was never attempted. Marking it
failed loses the retry that would have fixed it, and emails a human about
something the engine never tried. The resource stays exposed either way.
"""

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError


def _error(code: str) -> ClientError:
    return ClientError({'Error': {'Code': code, 'Message': 'slow down'}}, 'Op')


THROTTLE = 'RequestLimitExceeded'
REAL_FAILURE = 'UnauthorizedOperation'


# ─── security groups ─────────────────────────────────────────────────────────

SG_DETAIL = {
    'userIdentity': {'arn': 'arn:aws:iam::1:user/dev'},
    'requestParameters': {
        'groupId': 'sg-victim',
        'ipPermissions': {'items': [{
            'ipProtocol': 'tcp', 'fromPort': 22, 'toPort': 22,
            'ipRanges': {'items': [{'cidrIp': '0.0.0.0/0'}]},
            'ipv6Ranges': {'items': []},
        }]},
    },
}


@patch('rules.sg_rules.publish_throttled')
@patch('rules.sg_rules.send_alert')
@patch('rules.sg_rules.publish_violation')
@patch('rules.sg_rules._get_client')
class TestSecurityGroupThrottling:
    def test_throttle_is_raised_so_the_event_retries(
        self, factory, metric, alert, throttled
    ):
        ec2 = MagicMock()
        ec2.revoke_security_group_ingress.side_effect = _error(THROTTLE)
        factory.return_value = ec2

        from rules.sg_rules import handle_authorize_sg_ingress
        # Raising fails the invocation, so EventBridge retries and the event
        # reaches the DLQ if it keeps failing. Returning normally loses it.
        with pytest.raises(ClientError):
            handle_authorize_sg_ingress(SG_DETAIL)

    def test_throttle_does_not_publish_a_remediation_failure(
        self, factory, metric, alert, throttled
    ):
        ec2 = MagicMock()
        ec2.revoke_security_group_ingress.side_effect = _error(THROTTLE)
        factory.return_value = ec2

        from rules.sg_rules import handle_authorize_sg_ingress
        with pytest.raises(ClientError):
            handle_authorize_sg_ingress(SG_DETAIL)

        metric.assert_not_called()
        throttled.assert_called_once_with('SG_OPEN_PORT_22', 'sg-victim')

    def test_throttle_does_not_email_a_human(self, factory, metric, alert, throttled):
        ec2 = MagicMock()
        ec2.revoke_security_group_ingress.side_effect = _error(THROTTLE)
        factory.return_value = ec2

        from rules.sg_rules import handle_authorize_sg_ingress
        with pytest.raises(ClientError):
            handle_authorize_sg_ingress(SG_DETAIL)

        # No REQUIRES MANUAL ACTION for something the engine never attempted.
        # A burst would otherwise flood the one mailbox that matters.
        alert.assert_not_called()

    def test_a_real_failure_still_reports_as_before(
        self, factory, metric, alert, throttled
    ):
        ec2 = MagicMock()
        ec2.revoke_security_group_ingress.side_effect = _error(REAL_FAILURE)
        factory.return_value = ec2

        from rules.sg_rules import handle_authorize_sg_ingress
        result = handle_authorize_sg_ingress(SG_DETAIL)

        assert result['results'][0]['status'] == 'remediation_failed'
        metric.assert_called_once_with('SG_OPEN_PORT_22', 'sg-victim', False)
        alert.assert_called_once()
        throttled.assert_not_called()


# ─── S3 ──────────────────────────────────────────────────────────────────────

ACL_DETAIL = {
    'userIdentity': {'arn': 'arn:aws:iam::1:user/dev'},
    'requestParameters': {
        'bucketName': 'victim-bucket',
        'AccessControlPolicy': {'AccessControlList': {'Grant': [
            {'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}}
        ]}},
    },
}

ENCRYPTION_DETAIL = {
    'userIdentity': {'arn': 'arn:aws:iam::1:user/dev'},
    'requestParameters': {
        'bucketName': 'victim-bucket',
        'ServerSideEncryptionConfiguration': {'Rule': {
            'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}
        }},
    },
}


@patch('rules.s3_rules.publish_throttled')
@patch('rules.s3_rules.send_alert')
@patch('rules.s3_rules.publish_violation')
@patch('rules.s3_rules._get_client')
class TestS3Throttling:
    def test_acl_throttle_is_raised(self, factory, metric, alert, throttled):
        s3 = MagicMock()
        s3.get_bucket_tagging.return_value = {'TagSet': []}
        s3.put_public_access_block.side_effect = _error('SlowDown')
        factory.return_value = s3

        from rules.s3_rules import handle_put_bucket_acl
        with pytest.raises(ClientError):
            handle_put_bucket_acl(ACL_DETAIL)

        throttled.assert_called_once_with('S3_PUBLIC_ACL', 'victim-bucket')
        metric.assert_not_called()
        alert.assert_not_called()

    def test_encryption_throttle_is_raised(self, factory, metric, alert, throttled):
        s3 = MagicMock()
        s3.get_bucket_tagging.return_value = {'TagSet': []}
        s3.put_bucket_encryption.side_effect = _error('SlowDown')
        factory.return_value = s3

        from rules.s3_rules import handle_put_bucket_encryption
        with pytest.raises(ClientError):
            handle_put_bucket_encryption(ENCRYPTION_DETAIL)

        throttled.assert_called_once_with('S3_WEAK_ENCRYPTION', 'victim-bucket')

    def test_a_real_acl_failure_still_reports(self, factory, metric, alert, throttled):
        s3 = MagicMock()
        s3.get_bucket_tagging.return_value = {'TagSet': []}
        s3.put_public_access_block.side_effect = _error('AccessDenied')
        factory.return_value = s3

        from rules.s3_rules import handle_put_bucket_acl
        result = handle_put_bucket_acl(ACL_DETAIL)

        assert result['status'] == 'remediation_failed'
        throttled.assert_not_called()


# ─── EC2 ─────────────────────────────────────────────────────────────────────

EC2_DETAIL = {
    'userIdentity': {'arn': 'arn:aws:iam::1:user/dev'},
    'responseElements': {'instancesSet': {'items': [{'instanceId': 'i-victim'}]}},
}


def _violating_instance():
    return {'Reservations': [{'Instances': [{
        'State': {'Name': 'running'}, 'Tags': [],
        'BlockDeviceMappings': [{'Ebs': {'VolumeId': 'vol-a'}}],
    }]}]}


@patch('rules.ec2_rules.publish_throttled')
@patch('rules.ec2_rules.send_notice')
@patch('rules.ec2_rules.publish_detection_undetermined')
@patch('rules.ec2_rules.send_alert')
@patch('rules.ec2_rules.publish_violation')
@patch('rules.ec2_rules._get_client')
class TestEc2Throttling:
    def test_remediation_throttle_is_raised(
        self, factory, metric, alert, undetermined, notice, throttled
    ):
        ec2 = MagicMock()
        ec2.describe_instances.return_value = _violating_instance()
        ec2.describe_volumes.return_value = {'Volumes': [{'Encrypted': False}]}
        ec2.stop_instances.side_effect = _error(THROTTLE)
        factory.return_value = ec2

        from rules.ec2_rules import handle_run_instances
        # Replay on retry is safe: create_tags and stop_instances are both
        # idempotent, verified against moto.
        with pytest.raises(ClientError):
            handle_run_instances(EC2_DETAIL)

        throttled.assert_called_once_with('EC2_UNENCRYPTED_EBS', 'i-victim')
        metric.assert_not_called()

    def test_detection_throttle_is_raised_not_reported_undetermined(
        self, factory, metric, alert, undetermined, notice, throttled
    ):
        ec2 = MagicMock()
        ec2.describe_instances.side_effect = _error(THROTTLE)
        factory.return_value = ec2

        from rules.ec2_rules import handle_run_instances
        # Undetermined means "I looked and could not tell". Being throttled
        # means I never looked, and retrying would tell me.
        with pytest.raises(ClientError):
            handle_run_instances(EC2_DETAIL)

        undetermined.assert_not_called()

    def test_a_real_remediation_failure_still_reports(
        self, factory, metric, alert, undetermined, notice, throttled
    ):
        ec2 = MagicMock()
        ec2.describe_instances.return_value = _violating_instance()
        ec2.describe_volumes.return_value = {'Volumes': [{'Encrypted': False}]}
        ec2.stop_instances.side_effect = _error('UnsupportedOperation')
        factory.return_value = ec2

        from rules.ec2_rules import handle_run_instances
        result = handle_run_instances(EC2_DETAIL)

        assert result['results'][0]['status'] == 'remediation_failed'
        throttled.assert_not_called()
