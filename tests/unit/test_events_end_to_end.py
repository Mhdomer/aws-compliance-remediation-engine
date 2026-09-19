"""Drive the captured CloudTrail fixtures through lambda_handler.

The unit tests build event payloads by hand, which means they can only be wrong
in the same way the code is wrong. These run the real recorded shapes end to
end, which is what catches a mistaken assumption about how CloudTrail renders a
request — the class of bug that produced the ipPermissions.items and
ServerSideEncryptionConfiguration.Rule comments in the rule modules.

boto3 is mocked throughout; nothing here touches AWS.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

EVENTS_DIR = Path(__file__).resolve().parents[1] / 'events'
FIXTURES = sorted(EVENTS_DIR.glob('*.json'))


def load(name: str) -> dict:
    return json.loads((EVENTS_DIR / name).read_text(encoding='utf-8'))


@pytest.fixture(autouse=True)
def _silence_outputs():
    """Metrics and notifications are asserted elsewhere; keep them off the wire."""
    targets = [
        'rules.s3_rules.publish_violation', 'rules.s3_rules.send_alert',
        'rules.s3_rules.publish_exemption', 'rules.s3_rules.send_notice',
        'rules.ec2_rules.publish_violation', 'rules.ec2_rules.send_alert',
        'rules.ec2_rules.publish_exemption', 'rules.ec2_rules.send_notice',
        'rules.ec2_rules.publish_detection_undetermined',
        'rules.sg_rules.publish_violation', 'rules.sg_rules.send_alert',
    ]
    patchers = [patch(t) for t in targets]
    for p in patchers:
        p.start()
    yield
    for p in patchers:
        p.stop()


class TestFixturesAreRoutable:
    @pytest.mark.parametrize('fixture', FIXTURES, ids=lambda p: p.stem)
    def test_every_fixture_reaches_a_rule(self, fixture):
        import handler
        event = json.loads(fixture.read_text(encoding='utf-8'))

        key = (event['source'], event['detail']['eventName'])
        assert key in handler._RULE_REGISTRY, (
            f'{fixture.name} routes to {key}, which no rule handles'
        )

    def test_there_is_a_fixture_for_every_registered_rule(self):
        import handler
        covered = {
            (json.loads(f.read_text(encoding='utf-8'))['source'],
             json.loads(f.read_text(encoding='utf-8'))['detail']['eventName'])
            for f in FIXTURES
        }
        assert covered == set(handler._RULE_REGISTRY)


class TestS3PublicAcl:
    def test_public_acl_event_is_remediated(self):
        import handler
        from rules import s3_rules

        s3 = MagicMock()
        s3.get_bucket_tagging.return_value = {'TagSet': []}

        with patch.object(s3_rules, '_get_client', return_value=s3):
            result = handler.lambda_handler(load('s3_public_acl_event.json'), None)

        assert result['status'] == 'remediated'
        assert result['resource'] == 'my-sensitive-data-bucket'
        # The grant in the fixture is an AllUsers URI inside
        # AccessControlPolicy.AccessControlList.Grant.
        s3.put_public_access_block.assert_called_once()
        _, kwargs = s3.put_public_access_block.call_args
        assert kwargs['PublicAccessBlockConfiguration']['BlockPublicAcls'] is True


class TestS3WeakEncryption:
    def test_aes256_event_is_remediated_to_kms(self, monkeypatch):
        import handler
        from rules import s3_rules

        monkeypatch.setenv('REQUIRED_KMS_KEY_ARN',
                           'arn:aws:kms:us-east-1:123456789012:key/mandated')
        s3 = MagicMock()
        s3.get_bucket_tagging.return_value = {'TagSet': []}

        with patch.object(s3_rules, '_get_client', return_value=s3):
            result = handler.lambda_handler(
                load('s3_put_bucket_encryption_event.json'), None
            )

        assert result['status'] == 'remediated'
        _, kwargs = s3.put_bucket_encryption.call_args
        applied = kwargs['ServerSideEncryptionConfiguration']['Rules'][0]
        assert applied['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] == 'aws:kms'


class TestEc2RunInstances:
    def test_unencrypted_instance_is_stopped_and_tagged(self):
        import handler
        from rules import ec2_rules

        ec2 = MagicMock()
        ec2.describe_instances.return_value = {'Reservations': [{'Instances': [{
            'State': {'Name': 'running'},
            'Tags': [],
            'BlockDeviceMappings': [{'Ebs': {'VolumeId': 'vol-0abc123'}}],
        }]}]}
        ec2.describe_volumes.return_value = {'Volumes': [{'Encrypted': False}]}

        with patch.object(ec2_rules, '_get_client', return_value=ec2):
            result = handler.lambda_handler(load('ec2_run_instances_event.json'), None)

        assert result['status'] == 'processed'
        assert result['results'][0]['status'] == 'remediated'
        # The instance id comes from responseElements.instancesSet.items.
        ec2.stop_instances.assert_called_once_with(InstanceIds=['i-0abcdef1234567890'])
        ec2.terminate_instances.assert_not_called()
        ec2.create_tags.assert_called_once()


class TestSgIngress:
    def test_open_ssh_rule_is_revoked(self):
        import handler
        from rules import sg_rules

        ec2 = MagicMock()
        with patch.object(sg_rules, '_get_client', return_value=ec2):
            result = handler.lambda_handler(load('sg_ingress_event.json'), None)

        assert result['status'] == 'processed'
        assert result['results'][0]['violation'] == 'SG_OPEN_PORT_22'
        assert result['results'][0]['status'] == 'remediated'

        # ipPermissions, ipRanges and ipv6Ranges are all {"items": [...]} on the
        # wire. Getting that wrong is what this fixture exists to catch.
        ec2.revoke_security_group_ingress.assert_called_once()
        _, kwargs = ec2.revoke_security_group_ingress.call_args
        assert kwargs['GroupId'] == 'sg-0abcdef1234567890'
        permission = kwargs['IpPermissions'][0]
        assert permission['FromPort'] == 22
        assert permission['IpRanges'] == [{'CidrIp': '0.0.0.0/0'}]


class TestFailedApiCallsAreNotViolations:
    """CloudTrail records calls AWS rejected, and EventBridge delivers them.

    Found on a real deployment, 2026-09-19. A put-bucket-acl that Block Public
    Access refused still produced a CloudTrail event carrying
    x-amz-acl=public-read, so the engine read the *requested* ACL, called it a
    violation, applied PutPublicAccessBlock and incremented both
    ViolationsDetected and RemediationsApplied. The bucket was never public and
    the call never succeeded.

    None of the other fixtures carry an errorCode, so nothing in the suite
    could have caught this: every recorded event was a success.

    A rejected attempt is still worth telling a human about. It is just not a
    finding, and it must never be counted as one - the same distinction
    send_notice() already draws for exemptions and undetermined checks.
    """

    def test_denied_call_never_reaches_a_rule(self):
        import handler
        event = load('s3_put_bucket_acl_denied_event.json')
        assert event['detail']['errorCode'] == 'AccessDenied'

        spy = MagicMock()
        with patch.dict(handler._RULE_REGISTRY,
                        {('aws.s3', 'PutBucketAcl'): spy}):
            with patch('handler.publish_attempt_blocked'), \
                 patch('handler.send_notice'):
                result = handler.lambda_handler(event, None)

        spy.assert_not_called()
        assert result['status'] == 'ignored'
        assert result['reason'] == 'failed_api_call'
        assert result['error_code'] == 'AccessDenied'

    def test_denied_call_publishes_an_attempt_metric_not_a_violation(self):
        import handler
        event = load('s3_put_bucket_acl_denied_event.json')

        with patch('handler.publish_attempt_blocked') as attempt, \
             patch('handler.send_notice') as notice, \
             patch('rules.s3_rules.publish_violation') as violation:
            handler.lambda_handler(event, None)

        # The denial means the existing controls worked. Counting it in
        # ViolationsDetected would report an exposure that never happened.
        violation.assert_not_called()
        attempt.assert_called_once()
        assert attempt.call_args.args[0] == 'PutBucketAcl'
        notice.assert_called_once()

    def test_the_notice_carries_the_actor(self):
        import handler
        event = load('s3_put_bucket_acl_denied_event.json')

        with patch('handler.publish_attempt_blocked'), \
             patch('handler.send_notice') as notice:
            handler.lambda_handler(event, None)

        # Someone probing an account generates these. Without the principal
        # the notice says an attempt happened and not who made it.
        assert 'developer' in str(notice.call_args)

    def test_a_successful_call_still_reaches_its_rule(self):
        import handler
        event = load('s3_public_acl_event.json')
        assert 'errorCode' not in event['detail']

        spy = MagicMock(return_value={'status': 'remediated'})
        with patch.dict(handler._RULE_REGISTRY,
                        {('aws.s3', 'PutBucketAcl'): spy}):
            result = handler.lambda_handler(event, None)

        # The guard must key on errorCode alone. Widening it to anything else
        # would stop real violations from being remediated.
        spy.assert_called_once()
        assert result['status'] == 'remediated'
