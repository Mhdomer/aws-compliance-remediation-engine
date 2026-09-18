"""A rejected exemption must be checked AND reported.

Two things have to happen when someone's exemption does not hold: the resource
gets assessed like any other, and the rejection is visible so they can fix the
tag. Silently starting to check a resource someone believed was exempt is its
own kind of surprise.
"""

from unittest.mock import MagicMock, patch

import pytest

EXPIRED = {'ComplianceExempt': 'true', 'ComplianceExemptUntil': '2020-01-01'}
NO_EXPIRY = {'ComplianceExempt': 'true'}
MALFORMED = {'ComplianceExempt': 'true', 'ComplianceExemptUntil': 'whenever'}
VALID = {'ComplianceExempt': 'true', 'ComplianceExemptUntil': '2099-12-31'}


def _tag_set(tags: dict) -> dict:
    return {'TagSet': [{'Key': k, 'Value': v} for k, v in tags.items()]}


def _instance(tags: dict) -> dict:
    return {'Reservations': [{'Instances': [{
        'State': {'Name': 'running'},
        'Tags': [{'Key': k, 'Value': v} for k, v in tags.items()],
        'BlockDeviceMappings': [{'Ebs': {'VolumeId': 'vol-a'}}],
    }]}]}


ACL_DETAIL = {
    'userIdentity': {'arn': 'arn:aws:iam::1:user/dev'},
    'requestParameters': {
        'bucketName': 'victim-bucket',
        'AccessControlPolicy': {'AccessControlList': {'Grant': [
            {'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}}
        ]}},
    },
}

EC2_DETAIL = {
    'userIdentity': {'arn': 'arn:aws:iam::1:user/dev'},
    'responseElements': {'instancesSet': {'items': [{'instanceId': 'i-victim'}]}},
}


# ─── S3 ──────────────────────────────────────────────────────────────────────

@patch('rules.s3_rules.publish_exemption_rejected')
@patch('rules.s3_rules.send_notice')
@patch('rules.s3_rules.publish_exemption')
@patch('rules.s3_rules.send_alert')
@patch('rules.s3_rules.publish_violation')
@patch('rules.s3_rules._get_client')
class TestS3ExemptionExpiry:
    @pytest.mark.parametrize('tags,reason', [
        (EXPIRED, 'expired'),
        (NO_EXPIRY, 'missing_expiry'),
        (MALFORMED, 'malformed_expiry'),
    ])
    def test_a_rejected_exemption_is_remediated(
        self, factory, metric, alert, exemption, notice, rejected, tags, reason
    ):
        s3 = MagicMock()
        s3.get_bucket_tagging.return_value = _tag_set(tags)
        factory.return_value = s3

        from rules.s3_rules import handle_put_bucket_acl
        result = handle_put_bucket_acl(ACL_DETAIL)

        assert result['status'] == 'remediated'
        s3.put_public_access_block.assert_called_once()
        exemption.assert_not_called()

    @pytest.mark.parametrize('tags,reason', [
        (EXPIRED, 'expired'),
        (NO_EXPIRY, 'missing_expiry'),
        (MALFORMED, 'malformed_expiry'),
    ])
    def test_the_rejection_is_reported_with_its_reason(
        self, factory, metric, alert, exemption, notice, rejected, tags, reason
    ):
        s3 = MagicMock()
        s3.get_bucket_tagging.return_value = _tag_set(tags)
        factory.return_value = s3

        from rules.s3_rules import handle_put_bucket_acl
        handle_put_bucket_acl(ACL_DETAIL)

        # Whoever set the tag needs to know it stopped working, and the three
        # reasons need different responses.
        rejected.assert_called_once_with('S3_PUBLIC_ACL', 'victim-bucket', reason)

    def test_a_valid_exemption_still_skips(
        self, factory, metric, alert, exemption, notice, rejected
    ):
        s3 = MagicMock()
        s3.get_bucket_tagging.return_value = _tag_set(VALID)
        factory.return_value = s3

        from rules.s3_rules import handle_put_bucket_acl
        result = handle_put_bucket_acl(ACL_DETAIL)

        assert result['status'] == 'exempt'
        exemption.assert_called_once()
        rejected.assert_not_called()

    def test_an_untagged_bucket_reports_no_rejection(
        self, factory, metric, alert, exemption, notice, rejected
    ):
        s3 = MagicMock()
        s3.get_bucket_tagging.return_value = {'TagSet': []}
        factory.return_value = s3

        from rules.s3_rules import handle_put_bucket_acl
        handle_put_bucket_acl(ACL_DETAIL)

        # Nobody asked for an exemption, so there is nothing to report.
        rejected.assert_not_called()


# ─── EC2 ─────────────────────────────────────────────────────────────────────

@patch('rules.ec2_rules.publish_exemption_rejected')
@patch('rules.ec2_rules.send_notice')
@patch('rules.ec2_rules.publish_exemption')
@patch('rules.ec2_rules.publish_detection_undetermined')
@patch('rules.ec2_rules.send_alert')
@patch('rules.ec2_rules.publish_violation')
@patch('rules.ec2_rules._get_client')
class TestEc2ExemptionExpiry:
    def test_an_expired_exemption_is_remediated(
        self, factory, metric, alert, undetermined, exemption, notice, rejected
    ):
        ec2 = MagicMock()
        ec2.describe_instances.return_value = _instance(EXPIRED)
        ec2.describe_volumes.return_value = {'Volumes': [{'Encrypted': False}]}
        factory.return_value = ec2

        from rules.ec2_rules import handle_run_instances
        result = handle_run_instances(EC2_DETAIL)

        assert result['results'][0]['status'] == 'remediated'
        ec2.stop_instances.assert_called_once()
        rejected.assert_called_once_with('EC2_UNENCRYPTED_EBS', 'i-victim', 'expired')

    def test_a_missing_expiry_is_remediated(
        self, factory, metric, alert, undetermined, exemption, notice, rejected
    ):
        ec2 = MagicMock()
        ec2.describe_instances.return_value = _instance(NO_EXPIRY)
        ec2.describe_volumes.return_value = {'Volumes': [{'Encrypted': False}]}
        factory.return_value = ec2

        from rules.ec2_rules import handle_run_instances
        result = handle_run_instances(EC2_DETAIL)

        assert result['results'][0]['status'] == 'remediated'
        rejected.assert_called_once_with(
            'EC2_UNENCRYPTED_EBS', 'i-victim', 'missing_expiry'
        )

    def test_a_valid_exemption_still_skips(
        self, factory, metric, alert, undetermined, exemption, notice, rejected
    ):
        ec2 = MagicMock()
        ec2.describe_instances.return_value = _instance(VALID)
        factory.return_value = ec2

        from rules.ec2_rules import handle_run_instances
        result = handle_run_instances(EC2_DETAIL)

        assert result['results'][0]['status'] == 'exempt'
        ec2.stop_instances.assert_not_called()
        rejected.assert_not_called()
