import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError


def _client_error(code: str) -> ClientError:
    return ClientError({'Error': {'Code': code, 'Message': ''}}, 'Operation')


# ─── has_public_acl ───────────────────────────────────────────────────────────

class TestHasPublicAcl:
    def test_allUsers_uri_is_violation(self):
        from rules.s3_rules import has_public_acl
        grants = [{'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}}]
        assert has_public_acl(grants) is True

    def test_authenticatedUsers_uri_is_violation(self):
        from rules.s3_rules import has_public_acl
        grants = [{'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'}}]
        assert has_public_acl(grants) is True

    def test_private_canonical_id_is_compliant(self):
        from rules.s3_rules import has_public_acl
        grants = [{'Grantee': {'ID': 'abc123def456', 'Type': 'CanonicalUser'}}]
        assert has_public_acl(grants) is False

    def test_empty_grants_is_compliant(self):
        from rules.s3_rules import has_public_acl
        assert has_public_acl([]) is False


# ─── handle_put_bucket_acl ────────────────────────────────────────────────────

@pytest.fixture
def public_acl_detail():
    return {
        'eventName': 'PutBucketAcl',
        'userIdentity': {'arn': 'arn:aws:iam::123456789012:user/dev'},
        'requestParameters': {
            'bucketName': 'test-bucket',
            'AccessControlPolicy': {
                'AccessControlList': {
                    'Grant': [{'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}}]
                }
            },
        },
    }

@pytest.fixture
def private_acl_detail():
    return {
        'eventName': 'PutBucketAcl',
        'userIdentity': {'arn': 'arn:aws:iam::123456789012:user/dev'},
        'requestParameters': {
            'bucketName': 'test-bucket',
            'AccessControlPolicy': {
                'AccessControlList': {
                    'Grant': [{'Grantee': {'ID': 'abc123', 'Type': 'CanonicalUser'}}]
                }
            },
        },
    }

@pytest.fixture
def canned_public_read_detail():
    # This is the actual CloudTrail shape for `aws s3api put-bucket-acl --acl public-read` —
    # canned ACLs never produce an AccessControlPolicy/Grant structure.
    return {
        'eventName': 'PutBucketAcl',
        'userIdentity': {'arn': 'arn:aws:iam::123456789012:user/dev'},
        'requestParameters': {
            'bucketName': 'test-bucket',
            'acl': '',
            'x-amz-acl': 'public-read',
        },
    }


class TestHandlePutBucketAcl:
    @patch('rules.s3_rules.send_alert')
    @patch('rules.s3_rules.publish_violation')
    @patch('rules.s3_rules._get_client')
    def test_public_acl_triggers_remediation(self, mock_factory, mock_metric, mock_alert, public_acl_detail):
        mock_s3 = MagicMock()
        mock_factory.return_value = mock_s3
        mock_s3.get_bucket_tagging.side_effect = _client_error('NoSuchTagSet')

        from rules.s3_rules import handle_put_bucket_acl
        result = handle_put_bucket_acl(public_acl_detail)

        assert result['status'] == 'remediated'
        mock_s3.put_public_access_block.assert_called_once()
        mock_metric.assert_called_once_with('S3_PUBLIC_ACL', 'test-bucket', True)
        mock_alert.assert_called_once()

    @patch('rules.s3_rules.send_alert')
    @patch('rules.s3_rules.publish_violation')
    @patch('rules.s3_rules._get_client')
    def test_private_acl_is_compliant(self, mock_factory, mock_metric, mock_alert, private_acl_detail):
        mock_s3 = MagicMock()
        mock_factory.return_value = mock_s3
        mock_s3.get_bucket_tagging.side_effect = _client_error('NoSuchTagSet')

        from rules.s3_rules import handle_put_bucket_acl
        result = handle_put_bucket_acl(private_acl_detail)

        assert result['status'] == 'compliant'
        mock_s3.put_public_access_block.assert_not_called()
        mock_metric.assert_not_called()

    @patch('rules.s3_rules.send_alert')
    @patch('rules.s3_rules.publish_violation')
    @patch('rules.s3_rules._get_client')
    def test_canned_public_read_acl_triggers_remediation(
        self, mock_factory, mock_metric, mock_alert, canned_public_read_detail
    ):
        mock_s3 = MagicMock()
        mock_factory.return_value = mock_s3
        mock_s3.get_bucket_tagging.side_effect = _client_error('NoSuchTagSet')

        from rules.s3_rules import handle_put_bucket_acl
        result = handle_put_bucket_acl(canned_public_read_detail)

        assert result['status'] == 'remediated'
        mock_s3.put_public_access_block.assert_called_once()
        mock_metric.assert_called_once_with('S3_PUBLIC_ACL', 'test-bucket', True)

    @patch('rules.s3_rules._get_client')
    def test_exempt_bucket_skipped(self, mock_factory, public_acl_detail):
        mock_s3 = MagicMock()
        mock_factory.return_value = mock_s3
        mock_s3.get_bucket_tagging.return_value = {
            'TagSet': [
                {'Key': 'ComplianceExempt', 'Value': 'true'},
                {'Key': 'ComplianceExemptUntil', 'Value': '2099-12-31'},
            ]
        }

        from rules.s3_rules import handle_put_bucket_acl
        result = handle_put_bucket_acl(public_acl_detail)

        assert result['status'] == 'exempt'
        mock_s3.put_public_access_block.assert_not_called()

    @patch('rules.s3_rules.send_alert')
    @patch('rules.s3_rules.publish_violation')
    @patch('rules.s3_rules._get_client')
    def test_remediation_failure_is_reported(self, mock_factory, mock_metric, mock_alert, public_acl_detail):
        mock_s3 = MagicMock()
        mock_factory.return_value = mock_s3
        mock_s3.get_bucket_tagging.side_effect = _client_error('NoSuchTagSet')
        mock_s3.put_public_access_block.side_effect = _client_error('AccessDenied')

        from rules.s3_rules import handle_put_bucket_acl
        result = handle_put_bucket_acl(public_acl_detail)

        assert result['status'] == 'remediation_failed'
        mock_metric.assert_called_once_with('S3_PUBLIC_ACL', 'test-bucket', False)

    @patch('rules.s3_rules._get_client')
    def test_missing_bucket_name_returns_error(self, mock_factory):
        mock_factory.return_value = MagicMock()
        from rules.s3_rules import handle_put_bucket_acl
        result = handle_put_bucket_acl({'userIdentity': {'arn': 'arn:...'}, 'requestParameters': {}})
        assert result['status'] == 'error'


# ─── handle_put_bucket_encryption ─────────────────────────────────────────────
# Fixture shapes below are the real CloudTrail wire format for PutBucketEncryption,
# confirmed by inspecting a live event: ServerSideEncryptionConfiguration.Rule is a
# singular object, not the `Rules` list boto3 uses as its parameter name.

@pytest.fixture
def weak_encryption_detail():
    return {
        'eventName': 'PutBucketEncryption',
        'userIdentity': {'arn': 'arn:aws:iam::123456789012:user/dev'},
        'requestParameters': {
            'bucketName': 'test-bucket',
            'ServerSideEncryptionConfiguration': {
                'Rule': {
                    'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}
                }
            },
        },
    }

@pytest.fixture
def kms_encryption_detail():
    return {
        'eventName': 'PutBucketEncryption',
        'userIdentity': {'arn': 'arn:aws:iam::123456789012:user/dev'},
        'requestParameters': {
            'bucketName': 'test-bucket',
            'ServerSideEncryptionConfiguration': {
                'Rule': {
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'aws:kms',
                        'KMSMasterKeyID': 'arn:aws:kms:us-east-1:123456789012:key/abc123',
                    }
                }
            },
        },
    }


class TestHandlePutBucketEncryption:
    @patch('rules.s3_rules.send_alert')
    @patch('rules.s3_rules.publish_violation')
    @patch('rules.s3_rules._get_client')
    def test_aes256_baseline_triggers_remediation(
        self, mock_factory, mock_metric, mock_alert, weak_encryption_detail
    ):
        mock_s3 = MagicMock()
        mock_factory.return_value = mock_s3
        mock_s3.get_bucket_tagging.side_effect = _client_error('NoSuchTagSet')

        from rules.s3_rules import handle_put_bucket_encryption
        result = handle_put_bucket_encryption(weak_encryption_detail)

        assert result['status'] == 'remediated'
        mock_s3.put_bucket_encryption.assert_called_once()
        mock_metric.assert_called_once_with('S3_WEAK_ENCRYPTION', 'test-bucket', True)
        mock_alert.assert_called_once()

    @patch('rules.s3_rules.send_alert')
    @patch('rules.s3_rules.publish_violation')
    @patch('rules.s3_rules._get_client')
    def test_kms_encryption_is_compliant(
        self, mock_factory, mock_metric, mock_alert, kms_encryption_detail
    ):
        mock_s3 = MagicMock()
        mock_factory.return_value = mock_s3
        mock_s3.get_bucket_tagging.side_effect = _client_error('NoSuchTagSet')

        from rules.s3_rules import handle_put_bucket_encryption
        result = handle_put_bucket_encryption(kms_encryption_detail)

        assert result['status'] == 'compliant'
        mock_s3.put_bucket_encryption.assert_not_called()
        mock_metric.assert_not_called()

    @patch('rules.s3_rules._get_client')
    def test_exempt_bucket_skipped(self, mock_factory, weak_encryption_detail):
        mock_s3 = MagicMock()
        mock_factory.return_value = mock_s3
        mock_s3.get_bucket_tagging.return_value = {
            'TagSet': [
                {'Key': 'ComplianceExempt', 'Value': 'true'},
                {'Key': 'ComplianceExemptUntil', 'Value': '2099-12-31'},
            ]
        }

        from rules.s3_rules import handle_put_bucket_encryption
        result = handle_put_bucket_encryption(weak_encryption_detail)

        assert result['status'] == 'exempt'
        mock_s3.put_bucket_encryption.assert_not_called()

    @patch('rules.s3_rules.send_alert')
    @patch('rules.s3_rules.publish_violation')
    @patch('rules.s3_rules._get_client')
    def test_remediation_failure_is_reported(
        self, mock_factory, mock_metric, mock_alert, weak_encryption_detail
    ):
        mock_s3 = MagicMock()
        mock_factory.return_value = mock_s3
        mock_s3.get_bucket_tagging.side_effect = _client_error('NoSuchTagSet')
        mock_s3.put_bucket_encryption.side_effect = _client_error('AccessDenied')

        from rules.s3_rules import handle_put_bucket_encryption
        result = handle_put_bucket_encryption(weak_encryption_detail)

        assert result['status'] == 'remediation_failed'
        mock_metric.assert_called_once_with('S3_WEAK_ENCRYPTION', 'test-bucket', False)

    @patch('rules.s3_rules._get_client')
    def test_missing_bucket_name_returns_error(self, mock_factory):
        mock_factory.return_value = MagicMock()
        from rules.s3_rules import handle_put_bucket_encryption
        result = handle_put_bucket_encryption({'userIdentity': {'arn': 'arn:...'}, 'requestParameters': {}})
        assert result['status'] == 'error'


# ─── the exemption tag is a bypass and has to be audited ─────────────────────

# An exemption now needs an expiry date; without one it is rejected.
EXEMPT_TAGS = {'TagSet': [
    {'Key': 'ComplianceExempt', 'Value': 'true'},
    {'Key': 'ComplianceExemptUntil', 'Value': '2099-12-31'},
]}


@patch('rules.s3_rules.send_notice')
@patch('rules.s3_rules.publish_exemption')
@patch('rules.s3_rules._get_client')
class TestExemptionIsAudited:
    def test_acl_exemption_publishes_a_metric(
        self, mock_factory, mock_exemption, mock_notice, public_acl_detail
    ):
        mock_s3 = MagicMock()
        mock_s3.get_bucket_tagging.return_value = EXEMPT_TAGS
        mock_factory.return_value = mock_s3

        from rules.s3_rules import handle_put_bucket_acl
        handle_put_bucket_acl(public_acl_detail)

        mock_exemption.assert_called_once_with('S3_PUBLIC_ACL', 'test-bucket')

    def test_acl_exemption_sends_a_notice_naming_the_actor(
        self, mock_factory, mock_exemption, mock_notice, public_acl_detail
    ):
        mock_s3 = MagicMock()
        mock_s3.get_bucket_tagging.return_value = EXEMPT_TAGS
        mock_factory.return_value = mock_s3

        from rules.s3_rules import handle_put_bucket_acl
        handle_put_bucket_acl(public_acl_detail)

        mock_notice.assert_called_once()
        args, _ = mock_notice.call_args
        assert args[1] == 'test-bucket'
        assert args[2] == 'arn:aws:iam::123456789012:user/dev'

    def test_encryption_exemption_is_also_reported(
        self, mock_factory, mock_exemption, mock_notice, weak_encryption_detail
    ):
        mock_s3 = MagicMock()
        mock_s3.get_bucket_tagging.return_value = EXEMPT_TAGS
        mock_factory.return_value = mock_s3

        from rules.s3_rules import handle_put_bucket_encryption
        handle_put_bucket_encryption(weak_encryption_detail)

        # This path previously returned without logging anything at all.
        mock_exemption.assert_called_once_with('S3_WEAK_ENCRYPTION', 'test-bucket')
        mock_notice.assert_called_once()

    def test_untagged_bucket_is_not_exempt(
        self, mock_factory, mock_exemption, mock_notice, public_acl_detail
    ):
        mock_s3 = MagicMock()
        mock_s3.get_bucket_tagging.side_effect = _client_error('NoSuchTagSet')
        mock_factory.return_value = mock_s3

        from rules.s3_rules import handle_put_bucket_acl
        result = handle_put_bucket_acl(public_acl_detail)

        # A bucket with no tags at all is not exempt; it is just untagged.
        assert result['status'] != 'exempt'
        mock_exemption.assert_not_called()

    def test_unreadable_tags_fail_the_invocation(
        self, mock_factory, mock_exemption, mock_notice, public_acl_detail
    ):
        mock_s3 = MagicMock()
        mock_s3.get_bucket_tagging.side_effect = _client_error('AccessDenied')
        mock_factory.return_value = mock_s3

        from rules.s3_rules import handle_put_bucket_acl
        # Deliberate: one event concerns one bucket, so there is no other work
        # to protect. Raising sends it to the DLQ rather than guessing.
        with pytest.raises(ClientError):
            handle_put_bucket_acl(public_acl_detail)


# ─── wire shapes and module entry point ──────────────────────────────────────

class TestExtractSseAlgorithm:
    def test_rule_as_a_singular_object(self):
        from rules.s3_rules import _extract_sse_algorithm
        detail = {'requestParameters': {'ServerSideEncryptionConfiguration': {
            'Rule': {'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}
        }}}
        assert _extract_sse_algorithm(detail) == 'AES256'

    def test_rule_as_a_list(self):
        from rules.s3_rules import _extract_sse_algorithm
        # CloudTrail logs the XML wire shape (singular Rule), but the SDK shape
        # is a Rules list and both have been seen. Handle either.
        detail = {'requestParameters': {'ServerSideEncryptionConfiguration': {
            'Rule': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'aws:kms'}}]
        }}}
        assert _extract_sse_algorithm(detail) == 'aws:kms'

    def test_empty_rule_list(self):
        from rules.s3_rules import _extract_sse_algorithm
        detail = {'requestParameters': {'ServerSideEncryptionConfiguration': {'Rule': []}}}
        assert _extract_sse_algorithm(detail) == ''

    def test_missing_configuration_entirely(self):
        from rules.s3_rules import _extract_sse_algorithm
        assert _extract_sse_algorithm({'requestParameters': {}}) == ''


class TestS3Evaluate:
    def test_unknown_event_returns_no_rule(self):
        from rules.s3_rules import evaluate
        result = evaluate('DeleteBucket', {})
        assert result['status'] == 'no_rule'
        assert result['event'] == 'DeleteBucket'

    def test_client_is_built_once_and_reused(self):
        from unittest.mock import patch as _patch
        from rules import s3_rules
        s3_rules._s3_client = None
        with _patch('boto3.client', return_value=MagicMock()) as make_client:
            first = s3_rules._get_client()
            second = s3_rules._get_client()
        assert first is second
        from utils.aws_client import CLIENT_CONFIG
        make_client.assert_called_once_with('s3', config=CLIENT_CONFIG)
