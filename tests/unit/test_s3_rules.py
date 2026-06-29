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
            'TagSet': [{'Key': 'ComplianceExempt', 'Value': 'true'}]
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
            'TagSet': [{'Key': 'ComplianceExempt', 'Value': 'true'}]
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
