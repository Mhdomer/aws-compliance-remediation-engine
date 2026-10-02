"""Watch the calls that make a public bucket possible, not just the last one.

The S3 rule watches PutBucketAcl. On an account created since April 2023 that
call cannot succeed: every new bucket has Block Public Access on and
ObjectOwnership set to BucketOwnerEnforced, which disables ACLs outright.
Confirmed on a live account, entry 16.

So the real sequence to a public bucket is three calls, and the engine only
watched the third:

    DeleteBucketPublicAccessBlock     <- protection off
    PutBucketOwnershipControls        <- ACLs back on
    PutBucketAcl                      <- the bucket goes public

By the time the third fires, the account has already been weakened and nothing
said so.

These two are reported, not remediated. Turning off Block Public Access is not
automatically a violation the way a public ACL is: some buckets legitimately
need ACLs, and a static site may need public reads. Remediating would mean the
engine fighting a deliberate change with no idea whether it was deliberate.
Saying who did it, immediately, is the useful thing.
"""

from unittest.mock import patch

import pytest


def _detail(event_name: str, bucket: str = 'my-bucket', **params) -> dict:
    return {
        'eventName': event_name,
        'userIdentity': {'arn': 'arn:aws:iam::123456789012:user/dev'},
        'requestParameters': {'bucketName': bucket, **params},
    }


class TestBlockPublicAccessRemoval:
    @patch('rules.s3_rules.send_notice')
    @patch('rules.s3_rules.publish_protection_weakened')
    def test_removing_the_block_is_reported(self, metric, notice):
        from rules.s3_rules import evaluate

        result = evaluate('DeleteBucketPublicAccessBlock',
                          _detail('DeleteBucketPublicAccessBlock'))

        assert result['status'] == 'reported'
        assert metric.called
        assert notice.called
        assert 'my-bucket' in str(notice.call_args)

    @patch('rules.s3_rules.send_notice')
    @patch('rules.s3_rules.publish_protection_weakened')
    def test_the_notice_names_who_did_it(self, metric, notice):
        from rules.s3_rules import evaluate

        evaluate('DeleteBucketPublicAccessBlock',
                 _detail('DeleteBucketPublicAccessBlock'))

        # Without the principal this says a protection came off and not who
        # took it off, which is the only part anyone can act on.
        assert 'user/dev' in str(notice.call_args)

    @patch('rules.s3_rules.send_notice')
    @patch('rules.s3_rules.publish_protection_weakened')
    @patch('rules.s3_rules._get_client')
    def test_nothing_is_remediated(self, client, metric, notice):
        from rules.s3_rules import evaluate

        evaluate('DeleteBucketPublicAccessBlock',
                 _detail('DeleteBucketPublicAccessBlock'))

        # Putting the block back would fight a change that may well have been
        # deliberate, and the engine cannot tell which.
        client.return_value.put_public_access_block.assert_not_called()

    @patch('rules.s3_rules.send_notice')
    @patch('rules.s3_rules.publish_protection_weakened')
    def test_a_denied_removal_is_not_reported_as_one(self, metric, notice):
        import handler

        event = {
            'source': 'aws.s3',
            'detail': dict(_detail('DeleteBucketPublicAccessBlock'),
                           errorCode='AccessDenied'),
        }
        with patch('handler.publish_attempt_blocked'), patch('handler.send_notice'):
            result = handler.lambda_handler(event, None)

        # The handler drops failed calls before dispatch. Nothing came off.
        assert result['reason'] == 'failed_api_call'
        assert not notice.called


class TestOwnershipControls:
    @patch('rules.s3_rules.send_notice')
    @patch('rules.s3_rules.publish_protection_weakened')
    def test_re_enabling_acls_is_reported(self, metric, notice):
        from rules.s3_rules import evaluate

        detail = _detail('PutBucketOwnershipControls')
        detail['requestParameters']['OwnershipControls'] = {
            'Rule': [{'ObjectOwnership': 'ObjectWriter'}]
        }

        result = evaluate('PutBucketOwnershipControls', detail)

        assert result['status'] == 'reported'
        assert notice.called

    @patch('rules.s3_rules.send_notice')
    @patch('rules.s3_rules.publish_protection_weakened')
    def test_setting_owner_enforced_is_not_reported(self, metric, notice):
        from rules.s3_rules import evaluate

        detail = _detail('PutBucketOwnershipControls')
        detail['requestParameters']['OwnershipControls'] = {
            'Rule': [{'ObjectOwnership': 'BucketOwnerEnforced'}]
        }

        result = evaluate('PutBucketOwnershipControls', detail)

        # This is the safe direction: it turns ACLs off. Reporting it would
        # mean emailing somebody every time a bucket got safer.
        assert result['status'] == 'compliant'
        assert not notice.called

    @patch('rules.s3_rules.send_notice')
    @patch('rules.s3_rules.publish_protection_weakened')
    def test_an_unreadable_ownership_setting_is_not_called_compliant(
        self, metric, notice
    ):
        from rules.s3_rules import evaluate

        detail = _detail('PutBucketOwnershipControls')  # no OwnershipControls

        result = evaluate('PutBucketOwnershipControls', detail)

        # Could not tell which way it went. By this project's own rule that is
        # undetermined, not a pass.
        assert result['status'] == 'undetermined'


class TestTheEventsAreWiredIn:
    @pytest.mark.parametrize('event_name', [
        'DeleteBucketPublicAccessBlock',
        'PutBucketOwnershipControls',
    ])
    def test_the_registry_routes_it(self, event_name):
        import handler
        from rules import s3_rules

        assert handler._RULE_REGISTRY[('aws.s3', event_name)] is s3_rules.evaluate

    @pytest.mark.parametrize('event_name', [
        'DeleteBucketPublicAccessBlock',
        'PutBucketOwnershipControls',
    ])
    def test_the_event_is_a_write_so_the_trail_records_it(self, event_name):
        # The trail logs WriteOnly management events. A read-only event would
        # need the trail widened and the rule given a special state, and would
        # otherwise never fire at all.
        read_only = ('Get', 'List', 'Describe', 'Lookup', 'Head')
        assert not event_name.startswith(read_only)
