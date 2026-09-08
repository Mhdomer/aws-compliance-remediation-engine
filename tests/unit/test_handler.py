import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


ENGINE_ROLE_ARN = 'arn:aws:iam::123456789012:role/compliance-engine-prod-lambda-role'

# CloudTrail records an assumed role with two different ARNs: the top-level one
# is an STS assumed-role ARN carrying the session name, while
# sessionContext.sessionIssuer.arn is the IAM role ARN. Only the second compares
# directly against aws_iam_role.lambda_exec.arn.
ENGINE_IDENTITY = {
    'type': 'AssumedRole',
    'arn': 'arn:aws:sts::123456789012:assumed-role/compliance-engine-prod-lambda-role/compliance-engine-prod',
    'sessionContext': {'sessionIssuer': {
        'type': 'Role',
        'arn': ENGINE_ROLE_ARN,
        'userName': 'compliance-engine-prod-lambda-role',
    }},
}

# sessionContext is not present on every CloudTrail record.
ENGINE_IDENTITY_NO_SESSION_CONTEXT = {
    'type': 'AssumedRole',
    'arn': 'arn:aws:sts::123456789012:assumed-role/compliance-engine-prod-lambda-role/compliance-engine-prod',
}

HUMAN_IDENTITY = {
    'type': 'IAMUser',
    'arn': 'arn:aws:iam::123456789012:user/developer',
    'userName': 'developer',
}

# A different role whose name merely starts with the engine's role name.
SIMILAR_ROLE_IDENTITY = {
    'type': 'AssumedRole',
    'arn': 'arn:aws:sts::123456789012:assumed-role/compliance-engine-prod-lambda-role-readonly/audit',
    'sessionContext': {'sessionIssuer': {
        'arn': 'arn:aws:iam::123456789012:role/compliance-engine-prod-lambda-role-readonly',
    }},
}


def _event(user_identity: dict) -> dict:
    return {
        'source': 'aws.s3',
        'detail-type': 'AWS API Call via CloudTrail',
        'detail': {
            'eventName': 'PutBucketEncryption',
            'userIdentity': user_identity,
            'requestParameters': {'bucketName': 'demo-bucket'},
        },
    }


@pytest.fixture
def rule():
    """Stand in for the real rule so no test ever reaches boto3."""
    return MagicMock(return_value={'status': 'compliant'})


@pytest.fixture
def engine_role(monkeypatch):
    monkeypatch.setenv('ENGINE_ROLE_ARN', ENGINE_ROLE_ARN)


def _handler_with(rule):
    """Patch the registry entry the test events route to."""
    import handler
    return patch.dict(
        handler._RULE_REGISTRY,
        {('aws.s3', 'PutBucketEncryption'): rule},
    )


class TestSelfInvocationGuard:
    def test_event_caused_by_the_engine_is_dropped(self, rule, engine_role):
        import handler
        with _handler_with(rule):
            result = handler.lambda_handler(_event(ENGINE_IDENTITY), None)

        assert result['status'] == 'ignored'
        assert result['reason'] == 'self_invocation'
        rule.assert_not_called()

    def test_engine_event_without_session_context_is_dropped(self, rule, engine_role):
        import handler
        with _handler_with(rule):
            result = handler.lambda_handler(_event(ENGINE_IDENTITY_NO_SESSION_CONTEXT), None)

        assert result['status'] == 'ignored'
        rule.assert_not_called()

    def test_event_caused_by_a_person_is_still_processed(self, rule, engine_role):
        import handler
        with _handler_with(rule):
            result = handler.lambda_handler(_event(HUMAN_IDENTITY), None)

        assert result['status'] == 'compliant'
        rule.assert_called_once()

    def test_role_with_a_similar_name_is_still_processed(self, rule, engine_role):
        import handler
        with _handler_with(rule):
            result = handler.lambda_handler(_event(SIMILAR_ROLE_IDENTITY), None)

        assert result['status'] == 'compliant'
        rule.assert_called_once()

    def test_drop_is_logged_at_warning(self, rule, engine_role):
        import handler
        with _handler_with(rule), patch.object(handler, 'logger') as mock_logger:
            handler.lambda_handler(_event(ENGINE_IDENTITY), None)

        # The guard blinds the engine to actions taken with its own role, so the
        # log line is the compensating control that keeps them auditable.
        assert mock_logger.warning.called
        _, kwargs = mock_logger.warning.call_args
        assert kwargs['extra']['actor'] == ENGINE_IDENTITY['arn']

    def test_guard_is_inert_when_role_arn_is_not_configured(self, rule, monkeypatch):
        monkeypatch.delenv('ENGINE_ROLE_ARN', raising=False)
        import handler
        with _handler_with(rule):
            result = handler.lambda_handler(_event(ENGINE_IDENTITY), None)

        # Failing open is deliberate: an unset variable must not silently
        # disable the whole engine.
        assert result['status'] == 'compliant'
        rule.assert_called_once()


# ─── dispatch registry ───────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[2]


def _eventbridge_pairs() -> set:
    """(source, eventName) pairs the terraform actually routes to this Lambda."""
    text = (REPO_ROOT / 'infrastructure' / 'eventbridge.tf').read_text(encoding='utf-8')
    pairs = set()
    for block in text.split('resource "aws_cloudwatch_event_rule"')[1:]:
        source = re.search(r'source\s*=\s*\["([^"]+)"\]', block)
        event = re.search(r'eventName\s*=\s*\["([^"]+)"\]', block)
        if source and event:
            pairs.add((source.group(1), event.group(1)))
    return pairs


class TestRuleRegistry:
    def test_each_event_routes_to_its_service_module(self):
        import handler
        from rules import ec2_rules, s3_rules, sg_rules

        assert handler._RULE_REGISTRY[('aws.s3', 'PutBucketAcl')] is s3_rules.evaluate
        assert handler._RULE_REGISTRY[('aws.s3', 'PutBucketEncryption')] is s3_rules.evaluate
        assert handler._RULE_REGISTRY[('aws.ec2', 'RunInstances')] is ec2_rules.evaluate
        assert handler._RULE_REGISTRY[
            ('aws.ec2', 'AuthorizeSecurityGroupIngress')] is sg_rules.evaluate

    def test_registry_matches_the_eventbridge_rules(self):
        import handler

        # A rule added to eventbridge.tf without a registry entry delivers
        # events that quietly return no_rule; a registry entry with no rule
        # never fires at all. Neither failure announces itself.
        assert _eventbridge_pairs() == set(handler._RULE_REGISTRY)

    def test_known_event_is_dispatched(self):
        import handler
        rule = MagicMock(return_value={'status': 'compliant'})

        with patch.dict(handler._RULE_REGISTRY, {('aws.s3', 'PutBucketAcl'): rule}):
            result = handler.lambda_handler(
                {'source': 'aws.s3', 'detail': {'eventName': 'PutBucketAcl'}}, None
            )

        rule.assert_called_once_with('PutBucketAcl', {'eventName': 'PutBucketAcl'})
        assert result['status'] == 'compliant'

    def test_unknown_event_name_returns_no_rule(self):
        import handler
        result = handler.lambda_handler(
            {'source': 'aws.s3', 'detail': {'eventName': 'DeleteBucket'}}, None
        )

        assert result['status'] == 'no_rule'
        assert result['event_name'] == 'DeleteBucket'

    def test_known_event_from_unknown_source_returns_no_rule(self):
        import handler
        # The key is the pair, so a matching name from elsewhere must not route.
        result = handler.lambda_handler(
            {'source': 'aws.rds', 'detail': {'eventName': 'RunInstances'}}, None
        )

        assert result['status'] == 'no_rule'

    def test_empty_event_returns_no_rule_rather_than_raising(self):
        import handler
        assert handler.lambda_handler({}, None)['status'] == 'no_rule'

    def test_rule_exception_is_logged_and_re_raised(self):
        import handler
        rule = MagicMock(side_effect=RuntimeError('rule blew up'))

        with patch.dict(handler._RULE_REGISTRY, {('aws.s3', 'PutBucketAcl'): rule}), \
                patch.object(handler, 'logger') as mock_logger:
            with pytest.raises(RuntimeError, match='rule blew up'):
                handler.lambda_handler(
                    {'source': 'aws.s3', 'detail': {'eventName': 'PutBucketAcl'}}, None
                )

        # Re-raising is what gets the event retried and then onto the DLQ,
        # where the existing alarm catches it. Swallowing would lose it.
        assert mock_logger.error.called

    def test_request_id_is_taken_from_the_lambda_context(self):
        import handler

        class Context:
            aws_request_id = 'req-12345'

        with patch.object(handler, 'logger') as mock_logger:
            handler.lambda_handler(
                {'source': 'aws.s3', 'detail': {'eventName': 'Unknown'}}, Context()
            )

        first_call = mock_logger.info.call_args_list[0]
        assert first_call.kwargs['extra']['request_id'] == 'req-12345'
