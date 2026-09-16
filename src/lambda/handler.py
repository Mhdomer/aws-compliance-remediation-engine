import os

from utils.logger import setup_logger
from rules import s3_rules, ec2_rules, sg_rules

logger = setup_logger(__name__)

# Registry maps (event source, CloudTrail event name) → rule module's evaluate function.
# Adding a new compliance rule = adding one entry here and implementing evaluate() in a rules module.
_RULE_REGISTRY = {
    ('aws.s3',  'PutBucketAcl'):                s3_rules.evaluate,
    ('aws.s3',  'PutBucketEncryption'):         s3_rules.evaluate,
    ('aws.ec2', 'RunInstances'):                ec2_rules.evaluate,
    ('aws.ec2', 'AuthorizeSecurityGroupIngress'): sg_rules.evaluate,
}


def _is_self_invocation(detail: dict) -> bool:
    """True when this event was caused by the engine's own execution role.

    Every remediation is itself an API call, so CloudTrail logs it and
    EventBridge feeds it straight back in. PutBucketEncryption is the live
    example: the engine's own put_bucket_encryption re-triggers this function.
    It currently stops after one extra pass only because the value the
    remediator writes happens to satisfy the detector's predicate — an
    accidental agreement between two unrelated pieces of code, with no backoff,
    counter or dedupe behind it. Tighten the predicate or stale the key ARN and
    the same code loops without bound. Dropping our own events makes
    loop-freedom structural rather than emergent.
    """
    engine_role_arn = os.environ.get('ENGINE_ROLE_ARN', '')
    if not engine_role_arn:
        # Fail open: an unset variable must not silently disable the engine.
        return False

    identity = detail.get('userIdentity', {})

    # sessionContext.sessionIssuer.arn is the IAM role ARN, which is what
    # compares directly against the role terraform created. The top-level arn
    # is an STS assumed-role ARN with a session name appended.
    issuer_arn = (
        identity.get('sessionContext', {})
                .get('sessionIssuer', {})
                .get('arn', '')
    )
    if issuer_arn:
        return issuer_arn == engine_role_arn

    # sessionContext is not on every record. Fall back to the assumed-role ARN,
    # which embeds the role name as arn:aws:sts::<acct>:assumed-role/<role>/<session>.
    # The trailing slash stops "<role>-readonly" matching "<role>".
    role_name = engine_role_arn.rsplit('/', 1)[-1]
    return f':assumed-role/{role_name}/' in identity.get('arn', '')


def lambda_handler(event: dict, context) -> dict:
    source = event.get('source', '')
    detail = event.get('detail', {})
    event_name = detail.get('eventName', '')
    request_id = getattr(context, 'aws_request_id', 'local')

    logger.info('Compliance event received', extra={
        'source': source,
        'event_name': event_name,
        'detail_type': event.get('detail-type', ''),
        'request_id': request_id,
    })

    if _is_self_invocation(detail):
        # WARNING rather than INFO on purpose: this guard blinds the engine to
        # anything done with its own role, so the log line is the compensating
        # control that keeps those actions auditable.
        logger.warning('Dropping event caused by the engine itself', extra={
            'source': source,
            'event_name': event_name,
            'actor': detail.get('userIdentity', {}).get('arn', 'unknown'),
            'request_id': request_id,
        })
        return {
            'status': 'ignored',
            'reason': 'self_invocation',
            'source': source,
            'event_name': event_name,
        }

    evaluate_fn = _RULE_REGISTRY.get((source, event_name))

    if evaluate_fn is None:
        logger.info('No compliance rule registered for this event', extra={
            'source': source,
            'event_name': event_name,
        })
        return {'status': 'no_rule', 'source': source, 'event_name': event_name}

    try:
        result = evaluate_fn(event_name, detail)
        logger.info('Compliance evaluation complete', extra={'result': result})
        return result
    except Exception as exc:
        logger.error('Unhandled error during compliance evaluation', extra={
            'source': source,
            'event_name': event_name,
            'error': str(exc),
        })
        raise
