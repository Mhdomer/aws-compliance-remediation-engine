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
