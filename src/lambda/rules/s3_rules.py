import logging
import os

import boto3
from botocore.exceptions import ClientError

from utils.cloudwatch_utils import publish_violation
from utils.notifier import send_alert

logger = logging.getLogger(__name__)

EXEMPT_TAG_KEY = 'ComplianceExempt'
EXEMPT_TAG_VALUE = 'true'

PUBLIC_GRANTEE_URIS = {
    'http://acs.amazonaws.com/groups/global/AllUsers',
    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers',
}

# Canned ACLs (set via the `x-amz-acl` header, e.g. `--acl public-read`) never appear
# as an AccessControlPolicy/Grant structure in the CloudTrail event — CloudTrail logs
# them as a bare string in requestParameters instead. This is how most public buckets
# actually happen in practice (S3 console checkbox, `aws s3api ... --acl public-read`).
PUBLIC_CANNED_ACLS = {'public-read', 'public-read-write', 'authenticated-read'}

# Org policy: buckets must use a customer-managed KMS key for default encryption,
# not the AWS-managed baseline (SSE-S3/AES256) that S3 now applies automatically
# to every bucket since Jan 2023. SSE-S3 is still real encryption, but it isn't
# under this account's key rotation or audit control, which SOC2/HIPAA/PCI-style
# policies typically require.
REQUIRED_SSE_ALGORITHM = 'aws:kms'

_s3_client = None


def _get_client():
    global _s3_client
    if _s3_client is None:
        _s3_client = boto3.client('s3')
    return _s3_client


def _is_exempt(bucket_name: str) -> bool:
    try:
        response = _get_client().get_bucket_tagging(Bucket=bucket_name)
        tags = {t['Key']: t['Value'] for t in response.get('TagSet', [])}
        return tags.get(EXEMPT_TAG_KEY, '').lower() == EXEMPT_TAG_VALUE
    except ClientError as exc:
        if exc.response['Error']['Code'] == 'NoSuchTagSet':
            return False
        raise


def has_public_acl(grants: list) -> bool:
    for grant in grants:
        if grant.get('Grantee', {}).get('URI') in PUBLIC_GRANTEE_URIS:
            return True
    return False


def handle_put_bucket_acl(detail: dict) -> dict:
    bucket_name = detail.get('requestParameters', {}).get('bucketName', '')
    actor = detail.get('userIdentity', {}).get('arn', 'unknown')

    if not bucket_name:
        logger.error('PutBucketAcl event missing bucketName')
        return {'status': 'error', 'reason': 'missing_bucket_name'}

    if _is_exempt(bucket_name):
        logger.info('Bucket is exempt from compliance checks', extra={'bucket': bucket_name})
        return {'status': 'exempt', 'bucket': bucket_name}

    request_params = detail.get('requestParameters', {})
    canned_acl = request_params.get('x-amz-acl', '')
    grants = (
        request_params.get('AccessControlPolicy', {})
                       .get('AccessControlList', {})
                       .get('Grant', [])
    )

    if canned_acl not in PUBLIC_CANNED_ACLS and not has_public_acl(grants):
        return {'status': 'compliant', 'bucket': bucket_name}

    violation_type = 'S3_PUBLIC_ACL'
    logger.warning('Violation detected', extra={
        'violation': violation_type,
        'bucket': bucket_name,
        'actor': actor,
    })

    try:
        _get_client().put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True,
            },
        )
        remediated = True
        action = 'Blocked all public access via PutPublicAccessBlock'
        logger.info('Remediation applied', extra={'bucket': bucket_name, 'action': action})
    except ClientError as exc:
        remediated = False
        action = f'Remediation failed: {exc}'
        logger.error('Remediation failed', extra={'bucket': bucket_name, 'error': str(exc)})

    publish_violation(violation_type, bucket_name, remediated)
    send_alert(violation_type, bucket_name, actor, action, remediated)

    return {
        'status': 'remediated' if remediated else 'remediation_failed',
        'violation': violation_type,
        'resource': bucket_name,
        'actor': actor,
        'action': action,
    }


def _extract_sse_algorithm(detail: dict) -> str:
    # CloudTrail logs the actual XML wire shape, not the boto3 parameter names —
    # the request body's root rule element is `Rule` (singular object), not the
    # `Rules` (list) key the SDK uses. Confirmed by inspecting a real CloudTrail
    # event before writing this, after Bug 1 taught us not to guess this shape.
    rule = (
        detail.get('requestParameters', {})
              .get('ServerSideEncryptionConfiguration', {})
              .get('Rule', {})
    )
    if isinstance(rule, list):
        rule = rule[0] if rule else {}
    return rule.get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm', '')


def handle_put_bucket_encryption(detail: dict) -> dict:
    bucket_name = detail.get('requestParameters', {}).get('bucketName', '')
    actor = detail.get('userIdentity', {}).get('arn', 'unknown')

    if not bucket_name:
        logger.error('PutBucketEncryption event missing bucketName')
        return {'status': 'error', 'reason': 'missing_bucket_name'}

    if _is_exempt(bucket_name):
        return {'status': 'exempt', 'bucket': bucket_name}

    sse_algorithm = _extract_sse_algorithm(detail)
    if sse_algorithm == REQUIRED_SSE_ALGORITHM:
        return {'status': 'compliant', 'bucket': bucket_name}

    violation_type = 'S3_WEAK_ENCRYPTION'
    logger.warning('Violation detected', extra={
        'violation': violation_type,
        'bucket': bucket_name,
        'actor': actor,
        'sse_algorithm': sse_algorithm or 'none',
    })

    required_key_arn = os.environ.get('REQUIRED_KMS_KEY_ARN', '')

    try:
        _get_client().put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': [{
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'aws:kms',
                        'KMSMasterKeyID': required_key_arn,
                    },
                    'BucketKeyEnabled': True,
                }]
            },
        )
        remediated = True
        action = 'Reapplied mandated customer-managed KMS encryption'
        logger.info('Remediation applied', extra={'bucket': bucket_name, 'action': action})
    except ClientError as exc:
        remediated = False
        action = f'Remediation failed: {exc}'
        logger.error('Remediation failed', extra={'bucket': bucket_name, 'error': str(exc)})

    publish_violation(violation_type, bucket_name, remediated)
    send_alert(violation_type, bucket_name, actor, action, remediated)

    return {
        'status': 'remediated' if remediated else 'remediation_failed',
        'violation': violation_type,
        'resource': bucket_name,
        'actor': actor,
        'action': action,
    }


_HANDLERS = {
    'PutBucketAcl': handle_put_bucket_acl,
    'PutBucketEncryption': handle_put_bucket_encryption,
}


def evaluate(event_name: str, detail: dict) -> dict:
    handler = _HANDLERS.get(event_name)
    if handler:
        return handler(detail)
    return {'status': 'no_rule', 'event': event_name}
