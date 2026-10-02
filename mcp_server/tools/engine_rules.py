"""Describe what the compliance engine enforces. Makes no AWS API calls."""

from mcp_server.engine_source import eventbridge_pairs  # noqa: F401  (sets sys.path)

from rules import ec2_rules, s3_rules, sg_rules  # noqa: E402

# Prose lives here rather than in the engine, which has no reason to carry it.
# Keyed by event name so an undescribed check raises rather than silently
# reporting a rule with no explanation.
_DESCRIPTIONS = {
    'PutBucketAcl': (
        'S3_PUBLIC_ACL',
        'A bucket ACL granting READ to AllUsers or AuthenticatedUsers, or a '
        'public canned ACL such as public-read set via the x-amz-acl header.',
        'Applies PutPublicAccessBlock with all four blocks enabled.',
    ),
    'PutBucketEncryption': (
        'S3_WEAK_ENCRYPTION',
        'Default encryption set to anything other than the mandated '
        'customer-managed KMS key, for example reverted to the AWS-managed '
        'SSE-S3 (AES256) baseline.',
        'Re-applies SSE-KMS using the key in REQUIRED_KMS_KEY_ARN.',
    ),
    'RunInstances': (
        'EC2_UNENCRYPTED_EBS',
        'An instance launched with an unencrypted EBS volume. Reports '
        'undetermined rather than compliant when the volumes cannot be read, '
        'so a check that could not see the data is never mistaken for a pass.',
        'Tags the instance with the violation and stops it, which halts writes '
        'to the unencrypted volume while leaving the volume intact to be fixed. '
        'Terminating is opt-in and the IAM permission does not exist by default.',
    ),
    'DeleteBucketPublicAccessBlock': (
        'S3_PUBLIC_ACCESS_BLOCK_REMOVED',
        'Block Public Access being removed from a bucket. Not a violation on '
        'its own, but since April 2023 it is the first of the two calls that '
        'have to happen before a public ACL can be accepted at all.',
        'Reports it with the principal who did it. Nothing is changed back: '
        'the engine cannot tell a deliberate change from a mistake, and some '
        'buckets legitimately need public reads.',
    ),
    'PutBucketOwnershipControls': (
        'S3_ACLS_REENABLED',
        'Object ownership moving off BucketOwnerEnforced, which turns bucket '
        'ACLs back on. The second of the two calls that precede a public ACL. '
        'Setting BucketOwnerEnforced is the safe direction and is not reported.',
        'Reports it with the principal who did it. Nothing is changed back, '
        'for the same reason.',
    ),
    'AuthorizeSecurityGroupIngress': (
        'SG_OPEN_PORT_<port>',
        'An ingress rule opening port 22 or 3389 to 0.0.0.0/0 or ::/0, '
        'including wide port ranges and all-traffic (-1) rules that cover them.',
        'Revokes the offending rule, once per underlying rule rather than once '
        'per exposed port.',
    ),
}


def describe_engine_rules() -> dict:
    """Describe every compliance check this engine enforces and how it remediates.

    Start here before using the other tools. Reads the engine's own source and
    terraform, so it cannot drift from the running code. Makes no AWS API calls.
    """
    checks = []
    for source, event_name in sorted(eventbridge_pairs()):
        violation_type, detects, remediates = _DESCRIPTIONS[event_name]
        checks.append({
            'violation_type': violation_type,
            'event_name': event_name,
            'source': source,
            'detects': detects,
            'remediates': remediates,
        })

    return {
        'checks': checks,
        'restricted_ports': sorted(sg_rules.RESTRICTED_PORTS),
        'required_sse_algorithm': s3_rules.REQUIRED_SSE_ALGORITHM,
        'exemption_tag': (
            f'{ec2_rules.EXEMPT_TAG_KEY}={ec2_rules.EXEMPT_TAG_VALUE}'
        ),
        'metrics_published': [
            'ViolationsDetected',
            'RemediationsApplied',
            'RemediationsFailed',
            'DetectionsUndetermined',
            'ExemptionsApplied',
            'ExemptionsRejected',
            'RemediationsThrottled',
            'ViolationAttemptsBlocked',
            'ExemptionsExpiringSoon',
            'ProtectionsWeakened',
        ],
        'note': (
            'Detection is event-driven through CloudTrail and EventBridge. A '
            'CloudTrail trail must be logging write management events in the '
            'deployed region or no event reaches the engine at all, in which '
            'case an absence of violations means nothing. Resources tagged '
            'with the exemption tag are skipped, and every skip is recorded '
            'as an ExemptionsApplied metric and an alert. Three counters are '
            'deliberately separate from the violation counters and mean '
            'different things: an exemption past its expiry date is rejected '
            'rather than honoured and counts as ExemptionsRejected with a '
            'reason; a remediation AWS throttled counts as '
            'RemediationsThrottled and is not a failure; an API call AWS '
            'itself rejected counts as ViolationAttemptsBlocked and is not a '
            'violation, because nothing changed.'
        ),
    }
