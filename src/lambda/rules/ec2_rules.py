import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from utils.aws_client import is_throttling_error, make_client
from utils.exemption import (
    EXEMPT_TAG_KEY,
    EXEMPT_TAG_VALUE,
    EXEMPT_UNTIL_TAG_KEY,
    REJECTED_REASONS,
    evaluate_exemption,
)
from utils.cloudwatch_utils import (
    publish_detection_undetermined,
    publish_exemption,
    publish_exemption_rejected,
    publish_throttled,
    publish_violation,
)
from utils.logger import setup_logger
from utils.notifier import (
    NOTICE_EXEMPTION,
    NOTICE_UNDETERMINED,
    STATUS_EXEMPTION,
    STATUS_REVIEW,
    send_alert,
    send_notice,
)

logger = setup_logger(__name__)

# Terminating does not remediate this violation. The finding is an unencrypted
# EBS volume; termination destroys the compute and, when DeleteOnTermination is
# false (the default for volumes attached at launch), leaves the unencrypted
# volume behind. Where it does delete the volume it is deleting the data, which
# is not a fix either. Stopping halts writes to the volume while keeping it
# intact, so the real fix — snapshot, copy encrypted, reattach — stays possible.
ACTION_STOP = 'stop'
ACTION_TERMINATE = 'terminate'
VALID_ACTIONS = {ACTION_STOP, ACTION_TERMINATE}

# A detection control has three possible answers, not two. Collapsing
# "could not tell" into "compliant" is a silent miss, which is worse than an
# error: an error gets noticed, a confident wrong answer does not.
ENCRYPTION_UNENCRYPTED = 'unencrypted'
ENCRYPTION_OK = 'encrypted'
ENCRYPTION_UNDETERMINED = 'undetermined'

VIOLATION_TYPE = 'EC2_UNENCRYPTED_EBS'
UNDETERMINED_TYPE = 'EC2_ENCRYPTION_UNDETERMINED'

# States in which an instance's block device mappings have settled. RunInstances
# fires at launch, and an instance still in `pending` may not have had its
# volumes attached yet, so an empty mapping list from anything outside this set
# means "cannot tell" rather than "no volumes to check". A response with no
# State at all is treated the same way.
SETTLED_STATES = {'running', 'stopping', 'stopped', 'shutting-down', 'terminated'}

_ec2_client = None


def _get_client():
    global _ec2_client
    if _ec2_client is None:
        _ec2_client = make_client('ec2')
    return _ec2_client


def _remediation_action() -> str:
    """Which action to take on a violating instance.

    Defaults to stop, and falls back to stop for any value it does not
    recognise. An unreadable setting must never escalate to something
    irreversible. Terraform only grants ec2:TerminateInstances when the
    matching variable is set, so with the default the role cannot terminate
    even if this returned the wrong answer.
    """
    configured = os.environ.get('EC2_REMEDIATION_ACTION', ACTION_STOP).strip().lower()
    if configured not in VALID_ACTIONS:
        logger.warning('Unrecognised EC2_REMEDIATION_ACTION, defaulting to stop', extra={
            'configured': configured,
        })
        return ACTION_STOP
    return configured


def _tag_instance(instance_id: str, violation_type: str, action_taken: str) -> None:
    _get_client().create_tags(
        Resources=[instance_id],
        Tags=[
            {'Key': 'ComplianceViolation', 'Value': violation_type},
            {'Key': 'ComplianceAction', 'Value': action_taken},
            {'Key': 'ComplianceDetectedAt', 'Value': datetime.now(timezone.utc).isoformat()},
        ],
    )


def _remediate(instance_id: str, violation_type: str) -> str:
    """Apply the configured remediation, returning what was done.

    Tags go on before the action so that a failed stop still leaves the
    instance carrying the reason, and so the CreateTags call is recorded in
    CloudTrail even when the instance is about to disappear.
    """
    if _remediation_action() == ACTION_TERMINATE:
        _tag_instance(instance_id, violation_type, 'terminated')
        _get_client().terminate_instances(InstanceIds=[instance_id])
        return 'Instance terminated: unencrypted EBS volume detected'

    _tag_instance(instance_id, violation_type, 'stopped')
    _get_client().stop_instances(InstanceIds=[instance_id])
    return 'Instance stopped and tagged for review: unencrypted EBS volume detected'


def _get_instance_ids(detail: dict) -> list[str]:
    items = (
        detail.get('responseElements', {})
              .get('instancesSet', {})
              .get('items', [])
    )
    return [item['instanceId'] for item in items]


def _prefetch_instances(instance_ids: list) -> dict | None:
    """Describe every instance the event named, in one call.

    Returns a map keyed on instance id, or None if the batch could not be made
    at all, in which case the caller falls back to describing one at a time and
    behaviour is exactly what it was before.

    A throttle re-raises rather than degrading: being throttled means nothing
    was looked at, and the retry is what answers the question.
    """
    try:
        response = _get_client().describe_instances(InstanceIds=instance_ids)
    except ClientError as exc:
        if is_throttling_error(exc):
            publish_throttled(VIOLATION_TYPE, instance_ids[0])
            logger.warning('Detection throttled, retrying via event replay', extra={
                'instance_count': len(instance_ids),
                'error': str(exc),
            })
            raise
        # Not fatal. Fall back to the per-instance path, which isolates the
        # failure to the one instance that caused it.
        logger.warning('Batched describe_instances failed, falling back', extra={
            'instance_count': len(instance_ids),
            'error': str(exc),
        })
        return None

    found = {}
    returned = 0
    for reservation in response.get('Reservations', []):
        for instance in reservation.get('Instances', []):
            returned += 1
            instance_id = instance.get('InstanceId')
            if instance_id:
                found[instance_id] = instance

    if returned and not found:
        # Instances came back but none carried an InstanceId, so there is no
        # way to say which is which. Real EC2 always sends it; whatever this
        # is, it cannot be indexed, so fall back rather than guess by position.
        logger.warning('describe_instances returned instances with no ids', extra={
            'returned': returned,
        })
        return None

    return found


def _prefetch_volumes(instances: list) -> dict | None:
    """Describe every volume across every instance, in one call.

    Same contract as _prefetch_instances: None means fall back.
    """
    volume_ids = []
    for instance in instances:
        for mapping in instance.get('BlockDeviceMappings', []):
            volume_id = mapping.get('Ebs', {}).get('VolumeId')
            if volume_id:
                volume_ids.append(volume_id)

    if not volume_ids:
        return {}

    try:
        response = _get_client().describe_volumes(VolumeIds=volume_ids)
    except ClientError as exc:
        if is_throttling_error(exc):
            publish_throttled(VIOLATION_TYPE, volume_ids[0])
            logger.warning('Detection throttled, retrying via event replay', extra={
                'volume_count': len(volume_ids),
                'error': str(exc),
            })
            raise
        logger.warning('Batched describe_volumes failed, falling back', extra={
            'volume_count': len(volume_ids),
            'error': str(exc),
        })
        return None

    volumes = response.get('Volumes', [])
    found = {v['VolumeId']: v for v in volumes if v.get('VolumeId')}

    if volumes and not found:
        # Same reasoning as the instance prefetch: a response with no ids on it
        # cannot be matched back to the volumes that were asked about.
        logger.warning('describe_volumes returned volumes with no ids', extra={
            'returned': len(volumes),
        })
        return None

    return found


def _describe_instance(instance_id: str, prefetched: dict | None = None) -> dict:
    """Fetch the instance once, for both the exemption and volume checks.

    These used to be two separate describe_instances calls for the same
    instance, which doubled the throttling exposure on a RunInstances burst and
    left a window in which the two could disagree.

    With a prefetched map this is a lookup. A missing key raises KeyError on
    purpose: EC2 answered the batch and did not mention this instance, so it is
    undetermined, and the caller's existing handler already reports that.
    Asking again would most likely get the same silence.
    """
    if prefetched is not None:
        return prefetched[instance_id]

    response = _get_client().describe_instances(InstanceIds=[instance_id])
    return response['Reservations'][0]['Instances'][0]


def _exemption_status(instance: dict) -> tuple[bool, str]:
    """Whether the instance's tags exempt it, and why not if they do not.

    This cannot fail: tags arrive inline on the describe_instances response, so
    there is no second call to go wrong. The error case lives in
    _describe_instance(), which raises and is caught per-instance - deliberately
    unlike the S3 rule, because one RunInstances event can name several
    instances and one unreadable instance must not abandon the rest. The caller
    reports that gap rather than swallowing it.
    """
    tags = {tag.get('Key'): tag.get('Value', '') for tag in instance.get('Tags', [])}
    return evaluate_exemption(tags)


def _volume_encryption_status(
    instance: dict, prefetched_volumes: dict | None = None
) -> str:
    """Return whether the instance's EBS volumes are encrypted, or that we could not tell.

    Every path that cannot see the data returns ENCRYPTION_UNDETERMINED rather
    than guessing. In particular a volume with no Encrypted field is not
    assumed unencrypted: that would stop an instance on the strength of a
    missing key.
    """
    mappings = instance.get('BlockDeviceMappings', [])

    if not mappings:
        state = instance.get('State', {}).get('Name', '')
        if state in SETTLED_STATES:
            return ENCRYPTION_OK  # settled and genuinely no EBS volumes attached
        return ENCRYPTION_UNDETERMINED

    volume_ids = [
        mapping['Ebs']['VolumeId']
        for mapping in mappings
        if mapping.get('Ebs', {}).get('VolumeId')
    ]
    if len(volume_ids) != len(mappings):
        return ENCRYPTION_UNDETERMINED  # a mapping we could not read

    if prefetched_volumes is not None:
        volumes = [
            prefetched_volumes[v] for v in volume_ids if v in prefetched_volumes
        ]
    else:
        volumes = _get_client().describe_volumes(
            VolumeIds=volume_ids
        ).get('Volumes', [])

    if len(volumes) != len(volume_ids):
        return ENCRYPTION_UNDETERMINED  # AWS did not answer about every volume

    for volume in volumes:
        if 'Encrypted' not in volume:
            return ENCRYPTION_UNDETERMINED
        if not volume['Encrypted']:
            return ENCRYPTION_UNENCRYPTED

    return ENCRYPTION_OK


def handle_run_instances(detail: dict) -> dict:
    actor = detail.get('userIdentity', {}).get('arn', 'unknown')
    instance_ids = _get_instance_ids(detail)

    if not instance_ids:
        logger.error('RunInstances event has no instance IDs in responseElements')
        return {'status': 'error', 'reason': 'no_instances_in_event'}

    # One describe for every instance, and one for every volume across them,
    # instead of two per instance. A fifty-instance RunInstances used to cost
    # 300 API calls inside one 60-second invocation, which times out and
    # replays. Either prefetch returning None means the batch failed for a
    # reason that was not a throttle, and the loop below falls back to the
    # per-instance calls it always made.
    prefetched = _prefetch_instances(instance_ids)
    prefetched_volumes = (
        _prefetch_volumes(list(prefetched.values())) if prefetched else None
    )

    results = []
    for instance_id in instance_ids:
        try:
            instance = _describe_instance(instance_id, prefetched)
        except (ClientError, IndexError, KeyError) as exc:
            if is_throttling_error(exc):
                # Undetermined means "I looked and could not tell". Being
                # throttled means I never looked, and a retry would tell me.
                publish_throttled(VIOLATION_TYPE, instance_id)
                logger.warning('Detection throttled, retrying via event replay', extra={
                    'instance_id': instance_id,
                    'error': str(exc),
                })
                raise

            logger.error('Could not describe instance', extra={
                'instance_id': instance_id,
                'error': str(exc),
            })
            # Caught rather than raised so the other instances named by this
            # event are still assessed, but reported so the gap is not silent.
            publish_detection_undetermined(VIOLATION_TYPE, instance_id)
            send_notice(
                NOTICE_UNDETERMINED,
                instance_id,
                actor,
                f'Could not describe instance to assess EBS encryption: {exc}',
                STATUS_REVIEW,
            )
            results.append({'instance': instance_id, 'status': 'error', 'reason': str(exc)})
            continue

        exempt, exemption_reason = _exemption_status(instance)

        if not exempt and exemption_reason in REJECTED_REASONS:
            # Someone asked for an exemption that does not hold. Check the
            # resource anyway, but say so: they believed it was exempt.
            logger.warning('Exemption rejected, checking the instance anyway', extra={
                'check': VIOLATION_TYPE,
                'instance_id': instance_id,
                'actor': actor,
                'reason': exemption_reason,
                'expiry_tag': EXEMPT_UNTIL_TAG_KEY,
            })
            publish_exemption_rejected(VIOLATION_TYPE, instance_id, exemption_reason)

        if exempt:
            logger.warning('Compliance check bypassed by exemption tag', extra={
                'check': VIOLATION_TYPE,
                'instance_id': instance_id,
                'actor': actor,
                'tag': f'{EXEMPT_TAG_KEY}={EXEMPT_TAG_VALUE}',
            })
            publish_exemption(VIOLATION_TYPE, instance_id)
            send_notice(
                NOTICE_EXEMPTION,
                instance_id,
                actor,
                f'{VIOLATION_TYPE} skipped: instance carries '
                f'{EXEMPT_TAG_KEY}={EXEMPT_TAG_VALUE}',
                STATUS_EXEMPTION,
            )
            results.append({'instance': instance_id, 'status': 'exempt'})
            continue

        try:
            encryption = _volume_encryption_status(
                instance, prefetched_volumes
            )
        except (ClientError, KeyError) as exc:
            if is_throttling_error(exc):
                publish_throttled(VIOLATION_TYPE, instance_id)
                logger.warning('Detection throttled, retrying via event replay', extra={
                    'instance_id': instance_id,
                    'error': str(exc),
                })
                raise

            logger.error('Could not check volume encryption', extra={
                'instance_id': instance_id,
                'error': str(exc),
            })
            results.append({'instance': instance_id, 'status': 'error', 'reason': str(exc)})
            continue

        if encryption == ENCRYPTION_UNDETERMINED:
            reason = 'volume encryption could not be determined'
            logger.warning('Volume encryption could not be determined', extra={
                'instance_id': instance_id,
                'instance_state': instance.get('State', {}).get('Name', 'unknown'),
                'actor': actor,
            })
            # Surfaced rather than remediated: we have not established a
            # violation, so acting on one would be a guess. Someone has to look.
            publish_detection_undetermined(VIOLATION_TYPE, instance_id)
            send_notice(
                NOTICE_UNDETERMINED,
                instance_id,
                actor,
                'Could not determine EBS encryption for this instance; no action taken',
                STATUS_REVIEW,
            )
            results.append({
                'instance': instance_id,
                'status': 'undetermined',
                'reason': reason,
            })
            continue

        if encryption == ENCRYPTION_OK:
            results.append({'instance': instance_id, 'status': 'compliant'})
            continue

        violation_type = VIOLATION_TYPE
        logger.warning('Violation detected', extra={
            'violation': violation_type,
            'instance_id': instance_id,
            'actor': actor,
        })

        try:
            action = _remediate(instance_id, violation_type)
            remediated = True
            logger.info('Remediation applied', extra={
                'instance_id': instance_id,
                'action': action,
            })
        except ClientError as exc:
            if is_throttling_error(exc):
                # A throttle means the remediation was never attempted, so it is
                # not a failure. Re-raising fails the invocation, EventBridge
                # retries it, and it only reaches the DLQ if it keeps failing.
                # Recording it as remediation_failed would lose that retry and
                # leave the resource exposed with nobody coming back to it.
                # Replay is safe here: create_tags and stop_instances are both
                # idempotent, verified against moto.
                publish_throttled(violation_type, instance_id)
                logger.warning('Remediation throttled, retrying via event replay', extra={
                    'instance_id': instance_id,
                    'error': str(exc),
                })
                raise

            remediated = False
            code = exc.response.get('Error', {}).get('Code', '')
            if code == 'UnsupportedOperation':
                # Instance-store backed instances cannot be stopped at all.
                action = (
                    f'Remediation failed ({code}): this instance cannot be stopped, '
                    'which usually means it is instance-store backed'
                )
            else:
                action = f'Remediation failed: {exc}'
            logger.error('Remediation failed', extra={
                'instance_id': instance_id,
                'error': str(exc),
            })

        publish_violation(violation_type, instance_id, remediated)
        send_alert(violation_type, instance_id, actor, action, remediated)

        results.append({
            'instance': instance_id,
            'status': 'remediated' if remediated else 'remediation_failed',
            'violation': violation_type,
            'action': action,
        })

    return {'status': 'processed', 'results': results}


_HANDLERS = {
    'RunInstances': handle_run_instances,
}


def evaluate(event_name: str, detail: dict) -> dict:
    handler = _HANDLERS.get(event_name)
    if handler:
        return handler(detail)
    return {'status': 'no_rule', 'event': event_name}
