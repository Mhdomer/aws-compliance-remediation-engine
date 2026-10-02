"""Warn before an exemption lapses, rather than after.

Exemptions expire, which stopped a tag granted once from suppressing a control
forever. What it did not do is tell anybody. On the expiry date the resource
silently starts being checked again, and the owner finds out when the engine
remediates something they believed was exempted.

This sweep runs on a schedule, reads the exemption tags across the account, and
sends a notice for anything lapsing within the next week. A notice rather than
an alert: nothing has been found and nothing is wrong yet, which is the same
line send_notice() already draws for exemptions and undetermined checks.

It deliberately says nothing about exemptions that have already expired. The
engine rejects those on the next event and reports it then. Warning that
something is "about to" expire when it already has is the kind of small
inaccuracy that teaches people to stop reading the mailbox.
"""

import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from utils.exemption import (
    EXPIRED,
    EXEMPT_TAG_KEY,
    EXEMPT_TAG_VALUE,
    EXEMPT_UNTIL_TAG_KEY,
    _parse_until,
    evaluate_exemption,
)
from utils.cloudwatch_utils import publish_exemption_expiring
from utils.logger import setup_logger
from utils.notifier import NOTICE_EXEMPTION_EXPIRING, STATUS_REVIEW, send_notice

logger = setup_logger(__name__)

# Far enough ahead to renew or remove the tag, close enough that the warning
# still means something. Warning months early is indistinguishable from noise.
WARN_WITHIN_DAYS = 7

_client = None


def _get_client():
    global _client
    if _client is None:
        _client = boto3.client(
            'resourcegroupstaggingapi',
            region_name=os.environ.get('AWS_REGION', 'us-east-1'),
        )
    return _client


def _tags_of(mapping: dict) -> dict:
    return {t.get('Key'): t.get('Value', '') for t in mapping.get('Tags', [])}


def sweep(now: datetime | None = None) -> dict:
    """Report exemptions lapsing within WARN_WITHIN_DAYS.

    Returns counts rather than raising on a lookup failure, but says plainly
    that the lookup failed. Zero exemptions found and "I could not look" are
    different answers and must not arrive looking the same.
    """
    now = now or datetime.now(timezone.utc)

    expiring = []
    expired = 0
    no_expiry = 0
    checked = 0

    try:
        paginator = _get_client().get_paginator('get_resources')
        pages = paginator.paginate(
            TagFilters=[{'Key': EXEMPT_TAG_KEY, 'Values': [EXEMPT_TAG_VALUE]}]
        )

        for page in pages:
            for mapping in page.get('ResourceTagMappingList', []):
                checked += 1
                arn = mapping.get('ResourceARN', 'unknown')
                tags = _tags_of(mapping)

                is_exempt, reason = evaluate_exemption(tags, now)
                if not is_exempt:
                    if reason == EXPIRED:
                        # Already lapsed. The engine rejects it on the next
                        # event for that resource and says so then.
                        expired += 1
                    else:
                        # Tagged exempt, but the expiry is missing or
                        # unreadable, so the exemption is not being honoured at
                        # all. Somebody believes this resource is exempted and
                        # it is not. Worth more attention than one about to
                        # lapse, not less.
                        no_expiry += 1
                    continue

                raw = tags.get(EXEMPT_UNTIL_TAG_KEY, '')
                until = _parse_until(raw)
                if until is None:
                    # evaluate_exemption already rejects an unparseable date,
                    # so reaching here would mean the two disagree.
                    no_expiry += 1
                    continue

                days_left = (until - now).days
                if days_left <= WARN_WITHIN_DAYS:
                    expiring.append((arn, raw, days_left))

    except ClientError as exc:
        logger.error('Could not list exemptions', extra={'error': str(exc)})
        return {
            'status': 'error',
            'expiring': 0,
            'expired': 0,
            'no_expiry': 0,
            'checked': 0,
            'warning': (
                'The exemption lookup failed, so this is not a report that '
                'nothing is expiring. It is a report that nothing could be '
                f'read: {exc}'
            ),
        }

    for arn, raw, days_left in expiring:
        logger.warning('Exemption expiring soon', extra={
            'resource': arn,
            'expires': raw,
            'days_left': days_left,
            'tag': EXEMPT_UNTIL_TAG_KEY,
        })
        publish_exemption_expiring(arn)
        send_notice(
            NOTICE_EXEMPTION_EXPIRING,
            arn,
            'scheduled-sweep',
            f'The compliance exemption on {arn} expires on {raw} '
            f'({days_left} days). After that the engine checks it again and '
            'will remediate anything it finds. Renew the '
            f'{EXEMPT_UNTIL_TAG_KEY} tag or remove the exemption deliberately.',
            STATUS_REVIEW,
        )

    logger.info('Exemption expiry sweep complete', extra={
        'checked': checked,
        'expiring': len(expiring),
        'expired': expired,
        'no_expiry': no_expiry,
    })

    return {
        'status': 'ok',
        'checked': checked,
        'expiring': len(expiring),
        'expired': expired,
        'no_expiry': no_expiry,
    }
