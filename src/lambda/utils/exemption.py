"""When a ComplianceExempt tag actually counts.

The tag disables this engine for a resource, which makes it an authorisation
boundary granted by ordinary tagging permissions. It also had no expiry, so
every exemption was permanent. In practice exemptions are temporary — "we need
this open for the migration this week" — and then the migration ends, nobody
removes the tag, and years later there is an exempt resource nobody can explain.

An exemption now needs a ComplianceExemptUntil date, and this **fails closed**:
expired, malformed, or missing all mean not exempt, so the resource gets
checked.

That is the opposite direction from the self-invocation guard in handler.py,
which fails open, and the difference is deliberate. The rule is not "always fail
closed" — it is fail in the direction where being wrong is noisy. A resource
checked that someone wanted skipped produces a complaint. An unparseable date
treated as exempt produces a permanent silent bypass, which is the exact thing
this control exists to prevent.

This module holds only the pure decision. Each rule module keeps its own way of
fetching tags, because those genuinely differ: S3 makes an API call that can
fail, EC2 reads them inline off a response it already has.
"""

from datetime import datetime, time, timezone

EXEMPT_TAG_KEY = 'ComplianceExempt'
EXEMPT_TAG_VALUE = 'true'
EXEMPT_UNTIL_TAG_KEY = 'ComplianceExemptUntil'

# The resource is genuinely exempt.
EXEMPT = 'exempt'

# Nobody asked for an exemption. Not interesting, and not worth a metric.
NOT_TAGGED = 'not_tagged'

# Someone asked for an exemption and it does not hold. Each of these is worth
# surfacing, and they need different responses: an expired one was deliberate
# and lapsed, a missing one predates the expiry requirement, a malformed one is
# a typo somebody needs to fix.
EXPIRED = 'expired'
MISSING_EXPIRY = 'missing_expiry'
MALFORMED_EXPIRY = 'malformed_expiry'

REJECTED_REASONS = frozenset({EXPIRED, MISSING_EXPIRY, MALFORMED_EXPIRY})


def _parse_until(raw: str) -> datetime | None:
    """Parse the expiry tag, or return None if it cannot be trusted."""
    text = (raw or '').strip()
    if not text:
        return None

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None

    # A date with no time means "through the end of that day". Expiring at
    # midnight would surprise everyone who wrote a date expecting to have it.
    if parsed.time() == time(0, 0) and len(text) == 10:
        parsed = datetime.combine(parsed.date(), time.max)

    # A tag written without a timezone must not blow up the comparison.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed


def evaluate_exemption(tags: dict, now: datetime | None = None) -> tuple[bool, str]:
    """Decide whether a resource's tags exempt it, and say why if they do not.

    Returns (is_exempt, reason). A reason in REJECTED_REASONS means someone
    asked for an exemption that does not hold, which is worth reporting.
    """
    value = tags.get(EXEMPT_TAG_KEY) or ''
    if value.strip().lower() != EXEMPT_TAG_VALUE:
        return False, NOT_TAGGED

    if EXEMPT_UNTIL_TAG_KEY not in tags:
        return False, MISSING_EXPIRY

    until = _parse_until(tags.get(EXEMPT_UNTIL_TAG_KEY, ''))
    if until is None:
        return False, MALFORMED_EXPIRY

    if (now or datetime.now(timezone.utc)) > until:
        return False, EXPIRED

    return True, EXEMPT
