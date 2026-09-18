"""An exemption without an expiry is a permanent bypass.

Exemptions are meant to be temporary ("we need this open for the migration this
week"). Then the migration ends, nobody removes the tag, and two years later
there is a permanently exempt resource nobody can explain.

This fails CLOSED: expired, malformed, or missing expiry all mean NOT exempt.
The opposite direction would make a typo in a date into a silent permanent
bypass, which is the exact thing the control exists to prevent.
"""

from datetime import datetime, timedelta, timezone

import pytest

NOW = datetime(2026, 9, 19, 12, 0, 0, tzinfo=timezone.utc)


def _tags(exempt='true', until=None):
    tags = {}
    if exempt is not None:
        tags['ComplianceExempt'] = exempt
    if until is not None:
        tags['ComplianceExemptUntil'] = until
    return tags


class TestValidExemption:
    def test_future_date_is_exempt(self):
        from utils.exemption import EXEMPT, evaluate_exemption
        exempt, reason = evaluate_exemption(_tags(until='2026-12-31'), now=NOW)
        assert exempt is True
        assert reason == EXEMPT

    def test_today_is_still_exempt_until_end_of_day(self):
        from utils.exemption import evaluate_exemption
        # "until 2026-09-19" most naturally means through the end of that day,
        # not from midnight. Expiring at 00:00 would surprise everyone.
        exempt, _ = evaluate_exemption(_tags(until='2026-09-19'), now=NOW)
        assert exempt is True

    def test_full_iso_timestamp_is_accepted(self):
        from utils.exemption import evaluate_exemption
        exempt, _ = evaluate_exemption(
            _tags(until='2026-12-31T23:59:59+00:00'), now=NOW
        )
        assert exempt is True

    def test_tag_value_is_case_insensitive(self):
        from utils.exemption import evaluate_exemption
        exempt, _ = evaluate_exemption(_tags(exempt='TRUE', until='2026-12-31'), now=NOW)
        assert exempt is True


class TestRejectedExemption:
    def test_expired_date_is_not_exempt(self):
        from utils.exemption import EXPIRED, evaluate_exemption
        exempt, reason = evaluate_exemption(_tags(until='2026-09-18'), now=NOW)
        assert exempt is False
        assert reason == EXPIRED

    def test_missing_expiry_is_not_exempt(self):
        from utils.exemption import MISSING_EXPIRY, evaluate_exemption
        # This is the case that made the whole tag a permanent bypass.
        exempt, reason = evaluate_exemption(_tags(), now=NOW)
        assert exempt is False
        assert reason == MISSING_EXPIRY

    def test_malformed_expiry_is_not_exempt(self):
        from utils.exemption import MALFORMED_EXPIRY, evaluate_exemption
        # Fails closed on purpose. Treating an unparseable date as exempt would
        # turn a typo into a permanent silent bypass.
        exempt, reason = evaluate_exemption(_tags(until='2026-13-45'), now=NOW)
        assert exempt is False
        assert reason == MALFORMED_EXPIRY

    def test_empty_expiry_is_malformed_not_missing(self):
        from utils.exemption import MALFORMED_EXPIRY, evaluate_exemption
        exempt, reason = evaluate_exemption(_tags(until='   '), now=NOW)
        assert exempt is False
        assert reason == MALFORMED_EXPIRY

    def test_nonsense_expiry_is_not_exempt(self):
        from utils.exemption import MALFORMED_EXPIRY, evaluate_exemption
        exempt, reason = evaluate_exemption(_tags(until='forever'), now=NOW)
        assert exempt is False
        assert reason == MALFORMED_EXPIRY


class TestNotTagged:
    def test_no_tags_at_all(self):
        from utils.exemption import NOT_TAGGED, evaluate_exemption
        exempt, reason = evaluate_exemption({}, now=NOW)
        assert exempt is False
        # Distinct from a rejected exemption: nobody asked for one, so there is
        # nothing to report.
        assert reason == NOT_TAGGED

    def test_exempt_false_is_not_a_rejected_exemption(self):
        from utils.exemption import NOT_TAGGED, evaluate_exemption
        exempt, reason = evaluate_exemption(_tags(exempt='false', until='2026-12-31'), now=NOW)
        assert exempt is False
        assert reason == NOT_TAGGED

    def test_expiry_without_the_exempt_tag_is_not_tagged(self):
        from utils.exemption import NOT_TAGGED, evaluate_exemption
        exempt, reason = evaluate_exemption(_tags(exempt=None, until='2026-12-31'), now=NOW)
        assert exempt is False
        assert reason == NOT_TAGGED


class TestDefaults:
    def test_now_defaults_to_the_current_time(self):
        from utils.exemption import evaluate_exemption
        far_future = (datetime.now(timezone.utc) + timedelta(days=365)).date().isoformat()
        exempt, _ = evaluate_exemption(_tags(until=far_future))
        assert exempt is True

    def test_a_rejected_reason_is_never_the_exempt_reason(self):
        from utils.exemption import EXEMPT, REJECTED_REASONS
        assert EXEMPT not in REJECTED_REASONS
        assert REJECTED_REASONS


@pytest.mark.parametrize('naive', ['2026-12-31T10:00:00', '2026-12-31'])
def test_naive_timestamps_do_not_crash_on_comparison(naive):
    from utils.exemption import evaluate_exemption
    # A tag written without a timezone must not raise "can't compare offset-naive
    # and offset-aware datetimes" at runtime.
    exempt, _ = evaluate_exemption(_tags(until=naive), now=NOW)
    assert exempt is True
