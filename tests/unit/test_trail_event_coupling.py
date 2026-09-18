"""The trail's read_write_type and the registry's event names are coupled.

infrastructure/cloudtrail.tf logs WriteOnly management events. That is correct
for the four rules registered today, all of which match write events. Add a rule
for a read-only event and it silently never fires, because two separate things
would both need changing:

  1. the trail would have to log "All" rather than "WriteOnly"
  2. that EventBridge rule would need
     state = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS", because
     default-enabled rules only match write management events

Neither omission errors. The rule deploys, reports healthy, and receives
nothing. Until now the only thing guarding that was a code comment, and by this
project's own lesson a comment is not a control.
"""

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CLOUDTRAIL_TF = REPO_ROOT / 'infrastructure' / 'cloudtrail.tf'
EVENTBRIDGE_TF = REPO_ROOT / 'infrastructure' / 'eventbridge.tf'
EVENTS_DIR = REPO_ROOT / 'tests' / 'events'

# CloudTrail classifies an event as read-only in its own `readOnly` field, but
# that field is not present on every record - two of the four captured fixtures
# here omit it. So the verb prefix is the primary check and readOnly only
# corroborates where it exists.
READ_ONLY_PREFIXES = (
    'Get', 'List', 'Describe', 'Lookup', 'Head', 'Search', 'Query', 'Select',
    'Preview', 'Estimate', 'Validate', 'Check', 'Test', 'Simulate',
)

READ_ONLY_RULE_STATE = 'ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS'


def trail_read_write_type() -> str:
    match = re.search(
        r'read_write_type\s*=\s*"([^"]+)"', CLOUDTRAIL_TF.read_text(encoding='utf-8')
    )
    assert match, 'could not find read_write_type in cloudtrail.tf'
    return match.group(1)


def rules_from_terraform() -> dict[str, str]:
    """eventName -> the rule's `state`, or '' when it uses the default."""
    text = EVENTBRIDGE_TF.read_text(encoding='utf-8')
    rules = {}
    for block in text.split('resource "aws_cloudwatch_event_rule"')[1:]:
        event = re.search(r'eventName\s*=\s*\["([^"]+)"\]', block)
        state = re.search(r'^\s*state\s*=\s*"([^"]+)"', block, re.MULTILINE)
        if event:
            rules[event.group(1)] = state.group(1) if state else ''
    return rules


def registry_event_names() -> set[str]:
    import handler
    return {event_name for _source, event_name in handler._RULE_REGISTRY}


def is_read_only(event_name: str) -> bool:
    return event_name.startswith(READ_ONLY_PREFIXES)


class TestTheCouplingHolds:
    def test_there_is_something_to_check(self):
        # Without this, a parsing change could empty every set below and make
        # the whole file pass by checking nothing.
        assert registry_event_names()
        assert rules_from_terraform()
        assert trail_read_write_type()

    def test_a_writeonly_trail_implies_every_event_is_a_write(self):
        if trail_read_write_type() != 'WriteOnly':
            pytest.skip('trail logs All management events, so this does not apply')

        read_only = {name for name in registry_event_names() if is_read_only(name)}
        assert not read_only, (
            f'{sorted(read_only)} look like read-only events, but the trail in '
            'cloudtrail.tf logs WriteOnly management events, so CloudTrail will '
            'never record them and the rule will never fire. Set '
            'read_write_type = "All" and give those rules '
            f'state = "{READ_ONLY_RULE_STATE}".'
        )

    def test_read_only_events_carry_the_required_rule_state(self):
        for event_name, state in rules_from_terraform().items():
            if not is_read_only(event_name):
                continue
            assert state == READ_ONLY_RULE_STATE, (
                f'{event_name} is a read-only management event, so its rule needs '
                f'state = "{READ_ONLY_RULE_STATE}". Default-enabled rules only '
                'match write management events, so it would never fire.'
            )

    def test_write_events_do_not_need_the_special_state(self):
        for event_name, state in rules_from_terraform().items():
            if is_read_only(event_name):
                continue
            assert state != READ_ONLY_RULE_STATE, (
                f'{event_name} is a write event and does not need '
                f'{READ_ONLY_RULE_STATE}. Setting it there widens what the rule '
                'matches for no reason.'
            )

    def test_terraform_and_the_registry_agree_on_the_event_set(self):
        # A rule with no registry entry delivers events that return no_rule;
        # a registry entry with no rule never fires. Neither announces itself.
        assert set(rules_from_terraform()) == registry_event_names()


class TestFixturesCorroborate:
    def test_no_captured_fixture_is_a_read_only_event(self):
        checked = 0
        for path in sorted(EVENTS_DIR.glob('*.json')):
            detail = json.loads(path.read_text(encoding='utf-8'))['detail']
            if 'readOnly' not in detail:
                continue
            checked += 1
            assert detail['readOnly'] is False, (
                f'{path.name} is a read-only event, which a WriteOnly trail '
                'would never deliver'
            )
        # Two of the four fixtures omit the field entirely, which is why the
        # verb-prefix check above is the primary guard rather than this one.
        assert checked >= 2, 'expected at least two fixtures to carry readOnly'

    def test_the_prefix_check_agrees_with_cloudtrails_own_classification(self):
        for path in sorted(EVENTS_DIR.glob('*.json')):
            detail = json.loads(path.read_text(encoding='utf-8'))['detail']
            if 'readOnly' not in detail:
                continue
            assert is_read_only(detail['eventName']) == detail['readOnly'], (
                f"the verb heuristic disagrees with AWS for {detail['eventName']}"
            )


class TestTheGuardItselfWorks:
    @pytest.mark.parametrize('name', [
        'GetBucketAcl', 'ListBuckets', 'DescribeInstances', 'LookupEvents',
    ])
    def test_read_only_names_are_recognised(self, name):
        assert is_read_only(name) is True

    @pytest.mark.parametrize('name', [
        'PutBucketAcl', 'PutBucketEncryption', 'RunInstances',
        'AuthorizeSecurityGroupIngress', 'CreateBucket', 'DeleteBucket',
    ])
    def test_write_names_are_not_flagged(self, name):
        assert is_read_only(name) is False
