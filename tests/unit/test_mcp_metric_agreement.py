"""The engine's metrics and the MCP server's idea of them are coupled.

The Lambda publishes metrics from src/lambda/utils/cloudwatch_utils.py. Two
places in mcp_server/ hold their own hardcoded copy of that list:

  1. tools/posture.py   ENGINE_METRICS   - which metrics get_compliance_posture
                                           queries, so a missing one is simply
                                           never reported
  2. tools/engine_rules.py metrics_published - what describe_engine_rules tells
                                           an agent the engine publishes, so a
                                           missing one is never asked about

Neither omission errors. Found on a live deployment 2026-09-25: the engine was
publishing ExemptionsRejected, RemediationsThrottled and ViolationAttemptsBlocked,
and the MCP layer reported none of them. An expired exemption is exactly the kind
of thing an agent is supposed to surface, and it was invisible.

Every metric added since the MCP server was written had gone missing the same
way, which is what makes this a coupling problem rather than three oversights.
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CLOUDWATCH_UTILS = ROOT / 'src' / 'lambda' / 'utils' / 'cloudwatch_utils.py'
POSTURE = ROOT / 'mcp_server' / 'tools' / 'posture.py'
ENGINE_RULES = ROOT / 'mcp_server' / 'tools' / 'engine_rules.py'


def _engine_metric_names() -> set:
    """Every MetricName the Lambda can publish.

    Read out of the source rather than imported, so this stays honest even if
    a metric is published from a branch no test happens to exercise.
    """
    source = CLOUDWATCH_UTILS.read_text(encoding='utf-8')
    names = set(re.findall(r"'MetricName':\s*'([A-Za-z]+)'", source))

    # RemediationsApplied/Failed are chosen by a ternary on one line, so the
    # literal above only captures one of them.
    names |= set(re.findall(
        r"'MetricName':\s*'([A-Za-z]+)'\s+if\s+\w+\s+else\s+'([A-Za-z]+)'",
        source,
    ) and sum(re.findall(
        r"'MetricName':\s*'([A-Za-z]+)'\s+if\s+\w+\s+else\s+'([A-Za-z]+)'",
        source,
    ), ()))

    assert names, 'found no metric names in cloudwatch_utils.py, the regex has rotted'
    return names


def _listed_in(path: Path, anchor: str) -> set:
    """The metric names inside one list/tuple literal in an MCP module."""
    source = path.read_text(encoding='utf-8')
    start = source.index(anchor)
    chunk = source[start:start + 800]
    opener = '(' if '(' in chunk[:len(anchor) + 4] else '['
    closer = ')' if opener == '(' else ']'
    body = chunk[chunk.index(opener) + 1:chunk.index(closer)]
    return set(re.findall(r"'([A-Za-z]+)'", body))


class TestMcpKnowsEveryMetricTheEngineEmits:
    def test_posture_queries_every_engine_metric(self):
        engine = _engine_metric_names()
        queried = _listed_in(POSTURE, 'ENGINE_METRICS')

        missing = sorted(engine - queried)
        assert not missing, (
            f'the engine publishes {missing} but get_compliance_posture never '
            'queries them, so they are silently absent from every posture '
            'report. Add them to ENGINE_METRICS in mcp_server/tools/posture.py '
            'and give each one a dimension in _DIMENSION.'
        )

    def test_posture_dimensions_cover_every_metric_it_queries(self):
        queried = _listed_in(POSTURE, 'ENGINE_METRICS')
        dimensioned = set(re.findall(
            r"'([A-Za-z]+)':\s*'(?:ViolationType|CheckType|EventName|ErrorCode)'",
            POSTURE.read_text(encoding='utf-8'),
        ))

        missing = sorted(queried - dimensioned)
        assert not missing, (
            f'{missing} are queried without a dimension mapping, so the '
            'breakdown by type will be empty for them'
        )

    def test_describe_engine_rules_lists_every_engine_metric(self):
        engine = _engine_metric_names()
        advertised = _listed_in(ENGINE_RULES, 'metrics_published')

        missing = sorted(engine - advertised)
        assert not missing, (
            f'the engine publishes {missing} but describe_engine_rules does not '
            'mention them. That tool is how an agent learns what signals exist, '
            'so anything absent here is a signal it will never think to ask '
            'about. Update metrics_published in mcp_server/tools/engine_rules.py.'
        )

    def test_neither_module_advertises_a_metric_that_does_not_exist(self):
        engine = _engine_metric_names()
        for path, anchor in ((POSTURE, 'ENGINE_METRICS'),
                             (ENGINE_RULES, 'metrics_published')):
            extra = sorted(_listed_in(path, anchor) - engine)
            assert not extra, (
                f'{path.name} names {extra}, which the engine never publishes. '
                'A metric that is queried but never emitted reads as a flat '
                'zero, which looks like good news.'
            )
