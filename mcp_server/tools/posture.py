"""Compliance posture from the metrics the engine publishes."""

from datetime import datetime, timedelta, timezone

from mcp_server.aws_clients import read_only_client
from mcp_server.config import load_config

# The five metrics src/lambda/utils/cloudwatch_utils.py publishes. The last two
# were added to surface the engine's quiet failure modes: a check that could not
# reach a verdict, and a resource that bypassed checks via the exemption tag.
ENGINE_METRICS = (
    'ViolationsDetected',
    'RemediationsApplied',
    'RemediationsFailed',
    'DetectionsUndetermined',
    'ExemptionsApplied',
)

# ViolationsDetected and the remediation counters are dimensioned by
# ViolationType; the undetermined and exemption counters by CheckType.
_DIMENSION = {
    'ViolationsDetected': 'ViolationType',
    'RemediationsApplied': 'ViolationType',
    'RemediationsFailed': 'ViolationType',
    'DetectionsUndetermined': 'CheckType',
    'ExemptionsApplied': 'CheckType',
}

MIN_HOURS = 1
MAX_HOURS = 720  # 30 days, CloudWatch's practical retention for this resolution


def _client():
    return read_only_client('cloudwatch', load_config().region)


def get_compliance_posture(hours: int = 24) -> dict:
    """Summarise what the compliance engine has seen over a time window."""
    config = load_config()
    hours = max(MIN_HOURS, min(int(hours), MAX_HOURS))

    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)

    # SEARCH returns one series per dimension value, so the query does not need
    # to know which violation types exist.
    queries = [
        {
            'Id': f'q{index}',
            'Expression': (
                f"SEARCH('{{{config.metric_namespace},{_DIMENSION[metric]}}} "
                f"MetricName=\"{metric}\"', 'Sum', 300)"
            ),
            'ReturnData': True,
        }
        for index, metric in enumerate(ENGINE_METRICS)
    ]

    response = _client().get_metric_data(
        MetricDataQueries=queries,
        StartTime=start,
        EndTime=end,
    )

    totals: dict[str, int] = {}
    by_type: dict[str, dict[str, int]] = {}

    for series in response.get('MetricDataResults', []):
        # CloudWatch labels a SEARCH series "<DimensionValue> <MetricName>".
        label = series.get('Label', '')
        parts = label.rsplit(' ', 1)
        if len(parts) != 2:
            continue
        dimension_value, metric_name = parts

        total = int(sum(series.get('Values', [])))
        if not total:
            continue

        totals[metric_name] = totals.get(metric_name, 0) + total
        by_type.setdefault(dimension_value, {})
        by_type[dimension_value][metric_name] = (
            by_type[dimension_value].get(metric_name, 0) + total
        )

    result = {
        'window_hours': hours,
        'region': config.region,
        'namespace': config.metric_namespace,
        'totals': totals,
        'by_type': by_type,
    }

    if not totals:
        # An account with nothing wrong and an engine receiving no events at all
        # produce identical output here. Reporting "all clear" would be a guess.
        result['warning'] = (
            'No metric data in this window. That means either nothing was '
            'detected, or the engine is not receiving events at all. Check that '
            'a CloudTrail trail is logging write management events in '
            f'{config.region}, and that this is the region the engine is '
            'deployed in. Do not report the account as clean on this alone.'
        )

    return result
