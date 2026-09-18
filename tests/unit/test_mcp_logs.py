from unittest.mock import MagicMock, patch

import pytest


def _row(**fields) -> list[dict]:
    return [{'field': k, 'value': v} for k, v in fields.items()]


@pytest.fixture(autouse=True)
def region(monkeypatch):
    monkeypatch.setenv('COMPLIANCE_REGION', 'us-east-1')
    monkeypatch.setenv('COMPLIANCE_LOG_GROUP', '/aws/lambda/compliance-engine-prod')


@pytest.fixture
def logs():
    from mcp_server.tools import logs as logs_module
    client = MagicMock()
    client.start_query.return_value = {'queryId': 'q-1'}
    client.get_query_results.return_value = {'status': 'Complete', 'results': []}
    # Patch sleep so the poll loop does not actually wait.
    with patch.object(logs_module, '_client', return_value=client), \
            patch.object(logs_module.time, 'sleep'):
        yield client


class TestSearchComplianceLogs:
    def test_records_are_flattened_to_dicts(self, logs):
        from mcp_server.tools.logs import search_compliance_logs
        logs.get_query_results.return_value = {
            'status': 'Complete',
            'results': [_row(**{
                '@timestamp': '2026-09-18 14:40:00',
                'violation': 'SG_OPEN_PORT_22',
                'actor': 'arn:aws:iam::1:user/dev',
            })],
        }

        result = search_compliance_logs(hours=24)

        assert result['records'] == [{
            '@timestamp': '2026-09-18 14:40:00',
            'violation': 'SG_OPEN_PORT_22',
            'actor': 'arn:aws:iam::1:user/dev',
        }]
        assert result['count'] == 1

    def test_queries_the_configured_log_group(self, logs):
        from mcp_server.tools.logs import search_compliance_logs
        search_compliance_logs(hours=24)

        _, kwargs = logs.start_query.call_args
        assert kwargs['logGroupName'] == '/aws/lambda/compliance-engine-prod'

    def test_pattern_is_applied_as_a_filter(self, logs):
        from mcp_server.tools.logs import search_compliance_logs
        search_compliance_logs(pattern='SG_OPEN_PORT_22', hours=24)

        _, kwargs = logs.start_query.call_args
        assert 'SG_OPEN_PORT_22' in kwargs['queryString']
        assert 'filter' in kwargs['queryString']

    def test_no_pattern_means_no_filter_clause(self, logs):
        from mcp_server.tools.logs import search_compliance_logs
        search_compliance_logs(hours=24)

        _, kwargs = logs.start_query.call_args
        assert 'filter' not in kwargs['queryString']

    def test_quotes_in_a_pattern_cannot_break_the_query(self, logs):
        from mcp_server.tools.logs import search_compliance_logs
        # A model can pass anything here. Unescaped, this would corrupt the
        # query string rather than search for the literal text.
        search_compliance_logs(pattern='a"b/c\\d', hours=24)

        _, kwargs = logs.start_query.call_args
        assert '"' not in kwargs['queryString'].split('filter')[1].split('\n')[0]

    def test_polls_until_the_query_completes(self, logs):
        from mcp_server.tools.logs import search_compliance_logs
        logs.get_query_results.side_effect = [
            {'status': 'Running', 'results': []},
            {'status': 'Running', 'results': []},
            {'status': 'Complete', 'results': [_row(violation='S3_PUBLIC_ACL')]},
        ]

        result = search_compliance_logs(hours=24)

        assert result['count'] == 1
        assert logs.get_query_results.call_count == 3

    def test_a_query_that_never_finishes_is_reported_not_hung(self, logs):
        from mcp_server.tools.logs import search_compliance_logs
        logs.get_query_results.return_value = {'status': 'Running', 'results': []}

        result = search_compliance_logs(hours=24)

        # Returning a timeout beats blocking the MCP client forever.
        assert result['status'] == 'Timeout'
        assert result['records'] == []

    def test_a_failed_query_is_reported(self, logs):
        from mcp_server.tools.logs import search_compliance_logs
        logs.get_query_results.return_value = {'status': 'Failed', 'results': []}

        assert search_compliance_logs(hours=24)['status'] == 'Failed'

    def test_missing_log_group_is_explained_not_raised(self, logs):
        from botocore.exceptions import ClientError
        from mcp_server.tools.logs import search_compliance_logs
        logs.start_query.side_effect = ClientError(
            {'Error': {'Code': 'ResourceNotFoundException', 'Message': 'no'}},
            'StartQuery',
        )

        result = search_compliance_logs(hours=24)

        # Almost always means the engine was never deployed to this region.
        assert result['status'] == 'LogGroupNotFound'
        assert 'deployed' in result['warning'].lower()

    def test_limit_is_clamped(self, logs):
        from mcp_server.tools.logs import search_compliance_logs
        search_compliance_logs(hours=24, limit=99999)

        _, kwargs = logs.start_query.call_args
        assert 'limit 1000' in kwargs['queryString']


class TestGetResourceHistory:
    def test_filters_on_the_resource_id(self, logs):
        from mcp_server.tools.logs import get_resource_history
        get_resource_history('sg-0abc123', hours=48)

        _, kwargs = logs.start_query.call_args
        assert 'sg-0abc123' in kwargs['queryString']

    def test_reports_the_resource_it_looked_up(self, logs):
        from mcp_server.tools.logs import get_resource_history
        result = get_resource_history('i-0abc123')

        assert result['resource_id'] == 'i-0abc123'

    def test_empty_history_is_not_read_as_compliant(self, logs):
        from mcp_server.tools.logs import get_resource_history
        result = get_resource_history('i-0abc123')

        assert result['records'] == []
        # No log lines means the engine never evaluated it, which is different
        # from having evaluated it and found nothing wrong.
        assert 'never' in result['warning'].lower()
