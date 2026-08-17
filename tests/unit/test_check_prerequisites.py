import sys
import os
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'scripts'))


def _trails(*names):
    return {'trailList': [
        {'Name': n, 'TrailARN': f'arn:aws:cloudtrail:us-east-1:123456789012:trail/{n}',
         'HomeRegion': 'us-east-1', 'IsMultiRegionTrail': True}
        for n in names
    ]}


def _selectors(read_write_type='All', include_management=True):
    return {'EventSelectors': [{
        'ReadWriteType': read_write_type,
        'IncludeManagementEvents': include_management,
        'DataResources': [],
    }]}


def _client(trails, logging=True, selectors=None):
    client = MagicMock()
    client.describe_trails.return_value = trails
    client.get_trail_status.return_value = {'IsLogging': logging}
    client.get_event_selectors.return_value = selectors or _selectors()
    return client


class TestCloudTrailPrerequisite:
    def test_no_trail_at_all_fails(self):
        from check_prerequisites import check_cloudtrail
        result = check_cloudtrail(_client({'trailList': []}))

        assert result.ok is False
        assert 'no cloudtrail trail' in result.detail.lower()

    def test_trail_that_is_not_logging_fails(self):
        from check_prerequisites import check_cloudtrail
        result = check_cloudtrail(_client(_trails('audit'), logging=False))

        # A trail that exists but is stopped delivers nothing to EventBridge.
        assert result.ok is False
        assert 'not logging' in result.detail.lower()

    def test_trail_without_management_events_fails(self):
        from check_prerequisites import check_cloudtrail
        client = _client(_trails('audit'), selectors=_selectors(include_management=False))
        result = check_cloudtrail(client)

        assert result.ok is False
        assert 'management events' in result.detail.lower()

    def test_read_only_trail_fails(self):
        from check_prerequisites import check_cloudtrail
        client = _client(_trails('audit'), selectors=_selectors(read_write_type='ReadOnly'))
        result = check_cloudtrail(client)

        # All four rules match write events; a ReadOnly trail never sees them.
        assert result.ok is False
        assert 'writeonly' in result.detail.lower() or 'write' in result.detail.lower()

    def test_write_only_trail_passes(self):
        from check_prerequisites import check_cloudtrail
        client = _client(_trails('audit'), selectors=_selectors(read_write_type='WriteOnly'))
        result = check_cloudtrail(client)

        assert result.ok is True

    def test_all_events_trail_passes(self):
        from check_prerequisites import check_cloudtrail
        result = check_cloudtrail(_client(_trails('audit')))

        assert result.ok is True
        assert 'audit' in result.detail

    def test_one_good_trail_among_several_passes(self):
        from check_prerequisites import check_cloudtrail
        client = _client(_trails('stopped-one', 'good-one'))
        # First trail is stopped, second is fine.
        client.get_trail_status.side_effect = [{'IsLogging': False}, {'IsLogging': True}]
        result = check_cloudtrail(client)

        assert result.ok is True

    def test_trail_with_no_event_selectors_is_treated_as_management(self):
        from check_prerequisites import check_cloudtrail
        # CloudTrail includes management events by default, and a trail created
        # without explicit selectors returns an empty list.
        client = _client(_trails('audit'), selectors={'EventSelectors': []})
        result = check_cloudtrail(client)

        assert result.ok is True

    def test_permission_error_is_reported_not_swallowed(self):
        from botocore.exceptions import ClientError
        from check_prerequisites import check_cloudtrail

        client = MagicMock()
        client.describe_trails.side_effect = ClientError(
            {'Error': {'Code': 'AccessDeniedException', 'Message': 'nope'}}, 'DescribeTrails'
        )
        result = check_cloudtrail(client)

        # "I could not check" must not read as "everything is fine".
        assert result.ok is False
        assert 'accessdenied' in result.detail.lower()


class TestExitCode:
    def test_main_exits_nonzero_when_a_check_fails(self):
        from check_prerequisites import main
        with patch('check_prerequisites._cloudtrail_client', return_value=_client({'trailList': []})):
            assert main([]) == 1

    def test_main_exits_zero_when_all_checks_pass(self):
        from check_prerequisites import main
        with patch('check_prerequisites._cloudtrail_client', return_value=_client(_trails('audit'))):
            assert main([]) == 0


class TestPreflightErrorBranches:
    def test_unreadable_trail_status_is_reported(self):
        from botocore.exceptions import ClientError
        from check_prerequisites import check_cloudtrail

        client = _client(_trails('audit'))
        client.get_trail_status.side_effect = ClientError(
            {'Error': {'Code': 'AccessDeniedException', 'Message': 'no'}}, 'GetTrailStatus'
        )
        result = check_cloudtrail(client)

        assert result.ok is False
        assert 'could not read status' in result.detail.lower()

    def test_unreadable_event_selectors_are_reported(self):
        from botocore.exceptions import ClientError
        from check_prerequisites import check_cloudtrail

        client = _client(_trails('audit'))
        client.get_event_selectors.side_effect = ClientError(
            {'Error': {'Code': 'AccessDeniedException', 'Message': 'no'}}, 'GetEventSelectors'
        )
        result = check_cloudtrail(client)

        assert result.ok is False
        assert 'event selectors' in result.detail.lower()

    def test_client_factory_asks_for_cloudtrail(self):
        from unittest.mock import patch as _patch
        import check_prerequisites

        with _patch('boto3.client', return_value=MagicMock()) as make_client:
            check_prerequisites._cloudtrail_client()

        make_client.assert_called_once_with('cloudtrail')


class TestRegionResolution:
    def test_explicit_region_wins(self, monkeypatch):
        monkeypatch.setenv('COMPLIANCE_REGION', 'ap-southeast-1')
        from check_prerequisites import resolve_region

        region, warning = resolve_region('us-east-1')
        assert region == 'us-east-1'
        assert warning is None

    def test_falls_back_to_the_compliance_region_variable(self, monkeypatch):
        monkeypatch.setenv('COMPLIANCE_REGION', 'us-east-1')
        from check_prerequisites import resolve_region

        region, warning = resolve_region(None)
        assert region == 'us-east-1'
        assert warning is None

    def test_no_region_anywhere_warns_about_the_cli_default(self, monkeypatch):
        monkeypatch.delenv('COMPLIANCE_REGION', raising=False)
        from check_prerequisites import resolve_region

        region, warning = resolve_region(None)
        # Falling back silently is what made this check the wrong region: the
        # CLI default here is ap-southeast-1 while the engine deploys elsewhere.
        assert region is None
        assert 'region' in warning.lower()
        assert 'terraform.tfvars' in warning

    def test_client_is_built_for_the_resolved_region(self):
        from unittest.mock import patch as _patch
        import check_prerequisites

        with _patch('boto3.client', return_value=MagicMock()) as make_client:
            check_prerequisites._cloudtrail_client('us-east-1')

        make_client.assert_called_once_with('cloudtrail', region_name='us-east-1')

    def test_client_without_a_region_uses_the_default(self):
        from unittest.mock import patch as _patch
        import check_prerequisites

        with _patch('boto3.client', return_value=MagicMock()) as make_client:
            check_prerequisites._cloudtrail_client(None)

        make_client.assert_called_once_with('cloudtrail')


class TestMainReportsTheRegion:
    def test_the_checked_region_is_printed(self, monkeypatch, capsys):
        monkeypatch.setenv('COMPLIANCE_REGION', 'us-east-1')
        from check_prerequisites import main

        with patch('check_prerequisites._cloudtrail_client',
                   return_value=_client(_trails('audit'))):
            main([])

        # A pass against the wrong region is worse than a fail, so say which.
        assert 'us-east-1' in capsys.readouterr().out

    def test_unset_region_is_surfaced_to_the_operator(self, monkeypatch, capsys):
        monkeypatch.delenv('COMPLIANCE_REGION', raising=False)
        from check_prerequisites import main

        with patch('check_prerequisites._cloudtrail_client',
                   return_value=_client(_trails('audit'))):
            main([])

        assert 'COMPLIANCE_REGION' in capsys.readouterr().out
