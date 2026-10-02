"""An exemption that is about to expire should warn somebody first.

Exemptions expire, which was the right fix. But nothing announces it. On the
expiry date the resource silently starts being checked again, and the owner
finds out when the engine remediates something they believed was exempted.
That is the same shape as every other bug in this project: the quiet path is
the one that surprises people.

A daily sweep reads the exemption tags, works out which ones lapse soon, and
sends a notice naming the resource and the date. A notice, not an alert:
nothing has been found, and nothing is wrong yet.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

NOW = datetime(2026, 10, 2, tzinfo=timezone.utc)


def _tagged(arn: str, until: str, exempt: str = 'true') -> dict:
    return {
        'ResourceARN': arn,
        'Tags': [
            {'Key': 'ComplianceExempt', 'Value': exempt},
            {'Key': 'ComplianceExemptUntil', 'Value': until},
        ],
    }


def _paginator(pages):
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = pages
    return client


class TestExpiringExemptionsAreAnnounced:
    @patch('expiry_sweep.send_notice')
    @patch('expiry_sweep.publish_exemption_expiring')
    @patch('expiry_sweep._get_client')
    def test_an_exemption_lapsing_this_week_is_reported(
        self, factory, metric, notice
    ):
        import expiry_sweep

        soon = (NOW + timedelta(days=3)).date().isoformat()
        factory.return_value = _paginator([
            {'ResourceTagMappingList': [_tagged('arn:aws:s3:::paid-bucket', soon)]}
        ])

        result = expiry_sweep.sweep(now=NOW)

        assert result['expiring'] == 1
        assert metric.called
        assert notice.called
        said = str(notice.call_args)
        assert 'paid-bucket' in said
        assert soon in said, 'the notice has to name the date, not just warn'

    @patch('expiry_sweep.send_notice')
    @patch('expiry_sweep.publish_exemption_expiring')
    @patch('expiry_sweep._get_client')
    def test_an_exemption_with_months_left_is_left_alone(
        self, factory, metric, notice
    ):
        import expiry_sweep

        later = (NOW + timedelta(days=120)).date().isoformat()
        factory.return_value = _paginator([
            {'ResourceTagMappingList': [_tagged('arn:aws:s3:::fine', later)]}
        ])

        result = expiry_sweep.sweep(now=NOW)

        assert result['expiring'] == 0
        assert not notice.called, 'warning months early trains people to ignore it'

    @patch('expiry_sweep.send_notice')
    @patch('expiry_sweep.publish_exemption_expiring')
    @patch('expiry_sweep._get_client')
    def test_an_already_expired_exemption_is_not_warned_about(
        self, factory, metric, notice
    ):
        import expiry_sweep

        gone = (NOW - timedelta(days=5)).date().isoformat()
        factory.return_value = _paginator([
            {'ResourceTagMappingList': [_tagged('arn:aws:s3:::lapsed', gone)]}
        ])

        result = expiry_sweep.sweep(now=NOW)

        # The engine already rejects it and says so on the next event. Warning
        # that it is "about to" expire would be wrong: it already has.
        assert result['expiring'] == 0
        assert result['expired'] == 1

    @patch('expiry_sweep.send_notice')
    @patch('expiry_sweep.publish_exemption_expiring')
    @patch('expiry_sweep._get_client')
    def test_an_exemption_with_no_expiry_is_counted_separately(
        self, factory, metric, notice
    ):
        import expiry_sweep

        factory.return_value = _paginator([
            {'ResourceTagMappingList': [{
                'ResourceARN': 'arn:aws:s3:::forever',
                'Tags': [{'Key': 'ComplianceExempt', 'Value': 'true'}],
            }]}
        ])

        result = expiry_sweep.sweep(now=NOW)

        # An exemption with no expiry date is not honoured at all: the engine
        # requires one. So somebody has tagged this believing it is exempted
        # and it is not, which is a different problem from one about to lapse
        # and should not be counted as either expired or expiring.
        assert result['no_expiry'] == 1
        assert result['expiring'] == 0
        assert result['expired'] == 0

    @patch('expiry_sweep.send_notice')
    @patch('expiry_sweep.publish_exemption_expiring')
    @patch('expiry_sweep._get_client')
    def test_every_page_is_read(self, factory, metric, notice):
        import expiry_sweep

        soon = (NOW + timedelta(days=2)).date().isoformat()
        factory.return_value = _paginator([
            {'ResourceTagMappingList': [_tagged('arn:aws:s3:::one', soon)]},
            {'ResourceTagMappingList': [_tagged('arn:aws:s3:::two', soon)]},
        ])

        result = expiry_sweep.sweep(now=NOW)

        # Stopping at the first page would silently miss exemptions.
        assert result['expiring'] == 2

    @patch('expiry_sweep.send_notice')
    @patch('expiry_sweep.publish_exemption_expiring')
    @patch('expiry_sweep._get_client')
    def test_a_failed_lookup_says_so_rather_than_reporting_none(
        self, factory, metric, notice
    ):
        from botocore.exceptions import ClientError
        import expiry_sweep

        client = MagicMock()
        client.get_paginator.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': ''}}, 'GetResources'
        )
        factory.return_value = client

        result = expiry_sweep.sweep(now=NOW)

        # Zero exemptions found and "could not look" must never be the same
        # answer. This is the lesson the whole project is built on.
        assert result['status'] == 'error'
        assert 'warning' in result


class TestTheSweepIsWiredIn:
    def test_handler_routes_a_scheduled_event_to_the_sweep(self):
        import handler

        with patch('handler.run_expiry_sweep') as sweep:
            sweep.return_value = {'status': 'ok', 'expiring': 0}
            result = handler.lambda_handler(
                {'source': 'aws.events', 'detail-type': 'Scheduled Event',
                 'detail': {}},
                None,
            )

        sweep.assert_called_once()
        assert result['status'] == 'ok'

    def test_a_scheduled_event_is_not_treated_as_an_unknown_rule(self):
        import handler

        with patch('handler.run_expiry_sweep', return_value={'status': 'ok'}):
            result = handler.lambda_handler(
                {'source': 'aws.events', 'detail-type': 'Scheduled Event',
                 'detail': {}},
                None,
            )

        assert result['status'] != 'no_rule'
