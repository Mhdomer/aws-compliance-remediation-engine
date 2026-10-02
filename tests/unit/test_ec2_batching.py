"""One RunInstances event must not cost two API calls per instance.

handle_run_instances loops over every instance the event names, and each pass
made its own describe_instances and its own describe_volumes. At a measured 6
API calls per instance (entry 11), fifty instances is 300 calls inside a single
60-second invocation. At roughly 40ms per call that is 12 seconds clean, and any
throttling with backoff pushes it past the timeout, at which point Lambda
replays the whole event and does it again.

Both describes take a list. The fix is to fetch once up front and look up per
instance, which leaves the loop, its per-instance error isolation and its
throttle handling exactly as they were.

These tests count calls rather than asserting on a number of seconds, because
the call count is the thing that actually scales.
"""

import pytest
from unittest.mock import MagicMock, patch


def _detail(instance_ids: list) -> dict:
    return {
        'eventName': 'RunInstances',
        'userIdentity': {'arn': 'arn:aws:iam::123456789012:user/dev'},
        'responseElements': {
            'instancesSet': {
                'items': [{'instanceId': i} for i in instance_ids]
            }
        },
    }


def _wire(mock_ec2, instance_ids, encrypted=True):
    """Answer describes for any subset of the instances, like EC2 does."""
    def describe_instances(InstanceIds=None, **kw):
        wanted = InstanceIds or instance_ids
        return {'Reservations': [{'Instances': [
            {
                'InstanceId': i,
                'Tags': [],
                'State': {'Name': 'running'},
                'BlockDeviceMappings': [{'Ebs': {'VolumeId': 'vol-%s' % i[-4:]}}],
            }
            for i in wanted
        ]}]}

    def describe_volumes(VolumeIds=None, **kw):
        return {'Volumes': [
            {'VolumeId': v, 'Encrypted': encrypted} for v in (VolumeIds or [])
        ]}

    mock_ec2.describe_instances.side_effect = describe_instances
    mock_ec2.describe_volumes.side_effect = describe_volumes


class TestDescribesAreBatched:
    @patch('rules.ec2_rules.send_notice')
    @patch('rules.ec2_rules.publish_detection_undetermined')
    @patch('rules.ec2_rules.send_alert')
    @patch('rules.ec2_rules.publish_violation')
    @patch('rules.ec2_rules._get_client')
    def test_twenty_instances_do_not_cost_forty_describes(
        self, mock_factory, _violation, _alert, _undetermined, _notice
    ):
        from rules.ec2_rules import handle_run_instances

        ids = ['i-%012d' % n for n in range(20)]
        mock_ec2 = MagicMock()
        _wire(mock_ec2, ids, encrypted=True)
        mock_factory.return_value = mock_ec2

        handle_run_instances(_detail(ids))

        describes = mock_ec2.describe_instances.call_count
        volumes = mock_ec2.describe_volumes.call_count

        assert describes <= 2, (
            f'{describes} describe_instances calls for 20 instances. '
            'describe_instances takes a list; fetch once and look up per '
            'instance, or a large RunInstances times out and replays.'
        )
        assert volumes <= 2, (
            f'{volumes} describe_volumes calls for 20 instances. '
            'describe_volumes takes a list of volume ids across every instance.'
        )

    @patch('rules.ec2_rules.send_notice')
    @patch('rules.ec2_rules.publish_detection_undetermined')
    @patch('rules.ec2_rules.send_alert')
    @patch('rules.ec2_rules.publish_violation')
    @patch('rules.ec2_rules._get_client')
    def test_call_count_does_not_grow_with_the_number_of_instances(
        self, mock_factory, _violation, _alert, _undetermined, _notice
    ):
        from rules.ec2_rules import handle_run_instances

        counts = []
        for size in (1, 10, 40):
            ids = ['i-%012d' % n for n in range(size)]
            mock_ec2 = MagicMock()
            _wire(mock_ec2, ids, encrypted=True)
            mock_factory.return_value = mock_ec2
            handle_run_instances(_detail(ids))
            counts.append(
                mock_ec2.describe_instances.call_count
                + mock_ec2.describe_volumes.call_count
            )

        # Flat, not linear. One instance and forty should cost about the same.
        assert counts[-1] <= counts[0] + 2, (
            f'describe calls grew {counts[0]} -> {counts[-1]} going from 1 to '
            '40 instances, so the cost is still per instance'
        )


class TestBatchingKeepsTheExistingBehaviour:
    @patch('rules.ec2_rules.send_notice')
    @patch('rules.ec2_rules.publish_detection_undetermined')
    @patch('rules.ec2_rules.send_alert')
    @patch('rules.ec2_rules.publish_violation')
    @patch('rules.ec2_rules._get_client')
    def test_every_instance_still_gets_a_result(
        self, mock_factory, _violation, _alert, _undetermined, _notice
    ):
        from rules.ec2_rules import handle_run_instances

        ids = ['i-%012d' % n for n in range(5)]
        mock_ec2 = MagicMock()
        _wire(mock_ec2, ids, encrypted=True)
        mock_factory.return_value = mock_ec2

        result = handle_run_instances(_detail(ids))

        reported = {r['instance'] for r in result['results']}
        assert reported == set(ids), 'batching dropped instances from the report'

    @patch('rules.ec2_rules.send_notice')
    @patch('rules.ec2_rules.publish_detection_undetermined')
    @patch('rules.ec2_rules.send_alert')
    @patch('rules.ec2_rules.publish_violation')
    @patch('rules.ec2_rules._get_client')
    def test_an_instance_missing_from_the_batch_is_undetermined_not_fatal(
        self, mock_factory, _violation, _alert, undetermined, _notice
    ):
        from rules.ec2_rules import handle_run_instances

        ids = ['i-000000000001', 'i-000000000002']
        mock_ec2 = MagicMock()

        # EC2 answered about one of the two. The other must not be reported
        # compliant, and must not take the first one down with it.
        mock_ec2.describe_instances.return_value = {
            'Reservations': [{'Instances': [{
                'InstanceId': 'i-000000000001',
                'Tags': [],
                'State': {'Name': 'running'},
                'BlockDeviceMappings': [{'Ebs': {'VolumeId': 'vol-1'}}],
            }]}]
        }
        mock_ec2.describe_volumes.return_value = {
            'Volumes': [{'VolumeId': 'vol-1', 'Encrypted': True}]
        }
        mock_factory.return_value = mock_ec2

        result = handle_run_instances(_detail(ids))

        reported = {r['instance'] for r in result['results']}
        assert reported == set(ids), 'the unanswered instance vanished from the report'
        assert undetermined.called, (
            'an instance EC2 did not answer about was not reported as '
            'undetermined; silence is not compliance'
        )

    @patch('rules.ec2_rules.send_notice')
    @patch('rules.ec2_rules.publish_throttled')
    @patch('rules.ec2_rules.send_alert')
    @patch('rules.ec2_rules.publish_violation')
    @patch('rules.ec2_rules._get_client')
    def test_a_throttled_batch_still_re_raises(
        self, mock_factory, _violation, _alert, throttled, _notice
    ):
        from botocore.exceptions import ClientError
        from rules.ec2_rules import handle_run_instances

        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.side_effect = ClientError(
            {'Error': {'Code': 'RequestLimitExceeded', 'Message': ''}}, 'Describe'
        )
        mock_factory.return_value = mock_ec2

        # Throttled means never looked. Re-raise so EventBridge replays it,
        # rather than recording a verdict that was never reached.
        with pytest.raises(ClientError):
            handle_run_instances(_detail(['i-000000000001']))
        assert throttled.called
