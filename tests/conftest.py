import os
import sys

import boto3
import pytest

# Make the Lambda source package importable from any test file
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'lambda'))


def pytest_configure(config):
    config.addinivalue_line(
        'markers',
        'real_boto3: test builds real boto3 clients (moto-backed); skips the no-AWS guard',
    )


@pytest.fixture(autouse=True)
def _no_unmocked_aws(request, monkeypatch):
    """Fail loudly if a test constructs a real boto3 client.

    This suite is fully mocked. A test that misses a patch still passes, but it
    reaches the network: slow, flaky, and capable of using whatever credentials
    the developer happens to have loaded. Failing here turns that into an
    obvious error instead of a silent 2-second delay.

    Mark a test with @pytest.mark.real_boto3 to opt out (moto-backed tests).
    """
    if request.node.get_closest_marker('real_boto3'):
        return

    def _blocked(*args, **kwargs):
        service = args[0] if args else kwargs.get('service_name', '<unknown>')
        raise AssertionError(
            f'test built a real boto3 client for {service!r}. Patch the '
            "module's _get_client, or mark the test with @pytest.mark.real_boto3."
        )

    monkeypatch.setattr(boto3, 'client', _blocked)


@pytest.fixture(autouse=True)
def _reset_cached_clients():
    """Clear the modules' memoised clients between tests.

    Each rule and util module caches its client in a global, so one test's
    client would otherwise leak into the next.
    """
    yield

    from rules import ec2_rules, s3_rules, sg_rules
    from utils import cloudwatch_utils, notifier

    ec2_rules._ec2_client = None
    s3_rules._s3_client = None
    sg_rules._ec2_client = None
    cloudwatch_utils._client = None
    notifier._client = None
