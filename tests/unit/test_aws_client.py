from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError


def _error(code: str) -> ClientError:
    return ClientError({'Error': {'Code': code, 'Message': ''}}, 'Op')


class TestClientConfig:
    def test_retry_mode_is_adaptive(self):
        from utils.aws_client import CLIENT_CONFIG
        # Adaptive adds a client-side rate limiter on top of standard's backoff.
        # It paces calls within one invocation, which is what the EC2 path needs.
        assert CLIENT_CONFIG.retries['mode'] == 'adaptive'

    def test_max_attempts_is_set_explicitly(self):
        from utils.aws_client import CLIENT_CONFIG
        # standard/adaptive default to 3, fewer than legacy's 5. Inheriting that
        # silently would be a downgrade, so it is stated.
        assert CLIENT_CONFIG.retries['max_attempts'] >= 4

    def test_socket_timeouts_are_bounded_below_the_lambda_timeout(self):
        from utils.aws_client import CLIENT_CONFIG, MAX_ATTEMPTS, READ_TIMEOUT

        # botocore's default read timeout is 60s, the same as the whole Lambda
        # timeout, so one hung socket currently eats the entire invocation.
        assert CLIENT_CONFIG.read_timeout == READ_TIMEOUT
        assert CLIENT_CONFIG.connect_timeout < READ_TIMEOUT
        assert READ_TIMEOUT * MAX_ATTEMPTS < 60

    def test_make_client_applies_the_shared_config(self):
        from utils.aws_client import CLIENT_CONFIG, make_client

        with patch('boto3.client', return_value=MagicMock()) as boto_client:
            make_client('ec2')

        _, kwargs = boto_client.call_args
        assert kwargs['config'] is CLIENT_CONFIG


class TestThrottleClassification:
    @pytest.mark.parametrize('code', [
        'RequestLimitExceeded',      # EC2
        'SlowDown',                  # S3
        'Throttling',
        'ThrottlingException',
        'TooManyRequestsException',
        'EC2ThrottledException',
    ])
    def test_throttle_codes_are_recognised(self, code):
        from utils.aws_client import is_throttling_error
        assert is_throttling_error(_error(code)) is True

    @pytest.mark.parametrize('code', [
        'AccessDenied',
        'UnauthorizedOperation',
        'InvalidPermission.NotFound',
        'NoSuchBucket',
        'UnsupportedOperation',
    ])
    def test_real_failures_are_not_mistaken_for_throttling(self, code):
        from utils.aws_client import is_throttling_error
        # These mean the remediation genuinely failed and a human is needed.
        # Treating one as transient would retry it forever and never alert.
        assert is_throttling_error(_error(code)) is False

    def test_codes_come_from_botocore_not_a_handwritten_list(self):
        from utils.aws_client import THROTTLE_CODES
        from botocore.retries.standard import ThrottledRetryableChecker

        # botocore maintains the union of throttle codes across all services.
        # Copying it by hand would drift the moment AWS adds one.
        assert set(ThrottledRetryableChecker._THROTTLED_ERROR_CODES) <= THROTTLE_CODES

    def test_a_non_client_error_is_not_throttling(self):
        from utils.aws_client import is_throttling_error
        assert is_throttling_error(RuntimeError('boom')) is False

    def test_a_malformed_client_error_does_not_crash(self):
        from utils.aws_client import is_throttling_error
        assert is_throttling_error(ClientError({}, 'Op')) is False
