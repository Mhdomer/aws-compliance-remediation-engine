"""How this engine talks to AWS: one shared client config, one throttle test.

Two problems this solves.

Clients were built bare (`boto3.client('ec2')`), which inherits botocore's
legacy retry mode and a 60 second read timeout — the same as the whole Lambda
timeout, so a single hung socket ate the entire invocation. Legacy does retry
throttling, but it does not pace: every concurrent invocation discovers the
limit independently by being refused.

And throttling was indistinguishable from failure. A RequestLimitExceeded was
caught by the same `except ClientError` as an AccessDenied, marked
remediation_failed, and emailed as REQUIRES MANUAL ACTION while the Lambda
returned success — so nothing retried and the resource stayed exposed. Those
are different things: one means the remediation was attempted and rejected, the
other means it was never attempted at all.
"""

import boto3
from botocore.config import Config

# Adaptive adds a client-side rate limiter (CUBIC rate adjustor + token bucket)
# on top of standard's backoff. The limiter is per client instance, so it paces
# calls *within* one invocation rather than coordinating across them. That suits
# the worst path here, which is the EC2 rule making several API calls per
# instance, serially, inside one invocation.
RETRY_MODE = 'adaptive'

# standard and adaptive default to 3 attempts, fewer than legacy's 5. Stated
# explicitly so the change of retry mode is not also a silent downgrade.
MAX_ATTEMPTS = 4

# botocore's default read timeout is 60 seconds, which equals var.lambda_timeout.
# One unresponsive socket would consume the whole invocation with nothing left
# for the remaining work. Bounded so the worst case for a single call
# (MAX_ATTEMPTS * READ_TIMEOUT) still fits inside the function timeout.
CONNECT_TIMEOUT = 3
READ_TIMEOUT = 10

CLIENT_CONFIG = Config(
    retries={'mode': RETRY_MODE, 'max_attempts': MAX_ATTEMPTS},
    connect_timeout=CONNECT_TIMEOUT,
    read_timeout=READ_TIMEOUT,
)


def _throttle_codes() -> frozenset:
    """The set of error codes that mean "slow down", taken from botocore.

    botocore maintains the union of throttling codes across every AWS service.
    Copying that list by hand would drift the moment AWS adds one, and the
    failure would be silent: an unrecognised throttle gets treated as a
    permanent remediation failure.
    """
    codes = {
        'Throttling', 'ThrottlingException', 'ThrottledException',
        'RequestThrottled', 'RequestThrottledException',
        'TooManyRequestsException', 'ProvisionedThroughputExceededException',
        'TransactionInProgressException', 'RequestLimitExceeded',
        'BandwidthLimitExceeded', 'LimitExceededException',
        'PriorRequestNotComplete', 'SlowDown', 'EC2ThrottledException',
    }
    try:
        from botocore.retries.standard import ThrottledRetryableChecker

        codes |= set(ThrottledRetryableChecker._THROTTLED_ERROR_CODES)
    except (ImportError, AttributeError):
        # Private attribute. If botocore moves it, fall back to the literals
        # above rather than losing throttle detection entirely.
        pass
    return frozenset(codes)


THROTTLE_CODES = _throttle_codes()


def make_client(service: str):
    """Build an AWS client with this engine's shared retry and timeout config."""
    return boto3.client(service, config=CLIENT_CONFIG)


def is_throttling_error(exc: Exception) -> bool:
    """True when AWS refused the call because we are going too fast.

    Distinguishes "I was not allowed to try" from "I tried and it failed". The
    first should be retried; the second needs a human.
    """
    response = getattr(exc, 'response', None)
    if not isinstance(response, dict):
        return False
    return response.get('Error', {}).get('Code', '') in THROTTLE_CODES
