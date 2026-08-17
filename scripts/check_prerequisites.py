"""Verify the account-level prerequisites this engine depends on.

    python scripts/check_prerequisites.py

Exits 0 if everything needed is in place, 1 otherwise. Run it before
`terraform apply`, and again afterwards against the target account.

Why this exists: EventBridge only delivers "AWS API Call via CloudTrail"
events when a trail is enabled and logging. Without one, `terraform apply`
succeeds, every resource reports healthy, the dashboard renders, and no event
ever arrives. Nothing errors anywhere. The README has stated this prerequisite
since the first commit and it did not prevent the problem, because prose is not
checkable. This is.

Only read-only API calls are made (DescribeTrails, GetTrailStatus,
GetEventSelectors). Nothing here creates, changes, or costs anything.
"""

import argparse
import os
import sys
from dataclasses import dataclass

import boto3
from botocore.exceptions import ClientError

# Every EventBridge rule in this project matches a *write* management event
# (PutBucketAcl, PutBucketEncryption, RunInstances,
# AuthorizeSecurityGroupIngress), so a trail limited to read-only events would
# never deliver them. Read-only management events would additionally need the
# rule state ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS, which this project
# does not use.
USABLE_READ_WRITE_TYPES = {'All', 'WriteOnly'}

CLOUDTRAIL_CHECK = 'CloudTrail'

REMEDY = (
    'Enable a trail logging write management events in this region (a '
    'multi-region trail counts), or set create_cloudtrail = true to have this '
    'project create a management-events-only trail for you.'
)


@dataclass(frozen=True)
class CheckResult:
    ok: bool
    name: str
    detail: str


def resolve_region(explicit: str | None) -> tuple[str | None, str | None]:
    """Work out which region to check, and say so when we had to guess.

    CloudTrail and EventBridge are regional. Falling back silently to the CLI's
    configured region checks somewhere the engine may not be deployed, and a
    pass against the wrong region is worse than a failure: it reports the
    prerequisite satisfied when nothing will ever reach the Lambda.
    """
    if explicit:
        return explicit, None

    from_env = os.environ.get('COMPLIANCE_REGION', '').strip()
    if from_env:
        return from_env, None

    return None, (
        'No region given, so the AWS CLI default will be used. That is not '
        'necessarily where the engine is deployed. Pass --region, or set '
        'COMPLIANCE_REGION, to the aws_region value in terraform.tfvars.'
    )


def _cloudtrail_client(region: str | None = None):
    if region:
        return boto3.client('cloudtrail', region_name=region)
    return boto3.client('cloudtrail')


def _error_code(exc: ClientError) -> str:
    return exc.response.get('Error', {}).get('Code', 'Unknown')


def check_cloudtrail(client) -> CheckResult:
    """Is at least one trail logging the events this engine needs?"""
    try:
        trails = client.describe_trails().get('trailList', [])
    except ClientError as exc:
        # Not being able to check is not the same as passing.
        return CheckResult(
            False,
            CLOUDTRAIL_CHECK,
            f'Could not list trails ({_error_code(exc)}). '
            'cloudtrail:DescribeTrails is required to verify this.',
        )

    if not trails:
        return CheckResult(
            False,
            CLOUDTRAIL_CHECK,
            f'No CloudTrail trail exists in this account. {REMEDY}',
        )

    problems = []

    for trail in trails:
        name = trail.get('Name', '<unnamed>')
        identifier = trail.get('TrailARN') or name

        try:
            if not client.get_trail_status(Name=identifier).get('IsLogging', False):
                problems.append(f'{name}: exists but is not logging')
                continue
        except ClientError as exc:
            problems.append(f'{name}: could not read status ({_error_code(exc)})')
            continue

        try:
            selectors = client.get_event_selectors(
                TrailName=identifier
            ).get('EventSelectors', [])
        except ClientError as exc:
            problems.append(f'{name}: could not read event selectors ({_error_code(exc)})')
            continue

        if not selectors:
            # CloudTrail includes management events by default, so a trail with
            # no explicit selectors is already logging what we need.
            return CheckResult(
                True,
                CLOUDTRAIL_CHECK,
                f'{name} is logging management events (default selectors)',
            )

        for selector in selectors:
            if not selector.get('IncludeManagementEvents', False):
                problems.append(f'{name}: not logging management events')
                continue

            read_write = selector.get('ReadWriteType', 'All')
            if read_write in USABLE_READ_WRITE_TYPES:
                return CheckResult(
                    True,
                    CLOUDTRAIL_CHECK,
                    f'{name} is logging {read_write} management events',
                )

            problems.append(
                f'{name}: ReadWriteType is {read_write}, needs All or WriteOnly '
                'because every rule here matches a write event'
            )

    return CheckResult(
        False,
        CLOUDTRAIL_CHECK,
        f'No usable trail found — {"; ".join(problems)}. {REMEDY}',
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description='Verify the account prerequisites the compliance engine needs.'
    )
    parser.add_argument(
        '--region',
        help='Region the engine is deployed in. Defaults to COMPLIANCE_REGION, '
             'then to the AWS CLI default.',
    )
    args = parser.parse_args(argv)

    region, region_warning = resolve_region(args.region)

    print(f'Checking region: {region or "AWS CLI default"}')
    if region_warning:
        print(f'  ! {region_warning}')
    print()

    results = [check_cloudtrail(_cloudtrail_client(region))]

    for result in results:
        print(f'[{"PASS" if result.ok else "FAIL"}] {result.name}: {result.detail}')

    failures = [r for r in results if not r.ok]
    if failures:
        print(
            '\nThe engine would deploy successfully and receive nothing. '
            'Fix the above before relying on it.'
        )
        return 1

    print('\nPrerequisites satisfied.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
