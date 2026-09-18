"""Generate real violations against a deployed engine, to see how it behaves.

    python scripts/load_test.py                 # estimate only, touches nothing
    python scripts/load_test.py --run --yes     # actually does it, costs money

**This has never been run.** Every performance claim about this project comes
from mocked tests. This script exists so the gap is a decision rather than an
oversight: the plan is written down, the cost is calculated, and running it is
one flag away.

Read the whole file before using --run. It creates real resources that a real
engine will then act on, and it sends a real email per violation.
"""

import argparse
import sys

# Measured, not estimated: scripts/../ tests drive each handler with recording
# mocks and count the calls. See docs/engineering-log.md entry 11.
CALLS_PER_VIOLATION = {
    'security_group': 5,   # 1 revoke + 2 metrics + 2 SNS (one wide rule, two ports)
    's3_acl': 4,           # get tagging + put PAB + 1 metric + 1 SNS
    's3_encryption': 4,    # get tagging + put encryption + 1 metric + 1 SNS
    'ec2_instance': 6,     # describe instances + volumes + tags + stop + metric + SNS
}

# us-east-1 on-demand, at the time of writing. Verify before trusting.
PRICE = {
    'ec2_t3_micro_hour': 0.0104,
    'ebs_gp3_gb_month': 0.08,
    'lambda_per_million_requests': 0.20,
    'lambda_gb_second': 0.0000166667,
    'sns_per_million_publishes': 0.50,
    'sns_email_per_100k': 2.00,
    'cloudwatch_put_per_1000': 0.01,
}


def plan(violations: int, instances: int, minutes: int) -> dict:
    """What the run would create, and what it would cost."""
    sg_calls = violations * CALLS_PER_VIOLATION['security_group']
    ec2_calls = instances * CALLS_PER_VIOLATION['ec2_instance']
    total_calls = sg_calls + ec2_calls

    # One Lambda invocation per event. The EC2 rule handles every instance in
    # one event, so instances do not multiply invocations.
    invocations = violations + 1
    emails = violations * 2 + instances
    metrics = violations * 2 + instances

    instance_hours = instances * (minutes / 60)

    cost = {
        'ec2 instances': instance_hours * PRICE['ec2_t3_micro_hour'],
        'ebs volumes (8GB each, prorated)': instances * 8 * PRICE['ebs_gp3_gb_month'] * (minutes / (30 * 24 * 60)),
        'lambda requests': invocations / 1_000_000 * PRICE['lambda_per_million_requests'],
        'lambda duration (256MB, 2s each)': invocations * 2 * 0.25 * PRICE['lambda_gb_second'],
        'sns publishes': emails / 1_000_000 * PRICE['sns_per_million_publishes'],
        'sns email delivery': emails / 100_000 * PRICE['sns_email_per_100k'],
        'cloudwatch put_metric_data': metrics / 1000 * PRICE['cloudwatch_put_per_1000'],
    }

    return {
        'violations': violations,
        'instances': instances,
        'invocations': invocations,
        'aws_api_calls_by_the_engine': total_calls,
        'emails': emails,
        'cost': cost,
        'total_cost': sum(cost.values()),
    }


def print_estimate(p: dict) -> None:
    print('What this would do')
    print(f"  {p['violations']} security groups opened to 0.0.0.0/0")
    print(f"  {p['instances']} EC2 instances launched with unencrypted volumes")
    print(f"  -> {p['invocations']} Lambda invocations")
    print(f"  -> {p['aws_api_calls_by_the_engine']} AWS API calls made BY the engine")
    print(f"  -> {p['emails']} emails to the SNS subscriber")
    print()
    print('Estimated cost')
    for item, amount in p['cost'].items():
        print(f'  ${amount:>8.4f}  {item}')
    print(f"  ${p['total_cost']:>8.4f}  TOTAL")
    print()
    print('What this costs that is not money')
    print('  - Every violation emails the SNS subscriber. A 50-violation run is')
    print('    150+ emails to one mailbox in under a minute.')
    print('  - The instances are real. If cleanup fails they keep billing.')
    print('  - CloudTrail management events are free for the first trail per')
    print('    region, so the audit trail itself adds nothing.')
    print()
    print('What it would actually tell you')
    print('  - Whether reserved concurrency (currently 10) paces below the EC2')
    print('    token bucket refill rates, or whether RemediationsThrottled fires.')
    print('  - Whether a RunInstances event carrying many instances completes')
    print('    inside the function timeout, or times out and replays. The EC2')
    print('    rule makes 6 API calls per instance, serially, in one invocation.')
    print('  - Real end-to-end latency from API call to remediation.')
    print()
    print('None of that is knowable from mocked tests, and none of it is')
    print('knowable without spending the money above.')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--violations', type=int, default=50)
    parser.add_argument('--instances', type=int, default=10)
    parser.add_argument('--minutes', type=int, default=5)
    parser.add_argument('--run', action='store_true',
                        help='actually create resources. Costs money.')
    parser.add_argument('--yes', action='store_true',
                        help='required alongside --run. Two flags, on purpose.')
    args = parser.parse_args(argv)

    p = plan(args.violations, args.instances, args.minutes)
    print_estimate(p)

    if not args.run:
        print('\nEstimate only. Nothing was created. Pass --run --yes to execute.')
        return 0

    if not args.yes:
        print('\n--run needs --yes as well. Refusing.')
        return 1

    print('\nNOT IMPLEMENTED.')
    print('The generator and its cleanup are deliberately unwritten: a script')
    print('that creates public security groups and unencrypted instances is one')
    print('bad flag away from being an incident, and it has no business existing')
    print('until someone has actually decided to run it. Write it then, with the')
    print('teardown first.')
    return 1


if __name__ == '__main__':
    sys.exit(main())
