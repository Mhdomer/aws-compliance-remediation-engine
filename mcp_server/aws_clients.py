"""The single place this server builds an AWS client.

Every client here is read-only by construction. There is no tool in this
package that calls a mutating API, and tests/unit/mcp/test_read_only.py parses
the source of every module to prove it. That matters more than a policy
document: a model cannot be prompted into calling a function that does not
exist.

The engine that *does* mutate AWS is a separate codebase (src/lambda) with its
own execution role. These two share a data layer and nothing else.
"""

import boto3

# Exhaustive list of the AWS operations this server may perform. Adding an entry
# is a deliberate act, and adding a mutating one fails the test suite.
READ_ONLY_METHODS = frozenset({
    # CloudWatch metrics
    'get_metric_data',
    # CloudWatch Logs Insights
    'start_query',
    'get_query_results',
    # EC2 and security groups
    'describe_instances',
    'describe_volumes',
    'describe_security_groups',
    # S3
    'get_bucket_acl',
    'get_bucket_encryption',
    'get_bucket_tagging',
    'get_public_access_block',
    # Resource Groups Tagging API
    'get_resources',
})


def read_only_client(service: str, region: str):
    """Build a boto3 client for a read-only call against one region.

    Region is passed explicitly and never inherited. boto3's default resolution
    would pick up the CLI's configured region, which is not necessarily the one
    the engine is deployed in, and the resulting empty responses would read as
    "nothing to report" rather than "wrong region".
    """
    return boto3.client(service, region_name=region)
