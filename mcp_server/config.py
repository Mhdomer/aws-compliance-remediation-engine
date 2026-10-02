"""Configuration for the compliance MCP server.

Region is required rather than inherited. boto3 would otherwise fall back to
the CLI's configured region, which on this machine is ap-southeast-1 while the
engine deploys to us-east-1. Every query would return nothing, and an empty
result reads as "no violations" rather than "you asked the wrong region" —
the same silent-failure shape the EC2 detection bug had.

The log group is required for the same reason. It used to default to the
engine's "prod" function name, while the only tfvars in this repo deploys
"test", so a clean checkout pointed two of the six tools at a log group that
does not exist. A default that is wrong for the repo's own default deployment
is a bug with a fallback value, not a default.
"""

import os
from dataclasses import dataclass


class ConfigError(RuntimeError):
    """Raised when required configuration is missing."""


@dataclass(frozen=True)
class Config:
    region: str
    log_group: str
    metric_namespace: str


def load_config() -> Config:
    region = os.environ.get('COMPLIANCE_REGION', '').strip()
    if not region:
        raise ConfigError(
            'COMPLIANCE_REGION is not set. Set it to the region the engine is '
            'deployed in (aws_region in terraform.tfvars), which is not '
            'necessarily your AWS CLI default.'
        )

    log_group = os.environ.get('COMPLIANCE_LOG_GROUP', '').strip()
    if not log_group:
        raise ConfigError(
            'COMPLIANCE_LOG_GROUP is not set. Set it to the log group of '
            'the engine function: /aws/lambda/<project_name>-<environment> '
            'from terraform.tfvars, for example '
            '/aws/lambda/compliance-engine-test. This used to default to '
            'the prod name while the only tfvars in this repo deploys '
            'test, so two of the six tools queried a log group that is '
            'never created.'
        )

    return Config(
        region=region,
        log_group=log_group,
        # Must match NAMESPACE in src/lambda/utils/cloudwatch_utils.py.
        metric_namespace=os.environ.get('COMPLIANCE_NAMESPACE', 'ComplianceEngine'),
    )
