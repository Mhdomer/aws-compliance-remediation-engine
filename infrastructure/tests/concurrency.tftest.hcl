# Offline test: no AWS credentials, no API calls, no spend.
# Lambda already queues async invocations and retries throttled ones for up to
# six hours. Running unreserved bypasses that buffer entirely, so a burst of
# violations becomes a burst of concurrent AWS API calls.

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/mock-lambda-exec" }
  }
  mock_resource "aws_iam_policy" {
    defaults = { arn = "arn:aws:iam::123456789012:policy/mock-policy" }
  }
  mock_resource "aws_sns_topic" {
    defaults = { arn = "arn:aws:sns:us-east-1:123456789012:mock-alerts" }
  }
  mock_resource "aws_sqs_queue" {
    defaults = { arn = "arn:aws:sqs:us-east-1:123456789012:mock-dlq" }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000" }
  }
  mock_resource "aws_cloudwatch_event_rule" {
    defaults = { arn = "arn:aws:events:us-east-1:123456789012:rule/mock-rule" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/mock" }
  }
  mock_resource "aws_lambda_function" {
    defaults = { arn = "arn:aws:lambda:us-east-1:123456789012:function:mock-engine" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::mock-cloudtrail-bucket" }
  }
  mock_resource "aws_cloudtrail" {
    defaults = { arn = "arn:aws:cloudtrail:us-east-1:123456789012:trail/mock-trail" }
  }
}

mock_provider "archive" {}

variables {
  alert_email = "security@example.com"
}

run "concurrency_is_capped" {
  command = apply

  assert {
    condition     = aws_lambda_function.compliance_engine.reserved_concurrent_executions > 0
    error_message = "the function must reserve concurrency: running unreserved lets a burst of violations become a burst of concurrent AWS API calls"
  }
}

run "concurrency_is_not_zero" {
  command = apply

  # reserved_concurrent_executions = 0 does not throttle the function, it
  # disables it completely. For a security control that is a silent outage.
  assert {
    condition     = var.lambda_reserved_concurrency != 0
    error_message = "reserved concurrency of 0 disables the function entirely rather than limiting it"
  }
}

run "concurrency_paces_below_the_ec2_refill_rates" {
  command = apply

  # The mutating EC2 actions this engine calls refill at 5/sec
  # (RevokeSecurityGroupIngress, StopInstances). A cap above that would let the
  # engine outrun the bucket refill and throttle itself under sustained load.
  assert {
    condition     = var.lambda_reserved_concurrency <= 10
    error_message = "cap concurrency at or below 10 to stay near the slowest EC2 token bucket refill rate (5/sec)"
  }
}

run "throttled_remediations_are_alarmed_on" {
  command = apply

  # Throttling is now a distinct signal from remediation failure. Without an
  # alarm it is a metric nobody reads.
  assert {
    condition = (
      aws_cloudwatch_metric_alarm.remediations_throttled.metric_name == "RemediationsThrottled" &&
      aws_cloudwatch_metric_alarm.remediations_throttled.namespace == "ComplianceEngine"
    )
    error_message = "throttled remediations need their own alarm: they mean the engine is outrunning the account's API limits"
  }
}
