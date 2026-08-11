# Offline test: no AWS credentials, no API calls, no spend.
# The trail must not appear unless it is explicitly opted into, because a second
# trail delivering the same management events is billed as an additional copy.

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

run "no_trail_is_created_by_default" {
  command = apply

  assert {
    condition     = length(aws_cloudtrail.compliance) == 0
    error_message = "a trail must not be created unless create_cloudtrail is set: a second trail delivering the same management events is billed as an additional copy"
  }
}

run "no_trail_bucket_by_default" {
  command = apply

  assert {
    condition     = length(aws_s3_bucket.cloudtrail) == 0
    error_message = "the trail bucket must not be created unless create_cloudtrail is set"
  }
}

run "trail_is_created_when_opted_in" {
  command = apply

  variables {
    create_cloudtrail = true
  }

  assert {
    condition     = length(aws_cloudtrail.compliance) == 1
    error_message = "create_cloudtrail = true must create exactly one trail"
  }
}

run "trail_logs_write_management_events_only" {
  command = apply

  variables {
    create_cloudtrail = true
  }

  # Management events because that is what the four rules match; WriteOnly
  # because every one of them matches a write event; no data events because
  # those are billed on every copy including the first.
  assert {
    condition = alltrue([
      for selector in aws_cloudtrail.compliance[0].event_selector :
      selector.include_management_events && selector.read_write_type == "WriteOnly"
    ])
    error_message = "the trail must log write management events"
  }

  assert {
    condition = alltrue([
      for selector in aws_cloudtrail.compliance[0].event_selector :
      length(selector.data_resource) == 0
    ])
    error_message = "the trail must not log data events: they are charged on every copy"
  }
}

run "trail_is_multi_region_and_validated" {
  command = apply

  variables {
    create_cloudtrail = true
  }

  assert {
    condition = (
      aws_cloudtrail.compliance[0].is_multi_region_trail &&
      aws_cloudtrail.compliance[0].enable_log_file_validation
    )
    error_message = "the trail should be multi-region with log file validation enabled"
  }
}

run "trail_bucket_blocks_public_access" {
  command = apply

  variables {
    create_cloudtrail = true
  }

  # This engine remediates public buckets; its own audit bucket must not be one.
  assert {
    condition = (
      aws_s3_bucket_public_access_block.cloudtrail[0].block_public_acls &&
      aws_s3_bucket_public_access_block.cloudtrail[0].block_public_policy &&
      aws_s3_bucket_public_access_block.cloudtrail[0].ignore_public_acls &&
      aws_s3_bucket_public_access_block.cloudtrail[0].restrict_public_buckets
    )
    error_message = "the CloudTrail bucket must block all public access"
  }
}
