# Offline test: no AWS credentials, no API calls, no spend.
#
# The expiry sweep is the only rule here that fires on a timer. Everything else
# reacts to somebody doing something; a date passing is nobody doing anything,
# so nothing emits an event for it and only a schedule catches it.
#
# Two things have to hold. The rule has to actually be a schedule, because a
# pattern-matched rule with no pattern never fires and nothing errors. And the
# function has to be allowed to read tags across the account, because without
# that the sweep returns "no exemptions" when it means "I could not look".

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

run "the_sweep_is_actually_scheduled" {
  command = apply

  assert {
    condition     = aws_cloudwatch_event_rule.exemption_expiry.schedule_expression != ""
    error_message = "the expiry sweep rule has no schedule, so it never fires and nothing says so"
  }
}

run "the_sweep_does_not_wait_on_an_event_pattern" {
  command = apply

  # A rule carrying both would be ambiguous, and a rule with only a pattern
  # would be waiting for an event that nobody ever emits.
  assert {
    condition     = aws_cloudwatch_event_rule.exemption_expiry.event_pattern == null
    error_message = "the expiry sweep should fire on its schedule, not on an event pattern"
  }
}

run "the_sweep_runs_often_enough_to_be_seen_before_the_expiry" {
  command = apply

  # The warning window in expiry_sweep.py is seven days. A sweep that ran less
  # often than that could step straight over the window and warn nobody.
  assert {
    condition = contains(
      ["rate(1 day)", "rate(1 hour)", "rate(12 hours)"],
      aws_cloudwatch_event_rule.exemption_expiry.schedule_expression
    )
    error_message = "sweep must run at least daily, or an exemption can lapse inside one interval with no warning"
  }
}

run "the_function_can_read_exemption_tags" {
  command = apply

  # Without this the sweep returns an empty list and reports no exemptions,
  # which is the silent-failure shape this whole project exists to avoid.
  assert {
    condition = can(regex(
      "tag:GetResources",
      aws_iam_role_policy.exemption_discovery.policy
    ))
    error_message = "the lambda role cannot read tags, so the sweep cannot see any exemption"
  }
}

run "tag_discovery_is_read_only" {
  command = apply

  # GetResources is the only tagging call the sweep makes. Anything that writes
  # tags would let the engine grant itself an exemption.
  assert {
    condition = length(regexall(
      "tag:(TagResources|UntagResources)",
      aws_iam_role_policy.exemption_discovery.policy
    )) == 0
    error_message = "the exemption discovery policy grants a tag write, which would let the engine exempt resources from itself"
  }
}
