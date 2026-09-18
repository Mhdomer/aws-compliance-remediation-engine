# Offline test: no AWS credentials, no API calls, no spend.
# The MCP server is read-only in Python (a test parses its AST). This asserts
# the same property in IAM, so the two layers cannot disagree.

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

run "reader_policy_is_not_created_by_default" {
  command = apply

  assert {
    condition     = length(aws_iam_policy.mcp_reader) == 0
    error_message = "the MCP reader policy must be opt-in like everything else here"
  }
}

run "reader_policy_grants_only_read_actions" {
  command = apply

  variables {
    create_mcp_reader_policy = true
  }

  # The Python side proves no write call exists in the code. This proves the
  # identity could not perform one even if it did.
  assert {
    condition = alltrue([
      for action in flatten([
        for statement in jsondecode(aws_iam_policy.mcp_reader[0].policy).Statement :
        statement.Action
      ]) :
      length(regexall("^[a-z0-9]+:(Describe|Get|List|StartQuery)", action)) > 0
    ])
    error_message = "the MCP reader policy may only grant Describe, Get, List or StartQuery actions"
  }
}

run "reader_policy_covers_every_service_the_tools_use" {
  command = apply

  variables {
    create_mcp_reader_policy = true
  }

  assert {
    condition = alltrue([
      for service in ["cloudwatch", "logs", "ec2", "s3", "tag"] :
      length([
        for action in flatten([
          for statement in jsondecode(aws_iam_policy.mcp_reader[0].policy).Statement :
          statement.Action
        ]) : action if startswith(action, "${service}:")
      ]) > 0
    ])
    error_message = "every service the MCP tools call needs a grant here or those tools fail at runtime"
  }
}

run "log_queries_are_scoped_to_this_engines_log_group" {
  command = apply

  variables {
    create_mcp_reader_policy = true
  }

  # Logs Insights can read any log group it is granted; this one only needs ours.
  assert {
    condition = alltrue([
      for statement in jsondecode(aws_iam_policy.mcp_reader[0].policy).Statement :
      statement.Resource != "*"
      if statement.Sid == "QueryEngineLogs"
    ])
    error_message = "log query permissions must be scoped to the engine's log group"
  }
}
