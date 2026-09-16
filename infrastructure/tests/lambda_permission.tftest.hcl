# Offline test: no AWS credentials, no API calls, no spend.
# mock_provider replaces the AWS provider wholesale, so the "apply" below is
# entirely synthetic. apply rather than plan because computed attributes such
# as a rule ARN are unknown during plan, and source_arn is derived from one.
#
# The generated mock values are random 8-character strings, which the AWS
# provider's own ARN validators reject, so every ARN consumed elsewhere in the
# config needs a realistic stand-in.

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
  mock_resource "aws_lambda_function" {
    defaults = { arn = "arn:aws:lambda:us-east-1:123456789012:function:mock-engine" }
  }
}

mock_provider "archive" {}

# Distinct ARNs per rule, so "each permission points at its own rule" is a real
# assertion rather than one satisfied by four identical mock values.

override_resource {
  target = aws_cloudwatch_event_rule.s3_public_acl
  values = { arn = "arn:aws:events:us-east-1:123456789012:rule/mock-s3-public-acl" }
}

override_resource {
  target = aws_cloudwatch_event_rule.s3_weak_encryption
  values = { arn = "arn:aws:events:us-east-1:123456789012:rule/mock-s3-weak-encryption" }
}

override_resource {
  target = aws_cloudwatch_event_rule.ec2_run_instances
  values = { arn = "arn:aws:events:us-east-1:123456789012:rule/mock-ec2-run-instances" }
}

override_resource {
  target = aws_cloudwatch_event_rule.sg_ingress
  values = { arn = "arn:aws:events:us-east-1:123456789012:rule/mock-sg-ingress" }
}

variables {
  alert_email = "security@example.com"
}

run "every_permission_is_scoped_to_a_source_arn" {
  command = apply

  # With no source_arn the statement authorises the EventBridge service
  # globally: any rule, in any account, may invoke this function.
  assert {
    condition = alltrue([
      for permission in values(aws_lambda_permission.eventbridge) :
      permission.source_arn != null && permission.source_arn != ""
    ])
    error_message = "every EventBridge invoke permission must carry a source_arn"
  }
}

run "permissions_cover_exactly_the_four_rules" {
  command = apply

  # A rule with no matching permission cannot invoke the function, so this
  # catches a rule added to eventbridge.tf without a permission beside it.
  assert {
    condition = toset([
      for permission in values(aws_lambda_permission.eventbridge) :
      permission.source_arn
      ]) == toset([
      aws_cloudwatch_event_rule.s3_public_acl.arn,
      aws_cloudwatch_event_rule.s3_weak_encryption.arn,
      aws_cloudwatch_event_rule.ec2_run_instances.arn,
      aws_cloudwatch_event_rule.sg_ingress.arn,
    ])
    error_message = "invoke permissions must match the four EventBridge rule ARNs exactly"
  }
}

run "statement_ids_are_unique" {
  command = apply

  # Lambda keys policy statements by statement_id; duplicates would collapse
  # the four grants into one.
  assert {
    condition = length(toset([
      for permission in values(aws_lambda_permission.eventbridge) :
      permission.statement_id
    ])) == length(values(aws_lambda_permission.eventbridge))
    error_message = "each permission needs a distinct statement_id or they overwrite each other"
  }
}

run "principal_is_eventbridge_only" {
  command = apply

  assert {
    condition = alltrue([
      for permission in values(aws_lambda_permission.eventbridge) :
      permission.principal == "events.amazonaws.com"
    ])
    error_message = "only the EventBridge service should hold invoke rights on this function"
  }
}
