# Offline test: no AWS credentials, no API calls, no spend.
# Proves that terminate is not merely discouraged in code — the IAM permission
# is absent from the role unless it is explicitly opted into.

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
}

mock_provider "archive" {}

variables {
  alert_email = "security@example.com"
}

run "terminate_is_not_granted_by_default" {
  command = apply

  assert {
    condition = !contains(flatten([
      for statement in jsondecode(aws_iam_role_policy.ec2_remediation.policy).Statement :
      statement.Action
    ]), "ec2:TerminateInstances")
    error_message = "the default configuration must not grant ec2:TerminateInstances"
  }
}

run "stop_and_tag_are_granted_by_default" {
  command = apply

  assert {
    condition = alltrue([
      for action in ["ec2:StopInstances", "ec2:CreateTags"] :
      contains(flatten([
        for statement in jsondecode(aws_iam_role_policy.ec2_remediation.policy).Statement :
        statement.Action
      ]), action)
    ])
    error_message = "the default remediation needs ec2:StopInstances and ec2:CreateTags"
  }
}

run "terminate_is_granted_only_when_opted_in" {
  command = apply

  variables {
    ec2_remediation_action = "terminate"
  }

  assert {
    condition = contains(flatten([
      for statement in jsondecode(aws_iam_role_policy.ec2_remediation.policy).Statement :
      statement.Action
    ]), "ec2:TerminateInstances")
    error_message = "opting in to terminate must grant ec2:TerminateInstances"
  }
}

run "mutating_actions_are_scoped_to_this_account" {
  command = apply

  # ec2:Describe* has no resource-level support and stays on "*"; nothing that
  # changes state is allowed to.
  assert {
    condition = alltrue([
      for statement in jsondecode(aws_iam_role_policy.ec2_remediation.policy).Statement :
      statement.Resource != "*"
      if statement.Sid != "ReadOnlyDiscovery"
    ])
    error_message = "mutating EC2 actions must not be granted on Resource = \"*\""
  }
}

run "discovery_statement_is_read_only" {
  command = apply

  assert {
    condition = alltrue([
      for statement in jsondecode(aws_iam_role_policy.ec2_remediation.policy).Statement :
      alltrue([for action in statement.Action : startswith(action, "ec2:Describe")])
      if statement.Sid == "ReadOnlyDiscovery"
    ])
    error_message = "the statement granted on \"*\" must contain only read-only actions"
  }
}

run "undetermined_detections_are_alarmed_on" {
  command = apply

  # The metric exists so something can watch it; an unwatched metric is not a
  # control.
  assert {
    condition = (
      aws_cloudwatch_metric_alarm.detections_undetermined.metric_name == "DetectionsUndetermined" &&
      aws_cloudwatch_metric_alarm.detections_undetermined.namespace == "ComplianceEngine" &&
      aws_cloudwatch_metric_alarm.detections_undetermined.threshold == 0
    )
    error_message = "the undetermined-detection alarm must watch ComplianceEngine/DetectionsUndetermined with a zero threshold"
  }
}

run "exemption_bursts_are_alarmed_on" {
  command = apply

  assert {
    condition = (
      aws_cloudwatch_metric_alarm.exemption_burst.metric_name == "ExemptionsApplied" &&
      aws_cloudwatch_metric_alarm.exemption_burst.namespace == "ComplianceEngine"
    )
    error_message = "the exemption alarm must watch ComplianceEngine/ExemptionsApplied"
  }
}
