# ─── Alarms ───────────────────────────────────────────────────────────────────

resource "aws_cloudwatch_metric_alarm" "high_violation_rate" {
  alarm_name          = "${local.name_prefix}-high-violation-rate"
  alarm_description   = "More than 20 violations detected in a 5-minute window — possible attack or misconfiguration wave"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ViolationsDetected"
  namespace           = "ComplianceEngine"
  period              = 300
  statistic           = "Sum"
  threshold           = 20
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "${local.name_prefix}-lambda-errors"
  alarm_description   = "Lambda remediation function is throwing unhandled exceptions"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    FunctionName = aws_lambda_function.compliance_engine.function_name
  }
}

resource "aws_cloudwatch_metric_alarm" "dlq_depth" {
  alarm_name          = "${local.name_prefix}-dlq-depth"
  alarm_description   = "Messages in DLQ mean violations could not be auto-remediated — requires manual review"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    QueueName = aws_sqs_queue.dlq.name
  }
}

# ─── Dashboard ────────────────────────────────────────────────────────────────

resource "aws_cloudwatch_dashboard" "compliance" {
  dashboard_name = "${local.name_prefix}-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      # Row 1: violation and remediation trends
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Violations Detected (by Type)"
          view   = "timeSeries"
          region = var.aws_region
          stat   = "Sum"
          period = 3600
          metrics = [
            ["ComplianceEngine", "ViolationsDetected", "ViolationType", "S3_PUBLIC_ACL"],
            ["ComplianceEngine", "ViolationsDetected", "ViolationType", "S3_WEAK_ENCRYPTION"],
            ["ComplianceEngine", "ViolationsDetected", "ViolationType", "EC2_UNENCRYPTED_EBS"],
            ["ComplianceEngine", "ViolationsDetected", "ViolationType", "SG_OPEN_PORT_22"],
            ["ComplianceEngine", "ViolationsDetected", "ViolationType", "SG_OPEN_PORT_3389"],
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Remediations: Auto-Fixed vs Failed"
          view   = "timeSeries"
          region = var.aws_region
          stat   = "Sum"
          period = 3600
          metrics = [
            ["ComplianceEngine", "RemediationsApplied",
            { color = "#2ca02c", label = "Auto-Remediated" }],
            ["ComplianceEngine", "RemediationsFailed",
            { color = "#d62728", label = "Failed" }],
          ]
        }
      },
      # Row 2: Lambda health
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 8
        height = 6
        properties = {
          title  = "Lambda Invocations"
          view   = "timeSeries"
          region = var.aws_region
          stat   = "Sum"
          period = 300
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName",
            aws_lambda_function.compliance_engine.function_name]
          ]
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 6
        width  = 8
        height = 6
        properties = {
          title  = "Lambda Errors"
          view   = "timeSeries"
          region = var.aws_region
          stat   = "Sum"
          period = 300
          metrics = [
            ["AWS/Lambda", "Errors", "FunctionName",
              aws_lambda_function.compliance_engine.function_name,
            { color = "#d62728" }]
          ]
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 6
        width  = 8
        height = 6
        properties = {
          title  = "Lambda Duration (ms)"
          view   = "timeSeries"
          region = var.aws_region
          period = 300
          metrics = [
            ["AWS/Lambda", "Duration", "FunctionName",
              aws_lambda_function.compliance_engine.function_name,
            { stat = "Average", label = "Average" }],
            ["AWS/Lambda", "Duration", "FunctionName",
              aws_lambda_function.compliance_engine.function_name,
            { stat = "p99", label = "p99" }],
          ]
        }
      },
      # Row 3: DLQ depth + alarm status
      {
        type   = "metric"
        x      = 0
        y      = 12
        width  = 12
        height = 6
        properties = {
          title  = "DLQ Depth (Unresolved Remediation Failures)"
          view   = "timeSeries"
          region = var.aws_region
          stat   = "Maximum"
          period = 300
          metrics = [
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible",
              "QueueName", aws_sqs_queue.dlq.name,
            { color = "#d62728" }]
          ]
        }
      },
      {
        type   = "alarm"
        x      = 12
        y      = 12
        width  = 12
        height = 6
        properties = {
          title = "Compliance Engine Alarms"
          alarms = [
            aws_cloudwatch_metric_alarm.high_violation_rate.arn,
            aws_cloudwatch_metric_alarm.lambda_errors.arn,
            aws_cloudwatch_metric_alarm.dlq_depth.arn,
          ]
        }
      },
    ]
  })
}
