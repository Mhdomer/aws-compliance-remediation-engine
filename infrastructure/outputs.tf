output "lambda_function_name" {
  description = "Name of the compliance engine Lambda function"
  value       = aws_lambda_function.compliance_engine.function_name
}

output "lambda_function_arn" {
  description = "ARN of the compliance engine Lambda function"
  value       = aws_lambda_function.compliance_engine.arn
}

output "cloudwatch_dashboard_url" {
  description = "Direct link to the compliance dashboard in the AWS Console"
  value       = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.compliance.dashboard_name}"
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic that receives compliance alerts"
  value       = aws_sns_topic.alerts.arn
}

output "dlq_url" {
  description = "URL of the Dead Letter Queue — check this if remediations are failing"
  value       = aws_sqs_queue.dlq.url
}

output "eventbridge_rule_arns" {
  description = "ARNs of all EventBridge compliance rules"
  value = {
    s3_public_acl      = aws_cloudwatch_event_rule.s3_public_acl.arn
    s3_weak_encryption = aws_cloudwatch_event_rule.s3_weak_encryption.arn
    ec2_run_instances  = aws_cloudwatch_event_rule.ec2_run_instances.arn
    sg_ingress         = aws_cloudwatch_event_rule.sg_ingress.arn
  }
}
