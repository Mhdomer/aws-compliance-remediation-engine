# ─── Zip the Lambda source directory at plan/apply time ──────────────────────

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../src/lambda"
  output_path = "${path.module}/../build/compliance_engine.zip"
}

# ─── CloudWatch Log Group (explicit so we control retention) ─────────────────

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.name_prefix}"
  retention_in_days = var.log_retention_days
}

# ─── Dead Letter Queue (receives events that fail all Lambda retries) ─────────

resource "aws_sqs_queue" "dlq" {
  name                      = "${local.name_prefix}-dlq"
  message_retention_seconds = var.dlq_retention_seconds
}

# ─── Lambda function ──────────────────────────────────────────────────────────

resource "aws_lambda_function" "compliance_engine" {
  function_name = local.name_prefix
  role          = aws_iam_role.lambda_exec.arn
  handler       = "handler.lambda_handler"
  runtime       = "python3.12"
  timeout       = var.lambda_timeout

  # Lambda queues asynchronous invocations and retries throttled ones for up
  # to six hours. Running unreserved bypasses that buffer, turning a burst of
  # violations into a burst of concurrent AWS API calls that throttle each
  # other. Capping converts that into "N at a time, the rest held and
  # retried", enforced by the platform rather than by library config.
  reserved_concurrent_executions = var.lambda_reserved_concurrency
  memory_size                    = var.lambda_memory_mb
  filename                       = data.archive_file.lambda_zip.output_path
  source_code_hash               = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      SNS_TOPIC_ARN        = aws_sns_topic.alerts.arn
      REQUIRED_KMS_KEY_ARN = aws_kms_key.s3_encryption.arn
      LOG_LEVEL            = "INFO"

      # Lets the handler recognise CloudTrail events caused by its own
      # remediations and drop them, so remediation can never feed itself.
      ENGINE_ROLE_ARN = aws_iam_role.lambda_exec.arn

      # "stop" (default) or "terminate". The IAM policy is built from the
      # same variable, so terminate is not merely discouraged here — the
      # permission does not exist unless it is opted into.
      EC2_REMEDIATION_ACTION = var.ec2_remediation_action
    }
  }

  # Ensures the log group exists before the function tries to write to it
  depends_on = [aws_cloudwatch_log_group.lambda]
}

# ─── Lambda Destinations: route async failures to DLQ ────────────────────────
# EventBridge invocations are asynchronous; Lambda Destinations captures
# failures after all retries are exhausted and sends a rich payload to the DLQ.

resource "aws_lambda_function_event_invoke_config" "async_config" {
  function_name          = aws_lambda_function.compliance_engine.function_name
  maximum_retry_attempts = 2

  destination_config {
    on_failure {
      destination = aws_sqs_queue.dlq.arn
    }
  }
}

# ─── Allow EventBridge to invoke this function ────────────────────────────────
# source_arn is what stops this from being a confused deputy. Without it the
# statement authorises the EventBridge service itself, so anyone able to create
# a rule (events:PutRule + events:PutTargets — far more commonly granted than
# lambda:*) could point one at this function and feed it a hand-crafted event.
# The engine acts on resource IDs taken from the event body using its own
# execution role, which can revoke SG rules, terminate instances and rewrite
# bucket encryption.
#
# source_arn takes a single ARN rather than a list, so there is one statement
# per rule. Adding a fifth rule means adding it here too, or it will not be
# able to invoke the function.

resource "aws_lambda_permission" "eventbridge" {
  for_each = {
    s3-public-acl      = aws_cloudwatch_event_rule.s3_public_acl.arn
    s3-weak-encryption = aws_cloudwatch_event_rule.s3_weak_encryption.arn
    ec2-run-instances  = aws_cloudwatch_event_rule.ec2_run_instances.arn
    sg-ingress         = aws_cloudwatch_event_rule.sg_ingress.arn
  }

  statement_id  = "AllowExecutionFrom-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.compliance_engine.function_name
  principal     = "events.amazonaws.com"
  source_arn    = each.value
}
