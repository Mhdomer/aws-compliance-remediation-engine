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
  function_name    = local.name_prefix
  role             = aws_iam_role.lambda_exec.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_mb
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      SNS_TOPIC_ARN        = aws_sns_topic.alerts.arn
      REQUIRED_KMS_KEY_ARN = aws_kms_key.s3_encryption.arn
      LOG_LEVEL            = "INFO"
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

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.compliance_engine.function_name
  principal     = "events.amazonaws.com"
}
