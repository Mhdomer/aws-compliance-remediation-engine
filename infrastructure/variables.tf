variable "aws_region" {
  description = "AWS region to deploy all resources into"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Short project name, used as a prefix on every resource"
  type        = string
  default     = "compliance-engine"
}

variable "environment" {
  description = "Deployment environment (prod, staging, dev)"
  type        = string
  default     = "prod"
}

variable "alert_email" {
  description = "Email address that receives compliance violation alerts via SNS"
  type        = string
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds (max 900)"
  type        = number
  default     = 60
}

variable "lambda_memory_mb" {
  description = "Lambda function memory allocation in MB"
  type        = number
  default     = 256
}

variable "log_retention_days" {
  description = "How many days to keep Lambda logs in CloudWatch"
  type        = number
  default     = 90
}

variable "dlq_retention_seconds" {
  description = "How long failed events are kept in the Dead Letter Queue"
  type        = number
  default     = 1209600 # 14 days
}

variable "ec2_remediation_action" {
  description = "What to do with an instance found to have an unencrypted EBS volume. \"stop\" tags it and stops it: reversible, halts writes to the unencrypted volume, and leaves the volume intact so it can actually be fixed. \"terminate\" is irreversible, does not remove the volume when DeleteOnTermination is false, and additionally grants ec2:TerminateInstances to the Lambda role."
  type        = string
  default     = "stop"

  validation {
    condition     = contains(["stop", "terminate"], var.ec2_remediation_action)
    error_message = "ec2_remediation_action must be either \"stop\" or \"terminate\"."
  }
}

variable "create_cloudtrail" {
  description = "Create a management-events-only CloudTrail trail for this engine. Leave false when the account already has a trail: AWS delivers the first copy of management events per Region free, but a second trail carrying the same events is billed as an additional copy. Set true on a clean account, such as a fresh sandbox used to demo the project. Run scripts/check_prerequisites.py to see which case applies."
  type        = bool
  default     = false
}

variable "create_mcp_reader_policy" {
  description = "Create a least-privilege IAM policy for the read-only MCP server in mcp_server/. Only needed when the server runs under a dedicated identity rather than a developer's own credentials. Creating it costs nothing."
  type        = bool
  default     = false
}

variable "lambda_reserved_concurrency" {
  description = "Maximum concurrent executions of the remediation function. Lambda already queues asynchronous invocations and retries throttled ones for up to six hours; running unreserved bypasses that buffer, so a burst of violations becomes a burst of concurrent AWS API calls. 10 keeps the engine near the slowest EC2 token bucket refill rate (5/sec for RevokeSecurityGroupIngress and StopInstances) while still clearing a 50-violation burst in about ten seconds. Must not be 0, which disables the function entirely rather than limiting it. Use -1 to reserve nothing, which is the only option on an account whose total concurrency quota is 10: AWS requires 10 executions to remain unreserved, so any positive reservation is rejected."
  type        = number
  default     = 10

  # -1 is the provider's "no reservation". It is deliberately not the default:
  # the cap is a blast-radius control and should have to be given up on
  # purpose. But a new AWS account's total concurrency quota is 10, and AWS
  # refuses any reservation that would leave fewer than 10 unreserved, so on
  # such an account every positive value here fails the apply outright.
  validation {
    condition     = var.lambda_reserved_concurrency > 0 || var.lambda_reserved_concurrency == -1
    error_message = "lambda_reserved_concurrency must be greater than 0, or -1 to reserve nothing. A value of 0 disables the function completely rather than throttling it."
  }
}
