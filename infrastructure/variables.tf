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
