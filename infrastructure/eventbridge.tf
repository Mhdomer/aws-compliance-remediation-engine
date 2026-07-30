# Each EventBridge rule maps a specific CloudTrail API call to the Lambda function.
# CloudTrail must be enabled in the account for these events to flow through EventBridge.

locals {
  lambda_arn = aws_lambda_function.compliance_engine.arn
}

# ─── Rule 1: S3 bucket ACL set to public ─────────────────────────────────────

resource "aws_cloudwatch_event_rule" "s3_public_acl" {
  name        = "${local.name_prefix}-s3-public-acl"
  description = "Trigger remediation when an S3 bucket ACL grants public access"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail      = { eventName = ["PutBucketAcl"] }
  })
}

resource "aws_cloudwatch_event_target" "s3_public_acl" {
  rule = aws_cloudwatch_event_rule.s3_public_acl.name
  arn  = local.lambda_arn
}

# ─── Rule 2: S3 bucket encryption set to something other than the mandated CMK ─
# Note: this used to watch CreateBucket and check for *missing* encryption, but
# S3 has applied SSE-S3 encryption to every new bucket by default since Jan
# 2023 — that violation can no longer occur. Watching PutBucketEncryption for a
# non-KMS algorithm instead catches a real, still-possible violation: someone
# reverting a bucket from the mandated customer-managed key back to the
# AWS-managed baseline.

resource "aws_cloudwatch_event_rule" "s3_weak_encryption" {
  name        = "${local.name_prefix}-s3-weak-encryption"
  description = "Trigger remediation when a bucket's encryption is set to something other than the mandated customer-managed KMS key"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail      = { eventName = ["PutBucketEncryption"] }
  })
}

resource "aws_cloudwatch_event_target" "s3_weak_encryption" {
  rule = aws_cloudwatch_event_rule.s3_weak_encryption.name
  arn  = local.lambda_arn
}

# ─── Rule 3: EC2 instance launched (check EBS encryption) ────────────────────

resource "aws_cloudwatch_event_rule" "ec2_run_instances" {
  name        = "${local.name_prefix}-ec2-run-instances"
  description = "Trigger EBS encryption check when an EC2 instance is launched"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail      = { eventName = ["RunInstances"] }
  })
}

resource "aws_cloudwatch_event_target" "ec2_run_instances" {
  rule = aws_cloudwatch_event_rule.ec2_run_instances.name
  arn  = local.lambda_arn
}

# ─── Rule 4: Security group ingress rule added (check for open SSH/RDP) ──────

resource "aws_cloudwatch_event_rule" "sg_ingress" {
  name        = "${local.name_prefix}-sg-ingress"
  description = "Trigger port check when a security group ingress rule is added"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail      = { eventName = ["AuthorizeSecurityGroupIngress"] }
  })
}

resource "aws_cloudwatch_event_target" "sg_ingress" {
  rule = aws_cloudwatch_event_rule.sg_ingress.name
  arn  = local.lambda_arn
}
