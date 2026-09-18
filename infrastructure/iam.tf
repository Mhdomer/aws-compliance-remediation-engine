# ─── Lambda execution role ────────────────────────────────────────────────────

resource "aws_iam_role" "lambda_exec" {
  name = "${local.name_prefix}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# ─── CloudWatch Logs ──────────────────────────────────────────────────────────

resource "aws_iam_role_policy" "logs" {
  name = "cloudwatch-logs"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "arn:aws:logs:*:*:*"
    }]
  })
}

# ─── Custom CloudWatch metrics ────────────────────────────────────────────────

resource "aws_iam_role_policy" "metrics" {
  name = "cloudwatch-metrics"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["cloudwatch:PutMetricData"]
      Resource = "*"
    }]
  })
}

# ─── S3 remediation (least-privilege: only what the rules actually call) ──────

resource "aws_iam_role_policy" "s3_remediation" {
  name = "s3-remediation"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetBucketTagging",
        # PutBucketEncryption's actual required IAM action is PutEncryptionConfiguration —
        # confirmed via a live AccessDenied response, not assumed. Same trap as
        # PutPublicAccessBlock: the API operation name and the IAM action name don't match.
        "s3:PutEncryptionConfiguration",
        "s3:GetBucketPublicAccessBlock",
        "s3:PutBucketPublicAccessBlock",
      ]
      Resource = "arn:aws:s3:::*"
    }]
  })
}

# ─── KMS (required to reference the mandated CMK in PutBucketEncryption) ──────

resource "aws_iam_role_policy" "kms_s3_encryption" {
  name = "kms-s3-encryption"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["kms:DescribeKey", "kms:GenerateDataKey", "kms:Decrypt"]
      Resource = aws_kms_key.s3_encryption.arn
    }]
  })
}

# ─── EC2 / Security Group remediation ────────────────────────────────────────

resource "aws_iam_role_policy" "ec2_remediation" {
  name = "ec2-remediation"
  role = aws_iam_role.lambda_exec.id

  # ec2:Describe* does not support resource-level permissions, so those stay on
  # "*". That is an AWS constraint, not an oversight. Everything that mutates is
  # scoped to this account and region, and ec2:TerminateInstances is only put in
  # the policy at all when var.ec2_remediation_action is "terminate" — with the
  # default the role cannot terminate an instance even if the function asked it to.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadOnlyDiscovery"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeVolumes",
          "ec2:DescribeSecurityGroups",
        ]
        Resource = "*"
      },
      {
        Sid    = "InstanceRemediation"
        Effect = "Allow"
        Action = concat(
          [
            "ec2:StopInstances",
            "ec2:CreateTags",
          ],
          var.ec2_remediation_action == "terminate" ? ["ec2:TerminateInstances"] : [],
        )
        Resource = "arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:instance/*"
      },
      {
        Sid      = "SecurityGroupRemediation"
        Effect   = "Allow"
        Action   = ["ec2:RevokeSecurityGroupIngress"]
        Resource = "arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:security-group/*"
      },
    ]
  })
}

# ─── SNS alert publishing ─────────────────────────────────────────────────────

resource "aws_iam_role_policy" "sns_publish" {
  name = "sns-publish"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["sns:Publish"]
      Resource = aws_sns_topic.alerts.arn
    }]
  })
}

# ─── SQS Dead Letter Queue ────────────────────────────────────────────────────

resource "aws_iam_role_policy" "sqs_dlq" {
  name = "sqs-dlq"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["sqs:SendMessage"]
      Resource = aws_sqs_queue.dlq.arn
    }]
  })
}
