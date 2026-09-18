# ─── Optional least-privilege policy for the MCP server ──────────────────────
# The MCP server in mcp_server/ reads this engine's telemetry so a model can
# investigate incidents. It is read-only in the code — no tool calls a mutating
# API, and a test parses the package's AST to prove it — and this policy is the
# second, independent layer: an identity holding only this cannot write even if
# the code were wrong.
#
# Off by default. The server normally runs locally under a developer's own
# credentials, so the policy is only needed when you want a dedicated identity
# for it. Creating an IAM policy costs nothing; it is gated for the same reason
# the trail is, which is that this repo should not create things nobody asked
# for.

resource "aws_iam_policy" "mcp_reader" {
  count = var.create_mcp_reader_policy ? 1 : 0

  name        = "${local.name_prefix}-mcp-reader"
  description = "Read-only access to the compliance engine's telemetry for the MCP server"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # GetMetricData has no resource-level permission support.
        Sid      = "ReadEngineMetrics"
        Effect   = "Allow"
        Action   = ["cloudwatch:GetMetricData"]
        Resource = "*"
      },
      {
        # Scoped to this engine's log group, the only one the server queries.
        Sid    = "QueryEngineLogs"
        Effect = "Allow"
        Action = [
          "logs:StartQuery",
          "logs:GetQueryResults",
          "logs:DescribeLogGroups",
        ]
        Resource = [
          aws_cloudwatch_log_group.lambda.arn,
          "${aws_cloudwatch_log_group.lambda.arn}:*",
        ]
      },
      {
        # ec2:Describe* does not support resource-level permissions either.
        Sid    = "DescribeResources"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeVolumes",
          "ec2:DescribeSecurityGroups",
        ]
        Resource = "*"
      },
      {
        # The IAM action names do not match the S3 API operation names:
        # GetBucketEncryption is s3:GetEncryptionConfiguration, and
        # GetPublicAccessBlock is s3:GetBucketPublicAccessBlock. Same trap as
        # PutPublicAccessBlock in the engine's own policy.
        Sid    = "ReadBucketConfiguration"
        Effect = "Allow"
        Action = [
          "s3:GetBucketAcl",
          "s3:GetEncryptionConfiguration",
          "s3:GetBucketTagging",
          "s3:GetBucketPublicAccessBlock",
        ]
        Resource = "arn:aws:s3:::*"
      },
      {
        # Finding resources that carry the exemption tag.
        Sid      = "FindExemptResources"
        Effect   = "Allow"
        Action   = ["tag:GetResources"]
        Resource = "*"
      },
    ]
  })
}
