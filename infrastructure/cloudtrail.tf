# ─── Optional CloudTrail trail ────────────────────────────────────────────────
# EventBridge only delivers "AWS API Call via CloudTrail" events when a trail is
# enabled and logging. Without one, everything in this directory applies cleanly,
# every resource reports healthy, the dashboard renders — and not a single event
# ever arrives. Nothing errors.
#
# Off by default on purpose. AWS delivers the first copy of management events in
# each Region free of charge; a second trail carrying the same events is billed
# as an additional copy. Most real accounts already have a trail (an
# Organizations trail, Control Tower, Security Hub), so creating one here would
# duplicate both the audit path and the bill. Turn this on for a clean account,
# such as a fresh sandbox used to demo the project.
#
# Run scripts/check_prerequisites.py to find out which situation you are in.

locals {
  cloudtrail_name  = "${local.name_prefix}-trail"
  cloudtrail_count = var.create_cloudtrail ? 1 : 0
  cloudtrail_arn = join("", [
    "arn:aws:cloudtrail:${var.aws_region}:",
    "${data.aws_caller_identity.current.account_id}:trail/${local.cloudtrail_name}",
  ])
}

resource "aws_s3_bucket" "cloudtrail" {
  count = local.cloudtrail_count

  bucket = "${local.name_prefix}-cloudtrail-${data.aws_caller_identity.current.account_id}"

  # This project is deployed and torn down repeatedly. Without this, destroy
  # fails until the log objects are deleted by hand.
  force_destroy = true
}

# The engine deployed from this directory remediates public buckets. Its own
# audit bucket being reachable would be a poor look.
resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  count = local.cloudtrail_count

  bucket                  = aws_s3_bucket.cloudtrail[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Deliberately no aws_s3_bucket_server_side_encryption_configuration here.
# S3 applies SSE-S3 to every new bucket automatically, so the bucket is already
# encrypted. Setting it explicitly would issue a PutBucketEncryption call, which
# is exactly what this engine watches for — it would read AES256 as non-compliant
# and rewrite the encryption of its own audit bucket seconds after creating it.

resource "aws_s3_bucket_policy" "cloudtrail" {
  count = local.cloudtrail_count

  bucket = aws_s3_bucket.cloudtrail[0].id

  # The aws:SourceArn conditions are the same confused-deputy protection the
  # Lambda's invoke permission needs: without them the bucket accepts writes
  # from the CloudTrail service on behalf of any trail, in any account.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail[0].arn
        Condition = {
          StringEquals = { "aws:SourceArn" = local.cloudtrail_arn }
        }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail[0].arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = local.cloudtrail_arn
          }
        }
      },
    ]
  })
}

resource "aws_cloudtrail" "compliance" {
  count = local.cloudtrail_count

  name                          = local.cloudtrail_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail[0].id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  # Management events only, and only writes.
  #
  # Data events are billed on every copy including the first, and none of the
  # four rules match one. WriteOnly is enough because every rule here matches a
  # write event (PutBucketAcl, PutBucketEncryption, RunInstances,
  # AuthorizeSecurityGroupIngress). Adding a rule for a read-only event would
  # need this widened to "All" *and* that EventBridge rule's state changed to
  # ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS — default-enabled rules only
  # match write management events.
  event_selector {
    read_write_type           = "WriteOnly"
    include_management_events = true
  }

  # The trail cannot write until the bucket policy allows it.
  depends_on = [aws_s3_bucket_policy.cloudtrail]
}
