# ─── Customer-managed KMS key required for S3 default encryption ──────────────
# Org policy: buckets must use a customer-managed key, not the AWS-managed
# default (SSE-S3/AES256) that S3 now applies automatically to every bucket
# since Jan 2023. SSE-S3 is still real encryption, but it isn't under this
# account's key rotation or audit control — several compliance frameworks
# (SOC2, HIPAA, PCI) specifically require the latter.

resource "aws_kms_key" "s3_encryption" {
  description             = "Customer-managed key required for S3 default encryption (${local.name_prefix})"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_kms_alias" "s3_encryption" {
  name          = "alias/${local.name_prefix}-s3"
  target_key_id = aws_kms_key.s3_encryption.key_id
}
