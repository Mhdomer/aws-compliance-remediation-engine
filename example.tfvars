aws_region            = "us-east-1"
project_name          = "compliance-engine"
environment           = "prod"
alert_email           = "security-team@example.com"
lambda_timeout        = 60
lambda_memory_mb      = 256
log_retention_days    = 90
dlq_retention_seconds = 1209600

# "stop" (default) tags the instance and stops it: reversible, halts writes to
# the unencrypted volume, and leaves the volume intact so it can be fixed.
# "terminate" is irreversible and also grants ec2:TerminateInstances to the
# Lambda role, which the default does not.
ec2_remediation_action = "stop"

# Leave false if this account already has a CloudTrail trail. The first copy of
# management events per Region is free; a second trail carrying the same events
# is billed as an additional copy. Run scripts/check_prerequisites.py to check.
create_cloudtrail = false

# Creates a least-privilege IAM policy for the read-only MCP server in
# mcp_server/. Only needed if the server runs under its own identity rather
# than a developer's credentials. Costs nothing either way.
create_mcp_reader_policy = false
