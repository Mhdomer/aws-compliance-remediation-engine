# System Architecture

## High-Level Flow

```
AWS Account Activity
        │
        │  (every API call)
        ▼
  ┌─────────────┐
  │ CloudTrail  │  Records all API calls made in the account
  └──────┬──────┘
         │  (near real-time event stream)
         ▼
  ┌──────────────┐
  │ EventBridge  │  Evaluates event against compliance rules
  │  Event Bus   │
  └──────┬───────┘
         │
    ┌────┴────────────────────────────┐
    │  Pattern matching (free)        │
    │  source = "aws.s3"              │
    │  eventName = "PutBucketAcl"     │
    └────┬────────────────────────────┘
         │  MATCH → invoke Lambda
         ▼
  ┌────────────────────────────────────────────┐
  │          Lambda: Compliance Engine         │
  │                                            │
  │  handler.py                                │
  │    └─► _RULE_REGISTRY lookup               │
  │           ├─► s3_rules.evaluate()          │
  │           ├─► ec2_rules.evaluate()         │
  │           └─► sg_rules.evaluate()          │
  │                    │                       │
  │          ┌─────────┴──────────┐            │
  │          │  Evaluate + Fix    │            │
  │          └─────────┬──────────┘            │
  │                    │                       │
  │          ┌─────────┴──────────┐            │
  │          │   utils/           │            │
  │          │   ├ cloudwatch ──► CW Metrics   │
  │          │   ├ notifier   ──► SNS Topic    │
  │          │   └ logger     ──► CW Logs      │
  │          └────────────────────┘            │
  └────────────────────────────────────────────┘
         │                    │
    [SUCCESS]            [FAILURE × 3]
         │                    │
         ▼                    ▼
  CW Dashboard          SQS Dead Letter Queue
  (live metrics)        (manual review)
         │                    │
         ▼                    ▼
   Security Team          CW Alarm
   sees green             → SNS Alert
                          → Human resolves
```

## Compliance Rules Implemented

```
EventBridge Rule              CloudTrail Trigger          Remediation
─────────────────────────────────────────────────────────────────────────
s3-public-acl           ←  PutBucketAcl          →  PutPublicAccessBlock
s3-weak-encryption      ←  PutBucketEncryption    →  PutBucketEncryption (mandated CMK)
ec2-run-instances       ←  RunInstances           →  TerminateInstances
sg-ingress              ←  AuthorizeSGIngress      →  RevokeSGIngress
```

## Lambda Source Structure

```
src/lambda/
├── handler.py                  ← entry point, rule registry, routing
├── rules/
│   ├── s3_rules.py             ← S3_PUBLIC_ACL, S3_WEAK_ENCRYPTION
│   ├── ec2_rules.py            ← EC2_UNENCRYPTED_EBS
│   └── sg_rules.py             ← SG_OPEN_PORT_22, SG_OPEN_PORT_3389
└── utils/
    ├── logger.py               ← structured JSON logging
    ├── cloudwatch_utils.py     ← custom metric publishing
    └── notifier.py             ← SNS alert publishing
```

## Infrastructure Resources

```
IAM Role (lambda_exec)
  └── Policies (one per service, least privilege)
      ├── cloudwatch-logs
      ├── cloudwatch-metrics
      ├── s3-remediation
      ├── kms-s3-encryption
      ├── ec2-remediation
      ├── sns-publish
      └── sqs-dlq

KMS Key (compliance-engine-prod-s3, alias)
  └── Customer-managed key mandated for S3 default encryption

Lambda Function (compliance-engine-prod)
  ├── Runtime: Python 3.12
  ├── Memory: 256 MB
  ├── Timeout: 60 s
  ├── Retry: 2 attempts
  └── On failure → SQS DLQ

EventBridge Rules (×4)
  └── All target the same Lambda function

SNS Topic (compliance-engine-prod-alerts)
  └── Email subscription

SQS Queue (compliance-engine-prod-dlq)
  └── 14-day retention

CloudWatch
  ├── Log Group: /aws/lambda/compliance-engine-prod (90-day retention)
  ├── Custom Metrics: ComplianceEngine namespace
  │   ├── ViolationsDetected    [dim: ViolationType]
  │   ├── RemediationsApplied   [dim: ViolationType]
  │   └── RemediationsFailed    [dim: ViolationType]
  ├── Alarms (×3)
  │   ├── high-violation-rate   > 20 violations / 5 min
  │   ├── lambda-errors         > 5 errors / 5 min
  │   └── dlq-depth             > 0 messages
  └── Dashboard: compliance-engine-prod-dashboard
```

## Key Design Decisions

| Decision | Choice | Reason |
|---|---|---|
| Architecture | Event-driven | Seconds-level MTTR vs minutes for polling |
| Compute | Lambda | Zero idle cost; scales to 1000s of concurrent violations |
| IaC | Terraform | Cloud-agnostic, readable HCL, `plan` before `apply` |
| Logging | Structured JSON | Queryable with CloudWatch Logs Insights |
| IAM | Per-service policies | Auditable; limits blast radius of a Lambda compromise |
| Filtering | EventBridge patterns | Free filtering at the bus level; Lambda only runs on matches |
| Failure handling | Lambda Destinations → SQS DLQ | Automatic retry + guaranteed capture of failures |
| Exemptions | `ComplianceExempt: true` tag | Allows opt-out without disabling rules globally |
