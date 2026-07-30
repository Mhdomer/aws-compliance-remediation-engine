# Technical Interview Deep Dive: Automated Cloud Compliance & Remediation Engine

> Audience: Microsoft Cloud Solution Architect Intern Interview  
> Goal: Defend every architectural decision, explain every concept from first principles.

---

## Table of Contents

1. [What This System Does — The One-Sentence Pitch](#1-what-this-system-does)
2. [Serverless Architecture — What It Means and Why I Chose It](#2-serverless-architecture)
3. [Event-Driven Architecture — The Core Paradigm](#3-event-driven-architecture)
4. [AWS EventBridge — The Nervous System](#4-aws-eventbridge)
5. [AWS Lambda — The Execution Engine](#5-aws-lambda)
6. [Auto-Remediation Patterns — How the Fix Happens](#6-auto-remediation-patterns)
7. [CloudWatch — Observability and Dashboards](#7-cloudwatch)
8. [Compliance as Code — The Security Philosophy](#8-compliance-as-code)
9. [IAM and Least Privilege — The Security Foundation](#9-iam-and-least-privilege)
10. [End-to-End Flow — Connecting Everything](#10-end-to-end-flow)
11. [Common Interview Questions and How to Answer Them](#11-common-interview-questions)

---

## 1. What This System Does

**One sentence:** A real-time, serverless system that watches for security policy violations in an AWS account and automatically fixes them without human intervention.

**Why this matters to an interviewer:** This project hits four pillars that cloud architects care about:
- **Automation** — no manual toil
- **Security posture** — enforcing rules proactively, not reactively
- **Observability** — proving compliance through dashboards
- **Cost efficiency** — serverless means zero cost when idle

**The analogy to use in an interview:** Think of it as a building's fire suppression system. The sprinklers don't wait for a firefighter — they detect heat and act instantly. This system detects a policy violation (the heat) and triggers a Lambda function (the sprinkler) automatically.

---

## 2. Serverless Architecture

### What "Serverless" Actually Means

Serverless does **not** mean no servers. It means you do not manage servers. The cloud provider allocates compute on demand and charges you only for execution time.

**The three core properties:**
1. **No provisioning** — You write code, not infrastructure. No EC2 instance to size, patch, or maintain.
2. **Auto-scaling** — If 1,000 compliance violations happen simultaneously, 1,000 Lambda invocations run in parallel automatically.
3. **Pay-per-use** — You pay per 100ms of execution. Zero invocations = zero cost.

### Why Serverless for a Compliance Engine?

| Alternative | Problem |
|---|---|
| EC2 running a polling script | Paying for idle compute, manual scaling, OS patching |
| Container (ECS/Fargate) | Better than EC2 but still needs cluster management |
| Lambda | Zero idle cost, infinite scale, event-triggered |

A compliance engine is **event-driven by nature** — it does nothing 99% of the time, then bursts when a violation occurs. Serverless is architecturally aligned with that pattern.

### What You Sacrifice

Always be honest about trade-offs in an interview:
- **Cold starts** — The first invocation after a period of inactivity has latency (100ms–1s) while the runtime initializes. For compliance, this is acceptable because we don't need sub-millisecond response.
- **15-minute max timeout** — Lambda functions cannot run indefinitely. Long-running remediation tasks must be broken into steps.
- **Statelessness** — Lambda has no persistent memory between invocations. State must be stored externally (DynamoDB, S3, SSM Parameter Store).

---

## 3. Event-Driven Architecture

### The Core Concept

In a traditional (polling) system, your code repeatedly asks: *"Has anything changed?"* This wastes compute and introduces latency equal to your poll interval.

In an event-driven system, the infrastructure asks your code: *"Something changed — go handle it now."*

```
Polling model:
[Your Code] --asks every 60s--> [AWS API]
                                    |
                     "Nothing changed... nothing changed... violation!"
                     (you find out up to 60s late)

Event-driven model:
[AWS API] --violation detected--> [EventBridge] --immediately--> [Lambda]
                                                                (zero delay)
```

### Why Event-Driven for Compliance?

Security violations need **immediate response**. If someone opens an S3 bucket to public access, you want remediation in seconds, not minutes. EventBridge + Lambda achieves seconds-level response time.

### The Three Components of Event-Driven

1. **Event Producer** — Something that emits an event (AWS Config, CloudTrail, AWS API calls)
2. **Event Router** — Something that receives events and decides where they go (EventBridge)
3. **Event Consumer** — Something that processes the event (Lambda)

---

## 4. AWS EventBridge

### What EventBridge Is

EventBridge is a **serverless event bus** — a managed pub/sub (publish-subscribe) message routing service. It receives events from AWS services, your own applications, or SaaS products, and routes them to targets based on rules.

Think of it as a smart postal sorting facility. Mail (events) arrives, workers (rules) read the address, and packages get sent to the right destinations (Lambda, SQS, SNS, Step Functions).

### How It Works Step by Step

```
1. An AWS API call happens (e.g., CreateBucket, RunInstances, PutBucketPublicAccessBlock)
      |
2. CloudTrail records it
      |
3. EventBridge receives the CloudTrail event in near real-time
      |
4. EventBridge evaluates your rules against the event
      |
5. If a rule matches → EventBridge invokes the target (Lambda function)
      |
6. Lambda receives the full event payload and acts
```

### Event Rules — The Core of Filtering

An EventBridge rule is a JSON pattern that acts as a filter. You define what events matter.

**Example rule — detect when an S3 bucket ACL is set to public:**
```json
{
  "source": ["aws.s3"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["PutBucketAcl"],
    "requestParameters": {
      "AccessControlPolicy": {
        "AccessControlList": {
          "Grant": {
            "Grantee": {
              "URI": ["http://acs.amazonaws.com/groups/global/AllUsers"]
            }
          }
        }
      }
    }
  }
}
```

**Example rule — detect EC2 instance launched without encrypted volume:**
```json
{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["RunInstances"]
  }
}
```

### Why EventBridge Over Simple CloudWatch Events?

CloudWatch Events was the predecessor. EventBridge is the evolution — same underlying service, but EventBridge adds:
- **Third-party SaaS event sources** (Datadog, PagerDuty, etc.)
- **Schema Registry** — auto-discovers and documents event shapes
- **Event Archives and Replay** — re-process past events for debugging or testing new rules
- **Cross-account event buses** — route events across AWS accounts (critical for enterprise multi-account architectures)

### EventBridge vs. SNS vs. SQS

This is a common interview comparison:

| Service | Use Case | Delivery |
|---|---|---|
| SNS | Fan-out (one event → many subscribers) | Push, fire-and-forget |
| SQS | Decoupled queue, retry handling | Pull, persistent |
| EventBridge | Complex routing with filtering rules | Push, content-based routing |

For compliance, EventBridge wins because of **content-based routing** — you can filter on specific event fields (e.g., only trigger if the EC2 instance lacks encryption) without writing filtering code in Lambda.

---

## 5. AWS Lambda

### The Execution Model — What Happens When Lambda Runs

When EventBridge invokes your Lambda:

1. **Invoke request arrives** at the Lambda service
2. **Lambda looks for a warm container** (one that already has your runtime and code loaded)
   - If found → **warm start** — your handler runs immediately (milliseconds)
   - If not found → **cold start** — Lambda must initialize (download code, start runtime, run init code)
3. Your **handler function executes** with the event payload
4. Lambda returns the result and the **container is frozen** (kept alive briefly for reuse)

```
Cold Start Timeline:
|--Init runtime--|--Load your code--|--Run init code--|--Handler runs--|
 ~100–500ms        ~50–200ms          ~your code         ~your logic

Warm Start Timeline:
|--Handler runs--|
  ~your logic only
```

### Lambda Handler — The Entry Point

```python
import boto3
import json

def lambda_handler(event, context):
    # event: the EventBridge event payload (dict)
    # context: metadata about the invocation (function name, timeout remaining, etc.)
    
    detail = event.get('detail', {})
    event_name = detail.get('eventName')
    
    if event_name == 'RunInstances':
        remediate_ec2(detail)
    elif event_name == 'PutBucketAcl':
        remediate_s3(detail)
```

**The `event` object** contains everything EventBridge captured — the original API call, the principal who made it, the request parameters, the response, timestamps, and region.

**The `context` object** gives you:
- `context.function_name` — which Lambda function is running
- `context.get_remaining_time_in_millis()` — time left before timeout
- `context.aws_request_id` — unique invocation ID for tracing

### Lambda Configuration Decisions

**Memory:** You configure memory (128MB–10GB). CPU scales proportionally with memory. For remediation logic that calls AWS APIs, 256MB–512MB is typical. More memory = faster execution = lower wall-clock cost (possibly).

**Timeout:** Maximum 15 minutes. Set it to the worst-case execution time of your remediation, not the maximum. A tight timeout prevents runaway functions.

**Concurrency:** Lambda scales to thousands of concurrent executions. You can set **reserved concurrency** to prevent your function from consuming the account's Lambda quota.

**Environment Variables:** Store configuration (like Slack webhook URLs, compliance rule thresholds) as environment variables. For secrets (API keys), use **AWS Secrets Manager** or **SSM Parameter Store**, and reference them at runtime.

### Why Lambda Over Other Compute?

The key reason: **your compliance engine does nothing between violations**. EC2 costs money while idle. Lambda costs nothing. This is a CloudWatch events pattern that inherently suits serverless.

---

## 6. Auto-Remediation Patterns

### Pattern 1: Immediate Reversal

The simplest pattern — detect violation, immediately undo it.

**Example: S3 bucket made public → Lambda makes it private again**

```python
def remediate_public_s3(bucket_name):
    s3 = boto3.client('s3')
    
    # Block all public access
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )
    
    # Log the remediation for audit trail
    print(f"Remediated: Blocked public access on {bucket_name}")
```

**Example: EC2 launched without encryption → terminate it**

```python
def remediate_unencrypted_ec2(instance_id):
    ec2 = boto3.client('ec2')
    ec2.terminate_instances(InstanceIds=[instance_id])
    print(f"Terminated unencrypted instance: {instance_id}")
```

### Pattern 2: Alert-Only (No Auto-Fix)

Not everything should be auto-remediated. Sometimes the violation needs human review. In this case, Lambda sends an alert instead.

```python
def alert_violation(resource_id, violation_type, account_id):
    sns = boto3.client('sns')
    sns.publish(
        TopicArn='arn:aws:sns:us-east-1:123456789:compliance-alerts',
        Subject=f"Compliance Violation: {violation_type}",
        Message=f"Resource {resource_id} in account {account_id} violated policy: {violation_type}"
    )
```

### Pattern 3: Tag-and-Quarantine

For resources that can't be safely terminated (production databases), quarantine them by:
1. Adding a `Compliance: Quarantined` tag
2. Applying a restrictive security group or policy
3. Alerting the owner
4. Setting a remediation deadline

### Pattern 4: Step Functions Orchestration

For complex multi-step remediation (e.g., encrypt an EBS volume: snapshot → create encrypted copy → swap attachment → delete original), use **AWS Step Functions** to orchestrate multiple Lambda calls with retry logic and state management.

### Why Not Let Humans Fix Everything?

The interview answer: **MTTD (Mean Time to Detect) and MTTR (Mean Time to Remediate)** are key security metrics. Manual remediation means MTTR measured in hours. Automated remediation gets MTTR under 60 seconds. Every second a public S3 bucket exists is an exposure window.

---

## 7. CloudWatch

### CloudWatch Architecture — Three Pillars

CloudWatch covers three observability domains:

```
┌─────────────────────────────────────────────────────────────┐
│                        CloudWatch                           │
├─────────────────┬───────────────────┬───────────────────────┤
│    METRICS      │       LOGS        │        ALARMS         │
│                 │                   │                       │
│ Numeric time-   │ Text output from  │ Threshold triggers    │
│ series data     │ your Lambda       │ on metric values      │
│                 │ (print statements │                       │
│ e.g., Lambda    │ become log events)│ e.g., Alert if        │
│ invocation      │                   │ violations > 10/hour  │
│ count,          │ Structured JSON   │                       │
│ error rate,     │ logging → easier  │                       │
│ duration        │ to query          │                       │
└─────────────────┴───────────────────┴───────────────────────┘
```

### Lambda Metrics — What CloudWatch Captures Automatically

Every Lambda invocation generates these metrics with zero configuration:

| Metric | What It Measures | Why It Matters |
|---|---|---|
| `Invocations` | Times Lambda was called | How many violations occurred |
| `Errors` | Invocations that threw an exception | Remediation failures |
| `Duration` | Execution time in ms | Performance, cost |
| `ConcurrentExecutions` | Parallel runs | Scaling behavior |
| `Throttles` | Invocations rejected due to concurrency limits | Capacity issues |

### Custom Metrics — Measuring Business Logic

AWS metrics tell you about infrastructure. Custom metrics tell you about **your application's health**.

```python
import boto3

cloudwatch = boto3.client('cloudwatch')

def publish_compliance_metric(violation_type, remediated=True):
    cloudwatch.put_metric_data(
        Namespace='ComplianceEngine',
        MetricData=[
            {
                'MetricName': 'ViolationsDetected',
                'Dimensions': [
                    {'Name': 'ViolationType', 'Value': violation_type}
                ],
                'Value': 1,
                'Unit': 'Count'
            },
            {
                'MetricName': 'RemediationsApplied',
                'Dimensions': [
                    {'Name': 'ViolationType', 'Value': violation_type}
                ],
                'Value': 1 if remediated else 0,
                'Unit': 'Count'
            }
        ]
    )
```

This lets your dashboard show: "Today we detected 47 violations, auto-remediated 45, escalated 2 for human review."

### CloudWatch Dashboard — Proving Compliance

A dashboard is a **single pane of glass** that shows the current security posture. For a Cloud Solution Architect, this answers the question: *"How do I know the system is working?"*

Widgets on your compliance dashboard:
- **Total violations today** (line graph over time)
- **Violations by type** (S3 public, EC2 unencrypted, security group open)
- **Remediation success rate** (% of violations auto-fixed)
- **Lambda error rate** (are the fixers themselves failing?)
- **Mean time to remediate** (computed metric)

### CloudWatch Logs — The Audit Trail

Every `print()` in a Python Lambda function is automatically sent to CloudWatch Logs. This creates an **immutable audit trail** of every remediation action.

```python
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    logger.info(json.dumps({
        "action": "remediation_started",
        "resource": "s3://my-bucket",
        "violation": "public_access",
        "triggered_by": event['detail']['userIdentity']['arn']
    }))
```

**Structured logging** (JSON) is better than plain text because you can query it with **CloudWatch Logs Insights** — essentially SQL for your log data.

```sql
-- Find all S3 remediations in the last 24 hours
fields @timestamp, resource, violation, triggered_by
| filter action = "remediation_started" and resource like /s3/
| sort @timestamp desc
```

### CloudWatch Alarms

Alarms watch a metric and trigger an action when a threshold is breached.

**Example alarm:** If `ViolationsDetected` > 20 in 5 minutes, something unusual is happening. Alert the security team immediately.

```python
cloudwatch.put_metric_alarm(
    AlarmName='HighViolationRate',
    MetricName='ViolationsDetected',
    Namespace='ComplianceEngine',
    Statistic='Sum',
    Period=300,  # 5 minutes
    EvaluationPeriods=1,
    Threshold=20,
    ComparisonOperator='GreaterThanThreshold',
    AlarmActions=['arn:aws:sns:us-east-1:123456789:security-team']
)
```

---

## 8. Compliance as Code

### What "Compliance as Code" Means

Instead of a PDF document saying *"all S3 buckets must be private"*, you write code that **enforces** and **verifies** that rule. The policy lives in version control (Git), is peer-reviewed, and is automatically applied.

**Benefits:**
- **Consistency** — The rule applies the same way every time, no human interpretation
- **Speed** — Enforcement is instantaneous, not periodic
- **Auditability** — Git history shows when rules changed and who approved it
- **Testability** — You can unit test your compliance rules

### The Compliance Rule Structure

A compliance rule has three parts:

```
1. TRIGGER:    What event indicates a potential violation?
               → "An EC2 instance was launched" (RunInstances API call)

2. EVALUATION: Is this actually a violation?
               → "Does the instance have encrypted EBS volumes?"

3. REMEDIATION: If yes, what action do we take?
               → "Terminate the instance AND alert the owner"
```

```python
def evaluate_ec2_encryption(instance_id, detail):
    ec2 = boto3.client('ec2')
    
    # Get full instance details from the API call response
    instances = ec2.describe_instances(InstanceIds=[instance_id])
    instance = instances['Reservations'][0]['Instances'][0]
    
    # Check each block device mapping
    for bdm in instance.get('BlockDeviceMappings', []):
        volume_id = bdm['Ebs']['VolumeId']
        volume = ec2.describe_volumes(VolumeIds=[volume_id])['Volumes'][0]
        
        if not volume['Encrypted']:
            return True  # Violation found
    
    return False  # Compliant
```

### AWS Config — The Alternative Approach

AWS Config is a managed service specifically for compliance evaluation. It tracks the **configuration state** of every AWS resource over time and runs **Config Rules** to evaluate compliance.

For an interview, know that Config and your Lambda-based approach address different scenarios:

| | Custom Lambda Approach | AWS Config |
|---|---|---|
| Detection speed | Near real-time (seconds) | Near real-time to minutes |
| Flexibility | Full Python logic | Limited to Config rule API |
| Cost | Lambda per-invocation | Config rule evaluation cost |
| Historical state | You must build it | Built-in |
| Managed remediation | Custom Lambda | SSM Automation documents |

Your custom approach is more flexible. AWS Config is more managed. A production system uses both — Config for resource inventory and historical compliance state, custom Lambda for complex remediation logic.

### Frameworks Your Work Aligns With

Be able to name these in an interview:

- **CIS Benchmarks** — Center for Internet Security benchmark rules for AWS (e.g., "no security groups should allow 0.0.0.0/0 on port 22")
- **SOC 2** — Service Organization Control, requires evidence of access controls
- **NIST 800-53** — US government security controls framework
- **ISO 27001** — International information security standard

Your project implements the automated enforcement layer that helps organizations meet these frameworks.

---

## 9. IAM and Least Privilege

### Why IAM Is Central to This Project

Your Lambda function needs AWS permissions to do its job — but granting too many permissions creates a security risk. If the Lambda function itself were compromised, an attacker would inherit its permissions.

**Least Privilege Principle:** Grant only the exact permissions required, nothing more.

### Lambda Execution Role

Lambda assumes an **IAM role** at runtime. This role defines what the function can do.

**Bad (overprivileged) role:**
```json
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}
```

**Good (least privilege) role for your project:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:TerminateInstances"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutPublicAccessBlock",
        "s3:GetBucketPublicAccessBlock"
      ],
      "Resource": "arn:aws:s3:::*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "cloudwatch:PutMetricData"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "sns:Publish"
      ],
      "Resource": "arn:aws:sns:us-east-1:123456789:compliance-alerts"
    }
  ]
}
```

### The IAM Decision Questions You'll Get

**"Why not use AdministratorAccess?"**  
Because if someone exploits a vulnerability in your Lambda code (e.g., code injection via malformed event data), they'd have full control of your AWS account. Least privilege limits the blast radius of a compromise.

**"How do you handle cross-account remediation?"**  
Use **IAM role assumption** (`sts:AssumeRole`). Your Lambda assumes a role in the target account with just the permissions needed. This is the standard pattern for multi-account architectures.

---

## 10. End-to-End Flow

Here is the complete sequence for the **S3 public access violation** scenario:

```
1. Developer (or script, or mistake) calls s3:PutBucketAcl API
   │
   ▼
2. CloudTrail records the API call within seconds
   │
   ▼
3. EventBridge receives the CloudTrail event
   │
   ▼
4. EventBridge evaluates it against your rule:
   "Is this a PutBucketAcl event with AllUsers grantee?"
   │
   ├─ NO MATCH → event is ignored
   │
   └─ MATCH ▼
   
5. EventBridge invokes your Lambda function, passing the full event JSON
   │
   ▼
6. Lambda cold-starts (if needed) or reuses warm container
   │
   ▼
7. Your handler extracts the bucket name from event['detail']['requestParameters']['bucketName']
   │
   ▼
8. Lambda calls boto3 to:
   a. Verify the bucket is still public (avoid acting on stale events)
   b. Apply s3:PutPublicAccessBlock to block all public access
   c. Publish a custom CloudWatch metric (ViolationsDetected, RemediationsApplied)
   d. Write structured log to CloudWatch Logs: who did it, when, what was fixed
   e. Publish SNS alert to notify the bucket owner
   │
   ▼
9. CloudWatch Dashboard updates automatically (metrics refresh every 1–5 min)
   │
   ▼
10. Security team sees the violation + remediation in the dashboard
    Total elapsed time from violation to fix: < 30 seconds
```

---

## 11. Common Interview Questions

### Architecture Questions

**"Why EventBridge instead of polling with a cron Lambda?"**  
Polling has inherent latency equal to the poll interval. EventBridge is event-driven — it fires within seconds of the API call. For security, seconds matter. Also, polling means paying for Lambda invocations that return nothing, which is wasteful.

**"What happens if Lambda fails to remediate?"**  
Lambda has built-in retry — for asynchronous invocations (which EventBridge uses), it retries twice by default. You configure a **Dead Letter Queue (DLQ)** — an SQS queue that receives the event if all retries fail. Your on-call team monitors the DLQ and handles manual remediation for failed auto-remediations.

**"How does this scale to 1,000 violations per minute?"**  
Lambda scales automatically. Each violation triggers an independent invocation. AWS Lambda supports up to 1,000 concurrent executions by default per account per region (soft limit, can be increased). EventBridge delivers each event independently, so 1,000 violations = 1,000 parallel Lambda invocations.

**"How do you prevent the Lambda from being triggered in a loop?"**  
Good question. When Lambda calls `PutPublicAccessBlock`, that API call could trigger another EventBridge rule. You prevent this by:
1. Designing your EventBridge rule to only match the specific violation (not the remediation action)
2. Adding a tag `RemediedBy: ComplianceEngine` to the resource before acting, and checking for it at the start of Lambda to skip already-remediated resources
3. Using a specific IAM role for Lambda — and excluding events from that role's ARN in your EventBridge rule

**"What about false positives? What if a legitimate action triggers remediation?"**  
You build an **allowlist mechanism**. Resources tagged `ComplianceExempt: true` with an approved exception are skipped. The exemption is itself logged and auditable.

### Cost Questions

**"How much does this cost to run?"**  
Lambda: First 1 million requests/month free, then $0.20 per million. Each invocation is ~$0.0000166 per GB-second. For 10,000 violations/month at 500ms average duration with 256MB memory: essentially pennies.

EventBridge: $1 per million events.

CloudWatch: Custom metrics at $0.30/metric/month. Logs at $0.50/GB ingested.

Total for a moderate-sized organization: likely $5–20/month. Compared to a full-time security analyst's hourly rate, this pays for itself in minutes.

### Microsoft-Specific Angle

Since you're interviewing at Microsoft, be ready to connect this to Azure:

| AWS Service | Azure Equivalent |
|---|---|
| EventBridge | Azure Event Grid |
| Lambda | Azure Functions |
| CloudWatch | Azure Monitor |
| CloudTrail | Azure Activity Log |
| AWS Config | Azure Policy |
| SNS | Azure Service Bus / Event Hubs |

**"How would you build this on Azure?"**  
Azure Policy with DeployIfNotExists effect auto-remediates non-compliant resources. Azure Event Grid routes events from Azure Monitor to Azure Functions. Azure Monitor workbooks replace CloudWatch dashboards. The architecture pattern is identical — the service names differ.

This shows you understand the architecture independently of the specific vendor, which is exactly what a Cloud Solution Architect needs.

### The "Why Did You Build This?" Question

*"This project is relevant to me as someone targeting cloud security and DevSecOps. The real-world problem it solves is the gap between 'we have a policy' and 'we enforce a policy.' Most organizations have written security policies that rely on humans checking compliance — that process is slow, inconsistent, and doesn't scale. By encoding policies as executable rules and remediating programmatically, I'm removing human latency from the security loop. This directly reduces the window of exposure when a misconfiguration occurs."*

---

## Key Terms Glossary

| Term | Definition |
|---|---|
| **MTTD** | Mean Time to Detect — how long from violation to detection |
| **MTTR** | Mean Time to Remediate — how long from detection to fix |
| **Cold Start** | Latency when Lambda initializes a new container |
| **Idempotent** | An operation that produces the same result if run once or multiple times |
| **Dead Letter Queue (DLQ)** | Destination for events that failed all Lambda retries |
| **Compliance as Code** | Expressing compliance requirements as executable code rather than documents |
| **Event Bus** | A channel that receives and routes events (EventBridge's core primitive) |
| **IAM Role** | An identity with permissions, assumable by services like Lambda |
| **Least Privilege** | Granting only the minimum permissions required |
| **Boto3** | The AWS SDK for Python |
| **Structured Logging** | Logging as JSON instead of plain text for queryability |
| **Custom Metric** | A metric you publish to CloudWatch from your code |
| **Reserved Concurrency** | Guaranteeing a set number of Lambda instances for a function |
| **Asynchronous Invocation** | EventBridge invokes Lambda without waiting for a response |
