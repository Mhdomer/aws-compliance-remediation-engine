# Services Explained

Every AWS service and tool I used in this project, what it is, the specific job it does here, and why I chose it over the alternatives.

---

## AWS CloudTrail

**What it is:** A service that records every API call made in your AWS account — who did what, when, from where. It's the account's security camera footage.

**What it does in this project:** It's the source of truth. Every action (creating a bucket, launching an instance, changing a security group) is an API call that CloudTrail captures. Without CloudTrail, EventBridge would have nothing to react to.

**Why I rely on it:** It's automatic and account-wide. I don't have to instrument anything — the moment any user, role, or service makes a change, CloudTrail sees it. This is what makes the system catch violations no matter how they were introduced (console, CLI, SDK, Terraform, anything).

---

## Amazon EventBridge

**What it is:** A serverless event bus — a smart router that receives events and forwards them to targets based on rules you define.

**What it does in this project:** It watches the CloudTrail event stream and, when an event matches one of my four rules (e.g., `eventName = PutBucketAcl`), it invokes the Lambda function and hands it the full event payload.

**Why I chose it:**
- **Content-based filtering is free.** EventBridge evaluates my rule patterns at no cost. Lambda only runs when an event actually matches, so I'm not paying for invocations on irrelevant events like `GetObject` or `ListBuckets`.
- **It's event-driven, not polling.** Reaction time is seconds, not minutes.
- **vs. the older CloudWatch Events:** EventBridge is the modern evolution with the same core but added schema registry, event replay/archive, and cross-account buses — useful if this ever scales to an enterprise multi-account setup.
- **vs. SNS/SQS:** Those move messages around but can't do rich content-based routing on event fields. EventBridge can filter on nested JSON like "is this instance unencrypted?" without any code.

---

## AWS Lambda

**What it is:** A serverless compute service. You upload code; AWS runs it on demand and charges only for execution time. No servers to manage.

**What it does in this project:** It's the brain. When EventBridge invokes it, the handler routes the event to the right rule module, which evaluates whether it's a real violation and, if so, calls the AWS API to fix it.

**Why I chose it:**
- **Zero idle cost.** A compliance engine does nothing 99% of the time, then bursts when a violation occurs. Lambda charges nothing while idle — an EC2 instance would bill 24/7 for that same idle time.
- **Auto-scaling.** If 500 violations happen at once, Lambda runs 500 invocations in parallel automatically. No capacity planning.
- **Event-native.** Lambda is built to be triggered by events, which is exactly this architecture.
- **Trade-off I accepted:** cold starts add a small latency on the first invocation after idle, but for compliance, sub-second is plenty fast.

---

## Python + boto3

**What it is:** Python is the language; boto3 is the official AWS SDK for Python.

**What it does in this project:** All the rule logic is Python. boto3 is how my code talks to AWS — `s3.put_public_access_block()`, `ec2.terminate_instances()`, etc.

**Why I chose it:**
- Python is a first-class Lambda runtime with the fastest cold starts among the common runtimes.
- boto3 is pre-installed in the Lambda Python runtime, so I don't have to bundle it.
- It's the lingua franca of cloud/DevOps scripting — readable and widely understood.

---

## Amazon CloudWatch

CloudWatch is really three tools in one, and I use all three.

### CloudWatch Logs
**What it does here:** Every `print`/log line from my Lambda lands here automatically. I emit them as structured JSON so they're queryable.

**Why:** It's an immutable audit trail. Using Logs Insights I can run SQL-like queries — "show me every S3 remediation in the last 24 hours and who triggered it." Plain-text logs would force regex parsing; JSON makes every field directly queryable.

### CloudWatch Metrics
**What it does here:** I publish custom metrics (`ViolationsDetected`, `RemediationsApplied`, `RemediationsFailed`) with a `ViolationType` dimension.

**Why custom metrics instead of Lambda's built-in ones:** Lambda's `Invocations` counts every call, including compliant events where nothing was wrong. My custom metrics only count real violations, so the numbers reflect security reality, not Lambda activity. The dimension lets me break violations down by type.

### CloudWatch Alarms
**What it does here:** Three alarms — high violation rate (>20 in 5 min), Lambda errors (>5 in 5 min), and any message in the DLQ.

**Why:** Metrics are passive; alarms are active. They turn "the data shows a problem" into "someone gets paged." They're the difference between a dashboard nobody watches and a system that tells you when to look.

### CloudWatch Dashboard
**What it does here:** A single-pane-of-glass view with six widgets across three rows — business metrics, Lambda health, and DLQ/alarm status.

**Why:** It's the proof of compliance. In a demo or audit, it answers "how do you know it's working?" at a glance.

---

## Amazon SNS (Simple Notification Service)

**What it is:** A pub/sub messaging service for sending notifications (email, SMS, to other services).

**What it does in this project:** When a violation is remediated (or fails), the Lambda publishes a message to an SNS topic, which emails the security team. CloudWatch alarms also publish here.

**Why I chose it:**
- It decouples alerting from the Lambda. The Lambda doesn't need to know who's subscribed or how — it just publishes; SNS fans out to all subscribers.
- Easy to extend: today it's email; tomorrow I could add SMS, Slack, or PagerDuty by adding subscriptions, with zero code changes.

---

## Amazon SQS (Simple Queue Service)

**What it is:** A managed message queue.

**What it does in this project:** It's the Dead Letter Queue (DLQ). If a Lambda invocation fails all its retries, EventBridge/Lambda Destinations routes the failed event here instead of losing it.

**Why I chose it:**
- **No event is ever silently dropped.** A failed remediation is a security gap — I must not lose track of it. The DLQ guarantees the event is preserved with full metadata for a human to act on.
- A CloudWatch alarm watches the queue depth, so any message in the DLQ pages the team immediately.
- 14-day retention gives ample time to investigate before anything expires.

---

## AWS IAM (Identity and Access Management)

**What it is:** The service that controls who/what can do what in AWS.

**What it does in this project:** The Lambda assumes an IAM execution role that grants it exactly the permissions its rules need — and nothing else.

**Why I designed it the way I did:**
- **Least privilege.** I explicitly list each API action (`s3:PutPublicAccessBlock`, `ec2:TerminateInstances`, etc.) instead of wildcards like `s3:*`. If the Lambda were ever compromised, the blast radius is limited to those specific actions.
- **One policy per service.** Separate, named policies (`s3-remediation`, `ec2-remediation`...) make permissions auditable — a reviewer can see at a glance why each permission exists.

---

## Terraform

**What it is:** An Infrastructure-as-Code tool. You describe your cloud resources in code; Terraform creates, updates, and deletes them to match.

**What it does in this project:** Every single AWS resource — the Lambda, IAM role, EventBridge rules, CloudWatch dashboard and alarms, SNS topic, SQS queue — is defined in `.tf` files. One `terraform apply` stands up the whole system; one `terraform destroy` removes it.

**Why I chose it over the alternatives:**
- **vs. ClickOps (manual console):** Manual setup isn't repeatable, reviewable, or version-controlled. Terraform makes the entire system reproducible from code.
- **vs. CloudFormation:** Terraform is cloud-agnostic (the same skills transfer to Azure/GCP), and HCL is more readable than CloudFormation's JSON/YAML.
- **`plan` before `apply`:** Terraform shows me exactly what will change before anything happens — a safety net against accidents.

---

## pytest + unittest.mock

**What it is:** pytest is Python's testing framework; `unittest.mock` lets me replace real objects (like the boto3 AWS client) with fakes.

**What it does in this project:** I mock the AWS clients so tests verify my rule logic — "does a public ACL trigger remediation?" — without making real AWS calls or needing credentials.

**Why I chose this approach:**
- **Fast and free.** Tests run in milliseconds with no AWS account required.
- **Deterministic.** No flaky network calls; the same input always gives the same result.
- **Tests behaviour, not implementation.** I assert on what the function returns and which AWS calls it makes, so I can refactor internals without rewriting tests.

---

## Service Decision Summary

| Need | Service chosen | Main alternative | Why I picked it |
|---|---|---|---|
| Detect changes | CloudTrail | — | Automatic, account-wide capture |
| Route events | EventBridge | SNS/SQS, polling | Free content-based filtering, event-driven |
| Run logic | Lambda | EC2, Fargate | Zero idle cost, auto-scaling |
| Observe | CloudWatch | 3rd-party (Datadog) | Native, no extra integration |
| Alert | SNS | Direct email in code | Decoupled, multi-channel fan-out |
| Catch failures | SQS DLQ | Log-and-forget | Guarantees no lost events |
| Permissions | IAM least-privilege | Broad/admin role | Limits blast radius |
| Provision | Terraform | CloudFormation, manual | Cloud-agnostic, reviewable, `plan` safety |
