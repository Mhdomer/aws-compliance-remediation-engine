# Build Log — Automated Cloud Compliance & Remediation Engine

> Written in first person. Every decision I made is explained here, including the alternatives I considered and rejected.

---

## Phase 1 — Defining the Problem Before Writing Any Code

Before I touched any code I forced myself to answer one question: **what does "compliance" actually mean in this system?**

I landed on this definition: *a resource is compliant if it satisfies every policy rule I've declared. If it doesn't, the system must either fix it automatically or alert a human, and it must do so in seconds, not hours.*

That definition immediately ruled out a polling-based approach. If I had a cron Lambda that ran every 5 minutes scanning for violations, I'd have a 5-minute window where a public S3 bucket could exist undetected. In security, that window is the attacker's opportunity. So from day one I committed to an event-driven architecture.

I also decided to support four compliance rules as the initial scope:

| Rule ID | Violation | Remediation |
|---|---|---|
| `S3_PUBLIC_ACL` | S3 bucket ACL grants public read | Block all public access |
| `S3_NO_ENCRYPTION` | S3 bucket created without server-side encryption | Enable AES-256 encryption |
| `EC2_UNENCRYPTED_EBS` | EC2 instance launched with unencrypted EBS volume | Terminate the instance |
| `SG_OPEN_PORT_22/3389` | Security group opens SSH or RDP to 0.0.0.0/0 | Revoke the offending rule |

> **Addendum, added during live testing:** `S3_NO_ENCRYPTION` as originally scoped above is no longer a reachable violation — AWS started applying SSE-S3 encryption to every new bucket by default in January 2023, so `CreateBucket` can never produce an unencrypted bucket anymore. I replaced it with `S3_WEAK_ENCRYPTION`, which watches `PutBucketEncryption` instead and catches a violation that's still real today: reverting a bucket from the org-mandated customer-managed KMS key back to the AWS-managed baseline. See [docs/deployment-log.md](deployment-log.md) for the full story of how this was found.

---

## Phase 2 — Project Structure

I organised the project into four top-level directories:

```
src/lambda/     ← all Python that runs inside Lambda
infrastructure/ ← all Terraform (IaC)
tests/          ← unit tests and sample event payloads
docs/           ← this build log and the architecture diagram
```

**Why separate `src/lambda` from the project root?**
Terraform needs to zip the Lambda source. If I mixed Python and Terraform files in the same directory the zip would bloat with `.tf` files. By putting Lambda code under `src/lambda/`, Terraform's `archive_file` data source can zip exactly that directory and nothing else.

**Why subdirectories inside `src/lambda`?**
I split the code into `rules/` and `utils/`. The rules modules contain business logic — the "what is a violation and how do I fix it" knowledge. The utils modules contain infrastructure plumbing — logging, metric publishing, alert sending. This separation means I can test rule logic by mocking the utils, without needing real AWS credentials.

---

## Phase 3 — Lambda Utilities

I built three utility modules before writing any rule logic. This is the same approach a software engineer uses when building a house — you lay the foundation (utilities) before the walls (rules).

### `utils/logger.py` — Structured Logging

I wrote a custom `StructuredFormatter` that emits every log line as a JSON object instead of plain text.

**Why JSON logs?**
CloudWatch Logs Insights can query JSON fields directly using syntax like:
```sql
fields @timestamp, bucket, violation
| filter violation = "S3_PUBLIC_ACL"
| sort @timestamp desc
```
If I logged plain strings, I'd have to parse them with regex. JSON logs make every field queryable as-is. In production this is how security teams investigate incidents — they query logs, not grep them.

I also pull the Lambda function name and X-Ray trace ID from environment variables and attach them to every log entry automatically. This means every log line tells you *which function invocation* produced it, which is essential for correlating logs when hundreds of invocations run concurrently.

### `utils/cloudwatch_utils.py` — Custom Metrics

I publish two custom metrics per violation event: `ViolationsDetected` and either `RemediationsApplied` or `RemediationsFailed`. Both are in the `ComplianceEngine` namespace with a `ViolationType` dimension.

**Why not just count Lambda invocations?**
Lambda's built-in `Invocations` metric counts every call — including compliant events that triggered a rule but found no violation. My custom metrics only increment when a real violation occurs, so the dashboard reflects business reality, not Lambda activity.

**Why use dimensions?**
Dimensions let me filter the metric by violation type. I can graph `SG_OPEN_PORT_22` violations separately from `EC2_UNENCRYPTED_EBS` violations, which means the dashboard tells me *what kind* of problem is happening, not just *how many* problems.

### `utils/notifier.py` — SNS Alerts

I abstracted SNS publishing into a single function that reads the topic ARN from an environment variable at runtime.

**Why an environment variable instead of hardcoding the ARN?**
Hardcoding an ARN couples the code to a specific AWS account and region. By reading from `SNS_TOPIC_ARN`, the same Lambda package works in dev, staging, and prod — Terraform injects the correct ARN for each environment at deploy time.

I also made the notifier gracefully skip the SNS call if the environment variable isn't set (instead of crashing). This makes local testing and unit testing easier — I can run the rule logic without needing a real SNS topic.

---

## Phase 4 — Compliance Rule Modules

Each service gets its own module in `rules/`. Every module exposes a single `evaluate(event_name, detail)` function. This is the interface the main handler calls — it doesn't need to know the internals of each rule.

### `rules/s3_rules.py`

**The exemption check (`_is_exempt`)** runs first in every handler. If the resource has a `ComplianceExempt: true` tag, I skip all checks and return immediately. This is critical for production systems — sometimes a bucket legitimately needs to be public (e.g., a static website). The exemption tag lets teams opt out of a rule through a controlled process (tag the resource → get it reviewed → PR to document the exception), rather than disabling the rule for everyone.

**`handle_put_bucket_acl`** checks whether any grant in the ACL points to the `AllUsers` or `AuthenticatedUsers` URI. Both are public group URIs defined by S3's ACL specification. If either is present, I call `put_public_access_block` with all four block settings enabled. This is stricter than just removing the public grant — it also prevents any future public ACLs or policies from taking effect.

**`handle_create_bucket`** checks for server-side encryption by calling `get_bucket_encryption`. If the call fails with `ServerSideEncryptionConfigurationNotFoundError`, that means no encryption rule exists. I then apply AES-256 with `BucketKeyEnabled: True`. I enabled Bucket Keys because they reduce the number of calls to AWS KMS by 99%, which reduces cost significantly at scale.

### `rules/ec2_rules.py`

**`handle_run_instances`** extracts instance IDs from `responseElements.instancesSet.items` — this is the *response* from EC2, not the request. The response is what I need because it contains the actual instance IDs that were assigned.

For each instance, I call `describe_volumes` and check the `Encrypted` field. If any volume is unencrypted, I call `terminate_instances`.

**Why terminate instead of encrypt?**
Encrypting an existing EBS volume in place is not possible — you have to take a snapshot, create an encrypted copy, and swap the volume. That process takes minutes and requires the instance to be stopped. During those minutes the unencrypted volume is still accessible. Terminating immediately is the zero-trust approach: destroy the non-compliant resource and force the user to relaunch it correctly. I also notify the instance owner via SNS so they understand what happened and why.

### `rules/sg_rules.py`

**`is_public_ingress`** is a pure function (no side effects, no AWS calls) that takes a list of IP permission objects and returns a list of violations. I made it pure so it's trivially testable.

The logic checks both IPv4 (`0.0.0.0/0`) and IPv6 (`::/0`) open CIDRs, and checks whether any restricted port (22 for SSH, 3389 for RDP) falls within the permission's port range. The range check (`from_port <= port <= to_port`) catches the common mistake of opening port range `0-65535` which includes SSH and RDP implicitly.

**`_revoke_rule`** calls `revoke_security_group_ingress` with only the specific offending rule, not all rules. This is important — I don't want to accidentally remove legitimate rules that were on the same security group.

---

## Phase 5 — Main Lambda Handler

The `handler.py` file is intentionally thin. It contains a `_RULE_REGISTRY` dictionary that maps `(source, event_name)` tuples to `evaluate` functions. The handler looks up the right function and calls it — that's all it does.

**Why a registry pattern instead of if/elif?**
Adding a new compliance rule requires only one line change in the registry:
```python
('aws.rds', 'CreateDBInstance'): rds_rules.evaluate,
```
No conditional logic to modify. This scales cleanly as the rule set grows.

**Why re-raise exceptions from rule evaluators?**
If a rule crashes with an unhandled exception, I want Lambda to see it as a failed invocation so it retries and (if all retries fail) routes the event to the Dead Letter Queue. Swallowing the exception would mark the invocation as successful, and the violation would be silently ignored.

---

## Phase 6 — Terraform Infrastructure

I chose Terraform over raw CloudFormation because:
1. It's cloud-agnostic — the same skills transfer to Azure, GCP, and multi-cloud
2. The `plan` command shows exactly what will change before I apply anything, preventing accidents
3. The HCL syntax is more readable than JSON/YAML CloudFormation

### `iam.tf` — Least Privilege

I created one IAM role for Lambda with separate policy documents per service. Each policy grants only the specific API actions the rules actually call.

**Why not one big policy?**
Separate policies make the permissions auditable — when a security reviewer asks "why does this Lambda have `ec2:TerminateInstances`?", the answer is visible directly in the policy named `ec2-remediation`. With one monolithic policy that question is harder to answer.

I also did NOT grant `s3:*` or `ec2:*`. I explicitly listed each action. If I add a new remediation that needs a new permission, I must consciously add it — there's no implicit permission creep.

### `lambda.tf` — Deployment

I used Terraform's `archive_file` data source to zip the Lambda code at plan/apply time. This means the zip is always built from the current source code — no manual zip step required.

I configured `aws_lambda_function_event_invoke_config` with `maximum_retry_attempts = 2` and an `on_failure` destination pointing to the SQS Dead Letter Queue. This means:
- EventBridge fires the Lambda (asynchronous invocation)
- If Lambda crashes, it retries up to 2 more times automatically
- If all 3 attempts fail, the event is delivered to the DLQ with full metadata
- A CloudWatch alarm monitors the DLQ and alerts the team

This gives me automatic fault tolerance without writing any retry logic myself.

### `eventbridge.tf` — Event Rules

Each EventBridge rule has an `event_pattern` that filters on a specific `eventName`. I could have written one broad rule matching all S3 and EC2 events and done the filtering in Lambda, but that would invoke Lambda for every S3 API call — `GetObject`, `ListBuckets`, `HeadObject`, etc. — wasting invocations and cost.

By filtering at the EventBridge level, Lambda only runs when an event actually matches a compliance rule. EventBridge filtering is free; Lambda invocations cost money.

### `cloudwatch.tf` — Observability

I created three alarms:
1. **High violation rate** — > 20 violations in 5 minutes. This might indicate a mass misconfiguration or someone systematically testing controls.
2. **Lambda errors** — > 5 errors in 5 minutes. This means my remediation code is broken, not the infrastructure.
3. **DLQ depth** — any message in the DLQ. If even one event lands there, a human needs to investigate.

I also built a CloudWatch Dashboard with six widgets arranged in three rows:
- Row 1: Business metrics (violations and remediations)
- Row 2: Lambda health (invocations, errors, duration)
- Row 3: DLQ depth and alarm status board

The dashboard is the single pane of glass I show in a demo to prove the system is working. It answers the question "are we currently compliant?" at a glance.

---

## Phase 7 — Tests

I wrote tests before running any of the code in AWS. The test strategy is:

**Mock AWS at the client level** using `unittest.mock.patch`. I patch `_get_client()` in each rule module — the function that returns the boto3 client — and replace it with a `MagicMock`. This means tests run instantly without AWS credentials and without making real API calls.

I tested four scenarios per rule:
1. **Violation detected + remediation succeeds** — the happy path
2. **No violation** — compliant resource, no action taken
3. **Violation detected + remediation fails** — the boto3 call throws a ClientError, verify the failure is reported correctly
4. **Edge cases** — missing required fields, exempt resources

The tests verify behaviour, not implementation. They check what the function *returns* and *which mocked functions were called*, not the internal logic path. This means I can refactor the internals without rewriting tests.

I also stored sample EventBridge event payloads in `tests/events/`. These are real JSON structures matching what EventBridge actually delivers (extracted from CloudTrail). I use them to test the full handler in integration scenarios and to demonstrate the system to interviewers.

---

## Phase 8 — What I Would Add Next

If I were continuing this project, the next three things I'd build are:

1. **AWS Config integration** — Config can maintain a historical record of every resource's compliance state over time, giving me a compliance timeline, not just current state.

2. **Step Functions for complex remediations** — The EBS encryption remediation (snapshot → encrypt → swap) needs multiple steps with error handling between each. Step Functions is the right tool for that orchestration.

3. **Terraform remote state** — Currently state is local. For a team environment I'd use an S3 backend with DynamoDB state locking so multiple engineers can run `terraform apply` safely.
