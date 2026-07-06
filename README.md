# Automated Cloud Compliance & Remediation Engine

A real-time, serverless system that watches an AWS account for security policy violations and **automatically fixes them** in seconds — no human in the loop.

When someone makes an S3 bucket public, launches an unencrypted EC2 instance, or opens SSH to the entire internet, this engine detects it the moment it happens and reverses it before it becomes an exposure.

---

## What It Does

| It detects... | It automatically... |
|---|---|
| An S3 bucket made publicly readable | Blocks all public access |
| A bucket's encryption reverted to the AWS-managed key instead of the mandated customer-managed KMS key | Re-applies the required SSE-KMS configuration |
| An EC2 instance with an unencrypted disk | Terminates the instance |
| A security group opening SSH (22) or RDP (3389) to `0.0.0.0/0` | Revokes the offending rule |

Every action is logged, measured on a live dashboard, and alerted to a security team via email.

---

## Architecture at a Glance

```
API call → CloudTrail → EventBridge → Lambda → Remediation
                                         │
                          ┌──────────────┼──────────────┐
                          ▼              ▼              ▼
                   CloudWatch        SNS Alert      SQS DLQ
                   Metrics/Logs      (email)        (failures)
```

Full diagrams are in [docs/architecture.md](docs/architecture.md).

---

## Tech Stack

| Layer | Technology |
|---|---|
| Compute | AWS Lambda (Python 3.12) |
| Event routing | Amazon EventBridge |
| Audit source | AWS CloudTrail |
| Observability | Amazon CloudWatch (Metrics, Logs, Alarms, Dashboard) |
| Alerting | Amazon SNS |
| Failure handling | Amazon SQS (Dead Letter Queue) |
| Infrastructure as Code | Terraform |
| Testing | pytest + unittest.mock |

A full per-service breakdown is in [docs/services-explained.md](docs/services-explained.md).

---

## Project Structure

```
.
├── src/lambda/              # Python that runs inside Lambda
│   ├── handler.py           #   entry point + rule registry
│   ├── rules/               #   one module per AWS service
│   └── utils/               #   logging, metrics, notifications
├── infrastructure/          # Terraform (all AWS resources)
├── tests/                   # unit tests + sample event payloads
└── docs/                    # documentation
```

---

## Getting Started

### Prerequisites
- An AWS account with **CloudTrail enabled** (events flow through CloudTrail)
- [Terraform](https://www.terraform.io/) >= 1.5
- Python 3.12
- AWS credentials configured (`aws configure`)

### 1. Run the tests
```bash
pip install -r requirements-dev.txt
pytest
```

### 2. Configure your deployment
Copy the example variables file and set your alert email:
```bash
cp example.tfvars terraform.tfvars
# edit terraform.tfvars → set alert_email to your address
```

### 3. Deploy
```bash
cd infrastructure
terraform init
terraform plan -var-file=../terraform.tfvars
terraform apply -var-file=../terraform.tfvars
```

After apply, check your inbox and **confirm the SNS email subscription**. Then open the dashboard URL printed in the Terraform outputs.

### 4. Tear down
```bash
terraform destroy -var-file=../terraform.tfvars
```

---

## How to Test It Live

Once deployed, trigger a violation and watch it self-heal:

```bash
# Create a test bucket and make it public — the engine will lock it back down within seconds
aws s3api create-bucket --bucket my-test-bucket-$RANDOM --region us-east-1
aws s3api put-bucket-acl --bucket <bucket-name> --acl public-read

# Within seconds, check the bucket — public access will be blocked
aws s3api get-public-access-block --bucket <bucket-name>
```

You'll receive an email alert and the violation will appear on the CloudWatch dashboard.

---

## Safety Features

- **Exemptions** — Tag any resource `ComplianceExempt = true` to opt it out of remediation (for legitimate cases like static-website buckets).
- **Least-privilege IAM** — The Lambda can only perform the exact API calls its rules require, nothing more.
- **Dead Letter Queue** — If a remediation fails after 3 attempts, the event is captured for manual review and a human is alerted.
- **Full audit trail** — Every detection and remediation is logged as structured JSON, queryable in CloudWatch Logs Insights.

---

## Documentation

| Document | Purpose |
|---|---|
| [docs/deployment-log.md](docs/deployment-log.md) | Running log of every real deployment and live test — read this first to know what's currently live and where things were left off |
| [docs/build-log.md](docs/build-log.md) | Every design decision, explained in detail with the alternatives I considered |
| [docs/architecture.md](docs/architecture.md) | System diagrams and resource inventory |
| [docs/services-explained.md](docs/services-explained.md) | What each AWS service is and why I used it |
| [docs/explain-like-im-5.md](docs/explain-like-im-5.md) | A non-technical explanation of the whole project |
| [Interview Technical Deep Dive.md](Interview%20Technical%20Deep%20Dive.md) | Interview prep covering every concept in depth |

---

## Extending It

Adding a new compliance rule takes two steps:

1. Implement an `evaluate(event_name, detail)` function in a module under `src/lambda/rules/`.
2. Register it in `_RULE_REGISTRY` in [src/lambda/handler.py](src/lambda/handler.py) and add a matching EventBridge rule in [infrastructure/eventbridge.tf](infrastructure/eventbridge.tf).

No changes to the core handler logic are required.
