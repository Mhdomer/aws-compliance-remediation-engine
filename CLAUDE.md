# CLAUDE.md — A2 Automated Cloud Compliance & Remediation Engine

Read this before touching anything here. It is the stable picture of the repo.
Fast-moving state (the current commit queue) lives in `docs/pending-commits.md`,
which is gitignored.

## What this is

A serverless AWS compliance engine. One Lambda sits behind four EventBridge
rules that watch CloudTrail API calls. When one fires, the Lambda detects a
compliance violation, auto-remediates it, publishes a CloudWatch metric, and
sends an SNS alert.

It is a portfolio project aimed at Cloud Security / DevSecOps interviews. It has
been deployed to real AWS twice and torn down both times. **The terraform state
is empty.** Per the vault's root `CLAUDE.md`, this is the most fully built of the
"Projects Idea" set, and one of only two that survive an interviewer asking
"what actually broke and how did you fix it."

## Hard constraints — these override convenience

- **No AWS spend.** Everything must be provable with mocks, `terraform
  validate`, or `terraform test`. Never `terraform apply` against a real
  account. Never assume an AWS behaviour — prove it with moto or say plainly
  that you could not.
- **Never add AI attribution to commits.** No `Co-Authored-By`, no "Generated
  with". All work here is Mohamed's.
- **Do not commit unless explicitly asked.** During the current review pass he
  commits everything himself. Leave changes in the working tree and hand over
  the paths plus a ready commit message.
- **Never commit** `docs/deployment-log.md`, `docs/explain-like-im-5.md`,
  `docs/pending-commits.md`, `docs/mcp-build-plan.md`, or
  `Interview Technical Deep Dive.md` (all gitignored).
- **`mcp_server/free_agent.py` runs the same tools for free** via Groq's free
  tier or a local Ollama. Its tool schemas are derived from the MCP server, not
  hand-written: a hand-written draft silently offered 4 of 6 tools.
- **`mcp_server/agent.py` is the only thing here that costs money to run.**
  It calls the Anthropic API. Never run it to "check something works" —
  its tests mock the API entirely.

## How he wants to work

Learning-first. Explain the problem and why it matters *before* changing
anything — he needs to be able to defend this code in an interview without
opening it. Write a failing test that proves the bug, then fix it, then show the
test passing. Checkpoint between issues rather than plowing through.

Plain, direct voice. No rhetorical em-dashes, no stacked "not X, but Y", no
corporate softeners.

## Layout

| Path | What |
|---|---|
| `src/lambda/handler.py` | Entry point. Dispatch registry keyed on `(source, eventName)`. Self-invocation guard. |
| `src/lambda/rules/s3_rules.py` | `PutBucketAcl`, `PutBucketEncryption` |
| `src/lambda/rules/ec2_rules.py` | `RunInstances` (EBS encryption) |
| `src/lambda/rules/sg_rules.py` | `AuthorizeSecurityGroupIngress` (open 22/3389) |
| `src/lambda/utils/` | `logger` (structured JSON), `cloudwatch_utils` (metrics), `notifier` (SNS) |
| `infrastructure/` | Terraform: lambda, iam, eventbridge, cloudwatch, sns, kms |
| `infrastructure/tests/` | `.tftest.hcl` suites, fully mocked |
| `mcp_server/` | Read-only MCP server. Six tools, plus an optional agent loop. Never put this in `src/lambda/`. |
| `scripts/` | `check_prerequisites.py` — verifies the CloudTrail dependency. |
| `tests/unit/` | pytest, fully mocked |
| `tests/events/` | CloudTrail fixtures, driven end to end through `lambda_handler`. Three captured from a live account; `s3_put_bucket_encryption_event.json` is constructed and says so in a `_comment` field. |

Each rule module exposes `evaluate(event_name, detail)`. Adding a rule = one
registry entry in `handler.py` + a module + an EventBridge rule + a matching
`aws_lambda_permission` (see below).

## How to verify

```bash
python -m pytest -q --cov=src/lambda --cov=scripts   # coverage report
python -m pytest -q                                  # 340 tests
cd infrastructure && terraform test                  # 25 tests, no credentials
cd infrastructure && terraform validate
cd infrastructure && terraform fmt -check -recursive
```

## Testing notes learned the hard way

- `tests/conftest.py` **fails any test that constructs a real boto3 client.**
  This exists because a test that misses a patch still passes while reaching
  the network — slow, flaky, and capable of using whatever credentials are
  loaded. Opt out with `@pytest.mark.real_boto3` for moto-backed tests.
- `terraform test` uses `mock_provider`, so it needs **`command = apply`, not
  `plan`**. Mock values only materialise at apply, and computed attributes like
  a rule ARN are unknown during plan.
- `mock_provider` generates **random 8-character strings** for computed
  attributes, which the AWS provider's own ARN validators reject. Anything
  whose ARN is consumed elsewhere needs a `mock_resource` default or an
  `override_resource` with a realistic ARN. Use *distinct* ARNs where a test
  asserts things point at different resources, or it passes vacuously.
- **moto does not reproduce the EC2 pending-state window.** It returns
  `running` with `BlockDeviceMappings` already populated. The real timing gap
  is not testable offline; only the code's response to an empty list is.

## Design decisions — do not "fix" these back

These look like inconsistencies. They are deliberate and each has a test.

- **SG violations are grouped before revoking.** One ingress rule spanning a
  port range trips both 22 and 3389, but it is one rule. Revoking per port sent
  AWS the same request twice; the second got `InvalidPermission.NotFound` and
  was reported as a remediation failure for a rule that had just been closed.
  Detection still reports every exposed port.
- **`ipProtocol: -1` carries `from_port`/`to_port` of `None`.** An all-traffic
  rule has no port range and AWS stores it without one; synthesising 0-65535
  described it as a TCP range and dragged it into the duplicate-revoke bug.
- **`aws_lambda_permission` is a `for_each` over the four rule ARNs.**
  `source_arn` takes one ARN, not a list. Add a fifth EventBridge rule and you
  must add a permission here too, or it silently cannot invoke the function.
- **The handler drops events caused by its own execution role.** Remediation
  calls are themselves API calls that CloudTrail logs and EventBridge feeds
  back in. It compares `sessionContext.sessionIssuer.arn` (the IAM role ARN)
  against `ENGINE_ROLE_ARN` — *not* the top-level `userIdentity.arn`, which is
  an STS assumed-role ARN and never matches. Fails **open** when the variable is
  unset: a missing env var degrading to old behaviour is survivable, one that
  silently drops every event is not.
- **EC2 remediation stops and tags; it does not terminate.** Terminating never
  fixed the violation — the finding is an unencrypted volume, and with
  `DeleteOnTermination: false` (the default for volumes attached at launch) the
  volume outlives the instance. Terminate is behind
  `var.ec2_remediation_action`, and **the same variable builds the IAM policy**,
  so `ec2:TerminateInstances` is absent from the role entirely under the
  default. Unset or unrecognised values fall back to stop: never fail
  destructive.
- **Detection returns three verdicts, not two.** Unencrypted / encrypted /
  **undetermined**. Every path that cannot see the data reports undetermined and
  is neither remediated nor counted as a violation. A missing `Encrypted` field
  is *not* read as unencrypted.
- **`ec2:Describe*` is granted on `"*"`.** AWS does not support resource-level
  permissions for it. That is a constraint, not an oversight; a terraform test
  enforces that only read-only actions sit in that statement.
- **The two `_is_exempt()` implementations differ on purpose.** S3 raises on any
  tag-read error but `NoSuchTagSet`, because one event concerns one bucket, so
  failing the invocation abandons no other work and EventBridge retries it into
  the DLQ. EC2 catches per-instance, because one `RunInstances` event can name
  several instances and one unreadable instance must not abandon the rest — but
  it publishes `DetectionsUndetermined` and a notice rather than staying silent.
- **One test parses `eventbridge.tf`** and asserts its `(source, eventName)`
  pairs match `handler._RULE_REGISTRY` exactly. Adding a rule in one place and
  not the other fails silently in production, so it fails loudly here.
- **The MCP server is read-only in three layers**: no write code path, a test parsing the package AST for mutating call names, and an optional IAM policy granting only Describe/Get/List/StartQuery. `start_` counts as mutating (ec2:StartInstances) with `start_query` exempted by name.
- **The trail and the registry are coupled, and a test enforces it.** The trail
  logs `WriteOnly`, so every registered event must be a write event. Adding a
  read-only one needs `read_write_type = "All"` *and*
  `state = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"` on that rule.
- **An already-revoked SG rule counts as success.** Throttles re-raise, so
  Lambda replays the event and re-attempts revokes that already succeeded.
  `InvalidPermission.NotFound` means the rule is gone, which is the goal.
- **A throttle is not a remediation failure.** `ClientError` is split: throttle
  codes (from botocore's own list) re-raise so EventBridge retries, and publish
  `RemediationsThrottled` with no manual-action email. Everything else reports
  `remediation_failed` as before. Do not merge those branches back together.
- **`send_notice()` is separate from `send_alert()`.** Exemptions and
  undetermined checks need a human but are not findings. Labelling them
  "Compliance Violation" in the subject teaches people to ignore the mailbox.

## Active work

### Agentic AI / MCP extension — ALL FOUR PHASES DONE

**The build plan is `docs/mcp-build-plan.md`** (local, gitignored). Read it
before doing anything here. Decisions already made: read-only MCP server over
stdio, driven from Claude Desktop/Claude Code so it costs nothing to run; a
standalone agent loop is optional phase 4. Code goes in a new top-level
`mcp_server/`, never in `src/lambda/` (that directory is what archive_file zips
into the Lambda).

The resume bullet describes this as *"Agentic AI Extension (Active):
Integrating an event-driven agent layer using Python and MCP (Model Context
Protocol) tool-calling to analyze CloudWatch log patterns, evaluate alert
context, and trigger scoped remediation."*

**Nothing in this repo does MCP yet.** If an interviewer opens the repo, there
is no agent layer to find. Either build it or reword the bullet — the vault
`CLAUDE.md` already warns that these projects read as architected rather than
built, and this is exactly that risk.

Shape when it gets built:

- An MCP server exposing the engine's read surface as tools: query CloudWatch
  Logs Insights over the structured JSON this Lambda already emits, read
  `ComplianceEngine` metrics, fetch a resource's current state.
- Remediation tools stay **scoped and opt-in**, matching the pattern already
  established for `ec2:TerminateInstances`: the permission should not exist
  unless deliberately granted. An agent deciding to act is not a reason to
  widen IAM.
- The signals the agent would reason over already exist: `ViolationsDetected`,
  `RemediationsApplied`/`Failed`, `DetectionsUndetermined`, `ExemptionsApplied`,
  plus the structured log records with `actor`, `violation`, and resource ids.
- The self-invocation guard matters more here, not less. An agent that
  remediates through the same role will generate CloudTrail events that feed
  back into the engine.

### Review pass — complete

All eight issues are done and sitting uncommitted in the working tree, except
issue 1 which is commit `45597c1`. Commit messages and per-issue paths are in
`docs/pending-commits.md`.

## docs/engineering-log.md

A first-person write-up of nine bugs found in the review pass: what was assumed,
what was actually happening, how it was found, what changed. Tracked (not
gitignored) because it is the "built and defended" evidence the vault CLAUDE.md
says these projects lack. If he asks for interview prep material, start there
rather than re-deriving it.

## Releases

`v1.0.0` exists on GitHub, tagged at `987a49b`. It covers the eight-issue review
pass and MCP phases 1-4. It **predates `mcp_server/free_agent.py`**, so do not
describe the free agent as part of it.

The tag sitting behind `main` is normal: a release is a snapshot, `main` moves on.

### Cutting the next one

```bash
git tag -a v1.1.0 -m "short summary"
git push origin v1.1.0
```

Then write the release notes on GitHub. `docs/pending-commits.md` and
`docs/engineering-log.md` are the raw material - the log entries are already in
"what broke and why it mattered" form, which reads well in release notes.

Candidates for `v1.1.0`: the free agent, the four follow-up tasks (rate limiting
and the throttle/failure split, exemption expiry, the load-test analysis, the
trail/registry coupling test).

### Gotcha, learned the hard way

**A tag can keep deleted history alive.** When history was rewritten to strip a
private file, `git filter-repo` rewrote every local ref - but `v1.0.0` existed
only on GitHub, so it was never rewritten, and `git push --force origin main`
does not touch tags. The old commits stayed reachable through the tag, including
the file the rewrite was supposed to remove.

Worse, checking the *local* repo showed the file as gone, because the objects had
been pruned locally. It was only visible by cloning from GitHub and running
`git ls-remote origin` to see every published ref.

If history is ever rewritten again: enumerate `git ls-remote origin` afterwards,
not `git log` locally, and re-point or delete every tag.

## Gotchas in this working copy

- **`.gitignore` had no trailing newline.** Appending a pattern concatenated it
  onto the previous line and silently broke both. Already bitten once before
  (commit `89c0767`, "fix broken gitignore pattern"). Fixed now — check before
  appending.
- **`Interview Technical Deep Dive.md` is tracked by git**, despite the
  assumption that it is ignored. It shows as modified. Decide separately whether
  to `git rm --cached` it.
- **Long bash heredocs fail in this environment** (line-ending issue — the
  terminator does not match). Write the script to a file and run it instead.
- The resume bullet cites **"a 31-test automated unit test suite."** That number
  is stale: it is now 73 python tests plus 11 terraform tests. The terraform
  ones are the more interesting claim — they assert IAM least-privilege
  properties offline, with no credentials and no spend.
- `scripts/check_prerequisites.py` verifies the CloudTrail dependency before
  deploying. Run it on any account this is deployed to: without a logging
  trail the engine deploys cleanly and receives nothing.
