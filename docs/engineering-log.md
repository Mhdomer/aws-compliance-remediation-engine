# What broke, and how I worked it out

This is my engineering log for the compliance engine. Not a feature list. It is
the record of things I got wrong, how I found out, and what I changed.

I wrote it because I noticed I could describe what my project *does* but not
what it *cost me to get right*, and the second one is the interesting part. Most
of these are bugs my own tests were passing over.

Each entry has the same shape: what I assumed, what was actually happening, how
I found out, what I changed, and what I took from it.

---

## 1. Terminating the instance never fixed the violation

**What I assumed.** My rule detects an EC2 instance launched with an unencrypted
EBS volume, and remediates by terminating the instance. Violation gone.

**What was actually happening.** The violation is "there is an unencrypted
volume." Terminating destroys the *compute*. Whether it touches the volume
depends entirely on the `DeleteOnTermination` flag, which my detection code
never even read. For a data volume attached at launch that flag defaults to
false, so the volume outlives the instance.

**How I found out.** I stopped arguing about it and tested it against mocked
EC2:

```
/dev/sdf   encrypted=False  deleteOnTermination=False
volumes before terminate: 1   after: 1
unencrypted volumes still in the account: ['vol-4b64e5acc299ea34b']
instance state: terminated
```

The instance is gone. The unencrypted volume is still sitting there. My engine
published a success metric and emailed "AUTO-REMEDIATED."

And in the case where it *does* delete the volume (the root volume, where the
flag defaults true), my remediation for "this data is not encrypted" is "delete
the data." Neither branch is a remediation.

**What I changed.** Default is now tag-and-stop. Stopping halts writes to the
unencrypted volume while leaving the volume intact, so the actual fix (snapshot,
copy encrypted, reattach) is still possible, and it is reversible with one API
call. Terminate is behind a variable, and **the same variable builds the IAM
policy**, so with the default the role does not have `ec2:TerminateInstances` at
all.

**What I took from it.** I had been checking whether my remediation *ran*, not
whether it *worked*. Those are different questions and only one of them matters.
Also: two independent controls beat one. A code flag someone can override with
an environment variable is weaker than a permission that does not exist.

---

## 2. My engine reported a failure on something it had just fixed

**What I assumed.** Security group rule opens port 22 to the world, I revoke it,
done.

**What was actually happening.** My detection loop emitted one violation per
restricted port covered by a rule. But each violation carried the *rule's* port
range, not the matched port. So one rule spanning 0-65535, or protocol `-1`,
produced two violations with byte-identical revoke parameters.

First revoke removed the rule. Second revoke asked AWS to remove a rule that no
longer existed:

```
revoke #1 -> {'Return': True}
revoke #2 -> ClientError: InvalidPermission.NotFound
```

That is caught as a failure. So the sequence was: close both ports with one
call, then report that port 22 could not be remediated, send a "REQUIRES MANUAL
ACTION" email, and increment the failure metric. For something I had already
fixed.

**How I found out.** I ran the handler against a client that behaves like real
AWS and watched the output. Not by reading the code, which I had read several
times without seeing it.

**What I changed.** Group violations by the tuple the revoke is actually built
from `(cidr, from_port, to_port, protocol)`, revoke once per group, attribute
the outcome to every port in it. Detection is unchanged, so I still learn both
ports were exposed.

**What I took from it.** All 31 of my tests passed because every fixture used a
single-port rule, which makes the bug structurally unreachable. I had a test
that built a 0-65535 rule, but it only checked detection and never called the
handler. It stopped one layer short of the code that breaks. That gap, tests
that stop just before the thing that fails, is the one I now look for first.

Second thing: a security tool whose failure alerts are wrong is worse than one
with no alerts, because it teaches people to ignore the mailbox.

---

## 3. My detector returned "compliant" when it could not see anything

**What I assumed.** `_has_unencrypted_volume()` returns True or False. False
means compliant.

**What was actually happening.** The function loops over `BlockDeviceMappings`
and returns True on the first unencrypted volume. If that list is **empty**, the
loop body never runs and it falls through to `return False`.

So "I found no unencrypted volumes" and "I could not see any volumes" produced
the identical answer. The trigger is `RunInstances`, which fires at launch, and
an instance still in `pending` may not have its volumes attached yet. The
instance gets logged compliant. No metric, no alert, nothing to review.

**How I found out.** I went looking for it deliberately after the first two
bugs, because I had started to distrust anywhere my code returned a boolean for
something that had three possible states.

I could not reproduce the actual timing window offline, and I want to be honest
about that: moto returns `running` with the mappings already populated. What I
could test exhaustively was the code's response to an empty list, which is where
the bug lives.

**Confirmed on a live account, 2026-09-19.** The window is real. `RunInstances`
came back with the instance `pending` and the mappings empty:

```
i-0e90984ff035b692d   pending   BlockDeviceMappings: []
```

That empty list is what CloudTrail puts in `responseElements`, so a rule reading
the event payload would hit this on every launch. Mine does not. It calls
`describe_instances` fresh, and by the time the Lambda ran, roughly eight seconds
after launch, the mappings were populated. Detection returned
`EC2_UNENCRYPTED_EBS` rather than undetermined and `DetectionsUndetermined`
stayed at zero.

So the race exists and the re-describe is what steps around it. That was not a
decision I made for this reason, it is how I happened to write it. It is a
decision now, and the reason is written down.

**What I changed.** Three verdicts instead of two: unencrypted, encrypted, or
**undetermined**. Every path that cannot see the data returns undetermined, and
undetermined is neither remediated nor counted as a violation. It gets its own
metric and an alert.

Writing those tests found a second bug pointing the other way: a volume with no
`Encrypted` field at all was being read as unencrypted, because the lookup
defaulted to False. That would have stopped an instance on the strength of a
missing key.

**What I took from it.** A detection control that errors gets noticed. One that
returns a confident wrong answer does not. **"Nothing found" and "I could not
look" must never be the same value.** This turned out to be the theme of the
whole project.

---

## 4. The way to bypass my engine was quieter than using it

**What I assumed.** The `ComplianceExempt=true` tag is a convenience for
resources that legitimately need an exception.

**What was actually happening.** That tag disables the control for a resource,
which makes it an authorisation boundary. And it is granted by
`s3:PutBucketTagging` and `ec2:CreateTags`, which get handed out routinely for
cost allocation, by people who have no idea they are also granting "turn off the
compliance engine for this resource."

Nothing recorded its use. Three different silences:

- the S3 ACL path logged at INFO, without the actor, no metric
- the S3 encryption path logged **nothing at all** and just returned
- the EC2 path appended a result and moved on

So the attack is two API calls with no alarm anywhere. Tag the bucket, then make
it public. My engine sees the event, checks the tag, stops. No email, no metric,
nothing on the dashboard. Meanwhile the *compliant* path emails you.

**How I found out.** I was reading the exemption code for an unrelated reason
and noticed the encryption handler had no log line at all. Then I compared it to
what happens on the normal path and the asymmetry was obvious.

**What I changed.** Every exemption now logs at WARNING with the actor,
publishes an `ExemptionsApplied` metric, and sends a notice naming who did it.
Plus an alarm on bursts, which is a different signal: one exemption is
legitimate governance, several in five minutes is someone disabling the engine
at scale.

**What I took from it.** **A control's exception path needs more visibility than
its happy path, because the exception path is the one an attacker chooses.** I
had it backwards.

---

## 5. Anyone who could create an EventBridge rule could borrow my Lambda's role

**What I assumed.** `aws_lambda_permission` with `principal =
"events.amazonaws.com"` means "EventBridge can invoke this."

**What was actually happening.** It means *any* EventBridge rule, in *any*
account, can invoke it. With no `source_arn` and no `source_account`, the policy
statement had no `Condition` block at all. The whole authorisation decision was
"is the caller the EventBridge service?"

That is worse here than on a normal Lambda, because of what my function does. It
dispatches on `detail.eventName` and takes the target resource ID straight out of
the event body, then acts on it with a role that can revoke security group rules,
stop instances, and rewrite bucket encryption.

So: someone with `events:PutRule` and `events:PutTargets`, a far more commonly
granted pair than any `lambda:*` permission, creates their own rule, points it at
my function, and hands it a hand-crafted event naming any resource they like. My
engine acts on it. They never needed permission on the target. They borrowed my
execution role.

**How I found out.** This one was pointed out to me in review, and I had to go
and understand *why* it mattered rather than just adding the parameter. The
concept has a name: confused deputy. My Lambda is the deputy, its IAM role is
the authority, and the missing condition is what lets someone else direct it.

**What I changed.** `source_arn` takes one ARN, not a list, so it became a
`for_each` over the four rule ARNs with one statement each. The rule ARN embeds
the account, which closes the cross-account case at the same time.

**What I took from it.** I now read every resource policy asking "who *else*
satisfies this condition?" rather than "does my thing satisfy it?" The same
pattern came up twice more in this project, on the CloudTrail bucket policy.

---

## 6. I had documented the dependency, and it still did not help

**What I assumed.** The README says CloudTrail must be enabled. Dependency
documented, job done.

**What was actually happening.** Without a trail logging write management
events, `terraform apply` succeeds, every resource reports healthy, the
dashboard renders, and no event ever arrives. Nothing errors anywhere.

The line was already in my README, and in a comment in `eventbridge.tf`. Two
places. It did not prevent anything, because prose is not checkable. It was also
underspecified: "CloudTrail enabled" does not tell you a *trail* is needed rather
than Event history (which is always on and is not the same thing), does not name
a region, and does not mention management events.

**How I found out.** I was asked to make the dependency explicit, and while
writing it up I realised the documentation already existed. That was the actual
finding. The problem was never that it was undocumented.

**What I changed.** `scripts/check_prerequisites.py`, which makes only read-only
calls and exits non-zero with the specific reason. It catches a missing trail, a
stopped trail, management events excluded, a read-only trail (all four of my
rules match *write* events), and, importantly, **not having permission to
check** — because "I could not look" is not "everything is fine."

I also verified the cost question rather than assuming. AWS delivers the first
copy of management events per region free; a *second* trail carrying the same
events is billed as an additional copy. That is why the trail resource I added is
off by default: most real accounts already have one.

**What I took from it.** If the failure is silent, a sentence in the README is
not a fix. Make it checkable or it will happen again. I also had to fix this
script a second time: it was building its client with no region, so it checked
whatever my CLI defaults to (`ap-southeast-1`) while the engine deploys to
`us-east-1`. **A pass against the wrong region is worse than a failure.**

---

## 7. My remediation triggered my own detector

**What I assumed.** The engine remediates and stops.

**What was actually happening.** Every remediation is itself an API call, so
CloudTrail logs it and EventBridge feeds it straight back in. When my S3
encryption handler calls `put_bucket_encryption`, that emits a
`PutBucketEncryption` event, which is exactly what one of my rules watches for.

It stopped after one extra pass, but only because the value my remediator writes
happened to satisfy my detector's check. Nothing enforced that agreement. No test
covered it. No comment mentioned it.

**How I found out.** I wanted to know how fragile it was, so I tightened the
predicate the way a reasonable future change would (compare the key ARN, not just
the algorithm) with a stale key ARN, and ran it:

```
today's predicate:      ['remediated', 'compliant']
tightened predicate:    ['remediated','remediated','remediated','remediated','remediated','remediated']
```

The second one never converges. It only stops because I capped the loop. In real
AWS that is unbounded: an invocation, an S3 write, a metric and an email on every
pass, at machine speed, until someone disables the rule.

**What I changed.** The handler drops events caused by its own execution role. It
compares `sessionContext.sessionIssuer.arn` (the IAM role ARN) against the role
terraform created. Not the top-level `userIdentity.arn`, which is an STS
*assumed-role* ARN with a session name appended and never equals the role ARN.
Comparing the wrong one would have looked like a working guard that silently does
nothing.

It fails **open** when the variable is unset. A missing env var degrading to the
old behaviour is survivable. One that silently drops every event is a detection
control that looks alive and does nothing.

**Confirmed on a live account, 2026-09-19.** I deployed this and put AES256
encryption on a bucket. The engine remediated to KMS, its own
`PutBucketEncryption` arrived back 6.5 seconds later, and the guard dropped it.
The ARNs on that event:

```
userIdentity.arn  : arn:aws:sts::...:assumed-role/compliance-engine-test-lambda-role/compliance-engine-test
sessionIssuer.arn : arn:aws:iam::...:role/compliance-engine-test-lambda-role
ENGINE_ROLE_ARN   : arn:aws:iam::...:role/compliance-engine-test-lambda-role
```

`sessionIssuer.arn` matches exactly. `userIdentity.arn` is a different string and
no comparison against it could ever have been true. I had worked that out from
the documentation and hand-built fixtures; this is the first time I have seen the
real record say it. The loop stopped after one pass.

The other direction is worth noting too. My own IAM user's events carry no
`sessionContext` at all, which is the case the fallback branch exists for.

**What I took from it.** Loop-freedom was an accident of two unrelated pieces of
code agreeing. I made it structural. Also: the guard creates a blind spot, since
the engine now ignores anything done with its own role. That is why the drop logs
at WARNING with the actor. The log line is the compensating control, not debug
output.

---

## 8. 88% test coverage was hiding the parts that mattered

**What I assumed.** 31 tests, all passing, covering all three rule modules.
Reasonable coverage.

**What was actually happening.** When I finally measured it, the gaps were
exactly where you would least want them:

```
src/lambda/utils/notifier.py    60%
src/lambda/utils/cloudwatch_utils.py  78%
src/lambda/handler.py           86%
```

`notifier.py` at 60% because **every rule test mocks `send_alert`**, so neither
notification body had ever actually executed. My tests mocked the thing and then
never tested the thing. The dispatch registry had zero tests. And my real
captured CloudTrail fixtures were never driven end to end through
`lambda_handler` at all, which is the one thing that would catch a wrong
assumption about the event shape.

**What I changed.** Coverage is now 99%, but the number is not the point. The
tests I actually care about:

- one that parses `eventbridge.tf`, extracts the `(source, eventName)` pairs, and
  asserts they match the handler's registry exactly. Add a terraform rule without
  a registry entry and events arrive and silently return `no_rule`. Add a registry
  entry with no rule and it never fires. Neither announces itself in production,
  so now it fails in CI.
- the real fixtures driven through the handler. Hand-built payloads can only be
  wrong in the same way my code is wrong.

**What I took from it.** Coverage percentage told me where to look, not whether I
was done. The useful question was "which of these lines has never run in any
test?" and the answer was the notification code, which is the whole output of the
system.

---

## 9. A test that reached the internet, and still passed

**How I found out.** I added a metric call, and the suite went from 0.31s to
2.67s with botocore deprecation warnings. Tests still green.

**What was happening.** One test class was missing a patch, so it built a real
CloudWatch client and attempted network calls. It passed anyway, because the
metric publisher swallows its own errors by design.

That is the same failure shape as bug 3: something that looks like success and
is not. It was also quietly using whatever AWS credentials happened to be loaded
on my machine.

**What I changed.** `tests/conftest.py` now fails any test that constructs a real
boto3 client, with an opt-out marker for mocked-AWS tests. I checked it bites
rather than assuming:

```
AssertionError: test built a real boto3 client for 'cloudwatch'.
```

Suite is now 0.18s, faster than before I started.

---

## 10. Being throttled and failing were the same value

**What I assumed.** Rate limiting was a capacity problem: under a burst the
engine would be throttled, remediations would fail, and the DLQ would fill with
things to retry.

**What was actually happening.** Throttled remediations never reach the DLQ at
all. `RequestLimitExceeded` arrives as a `ClientError`, and every rule module
catches `ClientError` the same way: set `remediated = False`, publish
`RemediationsFailed`, email `[REQUIRES MANUAL ACTION]`, return normally. Lambda
sees success. Nothing retries.

I proved it rather than reasoning about it:

```
per-port status : ['remediation_failed']
metric          : RemediationsFailed
email           : REQUIRES MANUAL ACTION
lambda          : returned success - nothing retries, nothing reaches the DLQ
the SG          : STILL OPEN TO 0.0.0.0/0
```

So the engine was treating two different things as one value:

- "I called revoke and AWS refused, the rule is still there" - a real failure
  needing a human
- "I never got to call revoke, AWS told me to slow down" - transient, should
  just be retried

This is bug 3 again in a new place. There, *nothing found* and *I could not
look* were the same value. Here, *I tried and failed* and *I was not allowed to
try* are the same value. The consequence is worse, because the retry that would
have fixed it never happens and the only record is one more email in a mailbox
that is flooding from the same burst.

**How I found out.** I sat down to add rate limiting and started by checking
what the code actually does under a throttle instead of assuming. The buffering
question turned out to be the smaller half of the problem.

**What I changed.**

- Throttling is now classified separately using botocore's own list of throttle
  codes, not a hand-written one that would drift the moment AWS adds a code.
  A throttle re-raises: the invocation fails, EventBridge retries, and the event
  reaches the DLQ only if it keeps failing. It publishes `RemediationsThrottled`
  and sends no manual-action email, because the engine never attempted anything.
- Every client now shares a botocore `Config` with adaptive retries. Adaptive
  adds a client-side rate limiter that paces calls *within* one invocation. It
  does not coordinate across invocations, which is a real limitation, but the
  worst path here is one invocation making many serial calls, which is exactly
  what a per-client limiter is for.
- Socket timeouts are bounded. The botocore default read timeout is 60 seconds,
  the same as the whole Lambda timeout, so one hung socket ate the entire
  invocation.
- `reserved_concurrent_executions = 10`. Lambda already queues async
  invocations and retries throttled ones for up to six hours; running
  unreserved bypassed that buffer entirely. 10 keeps the engine near the
  slowest EC2 token bucket refill rate (5/sec) while still clearing a
  50-violation burst in about ten seconds.

**What I considered and did not do.** An SQS queue between EventBridge and
Lambda. It buys real things Lambda's async queue does not: a visible depth
metric, no silent ageing-out of events, and `ReportBatchItemFailures` so a
throttled item can be returned to the queue. But it changes the event shape the
handler receives, which breaks every test that drives `lambda_handler` including
the four captured CloudTrail fixtures. Three of those came from a live account,
and rewrapping them weakens the one claim in this project that cannot be faked.

The condition that would change my answer: if Lambda's async queue ever starts
ageing events out under sustained load, that is a silent drop in a detection
control, and SQS becomes worth the cost.

**What I took from it.** The same lesson a third time, and I now think it is the
single most useful idea in this project: **two outcomes that need different
responses must never be recorded as the same value.** Also that "add rate
limiting" was the wrong framing. Checking what the code did under the condition
I was designing for found a worse bug than the one I set out to fix.

**Still broken, deliberately out of scope.** `handle_run_instances` loops over
every instance in the event serially inside one 60-second invocation. A
`RunInstances` with 50 instances is around 300 API calls, which will time out,
and a timeout is a function error that replays the whole event. That is a
separate bug from rate limiting and it is the one most likely to actually bite.
Replay is at least safe: `create_tags` and `stop_instances` are both idempotent,
verified against moto.

---

## 11. I could not load test it, so I worked out what it would tell me

**What I assumed.** "I have never load tested this" was a limitation I could
only state, not do anything about, because testing it means deploying and
generating load, and that costs money.

**What was actually happening.** The cost part was wrong. I wrote the estimator
and ran it:

```
50 security groups opened + 10 unencrypted instances
  -> 51 Lambda invocations
  -> 310 AWS API calls made BY the engine
  -> 110 emails to the SNS subscriber

  $  0.0087  ec2 instances
  $  0.0022  sns email delivery
  $  0.0011  cloudwatch put_metric_data
  $  0.0132  TOTAL
```

One and a third cents. The load test is not expensive. What actually stops me
running it is the no-spend rule I set myself, and two real operational costs
that are not money: 110 emails hitting one mailbox in under a minute, and real
instances that keep billing if cleanup fails.

Saying "it costs money" was the comfortable version. The honest version is that
it costs about a penny and I have chosen not to, which is a different statement.

**What I measured instead.** The API call count per invocation, by driving each
handler with recording mocks and counting. These are measured, not read off the
source:

| Event | API calls |
|---|---|
| Security group, one wide rule tripping both ports | 5 |
| S3 public ACL | 4 |
| S3 weak encryption | 4 |
| RunInstances, per instance | **6** |

The EC2 number is the one that matters, because the rule loops over every
instance in the event serially inside one invocation. Fifty instances is 300 API
calls in one 60-second function. At roughly 40ms per call that is 12 seconds
clean, and any throttling with backoff pushes it past the timeout.

Against the documented EC2 token buckets (from AWS docs, which I cannot verify
without an account): the mutating actions this engine calls refill at 5/sec.
Reserved concurrency of 10 sits just above that, which is why the setting is
where it is.

One caveat I could not resolve offline. The AWS docs define the larger
Describe bucket by reference to the `Filters` parameter, and this engine calls
`describe_instances(InstanceIds=[...])`, which is a resource-id parameter rather
than a filter. So those two calls may draw from the larger bucket. I used the
smaller, more conservative number and am flagging it rather than pretending to
know.

**What I built.** `scripts/load_test.py`. It estimates by default, prints what
it would create and what it would cost, and refuses to run without two separate
flags. The generator itself is deliberately unwritten: a script that creates
public security groups and unencrypted instances is one bad flag away from being
an incident, and it has no business existing until someone has decided to run it.

**The bug this found.** Writing a replay-safety test, because throttles now
re-raise and Lambda retries the whole event, turned up a regression I had just
introduced. If one rule in an event revokes successfully and a later one is
throttled, the replay re-attempts the first revoke, AWS returns
`InvalidPermission.NotFound`, and the engine reported `remediation_failed` and
emailed a human.

That is bug 2 again, arriving through a different door. Bug 2 was a duplicate
revoke caused by duplicate violations. This is a duplicate revoke caused by a
replay, and my fix for bug 2 did nothing about it because it grouped violations
within a single invocation.

Revoking a rule that is already gone is now treated as success, because it is:
the rule does not exist, which is the outcome the remediation wanted.

**What I took from it.** Two things.

Every safety mechanism I add creates a new path, and the new path needs the same
scrutiny as the original. Re-raising on throttle was correct and introduced a
replay, and the replay reintroduced a bug I had already fixed once.

And I should be more careful about which limitations are real. "It costs money"
sounded like a constraint. Measuring it turned it into a choice, and a choice is
something I can defend in an interview. A vague constraint is something I just
repeat.

---

## 12. The last thing guarded only by a comment

**What I assumed.** The optional CloudTrail trail logs `WriteOnly` management
events, which is correct for all four rules. I had written a comment explaining
that adding a read-only rule would need the trail widened, and considered that
handled.

**What was actually happening.** Nothing was handled. Two separate things would
both need changing to add a read-only rule, and neither omission errors:

1. the trail would have to log `All` rather than `WriteOnly`, or CloudTrail
   never records the event
2. that EventBridge rule would need
   `state = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"`, because
   default-enabled rules only match *write* management events

Miss either and the rule deploys, reports healthy, and receives nothing. The
same silent-deployment failure as the missing trail in entry 6, and I had
"fixed" that one by writing a check rather than a sentence. Then left this one
as a sentence.

**How I found out.** I listed it in my own "what I would still change" section
as "documented only in a comment, which by my own lesson is not good enough",
and then did nothing about it for a while.

**What I changed.** A test that reads all three sources and asserts they agree:
the event names in `handler.py`'s registry, the `read_write_type` in
`cloudtrail.tf`, and each rule's `state` in `eventbridge.tf`. If the trail is
`WriteOnly`, every registered event must be a write event. If any registered
event is read-only, its rule must carry the special state.

Then I proved it bites, by adding a `GetBucketAcl` rule the way someone
naturally would:

```
AssertionError: ['GetBucketAcl'] look like read-only events, but the trail in
cloudtrail.tf logs WriteOnly management events, so CloudTrail will never record
them and the rule will never fire. Set read_write_type = "All" and give those
rules state = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS".
```

Two assertions fire independently, one for the trail and one for the rule state,
so whichever half you forget is named.

**One thing I could not do the easy way.** CloudTrail marks each event with a
`readOnly` field, and I wanted to use that rather than guess from the verb. But
only two of my four captured fixtures carry it - the two real EC2 events omit it
entirely. So the verb prefix is the primary check and `readOnly` only
corroborates where it exists, with a test asserting the two agree wherever both
are available.

I also checked that the terraform provider actually accepts
`ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS` before writing a test that tells
people to use it, rather than sending someone down a path that does not work.

**What I took from it.** I knew this was a gap, wrote it down, and still left it.
Writing a limitation down feels like addressing it and is not the same thing. The
useful question is not "have I documented this" but "what would fail if someone
got it wrong", and if the answer is "nothing", it is not guarded.

---

## 13. "Attempted" and "succeeded" were the same value

**What I assumed.** CloudTrail delivers mutating API calls that happened in AWS.
If an event has `eventName: PutBucketAcl` and `requestParameters: {x-amz-acl: public-read}`,
a caller put a public ACL on the bucket.

**What was actually happening.** CloudTrail records API calls that AWS *rejected*,
and EventBridge delivers them to the default event bus with the caller's
`requestParameters` intact. When S3 Block Public Access rejected a `PutBucketAcl`
call with `AccessDenied`, the bucket was never public. But my handler inspected
only what was requested, saw `public-read`, logged a violation, applied
`PutPublicAccessBlock`, published `ViolationsDetected = 1` and
`RemediationsApplied = 1`, and would have sent an alert email. The engine
reported an exposure that never happened and took credit for remediating a
control that AWS had already enforced.

**How I found out.** Deploying to a live AWS account on 2026-09-19. I attempted a
`public-read` ACL on a fresh bucket before disabling S3 Block Public Access. AWS
rejected the call with `AccessDenied`. When I checked CloudWatch metrics,
`ViolationsDetected` was 2.0 and `RemediationsApplied` was 2.0 for a test where I
only exposed the bucket once. The extra count was the failed attempt.

**What I changed.** `lambda_handler` now inspects `detail.get('errorCode')`. When
present, the API call failed before taking effect. Instead of dispatching to
rule evaluators, the handler drops the event, logs at WARNING with the actor,
publishes a `ViolationAttemptsBlocked` metric (dimensioned by `EventName` and
`ErrorCode`), and sends an operational notice via
`send_notice(NOTICE_ATTEMPT_BLOCKED, ..., STATUS_BLOCKED)`.

**What I took from it.** The engine's recurring theme was "nothing found" and "could
not look" must never be the same value. This was the same failure mode pointing
the other direction: "attempted" and "succeeded" must never be the same value.
CloudTrail is an audit log of requests, not just successful state transitions.
Treating requested parameters as ground truth without checking `errorCode` turns
an attacker's failed probing into false compliance victories.

---

## 14. 340 tests passed while every violation log line lost its fields

**What I assumed.** My logging tests proved that violations logged as structured
JSON with the actor, resource ID, and violation type ready for CloudWatch Logs
Insights.

**What was actually happening.** In production, every violation log line arrived
in CloudWatch as an unstructured string: `[WARNING] ... Violation detected`.
The actor, violation type, CIDR, and resource ID were completely missing. Even
worse, all 5 `logger.info` lines in the rule modules — including the replay-safety
log line when a security group rule was already revoked — were silently
discarded and never reached CloudWatch at all.

**How I found out.** Looking at the real CloudWatch log stream during the live
security group remediation test. The handler's own logs were valid JSON, but the
rule module's WARNING had no fields.

**What was actually wrong.** `handler.py` called `setup_logger(__name__)`, which
attaches `StructuredFormatter` and sets `propagate = False`. But all three rule
modules (`sg_rules.py`, `s3_rules.py`, `ec2_rules.py`) called bare
`logging.getLogger(__name__)`. In Lambda's runtime, unconfigured loggers inherit
the root logger, which defaults to `WARNING` (dropping `INFO` calls) and renders
only `%(message)s` (dropping `extra={...}`).

**Why 340 unit tests missed it.** `test_logger.py` created a
`LogRecord(name='rules.s3_rules')` by hand and passed it into a manually
instantiated `StructuredFormatter()`. It tested that the formatter worked if
called, but never tested that the rule modules actually used that formatter. And
in the rule unit tests, assertions read `record.actor` directly off the Python
`LogRecord` object, which is populated in memory regardless of how any handler
renders it.

**What I changed.** Replaced `logging.getLogger(__name__)` with
`setup_logger(__name__)` across `sg_rules.py`, `s3_rules.py`, and `ec2_rules.py`.
Added a test in `test_logger.py` that inspects the real loggers on those three
modules and asserts they have a `StructuredFormatter` handler and
`propagate = False`.

---

## 15. The module could not deploy to a default-quota AWS account

**What I assumed.** `lambda_reserved_concurrency` defaults to 10 to pace
remediations near the EC2 token bucket refill rate. A validation condition
`var.lambda_reserved_concurrency > 0` ensured users could not pass 0 (which
disables the function).

**What was actually happening.** On a newer AWS account, the total Lambda
concurrency quota is 10, not 1000. AWS enforces that at least 10 executions
must remain unreserved. Therefore, unreserved = 10 - reserved >= 10 forces
reserved <= 0. Every positive reservation is rejected by AWS with
`InvalidParameterValueException`. And because 0 disables the function, no legal
value existed for this variable on such an account.

**How I found out.** The first `terraform apply` against real AWS failed with
`PutFunctionConcurrency: InvalidParameterValueException`.

**What I changed.** Relaxed validation to allow `-1` (the provider's sentinel for
"no reservation"), documented the quota constraint, and added a terraform test
asserting that `-1` is expressible. On such accounts, the account quota itself
already enforces the pacing.

---

## 16. The rule guarded a door AWS had already welded shut

**What I assumed.** `PutBucketAcl` with a public canned ACL is how a bucket
becomes public, so watching that event covers the exposure.

**What was actually happening.** I created a plain bucket on a live account to
exercise the rule and could not make it public at all:

```
AccessDenied: ... because public ACLs are prevented by the BlockPublicAcls
setting in S3 Block Public Access.
```

Every bucket created since April 2023 arrives with Block Public Access fully on
and `ObjectOwnership: BucketOwnerEnforced`, which disables ACLs outright. To
produce the violation my rule watches for, I had to make two calls first:

```
DeleteBucketPublicAccessBlock
PutBucketOwnershipControls   (BucketOwnerEnforced -> ObjectWriter)
```

Neither is in `_RULE_REGISTRY`. Both are write management events the trail
already logs, so they reach EventBridge. Nothing is listening for them.

**Why that matters.** The realistic path to a public bucket in a current account
does not begin with the event I watch. It begins with the two calls that take the
protections off, and by the time `PutBucketAcl` fires the account has already
been weakened, with nothing raised in between. My rule is the last line, and I
had been describing it as the detection.

**What I have not changed yet.** Adding these is a registry entry, a module, an
EventBridge rule and a matching `aws_lambda_permission` for each. I am recording
it rather than half doing it, because disabling Block Public Access is not
automatically a violation the way a public ACL is. Some buckets legitimately need
ACLs back on. The right shape is probably a notice carrying the actor rather than
a remediation, and that deserves its own thinking instead of being bolted on at
the end of a deployment session.

**What I took from it.** I wrote this rule against how S3 behaved when I learned
S3, and AWS moved the defaults underneath it. Deploying to a real account was the
only thing that was going to tell me. Every fixture I had was a successful
`PutBucketAcl`, which is a call a default bucket in 2026 will not even accept.

---

## The things I would tell myself at the start

**"Nothing found" and "I could not look" must never be the same value.** This is
the single lesson that recurs. It showed up in the volume check, in the
prerequisite script, in the exemption lookup, and in the MCP tools I wrote later.
Every tool I have written since returns a warning when an empty result is
ambiguous, instead of an empty success.

**"Attempted" and "succeeded" must never be the same value.** CloudTrail logs
failed calls and EventBridge delivers them. Reading what was requested without
checking `errorCode` turns failed attacks into false remediation credits.

**A control's exception path needs more logging than its happy path.** Exemptions,
errors, skips. Those are the paths someone evading the control will take, and
they were the quietest paths in my code.

**Check whether the remediation fixed the violation, not whether it ran.**
Terminating an instance ran perfectly and fixed nothing.

**Test the wiring, not just the component.** A formatter test that constructs the
formatter by hand proves the class works; it does not prove any module uses it.
A test that checks what a terraform value *is* does not prove AWS will accept it.

**Test the guard, not just with the guard.** After writing each safety check I
deliberately broke the thing it protects to confirm it fails. The read-only IAM
policy test looked fine until I injected `ec2:TerminateInstances` and watched it
fail. Before that I did not actually know it worked, I only believed it did.

**Do not trust what I remember about a library.** Building the MCP layer, I
would have written `FastMCP` (does not exist in the current SDK) and
`inputSchema` (it is `input_schema`). I installed the package and inspected it
instead, which took two minutes. Same with the Anthropic API: the thinking
parameter shape I remembered is now rejected with a 400.

**Two weak controls beat one, if they fail independently.** A code flag plus an
absent IAM permission. A Python test plus a terraform test. Either alone is
something I could get wrong.

---

## What I would still change

Honest list of what this project does not do yet.

- `handle_run_instances` processes every instance in an event serially inside
  one invocation. A large `RunInstances` will time out and replay. See entry 10.
- Exemptions have no expiry. A resource tagged exempt stays exempt forever, and
  the right design is probably a date the tag stops being honoured.
- I have still never load-tested this under sustained traffic, but the
  deployment gap is closed: on 2026-09-19 it ran on a real account and every rule
  was driven end to end. Measured CloudTrail-to-Lambda delivery latency was 3.5s
  to 6s for EC2 and security groups and 8s to 9.5s for S3. A cold invocation took
  2530ms and used 109MB of the 256MB allocated, so the memory setting has more
  headroom than it needs. EC2 remediation stopped and tagged the instance and did
  not terminate it, with `ec2:TerminateInstances` absent from the deployed role.
- The engine watches `PutBucketAcl` but not the two calls that make a public ACL
  possible on a current account. See entry 16.
- Exemptions now expire, but nothing reminds anyone before they do. A resource
  silently starts being checked again on the expiry date, and the owner finds
  out from a remediation rather than a warning.
