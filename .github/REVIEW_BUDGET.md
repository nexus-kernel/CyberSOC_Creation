# CyberSOC optional review budget (disabled)

Installation is authorized; activation, review requests, issue handoffs and automatic
merge are not. `review-budget.json` is target-bound and remains enabled=false,
activation_after=null, independent_code_triggers_disabled=false,
security_review_required=true, ordinary_completed_rounds=3,
native_merge_policy_verified=false, merge_queue_required=null.
No credentials, integration/security settings, subscriptions or protections are changed.
The current draft→Void→ready→automatic Codex→clean exact-head CI path stays active.
The following describes prospective behavior only. Protocol strings `MXDR budget`
and `mxdr-budget` are retained consistently for title/artifact/history compatibility;
all repository bindings point to CyberSOC. The old EBR webhook-ledger prototype is
removed; it cannot be activated or have its state guessed into this artifact ledger.

## Sole requester and completed rounds

After separate activation, only review-budget.yml may request Code Review. Wakes are PR readiness/new heads,
authenticated Codex summary updates, completed trusted CI, and manual dispatch.
Wakes dispatch the controller on the actual default branch; they never execute PR
code. Human issue comments cannot supply counts, clearances or severity overrides.
One per-PR concurrency group serializes controller actions. No native reruns.
The wake relay and every controller phase require verified native merge policy
and explicitly no merge queue before any operational write. Partial activation is inert.
Unknown mergeability is retried with five read-only snapshots and 2/4/8/16-second
backoffs (30 seconds total, excluding API time). Confirmed conflicts, malformed
responses, API failures, closed/draft PRs, or head/base changes stop immediately.
If mergeability stays unknown beyond this bound, no review request or clearance
is issued; an owner must request a fresh controller wake after GitHub settles.
This bounded retry does not guarantee delivery through a prolonged GitHub outage.

The ordinary budget is THREE COMPLETED Code Review rounds over the PR's lifetime,
across all heads. One outstanding request is permitted. A request is reserved and
persisted before POST; only an authenticated, later current-head completion linked
to that immutable request increments the completed count. Duplicate wakes do not
request another review. A completed same-head review with findings waits for a fix
and new head; it does not burn another round by re-requesting the same diff.
Authenticated completion is checkpointed even when P1 or another clearance blocker
prevents handoff. A subsequent fix head can therefore use the recorded P1 exception.
Budget clearance also requires a live exact-head completion: a running, missing,
unknown, or stale summary cannot inherit clearance from the ledger. Authenticated
review activity newer than the summary completion blocks clearance.

Before the cap, new heads may receive reviews after the preceding completion was
recorded. After three completed rounds, another request requires a currently
unresolved authenticated P1, recorded as the exception before dispatch and checked
again before POST. Keep the P1 open until its follow-up completes; resolving it
before reserving the follow-up requires owner reconciliation. P0, unknown severity,
ambiguous activity and unknown review formats block automation. Security Review
is separate and NEVER waived by this budget.

A post-cap new head without P1 cannot inherit prior review or obtain a fourth
ordinary round. CI-fix commits have the same restriction. Stop for owner decision;
no hidden exception or supplied-count input exists. Failed/uncertain requests do
not count as completed, but block recovery until audited rather than being resent.

## Authenticated evidence

The collector pins Codex ID 199175422, login chatgpt-codex-connector[bot], Bot type;
validates structured summary state and exact full SHA; requires authenticated review
receipts and finding-to-review associations; and parses only the observed anchored
P0/P1/P2 code-finding badge. Markers or severity quoted by humans are not authority.
It reads paginated reviews, comments, reactions and thread roots, including outdated
threads. All inline comments must map to GraphQL threads. Unresolved multi-comment
threads or unsupported nested pagination block for manual resolution/classification.
Security/unknown findings are not reclassified into P2. Dismissal is not resolution.

Configured/requested Security Review must finish clean on the same head. Requested
security completion must postdate its request; unknown coverage blocks activation.
Newer/running review activity, changes requests, unknown mergeability, draft/closed
state, forks and unsatisfied native review decisions stay blocking. Head/base/state
are read again after collection. Normal clean review still uses the existing clean
reaction checks. Remaining P2 requires three completed ledger rounds and a completed
latest round on the current head; no thumbs-up is fabricated.

## Durable ledger and recovery limits

The durable store is GitHub Actions v4 immutable artifacts, using the existing
Actions service and job credentials; no new persistent credentials or infrastructure.
Each controller run uploads ledger.json as a prepared checkpoint before any write,
then uploads a distinct final checkpoint after confirmed read-back. The ledger holds
request/comment IDs, heads, completion IDs/timestamps, source digests, P1 exceptions,
issue mapping and a hash-linked history of prior final runs.

Readers verify authenticated API artifact metadata, SHA-256 archive digest, exact
archive member, run ID, repository, default branch ancestry, event, attempt 1, path,
and byte-identical controller source at the producing revision. They do not trust
PR artifacts or issue-comment JSON. The ledger-producing workflow has no job that
runs PR code. Test jobs cannot supply ledger contents to privileged control.
A final checkpoint may be read while its dispatch-only tail is finishing. Completed
failed controller runs block recovery. Queued/cancelled zero-job runs may be ignored
only after stable explicit job evidence; a skipped action step proves no write for
an earlier pre-write failure. Prepared-without-final after a started action is an
uncertain write, never an automatic retry or count refund.

Retention is 90 days, not indefinite. Earlier artifact expiry/deletion, missing run
history, a controller-source change, history saturation at 1,000 runs, inconsistent
pagination or missing digests blocks. No silent reset. Open PRs spanning those
boundaries need a separately reviewed audit/migration; there is no migration bypass
CLI. This favors safety over availability. Run/artifact deletion by privileged actors
is outside the trustworthy history model and must not be used to defeat the gate.

Enrollment is prospective: PR creation must follow the reviewed activation timestamp,
with no prior Codex summary, receipt or reaction. Existing PRs cannot be backfilled
from mutable summaries. Counting current mutable review objects cannot establish lifetime history. Independent requests are detected and block; independent automatic
integration triggers must be disabled/verified before activation. A missed overwritten
completion or push before completion capture blocks instead of guessing a round.

## Issue handoff

One linked issue per authenticated finding root uses a stable repo/PR/root-ID key.
The issue includes PR/root links, original review/commit, exact reviewed head,
source digest, full finding and an explicit deferred-not-fixed statement. The final
trusted ledger records returned issue IDs. Readers require live open issues, exact
body/title and expected publisher identity. A same-key unmapped issue is a recovery
blocker, not permission to adopt a marker someone copied. Partial creation, uncertain
POST, edited/closed issue, changed finding or stale mapping cannot clear CI.

Repeated events reuse the persisted mapping and do not create duplicate issues.
Cross-head issue rebinding is deliberately not automatic: changed head/evidence
needs reviewed recovery, rather than overwriting an earlier handoff. Resolved roots
already transferred to issues remain part of budget evidence, so native conversation
resolution cannot erase the deferred obligation. There is no automatic thread
resolution, review dismissal, or fake approval. Native conversation/approval blockers
may still require an authorized human or reviewer to act.

## CI and merge

The existing workflow retains exact-SHA checkout, repeated live admission, full
history/duplicate checks, guarded retries, read-only PR tests, isolated reporting,
no push test trigger and asynchronous head/draft/close cancellation. When enabled,
its gate reads the authenticated ledger and chooses clean-review or p2-budget.
The trusted reporter binds success to base SHA and evidence digest as well as head.

Merge is a separate job with contents:write and read-only evidence permissions.
It requires the trusted workflow's completed first-attempt successful run, expected
successful jobs, matching status origin/run URL/base/evidence, unchanged head,
current issue handoff, native review requirements and CLEAN native merge state.
It re-collects immediately before a normal squash merge with an expected SHA. No
force/admin bypass or protection alteration. Squash must be available under existing
repository policy. Merge queues are unsupported and block activation for auto-merge.

Automatic merge excludes AGENTS.md, .github/, .agents/, .codex/ and tests/ci/, including
renames from those paths. Those changes require parent review/manual merge. No input
can override this restriction. The CI success is historical test evidence, not an
atomic lock on review state. Head CAS protects against head swaps; review revocation
or base movement after the final read can still race the merge API. GitHub native
protections remain the final guard. A base change invalidates the CI evidence; existing
same-head success deduplication may then require owner-guided retesting/new review.

## Current/desired external settings and permissions

Current CyberSOC Codex trigger/security settings and effective token policy are unknown.
Repository instructions cannot configure or suppress an external integration.

Desired: disable independent automatic Code Review triggers for CyberSOC, retain an
operational @codex review route, and verify exactly one controller request produces
one completion. Preserve configured Security Review coverage, including its automatic
association with Code Review if used. Readiness now wakes the designated requester,
not an independent integration trigger. Do not change other repositories or broader
personal preferences as a shortcut. Settings must be inspected by an authorized owner
before any change; if no CyberSOC-scoped option exists, stop and report that scope limit.

| Job/action | Permissions |
| --- | --- |
| Wake relay | contents:read, actions:write |
| Collector/issue publisher | contents:read, pull-requests:read, issues:write, actions:write, statuses:read (CI result verification) |
| Existing launch/admit | unchanged: contents/pull-requests/issues read, actions write |
| Repeat CI clearance | contents/pull-requests/issues read, statuses write; adds actions:read for ledger verification |
| PR tests | unchanged contents:read only |
| CI reporter | unchanged statuses:write only |
| Normal merge | contents:write; pull-requests/issues/actions/statuses read |
| Ledger artifacts | existing Actions runtime identity; no id-token:write or new secret |

Issue/merge writes are NOT authorized by this installation; activation needs separate approval. Additional read scopes are itemized
above for review; no external token defaults are expanded. Denied Actions settings
and workflow-list endpoints were NOT retried. Publishing source is not proof hosted
permissions, artifact access or the Codex comment trigger work. A GITHUB_TOKEN-authored
comment must be demonstrated to trigger the external Codex integration; if it does
not, stop rather than create a PAT/App credential or broaden permissions.

## First rollout and future unattended operation

1. Parent reviews this separate draft and offline evidence. Keep activation false.
   Bootstrap uses existing clean-review rules; do not enroll the controller PR or existing PRs
   with fabricated counts. Parent handles manual merge after appropriate review.
2. Owner inspects CyberSOC-scoped Codex settings and existing merge/security policy,
   obtains separate approval for any scoped trigger change, and records actual values. No
   setting is changed by these files. Prior Actions denials remain unresolved.
3. Through a separately reviewed activation change set enabled=true, a future
   activation_after timestamp, independent_code_triggers_disabled=true, verified
   security_review_required, native_merge_policy_verified=true and actual
   merge_queue_required=false only if no queue is required. Do not backdate the epoch.
4. Use a new disposable PR created after activation. Verify Void/draft handling,
   sole-request triggering, completion capture, duplicate wakes, P0/P1/security
   rejection, three P2 rounds, issue read-back, exact-head CI, and manual inspection
   of native merge eligibility. No production or protection changes. Do not merge
   the test fixture; explicitly authorize a separate normal-code merge trial if needed.
5. Enable unattended use only after hosted evidence confirms effective permissions,
   external reviewer delivery, artifact digest/history access and merge protections.
   Retain audit links. A denial or uncertain write stops the workflow for owner review.
   Subsequent ordinary ready PRs enroll prospectively; existing unknown-history PRs
   continue under the prior clean-review/manual process until audited migration.

Offline tests mock API/CLI boundaries and do not validate hosted delivery or eventual
consistency. Run: python3 -m unittest discover -s tests/ci -v and actionlint on all
workflows. No activation, hosted operation or automatic merge is claimed by this PR.
