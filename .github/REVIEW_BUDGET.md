# Three-round Code Review budget: staged implementation

Status: **agent request policy installed; automated deferral and enforcement are
not activated**. The policy core is `.github/scripts/review_budget.py`, tested in
`tests/ci/test_review_budget.py`. Existing `review_gate.py`, workflow permissions,
dispatch admission, human review requirements and `Reviewed CI` are unchanged.
There is no CLI accepting a user-provided JSON snapshot as clearance.

## Verified requester boundary

Inspected main `e11220d3fa067edbd1138ffe466bf51223f0a87b`, all three tracked
workflows, the gate and repository instructions. There is no in-repository
Codex requester and no `.agents/skills` directory. The controller dispatches CI,
not Code Review. Read-only PR #3 comments show account-authored `@codex review`
requests (including Claude Code-generated comments). The authenticated Codex
summary says opening a PR for review, marking ready and comments trigger reviews.
The mutable summary records only the latest activity, not lifetime invocations.
These observations do not establish control of the external integration or its
settings. A shell read of registered Actions workflows returned `Forbidden`;
external workflow inventory is therefore unverified. No settings were changed.

`AGENTS.md` now directs cooperating agents to stop at three, with initial review
included and no reset on a push. Unknown count means stop too. This cannot prevent
manual comments, other agents ignoring instructions, or external automatic
requests. An absolute maximum needs the actual requester/integration owner to
adopt a common admission controller; no repository CI change can claim that control.

## Reusable policy and evidence contract

The immutable Snapshot is an internal trusted-adapter boundary, not an input
schema for PR artifacts, comments, workflow_dispatch or user files. Its flags
are assertions the adapter must prove from authenticated live APIs. The module
has no network client and is deliberately not imported by the active gate.

The future adapter must prove complete lifetime invocation history from the
initial review onward, including clean reviews with no submitted review/findings,
multiple invocations on one SHA, and reviews on old SHAs. Count Code Review only;
keep Security Review separate. Request comments, GitHub submitted-review counts,
SHA counts and the current edited summary are not a complete invocation ledger.
Use an authoritative provider history API or a durable trusted event ledger with
verified enrollment before the initial review, gap detection and reconciliation.
If neither exists, existing PRs cannot use capped deferral. Do not infer zero.

Each Round uses a provider invocation ID. Duplicate, unknown, running or
incomplete invocations block. Before an actual controlled request, serialize by
repository/PR, persist a reservation and read back its identity before sending;
a pending or uncertain request consumes an in-flight slot and blocks another
request until reconciled. The pure request_allowed predicate alone is not an
atomic request allocator. Completed count >= 3 forbids a new request, even on a
new head. If the third completed review was for an older head, stop for an owner
resolution: neither an unreviewed-head waiver nor a fourth review is authorized.

Collect every relevant review, inline thread (including outdated threads), review
body and summary finding. Authenticate provider authors. Parse only known
priority formats; unknown severity or unclassified content blocks. Do not treat
a dismissed review or outdated location as a resolved finding. Prove resolutions
from their authoritative state. The adapter must preserve a finding's stable ID
and source URL, and canonicalize repeated appearances without losing the highest
severity or an unresolved state. Human findings and changes requests must also be
accounted for; Code Review deferral cannot waive them. A single unresolved P0/P1
anywhere blocks *all* issue creation, even for an unrelated P2.

The evidence revision is a digest of the entire canonical state, including head,
base, every invocation, summaries, reactions, priorities, resolutions, native
review decisions, and human/Security Review requirements. Every page must be
complete and consistent; pagination/API errors and snapshot changes block.
Security clearance requires a completed current-head security invocation and its
existing independent clean-signoff requirements. Security findings cannot be
waived by the Code Review cap.

## Issue transaction and truthful outcome

`defer` implements the staged writer protocol through injected read, inventory and
create transports. It validates all candidates before any write, rechecks live
state before each mutation and after the batch, and returns `capped-deferral`
with the exact reviewed head and issue numbers. It never emits Codex approval,
posts a reaction, resolves a thread or writes a commit status.

A future writer must run only from immutable trusted default-branch code, under
an exclusive per-PR lock shared by every writer/requester. Give only that isolated
job issues:write; no PR checkout, PR imports, PR-supplied executable artifacts,
credential persistence or issue-write token in test jobs. No such grant or job
is included in this change. The adapter must reject closed/merged/draft PRs.

Read all issues in **all states**, without relying on capped/eventually-consistent
search. Reuse a single match by hashed stable finding identity OR exact source
URL, even when closed. Do not reopen it automatically. Existing issues #4/#5
illustrate source-link-only compatibility, not permission to backfill PR #3.
Duplicate matches, malformed/incomplete inventories or uncertain writes block.
After any POST, including an exception/lost response, read the complete inventory
back. Never blindly retry an uncertain POST, including across process restarts:
the future durable ledger must persist a write intent before POST and reconcile
it before another attempt. Disable transport automatic POST retries. GitHub
issue creation has no atomic uniqueness key; without a single writer/lock and
uncertain-intent journal, do not activate. A post-write revocation may leave a
valid tracking issue but produces no clearance; retain it for dedup/reconciliation.

## Activation and reuse gates

This draft deliberately stops before a security-sensitive permission expansion.
Approval is needed for an isolated issues:write job and a new CI admission basis;
implementation of a trusted provider/ledger adapter and durable transaction
journal is also required. Merely approving a permission cannot supply missing
history or enforce a cap on an uncontrolled external requester.

Before activation, independent review must validate the adapter's authenticated
completeness guarantees, lifetime reservation behavior, issue inventory,
uncertain-intent recovery and hosted concurrency. Then add a distinct
`capped-deferral` gate route that re-verifies linked issues and all nondeferrable
requirements on every check, dispatch, --admit-run and downstream clearance.
Bind it to exact head/base/evidence and the existing complete run-history/retry
rules. Keep human approvals, unresolved nondeferred threads, changes requests,
Security Review, trusted-default execution, cancellation and rerun restrictions.
Never synthesize a Codex thumbs-up or silently make the current clean-review gate
accept a completed review with findings. A label/input alone is not authority.

For the other five repositories: inventory their actual requester, gate, separate
Security Review rules, workflows and instructions first. Reuse this pure policy
and adversarial tests, not EBR-specific permissions or activation assumptions.
No report grading, PR #3 discussion, repository settings, credentials, branch
protections, merges or deployments are part of this change.

## Preparation validation (2026-10-14)

- `npm ci --cache /tmp/ebr-npm-cache`: passed with committed lockfile.
- `node --test tests/*.test.cjs`: 82 passed, 0 failed, 1 existing optional
  local-evidence-pack test skipped (83 total). No customer evidence was fetched.
- `python3 -m unittest discover -s tests/ci -v`: 115 passed, including 13 new
  budget tests and all 102 existing gate/admission/workflow regressions.
- actionlint 1.7.7 and `git diff --check`: passed; workflows are unchanged.
- Independent review of the inactive scope: no remaining findings after fixing
  source-URL punctuation dedup and adding Markdown/HTML-link regression cases.
- Required Pester suite: **blocked, not passed**. PowerShell 7.4.7 runs with
  writable temporary XDG directories and Node is present, but Pester 5.9.1 was
  unavailable. Both PowerShell Gallery API and CDN package downloads returned
  HTTP 403. No Pester tests ran. Rerun all tests using the AGENTS.md zero-failure,
  zero-skip, nonzero-test criteria in a provisioned environment before readiness.

This is an independently reviewed draft preparation, not a production rollout or
complete automated implementation. Hosted control/permissions/race behavior has
not been validated, and the documented adapter/journal/admission work remains.
