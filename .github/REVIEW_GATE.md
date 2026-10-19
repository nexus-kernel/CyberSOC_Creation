# CyberSOC draft-first reviewed CI

Applied to `nexus-kernel/CyberSOC_Creation` (repository ID 1425003650), main
`16dda0245d6dd17cfb8fda90ff941e8c55746eeb`. See
[port provenance and naming audit](../docs/REVIEW_WORKFLOW_MIGRATION.md).
The active path remains clean exact-head clearance. The optional budget stays disabled.
Tests run CyberSOC's actual Node reporting/privacy suites, mocked PowerShell collector,
monthly trend/vulnerability import/report/worklist suites, and Python controller regressions.
No assessment/deployment application from the template source is copied.

`reviewed-ci.yml` remains inert, with empty permissions and an always-skipped job.
Both its historical runs and `review-clearance.yml` history are checked for duplicates,
prior success, reruns and incomplete history. Do not delete this history on migration.
The native clean-review rule remains APPROVED or explicit null; null is not proof
of human approval. Native required approvals/protections still apply separately.

## Sequence and gate

1. Publish a draft only after separate authorization. Void reviews that draft.
2. Resolve Void findings, then mark ready so the existing Codex integration reviews
   the final head. These workflows do not configure integrations, invoke reviewers,
   post comments, change draft state, resolve threads, or merge. Persistent draft
   automation is handled separately by the parent.
3. A completed authenticated Codex summary event checks live state. Running summaries
   and human comments do not allocate a runner. Completed does not mean clean.
4. Clearance launches this same controller on the trusted default branch, passing
   PR number and full SHA as data. The execution phase independently admits the
   run using live review and complete run history, then repeats live clearance.
5. Only successful admission and clearance allow tests of the exact verified SHA.
   The separate trusted reporter publishes `Reviewed CI` on that SHA.

Clearance requires an open, explicitly non-draft, same-repository, mergeable PR;
exactly one summary from `chatgpt-codex-connector[bot]`, ID `199175422`, type `Bot`;
completed Code Review and any listed Security Review for the current head; and
an authenticated thumbs-up strictly after Code Review completion. Short commit
IDs are resolved through GitHub to the full SHA. Reaction records allow the
pinned identity's documented `User` or `Bot` type, never arbitrary users.

Request-comment reactions must also be later than the request's latest edit;
missing, invalid, or same-second ordering cannot establish freshness. Security-only
and mixed requests cannot sign off Code Review. New running reactions and newer
Codex reviews block. Every unresolved thread (including outdated ones), outstanding
changes request, or unsatisfied native review decision blocks. All relevant API
pages are read. Head/base races, unknown mergeability, incomplete evidence and API
errors fail closed. GraphQL head/base checks and a final REST read detect movement
during evidence collection. This parser deliberately accepts a narrow recorded
summary format; changed upstream formats can block until independently reviewed.

Independent adversarial review added fail-closed checks for missing REST pages,
non-boolean GraphQL pagination, timezone-less timestamps, same-second running or
superseding Codex activity, and dismissal of an unrelated later review. A dismissed
review record cannot clear an earlier still-active changes-requested record.

## Trust boundary and proposed runtime permissions

All control checkouts use immutable `github.sha` from the default-branch workflow.
No input or PR ref chooses control code. The test job checks out the verified PR
SHA with no persisted Git credentials. Write-token jobs never execute PR code.
Actions are pinned by full commit SHA. No secrets, credentials, deployment jobs,
or untrusted artifacts are shared with a privileged job.

| Action/job | Proposed GitHub token permissions | Boundary |
| --- | --- | --- |
| Launch/admit controller | contents, pull-requests, issues: read; actions: write | Actions write is needed only to dispatch the trusted controller; read APIs inspect reviews/history. |
| Repeat clearance and pending status | contents, pull-requests, issues: read; statuses: write; actions: read | Trusted checkout only; pending status targets verified head. |
| Offline tests | contents: read | PR code runs here; no write permissions, secrets, or persisted credentials. |
| Final reporter | statuses: write | Inline trusted script; no checkout or PR execution. |
| Cancellation | none | Always-skipped job; workflow concurrency cancels obsolete execution. |

These are proposed workflow declarations, not an applied token-policy expansion.
No external permission changes were made. If policy denies a listed permission,
stop and obtain separate per-action approval; do not add a PAT or widen defaults.
Publishing workflow files later needs repository Contents write and the publisher's
workflow-file authorization; creating a draft or marking ready needs Pull requests
write. Merge needs separate merge authorization and all existing requirements.
Any change to integration, Actions policy, or branch protection requires separate
owner authorization; it is not part of this patch.

## Deduplication, retries, cancellation and limits

Automatic events use `--once`; manual PR-number requests use `--retry-failed`.
An execution request containing SHA/mode still must pass `--admit-run`. Admission
identifies the current controller run by GitHub run ID and workflow ref, not supplied
input. It must appear as in_progress in complete matching history. The invocation
holding the serialized execution slot wins independently of run-ID order.
Queued/pending/requested runs with null conclusions and completed cancelled runs
are candidates for exclusion only if the first-attempt jobs endpoint proves a
complete, explicit zero-job collection. This includes pending duplicates replaced
and cancelled by a third or subsequent delivery, as well as older unstarted runs
when GitHub schedules out of ID order. Cancellation alone is never proof.

Run metadata is fetched before and after job evidence and must match history
(identity, attempt, event, branch, title, status, conclusion). Job pages require
stable totals, unique job IDs, correct run/attempt identity and exact counts.
Missing/malformed/partial evidence or API errors block admission. Any job record,
even skipped or apparently unstarted, retains the run conservatively. Started
cancelled executions therefore remain history: automatic once cannot repeat them;
explicit manual retry may retry the latest completed failure/cancellation/timeout.
Success, in-progress, waiting and unknown states are never candidates for exclusion.
All matching run-attempt and history-completeness checks happen before exclusions.

After the winner finishes, surviving automatic children retain its execution
history and cannot repeat tests even if it failed. Launcher dedup still considers
all runs; this provenance filter applies only to execution admission. Concurrency
remains per PR with cancel-in-progress false. No workflow or permission change is
needed: the jobs API uses existing Actions read capability. The final live review
check still follows admission evidence collection.

This relies on GitHub's authenticated job totals accurately describing the attempt
and on the trusted workflow's serialized concurrency. It is not an atomic API
snapshot. State changes during inspection fail closed and may require a guarded
manual retry; unavailable evidence, timeouts, cancelled winners or infrastructure
failure still prevent an unconditional liveness guarantee. No hosted cancellation
or job-list visibility experiment was performed during this correction.
Any prior success or potentially executing matching run blocks repeats. Manual retry permits only
a latest completed failure, cancellation or timeout. Unknown metadata blocks.
Native reruns are rejected in control, tests and success reporting. Any history
entry with run_attempt other than integer 1 blocks, since later attempts can hide
an earlier success. Use a new reviewed commit if native reruns have made history
ambiguous; never delete history to bypass this guard.

History pages must have stable totals, unique run IDs and complete counts. The
filtered GitHub endpoint's 1,000-result boundary fails closed. This can eventually
block availability; a different complete-history strategy requires a reviewed
change. Dispatch history visibility is not an atomic cross-host lock: do not use
independent publishers. Serialized controller admission is the enforcement point.
Missing/eventually invisible current-run history blocks admission safely.

No push, pull_request test, schedule, or post-merge test path exists. A trusted-base
`pull_request_target` cancellation workflow has no executing job and no token
permissions. It cancels the per-PR execution group on new commits, conversion to
draft, and closure. Reporter interruption can leave pending, never fabricated
success. Skipped control/cancellation jobs are not successful reviewed CI.

Review evidence is a point-in-time API snapshot, not an atomic lock with GitHub.
A push or revocation immediately after the last check can race test startup;
cancellation is asynchronous. The checkout remains pinned to the verified SHA,
never the new unreviewed head. Reviews are not continuously polled after startup;
success describes the tested SHA, not current merge eligibility. Recheck head and
review state before merging. This workflow cannot prevent an authorized writer
from introducing another workflow or protect against privileged administrators;
repository policy is separate and was not modified. Fork PRs fail closed.

In particular, a new PR can add its own `push` or `pull_request` workflow that runs
before Codex review, subject to existing GitHub policy. A writer can also change a
branch's manually dispatched workflow to remove guards. This patch cannot stop
those independent workflows. Its no-pre-review-tests guarantee is scoped to the
installed trusted controller, not all repository Actions execution. No claim of
repository-wide enforcement is made without separately reviewed external controls.

The lightweight trusted controller allocates an Actions runner before clearance
to read review evidence; this consumes Actions time. It does not install PR
dependencies or run fixture/application tests. Those operations run only in the
downstream test job after admission and repeated clearance. If "no CI" means no
Actions jobs at all before sign-off, this design does not meet that stronger
requirement: the review checker would have to run outside Actions.

Review collections can mutate between paginated reads. Final PR reads detect
head/base/state changes, not every reaction deletion, new finding, or revoked
review. Review revocation does not trigger cancellation. A successful status is
historical test evidence; reporting does not revalidate review eligibility. Native
reruns fail closed but can replace prior success with failure, leaving history
ambiguous and blocking later retries. These are availability and snapshot limits.

## Bootstrap and activation runbook (not performed)

1. Review this local patch and offline results. Independently inventory registered
   workflows/external CI publishers through authorized read access. Coordinate any
   conflicting publisher separately; never silently disable it.
2. Parent obtains publication authorization, publishes a topic branch and draft PR,
   and handles Void draft review. Confirm the existing Codex integration is installed
   for this repository and triggers on readiness; do not assume repository files
   configure it. Resolve findings before readiness; do not duplicate requests.
3. Obtain clean Codex review of the final bootstrap head. These new workflows cannot
   run as trusted control until merged into `main`. Use offline results during
   bootstrap. If existing required checks prevent bootstrap, stop for an owner-led
   transition; never forge checks, relax protection, or bypass requirements.
   Existing draft automation must be respected. Bootstrap promotion or an explicit
   review request requires owner authorization after Void review.
   Codex review itself does not depend on this controller being on main. Do not
   automatically promote the bootstrap PR or infer integration settings from files.
4. After separate authorized merge, confirm clearance and cancellation workflows are registered and
   enabled and policy permits the job-specific permissions above. Any enabling or
   policy change is a separate action requiring authorization. Do not activate any
   disabled review-budget controller.
5. On a new same-repository fixture PR, exercise Void draft review, readiness/Codex,
   and fresh clean-head sign-off. Confirm no tests before clearance, the trusted
   workflow revision, exact test checkout SHA, and linked `Reviewed CI` status.
   Exercise draft, stale head, missing/spoofed sign-off, unresolved threads, changes
   requests, cancellation, duplicate suppression and manual failed-run retry.
6. After the hosted checks succeed, the owner may separately consider making
   `Reviewed CI` required. No protection changes are requested or applied here.

For delayed reactions or final thread resolution (neither emits issue_comment),
use Actions → Check Codex review clearance → Run workflow on `main`, providing
only `pr_number`. Leave reviewed_sha empty. This rechecks all live requirements.
Do not use native Re-run jobs. Trusted local read-only preflight, if separately
authorized with an existing authenticated CLI, is:

```sh
python3 .github/scripts/review_gate.py --repo nexus-kernel/CyberSOC_Creation --pr NUMBER
```

Local tests mock APIs and subprocess calls. Hosted delivery, cancellation, run visibility,
integration behavior and effective runtime token permissions require authorized rollout.
