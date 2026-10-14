# EBR reviewed CI

## PR published; trusted-default bootstrap is still required

Baseline: `nexus-kernel/EBR_Creation` main at
`1d451388fcbd1544bbea9dfec7109af62db8daf1`. The tracked tree contained no
`.github` workflows, AGENTS.md or `.agents` skills. No legacy workflow ID or
external publisher is assumed. Workflow code is published on PR #2, but no
repository settings or protections were changed. Before activation, inventory registered Actions workflows and
external publishers with an authorized read-only API: the shell API was blocked
in this preparation environment, so repository-tree inventory is the verified
scope. If an external publisher exists, coordinate its retirement separately.

Read-only references inspected:
- PowerShell_Vuln_Assess default `1c5b639adcd77293647a38be6964722163326731`.
- Rapid7_Deployment PR8 head `5013e956fb8374d6072260eaa65a78de34e10c82`.
- sentinel_config PR20 head `c2e6f0c2e071d3899a59cc239c4a39730e3cd2cf`.

PowerShell's default currently has push-to-main CI. **EBR deliberately does not
run post-merge or push CI.** EBR executes CI through `review-clearance.yml`;
`reviewed-ci.yml` is now an inert compatibility entry point. No legacy
migration fixtures or app-specific Az/Chromium/analyzer dependencies were copied.

## Review sequence and clearance

Void reviews draft PRs first. Resolve its findings, mark ready, then request
Codex review of the final head. AGENTS.md records this sequence; these workflows
do not configure or invoke Void/Codex integrations, post review requests, change
readiness, or merge PRs. The assistant draft-first automation was separately
enabled for EBR, and PR #2 was promoted by the review process. Publication of
additional fixes does not imply sign-off for the new head.

The controller requires an open, non-draft, same-repository, mergeable PR;
exactly one Codex summary authenticated by login, Bot type and user ID 199175422;
completed Code Review (and any Security Review) for the current full SHA; and a
fresh authenticated Codex thumbs-up after Code Review completion. Abbreviated
SHAs are resolved by GitHub. Human reactions, stale reviews and security-only or
mixed request reactions cannot sign off Code Review. New running-review reactions
or newer Codex findings block clearance.

Request-comment thumbs-up reactions must be strictly later than the comment's
latest `updated_at`, with valid timezone-aware `created_at`/`updated_at` and
`updated_at >= created_at`. Missing or malformed dates cannot supply sign-off;
there is no fallback from a missing edit time to creation time. Equal-second
reactions fail closed, including fractional timestamps in the same second.
Editing an unrelated comment to add `@codex review` therefore cannot reuse its
older thumbs-up. Eyes reactions remain blockers even when the request was edited
later or its revision dates are invalid. PR-level reactions retain their existing
current-SHA and review-completion requirements. This addresses the
[request-edit freshness finding](https://github.com/nexus-kernel/Void_Probably_Broken/pull/5#discussion_r4271261997).

Every comments/reactions/reviews/thread page is read. All unresolved threads,
including outdated ones, block. Changes requests remain effective across later
comment-only reviews. Native reviewDecision must be APPROVED or null. Unknown
mergeability, malformed data, missing evidence and API errors fail closed.
GraphQL checks head/base on every page; a final REST read checks them again along
with ready/open state. Another full exact-SHA check follows the dispatch history
lookup, and the trusted CI clearance job checks again before testing.

## Trust and permissions

`review-clearance.yml` owns both request and execution phases. Initial completed
bot-summary comments or manual PR-number requests check live review and run
history, then dispatch this same trusted default-branch workflow with the exact
reviewed SHA and guarded mode as data. Human comments/running summaries allocate
no runner. Every control checkout uses immutable `github.sha`, never PR code.

An execution request (including one manually supplying the internal SHA/mode)
must pass `--admit-run`: current-head live review, complete history for **both**
the previous `reviewed-ci.yml` identity and the controller identity, and another
exact-SHA review check after history. Only the current run, identified by GitHub's
immutable run ID and trusted workflow ref, is excluded from active-run detection.
It must be present under the controller identity with the expected PR/SHA title,
branch/event and active state. Missing/eventually-invisible history fails closed.
Inputs cannot choose the run ID to exclude. Unknown modes and unguarded CLI
dispatch are rejected. Admission emits no test SHA on failure.

A separate downstream clearance job still repeats live review before setting a
pending status. Tests and reporting depend on successful admission and clearance.
The old downstream fresh-review check already blocked stale sign-off; the direct
workflow defect bypassed **history/retry admission**, not that live-review check.
`reviewed-ci.yml` now has empty permissions, no concurrency and an always-skipped
job: direct invocation cannot run tests, cancel admitted runs or post a status.
Existing history is retained for deduplication; no workflow ID or disable-setting
interlock is invented.

Job permissions are unchanged by consolidation: the trusted controller has
contents/pull-requests/issues read plus Actions write; downstream clearance has
contents/pull-requests/issues read plus statuses write; tests have only contents
read and no persisted credentials; the isolated reporter has only statuses write
and never checks out PR code. No token scope, credential or repository setting
was added. Tests still run npm ci, all Node/Pester suites and gate regressions.
Native reruns fail admission and the test step; reporting cannot mark a rerun
successful.

Request and execution phases use separate per-PR concurrency groups with
cancel-in-progress false. Direct execution cannot preempt an active admitted run.
Execution keeps the `reviewed-ci-<PR>` group used by runner-free cancellation.

`cancel-ci.yml` uses trusted-base `pull_request_target` configuration with empty
permissions and an always-skipped job. Matching concurrency cancels reviewed CI
on synchronize, converted_to_draft and closed without allocating a runner. It
never executes PR code. Cancellation can leave an obsolete status pending if the
reporter cannot start; pending is not success. Review revocation after preflight
is not continuously polled. Status success describes the tested SHA and does not
replace native merge/review requirements.

## Retries

After bootstrap, manually run `review-clearance.yml` on main with `pr_number`.
The event selects `--retry-failed`; automatic issue comments select `--once`.
Unknown event types fail closed. Automatic events never repeat a matching PR/SHA.
Manual requests allow the first run, or retry a latest completed failure,
cancellation or timeout. Any active matching run (including queued/waiting runs
on later pages) prevents another dispatch. **Any prior matching success** prevents
another test run, even if a newer direct admission was rejected and concluded
failure. This prevents denied requests from laundering a prior success into a
retryable latest failure. Both automatic/manual execution recheck these guards.
Unknown statuses/conclusions cannot authorize retry. Before either guarded mode
can dispatch, every history page must report the same nonnegative integer
`total_count`, every run must have a unique positive integer ID and classifiable
identity, and the returned run count must equal that total. Missing, malformed,
duplicated or inconsistent history fails closed. Because GitHub caps this
[event/branch-filtered endpoint](https://docs.github.com/en/rest/actions/workflow-runs#list-workflow-runs-for-a-workflow)
at 1,000 results, a total of **1,000 or more in either workflow history blocks
both launch and admission in both modes**, even
when all returned pages appear internally consistent. This intentionally trades
availability at the boundary for duplicate protection; do not delete run history
or use bare dispatch to bypass it. A future completeness-preserving retrieval
strategy needs separate implementation and validation. All review checks still
apply. A reaction/thread resolution arriving after the short sign-off wait needs
a manual clearance request: those changes are not issue-comment events.

Read-only inspection from trusted control code:

```bash
python3 .github/scripts/review_gate.py --repo nexus-kernel/EBR_Creation --pr 123
```

The guarded dispatch CLI adds `--dispatch --retry-failed` (manual) or
`--dispatch --once` (automatic). Bare `--dispatch` is rejected. The internal
`--admit-run` route requires a full expected SHA, a guarded mode and authentic
controller runtime context. It never dispatches another run. Do not run an
independent publisher. Dedup depends
on Actions run visibility and is not an atomic cross-host lock.

## Remaining activation steps

1. The saved cloud environment and PR #2 are published. Local application and
   control tests pass. The current changed head still needs independent review.
2. Follow the established Void/Codex review process. These new workflows cannot
   bootstrap themselves as trusted control code until they reach main. Use local results for bootstrap; if native
   required checks block it, the owner must arrange an explicit transition.
   Never forge statuses or bypass protections.
3. After reviewed, authorized merge, verify the controller and cancellation
   workflows are enabled; keep the compatibility entry point inert.
   Request clearance for a genuinely signed-off current PR. Confirm the trusted
   workflow SHA, exact tested SHA, suites, and status on that SHA. Exercise
   draft/stale/no-signoff/changes-requested/unresolved rejection and cancellation.
4. Validate manual failed/cancelled/timed-out retry, automatic dedup, active-run
   suppression and native rerun rejection in hosted Actions. Only after observing
   delivery should the owner consider mapping a required check to `Reviewed CI`.
   No protection/settings changes are included in this preparation.

Tests model GitHub responses locally; hosted event delivery, run-list visibility,
permissions, cancellation and integration behavior remain unverified until rollout.
