# EBR reviewed CI

## Prepared locally; bootstrap is still required

Baseline: `nexus-kernel/EBR_Creation` main at
`1d451388fcbd1544bbea9dfec7109af62db8daf1`. The tracked tree contained no
`.github` workflows, AGENTS.md or `.agents` skills. No legacy workflow ID or
external publisher is assumed, and no workflow/settings/protection changes were
made remotely. Before publication, inventory registered Actions workflows and
external publishers with an authorized read-only API: the shell API was blocked
in this preparation environment, so repository-tree inventory is the verified
scope. If an external publisher exists, coordinate its retirement separately.

Read-only references inspected:
- PowerShell_Vuln_Assess default `1c5b639adcd77293647a38be6964722163326731`.
- Rapid7_Deployment PR8 head `5013e956fb8374d6072260eaa65a78de34e10c82`.
- sentinel_config PR20 head `c2e6f0c2e071d3899a59cc239c4a39730e3cd2cf`.

PowerShell's default currently has push-to-main CI. **EBR deliberately does not
run post-merge or push CI.** EBR uses a new `reviewed-ci.yml` identity. No legacy
migration fixtures or app-specific Az/Chromium/analyzer dependencies were copied.

## Review sequence and clearance

Void reviews draft PRs first. Resolve its findings, mark ready, then request
Codex review of the final head. AGENTS.md records this sequence; these workflows
do not configure or invoke Void/Codex integrations, post review requests, change
readiness, or merge PRs. Configure their integration preferences separately when
publication is authorized; draft-first process is not proof of a Void review.

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

`review-clearance.yml` runs only on the default branch for authenticated completed
bot-summary comments or an explicit manual PR-number request. Ordinary comments
and running summaries allocate no runner. It checks out the workflow's immutable
`github.sha`, never PR code, with no persisted credentials. Only this controller
has Actions write permission. Per-PR concurrency serializes requests without
cancelling a dispatch in the middle of its POST.

`reviewed-ci.yml` is dispatch-only, executing trusted default-branch control code.
Its clearance job has review read permissions and status write permission. The
separate test job checks out only the verified SHA with contents: read, no secrets
and no persisted credentials. It runs npm ci, every Node report test, gate tests,
and all Pester tests. A separate status reporter never checks out PR code and
reports `Reviewed CI` success only when clearance and tests succeed on attempt 1.
Native reruns fail before test execution; request new clearance for retries.

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
on later pages) prevents another dispatch; latest success is not repeated.
Unknown statuses/conclusions cannot authorize retry. All review checks still
apply. A reaction/thread resolution arriving after the short sign-off wait needs
a manual clearance request: those changes are not issue-comment events.

Read-only inspection from trusted control code:

```bash
python3 .github/scripts/review_gate.py --repo nexus-kernel/EBR_Creation --pr 123
```

The guarded dispatch CLI adds `--dispatch --retry-failed` (manual) or
`--dispatch --once` (automatic). The reference's low-level bare `--dispatch`
performs fresh clearance but has no duplicate suppression; the workflow never
uses it. Use only the guarded modes, and no independent publisher. Dedup depends
on Actions run visibility and is not an atomic cross-host lock.

## Publication steps (not performed)

1. Publish the saved cloud environment after adding the dependencies in
   `docs/DEVELOPMENT.md`; the full Pester suite now passes via official source setup. Recheck main and review
   the local diff, including workflow/control changes, before any remote write.
2. With publication authorization, publish a draft PR; follow Void-first then
   ready/Codex review. These new workflows cannot bootstrap themselves as trusted
   control code until they reach main. Use local results for bootstrap; if native
   required checks block it, the owner must arrange an explicit transition.
   Never forge statuses or bypass protections.
3. After reviewed merge, verify all three new workflow identities are enabled.
   Request clearance for a genuinely signed-off current PR. Confirm the trusted
   workflow SHA, exact tested SHA, suites, and status on that SHA. Exercise
   draft/stale/no-signoff/changes-requested/unresolved rejection and cancellation.
4. Validate manual failed/cancelled/timed-out retry, automatic dedup, active-run
   suppression and native rerun rejection in hosted Actions. Only after observing
   delivery should the owner consider mapping a required check to `Reviewed CI`.
   No protection/settings changes are included in this preparation.

Tests model GitHub responses locally; hosted event delivery, run-list visibility,
permissions, cancellation and integration behavior remain unverified until rollout.
