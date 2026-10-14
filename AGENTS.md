# EBR repository work

Work on a topic branch. Open draft PRs when publication is authorized. Void reviews
the draft first; resolve its findings before marking the PR ready. Request Codex
review only after readiness and after the final code changes. Never treat a
completed review with findings as clearance. Obtain a fresh current-head Codex
thumbs-up, resolve all review threads (including outdated threads), and satisfy
outstanding changes requests before requesting reviewed CI.

Use `.github/REVIEW_GATE.md` for CI trust boundaries, retries and bootstrap.
The trusted default-branch controller owns dispatch; never run PR control code
with a write token, forge statuses, relax protections, or use native reruns.
Do not publish, change repository settings, or modify external environments
without authorization. There is deliberately no post-merge/push CI.

Safe local validation:
- `npm ci` using the committed lockfile, then `node --test tests/*.test.cjs`.
- `python3 -m unittest discover -s tests/ci -v` (PyYAML dependency).
- Run all Pester `./tests` with PowerShell 7 and Pester 5.9.1. Require Node first
  so the PowerPoint test cannot silently skip. Treat zero tests, failures, skipped
  or not-run Pester tests as failure.
- Run actionlint and `git diff --check` after workflow changes.

Do not run evidence collection, Azure/Exchange sign-ins, or tenant operations for
CI validation. Unit tests use fixtures and mocks. The safe controls-standard
HTML/PPTX generation can be used as a local smoke test.

## Codex Code Review budget

Request at most three completed Code Review rounds per PR, including the initial
review. New commits do not reset this lifetime count. Before any agent-controlled
request, verify complete authenticated invocation history, including clean rounds
and any active request. Unknown/incomplete history or a running review means stop;
never infer the count from the latest mutable summary, finding count or head SHAs.
At three rounds, do not post another `@codex review` or use readiness to trigger one.
External/manual/integration requests are not suppressed by these instructions.

At the cap, unresolved P0/P1 anywhere in relevant history blocks all deferral.
Unknown priorities, incomplete history and an unreviewed current head also block.
Only remaining P2/P3 Code Review findings may become deduplicated follow-up issues;
Security Review and human approval requirements remain separate and mandatory.
The staged `.github/scripts/review_budget.py` is NOT active CI clearance. Until the
trusted adapter/writer in `.github/REVIEW_BUDGET.md` is approved and deployed, stop
and report the cap/activation blocker; do not fabricate a thumbs-up, resolve threads
just to pass the gate, or request a fourth review. Do not backfill merged PRs.
