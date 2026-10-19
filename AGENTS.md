# CyberSOC repository work

This repository is the monthly CyberSOC copy of EBR_Creation and follows the same process. README.md describes
how it differs and how EBR fixes are merged in.

Work on a topic branch. Open draft PRs when publication is authorized. Void reviews
the draft first; resolve its findings before marking the PR ready. Readiness should
trigger the existing Codex integration after final changes; do not post a duplicate
review request. Never treat a
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

Do not run evidence collection, Azure/Exchange sign-ins, vulnerability assessments or tenant operations for
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

At the cap, stop and report the blocker. The optional v1.1 controller in
`.github/REVIEW_BUDGET.md` remains disabled and requires separate activation approval.
Its prospective P1 exception and verified P2 handoff are not permission for an agent
to request a fourth round, defer findings, or activate it. Security Review and native
human requirements remain separate. Never infer/reset ledger counts, fabricate a
thumbs-up, or resolve threads solely to pass CI. Workflow/controller/test changes
require independent review and manual authorized merge.
