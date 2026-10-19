# CyberSOC review workflow v1.1.0 port

## Scope and source verification

Target only: `nexus-kernel/CyberSOC_Creation`, repository ID **1425003650**,
base main **16dda0245d6dd17cfb8fda90ff941e8c55746eeb**. The initial saved checkout
was stale at 9fbd27d; it was fetched and a new topic branch started from current main.
Read-only inventory found no open PRs, main and `nexus/adoring-newton-bsfpdl` branches,
three inherited workflow files, AGENTS.md and no repository `.agents` directory.
The other branch is untouched. Branch metadata reported protected=false; this is
not a complete ruleset/protection audit. Registered workflow inventory was unsupported
by the connector and shell API requests returned Forbidden. External publishers,
Codex/Void integration settings and effective token policy remain unverified.

The current Library skill resolved `draft-first-reviewed-ci-v1.1.0.zip`
(`libfile_3919e374bbc08191a5730e1834909381`), but its transfer helper failed to
download. The expected ZIP SHA-256
`150cefec7881fa9d00ded4699df3238d18d74e3919fb1de74b41550ca685b0b9`
was therefore **not verified**. The Library quickstart
`libfile_58cdd487f78c8191a3ea29c5a37ddab5` identified the source and transformations.
The explicitly authorized fallback used read-only GitHub files at
`nexus-kernel/mxdr_deployment@5aa4ddb35d4988ecd6d69f0ff2af76298b4a79e4`.
All 19 retrieved source blobs (controllers, workflows, tests, docs and AGENTS)
were verified against the pinned Git tree's blob hashes before adaptation.
[review-template-source.json](../.github/review-template-source.json) records source
SHA-256 values for copied executable/config/test files. This is a direct source port,
not a claim that the unavailable ZIP or generator was executed.

## Explicit transformations and migration

- Bind configuration, gate routing, budget policy, wake relay, GraphQL target and
  fixtures to `nexus-kernel/CyberSOC_Creation`; use main in operational examples.
- Copy the pinned gate/admission hardening and budget artifact controller/tests.
  Remove the incompatible inherited disabled webhook-ledger runtime/store/history
  and its fixtures. No old ledger is enrolled, reset or migrated.
- Preserve CyberSOC's inert `reviewed-ci.yml` and query BOTH its historical runs
  and `review-clearance.yml`. Keep `Reviewed CI`, run-title syntax, workflow paths
  and per-PR concurrency identities stable. Tests cover old success/incomplete history.
- Keep clean native reviewDecision semantics (APPROVED or explicit null), with
  missing/required/changes-requested decisions blocked. Null does not assert human
  approval. Native protections are separate and are not changed.
- Use the target's actual locked npm, Node report/monthly/privacy/deck suites and
  all mocked Pester collector/import/report/worklist suites in the read-only test job,
  alongside Python controller regressions. Preserve pinned Node/Python setup actions,
  Pester 5.9.1, zero/skipped/not-run Pester failure checks, exact-SHA checkout,
  nonpersisted credentials and isolated status reporting. No MXDR application or
  trivial template fixture substitutes for these suites.
- Keep disabled budget configuration: false enabled/independent-trigger/native-policy
  flags; null activation/queue; security review required; three ordinary completions.
  Its staged merge job and P1 exception require separate activation approval.
  `MXDR budget` run-title and `mxdr-budget` artifact/request/finding/concurrency
  strings are compatible protocol names, retained consistently in producers/readers
  and tests. They do not route to another repository. Display name and deferred
  issue label now say CyberSOC.
- Rewrite gate/budget runbooks around this target; remove claims of inherited owner
  approval, source PR deployment and source settings. Readiness should trigger the
  existing Codex integration; agents must not post duplicate requests.

## Naming audit and intentionally retained identifiers

Corrected saved-environment repo/path examples, package/lock name
`cybersoc-creation` (private), IDE module `CyberSOC_Creation.iml`, test job label
(also the job name the disabled budget controller's CI verification expects),
collector query/progress labels and SecOps help. `setup-cloud.sh` now derives its
checkout from its own path, accepts only `CYBERSOC_REPO_DIR`, and verifies the
CyberSOC origin (HTTPS or SSH, with or without `.git`) before any dependency
operation. `EBR_REPO_DIR` is deliberately not an alias. Offline routing tests cover
spaces, explicit override, both origin forms, legacy variable isolation and
wrong-repository rejection. Saved setup commands outside the repository
must be reviewed separately; files do not update the saved environment configuration.

The current main already uses CyberSOC public script names, monthly HTML/PPTX titles
and monthly report entry points; these are retained. Internal `Ebr` functions,
`EbrReport`, `EbrStory`, `EbrCyberSoc`, `Read-EbrCaEvaluation`, the
`report/Get-EbrCaEvaluation.ps1` helper, `script:EbrVersion` and `EbrBaseVersion`
are compatible API/provenance identifiers. Renaming would break PowerShell callers,
script loading, VM/browser bindings and portable upstream fixes. Existing `ebr-*`
Node test filenames remain discoverable by the same glob. Client-export checks
that reject internal Ebr globals stay intact. The packaging filter continues to
reject BOTH CyberSOC-Evidence and EBR-Evidence directories to protect client data.

README's EBR source link/comparison/upstream-fetch instructions, historical EBR
runbook and packaging reference, design lineage, ATMO-MXDR controls and historical
validation notes are truthful provenance, not target routing. MANIFEST.sha256 is
the inherited EBR release manifest (as SETUP.md explains); it is not regenerated
as a release by this workflow port. No EBR repository reads/writes were needed for
the application, and no source repository was mutated.

## Validation and deployment boundary

Local test results are recorded in the draft PR. All suites use synthetic fixtures,
mocked API/CLI calls and local report generation. Node's optional real evidence-pack
comparison may skip without a pack; no customer data is collected to satisfy it.
Dependency installation needs network access, but tests perform no tenant sign-ins,
vulnerability assessment, cloud deployment or live infrastructure operations.

Before working hosted deployment, an authorized owner must verify CyberSOC-scoped
Void draft handling and automatic Codex-on-ready settings, preserve Security Review
coverage, inventory other CI publishers, and confirm effective Actions permissions.
After independent Void/Codex review, a separately authorized merge puts trusted code
on main. The bootstrap PR is left draft; no ready transition, review request, CI
manual dispatch, status fabrication, settings/protection changes or merge is included.
Validate event delivery, exact tested SHA, duplicate rejection, cancellation, retries
and native-rerun rejection on an authorized disposable PR before considering a
required Reviewed CI check. Files alone do not install integration settings.

Optional budget activation is a distinct reviewed change described in
[REVIEW_BUDGET.md](../.github/REVIEW_BUDGET.md): prospective timestamp, repository-scoped
independent Code Review triggers disabled, working controller-authored comment delivery,
verified security/native merge policy and no required queue, artifact/history access,
and hosted three-round/P0/P1/security/P2-handoff tests. Do not use broader personal
settings or create credentials to work around a denial. No webhook automation or
subscription is changed by this port.

### Local results for this port (2026-10-19)

- Locked `npm ci` passed with the workspace npm cache (home cache was unavailable).
- Python 3.12/PyYAML: 178 controller and port regressions passed, no skips.
- Pester 5.9.1/PowerShell 7: 281 passed; zero failed/skipped/inconclusive/not-run.
- Node 24: 183 discovered, 182 passed, one optional real-pack comparison skipped.
  The initial Node invocation lacked pwsh on PATH; the final full run used the
  documented local PowerShell/XDG paths and passed.
- actionlint 1.7.7, shell syntax, Python compilation and staged diff whitespace passed.
- No hosted CI run is claimed. No production credentials or tenant actions used.
- Draft review follow-up (budget CI job name, suffix-less origin, npm-ordered lock):
  Python 179 passed; Node 182 passed with the same optional skip; Pester 281 passed;
  actionlint 1.7.7 and diff whitespace clean.
