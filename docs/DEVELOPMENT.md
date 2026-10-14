# Development and cloud environment

Use Linux, PowerShell 7, Pester 5.9.1, Node 24 LTS (application supports Node 18+),
Python 3.10+ (3.12 recommended), npm, Git and GitHub CLI. The gate uses Python's
standard library and gh; workflow regression tests additionally need
`.github/review-gate-requirements.txt` (PyYAML 6.0.3). actionlint 1.7.7 was used
for local workflow lint. Hosted CI uses Ubuntu 24.04 for application tests.

The git checkout does not bundle node_modules. Always use `npm ci` from the
committed lockfile. No Azure CLI, Exchange module, Az module, browser or analyzer
is needed for these mocked local suites. Do not run evidence collection or tenant
sign-ins to validate the repository.

## Saved cloud environment recommendation

- Repository: nexus-kernel/EBR_Creation; base branch: main; working directory:
  `/workspace/EBR_Creation`.
- Preinstall a supported PowerShell 7 Linux build and Node 24, plus Python 3.12,
  npm, gh and Git in the environment image. PowerShell must be on PATH.
- Setup command: `bash .codex/setup.sh`. It installs locked npm dependencies,
  a local Python virtual environment and pinned Pester. It fails on missing tools.
- Allow dependency downloads during setup from registry.npmjs.org, pypi.org,
  files.pythonhosted.org and powershellgallery.com / www.powershellgallery.com
  plus its package CDN redirects. PowerShell release assets and actionlint binaries
  may instead be preinstalled by the image owner. Do not disable TLS verification.
- Keep npm cache and XDG cache/config/data paths writable. The setup uses
  `/workspace/EBR_Creation/.dev-cache`; preserve these XDG values during tests:
  `XDG_CACHE_HOME=$PWD/.dev-cache/cache`,
  `XDG_CONFIG_HOME=$PWD/.dev-cache/config`,
  `XDG_DATA_HOME=$PWD/.dev-cache/data`.
- Use `.venv/bin/python` for local gate tests. Application and gate unit tests need
  no credentials or network after setup. Live controller calls require authorized
  GitHub API access only in the trusted control environment; do not add tokens to
  this repository or cloud setup script. Hosted Actions uses its job-scoped token.

## Validation commands

```bash
npm ci
node --test tests/*.test.cjs
.venv/bin/python -m unittest discover -s tests/ci -v
actionlint
git diff --check
```

In PowerShell, with Node already on PATH:

```powershell
Get-Command node -ErrorAction Stop | Out-Null
Import-Module Pester -RequiredVersion 5.9.1 -ErrorAction Stop
$config = New-PesterConfiguration
$config.Run.Path = './tests'
$config.Run.PassThru = $true
$result = Invoke-Pester -Configuration $config
if ($result.TotalCount -eq 0 -or $result.Result -ne 'Passed' -or
    $result.SkippedCount -gt 0 -or $result.NotRunCount -gt 0) { throw 'Pester failed or skipped tests.' }
```

Optional safe smoke test (writes only local HTML/PPTX):
`pwsh ./New-EbrControlsStandard.ps1 -OutputPath /tmp/ebr-install-check/standard.html`.
The Node suite intentionally skips its real-evidence-pack comparison when no local
packs exist. Do not add client data merely to remove that optional skip.

## Verified standalone setup for this saved environment

The contents of [.codex/setup-cloud.sh](../.codex/setup-cloud.sh) can be pasted
verbatim into the saved environment's setup-script field **before publication**.
It is self-contained and works with the existing main checkout; it does not need
other new repository files. With this prepared branch present, the equivalent is:

```bash
bash /workspace/EBR_Creation/.codex/setup-cloud.sh
```

Base-image prerequisites are Linux x64, Node 18+ (24 LTS recommended), npm,
Python 3.10+ with venv, Git, gh, curl and tar. The script installs portable
PowerShell 7.4.6 and .NET SDK 8.0.408 only if their executables are absent, then
builds Pester 5.9.1 using upstream's supported build and lockfiles. Those runtime
pins reproduce this validation; a maintained image can supply its supported
PowerShell 7/.NET 8 builds instead. All installs/caches stay under `.dev-cache`
and `.venv`; no credentials, system package changes or live tenant calls occur.

Only the following dependency hosts were needed for this source-install route:
`github.com`, `release-assets.githubusercontent.com`, `builds.dotnet.microsoft.com`,
`api.nuget.org`, `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`.
Use the existing permitted access; do not relax a denial or enable unrestricted
networking. The source route does not call PowerShell Gallery. After setup,
application/gate tests need no network. The registered-workflow inventory is a
separate authorized GitHub API read and is not needed to run local tests.

Persist these environment variables in the saved environment (setup-shell exports
alone do not carry into a fresh shell):

```text
PATH=/workspace/EBR_Creation/.dev-cache/tools/pwsh:/workspace/EBR_Creation/.dev-cache/tools/dotnet:<existing PATH>
XDG_CACHE_HOME=/workspace/EBR_Creation/.dev-cache/cache
XDG_CONFIG_HOME=/workspace/EBR_Creation/.dev-cache/config
XDG_DATA_HOME=/workspace/EBR_Creation/.dev-cache/data
```

`<existing PATH>` means retain the image's actual PATH, not that literal text.
Alternatively export those three XDG variables and prepend the two tool paths in
each test shell. Use `.venv/bin/python` for the Python tests. No tokens are needed.

When PowerShell/.NET already exist, the smaller repository setup is
`PESTER_INSTALL=source bash .codex/setup.sh`. Its default Gallery mode reuses an
already installed Pester 5.9.1 and does not download it again. Source mode is an
explicit choice, not an automatic response to a denied Gallery request.

## Installation provenance and local results

On 2026-10-14 the image provided Node 24.19.0, npm 11.9.0, Python 3.12.14,
gh 2.46.0 and PyYAML 6.0.3, but no PowerShell/Pester/actionlint. Gallery metadata,
package and CDN downloads returned HTTP 403; no proxy or access rules were changed.
No reusable Pester cache was found in the accessible workspace/shared/tool paths.

Official upstream source installation succeeded:
- Pester tag 5.9.1 resolves to `81e59ad383579f957bcc3e0faf4085461b189032`.
  Its [CONTRIBUTING.md](https://github.com/pester/Pester/blob/81e59ad383579f957bcc3e0faf4085461b189032/CONTRIBUTING.md)
  documents `build.ps1 -Clean` and importing `bin/Pester.psd1`; the build also used
  upstream-supported `-Inline -LockedRestore`. No upstream code was patched.
- Official dotnet/install-scripts commit
  `e5cf1dd2d1540ed05ac84f8eb8c5cdec2807621e` installed SDK 8.0.408 from
  `builds.dotnet.microsoft.com`. Both target assemblies built with zero errors.
- Portable PowerShell 7.4.6 came from the official PowerShell GitHub release.
- The installed workspace module imports as Pester 5.9.1; provenance is written
  to `.dev-cache/pester-provenance.txt`.

Full source setup, default setup reusing Pester, and the standalone cloud setup
were run successfully. All 219 Pester tests passed with zero failures, skips,
inconclusive or not-run tests, including the Node-dependent PowerPoint test.
The 77 gate/permission/retry/request-freshness tests, actionlint 1.7.7, shell syntax, PowerShell
parsing and diff checks passed. The controls-standard smoke test produced both
HTML and PPTX without signing in.

The ordinary Node run passed 65 tests and skipped one optional real-evidence-pack
comparison because no `EBR-Evidence_*/03-security-report.html` existed. A synthetic
fixture exercised that test too: 66 passed, zero skips. This is synthetic coverage,
not validation against real customer packs. Reproduce without client data:

```bash
# Require that this destination does not already exist.
test ! -e EBR-Evidence_synthetic-validation
cp -R tests/fixtures/offline-pack EBR-Evidence_synthetic-validation
pwsh -NoProfile -File ./New-EbrSecurityReport.ps1 -EvidencePath ./EBR-Evidence_synthetic-validation -SkipDeck
node --test tests/*.test.cjs
# Remove only the temporary synthetic copy created above after inspecting results.
rm -rf -- EBR-Evidence_synthetic-validation
```

The current workspace is adequate for full local validation using these installed
paths. The saved environment's published configuration is unchanged: paste the
setup and persist the variables before relying on it in a new session. Shell
`gh api` still returns Forbidden for the registered Actions workflow inventory;
the connector exposes no callable inventory action. Git read-only checks verify
main and the absence of tracked workflows at baseline, but do not prove that no
historical workflow registration or external publisher exists. Hosted rollout
and registered-inventory checks remain outstanding.

The existing MANIFEST.sha256 is a release-package manifest; regenerate it as part
of a future packaging task, not as a claim that this development checkout is the
original release bundle.

## Revalidation against the refreshed publication base

Before publication, main advanced to `6d7bcc508787e3b3f49b9a76971db26d2d7104bb`
(PR #1). It was merged locally without conflicts, preserving the tested freshness
fix at `0142fe420b1425f3cc9707a2d2101a1d17fc2ccd`. The combined branch passed
`npm ci`, 77 gate tests, all 238 Pester tests, and all 72 Node tests with the
synthetic evidence fixture; no tests were skipped. Actionlint, shell syntax and
full branch diff whitespace checks also passed. The earlier 219 Pester/66 Node
counts above describe validation before main's additional application tests.

The user reports the replacement saved environment is published successfully.
That is separate from hosted GitHub Actions validation, which has not been run.
The assistant's existing draft-first review automation was separately extended to
EBR and confirmed enabled by the parent session. Native Codex repository review
settings remain unverified. No repository settings were changed by this branch.
