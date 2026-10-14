# EBR Security Evidence Toolkit v1.14.0

Packaged 2026-10-14.

## Prerequisites

- PowerShell 7.x (Windows PowerShell 5.1 also works).
- Azure CLI 2.50 or later (`brew install azure-cli` or `winget install Microsoft.AzureCLI`).
- Node.js 18 or later, for the PowerPoint editions. Without it the HTML report is still written.
- The ExchangeOnlineManagement module, installed for the current user on the first run unless you pass `-SkipExchange`.

For a git checkout, run `npm ci` using the committed lockfile before generating
PowerPoint files. Release bundles may include node_modules. Developer tests and
cloud environment setup are documented in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md);
reviewed CI and bootstrap are documented in [.github/REVIEW_GATE.md](.github/REVIEW_GATE.md).

## Windows

Files extracted from a downloaded zip are marked as coming from the internet, and PowerShell blocks them under the RemoteSigned policy. Run this once from the extracted folder:

```powershell
Get-ChildItem -Recurse -File | Unblock-File
```

## Check the install

This writes the controls standard as HTML and PPTX without signing in anywhere. Both files appearing means the report assets, Node.js and pptxgenjs all work.

```powershell
pwsh ./New-EbrControlsStandard.ps1 -OutputPath ./install-check/standard.html
```

## Collect evidence

```powershell
pwsh ./Get-EbrSecurityEvidence.ps1 -TenantId <tenant> -SubscriptionId <subscription>
```

Each run writes an evidence pack with the report (`03-security-report.html` and `.pptx`) and the SecOps worklist (`04-secops-worklist.md` and `.csv`). The worklist names client resources and is internal only, so it never goes to the client. Get-EbrSecurityEvidence.README.md covers parameters, permissions and sign-ins.

## Integrity

MANIFEST.sha256 holds the SHA-256 of every other file in this folder. On macOS or Linux, check it with `shasum -a 256 -c MANIFEST.sha256`.