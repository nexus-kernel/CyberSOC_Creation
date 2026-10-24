# CyberSOC Monthly Report Toolkit v1.22.0

`Export-CyberSocToolkit.ps1` writes this file into each release zip with the packaging date.

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
pwsh ./New-CyberSocControlsStandard.ps1 -OutputPath ./install-check/standard.html
```

## Collect evidence

```powershell
pwsh ./Get-CyberSocEvidence.ps1 -TenantId <tenant> -SubscriptionId <subscription> -ReportMonth <yyyy-MM> -VulnAssessmentPath <vulnerability assessment run folders>
```

Add `-DefenderEndpointPlan Plan1`, `Plan2`, `Business` or `Mixed` with the plan the Defender portal shows under Settings > Endpoints > Licenses, since no API reads that page. The licensing check also reads the tenant's licenses (Graph LicenseAssignment.Read.All), the Microsoft Entra devices (Graph Device.Read.All) and the Defender for Endpoint devices (Machine.Read and the View Data role). A permission the token lacks makes that read UNAVAILABLE, and what it feeds reads Unknown, never Not licensed. The guest read for change request CR-26 (IA.17-GUESTS) also reads each guest's last sign-in, which needs Graph AuditLog.Read.All and Microsoft Entra ID P1 or P2: without them the guests and their roles are still read, and the last sign-in reads not read. The window is the report month and the two full months before it, the 90-day trend. The report month defaults to the last full month. `-VulnAssessmentPath` imports the monthly Atmosera.VulnAssessment runs of that window for these subscriptions. A pack collected without them takes them later with `Import-CyberSocVulnAssessment.ps1 -EvidencePath <pack> -VulnAssessmentPath <runs>`, then `New-CyberSocReport.ps1 -EvidencePath <pack>`.

Each run writes an evidence pack with the report in two HTML editions and a deck, the SecOps worklist (`04-secops-worklist.md` and `.csv`) and the hardening change requests (`05-change-requests`). Send the client `03-security-report.client.html` and `03-security-report.pptx`. `03-security-report.html` is the internal edition, with the presenter notes, the evidence review, the collection register and the subscription and workspace IDs, so it never goes to the client. The client edition and the deck need Node.js. The worklist names client resources and is internal only, so it never goes to the client either. Get-CyberSocEvidence.README.md covers parameters, permissions and sign-ins.

## Raise the hardening change requests

The collection run writes `05-change-requests` into the pack: one change request for each low-impact hardening item that still has resources to fix, and a ready-to-send client email for each one. Every email asks for the client's approval, of a proposed date or, where the change restarts machines, of a maintenance window, and no change is scheduled without it. Pass `-ClientContact` and `-SenderName` to the collection run for the emails, or write them again on their own:

```powershell
pwsh ./New-CyberSocChangeRequests.ps1 -EvidencePath <pack> -ClientContact <name> -SenderName <name>
```

CR-26 asks the client Keep or Remove for each guest account in the file attached to its email. When the file comes back, save it outside `05-change-requests` and run the generator again with `-GuestDecisions <returned file>`, so CR-26 lists only the guests marked Remove.

New-CyberSocChangeRequests.README.md covers the changes, the emails and the options.

## Integrity

MANIFEST.sha256 exists only in a release zip. Export-CyberSocToolkit.ps1 writes it into the package with the SHA-256 of every other file in the folder, and the repository root has no copy. In the extracted release folder on macOS or Linux, check it with `shasum -a 256 -c MANIFEST.sha256`.