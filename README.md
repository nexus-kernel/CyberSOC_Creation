# CyberSOC_Creation

The monthly CyberSOC security report toolkit. It collects the evidence for one client, read-only, and writes a
structured monthly report on the client's overall security posture: the report month with its 90-day trend,
security operations, threat intelligence, vulnerability management and the control posture.

This repository is a copy of [EBR_Creation](https://github.com/nexus-kernel/EBR_Creation) (EBR collector 1.14.0,
main at `9fbd27d`), geared to the monthly report. The executive business review answers "where does the program
stand across the whole service history". The CyberSOC report answers "what happened this month, how does it compare
with the two months before, and what needs attention".

## What is different from the EBR toolkit

| | EBR | CyberSOC monthly |
|---|---|---|
| Window | Maximum reach of the SecurityIncident data | The report month and the two full months before it, the 90-day trend (`-ReportMonth`, last full month by default) |
| Trend | Alerts by month | Alerts by week and month, response timing by month, alert types by title, scores by month, and the month at a glance with a neutral change from the previous month |
| Threat intelligence | Ingestion and matches as two controls (DR.7, DR.8) | A page and a slide: indicators monitored, indicator matches by month, MITRE ATT&CK tactics and techniques on the alerts, identity threat activity and Entra ID Protection risk detections, email threats, malware on Azure virtual machines, and the CISA KEV-listed vulnerabilities present |
| Vulnerability assessment | Exploitable vulnerabilities as one backlog figure (BKL.1) | A page and a slide from the monthly Atmosera.VulnAssessment runs: open findings by severity at each assessment, CISA KEV, public exploit, the change between assessments, top products to patch, remediation status and owner. The Defender current state when no run is imported |
| Compromise and exfiltration | Confirmed data loss or exfiltration, identity compromises contained, malicious sign-in to containment (OUT.8), the exfiltration or impact tactic count on the true positives and the reviewed `Impact` determination | Not reported or collected. The report keeps the true positive detections, the alerts the SOC classified as true positives, with their examples. Keep these out when merging EBR fixes |
| True positive label | "Confirmed threats" on the tiles, the KPIs, the threats block and slide, and the handling strip ("EVERY CONFIRMED THREAT") | "True positive detections" ("EVERY TRUE POSITIVE DETECTION" on the strip): the label names the classification the evidence records and suggests no confirmed compromise. Keep the CyberSOC label when merging EBR fixes. The edition, deck and Pester tests fail if "Confirmed threat" reaches an edition |
| Report | Security business review | CyberSOC monthly security report, same editions (internal HTML, client HTML, PowerPoint) and the same evidence and copy rules |

Everything else carries over unchanged: the control matrix, the measured outcomes by pillar, the hardening
roadmap, the scores in context, the SecOps worklist, the client edition without identifiers, and the rule that
missing evidence never becomes a favorable zero.

## Monthly workflow

1. **Run the vulnerability assessment** for the client with
   [PowerShell_Vuln_Assess](https://github.com/nexus-kernel/PowerShell_Vuln_Assess), as every month. Keep the run
   folders (or the client's `per_client` CSVs with their `run_metadata` beside or above them).
2. **Collect** after the month ends:

   ```powershell
   pwsh ./Get-CyberSocEvidence.ps1 -TenantId <tenant> -SubscriptionId <sub1>,<sub2> -ReportMonth 2026-09 `
       -VulnAssessmentPath ./VULN_ASSESSMENT/2026-07, ./VULN_ASSESSMENT/2026-08, ./VULN_ASSESSMENT/2026-09, ./VULN_ASSESSMENT/2026-10
   ```

   The pack is `CyberSOC-Evidence_<client>_<report month>_<timestamp>/`. Runs dated inside the window, up to the
   collection date, are imported, and only for this client's subscriptions.
3. **Add reviewed context** if you have it (optional): copy `report/context.example.json` and add the analyst
   highlights of the month (`MonthHighlights`), the open alert split and the tenant Secure Score portal reading.
   Regenerate:

   ```powershell
   pwsh ./New-CyberSocReport.ps1 -EvidencePath ./CyberSOC-Evidence_Contoso_2026-09_20261003-090000 -ContextPath ./contoso-2026-09.json
   ```

4. **Send** `03-security-report.client.html` and `03-security-report.pptx`. `03-security-report.html` is the
   internal edition, with the presenter notes and the evidence review, and the SecOps worklist names client
   resources. Neither goes to the client.
5. **Raise the hardening change requests** when the client is ready for them. The collection run already wrote
   them, with a client email for each, into `05-change-requests/`. Pass the client details to the collection run
   (`-ClientContact`, `-SenderName`, and `-DrClient`, `-SentinelWorkspace`, `-ManagementGroup` or
   `-PurgeProtectionApproved` when they apply), or write the change requests again on their own:

   ```powershell
   pwsh ./New-CyberSocChangeRequests.ps1 -EvidencePath ./CyberSOC-Evidence_Contoso_2026-09_20261003-090000 -ClientContact 'Dana' -SenderName 'Scott'
   ```

   `05-change-requests/` holds one change request for each low-impact hardening item that still has resources to
   fix (diagnostic logging, secure transfer, minimum TLS 1.2 on storage, App Service, Azure SQL, Redis, Service Bus,
   Event Hubs and Cosmos DB, purge protection, anonymous blob access, HTTPS only, encryption at host on virtual
   machines and on scale sets, closing internet-facing RDP, SSH and WinRM rules, and turning off plain FTP on App
   Service apps), and a ready-to-send client email for every change request. Every email asks for the
   client's approval and reads as a letter, with no titles and each paragraph opening in its own words, in one order:
   what is to change, why, what it means for the client, the resources
   by subscription, how it can be reversed, and the request. It asks the client to approve the proposed date, two
   weeks after the build by default, or, for encryption at host, which restarts each machine, to suggest a
   maintenance window, and to reply a week before the proposed date. No change is scheduled without the client's
   approval. To propose another date, run the generator again with it, since the collection run does not take
   `-ChangeDate`:

   ```powershell
   pwsh ./New-CyberSocChangeRequests.ps1 -EvidencePath ./CyberSOC-Evidence_Contoso_2026-09_20261003-090000 -ClientContact 'Dana' -SenderName 'Scott' -ChangeDate 2026-11-16
   ```

   The
   diagnostic logging emails say that the resource logs add Log Analytics ingestion to the Sentinel workspace.
   Anonymous blob access is turned off only on the storage accounts whose containers were all listed and are private,
   so its email walks the client through why nothing breaks, and the index names the accounts left out. Add
   `-PurgeProtectionApproved` when the client approved purge protection at build kickoff: its email then refers to
   that approval and asks the client to confirm it still stands and to approve the proposed date, and the index
   records it. The management port email asks who still needs RDP, SSH or WinRM from the internet and which replacement
   the client wants, just-in-time VM access (which needs Defender for Servers Plan 2) or Azure Bastion for RDP and SSH
   (WinRM continues through just-in-time access or named addresses, since Bastion does not provide it), asks for the
   private ranges that connect where a rule is open to every address, and the index
   names the rules left out: appliance untrust interfaces, groups attached to nothing (a cleanup item) and `*` or port
   range rules (for review). The FTP email asks whether any deployment tool, process or person still connects over FTP or
   FTPS, to upload files or to download files or logs, and whether FTPS only or Disabled suits each app, and the index names the apps whose FTP state Resource Graph
   returned empty, for a portal check, and says that deployment slots are not covered. AKS node pools without encryption at host get no change
   request: a pool takes it only when it is created, so the index names each cluster and node pool for a planned node
   pool replacement with the client.

A pack collected without the vulnerability runs takes them later:

```powershell
pwsh ./Import-CyberSocVulnAssessment.ps1 -EvidencePath ./CyberSOC-Evidence_Contoso_2026-09_20261003-090000 -VulnAssessmentPath ./VULN_ASSESSMENT
pwsh ./New-CyberSocReport.ps1 -EvidencePath ./CyberSOC-Evidence_Contoso_2026-09_20261003-090000
```

## The report

| Page | Depth | Content |
|---|---|---|
| 01 Executive summary | all | The month's tiles, the month in brief, the month at a glance beside the two months before it, reviewed analyst highlights, the four tier posture block |
| 02 Security operations | Balanced, Detailed | Response timing, alerts by month and by week, response timing by month, the most common alert types, disposition, detections by source, true positive detections |
| 03 Threat intelligence | all | Indicator matches, indicators monitored, ATT&CK tactics and techniques, identity threat activity and risk detections, email threats, malware detections, the CISA KEV-listed vulnerabilities present |
| 04 Vulnerability management | all | Open findings at each assessment, the change between them, top products to patch, remediation status and owner |
| 05 Measured outcomes | Balanced, Detailed | One row per pillar |
| 06 The controls that matter | Balanced, Detailed | E, P, N marks by pillar |
| 07 What comes next | all | The hardening roadmap |
| 08 Posture in context | Balanced, Detailed | Both Microsoft scores, the scores by month over the window and recommendation health by week |

The deck adds the month at a glance after the cover, the 90-day trend after security operations, and the threat
intelligence and vulnerability management slides at every depth.

## Documents

| Document | What it covers |
|---|---|
| [SETUP.md](SETUP.md) | Prerequisites and the first commands |
| [Get-CyberSocEvidence.README.md](Get-CyberSocEvidence.README.md) | The collector: parameters, permissions, sign-ins, engines, output |
| [CyberSOC Monthly Report Runbook.md](CyberSOC%20Monthly%20Report%20Runbook.md) | The window, the trend, threat intelligence and vulnerability queries, and the vulnerability assessment import |
| [EBR Security Evidence Collection Runbook.md](EBR%20Security%20Evidence%20Collection%20Runbook.md) | Every EBR query the collector still runs |
| [New-CyberSocReport.README.md](New-CyberSocReport.README.md) | The report editions, the figure rules and the reviewed context file |
| [New-CyberSocSecOpsWorklist.README.md](New-CyberSocSecOpsWorklist.README.md) | The internal SecOps worklist |
| [New-CyberSocChangeRequests.README.md](New-CyberSocChangeRequests.README.md) | The hardening change requests and client emails |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Development environment and validation |

## Lineage and porting EBR fixes

Internal function names keep the `Ebr` prefix of the EBR collector (`Get-EbrQueryCatalog`, `Invoke-EbrMain`,
`report/report-model.js` and its `EbrReport` global), and the CyberSOC additions live in their own functions and
files (`report/cybersoc-model.js`, `Import-CyberSocVulnAssessment.ps1`, Phase 5 of the catalog). That keeps fixes
portable both ways. To bring EBR fixes in:

```bash
git remote add ebr https://github.com/nexus-kernel/EBR_Creation.git
git fetch ebr main
git merge ebr/main
```

Git follows the renamed entry points (`Get-EbrSecurityEvidence.ps1` is `Get-CyberSocEvidence.ps1`, and so on).

## Validation

```bash
npm ci
node --test tests/*.test.cjs
```

```powershell
Invoke-Pester ./tests -Output Detailed
```

Nothing in the suites signs in or calls Azure. The fixtures are synthetic. See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)
and [AGENTS.md](AGENTS.md).
