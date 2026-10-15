# EBR security HTML report

The collector creates `03-security-report.html` and its PowerPoint edition `03-security-report.pptx` in each completed evidence pack. The report works offline as a single file with embedded data, styles and graphics. Open it in a browser to view the report, change its depth, read the presenter notes or print the selected view.

The report follows the navy, cyan and white theme of the EBR decks and the structure of the security slides: a four tile strip, the four tier "How we report posture" block, measured outcomes by pillar, the E, P, N control matrix, delivered and sequenced work with the passwordless transition, and the two Microsoft scores in context. It works for any client regardless of subscription or workspace count.

## Generate from an existing evidence pack

```powershell
./New-EbrSecurityReport.ps1 -EvidencePath './EBR-Evidence_Client_20261008-120000'
```

```powershell
./New-EbrSecurityReport.ps1 -EvidencePath './EBR-Evidence_Client_20261008-120000' -Depth Detailed -ContextPath './client-review-context.json' -OutputPath './Client-Security-Review.html'
```

Generation requires PowerShell 5.1 or later and the adjacent `report` folder. No Azure session, browser automation package, Node installation or Python installation is required to generate or view the HTML report. The PowerPoint edition needs Node.js and pptxgenjs (`npm ci` in this folder, see [Windows setup](#windows-setup-for-the-powerpoint-edition)). Without them the HTML is still written and a warning says the deck was skipped. `-SkipDeck` writes the HTML only. The browser must support JavaScript. The completed HTML has no dependency on the original evidence folder.

To change the default for a new collection use `./Get-EbrSecurityEvidence.ps1 -ReportDepth Brief`. Use `-SkipHtmlReport` to collect evidence without generating HTML. A report generation error preserves the collected evidence and returns exit code 2. Re-run the standalone generator after correcting the error.

### Windows setup for the PowerPoint edition

PowerShell 5.1 ships with Windows, so the deck needs only Node.js and pptxgenjs.

1. Install Node.js 16 or later. The current LTS is the safe choice. Open a new PowerShell window afterwards so `node` is on PATH. Without it the generator writes the HTML and warns that the deck was skipped.

   ```powershell
   winget install OpenJS.NodeJS.LTS
   ```

2. In the folder that holds `package.json`, install the locked packages. `npm ci` installs pptxgenjs 4.0.1 and jszip exactly as `package-lock.json` records them. Use it rather than `npm install`, because `package.json` allows any 4.x release and the chart repair in `report/deck-common.cjs` was written for the 4.0.1 workbook bug. Copying an existing `node_modules` folder also works, since every package in it is plain JavaScript.

   ```powershell
   npm ci
   ```

   pptxgenjs is looked up from `report` upward, so keep `report` inside the folder where the packages were installed, or set `NODE_PATH` to a `node_modules` folder that has them. The macOS fallback path in `report/deck-common.cjs` is skipped on Windows.

3. If the scripts arrived in a zip or a download, Windows may block them as unsigned. Allow them for the current PowerShell window only.

   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   ```

PowerPoint, Python, LibreOffice and Chrome are not needed to build the deck. They are used only for visual QA. The deck backgrounds are already rendered in `report/assets`. The controls deck (`node report/build-controls-deck.cjs`) uses the same setup.

## Report pages

| Page | Depth | Content |
|---|---|---|
| 01 Executive summary | all | Four headline tiles, the four tier posture block, what comes next |
| 02 Security operations | Balanced, Detailed | Response performance, alerts created each month, disposition, detections by source, and the confirmed threats table when there are examples |
| 03 Measured outcomes | Balanced, Detailed | One row per pillar with a headline statement, narrative, measure and callout |
| 04 The controls that matter | Balanced, Detailed | E, P, N status marks by pillar |
| 05 What comes next | all | Verified delivery, the top three sequenced priorities, the MFA method update |
| 06 Tenant and cloud posture | Detailed | Score rings as percentages with their movement in percentage points, trend, where the next points are, the measurement model explainer |
| Presenter notes | screen only | Prepared answers, timing selection, evidence review, collection register |

The default is Balanced. The depth selector updates the view without modifying the embedded evidence. Printing follows the selected view and excludes the presenter notes.

## PowerPoint edition

`03-security-report.pptx` is written beside the HTML on every run by `report/build-report-deck.cjs`, from the same embedded aggregates and the same report model. The story behind it (outcome KPIs, wins, watch list, decisions, drift, the posture matrix and the roadmap horizons) comes from `report/report-story.js`, which the HTML can adopt later. The structure follows the Oct 12, 2026 deck review and designer mock-up, recorded in `docs/plans/2026-10-12-ebr-deck-restructure-design.md`.

| Slide | Brief | Balanced | Detailed |
|---|---|---|---|
| Cover, with a quarter label when the alert window is a calendar quarter | yes | yes | yes |
| Executive summary: four outcome KPIs, the four tier "How we report posture" block as the HTML page shows it, then Wins, Watch and Items that need action (read access stays on the closing slide) | yes | yes | yes |
| Quarter wins: up to six, at most one per area | yes | yes | yes |
| Security operations: volume by month, time to close by severity, how closed alerts were resolved, detections by source | | yes | yes |
| Confirmed threats: up to five example groups by alert title, highest severity first, whenever the pack has true positives. Without a screened example the slide holds the outcome cards and the impact statement without the table. The caption carries the impact statement (the reviewed determination from the context file, otherwise the tactic reading and the request for additional investigation evidence). A short table is followed by the outcome cards (confirmed threats, the exfiltration or impact tactic count, high severity alerts, response speed) and the handling strip | | yes | yes |
| Control posture: five-pillar matrix with the headline measure column on a band, figures in bold, and the foundational gaps panel. MFA at sign-in and MFA at the admin portals below E together read as one gap, with the admin portal reading folded in | | yes | yes |
| Measured outcomes by pillar: the headline, narrative, lead measure and callout of each pillar, as the HTML pillar page shows them | | yes | yes |
| Hardening roadmap: Now, Next and Later, every below-E control mapped | yes | yes | yes |
| Priority workstreams: the first three priorities with evidence, action and outcome, the rest in one line | | yes | yes |
| MFA method update, when users still sign in with text message or voice: the countdown, users by method, and the steps to move each one to a stronger method | yes | yes | yes |
| Decisions needed | yes | yes | yes |
| Appendix A1 to A3: the control register, two pillars per slide, and how we grade | | yes | yes |
| Appendix A4: scope and evidence, what the readings cover and the controls this collection could not grade | | yes | yes |
| Appendix A5 and A6: tenant and cloud posture (the Defender for Cloud score by month as a line chart, the tenant score with its category scores, both as percentages with their movement in percentage points), where the next points are | | | yes |

Rules the deck follows:

- Each subtitle is a takeaway built from the slide's lead metric.
- Medians under 20 minutes are never shown. Where the high severity median is under the floor, the 90th percentile carries the speed story when it is one hour or less.
- Open alert counts and severity increases stay in the HTML presenter notes. The operations slide shows how closed alerts were resolved and the existing referral sentence only.
- Foundational controls below E appear on the gaps panel and first in Now, as Atmosera's fix. The deck calls them gaps against the baseline, never drift or a regression, and never says a control was configured at build: the evidence holds the current reading only (Oct 14, 2026). A foundational control that needs a license the client holds (Defender for Identity when the tenant is not onboarded) goes to Later with a licensing ask instead.
- A Conditional Access control reads In force when an enabled policy covers every user on every application in every condition, Mostly enforced (marked P, with the sign-in ratio beside it) when the enabled policy stops short of that, by selecting its users or applications or by a platform, risk level, device filter or location condition, and at least half of the measured sign-ins still satisfied it, and Not in force otherwise. The grade rests on the measured ratio. The note says how the policy is scoped, from the `ScopeReason` the evaluator records (Users, Applications, UsersAndApplications or Conditions), and a policy scoped to selected applications is never described as requiring the control on every application.
- Workload protection names the resource types outside Standard plan coverage, for example "24 AI services not covered", on the gaps panel, the roadmap and the register.
- A ratio control with fewer than 10 resources, such as 2 of 2 machines patched, never stands as a win or leads a pillar in the posture matrix. The control itself still reads in the register.
- Read access is asked for only where the collector's token was not permitted to read the evidence (the `AccessGap` flag the builder derives from the manifest detail). Service errors are Atmosera's to resolve and never become an ask. A service that answers that the tenant is not onboarded or not licensed sets `NotOnboarded` instead, so the control reads Not in force where the collection shows domain controllers (NB.10 devices or DR.4 events). Without that positive evidence it stays ungathered: NB.10 reads Azure virtual machines only and DR.4 needs Defender for Identity telemetry, so an empty read never proves a cloud-only tenant.
- The deck never prints `(null)`. Ungathered controls read "Not gathered" with a dash chip.
- Containment is never claimed, and neither is impact. The tactic count is of true positives whose recorded tactics include Exfiltration or Impact, from the tactics the builder embeds on every OUT.4 row, and every surface reads "carried an exfiltration or impact tactic", never "reached": the tactic is a detection-time label on the alert, not an investigation finding, and the collector's own OUT.4 note holds that a zero data loss statement needs each flagged closing comment reviewed. The collector's ExfilOrImpactTactic flag also fires on a Collection tactic, so a pack whose rows carry no tactics (an older builder, or a flagged row whose tactics could not be read) keeps the flag count and reads "carried a collection, exfiltration or impact tactic" instead. A true positive is a closure classification, so the surfaces say "classified as true positives by the SOC", never investigated. The handling strip on the confirmed threats slide names only the steps the evidence records (detect, triage, classify) and closes with "impact confirmed only from reviewed investigation records", so neither the strip nor the speaker notes say a confirmed threat was investigated, assessed for impact or closed. No client-facing string says "no impact", "did not reach" or "reached" unless the context file carries a reviewed `Impact` record (see below). Until it does, the threats table caption, the HTML threats block and the speaker notes read "Based on the tactics Sentinel recorded on the alerts, none of the confirmed threats carried an exfiltration or impact tactic. Additional investigation evidence is required to confirm whether any data exposure or business impact occurred." The 90th percentile is creation to recorded close, so it reads "Nine in ten triaged and closed within", never investigated or resolved.
- A presenter note records that an indicator-based true positive (a Log4Shell IP or domain indicator match, for example) confirms the indicator was observed, not that exploitation or compromise occurred, and counts the example titles that name an indicator.
- The hardening count of members without MFA is written against the same members as the MFA at sign-in control, for example "14 of 194" beside a control reading "180 of 194", so the two reconcile at a glance.

Charts are native PowerPoint charts, so they stay editable. Speaker notes are talking points built only from text the client already sees in the HTML, such as pillar narratives and control descriptions. The presenter notes are never copied in, so the deck can be sent to the client after the review.

## Vocabulary and copy rules

Sentinel incidents are presented as **alerts** in every client-facing sentence. SecurityAlert records are presented as **detections**, so the two counts never collide. Dates are written out, for example "Jul 1 to Sep 30, 2026". Visible copy contains no arrows, emoji or semicolons, and the greater-than sign is not used in prose. HTML, CSS and JavaScript keep their required syntax. Reviewed context receives the same normalization.

## How figures are selected

| Measure | Rule |
|---|---|
| Alert scope | An alert is a Sentinel incident that opened an Atmosera ticket, identified by a ticket reference in its comments or closing comment. Informational severity is excluded. Detections are limited to those linked to these alerts. The collector applies this scope (version 1.6 or later, `-TicketPattern`). Packs collected without it receive a presenter note and count every incident |
| Alerts triaged | Alerts created in the period (OUT.1). When automation rules closed at least half of the closed alerts, the headline excludes automation closures and the automation count is shown as a supporting line |
| Open alerts | Never shown on the executive page and never a roadmap priority. The operations page describes them as items referred to the client for action or confirmation under the agreed notification process. The presenter note carries the raw count |
| Resolved share | Shown in the outcomes tier only at 90 percent or more. Always shown on the operations page |
| Response timing | Candidates in order: high severity for the full period, high severity for the trailing three full months (`OUT.2-RECENT`), all severities excluding automation closures for the full period (`OUT.2-ANALYST`), then the trailing three months. The first candidate with at least 5 closed alerts, a median of at least 20 minutes and a 90th percentile within one hour supplies both tiles. Otherwise the largest sample with a median of at least 20 minutes supplies the median alone and the 90th percentile tile is omitted. A median under 20 minutes is never shown. The selection table is in the presenter notes |
| Monthly volume | Presented as work absorbed by the SOC, stacked by severity in one hue. No first-to-last comparison is written for the client. A high severity increase becomes a presenter note |
| Confirmed threats | Three measures are kept apart. Confirmed malicious activity is the true positive classification count from OUT.1, labelled "Confirmed threats" and described as alerts the SOC classified as true positives. Confirmed security incidents have no collected or reviewed source, so no surface prints one. Confirmed business impact comes only from the reviewed `Impact` record in the context file and is never derived from tactics. The exfiltration or impact line counts the OUT.4 tactics only, never incident comments, and reads "carried", never "reached". The examples are OUT.4 true positives with an attack stage, grouped by screened alert title with the alert count, highest severity, attack stages and the months they span, up to five groups, highest severity first. Withheld titles and true positives with no attack stage, such as a service limit warning, stay out of the examples and are counted in the presenter notes. With no examples the table is left out, and the HTML block and the slide still carry the true positive count and the impact statement |
| Status marks | E at 90 percent or more, P from 50 to 89, N below 50. Verified configurations such as the Conditional Access controls, anti-phishing, Safe Links, Safe Attachments, threat intelligence and domain controller telemetry read as In force. An enabled Conditional Access policy that stops short of every user on every application in every condition reads Mostly enforced (P) when the sign-in ratio behind it is 50 percent or more, with the ratio shown beside it and the note naming how the policy is scoped. The percentage bands apply to ratio controls: a policy scoped by users, applications or conditions reads P however high its ratio, since the policy is not in force everywhere. No pillar letter grade is generated |
| Secure score movement | Measured from the first month of the continuous export (POS.7) to the current score (POS.1), so the points and the percentage on the page reconcile. A current score below the first month shows no gain |
| Benchmark controls | POS.5 rows for one edition of the Microsoft cloud security benchmark only: the unversioned name, else a versioned name that is not a preview, else the latest preview. A second edition or the CSPM scaffold assigned beside it is not added in, and named standards that are not the benchmark never stand in for it, so the meter is left out without a benchmark edition. Legacy rows with no standard name count as a whole |
| Device scope | Every device measure (endpoint detection, sensors, anti-malware, tamper protection, host firewall, credential protection, Remote Desktop, network protection, NTLMv2, directory signing, vulnerability assessment, exploitable findings) reads Azure virtual machines only (Oct 14, 2026). Collector 1.14.0 drops other endpoints at the source, and the report leaves the Other device rows of older packs out, so a workstation fleet never inflates a figure such as network protection to the thousands |
| Endpoint detection | Azure virtual machines reporting to endpoint detection is onboarded plus machines covered by a third-party endpoint detection product, over the machines eligible for endpoint detection. The reasons come from EW.1-GAPS (collector 1.14.0): a machine covered by CrowdStrike Falcon or another product named by `-EdrVendorPattern` is protected, a network virtual appliance, a deallocated machine and an unsupported operating system leave the denominator, and a machine Defender for Endpoint has never discovered joins it. The note under this row and under the sensor row states every reason, so the two figures reconcile on the page. The presenter notes carry the Resource Graph inventory count beside the Defender count |
| Ungathered controls | Shown on the controls page as (null) with no status mark, excluded from the executive summary tiers, and listed in the presenter notes with the reason. Controls with no applicable resources in scope are omitted |
| Controls without evidence either way | Shown as N/A with no status mark and excluded from every count. Used when the evidence was gathered but holds nothing to judge, for example no device code sign-ins and no Conditional Access policy inventory. Listed in the evidence review |
| Location-based sign-in access | IA.4-LOCATION replaced the share of sign-ins Conditional Access evaluated (IA.4) on Oct 12, 2026. It reads In force when an enabled policy in IA.8-POLICIES has a country or named location condition, blocks access or requires MFA, and covers all users and all resources. Scoped and report-only policies read Not in force. Packs with only the flattened IA.8 inventory read (null), since it never recorded locations. Exclusion counts stay in the presenter notes |
| Endpoint sensors | Active sensors among the Azure virtual machines onboarded to Defender for Endpoint. Workstations and network devices such as firewalls are not part of the measure, and rows whose platform names a firewall operating system are dropped for older packs too. The EW.1-GAPS reasons are repeated in its note |
| Patch cadence | Machines whose tags record patching as waived or client owned leave the measure at collection (collector 1.14.0, `-PatchExclusionTagPattern`). The note states how many were left out, from EW.10-EXCLUDED, and the evidence review repeats it |
| Blob containers | DP.1-CONTAINERS (collector 1.11.0) grades the defense in depth row Blob containers closed to anonymous access on each container's own access level, read in every storage account. Containers readable anonymously today, and accounts that could not be listed, go to the presenter notes and evidence review, never the client page |
| Conditional Access controls | IA.1, IA.1-ADMINPORTAL, IA.3 and IA.3-DEVICECODE read the policy state from IA.8-POLICIES (or the flattened IA.8 inventory for packs before collector 1.10.0) and the per-account sign-in detail from IA.8-SIGNINS, through `report/Get-EbrCaEvaluation.ps1`. Only the per-control counts are embedded, as IA.8-CA. Multifactor authentication required at sign-in (IA.1) reads In force when an enabled policy requires multifactor authentication on every application for all users and is not narrowed to a platform, risk level, device filter or location, or when security defaults are on (Oct 14, 2026). Multifactor authentication at admin portal sign-in (IA.1-ADMINPORTAL) reads In force when an enabled policy requires it on the Microsoft admin portals or on every application, for all users or for the administrator roles. A scoped, report-only or missing policy reads Not in force. The sign-in ratio from IA.1 and IA.1-ADMINPORTAL moves to the note and the pillar page, and a ratio below E with the policy in force is explained in the presenter notes. Without a policy inventory the sign-in ratio grades both as before. For IA.3 and IA.3-DEVICECODE the block policy decides the status. An enabled block policy for all users, or security defaults for legacy authentication, makes the control In force, and a scoped, report-only or missing policy makes it Not in force. Sign-ins show only whether an account got past the policy. Sign-ins by excluded accounts are framed as approved exceptions, and successful sign-ins the policy did not evaluate go to the presenter notes. Without a policy inventory the control reads In force only when Conditional Access blocks are recorded and no sign-in succeeded, Not in force when a sign-in succeeded, and N/A otherwise. Only error 53003 counts as a Conditional Access block, so legacy attempts that failed without one, such as a wrong password or a locked account, are never presented as blocked |
| Cloud score | Computed from points. With at least two valid monthly readings, the continuous export trend (POS.7) is shown in both HTML and PowerPoint whether rising, flat or declining. With less history the current score stands alone. A gain line compares the current POS.1 score with the first trend reading and appears only for a positive change. The Microsoft measurement model explainer remains alongside the scores: scope, weighting and model changes can move the percentage without a change in controls |
| Tenant score | Requires a dated portal reading in the context file. The device score is never substituted |
| Priorities | Ranked in a fixed sequence: critical exploitable findings, multifactor coverage, the MFA method update, endpoint coverage, anti-malware configuration, workload protection, logging, encryption at host, backup, storage transport, key protection, segmentation, platform integrity. The top three are shown, the rest expand |
| Data gaps | Missing, failed, unavailable, manual and empty evidence never become a favorable zero or 100 percent. Duplicate cross-workspace alerts withhold every alert figure until reconciled |

Alert activity uses the recorded period. Identity and endpoint evidence retains its source lookback, generally the last 30 days. Configuration and score readings are point-in-time measurements.

## Add reviewed context

Copy `report/context.example.json`, enter the exact client and tenant from the pack, then populate the supported fields. Each field below is an example of the format, not client evidence.

```json
{
  "ClientName": "Example Client",
  "TenantId": "example-client-tenant-id",
  "ServiceStartDate": "2023-08-15",
  "TenantScore": {
    "Current": 58.68,
    "Max": 100,
    "ReadDate": "2026-10-08",
    "Source": "Defender portal capture saved with the October review",
    "Previous": 53.2,
    "PreviousMax": 100,
    "PreviousReadDate": "2026-07-10",
    "Categories": { "Identity": 50.8, "Device": 61.3, "Apps": 59.5, "Data": 71.4 }
  },
  "Delivered": [
    {
      "Title": "Storage transport baseline",
      "Outcome": "Validated the approved transport settings across the agreed storage scope.",
      "Reference": "CHG-12345",
      "CompletedDate": "2026-09-18",
      "Pillar": "Data protection"
    }
  ],
  "Impact": {
    "Confirmed": 0,
    "Reviewed": "2026-10-10",
    "Reference": "ZD 9900100",
    "WindowStart": "2026-07-01",
    "WindowEnd": "2026-09-30"
  }
}
```

`ServiceStartDate` enables the "Months of managed security" tile. `Previous`, `PreviousMax` and `PreviousReadDate` add the tenant score movement line, in percentage points with each reading over its own maximum, since Microsoft widens the maximum over time. Without `PreviousMax` the maximum comes from the POS.6-TREND snapshot dated `PreviousReadDate`, and without that the movement line is omitted and the evidence review says so. `Categories` are percentages and add the category bars on the posture page. A delivered item needs a title, outcome, reference and a completion date inside the alert period. Incomplete entries appear in the evidence review instead of on the client page. `Impact` is the reviewed data exposure and business impact determination for the period's true positives: `Confirmed` is the number of true positives with confirmed data exposure or business impact (0 when the review found none), `Reviewed` is the date the closing comments and tickets were reviewed, `Reference` is the ticket or record that holds the review, and `WindowStart` and `WindowEnd` are the alert period the review covers, copied from the pack's `00-parameters.json`. All five are required. The window must match the pack's alert period, `Reviewed` must be on or after `WindowEnd`, and `Confirmed` cannot exceed the OUT.1 true positive count, so a context file reused from an earlier period never carries a determination forward to later true positives. A record that fails any check is omitted with an evidence review note naming the reason. With the record the threats caption, the HTML threats block, the executive tile and the outcomes tier print the determination with its reference and date, and a confirmed impact withdraws the tactic win from the summary. Without it the report prints the tactic count and asks for additional investigation evidence, and the evidence review says so. The generator checks structure and date scope but cannot verify the referenced ticket, portal capture or impact review. It accepts no overrides for computed metrics.

## Presenter notes

Open **Presenter notes** in the toolbar before the review. The section lists every figure that needs a prepared answer (open alerts, closure classification, automation share, high severity trend, workspace coverage, score movement), the response timing candidates and why each was or was not used, the controls that were not measured, outstanding portal readings and the collection register. It is excluded from printing. The toggle is a display choice, not an access boundary. Anyone receiving the HTML can inspect its embedded contents.

The HTML embeds aggregate data and collection metadata only. Row-level results that name resources (subnets, virtual machines, privileged accounts) are reduced to counts before embedding. Incident titles are embedded only for confirmed threats with an attack stage, after screening: a title naming an email address, IP address, a host name with a domain suffix, a machine name such as DESKTOP-4F2KQ1 or FILESERVER01, a path, GUID, ticket reference or long number, or longer than 200 characters, is replaced with 'Title withheld'. An all-caps name with a digit counts as a machine name, so CVE identifiers and KB numbers are withheld too. Comments, incident numbers, ticket numbers, query text and authentication diagnostics are never embedded. The screen does not recognise a bare account name, a person's name or an unhyphenated lowercase machine name such as fileserver01, so read the confirmed threats table before delivery.

## Controls standard for executives

```powershell
./New-EbrControlsStandard.ps1
```

Writes `docs/The Controls That Matter.html` and `docs/The Controls That Matter.pptx`: page 04 on its own, as a standard rather than a client reading. Both are informational. They outline every control by pillar and tier with the reading that grades it, explain the tiers and the E, P and N marks, count the controls per pillar and close with an invitation for feedback. They do not ask for sign-off and carry no measure IDs, change list or page footers, and they hold no client data. The control list comes from `report/report-model.js` run on an empty pack in standards mode, so both always match the client report. Set the title and version in `report/controls-standard.json`, then regenerate after any change to a control, its tier or its measure.

The deck is built by `node report/build-controls-deck.cjs [output.pptx]` (pptxgenjs, `npm ci` if it is missing). It has a title slide, the two tiers, grading, controls by pillar as a native chart, one slide per pillar and tier with a card per control and speaker notes, and a closing feedback slide. Its backgrounds (`report/assets/deck-title.jpg`, `deck-band.jpg`) are rendered from the report background by `node .report-build/make-deck-assets.cjs`. `-SkipDeck` writes the HTML only. `node .report-build/check-standard.cjs` checks the HTML headlessly and writes screenshots and a PDF to `.report-build/standard`.

## Validation

```powershell
Invoke-Pester ./tests/Get-EbrSecurityEvidence.Tests.ps1, ./tests/New-EbrSecurityReport.Tests.ps1 -Output Detailed
```

```bash
node --test tests/ebr-report-model.test.cjs tests/ebr-report-story.test.cjs tests/ebr-report-deck.test.cjs
```

The model tests cover the alert vocabulary, the timing candidate ladder, the automation adjustment, open alert handling, status marks, score movement, context validation and the real packs in this folder. The Pester tests cover generation, escaping, aggregate reduction, context acceptance and the trailing three month catalog entries. No test signs in or changes client resources.
