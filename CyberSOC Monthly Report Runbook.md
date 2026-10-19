# CyberSOC Monthly Report Runbook

Oct 19, 2026. The evidence the monthly CyberSOC report adds to the *EBR Security Evidence Collection Runbook*.
Every query of that runbook still runs, word for word, over the window below. This runbook defines the window,
the queries added for the 90-day trend, threat intelligence and vulnerability exposure, the vulnerability
assessment import, and the per-resource lists the change requests read. `Get-CyberSocEvidence.ps1` runs it. Change a query here first, then in the catalog.

## 1. The reporting window

The report is for one month, the **report month**, with the **90-day trend** beside it.

| Parameter | Rule |
|---|---|
| Report month | `-ReportMonth yyyy-MM`, the last full month by default. A month that has not ended is refused |
| Window | The first day of the month two months before the report month to the last day of the report month. The September 2026 report reads Jul 1 to Sep 30, 2026 |
| Late data | A client whose SecurityIncident data (P0.1), or workspace retention, starts inside the trend gets a shorter window from its first full month of data, so monthly figures compare full months. Data that starts inside the report month starts the window on its first day, a partial report month, and the basis says so. A report month that ends before the data starts is refused, never reported as zeros |
| Overrides | `-WindowStart` and `-WindowEnd` as before. The report month is then the month of `WindowEnd`. `-ReportMonth` and `-WindowEnd` together are refused |
| Recorded | `00-parameters.json` carries `ReportType` (CyberSOC monthly), `ReportMonth`, `TrendMonths` (3), `WindowStart`, `WindowEnd` and `WindowBasis` |

The EBR collector reads the maximum reach instead. Every EBR query keeps its own lookback: identity and endpoint
readings use the last 30 days, configuration and scores are read at collection.

The alert population is the EBR one throughout: Sentinel incidents whose comments reference an Atmosera ticket,
informational severity excluded, keyed by `TenantId, IncidentNumber` so equal incident numbers in two workspaces
stay apart. Client copy says alerts, never incidents, and detections for SecurityAlert records.

## 2. The 90-day trend

OUT.2-MONTH splits the OUT.2 cohort (every alert created in the window and closed by collection) by the month each
alert was created. OUT.3-WEEK counts OUT.3 in 7-day bins from the window start, so a 92-day window ends with a
1-day bin, which the report labels. OUT.9 counts alerts by title and month. Titles can name accounts, hosts or
addresses, so the report embeds only titles that pass the OUT.4 screen and counts the rest as withheld.

How the report reads them:

- A month with fewer than 5 closed alerts in a scope reports no timing for it. A median under 20 minutes or a 90th
  percentile over one hour keeps its note, as on the full period.
- The month at a glance puts the report month beside the months before it with a neutral change ("6 more", "4 min
  shorter"), never better or worse. A high severity increase is a presenter note.
- Duplicate Defender XDR alerts across workspaces (P0.1-XDRDUP) withhold every monthly figure, as they withhold the
  period figures.

## 3. Threat intelligence

| ID | What it reads | Report rule |
|---|---|---|
| TI.0 | Which threat intelligence and threat telemetry tables Sentinel holds in the window, per workspace | A table missing here is not collected, so the measure that reads it has no figure, never a zero. TI.0-BY-WORKSPACE picks the workspace TI.6 reads |
| TI.1 | Threat intelligence indicators by feed and type, from the STIX `ThreatIntelIndicators` and the legacy `ThreatIntelligenceIndicator` table | Each indicator at its latest record up to the window end, over the 365 days before it. Active means not expired, revoked or deleted at the end of the window |
| TI.2 | Detections from the threat intelligence analytics rules (TI map rules, Microsoft Threat Intelligence Analytics) by month and indicator type, and how many sit in ticketed alerts | A match confirms an indicator was observed in telemetry, not that exploitation or compromise occurred |
| TI.3 | MITRE ATT&CK tactics on the detections in ticketed alerts, by month | A tactic is a detection-time label, not an investigation finding. Shown in attack chain order |
| TI.4 | MITRE ATT&CK techniques on the same detections, top 25 | Named from the ATT&CK Enterprise matrix, an unknown ID reads as the ID |
| TI.5 | Identity threat activity in interactive sign-ins by month: failed passwords (50126), smart lockouts and blocked addresses (50053), Conditional Access blocks (53003), password spraying sources, risky sign-ins | A password spraying source is an address that failed a password against 10 or more accounts in one day, a signal and not a confirmed attack. Risk levels need Entra ID P2: when most sign-ins carry the hidden level the risky sign-in row is left out |
| TI.5-RISK | Microsoft Entra ID Protection risk detections by month and type | Needs Entra ID P2 and the AADUserRiskEvents diagnostic setting. Read from the workspace that holds the most of them, else the one that holds the sign-ins |
| TI.6 | Inbound email threats by month from `EmailEvents` | Needs the Defender XDR connector to stream EmailEvents into Sentinel. Read once from the workspace holding the most, since a tenant-wide table streamed into several workspaces would otherwise double count |
| TI.7 | Microsoft Defender Antivirus detections on Azure virtual machines, last 30 days | Advanced Hunting holds 30 days, so this reads the last 30 days whatever the window. Azure virtual machines only, as every device measure since EBR collector 1.14.0 |

Every TI query returns counts only. Names, addresses and machines stay out of the results the report embeds.

## 4. Vulnerability exposure

VA.1 to VA.3 read Defender for Endpoint vulnerability management on Azure virtual machines at collection: open
CVEs by severity, the most exposed software, and the CVEs published in each month of the window that are open now.
They are the fallback when no assessment run is imported, and the cross-check when one is.

### Vulnerability assessment runs (Import-CyberSocVulnAssessment.ps1)

The monthly Atmosera.VulnAssessment runs are the record of vulnerability management: they carry the CISA KEV
listing, remediation status, ownership and the change between runs. `-VulnAssessmentPath` on the collector, or
`Import-CyberSocVulnAssessment.ps1` on an existing pack, reads them offline and writes four results.

| ID | Contents |
|---|---|
| VA.RUNS | One row per run dated inside the window, up to the posture read date: open findings (ACTIONABLE) by report severity, CISA KEV listed, public exploit, VMs, CVEs, end-of-support VMs, no vendor fix, owner and the remediation status counts. `Complete` when the run assessed every pack subscription with complete data, else `Partial` |
| VA.CHANGE | The change between each run and the one before it, counted as the tool counts its trend: a finding is one VM x vuln_id, earlier plus new minus no longer reported is current. Compared only between Complete runs with the same severity filter |
| VA.TOP | The latest run's open findings by product, ranked by CISA KEV listing, public exploit code, maximum CVSS, VMs, fix availability and severity |
| VA.KEV | The latest run's open findings with a CISA KEV-listed CVE, by product, with the date CISA added it and whether that was in the report month |

Rules:

- Only the pack's subscriptions are kept. A run that assessed none of them is skipped. Findings of other
  subscriptions are counted in the VA.RUNS detail, never read.
- A run without its `run_metadata_<timestamp>.json` (beside the CSV, or one folder up for per_client and
  per_subscription CSVs), an `-UrgentOnly` run, a run written before `data_completeness`, and a run dated outside
  the window are skipped and named in the VA.RUNS detail and `00-parameters.json` (`VulnAssessment.Skipped`).
- A folder is searched with its subfolders for every `<name>_<timestamp>.csv`, so the tool's output folder, a
  folder of monthly run folders, one run folder and a per_client folder all work. A run's run-wide
  `vuln_assessment_<timestamp>.csv` wins over its per_client and per_subscription CSVs. Exact duplicate rows (a
  subscription listed under two roster titles) count once.
- A run that did not check the CISA KEV catalog leaves the KEV counts empty, never zero. A run without Defender for
  Endpoint data for every subscription leaves the public exploit count empty.
- A finding the earlier run reported and the later one did not is no longer reported (pending validation), never
  remediated or resolved. A CISA KEV listing means CISA has reported exploitation in the wild, not exploitation in
  the client environment.
- Only counts and product names reach the results. VM names, resource ids and paths stay in the assessment output.

## 5. Query blocks

The query text the collector runs, with the tokens of the EBR runbook (`{{WINDOW_START}}`, `{{WINDOW_END}}`,
`{{TICKET}}`, `{{MRG}}`). A dry run writes every query expanded to `queries/<ID>.kql`.

### OUT.2-MONTH Triage and close time by month of creation and severity

Engine LA, combined only. CyberSOC trend. The OUT.2 cohort split by the month each alert was created. A month with fewer than 5 closed high severity alerts has no reportable timing. Quote the median, never the mean.

```kql
SecurityIncident
| where TimeGenerated between ({{WINDOW_START}} .. now())
| summarize arg_max(TimeGenerated, Status, Severity, CreatedTime, ClosedTime, ModifiedBy, Comments, ClassificationComment),
            FirstTriaged = minif(TimeGenerated, Status != "New")
          by TenantId, IncidentNumber
| where CreatedTime between ({{WINDOW_START}} .. endofday({{WINDOW_END}}))
| where Severity != "Informational"
| where {{TICKET}}
| where Status == "Closed" and isnotempty(ClosedTime)
| extend MinutesToTriage = datetime_diff("minute", FirstTriaged, CreatedTime),
         MinutesToClose  = datetime_diff("minute", ClosedTime, CreatedTime),
         IsAutoClosed    = ModifiedBy has "Automation rule"
| extend Scope = pack_array(Severity, "All")
| mv-expand Scope to typeof(string)
| summarize Incidents       = count(),
            AutoClosed      = countif(IsAutoClosed),
            MedianTriageMin = percentile(MinutesToTriage, 50),
            MedianCloseMin  = percentile(MinutesToClose, 50),
            P90CloseMin     = percentile(MinutesToClose, 90)
          by Month = startofmonth(CreatedTime), Scope
| order by Month asc, Scope asc
```

### OUT.3-WEEK Weekly alert volume by severity and classification

Engine LA, combined only. CyberSOC trend. 7-day bins from the window start, so the last bin can be shorter (Days). A week with no alert has no row.

```kql
SecurityIncident
| where TimeGenerated between ({{WINDOW_START}} .. now())
| summarize arg_max(TimeGenerated, Severity, CreatedTime, Classification, Comments, ClassificationComment) by TenantId, IncidentNumber
| where CreatedTime between ({{WINDOW_START}} .. endofday({{WINDOW_END}}))
| where Severity != "Informational"
| where {{TICKET}}
| summarize Total         = count(),
            High          = countif(Severity == "High"),
            Medium        = countif(Severity == "Medium"),
            Low           = countif(Severity == "Low"),
            TruePositive  = countif(Classification == "TruePositive"),
            FalsePositive = countif(Classification == "FalsePositive")
          by Week = bin_at(CreatedTime, 7d, {{WINDOW_START}})
| extend WeekEnd = iff(Week + 6d > {{WINDOW_END}}, {{WINDOW_END}}, Week + 6d)
| extend Days = datetime_diff("day", WeekEnd, Week) + 1
| order by Week asc
```

### OUT.9 Alert types by title and month

Engine LA, combined only. CyberSOC trend. Titles can name accounts, hosts or addresses, so the report embeds only titles that pass the same screen as the OUT.4 threat titles. Internal: the raw titles stay in the pack.

```kql
SecurityIncident
| where TimeGenerated between ({{WINDOW_START}} .. now())
| summarize arg_max(TimeGenerated, Title, Severity, CreatedTime, Classification, Comments, ClassificationComment) by TenantId, IncidentNumber
| where CreatedTime between ({{WINDOW_START}} .. endofday({{WINDOW_END}}))
| where Severity != "Informational"
| where {{TICKET}}
| summarize Alerts         = count(),
            High           = countif(Severity == "High"),
            TruePositive   = countif(Classification == "TruePositive"),
            BenignPositive = countif(Classification == "BenignPositive"),
            FalsePositive  = countif(Classification == "FalsePositive")
          by Month = startofmonth(CreatedTime), Title
| order by Month asc, Alerts desc
```

### TI.0 Threat intelligence and threat telemetry reach

Engine LA, always broken down per workspace. CyberSOC. Records inside the window only, the same window the measures that read the tables use. A table missing from the output has no records in the window, so the measures that read it have no figure, not a zero. TI.0-BY-WORKSPACE picks the workspaces EmailEvents and AADUserRiskEvents are read from.

```kql
union withsource = SourceTable isfuzzy = true
    ThreatIntelIndicators, ThreatIntelligenceIndicator, SecurityAlert, SigninLogs, AADUserRiskEvents, EmailEvents
| where TimeGenerated between ({{WINDOW_START}} .. endofday({{WINDOW_END}}))
| summarize EarliestRecord = min(TimeGenerated),
            LatestRecord   = max(TimeGenerated),
            Records        = count()
          by SourceTable
| order by SourceTable asc
```

### TI.1 Threat intelligence indicators by source and type

Engine LA, combined only. CyberSOC. Each indicator at its latest record up to the end of the window, over the 365 days before it, so an indicator ingested before the window and still valid at its end is counted. Keyed by table and indicator ID, so an indicator held in several workspaces counts once when the IDs match. Active means not expired, revoked or deleted at the end of the window. Both the STIX ThreatIntelIndicators table and the legacy ThreatIntelligenceIndicator table are read.

```kql
union withsource = SourceTable isfuzzy = true ThreatIntelIndicators, ThreatIntelligenceIndicator
| where TimeGenerated between (endofday({{WINDOW_END}}) - 365d .. endofday({{WINDOW_END}}))
| extend IndicatorKey = coalesce(tostring(column_ifexists("Id", "")), tostring(column_ifexists("IndicatorId", ""))),
         Stix         = SourceTable endswith "ThreatIntelIndicators"
| where isnotempty(IndicatorKey)
| extend Observable = tolower(tostring(column_ifexists("ObservableKey", "")))
| extend Kind = case(
    Observable startswith "ipv4" or Observable startswith "ipv6" or isnotempty(tostring(column_ifexists("NetworkIP", ""))) or isnotempty(tostring(column_ifexists("NetworkSourceIP", ""))) or isnotempty(tostring(column_ifexists("NetworkDestinationIP", ""))) or isnotempty(tostring(column_ifexists("EmailSourceIpAddress", ""))), "IP address",
    Observable startswith "domain" or isnotempty(tostring(column_ifexists("DomainName", ""))), "Domain",
    Observable startswith "url" or isnotempty(tostring(column_ifexists("Url", ""))), "URL",
    Observable startswith "file" or isnotempty(tostring(column_ifexists("FileHashValue", ""))), "File hash",
    Observable startswith "email" or isnotempty(tostring(column_ifexists("EmailSenderAddress", ""))), "Email address",
    "Other")
| extend Source = coalesce(tostring(column_ifexists("SourceSystem", "")), "Not recorded")
| extend Until = iff(Stix, todatetime(column_ifexists("ValidUntil", datetime(null))), todatetime(column_ifexists("ExpirationDateTime", datetime(null))))
| extend IsActive = iff(Stix,
    coalesce(tobool(column_ifexists("IsActive", bool(null))), true) and not(coalesce(tobool(column_ifexists("IsDeleted", bool(null))), false)),
    coalesce(tobool(column_ifexists("Active", bool(null))), false))
    and (isnull(Until) or Until > endofday({{WINDOW_END}}))
| summarize arg_max(TimeGenerated, Kind, Source, IsActive) by Stix, IndicatorKey
| summarize Indicators = count(), Active = countif(IsActive), LastIngested = max(TimeGenerated) by Source, Kind
| order by Indicators desc
```

### TI.2 Threat intelligence matches by month and indicator type

Engine LA, combined only. CyberSOC. Detections from the threat intelligence analytics rules (TI map rules and Microsoft Threat Intelligence Analytics), informational severity excluded. Ticketed counts the ones correlated into an alert that opened an Atmosera ticket. A match means the indicator was observed in telemetry, not an investigation finding.

```kql
let Ticketed = SecurityIncident
| where TimeGenerated between ({{WINDOW_START}} .. now())
| summarize arg_max(TimeGenerated, *) by TenantId, IncidentNumber
| where CreatedTime between ({{WINDOW_START}} .. endofday({{WINDOW_END}}))
| where Severity != "Informational"
| where {{TICKET}}
| extend IncidentKey = strcat(TenantId, "|", IncidentNumber), Month = startofmonth(CreatedTime)
| mv-expand AlertId = AlertIds to typeof(string)
| project AlertId, IncidentKey, Classification, Month;
SecurityAlert
| where TimeGenerated between ({{WINDOW_START}} .. endofday({{WINDOW_END}}))
| summarize arg_max(TimeGenerated, AlertName, AlertSeverity, ProductName, ProviderName) by SystemAlertId
| where AlertSeverity != "Informational"
| where AlertName has_any ("TI map", "Threat Intelligence", "ThreatIntelligence") or ProviderName has "Threat Intelligence"
| extend Indicator = case(
    AlertName has "IP" or AlertName has "IPAddress", "IP address",
    AlertName has "Domain" or AlertName has "DNS", "Domain",
    AlertName has "URL", "URL",
    AlertName has "File" or AlertName has "Hash", "File hash",
    AlertName has "Email", "Email address",
    "Other")
| join kind=leftouter (Ticketed | distinct AlertId | extend IsTicketed = true) on $left.SystemAlertId == $right.AlertId
| summarize Detections = count(), Ticketed = countif(IsTicketed == true)
          by Month = startofmonth(TimeGenerated), Indicator, AlertSeverity
| order by Month asc, Indicator asc
```

### TI.3 Attack stages observed, by month

Engine LA, combined only. CyberSOC. The MITRE ATT&CK tactics Sentinel recorded on the detections correlated into the alerts OUT.1 counts, by the month the alert was created. A tactic is a detection-time label, not an investigation finding.

```kql
let Ticketed = SecurityIncident
| where TimeGenerated between ({{WINDOW_START}} .. now())
| summarize arg_max(TimeGenerated, *) by TenantId, IncidentNumber
| where CreatedTime between ({{WINDOW_START}} .. endofday({{WINDOW_END}}))
| where Severity != "Informational"
| where {{TICKET}}
| extend IncidentKey = strcat(TenantId, "|", IncidentNumber), Month = startofmonth(CreatedTime)
| mv-expand AlertId = AlertIds to typeof(string)
| project AlertId, IncidentKey, Classification, Month;
SecurityAlert
| where TimeGenerated between ({{WINDOW_START}} .. endofday({{WINDOW_END}}))
| summarize arg_max(TimeGenerated, Tactics) by SystemAlertId
| join kind=inner (Ticketed) on $left.SystemAlertId == $right.AlertId
| mv-expand Tactic = split(Tactics, ",") to typeof(string)
| extend Tactic = trim(@"\s+", Tactic)
| where isnotempty(Tactic) and Tactic != "Unknown"
| summarize Detections         = dcount(SystemAlertId),
            Alerts             = dcount(IncidentKey),
            TruePositiveAlerts = dcountif(IncidentKey, Classification == "TruePositive")
          by Month, Tactic
| order by Month asc, Alerts desc
```

### TI.4 Attack techniques observed

Engine LA, combined only. CyberSOC. The MITRE ATT&CK techniques on the same detections as TI.3, over the whole window, top 25 by alert count. Sentinel writes the techniques as a JSON list or a comma-separated list, and both are read.

```kql
let Ticketed = SecurityIncident
| where TimeGenerated between ({{WINDOW_START}} .. now())
| summarize arg_max(TimeGenerated, *) by TenantId, IncidentNumber
| where CreatedTime between ({{WINDOW_START}} .. endofday({{WINDOW_END}}))
| where Severity != "Informational"
| where {{TICKET}}
| extend IncidentKey = strcat(TenantId, "|", IncidentNumber), Month = startofmonth(CreatedTime)
| mv-expand AlertId = AlertIds to typeof(string)
| project AlertId, IncidentKey, Classification, Month;
SecurityAlert
| where TimeGenerated between ({{WINDOW_START}} .. endofday({{WINDOW_END}}))
| summarize arg_max(TimeGenerated, Techniques) by SystemAlertId
| join kind=inner (Ticketed) on $left.SystemAlertId == $right.AlertId
| mv-expand Technique = split(replace_regex(tostring(Techniques), @'[\[\]"\s]', ""), ",") to typeof(string)
| extend Technique = toupper(Technique)
| where Technique matches regex @"^T\d{4}(\.\d{3})?$"
| summarize Detections         = dcount(SystemAlertId),
            Alerts             = dcount(IncidentKey),
            TruePositiveAlerts = dcountif(IncidentKey, Classification == "TruePositive")
          by Technique
| order by Alerts desc, Detections desc, Technique asc
| take 25
```

### TI.5 Identity threat activity by month

Engine LA, read once from the workspace holding the most SigninLogs. CyberSOC. Interactive sign-ins. FailedPassword is error 50126, Lockouts 50053 (smart lockout or a blocked address), BlockedByCa 53003. SprayIps counts addresses that failed a password against 10 or more accounts in one day, a password spraying signal, not a confirmed attack. Risk levels need Entra ID P2: RiskHidden counts sign-ins whose risk the tenant cannot see. Counts only, no account names.

```kql
let Base = SigninLogs
| where TimeGenerated between ({{WINDOW_START}} .. endofday({{WINDOW_END}}));
let Spray = Base
| where ResultType == "50126"
| summarize Targets = dcount(UserPrincipalName) by IPAddress, Day = startofday(TimeGenerated)
| where Targets >= 10
| summarize SprayIps = dcount(IPAddress), SprayDays = dcount(Day) by Month = startofmonth(Day);
Base
| summarize SignIns         = count(),
            FailedPassword  = countif(ResultType == "50126"),
            TargetedUsers   = dcountif(UserPrincipalName, ResultType == "50126"),
            Lockouts        = countif(ResultType == "50053"),
            BlockedByCa     = countif(ResultType == "53003"),
            RiskySignIns    = countif(RiskLevelDuringSignIn in~ ("medium", "high")),
            RiskyUsers      = dcountif(UserPrincipalName, RiskLevelDuringSignIn in~ ("medium", "high")),
            SuccessfulRisky = countif(ResultType == "0" and RiskLevelDuringSignIn in~ ("medium", "high")),
            RiskHidden      = countif(RiskLevelDuringSignIn =~ "hidden")
          by Month = startofmonth(TimeGenerated)
| join kind=leftouter (Spray) on Month
| project Month, SignIns, FailedPassword, TargetedUsers, Lockouts, BlockedByCa, RiskySignIns, RiskyUsers,
          SuccessfulRisky, RiskHidden, SprayIps = coalesce(SprayIps, 0), SprayDays = coalesce(SprayDays, 0)
| order by Month asc
```

### TI.5-RISK Entra ID Protection risk detections by month and type

Engine LA, read once from the workspace holding the most AADUserRiskEvents. CyberSOC. Each risk detection at its latest record. Needs Entra ID P2 and the AADUserRiskEvents diagnostic setting. Read from the workspace holding the most AADUserRiskEvents in TI.0, else the one that holds the sign-ins. Counts only, no account names.

```kql
AADUserRiskEvents
| where TimeGenerated between ({{WINDOW_START}} .. now())
| summarize arg_max(TimeGenerated, RiskEventType, RiskLevel, DetectedDateTime, UserId) by Id
| extend Detected = coalesce(todatetime(DetectedDateTime), TimeGenerated)
| where Detected between ({{WINDOW_START}} .. endofday({{WINDOW_END}}))
| summarize Detections = count(),
            Users      = dcount(UserId),
            High       = countif(RiskLevel =~ "high"),
            Medium     = countif(RiskLevel =~ "medium")
          by Month = startofmonth(Detected), RiskEventType
| order by Month asc, Detections desc
```

### TI.6 Inbound email threats by month

Engine LA, read once from the workspace holding the most EmailEvents. CyberSOC. Needs the Microsoft Defender XDR connector to stream EmailEvents into Sentinel, and TI.0 says whether it does. Read once, from the workspace holding the most EmailEvents, because a tenant-wide table streamed into several workspaces would otherwise be counted more than once. ThreatsBlocked is phishing or malware not delivered to the inbox at first delivery. Post-delivery removal is DP.7.

```kql
EmailEvents
| where TimeGenerated between ({{WINDOW_START}} .. endofday({{WINDOW_END}}))
| where EmailDirection == "Inbound"
| extend Phish = ThreatTypes has "Phish", Malware = ThreatTypes has "Malware", Spam = ThreatTypes has "Spam"
| summarize Messages         = count(),
            Phish            = countif(Phish),
            Malware          = countif(Malware),
            Spam             = countif(Spam),
            ThreatsBlocked   = countif((Phish or Malware) and DeliveryAction in ("Blocked", "Junked", "Replaced")),
            ThreatsDelivered = countif((Phish or Malware) and DeliveryAction == "Delivered")
          by Month = startofmonth(TimeGenerated)
| order by Month asc
```

### TI.7 Malware detected on Azure virtual machines, last 30 days

Engine AH. CyberSOC. Microsoft Defender Antivirus detections, Azure virtual machines only as every device measure since 1.14.0. Advanced Hunting holds 30 days, so this reads the last 30 days whatever the window. Threat names only, no device names.

```kql
DeviceEvents
| where Timestamp between (ago(30d) .. now())
| where ActionType == "AntivirusDetection"
| join kind=inner (
    DeviceInfo
    | where Timestamp between (ago(30d) .. now())
    | summarize arg_max(Timestamp, AzureResourceId) by DeviceId
    | where isnotempty(AzureResourceId)   // Azure virtual machines only
    | where AzureResourceId !contains "{{MRG}}"
  ) on DeviceId
| extend Fields = parse_json(AdditionalFields)
| extend Threat        = tostring(Fields.ThreatName),
         WasRemediated = tobool(Fields.WasRemediated),
         WasExecuting  = tobool(Fields.WasExecutingWhileDetected)
| extend Threat = iff(isempty(Threat), "Not named", Threat)
| summarize Detections   = count(),
            Devices      = dcount(DeviceId),
            Remediated   = countif(WasRemediated),
            WasExecuting = countif(WasExecuting)
          by Threat
| order by Detections desc
| take 25
```

### VA.1 Open vulnerabilities on Azure virtual machines by severity

Engine AH. CyberSOC. Current state only. Exposures counts each vulnerable software on each machine. ExploitableCves are CVEs with public exploit code per Defender, not a CISA KEV listing.

```kql
DeviceTvmSoftwareVulnerabilities
| join kind=inner (
    DeviceInfo
    | where Timestamp between (ago(7d) .. now())
    | summarize arg_max(Timestamp, AzureResourceId) by DeviceId
    | where isnotempty(AzureResourceId)   // Azure virtual machines only
    | where AzureResourceId !contains "{{MRG}}"
  ) on DeviceId| join kind=leftouter (
    DeviceTvmSoftwareVulnerabilitiesKB
    | project CveId, IsExploitAvailable
  ) on CveId
| extend Exploitable = tobool(IsExploitAvailable)
| summarize Cves               = dcount(CveId, 4),
            Devices            = dcount(DeviceId, 4),
            Exposures          = count(),
            ExploitableCves    = dcountif(CveId, Exploitable, 4),
            ExploitableDevices = dcountif(DeviceId, Exploitable, 4)
          by VulnerabilitySeverityLevel
| order by VulnerabilitySeverityLevel asc
```

### VA.2 Most exposed software on Azure virtual machines

Engine AH. CyberSOC. Current state only, top 15 ranked by exploitable, critical and high CVEs, then machines. Software names only, no machine names.

```kql
DeviceTvmSoftwareVulnerabilities
| join kind=inner (
    DeviceInfo
    | where Timestamp between (ago(7d) .. now())
    | summarize arg_max(Timestamp, AzureResourceId) by DeviceId
    | where isnotempty(AzureResourceId)   // Azure virtual machines only
    | where AzureResourceId !contains "{{MRG}}"
  ) on DeviceId| join kind=leftouter (
    DeviceTvmSoftwareVulnerabilitiesKB
    | project CveId, IsExploitAvailable
  ) on CveId
| summarize Devices         = dcount(DeviceId, 4),
            Cves            = dcount(CveId, 4),
            Critical        = dcountif(CveId, VulnerabilitySeverityLevel == "Critical", 4),
            High            = dcountif(CveId, VulnerabilitySeverityLevel == "High", 4),
            ExploitableCves = dcountif(CveId, tobool(IsExploitAvailable), 4)
          by SoftwareVendor, SoftwareName
| order by ExploitableCves desc, Critical desc, High desc, Devices desc
| take 15
```

### VA.3 Vulnerabilities published in the window and open now, by month

Engine AH. CyberSOC. CVEs published in each month of the window that are open on Azure virtual machines at collection: the new exposure each month added.

```kql
DeviceTvmSoftwareVulnerabilities
| join kind=inner (
    DeviceInfo
    | where Timestamp between (ago(7d) .. now())
    | summarize arg_max(Timestamp, AzureResourceId) by DeviceId
    | where isnotempty(AzureResourceId)   // Azure virtual machines only
    | where AzureResourceId !contains "{{MRG}}"
  ) on DeviceId| join kind=inner (
    DeviceTvmSoftwareVulnerabilitiesKB
    | where PublishedDate between ({{WINDOW_START}} .. endofday({{WINDOW_END}}))
    | project CveId, PublishedDate, IsExploitAvailable
  ) on CveId
| summarize Cves            = dcount(CveId, 4),
            Devices         = dcount(DeviceId, 4),
            Critical        = dcountif(CveId, VulnerabilitySeverityLevel == "Critical", 4),
            High            = dcountif(CveId, VulnerabilitySeverityLevel == "High", 4),
            ExploitableCves = dcountif(CveId, tobool(IsExploitAvailable), 4)
          by Month = startofmonth(PublishedDate)
| order by Month asc
```

## 6. Change request inputs

CyberSOC collector 1.1.0, 1.2.0 for NB.6-PAAS-DETAIL, 1.3.0 for DP.4-VMSS-ELIGIBILITY and the ScaleSet column of DP.4-ELIGIBILITY, 1.4.0 for the VmId column of DP.4-ELIGIBILITY and the UniqueId column of DP.4-VMSS-ELIGIBILITY, and 1.6.0 for NB.2-DETAIL. The per-resource lists behind the hardening counts, read by `New-CyberSocChangeRequests.ps1`
to name the resources in each change request and its client email (see `New-CyberSocChangeRequests.README.md`).
From collector 1.5.0 the collector runs `New-CyberSocChangeRequests.ps1` at the end of each collection, so the pack
holds `05-change-requests` (`-SkipChangeRequests` turns it off). The report embeds counts only. These lists name
client resources and stay internal.

### P0.7 Subscription names

Engine ARG. Subscription level, so no managed resource group exclusion. The display name of each subscription in scope, so a change request names the subscription beside its ID.

```kql
resourcecontainers
| where type =~ "microsoft.resources/subscriptions"
| project subscriptionId, SubscriptionName = name
| order by SubscriptionName asc
```

### NB.2-DETAIL Internet-exposed management port rules with their properties and attachments

Engine ARG. CyberSOC collector 1.6.0. The rules NB.2 lists, read the same way: allow inbound from any address (`*`), `Internet` or `0.0.0.0/0` on 22, 3389, 5985, 5986, `*` or a port range. One row per rule with everything CR-16 needs to change it and to recreate it on rollback: the subscription, the network security group and rule resource IDs, priority, direction, access, protocol, the source and destination prefixes and ports as lists (the single and the list form of each property together, so an empty single form shows as an empty entry), the description, the destination application security groups, and the association (Subnet, NIC or Unassociated, as in NB.2). `Subnets` and `Nics` list what the group is attached to, and `NicVms` names the virtual machine of each network interface that names the group. `ApplianceNicIds` and `ApplianceSubnetIds` list every network interface of a network virtual appliance (the P0.6-APPLIANCES pattern) and the subnets it sits in, the same on every row, so a rule that reaches an appliance through its network interface or through the group on its subnet is found. A missing property reads as an empty list. `mv-expand` takes up to 1,000 rules per group, the most a group can hold, rather than its default of 128. CR-16 closes the rules on a workload subnet or network interface that name their ports, and leaves to the index notes a group attached only to appliance network interfaces (an untrust interface takes internet traffic by design), a group that reaches an appliance through a subnet or as well as other resources (for review), a group attached to nothing (a cleanup item) and a rule whose ports are `*` or a range (for review). Feeds CR-16 and its client email, with P0.3 for Defender for Servers Plan 2 by subscription, which just-in-time VM access needs.

```kql
resources
| where type =~ "microsoft.network/networksecuritygroups"
| where id !contains "{{MRG}}"
| extend NsgKey  = tolower(id),
         Subnets = coalesce(properties.subnets, dynamic([])),
         Nics    = coalesce(properties.networkInterfaces, dynamic([]))
| mv-expand Rule = properties.securityRules limit 1000
| where tostring(Rule.properties.access) =~ "Allow"
    and tostring(Rule.properties.direction) =~ "Inbound"
| extend SourcePrefixes   = array_concat(pack_array(tostring(Rule.properties.sourceAddressPrefix)),
                                         coalesce(Rule.properties.sourceAddressPrefixes, dynamic([]))),
         DestinationPorts = array_concat(pack_array(tostring(Rule.properties.destinationPortRange)),
                                         coalesce(Rule.properties.destinationPortRanges, dynamic([])))
| extend SourceText = tostring(SourcePrefixes), PortText = tostring(DestinationPorts)
| where SourceText contains '"*"' or SourceText contains '"Internet"' or SourceText contains '"0.0.0.0/0"'
| where PortText contains '"*"' or PortText contains '"22"' or PortText contains '"3389"'
     or PortText contains '"5985"' or PortText contains '"5986"' or PortText contains "-"
// Each network interface the group is attached to directly, with its virtual machine.
| join kind=leftouter (
    resources
    | where type =~ "microsoft.network/networkinterfaces"
    | extend NsgKey = tolower(tostring(properties.networkSecurityGroup.id))
    | where isnotempty(NsgKey)
    | summarize NicVms = make_list(pack("NicId", tolower(id), "VmId", tolower(tostring(properties.virtualMachine.id)))) by NsgKey
  ) on NsgKey
// Every network interface of a network virtual appliance and the subnets it sits in, so CR-16 can leave out a
// rule that reaches an appliance through its network interface or through a subnet group.
| extend ApplianceKey = 1
| join kind=leftouter (
    resources
    | where type =~ "microsoft.network/networkinterfaces"
    | extend VmKey = tolower(tostring(properties.virtualMachine.id))
    | join kind=inner (
        resources
        | where type =~ "microsoft.compute/virtualmachines"
        | where {{APPLIANCE}}   // network virtual appliances, see P0.6-APPLIANCES
        | project VmKey = tolower(id)
      ) on VmKey
    | mv-expand IpConfig = properties.ipConfigurations
    | summarize ApplianceNicIds    = make_set(tolower(id)),
                ApplianceSubnetIds = make_set(tolower(tostring(IpConfig.properties.subnet.id)))
    | extend ApplianceKey = 1
  ) on ApplianceKey
| extend Association = case(0 < array_length(Subnets), "Subnet", 0 < array_length(Nics), "NIC", "Unassociated"),
         RangeNeedsReview = PortText contains "-"
| project subscriptionId, resourceGroup, NSG = name, NsgId = id,
          RuleName    = tostring(Rule.name), RuleId = tostring(Rule.id),
          Priority    = toint(Rule.properties.priority),
          Direction   = tostring(Rule.properties.direction), Access = tostring(Rule.properties.access),
          Protocol    = tostring(Rule.properties.protocol),
          SourcePrefixes,
          SourcePorts = array_concat(pack_array(tostring(Rule.properties.sourcePortRange)),
                                     coalesce(Rule.properties.sourcePortRanges, dynamic([]))),
          DestinationPrefixes = array_concat(pack_array(tostring(Rule.properties.destinationAddressPrefix)),
                                             coalesce(Rule.properties.destinationAddressPrefixes, dynamic([]))),
          DestinationAsgs = coalesce(Rule.properties.destinationApplicationSecurityGroups, dynamic([])),
          DestinationPorts,
          Description = tostring(Rule.properties.description),
          Association, RangeNeedsReview,
          Subnets, Nics,
          NicVms             = coalesce(NicVms, dynamic([])),
          ApplianceNicIds    = coalesce(ApplianceNicIds, dynamic([])),
          ApplianceSubnetIds = coalesce(ApplianceSubnetIds, dynamic([]))
| order by subscriptionId asc, resourceGroup asc, NSG asc, Priority asc
```

### NB.4-DETAIL Web and Function Apps without HTTPS only

Engine ARG. The sites NB.4 counts as not HTTPS only, one row each, with the default host name. Feeds CR-08 and its client email.

```kql
resources
| where type =~ "microsoft.web/sites"
| where id !contains "{{MRG}}"
| where not(coalesce(tobool(properties.httpsOnly), false))
| project Name = name, ResourceId = id, Kind = kind, resourceGroup, subscriptionId,
          DefaultHostName = tostring(properties.defaultHostName)
| order by subscriptionId asc, resourceGroup asc, Name asc
```

### NB.5-DETAIL App Service sites below minimum TLS 1.2

Engine ARG. The site configurations NB.5 counts as below TLS 1.2, one row per site. The site name, resource group and subscription are read from the configuration ID, because the config record is not the site. Feeds CR-04, which leaves out a site whose value reads empty, since App Service applies 1.2 when no minimum is set.

```kql
appserviceresources
| where type =~ "microsoft.web/sites/config"
| where id !contains "{{MRG}}"
// appserviceresources returns site config keys in PascalCase and dynamic access is case-sensitive.
| extend MinTlsVersion = tostring(coalesce(properties.MinTlsVersion, properties.minTlsVersion))
| where not(MinTlsVersion in ("1.2", "1.3"))
| extend Parts = split(id, "/")
| project Name = tostring(Parts[8]), ResourceId = tostring(split(id, "/config/")[0]),
          resourceGroup = tostring(Parts[4]), subscriptionId = tostring(Parts[2]), MinTlsVersion
| order by subscriptionId asc, resourceGroup asc, Name asc
```

### NB.6-DETAIL Azure SQL servers below minimum TLS 1.2

Engine ARG. The servers NB.6 counts as below TLS 1.2, one row each. An empty value or None means no minimum is set. Feeds CR-05.

```kql
resources
| where type =~ "microsoft.sql/servers"
| where id !contains "{{MRG}}"
| extend MinimalTlsVersion = tostring(properties.minimalTlsVersion)
| where not(MinimalTlsVersion in ("1.2", "1.3"))
| project Name = name, ResourceId = id, resourceGroup, subscriptionId, MinimalTlsVersion
| order by subscriptionId asc, resourceGroup asc, Name asc
```

### NB.6-PAAS-DETAIL Redis caches, Service Bus and Event Hubs namespaces and Cosmos DB accounts below minimum TLS 1.2

Engine ARG. CyberSOC collector 1.2.0. One row per Azure Cache for Redis cache, Service Bus namespace, Event Hubs namespace or Azure Cosmos DB account whose minimum TLS version is below 1.2 or not set, with its resource type. Cosmos DB names the property minimalTlsVersion, with the values Tls, Tls11 and Tls12. An empty value means the property is missing. Feeds CR-11 (Redis), CR-12 (Service Bus), CR-13 (Event Hubs, with a client email) and CR-14 (Cosmos DB).

```kql
resources
| where type in~ ("microsoft.cache/redis", "microsoft.servicebus/namespaces",
                  "microsoft.eventhub/namespaces", "microsoft.documentdb/databaseaccounts")
| where id !contains "{{MRG}}"
// Cosmos DB names the property minimalTlsVersion. A missing property reads as not set.
| extend ResourceType      = tolower(type),
         MinimumTlsVersion = tostring(coalesce(properties.minimumTlsVersion, properties.minimalTlsVersion))
| where not(MinimumTlsVersion in ("1.2", "1.3", "Tls12", "Tls13"))
| project Name = name, ResourceId = id, ResourceType, resourceGroup, subscriptionId, MinimumTlsVersion
| order by ResourceType asc, subscriptionId asc, resourceGroup asc, Name asc
```

### DP.1-DETAIL Storage accounts without secure transfer, minimum TLS 1.2 or anonymous access off

Engine ARG. One row per storage account DP.1 counts against secure transfer, minimum TLS 1.2 or anonymous blob access, read the same way: a missing allowBlobPublicAccess means anonymous access is allowed. NfsV3 and the FileStorage kind mark accounts that may serve NFS, which CR-02 leaves out because NFS mounts are refused once secure transfer is required. CR-07 also leaves out FileStorage accounts, which hold no blob service. Feeds CR-02, CR-03 and CR-07. CR-07 takes only the accounts whose containers DP.1-CONTAINERS listed in full with none set to Blob or Container access, and names the others in the index.

```kql
resources
| where type =~ "microsoft.storage/storageaccounts"
| where id !contains "{{MRG}}"
| extend SecureTransfer        = coalesce(tobool(properties.supportsHttpsTrafficOnly), false),
         MinimumTlsVersion     = tostring(properties.minimumTlsVersion),
         AllowBlobPublicAccess = coalesce(tobool(properties.allowBlobPublicAccess), true),
         NfsV3                 = coalesce(tobool(properties.isNfsV3Enabled), false)
| where not(SecureTransfer) or not(MinimumTlsVersion in ("TLS1_2", "TLS1_3")) or AllowBlobPublicAccess
| project Name = name, ResourceId = id, Kind = kind, resourceGroup, subscriptionId,
          SecureTransfer, MinimumTlsVersion, AllowBlobPublicAccess, NfsV3
| order by subscriptionId asc, resourceGroup asc, Name asc
```

### DP.2-DETAIL Key vaults without purge protection

Engine ARG. The vaults DP.2 counts as without purge protection, one row each, with the soft delete retention that purge protection will enforce, 90 days when the property is missing. Feeds CR-06.

```kql
resources
| where type =~ "microsoft.keyvault/vaults"
| where id !contains "{{MRG}}"
| where not(coalesce(tobool(properties.enablePurgeProtection), false))
| project Name = name, ResourceId = id, resourceGroup, subscriptionId,
          RetentionDays = coalesce(toint(properties.softDeleteRetentionInDays), 90)
| order by subscriptionId asc, resourceGroup asc, Name asc
```

### DP.4-ELIGIBILITY Virtual machines that can take encryption at host

Engine ARG, then the Compute resource SKUs API. The virtual machines without encryption at host, network virtual appliances and scale sets left out, with whether each can take it. A machine that ever used Azure Disk Encryption cannot: its disks keep an encryptionSettingsCollection, enabled or not, or it carries an ADE extension. Nor can a machine with an attached Ultra Disk or Premium SSD v2 that uses 512e sectors and was created before May 13, 2023. Size support is not in Resource Graph, so for each region the collector reads `GET https://management.azure.com/subscriptions/<id>/providers/Microsoft.Compute/skus?api-version=2021-07-01&$filter=location eq '<region>'` (Reader is enough) through one of the subscriptions there, trying the next one if a read fails, and takes the EncryptionAtHostSupported capability of each size. A size the list cannot answer for, or a region whose list could not be read, reads Unknown. The result reads PARTIAL when some lists could not be read or Resource Graph truncated the machine list, and FAILED when no list could be read. From collector 1.3.0 each row carries ScaleSet, the lowercase ID of the Flexible scale set the machine belongs to (empty for a standalone machine). From collector 1.4.0 each row carries VmId (`properties.vmId`), the unique ID Azure gives the machine. A machine deleted and created again under the same name gets a new one, so CR-09 and CR-15 list it beside each name and change only a machine whose VM ID still matches under Overview > JSON View, never one matched by its name alone. CR-09 lists only the eligible machines and names the others in the index, so no machine is deallocated for a change Azure would reject, and leaves to CR-15 the machines of a Flexible scale set that CR-15 changes, which requires every one of them to be eligible. The machines of a scale set CR-15 leaves out stay in CR-09.

```kql
resources
| where type =~ "microsoft.compute/virtualmachines"
| where id !contains "{{MRG}}"
| where not({{APPLIANCE}})   // network virtual appliances, see P0.6-APPLIANCES
| where not(coalesce(tobool(properties.securityProfile.encryptionAtHost), false))
| project VmKey = tolower(id), ResourceId = id, Name = name, resourceGroup, subscriptionId, Location = tolower(location),
          Size = tostring(properties.hardwareProfile.vmSize),
          PowerState = tostring(properties.extended.instanceView.powerState.code),
          ScaleSet = tolower(tostring(properties.virtualMachineScaleSet.id)),
          VmId = tostring(properties.vmId)
| join kind=leftouter (
    resources
    | where type =~ "microsoft.compute/disks"
    | where isnotnull(properties.encryptionSettingsCollection)
    | summarize AdeDisks = count() by VmKey = tolower(tostring(managedBy))
  ) on VmKey
| join kind=leftouter (
    resources
    | where type =~ "microsoft.compute/virtualmachines/extensions"
    | where tostring(properties.type) in~ ("AzureDiskEncryption", "AzureDiskEncryptionForLinux")
    | summarize AdeExtensions = count() by VmKey = tolower(tostring(split(id, "/extensions/")[0]))
  ) on VmKey
| join kind=leftouter (
    resources
    | where type =~ "microsoft.compute/disks"
    | where tostring(sku.name) in~ ("UltraSSD_LRS", "PremiumV2_LRS")
    | where toint(properties.creationData.logicalSectorSize) == 512
    | where todatetime(properties.timeCreated) < datetime(2023-05-13)
    | summarize OldSectorDisks = count() by VmKey = tolower(tostring(managedBy))
  ) on VmKey
| extend AdeUsed       = coalesce(AdeDisks, 0) > 0 or coalesce(AdeExtensions, 0) > 0,
         OldSectorDisk = coalesce(OldSectorDisks, 0) > 0
| project Name, ResourceId, resourceGroup, subscriptionId, Location, Size, PowerState, ScaleSet, VmId, AdeUsed, OldSectorDisk
| order by subscriptionId asc, resourceGroup asc, Name asc
```

### DP.4-VMSS-ELIGIBILITY Scale sets that can take encryption at host

Engine ARG, then the Compute resource SKUs API. CyberSOC collector 1.3.0. The scale sets whose model, `virtualMachineProfile.securityProfile.encryptionAtHost`, is not set, network virtual appliances left out, one row each with the orchestration mode (a scale set without one is Uniform), the upgrade policy mode, the instance count (`sku.capacity`), the size of the model and, from collector 1.4.0, the unique ID (`properties.uniqueId`) that CR-15 checks under Overview > JSON View before it changes the scale set, and whether the model can take encryption at host. A scale set that ever used Azure Disk Encryption cannot: the extensions on its model are searched for AzureDiskEncryption, which also matches AzureDiskEncryptionForLinux. An extension removed from the model leaves no trace in Resource Graph, which is a limit of this check. The disks of a Uniform instance are not Resource Graph resources, so an Ultra Disk or Premium SSD v2 in the model of a scale set created before May 13, 2023, or with no creation time, rules it out, since those disks may use 512e sectors from before that date. Size support is read as in DP.4-ELIGIBILITY, one size list per region. A scale set in the node resource group of an AKS cluster (`properties.nodeResourceGroup` of a `microsoft.containerservice/managedclusters` resource in the same subscription), or with a tag that starts with `aks-managed-`, is an AKS node pool. AKS manages its model and sets encryption at host only when a node pool is created, so it is never eligible, its size is not read, and the row names the cluster, its resource group and the node pool (`aks-managed-poolName`). A Flexible scale set without a model has nothing to set and its size is not read either. Its machines are standalone virtual machines in DP.4-ELIGIBILITY and CR-09. The result reads PARTIAL when a size list it needed could not be read or Resource Graph truncated the list, and FAILED when none it needed could be read. Feeds CR-15, its client email and the AKS note in the change request index. A Flexible scale set goes into CR-15 only when DP.4-ELIGIBILITY is complete (OK or EMPTY) and each of its machines there is eligible too.

```kql
resources
| where type =~ "microsoft.compute/virtualmachinescalesets"
| where id !contains "{{MRG}}"
| where not({{APPLIANCE}})   // network virtual appliances, see P0.6-APPLIANCES
| where not(coalesce(tobool(properties.virtualMachineProfile.securityProfile.encryptionAtHost), false))
// AKS creates the scale set of each node pool in the node resource group of its cluster.
| extend NodeRgKey = strcat(tolower(subscriptionId), "/", tolower(resourceGroup))
| join kind=leftouter (
    resources
    | where type =~ "microsoft.containerservice/managedclusters"
    | project NodeRgKey = strcat(tolower(subscriptionId), "/", tolower(tostring(properties.nodeResourceGroup))),
              AksCluster = name, AksClusterResourceGroup = resourceGroup
  ) on NodeRgKey
| extend Model = properties.virtualMachineProfile
| extend OrchestrationMode = coalesce(tostring(properties.orchestrationMode), "Uniform"),
         UpgradePolicy     = tostring(properties.upgradePolicy.mode),
         Instances         = toint(sku.capacity),
         UniqueId          = tostring(properties.uniqueId),
         Size              = tostring(sku.name),
         HasModel          = isnotnull(Model),
         AdeUsed           = tostring(Model.extensionProfile.extensions) contains "AzureDiskEncryption",
         OldSectorDisk     = tostring(Model.storageProfile.dataDisks) has_any ("UltraSSD_LRS", "PremiumV2_LRS")
                             and coalesce(todatetime(properties.timeCreated), datetime(2000-01-01)) < datetime(2023-05-13),
         AksNodePool       = tostring(tags["aks-managed-poolName"]),
         Aks               = isnotempty(AksCluster) or tostring(bag_keys(tags)) contains "aks-managed-"
| project Name = name, ResourceId = id, resourceGroup, subscriptionId, Location = tolower(location), OrchestrationMode,
          UpgradePolicy, Instances, Size, UniqueId, HasModel, AdeUsed, OldSectorDisk, Aks, AksCluster, AksClusterResourceGroup, AksNodePool
| order by subscriptionId asc, resourceGroup asc, Name asc
```

### DR.6-COVERAGE ATMO-MXDR diagnostic logging initiative coverage by subscription

Engine ARG. The resources with a policy state from the ATMO-MXDR-DIAG initiative in each subscription, counted only for assignments at subscription or management group scope, since an assignment on one resource group leaves the rest of the subscription out. Policy states are read per resource, so an assignment at a management group counts for every subscription under it. A subscription in the pack without a row has no evaluated assignment, and CR-01 assigns the initiative there. A PARTIAL result stops CR-01, since a subscription without the initiative cannot be told from one that was not read. An assignment made shortly before collection shows no state until its first compliance scan, so the index asks to confirm under Policy > Assignments before raising CR-01.

```kql
policyresources
| where type =~ "microsoft.policyinsights/policystates"
| extend AssignmentName  = tostring(properties.policyAssignmentName),
         InitiativeName  = tostring(properties.policySetDefinitionName),
         AssignmentId    = tolower(tostring(properties.policyAssignmentId)),
         AssignmentScope = tolower(tostring(properties.policyAssignmentScope)),
         ResourceId      = tolower(tostring(properties.resourceId))
| where AssignmentName contains "ATMO-MXDR-DIAG" or InitiativeName contains "ATMO-MXDR-DIAG"
| where AssignmentScope !contains "/resourcegroups/"
| where ResourceId !contains "{{MRG}}"
| extend SubscriptionKey = tostring(split(ResourceId, "/")[2])
| summarize Resources = dcount(ResourceId), Assignments = dcount(AssignmentId) by subscriptionId = SubscriptionKey
| order by subscriptionId asc
```

### DR.6-NONCOMPLIANT Resources not compliant with the ATMO-MXDR diagnostic logging initiative

Engine ARG. The resources DR.6-INITIATIVE counts as NonCompliant, one row per resource and assignment, with the assignment ID and scope and the policies each one fails: the reference ID inside the initiative, or the definition name. A remediation task belongs to one assignment and one policy, so CR-10 lists a task for each pair and each resource once, and an initiative assigned once per subscription under the same name keeps each assignment apart. When DR.6-INITIATIVE is EMPTY, CR-01 assigns the initiative instead, once at a management group named with -ManagementGroup or at each subscription, and counts the covered resource types from P0.5.

```kql
policyresources
| where type =~ "microsoft.policyinsights/policystates"
| extend AssignmentName = tostring(properties.policyAssignmentName),
         InitiativeName = tostring(properties.policySetDefinitionName),
         DefinitionName = tostring(properties.policyDefinitionName),
         ReferenceId    = tostring(properties.policyDefinitionReferenceId),
         Compliance     = tostring(properties.complianceState),
         ResourceId     = tolower(tostring(properties.resourceId)),
         ResourceType   = tolower(tostring(properties.resourceType)),
         AssignmentId   = tolower(tostring(properties.policyAssignmentId)),
         AssignmentScope = tostring(properties.policyAssignmentScope)
| where AssignmentName contains "ATMO-MXDR" or InitiativeName contains "ATMO-MXDR" or DefinitionName contains "ATMO-MXDR"
| where ResourceId !contains "{{MRG}}"
| where Compliance =~ "NonCompliant"
| extend Policy = iff(isnotempty(ReferenceId), ReferenceId, DefinitionName)
| summarize Policies = strcat_array(make_set(Policy), ", ") by ResourceId, ResourceType, AssignmentName, AssignmentId, AssignmentScope
| order by ResourceType asc, ResourceId asc
```
