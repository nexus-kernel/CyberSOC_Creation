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

CyberSOC collector 1.1.0, 1.2.0 for NB.6-PAAS-DETAIL, 1.3.0 for DP.4-VMSS-ELIGIBILITY and the ScaleSet column of DP.4-ELIGIBILITY, 1.4.0 for the VmId column of DP.4-ELIGIBILITY and the UniqueId column of DP.4-VMSS-ELIGIBILITY, 1.6.0 for NB.2-DETAIL, 1.7.0 for NB.5-FTPS-DETAIL, 1.8.0 for DP.1-CONTAINERS-DETAIL, 1.9.0 for IA.15-DISABLED, IA.15-RBAC and IA.15-ENTRA, 1.10.0 for the group membership columns of IA.15-RBAC and IA.15-ENTRA (MemberOfId, MemberOfName, MemberOfType, GroupPath, GroupPathIds), which CR-19 needs to remove an account from its group, 1.11.0 for the licensing check (LIC.1-SKUS to LIC.5-MATRIX) and the Extensions column of P0.3, which gate the change requests on the licenses they need, 1.12.0 for the emergency access accounts (IA.16-ACCOUNTS and IA.16-GROUPS) that every Conditional Access change excludes, 1.13.0 for the ScmMinTlsVersion column of NB.5-DETAIL, the SCM (Kudu) site minimum TLS version CR-04 sets, 1.14.0 for NB.5-FTPAUTH and NB.5-FTPAUTH-DETAIL, the FTP basic authentication setting of each App Service app that CR-17 turns off, 1.15.0 for DR.6-MYSQLAUDIT, the audit log parameters of each MySQL flexible server that CR-01 and CR-10 set, 1.16.0 for IA.8-SIGNINS-NONINTERACTIVE, the non-interactive legacy sign-ins CR-21 needs before it removes an exclusion or blocks legacy authentication, 1.17.0 for EW.4-SERVERS and EW.4-AVMODE, the Windows servers with their attack surface reduction rules and the Microsoft Defender Antivirus mode CR-22 needs, 1.18.0 for EW.10-ASSESSMENT, the virtual machines without periodic assessment CR-23 turns it on for, and 1.19.0 for the PhysicalIds, ProfileType and SystemLabels columns of LIC.4-DEVICES, which CR-24 needs to leave out Windows Autopilot devices, printers and system-managed devices before it disables the stale devices, 1.20.0 for DP.1-SOFTDELETE, the blob and container soft delete of each storage account with its lifecycle rules and whether Site Recovery uses it, which CR-25 needs before it turns soft delete on, 1.21.0 for IA.17-GUESTS, IA.17-RBAC and IA.17-ENTRA, the enabled guest accounts with when each was created and last signed in and the roles they hold, which CR-26 needs before it removes the Azure roles of the guests the client no longer needs, and 1.22.0 for POS.9-GUARDRAILS, the assignments of the guardrail policy definitions at the subscriptions and the management groups above them, which the guardrail template CR-27 reads before it offers a policy. The per-resource lists behind the hardening counts, read by `New-CyberSocChangeRequests.ps1`
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

### LIC.1-SKUS to LIC.5-MATRIX The licensing check

CyberSOC collector 1.11.0, phase P2 Licensing. The Defender for Endpoint plan and its usage, and the licenses each change request needs. The results name devices and stay internal. `New-CyberSocChangeRequests.ps1` derives the matrix again from the four reads below with `report/Get-CyberSocLicensing.ps1`, the code that writes LIC.5-MATRIX, and gates its change requests on it: a change request whose capability reads Not licensed is not written, and one reading Unknown is written with a note to confirm the license before sending. A read that failed, was refused or is partial reads Unknown, never Not licensed.

The Licenses page of the Defender portal (Settings > Endpoints > Licenses: the subscription state, the available and assigned licenses, a usage estimate from the users signing in to onboarded devices, and the mixed mode setting) has no API. Read it by hand, with Security Administrator, or License Administrator and Defender for Endpoint Administrator, and pass the plan as `-DefenderEndpointPlan` Plan1, Plan2, Business or Mixed. The SecOps worklist asks for it on every collection, with the enforcement scope of security settings management (Settings > Endpoints > Configuration management > Enforcement scope), which has no API either.

LIC.1-SKUS, the licenses in the tenant. Needs LicenseAssignment.Read.All (Directory.Read.All and Organization.Read.All also work). The endpoint takes `$select` only. A license is matched on service plan IDs (Microsoft Learn, Product names and service plan identifiers for licensing), since bundles carry the plans, and counts while its SKU reads Enabled or Warning and the plan is not Disabled or Error. The Defender for Endpoint server SKU (MDATP_Server) carries WINDEFATP, the Plan 2 plan, so it is matched by its SKU ID and never counted as Plan 2.

```http
GET https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuId,skuPartNumber,appliesTo,capabilityStatus,consumedUnits,prepaidUnits,servicePlans
```

| Capability | Service plans (ID) |
|---|---|
| Microsoft Entra ID P1 | AAD_PREMIUM (41781fb2-bc02-4b7c-bd55-b576c07bb09d), or AAD_PREMIUM_P2 |
| Microsoft Entra ID P2 | AAD_PREMIUM_P2 (eec0eb4f-6444-4f95-aba0-50c24d67f998) |
| Defender for Endpoint Plan 1 | MDE_LITE (292cc034-7b7c-4950-aaf5-943befd3f1d4) |
| Defender for Endpoint Plan 2 | WINDEFATP (871d91ec-ec1a-452b-a83f-bd76c7d770ef), outside the server SKU |
| Defender for Business | MDE_SMB (bfc1bbd9-981b-4f71-9b82-17c35fd0e2a4) |
| Defender for Endpoint for servers | SKU MDATP_Server (509e8ab6-0274-4cda-bcbd-bd164fd562c4). Learn lists no SKU for Defender for Business servers |
| Defender for Endpoint user license, which security settings management needs | MDE_LITE, WINDEFATP, MDE_SMB or Intune_Defender (MDE_SecurityManagement, 1689aade-3d6a-4bfc-b017-46d2672df5ad), outside the server SKU |
| Defender Vulnerability Management premium | TVM_PREMIUM_1 (36810a13-b903-490a-aa45-afbeb7540832) |
| Defender for Office 365 Plan 1 | ATP_ENTERPRISE (f20fedf3-f3c3-43c3-8267-2bfdd51c0939), ATP_ENTERPRISE_GOV (493ff600-6a2b-4db6-ad37-a7d4eb214516), or Plan 2. Office 365 E3 and Microsoft 365 E3 carry ATP_ENTERPRISE from July 1, 2026 |
| Defender for Office 365 Plan 2 | THREAT_INTELLIGENCE (8e0c0a52-6a6c-4d40-8370-dd62790dcd70), THREAT_INTELLIGENCE_GOV (900018f1-0cdb-4ecb-94d4-90281760fdc6) |
| Defender for Identity | ATA (14ab5db5-e6c4-4b20-b4bc-13e36fd2227f) |
| Defender for Cloud Apps | ADALLOM_S_STANDALONE (2e2ddb96-6af9-4b1d-a3f0-d6ecfd22edb2) |
| Microsoft Defender XDR | MTP (bf28f719-7844-4079-9c78-c1307898e192) |
| Microsoft Intune Plan 1 | INTUNE_A (c1ec4a95-1f05-45b3-a911-aa3fa01094f5), INTUNE_A_GOV (d216f254-796f-4dab-bbfa-710686e646b9) |

The other plans keep their commercial IDs in the government SKUs Learn lists.

LIC.2-MACHINES, every device the Defender for Endpoint API lists, any platform. Needs Machine.Read (Machine.Read.All for an application) and the View Data role, and returns the devices the account's device groups allow. Paged with `$top` 10,000, the documented maximum, and `$skip`. A 404 means no recent device and reads EMPTY. A device carrying the `License MDE P1` tag gets Plan 1 under mixed licensing, which applies to client devices only. The API documents no Azure resource ID, so a device is tied to its Azure virtual machine by the same device ID in EW.1-VMS or, failing that, by one virtual machine of the same name in EW.1-EDR, and a device in the managed resource group is left out.

```http
GET https://api.security.microsoft.com/api/machines?$top=10000&$skip=0
```

LIC.3-TVM, Advanced Hunting. Every onboarded device, not only Azure virtual machines, by platform, with the devices that have vulnerability management data and the devices tagged `License MDE P1` by hand or by a dynamic rule. Plan 1 devices show no vulnerabilities, Plan 2 adds core vulnerability management, and Defender for Servers gives servers the Plan 2 benefits. Plan 1 and Defender for Business include no Advanced Hunting.

```kql
let Devices = DeviceInfo
| where Timestamp between (ago(7d) .. now())
| summarize arg_max(Timestamp, *) by DeviceId
| where OnboardingStatus == "Onboarded"
| where AzureResourceId !contains "{{MRG}}"
| extend Tags = strcat(tostring(column_ifexists("DeviceManualTags", "")), " ", tostring(column_ifexists("DeviceDynamicTags", "")))
| project DeviceId, OSPlatform, DeviceType, DeviceCategory, Tagged = Tags contains "License MDE P1";
let Vulnerable = union isfuzzy = true (DeviceTvmSoftwareVulnerabilities | distinct DeviceId), (datatable(DeviceId: string) [])
| distinct DeviceId | extend HasVulnerabilities = true;
let Assessed = union isfuzzy = true (DeviceTvmSecureConfigurationAssessment | where Timestamp between (ago(7d) .. now()) | distinct DeviceId), (datatable(DeviceId: string) [])
| distinct DeviceId | extend HasAssessments = true;
Devices
| join kind=leftouter Vulnerable on DeviceId
| join kind=leftouter Assessed on DeviceId
| summarize Devices = count(), WithVulnerabilities = countif(HasVulnerabilities == true), WithAssessments = countif(HasAssessments == true), TaggedPlan1 = countif(Tagged)
          by OSPlatform, DeviceType, DeviceCategory
| order by Devices desc
```

LIC.4-DEVICES, every Microsoft Entra device. Needs Device.Read.All. A device managed by security settings management has management type `MicrosoftSense`. The list also serves the stale device change request, CR-24, which disables each enabled device whose last sign-in (`approximateLastSignInDateTime`, the activity timestamp) is more than `-StaleDeviceDays` days (90 by default) before this read, and never deletes one. From collector 1.19.0 it also reads `physicalIds`, `profileType` and `systemLabels`, so CR-24 leaves out, besides hybrid joined and synced devices (`trustType` ServerAd, `onPremisesSyncEnabled`), devices an MDM manages (`isManaged`) and devices security settings management manages, the Windows Autopilot devices (a `physicalIds` entry starting with `[ZTDid]`, How To: Manage stale devices in Microsoft Entra ID, Create device groups for Windows Autopilot), the Universal Print printers (`profileType` Printer, which cannot be disabled in Microsoft Entra ID) and the devices carrying a system label. A device with a blank activity timestamp is never read as stale, since Microsoft Learn notes some active devices have one. A refused read (403) is UNAVAILABLE and CR-24 reads not collected, never no gaps.

```http
GET https://graph.microsoft.com/v1.0/devices?$select=id,deviceId,displayName,accountEnabled,operatingSystem,operatingSystemVersion,trustType,isManaged,isCompliant,managementType,approximateLastSignInDateTime,registrationDateTime,onPremisesSyncEnabled,physicalIds,profileType,systemLabels&$top=999
```

LIC.5-MATRIX, derived, no query. One row for the Defender for Endpoint plan (the Licenses page reading when given, otherwise Plan 2, Plan 1, Mixed, Defender for Business, no license or Unknown from the API reads, with any disagreement named), one per device count (onboarded clients, onboarded servers, other Linux devices, clients tagged `License MDE P1`, servers without a server license, devices security settings management manages), and one per capability: Licensed, Partly licensed, Not licensed or Unknown, with its seats, assigned licenses, source and basis. Defender for Servers (any plan or Plan 2) and Defender for Containers come from P0.3 for each subscription, and a subscription P0.3 did not read is unknown. LIC.5-SERVERS lists each onboarded server, Windows Server or Linux on an Azure virtual machine, with Defender for Servers on its subscription, the license that covers it, and Licensed Yes, No (its subscription has Defender for Servers off, and the tenant holds neither a server license nor Defender for Business, whose server licenses no license read can identify) or Unknown. Defender for Endpoint for servers is licensed per operating system environment, so too few seats for the servers outside Defender for Servers leaves those servers Unknown and names the shortfall. The device API lists only the devices the account's device groups allow, so its list is a lower bound: it can show servers without a server license, but never that every server has one. Enough seats for the servers listed therefore still reads Unknown, and Defender for Endpoint on servers reads neither Licensed nor Not licensed from the device reads, since a server they hide may sit in a subscription outside the pack with Defender for Servers on: it reads Partly licensed where the list shows a covered server beside an uncovered one, and Unknown otherwise, with what was established. A pricing set on a single machine (P0.3 `PricingId` under the machine's ID: Defender for Servers Plan 1 enabled, or either plan disabled, at the resource level) decides that machine, and the subscription reading takes the subscription-scope pricings only. For the same reason the vulnerability and configuration data behind EW.3, EW.4 and EW.5 never read Licensed from the API reads, which can exclude neither mixed mode on clients the account cannot see nor a server without a server license: they read Partly licensed where a gap is seen beside some coverage (Defender for Business counts as client coverage, since it includes core vulnerability management), and Unknown otherwise, with what was established. Security settings management follows the license read alone, since a device still managed by it shows it was set up, not that it is licensed today. Defender for Business supports no mixed licensing, and a tenant holding it beside Plan 2 keeps the Defender for Business experience until Microsoft Support switches it, so the API reads give Defender for Business there and the Licenses page reading confirms a switch.

### IA.15-DISABLED, IA.15-RBAC and IA.15-ENTRA Roles held by disabled accounts

Engine DISABLED-ROLES. CyberSOC collector 1.9.0, the group membership columns 1.10.0. Microsoft Graph for the accounts and the Entra roles, Resource Graph for the Azure roles. All three results name accounts and stay internal. Feeds CR-19, which removes each role assigned directly to a disabled account, removes the account from the group it sits in where a group holds the role, and names in the index the roles held through a dynamic or synced group, the accounts synced from on-premises and anything that could not be read.

IA.15-DISABLED, the disabled user accounts, paged through `@odata.nextLink`. An account is kept only when Graph returns `accountEnabled` false. Needs User.Read.All. Without it all three results are UNAVAILABLE ("Not a zero"), since no role can be tied to an account. Disabled service principals are not read.

```http
GET https://graph.microsoft.com/v1.0/users?$filter=accountEnabled eq false&$select=id,displayName,userPrincipalName,accountEnabled,onPremisesSyncEnabled&$top=999
```

IA.15-ENTRA, every Microsoft Entra role the accounts hold. `roleAssignments` is the read IA.6 makes, shared, and every directory role counts, not only the 12 privileged ones. The schedule instances mark an active assignment Activated or Time-bound and add the Eligible ones. An eligibility a user inherits from a group (`memberType` Group) is the group's own assignment, so it is read with the group, never as the user's. A role scoped to one application or other object keeps its `/<object ID>` directory scope, and CR-19 restores it there. When they answer 403 the result is PARTIAL and reads "Eligible assignments not visible, needs RoleManagement.Read.Directory". When `roleAssignments` cannot be read, IA.15-ENTRA alone is UNAVAILABLE and the Azure side still runs.

```http
GET https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal
GET https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId
GET https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$expand=principal
GET https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$expand=principal
```

A role held by a group, on either side, is followed to the group's disabled members through its direct members and those of each group nested in it (GroupMember.Read.All), breadth first, so each group is read once and reached by its shortest route, a loop stopped at a group already seen, and a group deleted since the role was given to it holding the role for no one. Graph takes `$select` and `$top` on `members` only as an advanced query, so the request carries `$count=true` and the `ConsistencyLevel: eventual` header. Each row names the role group (`HeldThrough` Group, `GroupId`, `GroupName`) and, from collector 1.10.0, the group the account sits in (`MemberOfId`, `MemberOfName`), its membership type (`MemberOfType`: Assigned, Dynamic for a dynamic membership group, On-premises for a group synced from Active Directory, from `groupTypes` and `onPremisesSyncEnabled`) and the path from the role group down to it (`GroupPath`, `GroupPathIds`). CR-19 removes the account from an Assigned group, so the group keeps its role and its other members, and names a Dynamic or On-premises membership for review.

```http
GET https://graph.microsoft.com/v1.0/groups/{id}?$select=id,displayName,groupTypes,onPremisesSyncEnabled
GET https://graph.microsoft.com/v1.0/groups/{id}/members?$count=true&$select=id,displayName&$top=999
ConsistencyLevel: eventual
```

IA.15-RBAC, every Azure role assignment the accounts hold, with the query below. It is sent with the request option `"authorizationScopeFilter": "AtScopeAboveAndBelow"`. Microsoft Learn (Understanding the Azure Resource Graph query language, query scope) documents that the filter defaults to `AtScopeAndBelow`, which returns the assignments at and below the subscriptions in the request, so the management group and root scope assignments above them come back only with `AtScopeAboveAndBelow`. Each assignment is kept once, with its ABAC `Condition` and `ConditionVersion`, which narrow what the role grants, so CR-19's rollback recreates the assignment with them. `ScopeLevel` is read from the scope: Root (`/`), Management group, Subscription, Resource group or Resource. Learn lists only `roleassignments`, `roledefinitions` and `classicadministrators` in `authorizationresources`, so the eligible assignments of Privileged Identity Management for Azure resources are not read, and the CR-19 index says so. As with IA.7, through Lighthouse Resource Graph shows the managing tenant's delegations instead of the client's own role assignments, so IA.15-RBAC reads PARTIAL there.

```kql
authorizationresources
| where type =~ "microsoft.authorization/roleassignments"
| where id !contains "{{MRG}}"
| extend PrincipalId      = tolower(tostring(properties.principalId)),
         PrincipalType    = tostring(properties.principalType),
         Scope            = tostring(properties.scope),
         RoleDefinitionId = tolower(tostring(properties.roleDefinitionId)),
         Condition        = tostring(properties.condition),
         ConditionVersion = tostring(properties.conditionVersion)
| extend RoleGuid = tostring(split(RoleDefinitionId, "/")[-1])
| join kind=leftouter (
    authorizationresources
    | where type =~ "microsoft.authorization/roledefinitions"
    | extend RoleGuid = tolower(name), Role = tostring(properties.roleName)
    | summarize Role = take_any(Role) by RoleGuid
  ) on RoleGuid
| where PrincipalType !~ "ServicePrincipal"   // users and groups, and any assignment without a type
| project AssignmentId = id, subscriptionId, Scope, RoleDefinitionId, Role, Condition, ConditionVersion, PrincipalId, PrincipalType
| order by PrincipalId asc, Scope asc
```

### IA.17-GUESTS, IA.17-RBAC and IA.17-ENTRA Roles held by enabled guest accounts

Engine GUEST-ROLES. CyberSOC collector 1.21.0. The engine of IA.15 run for the guest accounts that are still enabled: Microsoft Graph for the guests and the Entra roles, Resource Graph for the Azure roles, with the same reads, the same group walk and the same query as IA.15 above. Disabled guests are already in IA.15. All three results name accounts and stay internal. Feeds CR-26, which removes the Azure roles of each guest the client marks Remove, at every scope, assigned directly or through a group, with CR-19's removal, and names the Microsoft Entra roles guests hold for review.

IA.17-GUESTS, the guest accounts, paged through `@odata.nextLink` and read in full. A guest is kept only when Graph returns `userType` Guest and `accountEnabled` true. Microsoft Learn (user resource type, signInActivity resource type) documents that `signInActivity` needs AuditLog.Read.All and Microsoft Entra ID P1 or P2, that `lastSuccessfulSignInDateTime` is the last successful sign-in, interactive or not, recorded since December 2023, and (List users) that a request selecting `signInActivity` returns at most 500 users a page. When that read is refused, the guests are read again with the second request, `SignInRead` reads No and the client file says the last sign-in was not read. Needs User.Read.All. Without it all three results are UNAVAILABLE ("Not a zero").

```http
GET https://graph.microsoft.com/v1.0/users?$filter=userType eq 'Guest'&$select=id,displayName,userPrincipalName,mail,userType,accountEnabled,externalUserState,createdDateTime,onPremisesSyncEnabled,signInActivity&$top=500
GET https://graph.microsoft.com/v1.0/users?$filter=userType eq 'Guest'&$select=id,displayName,userPrincipalName,mail,userType,accountEnabled,externalUserState,createdDateTime,onPremisesSyncEnabled&$top=999
```

IA.17-ENTRA and IA.17-RBAC read the roles as IA.15-ENTRA and IA.15-RBAC do, with the shared `roleAssignments` read, the group walk to the guest members of each role group and of each group nested in it, and the IA.15 query above sent with `"authorizationScopeFilter": "AtScopeAboveAndBelow"`, so the management group and root scope assignments come back too, each with its ABAC condition. Through Lighthouse IA.17-RBAC reads PARTIAL, as IA.15-RBAC does.

### IA.16-ACCOUNTS and IA.16-GROUPS Emergency access accounts

Engine EMERGENCY-ACCESS. CyberSOC collector 1.12.0. Microsoft Graph, read-only. Both results name accounts and stay internal. Feeds the emergency access exclusions of every Conditional Access change: the change requests write a Conditional Access block or MFA policy only with these exclusions, and none when this read failed, is partial or found no account.

The emergency access accounts are every account whose user principal name contains Atmosera, members and guests alike, and every user in an Atmosera group, read as a group whose display name contains Atmosera. Both matches ignore case and look anywhere in the value, and the rule lives in one place, `report/Get-CyberSocEmergencyAccess.ps1`, which the collector and the change requests share. A guest from an Atmosera domain matches through its UPN, which Microsoft Learn (List users) documents as the external address with `@` turned into `_`, followed by `#EXT#`. Graph `$filter` has no contains on `userPrincipalName` or `displayName`, and Learn (Use the $search query parameter) documents that `$search` tokenizes `displayName` and `description` only and reads every other property as starts with, so a search could miss `breakglass-atmosera01@...` or a group named `SOCatmosera`. Every user and every group is therefore read in full and matched offline. Needs User.Read.All (List users) and GroupMember.Read.All (List groups, List group transitive members), which IA.15 already holds.

```http
GET https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,displayName,userType,accountEnabled&$top=999
GET https://graph.microsoft.com/v1.0/groups?$select=id,displayName,groupTypes,onPremisesSyncEnabled,membershipRule,visibility&$top=999
```

The user members of each Atmosera group are read transitively, so a member of a group nested in it, an Atmosera group or any other, is listed too. Learn (List group transitive members) requires `$count=true` and the `ConsistencyLevel: eventual` header for the OData cast, and notes that the index behind it might not show a very recent change, and that a group with hidden membership needs Member.Read.Hidden. The groups read `visibility`, so a refusal on a group with `HiddenMembership` asks for Member.Read.Hidden rather than GroupMember.Read.All.

```http
GET https://graph.microsoft.com/v1.0/groups/{id}/transitiveMembers/microsoft.graph.user?$count=true&$select=id,userPrincipalName,displayName,userType,accountEnabled&$top=999
ConsistencyLevel: eventual
```

IA.16-ACCOUNTS, one row per account: `PrincipalId`, `UserPrincipalName`, `DisplayName`, `UserType`, `AccountEnabled`, `MatchedBy` (UPN, Group, or UPN and group) and the Atmosera groups it sits in (`Groups`, `GroupIds`). IA.16-GROUPS, one row per Atmosera group: `GroupId`, `DisplayName`, `Members` (its user members, counted once each), `Membership` (Assigned, Dynamic for a dynamic membership group, On-premises for a group synced from Active Directory), `MembersRead` and the `MembershipRule` of a dynamic group. Each read pages through `@odata.nextLink` and fails when pages remain after the page limit, so a read cut short is never taken as complete. A refused read is UNAVAILABLE with the permission it needs, any other failure FAILED. A group whose members cannot be read makes both results PARTIAL and is named. The groups unread leave IA.16-ACCOUNTS PARTIAL with the UPN matches only. A tenant with no match reads EMPTY on both, which the change requests treat as no emergency access account, not as clearance. An account Atmosera uses whose UPN does not contain the word is found only when it sits in an Atmosera group.

### IA.8-SIGNINS-NONINTERACTIVE Non-interactive legacy sign-ins

Engine LA, read once from the workspace that holds the tenant-wide `SigninLogs`. CyberSOC collector 1.16.0. Names accounts and stays internal. Feeds CR-21 with IA.8-SIGNINS: IA.8-SIGNINS reads `SigninLogs`, the interactive sign-ins only, and a service account that sends mail with SMTP AUTH or reads it with POP or IMAP can sign in non-interactively only, so without this read its exclusion could read as no longer used. Microsoft Learn (Block legacy authentication with Conditional Access, identify legacy authentication use) has legacy use checked on the interactive and the non-interactive sign-ins. Legacy authentication is read as IA.8-SIGNINS reads it: a client app other than Browser, Mobile Apps and Desktop clients and Unknown. `ConditionalAccessPolicies` is a string in this table (Azure Monitor table reference, AADNonInteractiveUserSignInLogs), which `todynamic` reads. One `Coverage` row per sign-in table, `AADNonInteractiveUserSignInLogs` and `SigninLogs`, counts its sign-ins of the 30 days with the first and the last, and `FullWindow` is true only when the first is more than 29 days old. A workspace that does not receive `NonInteractiveUserSignInLogs` from the Microsoft Entra diagnostic settings has no table, which reads EMPTY, or no row, and one that began receiving a log within the 30 days misses the legacy sign-ins from before. CR-21 then writes nothing rather than read any of them as no legacy sign-in. A pause in forwarding inside the window is not detected.

```kusto
let NonInteractive = AADNonInteractiveUserSignInLogs
| where TimeGenerated between (ago(30d) .. now());
let Legacy = NonInteractive
| where ResultType == "0" and isnotempty(UserId)
| where isnotempty(ClientAppUsed) and ClientAppUsed !in ("Browser", "Mobile Apps and Desktop clients", "Unknown")
| extend Flow = "Legacy authentication"
| mv-apply Policy = todynamic(ConditionalAccessPolicies) on (
    where tostring(Policy.result) != "notEnabled"
    | summarize PolicySet = make_set(strcat(tostring(Policy.id), "=", tostring(Policy.result)))
  )
| extend PolicyResults = strcat_array(array_sort_asc(PolicySet), ",")
| summarize SignIns = count(), LastSignIn = max(TimeGenerated), Apps = strcat_array(make_set(AppDisplayName, 5), ", ")
          by Flow, ClientAppUsed, UserId, UserPrincipalName, UserType, PolicyResults
| extend Kind = "Account", Table = "AADNonInteractiveUserSignInLogs";
let Coverage = union
    (NonInteractive | summarize SignIns = count(), FirstSignIn = min(TimeGenerated), LastSignIn = max(TimeGenerated) | extend Table = "AADNonInteractiveUserSignInLogs"),
    (SigninLogs | where TimeGenerated between (ago(30d) .. now()) | summarize SignIns = count(), FirstSignIn = min(TimeGenerated), LastSignIn = max(TimeGenerated) | extend Table = "SigninLogs")
| extend Kind = "Coverage", FullWindow = SignIns > 0 and FirstSignIn < ago(29d);
union Coverage, Legacy
| project Kind, Table, Flow, ClientAppUsed, UserId, UserPrincipalName, UserType, PolicyResults, SignIns, FirstSignIn, LastSignIn, FullWindow, Apps
| order by Kind asc, Table asc, SignIns desc
```

### EW.4-SERVERS Windows servers with their attack surface reduction rules and antivirus prerequisites

Engine AH. CyberSOC collector 1.17.0. Names machines and stays internal. Feeds CR-22, which sets the attack surface reduction (ASR) rules to Audit on the Windows servers through one endpoint security policy and security settings management. One row per Windows Server Azure virtual machine Defender for Endpoint saw in the last 7 days, in any onboarding status, so a server seen but not onboarded is named rather than missed, with the `{{MRG}}` exclusion. The configuration assessment is joined leftouter, so a server without one stays listed with `AsrApplicable` 0, which is not a reading that no rule is set. The ASR checks are matched by the rule names of Microsoft Learn (ASR rules overview) that Windows Server supports, so Block Win32 API calls from Office macros, which does not apply to Windows Server (ASR rules reference, operating system support), is left out. A rule read as compliant is configured on the server, in Audit, Block or Warn, and CR-22 leaves it Not configured in its policy, since a policy overwrites local settings and Audit could lower a rule in Block (Configure ASR rules and exclusions, how policy conflicts are handled). Real-time protection and cloud-delivered protection come from the checks in the Antivirus subcategory (DeviceTvmSecureConfigurationAssessmentKB) and read On, Off, or empty when not assessed. `AadDeviceId` is the Microsoft Entra device ID (DeviceInfo), which LIC.4-DEVICES matches for the management type MicrosoftSense that marks a device security settings management manages. `DomainController` reads the Domain Controller role from `DeviceRoles`, the role the device inventory shows (Device inventory field reference), and CR-22 lists those servers on their own.

```kusto
let AsrRules = dynamic([
    "Block abuse of exploited vulnerable signed drivers",
    "Block credential stealing from the Windows local security authority subsystem",
    "Block persistence through WMI event subscription",
    "Block Adobe Reader from creating child processes",
    "Block all Office applications from creating child processes",
    "Block executable content from email client and webmail",
    "Block executable files from running unless they meet a prevalence, age, or trusted list criterion",
    "Block execution of potentially obfuscated scripts",
    "Block JavaScript or VBScript from launching downloaded executable content",
    "Block Office applications from creating executable content",
    "Block Office applications from injecting code into other processes",
    "Block Office communication application from creating child processes",
    "Block process creations originating from PSExec and WMI commands",
    "Block rebooting machine in Safe Mode",
    "Block untrusted and unsigned processes that run from USB",
    "Block use of copied or impersonated system tools",
    "Block Webshell creation for Servers",
    "Use advanced protection against ransomware"
  ]);
DeviceInfo
| where Timestamp between (ago(7d) .. now())
| where OSPlatform startswith "WindowsServer"
| summarize arg_max(Timestamp, DeviceName, OSPlatform, OSVersion, OnboardingStatus, MachineGroup, AadDeviceId, AzureResourceId, DeviceRoles)
          by DeviceId
| where isnotempty(AzureResourceId)   // Azure virtual machines only
| where AzureResourceId !contains "{{MRG}}"
| join kind=leftouter (
    DeviceTvmSecureConfigurationAssessment
    | summarize arg_max(Timestamp, *) by DeviceId, ConfigurationId
    | where tobool(IsApplicable)
    | join kind=inner DeviceTvmSecureConfigurationAssessmentKB on ConfigurationId
    | extend Asr   = ConfigurationName in~ (AsrRules),
             Rtp   = ConfigurationSubcategory =~ "Antivirus" and ConfigurationName has "real-time protection",
             Cloud = ConfigurationSubcategory =~ "Antivirus" and ConfigurationName has "cloud-delivered protection"
    | where Asr or Rtp or Cloud
    | summarize AsrApplicable   = countif(Asr),
                AsrConfigured   = countif(Asr and tobool(IsCompliant)),
                ConfiguredRules = make_set_if(ConfigurationName, Asr and tobool(IsCompliant)),
                MissingRules    = make_set_if(ConfigurationName, Asr and not(tobool(IsCompliant))),
                RtpChecks = countif(Rtp), RtpOn = countif(Rtp and tobool(IsCompliant)),
                CloudChecks = countif(Cloud), CloudOn = countif(Cloud and tobool(IsCompliant))
              by DeviceId
  ) on DeviceId
| extend RealTimeProtection = case(isnull(RtpChecks) or RtpChecks == 0, "", RtpOn == RtpChecks, "On", "Off"),
         CloudProtection    = case(isnull(CloudChecks) or CloudChecks == 0, "", CloudOn == CloudChecks, "On", "Off"),
         DomainController   = tostring(DeviceRoles) has_any ("DomainController", "Domain Controller"),
         subscriptionId     = tolower(tostring(split(AzureResourceId, "/")[2])),
         ResourceGroup      = tostring(split(AzureResourceId, "/")[4]),
         VmName             = tostring(split(AzureResourceId, "/")[8])
| project DeviceId, DeviceName, VmName, ResourceGroup, subscriptionId, AzureResourceId, OSPlatform, OSVersion,
          OnboardingStatus, MachineGroup, AadDeviceId, DomainController, RealTimeProtection, CloudProtection,
          AsrApplicable = coalesce(AsrApplicable, 0), AsrConfigured = coalesce(AsrConfigured, 0), ConfiguredRules, MissingRules
| order by subscriptionId asc, ResourceGroup asc, DeviceName asc
```

### EW.4-AVMODE Microsoft Defender Antivirus mode per Windows device

Engine DEFENDER-AVINFO. CyberSOC collector 1.17.0. Names devices and stays internal. Feeds CR-22 with EW.4-SERVERS, matched on the device ID. ASR rules run only when Microsoft Defender Antivirus is in Active mode, never Passive, Passive with EDR in block mode, limited periodic scanning or Off (ASR rules overview), and Microsoft Learn documents the mode for the antivirus health export as a string typed integer: 0 Active, 1 Passive, 2 Disabled, 3 or empty Other, 4 EDRBlocked, 5 PassiveAudit (Export device antivirus health details API methods and properties). CR-22 leaves out every server in another mode, or whose mode is not reported, for the Defender Antivirus server baseline first. Windows Server 2012 R2 and 2016 report here only when onboarded with the modern unified solution. Paged with `$top` 10,000 and `$skip`, as LIC.2-MACHINES is. Needs Machine.Read (delegated) or Machine.Read.All (application) and the View Data role. A 403 is UNAVAILABLE, a 404 no device, any other failure FAILED, never a zero. Devices that are not Windows (`osKind`) are left out.

```http
GET https://api.security.microsoft.com/api/deviceavinfo?$top=10000&$skip=0
```

One row per Windows device: `MachineId` (lower case, as Advanced Hunting gives `DeviceId`), `ComputerDnsName`, `OsPlatform`, `AvMode`, `AvModeName`, `DataRefreshTimestamp` and `LastSeenTime`.

### EW.10-ASSESSMENT Virtual machines without periodic assessment

Engine PATCH-ASSESSMENT. CyberSOC collector 1.18.0. Names machines and stays internal. Feeds CR-23, which turns on periodic assessment in Azure Update Manager, so Azure checks each machine for missing updates every 24 hours (Assessment options in Update Manager). One row per Azure virtual machine whose `patchSettings.assessmentMode` (under `osProfile.windowsConfiguration`, or `linuxConfiguration` for Linux) is not AutomaticByPlatform, an empty value included, with the `{{MRG}}` exclusion. These are the machines EW.10 leaves out of its denominator when they were never assessed. `PatchMode` is kept for context only: CR-23 changes the assessment mode alone, since Patch orchestration set to Customer Managed Schedules on a machine with no schedule attached stops it being patched (Troubleshoot known issues with Azure Update Manager). Each row carries what CR-23 leaves out: `Appliance` (the P0.6-APPLIANCES pattern), `Aks` (a machine in the node resource group of an AKS cluster, or tagged `aks-managed-`, which Update Manager does not support), `WindowsClient` (an image from MicrosoftWindowsDesktop or an operating system name of Windows 10 or 11, which Update Manager does not support, Unsupported workloads for Azure Update Manager), `GuestPatchSupport` (the `detectedVMGuestPatchSupportState` of the last assessment, Unsupported for an image Update Manager does not support, Manage updates for customized images), `ProvisionVmAgent` (false when the VM agent periodic assessment needs is not provisioned) and `PatchExcluded` (the tag exclusion of EW.10-EXCLUDED, `-PatchExclusionTagPattern`). Then the Azure Virtual Desktop host pools are listed from Resource Graph and each one is read with a GET on `sessionHosts` (`api-version=2024-04-03`, following `nextLink`), whose `properties.resourceId` names the virtual machine of each session host, so `HostPool` and `HostPoolType` mark a session host, and CR-23 names a pooled one, which loses the setting when rebuilt from its image. A host pool that cannot be listed or read makes the result PARTIAL, never a session host read as outside a host pool.

```kusto
resources
| where type =~ "microsoft.compute/virtualmachines"
| where id !contains "{{MRG}}"
| extend OsType = tostring(properties.storageProfile.osDisk.osType)
| extend Os = iff(OsType =~ "Linux", properties.osProfile.linuxConfiguration, properties.osProfile.windowsConfiguration)
| extend AssessmentMode = tostring(Os.patchSettings.assessmentMode)
| where AssessmentMode !~ "AutomaticByPlatform"
| extend VmKey = tolower(id), NodeRgKey = strcat(tolower(subscriptionId), "/", tolower(resourceGroup))
// AKS creates the machines of each node pool in the node resource group of its cluster.
| join kind=leftouter (
    resources
    | where type =~ "microsoft.containerservice/managedclusters"
    | project NodeRgKey = strcat(tolower(subscriptionId), "/", tolower(tostring(properties.nodeResourceGroup))), AksCluster = name
  ) on NodeRgKey
| join kind=leftouter (
    patchassessmentresources
    | where type =~ "microsoft.compute/virtualmachines/patchassessmentresults"
    | extend VmKey = tostring(split(tolower(id), "/patchassessmentresults")[0]),
             LastAssessed = todatetime(properties.lastModifiedDateTime),
             GuestPatchSupport = tostring(properties.configurationStatus.vmGuestPatchReadiness.detectedVMGuestPatchSupportState)
    | summarize arg_max(LastAssessed, GuestPatchSupport) by VmKey
  ) on VmKey
| extend PatchExcluded = false
| extend PatchExcluded = tolower(tostring(tags)) matches regex @"{{PATCH_EXCLUDED}}"
| extend ImagePublisher   = tostring(properties.storageProfile.imageReference.publisher),
         ImageOffer       = tostring(properties.storageProfile.imageReference.offer),
         ImageSku         = tostring(properties.storageProfile.imageReference.sku),
         OsName           = tostring(properties.extended.instanceView.osName),
         PatchMode        = tostring(Os.patchSettings.patchMode),
         ProvisionVmAgent = tostring(Os.provisionVMAgent),
         PowerState       = tostring(properties.extended.instanceView.powerState.code),
         Appliance        = {{APPLIANCE}},   // network virtual appliances, see P0.6-APPLIANCES
         Aks              = isnotempty(AksCluster) or tostring(bag_keys(tags)) contains "aks-managed-"
| extend WindowsClient = OsType =~ "Windows" and (ImagePublisher =~ "microsoftwindowsdesktop" or OsName has_any ("Windows 10", "Windows 11"))
| project Name = name, resourceGroup, subscriptionId, OsType, OsName, ImagePublisher, ImageOffer, ImageSku, PowerState,
          AssessmentMode, PatchMode, ProvisionVmAgent, Appliance, Aks, AksCluster, WindowsClient, GuestPatchSupport,
          LastAssessed, PatchExcluded, VmId = tostring(properties.vmId), ResourceId = tolower(id)
| order by subscriptionId asc, resourceGroup asc, Name asc
```

The host pools, before the `sessionHosts` GET on each:

```kusto
resources
| where type =~ "microsoft.desktopvirtualization/hostpools"
| project Name = name, resourceGroup, subscriptionId, HostPoolType = tostring(properties.hostPoolType), ResourceId = id
```

```http
GET https://management.azure.com/<host pool resource ID>/sessionHosts?api-version=2024-04-03
```

### NB.2-DETAIL Internet-exposed management port rules with their properties and attachments

Engine ARG. CyberSOC collector 1.6.0. The rules NB.2 lists, read the same way: allow inbound from any address (`*`), `Internet`, `0.0.0.0/0` or `::/0` (from collector 1.6.0, in NB.2 too) on 22, 3389, 5985, 5986, `*` or a port range. One row per rule with everything CR-16 needs to change it and to recreate it on rollback: the subscription, the network security group and rule resource IDs, priority, direction, access, protocol, the source and destination prefixes and ports as lists (the single and the list form of each property together, so an empty single form shows as an empty entry), the description, the destination application security groups, and the association (Subnet, NIC or Unassociated, as in NB.2). `Subnets` and `Nics` list what the group is attached to, and `NicVms` names the virtual machine of each network interface that names the group. `ApplianceNicIds` and `ApplianceSubnetIds` list every network interface of a network virtual appliance (the P0.6-APPLIANCES pattern) and the subnets it sits in, the same on every row, so a rule that reaches an appliance through its network interface or through the group on its subnet is found. A missing property reads as an empty list. `mv-expand` takes up to 1,000 rules per group, the most a group can hold, rather than its default of 128. CR-16 closes the rules on a workload subnet or network interface that name their ports over TCP or any protocol, leaves a rule for another protocol for review, and leaves to the index notes a group attached only to appliance network interfaces (an untrust interface takes internet traffic by design), a group that reaches an appliance through a subnet or as well as other resources (for review), a group attached to nothing (a cleanup item) and a rule whose ports are `*` or a range (for review). Feeds CR-16 and its client email, with P0.3 for Defender for Servers Plan 2 by subscription, which just-in-time VM access needs.

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
     or SourceText contains '"::/0"'
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

Engine ARG. The site configurations NB.5 counts as below TLS 1.2, one row per site. The site name, resource group and subscription are read from the configuration ID, because the config record is not the site. CyberSOC collector 1.13.0 adds `ScmMinTlsVersion`, the minimum inbound TLS version of the SCM (Kudu) site, read with the same PascalCase key handling, and lists a site when either value is below 1.2 or empty. Deployment slots (`sites/slots/config`) are not read. Feeds CR-04, which sets each value to 1.2 only where it is below 1.2, and leaves to the index notes a value that reads empty, since App Service applies 1.2 to the site and to the SCM site when no minimum is set.

```kql
appserviceresources
| where type =~ "microsoft.web/sites/config"
| where id !contains "{{MRG}}"
// appserviceresources returns site config keys in PascalCase and dynamic access is case-sensitive.
| extend MinTlsVersion    = tostring(coalesce(properties.MinTlsVersion, properties.minTlsVersion)),
         ScmMinTlsVersion = tostring(coalesce(properties.ScmMinTlsVersion, properties.scmMinTlsVersion))
| where not(MinTlsVersion in ("1.2", "1.3")) or not(ScmMinTlsVersion in ("1.2", "1.3"))
| extend Parts = split(id, "/")
| project Name = tostring(Parts[8]), ResourceId = tostring(split(id, "/config/")[0]),
          resourceGroup = tostring(Parts[4]), subscriptionId = tostring(Parts[2]), MinTlsVersion, ScmMinTlsVersion
| order by subscriptionId asc, resourceGroup asc, Name asc
```

### NB.5-FTPS-DETAIL App Service sites that still allow plain FTP

Engine ARG. CyberSOC collector 1.7.0. The site configurations whose FTP state is not `FtpsOnly` or `Disabled`, one row per site, read as NB.5-DETAIL reads them: the site name, resource group and subscription from the configuration ID, and the PascalCase keys. An empty state is kept, so a site whose state Resource Graph did not return is never read as enforced. The minimum TLS version is read too, since FTPS only does not support TLS 1.0 or 1.1. Deployment slots (`sites/slots/config`) are not read. Feeds CR-17, which changes the sites whose state reads `AllAllowed` and leaves to the index notes a site whose state reads empty, since Microsoft Learn documents no state App Service applies when none is set.

```kql
appserviceresources
| where type =~ "microsoft.web/sites/config"
| where id !contains "{{MRG}}"
// appserviceresources returns site config keys in PascalCase and dynamic access is case-sensitive.
| extend FtpsState     = tostring(coalesce(properties.FtpsState, properties.ftpsState)),
         MinTlsVersion = tostring(coalesce(properties.MinTlsVersion, properties.minTlsVersion))
| where not(FtpsState in~ ("FtpsOnly", "Disabled"))
| extend Parts = split(id, "/")
| project Name = tostring(Parts[8]), ResourceId = tostring(split(id, "/config/")[0]),
          resourceGroup = tostring(Parts[4]), subscriptionId = tostring(Parts[2]), FtpsState, MinTlsVersion
| order by subscriptionId asc, resourceGroup asc, Name asc
```

### NB.5-FTPAUTH and NB.5-FTPAUTH-DETAIL App Service FTP basic authentication publishing credentials

Engine APPSERVICE-FTPAUTH. CyberSOC collector 1.14.0. Resource Graph does not index `basicPublishingCredentialsPolicies` (it is not among the `appserviceresources` or `resources` types), so NB.5-FTPAUTH lists every App Service and Function app site configuration with the query below, read as NB.5-FTPS-DETAIL reads them but with no filter on the FTP state, and then reads each app with `GET <app>/basicPublishingCredentialsPolicies/ftp?api-version=2022-09-01` on the App Service resource provider (Reader is enough). NB.5-FTPAUTH has one row per app: `subscriptionId`, `resourceGroup`, `Name`, `FtpsState`, `FtpBasicAuth` (On when `properties.allow` is true, Off when it is false, empty when not read), `ReadStatus` and `ResourceId`. An app whose read fails, or whose response carries no `properties.allow`, records why in `ReadStatus` and is never read as Off. NB.5-FTPAUTH-DETAIL has one row per app read as On, whatever its FTP state, with the same columns but `ReadStatus`. Both read PARTIAL when an app was not read or Resource Graph truncated the list, FAILED when no app was read, and EMPTY when no app is in scope. Deployment slots and the SCM basic authentication setting are not read. Feeds CR-17, which turns FTP basic authentication off on each app in NB.5-FTPAUTH-DETAIL and names in the index the apps NB.5-FTPAUTH could not read.

```kql
appserviceresources
| where type =~ "microsoft.web/sites/config"
| where id !contains "{{MRG}}"
// appserviceresources returns site config keys in PascalCase and dynamic access is case-sensitive.
| extend FtpsState = tostring(coalesce(properties.FtpsState, properties.ftpsState))
| extend Parts = split(id, "/")
| project Name = tostring(Parts[8]), ResourceId = tostring(split(id, "/config/")[0]),
          resourceGroup = tostring(Parts[4]), subscriptionId = tostring(Parts[2]), FtpsState
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

Engine ARG. One row per storage account DP.1 counts against secure transfer, minimum TLS 1.2 or anonymous blob access, read the same way: a missing allowBlobPublicAccess means anonymous access is allowed. NfsV3 and the FileStorage kind mark accounts that may serve NFS, which CR-02 leaves out because NFS mounts are refused once secure transfer is required. CR-07 also leaves out FileStorage accounts, which hold no blob service, and CR-18 names them in its notes. Feeds CR-02, CR-03 and CR-07. CR-07 takes only the accounts whose containers DP.1-CONTAINERS listed in full with none set to Blob or Container access, and names the others in the index.

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

### DP.1-CONTAINERS-DETAIL Blob containers set to Blob or Container access

Engine STORAGE-CONTAINERS, written with DP.1-CONTAINERS. CyberSOC collector 1.8.0. Resource Graph does not index blob containers, so DP.1-CONTAINERS lists the storage accounts with the query below (from collector 1.20.0 the engine leaves out the FileStorage accounts, which hold no blob service, rather than the query, so DP.1-SOFTDELETE can name them) and then reads each account with `GET <account>/blobServices/default/containers?api-version=2023-05-01` on the Storage resource provider, following `nextLink` (Reader is enough). DP.1-CONTAINERS-DETAIL has one row per container whose `properties.publicAccess` reads `Blob` or `Container`: `subscriptionId`, `resourceGroup`, `Account`, `Container`, `AccessLevel`, `AccountAnonymousAccess` (Allowed, Disabled, or Not set, allowed), `ReadableToday` (true when the account setting allows anonymous access), `AccountId` and the container `ResourceId`. An account that cannot be listed in full adds no rows, and its DP.1-CONTAINERS row records the error, so the detail reads PARTIAL with DP.1-CONTAINERS, and FAILED or EMPTY with it when no account is read or none is in scope. Feeds CR-18, which sets the containers readable today to private, and names in the index the static website containers (`$web`), the containers an account blocking anonymous access already keeps closed, and the accounts not listed.

```kql
resources
| where type =~ "microsoft.storage/storageaccounts"
| where id !contains "{{MRG}}"
| project ResourceId = id, Account = name, resourceGroup, subscriptionId, Kind = kind,
          AllowBlobPublicAccess = tostring(properties.allowBlobPublicAccess),
          HnsEnabled = coalesce(tobool(properties.isHnsEnabled), false)
| order by subscriptionId asc, Account asc
```

### DP.1-SOFTDELETE Blob and container soft delete of each storage account

Engine STORAGE-CONTAINERS, written with DP.1-CONTAINERS in the same pass over the accounts of the query above. CyberSOC collector 1.20.0. Names accounts and stays internal. Resource Graph does not index blob service properties, so each account with a blob service is read with `GET <account>/blobServices/default?api-version=2023-05-01` for `deleteRetentionPolicy` (blob soft delete) and `containerDeleteRetentionPolicy` (container soft delete), each with `enabled` and `days`, and `GET <account>/managementPolicies/default?api-version=2023-05-01` for the lifecycle rules, where a 404 means the account has no policy. Reader is enough for both. A policy left out of the response reads Off. Before the accounts, the Recovery Services vaults are listed with the query below and each is read with `GET <vault>/replicationProtectedItems?api-version=2023-08-01`, following `nextLink`, for the storage accounts a replication protected item names as Site Recovery cache or log storage (`primaryStagingAzureStorageAccountId` for Azure to Azure, `recoveryAzureLogStorageAccountId` or `logStorageAccountId` for the other providers), which Site Recovery does not support soft delete on. One row per storage account: `subscriptionId`, `resourceGroup`, `Account`, `Kind`, `HnsEnabled`, `BlobSoftDelete` and `ContainerSoftDelete` (On or Off), `BlobRetentionDays` and `ContainerRetentionDays`, `LifecycleRules` (the enabled rules) and `LifecycleDeleteRules` (those with a delete action on the current blob, a snapshot or a version), `SiteRecoveryCache` (Yes, No, or Unknown when a vault could not be read), `SiteRecoveryVaults`, `ReadStatus` and `ResourceId`. A FileStorage account is listed with no read, since it has no blob service. An account whose blob service or lifecycle read fails keeps its settings empty and records why in `ReadStatus`, so it is never read as having soft delete. The result is PARTIAL when an account or a vault was not read, FAILED when no account with a blob service was read or the account list failed, and EMPTY when there is no storage account. Feeds CR-25, which turns on whichever of the two is off with `-SoftDeleteRetentionDays` (7 days by default).

```kql
resources
| where type =~ "microsoft.recoveryservices/vaults"
| where id !contains "{{MRG}}"
| project Name = name, resourceGroup, subscriptionId, ResourceId = id
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

### POS.9-GUARDRAILS Guardrail policy assignments

Engine ARG, run with the Resource Graph request option `"authorizationScopeFilter": "AtScopeAboveAndBelow"`, so an assignment at a management group or the root above the subscriptions comes back too (Understanding the Azure Resource Graph query language, query scope). CyberSOC collector 1.22.0. The assignments of the built-in policy definitions that guard a remediation change request: secure transfer (CR-02), storage minimum TLS (CR-03), Azure SQL minimum TLS (CR-05), Key Vault deletion protection (CR-06), storage account public access, Deny and Modify (CR-07), App Service HTTPS only (CR-08), encryption at host (CR-09 and CR-15) and periodic assessment, Modify (CR-23). Each assignment is joined with the management group chain of each subscription (`properties.managementGroupAncestorsChain` of `resourcecontainers`), so there is one row per assignment and subscription it covers, and `subscriptionId` is empty for an assignment at a management group no subscription in the collection sits under. Columns: `AssignmentId`, `AssignmentName`, `DisplayName`, `Definition` (the definition GUID), `Scope`, `ScopeLevel` (ManagementGroup, Subscription, ResourceGroup or Other), `subscriptionId`, `EnforcementMode` (Default or DoNotEnforce), `Effect` (the effect parameter, empty when the assignment leaves it at the definition default), `Parameters` (every parameter the assignment sets, as JSON, which CR-27 reads to tell whether the assignment enforces the baseline: the minimum TLS version, or the OS type, assessment mode, locations and tags of the periodic assessment policy), `NotScopes` and `NonComplianceMessage`. An initiative that holds one of these definitions is not read. Through Lighthouse, which delegates subscriptions but not the management groups above them, it reads PARTIAL. Names assignments and scopes, so it stays internal. Feeds the guardrail template CR-27, which offers a definition only when every change request it follows reads No gaps found and no resource in the pack would fail it, leaves out a definition already assigned with Deny (or Modify) and enforced over every subscription, and names any other assignment so it is edited rather than duplicated.

```kql
policyresources
| where type =~ "microsoft.authorization/policyassignments"
| where id !contains "{{MRG}}"
| extend Definition = extract(@"/providers/microsoft\.authorization/policydefinitions/([0-9a-f-]+)$", 1, tolower(tostring(properties.policyDefinitionId)))
| where Definition in ("404c3081-a854-4457-ae30-26a93ef643f9", "fe83a0eb-a853-422d-aac2-1bffd182c5d0", "32e6bbec-16b6-44c2-be37-c5b672d103cf", "0b60c0b2-2dc2-4e1c-b5c9-abbed971de53", "4fa4b6c0-31ca-4c0d-b10d-24b96f62a751", "13502221-8df0-4414-9937-de9c5c4e396b", "a4af4a39-4135-47fb-b175-47fbdf85311d", "fc4d8e41-e223-45ea-9bf5-eada37891d87", "59efceea-0c96-497e-a4a1-4eb2290dac15")
| extend Scope = tolower(tostring(properties.scope))
| extend MgName = extract(@"^/providers/microsoft\.management/managementgroups/([^/]+)$", 1, Scope),
         SubscriptionKey = extract(@"^/subscriptions/([^/]+)", 1, Scope)
| extend ScopeLevel = case(isnotempty(MgName), "ManagementGroup", Scope matches regex @"^/subscriptions/[^/]+$", "Subscription", Scope matches regex @"^/subscriptions/[^/]+/resourcegroups/[^/]+$", "ResourceGroup", "Other"),
         EnforcementMode = tostring(properties.enforcementMode),
         Effect = tostring(properties.parameters.effect.value),
         Parameters = tostring(properties.parameters),
         NotScopes = strcat_array(properties.notScopes, ", "),
         NonComplianceMessage = tostring(properties.nonComplianceMessages[0].message)
| join kind=leftouter (
    resourcecontainers
    | where type =~ "microsoft.resources/subscriptions"
    | extend Chain = properties.managementGroupAncestorsChain
    | mv-expand Chain
    | project CoveredSubscription = tolower(subscriptionId), MgName = tolower(tostring(Chain.name))
) on MgName
| extend subscriptionId = iff(isnotempty(SubscriptionKey), SubscriptionKey, CoveredSubscription)
| project AssignmentId = id, AssignmentName = name, DisplayName = tostring(properties.displayName), Definition, Scope, ScopeLevel, subscriptionId, EnforcementMode, Effect, Parameters, NotScopes, NonComplianceMessage
| order by Definition asc, Scope asc, subscriptionId asc
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

### DR.6-MYSQLAUDIT MySQL flexible server audit log parameters

Engine MYSQL-AUDIT. CyberSOC collector 1.15.0. Server parameters are not in Resource Graph, so DR.6-MYSQLAUDIT lists every MySQL flexible server with the query below and then reads each one with `GET <server>/configurations/<name>?api-version=2023-12-30` for `audit_log_enabled`, `audit_log_events`, `audit_log_include_users` and `audit_log_exclude_users` on the MySQL resource provider (Reader is enough). A server is read only when all four are, since the user filters decide which users it audits. Every server is read, not only the ones DR.6-NONCOMPLIANT names: the ATMO-MXDR-MYSQL-TOSENT diagnostic setting sends the MySqlAuditLogs category, but MySQL writes no audit rows until `audit_log_enabled` is ON, so a compliant server can still send nothing. The query joins the ATMO-MXDR policy state of each server (`PolicyState`: NonCompliant, Compliant, or empty when the initiative has not evaluated it). One row per server: `subscriptionId`, `resourceGroup`, `Name`, `State`, `PolicyState`, `AuditLogEnabled`, `AuditLogEvents`, `AuditLogIncludeUsers` and `AuditLogExcludeUsers` (the value in effect, `properties.currentValue` where the response carries it and `properties.value` otherwise, empty when not read), `PendingRestart` (Yes when `audit_log_enabled` or `audit_log_events` has a saved value waiting for a restart, from `isConfigPendingRestart` or a `currentValue` that differs from `value`), `Dynamic` (Yes when `audit_log_enabled` and `audit_log_events` both return `isDynamicConfig` True, No when either returns False, empty when not reported), `ReadStatus` and `ResourceId`. A server whose read fails, or whose response carries no `properties.value`, records why in `ReadStatus` and is never read as set. It reads PARTIAL when a server was not read or Resource Graph truncated the list, FAILED when no server was read, and EMPTY when no server is in scope. Feeds CR-01, which sets the parameters on the servers in the subscriptions it assigns the initiative to, and CR-10, which sets them on every other server the initiative has evaluated (a `PolicyState`) where `audit_log_enabled` is not ON or `audit_log_events` does not cover CONNECTION, ADMIN, DDL and DCL, the events the MXDR baseline sets (CONNECTION_V2 covers CONNECTION and GENERAL covers ADMIN, DDL and DCL). Both add the missing events and keep the ones already selected, and leave the user filters as they are.

```kql
resources
| where type =~ "microsoft.dbformysql/flexibleservers"
| where id !contains "{{MRG}}"
| extend ResourceKey = tolower(id)
| join kind=leftouter (
    policyresources
    | where type =~ "microsoft.policyinsights/policystates"
    | extend AssignmentName = tostring(properties.policyAssignmentName),
             InitiativeName = tostring(properties.policySetDefinitionName),
             DefinitionName = tostring(properties.policyDefinitionName),
             Compliance     = tostring(properties.complianceState),
             ResourceKey    = tolower(tostring(properties.resourceId))
    | where AssignmentName contains "ATMO-MXDR" or InitiativeName contains "ATMO-MXDR" or DefinitionName contains "ATMO-MXDR"
    | summarize NonCompliant = countif(Compliance =~ "NonCompliant"), Compliant = countif(Compliance =~ "Compliant") by ResourceKey
) on ResourceKey
// The server's own ATMO-MXDR policy state: empty when the initiative has not evaluated it, so nothing proves its diagnostic setting.
| extend PolicyState = case(coalesce(NonCompliant, 0) > 0, "NonCompliant", coalesce(Compliant, 0) > 0, "Compliant", "")
| project Name = name, ResourceId = id, resourceGroup, subscriptionId, State = tostring(properties.state), PolicyState
| order by subscriptionId asc, resourceGroup asc, Name asc
```
