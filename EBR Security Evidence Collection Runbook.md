# EBR Security Evidence Collection Runbook

Oct 7, 2026 · @Scott Bochelen

## How to use this runbook

Run the five phases in order for each client, record every value in the worksheet in section 7, and put nothing on a slide that does not trace to a query ID or a dated portal reading.

**Set these per client before running anything**

| Parameter | Example (DRB Capital) | Used by |
| --- | --- | --- |
| Subscription IDs in scope | `a0c307ad-f1c3-4a7d-96c3-10a6eb7c9c62` | Every ARG query |
| Sentinel workspace | `drbcuswsaznatv0a0c307adf` | Every Log Analytics query |
| Managed resource group pattern | `aznativesol0` | Every ARG, Advanced Hunting and Log Analytics query that names a resource. Subscription-level results (P0.3, POS.1, POS.3, POS.5, POS.7) and the workspace inventory (P0.2) cannot exclude it |
| Service start date | Month and year from the contract | Months of managed security tile |
| Incident reporting window | Start and end date, fixed | Every OUT query |
| Posture read date | Date the ARG and portal readings were taken | Every POS and pillar figure |

**Where each query runs**

| Engine | Where to run it | Tables | Scope rule |
| --- | --- | --- | --- |
| Azure Resource Graph | Resource Graph Explorer with only this client's subscriptions selected, or `Search-AzGraph -Subscription <client IDs> -First 1000`, paging with `-SkipToken` | `resources`, `securityresources`, `authorizationresources`, `policyresources`, `recoveryservicesresources`, `appserviceresources`, `patchassessmentresources` | Exclude the managed resource group with `id !contains "aznativesol0"`. Where a record describes another resource (backup items, policy states, Defender for Cloud alerts) test that resource's id instead, as the queries below do. Never apply it to the logging estate |
| Log Analytics | Sentinel workspace > Logs | `SecurityIncident`, `SecurityAlert`, `SigninLogs`, `Usage`, `SecureScores`, `SecurityRecommendation`, `ThreatIntelIndicators` | Bounded by workspace retention, confirmed in P0.1 |
| Defender Advanced Hunting | Defender portal > Investigation & response > Hunting > Advanced hunting | `DeviceInfo`, `DeviceTvm*`, `DeviceEvents`, `EmailPostDeliveryEvents`, `IdentityLogonEvents` | 30-day lookback. Azure VM scope uses the inline `AzureResourceId` join. Devices whose `AzureResourceId` contains `aznativesol0` are excluded, as in ARG |
| Microsoft Graph and service PowerShell | The collector reads Graph with GET requests on the Azure CLI token. By hand: Graph Explorer, `az rest`, or the Microsoft.Graph PowerShell shown in each block. ExchangeOnlineManagement for mail and Purview | Tenant Secure Score, method registration, PIM, Conditional Access policies, consent, SharePoint sharing, Intune encryption and App Control, Defender for Identity sensors, DLP | Tenant-wide. An endpoint the token cannot read is UNAVAILABLE with the permission named, never a zero |
| Portal reading | Screenshot saved to the evidence pack | Assessed resources, regulatory compliance, workload protection coverage | Record the read date |

**Reporting window rules**

- Incident and alert figures use one fixed window with stated start and end dates, identical on every slide that quotes them.
- Posture figures are point-in-time and carry the read date.
- A trend (since February, since May) is quoted only when the earlier value comes from continuous export or a dated screenshot.

**Run sequence**

1. Pre-flight (P0). Confirm data reach, retention, enabled Defender plans and table availability. The reporting window is decided here.
2. Outcomes (OUT). Incident, alert and response figures for Tier 1 and the measured outcomes slide.
3. Control evidence (IA, EW, NB, DP, DR). One measured value per control, graded with the E, P, N rule.
4. Posture and benchmark (POS). Both Microsoft scores, assessed resources and benchmark controls for Tier 4 and the score model slide.
5. Backlog (BKL). The Tier 3 counts and roadmap evidence.
6. Reconcile. Trace every worksheet value to an ID, then run the checks in section 8.

Query IDs are stable across clients, so a figure in any deck can be traced back by ID. All KQL is written without `let` statements, so every block pastes straight into Resource Graph Explorer, the Logs blade or Advanced Hunting.

**Scope warning for Lighthouse.** Never run ARG with `-UseTenantScope` or with every subscription selected from the Atmosera tenant. Both return resources from every delegated customer, so one client's figures absorb another's. Scope every ARG run to the client's subscription IDs.

## Phase 0: Pre-flight

Five checks decide what the deck is allowed to claim before any figure is collected: how far back incident data reaches, which Defender plans are on, and whether the Advanced Hunting tables resolve.

**P0.1 Data reach per table** (Log Analytics)

```kusto
union withsource = SourceTable isfuzzy = true
    SecurityIncident, SecurityAlert, SigninLogs, AuditLogs, SecureScores, SecurityRecommendation
| summarize EarliestRecord = min(TimeGenerated),
            LatestRecord   = max(TimeGenerated),
            Records        = count()
          by SourceTable
| order by SourceTable asc
```

- The `SecurityIncident` earliest record is the earliest possible window start. A caption such as "since service start" that reaches further back needs a search job against archived data, or the CyberSOC reports as the named source.
- If `SecureScores` or `SecurityRecommendation` is missing, continuous export is off. POS.7 and POS.8 will return nothing, so any "since February" trend needs a dated screenshot instead.

**P0.2 Workspace retention** (ARG)

```kusto
resources
| where type =~ "microsoft.operationalinsights/workspaces"
| project Workspace     = name,
          resourceGroup,
          subscriptionId,
          RetentionDays = toint(properties.retentionInDays),
          Sku           = tostring(properties.sku.name),
          DailyCapGb    = todouble(properties.workspaceCapping.dailyQuotaGb)
```

This query deliberately carries no managed resource group exclusion. The Sentinel workspace can live in that group, and the exclusion would hide it.

**P0.3 Defender for Cloud plans by subscription** (ARG)

```kusto
securityresources
| where type =~ "microsoft.security/pricings"
| project subscriptionId,
          Plan    = name,
          Tier    = tostring(properties.pricingTier),
          SubPlan = tostring(properties.subPlan)
| order by subscriptionId asc, Tier desc, Plan asc
```

If `CloudPosture` reads Free, Defender CSPM is off. The attack path and critical recommendation tiles then read zero because the analysis is not running, so never quote them. Any plan on Free also caps the coverage figure in DR.2.

**P0.4 Advanced Hunting table availability** (Advanced Hunting)

```kusto
union withsource = SourceTable isfuzzy = true
    DeviceInfo, DeviceTvmSecureConfigurationAssessment, DeviceEvents,
    EmailPostDeliveryEvents, IdentityLogonEvents
| where Timestamp between (ago(7d) .. now())
| summarize Rows = count(), LatestRecord = max(Timestamp) by SourceTable
```

A table missing from the output did not resolve. When the device tables are missing, as at DRB Capital in August, every EW figure falls back to Microsoft Secure Score controls from POS.6 and the slide footnote says so.

**P0.5 Estate inventory by resource type** (ARG)

```kusto
resources
| where id !contains "aznativesol0"
| summarize Resources = count() by subscriptionId, ResourceType = tolower(type)
| order by Resources desc
```

The sum is the estate count. Never caption it as assessed resources, which is POS.2 or the portal reading.

## Phase 1: Outcomes and SOC performance

Every Tier 1 figure and every response tile on the measured outcomes slide comes from eight queries run against one fixed window. Replace `datetime(2026-01-01)` and `datetime(2026-07-31)` with the window start and end in each query.

**Lock the definitions before collecting.** The two decks used "alerts investigated and resolved" and "alerts triaged" for counts drawn from different tables. Pick one row below per tile and keep the slide label word for word.

| Tile | Definition | Query |
| --- | --- | --- |
| Alerts triaged | Distinct `SecurityAlert` records in the window, all products | OUT.5 |
| Incidents resolved | Closed incidents created in the window | OUT.1 |
| Median time to close | All closed incidents, creation to close | OUT.2, row All |
| 90th percentile close, high severity | High severity closed incidents only | OUT.2, row High |
| High severity reduction | First full month against last full month | OUT.3 |
| True positives contained | True positive incidents with a containment comment | OUT.4 |
| Confirmed data loss | True positives with confirmed data access, zero rows expected | OUT.4 |
| Malicious sign-in to containment | Account disable time minus malicious sign-in time | OUT.7, OUT.8 |

**Scope rule for OUT.1 to OUT.7.** Only incidents that reached the managed service are counted. An incident counts when its comments or closing comment reference an Atmosera ticket (the Zendesk ticket URL, or "per ZD ticket NNNN" appended by the ticket integration). Informational severity is excluded everywhere. The script expands `{{TICKET}}` to the clause below and accepts `-TicketPattern` to change the expression for a client whose ticket integration writes a different comment. Detections (OUT.5, OUT.6) are limited to the alerts linked to those incidents.

```kusto
| where Severity != "Informational"
| where (tostring(Comments) matches regex @"(?i)(zendesk\.com/agent/tickets/\d+|\bZD\s*(ticket|#)?\s*#?\s*\d{4,})" or tostring(ClassificationComment) matches regex @"(?i)(zendesk\.com/agent/tickets/\d+|\bZD\s*(ticket|#)?\s*#?\s*\d{4,})")
```

**OUT.1 Incident volume and disposition** (Log Analytics)

```kusto
SecurityIncident
| where TimeGenerated between (datetime(2026-01-01) .. now())        // prefilter at window start
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where CreatedTime between (datetime(2026-01-01) .. endofday(datetime(2026-07-31)))            // reporting window
| where Severity != "Informational"
| where (tostring(Comments) matches regex @"(?i)(zendesk\.com/agent/tickets/\d+|\bZD\s*(ticket|#)?\s*#?\s*\d{4,})" or tostring(ClassificationComment) matches regex @"(?i)(zendesk\.com/agent/tickets/\d+|\bZD\s*(ticket|#)?\s*#?\s*\d{4,})")
| summarize Raised         = count(),
            Closed         = countif(Status == "Closed"),
            Open           = countif(Status != "Closed"),
            TruePositive   = countif(Classification == "TruePositive"),
            BenignPositive = countif(Classification == "BenignPositive"),
            FalsePositive  = countif(Classification == "FalsePositive"),
            ClosedUnclassified = countif(Status == "Closed" and Classification in ("Undetermined", ""))
```

Window membership is set by `CreatedTime` after the latest state is taken. An incident created before the window but updated during it is not counted.

**OUT.2 Triage and close time by severity, plus all incidents** (Log Analytics)

```kusto
SecurityIncident
| where TimeGenerated between (datetime(2026-01-01) .. now())
| summarize arg_max(TimeGenerated, Status, Severity, CreatedTime, ClosedTime, ModifiedBy, Comments, ClassificationComment),
            FirstTriaged = minif(TimeGenerated, Status != "New")
          by IncidentNumber
| where CreatedTime between (datetime(2026-01-01) .. endofday(datetime(2026-07-31)))
| where Severity != "Informational"
| where (tostring(Comments) matches regex @"(?i)(zendesk\.com/agent/tickets/\d+|\bZD\s*(ticket|#)?\s*#?\s*\d{4,})" or tostring(ClassificationComment) matches regex @"(?i)(zendesk\.com/agent/tickets/\d+|\bZD\s*(ticket|#)?\s*#?\s*\d{4,})")
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
          by Scope
```

- One row per severity plus an All row, so the overall median and the high severity percentile come from one run.
- If `AutoClosed` is a large share of `Incidents`, the median describes automation rather than analysts. Add `| where not(IsAutoClosed)` before the summarize and label the tile analyst-handled. Confirm the `ModifiedBy` text for automation rules on the first run.
- Quote the median, never the mean. One long-running incident drags a mean past the point of being defensible.

**OUT.3 Monthly incident volume by severity and classification** (Log Analytics)

```kusto
SecurityIncident
| where TimeGenerated between (datetime(2026-01-01) .. now())
| summarize arg_max(TimeGenerated, Severity, CreatedTime, Classification, Comments, ClassificationComment) by IncidentNumber
| where CreatedTime between (datetime(2026-01-01) .. endofday(datetime(2026-07-31)))
| where Severity != "Informational"
| where (tostring(Comments) matches regex @"(?i)(zendesk\.com/agent/tickets/\d+|\bZD\s*(ticket|#)?\s*#?\s*\d{4,})" or tostring(ClassificationComment) matches regex @"(?i)(zendesk\.com/agent/tickets/\d+|\bZD\s*(ticket|#)?\s*#?\s*\d{4,})")
| summarize Total         = count(),
            High          = countif(Severity == "High"),
            Medium        = countif(Severity == "Medium"),
            Low           = countif(Severity == "Low"),
            Informational = countif(Severity == "Informational"),
            TruePositive  = countif(Classification == "TruePositive"),
            FalsePositive = countif(Classification == "FalsePositive")
          by Month = startofmonth(CreatedTime)
| order by Month asc
```

Compare full months only. A partial final month understates volume and overstates the reduction. If retention does not reach the first month, cite the CyberSOC report by name as the source.

**OUT.4 True positives and the data loss check** (Log Analytics)

```kusto
SecurityIncident
| where TimeGenerated between (datetime(2026-01-01) .. now())
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where CreatedTime between (datetime(2026-01-01) .. endofday(datetime(2026-07-31)))
| where Severity != "Informational"
| where (tostring(Comments) matches regex @"(?i)(zendesk\.com/agent/tickets/\d+|\bZD\s*(ticket|#)?\s*#?\s*\d{4,})" or tostring(ClassificationComment) matches regex @"(?i)(zendesk\.com/agent/tickets/\d+|\bZD\s*(ticket|#)?\s*#?\s*\d{4,})")
| where Classification == "TruePositive"
| extend Tactics = tostring(AdditionalData.tactics)
| project IncidentNumber, Title, Severity, CreatedTime, ClosedTime,
          ClassificationReason, ClassificationComment, Tactics,
          ExfilOrImpactTactic = Tactics has_any ("Exfiltration", "Collection", "Impact")
| order by CreatedTime asc
```

The "3 of 3 contained" tile is the row count, with a containment statement in each `ClassificationComment`. The zero data loss tile holds only when no row is flagged `ExfilOrImpactTactic`, or each flagged row's comment records no data access. Tactic tags are detection-time labels, so the comment and the incident report are the evidence.

**OUT.5 Alerts triaged by product and severity** (Log Analytics)

```kusto
let TicketedAlertIds = SecurityIncident
| where TimeGenerated between (datetime(2026-01-01) .. now())
| summarize arg_max(TimeGenerated, *) by TenantId, IncidentNumber
| where CreatedTime between (datetime(2026-01-01) .. endofday(datetime(2026-07-31)))
| where Severity != "Informational"
| where (tostring(Comments) matches regex @"(?i)(zendesk\.com/agent/tickets/\d+|\bZD\s*(ticket|#)?\s*#?\s*\d{4,})" or tostring(ClassificationComment) matches regex @"(?i)(zendesk\.com/agent/tickets/\d+|\bZD\s*(ticket|#)?\s*#?\s*\d{4,})")
| mv-expand AlertId = AlertIds to typeof(string)
| distinct AlertId;
SecurityAlert
| where TimeGenerated between (datetime(2026-01-01) .. endofday(datetime(2026-07-31)))
| summarize arg_max(TimeGenerated, ProductName, AlertSeverity) by SystemAlertId
| where AlertSeverity != "Informational"
| where SystemAlertId in (TicketedAlertIds)
| summarize Alerts = count() by ProductName, AlertSeverity
| order by Alerts desc
```

**OUT.6 Boundary and egress detections** (Log Analytics)

```kusto
let TicketedAlertIds = SecurityIncident
| where TimeGenerated between (datetime(2026-01-01) .. now())
| summarize arg_max(TimeGenerated, *) by TenantId, IncidentNumber
| where CreatedTime between (datetime(2026-01-01) .. endofday(datetime(2026-07-31)))
| where Severity != "Informational"
| where (tostring(Comments) matches regex @"(?i)(zendesk\.com/agent/tickets/\d+|\bZD\s*(ticket|#)?\s*#?\s*\d{4,})" or tostring(ClassificationComment) matches regex @"(?i)(zendesk\.com/agent/tickets/\d+|\bZD\s*(ticket|#)?\s*#?\s*\d{4,})")
| mv-expand AlertId = AlertIds to typeof(string)
| distinct AlertId;
SecurityAlert
| where TimeGenerated between (datetime(2026-01-01) .. endofday(datetime(2026-07-31)))
| summarize arg_max(TimeGenerated, AlertName, ProductName, Tactics) by SystemAlertId
| where SystemAlertId in (TicketedAlertIds)
| where AlertName has_any ("DNS", "domain", "tunneling", "SSH", "RDP", "remote management",
                           "brute force", "port scan", "scanning", "blob", "exfiltration")
     or Tactics has_any ("CommandAndControl", "Exfiltration")
| summarize Alerts = count() by AlertName, ProductName
| order by Alerts desc
```

The keyword list is the definition of a boundary detection. Record it in the worksheet and reuse it unchanged next cycle so the trend compares like with like.

**OUT.7 Attack disruption incidents** (Log Analytics)

```kusto
SecurityIncident
| where TimeGenerated between (datetime(2026-01-01) .. now())
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where CreatedTime between (datetime(2026-01-01) .. endofday(datetime(2026-07-31)))
| where Severity != "Informational"
| where (tostring(Comments) matches regex @"(?i)(zendesk\.com/agent/tickets/\d+|\bZD\s*(ticket|#)?\s*#?\s*\d{4,})" or tostring(ClassificationComment) matches regex @"(?i)(zendesk\.com/agent/tickets/\d+|\bZD\s*(ticket|#)?\s*#?\s*\d{4,})")
| where tostring(Labels) has "Attack Disruption"
| project IncidentNumber, Title, Severity, FirstActivityTime, CreatedTime,
          ClosedTime, Classification
| order by CreatedTime asc
```

**OUT.8 Account disable events for containment timing** (Log Analytics)

```kusto
AuditLogs
| where TimeGenerated between (datetime(2026-01-01) .. endofday(datetime(2026-07-31)))
| where OperationName =~ "Disable account"
| extend TargetUser = tostring(TargetResources[0].userPrincipalName),
         Initiator  = coalesce(tostring(InitiatedBy.app.displayName),
                               tostring(InitiatedBy.user.userPrincipalName))
| project TimeGenerated, TargetUser, Initiator, Result
| order by TimeGenerated asc
```

Containment minutes are the OUT.8 disable time minus the malicious sign-in time for the same user in `SigninLogs`. Confirm the disruption tag text and the initiator name on the first run, and keep the incident timeline from Defender portal > Investigation & response > Incidents & alerts > Incidents as the source of record.

## Phase 2: Control evidence by pillar

Each control on the controls slides gets one measured value, graded with a single rule that every client deck states the same way.

**Grading rule, standard for every client**

- E is enforced on 90 percent or more of in-scope resources, P is 50 to 89 percent, N is under 50 percent.
- Foundational controls carry 2 points and defense in depth controls carry 1. E earns full points, P earns half, N earns none.
- A control marked out of scope leaves the denominator rather than counting against the grade.
- Grade bands: A 93, A minus 90, B plus 87, B 83, B minus 80, C plus 77, C 73, C minus 70, D below 70.

The Tier 2 tiles come straight from the finished matrix. Foundational controls enforced is the count of foundational controls at E. Defense in depth in force is the count of in-scope defense in depth controls at E. The overall grade is total points earned over total available.

**Run first: DFC.1 Defender for Cloud control evidence sweep** (ARG)

One pass returns the Defender for Cloud healthy and unhealthy split for roughly twenty controls across all five pillars. Read the matching rows wherever a table below cites DFC.1.

```kusto
securityresources
| where type =~ "microsoft.security/assessments"
| where id !contains "aznativesol0"
| extend Recommendation = tostring(properties.displayName),
         Status         = tostring(properties.status.code),
         Severity       = tostring(properties.metadata.severity)
| where Recommendation has_any (
    "EDR", "endpoint protection", "Secure Boot", "vTPM", "guest configuration",
    "encryption at host", "Disk Encryption", "backup", "system updates",
    "vulnerability", "vulnerabilities",
    "management ports", "network security groups", "private endpoint", "private link",
    "public network access",
    "secure transfer", "TLS", "HTTPS", "FTPS", "secure communication protocols",
    "purge protection", "soft delete", "RBAC", "resource logs", "diagnostic logs", "auditing",
    "MFA", "owner permissions", "Defender for", "threat protection")
| summarize Healthy       = countif(Status == "Healthy"),
            Unhealthy     = countif(Status == "Unhealthy"),
            NotApplicable = countif(Status == "NotApplicable")
          by Recommendation, Severity
| extend PctHealthy = round(100.0 * Healthy / (Healthy + Unhealthy), 1)
| order by Recommendation asc
```

Where Defender for Cloud and a direct ARG property query disagree, quote Defender for Cloud and keep the ARG result as the itemized list. Encryption at host is the usual case: the property query misses machines protected by Azure Disk Encryption, which Defender for Cloud accepts.

### Identity and Access (SOC 2 CC6.1, CC6.2, CC6.3)

| ID | Control | Tier | Measure | Evidence |
| --- | --- | --- | --- | --- |
| IA-F1 | Multifactor authentication required for all users | F | An enabled Conditional Access policy requiring MFA on every application for all users, or security defaults, reads In force, and the same for the admin portals. The sign-in evidence (members with MFA over members signing in, 30 days, reused sessions no policy checked left out in a federated tenant) supports the note. Without the policy inventory the sign-in ratio grades the control | IA.8, IA.1, IA.1-ADMINPORTAL, IA.1-FEDERATION |
| IA-F2 | Privileged role assignments governed and reviewed | F | Eligible against standing privileged Entra assignments, and Azure Owner count | IA.6, IA.7 |
| IA-F3 | Anti-phishing policy applied to every mailbox | F | Defender for Office anti-phishing points earned of available | POS.6, IA.9 |
| IA-F4 | Legacy and high-risk authentication protocols blocked | F | Enabled Conditional Access policies that block legacy authentication (or security defaults) and device code flow for all users. Sign-ins show only whether an account got past the policy. Without a policy inventory, In force only when Conditional Access blocks (error 53003) are recorded and no sign-in succeeded | IA.3, IA.3-DEVICECODE, IA.8 |
| IA-F5 | Location-based sign-in access controls enforced through Conditional Access | F | An enabled policy with a country or named location condition that blocks access or requires MFA for all users and all resources (replaced the share of sign-ins with a CA status other than notApplied on Oct 12, 2026) | IA.4-LOCATION, IA.8 |
| IA-D1 | Phishing-resistant authentication required for all users | D | Distinct phishing-resistant users over users signing in | IA.2, IA.5 |
| IA-D2 | Access conditioned on device compliance and ownership | D | Sign-ins gated by a compliant or hybrid-joined device grant | IA.4b |
| IA-D3 | Cloud management plane limited to administrative roles | D | Users reaching Azure management against privileged role holders, and the Manage access control points | IA.14, IA.6, POS.3 |
| IA-D4 | Identity Protection sign-in and user risk policies enforced | D | Enabled CA policies carrying risk conditions, including all users | IA.11, IA.8 |
| IA-D5 | Active Directory attack path exposure managed (US Claims) | D | Identity recommended actions complete | POS.6 |
| IA-D6 | Application consent governed by admin approval (DRB) | D | Permission grant policy assigned to users and the admin consent workflow | IA.13 |
| IA-D7 | Self-service reset and leaked credential response (DRB) | D | SSPR and leaked credential actions complete | POS.6 |

IA-D5 to IA-D7 are alternates. Each client carries five defense in depth controls per pillar, so choose them once and keep them fixed across review cycles.

**IA.1 MFA evidence per user, successful sign-ins** (Log Analytics)

```kusto
// Earliest direct MFA in each session, 90 days of successful sign-ins in every app (bounded by workspace retention)
let MfaSessions = SigninLogs
| where TimeGenerated between (ago(90d) .. now())
| where ResultType == "0" and isnotempty(UserId)
| project TimeGenerated, SessionKey = tostring(column_ifexists("SessionId", "")),
          AuthenticationRequirement, AuthenticationDetails, AuthenticationMethodsUsed, MfaDetail
| where isnotempty(SessionKey)
| extend AuthText = strcat(tostring(AuthenticationDetails), " ", AuthenticationMethodsUsed)
| extend MfaRequired     = AuthenticationRequirement =~ "multiFactorAuthentication",
         MfaExternal     = AuthText has "claim provided by external provider",
         MfaTokenClaim   = AuthText has "MFA requirement satisfied by claim in the token",
         Passwordless    = AuthText has_any ("Windows Hello", "FIDO2", "Passkey", "Passwordless", "Platform Credential"),
         MfaEntraStep    = isnotempty(tostring(MfaDetail.authMethod))
                           or AuthText has_any ("Mobile app notification", "Text message", "Phone call", "OATH verification code")
| summarize FirstMfa = minif(TimeGenerated, MfaEntraStep or MfaExternal or Passwordless or MfaRequired or MfaTokenClaim) by SessionKey
| where isnotnull(FirstMfa);
SigninLogs
| where TimeGenerated between (ago(30d) .. now())
| where ResultType == "0" and isnotempty(UserId)
| project TimeGenerated, SessionKey = tostring(column_ifexists("SessionId", "")),
          UserId, UserType, CrossTenantAccessType, AppDisplayName, AuthenticationRequirement,
          AuthenticationDetails, AuthenticationMethodsUsed, MfaDetail, AuthenticationProtocol,
          IncomingTokenType, DeviceDetail, ConditionalAccessPolicies
// Partner technicians (GDAP) and outbound passthrough get their own rows, so Member is the client's own members
| extend UserType = case(CrossTenantAccessType =~ "serviceProvider", "Partner (GDAP)",
                         CrossTenantAccessType =~ "passthrough",     "Outbound passthrough",
                         UserType)
| extend AuthText = strcat(tostring(AuthenticationDetails), " ", AuthenticationMethodsUsed)
| extend MfaRequired     = AuthenticationRequirement =~ "multiFactorAuthentication",
         MfaExternal     = AuthText has "claim provided by external provider",
         MfaTokenClaim   = AuthText has "MFA requirement satisfied by claim in the token",
         Passwordless    = AuthText has_any ("Windows Hello", "FIDO2", "Passkey", "Passwordless", "Platform Credential"),
         MfaEntraStep    = isnotempty(tostring(MfaDetail.authMethod))
                           or AuthText has_any ("Mobile app notification", "Text message", "Phone call", "OATH verification code")
// A PRT or refresh token is a reused session even without the "Previously satisfied" step
| extend Federated       = IncomingTokenType has_any ("saml11", "saml20"),
         SessionReuse    = AuthText has "Previously satisfied" or IncomingTokenType has_any ("primaryRefreshToken", "refreshToken"),
         DeviceLogon     = AppDisplayName in~ ("Windows Sign In", "Device Registration Service"),
         PasswordGrant   = AuthenticationProtocol =~ "ropc",
         CompliantDevice = tostring(DeviceDetail.isCompliant) =~ "true"
// Policy evaluation is the only record of whether a reused session carried MFA
| extend CaPolicies = todynamic(ConditionalAccessPolicies)
| mv-apply Policy = iff(coalesce(array_length(CaPolicies), 0) == 0, dynamic([{}]), CaPolicies) on (
      extend Result  = tostring(Policy.result),
             Grants  = tostring(Policy.enforcedGrantControls),
             MfaOnly = coalesce(array_length(Policy.enforcedGrantControls), 0) == 1
                       and tostring(Policy.enforcedGrantControls[0]) == "Mfa"
      | summarize EnforcedDevice = countif(Result == "success" and Grants has_any ("RequireCompliantDevice", "RequireDomainJoinedDevice")),
                  SessionMfa     = countif(Result in ("success", "reportOnlySuccess") and MfaOnly),
                  SessionNoMfa   = countif(Result == "reportOnlyInterrupted" and MfaOnly)
  )
// FirstMfa: the earliest direct MFA in the same session, from the pre-pass
| lookup kind=leftouter MfaSessions on SessionKey
| extend Evidence = case(
      MfaEntraStep,                                     "MFA performed at Entra",
      MfaExternal,                                      "MFA asserted by federated provider",
      Passwordless,                                     "Phishing-resistant credential",
      MfaRequired or MfaTokenClaim or 0 < SessionMfa,   "MFA carried in session",
      PasswordGrant,                                    "Password only: ROPC",
      DeviceLogon and Federated,                        "Windows logon through federation (WS-Trust, no MFA possible)",
      DeviceLogon,                                      "Device logon or registration",
      Federated,                                        "Federated sign-in without an MFA assertion",
      0 < SessionNoMfa,                                 "Session without MFA (report-only policy would prompt)",
      FirstMfa <= TimeGenerated,                        "MFA earlier in the same session",
      SessionReuse,                                     "Session reuse, MFA not evaluated",
      "No MFA evidence, no session reuse")
| extend HasMfa = Evidence in ("MFA performed at Entra", "MFA asserted by federated provider",
                               "Phishing-resistant credential", "MFA carried in session",
                               "MFA earlier in the same session"),
         Device = case(0 < EnforcedDevice, "Enforced", CompliantDevice, "CompliantNotEnforced", "Unmanaged")
// Member view: Windows logon and device registration are left out of every denominator
| where not(DeviceLogon)
| summarize AppSignIns      = count(),
            MfaSignIns      = countif(HasMfa),
            EntraMfaSignIns = countif(HasMfa and Evidence != "MFA asserted by federated provider"),
            FedMfaSignIns   = countif(Evidence == "MFA asserted by federated provider"),
            FedNoMfaSignIns = countif(Evidence == "Federated sign-in without an MFA assertion"),
            NotEvaluated    = countif(Evidence == "Session reuse, MFA not evaluated"),
            SessionLinked   = countif(Evidence == "MFA earlier in the same session"),
            Covered         = countif(HasMfa or Device == "Enforced")
          by UserId, UserType
| summarize UsersSignedIn           = count(),
            MfaAtLeastOnce          = countif(0 < MfaSignIns),
            MfaEveryAppSignIn       = countif(MfaSignIns == AppSignIns),
            CoveredEveryAppSignIn   = countif(Covered == AppSignIns),
            FederatedMfaAtLeastOnce = countif(0 < FedMfaSignIns),
            FederatedWithoutMfa     = countif(0 < FedNoMfaSignIns),
            NoMfaOnlyUnevaluated    = countif(MfaSignIns == 0 and NotEvaluated == AppSignIns),
            MfaSessionLinkedOnly    = countif(0 < MfaSignIns and SessionLinked == MfaSignIns),
            UsersEntraMfa           = countif(0 < EntraMfaSignIns)
          by UserType
// Earlier column names, kept so report-model.js and packs collected before 1.12.0 read the same way
| extend UsersChallenged  = MfaAtLeastOnce,
         UsersAlwaysMfa   = MfaEveryAppSignIn,
         UsersExternalMfa = FederatedMfaAtLeastOnce
| extend PctChallenged = round(100.0 * UsersChallenged / UsersSignedIn, 1),
         PctAlwaysMfa  = round(100.0 * UsersAlwaysMfa / UsersSignedIn, 1)
| project UserType, UsersSignedIn, UsersChallenged, UsersAlwaysMfa, UsersExternalMfa, UsersEntraMfa,
          PctChallenged, PctAlwaysMfa, MfaAtLeastOnce, MfaEveryAppSignIn, CoveredEveryAppSignIn,
          FederatedMfaAtLeastOnce, FederatedWithoutMfa, NoMfaOnlyUnevaluated, MfaSessionLinkedOnly
| order by UsersSignedIn desc
```

Each successful sign-in is classified by the strongest MFA evidence it carries, following `docs/Federated MFA Evaluation.md` (Q2, the member view and Q5). Collector 1.12.0 replaced the three-signal query, which read a reused session that no policy checked as a sign-in without MFA. Collector 1.13.0 added the session rules from Q5. The step detail strings were confirmed with Q1 in the Shook tenant (Okta) on October 13, 2026.

- MFA evidence, strongest first: an MFA step at Entra (`MfaDetail.authMethod`, or an Authenticator, text, phone or OATH step), MFA asserted by the federated provider (step detail "MFA requirement satisfied by claim provided by external provider"), a phishing-resistant credential, or MFA carried in the session (the requirement field, "MFA requirement satisfied by claim in the token", or a policy whose only grant is Require multifactor authentication returning success or reportOnlySuccess).
- Session pre-pass (1.13.0): the `MfaSessions` let reads 90 days of successful sign-ins in every app (in practice bounded by workspace retention) and records the earliest direct MFA in each `SessionId` (an Entra step, the federated provider claim, a phishing-resistant credential, the requirement field or the claim in the token). Policy results are left out of the pre-pass. `column_ifexists` keeps the query running in a workspace without `SessionId`, where the rule simply never fires.
- A sign-in without direct evidence reads "MFA earlier in the same session" when the pre-pass found direct MFA in its session at or before its own time. That counts as MFA. It comes after the federated, device logon and report-only interrupted rules, and before session reuse, so it also applies to "Previously satisfied" sign-ins.
- Sign-ins without MFA evidence are grouped by path: ROPC password grant, Windows logon through federation (WS-Trust can never carry MFA), other device logon or registration, a federated sign-in without an MFA assertion, a session the report-only Require MFA policy would have prompted (reportOnlyInterrupted), a reused session that no policy checked ("Session reuse, MFA not evaluated", which since 1.13.0 also takes a PRT or refresh token without the "Previously satisfied" step), and the rest ("No MFA evidence, no session reuse").
- Windows Sign In and Device Registration Service are left out before the per-user count, so Windows logon never enters a denominator.
- Partner technicians (GDAP, `CrossTenantAccessType` serviceProvider) and outbound passthrough sign-ins get their own `UserType` rows, so `Member` is the client's own members.
- Only the plain Require multifactor authentication grant counts as policy evidence. The phishing-resistant authentication strength rejects federated MFA, so it cannot measure a federated tenant, and the query names no tenant-specific policy.

| Column | Meaning |
| --- | --- |
| `UsersSignedIn` | Users with at least one successful sign-in other than Windows logon or device registration |
| `UsersChallenged`, `MfaAtLeastOnce` | Users with MFA evidence on at least one of those sign-ins (same figure, the earlier name is kept for the report and older packs) |
| `UsersAlwaysMfa`, `MfaEveryAppSignIn` | Users with MFA evidence on every one of those sign-ins |
| `UsersExternalMfa`, `FederatedMfaAtLeastOnce` | Users whose MFA was asserted by the federated identity provider at least once |
| `UsersEntraMfa` | Users with MFA evidence Entra recorded itself (Entra step, phishing-resistant credential or session) |
| `CoveredEveryAppSignIn` | Users whose every sign-in carried MFA or passed an enforced device grant |
| `FederatedWithoutMfa` | Users with at least one federated sign-in that carried no MFA assertion |
| `NoMfaOnlyUnevaluated` | Users with no MFA evidence whose only sign-ins were reused sessions no policy checked. Not evaluated, not missing MFA |
| `MfaSessionLinkedOnly` | Users whose only MFA evidence is "MFA earlier in the same session", inferred from an earlier MFA sign-in in that session (1.13.0) |
| `PctChallenged`, `PctAlwaysMfa` | The two ratios over `UsersSignedIn` |

In a federated tenant (IA.1-FEDERATION lists a federated domain), the report grades members as `UsersChallenged` over `UsersSignedIn` minus `NoMfaOnlyUnevaluated`, says so in the control note and keeps the not evaluated count and `MfaSessionLinkedOnly` in the presenter notes. In a managed tenant the grade stays `UsersChallenged` over `UsersSignedIn`. Packs collected before 1.12.0 carry neither column and grade as before.

Shook (shb-com), September 13 to October 13, 2026, members, with collector 1.12.0: 1,414 signed in, 563 with MFA evidence (all asserted by Okta), 550 with only unevaluated sessions and 2 with a federated sign-in that carried no MFA assertion, so the grade read 563 of 864. Q5 (October 14, 2026) moved 232 of the 1,884 "No MFA evidence, no session reuse" sign-ins to "MFA earlier in the same session" and 87 to session reuse, so with 1.13.0 the 563 and the 550 shift. The other 1,565 are interactive with no token and stay in that bucket. To measure the reused sessions, deploy a report-only Conditional Access policy with the plain Require multifactor authentication grant for all members and all resources. After 7 to 30 days every reused session records reportOnlySuccess or reportOnlyInterrupted, and this query reads both. Check `federatedIdpMfaBehavior` first (IA.1-FEDERATION), because with rejectMfaByFederatedIdp the policy ignores the provider's MFA.

This counts successful sign-ins only. `PctAlwaysMfa` is the stricter reading for a client that asks how many users can sign in without MFA.

**IA.1-ADMINPORTAL MFA at admin portal sign-in** (Log Analytics)

```kusto
// Earliest direct MFA in each session, 90 days of successful sign-ins in every app (bounded by workspace retention)
let MfaSessions = SigninLogs
| where TimeGenerated between (ago(90d) .. now())
| where ResultType == "0" and isnotempty(UserId)
| project TimeGenerated, SessionKey = tostring(column_ifexists("SessionId", "")),
          AuthenticationRequirement, AuthenticationDetails, AuthenticationMethodsUsed, MfaDetail
| where isnotempty(SessionKey)
| extend AuthText = strcat(tostring(AuthenticationDetails), " ", AuthenticationMethodsUsed)
| extend MfaRequired     = AuthenticationRequirement =~ "multiFactorAuthentication",
         MfaExternal     = AuthText has "claim provided by external provider",
         MfaTokenClaim   = AuthText has "MFA requirement satisfied by claim in the token",
         Passwordless    = AuthText has_any ("Windows Hello", "FIDO2", "Passkey", "Passwordless", "Platform Credential"),
         MfaEntraStep    = isnotempty(tostring(MfaDetail.authMethod))
                           or AuthText has_any ("Mobile app notification", "Text message", "Phone call", "OATH verification code")
| summarize FirstMfa = minif(TimeGenerated, MfaEntraStep or MfaExternal or Passwordless or MfaRequired or MfaTokenClaim) by SessionKey
| where isnotnull(FirstMfa);
SigninLogs
| where TimeGenerated between (ago(30d) .. now())
| where ResultType == "0" and isnotempty(UserId)
| where ResourceIdentity in ("497effe9-df71-4043-a8bb-14cf78c4b63b",   // Exchange admin center
                             "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",   // Azure portal and Entra admin center
                             "00000006-0000-0ff1-ce00-000000000000",   // Microsoft 365 admin center
                             "80ccca67-54bd-44ab-8625-4b79c4dc7775")   // Security and Compliance center
| project TimeGenerated, SessionKey = tostring(column_ifexists("SessionId", "")),
          UserId, UserType, CrossTenantAccessType, AppDisplayName, AuthenticationRequirement,
          AuthenticationDetails, AuthenticationMethodsUsed, MfaDetail, AuthenticationProtocol,
          IncomingTokenType, DeviceDetail, ConditionalAccessPolicies
// Partner technicians (GDAP) and outbound passthrough get their own rows, so Member is the client's own members
| extend UserType = case(CrossTenantAccessType =~ "serviceProvider", "Partner (GDAP)",
                         CrossTenantAccessType =~ "passthrough",     "Outbound passthrough",
                         UserType)
| extend AuthText = strcat(tostring(AuthenticationDetails), " ", AuthenticationMethodsUsed)
| extend MfaRequired     = AuthenticationRequirement =~ "multiFactorAuthentication",
         MfaExternal     = AuthText has "claim provided by external provider",
         MfaTokenClaim   = AuthText has "MFA requirement satisfied by claim in the token",
         Passwordless    = AuthText has_any ("Windows Hello", "FIDO2", "Passkey", "Passwordless", "Platform Credential"),
         MfaEntraStep    = isnotempty(tostring(MfaDetail.authMethod))
                           or AuthText has_any ("Mobile app notification", "Text message", "Phone call", "OATH verification code")
// A PRT or refresh token is a reused session even without the "Previously satisfied" step
| extend Federated       = IncomingTokenType has_any ("saml11", "saml20"),
         SessionReuse    = AuthText has "Previously satisfied" or IncomingTokenType has_any ("primaryRefreshToken", "refreshToken"),
         DeviceLogon     = AppDisplayName in~ ("Windows Sign In", "Device Registration Service"),
         PasswordGrant   = AuthenticationProtocol =~ "ropc",
         CompliantDevice = tostring(DeviceDetail.isCompliant) =~ "true"
// Policy evaluation is the only record of whether a reused session carried MFA
| extend CaPolicies = todynamic(ConditionalAccessPolicies)
| mv-apply Policy = iff(coalesce(array_length(CaPolicies), 0) == 0, dynamic([{}]), CaPolicies) on (
      extend Result  = tostring(Policy.result),
             Grants  = tostring(Policy.enforcedGrantControls),
             MfaOnly = coalesce(array_length(Policy.enforcedGrantControls), 0) == 1
                       and tostring(Policy.enforcedGrantControls[0]) == "Mfa"
      | summarize EnforcedDevice = countif(Result == "success" and Grants has_any ("RequireCompliantDevice", "RequireDomainJoinedDevice")),
                  SessionMfa     = countif(Result in ("success", "reportOnlySuccess") and MfaOnly),
                  SessionNoMfa   = countif(Result == "reportOnlyInterrupted" and MfaOnly)
  )
// FirstMfa: the earliest direct MFA in the same session, from the pre-pass
| lookup kind=leftouter MfaSessions on SessionKey
| extend Evidence = case(
      MfaEntraStep,                                     "MFA performed at Entra",
      MfaExternal,                                      "MFA asserted by federated provider",
      Passwordless,                                     "Phishing-resistant credential",
      MfaRequired or MfaTokenClaim or 0 < SessionMfa,   "MFA carried in session",
      PasswordGrant,                                    "Password only: ROPC",
      DeviceLogon and Federated,                        "Windows logon through federation (WS-Trust, no MFA possible)",
      DeviceLogon,                                      "Device logon or registration",
      Federated,                                        "Federated sign-in without an MFA assertion",
      0 < SessionNoMfa,                                 "Session without MFA (report-only policy would prompt)",
      FirstMfa <= TimeGenerated,                        "MFA earlier in the same session",
      SessionReuse,                                     "Session reuse, MFA not evaluated",
      "No MFA evidence, no session reuse")
| extend HasMfa = Evidence in ("MFA performed at Entra", "MFA asserted by federated provider",
                               "Phishing-resistant credential", "MFA carried in session",
                               "MFA earlier in the same session"),
         Device = case(0 < EnforcedDevice, "Enforced", CompliantDevice, "CompliantNotEnforced", "Unmanaged")
| summarize SignIns         = count(),
            MfaSignIns      = countif(HasMfa),
            FedMfaSignIns   = countif(Evidence == "MFA asserted by federated provider"),
            FedNoMfaSignIns = countif(Evidence == "Federated sign-in without an MFA assertion"),
            NotEvaluated    = countif(Evidence == "Session reuse, MFA not evaluated")
          by UserId, UserType
| summarize Users                   = count(),
            UsersChallenged         = countif(0 < MfaSignIns),
            UsersAlwaysMfa          = countif(MfaSignIns == SignIns),
            FederatedMfaAtLeastOnce = countif(0 < FedMfaSignIns),
            FederatedWithoutMfa     = countif(0 < FedNoMfaSignIns),
            NoMfaOnlyUnevaluated    = countif(MfaSignIns == 0 and NotEvaluated == SignIns),
            SignIns                 = sum(SignIns),
            MfaSignIns              = sum(MfaSignIns),
            NotEvaluatedSignIns     = sum(NotEvaluated)
          by UserType
| extend PctSignInsMfa = round(100.0 * MfaSignIns / SignIns, 1)
| order by Users desc
```

The four app IDs are the Microsoft Admin Portals target resource group, which the ATMO-MXDR-CA-MFA-ADMIN policy targets. Members only on the slide. Same evidence classification as IA.1 (no Windows logon reaches these apps). The session pre-pass reads every app, so "MFA earlier in the same session" can come from a sign-in outside the portals. `NoMfaOnlyUnevaluated` and `NotEvaluatedSignIns` count the users and sign-ins that only reused a session no policy checked. In a federated tenant the report leaves those users out of the grade, as for IA.1.

**IA.1-FEDERATION Federated domains and how Entra treats their MFA** (Microsoft Graph)

The collector reads `GET /v1.0/domains?$select=id,authenticationType,isRoot,isVerified` and, for each domain whose `authenticationType` is Federated, `GET /v1.0/domains/{id}/federationConfiguration` (needs Domain.Read.All, GET only, with the Azure CLI token like every Graph measure). One row per federated domain: Domain, IsRoot, IdentityProvider (Okta, AD FS, Ping or Other, named from the URIs), IssuerUri, PassiveSignInUri, ActiveSignInUri, PreferredAuthenticationProtocol, FederatedIdpMfaBehavior and ConfigSource. A subdomain of a federated root inherits its federation and Graph answers 404 Request_ResourceNotFound for it, which the collector records as "Inherited from" the root domain. EMPTY means no federated domain. A 403 makes the measure UNAVAILABLE naming Domain.Read.All.

- `acceptIfMfaDoneByFederatedIdp`: the provider's MFA counts. Without it, Entra prompts with its own MFA.
- `enforceMfaByFederatedIdp`: the provider's MFA counts. Without it, Entra sends the user back to the provider. Shook (shb.com, Okta) is set this way.
- `rejectMfaByFederatedIdp`: the provider's MFA is ignored, so a Require MFA policy never counts it.
- Empty: the legacy SupportsMfa setting applies, or the default, which is accept.

Okta shows as an `http://www.okta.com/exk...` issuer, an `*.okta.com` sign-in URI, or on a custom sign-in domain through the `/app/office365/<app id>/sso/wsfed/` path. An `/adfs/` path means AD FS. The report embeds only the count of federated domains, the provider names and the MFA behavior. Domains and URIs stay in the pack. The manual equivalent is Q0 in `docs/Federated MFA Evaluation.md`.

**IA.2 Authentication methods in use, distinct users per bucket** (Log Analytics)

```kusto
SigninLogs
| where TimeGenerated between (ago(30d) .. now())
| where ResultType == "0"
| mv-expand AuthDetail = todynamic(AuthenticationDetails)
| extend Method = tostring(AuthDetail.authenticationMethod)
| where isnotempty(Method) and Method != "Previously satisfied"
| extend Bucket = case(
    Method has_any ("Text message", "Phone call", "Voice"),                     "Retiring: SMS or voice",
    Method has_any ("FIDO", "FIDO2", "Passkey", "Windows Hello", "Certificate"), "Phishing-resistant",
    Method has_any ("Authenticator", "Mobile app", "OATH"),                     "Authenticator or OTP",
    Method =~ "Password",                                                      "Password",
    "Other")
| summarize DistinctUsers = dcount(UserId),
            SignIns       = count(),
            Methods       = make_set(Method)
          by Bucket
| order by Bucket asc
```

These are methods used, not methods registered. The retiring bucket is the at-risk population on the passwordless slide. Change `by Bucket` to `by Method` for the per-method split behind a line such as 35 on text message and 1 on phone call.

**IA.3 Legacy authentication attempts** (Log Analytics)

```kusto
SigninLogs
| where TimeGenerated between (ago(30d) .. now())
| where isnotempty(ClientAppUsed)
| where ClientAppUsed !in ("Browser", "Mobile Apps and Desktop clients")
| summarize Attempts    = count(),
            Succeeded   = countif(ResultType == "0"),
            BlockedByCa = countif(ResultType == "53003"),
            Users       = dcountif(UserPrincipalName, ResultType == "0")
          by ClientAppUsed
| order by Succeeded desc
```

The block policy decides the status. The control is In force when an enabled Conditional Access policy blocks legacy authentication for all users, or security defaults are on (IA.8), and Not in force when the policy is scoped, report-only or missing. Successful sign-ins show whether any account got past it, and IA.8-SIGNINS splits them into approved exceptions the policy excludes and accounts it did not evaluate. Without a policy inventory the control is In force only when `BlockedByCa` is above zero and `Succeeded` is zero on every row, Not in force when any sign-in succeeded, and N/A otherwise. Only error 53003 (`BlockedByCa`) counts as a Conditional Access block. Attempts that failed without one, such as a wrong password or a locked account, are never presented as blocked.

**IA.3-DEVICECODE Device code flow sign-ins** (Log Analytics)

```kusto
SigninLogs
| where TimeGenerated between (ago(30d) .. now())
| where AuthenticationProtocol =~ "deviceCode"
| summarize Attempts    = count(),
            Succeeded   = countif(ResultType == "0"),
            BlockedByCa = countif(ResultType == "53003"),
            Users       = dcount(UserPrincipalName),
            Apps        = dcount(AppId)
| extend InForce = Succeeded == 0
```

In force when ATMO-MXDR-CA-BLOCK-DEVICECODE is On. Without a policy inventory the same rule as IA.3 applies: In force only when `BlockedByCa` is above zero and nothing succeeded, Not in force when a sign-in succeeded, otherwise N/A. Approved Teams Rooms or signage devices sit in the excluded group and still show as succeeded, so name them in the exception note.

**IA.4 Conditional Access coverage of successful sign-ins** (Log Analytics)

```kusto
SigninLogs
| where TimeGenerated between (ago(30d) .. now())
| where ResultType == "0"
| summarize Users = dcount(UserId), SignIns = count() by ConditionalAccessStatus
```

The `notApplied` share is the coverage gap. High MFA coverage alongside a large `notApplied` population means MFA is carried by per-user settings rather than policy, which was the DRB finding behind the H2 Conditional Access item. Since Oct 12, 2026 IA.4 is reference evidence only and no longer grades a control row.

**IA.4-LOCATION Location-based sign-in access** (evaluated offline from IA.8-POLICIES)

No query of its own. The report builder reads the raw Conditional Access policies collected with IA.8 and looks for an enabled policy whose location condition names countries or named networks, or carves trusted networks out of Any location, with a Block or Require MFA grant. It reads In force when one such policy targets all users and all resources with no platform, risk or device filter narrowing it. A policy scoped to selected users or applications, or in report-only mode, reads Not in force. Packs before collector 1.10.0 carry only the flattened IA.8 inventory, which never recorded locations, so the row reads (null) until recollected. Portal check: Entra admin center > Protection > Conditional Access > Policies, filter on the Locations condition, and Named locations for the countries and networks it names.

**IA.4b Sign-ins gated by a device compliance grant** (Log Analytics)

```kusto
SigninLogs
| where TimeGenerated between (ago(30d) .. now())
| where ResultType == "0"
| mv-apply Policy = ConditionalAccessPolicies on (
    where tostring(Policy.result) == "success"
    | summarize DeviceGrants = countif(tostring(Policy.enforcedGrantControls)
                                       has_any ("RequireCompliantDevice", "RequireDomainJoinedDevice"))
  )
| summarize SignIns            = count(),
            DeviceGatedSignIns = countif(0 < DeviceGrants),
            Users              = dcount(UserId)
| extend PctDeviceGated = round(100.0 * DeviceGatedSignIns / SignIns, 1)
```

Confirm the grant control strings against one sign-in record on the first run.

**IA.5 Registered methods** (Microsoft Graph)

The collector reads `GET /v1.0/reports/authenticationMethods/userRegistrationDetails?$filter=userType eq 'member'` with the Azure CLI Graph token (needs AuditLog.Read.All) and writes one row: Members, MfaRegistered, MfaCapable, SsprRegistered, PasswordlessCapable, PhishingResistant, PhoneRegistered, AuthenticatorRegistered, PhoneOnly, Admins, AdminsMfaRegistered. PhoneOnly counts members whose only registered MFA method is a phone (email, security questions and app passwords do not count as another method). When the token lacks the permission the result is UNAVAILABLE and the worksheet row says so with the portal path. By hand, the Graph PowerShell below gives the same data.

```powershell
Connect-MgGraph -Scopes "AuditLog.Read.All", "UserAuthenticationMethod.Read.All" -NoWelcome

$reg = Get-MgReportAuthenticationMethodUserRegistrationDetail -All |
    Where-Object { $_.UserType -eq "member" } |
    ForEach-Object {
        [pscustomobject]@{
            User    = $_.UserPrincipalName
            Mfa     = $_.IsMfaRegistered
            Methods = $_.MethodsRegistered -join ","
        }
    }

[pscustomobject]@{
    Members                 = @($reg).Count
    MfaRegistered           = @($reg | Where-Object Mfa).Count
    PhishingResistant       = @($reg | Where-Object Methods -match "fido2|passKey|windowsHelloForBusiness").Count
    PhoneRegistered         = @($reg | Where-Object Methods -match "mobilePhone|officePhone|alternateMobilePhone").Count
    AuthenticatorRegistered = @($reg | Where-Object Methods -match "microsoftAuthenticator").Count
    PhoneOnly               = @($reg | Where-Object { $m = @($_.Methods -split "," | Where-Object { $_ }); @($m | Where-Object { $_ -match "^(mobilePhone|officePhone|alternateMobilePhone)$" }).Count -gt 0 -and @($m | Where-Object { $_ -notmatch "^(mobilePhone|officePhone|alternateMobilePhone|email|securityQuestion|appPassword)$" }).Count -eq 0 }).Count
}
```

Phone registration does not separate SMS from voice. Quote IA.2 for who signed in with a retiring method, and this block for who could.

**IA.6 Standing privileged Entra roles** (Microsoft Graph)

The collector reads `roleManagement/directory/roleAssignmentScheduleInstances?$expand=principal` and `roleEligibilityScheduleInstances?$expand=principal` (needs RoleManagement.Read.Directory), keeps the 12 privileged role template IDs below, and writes one row per assignment with AssignmentType Standing, Time-bound, Activated or Eligible. Without PIM those endpoints answer 400, so it falls back to `roleManagement/directory/roleAssignments?$expand=principal` and lists every assignment as Standing, which is then the truth. The worksheet quotes standing and eligible counts from this result and only uses IA.6-SUB when Graph could not be read.

```powershell
Connect-MgGraph -Scopes "RoleManagement.Read.Directory" -NoWelcome

# Built-in role template IDs treated as privileged. Keep this list identical across clients.
$privileged = @{
    "62e90394-69f5-4237-9190-012177145e10" = "Global Administrator"
    "e8611ab8-c189-46e8-94e1-60213ab1f814" = "Privileged Role Administrator"
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" = "Privileged Authentication Administrator"
    "194ae4cb-b126-40b2-bd5b-6091b380977d" = "Security Administrator"
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9" = "Conditional Access Administrator"
    "29232cdf-9323-42fd-ade2-1d097af3e4de" = "Exchange Administrator"
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c" = "SharePoint Administrator"
    "fe930be7-5e62-47db-91af-98c3a49a38b1" = "User Administrator"
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" = "Application Administrator"
    "158c047a-c907-4556-b7ef-446551a6b5f7" = "Cloud Application Administrator"
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2" = "Hybrid Identity Administrator"
    "3a2c62db-5318-420d-8d74-23affee5d9d5" = "Intune Administrator"
}

$active   = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All
$eligible = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All

$standing = $active | Where-Object {
    $privileged.ContainsKey($_.RoleDefinitionId) -and
    $_.AssignmentType -eq "Assigned" -and
    -not $_.EndDateTime
}

$standing |
    ForEach-Object {
        [pscustomobject]@{
            PrincipalId = $_.PrincipalId
            Role        = $privileged[$_.RoleDefinitionId]
        }
    } |
    Sort-Object Role

"Standing privileged assignments: {0}" -f @($standing).Count
"Eligible privileged assignments: {0}" -f @($eligible | Where-Object { $privileged.ContainsKey($_.RoleDefinitionId) }).Count
```

This needs PIM (Entra ID P2). Without it every assignment is standing, so use `Get-MgRoleManagementDirectoryRoleAssignment -All` instead. Exclude documented break-glass accounts from the Tier 3 count and footnote them.

**IA.7 Azure Owner and User Access Administrator assignments** (ARG)

```kusto
authorizationresources
| where type =~ "microsoft.authorization/roleassignments"
| where id !contains "aznativesol0"
| extend RoleDefinitionId = tolower(tostring(properties.roleDefinitionId)),
         PrincipalType    = tostring(properties.principalType)
| where RoleDefinitionId endswith "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
     or RoleDefinitionId endswith "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
| extend Role = iff(RoleDefinitionId endswith "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
                    "Owner", "User Access Administrator")
| summarize Assignments = count() by Role, PrincipalType, subscriptionId
| order by Role asc, Assignments desc
```

**IA.8 Conditional Access policy inventory** (Microsoft Graph)

The collector reads `GET /v1.0/identity/conditionalAccess/policies` (needs Policy.Read.All) and writes one row per policy: Policy, State, IncludeUsers, ExcludeUsers, IncludeApplications, ExcludeApplications, UserActions, ClientAppTypes, AuthenticationFlows, SignInRiskLevels, UserRiskLevels, Platforms, Grants, GrantOperator, AuthStrength, Baseline (name starts ATMO-MXDR-CA-) and ModifiedUtc. The consent setting moved to IA.13. IA.8-SUB stays as the sign-in based substitute.

The report builder grades every Conditional Access control from this inventory (`report/Get-EbrCaEvaluation.ps1`), and each reads In force or Not in force on the slide rather than a ratio: MFA required at sign-in (IA.1, since collector 1.14.0: an enabled policy requiring MFA on every application for all users, not narrowed by platform, risk, device filter or location, or security defaults), MFA at admin portal sign-in (IA.1-ADMINPORTAL), legacy authentication blocked (IA.3), device code flow blocked (IA.3-DEVICECODE) and location-based access (IA.4-LOCATION). The sign-in figures from IA.1 and IA.1-ADMINPORTAL support the note under each control and the pillar page. Without the inventory the sign-in ratios grade IA.1 and IA.1-ADMINPORTAL as before.

```powershell
Connect-MgGraph -Scopes "Policy.Read.All" -NoWelcome

Get-MgIdentityConditionalAccessPolicy -All |
    ForEach-Object {
        [pscustomobject]@{
            Policy       = $_.DisplayName
            State        = $_.State
            ClientApps   = $_.Conditions.ClientAppTypes -join ","
            SignInRisk   = $_.Conditions.SignInRiskLevels -join ","
            UserRisk     = $_.Conditions.UserRiskLevels -join ","
            Grants       = $_.GrantControls.BuiltInControls -join ","
            AuthStrength = $_.GrantControls.AuthenticationStrength.DisplayName
            IncludeUsers = $_.Conditions.Users.IncludeUsers -join ","
        }
    } |
    Sort-Object State, Policy |
    Format-Table -AutoSize

# Empty means users cannot consent. A legacy or low policy value means they can.
(Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions.PermissionGrantPoliciesAssigned
```

A policy in `enabledForReportingButNotEnforced` state is report-only and does not count toward E.

**IA.11 Identity Protection risk policies in force** (Microsoft Graph)

From the IA.8 policy list (one read, cached): a sign-in risk policy is one whose `signInRiskLevels` is set, a user risk policy one whose `userRiskLevels` is set. Each counts only when its state is enabled and `includeUsers` contains All. The row carries SignInRiskPolicies, SignInRiskPolicy, SignInRiskAllUsers, UserRiskPolicies, UserRiskPolicy, UserRiskAllUsers, InForce (both true) and PasswordHashSync from `GET /v1.0/directory/onPremisesSynchronization` (On, Off, Cloud-only, or Unknown when OnPremDirectorySynchronization.Read.All is missing). Needs Entra ID P2; leaked credential detection in a hybrid tenant also needs password hash sync.

**IA.13 Application consent governance** (Microsoft Graph)

`GET /v1.0/policies/authorizationPolicy` gives `defaultUserRolePermissions.permissionGrantPoliciesAssigned`: empty means users cannot consent (None), `microsoft-user-default-low` means low-risk permissions from verified publishers, `microsoft-user-default-legacy` means any application. `GET /v1.0/policies/adminConsentRequestPolicy` gives `isEnabled` for the admin consent request workflow. Both need Policy.Read.All. Governed is true when consent is None or low risk and the workflow is on.

**IA.14 Users signing in to Azure management** (Log Analytics)

```kusto
SigninLogs
| where TimeGenerated between (ago(30d) .. now())
| where ResultType == "0" and isnotempty(UserId)
| where ResourceIdentity == "797f4846-ba00-4fd7-ba43-dac1f8f63013"   // Windows Azure Service Management API
| summarize SignIns = count(), LastSignIn = max(TimeGenerated), Apps = dcount(AppId) by UserId, UserPrincipalName, UserType
| order by SignIns desc
```

One row per user who reached Azure management. Compare the list with the privileged role holders in IA.6 (or IA.6-SUB): users outside that set are the gap for the management plane control. The HTML report carries the user count only.

**IA.9 Anti-phishing policy coverage** (Exchange Online PowerShell)

```powershell
Connect-ExchangeOnline -ShowBanner:$false

Get-AntiPhishPolicy |
    Select-Object Name, IsDefault, Enabled, PhishThresholdLevel,
        EnableTargetedUserProtection, EnableOrganizationDomainsProtection,
        EnableMailboxIntelligenceProtection, EnableSpoofIntelligence

Get-AntiPhishRule |
    ForEach-Object {
        [pscustomobject]@{
            Rule     = $_.Name
            Policy   = $_.AntiPhishPolicy
            State    = $_.State
            Priority = $_.Priority
            Domains  = $_.RecipientDomainIs -join ","
        }
    }

Get-ATPProtectionPolicyRule | Select-Object Name, State, Priority
```

The default policy covers every mailbox but ships with impersonation protection off. That gap is what scored DRB at 16.27 of 62 anti-phishing points even with Safe Links and zero-hour auto purge complete.

### Endpoint and Workload (SOC 2 CC6.8, CC7.1)

| ID | Control | Tier | Measure | Evidence |
| --- | --- | --- | --- | --- |
| EW-F1 | Azure virtual machines reporting to endpoint detection | F | Onboarded plus machines covered by a third-party product, over the machines eligible for endpoint detection, Azure virtual machines only, with the reason for every machine not reporting | EW.1, EW.1-GAPS, DFC.1 |
| EW-F2 | Anti-malware active with real-time and cloud-delivered protection | F | Devices compliant on both checks | EW.3 |
| EW-F3 | Tamper protection enforced so agents cannot be disabled | F | Devices compliant on the tamper protection check | EW.15, EW.3 |
| EW-F4 | Host firewall enforced centrally through endpoint policy | F | Devices with Defender Firewall on | EW.16, EW.3 |
| EW-F5 | OS and Azure VM extension findings remediated on cadence (US Claims) | F | Machines within the agreed patch cadence, plus pending patches and control points | EW.10, EW.6, POS.3 |
| EW-F6 | Encryption at host enforced on virtual machines (DRB) | F | Defender for Cloud healthy over evaluated | DFC.1, DP.4 |
| EW-D1 | Attack surface reduction rules enforced in block mode | D | Devices with every deployed rule in block | EW.4, EW.5 |
| EW-D2 | Credential protection enforced on eligible devices | D | LSA protection and WDigest checks per device | EW.12, EW.3 |
| EW-D3 | Configuration baselines continuously assessed | D | Guest Configuration installed over VMs | EW.8, EW.9 |
| EW-D4 | Platform integrity enforced through Secure Boot and vTPM | D | Defender for Cloud healthy over evaluated | DFC.1, EW.7 |
| EW-D5 | Application allow-listing on corporate-owned devices | D | App Control for Business policy assigned | EW.13, or Intune admin center > Endpoint security > App Control for Business |
| EW-D6 | Remote Desktop hardened with TLS and file transfer blocked (DRB) | D | TLS and Network Level Authentication checks per device | EW.14, EW.3 |
| EW-D7 | Legacy credential and hash exposure removed (DRB) | D | WDigest and LAN Manager hash checks, NTLMv2 only | EW.12, NB.11, EW.3 |

When P0.4 shows the device tables did not resolve, grade EW-F1, EW-F2 and EW-D1 from the matching Secure Score controls in POS.6 and footnote the substitution, as the DRB deck did.

**Scope of every device measure (collector 1.14.0).** Every Advanced Hunting query that reads devices (EW.1, EW.1-DEVICES, EW.1-VMS, EW.3, EW.4, EW.5, EW.12, EW.14, EW.15, EW.16, NB.8, NB.10, NB.11, DR.5, DR.12 and BKL.1) covers Azure virtual machines only: `| where isnotempty(AzureResourceId)`. Workstations, laptops and any other endpoint that is not an Azure resource are never counted, in the evidence or in the report. The `Scope` column is kept, always `Azure VM`, so earlier packs and the report read the same columns.

**EW.1 EDR onboarding and sensor health, Azure virtual machines** (Advanced Hunting)

```kusto
DeviceInfo
| where Timestamp between (ago(7d) .. now())
| summarize arg_max(Timestamp, *) by DeviceId
| where isnotempty(OSPlatform)
| where isnotempty(AzureResourceId)   // Azure virtual machines only
| where not(tostring(column_ifexists("DeviceCategory", "")) contains "network"
            or tostring(column_ifexists("DeviceType", "")) contains "network"
            or tolower(strcat(tostring(column_ifexists("Vendor", "")), " ", tostring(column_ifexists("Model", "")), " ",
                              tostring(OSPlatform), " ", tostring(column_ifexists("OSDistribution", ""))))
               matches regex @"(palo ?alto|pan-?os|meraki|fortinet|forti(gate|os)|sonicwall|sonicos|watchguard|check ?point|gaia|barracuda)")
| where AzureResourceId !contains "aznativesol0"
| extend Scope = "Azure VM"
| summarize Devices          = count(),
            Onboarded        = countif(OnboardingStatus == "Onboarded"),
            CanBeOnboarded   = countif(OnboardingStatus == "Can be onboarded"),
            Unsupported      = countif(OnboardingStatus == "Unsupported"),
            InsufficientInfo = countif(OnboardingStatus == "Insufficient info"),
            SensorActive     = countif(SensorHealthState == "Active")
          by Scope, OSPlatform
| order by Devices desc
```

The EDR denominator is `Onboarded` plus `CanBeOnboarded`. `Unsupported` and `InsufficientInfo` are context for EW.1-GAPS. Since collector 1.11.0 network devices and firewalls (Palo Alto, Meraki, Fortinet, SonicWall and similar) are dropped before counting, because they cannot run a sensor. `SensorActive` feeds DR-F1, the sensor measure on onboarded Azure virtual machines.

**EW.1-VMS Azure virtual machines known to Defender for Endpoint** (Advanced Hunting, collector 1.14.0)

Every Azure virtual machine Defender has seen in the last 7 days, in any onboarding status, so EW.1-GAPS can tell which machines in Resource Graph Defender has never discovered. Same filters as EW.1, then `| project DeviceId, DeviceName, OSPlatform, OnboardingStatus, SensorHealthState, LastSeen = Timestamp, MachineGroup, AzureResourceId`. Internal: names devices.

**EW.1-EDR Endpoint detection evidence per Azure virtual machine, from Azure** (ARG, collector 1.14.0)

One row per Azure virtual machine with what Azure itself knows about endpoint detection: the Defender for Endpoint extension (`MDE.Windows`, `MDE.Linux`), any extension whose publisher or type names a third-party product, the Defender for Cloud `EDR solution should be installed` assessment status, the power state and whether the image is a network appliance (P0.6-APPLIANCES). The collector takes the product pattern from `-EdrVendorPattern`, which covers CrowdStrike Falcon by default.

```kusto
resources
| where type =~ "microsoft.compute/virtualmachines"
| where id !contains "aznativesol0"
| project VmId = tolower(id), VmName = name, resourceGroup, subscriptionId,
          OsType     = tostring(properties.storageProfile.osDisk.osType),
          PowerState = tostring(properties.extended.instanceView.powerState.code),
          Appliance  = tolower(strcat(tostring(plan.publisher), " ", tostring(properties.storageProfile.imageReference.publisher), " ", tostring(properties.virtualMachineProfile.storageProfile.imageReference.publisher))) matches regex @"(paloalto|fortinet|checkpoint|barracuda|cisco|sophos|f5-networks|netgate|juniper|citrix|versa-networks|silver-peak|silverpeak|aviatrix|watchguard|forcepoint|kemptech|a10networks|arista|zscaler|cloudflare|vyos|mikrotik|opnsense|riverbed|catonetworks|cradlepoint)"
| join kind=leftouter (
    resources
    | where type =~ "microsoft.compute/virtualmachines/extensions"
    | extend VmId = tostring(split(tolower(id), "/extensions/")[0]),
             Publisher = tostring(properties.publisher), ExtensionType = tostring(properties.type)
    | extend Product = tolower(strcat(Publisher, " ", ExtensionType, " ", name))
    | summarize DefenderExtension    = countif(ExtensionType startswith "MDE."),
                ThirdPartyExtensions = make_set_if(strcat(Publisher, "/", ExtensionType), Product matches regex @"(crowdstrike|falcon|sentinelone|carbon ?black|cortex ?xdr|cybereason|tanium|trellix|cylance)")
              by VmId
  ) on VmId
| join kind=leftouter (
    securityresources
    | where type =~ "microsoft.security/assessments"
    | extend Recommendation = tostring(properties.displayName), Status = tostring(properties.status.code)
    | where Recommendation has "EDR solution should be installed"
    | extend VmId = tostring(split(tolower(id), "/providers/microsoft.security/assessments/")[0])
    | summarize EdrAssessment = make_set(Status) by VmId
  ) on VmId
| extend DefenderExtension    = coalesce(DefenderExtension, 0),
         ThirdPartyExtensions = coalesce(ThirdPartyExtensions, dynamic([])),
         EdrAssessment        = coalesce(EdrAssessment, dynamic([]))
| extend ThirdPartyEdr = array_length(ThirdPartyExtensions) > 0
| project VmId, VmName, resourceGroup, subscriptionId, OsType, PowerState, Appliance, DefenderExtension, ThirdPartyEdr, ThirdPartyExtensions, EdrAssessment
| order by resourceGroup asc, VmName asc
```

**EW.1-EDR-HOSTS Hosts reporting to a third-party endpoint detection product through Sentinel** (Log Analytics, collector 1.14.0)

Hosts seen in the last 7 days in the CrowdStrike tables, or in `CommonSecurityLog` with a vendor or product matching the pattern. EMPTY means the workspaces hold no such telemetry, which is a reading, not a gap.

```kusto
union withsource = SourceTable isfuzzy = true CrowdStrike*, CommonSecurityLog
| where TimeGenerated > ago(7d)
| extend Product = tolower(strcat(SourceTable, " ", tostring(column_ifexists("DeviceVendor", "")), " ", tostring(column_ifexists("DeviceProduct", ""))))
| where Product matches regex @"(crowdstrike|falcon|sentinelone|carbon ?black|cortex ?xdr|cybereason|tanium|trellix|cylance)"
| extend Host = tolower(case(isnotempty(tostring(column_ifexists("ComputerName", ""))),   tostring(column_ifexists("ComputerName", "")),
                             isnotempty(tostring(column_ifexists("DeviceName", ""))),     tostring(column_ifexists("DeviceName", "")),
                             isnotempty(tostring(column_ifexists("SourceHostName", ""))), tostring(column_ifexists("SourceHostName", "")),
                             isnotempty(tostring(column_ifexists("HostName", ""))),       tostring(column_ifexists("HostName", "")),
                             tostring(column_ifexists("Computer", ""))))
| where isnotempty(Host)
| extend Host = tostring(split(Host, ".")[0])
| summarize Events = count(), LastSeen = max(TimeGenerated), Sources = make_set(SourceTable) by Host
| order by Host asc
```

**EW.1-GAPS Azure virtual machines not reporting to Defender for Endpoint, with the reason** (derived, collector 1.14.0)

No query. The collector builds it from EW.1-VMS, EW.1-DEVICES, EW.1-EDR, EW.1-EDR-HOSTS and P0.6-APPLIANCES: one row per Azure virtual machine that is not onboarded with an active sensor, with the first reason that applies, in this order.

| Reason | Evidence | In the denominator | Counts as protected |
| --- | --- | --- | --- |
| Network virtual appliance, cannot run a sensor | P0.6-APPLIANCES, the image publisher in EW.1-EDR, or a firewall operating system | No | No |
| Covered by a third-party endpoint detection product | A matching extension in EW.1-EDR, the host in EW.1-EDR-HOSTS, or Defender for Cloud reporting an EDR solution installed on a machine Defender for Endpoint says is not onboarded. The product is named, CrowdStrike Falcon for example | Yes | Yes |
| Operating system not supported by the sensor | OnboardingStatus Unsupported | No | No |
| Deallocated or stopped at collection | Power state in EW.1-EDR | No | No |
| Discovered only, insufficient information | OnboardingStatus Insufficient info | No | No |
| Not discovered by Defender for Endpoint | In Resource Graph, absent from EW.1-VMS | Yes | No |
| Onboarded, sensor not active | SensorHealthState | Yes | Yes, the sensor measure grades it |
| Not onboarded, no endpoint detection found | None of the above | Yes | No |

The report reads the counts by reason. The onboarding figure (EW-F1) becomes onboarded plus machines covered by a third-party product, over the machines eligible for endpoint detection, and the note under both the onboarding figure and the sensor figure (DR-F1) states the reasons, so 87 of 87 sensors active beside 87 of 90 reporting is explained on the slide itself. The SecOps worklist names each machine with its evidence.

**EW.3 Security configuration checks, every control in one pass** (Advanced Hunting)

```kusto
DeviceTvmSecureConfigurationAssessment
| summarize arg_max(Timestamp, *) by DeviceId, ConfigurationId
| where tobool(IsApplicable)
| join kind=inner (
    DeviceInfo
    | where Timestamp between (ago(7d) .. now())
    | summarize arg_max(Timestamp, AzureResourceId) by DeviceId
    | where isnotempty(AzureResourceId)   // Azure virtual machines only
    | where AzureResourceId !contains "aznativesol0"
  ) on DeviceId
| join kind=inner DeviceTvmSecureConfigurationAssessmentKB on ConfigurationId
| extend Scope = "Azure VM"
| summarize Devices   = dcount(DeviceId),
            Compliant = dcountif(DeviceId, tobool(IsCompliant))
          by Scope, ConfigurationId, ConfigurationName
| extend PctCompliant = round(100.0 * Compliant / Devices, 1)
| order by Scope asc, PctCompliant asc
```

This replaces the category filter in the earlier version. At US Claims every row came back in the Security controls category, so filtering on Antivirus or Firewall matched nothing. Select rows by configuration name instead, then pin the `ConfigurationId` values after the first run so a renamed check does not silently drop out.

| Control | Filter the EW.3 output on ConfigurationName containing |
| --- | --- |
| EW-F2 Anti-malware | real-time protection, cloud-delivered protection, behavior monitoring |
| EW-F3 Tamper protection | Tamper Protection |
| EW-F4 Host firewall | Firewall, one row per profile |
| EW-D2 Credential protection | Credential Guard |
| EW-D6 Remote Desktop | Remote Desktop |
| EW-D7 Legacy credential exposure | WDigest, LAN Manager hash |
| NB-F3 Anonymous access | anonymous |
| NB-F4 Legacy protocols | SMBv1, multicast name resolution |
| NB-D1 NTLM | LAN Manager authentication level |
| NB-D2 Directory signing | LDAP, signing |
| DP-D4 Endpoint disk encryption | BitLocker, Encrypt |

A control spanning several checks grades on its weakest check.

**EW.4 Machines missing deployed ASR rules** (Advanced Hunting)

```kusto
DeviceTvmSecureConfigurationAssessment
| summarize arg_max(Timestamp, *) by DeviceId, ConfigurationId
| where tobool(IsApplicable)
| join kind=inner DeviceTvmSecureConfigurationAssessmentKB on ConfigurationId   // edit the rule list to the client's set
| where ConfigurationName in (dynamic([
    "Block untrusted and unsigned processes that run from USB",
    "Block abuse of exploited vulnerable signed drivers",
    "Use advanced protection against ransomware",
    "Block execution of potentially obfuscated scripts",
    "Block executable content from email client and webmail",
    "Block executable files from running unless they meet a prevalence, age, or trusted list criterion",
    "Block Office communication application from creating child processes",
    "Block persistence through WMI event subscription",
    "Block process creations originating from PSExec and WMI commands",
    "Block JavaScript or VBScript from launching downloaded executable content",
    "Block Win32 API calls from Office macros"
  ]))
| summarize Applicable   = count(),
            Configured   = countif(tobool(IsCompliant)),
            MissingRules = make_set_if(ConfigurationName, not(tobool(IsCompliant)))
          by DeviceId
| where Configured < Applicable
| join kind=inner (
    DeviceInfo
    | where Timestamp between (ago(7d) .. now())
    | summarize arg_max(Timestamp, DeviceName, OSPlatform, OSVersion, MachineGroup, AzureResourceId)
              by DeviceId
    | where isnotempty(AzureResourceId)   // Azure virtual machines only
    | where AzureResourceId !contains "aznativesol0"
  ) on DeviceId
| extend ResourceGroup = tostring(split(AzureResourceId, "/")[4]),
         VmName        = tostring(split(AzureResourceId, "/")[8])
| project DeviceName, VmName, ResourceGroup, OSPlatform, OSVersion, MachineGroup,
          Configured, Applicable, MissingRules
| order by Configured asc, DeviceName asc
```

Rows with `Configured` at zero sit outside the policy assignment entirely. If they cluster by resource group, OS version or machine group, the fix is the assignment scope rather than the devices.

**EW.5 ASR activity, audit versus block** (Advanced Hunting)

```kusto
DeviceEvents
| where Timestamp between (ago(30d) .. now())
| where ActionType startswith "Asr"
| join kind=inner (
    DeviceInfo
    | where Timestamp between (ago(7d) .. now())
    | summarize arg_max(Timestamp, AzureResourceId) by DeviceId
    | where isnotempty(AzureResourceId)   // Azure virtual machines only
  ) on DeviceId
| where AzureResourceId !contains "aznativesol0"
| extend Mode  = iff(ActionType endswith "Blocked", "Block", "Audit"),
         Scope = "Azure VM"
| summarize Events = count(), Devices = dcount(DeviceId) by Scope, ActionType, Mode
| order by Scope asc, Events desc
```

The configuration check only credits block mode, so a rule running in audit reads as missing in EW.4. This query is the evidence that audit-mode rules are deployed and generating signal before they move to block.

**EW.6 Pending patches from Update Manager** (ARG)

```kusto
patchassessmentresources
| where type in~ ("microsoft.compute/virtualmachines/patchassessmentresults/softwarepatches",
                  "microsoft.hybridcompute/machines/patchassessmentresults/softwarepatches")
| where id !contains "aznativesol0"
| extend MachineId      = tostring(split(tolower(id), "/patchassessmentresults")[0]),
         Classification = tostring(properties.classifications[0])
| join kind=leftouter (
    resources
    | where type in~ ("microsoft.compute/virtualmachines", "microsoft.hybridcompute/machines")
    | extend PatchExcluded = false
    | extend PatchExcluded = tolower(tostring(tags)) matches regex @"""[^""]*patch[^""]*""\s*:\s*""[^""]*(waiv|client[ _-]?owned|customer[ _-]?owned)[^""]*""|""[^""]*(waiv|client[ _-]?owned|customer[ _-]?owned)[^""]*patch[^""]*""|""[^""]*patch[^""]*(waiv|client[ _-]?owned|customer[ _-]?owned)[^""]*"""
    | project MachineId = tolower(id), PatchExcluded
  ) on MachineId
| where not(coalesce(PatchExcluded, false))   // patching waived or client owned by tag, see EW.10-EXCLUDED
| summarize PendingPatches = count(), Machines = dcount(MachineId) by Classification
| order by PendingPatches desc
```

Machines whose tags record patching as waived or client owned leave EW.6 and EW.10 (collector 1.14.0, see EW.10-EXCLUDED).

**EW.7 Trusted Launch, Secure Boot and vTPM** (ARG)

```kusto
resources
| where type =~ "microsoft.compute/virtualmachines"
| where id !contains "aznativesol0"
| extend SecurityType = tostring(properties.securityProfile.securityType),
         SecureBoot   = tobool(properties.securityProfile.uefiSettings.secureBootEnabled),
         VTpm         = tobool(properties.securityProfile.uefiSettings.vTpmEnabled)
| summarize VMs                = count(),
            TrustedLaunchOrCvm = countif(SecurityType in~ ("TrustedLaunch", "ConfidentialVM")),
            SecureBootOn       = countif(SecureBoot == true),
            VTpmOn             = countif(VTpm == true)
```

Generation 1 VMs cannot run Trusted Launch, so grade on the Defender for Cloud rows from DFC.1, which only evaluate supported machines. Use this query for the itemized list.

**EW.8 Guest Configuration extension coverage** (ARG)

```kusto
resources
| where type =~ "microsoft.compute/virtualmachines"
| where id !contains "aznativesol0"
| project VmId       = tolower(id),
          PowerState = tostring(properties.extended.instanceView.powerState.code)
| join kind=leftouter (
    resources
    | where type =~ "microsoft.compute/virtualmachines/extensions"
    | where name in~ ("AzurePolicyforWindows", "AzurePolicyforLinux",
                      "ConfigurationforWindows", "ConfigurationForLinux")
    | extend VmId = tostring(split(tolower(id), "/extensions/")[0])
    | summarize GuestConfigExtensions = count() by VmId
  ) on VmId
| summarize VMs             = count(),
            WithGuestConfig = countif(0 < GuestConfigExtensions),
            Running         = countif(PowerState =~ "PowerState/running")
```

**EW.9 Guest configuration assignment compliance** (ARG)

```kusto
guestconfigurationresources
| where type =~ "microsoft.guestconfiguration/guestconfigurationassignments"
| where id !contains "aznativesol0"
| extend Assignment = tostring(properties.guestConfiguration.name),
         Compliance = tostring(properties.complianceStatus)
| summarize Machines = dcount(tostring(split(tolower(id), "/providers/microsoft.guestconfiguration")[0]))
          by Assignment, Compliance
| order by Assignment asc, Compliance asc
```

EW.8 proves the extension is installed. EW.9 proves the baselines are actually being evaluated, which is what "continuously assessed" claims.

**EW.10 Patch cadence from Update Manager** (ARG)

```kusto
patchassessmentresources
| where type in~ ("microsoft.compute/virtualmachines/patchassessmentresults",
                  "microsoft.hybridcompute/machines/patchassessmentresults")
| where id !contains "aznativesol0"
| extend MachineId   = tostring(split(tolower(id), "/patchassessmentresults")[0]),
         AssessedUtc = todatetime(properties.lastModifiedDateTime)
| join kind=leftouter (
    patchassessmentresources
    | where type in~ ("microsoft.compute/virtualmachines/patchassessmentresults/softwarepatches",
                      "microsoft.hybridcompute/machines/patchassessmentresults/softwarepatches")
    | where id !contains "aznativesol0"
    | extend MachineId      = tolower(tostring(split(id, "/patchassessmentresults")[0])),
             Classification = tostring(properties.classifications[0]),
             PublishedUtc   = todatetime(properties.publishedDateTime)
    | where Classification in~ ("Critical", "Security")
    | where PublishedUtc < ago(30d)
    | summarize OverduePatches = count() by MachineId
  ) on MachineId
| extend OverduePatches = coalesce(OverduePatches, 0)
| join kind=leftouter (
    resources
    | where type in~ ("microsoft.compute/virtualmachines", "microsoft.hybridcompute/machines")
    | extend PatchExcluded = false
    | extend PatchExcluded = tolower(tostring(tags)) matches regex @"""[^""]*patch[^""]*""\s*:\s*""[^""]*(waiv|client[ _-]?owned|customer[ _-]?owned)[^""]*""|""[^""]*(waiv|client[ _-]?owned|customer[ _-]?owned)[^""]*patch[^""]*""|""[^""]*patch[^""]*(waiv|client[ _-]?owned|customer[ _-]?owned)[^""]*"""
    | project MachineId = tolower(id), PatchExcluded
  ) on MachineId
| where not(coalesce(PatchExcluded, false))   // patching waived or client owned by tag, see EW.10-EXCLUDED
| summarize Machines         = count(),
            WithinCadence    = countif(OverduePatches == 0),
            OverduePatches   = sum(OverduePatches),
            AssessedWithin7d = countif(AssessedUtc > ago(7d))
```

`ago(30d)` is the agreed cadence. The collector takes it from `-PatchCadenceDays`. A machine is within cadence when it has no pending Critical or Security patch published more than that long ago. Machines never assessed are not in the denominator, so compare `Machines` with the VM count in DP.4.

**Patching waived or client owned (collector 1.14.0).** A machine whose tags record patching as waived, or as owned by the client, is not Atmosera's to patch and leaves EW.6 and EW.10. The test is a regular expression against the lowercased JSON of the machine's tags, so both the key and the value are read and the client's own tag names work: `Patching=Waived`, `PatchPolicy=Client Owned` and `Maintenance=Patching waived` all match. The collector takes the pattern from `-PatchExclusionTagPattern`. An empty pattern turns the exclusion off, and the report note states how many machines were left out.

**EW.10-EXCLUDED Machines left out of the patch measures by tag** (ARG, collector 1.14.0)

```kusto
resources
| where type in~ ("microsoft.compute/virtualmachines", "microsoft.hybridcompute/machines")
| where id !contains "aznativesol0"
| extend TagText = tolower(tostring(tags))
| extend PatchExcluded = false, MatchedTag = ""
| extend PatchExcluded = TagText matches regex @"""[^""]*patch[^""]*""\s*:\s*""[^""]*(waiv|client[ _-]?owned|customer[ _-]?owned)[^""]*""|""[^""]*(waiv|client[ _-]?owned|customer[ _-]?owned)[^""]*patch[^""]*""|""[^""]*patch[^""]*(waiv|client[ _-]?owned|customer[ _-]?owned)[^""]*"""
| extend MatchedTag = extract(@"""[^""]*patch[^""]*""\s*:\s*""[^""]*(waiv|client[ _-]?owned|customer[ _-]?owned)[^""]*""|""[^""]*(waiv|client[ _-]?owned|customer[ _-]?owned)[^""]*patch[^""]*""|""[^""]*patch[^""]*(waiv|client[ _-]?owned|customer[ _-]?owned)[^""]*""", 0, TagText)
| where PatchExcluded
| project Name = name, ResourceType = tolower(type), resourceGroup, subscriptionId, MatchedTag, ResourceId = tolower(id)
| order by resourceGroup asc, Name asc
```

Internal: names machines. The report embeds the count only, and the SecOps worklist lists each one so a stale tag can be caught.

**Per-device secure configuration measures** (Advanced Hunting)

EW.12, EW.14, EW.15, EW.16, NB.8, NB.10 and NB.11 share one shape. The latest assessment per device and check, applicable checks only, joined to the onboarded Azure virtual machines. A device counts as compliant only when every applicable check in its set is compliant. EW.15 is shown in full. The others differ only in the `ConfigurationId` list.

| ID | Measure | ConfigurationId list |
| --- | --- | --- |
| EW.12 | Credential protection per device | "scid-25", "scid-102", "scid-57" (LSA protection, LSA protection on Windows 11 22H2 and later, WDigest off) |
| EW.14 | Remote Desktop hardening per device | "scid-24", "scid-45" (security level TLS, Network Level Authentication) |
| EW.15 | Tamper protection per device | "scid-2003" |
| EW.16 | Host firewall on per device | "scid-2070" (every profile. The hardened profile checks scid-2071 to scid-2073 stay in EW.3 as context) |
| NB.8 | Network protection per device | "scid-96" |
| NB.10 | LDAP signing and channel binding on domain controllers | "scid-105", "scid-106" (applicable to domain controllers only, so Devices is the DC count) |
| NB.11 | NTLMv2 only per device | "scid-72" |

```kusto
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId in ("scid-2003")
| summarize arg_max(Timestamp, *) by DeviceId, ConfigurationId
| where tobool(IsApplicable)
| summarize Checks = dcount(ConfigurationId), Passed = dcountif(ConfigurationId, tobool(IsCompliant)) by DeviceId
| join kind=inner (
    DeviceInfo
    | where Timestamp between (ago(30d) .. now())
    | where OnboardingStatus == "Onboarded"
    | summarize arg_max(Timestamp, AzureResourceId, OSPlatform) by DeviceId
    | where isnotempty(AzureResourceId)   // Azure virtual machines only
    | where AzureResourceId !contains "aznativesol0"
  ) on DeviceId
| extend Scope = "Azure VM"
| summarize Devices = count(), Compliant = countif(Passed == Checks) by Scope
| extend PctCompliant = round(100.0 * Compliant / Devices, 1)
| order by Scope asc
```

The document numbers tamper protection EW.8 and host firewall EW.9. The collector already uses those IDs for Guest Configuration, so they are EW.15 and EW.16 here. Drive and clipboard redirection for Remote Desktop are not secure configuration checks: read them from Intune or machine configuration.

**EW.13 Application allow-listing policies** (Microsoft Graph)

`GET /beta/deviceManagement/configurationPolicies?$filter=templateReference/templateFamily eq 'endpointSecurityApplicationControl'` (needs DeviceManagementConfiguration.Read.All; the settings catalog exists only in the beta surface) gives one row per App Control for Business policy: Policy, Platforms, Technologies, Assigned (the isAssigned flag), Settings, ModifiedUtc. If the filter is rejected the collector reads every policy and filters by template family. In force when at least one policy is assigned. Where the client runs ThreatLocker, read coverage from the ThreatLocker portal instead.

### Network and Boundary (SOC 2 CC6.6, CC6.1)

| ID | Control | Tier | Measure | Evidence |
| --- | --- | --- | --- | --- |
| NB-F1 | Egress and DNS monitored for tunneling and command traffic | F | DNS and firewall telemetry ingesting, boundary detections investigated | NB.7, OUT.6 |
| NB-F2 | Network security groups applied across the estate | F | Segmented workload subnets over workload subnets | NB.1, DFC.1 |
| NB-F3 | Anonymous host and share access restricted | F | Anonymous access checks | EW.3 |
| NB-F4 | Legacy and plaintext network protocols disabled | F | SMBv1 and multicast name resolution checks | EW.3 |
| NB-F5 | No management ports exposed directly to the internet | F | Associated allow rules from any source, target zero | NB.2, POS.3 |
| NB-D1 | NTLM restricted and NTLMv2 enforced fleet-wide | D | LAN Manager authentication level check | EW.3 |
| NB-D2 | Directory traffic signed and channel-bound | D | LDAP server signing and channel binding on domain controllers | NB.10, EW.3 |
| NB-D3 | Platform services isolated behind private endpoints | D | PaaS with public access disabled or a private endpoint | NB.3 |
| NB-D4 | Perimeter rule sets reviewed with findings tracked | D | Rule review change requests in the window | Change system of record |
| NB-D5 | Encryption in transit enforced on published services | F (moved from D on Oct 12, 2026, the ID is kept) | HTTPS-only sites, FTPS and minimum TLS | NB.4, NB.5, DFC.1 |
| NB-D6 | Secure communication protocols on Windows servers (DRB) | D | Defender for Cloud healthy over evaluated | DFC.1 |
| NB-D7 | Transport encryption on data platform services (DRB) | D | SQL and storage at minimum TLS 1.2 | NB.6, DP.1 |
| NB-D8 | Blob containers closed to anonymous access at the container level | D | Containers set to private over all containers, read in every storage account | DP.1-CONTAINERS |

NB-F1 was graded E at DRB with no export behind it. NB.7 and OUT.6 together now evidence it: the telemetry is arriving and the detections it produces are worked to a disposition.

**NB.1 Subnet segmentation by subnet class** (ARG)

```kusto
resources
| where type =~ "microsoft.network/virtualnetworks"
| where id !contains "aznativesol0"
| mv-expand Subnet = properties.subnets
| extend SubnetName = tostring(Subnet.name),
         Prefix     = tostring(Subnet.properties.addressPrefix),
         HasNsg     = isnotempty(tostring(Subnet.properties.networkSecurityGroup.id)),
         HasUdr     = isnotempty(tostring(Subnet.properties.routeTable.id))
| extend SubnetClass = case(
    SubnetName in~ ("AzureBastionSubnet", "AzureFirewallSubnet", "AzureFirewallManagementSubnet",
                    "GatewaySubnet", "RouteServerSubnet"), "Platform",
    SubnetName startswith "FW-", "Firewall appliance",      // adjust to the client's naming
    "Workload")
| project Vnet = name, resourceGroup, SubnetName, Prefix, SubnetClass, HasNsg, HasUdr,
          Segmented = HasNsg or HasUdr
| order by SubnetClass desc, Segmented asc, Vnet asc
```

Grade on workload subnets only, and keep that denominator on every slide. DRB was 14 of 18 workload subnets, yet one slide quoted 86.7 percent of all 30 subnets. A route table counts as segmentation only when its default route points at the firewall, so confirm the next hop for each `HasUdr` row.

**NB.2 Internet-exposed management ports with association** (ARG)

```kusto
resources
| where type =~ "microsoft.network/networksecuritygroups"
| where id !contains "aznativesol0"
| extend Subnets = array_length(properties.subnets),
         Nics    = array_length(properties.networkInterfaces)
| mv-expand Rule = properties.securityRules
| where tostring(Rule.properties.access) =~ "Allow"
    and tostring(Rule.properties.direction) =~ "Inbound"
| extend SourceText = tostring(array_concat(pack_array(tostring(Rule.properties.sourceAddressPrefix)),
                                            coalesce(Rule.properties.sourceAddressPrefixes, dynamic([])))),
         PortText   = tostring(array_concat(pack_array(tostring(Rule.properties.destinationPortRange)),
                                            coalesce(Rule.properties.destinationPortRanges, dynamic([]))))
| where SourceText contains '"*"' or SourceText contains '"Internet"' or SourceText contains '"0.0.0.0/0"'
| where PortText contains '"*"' or PortText contains '"22"' or PortText contains '"3389"'
     or PortText contains '"5985"' or PortText contains '"5986"' or PortText contains "-"
| extend Association = case(0 < Subnets, "Subnet", 0 < Nics, "NIC", "Unassociated"),
         RangeNeedsReview = PortText contains "-"
| project NSG = name, resourceGroup, RuleName = tostring(Rule.name),
          Priority = toint(Rule.properties.priority), PortText, SourceText,
          Association, RangeNeedsReview
| order by Association asc, Priority asc
```

The earlier version read only the singular port and source fields, so a rule using the plural arrays or a port range never appeared. Read each row with this verdict:

| Association | Verdict |
| --- | --- |
| Unassociated | Enforces nothing. Cleanup item, not exposure |
| NIC on a firewall untrust or outside interface | By design. Note it, do not count it |
| Subnet or NIC on a workload | Real finding. Counts against NB-F5 |
| Any row with `RangeNeedsReview` | Check whether the range spans 22, 3389, 5985 or 5986 |

**NB.3 PaaS network exposure and private endpoints** (ARG)

```kusto
resources
| where type in~ ("microsoft.storage/storageaccounts", "microsoft.keyvault/vaults",
                  "microsoft.sql/servers", "microsoft.cognitiveservices/accounts",
                  "microsoft.documentdb/databaseaccounts", "microsoft.web/sites")
| where id !contains "aznativesol0"
| extend PublicAccess     = tostring(properties.publicNetworkAccess),
         DefaultAction    = tostring(properties.networkAcls.defaultAction),
         PrivateEndpoints = array_length(properties.privateEndpointConnections)
| extend Posture = case(PublicAccess =~ "Disabled", "Public access disabled",
                        DefaultAction =~ "Deny",    "Selected networks only",
                        "Open to all networks")
| summarize Resources           = count(),
            WithPrivateEndpoint = countif(0 < PrivateEndpoints)
          by ResourceType = tolower(type), Posture
| order by ResourceType asc, Posture asc
```

Selected networks only is restricted but not private, so NB-D3 credits only public access disabled or a private endpoint. SQL server firewall rules are not read here, so check any SQL row marked open for an allow-all rule.

**NB.4 Web and Function App HTTPS-only** (ARG)

```kusto
resources
| where type =~ "microsoft.web/sites"
| where id !contains "aznativesol0"
| summarize Sites     = count(),
            HttpsOnly = countif(tobool(properties.httpsOnly) == true)
```

**NB.5 App Service FTPS and minimum TLS** (ARG)

```kusto
appserviceresources
| where type =~ "microsoft.web/sites/config"
| where id !contains "aznativesol0"
// appserviceresources returns site config keys in PascalCase and dynamic access is case-sensitive.
| extend FtpsState = tostring(coalesce(properties.FtpsState, properties.ftpsState)),
         MinTls    = tostring(coalesce(properties.MinTlsVersion, properties.minTlsVersion))
| summarize Configs      = count(),
            FtpsEnforced = countif(FtpsState in ("FtpsOnly", "Disabled")),
            MinTls12     = countif(MinTls in ("1.2", "1.3"))
```

The site configuration child lives in the `appserviceresources` table. The earlier version looked for it in `resources`, which is why only the HTTPS-only figure ever came back. That table returns the config keys in PascalCase (`MinTlsVersion`, `FtpsState`) and Kusto property access is case-sensitive, so the camelCase keys read as null and every site counted as failing. Packs produced before script 1.6.1 show 0 for both counters and must be rerun. If this returns no rows, grade from the FTPS and TLS rows in DFC.1.

**NB.6 Azure SQL minimum TLS and public access** (ARG)

```kusto
resources
| where type =~ "microsoft.sql/servers"
| where id !contains "aznativesol0"
| summarize Servers        = count(),
            MinTls12       = countif(tostring(properties.minimalTlsVersion) in ("1.2", "1.3")),
            PublicDisabled = countif(tostring(properties.publicNetworkAccess) =~ "Disabled")
```

**NB.7 DNS and egress telemetry present** (Log Analytics)

```kusto
Usage
| where TimeGenerated between (ago(30d) .. now())
| where DataType matches regex "(?i)dns|azfw|firewall|commonsecuritylog|networksession"
| summarize GB = round(sum(Quantity) / 1000, 2), LastSeen = max(TimeGenerated) by DataType
| order by GB desc
```

**NB.8, NB.10 and NB.11** (Advanced Hunting)

Per-device measures built from the shared shape above, Azure virtual machines only: network protection in block mode (NB.8, scid-96), LDAP server signing and channel binding on domain controllers (NB.10, scid-105 and scid-106), and LAN Manager authentication level NTLMv2 only (NB.11, scid-72). NB.8 reads E only when the Atmosera DNS tunneling and beaconing analytics rules are enabled in Sentinel. Count them from DR.9-RULES. Since collector 1.14.0 the figure is the Azure virtual machines in block mode, not the whole fleet, so it reads in the tens rather than the thousands on the slide. NB.10 is out of scope for cloud-only tenants, and Directory Service events 2889 and 3039 name the clients still binding insecurely once that log reaches Sentinel. NTLM-dependent systems show in IdentityLogonEvents through the Defender for Identity connector.

### Data Protection (SOC 2 CC6.7, C1.1, C1.2)

| ID | Control | Tier | Measure | Evidence |
| --- | --- | --- | --- | --- |
| DP-F1 | Data loss prevention enforced across mail and endpoint | F | DLP policies in Enable mode covering Exchange and endpoint | DP.6 |
| DP-F2 | Malicious mail removed from mailboxes after delivery | F | Post-delivery removals succeeded over attempted | DP.7 |
| DP-F3 | Mail and collaboration protected by threat protection (US Claims) | F | Safe Links and Safe Attachments points earned | POS.6, IA.9 |
| DP-F4 | Secret and key stores protected against deletion and purge | F | Vaults with purge protection over vaults | DP.2 |
| DP-F5 | Storage and managed disks encrypted with platform keys | F | Disks with an at-rest encryption type | DP.3 |
| DP-F6 | Public network access not allowed on storage accounts (DRB) | F | Accounts with public network access disabled | DP.1 |
| DP-D1 | Sensitivity labeling and classification | D | Out of scope at both clients, leaves the denominator | None |
| DP-D2 | Encryption at host on virtual machines and scale sets | D | Defender for Cloud healthy over evaluated | DFC.1, DP.4 |
| DP-D3 | Key vault access governed by role-based access control | D | Vaults on RBAC authorization | DP.2 |
| DP-D4 | Endpoint disk encryption enforced on managed devices (US Claims) | D | Intune encryption state, or the BitLocker check | DP.10, EW.3 |
| DP-D5 | Collaboration sharing boundaries defined and governed | D | Sharing capability and domain restriction | DP.8 |
| DP-D6 | Azure Backup enabled on all persistent virtual machines (DRB) | D | Persistent VMs with a protected item | DP.5, DP.5b, DP.5c |

**DP.1 Storage account protection** (ARG)

```kusto
resources
| where type =~ "microsoft.storage/storageaccounts"
| where id !contains "aznativesol0"
| summarize Accounts         = count(),
            SecureTransfer   = countif(tobool(properties.supportsHttpsTrafficOnly) == true),
            MinTls12         = countif(tostring(properties.minimumTlsVersion) in ("TLS1_2", "TLS1_3")),
            AnonymousBlobOff = countif(tobool(properties.allowBlobPublicAccess) == false),
            PublicNetworkOff = countif(tostring(properties.publicNetworkAccess) =~ "Disabled"),
            SelectedNetworks = countif(tostring(properties.networkAcls.defaultAction) =~ "Deny"),
            SharedKeyOff     = countif(tobool(properties.allowSharedKeyAccess) == false)
```

- Two different controls hide behind "storage public access". `AnonymousBlobOff` is anonymous blob reads. `PublicNetworkOff` is network reachability. The US Claims query measured the first, while the DRB slide claimed the second, so name the property on the slide.
- A null `allowBlobPublicAccess` on an older account means anonymous access is allowed, and the query correctly leaves it uncounted.
- Azure Storage stopped accepting TLS 1.0 and 1.1 connections on February 3, 2026 ([The Register](https://www.theregister.com/2026/02/03/microsoft_tls_deprecations/)). An account whose `minimumTlsVersion` still reads TLS1\_0 is a configuration hygiene item, not an open downgrade path. Word it that way on the slide.
- `SharedKeyOff` backs the roadmap item moving storage access to Entra ID authentication.

**DP.1-CONTAINERS Blob container anonymous access levels** (ARG, then the Storage resource provider)

Resource Graph does not index blob containers, so the collector lists the storage accounts first and then reads each account's containers with a GET, which the Reader role allows.

```kusto
resources
| where type =~ "microsoft.storage/storageaccounts"
| where id !contains "aznativesol0"
| where kind !~ "FileStorage"   // no blob service
| project ResourceId = id, Account = name, resourceGroup, subscriptionId,
          AllowBlobPublicAccess = tostring(properties.allowBlobPublicAccess)
| order by subscriptionId asc, Account asc
```

Then, for each account: `GET https://management.azure.com/<ResourceId>/blobServices/default/containers?api-version=2023-05-01`, following `nextLink`.

- One row per account: the account setting (Allowed, Disabled, or Not set, which means allowed), the containers, the containers whose own `publicAccess` is Blob or Container, and how many of those are readable anonymously today because the account setting allows it.
- Containers are read in every account. A container left public under an account that blocks anonymous access still counts against the defense in depth row, because it opens again the moment the account setting is relaxed.
- An account whose containers cannot be listed is recorded with the error and left out of the counts, and the result reads PARTIAL.
- Portal check: Storage account > Data storage > Containers, the Anonymous access level column.

**DP.2 Key Vault protection** (ARG)

```kusto
resources
| where type =~ "microsoft.keyvault/vaults"
| where id !contains "aznativesol0"
| summarize Vaults          = count(),
            SoftDelete      = countif(isnull(properties.enableSoftDelete)
                                      or tobool(properties.enableSoftDelete) == true),
            PurgeProtection = countif(tobool(properties.enablePurgeProtection) == true),
            RbacAuth        = countif(tobool(properties.enableRbacAuthorization) == true),
            PublicDisabled  = countif(tostring(properties.publicNetworkAccess) =~ "Disabled")
```

Soft delete can no longer be turned off on any vault, so a missing property counts as on. Purge protection is the reverse: missing means off. DP-F4 therefore grades on `PurgeProtection`.

**DP.3 Managed disk encryption type** (ARG)

```kusto
resources
| where type =~ "microsoft.compute/disks"
| where id !contains "aznativesol0"
| extend EncryptionType = tostring(properties.encryption.type),
         AdeEnabled     = tobool(properties.encryptionSettingsCollection.enabled) == true
| summarize Disks = count() by EncryptionType, AdeEnabled
```

Storage service encryption is always on and cannot be disabled, so the storage half of DP-F5 is enforced by platform default. This query evidences the disk half.

**DP.4 Encryption at host on VMs and scale sets** (ARG)

```kusto
resources
| where type in~ ("microsoft.compute/virtualmachines", "microsoft.compute/virtualmachinescalesets")
| where id !contains "aznativesol0"
| extend EncryptionAtHost = coalesce(tobool(properties.securityProfile.encryptionAtHost),
                                     tobool(properties.virtualMachineProfile.securityProfile.encryptionAtHost),
                                     false),
         PowerState = iff(type =~ "microsoft.compute/virtualmachinescalesets", "Scale set",
                          tostring(properties.extended.instanceView.powerState.code))
| summarize Resources = count(), WithEncryptionAtHost = countif(EncryptionAtHost)
          by ResourceType = tolower(type), PowerState
```

Grade and quote from the DFC.1 encryption rows, which accept Azure Disk Encryption as an alternative (DRB was 49 of 52 there). Use this query to name the machines still pending, and keep deallocated machines in the count.

**DP.5 Azure Backup protected items** (ARG)

```kusto
recoveryservicesresources
| where type =~ "microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems"
| where tostring(properties.sourceResourceId) !contains "aznativesol0"
| extend ProtectionState = tostring(properties.protectionState),
         LastBackup      = todatetime(properties.lastBackupTime)
| summarize Items       = count(),
            StaleOver48h = countif(LastBackup < ago(2d))
          by ProtectionState
```

**DP.5b Virtual machines without a protected backup item** (ARG)

```kusto
resources
| where type =~ "microsoft.compute/virtualmachines"
| where id !contains "aznativesol0"
| project VmId = tolower(id), VmName = name, resourceGroup,
          PowerState = tostring(properties.extended.instanceView.powerState.code)
| join kind=leftouter (
    recoveryservicesresources
    | where type =~ "microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems"
    | where tostring(properties.sourceResourceId) !contains "aznativesol0"
    | project VmId            = tolower(tostring(properties.sourceResourceId)),
              ProtectionState = tostring(properties.protectionState)
  ) on VmId
| where isempty(ProtectionState) or ProtectionState != "Protected"
| project VmName, resourceGroup, PowerState, ProtectionState
| order by resourceGroup asc, VmName asc
```

**DP.5c AVD host pool type for the backup exclusion** (ARG)

```kusto
resources
| where type =~ "microsoft.desktopvirtualization/hostpools"
| where id !contains "aznativesol0"
| project HostPool           = name,
          resourceGroup,
          HostPoolType       = tostring(properties.hostPoolType),
          PersonalAssignment = tostring(properties.personalDesktopAssignmentType)
```

Pooled session hosts are rebuilt from an image, so they leave the backup denominator and the slide footnotes the exclusion. If any pool returns `Personal`, the exclusion does not hold for its hosts. A host pool in the managed resource group is excluded like every other resource there.

**DP.6 DLP policy mode** (Security and Compliance PowerShell)

```powershell
Connect-IPPSSession

Get-DlpCompliancePolicy |
    ForEach-Object {
        [pscustomobject]@{
            Name      = $_.Name
            Mode      = $_.Mode
            Enabled   = $_.Enabled
            Workloads = $_.Workload -join ","
        }
    } |
    Sort-Object Mode, Name |
    Format-Table -AutoSize
```

Only `Enable` mode is enforcement. Both test modes are simulation. Confirm endpoint DLP licensing before the slide claims endpoint coverage.

**DP.7 Post-delivery mail removal** (Advanced Hunting)

```kusto
EmailPostDeliveryEvents
| where Timestamp between (ago(30d) .. now())
| summarize Events     = count(),
            Succeeded  = countif(ActionResult == "Success"),
            Recipients = dcount(RecipientEmailAddress)
          by ActionType, ActionTrigger
| order by Events desc
```

`ActionTrigger` separates automatic purge from analyst remediation, which is the evidence for the line that Atmosera removes any remaining phishing items. Advanced Hunting reaches back 30 days only, so window-wide counts come from the CyberSOC reports.

**DP.7-ZAP Zero-hour auto purge settings** (Exchange Online PowerShell)

```powershell
Get-MalwareFilterPolicy | Select-Object Name, IsDefault, ZapEnabled
Get-HostedContentFilterPolicy | Select-Object Name, IsDefault, PhishZapEnabled, SpamZapEnabled
```

The setting behind DP.7. In force when every policy in use has the flags on. DP.7 counts the removals it produced.

**DP.8 SharePoint and OneDrive sharing** (Microsoft Graph)

The collector reads `GET /v1.0/admin/sharepoint/settings` (needs SharePointTenantSettings.Read.All) and writes one row: SharingCapability, DomainRestrictionMode, AllowedDomains, BlockedDomains, ResharingByExternalUsers, LegacyAuthProtocols, UnmanagedSyncRestricted. By hand, the Graph PowerShell below gives the same data.

```powershell
Connect-MgGraph -Scopes "SharePointTenantSettings.Read.All" -NoWelcome

Get-MgAdminSharepointSetting |
    Select-Object SharingCapability, SharingDomainRestrictionMode,
        IsResharingByExternalUsersEnabled, SharingAllowedDomainList
```

**DP.10 Endpoint disk encryption on managed devices** (Microsoft Graph)

`GET /v1.0/deviceManagement/managedDevices?$select=id,operatingSystem,isEncrypted,managedDeviceOwnerType,complianceState` (needs DeviceManagementManagedDevices.Read.All), aggregated to one row per operating system and ownership: Devices, Encrypted, Compliant. Windows and macOS are the platforms in scope. Without Intune access the report grades from the BitLocker row of EW.3 (scid-2090, Encrypt all BitLocker-supported drives) and says so.

### Detection and Response (SOC 2 CC7.2, CC7.3, CC7.4)

| ID | Control | Tier | Measure | Evidence |
| --- | --- | --- | --- | --- |
| DR-F1 | Endpoint detection sensor reporting on Azure virtual machines | F | Sensor active over onboarded Azure virtual machines, network devices and firewalls excluded, reconciled with EW-F1 through the EW.1-GAPS reasons | EW.1, EW.1-GAPS |
| DR-F2 | Every alert triaged to a documented disposition | F | Closed alerts with a classification and a closing comment, alerts linked to an incident | DR.10, OUT.1, DR.1 |
| DR-F3 | Cloud workload protection enabled across the resource estate | F | Plan-covered resources over plan-eligible resources | DR.2 |
| DR-F4 | Security telemetry centrally collected and retained | F | Retention days and active data types | P0.2, DR.3 |
| DR-F5 | Domain controller telemetry collected continuously (US Claims) | F | Healthy sensors over sensors registered, and domain controllers emitting events | DR.11, DR.4 |
| DR-F6 | Vulnerability assessment running estate-wide (DRB) | F | Onboarded devices with a software inventory | DR.5, DFC.1 |
| DR-D1 | Diagnostic logging enabled on all platform resources | D | Resources with every logging assessment healthy, and initiative compliance once assigned | DR.13, DR.6-INITIATIVE, DR.6 |
| DR-D2 | Vulnerability assessment running estate-wide (US Claims) | D | Same measure as DR-F6 | DR.5, DFC.1 |
| DR-D3 | Threat intelligence indicators ingested and matched | D | Indicators ingested and TI match alerts raised | DR.7, DR.8 |
| DR-D4 | Detection content engineered and tuned to this environment | D | Enabled rules, rules modified in the window, noise trend | DR.9, OUT.3 |
| DR-D5 | Automated attack disruption active on identity threats | D | Disruption-tagged incidents, and the automation level of each device group | OUT.7, DR.12 |

DR-F5 is out of scope for a client with no on-premises Active Directory, which applies to US Claims now that directory sync is retired. Mark it out of scope rather than E.

**DR.1 Alerts not linked to any incident** (Log Analytics)

```kusto
SecurityAlert
| where TimeGenerated between (datetime(2026-01-01) .. endofday(datetime(2026-07-31)))
| summarize arg_max(TimeGenerated, AlertName, ProductName, AlertSeverity) by SystemAlertId
| join kind=leftanti (
    SecurityIncident
    | where TimeGenerated between (datetime(2026-01-01) .. now())
    | mv-expand AlertId = AlertIds to typeof(string)
    | distinct AlertId
  ) on $left.SystemAlertId == $right.AlertId
| summarize UnlinkedAlerts = count() by ProductName, AlertSeverity
| order by UnlinkedAlerts desc
```

An unlinked alert is not automatically untriaged, because incident creation rules can filter informational alerts by design. Every unlinked row needs an explanation before the deck says every alert reached a disposition.

**DR.2 Workload protection coverage by plan** (ARG)

```kusto
resources
| where id !contains "aznativesol0"
| extend Plan = case(
    type in~ ("microsoft.compute/virtualmachines", "microsoft.compute/virtualmachinescalesets",
              "microsoft.hybridcompute/machines"),                                "VirtualMachines",
    type =~ "microsoft.web/sites",                                                "AppServices",
    type =~ "microsoft.storage/storageaccounts",                                  "StorageAccounts",
    type =~ "microsoft.keyvault/vaults",                                          "KeyVaults",
    type in~ ("microsoft.sql/servers", "microsoft.sql/managedinstances"),         "SqlServers",
    type in~ ("microsoft.dbforpostgresql/flexibleservers",
              "microsoft.dbformysql/flexibleservers"),                            "OpenSourceRelationalDatabases",
    type =~ "microsoft.documentdb/databaseaccounts",                              "CosmosDbs",
    type in~ ("microsoft.containerservice/managedclusters",
              "microsoft.containerregistry/registries"),                          "Containers",
    type =~ "microsoft.apimanagement/service",                                    "Api",
    type =~ "microsoft.cognitiveservices/accounts"
        and tostring(kind) in~ ("OpenAI", "AIServices"),                          "AI",
    "")
| where isnotempty(Plan)
| project subscriptionId, Plan, ResourceType = tolower(type)
| join kind=leftouter (
    securityresources
    | where type =~ "microsoft.security/pricings"
    | project subscriptionId, Plan = name, Tier = tostring(properties.pricingTier)
  ) on subscriptionId, Plan
| summarize Resources = count(), Covered = countif(Tier =~ "Standard") by Plan, ResourceType
| extend PctCovered = round(100.0 * Covered / Resources, 1)
| order by PctCovered asc
```

The `AI` row is the Tier 3 figure for AI service resources without workload protection. Per-resource plan overrides on VMs and storage are not visible here, so reconcile the total with the portal coverage reading (US Claims showed 99.87 percent) and quote the portal figure.

**DR.3 Telemetry breadth by table** (Log Analytics)

```kusto
Usage
| where TimeGenerated between (ago(30d) .. now())
| summarize GB = round(sum(Quantity) / 1000, 2), LastSeen = max(TimeGenerated) by DataType, Solution
| order by GB desc
| take 25
```

**DR.4 Domain controller telemetry** (Advanced Hunting)

```kusto
IdentityLogonEvents
| where Timestamp between (ago(7d) .. now())
| where isnotempty(DestinationDeviceName)
| summarize Events = count(), LastEvent = max(Timestamp) by DomainController = DestinationDeviceName
| order by LastEvent asc
```

Compare the list with the sensor inventory at Defender portal > System > Settings > Identities > Sensors. A domain controller missing here, or with a stale `LastEvent`, is the gap.

**DR.5 Vulnerability assessment coverage of onboarded Azure virtual machines** (Advanced Hunting)

```kusto
DeviceInfo
| where Timestamp between (ago(7d) .. now())
| summarize arg_max(Timestamp, OnboardingStatus, AzureResourceId) by DeviceId
| where OnboardingStatus == "Onboarded"
| where isnotempty(AzureResourceId)   // Azure virtual machines only
| where AzureResourceId !contains "aznativesol0"
| join kind=leftouter (
    DeviceTvmSoftwareInventory
    | distinct DeviceId
    | extend HasInventory = true
  ) on DeviceId
| extend Scope = "Azure VM"
| summarize Onboarded = count(), Assessed = countif(HasInventory == true) by Scope
```

**DR.6 Diagnostic and audit logging gaps** (ARG)

```kusto
securityresources
| where type =~ "microsoft.security/assessments"
| where id !contains "aznativesol0"
| extend Recommendation = tostring(properties.displayName),
         Status         = tostring(properties.status.code)
| where Recommendation has_any ("resource logs", "diagnostic logs", "auditing", "audit logs", "flow logs")
| summarize Healthy = countif(Status == "Healthy"), Unhealthy = countif(Status == "Unhealthy")
          by Recommendation
| order by Unhealthy desc
```

The summed `Unhealthy` count is the Tier 3 Enable audit logging figure. The Enable auditing and logging row in POS.3 should agree, so quote one source and cross-check against the other.

**DR.7 Threat intelligence ingestion** (Log Analytics)

```kusto
union withsource = SourceTable isfuzzy = true ThreatIntelIndicators, ThreatIntelligenceIndicator
| where TimeGenerated between (ago(30d) .. now())
| extend IndicatorKey = coalesce(tostring(column_ifexists("Id", "")),
                                 tostring(column_ifexists("IndicatorId", "")))
| summarize Indicators = dcount(IndicatorKey), LastIngested = max(TimeGenerated) by SourceTable
```

Sentinel moved threat intelligence to the STIX-based `ThreatIntelIndicators` table. The union reads whichever table the workspace has, so the query works before and after migration.

**DR.8 Threat intelligence matches** (Log Analytics)

```kusto
SecurityAlert
| where TimeGenerated between (datetime(2026-01-01) .. endofday(datetime(2026-07-31)))
| where AlertName has_any ("TI map", "Threat Intelligence")
| summarize Alerts = dcount(SystemAlertId) by AlertName
| order by Alerts desc
```

**DR.9 Analytics rule inventory** (Az PowerShell)

```powershell
Connect-AzAccount
Set-AzContext -Subscription "CLIENT-SUBSCRIPTION-ID"

$rules = Get-AzSentinelAlertRule -ResourceGroupName "WORKSPACE-RESOURCE-GROUP" -WorkspaceName "WORKSPACE-NAME"

$rules | Group-Object Kind | Select-Object Name, Count
"Enabled rules: {0}" -f @($rules | Where-Object Enabled).Count
"Rules modified since window start: {0}" -f @($rules | Where-Object { $_.LastModifiedUtc -ge [datetime]"2026-01-01" }).Count
```

Rules modified in the window plus the falling monthly volume in OUT.3 is the evidence behind "detection content engineered and tuned", rather than the assertion alone.

**DR.10 Closed alerts with a documented disposition** (Log Analytics)

```kusto
SecurityIncident
| where TimeGenerated between (ago(45d) .. now())
| summarize arg_max(TimeGenerated, *) by TenantId, IncidentNumber
| where Status == "Closed" and ClosedTime between (ago(30d) .. now())
| where Severity != "Informational"
| where (tostring(Comments) matches regex @"(?i)(zendesk\.com/agent/tickets/\d+|\bZD\s*(ticket|#)?\s*#?\s*\d{4,})" or tostring(ClassificationComment) matches regex @"(?i)(zendesk\.com/agent/tickets/\d+|\bZD\s*(ticket|#)?\s*#?\s*\d{4,})")
| summarize Closed             = count(),
            WithClassification = countif(isnotempty(Classification) and Classification != "Undetermined"),
            WithComment        = countif(isnotempty(ClassificationComment)),
            Documented         = countif(isnotempty(Classification) and Classification != "Undetermined" and isnotempty(ClassificationComment))
```

Same alert scope as OUT.1 to OUT.7. Documented over Closed is the DR-F2 figure.

**DR.11 Defender for Identity sensors** (Microsoft Graph)

`GET /v1.0/security/identities/sensors` (needs SecurityIdentitiesSensors.Read.All), one row per sensor: Sensor, SensorType, HealthStatus, DeploymentStatus, Version, Domain, OpenHealthIssues, CreatedUtc. Healthy over registered is the figure; a domain controller with no sensor row is the gap, and DR.4 shows which ones emit events. Out of scope for cloud-only tenants.

**DR.12 Onboarded Azure virtual machines by device group** (Advanced Hunting)

```kusto
DeviceInfo
| where Timestamp between (ago(30d) .. now())
| where OnboardingStatus == "Onboarded"
| summarize arg_max(Timestamp, MachineGroup, OSPlatform, AzureResourceId) by DeviceId
| where isnotempty(AzureResourceId)   // Azure virtual machines only
| where AzureResourceId !contains "aznativesol0"
| extend MachineGroup = iff(isempty(MachineGroup), "(no group)", MachineGroup)
| summarize Devices = count() by MachineGroup
| order by Devices desc
```

Membership only. The automation level of each group is read at Defender portal > System > Settings > Endpoints > Device groups. There is no documented API for it.

**DR.13 Diagnostic logging assessments per resource** (ARG)

```kusto
securityresources
| where type =~ "microsoft.security/assessments"
| where id !contains "aznativesol0"
| extend Recommendation = tostring(properties.displayName),
         Status         = tostring(properties.status.code),
         ResourceId     = tolower(tostring(properties.resourceDetails.Id))
| where Recommendation has_any ("resource logs", "diagnostic logs", "auditing", "audit logs", "flow logs")
| where Status in ("Healthy", "Unhealthy")
| summarize Assessments = count(), Unhealthy = countif(Status == "Unhealthy") by ResourceId
| summarize Resources = count(), AllHealthy = countif(Unhealthy == 0), WithGaps = countif(Unhealthy > 0)
```

DR.6 counted per resource. AllHealthy over Resources is the DR-D1 figure.

**DR.6-INITIATIVE ATMO-MXDR diagnostic logging initiative compliance** (ARG)

```kusto
policyresources
| where type =~ "microsoft.policyinsights/policystates"
| extend AssignmentName = tostring(properties.policyAssignmentName),
         InitiativeName = tostring(properties.policySetDefinitionName),
         DefinitionName = tostring(properties.policyDefinitionName),
         Compliance     = tostring(properties.complianceState),
         ResourceId     = tolower(tostring(properties.resourceId))
| where AssignmentName contains "ATMO-MXDR" or InitiativeName contains "ATMO-MXDR" or DefinitionName contains "ATMO-MXDR"
| where ResourceId !contains "aznativesol0"
| summarize Resources    = dcount(ResourceId),
            Compliant    = dcountif(ResourceId, Compliance =~ "Compliant"),
            NonCompliant = dcountif(ResourceId, Compliance =~ "NonCompliant")
          by DefinitionName
| order by NonCompliant desc, DefinitionName asc
```

Empty means the initiative is not assigned in these subscriptions yet. Once it is, Compliant over Resources is the foundational logging figure.

## Phase 3: Posture and benchmark

Both Microsoft scores are Tier 4 context, never the objective, and each one goes on a slide with its read date and the resource count it was measured across.

**POS.1 Defender for Cloud secure score, overall** (ARG)

```kusto
securityresources
| where type =~ "microsoft.security/securescores"
| where name =~ "ascScore"
| extend Current = todouble(properties.score.current),
         Max     = todouble(properties.score.max)
| summarize Current = sum(Current), Max = sum(Max), Subscriptions = count()
| extend Percent = round(100.0 * Current / Max, 1)
```

This is the classic Defender for Cloud score. Since the May 5, 2026 restatement the Defender portal also shows a risk-based cloud secure score, so the slide must say which one it quotes.

**POS.2 Distinct resources assessed by Defender for Cloud** (ARG)

```kusto
securityresources
| where type =~ "microsoft.security/assessments"
| where id !contains "aznativesol0"
| extend AssessedId = tostring(split(tolower(id), "/providers/microsoft.security/assessments/")[0])
| where AssessedId has "/resourcegroups/"
| summarize Assessments = count() by AssessedId
| summarize AssessedResources = count()
```

The portal reading at Defender for Cloud > Overview is the source of record for assessed resources, because it counts identity and configuration objects this query cannot see. Record both values. The Inventory blade can lag the Overview blade by a few resources (US Claims read 618 against 611), so quote the Overview figure, which reconciles to the health split.

**POS.3 Secure score by control, summed across subscriptions** (ARG)

```kusto
securityresources
| where type =~ "microsoft.security/securescores/securescorecontrols"
| extend Control       = tostring(properties.displayName),
         Current       = todouble(properties.score.current),
         Max           = todouble(properties.score.max),
         Healthy       = toint(properties.healthyResourceCount),
         Unhealthy     = toint(properties.unhealthyResourceCount),
         NotApplicable = toint(properties.notApplicableResourceCount)
| summarize Current = sum(Current), Max = sum(Max), Healthy = sum(Healthy),
            Unhealthy = sum(Unhealthy), NotApplicable = sum(NotApplicable)
          by Control
| extend Remaining    = round(Max - Current, 2),
         PctOfControl = round(100.0 * Current / Max, 1)
| order by Remaining desc
```

At DRB this single result drove eight deck figures, including the 26.52 of 43 control points, the 82.2 percent system updates rollup and the 94.8 percent transit encryption. Score controls are subscription-level, so the managed resource group cannot be excluded here. Note that beside any figure taken from this query.

**POS.4 Assessment health by severity** (ARG)

```kusto
securityresources
| where type =~ "microsoft.security/assessments"
| where id !contains "aznativesol0"
| extend Status   = tostring(properties.status.code),
         Severity = tostring(properties.metadata.severity)
| where Status in ("Healthy", "Unhealthy")
| summarize Healthy = countif(Status == "Healthy"), Total = count() by Severity
| extend PctHealthy = round(100.0 * Healthy / Total, 1)
| order by Severity asc
```

Quote high severity, or high and medium combined, as the headline. Low severity runs far lower (9.1 percent at US Claims) and belongs in the talk track, not on a tile.

**POS.5 Regulatory compliance controls passed** (ARG)

```kusto
securityresources
| where type =~ "microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols"
| extend Standard = tostring(split(id, "/")[6]),
         State    = tostring(properties.state)
| summarize Passed  = countif(State == "Passed"),
            Failed  = countif(State == "Failed"),
            Skipped = countif(State == "Skipped"),
            Total   = count()
          by Standard, subscriptionId
| order by Standard asc
```

Reconcile with Defender for Cloud > Regulatory compliance before quoting, because the Microsoft cloud security benchmark v2 rollout changed how controls are counted. Read the row for the benchmark standard the portal shows.

**POS.6 Tenant Secure Score with category points and 90-day trend** (Microsoft Graph)

The collector reads `GET /v1.0/security/secureScores?$top=90` and `GET /v1.0/security/secureScoreControlProfiles` (needs SecurityEvents.Read.All) and writes three results: POS.6 with ReadDate, Current, Max, Percent, IdentityPct, DevicePct, AppsPct, DataPct, AllTenantsAverage and Snapshots; POS.6-TREND with one row per daily snapshot; POS.6-CATEGORIES with Earned, Available and Percent per category. The worksheet fills the tenant score, trend and category rows from them, and the HTML report shows the tenant score with its 90-day movement without a context file. By hand, the Graph PowerShell below produces the same CSVs.

```powershell
Connect-MgGraph -Scopes "SecurityEvents.Read.All" -NoWelcome

$history  = Get-MgSecuritySecureScore -Top 90
$score    = $history | Sort-Object CreatedDateTime -Descending | Select-Object -First 1
$profiles = Get-MgSecuritySecureScoreControlProfile -All |
    Group-Object -Property Id -AsHashTable -AsString

$controls = foreach ($c in $score.ControlScores) {
    $p = $profiles[$c.ControlName]
    if ($p) {
        [pscustomobject]@{
            Category = $c.ControlCategory
            Control  = $c.ControlName
            Title    = $p[0].Title
            Score    = [double]$c.Score
            Max      = [double]$p[0].MaxScore
        }
    }
}
$controls | Export-Csv -Path ".\POS.6-secure-score-controls.csv" -NoTypeInformation

# Category points, the basis for the tenant posture slide
$controls | Group-Object Category | ForEach-Object {
    $earned    = ($_.Group | Measure-Object Score -Sum).Sum
    $available = ($_.Group | Measure-Object Max -Sum).Sum
    [pscustomobject]@{
        Category  = $_.Name
        Earned    = [math]::Round($earned, 2)
        Available = $available
        Percent   = [math]::Round(100 * $earned / $available, 1)
    }
} | Sort-Object Available -Descending | Format-Table -AutoSize

"Tenant score {0:N2} of {1:N0}, {2:N2} percent, read {3:yyyy-MM-dd}" -f $score.CurrentScore, $score.MaxScore, (100 * $score.CurrentScore / $score.MaxScore), $score.CreatedDateTime
$score.AverageComparativeScores | Select-Object Basis, AverageScore

# 90-day trend for the tenant score chart
$history | Sort-Object CreatedDateTime |
    ForEach-Object {
        [pscustomobject]@{
            Date    = $_.CreatedDateTime.ToString("yyyy-MM-dd")
            Percent = [math]::Round(100 * $_.CurrentScore / $_.MaxScore, 2)
        }
    } |
    Export-Csv -Path ".\POS.6-secure-score-trend.csv" -NoTypeInformation
```

- The category table is the DRB tenant slide in one run: Identity 45.89 of 76, Device 382.60 of 914 and so on.
- The controls CSV grades every Secure Score-based control in Phase 2: anti-phishing, Credential Guard, BitLocker, sharing, SSPR and the identity recommended actions.
- The trend CSV backs "up 5.5 points since May" without a screenshot.
- Category sums use active control profiles, so they can differ from the headline maximum by a few points. Quote the headline from `CurrentScore` over `MaxScore`, and peer medians from the portal comparison view.

**POS.7 Defender for Cloud score trend from continuous export** (Log Analytics)

```kusto
SecureScores
| where TimeGenerated between (datetime(2026-01-01) .. now())
| summarize arg_max(TimeGenerated, CurrentScore, MaxScore)
          by Month = startofmonth(TimeGenerated), ScoreId = tolower(_ResourceId)
| summarize Current = sum(CurrentScore), Max = sum(MaxScore) by Month
| extend Percent = round(100.0 * Current / Max, 1)
| order by Month asc
```

Exported rows keep the model in force when they were written, while the portal shows history recalculated after May 5, 2026. The two will disagree around that date, so pick one source for the whole series and footnote it.

**POS.8 Recommendation health trend from weekly snapshots** (Log Analytics)

```kusto
SecurityRecommendation
| where TimeGenerated between (datetime(2026-01-01) .. now())
| where tobool(IsSnapshot)
| where AssessedResourceId !contains "aznativesol0"
| summarize arg_max(TimeGenerated, RecommendationState)
          by Week = startofweek(TimeGenerated), AssessedResourceId, RecommendationName
| summarize Healthy   = countif(RecommendationState == "Healthy"),
            Unhealthy = countif(RecommendationState == "Unhealthy")
          by Week
| extend PctHealthy = round(100.0 * Healthy / (Healthy + Unhealthy), 1)
| order by Week asc
```

Streaming export only writes a row when something changes, so a daily count of streamed rows misses every resource that stayed the same. Weekly snapshots carry the full state. If the export was set up without snapshots, enable them now so the next review has a real remediation trend.

## Phase 4: Improvement backlog

Every Tier 3 tile is already produced by an earlier query except two, so this phase is mostly a lookup plus BKL.1 and BKL.2.

| Tier 3 tile | Count it as | Query |
| --- | --- | --- |
| Exploitable OS findings open | Distinct CVEs with a public exploit on operating system software | BKL.1, row Operating system |
| Enable audit logging | Resources unhealthy on the logging recommendations | DR.6 |
| Add workload protection to AI service resources | AI resources not covered by a Standard plan | DR.2, row AI |
| VMs pending host encryption | Defender for Cloud unhealthy on encryption at host | DFC.1, DP.4 |
| Users on a retiring MFA method | Distinct users in the retiring bucket | IA.2 |
| Open security alerts | Active Defender for Cloud alerts plus open Sentinel incidents | BKL.2, OUT.1 |
| Standing privileged roles | Standing privileged Entra assignments, break-glass excluded | IA.6 |

**BKL.1 Exploitable vulnerabilities open on Azure virtual machines** (Advanced Hunting)

```kusto
DeviceTvmSoftwareVulnerabilities
| join kind=inner (
    DeviceTvmSoftwareVulnerabilitiesKB
    | where tobool(IsExploitAvailable)
    | project CveId
  ) on CveId
| join kind=inner (
    DeviceInfo
    | where Timestamp between (ago(7d) .. now())
    | summarize arg_max(Timestamp, AzureResourceId) by DeviceId
    | where isnotempty(AzureResourceId)   // Azure virtual machines only
    | where AzureResourceId !contains "aznativesol0"
  ) on DeviceId
| extend Scope    = "Azure VM",
         Software = iff(SoftwareName startswith "windows" or SoftwareName contains "linux",
                        "Operating system", "Application")
| summarize ExploitableCves = dcount(CveId), Devices = dcount(DeviceId)
          by Scope, Software, VulnerabilitySeverityLevel
| order by Scope asc, Software asc, VulnerabilitySeverityLevel asc
```

This is current state only. A month-by-month story such as 173 exposed endpoints falling to 22 must cite the CyberSOC report that recorded it, and a zero tile carries its read date.

**BKL.2 Open Defender for Cloud alerts** (ARG)

```kusto
securityresources
| where type =~ "microsoft.security/locations/alerts"
| where tostring(properties.resourceIdentifiers) !contains "aznativesol0"
| where tostring(properties.status) == "Active"
| summarize OpenAlerts = count() by Severity = tostring(properties.severity)
```

**Roadmap and delivered-work slides.** Every in-flight or delivered item cites its change request number from the change system of record. That record is also the only CC8.1 evidence, since no Microsoft query can show that a change went through change control.

## Slide map and collection worksheet

Every figure the template carries maps to a query ID below. Fill Value and Read date as you run, and a figure without both does not go on a slide.

| Slide | Figure | Query | Value | Read date |
| --- | --- | --- | --- | --- |
| Executive summary | Months of managed security | Contract start date |  |  |
| Executive summary | Azure resources in the estate | P0.5, summed |  |  |
| Executive summary | Resources assessed by Defender for Cloud | Portal Overview, POS.2 |  |  |
| Executive summary | Alerts triaged | OUT.5 |  |  |
| Executive summary | Median time to close | OUT.2, row All |  |  |
| Executive summary | 90th percentile close, high severity | OUT.2, row High |  |  |
| Executive summary | Microsoft tenant Secure Score | POS.6 |  |  |
| Executive summary | Defender for Cloud score | POS.1 |  |  |
| Tier 1 | Confirmed data loss or exfiltration | OUT.4 |  |  |
| Tier 1 | High severity incident reduction | OUT.3 |  |  |
| Tier 1 | Monthly incident volume | OUT.3 |  |  |
| Tier 1 | True positives detected and managed | OUT.4 |  |  |
| Tier 1 | Malicious sign-in to containment | OUT.7, OUT.8 |  |  |
| Tier 2 | Overall program control grade | Phase 2 matrix |  |  |
| Tier 2 | Foundational controls enforced | Phase 2 matrix |  |  |
| Tier 2 | Defense in depth in force | Phase 2 matrix |  |  |
| Tier 2 | Devices onboarded to EDR | EW.1 |  |  |
| Tier 2 | MFA required at sign-in | IA.1 |  |  |
| Tier 2 | Workload protection coverage | Portal, DR.2 |  |  |
| Tier 2 | Endpoint anti-malware coverage | EW.3 |  |  |
| Tier 3 | Exploitable OS findings open | BKL.1 |  |  |
| Tier 3 | Enable audit logging | DR.6 |  |  |
| Tier 3 | AI service resources without workload protection | DR.2, row AI |  |  |
| Tier 3 | VMs pending host encryption | DFC.1 |  |  |
| Tier 3 | Users on a retiring MFA method | IA.2 |  |  |
| Tier 3 | Open security alerts | BKL.2, OUT.1 |  |  |
| Tier 3 | Standing privileged roles | IA.6 |  |  |
| Tier 4 | Benchmark controls passed | Portal, POS.5 |  |  |
| Tier 4 | Category scores against peer median | POS.6, portal comparison |  |  |
| Controls | Pillar grades and every E, P, N mark | Phase 2 tables |  |  |
| Measured outcomes | Identity compromises contained | OUT.4, OUT.7 |  |  |
| Measured outcomes | Exploitable findings closed in the patch cycle | BKL.1, CyberSOC report |  |  |
| Measured outcomes | Malicious mail removed after delivery | DP.7 |  |  |
| Measured outcomes | Boundary detections investigated | OUT.6 |  |  |
| Measured outcomes | High severity incidents per month | OUT.3 |  |  |
| Measured outcomes | Users challenged for MFA, x of y | IA.1 |  |  |
| Measured outcomes | Encryption at host, x of y | DFC.1 |  |  |
| Measured outcomes | Items under Azure Backup, x of y | DP.5 |  |  |
| Measured outcomes | Storage closed to public access with secure transfer | DP.1 |  |  |
| Measured outcomes | Workload subnets segmented, x of y | NB.1 |  |  |
| Score model change | Score and assessed count, before and after | POS.1, POS.2, POS.7 |  |  |
| Score model change | High severity assessments healthy | POS.4 |  |  |
| Tenant posture | Tenant score trend, 90 days | POS.6 trend CSV |  |  |
| Tenant posture | Category points and share of the scale | POS.6 |  |  |
| Passwordless | Users on a retiring method | IA.2 |  |  |
| Passwordless | Phishing-resistant users | IA.2, IA.5 |  |  |
| Passwordless | Users registered for Authenticator | IA.5 |  |  |
| Delivered and roadmap | Changes delivered under change control | Change system of record |  |  |
