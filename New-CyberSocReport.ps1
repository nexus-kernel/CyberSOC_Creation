<#
.SYNOPSIS
    Creates the self-contained monthly CyberSOC security report from an existing CyberSOC evidence pack.
.DESCRIPTION
    Offline only. Reads the manifest and selected aggregate evidence, then embeds the report
    assets in one HTML file. No Azure sign-in, network requests or source evidence changes.
    The report covers the report month with the 90-day trend of the window: security operations, threat
    intelligence, vulnerability management (from the imported Atmosera.VulnAssessment runs when the pack
    holds them, else the Defender queries) and the control posture of the EBR report it was copied from.
    Import vulnerability assessment runs into an existing pack first with Import-CyberSocVulnAssessment.ps1.
    Requires the adjacent report folder when generating a report. The generated HTML is portable.
    Writes two editions of the HTML. 03-security-report.html is the internal edition, with the embedded data, the
    presenter notes, the evidence review and the collection register. 03-security-report.client.html is the client
    edition, for sending to the client: the same pages rendered ahead of time through report/build-client-report.cjs,
    with no embedded data, no report model, no presenter notes and no GUIDs. It needs Node.js, and without it only the
    internal edition is written, with a warning. With -OutputPath the client edition takes the same name ending in
    .client.html.
    Also writes the PowerPoint edition beside it (03-security-report.pptx) from the same data,
    through report/build-report-deck.cjs, when Node.js and pptxgenjs are available. Its speaker
    notes are talking points only, never the presenter notes. -SkipDeck writes the two HTML editions only.
.EXAMPLE
    ./New-CyberSocReport.ps1 -EvidencePath ./CyberSOC-Evidence_Client_20261008-120000
.EXAMPLE
    ./New-CyberSocReport.ps1 -EvidencePath ./CyberSOC-Evidence_Client_20261008-120000 -ContextPath ./client-context.json -Depth Detailed
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$EvidencePath,
    [string]$OutputPath,
    [ValidateSet('Brief', 'Balanced', 'Detailed')][string]$Depth = 'Balanced',
    [string]$ContextPath,
    [switch]$SkipDeck
)

$ErrorActionPreference = 'Stop'
$pack = (Resolve-Path -LiteralPath $EvidencePath).Path
$assets = Join-Path $PSScriptRoot 'report'
foreach ($required in '00-parameters.json', '00-manifest.csv') {
    if (-not (Test-Path -LiteralPath (Join-Path $pack $required) -PathType Leaf)) {
        throw "Evidence pack is missing $required. Finish evidence collection before generating the report."
    }
}
$parameters = Get-Content -LiteralPath (Join-Path $pack '00-parameters.json') -Raw | ConvertFrom-Json
$manifest = @(Import-Csv -LiteralPath (Join-Path $pack '00-manifest.csv'))

# Explicit field selection keeps account names, machine names, comments, workload identifiers,
# query text and authentication diagnostics out of the portable report. Incident titles are
# embedded only as the screened OUT.4 Threat values (see Get-EbrScreenedTitle below).
$fields = [ordered]@{
    'P0.1' = @('SourceTable','EarliestRecord','LatestRecord','Records','Workspace')
    'P0.1-BY-WORKSPACE' = @('SourceTable','EarliestRecord','LatestRecord','Records','Workspace','WorkspaceId')
    'P0.1-XDRDUP' = @('XdrIncidents','InMultipleWorkspaces')
    'P0.5' = @('Resources')
    'OUT.1' = @('Raised','Closed','Open','TruePositive','BenignPositive','FalsePositive','ClosedUnclassified')
    'OUT.2' = @('Scope','Incidents','AutoClosed','MedianTriageMin','MedianCloseMin','P90CloseMin')
    'OUT.2-ANALYST' = @('Scope','Incidents','AutoClosed','MedianTriageMin','MedianCloseMin','P90CloseMin')
    'OUT.2-RECENT' = @('Scope','Incidents','AutoClosed','MedianCloseMin','P90CloseMin')
    'OUT.2-RECENT-ANALYST' = @('Scope','Incidents','AutoClosed','MedianCloseMin','P90CloseMin')
    'OUT.3' = @('Month','Total','High','Medium','Low','Informational','TruePositive','FalsePositive')
    'OUT.5' = @('ProductName','AlertSeverity','Alerts')
    'OUT.6' = @('ProductName','Alerts')
    'IA.1' = @('UserType','UsersSignedIn','UsersChallenged','UsersAlwaysMfa','UsersExternalMfa','UsersEntraMfa','MfaAtLeastOnce','MfaEveryAppSignIn','CoveredEveryAppSignIn','FederatedMfaAtLeastOnce','FederatedWithoutMfa','NoMfaOnlyUnevaluated','MfaSessionLinkedOnly')
    'IA.2' = @('Bucket','DistinctUsers','SignIns')
    'IA.3' = @('ClientAppUsed','Attempts','Succeeded','BlockedByCa','Users')
    'IA.9' = @('IsDefault','Enabled','EnableTargetedUserProtection','EnableOrganizationDomainsProtection','EnableMailboxIntelligenceProtection','EnableSpoofIntelligence')
    'IA.9-SAFELINKS' = @('EnableSafeLinksForEmail','EnableSafeLinksForTeams','EnableSafeLinksForOffice')
    'IA.9-SAFEATTACH' = @('Enable','Action','Enabled','Redirect')
    'EW.1' = @('Scope','OSPlatform','Devices','Onboarded','CanBeOnboarded','Unsupported','InsufficientInfo','SensorActive')
    'EW.3' = @('Scope','ConfigurationName','Devices','Compliant')
    'EW.7' = @('VMs','TrustedLaunchOrCvm','SecureBootOn','VTpmOn')
    'NB.4' = @('Sites','HttpsOnly')
    'NB.5' = @('Configs','FtpsEnforced','MinTls12')
    'NB.6' = @('Servers','MinTls12','PublicDisabled')
    'DP.1' = @('Accounts','SecureTransfer','MinTls12','AnonymousBlobOff','PublicNetworkOff')
    'DP.2' = @('Vaults','SoftDelete','PurgeProtection','RbacAuth')
    'DP.3' = @('EncryptionType','AdeEnabled','Disks')
    'DP.4' = @('ResourceType','PowerState','Resources','WithEncryptionAtHost')
    'DP.5' = @('ProtectionState','Items','StaleOver48h')
    'DP.7' = @('ActionType','Events','Succeeded')
    'DR.2' = @('Plan','ResourceType','Resources','Covered')
    'DR.3' = @('DataType','GB')
    'DR.4' = @('Events')
    'DR.5' = @('Scope','Onboarded','Assessed')
    'DR.6' = @('Recommendation','Healthy','Unhealthy')
    'DR.7' = @('Indicators')
    'DR.9' = @('Scope','Metric','Value')
    'POS.1' = @('Current','Max','Subscriptions','Percent')
    'POS.2' = @('AssessedResources')
    'POS.3' = @('Control','Current','Max','Healthy','Unhealthy','Remaining')
    'POS.4' = @('Severity','Healthy','Total')
    'POS.5' = @('Standard','Passed','Failed')
    'POS.7' = @('Month','Current','Max','Percent')
    'POS.8' = @('Week','Healthy','Unhealthy','PctHealthy')
    'BKL.1' = @('Scope','Software','VulnerabilitySeverityLevel','ExploitableCves','Devices')
    'BKL.2' = @('AlertId')
    # Graph and the controls added on Oct 11, 2026. Counts and flags only; names, domains and policy titles stay in the pack.
    'IA.5' = @('Members','MfaRegistered','MfaCapable','SsprRegistered','PasswordlessCapable','PhishingResistant','PhoneRegistered','AuthenticatorRegistered','PhoneOnly','Admins','AdminsMfaRegistered')
    'IA.1-ADMINPORTAL' = @('UserType','Users','UsersChallenged','UsersAlwaysMfa','SignIns','MfaSignIns','FederatedMfaAtLeastOnce','FederatedWithoutMfa','NoMfaOnlyUnevaluated','NotEvaluatedSignIns')
    'IA.3-DEVICECODE' = @('Attempts','Succeeded','BlockedByCa','Users','Apps','InForce')
    'IA.11' = @('SignInRiskPolicies','SignInRiskAllUsers','UserRiskPolicies','UserRiskAllUsers','InForce','PasswordHashSync')
    'IA.13' = @('UserConsent','AdminConsentWorkflow','RiskyAppConsent','Governed')
    'EW.10' = @('Machines','WithinCadence','OverduePatches','AssessedWithin7d')
    'EW.12' = @('Scope','Devices','Compliant')
    'EW.14' = @('Scope','Devices','Compliant')
    'EW.15' = @('Scope','Devices','Compliant')
    'EW.16' = @('Scope','Devices','Compliant')
    'NB.8' = @('Scope','Devices','Compliant')
    'NB.10' = @('Scope','Devices','Compliant')
    'NB.11' = @('Scope','Devices','Compliant')
    'DP.8' = @('SharingCapability','DomainRestrictionMode','ResharingByExternalUsers','LegacyAuthProtocols','UnmanagedSyncRestricted')
    'DP.10' = @('OperatingSystem','Ownership','Devices','Encrypted','Compliant')
    'DP.7-ZAP' = @('Kind','IsDefault','ZapEnabled','PhishZapEnabled','SpamZapEnabled')
    'DR.10' = @('Closed','WithClassification','WithComment','Documented')
    'DR.13' = @('Resources','AllHealthy','WithGaps')
    'DR.6-INITIATIVE' = @('DefinitionName','Resources','Compliant','NonCompliant')
    'POS.6' = @('ReadDate','Current','Max','Percent','IdentityPct','DevicePct','AppsPct','DataPct','AllTenantsAverage','Snapshots')
    'POS.6-TREND' = @('Date','Current','Max','Percent')
    'POS.6-CATEGORIES' = @('Category','Earned','Available','Percent')
    # CyberSOC monthly report (CyberSOC Monthly Report Runbook). Counts, months, tactic and technique IDs, indicator
    # types, feed and software names only. Alert titles (OUT.9) and threat names (TI.7) are reduced below.
    'OUT.2-MONTH' = @('Month','Scope','Incidents','AutoClosed','MedianTriageMin','MedianCloseMin','P90CloseMin')
    'OUT.3-WEEK' = @('Week','WeekEnd','Days','Total','High','Medium','Low','TruePositive','FalsePositive')
    'TI.0' = @('SourceTable','EarliestRecord','LatestRecord','Records')
    'TI.1' = @('Source','Kind','Indicators','Active','LastIngested')
    'TI.2' = @('Month','Indicator','AlertSeverity','Detections','Ticketed')
    'TI.3' = @('Month','Tactic','Detections','Alerts','TruePositiveAlerts')
    'TI.4' = @('Technique','Detections','Alerts','TruePositiveAlerts')
    'TI.5' = @('Month','SignIns','FailedPassword','TargetedUsers','Lockouts','BlockedByCa','RiskySignIns','RiskyUsers','SuccessfulRisky','RiskHidden','SprayIps','SprayDays')
    'TI.5-RISK' = @('Month','RiskEventType','Detections','Users','High','Medium')
    'TI.6' = @('Month','Messages','Phish','Malware','Spam','ThreatsBlocked','ThreatsDelivered')
    'VA.1' = @('VulnerabilitySeverityLevel','Cves','Devices','Exposures','ExploitableCves','ExploitableDevices')
    'VA.2' = @('SoftwareVendor','SoftwareName','Devices','Cves','Critical','High','ExploitableCves')
    'VA.3' = @('Month','Cves','Devices','Critical','High','ExploitableCves')
    'VA.RUNS' = @('RunDate','Status','SubscriptionsCovered','SubscriptionsMissing','SubscriptionsIncomplete','Findings','Open','Critical','High','Medium','Low','Vms','Cves','KevChecked','KevOpen','KevVms','KevAddedInReportMonth','ExploitChecked','ExploitOpen','NoVendorFix','EosVms','OwnerProvider','OwnerClient','OwnerUnknown','Status_remediation_required','Status_scheduled','Status_pending_client_action','Status_pending_vendor_fix','Status_mitigation_applied','Status_mitigation_in_place','Status_pending_validation','Status_resolved')
    'VA.CHANGE' = @('FromRun','ToRun','Compared','Reason','SeverityCompared','Earlier','Current','New','NoLongerReported','Persistent','OpenEarlier','OpenCurrent','OpenNew','OpenNoLonger')
    'VA.TOP' = @('Product','Severity','Vms','Findings','Cves','Kev','Exploit','MaxCvss','FixStatus','Owner')
    'VA.KEV' = @('Product','Severity','Vms','Findings','KevDateAdded','AddedThisMonth')
}
# Confirmed threat titles (OUT.4) reach the report only when they name no account, address, host, path,
# GUID, long number, machine or ticket, and run to 200 characters or fewer. A bare account, a person's name and an
# unhyphenated lowercase machine name are not recognised. Titles of true positives with no attack stage are left
# out, since the report shows them nowhere.
# The collector's default ticket reference, copied from $script:EbrTicketPattern in Get-CyberSocEvidence.ps1.
# It applies even when the pack carries its own TicketPattern.
$script:EbrTicketPattern = '(?i)(([a-z0-9-]+\.)?zendesk\.com/agent/tickets/\d+|\bZD\s*(ticket|#)?\s*#?\s*\d{4,})'
function Get-EbrScreenedTitle([string]$Title, [string]$TicketPattern) {
    $t = ($Title -replace '\s+', ' ').Trim()
    if (-not $t) { return '' }
    if ($t.Length -gt 200) { return 'Title withheld' }
    $patterns = @(
        '@'                                                            # email address or UPN
        '\b\d{1,3}(\.\d{1,3}){3}\b'                                    # IPv4 address
        '\b(?:[0-9a-f]{1,4}:){2,}[0-9a-f]{0,4}'                        # IPv6 address
        '\b[0-9a-f]{1,4}::(?:[0-9a-f]{1,4}\b)?'                        # compressed IPv6 address
        '\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b'              # GUID
        '\b[\w-]+(\.[\w-]+)*\.(?!(?:exe|dll|sys|js)\b)[a-z]{2,}\b'     # domain, host or file name, not a program such as cmd.exe
        '\\|://|(?<!\w)/\w|\b[a-z]:/'                                  # file, UNC or URL path
        '\b\d{6,}\b'                                                   # ticket or record number
        '\b[a-z][a-z0-9]*-(?=[a-z0-9]*\d)[a-z0-9]{5,}\b'               # machine name such as DESKTOP-4F2KQ1, with a digit in the suffix
        $script:EbrTicketPattern                                       # ticket reference in the collector's default shape
    )
    foreach ($p in $patterns) { if ($t -match $p) { return 'Title withheld' } }
    # An all-caps machine name with a digit, such as FILESERVER01, WEB01 or SRV-DC01. Case-sensitive, so ordinary
    # words pass. CVE identifiers and KB numbers are withheld too.
    if ($t -cmatch '\b[A-Z][A-Z0-9-]*\d[A-Z0-9-]*\b') { return 'Title withheld' }
    # The pack's own TicketPattern is RE2, as KQL reads it. One that .NET cannot read throws, and the
    # OUT.4 row's catch withholds the title and adds the review note.
    if (-not [string]::IsNullOrWhiteSpace($TicketPattern) -and $t -match $TicketPattern) { return 'Title withheld' }
    $t
}
function ConvertTo-EbrTactics($Value) {
    $items = if ($Value -is [array]) { $Value } elseif ([string]$Value -match '^\s*\[') {
        # Windows PowerShell 5.1 emits a JSON array as one object. ForEach-Object unrolls it on both editions.
        try { @([string]$Value | ConvertFrom-Json | ForEach-Object { $_ }) } catch { @() }
    } else { [string]$Value -split '[,\s]+' }
    (@($items | ForEach-Object { [string]$_ } | Where-Object { $_ -match '^[A-Za-z]+$' }) -join ',')
}
# The UTC day, as the collector's ConvertTo-EbrUtcDate reads it. A time with no offset is taken as UTC.
function ConvertTo-EbrDay($Value) {
    if ($Value -is [datetimeoffset]) { $Value = $Value.UtcDateTime }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Local) { $Value = $Value.ToUniversalTime() }
        return $Value.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)
    }
    if ([string]$Value -match '^\d{4}-\d{2}-\d{2}') { return $Matches[0] }
    ''
}
# Row-level results that name resources are reduced to counts or screened before embedding.
$aggregates = [ordered]@{
    'NB.1' = { param($rows) $w = @($rows | Where-Object { $_.SubnetClass -eq 'Workload' }); [pscustomobject]@{ WorkloadSubnets = $w.Count; Segmented = @($w | Where-Object { [int]$_.Segmented -eq 1 }).Count } }
    'DP.5b' = { param($rows) [pscustomobject]@{ VmsWithoutBackup = @($rows).Count } }
    # Attack disruption incidents, as a count only. Incident numbers and titles stay in the pack.
    'OUT.7' = { param($rows) [pscustomobject]@{ Incidents = @($rows).Count } }
    'NB.2' = { param($rows) [pscustomobject]@{ Rules = @($rows).Count; NeedsReview = @($rows | Where-Object { [int]$_.RangeNeedsReview -eq 1 }).Count } }
    'IA.6-SUB' = { param($rows) [pscustomobject]@{ Assignments = @($rows).Count; Accounts = @($rows | ForEach-Object { @($_.AccountObjectId, $_.AccountUpn, $_.AccountDisplayName) | Where-Object { $_ } | Select-Object -First 1 } | Sort-Object -Unique).Count } }
    'IA.6' = { param($rows) [pscustomobject]@{
            Standing = @($rows | Where-Object { $_.AssignmentType -eq 'Standing' }).Count
            Eligible = @($rows | Where-Object { $_.AssignmentType -eq 'Eligible' }).Count
            Activated = @($rows | Where-Object { $_.AssignmentType -in 'Activated', 'Time-bound' }).Count
            Accounts = @($rows | Where-Object { $_.AssignmentType -eq 'Standing' } | ForEach-Object { $_.PrincipalId } | Where-Object { $_ } | Sort-Object -Unique).Count
            PimRead = $(if (@($rows).Count -and $rows[0].PSObject.Properties['PimRead']) { [string]$rows[0].PimRead } else { 'Yes' }) } }
    'IA.8' = { param($rows) [pscustomobject]@{
            Policies = @($rows).Count
            Enabled = @($rows | Where-Object { $_.State -eq 'enabled' }).Count
            ReportOnly = @($rows | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' }).Count
            Baseline = @($rows | Where-Object { [string]$_.Baseline -eq 'True' }).Count
            BaselineEnabled = @($rows | Where-Object { [string]$_.Baseline -eq 'True' -and $_.State -eq 'enabled' }).Count } }
    'IA.14' = { param($rows) [pscustomobject]@{ Users = @($rows).Count; SignIns = (@($rows | ForEach-Object { [int]$_.SignIns }) | Measure-Object -Sum).Sum } }
    'DR.11' = { param($rows) [pscustomobject]@{ Sensors = @($rows).Count; Healthy = @($rows | Where-Object { $_.HealthStatus -eq 'healthy' }).Count; UpToDate = @($rows | Where-Object { $_.DeploymentStatus -eq 'upToDate' }).Count } }
    'EW.13' = { param($rows) [pscustomobject]@{ Policies = @($rows).Count; Assigned = @($rows | Where-Object { [string]$_.Assigned -eq 'True' }).Count } }
    'DR.12' = { param($rows) [pscustomobject]@{ Groups = @($rows).Count; Devices = (@($rows | ForEach-Object { [int]$_.Devices }) | Measure-Object -Sum).Sum } }
    'P0.6-APPLIANCES' = { param($rows) [pscustomobject]@{ Appliances = @($rows).Count } }
    # Azure virtual machines not reporting to Defender for Endpoint (collector 1.14.0), counted by reason and
    # product. Eligible says whether the reason keeps the machine in the onboarding denominator, Covered whether
    # it counts as protected. CountedAs splits each reason by how EW.1 counted the machine. Never the names.
    'EW.1-GAPS' = { param($rows) @($rows) | Group-Object { '{0}|{1}' -f (([string]$_.Reason).Trim()), (([string]$_.Product).Trim()) } | Sort-Object Count -Descending | ForEach-Object {
            $first = $_.Group[0]
            [pscustomobject]@{
                Reason = ([string]$first.Reason).Trim(); Product = ([string]$first.Product).Trim(); Devices = $_.Count
                Eligible = ([string]$first.Eligible -eq 'True'); Covered = ([string]$first.Covered -eq 'True')
                Onboarded = @($_.Group | Where-Object { [string]$_.CountedAs -eq 'Onboarded' }).Count
                CanBeOnboarded = @($_.Group | Where-Object { [string]$_.CountedAs -eq 'CanBeOnboarded' }).Count
                NotSeen = @($_.Group | Where-Object { [string]$_.CountedAs -eq 'NotSeen' }).Count
                Other = @($_.Group | Where-Object { [string]$_.CountedAs -eq 'Other' }).Count } } }
    # Azure virtual machine inventory from Resource Graph with its endpoint detection evidence (collector 1.14.0), counts only.
    'EW.1-EDR' = { param($rows) [pscustomobject]@{
            VMs = @($rows).Count
            DefenderExtension = @($rows | Where-Object { [int]$_.DefenderExtension -gt 0 }).Count
            ThirdPartyEdr = @($rows | Where-Object { [string]$_.ThirdPartyEdr -eq 'True' }).Count
            Appliances = @($rows | Where-Object { [string]$_.Appliance -eq 'True' }).Count } }
    # Machines whose tags record patching as waived or client owned (collector 1.14.0), count only.
    'EW.10-EXCLUDED' = { param($rows) [pscustomobject]@{ Machines = @($rows).Count } }
    # Federated domains (collector 1.12.0). The provider name and MFA behavior only, never the domains or URIs.
    'IA.1-FEDERATION' = { param($rows)
        $read = @($rows | Where-Object { [string]$_.ConfigSource -eq 'Read' })
        $distinct = { param($f) (@($read | ForEach-Object { [string]$_.$f } | Where-Object { $_ } | Sort-Object -Unique) -join ', ') }
        [pscustomobject]@{
            FederatedDomains = @($rows).Count; ConfigsRead = $read.Count
            Provider = & $distinct 'IdentityProvider'; MfaBehavior = & $distinct 'FederatedIdpMfaBehavior'
            MfaBehaviorUnset = @($read | Where-Object { -not [string]$_.FederatedIdpMfaBehavior }).Count } }
    # Blob container access levels (collector 1.11.0), one row per storage account. Unlisted accounts are left out of every count.
    'DP.1-CONTAINERS' = { param($rows)
        $read = @($rows | Where-Object { [string]$_.ReadStatus -eq 'OK' })
        $total = { param($f) [int](@($read | ForEach-Object { [int]$_.$f }) | Measure-Object -Sum).Sum }
        [pscustomobject]@{
            Accounts = @($rows).Count; AccountsUnread = @($rows).Count - $read.Count
            Containers = & $total 'Containers'; PrivateContainers = (& $total 'Containers') - (& $total 'PublicContainers')
            ExposedContainers = & $total 'ExposedContainers'; AccountsExposed = @($read | Where-Object { [int]$_.ExposedContainers -gt 0 }).Count } }
    # Confirmed true positives, one row each. Severity, the screened title, tactics and day only, never the comments.
    # A row that cannot be converted is kept with its title withheld, so one bad row never empties OUT.4.
    'OUT.4' = { param($rows)
        $unscreened = $false
        foreach ($r in $rows) {
            try {
                $tactics = ConvertTo-EbrTactics $r.Tactics
                [pscustomobject]@{
                    Severity = $r.Severity
                    Threat = $(if ($tactics) { Get-EbrScreenedTitle ([string]$r.Title) ([string]$parameters.TicketPattern) } else { '' })
                    Tactics = $tactics; Created = ConvertTo-EbrDay $r.CreatedTime }
            }
            catch {
                $unscreened = $true
                [pscustomobject]@{ Severity = $r.Severity; Threat = 'Title withheld'; Tactics = ''; Created = '' }
            }
        }
        if ($unscreened) { $issues.Add('An OUT.4 row could not be screened, so its title was withheld.') } }
    # Alert types by title and month (CyberSOC). A title that names an account, address, host, path or ticket is
    # withheld by the OUT.4 screen, and every withheld title of a month is counted on one row.
    'OUT.9' = { param($rows)
        $screened = foreach ($r in $rows) {
            $t = try { Get-EbrScreenedTitle ([string]$r.Title) ([string]$parameters.TicketPattern) } catch { 'Title withheld' }
            [pscustomobject]@{ Month = ConvertTo-EbrDay $r.Month; Title = $(if ($t) { $t } else { 'Title withheld' }); Alerts = [int]$r.Alerts; High = [int]$r.High; TruePositive = [int]$r.TruePositive; BenignPositive = [int]$r.BenignPositive; FalsePositive = [int]$r.FalsePositive }
        }
        @($screened) | Group-Object Month, Title | ForEach-Object {
            $sumOf = { param($f) [int](@($_.Group | ForEach-Object { $_.$f }) | Measure-Object -Sum).Sum }
            [pscustomobject]@{ Month = $_.Group[0].Month; Title = $_.Group[0].Title; Alerts = & $sumOf 'Alerts'; High = & $sumOf 'High'; TruePositive = & $sumOf 'TruePositive'; BenignPositive = & $sumOf 'BenignPositive'; FalsePositive = & $sumOf 'FalsePositive' }
        } }
    # Malware detected on Azure virtual machines (CyberSOC). Defender's own threat names, which name no client
    # resource, cut to 120 characters. Device names and file paths stay in the pack.
    'TI.7' = { param($rows) foreach ($r in $rows) {
            $t = (([string]$r.Threat) -replace '[\r\n<>]', ' ').Trim()
            if ($t.Length -gt 120) { $t = $t.Substring(0, 120) }
            [pscustomobject]@{ Threat = $(if ($t) { $t } else { 'Not named' }); Detections = [int]$r.Detections; Devices = [int]$r.Devices; Remediated = [int]$r.Remediated; WasExecuting = [int]$r.WasExecuting } } }
}
$results = [ordered]@{}
$issues = [System.Collections.Generic.List[string]]::new()
function Read-ResultRows([string]$id) {
    $file = Join-Path $pack "results/$id.json"
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { return $null }
    # Parenthesised, so Windows PowerShell 5.1 enumerates the array that ConvertFrom-Json returns as one
    # object, as PowerShell 7 does. Without it an empty result still runs its aggregate, which then embeds
    # zero counts where PowerShell 7 embeds none.
    try { return @((Get-Content -LiteralPath $file -Raw | ConvertFrom-Json)) }
    catch { $issues.Add("$id could not be read. Regenerate or recollect this result."); return @() }
}
foreach ($id in $fields.Keys) {
    $raw = Read-ResultRows $id
    $rows = @()
    if ($null -ne $raw) {
        $rows = @(foreach ($row in $raw) {
            if ($null -eq $row) { continue }
            $selected = [ordered]@{}
            foreach ($field in $fields[$id]) {
                if ($null -ne $row.PSObject.Properties[$field]) { $selected[$field] = $row.$field }
            }
            [pscustomobject]$selected
        })
    }
    $results[$id] = $rows
}
foreach ($id in $aggregates.Keys) {
    $raw = Read-ResultRows $id
    $results[$id] = @()
    if ($null -ne $raw) {
        try { $results[$id] = @(& $aggregates[$id] @($raw | Where-Object { $null -ne $_ })) }
        catch { $issues.Add("$id could not be summarized. $($_.Exception.Message)") }
    }
}
# Conditional Access controls: the raw policies (IA.8-POLICIES) and the per-account sign-in detail
# (IA.8-SIGNINS) are evaluated here and only the per-control counts reach the report as IA.8-CA.
. (Join-Path $assets 'Get-EbrCaEvaluation.ps1')
try {
    $ca = Read-EbrCaEvaluation -Pack $pack -Manifest $manifest
    if ($null -ne $ca) { $results['IA.8-CA'] = @($ca.Flows) }
}
catch { $issues.Add("The Conditional Access evaluation could not be completed. $($_.Exception.Message)") }
$context = $null
if ($ContextPath) {
    $context = Get-Content -LiteralPath $ContextPath -Raw | ConvertFrom-Json
    if ($context.ClientName -cne $parameters.ClientName -or $context.TenantId -ne $parameters.TenantId) {
        throw 'The context client and tenant must match the evidence pack.'
    }
    # Allow only the documented editorial inputs. An Impact record from an EBR context file is dropped: the CyberSOC
    # report carries no data exposure or compromise determination.
    $context = $context | Select-Object ClientName, TenantId, ServiceStartDate, TenantScore, Delivered, Actions, OpenAlertNote, ResponseTargetMinutes, MonthHighlights
}
$data = [ordered]@{
    version = '2.0.0'
    depth = $Depth.ToLowerInvariant()
    parameters = $parameters | Select-Object ClientName, ReportType, ReportMonth, TrendMonths, WindowStart, WindowEnd, WindowBasis, RecentStart, PostureReadDate, ManagedRgPattern, TicketPattern, AlertScope, Subscriptions, Workspaces, TenantWideTables, DefenderApi, GraphApi, PatchCadenceDays, PatchExclusionTagPattern, EdrVendorPattern,
        @{ Name = 'VulnAssessmentRuns'; Expression = { @($_.VulnAssessment.Runs | Where-Object { $_ } | ForEach-Object { [ordered]@{ RunDate = [string]$_.RunDate; Status = [string]$_.Status } }) } },
        @{ Name = 'VulnAssessmentSkipped'; Expression = { @($_.VulnAssessment.Skipped | Where-Object { $_ }).Count } }
    # AccessGap marks evidence that the collector's token was not permitted to read, so the deck can ask
    # for read access. Service errors and missing tables are not access gaps. A service that answers that
    # the tenant is not onboarded or not licensed (Defender for Identity returns that as a 403) is not an
    # access gap either: NotOnboarded marks it, so the control reads Not in force instead of asking for
    # read access. Only the flags are embedded.
    manifest = @($manifest | Select-Object ResultId, Status, Rows, ReadTimeUtc,
        @{ Name = 'NotOnboarded'; Expression = { [string]$_.Detail -match '(?i)tenant is not onboarded|not onboarded to|not licensed|after license is purchased' } },
        # NoTable marks an EMPTY result whose table no workspace holds, so the CyberSOC sections read not collected,
        # never a measured zero (a missing Log Analytics table answers EMPTY, see Test-EbrMissingTableError).
        @{ Name = 'NoTable'; Expression = { [string]$_.Status -eq 'EMPTY' -and [string]$_.Detail -match 'No workspace has the table|Failed to resolve table' } },
        @{ Name = 'AccessGap'; Expression = { ([string]$_.Detail -match 'token (lacks|cannot read)|Needs [A-Za-z]+(\.[A-Za-z]+)*\.Read|could not be read|Insufficient privileges|Authorization_RequestDenied|\b403\b') -and -not ([string]$_.Detail -match '(?i)tenant is not onboarded|not onboarded to|not licensed|after license is purchased') } })
    results = $results
    issues = @($issues)
    context = $context
}
# Escape HTML-sensitive characters even inside application/json script elements.
$json = ConvertTo-Json -InputObject $data -Depth 15 -Compress
$json = $json.Replace('&', '\u0026').Replace('<', '\u003c').Replace('>', '\u003e')
$json = $json.Replace([string][char]0x2028, '\u2028').Replace([string][char]0x2029, '\u2029')
$template = Get-Content -LiteralPath (Join-Path $assets 'report.html') -Raw
$css = Get-Content -LiteralPath (Join-Path $assets 'report.css') -Raw
$background = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $assets 'assets/template-background.jpg')))
$css = $css.Replace('__BACKGROUND__', $background)
$model = Get-Content -LiteralPath (Join-Path $assets 'report-model.js') -Raw
$cybersoc = Get-Content -LiteralPath (Join-Path $assets 'cybersoc-model.js') -Raw
$render = Get-Content -LiteralPath (Join-Path $assets 'report-render.js') -Raw
$review = Get-Content -LiteralPath (Join-Path $assets 'report-review.js') -Raw
$controls = Get-Content -LiteralPath (Join-Path $assets 'report-controls.js') -Raw
$template = $template.Replace('__CSS__', $css).Replace('__CONTROLS__', $controls)
if (-not $OutputPath) { $OutputPath = Join-Path $pack '03-security-report.html' }
$destination = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
if ([IO.Path]::GetExtension($destination) -ine '.html') { throw 'OutputPath must end in .html.' }
# OutputPath names the internal edition, so a client-looking name never holds the presenter notes and identifiers.
if ($destination -match '(?i)\.client\.html$') { throw 'OutputPath names the internal edition and cannot end in .client.html. The client edition is written beside it with that ending.' }
$parent = Split-Path -Parent $destination
if (-not (Test-Path -LiteralPath $parent -PathType Container)) { [void](New-Item -ItemType Directory -Path $parent -Force) }

# The internal edition embeds the data, the report model and the renderer, and carries the presenter notes toggle,
# the aside and the script that fills it.
$scripts = "<noscript>This report requires JavaScript to display the embedded evidence. Enable JavaScript and reopen this local file.</noscript>`n" +
    "<script id=""report-data"" type=""application/json"">__DATA__</script>`n<script>$model</script>`n<script>$cybersoc</script>`n<script>$render</script>`n<script>$review</script>"
$html = $template.Replace('__REVIEW_TOGGLE__', '    <button id="review-toggle" aria-expanded="false" aria-controls="review">Presenter notes</button>')
$html = $html.Replace('__REVIEW_ASIDE__', '<aside id="review" hidden aria-label="Presenter notes and evidence review"></aside>').Replace('__REPORT__', '')
$html = $html.Replace('__SCRIPTS__', $scripts).Replace('__DATA__', $json)
[IO.File]::WriteAllText($destination, $html, [Text.UTF8Encoding]::new($false))
Write-Output $destination

# The client edition carries the report pages already rendered, by report/build-client-report.cjs from the same data,
# and the toolbar script only: no embedded data, no report model, so none of the presenter notes, evidence review,
# timing rationale or collection register, and none of the subscription, workspace or other identifiers in the data.
# Every GUID on the rendered pages, such as one inside a default workspace name or a context Reference, becomes the
# same [id N] placeholder wherever it appears. The builder refuses to write a client edition that still holds a GUID
# or presenter material. It needs Node.js, like the PowerPoint edition, and without it only the internal edition is
# written, with a warning.
$guidPattern = '(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
$clientDestination = [IO.Path]::ChangeExtension($destination, '.client.html')
# A client edition from an earlier run is removed first, so a run that cannot write one never leaves a stale file.
if (Test-Path -LiteralPath $clientDestination) { Remove-Item -LiteralPath $clientDestination -Force }
if (-not (Get-Command node -ErrorAction SilentlyContinue)) { Write-Warning 'Node.js was not found, so the client edition of the report was not written. Do not send the internal edition to the client.' }
else {
    $dataFile = Join-Path ([IO.Path]::GetTempPath()) ('ebr-client-{0}.json' -f [guid]::NewGuid())
    $pagesFile = Join-Path ([IO.Path]::GetTempPath()) ('ebr-client-pages-{0}.json' -f [guid]::NewGuid())
    try {
        [IO.File]::WriteAllText($dataFile, $json, [Text.UTF8Encoding]::new($false))
        $built = & node (Join-Path $assets 'build-client-report.cjs') $dataFile $pagesFile 2>&1
        if ($LASTEXITCODE -ne 0) { throw "The client edition of the report was not written. $built" }
        $pages = [IO.File]::ReadAllText($pagesFile, [Text.Encoding]::UTF8) | ConvertFrom-Json
    }
    finally { Remove-Item -LiteralPath $dataFile, $pagesFile -Force -ErrorAction SilentlyContinue }
    $ids = @{}
    $mask = { param($text) [regex]::Replace([string]$text, $guidPattern, { param($match) $k = $match.Value.ToLowerInvariant(); if (-not $ids.ContainsKey($k)) { $ids[$k] = '[id {0}]' -f ($ids.Count + 1) }; $ids[$k] }) }
    $title = [Net.WebUtility]::HtmlEncode((& $mask $pages.title))
    $clientHtml = $template -replace '(?m)^__REVIEW_(TOGGLE|ASIDE)__\r?\n', ''
    $clientHtml = $clientHtml.Replace('<title>CyberSOC monthly security report</title>', "<title>$title</title>").Replace("<option value=""$($Depth.ToLowerInvariant())"">", "<option value=""$($Depth.ToLowerInvariant())"" selected>")
    $clientHtml = $clientHtml -replace '(?m)^__SCRIPTS__\r?\n', ''
    $clientHtml = $clientHtml.Replace('__REPORT__', (& $mask $pages.html))
    if ($clientHtml -cmatch 'Presenter notes|review-toggle|report-data|EbrReport|__[A-Z_]+__' -or $clientHtml -match $guidPattern) { throw 'The client edition of the report still carries presenter material, report data or a GUID, so it was not written.' }
    [IO.File]::WriteAllText($clientDestination, $clientHtml, [Text.UTF8Encoding]::new($false))
    Write-Output $clientDestination
}

# PowerPoint edition. The deck builder reads the same aggregate data the HTML embeds, so it sees
# nothing the HTML does not. A missing Node.js or pptxgenjs leaves the HTML in place with a warning.
if (-not $SkipDeck) {
    $deck = [IO.Path]::ChangeExtension($destination, '.pptx')
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) { Write-Warning 'Node.js was not found, so the PowerPoint edition of the report was not written.' }
    else {
        $dataFile = Join-Path ([IO.Path]::GetTempPath()) ('ebr-report-{0}.json' -f [guid]::NewGuid())
        try {
            [IO.File]::WriteAllText($dataFile, $json, [Text.UTF8Encoding]::new($false))
            $built = & node (Join-Path $assets 'build-report-deck.cjs') $dataFile $deck 2>&1
            if ($LASTEXITCODE -ne 0) { Write-Warning "The PowerPoint edition of the report was not written. $built" } else { Write-Output $deck }
        }
        finally { Remove-Item -LiteralPath $dataFile -Force -ErrorAction SilentlyContinue }
    }
}
