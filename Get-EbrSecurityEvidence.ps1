<#
.SYNOPSIS
    Runs every query in the EBR Security Evidence Collection Runbook for one client and
    writes a traceable evidence pack.

.DESCRIPTION
    READ-ONLY SCRIPT - NO MODIFICATIONS

    Give it the client's tenant and subscription IDs. It then:
      1. Signs in with the Azure CLI and refuses any subscription that is not homed in the
         client tenant, so one client's figures never absorb another's (Lighthouse warning).
      2. Finds every Sentinel workspace in the client subscriptions. Workspace-level queries run
       once across all of them (correct client-level medians and distinct counts) and once per
       workspace (the <ID>-BY-WORKSPACE breakdown). Tenant-wide tables (SigninLogs, AuditLogs)
       are read from one workspace so copies are never double counted.
      3. Runs Phase 0 to Phase 4 of the runbook across Azure Resource Graph, Log Analytics,
         Defender Advanced Hunting, the Sentinel ARM API, Exchange Online and Purview.
      4. Writes one CSV and one JSON file per query ID, the exact KQL that ran, a manifest,
         the runbook slide-map worksheet with every derivable value filled in, and
         copy-ready notes.

    Microsoft Graph is read with GET requests only, on the instruction of Oct 11, 2026, for the
    measures that have no other source: IA.1-FEDERATION, IA.5, IA.6, IA.8, IA.11, IA.13, POS.6,
    DP.8, DP.10, DR.11 and EW.13. The Graph token comes from the Azure CLI exactly as the Defender token
    does (az account get-access-token --resource https://graph.microsoft.com/). An endpoint the
    token cannot read makes that measure UNAVAILABLE with the permission it needs, never a zero,
    and the non-Graph substitute still runs. ATMOSERA_SCRIPT_REQUIREMENTS.md 1.4 still forbids
    Graph; that standard has not been updated and -SkipGraph restores the old behaviour.

    API calls made, all read-only:
      - az account list, az account get-access-token, az login (local sign-in only)
      - GET  https://login.microsoftonline.com/<domain>/v2.0/.well-known/openid-configuration
      - GET  https://management.azure.com/tenants
      - POST https://management.azure.com/providers/Microsoft.ResourceGraph/resources (query)
      - POST https://api.loganalytics.io/v1/workspaces/<id>/query (query, optionally with a
        list of additional workspaces for one combined query)
      - POST https://api.security.microsoft.com/api/advancedqueries/run (query)
      - GET  https://api.security.microsoft.com/api/configurationScore and /api/exposureScore
      - GET  <workspace>/providers/Microsoft.SecurityInsights/alertRules
      - GET  <storage account>/blobServices/default/containers (container access levels, DP.1-CONTAINERS)
      - GET  https://graph.microsoft.com/v1.0/organization, domains,
        domains/<id>/federationConfiguration, reports/authenticationMethods/
        userRegistrationDetails, roleManagement/directory/roleAssignments and
        roleEligibilityScheduleInstances, identity/conditionalAccess/policies,
        directory/onPremisesSynchronization, policies/authorizationPolicy,
        policies/adminConsentRequestPolicy, security/secureScores,
        security/secureScoreControlProfiles, admin/sharepoint/settings,
        security/identities/sensors, deviceManagement/managedDevices,
        deviceManagement/configurationPolicies
      - Exchange Online and Purview: Get-AntiPhishPolicy, Get-AntiPhishRule,
        Get-ATPProtectionPolicyRule, Get-SafeLinksPolicy, Get-SafeAttachmentPolicy,
        Get-MalwareFilterPolicy, Get-HostedContentFilterPolicy, Get-DlpCompliancePolicy
    Assert-EbrReadOnlyRequest blocks any REST call that is not a GET or a POST to one of the
    three query endpoints above.

    Why PowerShell and not Python (requirements 6.2): IA.9 and DP.6 need the
    ExchangeOnlineManagement cmdlets, which only exist in PowerShell, and the runbook's own
    non-KQL evidence blocks are PowerShell.

.PARAMETER TenantId
    Client tenant ID (GUID) or any verified domain. Prompted for when omitted.

.PARAMETER SubscriptionId
    Client subscription IDs in scope. Comma, semicolon or space separated. Prompted for
    when omitted.

.PARAMETER WorkspaceResourceId
    Sentinel workspace resource IDs to use. By default every Sentinel workspace in the client
    subscriptions is used.

.PARAMETER SkipWorkspaceBreakdown
    Skip the per-workspace run of each workspace-level query (the <ID>-BY-WORKSPACE files).
    Combined client figures are still produced.

.PARAMETER WindowStart
    Incident reporting window start, yyyy-MM-dd. Defaults to the first full month of
    SecurityIncident data (maximum reach).

.PARAMETER WindowEnd
    Incident reporting window end, yyyy-MM-dd. Defaults to the last day of the last full month.

.PARAMETER ManagedRgPattern
    Managed resource group pattern. Default aznativesol0, the same on every client subscription.
    Every resource that belongs to it is excluded from evaluation: ARG queries drop resources whose
    id contains it, and for records that describe another resource (backup items, assessments,
    policy states, Defender for Cloud alerts, Defender devices in Advanced Hunting, recommendation
    snapshots in Log Analytics) the described resource's id is tested instead. Subscription-level
    results (P0.3, POS.1, POS.3, POS.5, POS.7) carry no exclusion because the resource is the
    subscription itself, and P0.2 deliberately lists every workspace. Pass an empty string to
    remove the exclusion.

.PARAMETER TicketPattern
    Regular expression (RE2, as used by KQL) that identifies an Atmosera ticket reference in a
    Sentinel incident's comments or closing comment. Only incidents that match are counted as
    alerts in OUT.1 to OUT.7. Default matches Zendesk ticket URLs and "ZD ticket NNNN" text.
    Must not contain double quotes or line breaks.

.PARAMETER ClientName
    Name used in the output folder. Defaults to the tenant display name.

.PARAMETER OutputPath
    Folder that receives the evidence pack folder. Defaults to the current folder.

.PARAMETER SkipExchange
    Skip the Exchange Online and Purview sign-in (IA.9, DP.6).

.PARAMETER SkipDefender
    Skip the Defender API. Advanced Hunting queries then run against the Sentinel workspace only.

.PARAMETER SkipGraph
    Skip Microsoft Graph. The Graph measures are then marked UNAVAILABLE with their portal path
    and only their substitutes run.

.PARAMETER PatchCadenceDays
    Agreed patch cadence in days for EW.10. A machine is within cadence when it has no pending
    security or critical patch published more than this many days ago. Default 30.

.PARAMETER PatchExclusionTagPattern
    Regular expression (RE2, as used by KQL) matched against the lowercased JSON of each machine's
    tags. A machine whose tags match is left out of the patch measures (EW.6, EW.10) and listed in
    EW.10-EXCLUDED. The default matches a tag that records patching as waived or as client owned,
    under whichever key the client uses, for example Patching=Waived, PatchPolicy=Client Owned or
    Maintenance=Patching waived. Must not contain line breaks. Pass an empty string to turn the
    exclusion off.

.PARAMETER EdrVendorPattern
    Regular expression (RE2) naming the third-party endpoint detection products in use, matched
    against virtual machine extension publishers and types and against the Sentinel tables and
    vendors that carry the product's telemetry (EW.1-EDR, EW.1-EDR-HOSTS). An Azure virtual
    machine that is not onboarded to Defender for Endpoint but carries a matching product is
    reported as covered by that product, not as a gap. The default covers CrowdStrike Falcon and
    the other common products. Must not contain double quotes or line breaks.

.PARAMETER DryRun
    Expand and write every query without signing in or calling anything.

.PARAMETER SkipHtmlReport
    Skip the offline executive HTML report and its PowerPoint edition. By default both are
    generated after collection (the deck needs Node.js and pptxgenjs, and is skipped with a
    warning without them).

.PARAMETER ReportDepth
    Initial report depth: Brief, Balanced or Detailed. Readers can change depth in the HTML.

.PARAMETER SkipSecOpsWorklist
    Skip the internal SecOps worklist (04-secops-worklist.md and .csv). By default it is written
    after collection by New-EbrSecOpsWorklist.ps1. It names incidents, devices and resources and
    is never part of the client report.

.PARAMETER LoadFunctionsOnly
    Load the functions and stop. Used by the Pester tests.

.EXAMPLE
    ./Get-EbrSecurityEvidence.ps1
    Prompts for the tenant and subscriptions, then collects everything.

.EXAMPLE
    ./Get-EbrSecurityEvidence.ps1 -TenantId contoso.onmicrosoft.com -SubscriptionId a0c307ad-f1c3-4a7d-96c3-10a6eb7c9c62

.EXAMPLE
    ./Get-EbrSecurityEvidence.ps1 -TenantId <guid> -SubscriptionId <sub1>,<sub2> -WindowStart 2026-01-01 -WindowEnd 2026-07-31

.EXAMPLE
    ./Get-EbrSecurityEvidence.ps1 -TenantId <guid> -SubscriptionId <sub1> -DryRun
    Writes every expanded query to disk so you can paste them by hand. No sign-in.

.NOTES
    Author: Atmosera Automation
    Created: 2026-10-07
    Version: 1.14.0
    Read-Only: YES
    Requires: Azure CLI 2.50+, PowerShell 5.1 or 7.x (7.x recommended for large result sets),
              ExchangeOnlineManagement (auto-installed unless -SkipExchange).
    Exit codes: 0 everything collected, 2 finished with one or more FAILED, PARTIAL or UNAVAILABLE result sets,
    1 fatal error.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$TenantId,
    [string[]]$SubscriptionId,
    [string[]]$WorkspaceResourceId,
    [string]$WindowStart,
    [string]$WindowEnd,
    [AllowEmptyString()]
    [string]$ManagedRgPattern = 'aznativesol0',
    [string]$TicketPattern,
    [string]$ClientName,
    [string]$OutputPath = (Get-Location).Path,
    [switch]$SkipExchange,
    [switch]$SkipDefender,
    [switch]$SkipGraph,
    [ValidateRange(1, 365)]
    [int]$PatchCadenceDays = 30,
    [AllowEmptyString()]
    [string]$PatchExclusionTagPattern,
    [string]$EdrVendorPattern,
    [switch]$SkipWorkspaceBreakdown,
    [switch]$SkipHtmlReport,
    [ValidateSet('Brief', 'Balanced', 'Detailed')]
    [string]$ReportDepth = 'Balanced',
    [switch]$SkipSecOpsWorklist,
    [switch]$DryRun,
    [switch]$LoadFunctionsOnly
)

$script:EbrVersion = '1.14.0'
# Atmosera ticket reference in a Sentinel incident comment or closing comment. Incidents without
# one never reached the managed service and are not counted as alerts. The optional subdomain keeps
# the full host in the extracted reference (atmosera.zendesk.com, not zendesk.com).
$script:EbrTicketPattern = '(?i)(([a-z0-9-]+\.)?zendesk\.com/agent/tickets/\d+|\bZD\s*(ticket|#)?\s*#?\s*\d{4,})'
# Network devices and firewalls that Defender for Endpoint discovers on the network (Palo Alto, Meraki,
# Fortinet, SonicWall and similar). They cannot run a sensor, so EW.1 and EW.1-DEVICES leave them out
# (1.11.0). Matched against the device vendor, model and operating system in DeviceInfo.
$script:EbrNetworkDevicePattern = 'palo ?alto|pan-?os|meraki|fortinet|forti(gate|os)|sonicwall|sonicos|watchguard|check ?point|gaia|barracuda'
# Marketplace image publishers of network virtual appliances (firewalls, routers, SD-WAN). Their
# vendor images cannot take Trusted Launch, host or guest disk encryption, Azure Backup, guest
# agents or endpoint detection, so they leave those VM measures. Matched against the plan
# publisher and the image reference publisher. P0.6-APPLIANCES lists every machine it removes.
$script:EbrAppliancePattern = 'paloalto|fortinet|checkpoint|barracuda|cisco|sophos|f5-networks|netgate|juniper|citrix|versa-networks|silver-peak|silverpeak|aviatrix|watchguard|forcepoint|kemptech|a10networks|arista|zscaler|cloudflare|vyos|mikrotik|opnsense|riverbed|catonetworks|cradlepoint'
# Tags that take a machine out of the patch cadence measures (EW.6, EW.10): patching recorded as
# waived, or as owned by the client, under whichever tag key the client uses (1.14.0). Matched
# against the lowercased JSON of the machine's tags, so the key and the value are both tested.
# EW.10-EXCLUDED lists every machine it removes. -PatchExclusionTagPattern overrides it.
$script:EbrPatchExclusionTagPattern = '"[^"]*patch[^"]*"\s*:\s*"[^"]*(waiv|client[ _-]?owned|customer[ _-]?owned)[^"]*"|"[^"]*(waiv|client[ _-]?owned|customer[ _-]?owned)[^"]*patch[^"]*"|"[^"]*patch[^"]*(waiv|client[ _-]?owned|customer[ _-]?owned)[^"]*"'
# Third-party endpoint detection products (1.14.0). An Azure virtual machine that is not onboarded
# to Defender for Endpoint but runs one of these is covered, not a gap. Matched against virtual
# machine extension publishers and types (EW.1-EDR) and against the Sentinel tables and vendors
# that carry the product's telemetry (EW.1-EDR-HOSTS). -EdrVendorPattern overrides it.
$script:EbrEdrVendorPattern = 'crowdstrike|falcon|sentinelone|carbon ?black|cortex ?xdr|cybereason|tanium|trellix|cylance'

#region Console, snark and logging

# Symbols built from code points so the file stays pure ASCII. Windows PowerShell 5.1 reads
# BOM-less files as ANSI and would otherwise turn every check mark into modern art.
$script:EbrSym = @{
    Ok     = [string][char]0x2713
    Fail   = [string][char]0x2717
    Warn   = [string][char]0x26A0
    Step   = [string][char]0x25B6
    Dot    = [string][char]0x2022
    Light  = ([string][char]0x2500) * 64
    Heavy  = ([string][char]0x2550) * 64
    Branch = [string][char]0x2514 + [string][char]0x2500 + [string][char]0x2500
}

$script:EbrSnark = @{
    Step  = @(
        "Alright, let's do this...",
        'Here we go again...',
        'Oh joy, another step...',
        'Brace yourself...',
        'Watch and learn...',
        'Fetching data. Perfect time for coffee.'
    )
    Ok    = @(
        'Nailed it. Obviously.',
        'Success! Try to contain your amazement.',
        "Done. You're welcome.",
        'Completed without incident. Mark your calendars.',
        'That was suspiciously painless.'
    )
    Fail  = @(
        "Well, that didn't work. Surprise!",
        'Failed. But you expected that, right?',
        'API returned an error. Microsoft being Microsoft.',
        "Oops. It's in the manifest now, so it's officially someone's problem."
    )
    Empty = @(
        'Zero rows. Either the estate is perfect or the table is empty. Place your bets.',
        'Nothing came back. Very zen.',
        'An empty result. Still evidence. Technically.'
    )
}

function Get-EbrSnark {
    param([string]$Kind)
    $script:EbrSnark[$Kind] | Get-Random
}

function Write-EbrQuip {
    param([string]$Text)
    Write-Host ('      {0} {1}' -f $script:EbrSym.Branch, $Text) -ForegroundColor DarkGray
}

function Write-EbrInfo {
    param([string]$Message)
    Write-Host "  $Message" -ForegroundColor Gray
    Write-EbrLog -Level INFO -Component Console -Message $Message
}

function Write-EbrOk {
    param([string]$Message, [switch]$Snark)
    Write-Host ('  [{0}] {1}' -f $script:EbrSym.Ok, $Message) -ForegroundColor Green
    if ($Snark) { Write-EbrQuip (Get-EbrSnark Ok) }
    Write-EbrLog -Level INFO -Component Console -Message $Message
}

function Write-EbrWarn {
    param([string]$Message)
    Write-Host ('  [{0}] {1}' -f $script:EbrSym.Warn, $Message) -ForegroundColor Yellow
    Write-EbrLog -Level WARNING -Component Console -Message $Message
}

function Write-EbrFail {
    param([string]$Message)
    Write-Host ('  [{0}] {1}' -f $script:EbrSym.Fail, $Message) -ForegroundColor Red
    Write-EbrQuip (Get-EbrSnark Fail)
    Write-EbrLog -Level ERROR -Component Console -Message $Message
}

function Write-EbrStep {
    param([int]$Number, [int]$Total, [string]$Title)
    Write-Host ''
    Write-Host $script:EbrSym.Light -ForegroundColor Cyan
    Write-Host ('[{0}] Step {1}/{2}: {3}' -f (Get-Date -Format 'HH:mm:ss'), $Number, $Total, $Title) -ForegroundColor Cyan
    Write-EbrQuip $script:EbrSnark.Step[$Number % $script:EbrSnark.Step.Count]
    Write-EbrLog -Level INFO -Component Step -Message ('Step {0}/{1}: {2}' -f $Number, $Total, $Title)
}

$script:EbrLogBuffer = [System.Collections.Generic.List[string]]::new()
$script:EbrLogPath = $null

function Write-EbrLog {
    param(
        [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')][string]$Level = 'INFO',
        [string]$Component = 'General',
        [string]$Message
    )
    # Format from requirements 8.2. Tokens never come through here. Ever.
    $line = '{0} {1} {2} - {3}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss', [cultureinfo]::InvariantCulture), $Level, $Component, $Message
    if ($script:EbrLogPath) {
        Add-Content -LiteralPath $script:EbrLogPath -Value $line -Encoding UTF8
    }
    else {
        $script:EbrLogBuffer.Add($line)
    }
    Write-Verbose $line
}

function Set-EbrLogPath {
    param([string]$Path)
    $script:EbrLogPath = $Path
    if ($script:EbrLogBuffer.Count -gt 0) {
        Add-Content -LiteralPath $Path -Value $script:EbrLogBuffer.ToArray() -Encoding UTF8
        $script:EbrLogBuffer.Clear()
    }
}

#endregion

#region Pure helpers

function Test-EbrGuid {
    param([string]$Value)
    $Value -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
}

function Test-EbrTenantInput {
    param([string]$Value)
    (Test-EbrGuid $Value) -or ($Value -match '^(?=.{4,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$')
}

function Split-EbrSubscriptionInput {
    param([string[]]$Value)
    $ids = [System.Collections.Generic.List[string]]::new()
    foreach ($chunk in $Value) {
        foreach ($part in ([string]$chunk -split '[,;\s]+')) {
            $p = $part.Trim().ToLowerInvariant()
            if ($p) { $ids.Add($p) }
        }
    }
    $bad = @($ids | Where-Object { -not (Test-EbrGuid $_) })
    if ($bad.Count -gt 0) { throw "Not a subscription ID: $($bad -join ', ')" }
    if ($ids.Count -eq 0) { throw 'No subscription IDs supplied.' }
    $seen = @{}
    $unique = foreach ($id in $ids) { if (-not $seen.ContainsKey($id)) { $seen[$id] = $true; $id } }
    , @($unique)
}

function ConvertTo-EbrSafeFileName {
    param([string]$Value)
    $s = ($Value -replace '[^A-Za-z0-9_-]+', '-') -replace '-{2,}', '-'
    $s = $s.Trim('-')
    if ($s.Length -gt 60) { $s = $s.Substring(0, 60).Trim('-') }
    if (-not $s) { $s = 'client' }
    $s
}

function ConvertTo-EbrDate {
    param([string]$Value)
    $out = [datetime]::MinValue
    $ok = [datetime]::TryParseExact($Value, 'yyyy-MM-dd', [cultureinfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::None, [ref]$out)
    if (-not $ok) { throw "Date '$Value' is not in yyyy-MM-dd format." }
    $out
}

function ConvertTo-EbrUtcDate {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Local) { return $Value.ToUniversalTime() }
        return $Value
    }
    [datetime]::Parse([string]$Value, [cultureinfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal')
}

function Format-EbrUtc {
    param($Value)
    $u = ConvertTo-EbrUtcDate $Value
    if ($null -eq $u) { return $null }
    $fmt = if ($u.Millisecond -ne 0) { "yyyy-MM-dd'T'HH:mm:ss.fff'Z'" } else { "yyyy-MM-dd'T'HH:mm:ss'Z'" }
    $u.ToString($fmt, [cultureinfo]::InvariantCulture)
}

function Get-EbrDefaultReportingWindow {
    param(
        [Nullable[datetime]]$EarliestIncident,
        [Nullable[int]]$RetentionDays,
        [datetime]$Now = (Get-Date).ToUniversalTime()
    )
    $thisMonth = [datetime]::new($Now.Year, $Now.Month, 1)
    $end = $thisMonth.AddDays(-1)
    $lastFullMonthStart = [datetime]::new($end.Year, $end.Month, 1)

    # First month that the data covers from day one, so OUT.3 only compares full months
    $firstFull = {
        param([datetime]$d)
        $monthStart = [datetime]::new($d.Year, $d.Month, 1)
        if ($d -eq $monthStart) { $monthStart } else { $monthStart.AddMonths(1) }
    }

    $source = $null
    if ($EarliestIncident) {
        $source = [datetime]$EarliestIncident
        $start = & $firstFull $source
        $basis = 'first full month of SecurityIncident data (earliest record {0})' -f $source.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)
    }
    elseif ($RetentionDays) {
        $source = $Now.AddDays(-[int]$RetentionDays)
        $start = & $firstFull $source
        $basis = 'first full month inside the {0}-day workspace retention (no SecurityIncident data found)' -f [int]$RetentionDays
    }
    else {
        $start = $lastFullMonthStart.AddMonths(-5)
        $basis = 'default of six full months (no incident data or retention reading)'
    }

    if ($start -gt $end) {
        # Data begins after the last full month started, so the only option is a partial month
        $start = [datetime]::new($source.Year, $source.Month, 1)
        if ($start -gt $end) { $start = $lastFullMonthStart }
        $basis += ', partial first month because the data starts after the last full month began'
    }

    [pscustomobject]@{ Start = $start; End = $end; Basis = $basis }
}

function Test-EbrSubscriptionTenant {
    param($Account, [string]$TenantGuid)
    $homeTenant = $null
    $prop = $Account.PSObject.Properties['homeTenantId']
    if ($prop -and $prop.Value) { $homeTenant = [string]$prop.Value } else { $homeTenant = [string]$Account.tenantId }
    [string]::Equals($homeTenant, $TenantGuid, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-EbrJwtClaims {
    param([string]$Token)
    $parts = $Token.Split('.')
    if ($parts.Count -lt 2) { throw 'Not a JWT.' }
    $p = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } }
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json
}

function Test-EbrExternalUser {
    param($Claims, [string]$TenantGuid)
    # An idp claim that is not the client tenant means GDAP, B2B guest or MSA: use DelegatedOrganization
    $idp = $Claims.PSObject.Properties['idp']
    if (-not $idp -or -not $idp.Value) { return $false }
    -not ([string]$idp.Value -match [regex]::Escape($TenantGuid))
}

function Assert-EbrReadOnlyRequest {
    param([string]$Method, [string]$Uri)
    # The only POSTs allowed are the three query endpoints. Queries read. Everything else is a no.
    $allowedPost = @(
        '^https://management\.azure\.com/providers/Microsoft\.ResourceGraph/resources\?api-version=[0-9A-Za-z.-]+$',
        '^https://api\.loganalytics\.io/v1/workspaces/[0-9A-Fa-f-]+/query$',
        '^https://api\.security\.microsoft\.com/api/advancedqueries/run$'
    )
    $m = ([string]$Method).ToUpperInvariant()
    if ($m -eq 'GET') { return }
    if ($m -eq 'POST') {
        foreach ($pattern in $allowedPost) { if ($Uri -match $pattern) { return } }
    }
    throw "READ-ONLY GUARD: blocked $m $Uri. This script only reads. Whoever taught it to write: no."
}

function ConvertTo-EbrRow {
    param($InputObject)
    $o = [ordered]@{}
    foreach ($p in $InputObject.PSObject.Properties) {
        $v = $p.Value
        if ($v -is [datetime] -or $v -is [datetimeoffset]) { $v = Format-EbrUtc $v }
        $o[$p.Name] = $v
    }
    [pscustomobject]$o
}

function ConvertTo-EbrCsvRow {
    param($InputObject)
    $o = [ordered]@{}
    foreach ($p in $InputObject.PSObject.Properties) {
        $v = $p.Value
        if ($null -eq $v) { $o[$p.Name] = '' }
        elseif ($v -is [double] -or $v -is [single]) {
            # 15 significant digits: 130.36, not 130.35999999999999. Invariant, so never 130,36.
            $o[$p.Name] = ([double]$v).ToString('G15', [cultureinfo]::InvariantCulture)
        }
        elseif ($v -is [decimal]) { $o[$p.Name] = $v.ToString([cultureinfo]::InvariantCulture) }
        elseif ($v -is [string] -or $v -is [ValueType]) {
            if ($v -is [datetime] -or $v -is [datetimeoffset]) { $o[$p.Name] = Format-EbrUtc $v } else { $o[$p.Name] = $v }
        }
        else { $o[$p.Name] = ConvertTo-Json -InputObject $v -Compress -Depth 20 }
    }
    [pscustomobject]$o
}

function ConvertFrom-EbrLaResponse {
    param($Response)
    $tables = $Response.tables
    if ($null -eq $tables -or @($tables).Count -eq 0) {
        return [pscustomobject]@{ Columns = @(); Rows = @() }
    }
    $t = @($tables)[0]
    $cols = @(foreach ($c in @($t.columns)) { [string]$c.name })
    $rows = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $t.rows) {
        foreach ($r in @($t.rows)) {
            $o = [ordered]@{}
            for ($i = 0; $i -lt $cols.Count; $i++) {
                $v = $r[$i]
                if ($v -is [datetime] -or $v -is [datetimeoffset]) { $v = Format-EbrUtc $v }
                $o[$cols[$i]] = $v
            }
            $rows.Add([pscustomobject]$o)
        }
    }
    [pscustomobject]@{ Columns = $cols; Rows = $rows.ToArray() }
}

function ConvertFrom-EbrAhResponse {
    param($Response)
    $cols = @()
    if ($null -ne $Response.Schema) { $cols = @(foreach ($c in @($Response.Schema)) { [string]$c.Name }) }
    $rows = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $Response.Results) {
        foreach ($r in @($Response.Results)) { if ($null -ne $r) { $rows.Add((ConvertTo-EbrRow $r)) } }
    }
    [pscustomobject]@{ Columns = $cols; Rows = $rows.ToArray() }
}

function Get-EbrProp {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { $p.Value } else { $null }
}

function Test-EbrTrue {
    param($Value)
    [string]$Value -in 'true', '1'
}

function Add-EbrWorkspaceColumns {
    param($Rows, $Workspace)
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $o = [ordered]@{ Workspace = [string]$Workspace.WorkspaceName; WorkspaceId = [string]$Workspace.CustomerId; SubscriptionId = [string]$Workspace.subscriptionId }
        foreach ($p in $r.PSObject.Properties) { if (-not $o.Contains($p.Name)) { $o[$p.Name] = $p.Value } }
        $out.Add([pscustomobject]$o)
    }
    , $out.ToArray()
}

function Select-EbrTenantWorkspace {
    param([object[]]$Workspaces, $ReachRows, [string]$Table)
    # Every copy of a tenant-wide table holds the same sign-ins, so read the fullest copy once
    $best = $null
    $bestCount = -1.0
    foreach ($r in @($ReachRows)) {
        if ($null -eq $r -or [string](Get-EbrProp $r 'SourceTable') -ne $Table) { continue }
        $n = [double](Get-EbrProp $r 'Records')
        if ($n -le $bestCount) { continue }
        $ws = @($Workspaces) | Where-Object { [string]$_.CustomerId -eq [string](Get-EbrProp $r 'WorkspaceId') } | Select-Object -First 1
        if ($ws) { $best = $ws; $bestCount = $n }
    }
    if ($best) { return $best }
    @($Workspaces)[0]
}

function Get-EbrEarliestIncident {
    param($ReachRows)
    $per = [System.Collections.Generic.List[string]]::new()
    $earliest = $null
    $earliestWs = $null
    $rows = @($ReachRows) | Where-Object { $null -ne $_ -and [string](Get-EbrProp $_ 'SourceTable') -eq 'SecurityIncident' } |
        Sort-Object { ConvertTo-EbrUtcDate (Get-EbrProp $_ 'EarliestRecord') }
    foreach ($r in @($rows)) {
        $d = ConvertTo-EbrUtcDate (Get-EbrProp $r 'EarliestRecord')
        if ($null -eq $d) { continue }
        if ($null -eq $earliest -or $d -lt $earliest) { $earliest = $d }
        $name = Get-EbrProp $r 'Workspace'
        if ($name) { $per.Add(('{0} {1}' -f $name, $d.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture))) }
        if ($d -eq $earliest) { $earliestWs = [string](Get-EbrProp $r 'WorkspaceId') }
    }
    [pscustomobject]@{ Earliest = $earliest; EarliestWorkspaceId = $earliestWs; PerWorkspace = $per.ToArray() }
}

function Test-EbrRetentionBound {
    param($Earliest, [int]$RetentionDays, $Now = (Get-Date).ToUniversalTime())
    # Data that starts within two days of the retention cutoff was purged, not born, on that date
    if ($null -eq $Earliest -or $RetentionDays -le 0) { return $false }
    $cutoff = (ConvertTo-EbrUtcDate $Now).AddDays(-$RetentionDays)
    ((ConvertTo-EbrUtcDate $Earliest) - $cutoff).TotalDays -lt 2
}

function Get-EbrAhTableNames {
    # Every Advanced Hunting table the catalog reads. The KB tables exist only in Advanced Hunting.
    'DeviceInfo', 'DeviceEvents', 'DeviceTvmSecureConfigurationAssessment', 'DeviceTvmSecureConfigurationAssessmentKB',
    'DeviceTvmSoftwareInventory', 'DeviceTvmSoftwareVulnerabilities', 'DeviceTvmSoftwareVulnerabilitiesKB',
    'EmailPostDeliveryEvents', 'IdentityLogonEvents', 'IdentityInfo'
}

function Get-EbrXdrOnlyTableNames {
    # Defender for Office 365 and Defender for Identity tables. The Defender for Endpoint hunting API
    # (the one Azure CLI tokens work with) never resolves these; the Defender XDR hunting API that
    # does resolve them rejects Azure CLI tokens. Tested 2026-10-08.
    'IdentityInfo', 'IdentityLogonEvents', 'EmailPostDeliveryEvents'
}

function Get-EbrAhTables {
    param([string]$Query)
    # Whole-word match, so DeviceId and DeviceName do not count as tables
    Get-EbrAhTableNames | Where-Object { $Query -match ('\b' + $_ + '\b') }
}

function New-EbrTableProbeQuery {
    param([string[]]$Tables)
    $legs = foreach ($t in $Tables) { '    ({0} | where TimeGenerated > ago(30d) | take 1 | project SourceTable = "{0}")' -f $t }
    # The print leg keeps the union valid when every table is missing
    $legs = @($legs) + @('    (print SourceTable = "" | where false)')
    "union isfuzzy = true`n" + ($legs -join ",`n") + "`n| distinct SourceTable"
}

function Test-EbrReauthError {
    param([string]$Message)
    # MFA expired or required, or the refresh token aged out: one interactive sign-in fixes these
    $Message -match 'AADSTS(50078|50076|50079|50072|50074|50173|50133|700082|70043|70044)\b|interaction_required'
}

function Get-EbrCaBlockAdvice {
    param([string]$Message)
    # Conditional Access blocks that no amount of signing in again will fix
    if ($Message -match 'AADSTS530004\b') {
        return "The client requires a compliant device for this API but does not trust device compliance from your home organization, so no sign-in can satisfy it. A client admin can fix it in Entra admin center > External Identities > Cross-tenant access settings > (your organization, or Default settings) > Inbound access > Trust settings > Trust compliant devices. Your device must then be compliant in Atmosera's Intune. Or the client excludes your access from that policy for the Defender API."
    }
    if ($Message -match 'AADSTS(53000|53001|530002|530003)\b') {
        return "The client requires a compliant or managed device for this API and yours did not qualify. Sign in from a device that is compliant in Atmosera's Intune, with a browser that passes device state (Edge, or Chrome with the Microsoft Single Sign On extension and Company Portal installed). The client must also trust compliant devices in its cross-tenant access settings."
    }
    if ($Message -match 'AADSTS53003\b') {
        return 'A Conditional Access policy in the client tenant blocked the sign-in (for example by location, platform or app). Ask the client to check the Entra sign-in log for your account to find the policy, then exclude your access from it or adjust it.'
    }
    $null
}

function Get-EbrAzErrorSummary {
    param([string]$Text)
    $m = [regex]::Match($Text, 'AADSTS\d+:.*?\.(?=\s|$)')
    if ($m.Success) { return $m.Value }
    $t = ($Text -replace '\s+', ' ').Trim()
    if ($t.Length -gt 300) { $t = $t.Substring(0, 297) + '...' }
    $t
}

function Get-EbrClientName {
    param([string]$Override, $TenantInfo, $Accounts, [string]$TenantGuid, [string]$TenantInput, [string]$OrgName)
    if ($Override) { return $Override }
    if ($TenantInfo -and (Get-EbrProp $TenantInfo 'DisplayName')) { return [string]$TenantInfo.DisplayName }
    # Lighthouse lists subscriptions under the managing tenant, so only a direct entry knows the client's name
    $direct = @($Accounts) | Where-Object { $_ -and [string]$_.tenantId -eq $TenantGuid -and (Get-EbrProp $_ 'tenantDisplayName') } | Select-Object -First 1
    if ($direct) { return [string]$direct.tenantDisplayName }
    # Exchange knows the organization's own display name, even when you came in with a GUID
    if ($OrgName) { return $OrgName }
    if ($TenantInput -and -not (Test-EbrGuid $TenantInput)) { return $TenantInput.ToLowerInvariant() }
    if ($TenantInfo -and (Get-EbrProp $TenantInfo 'DefaultDomain')) { return [string]$TenantInfo.DefaultDomain }
    $TenantGuid
}

function New-EbrLaBody {
    param([string]$Query, [string[]]$AdditionalWorkspaceIds)
    $body = @{ query = $Query }
    $extra = @($AdditionalWorkspaceIds | Where-Object { $_ })
    if ($extra.Count) { $body['workspaces'] = $extra }
    $body
}

function Test-EbrMissingTableError {
    param([string]$Message)
    # A workspace without the table has no data for it. That is a reading, not a failure.
    $Message -match 'Failed to resolve table'
}

function Get-EbrRuleSummary {
    param($Rules, [datetime]$WindowStart)
    $all = @($Rules | Where-Object { $null -ne $_ })
    $label = 'Rules modified since window start ({0})' -f $WindowStart.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)
    $scopes = [ordered]@{ 'All workspaces' = $all }
    foreach ($g in ($all | Group-Object { [string](Get-EbrProp $_ 'Workspace') } | Sort-Object Name)) {
        if ($g.Name) { $scopes[$g.Name] = @($g.Group) }
    }
    foreach ($scope in @($scopes.Keys)) {
        $set = @($scopes[$scope])
        [pscustomobject]@{ Scope = $scope; Metric = 'Total rules'; Value = $set.Count }
        [pscustomobject]@{ Scope = $scope; Metric = 'Enabled rules'; Value = @($set | Where-Object { Test-EbrTrue $_.Enabled }).Count }
        [pscustomobject]@{ Scope = $scope; Metric = $label; Value = @($set | Where-Object { $_.LastModifiedUtc -and (ConvertTo-EbrUtcDate $_.LastModifiedUtc) -ge $WindowStart }).Count }
        if ($scope -eq 'All workspaces') {
            foreach ($k in ($set | Group-Object Kind | Sort-Object Name)) {
                [pscustomobject]@{ Scope = $scope; Metric = "Kind: $($k.Name)"; Value = $k.Count }
            }
        }
    }
}

#endregion

#region Query catalog

function New-EbrQuery {
    param(
        [string]$Id, [string]$Phase, [string]$Title, [string]$Engine,
        [string]$Query = '', [string]$Notes = '',
        # Log Analytics only. TenantTable: read from the one workspace holding most of that
        # tenant-wide table. CombinedOnly: no per-workspace breakdown. AlwaysBreakdown: per-
        # workspace run even with -SkipWorkspaceBreakdown, because later steps depend on it.
        [string]$TenantTable = '', [switch]$CombinedOnly, [switch]$AlwaysBreakdown,
        # Resource Graph: the result is incomplete when read through Lighthouse
        [switch]$LighthouseIncomplete,
        # Derived: built from results already collected, no engine call. The block receives the context.
        [scriptblock]$Derive
    )
    [pscustomobject]@{
        Id = $Id; Phase = $Phase; Title = $Title; Engine = $Engine; Query = $Query.Trim(); Notes = $Notes
        TenantTable = $TenantTable; CombinedOnly = [bool]$CombinedOnly; AlwaysBreakdown = [bool]$AlwaysBreakdown
        LighthouseIncomplete = [bool]$LighthouseIncomplete; Derive = $Derive
    }
}

function Get-EbrRecentStart {
    # The trailing three full months of the window: the first day of the month two months before
    # the window end month, never earlier than the window start. The HTML report uses this shorter
    # range when the full-window response timing does not qualify (see New-EbrSecurityReport.README.md).
    param([datetime]$WindowStart, [datetime]$WindowEnd)
    $recent = (New-Object datetime $WindowEnd.Year, $WindowEnd.Month, 1).AddMonths(-2)
    if ($recent -lt $WindowStart) { $WindowStart } else { $recent }
}

function Expand-EbrQuery {
    param(
        [string]$Query,
        [datetime]$WindowStart,
        [datetime]$WindowEnd,
        [AllowEmptyString()][string]$ManagedRgPattern,
        [AllowEmptyString()][string]$TicketPattern = '',
        [int]$PatchCadenceDays = 30,
        # Left out means the default pattern. An empty string turns the patch exclusion off.
        [AllowEmptyString()][string]$PatchExclusionTagPattern,
        [AllowEmptyString()][string]$EdrVendorPattern = ''
    )
    if ($ManagedRgPattern -match '["\\\r\n]') {
        throw 'ManagedRgPattern must not contain quotes, backslashes or line breaks.'
    }
    if ([string]::IsNullOrWhiteSpace($TicketPattern)) { $TicketPattern = $script:EbrTicketPattern }
    if ($TicketPattern -match '["\r\n]') { throw 'TicketPattern must not contain double quotes or line breaks.' }
    if ($PatchCadenceDays -lt 1) { $PatchCadenceDays = 30 }
    if (-not $PSBoundParameters.ContainsKey('PatchExclusionTagPattern')) { $PatchExclusionTagPattern = $script:EbrPatchExclusionTagPattern }
    if ($PatchExclusionTagPattern -match '[\r\n]') { throw 'PatchExclusionTagPattern must not contain line breaks.' }
    if ([string]::IsNullOrWhiteSpace($EdrVendorPattern)) { $EdrVendorPattern = $script:EbrEdrVendorPattern }
    if ($EdrVendorPattern -match '["\r\n]') { throw 'EdrVendorPattern must not contain double quotes or line breaks.' }
    $inv = [cultureinfo]::InvariantCulture
    $text = $Query.Replace('{{PATCH_DAYS}}', [string]$PatchCadenceDays)
    $text = $text.Replace('{{EDR_VENDOR}}', $EdrVendorPattern)
    if ([string]::IsNullOrWhiteSpace($PatchExclusionTagPattern)) {
        # Exclusion off: drop the lines that test the tag. Each query sets PatchExcluded to false first.
        $text = (($text -split "`r?`n") | Where-Object { $_ -notmatch '\{\{PATCH_EXCLUDED\}\}' }) -join "`n"
    }
    else {
        # Inside a KQL verbatim string a double quote is written twice
        $text = $text.Replace('{{PATCH_EXCLUDED}}', $PatchExclusionTagPattern.Replace('"', '""'))
    }
    $text = $text.Replace('{{WINDOW_START}}', ('datetime({0})' -f $WindowStart.ToString('yyyy-MM-dd', $inv)))
    $text = $text.Replace('{{WINDOW_END}}', ('datetime({0})' -f $WindowEnd.ToString('yyyy-MM-dd', $inv)))
    $text = $text.Replace('{{RECENT_START}}', ('datetime({0})' -f (Get-EbrRecentStart -WindowStart $WindowStart -WindowEnd $WindowEnd).ToString('yyyy-MM-dd', $inv)))
    $text = $text.Replace('{{TICKET}}', ('(tostring(Comments) matches regex @"{0}" or tostring(ClassificationComment) matches regex @"{0}")' -f $TicketPattern))
    $text = $text.Replace('{{TICKET_PATTERN}}', $TicketPattern)   # the raw pattern, for extracting the ticket reference
    # A row is a network virtual appliance when its plan or image publisher matches the vendor list.
    # Scale sets carry the image reference under virtualMachineProfile.
    $text = $text.Replace('{{APPLIANCE}}', ('tolower(strcat(tostring(plan.publisher), " ", tostring(properties.storageProfile.imageReference.publisher), " ", tostring(properties.virtualMachineProfile.storageProfile.imageReference.publisher))) matches regex @"({0})"' -f $script:EbrAppliancePattern))
    # A DeviceInfo row is a network device when Defender classifies it as one or its vendor, model or
    # operating system names a firewall vendor. column_ifexists keeps the workspace fallback working.
    $text = $text.Replace('{{NETWORK_DEVICE}}', ('(tostring(column_ifexists("DeviceCategory", "")) contains "network" or tostring(column_ifexists("DeviceType", "")) contains "network" or tolower(strcat(tostring(column_ifexists("Vendor", "")), " ", tostring(column_ifexists("Model", "")), " ", tostring(OSPlatform), " ", tostring(column_ifexists("OSDistribution", "")))) matches regex @"({0})")' -f $script:EbrNetworkDevicePattern))
    if ([string]::IsNullOrWhiteSpace($ManagedRgPattern)) {
        # id !contains "" would exclude every resource, so drop the whole exclusion line instead
        $text = (($text -split "`r?`n") | Where-Object { $_ -notmatch '\{\{MRG\}\}' }) -join "`n"
    }
    else {
        $text = $text.Replace('{{MRG}}', $ManagedRgPattern.Trim())
    }
    $text
}

function New-EbrDeviceCheckQuery {
    # One shape for every per-device secure configuration measure: the latest assessment per device
    # and check, applicable checks only, joined to the onboarded Azure virtual machines. A device
    # counts as compliant only when every applicable check in the set is compliant. Since 1.14.0
    # every device measure reads Azure virtual machines only: workstations, laptops and other
    # endpoints that are not Azure resources are never counted.
    param([string[]]$ConfigurationIds)
    $ids = ($ConfigurationIds | ForEach-Object { '"{0}"' -f $_ }) -join ', '
    @"
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId in ($ids)
| summarize arg_max(Timestamp, *) by DeviceId, ConfigurationId
| where tobool(IsApplicable)
| summarize Checks = dcount(ConfigurationId), Passed = dcountif(ConfigurationId, tobool(IsCompliant)) by DeviceId
| join kind=inner (
    DeviceInfo
    | where Timestamp between (ago(30d) .. now())
    | where OnboardingStatus == "Onboarded"
    | summarize arg_max(Timestamp, AzureResourceId, OSPlatform) by DeviceId
    | where isnotempty(AzureResourceId)   // Azure virtual machines only
    | where AzureResourceId !contains "{{MRG}}"
  ) on DeviceId
| extend Scope = "Azure VM"
| summarize Devices = count(), Compliant = countif(Passed == Checks) by Scope
| extend PctCompliant = round(100.0 * Compliant / Devices, 1)
| order by Scope asc
"@
}

function Get-EbrQueryCatalog {
    # Query text is the runbook's, word for word, except three tokens:
    #   {{WINDOW_START}} / {{WINDOW_END}}  replace datetime(2026-01-01) / datetime(2026-07-31)
    #   {{MRG}}                            replaces "aznativesol0"
    # and two multi-workspace fixes:
    #   - incident queries summarize by TenantId, IncidentNumber (TenantId is the workspace ID),
    #     so incident 12 in workspace A and incident 12 in workspace B are not merged
    #   - POS.7 also keys each score by subscription (or workspace). _ResourceId alone does not
    #     separate subscriptions, so combining collapsed six subscriptions into one score.
    # With one workspace and one subscription the results are identical to the runbook's.
    # If you're here to "improve" a runbook query: change the runbook first, then this.
    $q = [System.Collections.Generic.List[object]]::new()

    #region Phase 0
    $q.Add((New-EbrQuery -Id 'P0.1' -Phase 'P0 Pre-flight' -Engine 'LA' -AlwaysBreakdown -Title 'Data reach per table' -Notes 'SecurityIncident earliest record is the earliest possible window start. Missing SecureScores or SecurityRecommendation means continuous export is off. P0.1-BY-WORKSPACE gives the reach of each workspace.' -Query @'
union withsource = SourceTable isfuzzy = true
    SecurityIncident, SecurityAlert, SigninLogs, AuditLogs, SecureScores, SecurityRecommendation
| summarize EarliestRecord = min(TimeGenerated),
            LatestRecord   = max(TimeGenerated),
            Records        = count()
          by SourceTable
| order by SourceTable asc
'@))

    # Not a runbook query. With one Sentinel workspace per subscription, a Defender XDR incident
    # synced into several workspaces would be counted once per workspace in OUT.1 and OUT.3.
    $q.Add((New-EbrQuery -Id 'P0.1-XDRDUP' -Phase 'P0 Pre-flight' -Engine 'LA' -CombinedOnly -Title 'Defender XDR incidents in Sentinel, and duplicates' -Notes 'XdrIncidents of zero means Defender XDR incidents do not reach Sentinel, so the OUT figures leave them out. InMultipleWorkspaces above zero means the combined incident counts include the same XDR incident more than once.' -Query @'
SecurityIncident
| where TimeGenerated > ago(365d)
| where ProviderName in~ ("Microsoft XDR", "Microsoft 365 Defender") and isnotempty(ProviderIncidentId)
| summarize Workspaces = dcount(TenantId) by ProviderIncidentId
| summarize XdrIncidents = count(), InMultipleWorkspaces = countif(Workspaces > 1)
'@))

    $q.Add((New-EbrQuery -Id 'P0.2' -Phase 'P0 Pre-flight' -Engine 'ARG' -Title 'Workspace retention' -Notes 'Deliberately no managed resource group exclusion.' -Query @'
resources
| where type =~ "microsoft.operationalinsights/workspaces"
| project Workspace     = name,
          resourceGroup,
          subscriptionId,
          RetentionDays = toint(properties.retentionInDays),
          Sku           = tostring(properties.sku.name),
          DailyCapGb    = todouble(properties.workspaceCapping.dailyQuotaGb)
'@))

    $q.Add((New-EbrQuery -Id 'P0.3' -Phase 'P0 Pre-flight' -Engine 'ARG' -Title 'Defender for Cloud plans by subscription' -Notes 'CloudPosture on Free means Defender CSPM is off: never quote attack path or critical recommendation tiles.' -Query @'
securityresources
| where type =~ "microsoft.security/pricings"
| project subscriptionId,
          Plan    = name,
          Tier    = tostring(properties.pricingTier),
          SubPlan = tostring(properties.subPlan)
| order by subscriptionId asc, Tier desc, Plan asc
'@))

    $q.Add((New-EbrQuery -Id 'P0.4' -Phase 'P0 Pre-flight' -Engine 'AH' -Title 'Advanced Hunting table availability' -Notes 'A table missing from the output did not resolve. Missing device tables mean EW figures fall back to Secure Score controls.' -Query @'
union withsource = SourceTable isfuzzy = true
    DeviceInfo, DeviceTvmSecureConfigurationAssessment, DeviceEvents,
    EmailPostDeliveryEvents, IdentityLogonEvents
| where Timestamp between (ago(7d) .. now())
| summarize Rows = count(), LatestRecord = max(Timestamp) by SourceTable
'@))

    $q.Add((New-EbrQuery -Id 'P0.5' -Phase 'P0 Pre-flight' -Engine 'ARG' -Title 'Estate inventory by resource type' -Notes 'The sum is the estate count. Never caption it as assessed resources.' -Query @'
resources
| where id !contains "{{MRG}}"
| summarize Resources = count() by subscriptionId, ResourceType = tolower(type)
| order by Resources desc
'@))

    $q.Add((New-EbrQuery -Id 'P0.6-APPLIANCES' -Phase 'P0 Pre-flight' -Engine 'ARG' -Title 'Network virtual appliances excluded from VM measures' -Notes 'Added in 1.10.0. Machines whose marketplace plan or image publisher is a firewall, router or SD-WAN vendor. They leave EW.7, EW.8, DP.4, DP.5b and the agent-based DFC.1 rows because the vendor image cannot take those controls. Internal: names machines, the report embeds the count only.' -Query @'
resources
| where type in~ ("microsoft.compute/virtualmachines", "microsoft.compute/virtualmachinescalesets")
| where id !contains "{{MRG}}"
| where {{APPLIANCE}}
| project Name          = name,
          ResourceType  = tolower(type),
          resourceGroup, subscriptionId,
          Publisher     = coalesce(tostring(plan.publisher), tostring(properties.storageProfile.imageReference.publisher),
                                   tostring(properties.virtualMachineProfile.storageProfile.imageReference.publisher)),
          Offer         = coalesce(tostring(plan.product), tostring(properties.storageProfile.imageReference.offer),
                                   tostring(properties.virtualMachineProfile.storageProfile.imageReference.offer)),
          PowerState    = tostring(properties.extended.instanceView.powerState.code),
          ResourceId    = tolower(id)
| order by resourceGroup asc, Name asc
'@))
    #endregion

    #region Phase 1
    $q.Add((New-EbrQuery -Id 'OUT.1' -Phase 'P1 Outcomes' -Engine 'LA' -Title 'Incident volume and disposition' -Notes 'Window membership is set by CreatedTime after the latest state is taken.' -Query @'
SecurityIncident
| where TimeGenerated between ({{WINDOW_START}} .. now())        // prefilter at window start
| summarize arg_max(TimeGenerated, *) by TenantId, IncidentNumber
| where CreatedTime between ({{WINDOW_START}} .. endofday({{WINDOW_END}}))            // reporting window
| where Severity != "Informational"                                                    // informational alerts are not tracked
| where {{TICKET}}                                                                      // only incidents that opened an Atmosera ticket
| summarize Raised         = count(),
            Closed         = countif(Status == "Closed"),
            Open           = countif(Status != "Closed"),
            TruePositive   = countif(Classification == "TruePositive"),
            BenignPositive = countif(Classification == "BenignPositive"),
            FalsePositive  = countif(Classification == "FalsePositive"),
            ClosedUnclassified = countif(Status == "Closed" and Classification in ("Undetermined", ""))
'@))

    $q.Add((New-EbrQuery -Id 'OUT.1-OPEN' -Phase 'P1 Outcomes' -Engine 'LA' -CombinedOnly -Title 'Open alerts with their ticket reference' -Notes 'SecOps worklist input, added in 1.8.0. The incidents OUT.1 counts as Open, one row each, with the Atmosera ticket extracted from the comments. Internal: names incidents, never embedded in the client report.' -Query @'
SecurityIncident
| where TimeGenerated between ({{WINDOW_START}} .. now())
| summarize arg_max(TimeGenerated, *) by TenantId, IncidentNumber
| where CreatedTime between ({{WINDOW_START}} .. endofday({{WINDOW_END}}))
| where Severity != "Informational"
| where {{TICKET}}
| where Status != "Closed"
| extend TicketRef = extract(@"{{TICKET_PATTERN}}", 0, tostring(Comments))
| extend TicketRef = iff(isempty(TicketRef), extract(@"{{TICKET_PATTERN}}", 0, tostring(ClassificationComment)), TicketRef)
| extend TicketNumber = extract(@"(\d+)\s*$", 1, TicketRef)
| project WorkspaceId = TenantId, IncidentNumber, Title, Severity, Status, Owner = tostring(Owner.assignedTo),
          CreatedTime, LastModifiedTime, AgeDays = datetime_diff("day", now(), CreatedTime), TicketRef, TicketNumber, IncidentUrl
| order by Severity asc, CreatedTime asc
'@))

    $out2 = @'
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
          by Scope
'@
    $q.Add((New-EbrQuery -Id 'OUT.2' -Phase 'P1 Outcomes' -Engine 'LA' -Title 'Triage and close time by severity, plus all' -Notes 'Quote the median, never the mean. If AutoClosed is a large share, use OUT.2-ANALYST and label the tile analyst-handled.' -Query $out2))
    $q.Add((New-EbrQuery -Id 'OUT.2-ANALYST' -Phase 'P1 Outcomes' -Engine 'LA' -Title 'Triage and close time, analyst-handled only' -Notes 'Runbook variant of OUT.2 with automation-closed incidents removed. Confirm the ModifiedBy text for automation rules.' -Query ($out2.Replace("IsAutoClosed    = ModifiedBy has `"Automation rule`"`n", "IsAutoClosed    = ModifiedBy has `"Automation rule`"`n| where not(IsAutoClosed)`n").Replace("IsAutoClosed    = ModifiedBy has `"Automation rule`"`r`n", "IsAutoClosed    = ModifiedBy has `"Automation rule`"`r`n| where not(IsAutoClosed)`r`n"))))

    $out2Recent = $out2.Replace('{{WINDOW_START}}', '{{RECENT_START}}')
    $q.Add((New-EbrQuery -Id 'OUT.2-RECENT' -Phase 'P1 Outcomes' -Engine 'LA' -Title 'Triage and close time, trailing three full months' -Notes 'OUT.2 over the last three full months of the window, for the analyst. The HTML report presents one fixed cohort from OUT.2 and never falls back to it. Identical to OUT.2 when the window is three months or shorter.' -Query $out2Recent))
    $q.Add((New-EbrQuery -Id 'OUT.2-RECENT-ANALYST' -Phase 'P1 Outcomes' -Engine 'LA' -Title 'Triage and close time, trailing three full months, analyst-handled only' -Notes 'OUT.2-ANALYST over the last three full months of the window.' -Query ($out2Recent.Replace("IsAutoClosed    = ModifiedBy has `"Automation rule`"`n", "IsAutoClosed    = ModifiedBy has `"Automation rule`"`n| where not(IsAutoClosed)`n").Replace("IsAutoClosed    = ModifiedBy has `"Automation rule`"`r`n", "IsAutoClosed    = ModifiedBy has `"Automation rule`"`r`n| where not(IsAutoClosed)`r`n"))))

    $q.Add((New-EbrQuery -Id 'OUT.3' -Phase 'P1 Outcomes' -Engine 'LA' -Title 'Monthly incident volume by severity and classification' -Notes 'Compare full months only.' -Query @'
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
            Informational = countif(Severity == "Informational"),
            TruePositive  = countif(Classification == "TruePositive"),
            FalsePositive = countif(Classification == "FalsePositive")
          by Month = startofmonth(CreatedTime)
| order by Month asc
'@))

    $q.Add((New-EbrQuery -Id 'OUT.4' -Phase 'P1 Outcomes' -Engine 'LA' -Title 'True positives and the data loss check' -Notes 'Row count is the contained tile, with a containment statement in each ClassificationComment. Zero data loss holds only if no row is flagged or each flagged comment records no data access.' -Query @'
SecurityIncident
| where TimeGenerated between ({{WINDOW_START}} .. now())
| summarize arg_max(TimeGenerated, *) by TenantId, IncidentNumber
| where CreatedTime between ({{WINDOW_START}} .. endofday({{WINDOW_END}}))
| where Severity != "Informational"
| where {{TICKET}}
| where Classification == "TruePositive"
| extend Tactics = tostring(AdditionalData.tactics)
| project IncidentNumber, Title, Severity, CreatedTime, ClosedTime,
          ClassificationReason, ClassificationComment, Tactics,
          ExfilOrImpactTactic = Tactics has_any ("Exfiltration", "Collection", "Impact")
| order by CreatedTime asc
'@))

    $q.Add((New-EbrQuery -Id 'OUT.5' -Phase 'P1 Outcomes' -Engine 'LA' -Title 'Alerts triaged by product and severity' -Notes 'Detections correlated into ticketed, non-informational incidents only.' -Query @'
let TicketedAlertIds = SecurityIncident
| where TimeGenerated between ({{WINDOW_START}} .. now())
| summarize arg_max(TimeGenerated, *) by TenantId, IncidentNumber
| where CreatedTime between ({{WINDOW_START}} .. endofday({{WINDOW_END}}))
| where Severity != "Informational"
| where {{TICKET}}
| mv-expand AlertId = AlertIds to typeof(string)
| distinct AlertId;
SecurityAlert
| where TimeGenerated between ({{WINDOW_START}} .. endofday({{WINDOW_END}}))
| summarize arg_max(TimeGenerated, ProductName, AlertSeverity) by SystemAlertId
| where AlertSeverity != "Informational"
| where SystemAlertId in (TicketedAlertIds)
| summarize Alerts = count() by ProductName, AlertSeverity
| order by Alerts desc
'@))

    $q.Add((New-EbrQuery -Id 'OUT.6' -Phase 'P1 Outcomes' -Engine 'LA' -Title 'Boundary and egress detections' -Notes 'The keyword list is the definition of a boundary detection. Reuse it unchanged next cycle.' -Query @'
let TicketedAlertIds = SecurityIncident
| where TimeGenerated between ({{WINDOW_START}} .. now())
| summarize arg_max(TimeGenerated, *) by TenantId, IncidentNumber
| where CreatedTime between ({{WINDOW_START}} .. endofday({{WINDOW_END}}))
| where Severity != "Informational"
| where {{TICKET}}
| mv-expand AlertId = AlertIds to typeof(string)
| distinct AlertId;
SecurityAlert
| where TimeGenerated between ({{WINDOW_START}} .. endofday({{WINDOW_END}}))
| summarize arg_max(TimeGenerated, AlertName, ProductName, Tactics) by SystemAlertId
| where SystemAlertId in (TicketedAlertIds)
| where AlertName has_any ("DNS", "domain", "tunneling", "SSH", "RDP", "remote management",
                           "brute force", "port scan", "scanning", "blob", "exfiltration")
     or Tactics has_any ("CommandAndControl", "Exfiltration")
| summarize Alerts = count() by AlertName, ProductName
| order by Alerts desc
'@))

    $q.Add((New-EbrQuery -Id 'OUT.7' -Phase 'P1 Outcomes' -Engine 'LA' -Title 'Attack disruption incidents' -Notes 'Confirm the disruption tag text on the first run.' -Query @'
SecurityIncident
| where TimeGenerated between ({{WINDOW_START}} .. now())
| summarize arg_max(TimeGenerated, *) by TenantId, IncidentNumber
| where CreatedTime between ({{WINDOW_START}} .. endofday({{WINDOW_END}}))
| where Severity != "Informational"
| where {{TICKET}}
| where tostring(Labels) has "Attack Disruption"
| project IncidentNumber, Title, Severity, FirstActivityTime, CreatedTime,
          ClosedTime, Classification
| order by CreatedTime asc
'@))

    $q.Add((New-EbrQuery -Id 'OUT.8' -Phase 'P1 Outcomes' -Engine 'LA' -TenantTable 'AuditLogs' -Title 'Account disable events for containment timing' -Notes 'Containment minutes = OUT.8 disable time minus the malicious sign-in time for the same user in SigninLogs.' -Query @'
AuditLogs
| where TimeGenerated between ({{WINDOW_START}} .. endofday({{WINDOW_END}}))
| where OperationName =~ "Disable account"
| extend TargetUser = tostring(TargetResources[0].userPrincipalName),
         Initiator  = coalesce(tostring(InitiatedBy.app.displayName),
                               tostring(InitiatedBy.user.userPrincipalName))
| project TimeGenerated, TargetUser, Initiator, Result
| order by TimeGenerated asc
'@))
    #endregion

    #region Phase 2 sweep
    $dfcList = @'
    "EDR", "endpoint protection", "Secure Boot", "vTPM", "guest configuration",
    "encryption at host", "Disk Encryption", "backup", "system updates",
    "vulnerability", "vulnerabilities",
    "management ports", "network security groups", "private endpoint", "private link",
    "public network access",
    "secure transfer", "TLS", "HTTPS", "FTPS", "secure communication protocols",
    "purge protection", "soft delete", "RBAC", "resource logs", "diagnostic logs", "auditing",
    "MFA", "owner permissions", "Defender for", "threat protection")
'@
    # Network virtual appliances (P0.6-APPLIANCES) cannot run guest agents or take disk, platform
    # integrity or backup changes, so those recommendations are dropped for them. Network
    # recommendations such as management ports still apply.
    $dfcAppliance = @'
| join kind=leftouter (
    resources
    | where type =~ "microsoft.compute/virtualmachines"
    | where {{APPLIANCE}}
    | project ResourceId = tolower(id), Appliance = name
  ) on ResourceId
| where isempty(Appliance) or not(Recommendation has_any (
    "EDR", "endpoint protection", "Secure Boot", "vTPM", "guest configuration", "guest attestation",
    "encryption at host", "EncryptionAtHost", "Disk Encryption", "backup", "system updates",
    "vulnerability", "vulnerabilities"))
'@
    $q.Add((New-EbrQuery -Id 'DFC.1' -Phase 'P2 Control sweep' -Engine 'ARG' -Title 'Defender for Cloud control evidence sweep' -Notes 'Where Defender for Cloud and a direct ARG property query disagree, quote Defender for Cloud.' -Query (@'
securityresources
| where type =~ "microsoft.security/assessments"
| where id !contains "{{MRG}}"
| extend Recommendation = tostring(properties.displayName),
         Status         = tostring(properties.status.code),
         Severity       = tostring(properties.metadata.severity),
         ResourceId     = tostring(split(tolower(id), "/providers/microsoft.security/assessments/")[0])
| where Recommendation has_any (
'@ + "`n" + $dfcList + "`n" + $dfcAppliance + "`n" + @'
| summarize Healthy       = countif(Status == "Healthy"),
            Unhealthy     = countif(Status == "Unhealthy"),
            NotApplicable = countif(Status == "NotApplicable")
          by Recommendation, Severity
| extend PctHealthy = round(100.0 * Healthy / (Healthy + Unhealthy), 1)
| order by Recommendation asc
'@)))

    $q.Add((New-EbrQuery -Id 'DFC.1-DETAIL' -Phase 'P2 Control sweep' -Engine 'ARG' -Title 'DFC.1 itemized unhealthy resources' -Notes 'The itemized list behind DFC.1 (runbook: keep the ARG result as the itemized list). The SecOps worklist groups it by recommendation.' -Query (@'
securityresources
| where type =~ "microsoft.security/assessments"
| where id !contains "{{MRG}}"
| extend Recommendation = tostring(properties.displayName),
         Status         = tostring(properties.status.code),
         Severity       = tostring(properties.metadata.severity),
         ResourceId     = tostring(split(tolower(id), "/providers/microsoft.security/assessments/")[0])
| where Status == "Unhealthy"
| where Recommendation has_any (
'@ + "`n" + $dfcList + "`n" + $dfcAppliance + "`n" + @'
| project Recommendation, Severity, ResourceId, subscriptionId, resourceGroup
| order by Recommendation asc, ResourceId asc
'@)))
    #endregion

    #region Phase 2 Identity and Access
    # Federation-aware MFA evidence (docs/Federated MFA Evaluation.md, Q2), shared by IA.1 and
    # IA.1-ADMINPORTAL. Each successful sign-in is classified by the strongest MFA evidence it
    # carries. A reused session that no policy checked reads "not evaluated", not "no MFA".
    # Only the plain Require multifactor authentication grant, enforced or report-only, proves
    # whether a reused session carried MFA. The step detail strings were confirmed with Q1 in a
    # federated tenant (Okta) on Oct 13, 2026.
    # Direct MFA signals on a single sign-in, used by the session pre-pass and the classification.
    $mfaSignals = @'
| extend AuthText = strcat(tostring(AuthenticationDetails), " ", AuthenticationMethodsUsed)
| extend MfaRequired     = AuthenticationRequirement =~ "multiFactorAuthentication",
         MfaExternal     = AuthText has "claim provided by external provider",
         MfaTokenClaim   = AuthText has "MFA requirement satisfied by claim in the token",
         Passwordless    = AuthText has_any ("Windows Hello", "FIDO2", "Passkey", "Passwordless", "Platform Credential"),
         MfaEntraStep    = isnotempty(tostring(MfaDetail.authMethod))
                           or AuthText has_any ("Mobile app notification", "Text message", "Phone call", "OATH verification code")
'@
    # Session pre-pass (collector 1.13.0, Q5 in the doc): the earliest direct MFA in each SessionId
    # over 90 days of successful sign-ins, all apps, bounded in practice by workspace retention.
    # Policy results are left out, so a session counts only on MFA recorded on one of its sign-ins.
    $sessionMfa = @'
// Earliest direct MFA in each session, 90 days of successful sign-ins in every app (bounded by workspace retention)
let MfaSessions = SigninLogs
| where TimeGenerated between (ago(90d) .. now())
| where ResultType == "0" and isnotempty(UserId)
| project TimeGenerated, SessionKey = tostring(column_ifexists("SessionId", "")),
          AuthenticationRequirement, AuthenticationDetails, AuthenticationMethodsUsed, MfaDetail
| where isnotempty(SessionKey)
'@ + "`n" + $mfaSignals + "`n" + @'
| summarize FirstMfa = minif(TimeGenerated, MfaEntraStep or MfaExternal or Passwordless or MfaRequired or MfaTokenClaim) by SessionKey
| where isnotnull(FirstMfa);
'@
    $mfaEvidence = @'
| project TimeGenerated, SessionKey = tostring(column_ifexists("SessionId", "")),
          UserId, UserType, CrossTenantAccessType, AppDisplayName, AuthenticationRequirement,
          AuthenticationDetails, AuthenticationMethodsUsed, MfaDetail, AuthenticationProtocol,
          IncomingTokenType, DeviceDetail, ConditionalAccessPolicies
// Partner technicians (GDAP) and outbound passthrough get their own rows, so Member is the client's own members
| extend UserType = case(CrossTenantAccessType =~ "serviceProvider", "Partner (GDAP)",
                         CrossTenantAccessType =~ "passthrough",     "Outbound passthrough",
                         UserType)
'@ + "`n" + $mfaSignals + "`n" + @'
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
'@
    $q.Add((New-EbrQuery -Id 'IA.1' -Phase 'P2 Identity' -Engine 'LA' -TenantTable 'SigninLogs' -Title 'MFA evidence per user, successful sign-ins' -Notes 'Each sign-in is classified by the strongest MFA evidence it carries (federation aware). Windows logon and device registration are left out, because a federated Windows logon (WS-Trust) can never carry MFA. NoMfaOnlyUnevaluated counts users whose only sign-ins reused a session no policy checked: not evaluated, not missing MFA. Since 1.13.0 a sign-in without direct evidence counts as MFA when an earlier sign-in in the same SessionId (90 days) carried direct MFA, and MfaSessionLinkedOnly counts users whose only MFA evidence is that inference. UsersChallenged, UsersAlwaysMfa and UsersExternalMfa repeat MfaAtLeastOnce, MfaEveryAppSignIn and FederatedMfaAtLeastOnce under their earlier names. IA.1-FEDERATION says whether the tenant is federated.' -Query ($sessionMfa + "`n" + @'
SigninLogs
| where TimeGenerated between (ago(30d) .. now())
| where ResultType == "0" and isnotempty(UserId)
'@ + "`n" + $mfaEvidence + "`n" + @'
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
'@)))

    $ia2Head = @'
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
'@
    $q.Add((New-EbrQuery -Id 'IA.2' -Phase 'P2 Identity' -Engine 'LA' -TenantTable 'SigninLogs' -Title 'Authentication methods in use, distinct users per bucket' -Notes 'Methods used, not registered. The retiring bucket is the at-risk population.' -Query ($ia2Head + "`n" + @'
| summarize DistinctUsers = dcount(UserId),
            SignIns       = count(),
            Methods       = make_set(Method)
          by Bucket
| order by Bucket asc
'@)))
    $q.Add((New-EbrQuery -Id 'IA.2-METHOD' -Phase 'P2 Identity' -Engine 'LA' -TenantTable 'SigninLogs' -Title 'Authentication methods in use, per method' -Notes 'Runbook variant of IA.2 split by method (for lines such as 35 on text message and 1 on phone call).' -Query ($ia2Head + "`n" + @'
| summarize DistinctUsers = dcount(UserId),
            SignIns       = count()
          by Bucket, Method
| order by Bucket asc, DistinctUsers desc
'@)))

    $q.Add((New-EbrQuery -Id 'IA.1-ADMINPORTAL' -Phase 'P2 Identity' -Engine 'LA' -TenantTable 'SigninLogs' -Title 'MFA at admin portal sign-in' -Notes 'The four app IDs are the Microsoft Admin Portals target resource group (Exchange admin center, Azure portal which also serves the Entra admin center, Microsoft 365 admin center, Security and Compliance center). Same federation-aware MFA evidence as IA.1. NoMfaOnlyUnevaluated counts users whose only portal sign-ins reused a session no policy checked. The session pre-pass reads every app, so MFA earlier in the same session can come from a sign-in outside the portals.' -Query ($sessionMfa + "`n" + @'
SigninLogs
| where TimeGenerated between (ago(30d) .. now())
| where ResultType == "0" and isnotempty(UserId)
| where ResourceIdentity in ("497effe9-df71-4043-a8bb-14cf78c4b63b",   // Exchange admin center
                             "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",   // Azure portal and Entra admin center
                             "00000006-0000-0ff1-ce00-000000000000",   // Microsoft 365 admin center
                             "80ccca67-54bd-44ab-8625-4b79c4dc7775")   // Security and Compliance center
'@ + "`n" + $mfaEvidence + "`n" + @'
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
'@)))

    $q.Add((New-EbrQuery -Id 'IA.1-FEDERATION' -Phase 'P2 Identity' -Engine 'GRAPH' -Title 'Federated domains and how Entra treats their MFA' -Query @'
GET /v1.0/domains?$select=id,authenticationType,isRoot,isVerified
GET /v1.0/domains/{id}/federationConfiguration   (each federated domain)
Permission: Domain.Read.All
'@ -Notes 'Portal fallback: Entra admin center > Identity > Settings > Domain names (federated domains), then Get-MgDomainFederationConfiguration or az rest GET on /domains/{id}/federationConfiguration. A subdomain of a federated root domain inherits its federation and Graph answers 404 for it. In a federated tenant IA.1 reads reused sessions as not evaluated, not as missing MFA.'))

    $q.Add((New-EbrQuery -Id 'IA.3' -Phase 'P2 Identity' -Engine 'LA' -TenantTable 'SigninLogs' -Title 'Legacy authentication attempts' -Notes 'The Conditional Access block policy (IA.8) grades it. In force when an enabled policy blocks legacy authentication for all users, or security defaults are on. Without a policy inventory, In force only when BlockedByCa is above zero and Succeeded is zero on every row, Not in force when any sign-in succeeded, N/A otherwise. Only error 53003 (BlockedByCa) counts as a block, and attempts that failed without it are never read as blocked. Unknown is not a legacy protocol and is left out (1.10.0). IA.8-SIGNINS splits successful attempts into accounts excluded from the block policy and accounts it did not govern.' -Query @'
SigninLogs
| where TimeGenerated between (ago(30d) .. now())
| where isnotempty(ClientAppUsed)
| where ClientAppUsed !in ("Browser", "Mobile Apps and Desktop clients", "Unknown")
| summarize Attempts    = count(),
            Succeeded   = countif(ResultType == "0"),
            BlockedByCa = countif(ResultType == "53003"),
            Users       = dcountif(UserPrincipalName, ResultType == "0")
          by ClientAppUsed
| order by Succeeded desc
'@))

    $q.Add((New-EbrQuery -Id 'IA.3-DEVICECODE' -Phase 'P2 Identity' -Engine 'LA' -TenantTable 'SigninLogs' -Title 'Device code flow sign-ins' -Notes 'Graded from the block policy (IA.8-POLICIES). Without a policy inventory, In force only when Conditional Access blocks are recorded and nothing succeeded, Not in force when a sign-in succeeded, otherwise N/A. Attempts blocked by Conditional Access (53003) are the evidence that the policy is doing the blocking. Approved Teams Rooms or signage devices sit in the excluded group.' -Query @'
SigninLogs
| where TimeGenerated between (ago(30d) .. now())
| where AuthenticationProtocol =~ "deviceCode"
| summarize Attempts    = count(),
            Succeeded   = countif(ResultType == "0"),
            BlockedByCa = countif(ResultType == "53003"),
            Users       = dcount(UserPrincipalName),
            Apps        = dcount(AppId)
| extend InForce = Succeeded == 0
'@))

    $q.Add((New-EbrQuery -Id 'IA.14' -Phase 'P2 Identity' -Engine 'LA' -TenantTable 'SigninLogs' -Title 'Users signing in to Azure management' -Notes 'One row per user who reached Windows Azure Service Management API in 30 days. The worksheet compares the list with privileged role holders (IA.6, or IA.6-SUB). Users outside that set are the gap for the management plane control.' -Query @'
SigninLogs
| where TimeGenerated between (ago(30d) .. now())
| where ResultType == "0" and isnotempty(UserId)
| where ResourceIdentity == "797f4846-ba00-4fd7-ba43-dac1f8f63013"   // Windows Azure Service Management API
| summarize SignIns = count(), LastSignIn = max(TimeGenerated), Apps = dcount(AppId) by UserId, UserPrincipalName, UserType
| order by SignIns desc
'@))

    $q.Add((New-EbrQuery -Id 'IA.4' -Phase 'P2 Identity' -Engine 'LA' -TenantTable 'SigninLogs' -Title 'Conditional Access coverage of successful sign-ins' -Notes 'The notApplied share is the coverage gap.' -Query @'
SigninLogs
| where TimeGenerated between (ago(30d) .. now())
| where ResultType == "0"
| summarize Users = dcount(UserId), SignIns = count() by ConditionalAccessStatus
'@))

    $q.Add((New-EbrQuery -Id 'IA.4b' -Phase 'P2 Identity' -Engine 'LA' -TenantTable 'SigninLogs' -Title 'Sign-ins gated by a device compliance grant' -Notes 'Confirm the grant control strings against one sign-in record on the first run.' -Query @'
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
'@))

    $q.Add((New-EbrQuery -Id 'IA.5' -Phase 'P2 Identity' -Engine 'GRAPH' -Title 'Registered methods' -Query @'
GET /v1.0/reports/authenticationMethods/userRegistrationDetails?$filter=userType eq 'member'
Permission: AuditLog.Read.All
'@ -Notes 'Portal fallback: Entra admin center > Protection > Authentication methods > User registration details: export, then count members, MFA registered, phishing-resistant (FIDO2, passkey, Windows Hello), phone and Microsoft Authenticator registrations.'))

    $q.Add((New-EbrQuery -Id 'IA.6' -Phase 'P2 Identity' -Engine 'GRAPH' -Title 'Standing privileged Entra roles' -Query @'
GET /v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$expand=principal
GET /v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$expand=principal
GET /v1.0/roleManagement/directory/roleAssignments?$expand=principal   (fallback without PIM)
Permission: RoleManagement.Read.Directory
Filtered to the 12 privileged role template IDs in the runbook IA.6 block.
'@ -Notes 'Portal fallback: Entra admin center > Identity governance > Privileged Identity Management > Microsoft Entra roles > Assignments: export Active (permanent = standing) and Eligible for the 12 privileged roles. IA.6-SUB lists current privileged role holders without Graph.'))

    $q.Add((New-EbrQuery -Id 'IA.6-SUB' -Phase 'P2 Identity' -Engine 'AH' -Title 'Privileged Entra role holders (IdentityInfo substitute)' -Notes 'Substitute for IA.6. Accounts holding one of the 12 IA.6 privileged roles per IdentityInfo. Cannot separate permanent from PIM-activated assignments. Exclude documented break-glass accounts.' -Query @'
IdentityInfo
| extend EventTime = coalesce(column_ifexists("Timestamp", datetime(null)), column_ifexists("TimeGenerated", datetime(null)))
| where EventTime > ago(14d)
| where isnotempty(AccountObjectId)
| summarize arg_max(EventTime, *) by AccountObjectId
| extend ActiveRoles      = todynamic(column_ifexists("AssignedRoles", dynamic([]))),
         PimEligibleRoles = todynamic(column_ifexists("PrivilegedEntraPimRoles", dynamic([])))
| mv-expand Role = ActiveRoles to typeof(string)
| where Role in~ ("Global Administrator", "Privileged Role Administrator",
                  "Privileged Authentication Administrator", "Security Administrator",
                  "Conditional Access Administrator", "Exchange Administrator",
                  "SharePoint Administrator", "User Administrator", "Application Administrator",
                  "Cloud Application Administrator", "Hybrid Identity Administrator",
                  "Intune Administrator")
| project AccountUpn         = tostring(column_ifexists("AccountUpn", "")),
          AccountDisplayName = tostring(column_ifexists("AccountDisplayName", "")),
          AccountObjectId, Role,
          PimEligibleRoles   = tostring(PimEligibleRoles),
          LastSeen           = EventTime
| order by Role asc, AccountUpn asc
'@))

    $q.Add((New-EbrQuery -Id 'IA.7' -Phase 'P2 Identity' -Engine 'ARG' -LighthouseIncomplete -Notes 'Needs direct access to the client tenant: through Lighthouse, Resource Graph shows the managing tenant''s delegations instead of the client''s role assignments.' -Title 'Azure Owner and User Access Administrator assignments' -Query @'
authorizationresources
| where type =~ "microsoft.authorization/roleassignments"
| where id !contains "{{MRG}}"
| extend RoleDefinitionId = tolower(tostring(properties.roleDefinitionId)),
         PrincipalType    = tostring(properties.principalType)
| where RoleDefinitionId endswith "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
     or RoleDefinitionId endswith "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
| extend Role = iff(RoleDefinitionId endswith "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
                    "Owner", "User Access Administrator")
| summarize Assignments = count() by Role, PrincipalType, subscriptionId
| order by Role asc, Assignments desc
'@))

    $q.Add((New-EbrQuery -Id 'IA.8' -Phase 'P2 Identity' -Engine 'GRAPH' -Title 'Conditional Access policy inventory' -Query @'
GET /v1.0/identity/conditionalAccess/policies
GET /v1.0/policies/identitySecurityDefaultsEnforcementPolicy
Permission: Policy.Read.All
Also writes IA.8-POLICIES (the policies exactly as Graph returned them, with the excluded user, group and role IDs) and IA.8-DEFAULTS (security defaults on or off).
'@ -Notes 'Portal fallback: Entra admin center > Protection > Conditional Access > Policies (state, client apps, risk conditions, grants, authentication strength), and Enterprise applications > Consent and permissions > User consent settings. IA.8-SUB infers policy state and grants from sign-in evaluations. IA.8-POLICIES and IA.8-SIGNINS together decide the Conditional Access controls (IA.1-ADMINPORTAL, IA.3, IA.3-DEVICECODE): a successful sign-in by an account the block policy excludes is an exception by design, not a gap.'))

    $q.Add((New-EbrQuery -Id 'IA.8-SUB' -Phase 'P2 Identity' -Engine 'LA' -TenantTable 'SigninLogs' -Title 'Conditional Access policies seen in sign-ins (substitute)' -Notes 'Substitute for IA.8. State is inferred from 30 days of evaluations: notEnabled = off, reportOnly* = report-only (does not count toward E). Risk conditions and the consent setting still need the portal.' -Query @'
SigninLogs
| where TimeGenerated between (ago(30d) .. now())
| mv-expand Policy = todynamic(ConditionalAccessPolicies)
| extend PolicyId        = tostring(Policy.id),
         PolicyName      = tostring(Policy.displayName),
         Result          = tostring(Policy.result),
         Grants          = tostring(Policy.enforcedGrantControls),
         SessionControls = tostring(Policy.enforcedSessionControls)
| where isnotempty(PolicyId)
| summarize Evaluations   = count(),
            Success       = countif(Result == "success"),
            Failure       = countif(Result == "failure"),
            NotApplied    = countif(Result == "notApplied"),
            ReportOnly    = countif(Result startswith "reportOnly"),
            NotEnabled    = countif(Result == "notEnabled"),
            GrantControls = make_set_if(Grants, Grants != "[]", 10),
            Sessions      = make_set_if(SessionControls, SessionControls != "[]", 10),
            LastEvaluated = max(TimeGenerated)
          by PolicyId, PolicyName
| extend InferredState = case(NotEnabled == Evaluations, "Off",
                              0 < ReportOnly and Success + Failure + NotApplied == 0, "Report-only",
                              "On (enforced)")
| order by InferredState asc, PolicyName asc
'@))

    $q.Add((New-EbrQuery -Id 'IA.8-SIGNINS' -Phase 'P2 Identity' -Engine 'LA' -TenantTable 'SigninLogs' -Title 'Successful device code and legacy sign-ins with their Conditional Access results' -Notes 'Added in 1.10.0. One row per account, flow and set of policy results. PolicyResults lists policyId=result for every policy evaluated (notEnabled left out). Matched offline against IA.8-POLICIES: notApplied on an enabled block policy that covers all users means the account is excluded from it. Internal: names accounts, the report embeds counts only.' -Query @'
SigninLogs
| where TimeGenerated between (ago(30d) .. now())
| where ResultType == "0" and isnotempty(UserId)
| extend Flow = case(AuthenticationProtocol =~ "deviceCode", "Device code",
                     isnotempty(ClientAppUsed) and ClientAppUsed !in ("Browser", "Mobile Apps and Desktop clients", "Unknown"), "Legacy authentication",
                     "")
| where isnotempty(Flow)
| mv-apply Policy = todynamic(ConditionalAccessPolicies) on (
    where tostring(Policy.result) != "notEnabled"
    | summarize PolicySet = make_set(strcat(tostring(Policy.id), "=", tostring(Policy.result)))
  )
| extend PolicyResults = strcat_array(array_sort_asc(PolicySet), ",")
| summarize SignIns = count(), LastSignIn = max(TimeGenerated), Apps = strcat_array(make_set(AppDisplayName, 5), ", ")
          by Flow, ClientAppUsed, UserId, UserPrincipalName, UserType, PolicyResults
| order by Flow asc, SignIns desc
'@))

    $q.Add((New-EbrQuery -Id 'IA.11' -Phase 'P2 Identity' -Engine 'GRAPH' -Title 'Identity Protection risk policies in force' -Query @'
GET /v1.0/identity/conditionalAccess/policies   (shared with IA.8)
GET /v1.0/directory/onPremisesSynchronization   (password hash sync, optional)
Permission: Policy.Read.All, OnPremDirectorySynchronization.Read.All
'@ -Notes 'Portal fallback: Entra admin center > Protection > Conditional Access > Policies, filter on sign-in risk and user risk conditions. Entra Connect > password hash sync for hybrid tenants.'))

    $q.Add((New-EbrQuery -Id 'IA.13' -Phase 'P2 Identity' -Engine 'GRAPH' -Title 'Application consent governance' -Query @'
GET /v1.0/policies/authorizationPolicy
GET /v1.0/policies/adminConsentRequestPolicy
Permission: Policy.Read.All
'@ -Notes 'Portal fallback: Entra admin center > Enterprise applications > Consent and permissions > User consent settings, and Admin consent settings > Admin consent requests.'))

    $q.Add((New-EbrQuery -Id 'IA.9' -Phase 'P2 Identity' -Engine 'EXO' -Title 'Anti-phishing policy coverage' -Notes 'Also writes IA.9-RULES, IA.9-ATP, IA.9-SAFELINKS and IA.9-SAFEATTACH. The default policy ships with impersonation protection off.'))
    #endregion

    #region Phase 2 Endpoint and Workload
    $q.Add((New-EbrQuery -Id 'EW.1' -Phase 'P2 Endpoint' -Engine 'AH' -Title 'EDR onboarding and sensor health, Azure virtual machines' -Notes 'Azure virtual machines only since 1.14.0: devices with no Azure resource ID (workstations, laptops, other endpoints) are never counted. Denominator is Onboarded plus CanBeOnboarded. Unsupported and InsufficientInfo are context for EW.1-GAPS. SensorActive feeds DR-F1. Network devices and firewalls (Palo Alto, Meraki, Fortinet, SonicWall and similar) are left out since 1.11.0 because they cannot run a sensor.' -Query @'
DeviceInfo
| where Timestamp between (ago(7d) .. now())
| summarize arg_max(Timestamp, *) by DeviceId
| where isnotempty(OSPlatform)
| where isnotempty(AzureResourceId)   // Azure virtual machines only
| where not({{NETWORK_DEVICE}})   // network devices and firewalls cannot run a sensor
| where AzureResourceId !contains "{{MRG}}"
| extend Scope = "Azure VM"
| summarize Devices          = count(),
            Onboarded        = countif(OnboardingStatus == "Onboarded"),
            CanBeOnboarded   = countif(OnboardingStatus == "Can be onboarded"),
            Unsupported      = countif(OnboardingStatus == "Unsupported"),
            InsufficientInfo = countif(OnboardingStatus == "Insufficient info"),
            SensorActive     = countif(SensorHealthState == "Active")
          by Scope, OSPlatform
| order by Devices desc
'@))

    $q.Add((New-EbrQuery -Id 'EW.1-DEVICES' -Phase 'P2 Endpoint' -Engine 'AH' -Title 'Azure virtual machines not onboarded or with an inactive sensor' -Notes 'SecOps worklist input, added in 1.8.0. Azure virtual machines only since 1.10.0: endpoints that are not native to Azure stay out of the worklist. Every Azure VM not onboarded, whatever its onboarding status, plus onboarded Azure VMs whose sensor is not Active. Network devices and firewalls are left out since 1.11.0. EW.1-GAPS adds the reason for each one. Internal: names devices, never embedded in the client report.' -Query @'
DeviceInfo
| where Timestamp between (ago(7d) .. now())
| summarize arg_max(Timestamp, *) by DeviceId
| where isnotempty(OSPlatform)
| where not({{NETWORK_DEVICE}})   // network devices and firewalls cannot run a sensor
| where isnotempty(AzureResourceId)
| where AzureResourceId !contains "{{MRG}}"
| where OnboardingStatus != "Onboarded" or SensorHealthState != "Active"
| extend Scope = "Azure VM",
         Gap   = iff(OnboardingStatus != "Onboarded", "Not onboarded", strcat("Sensor ", SensorHealthState))
| project DeviceName, Scope, OSPlatform, OnboardingStatus, SensorHealthState, Gap, LastSeen = Timestamp, MachineGroup, AzureResourceId
| order by Gap asc, Scope asc, DeviceName asc
'@))

    $q.Add((New-EbrQuery -Id 'EW.1-VMS' -Phase 'P2 Endpoint' -Engine 'AH' -Title 'Azure virtual machines known to Defender for Endpoint' -Notes 'Added in 1.14.0. Every Azure virtual machine Defender for Endpoint has seen in the last 7 days, in any onboarding status, so EW.1-GAPS can tell which machines in Resource Graph Defender has never discovered. Internal: names devices, never embedded in the client report.' -Query @'
DeviceInfo
| where Timestamp between (ago(7d) .. now())
| summarize arg_max(Timestamp, *) by DeviceId
| where isnotempty(OSPlatform)
| where not({{NETWORK_DEVICE}})   // network devices and firewalls cannot run a sensor
| where isnotempty(AzureResourceId)
| where AzureResourceId !contains "{{MRG}}"
| project DeviceId, DeviceName, OSPlatform, OnboardingStatus, SensorHealthState, LastSeen = Timestamp, MachineGroup, AzureResourceId
| order by DeviceName asc
'@))

    $q.Add((New-EbrQuery -Id 'EW.1-EDR' -Phase 'P2 Endpoint' -Engine 'ARG' -Title 'Endpoint detection evidence per Azure virtual machine, from Azure' -Notes 'Added in 1.14.0. One row per Azure virtual machine: the Defender for Endpoint extension (MDE.Windows, MDE.Linux), any extension whose publisher or type names a third-party product (-EdrVendorPattern, CrowdStrike Falcon by default), the Defender for Cloud EDR assessment status, the power state and whether the image is a network appliance. EW.1-GAPS reads it to explain each machine that is not reporting to Defender for Endpoint. Internal: names machines, the report embeds counts only.' -Query @'
resources
| where type =~ "microsoft.compute/virtualmachines"
| where id !contains "{{MRG}}"
| project VmId = tolower(id), VmName = name, resourceGroup, subscriptionId,
          OsType     = tostring(properties.storageProfile.osDisk.osType),
          PowerState = tostring(properties.extended.instanceView.powerState.code),
          Appliance  = {{APPLIANCE}}
| join kind=leftouter (
    resources
    | where type =~ "microsoft.compute/virtualmachines/extensions"
    | extend VmId = tostring(split(tolower(id), "/extensions/")[0]),
             Publisher = tostring(properties.publisher), ExtensionType = tostring(properties.type)
    | extend Product = tolower(strcat(Publisher, " ", ExtensionType, " ", name))
    | summarize DefenderExtension    = countif(ExtensionType startswith "MDE."),
                ThirdPartyExtensions = make_set_if(strcat(Publisher, "/", ExtensionType), Product matches regex @"({{EDR_VENDOR}})")
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
'@))

    $q.Add((New-EbrQuery -Id 'EW.1-EDR-HOSTS' -Phase 'P2 Endpoint' -Engine 'LA' -CombinedOnly -Title 'Hosts reporting to a third-party endpoint detection product through Sentinel' -Notes 'Added in 1.14.0. Hosts seen in the last 7 days in the CrowdStrike tables or in CommonSecurityLog with a vendor or product matching -EdrVendorPattern. EW.1-GAPS matches them by host name to Azure virtual machines that are not onboarded to Defender for Endpoint. EMPTY means the workspaces hold no such telemetry, which is a reading, not a gap. Internal: names hosts, never embedded in the client report.' -Query @'
union withsource = SourceTable isfuzzy = true CrowdStrike*, CommonSecurityLog
| where TimeGenerated > ago(7d)
| extend Product = tolower(strcat(SourceTable, " ", tostring(column_ifexists("DeviceVendor", "")), " ", tostring(column_ifexists("DeviceProduct", ""))))
| where Product matches regex @"({{EDR_VENDOR}})"
| extend Host = tolower(case(isnotempty(tostring(column_ifexists("ComputerName", ""))),   tostring(column_ifexists("ComputerName", "")),
                             isnotempty(tostring(column_ifexists("DeviceName", ""))),     tostring(column_ifexists("DeviceName", "")),
                             isnotempty(tostring(column_ifexists("SourceHostName", ""))), tostring(column_ifexists("SourceHostName", "")),
                             isnotempty(tostring(column_ifexists("HostName", ""))),       tostring(column_ifexists("HostName", "")),
                             tostring(column_ifexists("Computer", ""))))
| where isnotempty(Host)
| extend Host = tostring(split(Host, ".")[0])
| summarize Events = count(), LastSeen = max(TimeGenerated), Sources = make_set(SourceTable) by Host
| order by Host asc
'@))

    $q.Add((New-EbrQuery -Id 'EW.1-GAPS' -Phase 'P2 Endpoint' -Engine 'DERIVED' -Title 'Azure virtual machines not reporting to Defender for Endpoint, with the reason' -Notes 'Added in 1.14.0. Built from EW.1-VMS, EW.1-DEVICES, EW.1-EDR, EW.1-EDR-HOSTS and P0.6-APPLIANCES, no query. One row per Azure virtual machine that is not onboarded with an active sensor, with the reason: covered by a third-party product, network virtual appliance, operating system not supported, deallocated, discovered only, not discovered, sensor not active, or not onboarded with no endpoint detection found. The report counts a machine covered by a third-party product as protected and explains the difference between the sensor and onboarding figures. Internal: names machines, the report embeds counts by reason only.' -Derive { param($Ctx) New-EbrOnboardingGapResult -Ctx $Ctx }))

    $q.Add((New-EbrQuery -Id 'EW.3' -Phase 'P2 Endpoint' -Engine 'AH' -Title 'Security configuration checks, every control in one pass' -Notes 'Select rows by ConfigurationName per the runbook table, then pin the ConfigurationId values. A control spanning several checks grades on its weakest check.' -Query @'
DeviceTvmSecureConfigurationAssessment
| summarize arg_max(Timestamp, *) by DeviceId, ConfigurationId
| where tobool(IsApplicable)
| join kind=inner (
    DeviceInfo
    | where Timestamp between (ago(7d) .. now())
    | summarize arg_max(Timestamp, AzureResourceId) by DeviceId
    | where isnotempty(AzureResourceId)   // Azure virtual machines only
    | where AzureResourceId !contains "{{MRG}}"
  ) on DeviceId
| join kind=inner DeviceTvmSecureConfigurationAssessmentKB on ConfigurationId
| extend Scope = "Azure VM"
| summarize Devices   = dcount(DeviceId),
            Compliant = dcountif(DeviceId, tobool(IsCompliant))
          by Scope, ConfigurationId, ConfigurationName
| extend PctCompliant = round(100.0 * Compliant / Devices, 1)
| order by Scope asc, PctCompliant asc
'@))

    $q.Add((New-EbrQuery -Id 'EW.4' -Phase 'P2 Endpoint' -Engine 'AH' -Title 'Machines missing deployed ASR rules' -Notes 'Rows with Configured at zero sit outside the policy assignment entirely. Edit the rule list to the client set if it differs.' -Query @'
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
    | where AzureResourceId !contains "{{MRG}}"
  ) on DeviceId
| extend ResourceGroup = tostring(split(AzureResourceId, "/")[4]),
         VmName        = tostring(split(AzureResourceId, "/")[8])
| project DeviceName, VmName, ResourceGroup, OSPlatform, OSVersion, MachineGroup,
          Configured, Applicable, MissingRules
| order by Configured asc, DeviceName asc
'@))

    $q.Add((New-EbrQuery -Id 'EW.5' -Phase 'P2 Endpoint' -Engine 'AH' -Title 'ASR activity, audit versus block' -Notes 'Evidence that audit-mode rules are deployed and generating signal before they move to block.' -Query @'
DeviceEvents
| where Timestamp between (ago(30d) .. now())
| where ActionType startswith "Asr"
| join kind=inner (
    DeviceInfo
    | where Timestamp between (ago(7d) .. now())
    | summarize arg_max(Timestamp, AzureResourceId) by DeviceId
    | where isnotempty(AzureResourceId)   // Azure virtual machines only
  ) on DeviceId
| where AzureResourceId !contains "{{MRG}}"
| extend Mode  = iff(ActionType endswith "Blocked", "Block", "Audit"),
         Scope = "Azure VM"
| summarize Events = count(), Devices = dcount(DeviceId) by Scope, ActionType, Mode
| order by Scope asc, Events desc
'@))

    # Machines whose tags record patching as waived or client owned leave EW.6 and EW.10 (1.14.0).
    # Each query sets PatchExcluded to false first, so an empty -PatchExclusionTagPattern, which
    # drops the token line, leaves every machine in.
    $patchTagJoin = @'
| join kind=leftouter (
    resources
    | where type in~ ("microsoft.compute/virtualmachines", "microsoft.hybridcompute/machines")
    | extend PatchExcluded = false
    | extend PatchExcluded = tolower(tostring(tags)) matches regex @"{{PATCH_EXCLUDED}}"
    | project MachineId = tolower(id), PatchExcluded
  ) on MachineId
| where not(coalesce(PatchExcluded, false))   // patching waived or client owned by tag, see EW.10-EXCLUDED
'@
    $q.Add((New-EbrQuery -Id 'EW.6' -Phase 'P2 Endpoint' -Engine 'ARG' -Title 'Pending patches from Update Manager' -Notes 'Machines whose tags record patching as waived or client owned are left out since 1.14.0 (EW.10-EXCLUDED names them).' -Query (@'
patchassessmentresources
| where type in~ ("microsoft.compute/virtualmachines/patchassessmentresults/softwarepatches",
                  "microsoft.hybridcompute/machines/patchassessmentresults/softwarepatches")
| where id !contains "{{MRG}}"
| extend MachineId      = tostring(split(tolower(id), "/patchassessmentresults")[0]),
         Classification = tostring(properties.classifications[0])
'@ + "`n" + $patchTagJoin + "`n" + @'
| summarize PendingPatches = count(), Machines = dcount(MachineId) by Classification
| order by PendingPatches desc
'@)))

    $q.Add((New-EbrQuery -Id 'EW.7' -Phase 'P2 Endpoint' -Engine 'ARG' -Title 'Trusted Launch, Secure Boot and vTPM' -Notes 'Grade on the DFC.1 rows (supported machines only). EW.7-DETAIL is the itemized list. Network virtual appliances (P0.6-APPLIANCES) are left out because their vendor images do not support Trusted Launch.' -Query @'
resources
| where type =~ "microsoft.compute/virtualmachines"
| where id !contains "{{MRG}}"
| where not({{APPLIANCE}})   // network virtual appliances, see P0.6-APPLIANCES
| extend SecurityType = tostring(properties.securityProfile.securityType),
         SecureBoot   = tobool(properties.securityProfile.uefiSettings.secureBootEnabled),
         VTpm         = tobool(properties.securityProfile.uefiSettings.vTpmEnabled)
| summarize VMs                = count(),
            TrustedLaunchOrCvm = countif(SecurityType in~ ("TrustedLaunch", "ConfidentialVM")),
            SecureBootOn       = countif(SecureBoot == true),
            VTpmOn             = countif(VTpm == true)
'@))

    $q.Add((New-EbrQuery -Id 'EW.7-DETAIL' -Phase 'P2 Endpoint' -Engine 'ARG' -Title 'EW.7 itemized per VM' -Notes 'Itemized list behind EW.7 (runbook: use this query for the itemized list). Network virtual appliances are left out, as in EW.7.' -Query @'
resources
| where type =~ "microsoft.compute/virtualmachines"
| where id !contains "{{MRG}}"
| where not({{APPLIANCE}})   // network virtual appliances, see P0.6-APPLIANCES
| extend SecurityType = tostring(properties.securityProfile.securityType),
         SecureBoot   = tobool(properties.securityProfile.uefiSettings.secureBootEnabled),
         VTpm         = tobool(properties.securityProfile.uefiSettings.vTpmEnabled),
         PowerState   = tostring(properties.extended.instanceView.powerState.code),
         OsType       = tostring(properties.storageProfile.osDisk.osType)
| project VmName = name, resourceGroup, subscriptionId, OsType, PowerState, SecurityType, SecureBoot, VTpm
| order by SecurityType asc, resourceGroup asc, VmName asc
'@))

    $q.Add((New-EbrQuery -Id 'EW.8' -Phase 'P2 Endpoint' -Engine 'ARG' -Title 'Guest Configuration extension coverage' -Notes 'Proves the extension is installed. EW.9 proves the baselines are evaluated. Network virtual appliances cannot run the extension and are left out.' -Query @'
resources
| where type =~ "microsoft.compute/virtualmachines"
| where id !contains "{{MRG}}"
| where not({{APPLIANCE}})   // network virtual appliances, see P0.6-APPLIANCES
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
'@))

    $q.Add((New-EbrQuery -Id 'EW.9' -Phase 'P2 Endpoint' -Engine 'ARG' -Title 'Guest configuration assignment compliance' -Query @'
guestconfigurationresources
| where type =~ "microsoft.guestconfiguration/guestconfigurationassignments"
| where id !contains "{{MRG}}"
| extend Assignment = tostring(properties.guestConfiguration.name),
         Compliance = tostring(properties.complianceStatus)
| summarize Machines = dcount(tostring(split(tolower(id), "/providers/microsoft.guestconfiguration")[0]))
          by Assignment, Compliance
| order by Assignment asc, Compliance asc
'@))
    #endregion

    #region Phase 2 Network and Boundary
    $q.Add((New-EbrQuery -Id 'EW.10' -Phase 'P2 Endpoint' -Engine 'ARG' -Title 'Patch cadence from Update Manager' -Notes 'A machine is within cadence when it has no pending Critical or Security patch published more than the agreed cadence ago (-PatchCadenceDays, default 30). Machines never assessed are not in the denominator: compare Machines with the VM count in DP.4. Machines whose tags record patching as waived or client owned are left out since 1.14.0 (-PatchExclusionTagPattern, EW.10-EXCLUDED names them).' -Query (@'
patchassessmentresources
| where type in~ ("microsoft.compute/virtualmachines/patchassessmentresults",
                  "microsoft.hybridcompute/machines/patchassessmentresults")
| where id !contains "{{MRG}}"
| extend MachineId   = tostring(split(tolower(id), "/patchassessmentresults")[0]),
         AssessedUtc = todatetime(properties.lastModifiedDateTime)
| join kind=leftouter (
    patchassessmentresources
    | where type in~ ("microsoft.compute/virtualmachines/patchassessmentresults/softwarepatches",
                      "microsoft.hybridcompute/machines/patchassessmentresults/softwarepatches")
    | where id !contains "{{MRG}}"
    | extend MachineId      = tostring(split(tolower(id), "/patchassessmentresults")[0]),
             Classification = tostring(properties.classifications[0]),
             PublishedUtc   = todatetime(properties.publishedDateTime)
    | where Classification in~ ("Critical", "Security")
    | where PublishedUtc < ago({{PATCH_DAYS}}d)
    | summarize OverduePatches = count() by MachineId
  ) on MachineId
| extend OverduePatches = coalesce(OverduePatches, 0)
'@ + "`n" + $patchTagJoin + "`n" + @'
| summarize Machines         = count(),
            WithinCadence    = countif(OverduePatches == 0),
            OverduePatches   = sum(OverduePatches),
            AssessedWithin7d = countif(AssessedUtc > ago(7d))
'@)))

    $q.Add((New-EbrQuery -Id 'EW.10-EXCLUDED' -Phase 'P2 Endpoint' -Engine 'ARG' -Title 'Machines left out of the patch measures by tag' -Notes 'Added in 1.14.0. Virtual machines and Arc machines whose tags record patching as waived or client owned (-PatchExclusionTagPattern). They leave EW.6 and EW.10. The report embeds the count only. Internal: names machines.' -Query @'
resources
| where type in~ ("microsoft.compute/virtualmachines", "microsoft.hybridcompute/machines")
| where id !contains "{{MRG}}"
| extend TagText = tolower(tostring(tags))
| extend PatchExcluded = false, MatchedTag = ""
| extend PatchExcluded = TagText matches regex @"{{PATCH_EXCLUDED}}"
| extend MatchedTag = extract(@"{{PATCH_EXCLUDED}}", 0, TagText)
| where PatchExcluded
| project Name = name, ResourceType = tolower(type), resourceGroup, subscriptionId, MatchedTag, ResourceId = tolower(id)
| order by resourceGroup asc, Name asc
'@))

    $q.Add((New-EbrQuery -Id 'EW.12' -Phase 'P2 Endpoint' -Engine 'AH' -Title 'Credential protection per device' -Notes 'LSA protection (scid-25, or scid-102 on Windows 11 22H2 and later) and WDigest credential caching off (scid-57). A device counts only when every applicable check passes.' -Query (New-EbrDeviceCheckQuery -ConfigurationIds 'scid-25', 'scid-102', 'scid-57')))

    $q.Add((New-EbrQuery -Id 'EW.14' -Phase 'P2 Endpoint' -Engine 'AH' -Title 'Remote Desktop hardening per device' -Notes 'Remote Desktop security level TLS (scid-24) and Network Level Authentication (scid-45). Drive and clipboard redirection are not secure configuration checks. Read them from Intune or machine configuration.' -Query (New-EbrDeviceCheckQuery -ConfigurationIds 'scid-24', 'scid-45')))

    $q.Add((New-EbrQuery -Id 'EW.15' -Phase 'P2 Endpoint' -Engine 'AH' -Title 'Tamper protection per device' -Notes 'Turn on Tamper Protection (scid-2003). The document numbers this EW.8, which the collector already uses for Guest Configuration.' -Query (New-EbrDeviceCheckQuery -ConfigurationIds 'scid-2003')))

    $q.Add((New-EbrQuery -Id 'EW.16' -Phase 'P2 Endpoint' -Engine 'AH' -Title 'Host firewall on per device' -Notes 'Turn on Microsoft Defender Firewall (scid-2070), which covers every profile. The hardened profile checks (scid-2071 to scid-2073) stay in EW.3 as context. The document numbers this EW.9, which the collector already uses for Guest Configuration compliance.' -Query (New-EbrDeviceCheckQuery -ConfigurationIds 'scid-2070')))

    $q.Add((New-EbrQuery -Id 'EW.13' -Phase 'P2 Endpoint' -Engine 'GRAPH' -Title 'Application allow-listing policies' -Query @'
GET /beta/deviceManagement/configurationPolicies?$filter=templateReference/templateFamily eq 'endpointSecurityApplicationControl'&$select=id,name,platforms,technologies,isAssigned,settingCount,lastModifiedDateTime,templateReference
Permission: DeviceManagementConfiguration.Read.All
The settings catalog exists only in the beta surface. If the filter is rejected, every policy is read and filtered by template family.
'@ -Notes 'Portal fallback: Intune admin center > Endpoint security > App Control for Business. Where the client runs ThreatLocker, read coverage from the ThreatLocker portal.'))

    $q.Add((New-EbrQuery -Id 'NB.1' -Phase 'P2 Network' -Engine 'ARG' -Title 'Subnet segmentation by subnet class' -Notes 'Grade on workload subnets only. A route table counts only when its default route points at the firewall. Adjust the FW- prefix to the client naming.' -Query @'
resources
| where type =~ "microsoft.network/virtualnetworks"
| where id !contains "{{MRG}}"
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
'@))

    $q.Add((New-EbrQuery -Id 'NB.2' -Phase 'P2 Network' -Engine 'ARG' -Title 'Internet-exposed management ports with association' -Notes 'Unassociated = cleanup item. NIC on a firewall untrust interface = by design. Subnet or NIC on a workload = real finding against NB-F5. Check every RangeNeedsReview row.' -Query @'
resources
| where type =~ "microsoft.network/networksecuritygroups"
| where id !contains "{{MRG}}"
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
'@))

    $q.Add((New-EbrQuery -Id 'NB.3' -Phase 'P2 Network' -Engine 'ARG' -Title 'PaaS network exposure and private endpoints' -Notes 'NB-D3 credits only public access disabled or a private endpoint. SQL firewall rules are not read here.' -Query @'
resources
| where type in~ ("microsoft.storage/storageaccounts", "microsoft.keyvault/vaults",
                  "microsoft.sql/servers", "microsoft.cognitiveservices/accounts",
                  "microsoft.documentdb/databaseaccounts", "microsoft.web/sites")
| where id !contains "{{MRG}}"
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
'@))

    $q.Add((New-EbrQuery -Id 'NB.4' -Phase 'P2 Network' -Engine 'ARG' -Title 'Web and Function App HTTPS-only' -Query @'
resources
| where type =~ "microsoft.web/sites"
| where id !contains "{{MRG}}"
| summarize Sites     = count(),
            HttpsOnly = countif(tobool(properties.httpsOnly) == true)
'@))

    $q.Add((New-EbrQuery -Id 'NB.5' -Phase 'P2 Network' -Engine 'ARG' -Title 'App Service FTPS and minimum TLS' -Notes 'If this returns no rows, grade from the FTPS and TLS rows in DFC.1.' -Query @'
appserviceresources
| where type =~ "microsoft.web/sites/config"
| where id !contains "{{MRG}}"
// appserviceresources returns site config keys in PascalCase and dynamic access is case-sensitive.
| extend FtpsState = tostring(coalesce(properties.FtpsState, properties.ftpsState)),
         MinTls    = tostring(coalesce(properties.MinTlsVersion, properties.minTlsVersion))
| summarize Configs      = count(),
            FtpsEnforced = countif(FtpsState in ("FtpsOnly", "Disabled")),
            MinTls12     = countif(MinTls in ("1.2", "1.3"))
'@))

    $q.Add((New-EbrQuery -Id 'NB.6' -Phase 'P2 Network' -Engine 'ARG' -Title 'Azure SQL minimum TLS and public access' -Query @'
resources
| where type =~ "microsoft.sql/servers"
| where id !contains "{{MRG}}"
| summarize Servers        = count(),
            MinTls12       = countif(tostring(properties.minimalTlsVersion) in ("1.2", "1.3")),
            PublicDisabled = countif(tostring(properties.publicNetworkAccess) =~ "Disabled")
'@))

    $q.Add((New-EbrQuery -Id 'NB.7' -Phase 'P2 Network' -Engine 'LA' -Title 'DNS and egress telemetry present' -Query @'
Usage
| where TimeGenerated between (ago(30d) .. now())
| where DataType matches regex "(?i)dns|azfw|firewall|commonsecuritylog|networksession"
| summarize GB = round(sum(Quantity) / 1000, 2), LastSeen = max(TimeGenerated) by DataType
| order by GB desc
'@))
    #endregion

    #region Phase 2 Data Protection
    $q.Add((New-EbrQuery -Id 'NB.8' -Phase 'P2 Network' -Engine 'AH' -Title 'Network protection per device' -Notes 'Enable Network Protection in block mode (scid-96). The control reads E only when the Sentinel DNS tunneling and beaconing rules are enabled too: the worksheet counts them from DR.9-RULES.' -Query (New-EbrDeviceCheckQuery -ConfigurationIds 'scid-96')))

    $q.Add((New-EbrQuery -Id 'NB.10' -Phase 'P2 Network' -Engine 'AH' -Title 'LDAP signing and channel binding on domain controllers' -Notes 'Require LDAP server signing (scid-106) and enforce LDAP channel binding (scid-105) apply to domain controllers only, so Devices is the domain controller count. Not in scope for cloud-only tenants. Directory Service events 2889 and 3039 name the clients still binding insecurely and need that log in Sentinel.' -Query (New-EbrDeviceCheckQuery -ConfigurationIds 'scid-105', 'scid-106')))

    $q.Add((New-EbrQuery -Id 'NB.11' -Phase 'P2 Network' -Engine 'AH' -Title 'NTLMv2 only per device' -Notes 'LAN Manager authentication level set to send NTLMv2 only and refuse LM and NTLM (scid-72). Dependent systems show up in IdentityLogonEvents, which the Defender for Identity connector brings into Sentinel.' -Query (New-EbrDeviceCheckQuery -ConfigurationIds 'scid-72')))

    $q.Add((New-EbrQuery -Id 'DP.1' -Phase 'P2 Data protection' -Engine 'ARG' -Title 'Storage account protection' -Notes 'AnonymousBlobOff is anonymous blob reads. PublicNetworkOff is network reachability. Name the property on the slide.' -Query @'
resources
| where type =~ "microsoft.storage/storageaccounts"
| where id !contains "{{MRG}}"
| summarize Accounts         = count(),
            SecureTransfer   = countif(tobool(properties.supportsHttpsTrafficOnly) == true),
            MinTls12         = countif(tostring(properties.minimumTlsVersion) in ("TLS1_2", "TLS1_3")),
            AnonymousBlobOff = countif(tobool(properties.allowBlobPublicAccess) == false),
            PublicNetworkOff = countif(tostring(properties.publicNetworkAccess) =~ "Disabled"),
            SelectedNetworks = countif(tostring(properties.networkAcls.defaultAction) =~ "Deny"),
            SharedKeyOff     = countif(tobool(properties.allowSharedKeyAccess) == false)
'@))

    $q.Add((New-EbrQuery -Id 'DP.1-CONTAINERS' -Phase 'P2 Data protection' -Engine 'STORAGE-CONTAINERS' -Title 'Blob container anonymous access levels' -Notes 'Added in 1.11.0. Resource Graph does not index blob containers, so the collector lists them per storage account with a GET on the blobServices/default/containers path of each account (Reader is enough). One row per account: the account-level anonymous access setting, the containers, the containers whose own access level is Blob or Container, and how many of those are readable anonymously today because the account setting allows it. Containers are read in every account, so a public container under an account that blocks anonymous access still counts against the defense in depth control. Internal: names accounts and containers, the report embeds counts only.' -Query @'
resources
| where type =~ "microsoft.storage/storageaccounts"
| where id !contains "{{MRG}}"
| where kind !~ "FileStorage"   // no blob service
| project ResourceId = id, Account = name, resourceGroup, subscriptionId,
          AllowBlobPublicAccess = tostring(properties.allowBlobPublicAccess)
| order by subscriptionId asc, Account asc
'@))

    $q.Add((New-EbrQuery -Id 'DP.2' -Phase 'P2 Data protection' -Engine 'ARG' -Title 'Key Vault protection' -Notes 'DP-F4 grades on PurgeProtection.' -Query @'
resources
| where type =~ "microsoft.keyvault/vaults"
| where id !contains "{{MRG}}"
| summarize Vaults          = count(),
            SoftDelete      = countif(isnull(properties.enableSoftDelete)
                                      or tobool(properties.enableSoftDelete) == true),
            PurgeProtection = countif(tobool(properties.enablePurgeProtection) == true),
            RbacAuth        = countif(tobool(properties.enableRbacAuthorization) == true),
            PublicDisabled  = countif(tostring(properties.publicNetworkAccess) =~ "Disabled")
'@))

    $q.Add((New-EbrQuery -Id 'DP.3' -Phase 'P2 Data protection' -Engine 'ARG' -Title 'Managed disk encryption type' -Query @'
resources
| where type =~ "microsoft.compute/disks"
| where id !contains "{{MRG}}"
| extend EncryptionType = tostring(properties.encryption.type),
         AdeEnabled     = tobool(properties.encryptionSettingsCollection.enabled) == true
| summarize Disks = count() by EncryptionType, AdeEnabled
'@))

    $q.Add((New-EbrQuery -Id 'DP.4' -Phase 'P2 Data protection' -Engine 'ARG' -Title 'Encryption at host on VMs and scale sets' -Notes 'Grade and quote from the DFC.1 encryption rows. DP.4-DETAIL names the machines still pending. Network virtual appliances are left out: their vendor images are not certified for host or guest disk encryption. DP.4 also supplies the backup denominator, so the appliances leave DP.5b with it.' -Query @'
resources
| where type in~ ("microsoft.compute/virtualmachines", "microsoft.compute/virtualmachinescalesets")
| where id !contains "{{MRG}}"
| where not({{APPLIANCE}})   // network virtual appliances, see P0.6-APPLIANCES
| extend EncryptionAtHost = coalesce(tobool(properties.securityProfile.encryptionAtHost),
                                     tobool(properties.virtualMachineProfile.securityProfile.encryptionAtHost),
                                     false),
         PowerState = iff(type =~ "microsoft.compute/virtualmachinescalesets", "Scale set",
                          tostring(properties.extended.instanceView.powerState.code))
| summarize Resources = count(), WithEncryptionAtHost = countif(EncryptionAtHost)
          by ResourceType = tolower(type), PowerState
'@))

    $q.Add((New-EbrQuery -Id 'DP.4-DETAIL' -Phase 'P2 Data protection' -Engine 'ARG' -Title 'Machines without encryption at host' -Notes 'Runbook: use DP.4 to name the machines still pending, deallocated machines included. Network virtual appliances are left out, as in DP.4.' -Query @'
resources
| where type in~ ("microsoft.compute/virtualmachines", "microsoft.compute/virtualmachinescalesets")
| where id !contains "{{MRG}}"
| where not({{APPLIANCE}})   // network virtual appliances, see P0.6-APPLIANCES
| extend EncryptionAtHost = coalesce(tobool(properties.securityProfile.encryptionAtHost),
                                     tobool(properties.virtualMachineProfile.securityProfile.encryptionAtHost),
                                     false),
         PowerState = iff(type =~ "microsoft.compute/virtualmachinescalesets", "Scale set",
                          tostring(properties.extended.instanceView.powerState.code))
| where not(EncryptionAtHost)
| project Name = name, ResourceType = tolower(type), resourceGroup, subscriptionId, PowerState,
          Size = coalesce(tostring(properties.hardwareProfile.vmSize), tostring(sku.name))
| order by resourceGroup asc, Name asc
'@))

    $q.Add((New-EbrQuery -Id 'DP.5' -Phase 'P2 Data protection' -Engine 'ARG' -Title 'Azure Backup protected items' -Query @'
recoveryservicesresources
| where type =~ "microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems"
| where tostring(properties.sourceResourceId) !contains "{{MRG}}"
| extend ProtectionState = tostring(properties.protectionState),
         LastBackup      = todatetime(properties.lastBackupTime)
| summarize Items       = count(),
            StaleOver48h = countif(LastBackup < ago(2d))
          by ProtectionState
'@))

    $q.Add((New-EbrQuery -Id 'DP.5-STALE' -Phase 'P2 Data protection' -Engine 'ARG' -Title 'Backup items stale or not protected' -Notes 'SecOps worklist input, added in 1.8.0. The items DP.5 counts as StaleOver48h, plus items whose protection state is not Protected. Since 1.10.0 each row carries a Finding: Superseded when a current healthy item protects the same machine (protection moved to another vault, or the machine was moved or rebuilt under the same name and its old resource is gone), Source deleted when the protected resource no longer exists and recovery points are retained, otherwise Protection stopped, Not protected or Backup stale. Internal: names resources, never embedded in the client report.' -Query @'
recoveryservicesresources
| where type =~ "microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems"
| where tostring(properties.sourceResourceId) !contains "{{MRG}}"
| extend ProtectionState  = tostring(properties.protectionState),
         LastBackup       = todatetime(properties.lastBackupTime),
         LastBackupStatus = tostring(properties.lastBackupStatus),
         ItemName         = tostring(properties.friendlyName),
         Workload         = tostring(properties.workloadType),
         Vault            = tostring(split(id, "/")[8]),
         SourceResourceId = tostring(properties.sourceResourceId)
| where LastBackup < ago(2d) or ProtectionState != "Protected"
| extend SourceKey = tolower(SourceResourceId),
         NameKey   = tolower(strcat(Workload, "|", ItemName))
// A current item is Protected with a backup in the last 48 hours.
| join kind=leftouter (
    recoveryservicesresources
    | where type =~ "microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems"
    | where tostring(properties.protectionState) == "Protected" and todatetime(properties.lastBackupTime) >= ago(2d)
    | summarize CurrentForSource = count() by SourceKey = tolower(tostring(properties.sourceResourceId))
  ) on SourceKey
| join kind=leftouter (
    recoveryservicesresources
    | where type =~ "microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems"
    | where tostring(properties.protectionState) == "Protected" and todatetime(properties.lastBackupTime) >= ago(2d)
    | summarize CurrentForName = count(), CurrentBackup = max(todatetime(properties.lastBackupTime))
              by NameKey = tolower(strcat(tostring(properties.workloadType), "|", tostring(properties.friendlyName)))
  ) on NameKey
// Existence is checked for the source types below. Any other source type is assumed to exist.
| join kind=leftouter (
    resources
    | where type in~ ("microsoft.compute/virtualmachines", "microsoft.storage/storageaccounts", "microsoft.compute/disks")
    | project SourceKey = tolower(id), SourceType = type
  ) on SourceKey
| extend SourceProvider = tolower(extract(@"/providers/([^/]+/[^/]+)/[^/]+$", 1, SourceResourceId))
| extend SourceExists = isnotempty(SourceType)
                        or SourceProvider !in ("microsoft.compute/virtualmachines", "microsoft.storage/storageaccounts", "microsoft.compute/disks"),
         CurrentForSource = coalesce(CurrentForSource, 0), CurrentForName = coalesce(CurrentForName, 0)
| extend Finding = case(CurrentForSource > 0, "Superseded",
                        CurrentForName > 0 and not(SourceExists), "Superseded",
                        not(SourceExists), "Source deleted",
                        ProtectionState == "ProtectionStopped", "Protection stopped",
                        ProtectionState != "Protected", "Not protected",
                        "Backup stale")
| extend StaleDays = datetime_diff("day", now(), LastBackup)
| project ItemName, Workload, Vault, resourceGroup, ProtectionState, LastBackupStatus, LastBackup, StaleDays,
          Finding, SourceExists, CurrentBackup, SourceResourceId
| order by StaleDays desc, ItemName asc
'@))

    $q.Add((New-EbrQuery -Id 'DP.5b' -Phase 'P2 Data protection' -Engine 'ARG' -Title 'Virtual machines without a protected backup item' -Notes 'One row per machine with no Protected item in any vault. Since 1.10.0 a machine with a stopped item in one vault and a Protected item in another is counted as protected, and network virtual appliances (P0.6-APPLIANCES) are left out because their vendors do not support Azure Backup of the appliance.' -Query @'
resources
| where type =~ "microsoft.compute/virtualmachines"
| where id !contains "{{MRG}}"
| where not({{APPLIANCE}})   // network virtual appliances, see P0.6-APPLIANCES
| project VmId = tolower(id), VmName = name, resourceGroup,
          PowerState = tostring(properties.extended.instanceView.powerState.code)
| join kind=leftouter (
    recoveryservicesresources
    | where type =~ "microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems"
    | where tostring(properties.sourceResourceId) !contains "{{MRG}}"
    | extend ProtectionState = tostring(properties.protectionState)
    | summarize Items          = count(),
                ProtectedItems = countif(ProtectionState == "Protected"),
                StoppedItems   = countif(ProtectionState == "ProtectionStopped")
              by VmId = tolower(tostring(properties.sourceResourceId))
  ) on VmId
| extend Items = coalesce(Items, 0), ProtectedItems = coalesce(ProtectedItems, 0), StoppedItems = coalesce(StoppedItems, 0)
| where ProtectedItems == 0
| extend ProtectionState = case(Items == 0, "", StoppedItems > 0, "ProtectionStopped", "Not protected")
| project VmName, resourceGroup, PowerState, ProtectionState
| order by resourceGroup asc, VmName asc
'@))

    $q.Add((New-EbrQuery -Id 'DP.5c' -Phase 'P2 Data protection' -Engine 'ARG' -Title 'AVD host pool type for the backup exclusion' -Notes 'Pooled session hosts leave the backup denominator. A Personal pool breaks the exclusion for its hosts. Host pools in the managed resource group are excluded like every other resource there.' -Query @'
resources
| where type =~ "microsoft.desktopvirtualization/hostpools"
| where id !contains "{{MRG}}"
| project HostPool           = name,
          resourceGroup,
          HostPoolType       = tostring(properties.hostPoolType),
          PersonalAssignment = tostring(properties.personalDesktopAssignmentType)
'@))

    $q.Add((New-EbrQuery -Id 'DP.6' -Phase 'P2 Data protection' -Engine 'IPPS' -Title 'DLP policy mode' -Notes 'Only Enable mode is enforcement. Confirm endpoint DLP licensing before claiming endpoint coverage.'))

    $q.Add((New-EbrQuery -Id 'DP.7' -Phase 'P2 Data protection' -Engine 'AH' -Title 'Post-delivery mail removal' -Notes '30-day lookback only. Window-wide counts come from the CyberSOC reports.' -Query @'
EmailPostDeliveryEvents
| where Timestamp between (ago(30d) .. now())
| summarize Events     = count(),
            Succeeded  = countif(ActionResult == "Success"),
            Recipients = dcount(RecipientEmailAddress)
          by ActionType, ActionTrigger
| order by Events desc
'@))

    $q.Add((New-EbrQuery -Id 'DP.7-ZAP' -Phase 'P2 Data protection' -Engine 'EXO' -Title 'Zero-hour auto purge settings' -Notes 'The setting behind DP.7: ZapEnabled on the malware policies, PhishZapEnabled and SpamZapEnabled on the content filter policies. In force when every policy in use has them on.'))

    $q.Add((New-EbrQuery -Id 'DP.8' -Phase 'P2 Data protection' -Engine 'GRAPH' -Title 'SharePoint and OneDrive sharing' -Query @'
GET /v1.0/admin/sharepoint/settings
Permission: SharePointTenantSettings.Read.All
'@ -Notes 'Portal fallback: SharePoint admin center > Policies > Sharing: record the external sharing level for SharePoint and OneDrive, domain restriction mode and allowed domains, and whether guests can reshare.'))

    $q.Add((New-EbrQuery -Id 'DP.10' -Phase 'P2 Data protection' -Engine 'GRAPH' -Title 'Endpoint disk encryption on managed devices' -Query @'
GET /v1.0/deviceManagement/managedDevices?$select=id,operatingSystem,isEncrypted,managedDeviceOwnerType,complianceState
Permission: DeviceManagementManagedDevices.Read.All
'@ -Notes 'Portal fallback: Intune admin center > Devices > All devices, filter on encryption state. Without Intune, the BitLocker row of EW.3 (scid-2090) is the Windows substitute.'))
    #endregion

    #region Phase 2 Detection and Response
    $q.Add((New-EbrQuery -Id 'DR.1' -Phase 'P2 Detection and response' -Engine 'LA' -Title 'Alerts not linked to any incident' -Notes 'Every unlinked row needs an explanation before the deck says every alert reached a disposition.' -Query @'
SecurityAlert
| where TimeGenerated between ({{WINDOW_START}} .. endofday({{WINDOW_END}}))
| summarize arg_max(TimeGenerated, AlertName, ProductName, AlertSeverity) by SystemAlertId
| join kind=leftanti (
    SecurityIncident
    | where TimeGenerated between ({{WINDOW_START}} .. now())
    | mv-expand AlertId = AlertIds to typeof(string)
    | distinct AlertId
  ) on $left.SystemAlertId == $right.AlertId
| summarize UnlinkedAlerts = count() by ProductName, AlertSeverity
| order by UnlinkedAlerts desc
'@))

    $q.Add((New-EbrQuery -Id 'DR.2' -Phase 'P2 Detection and response' -Engine 'ARG' -Title 'Workload protection coverage by plan' -Notes 'Per-resource plan overrides are not visible here. Quote the portal coverage reading. The AI row is a Tier 3 figure.' -Query @'
resources
| where id !contains "{{MRG}}"
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
'@))

    $q.Add((New-EbrQuery -Id 'DR.3' -Phase 'P2 Detection and response' -Engine 'LA' -Title 'Telemetry breadth by table' -Query @'
Usage
| where TimeGenerated between (ago(30d) .. now())
| summarize GB = round(sum(Quantity) / 1000, 2), LastSeen = max(TimeGenerated) by DataType, Solution
| order by GB desc
| take 25
'@))

    $q.Add((New-EbrQuery -Id 'DR.4' -Phase 'P2 Detection and response' -Engine 'AH' -Title 'Domain controller telemetry' -Notes 'Compare with Defender portal > System > Settings > Identities > Sensors. A DC missing here or with a stale LastEvent is the gap.' -Query @'
IdentityLogonEvents
| where Timestamp between (ago(7d) .. now())
| where isnotempty(DestinationDeviceName)
| summarize Events = count(), LastEvent = max(Timestamp) by DomainController = DestinationDeviceName
| order by LastEvent asc
'@))

    $q.Add((New-EbrQuery -Id 'DR.5' -Phase 'P2 Detection and response' -Engine 'AH' -Title 'Vulnerability assessment coverage of onboarded Azure virtual machines' -Notes 'Azure virtual machines only since 1.14.0.' -Query @'
DeviceInfo
| where Timestamp between (ago(7d) .. now())
| summarize arg_max(Timestamp, OnboardingStatus, AzureResourceId) by DeviceId
| where OnboardingStatus == "Onboarded"
| where isnotempty(AzureResourceId)   // Azure virtual machines only
| where AzureResourceId !contains "{{MRG}}"
| join kind=leftouter (
    DeviceTvmSoftwareInventory
    | distinct DeviceId
    | extend HasInventory = true
  ) on DeviceId
| extend Scope = "Azure VM"
| summarize Onboarded = count(), Assessed = countif(HasInventory == true) by Scope
'@))

    $q.Add((New-EbrQuery -Id 'DR.6' -Phase 'P2 Detection and response' -Engine 'ARG' -Title 'Diagnostic and audit logging gaps' -Notes 'Summed Unhealthy is the Tier 3 Enable audit logging figure. Cross-check against the POS.3 row.' -Query @'
securityresources
| where type =~ "microsoft.security/assessments"
| where id !contains "{{MRG}}"
| extend Recommendation = tostring(properties.displayName),
         Status         = tostring(properties.status.code)
| where Recommendation has_any ("resource logs", "diagnostic logs", "auditing", "audit logs", "flow logs")
| summarize Healthy = countif(Status == "Healthy"), Unhealthy = countif(Status == "Unhealthy")
          by Recommendation
| order by Unhealthy desc
'@))

    $q.Add((New-EbrQuery -Id 'DR.7' -Phase 'P2 Detection and response' -Engine 'LA' -Title 'Threat intelligence ingestion' -Query @'
union withsource = SourceTable isfuzzy = true ThreatIntelIndicators, ThreatIntelligenceIndicator
| where TimeGenerated between (ago(30d) .. now())
| extend IndicatorKey = coalesce(tostring(column_ifexists("Id", "")),
                                 tostring(column_ifexists("IndicatorId", "")))
| summarize Indicators = dcount(IndicatorKey), LastIngested = max(TimeGenerated) by SourceTable
'@))

    $q.Add((New-EbrQuery -Id 'DR.8' -Phase 'P2 Detection and response' -Engine 'LA' -Title 'Threat intelligence matches' -Query @'
SecurityAlert
| where TimeGenerated between ({{WINDOW_START}} .. endofday({{WINDOW_END}}))
| where AlertName has_any ("TI map", "Threat Intelligence")
| summarize Alerts = dcount(SystemAlertId) by AlertName
| order by Alerts desc
'@))

    $q.Add((New-EbrQuery -Id 'DR.9' -Phase 'P2 Detection and response' -Engine 'SENTINEL-RULES' -Title 'Analytics rule inventory' -Notes 'Same data as Get-AzSentinelAlertRule, read through the Sentinel ARM API. Also writes DR.9-RULES.'))

    $q.Add((New-EbrQuery -Id 'DR.11' -Phase 'P2 Detection and response' -Engine 'GRAPH' -Title 'Defender for Identity sensors' -Query @'
GET /v1.0/security/identities/sensors
Permission: SecurityIdentitiesSensors.Read.All
'@ -Notes 'Portal fallback: Defender portal > System > Settings > Identities > Sensors. Not in scope for cloud-only tenants. DR.4 shows which domain controllers emit events.'))

    $q.Add((New-EbrQuery -Id 'DR.10' -Phase 'P2 Detection and response' -Engine 'LA' -CombinedOnly -Title 'Closed alerts with a documented disposition' -Notes 'Same alert scope as OUT.1 to OUT.7: ticketed, non-informational incidents. Documented means a classification other than Undetermined and a closing comment. Last 30 days by close time.' -Query @'
SecurityIncident
| where TimeGenerated between (ago(45d) .. now())
| summarize arg_max(TimeGenerated, *) by TenantId, IncidentNumber
| where Status == "Closed" and ClosedTime between (ago(30d) .. now())
| where Severity != "Informational"
| where {{TICKET}}
| summarize Closed             = count(),
            WithClassification = countif(isnotempty(Classification) and Classification != "Undetermined"),
            WithComment        = countif(isnotempty(ClassificationComment)),
            Documented         = countif(isnotempty(Classification) and Classification != "Undetermined" and isnotempty(ClassificationComment))
'@))

    $q.Add((New-EbrQuery -Id 'DR.10-GAPS' -Phase 'P2 Detection and response' -Engine 'LA' -CombinedOnly -Title 'Closed alerts without a documented disposition' -Notes 'SecOps worklist input, added in 1.8.0. The incidents DR.10 counts as not Documented, one row each. Internal: names incidents, never embedded in the client report.' -Query @'
SecurityIncident
| where TimeGenerated between (ago(45d) .. now())
| summarize arg_max(TimeGenerated, *) by TenantId, IncidentNumber
| where Status == "Closed" and ClosedTime between (ago(30d) .. now())
| where Severity != "Informational"
| where {{TICKET}}
| where isempty(Classification) or Classification == "Undetermined" or isempty(ClassificationComment)
| extend Gap = case(isempty(Classification) or Classification == "Undetermined",
                    iff(isempty(ClassificationComment), "No classification and no closing comment", "No classification"),
                    "No closing comment")
| extend TicketRef = extract(@"{{TICKET_PATTERN}}", 0, tostring(Comments))
| extend TicketRef = iff(isempty(TicketRef), extract(@"{{TICKET_PATTERN}}", 0, tostring(ClassificationComment)), TicketRef)
| extend TicketNumber = extract(@"(\d+)\s*$", 1, TicketRef)
| project WorkspaceId = TenantId, IncidentNumber, Title, Severity, ClosedTime, ClosedBy = ModifiedBy, Classification, Gap, TicketRef, TicketNumber, IncidentUrl
| order by ClosedTime desc
'@))

    $q.Add((New-EbrQuery -Id 'DR.12' -Phase 'P2 Detection and response' -Engine 'AH' -Title 'Onboarded Azure virtual machines by device group' -Notes 'Device group membership, Azure virtual machines only since 1.14.0. The automation level of each group (Full, Semi, No automated response) is read at Defender portal > System > Settings > Endpoints > Device groups. There is no documented API for it.' -Query @'
DeviceInfo
| where Timestamp between (ago(30d) .. now())
| where OnboardingStatus == "Onboarded"
| summarize arg_max(Timestamp, MachineGroup, OSPlatform, AzureResourceId) by DeviceId
| where isnotempty(AzureResourceId)   // Azure virtual machines only
| where AzureResourceId !contains "{{MRG}}"
| extend MachineGroup = iff(isempty(MachineGroup), "(no group)", MachineGroup)
| summarize Devices = count() by MachineGroup
| order by Devices desc
'@))

    $q.Add((New-EbrQuery -Id 'DR.13' -Phase 'P2 Detection and response' -Engine 'ARG' -Title 'Diagnostic logging assessments per resource' -Notes 'DR.6 counted per resource instead of per assessment entry. AllHealthy over Resources is the defense in depth logging figure.' -Query @'
securityresources
| where type =~ "microsoft.security/assessments"
| where id !contains "{{MRG}}"
| extend Recommendation = tostring(properties.displayName),
         Status         = tostring(properties.status.code),
         ResourceId     = tolower(tostring(properties.resourceDetails.Id))
| where Recommendation has_any ("resource logs", "diagnostic logs", "auditing", "audit logs", "flow logs")
| where Status in ("Healthy", "Unhealthy")
| summarize Assessments = count(), Unhealthy = countif(Status == "Unhealthy") by ResourceId
| summarize Resources = count(), AllHealthy = countif(Unhealthy == 0), WithGaps = countif(Unhealthy > 0)
'@))

    $q.Add((New-EbrQuery -Id 'DR.6-INITIATIVE' -Phase 'P2 Detection and response' -Engine 'ARG' -Title 'ATMO-MXDR diagnostic logging initiative compliance' -Notes 'Policy states for the ATMO-MXDR-DIAG initiative, per policy definition. EMPTY means the initiative is not assigned in these subscriptions yet. Compliant over Resources is the foundational logging figure once it is.' -Query @'
policyresources
| where type =~ "microsoft.policyinsights/policystates"
| extend AssignmentName = tostring(properties.policyAssignmentName),
         InitiativeName = tostring(properties.policySetDefinitionName),
         DefinitionName = tostring(properties.policyDefinitionName),
         Compliance     = tostring(properties.complianceState),
         ResourceId     = tolower(tostring(properties.resourceId))
| where AssignmentName contains "ATMO-MXDR" or InitiativeName contains "ATMO-MXDR" or DefinitionName contains "ATMO-MXDR"
| where ResourceId !contains "{{MRG}}"
| summarize Resources    = dcount(ResourceId),
            Compliant    = dcountif(ResourceId, Compliance =~ "Compliant"),
            NonCompliant = dcountif(ResourceId, Compliance =~ "NonCompliant")
          by DefinitionName
| order by NonCompliant desc, DefinitionName asc
'@))
    #endregion

    #region Phase 3
    $q.Add((New-EbrQuery -Id 'POS.1' -Phase 'P3 Posture' -Engine 'ARG' -Title 'Defender for Cloud secure score, overall' -Notes 'Classic Defender for Cloud score. The slide must say which score it quotes.' -Query @'
securityresources
| where type =~ "microsoft.security/securescores"
| where name =~ "ascScore"
| extend Current = todouble(properties.score.current),
         Max     = todouble(properties.score.max)
| summarize Current = sum(Current), Max = sum(Max), Subscriptions = count()
| extend Percent = round(100.0 * Current / Max, 1)
'@))

    $q.Add((New-EbrQuery -Id 'POS.2' -Phase 'P3 Posture' -Engine 'ARG' -Title 'Distinct resources assessed by Defender for Cloud' -Notes 'The portal Overview reading is the source of record. Record both values.' -Query @'
securityresources
| where type =~ "microsoft.security/assessments"
| where id !contains "{{MRG}}"
| extend AssessedId = tostring(split(tolower(id), "/providers/microsoft.security/assessments/")[0])
| where AssessedId has "/resourcegroups/"
| summarize Assessments = count() by AssessedId
| summarize AssessedResources = count()
'@))

    $q.Add((New-EbrQuery -Id 'POS.3' -Phase 'P3 Posture' -Engine 'ARG' -Title 'Secure score by control, summed across subscriptions' -Notes 'Score controls are subscription-level, so the managed resource group cannot be excluded. Note that beside any figure taken from here.' -Query @'
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
'@))

    $q.Add((New-EbrQuery -Id 'POS.4' -Phase 'P3 Posture' -Engine 'ARG' -Title 'Assessment health by severity' -Notes 'Quote high, or high and medium combined, as the headline.' -Query @'
securityresources
| where type =~ "microsoft.security/assessments"
| where id !contains "{{MRG}}"
| extend Status   = tostring(properties.status.code),
         Severity = tostring(properties.metadata.severity)
| where Status in ("Healthy", "Unhealthy")
| summarize Healthy = countif(Status == "Healthy"), Total = count() by Severity
| extend PctHealthy = round(100.0 * Healthy / Total, 1)
| order by Severity asc
'@))

    $q.Add((New-EbrQuery -Id 'POS.5' -Phase 'P3 Posture' -Engine 'ARG' -Title 'Regulatory compliance controls passed' -Notes 'Reconcile with Defender for Cloud > Regulatory compliance before quoting.' -Query @'
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
'@))

    $q.Add((New-EbrQuery -Id 'POS.6' -Phase 'P3 Posture' -Engine 'GRAPH' -Title 'Tenant Secure Score, category points and 90-day trend' -Query @'
GET /v1.0/security/secureScores?$top=90
GET /v1.0/security/secureScoreControlProfiles
Permission: SecurityEvents.Read.All
Also writes POS.6-TREND (one row per daily snapshot) and POS.6-CATEGORIES (points by category).
'@ -Notes 'Portal fallback: Defender portal > Exposure management > Secure score: record score, max and read date. Export History (90 days), Recommended actions (category points) and the Comparison view (peer median). POS.6-SUB adds the device secure score and exposure score.'))

    $q.Add((New-EbrQuery -Id 'POS.6-SUB' -Phase 'P3 Posture' -Engine 'DEFENDER-SCORES' -Title 'Device secure score and exposure score (substitute)' -Notes 'Substitute for part of POS.6 from the Defender API: Microsoft Secure Score for Devices and the exposure score. Not the tenant Secure Score.'))

    $q.Add((New-EbrQuery -Id 'POS.7' -Phase 'P3 Posture' -Engine 'LA' -Title 'Defender for Cloud score trend from continuous export' -Notes 'Exported rows keep the model in force when written. Pick one source for the whole series and footnote it. The current month is partial.' -Query @'
SecureScores
| where TimeGenerated between ({{WINDOW_START}} .. now())
| summarize arg_max(TimeGenerated, CurrentScore, MaxScore)
          by Month = startofmonth(TimeGenerated), ScoreId = tolower(_ResourceId),
             ScoreKey = coalesce(tostring(column_ifexists("SecureScoresSubscriptionId", "")),
                                 tostring(column_ifexists("SubscriptionId", "")), TenantId)
| summarize Current = sum(CurrentScore), Max = sum(MaxScore) by Month
| extend Percent = round(100.0 * Current / Max, 1)
| order by Month asc
'@))

    $q.Add((New-EbrQuery -Id 'POS.8' -Phase 'P3 Posture' -Engine 'LA' -Title 'Recommendation health trend from weekly snapshots' -Notes 'Needs continuous export with snapshots enabled.' -Query @'
SecurityRecommendation
| where TimeGenerated between ({{WINDOW_START}} .. now())
| where tobool(IsSnapshot)
| where AssessedResourceId !contains "{{MRG}}"
| summarize arg_max(TimeGenerated, RecommendationState)
          by Week = startofweek(TimeGenerated), AssessedResourceId, RecommendationName
| summarize Healthy   = countif(RecommendationState == "Healthy"),
            Unhealthy = countif(RecommendationState == "Unhealthy")
          by Week
| extend PctHealthy = round(100.0 * Healthy / (Healthy + Unhealthy), 1)
| order by Week asc
'@))
    #endregion

    #region Phase 4
    $q.Add((New-EbrQuery -Id 'BKL.1' -Phase 'P4 Backlog' -Engine 'AH' -Title 'Exploitable vulnerabilities open on Azure virtual machines' -Notes 'Current state only, Azure virtual machines only since 1.14.0. Month-by-month stories cite the CyberSOC report.' -Query @'
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
    | where AzureResourceId !contains "{{MRG}}"
  ) on DeviceId
| extend Scope    = "Azure VM",
         Software = iff(SoftwareName startswith "windows" or SoftwareName contains "linux",
                        "Operating system", "Application")
| summarize ExploitableCves = dcount(CveId), Devices = dcount(DeviceId)
          by Scope, Software, VulnerabilitySeverityLevel
| order by Scope asc, Software asc, VulnerabilitySeverityLevel asc
'@))

    $q.Add((New-EbrQuery -Id 'BKL.2' -Phase 'P4 Backlog' -Engine 'ARG' -Title 'Open Defender for Cloud alerts' -Query @'
securityresources
| where type =~ "microsoft.security/locations/alerts"
| where tostring(properties.resourceIdentifiers) !contains "{{MRG}}"
| where tostring(properties.status) == "Active"
| summarize OpenAlerts = count() by Severity = tostring(properties.severity)
'@))
    #endregion

    $q.ToArray()
}

#endregion

#region Worksheet

function Get-EbrRows {
    param([hashtable]$Results, [string]$Id)
    if (-not $Results.ContainsKey($Id)) { return $null }
    $r = $Results[$Id]
    if ($r.Status -notin 'OK', 'EMPTY', 'PARTIAL') { return $null }
    if ($null -eq $r.Rows) { return , @() }
    , @($r.Rows)
}

function Get-EbrSum {
    param($Rows, [string]$Property, [scriptblock]$Where)
    $total = 0.0
    foreach ($row in $Rows) {
        if ($Where -and -not (& $Where $row)) { continue }
        $v = Get-EbrProp $row $Property
        if ($null -ne $v -and "$v" -ne '') { $total += [double]$v }
    }
    $total
}

function Format-EbrNumber {
    param([double]$Value)
    $Value.ToString('0.##', [cultureinfo]::InvariantCulture)
}

function Format-EbrRatio {
    param([double]$X, [double]$Y)
    if ($Y -le 0) { return ('{0} of {1}' -f (Format-EbrNumber $X), (Format-EbrNumber $Y)) }
    '{0} of {1} ({2}%)' -f (Format-EbrNumber $X), (Format-EbrNumber $Y), (100.0 * $X / $Y).ToString('0.#', [cultureinfo]::InvariantCulture)
}

function Format-EbrMinutes {
    param([double]$Minutes)
    '{0} min ({1} h)' -f (Format-EbrNumber $Minutes), ($Minutes / 60).ToString('0.#', [cultureinfo]::InvariantCulture)
}

function Format-EbrMonth {
    param($Value)
    $d = ConvertTo-EbrUtcDate $Value
    if ($null -eq $d) { return [string]$Value }
    $d.ToString('MMM yyyy', [cultureinfo]::InvariantCulture)
}

function Get-EbrReadDate {
    param([hashtable]$Results, [string]$Id)
    if (-not $Id -or -not $Results.ContainsKey($Id)) { return '' }
    $t = ConvertTo-EbrUtcDate $Results[$Id].ReadTimeUtc
    if ($null -eq $t) { return '' }
    $t.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)
}

# Why an Azure virtual machine is not reporting to Defender for Endpoint with an active sensor
# (EW.1-GAPS, 1.14.0). Eligible: the machine belongs in the onboarding denominator. Covered: it
# counts as protected by endpoint detection. The order is the order the reasons are tested in.
$script:EbrGapReasons = @(
    @{ Key = 'Appliance';    Reason = 'Network virtual appliance, cannot run a sensor';      Eligible = $false; Covered = $false }
    @{ Key = 'ThirdParty';   Reason = 'Covered by a third-party endpoint detection product'; Eligible = $true;  Covered = $true }
    @{ Key = 'Unsupported';  Reason = 'Operating system not supported by the sensor';        Eligible = $false; Covered = $false }
    @{ Key = 'Deallocated';  Reason = 'Deallocated or stopped at collection';                Eligible = $false; Covered = $false }
    @{ Key = 'Discovered';   Reason = 'Discovered only, insufficient information';           Eligible = $false; Covered = $false }
    @{ Key = 'NotSeen';      Reason = 'Not discovered by Defender for Endpoint';             Eligible = $true;  Covered = $false }
    @{ Key = 'Sensor';       Reason = 'Onboarded, sensor not active';                        Eligible = $true;  Covered = $true }
    @{ Key = 'NotOnboarded'; Reason = 'Not onboarded, no endpoint detection found';          Eligible = $true;  Covered = $false }
)

function Get-EbrEdrProductName {
    # The product a piece of evidence names, in the words the report uses.
    param([string]$Text)
    switch -Regex ([string]$Text) {
        '(?i)crowdstrike|falcon' { return 'CrowdStrike Falcon' }
        '(?i)sentinelone'        { return 'SentinelOne' }
        '(?i)carbon ?black'      { return 'Carbon Black' }
        '(?i)cortex'             { return 'Cortex XDR' }
        '(?i)cybereason'         { return 'Cybereason' }
        '(?i)tanium'             { return 'Tanium' }
        '(?i)trellix'            { return 'Trellix' }
        '(?i)cylance'            { return 'Cylance' }
    }
    'a third-party endpoint detection product'
}

function Get-EbrOnboardingGapRows {
    <#
    .SYNOPSIS
        One row per Azure virtual machine that is not onboarded to Defender for Endpoint with an
        active sensor, with the reason. Pure: takes the collected row sets and touches nothing.
    .PARAMETER Known
        EW.1-VMS rows (every Azure VM Defender has seen), or EW.1-DEVICES rows on an older pack.
    .PARAMETER Azure
        EW.1-EDR rows: every Azure VM in Resource Graph with its extensions, EDR assessment and power state.
    .PARAMETER Hosts
        EW.1-EDR-HOSTS rows: hosts reporting to a third-party product through Sentinel.
    .PARAMETER Appliances
        P0.6-APPLIANCES rows.
    .PARAMETER KnownIsComplete
        $true when Known lists every Azure VM Defender has seen (EW.1-VMS), so a machine in Azure
        that is absent from it was never discovered. $false with EW.1-DEVICES, which lists gaps only.
    #>
    param($Known, $Azure, $Hosts, $Appliances, [bool]$KnownIsComplete = $true)
    $lower = { param($v) ([string]$v).Trim().ToLowerInvariant() }
    $short = { param($v) ((& $lower $v) -split '\.')[0] }
    $applianceIds = @{}
    foreach ($a in @($Appliances)) { $id = & $lower (Get-EbrProp $a 'ResourceId'); if ($id) { $applianceIds[$id] = $true } }
    $hostIndex = @{}
    foreach ($h in @($Hosts)) { $n = & $short (Get-EbrProp $h 'Host'); if ($n) { $hostIndex[$n] = $h } }
    $azureIndex = @{}
    foreach ($v in @($Azure)) { $id = & $lower (Get-EbrProp $v 'VmId'); if ($id) { $azureIndex[$id] = $v } }
    $reasonOf = { param($key) $script:EbrGapReasons | Where-Object { $_.Key -eq $key } | Select-Object -First 1 }
    $build = {
        param([string]$Id, $Device, $Vm)
        $status = [string](Get-EbrProp $Device 'OnboardingStatus')
        $sensor = [string](Get-EbrProp $Device 'SensorHealthState')
        $platform = [string](Get-EbrProp $Device 'OSPlatform')
        if (-not $platform -and $Vm) { $platform = [string](Get-EbrProp $Vm 'OsType') }
        $name = [string](Get-EbrProp $Device 'DeviceName')
        if (-not $name -and $Vm) { $name = [string](Get-EbrProp $Vm 'VmName') }
        $power = ([string](Get-EbrProp $Vm 'PowerState')).Replace('PowerState/', '')
        $extensions = @(Get-EbrProp $Vm 'ThirdPartyExtensions' | ForEach-Object { [string]$_ } | Where-Object { $_ })
        $assessment = @(Get-EbrProp $Vm 'EdrAssessment' | ForEach-Object { [string]$_ } | Where-Object { $_ })
        $defenderExt = [int](Get-EbrSum @($Vm) 'DefenderExtension')
        $sentinelHost = $hostIndex[(& $short $name)]
        $isAppliance = $applianceIds.ContainsKey($Id) -or (Test-EbrTrue (Get-EbrProp $Vm 'Appliance')) -or ($platform -match ('(?i)' + $script:EbrNetworkDevicePattern))
        # Third-party evidence, strongest first: an extension, telemetry in Sentinel, then Defender for Cloud
        # reporting an EDR solution installed on a machine that Defender for Endpoint says is not onboarded.
        $evidence = ''
        $sources = @(Get-EbrProp $sentinelHost 'Sources' | ForEach-Object { [string]$_ } | Where-Object { $_ })
        $hostSeen = [string](Get-EbrProp $sentinelHost 'LastSeen')
        if ($hostSeen.Length -gt 10) { $hostSeen = $hostSeen.Substring(0, 10) }
        if ($extensions.Count) { $evidence = 'Extension ' + ($extensions -join ', ') }
        elseif ($sentinelHost) { $evidence = 'Reporting through Sentinel ({0}), last seen {1}' -f ($sources -join ', '), $hostSeen }
        elseif ($status -ne 'Onboarded' -and $defenderExt -eq 0 -and ($assessment -contains 'Healthy')) { $evidence = 'Defender for Cloud reports an EDR solution installed' }
        $key = if ($isAppliance) { 'Appliance' }
        elseif ($evidence) { 'ThirdParty' }
        elseif ($status -eq 'Unsupported') { 'Unsupported' }
        elseif ($power -match '(?i)deallocat|stopp') { 'Deallocated' }
        elseif ($status -eq 'Insufficient info') { 'Discovered' }
        elseif ($null -eq $Device) { 'NotSeen' }
        elseif ($status -eq 'Onboarded') { 'Sensor' }
        else { 'NotOnboarded' }
        $r = & $reasonOf $key
        $product = if ($key -eq 'ThirdParty') { Get-EbrEdrProductName ($evidence + ' ' + ($sources -join ' ')) } else { '' }
        $countedAs = if ($null -eq $Device) { 'NotSeen' } elseif ($status -eq 'Onboarded') { 'Onboarded' } elseif ($status -eq 'Can be onboarded') { 'CanBeOnboarded' } else { 'Other' }
        $gap = if ($null -eq $Device) { 'Not discovered' } elseif ($status -ne 'Onboarded') { 'Not onboarded' } else { 'Sensor ' + $sensor }
        [pscustomobject]@{
            DeviceName = $name
            VmName = [string](Get-EbrProp $Vm 'VmName')
            resourceGroup = [string](Get-EbrProp $Vm 'resourceGroup')
            subscriptionId = [string](Get-EbrProp $Vm 'subscriptionId')
            OSPlatform = $platform
            OnboardingStatus = $(if ($null -eq $Device) { 'Not discovered' } else { $status })
            SensorHealthState = $sensor
            PowerState = $power
            Gap = $gap
            Reason = $r.Reason
            Product = $product
            Evidence = $evidence
            CountedAs = $countedAs
            Eligible = [bool]$r.Eligible
            Covered = [bool]$r.Covered
            LastSeen = [string](Get-EbrProp $Device 'LastSeen')
            AzureResourceId = $Id
        }
    }
    $rows = [System.Collections.Generic.List[object]]::new()
    $seen = @{}
    foreach ($d in @($Known)) {
        if ($null -eq $d) { continue }
        $id = & $lower (Get-EbrProp $d 'AzureResourceId')
        if (-not $id -or $seen.ContainsKey($id)) { continue }
        $seen[$id] = $true
        if ([string](Get-EbrProp $d 'OnboardingStatus') -eq 'Onboarded' -and [string](Get-EbrProp $d 'SensorHealthState') -eq 'Active') { continue }
        $rows.Add((& $build $id $d $azureIndex[$id]))
    }
    if ($KnownIsComplete) {
        foreach ($v in @($Azure)) {
            if ($null -eq $v) { continue }
            $id = & $lower (Get-EbrProp $v 'VmId')
            if (-not $id -or $seen.ContainsKey($id)) { continue }
            $seen[$id] = $true
            $rows.Add((& $build $id $null $v))
        }
    }
    $order = @{}; $i = 0; foreach ($r in $script:EbrGapReasons) { $order[$r.Reason] = $i; $i++ }
    @($rows | Sort-Object { $order[$_.Reason] }, { $_.DeviceName })
}

function New-EbrOnboardingGapResult {
    # EW.1-GAPS from the results already collected. Defender's own device list decides which
    # machines are gaps, so without it the result is UNAVAILABLE rather than a list of every VM.
    param($Ctx)
    $columns = @('DeviceName', 'VmName', 'resourceGroup', 'subscriptionId', 'OSPlatform', 'OnboardingStatus', 'SensorHealthState', 'PowerState', 'Gap', 'Reason', 'Product', 'Evidence', 'CountedAs', 'Eligible', 'Covered', 'LastSeen', 'AzureResourceId')
    $source = 'Derived from EW.1-VMS, EW.1-EDR, EW.1-EDR-HOSTS and P0.6-APPLIANCES'
    $known = Get-EbrRows $Ctx.Results 'EW.1-VMS'
    $complete = $null -ne $known
    if (-not $complete) { $known = Get-EbrRows $Ctx.Results 'EW.1-DEVICES' }
    if ($null -eq $known) {
        return New-EbrResult -ResultId 'EW.1-GAPS' -Status 'UNAVAILABLE' -Source $source -Columns $columns -Detail 'Not a zero: Defender for Endpoint did not return its device list (EW.1-VMS, EW.1-DEVICES), so the machines not reporting to it cannot be named.'
    }
    $azure = Get-EbrRows $Ctx.Results 'EW.1-EDR'
    $hosts = Get-EbrRows $Ctx.Results 'EW.1-EDR-HOSTS'
    $appliances = Get-EbrRows $Ctx.Results 'P0.6-APPLIANCES'
    $rows = @(Get-EbrOnboardingGapRows -Known $known -Azure $azure -Hosts $hosts -Appliances $appliances -KnownIsComplete ($complete -and $null -ne $azure))
    $notes = [System.Collections.Generic.List[string]]::new()
    if ($null -ne $azure) { $notes.Add(('{0} Azure virtual machines in Resource Graph' -f @($azure).Count)) } else { $notes.Add('EW.1-EDR was not available, so machines Defender has never discovered are not listed and no extension evidence was read') }
    if ($complete) {
        $active = @($known | Where-Object { [string](Get-EbrProp $_ 'OnboardingStatus') -eq 'Onboarded' -and [string](Get-EbrProp $_ 'SensorHealthState') -eq 'Active' }).Count
        $notes.Add(('{0} seen by Defender for Endpoint, {1} onboarded with an active sensor' -f @($known).Count, $active))
    }
    else { $notes.Add('Built from EW.1-DEVICES (gaps only), so machines Defender has never discovered are not listed') }
    if ($null -eq $hosts) { $notes.Add('EW.1-EDR-HOSTS was not available, so Sentinel telemetry was not matched') }
    $byReason = @($rows | Group-Object Reason | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
    if ($byReason.Count) { $notes.Add('Not reporting with an active sensor, by reason: ' + ($byReason -join ', ')) } else { $notes.Add('Every Azure virtual machine Defender has seen is onboarded with an active sensor') }
    $status = if ($rows.Count) { 'OK' } else { 'EMPTY' }
    New-EbrResult -ResultId 'EW.1-GAPS' -Status $status -Rows $rows -Columns $columns -Source $source -Detail (($notes -join '. ') + '.')
}

function Get-EbrGapSummary {
    # One sentence for the worksheet note: the EW.1-GAPS reasons, or nothing.
    param([hashtable]$Results)
    $rows = Get-EbrRows $Results 'EW.1-GAPS'
    if ($null -eq $rows) { return '' }
    if ($rows.Count -eq 0) { return ' Every Azure virtual machine seen by Defender is onboarded with an active sensor.' }
    $parts = @($rows | Group-Object Reason | Sort-Object Count -Descending | ForEach-Object { '{0} ({1})' -f $_.Name.ToLowerInvariant(), $_.Count })
    ' Not reporting with an active sensor: {0}. By reason: {1}.' -f $rows.Count, ($parts -join ', ')
}

function Get-EbrWorksheetSpec {
    # One entry per row of the runbook slide map, in the runbook's order. Each Derive block
    # returns @{ Value; Note; Source } or nothing, in which case the row points at the CSV.
    $retiring = {
        param($R)
        $rows = Get-EbrRows $R 'IA.2'; if ($null -eq $rows) { return }
        @{ Value = Format-EbrNumber (Get-EbrSum $rows 'DistinctUsers' { param($r) (Get-EbrProp $r 'Bucket') -eq 'Retiring: SMS or voice' })
           Note  = 'Distinct users who signed in with SMS or voice in the last 30 days (methods used, not registered).' }
    }
    $mfa = {
        param($R)
        $rows = Get-EbrRows $R 'IA.1'; if ($null -eq $rows -or $rows.Count -eq 0) { return }
        # Guests swamp the member figure, so members are the headline and the rest go in the note
        $isMember = { param($r) (Get-EbrProp $r 'UserType') -eq 'Member' }
        $membersIn = Get-EbrSum $rows 'UsersSignedIn' $isMember
        $split = ($rows | ForEach-Object {
                $type = [string](Get-EbrProp $_ 'UserType')
                if (-not $type -or $type -eq '-1') { $type = 'Unknown type' }
                '{0}: {1}' -f $type, (Format-EbrRatio ([double](Get-EbrProp $_ 'UsersChallenged')) ([double](Get-EbrProp $_ 'UsersSignedIn')))
            }) -join ', '
        $all = Format-EbrRatio (Get-EbrSum $rows 'UsersChallenged') (Get-EbrSum $rows 'UsersSignedIn')
        if ($membersIn -gt 0) {
            # Collector 1.12.0 classifies each sign-in by its strongest MFA evidence and counts
            # members whose only sign-ins were reused sessions that no policy checked.
            $memberRow = @($rows | Where-Object { & $isMember $_ }) | Select-Object -First 1
            $unevaluated = ''
            if ($null -ne (Get-EbrProp $memberRow 'NoMfaOnlyUnevaluated')) {
                $unevaluated = ' Members whose only sign-ins reused a session no policy checked (not evaluated, not missing MFA): ' + (Format-EbrNumber (Get-EbrSum $rows 'NoMfaOnlyUnevaluated' $isMember)) + '. Members with a federated sign-in that carried no MFA assertion: ' + (Format-EbrNumber (Get-EbrSum $rows 'FederatedWithoutMfa' $isMember)) + '. Windows logon and device registration are left out. MFA is recognised from the Entra step, the federated provider claim, a phishing-resistant credential, the requirement field, the claim in the token and Require MFA policy results. IA.1-FEDERATION says whether the tenant is federated.'
                if ($null -ne (Get-EbrProp $memberRow 'MfaSessionLinkedOnly')) {
                    $unevaluated += ' Since collector 1.13.0 a sign-in also counts when an earlier sign-in in the same session carried MFA. Members whose only MFA evidence is that inference: ' + (Format-EbrNumber (Get-EbrSum $rows 'MfaSessionLinkedOnly' $isMember)) + '.'
                }
            }
            else { $unevaluated = ' MFA is recognised from the requirement field, the step detail (claim in the token or from an external provider) and MfaDetail.' }
            @{ Value = Format-EbrRatio (Get-EbrSum $rows 'UsersChallenged' $isMember) $membersIn
               Note  = "Members only. By user type: $split. All user types: $all. Members with MFA on every sign-in: " + (Format-EbrRatio (Get-EbrSum $rows 'UsersAlwaysMfa' $isMember) $membersIn) + '. Members whose MFA came from an external identity provider claim: ' + (Format-EbrNumber (Get-EbrSum $rows 'UsersExternalMfa' $isMember)) + '. Successful sign-ins, last 30 days.' + $unevaluated }
        }
        else {
            @{ Value = $all; Note = "No member sign-ins found, so this covers all user types. By user type: $split. Successful sign-ins, last 30 days." }
        }
    }
    $highOutcome = {
        param($R)
        $rows = Get-EbrRows $R 'OUT.3'; if ($null -eq $rows -or $rows.Count -eq 0) { return }
        @{ Value = (($rows | ForEach-Object { '{0}: {1}' -f (Format-EbrMonth (Get-EbrProp $_ 'Month')), (Format-EbrNumber ([double](Get-EbrProp $_ 'High'))) }) -join ', ')
           Note  = 'High severity incidents created per month. Compare full months only.' }
    }

    @(
        @{ Slide = 'Executive summary'; Figure = 'Months of managed security'; Query = 'Contract start date'; Manual = 'Contract start date from the client agreement. Not available from any API.' }
        @{ Slide = 'Executive summary'; Figure = 'Azure resources in the estate'; Query = 'P0.5, summed'; Ids = @('P0.5'); Derive = {
                param($R) $rows = Get-EbrRows $R 'P0.5'; if ($null -eq $rows) { return }
                @{ Value = Format-EbrNumber (Get-EbrSum $rows 'Resources'); Note = 'Estate count, managed resource group excluded. Never caption it as assessed resources.' } } }
        @{ Slide = 'Executive summary'; Figure = 'Resources assessed by Defender for Cloud'; Query = 'Portal Overview, POS.2'; Ids = @('POS.2'); Derive = {
                param($R) $rows = Get-EbrRows $R 'POS.2'; if ($null -eq $rows -or $rows.Count -eq 0) { return }
                @{ Value = Format-EbrNumber ([double](Get-EbrProp $rows[0] 'AssessedResources')); Note = 'POS.2 query value. The Defender for Cloud > Overview portal reading is the source of record: record it beside this one.' } } }
        @{ Slide = 'Executive summary'; Figure = 'Alerts triaged'; Query = 'OUT.5'; Ids = @('OUT.5'); Window = $true; Derive = {
                param($R) $rows = Get-EbrRows $R 'OUT.5'; if ($null -eq $rows) { return }
                @{ Value = Format-EbrNumber (Get-EbrSum $rows 'Alerts'); Note = 'Distinct SecurityAlert records, all products.' } } }
        @{ Slide = 'Executive summary'; Figure = 'Median time to close'; Query = 'OUT.2, row All'; Ids = @('OUT.2', 'OUT.2-ANALYST'); Window = $true; Derive = {
                param($R) $rows = Get-EbrRows $R 'OUT.2'; if ($null -eq $rows) { return }
                $all = $rows | Where-Object { (Get-EbrProp $_ 'Scope') -eq 'All' } | Select-Object -First 1
                if (-not $all) { return @{ Value = 'No closed incidents in window'; Note = '' } }
                $inc = [double](Get-EbrProp $all 'Incidents'); $auto = [double](Get-EbrProp $all 'AutoClosed')
                $allMedian = Format-EbrMinutes ([double](Get-EbrProp $all 'MedianCloseMin'))
                $anAll = $null
                $an = Get-EbrRows $R 'OUT.2-ANALYST'
                if ($an) { $anAll = $an | Where-Object { (Get-EbrProp $_ 'Scope') -eq 'All' } | Select-Object -First 1 }
                if ($inc -gt 0 -and ($auto / $inc) -ge 0.5 -and $anAll) {
                    # Runbook rule: when automation closes most incidents, the median measures the automation
                    $n = [double](Get-EbrProp $anAll 'Incidents')
                    $note = '{0} closed incidents were closed by automation rules, so this quotes analyst-handled incidents only (OUT.2-ANALYST, {1} incidents). Label the tile analyst-handled. All closed incidents: {2}.' -f (Format-EbrRatio $auto $inc), (Format-EbrNumber $n), $allMedian
                    if ($n -lt 20) { $note += ' Only {0} analyst-handled incidents, so quote the median with that caveat.' -f (Format-EbrNumber $n) }
                    return @{ Value = (Format-EbrMinutes ([double](Get-EbrProp $anAll 'MedianCloseMin'))) + ', analyst-handled'; Note = $note; Source = 'OUT.2-ANALYST' }
                }
                $note = 'All closed incidents, creation to close.'
                if ($inc -gt 0 -and ($auto / $inc) -ge 0.25) {
                    $note += ' {0} closed by automation rules.' -f (Format-EbrRatio $auto $inc)
                    if ($anAll) { $note += ' Analyst-handled median (OUT.2-ANALYST): ' + (Format-EbrMinutes ([double](Get-EbrProp $anAll 'MedianCloseMin'))) + '.' }
                }
                if ($inc -lt 20) { $note += ' Only {0} closed incidents, so quote the median with that caveat.' -f (Format-EbrNumber $inc) }
                @{ Value = $allMedian; Note = $note } } }
        @{ Slide = 'Executive summary'; Figure = '90th percentile close, high severity'; Query = 'OUT.2, row High'; Ids = @('OUT.2', 'OUT.2-ANALYST'); Window = $true; Derive = {
                param($R) $rows = Get-EbrRows $R 'OUT.2'; if ($null -eq $rows) { return }
                $high = $rows | Where-Object { (Get-EbrProp $_ 'Scope') -eq 'High' } | Select-Object -First 1
                if (-not $high) { return @{ Value = 'No closed high severity incidents in window'; Note = '' } }
                $inc = [double](Get-EbrProp $high 'Incidents'); $auto = [double](Get-EbrProp $high 'AutoClosed')
                $use = $high; $label = ''; $src = $null
                $note = 'High severity closed incidents: {0}.' -f (Format-EbrNumber $inc)
                if ($inc -gt 0 -and ($auto / $inc) -ge 0.5) {
                    $an = Get-EbrRows $R 'OUT.2-ANALYST'
                    $anHigh = if ($an) { $an | Where-Object { (Get-EbrProp $_ 'Scope') -eq 'High' } | Select-Object -First 1 } else { $null }
                    if ($anHigh) {
                        $use = $anHigh; $label = ', analyst-handled'; $src = 'OUT.2-ANALYST'
                        $note = '{0} high severity incidents were closed by automation rules, so this quotes analyst-handled ones only. All high severity: {1}.' -f (Format-EbrRatio $auto $inc), (Format-EbrMinutes ([double](Get-EbrProp $high 'P90CloseMin')))
                    }
                }
                $n = [double](Get-EbrProp $use 'Incidents')
                if ($n -lt 20) { $note += ' Only {0} high severity incidents, so the 90th percentile is close to the slowest single incident. Quote it with that caveat.' -f (Format-EbrNumber $n) }
                $h = @{ Value = (Format-EbrMinutes ([double](Get-EbrProp $use 'P90CloseMin'))) + $label; Note = $note }
                if ($src) { $h.Source = $src }
                $h } }
        @{ Slide = 'Executive summary'; Figure = 'Microsoft tenant Secure Score'; Query = 'POS.6'; Ids = @('POS.6'); Fallback = 'Defender portal > Exposure management > Secure score (POS.6 needs SecurityEvents.Read.All in Graph). Record score, max and read date.'; Derive = {
                param($R) $rows = Get-EbrRows $R 'POS.6'; if ($null -eq $rows -or $rows.Count -eq 0) { return }
                $s = $rows[0]
                $avg = Get-EbrProp $s 'AllTenantsAverage'
                @{ Value = Format-EbrRatio ([double](Get-EbrProp $s 'Current')) ([double](Get-EbrProp $s 'Max'))
                   Note  = 'Tenant Secure Score from Microsoft Graph, snapshot dated {0}.{1}' -f (Get-EbrProp $s 'ReadDate'), $(if ($null -ne $avg -and "$avg" -ne '') { ' All-tenant average {0} points.' -f (Format-EbrNumber ([double]$avg)) } else { '' }) } } }
        @{ Slide = 'Executive summary'; Figure = 'Defender for Cloud score'; Query = 'POS.1'; Ids = @('POS.1'); Derive = {
                param($R) $rows = Get-EbrRows $R 'POS.1'; if ($null -eq $rows -or $rows.Count -eq 0) { return }
                $r0 = $rows[0]
                @{ Value = Format-EbrRatio ([double](Get-EbrProp $r0 'Current')) ([double](Get-EbrProp $r0 'Max'))
                   Note  = 'Classic Defender for Cloud secure score across {0} subscription(s). Say which score the slide quotes.' -f (Get-EbrProp $r0 'Subscriptions') } } }
        @{ Slide = 'Tier 1'; Figure = 'Confirmed data loss or exfiltration'; Query = 'OUT.4'; Ids = @('OUT.4'); Window = $true; Derive = {
                param($R) $rows = Get-EbrRows $R 'OUT.4'; if ($null -eq $rows) { return }
                $flagged = @($rows | Where-Object { Test-EbrTrue (Get-EbrProp $_ 'ExfilOrImpactTactic') }).Count
                @{ Value = '{0} flagged of {1} true positives' -f $flagged, $rows.Count
                   Note  = 'Zero data loss holds only if no row is flagged, or each flagged ClassificationComment records no data access.' } } }
        @{ Slide = 'Tier 1'; Figure = 'High severity incident reduction'; Query = 'OUT.3'; Ids = @('OUT.3'); Window = $true; Derive = {
                param($R) $rows = Get-EbrRows $R 'OUT.3'; if ($null -eq $rows -or $rows.Count -lt 2) { return }
                $first = $rows[0]; $last = $rows[$rows.Count - 1]
                $a = [double](Get-EbrProp $first 'High'); $b = [double](Get-EbrProp $last 'High')
                $change = if ($a -gt 0) { ', {0}% change' -f (100.0 * ($b - $a) / $a).ToString('0.#', [cultureinfo]::InvariantCulture) } else { '' }
                @{ Value = '{0} ({1}) to {2} ({3}){4}' -f (Format-EbrNumber $a), (Format-EbrMonth (Get-EbrProp $first 'Month')), (Format-EbrNumber $b), (Format-EbrMonth (Get-EbrProp $last 'Month')), $change
                   Note  = 'First full month against last full month.' } } }
        @{ Slide = 'Tier 1'; Figure = 'Monthly incident volume'; Query = 'OUT.3'; Ids = @('OUT.3'); Window = $true; Derive = {
                param($R) $rows = Get-EbrRows $R 'OUT.3'; if ($null -eq $rows) { return }
                @{ Value = (($rows | ForEach-Object { '{0}: {1}' -f (Format-EbrMonth (Get-EbrProp $_ 'Month')), (Format-EbrNumber ([double](Get-EbrProp $_ 'Total'))) }) -join ', ')
                   Note  = 'Total incidents created per month. Severity and classification split in results/OUT.3.csv.' } } }
        @{ Slide = 'Tier 1'; Figure = 'True positives detected and managed'; Query = 'OUT.4'; Ids = @('OUT.4'); Window = $true; Derive = {
                param($R) $rows = Get-EbrRows $R 'OUT.4'; if ($null -eq $rows) { return }
                @{ Value = [string]$rows.Count; Note = 'Each row needs a containment statement in ClassificationComment.' } } }
        @{ Slide = 'Tier 1'; Figure = 'Malicious sign-in to containment'; Query = 'OUT.7, OUT.8'; Ids = @('OUT.7', 'OUT.8'); Window = $true; Derive = {
                param($R) $a = Get-EbrRows $R 'OUT.7'; $b = Get-EbrRows $R 'OUT.8'; if ($null -eq $a -and $null -eq $b) { return }
                $na = if ($null -eq $a) { 'n/a' } else { $a.Count }; $nb = if ($null -eq $b) { 'n/a' } else { $b.Count }
                @{ Value = 'REVIEW'; Note = "Per user: OUT.8 disable time minus the malicious sign-in time in SigninLogs. OUT.7 disruption incidents: $na. OUT.8 disable events: $nb. Incident timeline in the Defender portal is the source of record." } } }
        @{ Slide = 'Tier 2'; Figure = 'Overall program control grade'; Query = 'Phase 2 matrix'; Manual = 'Grade the Phase 2 control matrix (E, P, N) from the collected evidence, then total points earned over points available.' }
        @{ Slide = 'Tier 2'; Figure = 'Foundational controls enforced'; Query = 'Phase 2 matrix'; Manual = 'Count of foundational controls graded E in the Phase 2 matrix.' }
        @{ Slide = 'Tier 2'; Figure = 'Defense in depth in force'; Query = 'Phase 2 matrix'; Manual = 'Count of in-scope defense in depth controls graded E in the Phase 2 matrix.' }
        @{ Slide = 'Tier 2'; Figure = 'Devices onboarded to EDR'; Query = 'EW.1'; Ids = @('EW.1'); Derive = {
                param($R) $rows = Get-EbrRows $R 'EW.1'; if ($null -eq $rows -or $rows.Count -eq 0) { return }
                $on = Get-EbrSum $rows 'Onboarded'; $can = Get-EbrSum $rows 'CanBeOnboarded'
                $isVm = { param($r) (Get-EbrProp $r 'Scope') -eq 'Azure VM' }
                $vmOn = Get-EbrSum $rows 'Onboarded' $isVm; $vmCan = Get-EbrSum $rows 'CanBeOnboarded' $isVm
                @{ Value = Format-EbrRatio $on ($on + $can)
                   Note  = 'Azure virtual machines only. Onboarded over onboarded plus can be onboarded: {0}. Sensor active over onboarded (DR-F1): {1}.{2}' -f (Format-EbrRatio $vmOn ($vmOn + $vmCan)), (Format-EbrRatio (Get-EbrSum $rows 'SensorActive' $isVm) $vmOn), (Get-EbrGapSummary $R) } } }
        @{ Slide = 'Tier 2'; Figure = 'MFA required at sign-in'; Query = 'IA.1'; Ids = @('IA.1'); Derive = $mfa }
        @{ Slide = 'Tier 2'; Figure = 'Workload protection coverage'; Query = 'Portal, DR.2'; Ids = @('DR.2'); Derive = {
                param($R) $rows = Get-EbrRows $R 'DR.2'; if ($null -eq $rows -or $rows.Count -eq 0) { return }
                @{ Value = Format-EbrRatio (Get-EbrSum $rows 'Covered') (Get-EbrSum $rows 'Resources')
                   Note  = 'Plan-covered over plan-eligible resources (DR.2). Per-resource overrides are invisible to ARG: quote the portal coverage reading.' } } }
        @{ Slide = 'Tier 2'; Figure = 'Endpoint anti-malware coverage'; Query = 'EW.3'; Ids = @('EW.3'); Derive = {
                param($R) $rows = Get-EbrRows $R 'EW.3'; if ($null -eq $rows) { return }
                $checks = @($rows | Where-Object { [string](Get-EbrProp $_ 'ConfigurationName') -match 'real-time protection|cloud-delivered protection|behavior monitoring' })
                if ($checks.Count -eq 0) { return }
                $weak = $checks | Sort-Object { [double](Get-EbrProp $_ 'PctCompliant') } | Select-Object -First 1
                $every = ($checks | Sort-Object { [string](Get-EbrProp $_ 'Scope') }, { [string](Get-EbrProp $_ 'ConfigurationName') } | ForEach-Object {
                        '{0}, {1}: {2}' -f (Get-EbrProp $_ 'Scope'), (Get-EbrProp $_ 'ConfigurationName'), (Format-EbrRatio ([double](Get-EbrProp $_ 'Compliant')) ([double](Get-EbrProp $_ 'Devices')))
                    }) -join '. '
                @{ Value = Format-EbrRatio ([double](Get-EbrProp $weak 'Compliant')) ([double](Get-EbrProp $weak 'Devices'))
                   Note  = 'Weakest check: {0} ({1}). A control spanning several checks grades on its weakest. Every check: {2}.' -f (Get-EbrProp $weak 'ConfigurationName'), (Get-EbrProp $weak 'Scope'), $every } } }
        @{ Slide = 'Tier 3'; Figure = 'Exploitable OS findings open'; Query = 'BKL.1'; Ids = @('BKL.1'); Derive = {
                param($R) $rows = Get-EbrRows $R 'BKL.1'; if ($null -eq $rows) { return }
                @{ Value = Format-EbrNumber (Get-EbrSum $rows 'ExploitableCves' { param($r) (Get-EbrProp $r 'Software') -eq 'Operating system' })
                   Note  = 'Distinct exploitable CVEs on OS software across Azure virtual machines, summed across the severity rows. Current state only.' } } }
        @{ Slide = 'Tier 3'; Figure = 'Enable audit logging'; Query = 'DR.6'; Ids = @('DR.6'); Derive = {
                param($R) $rows = Get-EbrRows $R 'DR.6'; if ($null -eq $rows) { return }
                @{ Value = Format-EbrNumber (Get-EbrSum $rows 'Unhealthy'); Note = 'Resources unhealthy on the logging recommendations. Cross-check the POS.3 Enable auditing and logging row.' } } }
        @{ Slide = 'Tier 3'; Figure = 'AI service resources without workload protection'; Query = 'DR.2, row AI'; Ids = @('DR.2'); Derive = {
                param($R) $rows = Get-EbrRows $R 'DR.2'; if ($null -eq $rows) { return }
                $isAi = { param($r) (Get-EbrProp $r 'Plan') -eq 'AI' }
                $res = Get-EbrSum $rows 'Resources' $isAi
                $note = if ($res -eq 0) { 'No Azure OpenAI or AI Services accounts in scope.' } else { 'AI resources not covered by a Standard plan, of {0}.' -f (Format-EbrNumber $res) }
                @{ Value = Format-EbrNumber ($res - (Get-EbrSum $rows 'Covered' $isAi)); Note = $note } } }
        @{ Slide = 'Tier 3'; Figure = 'VMs pending host encryption'; Query = 'DFC.1'; Ids = @('DFC.1', 'DP.4-DETAIL'); Derive = {
                param($R) $rows = Get-EbrRows $R 'DFC.1'; if ($null -eq $rows) { return }
                $enc = @($rows | Where-Object { [string](Get-EbrProp $_ 'Recommendation') -match 'encryption at host' }); if ($enc.Count -eq 0) { return }
                @{ Value = Format-EbrNumber (Get-EbrSum $enc 'Unhealthy'); Note = 'Defender for Cloud unhealthy on encryption at host. Machine names in results/DP.4-DETAIL.csv.' } } }
        @{ Slide = 'Tier 3'; Figure = 'Users on a retiring MFA method'; Query = 'IA.2'; Ids = @('IA.2'); Derive = $retiring }
        @{ Slide = 'Tier 3'; Figure = 'Open security alerts'; Query = 'BKL.2, OUT.1'; Ids = @('BKL.2', 'OUT.1'); Derive = {
                param($R) $a = Get-EbrRows $R 'BKL.2'; $b = Get-EbrRows $R 'OUT.1'; if ($null -eq $a -and $null -eq $b) { return }
                $dfc = if ($null -eq $a) { 0 } else { Get-EbrSum $a 'OpenAlerts' }
                $inc = if ($null -eq $b) { 0 } else { Get-EbrSum $b 'Open' }
                $missing = @(); if ($null -eq $a) { $missing += 'BKL.2' }; if ($null -eq $b) { $missing += 'OUT.1' }
                $note = 'Active Defender for Cloud alerts plus open Sentinel incidents from the window.'
                if ($missing) { $note += ' Missing: ' + ($missing -join ', ') + '.' }
                @{ Value = '{0} ({1} Defender for Cloud active alerts, {2} open Sentinel incidents)' -f (Format-EbrNumber ($dfc + $inc)), (Format-EbrNumber $dfc), (Format-EbrNumber $inc); Note = $note } } }
        @{ Slide = 'Tier 3'; Figure = 'Standing privileged roles'; Query = 'IA.6'; Ids = @('IA.6', 'IA.6-SUB'); Derive = {
                param($R)
                $graph = Get-EbrRows $R 'IA.6'
                if ($null -ne $graph -and $graph.Count -gt 0) {
                    $standing = @($graph | Where-Object { (Get-EbrProp $_ 'AssignmentType') -eq 'Standing' })
                    $eligible = @($graph | Where-Object { (Get-EbrProp $_ 'AssignmentType') -eq 'Eligible' })
                    $other = @($graph | Where-Object { (Get-EbrProp $_ 'AssignmentType') -in 'Activated', 'Time-bound' })
                    $accounts = @($standing | ForEach-Object { Get-EbrProp $_ 'PrincipalId' } | Where-Object { $_ } | Select-Object -Unique).Count
                    $pim = [string](Get-EbrProp $graph[0] 'PimRead')
                    $gap = if ($pim -eq 'NoPermission') { ' Eligible assignments could not be read (the Graph token lacks RoleManagement.Read.Directory), so activated PIM assignments are counted as standing here.' } elseif ($pim -eq 'NoLicense') { ' PIM is not licensed, so every assignment is standing.' } else { '' }
                    return @{ Value  = '{0} standing and {1} eligible assignments, {2} accounts holding a standing role' -f $standing.Count, $eligible.Count, $accounts
                              Note   = 'Privileged Entra role assignments from Microsoft Graph (IA.6), 12 privileged roles. Standing is a permanent active assignment.{0}{1} Exclude documented break-glass accounts before quoting a standing count.' -f $(if ($other.Count) { ' {0} activated or time-bound assignments are listed in results/IA.6.csv.' -f $other.Count } else { '' }), $gap
                              Source = 'IA.6' }
                }
                $rows = Get-EbrRows $R 'IA.6-SUB'; if ($null -eq $rows) { return }
                $accounts = @($rows | ForEach-Object { Get-EbrProp $_ 'AccountObjectId' } | Select-Object -Unique).Count
                @{ Value  = '{0} role assignments across {1} accounts' -f $rows.Count, $accounts
                   Note   = 'Privileged Entra role assignments held now, per IdentityInfo (IA.6-SUB, the substitute for Graph IA.6). Whether each is standing or PIM-eligible is unknown: confirm in PIM and exclude documented break-glass accounts before quoting a standing count.'
                   Source = 'IA.6-SUB' } } }
        @{ Slide = 'Tier 4'; Figure = 'Benchmark controls passed'; Query = 'Portal, POS.5'; Ids = @('POS.5'); Derive = {
                param($R) $rows = Get-EbrRows $R 'POS.5'; if ($null -eq $rows) { return }
                $bench = @($rows | Where-Object { [string](Get-EbrProp $_ 'Standard') -match 'benchmark|MCSB' })
                if ($bench.Count -eq 0) { return }
                $passed = Get-EbrSum $bench 'Passed'
                $names = ($bench | ForEach-Object { Get-EbrProp $_ 'Standard' } | Select-Object -Unique) -join ', '
                @{ Value = Format-EbrRatio $passed ($passed + (Get-EbrSum $bench 'Failed'))
                   Note  = "Passed over passed plus failed for: $names. Reconcile with Defender for Cloud > Regulatory compliance." } } }
        @{ Slide = 'Tier 4'; Figure = 'Category scores against peer median'; Query = 'POS.6, portal comparison'; Manual = 'Defender portal > Exposure management > Secure score > Comparison. POS.6 carries the all-tenant average score, not the per-category peer medians.' }
        @{ Slide = 'Controls'; Figure = 'Pillar grades and every E, P, N mark'; Query = 'Phase 2 tables'; Manual = 'Grade each control from its evidence IDs using the standard E, P, N rule.' }
        @{ Slide = 'Measured outcomes'; Figure = 'Identity compromises contained'; Query = 'OUT.4, OUT.7'; Ids = @('OUT.4', 'OUT.7'); Window = $true; Derive = {
                param($R) $a = Get-EbrRows $R 'OUT.4'; $b = Get-EbrRows $R 'OUT.7'; if ($null -eq $a -and $null -eq $b) { return }
                $na = if ($null -eq $a) { 'n/a' } else { $a.Count }; $nb = if ($null -eq $b) { 'n/a' } else { $b.Count }
                @{ Value = 'REVIEW'; Note = "True positives (OUT.4): $na. Attack disruption incidents (OUT.7): $nb. Count the identity compromises from the incident titles and comments." } } }
        @{ Slide = 'Measured outcomes'; Figure = 'Exploitable findings closed in the patch cycle'; Query = 'BKL.1, CyberSOC report'; Ids = @('BKL.1'); Derive = {
                param($R) $rows = Get-EbrRows $R 'BKL.1'; if ($null -eq $rows) { return }
                @{ Value = 'REVIEW'; Note = 'Open now: {0} exploitable CVE rows summed. The closed-in-cycle figure needs the CyberSOC report.' -f (Format-EbrNumber (Get-EbrSum $rows 'ExploitableCves')) } } }
        @{ Slide = 'Measured outcomes'; Figure = 'Malicious mail removed after delivery'; Query = 'DP.7'; Ids = @('DP.7'); Derive = {
                param($R) $rows = Get-EbrRows $R 'DP.7'; if ($null -eq $rows) { return }
                @{ Value = Format-EbrRatio (Get-EbrSum $rows 'Succeeded') (Get-EbrSum $rows 'Events')
                   Note  = 'Post-delivery removals succeeded over attempted, last 30 days. Window-wide counts come from the CyberSOC reports.' } } }
        @{ Slide = 'Measured outcomes'; Figure = 'Boundary detections investigated'; Query = 'OUT.6'; Ids = @('OUT.6'); Window = $true; Derive = {
                param($R) $rows = Get-EbrRows $R 'OUT.6'; if ($null -eq $rows) { return }
                @{ Value = Format-EbrNumber (Get-EbrSum $rows 'Alerts'); Note = 'Boundary detection keyword list is fixed in OUT.6. Reuse it unchanged next cycle.' } } }
        @{ Slide = 'Measured outcomes'; Figure = 'High severity incidents per month'; Query = 'OUT.3'; Ids = @('OUT.3'); Window = $true; Derive = $highOutcome }
        @{ Slide = 'Measured outcomes'; Figure = 'Users challenged for MFA, x of y'; Query = 'IA.1'; Ids = @('IA.1'); Derive = $mfa }
        @{ Slide = 'Measured outcomes'; Figure = 'Encryption at host, x of y'; Query = 'DFC.1'; Ids = @('DFC.1'); Derive = {
                param($R) $rows = Get-EbrRows $R 'DFC.1'; if ($null -eq $rows) { return }
                $enc = @($rows | Where-Object { [string](Get-EbrProp $_ 'Recommendation') -match 'encryption at host' }); if ($enc.Count -eq 0) { return }
                $h = Get-EbrSum $enc 'Healthy'
                @{ Value = Format-EbrRatio $h ($h + (Get-EbrSum $enc 'Unhealthy')); Note = 'Defender for Cloud healthy over evaluated; accepts Azure Disk Encryption as an alternative.' } } }
        @{ Slide = 'Measured outcomes'; Figure = 'Items under Azure Backup, x of y'; Query = 'DP.5'; Ids = @('DP.5b', 'EW.7', 'DP.5'); Derive = {
                param($R) $vm = Get-EbrRows $R 'EW.7'; $gap = Get-EbrRows $R 'DP.5b'
                if ($null -ne $vm -and $vm.Count -gt 0 -and $null -ne $gap) {
                    $total = [double](Get-EbrProp $vm[0] 'VMs')
                    return @{ Value = Format-EbrRatio ($total - $gap.Count) $total; Note = 'VMs with a protected backup item over all VMs. Remove pooled AVD hosts (DP.5c) from the denominator by hand and footnote it.' }
                }
                $items = Get-EbrRows $R 'DP.5'; if ($null -eq $items) { return }
                @{ Value = Format-EbrRatio (Get-EbrSum $items 'Items' { param($r) (Get-EbrProp $r 'ProtectionState') -eq 'Protected' }) (Get-EbrSum $items 'Items'); Note = 'Protected items over all backup items (DP.5).'; Source = 'DP.5' } } }
        @{ Slide = 'Measured outcomes'; Figure = 'Storage closed to public access with secure transfer'; Query = 'DP.1'; Ids = @('DP.1'); Derive = {
                param($R) $rows = Get-EbrRows $R 'DP.1'; if ($null -eq $rows -or $rows.Count -eq 0) { return }
                $r0 = $rows[0]; $n = [double](Get-EbrProp $r0 'Accounts')
                @{ Value = 'Public network access disabled {0}, secure transfer {1}' -f (Format-EbrRatio ([double](Get-EbrProp $r0 'PublicNetworkOff')) $n), (Format-EbrRatio ([double](Get-EbrProp $r0 'SecureTransfer')) $n)
                   Note  = 'Anonymous blob access off: {0}. Name the property on the slide.' -f (Format-EbrRatio ([double](Get-EbrProp $r0 'AnonymousBlobOff')) $n) } } }
        @{ Slide = 'Measured outcomes'; Figure = 'Workload subnets segmented, x of y'; Query = 'NB.1'; Ids = @('NB.1'); Derive = {
                param($R) $rows = Get-EbrRows $R 'NB.1'; if ($null -eq $rows) { return }
                $work = @($rows | Where-Object { (Get-EbrProp $_ 'SubnetClass') -eq 'Workload' })
                $seg = @($work | Where-Object { Test-EbrTrue (Get-EbrProp $_ 'Segmented') }).Count
                @{ Value = Format-EbrRatio $seg $work.Count; Note = 'Workload subnets only. Confirm each route-table-only subnet points its default route at the firewall.' } } }
        @{ Slide = 'Score model change'; Figure = 'Score and assessed count, before and after'; Query = 'POS.1, POS.2, POS.7'; Ids = @('POS.1', 'POS.2', 'POS.7'); Derive = {
                param($R) $s = Get-EbrRows $R 'POS.1'; $a = Get-EbrRows $R 'POS.2'; if ($null -eq $s -or $s.Count -eq 0) { return }
                $assessed = if ($null -ne $a -and $a.Count -gt 0) { Format-EbrNumber ([double](Get-EbrProp $a[0] 'AssessedResources')) } else { 'n/a' }
                $trend = Get-EbrRows $R 'POS.7'
                $months = if ($null -eq $trend) { 'not available' } else { '{0} month(s)' -f $trend.Count }
                @{ Value = '{0}% across {1} assessed resources (now)' -f (Format-EbrNumber ([double](Get-EbrProp $s[0] 'Percent'))), $assessed
                   Note  = "Earlier value: POS.7 continuous export ($months) or a dated screenshot. Exported rows keep the pre-May 5, 2026 model." } } }
        @{ Slide = 'Score model change'; Figure = 'High severity assessments healthy'; Query = 'POS.4'; Ids = @('POS.4'); Derive = {
                param($R) $rows = Get-EbrRows $R 'POS.4'; if ($null -eq $rows) { return }
                $high = $rows | Where-Object { (Get-EbrProp $_ 'Severity') -eq 'High' } | Select-Object -First 1
                if (-not $high) { return }
                @{ Value = Format-EbrRatio ([double](Get-EbrProp $high 'Healthy')) ([double](Get-EbrProp $high 'Total')); Note = 'Healthy over healthy plus unhealthy, high severity assessments.' } } }
        @{ Slide = 'Tenant posture'; Figure = 'Tenant score trend, 90 days'; Query = 'POS.6-TREND'; Ids = @('POS.6-TREND'); Fallback = 'Defender portal > Exposure management > Secure score > History: export 90 days (POS.6 needs SecurityEvents.Read.All in Graph).'; Derive = {
                param($R) $rows = Get-EbrRows $R 'POS.6-TREND'; if ($null -eq $rows -or $rows.Count -eq 0) { return }
                $sorted = @($rows | Sort-Object { [string](Get-EbrProp $_ 'Date') })
                $first = $sorted[0]; $last = $sorted[-1]
                @{ Value = '{0}% on {1} to {2}% on {3}' -f (Get-EbrProp $first 'Percent'), (Get-EbrProp $first 'Date'), (Get-EbrProp $last 'Percent'), (Get-EbrProp $last 'Date')
                   Note  = '{0} daily snapshots from Microsoft Graph (POS.6-TREND). Points: {1} to {2}.' -f $sorted.Count, (Format-EbrNumber ([double](Get-EbrProp $first 'Current'))), (Format-EbrNumber ([double](Get-EbrProp $last 'Current'))) } } }
        @{ Slide = 'Tenant posture'; Figure = 'Category points and share of the scale'; Query = 'POS.6-CATEGORIES'; Ids = @('POS.6-CATEGORIES'); Fallback = 'Defender portal > Exposure management > Secure score > Recommended actions: export and sum points by category (POS.6 needs SecurityEvents.Read.All in Graph).'; Derive = {
                param($R) $rows = Get-EbrRows $R 'POS.6-CATEGORIES'; if ($null -eq $rows -or $rows.Count -eq 0) { return }
                $parts = @($rows | Sort-Object { -[double](Get-EbrProp $_ 'Available') } | ForEach-Object { '{0} {1}' -f (Get-EbrProp $_ 'Category'), (Format-EbrRatio ([double](Get-EbrProp $_ 'Earned')) ([double](Get-EbrProp $_ 'Available'))) })
                @{ Value = ($parts -join ', ')
                   Note  = 'Earned over available points by category, active control profiles only (POS.6-CATEGORIES). Sums can differ from the headline maximum by a few points.' } } }
        @{ Slide = 'Passwordless'; Figure = 'Users on a retiring method'; Query = 'IA.2'; Ids = @('IA.2'); Derive = $retiring }
        @{ Slide = 'Passwordless'; Figure = 'Phishing-resistant users'; Query = 'IA.2, IA.5'; Ids = @('IA.2'); Derive = {
                param($R) $rows = Get-EbrRows $R 'IA.2'; if ($null -eq $rows) { return }
                $reg = Get-EbrRows $R 'IA.5'
                $registered = if ($null -ne $reg -and $reg.Count -gt 0) { ' Registered for a phishing-resistant method (IA.5): {0}.' -f (Format-EbrRatio ([double](Get-EbrProp $reg[0] 'PhishingResistant')) ([double](Get-EbrProp $reg[0] 'Members'))) } else { ' Registered counts (IA.5) are a portal reading when Graph cannot be read.' }
                @{ Value = Format-EbrNumber (Get-EbrSum $rows 'DistinctUsers' { param($r) (Get-EbrProp $r 'Bucket') -eq 'Phishing-resistant' })
                   Note  = 'Distinct users who signed in with a phishing-resistant method (IA.2).' + $registered } } }
        @{ Slide = 'Passwordless'; Figure = 'Users registered for Authenticator'; Query = 'IA.5'; Ids = @('IA.5'); Fallback = 'Entra admin center > Protection > Authentication methods > User registration details (IA.5 needs AuditLog.Read.All in Graph).'; Derive = {
                param($R) $rows = Get-EbrRows $R 'IA.5'; if ($null -eq $rows -or $rows.Count -eq 0) { return }
                $s = $rows[0]
                @{ Value = Format-EbrRatio ([double](Get-EbrProp $s 'AuthenticatorRegistered')) ([double](Get-EbrProp $s 'Members'))
                   Note  = 'Members registered for Microsoft Authenticator (IA.5). MFA registered: {0}. Phishing-resistant registered: {1}. Phone registered: {2}.' -f (Format-EbrRatio ([double](Get-EbrProp $s 'MfaRegistered')) ([double](Get-EbrProp $s 'Members'))), (Format-EbrNumber ([double](Get-EbrProp $s 'PhishingResistant'))), (Format-EbrNumber ([double](Get-EbrProp $s 'PhoneRegistered'))) } } }
        @{ Slide = 'Delivered and roadmap'; Figure = 'Changes delivered under change control'; Query = 'Change system of record'; Manual = 'Change request numbers from the change system of record (the only CC8.1 evidence).' }
    )
}

function Get-EbrWorksheet {
    param([hashtable]$Results, [datetime]$WindowStart, [datetime]$WindowEnd)
    $inv = [cultureinfo]::InvariantCulture
    $window = 'Window {0} to {1}' -f $WindowStart.ToString('yyyy-MM-dd', $inv), $WindowEnd.ToString('yyyy-MM-dd', $inv)
    foreach ($s in (Get-EbrWorksheetSpec)) {
        $value = ''; $note = ''; $read = ''
        if ($s.ContainsKey('Manual')) {
            $value = 'MANUAL'; $note = $s.Manual
        }
        else {
            $d = $null
            try { $d = & $s.Derive $Results } catch { $d = $null; Write-EbrLog -Level WARNING -Component Worksheet -Message ("{0}: {1}" -f $s.Figure, $_.Exception.Message) }
            if ($d -and $null -ne $d.Value -and "$($d.Value)" -ne '') {
                $value = [string]$d.Value
                $note = [string]$d.Note
                $src = if ($d.ContainsKey('Source') -and $d.Source) { $d.Source } else { $s.Ids[0] }
                $read = Get-EbrReadDate $Results $src
                $partial = @($s.Ids | Where-Object { $Results.ContainsKey($_) -and $Results[$_].Status -eq 'PARTIAL' })
                if ($partial.Count) {
                    $note = (@($note, ('PARTIAL: at least one workspace is missing from {0}, see the manifest.' -f ($partial -join ', '))) | Where-Object { $_ }) -join ' '
                }
            }
            else {
                $state = foreach ($id in $s.Ids) {
                    $st = if ($Results.ContainsKey($id)) { $Results[$id].Status } else { 'NOT RUN' }
                    'results/{0}.csv ({1})' -f $id, $st
                }
                $note = 'Not derived automatically. Read it from ' + ($state -join ', ') + '.'
                $noSource = @($s.Ids | Where-Object { $Results.ContainsKey($_) -and $Results[$_].Status -eq 'UNAVAILABLE' })
                if ($noSource.Count) {
                    $note = 'No figure, not a zero: {0} had no data source in this run (see 00-manifest.csv for why).' -f ($noSource -join ', ')
                }
                # A row that Graph answers when it can, and a portal reading when it cannot
                if ($s.ContainsKey('Fallback') -and $s.Fallback) {
                    $value = 'MANUAL'
                    $note = if ($noSource.Count) { $note + ' ' + $s.Fallback } else { $s.Fallback }
                }
            }
            if ($s.ContainsKey('Window') -and $s.Window) { $note = (@($note, $window) | Where-Object { $_ }) -join ' ' }
        }
        [pscustomobject]@{ Slide = $s.Slide; Figure = $s.Figure; Query = $s.Query; Value = $value; ReadDate = $read; Note = $note }
    }
}

#endregion

#region Azure CLI and REST

function Invoke-EbrAz {
    param([string[]]$Arguments)
    # Native stderr plus ErrorActionPreference=Stop makes Windows PowerShell throw on the first
    # warning az prints. So: Continue, locally, and sort stdout from stderr by hand.
    $eap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & az @Arguments 2>&1
        $code = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $eap }
    $stdout = ($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } | ForEach-Object { [string]$_ }) -join "`n"
    $stderr = ($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | ForEach-Object { $_.ToString() }) -join "`n"
    [pscustomobject]@{ ExitCode = $code; StdOut = $stdout; StdErr = $stderr }
}

function Test-EbrAzCli {
    [bool](Get-Command az -ErrorAction SilentlyContinue)
}

function Get-EbrAzAccounts {
    $res = Invoke-EbrAz @('account', 'list', '--all', '-o', 'json', '--only-show-errors')
    if ($res.ExitCode -ne 0 -or -not $res.StdOut) { return $null }
    # Windows PowerShell 5.1 emits a JSON array as one object; foreach unrolls it either way
    $list = foreach ($a in ($res.StdOut | ConvertFrom-Json)) { $a }
    , @($list)
}

function Invoke-EbrAzLogin {
    # Tenant may be a GUID or a domain: az login --tenant accepts either
    param([string]$Tenant, [string]$Scope)
    # Login experience v2 pops an interactive subscription picker. We have opinions about which
    # subscriptions matter, thanks. Env var only, so the user's az config stays untouched.
    $old = $env:AZURE_CORE_LOGIN_EXPERIENCE_V2
    $env:AZURE_CORE_LOGIN_EXPERIENCE_V2 = 'off'
    try {
        # Interactive browser sign-in. Device code is prohibited by the requirements, so no fallback.
        $azArgs = @('login', '--tenant', $Tenant, '--allow-no-subscriptions', '-o', 'none', '--only-show-errors')
        if ($Scope) { $azArgs += @('--scope', $Scope) }
        $res = Invoke-EbrAz $azArgs
    }
    finally { $env:AZURE_CORE_LOGIN_EXPERIENCE_V2 = $old }
    if ($res.ExitCode -ne 0) { throw "az login failed: $($res.StdErr)" }
}

$script:EbrTokens = @{}
# Requests at least this slow are written to run.log with their duration
$script:EbrSlowRequestSec = 30

function Get-EbrToken {
    param([string]$Resource, [string]$Tenant)
    $key = "$Resource|$Tenant"
    $cached = $script:EbrTokens[$key]
    if ($cached -and $cached.ExpiresUtc -gt (Get-Date).ToUniversalTime().AddMinutes(5)) { return $cached.Token }
    $res = Invoke-EbrAz @('account', 'get-access-token', '--resource', $Resource, '--tenant', $Tenant, '-o', 'json', '--only-show-errors')
    if ($res.ExitCode -ne 0 -or -not $res.StdOut) {
        $why = ($res.StdErr -replace '\s+', ' ').Trim()
        if ($why.Length -gt 2000) { $why = $why.Substring(0, 2000) + '...' }
        throw "az could not issue a token for $Resource in tenant $Tenant. $why"
    }
    $j = $res.StdOut | ConvertFrom-Json
    $exp = $null
    if ($j.PSObject.Properties['expires_on'] -and $j.expires_on) {
        $exp = [DateTimeOffset]::FromUnixTimeSeconds([int64]$j.expires_on).UtcDateTime
    }
    else {
        $exp = ([datetime]::Parse([string]$j.expiresOn, [cultureinfo]::InvariantCulture)).ToUniversalTime()
    }
    $script:EbrTokens[$key] = @{ Token = [string]$j.accessToken; ExpiresUtc = $exp }
    [string]$j.accessToken
}

function Get-EbrHttpStatus {
    param($ErrorRecord)
    try {
        $resp = $ErrorRecord.Exception.Response
        if ($resp -and $resp.StatusCode) { return [int]$resp.StatusCode }
    }
    catch { }
    0
}

function Get-EbrRetryAfter {
    param($ErrorRecord)
    try {
        $h = $ErrorRecord.Exception.Response.Headers
        if ($h) {
            try { if ($h.RetryAfter -and $h.RetryAfter.Delta) { return [int][math]::Ceiling($h.RetryAfter.Delta.TotalSeconds) } } catch { }
            try { $v = $h['Retry-After']; if ($v) { return [int]$v } } catch { }
        }
    }
    catch { }
    $null
}

function Get-EbrErrorText {
    param($ErrorRecord, [int]$Status)
    $parts = [System.Collections.Generic.List[string]]::new()
    $parts.Add([string]$ErrorRecord.Exception.Message)
    $detail = $null
    if ($ErrorRecord.ErrorDetails) { $detail = [string]$ErrorRecord.ErrorDetails.Message }
    if ($detail) {
        $parsed = $null
        try { $parsed = $detail | ConvertFrom-Json } catch { $parsed = $null }
        if ($parsed -and $parsed.PSObject.Properties['error']) {
            # Log Analytics buries the useful bit three innererrors deep. Naturally.
            $e = $parsed.error
            while ($e) {
                $m = Get-EbrProp $e 'message'
                if ($m -and -not $parts.Contains([string]$m)) { $parts.Add([string]$m) }
                $e = Get-EbrProp $e 'innererror'
            }
        }
        else { $parts.Add($detail) }
    }
    $text = ($parts -join ' | ') -replace '\s+', ' '
    if ($text.Length -gt 800) { $text = $text.Substring(0, 800) + '...' }
    if ($Status) { "HTTP ${Status}: $text" } else { $text }
}

function Invoke-EbrRest {
    param(
        [string]$Method,
        [string]$Uri,
        [string]$Resource,
        [string]$Tenant,
        $Body,
        [hashtable]$Headers = @{},
        [int]$TimeoutSec = 120,
        [int]$MaxAttempts = 3
    )
    Assert-EbrReadOnlyRequest -Method $Method -Uri $Uri
    $json = if ($null -ne $Body) { ConvertTo-Json -InputObject $Body -Depth 20 -Compress } else { $null }
    $attempt = 0
    while ($true) {
        $attempt++
        $token = Get-EbrToken -Resource $Resource -Tenant $Tenant
        $h = @{ Authorization = "Bearer $token" }
        foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] }
        $params = @{ Method = $Method; Uri = $Uri; Headers = $h; TimeoutSec = $TimeoutSec; ErrorAction = 'Stop' }
        if ($json) {
            $params.Body = [Text.Encoding]::UTF8.GetBytes($json)
            $params.ContentType = 'application/json; charset=utf-8'
        }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try {
            $resp = Invoke-RestMethod @params
            # A slow run with no slow requests in run.log was held up at the console or the machine, not the network
            if ($sw.Elapsed.TotalSeconds -ge $script:EbrSlowRequestSec) {
                Write-EbrLog -Level INFO -Component Http -Message ('{0} {1} answered in {2}s' -f $Method, ($Uri -replace '\?.*$', ''), [int]$sw.Elapsed.TotalSeconds)
            }
            return $resp
        }
        catch {
            $status = Get-EbrHttpStatus $_
            if ($status -eq 401 -and $attempt -eq 1) {
                $script:EbrTokens.Remove("$Resource|$Tenant")
                continue
            }
            $retryable = ($status -eq 0) -or ($status -in 408, 429, 500, 502, 503, 504)
            if (-not $retryable -or $attempt -ge $MaxAttempts) { throw (Get-EbrErrorText $_ $status) }
            $wait = Get-EbrRetryAfter $_
            if (-not $wait) { $wait = [int]([math]::Pow(2, $attempt) * 2) }
            $wait = [math]::Min($wait, 60)
            Write-EbrLog -Level WARNING -Component Http -Message ("{0} {1} returned {2}, retry {3} in {4}s" -f $Method, ($Uri -replace '\?.*$', ''), $status, $attempt, $wait)
            Start-Sleep -Seconds $wait
        }
    }
}

function Resolve-EbrTenantGuid {
    param([string]$Tenant)
    if (Test-EbrGuid $Tenant) { return $Tenant.ToLowerInvariant() }
    $uri = "https://login.microsoftonline.com/$Tenant/v2.0/.well-known/openid-configuration"
    Assert-EbrReadOnlyRequest -Method GET -Uri $uri
    try { $cfg = Invoke-RestMethod -Method GET -Uri $uri -TimeoutSec 30 -ErrorAction Stop }
    catch { throw "Could not resolve tenant '$Tenant' to an ID. Is that domain verified in the client tenant?" }
    if ([string]$cfg.issuer -match '([0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})') { return $Matches[1].ToLowerInvariant() }
    throw "Tenant '$Tenant' resolved, but the issuer had no tenant ID in it. Microsoft, why."
}

function Get-EbrTenantInfo {
    param([string]$TenantGuid, [string]$ArmTenant)
    try {
        $resp = Invoke-EbrRest -Method GET -Uri 'https://management.azure.com/tenants?api-version=2022-12-01' -Resource 'https://management.azure.com/' -Tenant $ArmTenant
        $t = @($resp.value) | Where-Object { [string]$_.tenantId -eq $TenantGuid } | Select-Object -First 1
        if ($t) {
            $initial = @($t.domains) | Where-Object { $_ -match '^[^.]+\.onmicrosoft\.com$' } | Select-Object -First 1
            return [pscustomobject]@{ DisplayName = [string]$t.displayName; DefaultDomain = [string]$t.defaultDomain; InitialDomain = [string]$initial }
        }
    }
    catch { Write-EbrLog -Level DEBUG -Component Tenant -Message $_.Exception.Message }
    $null
}

#endregion

#region Engine runners

function New-EbrResult {
    param(
        [string]$ResultId, [string]$Status, $Rows = @(), $Columns = @(),
        [string]$Source = '', [string]$Detail = '', [double]$DurationSec = 0
    )
    [pscustomobject]@{
        ResultId    = $ResultId
        Status      = $Status
        Rows        = @($Rows)
        Columns     = @($Columns)
        Source      = $Source
        Detail      = $Detail
        ReadTimeUtc = (Get-Date).ToUniversalTime()
        DurationSec = [math]::Round($DurationSec, 1)
    }
}

function Invoke-EbrArgQuery {
    param([string]$Query, [string[]]$Subscriptions, [string]$Tenant)
    $uri = 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01'
    $rows = [System.Collections.Generic.List[object]]::new()
    $skip = $null
    $page = 0
    $truncated = $false
    do {
        $page++
        $options = @{ '$top' = 1000; resultFormat = 'objectArray' }
        if ($skip) { $options['$skipToken'] = $skip }
        # Scoped to the client's subscriptions every single time. Tenant scope from the
        # Atmosera tenant returns every delegated customer, and nobody wants that slide.
        $body = @{ subscriptions = @($Subscriptions); query = $Query; options = $options }
        $resp = Invoke-EbrRest -Method POST -Uri $uri -Resource 'https://management.azure.com/' -Tenant $Tenant -Body $body -TimeoutSec 180
        if ($null -ne $resp.data) {
            foreach ($d in @($resp.data)) { if ($null -ne $d) { $rows.Add((ConvertTo-EbrRow $d)) } }
        }
        if ([string]$resp.resultTruncated -eq 'true') { $truncated = $true }
        $skip = Get-EbrProp $resp '$skipToken'
        if ($skip) {
            Write-Progress -Id 2 -ParentId 1 -Activity 'Paging Resource Graph' -Status ('Page {0}, {1} rows so far' -f $page, $rows.Count)
            Start-Sleep -Milliseconds 300
        }
    } while ($skip)
    Write-Progress -Id 2 -ParentId 1 -Activity 'Paging Resource Graph' -Completed
    $cols = if ($rows.Count -gt 0) { @($rows[0].PSObject.Properties.Name) } else { @() }
    [pscustomobject]@{ Columns = $cols; Rows = $rows.ToArray(); Detail = $(if ($truncated) { 'Resource Graph flagged the result as truncated.' } else { '' }) }
}

function Invoke-EbrLaQuery {
    param([string]$Query, [string]$WorkspaceCustomerId, [string]$Tenant, [string[]]$AdditionalWorkspaceIds)
    $uri = "https://api.loganalytics.io/v1/workspaces/$WorkspaceCustomerId/query"
    $body = New-EbrLaBody -Query $Query -AdditionalWorkspaceIds $AdditionalWorkspaceIds
    $resp = Invoke-EbrRest -Method POST -Uri $uri -Resource 'https://api.loganalytics.io' -Tenant $Tenant -Body $body -Headers @{ Prefer = 'wait=600' } -TimeoutSec 660
    $conv = ConvertFrom-EbrLaResponse -Response $resp
    $detail = ''
    $err = Get-EbrProp $resp 'error'
    if ($err) { $detail = 'Partial result: ' + [string](Get-EbrProp $err 'message') }
    [pscustomobject]@{ Columns = $conv.Columns; Rows = $conv.Rows; Detail = $detail }
}

function Invoke-EbrLaCombined {
    # One query over several workspaces: the first is the primary, the rest ride along in the
    # body. A workspace reached through a different access tenant cannot share the token.
    param([string]$Query, [object[]]$Workspaces)
    $set = @($Workspaces)
    $primary = $set[0]
    $rest = @($set | Select-Object -Skip 1)
    $others = @($rest | Where-Object { $_.AccessTenant -eq $primary.AccessTenant })
    $excluded = @($rest | Where-Object { $_.AccessTenant -ne $primary.AccessTenant })
    $ids = @($others | ForEach-Object { [string]$_.CustomerId })
    $r = Invoke-EbrLaQuery -Query $Query -WorkspaceCustomerId $primary.CustomerId -AdditionalWorkspaceIds $ids -Tenant $primary.AccessTenant
    [pscustomobject]@{ Columns = $r.Columns; Rows = $r.Rows; Detail = $r.Detail; Used = @(@($primary) + $others); Excluded = $excluded }
}

function Invoke-EbrLaPerWorkspace {
    param([string]$Query, [object[]]$Workspaces, [string]$Label)
    $rows = [System.Collections.Generic.List[object]]::new()
    $usable = [System.Collections.Generic.List[object]]::new()
    $missing = [System.Collections.Generic.List[string]]::new()
    $failed = [System.Collections.Generic.List[string]]::new()
    $cols = @()
    $n = 0
    $set = @($Workspaces)
    foreach ($ws in $set) {
        $n++
        Write-Progress -Id 2 -ParentId 1 -Activity "$Label, one workspace at a time" -Status ('{0} ({1}/{2})' -f $ws.WorkspaceName, $n, $set.Count)
        try {
            $r = Invoke-EbrLaQuery -Query $Query -WorkspaceCustomerId $ws.CustomerId -Tenant $ws.AccessTenant
            foreach ($row in (Add-EbrWorkspaceColumns -Rows $r.Rows -Workspace $ws)) { $rows.Add($row) }
            if ($cols.Count -eq 0) { $cols = @('Workspace', 'WorkspaceId', 'SubscriptionId') + @($r.Columns) }
            $usable.Add($ws)
        }
        catch {
            $m = $_.Exception.Message
            if (Test-EbrMissingTableError $m) { $missing.Add([string]$ws.WorkspaceName) }
            else { $failed.Add(('{0}: {1}' -f $ws.WorkspaceName, $m)) }
        }
    }
    Write-Progress -Id 2 -ParentId 1 -Activity "$Label, one workspace at a time" -Completed
    [pscustomobject]@{ Rows = $rows.ToArray(); Columns = $cols; Usable = $usable.ToArray(); MissingTable = $missing.ToArray(); Failed = $failed.ToArray() }
}

function Invoke-EbrLaAcross {
    # Combined query across workspaces. With -Breakdown it first runs once per workspace and keeps
    # those rows. Without it the per-workspace pass only happens when the combined query trips
    # over one workspace, to find out which one and leave it out. Trust, but verify. Then verify.
    param([string]$Query, [object[]]$Workspaces, [string]$Label, [switch]$Breakdown)
    $all = @($Workspaces)
    $per = $null
    $usable = $all
    if ($Breakdown) {
        $per = Invoke-EbrLaPerWorkspace -Query $Query -Workspaces $all -Label $Label
        $usable = @($per.Usable)
    }
    $combined = $null
    $err = $null
    if ($usable.Count) {
        try { $combined = Invoke-EbrLaCombined -Query $Query -Workspaces $usable }
        catch {
            $err = $_.Exception.Message
            if (-not $per) {
                $per = Invoke-EbrLaPerWorkspace -Query $Query -Workspaces $all -Label $Label
                $usable = @($per.Usable)
                if ($usable.Count -and $usable.Count -lt $all.Count) {
                    try { $combined = Invoke-EbrLaCombined -Query $Query -Workspaces $usable; $err = $null }
                    catch { $err = $_.Exception.Message }
                }
            }
        }
    }
    [pscustomobject]@{ Combined = $combined; Per = $per; Error = $err }
}

function Get-EbrWorkspaceNames {
    param($Workspaces)
    (@($Workspaces) | ForEach-Object { [string]$_.WorkspaceName }) -join ', '
}

$script:EbrLastDefenderCall = [datetime]::MinValue

function Invoke-EbrAhQuery {
    param([string]$Query, [string]$Tenant)
    # Defender allows 45 calls a minute. We pace at 40 because living on the edge is for other scripts.
    $gap = ((Get-Date) - $script:EbrLastDefenderCall).TotalMilliseconds
    if ($gap -lt 1500) { Start-Sleep -Milliseconds ([int](1500 - $gap)) }
    $script:EbrLastDefenderCall = Get-Date
    $resp = Invoke-EbrRest -Method POST -Uri 'https://api.security.microsoft.com/api/advancedqueries/run' -Resource 'https://api.securitycenter.microsoft.com/' -Tenant $Tenant -Body @{ Query = $Query } -TimeoutSec 600
    $conv = ConvertFrom-EbrAhResponse -Response $resp
    [pscustomobject]@{ Columns = $conv.Columns; Rows = $conv.Rows; Detail = '' }
}

function Get-EbrBlobContainerRow {
    # Lists one storage account's blob containers through the Storage resource provider (a GET that
    # Reader can make) and reduces them to counts plus the names of the containers set to public.
    # allowBlobPublicAccess only appears once someone sets it, and not set means allowed.
    param($Account, [string]$Tenant, [int]$NameLimit = 25)
    $setting = ([string]$Account.AllowBlobPublicAccess).ToLowerInvariant()
    $allows = $setting -ne 'false'
    $row = [ordered]@{
        subscriptionId = [string]$Account.subscriptionId; resourceGroup = [string]$Account.resourceGroup; Account = [string]$Account.Account
        AccountAnonymousAccess = $(if ($setting -eq 'false') { 'Disabled' } elseif ($setting -eq 'true') { 'Allowed' } else { 'Not set, allowed' })
        Containers = 0; PublicContainers = 0; ExposedContainers = 0; PublicContainerNames = ''; ReadStatus = 'OK'; ResourceId = [string]$Account.ResourceId
    }
    try {
        $public = [System.Collections.Generic.List[string]]::new()
        $uri = 'https://management.azure.com{0}/blobServices/default/containers?api-version=2023-05-01' -f $Account.ResourceId
        while ($uri) {
            $resp = Invoke-EbrRest -Method GET -Uri $uri -Resource 'https://management.azure.com/' -Tenant $Tenant
            foreach ($c in @($resp.value)) {
                if ($null -eq $c) { continue }
                $row.Containers++
                $level = [string](Get-EbrProp (Get-EbrProp $c 'properties') 'publicAccess')
                if ($level -in 'Blob', 'Container') { $public.Add(('{0} ({1})' -f $c.name, $level)) }
            }
            $uri = Get-EbrProp $resp 'nextLink'
        }
        $row.PublicContainers = $public.Count
        $row.ExposedContainers = $(if ($allows) { $public.Count } else { 0 })
        $row.PublicContainerNames = (@($public | Select-Object -First $NameLimit) -join ', ') + $(if ($public.Count -gt $NameLimit) { ', and {0} more' -f ($public.Count - $NameLimit) } else { '' })
    }
    catch { $row.ReadStatus = [string]$_.Exception.Message }
    [pscustomobject]$row
}

function Get-EbrSentinelRules {
    param([string]$WorkspaceResourceId, [string]$Tenant)
    $rules = [System.Collections.Generic.List[object]]::new()
    $uri = $null
    foreach ($apiVersion in '2024-03-01', '2023-02-01') {
        try {
            $uri = "https://management.azure.com$WorkspaceResourceId/providers/Microsoft.SecurityInsights/alertRules?api-version=$apiVersion"
            $rules.Clear()
            while ($uri) {
                $resp = Invoke-EbrRest -Method GET -Uri $uri -Resource 'https://management.azure.com/' -Tenant $Tenant
                foreach ($v in @($resp.value)) {
                    if ($null -eq $v) { continue }
                    $p = $v.properties
                    $rules.Add([pscustomobject]@{
                            RuleName        = $(if (Get-EbrProp $p 'displayName') { [string]$p.displayName } else { [string]$v.name })
                            Kind            = [string]$v.kind
                            Enabled         = Get-EbrProp $p 'enabled'
                            Severity        = [string](Get-EbrProp $p 'severity')
                            LastModifiedUtc = Format-EbrUtc (Get-EbrProp $p 'lastModifiedUtc')
                            Tactics         = (@(Get-EbrProp $p 'tactics') | Where-Object { $_ }) -join ','
                            TemplateName    = [string](Get-EbrProp $p 'alertRuleTemplateName')
                            RuleId          = [string]$v.name
                        })
                }
                $uri = Get-EbrProp $resp 'nextLink'
            }
            break
        }
        catch {
            # Older regions sometimes reject the newer API version. Try the older one once.
            if ($apiVersion -eq '2023-02-01' -or $_.Exception.Message -notmatch 'api-version|ApiVersion|NoRegisteredProviderFound') { throw }
        }
    }
    $rules.ToArray()
}

function Test-EbrDirectAccess {
    param([string]$TenantGuid, [string[]]$Subscriptions)
    # Direct means: a token issued by the client tenant itself, and Resource Graph sees every
    # subscription with it. Anything less and Lighthouse stays in charge.
    try {
        $null = Get-EbrToken -Resource 'https://management.azure.com/' -Tenant $TenantGuid
        $q = 'resourcecontainers | where type =~ "microsoft.resources/subscriptions" | project subscriptionId'
        $r = Invoke-EbrArgQuery -Query $q -Subscriptions $Subscriptions -Tenant $TenantGuid
        $seen = @($r.Rows | ForEach-Object { ([string](Get-EbrProp $_ 'subscriptionId')).ToLowerInvariant() })
        $missing = @($Subscriptions | Where-Object { $_ -notin $seen })
        [pscustomobject]@{ Ok = ($missing.Count -eq 0); Missing = $missing; Error = $null }
    }
    catch { [pscustomobject]@{ Ok = $false; Missing = @($Subscriptions); Error = $_.Exception.Message } }
}

function Resolve-EbrAccessPath {
    param([string]$TenantGuid, [string]$TenantInput, [string[]]$Subscriptions, $Accounts)
    # Fallback map from az account list. A subscription listed twice prefers its Lighthouse entry,
    # because the direct one has just been shown not to cover everything.
    $fallback = @{}
    foreach ($sub in $Subscriptions) {
        $entries = @(@($Accounts) | Where-Object { $_ -and ([string]$_.id).ToLowerInvariant() -eq $sub })
        $lh = $entries | Where-Object { [string]$_.tenantId -ne $TenantGuid } | Select-Object -First 1
        $fallback[$sub] = if ($lh) { [string]$lh.tenantId } elseif ($entries.Count) { [string]$entries[0].tenantId } else { $TenantGuid }
    }

    $direct = Test-EbrDirectAccess -TenantGuid $TenantGuid -Subscriptions $Subscriptions
    if (-not $direct.Ok) {
        $why = if ($direct.Error) { Get-EbrAzErrorSummary $direct.Error } else { 'it cannot see ' + ($direct.Missing -join ', ') }
        Write-EbrWarn "No direct sign-in to the client tenant covers every subscription ($why)."
        Write-EbrQuip "Through Lighthouse, Resource Graph shows your own delegations instead of the client's role assignments, so IA.7 comes out wrong."
        $answer = 'n'
        try {
            $answer = Read-EbrInput -Prompt ('Run az login --tenant {0} now for direct access? (y/n)' -f $TenantInput) -Default 'y' -Hint 'y or n.' -Validator { param($v) $v -match '^(y|yes|n|no)$' }
        }
        catch { $answer = 'n' }
        if ($answer -match '^y') {
            try {
                Invoke-EbrAzLogin -Tenant $TenantInput
                if ($script:EbrTokens) { $script:EbrTokens.Remove("https://management.azure.com/|$TenantGuid") }
                $direct = Test-EbrDirectAccess -TenantGuid $TenantGuid -Subscriptions $Subscriptions
                if (-not $direct.Ok) { Write-EbrWarn 'Signed in, but the direct sign-in still does not reach every subscription. Using Lighthouse.' }
            }
            catch { Write-EbrWarn ('Direct sign-in failed: ' + (Get-EbrAzErrorSummary $_.Exception.Message)) }
        }
    }

    if ($direct.Ok) {
        $map = @{}
        foreach ($sub in $Subscriptions) { $map[$sub] = $TenantGuid }
        return [pscustomobject]@{ Path = 'Direct'; ArmTenant = $TenantGuid; SubAccess = $map; Warning = $null }
    }
    $arm = $fallback[$Subscriptions[0]]
    $path = if ($arm -eq $TenantGuid) { 'Direct' } else { 'Lighthouse' }
    $warning = $null
    if ($path -eq 'Lighthouse') {
        $warning = "Azure data was read through Lighthouse (managing tenant $arm). Resource Graph then returns the managing tenant's Lighthouse delegations instead of the client's own role assignments, so IA.7 (Owner and User Access Administrator) is incomplete. For a complete IA.7, run az login --tenant $TenantInput and rerun. Every other Azure query reads the same through either path."
    }
    [pscustomobject]@{ Path = $path; ArmTenant = $arm; SubAccess = $fallback; Warning = $warning }
}

function Initialize-EbrDefender {
    param($Ctx)
    $resource = 'https://api.securitycenter.microsoft.com/'
    $scope = 'https://api.securitycenter.microsoft.com/.default'
    $err = $null
    try { $null = Get-EbrToken -Resource $resource -Tenant $Ctx.TenantGuid } catch { $err = $_.Exception.Message }

    if ($err -and (Test-EbrReauthError $err)) {
        # The client's Conditional Access wants a fresher MFA than your saved az session carries.
        # Lighthouse calls never see that policy; Defender calls go straight into the client tenant.
        Write-EbrWarn ('Tenant {0} wants a fresh sign-in before it releases Defender data. {1}' -f $Ctx.TenantGuid, (Get-EbrAzErrorSummary $err))
        Write-EbrQuip 'Its sign-in frequency policy is stricter than your saved session. One browser sign-in sorts it out.'
        $answer = 'n'
        try {
            $answer = Read-EbrInput -Prompt 'Open a browser sign-in for the client tenant now? (y/n)' -Default 'y' -Hint 'y or n.' -Validator { param($v) $v -match '^(y|yes|n|no)$' }
        }
        catch { $answer = 'n' }
        if ($answer -match '^y') {
            try {
                Invoke-EbrAzLogin -Tenant $Ctx.TenantGuid -Scope $scope
                if ($script:EbrTokens) { $script:EbrTokens.Remove("$resource|$($Ctx.TenantGuid)") }
                $null = Get-EbrToken -Resource $resource -Tenant $Ctx.TenantGuid
                $err = $null
            }
            catch { $err = $_.Exception.Message }
        }
    }

    if ($err) {
        $reason = 'No Defender API token: ' + (Get-EbrAzErrorSummary $err)
        if (Test-EbrReauthError $err) { $reason += " Fix: az login --tenant $($Ctx.TenantGuid) --scope $scope, then rerun." }
        $Ctx.DefenderAvailable = $false
        $Ctx.DefenderReason = $reason
        Write-EbrLog -Level WARNING -Component Defender -Message $err
        Write-EbrWarn ('Defender API unavailable. Advanced Hunting queries fall back to the Sentinel workspaces where those hold the tables, and are marked UNAVAILABLE where they do not. ' + $reason)
        $advice = Get-EbrCaBlockAdvice $err
        if ($advice) {
            $Ctx.DefenderAdvice = $advice + ' Meanwhile, every Advanced Hunting query is saved in queries/ to paste into Defender portal > Advanced hunting.'
            Write-EbrQuip $advice
        }
        return
    }
    $Ctx.DefenderAvailable = $true
    Write-EbrOk 'Defender API token issued for the client tenant.'
}

$script:EbrGraphResource = 'https://graph.microsoft.com/'
$script:EbrGraphScope = 'https://graph.microsoft.com/.default'

function Invoke-EbrGraphGet {
    # GET only. Follows @odata.nextLink, so a caller gets every page in one array. A single object
    # (no value array) is returned as is. A 403, or a 401 from a resource that rejects a token
    # without its scope (SharePoint settings do that), is rethrown as GRAPH-403 so the engine can
    # mark the measure UNAVAILABLE with the permission it needs instead of failing it.
    param([string]$Uri, [string]$Tenant, [int]$MaxPages = 200)
    $headers = @{}
    if ($Uri -match '\$count=true|\$search=') { $headers['ConsistencyLevel'] = 'eventual' }
    $all = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    $pages = 0
    while ($next -and $pages -lt $MaxPages) {
        $pages++
        try { $resp = Invoke-EbrRest -Method GET -Uri $next -Resource $script:EbrGraphResource -Tenant $Tenant -Headers $headers }
        catch {
            $m = $_.Exception.Message
            if ($m -match '^HTTP (401|403)\b|Authorization_RequestDenied|Insufficient privileges') { throw ('GRAPH-403 {0}: {1}' -f ($next -replace '\?.*$', ''), $m) }
            throw
        }
        if ($null -eq $resp) { break }
        if ($resp.PSObject.Properties['value']) {
            foreach ($v in @($resp.value)) { if ($null -ne $v) { $all.Add($v) } }
            $next = if ($resp.PSObject.Properties['@odata.nextLink']) { [string]$resp.'@odata.nextLink' } else { $null }
        }
        else { return $resp }
    }
    , $all.ToArray()
}

function Initialize-EbrGraph {
    param($Ctx)
    # Same shape as Initialize-EbrDefender: one token from the Azure CLI, one optional browser
    # sign-in when the tenant wants fresher MFA, then a probe that proves the token reaches Graph.
    $resource = $script:EbrGraphResource
    $scope = $script:EbrGraphScope
    $err = $null
    $probeFailed = $false
    try { $null = Get-EbrToken -Resource $resource -Tenant $Ctx.TenantGuid } catch { $err = $_.Exception.Message }

    if ($err -and (Test-EbrReauthError $err)) {
        Write-EbrWarn ('Tenant {0} wants a fresh sign-in before it releases Microsoft Graph data. {1}' -f $Ctx.TenantGuid, (Get-EbrAzErrorSummary $err))
        $answer = 'n'
        try {
            $answer = Read-EbrInput -Prompt 'Open a browser sign-in for Microsoft Graph in the client tenant now? (y/n)' -Default 'y' -Hint 'y or n.' -Validator { param($v) $v -match '^(y|yes|n|no)$' }
        }
        catch { $answer = 'n' }
        if ($answer -match '^y') {
            try {
                Invoke-EbrAzLogin -Tenant $Ctx.TenantGuid -Scope $scope
                if ($script:EbrTokens) { $script:EbrTokens.Remove("$resource|$($Ctx.TenantGuid)") }
                $null = Get-EbrToken -Resource $resource -Tenant $Ctx.TenantGuid
                $err = $null
            }
            catch { $err = $_.Exception.Message }
        }
    }

    if (-not $err) {
        # The cheapest read any directory token can make. Proves the token is accepted for this tenant.
        try { $null = Invoke-EbrGraphGet -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id' -Tenant $Ctx.TenantGuid }
        catch { $err = $_.Exception.Message; $probeFailed = $true }
    }

    if ($err) {
        $reason = $(if ($probeFailed) { 'Graph probe failed: ' } else { 'No Graph token: ' }) + (Get-EbrAzErrorSummary $err)
        if (Test-EbrReauthError $err) { $reason += " Fix: az login --tenant $($Ctx.TenantGuid) --scope $scope, then rerun." }
        $Ctx.GraphAvailable = $false
        $Ctx.GraphReason = $reason
        Write-EbrLog -Level WARNING -Component Graph -Message $err
        Write-EbrWarn ('Microsoft Graph unavailable. Graph measures are marked UNAVAILABLE with their portal path, and their substitutes still run. ' + $reason)
        $advice = Get-EbrCaBlockAdvice $err
        if ($advice) {
            $Ctx.GraphAdvice = $advice
            Write-EbrQuip $advice
        }
        return
    }
    $Ctx.GraphAvailable = $true
    Write-EbrOk 'Microsoft Graph token issued for the client tenant.'
}

function Get-EbrFallbackTables {
    # Which Defender tables the Sentinel workspaces actually hold (last 30 days). Asked once per
    # run. Returns $null when the check itself failed, so callers stay cautious.
    param($Ctx)
    if (-not $Ctx.FallbackChecked) {
        $Ctx.FallbackChecked = $true
        $x = Invoke-EbrLaAcross -Query (New-EbrTableProbeQuery -Tables (Get-EbrAhTableNames)) -Workspaces $Ctx.Workspaces -Label 'Defender table check'
        if ($x.Combined) {
            $Ctx.FallbackTables = @($x.Combined.Rows | ForEach-Object { [string](Get-EbrProp $_ 'SourceTable') } | Where-Object { $_ } | Select-Object -Unique)
            $held = if ($Ctx.FallbackTables.Count) { $Ctx.FallbackTables -join ', ' } else { 'none' }
            Write-EbrLog -Level INFO -Component Defender -Message "Defender tables held by the Sentinel workspaces (30 days): $held"
        }
        else {
            $Ctx.FallbackTables = $null
            Write-EbrLog -Level WARNING -Component Defender -Message "Defender table check failed: $($x.Error)"
        }
    }
    if ($null -eq $Ctx.FallbackTables) { return $null }
    , @($Ctx.FallbackTables)
}

function Get-EbrDefenderScores {
    param([string]$Tenant)
    $rows = [System.Collections.Generic.List[object]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()
    $targets = [ordered]@{
        'Microsoft Secure Score for Devices' = 'https://api.security.microsoft.com/api/configurationScore'
        'Exposure score'                     = 'https://api.security.microsoft.com/api/exposureScore'
    }
    foreach ($name in $targets.Keys) {
        try {
            $r = Invoke-EbrRest -Method GET -Uri $targets[$name] -Resource 'https://api.securitycenter.microsoft.com/' -Tenant $Tenant
            $rows.Add([pscustomobject]@{ Metric = $name; Score = Get-EbrProp $r 'score'; Time = Format-EbrUtc (Get-EbrProp $r 'time') })
        }
        catch { $errors.Add("${name}: $($_.Exception.Message)") }
    }
    if ($rows.Count -eq 0) { throw ($errors -join ' / ') }
    [pscustomobject]@{ Rows = $rows.ToArray(); Detail = ($errors -join ' / ') }
}

function Find-EbrWorkspaces {
    param([string[]]$Subscriptions, [string]$Tenant)
    $query = @'
resources
| where type =~ "microsoft.operationalinsights/workspaces"
| project WorkspaceResourceId = tolower(id), WorkspaceName = name, CustomerId = tostring(properties.customerId),
          resourceGroup, subscriptionId, location, RetentionDays = toint(properties.retentionInDays)
| join kind=leftouter (
    resources
    | where type =~ "microsoft.operationsmanagement/solutions"
    | where name startswith "SecurityInsights("
    | project WorkspaceResourceId = tolower(tostring(properties.workspaceResourceId)), HasSentinel = true
  ) on WorkspaceResourceId
| extend HasSentinel = coalesce(HasSentinel, false)
| project WorkspaceName, CustomerId, resourceGroup, subscriptionId, location, RetentionDays, HasSentinel, WorkspaceResourceId
| order by HasSentinel desc, WorkspaceName asc
'@
    (Invoke-EbrArgQuery -Query $query -Subscriptions $Subscriptions -Tenant $Tenant).Rows
}

#endregion

#region Exchange Online and Purview

function Install-EbrModuleIfMissing {
    param([string]$Name)
    if (Get-Module -ListAvailable -Name $Name) {
        Import-Module $Name -ErrorAction Stop
        return $true
    }
    Write-EbrInfo "Module '$Name' not found. Installing it for the current user. Riveting stuff."
    try {
        Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Import-Module $Name -ErrorAction Stop
        Write-EbrOk "Installed '$Name'."
        return $true
    }
    catch {
        Write-EbrWarn "Could not install '$Name': $($_.Exception.Message). Install it yourself with: Install-Module $Name -Scope CurrentUser"
        return $false
    }
}

function Invoke-EbrCollector {
    param([string]$ResultId, [string]$Source, [scriptblock]$Block, [string]$MissingCmdletHint)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $rows = @(& $Block | Where-Object { $null -ne $_ } | ForEach-Object { ConvertTo-EbrRow $_ })
        $status = if ($rows.Count -gt 0) { 'OK' } else { 'EMPTY' }
        New-EbrResult -ResultId $ResultId -Status $status -Rows $rows -Source $Source -DurationSec $sw.Elapsed.TotalSeconds
    }
    catch {
        $msg = $_.Exception.Message -replace '\s+', ' '
        if ($_.Exception -is [System.Management.Automation.CommandNotFoundException] -or $msg -match 'is not recognized as (a|the) name of a cmdlet') {
            # Exchange and Purview only load the cmdlets your role allows, so "not recognized" means "not permitted"
            $name = [string]$_.Exception.CommandName
            if (-not $name) { $name = [regex]::Match($msg, "'([^']+)'").Groups[1].Value }
            $msg = ('Connected, but {0} was not loaded. Exchange Online and Purview PowerShell only load the cmdlets your role allows. {1}' -f $name, $MissingCmdletHint).Trim()
        }
        New-EbrResult -ResultId $ResultId -Status 'FAILED' -Source $Source -Detail $msg -DurationSec $sw.Elapsed.TotalSeconds
    }
}

# Every cmdlet Get-EbrExchangeEvidence calls, and nothing else. Each connect builds a temporary
# module of every cmdlet the role allows, and -CommandName limits that to these (Microsoft's own
# advice for scripts, because it makes the connect faster). A cmdlet added to a collector and not
# here never loads and reads as "not loaded", so a test holds the lists to the function body.
$script:EbrExoCommands = @('Get-OrganizationConfig', 'Get-AcceptedDomain', 'Get-AntiPhishPolicy', 'Get-AntiPhishRule',
    'Get-ATPProtectionPolicyRule', 'Get-SafeLinksPolicy', 'Get-SafeAttachmentPolicy', 'Get-MalwareFilterPolicy', 'Get-HostedContentFilterPolicy')
$script:EbrIppsCommands = @('Get-DlpCompliancePolicy')

function Select-EbrSupportedParams {
    # Keeps only the parameters the installed ExchangeOnlineManagement knows, so an older module still connects
    param([string]$Command, [hashtable]$Params)
    $known = (Get-Command -Name $Command -ErrorAction Stop).Parameters
    $out = @{}
    foreach ($k in $Params.Keys) { if ($known.ContainsKey($k)) { $out[$k] = $Params[$k] } }
    $out
}

function Get-EbrExchangeEvidence {
    param([string]$DelegatedOrganization)
    $results = [System.Collections.Generic.List[object]]::new()
    $exoIds = 'IA.9', 'IA.9-RULES', 'IA.9-ATP', 'IA.9-SAFELINKS', 'IA.9-SAFEATTACH', 'DP.7-ZAP'
    $exoHint = 'Either the tenant does not license Defender for Office 365 (Safe Links, Safe Attachments and preset policies need it) or the account has no Security Reader or View-Only Organization Management role there.'
    $dlpHint = 'The signed-in account (GDAP or guest) has no Purview role with DLP Compliance Management or View-Only DLP Compliance Management in this tenant, for example Compliance Administrator or Compliance Data Administrator. Read it in the Purview portal instead: Data loss prevention > Policies.'

    $orgName = $null
    $initialDomain = $null
    # ShowBanner off on both: Purview otherwise downloads and prints its announcement on every connect
    $connect = Select-EbrSupportedParams 'Connect-ExchangeOnline' @{ ShowBanner = $false; CommandName = $script:EbrExoCommands; SkipLoadingFormatData = $true }
    $ipps = Select-EbrSupportedParams 'Connect-IPPSSession' @{ ShowBanner = $false; CommandName = $script:EbrIppsCommands }
    $connect.ErrorAction = 'Stop'; $ipps.ErrorAction = 'Stop'
    if ($DelegatedOrganization) { $connect.DelegatedOrganization = $DelegatedOrganization; $ipps.DelegatedOrganization = $DelegatedOrganization }
    # Each stage is timed into the console and run.log, so a slow run shows which stage held it up
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $lap = { $s = [int]$sw.Elapsed.TotalSeconds; $sw.Restart(); $s }

    try {
        try {
            Write-EbrInfo 'Connecting to Exchange Online. Finish the sign-in window if one opens.'
            Connect-ExchangeOnline @connect
            Write-EbrInfo ('Exchange Online connected in {0}s, sign-in included.' -f (& $lap))
            # The organization's own name and .onmicrosoft.com domain. Better than a GUID for the folder,
            # and Purview's -DelegatedOrganization answered a GUID with an HTML page (2026-10-08).
            try {
                $org = Get-OrganizationConfig -ErrorAction Stop
                $orgName = [string]$org.DisplayName
                $initial = @(Get-AcceptedDomain -ErrorAction Stop | Where-Object { $_.InitialDomain }) | Select-Object -First 1
                $initialDomain = if ($initial) { [string]$initial.DomainName } elseif ([string]$org.Name -match '\.onmicrosoft\.com$') { [string]$org.Name } else { $null }
            }
            catch { Write-EbrLog -Level DEBUG -Component Exchange -Message ('Organization details unavailable: ' + $_.Exception.Message) }
            $results.Add((Invoke-EbrCollector 'IA.9' 'Exchange Online' -MissingCmdletHint $exoHint {
                        Get-AntiPhishPolicy | Select-Object Name, IsDefault, Enabled, PhishThresholdLevel,
                        EnableTargetedUserProtection, EnableOrganizationDomainsProtection,
                        EnableMailboxIntelligenceProtection, EnableSpoofIntelligence }))
            $results.Add((Invoke-EbrCollector 'IA.9-RULES' 'Exchange Online' -MissingCmdletHint $exoHint {
                        Get-AntiPhishRule | ForEach-Object {
                            [pscustomobject]@{ Rule = $_.Name; Policy = [string]$_.AntiPhishPolicy; State = [string]$_.State; Priority = $_.Priority; Domains = (@($_.RecipientDomainIs) -join ',') }
                        } }))
            $results.Add((Invoke-EbrCollector 'IA.9-ATP' 'Exchange Online' -MissingCmdletHint $exoHint {
                        Get-ATPProtectionPolicyRule | ForEach-Object { [pscustomobject]@{ Name = $_.Name; State = [string]$_.State; Priority = $_.Priority } } }))
            $results.Add((Invoke-EbrCollector 'IA.9-SAFELINKS' 'Exchange Online' -MissingCmdletHint $exoHint {
                        Get-SafeLinksPolicy | Select-Object Name, IsBuiltInProtection, EnableSafeLinksForEmail, EnableSafeLinksForTeams,
                        EnableSafeLinksForOffice, ScanUrls, DeliverMessageAfterScan, EnableForInternalSenders, TrackClicks, AllowClickThrough }))
            $results.Add((Invoke-EbrCollector 'IA.9-SAFEATTACH' 'Exchange Online' -MissingCmdletHint $exoHint {
                        Get-SafeAttachmentPolicy | ForEach-Object { [pscustomobject]@{ Name = $_.Name; IsBuiltInProtection = $_.IsBuiltInProtection; Enable = $_.Enable; Action = [string]$_.Action; Redirect = $_.Redirect } } }))
            $results.Add((Invoke-EbrCollector 'DP.7-ZAP' 'Exchange Online' -MissingCmdletHint 'Zero-hour auto purge settings need View-Only Organization Management or Security Reader in Exchange Online.' {
                        @(Get-MalwareFilterPolicy | ForEach-Object { [pscustomobject]@{ Policy = $_.Name; Kind = 'Malware'; IsDefault = $_.IsDefault; ZapEnabled = $_.ZapEnabled; PhishZapEnabled = $null; SpamZapEnabled = $null } }) +
                        @(Get-HostedContentFilterPolicy | ForEach-Object { [pscustomobject]@{ Policy = $_.Name; Kind = 'Spam and phishing'; IsDefault = $_.IsDefault; ZapEnabled = $null; PhishZapEnabled = $_.PhishZapEnabled; SpamZapEnabled = $_.SpamZapEnabled } }) }))
            Write-EbrInfo ('Exchange Online read in {0}s.' -f (& $lap))
        }
        catch {
            $msg = 'Exchange Online sign-in failed: ' + ($_.Exception.Message -replace '\s+', ' ')
            foreach ($id in $exoIds) { if (-not ($results | Where-Object ResultId -eq $id)) { $results.Add((New-EbrResult -ResultId $id -Status 'FAILED' -Source 'Exchange Online' -Detail $msg)) } }
            Write-EbrInfo ('Exchange Online failed after {0}s.' -f (& $lap))
        }

        try {
            if ($DelegatedOrganization -and $initialDomain) { $ipps.DelegatedOrganization = $initialDomain }
            Write-EbrInfo 'Connecting to Purview. Finish the sign-in window if one opens.'
            Connect-IPPSSession @ipps
            Write-EbrInfo ('Purview connected in {0}s, sign-in included.' -f (& $lap))
            $results.Add((Invoke-EbrCollector 'DP.6' 'Security & Compliance' -MissingCmdletHint $dlpHint {
                        Get-DlpCompliancePolicy | ForEach-Object {
                            [pscustomobject]@{ Name = $_.Name; Mode = [string]$_.Mode; Enabled = $_.Enabled; Workloads = (@($_.Workload) -join ','); WhenChangedUtc = Format-EbrUtc $_.WhenChangedUTC }
                        } }))
        }
        catch {
            $results.Add((New-EbrResult -ResultId 'DP.6' -Status 'FAILED' -Source 'Security & Compliance' -Detail ('Purview sign-in failed: ' + ($_.Exception.Message -replace '\s+', ' '))))
            Write-EbrInfo ('Purview failed after {0}s.' -f (& $lap))
        }
    }
    finally {
        $null = & $lap
        try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { }
        Write-EbrInfo ('Signed out of Exchange Online and Purview in {0}s.' -f (& $lap))
    }
    [pscustomobject]@{ Results = $results.ToArray(); OrgName = $orgName; InitialDomain = $initialDomain }
}

#endregion

#region Graph collectors

# Built-in role template IDs treated as privileged. Same list as the runbook IA.6 block. Keep it
# identical across clients.
$script:EbrPrivilegedRoleTemplates = @{
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
    'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = 'Privileged Authentication Administrator'
    '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Conditional Access Administrator'
    '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = 'SharePoint Administrator'
    'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
    '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
    '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2' = 'Hybrid Identity Administrator'
    '3a2c62db-5318-420d-8d74-23affee5d9d5' = 'Intune Administrator'
}

function Get-EbrGraphUri { param([string]$Path, [switch]$Beta) 'https://graph.microsoft.com/' + $(if ($Beta) { 'beta/' } else { 'v1.0/' }) + $Path.TrimStart('/') }

function Add-EbrGraphMissingScope {
    # Records a permission the token lacked, for the combined az login --scope line in the notes.
    # Partial names a measure that still produced rows but with a gap, so the notes can say so.
    param($Ctx, [string]$Permission, [string]$Partial = '')
    if ($Permission -and $Ctx.PSObject.Properties['GraphMissingScopes'] -and $Permission -notin $Ctx.GraphMissingScopes) { $Ctx.GraphMissingScopes.Add($Permission) }
    if ($Partial -and $Ctx.PSObject.Properties['GraphPartial'] -and $Partial -notin $Ctx.GraphPartial) { $Ctx.GraphPartial.Add($Partial) }
}

function Get-EbrGraphList {
    # Every item of a collection, emitted one by one. Callers wrap the call in @(...) and get a
    # flat array of 0, 1 or n items. (Returning ", $array" here would nest inside @(...).) Graph
    # items are never arrays themselves, so one level of flattening is safe.
    param($Ctx, [string]$Path, [switch]$Beta)
    $out = Invoke-EbrGraphGet -Uri (Get-EbrGraphUri $Path -Beta:$Beta) -Tenant $Ctx.TenantGuid
    foreach ($o in @($out)) {
        if ($null -eq $o) { continue }
        if ($o -is [array]) { foreach ($i in $o) { if ($null -ne $i) { $i } } }
        else { $o }
    }
}

function Get-EbrGraphObject {
    param($Ctx, [string]$Path)
    Invoke-EbrGraphGet -Uri (Get-EbrGraphUri $Path) -Tenant $Ctx.TenantGuid
}

function Join-EbrList {
    param($Items)
    (@($Items | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { [string]$_ }) -join ',')
}

function Format-EbrCount {
    param([int]$Count, [string]$One, [string]$Many)
    '{0} {1}' -f $Count, $(if ($Count -eq 1) { $One } else { $Many })
}

function New-EbrGraphResult {
    param($Rows, [string[]]$Columns, [string]$Detail = '', $Extra = @())
    [pscustomobject]@{ Rows = @($Rows | Where-Object { $null -ne $_ }); Columns = @($Columns); Detail = $Detail; Extra = @($Extra) }
}

function Get-EbrGraphSpec {
    # One line per Graph measure: the delegated permission the endpoint needs (named in the
    # UNAVAILABLE detail when the token lacks it) and the function that shapes the rows.
    param([string]$Id)
    $specs = @{
        'IA.1-FEDERATION' = @{ Permission = 'Domain.Read.All'; Collector = 'Get-EbrGraphIA1Federation' }
        'IA.5'  = @{ Permission = 'AuditLog.Read.All'; Collector = 'Get-EbrGraphIA5' }
        'IA.6'  = @{ Permission = 'RoleManagement.Read.Directory'; Collector = 'Get-EbrGraphIA6' }
        'IA.8'  = @{ Permission = 'Policy.Read.All'; Collector = 'Get-EbrGraphIA8' }
        'IA.11' = @{ Permission = 'Policy.Read.All'; Collector = 'Get-EbrGraphIA11' }
        'IA.13' = @{ Permission = 'Policy.Read.All'; Collector = 'Get-EbrGraphIA13' }
        'POS.6' = @{ Permission = 'SecurityEvents.Read.All'; Collector = 'Get-EbrGraphPOS6' }
        'DP.8'  = @{ Permission = 'SharePointTenantSettings.Read.All'; Collector = 'Get-EbrGraphDP8' }
        'DP.10' = @{ Permission = 'DeviceManagementManagedDevices.Read.All'; Collector = 'Get-EbrGraphDP10' }
        'DR.11' = @{ Permission = 'SecurityIdentitiesSensors.Read.All'; Collector = 'Get-EbrGraphDR11' }
        'EW.13' = @{ Permission = 'DeviceManagementConfiguration.Read.All'; Collector = 'Get-EbrGraphEW13' }
    }
    $specs[$Id]
}

function Get-EbrFederationProvider {
    # Names the identity provider from the federation URIs. Okta also shows on a custom sign-in
    # domain through its /app/office365/<app id>/sso/wsfed/ path and its exk app IDs.
    param([string[]]$Uris)
    $text = (@($Uris) | Where-Object { $_ }) -join ' '
    if (-not $text) { 'Unknown' }
    elseif ($text -match 'okta(preview|-emea)?\.com|/app/office365/[^/]+/sso/wsfed/|(^|[:/])exk[0-9A-Za-z]{10,}') { 'Okta' }
    elseif ($text -match '/adfs/') { 'AD FS' }
    elseif ($text -match 'ping(one|identity)\.com|/idp/(prp\.wsf|sts\.wst)') { 'Ping' }
    else { 'Other' }
}

function Get-EbrGraphIA1Federation {
    param($Ctx)
    # Federated domains and federatedIdpMfaBehavior, which decides whether Entra accepts the
    # provider's MFA claim. A subdomain of a federated root inherits the root's federation and
    # Graph answers 404 Request_ResourceNotFound for its federationConfiguration.
    $columns = @('Domain', 'IsRoot', 'IdentityProvider', 'IssuerUri', 'PassiveSignInUri', 'ActiveSignInUri', 'PreferredAuthenticationProtocol', 'FederatedIdpMfaBehavior', 'ConfigSource')
    $domains = @(Get-EbrGraphList -Ctx $Ctx -Path 'domains?$select=id,authenticationType,isRoot,isVerified')
    # Parents before subdomains, so a 404 on a subdomain can name the root it inherits from
    $federated = @($domains | Where-Object { [string](Get-EbrProp $_ 'authenticationType') -eq 'Federated' } |
            Sort-Object { ([string](Get-EbrProp $_ 'id')).Split('.').Count }, { [string](Get-EbrProp $_ 'id') })
    $configured = [System.Collections.Generic.List[string]]::new()
    $unread = 0
    $rows = foreach ($d in $federated) {
        $id = [string](Get-EbrProp $d 'id')
        $cfg = $null
        $source = 'Read'
        try {
            $cfg = @(Get-EbrGraphList -Ctx $Ctx -Path ('domains/{0}/federationConfiguration' -f $id)) | Select-Object -First 1
            if ($null -eq $cfg) { $source = 'No configuration returned' }
        }
        catch {
            $m = $_.Exception.Message
            if ($m -match '^GRAPH-403') { throw }
            if ($m -match '^HTTP 404\b|Request_ResourceNotFound') {
                $parent = @($configured | Where-Object { $id.EndsWith('.' + $_, [StringComparison]::OrdinalIgnoreCase) } | Sort-Object Length -Descending) | Select-Object -First 1
                $source = $(if ($parent) { "Inherited from $parent" } else { 'Not returned (404)' })
            }
            else {
                $unread++
                $source = 'Could not be read: ' + (Get-EbrAzErrorSummary $m)
            }
        }
        if ($null -ne $cfg) { $configured.Add($id) }
        $issuer = [string](Get-EbrProp $cfg 'issuerUri')
        $passive = [string](Get-EbrProp $cfg 'passiveSignInUri')
        $active = [string](Get-EbrProp $cfg 'activeSignInUri')
        [pscustomobject]@{
            Domain                          = $id
            IsRoot                          = Get-EbrProp $d 'isRoot'
            IdentityProvider                = $(if ($null -ne $cfg) { Get-EbrFederationProvider @($issuer, $passive, $active) } else { '' })
            IssuerUri                       = $issuer
            PassiveSignInUri                = $passive
            ActiveSignInUri                 = $active
            PreferredAuthenticationProtocol = [string](Get-EbrProp $cfg 'preferredAuthenticationProtocol')
            FederatedIdpMfaBehavior         = [string](Get-EbrProp $cfg 'federatedIdpMfaBehavior')
            ConfigSource                    = $source
        }
    }
    $detail = 'Read {0}, {1} federated. FederatedIdpMfaBehavior: acceptIfMfaDoneByFederatedIdp and enforceMfaByFederatedIdp count the provider''s MFA, rejectMfaByFederatedIdp ignores it, and empty means the legacy SupportsMfa setting or the default, accept. In a federated tenant IA.1 reads reused sessions as not evaluated, not as missing MFA.' -f (Format-EbrCount $domains.Count 'domain' 'domains'), $federated.Count
    if ($unread) { $detail += ' ' + (Format-EbrCount $unread 'federation configuration' 'federation configurations') + ' could not be read, see ConfigSource.' }
    New-EbrGraphResult -Rows @($rows) -Columns $columns -Detail $detail
}

function Get-EbrGraphIA5 {
    param($Ctx)
    $users = $null
    try { $users = @(Get-EbrGraphList -Ctx $Ctx -Path 'reports/authenticationMethods/userRegistrationDetails?$filter=userType eq ''member''&$top=999') }
    catch {
        if ($_.Exception.Message -match '^GRAPH-403') { throw }
        # Some tenants reject the userType filter. Read everything and filter here.
        $users = @(Get-EbrGraphList -Ctx $Ctx -Path 'reports/authenticationMethods/userRegistrationDetails?$top=999' | Where-Object { [string](Get-EbrProp $_ 'userType') -eq 'member' })
    }
    $methods = { param($u) (@(Get-EbrProp $u 'methodsRegistered') -join ',') }
    $flag = { param($u, [string]$name) Test-EbrTrue (Get-EbrProp $u $name) }
    $admins = @($users | Where-Object { & $flag $_ 'isAdmin' })
    $row = [pscustomobject]@{
        Members                 = @($users).Count
        MfaRegistered           = @($users | Where-Object { & $flag $_ 'isMfaRegistered' }).Count
        MfaCapable              = @($users | Where-Object { & $flag $_ 'isMfaCapable' }).Count
        SsprRegistered          = @($users | Where-Object { & $flag $_ 'isSsprRegistered' }).Count
        PasswordlessCapable     = @($users | Where-Object { & $flag $_ 'isPasswordlessCapable' }).Count
        PhishingResistant       = @($users | Where-Object { (& $methods $_) -match 'fido2|passKey|windowsHelloForBusiness|certificate' }).Count
        PhoneRegistered         = @($users | Where-Object { (& $methods $_) -match 'mobilePhone|officePhone|alternateMobilePhone' }).Count
        AuthenticatorRegistered = @($users | Where-Object { (& $methods $_) -match 'microsoftAuthenticator' }).Count
        Admins                  = $admins.Count
        AdminsMfaRegistered     = @($admins | Where-Object { & $flag $_ 'isMfaRegistered' }).Count
    }
    New-EbrGraphResult -Rows @($row) -Columns @('Members', 'MfaRegistered', 'MfaCapable', 'SsprRegistered', 'PasswordlessCapable', 'PhishingResistant', 'PhoneRegistered', 'AuthenticatorRegistered', 'Admins', 'AdminsMfaRegistered') -Detail 'Members only. Methods registered, not methods used (IA.2 has those). Phone registration does not separate SMS from voice.'
}

function Get-EbrGraphIA6 {
    param($Ctx)
    $priv = $script:EbrPrivilegedRoleTemplates
    $rows = [System.Collections.Generic.List[object]]::new()
    $add = {
        param($a, [string]$kind)
        $roleId = ([string](Get-EbrProp $a 'roleDefinitionId')).ToLowerInvariant()
        if (-not $priv.ContainsKey($roleId)) { return }
        $p = Get-EbrProp $a 'principal'
        $type = ([string](Get-EbrProp $p '@odata.type')) -replace '^#microsoft\.graph\.', ''
        if (-not $type) { $type = 'unknown' }
        $rows.Add([pscustomobject]@{
                Role = $priv[$roleId]; RoleDefinitionId = $roleId; AssignmentType = $kind
                PrincipalType = $type; PrincipalId = [string](Get-EbrProp $a 'principalId')
                PrincipalDisplayName = [string](Get-EbrProp $p 'displayName'); PrincipalUpn = [string](Get-EbrProp $p 'userPrincipalName')
                DirectoryScope = [string](Get-EbrProp $a 'directoryScopeId'); EndDateUtc = Format-EbrUtc (Get-EbrProp $a 'endDateTime')
                PimRead = $pimRead
            })
    }
    # PimRead tells the worksheet and report whether eligibility was visible: Yes, NoLicense (no
    # Entra ID P2, so standing is the whole truth) or NoPermission (a gap, so the share is not graded).
    $pimRead = 'Yes'
    $detail = 'Standing is a permanent active assignment. Activated is a PIM activation in progress. Eligible needs activation. Exclude documented break-glass accounts before quoting a standing count.'
    try {
        foreach ($a in @(Get-EbrGraphList -Ctx $Ctx -Path 'roleManagement/directory/roleAssignmentScheduleInstances?$expand=principal')) {
            $kind = if ([string](Get-EbrProp $a 'assignmentType') -eq 'Activated') { 'Activated' } elseif (Get-EbrProp $a 'endDateTime') { 'Time-bound' } else { 'Standing' }
            & $add $a $kind
        }
        foreach ($e in @(Get-EbrGraphList -Ctx $Ctx -Path 'roleManagement/directory/roleEligibilityScheduleInstances?$expand=principal')) { & $add $e 'Eligible' }
    }
    catch {
        # No PIM (no Entra ID P2) answers 400 here, and a token without RoleManagement.Read.Directory
        # answers 403. Either way roleAssignments still lists every active assignment as standing.
        $why = $_.Exception.Message
        $rows.Clear()
        $pimRead = if ($why -match '^GRAPH-403') { 'NoPermission' } else { 'NoLicense' }
        if ($pimRead -eq 'NoPermission') {
            Add-EbrGraphMissingScope -Ctx $Ctx -Permission 'RoleManagement.Read.Directory' -Partial 'IA.6 (PIM eligibility, so activated PIM assignments count as standing)'
            $detail = 'PIM schedule instances need RoleManagement.Read.Directory, which the token lacks, so every active privileged assignment is listed as Standing from roleAssignments. If the tenant uses PIM, activated assignments are counted as standing and eligible ones are not visible until that permission is granted.'
        }
        else {
            $detail = 'PIM schedule instances were not readable (' + (Get-EbrAzErrorSummary $why) + '), so every privileged assignment is listed as Standing from roleAssignments. Without Entra ID P2 that is the whole picture.'
        }
        foreach ($a in @(Get-EbrGraphList -Ctx $Ctx -Path 'roleManagement/directory/roleAssignments?$expand=principal')) { & $add $a 'Standing' }
    }
    New-EbrGraphResult -Rows $rows.ToArray() -Columns @('Role', 'RoleDefinitionId', 'AssignmentType', 'PrincipalType', 'PrincipalId', 'PrincipalDisplayName', 'PrincipalUpn', 'DirectoryScope', 'EndDateUtc', 'PimRead') -Detail $detail
}

function Get-EbrGraphCaPolicies {
    param($Ctx)
    if (-not $Ctx.GraphCache.ContainsKey('caPolicies')) {
        $Ctx.GraphCache['caPolicies'] = @(Get-EbrGraphList -Ctx $Ctx -Path 'identity/conditionalAccess/policies')
    }
    , @($Ctx.GraphCache['caPolicies'])
}

function Get-EbrGraphIA8 {
    param($Ctx)
    $policies = Get-EbrGraphCaPolicies -Ctx $Ctx
    $who = {
        param($users)
        $parts = @(
            foreach ($pair in @(@('includeUsers', 'user', 'users'), @('includeGroups', 'group', 'groups'), @('includeRoles', 'role', 'roles'))) {
                $list = @(Get-EbrProp $users $pair[0] | Where-Object { $_ -and $_ -ne 'None' })
                if ($list -contains 'All') { 'All'; break }
                if ($list.Count) { Format-EbrCount $list.Count $pair[1] $pair[2] }
            })
        $parts -join ', '
    }
    $whoNot = {
        param($users)
        $parts = @(
            foreach ($pair in @(@('excludeUsers', 'user', 'users'), @('excludeGroups', 'group', 'groups'), @('excludeRoles', 'role', 'roles'))) {
                $list = @(Get-EbrProp $users $pair[0] | Where-Object { $_ })
                if ($list.Count) { Format-EbrCount $list.Count $pair[1] $pair[2] }
            })
        $parts -join ', '
    }
    $apps = {
        param($list)
        $list = @($list | Where-Object { $_ -and $_ -ne 'None' })
        if ($list -contains 'All') { return 'All' }
        if ($list -contains 'MicrosoftAdminPortals') { return (@('Microsoft Admin Portals') + @(if ($list.Count -gt 1) { Format-EbrCount ($list.Count - 1) 'app' 'apps' })) -join ', ' }
        if ($list.Count) { Format-EbrCount $list.Count 'app' 'apps' } else { '' }
    }
    $rows = foreach ($p in $policies) {
        $c = Get-EbrProp $p 'conditions'; $u = Get-EbrProp $c 'users'; $a = Get-EbrProp $c 'applications'; $g = Get-EbrProp $p 'grantControls'
        $name = [string](Get-EbrProp $p 'displayName')
        [pscustomobject]@{
            Policy              = $name
            State               = [string](Get-EbrProp $p 'state')
            IncludeUsers        = & $who $u
            ExcludeUsers        = & $whoNot $u
            IncludeApplications = & $apps (Get-EbrProp $a 'includeApplications')
            ExcludeApplications = & $apps (Get-EbrProp $a 'excludeApplications')
            UserActions         = Join-EbrList (Get-EbrProp $a 'includeUserActions')
            ClientAppTypes      = Join-EbrList (Get-EbrProp $c 'clientAppTypes')
            AuthenticationFlows = [string](Get-EbrProp (Get-EbrProp $c 'authenticationFlows') 'transferMethods')
            SignInRiskLevels    = Join-EbrList (Get-EbrProp $c 'signInRiskLevels')
            UserRiskLevels      = Join-EbrList (Get-EbrProp $c 'userRiskLevels')
            Platforms           = Join-EbrList (Get-EbrProp (Get-EbrProp $c 'platforms') 'includePlatforms')
            Grants              = Join-EbrList (Get-EbrProp $g 'builtInControls')
            GrantOperator       = [string](Get-EbrProp $g 'operator')
            AuthStrength        = [string](Get-EbrProp (Get-EbrProp $g 'authenticationStrength') 'displayName')
            Baseline            = ($name -match '^ATMO-MXDR-CA-')
            ModifiedUtc         = Format-EbrUtc (Get-EbrProp $p 'modifiedDateTime')
        }
    }
    # The policies exactly as Graph returned them. The flattened rows above keep counts only, and the
    # Conditional Access evaluation needs the excluded user, group and role IDs and the policy IDs
    # that sign-in records cite (IA.8-SIGNINS).
    $raw = @(foreach ($p in $policies) { $p })
    $extra = @(@{ Id = 'IA.8-POLICIES'; Rows = $raw; Columns = @('id', 'displayName', 'state', 'conditions', 'grantControls', 'sessionControls', 'createdDateTime', 'modifiedDateTime'); Detail = 'Raw Conditional Access policies from GET /v1.0/identity/conditionalAccess/policies. Internal: carries user, group and role IDs, the report embeds counts only.' })
    # Security defaults block legacy authentication and require MFA for administrators when no
    # Conditional Access policy is in use, so the evaluation needs to know whether they are on.
    try {
        $defaults = Get-EbrGraphObject -Ctx $Ctx -Path 'policies/identitySecurityDefaultsEnforcementPolicy'
        $extra += @{ Id = 'IA.8-DEFAULTS'; Rows = @([pscustomobject]@{ SecurityDefaults = (Test-EbrTrue (Get-EbrProp $defaults 'isEnabled')) }); Columns = @('SecurityDefaults'); Detail = 'Security defaults enforcement policy, isEnabled.' }
    }
    catch {
        if ($_.Exception.Message -match '^GRAPH-403') { Add-EbrGraphMissingScope -Ctx $Ctx -Permission 'Policy.Read.All' -Partial 'IA.8 (security defaults state)' }
    }
    New-EbrGraphResult -Rows @($rows) -Columns @('Policy', 'State', 'IncludeUsers', 'ExcludeUsers', 'IncludeApplications', 'ExcludeApplications', 'UserActions', 'ClientAppTypes', 'AuthenticationFlows', 'SignInRiskLevels', 'UserRiskLevels', 'Platforms', 'Grants', 'GrantOperator', 'AuthStrength', 'Baseline', 'ModifiedUtc') -Detail 'A policy in enabledForReportingButNotEnforced state is report-only and does not count toward E. Baseline marks the ATMO-MXDR-CA policies. IA.8-POLICIES keeps the raw policy JSON.' -Extra $extra
}

function Get-EbrGraphIA11 {
    param($Ctx)
    $policies = Get-EbrGraphCaPolicies -Ctx $Ctx
    $levels = { param($p, [string]$name) @(Get-EbrProp (Get-EbrProp $p 'conditions') $name | Where-Object { $_ }) }
    $enabledForAll = { param($p) ([string](Get-EbrProp $p 'state') -eq 'enabled') -and (@(Get-EbrProp (Get-EbrProp (Get-EbrProp $p 'conditions') 'users') 'includeUsers') -contains 'All') }
    $signIn = @($policies | Where-Object { (& $levels $_ 'signInRiskLevels').Count -gt 0 })
    $user = @($policies | Where-Object { (& $levels $_ 'userRiskLevels').Count -gt 0 })
    $signInAll = @($signIn | Where-Object { & $enabledForAll $_ })
    $userAll = @($user | Where-Object { & $enabledForAll $_ })
    $phs = 'Unknown'
    $phsDetail = ''
    try {
        $sync = @(Get-EbrGraphList -Ctx $Ctx -Path 'directory/onPremisesSynchronization')
        if ($sync.Count -eq 0) { $phs = 'Cloud-only' }
        elseif (@($sync | Where-Object { Test-EbrTrue (Get-EbrProp (Get-EbrProp $_ 'features') 'passwordSyncEnabled') }).Count) { $phs = 'On' }
        else { $phs = 'Off' }
    }
    catch {
        if ($_.Exception.Message -match '^GRAPH-403') { Add-EbrGraphMissingScope -Ctx $Ctx -Permission 'OnPremDirectorySynchronization.Read.All' -Partial 'IA.11 (password hash sync)' }
        $phsDetail = ' Password hash sync could not be read (' + (Get-EbrAzErrorSummary $_.Exception.Message) + '). It needs OnPremDirectorySynchronization.Read.All.'
    }
    $row = [pscustomobject]@{
        SignInRiskPolicies = $signIn.Count
        SignInRiskPolicy   = (@($signInAll | ForEach-Object { [string](Get-EbrProp $_ 'displayName') }) -join ', ')
        SignInRiskAllUsers = ($signInAll.Count -gt 0)
        UserRiskPolicies   = $user.Count
        UserRiskPolicy     = (@($userAll | ForEach-Object { [string](Get-EbrProp $_ 'displayName') }) -join ', ')
        UserRiskAllUsers   = ($userAll.Count -gt 0)
        InForce            = ($signInAll.Count -gt 0 -and $userAll.Count -gt 0)
        PasswordHashSync   = $phs
    }
    New-EbrGraphResult -Rows @($row) -Columns @('SignInRiskPolicies', 'SignInRiskPolicy', 'SignInRiskAllUsers', 'UserRiskPolicies', 'UserRiskPolicy', 'UserRiskAllUsers', 'InForce', 'PasswordHashSync') -Detail ('In force when an enabled policy with a sign-in risk condition and one with a user risk condition both include all users. Needs Entra ID P2. Leaked credential detection in a hybrid tenant also needs password hash sync.' + $phsDetail)
}

function Get-EbrGraphIA13 {
    param($Ctx)
    $auth = Get-EbrGraphObject -Ctx $Ctx -Path 'policies/authorizationPolicy'
    $grant = @(Get-EbrProp (Get-EbrProp $auth 'defaultUserRolePermissions') 'permissionGrantPoliciesAssigned' | Where-Object { $_ })
    # ManagePermissionGrantsForOwnedResource.* policies cover Teams chat and team apps, not what a
    # user may consent to for themselves, so they do not change the classification.
    $self = @($grant | Where-Object { $_ -notmatch '^ManagePermissionGrantsForOwnedResource\.' })
    $lowRisk = '^ManagePermissionGrantsForSelf\.microsoft-user-default-(low|recommended)$'
    $consent = if ($self.Count -eq 0) { 'None' }
    elseif ($self -match 'microsoft-user-default-legacy') { 'Any application' }
    elseif (@($self | Where-Object { $_ -notmatch $lowRisk }).Count -eq 0) { 'Low risk, verified publishers' }
    else { 'Custom' }
    $workflow = $null
    $wfDetail = ''
    try { $workflow = Test-EbrTrue (Get-EbrProp (Get-EbrGraphObject -Ctx $Ctx -Path 'policies/adminConsentRequestPolicy') 'isEnabled') }
    catch {
        if ($_.Exception.Message -match '^GRAPH-403') { Add-EbrGraphMissingScope -Ctx $Ctx -Permission 'Policy.Read.All' -Partial 'IA.13 (admin consent workflow, so Governed is unknown)' }
        $wfDetail = ' The admin consent workflow could not be read, so Governed is unknown rather than false: ' + (Get-EbrAzErrorSummary $_.Exception.Message)
    }
    $row = [pscustomobject]@{
        PermissionGrantPolicies = ($grant -join ',')
        UserConsent             = $consent
        AdminConsentWorkflow    = $workflow
        RiskyAppConsent         = Test-EbrTrue (Get-EbrProp $auth 'allowUserConsentForRiskyApps')
        Governed                = $(if ($null -eq $workflow) { $null } else { ($consent -in 'None', 'Low risk, verified publishers') -and $workflow })
    }
    New-EbrGraphResult -Rows @($row) -Columns @('PermissionGrantPolicies', 'UserConsent', 'AdminConsentWorkflow', 'RiskyAppConsent', 'Governed') -Detail ('Governed when users cannot consent, or only to low-risk permissions from verified publishers, and the admin consent request workflow is on.' + $wfDetail)
}

function Get-EbrGraphPOS6 {
    param($Ctx)
    $columns = @('ReadDate', 'Current', 'Max', 'Percent', 'IdentityPct', 'DevicePct', 'AppsPct', 'DataPct', 'AllTenantsAverage', 'Snapshots')
    $scores = @(Get-EbrGraphList -Ctx $Ctx -Path 'security/secureScores?$top=90' | Where-Object { $null -ne (Get-EbrProp $_ 'currentScore') -and (Get-EbrProp $_ 'createdDateTime') })
    if ($scores.Count -eq 0) { return New-EbrGraphResult -Rows @() -Columns $columns -Detail 'No Secure Score snapshots were returned.' }
    $sorted = @($scores | Sort-Object { ConvertTo-EbrUtcDate (Get-EbrProp $_ 'createdDateTime') })
    $latest = $sorted[-1]
    $profiles = @{}
    $profDetail = ''
    try { foreach ($p in @(Get-EbrGraphList -Ctx $Ctx -Path 'security/secureScoreControlProfiles?$top=400')) { $profiles[[string](Get-EbrProp $p 'id')] = $p } }
    catch { $profDetail = ' Control profiles could not be read, so category points are empty: ' + (Get-EbrAzErrorSummary $_.Exception.Message) }
    $cats = [ordered]@{}
    foreach ($c in @(Get-EbrProp $latest 'controlScores')) {
        $prof = $profiles[[string](Get-EbrProp $c 'controlName')]
        if (-not $prof) { continue }
        $cat = [string](Get-EbrProp $c 'controlCategory')
        if (-not $cat) { $cat = [string](Get-EbrProp $prof 'controlCategory') }
        if (-not $cat) { continue }
        if (-not $cats.Contains($cat)) { $cats[$cat] = @{ Earned = 0.0; Available = 0.0 } }
        $cats[$cat].Earned += [double](Get-EbrProp $c 'score')
        $cats[$cat].Available += [double](Get-EbrProp $prof 'maxScore')
    }
    $pctOf = { param([string]$cat) if ($cats.Contains($cat) -and $cats[$cat].Available -gt 0) { [math]::Round(100 * $cats[$cat].Earned / $cats[$cat].Available, 1) } else { $null } }
    $snap = {
        param($s)
        $cur = [double](Get-EbrProp $s 'currentScore'); $max = [double](Get-EbrProp $s 'maxScore')
        [pscustomobject]@{
            Date    = (ConvertTo-EbrUtcDate (Get-EbrProp $s 'createdDateTime')).ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)
            Current = [math]::Round($cur, 2); Max = [math]::Round($max, 2)
            Percent = $(if ($max -gt 0) { [math]::Round(100 * $cur / $max, 2) } else { $null })
        }
    }
    $head = & $snap $latest
    $avg = @(Get-EbrProp $latest 'averageComparativeScores') | Where-Object { [string](Get-EbrProp $_ 'basis') -eq 'AllTenants' } | Select-Object -First 1
    $row = [pscustomobject]@{
        ReadDate = $head.Date; Current = $head.Current; Max = $head.Max; Percent = $head.Percent
        IdentityPct = & $pctOf 'Identity'; DevicePct = & $pctOf 'Device'; AppsPct = & $pctOf 'Apps'; DataPct = & $pctOf 'Data'
        AllTenantsAverage = $(if ($avg) { [math]::Round([double](Get-EbrProp $avg 'averageScore'), 2) } else { $null })
        Snapshots = $sorted.Count
    }
    $trend = @(foreach ($s in $sorted) { & $snap $s })
    $categories = @(foreach ($k in $cats.Keys) {
            [pscustomobject]@{ Category = $k; Earned = [math]::Round($cats[$k].Earned, 2); Available = [math]::Round($cats[$k].Available, 2); Percent = & $pctOf $k }
        })
    $extra = @(
        @{ Id = 'POS.6-TREND'; Rows = $trend; Columns = @('Date', 'Current', 'Max', 'Percent'); Detail = 'Daily snapshots, 90 at most. Percent is Current over Max.' }
        @{ Id = 'POS.6-CATEGORIES'; Rows = $categories; Columns = @('Category', 'Earned', 'Available', 'Percent'); Detail = 'Active control profiles only, so sums can differ from the headline maximum by a few points.' }
    )
    New-EbrGraphResult -Rows @($row) -Columns $columns -Detail ('Quote Current over Max as the headline. Peer medians come from the portal comparison view.' + $profDetail) -Extra $extra
}

function Get-EbrGraphDP8 {
    param($Ctx)
    $s = Get-EbrGraphObject -Ctx $Ctx -Path 'admin/sharepoint/settings'
    $row = [pscustomobject]@{
        SharingCapability        = [string](Get-EbrProp $s 'sharingCapability')
        DomainRestrictionMode    = [string](Get-EbrProp $s 'sharingDomainRestrictionMode')
        AllowedDomains           = Join-EbrList (Get-EbrProp $s 'sharingAllowedDomainList')
        BlockedDomains           = Join-EbrList (Get-EbrProp $s 'sharingBlockedDomainList')
        ResharingByExternalUsers = Get-EbrProp $s 'isResharingByExternalUsersEnabled'
        LegacyAuthProtocols      = Get-EbrProp $s 'isLegacyAuthProtocolsEnabled'
        UnmanagedSyncRestricted  = Get-EbrProp $s 'isUnmanagedSyncAppForTenantRestricted'
    }
    New-EbrGraphResult -Rows @($row) -Columns @('SharingCapability', 'DomainRestrictionMode', 'AllowedDomains', 'BlockedDomains', 'ResharingByExternalUsers', 'LegacyAuthProtocols', 'UnmanagedSyncRestricted') -Detail 'Tenant-level sharing settings. Compare with the boundaries agreed with the client.'
}

function Get-EbrGraphDR11 {
    param($Ctx)
    $rows = foreach ($s in @(Get-EbrGraphList -Ctx $Ctx -Path 'security/identities/sensors')) {
        [pscustomobject]@{
            Sensor = [string](Get-EbrProp $s 'displayName'); SensorType = [string](Get-EbrProp $s 'sensorType')
            HealthStatus = [string](Get-EbrProp $s 'healthStatus'); DeploymentStatus = [string](Get-EbrProp $s 'deploymentStatus')
            Version = [string](Get-EbrProp $s 'version'); Domain = [string](Get-EbrProp $s 'domainName')
            OpenHealthIssues = Get-EbrProp $s 'openHealthIssuesCount'; CreatedUtc = Format-EbrUtc (Get-EbrProp $s 'createdDateTime')
        }
    }
    New-EbrGraphResult -Rows @($rows) -Columns @('Sensor', 'SensorType', 'HealthStatus', 'DeploymentStatus', 'Version', 'Domain', 'OpenHealthIssues', 'CreatedUtc') -Detail 'Compare with the domain controller inventory: a domain controller with no sensor row is the gap. DR.4 shows which ones emit events.'
}

function Get-EbrGraphDP10 {
    param($Ctx)
    $devices = @(Get-EbrGraphList -Ctx $Ctx -Path 'deviceManagement/managedDevices?$select=id,operatingSystem,isEncrypted,managedDeviceOwnerType,complianceState&$top=1000')
    $Ctx.GraphCache['managedDevices'] = $devices
    $os = {
        param($d)
        $v = [string](Get-EbrProp $d 'operatingSystem')
        switch -Regex ($v) { '^windows' { 'Windows'; break } '^macos' { 'macOS'; break } '^ios' { 'iOS'; break } '^android' { 'Android'; break } default { if ($v) { $v } else { 'Unknown' } } }
    }
    $rows = @($devices) | Group-Object { '{0}|{1}' -f (& $os $_), [string](Get-EbrProp $_ 'managedDeviceOwnerType') } | Sort-Object Name | ForEach-Object {
        $parts = $_.Name -split '\|', 2
        [pscustomobject]@{
            OperatingSystem = $parts[0]; Ownership = $(if ($parts[1]) { $parts[1] } else { 'unknown' })
            Devices = $_.Count
            Encrypted = @($_.Group | Where-Object { Test-EbrTrue (Get-EbrProp $_ 'isEncrypted') }).Count
            Compliant = @($_.Group | Where-Object { [string](Get-EbrProp $_ 'complianceState') -eq 'compliant' }).Count
        }
    }
    New-EbrGraphResult -Rows @($rows) -Columns @('OperatingSystem', 'Ownership', 'Devices', 'Encrypted', 'Compliant') -Detail 'isEncrypted as reported by Intune. Windows and macOS are the platforms in scope for DP.10; mobile rows are context.'
}

function Get-EbrGraphEW13 {
    param($Ctx)
    # The Intune settings catalog only exists in the beta surface (v1.0 answers "Resource not found
    # for the segment 'configurationPolicies'"). isAssigned is the assignment flag.
    $select = '$select=id,name,platforms,technologies,isAssigned,settingCount,lastModifiedDateTime,templateReference'
    $family = 'endpointSecurityApplicationControl'
    $policies = $null
    try { $policies = @(Get-EbrGraphList -Ctx $Ctx -Beta -Path ('deviceManagement/configurationPolicies?$filter=templateReference/templateFamily eq ''' + $family + '''&' + $select)) }
    catch {
        if ($_.Exception.Message -match '^GRAPH-403') { throw }
        # Some tenants reject the templateFamily filter. Read every policy and filter here.
        $policies = @(Get-EbrGraphList -Ctx $Ctx -Beta -Path ('deviceManagement/configurationPolicies?' + $select) | Where-Object { [string](Get-EbrProp (Get-EbrProp $_ 'templateReference') 'templateFamily') -eq $family })
    }
    $rows = foreach ($p in $policies) {
        [pscustomobject]@{
            Policy = [string](Get-EbrProp $p 'name'); Platforms = [string](Get-EbrProp $p 'platforms'); Technologies = [string](Get-EbrProp $p 'technologies')
            Assigned = (Test-EbrTrue (Get-EbrProp $p 'isAssigned'))
            Settings = Get-EbrProp $p 'settingCount'; ModifiedUtc = Format-EbrUtc (Get-EbrProp $p 'lastModifiedDateTime')
        }
    }
    $corp = ''
    $cached = $Ctx.GraphCache['managedDevices']
    if ($cached) {
        $win = @($cached | Where-Object { [string](Get-EbrProp $_ 'operatingSystem') -match '^windows' -and [string](Get-EbrProp $_ 'managedDeviceOwnerType') -eq 'company' }).Count
        $corp = ' Corporate-owned Windows devices in Intune: {0} (DP.10).' -f $win
    }
    New-EbrGraphResult -Rows @($rows) -Columns @('Policy', 'Platforms', 'Technologies', 'Assigned', 'Settings', 'ModifiedUtc') -Detail ('App Control for Business policies from the Intune settings catalog. ThreatLocker coverage, where the client runs it, is read from the ThreatLocker portal.' + $corp)
}

function Invoke-EbrGraphCollector {
    param($Ctx, $Item)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $elapsed = { $sw.Elapsed.TotalSeconds }
    $spec = Get-EbrGraphSpec $Item.Id
    if (-not $spec) { return New-EbrResult -ResultId $Item.Id -Status 'FAILED' -Source 'Microsoft Graph' -Detail "No Graph collector is defined for $($Item.Id)." -DurationSec (& $elapsed) }
    try {
        $r = & $spec.Collector -Ctx $Ctx
        foreach ($x in @($r.Extra)) {
            $xs = if (@($x.Rows).Count) { 'OK' } else { 'EMPTY' }
            $Ctx.Pending.Add((New-EbrResult -ResultId $x.Id -Status $xs -Rows @($x.Rows) -Columns @($x.Columns) -Source 'Microsoft Graph' -Detail $x.Detail -DurationSec (& $elapsed)))
        }
        $rows = @($r.Rows)
        $status = if ($rows.Count -gt 0) { 'OK' } else { 'EMPTY' }
        return New-EbrResult -ResultId $Item.Id -Status $status -Rows $rows -Columns @($r.Columns) -Source 'Microsoft Graph' -Detail $r.Detail -DurationSec (& $elapsed)
    }
    catch {
        $m = $_.Exception.Message -replace '\s+', ' '
        if ($m -match '^GRAPH-403') {
            $perm = $spec.Permission
            Add-EbrGraphMissingScope -Ctx $Ctx -Permission $perm
            $detail = 'Not a zero: the Graph token cannot read this. Needs {0}. Fix: az login --tenant {1} --scope https://graph.microsoft.com/{0}, then rerun. {2} {3}' -f $perm, $Ctx.TenantGuid, $Item.Notes, $m
            return New-EbrResult -ResultId $Item.Id -Status 'UNAVAILABLE' -Source 'Microsoft Graph' -Detail $detail.Trim() -DurationSec (& $elapsed)
        }
        return New-EbrResult -ResultId $Item.Id -Status 'FAILED' -Source 'Microsoft Graph' -Detail $m -DurationSec (& $elapsed)
    }
}

#endregion

#region Writers

$script:EbrUtf8Bom = New-Object System.Text.UTF8Encoding($true)
$script:EbrUtf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Write-EbrTextFile {
    param([string]$Path, [string]$Text, [switch]$Bom)
    $enc = if ($Bom) { $script:EbrUtf8Bom } else { $script:EbrUtf8NoBom }
    [IO.File]::WriteAllText($Path, $Text, $enc)
}

function Write-EbrCsvFile {
    param([string]$Path, $Rows, [string[]]$Columns)
    $rows = @($Rows | Where-Object { $null -ne $_ })
    if ($rows.Count -gt 0) {
        $lines = $rows | ForEach-Object { ConvertTo-EbrCsvRow $_ } | ConvertTo-Csv -NoTypeInformation
        Write-EbrTextFile -Path $Path -Text (($lines -join "`r`n") + "`r`n") -Bom
    }
    else {
        $header = (@($Columns) | Where-Object { $_ } | ForEach-Object { '"' + ([string]$_).Replace('"', '""') + '"' }) -join ','
        Write-EbrTextFile -Path $Path -Text ($header + "`r`n") -Bom
    }
}

function Write-EbrResultFiles {
    param([string]$OutDir, $Result)
    $dir = Join-Path $OutDir 'results'
    Write-EbrCsvFile -Path (Join-Path $dir "$($Result.ResultId).csv") -Rows $Result.Rows -Columns $Result.Columns
    Write-EbrTextFile -Path (Join-Path $dir "$($Result.ResultId).json") -Text (ConvertTo-Json -InputObject @($Result.Rows) -Depth 20)
}

function Write-EbrQueryFile {
    param([string]$OutDir, $Item, [string]$Text, [string]$Target)
    $header = "// EBR evidence query {0}: {1}`n// Engine: {2}. Target: {3}`n// Expanded {4} UTC by Get-EbrSecurityEvidence.ps1 v{5}`n" -f $Item.Id, $Item.Title, $Item.Engine, $Target, (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss', [cultureinfo]::InvariantCulture), $script:EbrVersion
    # Graph items carry the endpoints they read rather than KQL, so they get their own extension.
    $ext = if ($Item.Engine -eq 'GRAPH') { '.graph.txt' } else { '.kql' }
    Write-EbrTextFile -Path (Join-Path (Join-Path $OutDir 'queries') "$($Item.Id)$ext") -Text ($header + $Text + "`n")
}

#endregion

#region Main

function Disable-EbrQuickEdit {
    # Windows console only. With QuickEdit on, a click in the window starts a text selection and the
    # script stops at its next line of output until Esc or Enter. Returns the mode to restore, or $null.
    if ([Environment]::OSVersion.Platform -ne 'Win32NT') { return $null }
    try {
        if (-not ('Ebr.ConsoleMode' -as [type])) {
            Add-Type -Namespace Ebr -Name ConsoleMode -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern IntPtr GetStdHandle(int nStdHandle);
[DllImport("kernel32.dll")] public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
[DllImport("kernel32.dll")] public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
'@
        }
        $handle = [Ebr.ConsoleMode]::GetStdHandle(-10)
        [uint32]$mode = 0
        # No console (redirected input) or QuickEdit (0x40) already off: nothing to do
        if (-not [Ebr.ConsoleMode]::GetConsoleMode($handle, [ref]$mode) -or ($mode -band 0x40) -eq 0) { return $null }
        # The QuickEdit bit only changes with ENABLE_EXTENDED_FLAGS (0x80) set
        if ([Ebr.ConsoleMode]::SetConsoleMode($handle, [uint32](($mode -bor 0x80) - 0x40))) {
            Write-EbrLog -Level INFO -Component Console -Message 'QuickEdit turned off for this run, so a click in the window cannot pause it. Restored at the end.'
            return $mode
        }
    }
    catch { Write-EbrLog -Level DEBUG -Component Console -Message ('QuickEdit left as it was: ' + $_.Exception.Message) }
    $null
}

function Restore-EbrQuickEdit {
    param($Mode)
    if ($null -eq $Mode) { return }
    try { $null = [Ebr.ConsoleMode]::SetConsoleMode([Ebr.ConsoleMode]::GetStdHandle(-10), [uint32]$Mode) } catch { }
}

function Read-EbrInput {
    param([string]$Prompt, [string]$Default, [scriptblock]$Validator, [string]$Hint)
    while ($true) {
        $suffix = if ($Default) { " [$Default]" } else { ' (required)' }
        $value = Read-Host "  $Prompt$suffix"
        if (-not $value -and $Default) { $value = $Default }
        if (-not $value) { Write-EbrQuip "Required field. You know what 'required' means, right?"; continue }
        if ($Validator -and -not (& $Validator $value)) { Write-EbrQuip "That's not valid. Shocking development. $Hint"; continue }
        return $value.Trim()
    }
}

function Write-EbrQueryLine {
    param($Result, [string]$Title)
    $sym = $script:EbrSym
    $short = if ($Title.Length -gt 48) { $Title.Substring(0, 45) + '...' } else { $Title }
    switch ($Result.Status) {
        'OK' { $mark = $sym.Ok; $color = 'Green'; $text = '{0} row(s), {1}s' -f $Result.Rows.Count, $Result.DurationSec }
        'EMPTY' { $mark = $sym.Ok; $color = 'DarkYellow'; $text = '0 rows, {0}s' -f $Result.DurationSec }
        'PARTIAL' { $mark = $sym.Warn; $color = 'Yellow'; $text = '{0} row(s), {1}s, PARTIAL' -f $Result.Rows.Count, $Result.DurationSec }
        'UNAVAILABLE' { $mark = $sym.Fail; $color = 'Magenta'; $text = 'no data source (not a zero)' }
        'FAILED' { $mark = $sym.Fail; $color = 'Red'; $text = 'FAILED' }
        'MANUAL' { $mark = $sym.Warn; $color = 'Yellow'; $text = 'manual portal reading' }
        'DRYRUN' { $mark = $sym.Dot; $color = 'Gray'; $text = 'written' }
        default { $mark = '-'; $color = 'DarkGray'; $text = 'skipped' }
    }
    if ($Result.Source -match 'fallback') { $text += ' (Sentinel workspace fallback)' }
    Write-Host ('  {0} {1,-16} {2,-48} {3}' -f $mark, $Result.ResultId, $short, $text) -ForegroundColor $color
    if ($Result.Status -in 'FAILED', 'SKIPPED', 'PARTIAL', 'UNAVAILABLE' -and $Result.Detail) {
        $d = $Result.Detail; if ($d.Length -gt 220) { $d = $d.Substring(0, 217) + '...' }
        Write-EbrQuip $d
    }
    Write-EbrLog -Level $(if ($Result.Status -eq 'FAILED') { 'ERROR' } elseif ($Result.Status -in 'PARTIAL', 'UNAVAILABLE') { 'WARNING' } else { 'INFO' }) -Component $Result.ResultId -Message ('{0} rows={1} source={2} {3}' -f $Result.Status, $Result.Rows.Count, $Result.Source, $Result.Detail)
}

function Add-EbrResult {
    param($Ctx, $Item, $Result)
    $Ctx.Results[$Result.ResultId] = $Result
    if ($Ctx.OutDir -and $Result.Status -notin 'MANUAL', 'DRYRUN') { Write-EbrResultFiles -OutDir $Ctx.OutDir -Result $Result }
    $Ctx.Manifest.Add([pscustomobject]@{
            ResultId    = $Result.ResultId
            Phase       = $Item.Phase
            Title       = $Item.Title
            Engine      = $Item.Engine
            Source      = $Result.Source
            Status      = $Result.Status
            Rows        = @($Result.Rows).Count
            ReadTimeUtc = Format-EbrUtc $Result.ReadTimeUtc
            DurationSec = $Result.DurationSec
            Detail      = $Result.Detail
            Guidance    = $Item.Notes
        })
    Write-EbrQueryLine -Result $Result -Title $Item.Title
}

function Invoke-EbrCatalogItem {
    param($Ctx, $Item)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $text = $null
    if ($Item.Query) {
        $ticket = if ($Ctx.PSObject.Properties['TicketPattern']) { [string]$Ctx.TicketPattern } else { '' }
        $cadence = if ($Ctx.PSObject.Properties['PatchCadenceDays'] -and [int]$Ctx.PatchCadenceDays -ge 1) { [int]$Ctx.PatchCadenceDays } else { 30 }
        $patchTags = if ($Ctx.PSObject.Properties['PatchExclusionTagPattern']) { [string]$Ctx.PatchExclusionTagPattern } else { $script:EbrPatchExclusionTagPattern }
        $edrVendors = if ($Ctx.PSObject.Properties['EdrVendorPattern']) { [string]$Ctx.EdrVendorPattern } else { '' }
        $text = Expand-EbrQuery -Query $Item.Query -WindowStart $Ctx.WindowStart -WindowEnd $Ctx.WindowEnd -ManagedRgPattern $Ctx.ManagedRgPattern -TicketPattern $ticket -PatchCadenceDays $cadence -PatchExclusionTagPattern $patchTags -EdrVendorPattern $edrVendors
    }
    $elapsed = { $sw.Elapsed.TotalSeconds }

    switch ($Item.Engine) {
        'MANUAL' {
            return New-EbrResult -ResultId $Item.Id -Status 'MANUAL' -Source 'Portal' -Detail $Item.Notes
        }
        'DERIVED' {
            # Built from results already in the pack. Nothing is queried.
            try {
                $r = & $Item.Derive $Ctx
                $r.DurationSec = [math]::Round((& $elapsed), 1)
                return $r
            }
            catch { return New-EbrResult -ResultId $Item.Id -Status 'FAILED' -Source 'Derived from collected results' -Detail $_.Exception.Message -DurationSec (& $elapsed) }
        }
        'ARG' {
            Write-EbrQueryFile -OutDir $Ctx.OutDir -Item $Item -Text $text -Target ('Resource Graph, subscriptions: ' + ($Ctx.Subscriptions -join ', '))
            try {
                $r = Invoke-EbrArgQuery -Query $text -Subscriptions $Ctx.Subscriptions -Tenant $Ctx.ArmTenant
                $status = if ($r.Rows.Count -gt 0) { 'OK' } else { 'EMPTY' }
                $detail = $r.Detail
                if ($Item.LighthouseIncomplete -and $Ctx.AccessPath -eq 'Lighthouse') {
                    $status = 'PARTIAL'
                    $detail = (@($detail, "Read through Lighthouse, which shows the managing tenant's delegations rather than the client's own role assignments, so this is incomplete. Sign in directly (az login --tenant followed by the client domain) and rerun.") | Where-Object { $_ }) -join ' '
                }
                return New-EbrResult -ResultId $Item.Id -Status $status -Rows $r.Rows -Columns $r.Columns -Source ('Resource Graph ({0})' -f $(if ($Ctx.AccessPath) { $Ctx.AccessPath.ToLowerInvariant() } else { 'direct' })) -Detail $detail -DurationSec (& $elapsed)
            }
            catch { return New-EbrResult -ResultId $Item.Id -Status 'FAILED' -Source 'Resource Graph' -Detail $_.Exception.Message -DurationSec (& $elapsed) }
        }
        'LA' {
            $all = @($Ctx.Workspaces)
            if ($all.Count -eq 0) { return New-EbrResult -ResultId $Item.Id -Status 'SKIPPED' -Source 'Log Analytics' -Detail 'No Sentinel workspace in scope.' }

            if ($Item.TenantTable -or $all.Count -eq 1) {
                if ($Item.TenantTable) {
                    $ws = $Ctx.TenantWorkspace[$Item.TenantTable]
                    if (-not $ws) { $ws = $all[0] }
                    $source = 'Log Analytics: {0} (tenant-wide {1}, read from one workspace)' -f $ws.WorkspaceName, $Item.TenantTable
                }
                else {
                    $ws = $all[0]
                    $source = 'Log Analytics: ' + $ws.WorkspaceName
                }
                Write-EbrQueryFile -OutDir $Ctx.OutDir -Item $Item -Text $text -Target $source
                try {
                    $r = Invoke-EbrLaQuery -Query $text -WorkspaceCustomerId $ws.CustomerId -Tenant $ws.AccessTenant
                    $status = if ($r.Rows.Count -gt 0) { 'OK' } else { 'EMPTY' }
                    return New-EbrResult -ResultId $Item.Id -Status $status -Rows $r.Rows -Columns $r.Columns -Source $source -Detail $r.Detail -DurationSec (& $elapsed)
                }
                catch {
                    $m = $_.Exception.Message
                    $status = if (Test-EbrMissingTableError $m) { 'EMPTY' } else { 'FAILED' }
                    return New-EbrResult -ResultId $Item.Id -Status $status -Source $source -Detail $m -DurationSec (& $elapsed)
                }
            }

            Write-EbrQueryFile -OutDir $Ctx.OutDir -Item $Item -Text $text -Target ('Log Analytics, {0} workspaces combined: {1}' -f $all.Count, (Get-EbrWorkspaceNames $all))
            $breakdown = $Item.AlwaysBreakdown -or (-not $Ctx.SkipBreakdown -and -not $Item.CombinedOnly)
            $x = Invoke-EbrLaAcross -Query $text -Workspaces $all -Label $Item.Id -Breakdown:$breakdown
            $per = $x.Per
            $notes = [System.Collections.Generic.List[string]]::new()
            $failedNames = @()
            if ($per) {
                $failedNames = @($per.Failed | ForEach-Object { ($_ -split ': ', 2)[0] })
                if ($per.MissingTable.Count) { $notes.Add('Table not present in ' + ($per.MissingTable -join ', ')) }
                if ($per.Failed.Count) { $notes.Add('Workspace errors: ' + ($per.Failed -join ' / ')) }
            }
            if ($breakdown -and $per) {
                $bdStatus = if ($per.Failed.Count -eq $all.Count) { 'FAILED' } elseif ($per.Failed.Count) { 'PARTIAL' } elseif ($per.Rows.Count) { 'OK' } else { 'EMPTY' }
                $Ctx.Pending.Add((New-EbrResult -ResultId "$($Item.Id)-BY-WORKSPACE" -Status $bdStatus -Rows $per.Rows -Columns $per.Columns -Source ('Log Analytics: {0} workspaces, one query each' -f $all.Count) -Detail ($notes -join '. ') -DurationSec (& $elapsed)))
            }
            if (-not $x.Combined) {
                if ($per -and $per.Usable.Count -eq 0 -and $per.Failed.Count -eq 0) {
                    return New-EbrResult -ResultId $Item.Id -Status 'EMPTY' -Source 'Log Analytics' -Detail ('No workspace has the table this query reads. ' + ($notes -join '. ')) -DurationSec (& $elapsed)
                }
                $why = if ($x.Error) { $x.Error } else { 'every workspace failed' }
                return New-EbrResult -ResultId $Item.Id -Status 'FAILED' -Source 'Log Analytics' -Detail ((@("Combined query: $why") + @($notes)) -join '. ') -DurationSec (& $elapsed)
            }
            $c = $x.Combined
            if ($c.Excluded.Count) { $notes.Add('Reached through a different tenant, left out of the combined figure: ' + (Get-EbrWorkspaceNames $c.Excluded)) }
            if ($failedNames.Count) { $notes.Add('Left out of the combined figure: ' + ($failedNames -join ', ')) }
            if ($c.Detail) { $notes.Add($c.Detail) }
            $notes.Insert(0, ('Combined across {0} of {1} workspaces ({2})' -f $c.Used.Count, $all.Count, (Get-EbrWorkspaceNames $c.Used)))
            $status = if ($failedNames.Count -or $c.Excluded.Count) { 'PARTIAL' } elseif ($c.Rows.Count) { 'OK' } else { 'EMPTY' }
            return New-EbrResult -ResultId $Item.Id -Status $status -Rows $c.Rows -Columns $c.Columns -Source ('Log Analytics: {0} workspaces combined' -f $c.Used.Count) -Detail ($notes -join '. ') -DurationSec (& $elapsed)
        }
        'AH' {
            Write-EbrQueryFile -OutDir $Ctx.OutDir -Item $Item -Text $text -Target 'Defender Advanced Hunting (Sentinel workspace fallback)'
            $needed = @(Get-EbrAhTables $text)
            $xdrOnly = @($needed | Where-Object { $_ -in (Get-EbrXdrOnlyTableNames) })
            # P0.4 is a fuzzy union that is meant to show which tables resolve, so it always asks the API
            $fuzzy = $text -match 'isfuzzy\s*=\s*true'
            $ahError = $null
            if ($Ctx.DefenderAvailable -and ($xdrOnly.Count -eq 0 -or $fuzzy)) {
                try {
                    $r = Invoke-EbrAhQuery -Query $text -Tenant $Ctx.TenantGuid
                    $status = if ($r.Rows.Count -gt 0) { 'OK' } else { 'EMPTY' }
                    return New-EbrResult -ResultId $Item.Id -Status $status -Rows $r.Rows -Columns $r.Columns -Source 'Defender Advanced Hunting' -DurationSec (& $elapsed)
                }
                catch { $ahError = 'Advanced Hunting returned an error: ' + $_.Exception.Message }
            }
            elseif ($Ctx.DefenderAvailable) {
                # Not worth the round trip: this endpoint has never once resolved these tables
                $ahError = 'The Defender for Endpoint hunting API that Azure CLI can reach does not expose {0} (Defender for Office 365 and Defender for Identity tables), and the Defender XDR hunting API does not accept Azure CLI tokens.' -f ($xdrOnly -join ', ')
            }
            else { $ahError = 'Advanced Hunting is unavailable. ' + $Ctx.DefenderReason }
            $byHand = 'Run queries/{0}.kql by hand in Defender portal > Advanced hunting.' -f $Item.Id
            $all = @($Ctx.Workspaces)
            if ($all.Count -eq 0) {
                return New-EbrResult -ResultId $Item.Id -Status 'UNAVAILABLE' -Source 'Defender Advanced Hunting' -Detail ("Not a zero: there is no Sentinel workspace to fall back to. $ahError $byHand") -DurationSec (& $elapsed)
            }
            # A workspace without the table answers "0 rows", which reads like a measured zero.
            # It is not: there is simply nothing there. So check which tables the workspaces hold.
            $held = Get-EbrFallbackTables -Ctx $Ctx
            if ($null -ne $held) {
                $missing = @($needed | Where-Object { $_ -notin $held })
                if ($missing.Count) {
                    $detail = 'Not a zero: the Sentinel workspaces hold no {0} data from the last 30 days, so there is nothing to measure. {1} {2}' -f ($missing -join ', '), $ahError, $byHand
                    return New-EbrResult -ResultId $Item.Id -Status 'UNAVAILABLE' -Source 'Defender Advanced Hunting' -Detail $detail -DurationSec (& $elapsed)
                }
            }
            $x = Invoke-EbrLaAcross -Query $text -Workspaces $all -Label "$($Item.Id) workspace fallback"
            if ($x.Combined) {
                $c = $x.Combined
                $detail = 'Answered by {0} Sentinel workspace(s): {1}. {2}' -f $c.Used.Count, (Get-EbrWorkspaceNames $c.Used), $ahError
                if ($c.Detail) { $detail += ' ' + $c.Detail }
                if ($c.Rows.Count -gt 0) { $status = 'OK' }
                elseif ($null -ne $held) { $status = 'EMPTY' }
                else {
                    $status = 'UNAVAILABLE'
                    $detail = 'Not a zero: 0 rows, and the workspaces could not be checked for the tables this query reads. ' + $detail
                }
                return New-EbrResult -ResultId $Item.Id -Status $status -Rows $c.Rows -Columns $c.Columns -Source 'Sentinel workspace (AH fallback)' -Detail $detail -DurationSec (& $elapsed)
            }
            $why = if ($x.Per -and $x.Per.Usable.Count -eq 0 -and $x.Per.Failed.Count -eq 0) { 'the table is not in any workspace' } else { $x.Error }
            return New-EbrResult -ResultId $Item.Id -Status 'FAILED' -Source 'Defender Advanced Hunting' -Detail ("$ahError | Workspace fallback: $why") -DurationSec (& $elapsed)
        }
        'SENTINEL-RULES' {
            $all = @($Ctx.Workspaces)
            if ($all.Count -eq 0) { return New-EbrResult -ResultId $Item.Id -Status 'SKIPPED' -Source 'Sentinel ARM API' -Detail 'No Sentinel workspace in scope.' }
            $rules = [System.Collections.Generic.List[object]]::new()
            $failed = [System.Collections.Generic.List[string]]::new()
            foreach ($ws in $all) {
                try {
                    $wsRules = @(Get-EbrSentinelRules -WorkspaceResourceId $ws.WorkspaceResourceId -Tenant $ws.AccessTenant)
                    foreach ($row in (Add-EbrWorkspaceColumns -Rows $wsRules -Workspace $ws)) { $rules.Add($row) }
                }
                catch { $failed.Add(('{0}: {1}' -f $ws.WorkspaceName, $_.Exception.Message)) }
            }
            $detail = if ($failed.Count) { 'Workspace errors: ' + ($failed -join ' / ') } else { '' }
            if ($failed.Count -eq $all.Count) { return New-EbrResult -ResultId $Item.Id -Status 'FAILED' -Source 'Sentinel ARM API' -Detail $detail -DurationSec (& $elapsed) }
            $status = if ($failed.Count) { 'PARTIAL' } else { 'OK' }
            $ruleStatus = if ($failed.Count) { 'PARTIAL' } elseif ($rules.Count) { 'OK' } else { 'EMPTY' }
            $Ctx.Pending.Add((New-EbrResult -ResultId 'DR.9-RULES' -Status $ruleStatus -Rows $rules.ToArray() -Columns @('Workspace', 'WorkspaceId', 'SubscriptionId', 'RuleName', 'Kind', 'Enabled', 'Severity', 'LastModifiedUtc', 'Tactics', 'TemplateName', 'RuleId') -Source 'Sentinel ARM API' -Detail $detail -DurationSec (& $elapsed)))
            $summary = @(Get-EbrRuleSummary -Rules $rules.ToArray() -WindowStart $Ctx.WindowStart)
            return New-EbrResult -ResultId $Item.Id -Status $status -Rows $summary -Columns @('Scope', 'Metric', 'Value') -Source ('Sentinel ARM API, {0} workspace(s)' -f $all.Count) -Detail $detail -DurationSec (& $elapsed)
        }
        'STORAGE-CONTAINERS' {
            Write-EbrQueryFile -OutDir $Ctx.OutDir -Item $Item -Text $text -Target ('Resource Graph, then a GET on the blobServices/default/containers path of each account, subscriptions: ' + ($Ctx.Subscriptions -join ', '))
            $columns = @('subscriptionId', 'resourceGroup', 'Account', 'AccountAnonymousAccess', 'Containers', 'PublicContainers', 'ExposedContainers', 'PublicContainerNames', 'ReadStatus', 'ResourceId')
            try { $accounts = @((Invoke-EbrArgQuery -Query $text -Subscriptions $Ctx.Subscriptions -Tenant $Ctx.ArmTenant).Rows) }
            catch { return New-EbrResult -ResultId $Item.Id -Status 'FAILED' -Source 'Resource Graph' -Detail $_.Exception.Message -DurationSec (& $elapsed) }
            if ($accounts.Count -eq 0) { return New-EbrResult -ResultId $Item.Id -Status 'EMPTY' -Columns $columns -Source 'Resource Graph' -Detail 'No storage account with a blob service in scope.' -DurationSec (& $elapsed) }
            $rows = [System.Collections.Generic.List[object]]::new()
            $i = 0
            foreach ($a in $accounts) {
                $i++
                Write-Progress -Id 2 -ParentId 1 -Activity 'Listing blob containers' -Status ('{0} ({1} of {2})' -f $a.Account, $i, $accounts.Count) -PercentComplete ([int](100 * $i / $accounts.Count))
                $rows.Add((Get-EbrBlobContainerRow -Account $a -Tenant $Ctx.ArmTenant))
            }
            Write-Progress -Id 2 -ParentId 1 -Activity 'Listing blob containers' -Completed
            $failed = @($rows | Where-Object ReadStatus -ne 'OK')
            $read = @($rows | Where-Object ReadStatus -eq 'OK')
            $total = { param($f) [int](@($read | ForEach-Object { [int]$_.$f }) | Measure-Object -Sum).Sum }
            $detail = '{0} of {1} storage accounts listed: {2} containers, {3} set to Blob or Container access, {4} readable anonymously today.' -f $read.Count, $rows.Count, (& $total 'Containers'), (& $total 'PublicContainers'), (& $total 'ExposedContainers')
            if ($failed.Count) { $detail += ' Not listed: ' + ((@($failed | Select-Object -First 5) | ForEach-Object { '{0}: {1}' -f $_.Account, $_.ReadStatus }) -join ' / ') + $(if ($failed.Count -gt 5) { ' / and {0} more' -f ($failed.Count - 5) } else { '' }) }
            $status = if ($read.Count -eq 0) { 'FAILED' } elseif ($failed.Count) { 'PARTIAL' } else { 'OK' }
            return New-EbrResult -ResultId $Item.Id -Status $status -Rows $rows.ToArray() -Columns $columns -Source ('Resource Graph and the Storage resource provider ({0})' -f $(if ($Ctx.AccessPath) { $Ctx.AccessPath.ToLowerInvariant() } else { 'direct' })) -Detail $detail -DurationSec (& $elapsed)
        }
        'DEFENDER-SCORES' {
            if (-not $Ctx.DefenderAvailable) { return New-EbrResult -ResultId $Item.Id -Status 'SKIPPED' -Source 'Defender API' -Detail $Ctx.DefenderReason }
            try {
                $r = Get-EbrDefenderScores -Tenant $Ctx.TenantGuid
                return New-EbrResult -ResultId $Item.Id -Status 'OK' -Rows $r.Rows -Source 'Defender API' -Detail $r.Detail -DurationSec (& $elapsed)
            }
            catch { return New-EbrResult -ResultId $Item.Id -Status 'FAILED' -Source 'Defender API' -Detail $_.Exception.Message -DurationSec (& $elapsed) }
        }
        'GRAPH' {
            Write-EbrQueryFile -OutDir $Ctx.OutDir -Item $Item -Text $text -Target 'Microsoft Graph'
            if (-not $Ctx.GraphAvailable) {
                $why = if ($Ctx.GraphReason) { $Ctx.GraphReason } else { 'Microsoft Graph was not initialised.' }
                return New-EbrResult -ResultId $Item.Id -Status 'UNAVAILABLE' -Source 'Microsoft Graph' -Detail (('Not a zero: Microsoft Graph was not reachable. {0} {1}' -f $why, $Item.Notes).Trim()) -DurationSec (& $elapsed)
            }
            return Invoke-EbrGraphCollector -Ctx $Ctx -Item $Item
        }
        default {
            return New-EbrResult -ResultId $Item.Id -Status 'SKIPPED' -Source $Item.Engine -Detail 'Collected in the Exchange Online and Purview step.'
        }
    }
}

function Invoke-EbrPhase {
    param($Ctx, [object[]]$Items, [string]$Activity)
    $i = 0
    foreach ($item in $Items) {
        $i++
        $done = $Ctx.Done
        $remaining = $Ctx.Total - $done
        $avg = if ($Ctx.Durations.Count) { ($Ctx.Durations | Measure-Object -Average).Average } else { 4 }
        Write-Progress -Id 1 -Activity $Activity -Status ('{0} {1} ({2}/{3} overall)' -f $item.Id, $item.Title, ($done + 1), $Ctx.Total) -PercentComplete ([int](100 * $done / [math]::Max(1, $Ctx.Total))) -SecondsRemaining ([int]($avg * $remaining))
        $result = Invoke-EbrCatalogItem -Ctx $Ctx -Item $item
        Add-EbrResult -Ctx $Ctx -Item $item -Result $result
        foreach ($extra in $Ctx.Pending) { Add-EbrResult -Ctx $Ctx -Item ([pscustomobject]@{ Phase = $item.Phase; Title = "$($item.Title) (detail)"; Engine = $item.Engine; Notes = $item.Notes }) -Result $extra }
        $Ctx.Pending.Clear()
        if ($item.Engine -ne 'MANUAL') { $Ctx.Durations.Add([double]$result.DurationSec) }
        $Ctx.Done++
        if ($result.Status -eq 'FAILED' -and ($i % 3 -eq 0)) { Write-EbrQuip (Get-EbrSnark Fail) }
        elseif ($result.Status -eq 'EMPTY' -and ($i % 4 -eq 0)) { Write-EbrQuip (Get-EbrSnark Empty) }
    }
    Write-Progress -Id 1 -Activity $Activity -Completed
}

function Get-EbrReachRows {
    # P0.1 per workspace, whichever way it was produced
    param($Ctx)
    $rows = Get-EbrRows $Ctx.Results 'P0.1-BY-WORKSPACE'
    if ($null -ne $rows -and $rows.Count) { return , $rows }
    $single = Get-EbrRows $Ctx.Results 'P0.1'
    if ($null -eq $single) { return , @() }
    $wss = @($Ctx.Workspaces)
    if ($wss.Count -eq 1) { return , (Add-EbrWorkspaceColumns -Rows $single -Workspace $wss[0]) }
    , @()
}

function Get-EbrPreflightWarnings {
    param($Ctx)
    $w = [System.Collections.Generic.List[string]]::new()
    $reach = Get-EbrReachRows -Ctx $Ctx
    if ($reach.Count) {
        $reachDetail = if ($Ctx.Results.ContainsKey('P0.1-BY-WORKSPACE')) { [string]$Ctx.Results['P0.1-BY-WORKSPACE'].Detail } else { '' }
        foreach ($ws in @($Ctx.Workspaces)) {
            $present = @($reach | Where-Object { [string](Get-EbrProp $_ 'WorkspaceId') -eq [string]$ws.CustomerId } | ForEach-Object { [string](Get-EbrProp $_ 'SourceTable') })
            if ($present.Count -eq 0) {
                # One line for an empty workspace, not one per missing table. Errors are reported elsewhere.
                if ($reachDetail -notmatch [regex]::Escape([string]$ws.WorkspaceName)) {
                    $w.Add("P0.1: workspace $($ws.WorkspaceName) holds no data in any of the incident, alert, sign-in, audit or score tables, so it adds nothing to the figures. To leave it out, pass the other workspaces with -WorkspaceResourceId.")
                }
                continue
            }
            if ('SecurityIncident' -notin $present) { $w.Add("P0.1: workspace $($ws.WorkspaceName) has no SecurityIncident data. Incident figures for it need the CyberSOC reports as the named source.") }
            $missing = @('SecureScores', 'SecurityRecommendation' | Where-Object { $_ -notin $present })
            if ($missing.Count) { $w.Add("P0.1: workspace $($ws.WorkspaceName) has no $($missing -join ' or ') data, so continuous export to it is off. Trends for its subscription need a dated screenshot.") }
        }
    }
    $dup = Get-EbrRows $Ctx.Results 'P0.1-XDRDUP'
    if ($null -ne $dup -and $dup.Count -and [double](Get-EbrProp $dup[0] 'XdrIncidents') -eq 0) {
        $w.Add('P0.1-XDRDUP: No Defender XDR incidents reached Sentinel in the last 365 days. The incident and alert figures (OUT.*) cover Defender for Cloud, Sentinel analytics and Identity Protection only. Defender for Endpoint, Office 365, Identity and Cloud Apps incidents are not in them. Say so on the outcome slides, or take those counts from the Defender portal.')
    }
    if ($null -ne $dup -and $dup.Count -and [double](Get-EbrProp $dup[0] 'InMultipleWorkspaces') -gt 0) {
        $w.Add(('P0.1-XDRDUP: {0} of {1} Defender XDR incidents appear in more than one workspace, so the combined OUT.1 and OUT.3 counts include them more than once. Use the BY-WORKSPACE files to pick one workspace per incident.' -f (Get-EbrProp $dup[0] 'InMultipleWorkspaces'), (Get-EbrProp $dup[0] 'XdrIncidents')))
    }
    $p03 = Get-EbrRows $Ctx.Results 'P0.3'
    if ($null -ne $p03) {
        $cspmOff = @($p03 | Where-Object { (Get-EbrProp $_ 'Plan') -eq 'CloudPosture' -and (Get-EbrProp $_ 'Tier') -eq 'Free' } | ForEach-Object { Get-EbrProp $_ 'subscriptionId' })
        if ($cspmOff.Count) { $w.Add("P0.3: Defender CSPM is off (CloudPosture on Free) in $($cspmOff -join ', '). Do not quote attack path or critical recommendation tiles.") }
        $free = @($p03 | Where-Object { (Get-EbrProp $_ 'Tier') -eq 'Free' } | ForEach-Object { Get-EbrProp $_ 'Plan' } | Select-Object -Unique)
        if ($free.Count) { $w.Add("P0.3: Plans on Free in at least one subscription: $($free -join ', '). These cap the DR.2 coverage figure.") }
    }
    $p04 = Get-EbrRows $Ctx.Results 'P0.4'
    if ($Ctx.Results.ContainsKey('P0.4') -and $Ctx.Results['P0.4'].Status -eq 'UNAVAILABLE') {
        $w.Add("P0.4: Advanced Hunting could not be reached and the Sentinel workspaces do not hold the Defender device, email and identity tables. Every query that needs them is UNAVAILABLE, not zero. Fix the Defender sign-in and rerun, or grade EW-F1, EW-F2 and EW-D1 from Secure Score controls (POS.6) and footnote it. $($Ctx.DefenderReason)")
    }
    elseif ($null -ne $p04) {
        $present = @($p04 | ForEach-Object { [string](Get-EbrProp $_ 'SourceTable') })
        $absentDevice = @('DeviceInfo', 'DeviceTvmSecureConfigurationAssessment', 'DeviceEvents' | Where-Object { $_ -notin $present })
        $absentOther = @('EmailPostDeliveryEvents', 'IdentityLogonEvents' | Where-Object { $_ -notin $present })
        if ($absentDevice.Count) { $w.Add("P0.4: Device tables did not resolve: $($absentDevice -join ', '). Grade EW-F1, EW-F2 and EW-D1 from Secure Score controls (POS.6) and footnote the substitution.") }
        if ($absentOther.Count) {
            if ([string]$Ctx.Results['P0.4'].Source -eq 'Defender Advanced Hunting') {
                $w.Add("P0.4: $($absentOther -join ', ') are not exposed by the Defender for Endpoint hunting API that Azure CLI reaches, so their absence says nothing about whether the client has Defender for Office 365 or Defender for Identity. DP.7 and DR.4 come from Sentinel if it collects those tables. Otherwise run queries/DP.7.kql and queries/DR.4.kql in Defender portal > Advanced hunting.")
            }
            else {
                $w.Add("P0.4: The Sentinel workspaces hold no $($absentOther -join ', ') data. Run queries/DP.7.kql and queries/DR.4.kql in Defender portal > Advanced hunting.")
            }
        }
    }
    $w
}

function New-EbrNotes {
    param($Ctx, $Worksheet)
    $sym = $script:EbrSym
    $inv = [cultureinfo]::InvariantCulture
    $div = '=' * 60
    $sb = [System.Text.StringBuilder]::new()
    $line = { param($t) [void]$sb.AppendLine($t) }

    & $line ''
    & $line $div
    & $line '  TICKET NOTES - COPY BELOW THIS LINE'
    & $line $div
    & $line ''
    & $line ("Script: Get-EbrSecurityEvidence.ps1 v{0}" -f $script:EbrVersion)
    & $line ("Executed: {0} UTC" -f $Ctx.StartedUtc.ToString('yyyy-MM-dd HH:mm:ss', $inv))
    & $line ''
    & $line '--- Scope ---'
    & $line ("  {0} Client tenant: {1} ({2})" -f $sym.Dot, $Ctx.ClientName, $Ctx.TenantGuid)
    & $line ("  {0} Subscriptions ({1}): {2}" -f $sym.Dot, $Ctx.Subscriptions.Count, ($Ctx.Subscriptions -join ', '))
    if ($Ctx.AccessDescription) { & $line ("  {0} Azure access: {1}" -f $sym.Dot, $Ctx.AccessDescription) }
    $wss = @($Ctx.Workspaces)
    if ($wss.Count) {
        & $line ("  {0} Sentinel workspaces ({1}), combined for client-level figures:" -f $sym.Dot, $wss.Count)
        foreach ($ws in $wss) { & $line ("      - {0} (resource group {1}, subscription {2}, retention {3} days)" -f $ws.WorkspaceName, $ws.resourceGroup, $ws.subscriptionId, $ws.RetentionDays) }
        foreach ($t in @($Ctx.TenantWorkspace.Keys | Sort-Object)) {
            & $line ("  {0} Tenant-wide {1} read once, from {2}" -f $sym.Dot, $t, $Ctx.TenantWorkspace[$t].WorkspaceName)
        }
    }
    else { & $line ("  {0} Sentinel workspaces: none found" -f $sym.Dot) }
    $mrg = if ($Ctx.ManagedRgPattern) { $Ctx.ManagedRgPattern } else { 'none (exclusion disabled)' }
    & $line ("  {0} Managed resource group excluded from posture queries: {1}" -f $sym.Dot, $mrg)
    & $line ("  {0} Incident reporting window: {1} to {2} ({3})" -f $sym.Dot, $Ctx.WindowStart.ToString('yyyy-MM-dd', $inv), $Ctx.WindowEnd.ToString('yyyy-MM-dd', $inv), $Ctx.WindowBasis)
    & $line ("  {0} Alert scope: incidents whose comments reference an Atmosera ticket (pattern {1}), informational severity excluded. OUT.1 to OUT.7 count only these." -f $sym.Dot, $(if ($Ctx.PSObject.Properties['TicketPattern'] -and $Ctx.TicketPattern) { $Ctx.TicketPattern } else { $script:EbrTicketPattern }))
    & $line ("  {0} Posture read date: {1}" -f $sym.Dot, $Ctx.StartedUtc.ToString('yyyy-MM-dd', $inv))
    & $line ''
    & $line '--- Collection Summary ---'
    $counts = $Ctx.Manifest | Group-Object Status | Sort-Object Name | ForEach-Object { '{0} {1}' -f $_.Name, $_.Count }
    & $line ("  {0} {1} result sets: {2}" -f $sym.Dot, $Ctx.Manifest.Count, ($counts -join ', '))
    & $line ("  {0} Evidence pack: {1}" -f $sym.Dot, $Ctx.OutDir)
    & $line ''
    $figures = @($Worksheet | Where-Object { $_.Value -and $_.Value -notin 'MANUAL', 'REVIEW' })
    if ($figures.Count) {
        & $line '--- Key Findings ---'
        foreach ($f in $figures) { & $line ("  {0} {1}: {2} [{3}]" -f $sym.Dot, $f.Figure, $f.Value, $f.Query) }
        & $line ''
    }
    $attention = [System.Collections.Generic.List[string]]::new()
    foreach ($m in ($Ctx.Manifest | Where-Object Status -eq 'FAILED')) {
        $d = [string]$m.Detail; if ($d.Length -gt 200) { $d = $d.Substring(0, 197) + '...' }
        $attention.Add(('{0} ({1}) failed: {2}' -f $m.ResultId, $m.Title, $d))
    }
    foreach ($m in ($Ctx.Manifest | Where-Object Status -eq 'PARTIAL')) {
        $d = [string]$m.Detail; if ($d.Length -gt 200) { $d = $d.Substring(0, 197) + '...' }
        $attention.Add(('{0} ({1}) is partial: {2}' -f $m.ResultId, $m.Title, $d))
    }
    foreach ($m in ($Ctx.Manifest | Where-Object Status -eq 'SKIPPED')) { $attention.Add(('{0} ({1}) skipped: {2}' -f $m.ResultId, $m.Title, $m.Detail)) }
    $graphIds = @($Ctx.Manifest | Where-Object { $_.Source -eq 'Microsoft Graph' -and $_.Status -eq 'UNAVAILABLE' } | ForEach-Object ResultId)
    $unavailable = @($Ctx.Manifest | Where-Object { $_.Status -eq 'UNAVAILABLE' -and $_.ResultId -notin $graphIds } | ForEach-Object ResultId)
    if ($unavailable.Count) {
        $why = if ($Ctx.DefenderReason) { ' Advanced Hunting: ' + $Ctx.DefenderReason } else { '' }
        $attention.Add('No data source, so no figure (these are not zeros): ' + ($unavailable -join ', ') + '.' + $why + ' Their queries are saved in the queries folder as ID.kql files to run by hand in Defender portal > Advanced hunting.')
    }
    if ($Ctx.DefenderAdvice) { $attention.Add('Defender access: ' + $Ctx.DefenderAdvice) }
    if ($Ctx.PSObject.Properties['GraphAvailable'] -and -not $Ctx.GraphAvailable -and $Ctx.GraphReason) {
        $attention.Add('Microsoft Graph: ' + $Ctx.GraphReason + $(if ($Ctx.GraphAdvice) { ' ' + $Ctx.GraphAdvice } else { '' }) + ' Graph measures read UNAVAILABLE with their portal path. Their substitutes still ran.')
    }
    if ($Ctx.PSObject.Properties['GraphMissingScopes'] -and @($Ctx.GraphMissingScopes).Count) {
        $scopes = @($Ctx.GraphMissingScopes)
        $partial = if ($Ctx.PSObject.Properties['GraphPartial']) { @($Ctx.GraphPartial) } else { @() }
        $who = @()
        if ($graphIds.Count) { $who += ($graphIds -join ', ') }
        if ($partial.Count) { $who += ('partly ' + ($partial -join ', ')) }
        # az login --scope takes several scopes as separate arguments (nargs +), so no quotes around the list
        $attention.Add(('Graph permissions missing for {0}: {1}. The unavailable ones are not zeros and keep their portal path. Fix: az login --tenant {2} --scope {3}, then rerun. Each scope needs consent in the client tenant, which a GDAP or guest account may not be able to give.' -f ($who -join ', and '), ($scopes -join ', '), $Ctx.TenantGuid, (@($scopes | ForEach-Object { 'https://graph.microsoft.com/' + $_ }) -join ' ')))
    }
    foreach ($w in $Ctx.Warnings) { $attention.Add($w) }
    $manual = @($Ctx.Manifest | Where-Object Status -eq 'MANUAL' | ForEach-Object ResultId)
    if ($manual.Count) { $attention.Add('Manual portal readings still needed: ' + ($manual -join ', ') + '. Paths are in 00-manifest.csv and 01-worksheet.csv.') }
    $review = @($Worksheet | Where-Object Value -eq 'REVIEW' | ForEach-Object Figure)
    if ($review.Count) { $attention.Add('Analyst calculation needed for: ' + ($review -join ', ') + '.') }
    if ($attention.Count) {
        & $line '--- Attention Required ---'
        foreach ($a in $attention) { & $line ("  {0} {1}" -f $sym.Warn, $a) }
        & $line ''
    }
    & $line $div
    & $line '  END OF NOTES'
    & $line $div
    $sb.ToString()
}

function Invoke-EbrMain {
    param(
        [string]$TenantId, [string[]]$SubscriptionId, [string[]]$WorkspaceResourceId,
        [string]$WindowStart, [string]$WindowEnd, [AllowEmptyString()][string]$ManagedRgPattern, [string]$TicketPattern,
        [string]$ClientName, [string]$OutputPath, [switch]$SkipExchange, [switch]$SkipDefender,
        [switch]$SkipGraph, [int]$PatchCadenceDays = 30,
        [AllowEmptyString()][string]$PatchExclusionTagPattern, [AllowEmptyString()][string]$EdrVendorPattern = '',
        [switch]$SkipWorkspaceBreakdown, [switch]$DryRun,
        [switch]$SkipHtmlReport, [ValidateSet('Brief', 'Balanced', 'Detailed')][string]$ReportDepth = 'Balanced',
        [switch]$SkipSecOpsWorklist
    )
    $ErrorActionPreference = 'Stop'
    try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
    # .NET file APIs resolve relative paths against the process directory, not PowerShell's. Fun.
    $OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

    $inv = [cultureinfo]::InvariantCulture
    $totalSteps = 10
    $ctx = [pscustomobject]@{
        StartedUtc = (Get-Date).ToUniversalTime(); TenantGuid = $null; ClientName = $null; Subscriptions = @()
        ArmTenant = $null; Workspaces = @(); TenantWorkspace = @{}; SkipBreakdown = [bool]$SkipWorkspaceBreakdown
        DefenderAvailable = $false; DefenderReason = ''; DefenderAdvice = ''; FallbackChecked = $false; FallbackTables = $null
        GraphAvailable = $false; GraphReason = ''; GraphAdvice = ''; GraphCache = @{}; GraphMissingScopes = [System.Collections.Generic.List[string]]::new(); GraphPartial = [System.Collections.Generic.List[string]]::new()
        PatchCadenceDays = $(if ($PatchCadenceDays -ge 1) { $PatchCadenceDays } else { 30 })
        PatchExclusionTagPattern = $(if ($PSBoundParameters.ContainsKey('PatchExclusionTagPattern')) { $PatchExclusionTagPattern } else { $script:EbrPatchExclusionTagPattern })
        EdrVendorPattern = $(if ([string]::IsNullOrWhiteSpace($EdrVendorPattern)) { $script:EbrEdrVendorPattern } else { $EdrVendorPattern })
        AccessPath = ''; AccessDescription = ''
        WindowStart = $null; WindowEnd = $null; WindowBasis = ''; ManagedRgPattern = $ManagedRgPattern
        TicketPattern = $(if ([string]::IsNullOrWhiteSpace($TicketPattern)) { $script:EbrTicketPattern } else { $TicketPattern })
        OutDir = $null; Results = @{}; Manifest = [System.Collections.Generic.List[object]]::new()
        Warnings = [System.Collections.Generic.List[string]]::new(); Pending = [System.Collections.Generic.List[object]]::new()
        Durations = [System.Collections.Generic.List[double]]::new(); Done = 0; Total = 0
    }

    Write-Host ''
    Write-Host $script:EbrSym.Heavy -ForegroundColor Blue
    Write-Host ("  EBR Security Evidence Collector v{0}" -f $script:EbrVersion) -ForegroundColor Blue
    Write-Host '  READ-ONLY. It looks, it counts, it judges. Silently. Mostly.' -ForegroundColor DarkGray
    Write-Host $script:EbrSym.Heavy -ForegroundColor Blue

    try {
        #region Step 1: inputs
        Write-EbrStep 1 $totalSteps 'Gathering inputs (tenant and subscriptions, that is all I ask)'
        if ($TenantId) {
            if (-not (Test-EbrTenantInput $TenantId)) { throw "TenantId '$TenantId' is neither a GUID nor a domain. Stellar work on that parameter." }
        }
        else {
            $TenantId = Read-EbrInput -Prompt 'Client tenant ID or domain' -Validator { param($v) Test-EbrTenantInput $v } -Hint 'A GUID or something like contoso.onmicrosoft.com.'
        }
        if ($SubscriptionId) {
            $ctx.Subscriptions = Split-EbrSubscriptionInput $SubscriptionId
        }
        else {
            $raw = Read-EbrInput -Prompt 'Client subscription ID(s), comma separated' -Validator { param($v) try { $null = Split-EbrSubscriptionInput @($v); $true } catch { $false } } -Hint 'Subscription GUIDs, separated by commas.'
            $ctx.Subscriptions = Split-EbrSubscriptionInput @($raw)
        }
        $ctx.Subscriptions = @($ctx.Subscriptions)
        $startOverride = if ($WindowStart) { ConvertTo-EbrDate $WindowStart } else { $null }
        $endOverride = if ($WindowEnd) { ConvertTo-EbrDate $WindowEnd } else { $null }
        if ($startOverride -and $endOverride -and $startOverride -gt $endOverride) { throw 'WindowStart is after WindowEnd. Time travel is out of scope.' }
        $null = Expand-EbrQuery -Query 'x' -WindowStart ([datetime]::Today) -WindowEnd ([datetime]::Today) -ManagedRgPattern $ManagedRgPattern -TicketPattern $TicketPattern
        Write-EbrOk ("Tenant {0}, {1} subscription(s)." -f $TenantId, $ctx.Subscriptions.Count)
        #endregion

        $catalog = Get-EbrQueryCatalog

        if ($DryRun) {
            Write-EbrStep 2 $totalSteps 'Dry run: expanding every query without touching anything'
            $ctx.TenantGuid = if (Test-EbrGuid $TenantId) { $TenantId.ToLowerInvariant() } else { $TenantId }
            $ctx.ClientName = if ($ClientName) { $ClientName } else { $ctx.TenantGuid }
            $def = Get-EbrDefaultReportingWindow
            $ctx.WindowStart = if ($startOverride) { $startOverride } else { $def.Start }
            $ctx.WindowEnd = if ($endOverride) { $endOverride } else { $def.End }
            $ctx.WindowBasis = if ($startOverride) { 'set by parameter' } else { 'dry run default (the real run uses P0.1)' }
            $ctx.OutDir = Join-Path $OutputPath ('EBR-Evidence_DRYRUN_{0}_{1}' -f (ConvertTo-EbrSafeFileName $ctx.ClientName), (Get-Date -Format 'yyyyMMdd-HHmmss'))
            foreach ($sub in 'queries', 'results') { [void][IO.Directory]::CreateDirectory((Join-Path $ctx.OutDir $sub)) }
            Set-EbrLogPath (Join-Path $ctx.OutDir 'run.log')
            foreach ($item in $catalog) {
                if ($item.Query) {
                    $text = Expand-EbrQuery -Query $item.Query -WindowStart $ctx.WindowStart -WindowEnd $ctx.WindowEnd -ManagedRgPattern $ManagedRgPattern -TicketPattern $TicketPattern -PatchCadenceDays $ctx.PatchCadenceDays -PatchExclusionTagPattern $ctx.PatchExclusionTagPattern -EdrVendorPattern $ctx.EdrVendorPattern
                    Write-EbrQueryFile -OutDir $ctx.OutDir -Item $item -Text $text -Target ('dry run; subscriptions: ' + ($ctx.Subscriptions -join ', '))
                }
                $status = if ($item.Engine -eq 'MANUAL') { 'MANUAL' } else { 'DRYRUN' }
                Add-EbrResult -Ctx $ctx -Item $item -Result (New-EbrResult -ResultId $item.Id -Status $status -Source $item.Engine -Detail $(if ($status -eq 'MANUAL') { $item.Notes } else { '' }))
            }
            Write-EbrCsvFile -Path (Join-Path $ctx.OutDir '00-manifest.csv') -Rows $ctx.Manifest
            Write-EbrOk ("Dry run written to {0}. Nothing was signed into, queried or harmed." -f $ctx.OutDir) -Snark
            return 0
        }

        #region Step 2: prerequisites
        Write-EbrStep 2 $totalSteps 'Checking prerequisites'
        if (-not (Test-EbrAzCli)) {
            throw 'Azure CLI (az) not found. Install it (winget install Microsoft.AzureCLI, or brew install azure-cli) and rerun. I would do it for you, but installing system software is not a read-only hobby.'
        }
        Write-EbrOk ("PowerShell {0}, Azure CLI present." -f $PSVersionTable.PSVersion)
        if ($PSVersionTable.PSVersion.Major -lt 7) { Write-EbrWarn 'Windows PowerShell 5.1 works, but very large Log Analytics results parse faster and safer in PowerShell 7.' }
        #endregion

        #region Step 3: sign-in and scope
        Write-EbrStep 3 $totalSteps 'Signing in and checking scope (no cross-client contamination on my watch)'
        $ctx.TenantGuid = Resolve-EbrTenantGuid $TenantId
        $accounts = Get-EbrAzAccounts
        $missing = @($ctx.Subscriptions | Where-Object { $s = $_; -not ($accounts | Where-Object { ([string]$_.id).ToLowerInvariant() -eq $s }) })
        if ($null -eq $accounts -or $missing.Count) {
            Write-EbrWarn ("Azure CLI cannot see {0} of the subscriptions yet. Opening a browser sign-in: az login --tenant {1}" -f $(if ($null -eq $accounts) { 'any' } else { $missing.Count }), $TenantId)
            Invoke-EbrAzLogin -Tenant $TenantId
            $accounts = Get-EbrAzAccounts
            $missing = @($ctx.Subscriptions | Where-Object { $s = $_; -not ($accounts | Where-Object { ([string]$_.id).ToLowerInvariant() -eq $s }) })
            if ($null -eq $accounts -or $missing.Count) {
                throw ("Still cannot see subscription(s) {0}. If you reach this client through Lighthouse, run 'az login' against your managing tenant and rerun." -f ($missing -join ', '))
            }
        }
        $subAccess = @{}
        foreach ($sub in $ctx.Subscriptions) {
            $acct = $accounts | Where-Object { ([string]$_.id).ToLowerInvariant() -eq $sub } | Select-Object -First 1
            if (-not (Test-EbrSubscriptionTenant -Account $acct -TenantGuid $ctx.TenantGuid)) {
                $homeTenant = if ($acct.PSObject.Properties['homeTenantId'] -and $acct.homeTenantId) { $acct.homeTenantId } else { $acct.tenantId }
                throw "Subscription $sub ($($acct.name)) is homed in tenant $homeTenant, not the client tenant $($ctx.TenantGuid). Refusing to blend two clients into one deck."
            }
            if ([string]$acct.state -ne 'Enabled') { Write-EbrWarn "Subscription $sub is in state '$($acct.state)'." }
            Write-EbrInfo ("{0} {1} ({2})" -f $script:EbrSym.Dot, $acct.name, $sub)
        }
        # Direct access to the client tenant beats Lighthouse: same data, except IA.7 is only
        # complete directly. Offers az login --tenant <what you typed> when direct isn't there yet.
        $access = Resolve-EbrAccessPath -TenantGuid $ctx.TenantGuid -TenantInput $TenantId -Subscriptions $ctx.Subscriptions -Accounts $accounts
        $subAccess = $access.SubAccess
        $ctx.ArmTenant = $access.ArmTenant
        $ctx.AccessPath = $access.Path
        $ctx.AccessDescription = if ($access.Path -eq 'Direct') { 'direct sign-in to the client tenant' } else { "Lighthouse, through managing tenant $($access.ArmTenant)" }
        if ($access.Warning) { $ctx.Warnings.Add($access.Warning); Write-EbrWarn $access.Warning }
        $accessTenants = @($subAccess.Values | Select-Object -Unique)
        if ($accessTenants.Count -gt 1) { Write-EbrWarn "Subscriptions are reached through different tenants ($($accessTenants -join ', ')). Resource Graph uses $($ctx.ArmTenant). Subscriptions only visible through another tenant may return nothing." }
        $via = if ($ctx.AccessPath -eq 'Direct') { 'directly (complete role assignment data)' } else { "through managing tenant $($ctx.ArmTenant) (Lighthouse)" }
        $null = Get-EbrToken -Resource 'https://management.azure.com/' -Tenant $ctx.ArmTenant
        Write-EbrOk "All subscriptions belong to the client tenant and are reached $via." -Snark

        $info = Get-EbrTenantInfo -TenantGuid $ctx.TenantGuid -ArmTenant $ctx.ArmTenant

        if ($SkipDefender) { $ctx.DefenderReason = 'Skipped with -SkipDefender.' }
        else { Initialize-EbrDefender -Ctx $ctx }
        if ($SkipGraph) { $ctx.GraphReason = 'Skipped with -SkipGraph.' }
        else { Initialize-EbrGraph -Ctx $ctx }
        #endregion

        #region Step 4: workspaces and output folder
        Write-EbrStep 4 $totalSteps 'Finding the Sentinel workspaces (all of them, one per subscription is fine)'
        $workspaces = @(Find-EbrWorkspaces -Subscriptions $ctx.Subscriptions -Tenant $ctx.ArmTenant)
        $chosen = @()
        if ($WorkspaceResourceId) {
            foreach ($wanted in @($WorkspaceResourceId | ForEach-Object { $_ -split '[,;\s]+' } | Where-Object { $_ })) {
                $match = $workspaces | Where-Object { $_.WorkspaceResourceId -eq $wanted.TrimEnd('/').ToLowerInvariant() } | Select-Object -First 1
                if (-not $match) { throw "Workspace $wanted is not in the client subscriptions. Typo, or wrong client?" }
                $chosen += $match
            }
        }
        else {
            $chosen = @($workspaces | Where-Object { Test-EbrTrue $_.HasSentinel })
            if ($chosen.Count -eq 0 -and $workspaces.Count) {
                Write-EbrWarn 'No workspace has the Sentinel solution. Pick from all Log Analytics workspaces instead:'
                for ($i = 0; $i -lt $workspaces.Count; $i++) {
                    Write-Host ('    [{0}] {1}  (rg {2}, sub {3})' -f ($i + 1), $workspaces[$i].WorkspaceName, $workspaces[$i].resourceGroup, $workspaces[$i].subscriptionId)
                }
                $max = $workspaces.Count
                $pick = Read-EbrInput -Prompt "Workspace numbers, comma separated, or 'all'" -Default 'all' -Hint "Numbers from 1 to $max, or all." -Validator {
                    param($v)
                    if ($v -eq 'all') { return $true }
                    $nums = @($v -split '[,;\s]+' | Where-Object { $_ })
                    $nums.Count -gt 0 -and -not ($nums | Where-Object { $n = 0; -not ([int]::TryParse($_, [ref]$n) -and $n -ge 1 -and $n -le $max) })
                }
                $chosen = if ($pick -eq 'all') { $workspaces } else { @($pick -split '[,;\s]+' | Where-Object { $_ } | ForEach-Object { [int]$_ } | Select-Object -Unique | ForEach-Object { $workspaces[$_ - 1] }) }
            }
        }
        $ctx.Workspaces = @(foreach ($ws in $chosen) {
                $access = $subAccess[[string]$ws.subscriptionId]
                if (-not $access) { $access = $ctx.ArmTenant }
                $ws | Add-Member -NotePropertyName AccessTenant -NotePropertyValue $access -Force -PassThru
            })
        if ($ctx.Workspaces.Count) {
            foreach ($ws in $ctx.Workspaces) { Write-EbrInfo ("{0} {1} (rg {2}, sub {3}, retention {4} days)" -f $script:EbrSym.Dot, $ws.WorkspaceName, $ws.resourceGroup, $ws.subscriptionId, $ws.RetentionDays) }
            $extra = if ($ctx.Workspaces.Count -gt 1) { ' Client figures combine them; BY-WORKSPACE files split them.' } else { '' }
            Write-EbrOk ("{0} Sentinel workspace(s) in scope.{1}" -f $ctx.Workspaces.Count, $extra) -Snark
            if ($ctx.Workspaces.Count -gt 1 -and -not $SkipWorkspaceBreakdown) { Write-EbrQuip 'Every workspace-level query runs once per workspace and once combined. Coffee is now mandatory.' }
        }
        else {
            Write-EbrWarn 'No Log Analytics workspace in these subscriptions. Every Log Analytics query will be skipped, which is most of Phase 1.'
            $ctx.Warnings.Add('No Sentinel workspace found in the client subscriptions. Log Analytics queries were skipped.')
        }

        $ctx.Total = @($catalog | Where-Object { $_.Engine -notin 'EXO', 'IPPS' }).Count
        #endregion

        #region Step 5: Exchange Online and Purview (interactive, so it goes first)
        Write-EbrStep 5 $totalSteps 'Exchange Online and Purview (the bit that needs you; after this, go get coffee)'
        $exoItem = $catalog | Where-Object Id -eq 'IA.9'
        $ippsItem = $catalog | Where-Object Id -eq 'DP.6'
        $exoResults = @()
        $orgName = $null
        $allExoIds = 'IA.9', 'IA.9-RULES', 'IA.9-ATP', 'IA.9-SAFELINKS', 'IA.9-SAFEATTACH', 'DP.7-ZAP', 'DP.6'
        if ($SkipExchange) {
            $exoResults = foreach ($id in $allExoIds) { New-EbrResult -ResultId $id -Status 'SKIPPED' -Source 'Exchange Online' -Detail 'Skipped with -SkipExchange.' }
        }
        elseif (-not (Install-EbrModuleIfMissing 'ExchangeOnlineManagement')) {
            $exoResults = foreach ($id in $allExoIds) { New-EbrResult -ResultId $id -Status 'FAILED' -Source 'Exchange Online' -Detail 'ExchangeOnlineManagement module unavailable.' }
        }
        else {
            $delegated = $null
            try {
                $claims = Get-EbrJwtClaims (Get-EbrToken -Resource 'https://management.azure.com/' -Tenant $ctx.TenantGuid)
                if (Test-EbrExternalUser -Claims $claims -TenantGuid $ctx.TenantGuid) { $delegated = $true }
            }
            catch { $delegated = $true }
            $delegatedOrg = $null
            if ($delegated) {
                $delegatedOrg = if (-not (Test-EbrGuid $TenantId)) { $TenantId } elseif ($info -and $info.InitialDomain) { $info.InitialDomain } else { $ctx.TenantGuid }
                Write-EbrInfo "Signing in as a partner or guest, so using -DelegatedOrganization $delegatedOrg."
            }
            Write-EbrInfo 'A browser window or two will open for Exchange Online and Purview.'
            $exo = Get-EbrExchangeEvidence -DelegatedOrganization $delegatedOrg
            $exoResults = $exo.Results
            $orgName = $exo.OrgName
        }

        # Named only now, so the folder can use the organization name Exchange just told us
        $ctx.ClientName = Get-EbrClientName -Override $ClientName -TenantInfo $info -Accounts $accounts -TenantGuid $ctx.TenantGuid -TenantInput $TenantId -OrgName $orgName
        if ($ctx.ClientName -eq $ctx.TenantGuid) { Write-EbrQuip 'Could not find a name for this tenant. Pass -ClientName next time and the folder will thank you.' }
        $ctx.OutDir = Join-Path $OutputPath ('EBR-Evidence_{0}_{1}' -f (ConvertTo-EbrSafeFileName $ctx.ClientName), (Get-Date -Format 'yyyyMMdd-HHmmss'))
        foreach ($sub in 'queries', 'results') { [void][IO.Directory]::CreateDirectory((Join-Path $ctx.OutDir $sub)) }
        Set-EbrLogPath (Join-Path $ctx.OutDir 'run.log')
        Write-EbrInfo "Evidence pack: $($ctx.OutDir)"
        $exoTitles = @{
            'IA.9-RULES' = 'Anti-phishing rules'; 'IA.9-ATP' = 'Preset security policy rules'
            'IA.9-SAFELINKS' = 'Safe Links policies'; 'IA.9-SAFEATTACH' = 'Safe Attachments policies'
        }
        foreach ($r in $exoResults) {
            $own = $catalog | Where-Object Id -eq $r.ResultId | Select-Object -First 1
            $item = if ($own) { $own } elseif ($r.ResultId -eq 'DP.6') { $ippsItem } elseif ($exoTitles.ContainsKey($r.ResultId)) {
                [pscustomobject]@{ Phase = $exoItem.Phase; Title = $exoTitles[$r.ResultId]; Engine = 'EXO'; Notes = 'Supplementary IA.9 and DP-F3 evidence.' }
            } else { $exoItem }
            Add-EbrResult -Ctx $ctx -Item $item -Result $r
        }
        #endregion

        #region Step 6: Phase 0 and the reporting window
        Write-EbrStep 6 $totalSteps 'Phase 0: pre-flight, and deciding the reporting window'
        # Phase 0 queries carry no window tokens, but expansion still needs dates. Provisional
        # window now, real one after P0.1 says how far back the incidents go.
        $provisional = Get-EbrDefaultReportingWindow
        $ctx.WindowStart = if ($startOverride) { $startOverride } else { $provisional.Start }
        $ctx.WindowEnd = if ($endOverride) { $endOverride } else { $provisional.End }
        Invoke-EbrPhase -Ctx $ctx -Items @($catalog | Where-Object { $_.Phase -like 'P0*' }) -Activity 'Phase 0 pre-flight'

        $reach = Get-EbrReachRows -Ctx $ctx
        foreach ($table in 'SigninLogs', 'AuditLogs') {
            if ($ctx.Workspaces.Count) {
                $ctx.TenantWorkspace[$table] = Select-EbrTenantWorkspace -Workspaces $ctx.Workspaces -ReachRows $reach -Table $table
                if ($ctx.Workspaces.Count -gt 1) { Write-EbrInfo ("Tenant-wide {0} will be read once, from {1} (it holds the most)." -f $table, $ctx.TenantWorkspace[$table].WorkspaceName) }
            }
        }
        $inc = Get-EbrEarliestIncident -ReachRows $reach
        $earliest = $inc.Earliest
        $retention = $null
        $retentions = @($ctx.Workspaces | Where-Object { $_.RetentionDays } | ForEach-Object { [int]$_.RetentionDays })
        if ($retentions.Count) { $retention = ($retentions | Measure-Object -Maximum).Maximum }
        $def = Get-EbrDefaultReportingWindow -EarliestIncident $earliest -RetentionDays $retention
        $ctx.WindowStart = if ($startOverride) { $startOverride } else { $def.Start }
        $ctx.WindowEnd = if ($endOverride) { $endOverride } else { $def.End }
        $ctx.WindowBasis = if ($startOverride -or $endOverride) { 'set by parameter' } else { $def.Basis }
        $earliestWs = $ctx.Workspaces | Where-Object { [string]$_.CustomerId -eq [string]$inc.EarliestWorkspaceId } | Select-Object -First 1
        $wsRetention = if ($earliestWs -and $earliestWs.RetentionDays) { [int]$earliestWs.RetentionDays } elseif ($retention) { [int]$retention } else { 0 }
        if ($earliest -and (Test-EbrRetentionBound -Earliest $earliest -RetentionDays $wsRetention)) {
            $wsName = if ($earliestWs) { $earliestWs.WorkspaceName } else { 'the workspace' }
            $msg = 'Incident data starts {0}, which is the {1}-day retention limit of {2}, not the service start. Older incidents were purged: anything before {0} needs a search job against archived data (if long-term retention is set) or the CyberSOC reports.' -f $earliest.ToString('yyyy-MM-dd', $inv), $wsRetention, $wsName
            $ctx.Warnings.Add($msg)
            Write-EbrWarn $msg
            if (-not ($startOverride -or $endOverride)) { $ctx.WindowBasis += ", cut off by the $wsRetention-day workspace retention" }
        }
        if ($earliest -and $ctx.WindowStart -lt $earliest.Date) {
            $ctx.Warnings.Add(('The window starts {0} but SecurityIncident data only reaches back to {1}. Figures before that need a search job or the CyberSOC reports.' -f $ctx.WindowStart.ToString('yyyy-MM-dd', $inv), $earliest.ToString('yyyy-MM-dd', $inv)))
        }
        if ($inc.PerWorkspace.Count -gt 1) {
            $ctx.Warnings.Add(('Earliest SecurityIncident record per workspace: {0}. A workspace that starts later contributes nothing before that date. Say so on any slide that compares months.' -f ($inc.PerWorkspace -join ', ')))
        }
        Write-EbrOk ("Reporting window {0} to {1} ({2})." -f $ctx.WindowStart.ToString('yyyy-MM-dd', $inv), $ctx.WindowEnd.ToString('yyyy-MM-dd', $inv), $ctx.WindowBasis)
        foreach ($w in (Get-EbrPreflightWarnings -Ctx $ctx)) { $ctx.Warnings.Add($w); Write-EbrWarn $w }
        #endregion

        #region Steps 7 to 9: the rest of the runbook
        Write-EbrStep 7 $totalSteps 'Phase 1: outcomes and SOC performance'
        Invoke-EbrPhase -Ctx $ctx -Items @($catalog | Where-Object { $_.Phase -like 'P1*' }) -Activity 'Phase 1 outcomes'
        $out2 = Get-EbrRows $ctx.Results 'OUT.2'
        if ($out2) {
            $all = $out2 | Where-Object { (Get-EbrProp $_ 'Scope') -eq 'All' } | Select-Object -First 1
            if ($all -and [double](Get-EbrProp $all 'Incidents') -gt 0 -and ([double](Get-EbrProp $all 'AutoClosed') / [double](Get-EbrProp $all 'Incidents')) -ge 0.5) {
                $msg = 'OUT.2: at least half the closed incidents were closed by automation rules, so the worksheet quotes the analyst-handled median (OUT.2-ANALYST) and labels it that way.'
                $ctx.Warnings.Add($msg); Write-EbrWarn $msg
            }
        }

        Write-EbrStep 8 $totalSteps 'Phase 2: control evidence across all five pillars'
        Invoke-EbrPhase -Ctx $ctx -Items @($catalog | Where-Object { $_.Phase -like 'P2*' -and $_.Engine -notin 'EXO', 'IPPS' }) -Activity 'Phase 2 control evidence'

        Write-EbrStep 9 $totalSteps 'Phases 3 and 4: posture, benchmark and backlog'
        Invoke-EbrPhase -Ctx $ctx -Items @($catalog | Where-Object { $_.Phase -like 'P3*' -or $_.Phase -like 'P4*' }) -Activity 'Phases 3 and 4'
        #endregion

        #region Step 10: worksheet, manifest, notes
        Write-EbrStep 10 $totalSteps 'Writing the worksheet, manifest and notes'
        $worksheet = @(Get-EbrWorksheet -Results $ctx.Results -WindowStart $ctx.WindowStart -WindowEnd $ctx.WindowEnd)
        Write-EbrCsvFile -Path (Join-Path $ctx.OutDir '01-worksheet.csv') -Rows $worksheet
        Write-EbrCsvFile -Path (Join-Path $ctx.OutDir '00-manifest.csv') -Rows $ctx.Manifest
        $params = [ordered]@{
            ScriptVersion       = $script:EbrVersion
            RunStartedUtc       = Format-EbrUtc $ctx.StartedUtc
            ClientName          = $ctx.ClientName
            TenantId            = $ctx.TenantGuid
            Subscriptions       = @($ctx.Subscriptions)
            AccessTenant        = $ctx.ArmTenant
            AccessPath          = $ctx.AccessPath
            Workspaces          = @($ctx.Workspaces | ForEach-Object { [ordered]@{ Name = $_.WorkspaceName; ResourceId = $_.WorkspaceResourceId; CustomerId = $_.CustomerId; SubscriptionId = $_.subscriptionId; RetentionDays = $_.RetentionDays; AccessTenant = $_.AccessTenant } })
            TenantWideTables    = [ordered]@{ SigninLogs = $(if ($ctx.TenantWorkspace['SigninLogs']) { $ctx.TenantWorkspace['SigninLogs'].WorkspaceName } else { $null }); AuditLogs = $(if ($ctx.TenantWorkspace['AuditLogs']) { $ctx.TenantWorkspace['AuditLogs'].WorkspaceName } else { $null }) }
            WorkspaceBreakdown  = -not $SkipWorkspaceBreakdown
            ManagedRgPattern    = $ctx.ManagedRgPattern
            WindowStart         = $ctx.WindowStart.ToString('yyyy-MM-dd', $inv)
            WindowEnd           = $ctx.WindowEnd.ToString('yyyy-MM-dd', $inv)
            WindowBasis         = $ctx.WindowBasis
            RecentStart         = (Get-EbrRecentStart -WindowStart $ctx.WindowStart -WindowEnd $ctx.WindowEnd).ToString('yyyy-MM-dd', $inv)
            TicketPattern       = $ctx.TicketPattern
            AlertScope          = 'Sentinel incidents with an Atmosera ticket reference in their comments or closing comment. Informational severity excluded. Applies to OUT.1 to OUT.7.'
            AppliancePattern    = $script:EbrAppliancePattern
            PostureReadDate     = $ctx.StartedUtc.ToString('yyyy-MM-dd', $inv)
            DefenderApi         = $(if ($ctx.DefenderAvailable) { 'available' } else { $ctx.DefenderReason })
            GraphApi            = $(if ($ctx.GraphAvailable) { 'available' } else { $ctx.GraphReason })
            GraphMissingScopes  = @($ctx.GraphMissingScopes)
            GraphPartial        = @($ctx.GraphPartial)
            PatchCadenceDays    = $ctx.PatchCadenceDays
            PatchExclusionTagPattern = $ctx.PatchExclusionTagPattern
            EdrVendorPattern    = $ctx.EdrVendorPattern
            ExchangeAndPurview  = $(if ($SkipExchange) { 'skipped' } else { 'attempted' })
            Warnings            = @($ctx.Warnings)
        }
        Write-EbrTextFile -Path (Join-Path $ctx.OutDir '00-parameters.json') -Text (ConvertTo-Json -InputObject $params -Depth 6)
        $notes = New-EbrNotes -Ctx $ctx -Worksheet $worksheet
        Write-EbrTextFile -Path (Join-Path $ctx.OutDir '02-notes.txt') -Text $notes -Bom

        $reportFailed = $false
        if (-not $SkipHtmlReport) {
            try {
                $reportGenerator = Join-Path $PSScriptRoot 'New-EbrSecurityReport.ps1'
                if (-not (Test-Path -LiteralPath $reportGenerator)) { throw 'New-EbrSecurityReport.ps1 is missing from the collector folder.' }
                $reportFiles = @(& $reportGenerator -EvidencePath $ctx.OutDir -Depth $ReportDepth)
                Write-EbrLog -Level INFO -Component Report -Message ('Report created: {0}' -f ($reportFiles -join ', '))
            }
            catch {
                $reportFailed = $true
                Write-EbrWarn "Evidence collection completed. HTML report generation needs attention: $($_.Exception.Message)"
                Write-EbrLog -Level WARN -Component Report -Message $_.Exception.Message
            }
        }

        if (-not $SkipSecOpsWorklist) {
            try {
                $worklistGenerator = Join-Path $PSScriptRoot 'New-EbrSecOpsWorklist.ps1'
                if (-not (Test-Path -LiteralPath $worklistGenerator)) { throw 'New-EbrSecOpsWorklist.ps1 is missing from the collector folder.' }
                $worklistFiles = @(& $worklistGenerator -EvidencePath $ctx.OutDir)
                Write-EbrLog -Level INFO -Component Report -Message ('SecOps worklist created: {0}' -f ($worklistFiles -join ', '))
            }
            catch {
                $reportFailed = $true
                Write-EbrWarn "Evidence collection completed. SecOps worklist generation needs attention: $($_.Exception.Message)"
                Write-EbrLog -Level WARN -Component Report -Message $_.Exception.Message
            }
        }

        $failed = @($ctx.Manifest | Where-Object { $_.Status -in 'FAILED', 'PARTIAL', 'UNAVAILABLE' }).Count
        $elapsed = (Get-Date).ToUniversalTime() - $ctx.StartedUtc
        Write-Host ''
        Write-Host $script:EbrSym.Heavy -ForegroundColor Green
        Write-Host '  EXECUTION SUMMARY (yes, I kept track. You are welcome.)' -ForegroundColor Green
        Write-Host $script:EbrSym.Heavy -ForegroundColor Green
        foreach ($g in ($ctx.Manifest | Group-Object Status | Sort-Object Name)) { Write-Host ('  {0,-8} {1}' -f $g.Name, $g.Count) }
        Write-Host ('  Elapsed  {0:hh\:mm\:ss}' -f $elapsed)
        Write-Host ('  Output   {0}' -f $ctx.OutDir)
        Write-Host $notes
        if ($failed) {
            Write-EbrWarn "$failed result set(s) failed, are partial or have no data source. Details in 00-manifest.csv and run.log."
            return 2
        }
        if ($reportFailed) { return 2 }
        Write-EbrOk 'Everything that could be collected was collected.' -Snark
        return 0
        #endregion
    }
    catch {
        Write-Progress -Id 1 -Activity 'EBR evidence' -Completed
        Write-EbrFail $_.Exception.Message
        Write-EbrLog -Level CRITICAL -Component Main -Message $_.Exception.Message
        if ($ctx.OutDir -and (Test-Path $ctx.OutDir) -and $ctx.Manifest.Count) {
            try { Write-EbrCsvFile -Path (Join-Path $ctx.OutDir '00-manifest.csv') -Rows $ctx.Manifest } catch { }
        }
        return 1
    }
}

#endregion

if ($LoadFunctionsOnly) { return }

# On 2026-10-14 a click in the window after each sign-in, and each copy of the output, paused a Windows run until Enter
$quickEditMode = Disable-EbrQuickEdit
try {
    # The patch exclusion pattern is passed only when it was given, so an empty string (exclusion off) and
    # the default stay distinct.
    $patternArgs = @{ EdrVendorPattern = $EdrVendorPattern }
    if ($PSBoundParameters.ContainsKey('PatchExclusionTagPattern')) { $patternArgs.PatchExclusionTagPattern = $PatchExclusionTagPattern }
    $mainOutput = Invoke-EbrMain -TenantId $TenantId -SubscriptionId $SubscriptionId -WorkspaceResourceId $WorkspaceResourceId `
        -WindowStart $WindowStart -WindowEnd $WindowEnd -ManagedRgPattern $ManagedRgPattern -TicketPattern $TicketPattern -ClientName $ClientName `
        -OutputPath $OutputPath -SkipExchange:$SkipExchange -SkipDefender:$SkipDefender `
        -SkipGraph:$SkipGraph -PatchCadenceDays $PatchCadenceDays @patternArgs `
        -SkipWorkspaceBreakdown:$SkipWorkspaceBreakdown -DryRun:$DryRun `
        -SkipHtmlReport:$SkipHtmlReport -ReportDepth $ReportDepth -SkipSecOpsWorklist:$SkipSecOpsWorklist
}
finally { Restore-EbrQuickEdit $quickEditMode }
# The exit code is the last thing main emits. Anything else that leaked is ignored, not exited with.
$exitCode = @($mainOutput)[-1]
if ($exitCode -isnot [int]) { $exitCode = 1 }
exit $exitCode
