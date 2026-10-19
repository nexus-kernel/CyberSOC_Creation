<#
.SYNOPSIS
    Writes the internal SecOps worklist from an existing CyberSOC evidence pack.
.DESCRIPTION
    Offline only. Reads the manifest, parameters and the row-level results of a finished pack and
    writes 04-secops-worklist.md and 04-secops-worklist.csv beside the client report. The list names
    incidents, tickets, devices and resources, so it is for the SecOps team and never for the client.
    Each category is an item Atmosera resolves at the platform level under the managed security service.
    No Azure sign-in, network requests or source evidence changes.
.PARAMETER EvidencePath
    The evidence pack folder written by Get-CyberSocEvidence.ps1.
.PARAMETER OutputPath
    Folder that receives the two files. Defaults to the evidence pack.
.PARAMETER ZendeskTicketUrl
    Ticket URL prefix. The ticket number is appended. Defaults to the Atmosera Zendesk agent view.
.EXAMPLE
    ./New-CyberSocSecOpsWorklist.ps1 -EvidencePath ./CyberSOC-Evidence_Client_20261012-120000
.NOTES
    Categories whose result was added in collector 1.8.0 (OUT.1-OPEN, DR.10-GAPS, EW.1-DEVICES,
    DP.5-STALE), 1.10.0 (IA.8-SIGNINS, P0.6-APPLIANCES), 1.11.0 (DP.1-CONTAINERS) or 1.14.0 (EW.1-GAPS,
    EW.10-EXCLUDED) read "needs recollection" on packs collected with an earlier version.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$EvidencePath,
    [string]$OutputPath,
    [string]$ZendeskTicketUrl = 'https://atmosera.zendesk.com/agent/tickets/'
)

$ErrorActionPreference = 'Stop'
$pack = (Resolve-Path -LiteralPath $EvidencePath).Path
foreach ($required in '00-parameters.json', '00-manifest.csv') {
    if (-not (Test-Path -LiteralPath (Join-Path $pack $required) -PathType Leaf)) {
        throw "Evidence pack is missing $required. Finish evidence collection before building the worklist."
    }
}
$parameters = Get-Content -LiteralPath (Join-Path $pack '00-parameters.json') -Raw | ConvertFrom-Json
$manifest = @(Import-Csv -LiteralPath (Join-Path $pack '00-manifest.csv'))
$inv = [cultureinfo]::InvariantCulture
# The collector version that added each worklist source, for the needs recollection status.
$addedIn = @{ 'OUT.1-OPEN' = '1.8'; 'DR.10-GAPS' = '1.8'; 'EW.1-DEVICES' = '1.8'; 'DP.5-STALE' = '1.8'; 'IA.8-SIGNINS' = '1.10.0'; 'P0.6-APPLIANCES' = '1.10.0'; 'DP.1-CONTAINERS' = '1.11.0'; 'EW.1-GAPS' = '1.14.0'; 'EW.10-EXCLUDED' = '1.14.0' }
# Managed resource group. The collector records the pattern it excluded (1.9.0 applies it to every
# query that names a resource). Packs from older collectors carry the default, and an explicit empty
# value means the exclusion was turned off for the run.
$managedRg = if ($parameters.PSObject.Properties.Name -contains 'ManagedRgPattern') { [string]$parameters.ManagedRgPattern } else { 'aznativesol0' }
$resourceColumns = '^(resourceGroup|ResourceGroup|ResourceId|AzureResourceId|SourceResourceId|VmId|Vault)$'

function Test-ManagedRow($row) {
    if ([string]::IsNullOrWhiteSpace($managedRg)) { return $false }
    foreach ($p in $row.PSObject.Properties) {
        if ($p.Name -notmatch $resourceColumns) { continue }
        $v = [string]$p.Value
        if ($v -and $v.IndexOf($managedRg, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    }
    $false
}

# Get-Text, Test-True, Get-Status, Get-Rows and Test-Unreadable. Every result is read without the managed
# resource group rows.
. (Join-Path $PSScriptRoot 'report/Read-CyberSocPackResult.ps1')
Initialize-CyberSocPackReader -Pack $pack -Manifest $manifest -RowFilter { param($row) -not (Test-ManagedRow $row) }
function Get-Day($value) {
    $v = Get-Text $value
    if ($v -eq '') { return '' }
    try { ([datetime]::Parse($v, $inv, 'AdjustToUniversal')).ToString('yyyy-MM-dd', $inv) } catch { $v.Substring(0, [Math]::Min(10, $v.Length)) }
}
function Get-Power($value) { (Get-Text $value).Replace('PowerState/', '') }
function Get-Severity-Rank($value) { switch (Get-Text $value) { 'High' { 0 } 'Medium' { 1 } 'Low' { 2 } default { 3 } } }
function Get-Ticket($row) {
    # The ticket number decides the link. Collectors before 1.10.0 extracted zendesk.com/agent/tickets/N
    # without the atmosera subdomain, and that host answers 404.
    $ref = Get-Text $row.TicketRef
    $num = Get-Text $row.TicketNumber
    if (-not $num -and $ref -match '(\d{3,})\s*$') { $num = $Matches[1] }
    if ($num) { return ($ZendeskTicketUrl.TrimEnd('/') + '/' + $num) }
    if ($ref) { return $ref }
    'No ticket reference found'
}
function Get-ShortName([string]$id) { $v = Get-Text $id; if ($v -match '/([^/]+)$') { $Matches[1] } else { $v } }
function New-Item2([string]$resource, [string]$detail, [string]$reference, [string]$source) {
    [pscustomobject]@{ Resource = $resource; Detail = $detail; Reference = $reference; Source = $source }
}

$pooledGroups = @(Get-Rows 'DP.5c' | Where-Object { (Get-Text $_.HostPoolType) -ieq 'Pooled' } | ForEach-Object { (Get-Text $_.resourceGroup).ToLowerInvariant() } | Sort-Object -Unique)
# Network virtual appliances (collector 1.10.0) cannot take an endpoint sensor, so they leave the device lists too.
$applianceIds = @(Get-Rows 'P0.6-APPLIANCES' | ForEach-Object { (Get-Text $_.ResourceId).ToLowerInvariant() } | Where-Object { $_ })
. (Join-Path $PSScriptRoot 'report/Get-EbrCaEvaluation.ps1')
$ca = $null
try { $ca = Read-EbrCaEvaluation -Pack $pack -Manifest $manifest }
catch { Write-Warning "The Conditional Access evaluation could not be completed. $($_.Exception.Message)" }
$policiesRead = (Get-Status 'IA.8-POLICIES') -in 'OK', 'EMPTY'
$azureDevice = { param($r) (Get-Text $r.AzureResourceId) -ne '' -and (Get-Text $r.AzureResourceId).ToLowerInvariant() -notin $applianceIds }
# The reason each machine is not reporting to Defender for Endpoint (EW.1-GAPS, collector 1.14.0), keyed by
# resource ID. A machine covered by a third-party product, or one that cannot take a sensor, is not an
# onboarding item: those move to their own categories.
$gapByResource = @{}
foreach ($g in @(Get-Rows 'EW.1-GAPS')) { $id = (Get-Text $g.AzureResourceId).ToLowerInvariant(); if ($id) { $gapByResource[$id] = $g } }
$gapOf = { param($r) $id = (Get-Text $r.AzureResourceId).ToLowerInvariant(); if ($id -and $gapByResource.ContainsKey($id)) { $gapByResource[$id] } }
$gapIsOnboardingItem = { param($r) $g = & $gapOf $r; if ($null -eq $g) { return $true } (Test-True $g.Eligible) -and -not (Test-True $g.Covered) }
$gapReasonText = { param($r) $g = & $gapOf $r; if ($null -eq $g) { return '' } $p = Get-Text $g.Product; $e = Get-Text $g.Evidence; '. ' + (Get-Text $g.Reason) + $(if ($p) { " ($p)" } else { '' }) + $(if ($e) { ". $e" } else { '' }) }

# Category definitions. Each maps the raw rows of one result to worklist items.
$categories = @(
    @{ Title = 'Open alerts'; Id = 'OUT.1-OPEN'; Control = 'OUT.1'
       Why = 'Alerts still open at collection. Close each with a classification and a closing comment, or confirm it is waiting on the client under the notification process.'
       Map = { param($rows) $rows | Sort-Object { Get-Severity-Rank $_.Severity }, { Get-Text $_.CreatedTime } | ForEach-Object {
            $owner = Get-Text $_.Owner; if (-not $owner) { $owner = 'unassigned' }
            New-Item2 ('Incident {0}: {1}' -f (Get-Text $_.IncidentNumber), (Get-Text $_.Title)) ('{0} severity, {1}, created {2}, {3} days open, owner {4}' -f (Get-Text $_.Severity), (Get-Text $_.Status), (Get-Day $_.CreatedTime), (Get-Text $_.AgeDays), $owner) (Get-Ticket $_) (Get-Text $_.IncidentUrl) } } }
    @{ Title = 'Closed alerts without a documented disposition'; Id = 'DR.10-GAPS'; Control = 'DR.10'
       Why = 'Closed in the last 30 days without a classification, or with Undetermined, or without a closing comment. Add the missing disposition so DR.10 reads complete.'
       Map = { param($rows) $rows | Sort-Object { Get-Text $_.ClosedTime } -Descending | ForEach-Object {
            $by = Get-Text $_.ClosedBy; if (-not $by) { $by = 'unknown' }
            New-Item2 ('Incident {0}: {1}' -f (Get-Text $_.IncidentNumber), (Get-Text $_.Title)) ('{0}. {1} severity, closed {2} by {3}' -f (Get-Text $_.Gap), (Get-Text $_.Severity), (Get-Day $_.ClosedTime), $by) (Get-Ticket $_) (Get-Text $_.IncidentUrl) } } }
    @{ Title = 'Azure virtual machines not onboarded to endpoint detection'; Id = 'EW.1-DEVICES'; Control = 'EW.1'
       Why = 'Azure virtual machines seen in the last 7 days that are not onboarded to Defender for Endpoint and carry no other endpoint detection product. Defender for Servers should onboard them, so check the plan, the MDE extension and the machine state. Machines covered by a third-party product, network appliances and machines the sensor cannot run on are listed under their own reason instead. Endpoints that are not native to Azure are left out.'
       Filter = { param($r) (& $azureDevice $r) -and (Get-Text $r.OnboardingStatus) -ine 'Onboarded' -and (& $gapIsOnboardingItem $r) }
       Note = { param($all) Get-OutsideAzureNote $all { param($r) (Get-Text $r.OnboardingStatus) -ine 'Onboarded' } }
       Map = { param($rows) $rows | Sort-Object { Get-Text $_.DeviceName } | ForEach-Object {
            $group = Get-Text $_.MachineGroup; $groupText = if ($group) { ", group $group" } else { '' }
            New-Item2 (Get-Text $_.DeviceName) ('{0}, onboarding status {1}, last seen {2}{3}{4}' -f (Get-Text $_.OSPlatform), (Get-Text $_.OnboardingStatus), (Get-Day $_.LastSeen), $groupText, (& $gapReasonText $_)) (Get-Text $_.AzureResourceId) 'EW.1-DEVICES' } } }
    @{ Title = 'Azure virtual machines with an inactive sensor'; Id = 'EW.1-DEVICES'; Control = 'EW.1'
       Why = 'Onboarded Azure virtual machines whose sensor state is not Active. Check connectivity, the sensor service and whether the machine is deallocated or retired. Endpoints that are not native to Azure are left out.'
       Filter = { param($r) (& $azureDevice $r) -and (Get-Text $r.OnboardingStatus) -ieq 'Onboarded' }
       Note = { param($all) Get-OutsideAzureNote $all { param($r) (Get-Text $r.OnboardingStatus) -ieq 'Onboarded' } }
       Map = { param($rows) $rows | Sort-Object { Get-Text $_.Gap }, { Get-Text $_.DeviceName } | ForEach-Object {
            New-Item2 (Get-Text $_.DeviceName) ('{0}, {1}, last seen {2}{3}' -f (Get-Text $_.Gap), (Get-Text $_.OSPlatform), (Get-Day $_.LastSeen), (& $gapReasonText $_)) (Get-Text $_.AzureResourceId) 'EW.1-DEVICES' } } }
    @{ Title = 'Azure virtual machines not reporting to Defender for Endpoint, by reason'; Id = 'EW.1-GAPS'; Control = 'EW.1'
       Why = 'Every Azure virtual machine that is not onboarded with an active sensor, with the reason the collector established: covered by a third-party product (CrowdStrike Falcon or another product named by the EDR vendor pattern), a network virtual appliance, an operating system the sensor does not support, deallocated at collection, discovered only, never discovered by Defender, sensor not active, or not onboarded with no endpoint detection found. The last two are the onboarding work. A machine covered by a third-party product counts as protected in the client report, so confirm that the product is licensed and reporting before the review.'
       Map = { param($rows) $rows | ForEach-Object {
            $p = Get-Text $_.Product; $e = Get-Text $_.Evidence
            New-Item2 (Get-Text $_.DeviceName) ('{0}{1}. {2}, {3}{4}{5}' -f (Get-Text $_.Reason), $(if ($p) { " ($p)" } else { '' }), (Get-Text $_.OSPlatform), (Get-Text $_.Gap).ToLowerInvariant(), $(if (Get-Text $_.PowerState) { ', ' + (Get-Text $_.PowerState) } else { '' }), $(if ($e) { ". $e" } else { '' })) (Get-Text $_.AzureResourceId) 'EW.1-GAPS' } } }
    @{ Title = 'Machines left out of the patch measures by tag'; Id = 'EW.10-EXCLUDED'; Control = 'EW.10'
       Why = 'Virtual machines and Arc machines whose tags record patching as waived or client owned. They are left out of the patch cadence and pending patch figures (EW.6, EW.10). Confirm that each tag is still intended, since a stale tag hides a machine from the patch measures.'
       Map = { param($rows) $rows | Sort-Object { Get-Text $_.resourceGroup }, { Get-Text $_.Name } | ForEach-Object {
            New-Item2 (Get-Text $_.Name) ('Tag {0}, resource group {1}' -f (Get-Text $_.MatchedTag), (Get-Text $_.resourceGroup)) (Get-Text $_.subscriptionId) 'EW.10-EXCLUDED' } } }
    @{ Title = 'Device code and legacy sign-ins to review'; Id = 'IA.8-SIGNINS'; Control = 'IA.3'
       Why = 'Successful sign-ins in the last 30 days through flows the Conditional Access baseline blocks. Not governed and not evaluated accounts are the gap: fix the policy scope or move the account to a modern flow. Excluded accounts are listed so each exclusion can be confirmed as intended.'
       Note = { param($all) if (-not $policiesRead) { 'the policy inventory (IA.8-POLICIES) was not read, so exclusions could not be checked' } }
       Map = { param($rows) @(if ($ca) { $ca.SignIns }) | Sort-Object { if ($_.Classification -eq 'Excluded') { 1 } else { 0 } }, { $_.Flow }, { -1 * $_.SignIns } | ForEach-Object {
            $policy = $_.Policy
            $why = switch ($_.Classification) {
                'Excluded' { 'excluded from {0}' -f $policy }
                'Not evaluated' { 'not evaluated by {0}, likely before the policy existed' -f $policy }
                default { 'no enabled block policy applies' }
            }
            $client = if ($_.ClientAppUsed -and $_.Flow -ne 'Device code') { ' ({0})' -f $_.ClientAppUsed } else { '' }
            New-Item2 $_.UserPrincipalName ('{0}{1}, {2} sign-in{3}, last {4}, {5}. Apps: {6}' -f $_.Flow, $client, $_.SignIns, $(if ($_.SignIns -eq 1) { '' } else { 's' }), (Get-Day $_.LastSignIn), $why, $(if ($_.Apps) { $_.Apps } else { 'not recorded' })) $_.Control 'IA.8-SIGNINS' } } }
    @{ Title = 'Legacy sign-ins that failed without a Conditional Access block'; Id = 'IA.3'; Control = 'IA.3'
       Why = 'Legacy protocol attempts in the last 30 days that failed without a Conditional Access block (error 53003), one line per protocol. Most are a wrong password or a locked account, and the client report never presents them as blocked. A large number points to password spraying against legacy endpoints. Review the sign-in logs for the source addresses and the accounts targeted, and disable the protocol where it is not needed. Where security defaults are on, their own block (error 530035) is counted here as well.'
       Filter = { param($r) (Get-Text $r.ClientAppUsed) -notin '', 'Unknown' -and (Get-Text $r.BlockedByCa) -ne '' -and (Get-LegacyFailed $r) -gt 0 }
       Note = { param($all) if (@($all | Where-Object { (Get-Text $_.BlockedByCa) -eq '' }).Count) { 'collected without the BlockedByCa column, so failures could not be told apart from Conditional Access blocks' } }
       Map = { param($rows) $rows | Sort-Object { -1 * (Get-LegacyFailed $_) }, { Get-Text $_.ClientAppUsed } | ForEach-Object {
            $failed = Get-LegacyFailed $_
            New-Item2 (Get-Text $_.ClientAppUsed) ('{0} of {1} attempt{2} failed without a Conditional Access block. {3} blocked by Conditional Access, {4} succeeded' -f $failed, (Get-Text $_.Attempts), $(if ((Get-Text $_.Attempts) -eq '1') { '' } else { 's' }), (Get-Text $_.BlockedByCa), (Get-Text $_.Succeeded)) 'Entra sign-in logs, last 30 days' 'IA.3' } } }
    @{ Title = 'Virtual machines without Azure Backup'; Id = 'DP.5b'; Control = 'DP.5b'
       Why = 'Virtual machines with no protected backup item. Add them to a backup policy or record the exclusion. Pooled AVD session hosts may be excluded by agreement.'
       Map = { param($rows) $rows | Sort-Object { Get-Text $_.resourceGroup }, { Get-Text $_.VmName } | ForEach-Object {
            $rg = Get-Text $_.resourceGroup
            $state = Get-Text $_.ProtectionState; $stateText = if ($state) { ", protection state $state" } else { '' }
            $pooled = if ($pooledGroups -contains $rg.ToLowerInvariant()) { ' A pooled AVD host pool shares this resource group, so the machine may be a session host excluded by agreement.' } else { '' }
            New-Item2 (Get-Text $_.VmName) ('Resource group {0}, {1}{2}.{3}' -f $rg, (Get-Power $_.PowerState), $stateText, $pooled) $rg 'DP.5b' } } }
    @{ Title = 'Backup items stale or not protected'; Id = 'DP.5-STALE'; Control = 'DP.5'
       Why = 'Protected items whose last backup is older than 48 hours or whose protection state is not Protected. Items superseded by a current backup of the same machine (moved, rebuilt or protected in another vault) are left out, and so are deleted resources whose protection was stopped with recovery points retained. A deleted resource that is still under protection is listed: stop protection and keep or delete its recovery points per the retention agreement.'
       Prepare = { param($all) Add-BackupFinding $all }
       Filter = { param($r) -not (Test-BackupLeftOut $r) }
       Note = { param($all)
            if (@($all | Where-Object { (Get-Text $_.Finding) -eq '' }).Count) { return 'collected before collector 1.10.0 without a VM inventory to check against, so items superseded by a current backup are still listed. Recollect to drop them' }
            $sup = @($all | Where-Object { (Get-Text $_.Finding) -eq 'Superseded' }).Count
            $del = @($all | Where-Object { (Test-BackupLeftOut $_) -and (Get-Text $_.Finding) -eq 'Source deleted' }).Count
            $inferred = @($all | Where-Object { $_.PSObject.Properties['FindingInferred'] }).Count
            @(if ($sup) { '{0} superseded by a current backup of the same machine left out' -f $sup }
              if ($del) { '{0} for deleted resources with protection stopped and recovery points retained left out' -f $del }
              if ($inferred) { 'findings inferred from the VM inventory (EW.7-DETAIL and DP.5b) because the pack predates collector 1.10.0' }) -join ', ' }
       Map = { param($rows) $rows | Sort-Object { -1 * [double](Get-Text $_.StaleDays) }, { Get-Text $_.ItemName } | ForEach-Object {
            $finding = Get-Text $_.Finding; $findingText = if ($finding) { "$finding. " } else { '' }
            New-Item2 (Get-Text $_.ItemName) ('{0}{1}, vault {2}, {3}, last backup {4} ({5} days ago), last status {6}' -f $findingText, (Get-Text $_.Workload), (Get-Text $_.Vault), (Get-Text $_.ProtectionState), (Get-Day $_.LastBackup), (Get-Text $_.StaleDays), (Get-Text $_.LastBackupStatus)) (Get-Text $_.SourceResourceId) 'DP.5-STALE' } } }
    @{ Title = 'Virtual machines without Trusted Launch'; Id = 'EW.7-DETAIL'; Control = 'EW.7'
       Why = 'Azure virtual machines deployed without Trusted Launch or confidential computing. Enable Secure Boot and vTPM on supported machines during planned maintenance.'
       Filter = { param($r) (Get-Text $r.SecurityType) -notin 'TrustedLaunch', 'ConfidentialVM' }
       Map = { param($rows) $rows | Sort-Object { Get-Text $_.resourceGroup }, { Get-Text $_.VmName } | ForEach-Object {
            $type = Get-Text $_.SecurityType; if (-not $type) { $type = 'standard' }
            New-Item2 (Get-Text $_.VmName) ('{0}, resource group {1}, {2}, security type {3}' -f (Get-Text $_.OsType), (Get-Text $_.resourceGroup), (Get-Power $_.PowerState), $type) (Get-Text $_.subscriptionId) 'EW.7-DETAIL' } } }
    @{ Title = 'Virtual machines without encryption at host'; Id = 'DP.4-DETAIL'; Control = 'DP.4'
       Why = 'Virtual machine and scale set resources without the encryption at host setting. Confirm disk encryption alternatives, then enable in planned batches.'
       Map = { param($rows) $rows | Sort-Object { Get-Text $_.resourceGroup }, { Get-Text $_.Name } | ForEach-Object {
            $kind = if ((Get-Text $_.ResourceType) -match 'scalesets') { 'Scale set' } else { 'Virtual machine' }
            New-Item2 (Get-Text $_.Name) ('{0}, resource group {1}, {2}, size {3}' -f $kind, (Get-Text $_.resourceGroup), (Get-Power $_.PowerState), (Get-Text $_.Size)) (Get-Text $_.subscriptionId) 'DP.4-DETAIL' } } }
    @{ Title = 'Workload subnets without segmentation'; Id = 'NB.1'; Control = 'NB.1'
       Why = 'Workload subnets with no network security group and no route table. Apply segmentation, starting with internet-facing and production ranges.'
       Filter = { param($r) (Get-Text $r.SubnetClass) -ieq 'Workload' -and -not (Test-True $r.Segmented) }
       Map = { param($rows) $rows | Sort-Object { Get-Text $_.Vnet }, { Get-Text $_.SubnetName } | ForEach-Object {
            New-Item2 ('{0}/{1}' -f (Get-Text $_.Vnet), (Get-Text $_.SubnetName)) ('{0}, resource group {1}, no network security group and no route table' -f (Get-Text $_.Prefix), (Get-Text $_.resourceGroup)) (Get-Text $_.resourceGroup) 'NB.1' } } }
    @{ Title = 'High severity Defender for Cloud recommendations'; Id = 'DFC.1-DETAIL'; Control = 'DFC.1'
       Why = 'Unhealthy high severity assessments on the recommendations the service tracks, one line per recommendation with every affected resource. Remediate or record an exemption in Defender for Cloud.'
       Filter = { param($r) (Get-Text $r.Severity) -ieq 'High' }
       Map = { param($rows) $rows | Group-Object { Get-Text $_.Recommendation } | Sort-Object { -1 * $_.Count }, Name | ForEach-Object {
            $resources = @($_.Group | ForEach-Object { Get-ShortName $_.ResourceId } | Sort-Object -Unique)
            $groups = @($_.Group | ForEach-Object { Get-Text $_.resourceGroup } | Where-Object { $_ } | Sort-Object -Unique)
            New-Item2 $_.Name ('{0} resource{1}: {2}' -f $resources.Count, $(if ($resources.Count -eq 1) { '' } else { 's' }), ($resources -join ', ')) ('Resource group{0} {1}' -f $(if ($groups.Count -eq 1) { '' } else { 's' }), ($groups -join ', ')) 'DFC.1-DETAIL' } } }
    @{ Title = 'Blob containers set to anonymous access'; Id = 'DP.1-CONTAINERS'; Control = 'DP.1'
       Why = 'Storage accounts holding containers whose own access level is Blob or Container. Readable today means the account setting also allows anonymous access, so the data can be read without signing in. Set each container to private, or confirm it serves public content by design and move that content behind a CDN or signed URLs. Accounts whose containers could not be listed are shown with the error.'
       Filter = { param($r) [int]$r.PublicContainers -gt 0 -or (Get-Text $r.ReadStatus) -ne 'OK' }
       Map = { param($rows) $rows | Sort-Object { -1 * [int]$_.ExposedContainers }, { Get-Text $_.Account } | ForEach-Object {
            $detail = if ((Get-Text $_.ReadStatus) -ne 'OK') { 'Containers not listed: {0}' -f (Get-Text $_.ReadStatus) }
            else { '{0} of {1} containers public, {2} readable anonymously today. Account setting {3}. {4}' -f (Get-Text $_.PublicContainers), (Get-Text $_.Containers), (Get-Text $_.ExposedContainers), (Get-Text $_.AccountAnonymousAccess).ToLowerInvariant(), (Get-Text $_.PublicContainerNames) }
            New-Item2 (Get-Text $_.Account) $detail ('Resource group {0}' -f (Get-Text $_.resourceGroup)) 'DP.1-CONTAINERS' } } }
    @{ Title = 'Network virtual appliances excluded from VM measures'; Id = 'P0.6-APPLIANCES'; Control = 'P0.6'
       Why = 'Machines on a marketplace firewall, router or SD-WAN image. They are left out of Trusted Launch, encryption at host, Azure Backup, endpoint detection and the agent-based Defender for Cloud recommendations because the vendor image cannot take those controls. Confirm each one really is an appliance.'
       Map = { param($rows) $rows | Sort-Object { Get-Text $_.resourceGroup }, { Get-Text $_.Name } | ForEach-Object {
            New-Item2 (Get-Text $_.Name) ('{0} {1}, resource group {2}, {3}' -f (Get-Text $_.Publisher), (Get-Text $_.Offer), (Get-Text $_.resourceGroup), (Get-Power $_.PowerState)) (Get-Text $_.subscriptionId) 'P0.6-APPLIANCES' } } }
)
# Stale backup findings. Collector 1.10.0 classifies each item in DP.5-STALE. For older packs the same
# finding is inferred for VM items from the VM inventory (EW.7-DETAIL lists every VM before 1.10.0) and
# DP.5b (a VM missing from it has a Protected item): a VM gone from its recorded resource ID is
# superseded when a VM of the same name exists elsewhere with a current backup, otherwise deleted.
function Test-BackupLeftOut($r) {
    $f = Get-Text $r.Finding
    $f -eq 'Superseded' -or ($f -eq 'Source deleted' -and (Get-Text $r.ProtectionState) -eq 'ProtectionStopped')
}
function Get-StateFinding($r) {
    switch (Get-Text $r.ProtectionState) { 'ProtectionStopped' { 'Protection stopped' } 'Protected' { 'Backup stale' } default { 'Not protected' } }
}
function Add-BackupFinding($all) {
    if (@($all | Where-Object { $null -eq $_.PSObject.Properties['Finding'] }).Count -eq 0) { return $all }
    if ((Get-Status 'EW.7-DETAIL') -notin 'OK', 'EMPTY' -or (Get-Status 'DP.5b') -notin 'OK', 'EMPTY') { return $all }
    $key = { param($sub, $rg, $name) ('{0}/{1}/{2}' -f $sub, $rg, $name).ToLowerInvariant() }
    $vms = @(Get-Rows 'EW.7-DETAIL')
    $exists = @{}; $byName = @{}
    foreach ($v in $vms) {
        $k = & $key (Get-Text $v.subscriptionId) (Get-Text $v.resourceGroup) (Get-Text $v.VmName)
        $exists[$k] = $true
        $n = (Get-Text $v.VmName).ToLowerInvariant()
        if (-not $byName.ContainsKey($n)) { $byName[$n] = @() }
        $byName[$n] += , @((Get-Text $v.subscriptionId), (Get-Text $v.resourceGroup), (Get-Text $v.VmName))
    }
    $unprotected = @{}
    foreach ($u in @(Get-Rows 'DP.5b')) { $unprotected[('{0}/{1}' -f (Get-Text $u.resourceGroup), (Get-Text $u.VmName)).ToLowerInvariant()] = $true }
    $parse = { param($id) if ((Get-Text $id) -match '(?i)/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft\.Compute/virtualMachines/([^/]+)$') { , @($Matches[1], $Matches[2], $Matches[3]) } }
    $stale = @{}
    foreach ($r in $all) { $s = & $parse $r.SourceResourceId; if ($s) { $stale[(& $key $s[0] $s[1] $s[2])] = $true } }
    foreach ($r in $all) {
        if ($null -ne $r.PSObject.Properties['Finding']) { continue }
        $s = & $parse $r.SourceResourceId
        $finding = Get-StateFinding $r
        if ($s -and -not $exists[(& $key $s[0] $s[1] $s[2])]) {
            $current = @($byName[$s[2].ToLowerInvariant()] | Where-Object { $_ -and -not $unprotected[('{0}/{1}' -f $_[1], $_[2]).ToLowerInvariant()] -and -not $stale[(& $key $_[0] $_[1] $_[2])] })
            $finding = if ($current.Count) { 'Superseded' } else { 'Source deleted' }
        }
        $r | Add-Member -NotePropertyName Finding -NotePropertyValue $finding
        $r | Add-Member -NotePropertyName FindingInferred -NotePropertyValue $true
    }
    $all
}

# Legacy attempts that neither succeeded nor reached a Conditional Access block (error 53003).
function Get-LegacyFailed($r) {
    foreach ($v in $r.Attempts, $r.Succeeded, $r.BlockedByCa) { if ((Get-Text $v) -notmatch '^\d+$') { return 0 } }
    [Math]::Max(0, [int]$r.Attempts - [int]$r.Succeeded - [int]$r.BlockedByCa)
}

# How many rows a device category left out because the endpoint is not an Azure virtual machine.
function Get-OutsideAzureNote($all, [scriptblock]$Kind) {
    $n = @($all | Where-Object { (& $Kind $_) -and -not (& $azureDevice $_) }).Count
    if ($n) { '{0} endpoint{1} outside Azure or on a network appliance left out' -f $n, $(if ($n -eq 1) { '' } else { 's' }) }
}

# Resolve every category to its status and items.
$sections = foreach ($c in $categories) {
    $status = Get-Status $c.Id
    $items = @()
    $state = ''
    switch -Regex ($status) {
        '^(OK|PARTIAL|EMPTY)$' {
            # A damaged result never reads as none found.
            if (Test-Unreadable $c.Id) { $state = Get-UnreadableState $c.Id; break }
            $all = @(Get-Rows $c.Id)
            if ($c.Prepare) { $all = @(& $c.Prepare $all) }
            $rows = if ($c.Filter) { @($all | Where-Object { & $c.Filter $_ }) } else { $all }
            $items = @(& $c.Map $rows)
            $state = if ($items.Count) { ('{0} item{1}{2}' -f $items.Count, $(if ($items.Count -eq 1) { '' } else { 's' }), $(if ($status -eq 'PARTIAL') { ', partial collection scope' } else { '' })) } else { 'None found' }
            if ($c.Note) { $extra = Get-Text (& $c.Note $all); if ($extra) { $state = "$state, $extra" } }
        }
        '^MISSING$' { $state = if ($addedIn.ContainsKey($c.Id)) { 'Needs recollection with collector {0} or later' -f $addedIn[$c.Id] } else { 'Not collected' } }
        default { $state = "Not collected ($status)" }
    }
    [pscustomobject]@{ Title = $c.Title; Id = $c.Id; Control = $c.Control; Why = $c.Why; Status = $status; State = $state; Items = $items }
}

# Markdown.
function Format-Cell($value) { (Get-Text $value).Replace('|', '\|') -replace '\r?\n', ' ' }
$packName = Split-Path -Leaf $pack
$collected = Get-Day $parameters.RunStartedUtc
$subs = @($parameters.Subscriptions | ForEach-Object { Get-Text $_ })
$md = [System.Text.StringBuilder]::new()
[void]$md.AppendLine(('# SecOps worklist: {0}' -f (Get-Text $parameters.ClientName)))
[void]$md.AppendLine()
[void]$md.AppendLine(('Internal. Built {0} from evidence pack {1} (collector {2}, collected {3}). Names incidents, tickets, devices and resources, so it stays with the SecOps team and is never sent to the client.' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd', $inv), $packName, (Get-Text $parameters.ScriptVersion), $collected))
[void]$md.AppendLine()
[void]$md.AppendLine(('- Tenant: {0}' -f (Get-Text $parameters.TenantId)))
[void]$md.AppendLine(('- Subscriptions ({0}): {1}' -f $subs.Count, ($subs -join ', ')))
[void]$md.AppendLine(('- Alert window: {0} to {1}' -f (Get-Text $parameters.WindowStart), (Get-Text $parameters.WindowEnd)))
if (Get-Text $parameters.AlertScope) { [void]$md.AppendLine(('- Alert scope: {0}' -f (Get-Text $parameters.AlertScope))) }
[void]$md.AppendLine(('- Posture read: {0}' -f (Get-Text $parameters.PostureReadDate)))
[void]$md.AppendLine()
[void]$md.AppendLine('## Summary')
[void]$md.AppendLine()
[void]$md.AppendLine('| Category | Control | Items | Status |')
[void]$md.AppendLine('| --- | --- | --- | --- |')
foreach ($s in $sections) { [void]$md.AppendLine(('| {0} | {1} | {2} | {3} |' -f (Format-Cell $s.Title), $s.Control, $s.Items.Count, (Format-Cell $s.State))) }
$n = 0
foreach ($s in $sections) {
    $n++
    [void]$md.AppendLine()
    [void]$md.AppendLine(('## {0}. {1} ({2})' -f $n, $s.Title, $s.Id))
    [void]$md.AppendLine()
    [void]$md.AppendLine($s.Why)
    [void]$md.AppendLine()
    [void]$md.AppendLine(('Status: {0}.' -f $s.State))
    if ($s.Items.Count) {
        [void]$md.AppendLine()
        [void]$md.AppendLine('| Resource | Detail | Reference |')
        [void]$md.AppendLine('| --- | --- | --- |')
        foreach ($i in $s.Items) { [void]$md.AppendLine(('| {0} | {1} | {2} |' -f (Format-Cell $i.Resource), (Format-Cell $i.Detail), (Format-Cell $i.Reference))) }
    }
}

# CSV: one row per item.
$csvRows = foreach ($s in $sections) {
    foreach ($i in $s.Items) {
        [pscustomobject]@{ Category = $s.Title; ControlId = $s.Control; Resource = $i.Resource; Detail = $i.Detail; Reference = $i.Reference; Source = $i.Source }
    }
}
$csvLines = @('"Category","ControlId","Resource","Detail","Reference","Source"')
if (@($csvRows).Count) { $csvLines = @($csvRows | ConvertTo-Csv -NoTypeInformation) }

$folder = if ($OutputPath) { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath) } else { $pack }
if (-not (Test-Path -LiteralPath $folder -PathType Container)) { [void](New-Item -ItemType Directory -Path $folder -Force) }
$mdPath = Join-Path $folder '04-secops-worklist.md'
$csvPath = Join-Path $folder '04-secops-worklist.csv'
[IO.File]::WriteAllText($mdPath, $md.ToString(), [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($csvPath, (($csvLines -join "`r`n") + "`r`n"), [Text.UTF8Encoding]::new($true))
Write-Output $mdPath
Write-Output $csvPath
