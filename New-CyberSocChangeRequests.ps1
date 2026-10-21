<#
.SYNOPSIS
    Writes the change requests for the low-impact security hardening items in an evidence pack.
.DESCRIPTION
    Offline only. Reads the manifest, parameters and the per-resource hardening results of a finished
    pack and writes one change request for each hardening item that still has resources to fix, laid
    out on the change request template: diagnostic logging through the ATMO-MXDR-DIAG-TOSENT initiative
    (assigned where it is missing, and remediated where resources are not compliant),
    secure transfer and minimum TLS 1.2 on storage accounts, minimum TLS 1.2 on App Service, Azure SQL,
    Azure Cache for Redis, Service Bus, Event Hubs and Azure Cosmos DB, Key Vault purge protection,
    encryption at host on virtual machines and scale sets, closing internet-facing RDP, SSH and WinRM
    rules on network security groups, turning off plain FTP on App Service apps, setting the blob containers
    that anyone can read today to private access, and removing the Azure and Microsoft Entra roles that disabled
    accounts still hold, by removing a role assigned to the account itself and by removing the account from the
    group that gives it a role, the role group or one nested in it. Every change request
    also gets a client email, drafted and ready to send, that asks for the client's approval. The CR-19 email names
    the accounts and their roles in a CSV written beside it (CR-19-disabled-account-roles.email.csv), to attach,
    since the list can be long. Every email has the same parts in the
    same order: what is to change, why it is recommended, what it means for the client, the resources by
    subscription, how it can be reversed, and the request, which asks for approval of the proposed date, or
    for a maintenance window where the change needs a restart, by a reply-by date a week before it. Nothing
    is scheduled without the client's approval. AKS node pools take encryption at host only when a node
    pool is created, so the index routes them to a planned project instead of a change request.

    Get-CyberSocEvidence.ps1 runs it at the end of each collection. Run it on its own to write the files
    again, for example with another contact, sender or proposed date.

    Every testing plan is a check in the Azure portal, every reference is a Microsoft Learn page and the
    notification list is left empty to fill in. The files name client resources, so they stay internal
    until sent. No Azure sign-in, network requests or source evidence changes.
.PARAMETER EvidencePath
    The evidence pack folder written by Get-CyberSocEvidence.ps1.
.PARAMETER OutputPath
    Folder that receives the files. Defaults to 05-change-requests inside the evidence pack.
.PARAMETER DrClient
    The client is a DR client. DR Impact then reads N/A - No DR impact, and the encryption at host
    change adds the DR Playbook step that Azure Site Recovery needs. Without it DR Impact reads Not a
    DR Client.
.PARAMETER SentinelWorkspace
    The workspace the diagnostic logging initiative sends to. Defaults to the workspace in the pack
    when it holds exactly one.
.PARAMETER ManagementGroup
    The client management group to assign the diagnostic logging initiative at, once. Without it the
    change assigns the initiative at each subscription in the pack.
.PARAMETER ClientContact
    The name the client emails open with. Without it they open with Hello.
.PARAMETER SenderName
    The name under the sign-off of the client emails.
.PARAMETER PurgeProtectionApproved
    The client approved purge protection at build kickoff. The CR-06 email then refers to that approval and
    asks the client to confirm it still stands and to approve the proposed date, and the index records it.
.PARAMETER ChangeDate
    The proposed date the client emails ask the client to approve. Every email asks for a reply by a week
    before it. Defaults to two weeks after the build date, and must be at least eight days after it.
.PARAMETER AdminRuleOpen
    The virtual machines whose effective security rules show an Azure Virtual Network Manager security
    admin rule with Always Allow on a management port from an internet source, each as the resource ID of
    the virtual machine followed by :port, such as
    /subscriptions/<subscription>/resourceGroups/rg-web/providers/Microsoft.Compute/virtualMachines/vm-web01:3389.
    The resource ID names the machine once, since a machine name is unique only within its resource group.
    Security admin rules apply before network security groups, so CR-16 cannot close those ports. The
    CR-16 email then says a central network policy keeps them open and asks who manages it, and the change
    request and the index name them.
.PARAMETER DefenderEndpointPlan
    The Defender for Endpoint plan read in the Defender portal under Settings > Endpoints > Licenses: Plan1, Plan2,
    Business or Mixed. Overrides the reading the collection recorded (Licensing in 00-parameters.json). The licensing
    check takes it for the plan and names any disagreement with what the API reads show.
.EXAMPLE
    ./New-CyberSocChangeRequests.ps1 -EvidencePath ./CyberSOC-Evidence_Contoso_2026-09_20261003-090000
.EXAMPLE
    ./New-CyberSocChangeRequests.ps1 -EvidencePath ./CyberSOC-Evidence_Contoso_2026-09_20261003-090000 -DrClient -ClientContact 'Dana' -SenderName 'Scott'
.NOTES
    The per-resource results (P0.7, NB.4-DETAIL, NB.5-DETAIL, NB.6-DETAIL, DP.1-DETAIL, DP.2-DETAIL,
    DP.4-ELIGIBILITY, DR.6-COVERAGE and DR.6-NONCOMPLIANT) were added in CyberSOC collector 1.1.0,
    NB.6-PAAS-DETAIL in 1.2.0, DP.4-VMSS-ELIGIBILITY in 1.3.0, NB.2-DETAIL in 1.6.0, NB.5-FTPS-DETAIL
    in 1.7.0, DP.1-CONTAINERS-DETAIL in 1.8.0 and IA.15-DISABLED, IA.15-RBAC and IA.15-ENTRA in 1.9.0. Changes that read them say "needs recollection" on packs collected with an earlier version. CR-09 and CR-15 also need the machine and scale
    set IDs added in 1.4.0, and say "needs recollection" on an earlier pack that lists anything to change. CR-19 removes
    an account from the group it sits in only with the group membership columns added in 1.10.0 (MemberOfId,
    MemberOfName, MemberOfType, GroupPath, GroupPathIds), and on an earlier pack leaves the roles held through groups
    unchanged and says so in the index. The licensing gate reads LIC.1-SKUS, LIC.2-MACHINES, LIC.3-TVM and LIC.4-DEVICES,
    added in 1.11.0, and on an earlier pack reads every capability as Unknown, so a change request that requires one is
    written with a note to confirm the license. The emergency access accounts every Conditional Access change excludes are
    read from IA.16-ACCOUNTS and IA.16-GROUPS, added in 1.12.0, and on an earlier pack, or when that read failed, is
    partial or found no account, no Conditional Access change is written and the index says why. CR-04 sets the SCM
    (Kudu) site minimum TLS version from the ScmMinTlsVersion column of NB.5-DETAIL, added in 1.13.0, and on an earlier
    pack sets the site minimum only and says in the index that the SCM part needs recollection.
    CR-17 turns FTP basic authentication publishing credentials off from NB.5-FTPAUTH-DETAIL, added in 1.14.0, on every
    app where it is On whatever its FTP state, and on an earlier pack changes the FTP state only and says in the index
    that the FTP basic authentication part needs recollection.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$EvidencePath,
    [string]$OutputPath,
    [switch]$DrClient,
    [string]$SentinelWorkspace,
    [string]$ManagementGroup,
    [string]$ClientContact,
    [string]$SenderName,
    [switch]$PurgeProtectionApproved,
    [datetime]$ChangeDate,
    [string[]]$AdminRuleOpen,
    [ValidateSet('Plan1', 'Plan2', 'Business', 'Mixed')]
    [string]$DefenderEndpointPlan
)

$ErrorActionPreference = 'Stop'
$pack = (Resolve-Path -LiteralPath $EvidencePath).Path
foreach ($required in '00-parameters.json', '00-manifest.csv') {
    if (-not (Test-Path -LiteralPath (Join-Path $pack $required) -PathType Leaf)) {
        throw "Evidence pack is missing $required. Finish evidence collection before building the change requests."
    }
}
$parameters = Get-Content -LiteralPath (Join-Path $pack '00-parameters.json') -Raw | ConvertFrom-Json
$manifest = @(Import-Csv -LiteralPath (Join-Path $pack '00-manifest.csv'))
$inv = [cultureinfo]::InvariantCulture
# The CyberSOC collector that added each per-resource result, for the needs recollection status.
$detailVersions = @{}
foreach ($id in 'P0.7', 'NB.4-DETAIL', 'NB.5-DETAIL', 'NB.6-DETAIL', 'DP.1-DETAIL', 'DP.2-DETAIL', 'DP.4-ELIGIBILITY', 'DR.6-COVERAGE', 'DR.6-NONCOMPLIANT') { $detailVersions[$id] = '1.1.0' }
$detailVersions['NB.6-PAAS-DETAIL'] = '1.2.0'
$detailVersions['DP.4-VMSS-ELIGIBILITY'] = '1.3.0'
$detailVersions['NB.2-DETAIL'] = '1.6.0'
$detailVersions['NB.5-FTPS-DETAIL'] = '1.7.0'
$detailVersions['DP.1-CONTAINERS-DETAIL'] = '1.8.0'
foreach ($id in 'IA.15-DISABLED', 'IA.15-RBAC', 'IA.15-ENTRA') { $detailVersions[$id] = '1.9.0' }
foreach ($id in 'LIC.1-SKUS', 'LIC.2-MACHINES', 'LIC.3-TVM', 'LIC.4-DEVICES', 'LIC.5-MATRIX', 'LIC.5-SERVERS') { $detailVersions[$id] = '1.11.0' }
foreach ($id in 'IA.16-ACCOUNTS', 'IA.16-GROUPS') { $detailVersions[$id] = '1.12.0' }
foreach ($id in 'NB.5-FTPAUTH', 'NB.5-FTPAUTH-DETAIL') { $detailVersions[$id] = '1.14.0' }
# The latest collector among the results given, so a pack missing several asks for the one that has them all.
function Get-RecollectionState([string[]]$Ids) {
    $version = @($Ids | ForEach-Object { $detailVersions[$_] } | Where-Object { $_ } | Sort-Object { [version]$_ })[-1]
    "Needs recollection with CyberSOC collector $version or later"
}
$needsRecollection = Get-RecollectionState 'DR.6-COVERAGE', 'DR.6-NONCOMPLIANT'
# CR-09 and CR-15 match each machine and scale set by the ID Azure gives it (VmId in DP.4-ELIGIBILITY,
# UniqueId in DP.4-VMSS-ELIGIBILITY), added in 1.4.0. A name alone cannot tell the machine that was checked
# from one deleted and created again under the same name, which would be stopped for a change Azure rejects.
$needsIdRecollection = 'Needs recollection with CyberSOC collector 1.4.0 or later'
# CR-04 sets the SCM (Kudu) site minimum TLS version from the ScmMinTlsVersion column of NB.5-DETAIL, added in 1.13.0.
# On an earlier pack it sets the site minimum only and its index note asks for recollection.
$scmTlsVersion = '1.13.0'
# CR-17 turns FTP basic authentication off from NB.5-FTPAUTH-DETAIL, added in 1.14.0. On an earlier pack it changes the
# FTP state only and its index note asks for recollection.
$ftpAuthVersion = $detailVersions['NB.5-FTPAUTH-DETAIL']

# Get-Text, Test-True, Get-Status, Get-Rows, Test-Unreadable and Get-UnreadableState. Each result file is
# parsed once. A result the manifest reads as OK or PARTIAL needs a file that parses, or a damaged pack would
# read as no gaps found and leave a change out without saying so.
. (Join-Path $PSScriptRoot 'report/Read-CyberSocPackResult.ps1')
Initialize-CyberSocPackReader -Pack $pack -Manifest $manifest
function Get-Number($value) { $n = 0; if ([int]::TryParse((Get-Text $value), [ref]$n)) { $n } else { 0 } }
# What the collector recorded about a result, such as the permission a read needed, cleaned to the copy rules.
function Get-ResultDetail([string]$id) { ConvertTo-CopyText (@($manifest | Where-Object ResultId -eq $id) | Select-Object -First 1).Detail }

# Copy rules: no semicolons, arrows, emoji or angle brackets, and the greater-than sign only in a
# navigation step such as Settings > Configuration. A client email has no navigation step, so it has no
# greater-than sign at all. Values read from the pack are cleaned first, and every file is checked before
# it is written, so a rule broken by the text below stops the run.
# The cleaner removes every character the check rejects, so a value read from the pack never stops the run.
$arrowCharacters = '\u2190-\u21FF\u27F0-\u27FF\u2900-\u297F\u2B00-\u2BFF\u25B6\u25BA'
$emojiCharacters = '\u2300-\u23FF\u2600-\u27BF\uFE0F\uD800-\uDFFF'
function ConvertTo-CopyText($value) {
    $v = (Get-Text $value) -replace ';', ',' -replace '[<>]', ' '
    $v = $v -replace ('[' + $arrowCharacters + $emojiCharacters + ']'), ''
    ($v -replace '\s+', ' ').Trim()
}
function Assert-CopyRules([string]$Text, [string]$Label, [switch]$Email) {
    $broken = @(
        if ($Text -match ';') { 'a semicolon' }
        if ($Text -match ('[' + $arrowCharacters + ']|->|<-|=>')) { 'an arrow' }
        if ($Text -match ('[' + $emojiCharacters + ']')) { 'an emoji' }
        if ($Text -match '<') { 'an angle bracket' }
        if ($Email -and $Text -match '>') { 'a greater-than sign, which a client email never needs' }
        elseif (($Text -replace '[A-Za-z0-9)] > [A-Za-z]', '') -match '>') { 'a greater-than sign outside a navigation step' }
    )
    if ($broken.Count) { throw "$Label breaks the copy rules with $($broken -join ', ')." }
}
function Get-SentenceCount([string]$Text) { [regex]::Matches($Text.Trim(), '[.!?](\s|$)').Count }

function Get-Pick([int]$n, $one, $many) { if ($n -eq 1) { $one } else { $many } }
function Get-Count([int]$n, [string]$one, [string]$many) { if ($n -eq 1) { "1 $one" } else { "$n $many" } }
function Get-Listed([int]$n, [string]$one, [string]$many) { if ($n -eq 1) { "the $one listed below" } else { "the $n $many listed below" } }
# The first step opens a resource, the last repeats the steps for every other one.
function Get-OpenStep([int]$n, [string]$blade, [string]$noun) {
    'In the Azure portal, go to {0} and open the {1}{2} listed in the RESOURCES section.' -f $blade, $(if ($n -gt 1) { 'first ' } else { '' }), $noun
}
function Get-EachStep([int]$n, [string]$noun) {
    if ($n -eq 1) { "the $noun listed in the RESOURCES section" } else { "each $noun listed in the RESOURCES section" }
}
function Add-RepeatStep($steps, [int]$n, [int]$from, [string]$nouns) {
    if ($n -gt 1) { $steps.Add(('Repeat steps {0} to {1} for each remaining {2} listed.' -f $from, $steps.Count, $nouns)) }
}

$client = ConvertTo-CopyText $parameters.ClientName
$subscriptionNames = @{}
foreach ($s in @(Get-Rows 'P0.7')) {
    $id = (ConvertTo-CopyText $s.subscriptionId).ToLowerInvariant()
    if ($id) { $subscriptionNames[$id] = ConvertTo-CopyText $s.SubscriptionName }
}
function Format-Subscription([string]$id) {
    $key = (ConvertTo-CopyText $id).ToLowerInvariant()
    if ($subscriptionNames[$key]) { '{0} ({1})' -f $subscriptionNames[$key], $key } else { $key }
}
function New-Resource([string]$Name, [string]$ResourceGroup, [string]$SubscriptionId, [string]$Setting, [string]$ResourceId) {
    [pscustomobject]@{
        Name = ConvertTo-CopyText $Name; ResourceGroup = ConvertTo-CopyText $ResourceGroup
        SubscriptionId = (ConvertTo-CopyText $SubscriptionId).ToLowerInvariant(); Setting = ConvertTo-CopyText $Setting; ResourceId = Get-Text $ResourceId
    }
}
# Resources grouped by subscription, one bullet each with its resource group and current setting.
function Format-ResourceList($resources) {
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($g in @($resources | Group-Object SubscriptionId | Sort-Object { Format-Subscription $_.Name })) {
        if ($lines.Count) { $lines.Add('') }
        $lines.Add(('Subscription: {0}' -f (Format-Subscription $g.Name)))
        foreach ($r in @($g.Group | Sort-Object ResourceGroup, Name)) {
            $parts = @($r.Name)
            if ($r.ResourceGroup) { $parts += 'resource group ' + $r.ResourceGroup }
            if ($r.Setting) { $parts += $r.Setting }
            $lines.Add('- ' + ($parts -join ', '))
        }
    }
    $lines.ToArray()
}
function Get-PowerText($value) {
    switch -Regex (Get-Text $value) { 'running$' { 'running' } 'deallocated$' { 'deallocated' } 'stopped$' { 'stopped' } '^$' { 'power state unknown' } default { (Get-Text $value).Replace('PowerState/', '') } }
}
# The FTP state as the portal names it. An empty or unknown state is never named as one of the three.
function Format-FtpState($value) {
    switch (Get-Text $value) { 'AllAllowed' { 'All allowed' } 'FtpsOnly' { 'FTPS only' } 'Disabled' { 'Disabled' } '' { 'not recorded' } default { ConvertTo-CopyText $value } }
}
function Format-TlsVersion($value) {
    # Storage writes TLS1_2, Cosmos DB Tls, Tls11 and Tls12, the other services 1.2.
    switch -Regex (Get-Text $value) { '^TLS1_(\d)$' { '1.' + $Matches[1] } '^Tls1(\d)$' { '1.' + $Matches[1] } '^Tls$' { '1.0' } '^(|None)$' { 'not set' } default { ConvertTo-CopyText $value } }
}

# The licensing check (collector 1.11.0), derived again from the pack's own reads with report/Get-CyberSocLicensing.ps1,
# the derivation the collector ran for LIC.5-MATRIX, so -DefenderEndpointPlan here can replace the reading it recorded.
# A change request registers the capabilities it needs in its catalog entry: Requires gates it (Not licensed writes no
# change request and the index names the missing license, Unknown writes it with a note to confirm the license before
# sending), and Uses only lists it in the licensing section of the index. A read that failed, was refused, is partial or
# is missing from an older pack reads Unknown, never Not licensed.
. (Join-Path $PSScriptRoot 'report/Get-CyberSocLicensing.ps1')
$planReading = if ($DefenderEndpointPlan) { $DefenderEndpointPlan } elseif ($parameters.PSObject.Properties['Licensing'] -and $parameters.Licensing) { Get-Text $parameters.Licensing.DefenderEndpointPlan } else { '' }
if ($planReading -and -not $script:CyberSocPlanReadings.Contains($planReading)) { $planReading = '' }
$readPack = {
    param([string]$Id)
    $status = Get-Status $Id
    $readable = $status -in 'OK', 'EMPTY', 'PARTIAL'
    @{ Status = $status; Rows = @(if ($readable) { Get-Rows $Id }); Unreadable = ($readable -and (Test-Unreadable $Id)); Source = Get-Text (@($manifest | Where-Object ResultId -eq $Id) | Select-Object -First 1).Source }
}
$licensing = Get-CyberSocLicensing -Read $readPack -Subscriptions @($parameters.Subscriptions) -Reading $planReading
# The emergency access accounts (collector 1.12.0, IA.16-ACCOUNTS and IA.16-GROUPS), shared by every Conditional Access
# change with report/Get-CyberSocEmergencyAccess.ps1. A change request whose catalog entry sets EmergencyAccess = $true
# is written only when $emergencyAccess.Ready, and every policy it proposes excludes $emergencyAccess.ExcludeGroups and
# $emergencyAccess.ExcludeUsers. Test-CyberSocEmergencyAccessId names an existing exclusion it must never remove.
. (Join-Path $PSScriptRoot 'report/Get-CyberSocEmergencyAccess.ps1')
$emergencyAccess = Get-CyberSocEmergencyAccess -Read $readPack
# Copy text that keeps a portal path such as Settings > Endpoints > Licenses, which the copy rules allow in the index.
function ConvertTo-PathText($value) { (ConvertTo-CopyText ((Get-Text $value) -replace ' > ', ' NAVSTEP ')) -replace ' NAVSTEP ', ' > ' }

$workspaces = @($parameters.Workspaces | Where-Object { $_ })
$workspaceName = if ($SentinelWorkspace) { ConvertTo-CopyText $SentinelWorkspace } elseif ($workspaces.Count -eq 1) { ConvertTo-CopyText $workspaces[0].Name } else { '' }
$workspace = if ($workspaceName) { "the Sentinel workspace $workspaceName" } else { 'the client Sentinel workspace' }
$managementGroup = ConvertTo-CopyText $ManagementGroup
$standardMitigation = 'If changes need to be reverted, follow the rollback plan.'
$drImpact = if ($DrClient) { 'N/A - No DR impact' } else { 'Not a DR Client' }
$drPlan = if ($DrClient) { 'No updates to the DR Playbook are required.' } else { 'Not a DR Client. No updates to the DR Playbook are required.' }
# Every client email asks the client to approve the proposed date, or to suggest a maintenance window, and to
# reply a week before the proposed date.
$buildDate = (Get-Date).ToUniversalTime().Date
$proposedDate = if ($PSBoundParameters.ContainsKey('ChangeDate')) { $ChangeDate.Date } else { $buildDate.AddDays(14) }
$replyDate = $proposedDate.AddDays(-7)
if ($replyDate -le $buildDate) { throw ('ChangeDate {0} leaves the client less than a week to reply to the approval requests. Pick a day at least eight days after {1}.' -f $proposedDate.ToString('yyyy-MM-dd', $inv), $buildDate.ToString('yyyy-MM-dd', $inv)) }
function Format-Day([datetime]$Day) { $Day.ToString('dddd, MMMM d, yyyy', $inv) }
$emailWorkspace = if ($workspaceName) { "your Sentinel workspace $workspaceName" } else { 'your Sentinel workspace' }

function New-ChangeRequest([hashtable]$Spec) {
    foreach ($field in 'Description', 'Purpose') {
        if ((Get-SentenceCount $Spec[$field]) -gt 2) { throw "CR-$($Spec.Number) $field runs past two sentences." }
    }
    foreach ($field in 'Availability', 'UserExperience', 'Dependencies') {
        if ($Spec[$field] -match '[\r\n]' -or (Get-SentenceCount $Spec[$field]) -ne 1) { throw "CR-$($Spec.Number) $field must be one line." }
    }
    # Every change request writes a client email that asks for the client's approval (New-ApprovalEmail).
    if (-not $Spec.Email -or -not $Spec.Email.Approval) { throw "CR-$($Spec.Number) has no client approval request. Every change request writes one with New-ApprovalEmail." }
    $defaults = @{ Mitigation = $standardMitigation; DrImpact = $drImpact; DrPlan = $drPlan; Csv = $null }
    foreach ($k in $defaults.Keys) { if (-not $Spec.ContainsKey($k)) { $Spec[$k] = $defaults[$k] } }
    [pscustomobject]$Spec
}

# One step per line. A step given as an array keeps its first line numbered and indents the rest,
# for the commands a step runs.
function Format-Steps($steps) {
    $i = 0
    foreach ($s in $steps) {
        $i++
        $lines = @($s)
        '{0}. {1}' -f $i, $lines[0]
        foreach ($extra in @($lines | Select-Object -Skip 1)) { '    ' + $extra }
    }
}
function Format-ChangeRequest($cr) {
    $l = [System.Collections.Generic.List[string]]::new()
    foreach ($line in @(
            "Title: $($cr.Title)", "Client: $client", '',
            '1. Summary', '',
            'A) CHANGE DESCRIPTION', $cr.Description, '',
            'B) PURPOSE', $cr.Purpose, '',
            'C) RESOURCES', $cr.ResourceIntro, '')) { $l.Add($line) }
    foreach ($line in @($cr.ResourceLines)) { $l.Add($line) }
    foreach ($line in @('',
            '2. Impact:', '',
            'A) AVAILABILITY/PERFORMANCE', $cr.Availability, '',
            'B) USER EXPERIENCE', $cr.UserExperience, '',
            'C) DEPENDENCIES', $cr.Dependencies, '',
            'D) DR Impact', $cr.DrImpact, '',
            'E) MITIGATION', $cr.Mitigation, '',
            '3. Implementation, Testing & Rollback:', '',
            'A) IMPLEMENTATION PLAN')) { $l.Add($line) }
    foreach ($line in @(Format-Steps $cr.Implementation)) { $l.Add($line) }
    $l.Add(''); $l.Add('B) TESTING PLAN')
    foreach ($line in @(Format-Steps $cr.Testing)) { $l.Add($line) }
    $l.Add(''); $l.Add('C) ROLLBACK PLAN')
    foreach ($line in @(Format-Steps $cr.Rollback)) { $l.Add($line) }
    $l.Add(''); $l.Add('D) DR PLAN')
    if ($cr.DrPlan -is [array]) { foreach ($line in @(Format-Steps $cr.DrPlan)) { $l.Add($line) } } else { $l.Add($cr.DrPlan) }
    foreach ($line in @('', '4. Additional Info / Notifications:', '', 'A) REFERENCES')) { $l.Add($line) }
    foreach ($ref in $cr.References) { $l.Add(('- {0}: {1}' -f $ref[0], $ref[1])) }
    foreach ($line in @('', 'B) NOTIFICATION LIST', '')) { $l.Add($line) }
    $l.ToArray()
}
# The email: subject, greeting, then the paragraphs separated by a blank line, with no titles. A paragraph
# given as an array is a bulleted list.
function Format-Email($email) {
    $l = [System.Collections.Generic.List[string]]::new()
    $l.Add("Subject: $($email.Subject)"); $l.Add('')
    $l.Add($(if ($ClientContact) { 'Hello {0},' -f (ConvertTo-CopyText $ClientContact) } else { 'Hello,' })); $l.Add('')
    foreach ($p in $email.Paragraphs) {
        if ($p -is [array]) { foreach ($item in $p) { $l.Add("- $item") } } else { $l.Add($p) }
        $l.Add('')
    }
    $l.Add('Thank you,')
    if ($SenderName) { $l.Add((ConvertTo-CopyText $SenderName)) }
    $l.ToArray()
}
# The resources of an email grouped by subscription: a line naming each subscription, then its resources as
# a bulleted list, each written by Label.
function Get-EmailResourceList($resources, [scriptblock]$Label) {
    $paragraphs = [System.Collections.Generic.List[object]]::new()
    foreach ($g in @($resources | Group-Object SubscriptionId | Sort-Object { Format-Subscription $_.Name })) {
        $paragraphs.Add(('Subscription {0}:' -f (Format-Subscription $g.Name)))
        $paragraphs.Add([string[]]@($g.Group | Sort-Object ResourceGroup, Name | ForEach-Object $Label))
    }
    , $paragraphs.ToArray()
}
$groupLabel = { '{0} (resource group {1})' -f $_.Name, $_.ResourceGroup }
$settingLabel = { '{0} (resource group {1}, {2})' -f $_.Name, $_.ResourceGroup, $_.Setting }
# The lines that head each group of resources in a client email. Azure resources sit under their subscription, and
# CR-19 adds the management groups and root scope above the subscriptions and the Microsoft Entra directory roles,
# which belong to no subscription.
$emailHeading = '^(Subscription .+|Management group .+|Root scope|Microsoft Entra ID directory roles):$'
function Get-Yours([int]$n, [string]$many) { if ($n -eq 1) { "one of your $many" } else { "$n of your $many" } }
$proposedDay = Format-Day $proposedDate
$replyDay = Format-Day $replyDate
$explainTls = 'TLS is the protocol that encrypts connections to a service, and versions 1.0 and 1.1 are its older versions.'
# Every client email is an approval request built here, so every change request asks the client the same way
# and nothing reads as already decided. It reads as a letter: no titles, each part a plain paragraph whose
# opening sentence says what the part is, in its own words. The parts always come in this order: the ask (one
# or two sentences, given as an array of them, the first turned into "I would like your approval to ..."), why
# ("I recommend ... because ..."), what it means for the client, the resources by subscription, how the change
# can be reversed, and the request. The request asks for approval of the proposed date, or with -Window for a
# maintenance window where the change needs a restart, then gives the reply-by date, any Options the client
# has, and the promise not to schedule the change without approval. Ask replaces the standard question when
# a change needs an answer from the client first. No two paragraphs may open with the same words.
function New-ApprovalEmail {
    param([string]$Subject, [string[]]$Change, [string]$Why, [object[]]$Effect, [string]$Listed, [object[]]$Resources, [string]$Reversal, [string]$Ask, [string]$Options, [switch]$Window)
    # Change is given as its authored sentences, so a name filled into one, such as a management group named
    # Contoso Inc. Production, cannot change the count.
    $Change = @($Change | Where-Object { $_ })
    if ($Change.Count -lt 1 -or $Change.Count -gt 2) { throw "The email for $Subject must ask for the change in one or two sentences." }
    foreach ($field in 'Why', 'Effect', 'Resources', 'Reversal') { if (-not (Get-Variable $field -ValueOnly)) { throw "The email for $Subject has no $field part." } }
    if ($Change[0] -notmatch '^I would like to ') { throw "The email for $Subject must ask with I would like to." }
    $Change[0] = 'I would like your approval to ' + $Change[0].Substring('I would like to '.Length)
    if ($Why -notmatch '^I recommend \S.* because\b') { throw "The email for $Subject must say why as I recommend ... because ..." }
    if (-not $Ask) { $Ask = if ($Window) { 'Could you approve this change and suggest a maintenance window that works for you?' } else { 'Could you approve this change for {0}?' -f $proposedDay } }
    if (-not $Options -and -not $Window) { $Options = 'If another date suits you better, or anything listed above should stay out of the change, please let me know.' }
    $request = (@($Ask, ('Please reply by {0}.' -f $replyDay), $Options, 'I will not schedule this change until I have your approval.') | Where-Object { $_ }) -join ' '
    $paragraphs = @(, ($Change -join ' ')) + @(, $Why) + @($Effect) + @(, $Listed) + @($Resources) + @(, $Reversal) + @(, $request)
    # Each paragraph opens in its own words. The lines that head each resource list are left out.
    $openings = @($paragraphs | Where-Object { $_ -is [string] -and $_ -notmatch $emailHeading } | ForEach-Object { (@($_ -split '\s+' | Select-Object -First 3) -join ' ').ToLowerInvariant() })
    $repeated = @($openings | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name)
    if ($repeated.Count) { throw "The email for $Subject opens more than one paragraph with $($repeated -join ', ')." }
    @{ Subject = "Approval requested: $Subject"; Approval = $true; Window = [bool]$Window; Paragraphs = $paragraphs }
}
# CR-01 and CR-10 send resource logs to the client's Sentinel workspace, which the client pays to ingest.
function Get-IngestionCost([bool]$ActivityLog) {
    'This change adds Log Analytics ingestion to {0}. The resource logs are billed as data ingested into the workspace, and their volume depends on how busy each resource is.{1}' -f $emailWorkspace, $(if ($ActivityLog) { ' The Azure Activity log of each subscription is ingested at no charge.' } else { '' })
}
function Get-LoggingEffect([int]$n) {
    'I do not expect any visible effect on {0} or the people who use {1}. A diagnostic setting only sends the logs a resource already produces to the workspace, and does not change how the resource runs.' -f (Get-Pick $n 'the resource' 'these resources'), (Get-Pick $n 'it' 'them')
}

#region Change requests
# Each Build returns the change request, or a State when there is nothing to change, plus Notes for
# the index about resources it left out.
$diagnosticTypes = [ordered]@{
    'microsoft.keyvault/vaults'               = 'Key vault', 'Key vaults'
    'microsoft.automation/automationaccounts' = 'Automation account', 'Automation accounts'
    'microsoft.web/sites'                     = 'App Service app', 'App Service apps'
    'microsoft.logic/workflows'               = 'Logic App', 'Logic Apps (Consumption)'
    'microsoft.recoveryservices/vaults'       = 'Recovery Services vault', 'Recovery Services vaults'
    'microsoft.network/bastionhosts'          = 'Bastion host', 'Azure Bastion hosts'
    'microsoft.cognitiveservices/accounts'    = 'Azure AI services account', 'Azure AI services accounts'
    'microsoft.dbformysql/flexibleservers'    = 'MySQL flexible server', 'MySQL flexible servers'
}
$diagnosticReferences = @(
    , @('Remediate non-compliant resources with Azure Policy', 'https://learn.microsoft.com/azure/governance/policy/how-to/remediate-resources')
    , @('Create diagnostic settings at scale using Azure Policy', 'https://learn.microsoft.com/azure/azure-monitor/platform/diagnostics-settings-policies-deployifnotexists')
)

# Assigns the initiative at the subscriptions given. Covered is true when other subscriptions in the pack
# already have it, and then each subscription gets its own assignment, since one at the management
# group would overlap theirs.
function New-DiagnosticAssignment([string[]]$Subscriptions, [bool]$Covered) {
    $subscriptions = @($Subscriptions)
    $n = $subscriptions.Count
    $atGroup = $managementGroup -and -not $Covered
    # The estate inventory (P0.5) counts each covered type. Without it, or in the older shape without
    # resource types, every covered type is listed without a count.
    $inventory = @(if ((Get-Status 'P0.5') -in 'OK', 'PARTIAL', 'EMPTY' -and -not (Test-Unreadable 'P0.5')) { Get-Rows 'P0.5' })
    $counted = (Get-Status 'P0.5') -eq 'EMPTY' -or ($inventory.Count -and $inventory[0].PSObject.Properties.Name -contains 'ResourceType')
    $counts = [ordered]@{}
    # The client email counts each subscription on its own.
    $bySubscription = @{}
    if ($counted) {
        # Only the subscriptions this assignment covers are counted.
        foreach ($row in @($inventory | Where-Object { -not (Get-Text $_.subscriptionId) -or (ConvertTo-CopyText $_.subscriptionId).ToLowerInvariant() -in $subscriptions })) {
            $type = (Get-Text $row.ResourceType).ToLowerInvariant()
            if (-not $diagnosticTypes.Contains($type)) { continue }
            $counts[$type] = [int]$counts[$type] + (Get-Number $row.Resources)
            $sub = (ConvertTo-CopyText $row.subscriptionId).ToLowerInvariant()
            if (-not $bySubscription[$sub]) { $bySubscription[$sub] = @{} }
            $bySubscription[$sub][$type] = [int]$bySubscription[$sub][$type] + (Get-Number $row.Resources)
        }
    }
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('Subscriptions:')
    foreach ($s in $subscriptions) { $lines.Add('- ' + (Format-Subscription $s)) }
    $lines.Add(''); $lines.Add('Resource types the initiative covers:')
    foreach ($type in $diagnosticTypes.Keys) {
        if ($counted -and -not $counts[$type]) { continue }
        $lines.Add('- ' + $diagnosticTypes[$type][1] + $(if ($counted) { ': ' + $counts[$type] } else { '' }))
    }
    $lines.Add('- Subscription Activity Log: ' + $n)
    $lines.Add(''); $lines.Add("Destination: $workspace")
    $countWords = if ($counted) { ' with their current counts' } else { '' }
    # An assignment has one scope: the management group when one is named, otherwise each subscription.
    $impl = [System.Collections.Generic.List[object]]::new()
    $impl.Add('In the Azure portal, go to Policy > Authoring > Definitions and open the ATMO-MXDR-DIAG-TOSENT initiative.')
    $impl.Add('Select Assign initiative.')
    if ($atGroup) {
        $intro = "The initiative is assigned once at the management group $managementGroup, which holds the subscriptions below, and covers the resource types listed$countWords."
        $impl.Add("On the Basics tab, set Scope to the management group $managementGroup and name the assignment ATMO-MXDR-DIAG-TOSENT.")
    }
    else {
        $intro = 'The initiative is assigned at {0}{1} and covers the resource types listed{2}.' -f (Get-Pick $n 'the subscription below' 'each subscription below'), $(if ($Covered) { Get-Pick $n ', which has no ATMO-MXDR policy state yet,' ', which have no ATMO-MXDR policy state yet,' } else { '' }), $countWords
        $impl.Add(('On the Basics tab, set Scope to the {0} listed in the RESOURCES section and name the assignment ATMO-MXDR-DIAG-TOSENT.' -f (Get-Pick $n 'subscription' 'first subscription')))
    }
    $impl.Add("On the Parameters tab, set the Log Analytics workspace to $workspace.")
    $impl.Add('On the Remediation tab, set the managed identity type to User assigned managed identity and select ATMO-MXDR-DIAG-MI.')
    $impl.Add('Select Review + create > Create.')
    if (-not $atGroup) { Add-RepeatStep $impl $n 1 'subscription' }
    $each = if ($atGroup -or $n -eq 1) { 'the ATMO-MXDR-DIAG-TOSENT assignment' } else { 'each ATMO-MXDR-DIAG-TOSENT assignment' }
    $impl.Add("Once the first compliance scan completes, go to Policy > Remediation, select the Policies to remediate tab, and for $each create a remediation task for each policy in the initiative.")
    $listed = [System.Collections.Generic.List[object]]::new()
    foreach ($s in @($subscriptions | Sort-Object { Format-Subscription $_ })) {
        $listed.Add(('Subscription {0}:' -f (Format-Subscription $s)))
        $types = @(foreach ($type in $diagnosticTypes.Keys) {
                if (-not $counted) { $diagnosticTypes[$type][1] }
                elseif ($bySubscription[$s] -and $bySubscription[$s][$type]) { '{0}: {1}' -f $diagnosticTypes[$type][1], $bySubscription[$s][$type] }
            })
        $listed.Add([string[]]@($types + 'Subscription Activity Log'))
    }
    $email = New-ApprovalEmail -Subject 'diagnostic logging for Azure resources' `
        -Change @(('I would like to turn on diagnostic logging for your Azure resources by assigning the ATMO-MXDR-DIAG-TOSENT Azure Policy initiative {0}.' -f $(if ($atGroup) { "once at the management group $managementGroup, which holds the subscriptions below" } else { Get-Pick $n 'on the subscription below' 'on each subscription below' }), $emailWorkspace), ('An Azure Policy initiative is a set of rules that Azure keeps applied, and this one adds diagnostic settings that send the audit logs of the supported resources to {1}, including resources created later.' -f $(if ($atGroup) { "once at the management group $managementGroup, which holds the subscriptions below" } else { Get-Pick $n 'on the subscription below' 'on each subscription below' }), $emailWorkspace)) `
        -Why 'I recommend turning on this logging because, without these audit logs, the SOC cannot detect or investigate activity on these resources, such as an unexpected change to a key vault or an automation account. The initiative keeps the logging in place on every supported resource, including resources created later, so no resource is missed as your environment grows.' `
        -Effect @((Get-LoggingEffect 2), (Get-IngestionCost $true)) `
        -Reversal 'The initiative assignment can be removed and the diagnostic settings it added can be deleted at any time, which stops the logs and the ingestion they add.' `
        -Listed ('{0} with the resources the initiative covers{1}:' -f (Get-Pick $n 'The subscription is listed below' 'Each subscription is listed below'), $(if ($counted) { (Get-Pick $n ' and how many it holds today' ' and how many each holds today') } else { '' })) `
        -Resources $listed.ToArray()
    @{ Used = @('P0.5'); Cr = New-ChangeRequest @{
            Number = 1; Key = 'diagnostic-logging'; Title = 'Deploy the ATMO-MXDR diagnostic logging initiative'
            Description = "Assign the ATMO-MXDR-DIAG-TOSENT Azure Policy initiative and run its remediation tasks, so the audit logs of supported Azure resources are sent to $workspace."
            Purpose = 'The initiative keeps audit logging in place on every supported resource, including resources created later. Sending these logs to Sentinel gives the SOC the telemetry it needs to detect and investigate activity on them.'
            ResourceIntro = $intro; ResourceLines = $lines.ToArray()
            Availability = 'No impact, since the Azure platform applies diagnostic settings without touching the running workloads.'
            UserExperience = 'No change for users or applications.'
            Dependencies = 'Relies on the ATMO-MXDR-DIAG-MI managed identity and adds a small amount of audit log ingestion to the Sentinel workspace.'
            Implementation = $impl.ToArray()
            Testing = @(
                "In the Azure portal, go to Policy > Compliance and open $each created by this change."
                'Confirm the resources in scope show as Compliant.'
                "Open one resource of each type listed in the RESOURCES section, go to Monitoring > Diagnostic settings and confirm the ATMO-MXDR setting sends to $workspace.")
            Rollback = @(
                "In the Azure portal, go to Policy > Authoring > Assignments, open $each created by this change and select Delete assignment."
                'On each resource the remediation tasks updated, go to Monitoring > Diagnostic settings, select Edit setting on the ATMO-MXDR setting and select Delete.'
                'For the Subscription Activity Log, go to Monitor > Activity log > Export Activity Logs, select each subscription listed in the RESOURCES section, select Edit setting on the ATMO-MXDR setting and select Delete.')
            References = @(, @('Assign a policy in the Azure portal', 'https://learn.microsoft.com/azure/governance/policy/assign-policy-portal')) + $diagnosticReferences
            Csv = @($subscriptions | ForEach-Object { New-Resource $_ '' $_ $(if ($atGroup) { "Under the management group $managementGroup" } else { 'Initiative assignment scope' }) "/subscriptions/$_" })
            Email = $email
        } }
}

# Where an assignment applies, read from its ID: a management group, a subscription or a resource group.
function Format-AssignmentScope([string]$AssignmentId) {
    $id = Get-Text $AssignmentId
    if ($id -match '(?i)^/providers/microsoft\.management/managementgroups/([^/]+)/') { return 'management group ' + (ConvertTo-CopyText $Matches[1]) }
    if ($id -match '(?i)^/subscriptions/([^/]+)/resourcegroups/([^/]+)/') { return 'resource group {0} in subscription {1}' -f (ConvertTo-CopyText $Matches[2]), (Format-Subscription $Matches[1]) }
    if ($id -match '(?i)^/subscriptions/([^/]+)/') { return 'subscription ' + (Format-Subscription $Matches[1]) }
    ''
}

function New-DiagnosticRemediation($rows) {
    # DR.6-NONCOMPLIANT has a row per resource and assignment. A resource that fails under two assignments
    # is listed once, with the policies of both.
    $resources = foreach ($g in @($rows | Group-Object { (Get-Text $_.ResourceId).ToLowerInvariant() })) {
        $r = $g.Group[0]
        $id = Get-Text $r.ResourceId
        $type = (Get-Text $r.ResourceType).ToLowerInvariant()
        $parts = $id.Split('/')
        $sub = if ($parts.Count -gt 2) { $parts[2] } else { '' }
        $label = if ($diagnosticTypes.Contains($type)) { $diagnosticTypes[$type][0] } else { ConvertTo-CopyText $type }
        $failing = (@($g.Group | ForEach-Object { (Get-Text $_.Policies) -split ',\s*' } | Where-Object { $_ } | Sort-Object -Unique) -join ', ')
        if ($id -match '^/subscriptions/[^/]+$') { $r = New-Resource 'Subscription Activity Log' '' $sub ('policies ' + $failing) $id }
        else {
            $rg = if ($id -match '/resourcegroups/([^/]+)/') { $Matches[1] } else { '' }
            $r = New-Resource $parts[-1] $rg $sub ('{0}, policies {1}' -f $label, $failing) $id
        }
        # The client email names the resource type, not the policy names.
        $r | Add-Member -NotePropertyName Label -NotePropertyValue $label
        $r
    }
    $resources = @($resources)
    # A remediation task belongs to one assignment and one policy. The initiative may be assigned once
    # per subscription under the same name, so each assignment, told apart by its ID, gets its own tasks.
    $pairs = foreach ($g in @($rows | Group-Object { $id = Get-Text $_.AssignmentId; if ($id) { $id } else { Get-Text $_.AssignmentName } } | Sort-Object Name)) {
        $first = $g.Group[0]
        $name = ConvertTo-CopyText $first.AssignmentName
        if (-not $name) { $name = 'ATMO-MXDR' }
        $scope = Format-AssignmentScope $(if (Get-Text $first.AssignmentScope) { (Get-Text $first.AssignmentScope) + '/' } else { $first.AssignmentId })
        $policies = @($g.Group | ForEach-Object { (Get-Text $_.Policies) -split ',\s*' } | Where-Object { $_ } | ForEach-Object { ConvertTo-CopyText $_ } | Sort-Object -Unique)
        '- Assignment {0}{1}: {2}' -f $name, $(if ($scope) { " at $scope" } else { '' }), ($policies -join ', ')
    }
    $activity = @($resources | Where-Object { $_.ResourceId -match '^/subscriptions/[^/]+$' }).Count
    $impl = [System.Collections.Generic.List[object]]::new()
    $impl.Add('In the Azure portal, go to Policy > Remediation and select the Policies to remediate tab.')
    $impl.Add(@('Create one remediation task for each assignment and policy below. Select the assignment, select New remediation task, choose the policy, keep the scope at the assignment scope and select Remediate:') + @($pairs))
    $testing = [System.Collections.Generic.List[object]]::new()
    $testing.Add('In the Azure portal, go to Policy > Remediation and select the Remediation tasks tab.')
    $testing.Add('Confirm each remediation task created for this change finished with no failed resources.')
    $testing.Add("Open each resource listed in the RESOURCES section, go to Monitoring > Diagnostic settings and confirm the ATMO-MXDR setting sends to $workspace.")
    $rollback = [System.Collections.Generic.List[object]]::new()
    $rollback.Add('In the Azure portal, open each resource to revert, go to Monitoring > Diagnostic settings, select Edit setting on the ATMO-MXDR setting created by this change and select Delete.')
    if ($activity) {
        $testing.Add("For the Subscription Activity Log, go to Monitor > Activity log > Export Activity Logs, select the subscription and confirm the ATMO-MXDR setting sends to $workspace.")
        $rollback.Add('For the Subscription Activity Log, go to Monitor > Activity log > Export Activity Logs, select the subscription, select Edit setting on the ATMO-MXDR setting and select Delete.')
    }
    $n = $resources.Count
    $email = New-ApprovalEmail -Subject 'diagnostic logging remediation for Azure resources' `
        -Change @(('I would like to run Azure Policy remediation tasks for the ATMO-MXDR-DIAG-TOSENT initiative on {0}.' -f (Get-Yours $n 'Azure resources'), (Get-Pick $n 'the resource sends' 'the resources send'), (Get-Pick $n 'its' 'their'), $emailWorkspace), ('A remediation task adds the diagnostic settings the initiative expects, so {1} {2} audit logs to {3}.' -f (Get-Yours $n 'Azure resources'), (Get-Pick $n 'the resource sends' 'the resources send'), (Get-Pick $n 'its' 'their'), $emailWorkspace)) `
        -Why ('I recommend running the remediation because {0} not send {1} audit logs to {2} today, so the SOC cannot detect or investigate activity on {3}. The remediation brings {3} in line with the rest of your environment.' -f (Get-Pick $n 'the resource below does' 'the resources below do'), (Get-Pick $n 'its' 'their'), $emailWorkspace, (Get-Pick $n 'it' 'them')) `
        -Effect @((Get-LoggingEffect $n), (Get-IngestionCost ([bool]$activity))) `
        -Listed (Get-Pick $n 'The resource is listed below with its type:' 'The resources are listed below by subscription, each with its type:') `
        -Resources (Get-EmailResourceList $resources { if ($_.ResourceGroup) { '{0} (resource group {1}, {2})' -f $_.Name, $_.ResourceGroup, $_.Label } else { $_.Name } }) `
        -Reversal 'The diagnostic settings the remediation adds can be deleted at any time, which stops the logs and the ingestion they add.'
    @{ Used = @('DR.6-NONCOMPLIANT'); Cr = New-ChangeRequest @{
            Number = 10; Key = 'diagnostic-remediation'; Title = 'Remediate resources missing ATMO-MXDR diagnostic logging'
            Description = ('Run Azure Policy remediation tasks for the ATMO-MXDR-DIAG-TOSENT initiative on {0}, so their audit logs reach {1}.' -f (Get-Listed $n 'resource' 'resources'), $workspace)
            Purpose = 'These resources are not compliant with the diagnostic logging initiative, so their audit activity does not reach Sentinel. Remediation deploys the missing diagnostic settings and returns them to compliance.'
            ResourceIntro = ('{0} not compliant with the initiative, with the policies each one fails.' -f $(if ($n -eq 1) { 'The resource below is' } else { "The $n resources below are" }))
            ResourceLines = Format-ResourceList $resources
            Availability = 'No impact, since the Azure platform applies diagnostic settings without touching the running workloads.'
            UserExperience = 'No change for users or applications.'
            Dependencies = 'Relies on the managed identity of the initiative assignment and adds a small amount of audit log ingestion to the Sentinel workspace.'
            Implementation = $impl.ToArray(); Testing = $testing.ToArray(); Rollback = $rollback.ToArray()
            References = $diagnosticReferences; Csv = $resources
            Email = $email
        } }
}

# NB.6-PAAS-DETAIL lists the Redis caches, Service Bus and Event Hubs namespaces and Cosmos DB accounts
# below TLS 1.2 together, so each of CR-11 to CR-14 reads the rows of its own resource type.
function Get-PaasTlsResource([string]$Type) {
    , @(Get-Rows 'NB.6-PAAS-DETAIL' | Where-Object { (Get-Text $_.ResourceType) -ieq $Type } |
            ForEach-Object { New-Resource $_.Name $_.resourceGroup $_.subscriptionId ('minimum TLS ' + (Format-TlsVersion $_.MinimumTlsVersion)) $_.ResourceId })
}

# DP.4-VMSS-ELIGIBILITY lists the scale sets whose model lacks encryption at host. The machines of a
# Flexible scale set are virtual machines, so DP.4-ELIGIBILITY lists them too (with their scale set since
# collector 1.3.0). Those of a Flexible scale set that CR-15 takes are changed with it there, and the
# machines of every other scale set stay in CR-09.
function Get-VmId($row) { (ConvertTo-CopyText $row.VmId).ToLowerInvariant() }
function Test-ResultRead([string]$Id) { (Get-Status $Id) -in 'OK', 'PARTIAL', 'EMPTY' -and -not (Test-Unreadable $Id) }
function Get-ScaleSetText($value) { (Get-Text $value).ToLowerInvariant() }
# The scale sets CR-15 can take on their model alone: not AKS, with a model, eligible, and with the unique ID
# CR-15 checks before changing it. CR-09 hands over the machines of these scale sets only, so a scale set
# that CR-15 leaves out for a missing ID keeps its machines in CR-09.
function Test-ScaleSetModel($row) { -not (Test-True $row.Aks) -and (Test-True $row.HasModel) }
function Test-EligibleScaleSetModel($row) { (Test-ScaleSetModel $row) -and (Test-True $row.Eligible) -and [bool](ConvertTo-CopyText $row.UniqueId) }
function Get-EligibleScaleSetModels {
    @(if (Test-ResultRead 'DP.4-VMSS-ELIGIBILITY') { Get-Rows 'DP.4-VMSS-ELIGIBILITY' | Where-Object { Test-EligibleScaleSetModel $_ } })
}
# Checks the machines of eligible Flexible scale sets against DP.4-ELIGIBILITY. A list that does not name
# the scale set of each machine cannot prove them eligible, and neither can a PARTIAL list, which may have
# lost machines to a truncated read or an unread size list. Only a complete list (OK or EMPTY) proves that
# a machine missing from it already has encryption at host. Qualified maps each scale set that passes, by
# lowercase ID, to its machines without the setting. Unchecked says why none could be checked, and Blocked
# names each scale set with a machine that cannot take the setting.
function Test-FlexibleScaleSets($flexible) {
    $check = @{ Qualified = @{}; Unchecked = ''; Blocked = [System.Collections.Generic.List[string]]::new() }
    if (-not @($flexible).Count) { return $check }
    $complete = (Get-Status 'DP.4-ELIGIBILITY') -in 'OK', 'EMPTY' -and -not (Test-Unreadable 'DP.4-ELIGIBILITY')
    $vms = @(if ($complete) { Get-Rows 'DP.4-ELIGIBILITY' })
    $named = (Get-Status 'DP.4-ELIGIBILITY') -eq 'EMPTY' -or ($vms.Count -and $vms[0].PSObject.Properties.Name -contains 'ScaleSet')
    $identified = (Get-Status 'DP.4-ELIGIBILITY') -eq 'EMPTY' -or ($vms.Count -and $vms[0].PSObject.Properties.Name -contains 'VmId')
    if (-not $complete -or -not $named -or -not $identified) {
        $check.Unchecked = if ($complete -and -not $named) { 'does not name the scale set of each machine' } elseif ($complete) { 'does not carry the VM ID of each machine' } elseif ((Get-Status 'DP.4-ELIGIBILITY') -eq 'MISSING') { 'was not collected' } elseif (Test-Unreadable 'DP.4-ELIGIBILITY') { 'is unreadable' } else { 'reads ' + (Get-Status 'DP.4-ELIGIBILITY') }
        return $check
    }
    foreach ($f in @($flexible)) {
        $key = (Get-Text $f.ResourceId).ToLowerInvariant()
        $members = @($vms | Where-Object { (Get-ScaleSetText $_.ScaleSet) -eq $key })
        # A machine without its VM ID cannot be told from one created again under its name, so it blocks too.
        $bad = @($members | Where-Object { -not (Test-True $_.Eligible) -or -not (Get-VmId $_) })
        if ($bad.Count) { $check.Blocked.Add(('{0} ({1})' -f (ConvertTo-CopyText $f.Name), (@($bad | Sort-Object Name | ForEach-Object { '{0} {1}' -f (ConvertTo-CopyText $_.Name), $(if (-not (Test-True $_.Eligible)) { (ConvertTo-CopyText $_.Reason) -replace '^(size support not read):.*$', '$1' } else { 'VM ID not read' }) }) -join ', '))) }
        else { $check.Qualified[$key] = $members }
    }
    $check
}
# The first two steps of CR-09 and CR-15. Each command names its subscription, so neither step depends on
# the subscription Cloud Shell was left on and step 2 checks every one, not only the last registered.
function New-EncryptionAtHostRegistration($resources) {
    $subscriptions = @($resources | ForEach-Object SubscriptionId | Sort-Object -Unique)
    $register = @('In the Azure portal, open Cloud Shell in Bash and register the EncryptionAtHost feature on each subscription in the RESOURCES section:')
    foreach ($s in $subscriptions) { $register += "az feature register --name EncryptionAtHost --namespace Microsoft.Compute --subscription $s" }
    $check = @('Wait for the registration on each subscription, running these until every one returns Registered:')
    foreach ($s in $subscriptions) { $check += "az feature show --name EncryptionAtHost --namespace Microsoft.Compute --subscription $s --query properties.state -o tsv" }
    , $register
    , $check
}
# Whether NB.5-DETAIL records the SCM minimum: a row carries the column, or a pack from 1.13.0 or later lists no site,
# since before 1.13.0 the list left out a site whose site minimum was 1.2 whatever its SCM minimum.
function Test-ScmTlsRead($rows) {
    if (@($rows).Count) { return @($rows)[0].PSObject.Properties.Name -contains 'ScmMinTlsVersion' }
    $version = $null
    [version]::TryParse((Get-Text $parameters.ScriptVersion), [ref]$version) -and $version -ge [version]$scmTlsVersion
}
# NB.5 counts every site configuration, so it shows when the pack has no App Service site at all, and then a note about
# deployment slots has nothing to say.
function Test-NoAppServiceSites {
    (Get-Status 'NB.5') -eq 'EMPTY' -or ((Get-Status 'NB.5') -eq 'OK' -and -not (Test-Unreadable 'NB.5') -and @(Get-Rows 'NB.5').Count -eq 1 -and (Get-Text @(Get-Rows 'NB.5')[0].Configs) -eq '0')
}
# A value quoted for Bash. Resource group names may hold parentheses, which Bash reads as syntax unquoted.
function Format-ShellArgument([string]$Value) { "'" + ($Value -replace "'", "'\''") + "'" }
function Format-UpgradePolicy($value) { $p = ConvertTo-CopyText $value; if ($p) { "upgrade policy $p" } else { 'no upgrade policy' } }

# NB.2-DETAIL keeps the prefixes, ports, subnets and network interfaces of each rule as lists. A list reads as an
# array, as the JSON text of one, or as one value. Empty entries, from a rule that sets the list form of a
# property and leaves the single form empty, are dropped. An attachment is read by its ID.
function Get-List($value) {
    $items = if ($value -is [array]) { $value } elseif ((Get-Text $value) -match '^\[') { @((Get-Text $value | ConvertFrom-Json) | ForEach-Object { $_ }) } else { @($value) }
    @(foreach ($i in $items) {
            $v = if ($null -ne $i -and $i.PSObject.Properties.Name -contains 'id') { Get-Text $i.id } else { Get-Text $i }
            if ($v) { $v }
        })
}
function Join-Words([string[]]$Words) {
    $w = @($Words | Where-Object { $_ })
    if ($w.Count -le 1) { return ($w -join '') }
    '{0} and {1}' -f ($w[0..($w.Count - 2)] -join ', '), $w[-1]
}
# The management ports CR-16 closes, and how a rule source reads in a sentence.
$managementPorts = '22', '3389', '5985', '5986'
# The machines -AdminRuleOpen names, each with the management ports a security admin rule with Always Allow keeps
# open to the internet. That rule applies before every network security group, so CR-16 cannot close them. A
# machine name is unique only within its resource group, so each machine is named by its resource ID, the one
# form that names it once, and is kept by that ID whatever its case.
$heldOpen = [ordered]@{}
foreach ($entry in @($AdminRuleOpen | Where-Object { $_ })) {
    if ($entry -notmatch '^\s*(?i)(/subscriptions/([^/\s]+)/resourceGroups/([^/\s]+)/providers/Microsoft\.Compute/virtualMachines/([^/:\s]+))\s*:\s*(22|3389|5985|5986)\s*$') {
        throw ('-AdminRuleOpen takes each machine as the resource ID of the virtual machine followed by :port, with port 22, 3389, 5985 or 5986, such as /subscriptions/<subscription>/resourceGroups/rg-web/providers/Microsoft.Compute/virtualMachines/vm-web01:3389, not "{0}".' -f (ConvertTo-CopyText $entry))
    }
    $key, $subscription, $group, $machine, $port = $Matches[1].ToLowerInvariant(), $Matches[2], $Matches[3], $Matches[4], $Matches[5]
    if (-not $heldOpen.Contains($key)) {
        $label = '{0} in resource group {1} of subscription {2}' -f (ConvertTo-CopyText $machine), (ConvertTo-CopyText $group), (Format-Subscription $subscription)
        $heldOpen[$key] = [pscustomobject]@{ Name = $label; Ports = [System.Collections.Generic.List[string]]::new() }
    }
    if ($port -notin $heldOpen[$key].Ports) { $heldOpen[$key].Ports.Add($port) }
}
# Each machine with its ports, such as vm-jump01 (ports 22 and 3389).
function Format-HeldOpen {
    Join-Words @(foreach ($m in $heldOpen.Values) { '{0} ({1} {2})' -f $m.Name, (Get-Pick $m.Ports.Count 'port' 'ports'), (Join-Words @($m.Ports | Sort-Object { [int]$_ })) })
}
function Format-RuleSource([string]$Prefix) { if ($Prefix -eq '*') { 'any address' } else { ConvertTo-CopyText $Prefix } }
function Format-RuleProtocol([string]$Protocol) { switch -Regex ($Protocol) { '^(\*|)$' { 'any protocol' } '^(?i)(tcp|udp|icmp|esp|ah)$' { $Protocol.ToUpperInvariant() } default { ConvertTo-CopyText $Protocol } } }
# Where a rule applies: each subnet by its name and virtual network, each network interface by its name and
# virtual machine.
function Get-RuleAttachments($row) {
    $vms = @{}
    $nicVms = if ($row.NicVms -isnot [array] -and (Get-Text $row.NicVms) -match '^\[') { @((Get-Text $row.NicVms | ConvertFrom-Json) | ForEach-Object { $_ }) } else { $row.NicVms }
    foreach ($n in @($nicVms | Where-Object { $_ })) { $vms[(Get-Text $n.NicId).ToLowerInvariant()] = Get-Text $n.VmId }
    @(
        foreach ($s in Get-List $row.Subnets) {
            if ($s -match '(?i)/virtualnetworks/([^/]+)/subnets/([^/]+)$') { 'subnet {0} of virtual network {1}' -f (ConvertTo-CopyText $Matches[2]), (ConvertTo-CopyText $Matches[1]) } else { 'subnet ' + (ConvertTo-CopyText $s) }
        }
        foreach ($n in Get-List $row.Nics) {
            $vm = $vms[$n.ToLowerInvariant()]
            '{0}{1}' -f ('network interface ' + (ConvertTo-CopyText ($n -split '/')[-1])), $(if ($vm) { ' of virtual machine ' + (ConvertTo-CopyText ($vm -split '/')[-1]) } else { '' })
        })
}
# Defender for Servers Plan 2, which just-in-time VM access needs, read from P0.3: On or Off for each subscription
# with a VirtualMachines row (On when its tier is Standard with sub-plan P2). A subscription without one, which a
# PARTIAL or unread P0.3 can leave out, stays unknown, so the email never calls a plan off that was not read.
function Get-ServersPlan2 {
    $plan = @{}
    if (-not (Test-ResultRead 'P0.3')) { return $plan }
    foreach ($p in @(Get-Rows 'P0.3' | Where-Object { (Get-Text $_.Plan) -ieq 'VirtualMachines' })) {
        $plan[(ConvertTo-CopyText $p.subscriptionId).ToLowerInvariant()] = $(if ((Get-Text $p.Tier) -ieq 'Standard' -and (Get-Text $p.SubPlan) -ieq 'P2') { 'On' } else { 'Off' })
    }
    $plan
}

$catalog = @(
    @{ Number = 1; Key = 'diagnostic-logging'; Change = 'Diagnostic logging initiative assigned on every subscription'; Sources = @('DR.6-INITIATIVE')
       Build = {
            $all = @($parameters.Subscriptions | ForEach-Object { (ConvertTo-CopyText $_).ToLowerInvariant() } | Where-Object { $_ })
            $fresh = 'CR-01 assigns the initiative where no ATMO-MXDR policy state was found. An assignment made shortly before collection shows no state until its first compliance scan, so confirm under Policy > Assignments that it is not already there before raising CR-01.'
            if ((Get-Status 'DR.6-INITIATIVE') -eq 'EMPTY' -or @(Get-Rows 'DR.6-INITIATIVE').Count -eq 0) {
                $built = New-DiagnosticAssignment $all $false
                $built.Notes = @($fresh)
                return $built
            }
            # The initiative has policy states somewhere. A subscription without any is still to be assigned.
            $status = Get-Status 'DR.6-COVERAGE'
            if ($status -eq 'MISSING') { return @{ State = $needsRecollection } }
            # A partial coverage list cannot tell a subscription without the initiative from one that was not
            # read, and assigning there again would overlap an existing assignment.
            if ($status -eq 'PARTIAL') { return @{ State = 'DR.6-COVERAGE is partial, so subscriptions without the initiative cannot be told apart. Recollect' } }
            if ($status -notin 'OK', 'EMPTY') { return @{ State = "Not collected (DR.6-COVERAGE $status)" } }
            if (Test-Unreadable 'DR.6-COVERAGE') { return @{ State = Get-UnreadableState 'DR.6-COVERAGE' } }
            $coverage = @(Get-Rows 'DR.6-COVERAGE' | ForEach-Object { (ConvertTo-CopyText $_.subscriptionId).ToLowerInvariant() })
            $uncovered = @($all | Where-Object { $_ -notin $coverage })
            if (-not $uncovered.Count) { return @{ State = 'No gaps found, every subscription has the initiative' } }
            $covered = $uncovered.Count -lt $all.Count
            $built = New-DiagnosticAssignment $uncovered $covered
            $built.Used = @('P0.5')
            $built.Notes = @($fresh) + @(if ($managementGroup -and $covered) { 'CR-01 assigns the initiative per subscription, not at the management group {0}, because other subscriptions already have it and an assignment at the group would overlap theirs.' -f $managementGroup })
            $built } }

    @{ Number = 2; Key = 'storage-secure-transfer'; Change = 'Secure transfer required on storage accounts'; Sources = @('DP.1-DETAIL')
       Build = {
            $gaps = @(Get-Rows 'DP.1-DETAIL' | Where-Object { -not (Test-True $_.SecureTransfer) })
            # NFS mounts are refused once secure transfer is required, so accounts that may serve NFS stay out.
            $nfs = @($gaps | Where-Object { (Test-True $_.NfsV3) -or (Get-Text $_.Kind) -ieq 'FileStorage' })
            $notes = @(if ($nfs.Count) { '{0} that may serve NFS left out of CR-02: {1}. {2}' -f (Get-Count $nfs.Count 'storage account' 'storage accounts'), (@($nfs | ForEach-Object { ConvertTo-CopyText $_.Name }) -join ', '), (Get-Pick $nfs.Count 'Add it only once it is confirmed to host no NFS share.' 'Add each one only once it is confirmed to host no NFS share.') })
            $resources = @($gaps | Where-Object { $_ -notin $nfs } | ForEach-Object { New-Resource $_.Name $_.resourceGroup $_.subscriptionId 'secure transfer disabled' $_.ResourceId })
            $n = $resources.Count
            if (-not $n) { return @{ State = $(if ($nfs.Count) { 'Only accounts that may serve NFS remain' } else { 'No gaps found' }); Notes = $notes } }
            $impl = [System.Collections.Generic.List[object]]::new()
            $impl.Add((Get-OpenStep $n 'Storage accounts' 'storage account'))
            $impl.Add('Go to Settings > Configuration.')
            $impl.Add('Set Secure transfer required to Enabled and select Save.')
            Add-RepeatStep $impl $n 1 'storage account'
            @{ Notes = $notes; Cr = New-ChangeRequest @{
                    Number = 2; Key = 'storage-secure-transfer'; Title = 'Require secure transfer on storage accounts'
                    Description = 'Enable Secure transfer required on {0}, so {1} encrypted connections only.' -f (Get-Listed $n 'storage account' 'storage accounts'), (Get-Pick $n 'it accepts' 'they accept')
                    Purpose = 'Requests over plain HTTP and SMB connections without encryption expose data and credentials in transit. Requiring secure transfer refuses those connections and keeps storage traffic encrypted.'
                    ResourceIntro = '{0} secure transfer.' -f $(if ($n -eq 1) { 'The storage account below does not require' } else { "The $n storage accounts below do not require" })
                    ResourceLines = Format-ResourceList $resources
                    Availability = 'No impact, since the setting applies immediately without taking storage offline.'
                    UserExperience = 'No change for clients that already connect over HTTPS or encrypted SMB.'
                    Dependencies = 'None expected, since only a client still using HTTP or unencrypted SMB would be refused.'
                    Implementation = $impl.ToArray()
                    Testing = @(
                        ('In the Azure portal, open {0} and go to Settings > Configuration.' -f (Get-EachStep $n 'storage account'))
                        'Confirm Secure transfer required shows Enabled.')
                    Rollback = @(
                        'In the Azure portal, open the storage account to revert and go to Settings > Configuration.'
                        'Set Secure transfer required to Disabled and select Save.')
                    References = @(, @('Require secure transfer to ensure secure connections', 'https://learn.microsoft.com/azure/storage/common/storage-require-secure-transfer'))
                    Csv = $resources
                    Email = New-ApprovalEmail -Subject 'secure transfer for Azure storage accounts' `
                        -Change @(('I would like to turn on Secure transfer required on {0}, so {1} encrypted connections only.' -f (Get-Yours $n 'storage accounts'), (Get-Pick $n 'it accepts' 'they accept')), 'Secure transfer means HTTPS for web requests and encrypted SMB, the protocol Windows uses for file shares.') `
                        -Why ('I recommend requiring secure transfer because requests over plain HTTP and SMB connections without encryption expose data and credentials in transit, where they can be read or altered. Requiring it refuses those connections, so all traffic to {0} is encrypted.' -f (Get-Pick $n 'the account' 'these accounts')) `
                        -Listed (Get-Pick $n 'The account is listed below:' 'The accounts are listed below by subscription:') `
                        -Resources (Get-EmailResourceList $resources $groupLabel) `
                        -Reversal 'Secure transfer required can be turned off again on any account, and the change takes effect straight away.' `
                        -Effect ('Applications and people that already connect over HTTPS, or over SMB with encryption, will see no change. Once the setting is on, Azure Storage rejects any request made over HTTP and any SMB connection without encryption, such as SMB 2.1, so a system that still connects to {0} that way would stop working until it moves to HTTPS or encrypted SMB.' -f (Get-Pick $n 'the account' 'these accounts'))
                } } } }

    @{ Number = 3; Key = 'storage-minimum-tls'; Change = 'Minimum TLS 1.2 on storage accounts'; Sources = @('DP.1-DETAIL')
       Build = {
            $resources = @(Get-Rows 'DP.1-DETAIL' | Where-Object { (Get-Text $_.MinimumTlsVersion) -notin 'TLS1_2', 'TLS1_3' } |
                ForEach-Object { New-Resource $_.Name $_.resourceGroup $_.subscriptionId ('minimum TLS ' + (Format-TlsVersion $_.MinimumTlsVersion)) $_.ResourceId })
            $n = $resources.Count
            if (-not $n) { return @{ State = 'No gaps found' } }
            $impl = [System.Collections.Generic.List[object]]::new()
            $impl.Add((Get-OpenStep $n 'Storage accounts' 'storage account'))
            $impl.Add('Go to Settings > Configuration.')
            $impl.Add('Set Minimum TLS version to Version 1.2 and select Save.')
            Add-RepeatStep $impl $n 1 'storage account'
            @{ Cr = New-ChangeRequest @{
                    Number = 3; Key = 'storage-minimum-tls'; Title = 'Set minimum TLS version 1.2 on storage accounts'
                    Description = 'Set the minimum TLS version to 1.2 on {0}.' -f (Get-Listed $n 'storage account' 'storage accounts')
                    Purpose = 'Azure Storage stopped accepting TLS 1.0 and 1.1 on February 3, 2026, but {0} still {1} an older version in {2} configuration. Setting 1.2 brings the configuration in line with the platform and the security baseline.' -f (Get-Pick $n 'this account' 'these accounts'), (Get-Pick $n 'allows' 'allow'), (Get-Pick $n 'its' 'their')
                    ResourceIntro = '{0} with the minimum TLS version {1} today.' -f $(if ($n -eq 1) { 'The storage account below is listed' } else { "The $n storage accounts below are listed" }), (Get-Pick $n 'it allows' 'each one allows')
                    ResourceLines = Format-ResourceList $resources
                    Availability = 'No impact, since Azure Storage already refuses TLS 1.0 and 1.1 and connections that work today keep working.'
                    UserExperience = 'No change for users or applications.'
                    Dependencies = 'None, since the platform already requires TLS 1.2 or later from every client.'
                    Implementation = $impl.ToArray()
                    Testing = @(
                        ('In the Azure portal, open {0} and go to Settings > Configuration.' -f (Get-EachStep $n 'storage account'))
                        'Confirm Minimum TLS version shows Version 1.2.')
                    Rollback = @(
                        'In the Azure portal, open the storage account to revert and go to Settings > Configuration.'
                        'Set Minimum TLS version back to the version recorded for the account in the RESOURCES section, or to Version 1.0 where it is recorded as not set, since an account without the setting accepts TLS 1.0, and select Save.')
                    References = @(
                        , @('Enforce a minimum required version of TLS for requests to a storage account', 'https://learn.microsoft.com/azure/storage/common/transport-layer-security-configure-minimum-version')
                        , @('Migrate to TLS 1.2 for Azure Storage', 'https://learn.microsoft.com/azure/storage/common/transport-layer-security-configure-migrate-to-tls2'))
                    Csv = $resources
                    Email = New-ApprovalEmail -Subject 'minimum TLS 1.2 for Azure storage accounts' `
                        -Change @(('I would like to set the minimum TLS version to 1.2 on {0}.' -f (Get-Yours $n 'storage accounts')), $explainTls) `
                        -Why ('I recommend setting this minimum because TLS 1.0 and 1.1 have known weaknesses. Azure Storage stopped accepting them on February 3, 2026, but {0} an older version in {1} configuration, so this change brings the configuration in line with the platform and the security baseline.' -f (Get-Pick $n 'this account still allows' 'these accounts still allow'), (Get-Pick $n 'its' 'their')) `
                        -Listed (Get-Pick $n 'The account is listed below with its minimum TLS version today:' 'The accounts are listed below by subscription, each with its minimum TLS version today:') `
                        -Resources (Get-EmailResourceList $resources $settingLabel) `
                        -Reversal ('The minimum TLS version can be set back to the version {0} today, shown above.' -f (Get-Pick $n 'the account has' 'each account has')) `
                        -Effect 'I do not expect any visible effect, because Azure Storage already refuses TLS 1.0 and 1.1, so every connection that works today keeps working.'
                } } } }

    @{ Number = 4; Key = 'app-service-minimum-tls'; Change = 'Minimum TLS 1.2 on App Service apps'; Sources = @('NB.5-DETAIL')
       Build = {
            # NB.5-DETAIL lists each site whose minimum inbound TLS version, or since collector 1.13.0 that of its SCM
            # (Kudu) site, is below 1.2 or empty. Each part is changed only where its value is below 1.2. App Service
            # applies 1.2 to a site or an SCM site without a minimum, so an empty value is named in the index instead.
            $rows = @(Get-Rows 'NB.5-DETAIL')
            $scmRead = Test-ScmTlsRead $rows
            $low = { param($v) (Get-Text $v) -and (Get-Text $v) -notin '1.2', '1.3' }
            $label = { '{0} (resource group {1})' -f (ConvertTo-CopyText $_.Name), (ConvertTo-CopyText $_.resourceGroup) }
            $siteLow = @($rows | Where-Object { & $low $_.MinTlsVersion })
            $scmLow = @(if ($scmRead) { $rows | Where-Object { & $low $_.ScmMinTlsVersion } })
            $unset = @($rows | Where-Object { -not (Get-Text $_.MinTlsVersion) })
            $notes = [System.Collections.Generic.List[string]]::new()
            $siteOnlyUnset = @($unset | Where-Object { $_ -notin $scmLow })
            if ($siteOnlyUnset.Count) { $notes.Add(('{0} left out of CR-04 because Resource Graph returned no minimum TLS version, and App Service applies 1.2 when none is set: {1}. Check {2} in the portal if the value may be missing from Resource Graph.' -f (Get-Count $siteOnlyUnset.Count 'App Service app' 'App Service apps'), (@($siteOnlyUnset | ForEach-Object { ConvertTo-CopyText $_.Name } | Sort-Object) -join ', '), (Get-Pick $siteOnlyUnset.Count 'it' 'them'))) }
            $scmOnlyUnset = @($unset | Where-Object { $_ -in $scmLow })
            if ($scmOnlyUnset.Count) { $notes.Add(('{0} in CR-04 {1} no site minimum TLS version recorded, and App Service applies 1.2 when none is set, so CR-04 changes only {2} SCM site minimum: {3}.' -f (Get-Count $scmOnlyUnset.Count 'App Service app' 'App Service apps'), (Get-Pick $scmOnlyUnset.Count 'has' 'have'), (Get-Pick $scmOnlyUnset.Count 'its' 'their'), (@($scmOnlyUnset | ForEach-Object $label | Sort-Object) -join ', '))) }
            if ($scmRead) {
                $scmUnset = @($rows | Where-Object { -not (Get-Text $_.ScmMinTlsVersion) })
                if ($scmUnset.Count) { $notes.Add(('{0} left out of the SCM part of CR-04 because Resource Graph returned no SCM minimum TLS version, and App Service applies 1.2 to the SCM site when none is set: {1}. Check SCM Minimum Inbound TLS Version under Settings > Configuration > General settings in the portal if the value may be missing from Resource Graph.' -f (Get-Count $scmUnset.Count 'App Service app' 'App Service apps'), (@($scmUnset | ForEach-Object $label | Sort-Object) -join ', '))) }
            }
            else { $notes.Add(('NB.5-DETAIL in this pack does not record the SCM (Kudu) site minimum TLS version, so CR-04 covers the site minimum only. Recollect with CyberSOC collector {0} or later for the SCM part.' -f $scmTlsVersion)) }
            if (-not (Test-NoAppServiceSites)) { $notes.Add('NB.5-DETAIL reads the production site of each app. Deployment slots have a minimum TLS version and an SCM minimum TLS version of their own, which the pack does not read, so CR-04 does not cover them. Check both on each slot in the portal.') }
            $resources = @($rows | Where-Object { $_ -in $siteLow -or $_ -in $scmLow } | ForEach-Object {
                    $setting = 'minimum TLS ' + (Format-TlsVersion $_.MinTlsVersion)
                    if ($scmRead) { $setting += ', SCM minimum TLS ' + (Format-TlsVersion $_.ScmMinTlsVersion) }
                    New-Resource $_.Name $_.resourceGroup $_.subscriptionId $setting $_.ResourceId
                })
            $n = $resources.Count
            if (-not $n) {
                $state = if ($rows.Count) { 'Only apps without a recorded minimum remain' } else { 'No gaps found' }
                if (-not $scmRead) { $state = 'No site gaps found, the SCM part needs recollection with CyberSOC collector {0} or later' -f $scmTlsVersion }
                return @{ State = $state; Notes = $notes.ToArray() }
            }
            $s = $siteLow.Count; $k = $scmLow.Count
            $these = Get-Pick $n 'the application' 'these applications'
            $impl = [System.Collections.Generic.List[object]]::new()
            $impl.Add((Get-OpenStep $n 'App Services' 'app'))
            $impl.Add('Go to Settings > Configuration and select the General settings tab.')
            # An app whose site minimum is already 1.2 or later, or not recorded, gets only the SCM step, and the other way
            # round. A value can be raised between collection and the change, so each step reads the value first and never
            # lowers one that already shows 1.2 or later.
            $still = 'If it still shows 1.0 or 1.1, set it to 1.2. If it shows 1.2 or later, the app has changed since collection, so leave it as it is and note it in the change record.'
            if ($s -eq $n) { $impl.Add('Read Minimum Inbound TLS Version. ' + $still) }
            elseif ($s) { $impl.Add('If the RESOURCES section lists a minimum TLS below 1.2 for the app, read Minimum Inbound TLS Version. ' + $still + ' Otherwise leave it as it is.') }
            if ($k -eq $n) { $impl.Add('Read SCM Minimum Inbound TLS Version. ' + $still) }
            elseif ($k) { $impl.Add('If the RESOURCES section lists an SCM minimum TLS below 1.2 for the app, read SCM Minimum Inbound TLS Version. ' + $still + ' Otherwise leave it as it is.') }
            $impl.Add('If a setting was changed, select Apply and confirm.')
            Add-RepeatStep $impl $n 1 'app'
            $testing = @(
                ('In the Azure portal, open {0}, go to Settings > Configuration and select the General settings tab.' -f (Get-EachStep $n 'app'))
                $(if ($k) { 'Confirm Minimum Inbound TLS Version and SCM Minimum Inbound TLS Version both show 1.2 or later.' } else { 'Confirm Minimum Inbound TLS Version shows 1.2.' }))
            # Each part goes back to the value recorded before the change, never to a fixed version.
            $rollback = @(
                'In the Azure portal, open the app to revert, go to Settings > Configuration and select the General settings tab.'
                $(if ($k) { 'Set Minimum Inbound TLS Version and SCM Minimum Inbound TLS Version back to the versions recorded for the app in the RESOURCES section, only for the settings the change set to 1.2, then select Apply and confirm.' } else { 'Set Minimum Inbound TLS Version back to the version recorded for the app in the RESOURCES section, select Apply and confirm.' }))
            $email = if (-not $k) {
                New-ApprovalEmail -Subject 'minimum TLS 1.2 for Azure App Service applications' `
                    -Change @(('I would like to set the minimum inbound TLS version to 1.2 on {0}.' -f (Get-Yours $n 'App Service and Function applications')), $explainTls) `
                    -Why ('I recommend setting this minimum now because TLS 1.0 and 1.1 have known weaknesses, and App Service stops accepting them on May 31, 2027. This change makes {0} refuse them now, and matches the default for new applications.' -f $these) `
                    -Listed (Get-Pick $n 'The application is listed below with its minimum TLS version today:' 'The applications are listed below by subscription, each with its minimum TLS version today:') `
                    -Resources (Get-EmailResourceList $resources $settingLabel) `
                    -Reversal ('The minimum TLS version can be set back to the version {0} today, shown above.' -f (Get-Pick $n 'the application has' 'each application has')) `
                    -Effect ('Browsers and applications that connect over TLS 1.2 or later will see no change. A client that can only use TLS 1.0 or 1.1, for example one on an old operating system or runtime, will no longer be able to connect to {0} once the change is applied.' -f $these)
            }
            else {
                $ask = if (-not $s) { 'I would like to set the minimum inbound TLS version of the SCM site to 1.2 on {0}.' -f (Get-Yours $n 'App Service and Function applications') }
                else { 'I would like to set the minimum inbound TLS version to 1.2 on {0} and on {1}, wherever either one allows an older version today.' -f (Get-Yours $n 'App Service and Function applications'), (Get-Pick $n 'its SCM site' 'the SCM site of each') }
                New-ApprovalEmail -Subject 'minimum TLS 1.2 for Azure App Service applications and their SCM sites' `
                    -Change @($ask, $explainTls) `
                    -Why ('I recommend setting this minimum now because TLS 1.0 and 1.1 have known weaknesses, and App Service stops accepting them on May 31, 2027, on each application and on its SCM site alike. This change makes {0} refuse them now, and matches the default for new applications.' -f $these) `
                    -Effect @(
                        ('The SCM site, also called Kudu, is the deployment and management endpoint that App Service runs beside each application, which tools such as zip deploy, Web Deploy and local Git reach to upload code, stream logs and manage {0}.' -f $these)
                        ('Browsers and applications that connect over TLS 1.2 or later will see no change. A deployment tool, build agent or script that reaches the SCM site over TLS 1.0 or 1.1, for example one on an old operating system or runtime, would fail to deploy once the change is applied, {0}.' -f $(if ($s) { 'and a client that can only use TLS 1.0 or 1.1 would no longer be able to connect to the application itself' } else { 'while the application itself is not affected' }))) `
                    -Listed (Get-Pick $n 'The application is listed below with its minimum TLS versions today, for the application and for its SCM site:' 'The applications are listed below by subscription, each with its minimum TLS versions today, for the application and for its SCM site:') `
                    -Resources (Get-EmailResourceList $resources $settingLabel) `
                    -Reversal ('Each minimum TLS version the change sets can be set back to the version {0} today, shown above.' -f (Get-Pick $n 'the application has' 'each application has')) `
                    -Ask ('Could you let me know whether any deployment tool, build agent or script still reaches the SCM site of {0} over TLS 1.0 or 1.1? With that confirmed, could you approve this change for {1}?' -f $these, $proposedDay) `
                    -Options ('If one still does, I will hold the SCM part of the change for {0} until it is updated. If another date suits you better, or anything listed above should stay out of the change, please let me know.' -f (Get-Pick $n 'the application' 'that application'))
            }
            @{ Notes = $notes.ToArray(); Cr = New-ChangeRequest @{
                    Number = 4; Key = 'app-service-minimum-tls'; Title = 'Set minimum inbound TLS version 1.2 on App Service apps'
                    Description = $(if (-not $k) { 'Set the minimum inbound TLS version to 1.2 on {0}.' -f (Get-Listed $n 'App Service app' 'App Service and Function apps') }
                        elseif (-not $s) { 'Set the SCM (Kudu) site minimum inbound TLS version to 1.2 on {0}.' -f (Get-Listed $n 'App Service app' 'App Service and Function apps') }
                        else { 'Set the minimum inbound TLS version and the SCM (Kudu) site minimum inbound TLS version to 1.2 on {0}, each where it is below 1.2.' -f (Get-Listed $n 'App Service app' 'App Service and Function apps') })
                    Purpose = $(if ($k) { 'TLS 1.0 and 1.1 have known weaknesses, and App Service stops accepting them on May 31, 2027, on the app endpoint and on the SCM (Kudu) endpoint used for deployments. Setting 1.2 on both now refuses these older protocols and matches the default for new apps.' }
                        else { 'TLS 1.0 and 1.1 have known weaknesses, and App Service stops accepting them on May 31, 2027. Setting 1.2 now refuses these older protocols and matches the default for new apps.' })
                    ResourceIntro = $(if ($scmRead) { '{0} with the minimum TLS versions {1} today, for the site and for its SCM site.' -f $(if ($n -eq 1) { 'The app below is listed' } else { "The $n apps below are listed" }), (Get-Pick $n 'it allows' 'each one allows') }
                        else { '{0} with the minimum TLS version {1} today.' -f $(if ($n -eq 1) { 'The app below is listed' } else { "The $n apps below are listed" }), (Get-Pick $n 'it allows' 'each one allows') })
                    ResourceLines = Format-ResourceList $resources
                    Availability = 'No downtime expected while the setting is applied.'
                    UserExperience = 'No change for browsers and clients that use TLS 1.2 or later.'
                    Dependencies = $(if ($k) { 'Clients and deployment tools limited to TLS 1.0 or 1.1 can no longer connect to the site or its SCM site once the change is applied.' } else { 'Clients limited to TLS 1.0 or 1.1 can no longer connect once the change is applied.' })
                    Implementation = $impl.ToArray()
                    Testing = $testing
                    Rollback = $rollback
                    References = @(
                        , @('Set the minimum TLS version for App Service', 'https://learn.microsoft.com/azure/app-service/tls-minimum-version')
                        , @('Transport Layer Security in Azure App Service', 'https://learn.microsoft.com/azure/app-service/overview-tls')
                        if ($k) { , @('Kudu service overview', 'https://learn.microsoft.com/azure/app-service/resources-kudu') })
                    Csv = $resources
                    Email = $email
                } } } }

    @{ Number = 5; Key = 'sql-minimum-tls'; Change = 'Minimum TLS 1.2 on Azure SQL servers'; Sources = @('NB.6-DETAIL')
       Build = {
            $resources = @(Get-Rows 'NB.6-DETAIL' | ForEach-Object { New-Resource $_.Name $_.resourceGroup $_.subscriptionId ('minimum TLS ' + (Format-TlsVersion $_.MinimalTlsVersion)) $_.ResourceId })
            $n = $resources.Count
            if (-not $n) { return @{ State = 'No gaps found' } }
            $impl = [System.Collections.Generic.List[object]]::new()
            $impl.Add((Get-OpenStep $n 'SQL servers' 'server'))
            $impl.Add('Go to Security > Networking and select the Connectivity tab.')
            $impl.Add('Set Minimum TLS Version to 1.2 and select Save.')
            Add-RepeatStep $impl $n 1 'server'
            @{ Cr = New-ChangeRequest @{
                    Number = 5; Key = 'sql-minimum-tls'; Title = 'Set minimum TLS version 1.2 on Azure SQL servers'
                    Description = 'Set the minimum TLS version to 1.2 on {0}.' -f (Get-Listed $n 'Azure SQL logical server' 'Azure SQL logical servers')
                    Purpose = 'Azure SQL retired TLS 1.0 and 1.1 on August 31, 2025, but {0} not enforce a minimum of 1.2 in {1} configuration. Setting 1.2 brings the configuration in line with the platform and the security baseline.' -f (Get-Pick $n 'this server does' 'these servers do'), (Get-Pick $n 'its' 'their')
                    ResourceIntro = '{0} with the minimum TLS version {1} today.' -f $(if ($n -eq 1) { 'The server below is listed' } else { "The $n servers below are listed" }), (Get-Pick $n 'it enforces' 'each one enforces')
                    ResourceLines = Format-ResourceList $resources
                    Availability = 'No impact, since Azure SQL already refuses TLS 1.0 and 1.1 and connections that work today keep working.'
                    UserExperience = 'No change for users or applications.'
                    Dependencies = 'None, since every client that connects today already uses TLS 1.2 or later.'
                    Implementation = $impl.ToArray()
                    Testing = @(
                        ('In the Azure portal, open {0}, go to Security > Networking and select the Connectivity tab.' -f (Get-EachStep $n 'server'))
                        'Confirm Minimum TLS Version shows 1.2.')
                    Rollback = @(
                        'No rollback is available or needed, because once a minimum is set Azure SQL does not allow a return to the unset default or a minimum below 1.2.'
                        'TLS 1.0 and 1.1 were retired across Azure SQL on August 31, 2025, so every client that connected before the change can still connect.')
                    References = @(, @('Connectivity settings for Azure SQL Database, minimum TLS version', 'https://learn.microsoft.com/azure/azure-sql/database/connectivity-settings#minimum-tls-version'))
                    Csv = $resources
                    Email = New-ApprovalEmail -Subject 'minimum TLS 1.2 for Azure SQL servers' `
                        -Change @(('I would like to set the minimum TLS version to 1.2 on {0}.' -f (Get-Yours $n 'Azure SQL logical servers')), $explainTls) `
                        -Why ('I recommend setting this minimum because TLS 1.0 and 1.1 have known weaknesses. Azure SQL retired them on August 31, 2025, but {0} not enforce a minimum of 1.2 in {1} configuration, so this change brings the configuration in line with the platform and the security baseline.' -f (Get-Pick $n 'this server does' 'these servers do'), (Get-Pick $n 'its' 'their')) `
                        -Listed (Get-Pick $n 'The server is listed below with its minimum TLS version today:' 'The servers are listed below by subscription, each with its minimum TLS version today:') `
                        -Resources (Get-EmailResourceList $resources $settingLabel) `
                        -Reversal 'Once a minimum is set, Azure SQL does not allow a return to the unset default or a minimum below 1.2, so this change cannot be reversed. I do not expect a reversal to be needed, because every client that connects today already uses TLS 1.2 or later.' `
                        -Effect 'I do not expect any visible effect, because Azure SQL no longer accepts TLS 1.0 and 1.1, so every connection that works today keeps working.'
                } } } }

    @{ Number = 6; Key = 'key-vault-purge-protection'; Change = 'Purge protection on key vaults'; Sources = @('DP.2-DETAIL')
       Build = {
            $resources = @(Get-Rows 'DP.2-DETAIL' | ForEach-Object {
                    $days = Get-Number $_.RetentionDays; if (-not $days) { $days = 90 }
                    New-Resource $_.Name $_.resourceGroup $_.subscriptionId ('soft delete retention {0} days' -f $days) $_.ResourceId })
            $n = $resources.Count
            if (-not $n) { return @{ State = 'No gaps found' } }
            $impl = [System.Collections.Generic.List[object]]::new()
            $impl.Add((Get-OpenStep $n 'Key vaults' 'key vault'))
            $impl.Add('Go to Settings > Properties.')
            $impl.Add('Under Purge protection, select Enable purge protection and select Save.')
            Add-RepeatStep $impl $n 1 'key vault'
            # Purge protection cannot be undone, so the client approves it in writing first. When the approval
            # was given at build kickoff, the email refers to it and asks the client to confirm it still stands.
            $notes = @()
            $theVaults = Get-Pick $n 'the vault' 'these vaults'
            $ask = ('Because this change cannot be undone, I need your written approval before I schedule it. Could you approve purge protection on {0} for {1}?' -f (Get-Pick $n 'this vault' 'these vaults'), $proposedDay)
            if ($PurgeProtectionApproved) {
                $notes = @('CR-06 refers to the purge protection approval the client gave at build kickoff (-PurgeProtectionApproved), and asks the client to confirm that it still stands and to approve the proposed date. Attach that approval and the reply to the change request.')
                $ask = ('You approved purge protection at the build kickoff. Because this change cannot be undone, could you confirm that your approval still stands for {0}, and approve the change for {1}?' -f (Get-Pick $n 'this vault' 'these vaults'), $proposedDay)
            }
            $email = New-ApprovalEmail -Subject 'purge protection for Azure key vaults' `
                -Change @(('I would like to turn on purge protection for {0}.' -f (Get-Yours $n 'Azure key vaults')), 'With it on, a deleted vault, key, secret or certificate cannot be purged, that is erased for good, before the retention period of its vault ends.') `
                -Why 'I recommend turning on purge protection because, without it, anyone with enough access, including an attacker who takes over an account, can delete a vault or its keys, secrets and certificates and purge them straight away, so they cannot be recovered. Purge protection keeps them recoverable for the retention period after an accidental or malicious deletion.' `
                -Effect @(
                    ('Nothing changes for the applications and people that read or write {0} today.' -f $theVaults)
                    ('Once it is on, a deleted vault, key, secret or certificate is kept for the retention period of its vault and cannot be purged early. It can be recovered at any time during that period, and Azure purges it automatically when the period ends. A deleted vault keeps its name until then, so the name cannot be reused, for example by automation that deletes and recreates a vault, and a deleted key, secret or certificate keeps its name in {0} in the same way.' -f (Get-Pick $n 'the vault' 'its vault'))) `
                -Listed (Get-Pick $n 'The vault is listed below with its soft delete retention period, which purge protection will enforce:' 'The vaults are listed below by subscription, each with its soft delete retention period, which purge protection will enforce:') `
                -Resources (Get-EmailResourceList $resources $settingLabel) `
                -Reversal 'This change cannot be undone. Purge protection cannot be turned off once it is enabled, by anyone including Microsoft, and the retention period of a vault is set when the vault is created and cannot be changed afterwards either.' `
                -Ask $ask -Options 'If a vault should stay out of the change, or another date suits you better, please let me know.'
            @{ Notes = $notes; Cr = New-ChangeRequest @{
                    Number = 6; Key = 'key-vault-purge-protection'; Title = 'Enable purge protection on key vaults'
                    Description = 'Enable purge protection on {0}.' -f (Get-Listed $n 'key vault' 'key vaults')
                    Purpose = 'Without purge protection, a deleted vault, key, secret or certificate can be purged for good before its retention period ends. Purge protection enforces that period, so deleted items stay recoverable after an accidental or malicious deletion.'
                    ResourceIntro = '{0} with the soft delete retention period that purge protection will enforce.' -f $(if ($n -eq 1) { 'The key vault below is listed' } else { "The $n key vaults below are listed" })
                    ResourceLines = Format-ResourceList $resources
                    Availability = 'No impact, since the setting changes deletion behavior only and does not affect vault operations.'
                    UserExperience = 'No change for the applications and users that read or write vault objects.'
                    Dependencies = 'A deleted vault keeps its name reserved until its retention period ends, which affects automation that recreates a vault under the same name.'
                    Mitigation = 'Purge protection cannot be disabled once it is enabled, so this change cannot be reverted. Deleted vaults and objects stay recoverable for each vault''s retention period, after which Azure purges them automatically.'
                    Implementation = $impl.ToArray()
                    Testing = @(
                        ('In the Azure portal, open {0} and go to Settings > Properties.' -f (Get-EachStep $n 'key vault'))
                        'Confirm Enable purge protection is selected under Purge protection.')
                    Rollback = @(
                        'No rollback is possible, because purge protection cannot be disabled once it is enabled, by anyone including Microsoft.'
                        'If a vault is deleted by mistake, recover it within its retention period from Key vaults > Manage deleted vaults by selecting the vault and selecting Recover.')
                    References = @(
                        , @('Azure Key Vault soft-delete overview, purge protection', 'https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview#purge-protection')
                        , @('Azure Key Vault recovery management with soft delete and purge protection', 'https://learn.microsoft.com/azure/key-vault/general/key-vault-recovery'))
                    Csv = $resources
                    Email = $email
                } } } }

    @{ Number = 7; Key = 'storage-anonymous-access'; Change = 'Anonymous blob access disabled on storage accounts'; Sources = @('DP.1-DETAIL')
       Build = {
            # Turning the account setting off stops every anonymous read, so CR-07 takes only the accounts whose
            # containers DP.1-CONTAINERS listed in full, with none set to Blob or Container access. The index names
            # the others: an account with a public container waits until its containers are private, and an account
            # whose containers were not listed waits for a pack that lists them.
            $containersStatus = Get-Status 'DP.1-CONTAINERS'
            $containersRead = $containersStatus -in 'OK', 'PARTIAL', 'EMPTY' -and -not (Test-Unreadable 'DP.1-CONTAINERS')
            $containers = @{}
            if ($containersRead) { foreach ($c in @(Get-Rows 'DP.1-CONTAINERS')) { $containers[(Get-Text $c.ResourceId).ToLowerInvariant()] = $c } }
            $public = [System.Collections.Generic.List[string]]::new()
            # CR-18 leaves the static website container ($web) out, so an account whose only public container is
            # $web gets a note of its own pointing to the separate change the CR-18 notes describe.
            $webOnly = [System.Collections.Generic.List[string]]::new()
            $unlisted = [System.Collections.Generic.List[string]]::new()
            $failed = [System.Collections.Generic.List[string]]::new()
            # A FileStorage account holds no blob service, so the setting does not apply to it.
            $resources = @(foreach ($a in @(Get-Rows 'DP.1-DETAIL' | Where-Object { (Test-True $_.AllowBlobPublicAccess) -and (Get-Text $_.Kind) -ine 'FileStorage' })) {
                    $c = $containers[(Get-Text $a.ResourceId).ToLowerInvariant()]
                    $label = '{0} (resource group {1})' -f (ConvertTo-CopyText $a.Name), (ConvertTo-CopyText $a.resourceGroup)
                    # A row without a whole number of public containers cannot show the account is safe to change.
                    if ($null -eq $c -or (Get-Text $c.PublicContainers) -notmatch '^\d+$') { $unlisted.Add($label); continue }
                    if ((Get-Text $c.ReadStatus) -ne 'OK') { $failed.Add($label); continue }
                    if ((Get-Number $c.PublicContainers) -gt 0 -or (Get-Text $c.PublicContainerNames)) {
                        $names = ConvertTo-CopyText $c.PublicContainerNames
                        if ((Get-Number $c.PublicContainers) -le 1 -and $names -match '^\$web \((Blob|Container)\)$') { $webOnly.Add(('{0}: {1}' -f $label, $names)) }
                        else { $public.Add(('{0}: {1}' -f $label, $names)) }
                        continue
                    }
                    $count = Get-Number $c.Containers
                    New-Resource $a.Name $a.resourceGroup $a.subscriptionId $(if ($count -eq 1) { '1 container, private' } elseif ($count) { "$count containers, all private" } else { 'no containers' }) $a.ResourceId
                })
            $notes = [System.Collections.Generic.List[string]]::new()
            if ($public.Count) {
                $notes.Add(('{0} left out of CR-07 because {1} a container set to Blob or Container access, which anyone can read today without signing in: {2}. Turning the account setting off would stop those anonymous reads, so CR-18 asks the owner of each container to confirm first that it serves no public content, and sets the container to private.{3} A later pack picks each account up for CR-07 once every container in it is private.' -f (Get-Count $public.Count 'storage account' 'storage accounts'), (Get-Pick $public.Count 'it has' 'each has'), ($public -join ' / '), $(if (@($public | Where-Object { $_ -match '\$web \(' }).Count) { ' CR-18 leaves out the static website container ($web), which is set to Private on its own, as the CR-18 notes say.' } else { '' })))
            }
            if ($webOnly.Count) {
                $notes.Add(('{0} left out of CR-07 because {1} only public container is the static website container ($web), set to Blob or Container access: {2}. CR-18 does not change $web, since the site is served from the web endpoint whatever its level. Set $web to Private on its own, as the CR-18 notes say, once the owner confirms nothing links to the blob endpoint addresses of the site, and a later pack picks {3} up for CR-07.' -f (Get-Count $webOnly.Count 'storage account' 'storage accounts'), (Get-Pick $webOnly.Count 'its' 'their'), ($webOnly -join ' / '), (Get-Pick $webOnly.Count 'the account' 'each account')))
            }
            if ($unlisted.Count) {
                $why = if ($containersRead) { 'DP.1-CONTAINERS did not list {0} containers' -f (Get-Pick $unlisted.Count 'its' 'their') }
                elseif ($containersStatus -eq 'MISSING') { '{0} containers were not read, since DP.1-CONTAINERS was not collected' -f (Get-Pick $unlisted.Count 'its' 'their') }
                elseif (Test-Unreadable 'DP.1-CONTAINERS') { '{0} containers were not read, since the DP.1-CONTAINERS result file is unreadable' -f (Get-Pick $unlisted.Count 'its' 'their') }
                else { '{0} containers were not read, since DP.1-CONTAINERS reads {1}' -f (Get-Pick $unlisted.Count 'its' 'their'), $containersStatus }
                $notes.Add(('{0} left out of CR-07 because {1}: {2}. Without the container list it cannot be shown that turning the setting off is safe, so recollect the pack.' -f (Get-Count $unlisted.Count 'storage account' 'storage accounts'), $why, ($unlisted -join ', ')))
            }
            if ($failed.Count) {
                $notes.Add(('{0} left out of CR-07 because DP.1-CONTAINERS reads {1} and could not list {2} containers: {3}. Only an account whose containers were all listed can qualify, so recollect the pack.' -f (Get-Count $failed.Count 'storage account' 'storage accounts'), $containersStatus, (Get-Pick $failed.Count 'its' 'their'), ($failed -join ', ')))
            }
            $n = $resources.Count
            if (-not $n) { return @{ State = 'No gaps found'; Notes = $notes.ToArray() } }
            # A container can be made public between collection and the change, so each account is checked again
            # before Save and left unchanged if any container reads Blob or Container.
            $impl = [System.Collections.Generic.List[object]]::new()
            $impl.Add((Get-OpenStep $n 'Storage accounts' 'storage account'))
            $impl.Add('Go to Data storage > Containers and confirm the Anonymous access level of every container reads Private.')
            $impl.Add('If any container reads Blob or Container, stop here and leave the account unchanged, and note it in the change record for the next pack.')
            $impl.Add('Go to Settings > Configuration.')
            $impl.Add('Set Allow Blob anonymous access to Disabled and select Save.')
            Add-RepeatStep $impl $n 1 'storage account'
            $email = New-ApprovalEmail -Subject 'turning off anonymous access to Azure Blob Storage' `
                -Change @(('I would like to turn off anonymous access to Azure Blob Storage at the account level on {0}.' -f (Get-Yours $n 'storage accounts')), 'Anonymous access lets anyone read a container over the internet without signing in.') `
                -Why ('I recommend turning anonymous access off because the account setting still allows a container to be made public today. Turning it off means no container in {0} can be opened to anonymous access later, by mistake or by a misconfigured deployment.' -f (Get-Pick $n 'it' 'them')) `
                -Effect @(
                    ('I do not expect this change to affect anything that uses {0} today, for these reasons:' -f (Get-Pick $n 'the account' 'these accounts'))
                    , @(
                        ('Every container in {0} is private today, so no one reads {1} blob data without signing in.' -f (Get-Pick $n 'the account' 'these accounts'), (Get-Pick $n 'its' 'their'))
                        'Applications and people that sign in, or that use a shared access signature or an account key, keep working as they do now. The setting only affects requests made without any credentials.'
                        'A static website hosted in a storage account keeps serving as it does now, since the setting does not apply to it.'
                        (Get-Pick $n 'Just before the change, I will check the containers of the account again, and leave it unchanged if a container has been made public since my review.' 'Just before the change, I will check the containers of each account again, and skip any account where a container has been made public since my review.'))) `
                -Listed (Get-Pick $n 'The account is listed below:' 'The accounts are listed below by subscription:') `
                -Resources (Get-EmailResourceList $resources $groupLabel) `
                -Reversal 'If anything unexpected comes up, I can turn the setting back on straight away. It takes up to 30 seconds to apply, and the containers stay as they are.'
            @{ Used = @('DP.1-CONTAINERS'); Notes = $notes.ToArray(); Cr = New-ChangeRequest @{
                    Number = 7; Key = 'storage-anonymous-access'; Title = 'Disable anonymous blob access on storage accounts'
                    Description = 'Set Allow Blob anonymous access to Disabled on {0}, none of which has a container open to anonymous access.' -f (Get-Listed $n 'storage account' 'storage accounts')
                    Purpose = 'Turning the setting off stops a container being opened to anonymous access later, by mistake or by a misconfigured deployment. No container in {0} is open to anonymous access today.' -f (Get-Pick $n 'this account' 'these accounts')
                    ResourceIntro = '{0} anonymous blob access, with the containers listed at collection. No container in {1} is set to Blob or Container access.' -f $(if ($n -eq 1) { 'The storage account below allows' } else { "The $n storage accounts below allow" }), (Get-Pick $n 'it' 'them')
                    ResourceLines = Format-ResourceList $resources
                    Availability = 'No impact on the storage service, since authorized requests are unaffected.'
                    UserExperience = 'No change, since no container in {0} allows anonymous access and a static website hosted in a storage account is not affected by the setting.' -f (Get-Pick $n 'this account' 'these accounts')
                    Dependencies = 'None, since access through Microsoft Entra ID, shared access signatures or account keys is unaffected.'
                    Implementation = $impl.ToArray()
                    Testing = @(
                        ('In the Azure portal, open {0} and go to Settings > Configuration.' -f (Get-EachStep $n 'storage account'))
                        'Confirm Allow Blob anonymous access shows Disabled.')
                    Rollback = @(
                        'In the Azure portal, open the storage account to revert and go to Settings > Configuration.'
                        'Set Allow Blob anonymous access to Enabled and select Save. The setting takes up to 30 seconds to apply, and the containers keep their Private access level, so nothing else changes.')
                    References = @(
                        , @('Remediate anonymous read access to blob data', 'https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent')
                        , @('Configure anonymous read access for containers and blobs', 'https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-configure'))
                    Csv = $resources
                    Email = $email
                } } } }

    @{ Number = 8; Key = 'app-service-https-only'; Change = 'HTTPS Only on App Service apps'; Sources = @('NB.4-DETAIL')
       Build = {
            $rows = @(Get-Rows 'NB.4-DETAIL')
            $resources = @($rows | ForEach-Object { New-Resource $_.Name $_.resourceGroup $_.subscriptionId (Get-Text $_.DefaultHostName) $_.ResourceId })
            $n = $resources.Count
            if (-not $n) { return @{ State = 'No gaps found' } }
            $impl = [System.Collections.Generic.List[object]]::new()
            $impl.Add((Get-OpenStep $n 'App Services' 'app'))
            $impl.Add('Go to Settings > Configuration and select the General settings tab.')
            $impl.Add('Under Platform settings, set HTTPS Only to On, select Apply and confirm.')
            Add-RepeatStep $impl $n 1 'app'
            @{ Cr = New-ChangeRequest @{
                    Number = 8; Key = 'app-service-https-only'; Title = 'Enable HTTPS Only on App Service apps'
                    Description = 'Turn on HTTPS Only for {0}, so requests over HTTP are redirected to HTTPS.' -f (Get-Listed $n 'App Service app' 'App Service and Function apps')
                    Purpose = 'Traffic over plain HTTP travels unencrypted and can be read or altered on the way. HTTPS Only redirects it to HTTPS, so every request is encrypted in transit.'
                    ResourceIntro = '{0} HTTP, with the default host name of each.' -f $(if ($n -eq 1) { 'The app below still accepts' } else { "The $n apps below still accept" })
                    ResourceLines = Format-ResourceList $resources
                    Availability = 'No impact, since the apps stay online and the setting takes effect without a redeployment.'
                    UserExperience = 'Browsers follow the redirect to HTTPS automatically, so users see no change.'
                    Dependencies = 'Integrations that call an app over HTTP and do not follow redirects need to switch to HTTPS.'
                    Implementation = $impl.ToArray()
                    Testing = @(
                        ('In the Azure portal, open {0}, go to Settings > Configuration and select the General settings tab.' -f (Get-EachStep $n 'app'))
                        'Confirm HTTPS Only shows On under Platform settings.')
                    Rollback = @(
                        'In the Azure portal, open the app to revert, go to Settings > Configuration and select the General settings tab.'
                        'Set HTTPS Only to Off, select Apply and confirm.')
                    References = @(
                        , @('Configure an App Service app, general settings', 'https://learn.microsoft.com/azure/app-service/configure-common#configure-general-settings')
                        , @('Secure your Azure App Service deployment, data protection', 'https://learn.microsoft.com/azure/app-service/overview-security#data-protection'))
                    Csv = $resources
                    Email = New-ApprovalEmail -Subject 'HTTPS only for Azure App Service applications' `
                        -Change @(('I would like to turn on the HTTPS Only setting for {0}.' -f (Get-Yours $n 'App Service and Function applications')), 'With it on, requests made over plain HTTP are redirected to HTTPS, the encrypted form of HTTP.') `
                        -Why ('I recommend turning on HTTPS Only because traffic over plain HTTP travels unencrypted and can be read or altered on the way. The setting makes sure every request to {0} is encrypted in transit.' -f (Get-Pick $n 'the application' 'these applications')) `
                        -Effect ('Browsers follow the redirect automatically, so people using {0} should not notice a difference. An integration that calls {1} over http:// and does not follow redirects, such as an older API client or a webhook, may fail until it is updated to use https://.' -f (Get-Pick $n 'the application' 'these applications'), (Get-Pick $n 'it' 'one of them')) `
                        -Listed (Get-Pick $n 'The application is listed below with its default host name:' 'The applications are listed below by subscription, each with its default host name:') `
                        -Resources (Get-EmailResourceList $resources { if ($_.Setting) { '{0} (resource group {1}, {2})' -f $_.Name, $_.ResourceGroup, $_.Setting } else { '{0} (resource group {1})' -f $_.Name, $_.ResourceGroup } }) `
                        -Reversal ('HTTPS Only can be turned off again on {0}, and it takes effect without a redeployment.' -f (Get-Pick $n 'the application' 'any application')) `
                        -Ask ('Could you let me know whether any of your systems or partners still call {0} over HTTP? If none do, could you approve this change for {1}?' -f (Get-Pick $n 'the application' 'these applications'), $proposedDay) `
                        -Options 'If one does, I will hold the change until it uses HTTPS. If another date suits you better, or anything listed above should stay out of the change, please let me know.'
                } } } }

    @{ Number = 9; Key = 'encryption-at-host'; Change = 'Encryption at host on virtual machines'; Sources = @('DP.4-ELIGIBILITY')
       Build = {
            # DP.4-ELIGIBILITY lists the virtual machines without encryption at host and whether each can
            # take it. A machine that used Azure Disk Encryption, runs on a size without support, or whose
            # size support was not read would be deallocated for a change Azure then rejects, so only the
            # eligible ones are listed.
            $rows = @(Get-Rows 'DP.4-ELIGIBILITY')
            # A pack from collector 1.3.0 names the scale set of each machine, and the instances of a Flexible
            # scale set that CR-15 takes are changed with it there. Those of a scale set CR-15 leaves out stay
            # here, and an older pack keeps every machine here, as before.
            $notes = [System.Collections.Generic.List[string]]::new()
            $used = @()
            if ($rows.Count -and $rows[0].PSObject.Properties.Name -contains 'ScaleSet') {
                $used = @('DP.4-VMSS-ELIGIBILITY')
                $flexible = @(Get-EligibleScaleSetModels | Where-Object { (Get-Text $_.OrchestrationMode) -ieq 'Flexible' })
                $models = @{}
                foreach ($f in $flexible) { $models[(Get-Text $f.ResourceId).ToLowerInvariant()] = ConvertTo-CopyText $f.Name }
                $taken = (Test-FlexibleScaleSets $flexible).Qualified
                $members = @($rows | Where-Object { $taken.ContainsKey((Get-ScaleSetText $_.ScaleSet)) })
                if ($members.Count) {
                    $notes.Add(('{0} left out of CR-09 because {1} to a Flexible scale set that CR-15 changes, so CR-15 handles {2} with {3} scale set: {4}.' -f (Get-Count $members.Count 'virtual machine' 'virtual machines'), (Get-Pick $members.Count 'it belongs' 'they belong'), (Get-Pick $members.Count 'it' 'them'), (Get-Pick $members.Count 'its' 'their'),
                            (@($members | Sort-Object Name | ForEach-Object { '{0} ({1})' -f (ConvertTo-CopyText $_.Name), $models[(Get-ScaleSetText $_.ScaleSet)] }) -join ', ')))
                    $rows = @($rows | Where-Object { $_ -notin $members })
                }
            }
            $ineligible = @($rows | Where-Object { -not (Test-True $_.Eligible) })
            if ($ineligible.Count) {
                $notes.Add(('{0} left out of CR-09 because {1} encryption at host as {2}: {3}.' -f (Get-Count $ineligible.Count 'virtual machine' 'virtual machines'), (Get-Pick $ineligible.Count 'it cannot take' 'they cannot take'), (Get-Pick $ineligible.Count 'it stands' 'they stand'),
                        (@($ineligible | Sort-Object Name | ForEach-Object { '{0} ({1}, {2})' -f (ConvertTo-CopyText $_.Name), (ConvertTo-CopyText $_.Size), ((ConvertTo-CopyText $_.Reason) -replace '^(size support not read):.*$', '$1') }) -join ', ')))
            }
            # Each machine is matched by its VM ID before it is stopped. A pack from before collector 1.4.0 has
            # no VM ID, so it cannot tell the machine that was checked from one created again under its name.
            $eligible = @($rows | Where-Object { Test-True $_.Eligible })
            if ($eligible.Count -and $eligible[0].PSObject.Properties.Name -notcontains 'VmId') { return @{ State = $needsIdRecollection; Notes = $notes.ToArray() } }
            $unnamed = @($eligible | Where-Object { -not (Get-VmId $_) })
            if ($unnamed.Count) {
                $notes.Add(('{0} left out of CR-09 because {1} VM ID was not read, so {2} cannot be told from a machine created again under the same name: {3}.' -f (Get-Count $unnamed.Count 'virtual machine' 'virtual machines'), (Get-Pick $unnamed.Count 'its' 'their'), (Get-Pick $unnamed.Count 'it' 'they'), (@($unnamed | Sort-Object Name | ForEach-Object { ConvertTo-CopyText $_.Name }) -join ', ')))
            }
            $resources = @($eligible | Where-Object { $_ -notin $unnamed } | ForEach-Object { New-Resource $_.Name $_.resourceGroup $_.subscriptionId ('size {0}, {1}, VM ID {2}' -f (Get-Text $_.Size), (Get-PowerText $_.PowerState), (Get-VmId $_)) $_.ResourceId })
            $n = $resources.Count
            if (-not $n) { return @{ State = $(if ($rows.Count) { 'No eligible virtual machines' } else { 'No gaps found' }); Notes = $notes.ToArray() } }
            $notes.Add('CR-09 changes a virtual machine only when the VM ID that Overview > JSON View shows matches the VM ID listed for it. A machine whose VM ID differs was deleted and created again under the same name after collection and was never checked, so it is skipped and left for the next pack.')
            $impl = [System.Collections.Generic.List[object]]::new()
            foreach ($step in New-EncryptionAtHostRegistration $resources) { $impl.Add($step) }
            $impl.Add((Get-OpenStep $n 'Virtual machines' 'virtual machine'))
            $impl.Add('On Overview, select JSON View and confirm properties.vmId reads the VM ID listed for the machine in the RESOURCES section. If it reads another ID, the machine was created again under the same name after collection and was never checked, so leave it unchanged for the next pack and skip the remaining steps for it.')
            $impl.Add('On Overview, note whether the status reads Running, then select Stop and wait for the status to read Stopped (deallocated).')
            $impl.Add('Go to Settings > Disks > Additional settings, set Encryption at host to Yes and select Save.')
            $impl.Add('Go back to Overview and select Start only if the status read Running before the stop, so a machine that was not running stays stopped.')
            Add-RepeatStep $impl $n 3 'virtual machine'
            $references = @(
                , @('Use the Azure portal to enable end-to-end encryption using encryption at host', 'https://learn.microsoft.com/azure/virtual-machines/disks-enable-host-based-encryption-portal')
                , @('Overview of managed disk encryption options, encryption at host', 'https://learn.microsoft.com/azure/virtual-machines/disk-encryption#encryption-at-host---end-to-end-encryption-for-your-vm-data'))
            $spec = @{
                Number = 9; Key = 'encryption-at-host'; Title = 'Enable encryption at host on virtual machines'
                Description = 'Enable encryption at host on {0}, which needs a stop and start of each machine.' -f (Get-Listed $n 'virtual machine' 'virtual machines')
                Purpose = 'Encryption at host encrypts the temporary disk and the OS and data disk caches on the Azure host, so the data of each machine is encrypted from end to end. Platform encryption covers only the managed disks at rest, which leaves these paths unencrypted today.'
                ResourceIntro = $(if ($n -eq 1) { 'The virtual machine below is listed with its size, power state and VM ID at collection. It is changed only if its VM ID still matches, and it is returned to the power state it has when the change is made.' } else { "The $n virtual machines below are listed with the size, power state and VM ID of each at collection. Each machine is changed only if its VM ID still matches, and it is returned to the power state it has when the change is made." })
                ResourceLines = Format-ResourceList $resources
                Availability = 'Each virtual machine is unavailable for a few minutes while it is stopped and started inside the agreed maintenance window.'
                UserExperience = 'Users of each server lose access during its restart and see no change afterwards.'
                Dependencies = 'Needs the EncryptionAtHost feature on each subscription, a VM size that supports it and a machine that never used Azure Disk Encryption.'
                Implementation = $impl.ToArray()
                Testing = @(
                    ('In the Azure portal, open {0} whose VM ID matched and go to Settings > Disks > Additional settings.' -f (Get-EachStep $n 'virtual machine'))
                    'Confirm Encryption at host shows Yes.'
                    (Get-Pick $n 'On Overview, confirm the machine shows Running if it was running before the change.' 'On Overview, confirm each machine that was running before the change shows Running.'))
                Rollback = @(
                    'In the Azure portal, open the virtual machine to revert, note on Overview whether the status reads Running, then select Stop and wait for the status to read Stopped (deallocated).'
                    'Go to Settings > Disks > Additional settings, set Encryption at host to No and select Save.'
                    'Go back to Overview and select Start only if the status read Running before the stop.')
                References = $references
                Csv = $resources
                Email = New-ApprovalEmail -Window -Subject 'encryption at host for Azure virtual machines' `
                    -Change @(('I would like to enable encryption at host on {0}.' -f (Get-Yours $n 'virtual machines')), 'Encryption at host encrypts the temporary disk and the disk caches on the Azure host, the physical server a virtual machine runs on.') `
                    -Why ('I recommend enabling encryption at host because Azure already encrypts the managed disks of {0} at rest, but not the temporary disk or the disk caches. Encryption at host closes that gap, so the data on {0} stays encrypted from the virtual machine all the way to Azure Storage.' -f (Get-Pick $n 'this server' 'these servers')) `
                    -Effect @(
                        (Get-Pick $n 'To apply it, the virtual machine has to be stopped first. If it is running at the time, it will be unavailable for a few minutes until I start it again, and if it is already stopped, it will be left stopped. Nothing changes inside the operating system or the applications.' 'To apply it, each virtual machine has to be stopped first. A server that is running at the time will be unavailable for a few minutes until I start it again, and a server that is already stopped will be left stopped. Nothing changes inside the operating system or the applications.')
                        'Because of that restart, I am asking for a maintenance window rather than proposing a date.') `
                    -Listed (Get-Pick $n 'The virtual machine is listed below:' 'The virtual machines are listed below by subscription:') `
                    -Resources (Get-EmailResourceList $resources {
                            $state = switch -Regex ($_.Setting) { ', running,' { ', running at my last review' } ', (deallocated|stopped),' { ', stopped at my last review' } default { '' } }
                            '{0} (resource group {1}{2})' -f $_.Name, $_.ResourceGroup, $state }) `
                    -Reversal ('Encryption at host can be turned off again, which needs the same stop and start of {0} inside a maintenance window.' -f (Get-Pick $n 'the virtual machine' 'each virtual machine')) `
                    -Ask (Get-Pick $n 'Could you approve this change and suggest a maintenance window that works for this server?' 'Could you approve this change and suggest a maintenance window that works for these servers?') `
                    -Options (Get-Pick $n '' 'If any of them need to be handled separately or in a particular order, please let me know.')
            }
            if ($DrClient) {
                $spec.DrImpact = 'This is a DR client. Azure Site Recovery does not carry encryption at host to test failover or failover virtual machines, so the DR Playbook needs an update.'
                $spec.DrPlan = @(
                    'In the DR Playbook, add a post-failover step for the virtual machines listed in this change.'
                    'The step notes whether each failed over virtual machine reads Running, stops it, sets Encryption at host to Yes under Settings > Disks > Additional settings, selects Save, and starts it again only if it was running before the stop.'
                    'Attach the link to the updated DR Playbook, or a screenshot of the new step, to this change request before it is closed.')
                $spec.References = $references + , @('Support matrix for Azure VM disaster recovery, replicated machines storage', 'https://learn.microsoft.com/azure/site-recovery/azure-to-azure-support-matrix#replicated-machines---storage')
            }
            @{ Used = $used; Notes = $notes.ToArray(); Cr = New-ChangeRequest $spec } } }

    @{ Number = 10; Key = 'diagnostic-remediation'; Change = 'Diagnostic logging remediated on non-compliant resources'; Sources = @('DR.6-INITIATIVE')
       Build = {
            $initiative = @(Get-Rows 'DR.6-INITIATIVE')
            if ((Get-Status 'DR.6-INITIATIVE') -eq 'EMPTY' -or $initiative.Count -eq 0) { return @{ State = 'Nothing to remediate until the initiative is assigned (CR-01)' } }
            $nonCompliant = 0
            foreach ($r in $initiative) { $nonCompliant += Get-Number $r.NonCompliant }
            if ($nonCompliant -eq 0) { return @{ State = 'No gaps found, every resource is compliant with the initiative' } }
            $status = Get-Status 'DR.6-NONCOMPLIANT'
            if ($status -eq 'MISSING') { return @{ State = $needsRecollection } }
            if ($status -notin 'OK', 'PARTIAL', 'EMPTY') { return @{ State = "Not collected (DR.6-NONCOMPLIANT $status)" } }
            if (Test-Unreadable 'DR.6-NONCOMPLIANT') { return @{ State = Get-UnreadableState 'DR.6-NONCOMPLIANT' } }
            $rows = @(Get-Rows 'DR.6-NONCOMPLIANT')
            if (-not $rows.Count) { return @{ State = 'No gaps found in DR.6-NONCOMPLIANT' } }
            New-DiagnosticRemediation $rows } }

    @{ Number = 11; Key = 'redis-minimum-tls'; Change = 'Minimum TLS 1.2 on Azure Cache for Redis'; Sources = @('NB.6-PAAS-DETAIL')
       Build = {
            $resources = Get-PaasTlsResource 'microsoft.cache/redis'
            $n = $resources.Count
            if (-not $n) { return @{ State = 'No gaps found' } }
            $impl = [System.Collections.Generic.List[object]]::new()
            $impl.Add((Get-OpenStep $n 'Azure Cache for Redis' 'cache'))
            $impl.Add('Go to Settings > Advanced settings.')
            $impl.Add('Set Minimum TLS version to 1.2 and select Save.')
            Add-RepeatStep $impl $n 1 'cache'
            @{ Cr = New-ChangeRequest @{
                    Number = 11; Key = 'redis-minimum-tls'; Title = 'Set minimum TLS version 1.2 on Azure Cache for Redis'
                    Description = 'Set the minimum TLS version to 1.2 on {0}.' -f (Get-Listed $n 'Azure Cache for Redis cache' 'Azure Cache for Redis caches')
                    Purpose = 'Azure Cache for Redis has refused TLS 1.0 and 1.1 on every cache since April 1, 2025, but {0} still {1} an older minimum in {2} configuration. Setting 1.2 brings the configuration in line with the platform and the security baseline.' -f (Get-Pick $n 'this cache' 'these caches'), (Get-Pick $n 'records' 'record'), (Get-Pick $n 'its' 'their')
                    ResourceIntro = '{0} with the minimum TLS version {1} today.' -f $(if ($n -eq 1) { 'The cache below is listed' } else { "The $n caches below are listed" }), (Get-Pick $n 'it records' 'each one records')
                    ResourceLines = Format-ResourceList $resources
                    Availability = 'No impact, since Azure Cache for Redis already refuses TLS 1.0 and 1.1 and connections that work today keep working.'
                    UserExperience = 'No change for users or applications.'
                    Dependencies = 'None, since the platform already requires TLS 1.2 or later from every client.'
                    Implementation = $impl.ToArray()
                    Testing = @(
                        ('In the Azure portal, open {0} and go to Settings > Advanced settings.' -f (Get-EachStep $n 'cache'))
                        'Confirm Minimum TLS version shows 1.2.')
                    Rollback = @(
                        'No rollback is available or needed, because Azure Cache for Redis has not allowed a minimum below 1.2 since March 1, 2024.'
                        'Every cache has refused TLS 1.0 and 1.1 since April 1, 2025, so every client that connected before the change can still connect.')
                    References = @(
                        , @('Remove TLS 1.0 and 1.1 from use with Azure Cache for Redis', 'https://learn.microsoft.com/azure/azure-cache-for-redis/cache-remove-tls-10-11')
                        , @('How to configure Azure Cache for Redis, advanced settings', 'https://learn.microsoft.com/azure/azure-cache-for-redis/cache-configure#advanced-settings'))
                    Csv = $resources
                    Email = New-ApprovalEmail -Subject 'minimum TLS 1.2 for Azure Cache for Redis' `
                        -Change @(('I would like to set the minimum TLS version to 1.2 on {0}.' -f (Get-Yours $n 'Azure Cache for Redis caches')), $explainTls) `
                        -Why ('I recommend setting this minimum because TLS 1.0 and 1.1 have known weaknesses. Azure Cache for Redis has refused them on every cache since April 1, 2025, but {0} an older minimum in {1} configuration, so this change brings the configuration in line with the platform and the security baseline.' -f (Get-Pick $n 'this cache still records' 'these caches still record'), (Get-Pick $n 'its' 'their')) `
                        -Listed (Get-Pick $n 'The cache is listed below with its minimum TLS version today:' 'The caches are listed below by subscription, each with its minimum TLS version today:') `
                        -Resources (Get-EmailResourceList $resources $settingLabel) `
                        -Reversal 'Azure Cache for Redis has not allowed a minimum below 1.2 since March 1, 2024, so this change cannot be reversed. I do not expect a reversal to be needed, because every cache has refused TLS 1.0 and 1.1 since April 1, 2025.' `
                        -Effect 'I do not expect any visible effect, because Azure Cache for Redis already refuses TLS 1.0 and 1.1, so every connection that works today keeps working.'
                } } } }

    @{ Number = 12; Key = 'service-bus-minimum-tls'; Change = 'Minimum TLS 1.2 on Service Bus namespaces'; Sources = @('NB.6-PAAS-DETAIL')
       Build = {
            $resources = Get-PaasTlsResource 'microsoft.servicebus/namespaces'
            $n = $resources.Count
            if (-not $n) { return @{ State = 'No gaps found' } }
            $impl = [System.Collections.Generic.List[object]]::new()
            $impl.Add((Get-OpenStep $n 'Service Bus' 'namespace'))
            $impl.Add('Go to Settings > Configuration.')
            $impl.Add('Set Minimum TLS version to 1.2 and select Save.')
            Add-RepeatStep $impl $n 1 'namespace'
            @{ Cr = New-ChangeRequest @{
                    Number = 12; Key = 'service-bus-minimum-tls'; Title = 'Set minimum TLS version 1.2 on Service Bus namespaces'
                    Description = 'Set the minimum TLS version to 1.2 on {0}.' -f (Get-Listed $n 'Service Bus namespace' 'Service Bus namespaces')
                    Purpose = 'Service Bus accepts only TLS 1.2 and later, but {0} still {1} an older minimum in {2} configuration. Setting 1.2 brings the configuration in line with the platform and the security baseline.' -f (Get-Pick $n 'this namespace' 'these namespaces'), (Get-Pick $n 'records' 'record'), (Get-Pick $n 'its' 'their')
                    ResourceIntro = '{0} with the minimum TLS version {1} today.' -f $(if ($n -eq 1) { 'The namespace below is listed' } else { "The $n namespaces below are listed" }), (Get-Pick $n 'it records' 'each one records')
                    ResourceLines = Format-ResourceList $resources
                    Availability = 'No impact, since Service Bus already refuses TLS 1.0 and 1.1 and connections that work today keep working.'
                    UserExperience = 'No change for users or applications.'
                    Dependencies = 'None, since every client that connects today already uses TLS 1.2 or later.'
                    Implementation = $impl.ToArray()
                    Testing = @(
                        ('In the Azure portal, open {0} and go to Settings > Configuration.' -f (Get-EachStep $n 'namespace'))
                        'Confirm Minimum TLS version shows 1.2.')
                    Rollback = @(
                        'No rollback is available or needed, because a Service Bus namespace takes only 1.2 or 1.3 as its minimum TLS version.'
                        'Service Bus accepts only TLS 1.2 and later, so every client that connected before the change can still connect.')
                    References = @(
                        , @('Enforce a minimum required version of TLS for requests to a Service Bus namespace', 'https://learn.microsoft.com/azure/service-bus-messaging/transport-layer-security-enforce-minimum-version')
                        , @('Configure the minimum TLS version for a Service Bus namespace', 'https://learn.microsoft.com/azure/service-bus-messaging/transport-layer-security-configure-minimum-version'))
                    Csv = $resources
                    Email = New-ApprovalEmail -Subject 'minimum TLS 1.2 for Azure Service Bus namespaces' `
                        -Change @(('I would like to set the minimum TLS version to 1.2 on {0}.' -f (Get-Yours $n 'Service Bus namespaces')), $explainTls) `
                        -Why ('I recommend setting this minimum because TLS 1.0 and 1.1 have known weaknesses. Service Bus accepts only TLS 1.2 and later, but {0} an older minimum in {1} configuration, so this change brings the configuration in line with the platform and the security baseline.' -f (Get-Pick $n 'this namespace still records' 'these namespaces still record'), (Get-Pick $n 'its' 'their')) `
                        -Listed (Get-Pick $n 'The namespace is listed below with its minimum TLS version today:' 'The namespaces are listed below by subscription, each with its minimum TLS version today:') `
                        -Resources (Get-EmailResourceList $resources $settingLabel) `
                        -Reversal 'A Service Bus namespace takes only 1.2 or 1.3 as its minimum TLS version, so this change cannot be reversed. I do not expect a reversal to be needed, because Service Bus accepts only TLS 1.2 and later.' `
                        -Effect 'I do not expect any visible effect, because Service Bus already refuses TLS 1.0 and 1.1, so every connection that works today keeps working.'
                } } } }

    @{ Number = 13; Key = 'event-hubs-minimum-tls'; Change = 'Minimum TLS 1.2 on Event Hubs namespaces'; Sources = @('NB.6-PAAS-DETAIL')
       Build = {
            # Event Hubs still documents namespaces that accept TLS 1.0 and 1.1 below a minimum of 1.2, so a
            # client on an older version would be refused. The client is asked first.
            $resources = Get-PaasTlsResource 'microsoft.eventhub/namespaces'
            $n = $resources.Count
            if (-not $n) { return @{ State = 'No gaps found' } }
            $impl = [System.Collections.Generic.List[object]]::new()
            $impl.Add((Get-OpenStep $n 'Event Hubs' 'namespace'))
            $impl.Add('Go to Settings > Configuration.')
            $impl.Add('Set Minimum TLS version to 1.2 and select Save.')
            Add-RepeatStep $impl $n 1 'namespace'
            @{ Cr = New-ChangeRequest @{
                    Number = 13; Key = 'event-hubs-minimum-tls'; Title = 'Set minimum TLS version 1.2 on Event Hubs namespaces'
                    Description = 'Set the minimum TLS version to 1.2 on {0}.' -f (Get-Listed $n 'Event Hubs namespace' 'Event Hubs namespaces')
                    Purpose = 'TLS 1.0 and 1.1 have known weaknesses, and an Event Hubs namespace with a minimum below 1.2 still accepts requests over them. Setting 1.2 refuses these older protocols and matches the default for new namespaces.'
                    ResourceIntro = '{0} with the minimum TLS version {1} today.' -f $(if ($n -eq 1) { 'The namespace below is listed' } else { "The $n namespaces below are listed" }), (Get-Pick $n 'it allows' 'each one allows')
                    ResourceLines = Format-ResourceList $resources
                    Availability = 'No downtime expected, since the setting takes effect within about 30 seconds without a restart.'
                    UserExperience = 'No change for applications that send or receive events over TLS 1.2 or later.'
                    Dependencies = 'Clients limited to TLS 1.0 or 1.1 can no longer send or receive events once the change is applied.'
                    Implementation = $impl.ToArray()
                    Testing = @(
                        ('In the Azure portal, open {0} and go to Settings > Configuration.' -f (Get-EachStep $n 'namespace'))
                        'Confirm Minimum TLS version shows 1.2.')
                    Rollback = @(
                        'In the Azure portal, open the namespace to revert and go to Settings > Configuration.'
                        'Set Minimum TLS version back to the version recorded for the namespace in the RESOURCES section, or to 1.0 where it is recorded as not set, since a namespace created without the setting accepts TLS 1.0, and select Save.'
                        'If the portal no longer offers that version, Event Hubs has retired TLS 1.0 and 1.1 for every namespace, so no client can use them and no rollback is needed.')
                    References = @(
                        , @('Enforce a minimum required version of TLS for requests to an Event Hubs namespace', 'https://learn.microsoft.com/azure/event-hubs/transport-layer-security-enforce-minimum-version')
                        , @('Configure the minimum TLS version for an Event Hubs namespace', 'https://learn.microsoft.com/azure/event-hubs/transport-layer-security-configure-minimum-version'))
                    Csv = $resources
                    Email = New-ApprovalEmail -Subject 'minimum TLS 1.2 for Azure Event Hubs namespaces' `
                        -Change @(('I would like to set the minimum TLS version to 1.2 on {0}.' -f (Get-Yours $n 'Event Hubs namespaces')), $explainTls) `
                        -Why ('I recommend setting this minimum because TLS 1.0 and 1.1 have known weaknesses, and an Event Hubs namespace with a minimum below 1.2 still accepts requests over them. Setting 1.2 makes {0} refuse these older versions, and matches the default for new namespaces.' -f (Get-Pick $n 'the namespace' 'these namespaces')) `
                        -Effect 'Applications that send or receive events over TLS 1.2 or later will see no change. An application, device or partner system that can only use TLS 1.0 or 1.1, for example one on an old operating system or runtime, will have its requests refused until it is updated.' `
                        -Listed (Get-Pick $n 'The namespace is listed below with its minimum TLS version today:' 'The namespaces are listed below by subscription, each with its minimum TLS version today:') `
                        -Resources (Get-EmailResourceList $resources $settingLabel) `
                        -Reversal ('The minimum TLS version can be set back to the version {0} today, shown above, for as long as Event Hubs still offers it.' -f (Get-Pick $n 'the namespace has' 'each namespace has')) `
                        -Ask ('Could you let me know whether anything that connects to {0} may still use TLS 1.0 or 1.1? If nothing does, could you approve this change for {1}?' -f (Get-Pick $n 'the namespace' 'these namespaces'), $proposedDay) `
                        -Options 'If something does, I will hold the change until it uses TLS 1.2. If another date suits you better, or anything listed above should stay out of the change, please let me know.'
                } } } }

    @{ Number = 14; Key = 'cosmos-db-minimum-tls'; Change = 'Minimum TLS 1.2 on Azure Cosmos DB accounts'; Sources = @('NB.6-PAAS-DETAIL')
       Build = {
            $resources = Get-PaasTlsResource 'microsoft.documentdb/databaseaccounts'
            $n = $resources.Count
            if (-not $n) { return @{ State = 'No gaps found' } }
            $impl = [System.Collections.Generic.List[object]]::new()
            $impl.Add((Get-OpenStep $n 'Azure Cosmos DB' 'account'))
            $impl.Add('Go to Settings > Networking and select the Connectivity tab.')
            $impl.Add('Set Minimum Transport Layer Security Protocol to TLS 1.2 and select Save.')
            Add-RepeatStep $impl $n 1 'account'
            @{ Cr = New-ChangeRequest @{
                    Number = 14; Key = 'cosmos-db-minimum-tls'; Title = 'Set minimum TLS version 1.2 on Azure Cosmos DB accounts'
                    Description = 'Set the minimum TLS version to 1.2 on {0}.' -f (Get-Listed $n 'Azure Cosmos DB account' 'Azure Cosmos DB accounts')
                    Purpose = 'Azure Cosmos DB retired TLS 1.0 and 1.1 on August 31, 2025, but {0} not record a minimum of 1.2 in {1} configuration. Setting 1.2 brings the configuration in line with the platform and the security baseline.' -f (Get-Pick $n 'this account does' 'these accounts do'), (Get-Pick $n 'its' 'their')
                    ResourceIntro = '{0} with the minimum TLS version {1} today.' -f $(if ($n -eq 1) { 'The account below is listed' } else { "The $n accounts below are listed" }), (Get-Pick $n 'it records' 'each one records')
                    ResourceLines = Format-ResourceList $resources
                    Availability = 'No impact, since Azure Cosmos DB already refuses TLS 1.0 and 1.1 and connections that work today keep working.'
                    UserExperience = 'No change for users or applications.'
                    Dependencies = 'None, since every client that connects today already uses TLS 1.2 or later.'
                    Implementation = $impl.ToArray()
                    Testing = @(
                        ('In the Azure portal, open {0}, go to Settings > Networking and select the Connectivity tab.' -f (Get-EachStep $n 'account'))
                        'Confirm Minimum Transport Layer Security Protocol shows TLS 1.2.')
                    Rollback = @(
                        'No rollback is available or needed, because Azure Cosmos DB accepts only TLS 1.2 as the minimum for an account.'
                        'TLS 1.0 and 1.1 were retired across Azure Cosmos DB on August 31, 2025, so every client that connected before the change can still connect.')
                    References = @(, @('Self-serve minimum TLS version enforcement in Azure Cosmos DB', 'https://learn.microsoft.com/azure/cosmos-db/self-serve-minimum-tls-enforcement'))
                    Csv = $resources
                    Email = New-ApprovalEmail -Subject 'minimum TLS 1.2 for Azure Cosmos DB accounts' `
                        -Change @(('I would like to set the minimum TLS version to 1.2 on {0}.' -f (Get-Yours $n 'Azure Cosmos DB accounts')), $explainTls) `
                        -Why ('I recommend setting this minimum because TLS 1.0 and 1.1 have known weaknesses. Azure Cosmos DB retired them on August 31, 2025, but {0} not record a minimum of 1.2 in {1} configuration, so this change brings the configuration in line with the platform and the security baseline.' -f (Get-Pick $n 'this account does' 'these accounts do'), (Get-Pick $n 'its' 'their')) `
                        -Listed (Get-Pick $n 'The account is listed below with its minimum TLS version today:' 'The accounts are listed below by subscription, each with its minimum TLS version today:') `
                        -Resources (Get-EmailResourceList $resources $settingLabel) `
                        -Reversal 'Azure Cosmos DB accepts only TLS 1.2 as the minimum for an account, so this change cannot be reversed. I do not expect a reversal to be needed, because Azure Cosmos DB retired TLS 1.0 and 1.1 on August 31, 2025.' `
                        -Effect 'I do not expect any visible effect, because Azure Cosmos DB already refuses TLS 1.0 and 1.1, so every connection that works today keeps working.'
                } } } }

    @{ Number = 15; Key = 'scale-set-encryption-at-host'; Change = 'Encryption at host on virtual machine scale sets'; Sources = @('DP.4-VMSS-ELIGIBILITY')
       Build = {
            # DP.4-VMSS-ELIGIBILITY lists the scale sets whose model lacks encryption at host and whether each
            # model can take it. AKS manages the model of its node pools and sets encryption at host only when
            # a node pool is created, so they go to a planned project instead. A Flexible scale set is listed
            # only when every one of its machines without the setting can take it too, since the change stops
            # each of them for a setting Azure would otherwise reject.
            $rows = @(Get-Rows 'DP.4-VMSS-ELIGIBILITY')
            $notes = [System.Collections.Generic.List[string]]::new()
            $aks = @($rows | Where-Object { Test-True $_.Aks })
            if ($aks.Count) {
                $pools = @($aks | Sort-Object AksCluster, AksNodePool, Name | ForEach-Object {
                        $pool = ConvertTo-CopyText $_.AksNodePool
                        $where = if (Get-Text $_.AksCluster) { 'cluster {0} (resource group {1})' -f (ConvertTo-CopyText $_.AksCluster), (ConvertTo-CopyText $_.AksClusterResourceGroup) } else { 'scale set {0} in resource group {1}' -f (ConvertTo-CopyText $_.Name), (ConvertTo-CopyText $_.resourceGroup) }
                        '{0} node pool {1} ({2}, {3})' -f $where, $(if ($pool) { $pool } else { 'name not tagged' }), (ConvertTo-CopyText $_.Size), (Get-Count (Get-Number $_.Instances) 'node' 'nodes') })
                $notes.Add(('{0} without encryption at host left out of CR-15 and routed to a planned project: {1}. AKS sets encryption at host only when a node pool is created, so each pool is replaced: a new node pool created with encryption at host, its workloads moved across and the old pool removed. Plan that with the client as a project, not as a low-impact change.' -f (Get-Count $aks.Count 'AKS node pool' 'AKS node pools'), ($pools -join ', ')))
            }
            $bare = @($rows | Where-Object { -not (Test-True $_.Aks) -and -not (Test-True $_.HasModel) })
            if ($bare.Count) {
                $notes.Add(('{0} without a scale set model left out of CR-15: {1}. With no model there is nothing to set on the scale set, so CR-09 covers {2} machines as standalone virtual machines.' -f (Get-Count $bare.Count 'Flexible scale set' 'Flexible scale sets'), (@($bare | Sort-Object Name | ForEach-Object { ConvertTo-CopyText $_.Name }) -join ', '), (Get-Pick $bare.Count 'its' 'their')))
            }
            $models = @($rows | Where-Object { Test-ScaleSetModel $_ })
            $ineligible = @($models | Where-Object { -not (Test-True $_.Eligible) })
            if ($ineligible.Count) {
                $notes.Add(('{0} left out of CR-15 because {1} encryption at host as {2}: {3}.' -f (Get-Count $ineligible.Count 'scale set' 'scale sets'), (Get-Pick $ineligible.Count 'its model cannot take' 'their models cannot take'), (Get-Pick $ineligible.Count 'it stands' 'they stand'),
                        (@($ineligible | Sort-Object Name | ForEach-Object { '{0} ({1}, {2})' -f (ConvertTo-CopyText $_.Name), (ConvertTo-CopyText $_.Size), ((ConvertTo-CopyText $_.Reason) -replace '^(size support not read):.*$', '$1') }) -join ', ')))
            }
            $eligible = @($models | Where-Object { Test-True $_.Eligible })
            # Each scale set is matched by its unique ID before its model is changed and its instances stopped.
            # A pack from before collector 1.4.0 has no unique ID, so it cannot tell the scale set that was
            # checked from one created again under its name.
            if ($eligible.Count -and $eligible[0].PSObject.Properties.Name -notcontains 'UniqueId') { return @{ State = $needsIdRecollection; Notes = $notes.ToArray() } }
            $unnamed = @($eligible | Where-Object { -not (Test-EligibleScaleSetModel $_) })
            if ($unnamed.Count) {
                $notes.Add(('{0} left out of CR-15 because {1} unique ID was not read, so {2} cannot be told from a scale set created again under the same name: {3}.' -f (Get-Count $unnamed.Count 'scale set' 'scale sets'), (Get-Pick $unnamed.Count 'its' 'their'), (Get-Pick $unnamed.Count 'it' 'they'), (@($unnamed | Sort-Object Name | ForEach-Object { ConvertTo-CopyText $_.Name }) -join ', ')))
                $eligible = @($eligible | Where-Object { $_ -notin $unnamed })
            }
            # The machines of each Flexible scale set must all be proven eligible too (Test-FlexibleScaleSets).
            $flexible = @($eligible | Where-Object { (Get-Text $_.OrchestrationMode) -ieq 'Flexible' })
            $check = Test-FlexibleScaleSets $flexible
            $instances = $check.Qualified
            if ($check.Unchecked) {
                $notes.Add(('{0} left out of CR-15 because DP.4-ELIGIBILITY {1}, so {2} could not be checked: {3}.' -f (Get-Count $flexible.Count 'Flexible scale set' 'Flexible scale sets'), $check.Unchecked, (Get-Pick $flexible.Count 'its machines' 'their machines'), (@($flexible | Sort-Object Name | ForEach-Object { ConvertTo-CopyText $_.Name }) -join ', ')))
            }
            if ($check.Blocked.Count) {
                $notes.Add(('{0} left out of CR-15 because {1} that cannot take encryption at host as it stands: {2}.' -f (Get-Count $check.Blocked.Count 'Flexible scale set' 'Flexible scale sets'), (Get-Pick $check.Blocked.Count 'it has a machine' 'each has a machine'), ($check.Blocked -join ', ')))
            }
            $eligible = @($eligible | Where-Object { (Get-Text $_.OrchestrationMode) -ine 'Flexible' -or $instances.ContainsKey((Get-Text $_.ResourceId).ToLowerInvariant()) })
            $resources = @($eligible | ForEach-Object {
                    $mode = if ((Get-Text $_.OrchestrationMode) -ieq 'Flexible') { 'Flexible' } else { 'Uniform' }
                    $setting = '{0}, {1}, {2}, size {3}, unique ID {4}' -f $mode, (Format-UpgradePolicy $_.UpgradePolicy), (Get-Count (Get-Number $_.Instances) 'instance' 'instances'), (ConvertTo-CopyText $_.Size), (ConvertTo-CopyText $_.UniqueId).ToLowerInvariant()
                    if ($mode -eq 'Flexible') {
                        $members = @($instances[(Get-Text $_.ResourceId).ToLowerInvariant()])
                        $setting += if ($members.Count) { ', instances without encryption at host: ' + (@($members | Sort-Object Name | ForEach-Object { '{0} ({1}, VM ID {2})' -f (ConvertTo-CopyText $_.Name), (Get-PowerText $_.PowerState), (Get-VmId $_) }) -join ', ') } else { ', no instance without encryption at host' }
                    }
                    $r = New-Resource $_.Name $_.resourceGroup $_.subscriptionId $setting $_.ResourceId
                    $r | Add-Member -NotePropertyName Mode -NotePropertyValue $mode
                    $r | Add-Member -NotePropertyName Policy -NotePropertyValue (ConvertTo-CopyText $_.UpgradePolicy)
                    $r | Add-Member -NotePropertyName Instances -NotePropertyValue (Get-Number $_.Instances)
                    $r })
            $n = $resources.Count
            if (-not $n) { return @{ Notes = $notes.ToArray(); State = $(if ($aks.Count -and $aks.Count -eq $rows.Count) { 'Only AKS node pools remain, see the notes' } elseif ($rows.Count) { 'No eligible scale sets' } else { 'No gaps found' }) } }
            $uniform = @($resources | Where-Object Mode -eq 'Uniform')
            $flex = @($resources | Where-Object Mode -eq 'Flexible')
            $automatic = @($resources | Where-Object { $_.Policy -in 'Automatic', 'Rolling' })
            $notes.Add(('CR-15 changes a scale set only when the unique ID that Overview > JSON View shows matches the unique ID listed for it{0}. One whose ID differs was deleted and created again under the same name after collection and was never checked, so it is skipped and left for the next pack.' -f $(if ($flex.Count) { ', and a Flexible scale set instance only when its VM ID matches one listed for its scale set' } else { '' })))
            $impl = [System.Collections.Generic.List[object]]::new()
            foreach ($step in New-EncryptionAtHostRegistration $resources) { $impl.Add($step) }
            $impl.Add(('In the Azure portal, go to Virtual machine scale sets, open {0}, select JSON View on Overview and confirm properties.uniqueId reads the unique ID listed for it. A scale set that reads another ID was created again under the same name after collection and was never checked, so leave it out of every step below, which leaves it for the next pack.' -f (Get-EachStep $n 'scale set')))
            $set = @(('In Cloud Shell, set encryption at host on the model of {0} whose unique ID matched{1}:' -f (Get-EachStep $n 'scale set'), $(if ($automatic.Count) { '. A scale set with an Automatic upgrade policy may take all its instances down at once to apply the new model, and one with a Rolling policy applies it in batches, so run this only inside the agreed maintenance window' } else { '' })))
            foreach ($r in @($resources | Sort-Object SubscriptionId, ResourceGroup, Name)) { $set += 'az vmss update --subscription {0} --resource-group {1} --name {2} --set virtualMachineProfile.securityProfile.encryptionAtHost=true' -f (Format-ShellArgument $r.SubscriptionId), (Format-ShellArgument $r.ResourceGroup), (Format-ShellArgument $r.Name) }
            $impl.Add($set)
            # Existing instances take the setting only once deallocated and started again. A Uniform instance
            # takes it from the model through Upgrade, and a Flexible instance is a virtual machine that takes
            # it directly, as in CR-09.
            if ($uniform.Count) {
                $from = $impl.Count + 1
                $impl.Add(('In the Azure portal, go to Virtual machine scale sets, open the {0}Uniform scale set listed in the RESOURCES section and go to Settings > Instances.' -f $(if ($uniform.Count -gt 1) { 'first ' } else { '' })))
                $impl.Add('Select the first instance, note whether its status reads Running, then select Stop and wait for the status to read Stopped (deallocated).')
                $impl.Add('With the instance still selected, select Upgrade if Latest model reads No, and wait for the upgrade to finish.')
                $impl.Add('Select Start only if the instance read Running before the stop, so an instance that was not running stays stopped.')
                $impl.Add(('Repeat steps {0} to {1} for each remaining instance{2}.' -f ($from + 1), $impl.Count, $(if ($uniform.Count -gt 1) { ", then steps $from to $($impl.Count) for each remaining Uniform scale set listed" } else { '' })))
            }
            if ($flex.Count) {
                $from = $impl.Count + 1
                # The steps work through the instances the scale set holds when the change is made, since it may
                # have gained some since collection. Only the instances listed were checked for Azure Disk
                # Encryption, old 512e disks and size support, and each is matched by its VM ID, since a name
                # alone would also match an instance created again under it. Any other one is left for the next pack.
                $impl.Add(('In the Azure portal, go to Virtual machine scale sets, open the {0}Flexible scale set listed in the RESOURCES section, go to Settings > Instances and open the first instance listed there, since the scale set may have gained instances since collection.' -f $(if ($flex.Count -gt 1) { 'first ' } else { '' })))
                $impl.Add('On Overview, select JSON View and go on to the next instance if properties.vmId does not read a VM ID listed for this scale set in the RESOURCES section, since the instance joined or was created again under the same name after collection and was not checked, which leaves it for the next pack.')
                $impl.Add('Go to Settings > Disks > Additional settings and go on to the next instance if Encryption at host already shows Yes.')
                $impl.Add('On Overview, note whether the status reads Running, then select Stop and wait for the status to read Stopped (deallocated).')
                $impl.Add('Go to Settings > Disks > Additional settings, set Encryption at host to Yes and select Save.')
                $impl.Add('Go back to Overview and select Start only if the status read Running before the stop, so an instance that was not running stays stopped.')
                $impl.Add(('Repeat steps {0} to {1} for each remaining instance under Settings > Instances{2}.' -f ($from + 1), $impl.Count, $(if ($flex.Count -gt 1) { ", then steps $from to $($impl.Count) for each remaining Flexible scale set listed" } else { '' })))
            }
            $testing = [System.Collections.Generic.List[object]]::new()
            $testing.Add(('In the Azure portal, open {0} whose unique ID matched, select JSON View on Overview and confirm virtualMachineProfile.securityProfile.encryptionAtHost reads true.' -f (Get-EachStep $n 'scale set')))
            if ($uniform.Count) { $testing.Add(('For {0}, go to Settings > Instances and confirm every instance shows Latest model Yes, and every instance that was running before the change shows Running.' -f (Get-Pick $uniform.Count 'the Uniform scale set' 'each Uniform scale set'))) }
            if ($flex.Count) { $testing.Add(('For {0}, open each instance changed under Settings > Instances, go to Settings > Disks > Additional settings and confirm Encryption at host shows Yes, and on Overview confirm each instance that was running before the change shows Running.' -f (Get-Pick $flex.Count 'the Flexible scale set' 'each Flexible scale set'))) }
            $rollback = [System.Collections.Generic.List[object]]::new()
            $off = @('In the Azure portal, open Cloud Shell in Bash and turn encryption at host off on the model of the scale set to revert, with the command for it below:')
            foreach ($r in @($resources | Sort-Object SubscriptionId, ResourceGroup, Name)) { $off += 'az vmss update --subscription {0} --resource-group {1} --name {2} --set virtualMachineProfile.securityProfile.encryptionAtHost=false' -f (Format-ShellArgument $r.SubscriptionId), (Format-ShellArgument $r.ResourceGroup), (Format-ShellArgument $r.Name) }
            $rollback.Add($off)
            if ($uniform.Count) { $rollback.Add('For a Uniform scale set, go to Settings > Instances and for each instance note whether its status reads Running, select Stop, wait for Stopped (deallocated), select Upgrade, and select Start only if it read Running before the stop.') }
            if ($flex.Count) { $rollback.Add('For a Flexible scale set, open each instance under Settings > Instances whose Encryption at host shows Yes under Settings > Disks > Additional settings, including any created after the model was changed, note on Overview whether its status reads Running, select Stop, wait for Stopped (deallocated), set Encryption at host to No under Settings > Disks > Additional settings, select Save, and select Start only if it read Running before the stop.') }
            $references = @(
                , @('Use the Azure portal to enable end-to-end encryption using encryption at host', 'https://learn.microsoft.com/azure/virtual-machines/disks-enable-host-based-encryption-portal')
                , @('Use the Azure CLI to enable end-to-end encryption using encryption at host, Virtual Machine Scale Sets', 'https://learn.microsoft.com/azure/virtual-machines/linux/disks-enable-host-based-encryption-cli#update-a-virtual-machine-scale-set-to-enable-encryption-at-host')
                , @('Upgrade policy modes for Virtual Machine Scale Sets', 'https://learn.microsoft.com/azure/virtual-machine-scale-sets/virtual-machine-scale-sets-upgrade-policy')
                , @('Performing manual upgrades on Virtual Machine Scale Sets', 'https://learn.microsoft.com/azure/virtual-machine-scale-sets/virtual-machine-scale-sets-perform-manual-upgrades'))
            $effect = [System.Collections.Generic.List[object]]::new()
            $effect.Add(('The setting goes on the configuration of {0}, so new instances are encrypted from the start. Each existing instance has to be stopped and started again to pick it up, which I will do one instance at a time. An instance that is running at the time will be unavailable for a few minutes until I start it again, and an instance that is already stopped will be left stopped. Nothing changes inside the operating system or the applications.' -f (Get-Pick $n 'the scale set' 'each scale set')))
            if ($automatic.Count) {
                $effect.Add(('{0} set to update {1} instances automatically, so once the setting is applied it may also restart them on its own, all at the same time under the Automatic policy and in batches under the Rolling policy. I will plan the window as if every instance could be unavailable at once: {2}.' -f $(if ($automatic.Count -eq 1) { 'One scale set is' } else { "$($automatic.Count) scale sets are" }), (Get-Pick $automatic.Count 'its' 'their'), (@($automatic | Sort-Object Name | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Policy }) -join ', ')))
            }
            $effect.Add('Because of those restarts, I am asking for a maintenance window rather than proposing a date.')
            $email = New-ApprovalEmail -Window -Subject 'encryption at host for Azure virtual machine scale sets' `
                -Change @(('I would like to enable encryption at host on {0}.' -f (Get-Yours $n 'virtual machine scale sets')), 'Encryption at host encrypts the temporary disk and the disk caches on the Azure host, the physical server each instance runs on.') `
                -Why ('I recommend enabling encryption at host because Azure already encrypts the managed disks of {0} at rest, but not the temporary disk or the disk caches. Encryption at host closes that gap, so the data of {0} stays encrypted all the way to Azure Storage.' -f (Get-Pick $n 'the instances of this scale set' 'the instances of these scale sets')) `
                -Effect $effect.ToArray() `
                -Listed (Get-Pick $n 'The scale set is listed below with its number of instances:' 'The scale sets are listed below by subscription, each with its number of instances:') `
                -Resources (Get-EmailResourceList $resources { '{0} (resource group {1}, {2})' -f $_.Name, $_.ResourceGroup, (Get-Count $_.Instances 'instance' 'instances') }) `
                -Reversal ('Encryption at host can be turned off again on {0}, which needs the same stop and start of each instance inside a maintenance window.' -f (Get-Pick $n 'the scale set' 'each scale set')) `
                -Ask (Get-Pick $n 'Could you approve this change and suggest a maintenance window that works for this scale set?' 'Could you approve this change and suggest a maintenance window that works for these scale sets?') `
                -Options (Get-Pick $n '' 'If any of them need to be handled separately or in a particular order, please let me know.')
            # Instances are restarted one at a time, unless the upgrade policy applies the model on its own.
            $auto = @($automatic | Where-Object Policy -eq 'Automatic').Count
            $rolling = @($automatic | Where-Object Policy -eq 'Rolling').Count
            $availability = 'Each instance is unavailable for a few minutes while it is stopped and started inside the agreed maintenance window{0}.' -f $(
                if ($auto -and $rolling) { ', and a scale set with an Automatic upgrade policy may take all its instances down at once, and one with a Rolling policy several in each batch, to apply the model' }
                elseif ($auto) { ', and a scale set with an Automatic upgrade policy may take all its instances down at once to apply the model' }
                elseif ($rolling) { ', and a scale set with a Rolling upgrade policy may take several instances down in each batch to apply the model' }
                else { ', one instance at a time' })
            $spec = @{
                Number = 15; Key = 'scale-set-encryption-at-host'; Title = 'Enable encryption at host on virtual machine scale sets'
                Description = 'Enable encryption at host on the model and the existing instances of {0}, which needs a stop and start of each instance.' -f (Get-Listed $n 'virtual machine scale set' 'virtual machine scale sets')
                Purpose = 'Encryption at host encrypts the temporary disk and the OS and data disk caches on the Azure host, so the data of each instance is encrypted from end to end. Setting it on the model covers the instances a scale set creates later, and the stop and start brings in the instances it already has.'
                ResourceIntro = $(if ($n -eq 1) { 'The scale set below is listed with its orchestration mode, upgrade policy, instance count, size and unique ID at collection, and a Flexible scale set with the VM ID of each instance to change. Only a scale set and an instance whose ID still matches are changed, and each instance is returned to the power state it has when the change is made.' } else { "The $n scale sets below are listed with the orchestration mode, upgrade policy, instance count, size and unique ID of each at collection, and a Flexible scale set with the VM ID of each instance to change. Only a scale set and an instance whose ID still matches are changed, and each instance is returned to the power state it has when the change is made." })
                ResourceLines = Format-ResourceList $resources
                Availability = $availability
                UserExperience = 'Users of a scale set see reduced capacity while one of its instances restarts, or a short outage where it runs a single instance, and no change afterwards.'
                Dependencies = 'Needs the EncryptionAtHost feature on each subscription, a VM size that supports it and a scale set that never used Azure Disk Encryption.'
                Implementation = $impl.ToArray(); Testing = $testing.ToArray(); Rollback = $rollback.ToArray()
                References = $references
                Csv = $resources
                Email = $email
            }
            # Azure Site Recovery replicates the machines of a Flexible scale set, never a Uniform one.
            if ($DrClient -and $flex.Count) {
                $spec.DrImpact = 'This is a DR client. Azure Site Recovery does not carry encryption at host to test failover or failover virtual machines, so the DR Playbook needs an update for the Flexible scale set instances in this change.'
                $spec.DrPlan = @(
                    'In the DR Playbook, add a post-failover step for the Flexible scale set instances listed in this change.'
                    'The step notes whether each failed over virtual machine reads Running, stops it, sets Encryption at host to Yes under Settings > Disks > Additional settings, selects Save, and starts it again only if it was running before the stop.'
                    'Attach the link to the updated DR Playbook, or a screenshot of the new step, to this change request before it is closed.')
                $spec.References = $references + , @('Support matrix for Azure VM disaster recovery, replicated machines storage', 'https://learn.microsoft.com/azure/site-recovery/azure-to-azure-support-matrix#replicated-machines---storage')
            }
            @{ Notes = $notes.ToArray(); Cr = New-ChangeRequest $spec } } }

    @{ Number = 16; Key = 'management-ports'; Change = 'Internet-facing RDP, SSH and WinRM rules closed'; Sources = @('NB.2-DETAIL'); Uses = @('DefenderServersP2')
       Build = {
            # NB.2-DETAIL lists every allow inbound rule open to any address, Internet, 0.0.0.0/0 or ::/0 on a management
            # port, * or a range. CR-16 closes those on a workload subnet or network interface that name their ports over
            # TCP or any protocol. A rule for another protocol, such as UDP 22 for an application, is left for review.
            # The index names the rest: a group attached to nothing exposes nothing yet, an appliance untrust
            # interface takes internet traffic by design, and * or a range may not mean a management port is meant.
            $rows = @(Get-Rows 'NB.2-DETAIL')
            $unattached = [System.Collections.Generic.List[string]]::new()
            $appliance = [System.Collections.Generic.List[string]]::new()
            $shared = [System.Collections.Generic.List[string]]::new()
            $ranges = [System.Collections.Generic.List[string]]::new()
            $protocols = [System.Collections.Generic.List[string]]::new()
            $resources = @(foreach ($r in $rows) {
                    $nsg = ConvertTo-CopyText $r.NSG
                    $rule = ConvertTo-CopyText $r.RuleName
                    $label = '{0} in {1} (resource group {2})' -f $rule, $nsg, (ConvertTo-CopyText $r.resourceGroup)
                    $subnets = @(Get-List $r.Subnets)
                    $nics = @(Get-List $r.Nics)
                    # Every network interface of an appliance and the subnets it sits in, so a group that reaches one
                    # directly or through its subnet is found.
                    $applianceNics = @(Get-List $r.ApplianceNicIds | ForEach-Object { $_.ToLowerInvariant() })
                    $applianceSubnets = @(Get-List $r.ApplianceSubnetIds | ForEach-Object { $_.ToLowerInvariant() })
                    $ports = @(Get-List $r.DestinationPorts)
                    if (-not $subnets.Count -and -not $nics.Count) { $unattached.Add($label); continue }
                    $onAppliance = @($nics | Where-Object { $_.ToLowerInvariant() -in $applianceNics }).Count
                    $inApplianceSubnet = @($subnets | Where-Object { $_.ToLowerInvariant() -in $applianceSubnets }).Count
                    if ($onAppliance -or $inApplianceSubnet) {
                        if (-not $subnets.Count -and $onAppliance -eq $nics.Count) { $appliance.Add($label) } else { $shared.Add($label) }
                        continue
                    }
                    if (@($ports | Where-Object { $_ -eq '*' -or $_ -match '-' }).Count) { $ranges.Add(('{0}, ports {1}' -f $label, (ConvertTo-CopyText ($ports -join ', ')))); continue }
                    if ((Get-Text $r.Protocol) -notmatch '^(?i)(tcp|\*|)$') { $protocols.Add(('{0}, {1} ports {2}' -f $label, (Format-RuleProtocol (Get-Text $r.Protocol)), (ConvertTo-CopyText ($ports -join ', ')))); continue }
                    $sources = @(Get-List $r.SourcePrefixes)
                    $attachments = @(Get-RuleAttachments $r)
                    $other = @($ports | Where-Object { $_ -notin $managementPorts })
                    # The setting records every property the rollback needs to recreate the rule as it was, in the change
                    # request and the CSV. A list of several values is kept together in parentheses, as the portal takes it.
                    $list = { param($items) $v = @($items | ForEach-Object { ConvertTo-CopyText $_ }); if ($v.Count -gt 1) { '({0})' -f ($v -join ', ') } else { $v -join '' } }
                    $setting = @(
                        'priority {0}' -f (Get-Text $r.Priority)
                        'allow inbound'
                        'protocol ' + $(if ((Get-Text $r.Protocol) -match '^(\*|)$') { 'Any' } else { Format-RuleProtocol (Get-Text $r.Protocol) })
                        'source ' + (& $list $sources)
                        'source ports ' + (& $list @(Get-List $r.SourcePorts))
                        'destination ' + (& $list @(Get-List $r.DestinationPrefixes))
                        if (@(Get-List $r.DestinationAsgs).Count) { 'destination application security groups ' + (& $list @(Get-List $r.DestinationAsgs | ForEach-Object { ($_ -split '/')[-1] })) }
                        'destination ports ' + (& $list $ports)
                        if (Get-Text $r.Description) { 'description "{0}"' -f (ConvertTo-CopyText $r.Description) }
                        'applies to ' + ($attachments -join ' and ')) -join ', '
                    $res = New-Resource ('{0}/{1}' -f $nsg, $rule) $r.resourceGroup $r.subscriptionId $setting $r.RuleId
                    $portWords = '{0} {1} {2}' -f (Format-RuleProtocol (Get-Text $r.Protocol)), (Get-Pick $ports.Count 'port' 'ports'), (Join-Words @($ports | ForEach-Object { ConvertTo-CopyText $_ }))
                    $summary = '{0} in network security group {1} (resource group {2}, priority {3}, {4} from {5}, on {6})' -f $rule, $nsg, $res.ResourceGroup, (Get-Text $r.Priority), $portWords, (Join-Words @($sources | ForEach-Object { Format-RuleSource $_ })), (Join-Words $attachments)
                    $res | Add-Member -NotePropertyName Summary -NotePropertyValue $summary
                    $res | Add-Member -NotePropertyName OtherPorts -NotePropertyValue ([bool]$other.Count)
                    # Any, 0.0.0.0/0 and ::/0 match private addresses too, unlike the Internet service tag.
                    $res | Add-Member -NotePropertyName Broad -NotePropertyValue ([bool]@($sources | Where-Object { $_ -in '*', '0.0.0.0/0', '::/0' }).Count)
                    # Azure Bastion provides RDP and SSH sessions only, so a rule that opens WinRM needs another path for it.
                    $res | Add-Member -NotePropertyName WinRm -NotePropertyValue ([bool]@($ports | Where-Object { $_ -in '5985', '5986' }).Count)
                    $res
                })
            $notes = [System.Collections.Generic.List[string]]::new()
            if ($unattached.Count) {
                $notes.Add(('{0} left out of CR-16 as a cleanup item because {1} attached to no subnet or network interface, so {2} nothing today: {3}. Delete the rule, or the group if it is unused, with the client, since attaching the group later would open the port to the internet.' -f (Get-Count $unattached.Count 'rule' 'rules'), (Get-Pick $unattached.Count 'its network security group is' 'their network security groups are'), (Get-Pick $unattached.Count 'it exposes' 'they expose'), ($unattached -join ', ')))
            }
            if ($appliance.Count) {
                $notes.Add(('{0} left out of CR-16 because {1} attached only to network interfaces of network virtual appliances (P0.6-APPLIANCES), where an untrust interface takes internet traffic by design: {2}. Review each with the client against the management design of the appliance.' -f (Get-Count $appliance.Count 'rule' 'rules'), (Get-Pick $appliance.Count 'its network security group is' 'their network security groups are'), ($appliance -join ', ')))
            }
            if ($shared.Count) {
                $notes.Add(('{0} left out of CR-16 for review because {1} a network virtual appliance through a subnet it sits in, or through its network interface as well as other resources, so changing the rule would change the appliance too: {2}. Review each with the client against the management design of the appliance, and give the appliance interface its own network security group if the rule is not needed there.' -f (Get-Count $shared.Count 'rule' 'rules'), (Get-Pick $shared.Count 'its network security group reaches' 'their network security groups reach'), ($shared -join ', ')))
            }
            if ($ranges.Count) {
                $notes.Add(('{0} left out of CR-16 for review because {1} * or a port range, which may not mean a management port is meant to be open: {2}. Review each with the client and narrow it to the ports it needs. A rule narrowed to name 22, 3389, 5985 or 5986 joins CR-16 in a later pack.' -f (Get-Count $ranges.Count 'rule' 'rules'), (Get-Pick $ranges.Count 'its destination ports include' 'their destination ports include'), ($ranges -join ' / ')))
            }
            if ($protocols.Count) {
                $notes.Add(('{0} left out of CR-16 for review because {1} a protocol other than TCP, so {2} may carry an application rather than RDP, SSH or WinRM: {3}. Review each with the client, since RDP can also use UDP 3389.' -f (Get-Count $protocols.Count 'rule' 'rules'), (Get-Pick $protocols.Count 'it allows only' 'they allow only'), (Get-Pick $protocols.Count 'it' 'they'), ($protocols -join ' / ')))
            }
            $n = $resources.Count
            # A security admin rule from Azure Virtual Network Manager applies before every network security group,
            # and Always Allow ends the evaluation, so no change to a group closes a port such a rule keeps open.
            $held = $heldOpen.Count
            if (-not $n) {
                if ($held) { $notes.Add(('-AdminRuleOpen names {0} that a security admin rule with Always Allow keeps open to the internet: {1}. CR-16 has no rule to close in this pack, so no email names {2}. Escalate each admin rule to whoever owns the Virtual Network Manager configuration.' -f (Get-Count $held 'machine' 'machines'), (Format-HeldOpen), (Get-Pick $held 'it' 'them'))) }
                return @{ State = $(if ($rows.Count) { 'Only rules for cleanup or review remain, see the notes' } else { 'No gaps found' }); Notes = $notes.ToArray() }
            }
            $notes.Add('CR-16 changes network security group rules only. Azure Virtual Network Manager security admin rules apply before them, and one with Always Allow ends the evaluation, so a machine whose effective security rules show such a rule for 22, 3389, 5985 or 5986 from an internet source stays open whatever CR-16 changes and is outside what CR-16 can close. The steps have the operator record that admin rule and escalate it to whoever owns the Virtual Network Manager configuration, and never count the port as closed. Run again with -AdminRuleOpen to name the machine in the client email.')
            if ($held) { $notes.Add(('CR-16 names {0} that a security admin rule with Always Allow keeps open to the internet (-AdminRuleOpen): {1}. Its email says a central network policy keeps {2} open and asks who manages it. Escalate each admin rule to whoever owns the Virtual Network Manager configuration.' -f (Get-Count $held 'machine' 'machines'), (Format-HeldOpen), (Get-Pick @($heldOpen.Values | ForEach-Object { $_.Ports }).Count 'the port' 'the ports'))) }

            # Just-in-time VM access needs Defender for Servers Plan 2 on the subscription (P0.3). The path that fits
            # each subscription is named in the change request and suggested in the email.
            $plan = Get-ServersPlan2
            $subscriptions = @($resources | ForEach-Object SubscriptionId | Sort-Object -Unique | Sort-Object { Format-Subscription $_ })
            $withPlan = @($subscriptions | Where-Object { $plan[$_] -eq 'On' })
            $withoutPlan = @($subscriptions | Where-Object { $plan[$_] -eq 'Off' })
            $unknownPlan = @($subscriptions | Where-Object { -not $plan[$_] })
            $planLines = @('', 'Defender for Servers Plan 2, which just-in-time VM access needs (P0.3):')
            $winRmSubscriptions = @($resources | Where-Object WinRm | ForEach-Object SubscriptionId)
            foreach ($s in $subscriptions) {
                $planLines += '- {0}: {1}' -f (Format-Subscription $s), $(switch ($plan[$s]) {
                        'On' { 'on, so just-in-time VM access is the path' }
                        'Off' { if ($s -in $winRmSubscriptions) { 'not on, so Azure Bastion is the path for RDP and SSH and named source addresses for WinRM, unless the client turns Plan 2 on' } else { 'not on, so Azure Bastion is the path unless the client turns Plan 2 on' } }
                        default { 'not read, so check the plan under Microsoft Defender for Cloud > Environment settings before choosing the path' } })
            }
            $subs = $subscriptions.Count
            $otherPorts = @($resources | Where-Object OtherPorts).Count
            $winRm = @($resources | Where-Object WinRm).Count

            $impl = [System.Collections.Generic.List[object]]::new()
            $impl.Add('Where the client agreed just-in-time VM access, in the Azure portal go to Microsoft Defender for Cloud > Workload protections > Just-in-time VM access, select the Not configured tab, select the virtual machines behind the rules listed in the RESOURCES section, select Enable JIT on VMs, keep the ports it proposes and select Save. The rules listed keep priority over its deny rules until they are removed below.')
            $impl.Add(('Where the client agreed Azure Bastion, go to the virtual network of the machines behind each rule and select Connect > Bastion. If the virtual network has no Bastion host, deploy one with the tier agreed with the client.{0}' -f $(if ($winRm) { ' Azure Bastion provides RDP and SSH sessions only, so it never replaces WinRM on 5985 or 5986.' } else { '' })))
            # Bastion reaches a machine over its private address on 22 or 3389, so every group on the subnet or
            # network interface of the machine must let it in ahead of any deny rule before the public allow goes.
            $impl.Add('Where Azure Bastion is the path, open each network security group on the subnet or network interface of the machines behind each rule and go to Settings > Inbound security rules. Unless a rule already allows ports 22 and 3389 from the AzureBastionSubnet address range ahead of every deny rule for those ports, select + Add and add one with Source set to IP Addresses and that range, at a lower priority number than those deny rules. Then open a Bastion session to one machine behind each rule from its Connect > Bastion page, and if it does not open, stop here and leave every rule listed unchanged.')
            # Bastion offers RDP and SSH sessions only, so remote PowerShell keeps a path of its own.
            if ($winRm) {
                $impl.Add('A rule that opens 5985 or 5986 keeps WinRM only through just-in-time VM access or the source addresses the client named for WinRM, never through Azure Bastion. Where the client still needs WinRM to the machines behind such a rule and neither is agreed, leave the rule unchanged and note it in the change record.')
            }
            $loop = $impl.Count + 1
            $impl.Add('Go to Network security groups and open the network security group of the first rule listed in the RESOURCES section.')
            $impl.Add('Go to Settings > Inbound security rules and find the rule. If its priority, access, direction, protocol, source, ports or destination no longer read as listed, or the group is no longer attached to what is listed, leave it unchanged and note it in the change record for the next pack.')
            # A source of Any, 0.0.0.0/0 or ::/0 also lets in the virtual network, peered networks and connected
            # on-premises networks. With a deny rule behind it, removing it would cut that private access too, so the
            # private access moves to a rule of its own first, unless the client confirmed nothing uses it. The rule
            # names the ranges the client confirmed, never a service tag: the tag for the virtual network also holds
            # the prefixes of user-defined routes, so with a 0.0.0.0/0 route it would keep the ports open to everyone.
            $broad = @($resources | Where-Object Broad).Count
            if ($broad) {
                $impl.Add('If the source of the rule is Any, 0.0.0.0/0 or ::/0, which also matches private addresses, select + Add and add an allow rule with the protocol and destination of the rule, Destination port ranges set to the management ports it lists, Source set to IP Addresses with the private ranges the client confirmed, the address spaces of the virtual networks, peered virtual networks and on-premises networks that connect to the machines, and a free priority number lower than any deny rule for those ports, then select Add. Enter each range as a CIDR block, never a service tag, Any, 0.0.0.0/0 or ::/0, and check that each is a private range or one the client owns. Leave this rule out only where the client confirmed nothing connects from those networks. If the client has confirmed neither the ranges nor that nothing connects, leave the rule unchanged and note it in the change record.')
            }
            # Narrowing the source of a rule that also allows other ports would narrow them too, so the management
            # ports move to a rule of their own and the other ports keep the source they have.
            $impl.Add('If the client named source addresses that still need direct access and the rule allows only ports 22, 3389, 5985 or 5986, select the rule, set Source to IP Addresses, enter those addresses in Source IP addresses/CIDR ranges and select Save.')
            $impl.Add('If the client named such addresses and the rule also allows other ports, select + Add and add an allow rule with the protocol and destination of the rule, Destination port ranges set to the management ports it lists, Source set to IP Addresses with those addresses, and a free priority number lower than any deny rule for those ports, including one just-in-time VM access added, then select Add. Have the client confirm a connection from one of those addresses before going on. Then select the original rule, remove 22, 3389, 5985 and 5986 from Destination port ranges and select Save, so its other ports keep the source they have.')
            $impl.Add('If the client named no addresses, select the rule. If it allows only ports 22, 3389, 5985 or 5986, select Delete and then Yes. If it also allows other ports, remove 22, 3389, 5985 and 5986 from Destination port ranges and select Save.')
            Add-RepeatStep $impl $n $loop 'rule'
            # Another allow can still let the internet in once the listed rules are gone, such as the default rule
            # for the virtual network where a user-defined route sends 0.0.0.0/0 elsewhere. The effective security
            # rules of a network interface show the prefixes behind every rule, so they show what is still open.
            # The rules can differ for each network interface of a machine, so each one the rules applied to is read.
            # A rule on a subnet names no network interfaces, so they are listed from the virtual network. A stopped
            # machine shows no effective rules, so it gets the deny without the check rather than waiting to start.
            # The just-in-time deny is a network security group rule too, so a machine it covers is still read for
            # the security admin rules that come before every group.
            $effective = 'For each network interface the rules applied to, directly or through its subnet, go to Virtual machines, open the machine it belongs to, select Networking, select the network interface and select Effective security rules under Help. The page shows only the first 50 rules, so select Download and check the complete list in the file it saves. For a rule on a subnet, find every network interface in it on the Connected devices page of its virtual network, which lists each device with its subnet. For a machine that just-in-time VM access covers, check only the security admin rules, since its deny rules already stop internet sources on the ports it protects once the groups decide.'
            # The first rule that matches a connection's source, protocol and port decides it in each group, and the
            # groups of the subnet and the network interface must both allow it. A deny for named addresses leaves
            # every other address to the rules after it, so only a deny that covers the internet stops it. The deny
            # carries TCP only, like the rules CR-16 changes, so a rule for another protocol left for review keeps
            # working, and it skips only the ports of a rule left unchanged, which stay open until agreed. Azure
            # Virtual Network Manager security admin rules are listed too and apply before both groups: the first
            # that matches decides, Always Allow and Deny end the evaluation, and Allow passes it on to the groups.
            $reach = 'The page shows the group of the subnet and the group of the network interface. In each group, rules apply in priority order and the first rule that matches the source, protocol and port of a connection decides it, and a connection gets through only if every group on its path allows it. A deny rule stops internet sources only where its source is Any, 0.0.0.0/0, ::/0 or Internet and it covers the port, since a deny for named addresses leaves every other address to the rules after it. Where Azure Virtual Network Manager applies security admin rules to the virtual network, the page and the file list them too, under the name of the virtual network manager, and they apply before both groups. The first admin rule that matches a connection decides it: Always Allow lets it in whatever the groups say, Deny stops it whatever they say, and Allow passes it on to the groups.'
            $always = 'the first security admin rule that matches an internet source on the port is an Always Allow'
            $wide = 'lists 0.0.0.0/0, ::/0 or other public prefixes the client did not name or already allow on purpose, such as 0.0.0.0/1 and 128.0.0.0/1'
            $impl.Add(('{0} {1} For each of 22, 3389, 5985 and 5986, select each inbound allow rule that covers the port to see its source prefixes. The port is still open to the internet where an allow {2}, no deny that stops internet sources on that port comes before it in the same group, and the other group on the path, if there is one, lets the same connection through. Where {3}, the port stays open whatever the groups say, so no network security group change can close it: record that admin rule, with its virtual network manager, priority, source and ports, in the change record, escalate it to whoever owns the Virtual Network Manager configuration and never count the port as closed on that interface. Still add the deny below for it, so the deny applies once the admin rule is gone. Effective security rules lists rules only while the machine is running, so treat every management port of a stopped machine as open and note it in the change record, and read its security admin rules on the Security admin configurations tab of its virtual network under Settings > Network Manager. Leave the ports of a rule this change left unchanged and noted in the change record out of the deny on the network interfaces behind it, since that rule stays open until the client agrees a path, and note them with it. For every other management port found open, add a deny rule with protocol TCP, Source set to Service Tag and Internet, Destination port ranges set to those ports in the group that holds the allow rules for the named addresses, or in the group of the network interface, or of the subnet where the interface has none, when no addresses were named. Give it a free priority number from 100 to 4096 that is higher than every allow rule in that group for those ports from the named addresses or another source the client already allows on purpose, and lower than the allow that lets the internet in where that allow is a custom rule in the same group. Default rules, numbered 65000 and above, always come after it. Select Add and check again. If no such number is free, leave the rule as it is and review it with the client.' -f $effective, $reach, $wide, $always))
            $privateTest = if ($broad) { ' Any rule added for the private ranges allows only the management ports, from the ranges the client confirmed.' } else { '' }
            $testing = @(
                ('In the Azure portal, open the network security group of {0} and go to Settings > Inbound security rules.' -f (Get-EachStep $n 'rule'))
                ('Confirm each rule listed is gone, allows only the source addresses the client named, or no longer allows 22, 3389, 5985 or 5986 while its other ports keep their source, and that no other rule allows those ports over TCP from Any, Internet, 0.0.0.0/0 or ::/0.{0}' -f $privateTest)
                ('{0} {1} For each of 22, 3389, 5985 and 5986, confirm that no allow rule that covers the port and {2}, lets an internet source through under those rules, apart from the Azure platform address 168.63.129.16 and the ports of a rule this change left unchanged and noted in the change record, so no other internet source reaches those ports. Where {3}, never report that port as closed, even with the deny in place: confirm the admin rule is recorded in the change record and escalated to whoever owns the Virtual Network Manager configuration, and report the port as still open until that owner closes it. For a stopped machine, confirm instead that the deny from the Internet service tag is in place and read the Security admin configurations tab of its virtual network under Settings > Network Manager the same way.' -f $effective, $reach, $wide, $always)
                if ($held) { 'Report {0}, which -AdminRuleOpen names as held open by a security admin rule with Always Allow, as still open and escalated, never closed.' -f (Format-HeldOpen) }
                'Where just-in-time VM access was enabled, go to Microsoft Defender for Cloud > Workload protections > Just-in-time VM access and confirm the virtual machines behind the rules show on the Configured tab.'
                'Where Azure Bastion is the path, open one virtual machine behind each rule, select Connect > Bastion and confirm a session opens.'
                if ($winRm) { 'Where a rule opened 5985 or 5986 and WinRM is still needed, have the client confirm a WinRM connection to one machine behind it, through an approved just-in-time request or from a named address.' })
            $rollback = @(
                'In the Azure portal, open the network security group of the rule to restore and go to Settings > Inbound security rules.'
                'For a rule that was deleted, select + Add, enter the name, priority, source, source port ranges, destination, destination port ranges, protocol, action Allow and description recorded for it in the RESOURCES section and in change-requests.csv, and select Add.'
                'For a rule that was narrowed, select it, set Source and Destination port ranges back to the values recorded for it and select Save.'
                ('Delete the rules this change added: any for the named addresses{0}, any deny on the management ports from the Internet service tag, and the rule for the AzureBastionSubnet address range if Azure Bastion is no longer wanted.' -f $(if ($broad) { ' or the private ranges' } else { '' }))
                'If just-in-time VM access added a deny rule for the same ports at a lower priority number than the restored rule, give the restored rule a priority number below it, so it applies first as it did before the change.')

            # A subscription whose plan was not read stays unknown in the email, never on or off.
            $named = { param($list) Join-Words @($list | ForEach-Object { 'subscription ' + (Format-Subscription $_) }) }
            $unknownWords = 'I could not confirm whether Plan 2 is on in {0}, and I will check that before the change.' -f (& $named $unknownPlan)
            $planWords = if ($unknownPlan.Count -eq $subs) { 'I could not confirm which of these subscriptions have Plan 2, and I will check that before the change.' }
            elseif (-not $unknownPlan.Count -and -not $withoutPlan.Count) { 'Plan 2 is on in {0}.' -f (Get-Pick $subs 'this subscription' 'each of these subscriptions') }
            elseif (-not $unknownPlan.Count -and -not $withPlan.Count) { 'Plan 2 is not on in {0}, so this path would add the cost of Plan 2 for the servers there.' -f (Get-Pick $subs 'this subscription' 'these subscriptions') }
            elseif (-not $unknownPlan.Count) { 'Plan 2 is on in {0}, and not on in {1}, where this path would add the cost of Plan 2 for the servers.' -f (& $named $withPlan), (& $named $withoutPlan) }
            elseif (-not $withoutPlan.Count) { 'Plan 2 is on in {0}. {1}' -f (& $named $withPlan), $unknownWords }
            elseif (-not $withPlan.Count) { 'Plan 2 is not on in {0}, where this path would add the cost of Plan 2 for the servers. {1}' -f (& $named $withoutPlan), $unknownWords }
            else { 'Plan 2 is on in {0}, and not on in {1}, where this path would add the cost of Plan 2 for the servers. {2}' -f (& $named $withPlan), (& $named $withoutPlan), $unknownWords }
            $suggest = if ($unknownPlan.Count) { 'I will suggest the path that fits each subscription once I know which have Plan 2.' }
            elseif (-not $withoutPlan.Count) { 'Because Plan 2 is already on, I suggest just-in-time VM access.' }
            elseif (-not $withPlan.Count) { 'Because Plan 2 is not on, I suggest Azure Bastion, unless you would rather turn Plan 2 on.' }
            else { 'I suggest just-in-time VM access where Plan 2 is on and Azure Bastion elsewhere, unless you would rather turn Plan 2 on there.' }
            # Bastion does not provide WinRM, so where it may be the path, remote PowerShell needs its own.
            if ($winRm -and ($withoutPlan.Count -or $unknownPlan.Count)) { $suggest += ' Azure Bastion does not provide WinRM, so remote PowerShell would continue through just-in-time VM access or only from addresses you name.' }
            $effect = [System.Collections.Generic.List[object]]::new()
            $effect.Add(('Once {0} closed, anyone who connects to these machines over RDP, SSH or WinRM straight from the internet today will no longer be able to open a new connection that way. A connection that is already open stays up, because a rule change applies only to new connections.' -f (Get-Pick $n 'the rule is' 'the rules are')))
            if ($broad) { $effect.Add(('Connections from your own networks, such as a VPN, a peered virtual network or an office linked to Azure over a private connection, can keep working. {0}, so I will keep that private access in a rule of its own, built only from the address ranges of those networks that you confirm, unless you tell me nobody uses it.' -f $(if ($n -eq 1) { 'The rule is open to every address, which includes those networks' } elseif ($broad -eq $n) { 'The rules are open to every address, which includes those networks' } elseif ($broad -eq 1) { 'One of the rules is open to every address, which includes those networks' } else { 'Some of the rules are open to every address, which includes those networks' }))) }
            if ($otherPorts) { $effect.Add(('Where a rule also allows other ports, only 22, 3389, 5985 and 5986 are removed from it, and {0}' -f (Get-Pick $otherPorts 'its other ports stay as they are.' 'the other ports stay as they are.'))) }
            $effect.Add('There are two ways to keep administrator access in place of the open ports:')
            $effect.Add([string[]]@(
                    ('Just-in-time VM access keeps the ports closed and opens them only when an administrator asks, for that person''s own address and for a limited time, with every request recorded. It is part of Microsoft Defender for Servers Plan 2. {0}' -f $planWords)
                    ('Azure Bastion lets administrators connect from the Azure portal over an encrypted connection on port 443, so the machines need no management port open to the internet. It is billed by the hour from the moment it is deployed in a virtual network, and its free Developer tier is meant for development and test only.{0}' -f $(if ($winRm) { ' It provides RDP and SSH sessions only, so it cannot replace WinRM, which remote PowerShell uses.' } else { '' }))))
            $effect.Add($suggest)
            # A central policy the client may not know about keeps a port open that this change cannot close.
            if ($held) {
                $heldPorts = @($heldOpen.Values | ForEach-Object { $_.Ports }).Count
                $where = if ($held -eq 1) { 'On virtual machine {0}, a central network policy, a security admin rule in Azure Virtual Network Manager, keeps {1} {2} open to the internet.' -f @($heldOpen.Values)[0].Name, (Get-Pick $heldPorts 'port' 'ports'), (Join-Words @(@($heldOpen.Values)[0].Ports | Sort-Object { [int]$_ })) }
                else { 'On virtual machines {0}, a central network policy, a security admin rule in Azure Virtual Network Manager, keeps those ports open to the internet.' -f (Format-HeldOpen) }
                $effect.Add(('{0} That policy applies before any network security group rule, so this change cannot close {1} there, and {2} open until the policy changes. Could you tell me who manages your Virtual Network Manager configuration, so I can raise this with them?' -f $where, (Get-Pick $heldPorts 'that port' 'those ports'), (Get-Pick $heldPorts 'it stays' 'they stay')))
            }
            $email = New-ApprovalEmail -Subject 'closing remote management ports to the internet' `
                -Change @(('I would like to close {0} that let anyone on the internet reach RDP, SSH or WinRM, the remote management ports, on your Azure virtual machines.' -f (Get-Pick $n 'the network security group rule' "the $n network security group rules")), ('In their place, administrators would connect through just-in-time VM access or Azure Bastion{0}.' -f $(if ($winRm) { ', and remote PowerShell over WinRM through just-in-time VM access or from addresses you name' } else { '' }))) `
                -Why ('I recommend closing {0} because ports open to the whole internet are scanned all the time, and attackers try guessed or stolen passwords against them. Closing {1} removes that exposure while keeping a controlled way in for your administrators.' -f (Get-Pick $n 'this rule' 'these rules'), (Get-Pick $n 'it' 'them')) `
                -Effect $effect.ToArray() `
                -Listed (Get-Pick $n 'The change covers the rule below, shown with its network security group, priority, ports, source and where it applies:' 'The change covers the rules below, listed by subscription, each with its network security group, priority, ports, source and where it applies:') `
                -Resources (Get-EmailResourceList $resources { $_.Summary }) `
                -Reversal ('If anything unexpected comes up, I can recreate {0} exactly as {1} today, since every setting of {2} is recorded.' -f (Get-Pick $n 'the rule' 'any of the rules'), (Get-Pick $n 'it is' 'they are'), (Get-Pick $n 'it' 'each rule')) `
                -Ask ('Could you tell me who still needs RDP, SSH or WinRM to these machines from the internet, and from which addresses, and which replacement you would like, just-in-time VM access or Azure Bastion{0}?{1} With that agreed, could you approve this change for {2}?' -f $(if ($winRm) { ' for RDP and SSH' } else { '' }), $(if ($broad) { ' Could you also send me the address ranges of the virtual networks, peered networks and on-premises networks that connect to these machines, or tell me that nothing connects from them?' } else { '' }), $proposedDay) `
                -Options 'Where someone still needs direct access, I can keep the management ports open to their named addresses only, and any other port a rule allows keeps the access it has today. If another date suits you better, or anything listed above should stay out of the change, please let me know.'
            @{ Used = @('P0.3'); Notes = $notes.ToArray(); Cr = New-ChangeRequest @{
                    Number = 16; Key = 'management-ports'; Title = 'Close internet-facing RDP, SSH and WinRM rules on network security groups'
                    Description = 'Remove {0} that allow RDP, SSH or WinRM from any internet address, or narrow each to named source addresses, and give administrators just-in-time VM access or Azure Bastion in their place{1}.' -f (Get-Listed $n 'inbound security rule' 'inbound security rules'), $(if ($winRm) { ', with WinRM through just-in-time VM access or named source addresses only' } else { '' })
                    Purpose = 'Management ports open to the internet are scanned constantly and attacked with guessed or stolen credentials. Closing them removes that exposure while keeping a controlled way in for administrators.'
                    ResourceIntro = '{0} RDP, SSH or WinRM from any internet address on a workload subnet or network interface, with every property recorded for the rollback. The last lines give the path that fits each subscription{1}.' -f $(if ($n -eq 1) { 'The inbound rule below allows' } else { "The $n inbound rules below allow" }), $(if ($held) { ', and the machines a security admin rule keeps open' } else { '' })
                    ResourceLines = @(Format-ResourceList $resources) + $planLines + @(if ($held) {
                            '', 'Kept open by an Azure Virtual Network Manager security admin rule with Always Allow (-AdminRuleOpen), which CR-16 cannot close:'
                            foreach ($m in $heldOpen.Values) { '- {0}: {1} {2}' -f $m.Name, (Get-Pick $m.Ports.Count 'port' 'ports'), (Join-Words @($m.Ports | Sort-Object { [int]$_ })) }
                        })
                    Availability = 'No impact on the virtual machines, since only new remote management connections from the internet are refused and connections already open stay up.'
                    UserExperience = 'Administrators who connect straight from the internet over RDP, SSH or WinRM move to just-in-time VM access or Azure Bastion, as agreed with the client{0}.' -f $(if ($winRm) { ', and remote PowerShell over WinRM to just-in-time VM access or named source addresses, since Azure Bastion does not provide WinRM' } else { '' })
                    Dependencies = 'Needs the replacement path the client agreed in place first, just-in-time VM access with Defender for Servers Plan 2 on the subscription, or an Azure Bastion host that every network security group of the machines lets in on 22 and 3389 for RDP and SSH{0}{1}.' -f $(if ($winRm) { ', with WinRM through just-in-time VM access or named source addresses' } else { '' }), $(if ($broad) { ', and for a rule open to every address, the private ranges the client confirmed or its word that nothing connects from its own networks' } else { '' })
                    Implementation = $impl.ToArray(); Testing = $testing; Rollback = $rollback
                    References = @(
                        , @('Create, change, or delete a network security group', 'https://learn.microsoft.com/azure/virtual-network/manage-network-security-group')
                        , @('How network security groups filter network traffic', 'https://learn.microsoft.com/azure/virtual-network/network-security-group-how-it-works')
                        , @('Enable just-in-time access', 'https://learn.microsoft.com/azure/defender-for-cloud/enable-just-in-time-access')
                        , @('Deploy Azure Bastion from the Azure portal', 'https://learn.microsoft.com/azure/bastion/quickstart-host-portal')
                        , @('Configure NSG rules for Azure Bastion, target VM subnet', 'https://learn.microsoft.com/azure/bastion/bastion-nsg#target-vm-subnet')
                        , @('What is Azure Bastion', 'https://learn.microsoft.com/azure/bastion/bastion-overview')
                        , @('View effective security rules of a network interface', 'https://learn.microsoft.com/azure/virtual-network/virtual-network-network-interface#view-effective-security-rules')
                        , @('Effective security rules overview', 'https://learn.microsoft.com/azure/network-watcher/effective-security-rules-overview')
                        , @('Security admin rules in Azure Virtual Network Manager', 'https://learn.microsoft.com/azure/virtual-network-manager/concept-security-admins#how-security-admin-rules-and-network-security-groups-nsgs-are-evaluated')
                        , @('View configurations applied by Azure Virtual Network Manager', 'https://learn.microsoft.com/azure/virtual-network-manager/how-to-view-applied-configurations')
                        , @('Choose the right Azure Bastion SKU', 'https://learn.microsoft.com/azure/bastion/bastion-sku-comparison'))
                    Csv = $resources
                    Email = $email
                } } } }
    @{ Number = 17; Key = 'app-service-ftps'; Change = 'Plain FTP and FTP basic authentication turned off on App Service apps'; Sources = @()
       Build = {
            # Two parts on the same General settings tab. The FTP state part reads NB.5-FTPS-DETAIL, which lists every
            # site whose FTP state is not FtpsOnly or Disabled. Only AllAllowed is known to accept plain FTP. Microsoft
            # Learn documents no state App Service applies when none is set, so a site whose state reads empty, or reads
            # a value Learn does not list, is named in the index for a portal check instead of being changed or read as
            # safe. The FTP basic authentication part reads NB.5-FTPAUTH-DETAIL, added in collector 1.14.0, which lists
            # every app where it is On whatever its FTP state, and on an earlier pack CR-17 writes the FTP state part only.
            # The two parts are read apart, so CR-17 lists no source for the resolver and checks each one here: a part
            # that was not read leaves the other to stand alone, and only when neither was read does the state say why.
            $ftpsStatus = Get-Status 'NB.5-FTPS-DETAIL'
            $ftpsRead = Test-ResultRead 'NB.5-FTPS-DETAIL'
            $authStatus = Get-Status 'NB.5-FTPAUTH-DETAIL'
            $authRead = Test-ResultRead 'NB.5-FTPAUTH-DETAIL'
            if (-not $ftpsRead -and -not $authRead) {
                if ($ftpsStatus -eq 'MISSING') { return @{ State = Get-RecollectionState @('NB.5-FTPS-DETAIL', 'NB.5-FTPAUTH-DETAIL' | Where-Object { (Get-Status $_) -eq 'MISSING' }) } }
                if (Test-Unreadable 'NB.5-FTPS-DETAIL') { return @{ State = Get-UnreadableState 'NB.5-FTPS-DETAIL' } }
                return @{ State = 'Not collected (NB.5-FTPS-DETAIL {0})' -f $ftpsStatus }
            }
            $rows = @(if ($ftpsRead) { Get-Rows 'NB.5-FTPS-DETAIL' })
            $label = { '{0} (resource group {1})' -f (ConvertTo-CopyText $_.Name), (ConvertTo-CopyText $_.resourceGroup) }
            $unread = @($rows | Where-Object { (Get-Text $_.FtpsState) -notin 'AllAllowed', 'FtpsOnly', 'Disabled' } | ForEach-Object {
                    $state = ConvertTo-CopyText $_.FtpsState
                    if ($state) { '{0} (resource group {1}, FTP state {2})' -f (ConvertTo-CopyText $_.Name), (ConvertTo-CopyText $_.resourceGroup), $state } else { $_ | ForEach-Object $label }
                } | Sort-Object)
            $notes = [System.Collections.Generic.List[string]]::new()
            if ($unread.Count) {
                $notes.Add(('{0} left out of CR-17 because Resource Graph returned an empty FTP state, or one Microsoft Learn does not list, and Learn documents no state App Service applies when none is set, so {1} may still accept plain FTP: {2}. Check {3} under Settings > Configuration > General settings in the portal, and raise the change for any that shows All allowed.' -f (Get-Count $unread.Count 'App Service app' 'App Service apps'), (Get-Pick $unread.Count 'it' 'they'), ($unread -join ', '), (Get-Pick $unread.Count 'its FTP state' 'the FTP state of each one')))
            }
            if (-not $ftpsRead) { $notes.Add(('NB.5-FTPS-DETAIL {0}, so CR-17 covers FTP basic authentication only. Recollect the pack for the FTP state part.' -f $(if ($ftpsStatus -eq 'MISSING') { 'is not in this pack' } elseif (Test-Unreadable 'NB.5-FTPS-DETAIL') { 'is unreadable' } else { "reads $ftpsStatus" }))) }
            # The FTP basic authentication read, and the apps it could not read, which are never read as Off.
            $used = @(if ($ftpsRead) { 'NB.5-FTPS-DETAIL' }) + @(if ($authRead) { 'NB.5-FTPAUTH-DETAIL' })
            $recorded = @{}
            if ($authStatus -eq 'MISSING') { $notes.Add(('NB.5-FTPAUTH-DETAIL is not in this pack, so CR-17 covers the FTP state only. Recollect with CyberSOC collector {0} or later for the FTP basic authentication part.' -f $ftpAuthVersion)) }
            elseif (-not $authRead) { $notes.Add(('NB.5-FTPAUTH-DETAIL {0}, so CR-17 covers the FTP state only. Recollect the pack for the FTP basic authentication part.' -f $(if (Test-Unreadable 'NB.5-FTPAUTH-DETAIL') { 'is unreadable' } else { "reads $authStatus" }))) }
            elseif (Test-ResultRead 'NB.5-FTPAUTH') {
                foreach ($r in @(Get-Rows 'NB.5-FTPAUTH')) { if ((Get-Text $r.ReadStatus) -eq 'OK') { $recorded[(Get-Text $r.ResourceId).ToLowerInvariant()] = Get-Text $r.FtpBasicAuth } }
                $notRead = @(Get-Rows 'NB.5-FTPAUTH' | Where-Object { (Get-Text $_.ReadStatus) -ne 'OK' } | ForEach-Object $label | Sort-Object)
                if (-not $notRead.Count -and $authStatus -eq 'PARTIAL') {
                    $notes.Add('NB.5-FTPAUTH-DETAIL is partial although NB.5-FTPAUTH names no app it could not read, so Resource Graph may have returned only part of the app list, and an app with FTP basic authentication On may be missing from CR-17. Recollect the pack.')
                }
                if ($notRead.Count) {
                    $notes.Add(('{0} left out of the FTP basic authentication part of CR-17 because the collector could not read {1} setting: {2}. Check FTP Basic Auth Publishing Credentials under Settings > Configuration > General settings in the portal, and raise the change for any that shows On.' -f (Get-Count $notRead.Count 'App Service app' 'App Service apps'), (Get-Pick $notRead.Count 'its' 'their'), ($notRead -join ', ')))
                }
            }
            elseif ($authStatus -eq 'PARTIAL') { $notes.Add(('NB.5-FTPAUTH-DETAIL is partial, and NB.5-FTPAUTH, which names the apps the collector could not read, {0}, so an app with FTP basic authentication On may be missing from CR-17. Recollect the pack.' -f $(if ((Get-Status 'NB.5-FTPAUTH') -eq 'MISSING') { 'is not in this pack' } elseif (Test-Unreadable 'NB.5-FTPAUTH') { 'is unreadable' } else { 'reads ' + (Get-Status 'NB.5-FTPAUTH') }))) }
            # A slot belongs to a site, so the slot note is left out only when NB.5 shows the pack has no site at all.
            if (-not (Test-NoAppServiceSites)) {
                $notes.Add($(if ($authRead) { 'NB.5-FTPS-DETAIL and NB.5-FTPAUTH-DETAIL read the production site of each app. Deployment slots have an FTP state and an FTP basic authentication setting of their own, which the pack does not read, so CR-17 does not cover them. Check both on each slot in the portal.' }
                        else { 'NB.5-FTPS-DETAIL reads the production site of each app. Deployment slots have a configuration of their own, which the pack does not read, so CR-17 does not cover them. Check the FTP state of each slot in the portal.' }))
            }
            # One entry per app, keyed by resource ID: the FTP state part where it reads AllAllowed, the basic
            # authentication part where it reads On.
            $entries = [ordered]@{}
            $lowTls = [System.Collections.Generic.List[string]]::new()
            $lowTlsNames = [System.Collections.Generic.List[string]]::new()
            foreach ($row in @($rows | Where-Object { (Get-Text $_.FtpsState) -eq 'AllAllowed' })) {
                $tls = Format-TlsVersion $row.MinTlsVersion
                # FTPS only does not support TLS 1.0 or 1.1, so an app below 1.2 needs CR-04 first.
                if ($tls -in '1.0', '1.1') { $lowTls.Add(($row | ForEach-Object $label)); $lowTlsNames.Add((ConvertTo-CopyText $row.Name)) }
                $entries[(Get-Text $row.ResourceId).ToLowerInvariant()] = [pscustomobject]@{ Row = $row; State = 'AllAllowed'; Tls = $tls; Ftp = $true; Auth = $false }
            }
            foreach ($row in @(if ($authRead) { Get-Rows 'NB.5-FTPAUTH-DETAIL' | Where-Object { (Get-Text $_.FtpBasicAuth) -eq 'On' } })) {
                $key = (Get-Text $row.ResourceId).ToLowerInvariant()
                if ($entries.Contains($key)) { $entries[$key].Auth = $true }
                else { $entries[$key] = [pscustomobject]@{ Row = $row; State = Get-Text $row.FtpsState; Tls = ''; Ftp = $false; Auth = $true } }
            }
            $list = @($entries.Values)
            $n = $list.Count
            if (-not $n) {
                $state = if ($unread.Count) { 'Only apps without a recorded FTP state remain, see the notes' } else { 'No gaps found' }
                if ($authStatus -eq 'MISSING') { $state = $(if ($unread.Count) { 'Only apps without a recorded FTP state remain, the FTP basic authentication part needs recollection with CyberSOC collector {0} or later' } else { 'No FTP state gaps found, the FTP basic authentication part needs recollection with CyberSOC collector {0} or later' }) -f $ftpAuthVersion }
                elseif (-not $authRead) { $state = 'No FTP state gaps found, the FTP basic authentication part was not collected, see the notes' }
                elseif (-not $ftpsRead) { $state = 'No FTP basic authentication gaps found, the FTP state part was not collected, see the notes' }
                # A partial read can leave out an app that still has a gap, so it never reads as no gaps.
                $partialRead = @($used | Where-Object { (Get-Status $_) -eq 'PARTIAL' })
                if ($partialRead.Count) { $state = $(if ($state -eq 'No gaps found') { 'No gaps found in the apps read' } else { $state }) + ', partial collection scope ({0}), see the notes' -f ($partialRead -join ', ') }
                return @{ State = $state; Notes = $notes.ToArray() }
            }
            $ftp = @($list | Where-Object Ftp); $auth = @($list | Where-Object Auth)
            $f = $ftp.Count; $a = $auth.Count
            # On an app whose FTP state is Disabled nothing connects over FTP or FTPS, but Microsoft Learn says publishing
            # through local Git with deployment credentials also needs FTP basic authentication On, so every app is
            # confirmed with the client before the setting is turned off.
            $authClosed = @($auth | Where-Object { $_.State -eq 'Disabled' })
            $resources = @(foreach ($e in $list) {
                    $setting = 'FTP state ' + (Format-FtpState $e.State)
                    if ($e.Tls -in '1.0', '1.1') { $setting += ', minimum TLS ' + $e.Tls }
                    $basic = if ($e.Auth) { 'On' } else { $recorded[(Get-Text $e.Row.ResourceId).ToLowerInvariant()] }
                    if ($basic) { $setting += ', FTP basic authentication ' + $basic }
                    New-Resource $e.Row.Name $e.Row.resourceGroup $e.Row.subscriptionId $setting $e.Row.ResourceId
                })
            if ($lowTls.Count) {
                $notes.Add(('{0} in CR-17 {1} a minimum inbound TLS version below 1.2: {2}. FTPS only does not support TLS 1.0 or 1.1, so CR-04 sets 1.2 on {3} first, or the client chooses Disabled.' -f (Get-Count $lowTls.Count 'App Service app' 'App Service apps'), (Get-Pick $lowTls.Count 'has' 'have'), ($lowTls -join ', '), (Get-Pick $lowTls.Count 'it' 'them')))
            }
            if ($authRead) { $notes.Add('SCM Basic Auth Publishing Credentials, under the same General settings tab, is a separate setting and not part of CR-17. It covers Web Deploy, local Git and the other deployment methods that use the SCM (Kudu) site with deployment credentials, such as a GitHub Actions workflow or a pipeline that uses a publish profile, so turning it off can break deployments and needs its own change once the client confirms how each app is deployed. Microsoft Learn notes that FTP basic authentication also needs SCM basic authentication to be On, and its page on deployment credentials says that publishing through local Git or FTP/S needs both settings On, so the client email asks about local Git as well.') }
            else { $notes.Add('FTP Basic Auth Publishing Credentials, under the same General settings tab, is a separate setting and not part of CR-17 in this pack. Turning it off stops sign-in to the FTP and FTPS endpoint with deployment credentials, and CR-17 covers it on a pack that records it.') }
            $these = Get-Pick $n 'the application' 'these applications'
            $impl = [System.Collections.Generic.List[object]]::new()
            $impl.Add((Get-OpenStep $n 'App Services' 'app'))
            $impl.Add('Go to Settings > Configuration and select the General settings tab.')
            # Each value can change between collection and the change, so it is read again first and left unchanged
            # when it no longer shows the recorded value.
            if (-not $a) {
                $impl.Add('Under Platform settings, read FTP state. If it no longer shows All allowed, the state recorded for the app in the RESOURCES section, the app has changed since collection, so leave it unchanged, note it in the change record for the next pack and skip the remaining steps for it.')
                $impl.Add('If the client chose FTPS only for the app, read Minimum Inbound TLS Version. FTPS only does not support TLS 1.0 or 1.1, so if it shows 1.0 or 1.1, leave the app unchanged until CR-04 has set 1.2 on it, note it in the change record and skip the remaining steps for it.')
                $impl.Add('Set FTP state to FTPS only, or to Disabled only where the client confirmed that no tool, process or person uses FTP or FTPS on the app, to upload files or to download files or logs, select Apply and confirm.')
            }
            else {
                if ($f) {
                    $impl.Add(('{0}nder Platform settings, read FTP state. If it no longer shows All allowed, the state recorded for the app in the RESOURCES section, the app has changed since collection, so leave the FTP state unchanged and note it in the change record for the next pack.' -f $(if ($f -lt $n) { 'If the RESOURCES section lists FTP state All allowed for the app, u' } else { 'U' })))
                    $impl.Add('If FTP state still shows All allowed, set it to the state the client chose for the app: FTPS only, or Disabled only where the client confirmed that no tool, process or person uses FTP or FTPS on the app, to upload files or to download files or logs. Before setting FTPS only, read Minimum Inbound TLS Version. FTPS only does not support TLS 1.0 or 1.1, so if it shows 1.0 or 1.1, leave the FTP state unchanged until CR-04 has set 1.2 on the app and note it in the change record.')
                }
                $when = ' If it shows On, set it to Off only where the client confirmed that no deployment tool, process or person uses deployment credentials on the app to sign in to FTP or FTPS or to deploy through local Git. Otherwise leave it On and note it in the change record.'
                $impl.Add(('{0}ead FTP Basic Auth Publishing Credentials. If it shows Off, the app has changed since collection, so leave it as it is and note it in the change record.{1}' -f $(if ($a -lt $n) { 'If the RESOURCES section lists FTP basic authentication On for the app, r' } else { 'R' }), $when))
                $impl.Add('If a setting was changed, select Save, or Apply where the portal shows it, and confirm.')
            }
            Add-RepeatStep $impl $n 1 'app'
            $testing = @(
                ('In the Azure portal, open {0}, go to Settings > Configuration and select the General settings tab.' -f (Get-EachStep $n 'app'))
                if ($f) { $(if ($a) { 'Where the change set the FTP state, confirm FTP state shows FTPS only or Disabled under Platform settings, as agreed with the client for the app.' } else { 'Confirm FTP state shows FTPS only or Disabled under Platform settings, as agreed with the client for the app.' }) }
                if ($a) { 'Where the change turned FTP basic authentication off, confirm FTP Basic Auth Publishing Credentials shows Off.' })
            $rollback = @(
                'In the Azure portal, open the app to revert, go to Settings > Configuration and select the General settings tab.'
                if (-not $a) { 'Set FTP state back to All allowed, the state recorded for the app in the RESOURCES section, select Apply and confirm. An app left unchanged during the change needs no rollback.' }
                elseif (-not $f) { 'Set FTP Basic Auth Publishing Credentials back to On, the setting recorded for the app in the RESOURCES section, then select Save, or Apply where the portal shows it, and confirm. An app left unchanged during the change needs no rollback.' }
                else { 'Set back only the settings the change made, FTP state to All allowed and FTP Basic Auth Publishing Credentials to On, each as recorded for the app in the RESOURCES section, then select Save, or Apply where the portal shows it, and confirm. An app left unchanged during the change needs no rollback.' })
            # The client email.
            $ftpApps = if ($f -eq $n) { $these } else { Get-Pick $f 'the application whose FTP state is All allowed' 'the applications whose FTP state is All allowed' }
            $plainEffect = ('A deployment tool or a person that connects to {0} over plain FTP, to upload files or to download them, will be refused once the change is applied, and will need to connect over FTPS, which FTP clients such as WinSCP, Cyberduck and Visual Studio support, or move to another deployment method. Disabled also turns off FTPS, so it suits only an application that nothing connects to over FTP or FTPS, to upload files or to download files or logs.' -f $ftpApps)
            $tlsEffect = if ($lowTls.Count) { 'FTPS only needs a minimum inbound TLS version of 1.2, and {0} still {1} an older version, so for {2} I would set the minimum to 1.2 first, under my separate request for it, or set Disabled.' -f (@($lowTlsNames | Sort-Object) -join ', ' -replace ', ([^,]+)$', ' and $1'), (Get-Pick $lowTls.Count 'allows' 'allow'), (Get-Pick $lowTls.Count 'it' 'them') }
            $authApps = if ($a -eq $n) { $these } else { Get-Pick $a 'the application where it is on today' 'the applications where it is on today' }
            $authEffect = $(if ($authClosed.Count -eq $a) { 'With FTP basic authentication off, signing in to FTP or FTPS with the user name and password in the publish profile of {0}, or with a user''s own deployment credentials, would no longer work even if FTP were turned back on.' -f $authApps }
                else { 'Turning off FTP basic authentication means that signing in to FTP or FTPS with the user name and password in the publish profile of {0}, or with a user''s own deployment credentials, stops working once the change is applied, so FTP and FTPS can no longer be used there to upload files or to download files or logs.' -f $authApps }) +
                ' Microsoft notes that publishing through local Git with deployment credentials also needs this setting, so a local Git deployment that signs in that way would stop as well.'
            $closedNames = @($authClosed | ForEach-Object { ConvertTo-CopyText $_.Row.Name } | Sort-Object)
            $closedEffect = if ($authClosed.Count -eq $n) { 'The FTP state of {0} is already Disabled, so nothing connects over FTP or FTPS today, and the change matters only if a local Git deployment signs in with deployment credentials.' -f (Get-Pick $n 'the application' 'each application') }
            elseif ($authClosed.Count) { '{0} already {1} the FTP state Disabled, so for {2} the change matters only if a local Git deployment signs in with deployment credentials.' -f ($closedNames -join ', ' -replace ', ([^,]+)$', ' and $1'), (Get-Pick $authClosed.Count 'has' 'have'), (Get-Pick $authClosed.Count 'it' 'them') }
            $keepServing = '{0} keep serving {1} users as {2} now' -f $(if ($n -eq 1) { 'the application will' } else { 'these applications will' }), (Get-Pick $n 'its' 'their'), (Get-Pick $n 'it does' 'they do')
            $otherMethods = if ($a) { 'Deployment that signs in with Microsoft Entra ID is not affected, nor are deployment methods other than FTP and local Git, such as ZIP deploy, Web Deploy, GitHub Actions or an Azure DevOps pipeline without an FTP upload step, and {0}.' -f $keepServing }
            else { 'Deployment methods other than FTP, such as ZIP deploy, Web Deploy, local Git, GitHub Actions or an Azure DevOps pipeline without an FTP upload step, are not affected, and {0}.' -f $keepServing }
            $settingsLabel = { '{0} (resource group {1}, {2})' -f $_.Name, $_.ResourceGroup, ($_.Setting -replace ', minimum TLS 1\.[01]', '') }
            $authAsk = 'whether any deployment tool, scheduled process or person still uses deployment credentials, the user name and password from a publish profile or a user''s own, to sign in to FTP or FTPS or to deploy through local Git on {0}' -f $(if ($a -eq $n) { $these } else { Get-Pick $a 'the application where FTP basic authentication is on' 'the applications where FTP basic authentication is on' })
            $authHold = 'If something still uses deployment credentials that way, I will leave FTP basic authentication on for that application until it moves to another deployment method.'
            $email = if (-not $a) {
                New-ApprovalEmail -Subject 'turning off plain FTP on Azure App Service applications' `
                    -Change @(('I would like to stop plain FTP connections to {0} by setting {1} to FTPS only, or to Disabled where nothing connects to it over FTP or FTPS.' -f (Get-Yours $n 'App Service and Function applications'), (Get-Pick $n 'its FTP state' 'the FTP state of each')), 'FTP is an older way to upload files to an application, and FTPS is the same with the connection encrypted.') `
                    -Why ('I recommend this change because plain FTP sends the deployment user name, password and files unencrypted, so anyone who can see the traffic can read them and use the credentials to change {0}. FTPS only keeps file uploads working over an encrypted connection, and Disabled turns the FTP endpoint off where nothing uses it.' -f $these) `
                    -Effect @($plainEffect, $otherMethods, $tlsEffect | Where-Object { $_ }) `
                    -Listed (Get-Pick $n 'The application is listed below with its FTP state today:' 'The applications are listed below by subscription, each with its FTP state today:') `
                    -Resources (Get-EmailResourceList $resources { '{0} (resource group {1}, FTP state All allowed)' -f $_.Name, $_.ResourceGroup }) `
                    -Reversal ('The FTP state can be set back to All allowed, the state {0} today, at any time.' -f (Get-Pick $n 'the application has' 'each application has')) `
                    -Ask ('Could you let me know whether any deployment tool, scheduled process or person still connects to {0} over FTP or FTPS, to upload files or to download files or logs, and whether FTPS only or Disabled suits {1}? With that agreed, could you approve this change for {2}?' -f $these, (Get-Pick $n 'it' 'each one'), $proposedDay) `
                    -Options ('If something still uses plain FTP, I will hold the change for {0} until it uses FTPS, and I will set Disabled only where nothing uses FTP or FTPS at all. If another date suits you better, or anything listed above should stay out of the change, please let me know.' -f (Get-Pick $n 'the application' 'that application'))
            }
            elseif (-not $f) {
                New-ApprovalEmail -Subject 'turning off FTP basic authentication on Azure App Service applications' `
                    -Change @(('I would like to turn off FTP basic authentication publishing credentials on {0}.' -f (Get-Yours $n 'App Service and Function applications')), 'This setting lets a tool or a person sign in to the FTP and FTPS endpoint of an application with a deployment user name and password, such as those in its publish profile.') `
                    -Why ('I recommend turning it off because anyone who holds those credentials can sign in and change the files of {0}, while signing in with Microsoft Entra ID, a more secure way to deploy, uses tokens that expire, are issued for one application and cannot be reused.' -f $these) `
                    -Effect @($authEffect, $otherMethods, $closedEffect | Where-Object { $_ }) `
                    -Listed (Get-Pick $n 'The application is listed below with its FTP state and FTP basic authentication setting today:' 'The applications are listed below by subscription, each with its FTP state and FTP basic authentication setting today:') `
                    -Resources (Get-EmailResourceList $resources $settingsLabel) `
                    -Reversal ('FTP basic authentication can be turned back on, the setting {0} today, at any time.' -f (Get-Pick $n 'the application has' 'each application has')) `
                    -Ask ('Could you let me know {0}? With that confirmed, could you approve this change for {1}?' -f $authAsk, $proposedDay) `
                    -Options ($authHold + ' If another date suits you better, or anything listed above should stay out of the change, please let me know.')
            }
            else {
                New-ApprovalEmail -Subject 'turning off plain FTP and FTP basic authentication on Azure App Service applications' `
                    -Change @(('I would like to turn off plain FTP and FTP basic authentication publishing credentials on {0}, wherever either one is allowed today.' -f (Get-Yours $n 'App Service and Function applications')), 'FTP is an older way to upload files to an application, FTPS is the same with the connection encrypted, and basic authentication lets a tool or a person sign in to either with a deployment user name and password, such as those in the publish profile of the application.') `
                    -Why ('I recommend this change because plain FTP sends the deployment user name, password and files unencrypted, and anyone who holds those credentials can sign in and change the files of {0}. FTPS only keeps file uploads encrypted, Disabled turns the FTP endpoint off where nothing uses it, and turning basic authentication off leaves deployment to methods such as Microsoft Entra ID sign-in, whose tokens expire, are issued for one application and cannot be reused.' -f $these) `
                    -Effect @($plainEffect, $authEffect, $otherMethods, $tlsEffect, $closedEffect | Where-Object { $_ }) `
                    -Listed (Get-Pick $n 'The application is listed below with its FTP state and FTP basic authentication setting today:' 'The applications are listed below by subscription, each with its FTP state and, where it was read, its FTP basic authentication setting today:') `
                    -Resources (Get-EmailResourceList $resources $settingsLabel) `
                    -Reversal ('Each setting the change makes can be set back to the value {0} today, shown above, at any time.' -f (Get-Pick $n 'the application has' 'each application has')) `
                    -Ask ('Could you let me know whether any deployment tool, scheduled process or person still connects to {0} over FTP or FTPS, to upload files or to download files or logs, and whether FTPS only or Disabled suits {1}?{2} With that agreed, could you approve this change for {3}?' -f $ftpApps, (Get-Pick $f 'it' 'each one'), (' Could you also let me know {0}?' -f $authAsk), $proposedDay) `
                    -Options ('If something still uses plain FTP, I will hold the FTP state change for that application until it uses FTPS, and I will set Disabled only where nothing uses FTP or FTPS at all.{0} If another date suits you better, or anything listed above should stay out of the change, please let me know.' -f (' ' + $authHold))
            }
            $apps = Get-Pick $n 'app' 'apps'
            @{ Notes = $notes.ToArray(); Used = $used; Cr = New-ChangeRequest @{
                    Number = 17; Key = 'app-service-ftps'
                    Title = $(if (-not $a) { 'Set the FTP state to FTPS only or Disabled on App Service apps' } elseif (-not $f) { 'Turn off FTP basic authentication publishing credentials on App Service apps' } else { 'Set the FTP state to FTPS only or Disabled and turn off FTP basic authentication on App Service apps' })
                    Description = $(if (-not $a) { 'Set the FTP state to FTPS only, or to Disabled where the client confirms nothing uses FTP or FTPS, on {0}.' -f (Get-Listed $n 'App Service app' 'App Service and Function apps') }
                        elseif (-not $f) { 'Turn off FTP Basic Auth Publishing Credentials on {0}, so no one can sign in to FTP or FTPS on {1} with deployment credentials.' -f (Get-Listed $n 'App Service app' 'App Service and Function apps'), (Get-Pick $n 'it' 'them') }
                        else { 'On {0}, set the FTP state to FTPS only, or to Disabled where the client confirms nothing uses FTP or FTPS, where it reads All allowed, and turn off FTP Basic Auth Publishing Credentials where it is On.' -f (Get-Listed $n 'App Service app' 'App Service and Function apps') })
                    Purpose = $(if (-not $a) { 'Plain FTP sends the deployment credentials and files unencrypted, and {0} still {1} it. FTPS only keeps file uploads working over an encrypted connection, and Disabled turns the FTP endpoint off where it is not used.' -f (Get-Pick $n 'this app' 'these apps'), (Get-Pick $n 'allows' 'allow') }
                        elseif (-not $f) { 'FTP basic authentication lets anyone who holds a deployment user name and password, such as those in the publish profile, sign in to the FTP and FTPS endpoint and change the files of the app. Turning it off leaves deployment to methods such as Microsoft Entra ID sign-in, which Microsoft Learn describes as more secure.' }
                        else { 'Plain FTP sends the deployment credentials and files unencrypted, and FTP basic authentication lets anyone who holds those credentials sign in to the FTP and FTPS endpoint and change the files of the app. FTPS only or Disabled removes plain FTP, and turning basic authentication off leaves deployment to methods such as Microsoft Entra ID sign-in.' })
                    ResourceIntro = $(if (-not $a) { '{0} with the FTP state {1} today.' -f $(if ($n -eq 1) { 'The app below is listed' } else { "The $n apps below are listed" }), (Get-Pick $n 'it has' 'each one has') }
                        else { '{0} with the FTP state and, where it was read, the FTP basic authentication setting {1} today.' -f $(if ($n -eq 1) { 'The app below is listed' } else { "The $n apps below are listed" }), (Get-Pick $n 'it has' 'each one has') })
                    ResourceLines = Format-ResourceList $resources
                    Availability = $(if (-not $a) { 'No impact on the requests the {0} since the FTP state applies only to the FTP and FTPS endpoint used to upload and download files.' -f (Get-Pick $n 'app serves,' 'apps serve,') }
                        else { 'No impact on the requests the {0} since {1} only to the FTP and FTPS endpoint used to upload and download files.' -f (Get-Pick $n 'app serves,' 'apps serve,'), $(if ($f) { 'both settings apply' } else { 'the setting applies' }) })
                    UserExperience = 'No change for the users of the {0}.' -f $apps
                    Dependencies = $(if (-not $a) { 'Tools, processes and people that use plain FTP, or FTP or FTPS on an app set to Disabled, to upload or download files can no longer connect once the change is applied.' }
                        elseif (-not $f) { 'Tools, processes and people that use deployment credentials to sign in to FTP or FTPS, or possibly to deploy through local Git, can no longer do so once the change is applied.' }
                        else { 'Tools, processes and people that use plain FTP, FTP or FTPS on an app set to Disabled, or deployment credentials for FTP, FTPS or possibly local Git where FTP basic authentication is turned off, can no longer connect once the change is applied.' })
                    Implementation = $impl.ToArray()
                    Testing = $testing
                    Rollback = $rollback
                    References = @(
                        if ($f) {
                            , @('Deploy your app to Azure App Service using FTP/S, enforce FTPS', 'https://learn.microsoft.com/azure/app-service/deploy-ftp#enforce-ftps')
                            , @('Configure an App Service app, general settings', 'https://learn.microsoft.com/azure/app-service/configure-common#configure-general-settings')
                            , @('Secure your Azure App Service deployment, service-specific security', 'https://learn.microsoft.com/azure/app-service/overview-security#service-specific-security') }
                        , @('Disable basic authentication in Azure App Service deployments', 'https://learn.microsoft.com/azure/app-service/configure-basic-auth-disable')
                        if ($a) {
                            , @('Disable basic authentication in Azure App Service deployments, deploy without basic authentication', 'https://learn.microsoft.com/azure/app-service/configure-basic-auth-disable#deploy-without-basic-authentication')
                            , @('Manage deployment credentials for Azure App Service', 'https://learn.microsoft.com/azure/app-service/deploy-configure-credentials') })
                    Csv = $resources
                    Email = $email
                } } } }
    @{ Number = 18; Key = 'storage-private-containers'; Change = 'Blob containers set to private access'; Sources = @('DP.1-CONTAINERS-DETAIL')
       Build = {
            # DP.1-CONTAINERS-DETAIL lists every container set to Blob or Container in the accounts DP.1-CONTAINERS
            # listed in full. CR-18 changes the ones anyone can read today, in accounts that allow anonymous access.
            # The index names the rest: Microsoft Learn says the portal cannot change a container's level while its
            # account blocks anonymous access, and a static website ($web) is served from its own endpoint whatever
            # the level of $web. It also names the accounts whose containers were not listed and the FileStorage
            # accounts, which hold no blob service.
            $label = { '{0} (resource group {1})' -f (ConvertTo-CopyText $_.Account), (ConvertTo-CopyText $_.resourceGroup) }
            $rows = @(Get-Rows 'DP.1-CONTAINERS-DETAIL' | Where-Object { (Get-Text $_.AccessLevel) -in 'Blob', 'Container' })
            $web = @($rows | Where-Object { (Get-Text $_.Container) -eq '$web' })
            $blocked = @($rows | Where-Object { (Get-Text $_.Container) -ne '$web' -and -not (Test-True $_.ReadableToday) })
            $open = @($rows | Where-Object { (Get-Text $_.Container) -ne '$web' -and (Test-True $_.ReadableToday) })
            # One entry per account, its containers by name with the level recorded for each, so a large estate
            # reads as a line per account rather than a line per container.
            $byAccount = { param($list)
                foreach ($g in @($list | Group-Object { (Get-Text $_.AccountId).ToLowerInvariant() })) {
                    $first = $g.Group[0]
                    $containers = @($g.Group | Sort-Object { Get-Text $_.Container })
                    $names = @($containers | ForEach-Object { '{0} ({1})' -f (ConvertTo-CopyText $_.Container), (Get-Text $_.AccessLevel) })
                    [pscustomobject]@{
                        Resource = New-Resource $first.Account $first.resourceGroup $first.subscriptionId ('{0}: {1}' -f (Get-Count $names.Count 'container' 'containers'), ($names -join ', ')) $first.AccountId
                        Label = $first | ForEach-Object $label; Containers = $containers
                    }
                } }
            $notes = [System.Collections.Generic.List[string]]::new()
            if ($web.Count) {
                $webLines = @($web | ForEach-Object { '{0}, {1} access' -f ($_ | ForEach-Object $label), (Get-Text $_.AccessLevel) } | Sort-Object)
                $notes.Add(('{0} set to Blob or Container access left out of CR-18: {1}. A static website is served from the web endpoint of its account whatever the access level of $web, so setting it to Private would not close the site and would only stop anonymous reads of the same files through the blob endpoint. Set it to Private on its own once the owner confirms nothing links to the blob endpoint addresses of the site. An account that allows anonymous access stays out of CR-07 until then.' -f (Get-Count $web.Count 'static website container ($web)' 'static website containers ($web)'), ($webLines -join ', ')))
            }
            if ($blocked.Count) {
                $closed = @(& $byAccount $blocked | Sort-Object Label)
                $notes.Add(('{0} in {1} anonymous access left out of CR-18: {2}. The account setting keeps {3} closed, so no one can read {3} anonymously today, and Microsoft Learn notes that the portal cannot change the access level of a container while its account blocks anonymous access. {4} open again as soon as the account allowed anonymous access, so any change that relaxes the account setting also sets {3} to Private.' -f (Get-Count $blocked.Count 'container set to Blob or Container access' 'containers set to Blob or Container access'), $(if ($closed.Count -eq 1) { 'a storage account that blocks' } else { '{0} storage accounts that block' -f $closed.Count }), (@($closed | ForEach-Object { '{0}, {1}' -f $_.Label, $_.Resource.Setting }) -join ' / '), (Get-Pick $blocked.Count 'it' 'them'), (Get-Pick $blocked.Count 'It would' 'They would')))
            }
            if (Test-ResultRead 'DP.1-CONTAINERS') {
                $unread = @(Get-Rows 'DP.1-CONTAINERS' | Where-Object { (Get-Text $_.ReadStatus) -ne 'OK' } | ForEach-Object $label | Sort-Object)
                if ($unread.Count) {
                    $notes.Add(('{0} left out of CR-18 because DP.1-CONTAINERS could not list {1} containers: {2}. A container set to Blob or Container there is not in CR-18, so recollect the pack.' -f (Get-Count $unread.Count 'storage account' 'storage accounts'), (Get-Pick $unread.Count 'its' 'their'), ($unread -join ', ')))
                }
            }
            if (Test-ResultRead 'DP.1-DETAIL') {
                $files = @(Get-Rows 'DP.1-DETAIL' | Where-Object { (Get-Text $_.Kind) -ieq 'FileStorage' } | ForEach-Object { '{0} (resource group {1})' -f (ConvertTo-CopyText $_.Name), (ConvertTo-CopyText $_.resourceGroup) } | Sort-Object)
                if ($files.Count) {
                    $notes.Add(('{0} left out of CR-18 because {1} no blob service, so {2} no blob containers to change: {3}.' -f (Get-Count $files.Count 'FileStorage account' 'FileStorage accounts'), (Get-Pick $files.Count 'it holds' 'they hold'), (Get-Pick $files.Count 'it has' 'they have'), ($files -join ', ')))
                }
            }
            $groups = @(& $byAccount $open | Sort-Object { Format-Subscription $_.Resource.SubscriptionId }, { $_.Resource.ResourceGroup }, { $_.Resource.Name })
            $resources = @($groups | ForEach-Object Resource)
            $n = $open.Count
            $m = $resources.Count
            if (-not $n) { return @{ State = $(if ($rows.Count) { 'Only containers the account setting already blocks, or static website containers, remain, see the notes' } else { 'No gaps found' }); Notes = $notes.ToArray() } }
            $notes.Add('Before CR-18 is sent, the metrics of each account show whether anything still reads it without signing in. In the Azure portal, open Monitoring > Metrics on the account, choose the Blob metric namespace and the Transactions metric, and add a filter of Authentication equal to Anonymous. Where the account sends its resource logs to the workspace, StorageBlobLogs with AuthenticationType Anonymous names each container read. A content delivery network in front of a private container needs a shared access signature, which Azure Front Door can add.')
            # The CSV keeps one row per container, with the level recorded for the rollback.
            $csv = @(foreach ($g in $groups) {
                    foreach ($c in $g.Containers) {
                        New-Resource ('{0}/{1}' -f $c.Account, $c.Container) $c.resourceGroup $c.subscriptionId ('anonymous access level {0}, readable anonymously today' -f (Get-Text $c.AccessLevel)) $c.ResourceId
                    } })
            # A level or the account setting can change between collection and the change, so each account and
            # container is read again first, and anything that no longer matches the record is left unchanged.
            $impl = [System.Collections.Generic.List[object]]::new()
            $impl.Add((Get-OpenStep $m 'Storage accounts' 'storage account'))
            $impl.Add('Go to Settings > Configuration and read Allow Blob anonymous access. If it shows Disabled, the account has blocked anonymous access since collection, so its containers can no longer be read anonymously and the portal cannot change their access level. Leave the account unchanged, note it in the change record for the next pack and skip the remaining steps for it.')
            $impl.Add('Go to Data storage > Containers and read the Anonymous access level of each container listed for the account in the RESOURCES section. A container that no longer shows its recorded level has changed since collection, so leave it unchanged and note it in the change record. Leave out too any container the client asked to keep out of the change.')
            $impl.Add('Select the remaining listed containers, select Change access level, set Anonymous access level to Private (no anonymous access) and select OK.')
            $impl.Add('If another container in the account, other than $web, shows Blob or Container, it was opened after collection and is not part of this change, so note it in the change record for the next pack.')
            Add-RepeatStep $impl $m 1 'storage account'
            $these = Get-Pick $n 'the container' 'these containers'
            $email = New-ApprovalEmail -Subject 'private access for Azure Blob Storage containers' `
                -Change @(('I would like to set {0} to private access, so {1} can no longer be read without signing in.' -f (Get-Yours $n 'Azure Blob Storage containers'), (Get-Pick $n 'it' 'they')), ('{0} set to public access today, and {1} it, so anyone who has the address of a file there can read it.' -f (Get-Pick $n 'It is' 'Each of them is'), (Get-Pick $m 'its storage account allows' 'their storage accounts allow'))) `
                -Why ('I recommend this change because anyone can read {0} today without signing in, so a file placed there by mistake, or one meant only for a partner, is open to everyone. A private container also stays closed if the account setting is changed later.' -f $these) `
                -Effect @(
                    ('Setting {0} to private stops anonymous reads straight away. A website, an application, a content delivery network or a link that reads files from {1} without signing in, such as images, downloads or documents shared by link, will get an error once the change is applied.' -f $these, (Get-Pick $n 'it' 'them'))
                    'Applications and people that sign in, or that use a shared access signature or an account key, keep working as they do now.'
                    'A static website hosted in a storage account is served from its own web address, which the container access level does not control, so the change leaves it as it is.'
                    (Get-Pick $n 'Just before the change, I will check the container again and leave it unchanged if its access level has changed since my review.' 'Just before the change, I will check each container again and skip any whose access level has changed since my review.')) `
                -Listed $(if ($n -eq 1) { 'The container is listed below under its storage account, with its access level today. Anyone can read it without signing in:' } else { 'The {0} containers are listed below by subscription and storage account, with the number in each account and the access level of each container today. Anyone can read every one of them without signing in:' -f $n }) `
                -Resources (Get-EmailResourceList $resources { '{0} (resource group {1}), {2}' -f $_.Name, $_.ResourceGroup, $_.Setting }) `
                -Reversal ('{0} can be set back to the access level it has today at any time, as long as its storage account still allows anonymous access.' -f (Get-Pick $n 'The container' 'Each container')) `
                -Ask ('Before I schedule the change, could you ask the owner of {0} to confirm that it serves no public content? Where {1} does, its files can move to shared access signatures, which give time-limited links, either on their own or through a content delivery network such as Azure Front Door that adds the signature, and I will leave {2} out until they have moved. With that confirmed, could you approve this change for {3}?' -f (Get-Pick $n 'the container' 'each container'), (Get-Pick $n 'it' 'a container'), (Get-Pick $n 'it' 'that container'), $proposedDay)
            @{ Used = @('DP.1-CONTAINERS'); Notes = $notes.ToArray(); Cr = New-ChangeRequest @{
                    Number = 18; Key = 'storage-private-containers'; Title = 'Set public blob containers to private access'
                    Description = 'Set the anonymous access level of {0} to Private, in {1} anonymous access.' -f (Get-Listed $n 'blob container' 'blob containers'), $(if ($m -eq 1) { 'a storage account that allows' } else { "$m storage accounts that allow" })
                    Purpose = 'Anyone can read {0} today without signing in, so setting {1} to Private stops those anonymous reads straight away. A private container also stays closed if the account setting is relaxed later.' -f (Get-Pick $n 'this container' 'these containers'), (Get-Pick $n 'it' 'them')
                    ResourceIntro = '{0} set to Blob or Container access in {1} anonymous access, so anyone can read {2} today. {3} its containers with the level recorded at collection. CR-07 turns anonymous access off at the account level only where no container is set to Blob or Container, so a later pack picks {4} up for CR-07 once every container in it reads Private.' -f $(if ($n -eq 1) { 'The container below is' } else { "The $n containers below are" }), $(if ($m -eq 1) { 'a storage account that allows' } else { "$m storage accounts that allow" }), (Get-Pick $n 'it' 'them'), (Get-Pick $m 'The account lists' 'Each account lists'), (Get-Pick $m 'the account' 'each account')
                    ResourceLines = Format-ResourceList $resources
                    Availability = 'No impact on the storage service, since requests made with Microsoft Entra ID, a shared access signature or an account key keep working.'
                    UserExperience = 'Anyone who reads {0} without signing in, such as a website, an application, a CDN or a shared link, is refused once the change is applied.' -f (Get-Pick $n 'this container' 'these containers')
                    Dependencies = 'Needs the owner of each container to confirm it serves no public content, or to move that content to shared access signatures, on their own or through a CDN that adds one, before the change.'
                    Implementation = $impl.ToArray()
                    Testing = @(
                        ('In the Azure portal, open {0} and go to Data storage > Containers.' -f (Get-EachStep $m 'storage account'))
                        'Confirm the Anonymous access level column shows Private for each container listed for the account, apart from any left unchanged and noted in the change record.')
                    Rollback = @(
                        'In the Azure portal, open the storage account to revert and go to Settings > Configuration. A container can be set to Blob or Container only while Allow Blob anonymous access shows Enabled. If it shows Disabled, for example after CR-07, enabling it again opens every container in the account that is set to Blob or Container, so agree that with the client first.'
                        'Go to Data storage > Containers, select the container to revert, select Change access level, set Anonymous access level back to the level recorded for it in the RESOURCES section and select OK. A container left unchanged during the change needs no rollback.')
                    References = @(
                        , @('Configure anonymous read access for containers and blobs, set the anonymous access level for a container', 'https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-configure#set-the-anonymous-access-level-for-a-container')
                        , @('Remediate anonymous read access to blob data, detect anonymous requests from client applications', 'https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent#detect-anonymous-requests-from-client-applications')
                        , @('Static website hosting in Azure Storage, impact of setting the access level on the web container', 'https://learn.microsoft.com/azure/storage/blobs/storage-blob-static-website#impact-of-setting-the-access-level-on-the-web-container')
                        , @('Grant limited access to Azure Storage resources using shared access signatures', 'https://learn.microsoft.com/azure/storage/common/storage-sas-overview')
                        , @('Use Azure Front Door with Azure Storage Blobs', 'https://learn.microsoft.com/azure/frontdoor/scenario-storage-blobs'))
                    Csv = $csv
                    Email = $email
                } } } }
    @{ Number = 19; Key = 'disabled-account-roles'; Change = 'Roles removed from disabled accounts'; Sources = @('IA.15-DISABLED')
       Build = {
            # IA.15-DISABLED lists the disabled user accounts, IA.15-RBAC their Azure role assignments at every scope and
            # IA.15-ENTRA their Microsoft Entra role assignments. A role is listed only for an account IA.15-DISABLED
            # records as disabled, whatever the role results hold. A role assigned to the account itself is removed. A
            # role held through a group is taken away by removing the account from the group it sits in, the role group
            # or a group nested in it (MemberOfId, collector 1.10.0), so the group and its other members keep the role.
            # A group whose members a rule or on-premises Active Directory decides cannot lose a member here, so its
            # roles stay and the index names them, as it names every group role on a pack that does not record the
            # group each account sits in. Each side is written when it was read, and the index says which side is
            # missing and why, so a side that could not be read never reads as no gaps. The client email names the
            # accounts in an attached CSV rather than in its text, since the list can be long.
            $accounts = @{}
            foreach ($u in @(Get-Rows 'IA.15-DISABLED' | Where-Object { (Get-Text $_.AccountEnabled) -ieq 'false' })) {
                $id = (Get-Text $u.PrincipalId).ToLowerInvariant()
                if ($id) { $accounts[$id] = $u }
            }
            $sides = @(@{ Id = 'IA.15-RBAC'; Name = 'Azure' }, @{ Id = 'IA.15-ENTRA'; Name = 'Microsoft Entra' })
            $notes = [System.Collections.Generic.List[string]]::new()
            $read = @{}
            foreach ($side in $sides) {
                $read[$side.Id] = Test-ResultRead $side.Id
                $status = Get-Status $side.Id
                if (-not $read[$side.Id]) {
                    $why = if (Test-Unreadable $side.Id) { 'its result file is unreadable, so recollect or restore the pack' } elseif ($status -eq 'MISSING') { 'it was not collected' } else { 'it reads {0}: {1}' -f $status, (Get-ResultDetail $side.Id) }
                    $notes.Add(('The {0} roles of the disabled accounts are unknown, not a zero, because {1} could not be used: {2}' -f $side.Name, $side.Id, $why).TrimEnd('.') + '.')
                }
                elseif ($status -eq 'PARTIAL') { $notes.Add(('{0} was read in part, so CR-19 may miss some {1} roles: {2}' -f $side.Id, $side.Name, (Get-ResultDetail $side.Id)).TrimEnd('.') + '.') }
            }
            $rowsOf = { param([string]$Id, [string]$Side)
                if ($read[$Id]) {
                    foreach ($r in @(Get-Rows $Id | Where-Object { $accounts.ContainsKey((Get-Text $_.PrincipalId).ToLowerInvariant()) })) {
                        $r | Add-Member -NotePropertyName Side -NotePropertyValue $Side -Force -PassThru
                    } } }
            $azureAll = @(& $rowsOf 'IA.15-RBAC' 'Azure')
            $entraAll = @(& $rowsOf 'IA.15-ENTRA' 'Microsoft Entra')
            $azure = @($azureAll | Where-Object { (Get-Text $_.HeldThrough) -eq 'Direct' })
            $entra = @($entraAll | Where-Object { (Get-Text $_.HeldThrough) -eq 'Direct' })
            $who = { param($r)
                $upn = ConvertTo-CopyText $r.UserPrincipalName; $name = ConvertTo-CopyText $r.DisplayName
                if ($upn -and $name) { '{0} ({1})' -f $name, $upn } elseif ($upn) { $upn } elseif ($name) { $name } else { 'object ID ' + (Get-Text $r.PrincipalId) } }
            $scopeWords = { param($r)
                $scope = ConvertTo-CopyText $r.Scope
                switch (Get-Text $r.ScopeLevel) {
                    'Root' { 'the root scope' }
                    'Management group' { 'the management group' }
                    'Subscription' { 'the subscription' }
                    'Resource group' { 'resource group ' + (ConvertTo-CopyText $r.resourceGroup) }
                    'Resource' { 'resource {0} in resource group {1}' -f ($scope -split '/')[-1], (ConvertTo-CopyText $r.resourceGroup) }
                    default { 'scope ' + $scope } } }
            $heading = { param($r)
                $level = Get-Text $r.ScopeLevel
                if ($level -eq 'Root') { 'Root scope' }
                elseif ($level -eq 'Management group') { 'Management group ' + ((ConvertTo-CopyText $r.Scope) -split '/')[-1] }
                elseif (Get-Text $r.subscriptionId) { 'Subscription ' + (Format-Subscription $r.subscriptionId) }
                else { 'Management group ' + (ConvertTo-CopyText $r.Scope) } }
            # Subscriptions first, then the management groups and the root scope above them.
            $headingOrder = { param([string]$h) if ($h -like 'Subscription *') { "1 $h" } elseif ($h -like 'Management group *') { "2 $h" } else { "3 $h" } }
            # ConvertFrom-Json reads an ISO date as a DateTime, so an end date is written back in ISO form.
            $endOf = { param($r, [switch]$Day)
                $v = $r.EndDateUtc
                if ($v -is [datetime]) { $v.ToUniversalTime().ToString($(if ($Day) { 'yyyy-MM-dd' } else { "yyyy-MM-dd'T'HH:mm:ss'Z'" }), $inv) }
                elseif ($Day) { $t = Get-Text $v; $t.Substring(0, [Math]::Min(10, $t.Length)) }
                else { Get-Text $v } }
            # Azure takes 2.0 when a condition is given without a version.
            $conditionVersion = { param($r) $v = Get-Text $r.ConditionVersion; if ($v) { $v } else { '2.0' } }
            # What an Entra assignment is beyond its role: its type, its end and its scope, in plain words.
            $entraParts = { param($r)
                $parts = @(switch (Get-Text $r.AssignmentType) {
                        'Eligible' { 'eligible in Privileged Identity Management' }
                        'Activated' { 'activated from an eligible assignment' }
                        'Time-bound' { 'active' }
                        default { } })
                $end = & $endOf $r -Day
                if ($end -and (Get-Text $r.AssignmentType) -ne 'Activated') { $parts += 'until ' + $end }
                $scope = ConvertTo-CopyText $r.DirectoryScope
                if ($scope -match '^/administrativeUnits/(.+)$') { $parts += 'in administrative unit ' + $Matches[1] }
                elseif ($scope -match '^/([^/]+)$') { $parts += 'for the single application or other Microsoft Entra object with ID ' + $Matches[1] }
                elseif ($scope -and $scope -ne '/') { $parts += 'at directory scope ' + $scope }
                $parts }
            $entraKind = { param($r)
                $parts = @(& $entraParts $r)
                $role = ConvertTo-CopyText $r.Role
                if ($parts.Count) { '{0} ({1})' -f $role, ($parts -join ', ') } else { $role } }

            # Roles held through a group. From collector 1.10.0 each row names the group the account sits in
            # (MemberOfId), the role group itself or a group nested in it, with the path between them (GroupPath) and
            # whether a member can be removed from it (MemberOfType Assigned, Dynamic or On-premises). The account is
            # removed from that group, which takes away every role the group holds, directly or through the groups it is
            # nested in. A dynamic membership group takes its members from a rule and a synced group from Active
            # Directory, so neither can lose a member here, and their roles are named for a separate review.
            $viaGroup = @(@($azureAll) + @($entraAll) | Where-Object { (Get-Text $_.HeldThrough) -eq 'Group' })
            $pathKnown = -not @($viaGroup | Where-Object { -not (Get-Text $_.MemberOfId) }).Count
            $removable = @(if ($pathKnown) { $viaGroup | Where-Object { (Get-Text $_.MemberOfType) -eq 'Assigned' } })
            $fixed = @(if ($pathKnown) { $viaGroup | Where-Object { (Get-Text $_.MemberOfType) -ne 'Assigned' } })
            $pathOf = { param($r) @(@($r.GroupPath) | ForEach-Object { ConvertTo-CopyText $_ } | Where-Object { $_ }) }
            $groupLabel = { param($r) '{0} ({1})' -f (ConvertTo-CopyText $r.GroupName), (Get-Text $r.GroupId) }
            $memberOfLabel = { param($r) '{0} ({1})' -f (ConvertTo-CopyText $r.MemberOfName), (Get-Text $r.MemberOfId) }
            $roleWords = { param($r) if ($r.Side -eq 'Azure') { 'Azure {0} on {1}' -f (ConvertTo-CopyText $r.Role), (ConvertTo-CopyText $r.Scope) } else { 'Microsoft Entra {0}' -f (& $entraKind $r) } }
            # An account that reaches one assignment through two groups has a row for each group, one removal each, but
            # holds one role, so the roles are counted by assignment and account, never by row.
            $roleKey = { param($r) '{0}|{1}|{2}' -f $r.Side, $(if (Get-Text $r.AssignmentId) { (Get-Text $r.AssignmentId).ToLowerInvariant() } else { '{0}|{1}|{2}|{3}' -f (Get-Text $r.Role), (Get-Text $r.Scope), (Get-Text $r.DirectoryScope), (Get-Text $r.AssignmentType) }), (Get-Text $r.PrincipalId).ToLowerInvariant() }
            $distinctRoles = { param($rows) @($rows | Group-Object { & $roleKey $_ } | ForEach-Object { $_.Group[0] }) }
            # ", nested in platform-operators (id) through ops-tier2" for a member of a nested group, else nothing.
            $nestedWords = { param($r)
                if ((Get-Text $r.GroupId).ToLowerInvariant() -eq (Get-Text $r.MemberOfId).ToLowerInvariant()) { return '' }
                $path = & $pathOf $r
                $via = @(if ($path.Count -gt 2) { $path[1..($path.Count - 2)] })
                ', nested in {0}{1}' -f (& $groupLabel $r), $(if ($via.Count) { ' through ' + (Join-Words $via) } else { '' }) }
            $fixedWhy = { param($r) if ((Get-Text $r.MemberOfType) -eq 'Dynamic') { 'a dynamic membership group whose members a rule decides' } else { 'synced from on-premises Active Directory, where its members are managed' } }
            # One removal per account and group it sits in, whatever roles that takes away.
            $memberships = @($removable | Group-Object { '{0}|{1}' -f (Get-Text $_.PrincipalId).ToLowerInvariant(), (Get-Text $_.MemberOfId).ToLowerInvariant() } | ForEach-Object {
                    $first = $_.Group[0]
                    [pscustomobject]@{ Account = $first; MemberOfId = Get-Text $first.MemberOfId; MemberOfName = ConvertTo-CopyText $first.MemberOfName; Label = (& $memberOfLabel $first); Rows = @($_.Group) } } |
                    Sort-Object { & $who $_.Account }, MemberOfName, MemberOfId)
            # "group ops-tier2 (id), nested in platform-operators (id), which holds Azure Contributor on /subscriptions/...
            # and Microsoft Entra Helpdesk Administrator"; a group nested in more than one role group names each.
            $membershipWords = { param($ms)
                $parts = @(foreach ($g in @($ms.Rows | Group-Object { (Get-Text $_.GroupId).ToLowerInvariant() } | Sort-Object { ConvertTo-CopyText $_.Group[0].GroupName })) {
                        $r = $g.Group[0]
                        $roles = Join-Words @($g.Group | ForEach-Object { & $roleWords $_ } | Sort-Object -Unique)
                        if ((Get-Text $r.GroupId).ToLowerInvariant() -eq $ms.MemberOfId.ToLowerInvariant()) { 'which holds {0}' -f $roles }
                        else { '{0}, which holds {1}' -f (& $nestedWords $r).TrimStart(', '), $roles } })
                'group {0}, {1}' -f $ms.Label, ($parts -join ', and ') }
            $inScopeAzure = @($azure) + @($removable | Where-Object Side -eq 'Azure')
            $inScopeEntra = @($entra) + @($removable | Where-Object Side -eq 'Microsoft Entra')
            if ($viaGroup.Count -and -not $pathKnown) {
                $groupLines = @(foreach ($g in @($viaGroup | Group-Object { (Get-Text $_.GroupId).ToLowerInvariant() })) {
                        $first = $g.Group[0]
                        $roles = @($g.Group | ForEach-Object { & $roleWords $_ } | Sort-Object -Unique)
                        $members = @($g.Group | ForEach-Object { & $who $_ } | Sort-Object -Unique)
                        'group {0}, which holds {1}, with the disabled {2} {3}' -f (& $groupLabel $first), ($roles -join ' and '), (Get-Pick $members.Count 'member' 'members'), ($members -join ', ')
                    })
                $notes.Add(('{0} roles through group membership, which CR-19 leaves unchanged because the pack does not record the group each account sits in: {1}. Collect again with CyberSOC collector 1.10.0 or later, and CR-19 removes each account from its group.' -f (Get-Count @($viaGroup | ForEach-Object PrincipalId | Sort-Object -Unique).Count 'disabled account holds' 'disabled accounts hold'), (@($groupLines | Sort-Object) -join ' / ')))
            }
            $k = @($memberships | ForEach-Object { (Get-Text $_.Account.PrincipalId).ToLowerInvariant() } | Sort-Object -Unique).Count
            if ($memberships.Count) {
                $notes.Add(('{0} roles through group membership, and CR-19 removes {1} from the group it sits in: {2}.' -f (Get-Count $k 'disabled account holds' 'disabled accounts hold'), (Get-Pick $k 'it' 'each one'), (@($memberships | ForEach-Object { '{0} from {1}' -f (& $who $_.Account), (& $membershipWords $_) }) -join ' / ')))
            }
            $fixedAccounts = @($fixed | ForEach-Object { (Get-Text $_.PrincipalId).ToLowerInvariant() } | Sort-Object -Unique).Count
            if ($fixed.Count) {
                $fixedLines = @($fixed | Group-Object { '{0}|{1}' -f (Get-Text $_.PrincipalId).ToLowerInvariant(), (Get-Text $_.MemberOfId).ToLowerInvariant() } | ForEach-Object {
                        $r = $_.Group[0]
                        '{0} through group {1}, {2}{3}, which holds {4}' -f (& $who $r), (& $memberOfLabel $r), (& $fixedWhy $r), (& $nestedWords $r), (Join-Words @($_.Group | ForEach-Object { & $roleWords $_ } | Sort-Object -Unique)) } | Sort-Object)
                $notes.Add(('{0} roles through a group whose members CR-19 cannot change, so they stay as they are: {1}. Review each with the group owner, who can change the membership rule, or remove the account from the group in Active Directory so that the next sync takes the role away.' -f (Get-Count $fixedAccounts 'disabled account holds' 'disabled accounts hold'), ($fixedLines -join ' / ')))
            }
            if ($read['IA.15-RBAC']) {
                if ((Get-Text $parameters.AccessPath) -eq 'Lighthouse' -or (Get-ResultDetail 'IA.15-RBAC') -match 'Lighthouse') {
                    $notes.Add("The Azure role assignments were read through Azure Lighthouse, where Resource Graph shows the managing tenant's delegations instead of the client's own role assignments, so CR-19 may miss Azure roles the disabled accounts hold. Collect the pack again with a direct sign-in to the client tenant before sending CR-19.")
                }
                $notes.Add('IA.15-RBAC reads the subscriptions in the pack and the management groups and root scope above them, so a role in another subscription of the tenant is not listed. Resource Graph also holds the active Azure role assignments only, not the eligible assignments of Privileged Identity Management for Azure resources, so CR-19 does not list those. Where the client uses it, check Privileged Identity Management > Azure resources for each disabled account before sending.')
            }
            # An Activated role is removed through the eligible assignment behind it, which is restored from the record
            # only when IA.15-ENTRA holds it as an Eligible row of the same account, role and directory scope. Any other
            # Activated row has its eligibility schedule recorded from Privileged Identity Management before removal.
            $entraKey = { param($r) '{0}|{1}|{2}' -f (Get-Text $r.PrincipalId).ToLowerInvariant(), (Get-Text $r.RoleDefinitionId).ToLowerInvariant(), (Get-Text $r.DirectoryScope) }
            $eligibleKeys = @{}
            foreach ($r in @($entra | Where-Object { (Get-Text $_.AssignmentType) -eq 'Eligible' })) { $eligibleKeys[(& $entraKey $r)] = $true }
            $activated = @($entra | Where-Object { (Get-Text $_.AssignmentType) -eq 'Activated' })
            $unmatched = @($activated | Where-Object { -not $eligibleKeys.ContainsKey((& $entraKey $_)) })
            $pimBlind = $false
            # Without the active schedule instances an activated or time-bound assignment reads as Standing, so a
            # Standing row is trusted only when an Activated or Time-bound row shows the instances were read.
            $activeUnsure = $false
            if ($read['IA.15-ENTRA']) {
                $pim = @($entraAll | ForEach-Object { Get-Text $_.PimRead } | Sort-Object -Unique)
                $pimBlind = (Get-ResultDetail 'IA.15-ENTRA') -match '^Eligible assignments not visible' -or @($pim | Where-Object { $_ -in 'NoPermission', 'Error' }).Count
                if ($pimBlind) {
                    $activeUnsure = -not @($entraAll | Where-Object { (Get-Text $_.AssignmentType) -in 'Activated', 'Time-bound' }).Count
                    $noPermission = 'NoPermission' -in $pim -or (Get-ResultDetail 'IA.15-ENTRA') -match 'needs RoleManagement\.Read\.Directory'
                    $notes.Add(('Eligible Microsoft Entra role assignments were not visible to the collection ({0}), so CR-19 lists only the active ones, {1}and a disabled account whose only roles are eligible is not listed at all. {2}, or check Privileged Identity Management > Microsoft Entra roles > Assignments > Eligible assignments before sending CR-19.' -f $(if ($noPermission) { 'it needs RoleManagement.Read.Directory' } else { 'the Privileged Identity Management schedules could not be read' }), $(if ($activeUnsure) { 'an activated assignment reads as Standing, ' } else { '' }), $(if ($noPermission) { 'Grant the permission and collect again' } else { 'Collect again' })))
                }
            }

            $direct = $azure.Count + $entra.Count
            $n = $direct + $memberships.Count
            if (-not $n) {
                $missing = @($sides | Where-Object { -not $read[$_.Id] })
                if ($missing.Count -eq $sides.Count) { return @{ State = ('Not collected ({0})' -f (@($sides | ForEach-Object { '{0} {1}' -f $_.Id, (Get-Status $_.Id) }) -join ', ')); Notes = $notes.ToArray() } }
                # A side read in part may hold a role it did not return, so it never reads as no gaps, whatever the
                # other side reads.
                $partial = @($sides | Where-Object { $read[$_.Id] -and (Get-Status $_.Id) -eq 'PARTIAL' } | ForEach-Object Id)
                $state = if ($partial.Count) { 'No roles found in what was read, {0} read in part' -f ($partial -join ' and ') }
                elseif ($viaGroup.Count -and $pathKnown) { 'Only roles held through groups whose members cannot be changed here remain' }
                elseif ($viaGroup.Count) { 'Only roles held through groups remain' }
                elseif ($missing.Count) { 'No gaps found in the {0} roles' -f (@($sides | Where-Object { $read[$_.Id] })[0].Name) }
                else { 'No gaps found' }
                if ($missing.Count) { $state += ', {0} roles not collected ({1} {2})' -f $missing[0].Name, $missing[0].Id, (Get-Status $missing[0].Id) }
                if ($state -ne 'No gaps found') { $state += ', see the notes' }
                return @{ State = $state; Notes = $notes.ToArray() }
            }
            $people = @(@($inScopeAzure) + @($inScopeEntra) | Group-Object { (Get-Text $_.PrincipalId).ToLowerInvariant() } | ForEach-Object { $_.Group[0] } | Sort-Object { & $who $_ })
            $m = $people.Count
            $synced = @($people | Where-Object { Test-True $accounts[(Get-Text $_.PrincipalId).ToLowerInvariant()].OnPremisesSyncEnabled } | ForEach-Object { & $who $_ })
            if ($synced.Count) {
                $notes.Add(('{0} in CR-19 {1} synced from on-premises Active Directory: {2}. {3} disabled state comes from Active Directory, so re-enabling {4} there turns {4} back on in Microsoft Entra ID at the next sync. Removing the roles still applies, and whoever manages Active Directory should know that an account turned back on starts without them.' -f (Get-Count $synced.Count 'account' 'accounts'), (Get-Pick $synced.Count 'is' 'are'), ($synced -join ', '), (Get-Pick $synced.Count 'Its' 'Their'), (Get-Pick $synced.Count 'it' 'them')))
            }
            # An account with the most powerful roles may be one kept for emergency access, so it is named before sending.
            $top = @(@($inScopeEntra | Where-Object { (Get-Text $_.RoleDefinitionId) -in '62e90394-69f5-4237-9190-012177145e10', 'e8611ab8-c189-46e8-94e1-60213ab1f814', '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' }) + @($inScopeAzure | Where-Object { (Get-Text $_.ScopeLevel) -eq 'Root' }) |
                    ForEach-Object { & $who $_ } | Sort-Object -Unique)
            if ($top.Count) {
                $notes.Add(('{0} in CR-19 {1} Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator or a role at the Azure root scope: {2}. Ask the client whether any of them is an emergency access account before sending, and leave it out of the change if it is. Privileged Identity Management does not remove the last Global Administrator assignment.' -f (Get-Count $top.Count 'account' 'accounts'), (Get-Pick $top.Count 'holds' 'hold'), ($top -join ', ')))
            }
            $notes.Add('IA.15-DISABLED reads user accounts only. Disabled service principals are not read, so CR-19 does not cover them.')
            $attachment = 'CR-{0:00}-{1}.email.csv' -f 19, 'disabled-account-roles'
            $notes.Add(('CR-19 names the accounts and their roles in {0} rather than in its email, since the list can be long. Attach the file to the email.' -f $attachment))

            # RESOURCES: the Azure role assignments by subscription, then the management groups and root scope above them,
            # one line each with its role, scope and assignment, then the Microsoft Entra role assignments, then the
            # group memberships removed, each with the group the account sits in and the roles the group holds.
            $lines = [System.Collections.Generic.List[string]]::new()
            if ($azure.Count) {
                $lines.Add('Azure role assignments, removed at the scope where each was made:')
                foreach ($g in @($azure | Group-Object { & $heading $_ } | Sort-Object { & $headingOrder $_.Name })) {
                    $lines.Add(''); $lines.Add($(if ($g.Name -eq 'Root scope') { 'Root scope: /' } else { $g.Name -replace '^(Subscription|Management group) ', '$1: ' }))
                    foreach ($r in @($g.Group | Sort-Object { & $who $_ }, { Get-Text $_.Scope }, { Get-Text $_.Role })) {
                        $lines.Add(('- {0}, object ID {1}: {2} on {3}, role definition {4}, scope {5}, assignment {6}{7}' -f (& $who $r), (Get-Text $r.PrincipalId), (ConvertTo-CopyText $r.Role), (& $scopeWords $r), ((Get-Text $r.RoleDefinitionId) -split '/')[-1], (ConvertTo-CopyText $r.Scope), ((Get-Text $r.AssignmentId) -split '/')[-1], $(if (Get-Text $r.Condition) { ', with a condition (version {0}) kept exactly in change-requests.csv: {1}' -f (& $conditionVersion $r), (ConvertTo-CopyText $r.Condition) } else { '' })))
                    }
                }
            }
            if ($entra.Count) {
                if ($lines.Count) { $lines.Add('') }
                $lines.Add('Microsoft Entra role assignments:')
                foreach ($r in @($entra | Sort-Object { & $who $_ }, { Get-Text $_.Role }, { Get-Text $_.AssignmentType })) {
                    $lines.Add(('- {0}, object ID {1}: {2}, {3}, role definition {4}, directory scope {5}, assignment {6}{7}' -f (& $who $r), (Get-Text $r.PrincipalId), (ConvertTo-CopyText $r.Role), (Get-Text $r.AssignmentType), (Get-Text $r.RoleDefinitionId), (ConvertTo-CopyText $r.DirectoryScope), (ConvertTo-CopyText $r.AssignmentId), $(if ($r -in $unmatched) { ', with no Eligible line, so its eligibility schedule is recorded before removal' } else { '' })))
                }
            }
            if ($memberships.Count) {
                if ($lines.Count) { $lines.Add('') }
                $lines.Add('Group memberships removed, which take the roles the group holds away from the account:')
                foreach ($ms in $memberships) {
                    $lines.Add(('- {0}, object ID {1}: removed from {2}' -f (& $who $ms.Account), (Get-Text $ms.Account.PrincipalId), (& $membershipWords $ms)))
                }
            }
            # The CSV keeps each assignment in full, role, role definition, scope and account, for the rollback, and each
            # group membership with the group the account is removed from.
            $csv = @(
                foreach ($r in @($azure | Sort-Object { & $who $_ }, { Get-Text $_.Scope })) {
                    $row = New-Resource ('{0}, {1}' -f (Get-Text $r.UserPrincipalName), (Get-Text $r.Role)) $r.resourceGroup $r.subscriptionId '' $r.AssignmentId
                    # The CSV is data, so a condition is kept exactly as Azure has it, angle brackets and all.
                    $row.Setting = 'Azure role {0} ({1}) at {2} scope {3}, assigned to {4} (object ID {5}){6}' -f (Get-Text $r.Role), (Get-Text $r.RoleDefinitionId), (Get-Text $r.ScopeLevel).ToLowerInvariant(), (Get-Text $r.Scope), (Get-Text $r.UserPrincipalName), (Get-Text $r.PrincipalId), $(if (Get-Text $r.Condition) { ', condition version {0}: {1}' -f (& $conditionVersion $r), [string]$r.Condition } else { '' })
                    $row
                }
                foreach ($r in @($entra | Sort-Object { & $who $_ }, { Get-Text $_.Role })) {
                    New-Resource ('{0}, {1}' -f (Get-Text $r.UserPrincipalName), (Get-Text $r.Role)) '' '' ('Microsoft Entra role {0} ({1}), {2}{3}, directory scope {4}, assigned to {5} (object ID {6}){7}' -f (Get-Text $r.Role), (Get-Text $r.RoleDefinitionId), (Get-Text $r.AssignmentType), $(if (& $endOf $r) { ' until ' + (& $endOf $r) } else { '' }), (Get-Text $r.DirectoryScope), (Get-Text $r.UserPrincipalName), (Get-Text $r.PrincipalId), $(if ($r -in $unmatched) { ', eligible assignment not collected, its schedule is recorded in the change record before removal' } else { '' })) $r.AssignmentId
                }
                foreach ($ms in $memberships) {
                    # The resource ID is the Graph path that removes the member, groups/{group}/members/{account}/$ref.
                    New-Resource ('{0}, member of group {1}' -f (Get-Text $ms.Account.UserPrincipalName), $ms.MemberOfName) '' '' ('Membership of {0}, held by {1} (object ID {2})' -f (& $membershipWords $ms), (Get-Text $ms.Account.UserPrincipalName), (Get-Text $ms.Account.PrincipalId)) ('/groups/{0}/members/{1}/$ref' -f $ms.MemberOfId, (Get-Text $ms.Account.PrincipalId))
                })
            $activeEntra = @($entra | Where-Object { (Get-Text $_.AssignmentType) -in 'Standing', 'Time-bound' })
            $eligibleEntra = @($entra | Where-Object { (Get-Text $_.AssignmentType) -eq 'Eligible' })
            $pimEntra = @($entra | Where-Object { (Get-Text $_.AssignmentType) -in 'Eligible', 'Activated' })
            $unsureStanding = @(if ($activeUnsure) { $entra | Where-Object { (Get-Text $_.AssignmentType) -eq 'Standing' } })
            $rootAzure = @($azure | Where-Object { (Get-Text $_.ScopeLevel) -eq 'Root' })
            $conditioned = @($azure | Where-Object { Get-Text $_.Condition })
            # Each account is read again first. One turned back on since collection keeps every role, and is noted.
            $impl = [System.Collections.Generic.List[object]]::new()
            $impl.Add((Get-OpenStep $m 'Microsoft Entra ID > Users' 'account'))
            $impl.Add('On the Overview page, read Account status, shown as Account enabled under Settings on the Properties tab. If it shows the account as enabled, the account has been turned back on since collection, so leave every role it holds unchanged, note it in the change record for the next pack and skip the remaining steps for it. Leave out too any account the client asked to keep out of the change.')
            $azureRemoveStep = 0
            if ($azure.Count - $rootAzure.Count) {
                $azureRemoveStep = $impl.Count + 2
                $impl.Add(('For each Azure role assignment listed for the account{0}, open its scope in the Azure portal, the management group, subscription, resource group or resource named in the RESOURCES section, go to Access control (IAM) and select the Role assignments tab.' -f $(if ($rootAzure.Count) { ' below the root scope' } else { '' })))
                # Resource Graph holds no schedule, so a time-bound assignment or a Privileged Identity Management activation
                # reads like a permanent one. Its end is read from the portal first, for the rollback.
                $impl.Add('Search for the account and find the assignment of the listed role whose Scope column reads This resource. Where the tab shows a State column and it reads Active time-bound, record in the change record the end time of the assignment, shown by selecting Edit columns and then End time, since the collection does not hold it and the rollback restores the assignment as time-bound with that end. A resource scope shows no State column, so for an assignment on a resource, where the client uses Privileged Identity Management, read its end on the Active roles tab of Privileged Identity Management > Azure resources > the resource > Roles > the role instead. Select Remove and then Yes. An assignment shown as Inherited was made at a parent scope and is removed there, under its own line in the RESOURCES section.')
            }
            if ($rootAzure.Count) {
                $impl.Add(@('The portal cannot remove an assignment at the root scope (/). As a Global Administrator with elevated access, remove each one listed for the account from Azure Cloud Shell, with the object ID and role definition listed for it, then read the assignments left at the root scope:'
                        'az role assignment delete --assignee OBJECT-ID --role ROLE-DEFINITION-ID --scope "/"'
                        'az role assignment list --assignee OBJECT-ID --scope "/"'))
            }
            $activeStep = 0; $pimStep = 0
            if ($activeEntra.Count) {
                $activeStep = $impl.Count + 1
                # Without the schedule instances a Standing row may be time-bound or an activation, so its end and any
                # eligibility behind it are read from Privileged Identity Management first, for the rollback.
                $impl.Add($(if ($unsureStanding.Count) { 'The collection could not read the Privileged Identity Management schedules, so a role listed as Standing may be time-bound or activated from an eligible assignment. Before removing one, open the role in Privileged Identity Management > Microsoft Entra roles > Roles and record in the change record the start time, end time and directory scope the Active assignments tab shows for the account, so the rollback restores what was there. ' } else { '' }) + 'For each Microsoft Entra role listed as Standing or Time-bound for the account, go to Microsoft Entra ID > Roles and administrators, open the role, select the account, select Remove assignment and then Yes. A role listed with an administrative unit is opened from Microsoft Entra ID > Administrative units > the unit > Roles and administrators, and one listed for a single application or other object from that object, such as App registrations > the application > Roles and administrators. Where the account holds the role at more than one scope, remove only the assignment whose scope matches the one listed. With Privileged Identity Management the role opens on its Active assignments tab, where the account has a Remove link.')
            }
            if ($pimEntra.Count) {
                $pimStep = $impl.Count + 1
                $matchedWords = if ($unmatched.Count) { 'A role listed as Activated with an Eligible line for the same role and directory scope comes from that eligible assignment' } else { 'A role listed as Activated comes from an eligible assignment' }
                $impl.Add(@(
                        if ($eligibleEntra.Count) { 'For each Microsoft Entra role listed as Eligible for the account, go to Privileged Identity Management > Microsoft Entra roles > Roles, open the role, find the account on the Eligible assignments tab, with the scope listed for the role, and select Remove.' }
                        if ($activated.Count -gt $unmatched.Count) { '{0} and ends when its activation expires, so remove that eligible assignment the same way, and where the Active assignments tab still lists the activation with a Remove link, select it as well.' -f $matchedWords }
                        # The CSV holds only the activation's expiry, so the eligibility is recorded before it is removed.
                        if ($unmatched.Count) { 'For each Microsoft Entra role listed as Activated with no Eligible line for the same role and directory scope, the eligible assignment it comes from was not collected, so its schedule is not in this change request. Go to Privileged Identity Management > Microsoft Entra roles > Roles, open the role and find the account on the Eligible assignments tab, with the scope listed for the role. Before removing it, record in the change record its start time, end time, role and directory scope as the tab shows them, then select Remove. Where the eligible assignment is held by a group rather than the account, leave it in place and note it in the change record, since removing it changes access for the group. Where the Active assignments tab still lists the activation with a Remove link, select it as well.' }) -join ' ')
            }
            if ($memberships.Count) {
                # The account leaves the group it sits in, which the RESOURCES line names first: the role group itself, or
                # a group nested in it. The group keeps its roles and its other members. A membership whose every recorded
                # role is gone since collection, or whose chain to every role group is broken, no longer carries a role, so
                # it stays, since leaving the group would take away whatever else the group gives. One that still carries
                # a role on its line is removed, however many of the others are gone.
                $impl.Add('For each group membership listed for the account, first confirm that it still gives the account a role on its line: go to Microsoft Entra ID > Groups > All groups, open each group the line says holds a role and check under Azure role assignments or Assigned roles that it still holds the roles listed, then, where the line says the account sits in a group nested in it, open that nested group and each group named between them and confirm under Group memberships that each is still a member of the one above it. Where the membership still carries at least one of the roles listed, remove it as follows, and note in the change record any role on the line that was already gone. Only where every role on the line is gone, or the chain to every group holding one is broken, does the membership no longer give the account a role, so leave it unchanged and note it in the change record. To remove it, open the group the account is removed from, the first group named on its line, which is the group that holds the role or a group nested in it. Select Members, find the account, select it, select Remove and then Yes. If Membership type on the group reads Dynamic User or Dynamic Device, or Source reads Windows server AD, a member cannot be removed here, so leave the membership unchanged and note it in the change record for a review with the group owner.')
            }
            Add-RepeatStep $impl $m 1 'account'
            $testing = [System.Collections.Generic.List[object]]::new()
            $testing.Add(('In the Azure portal, go to Microsoft Entra ID > Users and open {0}.' -f (Get-EachStep $m 'account')))
            if ($azure.Count - $rootAzure.Count) { $testing.Add('Select Azure role assignments, choose each subscription listed for the account in turn, and confirm that none of the Azure role assignments recorded for it remains, apart from any left unchanged and noted in the change record. For an assignment at a management group, open Access control (IAM) on the management group and search for the account on the Role assignments tab.') }
            if ($rootAzure.Count) { $testing.Add('Confirm that the list of assignments left at the root scope, read in the implementation, no longer shows the account.') }
            if ($entra.Count) { $testing.Add('Select Assigned roles and confirm that none of the Microsoft Entra roles recorded for the account appears under Active assignments or Eligible assignments, apart from any left unchanged and noted in the change record.') }
            if ($memberships.Count) { $testing.Add('Select Groups and confirm that no group recorded for the account under group memberships is listed, apart from any left unchanged and noted in the change record, then confirm under Azure role assignments and Assigned roles that the roles those groups hold no longer reach the account.') }
            $rollback = [System.Collections.Generic.List[object]]::new()
            # Each Azure assignment matches one rollback step only: recorded without a condition below the root, with a
            # condition at any scope, or without a condition at the root.
            $plainAzure = @($azure | Where-Object { (Get-Text $_.ScopeLevel) -ne 'Root' -and -not (Get-Text $_.Condition) })
            # A time-bound assignment is given its end on the Assignment type tab, before Review + assign creates it.
            $timeBound = 'Where step {0} recorded the assignment in the change record as Active time-bound, select Active on the Assignment type tab and set Assignment duration to Time bound with the recorded end date and time, never Permanent, so the role is not restored for longer than it was held. A resource scope has no Assignment type tab, so recreate a time-bound assignment on a resource from Privileged Identity Management > Azure resources > the resource > Roles > Add assignments instead, as Active with the recorded end date and time.' -f $azureRemoveStep
            $plainRoot = @($rootAzure | Where-Object { -not (Get-Text $_.Condition) })
            if ($plainAzure.Count) { $rollback.Add(('For an Azure role assignment{0}, open the scope recorded for it in the RESOURCES section, go to Access control (IAM) > Add > Add role assignment, select the recorded role, select User, group, or service principal and select the account by its object ID. {1} Then select Review + assign.' -f $(if ($conditioned.Count) { ' recorded without a condition' } else { '' }), $timeBound)) }
            if ($conditioned.Count) {
                # A condition narrows what the role grants, so recreating the assignment without it would grant more. The
                # command reads the condition from a file, since a shell would expand a token such as $key_case_sensitive$
                # written inside double quotes, and Bash does not expand the output of a command substitution again.
                $rollback.Add(@(('For an Azure role assignment recorded with a condition, recreate it with that condition, copied exactly from change-requests.csv, since without it the role grants more than it did. At a subscription, resource group or resource, open the recorded scope, go to Access control (IAM) > Add > Add role assignment, select the recorded role, select User, group, or service principal and the account by its object ID, then on the Conditions tab select Add condition, set Editor type to Code, paste the condition and select Save.{0} The portal cannot add a condition at a management group or root scope, so recreate one there from Azure Cloud Shell in Bash, as a Global Administrator with elevated access for the root scope: run code condition.txt, paste the condition, save the file, then run the command below with the recorded object ID, role definition ID, scope and condition version. The condition is read from the file, so the shell changes none of its characters.{1}:' -f $(if ($azureRemoveStep) { ' Where step {0} recorded it as Active time-bound, set it to Active and Time bound with the recorded end date and time on the Assignment type tab, then select Review + assign. A resource scope has no Assignment type tab, so recreate a time-bound one on a resource from Privileged Identity Management > Azure resources > the resource > Roles > Add assignments instead, as Active with the recorded end date and time and the condition added with Add condition.' -f $azureRemoveStep } else { ' Then select Review + assign.' }), $(if ($azureRemoveStep) { ' Where step {0} recorded the assignment at a management group as Active time-bound, open Access control (IAM) on the management group afterwards, select the State link of the new assignment on the Role assignments tab, set Assignment duration to Time bound with the recorded end date and time and select Save' -f $azureRemoveStep } else { '' }))
                        'az role assignment create --assignee-object-id OBJECT-ID --assignee-principal-type User --role ROLE-DEFINITION-ID --scope SCOPE --condition "$(cat condition.txt)" --condition-version VERSION'))
            }
            if ($plainRoot.Count) { $rollback.Add(('For an assignment at the root scope{0}, run in Azure Cloud Shell, as a Global Administrator with elevated access: az role assignment create --assignee-object-id OBJECT-ID --assignee-principal-type User --role ROLE-DEFINITION-ID --scope "/"' -f $(if ($conditioned.Count) { ' recorded without a condition' } else { '' }))) }
            if ($activeEntra.Count) { $rollback.Add('For a Microsoft Entra role recorded as Standing or Time-bound, go to Microsoft Entra ID > Roles and administrators, open the recorded role, select Add assignments, select the account and assign it, as active with the recorded end date where one is recorded{0}. A role recorded with an administrative unit is assigned from that unit, and one recorded for a single application or other object (a directory scope of the form /OBJECT-ID) from that object, such as App registrations > the application > Roles and administrators, never from the tenant-wide list, which would grant the role across the tenant.' -f $(if ($unsureStanding.Count) { ', or, for a role listed as Standing, with the end time step {0} recorded in the change record, never as permanent where it recorded one' -f $activeStep } else { '' })) }
            if ($pimEntra.Count) {
                $rollback.Add(@(
                        if ($eligibleEntra.Count) { 'For a Microsoft Entra role recorded as Eligible, go to Privileged Identity Management > Microsoft Entra roles > Roles, open the role, select Add assignments, select the account, set Assignment type to Eligible with the recorded end date, if any, and select Assign. For a role recorded with an administrative unit or a single application, select that scope and the recorded unit or application on the Add assignments page, so the role is not restored across the tenant.' }
                        if ($activated.Count -gt $unmatched.Count) { $(if ($unmatched.Count) { 'A role recorded as Activated with an Eligible line for the same role and directory scope needs no rollback of its own, since it came from that eligible assignment.' } else { 'A role recorded as Activated needs no rollback of its own, since it came from the eligible assignment recorded with it.' }) }
                        # The schedule recorded in the change record is the only record of that eligibility.
                        if ($unmatched.Count) { 'For a role recorded as Activated with no Eligible line, restore the eligible assignment it came from with the schedule recorded in the change record at step {0}, never from change-requests.csv, which holds only the activation''s expiry: go to Privileged Identity Management > Microsoft Entra roles > Roles, open the recorded role, select Add assignments, select the account and, for a role recorded with an administrative unit or a single application, that scope and the recorded unit or application. Select Next, set Assignment type to Eligible, clear Permanently eligible, set the recorded end date and time and select Assign. Never restore it as permanent, unless the change record shows that it had no end date, in which case leave Permanently eligible selected. An eligible assignment left in place because a group holds it needs no rollback.' -f $pimStep }) -join ' ')
            }
            if ($memberships.Count) { $rollback.Add('For a group membership, go to Microsoft Entra ID > Groups > All groups, open the recorded group, select Members, select Add members, find the account by its object ID, select it and select Select. Every role the group holds, itself or through the groups it is nested in, reaches the account again at once.') }
            $rollback.Add(('change-requests.csv carries each assignment in full, with the role, role definition ID, scope, any condition and the account object ID{0}{1}. An account left unchanged during the change needs no rollback.' -f $(if ($memberships.Count) { ', and each group membership with the group the account is removed from and the roles it holds' } else { '' }), $(if ($unmatched.Count -or $unsureStanding.Count -or ($azure.Count - $rootAzure.Count)) { ', and the change record carries each end time or schedule recorded before removal' } else { '' })))
            if ($unmatched.Count) {
                $notes.Add(('{0} listed as Activated in CR-19 {1} no Eligible line for the same account, role and directory scope, {2}: {3}. Step {4} of the implementation records the schedule of the eligible assignment behind {5} from Privileged Identity Management in the change record before removing it, and the rollback restores it from that record.' -f (Get-Count $unmatched.Count 'Microsoft Entra role' 'Microsoft Entra roles'), (Get-Pick $unmatched.Count 'has' 'have'), $(if ($pimBlind) { 'since eligible assignments were not visible to the collection' } else { 'since the collection holds no eligible assignment for it' }), (@($unmatched | Sort-Object { & $who $_ }, { Get-Text $_.Role } | ForEach-Object { '{0}, {1} at directory scope {2}' -f (& $who $_), (ConvertTo-CopyText $_.Role), (ConvertTo-CopyText $_.DirectoryScope) }) -join ' / '), $pimStep, (Get-Pick $unmatched.Count 'it' 'each')))
            }

            # The email names the accounts in an attached CSV, one line per role in plain words, and counts them by
            # subscription, then the management groups and root scope, then the Microsoft Entra roles. The roles a group
            # the change cannot alter holds are in the CSV too, marked as left unchanged, so the client sees every role.
            $azureWhere = { param($r)
                switch (Get-Text $r.ScopeLevel) {
                    'Root' { 'the root scope, above every subscription' }
                    'Management group' { 'the management group ' + (((ConvertTo-CopyText $r.Scope) -split '/')[-1]) }
                    'Subscription' { 'the subscription ' + (Format-Subscription $r.subscriptionId) }
                    'Resource group' { 'resource group {0} in the subscription {1}' -f (ConvertTo-CopyText $r.resourceGroup), (Format-Subscription $r.subscriptionId) }
                    'Resource' { 'resource {0} in resource group {1} in the subscription {2}' -f (((ConvertTo-CopyText $r.Scope) -split '/')[-1]), (ConvertTo-CopyText $r.resourceGroup), (Format-Subscription $r.subscriptionId) }
                    default { 'scope ' + (ConvertTo-CopyText $r.Scope) } } }
            $entraWhere = { param($r)
                $scope = ConvertTo-CopyText $r.DirectoryScope
                if ($scope -match '^/administrativeUnits/(.+)$') { 'administrative unit ' + $Matches[1] }
                elseif ($scope -match '^/([^/]+)$') { 'the single application or other Microsoft Entra object with ID ' + $Matches[1] }
                elseif ($scope -and $scope -ne '/') { 'directory scope ' + $scope }
                else { 'the whole directory' } }
            $heldWords = { param($r)
                if ((Get-Text $r.HeldThrough) -ne 'Group') { return 'Assigned to the account' }
                $path = & $pathOf $r
                if ($path.Count -le 1) { return 'Group ' + (ConvertTo-CopyText $r.GroupName) }
                $nested = Join-Words @($path | Select-Object -Skip 1)
                'Group {0}, through {1} {2} nested in it' -f (ConvertTo-CopyText $r.GroupName), (Get-Pick ($path.Count - 1) 'the group' 'the groups'), $nested }
            $actionWords = { param($r)
                if ((Get-Text $r.HeldThrough) -ne 'Group') { 'Remove the role assignment' }
                elseif ((Get-Text $r.MemberOfType) -eq 'Assigned') { 'Remove the account from group ' + (ConvertTo-CopyText $r.MemberOfName) }
                elseif ((Get-Text $r.MemberOfType) -eq 'Dynamic') { 'None in this change, the members of group {0} come from a rule' -f (ConvertTo-CopyText $r.MemberOfName) }
                else { 'None in this change, group {0} is synced from on-premises Active Directory' -f (ConvertTo-CopyText $r.MemberOfName) } }
            $detailWords = { param($r)
                if ($r.Side -eq 'Azure') { if (Get-Text $r.Condition) { 'with a condition that narrows what the role allows' } else { '' } }
                else { @(& $entraParts $r | Where-Object { $_ -notmatch '^(in administrative unit |for the single application |at directory scope )' }) -join ', ' } }
            # A spreadsheet reads a cell that starts with =, +, - or @ as a formula, quoted or not, and a display name or
            # role name comes from the directory, so such a value gets an apostrophe in front, which the spreadsheet
            # hides and which keeps the text as it is.
            $cellSafe = { param([string]$v) if ($v -match '^[=+\-@]') { "'" + $v } else { $v } }
            $emailRows = @(@($inScopeAzure) + @($inScopeEntra) + @($fixed) | ForEach-Object {
                    [pscustomobject]@{
                        Account = & $cellSafe (ConvertTo-CopyText $_.DisplayName); SignInName = & $cellSafe (ConvertTo-CopyText $_.UserPrincipalName)
                        RoleType = $(if ($_.Side -eq 'Azure') { 'Azure' } else { 'Microsoft Entra' }); Role = & $cellSafe (ConvertTo-CopyText $_.Role)
                        Scope = & $cellSafe $(if ($_.Side -eq 'Azure') { & $azureWhere $_ } else { & $entraWhere $_ })
                        Detail = & $cellSafe (& $detailWords $_); HeldThrough = & $cellSafe (& $heldWords $_); Action = & $cellSafe (& $actionWords $_) } } |
                    Sort-Object Account, SignInName, @{ Expression = { if ($_.RoleType -eq 'Azure') { 0 } else { 1 } } }, Scope, Role, Detail)
            $emailCsv = @('"Account","SignInName","RoleType","Role","Scope","Detail","HeldThrough","Action"')
            if ($emailRows.Count) { $emailCsv = @($emailRows | ConvertTo-Csv -NoTypeInformation) }
            $summary = { param($rows)
                $holders = @($rows | ForEach-Object { (Get-Text $_.PrincipalId).ToLowerInvariant() } | Sort-Object -Unique).Count
                $roles = @(& $distinctRoles $rows).Count
                $through = @(& $distinctRoles @($rows | Where-Object { (Get-Text $_.HeldThrough) -eq 'Group' })).Count
                '{0} holding {1}{2}' -f (Get-Count $holders 'account' 'accounts'), (Get-Count $roles 'role' 'roles'), $(if (-not $through) { '' } elseif ($through -eq $roles) { Get-Pick $roles ', held through a group' ', all held through a group' } else { ', {0} of them through a group' -f $through }) }
            # A role that reaches an account through two groups is on a line for each, since each names a group to leave.
            $emailLines = @($inScopeAzure) + @($inScopeEntra) + @($fixed)
            $multiPath = $emailLines.Count -ne @(& $distinctRoles $emailLines).Count
            # The file also lists a role that stays, through a group the change cannot alter, so the email then speaks of
            # the roles marked for removal rather than of every role in the file, and, where such a role belongs to an
            # account outside the change, of every disabled account in the file rather than of the accounts in the change.
            $inChange = @($people | ForEach-Object { (Get-Text $_.PrincipalId).ToLowerInvariant() })
            $others = @($fixed | ForEach-Object { (Get-Text $_.PrincipalId).ToLowerInvariant() } | Where-Object { $_ -notin $inChange } | Sort-Object -Unique).Count
            $emailResources = [System.Collections.Generic.List[object]]::new()
            foreach ($g in @($inScopeAzure | Group-Object { & $heading $_ } | Sort-Object { & $headingOrder $_.Name })) {
                $emailResources.Add("$($g.Name):")
                $emailResources.Add([string[]]@(& $summary $g.Group))
            }
            if ($inScopeEntra.Count) {
                $emailResources.Add('Microsoft Entra ID directory roles:')
                $emailResources.Add([string[]]@(& $summary $inScopeEntra))
            }
            $kinds = @(if ($inScopeAzure.Count) { 'Azure' }; if ($inScopeEntra.Count) { 'Microsoft Entra' }) -join ' and '
            $ask = if (-not $memberships.Count) { 'I would like to remove the {0} roles still assigned to {1} in your tenant.' -f $kinds, (Get-Count $m 'disabled account' 'disabled accounts') }
            elseif (-not $direct) { 'I would like to remove the {0} roles that {1} still {2} in your tenant through group membership, by removing {3} from the group that holds the role.' -f $kinds, (Get-Count $m 'disabled account' 'disabled accounts'), (Get-Pick $m 'holds' 'hold'), (Get-Pick $m 'it' 'each one') }
            else { 'I would like to remove the {0} roles still held by {1} in your tenant, by removing the roles assigned to {2} and, where a group holds a role for {3}, by removing {4} from the group.' -f $kinds, (Get-Count $m 'disabled account' 'disabled accounts'), (Get-Pick $m 'the account itself' 'the accounts themselves'), (Get-Pick $m 'it' 'one of them'), (Get-Pick $m 'it' 'that account') }
            $effect = @(
                ('Nobody loses access today, since {0} cannot sign in.' -f (Get-Pick $m 'the account' 'these accounts'))
                ('If {0} comes back into use later, it would need its roles assigned again{1}.' -f (Get-Pick $m 'the account' 'one of these accounts'), $(if ($memberships.Count) { ' and its group memberships restored' } else { '' }))
                $(if ($memberships.Count) { 'Where a group holds the role, I would remove {0} from the group rather than take the role away from the group, so its other members keep their access, and where {1} in a group nested inside the one that holds the role, it is the nested group {2} removed from. Removing an account from a group also ends anything else the group gives it, such as access to an application, which does not matter while the account is disabled.' -f (Get-Pick $k 'the account' 'the account concerned'), (Get-Pick $k 'the account sits' 'an account sits'), (Get-Pick $k 'it is' 'the account is') })
                $(if ($fixed.Count) { '{0} a role through a group whose members come from a rule or from your on-premises directory, so {1} cannot be changed in the group itself, and I would leave {2} as {3}, marked in the attached file, for a separate review with you.' -f (Get-Count $fixedAccounts 'account holds' 'accounts hold'), (Get-Pick $fixedAccounts 'that membership' 'those memberships'), (Get-Pick $fixedAccounts 'it' 'them'), (Get-Pick $fixedAccounts 'it is' 'they are') })
                $(if ($viaGroup.Count -and -not $pathKnown) { 'Roles that reach a disabled account through a group stay as they are for now, since my review did not record which group each account sits in, and I will come back to you about those separately.' })
                ((Get-Pick $m 'Just before the change, I will check the account again and leave it unchanged if it has been turned back on since my review.' 'Just before the change, I will check each account again and skip any that has been turned back on since my review.') + $(if ($memberships.Count) { ' I will also leave a group membership as it is if the group no longer gives the account any of the roles listed for it.' } else { '' })))
            $email = New-ApprovalEmail -Subject 'removing the roles held by disabled accounts' `
                -Change @($ask, ('{0} disabled, so {1} cannot sign in, but {2} still holds every role {3} in the attached file.' -f (Get-Pick $m 'The account is' 'These accounts are'), (Get-Pick $m 'it' 'they'), (Get-Pick $m 'it' 'each one'), $(if ($fixed.Count) { 'marked for removal' } else { 'listed' }))) `
                -Why ('I recommend removing these roles because a disabled account keeps every role it holds, so if {0} is turned back on, by mistake or by someone with access to your directory, it has all of that access again straight away. Removing the roles closes that path.' -f (Get-Pick $m 'the account' 'one of these accounts')) `
                -Effect @($effect | Where-Object { $_ }) `
                -Listed ('{0} in the attached file {1}, one line for each role with the account, the role, where it applies, how the account holds it and what I would do about it{2}, and {3} add up as follows:' -f $(if ($others) { 'The roles of every disabled account are' } else { Get-Pick $m 'The account and its roles are' 'The accounts and their roles are' }), $attachment, $(if ($multiPath) { ', and a role that reaches an account through more than one group on a line for each of them' } else { '' }), $(if ($fixed.Count) { 'the roles I would remove' } else { 'they' })) `
                -Resources $emailResources.ToArray() `
                -Reversal ('I can restore any of these roles at any time from the record I keep of each one, with its role, where it applies and the account it belongs to{0}.' -f $(if ($memberships.Count) { ', and add an account back to the group it was removed from' } else { '' })) `
                -Ask ('Before I schedule the change, could you tell me whether {0} is expected to come back into use, for example for someone on leave or a seasonal worker, or is kept for emergency access? I will leave any such account out of the change. With that confirmed, could you approve this change for {1}?' -f (Get-Pick $m 'the account' 'any of these accounts'), $proposedDay)
            # The CSV is written beside the email, under the name the email gives, for the sender to attach.
            $email.Attachments = @(@{ Name = $attachment; Lines = $emailCsv })
            $what = @(if ($azure.Count) { Get-Count $azure.Count 'Azure role assignment' 'Azure role assignments' }; if ($entra.Count) { Get-Count $entra.Count 'Microsoft Entra role assignment' 'Microsoft Entra role assignments' }) -join ' and '
            $groupsTouched = @($memberships | ForEach-Object { $_.MemberOfId.ToLowerInvariant() } | Sort-Object -Unique).Count
            $groupRoles = @(& $distinctRoles $removable).Count
            $description = if (-not $memberships.Count) { 'Remove the {0} held by {1}, at the scope where each was made.' -f $what, (Get-Listed $m 'disabled user account' 'disabled user accounts') }
            elseif (-not $direct) { 'Remove {0} from the {1} through which {2} {3} {4}.' -f (Get-Listed $m 'disabled user account' 'disabled user accounts'), (Get-Count $groupsTouched 'group' 'groups'), (Get-Pick $m 'it' 'they'), (Get-Pick $m 'holds' 'hold'), (Get-Count $groupRoles 'role assignment' 'role assignments') }
            else { 'Remove the {0} assigned directly to {1}, at the scope where each was made, and remove {2} from {3} through which {4} {5} {6}.' -f $what, (Get-Listed $m 'disabled user account' 'disabled user accounts'), $(if ($k -eq $m) { Get-Pick $m 'it' 'each of them' } else { "$k of them" }), (Get-Count $groupsTouched 'group' 'groups'), (Get-Pick $k 'it' 'they'), (Get-Pick $k 'holds' 'hold'), (Get-Count $groupRoles 'more role assignment' 'more role assignments') }
            $intro = '{0} recorded as disabled at collection.' -f (Get-Pick $m 'The account below is' "The $m accounts below are")
            if ($direct -and $memberships.Count) { $intro += ' Each role listed is assigned directly to {0}, or reaches the account through the group it is removed from.' -f (Get-Pick $m 'it' 'one of them') }
            elseif ($direct) { $intro += ' Each role listed is assigned directly to {0}.' -f (Get-Pick $m 'it' 'one of them') }
            else { $intro += ' Each role listed reaches the account through the group it is removed from.' }
            if ($fixed.Count -or ($viaGroup.Count -and -not $pathKnown)) { $intro += ' Roles held through a group the change cannot alter are left out and named in the index.' }
            $intro += ' The CSV carries every assignment{0} in full for the rollback.' -f $(if ($memberships.Count) { ' and membership' } else { '' })
            @{ Used = @($sides | Where-Object { $read[$_.Id] } | ForEach-Object Id); Notes = $notes.ToArray(); Cr = New-ChangeRequest @{
                    Number = 19; Key = 'disabled-account-roles'; Title = 'Remove the role assignments held by disabled accounts'
                    Description = $description
                    Purpose = 'A disabled account cannot sign in but keeps every role it holds, so turning it back on, by mistake or by someone with directory write access, restores all of that access at once. Removing the roles{0} closes that path, and each one can be assigned again from the record.' -f $(if ($memberships.Count) { ', and the group memberships that carry them,' } else { '' })
                    ResourceIntro = $intro
                    ResourceLines = $lines.ToArray()
                    Availability = 'No impact on any service, since the accounts are disabled and cannot sign in{0}.' -f $(if ($memberships.Count) { ', and a group keeps its roles and its other members' } else { '' })
                    UserExperience = 'No user is affected today, and an account turned back on later starts without these roles{0}.' -f $(if ($memberships.Count) { ' and group memberships' } else { '' })
                    Dependencies = 'Needs the client to confirm that no listed account, such as one for someone on leave, a seasonal worker or emergency access, is expected back in use.'
                    Implementation = $impl.ToArray()
                    Testing = $testing.ToArray()
                    Rollback = $rollback.ToArray()
                    References = @(
                        if ($azure.Count - $rootAzure.Count) {
                            , @('Remove Azure role assignments, Azure portal', 'https://learn.microsoft.com/azure/role-based-access-control/role-assignments-remove#azure-portal')
                            , @('Assign Azure roles using the Azure portal', 'https://learn.microsoft.com/azure/role-based-access-control/role-assignments-portal') }
                        if ($rootAzure.Count) { , @('Elevate access to manage all Azure subscriptions and management groups, perform steps at root scope', 'https://learn.microsoft.com/azure/role-based-access-control/elevate-access-global-admin#perform-steps-at-root-scope') }
                        if ($activeEntra.Count) { , @('Remove Microsoft Entra role assignments', 'https://learn.microsoft.com/entra/identity/role-based-access-control/groups-remove-assignment') }
                        if ($pimEntra.Count) { , @('Assign Microsoft Entra roles in Privileged Identity Management, update or remove an existing role assignment', 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-add-role-to-user#update-or-remove-an-existing-role-assignment') }
                        if ($memberships.Count) {
                            , @('Manage Microsoft Entra groups and group membership, remove members or owners of a group', 'https://learn.microsoft.com/entra/fundamentals/how-to-manage-groups#remove-members-or-owners-of-a-group')
                            , @('Manage Microsoft Entra groups and group membership, add members or owners of a group', 'https://learn.microsoft.com/entra/fundamentals/how-to-manage-groups#add-members-or-owners-of-a-group') }
                        if ($azure.Count - $rootAzure.Count) {
                            , @('List Azure role assignments using the Azure portal, list role assignments at a scope', 'https://learn.microsoft.com/azure/role-based-access-control/role-assignments-list-portal#list-role-assignments-at-a-scope')
                            , @('Assign Azure roles using the Azure portal, select assignment type and edit assignment', 'https://learn.microsoft.com/azure/role-based-access-control/role-assignments-portal#step-6-select-assignment-type')
                            , @('Assign Azure resource roles in Privileged Identity Management, assign a role', 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-resource-roles-assign-roles#assign-a-role') }
                        if ($unmatched.Count -or $unsureStanding.Count) { , @('Assign Microsoft Entra roles in Privileged Identity Management, assign a role with a start and end date', 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-add-role-to-user#assign-a-role') }
                        , @('Manage emergency access admin accounts in Microsoft Entra ID', 'https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access'))
                    Csv = $csv
                    Email = $email
                } } } }
)
#endregion

# Resolve every change to its status and build the change requests.
$results = foreach ($item in $catalog) {
    $state = ''; $cr = $null; $notes = @()
    $missing = @($item.Sources | Where-Object { (Get-Status $_) -eq 'MISSING' })
    $failed = @($item.Sources | Where-Object { (Get-Status $_) -notin 'OK', 'PARTIAL', 'EMPTY', 'MISSING' })
    $unreadable = @($item.Sources | Where-Object { Test-Unreadable $_ })
    if ($missing.Count) { $state = if (@($missing | Where-Object { $detailVersions.Contains($_) }).Count) { Get-RecollectionState $missing } else { "Not collected ($($missing -join ', '))" } }
    elseif ($failed.Count) { $state = 'Not collected ({0})' -f (@($failed | ForEach-Object { "$_ $(Get-Status $_)" }) -join ', ') }
    elseif ($unreadable.Count) { $state = Get-UnreadableState $unreadable }
    elseif (-not ($gate = Get-CyberSocCapabilityGate -Matrix $licensing.Matrix -Requires @($item.Requires)).Write) {
        # A license the change needs is not in the tenant, so no change request is written.
        $state = 'Not written, needs {0}, which reads Not licensed' -f (Join-Words @($gate.Blocked | ForEach-Object { ConvertTo-CopyText $_.Name }))
        $notes = @($gate.Blocked | ForEach-Object { 'CR-{0:00} is not written because {1} reads Not licensed. {2}' -f $item.Number, (ConvertTo-CopyText $_.Name), (ConvertTo-PathText $_.Detail) })
    }
    elseif ($item.EmergencyAccess -and -not $emergencyAccess.Ready) {
        # A Conditional Access change is never written without the emergency access exclusions.
        $state = if ($emergencyAccess.Why -eq 'Missing') { Get-RecollectionState 'IA.16-ACCOUNTS', 'IA.16-GROUPS' } else { 'Not written, {0}' -f $emergencyAccess.Why }
        $notes = @('CR-{0:00} is not written because {1}. A Conditional Access change is written only with the emergency access accounts it excludes.' -f $item.Number, $(if ($emergencyAccess.Why -eq 'Missing') { 'the pack was collected before the emergency access read' } else { $emergencyAccess.Why }))
    }
    else {
        $built = & $item.Build
        $cr = $built.Cr
        $notes = @($built.Notes | Where-Object { $_ })
        $state = if ($cr) { 'Change request and client email' } else { $built.State }
        # A change request also reads results beyond its sources, such as the container list behind CR-07.
        # The index says when one of them was partial, not collected or unreadable.
        $partial = @($item.Sources | Where-Object { (Get-Status $_) -eq 'PARTIAL' }).Count -gt 0
        if ($cr) {
            foreach ($used in @($built.Used | Where-Object { $_ })) {
                $status = Get-Status $used
                if ($status -eq 'PARTIAL') { $partial = $true }
                elseif ($status -notin 'OK', 'EMPTY') { $notes += ('CR-{0:00} was written without {1}, which {2}.' -f $item.Number, $used, $(if ($status -eq 'MISSING') { 'was not collected' } else { "reads $status" })) }
                elseif (Test-Unreadable $used) { $notes += ('CR-{0:00} was written without {1}, whose result file is unreadable. Recollect or restore the pack.' -f $item.Number, $used) }
            }
            if ($partial) { $state += ', partial collection scope' }
            # A license the licensing check could not establish is confirmed before the email is sent.
            foreach ($g in @($gate.Unknown)) { $notes += 'Confirm {0} before sending CR-{1:00}: the licensing check could not establish it. {2}' -f (ConvertTo-CopyText $g.Name), $item.Number, (ConvertTo-PathText $g.Detail) }
            foreach ($g in @($gate.Partly)) { $notes += 'CR-{0:00} needs {1}, which covers only part of the estate. {2}' -f $item.Number, (ConvertTo-CopyText $g.Name), (ConvertTo-PathText $g.Detail) }
            if (@($gate.Unknown).Count) { $state += ', confirm the license before sending' }
        }
    }
    [pscustomobject]@{ Item = $item; State = $state; Cr = $cr; Notes = $notes }
}

# Every file is built and checked against the copy rules before anything is written, so a run that stops
# leaves the earlier files as they were.
$folder = if ($OutputPath) { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath) } else { Join-Path $pack '05-change-requests' }
$fileBase = { param($item) 'CR-{0:00}-{1}' -f $item.Number, $item.Key }
$outputs = [System.Collections.Generic.List[object]]::new()
function Add-Output([string]$Name, [string[]]$Lines, [string]$NewLine = "`r`n", [bool]$Bom = $false, [bool]$Prose = $true, [bool]$Email = $false) {
    $text = ($Lines -join $NewLine) + $NewLine
    if ($Prose) { Assert-CopyRules $text $Name -Email:$Email }
    $outputs.Add([pscustomobject]@{ Path = Join-Path $folder $Name; Text = $text; Bom = $Bom })
}
foreach ($r in $results | Where-Object Cr) {
    $base = & $fileBase $r.Item
    Add-Output "$base.txt" (Format-ChangeRequest $r.Cr)
    Add-Output "$base.email.txt" (Format-Email $r.Cr.Email) -Email $true
    # An email whose list would run long names the resources in a CSV attached to it instead, written beside the email
    # under the name the email gives. It goes to the client, so it keeps the copy rules of an email.
    foreach ($a in @($r.Cr.Email.Attachments | Where-Object { $_ })) { Add-Output $a.Name $a.Lines "`r`n" $true $true $true }
}

# The index: what was written, what was not and why, and the resources each change left out.
$packName = Split-Path -Leaf $pack
$md = [System.Collections.Generic.List[string]]::new()
$md.Add(('# Change requests: {0}' -f $client)); $md.Add('')
$md.Add(('Internal. Built {0} from evidence pack {1} (collector {2}). The change requests and client emails name client resources. Fill in the notification list of each change request and send its client email. Every client email asks for the client''s approval, and no change is scheduled until the client approves it.' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd', $inv), (ConvertTo-CopyText $packName), (Get-Text $parameters.ScriptVersion)))
$md.Add('')
$md.Add('| CR | Change | Resources | Status | Files |'); $md.Add('| --- | --- | --- | --- | --- |')
foreach ($r in $results) {
    $base = & $fileBase $r.Item
    $files = if ($r.Cr) { (@("$base.txt", "$base.email.txt") + @($r.Cr.Email.Attachments | Where-Object { $_ } | ForEach-Object Name)) -join ', ' } else { '' }
    $md.Add(('| {0:00} | {1} | {2} | {3} | {4} |' -f $r.Item.Number, $r.Item.Change, $(if ($r.Cr) { @($r.Cr.Csv).Count } else { '' }), $r.State, $files))
}
# The licensing check: the Defender for Endpoint plan, the devices, and each capability with the change requests that
# depend on it, from the catalog's Requires (gated) and Uses (listed only).
$neededBy = @{}
foreach ($item in $catalog) {
    foreach ($k in @($item.Requires | Where-Object { $_ })) { if (-not $neededBy[$k]) { $neededBy[$k] = @() }; $neededBy[$k] += 'CR-{0:00}' -f $item.Number }
    foreach ($k in @($item.Uses | Where-Object { $_ })) { if (-not $neededBy[$k]) { $neededBy[$k] = @() }; $neededBy[$k] += 'CR-{0:00} (no gate)' -f $item.Number }
}
# The evidence behind the endpoint measures, which no change request gates on.
$neededBy['MdeVulnerabilityData'] = @($neededBy['MdeVulnerabilityData'] | Where-Object { $_ }) + 'EW.3, EW.4 and EW.5 evidence'
$planRow = @($licensing.Matrix | Where-Object Kind -eq 'Plan') | Select-Object -First 1
$md.Add(''); $md.Add('## Licensing'); $md.Add('')
$licensingRead = @('LIC.1-SKUS', 'LIC.2-MACHINES', 'LIC.3-TVM', 'LIC.4-DEVICES' | Where-Object { (Get-Status $_) -ne 'MISSING' }).Count -gt 0
if ($licensingRead) { $md.Add(('Defender for Endpoint plan: {0}, from the {1}. {2}' -f (ConvertTo-CopyText $planRow.State), (ConvertTo-CopyText $planRow.Source), (ConvertTo-PathText $planRow.Detail))) }
else { $md.Add(('The pack was collected before the licensing check, so every capability reads Unknown{0}. Recollect with CyberSOC collector 1.11.0 or later.' -f $(if ($planReading) { (' and the Defender for Endpoint plan is the Licenses page reading, {0}' -f (ConvertTo-CopyText $planRow.State)) } else { '' }))) }
if (-not $planReading) { $md.Add(''); $md.Add('No API reads the Licenses page. Read it in the Defender portal under Settings > Endpoints > Licenses (the subscription state, the available and assigned licenses, and whether mixed mode is on), and run again with -DefenderEndpointPlan Plan1, Plan2, Business or Mixed to record it.') }
$md.Add('')
foreach ($d in @($licensing.Matrix | Where-Object { $licensingRead -and $_.Kind -eq 'Devices' })) {
    $md.Add(('- {0}: {1}. {2}' -f (ConvertTo-CopyText $d.Name), $(if ((Get-Text $d.State) -eq 'Read') { Get-Text $d.Count } else { 'unknown' }), (ConvertTo-PathText $d.Detail)))
}
$md.Add('')
$md.Add('A change request that needs a capability reading Not licensed is not written, and one reading Unknown is written with a note to confirm the license before sending. A read that failed, was refused or is partial reads Unknown, never Not licensed.')
if ($licensingRead) {
    $md.Add('')
    $md.Add('| Capability | Reading | Seats | Assigned | Needed by | Basis |'); $md.Add('| --- | --- | --- | --- | --- | --- |')
}
foreach ($c in @($licensing.Matrix | Where-Object { $licensingRead -and $_.Kind -eq 'Capability' })) {
    $md.Add(('| {0} | {1} | {2} | {3} | {4} | {5} |' -f (ConvertTo-CopyText $c.Name), (ConvertTo-CopyText $c.State), (Get-Text $c.Seats), (Get-Text $c.Assigned), $(if ($neededBy[$c.Capability]) { $neededBy[$c.Capability] -join ', ' } else { 'None yet' }), ((ConvertTo-PathText $c.Detail) -replace '\|', '/')))
}
# The emergency access accounts every Conditional Access change excludes, and why none can be written when the read is
# not complete.
$md.Add(''); $md.Add('## Emergency access accounts'); $md.Add('')
# A table cell, with any pipe in a name turned into a slash so it cannot split the row.
function ConvertTo-CellText($value) { (ConvertTo-CopyText $value) -replace '\|', '/' }
$caChanges = @($catalog | Where-Object { $_.EmergencyAccess } | ForEach-Object { 'CR-{0:00}' -f $_.Number })
$caText = if ($caChanges.Count) { Join-Words $caChanges } else { 'No change request in this build changes Conditional Access yet, and one that does' }
if ($emergencyAccess.Why -eq 'Missing') {
    $md.Add(('The pack was collected before the emergency access read, so no Conditional Access change can be written. Recollect with CyberSOC collector 1.12.0 or later. {0} {1} written only with the emergency access accounts.' -f $caText, $(Get-Pick ([math]::Max(1, $caChanges.Count)) 'is' 'are')))
}
else {
    $md.Add(('The emergency access accounts are every account with Atmosera in its UPN and every member of an Atmosera group, a group whose display name contains Atmosera. Every Conditional Access change excludes each Atmosera group, so a new member is covered without a change, and each account matched by its UPN on its own as well, so it stays excluded if it leaves the group, and no change removes an existing exclusion of any of them. {0} {1} written only when the read is complete and found at least one account.' -f $caText, $(Get-Pick ([math]::Max(1, $caChanges.Count)) 'is' 'are')))
    $md.Add('')
    if (-not $emergencyAccess.Ready) { $md.Add(('No Conditional Access change can be written: {0}. {1}' -f $emergencyAccess.Why, (@('IA.16-ACCOUNTS', 'IA.16-GROUPS' | ForEach-Object { Get-ResultDetail $_ } | Where-Object { $_ }) -join ' '))); $md.Add('') }
    if (@($emergencyAccess.Groups).Count) {
        $md.Add('| Atmosera group | Members | Membership | Object ID |'); $md.Add('| --- | --- | --- | --- |')
        foreach ($g in @($emergencyAccess.Groups)) {
            $md.Add(('| {0} | {1} | {2} | {3} |' -f (ConvertTo-CellText $g.DisplayName), $(if (Test-True $g.MembersRead) { Get-Text $g.Members } else { 'not read' }), (ConvertTo-CellText $g.Membership), (ConvertTo-CellText $g.GroupId)))
        }
        $md.Add('')
    }
    if (@($emergencyAccess.Accounts).Count) {
        $md.Add('| Account | Name | Type | Enabled | Matched by | Atmosera groups | Excluded as |'); $md.Add('| --- | --- | --- | --- | --- | --- | --- |')
        foreach ($a in @($emergencyAccess.Accounts)) {
            $inGroups = @($a.Groups | Where-Object { $_ } | ForEach-Object { ConvertTo-CellText $_ })
            $md.Add(('| {0} | {1} | {2} | {3} | {4} | {5} | {6} |' -f (ConvertTo-CellText $a.UserPrincipalName), (ConvertTo-CellText $a.DisplayName), (ConvertTo-CellText $a.UserType), $(if ((Get-Text $a.AccountEnabled) -eq '') { 'unknown' } elseif (Test-True $a.AccountEnabled) { 'Yes' } else { 'No' }), (ConvertTo-CellText $a.MatchedBy), ($inGroups -join ', '), $(switch (Get-Text $a.MatchedBy) { 'UPN' { 'the account' } 'Group' { 'its group' } default { 'the account and its group' } })))
        }
        $md.Add('')
    }
    foreach ($g in @($emergencyAccess.Review)) {
        $md.Add(('- {0} has {1} membership, so {2}. Confirm that every emergency access account stays in it, or exclude the account on its own.' -f (ConvertTo-CellText $g.DisplayName), $(if ((Get-Text $g.Membership) -eq 'Dynamic') { 'dynamic' } else { 'on-premises synced' }), $(if ((Get-Text $g.Membership) -eq 'Dynamic') { 'its rule adds and removes members, and an account it drops loses the exclusion' } else { 'its members are managed in Active Directory, and an account removed there loses the exclusion' })))
    }
    $md.Add('- An account Atmosera uses whose UPN does not contain Atmosera is covered only when it sits in an Atmosera group. Add any such account to one before a Conditional Access change is made.')
}
$notes = @($results | ForEach-Object { $_.Notes })
$written = @($results | Where-Object Cr)
if ($written.Count) {
    $dated = @($written | Where-Object { -not $_.Cr.Email.Window } | ForEach-Object { 'CR-{0:00}' -f $_.Item.Number })
    $windows = @($written | Where-Object { $_.Cr.Email.Window } | ForEach-Object { 'CR-{0:00}' -f $_.Item.Number })
    $asks = @(
        if ($dated.Count) { '{0} {1} the client to approve the proposed date, {2}' -f ($dated -join ', '), (Get-Pick $dated.Count 'asks' 'ask'), $proposedDay }
        if ($windows.Count) { '{0} {1} the client to approve the change and suggest a maintenance window' -f ($windows -join ', '), (Get-Pick $windows.Count 'asks' 'ask') })
    $notes += '{0}. Every email asks for a reply by {1}. Run again with -ChangeDate to propose another day, or on the day the emails are sent to move both dates.' -f ($asks -join ', and '), $replyDay
}
if (-not $DrClient) { $notes += 'DR Impact reads Not a DR Client. Run again with -DrClient for a DR client.' }
if (-not $workspaceName -and @($results | Where-Object { $_.Cr -and $_.Item.Number -eq 1 }).Count) { $notes += 'The pack lists {0}, so CR-01 names the client Sentinel workspace without its name. Run again with -SentinelWorkspace to name it.' -f (Get-Count $workspaces.Count 'workspace' 'workspaces') }
if ((Get-Status 'P0.7') -notin 'OK', 'PARTIAL' -or (Test-Unreadable 'P0.7')) { $notes += 'Subscription names were not read (P0.7), so the change requests show subscription IDs only.' }
if ($notes.Count) { $md.Add(''); $md.Add('## Notes'); $md.Add(''); foreach ($n in $notes) { $md.Add("- $n") } }
Add-Output '00-index.md' $md.ToArray() "`n"

# CSV: one row per resource in each change request, for tracking the work.
$csvRows = foreach ($r in $results | Where-Object Cr) {
    foreach ($res in @($r.Cr.Csv)) {
        [pscustomobject]@{ CR = 'CR-{0:00}' -f $r.Item.Number; Change = $r.Cr.Title; Subscription = Format-Subscription $res.SubscriptionId; ResourceGroup = $res.ResourceGroup; Resource = $res.Name; CurrentSetting = $res.Setting; ResourceId = $res.ResourceId }
    }
}
$csvLines = @('"CR","Change","Subscription","ResourceGroup","Resource","CurrentSetting","ResourceId"')
if (@($csvRows).Count) { $csvLines = @($csvRows | ConvertTo-Csv -NoTypeInformation) }
# The CSV carries resource IDs as Azure has them, so it is data rather than copy and skips the copy check.
Add-Output 'change-requests.csv' $csvLines "`r`n" $true $false

# Earlier runs may have left a change request this run no longer needs, so the files this script names
# are cleared first. Nothing else in the folder is touched.
if (-not (Test-Path -LiteralPath $folder -PathType Container)) { [void](New-Item -ItemType Directory -Path $folder -Force) }
foreach ($item in $catalog) {
    foreach ($suffix in '.txt', '.email.txt', '.email.csv') {
        $old = Join-Path $folder ((& $fileBase $item) + $suffix)
        if (Test-Path -LiteralPath $old -PathType Leaf) { Remove-Item -LiteralPath $old }
    }
}
foreach ($o in $outputs) {
    [IO.File]::WriteAllText($o.Path, $o.Text, [Text.UTF8Encoding]::new($o.Bom))
    $o.Path
}
