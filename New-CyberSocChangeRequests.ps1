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
    encryption at host on virtual machines and scale sets, and closing internet-facing RDP, SSH and WinRM
    rules on network security groups. Every change request also gets a client email,
    drafted and ready to send, that asks for the client's approval. Every email has the same parts in the
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
.EXAMPLE
    ./New-CyberSocChangeRequests.ps1 -EvidencePath ./CyberSOC-Evidence_Contoso_2026-09_20261003-090000
.EXAMPLE
    ./New-CyberSocChangeRequests.ps1 -EvidencePath ./CyberSOC-Evidence_Contoso_2026-09_20261003-090000 -DrClient -ClientContact 'Dana' -SenderName 'Scott'
.NOTES
    The per-resource results (P0.7, NB.4-DETAIL, NB.5-DETAIL, NB.6-DETAIL, DP.1-DETAIL, DP.2-DETAIL,
    DP.4-ELIGIBILITY, DR.6-COVERAGE and DR.6-NONCOMPLIANT) were added in CyberSOC collector 1.1.0,
    NB.6-PAAS-DETAIL in 1.2.0, DP.4-VMSS-ELIGIBILITY in 1.3.0 and NB.2-DETAIL in 1.6.0. Changes that read them say "needs
    recollection" on packs collected with an earlier version. CR-09 and CR-15 also need the machine and scale
    set IDs added in 1.4.0, and say "needs recollection" on an earlier pack that lists anything to change.
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
    [datetime]$ChangeDate
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

# Get-Text, Test-True, Get-Status, Get-Rows, Test-Unreadable and Get-UnreadableState. Each result file is
# parsed once. A result the manifest reads as OK or PARTIAL needs a file that parses, or a damaged pack would
# read as no gaps found and leave a change out without saying so.
. (Join-Path $PSScriptRoot 'report/Read-CyberSocPackResult.ps1')
Initialize-CyberSocPackReader -Pack $pack -Manifest $manifest
function Get-Number($value) { $n = 0; if ([int]::TryParse((Get-Text $value), [ref]$n)) { $n } else { 0 } }

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
function Format-TlsVersion($value) {
    # Storage writes TLS1_2, Cosmos DB Tls, Tls11 and Tls12, the other services 1.2.
    switch -Regex (Get-Text $value) { '^TLS1_(\d)$' { '1.' + $Matches[1] } '^Tls1(\d)$' { '1.' + $Matches[1] } '^Tls$' { '1.0' } '^(|None)$' { 'not set' } default { ConvertTo-CopyText $value } }
}

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
    # Each paragraph opens in its own words. The subscription lines that head each resource list are left out.
    $openings = @($paragraphs | Where-Object { $_ -is [string] -and $_ -notmatch '^Subscription .+:$' } | ForEach-Object { (@($_ -split '\s+' | Select-Object -First 3) -join ' ').ToLowerInvariant() })
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
            # App Service applies TLS 1.2 to an app without a minimum, so a site whose value reads empty is
            # named in the index instead of changed.
            $rows = @(Get-Rows 'NB.5-DETAIL')
            $unset = @($rows | Where-Object { -not (Get-Text $_.MinTlsVersion) })
            $notes = @(if ($unset.Count) { '{0} left out of CR-04 because Resource Graph returned no minimum TLS version, and App Service applies 1.2 when none is set: {1}. Check {2} in the portal if the value may be missing from Resource Graph.' -f (Get-Count $unset.Count 'App Service app' 'App Service apps'), (@($unset | ForEach-Object { ConvertTo-CopyText $_.Name } | Sort-Object) -join ', '), (Get-Pick $unset.Count 'it' 'them') })
            $resources = @($rows | Where-Object { Get-Text $_.MinTlsVersion } | ForEach-Object { New-Resource $_.Name $_.resourceGroup $_.subscriptionId ('minimum TLS ' + (Format-TlsVersion $_.MinTlsVersion)) $_.ResourceId })
            $n = $resources.Count
            if (-not $n) { return @{ State = $(if ($unset.Count) { 'Only apps without a recorded minimum remain' } else { 'No gaps found' }); Notes = $notes } }
            $impl = [System.Collections.Generic.List[object]]::new()
            $impl.Add((Get-OpenStep $n 'App Services' 'app'))
            $impl.Add('Go to Settings > Configuration and select the General settings tab.')
            $impl.Add('Set Minimum Inbound TLS Version to 1.2, select Apply and confirm.')
            Add-RepeatStep $impl $n 1 'app'
            @{ Notes = $notes; Cr = New-ChangeRequest @{
                    Number = 4; Key = 'app-service-minimum-tls'; Title = 'Set minimum inbound TLS version 1.2 on App Service apps'
                    Description = 'Set the minimum inbound TLS version to 1.2 on {0}.' -f (Get-Listed $n 'App Service app' 'App Service and Function apps')
                    Purpose = 'TLS 1.0 and 1.1 have known weaknesses, and App Service stops accepting them on May 31, 2027. Setting 1.2 now refuses these older protocols and matches the default for new apps.'
                    ResourceIntro = '{0} with the minimum TLS version {1} today.' -f $(if ($n -eq 1) { 'The app below is listed' } else { "The $n apps below are listed" }), (Get-Pick $n 'it allows' 'each one allows')
                    ResourceLines = Format-ResourceList $resources
                    Availability = 'No downtime expected while the setting is applied.'
                    UserExperience = 'No change for browsers and clients that use TLS 1.2 or later.'
                    Dependencies = 'Clients limited to TLS 1.0 or 1.1 can no longer connect once the change is applied.'
                    Implementation = $impl.ToArray()
                    Testing = @(
                        ('In the Azure portal, open {0}, go to Settings > Configuration and select the General settings tab.' -f (Get-EachStep $n 'app'))
                        'Confirm Minimum Inbound TLS Version shows 1.2.')
                    Rollback = @(
                        'In the Azure portal, open the app to revert, go to Settings > Configuration and select the General settings tab.'
                        'Set Minimum Inbound TLS Version back to the version recorded for the app in the RESOURCES section, select Apply and confirm.')
                    References = @(
                        , @('Set the minimum TLS version for App Service', 'https://learn.microsoft.com/azure/app-service/tls-minimum-version')
                        , @('Transport Layer Security in Azure App Service', 'https://learn.microsoft.com/azure/app-service/overview-tls'))
                    Csv = $resources
                    Email = New-ApprovalEmail -Subject 'minimum TLS 1.2 for Azure App Service applications' `
                        -Change @(('I would like to set the minimum inbound TLS version to 1.2 on {0}.' -f (Get-Yours $n 'App Service and Function applications')), $explainTls) `
                        -Why ('I recommend setting this minimum now because TLS 1.0 and 1.1 have known weaknesses, and App Service stops accepting them on May 31, 2027. This change makes {0} refuse them now, and matches the default for new applications.' -f (Get-Pick $n 'the application' 'these applications')) `
                        -Listed (Get-Pick $n 'The application is listed below with its minimum TLS version today:' 'The applications are listed below by subscription, each with its minimum TLS version today:') `
                        -Resources (Get-EmailResourceList $resources $settingLabel) `
                        -Reversal ('The minimum TLS version can be set back to the version {0} today, shown above.' -f (Get-Pick $n 'the application has' 'each application has')) `
                        -Effect ('Browsers and applications that connect over TLS 1.2 or later will see no change. A client that can only use TLS 1.0 or 1.1, for example one on an old operating system or runtime, will no longer be able to connect to {0} once the change is applied.' -f (Get-Pick $n 'the application' 'these applications'))
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
            $unlisted = [System.Collections.Generic.List[string]]::new()
            $failed = [System.Collections.Generic.List[string]]::new()
            # A FileStorage account holds no blob service, so the setting does not apply to it.
            $resources = @(foreach ($a in @(Get-Rows 'DP.1-DETAIL' | Where-Object { (Test-True $_.AllowBlobPublicAccess) -and (Get-Text $_.Kind) -ine 'FileStorage' })) {
                    $c = $containers[(Get-Text $a.ResourceId).ToLowerInvariant()]
                    $label = '{0} (resource group {1})' -f (ConvertTo-CopyText $a.Name), (ConvertTo-CopyText $a.resourceGroup)
                    # A row without a whole number of public containers cannot show the account is safe to change.
                    if ($null -eq $c -or (Get-Text $c.PublicContainers) -notmatch '^\d+$') { $unlisted.Add($label); continue }
                    if ((Get-Text $c.ReadStatus) -ne 'OK') { $failed.Add($label); continue }
                    if ((Get-Number $c.PublicContainers) -gt 0 -or (Get-Text $c.PublicContainerNames)) { $public.Add(('{0}: {1}' -f $label, (ConvertTo-CopyText $c.PublicContainerNames))); continue }
                    $count = Get-Number $c.Containers
                    New-Resource $a.Name $a.resourceGroup $a.subscriptionId $(if ($count -eq 1) { '1 container, private' } elseif ($count) { "$count containers, all private" } else { 'no containers' }) $a.ResourceId
                })
            $notes = [System.Collections.Generic.List[string]]::new()
            if ($public.Count) {
                $notes.Add(('{0} left out of CR-07 because {1} a container set to Blob or Container access, which anyone can read today without signing in: {2}. Turning the account setting off would stop those anonymous reads, so the owner of each container confirms first that it serves no public content and the container is set to private. A later pack picks each account up for CR-07 once every container in it is private.' -f (Get-Count $public.Count 'storage account' 'storage accounts'), (Get-Pick $public.Count 'it has' 'each has'), ($public -join ' / ')))
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

    @{ Number = 16; Key = 'management-ports'; Change = 'Internet-facing RDP, SSH and WinRM rules closed'; Sources = @('NB.2-DETAIL')
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
            if (-not $n) { return @{ State = $(if ($rows.Count) { 'Only rules for cleanup or review remain, see the notes' } else { 'No gaps found' }); Notes = $notes.ToArray() } }

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
            $effective = 'For each network interface the rules applied to, directly or through its subnet, go to Virtual machines, open the machine it belongs to, select Networking, select the network interface and select Effective security rules under Help. The page shows only the first 50 rules, so select Download and check the complete list in the file it saves. For a rule on a subnet, find every network interface in it on the Connected devices page of its virtual network, which lists each device with its subnet. Leave out a machine that just-in-time VM access covers, since its deny rules already stop internet sources on the ports it protects.'
            # The first rule that matches a connection's source, protocol and port decides it in each group, and the
            # groups of the subnet and the network interface must both allow it. A deny for named addresses leaves
            # every other address to the rules after it, so only a deny that covers the internet stops it. The deny
            # carries TCP only, like the rules CR-16 changes, so a rule for another protocol left for review keeps
            # working, and it skips only the ports of a rule left unchanged, which stay open until agreed.
            $reach = 'The page shows the group of the subnet and the group of the network interface. In each group, rules apply in priority order and the first rule that matches the source, protocol and port of a connection decides it, and a connection gets through only if every group on its path allows it. A deny rule stops internet sources only where its source is Any, 0.0.0.0/0, ::/0 or Internet and it covers the port, since a deny for named addresses leaves every other address to the rules after it.'
            $wide = 'lists 0.0.0.0/0, ::/0 or other public prefixes the client did not name or already allow on purpose, such as 0.0.0.0/1 and 128.0.0.0/1'
            $impl.Add(('{0} {1} For each of 22, 3389, 5985 and 5986, select each inbound allow rule that covers the port to see its source prefixes. The port is still open to the internet where an allow {2}, no deny that stops internet sources on that port comes before it in the same group, and the other group on the path, if there is one, lets the same connection through. Effective security rules lists rules only while the machine is running, so treat every management port of a stopped machine as open and note it in the change record. Leave the ports of a rule this change left unchanged and noted in the change record out of the deny on the network interfaces behind it, since that rule stays open until the client agrees a path, and note them with it. For every other management port found open, add a deny rule with protocol TCP, Source set to Service Tag and Internet, Destination port ranges set to those ports in the group that holds the allow rules for the named addresses, or in the group of the network interface, or of the subnet where the interface has none, when no addresses were named. Give it a free priority number from 100 to 4096 that is higher than every allow rule in that group for those ports from the named addresses or another source the client already allows on purpose, and lower than the allow that lets the internet in where that allow is a custom rule in the same group. Default rules, numbered 65000 and above, always come after it. Select Add and check again. If no such number is free, leave the rule as it is and review it with the client.' -f $effective, $reach, $wide))
            $privateTest = if ($broad) { ' Any rule added for the private ranges allows only the management ports, from the ranges the client confirmed.' } else { '' }
            $testing = @(
                ('In the Azure portal, open the network security group of {0} and go to Settings > Inbound security rules.' -f (Get-EachStep $n 'rule'))
                ('Confirm each rule listed is gone, allows only the source addresses the client named, or no longer allows 22, 3389, 5985 or 5986 while its other ports keep their source, and that no other rule allows those ports over TCP from Any, Internet, 0.0.0.0/0 or ::/0.{0}' -f $privateTest)
                ('{0} {1} For each of 22, 3389, 5985 and 5986, confirm that no allow rule that covers the port and {2}, lets an internet source through under those rules, apart from the Azure platform address 168.63.129.16 and the ports of a rule this change left unchanged and noted in the change record, so no other internet source reaches those ports. For a stopped machine, confirm instead that the deny from the Internet service tag is in place.' -f $effective, $reach, $wide)
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
                    ResourceIntro = '{0} RDP, SSH or WinRM from any internet address on a workload subnet or network interface, with every property recorded for the rollback. The last lines give the path that fits each subscription.' -f $(if ($n -eq 1) { 'The inbound rule below allows' } else { "The $n inbound rules below allow" })
                    ResourceLines = @(Format-ResourceList $resources) + $planLines
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
                        , @('Choose the right Azure Bastion SKU', 'https://learn.microsoft.com/azure/bastion/bastion-sku-comparison'))
                    Csv = $resources
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
    $files = if ($r.Cr) { "$base.txt, $base.email.txt" } else { '' }
    $md.Add(('| {0:00} | {1} | {2} | {3} | {4} |' -f $r.Item.Number, $r.Item.Change, $(if ($r.Cr) { @($r.Cr.Csv).Count } else { '' }), $r.State, $files))
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
    foreach ($suffix in '.txt', '.email.txt') {
        $old = Join-Path $folder ((& $fileBase $item) + $suffix)
        if (Test-Path -LiteralPath $old -PathType Leaf) { Remove-Item -LiteralPath $old }
    }
}
foreach ($o in $outputs) {
    [IO.File]::WriteAllText($o.Path, $o.Text, [Text.UTF8Encoding]::new($o.Bom))
    $o.Path
}
