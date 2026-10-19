<#
.SYNOPSIS
    Writes the change requests for the low-impact security hardening items in an evidence pack.
.DESCRIPTION
    Offline only. Reads the manifest, parameters and the per-resource hardening results of a finished
    pack and writes one change request for each hardening item that still has resources to fix, laid
    out on the change request template: diagnostic logging through the ATMO-MXDR-DIAG-TOSENT initiative
    (assigned where it is missing, and remediated where resources are not compliant),
    secure transfer and minimum TLS 1.2 on storage accounts, minimum TLS 1.2 on App Service, Azure SQL,
    Azure Cache for Redis, Service Bus, Event Hubs and Azure Cosmos DB, Key Vault purge protection, and
    encryption at host on virtual machines and scale sets. The changes that need the client first (purge
    protection, which cannot be undone, anonymous blob access, HTTPS only on App Service, encryption at
    host and minimum TLS 1.2 on Event Hubs) also get a client email, drafted and ready to send. AKS node
    pools take encryption at host only when a node pool is created, so the index routes them to a planned
    project instead of a change request.

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
    The client approved purge protection at build kickoff. CR-06 is then written without its client email,
    and the index records the approval.
.EXAMPLE
    ./New-CyberSocChangeRequests.ps1 -EvidencePath ./CyberSOC-Evidence_Contoso_2026-09_20261003-090000
.EXAMPLE
    ./New-CyberSocChangeRequests.ps1 -EvidencePath ./CyberSOC-Evidence_Contoso_2026-09_20261003-090000 -DrClient -ClientContact 'Dana' -SenderName 'Scott'
.NOTES
    The per-resource results (P0.7, NB.4-DETAIL, NB.5-DETAIL, NB.6-DETAIL, DP.1-DETAIL, DP.2-DETAIL,
    DP.4-ELIGIBILITY, DR.6-COVERAGE and DR.6-NONCOMPLIANT) were added in CyberSOC collector 1.1.0,
    NB.6-PAAS-DETAIL in 1.2.0 and DP.4-VMSS-ELIGIBILITY in 1.3.0. Changes that read them say "needs
    recollection" on packs collected with an earlier version.
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
    [switch]$PurgeProtectionApproved
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
# The latest collector among the results given, so a pack missing several asks for the one that has them all.
function Get-RecollectionState([string[]]$Ids) {
    $version = @($Ids | ForEach-Object { $detailVersions[$_] } | Where-Object { $_ } | Sort-Object { [version]$_ })[-1]
    "Needs recollection with CyberSOC collector $version or later"
}
$needsRecollection = Get-RecollectionState 'DR.6-COVERAGE', 'DR.6-NONCOMPLIANT'

# Get-Text, Test-True, Get-Status, Get-Rows, Test-Unreadable and Get-UnreadableState. Each result file is
# parsed once. A result the manifest reads as OK or PARTIAL needs a file that parses, or a damaged pack would
# read as no gaps found and leave a change out without saying so.
. (Join-Path $PSScriptRoot 'report/Read-CyberSocPackResult.ps1')
Initialize-CyberSocPackReader -Pack $pack -Manifest $manifest
function Get-Number($value) { $n = 0; if ([int]::TryParse((Get-Text $value), [ref]$n)) { $n } else { 0 } }

# Copy rules: no semicolons, arrows, emoji or angle brackets, and the greater-than sign only in a
# navigation step such as Settings > Configuration. Values read from the pack are cleaned first, and
# every file is checked before it is written, so a rule broken by the text below stops the run.
# The cleaner removes every character the check rejects, so a value read from the pack never stops the run.
$arrowCharacters = '\u2190-\u21FF\u27F0-\u27FF\u2900-\u297F\u2B00-\u2BFF\u25B6\u25BA'
$emojiCharacters = '\u2600-\u27BF\uD800-\uDFFF'
function ConvertTo-CopyText($value) {
    $v = (Get-Text $value) -replace ';', ',' -replace '[<>]', ' '
    $v = $v -replace ('[' + $arrowCharacters + $emojiCharacters + ']'), ''
    ($v -replace '\s+', ' ').Trim()
}
function Assert-CopyRules([string]$Text, [string]$Label) {
    $broken = @(
        if ($Text -match ';') { 'a semicolon' }
        if ($Text -match ('[' + $arrowCharacters + ']|->|=>')) { 'an arrow' }
        if ($Text -match ('[' + $emojiCharacters + ']')) { 'an emoji' }
        if ($Text -match '<') { 'an angle bracket' }
        if (($Text -replace '[A-Za-z0-9)] > [A-Za-z]', '') -match '>') { 'a greater-than sign outside a navigation step' }
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

function New-ChangeRequest([hashtable]$Spec) {
    foreach ($field in 'Description', 'Purpose') {
        if ((Get-SentenceCount $Spec[$field]) -gt 2) { throw "CR-$($Spec.Number) $field runs past two sentences." }
    }
    foreach ($field in 'Availability', 'UserExperience', 'Dependencies') {
        if ($Spec[$field] -match '[\r\n]' -or (Get-SentenceCount $Spec[$field]) -ne 1) { throw "CR-$($Spec.Number) $field must be one line." }
    }
    $defaults = @{ Mitigation = $standardMitigation; DrImpact = $drImpact; DrPlan = $drPlan; Email = $null; Csv = $null }
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
# Paragraphs separated by a blank line. A paragraph given as an array is a bulleted list.
function Format-Email($email) {
    $l = [System.Collections.Generic.List[string]]::new()
    $l.Add("Subject: $($email.Subject)"); $l.Add('')
    $l.Add($(if ($ClientContact) { 'Hello {0},' -f (ConvertTo-CopyText $ClientContact) } else { 'Hello,' })); $l.Add('')
    foreach ($p in $email.Body) {
        if ($p -is [array]) { foreach ($item in $p) { $l.Add("- $item") } } else { $l.Add($p) }
        $l.Add('')
    }
    $l.Add('Thank you,')
    if ($SenderName) { $l.Add((ConvertTo-CopyText $SenderName)) }
    $l.ToArray()
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
    if ($counted) {
        # Only the subscriptions this assignment covers are counted.
        foreach ($row in @($inventory | Where-Object { -not (Get-Text $_.subscriptionId) -or (ConvertTo-CopyText $_.subscriptionId).ToLowerInvariant() -in $subscriptions })) {
            $type = (Get-Text $row.ResourceType).ToLowerInvariant()
            if ($diagnosticTypes.Contains($type)) { $counts[$type] = [int]$counts[$type] + (Get-Number $row.Resources) }
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
        if ($id -match '^/subscriptions/[^/]+$') { New-Resource 'Subscription Activity Log' '' $sub ('policies ' + $failing) $id }
        else {
            $rg = if ($id -match '/resourcegroups/([^/]+)/') { $Matches[1] } else { '' }
            New-Resource $parts[-1] $rg $sub ('{0}, policies {1}' -f $label, $failing) $id
        }
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
function Test-ResultRead([string]$Id) { (Get-Status $Id) -in 'OK', 'PARTIAL', 'EMPTY' -and -not (Test-Unreadable $Id) }
function Get-ScaleSetText($value) { (Get-Text $value).ToLowerInvariant() }
# The scale sets CR-15 can take on their model alone: not AKS, with a model, and eligible.
function Get-EligibleScaleSetModels {
    @(if (Test-ResultRead 'DP.4-VMSS-ELIGIBILITY') { Get-Rows 'DP.4-VMSS-ELIGIBILITY' | Where-Object { -not (Test-True $_.Aks) -and (Test-True $_.HasModel) -and (Test-True $_.Eligible) } })
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
    if (-not $complete -or -not $named) {
        $check.Unchecked = if ($complete) { 'does not name the scale set of each machine' } elseif ((Get-Status 'DP.4-ELIGIBILITY') -eq 'MISSING') { 'was not collected' } elseif (Test-Unreadable 'DP.4-ELIGIBILITY') { 'is unreadable' } else { 'reads ' + (Get-Status 'DP.4-ELIGIBILITY') }
        return $check
    }
    foreach ($f in @($flexible)) {
        $key = (Get-Text $f.ResourceId).ToLowerInvariant()
        $members = @($vms | Where-Object { (Get-ScaleSetText $_.ScaleSet) -eq $key })
        $bad = @($members | Where-Object { -not (Test-True $_.Eligible) })
        if ($bad.Count) { $check.Blocked.Add(('{0} ({1})' -f (ConvertTo-CopyText $f.Name), (@($bad | Sort-Object Name | ForEach-Object { '{0} {1}' -f (ConvertTo-CopyText $_.Name), ((ConvertTo-CopyText $_.Reason) -replace '^(size support not read):.*$', '$1') }) -join ', '))) }
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
            # Purge protection cannot be undone, so the client approves it in writing first, unless the
            # approval was given at build kickoff.
            $email = $null; $notes = @()
            if ($PurgeProtectionApproved) { $notes = @('CR-06 has no client email because the client approved purge protection at build kickoff (-PurgeProtectionApproved). Attach that approval to the change request.') }
            else {
                $body = [System.Collections.Generic.List[object]]::new()
                $body.Add(('I am planning a security hardening change that turns on purge protection for {0}. With it on, a deleted vault, key, secret or certificate cannot be purged for good before its retention period ends, so it stays recoverable after an accidental or malicious deletion.' -f $(if ($n -eq 1) { 'one of your Azure key vaults' } else { "$n of your Azure key vaults" })))
                $body.Add((Get-Pick $n 'The vault is listed below with its soft delete retention period, which purge protection will enforce:' 'The vaults are listed below by subscription, each with its soft delete retention period, which purge protection will enforce:'))
                foreach ($g in @($resources | Group-Object SubscriptionId | Sort-Object { Format-Subscription $_.Name })) {
                    $body.Add(('Subscription {0}:' -f (Format-Subscription $g.Name)))
                    $body.Add(@($g.Group | Sort-Object ResourceGroup, Name | ForEach-Object { '{0} (resource group {1}, {2})' -f $_.Name, $_.ResourceGroup, $_.Setting }))
                }
                $body.Add('Purge protection cannot be turned off once it is enabled, by anyone including Microsoft, so this change cannot be reverted. The retention period of a vault is set when the vault is created and cannot be changed afterwards either.')
                $body.Add(('Once it is on, a deleted vault, key, secret or certificate is kept for the retention period of its vault and cannot be purged early. It can be recovered at any time during that period, and Azure purges it automatically when the period ends. A deleted vault keeps its name until then, so the name cannot be reused, for example by automation that deletes and recreates a vault, and a deleted key, secret or certificate keeps its name in {0} in the same way.' -f (Get-Pick $n 'the vault' 'its vault')))
                $body.Add(('Nothing changes for the applications and people that read or write {0} today.' -f (Get-Pick $n 'the vault' 'these vaults')))
                $body.Add(('Because this change cannot be undone, I need your written approval before I schedule it. Could you reply to confirm that I can enable purge protection on {0}? If a vault should stay out of the change, please tell me which one and I will leave it out.' -f (Get-Pick $n 'this vault' 'these vaults')))
                $email = @{ Subject = 'Approval request: purge protection for Azure key vaults'; Body = $body.ToArray() }
            }
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
            # The containers each account holds (DP.1-CONTAINERS) name what anonymous readers lose.
            $containers = @{}
            $containersRead = (Get-Status 'DP.1-CONTAINERS') -in 'OK', 'PARTIAL', 'EMPTY' -and -not (Test-Unreadable 'DP.1-CONTAINERS')
            if ($containersRead) { foreach ($c in @(Get-Rows 'DP.1-CONTAINERS')) { $containers[(Get-Text $c.ResourceId).ToLowerInvariant()] = $c } }
            $public = [System.Collections.Generic.List[string]]::new()
            $closed = [System.Collections.Generic.List[string]]::new()
            $unread = [System.Collections.Generic.List[string]]::new()
            $exposed = 0
            # A FileStorage account holds no blob service, so the setting does not apply to it.
            $resources = @(Get-Rows 'DP.1-DETAIL' | Where-Object { (Test-True $_.AllowBlobPublicAccess) -and (Get-Text $_.Kind) -ine 'FileStorage' } | ForEach-Object {
                    $c = $containers[(Get-Text $_.ResourceId).ToLowerInvariant()]
                    $label = '{0} (resource group {1})' -f (ConvertTo-CopyText $_.Name), (ConvertTo-CopyText $_.resourceGroup)
                    $setting = if ($null -eq $c) { $unread.Add($label); '' }
                    elseif ((Get-Text $c.ReadStatus) -ne 'OK') { $unread.Add($label); 'containers not listed' }
                    elseif ((Get-Number $c.PublicContainers) -gt 0) {
                        $exposed += Get-Number $c.PublicContainers
                        $public.Add(('{0}: {1}' -f $label, (ConvertTo-CopyText $c.PublicContainerNames)))
                        '{0} open to anonymous read: {1}' -f (Get-Count (Get-Number $c.PublicContainers) 'container' 'containers'), (ConvertTo-CopyText $c.PublicContainerNames)
                    }
                    else { $closed.Add($label); 'no container open to anonymous read' }
                    New-Resource $_.Name $_.resourceGroup $_.subscriptionId $setting $_.ResourceId })
            $n = $resources.Count
            if (-not $n) { return @{ State = 'No gaps found' } }
            $impl = [System.Collections.Generic.List[object]]::new()
            $impl.Add((Get-OpenStep $n 'Storage accounts' 'storage account'))
            $impl.Add('Go to Settings > Configuration.')
            $impl.Add('Set Allow Blob anonymous access to Disabled and select Save.')
            Add-RepeatStep $impl $n 1 'storage account'
            $userExperience = if ($exposed) { 'Anyone who reads the public containers named in the RESOURCES section without signing in loses access, while signed-in users see no change.' }
            elseif ($unread.Count) { 'Signed-in users see no change, and only an anonymous reader of a public container would lose access.' }
            else { 'No change, since no listed account has a container open to anonymous access today.' }
            $dependencies = if ($exposed) { 'Websites or applications that read the public containers anonymously need a shared access signature or another authorized path.' }
            else { 'None expected, since only anonymous reads of a public container depend on this setting.' }
            $body = [System.Collections.Generic.List[object]]::new()
            $body.Add(('I am planning a security hardening change that turns off anonymous read access to Azure Blob Storage on {0}. Once it is off, every request to read blob data has to be authorized, which closes a common path for unintended data exposure.' -f $(if ($n -eq 1) { 'one of your storage accounts' } else { "$n of your storage accounts" })))
            if ($public.Count) {
                $body.Add(('My review found {0} that anyone can read today without signing in. Any website, application or person that reads {1} anonymously will lose access when the change is applied:' -f (Get-Pick $exposed 'a container' 'containers'), (Get-Pick $exposed 'it' 'them')))
                $body.Add($public.ToArray())
            }
            if ($closed.Count) {
                $body.Add($(if ($public.Count -or $unread.Count) { Get-Pick $closed.Count 'This account has no container open to anonymous access, so I do not expect the change to affect it:' 'These accounts have no container open to anonymous access, so I do not expect the change to affect them:' } else { Get-Pick $closed.Count 'The account has no container open to anonymous access today, so I do not expect any impact:' 'None of these accounts has a container open to anonymous access today, so I do not expect any impact:' }))
                $body.Add($closed.ToArray())
            }
            if ($unread.Count) {
                $body.Add((Get-Pick $unread.Count 'I could not read the container settings on this account, so please let me know if it serves public content:' 'I could not read the container settings on these accounts, so please let me know if any of them serve public content:'))
                $body.Add($unread.ToArray())
            }
            $body.Add($(if ($public.Count -or $unread.Count) { 'If a container is meant to be public, please tell me which one. I can leave its account out of this change and work with you on an authorized alternative, such as a shared access signature or Azure Front Door. Otherwise, could you confirm that I can go ahead and schedule the change?' }
                    else { 'Could you confirm that I can go ahead and schedule the change?' }))
            @{ Used = @('DP.1-CONTAINERS'); Cr = New-ChangeRequest @{
                    Number = 7; Key = 'storage-anonymous-access'; Title = 'Disable anonymous blob access on storage accounts'
                    Description = 'Set Allow Blob anonymous access to Disabled on {0}.' -f (Get-Listed $n 'storage account' 'storage accounts')
                    Purpose = 'Anonymous access lets anyone read the data in a public container without signing in. Disabling it at the account level blocks every anonymous request, whatever access level a container is set to.'
                    ResourceIntro = '{0} anonymous blob access, with the containers open to anonymous read today.' -f $(if ($n -eq 1) { 'The storage account below allows' } else { "The $n storage accounts below allow" })
                    ResourceLines = Format-ResourceList $resources
                    Availability = 'No impact on the storage service, since authorized requests are unaffected.'
                    UserExperience = $userExperience; Dependencies = $dependencies
                    Implementation = $impl.ToArray()
                    Testing = @(
                        ('In the Azure portal, open {0} and go to Settings > Configuration.' -f (Get-EachStep $n 'storage account'))
                        'Confirm Allow Blob anonymous access shows Disabled.')
                    Rollback = @(
                        'In the Azure portal, open the storage account to revert and go to Settings > Configuration.'
                        'Set Allow Blob anonymous access to Enabled and select Save. The container access levels are kept, so anonymous access returns as it was.')
                    References = @(, @('Remediate anonymous read access to blob data', 'https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent'))
                    Csv = $resources
                    Email = @{ Subject = 'Planned change: turning off anonymous access to Azure Blob Storage'; Body = $body.ToArray() }
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
            $apps = @($resources | Sort-Object Name | ForEach-Object { if ($_.Setting) { '{0} ({1})' -f $_.Name, $_.Setting } else { $_.Name } })
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
                    Email = @{ Subject = 'Planned change: HTTPS only for Azure App Service applications'; Body = @(
                            ('I am planning to turn on the HTTPS Only setting for {0}. With it on, requests made over plain HTTP are redirected to HTTPS, so all traffic to {1} is encrypted in transit.' -f $(if ($n -eq 1) { 'the App Service application below' } else { "the $n App Service applications below" }), $(if ($n -eq 1) { 'it' } else { 'them' }))
                            , $apps
                            ('Browsers follow the redirect automatically, so people using {0} should not notice a difference. An integration that calls {1} over http:// and does not follow redirects, such as an older API client or a webhook, may fail until it is updated to use https://.' -f (Get-Pick $n 'the application' 'these applications'), (Get-Pick $n 'it' 'one of them'))
                            ('Could you let me know whether any of your systems or partners still call {0} over HTTP? Once I have your confirmation, I will schedule the change.' -f (Get-Pick $n 'the application' 'these applications'))) }
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
            $resources = @($rows | Where-Object { Test-True $_.Eligible } | ForEach-Object { New-Resource $_.Name $_.resourceGroup $_.subscriptionId ('size {0}, {1}' -f (Get-Text $_.Size), (Get-PowerText $_.PowerState)) $_.ResourceId })
            $n = $resources.Count
            if (-not $n) { return @{ State = $(if ($rows.Count) { 'No eligible virtual machines' } else { 'No gaps found' }); Notes = $notes.ToArray() } }
            $impl = [System.Collections.Generic.List[object]]::new()
            foreach ($step in New-EncryptionAtHostRegistration $resources) { $impl.Add($step) }
            $impl.Add((Get-OpenStep $n 'Virtual machines' 'virtual machine'))
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
                ResourceIntro = $(if ($n -eq 1) { 'The virtual machine below is listed with its size and power state at collection. It is returned to the power state it has when the change is made.' } else { "The $n virtual machines below are listed with the size and power state of each at collection. Each machine is returned to the power state it has when the change is made." })
                ResourceLines = Format-ResourceList $resources
                Availability = 'Each virtual machine is unavailable for a few minutes while it is stopped and started inside the agreed maintenance window.'
                UserExperience = 'Users of each server lose access during its restart and see no change afterwards.'
                Dependencies = 'Needs the EncryptionAtHost feature on each subscription, a VM size that supports it and a machine that never used Azure Disk Encryption.'
                Implementation = $impl.ToArray()
                Testing = @(
                    ('In the Azure portal, open {0} and go to Settings > Disks > Additional settings.' -f (Get-EachStep $n 'virtual machine'))
                    'Confirm Encryption at host shows Yes.'
                    (Get-Pick $n 'On Overview, confirm the machine shows Running if it was running before the change.' 'On Overview, confirm each machine that was running before the change shows Running.'))
                Rollback = @(
                    'In the Azure portal, open the virtual machine to revert, note on Overview whether the status reads Running, then select Stop and wait for the status to read Stopped (deallocated).'
                    'Go to Settings > Disks > Additional settings, set Encryption at host to No and select Save.'
                    'Go back to Overview and select Start only if the status read Running before the stop.')
                References = $references
                Csv = $resources
                Email = @{ Subject = 'Maintenance window request: encryption at host for Azure virtual machines'; Body = @(
                        ('I am planning to enable encryption at host on {0}. This setting encrypts the temporary disk and the disk caches on the Azure host, so the data on {1} stays encrypted from the virtual machine all the way to Azure Storage.' -f $(if ($n -eq 1) { 'the virtual machine below' } else { "the $n virtual machines below" }), $(if ($n -eq 1) { 'this server' } else { 'these servers' }))
                        , @($resources | Sort-Object Name | ForEach-Object {
                                $state = switch -Regex ($_.Setting) { 'running$' { ', running at my last review' } '(deallocated|stopped)$' { ', stopped at my last review' } default { '' } }
                                '{0} (resource group {1}{2})' -f $_.Name, $_.ResourceGroup, $state })
                        (Get-Pick $n 'To apply it, the virtual machine has to be stopped first. If it is running at the time, it will be unavailable for a few minutes until I start it again, and if it is already stopped, it will be left stopped. Nothing changes inside the operating system or the applications.' 'To apply it, each virtual machine has to be stopped first. A server that is running at the time will be unavailable for a few minutes until I start it again, and a server that is already stopped will be left stopped. Nothing changes inside the operating system or the applications.')
                        (Get-Pick $n 'Could you suggest a maintenance window that works for this server? I will schedule the change once I have your confirmation.' 'Could you suggest a maintenance window that works for these servers, and let me know if any of them need to be handled separately or in a particular order? I will schedule the change once I have your confirmation.')) }
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
            $namespaces = @($resources | Sort-Object Name | ForEach-Object { '{0} (resource group {1}, {2})' -f $_.Name, $_.ResourceGroup, $_.Setting })
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
                    Email = @{ Subject = 'Planned change: minimum TLS 1.2 for Azure Event Hubs namespaces'; Body = @(
                            ('I am planning a security hardening change that sets the minimum TLS version to 1.2 on {0}. TLS 1.0 and 1.1 have known weaknesses, and once the change is applied {1} will refuse requests made over them.' -f $(if ($n -eq 1) { 'the Event Hubs namespace below' } else { "the $n Event Hubs namespaces below" }), (Get-Pick $n 'the namespace' 'these namespaces'))
                            , $namespaces
                            'Applications that send or receive events over TLS 1.2 or later see no change. An application, device or partner system that can only use TLS 1.0 or 1.1, for example one on an old operating system or runtime, will have its requests refused until it is updated.'
                            ('Could you let me know whether anything that connects to {0} may still use TLS 1.0 or 1.1? Once I have your confirmation, I will schedule the change.' -f (Get-Pick $n 'the namespace' 'these namespaces'))) }
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
            $models = @($rows | Where-Object { -not (Test-True $_.Aks) -and (Test-True $_.HasModel) })
            $ineligible = @($models | Where-Object { -not (Test-True $_.Eligible) })
            if ($ineligible.Count) {
                $notes.Add(('{0} left out of CR-15 because {1} encryption at host as {2}: {3}.' -f (Get-Count $ineligible.Count 'scale set' 'scale sets'), (Get-Pick $ineligible.Count 'its model cannot take' 'their models cannot take'), (Get-Pick $ineligible.Count 'it stands' 'they stand'),
                        (@($ineligible | Sort-Object Name | ForEach-Object { '{0} ({1}, {2})' -f (ConvertTo-CopyText $_.Name), (ConvertTo-CopyText $_.Size), ((ConvertTo-CopyText $_.Reason) -replace '^(size support not read):.*$', '$1') }) -join ', ')))
            }
            $eligible = @($models | Where-Object { Test-True $_.Eligible })
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
                    $setting = '{0}, {1}, {2}, size {3}' -f $mode, (Format-UpgradePolicy $_.UpgradePolicy), (Get-Count (Get-Number $_.Instances) 'instance' 'instances'), (ConvertTo-CopyText $_.Size)
                    if ($mode -eq 'Flexible') {
                        $members = @($instances[(Get-Text $_.ResourceId).ToLowerInvariant()])
                        $setting += if ($members.Count) { ', instances without encryption at host: ' + (@($members | Sort-Object Name | ForEach-Object { '{0} ({1})' -f (ConvertTo-CopyText $_.Name), (Get-PowerText $_.PowerState) }) -join ', ') } else { ', no instance without encryption at host' }
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
            $impl = [System.Collections.Generic.List[object]]::new()
            foreach ($step in New-EncryptionAtHostRegistration $resources) { $impl.Add($step) }
            $set = @(('In Cloud Shell, set encryption at host on the model of {0}{1}:' -f (Get-EachStep $n 'scale set'), $(if ($automatic.Count) { '. A scale set with an Automatic upgrade policy may take all its instances down at once to apply the new model, and one with a Rolling policy applies it in batches, so run this only inside the agreed maintenance window' } else { '' })))
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
                # have gained some since collection. A newer one created from the model has its size.
                $impl.Add(('In the Azure portal, go to Virtual machine scale sets, open the {0}Flexible scale set listed in the RESOURCES section, go to Settings > Instances and open the first instance listed there, since the scale set may have gained instances since collection.' -f $(if ($flex.Count -gt 1) { 'first ' } else { '' })))
                $impl.Add('Go to Settings > Disks > Additional settings and go on to the next instance if Encryption at host already shows Yes, or if the instance is not named in the RESOURCES section and its size differs from the size of the scale set, which leaves it for a follow-up change.')
                $impl.Add('On Overview, note whether the status reads Running, then select Stop and wait for the status to read Stopped (deallocated).')
                $impl.Add('Go to Settings > Disks > Additional settings, set Encryption at host to Yes and select Save.')
                $impl.Add('Go back to Overview and select Start only if the status read Running before the stop, so an instance that was not running stays stopped.')
                $impl.Add(('Repeat steps {0} to {1} for each remaining instance under Settings > Instances{2}.' -f ($from + 1), $impl.Count, $(if ($flex.Count -gt 1) { ", then steps $from to $($impl.Count) for each remaining Flexible scale set listed" } else { '' })))
            }
            $testing = [System.Collections.Generic.List[object]]::new()
            $testing.Add(('In the Azure portal, open {0}, select JSON View on Overview and confirm virtualMachineProfile.securityProfile.encryptionAtHost reads true.' -f (Get-EachStep $n 'scale set')))
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
            $body = [System.Collections.Generic.List[object]]::new()
            $body.Add(('I am planning to enable encryption at host on {0}. This setting encrypts the temporary disk and the disk caches on the Azure host, so the data of {1} stays encrypted all the way to Azure Storage.' -f $(if ($n -eq 1) { 'the virtual machine scale set below' } else { "the $n virtual machine scale sets below" }), (Get-Pick $n 'its instances' 'their instances')))
            $body.Add(@($resources | Sort-Object Name | ForEach-Object { '{0} (resource group {1}, {2})' -f $_.Name, $_.ResourceGroup, (Get-Count $_.Instances 'instance' 'instances') }))
            $body.Add(('The setting goes on the configuration of {0}, so new instances are encrypted from the start. Each existing instance has to be stopped and started again to pick it up, which I will do one instance at a time. An instance that is running at the time will be unavailable for a few minutes until I start it again, and an instance that is already stopped will be left stopped. Nothing changes inside the operating system or the applications.' -f (Get-Pick $n 'the scale set' 'each scale set')))
            if ($automatic.Count) {
                $body.Add(('{0} set to update {1} instances automatically, so once the setting is applied it may also restart them on its own, all at the same time under the Automatic policy and in batches under the Rolling policy. I will plan the window as if every instance could be unavailable at once: {2}.' -f $(if ($automatic.Count -eq 1) { 'One scale set is' } else { "$($automatic.Count) scale sets are" }), (Get-Pick $automatic.Count 'its' 'their'), (@($automatic | Sort-Object Name | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Policy }) -join ', ')))
            }
            $body.Add((Get-Pick $n 'Could you suggest a maintenance window that works for this scale set? I will schedule the change once I have your confirmation.' 'Could you suggest a maintenance window that works for these scale sets, and let me know if any of them need to be handled separately or in a particular order? I will schedule the change once I have your confirmation.'))
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
                ResourceIntro = $(if ($n -eq 1) { 'The scale set below is listed with its orchestration mode, upgrade policy, instance count and size at collection. Each instance is returned to the power state it has when the change is made.' } else { "The $n scale sets below are listed with the orchestration mode, upgrade policy, instance count and size of each at collection. Each instance is returned to the power state it has when the change is made." })
                ResourceLines = Format-ResourceList $resources
                Availability = $availability
                UserExperience = 'Users of a scale set see reduced capacity while one of its instances restarts, or a short outage where it runs a single instance, and no change afterwards.'
                Dependencies = 'Needs the EncryptionAtHost feature on each subscription, a VM size that supports it and a scale set that never used Azure Disk Encryption.'
                Implementation = $impl.ToArray(); Testing = $testing.ToArray(); Rollback = $rollback.ToArray()
                References = $references
                Csv = $resources
                Email = @{ Subject = 'Maintenance window request: encryption at host for Azure virtual machine scale sets'; Body = $body.ToArray() }
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
        $state = if ($cr) { 'Change request{0}' -f $(if ($cr.Email) { ' and client email' } else { '' }) } else { $built.State }
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
function Add-Output([string]$Name, [string[]]$Lines, [string]$NewLine = "`r`n", [bool]$Bom = $false, [bool]$Prose = $true) {
    $text = ($Lines -join $NewLine) + $NewLine
    if ($Prose) { Assert-CopyRules $text $Name }
    $outputs.Add([pscustomobject]@{ Path = Join-Path $folder $Name; Text = $text; Bom = $Bom })
}
foreach ($r in $results | Where-Object Cr) {
    $base = & $fileBase $r.Item
    Add-Output "$base.txt" (Format-ChangeRequest $r.Cr)
    if ($r.Cr.Email) { Add-Output "$base.email.txt" (Format-Email $r.Cr.Email) }
}

# The index: what was written, what was not and why, and the resources each change left out.
$packName = Split-Path -Leaf $pack
$md = [System.Collections.Generic.List[string]]::new()
$md.Add(('# Change requests: {0}' -f $client)); $md.Add('')
$md.Add(('Internal. Built {0} from evidence pack {1} (collector {2}). The change requests and client emails name client resources. Fill in the notification list of each change request, then send each client email and wait for the reply before scheduling that change.' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd', $inv), (ConvertTo-CopyText $packName), (Get-Text $parameters.ScriptVersion)))
$md.Add('')
$md.Add('| CR | Change | Resources | Status | Files |'); $md.Add('| --- | --- | --- | --- | --- |')
foreach ($r in $results) {
    $base = & $fileBase $r.Item
    $files = if ($r.Cr) { (@("$base.txt") + @(if ($r.Cr.Email) { "$base.email.txt" })) -join ', ' } else { '' }
    $md.Add(('| {0:00} | {1} | {2} | {3} | {4} |' -f $r.Item.Number, $r.Item.Change, $(if ($r.Cr) { @($r.Cr.Csv).Count } else { '' }), $r.State, $files))
}
$notes = @($results | ForEach-Object { $_.Notes })
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
