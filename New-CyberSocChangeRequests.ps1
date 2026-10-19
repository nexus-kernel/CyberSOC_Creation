<#
.SYNOPSIS
    Writes the change requests for the low-impact security hardening items in an evidence pack.
.DESCRIPTION
    Offline only. Reads the manifest, parameters and the per-resource hardening results of a finished
    pack and writes one change request for each hardening item that still has resources to fix, laid
    out on the change request template: diagnostic logging through the ATMO-MXDR-DIAG-TOSENT initiative,
    secure transfer and minimum TLS 1.2 on storage accounts, minimum TLS 1.2 on App Service and Azure
    SQL, and Key Vault purge protection. The changes that need the client first (anonymous blob access,
    HTTPS only on App Service and encryption at host) also get a client email, drafted and ready to send.

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
.PARAMETER ClientContact
    The name the client emails open with. Without it they open with Hello.
.PARAMETER SenderName
    The name under the sign-off of the client emails.
.EXAMPLE
    ./New-CyberSocChangeRequests.ps1 -EvidencePath ./CyberSOC-Evidence_Contoso_2026-09_20261003-090000
.EXAMPLE
    ./New-CyberSocChangeRequests.ps1 -EvidencePath ./CyberSOC-Evidence_Contoso_2026-09_20261003-090000 -DrClient -ClientContact 'Dana' -SenderName 'Scott'
.NOTES
    The per-resource results (P0.7, NB.4-DETAIL, NB.5-DETAIL, NB.6-DETAIL, DP.1-DETAIL, DP.2-DETAIL and
    DR.6-NONCOMPLIANT) were added in CyberSOC collector 1.1.0. Changes that read them say "needs
    recollection" on packs collected with an earlier version.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$EvidencePath,
    [string]$OutputPath,
    [switch]$DrClient,
    [string]$SentinelWorkspace,
    [string]$ClientContact,
    [string]$SenderName
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
# The CyberSOC collector that added the per-resource results, for the needs recollection status.
$detailIds = 'P0.7', 'NB.4-DETAIL', 'NB.5-DETAIL', 'NB.6-DETAIL', 'DP.1-DETAIL', 'DP.2-DETAIL', 'DR.6-NONCOMPLIANT'
$needsRecollection = 'Needs recollection with CyberSOC collector 1.1.0 or later'

function Get-Text($value) { if ($null -eq $value) { '' } else { ([string]$value).Trim() } }
function Test-True($value) { $v = Get-Text $value; $v -eq '1' -or $v -ieq 'true' }
function Get-Number($value) { $n = 0; if ([int]::TryParse((Get-Text $value), [ref]$n)) { $n } else { 0 } }
function Get-Status([string]$id) {
    $row = $manifest | Where-Object ResultId -eq $id | Select-Object -First 1
    if ($null -eq $row) { 'MISSING' } else { [string]$row.Status }
}
function Get-Rows([string]$id) {
    $file = Join-Path $pack "results/$id.json"
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { return @() }
    try { return @(Get-Content -LiteralPath $file -Raw | ConvertFrom-Json | Where-Object { $null -ne $_ }) }
    catch { Write-Warning "$id could not be read. Regenerate or recollect this result."; return @() }
}

# Copy rules: no semicolons, arrows, emoji or angle brackets, and the greater-than sign only in a
# navigation step such as Settings > Configuration. Values read from the pack are cleaned first, and
# every file is checked before it is written, so a rule broken by the text below stops the run.
function ConvertTo-CopyText($value) {
    $v = (Get-Text $value) -replace ';', ',' -replace '[<>]', ' '
    $v = $v -replace '[\u2190-\u21FF\u27F0-\u27FF\u2900-\u297F\u2B00-\u2BFF\u2600-\u27BF\uD800-\uDFFF]', ''
    ($v -replace '\s+', ' ').Trim()
}
function Assert-CopyRules([string]$Text, [string]$Label) {
    $broken = @(
        if ($Text -match ';') { 'a semicolon' }
        if ($Text -match '[\u2190-\u21FF\u27F0-\u27FF\u2900-\u297F\u2B00-\u2BFF\u25B6\u25BA]|->|=>') { 'an arrow' }
        if ($Text -match '[\u2600-\u27BF\uD800-\uDFFF]') { 'an emoji' }
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
    $id = (Get-Text $s.subscriptionId).ToLowerInvariant()
    if ($id) { $subscriptionNames[$id] = ConvertTo-CopyText $s.SubscriptionName }
}
function Format-Subscription([string]$id) {
    $key = (Get-Text $id).ToLowerInvariant()
    if ($subscriptionNames[$key]) { '{0} ({1})' -f $subscriptionNames[$key], $key } else { $key }
}
function New-Resource([string]$Name, [string]$ResourceGroup, [string]$SubscriptionId, [string]$Setting, [string]$ResourceId) {
    [pscustomobject]@{
        Name = ConvertTo-CopyText $Name; ResourceGroup = ConvertTo-CopyText $ResourceGroup
        SubscriptionId = (Get-Text $SubscriptionId).ToLowerInvariant(); Setting = ConvertTo-CopyText $Setting; ResourceId = Get-Text $ResourceId
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
    switch -Regex (Get-Text $value) { '^TLS1_(\d)$' { '1.' + $Matches[1] } '^(|None)$' { 'not set' } default { ConvertTo-CopyText $value } }
}

$workspaces = @($parameters.Workspaces | Where-Object { $_ })
$workspaceName = if ($SentinelWorkspace) { ConvertTo-CopyText $SentinelWorkspace } elseif ($workspaces.Count -eq 1) { ConvertTo-CopyText $workspaces[0].Name } else { '' }
$workspace = if ($workspaceName) { "the Sentinel workspace $workspaceName" } else { 'the client Sentinel workspace' }
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

function New-DiagnosticAssignment {
    $subscriptions = @($parameters.Subscriptions | ForEach-Object { (Get-Text $_).ToLowerInvariant() } | Where-Object { $_ })
    $counts = [ordered]@{}
    foreach ($row in @(Get-Rows 'P0.5')) {
        $type = (Get-Text $row.ResourceType).ToLowerInvariant()
        if ($diagnosticTypes.Contains($type)) { $counts[$type] = [int]$counts[$type] + (Get-Number $row.Resources) }
    }
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('Subscriptions:')
    foreach ($s in $subscriptions) { $lines.Add('- ' + (Format-Subscription $s)) }
    $lines.Add(''); $lines.Add('Resource types the initiative covers:')
    # With the estate inventory (P0.5) only the types present are listed, with their counts.
    foreach ($type in $diagnosticTypes.Keys) {
        if ($counts.Count -and -not $counts[$type]) { continue }
        $lines.Add('- ' + $diagnosticTypes[$type][1] + $(if ($counts.Count) { ': ' + $counts[$type] } else { '' }))
    }
    $lines.Add('- Subscription Activity Log: ' + $subscriptions.Count)
    $lines.Add(''); $lines.Add("Destination: $workspace")
    $intro = 'The initiative is assigned at the client top management group, or at each subscription below when there is no management group, and covers the resource types listed{0}.' -f $(if ($counts.Count) { ' with their current counts' } else { '' })
    @{ Cr = New-ChangeRequest @{
            Number = 1; Key = 'diagnostic-logging'; Title = 'Deploy the ATMO-MXDR diagnostic logging initiative'
            Description = "Assign the ATMO-MXDR-DIAG-TOSENT Azure Policy initiative and run its remediation tasks, so the audit logs of supported Azure resources are sent to $workspace."
            Purpose = 'The initiative keeps audit logging in place on every supported resource, including resources created later. Sending these logs to Sentinel gives the SOC the telemetry it needs to detect and investigate activity on them.'
            ResourceIntro = $intro; ResourceLines = $lines.ToArray()
            Availability = 'No impact, since the Azure platform applies diagnostic settings without touching the running workloads.'
            UserExperience = 'No change for users or applications.'
            Dependencies = 'Relies on the ATMO-MXDR-DIAG-MI managed identity and adds a small amount of audit log ingestion to the Sentinel workspace.'
            Implementation = @(
                'In the Azure portal, go to Policy > Authoring > Definitions and open the ATMO-MXDR-DIAG-TOSENT initiative.'
                'Select Assign initiative.'
                'On the Basics tab, set Scope to the client top management group, or to each subscription listed in the RESOURCES section when there is no management group, and name the assignment ATMO-MXDR-DIAG-TOSENT.'
                "On the Parameters tab, set the Log Analytics workspace to $workspace."
                'On the Remediation tab, set the managed identity type to User assigned managed identity and select ATMO-MXDR-DIAG-MI.'
                'Select Review + create > Create.'
                'Once the first compliance scan completes, go to Policy > Remediation, select the Policies to remediate tab, select the ATMO-MXDR-DIAG-TOSENT assignment and create a remediation task for each policy in the initiative.')
            Testing = @(
                'In the Azure portal, go to Policy > Compliance and open the ATMO-MXDR-DIAG-TOSENT assignment.'
                'Confirm the resources in scope show as Compliant.'
                "Open one resource of each type listed in the RESOURCES section, go to Monitoring > Diagnostic settings and confirm the ATMO-MXDR setting sends to $workspace.")
            Rollback = @(
                'In the Azure portal, go to Policy > Authoring > Assignments, open the ATMO-MXDR-DIAG-TOSENT assignment and select Delete assignment.'
                'On each resource the remediation tasks updated, go to Monitoring > Diagnostic settings, select Edit setting on the ATMO-MXDR setting and select Delete.')
            References = @(, @('Assign a policy in the Azure portal', 'https://learn.microsoft.com/azure/governance/policy/assign-policy-portal')) + $diagnosticReferences
            Csv = @($subscriptions | ForEach-Object { New-Resource $_ '' $_ 'Initiative assignment scope' "/subscriptions/$_" })
        } }
}

function New-DiagnosticRemediation($rows) {
    $resources = foreach ($r in $rows) {
        $id = Get-Text $r.ResourceId
        $type = (Get-Text $r.ResourceType).ToLowerInvariant()
        $parts = $id.Split('/')
        $sub = if ($parts.Count -gt 2) { $parts[2] } else { '' }
        $label = if ($diagnosticTypes.Contains($type)) { $diagnosticTypes[$type][0] } else { ConvertTo-CopyText $type }
        if ($id -match '^/subscriptions/[^/]+$') { New-Resource 'Subscription Activity Log' '' $sub ('policies ' + (Get-Text $r.Policies)) $id }
        else {
            $rg = if ($id -match '/resourcegroups/([^/]+)/') { $Matches[1] } else { '' }
            New-Resource $parts[-1] $rg $sub ('{0}, policies {1}' -f $label, (Get-Text $r.Policies)) $id
        }
    }
    $resources = @($resources)
    $policies = @($rows | ForEach-Object { (Get-Text $_.Policies) -split ',\s*' } | Where-Object { $_ } | ForEach-Object { ConvertTo-CopyText $_ } | Sort-Object -Unique)
    $assignments = @($rows | ForEach-Object { ConvertTo-CopyText $_.AssignmentName } | Where-Object { $_ } | Sort-Object -Unique)
    $assignment = if ($assignments.Count -eq 1) { "the $($assignments[0]) assignment" } else { 'the ATMO-MXDR assignment' }
    $activity = @($resources | Where-Object { $_.ResourceId -match '^/subscriptions/[^/]+$' }).Count
    $impl = [System.Collections.Generic.List[object]]::new()
    $impl.Add('In the Azure portal, go to Policy > Remediation and select the Policies to remediate tab.')
    $impl.Add("Select $assignment and select New remediation task.")
    $impl.Add(('Choose the policy {0}, keep the scope at the assignment scope and select Remediate.' -f $policies[0]))
    if ($policies.Count -gt 1) { $impl.Add(('Repeat steps 2 and 3 for each remaining policy: {0}.' -f (@($policies | Select-Object -Skip 1) -join ', '))) }
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
    @{ Cr = New-ChangeRequest @{
            Number = 1; Key = 'diagnostic-logging'; Title = 'Remediate resources missing ATMO-MXDR diagnostic logging'
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

$catalog = @(
    @{ Number = 1; Key = 'diagnostic-logging'; Change = 'Diagnostic logging through the ATMO-MXDR-DIAG-TOSENT initiative'; Sources = @('DR.6-INITIATIVE')
       Build = {
            $initiative = @(Get-Rows 'DR.6-INITIATIVE')
            if ((Get-Status 'DR.6-INITIATIVE') -eq 'EMPTY' -or $initiative.Count -eq 0) { return New-DiagnosticAssignment }
            $nonCompliant = 0
            foreach ($r in $initiative) { $nonCompliant += Get-Number $r.NonCompliant }
            if ($nonCompliant -eq 0) { return @{ State = 'No gaps found, every resource is compliant with the initiative' } }
            $status = Get-Status 'DR.6-NONCOMPLIANT'
            if ($status -eq 'MISSING') { return @{ State = $needsRecollection } }
            if ($status -notin 'OK', 'PARTIAL', 'EMPTY') { return @{ State = "Not collected (DR.6-NONCOMPLIANT $status)" } }
            $rows = @(Get-Rows 'DR.6-NONCOMPLIANT')
            if (-not $rows.Count) { return @{ State = 'No gaps found in DR.6-NONCOMPLIANT' } }
            New-DiagnosticRemediation $rows } }

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
                        'Set Minimum TLS version back to the version recorded for the account in the RESOURCES section and select Save.')
                    References = @(
                        , @('Enforce a minimum required version of TLS for requests to a storage account', 'https://learn.microsoft.com/azure/storage/common/transport-layer-security-configure-minimum-version')
                        , @('Migrate to TLS 1.2 for Azure Storage', 'https://learn.microsoft.com/azure/storage/common/transport-layer-security-configure-migrate-to-tls2'))
                    Csv = $resources
                } } } }

    @{ Number = 4; Key = 'app-service-minimum-tls'; Change = 'Minimum TLS 1.2 on App Service apps'; Sources = @('NB.5-DETAIL')
       Build = {
            $resources = @(Get-Rows 'NB.5-DETAIL' | ForEach-Object { New-Resource $_.Name $_.resourceGroup $_.subscriptionId ('minimum TLS ' + (Format-TlsVersion $_.MinTlsVersion)) $_.ResourceId })
            $n = $resources.Count
            if (-not $n) { return @{ State = 'No gaps found' } }
            $impl = [System.Collections.Generic.List[object]]::new()
            $impl.Add((Get-OpenStep $n 'App Services' 'app'))
            $impl.Add('Go to Settings > Configuration and select the General settings tab.')
            $impl.Add('Set Minimum Inbound TLS Version to 1.2, select Apply and confirm.')
            Add-RepeatStep $impl $n 1 'app'
            @{ Cr = New-ChangeRequest @{
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
            @{ Cr = New-ChangeRequest @{
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
                } } } }

    @{ Number = 7; Key = 'storage-anonymous-access'; Change = 'Anonymous blob access disabled on storage accounts'; Sources = @('DP.1-DETAIL')
       Build = {
            # The containers each account holds (DP.1-CONTAINERS) name what anonymous readers lose.
            $containers = @{}
            $containersRead = (Get-Status 'DP.1-CONTAINERS') -in 'OK', 'PARTIAL', 'EMPTY'
            if ($containersRead) { foreach ($c in @(Get-Rows 'DP.1-CONTAINERS')) { $containers[(Get-Text $c.ResourceId).ToLowerInvariant()] = $c } }
            $public = [System.Collections.Generic.List[string]]::new()
            $closed = [System.Collections.Generic.List[string]]::new()
            $unread = [System.Collections.Generic.List[string]]::new()
            $exposed = 0
            $resources = @(Get-Rows 'DP.1-DETAIL' | Where-Object { Test-True $_.AllowBlobPublicAccess } | ForEach-Object {
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
            @{ Cr = New-ChangeRequest @{
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

    @{ Number = 9; Key = 'encryption-at-host'; Change = 'Encryption at host on virtual machines'; Sources = @('DP.4-DETAIL')
       Build = {
            $rows = @(Get-Rows 'DP.4-DETAIL')
            # Scale sets take the setting through their model and an instance update, and AKS node pools
            # through the node pool, so they need their own change.
            $scaleSets = @($rows | Where-Object { (Get-Text $_.ResourceType) -match 'scalesets' })
            $notes = @(if ($scaleSets.Count) { '{0} left out of CR-09: {1}. Scale sets take encryption at host through their model and an instance update, and AKS node pools through the node pool, so they need their own change.' -f (Get-Count $scaleSets.Count 'scale set' 'scale sets'), (@($scaleSets | ForEach-Object { ConvertTo-CopyText $_.Name }) -join ', ') })
            $vms = @($rows | Where-Object { $_ -notin $scaleSets })
            $resources = @($vms | ForEach-Object { New-Resource $_.Name $_.resourceGroup $_.subscriptionId ('size {0}, {1}' -f (Get-Text $_.Size), (Get-PowerText $_.PowerState)) '' })
            $n = $resources.Count
            if (-not $n) { return @{ State = $(if ($scaleSets.Count) { 'Only scale sets remain' } else { 'No gaps found' }); Notes = $notes } }
            $subscriptions = @($resources | ForEach-Object SubscriptionId | Sort-Object -Unique)
            $register = @('In the Azure portal, open Cloud Shell in Bash and register the EncryptionAtHost feature on each subscription in the RESOURCES section:')
            foreach ($s in $subscriptions) { $register += "az account set --subscription $s"; $register += 'az feature register --name EncryptionAtHost --namespace Microsoft.Compute' }
            $impl = [System.Collections.Generic.List[object]]::new()
            $impl.Add($register)
            $impl.Add('Run az feature show --name EncryptionAtHost --namespace Microsoft.Compute on each subscription and continue once the state reads Registered.')
            $impl.Add((Get-OpenStep $n 'Virtual machines' 'virtual machine'))
            $impl.Add('On Overview, select Stop and wait for the status to read Stopped (deallocated).')
            $impl.Add('Go to Settings > Disks > Additional settings, set Encryption at host to Yes and select Save.')
            $impl.Add('Go back to Overview and select Start, unless the RESOURCES section lists the machine as deallocated.')
            Add-RepeatStep $impl $n 3 'virtual machine'
            $references = @(
                , @('Use the Azure portal to enable end-to-end encryption using encryption at host', 'https://learn.microsoft.com/azure/virtual-machines/disks-enable-host-based-encryption-portal')
                , @('Overview of managed disk encryption options, encryption at host', 'https://learn.microsoft.com/azure/virtual-machines/disk-encryption#encryption-at-host---end-to-end-encryption-for-your-vm-data'))
            $spec = @{
                Number = 9; Key = 'encryption-at-host'; Title = 'Enable encryption at host on virtual machines'
                Description = 'Enable encryption at host on {0}, which needs a stop and start of each machine.' -f (Get-Listed $n 'virtual machine' 'virtual machines')
                Purpose = 'Encryption at host encrypts the temporary disk and the OS and data disk caches on the Azure host, so the data of each machine is encrypted from end to end. Platform encryption covers only the managed disks at rest, which leaves these paths unencrypted today.'
                ResourceIntro = '{0} with the size and power state of each at collection.' -f $(if ($n -eq 1) { 'The virtual machine below is listed' } else { "The $n virtual machines below are listed" })
                ResourceLines = Format-ResourceList $resources
                Availability = 'Each virtual machine is unavailable for a few minutes while it is stopped and started inside the agreed maintenance window.'
                UserExperience = 'Users of each server lose access during its restart and see no change afterwards.'
                Dependencies = 'Needs the EncryptionAtHost feature on each subscription, a VM size that supports it and a machine that never used Azure Disk Encryption.'
                Implementation = $impl.ToArray()
                Testing = @(
                    ('In the Azure portal, open {0} and go to Settings > Disks > Additional settings.' -f (Get-EachStep $n 'virtual machine'))
                    'Confirm Encryption at host shows Yes.'
                    'On Overview, confirm each machine that was running before the change shows Running.')
                Rollback = @(
                    'In the Azure portal, open the virtual machine to revert, select Stop on Overview and wait for the status to read Stopped (deallocated).'
                    'Go to Settings > Disks > Additional settings, set Encryption at host to No and select Save.'
                    'Go back to Overview and select Start.')
                References = $references
                Csv = $resources
                Email = @{ Subject = 'Maintenance window request: encryption at host for Azure virtual machines'; Body = @(
                        ('I am planning to enable encryption at host on {0}. This setting encrypts the temporary disk and the disk caches on the Azure host, so the data on {1} stays encrypted from the virtual machine all the way to Azure Storage.' -f $(if ($n -eq 1) { 'the virtual machine below' } else { "the $n virtual machines below" }), $(if ($n -eq 1) { 'this server' } else { 'these servers' }))
                        , @($resources | Sort-Object Name | ForEach-Object {
                                $state = if ($_.Setting -match 'deallocated$') { 'currently stopped and will be left stopped' } else { 'currently ' + ($_.Setting -replace '^size [^,]*, ', '') }
                                '{0} (resource group {1}, {2})' -f $_.Name, $_.ResourceGroup, $state })
                        ('To apply it, each virtual machine has to be stopped and started again. Each server will be unavailable for a few minutes while this happens, and nothing changes inside the operating system or the applications.')
                        ('Could you suggest a maintenance window that works for {0}, and let me know if any of them need to be handled separately or in a particular order? I will schedule the change once I have your confirmation.' -f $(if ($n -eq 1) { 'this server' } else { 'these servers' }))) }
            }
            if ($DrClient) {
                $spec.DrImpact = 'This is a DR client. Azure Site Recovery does not carry encryption at host to test failover or failover virtual machines, so the DR Playbook needs an update.'
                $spec.DrPlan = @(
                    'In the DR Playbook, add a post-failover step for the virtual machines listed in this change.'
                    'The step stops each failed over virtual machine, sets Encryption at host to Yes under Settings > Disks > Additional settings, selects Save and starts the machine again.'
                    'Attach the link to the updated DR Playbook, or a screenshot of the new step, to this change request before it is closed.')
                $spec.References = $references + , @('Support matrix for Azure VM disaster recovery, replicated machines storage', 'https://learn.microsoft.com/azure/site-recovery/azure-to-azure-support-matrix#replicated-machines---storage')
            }
            @{ Notes = $notes; Cr = New-ChangeRequest $spec } } }
)
#endregion

# Resolve every change to its status and build the change requests.
$results = foreach ($item in $catalog) {
    $state = ''; $cr = $null; $notes = @()
    $missing = @($item.Sources | Where-Object { (Get-Status $_) -eq 'MISSING' })
    $failed = @($item.Sources | Where-Object { (Get-Status $_) -notin 'OK', 'PARTIAL', 'EMPTY', 'MISSING' })
    if ($missing.Count) { $state = if (@($missing | Where-Object { $_ -in $detailIds }).Count) { $needsRecollection } else { "Not collected ($($missing -join ', '))" } }
    elseif ($failed.Count) { $state = 'Not collected ({0})' -f (@($failed | ForEach-Object { "$_ $(Get-Status $_)" }) -join ', ') }
    else {
        $built = & $item.Build
        $cr = $built.Cr
        $notes = @($built.Notes | Where-Object { $_ })
        $state = if ($cr) { 'Change request{0}' -f $(if ($cr.Email) { ' and client email' } else { '' }) } else { $built.State }
        if ($cr -and @($item.Sources | Where-Object { (Get-Status $_) -eq 'PARTIAL' }).Count) { $state += ', partial collection scope' }
    }
    [pscustomobject]@{ Item = $item; State = $state; Cr = $cr; Notes = $notes }
}

# Write the files. Earlier runs may have left a change request this run no longer needs, so the
# files this script names are cleared first. Nothing else in the folder is touched.
$folder = if ($OutputPath) { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath) } else { Join-Path $pack '05-change-requests' }
if (-not (Test-Path -LiteralPath $folder -PathType Container)) { [void](New-Item -ItemType Directory -Path $folder -Force) }
$fileBase = { param($item) 'CR-{0:00}-{1}' -f $item.Number, $item.Key }
foreach ($item in $catalog) {
    foreach ($suffix in '.txt', '.email.txt') {
        $old = Join-Path $folder ((& $fileBase $item) + $suffix)
        if (Test-Path -LiteralPath $old -PathType Leaf) { Remove-Item -LiteralPath $old }
    }
}
$utf8 = [Text.UTF8Encoding]::new($false)
$written = [System.Collections.Generic.List[string]]::new()
function Write-CopyFile([string]$Path, [string[]]$Lines, [string]$NewLine = "`r`n") {
    $text = ($Lines -join $NewLine) + $NewLine
    Assert-CopyRules $text (Split-Path -Leaf $Path)
    [IO.File]::WriteAllText($Path, $text, $utf8)
    $written.Add($Path)
}
foreach ($r in $results | Where-Object Cr) {
    $base = Join-Path $folder (& $fileBase $r.Item)
    Write-CopyFile "$base.txt" (Format-ChangeRequest $r.Cr)
    if ($r.Cr.Email) { Write-CopyFile "$base.email.txt" (Format-Email $r.Cr.Email) }
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
if ((Get-Status 'P0.7') -notin 'OK', 'PARTIAL') { $notes += 'Subscription names were not collected (P0.7), so the change requests show subscription IDs only.' }
if ($notes.Count) { $md.Add(''); $md.Add('## Notes'); $md.Add(''); foreach ($n in $notes) { $md.Add("- $n") } }
$indexPath = Join-Path $folder '00-index.md'
Write-CopyFile $indexPath $md.ToArray() "`n"

# CSV: one row per resource in each change request, for tracking the work.
$csvRows = foreach ($r in $results | Where-Object Cr) {
    foreach ($res in @($r.Cr.Csv)) {
        [pscustomobject]@{ CR = 'CR-{0:00}' -f $r.Item.Number; Change = $r.Cr.Title; Subscription = Format-Subscription $res.SubscriptionId; ResourceGroup = $res.ResourceGroup; Resource = $res.Name; CurrentSetting = $res.Setting; ResourceId = $res.ResourceId }
    }
}
$csvLines = @('"CR","Change","Subscription","ResourceGroup","Resource","CurrentSetting","ResourceId"')
if (@($csvRows).Count) { $csvLines = @($csvRows | ConvertTo-Csv -NoTypeInformation) }
$csvPath = Join-Path $folder 'change-requests.csv'
[IO.File]::WriteAllText($csvPath, (($csvLines -join "`r`n") + "`r`n"), [Text.UTF8Encoding]::new($true))
$written.Add($csvPath)
$written.ToArray()
