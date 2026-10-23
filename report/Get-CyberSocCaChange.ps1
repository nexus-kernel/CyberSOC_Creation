<#
    Conditional Access change requests shared by New-CyberSocChangeRequests.ps1 (CR-20, device code flow, and CR-21,
    legacy authentication, next) and their tests. Offline: it reads the raw policies the collector wrote to IA.8-POLICIES
    and the emergency access set from report/Get-CyberSocEmergencyAccess.ps1, and calls nothing.

    A change request that blocks one authentication path with Conditional Access uses three pieces:

      Get-CyberSocCaGap          whether an enabled policy already blocks the path for all users and all resources, and
                                 if not, which existing policy the change brings to the baseline rather than adding a
                                 duplicate beside it. A policy in report-only or Off, scoped to some users or resources,
                                 narrowed by a condition, or with exclusions beyond the baseline is a gap.
      Get-CyberSocCaExclusions   the exclusions every policy the change writes carries: each Atmosera group and each
                                 account matched by its UPN (decision 4 of the Oct 21 review), with the exception group.
      Get-CyberSocCaPolicySteps  the portal steps that create or edit the policy, then its report-only companion, which
                                 targets the exception group so the next pack shows whether each exception is still used.

    CR-21 calls them the same way with its own Match (Block and Legacy from Get-EbrCaPolicyFacts), baseline name,
    companion name, exception group and condition steps, and no excluded resource.
#>

. (Join-Path $PSScriptRoot 'Get-EbrCaEvaluation.ps1')

# Device Registration Service, the one resource the device code baseline may exclude, by its client ID (Microsoft Learn,
# Authentication flows in Conditional Access).
$script:CyberSocDeviceRegistrationAppId = '01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9'

function Get-CyberSocCaText($v) { if ($null -eq $v) { '' } else { ([string]$v).Trim() } }

# A Microsoft-managed policy. Microsoft Learn says their names start with Microsoft-managed:, and the portal shows
# Microsoft in the Created by column. They can be turned Off and take exclusions, but cannot be renamed or deleted.
function Test-CyberSocCaManaged([string]$Name) { $Name -match '^\s*Microsoft-managed\s*:' }

function Get-CyberSocCaGap {
    <#
    .SYNOPSIS
        Classifies every policy that blocks one authentication path, and decides what a change request does with them.
    .PARAMETER Policies
        IA.8-POLICIES rows, the policies exactly as Graph returned them.
    .PARAMETER Match
        Script block taking the facts of one policy (Get-EbrCaPolicyFacts) and returning true when it blocks the path.
    .PARAMETER Baseline
        The baseline policy name, such as ATMO-MXDR-CA-BLOCK-DEVICECODE. A policy of that name is the one the change edits.
        The raw policies carry group IDs only, so no excluded group is ever read as the approved exception group: on an
        enabled baseline policy otherwise in force, the groups beyond the emergency access set go to Review.
    .PARAMETER Companion
        The name of the report-only companion policy, which targets the exception group and is never read as a gap. A
        policy of that name already in the tenant is returned in Companions, so the change brings it to its settings rather
        than creating a second one.
    .PARAMETER ClientAppCondition
        The path is itself a client app condition, as legacy authentication is (CR-21). Otherwise a policy that selects some
        client app types rather than all of them blocks the path only for those, so it is a gap.
    .PARAMETER Access
        The emergency access set from Get-CyberSocEmergencyAccess. Its groups and accounts are never extra exclusions.
    .PARAMETER AllowedExcludeApps
        The application IDs the baseline lets a policy exclude from All resources.
    .OUTPUTS
        Policies   one row per matching policy: Id, Name, State, Managed, Reasons (why it is a gap), Extra (its exclusions
                   beyond the baseline), MissingAccess (the emergency access groups and accounts it does not exclude),
                   Covers (enabled with no reason).
        Covering   the enabled policies that block the path for all users and all resources.
        Target     the existing policy the change edits: the one named Baseline, or the only other candidate. Null when
                   the change creates the baseline policy.
        Others     the candidates the change leaves unchanged and names, when one named Baseline is edited.
        Managed    the Microsoft-managed policies that block the path.
        Ambiguous  more than one candidate and none named Baseline, so the change cannot tell which to edit.
        Companions the policies named Companion, whatever they hold: Id, Name, State.
        Review     the enabled policies named Baseline whose one gap is groups excluded beyond the emergency access set:
                   the block is in force for everyone else, so the change is not written, but the groups are named for
                   review and never read as no gaps, since a group for all staff would leave the path open to them.
    #>
    param($Policies, [Parameter(Mandatory)][scriptblock]$Match, [Parameter(Mandatory)][string]$Baseline, [string]$Companion = '', $Access, [string[]]$AllowedExcludeApps = @(), [switch]$ClientAppCondition)
    $allowedApps = @($AllowedExcludeApps | ForEach-Object { (Get-CyberSocCaText $_).ToLowerInvariant() })
    $rows = [System.Collections.Generic.List[object]]::new()
    $companions = [System.Collections.Generic.List[object]]::new()
    foreach ($p in @($Policies | Where-Object { $null -ne $_ })) {
        $f = Get-EbrCaPolicyFacts $p
        $name = Get-CyberSocCaText $f.Name
        if ($Companion -and $name -ieq $Companion) { $companions.Add([pscustomobject]@{ Id = Get-CyberSocCaText $f.Id; Name = $name; State = Get-CyberSocCaText $f.State }); continue }
        # A policy with the baseline name is the change's own policy even when its condition or grant has drifted, so it is
        # brought back to the baseline rather than duplicated under the same name.
        $matched = & $Match $f
        if (-not $matched -and $name -ine $Baseline) { continue }
        $c = Get-EbrCaValue $p 'conditions'
        $users = Get-EbrCaValue $c 'users'
        $apps = Get-EbrCaValue $c 'applications'
        $baselineName = $name -ieq $Baseline
        $isAccess = { param($id) [bool]$Access -and (Test-CyberSocEmergencyAccessId $Access $id) }
        $extraUsers = @($f.ExcludeUsers | Where-Object { -not (& $isAccess $_) })
        $extraGroups = @($f.ExcludeGroups | Where-Object { -not (& $isAccess $_) })
        $extraRoles = @($f.ExcludeRoles)
        $guests = $null -ne (Get-EbrCaValue $users 'excludeGuestsOrExternalUsers')
        $extraApps = @(Get-EbrCaList $apps 'excludeApplications' | Where-Object { $_.ToLowerInvariant() -notin $allowedApps })
        # Two conditions the policy facts leave out: an excluded platform and an application filter each take part of the
        # sign-ins out of the block.
        $excludedPlatforms = @(Get-EbrCaList (Get-EbrCaValue $c 'platforms') 'excludePlatforms')
        $appFilter = $null -ne (Get-EbrCaValue $apps 'applicationFilter')
        # Client app types other than all, which the policy facts leave out too, unless they are the path itself.
        $clientApps = @(Get-EbrCaList $c 'clientAppTypes')
        $someClientApps = -not $ClientAppCondition -and $clientApps.Count -and $clientApps -notcontains 'all'
        $state = Get-CyberSocCaText $f.State
        $reasons = @(
            if (-not $matched) { 'Control' }
            if ($state -eq 'enabledForReportingButNotEnforced') { 'Report-only' }
            elseif ($state -ne 'enabled') { 'Off' }
            if (-not $f.AllUsers) { 'Users' }
            if (-not $f.AllApps -or $extraApps.Count -or $appFilter) { 'Resources' }
            if ($f.Narrowed -or $excludedPlatforms.Count -or $someClientApps) { 'Conditions' }
            if ($extraUsers.Count -or $extraGroups.Count -or $extraRoles.Count -or $guests) { 'Exclusions' })
        $excluded = @(@($f.ExcludeUsers) + @($f.ExcludeGroups) | ForEach-Object { $_.ToLowerInvariant() })
        $missing = @(if ($Access) { @($Access.ExcludeGroups) + @($Access.ExcludeUsers) | Where-Object { $_ -and $_ -notin $excluded } })
        $rows.Add([pscustomobject]@{
                Id = Get-CyberSocCaText $f.Id; Name = $name; State = $state; Managed = Test-CyberSocCaManaged $name; Baseline = $baselineName
                Reasons = $reasons; Covers = -not $reasons.Count
                Extra = [pscustomobject]@{ Users = $extraUsers; Groups = $extraGroups; Roles = $extraRoles; Guests = $guests; Apps = $extraApps; Filter = $appFilter }
                GroupsOnly = $state -eq 'enabled' -and $baselineName -and (@($reasons) -join ',') -eq 'Exclusions' -and -not ($extraUsers.Count -or $extraRoles.Count -or $guests)
                ExcludedGroups = @($f.ExcludeGroups); MissingAccess = $missing
            })
    }
    $review = @($rows | Where-Object GroupsOnly)
    $candidates = @($rows | Where-Object { -not $_.Managed -and -not $_.Covers -and -not $_.GroupsOnly })
    $named = @($candidates | Where-Object Baseline)
    $target = if ($named.Count) { $named[0] } elseif ($candidates.Count -eq 1) { $candidates[0] } else { $null }
    [pscustomobject]@{
        Policies = $rows.ToArray()
        Covering = @($rows | Where-Object Covers)
        Target = $target
        Others = @($candidates | Where-Object { $target -and $_ -ne $target })
        Managed = @($rows | Where-Object Managed)
        Ambiguous = $candidates.Count -gt 1 -and -not $named.Count
        Review = $review
        Companions = $companions.ToArray()
    }
}

# What makes one policy a gap, in words for the change request, the index and the email.
function Format-CyberSocCaGapReason($Row) {
    $parts = @(foreach ($r in @($Row.Reasons)) {
            switch ($r) {
                'Control' { 'no longer has the condition and the Block grant of the baseline' }
                'Report-only' { 'is in report-only mode, so it records what it would do without blocking anything' }
                'Off' { 'is Off' }
                'Users' { 'applies to selected users only' }
                'Resources' { if (@($Row.Extra.Apps).Count -or $Row.Extra.Filter) { 'leaves out resources beyond what the baseline allows' } else { 'applies to selected resources only' } }
                'Conditions' { 'applies only on some platforms, client apps, locations, risk levels or devices' }
                'Exclusions' { 'leaves out {0} beyond the emergency access accounts' -f (Format-CyberSocCaExtra $Row.Extra) }
            } })
    if ($parts.Count -le 1) { $parts -join '' } else { (($parts | Select-Object -SkipLast 1) -join ', ') + ' and ' + $parts[-1] }
}

# The exclusions beyond the baseline, counted.
function Format-CyberSocCaExtra($Extra) {
    $count = { param([int]$n, [string]$one, [string]$many) if ($n -eq 1) { "1 $one" } else { "$n $many" } }
    $parts = @(
        if (@($Extra.Users).Count) { & $count @($Extra.Users).Count 'account' 'accounts' }
        if (@($Extra.Groups).Count) { & $count @($Extra.Groups).Count 'group' 'groups' }
        if (@($Extra.Roles).Count) { & $count @($Extra.Roles).Count 'directory role' 'directory roles' }
        if ($Extra.Guests) { 'guests or external users' })
    if ($parts.Count -le 1) { $parts -join '' } else { (($parts | Select-Object -SkipLast 1) -join ', ') + ' and ' + $parts[-1] }
}

function Get-CyberSocCaExclusions {
    # The exclusions every policy a Conditional Access change writes carries: each Atmosera group, so a new member is
    # covered without a change, each account matched by its UPN on its own, so it stays excluded if it leaves the group,
    # and the exception group of the change. Lines name each one with its object ID for the RESOURCES section.
    param([Parameter(Mandatory)]$Access, [string]$ExceptionGroup)
    $clean = { param($v) ((Get-CyberSocCaText $v) -replace ';', ',' -replace '[<>]', ' ' -replace '\s+', ' ').Trim() }
    $groups = @(foreach ($id in @($Access.ExcludeGroups)) {
            $g = @($Access.Groups | Where-Object { (Get-CyberSocCaText $_.GroupId).ToLowerInvariant() -eq $id }) | Select-Object -First 1
            'Atmosera group {0} ({1})' -f $(if ($g) { & $clean $g.DisplayName } else { 'unnamed' }), $id })
    $users = @(foreach ($id in @($Access.ExcludeUsers)) {
            $a = @($Access.Accounts | Where-Object { (Get-CyberSocCaText $_.PrincipalId).ToLowerInvariant() -eq $id }) | Select-Object -First 1
            'emergency access account {0} ({1})' -f $(if ($a) { & $clean $a.UserPrincipalName } else { 'unnamed' }), $id })
    [pscustomobject]@{
        Groups = $groups; Users = $users
        Lines = @($groups) + @($users) + @(if ($ExceptionGroup) { 'group {0}, the exception group' -f $ExceptionGroup })
        Count = @($Access.ExcludeGroups).Count + @($Access.ExcludeUsers).Count
    }
}

function Get-CyberSocCaPolicySteps {
    <#
    .SYNOPSIS
        The portal steps that bring one block policy to the baseline, from Entra ID > Conditional Access > Policies, then
        create its report-only companion. Step numbers in the text count from First, the number of the first step returned.
    .PARAMETER Target
        The policy to edit (a row of Get-CyberSocCaGap), or null to create the baseline policy.
    .PARAMETER Condition
        The step that sets the condition, such as Authentication flows set to Device code flow.
    .PARAMETER Resources
        The step that sets the target resources.
    #>
    param($Target, [Parameter(Mandatory)][string]$Baseline, [Parameter(Mandatory)][string]$Companion, [Parameter(Mandatory)][string]$ExceptionGroup, $ExistingCompanion,
        [Parameter(Mandatory)][string]$Condition, [Parameter(Mandatory)][string]$Resources, [int]$First = 1)
    $clean = { param($v) ((Get-CyberSocCaText $v) -replace ';', ',' -replace '[<>]', ' ' -replace '\s+', ' ').Trim() }
    $steps = [System.Collections.Generic.List[string]]::new()
    if ($Target) {
        $name = & $clean $Target.Name
        $steps.Add(('Open the policy {0} ({1}).{2}' -f $name, $Target.Id, $(if ($Target.Baseline) { '' } else { ' Rename it {0}, so the baseline policy keeps one name across clients.' -f $Baseline })))
    }
    else { $steps.Add(('Select New policy and name it {0}.' -f $Baseline)) }
    $steps.Add('Under Assignments, select Users or workload identities. Under Include, select All users.')
    $steps.Add(('Under Exclude, select Users and groups and add each Atmosera group and each emergency access account listed in the RESOURCES section, and the group {0}.{1}' -f $ExceptionGroup, $(if ($Target -and @($Target.Reasons) -contains 'Exclusions') { ' Remove every other exclusion listed for the policy in the RESOURCES section, after the accounts the client confirmed were added to the group, and never remove an Atmosera group or an emergency access account.' } else { '' })))
    $steps.Add($Resources)
    $steps.Add(('{0}{1}' -f $Condition, $(if ($Target) { ' Set every other condition the policy has to Not configured.' } else { ' Leave every other condition not configured.' })))
    $steps.Add('Under Access controls, select Grant, select Block access and select Select.')
    $steps.Add(('Set Enable policy to On and select {0}.' -f $(if ($Target) { 'Save' } else { 'Create' })))
    if ($ExistingCompanion) {
        # A companion already in the tenant, from an earlier change or one that drifted, is brought to its settings rather
        # than duplicated, since one left On would block the approved accounts.
        $steps.Add(('Open the policy {0} ({1}), which already exists. Under Users or workload identities, set Include to the group {2} only. Under Exclude, remove every exclusion it has, the group {2} and any of its members included, so the companion watches every excepted account, then exclude each Atmosera group and each emergency access account as in step {3}. Set the target resources, the condition and the grant as in steps {4} to {5}, and every other condition to Not configured.' -f $Companion, $ExistingCompanion.Id, $ExceptionGroup, ($First + 2), ($First + 3), ($First + 5)))
        $steps.Add('Set Enable policy to Report-only and select Save. It blocks nothing and records each sign-in by an excepted account that the block would refuse.')
    }
    else {
        $steps.Add(('Select New policy and name it {0}. Under Users or workload identities, include the group {1} only, and exclude each Atmosera group and each emergency access account as in step {2}. Set the target resources, the condition and the grant as in steps {3} to {4}.' -f $Companion, $ExceptionGroup, ($First + 2), ($First + 3), ($First + 5)))
        $steps.Add('Set Enable policy to Report-only and select Create. It blocks nothing and records each sign-in by an excepted account that the block would refuse.')
    }
    $steps.ToArray()
}
