<#
    Emergency access accounts shared by Get-CyberSocEvidence.ps1 (IA.16-ACCOUNTS and IA.16-GROUPS),
    New-CyberSocChangeRequests.ps1 (the emergency access gate and the index section) and their tests. Offline: it
    matches what the collector read and reads collected results only.

    The emergency access accounts are every account with Atmosera in its user principal name, members and guests
    alike, and every account that is a member of an Atmosera group, directly or through a nested group (decision 4
    of the Oct 21 review). Every Conditional Access change excludes them, and no change removes their access.

    Using the set in a change request: give its catalog entry in New-CyberSocChangeRequests.ps1 EmergencyAccess =
    $true. The change request is then written only when $emergencyAccess.Ready is true, and its Build reads
    $emergencyAccess: ExcludeGroups and ExcludeUsers are what every Conditional Access policy it proposes excludes,
    and Test-CyberSocEmergencyAccessId tells it which existing exclusion it must never propose to remove.

    A change that removes access, such as CR-19, leaves out every account Test-CyberSocEmergencyAccessUpn or
    Test-CyberSocEmergencyAccessId names, and is written only when $emergencyAccess.Complete is true.
#>

# The word that marks an emergency access account or group, matched anywhere in the value without regard to case.
$script:CyberSocEmergencyAccessWord = 'atmosera'

# An account whose user principal name holds the word. A guest from an Atmosera domain carries it in its #EXT# name
# (the external address with @ turned into _), so it matches too.
function Test-CyberSocEmergencyAccessUpn([string]$UserPrincipalName) {
    [bool]$UserPrincipalName -and $UserPrincipalName.IndexOf($script:CyberSocEmergencyAccessWord, [StringComparison]::OrdinalIgnoreCase) -ge 0
}

# An Atmosera group: a group whose display name holds the word. This is the one place the rule lives. The owner is
# still to confirm that it matches the naming in use, so change it here and both the collector and the generator follow.
function Test-CyberSocEmergencyAccessGroup([string]$DisplayName) {
    [bool]$DisplayName -and $DisplayName.IndexOf($script:CyberSocEmergencyAccessWord, [StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Get-CyberSocEaProp($o, [string]$Name) { if ($null -ne $o -and $o.PSObject.Properties[$Name]) { $o.$Name } else { $null } }
function Get-CyberSocEaText($v) { if ($null -eq $v) { '' } else { ([string]$v).Trim() } }
function Test-CyberSocEaTrue($v) { $t = Get-CyberSocEaText $v; $t -eq '1' -or $t -ieq 'true' }

# The membership type of a group: Dynamic (a rule decides the members), On-premises (synced from Active Directory,
# managed there) or Assigned.
function Get-CyberSocEaMembership($Group) {
    if (@(Get-CyberSocEaProp $Group 'groupTypes') -contains 'DynamicMembership') { 'Dynamic' }
    elseif (Test-CyberSocEaTrue (Get-CyberSocEaProp $Group 'onPremisesSyncEnabled')) { 'On-premises' }
    else { 'Assigned' }
}

function ConvertTo-CyberSocEmergencyAccessRows {
    # The rows of IA.16-ACCOUNTS and IA.16-GROUPS from the Graph reads. Users is every user read (null when the read
    # failed), Groups every group read (null when that read failed), and Members the user members of each Atmosera
    # group by group ID, read transitively, so a member of a group nested in it is listed too (null for a group whose
    # members could not be read). Only the Atmosera groups are kept, and an account is kept when its UPN matches or it
    # sits in one of them.
    param($Users, $Groups, [hashtable]$Members = @{})
    $accounts = [ordered]@{}
    $add = {
        param($u)
        $id = (Get-CyberSocEaText (Get-CyberSocEaProp $u 'id')).ToLowerInvariant()
        if (-not $id) { return $null }
        if (-not $accounts.Contains($id)) {
            $accounts[$id] = [pscustomobject]@{
                PrincipalId = $id; UserPrincipalName = Get-CyberSocEaText (Get-CyberSocEaProp $u 'userPrincipalName'); DisplayName = Get-CyberSocEaText (Get-CyberSocEaProp $u 'displayName')
                UserType = Get-CyberSocEaText (Get-CyberSocEaProp $u 'userType'); AccountEnabled = $(if ($null -eq (Get-CyberSocEaProp $u 'accountEnabled')) { '' } else { Test-CyberSocEaTrue (Get-CyberSocEaProp $u 'accountEnabled') })
                MatchedBy = ''; ByUpn = $false; Groups = @(); GroupIds = @()
            }
        }
        $accounts[$id]
    }
    foreach ($u in @($Users | Where-Object { $null -ne $_ })) {
        if (Test-CyberSocEmergencyAccessUpn (Get-CyberSocEaProp $u 'userPrincipalName')) { $a = & $add $u; if ($a) { $a.ByUpn = $true } }
    }
    $groupRows = [System.Collections.Generic.List[object]]::new()
    $atmoseraGroups = @($Groups | Where-Object { $null -ne $_ -and (Test-CyberSocEmergencyAccessGroup (Get-CyberSocEaProp $_ 'displayName')) } | Sort-Object { Get-CyberSocEaText (Get-CyberSocEaProp $_ 'displayName') })
    foreach ($g in $atmoseraGroups) {
        $gid = (Get-CyberSocEaText (Get-CyberSocEaProp $g 'id')).ToLowerInvariant()
        $name = Get-CyberSocEaText (Get-CyberSocEaProp $g 'displayName')
        $read = $Members.ContainsKey($gid) -and $null -ne $Members[$gid]
        $users = @(if ($read) { @($Members[$gid]) | Where-Object { $null -ne $_ } })
        foreach ($u in $users) {
            $a = & $add $u
            if ($a -and $gid -notin $a.GroupIds) { $a.GroupIds += $gid; $a.Groups += $name }
        }
        $groupRows.Add([pscustomobject]@{
                GroupId = $gid; DisplayName = $name; Membership = Get-CyberSocEaMembership $g; MembersRead = $read
                Members = $(if ($read) { @($users | ForEach-Object { (Get-CyberSocEaText (Get-CyberSocEaProp $_ 'id')).ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique).Count } else { '' })
                MembershipRule = Get-CyberSocEaText (Get-CyberSocEaProp $g 'membershipRule')
            })
    }
    foreach ($a in $accounts.Values) {
        $a.MatchedBy = if ($a.ByUpn -and $a.GroupIds.Count) { 'UPN and group' } elseif ($a.ByUpn) { 'UPN' } else { 'Group' }
    }
    @{
        Accounts = @($accounts.Values | Sort-Object UserPrincipalName, PrincipalId | Select-Object PrincipalId, UserPrincipalName, DisplayName, UserType, AccountEnabled, MatchedBy, Groups, GroupIds)
        Groups = @($groupRows)
    }
}

function Get-CyberSocEmergencyAccess {
    # The emergency access set every Conditional Access change uses, from IA.16-ACCOUNTS and IA.16-GROUPS in the pack,
    # read through the Read script block the caller passes (it returns @{ Status; Rows; Unreadable } for a result ID,
    # Status MISSING when the pack does not hold it).
    #   Ready          true only when both reads are complete and found at least one account. A read that failed, is
    #                  partial, is unreadable or is missing, or a tenant with no Atmosera account, is never ready.
    #   Why            why it is not ready, for the index and the state of a gated change request.
    #   Complete       true when both reads are complete (OK or EMPTY, and readable), also when they found no account, so a
    #                  change that only leaves the accounts out, such as CR-19, can trust that nothing was missed.
    #   Accounts       every emergency access account, with how it matched (UPN, Group, or UPN and group).
    #   Groups         every Atmosera group, with its members and membership type.
    #   ExcludeGroups  the group IDs a policy excludes, so a new member is covered without a change.
    #   ExcludeUsers   the account IDs a policy excludes on their own: every account matched by its UPN, also when it sits in
    #                  an Atmosera group, so it stays excluded if it is later taken out of the group.
    #   Review         the Atmosera groups whose membership is dynamic or synced from on-premises.
    param([Parameter(Mandatory)][scriptblock]$Read)
    $acc = & $Read 'IA.16-ACCOUNTS'
    $grp = & $Read 'IA.16-GROUPS'
    $accounts = @(if ($acc.Status -in 'OK', 'PARTIAL' -and -not $acc.Unreadable) { @($acc.Rows) | Where-Object { $null -ne $_ } })
    $groups = @(if ($grp.Status -in 'OK', 'PARTIAL' -and -not $grp.Unreadable) { @($grp.Rows) | Where-Object { $null -ne $_ } })
    $why = ''
    $complete = $false
    if ($acc.Status -eq 'MISSING' -or $grp.Status -eq 'MISSING') { $why = 'Missing' }
    else {
        $bad = @(foreach ($p in @(@{ Id = 'IA.16-ACCOUNTS'; R = $acc }, @{ Id = 'IA.16-GROUPS'; R = $grp })) {
                if ($p.R.Unreadable) { '{0} unreadable' -f $p.Id }
                elseif ($p.R.Status -notin 'OK', 'EMPTY') { '{0} {1}' -f $p.Id, $p.R.Status }
            })
        $complete = -not $bad.Count
        if ($bad.Count) { $why = 'the emergency access read is not complete ({0})' -f ($bad -join ', ') }
        elseif (-not $accounts.Count) { $why = 'the emergency access read found no account with Atmosera in its UPN or in an Atmosera group' }
    }
    $lower = { param($v) (Get-CyberSocEaText $v).ToLowerInvariant() }
    $groupIds = @($groups | ForEach-Object { & $lower $_.GroupId } | Where-Object { $_ } | Sort-Object -Unique)
    [pscustomobject]@{
        Ready = -not $why
        Why = $why
        Complete = $complete
        Accounts = $accounts
        Groups = $groups
        ExcludeGroups = $groupIds
        ExcludeUsers = @($accounts | Where-Object { (Get-CyberSocEaText $_.MatchedBy) -in 'UPN', 'UPN and group' } | ForEach-Object { & $lower $_.PrincipalId } | Where-Object { $_ } | Sort-Object -Unique)
        Review = @($groups | Where-Object { (Get-CyberSocEaText $_.Membership) -in 'Dynamic', 'On-premises' })
        Protected = @(@($groupIds) + @($accounts | ForEach-Object { & $lower $_.PrincipalId }) | Where-Object { $_ } | Sort-Object -Unique)
    }
}

# An existing exclusion a change must keep: an emergency access account or Atmosera group, by its object ID.
function Test-CyberSocEmergencyAccessId($Access, [string]$Id) { [bool]$Id -and ($Id.Trim().ToLowerInvariant() -in @($Access.Protected)) }

