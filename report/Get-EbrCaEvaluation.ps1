<#
    Conditional Access evaluation shared by New-EbrSecurityReport.ps1 and New-EbrSecOpsWorklist.ps1.
    Offline. Reads three collector results (1.10.0 and later):
      IA.8-POLICIES  the policies exactly as Graph returned them, with excluded user, group and role IDs
      IA.8-DEFAULTS  security defaults on or off
      IA.8-SIGNINS   successful device code and legacy sign-ins per account, with policyId=result pairs
    For each Conditional Access control it decides whether a policy enforces it, and splits the
    successful sign-ins that should have been blocked into accounts the policy excludes by design
    and accounts it did not govern. Only the ungoverned accounts are a gap.
#>

function Get-EbrCaList {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return @() }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p -or $null -eq $p.Value) { return @() }
    @(@($p.Value) | ForEach-Object { [string]$_ } | Where-Object { $_ -and $_ -ne 'None' })
}

function Get-EbrCaValue {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { $null } else { $p.Value }
}

function Get-EbrCaPolicyFacts {
    # The properties of one policy that the evaluation needs, in plain booleans and lists.
    param($Policy)
    $c = Get-EbrCaValue $Policy 'conditions'
    $u = Get-EbrCaValue $c 'users'
    $a = Get-EbrCaValue $c 'applications'
    $g = Get-EbrCaValue $Policy 'grantControls'
    $platforms = Get-EbrCaList (Get-EbrCaValue $c 'platforms') 'includePlatforms'
    $locations = Get-EbrCaValue $c 'locations'
    $includeLocations = Get-EbrCaList $locations 'includeLocations'
    $excludeLocations = Get-EbrCaList $locations 'excludeLocations'
    $deviceFilter = Get-EbrCaValue (Get-EbrCaValue $c 'devices') 'deviceFilter'
    # A location condition names countries or networks, or carves trusted networks out of All.
    $byLocation = (@($includeLocations | Where-Object { $_ -ne 'All' }).Count -gt 0) -or ($excludeLocations.Count -gt 0)
    # A policy narrowed by platform, risk or device filter does not apply everywhere. Location is kept
    # apart because the location control is built on it. For every other flow it narrows too.
    $narrowedOther = (@($platforms | Where-Object { $_ -ne 'all' }).Count -gt 0) -or
                ((Get-EbrCaList $c 'signInRiskLevels').Count -gt 0) -or ((Get-EbrCaList $c 'userRiskLevels').Count -gt 0) -or
                ((Get-EbrCaList $c 'insiderRiskLevels').Count -gt 0) -or ($null -ne $deviceFilter)
    $narrowed = $narrowedOther -or $byLocation
    $grants = Get-EbrCaList $g 'builtInControls'
    $clientApps = Get-EbrCaList $c 'clientAppTypes'
    $includeApps = Get-EbrCaList $a 'includeApplications'
    [pscustomobject]@{
        Id            = [string](Get-EbrCaValue $Policy 'id')
        Name          = [string](Get-EbrCaValue $Policy 'displayName')
        State         = [string](Get-EbrCaValue $Policy 'state')
        AllUsers      = (Get-EbrCaList $u 'includeUsers') -contains 'All'
        Roles         = (Get-EbrCaList $u 'includeRoles').Count -gt 0
        AllApps       = $includeApps -contains 'All'
        AdminPortals  = $includeApps -contains 'MicrosoftAdminPortals'
        Block         = $grants -contains 'block'
        Mfa           = ($grants -contains 'mfa') -or ($null -ne (Get-EbrCaValue $g 'authenticationStrength'))
        DeviceCode    = [string](Get-EbrCaValue (Get-EbrCaValue $c 'authenticationFlows') 'transferMethods') -match 'deviceCodeFlow'
        Legacy        = @($clientApps | Where-Object { $_ -in 'exchangeActiveSync', 'other' }).Count -gt 0
        LegacyOnly    = $clientApps.Count -gt 0 -and @($clientApps | Where-Object { $_ -notin 'exchangeActiveSync', 'other' }).Count -eq 0
        Narrowed      = $narrowed
        NarrowedOther = $narrowedOther
        ByLocation    = $byLocation
        ExcludeUsers  = @(Get-EbrCaList $u 'excludeUsers')
        ExcludeGroups = @(Get-EbrCaList $u 'excludeGroups')
        ExcludeRoles  = @(Get-EbrCaList $u 'excludeRoles')
    }
}

function ConvertFrom-EbrCaFlatPolicy {
    # Packs from collectors 1.7.0 to 1.9.0 carry only the flattened IA.8 inventory: the policy state,
    # grants, flows and client apps, with users and exclusions reduced to counts ("12 users"). That is
    # enough to tell whether a policy enforces a control, not which accounts it excludes. Locations
    # were not recorded, so a location-narrowed policy reads as covering everyone.
    param($Row)
    $split = { param($v) @(([string]$v) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    $grants = & $split $Row.Grants
    $clientApps = & $split $Row.ClientAppTypes
    $excludeCount = 0
    foreach ($m in [regex]::Matches([string]$Row.ExcludeUsers, '(\d+)')) { $excludeCount += [int]$m.Groups[1].Value }
    $name = [string]$Row.Policy
    [pscustomobject]@{
        Id            = ''
        Name          = $name
        State         = [string]$Row.State
        AllUsers      = [string]$Row.IncludeUsers -eq 'All'
        Roles         = [string]$Row.IncludeUsers -match '\broles?\b'
        AllApps       = [string]$Row.IncludeApplications -eq 'All'
        AdminPortals  = [string]$Row.IncludeApplications -match 'Microsoft Admin Portals'
        Block         = $grants -contains 'block'
        Mfa           = ($grants -contains 'mfa') -or [bool]([string]$Row.AuthStrength)
        DeviceCode    = [string]$Row.AuthenticationFlows -match 'deviceCodeFlow'
        Legacy        = @($clientApps | Where-Object { $_ -in 'exchangeActiveSync', 'other' }).Count -gt 0
        LegacyOnly    = $clientApps.Count -gt 0 -and @($clientApps | Where-Object { $_ -notin 'exchangeActiveSync', 'other' }).Count -eq 0
        Narrowed      = (@(& $split $Row.Platforms | Where-Object { $_ -ne 'all' }).Count -gt 0) -or [bool]([string]$Row.SignInRiskLevels) -or [bool]([string]$Row.UserRiskLevels)
        NarrowedOther = (@(& $split $Row.Platforms | Where-Object { $_ -ne 'all' }).Count -gt 0) -or [bool]([string]$Row.SignInRiskLevels) -or [bool]([string]$Row.UserRiskLevels)
        ByLocation    = $false
        ExcludeUsers  = @(for ($i = 1; $i -le $excludeCount; $i++) { "$name#$i" })
        ExcludeGroups = @()
        ExcludeRoles  = @()
    }
}

function Get-EbrCaFlowDefinitions {
    # Which policies serve each control, and when one covers the whole tenant.
    @(
        @{ Flow = 'Device code'; Control = 'IA.3-DEVICECODE'; SignIns = $true
           Match = { param($f) $f.Block -and $f.DeviceCode }
           Covers = { param($f) $f.AllUsers -and $f.AllApps -and -not $f.Narrowed } }
        @{ Flow = 'Legacy authentication'; Control = 'IA.3'; SignIns = $true; Defaults = $true
           Match = { param($f) $f.Block -and $f.Legacy }
           Covers = { param($f) $f.AllUsers -and $f.AllApps -and -not $f.Narrowed } }
        # Admin portals: MFA required on the admin portals, or on all apps, for all users or for the admin roles.
        @{ Flow = 'Admin portals'; Control = 'IA.1-ADMINPORTAL'; SignIns = $false; Defaults = $true
           Match = { param($f) $f.Mfa -and ($f.AllApps -or $f.AdminPortals) -and -not $f.LegacyOnly }
           Covers = { param($f) ($f.AllUsers -or $f.Roles) -and -not $f.Narrowed } }
        # Location: a country or named network condition that blocks access or requires MFA, for all users
        # and all resources. Only the raw policies record locations, so the flattened inventory reads Unknown.
        @{ Flow = 'Location'; Control = 'IA.4-LOCATION'; SignIns = $false; RawOnly = $true
           Match = { param($f) $f.ByLocation -and ($f.Block -or $f.Mfa) }
           Covers = { param($f) $f.AllUsers -and $f.AllApps -and -not $f.NarrowedOther } }
    )
}

function Get-EbrCaEvaluation {
    <#
    .SYNOPSIS
        Evaluates the Conditional Access controls from the raw policies and the sign-in detail.
    .PARAMETER Policies
        IA.8-POLICIES rows. $null when the pack has no policy inventory (Graph unavailable or a
        collector before 1.10.0). An empty array means the tenant has no policies.
    .PARAMETER SecurityDefaults
        $true, $false or $null when unknown.
    .PARAMETER SignIns
        IA.8-SIGNINS rows. $null when the pack has no sign-in detail.
    .OUTPUTS
        Flows: one row per control with counts only, safe to embed in the client report.
        SignIns: one row per account and flow with its classification, for the SecOps worklist.
    #>
    param($Policies, $SecurityDefaults, $SignIns, $FlatPolicies)
    # Raw policies win. The flattened inventory is the fallback for packs before collector 1.10.0.
    $policyRead = $null -ne $Policies -or $null -ne $FlatPolicies
    $detailRead = $null -ne $SignIns
    $facts = if ($null -ne $Policies) { @(foreach ($p in @($Policies)) { if ($null -ne $p) { Get-EbrCaPolicyFacts $p } }) }
    else { @(foreach ($r in @($FlatPolicies)) { if ($null -ne $r) { ConvertFrom-EbrCaFlatPolicy $r } }) }
    # Security defaults and enabled Conditional Access policies exclude each other. With no enabled policy
    # and the defaults state unread, legacy authentication and admin MFA may still be enforced by the
    # defaults, so those controls read Unknown rather than None.
    $anyEnabled = @($facts | Where-Object State -eq 'enabled').Count -gt 0
    $flows = [System.Collections.Generic.List[object]]::new()
    $classified = [System.Collections.Generic.List[object]]::new()
    foreach ($d in Get-EbrCaFlowDefinitions) {
        $matching = @($facts | Where-Object { & $d.Match $_ })
        $enabled = @($matching | Where-Object State -eq 'enabled')
        $covering = @($enabled | Where-Object { & $d.Covers $_ })
        $state = if (-not $policyRead -or ($d.RawOnly -and $null -eq $Policies)) { 'Unknown' }
        elseif ($d.Defaults -and $SecurityDefaults -eq $true) { 'Security defaults' }
        elseif ($d.Defaults -and $null -eq $SecurityDefaults -and -not $anyEnabled) { 'Unknown' }
        elseif ($covering.Count) { 'Enforced' }
        elseif ($enabled.Count) { 'Scoped' }
        elseif (@($matching | Where-Object State -eq 'enabledForReportingButNotEnforced').Count) { 'Report-only' }
        else { 'None' }
        $excluded = @($covering | ForEach-Object { $_.ExcludeUsers + $_.ExcludeGroups + $_.ExcludeRoles } | Sort-Object -Unique)
        $rows = @()
        if ($d.SignIns -and $detailRead) {
            $rows = @(foreach ($s in @($SignIns | Where-Object { $null -ne $_ -and [string]$_.Flow -eq $d.Flow })) {
                    $results = @{}
                    foreach ($pair in ([string]$s.PolicyResults -split ',')) {
                        $kv = $pair -split '=', 2
                        if ($kv.Count -eq 2 -and $kv[0]) { $results[$kv[0].Trim().ToLowerInvariant()] = $kv[1].Trim() }
                    }
                    # Excluded: the account is named in an exclusion, or a policy that targets all users
                    # was evaluated and did not apply (a user, group, role or application exclusion).
                    # Not evaluated: the enabled policy is absent from the record, usually a sign-in made
                    # before the policy existed. Not governed: no enabled block policy applies at all.
                    $class = 'Not governed'; $by = ''
                    foreach ($p in $enabled) {
                        $r = $results[$p.Id.ToLowerInvariant()]
                        if ($p.ExcludeUsers -contains [string]$s.UserId -or ($r -eq 'notApplied' -and $p.AllUsers)) { $class = 'Excluded'; $by = $p.Name; break }
                        if (-not $r -and $class -eq 'Not governed') { $class = 'Not evaluated'; $by = $p.Name }
                    }
                    [pscustomobject]@{
                        Flow = $d.Flow; Control = $d.Control; UserPrincipalName = [string]$s.UserPrincipalName; UserId = [string]$s.UserId
                        UserType = [string]$s.UserType; ClientAppUsed = [string]$s.ClientAppUsed; SignIns = [int]$s.SignIns
                        LastSignIn = [string]$s.LastSignIn; Apps = [string]$s.Apps; Classification = $class; Policy = $by
                    }
                })
            foreach ($r in $rows) { $classified.Add($r) }
        }
        $ex = @($rows | Where-Object Classification -eq 'Excluded')
        $un = @($rows | Where-Object Classification -ne 'Excluded')
        $sumOf = { param($set) [int](@($set | ForEach-Object { $_.SignIns }) | Measure-Object -Sum).Sum }
        $flows.Add([pscustomobject]@{
                Flow                = $d.Flow
                Control             = $d.Control
                PolicyRead          = $policyRead
                PolicySource        = $(if ($null -ne $Policies) { 'Raw' } elseif ($null -ne $FlatPolicies) { 'Flattened' } else { '' })
                PolicyState         = $state
                EnforcedPolicies    = $covering.Count
                ExcludedIdentities  = $excluded.Count
                DetailRead          = [bool]($d.SignIns -and $detailRead)
                SignIns             = & $sumOf $rows
                SucceededExcluded   = & $sumOf $ex
                AccountsExcluded    = @($ex | ForEach-Object { $_.UserId } | Sort-Object -Unique).Count
                SucceededUngoverned = & $sumOf $un
                AccountsUngoverned  = @($un | ForEach-Object { $_.UserId } | Sort-Object -Unique).Count
            })
    }
    [pscustomobject]@{ Flows = $flows.ToArray(); SignIns = $classified.ToArray() }
}

function Read-EbrCaEvaluation {
    # Reads the three results from a pack and evaluates them. Returns $null when the pack carries
    # neither a policy inventory nor sign-in detail, so callers fall back to the summary results.
    param([string]$Pack, $Manifest, [scriptblock]$Filter = { $true })
    $status = { param($id) $r = @($Manifest | Where-Object ResultId -eq $id | Select-Object -First 1); if ($r.Count) { [string]$r[0].Status } else { 'MISSING' } }
    $load = {
        param($id)
        if ((& $status $id) -notin 'OK', 'EMPTY') { return $null }
        $file = Join-Path $Pack "results/$id.json"
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { return $null }
        , @(Get-Content -LiteralPath $file -Raw | ConvertFrom-Json | Where-Object { $null -ne $_ -and (& $Filter $_) })
    }
    $policies = & $load 'IA.8-POLICIES'
    $flat = if ($null -eq $policies) { & $load 'IA.8' } else { $null }
    $signIns = & $load 'IA.8-SIGNINS'
    if ($null -eq $policies -and $null -eq $flat -and $null -eq $signIns) { return $null }
    $defaults = & $load 'IA.8-DEFAULTS'
    $sd = if ($null -ne $defaults -and @($defaults).Count) { [string]$defaults[0].SecurityDefaults -eq 'True' } else { $null }
    Get-EbrCaEvaluation -Policies $policies -SecurityDefaults $sd -SignIns $signIns -FlatPolicies $flat
}
