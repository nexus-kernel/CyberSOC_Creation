# Pester 5 tests for Get-CyberSocEvidence.ps1
# Run: Invoke-Pester ./tests/Get-CyberSocEvidence.Tests.ps1 -Output Detailed
# These cover the pure logic only. Nothing here signs in or calls Azure.

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'Get-CyberSocEvidence.ps1') -LoadFunctionsOnly
}

Describe 'Query catalog' {
    BeforeAll { $catalog = Get-EbrQueryCatalog }

    It 'has unique IDs' {
        $dupes = $catalog | Group-Object Id | Where-Object Count -gt 1
        $dupes | Should -BeNullOrEmpty
    }

    It 'contains every runbook query ID' {
        $expected = @(
            'P0.1', 'P0.2', 'P0.3', 'P0.4', 'P0.5',
            'OUT.1', 'OUT.2', 'OUT.3', 'OUT.4', 'OUT.5', 'OUT.6', 'OUT.7', 'OUT.8',
            'DFC.1',
            'IA.1', 'IA.1-ADMINPORTAL', 'IA.2', 'IA.3', 'IA.3-DEVICECODE', 'IA.4', 'IA.4b', 'IA.5', 'IA.6', 'IA.7', 'IA.8', 'IA.9', 'IA.11', 'IA.13', 'IA.14',
            'EW.1', 'EW.3', 'EW.4', 'EW.5', 'EW.6', 'EW.7', 'EW.8', 'EW.9', 'EW.10', 'EW.12', 'EW.13', 'EW.14', 'EW.15', 'EW.16',
            'NB.1', 'NB.2', 'NB.3', 'NB.4', 'NB.5', 'NB.6', 'NB.7', 'NB.8', 'NB.10', 'NB.11',
            'DP.1', 'DP.2', 'DP.3', 'DP.4', 'DP.5', 'DP.5b', 'DP.5c', 'DP.6', 'DP.7', 'DP.7-ZAP', 'DP.8', 'DP.10',
            'DR.1', 'DR.2', 'DR.3', 'DR.4', 'DR.5', 'DR.6', 'DR.6-INITIATIVE', 'DR.7', 'DR.8', 'DR.9', 'DR.10', 'DR.11', 'DR.12', 'DR.13',
            'POS.1', 'POS.2', 'POS.3', 'POS.4', 'POS.5', 'POS.6', 'POS.7', 'POS.8',
            'BKL.1', 'BKL.2'
        )
        $missing = $expected | Where-Object { $_ -notin $catalog.Id }
        $missing | Should -BeNullOrEmpty
    }

    It 'adds the CyberSOC trend, threat intelligence and vulnerability exposure queries' {
        foreach ($id in 'OUT.2-MONTH', 'OUT.3-WEEK', 'OUT.9', 'TI.0', 'TI.1', 'TI.2', 'TI.3', 'TI.4', 'TI.5', 'TI.5-RISK', 'TI.6', 'TI.7', 'VA.1', 'VA.2', 'VA.3') { $catalog.Id | Should -Contain $id }
        $out2 = ($catalog | Where-Object Id -eq 'OUT.2').Query
        $month = ($catalog | Where-Object Id -eq 'OUT.2-MONTH').Query
        $month.StartsWith($out2.Substring(0, $out2.IndexOf('          by Scope'))) | Should -BeTrue -Because 'OUT.2-MONTH is the OUT.2 cohort split by month'
        $month | Should -Match 'by Month = startofmonth\(CreatedTime\), Scope\r?\n\| order by Month asc, Scope asc$'
        ($catalog | Where-Object Id -eq 'OUT.3-WEEK').Query | Should -Match 'by Week = bin_at\(CreatedTime, 7d, \{\{WINDOW_START\}\}\)'
        foreach ($id in 'OUT.2-MONTH', 'OUT.3-WEEK', 'OUT.9', 'TI.2', 'TI.3', 'TI.4') {
            $q = ($catalog | Where-Object Id -eq $id).Query
            $q | Should -Match '\{\{TICKET\}\}' -Because $id
            $q | Should -Match 'Severity != "Informational"' -Because $id
            $q | Should -Match 'by TenantId, IncidentNumber' -Because $id
        }
        foreach ($id in 'TI.3', 'TI.4') { ($catalog | Where-Object Id -eq $id).Query | Should -Match 'join kind=inner \(Ticketed\)' -Because 'stages and techniques read only the detections in ticketed alerts' }
        ($catalog | Where-Object Id -eq 'TI.2').Query | Should -Match 'join kind=leftouter \(Ticketed \| distinct AlertId'
        ($catalog | Where-Object Id -eq 'TI.0').AlwaysBreakdown | Should -BeTrue -Because 'the EmailEvents workspace is chosen from TI.0-BY-WORKSPACE'
        ($catalog | Where-Object Id -eq 'TI.1').Query | Should -Match 'ThreatIntelIndicators, ThreatIntelligenceIndicator'
        ($catalog | Where-Object Id -eq 'TI.5').Query | Should -Match 'Targets >= 10'
        ($catalog | Where-Object Id -eq 'TI.5').Query | Should -Not -Match 'project .*UserPrincipalName' -Because 'only counts leave the query'
        ($catalog | Where-Object Id -eq 'TI.7').Query | Should -Match 'Timestamp between \(ago\(30d\) \.\. now\(\)\)'
        foreach ($id in 'TI.7', 'VA.1', 'VA.2', 'VA.3') {
            $item = $catalog | Where-Object Id -eq $id
            $item.Engine | Should -Be 'AH' -Because $id
            $item.Query | Should -Match 'where isnotempty\(AzureResourceId\)' -Because 'every device measure reads Azure virtual machines only'
            $item.Query | Should -Match 'AzureResourceId !contains "\{\{MRG\}\}"' -Because $id
        }
        @($catalog | Where-Object { $_.Id -match '^(TI|VA)\.' } | Where-Object { $_.Phase -notlike 'P5*' }) | Should -BeNullOrEmpty
    }

    It 'includes the substitutes and runbook variants' {
        foreach ($id in 'IA.6-SUB', 'IA.8-SUB', 'POS.6-SUB', 'IA.2-METHOD', 'OUT.2-ANALYST',
                        'DFC.1-DETAIL', 'EW.7-DETAIL', 'DP.4-DETAIL',
                        'OUT.1-OPEN', 'DR.10-GAPS', 'EW.1-DEVICES', 'DP.5-STALE', 'IA.8-SIGNINS', 'P0.6-APPLIANCES') {
            $catalog.Id | Should -Contain $id
        }
    }

    It 'scopes the SecOps worklist incident lists like OUT.1 and DR.10 and extracts the ticket with the raw pattern' {
        foreach ($id in 'OUT.1-OPEN', 'DR.10-GAPS') {
            $item = $catalog | Where-Object Id -eq $id
            $item.CombinedOnly | Should -BeTrue -Because $id
            $item.Query | Should -Match '\{\{TICKET\}\}' -Because $id
            $item.Query | Should -Match 'Severity != "Informational"' -Because $id
            $item.Query | Should -Match 'by TenantId, IncidentNumber' -Because $id
            $item.Query | Should -Match 'extract\(@"\{\{TICKET_PATTERN\}\}", 0, tostring\(Comments\)\)' -Because $id
        }
        ($catalog | Where-Object Id -eq 'OUT.1-OPEN').Query | Should -Match 'Status != "Closed"'
        ($catalog | Where-Object Id -eq 'DR.10-GAPS').Query | Should -Match 'isempty\(Classification\) or Classification == "Undetermined" or isempty\(ClassificationComment\)'
        $out = Expand-EbrQuery -Query 'extract(@"{{TICKET_PATTERN}}", 0, x)' -WindowStart ([datetime]'2026-07-01') -WindowEnd ([datetime]'2026-09-30') -ManagedRgPattern 'x' -TicketPattern 'SNOW-\d+'
        $out | Should -Be 'extract(@"SNOW-\d+", 0, x)'
        ($catalog | Where-Object Id -eq 'EW.1-DEVICES').Query | Should -Match 'where isnotempty\(AzureResourceId\)'
        ($catalog | Where-Object Id -eq 'EW.1-DEVICES').Query | Should -Match 'OnboardingStatus != "Onboarded" or SensorHealthState != "Active"'
        ($catalog | Where-Object Id -eq 'DP.5-STALE').Query | Should -Match 'LastBackup < ago\(2d\) or ProtectionState != "Protected"'
    }

    It 'scopes DR.10 to ticketed, non-informational incidents closed in the last 30 days' {
        $q = ($catalog | Where-Object Id -eq 'DR.10').Query
        $q | Should -Match '\{\{TICKET\}\}'
        $q | Should -Match 'Severity != "Informational"'
        $q | Should -Match 'ClosedTime between \(ago\(30d\)'
        $q | Should -Match 'arg_max\(TimeGenerated, \*\) by TenantId, IncidentNumber'
    }

    It 'builds every per-device check measure from the shared shape with its own check IDs' {
        $expected = @{ 'EW.12' = 'scid-25", "scid-102", "scid-57'; 'EW.14' = 'scid-24", "scid-45'; 'EW.15' = 'scid-2003'; 'EW.16' = 'scid-2070'; 'NB.8' = 'scid-96'; 'NB.10' = 'scid-105", "scid-106'; 'NB.11' = 'scid-72' }
        foreach ($id in $expected.Keys) {
            $item = $catalog | Where-Object Id -eq $id
            $item.Engine | Should -Be 'AH'
            $item.Query | Should -Match ('ConfigurationId in \("' + [regex]::Escape($expected[$id]) + '"\)')
            $item.Query | Should -Match 'countif\(Passed == Checks\)'
            $item.Query | Should -Match 'OnboardingStatus == "Onboarded"'
        }
    }

    It 'expands the patch cadence token in EW.10 from the parameter' {
        $q = ($catalog | Where-Object Id -eq 'EW.10').Query
        $q | Should -Match '\{\{PATCH_DAYS\}\}'
        $text = Expand-EbrQuery -Query $q -WindowStart ([datetime]'2026-01-01') -WindowEnd ([datetime]'2026-06-30') -ManagedRgPattern 'aznativesol0' -PatchCadenceDays 45
        $text | Should -Match 'PublishedUtc < ago\(45d\)'
        $text | Should -Not -Match '\{\{'
        (Expand-EbrQuery -Query $q -WindowStart ([datetime]'2026-01-01') -WindowEnd ([datetime]'2026-06-30') -ManagedRgPattern 'x') | Should -Match 'ago\(30d\)'
    }

    It 'reads IA.1-ADMINPORTAL against the four Microsoft Admin Portals app IDs' {
        $q = ($catalog | Where-Object Id -eq 'IA.1-ADMINPORTAL').Query
        foreach ($app in '497effe9-df71-4043-a8bb-14cf78c4b63b', 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c', '00000006-0000-0ff1-ce00-000000000000', '80ccca67-54bd-44ab-8625-4b79c4dc7775') { $q | Should -Match $app }
        ($catalog | Where-Object Id -eq 'IA.3-DEVICECODE').Query | Should -Match 'AuthenticationProtocol =~ "deviceCode"'
        ($catalog | Where-Object Id -eq 'IA.14').Query | Should -Match '797f4846-ba00-4fd7-ba43-dac1f8f63013'
    }

    It 'uses only known engines' {
        $known = 'ARG', 'LA', 'AH', 'SENTINEL-RULES', 'STORAGE-CONTAINERS', 'DEFENDER-SCORES', 'EXO', 'IPPS', 'GRAPH', 'MANUAL', 'DERIVED'
        $catalog | Where-Object { $_.Engine -notin $known } | Should -BeNullOrEmpty
    }

    It 'has KQL for every query engine and a portal path for every MANUAL item' {
        $catalog | Where-Object { $_.Engine -in 'ARG', 'LA', 'AH' -and -not $_.Query } |
            Should -BeNullOrEmpty
        $catalog | Where-Object { $_.Engine -eq 'MANUAL' -and -not $_.Notes } |
            Should -BeNullOrEmpty
    }

    It 'routes every Graph item to GRAPH with its endpoints, its permission, a portal fallback and a collector' {
        foreach ($id in 'IA.1-FEDERATION', 'IA.5', 'IA.6', 'IA.8', 'IA.11', 'IA.13', 'POS.6', 'DP.8', 'DP.10', 'DR.11', 'EW.13') {
            $item = $catalog | Where-Object Id -eq $id
            $item.Engine | Should -Be 'GRAPH'
            $item.Query | Should -Match '(?m)^GET /(v1\.0|beta)/'
            $item.Query | Should -Match '(?m)^Permission: '
            $item.Notes | Should -Match '^Portal fallback: '
            (Get-EbrGraphSpec $id).Permission | Should -Not -BeNullOrEmpty
            $item.Query | Should -Match ([regex]::Escape((Get-EbrGraphSpec $id).Permission))
        }
        $catalog | Where-Object { $_.Engine -eq 'GRAPH' -and -not (Get-EbrGraphSpec $_.Id) } | Should -BeNullOrEmpty
    }

    It 'scopes every outcome query to ticketed, non-informational incidents' {
        foreach ($id in 'OUT.1', 'OUT.2', 'OUT.2-ANALYST', 'OUT.2-RECENT', 'OUT.2-RECENT-ANALYST', 'OUT.3', 'OUT.4', 'OUT.7') {
            $q = ($catalog | Where-Object Id -eq $id).Query
            $q | Should -Match '\{\{TICKET\}\}' -Because $id
            $q | Should -Match 'Severity != "Informational"' -Because $id
        }
        foreach ($id in 'OUT.5', 'OUT.6') {
            $q = ($catalog | Where-Object Id -eq $id).Query
            $q | Should -Match 'TicketedAlertIds' -Because $id
            $q | Should -Match '\{\{TICKET\}\}' -Because $id
        }
        ($catalog | Where-Object Id -eq 'OUT.5').Query | Should -Match 'AlertSeverity != "Informational"'
        ($catalog | Where-Object Id -eq 'DR.1').Query | Should -Not -Match '\{\{TICKET\}\}'
        $out = Expand-EbrQuery -Query '| where {{TICKET}}' -WindowStart ([datetime]'2026-07-01') -WindowEnd ([datetime]'2026-09-30') -ManagedRgPattern 'x'
        $out | Should -Match 'tostring\(Comments\) matches regex @"\(\?i\)\(\(\[a-z0-9-\]\+\\\.\)\?zendesk'
        $out | Should -Match 'tostring\(ClassificationComment\) matches regex'
        $custom = Expand-EbrQuery -Query '{{TICKET}}' -WindowStart ([datetime]'2026-07-01') -WindowEnd ([datetime]'2026-09-30') -ManagedRgPattern 'x' -TicketPattern 'SNOW-\d+'
        $custom | Should -Match 'matches regex @"SNOW-\\d\+"'
        { Expand-EbrQuery -Query 'x' -WindowStart ([datetime]'2026-07-01') -WindowEnd ([datetime]'2026-09-30') -ManagedRgPattern 'x' -TicketPattern 'a"b' } | Should -Throw '*double quotes*'
    }
    It 'classifies IA.1 and IA.1-ADMINPORTAL sign-ins by MFA evidence, federation aware' {
        foreach ($id in 'IA.1', 'IA.1-ADMINPORTAL') {
            $q = ($catalog | Where-Object Id -eq $id).Query
            # Step detail strings confirmed with Q1 in a federated (Okta) tenant on Oct 13, 2026
            $q | Should -Match 'AuthText has "claim provided by external provider"' -Because $id
            $q | Should -Match 'AuthText has "MFA requirement satisfied by claim in the token"' -Because $id
            $q | Should -Match 'AuthText has "Previously satisfied"' -Because $id
            $q | Should -Match 'IncomingTokenType has_any \("saml11", "saml20"\)' -Because $id
            $q | Should -Match 'MfaDetail\.authMethod' -Because $id
            $q | Should -Match '"Session reuse, MFA not evaluated"' -Because $id
            $q | Should -Match 'NoMfaOnlyUnevaluated' -Because $id
            # Only the plain Require MFA grant proves a reused session either way. No tenant-specific policy names.
            $q | Should -Match 'tostring\(Policy\.enforcedGrantControls\[0\]\) == "Mfa"' -Because $id
            $q | Should -Match 'Result == "reportOnlyInterrupted" and MfaOnly' -Because $id
            $q | Should -Not -Match 'Phishing-resistant MFA|Policy\.displayName' -Because $id
            $q | Should -Match '"Partner \(GDAP\)"' -Because $id
            $q | Should -Not -Match '(?m)isnotempty\(UserId\)\| project' -Because 'the shared block starts on its own line'
            # Session pre-pass (1.13.0): a let ahead of the SigninLogs head, 90 days, all apps, no policy results
            $q | Should -Match '^// Earliest direct MFA in each session' -Because $id
            $pre = $q.Substring(0, $q.IndexOf('| where isnotnull(FirstMfa);'))
            $pre | Should -Match 'let MfaSessions = SigninLogs\s+\| where TimeGenerated between \(ago\(90d\) \.\. now\(\)\)' -Because $id
            $pre | Should -Match 'SessionKey = tostring\(column_ifexists\("SessionId", ""\)\)' -Because $id
            $pre | Should -Match 'minif\(TimeGenerated, MfaEntraStep or MfaExternal or Passwordless or MfaRequired or MfaTokenClaim\) by SessionKey' -Because $id
            $pre | Should -Not -Match 'ConditionalAccessPolicies|ResourceIdentity' -Because "$id pre-pass reads every app and no policy results"
            $q | Should -Match '(?m)^SigninLogs\s+\| where TimeGenerated between \(ago\(30d\)' -Because $id
            $q | Should -Match '\| project TimeGenerated, SessionKey = tostring\(column_ifexists\("SessionId", ""\)\),' -Because $id
            $q | Should -Match '\| lookup kind=leftouter MfaSessions on SessionKey' -Because $id
            $q | Should -Match 'SessionReuse\s+= AuthText has "Previously satisfied" or IncomingTokenType has_any \("primaryRefreshToken", "refreshToken"\)' -Because $id
            # Rule order: report-only interrupted, then MFA earlier in the session, then session reuse
            $q.IndexOf('"Session without MFA (report-only policy would prompt)"') | Should -BeLessThan $q.IndexOf('FirstMfa <= TimeGenerated,') -Because $id
            $q.IndexOf('FirstMfa <= TimeGenerated,') | Should -BeLessThan $q.IndexOf('SessionReuse,                                     "Session reuse') -Because $id
            $q.IndexOf('Federated,                                        "Federated sign-in without') | Should -BeLessThan $q.IndexOf('FirstMfa <= TimeGenerated,') -Because $id
            $q | Should -Match '(?s)HasMfa = Evidence in \([^)]*"MFA earlier in the same session"\)' -Because $id
        }
        ($catalog | Where-Object Id -eq 'IA.1').Query | Should -Match 'MfaSessionLinkedOnly    = countif\(0 < MfaSignIns and SessionLinked == MfaSignIns\)'
        $ia1 = ($catalog | Where-Object Id -eq 'IA.1').Query
        # Windows logon is left out before the per-user summarize, so it never reaches the always-MFA denominator
        $ia1.IndexOf('| where not(DeviceLogon)') | Should -BeGreaterThan 0
        $ia1.IndexOf('| where not(DeviceLogon)') | Should -BeLessThan $ia1.IndexOf('by UserId, UserType')
        foreach ($col in 'UsersSignedIn', 'UsersChallenged', 'UsersAlwaysMfa', 'UsersExternalMfa', 'PctChallenged', 'PctAlwaysMfa',
                         'MfaAtLeastOnce', 'MfaEveryAppSignIn', 'CoveredEveryAppSignIn', 'FederatedMfaAtLeastOnce', 'FederatedWithoutMfa', 'NoMfaOnlyUnevaluated', 'MfaSessionLinkedOnly') {
            $ia1 | Should -Match ('(?m)^\| project .*\b{0}\b|^\s+.*\b{0}\b.*$' -f $col) -Because $col
        }
        $ia1 | Should -Match '(?s)\| project UserType, UsersSignedIn, UsersChallenged, UsersAlwaysMfa, UsersExternalMfa, UsersEntraMfa,\s+PctChallenged, PctAlwaysMfa, MfaAtLeastOnce, MfaEveryAppSignIn, CoveredEveryAppSignIn,\s+FederatedMfaAtLeastOnce, FederatedWithoutMfa, NoMfaOnlyUnevaluated, MfaSessionLinkedOnly'
        ($catalog | Where-Object Id -eq 'IA.1-ADMINPORTAL').Query | Should -Match 'Users\s+= count\(\),\s+UsersChallenged'
    }
    It 'builds the trailing three month OUT.2 variants from the recent start token' {
        $recent = ($catalog | Where-Object Id -eq 'OUT.2-RECENT').Query
        $recent | Should -Match '\{\{RECENT_START\}\}'
        $recent | Should -Not -Match '\{\{WINDOW_START\}\}'
        $recent | Should -Match '\{\{WINDOW_END\}\}'
        ($catalog | Where-Object Id -eq 'OUT.2-RECENT-ANALYST').Query | Should -Match 'where not\(IsAutoClosed\)'
        $expanded = Expand-EbrQuery -Query $recent -WindowStart ([datetime]'2025-11-01') -WindowEnd ([datetime]'2026-09-30') -ManagedRgPattern 'x'
        $expanded | Should -Match 'datetime\(2026-07-01\)'
        $expanded | Should -Not -Match '\{\{'
        (Get-EbrRecentStart -WindowStart ([datetime]'2026-07-01') -WindowEnd ([datetime]'2026-09-30')).ToString('yyyy-MM-dd') | Should -Be '2026-07-01'
        (Get-EbrRecentStart -WindowStart ([datetime]'2026-08-15') -WindowEnd ([datetime]'2026-09-30')).ToString('yyyy-MM-dd') | Should -Be '2026-08-15'
    }
    It 'builds OUT.2-ANALYST by dropping automation-closed incidents before the summarize' {
        $q = ($catalog | Where-Object Id -eq 'OUT.2-ANALYST').Query
        $q | Should -Match '\| where not\(IsAutoClosed\)'
        $q.IndexOf('where not(IsAutoClosed)') | Should -BeLessThan $q.IndexOf('| summarize Incidents')
        ($catalog | Where-Object Id -eq 'OUT.2').Query | Should -Not -Match 'where not\(IsAutoClosed\)'
    }

    It 'splits IA.2-METHOD by method while keeping the bucket' {
        ($catalog | Where-Object Id -eq 'IA.2-METHOD').Query | Should -Match 'by Bucket, Method'
    }

    It 'keeps the full DFC.1 keyword list in both the sweep and the detail query' {
        foreach ($id in 'DFC.1', 'DFC.1-DETAIL') {
            $q = ($catalog | Where-Object Id -eq $id).Query
            $q | Should -Match '"EDR", "endpoint protection"'
            $q | Should -Match '"MFA", "owner permissions", "Defender for", "threat protection"\)'
        }
    }

    It 'keys incidents by workspace so equal incident numbers in different workspaces stay apart' {
        foreach ($id in 'OUT.1', 'OUT.2', 'OUT.2-ANALYST', 'OUT.3', 'OUT.4', 'OUT.7') {
            $q = ($catalog | Where-Object Id -eq $id).Query
            $q | Should -Match 'by TenantId, IncidentNumber' -Because $id
            $q | Should -Not -Match '(?<!TenantId, )by IncidentNumber' -Because $id
        }
    }

    It 'keys the POS.7 score trend by subscription or workspace so combined months add up' {
        $q = ($catalog | Where-Object Id -eq 'POS.7').Query
        $q | Should -Match 'ScoreKey = coalesce\(tostring\(column_ifexists\("SecureScoresSubscriptionId", ""\)\)'
        $q | Should -Match 'TenantId\)'
    }

    It 'reads tenant-wide tables from one workspace only' {
        $tenant = $catalog | Where-Object TenantTable
        foreach ($id in 'IA.1', 'IA.1-ADMINPORTAL', 'IA.2', 'IA.2-METHOD', 'IA.3', 'IA.3-DEVICECODE', 'IA.4', 'IA.4b', 'IA.8-SUB', 'IA.8-SIGNINS', 'IA.14') {
            ($tenant | Where-Object Id -eq $id).TenantTable | Should -Be 'SigninLogs' -Because $id
        }
        ($tenant | Where-Object Id -eq 'OUT.8').TenantTable | Should -Be 'AuditLogs'
        # CyberSOC: identity threat activity, Entra ID Protection risk detections and email threats.
        ($tenant | Where-Object Id -eq 'TI.5').TenantTable | Should -Be 'SigninLogs'
        ($tenant | Where-Object Id -eq 'TI.5-RISK').TenantTable | Should -Be 'AADUserRiskEvents'
        ($tenant | Where-Object Id -eq 'TI.6').TenantTable | Should -Be 'EmailEvents'
        @($tenant).Count | Should -Be 15
    }

    It 'checks for Defender XDR incidents synced into more than one workspace' {
        $dup = $catalog | Where-Object Id -eq 'P0.1-XDRDUP'
        $dup.Engine | Should -Be 'LA'
        $dup.CombinedOnly | Should -BeTrue
        $dup.Query | Should -Match 'dcount\(TenantId\)'
    }

    It 'never filters the workspace inventory or subscription-level results by managed resource group' {
        foreach ($id in 'P0.2', 'P0.3', 'POS.1', 'POS.3', 'POS.5', 'POS.7') {
            ($catalog | Where-Object Id -eq $id).Query | Should -Not -Match '\{\{MRG\}\}'
        }
    }

    It 'excludes the managed resource group from every other ARG query' {
        $exempt = 'P0.2', 'P0.3', 'POS.1', 'POS.3', 'POS.5'
        $missing = @($catalog | Where-Object { $_.Engine -eq 'ARG' -and $_.Id -notin $exempt -and $_.Query -notmatch '\{\{MRG\}\}' } | ForEach-Object Id)
        $missing | Should -BeNullOrEmpty
    }

    It 'tests the described resource where the record is not the resource itself' {
        foreach ($id in 'DP.5', 'DP.5-STALE', 'DP.5b') {
            ($catalog | Where-Object Id -eq $id).Query | Should -Match 'tostring\(properties\.sourceResourceId\) !contains "\{\{MRG\}\}"'
        }
        ($catalog | Where-Object Id -eq 'DP.5c').Query | Should -Match 'id !contains "\{\{MRG\}\}"'
        ($catalog | Where-Object Id -eq 'DR.6-INITIATIVE').Query | Should -Match 'ResourceId !contains "\{\{MRG\}\}"'
        ($catalog | Where-Object Id -eq 'BKL.2').Query | Should -Match 'tostring\(properties\.resourceIdentifiers\) !contains "\{\{MRG\}\}"'
        ($catalog | Where-Object Id -eq 'POS.8').Query | Should -Match 'AssessedResourceId !contains "\{\{MRG\}\}"'
    }

    It 'excludes managed resource group devices from every Advanced Hunting query that reads DeviceInfo' {
        $missing = @($catalog | Where-Object { $_.Engine -eq 'AH' -and $_.Query -match '(?m)^\s*DeviceInfo\s*$' -and $_.Query -notmatch 'AzureResourceId !contains "\{\{MRG\}\}"' } | ForEach-Object Id)
        $missing | Should -BeNullOrEmpty
        foreach ($id in 'EW.1', 'EW.1-DEVICES', 'EW.3', 'EW.4', 'EW.5', 'EW.12', 'NB.8', 'DR.5', 'DR.12', 'BKL.1') {
            ($catalog | Where-Object Id -eq $id).Query | Should -Match 'AzureResourceId !contains "\{\{MRG\}\}"'
        }
        # EW.5 joins DeviceInfo leftouter, so the filter sits after the join: an excluded VM vanishes instead of becoming "Other device"
        $ew5 = ($catalog | Where-Object Id -eq 'EW.5').Query
        $ew5.IndexOf('AzureResourceId !contains') | Should -BeGreaterThan $ew5.IndexOf(') on DeviceId')
        $ew5.IndexOf('AzureResourceId !contains') | Should -BeLessThan $ew5.IndexOf('| extend Mode')
        $expanded = Expand-EbrQuery -Query $ew5 -WindowStart ([datetime]'2026-01-01') -WindowEnd ([datetime]'2026-06-30') -ManagedRgPattern ''
        $expanded | Should -Not -Match 'AzureResourceId !contains'
        $expanded | Should -Match '\) on DeviceId\n\| extend Mode'
    }

    It 'reads App Service config with the PascalCase keys Resource Graph returns' {
        # appserviceresources exposes site config as PascalCase (MinTlsVersion, FtpsState). KQL dynamic
        # access is case-sensitive, so the camelCase keys returned null on every row and NB.5 reported 0.
        $q = ($catalog | Where-Object Id -eq 'NB.5').Query
        $q | Should -MatchExactly 'properties\.MinTlsVersion'
        $q | Should -MatchExactly 'properties\.FtpsState'
        $q | Should -Not -MatchExactly 'tostring\(properties\.minTlsVersion\)'
        $q | Should -Not -MatchExactly 'tostring\(properties\.ftpsState\)'
    }

    It 'keeps Comments and ClassificationComment through arg_max in every ticket-scoped query' {
        # {{TICKET}} expands to a where on Comments and ClassificationComment. An explicit arg_max column
        # list that omits them makes Log Analytics fail with "Failed to resolve scalar expression".
        # Only the arg_max that feeds the filter matters; a later arg_max on SecurityAlert (OUT.5, OUT.6) is fine.
        foreach ($item in ($catalog | Where-Object { $_.Query -match '\{\{TICKET\}\}' })) {
            $before = $item.Query.Substring(0, $item.Query.IndexOf('{{TICKET}}'))
            $lists = [regex]::Matches($before, 'arg_max\(TimeGenerated, ([^)]*)\)')
            $lists.Count | Should -BeGreaterThan 0 -Because $item.Id
            $columns = $lists[$lists.Count - 1].Groups[1].Value
            if ($columns -ne '*') {
                $columns | Should -Match '\bComments\b' -Because $item.Id
                $columns | Should -Match '\bClassificationComment\b' -Because $item.Id
            }
        }
    }
}

Describe 'Network virtual appliances, backup findings and Conditional Access inputs (1.10.0)' {
    BeforeAll { $catalog = Get-EbrQueryCatalog }
    It 'leaves appliances out of every VM measure they cannot take and lists them in P0.6-APPLIANCES' {
        foreach ($id in 'EW.7', 'EW.7-DETAIL', 'EW.8', 'DP.4', 'DP.4-DETAIL', 'DP.5b') {
            ($catalog | Where-Object Id -eq $id).Query | Should -Match 'where not\(\{\{APPLIANCE\}\}\)' -Because $id
        }
        foreach ($id in 'DFC.1', 'DFC.1-DETAIL') {
            $q = ($catalog | Where-Object Id -eq $id).Query
            $q | Should -Match 'join kind=leftouter'
            $q | Should -Match 'where isempty\(Appliance\) or not\(Recommendation has_any'
            $q | Should -Match '"EDR", "endpoint protection"'
        }
        ($catalog | Where-Object Id -eq 'P0.6-APPLIANCES').Query | Should -Match '\| where \{\{APPLIANCE\}\}'
    }
    It 'classifies stale backup items so superseded and deleted sources can be left out' {
        $q = ($catalog | Where-Object Id -eq 'DP.5-STALE').Query
        $q | Should -Match 'CurrentForSource > 0, "Superseded"'
        $q | Should -Match 'CurrentForName > 0 and not\(SourceExists\), "Superseded"'
        $q | Should -Match 'not\(SourceExists\), "Source deleted"'
        ([regex]::Matches($q, 'join kind=')).Count | Should -BeLessOrEqual 3 -Because 'Resource Graph allows three joins per query'
        $b = ($catalog | Where-Object Id -eq 'DP.5b').Query
        $b | Should -Match 'ProtectedItems = countif\(ProtectionState == "Protected"\)'
        $b | Should -Match 'where ProtectedItems == 0'
    }
    It 'reads successful device code and legacy sign-ins with their policy results, and IA.3 leaves out Unknown' {
        $q = ($catalog | Where-Object Id -eq 'IA.8-SIGNINS').Query
        $q | Should -Match 'AuthenticationProtocol =~ "deviceCode", "Device code"'
        $q | Should -Match 'mv-apply Policy = todynamic\(ConditionalAccessPolicies\)'
        $q | Should -Match 'by Flow, ClientAppUsed, UserId, UserPrincipalName, UserType, PolicyResults'
        ($catalog | Where-Object Id -eq 'IA.3').Query | Should -Match '"Mobile Apps and Desktop clients", "Unknown"\)'
    }
}

Describe 'Network devices and blob containers (1.11.0)' {
    BeforeAll { $catalog = Get-EbrQueryCatalog }
    It 'leaves network devices and firewalls out of EW.1 and EW.1-DEVICES' {
        foreach ($id in 'EW.1', 'EW.1-DEVICES') {
            ($catalog | Where-Object Id -eq $id).Query | Should -Match 'where not\(\{\{NETWORK_DEVICE\}\}\)' -Because $id
        }
        $out = Expand-EbrQuery -Query 'DeviceInfo | where not({{NETWORK_DEVICE}})' -WindowStart ([datetime]'2026-01-01') -WindowEnd ([datetime]'2026-07-31') -ManagedRgPattern 'x'
        $out | Should -Not -Match '\{\{NETWORK_DEVICE\}\}'
        $out | Should -Match 'column_ifexists\("DeviceCategory", ""\)\) contains "network"'
        $out | Should -Match 'column_ifexists\("Vendor", ""\)'
        'Palo Alto Networks|PAN-OS|Cisco Meraki|Fortinet FortiGate|FortiOS|SonicWall|SonicOS' -split '\|' | ForEach-Object { $_ -match $script:EbrNetworkDevicePattern | Should -BeTrue -Because $_ }
        'WindowsServer2022|Windows11|Linux|macOS|Dell Inc.|Microsoft Corporation|Cisco UCS' -split '\|' | ForEach-Object { $_ -match $script:EbrNetworkDevicePattern | Should -BeFalse -Because $_ }
    }
    It 'reads blob containers per storage account through a GET on the Storage resource provider' {
        $item = $catalog | Where-Object Id -eq 'DP.1-CONTAINERS'
        $item.Engine | Should -Be 'STORAGE-CONTAINERS'
        $item.Query | Should -Match 'kind !~ "FileStorage"'
        $item.Query | Should -Match 'AllowBlobPublicAccess = tostring\(properties\.allowBlobPublicAccess\)'
        { Assert-EbrReadOnlyRequest -Method GET -Uri 'https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a/blobServices/default/containers?api-version=2023-05-01' } | Should -Not -Throw
    }
    It 'counts every container and treats a public container as readable only when the account setting allows it' {
        Mock Invoke-EbrRest {
            if ($Uri -match 'page2') { return [pscustomobject]@{ value = @([pscustomobject]@{ name = 'assets'; properties = [pscustomobject]@{ publicAccess = 'Container' } }) } }
            [pscustomobject]@{ value = @([pscustomobject]@{ name = 'private'; properties = [pscustomobject]@{ publicAccess = 'None' } }, [pscustomobject]@{ name = 'images'; properties = [pscustomobject]@{ publicAccess = 'Blob' } }); nextLink = 'https://management.azure.com/x?page2' }
        }
        $a = [pscustomobject]@{ ResourceId = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a'; Account = 'a'; resourceGroup = 'rg'; subscriptionId = 's'; AllowBlobPublicAccess = '' }
        $r = Get-EbrBlobContainerRow -Account $a -Tenant 't'
        $r.AccountAnonymousAccess | Should -Be 'Not set, allowed'
        @($r.Containers, $r.PublicContainers, $r.ExposedContainers) | Should -Be @(3, 2, 2)
        $r.PublicContainerNames | Should -Be 'images (Blob), assets (Container)'
        $r.ReadStatus | Should -Be 'OK'
        $a.AllowBlobPublicAccess = 'false'
        $r = Get-EbrBlobContainerRow -Account $a -Tenant 't'
        @($r.AccountAnonymousAccess, $r.PublicContainers, $r.ExposedContainers) | Should -Be @('Disabled', 2, 0)
        Should -Invoke Invoke-EbrRest -ParameterFilter { $Method -eq 'GET' -and $Uri -like 'https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a/blobServices/default/containers?api-version=*' }
    }
    It 'records an account it cannot list instead of counting it' {
        Mock Invoke-EbrRest { throw 'HTTP 403: Forbidden | AuthorizationFailed' }
        $r = Get-EbrBlobContainerRow -Account ([pscustomobject]@{ ResourceId = '/x'; Account = 'a'; AllowBlobPublicAccess = 'true' }) -Tenant 't'
        $r.ReadStatus | Should -Match '403'
        $r.Containers | Should -Be 0
    }
}

Describe 'Expand-EbrQuery' {
    BeforeAll {
        $start = [datetime]::new(2026, 1, 1)
        $end = [datetime]::new(2026, 7, 31)
    }

    It 'replaces the window tokens with KQL datetime literals' {
        $q = 'x | where T between ({{WINDOW_START}} .. endofday({{WINDOW_END}}))'
        Expand-EbrQuery -Query $q -WindowStart $start -WindowEnd $end -ManagedRgPattern 'aznativesol0' |
            Should -Be 'x | where T between (datetime(2026-01-01) .. endofday(datetime(2026-07-31)))'
    }

    It 'replaces the managed resource group token' {
        $q = "resources`n| where id !contains `"{{MRG}}`"`n| count"
        $out = Expand-EbrQuery -Query $q -WindowStart $start -WindowEnd $end -ManagedRgPattern 'aznativesol0'
        $out | Should -Match 'id !contains "aznativesol0"'
    }

    It 'expands the appliance token to a publisher match on the plan and both image references' {
        $out = Expand-EbrQuery -Query 'resources | where not({{APPLIANCE}})' -WindowStart $start -WindowEnd $end -ManagedRgPattern 'aznativesol0'
        $out | Should -Match 'tostring\(plan\.publisher\)'
        $out | Should -Match 'properties\.virtualMachineProfile\.storageProfile\.imageReference\.publisher'
        $out | Should -Match 'matches regex @"\(paloalto\|fortinet\|'
        $out | Should -Not -Match '\{\{APPLIANCE\}\}'
        'paloaltonetworks fortinet barracudanetworks f5-networks' -split ' ' | ForEach-Object { $_ -match $script:EbrAppliancePattern | Should -BeTrue }
        'canonical microsoftwindowsserver redhat' -split ' ' | ForEach-Object { $_ -match $script:EbrAppliancePattern | Should -BeFalse }
    }

    It 'drops the exclusion lines when the pattern is empty instead of excluding everything' {
        $q = "resources`n| where id !contains `"{{MRG}}`"`n| count"
        $out = Expand-EbrQuery -Query $q -WindowStart $start -WindowEnd $end -ManagedRgPattern ''
        $out | Should -Not -Match 'contains'
        $out | Should -Match 'count'
    }

    It 'rejects a managed resource group pattern containing a double quote' {
        { Expand-EbrQuery -Query 'x' -WindowStart $start -WindowEnd $end -ManagedRgPattern 'a"b' } |
            Should -Throw
    }

    It 'leaves no unexpanded token in any catalog query' {
        foreach ($item in (Get-EbrQueryCatalog | Where-Object Query)) {
            foreach ($mrg in 'aznativesol0', '') {
                $out = Expand-EbrQuery -Query $item.Query -WindowStart $start -WindowEnd $end -ManagedRgPattern $mrg
                $out | Should -Not -Match '\{\{' -Because "$($item.Id) must expand fully"
            }
        }
    }
}

Describe 'Assert-EbrReadOnlyRequest' {
    It 'allows GET anywhere' {
        { Assert-EbrReadOnlyRequest -Method GET -Uri 'https://management.azure.com/subscriptions/x?api-version=1' } |
            Should -Not -Throw
    }

    It 'allows POST to the three query endpoints' {
        { Assert-EbrReadOnlyRequest -Method POST -Uri 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01' } |
            Should -Not -Throw
        { Assert-EbrReadOnlyRequest -Method POST -Uri 'https://api.loganalytics.io/v1/workspaces/1111/query' } |
            Should -Not -Throw
        { Assert-EbrReadOnlyRequest -Method POST -Uri 'https://api.security.microsoft.com/api/advancedqueries/run' } |
            Should -Not -Throw
    }

    It 'blocks POST anywhere else' {
        { Assert-EbrReadOnlyRequest -Method POST -Uri 'https://management.azure.com/subscriptions/x/resourceGroups/y/providers/Microsoft.Compute/virtualMachines/z/start?api-version=1' } |
            Should -Throw
        { Assert-EbrReadOnlyRequest -Method POST -Uri 'https://api.security.microsoft.com/api/machines/abc/isolate' } |
            Should -Throw
    }

    It 'blocks every write verb' {
        foreach ($verb in 'PUT', 'PATCH', 'DELETE', 'MERGE') {
            { Assert-EbrReadOnlyRequest -Method $verb -Uri 'https://management.azure.com/x' } | Should -Throw
        }
    }
}

Describe 'Response conversion' {
    It 'turns a Log Analytics table into ordered rows' {
        $resp = [pscustomobject]@{
            tables = @([pscustomobject]@{
                name    = 'PrimaryResult'
                columns = @(
                    [pscustomobject]@{ name = 'SourceTable'; type = 'string' },
                    [pscustomobject]@{ name = 'Records'; type = 'long' }
                )
                rows    = @(, @('SecurityIncident', 12)) + @(, @('SigninLogs', 99))
            })
        }
        $r = ConvertFrom-EbrLaResponse -Response $resp
        $r.Columns | Should -Be @('SourceTable', 'Records')
        $r.Rows.Count | Should -Be 2
        $r.Rows[1].SourceTable | Should -Be 'SigninLogs'
        $r.Rows[1].Records | Should -Be 99
        ($r.Rows[0].PSObject.Properties.Name -join ',') | Should -Be 'SourceTable,Records'
    }

    It 'keeps the columns when Log Analytics returns no rows' {
        $resp = [pscustomobject]@{
            tables = @([pscustomobject]@{
                name    = 'PrimaryResult'
                columns = @([pscustomobject]@{ name = 'A'; type = 'string' })
                rows    = @()
            })
        }
        $r = ConvertFrom-EbrLaResponse -Response $resp
        $r.Rows.Count | Should -Be 0
        $r.Columns | Should -Be @('A')
    }

    It 'turns an Advanced Hunting response into rows' {
        $resp = [pscustomobject]@{
            Schema  = @([pscustomobject]@{ Name = 'SourceTable'; Type = 'String' }, [pscustomobject]@{ Name = 'Rows'; Type = 'Int64' })
            Results = @([pscustomobject]@{ SourceTable = 'DeviceInfo'; Rows = 5 })
        }
        $r = ConvertFrom-EbrAhResponse -Response $resp
        $r.Columns | Should -Be @('SourceTable', 'Rows')
        $r.Rows[0].SourceTable | Should -Be 'DeviceInfo'
    }

    It 'normalizes DateTime values to ISO 8601 UTC strings' {
        $row = [pscustomobject]@{ When = [datetime]::SpecifyKind([datetime]'2026-01-02T03:04:05', 'Utc'); N = 1 }
        $out = ConvertTo-EbrRow -InputObject $row
        $out.When | Should -Be '2026-01-02T03:04:05Z'
        $out.N | Should -Be 1
    }

    It 'flattens nested values to JSON for CSV' {
        $row = [pscustomobject]@{ Name = 'a'; Methods = @('x', 'y'); Obj = [pscustomobject]@{ k = 1 } }
        $flat = ConvertTo-EbrCsvRow -InputObject $row
        $flat.Methods | Should -Be '["x","y"]'
        $flat.Obj | Should -Be '{"k":1}'
        $flat.Name | Should -Be 'a'
    }
}

Describe 'Get-EbrDefaultReportingWindow' {
    # CyberSOC: the report month and the two full months before it, not the maximum reach of the EBR collector.
    BeforeAll { $now = [datetime]::new(2026, 10, 7, 15, 0, 0) }

    It 'reports the last full month by default, with the two full months before it' {
        $w = Get-EbrDefaultReportingWindow -EarliestIncident ([datetime]'2026-01-14T09:00:00') -Now $now
        $w.ReportMonth | Should -Be ([datetime]'2026-09-01')
        $w.Start | Should -Be ([datetime]'2026-07-01')
        $w.End | Should -Be ([datetime]'2026-09-30')
        $w.Basis | Should -Match 'report month September 2026 and the 2 full months before it, the 90-day trend'
        $w.Basis | Should -Not -Match 'shortened'
    }

    It 'takes the report month it is given' {
        $w = Get-EbrDefaultReportingWindow -ReportMonth ([datetime]'2026-01-20') -Now $now
        $w.Start | Should -Be ([datetime]'2025-11-01')
        $w.End | Should -Be ([datetime]'2026-01-31')
        $w.ReportMonth | Should -Be ([datetime]'2026-01-01')
    }

    It 'refuses a report month that has not ended' {
        { Get-EbrDefaultReportingWindow -ReportMonth ([datetime]'2026-10-01') -Now $now } | Should -Throw '*has not ended yet*2026-09*'
    }

    It 'starts at the next full month when the data begins mid-month inside the trend' {
        $w = Get-EbrDefaultReportingWindow -EarliestIncident ([datetime]'2026-07-14T09:00:00') -Now $now
        $w.Start | Should -Be ([datetime]'2026-08-01')
        $w.TrendStart | Should -Be ([datetime]'2026-07-01')
        $w.Basis | Should -Match 'shortened to the first full month of data because SecurityIncident data starts 2026-07-14'
    }

    It 'keeps the trend start when the data begins at midnight on its 1st' {
        $w = Get-EbrDefaultReportingWindow -EarliestIncident ([datetime]'2026-07-01T00:00:00') -Now $now
        $w.Start | Should -Be ([datetime]'2026-07-01')
    }

    It 'falls back to retention when there is no incident data' {
        $w = Get-EbrDefaultReportingWindow -RetentionDays 60 -Now $now
        $w.Start | Should -Be ([datetime]'2026-09-01')
        $w.Basis | Should -Match 'retention'
    }

    It 'uses the three full months with nothing to go on' {
        $w = Get-EbrDefaultReportingWindow -Now $now
        $w.Start | Should -Be ([datetime]'2026-07-01')
        $w.End | Should -Be ([datetime]'2026-09-30')
    }

    It 'uses the partial month when data only starts in the report month' {
        $w = Get-EbrDefaultReportingWindow -EarliestIncident ([datetime]'2026-09-15T00:00:00') -Now $now
        $w.Start | Should -Be ([datetime]'2026-09-01')
        $w.Basis | Should -Match 'partial'
    }

    It 'reads a report month as yyyy-MM only' {
        ConvertTo-EbrMonth '2026-09' | Should -Be ([datetime]'2026-09-01')
        { ConvertTo-EbrMonth '2026-9' } | Should -Throw
        { ConvertTo-EbrMonth '2026-09-01' } | Should -Throw
    }
}

Describe 'Input helpers' {
    It 'accepts a tenant GUID or a domain' {
        Test-EbrTenantInput '0a1399e1-c245-4c67-96d1-378ab497dd3a' | Should -BeTrue
        Test-EbrTenantInput 'contoso.onmicrosoft.com' | Should -BeTrue
        Test-EbrTenantInput 'not a tenant' | Should -BeFalse
    }

    It 'splits, trims, lowercases and dedupes subscription input' {
        $ids = Split-EbrSubscriptionInput @('A0C307AD-F1C3-4A7D-96C3-10A6EB7C9C62, a0c307ad-f1c3-4a7d-96c3-10a6eb7c9c62;11111111-2222-3333-4444-555555555555')
        $ids | Should -Be @('a0c307ad-f1c3-4a7d-96c3-10a6eb7c9c62', '11111111-2222-3333-4444-555555555555')
    }

    It 'rejects anything that is not a subscription GUID' {
        { Split-EbrSubscriptionInput @('a0c307ad, nope') } | Should -Throw
    }

    It 'makes safe folder names' {
        ConvertTo-EbrSafeFileName 'Contoso, Inc./HQ' | Should -Be 'Contoso-Inc-HQ'
    }

    It 'parses yyyy-MM-dd dates and rejects anything else' {
        ConvertTo-EbrDate '2026-07-31' | Should -Be ([datetime]'2026-07-31')
        { ConvertTo-EbrDate '07/31/2026' } | Should -Throw
    }
}

Describe 'Test-EbrSubscriptionTenant' {
    It 'matches on homeTenantId (Lighthouse delegated subscription)' {
        $acct = [pscustomobject]@{ id = 's1'; tenantId = 'managing'; homeTenantId = 'client' }
        Test-EbrSubscriptionTenant -Account $acct -TenantGuid 'client' | Should -BeTrue
    }

    It 'falls back to tenantId when homeTenantId is missing' {
        $acct = [pscustomobject]@{ id = 's1'; tenantId = 'client' }
        Test-EbrSubscriptionTenant -Account $acct -TenantGuid 'client' | Should -BeTrue
    }

    It 'rejects a subscription homed in another client tenant' {
        $acct = [pscustomobject]@{ id = 's1'; tenantId = 'managing'; homeTenantId = 'other-client' }
        Test-EbrSubscriptionTenant -Account $acct -TenantGuid 'client' | Should -BeFalse
    }
}

Describe 'Token claims' {
    BeforeAll {
        function New-FakeJwt([hashtable]$Claims) {
            $json = $Claims | ConvertTo-Json -Compress
            $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
            "eyJhbGciOiJub25lIn0.$b64.sig"
        }
    }

    It 'decodes the payload' {
        (Get-EbrJwtClaims (New-FakeJwt @{ tid = 'client'; upn = 'a@b.com' })).tid | Should -Be 'client'
    }

    It 'detects an external (GDAP or guest) user from the idp claim' {
        $ext = Get-EbrJwtClaims (New-FakeJwt @{ tid = 'client'; idp = 'https://sts.windows.net/partner/' })
        $int = Get-EbrJwtClaims (New-FakeJwt @{ tid = 'client' })
        Test-EbrExternalUser -Claims $ext -TenantGuid 'client' | Should -BeTrue
        Test-EbrExternalUser -Claims $int -TenantGuid 'client' | Should -BeFalse
    }
}

Describe 'Run 1 fixes' {
    It 'finds the Advanced Hunting tables a query reads, without matching column names' {
        $catalog = Get-EbrQueryCatalog
        $ew3 = Get-EbrAhTables (($catalog | Where-Object Id -eq 'EW.3').Query)
        $ew3 | Sort-Object | Should -Be @('DeviceInfo', 'DeviceTvmSecureConfigurationAssessment', 'DeviceTvmSecureConfigurationAssessmentKB')
        Get-EbrAhTables (($catalog | Where-Object Id -eq 'IA.6-SUB').Query) | Should -Be @('IdentityInfo')
        Get-EbrAhTables 'DeviceEvents | project DeviceId, DeviceName' | Should -Be @('DeviceEvents')
    }

    It 'builds a table probe that survives every table being missing' {
        $q = New-EbrTableProbeQuery -Tables @('DeviceInfo', 'IdentityInfo')
        $q | Should -Match 'union isfuzzy = true'
        $q | Should -Match '\(DeviceInfo \| where TimeGenerated > ago\(30d\) \| take 1 \| project SourceTable = "DeviceInfo"\)'
        $q | Should -Match 'print SourceTable = "" \| where false'
    }

    It 'recognises errors a fresh sign-in can fix' {
        Test-EbrReauthError 'ERROR: AADSTS50078: Presented multi-factor authentication has expired' | Should -BeTrue
        Test-EbrReauthError 'AADSTS50076: Due to a configuration change' | Should -BeTrue
        Test-EbrReauthError 'AADSTS65001: The user or administrator has not consented' | Should -BeFalse
        Test-EbrReauthError 'HTTP 403: Forbidden' | Should -BeFalse
    }

    It 'summarises a long az error to the AADSTS sentence' {
        $long = "az could not issue a token. ERROR: AADSTS50078: Presented multi-factor authentication has expired due to policies configured by your administrator, you must refresh your multi-factor authentication to access 'fc780465'. Trace ID: abc Correlation ID: def Timestamp: 2026-10-08 Run the command below to authenticate interactively"
        $s = Get-EbrAzErrorSummary $long
        $s | Should -Match "^AADSTS50078: Presented multi-factor authentication has expired .* to access 'fc780465'\.$"
        Get-EbrAzErrorSummary 'plain failure' | Should -Be 'plain failure'
    }

    It 'names the client from the tenant, then the domain typed, never a subscription' {
        $acct = @([pscustomobject]@{ id = 's1'; name = 'AZ-Pure-Sub'; tenantId = 'managing'; homeTenantId = 'client'; tenantDisplayName = 'Atmosera' })
        Get-EbrClientName -Override 'Contoso' -TenantGuid 'client' -TenantInput 'contoso.test' -Accounts $acct | Should -Be 'Contoso'
        Get-EbrClientName -TenantInfo ([pscustomobject]@{ DisplayName = 'Contoso Inc' }) -TenantGuid 'client' -TenantInput 'contoso.test' -Accounts $acct | Should -Be 'Contoso Inc'
        Get-EbrClientName -TenantGuid 'client' -TenantInput 'Contoso.test' -Accounts $acct | Should -Be 'contoso.test'
        Get-EbrClientName -TenantGuid 'client' -TenantInput 'client' -Accounts $acct | Should -Be 'client'
        $direct = @([pscustomobject]@{ id = 's1'; tenantId = 'client'; tenantDisplayName = 'Contoso Direct' })
        Get-EbrClientName -TenantGuid 'client' -TenantInput 'contoso.test' -Accounts $direct | Should -Be 'Contoso Direct'
    }

    It 'spots data that starts at the retention limit rather than at service start' {
        $now = [datetime]'2026-10-08T03:18:00Z'
        Test-EbrRetentionBound -Earliest ([datetime]'2026-06-10T14:54:00Z') -RetentionDays 120 -Now $now | Should -BeTrue
        Test-EbrRetentionBound -Earliest ([datetime]'2026-07-20T00:00:00Z') -RetentionDays 120 -Now $now | Should -BeFalse
        Test-EbrRetentionBound -Earliest $null -RetentionDays 120 -Now $now | Should -BeFalse
    }

    It 'gives the right advice for each Conditional Access block' {
        Get-EbrCaBlockAdvice "AADSTS530004: AcceptCompliantDevice setting isn't configured for this organization." | Should -Match 'Cross-tenant access settings .* Trust compliant devices'
        Get-EbrCaBlockAdvice 'AADSTS53000: Device is not in required device state: compliant.' | Should -Match 'compliant in Atmosera'
        Get-EbrCaBlockAdvice 'AADSTS53003: Access has been blocked by Conditional Access policies.' | Should -Match 'sign-in log'
        Get-EbrCaBlockAdvice 'AADSTS50078: Presented multi-factor authentication has expired.' | Should -BeNullOrEmpty
        Test-EbrReauthError 'AADSTS530004: AcceptCompliantDevice' | Should -BeFalse
    }

    It 'writes doubles to CSV without floating-point noise, in invariant culture' {
        $row = ConvertTo-EbrCsvRow ([pscustomobject]@{ Current = 130.35999999999999; Sum = 0.1 + 0.2; Count = 5; Name = 'x' })
        # -BeOfType first: PowerShell's own double-to-string coercion would hide the noise from -Be
        $row.Sum | Should -BeOfType [string]
        $row.Sum | Should -BeExactly '0.3'
        $row.Current | Should -BeOfType [string]
        $row.Current | Should -BeExactly '130.36'
        $row.Count | Should -Be 5
    }

    It 'explains a cmdlet the account is not allowed to see' {
        $r = Invoke-EbrCollector -ResultId 'DP.6' -Source 'Security & Compliance' -MissingCmdletHint 'Needs a DLP role.' -Block { Get-ThisCmdletDoesNotExist123 }
        $r.Status | Should -Be 'FAILED'
        $r.Detail | Should -Match 'Get-ThisCmdletDoesNotExist123'
        $r.Detail | Should -Match 'Needs a DLP role\.'
    }
}

Describe 'Resolve-EbrAccessPath' {
    BeforeAll {
        Mock Write-Host { }
        $subs = @('s1', 's2')
        $lhAccounts = @(
            [pscustomobject]@{ id = 's1'; tenantId = 'managing'; homeTenantId = 'client' },
            [pscustomobject]@{ id = 's2'; tenantId = 'managing'; homeTenantId = 'client' })
    }

    It 'uses direct access when it already reaches every subscription' {
        Mock Test-EbrDirectAccess { [pscustomobject]@{ Ok = $true; Missing = @(); Error = $null } }
        Mock Read-EbrInput { 'y' }
        $a = Resolve-EbrAccessPath -TenantGuid 'client' -TenantInput 'contoso.test' -Subscriptions $subs -Accounts $lhAccounts
        $a.Path | Should -Be 'Direct'
        $a.ArmTenant | Should -Be 'client'
        $a.SubAccess['s2'] | Should -Be 'client'
        Should -Invoke Read-EbrInput -Times 0 -Exactly
    }

    It 'offers az login --tenant with the domain typed and switches to direct when it works' {
        $script:directChecks = 0
        Mock Test-EbrDirectAccess { $script:directChecks++; [pscustomobject]@{ Ok = ($script:directChecks -gt 1); Missing = @(); Error = 'no token' } }
        Mock Read-EbrInput { 'y' }
        Mock Invoke-EbrAzLogin { }
        $a = Resolve-EbrAccessPath -TenantGuid 'client' -TenantInput 'contoso.test' -Subscriptions $subs -Accounts $lhAccounts
        $a.Path | Should -Be 'Direct'
        Should -Invoke Invoke-EbrAzLogin -Times 1 -Exactly -ParameterFilter { $Tenant -eq 'contoso.test' -and -not $Scope }
    }

    It 'falls back to Lighthouse when you decline, and says what that costs' {
        Mock Test-EbrDirectAccess { [pscustomobject]@{ Ok = $false; Missing = @('s1', 's2'); Error = 'no token' } }
        Mock Read-EbrInput { 'n' }
        Mock Invoke-EbrAzLogin { }
        $a = Resolve-EbrAccessPath -TenantGuid 'client' -TenantInput 'contoso.test' -Subscriptions $subs -Accounts $lhAccounts
        $a.Path | Should -Be 'Lighthouse'
        $a.ArmTenant | Should -Be 'managing'
        $a.Warning | Should -Match 'IA\.7'
        $a.Warning | Should -Match 'az login --tenant contoso\.test'
        Should -Invoke Invoke-EbrAzLogin -Times 0 -Exactly
    }

    It 'prefers the Lighthouse entry for the fallback when a subscription is listed twice' {
        Mock Test-EbrDirectAccess { [pscustomobject]@{ Ok = $false; Missing = @('s1'); Error = $null } }
        Mock Read-EbrInput { 'n' }
        $twice = @([pscustomobject]@{ id = 's1'; tenantId = 'client'; homeTenantId = 'client' }, [pscustomobject]@{ id = 's1'; tenantId = 'managing'; homeTenantId = 'client' })
        (Resolve-EbrAccessPath -TenantGuid 'client' -TenantInput 'contoso.test' -Subscriptions @('s1') -Accounts $twice).SubAccess['s1'] | Should -Be 'managing'
    }
}

Describe 'Initialize-EbrDefender' {
    BeforeAll {
        Mock Write-Host { }
        function New-Ctx { [pscustomobject]@{ TenantGuid = 'client'; DefenderAvailable = $false; DefenderReason = ''; DefenderAdvice = '' } }
    }

    It 'offers a fresh sign-in when the tenant wants new MFA, then retries' {
        $script:tokenCalls = 0
        Mock Get-EbrToken { $script:tokenCalls++; if ($script:tokenCalls -eq 1) { throw 'ERROR: AADSTS50078: Presented multi-factor authentication has expired.' } 'token' }
        Mock Read-EbrInput { 'y' }
        Mock Invoke-EbrAzLogin { }
        $ctx = New-Ctx
        Initialize-EbrDefender -Ctx $ctx
        $ctx.DefenderAvailable | Should -BeTrue
        Should -Invoke Invoke-EbrAzLogin -Times 1 -Exactly -ParameterFilter { $Tenant -eq 'client' -and $Scope -eq 'https://api.securitycenter.microsoft.com/.default' }
    }

    It 'carries on without Defender when the user declines, with a readable reason' {
        Mock Get-EbrToken { throw 'ERROR: AADSTS50078: Presented multi-factor authentication has expired. Trace ID: x' }
        Mock Read-EbrInput { 'n' }
        Mock Invoke-EbrAzLogin { }
        $ctx = New-Ctx
        Initialize-EbrDefender -Ctx $ctx
        $ctx.DefenderAvailable | Should -BeFalse
        $ctx.DefenderReason | Should -Match '^No Defender API token: AADSTS50078: Presented multi-factor authentication has expired\.'
        $ctx.DefenderReason | Should -Match 'az login --tenant client --scope https://api.securitycenter.microsoft.com/.default'
        Should -Invoke Invoke-EbrAzLogin -Times 0 -Exactly
    }

    It 'explains a device-compliance block instead of offering a pointless sign-in' {
        Mock Get-EbrToken { throw "ERROR: AADSTS530004: AcceptCompliantDevice setting isn't configured for this organization. Trace ID: x" }
        Mock Read-EbrInput { 'y' }
        Mock Invoke-EbrAzLogin { }
        $ctx = New-Ctx
        Initialize-EbrDefender -Ctx $ctx
        Should -Invoke Read-EbrInput -Times 0 -Exactly
        $ctx.DefenderAvailable | Should -BeFalse
        $ctx.DefenderAdvice | Should -Match 'Trust compliant devices'
    }

    It 'does not prompt for errors a sign-in cannot fix' {
        Mock Get-EbrToken { throw 'AADSTS65001: not consented' }
        Mock Read-EbrInput { 'y' }
        $ctx = New-Ctx
        Initialize-EbrDefender -Ctx $ctx
        Should -Invoke Read-EbrInput -Times 0 -Exactly
        $ctx.DefenderAvailable | Should -BeFalse
    }
}

Describe 'Invoke-EbrGraphGet' {
    It 'follows nextLink and returns every value' {
        Mock Invoke-EbrRest {
            if ($Uri -match 'skiptoken=2') { return [pscustomobject]@{ value = @([pscustomobject]@{ id = 'b' }) } }
            [pscustomobject]@{ value = @([pscustomobject]@{ id = 'a' }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/users?$skiptoken=2' }
        }
        $r = @(Invoke-EbrGraphGet -Uri 'https://graph.microsoft.com/v1.0/users' -Tenant 't')
        $r.id | Should -Be @('a', 'b')
        Should -Invoke Invoke-EbrRest -Times 2 -Exactly -ParameterFilter { $Method -eq 'GET' -and $Resource -eq 'https://graph.microsoft.com/' -and $Tenant -eq 't' }
    }

    It 'returns a single object when there is no value array' {
        Mock Invoke-EbrRest { [pscustomobject]@{ id = 'org' } }
        (Invoke-EbrGraphGet -Uri 'https://graph.microsoft.com/v1.0/organization' -Tenant 't').id | Should -Be 'org'
    }

    It 'returns an empty array, not null, when a collection is empty' {
        Mock Invoke-EbrRest { [pscustomobject]@{ value = @() } }
        $r = Invoke-EbrGraphGet -Uri 'https://graph.microsoft.com/v1.0/users' -Tenant 't'
        ($null -ne $r) | Should -BeTrue
        @($r).Count | Should -Be 0
    }

    It 'turns a 403 into a GRAPH-403 error naming the endpoint' {
        Mock Invoke-EbrRest { throw 'HTTP 403: Forbidden | Authorization_RequestDenied: Insufficient privileges to complete the operation.' }
        { Invoke-EbrGraphGet -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$top=1' -Tenant 't' } |
            Should -Throw 'GRAPH-403 https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies: *'
    }

    It 'passes other errors through unchanged' {
        Mock Invoke-EbrRest { throw 'HTTP 400: Bad Request | Invalid filter clause' }
        { Invoke-EbrGraphGet -Uri 'https://graph.microsoft.com/v1.0/x' -Tenant 't' } | Should -Throw 'HTTP 400*'
    }

    It 'treats a 401 from a resource that rejects the token scope (SharePoint settings) as a permission gap' {
        Mock Invoke-EbrRest { throw 'HTTP 401: Response status code does not indicate success: 401 (Unauthorized). | There has been an error authenticating the request.' }
        { Invoke-EbrGraphGet -Uri 'https://graph.microsoft.com/v1.0/admin/sharepoint/settings' -Tenant 't' } | Should -Throw 'GRAPH-403 https://graph.microsoft.com/v1.0/admin/sharepoint/settings: HTTP 401*'
    }

    It 'builds beta URIs on request' {
        Get-EbrGraphUri 'deviceManagement/configurationPolicies' -Beta | Should -Be 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies'
        Get-EbrGraphUri '/organization' | Should -Be 'https://graph.microsoft.com/v1.0/organization'
    }

    It 'sends ConsistencyLevel eventual for count queries' {
        Mock Invoke-EbrRest { [pscustomobject]@{ value = @() } }
        $null = Invoke-EbrGraphGet -Uri 'https://graph.microsoft.com/v1.0/users?$count=true' -Tenant 't'
        Should -Invoke Invoke-EbrRest -Times 1 -Exactly -ParameterFilter { $Headers.ConsistencyLevel -eq 'eventual' }
    }
}

Describe 'Initialize-EbrGraph' {
    BeforeAll {
        Mock Write-Host { }
        function New-GCtx { [pscustomobject]@{ TenantGuid = 'client'; GraphAvailable = $false; GraphReason = ''; GraphAdvice = '' } }
    }

    It 'is available when the token and the organization probe succeed' {
        Mock Get-EbrToken { 'token' }
        Mock Invoke-EbrGraphGet { [pscustomobject]@{ id = 'client' } }
        $ctx = New-GCtx
        Initialize-EbrGraph -Ctx $ctx
        $ctx.GraphAvailable | Should -BeTrue
        Should -Invoke Invoke-EbrGraphGet -Times 1 -Exactly -ParameterFilter { $Uri -match 'v1\.0/organization' -and $Tenant -eq 'client' }
    }

    It 'offers a fresh sign-in on a reauth error with the Graph scope, then retries' {
        $script:graphTokenCalls = 0
        Mock Get-EbrToken { $script:graphTokenCalls++; if ($script:graphTokenCalls -eq 1) { throw 'ERROR: AADSTS50078: Presented multi-factor authentication has expired.' } 'token' }
        Mock Read-EbrInput { 'y' }
        Mock Invoke-EbrAzLogin { }
        Mock Invoke-EbrGraphGet { [pscustomobject]@{ id = 'client' } }
        $ctx = New-GCtx
        Initialize-EbrGraph -Ctx $ctx
        $ctx.GraphAvailable | Should -BeTrue
        Should -Invoke Invoke-EbrAzLogin -Times 1 -Exactly -ParameterFilter { $Tenant -eq 'client' -and $Scope -eq 'https://graph.microsoft.com/.default' }
    }

    It 'records a readable reason and the compliance advice when the token is blocked' {
        Mock Get-EbrToken { throw "ERROR: AADSTS530004: AcceptCompliantDevice setting isn't configured for this organization. Trace ID: x" }
        Mock Read-EbrInput { 'y' }
        Mock Invoke-EbrAzLogin { }
        $ctx = New-GCtx
        Initialize-EbrGraph -Ctx $ctx
        Should -Invoke Read-EbrInput -Times 0 -Exactly
        $ctx.GraphAvailable | Should -BeFalse
        $ctx.GraphReason | Should -Match '^No Graph token: AADSTS530004'
        $ctx.GraphAdvice | Should -Match 'Trust compliant devices'
    }

    It 'treats a failed probe as unavailable and keeps the probe error' {
        Mock Get-EbrToken { 'token' }
        Mock Invoke-EbrGraphGet { throw 'GRAPH-403 https://graph.microsoft.com/v1.0/organization: HTTP 403' }
        $ctx = New-GCtx
        Initialize-EbrGraph -Ctx $ctx
        $ctx.GraphAvailable | Should -BeFalse
        $ctx.GraphReason | Should -Match '^Graph probe failed: GRAPH-403'
    }
}

Describe 'Graph collectors' {
    BeforeAll {
        Mock Write-Host { }
        function New-GraphCtx {
            [pscustomobject]@{
                TenantGuid = 'client'; GraphAvailable = $true; GraphReason = ''; GraphAdvice = ''; GraphCache = @{}
                GraphMissingScopes = [System.Collections.Generic.List[string]]::new(); GraphPartial = [System.Collections.Generic.List[string]]::new(); Pending = [System.Collections.Generic.List[object]]::new()
                OutDir = $TestDrive; WindowStart = [datetime]'2026-01-01'; WindowEnd = [datetime]'2026-09-30'; ManagedRgPattern = 'aznativesol0'; TicketPattern = ''; PatchCadenceDays = 30
            }
        }
        function New-GraphItem([string]$Id) { [pscustomobject]@{ Id = $Id; Title = $Id; Engine = 'GRAPH'; Query = 'GET /v1.0/x'; Notes = 'Portal fallback: somewhere.'; Phase = 'P2 Identity' } }
        $null = New-Item -ItemType Directory -Path (Join-Path $TestDrive 'queries') -Force
    }

    It 'IA.8 keeps the raw policies and the security defaults state as extra results' {
        Mock Invoke-EbrGraphGet {
            if ($Uri -match 'conditionalAccess/policies') { return , @([pscustomobject]@{ id = 'p1'; displayName = 'Block device code'; state = 'enabled'; conditions = [pscustomobject]@{ users = [pscustomobject]@{ includeUsers = @('All'); excludeUsers = @('u1', 'u2') }; applications = [pscustomobject]@{ includeApplications = @('All') }; clientAppTypes = @('all'); authenticationFlows = [pscustomobject]@{ transferMethods = 'deviceCodeFlow' } }; grantControls = [pscustomobject]@{ operator = 'OR'; builtInControls = @('block') } }) }
            if ($Uri -match 'identitySecurityDefaultsEnforcementPolicy') { return [pscustomobject]@{ id = 'x'; isEnabled = $false } }
            throw "unexpected $Uri"
        }
        $ctx = New-GraphCtx
        $r = Invoke-EbrGraphCollector -Ctx $ctx -Item (New-GraphItem 'IA.8')
        $r.Status | Should -Be 'OK'
        $r.Rows[0].ExcludeUsers | Should -Be '2 users'
        $raw = $ctx.Pending | Where-Object ResultId -eq 'IA.8-POLICIES'
        $raw.Status | Should -Be 'OK'
        @($raw.Rows[0].conditions.users.excludeUsers) | Should -Be @('u1', 'u2')
        ($ctx.Pending | Where-Object ResultId -eq 'IA.8-DEFAULTS').Rows[0].SecurityDefaults | Should -BeFalse
    }

    It 'IA.5 counts members by registration state and method family' {
        Mock Invoke-EbrGraphGet { , @(
                [pscustomobject]@{ userType = 'member'; isAdmin = $true; isMfaRegistered = $true; isMfaCapable = $true; isSsprRegistered = $false; isPasswordlessCapable = $true; methodsRegistered = @('microsoftAuthenticatorPush', 'passKeyDeviceBound') },
                [pscustomobject]@{ userType = 'member'; isAdmin = $false; isMfaRegistered = $true; isMfaCapable = $true; isSsprRegistered = $true; isPasswordlessCapable = $false; methodsRegistered = @('mobilePhone') },
                [pscustomobject]@{ userType = 'member'; isAdmin = $false; isMfaRegistered = $false; isMfaCapable = $false; isSsprRegistered = $false; isPasswordlessCapable = $false; methodsRegistered = @() }) }
        $r = Invoke-EbrGraphCollector -Ctx (New-GraphCtx) -Item (New-GraphItem 'IA.5')
        $r.Status | Should -Be 'OK'
        $row = $r.Rows[0]
        $row.Members | Should -Be 3
        $row.MfaRegistered | Should -Be 2
        $row.PhishingResistant | Should -Be 1
        $row.PhoneRegistered | Should -Be 1
        $row.AuthenticatorRegistered | Should -Be 1
        $row.PhoneOnly | Should -Be 1
        $row.Admins | Should -Be 1
        $row.AdminsMfaRegistered | Should -Be 1
        Should -Invoke Invoke-EbrGraphGet -Times 1 -Exactly -ParameterFilter { $Uri -like '*userRegistrationDetails?$filter=userType eq ''member''*' -and $Tenant -eq 'client' }
    }

    It 'IA.5 counts MFA-capable members whose only registered MFA method is a phone, as a count with no user identifiers' {
        Mock Invoke-EbrGraphGet { , @(
                [pscustomobject]@{ userType = 'member'; userPrincipalName = 'a@contoso.com'; id = 'u1'; isMfaCapable = $true; methodsRegistered = @('mobilePhone') },
                [pscustomobject]@{ userType = 'member'; userPrincipalName = 'b@contoso.com'; id = 'u2'; isMfaCapable = $true; methodsRegistered = @('officePhone', 'email', 'securityQuestion') },
                [pscustomobject]@{ userType = 'member'; userPrincipalName = 'c@contoso.com'; id = 'u3'; isMfaCapable = $true; methodsRegistered = @('alternateMobilePhone', 'mobilePhone', 'appPassword') },
                [pscustomobject]@{ userType = 'member'; userPrincipalName = 'd@contoso.com'; id = 'u4'; isMfaCapable = $true; methodsRegistered = @('mobilePhone', 'microsoftAuthenticatorPush') },
                [pscustomobject]@{ userType = 'member'; userPrincipalName = 'e@contoso.com'; id = 'u5'; isMfaCapable = $true; methodsRegistered = @('mobilePhone', 'softwareOneTimePasscode') },
                [pscustomobject]@{ userType = 'member'; userPrincipalName = 'f@contoso.com'; id = 'u6'; isMfaCapable = $true; methodsRegistered = @('mobilePhone', 'passKeyDeviceBound') },
                [pscustomobject]@{ userType = 'member'; userPrincipalName = 'g@contoso.com'; id = 'u7'; isMfaCapable = $false; methodsRegistered = @('email') },
                [pscustomobject]@{ userType = 'member'; userPrincipalName = 'h@contoso.com'; id = 'u8'; isMfaCapable = $false; methodsRegistered = $null },
                # A phone registered for password reset only, with SMS and voice disabled by policy, is not an MFA method.
                [pscustomobject]@{ userType = 'member'; userPrincipalName = 'i@contoso.com'; id = 'u9'; isMfaCapable = $false; methodsRegistered = @('mobilePhone') },
                [pscustomobject]@{ userType = 'member'; userPrincipalName = 'j@contoso.com'; id = 'u10'; methodsRegistered = @('mobilePhone') }) }
        $r = Invoke-EbrGraphCollector -Ctx (New-GraphCtx) -Item (New-GraphItem 'IA.5')
        $r.Status | Should -Be 'OK'
        @($r.Rows).Count | Should -Be 1
        $r.Rows[0].Members | Should -Be 10
        $r.Rows[0].PhoneRegistered | Should -Be 8
        $r.Rows[0].PhoneOnly | Should -Be 3
        $r.Columns | Should -Contain 'PhoneOnly'
        ($r.Rows | ConvertTo-Json -Depth 5) | Should -Not -Match 'contoso|"u\d+"'
    }

    It 'IA.6 separates standing, activated and eligible privileged assignments and ignores other roles' {
        Mock Invoke-EbrGraphGet {
            if ($Uri -match 'roleAssignmentScheduleInstances') {
                return , @(
                    [pscustomobject]@{ roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; principalId = 'u1'; assignmentType = 'Assigned'; endDateTime = $null; directoryScopeId = '/'; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Ann'; userPrincipalName = 'ann@contoso.com' } },
                    [pscustomobject]@{ roleDefinitionId = '194ae4cb-b126-40b2-bd5b-6091b380977d'; principalId = 'u2'; assignmentType = 'Activated'; endDateTime = '2026-10-11T20:00:00Z'; directoryScopeId = '/'; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Bob'; userPrincipalName = 'bob@contoso.com' } },
                    [pscustomobject]@{ roleDefinitionId = '88d8e3e3-8f55-4a1e-953a-9b9898b8876b'; principalId = 'u3'; assignmentType = 'Assigned'; endDateTime = $null; directoryScopeId = '/'; principal = $null })
            }
            if ($Uri -match 'roleEligibilityScheduleInstances') {
                return , @([pscustomobject]@{ roleDefinitionId = '62E90394-69F5-4237-9190-012177145E10'; principalId = 'g1'; directoryScopeId = '/'; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.group'; displayName = 'GA eligible' } })
            }
            throw "unexpected $Uri"
        }
        $r = Invoke-EbrGraphCollector -Ctx (New-GraphCtx) -Item (New-GraphItem 'IA.6')
        $r.Status | Should -Be 'OK'
        @($r.Rows).Count | Should -Be 3
        ($r.Rows | Where-Object AssignmentType -eq 'Standing').PrincipalUpn | Should -Be 'ann@contoso.com'
        ($r.Rows | Where-Object AssignmentType -eq 'Activated').Role | Should -Be 'Security Administrator'
        ($r.Rows | Where-Object AssignmentType -eq 'Eligible').PrincipalType | Should -Be 'group'
        $r.Detail | Should -Match 'break-glass'
    }

    It 'IA.6 falls back to roleAssignments as standing when PIM is not readable' {
        Mock Invoke-EbrGraphGet {
            if ($Uri -match 'ScheduleInstances') { throw 'HTTP 400: Bad Request | AadPremiumLicenseRequired: The tenant needs to have AadPremium license.' }
            if ($Uri -match 'roleAssignments\?') { return , @([pscustomobject]@{ roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; principalId = 'u1'; directoryScopeId = '/'; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Ann'; userPrincipalName = 'ann@contoso.com' } }) }
            throw "unexpected $Uri"
        }
        $r = Invoke-EbrGraphCollector -Ctx (New-GraphCtx) -Item (New-GraphItem 'IA.6')
        $r.Status | Should -Be 'OK'
        @($r.Rows).Count | Should -Be 1
        $r.Rows[0].AssignmentType | Should -Be 'Standing'
        $r.Detail | Should -Match 'PIM schedule instances were not readable'
    }

    It 'IA.6 records the PIM permission as a partial gap when the schedule instances answer 403 but roleAssignments work' {
        Mock Invoke-EbrGraphGet {
            if ($Uri -match 'ScheduleInstances') { throw 'GRAPH-403 https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances: HTTP 403: Forbidden' }
            if ($Uri -match 'roleAssignments\?') { return , @([pscustomobject]@{ roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; principalId = 'u1'; directoryScopeId = '/'; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Ann'; userPrincipalName = 'ann@contoso.com' } }) }
            throw "unexpected $Uri"
        }
        $ctx = New-GraphCtx
        $r = Invoke-EbrGraphCollector -Ctx $ctx -Item (New-GraphItem 'IA.6')
        $r.Status | Should -Be 'OK'
        $r.Detail | Should -Match 'need RoleManagement\.Read\.Directory'
        $r.Rows[0].PimRead | Should -Be 'NoPermission'
        @($ctx.GraphMissingScopes) | Should -Be @('RoleManagement.Read.Directory')
        @($ctx.GraphPartial)[0] | Should -Match '^IA\.6 \(PIM eligibility'
    }

    It 'IA.6 marks PIM as read, or unlicensed, on its rows' {
        Mock Invoke-EbrGraphGet {
            if ($Uri -match 'roleAssignmentScheduleInstances') { return , @([pscustomobject]@{ roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; principalId = 'u1'; assignmentType = 'Assigned'; directoryScopeId = '/'; principal = $null }) }
            if ($Uri -match 'roleEligibilityScheduleInstances') { return , @() }
            throw "unexpected $Uri"
        }
        (Invoke-EbrGraphCollector -Ctx (New-GraphCtx) -Item (New-GraphItem 'IA.6')).Rows[0].PimRead | Should -Be 'Yes'
        Mock Invoke-EbrGraphGet {
            if ($Uri -match 'ScheduleInstances') { throw 'HTTP 400: Bad Request | AadPremiumLicenseRequired' }
            if ($Uri -match 'roleAssignments\?') { return , @([pscustomobject]@{ roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; principalId = 'u1'; directoryScopeId = '/'; principal = $null }) }
            throw "unexpected $Uri"
        }
        $ctx = New-GraphCtx
        (Invoke-EbrGraphCollector -Ctx $ctx -Item (New-GraphItem 'IA.6')).Rows[0].PimRead | Should -Be 'NoLicense'
        @($ctx.GraphMissingScopes).Count | Should -Be 0
    }

    It 'IA.13 classifies user consent from the self-consent policies only' {
        $cases = @(
            @{ Policies = @(); Expect = 'None' }
            @{ Policies = @('ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team'); Expect = 'None' }
            @{ Policies = @('ManagePermissionGrantsForSelf.microsoft-user-default-recommended', 'ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-chat'); Expect = 'Low risk, verified publishers' }
            @{ Policies = @('ManagePermissionGrantsForSelf.microsoft-user-default-low'); Expect = 'Low risk, verified publishers' }
            @{ Policies = @('ManagePermissionGrantsForSelf.microsoft-user-default-legacy'); Expect = 'Any application' }
            @{ Policies = @('ManagePermissionGrantsForSelf.microsoft-user-default-recommended', 'ManagePermissionGrantsForSelf.microsoft-user-default-allow-consent-apps'); Expect = 'Custom' }
        )
        foreach ($case in $cases) {
            $policies = $case.Policies
            Mock Invoke-EbrGraphGet {
                if ($Uri -match 'authorizationPolicy') { return [pscustomobject]@{ defaultUserRolePermissions = [pscustomobject]@{ permissionGrantPoliciesAssigned = $policies } } }
                [pscustomobject]@{ isEnabled = $true }
            }
            (Invoke-EbrGraphCollector -Ctx (New-GraphCtx) -Item (New-GraphItem 'IA.13')).Rows[0].UserConsent | Should -Be $case.Expect -Because ($case.Policies -join ',')
        }
    }

    It 'IA.13 leaves Governed unknown and records the scope when the admin consent workflow cannot be read' {
        Mock Invoke-EbrGraphGet {
            if ($Uri -match 'authorizationPolicy') { return [pscustomobject]@{ allowUserConsentForRiskyApps = $false; defaultUserRolePermissions = [pscustomobject]@{ permissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-low') } } }
            if ($Uri -match 'adminConsentRequestPolicy') { throw 'GRAPH-403 https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy: HTTP 403: Forbidden' }
            throw "unexpected $Uri"
        }
        $ctx = New-GraphCtx
        $r = Invoke-EbrGraphCollector -Ctx $ctx -Item (New-GraphItem 'IA.13')
        $r.Status | Should -Be 'OK'
        $r.Rows[0].UserConsent | Should -Be 'Low risk, verified publishers'
        $null -eq $r.Rows[0].Governed | Should -BeTrue
        $r.Detail | Should -Match 'Governed is unknown rather than false'
        @($ctx.GraphMissingScopes) | Should -Be @('Policy.Read.All')
    }

    It 'IA.8 shapes policies, marks the Atmosera baseline and caches the list for IA.11' {
        $script:caCalls = 0
        Mock Invoke-EbrGraphGet {
            if ($Uri -match 'conditionalAccess/policies') {
                $script:caCalls++
                return , @(
                    [pscustomobject]@{ displayName = 'ATMO-MXDR-CA-MFA-ALLUSERS'; state = 'enabled'; modifiedDateTime = '2026-09-01T00:00:00Z'; conditions = [pscustomobject]@{ users = [pscustomobject]@{ includeUsers = @('All'); excludeUsers = @('a', 'b'); includeGroups = @(); excludeGroups = @('g') }; applications = [pscustomobject]@{ includeApplications = @('All') }; clientAppTypes = @('all'); signInRiskLevels = @(); userRiskLevels = @() }; grantControls = [pscustomobject]@{ operator = 'OR'; builtInControls = @(); authenticationStrength = [pscustomobject]@{ displayName = 'Multifactor authentication' } } },
                    [pscustomobject]@{ displayName = 'Risk: sign-in'; state = 'enabled'; conditions = [pscustomobject]@{ users = [pscustomobject]@{ includeUsers = @('All') }; applications = [pscustomobject]@{ includeApplications = @('MicrosoftAdminPortals') }; signInRiskLevels = @('high', 'medium'); userRiskLevels = @() }; grantControls = [pscustomobject]@{ builtInControls = @('mfa') } },
                    [pscustomobject]@{ displayName = 'Risk: user'; state = 'enabledForReportingButNotEnforced'; conditions = [pscustomobject]@{ users = [pscustomobject]@{ includeUsers = @('All') }; applications = [pscustomobject]@{ includeApplications = @('All') }; userRiskLevels = @('high') }; grantControls = [pscustomobject]@{ builtInControls = @('passwordChange') } },
                    [pscustomobject]@{ displayName = 'Block device code'; state = 'enabled'; conditions = [pscustomobject]@{ users = [pscustomobject]@{ includeUsers = @('All') }; applications = [pscustomobject]@{ includeApplications = @('All') }; authenticationFlows = [pscustomobject]@{ transferMethods = 'deviceCodeFlow' } }; grantControls = [pscustomobject]@{ builtInControls = @('block') } })
            }
            if ($Uri -match 'onPremisesSynchronization') { return , @([pscustomobject]@{ features = [pscustomobject]@{ passwordSyncEnabled = $true } }) }
            throw "unexpected $Uri"
        }
        $ctx = New-GraphCtx
        $ia8 = Invoke-EbrGraphCollector -Ctx $ctx -Item (New-GraphItem 'IA.8')
        $ia8.Status | Should -Be 'OK'
        @($ia8.Rows).Count | Should -Be 4
        $base = $ia8.Rows | Where-Object Policy -eq 'ATMO-MXDR-CA-MFA-ALLUSERS'
        $base.Baseline | Should -BeTrue
        $base.IncludeUsers | Should -Be 'All'
        $base.ExcludeUsers | Should -Be '2 users, 1 group'
        $base.AuthStrength | Should -Be 'Multifactor authentication'
        ($ia8.Rows | Where-Object Policy -eq 'Risk: sign-in').IncludeApplications | Should -Be 'Microsoft Admin Portals'
        ($ia8.Rows | Where-Object Policy -eq 'Block device code').AuthenticationFlows | Should -Be 'deviceCodeFlow'
        $ia11 = Invoke-EbrGraphCollector -Ctx $ctx -Item (New-GraphItem 'IA.11')
        $ia11.Rows[0].SignInRiskAllUsers | Should -BeTrue
        $ia11.Rows[0].UserRiskAllUsers | Should -BeFalse
        $ia11.Rows[0].InForce | Should -BeFalse
        $ia11.Rows[0].PasswordHashSync | Should -Be 'On'
        $script:caCalls | Should -Be 1
    }

    It 'IA.13 reads consent governance from the authorization and admin consent policies' {
        Mock Invoke-EbrGraphGet {
            if ($Uri -match 'authorizationPolicy') { return [pscustomobject]@{ allowUserConsentForRiskyApps = $false; defaultUserRolePermissions = [pscustomobject]@{ permissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-low') } } }
            if ($Uri -match 'adminConsentRequestPolicy') { return [pscustomobject]@{ isEnabled = $true } }
            throw "unexpected $Uri"
        }
        $r = Invoke-EbrGraphCollector -Ctx (New-GraphCtx) -Item (New-GraphItem 'IA.13')
        $r.Rows[0].UserConsent | Should -Be 'Low risk, verified publishers'
        $r.Rows[0].AdminConsentWorkflow | Should -BeTrue
        $r.Rows[0].Governed | Should -BeTrue
    }

    It 'POS.6 reads the latest snapshot, category points and the trend, and writes the two detail results' {
        Mock Invoke-EbrGraphGet {
            if ($Uri -match 'secureScores\?') {
                return , @(
                    [pscustomobject]@{ createdDateTime = '2026-10-10T00:00:00Z'; currentScore = 300; maxScore = 1000; averageComparativeScores = @([pscustomobject]@{ basis = 'AllTenants'; averageScore = 250 }); controlScores = @([pscustomobject]@{ controlCategory = 'Identity'; controlName = 'MFA'; score = 10 }, [pscustomobject]@{ controlCategory = 'Device'; controlName = 'AV'; score = 5 }, [pscustomobject]@{ controlCategory = 'Identity'; controlName = 'Ghost'; score = 1 }) },
                    [pscustomobject]@{ createdDateTime = '2026-10-09T00:00:00Z'; currentScore = 290; maxScore = 1000; controlScores = @() })
            }
            if ($Uri -match 'secureScoreControlProfiles') { return , @([pscustomobject]@{ id = 'MFA'; maxScore = 20; controlCategory = 'Identity' }, [pscustomobject]@{ id = 'AV'; maxScore = 10; controlCategory = 'Device' }) }
            throw "unexpected $Uri"
        }
        $ctx = New-GraphCtx
        $r = Invoke-EbrGraphCollector -Ctx $ctx -Item (New-GraphItem 'POS.6')
        $r.Status | Should -Be 'OK'
        $r.Rows[0].ReadDate | Should -Be '2026-10-10'
        $r.Rows[0].Current | Should -Be 300
        $r.Rows[0].Percent | Should -Be 30
        $r.Rows[0].IdentityPct | Should -Be 50
        $r.Rows[0].DevicePct | Should -Be 50
        $r.Rows[0].AllTenantsAverage | Should -Be 250
        $r.Rows[0].Snapshots | Should -Be 2
        @($ctx.Pending | ForEach-Object ResultId) | Should -Be @('POS.6-TREND', 'POS.6-CATEGORIES')
        $trend = @(($ctx.Pending | Where-Object ResultId -eq 'POS.6-TREND').Rows)
        $trend[0].Date | Should -Be '2026-10-09'
        $trend[1].Percent | Should -Be 30
        $cats = @(($ctx.Pending | Where-Object ResultId -eq 'POS.6-CATEGORIES').Rows)
        ($cats | Where-Object Category -eq 'Identity').Available | Should -Be 20
    }

    It 'IA.1-FEDERATION reads each federated domain, names the provider and marks inherited subdomains' {
        Mock Invoke-EbrGraphGet {
            if ($Uri -match '/domains\?\$select=id,authenticationType,isRoot,isVerified$') {
                return , @(
                    [pscustomobject]@{ id = 'eu.contoso.test'; authenticationType = 'Federated'; isRoot = $false; isVerified = $true },
                    [pscustomobject]@{ id = 'contoso.test'; authenticationType = 'Federated'; isRoot = $true; isVerified = $true },
                    [pscustomobject]@{ id = 'contoso.onmicrosoft.com'; authenticationType = 'Managed'; isRoot = $true; isVerified = $true },
                    [pscustomobject]@{ id = 'fabrikam.test'; authenticationType = 'Federated'; isRoot = $true; isVerified = $true })
            }
            if ($Uri -match '/domains/contoso\.test/federationConfiguration$') {
                return , @([pscustomobject]@{ issuerUri = 'contoso.test:exk0EXAMPLE00000000'; passiveSignInUri = 'https://sso.contoso.test/app/office365/exk0EXAMPLE00000000/sso/wsfed/passive'; activeSignInUri = 'https://sso.contoso.test/app/office365/exk0EXAMPLE00000000/sso/wsfed/active'; preferredAuthenticationProtocol = 'wsFed'; federatedIdpMfaBehavior = 'enforceMfaByFederatedIdp' })
            }
            if ($Uri -match '/domains/(eu\.contoso\.test|fabrikam\.test)/federationConfiguration$') { throw 'HTTP 404: Not Found | Resource ''federationConfiguration'' does not exist or one of its queried reference-property objects are not present.' }
            throw "unexpected $Uri"
        }
        $r = Invoke-EbrGraphCollector -Ctx (New-GraphCtx) -Item (New-GraphItem 'IA.1-FEDERATION')
        $r.Status | Should -Be 'OK'
        @($r.Rows).Count | Should -Be 3
        $root = $r.Rows | Where-Object Domain -eq 'contoso.test'
        $root.IdentityProvider | Should -Be 'Okta'
        $root.IssuerUri | Should -Be 'contoso.test:exk0EXAMPLE00000000'
        $root.PassiveSignInUri | Should -Match '/sso/wsfed/passive$'
        $root.ActiveSignInUri | Should -Match '/sso/wsfed/active$'
        $root.PreferredAuthenticationProtocol | Should -Be 'wsFed'
        $root.FederatedIdpMfaBehavior | Should -Be 'enforceMfaByFederatedIdp'
        $root.ConfigSource | Should -Be 'Read'
        ($r.Rows | Where-Object Domain -eq 'eu.contoso.test').ConfigSource | Should -Be 'Inherited from contoso.test'
        ($r.Rows | Where-Object Domain -eq 'fabrikam.test').ConfigSource | Should -Be 'Not returned (404)'
        $r.Rows.Domain | Should -Not -Contain 'contoso.onmicrosoft.com'
        $r.Detail | Should -Match '^Read 4 domains, 3 federated\.'
        Should -Invoke Invoke-EbrGraphGet -Times 0 -ParameterFilter { $Uri -match 'onmicrosoft' }
    }

    It 'IA.1-FEDERATION is EMPTY for a managed tenant, UNAVAILABLE naming Domain.Read.All on a 403, and records other errors per domain' {
        Mock Invoke-EbrGraphGet { , @([pscustomobject]@{ id = 'contoso.com'; authenticationType = 'Managed'; isRoot = $true }) }
        $r = Invoke-EbrGraphCollector -Ctx (New-GraphCtx) -Item (New-GraphItem 'IA.1-FEDERATION')
        $r.Status | Should -Be 'EMPTY'
        $r.Detail | Should -Match '^Read 1 domain, 0 federated\.'
        Mock Invoke-EbrGraphGet { throw 'GRAPH-403 https://graph.microsoft.com/v1.0/domains: HTTP 403: Forbidden | Authorization_RequestDenied' }
        $ctx = New-GraphCtx
        $r = Invoke-EbrGraphCollector -Ctx $ctx -Item (New-GraphItem 'IA.1-FEDERATION')
        $r.Status | Should -Be 'UNAVAILABLE'
        $r.Detail | Should -Match 'Needs Domain\.Read\.All'
        @($ctx.GraphMissingScopes) | Should -Be @('Domain.Read.All')
        Mock Invoke-EbrGraphGet {
            if ($Uri -match '/domains\?') { return , @([pscustomobject]@{ id = 'corp.com'; authenticationType = 'Federated'; isRoot = $true }) }
            throw 'HTTP 500: Internal Server Error | boom'
        }
        $r = Invoke-EbrGraphCollector -Ctx (New-GraphCtx) -Item (New-GraphItem 'IA.1-FEDERATION')
        $r.Status | Should -Be 'OK'
        $r.Rows[0].ConfigSource | Should -Match '^Could not be read: HTTP 500'
        $r.Rows[0].IdentityProvider | Should -Be ''
        $r.Detail | Should -Match '1 federation configuration could not be read'
    }

    It 'names the federation provider from its URIs' {
        Get-EbrFederationProvider @('http://www.okta.com/exk1a2b3c4d5e6f7g8h9') | Should -Be 'Okta'
        Get-EbrFederationProvider @('', 'https://sso.corp.com/app/office365/abc123/sso/wsfed/passive') | Should -Be 'Okta'
        Get-EbrFederationProvider @('http://sts.corp.com/adfs/services/trust', 'https://sts.corp.com/adfs/ls/') | Should -Be 'AD FS'
        Get-EbrFederationProvider @('https://sso.corp.com/idp/prp.wsf') | Should -Be 'Ping'
        Get-EbrFederationProvider @('urn:corp:idp') | Should -Be 'Other'
        Get-EbrFederationProvider @('', $null) | Should -Be 'Unknown'
    }

    It 'DP.8 reads the tenant sharing settings' {
        Mock Invoke-EbrGraphGet { [pscustomobject]@{ sharingCapability = 'externalUserSharingOnly'; sharingDomainRestrictionMode = 'allowList'; sharingAllowedDomainList = @('partner.com'); isResharingByExternalUsersEnabled = $false } }
        $r = Invoke-EbrGraphCollector -Ctx (New-GraphCtx) -Item (New-GraphItem 'DP.8')
        $r.Rows[0].SharingCapability | Should -Be 'externalUserSharingOnly'
        $r.Rows[0].AllowedDomains | Should -Be 'partner.com'
        $r.Rows[0].ResharingByExternalUsers | Should -BeFalse
    }

    It 'DR.11 lists sensors and returns EMPTY when there are none' {
        Mock Invoke-EbrGraphGet { , @([pscustomobject]@{ displayName = 'DC01'; sensorType = 'adSensor'; healthStatus = 'healthy'; deploymentStatus = 'upToDate'; version = '2.250'; domainName = 'corp.local'; openHealthIssuesCount = 0 }) }
        $r = Invoke-EbrGraphCollector -Ctx (New-GraphCtx) -Item (New-GraphItem 'DR.11')
        $r.Status | Should -Be 'OK'
        $r.Rows[0].Sensor | Should -Be 'DC01'
        Mock Invoke-EbrGraphGet { , @() }
        (Invoke-EbrGraphCollector -Ctx (New-GraphCtx) -Item (New-GraphItem 'DR.11')).Status | Should -Be 'EMPTY'
    }

    It 'DP.10 aggregates managed devices by platform and ownership, and EW.13 reads the cache' {
        Mock Invoke-EbrGraphGet {
            if ($Uri -match 'managedDevices') {
                return , @(
                    [pscustomobject]@{ operatingSystem = 'Windows'; isEncrypted = $true; managedDeviceOwnerType = 'company'; complianceState = 'compliant' },
                    [pscustomobject]@{ operatingSystem = 'Windows'; isEncrypted = $false; managedDeviceOwnerType = 'company'; complianceState = 'noncompliant' },
                    [pscustomobject]@{ operatingSystem = 'macOS'; isEncrypted = $true; managedDeviceOwnerType = 'personal'; complianceState = 'compliant' })
            }
            if ($Uri -match 'configurationPolicies') { return , @([pscustomobject]@{ name = 'App Control base'; platforms = 'windows10'; technologies = 'mdm'; isAssigned = $true; settingCount = 3; lastModifiedDateTime = '2026-08-01T00:00:00Z'; templateReference = [pscustomobject]@{ templateFamily = 'endpointSecurityApplicationControl' } }) }
            throw "unexpected $Uri"
        }
        $ctx = New-GraphCtx
        $dp10 = Invoke-EbrGraphCollector -Ctx $ctx -Item (New-GraphItem 'DP.10')
        $win = $dp10.Rows | Where-Object { $_.OperatingSystem -eq 'Windows' -and $_.Ownership -eq 'company' }
        $win.Devices | Should -Be 2
        $win.Encrypted | Should -Be 1
        $win.Compliant | Should -Be 1
        $ew13 = Invoke-EbrGraphCollector -Ctx $ctx -Item (New-GraphItem 'EW.13')
        $ew13.Rows[0].Assigned | Should -BeTrue
        $ew13.Detail | Should -Match 'Corporate-owned Windows devices in Intune: 2'
        Should -Invoke Invoke-EbrGraphGet -Times 1 -Exactly -ParameterFilter { $Uri -like 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$filter=templateReference/templateFamily eq ''endpointSecurityApplicationControl''*' }
    }

    It 'EW.13 reads every policy and filters by template family when the filter is rejected' {
        Mock Invoke-EbrGraphGet {
            if ($Uri -match 'configurationPolicies\?\$filter') { throw 'HTTP 400: Bad Request | Invalid filter clause' }
            if ($Uri -match 'configurationPolicies\?\$select') {
                return , @(
                    [pscustomobject]@{ name = 'AV baseline'; isAssigned = $true; templateReference = [pscustomobject]@{ templateFamily = 'endpointSecurityAntivirus' } },
                    [pscustomobject]@{ name = 'App Control base'; isAssigned = $false; templateReference = [pscustomobject]@{ templateFamily = 'endpointSecurityApplicationControl' } })
            }
            throw "unexpected $Uri"
        }
        $r = Invoke-EbrGraphCollector -Ctx (New-GraphCtx) -Item (New-GraphItem 'EW.13')
        @($r.Rows).Count | Should -Be 1
        $r.Rows[0].Policy | Should -Be 'App Control base'
        $r.Rows[0].Assigned | Should -BeFalse
    }

    It 'maps a 403 to UNAVAILABLE with the permission, the fix, the portal path and records the scope once' {
        Mock Invoke-EbrGraphGet { throw 'GRAPH-403 https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies: HTTP 403: Forbidden | Authorization_RequestDenied' }
        $ctx = New-GraphCtx
        $r = Invoke-EbrGraphCollector -Ctx $ctx -Item (New-GraphItem 'IA.8')
        $r.Status | Should -Be 'UNAVAILABLE'
        $r.Detail | Should -Match 'Needs Policy\.Read\.All'
        $r.Detail | Should -Match 'az login --tenant client --scope https://graph\.microsoft\.com/Policy\.Read\.All'
        $r.Detail | Should -Match 'Portal fallback: somewhere'
        $null = Invoke-EbrGraphCollector -Ctx $ctx -Item (New-GraphItem 'IA.13')
        @($ctx.GraphMissingScopes) | Should -Be @('Policy.Read.All')
    }

    It 'reports other errors as FAILED with the message' {
        Mock Invoke-EbrGraphGet { throw 'HTTP 500: Internal Server Error | boom' }
        $r = Invoke-EbrGraphCollector -Ctx (New-GraphCtx) -Item (New-GraphItem 'DR.11')
        $r.Status | Should -Be 'FAILED'
        $r.Detail | Should -Match 'HTTP 500'
    }

    It 'marks a Graph item UNAVAILABLE with the reason and the portal path when Graph is unreachable, and still writes its endpoint file' {
        $ctx = New-GraphCtx
        $ctx.GraphAvailable = $false
        $ctx.GraphReason = 'No Graph token: AADSTS530004: blocked.'
        $r = Invoke-EbrCatalogItem -Ctx $ctx -Item (New-GraphItem 'IA.5')
        $r.Status | Should -Be 'UNAVAILABLE'
        $r.Detail | Should -Match 'AADSTS530004'
        $r.Detail | Should -Match 'Portal fallback: somewhere'
        Test-Path (Join-Path $TestDrive 'queries/IA.5.graph.txt') | Should -BeTrue
    }
}

Describe 'Multiple workspaces' {
    BeforeAll {
        $wsA = [pscustomobject]@{ WorkspaceName = 'ws-a'; CustomerId = 'aaaa'; subscriptionId = 'sub-a'; AccessTenant = 't1' }
        $wsB = [pscustomobject]@{ WorkspaceName = 'ws-b'; CustomerId = 'bbbb'; subscriptionId = 'sub-b'; AccessTenant = 't1' }
        $reach = @(
            [pscustomobject]@{ Workspace = 'ws-a'; WorkspaceId = 'aaaa'; SubscriptionId = 'sub-a'; SourceTable = 'SigninLogs'; Records = 10; EarliestRecord = '2026-03-04T10:00:00Z' }
            [pscustomobject]@{ Workspace = 'ws-b'; WorkspaceId = 'bbbb'; SubscriptionId = 'sub-b'; SourceTable = 'SigninLogs'; Records = 900; EarliestRecord = '2026-01-02T00:00:00Z' }
            [pscustomobject]@{ Workspace = 'ws-a'; WorkspaceId = 'aaaa'; SubscriptionId = 'sub-a'; SourceTable = 'SecurityIncident'; Records = 50; EarliestRecord = '2026-02-10T08:00:00Z' }
            [pscustomobject]@{ Workspace = 'ws-b'; WorkspaceId = 'bbbb'; SubscriptionId = 'sub-b'; SourceTable = 'SecurityIncident'; Records = 5; EarliestRecord = '2026-05-20T08:00:00Z' }
        )
    }

    It 'prepends workspace and subscription columns to per-workspace rows' {
        $rows = Add-EbrWorkspaceColumns -Rows @([pscustomobject]@{ Alerts = 3 }) -Workspace $wsA
        ($rows[0].PSObject.Properties.Name -join ',') | Should -Be 'Workspace,WorkspaceId,SubscriptionId,Alerts'
        $rows[0].Workspace | Should -Be 'ws-a'
    }

    It 'reads a tenant-wide table from the workspace holding the most of it' {
        (Select-EbrTenantWorkspace -Workspaces @($wsA, $wsB) -ReachRows $reach -Table 'SigninLogs').WorkspaceName | Should -Be 'ws-b'
    }

    It 'falls back to the first workspace when no workspace has the table' {
        (Select-EbrTenantWorkspace -Workspaces @($wsA, $wsB) -ReachRows $reach -Table 'AuditLogs').WorkspaceName | Should -Be 'ws-a'
    }

    It 'takes the earliest SecurityIncident record across workspaces and lists each one' {
        $e = Get-EbrEarliestIncident -ReachRows $reach
        $e.Earliest | Should -Be ([datetime]::new(2026, 2, 10, 8, 0, 0))
        $e.PerWorkspace | Should -Be @('ws-a 2026-02-10', 'ws-b 2026-05-20')
        $e.EarliestWorkspaceId | Should -Be 'aaaa'
    }

    It 'builds a combined Log Analytics body with the extra workspaces' {
        $b = New-EbrLaBody -Query 'x' -AdditionalWorkspaceIds @('bbbb', 'cccc')
        $b.query | Should -Be 'x'
        $b.workspaces | Should -Be @('bbbb', 'cccc')
        (New-EbrLaBody -Query 'x').ContainsKey('workspaces') | Should -BeFalse
    }

    It 'treats a missing table as no data rather than a failure' {
        Test-EbrMissingTableError "HTTP 400: Bad request | Failed to resolve table or column expression named 'SecureScores'" | Should -BeTrue
        Test-EbrMissingTableError 'HTTP 403: Forbidden' | Should -BeFalse
    }

    It 'summarizes Sentinel rules across and within workspaces' {
        $rules = @(
            [pscustomobject]@{ Workspace = 'ws-a'; Kind = 'Scheduled'; Enabled = $true; LastModifiedUtc = '2026-03-01T00:00:00Z' }
            [pscustomobject]@{ Workspace = 'ws-a'; Kind = 'Fusion'; Enabled = $true; LastModifiedUtc = '' }
            [pscustomobject]@{ Workspace = 'ws-b'; Kind = 'Scheduled'; Enabled = $false; LastModifiedUtc = '2025-12-01T00:00:00Z' }
        )
        $s = Get-EbrRuleSummary -Rules $rules -WindowStart ([datetime]'2026-01-01')
        ($s | Where-Object { $_.Scope -eq 'All workspaces' -and $_.Metric -eq 'Total rules' }).Value | Should -Be 3
        ($s | Where-Object { $_.Scope -eq 'All workspaces' -and $_.Metric -eq 'Enabled rules' }).Value | Should -Be 2
        ($s | Where-Object { $_.Scope -eq 'All workspaces' -and $_.Metric -like 'Rules modified since*' }).Value | Should -Be 1
        ($s | Where-Object { $_.Scope -eq 'ws-b' -and $_.Metric -eq 'Total rules' }).Value | Should -Be 1
        ($s | Where-Object { $_.Scope -eq 'All workspaces' -and $_.Metric -eq 'Kind: Scheduled' }).Value | Should -Be 2
    }
}

Describe 'Get-EbrWorksheet' {
    BeforeAll {
        function New-Result([string]$Id, [object[]]$Rows) {
            [pscustomobject]@{ ResultId = $Id; Status = 'OK'; Rows = $Rows; ReadTimeUtc = [datetime]'2026-10-07T12:00:00Z' }
        }
        $r = @{}
        $r['P0.5'] = New-Result 'P0.5' @([pscustomobject]@{ Resources = 10 }, [pscustomobject]@{ Resources = 5 })
        $r['OUT.5'] = New-Result 'OUT.5' @([pscustomobject]@{ Alerts = 100 }, [pscustomobject]@{ Alerts = 20 })
        $r['OUT.2'] = New-Result 'OUT.2' @(
            [pscustomobject]@{ Scope = 'All'; Incidents = 50; AutoClosed = 5; MedianCloseMin = 42.5; P90CloseMin = 400 },
            [pscustomobject]@{ Scope = 'High'; Incidents = 4; AutoClosed = 0; MedianCloseMin = 60; P90CloseMin = 300 })
        $r['OUT.1'] = New-Result 'OUT.1' @([pscustomobject]@{ Raised = 60; Closed = 56; Open = 4 })
        $r['IA.1'] = New-Result 'IA.1' @(
            [pscustomobject]@{ UserType = 'Member'; UsersSignedIn = 100; UsersChallenged = 93; UsersAlwaysMfa = 80; UsersExternalMfa = 40; UsersEntraMfa = 60 },
            [pscustomobject]@{ UserType = 'Guest'; UsersSignedIn = 10; UsersChallenged = 5; UsersAlwaysMfa = 5 })
        $r['IA.2'] = New-Result 'IA.2' @(
            [pscustomobject]@{ Bucket = 'Retiring: SMS or voice'; DistinctUsers = 35 },
            [pscustomobject]@{ Bucket = 'Phishing-resistant'; DistinctUsers = 7 })
        $r['NB.1'] = New-Result 'NB.1' @(
            [pscustomobject]@{ SubnetClass = 'Workload'; Segmented = $true },
            [pscustomobject]@{ SubnetClass = 'Workload'; Segmented = $true },
            [pscustomobject]@{ SubnetClass = 'Workload'; Segmented = $false },
            [pscustomobject]@{ SubnetClass = 'Platform'; Segmented = $false })
        $r['DFC.1'] = New-Result 'DFC.1' @(
            [pscustomobject]@{ Recommendation = 'Virtual machines and virtual machine scale sets should have encryption at host enabled'; Healthy = 49; Unhealthy = 3 },
            [pscustomobject]@{ Recommendation = 'EDR solution should be installed on Virtual Machines'; Healthy = 10; Unhealthy = 0 })
        $r['BKL.2'] = New-Result 'BKL.2' @([pscustomobject]@{ Severity = 'High'; OpenAlerts = 2 }, [pscustomobject]@{ Severity = 'Low'; OpenAlerts = 3 })
        $r['POS.1'] = New-Result 'POS.1' @([pscustomobject]@{ Current = 30.5; Max = 50; Subscriptions = 1; Percent = 61 })
        $r['DR.2'] = New-Result 'DR.2' @(
            [pscustomobject]@{ Plan = 'VirtualMachines'; Resources = 20; Covered = 20 },
            [pscustomobject]@{ Plan = 'AI'; Resources = 3; Covered = 1 })
        $r['EW.1'] = New-Result 'EW.1' @(
            [pscustomobject]@{ Scope = 'Azure VM'; Onboarded = 18; CanBeOnboarded = 2; SensorActive = 18 },
            [pscustomobject]@{ Scope = 'Other device'; Onboarded = 80; CanBeOnboarded = 0; SensorActive = 79 })
        $r['IA.5'] = [pscustomobject]@{ ResultId = 'IA.5'; Status = 'MANUAL'; Rows = @(); ReadTimeUtc = $null }
        $r['IA.6-SUB'] = New-Result 'IA.6-SUB' @(
            [pscustomobject]@{ AccountObjectId = 'a1'; Role = 'Global Administrator' },
            [pscustomobject]@{ AccountObjectId = 'a1'; Role = 'Security Administrator' },
            [pscustomobject]@{ AccountObjectId = 'a2'; Role = 'Global Administrator' })
        $r['DP.7'] = [pscustomobject]@{ ResultId = 'DP.7'; Status = 'UNAVAILABLE'; Rows = @(); ReadTimeUtc = [datetime]'2026-10-07T12:00:00Z' }

        $ws = Get-EbrWorksheet -Results $r -WindowStart ([datetime]'2026-01-01') -WindowEnd ([datetime]'2026-07-31')
        function Get-Row([string]$Figure) { $ws | Where-Object Figure -eq $Figure | Select-Object -First 1 }
    }

    It 'carries every row of the runbook slide map' {
        $ws.Count | Should -Be 48
    }

    It 'sums the estate inventory' { (Get-Row 'Azure resources in the estate').Value | Should -Be '15' }
    It 'sums alerts triaged' { (Get-Row 'Alerts triaged').Value | Should -Be '120' }
    It 'reads the All median' { (Get-Row 'Median time to close').Value | Should -Match '^42\.5 min' }
    It 'reads the High P90' { (Get-Row '90th percentile close, high severity').Value | Should -Match '^300 min' }

    It 'quotes MFA for members, with guests and the all-user figure in the note' {
        $row = Get-Row 'Users challenged for MFA, x of y'
        $row.Value | Should -Be '93 of 100 (93%)'
        $row.Note | Should -Match 'Guest: 5 of 10 \(50%\)'
        $row.Note | Should -Match 'All user types: 98 of 110 \(89\.1%\)'
        $row.Note | Should -Match 'MFA is recognised from the requirement field'
        (Get-Row 'MFA required at sign-in').Value | Should -Be '93 of 100 (93%)'
    }

    It 'adds the not evaluated members to the MFA note for packs from collector 1.12.0' {
        $r2 = @{}
        foreach ($k in $r.Keys) { $r2[$k] = $r[$k] }
        $r2['IA.1'] = New-Result 'IA.1' @([pscustomobject]@{ UserType = 'Member'; UsersSignedIn = 1414; UsersChallenged = 563; UsersAlwaysMfa = 1; UsersExternalMfa = 563; FederatedWithoutMfa = 2; NoMfaOnlyUnevaluated = 550; MfaSessionLinkedOnly = 31 })
        $ws2 = Get-EbrWorksheet -Results $r2 -WindowStart ([datetime]'2026-01-01') -WindowEnd ([datetime]'2026-07-31')
        $row = $ws2 | Where-Object Figure -eq 'Users challenged for MFA, x of y' | Select-Object -First 1
        $row.Value | Should -Be '563 of 1414 (39.8%)'
        $row.Note | Should -Match 'reused a session no policy checked \(not evaluated, not missing MFA\): 550\.'
        $row.Note | Should -Match 'carried no MFA assertion: 2\.'
        $row.Note | Should -Match 'IA.1-FEDERATION'
        $row.Note | Should -Match 'only MFA evidence is that inference: 31\.'
    }

    It 'labels privileged roles as assignments and accounts' {
        (Get-Row 'Standing privileged roles').Value | Should -Be '3 role assignments across 2 accounts'
    }

    It 'never turns an unavailable source into a zero' {
        (Get-Row 'Malicious mail removed after delivery').Value | Should -BeNullOrEmpty
        (Get-Row 'Malicious mail removed after delivery').Note | Should -Match '^No figure, not a zero: DP\.7 had no data source'
    }

    It 'grades workload subnets only' {
        (Get-Row 'Workload subnets segmented, x of y').Value | Should -Be '2 of 3 (66.7%)'
    }

    It 'reads encryption at host from DFC.1' {
        (Get-Row 'Encryption at host, x of y').Value | Should -Be '49 of 52 (94.2%)'
        (Get-Row 'VMs pending host encryption').Value | Should -Be '3'
    }

    It 'reads the retiring MFA bucket' { (Get-Row 'Users on a retiring MFA method').Value | Should -Be '35' }

    It 'adds Defender for Cloud alerts and open incidents' {
        (Get-Row 'Open security alerts').Value | Should -Match '^9 '
    }

    It 'reads the AI workload protection gap' {
        (Get-Row 'AI service resources without workload protection').Value | Should -Be '2'
    }

    It 'computes EDR onboarding' {
        (Get-Row 'Devices onboarded to EDR').Value | Should -Match '^98 of 100 \(98(\.0)?%\)'
    }

    It 'stamps the read date from the source query' {
        (Get-Row 'Alerts triaged').ReadDate | Should -Be '2026-10-07'
    }

    It 'points to the CSV when a source query is missing' {
        $row = Get-Row 'Exploitable OS findings open'
        $row.Value | Should -BeNullOrEmpty
        $row.Note | Should -Match 'BKL\.1'
    }

    It 'uses a PARTIAL result but says so' {
        $p = $r.Clone()
        $p['OUT.5'] = [pscustomobject]@{ ResultId = 'OUT.5'; Status = 'PARTIAL'; Rows = @([pscustomobject]@{ Alerts = 7 }); ReadTimeUtc = [datetime]'2026-10-07T12:00:00Z' }
        $row = Get-EbrWorksheet -Results $p -WindowStart ([datetime]'2026-01-01') -WindowEnd ([datetime]'2026-07-31') | Where-Object Figure -eq 'Alerts triaged'
        $row.Value | Should -Be '7'
        $row.Note | Should -Match 'PARTIAL'
    }

    It 'flags manual rows' {
        (Get-Row 'Users registered for Authenticator').Value | Should -Be 'MANUAL'
        (Get-Row 'Users registered for Authenticator').Note | Should -Match '^Entra admin center'
        (Get-Row 'Microsoft tenant Secure Score').Value | Should -Be 'MANUAL'
        (Get-Row 'Tenant score trend, 90 days').Value | Should -Be 'MANUAL'
    }
}

Describe 'Get-EbrWorksheet with Graph results' {
    BeforeAll {
        function New-GResult([string]$Id, [object[]]$Rows, [string]$Status = 'OK') {
            [pscustomobject]@{ ResultId = $Id; Status = $Status; Rows = $Rows; ReadTimeUtc = [datetime]'2026-10-11T12:00:00Z' }
        }
        $r = @{}
        $r['IA.2'] = New-GResult 'IA.2' @([pscustomobject]@{ Bucket = 'Phishing-resistant'; DistinctUsers = 7 })
        $r['IA.5'] = New-GResult 'IA.5' @([pscustomobject]@{ Members = 200; MfaRegistered = 180; PhishingResistant = 25; PhoneRegistered = 90; AuthenticatorRegistered = 150 })
        $r['IA.6'] = New-GResult 'IA.6' @(
            [pscustomobject]@{ AssignmentType = 'Standing'; PrincipalId = 'a1'; Role = 'Global Administrator' },
            [pscustomobject]@{ AssignmentType = 'Standing'; PrincipalId = 'a1'; Role = 'Security Administrator' },
            [pscustomobject]@{ AssignmentType = 'Eligible'; PrincipalId = 'a2'; Role = 'Global Administrator' },
            [pscustomobject]@{ AssignmentType = 'Activated'; PrincipalId = 'a2'; Role = 'Global Administrator' })
        $r['IA.6-SUB'] = New-GResult 'IA.6-SUB' @([pscustomobject]@{ AccountObjectId = 'a1'; Role = 'Global Administrator' })
        $r['POS.6'] = New-GResult 'POS.6' @([pscustomobject]@{ ReadDate = '2026-10-10'; Current = 412.5; Max = 1000; Percent = 41.25; AllTenantsAverage = 300 })
        $r['POS.6-TREND'] = New-GResult 'POS.6-TREND' @(
            [pscustomobject]@{ Date = '2026-10-10'; Current = 412.5; Max = 1000; Percent = 41.25 },
            [pscustomobject]@{ Date = '2026-07-15'; Current = 380; Max = 1000; Percent = 38 })
        $r['POS.6-CATEGORIES'] = New-GResult 'POS.6-CATEGORIES' @(
            [pscustomobject]@{ Category = 'Identity'; Earned = 45.9; Available = 76; Percent = 60.4 },
            [pscustomobject]@{ Category = 'Device'; Earned = 382.6; Available = 914; Percent = 41.9 })
        $r['DP.7'] = New-GResult 'DP.7' @() 'UNAVAILABLE'
        $ws = Get-EbrWorksheet -Results $r -WindowStart ([datetime]'2026-01-01') -WindowEnd ([datetime]'2026-09-30')
        function Get-GRow([string]$Figure) { $ws | Where-Object Figure -eq $Figure | Select-Object -First 1 }
    }

    It 'still carries 48 rows' { $ws.Count | Should -Be 48 }

    It 'reads the tenant Secure Score from POS.6 with its read date' {
        $row = Get-GRow 'Microsoft tenant Secure Score'
        $row.Value | Should -Be '412.5 of 1000 (41.3%)'
        $row.ReadDate | Should -Be '2026-10-11'
        $row.Note | Should -Match 'snapshot dated 2026-10-10'
        $row.Note | Should -Match 'All-tenant average 300 points'
    }

    It 'prefers Graph role assignments over the IdentityInfo substitute and separates standing from eligible' {
        $row = Get-GRow 'Standing privileged roles'
        $row.Value | Should -Be '2 standing and 1 eligible assignments, 1 accounts holding a standing role'
        $row.Note | Should -Match '1 activated or time-bound'
        $row.Note | Should -Not -Match 'could not be read'
    }

    It 'says when eligibility was hidden by a missing permission' {
        $r3 = @{ 'IA.6' = (New-GResult 'IA.6' @([pscustomobject]@{ AssignmentType = 'Standing'; PrincipalId = 'a1'; Role = 'Global Administrator'; PimRead = 'NoPermission' })) }
        $ws3 = Get-EbrWorksheet -Results $r3 -WindowStart ([datetime]'2026-01-01') -WindowEnd ([datetime]'2026-09-30')
        ($ws3 | Where-Object Figure -eq 'Standing privileged roles').Note | Should -Match 'Eligible assignments could not be read \(the Graph token lacks RoleManagement\.Read\.Directory\)'
    }

    It 'describes the 90-day trend from first to last snapshot' {
        (Get-GRow 'Tenant score trend, 90 days').Value | Should -Be '38% on 2026-07-15 to 41.25% on 2026-10-10'
    }

    It 'lists category points largest scale first' {
        (Get-GRow 'Category points and share of the scale').Value | Should -Be 'Device 382.6 of 914 (41.9%), Identity 45.9 of 76 (60.4%)'
    }

    It 'reads Authenticator registration from IA.5 and adds the registered count to the phishing-resistant row' {
        (Get-GRow 'Users registered for Authenticator').Value | Should -Be '150 of 200 (75%)'
        (Get-GRow 'Phishing-resistant users').Value | Should -Be '7'
        (Get-GRow 'Phishing-resistant users').Note | Should -Match 'Registered for a phishing-resistant method \(IA\.5\): 25 of 200 \(12\.5%\)'
    }

    It 'falls back to the portal path with the not-a-zero note when Graph could not read a figure' {
        $r2 = @{ 'IA.5' = (New-GResult 'IA.5' @() 'UNAVAILABLE') }
        $ws2 = Get-EbrWorksheet -Results $r2 -WindowStart ([datetime]'2026-01-01') -WindowEnd ([datetime]'2026-09-30')
        $row = $ws2 | Where-Object Figure -eq 'Users registered for Authenticator'
        $row.Value | Should -Be 'MANUAL'
        $row.Note | Should -Match '^No figure, not a zero: IA\.5 had no data source'
        $row.Note | Should -Match 'Entra admin center'
    }
}

Describe 'End to end with mocked Azure: three workspaces, one per subscription' {
    BeforeAll {
        $client = 'cccccccc-0000-0000-0000-000000000000'
        $subs = @('11111111-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000002', '11111111-0000-0000-0000-000000000003')

        Mock Write-Host { }
        Mock Write-Progress { }
        Mock Test-EbrAzCli { $true }
        Mock Resolve-EbrTenantGuid { $client }
        Mock Get-EbrToken { 'e30.e30.sig' }
        Mock Get-EbrTenantInfo { [pscustomobject]@{ DisplayName = 'Contoso Test'; DefaultDomain = 'contoso.com'; InitialDomain = 'contoso.onmicrosoft.com' } }
        Mock Get-EbrAzAccounts {
            , @(for ($i = 0; $i -lt 3; $i++) {
                    [pscustomobject]@{ id = $subs[$i]; name = "Sub $($i + 1)"; state = 'Enabled'; tenantId = 'managing-tenant'; homeTenantId = $client }
                })
        }
        Mock Find-EbrWorkspaces {
            for ($i = 1; $i -le 3; $i++) {
                [pscustomobject]@{ WorkspaceName = "ws-$i"; CustomerId = "ws$i"; resourceGroup = "rg-$i"; subscriptionId = $subs[$i - 1]; location = 'westus'; RetentionDays = 365; HasSentinel = $true; WorkspaceResourceId = "/subscriptions/$($subs[$i - 1])/resourcegroups/rg-$i/providers/microsoft.operationalinsights/workspaces/ws-$i" }
            }
        }
        Mock Invoke-EbrArgQuery { [pscustomobject]@{ Columns = @('Resources'); Rows = @([pscustomobject]@{ Resources = 5 }); Detail = '' } }
        Mock Invoke-EbrAhQuery { throw 'HTTP 403: Forbidden' }
        Mock Get-EbrSentinelRules { [pscustomobject]@{ RuleName = 'r1'; Kind = 'Scheduled'; Enabled = $true; Severity = 'High'; LastModifiedUtc = '2026-09-01T00:00:00Z'; Tactics = ''; TemplateName = ''; RuleId = 'id' } }
        Mock Test-EbrDirectAccess { [pscustomobject]@{ Ok = $false; Missing = @(); Error = 'no direct token' } }
        Mock Read-EbrInput { 'n' }
        # One synthetic vulnerability assessment run naming the first subscription, dated the 1st of the report month
        # so it always falls inside the window.
        $vaDir = Join-Path $TestDrive 'va'
        New-Item -ItemType Directory -Path $vaDir | Out-Null
        $vaMonth = [datetime]::new(([datetime]::UtcNow).Year, ([datetime]::UtcNow).Month, 1).AddMonths(-1)
        $vaStamp = $vaMonth.ToString('yyyyMMdd') + '_090000'
        $vaSource = Join-Path $PSScriptRoot 'fixtures/vuln-assessment/2026-09'
        (Get-Content (Join-Path $vaSource 'vuln_assessment_20260901_090000.csv') -Raw).Replace('5f1c2a9e-3b7d-4e21-9a6c-0d8e4f2b7c11', $subs[0]) | Set-Content (Join-Path $vaDir "vuln_assessment_$vaStamp.csv") -NoNewline
        (Get-Content (Join-Path $vaSource 'run_metadata_20260901_090000.json') -Raw).Replace('5f1c2a9e-3b7d-4e21-9a6c-0d8e4f2b7c11', $subs[0]).Replace('2026-09-01T09:00:00', $vaMonth.ToString('yyyy-MM-dd') + 'T09:00:00') | Set-Content (Join-Path $vaDir "run_metadata_$vaStamp.json")
        Mock Get-EbrDefenderScores { [pscustomobject]@{ Rows = @([pscustomobject]@{ Metric = 'Exposure score'; Score = 30; Time = '' }); Detail = '' } }
        # Graph: the probe works, role assignments read without PIM, Conditional Access is not permitted, everything else is empty
        Mock Invoke-EbrGraphGet {
            if ($Uri -match 'v1\.0/organization') { return [pscustomobject]@{ id = $client } }
            if ($Uri -match 'ScheduleInstances') { throw 'HTTP 400: Bad Request | AadPremiumLicenseRequired' }
            if ($Uri -match 'roleAssignments\?') { return , @([pscustomobject]@{ roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; principalId = 'u1'; directoryScopeId = '/'; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Ann'; userPrincipalName = 'ann@contoso.com' } }) }
            if ($Uri -match 'conditionalAccess') { throw 'GRAPH-403 https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies: HTTP 403: Forbidden' }
            if ($Uri -match 'authorizationPolicy|adminConsentRequestPolicy|sharepoint/settings') { return [pscustomobject]@{} }
            , @()
        }
        Mock Invoke-EbrLaQuery {
            $combined = @($AdditionalWorkspaceIds | Where-Object { $_ }).Count -gt 0
            if ($Query -match '^union withsource = SourceTable isfuzzy = true\s+SecurityIncident') {
                $reach = @{
                    ws1 = @(@('SecurityIncident', '2026-02-10T08:00:00Z', 50), @('SigninLogs', '2026-01-01T00:00:00Z', 100), @('AuditLogs', '2026-01-01T00:00:00Z', 10))
                    ws2 = @(@('SecurityIncident', '2026-05-20T08:00:00Z', 5), @('SigninLogs', '2026-01-01T00:00:00Z', 900), @('AuditLogs', '2026-01-01T00:00:00Z', 500))
                    ws3 = @(@('SecurityIncident', '2026-03-03T00:00:00Z', 7))
                }
                $rows = foreach ($t in $reach[$WorkspaceCustomerId]) { [pscustomobject]@{ SourceTable = $t[0]; EarliestRecord = $t[1]; LatestRecord = '2026-10-07T00:00:00Z'; Records = $t[2] } }
                return [pscustomobject]@{ Columns = @('SourceTable', 'EarliestRecord', 'LatestRecord', 'Records'); Rows = @($rows); Detail = '' }
            }
            if ($Query -match '^union isfuzzy = true' -and $Query -match 'take 1 \| project SourceTable') {
                # Like SHB: the Sentinel workspaces hold UEBA IdentityInfo but no Defender device or email tables
                return [pscustomobject]@{ Columns = @('SourceTable'); Rows = @([pscustomobject]@{ SourceTable = 'IdentityInfo' }); Detail = '' }
            }
            if ($Query -match '^SecureScores' -and ($WorkspaceCustomerId -eq 'ws3' -or $AdditionalWorkspaceIds -contains 'ws3')) {
                throw "HTTP 400: Bad Request | Failed to resolve table or column expression named 'SecureScores'"
            }
            if ($Query -match '(?m)^SecurityAlert' -and -not $combined -and $WorkspaceCustomerId -eq 'ws2') { throw 'HTTP 500: workspace ws2 had a bad day' }
            if ($Query -match 'summarize Alerts = count\(\) by ProductName, AlertSeverity') {
                return [pscustomobject]@{ Columns = @('ProductName', 'AlertSeverity', 'Alerts'); Rows = @([pscustomobject]@{ ProductName = 'MDC'; AlertSeverity = 'High'; Alerts = $(if ($combined) { 40 } else { 20 }) }); Detail = '' }
            }
            [pscustomobject]@{ Columns = @('N'); Rows = @([pscustomobject]@{ N = 1 }); Detail = '' }
        }

        $code = Invoke-EbrMain -TenantId $client -SubscriptionId $subs -OutputPath $TestDrive -SkipExchange -ManagedRgPattern 'aznativesol0' -VulnAssessmentPath $vaDir
        $outDir = Get-ChildItem -Path $TestDrive -Directory -Filter 'CyberSOC-Evidence_*' | Select-Object -First 1
        $manifest = Import-Csv (Join-Path $outDir.FullName '00-manifest.csv')
        $params = Get-Content (Join-Path $outDir.FullName '00-parameters.json') -Raw | ConvertFrom-Json
        function Get-M([string]$Id) { $manifest | Where-Object ResultId -eq $Id }
    }

    It 'finishes with exit code 2 because one workspace failed some queries' {
        $code | Should -Be 2
    }

    It 'uses all three workspaces and writes the pack' {
        @($params.Workspaces).Count | Should -Be 3
        Test-Path (Join-Path $outDir.FullName '01-worksheet.csv') | Should -BeTrue
        @(Import-Csv (Join-Path $outDir.FullName '01-worksheet.csv')).Count | Should -Be 48
    }

    It 'sets the 90-day window ending with the last full month, since every workspace holds data before it' {
        $thisMonth = [datetime]::new(([datetime]::UtcNow).Year, ([datetime]::UtcNow).Month, 1)
        $params.WindowEnd | Should -Be $thisMonth.AddDays(-1).ToString('yyyy-MM-dd')
        $params.WindowStart | Should -Be $thisMonth.AddMonths(-3).ToString('yyyy-MM-dd')
        $params.ReportMonth | Should -Be $thisMonth.AddMonths(-1).ToString('yyyy-MM')
        $params.TrendMonths | Should -Be 3
        $params.ReportType | Should -Be 'CyberSOC monthly'
        $params.EbrBaseVersion | Should -Be '1.14.0'
    }

    It 'reads tenant-wide tables once, from the workspace holding the most' {
        $params.TenantWideTables.SigninLogs | Should -Be 'ws-2'
        Should -Invoke Invoke-EbrLaQuery -ParameterFilter { $Query -match 'MfaEveryAppSignIn' } -Times 1 -Exactly -Scope Describe
        Should -Invoke Invoke-EbrLaQuery -ParameterFilter { $Query -match 'MfaEveryAppSignIn' -and $WorkspaceCustomerId -eq 'ws2' } -Times 1 -Exactly -Scope Describe
        Should -Invoke Invoke-EbrLaQuery -ParameterFilter { $Query -match 'ResourceIdentity in \("497effe9' -and $WorkspaceCustomerId -eq 'ws2' } -Times 1 -Exactly -Scope Describe
        Get-M 'IA.1-BY-WORKSPACE' | Should -BeNullOrEmpty
    }

    It 'combines workspace-level queries in one call and breaks them down per workspace' {
        Should -Invoke Invoke-EbrLaQuery -ParameterFilter { $Query -match '^SecurityIncident' -and @($AdditionalWorkspaceIds).Count -eq 2 } -Scope Describe
        (Get-M 'OUT.1').Status | Should -Be 'OK'
        (Get-M 'OUT.1-BY-WORKSPACE').Status | Should -Be 'OK'
        (Get-M 'OUT.1-BY-WORKSPACE').Rows | Should -Be 3
    }

    It 'marks a combined figure PARTIAL when a workspace errored, and leaves that workspace out' {
        (Get-M 'OUT.5').Status | Should -Be 'PARTIAL'
        (Get-M 'OUT.5').Detail | Should -Match 'ws-2'
        (Get-M 'OUT.5-BY-WORKSPACE').Status | Should -Be 'PARTIAL'
        Should -Invoke Invoke-EbrLaQuery -ParameterFilter { $Query -match '(?m)^SecurityAlert' -and $WorkspaceCustomerId -eq 'ws1' -and $AdditionalWorkspaceIds -contains 'ws3' -and $AdditionalWorkspaceIds -notcontains 'ws2' } -Scope Describe
    }

    It 'treats a workspace without the table as no data, not a failure' {
        (Get-M 'POS.7').Status | Should -Be 'OK'
        (Get-M 'POS.7-BY-WORKSPACE').Status | Should -Be 'OK'
        (Get-M 'POS.7-BY-WORKSPACE').Detail | Should -Match 'Table not present in ws-3'
    }

    It 'falls back to the workspaces only for tables they actually hold' {
        (Get-M 'IA.6-SUB').Source | Should -Be 'Sentinel workspace (AH fallback)'
        (Get-M 'IA.6-SUB').Status | Should -Be 'OK'
    }

    It 'reports Defender queries with no data source as UNAVAILABLE, not as zero' {
        foreach ($id in 'P0.4', 'EW.1', 'EW.3', 'EW.4', 'EW.5', 'DP.7', 'DR.4', 'DR.5', 'BKL.1') {
            (Get-M $id).Status | Should -Be 'UNAVAILABLE' -Because $id
        }
        (Get-M 'BKL.1').Detail | Should -Match 'not a zero'
        Should -Invoke Invoke-EbrLaQuery -Scope Describe -Times 0 -Exactly -ParameterFilter { $Query -match '^DeviceTvmSoftwareVulnerabilities' }
        $ws = Import-Csv (Join-Path $outDir.FullName '01-worksheet.csv')
        ($ws | Where-Object Figure -eq 'Exploitable OS findings open').Value | Should -BeNullOrEmpty
        ($ws | Where-Object Figure -eq 'Malicious mail removed after delivery').Value | Should -BeNullOrEmpty
        Get-Content (Join-Path $outDir.FullName '02-notes.txt') -Raw | Should -Not -Match 'Exploitable OS findings open: 0'
    }

    It 'warns that Sentinel holds no Defender XDR incidents' {
        ($params.Warnings -join ' ') | Should -Match 'No Defender XDR incidents reached Sentinel'
    }

    It 'marks IA.7 partial when the run went through Lighthouse' {
        $params.AccessPath | Should -Be 'Lighthouse'
        (Get-M 'IA.7').Status | Should -Be 'PARTIAL'
        (Get-M 'IA.7').Detail | Should -Match 'Lighthouse'
        ($params.Warnings -join ' ') | Should -Match 'IA\.7'
    }

    It 'reads Graph measures through the Azure CLI token and marks the forbidden ones UNAVAILABLE with the scope to request' {
        $params.GraphApi | Should -Be 'available'
        (Get-M 'IA.6').Status | Should -Be 'OK'
        (Get-M 'IA.6').Source | Should -Be 'Microsoft Graph'
        (Get-M 'IA.8').Status | Should -Be 'UNAVAILABLE'
        (Get-M 'IA.8').Detail | Should -Match 'Needs Policy\.Read\.All'
        (Get-M 'IA.11').Status | Should -Be 'UNAVAILABLE'
        (Get-M 'DR.11').Status | Should -Be 'EMPTY'
        (Get-M 'IA.1-FEDERATION').Status | Should -Be 'EMPTY' -Because 'no federated domain is a reading, not a gap'
        @($params.GraphMissingScopes) | Should -Be @('Policy.Read.All')
        $notes = Get-Content (Join-Path $outDir.FullName '02-notes.txt') -Raw
        $notes | Should -Match 'Graph permissions missing for IA\.8, IA\.11: Policy\.Read\.All\. The unavailable ones are not zeros and keep their portal path\. Fix: az login --tenant cccccccc-0000-0000-0000-000000000000 --scope https://graph\.microsoft\.com/Policy\.Read\.All, then rerun'
        $notes | Should -Match 'No data source, so no figure \(these are not zeros\): P0\.4, EW\.1'
        $notes | Should -Not -Match 'not zeros\): [^\r\n]*IA\.8'
        Test-Path (Join-Path $outDir.FullName 'queries/IA.8.graph.txt') | Should -BeTrue
        $params.PatchCadenceDays | Should -Be 30
    }

    It 'carries the new control measures through the manifest' {
        foreach ($id in 'IA.1-ADMINPORTAL', 'IA.3-DEVICECODE', 'IA.14', 'DR.10', 'DR.13', 'DR.6-INITIATIVE', 'EW.10', 'EW.12', 'EW.15', 'NB.8', 'NB.10', 'NB.11', 'DP.7-ZAP') {
            (Get-M $id) | Should -Not -BeNullOrEmpty
        }
        (Get-M 'DP.7-ZAP').Status | Should -Be 'SKIPPED'
        (Get-M 'DP.7-ZAP').Phase | Should -Be 'P2 Data protection'
    }

    It 'names the pack after the client and the report month, not a subscription' {
        $outDir.Name | Should -Match ('^CyberSOC-Evidence_Contoso-Test_{0}_\d{{8}}-\d{{6}}$' -f [regex]::Escape($params.ReportMonth))
    }

    It 'runs Phase 5: tenant-wide tables once from their workspace, and the device queries as not a zero without Defender' {
        foreach ($id in 'OUT.2-MONTH', 'OUT.3-WEEK', 'OUT.9', 'TI.0', 'TI.0-BY-WORKSPACE', 'TI.1', 'TI.2', 'TI.3', 'TI.4', 'TI.5', 'TI.5-RISK', 'TI.6', 'TI.7', 'VA.1', 'VA.2', 'VA.3') { Get-M $id | Should -Not -BeNullOrEmpty -Because $id }
        (Get-M 'TI.0').Phase | Should -Be 'P5 Threat intelligence'
        Should -Invoke Invoke-EbrLaQuery -ParameterFilter { $Query -match 'SprayIps' } -Times 1 -Exactly -Scope Describe
        Should -Invoke Invoke-EbrLaQuery -ParameterFilter { $Query -match 'SprayIps' -and $WorkspaceCustomerId -eq 'ws2' } -Times 1 -Exactly -Scope Describe
        Should -Invoke Invoke-EbrLaQuery -ParameterFilter { $Query -match '^AADUserRiskEvents' -and $WorkspaceCustomerId -eq 'ws2' } -Times 1 -Exactly -Scope Describe -Because 'risk detections go where the sign-ins go'
        Should -Invoke Invoke-EbrLaQuery -ParameterFilter { $Query -match '^EmailEvents' } -Times 1 -Exactly -Scope Describe
        foreach ($id in 'TI.7', 'VA.1', 'VA.2', 'VA.3') {
            (Get-M $id).Status | Should -Be 'UNAVAILABLE' -Because $id
            (Get-M $id).Detail | Should -Match 'Not a zero' -Because $id
        }
    }

    It 'imports the vulnerability assessment run, partial because it covers one of the three subscriptions' {
        (Get-M 'VA.RUNS').Status | Should -Be 'PARTIAL'
        (Get-M 'VA.RUNS').Engine | Should -Be 'VULN-ASSESS'
        (Get-M 'VA.CHANGE').Status | Should -Be 'EMPTY'
        @($params.VulnAssessment.Runs).Count | Should -Be 1
        $params.VulnAssessment.Runs[0].Status | Should -Be 'Partial'
        (Get-Content (Join-Path $outDir.FullName 'results/VA.TOP.json') -Raw) | Should -Not -Match 'vm-app|rg-app|/subscriptions/'
        (Get-Content (Join-Path $outDir.FullName '02-notes.txt') -Raw) | Should -Match 'Vulnerability assessment runs imported: \d{4}-\d{2}-01 \(Partial\)'
    }

    It 'collects Sentinel rules from every workspace' {
        (Get-M 'DR.9-RULES').Rows | Should -Be 3
        $summary = Import-Csv (Join-Path $outDir.FullName 'results/DR.9.csv')
        ($summary | Where-Object { $_.Scope -eq 'All workspaces' -and $_.Metric -eq 'Total rules' }).Value | Should -Be '3'
    }

    It 'records the endpoint detection and patch exclusion patterns and derives EW.1-GAPS as UNAVAILABLE without the device list' {
        $params.EdrVendorPattern | Should -Be $script:EbrEdrVendorPattern
        $params.PatchExclusionTagPattern | Should -Be $script:EbrPatchExclusionTagPattern
        (Get-M 'EW.1-GAPS').Status | Should -Be 'UNAVAILABLE'
        (Get-M 'EW.1-GAPS').Engine | Should -Be 'DERIVED'
        (Get-M 'EW.1-GAPS').Detail | Should -Match 'Not a zero'
        (Get-M 'EW.10-EXCLUDED') | Should -Not -BeNullOrEmpty
        (Get-M 'EW.1-EDR') | Should -Not -BeNullOrEmpty
    }

    It 'keeps the notes and the worksheet to the copy rules' {
        $notes = Get-Content (Join-Path $outDir.FullName '02-notes.txt') -Raw
        $notes | Should -Not -Match ';'
        $notes | Should -Not -Match '->|=>|[\u2190-\u21FF]'
        ($notes -replace '[A-Za-z0-9)] > [A-Za-z]', '') | Should -Not -Match '[<>]'
        foreach ($row in @(Import-Csv (Join-Path $outDir.FullName '01-worksheet.csv'))) {
            foreach ($text in @($row.Figure, $row.Value, $row.Note)) {
                $text | Should -Not -Match ';' -Because $row.Figure
                ($text -replace '[A-Za-z0-9)] > [A-Za-z]', '') | Should -Not -Match '[<>]' -Because $row.Figure
            }
        }
        foreach ($m in $manifest) { $m.Guidance | Should -Not -Match ';' -Because $m.ResultId }
    }

    It 'fills the worksheet from the combined result and flags it partial' {
        $ws = Import-Csv (Join-Path $outDir.FullName '01-worksheet.csv')
        $row = $ws | Where-Object Figure -eq 'Alerts triaged'
        $row.Value | Should -Be '40'
        $row.Note | Should -Match 'PARTIAL'
    }

    It 'creates the executive HTML report from the completed pack' {
        $htmlPath = Join-Path $outDir.FullName '03-security-report.html'
        Test-Path $htmlPath | Should -BeTrue
        Get-Content $htmlPath -Raw | Should -Match 'Contoso Test'
    }

    It 'reads the rules of each workspace exactly once' {
        Should -Invoke Get-EbrSentinelRules -Times 3 -Exactly -Scope Describe
    }
}

Describe 'Worksheet: automation, small samples, anti-malware' {
    BeforeAll {
        function New-Result([string]$Id, [object[]]$Rows) {
            [pscustomobject]@{ ResultId = $Id; Status = 'OK'; Rows = $Rows; ReadTimeUtc = [datetime]'2026-10-08T08:00:00Z' }
        }
        $r = @{}
        $r['OUT.2'] = New-Result 'OUT.2' @(
            [pscustomobject]@{ Scope = 'All'; Incidents = 4686; AutoClosed = 3159; MedianCloseMin = 0; P90CloseMin = 88 },
            [pscustomobject]@{ Scope = 'High'; Incidents = 8; AutoClosed = 0; MedianCloseMin = 16; P90CloseMin = 8658 })
        $r['OUT.2-ANALYST'] = New-Result 'OUT.2-ANALYST' @(
            [pscustomobject]@{ Scope = 'All'; Incidents = 1527; AutoClosed = 0; MedianCloseMin = 45; P90CloseMin = 225 },
            [pscustomobject]@{ Scope = 'High'; Incidents = 8; AutoClosed = 0; MedianCloseMin = 16; P90CloseMin = 8658 })
        $r['EW.3'] = New-Result 'EW.3' @(
            [pscustomobject]@{ Scope = 'Azure VM'; ConfigurationId = 'scid-6090'; ConfigurationName = 'Turn on Microsoft Defender Antivirus real-time protection for Linux'; Devices = 45; Compliant = 0; PctCompliant = 0 },
            [pscustomobject]@{ Scope = 'Azure VM'; ConfigurationId = 'scid-2012'; ConfigurationName = 'Turn on real-time protection'; Devices = 14; Compliant = 12; PctCompliant = 85.7 },
            [pscustomobject]@{ Scope = 'Other device'; ConfigurationId = 'scid-2012'; ConfigurationName = 'Turn on real-time protection'; Devices = 32; Compliant = 32; PctCompliant = 100 },
            [pscustomobject]@{ Scope = 'Other device'; ConfigurationId = 'scid-1'; ConfigurationName = 'Something unrelated'; Devices = 32; Compliant = 0; PctCompliant = 0 })
        $ws = Get-EbrWorksheet -Results $r -WindowStart ([datetime]'2025-11-01') -WindowEnd ([datetime]'2026-09-30')
        function Get-Row([string]$Figure) { $ws | Where-Object Figure -eq $Figure | Select-Object -First 1 }
    }

    It 'quotes the analyst-handled median when automation closed at least half' {
        $row = Get-Row 'Median time to close'
        $row.Value | Should -Be '45 min (0.8 h), analyst-handled'
        $row.Note | Should -Match '3159 of 4686'
        $row.Note | Should -Match 'All closed incidents: 0 min'
    }

    It 'flags a high-severity P90 built on a handful of incidents' {
        $row = Get-Row '90th percentile close, high severity'
        $row.Value | Should -Match '^8658 min'
        $row.Note | Should -Match 'Only 8 high severity incidents'
    }

    It 'lists every anti-malware check under the weakest one' {
        $row = Get-Row 'Endpoint anti-malware coverage'
        $row.Value | Should -Be '0 of 45 (0%)'
        $row.Note | Should -Match 'Azure VM, Turn on real-time protection: 12 of 14 \(85\.7%\)'
        $row.Note | Should -Match 'Other device, Turn on real-time protection: 32 of 32 \(100%\)'
        $row.Note | Should -Not -Match 'unrelated'
    }
}

Describe 'Run 3 fixes' {
    BeforeAll { Mock Write-Host { } }

    It 'prefers the Exchange organization name over a domain or GUID' {
        Get-EbrClientName -TenantGuid 'g' -TenantInput 'g' -OrgName 'Guardian Research Network' -Accounts @() | Should -Be 'Guardian Research Network'
        Get-EbrClientName -TenantGuid 'g' -TenantInput 'grn.com' -OrgName 'Guardian Research Network' -Accounts @() | Should -Be 'Guardian Research Network'
        Get-EbrClientName -TenantGuid 'g' -TenantInput 'g' -Accounts @() | Should -Be 'g'
    }

    It 'knows which tables only the Defender XDR API exposes' {
        $x = Get-EbrXdrOnlyTableNames
        foreach ($t in 'IdentityInfo', 'IdentityLogonEvents', 'EmailPostDeliveryEvents') { $x | Should -Contain $t }
        $x | Should -Not -Contain 'DeviceInfo'
    }

    It 'reports an empty workspace once and tailors the P0.4 warning to what is missing' {
        $ctx = [pscustomobject]@{
            Workspaces     = @([pscustomobject]@{ WorkspaceName = 'real'; CustomerId = 'r1' }, [pscustomobject]@{ WorkspaceName = 'demo'; CustomerId = 'd1' })
            DefenderReason = ''
            Results        = @{
                'P0.1-BY-WORKSPACE' = [pscustomobject]@{ Status = 'OK'; Source = 'Log Analytics'; Rows = @(
                        [pscustomobject]@{ Workspace = 'real'; WorkspaceId = 'r1'; SourceTable = 'SecurityIncident'; Records = 5 },
                        [pscustomobject]@{ Workspace = 'real'; WorkspaceId = 'r1'; SourceTable = 'SecureScores'; Records = 5 },
                        [pscustomobject]@{ Workspace = 'real'; WorkspaceId = 'r1'; SourceTable = 'SecurityRecommendation'; Records = 5 }) }
                'P0.4'              = [pscustomobject]@{ Status = 'OK'; Source = 'Defender Advanced Hunting'; Rows = @(
                        [pscustomobject]@{ SourceTable = 'DeviceInfo' }, [pscustomobject]@{ SourceTable = 'DeviceEvents' },
                        [pscustomobject]@{ SourceTable = 'DeviceTvmSecureConfigurationAssessment' }) }
            }
        }
        $w = @(Get-EbrPreflightWarnings -Ctx $ctx)
        @($w | Where-Object { $_ -match 'demo' }).Count | Should -Be 1
        ($w | Where-Object { $_ -match 'demo' }) | Should -Match 'holds no data'
        $p04 = $w | Where-Object { $_ -match '^P0\.4' }
        $p04 | Should -Match 'Defender for Endpoint hunting API'
        $p04 | Should -Match 'EmailPostDeliveryEvents, IdentityLogonEvents'
        $p04 | Should -Not -Match 'Grade EW-F1'
    }

    Context 'Advanced Hunting routing' {
        BeforeAll {
            $catalog = Get-EbrQueryCatalog
            New-Item -ItemType Directory -Path (Join-Path $TestDrive 'queries') -Force | Out-Null
            function New-Ctx {
                [pscustomobject]@{
                    WindowStart = [datetime]'2026-01-01'; WindowEnd = [datetime]'2026-09-30'; ManagedRgPattern = 'aznativesol0'
                    OutDir = $TestDrive; DefenderAvailable = $true; DefenderReason = ''; TenantGuid = 'client'
                    Workspaces = @([pscustomobject]@{ WorkspaceName = 'ws'; CustomerId = 'w1'; AccessTenant = 'client' })
                    Pending = [System.Collections.Generic.List[object]]::new()
                }
            }
            Mock Invoke-EbrAhQuery { [pscustomobject]@{ Columns = @('N'); Rows = @([pscustomobject]@{ N = 1 }); Detail = '' } }
            Mock Get-EbrFallbackTables { , @('IdentityInfo') }
        }

        It 'sends email and identity queries straight to Sentinel and explains why' {
            $res = Invoke-EbrCatalogItem -Ctx (New-Ctx) -Item ($catalog | Where-Object Id -eq 'DP.7')
            $res.Status | Should -Be 'UNAVAILABLE'
            $res.Detail | Should -Match 'Defender for Endpoint hunting API'
            $res.Detail | Should -Match 'queries/DP\.7\.kql'
            Should -Invoke Invoke-EbrAhQuery -Times 0 -Exactly
        }

        It 'still uses the Defender API for device queries' {
            (Invoke-EbrCatalogItem -Ctx (New-Ctx) -Item ($catalog | Where-Object Id -eq 'EW.1')).Source | Should -Be 'Defender Advanced Hunting'
            Should -Invoke Invoke-EbrAhQuery -Times 1 -Exactly
        }

        It 'still runs the P0.4 availability check through the Defender API' {
            $null = Invoke-EbrCatalogItem -Ctx (New-Ctx) -Item ($catalog | Where-Object Id -eq 'P0.4')
            Should -Invoke Invoke-EbrAhQuery -Times 1 -Exactly
        }
    }

    Context 'Exchange organization details' {
        BeforeAll {
            # The end-to-end run above left run.log pointing into a TestDrive that is gone
            $script:EbrLogPath = $null
            # Stubs: the real cmdlets only exist after Connect-ExchangeOnline
            function Connect-ExchangeOnline { [CmdletBinding()] param([switch]$ShowBanner, [string]$DelegatedOrganization) }
            function Connect-IPPSSession { [CmdletBinding()] param([string]$DelegatedOrganization) }
            function Disconnect-ExchangeOnline { [CmdletBinding()] param([switch]$Confirm) }
            function Get-AntiPhishPolicy { }
            function Get-AntiPhishRule { }
            function Get-ATPProtectionPolicyRule { }
            function Get-SafeLinksPolicy { }
            function Get-SafeAttachmentPolicy { }
            function Get-MalwareFilterPolicy { [pscustomobject]@{ Name = 'Default'; IsDefault = $true; ZapEnabled = $true } }
            function Get-HostedContentFilterPolicy { [pscustomobject]@{ Name = 'Default'; IsDefault = $true; PhishZapEnabled = $true; SpamZapEnabled = $false } }
            function Get-DlpCompliancePolicy { }
            function Get-OrganizationConfig { [CmdletBinding()] param() [pscustomobject]@{ DisplayName = 'Guardian Research Network'; Name = 'grn.onmicrosoft.com' } }
            function Get-AcceptedDomain { [CmdletBinding()] param() @([pscustomobject]@{ DomainName = 'grn.com'; InitialDomain = $false }, [pscustomobject]@{ DomainName = 'grn.onmicrosoft.com'; InitialDomain = $true }) }
            Mock Connect-IPPSSession { }
        }

        It 'reads the organization name and connects Purview with the initial domain, not the GUID' {
            $x = Get-EbrExchangeEvidence -DelegatedOrganization '0a1399e1-c245-4c67-96d1-378ab497dd3a'
            $x.OrgName | Should -Be 'Guardian Research Network'
            $x.InitialDomain | Should -Be 'grn.onmicrosoft.com'
            @($x.Results).Count | Should -Be 7
            Should -Invoke Connect-IPPSSession -Times 1 -Exactly -ParameterFilter { $DelegatedOrganization -eq 'grn.onmicrosoft.com' }
        }

        It 'reads zero-hour auto purge from the malware and content filter policies into one result' {
            $x = Get-EbrExchangeEvidence -DelegatedOrganization 'grn.onmicrosoft.com'
            $zap = $x.Results | Where-Object ResultId -eq 'DP.7-ZAP'
            $zap.Status | Should -Be 'OK'
            @($zap.Rows).Count | Should -Be 2
            ($zap.Rows | Where-Object Kind -eq 'Malware').ZapEnabled | Should -BeTrue
            ($zap.Rows | Where-Object Kind -eq 'Spam and phishing').SpamZapEnabled | Should -BeFalse
        }

        It 'still connects with a module too old for CommandName or SkipLoadingFormatData' {
            # These stubs know only ShowBanner and DelegatedOrganization, like an early 3.x module
            Mock Connect-ExchangeOnline { }
            $null = Get-EbrExchangeEvidence -DelegatedOrganization 'grn.onmicrosoft.com'
            Should -Invoke Connect-ExchangeOnline -Times 1 -Exactly -ParameterFilter { -not $PSBoundParameters.ContainsKey('CommandName') -and $ShowBanner -eq $false }
        }
    }

    Context 'Exchange connection' {
        BeforeAll {
            $script:EbrLogPath = $null
            # Same parameters as ExchangeOnlineManagement 3.10
            function Connect-ExchangeOnline { [CmdletBinding()] param([switch]$ShowBanner, [string]$DelegatedOrganization, [string[]]$CommandName, [switch]$SkipLoadingFormatData) }
            function Connect-IPPSSession { [CmdletBinding()] param([switch]$ShowBanner, [string]$DelegatedOrganization, [string[]]$CommandName) }
            function Disconnect-ExchangeOnline { [CmdletBinding()] param([switch]$Confirm) }
            Mock Connect-ExchangeOnline { }
            Mock Connect-IPPSSession { }
        }

        It 'loads only the cmdlets the collectors use and skips format data' {
            $null = Get-EbrExchangeEvidence -DelegatedOrganization 'grn.onmicrosoft.com'
            Should -Invoke Connect-ExchangeOnline -Times 1 -Exactly -ParameterFilter {
                $ShowBanner -eq $false -and $SkipLoadingFormatData -and
                (Compare-Object @($CommandName) $script:EbrExoCommands) -eq $null
            }
            Should -Invoke Connect-IPPSSession -Times 1 -Exactly -ParameterFilter {
                $ShowBanner -eq $false -and (Compare-Object @($CommandName) $script:EbrIppsCommands) -eq $null
            }
        }

        It 'lists every Exchange and Purview cmdlet the collectors call' {
            # A cmdlet missing from the lists never loads and reads as "not loaded" for the client
            $ast = (Get-Command Get-EbrExchangeEvidence).ScriptBlock.Ast
            $called = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                    ForEach-Object { $_.GetCommandName() } | Where-Object { $_ -match '^Get-' -and $_ -notmatch '^Get-Ebr' } | Select-Object -Unique)
            $called.Count | Should -Be 10
            foreach ($c in $called) { $c | Should -BeIn @($script:EbrExoCommands + $script:EbrIppsCommands) }
            foreach ($c in @($script:EbrExoCommands + $script:EbrIppsCommands)) { $c | Should -BeIn $called }
        }
    }
}

Describe 'Run stalls' {
    It 'leaves the console alone off Windows, and restoring nothing is a no-op' {
        if ([Environment]::OSVersion.Platform -eq 'Win32NT') { Set-ItResult -Skipped -Because 'checks the non-Windows path'; return }
        Disable-EbrQuickEdit | Should -BeNullOrEmpty
        { Restore-EbrQuickEdit $null } | Should -Not -Throw
    }

    Context 'slow request log' {
        BeforeAll {
            Mock Get-EbrToken { 'token' }
            Mock Invoke-RestMethod { [pscustomobject]@{ tables = @() } }
            Mock Write-EbrLog { }
        }
        AfterEach { $script:EbrSlowRequestSec = 30 }

        It 'writes a request at or over the threshold to run.log with its duration, without the query string' {
            $script:EbrSlowRequestSec = 0
            $null = Invoke-EbrRest -Method GET -Uri 'https://graph.microsoft.com/v1.0/domains?$select=id' -Resource 'https://graph.microsoft.com/' -Tenant 't'
            Should -Invoke Write-EbrLog -Times 1 -Exactly -ParameterFilter { $Component -eq 'Http' -and $Message -like 'GET https://graph.microsoft.com/v1.0/domains answered in *s' }
        }

        It 'stays quiet for a fast request' {
            $null = Invoke-EbrRest -Method POST -Uri 'https://api.loganalytics.io/v1/workspaces/0a1399e1-c245-4c67-96d1-378ab497dd3a/query' -Resource 'https://api.loganalytics.io' -Tenant 't' -Body @{ query = 'T' }
            Should -Invoke Write-EbrLog -Times 0 -ParameterFilter { $Component -eq 'Http' }
        }
    }
}

Describe 'Azure virtual machine scope, third-party endpoint detection and patch exclusions (1.14.0)' {
    BeforeAll {
        $catalog = Get-EbrQueryCatalog
        $expand = { param($id, $extra = @{}) Expand-EbrQuery -Query ($catalog | Where-Object Id -eq $id).Query -WindowStart ([datetime]'2026-01-01') -WindowEnd ([datetime]'2026-06-30') -ManagedRgPattern 'aznativesol0' @extra }
    }

    It 'reads Azure virtual machines only in every device query and never counts another kind of endpoint' {
        foreach ($id in 'EW.1', 'EW.1-DEVICES', 'EW.1-VMS', 'EW.3', 'EW.4', 'EW.5', 'EW.12', 'EW.14', 'EW.15', 'EW.16', 'NB.8', 'NB.10', 'NB.11', 'DR.5', 'DR.12', 'BKL.1') {
            $q = ($catalog | Where-Object Id -eq $id).Query
            $q | Should -Match 'where isnotempty\(AzureResourceId\)' -Because $id
            $q | Should -Not -Match 'Other device' -Because $id
        }
        $every = @($catalog | Where-Object { $_.Engine -eq 'AH' -and $_.Query -match 'DeviceInfo' -and $_.Id -ne 'P0.4' -and $_.Query -notmatch 'where isnotempty\(AzureResourceId\)' } | ForEach-Object Id)
        $every | Should -BeNullOrEmpty -Because 'every Advanced Hunting query that reads DeviceInfo is scoped to Azure virtual machines'
        ($catalog | Where-Object Id -eq 'EW.1').Query | Should -Match 'Unsupported\s+= countif\(OnboardingStatus == "Unsupported"\)'
        ($catalog | Where-Object Id -eq 'EW.1').Query | Should -Match 'InsufficientInfo = countif\(OnboardingStatus == "Insufficient info"\)'
    }

    It 'carries the endpoint detection evidence queries and the derived gap list' {
        foreach ($id in 'EW.1-VMS', 'EW.1-EDR', 'EW.1-EDR-HOSTS', 'EW.1-GAPS', 'EW.10-EXCLUDED') { $catalog.Id | Should -Contain $id }
        ($catalog | Where-Object Id -eq 'EW.1-EDR').Engine | Should -Be 'ARG'
        ($catalog | Where-Object Id -eq 'EW.1-EDR-HOSTS').Engine | Should -Be 'LA'
        ($catalog | Where-Object Id -eq 'EW.1-EDR-HOSTS').CombinedOnly | Should -BeTrue
        $gaps = $catalog | Where-Object Id -eq 'EW.1-GAPS'
        $gaps.Engine | Should -Be 'DERIVED'
        $gaps.Query | Should -BeNullOrEmpty
        $gaps.Derive | Should -Not -BeNullOrEmpty
        # EW.1-GAPS runs after the results it reads, within Phase 2
        $ids = @($catalog | Where-Object { $_.Phase -like 'P2*' } | ForEach-Object Id)
        foreach ($before in 'EW.1-VMS', 'EW.1-EDR', 'EW.1-EDR-HOSTS', 'EW.1-DEVICES') { $ids.IndexOf($before) | Should -BeLessThan $ids.IndexOf('EW.1-GAPS') -Because $before }
    }

    It 'expands the EDR vendor pattern into the extension and Sentinel queries and rejects quotes in it' {
        $edr = & $expand 'EW.1-EDR'
        $edr | Should -Match 'make_set_if\(strcat\(Publisher, "/", ExtensionType\), Product matches regex @"\(crowdstrike\|falcon\|'
        $edr | Should -Match 'ExtensionType startswith "MDE\."'
        $edr | Should -Match 'Recommendation has "EDR solution should be installed"'
        $edr | Should -Match 'Appliance  = tolower\(strcat\(tostring\(plan\.publisher\)'
        $edr | Should -Not -Match '\{\{'
        $hosts = & $expand 'EW.1-EDR-HOSTS' @{ EdrVendorPattern = 'crowdstrike|falcon' }
        $hosts | Should -Match '^union withsource = SourceTable isfuzzy = true CrowdStrike\*, CommonSecurityLog'
        $hosts | Should -Match 'Product matches regex @"\(crowdstrike\|falcon\)"'
        { & $expand 'EW.1-EDR' @{ EdrVendorPattern = 'crowd"strike' } } | Should -Throw '*EdrVendorPattern*'
    }

    It 'leaves machines tagged as patching waived or client owned out of EW.6 and EW.10, names them in EW.10-EXCLUDED, and an empty pattern turns it off' {
        foreach ($id in 'EW.6', 'EW.10') {
            $q = ($catalog | Where-Object Id -eq $id).Query
            $q | Should -Match 'extend PatchExcluded = false' -Because $id
            $q | Should -Match 'PatchExcluded = tolower\(tostring\(tags\)\) matches regex @"\{\{PATCH_EXCLUDED\}\}"' -Because $id
            $q | Should -Match 'where not\(coalesce\(PatchExcluded, false\)\)' -Because $id
            $on = & $expand $id
            # inside a KQL verbatim string every double quote of the pattern is doubled
            $on | Should -Match 'matches regex @"""\[\^""\]\*patch' -Because $id
            $on | Should -Not -Match '\{\{' -Because $id
            $off = & $expand $id @{ PatchExclusionTagPattern = '' }
            $off | Should -Not -Match 'matches regex' -Because $id
            $off | Should -Match 'extend PatchExcluded = false\n    \| project MachineId = tolower\(id\), PatchExcluded' -Because $id
        }
        $ex = & $expand 'EW.10-EXCLUDED'
        $ex | Should -Match 'extract\(@"""\[\^""\]\*patch'
        $ex | Should -Match '\| where PatchExcluded\n\| project Name = name'
        $custom = & $expand 'EW.10-EXCLUDED' @{ PatchExclusionTagPattern = '"patching":"waived"' }
        $custom | Should -Match 'matches regex @"""patching"":""waived"""'
        { & $expand 'EW.10' @{ PatchExclusionTagPattern = "a`nb" } } | Should -Throw '*PatchExclusionTagPattern*'
        # The default tag pattern reads the key and the value, whichever carries the word
        $re = [regex]::new($script:EbrPatchExclusionTagPattern)
        foreach ($tags in '{"patching":"waived","env":"prod"}', '{"patchpolicy":"client owned"}', '{"maintenance":"patching waived"}', '{"owner":"client-owned patching"}', '{"patchgroup":"clientowned"}') { $re.IsMatch($tags) | Should -BeTrue -Because $tags }
        foreach ($tags in '{"patching":"atmosera","env":"prod"}', '{"owner":"client owned"}', '{}') { $re.IsMatch($tags) | Should -BeFalse -Because $tags }
    }

    Context 'Get-EbrOnboardingGapRows' {
        BeforeAll {
            $vm = { param($name, $rg = 'app') "/subscriptions/s1/resourceGroups/$rg/providers/Microsoft.Compute/virtualMachines/$name" }
            $known = @(
                [pscustomobject]@{ DeviceId = 'd1'; DeviceName = 'web-01'; OSPlatform = 'WindowsServer2022'; OnboardingStatus = 'Onboarded'; SensorHealthState = 'Active'; LastSeen = '2026-10-13T00:00:00Z'; MachineGroup = 'Servers'; AzureResourceId = (& $vm 'web-01') }
                [pscustomobject]@{ DeviceId = 'd2'; DeviceName = 'cs-01.corp.example'; OSPlatform = 'WindowsServer2019'; OnboardingStatus = 'Can be onboarded'; SensorHealthState = ''; LastSeen = '2026-10-13T00:00:00Z'; MachineGroup = ''; AzureResourceId = (& $vm 'cs-01') }
                [pscustomobject]@{ DeviceId = 'd3'; DeviceName = 'cs-02'; OSPlatform = 'Linux'; OnboardingStatus = 'Can be onboarded'; SensorHealthState = ''; LastSeen = '2026-10-13T00:00:00Z'; MachineGroup = ''; AzureResourceId = (& $vm 'cs-02') }
                [pscustomobject]@{ DeviceId = 'd4'; DeviceName = 'fw-01'; OSPlatform = 'Linux'; OnboardingStatus = 'Unsupported'; SensorHealthState = ''; LastSeen = '2026-10-13T00:00:00Z'; MachineGroup = ''; AzureResourceId = (& $vm 'fw-01' 'fw') }
                [pscustomobject]@{ DeviceId = 'd5'; DeviceName = 'old-01'; OSPlatform = 'WindowsServer2008'; OnboardingStatus = 'Unsupported'; SensorHealthState = ''; LastSeen = '2026-10-13T00:00:00Z'; MachineGroup = ''; AzureResourceId = (& $vm 'old-01') }
                [pscustomobject]@{ DeviceId = 'd6'; DeviceName = 'off-01'; OSPlatform = 'WindowsServer2022'; OnboardingStatus = 'Onboarded'; SensorHealthState = 'Inactive'; LastSeen = '2026-10-01T00:00:00Z'; MachineGroup = ''; AzureResourceId = (& $vm 'off-01') }
                [pscustomobject]@{ DeviceId = 'd7'; DeviceName = 'gap-01'; OSPlatform = 'WindowsServer2022'; OnboardingStatus = 'Can be onboarded'; SensorHealthState = ''; LastSeen = '2026-10-13T00:00:00Z'; MachineGroup = ''; AzureResourceId = (& $vm 'gap-01') }
                [pscustomobject]@{ DeviceId = 'd8'; DeviceName = 'disc-01'; OSPlatform = ''; OnboardingStatus = 'Insufficient info'; SensorHealthState = ''; LastSeen = '2026-10-13T00:00:00Z'; MachineGroup = ''; AzureResourceId = (& $vm 'disc-01') }
                [pscustomobject]@{ DeviceId = 'd9'; DeviceName = 'imp-01'; OSPlatform = 'WindowsServer2022'; OnboardingStatus = 'Onboarded'; SensorHealthState = 'Impaired communications'; LastSeen = '2026-10-13T00:00:00Z'; MachineGroup = ''; AzureResourceId = (& $vm 'imp-01') }
            )
            $azure = @(
                [pscustomobject]@{ VmId = (& $vm 'web-01').ToLowerInvariant(); VmName = 'web-01'; resourceGroup = 'app'; subscriptionId = 's1'; OsType = 'Windows'; PowerState = 'PowerState/running'; Appliance = $false; DefenderExtension = 1; ThirdPartyEdr = $false; ThirdPartyExtensions = @(); EdrAssessment = @('Healthy') }
                [pscustomobject]@{ VmId = (& $vm 'cs-01').ToLowerInvariant(); VmName = 'cs-01'; resourceGroup = 'app'; subscriptionId = 's1'; OsType = 'Windows'; PowerState = 'PowerState/running'; Appliance = $false; DefenderExtension = 0; ThirdPartyEdr = $true; ThirdPartyExtensions = @('CrowdStrike.Falcon/FalconSensorWindows'); EdrAssessment = @('Healthy') }
                [pscustomobject]@{ VmId = (& $vm 'cs-02').ToLowerInvariant(); VmName = 'cs-02'; resourceGroup = 'app'; subscriptionId = 's1'; OsType = 'Linux'; PowerState = 'PowerState/running'; Appliance = $false; DefenderExtension = 0; ThirdPartyEdr = $false; ThirdPartyExtensions = @(); EdrAssessment = @() }
                [pscustomobject]@{ VmId = (& $vm 'fw-01' 'fw').ToLowerInvariant(); VmName = 'fw-01'; resourceGroup = 'fw'; subscriptionId = 's1'; OsType = 'Linux'; PowerState = 'PowerState/running'; Appliance = $true; DefenderExtension = 0; ThirdPartyEdr = $false; ThirdPartyExtensions = @(); EdrAssessment = @() }
                [pscustomobject]@{ VmId = (& $vm 'old-01').ToLowerInvariant(); VmName = 'old-01'; resourceGroup = 'app'; subscriptionId = 's1'; OsType = 'Windows'; PowerState = 'PowerState/running'; Appliance = $false; DefenderExtension = 0; ThirdPartyEdr = $false; ThirdPartyExtensions = @(); EdrAssessment = @('Unhealthy') }
                [pscustomobject]@{ VmId = (& $vm 'off-01').ToLowerInvariant(); VmName = 'off-01'; resourceGroup = 'app'; subscriptionId = 's1'; OsType = 'Windows'; PowerState = 'PowerState/deallocated'; Appliance = $false; DefenderExtension = 1; ThirdPartyEdr = $false; ThirdPartyExtensions = @(); EdrAssessment = @() }
                [pscustomobject]@{ VmId = (& $vm 'gap-01').ToLowerInvariant(); VmName = 'gap-01'; resourceGroup = 'app'; subscriptionId = 's1'; OsType = 'Windows'; PowerState = 'PowerState/running'; Appliance = $false; DefenderExtension = 0; ThirdPartyEdr = $false; ThirdPartyExtensions = @(); EdrAssessment = @('Unhealthy') }
                [pscustomobject]@{ VmId = (& $vm 'new-01').ToLowerInvariant(); VmName = 'new-01'; resourceGroup = 'app'; subscriptionId = 's1'; OsType = 'Windows'; PowerState = 'PowerState/running'; Appliance = $false; DefenderExtension = 0; ThirdPartyEdr = $false; ThirdPartyExtensions = @(); EdrAssessment = @() }
                [pscustomobject]@{ VmId = (& $vm 'dfc-01').ToLowerInvariant(); VmName = 'dfc-01'; resourceGroup = 'app'; subscriptionId = 's1'; OsType = 'Windows'; PowerState = 'PowerState/running'; Appliance = $false; DefenderExtension = 0; ThirdPartyEdr = $false; ThirdPartyExtensions = @(); EdrAssessment = @('Healthy') }
            )
            $hosts = @([pscustomobject]@{ Host = 'cs-02'; Events = 120; LastSeen = '2026-10-13T11:00:00Z'; Sources = @('CrowdStrikeFalconEventStream_CL') })
            $appliances = @([pscustomobject]@{ Name = 'fw-01'; ResourceId = (& $vm 'fw-01' 'fw').ToLowerInvariant() })
            $rows = @(Get-EbrOnboardingGapRows -Known $known -Azure $azure -Hosts $hosts -Appliances $appliances -KnownIsComplete $true)
            function Get-Gap([string]$name) { $rows | Where-Object DeviceName -eq $name | Select-Object -First 1 }
        }

        It 'lists every machine that is not onboarded with an active sensor, and nothing else' {
            $rows.DeviceName | Sort-Object | Should -Be @('cs-01.corp.example', 'cs-02', 'dfc-01', 'disc-01', 'fw-01', 'gap-01', 'imp-01', 'new-01', 'off-01', 'old-01')
            $rows | Where-Object DeviceName -eq 'web-01' | Should -BeNullOrEmpty
        }

        It 'finds a third-party product through the extension, the Sentinel host name or the Defender for Cloud assessment, and names it' {
            $ext = Get-Gap 'cs-01.corp.example'
            $ext.Reason | Should -Be 'Covered by a third-party endpoint detection product'
            $ext.Product | Should -Be 'CrowdStrike Falcon'
            $ext.Evidence | Should -Be 'Extension CrowdStrike.Falcon/FalconSensorWindows'
            @($ext.CountedAs, $ext.Eligible, $ext.Covered) | Should -Be @('CanBeOnboarded', $true, $true)
            $sentinel = Get-Gap 'cs-02'
            $sentinel.Product | Should -Be 'CrowdStrike Falcon'
            $sentinel.Evidence | Should -Be 'Reporting through Sentinel (CrowdStrikeFalconEventStream_CL), last seen 2026-10-13'
            $dfc = Get-Gap 'dfc-01'
            $dfc.Reason | Should -Be 'Covered by a third-party endpoint detection product'
            $dfc.Product | Should -Be 'a third-party endpoint detection product'
            $dfc.Evidence | Should -Be 'Defender for Cloud reports an EDR solution installed'
            $dfc.CountedAs | Should -Be 'NotSeen'
        }

        It 'explains appliances, unsupported systems, deallocated and discovered-only machines and leaves them out of the denominator' {
            (Get-Gap 'fw-01').Reason | Should -Be 'Network virtual appliance, cannot run a sensor'
            (Get-Gap 'fw-01').Eligible | Should -BeFalse
            (Get-Gap 'old-01').Reason | Should -Be 'Operating system not supported by the sensor'
            (Get-Gap 'old-01').CountedAs | Should -Be 'Other'
            (Get-Gap 'off-01').Reason | Should -Be 'Deallocated or stopped at collection'
            (Get-Gap 'off-01').PowerState | Should -Be 'deallocated'
            (Get-Gap 'off-01').Gap | Should -Be 'Sensor Inactive'
            (Get-Gap 'disc-01').Reason | Should -Be 'Discovered only, insufficient information'
            foreach ($n in 'fw-01', 'old-01', 'off-01', 'disc-01') { (Get-Gap $n).Covered | Should -BeFalse -Because $n }
        }

        It 'reports the real gaps: never discovered, sensor not active, and not onboarded with nothing else on the machine' {
            $new = Get-Gap 'new-01'
            @($new.Reason, $new.OnboardingStatus, $new.Gap, $new.CountedAs, $new.Eligible, $new.Covered) | Should -Be @('Not discovered by Defender for Endpoint', 'Not discovered', 'Not discovered', 'NotSeen', $true, $false)
            $new.OSPlatform | Should -Be 'Windows'
            $imp = Get-Gap 'imp-01'
            @($imp.Reason, $imp.Gap, $imp.CountedAs, $imp.Covered) | Should -Be @('Onboarded, sensor not active', 'Sensor Impaired communications', 'Onboarded', $true)
            $gap = Get-Gap 'gap-01'
            @($gap.Reason, $gap.CountedAs, $gap.Eligible, $gap.Covered) | Should -Be @('Not onboarded, no endpoint detection found', 'CanBeOnboarded', $true, $false)
            $gap.Evidence | Should -BeNullOrEmpty
        }

        It 'orders the rows by reason and never lists a machine Defender has not seen when the known list is incomplete' {
            $rows[0].Reason | Should -Be 'Network virtual appliance, cannot run a sensor'
            $rows[-1].Reason | Should -Be 'Not onboarded, no endpoint detection found'
            $partial = @(Get-EbrOnboardingGapRows -Known ($known | Where-Object OnboardingStatus -ne 'Onboarded') -Azure $azure -Hosts $hosts -Appliances $appliances -KnownIsComplete $false)
            $partial | Where-Object DeviceName -in 'new-01', 'dfc-01' | Should -BeNullOrEmpty
            ($partial | Where-Object DeviceName -eq 'cs-01.corp.example').Product | Should -Be 'CrowdStrike Falcon'
            $noAzure = @(Get-EbrOnboardingGapRows -Known $known -Azure $null -Hosts $null -Appliances $null -KnownIsComplete $false)
            ($noAzure | Where-Object DeviceName -eq 'cs-01.corp.example').Reason | Should -Be 'Not onboarded, no endpoint detection found'
            ($noAzure | Where-Object DeviceName -eq 'old-01').Reason | Should -Be 'Operating system not supported by the sensor'
        }

        It 'derives EW.1-GAPS from the context, UNAVAILABLE without the Defender device list' {
            $r = @{ 'EW.1-EDR' = (New-EbrResult -ResultId 'EW.1-EDR' -Status 'OK' -Rows $azure) }
            $ctx = [pscustomobject]@{ Results = $r }
            $none = New-EbrOnboardingGapResult -Ctx $ctx
            $none.Status | Should -Be 'UNAVAILABLE'
            $none.Detail | Should -Match 'Not a zero'
            $r['EW.1-VMS'] = New-EbrResult -ResultId 'EW.1-VMS' -Status 'OK' -Rows $known
            $r['EW.1-EDR-HOSTS'] = New-EbrResult -ResultId 'EW.1-EDR-HOSTS' -Status 'OK' -Rows $hosts
            $r['P0.6-APPLIANCES'] = New-EbrResult -ResultId 'P0.6-APPLIANCES' -Status 'OK' -Rows $appliances
            $full = New-EbrOnboardingGapResult -Ctx $ctx
            $full.Status | Should -Be 'OK'
            @($full.Rows).Count | Should -Be 10
            $full.Detail | Should -Match '^9 Azure virtual machines in Resource Graph\. 9 seen by Defender for Endpoint, 1 onboarded with an active sensor\. Not reporting with an active sensor, by reason: Covered by a third-party endpoint detection product: 3'
            $full.Detail | Should -Not -Match ';'
            # The derived item runs through the catalog like any other
            $item = (Get-EbrQueryCatalog) | Where-Object Id -eq 'EW.1-GAPS'
            $viaCatalog = Invoke-EbrCatalogItem -Ctx $ctx -Item $item
            $viaCatalog.ResultId | Should -Be 'EW.1-GAPS'
            @($viaCatalog.Rows).Count | Should -Be 10
            $r['EW.1-GAPS'] = $full
            (Get-EbrGapSummary $r) | Should -Match '^ Not reporting with an active sensor: 10\. By reason: covered by a third-party endpoint detection product \(3\)'
        }
    }

    It 'keeps the manifest guidance and titles to the copy rules: no semicolons, arrows or emoji, and the greater-than sign only in navigation steps' {
        $arrows = [regex]'[←-⇿➔➡▶►]|->|=>'
        $emoji = [regex]'[☀-➿\uD83C-\uDBFF]'
        foreach ($item in $catalog) {
            foreach ($text in @($item.Title, $item.Notes)) {
                $text | Should -Not -Match ';' -Because "$($item.Id): $text"
                $arrows.IsMatch($text) | Should -BeFalse -Because "$($item.Id): $text"
                $emoji.IsMatch($text) | Should -BeFalse -Because "$($item.Id): $text"
                $text | Should -Not -Match '<' -Because "$($item.Id): $text"
                # every > is a navigation step: a word, a space, the sign, a space, a word
                ($text -replace '[A-Za-z0-9)] > [A-Za-z]', '') | Should -Not -Match '>' -Because "$($item.Id): $text"
            }
        }
    }
}
