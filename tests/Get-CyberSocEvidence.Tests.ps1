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
            'OUT.1', 'OUT.2', 'OUT.3', 'OUT.4', 'OUT.5', 'OUT.6', 'OUT.7',
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

    It 'runs no data loss, exfiltration or compromise check (CyberSOC)' {
        $catalog.Id | Should -Not -Contain 'OUT.8' -Because 'the account disable events only fed the malicious sign-in to containment timing'
        $out4 = $catalog | Where-Object Id -eq 'OUT.4'
        $out4.Query | Should -Not -Match 'ExfilOrImpactTactic|Exfiltration'
        "$($out4.Title) $($out4.Notes)" | Should -Not -Match 'data loss|contain'
        ($catalog | Where-Object Id -eq 'TI.5-RISK').Query | Should -Match '\| where RiskEventType !~ "adminConfirmedUserCompromised"' -Because 'an administrator compromise confirmation is not a detection'
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
        ($catalog | Where-Object Id -eq 'TI.1').Query | Should -Match 'TimeGenerated between \(endofday\(\{\{WINDOW_END\}\}\) - 365d \.\. endofday\(\{\{WINDOW_END\}\}\)\)' -Because 'an indicator ingested before the window and still valid at its end is monitored'
        ($catalog | Where-Object Id -eq 'TI.1').Query | Should -Not -Match 'now\(\)'
        foreach ($id in 'TI.0', 'POS.8') {
            $q = ($catalog | Where-Object Id -eq $id).Query
            $q | Should -Match 'TimeGenerated between \(\{\{WINDOW_START\}\} \.\. endofday\(\{\{WINDOW_END\}\}\)\)' -Because "$id reads the report window, not the days after it up to collection"
            $q | Should -Not -Match 'now\(\)' -Because $id
        }
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

    It 'adds the per-resource hardening lists the change requests read, each with the gap its parent count reads' {
        foreach ($id in 'P0.7', 'NB.4-DETAIL', 'NB.5-DETAIL', 'NB.6-DETAIL', 'DP.1-DETAIL', 'DP.2-DETAIL', 'DR.6-COVERAGE', 'DR.6-NONCOMPLIANT') {
            $item = $catalog | Where-Object Id -eq $id
            $item.Engine | Should -Be 'ARG' -Because $id
            $item.Notes | Should -Match '^Added in CyberSOC 1\.1\.0\.' -Because $id
        }
        ($catalog | Where-Object Id -eq 'P0.7').Query | Should -Match 'resourcecontainers'
        ($catalog | Where-Object Id -eq 'NB.4-DETAIL').Query | Should -Match 'where not\(coalesce\(tobool\(properties\.httpsOnly\), false\)\)'
        ($catalog | Where-Object Id -eq 'NB.5-DETAIL').Query | Should -Match 'coalesce\(properties\.MinTlsVersion, properties\.minTlsVersion\)' -Because 'appserviceresources returns the config keys in PascalCase'
        ($catalog | Where-Object Id -eq 'NB.5-DETAIL').Query | Should -Match 'where not\(MinTlsVersion in \("1\.2", "1\.3"\)\) or not\(ScmMinTlsVersion in \("1\.2", "1\.3"\)\)' -Because 'an app is listed when the site or the SCM site minimum is below 1.2 or empty (1.13.0)'
        ($catalog | Where-Object Id -eq 'NB.6-DETAIL').Query | Should -Match 'where not\(MinimalTlsVersion in \("1\.2", "1\.3"\)\)'
        $paas = $catalog | Where-Object Id -eq 'NB.6-PAAS-DETAIL'
        $paas.Engine | Should -Be 'ARG'
        $paas.Notes | Should -Match '^Added in CyberSOC 1\.2\.0\.'
        $paas.Query | Should -Match 'where type in~ \("microsoft\.cache/redis", "microsoft\.servicebus/namespaces",\s+"microsoft\.eventhub/namespaces", "microsoft\.documentdb/databaseaccounts"\)'
        $paas.Query | Should -Match 'id !contains "\{\{MRG\}\}"'
        $paas.Query | Should -Match 'MinimumTlsVersion = tostring\(coalesce\(properties\.minimumTlsVersion, properties\.minimalTlsVersion\)\)' -Because 'Cosmos DB names the property minimalTlsVersion'
        $paas.Query | Should -Match 'where not\(MinimumTlsVersion in \("1\.2", "1\.3", "Tls12", "Tls13"\)\)' -Because 'a missing value reads as empty and stays in the list'
        $paas.Query | Should -Match 'project Name = name, ResourceId = id, ResourceType, resourceGroup, subscriptionId, MinimumTlsVersion'
        $dp1 = ($catalog | Where-Object Id -eq 'DP.1-DETAIL').Query
        $dp1 | Should -Match 'AllowBlobPublicAccess = coalesce\(tobool\(properties\.allowBlobPublicAccess\), true\)' -Because 'a missing setting means anonymous access is allowed, as in DP.1'
        $dp1 | Should -Match 'NfsV3\s+= coalesce\(tobool\(properties\.isNfsV3Enabled\), false\)'
        $dp1 | Should -Match 'where not\(SecureTransfer\) or not\(MinimumTlsVersion in \("TLS1_2", "TLS1_3"\)\) or AllowBlobPublicAccess'
        ($catalog | Where-Object Id -eq 'DP.2-DETAIL').Query | Should -Match 'where not\(coalesce\(tobool\(properties\.enablePurgeProtection\), false\)\)'
        ($catalog | Where-Object Id -eq 'DP.2-DETAIL').Query | Should -Match 'RetentionDays = coalesce\(toint\(properties\.softDeleteRetentionInDays\), 90\)'
        $dr6 = ($catalog | Where-Object Id -eq 'DR.6-NONCOMPLIANT').Query
        $dr6 | Should -Match 'Compliance =~ "NonCompliant"'
        $dr6 | Should -Match 'where AssignmentName contains "ATMO-MXDR" or InitiativeName contains "ATMO-MXDR" or DefinitionName contains "ATMO-MXDR"' -Because 'it lists exactly the resources DR.6-INITIATIVE counts'
        $dr6 | Should -Match 'ResourceId !contains "\{\{MRG\}\}"'
        $dr6 | Should -Match 'AssignmentId   = tolower\(tostring\(properties\.policyAssignmentId\)\)'
        $dr6 | Should -Match 'by ResourceId, ResourceType, AssignmentName, AssignmentId, AssignmentScope' -Because 'a remediation task belongs to one assignment, and same-named assignments in two subscriptions stay apart'
        $dr6 | Should -Match 'AssignmentScope = tostring\(properties\.policyAssignmentScope\)' -Because 'the scope keeps the case the portal shows'
        $coverage = ($catalog | Where-Object Id -eq 'DR.6-COVERAGE').Query
        $coverage | Should -Match 'where AssignmentName contains "ATMO-MXDR-DIAG" or InitiativeName contains "ATMO-MXDR-DIAG"' -Because 'only the diagnostic logging initiative covers a subscription'
        $coverage | Should -Match 'where AssignmentScope !contains "/resourcegroups/"' -Because 'an assignment on one resource group leaves the rest of the subscription out'
        $coverage | Should -Match 'by subscriptionId = SubscriptionKey'
        $eah = $catalog | Where-Object Id -eq 'DP.4-ELIGIBILITY'
        $eah.Engine | Should -Be 'COMPUTE-SKUS'
        $eah.Notes | Should -Match '^Added in CyberSOC 1\.1\.0\.'
        $eah.Query | Should -Match 'where type =~ "microsoft\.compute/virtualmachines"'
        $eah.Query | Should -Match 'id !contains "\{\{MRG\}\}"'
        $eah.Query | Should -Match 'where not\(\{\{APPLIANCE\}\}\)' -Because 'network virtual appliances leave DP.4 and DP.4-DETAIL too'
        $eah.Query | Should -Match 'where not\(coalesce\(tobool\(properties\.securityProfile\.encryptionAtHost\), false\)\)'
        $eah.Query | Should -Match 'isnotnull\(properties\.encryptionSettingsCollection\)' -Because 'a disk that ever carried Azure Disk Encryption keeps its settings'
        $eah.Query | Should -Match '"AzureDiskEncryption", "AzureDiskEncryptionForLinux"'
        $eah.Query | Should -Match 'project Name, ResourceId, resourceGroup, subscriptionId, Location, Size, PowerState, ScaleSet, VmId, AdeUsed, OldSectorDisk'
        $eah.Query | Should -Match 'VmId = tostring\(properties\.vmId\)' -Because 'CR-09 and CR-15 match each machine by its VM ID, never by its name alone'
        $eah.Notes | Should -Match 'Since CyberSOC 1\.4\.0 each row carries VmId \(properties\.vmId\)'
        $eah.Query | Should -Match 'ScaleSet = tolower\(tostring\(properties\.virtualMachineScaleSet\.id\)\)' -Because 'a Flexible scale set instance is a virtual machine that CR-15 handles with its scale set'
        $eah.Notes | Should -Match 'Since CyberSOC 1\.3\.0 each row carries ScaleSet'
        $eah.Query | Should -Match 'where todatetime\(properties\.timeCreated\) < datetime\(2023-05-13\)' -Because 'a 512e Ultra or Premium SSD v2 disk created before then rules out encryption at host'
    }

    It 'lists the scale sets without encryption at host with what decides whether the model can take it (1.3.0, unique ID 1.4.0)' {
        $ss = $catalog | Where-Object Id -eq 'DP.4-VMSS-ELIGIBILITY'
        $ss.Engine | Should -Be 'COMPUTE-SKUS'
        $ss.Notes | Should -Match '^Added in CyberSOC 1\.3\.0\.'
        $ss.Query | Should -Match 'where type =~ "microsoft\.compute/virtualmachinescalesets"'
        $ss.Query | Should -Match 'id !contains "\{\{MRG\}\}"'
        $ss.Query | Should -Match 'where not\(\{\{APPLIANCE\}\}\)' -Because 'DP.4 and DP.4-DETAIL leave network virtual appliances out'
        $ss.Query | Should -Match 'where not\(coalesce\(tobool\(properties\.virtualMachineProfile\.securityProfile\.encryptionAtHost\), false\)\)' -Because 'the setting goes on the model'
        $ss.Query | Should -Match 'OrchestrationMode = coalesce\(tostring\(properties\.orchestrationMode\), "Uniform"\)' -Because 'a scale set created before Flexible orchestration records no mode'
        $ss.Query | Should -Match 'UpgradePolicy\s+= tostring\(properties\.upgradePolicy\.mode\)'
        $ss.Query | Should -Match 'Instances\s+= toint\(sku\.capacity\)'
        $ss.Query | Should -Match 'AdeUsed\s+= tostring\(Model\.extensionProfile\.extensions\) contains "AzureDiskEncryption"' -Because 'both the Windows and the Linux extension carry the name'
        $ss.Query | Should -Match 'has_any \("UltraSSD_LRS", "PremiumV2_LRS"\)\s+and coalesce\(todatetime\(properties\.timeCreated\), datetime\(2000-01-01\)\) < datetime\(2023-05-13\)' -Because 'a scale set without a creation time cannot prove its disks are recent'
        $ss.Query | Should -Match 'tolower\(tostring\(properties\.nodeResourceGroup\)\)' -Because 'an AKS node pool lives in the node resource group of its cluster'
        $ss.Query | Should -Match 'AksNodePool\s+= tostring\(tags\["aks-managed-poolName"\]\)'
        $ss.Query | Should -Match 'Aks\s+= isnotempty\(AksCluster\) or tostring\(bag_keys\(tags\)\) contains "aks-managed-"'
        $ss.Query | Should -Match 'UniqueId\s+= tostring\(properties\.uniqueId\)' -Because 'CR-15 matches each scale set by its unique ID, never by its name alone'
        $ss.Notes | Should -Match 'Since CyberSOC 1\.4\.0 each row carries UniqueId \(properties\.uniqueId\)'
        $ss.Query | Should -Match 'project Name = name, ResourceId = id, resourceGroup, subscriptionId, Location = tolower\(location\), OrchestrationMode,\s+UpgradePolicy, Instances, Size, UniqueId, HasModel, AdeUsed, OldSectorDisk, Aks, AksCluster, AksClusterResourceGroup, AksNodePool'
        ([regex]::Matches($ss.Query, 'join kind=')).Count | Should -BeLessOrEqual 3 -Because 'Resource Graph allows three joins per query'
    }

    It 'reads the SCM (Kudu) site minimum TLS version beside the site minimum in NB.5-DETAIL (1.13.0)' {
        $d = $catalog | Where-Object Id -eq 'NB.5-DETAIL'
        $d.Notes | Should -Match 'Added in CyberSOC 1\.13\.0: ScmMinTlsVersion, the minimum inbound TLS version of the SCM \(Kudu\) site'
        $d.Notes | Should -Match 'Deployment slots \(sites/slots/config\) are not read\.'
        $d.Query | Should -MatchExactly 'ScmMinTlsVersion = tostring\(coalesce\(properties\.ScmMinTlsVersion, properties\.scmMinTlsVersion\)\)' -Because 'appserviceresources returns the config keys in PascalCase, as for MinTlsVersion'
        $d.Query | Should -Match 'subscriptionId = tostring\(Parts\[2\]\), MinTlsVersion, ScmMinTlsVersion\r?\n'
        $d.Query | Should -Match 'where id !contains "\{\{MRG\}\}"'
    }

    It 'reads FTP basic authentication per App Service app through a GET on its basicPublishingCredentialsPolicies/ftp path (1.14.0)' {
        $item = $catalog | Where-Object Id -eq 'NB.5-FTPAUTH'
        $item.Engine | Should -Be 'APPSERVICE-FTPAUTH'
        $item.Phase | Should -Be 'P2 Network'
        $item.Notes | Should -Match '^Added in CyberSOC 1\.14\.0\. Resource Graph does not index basicPublishingCredentialsPolicies'
        $item.Notes | Should -Match 'It also writes NB\.5-FTPAUTH-DETAIL, one row per app where FTP basic authentication is On, whatever its FTP state, for change request CR-17\.'
        $item.Notes | Should -Match 'Internal: names sites, the report embeds counts only\.'
        $item.Query | Should -Match 'appserviceresources\r?\n\| where type =~ "microsoft\.web/sites/config"\r?\n\| where id !contains "\{\{MRG\}\}"'
        $item.Query | Should -MatchExactly 'coalesce\(properties\.FtpsState, properties\.ftpsState\)' -Because 'appserviceresources returns the config keys in PascalCase'
        $item.Query | Should -Not -Match '\| where not\(' -Because 'every app is read, an app already set to FTPS only or Disabled included'
        $item.Query | Should -Match 'subscriptionId = tostring\(Parts\[2\]\), FtpsState\r?\n'
        { Assert-EbrReadOnlyRequest -Method GET -Uri 'https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.Web/sites/a/basicPublishingCredentialsPolicies/ftp?api-version=2022-09-01' } | Should -Not -Throw
    }
    It 'reads the audit log parameters of every MySQL flexible server through a GET on its configurations (1.15.0)' {
        $item = $catalog | Where-Object Id -eq 'DR.6-MYSQLAUDIT'
        $item.Engine | Should -Be 'MYSQL-AUDIT'
        $item.Phase | Should -Be 'P2 Detection and response'
        $item.Notes | Should -Match '^Added in CyberSOC 1\.15\.0\. Server parameters are not in Resource Graph'
        $item.Notes | Should -Match 'Every server is read, not only the ones DR\.6-NONCOMPLIANT names'
        $item.Notes | Should -Match 'audit_log_include_users and audit_log_exclude_users paths' -Because 'the user filters decide which users are audited'
        $item.Notes | Should -Match 'Feeds change requests CR-01 and CR-10\. Internal: names servers, the report embeds counts only\.'
        $item.Query | Should -Match 'resources\r?\n\| where type =~ "microsoft\.dbformysql/flexibleservers"\r?\n\| where id !contains "\{\{MRG\}\}"'
        $item.Query | Should -Match 'project Name = name, ResourceId = id, resourceGroup, subscriptionId, State = tostring\(properties\.state\), PolicyState'
        $item.Query | Should -Match 'join kind=leftouter \(\r?\n    policyresources' -Because 'each server is proven by its own ATMO-MXDR policy state'
        $item.Query | Should -Match 'extend PolicyState = case\(coalesce\(NonCompliant, 0\) > 0, "NonCompliant", coalesce\(Compliant, 0\) > 0, "Compliant", ""\)'
        ([regex]::Matches($item.Query, 'join kind=')).Count | Should -Be 1 -Because 'Resource Graph allows one cross-table join'
        foreach ($name in 'audit_log_enabled', 'audit_log_events', 'audit_log_include_users', 'audit_log_exclude_users') {
            { Assert-EbrReadOnlyRequest -Method GET -Uri "https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.DBforMySQL/flexibleServers/m/configurations/$($name)?api-version=2023-12-30" } | Should -Not -Throw
        }
    }
    It 'records both audit parameters as the server returns them, whether they apply without a restart, and a server it cannot read as not read' {
        $server = [pscustomobject]@{ ResourceId = '/subscriptions/s/resourceGroups/rg-db/providers/Microsoft.DBforMySQL/flexibleServers/mysql-a'; Name = 'mysql-a'; resourceGroup = 'rg-db'; subscriptionId = 's'; State = 'Ready'; PolicyState = 'Compliant' }
        Mock Invoke-EbrRest {
            $v = switch -Regex ($Uri) { 'audit_log_enabled' { 'OFF' } 'audit_log_events' { 'CONNECTION' } 'audit_log_exclude_users' { 'svc_backup' } default { '' } }
            # The user filters read as static on purpose: the change leaves them as they are, so they never decide a restart.
            [pscustomobject]@{ name = 'x'; properties = [pscustomobject]@{ value = $v; isDynamicConfig = $(if ($Uri -match 'users') { 'False' } else { 'True' }); defaultValue = $v } }
        }
        $r = Get-EbrMySqlAuditRow -Server $server -Tenant 't'
        @($r.subscriptionId, $r.resourceGroup, $r.Name, $r.State, $r.PolicyState, $r.AuditLogEnabled, $r.AuditLogEvents, $r.AuditLogIncludeUsers, $r.AuditLogExcludeUsers, $r.PendingRestart, $r.Dynamic, $r.ReadStatus, $r.ResourceId) | Should -Be @('s', 'rg-db', 'mysql-a', 'Ready', 'Compliant', 'OFF', 'CONNECTION', '', 'svc_backup', '', 'Yes', 'OK', $server.ResourceId)
        foreach ($name in 'audit_log_enabled', 'audit_log_events', 'audit_log_include_users', 'audit_log_exclude_users') {
            Should -Invoke Invoke-EbrRest -Times 1 -Exactly -ParameterFilter { $Method -eq 'GET' -and $Uri -eq "https://management.azure.com/subscriptions/s/resourceGroups/rg-db/providers/Microsoft.DBforMySQL/flexibleServers/mysql-a/configurations/$($name)?api-version=2023-12-30" -and $Resource -eq 'https://management.azure.com/' }
        }
        Mock Invoke-EbrRest { [pscustomobject]@{ properties = [pscustomobject]@{ value = $(if ($Uri -match 'audit_log_enabled') { 'ON' } else { '' }); isDynamicConfig = $(if ($Uri -match 'audit_log_events') { 'False' } else { 'True' }) } } }
        $r = Get-EbrMySqlAuditRow -Server $server -Tenant 't'
        @($r.AuditLogEnabled, $r.AuditLogEvents, $r.Dynamic, $r.ReadStatus) | Should -Be @('ON', '', 'No', 'OK') -Because 'an empty event list is a reading, and one static parameter needs a restart'
        Mock Invoke-EbrRest { [pscustomobject]@{ properties = [pscustomobject]@{ value = 'ON' } } }
        (Get-EbrMySqlAuditRow -Server $server -Tenant 't').Dynamic | Should -Be '' -Because 'a response that does not report it leaves it unknown'
        # A static parameter saved with Restart later: value holds the saved setting, currentValue the one in effect.
        Mock Invoke-EbrRest {
            if ($Uri -match 'audit_log_enabled') { return [pscustomobject]@{ properties = [pscustomobject]@{ value = 'ON'; currentValue = 'OFF'; isDynamicConfig = 'False'; isConfigPendingRestart = 'True' } } }
            [pscustomobject]@{ properties = [pscustomobject]@{ value = $(if ($Uri -match 'audit_log_events') { 'CONNECTION,ADMIN,DDL,DCL' } else { '' }); currentValue = $(if ($Uri -match 'audit_log_events') { 'CONNECTION,ADMIN,DDL,DCL' } else { '' }); isDynamicConfig = 'False'; isConfigPendingRestart = 'False' } } }
        $r = Get-EbrMySqlAuditRow -Server $server -Tenant 't'
        @($r.AuditLogEnabled, $r.PendingRestart, $r.Dynamic) | Should -Be @('OFF', 'Yes', 'No') -Because 'the value in effect is recorded, and the saved one waits for a restart'
        Mock Invoke-EbrRest { [pscustomobject]@{ properties = [pscustomobject]@{ value = 'ON'; currentValue = 'ON'; isDynamicConfig = 'True'; isConfigPendingRestart = 'False' } } }
        (Get-EbrMySqlAuditRow -Server $server -Tenant 't').PendingRestart | Should -Be 'No'
        Mock Invoke-EbrRest { if ($Uri -match 'audit_log_events') { return [pscustomobject]@{ properties = [pscustomobject]@{ } } }; [pscustomobject]@{ properties = [pscustomobject]@{ value = 'ON'; isDynamicConfig = 'True' } } }
        $r = Get-EbrMySqlAuditRow -Server $server -Tenant 't'
        @($r.AuditLogEnabled, $r.AuditLogEvents, $r.Dynamic, $r.ReadStatus) | Should -Be @('', '', '', 'The audit_log_events response carried no properties.value.') -Because 'a server half read is not read'
        Mock Invoke-EbrRest { if ($Uri -match 'audit_log_exclude_users') { throw 'HTTP 500: Internal Server Error' }; [pscustomobject]@{ properties = [pscustomobject]@{ value = 'ON'; isDynamicConfig = 'True' } } }
        $r = Get-EbrMySqlAuditRow -Server $server -Tenant 't'
        @($r.AuditLogEnabled, $r.AuditLogExcludeUsers) | Should -Be @('', '') -Because 'a user filter that was not read could leave users out, so the server is not read'
        $r.ReadStatus | Should -Match '^audit_log_exclude_users: HTTP 500'
        Mock Invoke-EbrRest { throw 'HTTP 403: Forbidden | AuthorizationFailed' }
        $r = Get-EbrMySqlAuditRow -Server $server -Tenant 't'
        $r.AuditLogEnabled | Should -Be ''
        $r.ReadStatus | Should -Match '^audit_log_enabled: .*403'
    }
    It 'reads every MySQL flexible server, and never reads a partial or failed read as complete' {
        New-Item -ItemType Directory -Path (Join-Path $TestDrive 'queries') -Force | Out-Null
        $ctx = [pscustomobject]@{ WindowStart = [datetime]'2026-07-01'; WindowEnd = [datetime]'2026-09-30'; ManagedRgPattern = 'aznativesol0'; OutDir = $TestDrive; Subscriptions = @('s1'); ArmTenant = 't'; AccessPath = ''; Pending = [System.Collections.Generic.List[object]]::new() }
        $item = Get-EbrQueryCatalog | Where-Object Id -eq 'DR.6-MYSQLAUDIT'
        $server = { param($n) [pscustomobject]@{ Name = $n; ResourceId = "/subscriptions/s1/resourceGroups/rg-db/providers/Microsoft.DBforMySQL/flexibleServers/$n"; resourceGroup = 'rg-db'; subscriptionId = 's1'; State = 'Ready' } }
        $servers = @((& $server 'mysql-off'), (& $server 'mysql-on'))
        Mock Invoke-EbrArgQuery { [pscustomobject]@{ Rows = $servers; Detail = '' } }
        Mock Invoke-EbrRest { [pscustomobject]@{ properties = [pscustomobject]@{ value = $(if ($Uri -match 'audit_log_events') { 'CONNECTION,ADMIN,DDL,DCL' } elseif ($Uri -match 'mysql-on') { 'ON' } else { 'OFF' }); isDynamicConfig = 'True' } } }
        $res = Invoke-EbrCatalogItem -Ctx $ctx -Item $item
        $res.Status | Should -Be 'OK'
        $res.Detail | Should -Be '2 of 2 MySQL flexible servers read: audit_log_enabled ON in 1, not ON in 1.'
        @($res.Rows)[0].PSObject.Properties.Name | Should -Be @('subscriptionId', 'resourceGroup', 'Name', 'State', 'PolicyState', 'AuditLogEnabled', 'AuditLogEvents', 'AuditLogIncludeUsers', 'AuditLogExcludeUsers', 'PendingRestart', 'Dynamic', 'ReadStatus', 'ResourceId')
        $ctx.Pending.Count | Should -Be 0 -Because 'one result holds every server'
        Mock Invoke-EbrRest { if ($Uri -match 'mysql-on') { throw 'HTTP 429: Too Many Requests' }; [pscustomobject]@{ properties = [pscustomobject]@{ value = 'OFF'; isDynamicConfig = 'True' } } }
        $res = Invoke-EbrCatalogItem -Ctx $ctx -Item $item
        $res.Status | Should -Be 'PARTIAL' -Because 'a server not read may have audit_log_enabled OFF'
        ($res.Rows | Where-Object Name -eq 'mysql-on').ReadStatus | Should -Match '429'
        $res.Detail | Should -Match 'Not read: mysql-on: audit_log_enabled: HTTP 429'
        Mock Invoke-EbrRest { [pscustomobject]@{ properties = [pscustomobject]@{ value = 'ON'; isDynamicConfig = 'True' } } }
        Mock Invoke-EbrArgQuery { [pscustomobject]@{ Rows = $servers; Detail = 'Truncated at 1000 rows.' } }
        (Invoke-EbrCatalogItem -Ctx $ctx -Item $item).Status | Should -Be 'PARTIAL' -Because 'a truncated Resource Graph result leaves servers out'
        Mock Invoke-EbrArgQuery { [pscustomobject]@{ Rows = $servers; Detail = '' } }
        Mock Invoke-EbrRest { throw 'HTTP 403: Forbidden' }
        (Invoke-EbrCatalogItem -Ctx $ctx -Item $item).Status | Should -Be 'FAILED' -Because 'no server was read'
        Mock Invoke-EbrArgQuery { [pscustomobject]@{ Rows = @(); Detail = '' } }
        (Invoke-EbrCatalogItem -Ctx $ctx -Item $item).Status | Should -Be 'EMPTY'
        Mock Invoke-EbrArgQuery { throw 'HTTP 403: Forbidden' }
        (Invoke-EbrCatalogItem -Ctx $ctx -Item $item).Status | Should -Be 'FAILED'
    }
    It 'records FTP basic authentication On or Off from properties.allow, and an app it cannot read as not read, never as Off' {
        $site = [pscustomobject]@{ ResourceId = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Web/sites/app-a'; Name = 'app-a'; resourceGroup = 'rg'; subscriptionId = 's'; FtpsState = 'FtpsOnly' }
        Mock Invoke-EbrRest { [pscustomobject]@{ name = 'ftp'; properties = [pscustomobject]@{ allow = $true } } }
        $r = Get-EbrFtpBasicAuthRow -Site $site -Tenant 't'
        @($r.subscriptionId, $r.resourceGroup, $r.Name, $r.FtpsState, $r.FtpBasicAuth, $r.ReadStatus, $r.ResourceId) | Should -Be @('s', 'rg', 'app-a', 'FtpsOnly', 'On', 'OK', $site.ResourceId)
        Should -Invoke Invoke-EbrRest -ParameterFilter { $Method -eq 'GET' -and $Uri -eq 'https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.Web/sites/app-a/basicPublishingCredentialsPolicies/ftp?api-version=2022-09-01' -and $Resource -eq 'https://management.azure.com/' }
        Mock Invoke-EbrRest { [pscustomobject]@{ properties = [pscustomobject]@{ allow = $false } } }
        (Get-EbrFtpBasicAuthRow -Site $site -Tenant 't').FtpBasicAuth | Should -Be 'Off'
        Mock Invoke-EbrRest { [pscustomobject]@{ properties = [pscustomobject]@{ } } }
        $r = Get-EbrFtpBasicAuthRow -Site $site -Tenant 't'
        @($r.FtpBasicAuth, $r.ReadStatus) | Should -Be @('', 'The response carried no properties.allow value.')
        Mock Invoke-EbrRest { throw 'HTTP 403: Forbidden | AuthorizationFailed' }
        $r = Get-EbrFtpBasicAuthRow -Site $site -Tenant 't'
        $r.FtpBasicAuth | Should -Be ''
        $r.ReadStatus | Should -Match '403'
    }
    It 'writes NB.5-FTPAUTH-DETAIL with every outcome of NB.5-FTPAUTH, listing every app where it is On whatever its FTP state' {
        New-Item -ItemType Directory -Path (Join-Path $TestDrive 'queries') -Force | Out-Null
        $ctx = [pscustomobject]@{ WindowStart = [datetime]'2026-07-01'; WindowEnd = [datetime]'2026-09-30'; ManagedRgPattern = 'aznativesol0'; OutDir = $TestDrive; Subscriptions = @('s1'); ArmTenant = 't'; AccessPath = ''; Pending = [System.Collections.Generic.List[object]]::new() }
        $item = Get-EbrQueryCatalog | Where-Object Id -eq 'NB.5-FTPAUTH'
        $site = { param($n, $state) [pscustomobject]@{ Name = $n; ResourceId = "/subscriptions/s1/resourceGroups/rg-web/providers/Microsoft.Web/sites/$n"; resourceGroup = 'rg-web'; subscriptionId = 's1'; FtpsState = $state } }
        $sites = @((& $site 'app-plain' 'AllAllowed'), (& $site 'app-ftps' 'FtpsOnly'), (& $site 'func-off' 'Disabled'), (& $site 'app-secure' 'FtpsOnly'))
        Mock Invoke-EbrArgQuery { [pscustomobject]@{ Rows = $sites; Detail = '' } }
        Mock Invoke-EbrRest { [pscustomobject]@{ properties = [pscustomobject]@{ allow = ($Uri -notmatch 'app-secure') } } }
        $res = Invoke-EbrCatalogItem -Ctx $ctx -Item $item
        $res.Status | Should -Be 'OK'
        @($res.Rows).Count | Should -Be 4
        $res.Detail | Should -Be '4 of 4 App Service apps read: FTP basic authentication On in 3, Off in 1.'
        $d = $ctx.Pending[0]
        @($d.ResultId, $d.Status) | Should -Be @('NB.5-FTPAUTH-DETAIL', 'OK')
        @($d.Rows | ForEach-Object { '{0}|{1}|{2}' -f $_.Name, $_.FtpsState, $_.FtpBasicAuth }) | Should -Be @('app-plain|AllAllowed|On', 'app-ftps|FtpsOnly|On', 'func-off|Disabled|On') -Because 'FTP basic authentication matters on every app, FtpsOnly and Disabled included'
        @($d.Rows)[0].PSObject.Properties.Name | Should -Be @('subscriptionId', 'resourceGroup', 'Name', 'FtpsState', 'FtpBasicAuth', 'ResourceId')
        $ctx.Pending.Clear()
        Mock Invoke-EbrRest { if ($Uri -match 'app-ftps') { throw 'HTTP 429: Too Many Requests' }; [pscustomobject]@{ properties = [pscustomobject]@{ allow = $true } } }
        $res = Invoke-EbrCatalogItem -Ctx $ctx -Item $item
        @($res.Status, $ctx.Pending[0].Status) | Should -Be @('PARTIAL', 'PARTIAL') -Because 'an app not read may have it On'
        ($res.Rows | Where-Object Name -eq 'app-ftps').ReadStatus | Should -Match '429'
        $res.Detail | Should -Match 'Not read: app-ftps: HTTP 429'
        @($ctx.Pending[0].Rows).Name | Should -Not -Contain 'app-ftps'
        $ctx.Pending[0].Detail | Should -Match 'Apps not read add no rows, see NB\.5-FTPAUTH\.$'
        $ctx.Pending.Clear()
        Mock Invoke-EbrRest { [pscustomobject]@{ properties = [pscustomobject]@{ allow = $false } } }
        Mock Invoke-EbrArgQuery { [pscustomobject]@{ Rows = $sites; Detail = 'Truncated at 1000 rows.' } }
        $res = Invoke-EbrCatalogItem -Ctx $ctx -Item $item
        @($res.Status, $ctx.Pending[0].Status) | Should -Be @('PARTIAL', 'PARTIAL') -Because 'a truncated Resource Graph result leaves apps out'
        $ctx.Pending.Clear()
        Mock Invoke-EbrArgQuery { [pscustomobject]@{ Rows = $sites; Detail = '' } }
        $null = Invoke-EbrCatalogItem -Ctx $ctx -Item $item
        $ctx.Pending[0].Status | Should -Be 'EMPTY' -Because 'every app has it Off'
        $ctx.Pending.Clear()
        Mock Invoke-EbrRest { throw 'HTTP 403: Forbidden' }
        (Invoke-EbrCatalogItem -Ctx $ctx -Item $item).Status | Should -Be 'FAILED' -Because 'no app was read'
        $ctx.Pending[0].Status | Should -Be 'FAILED'
        $ctx.Pending.Clear()
        Mock Invoke-EbrArgQuery { [pscustomobject]@{ Rows = @(); Detail = '' } }
        (Invoke-EbrCatalogItem -Ctx $ctx -Item $item).Status | Should -Be 'EMPTY'
        $ctx.Pending[0].Status | Should -Be 'EMPTY'
        $ctx.Pending.Clear()
        Mock Invoke-EbrArgQuery { throw 'Resource Graph throttled' }
        (Invoke-EbrCatalogItem -Ctx $ctx -Item $item).Status | Should -Be 'FAILED'
        $ctx.Pending[0].Status | Should -Be 'FAILED'
        $ctx.Pending[0].Detail | Should -Match 'throttled'
    }

    It 'lists the virtual machines without periodic assessment, with what CR-23 leaves out, outside the managed resource group (1.18.0)' {
        $item = $catalog | Where-Object Id -eq 'EW.10-ASSESSMENT'
        $item.Engine | Should -Be 'PATCH-ASSESSMENT'
        $item.Phase | Should -Be 'P2 Endpoint'
        $item.Notes | Should -Match '^Added in CyberSOC 1\.18\.0\.'
        $item.Notes | Should -Match 'PatchMode is kept for context only, since CR-23 changes the assessment mode alone'
        $q = $item.Query
        $q | Should -Match 'where type =~ "microsoft\.compute/virtualmachines"'
        $q | Should -Match 'where id !contains "\{\{MRG\}\}"'
        $q | Should -Match 'extend Os = iff\(OsType =~ "Linux", properties\.osProfile\.linuxConfiguration, properties\.osProfile\.windowsConfiguration\)' -Because 'Linux and Windows keep patchSettings apart'
        $q | Should -Match 'extend AssessmentMode = tostring\(Os\.patchSettings\.assessmentMode\)\r?\n\| where AssessmentMode !~ "AutomaticByPlatform"' -Because 'an empty value is listed too'
        $q | Should -Match 'PatchMode        = tostring\(Os\.patchSettings\.patchMode\)'
        $q | Should -Match 'Appliance        = \{\{APPLIANCE\}\}'
        $q | Should -Match 'Aks              = isnotempty\(AksCluster\) or tostring\(bag_keys\(tags\)\) contains "aks-managed-"'
        $q | Should -Match 'WindowsClient = OsType =~ "Windows" and \(ImagePublisher =~ "microsoftwindowsdesktop" or OsName has_any \("Windows 10", "Windows 11"\)\)'
        $q | Should -Match 'GuestPatchSupport = tostring\(properties\.configurationStatus\.vmGuestPatchReadiness\.detectedVMGuestPatchSupportState\)'
        $q | Should -Match 'extend PatchExcluded = false\r?\n\| extend PatchExcluded = tolower\(tostring\(tags\)\) matches regex @"\{\{PATCH_EXCLUDED\}\}"'
        $expanded = Expand-EbrQuery -Query $q -WindowStart ([datetime]'2026-01-01') -WindowEnd ([datetime]'2026-06-30') -ManagedRgPattern 'aznativesol0' -PatchExclusionTagPattern 'patch.*waived'
        $expanded | Should -Match 'id !contains "aznativesol0"'
        $expanded | Should -Match 'Appliance        = tolower\(strcat\('
        $expanded | Should -Not -Match '\{\{'
        $off = Expand-EbrQuery -Query $q -WindowStart ([datetime]'2026-01-01') -WindowEnd ([datetime]'2026-06-30') -ManagedRgPattern 'aznativesol0' -PatchExclusionTagPattern ''
        $off | Should -Match 'extend PatchExcluded = false' -Because 'with the tag exclusion off, no machine reads as tagged'
        $off | Should -Not -Match 'matches regex @""'
    }

    It 'marks the session hosts of each Azure Virtual Desktop host pool, and reads a host pool it cannot read as partial, never as no host pool (1.18.0)' {
        { Assert-EbrReadOnlyRequest -Method GET -Uri 'https://management.azure.com/subscriptions/s1/resourceGroups/rg-avd/providers/Microsoft.DesktopVirtualization/hostPools/hp1/sessionHosts?api-version=2024-04-03' } | Should -Not -Throw
        New-Item -ItemType Directory -Path (Join-Path $TestDrive 'queries') -Force | Out-Null
        $ctx = [pscustomobject]@{ WindowStart = [datetime]'2026-07-01'; WindowEnd = [datetime]'2026-09-30'; ManagedRgPattern = 'aznativesol0'; OutDir = $TestDrive; Subscriptions = @('s1'); ArmTenant = 't'; AccessPath = ''; Pending = [System.Collections.Generic.List[object]]::new() }
        $item = Get-EbrQueryCatalog | Where-Object Id -eq 'EW.10-ASSESSMENT'
        $vm = { param($n, $mode) [pscustomobject]@{ Name = $n; resourceGroup = 'rg-avd'; subscriptionId = 's1'; OsType = 'Windows'; AssessmentMode = $mode; PatchMode = 'AutomaticByOS'; Appliance = $false; Aks = $false; WindowsClient = $false; PatchExcluded = $false; ResourceId = "/subscriptions/s1/resourcegroups/rg-avd/providers/microsoft.compute/virtualmachines/$n" } }
        $machines = @((& $vm 'avd-0' 'ImageDefault'), (& $vm 'avd-p0' ''), (& $vm 'vm-app01' 'ImageDefault'))
        $pools = @([pscustomobject]@{ Name = 'hp-pooled'; resourceGroup = 'rg-avd'; subscriptionId = 's1'; HostPoolType = 'Pooled'; ResourceId = '/subscriptions/s1/resourceGroups/rg-avd/providers/Microsoft.DesktopVirtualization/hostPools/hp-pooled' }
            [pscustomobject]@{ Name = 'hp-personal'; resourceGroup = 'rg-avd'; subscriptionId = 's1'; HostPoolType = 'Personal'; ResourceId = '/subscriptions/s1/resourceGroups/rg-avd/providers/Microsoft.DesktopVirtualization/hostPools/hp-personal' })
        Mock Invoke-EbrArgQuery { [pscustomobject]@{ Rows = $(if ($Query -match 'desktopvirtualization/hostpools') { $pools } else { $machines }); Detail = '' } }
        Mock Invoke-EbrRest {
            $Method | Should -Be 'GET'
            if ($Uri -match 'hp-pooled/sessionHosts\?api-version=2024-04-03$') { return [pscustomobject]@{ value = @([pscustomobject]@{ name = 'hp-pooled/avd-0.corp'; properties = [pscustomobject]@{ resourceId = '/subscriptions/s1/resourceGroups/rg-avd/providers/Microsoft.Compute/virtualMachines/AVD-0' } }); nextLink = 'https://management.azure.com/next-page' } }
            if ($Uri -eq 'https://management.azure.com/next-page') { return [pscustomobject]@{ value = @() } }
            if ($Uri -match 'hp-personal/sessionHosts\?') { return [pscustomobject]@{ value = @([pscustomobject]@{ properties = [pscustomobject]@{ resourceId = '/subscriptions/s1/resourceGroups/rg-avd/providers/Microsoft.Compute/virtualMachines/avd-p0' } }) } }
            throw "unexpected $Uri"
        }
        $res = Invoke-EbrCatalogItem -Ctx $ctx -Item $item
        $res.Status | Should -Be 'OK'
        $res.Detail | Should -Be '3 virtual machines without periodic assessment, 1 of them pooled Azure Virtual Desktop session hosts.'
        ($res.Rows | Where-Object Name -eq 'avd-0').HostPool | Should -Be 'hp-pooled' -Because 'the session host resource ID is matched in lower case'
        ($res.Rows | Where-Object Name -eq 'avd-0').HostPoolType | Should -Be 'Pooled'
        ($res.Rows | Where-Object Name -eq 'avd-p0').HostPoolType | Should -Be 'Personal'
        ($res.Rows | Where-Object Name -eq 'vm-app01').HostPool | Should -Be ''
        @($res.Rows)[0].PSObject.Properties.Name | Should -Be @('subscriptionId', 'resourceGroup', 'Name', 'OsType', 'OsName', 'ImagePublisher', 'ImageOffer', 'ImageSku', 'PowerState', 'AssessmentMode', 'PatchMode', 'ProvisionVmAgent', 'Appliance', 'Aks', 'AksCluster', 'WindowsClient', 'GuestPatchSupport', 'LastAssessed', 'PatchExcluded', 'HostPool', 'HostPoolType', 'VmId', 'ResourceId')
        Should -Invoke Invoke-EbrRest -ParameterFilter { $Uri -eq 'https://management.azure.com/next-page' } -Times 1 -Exactly -Because 'every page of session hosts is read'
        Mock Invoke-EbrRest { if ($Uri -match 'hp-pooled/') { throw 'HTTP 403: Forbidden | AuthorizationFailed' }; [pscustomobject]@{ value = @() } }
        $res = Invoke-EbrCatalogItem -Ctx $ctx -Item $item
        $res.Status | Should -Be 'PARTIAL' -Because 'a session host of a pool not read could be pooled'
        $res.Detail | Should -Match 'Session hosts not read: hp-pooled: HTTP 403'
        Mock Invoke-EbrArgQuery { if ($Query -match 'desktopvirtualization/hostpools') { throw 'Resource Graph throttled' }; [pscustomobject]@{ Rows = $machines; Detail = '' } }
        $res = Invoke-EbrCatalogItem -Ctx $ctx -Item $item
        $res.Status | Should -Be 'PARTIAL'
        $res.Detail | Should -Match 'The Azure Virtual Desktop host pools could not be listed: Resource Graph throttled'
        Mock Invoke-EbrArgQuery { [pscustomobject]@{ Rows = $(if ($Query -match 'desktopvirtualization/hostpools') { @() } else { $machines }); Detail = 'Truncated at 1000 rows.' } }
        (Invoke-EbrCatalogItem -Ctx $ctx -Item $item).Status | Should -Be 'PARTIAL' -Because 'a truncated Resource Graph result leaves machines out'
        Mock Invoke-EbrArgQuery { [pscustomobject]@{ Rows = @(); Detail = '' } }
        (Invoke-EbrCatalogItem -Ctx $ctx -Item $item).Status | Should -Be 'EMPTY'
        Mock Invoke-EbrArgQuery { throw 'HTTP 403: Forbidden' }
        (Invoke-EbrCatalogItem -Ctx $ctx -Item $item).Status | Should -Be 'FAILED'
    }

    It 'lists each App Service site that still allows plain FTP, read as NB.5-DETAIL reads its sites (1.7.0)' {
        $d = $catalog | Where-Object Id -eq 'NB.5-FTPS-DETAIL'
        $d.Engine | Should -Be 'ARG'
        $d.Phase | Should -Be 'P2 Network'
        $d.Notes | Should -Match '^Added in CyberSOC 1\.7\.0\.'
        $d.Notes | Should -Match 'Deployment slots \(sites/slots/config\) are not read\.'
        $d.Notes | Should -Match 'Internal: names sites, the report embeds counts only\.'
        $d.Query | Should -Match 'appserviceresources\r?\n\| where type =~ "microsoft\.web/sites/config"\r?\n\| where id !contains "\{\{MRG\}\}"'
        $d.Query | Should -MatchExactly 'coalesce\(properties\.FtpsState, properties\.ftpsState\)' -Because 'appserviceresources returns the config keys in PascalCase'
        $d.Query | Should -MatchExactly 'coalesce\(properties\.MinTlsVersion, properties\.minTlsVersion\)' -Because 'FTPS only needs TLS 1.2, so CR-17 reads the minimum too'
        $d.Query | Should -Match 'where not\(FtpsState in~ \("FtpsOnly", "Disabled"\)\)' -Because 'an empty state is kept for the index note, never read as enforced'
        $d.Query | Should -Match 'project Name = tostring\(Parts\[8\]\), ResourceId = tostring\(split\(id, "/config/"\)\[0\]\),\s+resourceGroup = tostring\(Parts\[4\]\), subscriptionId = tostring\(Parts\[2\]\), FtpsState, MinTlsVersion'
        $nb5 = ($catalog | Where-Object Id -eq 'NB.5-DETAIL').Query
        ($d.Query -split "`r?`n" | Select-Object -First 3) -join "`n" | Should -Be (($nb5 -split "`r?`n" | Select-Object -First 3) -join "`n") -Because 'both read the same site configurations with the managed resource group excluded'
    }

    It 'lists each internet-exposed management port rule with its properties and attachments, read as NB.2 reads them (1.6.0)' {
        $nb2 = ($catalog | Where-Object Id -eq 'NB.2').Query
        $d = $catalog | Where-Object Id -eq 'NB.2-DETAIL'
        $d.Engine | Should -Be 'ARG'
        $d.Phase | Should -Be 'P2 Network'
        $d.Notes | Should -Match '^Added in CyberSOC 1\.6\.0\.'
        $d.Notes | Should -Match 'Internal: names rules, the report embeds counts only\.'
        $d.Query | Should -Match 'where type =~ "microsoft\.network/networksecuritygroups"\r?\n\| where id !contains "\{\{MRG\}\}"'
        foreach ($filter in @(
                'where tostring\(Rule\.properties\.access\) =~ "Allow"\s+and tostring\(Rule\.properties\.direction\) =~ "Inbound"',
                [regex]::Escape(@'
| where SourceText contains '"*"' or SourceText contains '"Internet"' or SourceText contains '"0.0.0.0/0"'
     or SourceText contains '"::/0"'
'@.Trim()),
                [regex]::Escape(@'
| where PortText contains '"*"' or PortText contains '"22"' or PortText contains '"3389"'
'@.Trim()))) {
            $nb2 | Should -Match $filter -Because 'NB.2-DETAIL reads the rules NB.2 counts'
            $d.Query | Should -Match $filter
        }
        $d.Query | Should -Match 'mv-expand Rule = properties\.securityRules limit 1000' -Because 'a network security group holds up to 1,000 rules and mv-expand stops at 128 by default'
        foreach ($c in 'Subnets = coalesce\(properties\.subnets, dynamic\(\[\]\)\)', 'Nics\s+= coalesce\(properties\.networkInterfaces, dynamic\(\[\]\)\)', 'coalesce\(Rule\.properties\.sourceAddressPrefixes, dynamic\(\[\]\)\)',
            'coalesce\(Rule\.properties\.destinationPortRanges, dynamic\(\[\]\)\)', 'coalesce\(Rule\.properties\.sourcePortRanges, dynamic\(\[\]\)\)', 'coalesce\(Rule\.properties\.destinationAddressPrefixes, dynamic\(\[\]\)\)',
            'DestinationAsgs = coalesce\(Rule\.properties\.destinationApplicationSecurityGroups, dynamic\(\[\]\)\)', 'NicVms\s+= coalesce\(NicVms, dynamic\(\[\]\)\)', 'ApplianceNicIds\s+= coalesce\(ApplianceNicIds, dynamic\(\[\]\)\)', 'ApplianceSubnetIds = coalesce\(ApplianceSubnetIds, dynamic\(\[\]\)\)') {
            $d.Query | Should -Match $c -Because 'a missing property reads as an empty list'
        }
        $d.Query | Should -Match 'where type =~ "microsoft\.network/networkinterfaces"' -Because 'each network interface names its virtual machine'
        $d.Query | Should -Match '\| where \{\{APPLIANCE\}\}   // network virtual appliances, see P0\.6-APPLIANCES' -Because 'an appliance untrust interface is left to the index'
        $d.Query | Should -Match 'mv-expand IpConfig = properties\.ipConfigurations' -Because 'an appliance interface without a group of its own is reached through the group on its subnet'
        $d.Query | Should -Match 'ApplianceNicIds\s+= make_set\(tolower\(id\)\),\s+ApplianceSubnetIds = make_set\(tolower\(tostring\(IpConfig\.properties\.subnet\.id\)\)\)'
        $d.Query | Should -Match 'Association = case\(0 < array_length\(Subnets\), "Subnet", 0 < array_length\(Nics\), "NIC", "Unassociated"\)'
        $d.Query | Should -Match 'project subscriptionId, resourceGroup, NSG = name, NsgId = id,\s+RuleName\s+= tostring\(Rule\.name\), RuleId = tostring\(Rule\.id\),'
        foreach ($col in 'Priority', 'Direction', 'Access', 'Protocol', 'SourcePrefixes', 'SourcePorts', 'DestinationPrefixes', 'DestinationPorts', 'Description', 'RangeNeedsReview') { $d.Query | Should -Match "\b$col\b" -Because "CR-16 records $col" }
        ([regex]::Matches($d.Query, 'join kind=')).Count | Should -BeLessOrEqual 3 -Because 'Resource Graph allows three joins per query'
        ([regex]::Matches($d.Query, 'mv-expand')).Count | Should -BeLessOrEqual 3 -Because 'Resource Graph allows three mv-expand per query'
        $expanded = Expand-EbrQuery -Query $d.Query -WindowStart ([datetime]'2026-07-01') -WindowEnd ([datetime]'2026-09-30') -ManagedRgPattern 'aznativesol0'
        $expanded | Should -Not -Match '\{\{' -Because 'every placeholder is filled in'
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
        $known = 'ARG', 'LA', 'AH', 'SENTINEL-RULES', 'STORAGE-CONTAINERS', 'APPSERVICE-FTPAUTH', 'MYSQL-AUDIT', 'DISABLED-ROLES', 'EMERGENCY-ACCESS', 'COMPUTE-SKUS', 'DEFENDER-SCORES', 'DEFENDER-MACHINES', 'DEFENDER-AVINFO', 'PATCH-ASSESSMENT', 'EXO', 'IPPS', 'GRAPH', 'MANUAL', 'DERIVED'
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
        foreach ($id in 'IA.1', 'IA.1-ADMINPORTAL', 'IA.2', 'IA.2-METHOD', 'IA.3', 'IA.3-DEVICECODE', 'IA.4', 'IA.4b', 'IA.8-SUB', 'IA.8-SIGNINS', 'IA.8-SIGNINS-NONINTERACTIVE', 'IA.14') {
            ($tenant | Where-Object Id -eq $id).TenantTable | Should -Be 'SigninLogs' -Because $id
        }
        $tenant.TenantTable | Should -Not -Contain 'AuditLogs' -Because 'OUT.8 is not collected, so nothing reads the tenant audit log'
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
        foreach ($id in 'P0.2', 'P0.3', 'P0.7', 'POS.1', 'POS.3', 'POS.5', 'POS.7') {
            ($catalog | Where-Object Id -eq $id).Query | Should -Not -Match '\{\{MRG\}\}'
        }
    }

    It 'excludes the managed resource group from every other ARG query' {
        $exempt = 'P0.2', 'P0.3', 'P0.7', 'POS.1', 'POS.3', 'POS.5'
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
    It 'reads the non-interactive legacy sign-ins with a Coverage row, so a workspace without that log never reads as no legacy sign-in (1.16.0)' {
        $item = $catalog | Where-Object Id -eq 'IA.8-SIGNINS-NONINTERACTIVE'
        $item.Engine | Should -Be 'LA'
        $item.Notes | Should -Match '^Added in CyberSOC 1\.16\.0\.'
        $q = $item.Query
        $q | Should -Match '^let NonInteractive = AADNonInteractiveUserSignInLogs'
        $q | Should -Match 'ClientAppUsed !in \("Browser", "Mobile Apps and Desktop clients", "Unknown"\)' -Because 'legacy authentication is read as IA.8-SIGNINS reads it'
        $q | Should -Match 'mv-apply Policy = todynamic\(ConditionalAccessPolicies\)' -Because 'the non-interactive table holds the policies as a string'
        $q | Should -Match 'by Flow, ClientAppUsed, UserId, UserPrincipalName, UserType, PolicyResults'
        $q | Should -Match 'extend Kind = "Coverage", FullWindow = SignIns > 0 and FirstSignIn < ago\(29d\)' -Because 'a log that is empty or began within the 30 days is told apart from no legacy sign-in'
        $q | Should -Match 'extend Table = "AADNonInteractiveUserSignInLogs"\),\s+\(SigninLogs \| where TimeGenerated between \(ago\(30d\) \.\. now\(\)\) \| summarize SignIns = count\(\), FirstSignIn = min\(TimeGenerated\)' -Because 'the interactive log that IA.8-SIGNINS reads must cover the window too'
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
        $item.Query | Should -Not -Match 'kind !~ "FileStorage"' -Because 'from 1.20.0 DP.1-SOFTDELETE lists the FileStorage accounts, and the engine leaves them out of the container listing'
        $item.Query | Should -Match 'Kind = kind'
        $item.Query | Should -Match 'HnsEnabled = coalesce\(tobool\(properties\.isHnsEnabled\), false\)'
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
    It 'lists each container set to Blob or Container with what CR-18 needs, and none for an account it cannot list in full (1.8.0)' {
        $item = Get-EbrQueryCatalog | Where-Object Id -eq 'DP.1-CONTAINERS'
        $item.Notes | Should -Match 'Since CyberSOC 1\.8\.0 it also writes DP\.1-CONTAINERS-DETAIL, one row per container set to Blob or Container'
        $accountId = '/subscriptions/s1/resourceGroups/rg-web/providers/Microsoft.Storage/storageAccounts/stweb'
        Mock Invoke-EbrRest {
            if ($Uri -match 'page2') { return [pscustomobject]@{ value = @([pscustomobject]@{ id = "$accountId/blobServices/default/containers/downloads"; name = 'downloads'; properties = [pscustomobject]@{ publicAccess = 'Container' } }) } }
            [pscustomobject]@{ value = @(
                    [pscustomobject]@{ id = "$accountId/blobServices/default/containers/private"; name = 'private'; properties = [pscustomobject]@{ publicAccess = 'None' } }
                    [pscustomobject]@{ name = 'images'; properties = [pscustomobject]@{ publicAccess = 'Blob' } }
                    [pscustomobject]@{ id = "$accountId/blobServices/default/containers/`$web"; name = '$web'; properties = [pscustomobject]@{ publicAccess = 'Blob' } })
                nextLink = 'https://management.azure.com/x?page2' }
        }
        $a = [pscustomobject]@{ ResourceId = $accountId; Account = 'stweb'; resourceGroup = 'rg-web'; subscriptionId = 's1'; AllowBlobPublicAccess = 'true' }
        $details = [System.Collections.Generic.List[object]]::new()
        $r = Get-EbrBlobContainerRow -Account $a -Tenant 't' -Details $details
        $r.PublicContainers | Should -Be 3
        @($details | ForEach-Object { '{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f $_.subscriptionId, $_.resourceGroup, $_.Account, $_.Container, $_.AccessLevel, $_.AccountAnonymousAccess, $_.ReadableToday }) | Should -Be @(
            's1|rg-web|stweb|images|Blob|Allowed|True', 's1|rg-web|stweb|$web|Blob|Allowed|True', 's1|rg-web|stweb|downloads|Container|Allowed|True')
        $details[0].ResourceId | Should -Be "$accountId/blobServices/default/containers/images" -Because 'a container without an ID is named by its path under the account'
        $details[2].ResourceId | Should -Be "$accountId/blobServices/default/containers/downloads"
        @($details | ForEach-Object AccountId | Sort-Object -Unique) | Should -Be @($accountId)
        $a.AllowBlobPublicAccess = 'false'
        $details.Clear()
        $null = Get-EbrBlobContainerRow -Account $a -Tenant 't' -Details $details
        @($details | ForEach-Object { '{0}|{1}' -f $_.AccountAnonymousAccess, $_.ReadableToday } | Sort-Object -Unique) | Should -Be @('Disabled|False') -Because 'the account setting blocks every anonymous read'
        Mock Invoke-EbrRest { if ($Uri -match 'page2') { throw 'HTTP 429: Too Many Requests' }; [pscustomobject]@{ value = @([pscustomobject]@{ name = 'images'; properties = [pscustomobject]@{ publicAccess = 'Blob' } }); nextLink = 'https://management.azure.com/x?page2' } }
        $details.Clear()
        $r = Get-EbrBlobContainerRow -Account $a -Tenant 't' -Details $details
        $r.ReadStatus | Should -Match '429'
        $details.Count | Should -Be 0 -Because 'an account whose second page failed was not listed in full, so CR-18 names it in the index instead'
    }
    It 'writes DP.1-CONTAINERS-DETAIL with every outcome of DP.1-CONTAINERS, so a failed read never asks for a newer collector' {
        New-Item -ItemType Directory -Path (Join-Path $TestDrive 'queries') -Force | Out-Null
        $ctx = [pscustomobject]@{ WindowStart = [datetime]'2026-07-01'; WindowEnd = [datetime]'2026-09-30'; ManagedRgPattern = 'aznativesol0'; OutDir = $TestDrive; Subscriptions = @('s1'); ArmTenant = 't'; AccessPath = ''; Pending = [System.Collections.Generic.List[object]]::new() }
        $item = Get-EbrQueryCatalog | Where-Object Id -eq 'DP.1-CONTAINERS'
        $open = [pscustomobject]@{ ResourceId = '/subscriptions/s1/resourceGroups/rg-web/providers/Microsoft.Storage/storageAccounts/stweb'; Account = 'stweb'; resourceGroup = 'rg-web'; subscriptionId = 's1'; AllowBlobPublicAccess = '' }
        $denied = [pscustomobject]@{ ResourceId = '/subscriptions/s1/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stdenied'; Account = 'stdenied'; resourceGroup = 'rg-data'; subscriptionId = 's1'; AllowBlobPublicAccess = 'true' }
        Mock Invoke-EbrArgQuery { [pscustomobject]@{ Rows = @($open); Detail = '' } }
        Mock Invoke-EbrRest { if ($Uri -match 'stdenied') { throw 'HTTP 403: Forbidden' }; [pscustomobject]@{ value = @([pscustomobject]@{ name = 'images'; properties = [pscustomobject]@{ publicAccess = 'Blob' } }, [pscustomobject]@{ name = 'logs'; properties = [pscustomobject]@{ publicAccess = 'None' } }) } }
        $res = Invoke-EbrCatalogItem -Ctx $ctx -Item $item
        $res.Status | Should -Be 'OK'
        @($ctx.Pending | ForEach-Object ResultId) | Should -Be @('DP.1-CONTAINERS-DETAIL', 'DP.1-SOFTDELETE') -Because 'the same pass writes the soft delete read from 1.20.0'
        $d = $ctx.Pending[0]
        @($d.ResultId, $d.Status) | Should -Be @('DP.1-CONTAINERS-DETAIL', 'OK')
        @($d.Rows).Count | Should -Be 1
        @($d.Rows)[0].Container | Should -Be 'images'
        @($d.Rows)[0].AccountAnonymousAccess | Should -Be 'Not set, allowed'
        $d.Detail | Should -Be '1 containers set to Blob or Container access in 1 of 1 storage accounts listed, 1 readable anonymously today.'
        $ctx.Pending.Clear()
        Mock Invoke-EbrArgQuery { [pscustomobject]@{ Rows = @($open, $denied); Detail = '' } }
        $res = Invoke-EbrCatalogItem -Ctx $ctx -Item $item
        @($res.Status, $ctx.Pending[0].Status) | Should -Be @('PARTIAL', 'PARTIAL') -Because 'a container in an account not listed may be missing'
        $ctx.Pending[0].Detail | Should -Match 'Accounts not listed add no rows, see DP\.1-CONTAINERS\.$'
        $ctx.Pending.Clear()
        Mock Invoke-EbrRest { [pscustomobject]@{ value = @([pscustomobject]@{ name = 'logs'; properties = [pscustomobject]@{ publicAccess = 'None' } }) } }
        Mock Invoke-EbrArgQuery { [pscustomobject]@{ Rows = @($open); Detail = '' } }
        $null = Invoke-EbrCatalogItem -Ctx $ctx -Item $item
        $ctx.Pending[0].Status | Should -Be 'EMPTY' -Because 'every container is private'
        $ctx.Pending.Clear()
        Mock Invoke-EbrArgQuery { [pscustomobject]@{ Rows = @(); Detail = '' } }
        $null = Invoke-EbrCatalogItem -Ctx $ctx -Item $item
        $ctx.Pending[0].Status | Should -Be 'EMPTY'
        $ctx.Pending.Clear()
        Mock Invoke-EbrArgQuery { throw 'Resource Graph throttled' }
        (Invoke-EbrCatalogItem -Ctx $ctx -Item $item).Status | Should -Be 'FAILED'
        $ctx.Pending[0].Status | Should -Be 'FAILED'
        $ctx.Pending[0].Detail | Should -Match 'throttled'
        @($ctx.Pending | ForEach-Object { '{0} {1}' -f $_.ResultId, $_.Status }) | Should -Be @('DP.1-CONTAINERS-DETAIL FAILED', 'DP.1-SOFTDELETE FAILED') -Because 'a failed account list never reads as no account without soft delete'
    }
    It 'reads encryption at host support per size from the Compute resource SKUs API, one region at a time' {
        Mock Invoke-EbrRest {
            if ($Uri -match 'page2') { return [pscustomobject]@{ value = @([pscustomobject]@{ resourceType = 'virtualMachines'; name = 'Standard_A1'; capabilities = @([pscustomobject]@{ name = 'EncryptionAtHostSupported'; value = 'False' }) }) } }
            [pscustomobject]@{
                value = @(
                    [pscustomobject]@{ resourceType = 'virtualMachines'; name = 'Standard_D4s_v5'; capabilities = @([pscustomobject]@{ name = 'vCPUs'; value = '4' }, [pscustomobject]@{ name = 'EncryptionAtHostSupported'; value = 'True' }) }
                    [pscustomobject]@{ resourceType = 'virtualMachines'; name = 'Standard_B1ls'; capabilities = @([pscustomobject]@{ name = 'vCPUs'; value = '1' }) }
                    [pscustomobject]@{ resourceType = 'disks'; name = 'Premium_LRS'; capabilities = @([pscustomobject]@{ name = 'EncryptionAtHostSupported'; value = 'True' }) })
                nextLink = 'https://management.azure.com/x?page2'
            }
        }
        $sizes = Get-EbrEncryptionAtHostSizes -SubscriptionId 's1' -Location 'eastus' -Tenant 't'
        $sizes['standard_d4s_v5'] | Should -BeTrue
        $sizes['standard_a1'] | Should -BeFalse
        $sizes['standard_b1ls'] | Should -BeFalse -Because 'a size without the capability does not support it'
        $sizes.ContainsKey('premium_lrs') | Should -BeFalse -Because 'only virtual machine sizes count'
        Should -Invoke Invoke-EbrRest -Times 1 -Exactly -ParameterFilter { $Method -eq 'GET' -and $Uri -eq "https://management.azure.com/subscriptions/s1/providers/Microsoft.Compute/skus?api-version=2021-07-01&`$filter=location%20eq%20%27eastus%27" }
        { Assert-EbrReadOnlyRequest -Method GET -Uri 'https://management.azure.com/subscriptions/s1/providers/Microsoft.Compute/skus?api-version=2021-07-01' } | Should -Not -Throw
    }
    It 'marks a machine eligible for encryption at host only when its size supports it and it never used Azure Disk Encryption' {
        Mock Invoke-EbrRest {
            if ($Uri -match '/subscriptions/s2/') { throw 'HTTP 403: Forbidden' }
            [pscustomobject]@{ value = @(
                    [pscustomobject]@{ resourceType = 'virtualMachines'; name = 'Standard_D4s_v5'; capabilities = @([pscustomobject]@{ name = 'EncryptionAtHostSupported'; value = 'True' }) }
                    [pscustomobject]@{ resourceType = 'virtualMachines'; name = 'Standard_A1'; capabilities = @([pscustomobject]@{ name = 'EncryptionAtHostSupported'; value = 'False' }) }) }
        }
        $vm = { param($name, $sub, $size, $ade, $region = 'eastus') [pscustomobject]@{ Name = $name; ResourceId = "/subscriptions/$sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/$name"; resourceGroup = 'rg'; subscriptionId = $sub; Location = $region; Size = $size; PowerState = 'PowerState/running'; VmId = "id-$name"; AdeUsed = $ade } }
        $rows = @(Get-EbrEncryptionAtHostRows -Vms @((& $vm 'shared' 's2' 'Standard_D4s_v5' $false), (& $vm 'ok' 's1' 'Standard_D4s_v5' $false), (& $vm 'ade' 's1' 'Standard_D4s_v5' 'True'), (& $vm 'old' 's1' 'Standard_A1' $false), (& $vm 'new' 's1' 'Standard_Z9' $false), (& $vm 'denied' 's2' 'Standard_D4s_v5' $false 'westus')) -Tenant 't')
        $by = @{}; foreach ($r in $rows) { $by[$r.Name] = $r }
        @($by.ok.Eligible, $by.ok.SizeSupported, $by.ok.Reason) | Should -Be @($true, 'Yes', '')
        @($rows | ForEach-Object VmId) | Should -Be @('id-shared', 'id-ok', 'id-ade', 'id-old', 'id-new', 'id-denied') -Because 'each row keeps the VM ID of its machine'
        @($by.shared.Eligible, $by.shared.SizeRead) | Should -Be @($true, 'OK') -Because 'the size belongs to the region, so the list read through another subscription answers for it'
        @($by.ade.Eligible, $by.ade.AdeUsed, $by.ade.Reason) | Should -Be @($false, $true, 'Azure Disk Encryption used')
        @($by.old.Eligible, $by.old.SizeSupported, $by.old.Reason) | Should -Be @($false, 'No', 'size not supported')
        @($by.new.Eligible, $by.new.SizeSupported, $by.new.Reason) | Should -Be @($false, 'Unknown', 'size not listed for the region')
        @($by.denied.Eligible, $by.denied.SizeSupported) | Should -Be @($false, 'Unknown')
        $by.denied.Reason | Should -Match '^size support not read: .*403'
        $by.denied.SizeRead | Should -Match '^Not read: .*403'
        $by.ok.SizeRead | Should -Be 'OK'
        $oldDisk = [pscustomobject]@{ Name = 'ultra'; ResourceId = '/x/ultra'; resourceGroup = 'rg'; subscriptionId = 's1'; Location = 'eastus'; Size = 'Standard_D4s_v5'; PowerState = 'PowerState/running'; AdeUsed = $false; OldSectorDisk = 'True' }
        $old = @(Get-EbrEncryptionAtHostRows -Vms @($oldDisk) -Tenant 't')[0]
        @($old.Eligible, $old.Reason) | Should -Be @($false, '512e Ultra or Premium SSD v2 disk created before May 13, 2023')
        $deniedAde = @(Get-EbrEncryptionAtHostRows -Vms @((& $vm 'both' 's2' 'Standard_D4s_v5' 'true' 'westus')) -Tenant 't')[0]
        $deniedAde.Reason | Should -Be 'Azure Disk Encryption used'
        $deniedAde.SizeRead | Should -Match '^Not read' -Because 'a failed SKU read still counts when Azure Disk Encryption already rules the machine out'
        $by.ok.ResourceId | Should -Be '/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/ok'
        Should -Invoke Invoke-EbrRest -Times 5 -Exactly -Because 'each region is read once per call: eastus through s2 then s1 and westus through s2, then eastus and westus for the two single-machine calls'
    }
    It 'marks a scale set eligible only when its model can take encryption at host, and never an AKS node pool' {
        Mock Invoke-EbrRest {
            if ($Uri -match 'westus') { throw 'HTTP 403: Forbidden' }
            [pscustomobject]@{ value = @(
                    [pscustomobject]@{ resourceType = 'virtualMachines'; name = 'Standard_D4s_v5'; capabilities = @([pscustomobject]@{ name = 'EncryptionAtHostSupported'; value = 'True' }) }
                    [pscustomobject]@{ resourceType = 'virtualMachines'; name = 'Standard_A1'; capabilities = @([pscustomobject]@{ name = 'EncryptionAtHostSupported'; value = 'False' }) }) }
        }
        $ss = { param($name, $size, [hashtable]$extra = @{}) $o = [ordered]@{ Name = $name; ResourceId = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/$name"; resourceGroup = 'rg'; subscriptionId = 's1'; Location = 'eastus'; OrchestrationMode = 'Uniform'; UpgradePolicy = 'Manual'; Instances = 3; Size = $size; HasModel = 'true'; AdeUsed = $false; OldSectorDisk = $false; Aks = $false; AksCluster = ''; AksClusterResourceGroup = ''; AksNodePool = ''; UniqueId = "uid-$name" }; foreach ($k in $extra.Keys) { $o[$k] = $extra[$k] }; [pscustomobject]$o }
        $rows = @(Get-EbrScaleSetEncryptionAtHostRows -ScaleSets @(
                (& $ss 'web' 'Standard_D4s_v5'), (& $ss 'ade' 'Standard_D4s_v5' @{ AdeUsed = 'True' }), (& $ss 'a1' 'Standard_A1'), (& $ss 'ultra' 'Standard_D4s_v5' @{ OldSectorDisk = $true }),
                (& $ss 'flex' 'Standard_D4s_v5' @{ OrchestrationMode = 'Flexible'; UpgradePolicy = '' }), (& $ss 'bare' '' @{ OrchestrationMode = 'Flexible'; HasModel = $false }),
                (& $ss 'aks-system-12345678-vmss' 'Standard_D2s_v5' @{ Aks = $true; AksCluster = 'aks-prod'; AksClusterResourceGroup = 'rg-aks'; AksNodePool = 'system'; Location = 'westus' }),
                (& $ss 'denied' 'Standard_D4s_v5' @{ Location = 'westus' })) -Tenant 't')
        $by = @{}; foreach ($r in $rows) { $by[$r.Name] = $r }
        @($by.web.Eligible, $by.web.SizeSupported, $by.web.SizeRead, $by.web.Reason, $by.web.Instances, $by.web.UpgradePolicy, $by.web.UniqueId) | Should -Be @($true, 'Yes', 'OK', '', '3', 'Manual', 'uid-web')
        @($by.flex.Eligible, $by.flex.OrchestrationMode) | Should -Be @($true, 'Flexible') -Because 'the model of a Flexible scale set takes the setting too, and the generator checks its machines'
        @($by.ade.Eligible, $by.ade.Reason) | Should -Be @($false, 'Azure Disk Encryption used')
        @($by.a1.Eligible, $by.a1.Reason) | Should -Be @($false, 'size not supported')
        @($by.ultra.Eligible, $by.ultra.Reason) | Should -Be @($false, 'Ultra Disk or Premium SSD v2 in a scale set created before May 13, 2023')
        @($by.bare.Eligible, $by.bare.Reason, $by.bare.SizeRead) | Should -Be @($false, 'no scale set model', '') -Because 'a Flexible scale set without a model has no setting to change'
        $aks = $by['aks-system-12345678-vmss']
        @($aks.Eligible, $aks.Aks, $aks.AksCluster, $aks.AksNodePool, $aks.Reason, $aks.SizeRead) | Should -Be @($false, $true, 'aks-prod', 'system', 'AKS node pool, set only when a node pool is created', '') -Because 'AKS manages the model, so its size is not read'
        @($by.denied.Eligible, $by.denied.SizeSupported) | Should -Be @($false, 'Unknown')
        $by.denied.Reason | Should -Match '^size support not read: .*403'
        Should -Invoke Invoke-EbrRest -Times 2 -Exactly -Because 'eastus and westus are each read once, and the AKS node pool alone in westus would not need a read'
        $onlyAks = @(Get-EbrScaleSetEncryptionAtHostRows -ScaleSets @((& $ss 'aks-user-1-vmss' 'Standard_D2s_v5' @{ Aks = 'true' })) -Tenant 't')
        $onlyAks[0].Eligible | Should -BeFalse
        Should -Invoke Invoke-EbrRest -Times 2 -Exactly -Because 'a pack of AKS node pools only reads no size list'
    }
    It 'writes DP.4-VMSS-ELIGIBILITY with the scale set columns, and reads it PARTIAL only for a size list it needed' {
        New-Item -ItemType Directory -Path (Join-Path $TestDrive 'queries') -Force | Out-Null
        $ctx = [pscustomobject]@{ WindowStart = [datetime]'2026-07-01'; WindowEnd = [datetime]'2026-09-30'; ManagedRgPattern = 'aznativesol0'; OutDir = $TestDrive; Subscriptions = @('s1'); ArmTenant = 't'; Pending = [System.Collections.Generic.List[object]]::new() }
        $item = Get-EbrQueryCatalog | Where-Object Id -eq 'DP.4-VMSS-ELIGIBILITY'
        Mock Invoke-EbrRest { if ($Uri -match 'westus') { throw 'HTTP 403: Forbidden' }; [pscustomobject]@{ value = @([pscustomobject]@{ resourceType = 'virtualMachines'; name = 'Standard_D4s_v5'; capabilities = @([pscustomobject]@{ name = 'EncryptionAtHostSupported'; value = 'True' }) }) } }
        $web = [pscustomobject]@{ Name = 'vmss-web'; ResourceId = '/x/vmss-web'; resourceGroup = 'rg'; subscriptionId = 's1'; Location = 'eastus'; OrchestrationMode = 'Uniform'; UpgradePolicy = 'Rolling'; Instances = 4; Size = 'Standard_D4s_v5'; HasModel = $true; AdeUsed = $false; OldSectorDisk = $false; Aks = $false; AksCluster = $null; AksClusterResourceGroup = $null; AksNodePool = '' }
        $aks = [pscustomobject]@{ Name = 'aks-user-1-vmss'; ResourceId = '/x/aks'; resourceGroup = 'mc_rg'; subscriptionId = 's1'; Location = 'westus'; OrchestrationMode = 'Uniform'; UpgradePolicy = 'Manual'; Instances = 3; Size = 'Standard_D2s_v5'; HasModel = $true; AdeUsed = $false; OldSectorDisk = $false; Aks = $true; AksCluster = 'aks-prod'; AksClusterResourceGroup = 'rg-aks'; AksNodePool = 'user' }
        Mock Invoke-EbrArgQuery { [pscustomobject]@{ Rows = @($web, $aks); Detail = '' } }
        $res = Invoke-EbrCatalogItem -Ctx $ctx -Item $item
        $res.Status | Should -Be 'OK' -Because 'the AKS node pool in westus needs no size list, so the failed westus read is never made'
        $res.Detail | Should -Match '^1 of 2 scale sets can take encryption at host\. 1 AKS node pools, 0 without a model'
        @($res.Rows).Count | Should -Be 2
        Should -Invoke Invoke-EbrRest -Times 1 -Exactly
        $web.Location = 'westus'
        $res = Invoke-EbrCatalogItem -Ctx $ctx -Item $item
        $res.Status | Should -Be 'FAILED' -Because 'no scale set that needed a size list had one read'
        Mock Invoke-EbrArgQuery { [pscustomobject]@{ Rows = @(); Detail = '' } }
        (Invoke-EbrCatalogItem -Ctx $ctx -Item $item).Status | Should -Be 'EMPTY'
    }
}

Describe 'Blob and container soft delete (DP.1-SOFTDELETE, CyberSOC 1.20.0)' {
    BeforeAll {
        $script:sd = Get-Content (Join-Path $PSScriptRoot 'fixtures/offline-pack/blob-soft-delete/scenarios.json') -Raw | ConvertFrom-Json
        $script:sdItem = Get-EbrQueryCatalog | Where-Object Id -eq 'DP.1-CONTAINERS'
        # Answers each GET from the fixture by account or vault name and path. A string is the error the request throws.
        function Get-SdAnswer([string]$Uri) {
            if ($Uri -notmatch '/(storageAccounts|vaults)/([^/?]+)/([^?]+)\?') { throw "Unexpected GET $Uri" }
            $key = '{0}/{1}' -f $Matches[2], $Matches[3]
            $answer = $sd.Arm.PSObject.Properties[$key]
            if (-not $answer) { throw "HTTP 404: Not Found ($key)" }
            if ($answer.Value -is [string]) { throw $answer.Value }
            $answer.Value
        }
        function New-SdCtx {
            New-Item -ItemType Directory -Path (Join-Path $TestDrive 'queries') -Force | Out-Null
            [pscustomobject]@{ WindowStart = [datetime]'2026-07-01'; WindowEnd = [datetime]'2026-09-30'; ManagedRgPattern = 'aznativesol0'; OutDir = $TestDrive; Subscriptions = @('s1', 's2'); ArmTenant = 't'; AccessPath = ''; Pending = [System.Collections.Generic.List[object]]::new() }
        }
        function Get-SdResult($Ctx) { $Ctx.Pending | Where-Object ResultId -eq 'DP.1-SOFTDELETE' }
        $script:sdColumns = 'subscriptionId', 'resourceGroup', 'Account', 'Kind', 'HnsEnabled', 'BlobSoftDelete', 'BlobRetentionDays', 'ContainerSoftDelete', 'ContainerRetentionDays', 'LifecycleRules', 'LifecycleDeleteRules', 'SiteRecoveryCache', 'SiteRecoveryVaults', 'ReadStatus', 'ResourceId'
        function Format-SdRow($Row) { (@($sdColumns | ForEach-Object { '{0}={1}' -f $_, [string]$Row.$_ }) -join '|') }
    }
    It 'records the read in the catalog notes and the read-only header, with the vault read and the lifecycle read' {
        $sdItem.Notes | Should -Match 'Since CyberSOC 1\.20\.0 it also writes DP\.1-SOFTDELETE in the same pass, one row per storage account with blob soft delete and container soft delete'
        $sdItem.Notes | Should -Match 'a 404 read as no policy'
        $sdItem.Query | Should -Match 'where id !contains "\{\{MRG\}\}"'
        foreach ($uri in 'https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a/blobServices/default?api-version=2023-05-01', 'https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a/managementPolicies/default?api-version=2023-05-01', 'https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.RecoveryServices/vaults/v/replicationProtectedItems?api-version=2023-08-01') {
            { Assert-EbrReadOnlyRequest -Method GET -Uri $uri } | Should -Not -Throw
        }
        $text = Get-Content (Join-Path $PSScriptRoot '..' 'Get-CyberSocEvidence.ps1') -Raw
        $text | Should -Match 'GET  <storage account>/blobServices/default and <storage account>/managementPolicies/default \(blob and container soft delete and the lifecycle rules, DP\.1-SOFTDELETE\)'
        $text | Should -Match 'GET  <Recovery Services vault>/replicationProtectedItems \(the Site Recovery cache and log storage accounts, DP\.1-SOFTDELETE\)'
    }
    It 'writes one row per storage account from the fixture reads, with the cache account the vault names and the FileStorage account unread' {
        Mock Invoke-EbrArgQuery { if ($Query -match 'microsoft\.recoveryservices/vaults') { [pscustomobject]@{ Rows = @($sd.Vaults); Detail = '' } } else { [pscustomobject]@{ Rows = @($sd.Arg); Detail = '' } } }
        Mock Invoke-EbrRest { Get-SdAnswer $Uri }
        $ctx = New-SdCtx
        $res = Invoke-EbrCatalogItem -Ctx $ctx -Item $sdItem
        $res.Status | Should -Be 'PARTIAL' -Because 'stdenied could not be listed'
        @($res.Rows | ForEach-Object Account) | Should -Not -Contain 'stpremfiles' -Because 'a FileStorage account has no containers to list'
        $soft = Get-SdResult $ctx
        $soft.Status | Should -Be 'PARTIAL' -Because 'an account that was not read is never read as having soft delete'
        @($soft.Rows | ForEach-Object { Format-SdRow $_ } | Sort-Object) | Should -Be @($sd.Rows | ForEach-Object { Format-SdRow $_ } | Sort-Object)
        $soft.Detail | Should -Match '^8 of 9 storage accounts with a blob service read: blob soft delete off in 6, container soft delete off in 6, lifecycle rules that delete in 2\. 1 account named as a Site Recovery cache or log storage account in the 2 of 2 Recovery Services vaults read\. 1 FileStorage, not read\. Not read: stdenied: HTTP 403'
        Should -Invoke Invoke-EbrRest -Times 0 -Exactly -ParameterFilter { $Uri -match 'stpremfiles' } -Because 'a FileStorage account is never read'
        Should -Invoke Invoke-EbrRest -Times 1 -Exactly -ParameterFilter { $Uri -eq 'https://management.azure.com/subscriptions/5f1c2a9e-3b7d-4e21-9a6c-0d8e4f2b7c11/resourceGroups/rg-dr/providers/Microsoft.RecoveryServices/vaults/rsv-dr/replicationProtectedItems?api-version=2023-08-01' }
    }
    It 'reads every account as Unknown for Site Recovery when a vault was not read, and the result as partial' {
        Mock Invoke-EbrArgQuery { if ($Query -match 'microsoft\.recoveryservices/vaults') { [pscustomobject]@{ Rows = @($sd.Vaults); Detail = '' } } else { [pscustomobject]@{ Rows = @($sd.Arg | Where-Object Account -in 'stbothoff', 'stallon'); Detail = '' } } }
        Mock Invoke-EbrRest { if ($Uri -match 'rsv-backup') { throw 'HTTP 403: Forbidden' }; Get-SdAnswer $Uri }
        $ctx = New-SdCtx
        $null = Invoke-EbrCatalogItem -Ctx $ctx -Item $sdItem
        $soft = Get-SdResult $ctx
        $soft.Status | Should -Be 'PARTIAL' -Because 'an account in a vault not read may be a cache account'
        @($soft.Rows | ForEach-Object SiteRecoveryCache | Sort-Object -Unique) | Should -Be @('Unknown')
        $soft.Detail | Should -Match 'Recovery Services vaults not read, so SiteRecoveryCache reads Unknown: rsv-backup: HTTP 403: Forbidden$'
        Mock Invoke-EbrArgQuery { if ($Query -match 'microsoft\.recoveryservices/vaults') { throw 'Resource Graph throttled' } else { [pscustomobject]@{ Rows = @($sd.Arg | Where-Object Account -eq 'stbothoff'); Detail = '' } } }
        $ctx = New-SdCtx
        $null = Invoke-EbrCatalogItem -Ctx $ctx -Item $sdItem
        (Get-SdResult $ctx).Status | Should -Be 'PARTIAL'
        @(Get-SdResult $ctx).Rows[0].SiteRecoveryCache | Should -Be 'Unknown'
    }
    It 'reads a missing policy as Off, a 404 lifecycle read as no rules, and any other failure as unread' {
        $a = [pscustomobject]@{ ResourceId = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a'; Account = 'a'; resourceGroup = 'rg'; subscriptionId = 's'; Kind = 'StorageV2'; HnsEnabled = $false }
        $ok = [pscustomobject]@{ Accounts = @{}; Failed = @(); Vaults = 0; Read = 0 }
        Mock Invoke-EbrRest { if ($Uri -match 'managementPolicies') { throw 'HTTP 404: Not Found' }; [pscustomobject]@{ properties = [pscustomobject]@{ deleteRetentionPolicy = [pscustomobject]@{ enabled = $true; days = 7 } } } }
        $r = Get-EbrBlobSoftDeleteRow -Account $a -Tenant 't' -SiteRecovery $ok
        @($r.BlobSoftDelete, $r.BlobRetentionDays, $r.ContainerSoftDelete, $r.ContainerRetentionDays, $r.LifecycleRules, $r.LifecycleDeleteRules, $r.SiteRecoveryCache, $r.ReadStatus) | Should -Be @('On', '7', 'Off', '', 0, 0, 'No', 'OK')
        Mock Invoke-EbrRest { if ($Uri -match 'managementPolicies') { throw 'HTTP 403: Forbidden' }; [pscustomobject]@{ properties = [pscustomobject]@{ deleteRetentionPolicy = [pscustomobject]@{ enabled = $false } } } }
        $r = Get-EbrBlobSoftDeleteRow -Account $a -Tenant 't' -SiteRecovery $ok
        $r.ReadStatus | Should -Be 'Lifecycle management policy: HTTP 403: Forbidden' -Because 'the lifecycle rules change how much deleted data is kept, so an account is read only with them'
        @($r.BlobSoftDelete, $r.ContainerSoftDelete, $r.LifecycleRules) | Should -Be @('', '', '') -Because 'an unread account is never read as Off or On'
        Mock Invoke-EbrRest { [pscustomobject]@{ value = @() } }
        $r = Get-EbrBlobSoftDeleteRow -Account $a -Tenant 't' -SiteRecovery $ok
        $r.ReadStatus | Should -Be 'The blob service response carried no properties.'
        $r = Get-EbrBlobSoftDeleteRow -Account $a -Tenant 't'
        $r.SiteRecoveryCache | Should -Be 'Unknown' -Because 'no vault read means a cache account cannot be ruled out'
    }
    It 'writes DP.1-SOFTDELETE as FAILED when no account could be read, and lists only FileStorage accounts when there is nothing else' {
        Mock Invoke-EbrArgQuery { if ($Query -match 'microsoft\.recoveryservices/vaults') { [pscustomobject]@{ Rows = @(); Detail = '' } } else { [pscustomobject]@{ Rows = @($sd.Arg | Where-Object Account -in 'stbothoff', 'stpremfiles'); Detail = '' } } }
        Mock Invoke-EbrRest { throw 'HTTP 403: Forbidden' }
        $ctx = New-SdCtx
        $null = Invoke-EbrCatalogItem -Ctx $ctx -Item $sdItem
        (Get-SdResult $ctx).Status | Should -Be 'FAILED'
        Mock Invoke-EbrArgQuery { [pscustomobject]@{ Rows = @($sd.Arg | Where-Object Account -eq 'stpremfiles'); Detail = '' } }
        $ctx = New-SdCtx
        (Invoke-EbrCatalogItem -Ctx $ctx -Item $sdItem).Status | Should -Be 'EMPTY'
        $soft = Get-SdResult $ctx
        $soft.Status | Should -Be 'OK'
        @($soft.Rows).Count | Should -Be 1
        $soft.Detail | Should -Be 'No storage account with a blob service in scope, 1 FileStorage.'
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

    It 'starts a partial report month on the first day of data, never on the 1st' {
        $w = Get-EbrDefaultReportingWindow -EarliestIncident ([datetime]'2026-09-15T08:30:00') -Now $now
        $w.Start | Should -Be ([datetime]'2026-09-15')
        $w.End | Should -Be ([datetime]'2026-09-30')
        $w.Basis | Should -Match 'a partial report month from 2026-09-15'
        (Get-EbrDefaultReportingWindow -RetentionDays 30 -Now $now).Start | Should -Be ([datetime]'2026-09-07') -Because 'without incident data the retention start is the first day of data'
    }

    It 'refuses a report month that ends before the data starts, rather than reporting zeros' {
        { Get-EbrDefaultReportingWindow -EarliestIncident ([datetime]'2026-09-15T00:00:00') -ReportMonth ([datetime]'2026-08-01') -Now $now } | Should -Throw '*2026-08 ends before the data starts*SecurityIncident data starts 2026-09-15*first month that can be reported is 2026-09*'
        { Get-EbrDefaultReportingWindow -EarliestIncident ([datetime]'2026-10-02T00:00:00') -Now $now } | Should -Throw '*2026-09 ends before the data starts*'
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

Describe 'Resource Graph request options (CyberSOC 1.9.0)' {
    It 'sends the request options to Resource Graph on every page, with and without the scope filter' {
        # The real helper, with only its REST boundary mocked: a parameter named like the per-page options would be
        # the same variable, since PowerShell variable names ignore case, and every query would fail.
        Mock Write-Progress { }
        Mock Start-Sleep { }
        Mock Invoke-EbrRest {
            $script:bodies += , $Body
            if ($Body.options['$skipToken']) { return [pscustomobject]@{ data = @([pscustomobject]@{ n = 2 }) } }
            [pscustomobject]@{ data = @([pscustomobject]@{ n = 1 }); '$skipToken' = 'next' }
        }
        $script:bodies = @()
        $r = Invoke-EbrArgQuery -Query 'authorizationresources' -Subscriptions @('s1') -Tenant 't'
        @($r.Rows | ForEach-Object n) | Should -Be @(1, 2)
        $script:bodies.Count | Should -Be 2
        @($script:bodies | ForEach-Object { '{0}|{1}|{2}' -f $_.options['$top'], $_.options.resultFormat, $_.options.ContainsKey('authorizationScopeFilter') }) | Should -Be @('1000|objectArray|False', '1000|objectArray|False')
        $script:bodies = @()
        $r = Invoke-EbrArgQuery -Query 'authorizationresources' -Subscriptions @('s1') -Tenant 't' -RequestOptions @{ authorizationScopeFilter = 'AtScopeAboveAndBelow' }
        @($r.Rows).Count | Should -Be 2
        @($script:bodies | ForEach-Object { '{0}|{1}|{2}' -f $_.options['$top'], $_.options.resultFormat, $_.options.authorizationScopeFilter }) | Should -Be @('1000|objectArray|AtScopeAboveAndBelow', '1000|objectArray|AtScopeAboveAndBelow')
        $script:bodies[1].options['$skipToken'] | Should -Be 'next'
    }
}

Describe 'Roles held by disabled accounts (IA.15, CyberSOC 1.9.0)' {
    BeforeAll {
        # Synthetic tenant: two subscriptions under the management group mg-contoso-platform. Role definition IDs are
        # the real built-in IDs: Azure Owner, Contributor, Reader, User Access Administrator, Key Vault Administrator and
        # Storage Blob Data Contributor, and the Entra Global Administrator, User Administrator, Helpdesk Administrator,
        # Security Reader and Billing Administrator.
        $script:fx = @{
            S1 = '3f6a1c2e-8b4d-4e7a-9c1f-2d5b8e0a4c61'; S2 = '7b2d9e4f-1a3c-4b5d-8e6f-0a1b2c3d4e5f'; Mg = '/providers/Microsoft.Management/managementGroups/mg-contoso-platform'
            Morgan = 'a6f1c2d3-4b5e-4f60-8a7b-9c0d1e2f3a41'      # disabled, holds roles at every scope
            Lee = 'b7e2d3c4-5a6f-4071-9b8c-0d1e2f3a4b52'       # disabled, synced from on-premises, eligible Entra role
            Kim = 'c8f3e4d5-6b70-4182-8c9d-1e2f3a4b5c63'       # disabled, reaches roles only through a group
            Ann = 'd9a4f5e6-7c81-4293-9dae-2f3a4b5c6d74'       # enabled, holds Owner and Global Administrator
            Ops = 'e0b5a6f7-8d92-43a4-aebf-3a4b5c6d7e85'       # group: platform-operators, holds Contributor and Helpdesk Administrator
            Tier2 = 'f1c6d7e8-9ea3-44b5-bfc0-4b5c6d7e8f96'     # group: ops-tier2, nested in platform-operators, holds Lee, platform-operators again (a loop) and ops-contractors
            Contractors = 'd5fa0b12-3ce7-48f9-9041-8f9a0b1c2d3b' # group: ops-contractors, nested in platform-operators directly and in ops-tier2, holds Lee
            Dyn = 'a2d7e8f9-0fb4-45c6-8d1e-5c6d7e8f9a07'       # group: all-staff-dynamic, dynamic membership, holds Reader on S2, with Morgan
            Legacy = 'b3e8f9a0-1ac5-46d7-9e2f-6d7e8f9a0b18'    # group: legacy-admins, synced from on-premises, holds Reader on S1, with Kim
            Owner = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'; Contributor = 'b24988ac-6180-42a0-ab88-20f7382dd24c'; Reader = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'
            Uaa = '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'; KvAdmin = '00482a5a-887f-4fb3-b363-3b7fe8e74483'; BlobContributor = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
            Ga = '62e90394-69f5-4237-9190-012177145e10'; UserAdmin = 'fe930be7-5e62-47db-91af-98c3a49a38b1'; Helpdesk = '729827e3-9c14-49f7-bb1b-9608f156bbb8'
            SecReader = '5d6b6bb7-de71-4623-b4af-96380a352509'; Billing = 'b0f54661-2d74-4c50-afa3-1ec803f12efe'
        }
        $f = $script:fx
        $script:fxUsers = @(
            [pscustomobject]@{ id = $f.Morgan; displayName = 'Morgan Reyes'; userPrincipalName = 'morgan.reyes@contoso.com'; accountEnabled = $false; onPremisesSyncEnabled = $null }
            [pscustomobject]@{ id = $f.Lee.ToUpperInvariant(); displayName = 'Lee Ashford'; userPrincipalName = 'lee.ashford@contoso.com'; accountEnabled = $false; onPremisesSyncEnabled = $true }
            [pscustomobject]@{ id = $f.Kim; displayName = 'Kim Osei'; userPrincipalName = 'kim.osei@contoso.com'; accountEnabled = $false; onPremisesSyncEnabled = $false }
            # The filter is server side. Were it ever ignored, an enabled account would come back, and must not be kept.
            [pscustomobject]@{ id = $f.Ann; displayName = 'Ann Larsen'; userPrincipalName = 'ann.larsen@contoso.com'; accountEnabled = $true; onPremisesSyncEnabled = $null })
        $ra = { param([string]$Scope, [string]$Role, [string]$RoleName, [string]$Principal, [string]$Type = 'User')
            $name = (Get-TestGuid ($Scope + $Role + $Principal))
            $sub = if ($Scope -match '^/subscriptions/([^/]+)') { $Matches[1] } else { '' }
            [pscustomobject]@{ AssignmentId = "$Scope/providers/Microsoft.Authorization/roleAssignments/$name"; subscriptionId = $sub; Scope = $Scope; RoleDefinitionId = "/subscriptions/$($f.S1)/providers/Microsoft.Authorization/roleDefinitions/$Role"; Role = $RoleName; PrincipalId = $Principal; PrincipalType = $Type } }
        function script:Get-TestGuid([string]$Seed) { ([guid]::new([Security.Cryptography.MD5]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($Seed)))).ToString() }
        # A real ABAC condition shape from Microsoft Learn, with the angle brackets a tag key uses.
        $script:fxCondition = "((!(ActionMatches{'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'} AND NOT SubOperationMatches{'Blob.List'})) OR (@Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags:Project<`$key_case_sensitive`$>] StringEquals 'Cascade'))"
        $rg = "/subscriptions/$($f.S1)/resourceGroups/rg-app"
        $script:fxArg = @(
            (& $ra $f.Mg $f.Reader 'Reader' $f.Morgan)
            (& $ra "/subscriptions/$($f.S1)" $f.Owner 'Owner' $f.Morgan)
            (& $ra $rg $f.Contributor 'Contributor' $f.Morgan)
            (& $ra "$rg/providers/Microsoft.KeyVault/vaults/kv-app-prod" $f.KvAdmin 'Key Vault Administrator' $f.Morgan)
            (& $ra "/subscriptions/$($f.S2)/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stdataprod" $f.BlobContributor 'Storage Blob Data Contributor' $f.Lee)
            | ForEach-Object { $_ | Add-Member -NotePropertyName Condition -NotePropertyValue $script:fxCondition -PassThru | Add-Member -NotePropertyName ConditionVersion -NotePropertyValue '2.0' -PassThru }
            (& $ra '/' $f.Uaa 'User Access Administrator' $f.Lee)
            (& $ra "/subscriptions/$($f.S2)" $f.Owner 'Owner' $f.Ann)
            (& $ra "/subscriptions/$($f.S2)/resourceGroups/rg-ops" $f.Contributor 'Contributor' $f.Ops 'Group')
            (& $ra "/subscriptions/$($f.S2)" $f.Reader 'Reader' $f.Dyn 'Group')
            (& $ra "/subscriptions/$($f.S1)" $f.Reader 'Reader' $f.Legacy 'Group')
            (& $ra "/subscriptions/$($f.S2)" $f.Reader 'Reader' 'c4f9a0b1-2bd6-47e8-8f30-7e8f9a0b1c29' 'ServicePrincipal'))
        # A management group assignment comes back once per subscription under it. It must be kept once.
        $script:fxArg += $script:fxArg[0]
        $principal = { param([string]$Id, [string]$Type, [string]$Name, [string]$Upn) [pscustomobject]@{ '@odata.type' = "#microsoft.graph.$Type"; id = $Id; displayName = $Name; userPrincipalName = $Upn } }
        $script:fxRoleAssignments = @(
            [pscustomobject]@{ id = 'lAPpYvVpN0KRkAEhdxReEJC2sEqbR_9Hr48lds9SGHI-1'; roleDefinitionId = $f.UserAdmin; principalId = $f.Morgan; directoryScopeId = '/'; principal = (& $principal $f.Morgan 'user' 'Morgan Reyes' 'morgan.reyes@contoso.com') }
            [pscustomobject]@{ id = 'x3ifr6ub3U2nW8aaQyKm8BOXpYc9w0lJk5QCWa4yC4c-1'; roleDefinitionId = $f.SecReader; principalId = $f.Lee; directoryScopeId = '/'; principal = (& $principal $f.Lee 'user' 'Lee Ashford' 'lee.ashford@contoso.com') }
            [pscustomobject]@{ id = 'lAPpYvVpN0KRkAEhdxReEOkEVmWa3ZtIrqW1xbBWoWw-1'; roleDefinitionId = $f.Ga; principalId = $f.Ann; directoryScopeId = '/'; principal = (& $principal $f.Ann 'user' 'Ann Larsen' 'ann.larsen@contoso.com') }
            [pscustomobject]@{ id = 'kpD7cnQrWEiDkfnCZvOJXZOUaNFBQ-BLsvrSdmoMvDs-1'; roleDefinitionId = $f.Helpdesk; principalId = $f.Ops; directoryScopeId = '/administrativeUnits/4b5c6d7e-8f90-4a1b-b2c3-d4e5f6a7b8c9'; principal = (& $principal $f.Ops 'group' 'platform-operators' $null) })
        $script:fxSchedules = @(
            [pscustomobject]@{ id = 's1'; roleDefinitionId = $f.UserAdmin; principalId = $f.Morgan; directoryScopeId = '/'; assignmentType = 'Assigned'; endDateTime = $null }
            [pscustomobject]@{ id = 's2'; roleDefinitionId = $f.SecReader; principalId = $f.Lee; directoryScopeId = '/'; assignmentType = 'Activated'; endDateTime = '2026-10-11T20:00:00Z' })
        $script:fxEligible = @(
            [pscustomobject]@{ id = 'e1'; roleDefinitionId = $f.SecReader; principalId = $f.Lee; directoryScopeId = '/'; endDateTime = '2027-03-31T00:00:00Z'; principal = (& $principal $f.Lee 'user' 'Lee Ashford' 'lee.ashford@contoso.com') }
            [pscustomobject]@{ id = 'e2'; roleDefinitionId = $f.Billing; principalId = $f.Ann; directoryScopeId = '/'; endDateTime = $null; principal = (& $principal $f.Ann 'user' 'Ann Larsen' 'ann.larsen@contoso.com') }
            # Kim's eligibility inherited from a group is the group's assignment, never Kim's own to remove.
            [pscustomobject]@{ id = 'e3'; roleDefinitionId = $f.SecReader; principalId = $f.Kim; directoryScopeId = '/'; memberType = 'Group'; endDateTime = $null; principal = (& $principal $f.Kim 'user' 'Kim Osei' 'kim.osei@contoso.com') })
        $script:fxDefinitions = @(
            foreach ($d in @(@($f.Ga, 'Global Administrator'), @($f.UserAdmin, 'User Administrator'), @($f.Helpdesk, 'Helpdesk Administrator'), @($f.SecReader, 'Security Reader'), @($f.Billing, 'Billing Administrator'))) {
                [pscustomobject]@{ id = $d[0]; templateId = $d[0]; displayName = $d[1] } })
        # One Graph answer per path. A path set to a string throws it, so a test can make any one read fail. Each group
        # answers its properties and its direct members, as Graph returns them: users and groups together, typed.
        $member = { param([string]$Id, [string]$Type, [string]$Name) [pscustomobject]@{ '@odata.type' = "#microsoft.graph.$Type"; id = $Id; displayName = $Name } }
        $script:fxGroupMembers = @{
            # ops-contractors sits in platform-operators directly and in ops-tier2, listed after ops-tier2 so that a
            # depth-first walk would reach it the long way first. The shortest route is the one recorded.
            $f.Ops = @((& $member $f.Kim 'user' 'Kim Osei'), (& $member $f.Ann 'user' 'Ann Larsen'), (& $member $f.Tier2 'group' 'ops-tier2'), (& $member $f.Contractors 'group' 'ops-contractors'))
            # Lee comes back in upper case, as Graph can write an ID, and platform-operators is a member of its own
            # nested group, so the walk must stop at a group it has seen.
            $f.Tier2 = @((& $member $f.Lee.ToUpperInvariant() 'user' 'Lee Ashford'), (& $member $f.Ops 'group' 'platform-operators'), (& $member $f.Contractors 'group' 'ops-contractors'))
            $f.Contractors = @((& $member $f.Lee 'user' 'Lee Ashford'))
            $f.Dyn = @((& $member $f.Morgan 'user' 'Morgan Reyes'))
            $f.Legacy = @((& $member $f.Kim 'user' 'Kim Osei'))
        }
        function script:New-DisabledGraph([hashtable]$Fail = @{}) {
            $f = $script:fx
            $answers = [ordered]@{
                'users\?\$filter=accountEnabled eq false' = $script:fxUsers
                'roleManagement/directory/roleAssignments\?' = $script:fxRoleAssignments
                'roleManagement/directory/roleDefinitions' = $script:fxDefinitions
                'roleAssignmentScheduleInstances' = $script:fxSchedules
                'roleEligibilityScheduleInstances' = $script:fxEligible
                "groups/$($f.Ops)/members" = $script:fxGroupMembers[$f.Ops]
                "groups/$($f.Ops)\?\`$select=id,displayName" = [pscustomobject]@{ id = $f.Ops; displayName = 'platform-operators'; groupTypes = @(); onPremisesSyncEnabled = $null }
                "groups/$($f.Tier2)/members" = $script:fxGroupMembers[$f.Tier2]
                "groups/$($f.Tier2)\?\`$select=id,displayName" = [pscustomobject]@{ id = $f.Tier2; displayName = 'ops-tier2'; groupTypes = @('Unified'); onPremisesSyncEnabled = $false }
                "groups/$($f.Contractors)/members" = $script:fxGroupMembers[$f.Contractors]
                "groups/$($f.Contractors)\?\`$select=id,displayName" = [pscustomobject]@{ id = $f.Contractors; displayName = 'ops-contractors'; groupTypes = @(); onPremisesSyncEnabled = $false }
                "groups/$($f.Dyn)/members" = $script:fxGroupMembers[$f.Dyn]
                "groups/$($f.Dyn)\?\`$select=id,displayName" = [pscustomobject]@{ id = $f.Dyn; displayName = 'all-staff-dynamic'; groupTypes = @('DynamicMembership'); onPremisesSyncEnabled = $null }
                "groups/$($f.Legacy)/members" = $script:fxGroupMembers[$f.Legacy]
                "groups/$($f.Legacy)\?\`$select=id,displayName" = [pscustomobject]@{ id = $f.Legacy; displayName = 'legacy-admins'; groupTypes = @(); onPremisesSyncEnabled = $true }
            }
            foreach ($k in $Fail.Keys) { $answers[$k] = $Fail[$k] }
            $answers
        }
        function script:New-DisabledCtx([string]$AccessPath = 'Direct') {
            [pscustomobject]@{
                TenantGuid = 'client'; GraphAvailable = $true; GraphReason = ''; GraphCache = @{}; ArmTenant = 'client'; AccessPath = $AccessPath; Subscriptions = @($script:fx.S1, $script:fx.S2)
                GraphMissingScopes = [System.Collections.Generic.List[string]]::new(); GraphPartial = [System.Collections.Generic.List[string]]::new(); Pending = [System.Collections.Generic.List[object]]::new()
                OutDir = $TestDrive; WindowStart = [datetime]'2026-07-01'; WindowEnd = [datetime]'2026-09-30'; ManagedRgPattern = 'aznativesol0'
            }
        }
        $script:item = Get-EbrQueryCatalog | Where-Object Id -eq 'IA.15-DISABLED'
        $null = New-Item -ItemType Directory -Path (Join-Path $TestDrive 'queries') -Force
    }
    BeforeEach {
        $script:graph = New-DisabledGraph
        Mock Invoke-EbrGraphGet {
            foreach ($k in $script:graph.Keys) {
                if ($Uri -match $k) {
                    $v = $script:graph[$k]
                    if ($v -is [string]) { throw $v }
                    if ($v -is [array]) { return , @($v) }
                    return $v
                }
            }
            throw "unexpected $Uri"
        }
        Mock Invoke-EbrArgQuery { [pscustomobject]@{ Columns = @(); Rows = $script:fxArg; Detail = '' } }
    }

    It 'reads every Azure role assignment from the root down, joined to role definitions, with the managed resource group exclusion' {
        $script:item.Engine | Should -Be 'DISABLED-ROLES'
        $script:item.Phase | Should -Be 'P2 Identity'
        $script:item.LighthouseIncomplete | Should -BeTrue
        $q = $script:item.Query
        $q | Should -Match '^authorizationresources\r?\n\| where type =~ "microsoft\.authorization/roleassignments"'
        $q | Should -Match '\| where id !contains "\{\{MRG\}\}"'
        $q | Should -Match 'join kind=leftouter \(\s+authorizationresources\s+\| where type =~ "microsoft\.authorization/roledefinitions"'
        $q | Should -Match 'Condition        = tostring\(properties\.condition\),\r?\n\s+ConditionVersion = tostring\(properties\.conditionVersion\)'
        $q | Should -Match 'project AssignmentId = id, subscriptionId, Scope, RoleDefinitionId, Role, Condition, ConditionVersion, PrincipalId, PrincipalType'
        $q | Should -Not -Match 'principalType in' -Because 'an assignment without a principal type must not be dropped'
        $script:item.Notes | Should -Match 'User\.Read\.All'
        $script:item.Notes | Should -Match 'RoleManagement\.Read\.Directory'
        $script:item.Notes | Should -Match 'Lighthouse'
        $null = Invoke-EbrCatalogItem -Ctx (New-DisabledCtx) -Item $script:item
        Should -Invoke Invoke-EbrArgQuery -Times 1 -Exactly -ParameterFilter { $RequestOptions.authorizationScopeFilter -eq 'AtScopeAboveAndBelow' -and $Query -match 'id !contains "aznativesol0"' -and @($Subscriptions).Count -eq 2 }
        Get-Content (Join-Path $TestDrive 'queries/IA.15-DISABLED.kql') -Raw | Should -Match 'AtScopeAboveAndBelow'
    }

    It 'lists the disabled accounts only, never an enabled one, even when Graph returns one' {
        $ctx = New-DisabledCtx
        $r = Invoke-EbrCatalogItem -Ctx $ctx -Item $script:item
        $r.ResultId | Should -Be 'IA.15-DISABLED'
        $r.Status | Should -Be 'OK'
        @($r.Rows | ForEach-Object UserPrincipalName) | Should -Be @('kim.osei@contoso.com', 'lee.ashford@contoso.com', 'morgan.reyes@contoso.com')
        @($r.Rows | ForEach-Object AccountEnabled | Sort-Object -Unique) | Should -Be @($false)
        ($r.Rows | Where-Object UserPrincipalName -like 'lee*').PrincipalId | Should -Be $script:fx.Lee -Because 'object IDs are kept in lower case, so they match the role assignments'
        @($r.Rows | Where-Object OnPremisesSyncEnabled | ForEach-Object UserPrincipalName) | Should -Be @('lee.ashford@contoso.com')
        Should -Invoke Invoke-EbrGraphGet -Times 1 -Exactly -ParameterFilter { $Uri -like 'https://graph.microsoft.com/v1.0/users?$filter=accountEnabled eq false&$select=id,displayName,userPrincipalName,accountEnabled,onPremisesSyncEnabled&$top=999' }
        $all = @($r.Rows) + @($ctx.Pending | ForEach-Object { @($_.Rows) })
        ($all | ConvertTo-Json -Depth 5) | Should -Not -Match 'ann\.larsen|Ann Larsen' -Because 'no result names an enabled account, whatever it holds or whichever group it is in'
        @($ctx.Pending | ForEach-Object ResultId) | Should -Be @('IA.15-RBAC', 'IA.15-ENTRA')
    }

    It 'keeps every Azure role a disabled account holds, at management group, subscription, resource group, resource and root scope, once each' {
        $ctx = New-DisabledCtx
        $null = Invoke-EbrCatalogItem -Ctx $ctx -Item $script:item
        $rbac = $ctx.Pending | Where-Object ResultId -eq 'IA.15-RBAC'
        $rbac.Status | Should -Be 'OK'
        $rows = @($rbac.Rows)
        @($rows | Where-Object HeldThrough -eq 'Direct' | ForEach-Object { '{0}|{1}|{2}' -f $_.UserPrincipalName, $_.ScopeLevel, $_.Role } | Sort-Object) | Should -Be @(
            'lee.ashford@contoso.com|Resource|Storage Blob Data Contributor', 'lee.ashford@contoso.com|Root|User Access Administrator'
            'morgan.reyes@contoso.com|Management group|Reader', 'morgan.reyes@contoso.com|Resource group|Contributor', 'morgan.reyes@contoso.com|Resource|Key Vault Administrator', 'morgan.reyes@contoso.com|Subscription|Owner')
        $mg = $rows | Where-Object ScopeLevel -eq 'Management group'
        @($mg).Count | Should -Be 1 -Because 'a management group assignment returned under each subscription is one assignment'
        $mg.subscriptionId | Should -Be ''
        $mg.Scope | Should -Be $script:fx.Mg
        $kv = $rows | Where-Object Role -eq 'Key Vault Administrator'
        @($kv.subscriptionId, $kv.resourceGroup, $kv.RoleDefinitionId) | Should -Be @($script:fx.S1, 'rg-app', "/subscriptions/$($script:fx.S1)/providers/microsoft.authorization/roledefinitions/$($script:fx.KvAdmin)")
        $kv.AssignmentId | Should -Match '^/subscriptions/.+/providers/Microsoft\.KeyVault/vaults/kv-app-prod/providers/Microsoft\.Authorization/roleAssignments/[0-9a-f-]{36}$'
        $blob = $rows | Where-Object Role -eq 'Storage Blob Data Contributor'
        @($blob.Condition, $blob.ConditionVersion) | Should -Be @($script:fxCondition, '2.0') -Because 'the rollback recreates the condition exactly, since without it the role grants more'
        ($rows | Where-Object Role -eq 'Owner').Condition | Should -Be ''
        $rbac.Columns | Should -Contain 'Condition'
        $group = @($rows | Where-Object HeldThrough -eq 'Group')
        @($group | ForEach-Object { '{0}|{1}|{2}|{3}|{4}|{5}' -f $_.UserPrincipalName, $_.GroupName, $_.GroupId, $_.Role, $_.MemberOfName, $_.MemberOfType } | Sort-Object) | Should -Be @(
            "kim.osei@contoso.com|legacy-admins|$($script:fx.Legacy)|Reader|legacy-admins|On-premises"
            "kim.osei@contoso.com|platform-operators|$($script:fx.Ops)|Contributor|platform-operators|Assigned"
            "lee.ashford@contoso.com|platform-operators|$($script:fx.Ops)|Contributor|ops-contractors|Assigned"
            "lee.ashford@contoso.com|platform-operators|$($script:fx.Ops)|Contributor|ops-tier2|Assigned"
            "morgan.reyes@contoso.com|all-staff-dynamic|$($script:fx.Dyn)|Reader|all-staff-dynamic|Dynamic") -Because 'each disabled member of a group is listed with the group that holds the role and each group it sits in, and the enabled member is not'
        $rbac.Detail | Should -Match '^11 Azure role assignments held by 3 of the 3 disabled accounts, 5 through a group, read in the subscriptions of the pack and at the management groups and root scope above them\.'
        foreach ($c in 'MemberOfId', 'MemberOfName', 'MemberOfType', 'GroupPath', 'GroupPathIds') { $rbac.Columns | Should -Contain $c }
        @($rows | Where-Object HeldThrough -eq 'Direct' | ForEach-Object { '{0}|{1}|{2}|{3}|{4}' -f $_.MemberOfId, $_.MemberOfName, $_.MemberOfType, @($_.GroupPath).Count, @($_.GroupPathIds).Count } | Sort-Object -Unique) | Should -Be @('|||0|0') -Because 'a role assigned to the account itself names no group'
    }

    It 'keeps every Entra role, standing, activated and eligible, not only the 12 privileged ones' {
        $ctx = New-DisabledCtx
        $null = Invoke-EbrCatalogItem -Ctx $ctx -Item $script:item
        $entra = $ctx.Pending | Where-Object ResultId -eq 'IA.15-ENTRA'
        $entra.Status | Should -Be 'OK'
        @($entra.Rows | ForEach-Object { '{0}|{1}|{2}|{3}|{4}' -f $_.UserPrincipalName, $_.Role, $_.AssignmentType, $_.HeldThrough, $_.DirectoryScope }) | Should -Be @(
            'kim.osei@contoso.com|Helpdesk Administrator|Standing|Group|/administrativeUnits/4b5c6d7e-8f90-4a1b-b2c3-d4e5f6a7b8c9'
            'lee.ashford@contoso.com|Helpdesk Administrator|Standing|Group|/administrativeUnits/4b5c6d7e-8f90-4a1b-b2c3-d4e5f6a7b8c9'
            'lee.ashford@contoso.com|Helpdesk Administrator|Standing|Group|/administrativeUnits/4b5c6d7e-8f90-4a1b-b2c3-d4e5f6a7b8c9'
            'lee.ashford@contoso.com|Security Reader|Activated|Direct|/'
            'lee.ashford@contoso.com|Security Reader|Eligible|Direct|/'
            'morgan.reyes@contoso.com|User Administrator|Standing|Direct|/')
        ($entra.Rows | Where-Object AssignmentType -eq 'Eligible').EndDateUtc | Should -Be '2027-03-31T00:00:00Z'
        ($entra.Rows | Where-Object AssignmentType -eq 'Activated').AssignmentId | Should -Be 'x3ifr6ub3U2nW8aaQyKm8BOXpYc9w0lJk5QCWa4yC4c-1'
        @($entra.Rows | ForEach-Object PimRead | Sort-Object -Unique) | Should -Be @('Yes')
        @(($entra.Rows | Where-Object HeldThrough -eq 'Group').GroupName | Sort-Object -Unique) | Should -Be @('platform-operators')
        $nested = $entra.Rows | Where-Object { $_.HeldThrough -eq 'Group' -and $_.UserPrincipalName -eq 'lee.ashford@contoso.com' -and $_.MemberOfId -eq $script:fx.Tier2 }
        @($nested.MemberOfName, $nested.MemberOfType) | Should -Be @('ops-tier2', 'Assigned') -Because 'Lee reaches the role as a member of the nested group, which is where the account is removed from'
        @($nested.GroupPath) | Should -Be @('platform-operators', 'ops-tier2')
        @($nested.GroupPathIds) | Should -Be @($script:fx.Ops, $script:fx.Tier2)
        $twice = $entra.Rows | Where-Object { $_.HeldThrough -eq 'Group' -and $_.UserPrincipalName -eq 'lee.ashford@contoso.com' -and $_.MemberOfId -eq $script:fx.Contractors }
        @($twice.GroupPath) | Should -Be @('platform-operators', 'ops-contractors') -Because 'ops-contractors sits in platform-operators directly as well as in ops-tier2, and the shortest route is recorded even though ops-tier2 is listed first'
        @($twice.GroupPathIds) | Should -Be @($script:fx.Ops, $script:fx.Contractors)
    }

    It 'follows nested groups once each, records the group the account sits in with its membership type, and drops a deleted group' {
        $ctx = New-DisabledCtx
        $null = Invoke-EbrCatalogItem -Ctx $ctx -Item $script:item
        $rows = @(($ctx.Pending | Where-Object ResultId -eq 'IA.15-RBAC').Rows | Where-Object HeldThrough -eq 'Group')
        $direct = $rows | Where-Object { $_.UserPrincipalName -eq 'kim.osei@contoso.com' -and $_.GroupId -eq $script:fx.Ops }
        @($direct.MemberOfId, $direct.MemberOfName, $direct.MemberOfType) | Should -Be @($script:fx.Ops, 'platform-operators', 'Assigned') -Because 'a member of the role group itself is removed from that group'
        @($direct.GroupPath) | Should -Be @('platform-operators')
        $dynamic = $rows | Where-Object GroupId -eq $script:fx.Dyn
        @($dynamic.UserPrincipalName, $dynamic.MemberOfType) | Should -Be @('morgan.reyes@contoso.com', 'Dynamic') -Because 'a rule decides the members of a dynamic membership group'
        $synced = $rows | Where-Object GroupId -eq $script:fx.Legacy
        @($synced.UserPrincipalName, $synced.MemberOfType) | Should -Be @('kim.osei@contoso.com', 'On-premises') -Because 'the members of a synced group come from Active Directory'
        foreach ($g in $script:fx.Ops, $script:fx.Tier2, $script:fx.Contractors, $script:fx.Dyn, $script:fx.Legacy) {
            Should -Invoke Invoke-EbrGraphGet -Times 1 -Exactly -ParameterFilter { $Uri -like "*groups/$g/members?*" } -Because "group $g is read once, although platform-operators is a member of its own nested group"
            Should -Invoke Invoke-EbrGraphGet -Times 1 -Exactly -ParameterFilter { $Uri -like "*groups/$g[?]`$select=*" }
        }
        Should -Invoke Invoke-EbrGraphGet -Times 0 -Exactly -ParameterFilter { $Uri -like '*transitiveMembers*' } -Because 'the direct members are walked, so the group each account sits in is known'
        # A group deleted since the role was given to it holds the role for no one, and makes nothing partial.
        $ctx = New-DisabledCtx
        $script:graph["groups/$($script:fx.Legacy)\?\`$select=id,displayName"] = 'HTTP 404: Not Found | Request_ResourceNotFound'
        $null = Invoke-EbrCatalogItem -Ctx $ctx -Item $script:item
        $rbac = $ctx.Pending | Where-Object ResultId -eq 'IA.15-RBAC'
        $rbac.Status | Should -Be 'OK'
        @($rbac.Rows | Where-Object GroupId -eq $script:fx.Legacy).Count | Should -Be 0
        @($rbac.Rows | Where-Object HeldThrough -eq 'Group').Count | Should -Be 4
    }

    It 'reuses the role assignments IA.6 read, and reads each group once' {
        $ctx = New-DisabledCtx
        $script:graph['roleAssignmentScheduleInstances'] = 'HTTP 400: Bad Request | AadPremiumLicenseRequired'
        $null = Invoke-EbrGraphCollector -Ctx $ctx -Item ([pscustomobject]@{ Id = 'IA.6'; Title = 'IA.6'; Engine = 'GRAPH'; Query = 'GET /v1.0/x'; Notes = ''; Phase = 'P2 Identity' })
        $null = Invoke-EbrCatalogItem -Ctx $ctx -Item $script:item
        Should -Invoke Invoke-EbrGraphGet -Times 1 -Exactly -ParameterFilter { $Uri -match 'roleManagement/directory/roleAssignments\?' }
        Should -Invoke Invoke-EbrGraphGet -Times 1 -Exactly -ParameterFilter { $Uri -like "*groups/$($script:fx.Ops)/members?*" } -Because 'the group holds an Azure and an Entra role, and is read once'
        Should -Invoke Invoke-EbrGraphGet -Times 1 -Exactly -ParameterFilter { $Uri -like "*groups/$($script:fx.Ops)/members?*" -and $Uri -match '[?&]\$count=true(&|$)' -and $Uri -match '[?&]\$top=999(&|$)' } -Because 'Graph takes $select and $top on members only as an advanced query, with $count=true and ConsistencyLevel eventual'
        Should -Invoke Invoke-EbrGraphGet -Times 1 -Exactly -ParameterFilter { $Uri -like "*groups/$($script:fx.Ops)[?]`$select=*" } -Because 'its properties say whether a member can be removed'
        $entra = $ctx.Pending | Where-Object ResultId -eq 'IA.15-ENTRA'
        $entra.Status | Should -Be 'OK'
        $entra.Detail | Should -Match 'PIM is not licensed'
        @($entra.Rows | ForEach-Object AssignmentType | Sort-Object -Unique) | Should -Be @('Standing')
    }

    It 'reports both sides UNAVAILABLE, not a zero, when the users cannot be read, and names the permission' {
        $ctx = New-DisabledCtx
        $script:graph['users\?\$filter=accountEnabled eq false'] = 'GRAPH-403 https://graph.microsoft.com/v1.0/users: HTTP 403: Forbidden | Authorization_RequestDenied'
        $r = Invoke-EbrCatalogItem -Ctx $ctx -Item $script:item
        foreach ($x in @($r) + @($ctx.Pending)) {
            $x.Status | Should -Be 'UNAVAILABLE' -Because $x.ResultId
            $x.Detail | Should -Match '^Not a zero: the Graph token cannot read user accounts' -Because $x.ResultId
            $x.Detail | Should -Match 'Needs User\.Read\.All\. Fix: az login --tenant client --scope https://graph\.microsoft\.com/User\.Read\.All' -Because $x.ResultId
            @($x.Rows).Count | Should -Be 0
        }
        @($ctx.GraphMissingScopes) | Should -Be @('User.Read.All')
        Should -Invoke Invoke-EbrArgQuery -Times 0 -Exactly
    }

    It 'reports all three UNAVAILABLE when Microsoft Graph is not reachable' {
        $ctx = New-DisabledCtx
        $ctx.GraphAvailable = $false
        $ctx.GraphReason = 'No Graph token: AADSTS530004.'
        $r = Invoke-EbrCatalogItem -Ctx $ctx -Item $script:item
        @(@($r) + @($ctx.Pending) | ForEach-Object Status | Sort-Object -Unique) | Should -Be @('UNAVAILABLE')
        $r.Detail | Should -Match '^Not a zero: Microsoft Graph was not reachable.*AADSTS530004'
    }

    It 'keeps the Azure side when only the Entra roles cannot be read' {
        $ctx = New-DisabledCtx
        $script:graph['roleManagement/directory/roleAssignments\?'] = 'GRAPH-403 https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments: HTTP 403: Forbidden'
        $r = Invoke-EbrCatalogItem -Ctx $ctx -Item $script:item
        $r.Status | Should -Be 'OK'
        $entra = $ctx.Pending | Where-Object ResultId -eq 'IA.15-ENTRA'
        $entra.Status | Should -Be 'UNAVAILABLE'
        $entra.Detail | Should -Match '^Not a zero: .*Needs RoleManagement\.Read\.Directory'
        ($ctx.Pending | Where-Object ResultId -eq 'IA.15-RBAC').Status | Should -Be 'OK'
        @(($ctx.Pending | Where-Object ResultId -eq 'IA.15-RBAC').Rows).Count | Should -Be 11
        $r.Detail | Should -Match 'IA\.15-ENTRA UNAVAILABLE'
    }

    It 'keeps the Entra side when Resource Graph fails' {
        $ctx = New-DisabledCtx
        Mock Invoke-EbrArgQuery { throw 'HTTP 429: Too Many Requests' }
        $null = Invoke-EbrCatalogItem -Ctx $ctx -Item $script:item
        ($ctx.Pending | Where-Object ResultId -eq 'IA.15-RBAC').Status | Should -Be 'FAILED'
        ($ctx.Pending | Where-Object ResultId -eq 'IA.15-RBAC').Detail | Should -Match '429'
        ($ctx.Pending | Where-Object ResultId -eq 'IA.15-ENTRA').Status | Should -Be 'OK'
    }

    It 'flags the eligible assignments as not visible when PIM needs RoleManagement.Read.Directory' {
        $ctx = New-DisabledCtx
        $script:graph['roleAssignmentScheduleInstances'] = 'GRAPH-403 https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances: HTTP 403: Forbidden'
        $null = Invoke-EbrCatalogItem -Ctx $ctx -Item $script:item
        $entra = $ctx.Pending | Where-Object ResultId -eq 'IA.15-ENTRA'
        $entra.Status | Should -Be 'PARTIAL' -Because 'an eligible assignment may be missing'
        $entra.Detail | Should -Match '^Eligible assignments not visible, needs RoleManagement\.Read\.Directory'
        @($entra.Rows | ForEach-Object AssignmentType | Sort-Object -Unique) | Should -Be @('Standing')
        @($entra.Rows | ForEach-Object PimRead | Sort-Object -Unique) | Should -Be @('NoPermission')
        @($ctx.GraphPartial) | Should -Contain 'IA.15-ENTRA (eligible role assignments)'
    }

    It 'keeps the activated and time-bound assignments when only the eligible schedule read fails' {
        $ctx = New-DisabledCtx
        $script:graph['roleEligibilityScheduleInstances'] = 'HTTP 429: Too Many Requests'
        $null = Invoke-EbrCatalogItem -Ctx $ctx -Item $script:item
        $entra = $ctx.Pending | Where-Object ResultId -eq 'IA.15-ENTRA'
        $entra.Status | Should -Be 'PARTIAL' -Because 'an eligible assignment may be missing'
        $entra.Detail | Should -Match '^Eligible assignments not visible, the PIM schedule instances could not be read'
        $lee = @($entra.Rows | Where-Object { $_.UserPrincipalName -eq 'lee.ashford@contoso.com' -and $_.HeldThrough -eq 'Direct' })
        @($lee | ForEach-Object AssignmentType) | Should -Be @('Activated') -Because 'the active instances were read, so an activation never reads as Standing'
        $lee[0].EndDateUtc | Should -Be '2026-10-11T20:00:00Z'
        @($entra.Rows | Where-Object AssignmentType -eq 'Eligible').Count | Should -Be 0
    }

    It 'marks the Azure side partial through Lighthouse, and when a group cannot be read' {
        $ctx = New-DisabledCtx 'Lighthouse'
        $null = Invoke-EbrCatalogItem -Ctx $ctx -Item $script:item
        $rbac = $ctx.Pending | Where-Object ResultId -eq 'IA.15-RBAC'
        $rbac.Status | Should -Be 'PARTIAL'
        $rbac.Detail | Should -Match "Read through Lighthouse, which shows the managing tenant's delegations"
        $rbac.Source | Should -Be 'Resource Graph (lighthouse) and Microsoft Graph'
        $ctx = New-DisabledCtx
        $script:graph["groups/$($script:fx.Ops)/members"] = 'GRAPH-403 https://graph.microsoft.com/v1.0/groups: HTTP 403: Forbidden'
        $null = Invoke-EbrCatalogItem -Ctx $ctx -Item $script:item
        foreach ($id in 'IA.15-RBAC', 'IA.15-ENTRA') {
            $x = $ctx.Pending | Where-Object ResultId -eq $id
            $x.Status | Should -Be 'PARTIAL' -Because $id
            $x.Detail | Should -Match "The members of 1 group could not be read, so the (Azure|Entra) roles held through it are not listed: $($script:fx.Ops)\." -Because $id
            @($x.Rows | Where-Object GroupId -eq $script:fx.Ops).Count | Should -Be 0
        }
        @(($ctx.Pending | Where-Object ResultId -eq 'IA.15-RBAC').Rows | Where-Object HeldThrough -eq 'Group' | ForEach-Object GroupName | Sort-Object -Unique) | Should -Be @('all-staff-dynamic', 'legacy-admins') -Because 'the other groups are still read'
        @($ctx.GraphMissingScopes) | Should -Contain 'GroupMember.Read.All'
        # A nested group that cannot be read keeps the members read above it and is named itself.
        $ctx = New-DisabledCtx
        $script:graph = New-DisabledGraph @{ "groups/$($script:fx.Tier2)/members" = 'HTTP 429: Too Many Requests' }
        $null = Invoke-EbrCatalogItem -Ctx $ctx -Item $script:item
        $rbac = $ctx.Pending | Where-Object ResultId -eq 'IA.15-RBAC'
        $rbac.Status | Should -Be 'PARTIAL'
        $rbac.Detail | Should -Match "The members of 1 group could not be read, so the Azure roles held through it are not listed: $($script:fx.Tier2)\."
        @($rbac.Rows | Where-Object { $_.GroupId -eq $script:fx.Ops } | ForEach-Object { '{0}|{1}' -f $_.UserPrincipalName, $_.MemberOfName } | Sort-Object) | Should -Be @('kim.osei@contoso.com|platform-operators', 'lee.ashford@contoso.com|ops-contractors') -Because 'the direct member of platform-operators and the member reached through ops-contractors are still listed'
    }

    It 'reads nothing more when no account is disabled' {
        $ctx = New-DisabledCtx
        $script:fxUsersSaved = $script:graph['users\?\$filter=accountEnabled eq false']
        $script:graph['users\?\$filter=accountEnabled eq false'] = @($script:fxUsers | Where-Object accountEnabled)
        $r = Invoke-EbrCatalogItem -Ctx $ctx -Item $script:item
        @(@($r) + @($ctx.Pending) | ForEach-Object Status) | Should -Be @('EMPTY', 'EMPTY', 'EMPTY')
        Should -Invoke Invoke-EbrArgQuery -Times 0 -Exactly
        Should -Invoke Invoke-EbrGraphGet -Times 1 -Exactly
    }
}

Describe 'Emergency access accounts (IA.16, CyberSOC 1.12.0)' {
    BeforeAll {
        # A scenario from tests/fixtures/offline-pack/emergency-access: the Graph answers, and what the read makes of them.
        function script:Get-EaScenario([string]$Name) { Get-Content (Join-Path $PSScriptRoot "fixtures/offline-pack/emergency-access/$Name.json") -Raw | ConvertFrom-Json }
        function script:New-EaCtx {
            [pscustomobject]@{
                TenantGuid = 'client'; GraphAvailable = $true; GraphReason = ''; GraphCache = @{}; ArmTenant = 'client'; AccessPath = 'Direct'; Subscriptions = @('s1')
                GraphMissingScopes = [System.Collections.Generic.List[string]]::new(); GraphPartial = [System.Collections.Generic.List[string]]::new(); Pending = [System.Collections.Generic.List[object]]::new()
                OutDir = $TestDrive; WindowStart = [datetime]'2026-07-01'; WindowEnd = [datetime]'2026-09-30'; ManagedRgPattern = 'aznativesol0'
            }
        }
        # Runs IA.16 against a scenario's Graph answers. A string answer is the error Graph returns.
        function script:Invoke-EaScenario($Scenario, $Ctx = (New-EaCtx)) {
            $script:eaGraph = $Scenario.Graph
            $accounts = Invoke-EbrCatalogItem -Ctx $Ctx -Item $script:eaItem
            @{ Accounts = $accounts; Groups = ($Ctx.Pending | Where-Object ResultId -eq 'IA.16-GROUPS'); Ctx = $Ctx }
        }
        $script:eaItem = Get-EbrQueryCatalog | Where-Object Id -eq 'IA.16-ACCOUNTS'
        $null = New-Item -ItemType Directory -Path (Join-Path $TestDrive 'queries') -Force
    }
    BeforeEach {
        Mock Invoke-EbrGraphGet {
            $answer = if ($Uri -match '/v1\.0/users\?') { $script:eaGraph.Users }
            elseif ($Uri -match '/v1\.0/groups\?') { $script:eaGraph.Groups }
            elseif ($Uri -match '/v1\.0/groups/([0-9a-f-]+)/transitiveMembers/microsoft\.graph\.user\?') {
                $p = $script:eaGraph.Members.PSObject.Properties[$Matches[1]]
                if (-not $p) { throw "unexpected $Uri" }
                $p.Value
            }
            else { throw "unexpected $Uri" }
            if ($answer -is [string]) { throw $answer }
            , @($answer)
        }
    }

    It 'reads every user and every group in full and matches offline, since Graph has no contains and $search could miss one' {
        $script:eaItem.Engine | Should -Be 'EMERGENCY-ACCESS'
        $script:eaItem.Phase | Should -Be 'P2 Identity'
        $script:eaItem.Notes | Should -Match '^Added in CyberSOC 1\.12\.0\.'
        $script:eaItem.Notes | Should -Match 'User\.Read\.All and GroupMember\.Read\.All'
        $script:eaItem.Notes | Should -Match 'Internal: names accounts\.$'
        $q = $script:eaItem.Query
        $q | Should -Match '(?m)^GET /v1\.0/users\?\$select=id,userPrincipalName,displayName,userType,accountEnabled&\$top=999$'
        $q | Should -Match '(?m)^GET /v1\.0/groups\?\$select=id,displayName,groupTypes,onPremisesSyncEnabled,membershipRule,visibility&\$top=999$'
        $q | Should -Match 'transitiveMembers/microsoft\.graph\.user\?\$count=true'
        $q | Should -Match '(?m)^Permission: User\.Read\.All, GroupMember\.Read\.All \(Member\.Read\.Hidden for a group with hidden membership\)$'
        $q | Should -Not -Match '\$search|\$filter' -Because 'a whole-word or starts-with match could miss an account'
        $null = Invoke-EaScenario (Get-EaScenario 'complete')
        Should -Invoke Invoke-EbrGraphGet -Times 1 -Exactly -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,displayName,userType,accountEnabled&$top=999' -and $Complete }
        Should -Invoke Invoke-EbrGraphGet -Times 1 -Exactly -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/groups?$select=id,displayName,groupTypes,onPremisesSyncEnabled,membershipRule,visibility&$top=999' -and $Complete }
        Should -Invoke Invoke-EbrGraphGet -Times 3 -Exactly -ParameterFilter { $Uri -like '*/transitiveMembers/microsoft.graph.user?$count=true&$select=id,userPrincipalName,displayName,userType,accountEnabled&$top=999' -and $Complete } -Because 'only the three Atmosera groups are read, not IT Admins or Platform Ops'
        Test-Path (Join-Path $TestDrive 'queries/IA.16-ACCOUNTS.graph.txt') | Should -BeTrue
    }

    It 'matches a member by its UPN, a guest by its #EXT# UPN, any case, and the members of nested groups, and nothing else' {
        $sc = Get-EaScenario 'complete'
        $r = Invoke-EaScenario $sc
        $r.Accounts.ResultId | Should -Be 'IA.16-ACCOUNTS'
        $r.Accounts.Status | Should -Be $sc.Expect.'IA.16-ACCOUNTS'.Status
        $r.Groups.Status | Should -Be $sc.Expect.'IA.16-GROUPS'.Status
        @($r.Accounts.Rows | ForEach-Object { '{0}|{1}|{2}' -f $_.UserPrincipalName, $_.MatchedBy, (@($_.Groups) -join ',') }) | Should -Be @($sc.Expect.Accounts | ForEach-Object { '{0}|{1}|{2}' -f $_.UserPrincipalName, $_.MatchedBy, (@($_.Groups) -join ',') })
        @($r.Groups.Rows | ForEach-Object { '{0}|{1}|{2}' -f $_.DisplayName, $_.Members, $_.Membership }) | Should -Be @($sc.Expect.Groups | ForEach-Object { '{0}|{1}|{2}' -f $_.DisplayName, $_.Members, $_.Membership })
        $guest = $r.Accounts.Rows | Where-Object UserPrincipalName -like '*#EXT#*'
        $guest.UserType | Should -Be 'Guest'
        ($r.Accounts.Rows | Where-Object UserPrincipalName -like 'SOC.*').AccountEnabled | Should -BeFalse -Because 'a disabled emergency access account is still listed, with its state'
        @($r.Accounts.Rows | ForEach-Object PrincipalId) | Should -Not -Contain $null
        $json = ConvertTo-Json -InputObject @(@($r.Accounts.Rows) + @($r.Groups.Rows)) -Depth 5
        foreach ($n in $sc.Expect.NotListed) { $json | Should -Not -Match ([regex]::Escape($n)) -Because "$n is not Atmosera's" }
        ($r.Groups.Rows | Where-Object Membership -eq 'Dynamic').MembershipRule | Should -Be 'user.department -eq "SOC Tier 0"'
        $r.Groups.Detail | Should -Match 'Membership not assigned by hand: ATMOSERA Support \(synced\) \(On-premises\), SOC-atmosera-Tier0 \(Dynamic\)\.'
        $r.Accounts.Detail | Should -Match '^5 emergency access accounts: 3 by UPN and 3 in an Atmosera group, 1 of them guests, of 7 user accounts read\.'
        $r.Accounts.Detail | Should -Match 'An account whose UPN does not contain Atmosera is listed only when it sits in an Atmosera group\.'
    }

    It 'reads a tenant with no Atmosera account or group as EMPTY, which the change requests never take as clearance' {
        $sc = Get-EaScenario 'no-match'
        $r = Invoke-EaScenario $sc
        $r.Accounts.Status | Should -Be 'EMPTY'
        $r.Groups.Status | Should -Be 'EMPTY'
        Should -Invoke Invoke-EbrGraphGet -Times 0 -Exactly -ParameterFilter { $Uri -like '*transitiveMembers*' }
    }

    It 'reports a refused or failed read, never EMPTY, and names the permission' {
        $sc = Get-EaScenario 'failed-read'
        $r = Invoke-EaScenario $sc
        $r.Accounts.Status | Should -Be 'UNAVAILABLE'
        $r.Accounts.Detail | Should -Match '^Not a zero: the Graph token cannot read user accounts\. Needs User\.Read\.All\. Fix: az login --tenant client --scope https://graph\.microsoft\.com/User\.Read\.All'
        $r.Groups.Status | Should -Be 'FAILED'
        $r.Groups.Detail | Should -Match '^The groups could not be read in full\. HTTP 500'
        @($r.Ctx.GraphMissingScopes) | Should -Be @('User.Read.All')
        @($r.Accounts.Rows).Count + @($r.Groups.Rows).Count | Should -Be 0
    }

    It 'marks both results PARTIAL when an Atmosera group''s members cannot be read, and names the group' {
        $sc = Get-EaScenario 'members-unread'
        $r = Invoke-EaScenario $sc
        $r.Accounts.Status | Should -Be 'PARTIAL'
        $r.Groups.Status | Should -Be 'PARTIAL'
        $r.Groups.Detail | Should -Match 'The members of 1 Atmosera group could not be read, so the accounts in it are unknown: Atmosera Emergency Access \('
        ($r.Groups.Rows | Select-Object -First 1).MembersRead | Should -BeFalse
        @($r.Accounts.Rows | ForEach-Object UserPrincipalName) | Should -Be @($sc.Expect.Accounts | ForEach-Object UserPrincipalName)
        @($r.Ctx.GraphPartial) | Should -Be @('IA.16 (Atmosera group members)')
        @($r.Ctx.GraphMissingScopes) | Should -Be @('GroupMember.Read.All')
        # Microsoft Learn: the members of a group with hidden membership need Member.Read.Hidden as well.
        $sc = Get-EaScenario 'members-unread'
        $sc.Graph.Groups[0] | Add-Member -NotePropertyName visibility -NotePropertyValue 'HiddenMembership'
        $r = Invoke-EaScenario $sc
        @($r.Ctx.GraphMissingScopes) | Should -Be @('Member.Read.Hidden') -Because 'the token may already hold GroupMember.Read.All'
        $r.Groups.Detail | Should -Match 'Atmosera Emergency Access \([0-9a-f-]+, hidden membership, needs Member\.Read\.Hidden\)'
    }

    It 'keeps the UPN matches PARTIAL when only the groups cannot be read, and fails a read cut short' {
        $sc = Get-EaScenario 'complete'
        $sc.Graph.Groups = 'GRAPH-403 https://graph.microsoft.com/v1.0/groups: HTTP 403: Forbidden'
        $r = Invoke-EaScenario $sc
        $r.Groups.Status | Should -Be 'UNAVAILABLE'
        $r.Groups.Detail | Should -Match 'Needs GroupMember\.Read\.All'
        $r.Accounts.Status | Should -Be 'PARTIAL'
        $r.Accounts.Detail | Should -Match 'The groups were not read \(IA\.16-GROUPS UNAVAILABLE\), so only the accounts matched by UPN are listed\.'
        @($r.Accounts.Rows | ForEach-Object MatchedBy | Sort-Object -Unique) | Should -Be @('UPN')
        $sc = Get-EaScenario 'complete'
        $sc.Graph.Users = 'GRAPH-TRUNCATED https://graph.microsoft.com/v1.0/users: more than 200 pages, so the read was cut short.'
        $r = Invoke-EaScenario $sc
        $r.Accounts.Status | Should -Be 'FAILED'
        $r.Accounts.Detail | Should -Match 'cut short'
    }

    It 'reports both UNAVAILABLE when Microsoft Graph is not reachable' {
        $ctx = New-EaCtx
        $ctx.GraphAvailable = $false
        $ctx.GraphReason = 'No Graph token: AADSTS530004.'
        $r = Invoke-EaScenario (Get-EaScenario 'complete') $ctx
        $r.Accounts.Status | Should -Be 'UNAVAILABLE'
        $r.Groups.Status | Should -Be 'UNAVAILABLE'
        $r.Accounts.Detail | Should -Match '^Not a zero: Microsoft Graph was not reachable.*AADSTS530004'
        Should -Invoke Invoke-EbrGraphGet -Times 0 -Exactly
    }
}

Describe 'Graph paging that must not be cut short' {
    It 'throws GRAPH-TRUNCATED with Complete when pages remain, and returns what it read without it' {
        Mock Invoke-EbrRest { [pscustomobject]@{ value = @([pscustomobject]@{ id = '1' }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/users?$skiptoken=x' } }
        { Invoke-EbrGraphGet -Uri 'https://graph.microsoft.com/v1.0/users?$top=999' -Tenant 't' -MaxPages 2 -Complete } | Should -Throw 'GRAPH-TRUNCATED https://graph.microsoft.com/v1.0/users: more than 2 pages*'
        (Invoke-EbrGraphGet -Uri 'https://graph.microsoft.com/v1.0/users?$top=999' -Tenant 't' -MaxPages 2).Count | Should -Be 2 -Because 'the other reads keep their behaviour'
    }
}

Describe 'Licensing check (LIC, CyberSOC 1.11.0)' {
    BeforeAll {
        Mock Write-Host { }
        Mock Start-Sleep { }
        $catalog = Get-EbrQueryCatalog
        $s1 = '5f1c2a9e-3b7d-4e21-9a6c-0d8e4f2b7c11'
        function New-LicCtx {
            [pscustomobject]@{
                TenantGuid = 'client'; GraphAvailable = $true; GraphReason = ''; GraphAdvice = ''; GraphCache = @{}; DefenderAvailable = $true; DefenderReason = ''
                GraphMissingScopes = [System.Collections.Generic.List[string]]::new(); GraphPartial = [System.Collections.Generic.List[string]]::new(); Pending = [System.Collections.Generic.List[object]]::new()
                OutDir = $TestDrive; WindowStart = [datetime]'2026-07-01'; WindowEnd = [datetime]'2026-09-30'; ManagedRgPattern = 'aznativesol0'; TicketPattern = ''; PatchCadenceDays = 30
                Results = @{}; Subscriptions = @('5f1c2a9e-3b7d-4e21-9a6c-0d8e4f2b7c11', 'a0b1c2d3-e4f5-4a6b-8c7d-9e0f1a2b3c4d'); DefenderEndpointPlan = ''
            }
        }
        $null = New-Item -ItemType Directory -Path (Join-Path $TestDrive 'queries') -Force
        # A scenario from tests/fixtures/offline-pack/licensing loaded into a context, as the collector holds its results.
        function Get-LicScenario([string]$Name) {
            $sc = Get-Content (Join-Path $PSScriptRoot "fixtures/offline-pack/licensing/$Name.json") -Raw | ConvertFrom-Json
            $ctx = New-LicCtx
            $ctx.Subscriptions = @($sc.Subscriptions)
            $ctx.DefenderEndpointPlan = [string]$sc.Reading
            foreach ($p in $sc.Results.PSObject.Properties) { $ctx.Results[$p.Name] = New-EbrResult -ResultId $p.Name -Status $p.Value.Status -Rows @($p.Value.Rows) -Source $(if ($p.Name -eq 'LIC.3-TVM') { 'Defender Advanced Hunting' } else { 'x' }) }
            [pscustomobject]@{ Scenario = $sc; Ctx = $ctx }
        }
    }

    It 'adds the four reads and the derived matrix in their own phase, after the device reads they join' {
        $ids = @($catalog | ForEach-Object Id)
        foreach ($id in 'LIC.1-SKUS', 'LIC.2-MACHINES', 'LIC.3-TVM', 'LIC.4-DEVICES', 'LIC.5-MATRIX') {
            $item = $catalog | Where-Object Id -eq $id
            $item.Phase | Should -Be 'P2 Licensing' -Because $id
            $item.Notes | Should -Match 'Added in CyberSOC 1\.11\.0' -Because $id
            [array]::IndexOf($ids, $id) | Should -BeGreaterThan ([array]::IndexOf($ids, 'EW.1-EDR')) -Because "$id reads EW.1-VMS and EW.1-EDR"
        }
        ($catalog | Where-Object Id -eq 'LIC.5-MATRIX').Engine | Should -Be 'DERIVED'
        ($catalog | Where-Object Id -eq 'LIC.2-MACHINES').Engine | Should -Be 'DEFENDER-MACHINES'
        (Get-EbrGraphSpec 'LIC.1-SKUS').Permission | Should -Be 'LicenseAssignment.Read.All'
        (Get-EbrGraphSpec 'LIC.4-DEVICES').Permission | Should -Be 'Device.Read.All'
        $tvm = ($catalog | Where-Object Id -eq 'LIC.3-TVM').Query
        $tvm | Should -Match 'AzureResourceId !contains "\{\{MRG\}\}"'
        $tvm | Should -Match 'DeviceManualTags' -Because 'a tag set by hand counts'
        $tvm | Should -Match 'DeviceDynamicTags' -Because 'a tag set by a dynamic rule counts too'
        $tvm | Should -Match 'DeviceTvmSoftwareVulnerabilities' ; $tvm | Should -Match 'DeviceTvmSecureConfigurationAssessment'
        $p03 = $catalog | Where-Object Id -eq 'P0.3'
        $p03.Query | Should -Match 'Extensions = properties\.extensions'
        $p03.Notes | Should -Match 'Extensions added in CyberSOC 1\.11\.0'
    }

    It 'pages the device list with top and skip, ties each device to its Azure machine and leaves the managed resource group out' {
        $script:machineUris = [System.Collections.Generic.List[string]]::new()
        Mock Invoke-EbrRest {
            $script:machineUris.Add($Uri)
            $Method | Should -Be 'GET'
            $Resource | Should -Be 'https://api.securitycenter.microsoft.com/'
            if ($Uri -match 'skip=0') {
                return [pscustomobject]@{ value = @(
                        [pscustomobject]@{ id = 'ABC'; computerDnsName = 'vm-app01.corp.example'; osPlatform = 'WindowsServer2022'; onboardingStatus = 'Onboarded'; healthStatus = 'Active'; machineTags = @('License MDE P1'); rbacGroupName = 'Servers'; lastSeen = '2026-10-07T10:00:00Z' }
                        [pscustomobject]@{ id = 'def'; computerDnsName = 'vm-web01'; osPlatform = 'Linux'; onboardingStatus = 'Onboarded'; healthStatus = 'Active'; machineTags = @(); lastSeen = '2026-10-07T10:00:00Z' }
                        [pscustomobject]@{ id = 'ghi'; computerDnsName = 'ws-0101'; osPlatform = 'Windows11'; onboardingStatus = 'Onboarded'; healthStatus = 'Active'; machineTags = @('License MDE P1', 'VIP'); lastSeen = '2026-10-07T10:00:00Z' }
                        [pscustomobject]@{ id = 'mrg'; computerDnsName = 'aks-node'; osPlatform = 'Linux'; onboardingStatus = 'Onboarded'; healthStatus = 'Active'; machineTags = @(); lastSeen = '2026-10-07T10:00:00Z' }) }
            }
            throw "unexpected $Uri"
        }
        $vms = @([pscustomobject]@{ DeviceId = 'abc'; AzureResourceId = "/subscriptions/$s1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-app01" }
            [pscustomobject]@{ DeviceId = 'mrg'; AzureResourceId = "/subscriptions/$s1/resourceGroups/aznativesol0-rg/providers/Microsoft.Compute/virtualMachines/aks-node" })
        $azure = @([pscustomobject]@{ VmId = "/subscriptions/$s1/resourcegroups/rg-web/providers/microsoft.compute/virtualmachines/vm-web01"; VmName = 'vm-web01' })
        $rows = @(Get-EbrDefenderMachines -Tenant 'client' -Vms $vms -AzureVms $azure -ManagedRgPattern 'aznativesol0')
        $script:machineUris[0] | Should -Be 'https://api.security.microsoft.com/api/machines?$top=10000&$skip=0'
        $script:machineUris.Count | Should -Be 1 -Because 'a page shorter than 10,000 is the last'
        $rows.Count | Should -Be 3 -Because 'the device in the managed resource group is left out'
        ($rows | Where-Object ComputerDnsName -eq 'vm-app01.corp.example').subscriptionId | Should -Be $s1 -Because 'the device ID matches EW.1-VMS'
        ($rows | Where-Object ComputerDnsName -eq 'vm-web01').AzureResourceId | Should -Match 'rg-web/providers/microsoft\.compute/virtualmachines/vm-web01$' -Because 'the name matches one machine in EW.1-EDR'
        ($rows | Where-Object ComputerDnsName -eq 'vm-web01').DeviceClass | Should -Be 'Linux'
        ($rows | Where-Object ComputerDnsName -eq 'ws-0101').TaggedPlan1 | Should -BeTrue
        ($rows | Where-Object ComputerDnsName -eq 'ws-0101').DeviceClass | Should -Be 'Client'
        ($rows | Where-Object ComputerDnsName -eq 'ws-0101').AzureResourceId | Should -Be ''
    }

    It 'reads the next page while a page is full, ties no device to a name two machines share, and reads a 404 as no device' {
        $script:pages = 0
        Mock Invoke-EbrRest {
            $script:pages++
            if ($Uri -match 'skip=0$') { return [pscustomobject]@{ value = @(1..10000 | ForEach-Object { [pscustomobject]@{ id = "d$_"; computerDnsName = "ws-$_"; osPlatform = 'Windows11'; onboardingStatus = 'Onboarded' } }) } }
            if ($Uri -match 'skip=10000$') { return [pscustomobject]@{ value = @([pscustomobject]@{ id = 'last'; computerDnsName = 'dup'; osPlatform = 'WindowsServer2019'; onboardingStatus = 'Onboarded' }) } }
            throw "unexpected $Uri"
        }
        $azure = @([pscustomobject]@{ VmId = '/subscriptions/a/resourcegroups/r1/providers/microsoft.compute/virtualmachines/dup'; VmName = 'dup' }, [pscustomobject]@{ VmId = '/subscriptions/a/resourcegroups/r2/providers/microsoft.compute/virtualmachines/dup'; VmName = 'dup' })
        $rows = @(Get-EbrDefenderMachines -Tenant 'client' -Vms @() -AzureVms $azure)
        $script:pages | Should -Be 2
        $rows.Count | Should -Be 10001
        ($rows | Where-Object MachineId -eq 'last').AzureResourceId | Should -Be ''
        Mock Invoke-EbrRest { throw 'HTTP 404: Not Found | No recent machines' }
        @(Get-EbrDefenderMachines -Tenant 'client').Count | Should -Be 0
    }

    It 'marks the devices UNAVAILABLE, never a zero, without the Defender API or without the permission' {
        $item = $catalog | Where-Object Id -eq 'LIC.2-MACHINES'
        $ctx = New-LicCtx
        $ctx.DefenderAvailable = $false; $ctx.DefenderReason = 'No Defender API token.'
        $r = Invoke-EbrCatalogItem -Ctx $ctx -Item $item
        $r.Status | Should -Be 'UNAVAILABLE'
        $r.Detail | Should -Match 'Not a zero'
        Mock Get-EbrDefenderMachines { throw 'HTTP 403: Forbidden | Missing application roles' }
        $r = Invoke-EbrCatalogItem -Ctx (New-LicCtx) -Item $item
        $r.Status | Should -Be 'UNAVAILABLE'
        $r.Detail | Should -Match 'Needs Machine\.Read and the View Data role'
        Mock Get-EbrDefenderMachines { }
        (Invoke-EbrCatalogItem -Ctx (New-LicCtx) -Item $item).Status | Should -Be 'EMPTY'
    }

    It 'reads the Windows servers with their ASR rules and antivirus prerequisites, Azure virtual machines only, outside the managed resource group (1.17.0)' {
        $item = $catalog | Where-Object Id -eq 'EW.4-SERVERS'
        $item.Engine | Should -Be 'AH'
        $item.Phase | Should -Be 'P2 Endpoint'
        $item.Notes | Should -Match '^Added in CyberSOC 1\.17\.0\.'
        $q = $item.Query
        $q | Should -Match '(?m)^DeviceInfo$'
        $q | Should -Match 'where OSPlatform startswith "WindowsServer"'
        $q | Should -Match 'where isnotempty\(AzureResourceId\)' -Because 'every device query reads Azure virtual machines only'
        $q | Should -Match 'AzureResourceId !contains "\{\{MRG\}\}"'
        $q | Should -Not -Match 'where OnboardingStatus' -Because 'a server seen but not onboarded is listed, so the change request can name it'
        $q | Should -Match 'join kind=leftouter \(\s+DeviceTvmSecureConfigurationAssessment' -Because 'a server without a configuration assessment stays listed'
        $q | Should -Match 'ConfigurationSubcategory =~ "Antivirus" and ConfigurationName has "real-time protection"'
        $q | Should -Match 'ConfigurationSubcategory =~ "Antivirus" and ConfigurationName has "cloud-delivered protection"'
        $q | Should -Match 'case\(isnull\(RtpChecks\) or RtpChecks == 0, "", RtpOn == RtpChecks, "On", "Off"\)' -Because 'a check not assessed is never read as Off or On'
        $q | Should -Match 'DomainController   = tostring\(DeviceRoles\) has_any \("DomainController", "Domain Controller"\)'
        foreach ($rule in 'Block abuse of exploited vulnerable signed drivers', 'Block persistence through WMI event subscription', 'Block rebooting machine in Safe Mode', 'Block use of copied or impersonated system tools', 'Block Webshell creation for Servers', 'Use advanced protection against ransomware') { $q | Should -Match ([regex]::Escape(('"{0}"' -f $rule))) }
        $q | Should -Not -Match 'Block Win32 API calls from Office macros' -Because 'it does not apply to Windows Server'
        $q | Should -Match 'AsrApplicable = coalesce\(AsrApplicable, 0\), AsrConfigured = coalesce\(AsrConfigured, 0\), ConfiguredRules, MissingRules'
        $expanded = Expand-EbrQuery -Query $q -WindowStart ([datetime]'2026-01-01') -WindowEnd ([datetime]'2026-06-30') -ManagedRgPattern 'aznativesol0'
        $expanded | Should -Match 'AzureResourceId !contains "aznativesol0"'
        $expanded | Should -Not -Match '\{\{'
        [array]::IndexOf(@($catalog | ForEach-Object Id), 'EW.4-SERVERS') | Should -BeGreaterThan ([array]::IndexOf(@($catalog | ForEach-Object Id), 'EW.4'))
    }

    It 'pages the antivirus mode of each Windows device with top and skip, names each mode and reads a 404 as no device (1.17.0)' {
        $item = $catalog | Where-Object Id -eq 'EW.4-AVMODE'
        $item.Engine | Should -Be 'DEFENDER-AVINFO'
        $item.Notes | Should -Match '^Added in CyberSOC 1\.17\.0\.'
        $item.Notes | Should -Match '0 Active, 1 Passive, 2 Disabled, 3 or empty Other, 4 EDR in block mode, 5 Passive audit'
        $script:avUris = [System.Collections.Generic.List[string]]::new()
        Mock Invoke-EbrRest {
            $script:avUris.Add($Uri)
            $Method | Should -Be 'GET'
            $Resource | Should -Be 'https://api.securitycenter.microsoft.com/'
            if ($Uri -match 'skip=0$') { return [pscustomobject]@{ value = @(1..10000 | ForEach-Object { [pscustomobject]@{ machineId = "D$_"; computerDnsName = "srv-$_"; osKind = 'windows'; osPlatform = 'Windows Server 2022'; avMode = '0' } }) } }
            if ($Uri -match 'skip=10000$') { return [pscustomobject]@{ value = @(
                        [pscustomobject]@{ machineId = 'PASSIVE1'; computerDnsName = 'srv-legacy01'; osKind = 'windows'; osPlatform = 'Windows Server 2016'; avMode = '1'; dataRefreshTimestamp = '2026-10-07T10:00:00Z' }
                        [pscustomobject]@{ machineId = 'blank'; computerDnsName = 'srv-unknown'; osKind = 'windows'; avMode = '' }
                        [pscustomobject]@{ machineId = 'edr'; computerDnsName = 'srv-edr'; osKind = 'windows'; avMode = '4' }
                        [pscustomobject]@{ machineId = 'mac'; computerDnsName = 'mac-01'; osKind = 'mac'; avMode = '0' }) } }
            throw "unexpected $Uri"
        }
        $rows = @(Get-EbrDefenderAvInfo -Tenant 'client')
        $script:avUris[0] | Should -Be 'https://api.security.microsoft.com/api/deviceavinfo?$top=10000&$skip=0'
        $script:avUris.Count | Should -Be 2 -Because 'a full page is followed by the next'
        $rows.Count | Should -Be 10003 -Because 'a device that is not Windows is left out'
        ($rows | Where-Object MachineId -eq 'passive1').AvModeName | Should -Be 'Passive' -Because 'the machine ID is kept in lower case, as Advanced Hunting gives DeviceId'
        ($rows | Where-Object MachineId -eq 'passive1').DataRefreshTimestamp | Should -Be '2026-10-07T10:00:00Z'
        ($rows | Where-Object MachineId -eq 'blank').AvModeName | Should -Be 'Other' -Because 'an empty mode is never read as Active'
        ($rows | Where-Object MachineId -eq 'edr').AvModeName | Should -Be 'EDRBlocked'
        Mock Invoke-EbrRest { throw 'HTTP 404: Not Found' }
        @(Get-EbrDefenderAvInfo -Tenant 'client').Count | Should -Be 0
    }

    It 'marks the antivirus mode UNAVAILABLE, never a zero, without the Defender API or without the permission (1.17.0)' {
        $item = $catalog | Where-Object Id -eq 'EW.4-AVMODE'
        $ctx = New-LicCtx
        $ctx.DefenderAvailable = $false; $ctx.DefenderReason = 'No Defender API token.'
        $r = Invoke-EbrCatalogItem -Ctx $ctx -Item $item
        $r.Status | Should -Be 'UNAVAILABLE'
        $r.Detail | Should -Match 'Not a zero'
        Mock Get-EbrDefenderAvInfo { throw 'HTTP 403: Forbidden | Missing application roles' }
        $r = Invoke-EbrCatalogItem -Ctx (New-LicCtx) -Item $item
        $r.Status | Should -Be 'UNAVAILABLE'
        $r.Detail | Should -Match 'Needs Machine\.Read and the View Data role'
        Mock Get-EbrDefenderAvInfo { throw 'HTTP 500: Internal Server Error' }
        (Invoke-EbrCatalogItem -Ctx (New-LicCtx) -Item $item).Status | Should -Be 'FAILED'
        Mock Get-EbrDefenderAvInfo { [pscustomobject]@{ MachineId = 'a'; ComputerDnsName = 'srv'; OsPlatform = ''; AvMode = '1'; AvModeName = 'Passive'; DataRefreshTimestamp = ''; LastSeenTime = '' } }
        $r = Invoke-EbrCatalogItem -Ctx (New-LicCtx) -Item $item
        $r.Status | Should -Be 'OK'
        $r.Detail | Should -Be '1 Windows device listed, 0 in Active mode, 1 in another mode.'
    }

    It 'reads the licenses with their service plans, and names LicenseAssignment.Read.All when Graph refuses' {
        Mock Invoke-EbrGraphGet {
            $Uri | Should -Match 'v1\.0/subscribedSkus\?\$select='
            , @([pscustomobject]@{ skuId = 'CBDC14AB-D96C-4C30-B9F4-6ADA7CDC1D46'; skuPartNumber = 'SPB'; appliesTo = 'User'; capabilityStatus = 'Warning'; consumedUnits = 97; prepaidUnits = [pscustomobject]@{ enabled = 0; suspended = 0; warning = 120; lockedOut = 0 }
                    servicePlans = @([pscustomobject]@{ servicePlanId = 'BFC1BBD9-981B-4F71-9B82-17C35FD0E2A4'; servicePlanName = 'MDE_SMB'; provisioningStatus = 'Success'; appliesTo = 'User' }) })
        }
        $ctx = New-LicCtx
        $r = Invoke-EbrGraphCollector -Ctx $ctx -Item ($catalog | Where-Object Id -eq 'LIC.1-SKUS')
        $r.Status | Should -Be 'OK'
        $r.Rows[0].SkuId | Should -Be 'cbdc14ab-d96c-4c30-b9f4-6ada7cdc1d46'
        $r.Rows[0].Warning | Should -Be 120
        $r.Rows[0].Consumed | Should -Be 97
        $r.Rows[0].ServicePlans[0].ServicePlanId | Should -Be 'bfc1bbd9-981b-4f71-9b82-17c35fd0e2a4'
        $r.Detail | Should -Match '1 SKU, 1 active'
        Mock Invoke-EbrGraphGet { throw 'GRAPH-403 https://graph.microsoft.com/v1.0/subscribedSkus: HTTP 403: Forbidden' }
        $ctx = New-LicCtx
        $r = Invoke-EbrGraphCollector -Ctx $ctx -Item ($catalog | Where-Object Id -eq 'LIC.1-SKUS')
        $r.Status | Should -Be 'UNAVAILABLE'
        $r.Detail | Should -Match 'Needs LicenseAssignment\.Read\.All'
        @($ctx.GraphMissingScopes) | Should -Be @('LicenseAssignment.Read.All')
    }

    It 'lists the Microsoft Entra devices with their management type, and what the stale device change leaves out (1.19.0)' {
        Mock Invoke-EbrGraphGet {
            $Uri | Should -Match 'v1\.0/devices\?\$select=.*managementType.*approximateLastSignInDateTime'
            $Uri | Should -Match 'v1\.0/devices\?\$select=[^&]*,physicalIds,profileType,systemLabels&\$top=999$' -Because 'CR-24 leaves out Autopilot devices, printers and system-managed devices'
            , @([pscustomobject]@{ id = 'o1'; deviceId = 'd1'; displayName = 'srv-01'; accountEnabled = $true; operatingSystem = 'Windows Server'; managementType = 'MicrosoftSense'; approximateLastSignInDateTime = '2026-10-01T00:00:00Z'; physicalIds = @(); profileType = 'RegisteredDevice'; systemLabels = @() }
                [pscustomobject]@{ id = 'o2'; deviceId = 'd2'; displayName = 'ws-01'; accountEnabled = $false; operatingSystem = 'Windows'; managementType = 'mdm'; physicalIds = @('[ZTDId]:3f2c', '[HWID]:h:6896'); profileType = 'RegisteredDevice'; systemLabels = @() }
                [pscustomobject]@{ id = 'o3'; deviceId = 'd3'; displayName = 'prn-01'; accountEnabled = $true; operatingSystem = 'Windows'; profileType = 'Printer'; systemLabels = @('M365Managed') })
        }
        $r = Invoke-EbrGraphCollector -Ctx (New-LicCtx) -Item ($catalog | Where-Object Id -eq 'LIC.4-DEVICES')
        $r.Status | Should -Be 'OK'
        $r.Rows.Count | Should -Be 3
        ($r.Rows | Where-Object DisplayName -eq 'ws-01').AccountEnabled | Should -BeFalse
        $r.Detail | Should -Be '3 devices, 1 managed by Defender for Endpoint security settings management (managementType MicrosoftSense), 1 Windows Autopilot.' -Because 'the [ZTDid] prefix matches in any case'
        @(($r.Rows | Where-Object DisplayName -eq 'ws-01').PhysicalIds) | Should -Be @('[ZTDId]:3f2c', '[HWID]:h:6896')
        ($r.Rows | Where-Object DisplayName -eq 'prn-01').ProfileType | Should -Be 'Printer'
        @(($r.Rows | Where-Object DisplayName -eq 'prn-01').SystemLabels) | Should -Be @('M365Managed')
        @(($r.Rows | Where-Object DisplayName -eq 'prn-01').PhysicalIds).Count | Should -Be 0 -Because 'a missing property reads as an empty list'
        @($r.Rows)[0].PSObject.Properties.Name | Should -Be @('Id', 'DeviceId', 'DisplayName', 'AccountEnabled', 'OperatingSystem', 'OperatingSystemVersion', 'TrustType', 'IsManaged', 'IsCompliant', 'ManagementType', 'ApproximateLastSignInDateTime', 'RegistrationDateTime', 'OnPremisesSyncEnabled', 'PhysicalIds', 'ProfileType', 'SystemLabels')
        $item = $catalog | Where-Object Id -eq 'LIC.4-DEVICES'
        $item.Notes | Should -Match 'PhysicalIds, ProfileType and SystemLabels added in CyberSOC 1\.19\.0'
        $item.Query | Should -Match 'physicalIds,profileType,systemLabels&\$top=999' -Because 'the catalog query matches the read'
        Mock Invoke-EbrGraphGet { throw 'GRAPH-403 https://graph.microsoft.com/v1.0/devices: HTTP 403: Forbidden' }
        $ctx = New-LicCtx
        $r = Invoke-EbrGraphCollector -Ctx $ctx -Item $item
        $r.Status | Should -Be 'UNAVAILABLE' -Because 'a refused read is never an empty device list'
        $r.Detail | Should -Match 'Needs Device\.Read\.All'
    }

    It 'derives the matrix from every scenario fixture as the fixture expects, with the servers as its detail' {
        foreach ($name in 'plan2', 'plan1', 'mixed', 'business', 'business-servers', 'business-and-plan2', 'servers-without-defender-for-servers', 'server-seats-short', 'server-seats-enough', 'reading-disagrees', 'failed-read') {
            $l = Get-LicScenario $name
            $r = New-EbrLicensingResult -Ctx $l.Ctx
            foreach ($k in $l.Scenario.Expect.PSObject.Properties) {
                $row = $r.Rows | Where-Object Capability -eq $k.Name
                $got = if ($row.Kind -eq 'Devices') { $row.Count } else { $row.State }
                "$got" | Should -Be "$($k.Value)" -Because "$name $($k.Name): $($row.Detail)"
            }
            ($l.Ctx.Pending | Where-Object ResultId -eq 'LIC.5-SERVERS') | Should -Not -BeNullOrEmpty -Because $name
        }
    }

    It 'never reads Not licensed from a read that failed, was refused or is partial' {
        $l = Get-LicScenario 'failed-read'
        $r = New-EbrLicensingResult -Ctx $l.Ctx
        $r.Status | Should -Be 'PARTIAL'
        @($r.Rows | Where-Object State -eq 'Not licensed') | Should -BeNullOrEmpty
        $r.Detail | Should -Match 'Read in part, so what they feed reads Unknown, never Not licensed: LIC\.1-SKUS UNAVAILABLE'
        ($l.Ctx.Pending | Where-Object ResultId -eq 'LIC.5-SERVERS').Status | Should -Be 'UNAVAILABLE'
        # A partial license read is unknown too
        $l = Get-LicScenario 'plan2'
        $l.Ctx.Results['LIC.1-SKUS'].Status = 'PARTIAL'
        $l.Ctx.Results['LIC.1-SKUS'].Rows = @()
        $r = New-EbrLicensingResult -Ctx $l.Ctx
        ($r.Rows | Where-Object Capability -eq 'MdoP1').State | Should -Be 'Unknown'
        ($r.Rows | Where-Object Capability -eq 'EntraIdP1').Detail | Should -Match 'could not be read in full'
    }

    It 'never counts one server seat for two servers, never reads a server unlicensed while Defender for Business servers is possible, and lets Business decide beside Plan 2' {
        $l = Get-LicScenario 'server-seats-short'
        $r = New-EbrLicensingResult -Ctx $l.Ctx
        $servers = ($l.Ctx.Pending | Where-Object ResultId -eq 'LIC.5-SERVERS').Rows
        foreach ($name in 'vm-sql01', 'dc-onprem01') {
            ($servers | Where-Object DeviceName -eq $name).Licensed | Should -Be 'Unknown' -Because "$name may or may not hold the one seat"
            ($servers | Where-Object DeviceName -eq $name).LicenseSource | Should -Be 'Server licenses in the tenant, 1 seat for 2 servers outside Defender for Servers, so not every one is covered'
        }
        ($r.Rows | Where-Object Capability -eq 'MdeServers').Detail | Should -Match 'The server licenses are 1 seat short of the 2 servers outside Defender for Servers listed\.'
        ($r.Rows | Where-Object Capability -eq 'ServersWithoutLicense').Detail | Should -Match '1 seat short'

        $l = Get-LicScenario 'business-servers'
        $null = New-EbrLicensingResult -Ctx $l.Ctx
        $sql = ($l.Ctx.Pending | Where-Object ResultId -eq 'LIC.5-SERVERS').Rows | Where-Object DeviceName -eq 'vm-sql01'
        $sql.Licensed | Should -Be 'Unknown'
        $sql.LicenseSource | Should -Be 'Not established, Defender for Business servers cannot be read from the licenses'

        $l = Get-LicScenario 'business-and-plan2'
        $plan = (New-EbrLicensingResult -Ctx $l.Ctx).Rows | Where-Object Capability -eq 'DefenderEndpointPlan'
        $plan.State | Should -Be 'Defender for Business'
        $plan.Detail | Should -Match 'keeps the Defender for Business experience until Microsoft Support switches it to Plan 2'
        $l.Ctx.DefenderEndpointPlan = 'Plan2'
        $vuln = (New-EbrLicensingResult -Ctx $l.Ctx).Rows | Where-Object Capability -eq 'MdeVulnerabilityData'
        $vuln.Detail | Should -Match '^Clients: Plan 2, read on the Licenses page\.' -Because 'the Licenses page reading confirms the switch'
        $vuln.State | Should -Be 'Unknown' -Because 'no device read can show that every server has a server license'
    }

    It 'never reads the vulnerability data Licensed from the API reads, and reads a server without a license as a gap' {
        $l = Get-LicScenario 'plan2'
        $vuln = (New-EbrLicensingResult -Ctx $l.Ctx).Rows | Where-Object Capability -eq 'MdeVulnerabilityData'
        $vuln.State | Should -Be 'Unknown' -Because 'a Plan 2 license with no tag seen cannot exclude mixed mode on devices the account cannot see'
        $vuln.Detail | Should -Match 'the device reads cannot exclude mixed mode, so read the Licenses page'
        $l = Get-LicScenario 'servers-without-defender-for-servers'
        $l.Ctx.DefenderEndpointPlan = 'Plan2'
        $vuln = (New-EbrLicensingResult -Ctx $l.Ctx).Rows | Where-Object Capability -eq 'MdeVulnerabilityData'
        $vuln.State | Should -Be 'Partly licensed' -Because 'vm-sql01 has neither Defender for Servers nor a server license'
        $vuln.Detail | Should -Match 'Servers: some onboarded servers have no established server license'
    }

    It 'lets a pricing set on one machine decide that machine, and reads the subscription from subscription-scope pricings only' {
        $l = Get-LicScenario 'servers-without-defender-for-servers'
        $sub2 = 'a0b1c2d3-e4f5-4a6b-8c7d-9e0f1a2b3c4d'
        $vm = "/subscriptions/$sub2/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-sql01"
        # A machine-level pricing listed first must not be read as the subscription's own.
        $l.Ctx.Results['P0.3'].Rows = @([pscustomobject]@{ subscriptionId = $sub2; Plan = 'VirtualMachines'; Tier = 'Standard'; SubPlan = 'P1'; PricingId = "$vm/providers/Microsoft.Security/pricings/virtualMachines".ToLowerInvariant() }) +
            @($l.Ctx.Results['P0.3'].Rows | ForEach-Object { $c = $_.PSObject.Copy(); $c | Add-Member -NotePropertyName PricingId -NotePropertyValue ('/subscriptions/{0}/providers/microsoft.security/pricings/{1}' -f $c.subscriptionId, $c.Plan.ToLowerInvariant()); $c })
        $r = New-EbrLicensingResult -Ctx $l.Ctx
        ($r.Rows | Where-Object Capability -eq 'DefenderServers').State | Should -Be 'Partly licensed' -Because 'the second subscription is still off at subscription scope'
        $sql = ($l.Ctx.Pending | Where-Object ResultId -eq 'LIC.5-SERVERS').Rows | Where-Object DeviceName -eq 'vm-sql01'
        $sql.DefenderForServers | Should -Be 'On for the machine'
        $sql.Licensed | Should -Be 'Yes'
        ($r.Rows | Where-Object Capability -eq 'ServersWithoutLicense').Count | Should -Be 0
    }

    It 'counts Defender for Business as client coverage of the vulnerability data, and reads a server gap beside it as Partly licensed' {
        $l = Get-LicScenario 'business-servers'
        $vuln = (New-EbrLicensingResult -Ctx $l.Ctx).Rows | Where-Object Capability -eq 'MdeVulnerabilityData'
        $vuln.Detail | Should -Match '^Clients: Defender for Business, which includes core vulnerability management\.'
        $vuln.State | Should -Be 'Unknown' -Because 'no server gap is established, and the API reads never show every server covered'
        # One server seat for the two servers outside Defender for Servers leaves a gap beside the covered clients.
        $short = (Get-Content (Join-Path $PSScriptRoot 'fixtures/offline-pack/licensing/server-seats-short.json') -Raw | ConvertFrom-Json).Results.'LIC.1-SKUS'.Rows | Where-Object SkuPartNumber -eq 'MDATP_Server'
        $l.Ctx.Results['LIC.1-SKUS'].Rows = @($l.Ctx.Results['LIC.1-SKUS'].Rows) + $short
        $r = New-EbrLicensingResult -Ctx $l.Ctx
        ($r.Rows | Where-Object Capability -eq 'MdeServers').State | Should -Be 'Partly licensed'
        ($r.Rows | Where-Object Capability -eq 'MdeVulnerabilityData').State | Should -Be 'Partly licensed'
    }

    It 'never reads servers Not licensed from the device list, since a hidden server may sit in a subscription outside the pack with Defender for Servers on' {
        $l = Get-LicScenario 'plan1'
        $sub2 = 'a0b1c2d3-e4f5-4a6b-8c7d-9e0f1a2b3c4d'
        # Every server listed sits in a pack subscription with Defender for Servers off, and the tenant has no server license.
        $sql = [pscustomobject]@{ MachineId = 'sql'; ComputerDnsName = 'vm-sql01'; OsPlatform = 'WindowsServer2019'; DeviceClass = 'Server'; OnboardingStatus = 'Onboarded'; HealthStatus = 'Active'; MachineTags = @(); AzureResourceId = "/subscriptions/$sub2/resourcegroups/rg-app/providers/microsoft.compute/virtualmachines/vm-sql01"; subscriptionId = $sub2; TaggedPlan1 = $false }
        $l.Ctx.Results['LIC.2-MACHINES'].Rows = @($l.Ctx.Results['LIC.2-MACHINES'].Rows) + $sql
        $r = New-EbrLicensingResult -Ctx $l.Ctx
        (($l.Ctx.Pending | Where-Object ResultId -eq 'LIC.5-SERVERS').Rows | Where-Object DeviceName -eq 'vm-sql01').Licensed | Should -Be 'No'
        $servers = $r.Rows | Where-Object Capability -eq 'MdeServers'
        $servers.State | Should -Be 'Unknown'
        $servers.Detail | Should -Match 'No listed server is covered, but a server the device groups hide, or one in a subscription outside the pack, may be, so this is not read as Not licensed\.'
        ($r.Rows | Where-Object Capability -eq 'MdeVulnerabilityData').State | Should -Be 'Unknown' -Because 'Plan 1 clients and no server source seen still leave hidden servers possible'
    }

    It 'reads security settings management from the license alone, never from devices still managed by it' {
        $l = Get-LicScenario 'plan2'
        $l.Ctx.Results['LIC.1-SKUS'] = New-EbrResult -ResultId 'LIC.1-SKUS' -Status 'EMPTY'
        $row = (New-EbrLicensingResult -Ctx $l.Ctx).Rows | Where-Object Capability -eq 'MdeSecurityManagement'
        $row.State | Should -Be 'Not licensed' -Because 'the licenses were read in full and none is a Defender for Endpoint user license'
        $row.Count | Should -Be 2
        $row.Detail | Should -Match 'A device still managed by it shows it was set up, not that it is licensed today'
        $l.Ctx.Results['LIC.1-SKUS'] = New-EbrResult -ResultId 'LIC.1-SKUS' -Status 'FAILED'
        ((New-EbrLicensingResult -Ctx $l.Ctx).Rows | Where-Object Capability -eq 'MdeSecurityManagement').State | Should -Be 'Unknown'
    }

    It 'never reads every server covered from a device list the account''s device groups may limit, or from a failed device read' {
        $l = Get-LicScenario 'server-seats-enough'
        $r = New-EbrLicensingResult -Ctx $l.Ctx
        $servers = ($l.Ctx.Pending | Where-Object ResultId -eq 'LIC.5-SERVERS').Rows
        ($servers | Where-Object DeviceName -eq 'vm-sql01').Licensed | Should -Be 'Unknown' -Because 'enough seats for the servers listed is not enough for every server'
        ($servers | Where-Object DeviceName -eq 'vm-sql01').LicenseSource | Should -Match 'not established for any server the device groups hide'
        ($servers | Where-Object DeviceName -eq 'vm-app01').Licensed | Should -Be 'Yes' -Because 'Defender for Servers covers every server on its subscription'
        $row = $r.Rows | Where-Object Capability -eq 'MdeServers'
        $row.State | Should -Be 'Unknown'
        $row.Detail | Should -Match 'lists only the devices the account''s device groups allow'
        ($r.Rows | Where-Object Capability -eq 'OnboardedClients').Detail | Should -Match 'every device count is a lower bound'
        # A failed device read leaves the servers unknown even with server seats and Defender for Servers on everywhere.
        $l.Ctx.Results['LIC.2-MACHINES'] = New-EbrResult -ResultId 'LIC.2-MACHINES' -Status 'FAILED'
        $l.Ctx.Results['P0.3'].Rows = @($l.Ctx.Results['P0.3'].Rows | ForEach-Object { $c = $_.PSObject.Copy(); if ($c.Plan -eq 'VirtualMachines') { $c.Tier = 'Standard'; $c.SubPlan = 'P2' }; $c })
        $r = New-EbrLicensingResult -Ctx $l.Ctx
        ($r.Rows | Where-Object Capability -eq 'DefenderServers').State | Should -Be 'Licensed'
        ($r.Rows | Where-Object Capability -eq 'MdeServers').State | Should -Be 'Unknown'
        ($r.Rows | Where-Object Capability -eq 'MdeServers').Detail | Should -Match 'Without the device list the servers are unknown, whatever licenses are in place'
    }

    It 'reads no Plan 1 from a vulnerability read the Sentinel workspace fallback answered' {
        $l = Get-LicScenario 'plan2'
        $l.Ctx.Results['LIC.1-SKUS'] = New-EbrResult -ResultId 'LIC.1-SKUS' -Status 'FAILED'
        $l.Ctx.Results['LIC.3-TVM'] = New-EbrResult -ResultId 'LIC.3-TVM' -Status 'OK' -Rows @([pscustomobject]@{ OSPlatform = 'Windows11'; DeviceType = 'Workstation'; Devices = 5; WithVulnerabilities = 0; WithAssessments = 0; TaggedPlan1 = 0 }) -Source 'Sentinel workspace (AH fallback)'
        $r = New-EbrLicensingResult -Ctx $l.Ctx
        ($r.Rows | Where-Object Capability -eq 'DefenderEndpointPlan').State | Should -Be 'Unknown'
    }

    It 'takes the Licenses page reading for the plan and names the disagreement' {
        $l = Get-LicScenario 'reading-disagrees'
        $plan = (New-EbrLicensingResult -Ctx $l.Ctx).Rows | Where-Object Capability -eq 'DefenderEndpointPlan'
        $plan.State | Should -Be 'Plan 1'
        $plan.Signal | Should -Be 'Plan 2'
        $plan.Detail | Should -Match 'The reading and the API reads disagree: the API reads show Plan 2'
    }

    It 'matches the Defender for Endpoint server SKU by its ID, never as a Plan 2 user license' {
        $l = Get-LicScenario 'plan1'
        $server = [pscustomobject]@{ SkuId = '509e8ab6-0274-4cda-bcbd-bd164fd562c4'; SkuPartNumber = 'MDATP_Server'; CapabilityStatus = 'Enabled'; Enabled = 10; Warning = 0; Consumed = 4
            ServicePlans = @([pscustomobject]@{ ServicePlanId = '871d91ec-ec1a-452b-a83f-bd76c7d770ef'; ServicePlanName = 'WINDEFATP'; ProvisioningStatus = 'Success' }) }
        $l.Ctx.Results['LIC.1-SKUS'].Rows = @($l.Ctx.Results['LIC.1-SKUS'].Rows) + $server
        $r = New-EbrLicensingResult -Ctx $l.Ctx
        ($r.Rows | Where-Object Capability -eq 'MdeServerSku').State | Should -Be 'Licensed'
        ($r.Rows | Where-Object Capability -eq 'MdeServerSku').Seats | Should -Be 10
        ($r.Rows | Where-Object Capability -eq 'MdePlan2Sku').State | Should -Be 'Not licensed'
        ($r.Rows | Where-Object Capability -eq 'DefenderEndpointPlan').State | Should -Be 'Plan 1'
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

    It 'carries every row of the runbook slide map, without the confirmed data loss, compromise and containment rows' {
        $ws.Count | Should -Be 45
        $ws.Figure | Should -Not -Contain 'Confirmed data loss or exfiltration'
        $ws.Figure | Should -Not -Contain 'Identity compromises contained'
        $ws.Figure | Should -Not -Contain 'Malicious sign-in to containment'
        foreach ($row in $ws) { "$($row.Figure) $($row.Note)" | Should -Not -Match 'data loss|exfiltrat|compromis|containment' -Because $row.Figure }
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

    It 'still carries 45 rows' { $ws.Count | Should -Be 45 }

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
        Mock Invoke-EbrRest -ParameterFilter { $Uri -match '/basicPublishingCredentialsPolicies/ftp\?' } { throw 'HTTP 403: Forbidden' }
        Mock Invoke-EbrRest -ParameterFilter { $Uri -match '/configurations/audit_log_(enabled|events)\?' } { throw 'HTTP 403: Forbidden' }
        Mock Invoke-EbrRest -ParameterFilter { $Uri -match '/sessionHosts\?' } { throw 'HTTP 403: Forbidden' }
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
        # CR-22 reads the antivirus mode of each Windows device from the Defender API, never the network here (1.17.0)
        Mock Get-EbrDefenderAvInfo { @([pscustomobject]@{ MachineId = 'm2'; ComputerDnsName = 'vm-app01'; OsPlatform = 'WindowsServer2022'; AvMode = '0'; AvModeName = 'Active'; DataRefreshTimestamp = ''; LastSeenTime = '' }) }
        # The licensing check: the device list comes from the Defender API, never the network here
        Mock Get-EbrDefenderMachines { @(
                [pscustomobject]@{ MachineId = 'm1'; ComputerDnsName = 'ws-0101'; OsPlatform = 'Windows11'; DeviceClass = 'Client'; OnboardingStatus = 'Onboarded'; HealthStatus = 'Active'; MachineTags = @(); RbacGroupName = ''; LastSeen = ''; AzureResourceId = ''; subscriptionId = ''; TaggedPlan1 = $false }
                [pscustomobject]@{ MachineId = 'm2'; ComputerDnsName = 'vm-app01'; OsPlatform = 'WindowsServer2022'; DeviceClass = 'Server'; OnboardingStatus = 'Onboarded'; HealthStatus = 'Active'; MachineTags = @(); RbacGroupName = ''; LastSeen = ''; AzureResourceId = "/subscriptions/$($subs[0])/resourcegroups/rg-1/providers/microsoft.compute/virtualmachines/vm-app01"; subscriptionId = $subs[0]; TaggedPlan1 = $false }) }
        # Graph: the probe works, role assignments read without PIM, Conditional Access is not permitted, everything else is empty
        Mock Invoke-EbrGraphGet {
            if ($Uri -match 'v1\.0/organization') { return [pscustomobject]@{ id = $client } }
            if ($Uri -match 'ScheduleInstances') { throw 'HTTP 400: Bad Request | AadPremiumLicenseRequired' }
            if ($Uri -match 'roleAssignments\?') { return , @([pscustomobject]@{ roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; principalId = 'u1'; directoryScopeId = '/'; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Ann'; userPrincipalName = 'ann@contoso.com' } }) }
            if ($Uri -match 'conditionalAccess') { throw 'GRAPH-403 https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies: HTTP 403: Forbidden' }
            if ($Uri -match 'authorizationPolicy|adminConsentRequestPolicy|sharepoint/settings') { return [pscustomobject]@{} }
            if ($Uri -match 'v1\.0/subscribedSkus') { return , @([pscustomobject]@{ skuId = '06ebc4ee-1bb5-47dd-8120-11324bc54e06'; skuPartNumber = 'SPE_E5'; appliesTo = 'User'; capabilityStatus = 'Enabled'; consumedUnits = 40; prepaidUnits = [pscustomobject]@{ enabled = 50; suspended = 0; warning = 0; lockedOut = 0 }; servicePlans = @([pscustomobject]@{ servicePlanId = '871d91ec-ec1a-452b-a83f-bd76c7d770ef'; servicePlanName = 'WINDEFATP'; provisioningStatus = 'Success'; appliesTo = 'User' }, [pscustomobject]@{ servicePlanId = '41781fb2-bc02-4b7c-bd55-b576c07bb09d'; servicePlanName = 'AAD_PREMIUM'; provisioningStatus = 'Success'; appliesTo = 'User' }) }) }
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
            if ($Query -match '^union withsource = SourceTable isfuzzy = true\s+ThreatIntelIndicators, ThreatIntelligenceIndicator, SecurityAlert') {
                # TI.0: a separate Entra diagnostic setting sends the risk detections to ws1, the sign-ins go to ws2, email to ws3
                $tiReach = @{ ws1 = @{ AADUserRiskEvents = 30 }; ws2 = @{ SigninLogs = 900; AADUserRiskEvents = 3 }; ws3 = @{ EmailEvents = 50 } }
                $rows = foreach ($k in $tiReach.Keys) { if ($combined -or $k -eq $WorkspaceCustomerId) { foreach ($t in $tiReach[$k].GetEnumerator()) { [pscustomobject]@{ SourceTable = $t.Key; EarliestRecord = '2026-07-01T00:00:00Z'; LatestRecord = '2026-09-30T00:00:00Z'; Records = $t.Value } } } }
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

        $code = Invoke-EbrMain -TenantId $client -SubscriptionId $subs -OutputPath $TestDrive -SkipExchange -ManagedRgPattern 'aznativesol0' -VulnAssessmentPath $vaDir `
            -DrClient -SentinelWorkspace 'ws-2' -ManagementGroup 'mg-contoso' -ClientContact 'Dana' -SenderName 'Scott Example' -PurgeProtectionApproved -DefenderEndpointPlan 'Plan2'
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
        @(Import-Csv (Join-Path $outDir.FullName '01-worksheet.csv')).Count | Should -Be 45
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
        Should -Invoke Invoke-EbrLaQuery -ParameterFilter { $Query -match '^AADUserRiskEvents' } -Times 1 -Exactly -Scope Describe
        Should -Invoke Invoke-EbrLaQuery -ParameterFilter { $Query -match '^AADUserRiskEvents' -and $WorkspaceCustomerId -eq 'ws1' } -Times 1 -Exactly -Scope Describe -Because 'risk detections are read where TI.0 finds the most, not where the sign-ins are'
        Should -Invoke Invoke-EbrLaQuery -ParameterFilter { $Query -match '^EmailEvents' } -Times 1 -Exactly -Scope Describe
        Should -Invoke Invoke-EbrLaQuery -ParameterFilter { $Query -match '^EmailEvents' -and $WorkspaceCustomerId -eq 'ws3' } -Times 1 -Exactly -Scope Describe
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

    It 'writes NB.5-FTPAUTH and NB.5-FTPAUTH-DETAIL, and reads an app it could not read as failed, never as Off (CyberSOC 1.14.0)' {
        (Get-M 'NB.5-FTPAUTH').Status | Should -Be 'FAILED' -Because 'the mocked GET is refused for every app'
        (Get-M 'NB.5-FTPAUTH-DETAIL').Status | Should -Be 'FAILED'
        @(Get-ChildItem (Join-Path $outDir.FullName 'queries') -Filter 'NB.5-FTPAUTH.*').Count | Should -Be 1 -Because 'the Resource Graph query is written to the pack'
    }

    It 'writes DP.1-SOFTDELETE in the container pass, and reads an account it could not read as failed, never as having soft delete (CyberSOC 1.20.0)' {
        (Get-M 'DP.1-SOFTDELETE').Status | Should -Be (Get-M 'DP.1-CONTAINERS-DETAIL').Status -Because 'both are written in the same pass from the same account list'
        (Get-M 'DP.1-SOFTDELETE').Status | Should -BeIn 'FAILED', 'EMPTY' -Because 'the mocked GETs read no blob service'
    }

    It 'writes DR.6-MYSQLAUDIT, and reads a server it could not read as failed, never as set (CyberSOC 1.15.0)' {
        (Get-M 'DR.6-MYSQLAUDIT').Status | Should -Be 'FAILED' -Because 'the mocked GET is refused for every server'
        (Get-M 'DR.6-MYSQLAUDIT').Phase | Should -Be 'P2 Detection and response'
        @(Get-ChildItem (Join-Path $outDir.FullName 'queries') -Filter 'DR.6-MYSQLAUDIT.*').Count | Should -Be 1 -Because 'the Resource Graph query is written to the pack'
    }

    It 'runs the licensing check, records the Licenses page reading and keeps Unknown for what it could not read (CyberSOC 1.11.0)' {
        $params.ScriptVersion | Should -Be '1.20.0'
        $params.Licensing.DefenderEndpointPlan | Should -Be 'Plan2'
        foreach ($id in 'LIC.1-SKUS', 'LIC.2-MACHINES', 'LIC.3-TVM', 'LIC.4-DEVICES', 'LIC.5-MATRIX', 'LIC.5-SERVERS') { (Get-M $id) | Should -Not -BeNullOrEmpty -Because $id }
        (Get-M 'LIC.1-SKUS').Status | Should -Be 'OK'
        (Get-M 'LIC.2-MACHINES').Rows | Should -Be 2
        (Get-M 'LIC.3-TVM').Status | Should -Be 'UNAVAILABLE' -Because 'the vulnerability tables exist only in Advanced Hunting, which answered 403'
        (Get-M 'LIC.5-MATRIX').Status | Should -Be 'PARTIAL'
        (Get-M 'LIC.5-MATRIX').Phase | Should -Be 'P2 Licensing'
        $matrix = Get-Content (Join-Path $outDir.FullName 'results/LIC.5-MATRIX.json') -Raw | ConvertFrom-Json
        ($matrix | Where-Object Capability -eq 'DefenderEndpointPlan').State | Should -Be 'Plan 2'
        ($matrix | Where-Object Capability -eq 'DefenderEndpointPlan').Source | Should -Be 'Licenses page reading'
        ($matrix | Where-Object Capability -eq 'EntraIdP1').State | Should -Be 'Licensed'
        ($matrix | Where-Object Capability -eq 'EntraIdP1').Seats | Should -Be 50
        ($matrix | Where-Object Capability -eq 'MdoP1').State | Should -Be 'Not licensed' -Because 'the licenses were read in full and none carries it'
        $servers = Get-Content (Join-Path $outDir.FullName 'results/LIC.5-SERVERS.json') -Raw | ConvertFrom-Json
        @($servers).Count | Should -Be 1
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

    It 'writes the change requests and client emails into the pack, with the options recorded and passed through' {
        $folder = Join-Path $outDir.FullName '05-change-requests'
        $index = Get-Content (Join-Path $folder '00-index.md') -Raw
        $index | Should -Match '^# Change requests: Contoso Test'
        $index | Should -Not -Match 'Run again with -DrClient' -Because '-DrClient reached the generator'
        $crs = @(Get-ChildItem $folder -Filter 'CR-*.txt' | Where-Object Name -notlike '*.email.txt')
        $crs.Count | Should -BeGreaterThan 0 -Because 'the mocked pack has gaps to change'
        foreach ($cr in $crs) { Test-Path (Join-Path $folder ($cr.BaseName + '.email.txt')) | Should -BeTrue -Because "$($cr.Name) is written with its client email" }
        foreach ($email in @(Get-ChildItem $folder -Filter '*.email.txt')) {
            $text = Get-Content $email.FullName -Raw
            $text | Should -Match '\r?\n\r?\nHello Dana,\r?\n' -Because "-ClientContact reached the generator ($($email.Name))"
            $text | Should -Match 'Thank you,\r?\nScott Example\r?\n$' -Because "-SenderName reached the generator ($($email.Name))"
        }
        $params.ChangeRequests.Requested | Should -BeTrue
        $params.ChangeRequests.Written | Should -BeTrue -Because 'the generator finished'
        $params.ChangeRequests.DrClient | Should -BeTrue
        $params.ChangeRequests.SentinelWorkspace | Should -Be 'ws-2'
        $params.ChangeRequests.ManagementGroup | Should -Be 'mg-contoso'
        $params.ChangeRequests.ClientContact | Should -Be 'Dana'
        $params.ChangeRequests.SenderName | Should -Be 'Scott Example'
        $params.ChangeRequests.PurgeProtectionApproved | Should -BeTrue
        $notes = Get-Content (Join-Path $outDir.FullName '02-notes.txt') -Raw
        $notes | Should -Match ('--- Change Requests ---\r?\n  \S+ {0} change requests? and {0} client emails? in 05-change-requests\. 00-index\.md lists every change' -f $crs.Count)
        (Get-Item (Join-Path $folder '00-index.md')).LastWriteTimeUtc | Should -BeGreaterOrEqual (Get-Item (Join-Path $outDir.FullName '04-secops-worklist.md')).LastWriteTimeUtc -Because 'the change requests come after the worklist'
    }

    It 'runs the change request generator after the worklist with the options given, and only those' {
        Mock Invoke-EbrChangeRequestGenerator {
            $script:crCall = @{ Path = $EvidencePath; Options = $Options; Worklist = Test-Path (Join-Path $EvidencePath '04-secops-worklist.md'); Parameters = Test-Path (Join-Path $EvidencePath '00-parameters.json') }
            Join-Path $EvidencePath '05-change-requests/CR-02-storage-secure-transfer.txt'
            Join-Path $EvidencePath '05-change-requests/CR-02-storage-secure-transfer.email.txt'
            Join-Path $EvidencePath '05-change-requests/00-index.md'
        }
        $dest = Join-Path $TestDrive 'cr-options'
        $null = Invoke-EbrMain -TenantId $client -SubscriptionId $subs -OutputPath $dest -SkipExchange -SkipHtmlReport -ClientContact 'Dana' -ManagementGroup 'mg-contoso'
        Should -Invoke Invoke-EbrChangeRequestGenerator -Times 1 -Exactly
        $pack = Get-ChildItem -Path $dest -Directory -Filter 'CyberSOC-Evidence_*' | Select-Object -First 1
        $script:crCall.Path | Should -Be $pack.FullName
        $script:crCall.Worklist | Should -BeTrue -Because 'the worklist is written first'
        $script:crCall.Parameters | Should -BeTrue -Because 'the generator reads 00-parameters.json'
        @($script:crCall.Options.Keys | Sort-Object) | Should -Be @('ClientContact', 'ManagementGroup') -Because 'an option not given is left to the generator default'
        $script:crCall.Options.ClientContact | Should -Be 'Dana'
        $script:crCall.Options.ManagementGroup | Should -Be 'mg-contoso'
        $notes = Get-Content (Join-Path $pack.FullName '02-notes.txt') -Raw
        $notes | Should -Match '1 change request and 1 client email in 05-change-requests\.'
        $params2 = Get-Content (Join-Path $pack.FullName '00-parameters.json') -Raw | ConvertFrom-Json
        $params2.ChangeRequests.Written | Should -BeTrue
        $params2.ChangeRequests.DrClient | Should -BeFalse
        $params2.ChangeRequests.SenderName | Should -BeNullOrEmpty
        $params2.ScriptVersion | Should -Be '1.20.0'
    }

    It 'warns and leaves the collection complete when the change requests fail' {
        Mock Invoke-EbrChangeRequestGenerator { throw 'CR-03 has no client email. Every change request writes one.' }
        $dest = Join-Path $TestDrive 'cr-failed'
        $failedCode = Invoke-EbrMain -TenantId $client -SubscriptionId $subs -OutputPath $dest -SkipExchange -SkipHtmlReport
        $failedCode | Should -Be 2
        $pack = Get-ChildItem -Path $dest -Directory -Filter 'CyberSOC-Evidence_*' | Select-Object -First 1
        foreach ($f in '00-manifest.csv', '00-parameters.json', '01-worksheet.csv', '02-notes.txt', '04-secops-worklist.md') { Test-Path (Join-Path $pack.FullName $f) | Should -BeTrue -Because "$f is part of the completed collection" }
        $log = Get-Content (Join-Path $pack.FullName 'run.log') -Raw
        $log | Should -Match 'WARNING Console - Evidence collection completed\. Change request generation needs attention: CR-03 has no client email\.'
        Get-Content (Join-Path $pack.FullName '02-notes.txt') -Raw | Should -Match 'Not written: CR-03 has no client email\. Every change request writes one\. Run New-CyberSocChangeRequests\.ps1 -EvidencePath on this pack to write them\.'
        $failedParams = (Get-Content (Join-Path $pack.FullName '00-parameters.json') -Raw | ConvertFrom-Json).ChangeRequests
        $failedParams.Requested | Should -BeTrue
        $failedParams.Written | Should -BeFalse -Because 'the pack must not claim change requests the generator failed to write'
    }

    It 'warns and stays complete, not fatal, when the <Name> generator fails, and still runs the ones after it' -ForEach @(
        @{ Name = 'report'; Failing = 'Invoke-EbrReportGenerator'; Warning = 'HTML report generation needs attention' }
        @{ Name = 'SecOps worklist'; Failing = 'Invoke-EbrWorklistGenerator'; Warning = 'SecOps worklist generation needs attention' }
        @{ Name = 'change request'; Failing = 'Invoke-EbrChangeRequestGenerator'; Warning = 'Change request generation needs attention' }
    ) {
        foreach ($g in 'Invoke-EbrReportGenerator', 'Invoke-EbrWorklistGenerator', 'Invoke-EbrChangeRequestGenerator') {
            if ($g -eq $Failing) { Mock $g { throw 'generator failed on purpose' } } else { Mock $g { } }
        }
        $dest = Join-Path $TestDrive ('failing-' + $Failing)
        $result = Invoke-EbrMain -TenantId $client -SubscriptionId $subs -OutputPath $dest -SkipExchange
        $result | Should -Be 2 -Because "a $Name failure leaves the collection complete, which exit code 1 would deny"
        foreach ($g in 'Invoke-EbrReportGenerator', 'Invoke-EbrWorklistGenerator', 'Invoke-EbrChangeRequestGenerator') {
            Should -Invoke $g -Times 1 -Exactly -Because "the $Name failure does not stop the other generators"
        }
        $pack = Get-ChildItem -Path $dest -Directory -Filter 'CyberSOC-Evidence_*' | Select-Object -First 1
        foreach ($f in '00-manifest.csv', '00-parameters.json', '01-worksheet.csv', '02-notes.txt') { Test-Path (Join-Path $pack.FullName $f) | Should -BeTrue -Because "$f is part of the completed collection" }
        $log = Get-Content (Join-Path $pack.FullName 'run.log') -Raw
        $log | Should -Match ('WARNING Console - Evidence collection completed\. {0}: generator failed on purpose' -f $Warning)
        $log | Should -Match 'WARNING Report - generator failed on purpose'
        $log | Should -Not -Match 'CRITICAL'
    }

    It 'skips the change requests with -SkipChangeRequests and records it' {
        Mock Invoke-EbrChangeRequestGenerator { }
        $dest = Join-Path $TestDrive 'cr-skipped'
        $null = Invoke-EbrMain -TenantId $client -SubscriptionId $subs -OutputPath $dest -SkipExchange -SkipHtmlReport -SkipChangeRequests
        Should -Invoke Invoke-EbrChangeRequestGenerator -Times 0 -Exactly
        $pack = Get-ChildItem -Path $dest -Directory -Filter 'CyberSOC-Evidence_*' | Select-Object -First 1
        Test-Path (Join-Path $pack.FullName '05-change-requests') | Should -BeFalse
        $skippedParams = (Get-Content (Join-Path $pack.FullName '00-parameters.json') -Raw | ConvertFrom-Json).ChangeRequests
        $skippedParams.Requested | Should -BeFalse
        $skippedParams.Written | Should -BeFalse
        Get-Content (Join-Path $pack.FullName '02-notes.txt') -Raw | Should -Match 'Not written \(-SkipChangeRequests\)\. Run New-CyberSocChangeRequests\.ps1 -EvidencePath on this pack to write them\.'
    }

    It 'writes no change requests on a dry run, like the report and the worklist' {
        Mock Invoke-EbrChangeRequestGenerator { }
        $dest = Join-Path $TestDrive 'cr-dryrun'
        Invoke-EbrMain -TenantId $client -SubscriptionId $subs -OutputPath $dest -DryRun -ClientContact 'Dana' | Should -Be 0
        Should -Invoke Invoke-EbrChangeRequestGenerator -Times 0 -Exactly
        $pack = Get-ChildItem -Path $dest -Directory -Filter 'CyberSOC-Evidence_DRYRUN_*' | Select-Object -First 1
        Test-Path (Join-Path $pack.FullName '05-change-requests') | Should -BeFalse
        Test-Path (Join-Path $pack.FullName '04-secops-worklist.md') | Should -BeFalse
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
        $every = @($catalog | Where-Object { $_.Engine -eq 'AH' -and $_.Query -match 'DeviceInfo' -and $_.Id -notin 'P0.4', 'LIC.3-TVM' -and $_.Query -notmatch 'where isnotempty\(AzureResourceId\)' } | ForEach-Object Id)
        $every | Should -BeNullOrEmpty -Because 'every Advanced Hunting query that reads DeviceInfo is scoped to Azure virtual machines'
        # The licensing check is the one exception: a license covers every device, so LIC.3-TVM counts them all.
        ($catalog | Where-Object Id -eq 'LIC.3-TVM').Query | Should -Not -Match 'isnotempty\(AzureResourceId\)'
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
