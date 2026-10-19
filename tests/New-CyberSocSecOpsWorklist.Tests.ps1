BeforeAll {
    $generator = Join-Path $PSScriptRoot '../New-CyberSocSecOpsWorklist.ps1'
    # Windows PowerShell 5.1 writes the array ConvertFrom-Json parses to the pipeline as one object.
    # PowerShell 7 does the same with -NoEnumerate, so this runs a script block as 5.1 reads JSON.
    function Invoke-WithWindowsPowerShellJson([scriptblock]$Script) {
        function ConvertFrom-Json { param([Parameter(ValueFromPipeline, Position = 0)]$InputObject) process { Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $InputObject -NoEnumerate } }
        & $Script
    }
    function New-WorklistFixture {
        param([string]$Path)
        New-Item -ItemType Directory -Path (Join-Path $Path 'results') -Force | Out-Null
        @{ ClientName = 'Example Client'; TenantId = 'example-tenant'; ScriptVersion = '1.8.0'; ManagedRgPattern = 'aznativesol0'; RunStartedUtc = '2026-10-12T06:05:18.195Z'; WindowStart = '2026-07-01'; WindowEnd = '2026-09-30'; PostureReadDate = '2026-10-12'; Subscriptions = @('s1'); AlertScope = 'Ticketed incidents only' } |
            ConvertTo-Json -Depth 6 | Set-Content (Join-Path $Path '00-parameters.json')
        @(
            [pscustomobject]@{ ResultId = 'OUT.1-OPEN'; Status = 'OK'; Rows = 2; ReadTimeUtc = '2026-10-12T06:10:00Z' },
            [pscustomobject]@{ ResultId = 'EW.1-DEVICES'; Status = 'OK'; Rows = 2; ReadTimeUtc = '2026-10-12T06:10:00Z' },
            [pscustomobject]@{ ResultId = 'DP.5b'; Status = 'OK'; Rows = 2; ReadTimeUtc = '2026-10-12T06:10:00Z' },
            [pscustomobject]@{ ResultId = 'DP.5c'; Status = 'OK'; Rows = 1; ReadTimeUtc = '2026-10-12T06:10:00Z' },
            [pscustomobject]@{ ResultId = 'NB.1'; Status = 'EMPTY'; Rows = 0; ReadTimeUtc = '2026-10-12T06:10:00Z' },
            [pscustomobject]@{ ResultId = 'DFC.1-DETAIL'; Status = 'OK'; Rows = 2; ReadTimeUtc = '2026-10-12T06:10:00Z' },
            [pscustomobject]@{ ResultId = 'EW.7-DETAIL'; Status = 'UNAVAILABLE'; Rows = 0; ReadTimeUtc = '2026-10-12T06:10:00Z' }
        ) | Export-Csv (Join-Path $Path '00-manifest.csv') -NoTypeInformation
        '[{"WorkspaceId":"w1","IncidentNumber":41,"Title":"Suspicious sign-in | pipe","Severity":"Medium","Status":"Active","Owner":"","CreatedTime":"2026-09-12T10:00:00Z","AgeDays":30,"TicketRef":"ZD ticket 12345","TicketNumber":"12345","IncidentUrl":"https://portal/41"},{"WorkspaceId":"w1","IncidentNumber":42,"Title":"Malware on host","Severity":"High","Status":"New","Owner":"analyst@example.test","CreatedTime":"2026-09-20T10:00:00Z","AgeDays":22,"TicketRef":"zendesk.com/agent/tickets/777","TicketNumber":"777","IncidentUrl":"https://portal/42"}]' |
            Set-Content (Join-Path $Path 'results/OUT.1-OPEN.json')
        '[{"DeviceName":"ws-01","Scope":"Other device","OSPlatform":"Windows11","OnboardingStatus":"Can be onboarded","SensorHealthState":"","Gap":"Not onboarded","LastSeen":"2026-10-11T00:00:00Z","MachineGroup":"","AzureResourceId":""},{"DeviceName":"vm-02","Scope":"Azure VM","OSPlatform":"Linux","OnboardingStatus":"Onboarded","SensorHealthState":"Inactive","Gap":"Sensor Inactive","LastSeen":"2026-10-10T00:00:00Z","MachineGroup":"Servers","AzureResourceId":"/subscriptions/s1/vm-02"},{"DeviceName":"mxdr-jump","Scope":"Azure VM","OSPlatform":"Windows","OnboardingStatus":"Can be onboarded","SensorHealthState":"","Gap":"Not onboarded","LastSeen":"2026-10-10T00:00:00Z","MachineGroup":"","AzureResourceId":"/subscriptions/s1/resourceGroups/client-aznativesol0-rg/providers/Microsoft.Compute/virtualMachines/mxdr-jump"}]' |
            Set-Content (Join-Path $Path 'results/EW.1-DEVICES.json')
        '[{"VmName":"avd-host-1","resourceGroup":"avd-rg","PowerState":"PowerState/running","ProtectionState":""},{"VmName":"sql-01","resourceGroup":"data-rg","PowerState":"PowerState/deallocated","ProtectionState":"ProtectionStopped"},{"VmName":"mxdr-jump","resourceGroup":"client-AZNATIVESOL0-rg","PowerState":"PowerState/running","ProtectionState":""}]' |
            Set-Content (Join-Path $Path 'results/DP.5b.json')
        '[{"HostPool":"pool1","resourceGroup":"AVD-RG","HostPoolType":"Pooled","PersonalAssignment":""}]' |
            Set-Content (Join-Path $Path 'results/DP.5c.json')
        '[]' | Set-Content (Join-Path $Path 'results/NB.1.json')
        '[{"Recommendation":"Management ports should be closed","Severity":"High","ResourceId":"/subscriptions/s1/vm-02","subscriptionId":"s1","resourceGroup":"data-rg"},{"Recommendation":"Low thing","Severity":"Low","ResourceId":"/subscriptions/s1/vm-03","subscriptionId":"s1","resourceGroup":"data-rg"}]' |
            Set-Content (Join-Path $Path 'results/DFC.1-DETAIL.json')
    }
    function Add-WorklistResult {
        param([string]$Path, [string]$Id, [string]$Json, [string]$Status = 'OK')
        $m = @(Import-Csv (Join-Path $Path '00-manifest.csv') | Where-Object ResultId -ne $Id)
        $m += [pscustomobject]@{ ResultId = $Id; Status = $Status; Rows = 1; ReadTimeUtc = '2026-10-12T06:10:00Z' }
        $m | Export-Csv (Join-Path $Path '00-manifest.csv') -NoTypeInformation
        $Json | Set-Content (Join-Path $Path "results/$Id.json")
    }
}
Describe 'SecOps worklist generation' {
    BeforeEach {
        $pack = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-WorklistFixture $pack
        $files = @(& $generator -EvidencePath $pack)
        $md = Get-Content (Join-Path $pack '04-secops-worklist.md') -Raw
        $csv = @(Import-Csv (Join-Path $pack '04-secops-worklist.csv'))
    }
    It 'writes both files into the pack and returns their paths' {
        $files.Count | Should -Be 2
        Test-Path (Join-Path $pack '04-secops-worklist.md') | Should -BeTrue
        Test-Path (Join-Path $pack '04-secops-worklist.csv') | Should -BeTrue
        $md | Should -Match '# SecOps worklist: Example Client'
        $md | Should -Match 'collector 1\.8\.0, collected 2026-10-12'
        $md | Should -Match 'never sent to the client'
    }
    It 'lists open alerts high severity first with the incident number and the ticket' {
        $open = @($csv | Where-Object Category -eq 'Open alerts')
        $open.Count | Should -Be 2
        $open[0].Resource | Should -Be 'Incident 42: Malware on host'
        $open[0].Detail | Should -Match 'High severity, New, created 2026-09-20, 22 days open, owner analyst@example.test'
        $open[0].Reference | Should -Be 'https://atmosera.zendesk.com/agent/tickets/777' -Because 'zendesk.com without the atmosera subdomain answers 404'
        $open[1].Reference | Should -Be 'https://atmosera.zendesk.com/agent/tickets/12345'
        $open[1].Detail | Should -Match 'owner unassigned'
        $md | Should -Match '\| Incident 41: Suspicious sign-in \\\| pipe \|'
    }
    It 'drops rows that name a resource in the managed resource group' {
        $csv | Where-Object Resource -eq 'mxdr-jump' | Should -BeNullOrEmpty
        $md | Should -Not -Match 'aznativesol0'
        @($csv | Where-Object Category -eq 'Virtual machines without Azure Backup').Resource | Should -Be @('avd-host-1', 'sql-01')
    }
    It 'keeps managed resource group rows when the pack recorded an empty exclusion' {
        $p = Get-Content (Join-Path $pack '00-parameters.json') -Raw | ConvertFrom-Json
        $p.ManagedRgPattern = ''
        $p | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $pack '00-parameters.json')
        $null = & $generator -EvidencePath $pack
        @(Import-Csv (Join-Path $pack '04-secops-worklist.csv') | Where-Object Resource -eq 'mxdr-jump').Count | Should -Be 2
    }
    It 'lists Azure virtual machines only, split into not onboarded and inactive sensor' {
        @($csv | Where-Object Category -eq 'Azure virtual machines not onboarded to endpoint detection').Count | Should -Be 0 -Because 'ws-01 is not native to Azure'
        $md | Should -Match '\| Azure virtual machines not onboarded to endpoint detection \| EW\.1 \| 0 \| None found, 1 endpoint outside Azure or on a network appliance left out \|'
        $inactive = @($csv | Where-Object Category -eq 'Azure virtual machines with an inactive sensor')
        $inactive.Resource | Should -Be @('vm-02')
        $inactive[0].Detail | Should -Match 'Sensor Inactive, Linux, last seen 2026-10-10'
        $md | Should -Not -Match 'ws-01'
    }
    It 'lists Azure virtual machines in any onboarding status except Onboarded and leaves out network appliances' {
        Add-WorklistResult $pack 'EW.1-DEVICES' '[{"DeviceName":"vm-03","Scope":"Azure VM","OSPlatform":"Linux","OnboardingStatus":"Insufficient info","SensorHealthState":"","Gap":"Not onboarded","LastSeen":"2026-10-11T00:00:00Z","MachineGroup":"","AzureResourceId":"/subscriptions/s1/resourceGroups/app/providers/Microsoft.Compute/virtualMachines/vm-03"},{"DeviceName":"fw-01","Scope":"Azure VM","OSPlatform":"Linux","OnboardingStatus":"Unsupported","SensorHealthState":"","Gap":"Not onboarded","LastSeen":"2026-10-11T00:00:00Z","MachineGroup":"","AzureResourceId":"/subscriptions/s1/resourceGroups/fw/providers/Microsoft.Compute/virtualMachines/fw-01"}]'
        Add-WorklistResult $pack 'P0.6-APPLIANCES' '[{"Name":"fw-01","ResourceType":"microsoft.compute/virtualmachines","resourceGroup":"fw","subscriptionId":"s1","Publisher":"paloaltonetworks","Offer":"vmseries-flex","PowerState":"PowerState/running","ResourceId":"/subscriptions/s1/resourcegroups/fw/providers/microsoft.compute/virtualmachines/fw-01"}]'
        $null = & $generator -EvidencePath $pack
        $rows = @(Import-Csv (Join-Path $pack '04-secops-worklist.csv'))
        $not = @($rows | Where-Object Category -eq 'Azure virtual machines not onboarded to endpoint detection')
        $not.Resource | Should -Be @('vm-03')
        $not[0].Detail | Should -Match 'Linux, onboarding status Insufficient info, last seen 2026-10-11'
        $nva = @($rows | Where-Object Category -eq 'Network virtual appliances excluded from VM measures')
        $nva.Resource | Should -Be @('fw-01')
        $nva[0].Detail | Should -Match 'paloaltonetworks vmseries-flex, resource group fw, running'
    }
    It 'flags virtual machines without backup that share a resource group with a pooled host pool' {
        $backup = @($csv | Where-Object Category -eq 'Virtual machines without Azure Backup')
        $backup.Count | Should -Be 2
        ($backup | Where-Object Resource -eq 'avd-host-1').Detail | Should -Match 'running\. A pooled AVD host pool shares this resource group'
        ($backup | Where-Object Resource -eq 'sql-01').Detail | Should -Match 'deallocated, protection state ProtectionStopped\.$'
    }
    It 'keeps only high severity Defender for Cloud recommendations, one line per recommendation' {
        $dfc = @($csv | Where-Object Category -eq 'High severity Defender for Cloud recommendations')
        $dfc.Resource | Should -Be @('Management ports should be closed')
        $dfc[0].Detail | Should -Be '1 resource: vm-02'
        Add-WorklistResult $pack 'DFC.1-DETAIL' '[{"Recommendation":"EDR solution should be installed","Severity":"High","ResourceId":"/subscriptions/s1/resourcegroups/a/providers/microsoft.compute/virtualmachines/vm-1","subscriptionId":"s1","resourceGroup":"a"},{"Recommendation":"EDR solution should be installed","Severity":"High","ResourceId":"/subscriptions/s1/resourcegroups/b/providers/microsoft.compute/virtualmachines/vm-2","subscriptionId":"s1","resourceGroup":"b"},{"Recommendation":"Management ports should be closed","Severity":"High","ResourceId":"/subscriptions/s1/resourcegroups/a/providers/microsoft.compute/virtualmachines/vm-1","subscriptionId":"s1","resourceGroup":"a"}]'
        $null = & $generator -EvidencePath $pack
        $dfc = @(Import-Csv (Join-Path $pack '04-secops-worklist.csv') | Where-Object Category -eq 'High severity Defender for Cloud recommendations')
        $dfc.Resource | Should -Be @('EDR solution should be installed', 'Management ports should be closed')
        $dfc[0].Detail | Should -Be '2 resources: vm-1, vm-2'
        $dfc[0].Reference | Should -Be 'Resource groups a, b'
    }
    It 'leaves out backup items superseded by a current backup and items for deleted resources' {
        Add-WorklistResult $pack 'DP.5-STALE' '[{"ItemName":"DB-PHI","Workload":"VM","Vault":"vmbackupsvault","resourceGroup":"biome","ProtectionState":"ProtectionStopped","LastBackupStatus":"Completed","LastBackup":"2026-03-31T06:08:39Z","StaleDays":195,"Finding":"Superseded","SourceExists":false,"CurrentBackup":"2026-10-12T06:12:21Z","SourceResourceId":"/subscriptions/s1/resourceGroups/biome/providers/Microsoft.Compute/virtualMachines/DB-PHI"},{"ItemName":"old-vm","Workload":"VM","Vault":"v","resourceGroup":"r","ProtectionState":"ProtectionStopped","LastBackupStatus":"Completed","LastBackup":"2021-07-26T00:06:40Z","StaleDays":1904,"Finding":"Source deleted","SourceExists":false,"CurrentBackup":null,"SourceResourceId":"/subscriptions/s1/resourceGroups/r/providers/Microsoft.Compute/virtualMachines/old-vm"},{"ItemName":"app-01","Workload":"VM","Vault":"v","resourceGroup":"r","ProtectionState":"ProtectionStopped","LastBackupStatus":"Completed","LastBackup":"2026-09-01T00:00:00Z","StaleDays":41,"Finding":"Protection stopped","SourceExists":true,"CurrentBackup":null,"SourceResourceId":"/subscriptions/s1/resourceGroups/r/providers/Microsoft.Compute/virtualMachines/app-01"}]'
        $null = & $generator -EvidencePath $pack
        $stale = @(Import-Csv (Join-Path $pack '04-secops-worklist.csv') | Where-Object Category -eq 'Backup items stale or not protected')
        $stale.Resource | Should -Be @('app-01')
        $stale[0].Detail | Should -Match '^Protection stopped\. VM, vault v, ProtectionStopped, last backup 2026-09-01 \(41 days ago\)'
        Get-Content (Join-Path $pack '04-secops-worklist.md') -Raw | Should -Match '1 item, 1 superseded by a current backup of the same machine left out, 1 for deleted resources with protection stopped and recovery points retained left out'
    }
    It 'keeps every stale backup item from an older pack and says why' {
        Add-WorklistResult $pack 'DP.5-STALE' '[{"ItemName":"DB-PHI","Workload":"VM","Vault":"vmbackupsvault","resourceGroup":"biome","ProtectionState":"ProtectionStopped","LastBackupStatus":"Completed","LastBackup":"2026-03-31T06:08:39Z","StaleDays":195,"SourceResourceId":"/subscriptions/s1/x/DB-PHI"}]'
        $null = & $generator -EvidencePath $pack
        @(Import-Csv (Join-Path $pack '04-secops-worklist.csv') | Where-Object Category -eq 'Backup items stale or not protected').Resource | Should -Be @('DB-PHI')
        Get-Content (Join-Path $pack '04-secops-worklist.md') -Raw | Should -Match 'collected before collector 1\.10\.0 without a VM inventory to check against, so items superseded by a current backup'
    }
    It 'infers superseded and deleted backup sources for an older pack from the VM inventory' {
        Add-WorklistResult $pack 'EW.7-DETAIL' '[{"VmName":"DB-PHI","resourceGroup":"biome-phi","subscriptionId":"s1","OsType":"Linux","PowerState":"PowerState/running","SecurityType":""},{"VmName":"app-01","resourceGroup":"r","subscriptionId":"s1","OsType":"Linux","PowerState":"PowerState/running","SecurityType":""}]'
        Add-WorklistResult $pack 'DP.5-STALE' '[{"ItemName":"DB-PHI","Workload":"VM","Vault":"vmbackupsvault","resourceGroup":"biome","ProtectionState":"ProtectionStopped","LastBackupStatus":"Completed","LastBackup":"2026-03-31T06:08:39Z","StaleDays":195,"SourceResourceId":"/subscriptions/s1/resourceGroups/biome/providers/Microsoft.Compute/virtualMachines/DB-PHI"},{"ItemName":"gone-vm","Workload":"VM","Vault":"v","resourceGroup":"r","ProtectionState":"ProtectionStopped","LastBackupStatus":"Completed","LastBackup":"2021-07-26T00:06:40Z","StaleDays":1904,"SourceResourceId":"/subscriptions/s1/resourceGroups/r/providers/Microsoft.Compute/virtualMachines/gone-vm"},{"ItemName":"gone-on","Workload":"VM","Vault":"v","resourceGroup":"r","ProtectionState":"Protected","LastBackupStatus":"Completed","LastBackup":"2022-09-29T00:08:24Z","StaleDays":1474,"SourceResourceId":"/subscriptions/s1/resourceGroups/r/providers/Microsoft.Compute/virtualMachines/gone-on"},{"ItemName":"app-01","Workload":"VM","Vault":"v","resourceGroup":"r","ProtectionState":"Protected","LastBackupStatus":"Failed","LastBackup":"2026-10-01T00:00:00Z","StaleDays":11,"SourceResourceId":"/subscriptions/s1/resourceGroups/r/providers/Microsoft.Compute/virtualMachines/app-01"}]'
        $null = & $generator -EvidencePath $pack
        $stale = @(Import-Csv (Join-Path $pack '04-secops-worklist.csv') | Where-Object Category -eq 'Backup items stale or not protected')
        $stale.Resource | Should -Be @('gone-on', 'app-01') -Because 'DB-PHI moved to biome-phi and is backed up there, and gone-vm was deleted with protection stopped'
        $stale[0].Detail | Should -Match '^Source deleted\. VM'
        $stale[1].Detail | Should -Match '^Backup stale\. VM'
        Get-Content (Join-Path $pack '04-secops-worklist.md') -Raw | Should -Match '2 items, 1 superseded by a current backup of the same machine left out, 1 for deleted resources with protection stopped and recovery points retained left out, findings inferred from the VM inventory'
    }
    It 'reviews device code and legacy sign-ins against the Conditional Access policy exclusions' {
        Add-WorklistResult $pack 'IA.8-POLICIES' '[{"id":"P-DC","displayName":"Block Device Code Flow Enforcement","state":"enabled","conditions":{"users":{"includeUsers":["All"],"excludeUsers":["u-ex"],"excludeGroups":["g-1"],"excludeRoles":[]},"applications":{"includeApplications":["All"]},"clientAppTypes":["all"],"authenticationFlows":{"transferMethods":"deviceCodeFlow"}},"grantControls":{"operator":"OR","builtInControls":["block"]}},{"id":"P-RO","displayName":"CAP Block Device Code Flow Report Only","state":"enabledForReportingButNotEnforced","conditions":{"users":{"includeUsers":["u-ex"]},"applications":{"includeApplications":["All"]},"clientAppTypes":["all"],"authenticationFlows":{"transferMethods":"deviceCodeFlow"}},"grantControls":{"operator":"OR","builtInControls":["block"]}}]'
        Add-WorklistResult $pack 'IA.8-SIGNINS' '[{"Flow":"Device code","ClientAppUsed":"Mobile Apps and Desktop clients","UserId":"u-ex","UserPrincipalName":"room@example.test","UserType":"Member","PolicyResults":"p-dc=notApplied,p-ro=reportOnlyFailure","SignIns":3,"LastSignIn":"2026-10-10T00:00:00Z","Apps":"Microsoft Teams"},{"Flow":"Device code","ClientAppUsed":"Mobile Apps and Desktop clients","UserId":"u-grp","UserPrincipalName":"signage@example.test","UserType":"Member","PolicyResults":"p-dc=notApplied","SignIns":1,"LastSignIn":"2026-10-09T00:00:00Z","Apps":"Azure CLI"},{"Flow":"Device code","ClientAppUsed":"Mobile Apps and Desktop clients","UserId":"u-old","UserPrincipalName":"old@example.test","UserType":"Member","PolicyResults":"","SignIns":2,"LastSignIn":"2026-09-20T00:00:00Z","Apps":""}]'
        $null = & $generator -EvidencePath $pack
        $rows = @(Import-Csv (Join-Path $pack '04-secops-worklist.csv') | Where-Object Category -eq 'Device code and legacy sign-ins to review')
        $rows.Resource | Should -Be @('old@example.test', 'room@example.test', 'signage@example.test')
        $rows[0].Detail | Should -Match '^Device code, 2 sign-ins, last 2026-09-20, not evaluated by Block Device Code Flow Enforcement, likely before the policy existed\. Apps: not recorded$'
        $rows[1].Detail | Should -Match 'excluded from Block Device Code Flow Enforcement\. Apps: Microsoft Teams'
        $rows[2].Detail | Should -Match 'excluded from Block Device Code Flow Enforcement' -Because 'notApplied on a policy for all users is a group, role or app exclusion'
    }
    It 'lists legacy protocols whose attempts failed without a Conditional Access block, with the password spraying hint' {
        Add-WorklistResult $pack 'IA.3' '[{"ClientAppUsed":"Exchange ActiveSync","Attempts":40,"Succeeded":4,"BlockedByCa":30,"Users":2},{"ClientAppUsed":"Authenticated SMTP","Attempts":500,"Succeeded":0,"BlockedByCa":2,"Users":0},{"ClientAppUsed":"IMAP4","Attempts":10,"Succeeded":0,"BlockedByCa":10,"Users":0},{"ClientAppUsed":"Unknown","Attempts":9,"Succeeded":0,"BlockedByCa":0,"Users":0}]'
        $null = & $generator -EvidencePath $pack
        $rows = @(Import-Csv (Join-Path $pack '04-secops-worklist.csv') | Where-Object Category -eq 'Legacy sign-ins that failed without a Conditional Access block')
        $rows.Resource | Should -Be @('Authenticated SMTP', 'Exchange ActiveSync') -Because 'a protocol whose failures were all blocks, and Unknown, are left out'
        $rows[0].Detail | Should -Be '498 of 500 attempts failed without a Conditional Access block. 2 blocked by Conditional Access, 0 succeeded'
        $rows[1].Detail | Should -Be '6 of 40 attempts failed without a Conditional Access block. 30 blocked by Conditional Access, 4 succeeded'
        $rows[0].ControlId | Should -Be 'IA.3'
        $text = Get-Content (Join-Path $pack '04-secops-worklist.md') -Raw
        $text | Should -Match 'A large number points to password spraying against legacy endpoints\.'
        $text | Should -Match '\| Legacy sign-ins that failed without a Conditional Access block \| IA\.3 \| 2 \| 2 items \|'
        $text | Should -Not -Match ';'
    }
    It 'says when a legacy pack cannot tell failures from blocks' {
        Add-WorklistResult $pack 'IA.3' '[{"ClientAppUsed":"Exchange ActiveSync","Attempts":40,"Succeeded":4,"Users":2}]'
        $null = & $generator -EvidencePath $pack
        $text = Get-Content (Join-Path $pack '04-secops-worklist.md') -Raw
        $text | Should -Match '\| Legacy sign-ins that failed without a Conditional Access block \| IA\.3 \| 0 \| None found, collected without the BlockedByCa column, so failures could not be told apart from Conditional Access blocks \|'
    }
    It 'lists storage accounts with public blob containers, readable ones first, and accounts that could not be listed' {
        Add-WorklistResult $pack 'DP.1-CONTAINERS' '[{"subscriptionId":"s1","resourceGroup":"web-rg","Account":"lockedstore","AccountAnonymousAccess":"Disabled","Containers":4,"PublicContainers":1,"ExposedContainers":0,"PublicContainerNames":"legacy (Container)","ReadStatus":"OK","ResourceId":"/subscriptions/s1/resourceGroups/web-rg/providers/Microsoft.Storage/storageAccounts/lockedstore"},{"subscriptionId":"s1","resourceGroup":"web-rg","Account":"openstore","AccountAnonymousAccess":"Not set, allowed","Containers":3,"PublicContainers":2,"ExposedContainers":2,"PublicContainerNames":"images (Blob), assets (Container)","ReadStatus":"OK","ResourceId":"/subscriptions/s1/resourceGroups/web-rg/providers/Microsoft.Storage/storageAccounts/openstore"},{"subscriptionId":"s1","resourceGroup":"data-rg","Account":"cleanstore","AccountAnonymousAccess":"Disabled","Containers":9,"PublicContainers":0,"ExposedContainers":0,"PublicContainerNames":"","ReadStatus":"OK","ResourceId":"/subscriptions/s1/resourceGroups/data-rg/providers/Microsoft.Storage/storageAccounts/cleanstore"},{"subscriptionId":"s1","resourceGroup":"data-rg","Account":"deniedstore","AccountAnonymousAccess":"Allowed","Containers":0,"PublicContainers":0,"ExposedContainers":0,"PublicContainerNames":"","ReadStatus":"HTTP 403: Forbidden","ResourceId":"/subscriptions/s1/resourceGroups/data-rg/providers/Microsoft.Storage/storageAccounts/deniedstore"}]'
        $null = & $generator -EvidencePath $pack
        $rows = @(Import-Csv (Join-Path $pack '04-secops-worklist.csv') | Where-Object Category -eq 'Blob containers set to anonymous access')
        $rows.Resource | Should -Be @('openstore', 'deniedstore', 'lockedstore')
        $rows[0].Detail | Should -Be '2 of 3 containers public, 2 readable anonymously today. Account setting not set, allowed. images (Blob), assets (Container)'
        $rows[1].Detail | Should -Be 'Containers not listed: HTTP 403: Forbidden'
        $rows[2].Detail | Should -Match '^1 of 4 containers public, 0 readable anonymously today\. Account setting disabled\.'
    }
    It 'reports recollection, not collected and none found statuses without inventing items' {
        $md | Should -Match '\| Blob containers set to anonymous access \| DP\.1 \| 0 \| Needs recollection with collector 1\.11\.0 or later \|'
        $md | Should -Match '\| Closed alerts without a documented disposition \| DR\.10 \| 0 \| Needs recollection with collector 1\.8 or later \|'
        $md | Should -Match '\| Backup items stale or not protected \| DP\.5 \| 0 \| Needs recollection with collector 1\.8 or later \|'
        $md | Should -Match '\| Virtual machines without Trusted Launch \| EW\.7 \| 0 \| Not collected \(UNAVAILABLE\) \|'
        $md | Should -Match '\| Virtual machines without encryption at host \| DP\.4 \| 0 \| Not collected \|'
        $md | Should -Match '\| Workload subnets without segmentation \| NB\.1 \| 0 \| None found \|'
        $md | Should -Match '\| Device code and legacy sign-ins to review \| IA\.3 \| 0 \| Needs recollection with collector 1\.10\.0 or later \|'
        $md | Should -Match '\| Legacy sign-ins that failed without a Conditional Access block \| IA\.3 \| 0 \| Not collected \|'
        $md | Should -Match '\| Network virtual appliances excluded from VM measures \| P0\.6 \| 0 \| Needs recollection with collector 1\.10\.0 or later \|'
        @($csv | Where-Object Category -match 'Trusted Launch|encryption at host|segmentation|documented disposition').Count | Should -Be 0
    }
    It 'reads a result whose file is malformed or missing as unreadable, never as none found' {
        Add-WorklistResult $pack 'NB.1' '{invalid'
        Remove-Item (Join-Path $pack 'results/DFC.1-DETAIL.json')
        $null = & $generator -EvidencePath $pack -WarningVariable warnings -WarningAction SilentlyContinue
        $text = Get-Content (Join-Path $pack '04-secops-worklist.md') -Raw
        $text | Should -Match '\| Workload subnets without segmentation \| NB\.1 \| 0 \| Result file unreadable \(NB\.1\), recollect or restore the pack \|'
        $text | Should -Match '\| High severity Defender for Cloud recommendations \| DFC\.1 \| 0 \| Result file unreadable \(DFC\.1-DETAIL\), recollect or restore the pack \|'
        @($warnings | ForEach-Object { [string]$_ }) | Should -Be @('NB.1 could not be read. Recollect or restore this result.', 'DFC.1-DETAIL could not be read. Recollect or restore this result.')
        @(Import-Csv (Join-Path $pack '04-secops-worklist.csv') | Where-Object Category -eq 'Open alerts').Count | Should -Be 2
    }
    It 'does not change the evidence and writes to another folder when asked' {
        $before = (Get-FileHash (Join-Path $pack 'results/OUT.1-OPEN.json')).Hash
        $out = Join-Path $TestDrive 'elsewhere'
        $files = @(& $generator -EvidencePath $pack -OutputPath $out)
        Test-Path (Join-Path $out '04-secops-worklist.csv') | Should -BeTrue
        (Get-FileHash (Join-Path $pack 'results/OUT.1-OPEN.json')).Hash | Should -Be $before
    }
    It 'rejects an unfinished pack' {
        Remove-Item (Join-Path $pack '00-manifest.csv')
        { & $generator -EvidencePath $pack } | Should -Throw '*missing 00-manifest.csv*'
    }
}
Describe 'Onboarding reasons and patch exclusions (collector 1.14.0)' {
    BeforeEach {
        $pack = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-WorklistFixture $pack
        Add-WorklistResult $pack 'EW.1-DEVICES' '[{"DeviceName":"cs-01","Scope":"Azure VM","OSPlatform":"WindowsServer2019","OnboardingStatus":"Can be onboarded","SensorHealthState":"","Gap":"Not onboarded","LastSeen":"2026-10-13T00:00:00Z","MachineGroup":"","AzureResourceId":"/subscriptions/s1/resourceGroups/app/providers/Microsoft.Compute/virtualMachines/cs-01"},{"DeviceName":"gap-01","Scope":"Azure VM","OSPlatform":"WindowsServer2022","OnboardingStatus":"Can be onboarded","SensorHealthState":"","Gap":"Not onboarded","LastSeen":"2026-10-13T00:00:00Z","MachineGroup":"","AzureResourceId":"/subscriptions/s1/resourceGroups/app/providers/Microsoft.Compute/virtualMachines/gap-01"},{"DeviceName":"off-01","Scope":"Azure VM","OSPlatform":"WindowsServer2022","OnboardingStatus":"Onboarded","SensorHealthState":"Inactive","Gap":"Sensor Inactive","LastSeen":"2026-10-01T00:00:00Z","MachineGroup":"","AzureResourceId":"/subscriptions/s1/resourceGroups/app/providers/Microsoft.Compute/virtualMachines/off-01"}]'
        Add-WorklistResult $pack 'EW.1-GAPS' '[{"DeviceName":"cs-01","VmName":"cs-01","resourceGroup":"app","subscriptionId":"s1","OSPlatform":"WindowsServer2019","OnboardingStatus":"Can be onboarded","SensorHealthState":"","PowerState":"running","Gap":"Not onboarded","Reason":"Covered by a third-party endpoint detection product","Product":"CrowdStrike Falcon","Evidence":"Extension CrowdStrike.Falcon/FalconSensorWindows","CountedAs":"CanBeOnboarded","Eligible":true,"Covered":true,"LastSeen":"2026-10-13T00:00:00Z","AzureResourceId":"/subscriptions/s1/resourcegroups/app/providers/microsoft.compute/virtualmachines/cs-01"},{"DeviceName":"gap-01","VmName":"gap-01","resourceGroup":"app","subscriptionId":"s1","OSPlatform":"WindowsServer2022","OnboardingStatus":"Can be onboarded","SensorHealthState":"","PowerState":"running","Gap":"Not onboarded","Reason":"Not onboarded, no endpoint detection found","Product":"","Evidence":"","CountedAs":"CanBeOnboarded","Eligible":true,"Covered":false,"LastSeen":"2026-10-13T00:00:00Z","AzureResourceId":"/subscriptions/s1/resourcegroups/app/providers/microsoft.compute/virtualmachines/gap-01"},{"DeviceName":"off-01","VmName":"off-01","resourceGroup":"app","subscriptionId":"s1","OSPlatform":"WindowsServer2022","OnboardingStatus":"Onboarded","SensorHealthState":"Inactive","PowerState":"deallocated","Gap":"Sensor Inactive","Reason":"Deallocated or stopped at collection","Product":"","Evidence":"","CountedAs":"Onboarded","Eligible":false,"Covered":false,"LastSeen":"2026-10-01T00:00:00Z","AzureResourceId":"/subscriptions/s1/resourcegroups/app/providers/microsoft.compute/virtualmachines/off-01"},{"DeviceName":"new-01","VmName":"new-01","resourceGroup":"app","subscriptionId":"s1","OSPlatform":"Windows","OnboardingStatus":"Not discovered","SensorHealthState":"","PowerState":"running","Gap":"Not discovered","Reason":"Not discovered by Defender for Endpoint","Product":"","Evidence":"","CountedAs":"NotSeen","Eligible":true,"Covered":false,"LastSeen":"","AzureResourceId":"/subscriptions/s1/resourcegroups/app/providers/microsoft.compute/virtualmachines/new-01"}]'
        Add-WorklistResult $pack 'EW.10-EXCLUDED' '[{"Name":"legacy-app-01","ResourceType":"microsoft.compute/virtualmachines","resourceGroup":"app","subscriptionId":"s1","MatchedTag":"\"patching\":\"client owned\"","ResourceId":"/subscriptions/s1/resourcegroups/app/providers/microsoft.compute/virtualmachines/legacy-app-01"}]'
        $null = & $generator -EvidencePath $pack
        $csv = @(Import-Csv (Join-Path $pack '04-secops-worklist.csv'))
        $md = Get-Content (Join-Path $pack '04-secops-worklist.md') -Raw
    }
    It 'keeps a machine covered by a third-party product out of the onboarding work and carries the reason on the rest' {
        $not = @($csv | Where-Object Category -eq 'Azure virtual machines not onboarded to endpoint detection')
        $not.Resource | Should -Be @('gap-01')
        $not[0].Detail | Should -Match 'onboarding status Can be onboarded, last seen 2026-10-13\. Not onboarded, no endpoint detection found$'
        $inactive = @($csv | Where-Object Category -eq 'Azure virtual machines with an inactive sensor')
        $inactive.Resource | Should -Be @('off-01')
        $inactive[0].Detail | Should -Match 'Sensor Inactive, WindowsServer2022, last seen 2026-10-01\. Deallocated or stopped at collection$'
    }
    It 'lists every machine not reporting to Defender for Endpoint with its reason, product and evidence' {
        $gaps = @($csv | Where-Object Category -eq 'Azure virtual machines not reporting to Defender for Endpoint, by reason')
        $gaps.Resource | Should -Be @('cs-01', 'gap-01', 'off-01', 'new-01')
        $gaps[0].Detail | Should -Be 'Covered by a third-party endpoint detection product (CrowdStrike Falcon). WindowsServer2019, not onboarded, running. Extension CrowdStrike.Falcon/FalconSensorWindows'
        $gaps[2].Detail | Should -Be 'Deallocated or stopped at collection. WindowsServer2022, sensor inactive, deallocated'
        $gaps[3].Detail | Should -Be 'Not discovered by Defender for Endpoint. Windows, not discovered, running'
        $gaps[0].Reference | Should -Match 'virtualmachines/cs-01$'
        $md | Should -Match 'confirm that the product is licensed and reporting'
    }
    It 'lists the machines a tag left out of the patch measures' {
        $ex = @($csv | Where-Object Category -eq 'Machines left out of the patch measures by tag')
        $ex.Resource | Should -Be @('legacy-app-01')
        $ex[0].Detail | Should -Be 'Tag "patching":"client owned", resource group app'
        $ex[0].Source | Should -Be 'EW.10-EXCLUDED'
    }
    It 'reads needs recollection on an older pack' {
        $old = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-WorklistFixture $old
        $null = & $generator -EvidencePath $old
        $text = Get-Content (Join-Path $old '04-secops-worklist.md') -Raw
        $text | Should -Match '\| Azure virtual machines not reporting to Defender for Endpoint, by reason \| EW\.1 \| 0 \| Needs recollection with collector 1\.14\.0 or later \|'
        $text | Should -Match '\| Machines left out of the patch measures by tag \| EW\.10 \| 0 \| Needs recollection with collector 1\.14\.0 or later \|'
    }
    It 'keeps every line to the copy rules' {
        $md | Should -Not -Match ';'
        $md | Should -Not -Match '[←-⇿]|->|=>'
        ($md -replace '[A-Za-z0-9)] > [A-Za-z]', '') | Should -Not -Match '>'
    }
}
Describe 'Windows PowerShell 5.1, where ConvertFrom-Json writes a JSON array as one object' {
    BeforeEach {
        $pack = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-WorklistFixture $pack
    }
    It 'reads JSON as Windows PowerShell 5.1 does, so the tests below cannot pass by accident' {
        (Invoke-WithWindowsPowerShellJson { , @('[{"a":1},{"a":2}]' | ConvertFrom-Json | Where-Object { $null -ne $_ }) }).Count | Should -Be 1
    }
    It 'filters each row of a result on its own, and drops the managed resource group rows' {
        Invoke-WithWindowsPowerShellJson { $null = & $generator -EvidencePath $pack }
        $csv = @(Import-Csv (Join-Path $pack '04-secops-worklist.csv'))
        @($csv | Where-Object Category -eq 'High severity Defender for Cloud recommendations').Resource | Should -Be @('Management ports should be closed')
        @($csv | Where-Object Category -eq 'Azure virtual machines with an inactive sensor').Resource | Should -Be @('vm-02')
        @($csv | Where-Object Category -eq 'Virtual machines without Azure Backup').Resource | Should -Be @('avd-host-1', 'sql-01')
    }
    It 'reads an empty result as none found, with no note about rows it does not have' {
        Add-WorklistResult $pack 'EW.1-DEVICES' '[]' 'EMPTY'
        Invoke-WithWindowsPowerShellJson { $null = & $generator -EvidencePath $pack }
        $md = Get-Content (Join-Path $pack '04-secops-worklist.md') -Raw
        $md | Should -Match '\| Azure virtual machines not onboarded to endpoint detection \| EW\.1 \| 0 \| None found \|'
    }
}
