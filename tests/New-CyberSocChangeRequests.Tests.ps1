# Pester 5 tests for New-CyberSocChangeRequests.ps1
# Run: Invoke-Pester ./tests/New-CyberSocChangeRequests.Tests.ps1 -Output Detailed
# Offline fixtures only. Nothing here signs in or calls Azure.

BeforeAll {
    $generator = Join-Path $PSScriptRoot '../New-CyberSocChangeRequests.ps1'
    # Windows PowerShell 5.1 writes the array ConvertFrom-Json parses to the pipeline as one object.
    # PowerShell 7 does the same with -NoEnumerate, so this runs a script block as 5.1 reads JSON.
    function Invoke-WithWindowsPowerShellJson([scriptblock]$Script) {
        function ConvertFrom-Json { param([Parameter(ValueFromPipeline, Position = 0)]$InputObject) process { Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $InputObject -NoEnumerate } }
        & $Script
    }
    $s1 = '5f1c2a9e-3b7d-4e21-9a6c-0d8e4f2b7c11'
    $s2 = 'a0b1c2d3-e4f5-4a6b-8c7d-9e0f1a2b3c4d'
    # A stable GUID for a fixture name, standing in for the vmId or uniqueId Azure gives a machine or scale set.
    function Get-TestId([string]$Name) {
        $hash = [Security.Cryptography.MD5]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($Name))
        ([guid]::new($hash)).ToString()
    }
    function Set-PackResult {
        param([string]$Path, [string]$Id, $Rows, [string]$Status)
        $rows = @($Rows)
        if (-not $Status) { $Status = if ($rows.Count) { 'OK' } else { 'EMPTY' } }
        ConvertTo-Json -InputObject $rows -Depth 6 | Set-Content (Join-Path $Path "results/$Id.json")
        $m = @(Import-Csv (Join-Path $Path '00-manifest.csv') | Where-Object ResultId -ne $Id)
        $m += [pscustomobject]@{ ResultId = $Id; Status = $Status; Rows = $rows.Count; ReadTimeUtc = '2026-10-12T06:10:00Z' }
        $m | Export-Csv (Join-Path $Path '00-manifest.csv') -NoTypeInformation
    }
    function Remove-PackResult {
        param([string]$Path, [string]$Id)
        @(Import-Csv (Join-Path $Path '00-manifest.csv') | Where-Object ResultId -ne $Id) | Export-Csv (Join-Path $Path '00-manifest.csv') -NoTypeInformation
        Remove-Item (Join-Path $Path "results/$Id.json") -ErrorAction SilentlyContinue
    }
    function New-ChangeFixture {
        param([string]$Path)
        New-Item -ItemType Directory -Path (Join-Path $Path 'results') -Force | Out-Null
        @{ ClientName = 'Example Client'; TenantId = 'example-tenant'; ScriptVersion = '1.4.0'; Subscriptions = @($s1, $s2); Workspaces = @(@{ Name = 'law-example-sentinel' }) } |
            ConvertTo-Json -Depth 6 | Set-Content (Join-Path $Path '00-parameters.json')
        '"ResultId","Status","Rows","ReadTimeUtc"' | Set-Content (Join-Path $Path '00-manifest.csv')
        $sa = { param($name, $rg, $sub) "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Storage/storageAccounts/$name" }
        Set-PackResult $Path 'P0.7' @(@{ subscriptionId = $s1; SubscriptionName = 'Example Production' }, @{ subscriptionId = $s2; SubscriptionName = 'Example; Dev > Test' })
        Set-PackResult $Path 'P0.5' @(@{ subscriptionId = $s1; ResourceType = 'microsoft.keyvault/vaults'; Resources = 4 }, @{ subscriptionId = $s2; ResourceType = 'microsoft.keyvault/vaults'; Resources = 2 }, @{ subscriptionId = $s1; ResourceType = 'microsoft.compute/virtualmachines'; Resources = 9 })
        Set-PackResult $Path 'DR.6-INITIATIVE' @()
        Set-PackResult $Path 'DP.1-DETAIL' @(
            @{ Name = 'stdata'; ResourceId = (& $sa 'stdata' 'rg-data' $s1); Kind = 'StorageV2'; resourceGroup = 'rg-data'; subscriptionId = $s1; SecureTransfer = $false; MinimumTlsVersion = 'TLS1_0'; AllowBlobPublicAccess = $true; NfsV3 = $false }
            @{ Name = 'stweb'; ResourceId = (& $sa 'stweb' 'rg-web' $s1); Kind = 'StorageV2'; resourceGroup = 'rg-web'; subscriptionId = $s1; SecureTransfer = $false; MinimumTlsVersion = ''; AllowBlobPublicAccess = $true; NfsV3 = $false }
            @{ Name = 'stnfsblob'; ResourceId = (& $sa 'stnfsblob' 'rg-files' $s2); Kind = 'StorageV2'; resourceGroup = 'rg-files'; subscriptionId = $s2; SecureTransfer = $false; MinimumTlsVersion = 'TLS1_2'; AllowBlobPublicAccess = $false; NfsV3 = $true }
            @{ Name = 'stpremfiles'; ResourceId = (& $sa 'stpremfiles' 'rg-files' $s2); Kind = 'FileStorage'; resourceGroup = 'rg-files'; subscriptionId = $s2; SecureTransfer = $false; MinimumTlsVersion = 'TLS1_2'; AllowBlobPublicAccess = $true; NfsV3 = $false })
        Set-PackResult $Path 'DP.1-CONTAINERS' @(
            @{ Account = 'stdata'; ResourceId = (& $sa 'stdata' 'rg-data' $s1).ToUpperInvariant(); Containers = 4; PublicContainers = 0; ExposedContainers = 0; PublicContainerNames = ''; ReadStatus = 'OK' }
            @{ Account = 'stweb'; ResourceId = (& $sa 'stweb' 'rg-web' $s1); Containers = 3; PublicContainers = 2; ExposedContainers = 2; PublicContainerNames = 'images (Blob), downloads (Container)'; ReadStatus = 'OK' })
        Set-PackResult $Path 'DP.2-DETAIL' @(@{ Name = 'kv-app'; ResourceId = 'kv1'; resourceGroup = 'rg-app'; subscriptionId = $s1; RetentionDays = 90 }, @{ Name = 'kv-dev'; ResourceId = 'kv2'; resourceGroup = 'rg-dev'; subscriptionId = $s2; RetentionDays = 7 })
        Set-PackResult $Path 'NB.4-DETAIL' @(@{ Name = 'app-portal'; ResourceId = 'app1'; Kind = 'app'; resourceGroup = 'rg-web'; subscriptionId = $s1; DefaultHostName = 'app-portal.azurewebsites.net' }, @{ Name = 'func-jobs'; ResourceId = 'app2'; Kind = 'functionapp'; resourceGroup = 'rg-web'; subscriptionId = $s1; DefaultHostName = 'func-jobs.azurewebsites.net' })
        Set-PackResult $Path 'NB.5-DETAIL' @(@{ Name = 'app-portal'; ResourceId = 'app1'; resourceGroup = 'rg-web'; subscriptionId = $s1; MinTlsVersion = '1.0' }, @{ Name = 'app-blank'; ResourceId = 'app3'; resourceGroup = 'rg-web'; subscriptionId = $s1; MinTlsVersion = '' })
        Set-PackResult $Path 'NB.6-DETAIL' @()
        $paas = { param($provider, $name, $rg, $sub) "/subscriptions/$sub/resourceGroups/$rg/providers/$provider/$name" }
        Set-PackResult $Path 'NB.6-PAAS-DETAIL' @(
            @{ Name = 'redis-sessions'; ResourceId = (& $paas 'Microsoft.Cache/Redis' 'redis-sessions' 'rg-app' $s1); ResourceType = 'microsoft.cache/redis'; resourceGroup = 'rg-app'; subscriptionId = $s1; MinimumTlsVersion = '1.0' }
            @{ Name = 'sb-orders'; ResourceId = (& $paas 'Microsoft.ServiceBus/namespaces' 'sb-orders' 'rg-msg' $s1); ResourceType = 'microsoft.servicebus/namespaces'; resourceGroup = 'rg-msg'; subscriptionId = $s1; MinimumTlsVersion = '' }
            @{ Name = 'evh-telemetry'; ResourceId = (& $paas 'Microsoft.EventHub/namespaces' 'evh-telemetry' 'rg-msg' $s1); ResourceType = 'microsoft.eventhub/namespaces'; resourceGroup = 'rg-msg'; subscriptionId = $s1; MinimumTlsVersion = '1.0' }
            @{ Name = 'evh-audit'; ResourceId = (& $paas 'Microsoft.EventHub/namespaces' 'evh-audit' 'rg-logs' $s2); ResourceType = 'microsoft.eventhub/namespaces'; resourceGroup = 'rg-logs'; subscriptionId = $s2; MinimumTlsVersion = '1.1' }
            @{ Name = 'cosmos-catalog'; ResourceId = (& $paas 'Microsoft.DocumentDB/databaseAccounts' 'cosmos-catalog' 'rg-data' $s2); ResourceType = 'microsoft.documentdb/databaseaccounts'; resourceGroup = 'rg-data'; subscriptionId = $s2; MinimumTlsVersion = 'Tls' })
        $vm = { param($name, $sub) "/subscriptions/$sub/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/$name" }
        $vmss = { param($name, $rg, $sub) "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Compute/virtualMachineScaleSets/$name" }
        Set-PackResult $Path 'DP.4-ELIGIBILITY' @(
            @{ Name = 'vm-app01'; ResourceId = (& $vm 'vm-app01' $s1); resourceGroup = 'rg-app'; subscriptionId = $s1; Location = 'eastus'; Size = 'Standard_D4s_v5'; PowerState = 'PowerState/running'; ScaleSet = ''; VmId = '1a2b3c4d-0001-4000-8000-000000000001'; AdeUsed = $false; SizeSupported = 'Yes'; Eligible = $true; Reason = '' }
            @{ Name = 'vm-old'; ResourceId = (& $vm 'vm-old' $s2); resourceGroup = 'rg-app'; subscriptionId = $s2; Location = 'westus'; Size = 'Standard_B2s'; PowerState = 'PowerState/deallocated'; ScaleSet = ''; VmId = '1a2b3c4d-0002-4000-8000-000000000002'; AdeUsed = $false; SizeSupported = 'Yes'; Eligible = $true; Reason = '' }
            @{ Name = 'vm-paused'; ResourceId = (& $vm 'vm-paused' $s1); resourceGroup = 'rg-app'; subscriptionId = $s1; Location = 'eastus'; Size = 'Standard_B2s'; PowerState = 'PowerState/stopped'; ScaleSet = ''; VmId = '1a2b3c4d-0003-4000-8000-000000000003'; AdeUsed = $false; SizeSupported = 'Yes'; Eligible = $true; Reason = '' }
            @{ Name = 'vm-ade'; ResourceId = (& $vm 'vm-ade' $s1); resourceGroup = 'rg-app'; subscriptionId = $s1; Location = 'eastus'; Size = 'Standard_D2s_v5'; PowerState = 'PowerState/running'; ScaleSet = ''; VmId = '1a2b3c4d-0004-4000-8000-000000000004'; AdeUsed = $true; SizeSupported = 'Yes'; Eligible = $false; Reason = 'Azure Disk Encryption used' }
            @{ Name = 'vm-a1'; ResourceId = (& $vm 'vm-a1' $s1); resourceGroup = 'rg-app'; subscriptionId = $s1; Location = 'eastus'; Size = 'Standard_A1'; PowerState = 'PowerState/running'; ScaleSet = ''; VmId = '1a2b3c4d-0005-4000-8000-000000000005'; AdeUsed = $false; SizeSupported = 'No'; Eligible = $false; Reason = 'size not supported' }
            @{ Name = 'vm-unread'; ResourceId = (& $vm 'vm-unread' $s2); resourceGroup = 'rg-app'; subscriptionId = $s2; Location = 'westus'; Size = 'Standard_D2s_v5'; PowerState = 'PowerState/running'; ScaleSet = ''; VmId = '1a2b3c4d-0006-4000-8000-000000000006'; AdeUsed = $false; SizeSupported = 'Unknown'; Eligible = $false; Reason = 'size support not read: HTTP 403; Forbidden' }
            @{ Name = 'vm-flex-1'; ResourceId = (& $vm 'vm-flex-1' $s1); resourceGroup = 'rg-app'; subscriptionId = $s1; Location = 'eastus'; Size = 'Standard_D4s_v5'; PowerState = 'PowerState/running'; ScaleSet = (& $vmss 'vmss-flex' 'rg-app' $s1).ToLowerInvariant(); VmId = '1a2b3c4d-0007-4000-8000-000000000007'; AdeUsed = $false; SizeSupported = 'Yes'; Eligible = $true; Reason = '' }
            @{ Name = 'vm-flex-2'; ResourceId = (& $vm 'vm-flex-2' $s1); resourceGroup = 'rg-app'; subscriptionId = $s1; Location = 'eastus'; Size = 'Standard_D4s_v5'; PowerState = 'PowerState/deallocated'; ScaleSet = (& $vmss 'vmss-flex' 'rg-app' $s1).ToLowerInvariant(); VmId = '1a2b3c4d-0008-4000-8000-000000000008'; AdeUsed = $false; SizeSupported = 'Yes'; Eligible = $true; Reason = '' }
            @{ Name = 'vm-flexade-1'; ResourceId = (& $vm 'vm-flexade-1' $s1); resourceGroup = 'rg-app'; subscriptionId = $s1; Location = 'eastus'; Size = 'Standard_D4s_v5'; PowerState = 'PowerState/running'; ScaleSet = (& $vmss 'vmss-flexade' 'rg-app' $s1).ToLowerInvariant(); VmId = '1a2b3c4d-0009-4000-8000-000000000009'; AdeUsed = $true; SizeSupported = 'Yes'; Eligible = $false; Reason = 'Azure Disk Encryption used' })
        $ss = { param($name, $rg, $sub, [hashtable]$extra = @{})
            $o = @{ Name = $name; ResourceId = (& $vmss $name $rg $sub); resourceGroup = $rg; subscriptionId = $sub; Location = 'eastus'; OrchestrationMode = 'Uniform'; UpgradePolicy = 'Manual'; Instances = 2; Size = 'Standard_D4s_v5'; UniqueId = (Get-TestId $name); HasModel = $true; AdeUsed = $false; OldSectorDisk = $false; SizeSupported = 'Yes'; SizeRead = 'OK'; Aks = $false; AksCluster = ''; AksClusterResourceGroup = ''; AksNodePool = ''; Eligible = $true; Reason = '' }
            foreach ($k in $extra.Keys) { $o[$k] = $extra[$k] }
            $o }
        Set-PackResult $Path 'DP.4-VMSS-ELIGIBILITY' @(
            (& $ss 'vmss-web' 'rg-web' $s1 @{ UpgradePolicy = 'Rolling'; Instances = 4 })
            (& $ss 'vmss-batch' 'rg-batch' $s2 @{ Instances = 1; Location = 'westus' })
            (& $ss 'vmss-flex' 'rg-app' $s1 @{ OrchestrationMode = 'Flexible'; UpgradePolicy = '' })
            (& $ss 'vmss-flexade' 'rg-app' $s1 @{ OrchestrationMode = 'Flexible'; UpgradePolicy = ''; Instances = 1 })
            (& $ss 'vmss-legacy' 'rg-app' $s1 @{ AdeUsed = $true; Eligible = $false; Reason = 'Azure Disk Encryption used' })
            (& $ss 'aks-nodepool1-12345678-vmss' 'MC_rg-aks_aks-prod_eastus' $s1 @{ Size = 'Standard_D2s_v5'; Instances = 3; SizeSupported = ''; SizeRead = ''; Aks = $true; AksCluster = 'aks-prod'; AksClusterResourceGroup = 'rg-aks'; AksNodePool = 'nodepool1'; Eligible = $false; Reason = 'AKS node pool, set only when a node pool is created' }))
        # NB.2-DETAIL: a workload subnet rule, a network interface rule that also opens 443, a firewall untrust
        # interface, a subnet that holds the firewall interface, a group attached to nothing, and a port range and
        # * rule for review. Every row carries the network interfaces of the appliances and their subnets.
        $nsg = { param($name, $rg, $sub) "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Network/networkSecurityGroups/$name" }
        $subnet = { param($vnet, $name, $rg, $sub) @{ id = "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Network/virtualNetworks/$vnet/subnets/$name" } }
        $nic = { param($name, $rg, $sub) "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Network/networkInterfaces/$name" }
        $applianceNics = @((& $nic 'nic-fw-untrust' 'rg-fw' $s1).ToLowerInvariant())
        $applianceSubnets = @((& $subnet 'vnet-hub' 'snet-untrust' 'rg-net' $s1).id.ToLowerInvariant())
        $rule = { param($name, $group, $rg, $sub, [hashtable]$extra = @{})
            $o = @{ subscriptionId = $sub; resourceGroup = $rg; NSG = $group; NsgId = (& $nsg $group $rg $sub); RuleName = $name; RuleId = (& $nsg $group $rg $sub) + "/securityRules/$name"
                Priority = 300; Direction = 'Inbound'; Access = 'Allow'; Protocol = 'Tcp'; SourcePrefixes = @('Internet'); SourcePorts = @('*'); DestinationPrefixes = @('*'); DestinationAsgs = @()
                DestinationPorts = @('3389'); Description = ''; Association = 'Subnet'; RangeNeedsReview = $false; Subnets = @(); Nics = @(); NicVms = @(); ApplianceNicIds = $applianceNics; ApplianceSubnetIds = $applianceSubnets }
            foreach ($k in $extra.Keys) { $o[$k] = $extra[$k] }
            $o }
        Set-PackResult $Path 'NB.2-DETAIL' @(
            (& $rule 'Allow-RDP' 'nsg-web' 'rg-web' $s1 @{ Subnets = @((& $subnet 'vnet-app' 'snet-web' 'rg-net' $s1)) })
            (& $rule 'Allow-SSH-HTTPS' 'nsg-jump' 'rg-ops' $s2 @{ Priority = 310; SourcePrefixes = @('', '*'); DestinationPorts = @('', '22', '443'); Description = 'Jump box access; vendor'; Association = 'NIC'
                    Nics = @(@{ id = (& $nic 'nic-jump01' 'rg-ops' $s2) }); NicVms = @(@{ NicId = (& $nic 'nic-jump01' 'rg-ops' $s2).ToLowerInvariant(); VmId = "/subscriptions/$s2/resourcegroups/rg-ops/providers/microsoft.compute/virtualmachines/vm-jump01" }) })
            (& $rule 'Allow-Mgmt' 'nsg-fw-untrust' 'rg-fw' $s1 @{ Priority = 200; DestinationPorts = @('22', '443'); Association = 'NIC'
                    Nics = @(@{ id = (& $nic 'nic-fw-untrust' 'rg-fw' $s1) }); NicVms = @(@{ NicId = (& $nic 'nic-fw-untrust' 'rg-fw' $s1).ToLowerInvariant(); VmId = "/subscriptions/$s1/resourcegroups/rg-fw/providers/microsoft.compute/virtualmachines/fw-palo01" }) })
            (& $rule 'Allow-SSH-Untrust' 'nsg-hub-untrust' 'rg-net' $s1 @{ Priority = 210; DestinationPorts = @('22'); Subnets = @((& $subnet 'vnet-hub' 'snet-untrust' 'rg-net' $s1)) })
            (& $rule 'Allow-WinRM' 'nsg-old' 'rg-old' $s2 @{ DestinationPorts = @('5985', '5986'); Association = 'Unassociated' })
            (& $rule 'Allow-HighPorts' 'nsg-app' 'rg-app' $s1 @{ Priority = 400; SourcePrefixes = @('0.0.0.0/0'); DestinationPorts = @('3000-4000'); RangeNeedsReview = $true; Subnets = @((& $subnet 'vnet-app' 'snet-app' 'rg-net' $s1)) })
            (& $rule 'Allow-Any' 'nsg-app' 'rg-app' $s1 @{ Priority = 4000; Protocol = '*'; DestinationPorts = @('*'); Subnets = @((& $subnet 'vnet-app' 'snet-app' 'rg-net' $s1)) }))
        Set-PackResult $Path 'P0.3' @(
            @{ subscriptionId = $s1; Plan = 'VirtualMachines'; Tier = 'Standard'; SubPlan = 'P2' }
            @{ subscriptionId = $s1; Plan = 'CloudPosture'; Tier = 'Free'; SubPlan = '' }
            @{ subscriptionId = $s2; Plan = 'VirtualMachines'; Tier = 'Standard'; SubPlan = 'P1' })
        Set-PackResult $Path 'DP.4-DETAIL' @(
            @{ Name = 'vm-app01'; ResourceType = 'microsoft.compute/virtualmachines'; resourceGroup = 'rg-app'; subscriptionId = $s1; PowerState = 'PowerState/running'; Size = 'Standard_D4s_v5' }
            @{ Name = 'vm-old'; ResourceType = 'microsoft.compute/virtualmachines'; resourceGroup = 'rg-app'; subscriptionId = $s2; PowerState = 'PowerState/deallocated'; Size = 'Standard_B2s' }
            @{ Name = 'vm-paused'; ResourceType = 'microsoft.compute/virtualmachines'; resourceGroup = 'rg-app'; subscriptionId = $s1; PowerState = 'PowerState/stopped'; Size = 'Standard_B2s' }
            @{ Name = 'aks-nodepool1-vmss'; ResourceType = 'microsoft.compute/virtualmachinescalesets'; resourceGroup = 'rg-aks'; subscriptionId = $s1; PowerState = 'Scale set'; Size = 'Standard_D2s_v5' })
    }
    function Get-Section([string]$Text, [string]$Heading) {
        # The lines between a template heading and the next heading of the template.
        $lines = $Text -split "`r?`n"
        $start = [array]::IndexOf($lines, $Heading)
        if ($start -lt 0) { return $null }
        $out = @(); for ($i = $start + 1; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -in $templateHeadings) { break }
            $out += $lines[$i]
        }
        @($out | Where-Object { $_ -ne '' })
    }
    # The titles a client email no longer carries (#33). An email reads as a letter: each part is a plain paragraph
    # that opens in its own words.
    $oldEmailTitles = 'What I am asking to change', 'Why I recommend it', 'What it means for you', 'The resources', 'How it can be reversed', 'Your approval', 'Your approval and a maintenance window'
    $dayPattern = '(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (January|February|March|April|May|June|July|August|September|October|November|December) \d{1,2}, \d{4}'
    # Checks one client email against the shared structure and the copy rules. Every generated email goes through it.
    # The parts are found by what each paragraph says: the ask, why, what it means for the client, the resources by
    # subscription, how the change can be reversed, and the request.
    function Assert-ApprovalEmail([string]$Text, [string]$Name) {
        $Text | Should -Match '^Subject: Approval requested: \S' -Because "$Name asks for approval in its subject"
        $lines = @($Text -split "`r?`n")
        $lines[1] | Should -Be '' -Because $Name
        $lines[2] | Should -Match '^Hello( [^\r\n]+)?,$' -Because "$Name opens with the greeting"
        $end = [array]::LastIndexOf($lines, 'Thank you,')
        $end | Should -BeGreaterThan 3 -Because "$Name signs off"
        $body = @($lines[3..($end - 1)] | Where-Object { $_ -ne '' })
        foreach ($t in $oldEmailTitles) { $body | Should -Not -Contain $t -Because "$Name has no titles" }
        $prose = @($body | Where-Object { $_ -notmatch '^- ' })
        foreach ($p in $prose) { $p | Should -Match '[.?:]$' -Because "$Name has no short line standing alone as a heading" }
        $paragraphs = @($prose | Where-Object { $_ -notmatch '^Subscription .+:$' })
        $paragraphs[0] | Should -Match '^I would like your approval to ' -Because "$Name opens with what it asks to change"
        $paragraphs[1] | Should -Match '^I recommend \S.*\bbecause\b' -Because "$Name says why in a because sentence"
        # The resources open with the paragraph just before the first subscription, and only the reversal and the
        # request follow them.
        $firstSubscription = @(for ($i = 0; $i -lt $body.Count; $i++) { if ($body[$i] -match '^Subscription .+:$') { $i } })[0]
        $firstSubscription | Should -Not -BeNullOrEmpty -Because "$Name lists the resources by subscription"
        $listed = [array]::IndexOf($paragraphs, $body[$firstSubscription - 1])
        $listed | Should -BeGreaterThan 2 -Because "$Name says what the change means for the client before the resources"
        $body[$firstSubscription - 1] | Should -Match ':$' -Because "$Name introduces the resources"
        ($paragraphs.Count - $listed) | Should -Be 3 -Because "$Name follows the resources with the reversal and the request only"
        $lastBullet = @(for ($i = 0; $i -lt $body.Count; $i++) { if ($body[$i] -match '^- ') { $i } })[-1]
        [array]::IndexOf($body, $paragraphs[-2]) | Should -BeGreaterThan $lastBullet -Because "$Name says how the change can be reversed after the resources"
        $openings = @($paragraphs | ForEach-Object { (@($_ -split '\s+' | Select-Object -First 3) -join ' ').ToLowerInvariant() })
        @($openings | Group-Object | Where-Object Count -gt 1).Count | Should -Be 0 -Because "no two paragraphs of $Name open with the same words ($($openings -join ' | '))"
        $ask = $paragraphs[-1]
        $ask | Should -Match '\bapprov' -Because "$Name asks for approval"
        $ask | Should -Match ('Please reply by {0}\.' -f $dayPattern) -Because "$Name gives a reply-by date"
        $ask | Should -Match 'I will not schedule this change until I have your approval\.$' -Because "$Name promises not to schedule the change without approval"
        if ($ask -notmatch 'maintenance window') { $ask | Should -Match ('approve [^?]*{0}\?' -f $dayPattern) -Because "$Name asks for approval of the proposed date" }
        else { $ask | Should -Match 'suggest a maintenance window' -Because "$Name asks for a maintenance window" }
        $Text | Should -Match 'Thank you,\r?\n([^\r\n]+\r?\n)?$' -Because "$Name signs off"
        $Text | Should -Not -Match '(?i)notice of planned change|planned change:|I plan to|I am planning|raise any concern|on or after|let me know by|go ahead and schedule|hold the change until your concern' -Because "$Name asks and never presents the change as decided"
        $Text | Should -Not -Match '[\u2190-\u21FF\u27F0-\u27FF\u2900-\u297F\u2B00-\u2BFF\u25B6\u25BA]|->|<-|=>' -Because "$Name has no arrow"
        $Text | Should -Not -Match '[\u2300-\u23FF\u2600-\u27BF\uFE0F]|[\uD800-\uDFFF]' -Because "$Name has no emoji"
        $Text | Should -Not -Match ';' -Because "$Name has no semicolon"
        $Text | Should -Not -Match '>' -Because "$Name has no navigation step, so no greater-than sign"
        $Text | Should -Not -Match '<' -Because "$Name has no angle bracket"
        $Text | Should -Not -Match '(?i)\b(we|our|ours|us)\b' -Because "$Name reads as written by one person"
    }
    $templateHeadings = @(
        '1. Summary', 'A) CHANGE DESCRIPTION', 'B) PURPOSE', 'C) RESOURCES',
        '2. Impact:', 'A) AVAILABILITY/PERFORMANCE', 'B) USER EXPERIENCE', 'C) DEPENDENCIES', 'D) DR Impact', 'E) MITIGATION',
        '3. Implementation, Testing & Rollback:', 'A) IMPLEMENTATION PLAN', 'B) TESTING PLAN', 'C) ROLLBACK PLAN', 'D) DR PLAN',
        '4. Additional Info / Notifications:', 'A) REFERENCES', 'B) NOTIFICATION LIST')
}

Describe 'Change request generation' {
    BeforeAll {
        $pack = Join-Path $TestDrive 'full'
        New-ChangeFixture $pack
        $files = @(& $generator -EvidencePath $pack -ClientContact 'Dana' -SenderName 'Scott Example')
        $out = Join-Path $pack '05-change-requests'
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $csv = @(Import-Csv (Join-Path $out 'change-requests.csv'))
        $crFiles = @(Get-ChildItem $out -Filter 'CR-*.txt' | Where-Object Name -notlike '*.email.txt')
        $emailFiles = @(Get-ChildItem $out -Filter '*.email.txt')
        $read = { param($name) Get-Content (Join-Path $out $name) -Raw }
    }

    It 'writes a change request for each item with gaps, the client emails, the index and the CSV' {
        @($crFiles.Name | Sort-Object) | Should -Be @(
            'CR-01-diagnostic-logging.txt', 'CR-02-storage-secure-transfer.txt', 'CR-03-storage-minimum-tls.txt', 'CR-04-app-service-minimum-tls.txt',
            'CR-06-key-vault-purge-protection.txt', 'CR-07-storage-anonymous-access.txt', 'CR-08-app-service-https-only.txt', 'CR-09-encryption-at-host.txt',
            'CR-11-redis-minimum-tls.txt', 'CR-12-service-bus-minimum-tls.txt', 'CR-13-event-hubs-minimum-tls.txt', 'CR-14-cosmos-db-minimum-tls.txt', 'CR-15-scale-set-encryption-at-host.txt',
            'CR-16-management-ports.txt')
        @($emailFiles.Name | Sort-Object) | Should -Be @($crFiles.Name | Sort-Object | ForEach-Object { $_ -replace '\.txt$', '.email.txt' }) -Because 'every change request writes a client email'
        $files.Count | Should -Be ($crFiles.Count + $emailFiles.Count + 2)
        $index | Should -Match '\| 05 \| Minimum TLS 1\.2 on Azure SQL servers \|  \| No gaps found \|'
        $index | Should -Match '\| 06 \| Purge protection on key vaults \| 2 \| Change request and client email \| CR-06-key-vault-purge-protection\.txt, CR-06-key-vault-purge-protection\.email\.txt \|'
        $index | Should -Match '\| 07 \| Anonymous blob access disabled on storage accounts \| 1 \| Change request and client email \|' -Because 'an account with a public container is left out'
        $index | Should -Match 'Internal\. Built .* from evidence pack full \(collector 1\.4\.0\)'
    }

    It 'lays every change request out on the template, in order, with an empty notification list' {
        foreach ($f in $crFiles) {
            $text = Get-Content $f.FullName -Raw
            $lines = $text -split "`r?`n"
            $positions = @($templateHeadings | ForEach-Object { [array]::IndexOf($lines, $_) })
            $positions | Should -Not -Contain -1 -Because $f.Name
            ($positions | Sort-Object) -join ',' | Should -Be ($positions -join ',') -Because "$($f.Name) keeps the template order"
            $lines[0] | Should -Match '^Title: \S' -Because $f.Name
            $lines[1] | Should -Be 'Client: Example Client'
            @(Get-Section $text 'B) NOTIFICATION LIST').Count | Should -Be 0 -Because "$($f.Name) leaves the notification list to fill in"
        }
    }

    It 'keeps the description and purpose to two sentences and each impact to one line' {
        foreach ($f in $crFiles) {
            $text = Get-Content $f.FullName -Raw
            foreach ($h in 'A) CHANGE DESCRIPTION', 'B) PURPOSE') {
                $body = @(Get-Section $text $h)
                $body.Count | Should -Be 1 -Because "$($f.Name) $h"
                [regex]::Matches($body[0], '[.!?](\s|$)').Count | Should -BeLessOrEqual 2 -Because "$($f.Name) $h"
            }
            foreach ($h in 'A) AVAILABILITY/PERFORMANCE', 'B) USER EXPERIENCE', 'C) DEPENDENCIES') {
                $body = @(Get-Section $text $h)
                $body.Count | Should -Be 1 -Because "$($f.Name) $h"
                [regex]::Matches($body[0], '[.!?](\s|$)').Count | Should -Be 1 -Because "$($f.Name) $h is one sentence"
            }
        }
    }

    It 'uses the standard mitigation everywhere except the Key Vault data protection change' {
        foreach ($f in $crFiles | Where-Object Name -ne 'CR-06-key-vault-purge-protection.txt') {
            (Get-Section (Get-Content $f.FullName -Raw) 'E) MITIGATION') -join '|' | Should -Be 'If changes need to be reverted, follow the rollback plan.' -Because $f.Name
        }
        $kv = & $read 'CR-06-key-vault-purge-protection.txt'
        @(Get-Section $kv 'E) MITIGATION')[0] | Should -Match '^Purge protection cannot be disabled once it is enabled, so this change cannot be reverted\.'
        @(Get-Section $kv 'C) ROLLBACK PLAN')[0] | Should -Match '^1\. No rollback is possible'
        @(Get-Section $kv 'C) ROLLBACK PLAN')[1] | Should -Match 'Key vaults > Manage deleted vaults'
        $kv | Should -Match 'kv-dev, resource group rg-dev, soft delete retention 7 days'
    }

    It 'keeps the implementation to the change itself and the testing plan to checks in the Azure portal' {
        foreach ($f in $crFiles) {
            $text = Get-Content $f.FullName -Raw
            $impl = @(Get-Section $text 'A) IMPLEMENTATION PLAN')
            $impl.Count | Should -BeGreaterThan 0
            ($impl -join "`n") | Should -Not -Match '(?m)^\d+\. (Confirm|Verify|Check|Validate|Review|Make sure|Ensure)\b' -Because "$($f.Name) has no pre-check steps"
            ($impl -join "`n") | Should -Not -Match '(?i)pre-?check|before you begin' -Because $f.Name
            $testing = @(Get-Section $text 'B) TESTING PLAN')
            $testing[0] | Should -Match '^1\. In the Azure portal, ' -Because $f.Name
            ($testing -join "`n") | Should -Not -Match '\baz |Get-Az|Cloud Shell|PowerShell|curl' -Because "$($f.Name) tests in the portal only"
        }
    }

    It 'cites Microsoft Learn only' {
        foreach ($f in $crFiles) {
            $refs = @(Get-Section (Get-Content $f.FullName -Raw) 'A) REFERENCES')
            $refs.Count | Should -BeGreaterThan 0
            foreach ($r in $refs) { $r | Should -Match '^- [^:]+: https://learn\.microsoft\.com/azure/\S+$' -Because $f.Name }
            (Get-Content $f.FullName -Raw) | Should -Not -Match '(?i)\bSOP\b|zendesk|ticket' -Because $f.Name
        }
    }

    It 'keeps every file to the copy rules and the first person singular' {
        foreach ($f in Get-ChildItem $out -File) {
            $text = Get-Content $f.FullName -Raw
            $text | Should -Not -Match ';' -Because $f.Name
            $text | Should -Not -Match '[←-⇿➔➡▶►]|->|<-|=>' -Because $f.Name
            $text | Should -Not -Match '[☀-➿]|[\uD800-\uDFFF]' -Because $f.Name
            ($text -replace '[A-Za-z0-9)] > [A-Za-z]', '') | Should -Not -Match '>' -Because "$($f.Name) uses the greater-than sign only in navigation steps"
            $text | Should -Not -Match '(?i)\b(we|our|ours|us)\b' -Because "$($f.Name) reads as written by one person"
        }
        & $read 'CR-06-key-vault-purge-protection.txt' | Should -Match 'Subscription: Example, Dev Test \(a0b1c2d3' -Because 'pack values are cleaned of semicolons and angle brackets'
    }

    It 'refuses an arrow, an emoji, a semicolon and, in a client email, any greater-than sign' {
        # Assert-CopyRules checks every file before it is written. Loaded from the script, it must refuse each rule.
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $generator).Path, [ref]$null, [ref]$null)
        $defs = @($ast.FindAll({ param($n) ($n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Assert-CopyRules') -or ($n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -in '$arrowCharacters', '$emojiCharacters') }, $false))
        $defs.Count | Should -Be 3
        . ([scriptblock]::Create((@($defs | ForEach-Object { $_.Extent.Text }) -join "`n")))
        $broken = [ordered]@{
            ('Open it {0} then save.' -f [char]0x2192) = 'an arrow'; 'Open it -> then save.' = 'an arrow'; 'Open it <- then save.' = 'an arrow'; 'Open it => then save.' = 'an arrow'
            ('Done {0}' -f [char]0x2705) = 'an emoji'; ('Done {0}' -f [char]::ConvertFromUtf32(0x1F512)) = 'an emoji'; ('Done {0}{1}' -f [char]0x2714, [char]0xFE0F) = 'an emoji'
            'First, then second; third.' = 'a semicolon'
        }
        foreach ($text in $broken.Keys) {
            { Assert-CopyRules $text 'test' } | Should -Throw "*$($broken[$text])*" -Because $text
            { Assert-CopyRules $text 'test' -Email } | Should -Throw "*$($broken[$text])*" -Because "$text in an email"
        }
        { Assert-CopyRules 'Go to Settings > Configuration.' 'test' } | Should -Not -Throw -Because 'a navigation step may use the greater-than sign'
        { Assert-CopyRules 'Go to Settings > Configuration.' 'test' -Email } | Should -Throw '*greater-than sign, which a client email never needs*'
        { Assert-CopyRules 'Retention is > 7 days.' 'test' } | Should -Throw '*greater-than sign outside a navigation step*'
        { Assert-CopyRules 'Could you approve this change for Monday, November 2, 2026?' 'test' -Email } | Should -Not -Throw
    }

    It 'names subscriptions and groups the resources under them with their current setting' {
        $text = & $read 'CR-03-storage-minimum-tls.txt'
        $text | Should -Match "Subscription: Example Production \($s1\)\r?\n- stdata, resource group rg-data, minimum TLS 1\.0\r?\n- stweb, resource group rg-web, minimum TLS not set"
        $text | Should -Match 'Set the minimum TLS version to 1\.2 on the 2 storage accounts listed below\.'
        $text | Should -Match '4\. Repeat steps 1 to 3 for each remaining storage account listed\.'
    }

    It 'leaves storage accounts that may serve NFS out of the secure transfer change and says so' {
        $text = & $read 'CR-02-storage-secure-transfer.txt'
        $text | Should -Match '- stdata, resource group rg-data, secure transfer disabled'
        $text | Should -Not -Match 'stnfsblob|stpremfiles'
        $index | Should -Match '2 storage accounts that may serve NFS left out of CR-02: stnfsblob, stpremfiles\. Add each one only once it is confirmed to host no NFS share\.'
    }

    It 'turns off anonymous access only where every container was listed and none is public' {
        $text = & $read 'CR-07-storage-anonymous-access.txt'
        @(Get-Section $text 'C) RESOURCES') | Should -Be @(
            'The storage account below allows anonymous blob access, with the containers listed at collection. No container in it is set to Blob or Container access.'
            "Subscription: Example Production ($s1)"
            '- stdata, resource group rg-data, 4 containers, all private') -Because 'container rows match the account whatever the case of the resource ID'
        $text | Should -Not -Match 'stweb' -Because 'an account with a public container is left out'
        $text | Should -Not -Match 'stpremfiles' -Because 'a FileStorage account holds no blob service'
        $text | Should -Not -Match 'stnfsblob' -Because 'an account that already blocks anonymous access needs no change'
        @(Get-Section $text 'A) CHANGE DESCRIPTION')[0] | Should -Be 'Set Allow Blob anonymous access to Disabled on the storage account listed below, none of which has a container open to anonymous access.'
        @(Get-Section $text 'B) PURPOSE')[0] | Should -Be 'Turning the setting off stops a container being opened to anonymous access later, by mistake or by a misconfigured deployment. No container in this account is open to anonymous access today.'
        @(Get-Section $text 'B) USER EXPERIENCE')[0] | Should -Be 'No change, since no container in this account allows anonymous access and a static website hosted in a storage account is not affected by the setting.'
        @(Get-Section $text 'C) DEPENDENCIES')[0] | Should -Be 'None, since access through Microsoft Entra ID, shared access signatures or account keys is unaffected.'
        (Get-Section $text 'E) MITIGATION') -join '|' | Should -Be 'If changes need to be reverted, follow the rollback plan.'
        @(Get-Section $text 'A) IMPLEMENTATION PLAN') | Should -Be @(
            '1. In the Azure portal, go to Storage accounts and open the storage account listed in the RESOURCES section.'
            '2. Go to Data storage > Containers and confirm the Anonymous access level of every container reads Private.'
            '3. If any container reads Blob or Container, stop here and leave the account unchanged, and note it in the change record for the next pack.'
            '4. Go to Settings > Configuration.'
            '5. Set Allow Blob anonymous access to Disabled and select Save.') -Because 'the containers are checked again at change time, before Save'
        @(Get-Section $text 'B) TESTING PLAN') | Should -Be @(
            '1. In the Azure portal, open the storage account listed in the RESOURCES section and go to Settings > Configuration.'
            '2. Confirm Allow Blob anonymous access shows Disabled.')
        @(Get-Section $text 'C) ROLLBACK PLAN') | Should -Be @(
            '1. In the Azure portal, open the storage account to revert and go to Settings > Configuration.'
            '2. Set Allow Blob anonymous access to Enabled and select Save. The setting takes up to 30 seconds to apply, and the containers keep their Private access level, so nothing else changes.')
        $text | Should -Match '- Configure anonymous read access for containers and blobs: https://learn\.microsoft\.com/azure/storage/blobs/anonymous-read-access-configure'
        $text | Should -Not -Match '(?i)lose access|loses access'
        @($csv | Where-Object CR -eq 'CR-07' | ForEach-Object { '{0}|{1}' -f $_.Resource, $_.CurrentSetting }) | Should -Be @('stdata|4 containers, all private')
        $index | Should -Match ([regex]::Escape('- 1 storage account left out of CR-07 because it has a container set to Blob or Container access, which anyone can read today without signing in: stweb (resource group rg-web): images (Blob), downloads (Container). Turning the account setting off would stop those anonymous reads, so the owner of each container confirms first that it serves no public content and the container is set to private. A later pack picks each account up for CR-07 once every container in it is private.'))
    }

    It 'asks for approval to turn off anonymous access, with the no-risk walk-through and the fallback' {
        $email = & $read 'CR-07-storage-anonymous-access.email.txt'
        $email | Should -Match '^Subject: Approval requested: turning off anonymous access to Azure Blob Storage\r?\n\r?\nHello Dana,'
        $email | Should -Match 'I would like your approval to turn off anonymous access to Azure Blob Storage at the account level on one of your storage accounts\. Anonymous access lets anyone read a container over the internet without signing in\.'
        $email | Should -Match 'I recommend turning anonymous access off because the account setting still allows a container to be made public today\. Turning it off means no container in it can be opened to anonymous access later, by mistake or by a misconfigured deployment\.'
        $email | Should -Match "The account is listed below:\r?\n\r?\nSubscription Example Production \($s1\):\r?\n\r?\n- stdata \(resource group rg-data\)\r?\n"
        $email | Should -Match 'I do not expect this change to affect anything that uses the account today, for these reasons:'
        $email | Should -Match '- Every container in the account is private today, so no one reads its blob data without signing in\.'
        $email | Should -Match '- A static website hosted in a storage account keeps serving as it does now, since the setting does not apply to it\.' -Because 'the static website container stays public whatever the account setting'
        $email | Should -Match '- Applications and people that sign in, or that use a shared access signature or an account key, keep working as they do now\.'
        $email | Should -Match '- Just before the change, I will check the containers of the account again, and leave it unchanged if a container has been made public since my review\.'
        $email | Should -Match '\r?\n\r?\nIf anything unexpected comes up, I can turn the setting back on straight away\. It takes up to 30 seconds to apply, and the containers stay as they are\.'
        $email | Should -Match '\r?\n\r?\nCould you approve this change for \w+day, '
        $email | Should -Not -Match '(?i)lose access|loses access|stweb|images|downloads' -Because 'the email lists only the accounts in the change'
        $email | Should -Match 'Thank you,\r?\nScott Example\r?\n$'
    }

    It 'asks for written approval of purge protection, with the vaults by subscription and their retention' {
        $email = & $read 'CR-06-key-vault-purge-protection.email.txt'
        $email | Should -Match '^Subject: Approval requested: purge protection for Azure key vaults\r?\n\r?\nHello Dana,'
        $email | Should -Match '\bI would like your approval to turn on purge protection for 2 of your Azure key vaults\.' -Because 'the email is written in the first person singular'
        $email | Should -Match "Subscription Example Production \($s1\):\r?\n\r?\n- kv-app \(resource group rg-app, soft delete retention 90 days\)\r?\n\r?\nSubscription Example, Dev Test \($s2\):\r?\n\r?\n- kv-dev \(resource group rg-dev, soft delete retention 7 days\)"
        $email | Should -Match '\r?\n\r?\nThis change cannot be undone\. Purge protection cannot be turned off once it is enabled, by anyone including Microsoft'
        $email | Should -Match 'a deleted vault, key, secret or certificate is kept for the retention period of its vault and cannot be purged early\.'
        $email | Should -Match 'A deleted vault keeps its name until then, so the name cannot be reused'
        $email | Should -Match 'I need your written approval before I schedule it\. Could you approve purge protection on these vaults for \w+day, '
        $email | Should -Not -Match 'build kickoff' -Because 'no approval was given at kickoff'
        $email | Should -Match 'Thank you,\r?\nScott Example\r?\n$'
        @(Get-Section (& $read 'CR-06-key-vault-purge-protection.txt') 'E) MITIGATION')[0] | Should -Match '^Purge protection cannot be disabled once it is enabled' -Because 'the change request keeps its own mitigation'
    }

    It 'drafts the HTTPS Only email with the host names and asks about HTTP callers before the approval' {
        $email = & $read 'CR-08-app-service-https-only.email.txt'
        $email | Should -Match '^Subject: Approval requested: HTTPS only for Azure App Service applications\r?\n'
        $email | Should -Match 'I would like your approval to turn on the HTTPS Only setting for 2 of your App Service and Function applications\.'
        $email | Should -Match "Subscription Example Production \($s1\):\r?\n\r?\n- app-portal \(resource group rg-web, app-portal\.azurewebsites\.net\)\r?\n- func-jobs \(resource group rg-web, func-jobs\.azurewebsites\.net\)"
        $email | Should -Match '\r?\n\r?\nCould you let me know whether any of your systems or partners still call these applications over HTTP\? If none do, could you approve this change for \w+day, [^?]+\? Please reply by [^.]+\d{4}\. If one does, I will hold the change until it uses HTTPS\.'
    }

    It 'enables encryption at host on virtual machines only, with the feature registered per subscription' {
        $text = & $read 'CR-09-encryption-at-host.txt'
        $text | Should -Not -Match 'aks-nodepool1|vmss-' -Because 'scale sets have their own change, CR-15'
        foreach ($name in 'vm-flex-1', 'vm-flex-2') { $text | Should -Not -Match $name -Because "$name is an instance of a Flexible scale set that CR-15 changes" }
        $index | Should -Match '2 virtual machines left out of CR-09 because they belong to a Flexible scale set that CR-15 changes, so CR-15 handles them with their scale set: vm-flex-1 \(vmss-flex\), vm-flex-2 \(vmss-flex\)\.'
        $index | Should -Not -Match 'vm-flexade-1 \(vmss-flexade\)' -Because 'CR-15 leaves vmss-flexade out, so its machine stays with CR-09'
        $index | Should -Not -Match 'need their own change' -Because 'the old note pointed to a change that did not exist'
        foreach ($name in 'vm-ade', 'vm-a1', 'vm-unread') { $text | Should -Not -Match $name -Because "$name cannot take encryption at host as it stands" }
        $index | Should -Match '4 virtual machines left out of CR-09 because they cannot take encryption at host as they stand: vm-a1 \(Standard_A1, size not supported\), vm-ade \(Standard_D2s_v5, Azure Disk Encryption used\), vm-flexade-1 \(Standard_D4s_v5, Azure Disk Encryption used\), vm-unread \(Standard_D2s_v5, size support not read\)\.'
        $index | Should -Match '\| 09 \| Encryption at host on virtual machines \| 3 \| Change request and client email \|'
        foreach ($s in $s1, $s2) { $text | Should -Match "    az feature register --name EncryptionAtHost --namespace Microsoft\.Compute --subscription $s" }
        $text | Should -Not -Match 'az account set' -Because 'each command names its subscription'
        $text | Should -Match 'Go to Settings > Disks > Additional settings, set Encryption at host to Yes and select Save\.'
        $text | Should -Match '8\. Repeat steps 3 to 7 for each remaining virtual machine listed\.'
        $text | Should -Match '4\. On Overview, select JSON View and confirm properties\.vmId reads the VM ID listed for the machine in the RESOURCES section\. If it reads another ID, the machine was created again under the same name after collection and was never checked, so leave it unchanged for the next pack and skip the remaining steps for it\.' -Because 'a machine is matched by its VM ID before it is stopped, never by its name alone'
        $text | Should -Match '5\. On Overview, note whether the status reads Running, then select Stop'
        $text | Should -Match '7\. Go back to Overview and select Start only if the status read Running before the stop' -Because 'the machine returns to its power state at the time of the change, not at collection'
        $text | Should -Match '- vm-paused, resource group rg-app, size Standard_B2s, stopped, VM ID 1a2b3c4d-0003-4000-8000-000000000003'
        $text | Should -Match '- vm-app01, resource group rg-app, size Standard_D4s_v5, running, VM ID 1a2b3c4d-0001-4000-8000-000000000001'
        $text | Should -Match 'listed with the size, power state and VM ID of each at collection\. Each machine is changed only if its VM ID still matches'
        @(Get-Section $text 'B) TESTING PLAN')[0] | Should -Be '1. In the Azure portal, open each virtual machine listed in the RESOURCES section whose VM ID matched and go to Settings > Disks > Additional settings.'
        $index | Should -Match '- CR-09 changes a virtual machine only when the VM ID that Overview > JSON View shows matches the VM ID listed for it\. A machine whose VM ID differs was deleted and created again under the same name after collection and was never checked, so it is skipped and left for the next pack\.'
        @(Get-Section $text 'C) ROLLBACK PLAN')[-1] | Should -Match '^3\. Go back to Overview and select Start only if the status read Running before the stop\.$' -Because 'rollback restores the power state the machine had'
        (Get-Section $text 'D) DR Impact') -join '|' | Should -Be 'Not a DR Client'
        (Get-Section $text 'D) DR PLAN') -join '|' | Should -Be 'Not a DR Client. No updates to the DR Playbook are required.'
        $email = & $read 'CR-09-encryption-at-host.email.txt'
        $email | Should -Match '- vm-app01 \(resource group rg-app, running at my last review\)'
        $email | Should -Match '- vm-old \(resource group rg-app, stopped at my last review\)'
        $email | Should -Match '- vm-paused \(resource group rg-app, stopped at my last review\)' -Because 'a machine stopped but still allocated is not running either'
        $email | Should -Match 'a server that is already stopped will be left stopped'
        $email | Should -Match '^Subject: Approval requested: encryption at host for Azure virtual machines\r?\n'
        $email | Should -Match '\r?\n\r?\nCould you approve this change and suggest a maintenance window that works for these servers\? Please reply by '
        $email | Should -Match '\r?\n\r?\nEncryption at host can be turned off again, which needs the same stop and start of each virtual machine inside a maintenance window\.'
        $email | Should -Not -Match 'VM ID|1a2b3c4d-000' -Because 'the IDs are for the operator, and the client email keeps to the servers'
    }

    It 'enables encryption at host on the eligible scale sets through the model, then on each existing instance by orchestration mode' {
        $text = & $read 'CR-15-scale-set-encryption-at-host.txt'
        $text | Should -Match 'Title: Enable encryption at host on virtual machine scale sets'
        $text | Should -Match 'Enable encryption at host on the model and the existing instances of the 3 virtual machine scale sets listed below, which needs a stop and start of each instance\.'
        $text | Should -Match "Subscription: Example Production \($s1\)\r?\n- vmss-flex, resource group rg-app, Flexible, no upgrade policy, 2 instances, size Standard_D4s_v5, unique ID $(Get-TestId 'vmss-flex'), instances without encryption at host: vm-flex-1 \(running, VM ID 1a2b3c4d-0007-4000-8000-000000000007\), vm-flex-2 \(deallocated, VM ID 1a2b3c4d-0008-4000-8000-000000000008\)\r?\n- vmss-web, resource group rg-web, Uniform, upgrade policy Rolling, 4 instances, size Standard_D4s_v5, unique ID $(Get-TestId 'vmss-web')\r?\n"
        $text | Should -Match "- vmss-batch, resource group rg-batch, Uniform, upgrade policy Manual, 1 instance, size Standard_D4s_v5, unique ID $(Get-TestId 'vmss-batch')\r?\n"
        foreach ($name in 'vmss-legacy', 'vmss-flexade', 'aks-nodepool1') { $text | Should -Not -Match $name -Because "$name is not proven eligible" }
        $index | Should -Match '\| 15 \| Encryption at host on virtual machine scale sets \| 3 \| Change request and client email \| CR-15-scale-set-encryption-at-host\.txt, CR-15-scale-set-encryption-at-host\.email\.txt \|'
        $index | Should -Match '1 scale set left out of CR-15 because its model cannot take encryption at host as it stands: vmss-legacy \(Standard_D4s_v5, Azure Disk Encryption used\)\.'
        $index | Should -Match '1 Flexible scale set left out of CR-15 because it has a machine that cannot take encryption at host as it stands: vmss-flexade \(vm-flexade-1 Azure Disk Encryption used\)\.'
        $impl = @(Get-Section $text 'A) IMPLEMENTATION PLAN')
        foreach ($s in $s1, $s2) {
            $impl | Should -Contain "    az feature register --name EncryptionAtHost --namespace Microsoft.Compute --subscription $s"
            $impl | Should -Contain "    az feature show --name EncryptionAtHost --namespace Microsoft.Compute --subscription $s --query properties.state -o tsv"
        }
        $impl | Should -Contain '3. In the Azure portal, go to Virtual machine scale sets, open each scale set listed in the RESOURCES section, select JSON View on Overview and confirm properties.uniqueId reads the unique ID listed for it. A scale set that reads another ID was created again under the same name after collection and was never checked, so leave it out of every step below, which leaves it for the next pack.' -Because 'a scale set is matched by its unique ID before its model is changed and its instances stopped'
        $impl | Should -Contain '4. In Cloud Shell, set encryption at host on the model of each scale set listed in the RESOURCES section whose unique ID matched. A scale set with an Automatic upgrade policy may take all its instances down at once to apply the new model, and one with a Rolling policy applies it in batches, so run this only inside the agreed maintenance window:'
        $impl | Should -Contain "    az vmss update --subscription '$s1' --resource-group 'rg-web' --name 'vmss-web' --set virtualMachineProfile.securityProfile.encryptionAtHost=true"
        $impl | Should -Contain "    az vmss update --subscription '$s2' --resource-group 'rg-batch' --name 'vmss-batch' --set virtualMachineProfile.securityProfile.encryptionAtHost=true"
        $impl | Should -Contain '5. In the Azure portal, go to Virtual machine scale sets, open the first Uniform scale set listed in the RESOURCES section and go to Settings > Instances.'
        $impl | Should -Contain '6. Select the first instance, note whether its status reads Running, then select Stop and wait for the status to read Stopped (deallocated).'
        $impl | Should -Contain '7. With the instance still selected, select Upgrade if Latest model reads No, and wait for the upgrade to finish.'
        $impl | Should -Contain '8. Select Start only if the instance read Running before the stop, so an instance that was not running stays stopped.'
        $impl | Should -Contain '9. Repeat steps 6 to 8 for each remaining instance, then steps 5 to 8 for each remaining Uniform scale set listed.'
        $impl | Should -Contain '10. In the Azure portal, go to Virtual machine scale sets, open the Flexible scale set listed in the RESOURCES section, go to Settings > Instances and open the first instance listed there, since the scale set may have gained instances since collection.'
        $impl | Should -Contain '11. On Overview, select JSON View and go on to the next instance if properties.vmId does not read a VM ID listed for this scale set in the RESOURCES section, since the instance joined or was created again under the same name after collection and was not checked, which leaves it for the next pack.' -Because 'an instance that joined after collection, or one created again under a listed name, was never checked for Azure Disk Encryption, old 512e disks or its size'
        $impl | Should -Contain '12. Go to Settings > Disks > Additional settings and go on to the next instance if Encryption at host already shows Yes.'
        $impl | Should -Contain '13. On Overview, note whether the status reads Running, then select Stop and wait for the status to read Stopped (deallocated).'
        $impl | Should -Contain '14. Go to Settings > Disks > Additional settings, set Encryption at host to Yes and select Save.'
        $impl | Should -Contain '15. Go back to Overview and select Start only if the status read Running before the stop, so an instance that was not running stays stopped.'
        $impl[-1] | Should -Be '16. Repeat steps 11 to 15 for each remaining instance under Settings > Instances.' -Because 'the instances are those the scale set holds when the change is made, not only those collected'
        ($impl -join "`n") | Should -Not -Match 'not named in the RESOURCES section' -Because 'a name alone also matches an instance created again under it'
        $index | Should -Match '- CR-15 changes a scale set only when the unique ID that Overview > JSON View shows matches the unique ID listed for it, and a Flexible scale set instance only when its VM ID matches one listed for its scale set\. One whose ID differs was deleted and created again under the same name after collection and was never checked, so it is skipped and left for the next pack\.'
        $testing = @(Get-Section $text 'B) TESTING PLAN')
        $testing[0] | Should -Be '1. In the Azure portal, open each scale set listed in the RESOURCES section whose unique ID matched, select JSON View on Overview and confirm virtualMachineProfile.securityProfile.encryptionAtHost reads true.'
        $testing[1] | Should -Match '^2\. For each Uniform scale set, go to Settings > Instances and confirm every instance shows Latest model Yes'
        $testing[2] | Should -Match '^3\. For the Flexible scale set, open each instance changed under Settings > Instances, go to Settings > Disks > Additional settings and confirm Encryption at host shows Yes'
        $rollback = @(Get-Section $text 'C) ROLLBACK PLAN')
        $rollback | Should -Contain "    az vmss update --subscription '$s1' --resource-group 'rg-web' --name 'vmss-web' --set virtualMachineProfile.securityProfile.encryptionAtHost=false"
        ($rollback -join "`n") | Should -Match 'For a Uniform scale set, go to Settings > Instances and for each instance note whether its status reads Running, select Stop, wait for Stopped \(deallocated\), select Upgrade, and select Start only if it read Running before the stop\.'
        ($rollback -join "`n") | Should -Match 'For a Flexible scale set, open each instance under Settings > Instances whose Encryption at host shows Yes under Settings > Disks > Additional settings, including any created after the model was changed,' -Because 'an instance created from the changed model has the setting too'
        ($rollback -join "`n") | Should -Match 'set Encryption at host to No under Settings > Disks > Additional settings, select Save, and select Start only if it read Running before the stop\.'
        @(Get-Section $text 'A) AVAILABILITY/PERFORMANCE')[0] | Should -Be 'Each instance is unavailable for a few minutes while it is stopped and started inside the agreed maintenance window, and a scale set with a Rolling upgrade policy may take several instances down in each batch to apply the model.' -Because 'vmss-web uses a Rolling policy, which applies the model in batches'
        (Get-Section $text 'D) DR Impact') -join '|' | Should -Be 'Not a DR Client'
        $text | Should -Match 'virtual-machine-scale-sets-perform-manual-upgrades'
        @($csv | Where-Object CR -eq 'CR-15' | ForEach-Object Resource | Sort-Object) | Should -Be @('vmss-batch', 'vmss-flex', 'vmss-web')
    }

    It 'asks for a maintenance window for the scale sets, one instance at a time, and warns about automatic upgrades' {
        $email = & $read 'CR-15-scale-set-encryption-at-host.email.txt'
        $email | Should -Match '^Subject: Approval requested: encryption at host for Azure virtual machine scale sets\r?\n\r?\nHello Dana,'
        $email | Should -Match 'I would like your approval to enable encryption at host on 3 of your virtual machine scale sets\.'
        $email | Should -Match "Subscription Example Production \($s1\):\r?\n\r?\n- vmss-flex \(resource group rg-app, 2 instances\)\r?\n- vmss-web \(resource group rg-web, 4 instances\)\r?\n\r?\nSubscription Example, Dev Test \($s2\):\r?\n\r?\n- vmss-batch \(resource group rg-batch, 1 instance\)"
        $email | Should -Match 'which I will do one instance at a time'
        $email | Should -Match 'an instance that is already stopped will be left stopped'
        $email | Should -Match 'One scale set is set to update its instances automatically, so once the setting is applied it may also restart them on its own, all at the same time under the Automatic policy and in batches under the Rolling policy\. I will plan the window as if every instance could be unavailable at once: vmss-web \(Rolling\)\.'
        $email | Should -Match 'Could you approve this change and suggest a maintenance window that works for these scale sets\? Please reply by [^.]+\d{4}\. If any of them need to be handled separately or in a particular order, please let me know\.'
        $email | Should -Match 'Thank you,\r?\nScott Example\r?\n$'
        $email | Should -Not -Match 'unique ID|VM ID' -Because 'the IDs are for the operator, and the client email keeps to the scale sets'
    }

    It 'routes AKS node pools to a planned project in the index instead of a change request' {
        $index | Should -Match '1 AKS node pool without encryption at host left out of CR-15 and routed to a planned project: cluster aks-prod \(resource group rg-aks\) node pool nodepool1 \(Standard_D2s_v5, 3 nodes\)\. AKS sets encryption at host only when a node pool is created, so each pool is replaced: a new node pool created with encryption at host, its workloads moved across and the old pool removed\. Plan that with the client as a project, not as a low-impact change\.'
        @($files | Where-Object { $_ -match '(?i)aks' }) | Should -BeNullOrEmpty -Because 'no change request or email is written for AKS'
    }

    It 'checks the EncryptionAtHost registration state on each subscription, not only the last one set' {
        # Step 2 alone: from its numbered line to the next numbered step.
        $impl = @(Get-Section (& $read 'CR-09-encryption-at-host.txt') 'A) IMPLEMENTATION PLAN')
        $from = [array]::IndexOf($impl, @($impl -match '^2\. ')[0])
        $to = [array]::IndexOf($impl, @($impl -match '^3\. ')[0])
        $step = $impl[$from..($to - 1)] -join "`n"
        $step | Should -Match '2\. Wait for the registration on each subscription, running these until every one returns Registered:'
        foreach ($s in $s1, $s2) {
            $step | Should -Match "    az feature show --name EncryptionAtHost --namespace Microsoft\.Compute --subscription $s --query properties\.state -o tsv" -Because "step 2 checks $s itself"
        }
        $step | Should -Not -Match 'az feature show --name EncryptionAtHost --namespace Microsoft\.Compute on each subscription'
    }

    It 'assigns the diagnostic logging initiative when it is not assigned yet' {
        $text = & $read 'CR-01-diagnostic-logging.txt'
        $text | Should -Match 'Title: Deploy the ATMO-MXDR diagnostic logging initiative'
        $text | Should -Match "- Example Production \($s1\)"
        $text | Should -Match '- Key vaults: 6\r?\n- Subscription Activity Log: 2' -Because 'only the covered types present in the estate are counted'
        $text | Should -Match 'set the Log Analytics workspace to the Sentinel workspace law-example-sentinel\.'
        $text | Should -Match 'User assigned managed identity and select ATMO-MXDR-DIAG-MI'
        $text | Should -Match 'The initiative is assigned at each subscription below'
        $text | Should -Match '3\. On the Basics tab, set Scope to the first subscription listed in the RESOURCES section'
        $text | Should -Match '7\. Repeat steps 1 to 6 for each remaining subscription listed\.' -Because 'an assignment has one scope, so each subscription gets its own'
        $text | Should -Match '8\. Once the first compliance scan completes, .* for each ATMO-MXDR-DIAG-TOSENT assignment create a remediation task'
        $text | Should -Match 'open each ATMO-MXDR-DIAG-TOSENT assignment created by this change and select Delete assignment'
        @(Get-Section $text 'C) ROLLBACK PLAN')[-1] | Should -Match '^3\. For the Subscription Activity Log, go to Monitor > Activity log > Export Activity Logs' -Because 'the Activity Log setting is not under a resource blade'
        $index | Should -Match 'CR-01 assigns the initiative where no ATMO-MXDR policy state was found\. An assignment made shortly before collection'
        $index | Should -Match '\| 10 \| Diagnostic logging remediated on non-compliant resources \|  \| Nothing to remediate until the initiative is assigned \(CR-01\) \|'
    }

    It 'assigns the initiative only at the subscriptions without it, one by one, when others already have it' {
        $pack = Join-Path $TestDrive 'coverage'
        New-ChangeFixture $pack
        Set-PackResult $pack 'DR.6-INITIATIVE' @(@{ DefinitionName = 'ATMO-MXDR-KV-TOSENT'; Resources = 4; Compliant = 4; NonCompliant = 0 })
        Set-PackResult $pack 'DR.6-COVERAGE' @(@{ subscriptionId = $s1; Resources = 4; Assignments = 1 })
        $null = & $generator -EvidencePath $pack -ManagementGroup 'mg-example'
        $text = Get-Content (Join-Path $pack '05-change-requests/CR-01-diagnostic-logging.txt') -Raw
        $text | Should -Match 'The initiative is assigned at the subscription below, which has no ATMO-MXDR policy state yet,'
        $text | Should -Match "Subscriptions:\r?\n- Example, Dev Test \($s2\)\r?\n\r?\n"
        $text | Should -Match '- Key vaults: 2\r?\n' -Because 'only the vaults of the subscription being assigned are counted, not the 4 in the covered one'
        $text | Should -Not -Match "\($s1\)" -Because 'the covered subscription already has the initiative'
        $text | Should -Not -Match 'management group mg-example' -Because 'an assignment at the group would overlap the existing one'
        $index = Get-Content (Join-Path $pack '05-change-requests/00-index.md') -Raw
        $index | Should -Match 'CR-01 assigns the initiative per subscription, not at the management group mg-example'
        # Coverage that names no subscription of the pack leaves every subscription to assign, at the group.
        Set-PackResult $pack 'DR.6-COVERAGE' @(@{ subscriptionId = 'ffffffff-0000-0000-0000-000000000000'; Resources = 4; Assignments = 1 })
        $null = & $generator -EvidencePath $pack -ManagementGroup 'mg-example'
        $text = Get-Content (Join-Path $pack '05-change-requests/CR-01-diagnostic-logging.txt') -Raw
        $text | Should -Match 'set Scope to the management group mg-example'
        Get-Content (Join-Path $pack '05-change-requests/00-index.md') -Raw | Should -Not -Match 'other subscriptions already have it'
        # A partial coverage list cannot tell a missing assignment from an unread one.
        Set-PackResult $pack 'DR.6-COVERAGE' @(@{ subscriptionId = $s1; Resources = 4; Assignments = 1 }) 'PARTIAL'
        $null = & $generator -EvidencePath $pack
        Test-Path (Join-Path $pack '05-change-requests/CR-01-diagnostic-logging.txt') | Should -BeFalse
        Get-Content (Join-Path $pack '05-change-requests/00-index.md') -Raw | Should -Match '\| 01 \| .* \| DR\.6-COVERAGE is partial, so subscriptions without the initiative cannot be told apart\. Recollect \|'
    }

    It 'assigns the initiative once at a named management group' {
        $pack = Join-Path $TestDrive 'mg'
        New-ChangeFixture $pack
        $null = & $generator -EvidencePath $pack -ManagementGroup 'mg-example'
        $text = Get-Content (Join-Path $pack '05-change-requests/CR-01-diagnostic-logging.txt') -Raw
        $text | Should -Match 'The initiative is assigned once at the management group mg-example'
        $text | Should -Match '3\. On the Basics tab, set Scope to the management group mg-example and name the assignment ATMO-MXDR-DIAG-TOSENT\.'
        $text | Should -Not -Match 'Repeat steps'
        $text | Should -Match 'for the ATMO-MXDR-DIAG-TOSENT assignment create a remediation task'
    }

    It 'leaves App Service sites without a recorded minimum out of CR-04 and rolls storage back to 1.0 where none was set' {
        $app = & $read 'CR-04-app-service-minimum-tls.txt'
        $app | Should -Not -Match 'app-blank' -Because 'App Service applies TLS 1.2 to an app without a minimum'
        $index | Should -Match '1 App Service app left out of CR-04 because Resource Graph returned no minimum TLS version, and App Service applies 1\.2 when none is set: app-blank\. Check it in the portal'
        $stg = & $read 'CR-03-storage-minimum-tls.txt'
        @(Get-Section $stg 'C) ROLLBACK PLAN')[-1] | Should -Match 'or to Version 1\.0 where it is recorded as not set, since an account without the setting accepts TLS 1\.0, and select Save\.$'
    }

    It 'sets minimum TLS 1.2 on Redis, Service Bus and Cosmos DB with no rollback, since each already refuses TLS 1.0 and 1.1' {
        $checks = @(
            @{ File = 'CR-11-redis-minimum-tls'; Resource = "Subscription: Example Production \($s1\)\r?\n- redis-sessions, resource group rg-app, minimum TLS 1\.0"
               Step = '2\. Go to Settings > Advanced settings\.\r?\n3\. Set Minimum TLS version to 1\.2 and select Save\.'; Rollback = 'Azure Cache for Redis has not allowed a minimum below 1\.2 since March 1, 2024\.'
               Reference = 'https://learn\.microsoft\.com/azure/azure-cache-for-redis/cache-remove-tls-10-11' }
            @{ File = 'CR-12-service-bus-minimum-tls'; Resource = "Subscription: Example Production \($s1\)\r?\n- sb-orders, resource group rg-msg, minimum TLS not set"
               Step = '2\. Go to Settings > Configuration\.\r?\n3\. Set Minimum TLS version to 1\.2 and select Save\.'; Rollback = 'a Service Bus namespace takes only 1\.2 or 1\.3 as its minimum TLS version\.'
               Reference = 'https://learn\.microsoft\.com/azure/service-bus-messaging/transport-layer-security-enforce-minimum-version' }
            @{ File = 'CR-14-cosmos-db-minimum-tls'; Resource = "Subscription: Example, Dev Test \($s2\)\r?\n- cosmos-catalog, resource group rg-data, minimum TLS 1\.0"
               Step = '2\. Go to Settings > Networking and select the Connectivity tab\.\r?\n3\. Set Minimum Transport Layer Security Protocol to TLS 1\.2 and select Save\.'; Rollback = 'Azure Cosmos DB accepts only TLS 1\.2 as the minimum for an account\.'
               Reference = 'https://learn\.microsoft\.com/azure/cosmos-db/self-serve-minimum-tls-enforcement' })
        foreach ($c in $checks) {
            $text = & $read "$($c.File).txt"
            $text | Should -Match $c.Resource -Because $c.File
            $text | Should -Match $c.Step -Because $c.File
            $text | Should -Not -Match 'Repeat steps' -Because "$($c.File) lists one resource"
            $text | Should -Not -Match 'evh-' -Because "$($c.File) reads only its own resource type"
            $rollback = @(Get-Section $text 'C) ROLLBACK PLAN')
            $rollback[0] | Should -Match ('^1\. No rollback is available or needed, because ' + $c.Rollback + '$') -Because $c.File
            $rollback[1] | Should -Match 'so every client that connected before the change can still connect\.$' -Because $c.File
            @(Get-Section $text 'A) REFERENCES')[0] | Should -Match $c.Reference -Because $c.File
            (& $read "$($c.File).email.txt") | Should -Match '\r?\n\r?\n[^\r\n]+, so this change cannot be reversed\. I do not expect a reversal to be needed, because ' -Because "$($c.File) says plainly that the change has no rollback, and why none is needed"
        }
        @(Get-Section (& $read 'CR-11-redis-minimum-tls.txt') 'B) PURPOSE')[0] | Should -Match '^Azure Cache for Redis has refused TLS 1\.0 and 1\.1 on every cache since April 1, 2025, but this cache still records an older minimum in its configuration\.'
        @(Get-Section (& $read 'CR-14-cosmos-db-minimum-tls.txt') 'B) PURPOSE')[0] | Should -Match '^Azure Cosmos DB retired TLS 1\.0 and 1\.1 on August 31, 2025, but this account does not record a minimum of 1\.2'
        $index | Should -Match '\| 11 \| Minimum TLS 1\.2 on Azure Cache for Redis \| 1 \| Change request and client email \| CR-11-redis-minimum-tls\.txt, CR-11-redis-minimum-tls\.email\.txt \|'
        $index | Should -Match '\| 14 \| Minimum TLS 1\.2 on Azure Cosmos DB accounts \| 1 \| Change request and client email \| CR-14-cosmos-db-minimum-tls\.txt, CR-14-cosmos-db-minimum-tls\.email\.txt \|'
    }

    It 'asks the client first for minimum TLS 1.2 on Event Hubs, which still documents namespaces that accept TLS 1.0 and 1.1, and keeps a rollback' {
        $text = & $read 'CR-13-event-hubs-minimum-tls.txt'
        $text | Should -Match "Subscription: Example Production \($s1\)\r?\n- evh-telemetry, resource group rg-msg, minimum TLS 1\.0\r?\n\r?\nSubscription: Example, Dev Test \($s2\)\r?\n- evh-audit, resource group rg-logs, minimum TLS 1\.1"
        $text | Should -Match 'Set the minimum TLS version to 1\.2 on the 2 Event Hubs namespaces listed below\.'
        $text | Should -Match '1\. In the Azure portal, go to Event Hubs and open the first namespace listed in the RESOURCES section\.'
        $text | Should -Match '4\. Repeat steps 1 to 3 for each remaining namespace listed\.'
        @(Get-Section $text 'C) DEPENDENCIES')[0] | Should -Be 'Clients limited to TLS 1.0 or 1.1 can no longer send or receive events once the change is applied.'
        $rollback = @(Get-Section $text 'C) ROLLBACK PLAN')
        $rollback[1] | Should -Match '^2\. Set Minimum TLS version back to the version recorded for the namespace in the RESOURCES section, or to 1\.0 where it is recorded as not set'
        $rollback[2] | Should -Match '^3\. If the portal no longer offers that version, Event Hubs has retired TLS 1\.0 and 1\.1 for every namespace'
        $index | Should -Match '\| 13 \| Minimum TLS 1\.2 on Event Hubs namespaces \| 2 \| Change request and client email \| CR-13-event-hubs-minimum-tls\.txt, CR-13-event-hubs-minimum-tls\.email\.txt \|'
        $email = & $read 'CR-13-event-hubs-minimum-tls.email.txt'
        $email | Should -Match '^Subject: Approval requested: minimum TLS 1\.2 for Azure Event Hubs namespaces\r?\n\r?\nHello Dana,'
        $email | Should -Match 'I would like your approval to set the minimum TLS version to 1\.2 on 2 of your Event Hubs namespaces\. TLS is the protocol that encrypts connections to a service'
        $email | Should -Match "Subscription Example Production \($s1\):\r?\n\r?\n- evh-telemetry \(resource group rg-msg, minimum TLS 1\.0\)\r?\n\r?\nSubscription Example, Dev Test \($s2\):\r?\n\r?\n- evh-audit \(resource group rg-logs, minimum TLS 1\.1\)"
        $email | Should -Match '\r?\n\r?\nCould you let me know whether anything that connects to these namespaces may still use TLS 1\.0 or 1\.1\? If nothing does, could you approve this change for \w+day, [^?]+\? Please reply by [^.]+\d{4}\. If something does, I will hold the change until it uses TLS 1\.2\.'
        $email | Should -Match 'Thank you,\r?\nScott Example\r?\n$'
    }

    It 'writes every client email as an approval request with the shared structure, the proposed date and the reply-by date' {
        $today = (Get-Date).ToUniversalTime().Date
        $proposed = $today.AddDays(14).ToString('dddd, MMMM d, yyyy', [cultureinfo]::InvariantCulture)
        $reply = $today.AddDays(7).ToString('dddd, MMMM d, yyyy', [cultureinfo]::InvariantCulture)
        $emailFiles.Count | Should -Be $crFiles.Count
        foreach ($f in $emailFiles) {
            $email = Get-Content $f.FullName -Raw
            Assert-ApprovalEmail $email $f.Name
            $email | Should -Match "\r?\n\r?\nHello Dana,\r?\n" -Because $f.Name
            $email | Should -Match "Please reply by $reply\. " -Because "$($f.Name) asks for a reply a week before the proposed date"
            $email | Should -Match "\r?\n\r?\n[^\r\n]+:\r?\n\r?\nSubscription Example[^\r\n]*\((5f1c2a9e|a0b1c2d3)[^\r\n]*\):\r?\n\r?\n- " -Because "$($f.Name) lists the resources by subscription"
        }
        $dated = 'CR-01-diagnostic-logging', 'CR-02-storage-secure-transfer', 'CR-03-storage-minimum-tls', 'CR-04-app-service-minimum-tls', 'CR-06-key-vault-purge-protection', 'CR-07-storage-anonymous-access', 'CR-08-app-service-https-only', 'CR-11-redis-minimum-tls', 'CR-12-service-bus-minimum-tls', 'CR-13-event-hubs-minimum-tls', 'CR-14-cosmos-db-minimum-tls', 'CR-16-management-ports'
        foreach ($k in $dated) {
            $email = & $read "$k.email.txt"
            $email | Should -Match "\r?\n\r?\n[^\r\n]*approve [^?]*$proposed\? Please reply by $reply\. [^\r\n]*I will not schedule this change until I have your approval\.\r?\n\r?\nThank you,\r?\nScott Example\r?\n$" -Because "$k asks for approval of the proposed date"
            $email | Should -Not -Match 'maintenance window' -Because "$k needs no restart"
        }
        foreach ($k in 'CR-09-encryption-at-host', 'CR-15-scale-set-encryption-at-host') {
            $email = & $read "$k.email.txt"
            $email | Should -Match "\r?\n\r?\nCould you approve this change and suggest a maintenance window that works for these (servers|scale sets)\? Please reply by $reply\. " -Because "$k restarts machines, so it asks for a maintenance window"
            $email | Should -Not -Match $proposed -Because "$k leaves the date to the maintenance window"
        }
        $index | Should -Match ('- CR-01, CR-02, CR-03, CR-04, CR-06, CR-07, CR-08, CR-11, CR-12, CR-13, CR-14, CR-16 ask the client to approve the proposed date, {0}, and CR-09, CR-15 ask the client to approve the change and suggest a maintenance window\. Every email asks for a reply by {1}\. Run again with -ChangeDate to propose another day' -f $proposed, $reply)
        $index | Should -Match "Every client email asks for the client's approval, and no change is scheduled until the client approves it\."
        $index | Should -Not -Match '(?i)notice|concern'
    }

    It 'writes every email as a letter, with no titles and each paragraph opening in its own words, and the check refuses anything else' {
        $email = & $read 'CR-03-storage-minimum-tls.email.txt'
        Assert-ApprovalEmail $email 'CR-03'
        foreach ($f in $emailFiles) {
            $lines = @((Get-Content $f.FullName -Raw) -split "`r?`n")
            foreach ($t in $oldEmailTitles) { $lines | Should -Not -Contain $t -Because "$($f.Name) has no titles" }
        }
        $nl = if ($email -match "`r`n") { "`r`n" } else { "`n" }
        $titled = $email -replace '(Hello Dana,\r?\n\r?\n)', ('$1What I am asking to change' + $nl)
        { Assert-ApprovalEmail $titled 'titled' } | Should -Throw -Because 'an old title line is refused'
        $heading = $email -replace '(\r?\n\r?\nI recommend )', ($nl + $nl + 'A short heading' + $nl + 'I recommend ')
        { Assert-ApprovalEmail $heading 'heading' } | Should -Throw -Because 'a short line standing alone as a heading is refused'
        $noBecause = $email -replace 'I recommend setting this minimum because ', 'I recommend setting this minimum. '
        { Assert-ApprovalEmail $noBecause 'no because' } | Should -Throw -Because 'why is a because sentence'
        $repeated = $email -replace 'I do not expect any visible effect', 'I recommend setting this minimum because there is no visible effect'
        { Assert-ApprovalEmail $repeated 'repeated' } | Should -Throw -Because 'no two paragraphs open with the same words'
        $outOfOrder = $email -replace '(\r?\n\r?\n)(I do not expect any visible effect[^\r\n]*)(\r?\n\r?\n)(The accounts are listed below[^\r\n]*:)', '$1$4$3$2'
        $outOfOrder | Should -Not -Be $email
        { Assert-ApprovalEmail $outOfOrder 'out of order' } | Should -Throw -Because 'what it means for the client comes before the resources'
    }

    It 'says in each email what changes, why, what it means for the client and how it can be reversed' {
        $email = & $read 'CR-02-storage-secure-transfer.email.txt'
        $email | Should -Match 'I would like your approval to turn on Secure transfer required on 2 of your storage accounts, so they accept encrypted connections only\.'
        $email | Should -Match 'I recommend requiring secure transfer because requests over plain HTTP and SMB connections without encryption expose data and credentials in transit'
        $email | Should -Match "The accounts are listed below by subscription:\r?\n\r?\nSubscription Example Production \($s1\):\r?\n\r?\n- stdata \(resource group rg-data\)\r?\n- stweb \(resource group rg-web\)\r?\n"
        $email | Should -Match 'Azure Storage rejects any request made over HTTP and any SMB connection without encryption, such as SMB 2\.1, so a system that still connects to these accounts that way would stop working'
        $email | Should -Match '\r?\n\r?\nSecure transfer required can be turned off again on any account'
        $email | Should -Not -Match 'stnfsblob|stpremfiles' -Because 'the accounts left out of the change are not in its email'
        $email = & $read 'CR-03-storage-minimum-tls.email.txt'
        $email | Should -Match 'Azure Storage stopped accepting them on February 3, 2026, but these accounts still allow an older version in their configuration'
        $email | Should -Match '- stdata \(resource group rg-data, minimum TLS 1\.0\)\r?\n- stweb \(resource group rg-web, minimum TLS not set\)'
        $email | Should -Match 'I do not expect any visible effect, because Azure Storage already refuses TLS 1\.0 and 1\.1, so every connection that works today keeps working\.'
        $email | Should -Match 'TLS is the protocol that encrypts connections to a service' -Because 'the technical term is explained once in plain language'
        $email = & $read 'CR-04-app-service-minimum-tls.email.txt'
        $email | Should -Match 'I would like your approval to set the minimum inbound TLS version to 1\.2 on one of your App Service and Function applications\.'
        $email | Should -Match 'I recommend setting this minimum now because TLS 1\.0 and 1\.1 have known weaknesses, and App Service stops accepting them on May 31, 2027'
        $email | Should -Match 'The application is listed below with its minimum TLS version today:'
        $email | Should -Match 'A client that can only use TLS 1\.0 or 1\.1, for example one on an old operating system or runtime, will no longer be able to connect to the application once the change is applied\.'
        $email | Should -Match 'The minimum TLS version can be set back to the version the application has today'
        $email | Should -Not -Match 'app-blank'
        (& $read 'CR-11-redis-minimum-tls.email.txt') | Should -Match 'Azure Cache for Redis has refused them on every cache since April 1, 2025, but this cache still records an older minimum'
        (& $read 'CR-12-service-bus-minimum-tls.email.txt') | Should -Match '- sb-orders \(resource group rg-msg, minimum TLS not set\)'
        (& $read 'CR-14-cosmos-db-minimum-tls.email.txt') | Should -Match "Subscription Example, Dev Test \($s2\):\r?\n\r?\n- cosmos-catalog \(resource group rg-data, minimum TLS 1\.0\)"
    }

    It 'tells the client that diagnostic logging adds Log Analytics ingestion to their Sentinel workspace' {
        $email = & $read 'CR-01-diagnostic-logging.email.txt'
        $email | Should -Match '^Subject: Approval requested: diagnostic logging for Azure resources\r?\n'
        $email | Should -Match 'I would like your approval to turn on diagnostic logging for your Azure resources by assigning the ATMO-MXDR-DIAG-TOSENT Azure Policy initiative on each subscription below\. An Azure Policy initiative is a set of rules that Azure keeps applied, and this one adds diagnostic settings that send the audit logs of the supported resources to your Sentinel workspace law-example-sentinel, including resources created later\.'
        $email | Should -Match 'I recommend turning on this logging because, without these audit logs, the SOC cannot detect or investigate activity on these resources'
        $email | Should -Match "Each subscription is listed below with the resources the initiative covers and how many each holds today:\r?\n\r?\nSubscription Example Production \($s1\):\r?\n\r?\n- Key vaults: 4\r?\n- Subscription Activity Log\r?\n\r?\nSubscription Example, Dev Test \($s2\):\r?\n\r?\n- Key vaults: 2\r?\n- Subscription Activity Log\r?\n" -Because 'each subscription is counted on its own'
        $email | Should -Match 'I do not expect any visible effect on these resources or the people who use them\. A diagnostic setting only sends the logs a resource already produces to the workspace, and does not change how the resource runs\.'
        $email | Should -Match 'This change adds Log Analytics ingestion to your Sentinel workspace law-example-sentinel\. The resource logs are billed as data ingested into the workspace, and their volume depends on how busy each resource is\. The Azure Activity log of each subscription is ingested at no charge\.'
    }

    It 'closes the management port rules on workload subnets and network interfaces, with every property recorded for the rollback' {
        $text = & $read 'CR-16-management-ports.txt'
        $text | Should -Match '^Title: Close internet-facing RDP, SSH and WinRM rules on network security groups\r?\n'
        @(Get-Section $text 'A) CHANGE DESCRIPTION')[0] | Should -Be 'Remove the 2 inbound security rules listed below that allow RDP, SSH or WinRM from any internet address, or narrow each to named source addresses, and give administrators just-in-time VM access or Azure Bastion in their place.'
        $text | Should -Match "Subscription: Example Production \($s1\)\r?\n- nsg-web/Allow-RDP, resource group rg-web, priority 300, allow inbound, protocol TCP, source Internet, source ports \*, destination \*, destination ports 3389, applies to subnet snet-web of virtual network vnet-app\r?\n"
        $text | Should -Match '- nsg-jump/Allow-SSH-HTTPS, resource group rg-ops, priority 310, allow inbound, protocol TCP, source \*, source ports \*, destination \*, destination ports \(22, 443\), description "Jump box access, vendor", applies to network interface nic-jump01 of virtual machine vm-jump01\r?\n' -Because 'the empty single form of a list property is dropped, and a semicolon in the description is cleaned'
        $text | Should -Match "Defender for Servers Plan 2, which just-in-time VM access needs \(P0\.3\):\r?\n- Example Production \($s1\): on, so just-in-time VM access is the path\r?\n- Example, Dev Test \($s2\): not on, so Azure Bastion is the path unless the client turns Plan 2 on" -Because 'P0.3 reads Plan 2 only where the VirtualMachines plan has sub-plan P2'
        foreach ($left in 'nsg-fw-untrust', 'nsg-hub-untrust', 'nsg-old', 'Allow-HighPorts', 'Allow-Any') { $text | Should -Not -Match $left -Because "$left is left to the index notes" }
        $impl = @(Get-Section $text 'A) IMPLEMENTATION PLAN')
        $impl[0] | Should -Match '^1\. Where the client agreed just-in-time VM access, in the Azure portal go to Microsoft Defender for Cloud > Workload protections > Just-in-time VM access, select the Not configured tab, .*select Enable JIT on VMs, keep the ports it proposes and select Save\. The rules listed keep priority over its deny rules until they are removed below\.$' -Because 'the replacement path is in place before a rule is removed'
        $impl[1] | Should -Match '^2\. Where the client agreed Azure Bastion, go to the virtual network of the machines behind each rule and select Connect > Bastion\.'
        $impl[2] | Should -Be '3. Where Azure Bastion is the path, open each network security group on the subnet or network interface of the machines behind each rule and go to Settings > Inbound security rules. Unless a rule already allows ports 22 and 3389 from the AzureBastionSubnet address range ahead of every deny rule for those ports, select + Add and add one with Source set to IP Addresses and that range, at a lower priority number than those deny rules. Then open a Bastion session to one machine behind each rule from its Connect > Bastion page, and if it does not open, stop here and leave every rule listed unchanged.' -Because 'a deny rule behind the public allow would otherwise block Bastion too once the allow goes'
        $impl | Should -Contain '6. If the source of the rule is Any, 0.0.0.0/0 or ::/0, which also matches private addresses, select + Add and add an allow rule with the protocol and destination of the rule, Destination port ranges set to the management ports it lists, Source set to IP Addresses with the private ranges the client confirmed, the address spaces of the virtual networks, peered virtual networks and on-premises networks that connect to the machines, and a free priority number lower than any deny rule for those ports, then select Add. Enter each range as a CIDR block, never a service tag, Any, 0.0.0.0/0 or ::/0, and check that each is a private range or one the client owns. Leave this rule out only where the client confirmed nothing connects from those networks. If the client has confirmed neither the ranges nor that nothing connects, leave the rule unchanged and note it in the change record.' -Because 'nsg-jump allows any address, which includes private networks a deny rule behind it would cut off, and a service tag for the virtual network can hold 0.0.0.0/0'
        $impl | Should -Contain '7. If the client named source addresses that still need direct access and the rule allows only ports 22, 3389, 5985 or 5986, select the rule, set Source to IP Addresses, enter those addresses in Source IP addresses/CIDR ranges and select Save.'
        $impl | Should -Contain '8. If the client named such addresses and the rule also allows other ports, select + Add and add an allow rule with the protocol and destination of the rule, Destination port ranges set to the management ports it lists, Source set to IP Addresses with those addresses, and a free priority number lower than any deny rule for those ports, including one just-in-time VM access added, then select Add. Have the client confirm a connection from one of those addresses before going on. Then select the original rule, remove 22, 3389, 5985 and 5986 from Destination port ranges and select Save, so its other ports keep the source they have.' -Because 'narrowing the whole rule would narrow 443 too'
        $impl | Should -Contain '9. If the client named no addresses, select the rule. If it allows only ports 22, 3389, 5985 or 5986, select Delete and then Yes. If it also allows other ports, remove 22, 3389, 5985 and 5986 from Destination port ranges and select Save.'
        $impl | Should -Contain '10. Repeat steps 4 to 9 for each remaining rule listed.'
        $impl[-1] | Should -Match '^11\. For each network interface the rules applied to, directly or through its subnet, go to Virtual machines, open the machine it belongs to, select Networking, select the network interface and select Effective security rules under Help\. .* If any lists 0\.0\.0\.0/0 or ::/0, or prefixes that together span the internet such as 0\.0\.0\.0/1 and 128\.0\.0\.0/1, the ports are still open to the internet\. Then open the network security group of that network interface or its subnet, select \+ Add and add a deny rule with protocol Any, Source set to Service Tag and Internet, Destination port ranges set to 22, 3389, 5985 and 5986, and a free priority number lower than that allow rule and higher than every other allow rule for those ports' -Because 'another allow, such as the default rule for the virtual network behind a 0.0.0.0/0 route, can still let the internet in'
        $impl | Should -Contain '5. Go to Settings > Inbound security rules and find the rule. If its priority, access, direction, protocol, source, ports or destination no longer read as listed, or the group is no longer attached to what is listed, leave it unchanged and note it in the change record for the next pack.' -Because 'a rule changed since collection, such as TCP 22 turned into UDP 22, is no longer the one checked'
        (Get-Section $text 'B) TESTING PLAN') -join "`n" | Should -Match 'Any rule added for the private ranges allows only the management ports, from the ranges the client confirmed\.'
        (Get-Section $text 'B) TESTING PLAN') -join "`n" | Should -Match 'select Networking, select the network interface and select Effective security rules under Help\. .* confirm none of its source prefixes is 0\.0\.0\.0/0 or ::/0, that its prefixes do not together span the internet, and that any other public address is one the client named or already allowed, apart from the Azure platform address 168\.63\.129\.16, so no internet source reaches those ports\.' -Because 'the listed rules alone do not show what the effective rules still let in'
        $text | Should -Not -Match 'VirtualNetwork' -Because 'the service tag for the virtual network can hold 0.0.0.0/0 behind a user-defined route'
        (Get-Section $text 'B) TESTING PLAN') -join "`n" | Should -Match 'no other rule allows those ports over TCP from Any, Internet, 0\.0\.0\.0/0 or ::/0'
        $rollback = @(Get-Section $text 'C) ROLLBACK PLAN')
        $rollback[1] | Should -Match 'For a rule that was deleted, select \+ Add, enter the name, priority, source, source port ranges, destination, destination port ranges, protocol, action Allow and description recorded for it in the RESOURCES section and in change-requests\.csv'
        $rollback | Should -Contain '4. Delete the rules this change added: any for the named addresses or the private ranges, any deny on the management ports from the Internet service tag, and the rule for the AzureBastionSubnet address range if Azure Bastion is no longer wanted.'
        $rollback[-1] | Should -Match 'If just-in-time VM access added a deny rule for the same ports at a lower priority number than the restored rule, give the restored rule a priority number below it'
        @(Get-Section $text 'E) MITIGATION') -join '|' | Should -Be 'If changes need to be reverted, follow the rollback plan.'
        $index | Should -Match '\| 16 \| Internet-facing RDP, SSH and WinRM rules closed \| 2 \| Change request and client email \| CR-16-management-ports\.txt, CR-16-management-ports\.email\.txt \|'
    }

    It 'leaves appliance untrust interfaces, unattached groups and * or port range rules out of CR-16 with an index note each' {
        $index | Should -Match '- 1 rule left out of CR-16 as a cleanup item because its network security group is attached to no subnet or network interface, so it exposes nothing today: Allow-WinRM in nsg-old \(resource group rg-old\)\. Delete the rule, or the group if it is unused, with the client, since attaching the group later would open the port to the internet\.'
        $index | Should -Match '- 1 rule left out of CR-16 because its network security group is attached only to network interfaces of network virtual appliances \(P0\.6-APPLIANCES\), where an untrust interface takes internet traffic by design: Allow-Mgmt in nsg-fw-untrust \(resource group rg-fw\)\.'
        $index | Should -Match '- 2 rules left out of CR-16 for review because their destination ports include \* or a port range, which may not mean a management port is meant to be open: Allow-HighPorts in nsg-app \(resource group rg-app\), ports 3000-4000 / Allow-Any in nsg-app \(resource group rg-app\), ports \*\. Review each with the client and narrow it to the ports it needs\.'
        $index | Should -Match '- 1 rule left out of CR-16 for review because its network security group reaches a network virtual appliance through a subnet it sits in, or through its network interface as well as other resources, so changing the rule would change the appliance too: Allow-SSH-Untrust in nsg-hub-untrust \(resource group rg-net\)\.' -Because 'the firewall interface has no group of its own, so the subnet group is its group'
        $index | Should -Not -Match 'CR-16 was written without' -Because 'P0.3 was read'
    }

    It 'asks for approval to close the management ports, who still needs them and which replacement path to use' {
        $email = & $read 'CR-16-management-ports.email.txt'
        Assert-ApprovalEmail $email 'CR-16'
        $email | Should -Match '^Subject: Approval requested: closing remote management ports to the internet\r?\n'
        $email | Should -Match 'I would like your approval to close the 2 network security group rules that let anyone on the internet reach RDP, SSH or WinRM, the remote management ports, on your Azure virtual machines\. In their place, administrators would connect through just-in-time VM access or Azure Bastion\.'
        $email | Should -Match 'A connection that is already open stays up, because a rule change applies only to new connections\.'
        $email | Should -Match 'Where a rule also allows other ports, only 22, 3389, 5985 and 5986 are removed from it, and its other ports stay as they are\.' -Because 'nsg-jump also allows 443'
        $email | Should -Match 'Connections from your own networks, such as a VPN, a peered virtual network or an office linked to Azure over a private connection, can keep working\. One of the rules is open to every address, which includes those networks, so I will keep that private access in a rule of its own, built only from the address ranges of those networks that you confirm, unless you tell me nobody uses it\.' -Because 'nsg-jump allows any address'
        $email | Should -Match "- Just-in-time VM access keeps the ports closed .* It is part of Microsoft Defender for Servers Plan 2\. Plan 2 is on in subscription Example Production \($s1\), and not on in subscription Example, Dev Test \($s2\), where this path would add the cost of Plan 2 for the servers\.\r?\n- Azure Bastion lets administrators connect from the Azure portal over an encrypted connection on port 443"
        $email | Should -Match 'It is billed by the hour from the moment it is deployed in a virtual network, and its free Developer tier is meant for development and test only\.'
        $email | Should -Match 'I suggest just-in-time VM access where Plan 2 is on and Azure Bastion elsewhere'
        $email | Should -Match "Subscription Example Production \($s1\):\r?\n\r?\n- Allow-RDP in network security group nsg-web \(resource group rg-web, priority 300, TCP port 3389 from Internet, on subnet snet-web of virtual network vnet-app\)\r?\n\r?\nSubscription Example, Dev Test \($s2\):\r?\n\r?\n- Allow-SSH-HTTPS in network security group nsg-jump \(resource group rg-ops, priority 310, TCP ports 22 and 443 from any address, on network interface nic-jump01 of virtual machine vm-jump01\)"
        $email | Should -Match '\r?\n\r?\nIf anything unexpected comes up, I can recreate any of the rules exactly as they are today, since every setting of each rule is recorded\.'
        $email | Should -Match '\r?\n\r?\nCould you tell me who still needs RDP, SSH or WinRM to these machines from the internet, and from which addresses, and which replacement you would like, just-in-time VM access or Azure Bastion\? Could you also send me the address ranges of the virtual networks, peered networks and on-premises networks that connect to these machines, or tell me that nothing connects from them\? With that agreed, could you approve this change for \w+day, [^?]+\? Please reply by '
        $email | Should -Not -Match 'VirtualNetwork|cannot replace WinRM' -Because 'no rule listed opens WinRM'
        $email | Should -Match 'Where someone still needs direct access, I can keep the management ports open to their named addresses only, and any other port a rule allows keeps the access it has today\.'
        foreach ($left in 'nsg-fw-untrust', 'nsg-hub-untrust', 'nsg-old', 'Allow-HighPorts', 'Allow-Any') { $email | Should -Not -Match $left -Because "$left is not in the change" }
    }

    It 'lists one row per resource in the CSV' {
        @($csv | Where-Object CR -eq 'CR-06').Resource | Should -Be @('kv-app', 'kv-dev')
        ($csv | Where-Object { $_.CR -eq 'CR-04' }).CurrentSetting | Should -Be 'minimum TLS 1.0'
        ($csv | Where-Object { $_.CR -eq 'CR-14' }).CurrentSetting | Should -Be 'minimum TLS 1.0' -Because 'Cosmos DB writes TLS 1.0 as Tls'
        ($csv | Where-Object { $_.CR -eq 'CR-12' }).ResourceId | Should -Be "/subscriptions/$s1/resourceGroups/rg-msg/providers/Microsoft.ServiceBus/namespaces/sb-orders"
        @($csv | Where-Object CR -eq 'CR-13').Resource | Should -Be @('evh-telemetry', 'evh-audit')
        @($csv | Where-Object CR -eq 'CR-01').Count | Should -Be 2
        ($csv | Where-Object { $_.CR -eq 'CR-09' -and $_.Resource -eq 'vm-old' }).ResourceId | Should -Be "/subscriptions/$s2/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-old"
        $mgmt = @($csv | Where-Object CR -eq 'CR-16')
        @($mgmt.Resource) | Should -Be @('nsg-web/Allow-RDP', 'nsg-jump/Allow-SSH-HTTPS')
        ($mgmt | Where-Object Resource -eq 'nsg-web/Allow-RDP').ResourceId | Should -Be "/subscriptions/$s1/resourceGroups/rg-web/providers/Microsoft.Network/networkSecurityGroups/nsg-web/securityRules/Allow-RDP" -Because 'the CSV names the rule by its resource ID'
        ($mgmt | Where-Object Resource -eq 'nsg-jump/Allow-SSH-HTTPS').CurrentSetting | Should -Be 'priority 310, allow inbound, protocol TCP, source *, source ports *, destination *, destination ports (22, 443), description "Jump box access, vendor", applies to network interface nic-jump01 of virtual machine vm-jump01' -Because 'the CSV carries every property the rollback needs, cleaned to the copy rules like every file'
        @($csv | Where-Object { -not $_.ResourceId }).Count | Should -Be 0 -Because 'every tracking row carries the resource ID'
    }
}

Describe 'Change request variants' {
    It 'still asks for approval of purge protection when the client approved it at build kickoff, and records the approval' {
        $pack = Join-Path $TestDrive 'approved'
        New-ChangeFixture $pack
        $out = Join-Path $pack '05-change-requests'
        $null = & $generator -EvidencePath $pack
        $before = Get-Content (Join-Path $out 'CR-06-key-vault-purge-protection.email.txt') -Raw
        $before | Should -Not -Match 'build kickoff'
        $files = @(& $generator -EvidencePath $pack -PurgeProtectionApproved -ClientContact 'Dana')
        @($files | Where-Object { $_ -like '*CR-06*' } | ForEach-Object { Split-Path -Leaf $_ }) | Should -Be @('CR-06-key-vault-purge-protection.txt', 'CR-06-key-vault-purge-protection.email.txt')
        $email = Get-Content (Join-Path $out 'CR-06-key-vault-purge-protection.email.txt') -Raw
        Assert-ApprovalEmail $email 'CR-06 with -PurgeProtectionApproved'
        $email | Should -Match '^Subject: Approval requested: purge protection for Azure key vaults\r?\n\r?\nHello Dana,' -Because 'the approval given at kickoff is confirmed, not assumed'
        $email | Should -Match 'I would like your approval to turn on purge protection for 2 of your Azure key vaults\.'
        $email | Should -Match "Subscription Example Production \($s1\):\r?\n\r?\n- kv-app \(resource group rg-app, soft delete retention 90 days\)\r?\n\r?\nSubscription Example, Dev Test \($s2\):\r?\n\r?\n- kv-dev \(resource group rg-dev, soft delete retention 7 days\)"
        $email | Should -Match 'Nothing changes for the applications and people that read or write these vaults today\.'
        $email | Should -Match 'This change cannot be undone\. Purge protection cannot be turned off once it is enabled, by anyone including Microsoft'
        $email | Should -Match 'A deleted vault keeps its name until then, so the name cannot be reused'
        $email | Should -Match '\r?\n\r?\nYou approved purge protection at the build kickoff\. Because this change cannot be undone, could you confirm that your approval still stands for these vaults, and approve the change for \w+day, [^?]+\? Please reply by '
        $email | Should -Not -Match 'I need your written approval' -Because 'the written approval was given at kickoff'
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '\| 06 \| Purge protection on key vaults \| 2 \| Change request and client email \| CR-06-key-vault-purge-protection\.txt, CR-06-key-vault-purge-protection\.email\.txt \|'
        $index | Should -Match '- CR-06 refers to the purge protection approval the client gave at build kickoff \(-PurgeProtectionApproved\), and asks the client to confirm that it still stands and to approve the proposed date\. Attach that approval and the reply to the change request\.'
        $index | Should -Match 'CR-01, CR-02, CR-03, CR-04, CR-06, CR-07, CR-08, CR-11, CR-12, CR-13, CR-14, CR-16 ask the client to approve the proposed date'
        $kv = Get-Content (Join-Path $out 'CR-06-key-vault-purge-protection.txt') -Raw
        @(Get-Section $kv 'E) MITIGATION')[0] | Should -Match '^Purge protection cannot be disabled once it is enabled, so this change cannot be reverted\.'
        Get-Content (Join-Path $out 'CR-07-storage-anonymous-access.email.txt') -Raw | Should -Not -Match 'build kickoff' -Because 'the switch covers purge protection only'
    }

    It 'keeps the email structure check to the authored sentences, so a management group name with a full stop does not stop the run' {
        $pack = Join-Path $TestDrive 'group-name'
        New-ChangeFixture $pack
        $null = & $generator -EvidencePath $pack -ManagementGroup 'Contoso Inc. Production'
        $email = Get-Content (Join-Path $pack '05-change-requests/CR-01-diagnostic-logging.email.txt') -Raw
        Assert-ApprovalEmail $email 'CR-01 at a management group'
        $email | Should -Match 'initiative once at the management group Contoso Inc\. Production, which holds the subscriptions below\. An Azure Policy initiative is a set of rules'
    }

    It 'writes a client email for every change request, CR-01 to CR-16' {
        # The full fixture writes every change but CR-05 and CR-10. This pack adds an Azure SQL server and a
        # resource the diagnostic logging initiative reports as not compliant, so between them every change is
        # written at least once. A change request written without its email, or with an email that does not
        # ask for approval in the shared structure, fails here, so a new change request is held to it too.
        $full = Join-Path $TestDrive 'every-full'
        New-ChangeFixture $full
        $null = & $generator -EvidencePath $full
        $more = Join-Path $TestDrive 'every-more'
        New-ChangeFixture $more
        Set-PackResult $more 'NB.6-DETAIL' @(@{ Name = 'sql-orders'; ResourceId = "/subscriptions/$s1/resourceGroups/rg-data/providers/Microsoft.Sql/servers/sql-orders"; resourceGroup = 'rg-data'; subscriptionId = $s1; MinimalTlsVersion = 'None' })
        Set-PackResult $more 'DR.6-INITIATIVE' @(@{ DefinitionName = 'ATMO-MXDR-KV-TOSENT'; Resources = 6; Compliant = 5; NonCompliant = 1 })
        Set-PackResult $more 'DR.6-COVERAGE' @(@{ subscriptionId = $s1; Resources = 5; Assignments = 1 })
        Set-PackResult $more 'DR.6-NONCOMPLIANT' @(@{ ResourceId = "/subscriptions/$s1/resourcegroups/rg-app/providers/microsoft.keyvault/vaults/kv-app"; ResourceType = 'microsoft.keyvault/vaults'; AssignmentName = 'ATMO-MXDR-DIAG-TOSENT'; AssignmentId = "/subscriptions/$s1/providers/microsoft.authorization/policyassignments/a1"; Policies = 'ATMO-MXDR-KV-TOSENT' })
        $null = & $generator -EvidencePath $more -PurgeProtectionApproved
        $written = @()
        foreach ($pack in $full, $more) {
            $out = Join-Path $pack '05-change-requests'
            $index = Get-Content (Join-Path $out '00-index.md') -Raw
            foreach ($cr in @(Get-ChildItem $out -Filter 'CR-*.txt' | Where-Object Name -notlike '*.email.txt')) {
                $number = $cr.Name.Substring(3, 2)
                $written += [int]$number
                $email = Join-Path $out ($cr.BaseName + '.email.txt')
                Test-Path $email | Should -BeTrue -Because "$($cr.Name) is written with a client email"
                $text = Get-Content $email -Raw
                Assert-ApprovalEmail $text $cr.Name
                $index | Should -Match ('\| {0} \| [^|]+ \| \d+ \| Change request and client email(, partial collection scope)? \| {1}, {2} \|' -f $number, [regex]::Escape($cr.Name), [regex]::Escape($cr.BaseName + '.email.txt')) -Because $cr.Name
            }
            $index | Should -Not -Match '\| Change request \|' -Because 'no change request is listed without its email'
        }
        @($written | Sort-Object -Unique) | Should -Be @(1..16) -Because 'the two packs between them write every change request'
        $sql = Get-Content (Join-Path $more '05-change-requests/CR-05-sql-minimum-tls.email.txt') -Raw
        $sql | Should -Match '^Subject: Approval requested: minimum TLS 1\.2 for Azure SQL servers'
        $sql | Should -Match 'Azure SQL retired them on August 31, 2025, but this server does not enforce a minimum of 1\.2'
        $sql | Should -Match "Subscription Example Production \($s1\):\r?\n\r?\n- sql-orders \(resource group rg-data, minimum TLS not set\)"
        $sql | Should -Match '\r?\n\r?\nOnce a minimum is set, Azure SQL does not allow a return to the unset default or a minimum below 1\.2, so this change cannot be reversed\.'
    }

    It 'proposes the day -ChangeDate names, asks for a reply a week before it, and refuses a day that leaves the client less than a week' {
        $pack = Join-Path $TestDrive 'change-date'
        New-ChangeFixture $pack
        $day = (Get-Date).ToUniversalTime().Date.AddDays(30)
        $proposed = $day.ToString('dddd, MMMM d, yyyy', [cultureinfo]::InvariantCulture)
        $reply = $day.AddDays(-7).ToString('dddd, MMMM d, yyyy', [cultureinfo]::InvariantCulture)
        $null = & $generator -EvidencePath $pack -ChangeDate $day
        $out = Join-Path $pack '05-change-requests'
        foreach ($f in Get-ChildItem $out -Filter '*.email.txt') {
            $text = Get-Content $f.FullName -Raw
            Assert-ApprovalEmail $text "$($f.Name) with -ChangeDate"
            $text | Should -Match "Please reply by $reply\. " -Because $f.Name
        }
        $email = Get-Content (Join-Path $out 'CR-03-storage-minimum-tls.email.txt') -Raw
        $email | Should -Match "Could you approve this change for $proposed\? Please reply by $reply\."
        Get-Content (Join-Path $out 'CR-09-encryption-at-host.email.txt') -Raw | Should -Not -Match $proposed -Because 'a change that needs a maintenance window has no proposed date'
        (Get-Content (Join-Path $out '00-index.md') -Raw) | Should -Match "approve the proposed date, $proposed, .* Every email asks for a reply by $reply\."
        { & $generator -EvidencePath $pack -ChangeDate (Get-Date).ToUniversalTime().Date.AddDays(7) } | Should -Throw '*less than a week to reply to the approval requests*'
        Get-Content (Join-Path $out 'CR-03-storage-minimum-tls.email.txt') -Raw | Should -Be $email -Because 'a refused run leaves the earlier files as they were'
    }

    It 'writes the DR Playbook step for encryption at host on a DR client' {
        $pack = Join-Path $TestDrive 'dr'
        New-ChangeFixture $pack
        $null = & $generator -EvidencePath $pack -DrClient
        $text = Get-Content (Join-Path $pack '05-change-requests/CR-09-encryption-at-host.txt') -Raw
        @(Get-Section $text 'D) DR Impact')[0] | Should -Match '^This is a DR client\. Azure Site Recovery does not carry encryption at host'
        @(Get-Section $text 'D) DR PLAN')[0] | Should -Match '^1\. In the DR Playbook, add a post-failover step'
        @(Get-Section $text 'D) DR PLAN')[1] | Should -Match 'starts it again only if it was running before the stop\.$' -Because 'a failover machine that was stopped stays stopped'
        $text | Should -Match 'azure-to-azure-support-matrix'
        $other = Get-Content (Join-Path $pack '05-change-requests/CR-02-storage-secure-transfer.txt') -Raw
        (Get-Section $other 'D) DR Impact') -join '|' | Should -Be 'N/A - No DR impact'
        (Get-Section $other 'D) DR PLAN') -join '|' | Should -Be 'No updates to the DR Playbook are required.'
        Get-Content (Join-Path $pack '05-change-requests/00-index.md') -Raw | Should -Not -Match 'Run again with -DrClient'
    }

    It 'writes singular scale set wording, the Automatic policy warning and the DR Playbook step for Flexible instances' {
        $pack = Join-Path $TestDrive 'scale-set-single'
        New-ChangeFixture $pack
        $id = "/subscriptions/$s1/resourceGroups/rg-web/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-auto"
        Set-PackResult $pack 'DP.4-VMSS-ELIGIBILITY' @(@{ Name = 'vmss-auto'; ResourceId = $id; resourceGroup = 'rg-web'; subscriptionId = $s1; OrchestrationMode = 'Uniform'; UpgradePolicy = 'Automatic'; Instances = 1; Size = 'Standard_D4s_v5'; UniqueId = (Get-TestId 'vmss-auto'); HasModel = $true; Aks = $false; Eligible = $true; Reason = '' })
        $null = & $generator -EvidencePath $pack -DrClient
        $out = Join-Path $pack '05-change-requests'
        $text = Get-Content (Join-Path $out 'CR-15-scale-set-encryption-at-host.txt') -Raw
        $text | Should -Match 'on the model and the existing instances of the virtual machine scale set listed below'
        $text | Should -Match 'The scale set below is listed with its orchestration mode'
        $impl = @(Get-Section $text 'A) IMPLEMENTATION PLAN')
        $impl | Should -Contain '3. In the Azure portal, go to Virtual machine scale sets, open the scale set listed in the RESOURCES section, select JSON View on Overview and confirm properties.uniqueId reads the unique ID listed for it. A scale set that reads another ID was created again under the same name after collection and was never checked, so leave it out of every step below, which leaves it for the next pack.'
        $impl | Should -Contain '5. In the Azure portal, go to Virtual machine scale sets, open the Uniform scale set listed in the RESOURCES section and go to Settings > Instances.'
        $impl[-1] | Should -Be '9. Repeat steps 6 to 8 for each remaining instance.'
        ($impl -join "`n") | Should -Not -Match 'Flexible'
        @(Get-Section $text 'A) AVAILABILITY/PERFORMANCE')[0] | Should -Match 'a scale set with an Automatic upgrade policy may take all its instances down at once to apply the model\.$'
        (Get-Section $text 'D) DR Impact') -join '|' | Should -Be 'N/A - No DR impact' -Because 'Azure Site Recovery does not replicate a Uniform scale set'
        $email = Get-Content (Join-Path $out 'CR-15-scale-set-encryption-at-host.email.txt') -Raw
        Assert-ApprovalEmail $email 'CR-15 for one scale set'
        $email | Should -Match 'on one of your virtual machine scale sets\.'
        $email | Should -Match 'The scale set is listed below with its number of instances:'
        $email | Should -Match 'vmss-auto \(Automatic\)'
        $email | Should -Match 'Could you approve this change and suggest a maintenance window that works for this scale set\? Please reply by [^.]+\d{4}\. I will not schedule'
        $flexId = "/subscriptions/$s1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-flex"
        Set-PackResult $pack 'DP.4-VMSS-ELIGIBILITY' @(@{ Name = 'vmss-flex'; ResourceId = $flexId; resourceGroup = 'rg-app'; subscriptionId = $s1; OrchestrationMode = 'Flexible'; UpgradePolicy = ''; Instances = 2; Size = 'Standard_D4s_v5'; UniqueId = (Get-TestId 'vmss-flex'); HasModel = $true; Aks = $false; Eligible = $true; Reason = '' })
        $null = & $generator -EvidencePath $pack -DrClient
        $text = Get-Content (Join-Path $out 'CR-15-scale-set-encryption-at-host.txt') -Raw
        @(Get-Section $text 'D) DR Impact')[0] | Should -Match '^This is a DR client\. Azure Site Recovery does not carry encryption at host .* Flexible scale set instances in this change\.$'
        @(Get-Section $text 'D) DR PLAN')[1] | Should -Match 'starts it again only if it was running before the stop\.$'
        $text | Should -Match 'azure-to-azure-support-matrix'
    }

    It 'leaves Flexible scale sets out when their machines cannot be checked, and keeps the machines of a scale set without a model in CR-09' {
        $pack = Join-Path $TestDrive 'scale-set-flexible'
        New-ChangeFixture $pack
        $sid = { param($name) "/subscriptions/$s1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachineScaleSets/$name" }
        Set-PackResult $pack 'DP.4-VMSS-ELIGIBILITY' @(
            @{ Name = 'vmss-flex'; ResourceId = (& $sid 'vmss-flex'); resourceGroup = 'rg-app'; subscriptionId = $s1; OrchestrationMode = 'Flexible'; Instances = 2; Size = 'Standard_D4s_v5'; UniqueId = (Get-TestId 'vmss-flex'); HasModel = $true; Aks = $false; Eligible = $true; Reason = '' }
            @{ Name = 'vmss-bare'; ResourceId = (& $sid 'vmss-bare'); resourceGroup = 'rg-app'; subscriptionId = $s1; OrchestrationMode = 'Flexible'; Instances = 1; Size = ''; HasModel = $false; Aks = $false; Eligible = $false; Reason = 'no scale set model' })
        $vmId = "/subscriptions/$s1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-bare-1"
        Set-PackResult $pack 'DP.4-ELIGIBILITY' @(@{ Name = 'vm-bare-1'; ResourceId = $vmId; resourceGroup = 'rg-app'; subscriptionId = $s1; Location = 'eastus'; Size = 'Standard_D4s_v5'; PowerState = 'PowerState/running'; ScaleSet = (& $sid 'vmss-bare').ToLowerInvariant(); VmId = (Get-TestId 'vm-bare-1'); AdeUsed = $false; Eligible = $true; Reason = '' })
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        Get-Content (Join-Path $out 'CR-09-encryption-at-host.txt') -Raw | Should -Match '- vm-bare-1, resource group rg-app' -Because 'with no model the scale set has nothing to set, so its machine is a standalone change'
        $text = Get-Content (Join-Path $out 'CR-15-scale-set-encryption-at-host.txt') -Raw
        $text | Should -Match "vmss-flex, resource group rg-app, Flexible, no upgrade policy, 2 instances, size Standard_D4s_v5, unique ID $(Get-TestId 'vmss-flex'), no instance without encryption at host"
        $text | Should -Match 'open the Flexible scale set listed in the RESOURCES section'
        @(Get-Section $text 'A) AVAILABILITY/PERFORMANCE')[0] | Should -Match ', one instance at a time\.$' -Because 'no scale set here applies the model on its own'
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '1 Flexible scale set without a scale set model left out of CR-15: vmss-bare\. With no model there is nothing to set on the scale set, so CR-09 covers its machines as standalone virtual machines\.'
        Set-PackResult $pack 'DP.4-ELIGIBILITY' @(@{ Name = 'vm-x'; ResourceId = 'x'; resourceGroup = 'rg-app'; subscriptionId = $s1; Size = 'Standard_D4s_v5'; PowerState = 'PowerState/running'; Eligible = $true; Reason = '' })
        $null = & $generator -EvidencePath $pack
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '1 Flexible scale set left out of CR-15 because DP\.4-ELIGIBILITY does not name the scale set of each machine, so its machines could not be checked: vmss-flex\.'
        $index | Should -Match '\| 15 \| Encryption at host on virtual machine scale sets \|  \| No eligible scale sets \|'
        Test-Path (Join-Path $out 'CR-15-scale-set-encryption-at-host.txt') | Should -BeFalse -Because 'the change request from the earlier run is removed'
        Set-PackResult $pack 'DP.4-ELIGIBILITY' @() 'FAILED'
        $null = & $generator -EvidencePath $pack
        Get-Content (Join-Path $out '00-index.md') -Raw | Should -Match 'because DP\.4-ELIGIBILITY reads FAILED, so its machines could not be checked: vmss-flex\.'
    }

    It 'quotes each argument of the scale set commands, so a resource group with parentheses stays valid Bash' {
        $bash = Get-Command bash -ErrorAction Stop
        $pack = Join-Path $TestDrive 'scale-set-quoting'
        New-ChangeFixture $pack
        Set-PackResult $pack 'DP.4-VMSS-ELIGIBILITY' @(@{ Name = 'vmss-app'; ResourceId = "/subscriptions/$s1/resourceGroups/rg-app(prod)/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-app"; resourceGroup = 'rg-app(prod)'; subscriptionId = $s1; OrchestrationMode = 'Uniform'; UpgradePolicy = 'Manual'; Instances = 2; Size = 'Standard_D4s_v5'; UniqueId = (Get-TestId 'vmss-app'); HasModel = $true; Aks = $false; Eligible = $true; Reason = '' })
        $null = & $generator -EvidencePath $pack
        $text = Get-Content (Join-Path $pack '05-change-requests/CR-15-scale-set-encryption-at-host.txt') -Raw
        foreach ($flag in 'true', 'false') {
            $line = @($text -split "`r?`n" | Where-Object { $_ -match "az vmss update .*encryptionAtHost=$flag$" })
            $line.Count | Should -Be 1 -Because "one scale set, one $flag command"
            $command = $line[0].Trim()
            $command | Should -Be "az vmss update --subscription '$s1' --resource-group 'rg-app(prod)' --name 'vmss-app' --set virtualMachineProfile.securityProfile.encryptionAtHost=$flag"
            $script = Join-Path $TestDrive "command-$flag.sh"
            [IO.File]::WriteAllText($script, $command + "`n")
            & $bash.Source -n $script 2>&1 | Out-Null
            $LASTEXITCODE | Should -Be 0 -Because "the $flag command parses as Bash"
        }
    }

    It 'leaves a Flexible scale set out when DP.4-ELIGIBILITY is PARTIAL, since a machine missing from it may never have been checked' {
        $pack = Join-Path $TestDrive 'scale-set-partial'
        New-ChangeFixture $pack
        $sid = { param($name) "/subscriptions/$s1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachineScaleSets/$name" }
        $vm = { param($name, $set) @{ Name = $name; ResourceId = "/subscriptions/$s1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/$name"; resourceGroup = 'rg-app'; subscriptionId = $s1; Location = 'eastus'; Size = 'Standard_D4s_v5'; PowerState = 'PowerState/running'; ScaleSet = $set; VmId = (Get-TestId $name); AdeUsed = $false; Eligible = $true; Reason = '' } }
        Set-PackResult $pack 'DP.4-VMSS-ELIGIBILITY' @(@{ Name = 'vmss-flex'; ResourceId = (& $sid 'vmss-flex'); resourceGroup = 'rg-app'; subscriptionId = $s1; OrchestrationMode = 'Flexible'; Instances = 2; Size = 'Standard_D4s_v5'; UniqueId = (Get-TestId 'vmss-flex'); HasModel = $true; Aks = $false; Eligible = $true; Reason = '' })
        $out = Join-Path $pack '05-change-requests'
        # Only unrelated machines returned: the members may be among the machines a truncated read lost.
        Set-PackResult $pack 'DP.4-ELIGIBILITY' @((& $vm 'vm-other' '')) 'PARTIAL'
        $null = & $generator -EvidencePath $pack
        Test-Path (Join-Path $out 'CR-15-scale-set-encryption-at-host.txt') | Should -BeFalse -Because 'an incomplete list cannot show that the scale set has no instance left to change'
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '1 Flexible scale set left out of CR-15 because DP\.4-ELIGIBILITY reads PARTIAL, so its machines could not be checked: vmss-flex\.'
        $index | Should -Not -Match 'no instance without encryption at host'
        # One eligible member returned and the other missing: the missing one may be ineligible.
        Set-PackResult $pack 'DP.4-ELIGIBILITY' @((& $vm 'vm-flex-1' (& $sid 'vmss-flex').ToLowerInvariant())) 'PARTIAL'
        $null = & $generator -EvidencePath $pack
        Test-Path (Join-Path $out 'CR-15-scale-set-encryption-at-host.txt') | Should -BeFalse -Because 'the model change would cover a member that was never checked'
        Get-Content (Join-Path $out 'CR-09-encryption-at-host.txt') -Raw | Should -Match '- vm-flex-1, resource group rg-app' -Because 'CR-15 leaves its scale set out, so CR-09 still changes the eligible machine'
        Get-Content (Join-Path $out '00-index.md') -Raw | Should -Match 'because DP\.4-ELIGIBILITY reads PARTIAL, so its machines could not be checked: vmss-flex\.'
        # The same member on a complete list: a member missing from it already has encryption at host.
        Set-PackResult $pack 'DP.4-ELIGIBILITY' @((& $vm 'vm-flex-1' (& $sid 'vmss-flex').ToLowerInvariant())) 'OK'
        $null = & $generator -EvidencePath $pack
        Get-Content (Join-Path $out 'CR-15-scale-set-encryption-at-host.txt') -Raw | Should -Match "instances without encryption at host: vm-flex-1 \(running, VM ID $(Get-TestId 'vm-flex-1')\)"
    }

    It 'keeps the eligible machines of a Flexible scale set in CR-09 when CR-15 leaves the scale set out' {
        $pack = Join-Path $TestDrive 'scale-set-kept'
        New-ChangeFixture $pack
        $sid = { param($name) "/subscriptions/$s1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachineScaleSets/$name" }
        $vm = { param($name, $set, $eligible = $true) @{ Name = $name; ResourceId = "/subscriptions/$s1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/$name"; resourceGroup = 'rg-app'; subscriptionId = $s1; Location = 'eastus'; Size = 'Standard_D4s_v5'; PowerState = 'PowerState/running'; ScaleSet = (& $sid $set).ToLowerInvariant(); VmId = (Get-TestId $name); AdeUsed = -not $eligible; Eligible = $eligible; Reason = $(if ($eligible) { '' } else { 'Azure Disk Encryption used' }) } }
        Set-PackResult $pack 'DP.4-VMSS-ELIGIBILITY' @(
            @{ Name = 'vmss-model-ade'; ResourceId = (& $sid 'vmss-model-ade'); resourceGroup = 'rg-app'; subscriptionId = $s1; OrchestrationMode = 'Flexible'; Instances = 1; Size = 'Standard_D4s_v5'; UniqueId = (Get-TestId 'vmss-model-ade'); HasModel = $true; Aks = $false; AdeUsed = $true; Eligible = $false; Reason = 'Azure Disk Encryption used' }
            @{ Name = 'vmss-mixed'; ResourceId = (& $sid 'vmss-mixed'); resourceGroup = 'rg-app'; subscriptionId = $s1; OrchestrationMode = 'Flexible'; Instances = 2; Size = 'Standard_D4s_v5'; UniqueId = (Get-TestId 'vmss-mixed'); HasModel = $true; Aks = $false; Eligible = $true; Reason = '' })
        Set-PackResult $pack 'DP.4-ELIGIBILITY' @((& $vm 'vm-model-1' 'vmss-model-ade'), (& $vm 'vm-mixed-ok' 'vmss-mixed'), (& $vm 'vm-mixed-ade' 'vmss-mixed' $false))
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        Test-Path (Join-Path $out 'CR-15-scale-set-encryption-at-host.txt') | Should -BeFalse
        $text = Get-Content (Join-Path $out 'CR-09-encryption-at-host.txt') -Raw
        $text | Should -Match '- vm-model-1, resource group rg-app' -Because 'the model of its scale set cannot take the setting, but the machine itself can'
        $text | Should -Match '- vm-mixed-ok, resource group rg-app' -Because 'CR-15 leaves vmss-mixed out over another machine, so this one is changed as a virtual machine'
        $text | Should -Not -Match 'vm-mixed-ade'
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Not -Match 'CR-15 handles' -Because 'no machine is handed to a change request that leaves it out'
        $index | Should -Match '1 Flexible scale set left out of CR-15 because it has a machine that cannot take encryption at host as it stands: vmss-mixed \(vm-mixed-ade Azure Disk Encryption used\)\.'
    }

    It 'reads only AKS node pools as routed to a project, and no gaps when no scale set lacks encryption at host' {
        $pack = Join-Path $TestDrive 'scale-set-aks'
        New-ChangeFixture $pack
        Set-PackResult $pack 'DP.4-VMSS-ELIGIBILITY' @(
            @{ Name = 'aks-system-1-vmss'; ResourceId = 'a1'; resourceGroup = 'MC_rg_aks_eastus'; subscriptionId = $s1; Size = 'Standard_D2s_v5'; Instances = 1; HasModel = $true; Aks = $true; AksCluster = ''; AksNodePool = ''; Eligible = $false; Reason = 'AKS node pool, set only when a node pool is created' })
        $null = & $generator -EvidencePath $pack
        $index = Get-Content (Join-Path $pack '05-change-requests/00-index.md') -Raw
        $index | Should -Match '\| 15 \| Encryption at host on virtual machine scale sets \|  \| Only AKS node pools remain, see the notes \|'
        $index | Should -Match 'routed to a planned project: scale set aks-system-1-vmss in resource group MC_rg_aks_eastus node pool name not tagged \(Standard_D2s_v5, 1 node\)\.' -Because 'a node pool found by its tags alone is named by its scale set'
        Set-PackResult $pack 'DP.4-VMSS-ELIGIBILITY' @()
        $null = & $generator -EvidencePath $pack
        Get-Content (Join-Path $pack '05-change-requests/00-index.md') -Raw | Should -Match '\| 15 \| Encryption at host on virtual machine scale sets \|  \| No gaps found \|'
    }

    It 'lists each machine and scale set by its own ID, so a machine with the same name but a different ID is never taken for the one checked' {
        $pack = Join-Path $TestDrive 'same-name'
        New-ChangeFixture $pack
        $vmPath = { param($name, $rg) "/subscriptions/$s1/resourceGroups/$rg/providers/Microsoft.Compute/virtualMachines/$name" }
        $sid = { param($name) "/subscriptions/$s1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachineScaleSets/$name" }
        $row = { param($name, $rg, $id, $set = '') @{ Name = $name; ResourceId = (& $vmPath $name $rg); resourceGroup = $rg; subscriptionId = $s1; Location = 'eastus'; Size = 'Standard_D4s_v5'; PowerState = 'PowerState/running'; ScaleSet = $set; VmId = $id; AdeUsed = $false; Eligible = $true; Reason = '' } }
        $first = '0b9a6e1c-1111-4c2a-9d3e-5f7a8b9c0d11'
        $second = '7e4d2c1b-2222-4f8a-8b6c-3d2e1f0a9b22'
        Set-PackResult $pack 'DP.4-ELIGIBILITY' @((& $row 'vm-twin' 'rg-app' $first), (& $row 'vm-twin' 'rg-dr' $second))
        Set-PackResult $pack 'DP.4-VMSS-ELIGIBILITY' @()
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        $text = Get-Content (Join-Path $out 'CR-09-encryption-at-host.txt') -Raw
        $text | Should -Match "- vm-twin, resource group rg-app, size Standard_D4s_v5, running, VM ID $first\r?\n- vm-twin, resource group rg-dr, size Standard_D4s_v5, running, VM ID $second" -Because 'each machine is listed with the ID it had when it was checked'
        @(Import-Csv (Join-Path $out 'change-requests.csv') | Where-Object CR -eq 'CR-09' | ForEach-Object CurrentSetting) | Should -Be @("size Standard_D4s_v5, running, VM ID $first", "size Standard_D4s_v5, running, VM ID $second")
        # The machine in rg-app is deleted and created again under its name, so the next pack holds another ID.
        $third = 'c3d4e5f6-3333-4a1b-9c2d-0e1f2a3b4c33'
        Set-PackResult $pack 'DP.4-ELIGIBILITY' @((& $row 'vm-twin' 'rg-app' $third.ToUpperInvariant()), (& $row 'vm-twin' 'rg-dr' $second))
        $null = & $generator -EvidencePath $pack
        $text = Get-Content (Join-Path $out 'CR-09-encryption-at-host.txt') -Raw
        $text | Should -Match "- vm-twin, resource group rg-app, size Standard_D4s_v5, running, VM ID $third" -Because 'the ID is written in lowercase, as JSON View shows it'
        $text | Should -Not -Match $first -Because 'the machine checked under that ID is gone, and the steps compare the ID, not the name'
        # Two Flexible scale sets with an instance of the same name: each lists its own instance ID.
        Set-PackResult $pack 'DP.4-VMSS-ELIGIBILITY' @(
            @{ Name = 'vmss-a'; ResourceId = (& $sid 'vmss-a'); resourceGroup = 'rg-app'; subscriptionId = $s1; OrchestrationMode = 'Flexible'; Instances = 1; Size = 'Standard_D4s_v5'; UniqueId = (Get-TestId 'vmss-a'); HasModel = $true; Aks = $false; Eligible = $true; Reason = '' }
            @{ Name = 'vmss-b'; ResourceId = (& $sid 'vmss-b'); resourceGroup = 'rg-app'; subscriptionId = $s1; OrchestrationMode = 'Flexible'; Instances = 1; Size = 'Standard_D4s_v5'; UniqueId = (Get-TestId 'vmss-b'); HasModel = $true; Aks = $false; Eligible = $true; Reason = '' })
        Set-PackResult $pack 'DP.4-ELIGIBILITY' @((& $row 'vm-node' 'rg-app' $first (& $sid 'vmss-a').ToLowerInvariant()), (& $row 'vm-node' 'rg-app' $second (& $sid 'vmss-b').ToLowerInvariant()))
        $null = & $generator -EvidencePath $pack
        $text = Get-Content (Join-Path $out 'CR-15-scale-set-encryption-at-host.txt') -Raw
        $text | Should -Match "- vmss-a, resource group rg-app, Flexible, no upgrade policy, 1 instance, size Standard_D4s_v5, unique ID $(Get-TestId 'vmss-a'), instances without encryption at host: vm-node \(running, VM ID $first\)"
        $text | Should -Match "- vmss-b, resource group rg-app, Flexible, no upgrade policy, 1 instance, size Standard_D4s_v5, unique ID $(Get-TestId 'vmss-b'), instances without encryption at host: vm-node \(running, VM ID $second\)"
        $text | Should -Match 'go on to the next instance if properties\.vmId does not read a VM ID listed for this scale set'
        Test-Path (Join-Path $out 'CR-09-encryption-at-host.txt') | Should -BeFalse -Because 'both machines go to CR-15 with their scale sets'
        Test-Path (Join-Path $out 'CR-15-scale-set-encryption-at-host.email.txt') | Should -BeTrue
    }

    It 'leaves out a machine or scale set whose ID was not read, since it cannot be told from one created again under its name' {
        $pack = Join-Path $TestDrive 'id-not-read'
        New-ChangeFixture $pack
        $sid = { param($name) "/subscriptions/$s1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachineScaleSets/$name" }
        $row = { param($name, $id, $set = '') @{ Name = $name; ResourceId = "/subscriptions/$s1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/$name"; resourceGroup = 'rg-app'; subscriptionId = $s1; Location = 'eastus'; Size = 'Standard_D4s_v5'; PowerState = 'PowerState/running'; ScaleSet = $set; VmId = $id; AdeUsed = $false; Eligible = $true; Reason = '' } }
        Set-PackResult $pack 'DP.4-VMSS-ELIGIBILITY' @(
            @{ Name = 'vmss-flex'; ResourceId = (& $sid 'vmss-flex'); resourceGroup = 'rg-app'; subscriptionId = $s1; OrchestrationMode = 'Flexible'; Instances = 2; Size = 'Standard_D4s_v5'; UniqueId = (Get-TestId 'vmss-flex'); HasModel = $true; Aks = $false; Eligible = $true; Reason = '' }
            @{ Name = 'vmss-blank'; ResourceId = (& $sid 'vmss-blank'); resourceGroup = 'rg-app'; subscriptionId = $s1; OrchestrationMode = 'Uniform'; UpgradePolicy = 'Manual'; Instances = 2; Size = 'Standard_D4s_v5'; UniqueId = ''; HasModel = $true; Aks = $false; Eligible = $true; Reason = '' }
            @{ Name = 'vmss-ok'; ResourceId = (& $sid 'vmss-ok'); resourceGroup = 'rg-app'; subscriptionId = $s1; OrchestrationMode = 'Uniform'; UpgradePolicy = 'Manual'; Instances = 2; Size = 'Standard_D4s_v5'; UniqueId = (Get-TestId 'vmss-ok'); HasModel = $true; Aks = $false; Eligible = $true; Reason = '' })
        Set-PackResult $pack 'DP.4-ELIGIBILITY' @((& $row 'vm-solo' (Get-TestId 'vm-solo')), (& $row 'vm-noid' ''), (& $row 'vm-flex-1' (Get-TestId 'vm-flex-1') (& $sid 'vmss-flex').ToLowerInvariant()), (& $row 'vm-flex-2' '' (& $sid 'vmss-flex').ToLowerInvariant()))
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $vms = Get-Content (Join-Path $out 'CR-09-encryption-at-host.txt') -Raw
        $vms | Should -Match "- vm-solo, resource group rg-app, size Standard_D4s_v5, running, VM ID $(Get-TestId 'vm-solo')"
        $vms | Should -Match "- vm-flex-1, resource group rg-app, size Standard_D4s_v5, running, VM ID $(Get-TestId 'vm-flex-1')" -Because 'CR-15 leaves vmss-flex out, so its checked machine is changed as a virtual machine'
        $vms | Should -Not -Match 'vm-noid|vm-flex-2'
        $index | Should -Match '2 virtual machines left out of CR-09 because their VM ID was not read, so they cannot be told from a machine created again under the same name: vm-flex-2, vm-noid\.'
        $index | Should -Match '1 Flexible scale set left out of CR-15 because it has a machine that cannot take encryption at host as it stands: vmss-flex \(vm-flex-2 VM ID not read\)\.'
        $index | Should -Match '1 scale set left out of CR-15 because its unique ID was not read, so it cannot be told from a scale set created again under the same name: vmss-blank\.'
        $sets = Get-Content (Join-Path $out 'CR-15-scale-set-encryption-at-host.txt') -Raw
        $sets | Should -Match "- vmss-ok, resource group rg-app, Uniform, upgrade policy Manual, 2 instances, size Standard_D4s_v5, unique ID $(Get-TestId 'vmss-ok')"
        $sets | Should -Not -Match 'vmss-blank|vmss-flex'
        $index | Should -Match '- CR-15 changes a scale set only when the unique ID that Overview > JSON View shows matches the unique ID listed for it\. One whose ID differs' -Because 'with no Flexible scale set in the change the note leaves out the instance rule'
        foreach ($f in 'CR-09-encryption-at-host.email.txt', 'CR-15-scale-set-encryption-at-host.email.txt') { Test-Path (Join-Path $out $f) | Should -BeTrue -Because "every change request keeps its client email ($f)" }
    }

    It 'keeps the checked machines of a Flexible scale set in CR-09 when CR-15 leaves the scale set out for its missing unique ID' {
        $pack = Join-Path $TestDrive 'flex-no-unique-id'
        New-ChangeFixture $pack
        $sid = { param($name) "/subscriptions/$s1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachineScaleSets/$name" }
        $row = { param($name) @{ Name = $name; ResourceId = "/subscriptions/$s1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/$name"; resourceGroup = 'rg-app'; subscriptionId = $s1; Location = 'eastus'; Size = 'Standard_D4s_v5'; PowerState = 'PowerState/running'; ScaleSet = (& $sid 'vmss-flex').ToLowerInvariant(); VmId = (Get-TestId $name); AdeUsed = $false; Eligible = $true; Reason = '' } }
        Set-PackResult $pack 'DP.4-VMSS-ELIGIBILITY' @(@{ Name = 'vmss-flex'; ResourceId = (& $sid 'vmss-flex'); resourceGroup = 'rg-app'; subscriptionId = $s1; OrchestrationMode = 'Flexible'; Instances = 2; Size = 'Standard_D4s_v5'; UniqueId = ''; HasModel = $true; Aks = $false; Eligible = $true; Reason = '' })
        Set-PackResult $pack 'DP.4-ELIGIBILITY' @((& $row 'vm-flex-1'), (& $row 'vm-flex-2'))
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        Test-Path (Join-Path $out 'CR-15-scale-set-encryption-at-host.txt') | Should -BeFalse
        $text = Get-Content (Join-Path $out 'CR-09-encryption-at-host.txt') -Raw
        foreach ($name in 'vm-flex-1', 'vm-flex-2') { $text | Should -Match "- $name, resource group rg-app, size Standard_D4s_v5, running, VM ID $(Get-TestId $name)" -Because "CR-15 leaves vmss-flex out, so $name is changed as a virtual machine" }
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Not -Match 'CR-15 handles' -Because 'no machine is handed to a change request that leaves it out'
        $index | Should -Match '1 scale set left out of CR-15 because its unique ID was not read, so it cannot be told from a scale set created again under the same name: vmss-flex\.'
        $index | Should -Match '\| 09 \| Encryption at host on virtual machines \| 2 \| Change request and client email \|'
    }

    It 'reads needs recollection for CR-09 and CR-15 on a pack collected before the machine and scale set IDs' {
        $pack = Join-Path $TestDrive 'no-ids'
        New-ChangeFixture $pack
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        foreach ($f in 'CR-09-encryption-at-host.txt', 'CR-15-scale-set-encryption-at-host.txt') { Test-Path (Join-Path $out $f) | Should -BeTrue }
        # Collector 1.3.0 wrote the same rows without VmId and UniqueId.
        foreach ($id in 'DP.4-ELIGIBILITY', 'DP.4-VMSS-ELIGIBILITY') {
            $field = if ($id -eq 'DP.4-ELIGIBILITY') { 'VmId' } else { 'UniqueId' }
            $rows = @(Get-Content (Join-Path $pack "results/$id.json") -Raw | ConvertFrom-Json | ForEach-Object { $_ | Select-Object -Property * -ExcludeProperty $field })
            Set-PackResult $pack $id $rows
        }
        Set-Content (Join-Path $pack '00-parameters.json') ((Get-Content (Join-Path $pack '00-parameters.json') -Raw) -replace '"ScriptVersion":\s*"1\.4\.0"', '"ScriptVersion": "1.3.0"')
        $null = & $generator -EvidencePath $pack
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '\| 09 \| Encryption at host on virtual machines \|  \| Needs recollection with CyberSOC collector 1\.4\.0 or later \|  \|'
        $index | Should -Match '\| 15 \| Encryption at host on virtual machine scale sets \|  \| Needs recollection with CyberSOC collector 1\.4\.0 or later \|  \|'
        foreach ($f in 'CR-09-encryption-at-host.txt', 'CR-09-encryption-at-host.email.txt', 'CR-15-scale-set-encryption-at-host.txt', 'CR-15-scale-set-encryption-at-host.email.txt') {
            Test-Path (Join-Path $out $f) | Should -BeFalse -Because "a machine named without its ID could be one created again under that name ($f from the earlier run is removed)"
        }
        $index | Should -Match '4 virtual machines left out of CR-09 because they cannot take encryption at host as they stand' -Because 'the notes that need no ID are kept'
        $index | Should -Match '1 AKS node pool without encryption at host left out of CR-15 and routed to a planned project'
        $index | Should -Not -Match 'CR-09 changes a virtual machine only when|CR-15 changes a scale set only when'
        Test-Path (Join-Path $out 'CR-06-key-vault-purge-protection.txt') | Should -BeTrue -Because 'the other changes do not need the IDs'
        # A pack with nothing to change reads as before.
        Set-PackResult $pack 'DP.4-ELIGIBILITY' @()
        Set-PackResult $pack 'DP.4-VMSS-ELIGIBILITY' @()
        $null = & $generator -EvidencePath $pack
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '\| 09 \| Encryption at host on virtual machines \|  \| No gaps found \|'
        $index | Should -Match '\| 15 \| Encryption at host on virtual machine scale sets \|  \| No gaps found \|'
    }

    It 'remediates the non-compliant resources when the initiative is assigned' {
        $pack = Join-Path $TestDrive 'remediate'
        New-ChangeFixture $pack
        Set-PackResult $pack 'DR.6-INITIATIVE' @(@{ DefinitionName = 'ATMO-MXDR-KV-TOSENT'; Resources = 6; Compliant = 5; NonCompliant = 1 })
        Set-PackResult $pack 'DR.6-COVERAGE' @(@{ subscriptionId = $s1; Resources = 5; Assignments = 1 }, @{ subscriptionId = $s2; Resources = 1; Assignments = 1 })
        Set-PackResult $pack 'DR.6-NONCOMPLIANT' @(
            @{ ResourceId = "/subscriptions/$s1/resourcegroups/rg-app/providers/microsoft.keyvault/vaults/kv-app"; ResourceType = 'microsoft.keyvault/vaults'; AssignmentName = 'ATMO-MXDR-DIAG-TOSENT'; AssignmentId = "/subscriptions/$s1/providers/microsoft.authorization/policyassignments/atmo-mxdr-diag-tosent"; Policies = 'ATMO-MXDR-KV-TOSENT' }
            @{ ResourceId = "/subscriptions/$s1/resourcegroups/rg-app/providers/microsoft.keyvault/vaults/kv-app"; ResourceType = 'microsoft.keyvault/vaults'; AssignmentName = 'ATMO-MXDR-DIAG-TOSENT'; AssignmentId = '/providers/microsoft.management/managementgroups/mg-root/providers/microsoft.authorization/policyassignments/atmo-mxdr-diag'; AssignmentScope = '/providers/Microsoft.Management/managementGroups/MG-Root'; Policies = 'ATMO-MXDR-KV-TOSENT' }
            @{ ResourceId = "/subscriptions/$s1/resourcegroups/rg-ops/providers/microsoft.automation/automationaccounts/aa-ops"; ResourceType = 'microsoft.automation/automationaccounts'; AssignmentName = 'ATMO-MXDR-DIAG-TOSENT'; AssignmentId = "/subscriptions/$s1/providers/microsoft.authorization/policyassignments/atmo-mxdr-diag-tosent"; Policies = 'ATMO-MXDR-AA-TOSENT' }
            @{ ResourceId = "/subscriptions/$s2"; ResourceType = 'microsoft.resources/subscriptions'; AssignmentName = 'ATMO-MXDR-DIAG-TOSENT'; AssignmentId = "/subscriptions/$s2/providers/microsoft.authorization/policyassignments/atmo-mxdr-diag-tosent"; Policies = 'ATMO-MXDR-ACT-TOSENT' })
        $null = & $generator -EvidencePath $pack -SentinelWorkspace 'law-chosen'
        Test-Path (Join-Path $pack '05-change-requests/CR-01-diagnostic-logging.txt') | Should -BeFalse -Because 'every subscription already has the initiative'
        Get-Content (Join-Path $pack '05-change-requests/00-index.md') -Raw | Should -Match '\| 01 \| .* \| No gaps found, every subscription has the initiative \|'
        $text = Get-Content (Join-Path $pack '05-change-requests/CR-10-diagnostic-remediation.txt') -Raw
        $text | Should -Match 'Title: Remediate resources missing ATMO-MXDR diagnostic logging'
        ([regex]::Matches($text, '- kv-app, ')).Count | Should -Be 1 -Because 'a resource failing under two assignments is listed once'
        $text | Should -Match 'on the 3 resources listed below'
        $text | Should -Match '    - Assignment ATMO-MXDR-DIAG-TOSENT at management group MG-Root: ATMO-MXDR-KV-TOSENT' -Because 'the scope is shown as the portal writes it'
        $text | Should -Match '- kv-app, resource group rg-app, Key vault, policies ATMO-MXDR-KV-TOSENT'
        $text | Should -Match '- Subscription Activity Log, policies ATMO-MXDR-ACT-TOSENT'
        $text | Should -Match '2\. Create one remediation task for each assignment and policy below\. Select the assignment, select New remediation task, choose the policy, keep the scope at the assignment scope and select Remediate:'
        $text | Should -Match "    - Assignment ATMO-MXDR-DIAG-TOSENT at subscription Example Production \($s1\): ATMO-MXDR-AA-TOSENT, ATMO-MXDR-KV-TOSENT"
        $text | Should -Match "    - Assignment ATMO-MXDR-DIAG-TOSENT at subscription Example, Dev Test \($s2\): ATMO-MXDR-ACT-TOSENT" -Because 'a remediation task belongs to one assignment, and each subscription holds its own'
        $text | Should -Match 'Monitor > Activity log > Export Activity Logs'
        $text | Should -Match 'the Sentinel workspace law-chosen'
        $email = Get-Content (Join-Path $pack '05-change-requests/CR-10-diagnostic-remediation.email.txt') -Raw
        Assert-ApprovalEmail $email 'CR-10'
        $email | Should -Match '^Subject: Approval requested: diagnostic logging remediation for Azure resources'
        $email | Should -Match 'I would like your approval to run Azure Policy remediation tasks for the ATMO-MXDR-DIAG-TOSENT initiative on 3 of your Azure resources\. A remediation task adds the diagnostic settings the initiative expects, so the resources send their audit logs to your Sentinel workspace law-chosen\.'
        $email | Should -Match 'I recommend running the remediation because the resources below do not send their audit logs to your Sentinel workspace law-chosen today, so the SOC cannot detect or investigate activity on them\.'
        $email | Should -Match "The resources are listed below by subscription, each with its type:\r?\n\r?\nSubscription Example Production \($s1\):\r?\n\r?\n- kv-app \(resource group rg-app, Key vault\)\r?\n- aa-ops \(resource group rg-ops, Automation account\)\r?\n\r?\nSubscription Example, Dev Test \($s2\):\r?\n\r?\n- Subscription Activity Log\r?\n"
        $email | Should -Not -Match 'ATMO-MXDR-KV-TOSENT|ATMO-MXDR-AA-TOSENT' -Because 'the client email names the resource type, not the policy'
        $email | Should -Match 'This change adds Log Analytics ingestion to your Sentinel workspace law-chosen\. The resource logs are billed as data ingested into the workspace, and their volume depends on how busy each resource is\. The Azure Activity log of each subscription is ingested at no charge\.'
    }

    It 'writes no diagnostic logging change when every resource is compliant, and asks for recollection without the resource list' {
        $pack = Join-Path $TestDrive 'compliant'
        New-ChangeFixture $pack
        Set-PackResult $pack 'DR.6-INITIATIVE' @(@{ DefinitionName = 'ATMO-MXDR-KV-TOSENT'; Resources = 6; Compliant = 6; NonCompliant = 0 })
        $null = & $generator -EvidencePath $pack
        Test-Path (Join-Path $pack '05-change-requests/CR-10-diagnostic-remediation.txt') | Should -BeFalse
        Get-Content (Join-Path $pack '05-change-requests/00-index.md') -Raw | Should -Match '\| 10 \| .* \| No gaps found, every resource is compliant with the initiative \|'
        Set-PackResult $pack 'DR.6-INITIATIVE' @(@{ DefinitionName = 'ATMO-MXDR-KV-TOSENT'; Resources = 6; Compliant = 5; NonCompliant = 1 })
        $null = & $generator -EvidencePath $pack
        Get-Content (Join-Path $pack '05-change-requests/00-index.md') -Raw | Should -Match '\| 10 \| .* \| Needs recollection with CyberSOC collector 1\.1\.0 or later \|'
        Get-Content (Join-Path $pack '05-change-requests/00-index.md') -Raw | Should -Match '\| 01 \| .* \| Needs recollection with CyberSOC collector 1\.1\.0 or later \|' -Because 'coverage by subscription needs DR.6-COVERAGE once the initiative has states'
    }

    It 'suggests just-in-time VM access where every subscription has Plan 2, and keeps a plan unknown when P0.3 is partial or was not read' {
        $pack = Join-Path $TestDrive 'mgmt-plan2'
        New-ChangeFixture $pack
        Set-PackResult $pack 'P0.3' @(@{ subscriptionId = $s1; Plan = 'VirtualMachines'; Tier = 'Standard'; SubPlan = 'P2' }, @{ subscriptionId = $s2.ToUpperInvariant(); Plan = 'VirtualMachines'; Tier = 'Standard'; SubPlan = 'P2' })
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        $email = Get-Content (Join-Path $out 'CR-16-management-ports.email.txt') -Raw
        Assert-ApprovalEmail $email 'CR-16 with Plan 2 on'
        $email | Should -Match 'Plan 2 is on in each of these subscriptions\.'
        $email | Should -Match 'Because Plan 2 is already on, I suggest just-in-time VM access\.'
        Get-Content (Join-Path $out 'CR-16-management-ports.txt') -Raw | Should -Match "- Example, Dev Test \($s2\): on, so just-in-time VM access is the path"

        Set-PackResult $pack 'P0.3' @(@{ subscriptionId = $s1; Plan = 'VirtualMachines'; Tier = 'Free'; SubPlan = '' }, @{ subscriptionId = $s2; Plan = 'VirtualMachines'; Tier = 'Standard'; SubPlan = 'P1' })
        $null = & $generator -EvidencePath $pack
        $email = Get-Content (Join-Path $out 'CR-16-management-ports.email.txt') -Raw
        $email | Should -Match 'Plan 2 is not on in these subscriptions, so this path would add the cost of Plan 2 for the servers there\.'
        $email | Should -Match 'Because Plan 2 is not on, I suggest Azure Bastion, unless you would rather turn Plan 2 on\.'

        # A PARTIAL P0.3 that left a subscription out keeps it unknown, never off.
        Set-PackResult $pack 'P0.3' @(@{ subscriptionId = $s1; Plan = 'VirtualMachines'; Tier = 'Standard'; SubPlan = 'P2' }) 'PARTIAL'
        $null = & $generator -EvidencePath $pack
        $email = Get-Content (Join-Path $out 'CR-16-management-ports.email.txt') -Raw
        Assert-ApprovalEmail $email 'CR-16 with a partial P0.3'
        $email | Should -Match "Plan 2 is on in subscription Example Production \($s1\)\. I could not confirm whether Plan 2 is on in subscription Example, Dev Test \($s2\), and I will check that before the change\."
        $email | Should -Match 'I will suggest the path that fits each subscription once I know which have Plan 2\.'
        $email | Should -Not -Match 'not on in|add the cost' -Because 'a plan that was not read is never called off'
        Get-Content (Join-Path $out 'CR-16-management-ports.txt') -Raw | Should -Match "- Example, Dev Test \($s2\): not read, so check the plan under Microsoft Defender for Cloud > Environment settings before choosing the path"
        Get-Content (Join-Path $out '00-index.md') -Raw | Should -Match '\| 16 \| Internet-facing RDP, SSH and WinRM rules closed \| 2 \| Change request and client email, partial collection scope \|'

        Remove-PackResult $pack 'P0.3'
        $null = & $generator -EvidencePath $pack
        $email = Get-Content (Join-Path $out 'CR-16-management-ports.email.txt') -Raw
        Assert-ApprovalEmail $email 'CR-16 without P0.3'
        $email | Should -Match 'I could not confirm which of these subscriptions have Plan 2, and I will check that before the change\.'
        Get-Content (Join-Path $out 'CR-16-management-ports.txt') -Raw | Should -Match "- Example Production \($s1\): not read, so check the plan"
        Get-Content (Join-Path $out '00-index.md') -Raw | Should -Match '- CR-16 was written without P0\.3, which was not collected\.'
    }

    It 'writes singular wording for one rule, reads lists given as JSON text, and leaves a group shared with an appliance for review' {
        $pack = Join-Path $TestDrive 'mgmt-single'
        New-ChangeFixture $pack
        $id = "/subscriptions/$s1/resourceGroups/rg-web/providers/Microsoft.Network/networkSecurityGroups/nsg-web"
        $nic = "/subscriptions/$s1/resourceGroups/rg-fw/providers/Microsoft.Network/networkInterfaces"
        Set-PackResult $pack 'NB.2-DETAIL' @(
            @{ subscriptionId = $s1; resourceGroup = 'rg-web'; NSG = 'nsg-web'; NsgId = $id; RuleName = 'Allow-SSH'; RuleId = "$id/securityRules/Allow-SSH"; Priority = 120; Direction = 'Inbound'; Access = 'Allow'; Protocol = 'Tcp'
                SourcePrefixes = '["","Internet","0.0.0.0/0"]'; SourcePorts = '["*"]'; DestinationPrefixes = '["*"]'; DestinationAsgs = '[]'; DestinationPorts = '["22"]'; Description = ''; Association = 'Subnet'; RangeNeedsReview = $false
                Subnets = '[{"id":"/subscriptions/' + $s1 + '/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-app/subnets/snet-web"}]'; Nics = '[]'; NicVms = @(); ApplianceNicIds = ('["{0}"]' -f "$nic/nic-fw-untrust".ToLowerInvariant()); ApplianceSubnetIds = '[]' }
            @{ subscriptionId = $s1; resourceGroup = 'rg-fw'; NSG = 'nsg-shared'; NsgId = 'nsg-shared'; RuleName = 'Allow-RDP'; RuleId = 'r2'; Priority = 130; Protocol = 'Tcp'; SourcePrefixes = @('*'); DestinationPorts = @('3389'); Association = 'NIC'
                Subnets = @(); Nics = @(@{ id = "$nic/nic-fw-untrust" }, @{ id = "$nic/nic-app01" }); NicVms = @(); ApplianceNicIds = @("$nic/nic-fw-untrust".ToLowerInvariant()); ApplianceSubnetIds = @() })
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        $text = Get-Content (Join-Path $out 'CR-16-management-ports.txt') -Raw
        $text | Should -Match 'Remove the inbound security rule listed below that allow'
        $text | Should -Match 'The inbound rule below allows RDP, SSH or WinRM'
        $text | Should -Match '- nsg-web/Allow-SSH, resource group rg-web, priority 120, allow inbound, protocol TCP, source \(Internet, 0\.0\.0\.0/0\), source ports \*, destination \*, destination ports 22, applies to subnet snet-web of virtual network vnet-app'
        $text | Should -Not -Match 'Repeat steps'
        $email = Get-Content (Join-Path $out 'CR-16-management-ports.email.txt') -Raw
        Assert-ApprovalEmail $email 'CR-16 for one rule'
        $email | Should -Match 'I would like your approval to close the network security group rule that let anyone'
        $email | Should -Match 'The change covers the rule below, shown with its network security group, priority, ports, source and where it applies:'
        $email | Should -Match 'TCP port 22 from Internet and 0\.0\.0\.0/0, on subnet snet-web'
        $email | Should -Match 'If anything unexpected comes up, I can recreate the rule exactly as it is today, since every setting of it is recorded\.'
        $email | Should -Not -Match 'other ports' -Because 'the rule names only a management port'
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '- 1 rule left out of CR-16 for review because its network security group reaches a network virtual appliance through a subnet it sits in, or through its network interface as well as other resources, so changing the rule would change the appliance too: Allow-RDP in nsg-shared \(resource group rg-fw\)\.'
        $index | Should -Match '\| 16 \| Internet-facing RDP, SSH and WinRM rules closed \| 1 \| Change request and client email \|'
    }

    It 'reads ::/0 as the internet, and leaves a rule for a protocol other than TCP for review' {
        $pack = Join-Path $TestDrive 'mgmt-protocols'
        New-ChangeFixture $pack
        $id = "/subscriptions/$s1/resourceGroups/rg-web/providers/Microsoft.Network/networkSecurityGroups/nsg-v6"
        $subnet = @{ id = "/subscriptions/$s1/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-app/subnets/snet-v6" }
        $row = { param($name, $protocol, $source, $port) @{ subscriptionId = $s1; resourceGroup = 'rg-web'; NSG = 'nsg-v6'; NsgId = $id; RuleName = $name; RuleId = "$id/securityRules/$name"; Priority = 150; Protocol = $protocol
                SourcePrefixes = @($source); SourcePorts = @('*'); DestinationPrefixes = @('*'); DestinationAsgs = @(); DestinationPorts = @($port); Association = 'Subnet'; Subnets = @($subnet); Nics = @(); NicVms = @(); ApplianceNicIds = @(); ApplianceSubnetIds = @() } }
        Set-PackResult $pack 'NB.2-DETAIL' @((& $row 'Allow-SSH-v6' 'Tcp' '::/0' '22'), (& $row 'Allow-App-UDP' 'Udp' '*' '22'), (& $row 'Allow-RDP-Any' '*' 'Internet' '3389'))
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        $text = Get-Content (Join-Path $out 'CR-16-management-ports.txt') -Raw
        $text | Should -Match '- nsg-v6/Allow-SSH-v6, resource group rg-web, priority 150, allow inbound, protocol TCP, source ::/0,' -Because 'the IPv6 any-address prefix is the internet too'
        $text | Should -Match '- nsg-v6/Allow-RDP-Any, resource group rg-web, priority 150, allow inbound, protocol Any, source Internet,' -Because 'a rule for any protocol carries TCP'
        $text | Should -Not -Match 'Allow-App-UDP'
        Assert-ApprovalEmail (Get-Content (Join-Path $out 'CR-16-management-ports.email.txt') -Raw) 'CR-16 with ::/0'
        Get-Content (Join-Path $out 'CR-16-management-ports.email.txt') -Raw | Should -Match 'One of the rules is open to every address' -Because '::/0 matches private addresses too, the Internet tag does not'
        Get-Content (Join-Path $out '00-index.md') -Raw | Should -Match '- 1 rule left out of CR-16 for review because it allows only a protocol other than TCP, so it may carry an application rather than RDP, SSH or WinRM: Allow-App-UDP in nsg-v6 \(resource group rg-web\), UDP ports 22\. Review each with the client, since RDP can also use UDP 3389\.'
        Set-PackResult $pack 'NB.2-DETAIL' @((& $row 'Allow-RDP-Internet' 'Tcp' 'Internet' '3389'))
        $null = & $generator -EvidencePath $pack
        Get-Content (Join-Path $out 'CR-16-management-ports.txt') -Raw | Should -Not -Match 'VirtualNetwork' -Because 'the Internet service tag holds no private addresses, so nothing private needs a rule of its own'
        Get-Content (Join-Path $out 'CR-16-management-ports.email.txt') -Raw | Should -Not -Match 'your own networks|address ranges of the virtual networks' -Because 'no private ranges are needed for an Internet-only source'
    }

    It 'keeps WinRM off Azure Bastion, builds the private access rule from confirmed ranges and checks the effective security rules' {
        $pack = Join-Path $TestDrive 'mgmt-winrm'
        New-ChangeFixture $pack
        $row = { param($name, $group, $sub, $source, [string[]]$ports, $association, $attached)
            $id = "/subscriptions/$sub/resourceGroups/rg-win/providers/Microsoft.Network/networkSecurityGroups/$group"
            @{ subscriptionId = $sub; resourceGroup = 'rg-win'; NSG = $group; NsgId = $id; RuleName = $name; RuleId = "$id/securityRules/$name"; Priority = 200; Direction = 'Inbound'; Access = 'Allow'; Protocol = 'Tcp'
                SourcePrefixes = @($source); SourcePorts = @('*'); DestinationPrefixes = @('*'); DestinationAsgs = @(); DestinationPorts = $ports; Description = ''; Association = $association; RangeNeedsReview = $false
                Subnets = @(if ($association -eq 'Subnet') { $attached }); Nics = @(if ($association -eq 'NIC') { $attached }); NicVms = @(); ApplianceNicIds = @(); ApplianceSubnetIds = @() } }
        $subnet = @{ id = "/subscriptions/$s1/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-ops/subnets/snet-mgmt" }
        $nic = @{ id = "/subscriptions/$s2/resourceGroups/rg-win/providers/Microsoft.Network/networkInterfaces/nic-win01" }
        # A WinRM-only rule where Plan 2 is on, a mixed RDP and WinRM rule open to 0.0.0.0/0 and an SSH rule open to
        # ::/0 where Plan 2 is off, so Azure Bastion is suggested there and both broad rules need private access.
        Set-PackResult $pack 'NB.2-DETAIL' @(
            (& $row 'Allow-WinRM' 'nsg-mgmt' $s1 'Internet' @('5985', '5986') 'Subnet' $subnet)
            (& $row 'Allow-RDP-WinRM' 'nsg-win' $s2 '0.0.0.0/0' @('3389', '5986') 'NIC' $nic)
            (& $row 'Allow-SSH-v6' 'nsg-win' $s2 '::/0' @('22') 'NIC' $nic))
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        $text = Get-Content (Join-Path $out 'CR-16-management-ports.txt') -Raw
        $email = Get-Content (Join-Path $out 'CR-16-management-ports.email.txt') -Raw
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        foreach ($rule in 'nsg-mgmt/Allow-WinRM', 'nsg-win/Allow-RDP-WinRM', 'nsg-win/Allow-SSH-v6') { $text | Should -Match ([regex]::Escape("- $rule,")) }

        # Azure Bastion provides RDP and SSH sessions only, so it is never offered for WinRM.
        foreach ($doc in $text, $email) {
            $sentences = @($doc -split '(?<=[.?:])\s+' | Where-Object { $_ -match 'Bastion' -and $_ -match 'WinRM|5985|5986' })
            $sentences.Count | Should -BeGreaterThan 0
            foreach ($s in $sentences) { $s | Should -Match 'never|cannot|does not provide|RDP and SSH|just-in-time VM access or|named source addresses' -Because "a sentence that names Bastion with WinRM must keep WinRM off it: $s" }
        }
        $text | Should -Match "- Example, Dev Test \($s2\): not on, so Azure Bastion is the path for RDP and SSH and named source addresses for WinRM, unless the client turns Plan 2 on"
        $text | Should -Match "- Example Production \($s1\): on, so just-in-time VM access is the path"
        $impl = @(Get-Section $text 'A) IMPLEMENTATION PLAN')
        $impl[1] | Should -Match 'Azure Bastion provides RDP and SSH sessions only, so it never replaces WinRM on 5985 or 5986\.$'
        $impl[2] | Should -Match 'Unless a rule already allows ports 22 and 3389 from the AzureBastionSubnet address range' -Because 'the Bastion rule never opens 5985 or 5986'
        $impl[2] | Should -Not -Match '5985|5986'
        $impl[3] | Should -Be '4. A rule that opens 5985 or 5986 keeps WinRM only through just-in-time VM access or the source addresses the client named for WinRM, never through Azure Bastion. Where the client still needs WinRM to the machines behind such a rule and neither is agreed, leave the rule unchanged and note it in the change record.'
        $impl | Should -Contain '11. Repeat steps 5 to 10 for each remaining rule listed.'
        @(Get-Section $text 'A) CHANGE DESCRIPTION')[0] | Should -Match 'in their place, with WinRM through just-in-time VM access or named source addresses only\.$'
        $text | Should -Match 'Administrators who connect straight from the internet over RDP, SSH or WinRM move to just-in-time VM access or Azure Bastion, as agreed with the client, and remote PowerShell over WinRM to just-in-time VM access or named source addresses, since Azure Bastion does not provide WinRM\.'
        (Get-Section $text 'B) TESTING PLAN') -join "`n" | Should -Match 'Where a rule opened 5985 or 5986 and WinRM is still needed, have the client confirm a WinRM connection to one machine behind it, through an approved just-in-time request or from a named address\.'
        ($testing = (Get-Section $text 'B) TESTING PLAN') -join "`n") | Should -Not -Match '\baz |Get-Az|Cloud Shell|PowerShell|curl' -Because 'the testing plan stays in the portal'
        $text | Should -Match ([regex]::Escape('What is Azure Bastion: https://learn.microsoft.com/azure/bastion/bastion-overview'))

        # The private access rule names the ranges the client confirms, never the service tag for the virtual network.
        foreach ($doc in $text, $email, $index) { $doc | Should -Not -Match 'VirtualNetwork' -Because 'the service tag for the virtual network can hold 0.0.0.0/0 behind a user-defined route' }
        @(Import-Csv (Join-Path $out 'change-requests.csv') | Where-Object CR -eq 'CR-16' | Where-Object { $_.CurrentSetting -match 'VirtualNetwork' }).Count | Should -Be 0
        $private = @($impl | Where-Object { $_ -match 'which also matches private addresses' })
        $private.Count | Should -Be 1
        $private[0] | Should -Match 'Source set to IP Addresses with the private ranges the client confirmed, the address spaces of the virtual networks, peered virtual networks and on-premises networks that connect to the machines'
        $private[0] | Should -Match 'never a service tag, Any, 0\.0\.0\.0/0 or ::/0'
        $private[0] | Should -Match 'If the client has confirmed neither the ranges nor that nothing connects, leave the rule unchanged'
        $text | Should -Match 'and for a rule open to every address, the private ranges the client confirmed or its word that nothing connects from its own networks\.'
        $email | Should -Match 'Some of the rules are open to every address, which includes those networks, so I will keep that private access in a rule of its own, built only from the address ranges of those networks that you confirm, unless you tell me nobody uses it\.'
        $email | Should -Match 'Could you also send me the address ranges of the virtual networks, peered networks and on-premises networks that connect to these machines, or tell me that nothing connects from them\?'

        # The testing step reads the effective security rules of a network interface, not only the rules listed.
        $testing = (Get-Section $text 'B) TESTING PLAN') -join "`n"
        $testing | Should -Match 'For each network interface the rules applied to, directly or through its subnet, go to Virtual machines, open the machine it belongs to, select Networking, select the network interface and select Effective security rules under Help\.'
        $testing | Should -Match 'Select each inbound allow rule that covers 22, 3389, 5985 or 5986 and sits ahead of every deny rule for those ports from any source, and confirm none of its source prefixes is 0\.0\.0\.0/0 or ::/0, that its prefixes do not together span the internet'
        $text | Should -Match ([regex]::Escape('View effective security rules of a network interface: https://learn.microsoft.com/azure/virtual-network/virtual-network-network-interface#view-effective-security-rules'))

        # The email asks for approval, keeps WinRM off Bastion and keeps the copy rules.
        Assert-ApprovalEmail $email 'CR-16 with WinRM'
        $email | Should -Match 'In their place, administrators would connect through just-in-time VM access or Azure Bastion, and remote PowerShell over WinRM through just-in-time VM access or from addresses you name\.'
        $email | Should -Match 'It provides RDP and SSH sessions only, so it cannot replace WinRM, which remote PowerShell uses\.'
        $email | Should -Match 'I suggest just-in-time VM access where Plan 2 is on and Azure Bastion elsewhere, unless you would rather turn Plan 2 on there\. Azure Bastion does not provide WinRM, so remote PowerShell would continue through just-in-time VM access or only from addresses you name\.'
        $email | Should -Match 'and which replacement you would like, just-in-time VM access or Azure Bastion for RDP and SSH\?'
        $email | Should -Not -Match '[;>]|->|=>|<-'
    }

    It 'writes no management port change when only rules for cleanup or review remain, and no gaps when NB.2-DETAIL is empty' {
        $pack = Join-Path $TestDrive 'mgmt-none'
        New-ChangeFixture $pack
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        Test-Path (Join-Path $out 'CR-16-management-ports.txt') | Should -BeTrue
        $rows = @(Get-Content (Join-Path $pack 'results/NB.2-DETAIL.json') -Raw | ConvertFrom-Json | Where-Object { $_.NSG -notin 'nsg-web', 'nsg-jump' })
        Set-PackResult $pack 'NB.2-DETAIL' $rows
        $null = & $generator -EvidencePath $pack
        foreach ($f in 'CR-16-management-ports.txt', 'CR-16-management-ports.email.txt') { Test-Path (Join-Path $out $f) | Should -BeFalse -Because "the $f of the earlier run is removed" }
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '\| 16 \| Internet-facing RDP, SSH and WinRM rules closed \|  \| Only rules for cleanup or review remain, see the notes \|  \|'
        $index | Should -Match '- 1 rule left out of CR-16 as a cleanup item'
        @(Import-Csv (Join-Path $out 'change-requests.csv') | Where-Object CR -eq 'CR-16').Count | Should -Be 0
        Set-PackResult $pack 'NB.2-DETAIL' @()
        $null = & $generator -EvidencePath $pack
        Get-Content (Join-Path $out '00-index.md') -Raw | Should -Match '\| 16 \| Internet-facing RDP, SSH and WinRM rules closed \|  \| No gaps found \|'
    }

    It 'reads needs recollection on a pack collected before the per-resource results, and clears stale change requests' {
        $pack = Join-Path $TestDrive 'old'
        New-ChangeFixture $pack
        $null = & $generator -EvidencePath $pack
        foreach ($id in 'P0.7', 'NB.2-DETAIL', 'NB.4-DETAIL', 'NB.5-DETAIL', 'NB.6-DETAIL', 'NB.6-PAAS-DETAIL', 'DP.1-DETAIL', 'DP.2-DETAIL', 'DP.4-VMSS-ELIGIBILITY') { Remove-PackResult $pack $id }
        Set-PackResult $pack 'DP.4-ELIGIBILITY' @() 'FAILED'
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        @(Get-ChildItem $out -Filter 'CR-*' | ForEach-Object Name | Sort-Object) -join '|' | Should -Be 'CR-01-diagnostic-logging.email.txt|CR-01-diagnostic-logging.txt' -Because 'change requests from the earlier run that this pack can no longer support are removed'
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '\| 02 \| Secure transfer required on storage accounts \|  \| Needs recollection with CyberSOC collector 1\.1\.0 or later \|'
        $index | Should -Match '\| 09 \| Encryption at host on virtual machines \|  \| Not collected \(DP\.4-ELIGIBILITY FAILED\) \|'
        foreach ($n in 11..14) { $index | Should -Match ('\| {0} \| [^|]+ \|  \| Needs recollection with CyberSOC collector 1\.2\.0 or later \|' -f $n) -Because 'NB.6-PAAS-DETAIL was added in 1.2.0' }
        $index | Should -Match '\| 15 \| Encryption at host on virtual machine scale sets \|  \| Needs recollection with CyberSOC collector 1\.3\.0 or later \|' -Because 'DP.4-VMSS-ELIGIBILITY was added in 1.3.0'
        $index | Should -Match '\| 16 \| Internet-facing RDP, SSH and WinRM rules closed \|  \| Needs recollection with CyberSOC collector 1\.6\.0 or later \|' -Because 'NB.2-DETAIL was added in 1.6.0'
        $index | Should -Match 'Subscription names were not read \(P0\.7\)'
        Get-Content (Join-Path $out 'CR-01-diagnostic-logging.txt') -Raw | Should -Match "- $s1\r?\n"
    }

    It 'writes singular wording for one resource and leaves other files in the folder alone' {
        $pack = Join-Path $TestDrive 'single'
        New-ChangeFixture $pack
        Set-PackResult $pack 'DP.2-DETAIL' @(@{ Name = 'kv-only'; ResourceId = 'kv1'; resourceGroup = 'rg-app'; subscriptionId = $s1 })
        Set-PackResult $pack 'NB.4-DETAIL' @(@{ Name = 'app-portal'; ResourceId = 'app1'; resourceGroup = 'rg-web'; subscriptionId = $s1; DefaultHostName = 'app-portal.azurewebsites.net' })
        $folder = Join-Path $TestDrive 'single-out'
        New-Item -ItemType Directory -Path $folder | Out-Null
        'keep me' | Set-Content (Join-Path $folder 'notes.txt')
        $null = & $generator -EvidencePath $pack -OutputPath $folder
        $kv = Get-Content (Join-Path $folder 'CR-06-key-vault-purge-protection.txt') -Raw
        $kv | Should -Match 'Enable purge protection on the key vault listed below\.'
        $kv | Should -Match 'go to Key vaults and open the key vault listed in the RESOURCES section\.'
        $kv | Should -Match 'kv-only, resource group rg-app, soft delete retention 90 days' -Because 'a missing retention reads as the 90 day default'
        $kv | Should -Not -Match 'Repeat steps'
        $kvEmail = Get-Content (Join-Path $folder 'CR-06-key-vault-purge-protection.email.txt') -Raw
        Assert-ApprovalEmail $kvEmail 'CR-06 for one vault'
        $kvEmail | Should -Match 'I would like your approval to turn on purge protection for one of your Azure key vaults\.'
        $kvEmail | Should -Match 'The vault is listed below with its soft delete retention period'
        $kvEmail | Should -Match "Subscription Example Production \($s1\):\r?\n\r?\n- kv-only \(resource group rg-app, soft delete retention 90 days\)" -Because 'a missing retention reads as the 90 day default in the email too'
        $kvEmail | Should -Match 'Could you approve purge protection on this vault for \w+day, '
        $email = Get-Content (Join-Path $folder 'CR-08-app-service-https-only.email.txt') -Raw
        Assert-ApprovalEmail $email 'CR-08 for one application'
        $email | Should -Match 'I would like your approval to turn on the HTTPS Only setting for one of your App Service and Function applications\. With it on, requests made over plain HTTP are redirected to HTTPS, the encrypted form of HTTP\.'
        $email | Should -Match 'The setting makes sure every request to the application is encrypted in transit\.'
        $email | Should -Match 'still call the application over HTTP\?'
        $email | Should -Match '^Subject: .*\r?\n\r?\nHello,\r?\n' -Because 'without a contact the email opens with Hello'
        $email | Should -Match 'Thank you,\r?\n$'
        Get-Content (Join-Path $folder 'notes.txt') -Raw | Should -Match 'keep me'
        Test-Path (Join-Path $pack '05-change-requests') | Should -BeFalse
    }

    It 'reports an unreadable result file instead of reading it as no gaps' {
        $pack = Join-Path $TestDrive 'damaged'
        New-ChangeFixture $pack
        '{"Name": "kv-app", ' | Set-Content (Join-Path $pack 'results/DP.2-DETAIL.json')
        Remove-Item (Join-Path $pack 'results/NB.5-DETAIL.json')
        '' | Set-Content (Join-Path $pack 'results/NB.4-DETAIL.json')
        'not json' | Set-Content (Join-Path $pack 'results/DP.1-CONTAINERS.json')
        $null = & $generator -EvidencePath $pack -WarningAction SilentlyContinue
        $out = Join-Path $pack '05-change-requests'
        foreach ($f in 'CR-04-app-service-minimum-tls.txt', 'CR-06-key-vault-purge-protection.txt', 'CR-08-app-service-https-only.txt') { Test-Path (Join-Path $out $f) | Should -BeFalse -Because $f }
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '\| 04 \| .* \| Result file unreadable \(NB\.5-DETAIL\), recollect or restore the pack \|'
        $index | Should -Match '\| 06 \| .* \| Result file unreadable \(DP\.2-DETAIL\), recollect or restore the pack \|'
        $index | Should -Match '\| 08 \| .* \| Result file unreadable \(NB\.4-DETAIL\), recollect or restore the pack \|'
        Test-Path (Join-Path $out 'CR-07-storage-anonymous-access.txt') | Should -BeFalse -Because 'without the container list no account can be shown safe to change'
        Test-Path (Join-Path $out 'CR-07-storage-anonymous-access.email.txt') | Should -BeFalse
        $index | Should -Match '\| 07 \| Anonymous blob access disabled on storage accounts \|  \| No gaps found \|  \|'
        $index | Should -Match ([regex]::Escape('- 2 storage accounts left out of CR-07 because their containers were not read, since the DP.1-CONTAINERS result file is unreadable: stdata (resource group rg-data), stweb (resource group rg-web). Without the container list it cannot be shown that turning the setting off is safe, so recollect the pack.'))
    }

    It 'leaves out of the anonymous access change every account whose containers were not all listed' {
        $pack = Join-Path $TestDrive 'containers'
        New-ChangeFixture $pack
        $sa = { param($name, $rg, $sub) "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Storage/storageAccounts/$name" }
        $account = { param($name, $rg, $sub, $allow = $true, $kind = 'StorageV2') @{ Name = $name; ResourceId = (& $sa $name $rg $sub); Kind = $kind; resourceGroup = $rg; subscriptionId = $sub; SecureTransfer = $true; MinimumTlsVersion = 'TLS1_2'; AllowBlobPublicAccess = $allow; NfsV3 = $false } }
        $listed = { param($name, $rg, $sub, $count, $public = 0, $names = '', $status = 'OK') @{ Account = $name; ResourceId = (& $sa $name $rg $sub); Containers = $count; PublicContainers = $public; ExposedContainers = $public; PublicContainerNames = $names; ReadStatus = $status } }
        Set-PackResult $pack 'DP.1-DETAIL' @(
            (& $account 'stclosed' 'rg-data' $s1)
            (& $account 'stempty' 'rg-data' $s2)
            (& $account 'stone' 'rg-app' $s2)
            (& $account 'stpublic' 'rg-web' $s1)
            (& $account 'stmissing' 'rg-data' $s1)
            (& $account 'stdenied' 'rg-data' $s2)
            (& $account 'stblocked' 'rg-data' $s1 $false)
            (& $account 'stfiles' 'rg-files' $s2 $true 'FileStorage'))
        Set-PackResult $pack 'DP.1-CONTAINERS' @(
            (& $listed 'stclosed' 'rg-data' $s1 6)
            (& $listed 'stempty' 'rg-data' $s2 0)
            (& $listed 'stone' 'rg-app' $s2 1)
            (& $listed 'stpublic' 'rg-web' $s1 3 1 'assets (Container)')
            (& $listed 'stdenied' 'rg-data' $s2 0 0 '' 'HTTP 403: Forbidden')
            (& $listed 'stblocked' 'rg-data' $s1 2)) 'PARTIAL'
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '\| 07 \| Anonymous blob access disabled on storage accounts \| 3 \| Change request and client email, partial collection scope \|'
        $text = Get-Content (Join-Path $out 'CR-07-storage-anonymous-access.txt') -Raw
        @(Get-Section $text 'C) RESOURCES') | Should -Be @(
            'The 3 storage accounts below allow anonymous blob access, with the containers listed at collection. No container in them is set to Blob or Container access.'
            "Subscription: Example Production ($s1)"
            '- stclosed, resource group rg-data, 6 containers, all private'
            "Subscription: Example, Dev Test ($s2)"
            '- stone, resource group rg-app, 1 container, private'
            '- stempty, resource group rg-data, no containers')
        $text | Should -Match '6\. Repeat steps 1 to 5 for each remaining storage account listed\.' -Because 'the change-time check repeats for every account'
        @(Get-Section $text 'B) USER EXPERIENCE')[0] | Should -Be 'No change, since no container in these accounts allows anonymous access and a static website hosted in a storage account is not affected by the setting.'
        $text | Should -Not -Match 'stpublic|stmissing|stdenied|stblocked|stfiles'
        $email = Get-Content (Join-Path $out 'CR-07-storage-anonymous-access.email.txt') -Raw
        Assert-ApprovalEmail $email 'CR-07 for three accounts'
        $email | Should -Match 'at the account level on 3 of your storage accounts\.'
        $email | Should -Match "The accounts are listed below by subscription:\r?\n\r?\nSubscription Example Production \($s1\):\r?\n\r?\n- stclosed \(resource group rg-data\)\r?\n\r?\nSubscription Example, Dev Test \($s2\):\r?\n\r?\n- stone \(resource group rg-app\)\r?\n- stempty \(resource group rg-data\)"
        $email | Should -Match '- Every container in these accounts is private today, so no one reads their blob data without signing in\.'
        $email | Should -Match '- Just before the change, I will check the containers of each account again, and skip any account where a container has been made public since my review\.'
        $email | Should -Match 'I can turn the setting back on straight away'
        $email | Should -Not -Match '(?i)lose access|loses access|stpublic|stmissing|stdenied|could not read'
        @(Import-Csv (Join-Path $out 'change-requests.csv') | Where-Object CR -eq 'CR-07' | ForEach-Object Resource) | Should -Be @('stclosed', 'stempty', 'stone')
        $index | Should -Match ([regex]::Escape('- 1 storage account left out of CR-07 because it has a container set to Blob or Container access, which anyone can read today without signing in: stpublic (resource group rg-web): assets (Container).'))
        $index | Should -Match ([regex]::Escape('- 1 storage account left out of CR-07 because DP.1-CONTAINERS did not list its containers: stmissing (resource group rg-data). Without the container list it cannot be shown that turning the setting off is safe, so recollect the pack.'))
        $index | Should -Match ([regex]::Escape('- 1 storage account left out of CR-07 because DP.1-CONTAINERS reads PARTIAL and could not list its containers: stdenied (resource group rg-data). Only an account whose containers were all listed can qualify, so recollect the pack.'))
        $index | Should -Not -Match 'stblocked|stfiles' -Because 'an account that blocks anonymous access, or holds no blob service, is not a gap'
    }

    It 'reads No gaps found when no account qualifies, and still names the accounts left out' {
        $pack = Join-Path $TestDrive 'containers-none'
        New-ChangeFixture $pack
        $sa = { param($name, $rg, $sub) "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Storage/storageAccounts/$name" }
        Set-PackResult $pack 'DP.1-CONTAINERS' @(
            @{ Account = 'stdata'; ResourceId = (& $sa 'stdata' 'rg-data' $s1); Containers = 2; PublicContainers = 1; ExposedContainers = 1; PublicContainerNames = 'exports (Blob)'; ReadStatus = 'OK' }
            @{ Account = 'stweb'; ResourceId = (& $sa 'stweb' 'rg-web' $s1); Containers = 3; PublicContainers = 2; ExposedContainers = 2; PublicContainerNames = 'images (Blob), downloads (Container)'; ReadStatus = 'OK' })
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        Test-Path (Join-Path $out 'CR-07-storage-anonymous-access.txt') | Should -BeFalse
        Test-Path (Join-Path $out 'CR-07-storage-anonymous-access.email.txt') | Should -BeFalse
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '\| 07 \| Anonymous blob access disabled on storage accounts \|  \| No gaps found \|  \|'
        $index | Should -Match ([regex]::Escape('- 2 storage accounts left out of CR-07 because each has a container set to Blob or Container access, which anyone can read today without signing in: stdata (resource group rg-data): exports (Blob) / stweb (resource group rg-web): images (Blob), downloads (Container).'))
        @(Import-Csv (Join-Path $out 'change-requests.csv') | Where-Object CR -eq 'CR-07').Count | Should -Be 0
    }

    It 'cleans every character the copy check rejects from pack values instead of stopping' {
        $pack = Join-Path $TestDrive 'symbols'
        New-ChangeFixture $pack
        Set-PackResult $pack 'P0.7' @(@{ subscriptionId = $s1; SubscriptionName = ('Prod {0} EU {1}' -f [char]0x25BA, [char]0x25B6) }, @{ subscriptionId = $s2; SubscriptionName = ('Dev {0}' -f [char]0x2192) })
        { $null = & $generator -EvidencePath $pack } | Should -Not -Throw
        $text = Get-Content (Join-Path $pack '05-change-requests/CR-06-key-vault-purge-protection.txt') -Raw
        $text | Should -Match "Subscription: Prod EU \($s1\)"
        $text | Should -Match "Subscription: Dev \($s2\)"
    }

    It 'notes the results a change request read beyond its sources when they were partial or not collected' {
        $pack = Join-Path $TestDrive 'secondary'
        New-ChangeFixture $pack
        Set-PackResult $pack 'DP.1-CONTAINERS' @() 'FAILED'
        Set-PackResult $pack 'DR.6-INITIATIVE' @(@{ DefinitionName = 'ATMO-MXDR-KV-TOSENT'; Resources = 6; Compliant = 5; NonCompliant = 1 })
        Set-PackResult $pack 'DR.6-NONCOMPLIANT' @(@{ ResourceId = "/subscriptions/$s1/resourcegroups/rg-app/providers/microsoft.keyvault/vaults/kv-app"; ResourceType = 'microsoft.keyvault/vaults'; AssignmentName = 'ATMO-MXDR-DIAG-TOSENT'; AssignmentId = "/subscriptions/$s1/providers/microsoft.authorization/policyassignments/a1"; Policies = 'ATMO-MXDR-KV-TOSENT' }) 'PARTIAL'
        Set-PackResult $pack 'DP.4-VMSS-ELIGIBILITY' @() 'FAILED'
        $null = & $generator -EvidencePath $pack
        $index = Get-Content (Join-Path $pack '05-change-requests/00-index.md') -Raw
        $index | Should -Match ([regex]::Escape('- 2 storage accounts left out of CR-07 because their containers were not read, since DP.1-CONTAINERS reads FAILED: stdata (resource group rg-data), stweb (resource group rg-web).'))
        $index | Should -Match '\| 07 \| Anonymous blob access disabled on storage accounts \|  \| No gaps found \|'
        $index | Should -Match 'CR-09 was written without DP\.4-VMSS-ELIGIBILITY, which reads FAILED\.'
        $index | Should -Match '\| 15 \| Encryption at host on virtual machine scale sets \|  \| Not collected \(DP\.4-VMSS-ELIGIBILITY FAILED\) \|'
        $text = Get-Content (Join-Path $pack '05-change-requests/CR-09-encryption-at-host.txt') -Raw
        $text | Should -Match 'vm-flex-1' -Because 'without the scale set list CR-09 keeps the Flexible instances, which take the setting as virtual machines'
        $text | Should -Not -Match 'vm-flexade-1' -Because 'an ineligible instance stays out'
        $index | Should -Match '\| 10 \| .* \| 1 \| Change request and client email, partial collection scope \|' -Because 'a partial resource list must not read as complete'
    }

    It 'lists no covered resource type when the estate inventory holds none of them' {
        $pack = Join-Path $TestDrive 'inventory'
        New-ChangeFixture $pack
        Set-PackResult $pack 'P0.5' @(@{ subscriptionId = $s1; ResourceType = 'microsoft.compute/virtualmachines'; Resources = 9 })
        $null = & $generator -EvidencePath $pack
        $text = Get-Content (Join-Path $pack '05-change-requests/CR-01-diagnostic-logging.txt') -Raw
        $text | Should -Match 'Resource types the initiative covers:\r?\n- Subscription Activity Log: 2'
        $text | Should -Match 'covers the resource types listed with their current counts\.'
        Set-PackResult $pack 'P0.5' @(@{ Resources = 240 })
        $null = & $generator -EvidencePath $pack
        $text = Get-Content (Join-Path $pack '05-change-requests/CR-01-diagnostic-logging.txt') -Raw
        $text | Should -Match '- Key vaults\r?\n- Automation accounts' -Because 'an inventory without resource types lists every covered type without a count'
        $text | Should -Not -Match 'with their current counts'
    }

    It 'stops when the pack is not finished' {
        $pack = Join-Path $TestDrive 'unfinished'
        New-Item -ItemType Directory -Path $pack | Out-Null
        { & $generator -EvidencePath $pack } | Should -Throw '*missing 00-parameters.json*'
    }
}
Describe 'Windows PowerShell 5.1, where ConvertFrom-Json writes a JSON array as one object' {
    It 'reads JSON as Windows PowerShell 5.1 does, so the test below cannot pass by accident' {
        (Invoke-WithWindowsPowerShellJson { , @('[{"a":1},{"a":2}]' | ConvertFrom-Json | Where-Object { $null -ne $_ }) }).Count | Should -Be 1
    }
    It 'lists every resource of a result in its change request' {
        $pack = Join-Path $TestDrive 'windows-powershell'
        New-ChangeFixture $pack
        Invoke-WithWindowsPowerShellJson { $null = & $generator -EvidencePath $pack }
        $text = Get-Content (Join-Path $pack '05-change-requests/CR-03-storage-minimum-tls.txt') -Raw
        $text | Should -Match "Subscription: Example Production \($s1\)\r?\n- stdata, resource group rg-data, minimum TLS 1\.0\r?\n- stweb, resource group rg-web, minimum TLS not set"
        $text | Should -Match 'Set the minimum TLS version to 1\.2 on the 2 storage accounts listed below\.'
        $rules = Get-Content (Join-Path $pack '05-change-requests/CR-16-management-ports.txt') -Raw
        $rules | Should -Match 'destination ports \(22, 443\), description "Jump box access, vendor", applies to network interface nic-jump01 of virtual machine vm-jump01' -Because 'the lists inside each rule read the same way'
        $rules | Should -Match 'Remove the 2 inbound security rules listed below'
    }

    It 'reads a rule list given as JSON text as its items' {
        $pack = Join-Path $TestDrive 'windows-powershell-text'
        New-ChangeFixture $pack
        $id = "/subscriptions/$s1/resourceGroups/rg-web/providers/Microsoft.Network/networkSecurityGroups/nsg-web"
        $vm = "/subscriptions/$s1/resourcegroups/rg-web/providers/microsoft.compute/virtualmachines/vm-web01"
        $nic = "/subscriptions/$s1/resourcegroups/rg-web/providers/microsoft.network/networkinterfaces/nic-web01"
        Set-PackResult $pack 'NB.2-DETAIL' @(@{ subscriptionId = $s1; resourceGroup = 'rg-web'; NSG = 'nsg-web'; NsgId = $id; RuleName = 'Allow-SSH'; RuleId = "$id/securityRules/Allow-SSH"; Priority = 120; Protocol = 'Tcp'
                SourcePrefixes = '["","Internet","0.0.0.0/0"]'; SourcePorts = '["*"]'; DestinationPrefixes = '["*"]'; DestinationAsgs = '[]'; DestinationPorts = '["22","3389"]'; Association = 'NIC'
                Subnets = '[]'; Nics = ('[{{"id":"{0}"}}]' -f $nic); NicVms = ('[{{"NicId":"{0}","VmId":"{1}"}}]' -f $nic, $vm); ApplianceNicIds = '[]'; ApplianceSubnetIds = '[]' })
        Invoke-WithWindowsPowerShellJson { $null = & $generator -EvidencePath $pack }
        Get-Content (Join-Path $pack '05-change-requests/CR-16-management-ports.txt') -Raw | Should -Match 'source \(Internet, 0\.0\.0\.0/0\), source ports \*, destination \*, destination ports \(22, 3389\), applies to network interface nic-web01 of virtual machine vm-web01'
    }
}
