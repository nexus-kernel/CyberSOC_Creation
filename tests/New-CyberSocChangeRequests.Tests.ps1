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
            'CR-11-redis-minimum-tls.txt', 'CR-12-service-bus-minimum-tls.txt', 'CR-13-event-hubs-minimum-tls.txt', 'CR-14-cosmos-db-minimum-tls.txt', 'CR-15-scale-set-encryption-at-host.txt')
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
            $text | Should -Not -Match '[←-⇿➔➡▶►]|->|=>' -Because $f.Name
            $text | Should -Not -Match '[☀-➿]|[\uD800-\uDFFF]' -Because $f.Name
            ($text -replace '[A-Za-z0-9)] > [A-Za-z]', '') | Should -Not -Match '>' -Because "$($f.Name) uses the greater-than sign only in navigation steps"
            $text | Should -Not -Match '(?i)\b(we|our|ours|us)\b' -Because "$($f.Name) reads as written by one person"
        }
        & $read 'CR-06-key-vault-purge-protection.txt' | Should -Match 'Subscription: Example, Dev Test \(a0b1c2d3' -Because 'pack values are cleaned of semicolons and angle brackets'
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

    It 'writes the anonymous access email as a no-risk notice with the fallback' {
        $email = & $read 'CR-07-storage-anonymous-access.email.txt'
        $email | Should -Match '^Subject: Planned change: turning off anonymous access to Azure Blob Storage\r?\n\r?\nHello Dana,'
        $email | Should -Match '\bI am planning a security hardening change that turns off anonymous access to Azure Blob Storage at the account level on one of your storage accounts\.'
        $email | Should -Match 'no container in it can be opened to anonymous access later, by mistake or by a misconfigured deployment\.'
        $email | Should -Match "The account is listed below:\r?\n\r?\nSubscription Example Production \($s1\):\r?\n\r?\n- stdata \(resource group rg-data\)\r?\n"
        $email | Should -Match 'I do not expect this change to affect anything that uses the account today, for these reasons:'
        $email | Should -Match '- Every container in the account is private today, so no one reads its blob data without signing in\.'
        $email | Should -Match '- A static website hosted in a storage account keeps serving as it does now, since the setting does not apply to it\.' -Because 'the static website container stays public whatever the account setting'
        $email | Should -Match '- Applications and people that sign in, or that use a shared access signature or an account key, keep working as they do now\.'
        $email | Should -Match '- Just before the change, I will check the containers of the account again, and leave it unchanged if a container has been made public since my review\.'
        $email | Should -Match 'If anything unexpected comes up, I can turn the setting back on straight away\. It takes up to 30 seconds to apply, and the containers stay as they are\.'
        $email | Should -Match 'Could you confirm that I can go ahead and schedule the change\?'
        $email | Should -Not -Match '(?i)lose access|loses access|stweb|images|downloads' -Because 'the email lists only the accounts in the change'
        $email | Should -Match 'Thank you,\r?\nScott Example\r?\n$'
    }

    It 'asks for written approval of purge protection, with the vaults by subscription and their retention' {
        $email = & $read 'CR-06-key-vault-purge-protection.email.txt'
        $email | Should -Match '^Subject: Approval request: purge protection for Azure key vaults\r?\n\r?\nHello Dana,'
        $email | Should -Match '\bI am planning\b' -Because 'the email is written in the first person singular'
        $email | Should -Match "Subscription Example Production \($s1\):\r?\n\r?\n- kv-app \(resource group rg-app, soft delete retention 90 days\)\r?\n\r?\nSubscription Example, Dev Test \($s2\):\r?\n\r?\n- kv-dev \(resource group rg-dev, soft delete retention 7 days\)"
        $email | Should -Match 'Purge protection cannot be turned off once it is enabled, by anyone including Microsoft, so this change cannot be reverted\.'
        $email | Should -Match 'a deleted vault, key, secret or certificate is kept for the retention period of its vault and cannot be purged early\.'
        $email | Should -Match 'A deleted vault keeps its name until then, so the name cannot be reused'
        $email | Should -Match 'I need your written approval before I schedule it\. Could you reply to confirm that I can enable purge protection on these vaults\?'
        $email | Should -Match 'Thank you,\r?\nScott Example\r?\n$'
        $index | Should -Not -Match 'approved purge protection at build kickoff'
        @(Get-Section (& $read 'CR-06-key-vault-purge-protection.txt') 'E) MITIGATION')[0] | Should -Match '^Purge protection cannot be disabled once it is enabled' -Because 'the change request keeps its own mitigation'
    }

    It 'drafts the HTTPS Only email with the host names and asks about HTTP callers' {
        $email = & $read 'CR-08-app-service-https-only.email.txt'
        $email | Should -Match 'the 2 App Service applications below'
        $email | Should -Match '- app-portal \(app-portal\.azurewebsites\.net\)\r?\n- func-jobs \(func-jobs\.azurewebsites\.net\)'
        $email | Should -Match 'still call these applications over HTTP\?'
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
        $email | Should -Match 'Could you suggest a maintenance window'
        $email | Should -Not -Match 'VM ID|1a2b3c4d' -Because 'the IDs are for the operator, and the client email keeps to the servers'
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
        $email | Should -Match '^Subject: Maintenance window request: encryption at host for Azure virtual machine scale sets\r?\n\r?\nHello Dana,'
        $email | Should -Match 'I am planning to enable encryption at host on the 3 virtual machine scale sets below\.'
        $email | Should -Match '- vmss-batch \(resource group rg-batch, 1 instance\)\r?\n- vmss-flex \(resource group rg-app, 2 instances\)\r?\n- vmss-web \(resource group rg-web, 4 instances\)'
        $email | Should -Match 'which I will do one instance at a time'
        $email | Should -Match 'an instance that is already stopped will be left stopped'
        $email | Should -Match 'One scale set is set to update its instances automatically, so once the setting is applied it may also restart them on its own, all at the same time under the Automatic policy and in batches under the Rolling policy\. I will plan the window as if every instance could be unavailable at once: vmss-web \(Rolling\)\.'
        $email | Should -Match 'Could you suggest a maintenance window that works for these scale sets'
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

    It 'sets minimum TLS 1.2 on Redis, Service Bus and Cosmos DB with a notice and no rollback, since each already refuses TLS 1.0 and 1.1' {
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
            (& $read "$($c.File).email.txt") | Should -Match '^Subject: Notice of planned change: ' -Because "$($c.File) changes nothing a client can still use, so it needs no approval"
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
        $email | Should -Match '^Subject: Planned change: minimum TLS 1\.2 for Azure Event Hubs namespaces\r?\n\r?\nHello Dana,'
        $email | Should -Match 'I am planning a security hardening change that sets the minimum TLS version to 1\.2 on the 2 Event Hubs namespaces below\.'
        $email | Should -Match '- evh-audit \(resource group rg-logs, minimum TLS 1\.1\)\r?\n- evh-telemetry \(resource group rg-msg, minimum TLS 1\.0\)'
        $email | Should -Match 'Could you let me know whether anything that connects to these namespaces may still use TLS 1\.0 or 1\.1\?'
        $email | Should -Match 'Thank you,\r?\nScott Example\r?\n$'
    }

    It 'writes a notice of planned change for every change that does not need the client first, and keeps the other emails' {
        $today = (Get-Date).ToUniversalTime().Date
        $planned = $today.AddDays(14).ToString('dddd, MMMM d, yyyy', [cultureinfo]::InvariantCulture)
        $reply = $today.AddDays(7).ToString('dddd, MMMM d, yyyy', [cultureinfo]::InvariantCulture)
        $notices = @{
            'CR-01-diagnostic-logging' = 'diagnostic logging for Azure resources'
            'CR-02-storage-secure-transfer' = 'secure transfer for Azure storage accounts'
            'CR-03-storage-minimum-tls' = 'minimum TLS 1\.2 for Azure storage accounts'
            'CR-04-app-service-minimum-tls' = 'minimum TLS 1\.2 for Azure App Service applications'
            'CR-11-redis-minimum-tls' = 'minimum TLS 1\.2 for Azure Cache for Redis'
            'CR-12-service-bus-minimum-tls' = 'minimum TLS 1\.2 for Azure Service Bus namespaces'
            'CR-14-cosmos-db-minimum-tls' = 'minimum TLS 1\.2 for Azure Cosmos DB accounts' }
        foreach ($k in $notices.Keys) {
            $email = & $read "$k.email.txt"
            $email | Should -Match ('^Subject: Notice of planned change: {0}\r?\n\r?\nHello Dana,\r?\n\r?\nI plan to ' -f $notices[$k]) -Because $k
            $email | Should -Match "Subscription Example[^\r\n]*\((5f1c2a9e|a0b1c2d3)[^\r\n]*\):\r?\n\r?\n- " -Because "$k lists the resources by subscription"
            $email | Should -Match ('I plan to make this change on or after {0}\. If you have a concern about it, or anything listed above should stay out of it, please let me know by {1} and I will hold the change until your concern is resolved\.\r?\n\r?\nThank you,\r?\nScott Example\r?\n$' -f $planned, $reply) -Because "$k gives the planned date and a week to raise a concern"
            $email | Should -Not -Match '(?i)\bplease (approve|confirm)|maintenance window' -Because "$k needs no approval"
        }
        $kept = @{
            'CR-06-key-vault-purge-protection' = 'Approval request: purge protection'; 'CR-07-storage-anonymous-access' = 'Planned change: turning off anonymous access'
            'CR-08-app-service-https-only' = 'Planned change: HTTPS only'; 'CR-09-encryption-at-host' = 'Maintenance window request: encryption at host for Azure virtual machines'
            'CR-13-event-hubs-minimum-tls' = 'Planned change: minimum TLS 1\.2 for Azure Event Hubs'; 'CR-15-scale-set-encryption-at-host' = 'Maintenance window request: encryption at host for Azure virtual machine scale sets' }
        foreach ($k in $kept.Keys) {
            $email = & $read "$k.email.txt"
            $email | Should -Match ('^Subject: {0}' -f $kept[$k]) -Because "$k keeps its approval, confirmation or maintenance window request"
            $email | Should -Not -Match 'I plan to make this change on or after' -Because "$k waits for the reply"
        }
        $index | Should -Match ('- CR-01, CR-02, CR-03, CR-04, CR-11, CR-12, CR-14 send a notice of planned change that plans the change for {0} and asks the client to raise any concern by {1}\. Run again with -ChangeDate' -f $planned, $reply)
        $index | Should -Match 'a change with a notice of planned change goes ahead on its planned date unless the client raises a concern\.'
    }

    It 'says what each notice changes, why, and what the client should expect' {
        $email = & $read 'CR-02-storage-secure-transfer.email.txt'
        $email | Should -Match 'I plan to turn on Secure transfer required on 2 of your storage accounts, so they accept encrypted connections only\. Requests over plain HTTP and SMB connections without encryption expose data and credentials in transit\.'
        $email | Should -Match "The accounts are listed below by subscription:\r?\n\r?\nSubscription Example Production \($s1\):\r?\n\r?\n- stdata \(resource group rg-data\)\r?\n- stweb \(resource group rg-web\)\r?\n"
        $email | Should -Match 'Azure Storage rejects any request made over HTTP and any SMB connection without encryption, such as SMB 2\.1, so a system that still connects to these accounts that way would stop working'
        $email | Should -Not -Match 'stnfsblob|stpremfiles' -Because 'the accounts left out of the change are not in its email'
        $email = & $read 'CR-03-storage-minimum-tls.email.txt'
        $email | Should -Match 'Azure Storage stopped accepting TLS 1\.0 and 1\.1 on February 3, 2026, but these accounts still allow an older version in their configuration'
        $email | Should -Match '- stdata \(resource group rg-data, minimum TLS 1\.0\)\r?\n- stweb \(resource group rg-web, minimum TLS not set\)'
        $email | Should -Match 'I do not expect any visible effect, because Azure Storage already refuses TLS 1\.0 and 1\.1, so every connection that works today keeps working\.'
        $email = & $read 'CR-04-app-service-minimum-tls.email.txt'
        $email | Should -Match 'I plan to set the minimum inbound TLS version to 1\.2 on one of your App Service and Function applications\. TLS 1\.0 and 1\.1 have known weaknesses, and App Service stops accepting them on May 31, 2027'
        $email | Should -Match 'The application is listed below with its minimum TLS version today:'
        $email | Should -Match 'A client that can only use TLS 1\.0 or 1\.1, for example one on an old operating system or runtime, will no longer be able to connect to the application once the change is applied\.'
        $email | Should -Not -Match 'app-blank'
        (& $read 'CR-11-redis-minimum-tls.email.txt') | Should -Match 'Azure Cache for Redis has refused TLS 1\.0 and 1\.1 on every cache since April 1, 2025, but this cache still records an older minimum'
        (& $read 'CR-12-service-bus-minimum-tls.email.txt') | Should -Match '- sb-orders \(resource group rg-msg, minimum TLS not set\)'
        (& $read 'CR-14-cosmos-db-minimum-tls.email.txt') | Should -Match "Azure Cosmos DB retired TLS 1\.0 and 1\.1 on August 31, 2025.*\r?\n\r?\n.*\r?\n\r?\nSubscription Example, Dev Test \($s2\):\r?\n\r?\n- cosmos-catalog \(resource group rg-data, minimum TLS 1\.0\)"
    }

    It 'tells the client that diagnostic logging adds Log Analytics ingestion to their Sentinel workspace' {
        $email = & $read 'CR-01-diagnostic-logging.email.txt'
        $email | Should -Match 'by assigning the ATMO-MXDR-DIAG-TOSENT Azure Policy initiative on each subscription below\. The initiative adds diagnostic settings that send the audit logs of the supported resources to your Sentinel workspace law-example-sentinel, including resources created later'
        $email | Should -Match "Each subscription is listed below with the resources the initiative covers and how many each holds today:\r?\n\r?\nSubscription Example Production \($s1\):\r?\n\r?\n- Key vaults: 4\r?\n- Subscription Activity Log\r?\n\r?\nSubscription Example, Dev Test \($s2\):\r?\n\r?\n- Key vaults: 2\r?\n- Subscription Activity Log\r?\n" -Because 'each subscription is counted on its own'
        $email | Should -Match 'I do not expect any visible effect on these resources or the people who use them\. A diagnostic setting only sends the logs a resource already produces to the workspace, and does not change how the resource runs\.'
        $email | Should -Match 'This change adds Log Analytics ingestion to your Sentinel workspace law-example-sentinel\. The resource logs are billed as data ingested into the workspace, and their volume depends on how busy each resource is\. The Azure Activity log of each subscription is ingested at no charge\.'
    }

    It 'lists one row per resource in the CSV' {
        @($csv | Where-Object CR -eq 'CR-06').Resource | Should -Be @('kv-app', 'kv-dev')
        ($csv | Where-Object { $_.CR -eq 'CR-04' }).CurrentSetting | Should -Be 'minimum TLS 1.0'
        ($csv | Where-Object { $_.CR -eq 'CR-14' }).CurrentSetting | Should -Be 'minimum TLS 1.0' -Because 'Cosmos DB writes TLS 1.0 as Tls'
        ($csv | Where-Object { $_.CR -eq 'CR-12' }).ResourceId | Should -Be "/subscriptions/$s1/resourceGroups/rg-msg/providers/Microsoft.ServiceBus/namespaces/sb-orders"
        @($csv | Where-Object CR -eq 'CR-13').Resource | Should -Be @('evh-telemetry', 'evh-audit')
        @($csv | Where-Object CR -eq 'CR-01').Count | Should -Be 2
        ($csv | Where-Object { $_.CR -eq 'CR-09' -and $_.Resource -eq 'vm-old' }).ResourceId | Should -Be "/subscriptions/$s2/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-old"
        @($csv | Where-Object { -not $_.ResourceId }).Count | Should -Be 0 -Because 'every tracking row carries the resource ID'
    }
}

Describe 'Change request variants' {
    It 'writes a purge protection notice that refers to the build kickoff approval when the client gave it, and records the approval' {
        $pack = Join-Path $TestDrive 'approved'
        New-ChangeFixture $pack
        $out = Join-Path $pack '05-change-requests'
        $null = & $generator -EvidencePath $pack
        Get-Content (Join-Path $out 'CR-06-key-vault-purge-protection.email.txt') -Raw | Should -Match '^Subject: Approval request: '
        $files = @(& $generator -EvidencePath $pack -PurgeProtectionApproved -ClientContact 'Dana')
        @($files | Where-Object { $_ -like '*CR-06*' } | ForEach-Object { Split-Path -Leaf $_ }) | Should -Be @('CR-06-key-vault-purge-protection.txt', 'CR-06-key-vault-purge-protection.email.txt')
        $email = Get-Content (Join-Path $out 'CR-06-key-vault-purge-protection.email.txt') -Raw
        $email | Should -Match '^Subject: Notice of planned change: purge protection for Azure key vaults\r?\n\r?\nHello Dana,' -Because 'the approval request from the earlier run is replaced'
        $email | Should -Match 'As you approved at the build kickoff, I plan to turn on purge protection for 2 of your Azure key vaults\.'
        $email | Should -Match "Subscription Example Production \($s1\):\r?\n\r?\n- kv-app \(resource group rg-app, soft delete retention 90 days\)\r?\n\r?\nSubscription Example, Dev Test \($s2\):\r?\n\r?\n- kv-dev \(resource group rg-dev, soft delete retention 7 days\)"
        $email | Should -Match 'Nothing changes for the applications and people that read or write these vaults today\.'
        $email | Should -Match 'As a reminder, purge protection cannot be turned off once it is enabled, by anyone including Microsoft\.'
        $email | Should -Match 'a deleted vault keeps its name until then, so the name cannot be reused'
        $email | Should -Match 'I plan to make this change on or after \w+day, '
        $email | Should -Not -Match '(?i)written approval|Could you reply to confirm' -Because 'the approval was already given'
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '\| 06 \| Purge protection on key vaults \| 2 \| Change request and client email \| CR-06-key-vault-purge-protection\.txt, CR-06-key-vault-purge-protection\.email\.txt \|'
        $index | Should -Match '- CR-06 sends a notice of planned change instead of an approval request because the client approved purge protection at build kickoff \(-PurgeProtectionApproved\)\. Attach that approval to the change request\.'
        $index | Should -Match 'CR-01, CR-02, CR-03, CR-04, CR-06, CR-11, CR-12, CR-14 send a notice of planned change'
        $kv = Get-Content (Join-Path $out 'CR-06-key-vault-purge-protection.txt') -Raw
        @(Get-Section $kv 'E) MITIGATION')[0] | Should -Match '^Purge protection cannot be disabled once it is enabled, so this change cannot be reverted\.'
        Get-Content (Join-Path $out 'CR-07-storage-anonymous-access.email.txt') -Raw | Should -Match '^Subject: Planned change: turning off anonymous access' -Because 'the switch covers purge protection only'
    }

    It 'writes a client email for every change request, CR-01 to CR-15' {
        # The full fixture writes every change but CR-05 and CR-10. This pack adds an Azure SQL server and a
        # resource the diagnostic logging initiative reports as not compliant, so between them every change is
        # written at least once. A change request written without its email fails here.
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
                $text | Should -Match '^Subject: \S' -Because $cr.Name
                $text | Should -Not -Match ';|[<>]|->|=>' -Because "$($cr.Name) email keeps to the copy rules"
                $text | Should -Not -Match '(?i)\b(we|our|ours|us)\b' -Because "$($cr.Name) email reads as written by one person"
                $index | Should -Match ('\| {0} \| [^|]+ \| \d+ \| Change request and client email(, partial collection scope)? \| {1}, {2} \|' -f $number, [regex]::Escape($cr.Name), [regex]::Escape($cr.BaseName + '.email.txt')) -Because $cr.Name
            }
            $index | Should -Not -Match '\| Change request \|' -Because 'no change request is listed without its email'
        }
        @($written | Sort-Object -Unique) | Should -Be @(1..15) -Because 'the two packs between them write every change request'
        $sql = Get-Content (Join-Path $more '05-change-requests/CR-05-sql-minimum-tls.email.txt') -Raw
        $sql | Should -Match '^Subject: Notice of planned change: minimum TLS 1\.2 for Azure SQL servers'
        $sql | Should -Match 'Azure SQL retired TLS 1\.0 and 1\.1 on August 31, 2025, but this server does not enforce a minimum of 1\.2'
        $sql | Should -Match "Subscription Example Production \($s1\):\r?\n\r?\n- sql-orders \(resource group rg-data, minimum TLS not set\)"
        $sql | Should -Match 'Once a minimum is set, Azure SQL does not allow a return to the unset default, which is why I am letting you know before I make the change\.'
    }

    It 'plans the notices for the day -ChangeDate names, and refuses a day that leaves the client less than a week' {
        $pack = Join-Path $TestDrive 'change-date'
        New-ChangeFixture $pack
        $day = (Get-Date).ToUniversalTime().Date.AddDays(30)
        $null = & $generator -EvidencePath $pack -ChangeDate $day
        $email = Get-Content (Join-Path $pack '05-change-requests/CR-03-storage-minimum-tls.email.txt') -Raw
        $email | Should -Match ('on or after {0}\. .* please let me know by {1} and' -f $day.ToString('dddd, MMMM d, yyyy', [cultureinfo]::InvariantCulture), $day.AddDays(-7).ToString('dddd, MMMM d, yyyy', [cultureinfo]::InvariantCulture))
        Get-Content (Join-Path $pack '05-change-requests/CR-13-event-hubs-minimum-tls.email.txt') -Raw | Should -Not -Match 'on or after' -Because 'a change that waits for the reply has no planned date'
        { & $generator -EvidencePath $pack -ChangeDate (Get-Date).ToUniversalTime().Date.AddDays(7) } | Should -Throw '*less than a week to raise a concern*'
        Get-Content (Join-Path $pack '05-change-requests/CR-03-storage-minimum-tls.email.txt') -Raw | Should -Be $email -Because 'a refused run leaves the earlier files as they were'
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
        $email | Should -Match 'on the virtual machine scale set below\.'
        $email | Should -Match 'vmss-auto \(Automatic\)'
        $email | Should -Match 'Could you suggest a maintenance window that works for this scale set\?'
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
        $email | Should -Match '^Subject: Notice of planned change: diagnostic logging remediation for Azure resources'
        $email | Should -Match 'I plan to run Azure Policy remediation tasks for the ATMO-MXDR-DIAG-TOSENT initiative on 3 of your Azure resources, which do not send their audit logs to your Sentinel workspace law-chosen today\.'
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

    It 'reads needs recollection on a pack collected before the per-resource results, and clears stale change requests' {
        $pack = Join-Path $TestDrive 'old'
        New-ChangeFixture $pack
        $null = & $generator -EvidencePath $pack
        foreach ($id in 'P0.7', 'NB.4-DETAIL', 'NB.5-DETAIL', 'NB.6-DETAIL', 'NB.6-PAAS-DETAIL', 'DP.1-DETAIL', 'DP.2-DETAIL', 'DP.4-VMSS-ELIGIBILITY') { Remove-PackResult $pack $id }
        Set-PackResult $pack 'DP.4-ELIGIBILITY' @() 'FAILED'
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        @(Get-ChildItem $out -Filter 'CR-*' | ForEach-Object Name | Sort-Object) -join '|' | Should -Be 'CR-01-diagnostic-logging.email.txt|CR-01-diagnostic-logging.txt' -Because 'change requests from the earlier run that this pack can no longer support are removed'
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '\| 02 \| Secure transfer required on storage accounts \|  \| Needs recollection with CyberSOC collector 1\.1\.0 or later \|'
        $index | Should -Match '\| 09 \| Encryption at host on virtual machines \|  \| Not collected \(DP\.4-ELIGIBILITY FAILED\) \|'
        foreach ($n in 11..14) { $index | Should -Match ('\| {0} \| [^|]+ \|  \| Needs recollection with CyberSOC collector 1\.2\.0 or later \|' -f $n) -Because 'NB.6-PAAS-DETAIL was added in 1.2.0' }
        $index | Should -Match '\| 15 \| Encryption at host on virtual machine scale sets \|  \| Needs recollection with CyberSOC collector 1\.3\.0 or later \|' -Because 'DP.4-VMSS-ELIGIBILITY was added in 1.3.0'
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
        $kvEmail | Should -Match 'turns on purge protection for one of your Azure key vaults\.'
        $kvEmail | Should -Match 'The vault is listed below with its soft delete retention period'
        $kvEmail | Should -Match "Subscription Example Production \($s1\):\r?\n\r?\n- kv-only \(resource group rg-app, soft delete retention 90 days\)" -Because 'a missing retention reads as the 90 day default in the email too'
        $kvEmail | Should -Match 'enable purge protection on this vault\?'
        $email = Get-Content (Join-Path $folder 'CR-08-app-service-https-only.email.txt') -Raw
        $email | Should -Match 'for the App Service application below\. With it on, requests made over plain HTTP are redirected to HTTPS, so all traffic to it is encrypted in transit\.'
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
    }
}
