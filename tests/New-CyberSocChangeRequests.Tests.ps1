# Pester 5 tests for New-CyberSocChangeRequests.ps1
# Run: Invoke-Pester ./tests/New-CyberSocChangeRequests.Tests.ps1 -Output Detailed
# Offline fixtures only. Nothing here signs in or calls Azure.

BeforeAll {
    $generator = Join-Path $PSScriptRoot '../New-CyberSocChangeRequests.ps1'
    $s1 = '5f1c2a9e-3b7d-4e21-9a6c-0d8e4f2b7c11'
    $s2 = 'a0b1c2d3-e4f5-4a6b-8c7d-9e0f1a2b3c4d'
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
        @{ ClientName = 'Example Client'; TenantId = 'example-tenant'; ScriptVersion = '1.1.0'; Subscriptions = @($s1, $s2); Workspaces = @(@{ Name = 'law-example-sentinel' }) } |
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
        $vm = { param($name, $sub) "/subscriptions/$sub/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/$name" }
        Set-PackResult $Path 'DP.4-ELIGIBILITY' @(
            @{ Name = 'vm-app01'; ResourceId = (& $vm 'vm-app01' $s1); resourceGroup = 'rg-app'; subscriptionId = $s1; Location = 'eastus'; Size = 'Standard_D4s_v5'; PowerState = 'PowerState/running'; AdeUsed = $false; SizeSupported = 'Yes'; Eligible = $true; Reason = '' }
            @{ Name = 'vm-old'; ResourceId = (& $vm 'vm-old' $s2); resourceGroup = 'rg-app'; subscriptionId = $s2; Location = 'westus'; Size = 'Standard_B2s'; PowerState = 'PowerState/deallocated'; AdeUsed = $false; SizeSupported = 'Yes'; Eligible = $true; Reason = '' }
            @{ Name = 'vm-paused'; ResourceId = (& $vm 'vm-paused' $s1); resourceGroup = 'rg-app'; subscriptionId = $s1; Location = 'eastus'; Size = 'Standard_B2s'; PowerState = 'PowerState/stopped'; AdeUsed = $false; SizeSupported = 'Yes'; Eligible = $true; Reason = '' }
            @{ Name = 'vm-ade'; ResourceId = (& $vm 'vm-ade' $s1); resourceGroup = 'rg-app'; subscriptionId = $s1; Location = 'eastus'; Size = 'Standard_D2s_v5'; PowerState = 'PowerState/running'; AdeUsed = $true; SizeSupported = 'Yes'; Eligible = $false; Reason = 'Azure Disk Encryption used' }
            @{ Name = 'vm-a1'; ResourceId = (& $vm 'vm-a1' $s1); resourceGroup = 'rg-app'; subscriptionId = $s1; Location = 'eastus'; Size = 'Standard_A1'; PowerState = 'PowerState/running'; AdeUsed = $false; SizeSupported = 'No'; Eligible = $false; Reason = 'size not supported' }
            @{ Name = 'vm-unread'; ResourceId = (& $vm 'vm-unread' $s2); resourceGroup = 'rg-app'; subscriptionId = $s2; Location = 'westus'; Size = 'Standard_D2s_v5'; PowerState = 'PowerState/running'; AdeUsed = $false; SizeSupported = 'Unknown'; Eligible = $false; Reason = 'size support not read: HTTP 403; Forbidden' })
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
            'CR-06-key-vault-purge-protection.txt', 'CR-07-storage-anonymous-access.txt', 'CR-08-app-service-https-only.txt', 'CR-09-encryption-at-host.txt')
        @($emailFiles.Name | Sort-Object) | Should -Be @('CR-07-storage-anonymous-access.email.txt', 'CR-08-app-service-https-only.email.txt', 'CR-09-encryption-at-host.email.txt')
        $files.Count | Should -Be ($crFiles.Count + $emailFiles.Count + 2)
        $index | Should -Match '\| 05 \| Minimum TLS 1\.2 on Azure SQL servers \|  \| No gaps found \|'
        $index | Should -Match '\| 07 \| Anonymous blob access disabled on storage accounts \| 2 \| Change request and client email \|'
        $index | Should -Match 'Internal\. Built .* from evidence pack full \(collector 1\.1\.0\)'
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

    It 'names the public containers in the anonymous access change and its client email' {
        $text = & $read 'CR-07-storage-anonymous-access.txt'
        $text | Should -Match 'stweb, resource group rg-web, 2 containers open to anonymous read: images \(Blob\), downloads \(Container\)'
        $text | Should -Match 'stdata, resource group rg-data, no container open to anonymous read' -Because 'container rows match the account whatever the case of the resource ID'
        $text | Should -Not -Match 'stpremfiles' -Because 'a FileStorage account holds no blob service'
        @(Get-Section $text 'B) USER EXPERIENCE')[0] | Should -Match '^Anyone who reads the public containers'
        $email = & $read 'CR-07-storage-anonymous-access.email.txt'
        $email | Should -Match '^Subject: Planned change: turning off anonymous access to Azure Blob Storage\r?\n\r?\nHello Dana,'
        $email | Should -Match '- stweb \(resource group rg-web\): images \(Blob\), downloads \(Container\)'
        $email | Should -Match 'This account has no container open to anonymous access, so I do not expect the change to affect it:\r?\n\r?\n- stdata \(resource group rg-data\)'
        $email | Should -Match 'Thank you,\r?\nScott Example\r?\n$'
    }

    It 'drafts the HTTPS Only email with the host names and asks about HTTP callers' {
        $email = & $read 'CR-08-app-service-https-only.email.txt'
        $email | Should -Match 'the 2 App Service applications below'
        $email | Should -Match '- app-portal \(app-portal\.azurewebsites\.net\)\r?\n- func-jobs \(func-jobs\.azurewebsites\.net\)'
        $email | Should -Match 'still call these applications over HTTP\?'
    }

    It 'enables encryption at host on virtual machines only, with the feature registered per subscription' {
        $text = & $read 'CR-09-encryption-at-host.txt'
        $text | Should -Not -Match 'aks-nodepool1-vmss'
        $index | Should -Match '1 scale set left out of CR-09: aks-nodepool1-vmss\.'
        foreach ($name in 'vm-ade', 'vm-a1', 'vm-unread') { $text | Should -Not -Match $name -Because "$name cannot take encryption at host as it stands" }
        $index | Should -Match '3 virtual machines left out of CR-09 because they cannot take encryption at host as they stand: vm-a1 \(Standard_A1, size not supported\), vm-ade \(Standard_D2s_v5, Azure Disk Encryption used\), vm-unread \(Standard_D2s_v5, size support not read\)\.'
        $index | Should -Match '\| 09 \| Encryption at host on virtual machines \| 3 \| Change request and client email \|'
        foreach ($s in $s1, $s2) { $text | Should -Match "    az account set --subscription $s" }
        $text | Should -Match 'Go to Settings > Disks > Additional settings, set Encryption at host to Yes and select Save\.'
        $text | Should -Match '7\. Repeat steps 3 to 6 for each remaining virtual machine listed\.'
        $text | Should -Match '4\. On Overview, note whether the status reads Running, then select Stop'
        $text | Should -Match '6\. Go back to Overview and select Start only if the status read Running before the stop' -Because 'the machine returns to its power state at the time of the change, not at collection'
        $text | Should -Match '- vm-paused, resource group rg-app, size Standard_B2s, stopped'
        @(Get-Section $text 'C) ROLLBACK PLAN')[-1] | Should -Match '^3\. Go back to Overview and select Start only if the status read Running before the stop\.$' -Because 'rollback restores the power state the machine had'
        (Get-Section $text 'D) DR Impact') -join '|' | Should -Be 'Not a DR Client'
        (Get-Section $text 'D) DR PLAN') -join '|' | Should -Be 'Not a DR Client. No updates to the DR Playbook are required.'
        $email = & $read 'CR-09-encryption-at-host.email.txt'
        $email | Should -Match '- vm-app01 \(resource group rg-app, running at my last review\)'
        $email | Should -Match '- vm-old \(resource group rg-app, stopped at my last review\)'
        $email | Should -Match '- vm-paused \(resource group rg-app, stopped at my last review\)' -Because 'a machine stopped but still allocated is not running either'
        $email | Should -Match 'a server that is already stopped will be left stopped'
        $email | Should -Match 'Could you suggest a maintenance window'
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

    It 'lists one row per resource in the CSV' {
        @($csv | Where-Object CR -eq 'CR-06').Resource | Should -Be @('kv-app', 'kv-dev')
        ($csv | Where-Object { $_.CR -eq 'CR-04' }).CurrentSetting | Should -Be 'minimum TLS 1.0'
        @($csv | Where-Object CR -eq 'CR-01').Count | Should -Be 2
        ($csv | Where-Object { $_.CR -eq 'CR-09' -and $_.Resource -eq 'vm-old' }).ResourceId | Should -Be "/subscriptions/$s2/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-old"
        @($csv | Where-Object { -not $_.ResourceId }).Count | Should -Be 0 -Because 'every tracking row carries the resource ID'
    }
}

Describe 'Change request variants' {
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
        foreach ($id in 'P0.7', 'NB.4-DETAIL', 'NB.5-DETAIL', 'NB.6-DETAIL', 'DP.1-DETAIL', 'DP.2-DETAIL') { Remove-PackResult $pack $id }
        Set-PackResult $pack 'DP.4-ELIGIBILITY' @() 'FAILED'
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        @(Get-ChildItem $out -Filter 'CR-*' | ForEach-Object Name) -join '|' | Should -Be 'CR-01-diagnostic-logging.txt' -Because 'change requests from the earlier run that this pack can no longer support are removed'
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '\| 02 \| Secure transfer required on storage accounts \|  \| Needs recollection with CyberSOC collector 1\.1\.0 or later \|'
        $index | Should -Match '\| 09 \| Encryption at host on virtual machines \|  \| Not collected \(DP\.4-ELIGIBILITY FAILED\) \|'
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
        $index | Should -Match 'CR-07 was written without DP\.1-CONTAINERS, whose result file is unreadable\.'
        $email = Get-Content (Join-Path $out 'CR-07-storage-anonymous-access.email.txt') -Raw
        $email | Should -Match 'I could not read the container settings on these accounts' -Because 'without the container list no account is presented as closed'
        $email | Should -Not -Match 'no container open'
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
        Set-PackResult $pack 'DP.4-DETAIL' @() 'SKIPPED'
        $null = & $generator -EvidencePath $pack
        $index = Get-Content (Join-Path $pack '05-change-requests/00-index.md') -Raw
        $index | Should -Match 'CR-07 was written without DP\.1-CONTAINERS, which reads FAILED\.'
        $index | Should -Match 'Scale sets were not checked for encryption at host, because DP\.4-DETAIL reads SKIPPED\.'
        $index | Should -Match '\| 10 \| .* \| 1 \| Change request, partial collection scope \|' -Because 'a partial resource list must not read as complete'
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
