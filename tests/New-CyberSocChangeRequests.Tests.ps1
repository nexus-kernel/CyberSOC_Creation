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
        param([string]$Path, [string]$Id, $Rows, [string]$Status, [string]$Detail = '')
        $rows = @($Rows)
        if (-not $Status) { $Status = if ($rows.Count) { 'OK' } else { 'EMPTY' } }
        ConvertTo-Json -InputObject $rows -Depth 6 | Set-Content (Join-Path $Path "results/$Id.json")
        $m = @(Import-Csv (Join-Path $Path '00-manifest.csv') | Where-Object ResultId -ne $Id | Select-Object ResultId, Status, Rows, ReadTimeUtc, @{ n = 'Detail'; e = { $_.Detail } })
        $m += [pscustomobject]@{ ResultId = $Id; Status = $Status; Rows = $rows.Count; ReadTimeUtc = '2026-10-12T06:10:00Z'; Detail = $Detail }
        $m | Export-Csv (Join-Path $Path '00-manifest.csv') -NoTypeInformation
    }
    function Remove-PackResult {
        param([string]$Path, [string]$Id)
        @(Import-Csv (Join-Path $Path '00-manifest.csv') | Where-Object ResultId -ne $Id) | Export-Csv (Join-Path $Path '00-manifest.csv') -NoTypeInformation
        Remove-Item (Join-Path $Path "results/$Id.json") -ErrorAction SilentlyContinue
    }
    # IA.15 fixtures (CR-19): synthetic accounts, real built-in role definition IDs.
    $morgan = 'a6f1c2d3-4b5e-4f60-8a7b-9c0d1e2f3a41'
    $lee = 'b7e2d3c4-5a6f-4071-9b8c-0d1e2f3a4b52'
    $kim = 'c8f3e4d5-6b70-4182-8c9d-1e2f3a4b5c63'
    $ann = 'd9a4f5e6-7c81-4293-9dae-2f3a4b5c6d74'
    $opsGroup = @{ Id = 'e0b5a6f7-8d92-43a4-aebf-3a4b5c6d7e85'; Name = 'platform-operators' }
    # ops-tier2 is nested in platform-operators, so a member of it holds the group's roles and is removed from ops-tier2.
    $tier2Group = @{ Id = 'f1c6d7e8-9ea3-44b5-bfc0-4b5c6d7e8f96'; Name = 'ops-tier2' }
    $opsNested = @{ Id = $opsGroup.Id; Name = $opsGroup.Name; MemberOf = $tier2Group }
    # A dynamic membership group and a group synced from on-premises cannot lose a member here.
    $dynGroup = @{ Id = 'a2d7e8f9-0fb4-45c6-8d1e-5c6d7e8f9a07'; Name = 'all-staff-dynamic'; Type = 'Dynamic' }
    $legacyGroup = @{ Id = 'b3e8f9a0-1ac5-46d7-9e2f-6d7e8f9a0b18'; Name = 'legacy-admins'; Type = 'On-premises' }
    # A group given with Old stands for a pack collected before 1.10.0, without the group membership columns.
    $opsOld = @{ Id = $opsGroup.Id; Name = $opsGroup.Name; Old = $true }
    # The group columns of a row: none for a role assigned to the account, else the role group, the group the account
    # sits in (the role group itself, or the MemberOf group nested in it), its membership type and the path between them.
    $held = { param($Group)
        if (-not $Group) { return @{ HeldThrough = 'Direct'; GroupId = ''; GroupName = ''; MemberOfId = ''; MemberOfName = ''; MemberOfType = ''; GroupPath = @(); GroupPathIds = @() } }
        if ($Group.Old) { return @{ HeldThrough = 'Group'; GroupId = $Group.Id; GroupName = $Group.Name } }
        $of = if ($Group.MemberOf) { $Group.MemberOf } else { $Group }
        $path = @(@{ Id = $Group.Id; Name = $Group.Name }) + @(if ($Group.MemberOf) { $Group.MemberOf })
        @{ HeldThrough = 'Group'; GroupId = $Group.Id; GroupName = $Group.Name; MemberOfId = $of.Id; MemberOfName = $of.Name; MemberOfType = $(if ($of.Type) { $of.Type } else { 'Assigned' })
            GroupPath = @($path | ForEach-Object { $_.Name }); GroupPathIds = @($path | ForEach-Object { $_.Id }) } }
    $mgScope = '/providers/Microsoft.Management/managementGroups/mg-contoso-platform'
    $roleIds = @{
        Owner = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'; Contributor = 'b24988ac-6180-42a0-ab88-20f7382dd24c'; Reader = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'
        Uaa = '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'; KvAdmin = '00482a5a-887f-4fb3-b363-3b7fe8e74483'; BlobContributor = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
        Ga = '62e90394-69f5-4237-9190-012177145e10'; UserAdmin = 'fe930be7-5e62-47db-91af-98c3a49a38b1'; Helpdesk = '729827e3-9c14-49f7-bb1b-9608f156bbb8'; SecReader = '5d6b6bb7-de71-4623-b4af-96380a352509'
    }
    $people = @{
        $morgan = @('Morgan Reyes', 'morgan.reyes@contoso.com', $false); $lee = @('Lee Ashford', 'lee.ashford@contoso.com', $true)
        $kim = @('Kim Osei', 'kim.osei@contoso.com', $false); $ann = @('Ann Larsen', 'ann.larsen@contoso.com', $false)
    }
    # One IA.15-RBAC row as the collector writes it. A group given holds the role, and the account is its disabled member,
    # of the group itself or of the MemberOf group nested in it.
    $azureRole = { param([string]$Scope, [string]$Role, [string]$RoleId, [string]$Principal, $Group)
        $level = switch -Regex ($Scope) { '^/$' { 'Root' } 'managementGroups' { 'Management group' } '^/subscriptions/[^/]+$' { 'Subscription' } '^/subscriptions/[^/]+/resourceGroups/[^/]+$' { 'Resource group' } default { 'Resource' } }
        $p = $people[$Principal]
        $row = @{ subscriptionId = $(if ($Scope -match '^/subscriptions/([^/]+)') { $Matches[1] } else { '' }); resourceGroup = $(if ($Scope -match '/resourceGroups/([^/]+)') { $Matches[1] } else { '' })
            ScopeLevel = $level; Scope = $Scope; Role = $Role; RoleDefinitionId = "/subscriptions/$s1/providers/microsoft.authorization/roledefinitions/$RoleId"
            PrincipalId = $Principal; UserPrincipalName = $p[1]; DisplayName = $p[0]; OnPremisesSyncEnabled = $p[2]
            AssignmentId = ('{0}/providers/Microsoft.Authorization/roleAssignments/{1}' -f $Scope.TrimEnd('/'), (Get-TestId "$Scope|$RoleId|$Principal")) }
        $h = & $held $Group
        foreach ($k in $h.Keys) { $row[$k] = $h[$k] }
        $row }
    # One IA.15-ENTRA row as the collector writes it.
    $entraRole = { param([string]$Role, [string]$RoleId, [string]$Type, [string]$Principal, $Group, [string]$Scope = '/', [string]$End = '', [string]$PimRead = 'Yes')
        $p = $people[$Principal]
        $row = @{ Role = $Role; RoleDefinitionId = $RoleId; DirectoryScope = $Scope; AssignmentType = $Type; PrincipalId = $Principal; UserPrincipalName = $p[1]; DisplayName = $p[0]; OnPremisesSyncEnabled = $p[2]
            EndDateUtc = $End; AssignmentId = (Get-TestId "$Role|$Type|$Principal"); PimRead = $PimRead }
        $h = & $held $Group
        foreach ($k in $h.Keys) { $row[$k] = $h[$k] }
        $row }
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
        # DP.1-CONTAINERS reads every account with a blob service, so starchive, which blocks anonymous access and
        # meets every other DP.1 check, is listed here but not in DP.1-DETAIL. Its public container is not readable.
        Set-PackResult $Path 'DP.1-CONTAINERS' @(
            @{ subscriptionId = $s1; resourceGroup = 'rg-data'; Account = 'stdata'; AccountAnonymousAccess = 'Allowed'; ResourceId = (& $sa 'stdata' 'rg-data' $s1).ToUpperInvariant(); Containers = 4; PublicContainers = 0; ExposedContainers = 0; PublicContainerNames = ''; ReadStatus = 'OK' }
            @{ subscriptionId = $s1; resourceGroup = 'rg-web'; Account = 'stweb'; AccountAnonymousAccess = 'Allowed'; ResourceId = (& $sa 'stweb' 'rg-web' $s1); Containers = 3; PublicContainers = 2; ExposedContainers = 2; PublicContainerNames = 'images (Blob), downloads (Container)'; ReadStatus = 'OK' }
            @{ subscriptionId = $s2; resourceGroup = 'rg-files'; Account = 'stnfsblob'; AccountAnonymousAccess = 'Disabled'; ResourceId = (& $sa 'stnfsblob' 'rg-files' $s2); Containers = 1; PublicContainers = 0; ExposedContainers = 0; PublicContainerNames = ''; ReadStatus = 'OK' }
            @{ subscriptionId = $s2; resourceGroup = 'rg-data'; Account = 'starchive'; AccountAnonymousAccess = 'Disabled'; ResourceId = (& $sa 'starchive' 'rg-data' $s2); Containers = 3; PublicContainers = 1; ExposedContainers = 0; PublicContainerNames = 'legacy-exports (Container)'; ReadStatus = 'OK' })
        $container = { param($account, $rg, $sub, $name, $level, $allows)
            $id = & $sa $account $rg $sub
            @{ subscriptionId = $sub; resourceGroup = $rg; Account = $account; Container = $name; AccessLevel = $level; AccountAnonymousAccess = $(if ($allows) { 'Allowed' } else { 'Disabled' }); ReadableToday = [bool]$allows; AccountId = $id; ResourceId = "$id/blobServices/default/containers/$name" } }
        Set-PackResult $Path 'DP.1-CONTAINERS-DETAIL' @(
            (& $container 'stweb' 'rg-web' $s1 'images' 'Blob' $true)
            (& $container 'stweb' 'rg-web' $s1 'downloads' 'Container' $true)
            (& $container 'starchive' 'rg-data' $s2 'legacy-exports' 'Container' $false))
        Set-PackResult $Path 'DP.2-DETAIL' @(@{ Name = 'kv-app'; ResourceId = 'kv1'; resourceGroup = 'rg-app'; subscriptionId = $s1; RetentionDays = 90 }, @{ Name = 'kv-dev'; ResourceId = 'kv2'; resourceGroup = 'rg-dev'; subscriptionId = $s2; RetentionDays = 7 })
        Set-PackResult $Path 'NB.4-DETAIL' @(@{ Name = 'app-portal'; ResourceId = 'app1'; Kind = 'app'; resourceGroup = 'rg-web'; subscriptionId = $s1; DefaultHostName = 'app-portal.azurewebsites.net' }, @{ Name = 'func-jobs'; ResourceId = 'app2'; Kind = 'functionapp'; resourceGroup = 'rg-web'; subscriptionId = $s1; DefaultHostName = 'func-jobs.azurewebsites.net' })
        # NB.5-DETAIL as collector 1.13.0 writes it, with the SCM (Kudu) site minimum. app-portal is below 1.2 on the site
        # only, and app-blank reads empty in both. The SCM cases are in tests/fixtures/offline-pack/app-service-tls.
        Set-PackResult $Path 'NB.5-DETAIL' @(@{ Name = 'app-portal'; ResourceId = 'app1'; resourceGroup = 'rg-web'; subscriptionId = $s1; MinTlsVersion = '1.0'; ScmMinTlsVersion = '1.2' }, @{ Name = 'app-blank'; ResourceId = 'app3'; resourceGroup = 'rg-web'; subscriptionId = $s1; MinTlsVersion = ''; ScmMinTlsVersion = '' })
        # NB.5-FTPS-DETAIL: the sites whose FTP state is not FtpsOnly or Disabled, so AllAllowed or empty. app-portal
        # is also below TLS 1.2 in NB.5-DETAIL, and app-blank reads empty in both, as Resource Graph can return it.
        $site = { param($name, $rg, $sub) "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Web/sites/$name" }
        Set-PackResult $Path 'NB.5-FTPS-DETAIL' @(
            @{ Name = 'app-portal'; ResourceId = (& $site 'app-portal' 'rg-web' $s1); resourceGroup = 'rg-web'; subscriptionId = $s1; FtpsState = 'AllAllowed'; MinTlsVersion = '1.0' }
            @{ Name = 'func-jobs'; ResourceId = (& $site 'func-jobs' 'rg-web' $s1); resourceGroup = 'rg-web'; subscriptionId = $s1; FtpsState = 'AllAllowed'; MinTlsVersion = '1.2' }
            @{ Name = 'app-blank'; ResourceId = (& $site 'app-blank' 'rg-web' $s1); resourceGroup = 'rg-web'; subscriptionId = $s1; FtpsState = ''; MinTlsVersion = '' }
            @{ Name = 'app-partners'; ResourceId = (& $site 'app-partners' 'rg-api' $s2); resourceGroup = 'rg-api'; subscriptionId = $s2; FtpsState = 'AllAllowed'; MinTlsVersion = '1.2' })
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
        # IA.15: Morgan holds Azure roles at management group, subscription, resource group and resource scope and a
        # standing Entra role. Lee, synced from on-premises, holds a storage role and an eligible Entra role that is
        # activated now, and the roles of platform-operators as a member of ops-tier2, nested in it. Kim holds roles
        # only through the group platform-operators, as a member of it. Pat is disabled and holds nothing.
        # Ann is enabled: her rows stand for a collector that let an enabled account through, and must never be listed.
        # Role definition IDs are the real built-in ones.
        Set-PackResult $Path 'IA.15-DISABLED' @(
            @{ PrincipalId = $morgan; PrincipalType = 'User'; DisplayName = 'Morgan Reyes'; UserPrincipalName = 'morgan.reyes@contoso.com'; AccountEnabled = $false; OnPremisesSyncEnabled = $false }
            @{ PrincipalId = $lee; PrincipalType = 'User'; DisplayName = 'Lee Ashford'; UserPrincipalName = 'lee.ashford@contoso.com'; AccountEnabled = $false; OnPremisesSyncEnabled = $true }
            @{ PrincipalId = $kim; PrincipalType = 'User'; DisplayName = 'Kim Osei'; UserPrincipalName = 'kim.osei@contoso.com'; AccountEnabled = $false; OnPremisesSyncEnabled = $false }
            @{ PrincipalId = 'f2c7b8a9-0fb4-45c6-8d1e-5c6d7e8f9a07'; PrincipalType = 'User'; DisplayName = 'Pat Moreno'; UserPrincipalName = 'pat.moreno@contoso.com'; AccountEnabled = $false; OnPremisesSyncEnabled = $false })
        Set-PackResult $Path 'IA.15-RBAC' @(
            (& $azureRole $mgScope 'Reader' $roleIds.Reader $morgan)
            (& $azureRole "/subscriptions/$s1" 'Owner' $roleIds.Owner $morgan)
            (& $azureRole "/subscriptions/$s1/resourceGroups/rg-app" 'Contributor' $roleIds.Contributor $morgan)
            (& $azureRole "/subscriptions/$s1/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/kv-app" 'Key Vault Administrator' $roleIds.KvAdmin $morgan)
            (& $azureRole "/subscriptions/$s2/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stdataprod" 'Storage Blob Data Contributor' $roleIds.BlobContributor $lee)
            (& $azureRole "/subscriptions/$s2/resourceGroups/rg-ops" 'Contributor' $roleIds.Contributor $kim $opsGroup)
            (& $azureRole "/subscriptions/$s2/resourceGroups/rg-ops" 'Contributor' $roleIds.Contributor $lee $opsNested)
            (& $azureRole "/subscriptions/$s2" 'Owner' $roleIds.Owner $ann))
        Set-PackResult $Path 'IA.15-ENTRA' @(
            (& $entraRole 'User Administrator' $roleIds.UserAdmin 'Standing' $morgan)
            (& $entraRole 'Security Reader' $roleIds.SecReader 'Activated' $lee)
            (& $entraRole 'Security Reader' $roleIds.SecReader 'Eligible' $lee -End '2027-03-31T00:00:00Z')
            (& $entraRole 'Helpdesk Administrator' $roleIds.Helpdesk 'Standing' $kim $opsGroup -Scope '/administrativeUnits/4b5c6d7e-8f90-4a1b-b2c3-d4e5f6a7b8c9')
            (& $entraRole 'Helpdesk Administrator' $roleIds.Helpdesk 'Standing' $lee $opsNested -Scope '/administrativeUnits/4b5c6d7e-8f90-4a1b-b2c3-d4e5f6a7b8c9')
            (& $entraRole 'Global Administrator' $roleIds.Ga 'Standing' $ann))
        # IA.16 as a current pack holds it: read in full, with no Atmosera account or group, so CR-19 leaves no one out.
        Set-PackResult $Path 'IA.16-ACCOUNTS' @()
        Set-PackResult $Path 'IA.16-GROUPS' @()
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
    # The lines that head each group of resources: a subscription, and for CR-19 a management group, the root scope and
    # the Microsoft Entra directory roles, which belong to no subscription.
    $resourceHeading = '^(Subscription .+|Management group .+|Root scope|Microsoft Entra ID directory roles):$'
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
        $paragraphs = @($prose | Where-Object { $_ -notmatch $resourceHeading })
        $paragraphs[0] | Should -Match '^I would like your approval to ' -Because "$Name opens with what it asks to change"
        $paragraphs[1] | Should -Match '^I recommend \S.*\bbecause\b' -Because "$Name says why in a because sentence"
        # The resources open with the paragraph just before the first heading, and only the reversal and the request
        # follow them.
        $firstSubscription = @(for ($i = 0; $i -lt $body.Count; $i++) { if ($body[$i] -match $resourceHeading) { $i } })[0]
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
            'CR-16-management-ports.txt', 'CR-17-app-service-ftps.txt', 'CR-18-storage-private-containers.txt', 'CR-19-disabled-account-roles.txt')
        @($emailFiles.Name | Sort-Object) | Should -Be @($crFiles.Name | Sort-Object | ForEach-Object { $_ -replace '\.txt$', '.email.txt' }) -Because 'every change request writes a client email'
        $files.Count | Should -Be ($crFiles.Count + $emailFiles.Count + 3) -Because 'the index, the CSV and the CSV the CR-19 email attaches'
        Test-Path (Join-Path $out 'CR-19-disabled-account-roles.email.csv') | Should -BeTrue -Because 'CR-19 names the accounts in a CSV attached to its email'
        $index | Should -Match '\| 05 \| Minimum TLS 1\.2 on Azure SQL servers \|  \| No gaps found \|'
        $index | Should -Match '\| 06 \| Purge protection on key vaults \| 2 \| Change request and client email \| CR-06-key-vault-purge-protection\.txt, CR-06-key-vault-purge-protection\.email\.txt \|'
        $index | Should -Match '\| 07 \| Anonymous blob access disabled on storage accounts \| 1 \| Change request and client email \|' -Because 'an account with a public container is left out'
        $index | Should -Match '\| 18 \| Blob containers set to private access \| 2 \| Change request and client email \| CR-18-storage-private-containers\.txt, CR-18-storage-private-containers\.email\.txt \|' -Because 'CR-18 counts containers, one per CSV row'
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
            foreach ($r in $refs) { $r | Should -Match '^- [^:]+: https://learn\.microsoft\.com/(azure|entra)/\S+$' -Because $f.Name }
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
        $index | Should -Match ([regex]::Escape('- 1 storage account left out of CR-07 because it has a container set to Blob or Container access, which anyone can read today without signing in: stweb (resource group rg-web): images (Blob), downloads (Container). Turning the account setting off would stop those anonymous reads, so CR-18 asks the owner of each container to confirm first that it serves no public content, and sets the container to private. A later pack picks each account up for CR-07 once every container in it is private.'))
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
        $index | Should -Match '- 1 App Service app left out of the SCM part of CR-04 because Resource Graph returned no SCM minimum TLS version, and App Service applies 1\.2 to the SCM site when none is set: app-blank \(resource group rg-web\)\.'
        $index | Should -Match 'Deployment slots have a minimum TLS version and an SCM minimum TLS version of their own, which the pack does not read, so CR-04 does not cover them\.'
        $app | Should -Not -Match 'SCM Minimum Inbound TLS Version' -Because 'no SCM minimum in this pack is below 1.2'
        $app | Should -Match "- app-portal, resource group rg-web, minimum TLS 1\.0, SCM minimum TLS 1\.2\r?\n"
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
        $dated = 'CR-01-diagnostic-logging', 'CR-02-storage-secure-transfer', 'CR-03-storage-minimum-tls', 'CR-04-app-service-minimum-tls', 'CR-06-key-vault-purge-protection', 'CR-07-storage-anonymous-access', 'CR-08-app-service-https-only', 'CR-11-redis-minimum-tls', 'CR-12-service-bus-minimum-tls', 'CR-13-event-hubs-minimum-tls', 'CR-14-cosmos-db-minimum-tls', 'CR-16-management-ports', 'CR-17-app-service-ftps', 'CR-19-disabled-account-roles'
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
        $index | Should -Match ('- CR-01, CR-02, CR-03, CR-04, CR-06, CR-07, CR-08, CR-11, CR-12, CR-13, CR-14, CR-16, CR-17, CR-18, CR-19 ask the client to approve the proposed date, {0}, and CR-09, CR-15 ask the client to approve the change and suggest a maintenance window\. Every email asks for a reply by {1}\. Run again with -ChangeDate to propose another day' -f $proposed, $reply)
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
        $impl[-1] | Should -Match '^11\. For each network interface the rules applied to, directly or through its subnet, go to Virtual machines, open the machine it belongs to, select Networking, select the network interface and select Effective security rules under Help\. .* the first rule that matches the source, protocol and port of a connection decides it, and a connection gets through only if every group on its path allows it\. A deny rule stops internet sources only where its source is Any, 0\.0\.0\.0/0, ::/0 or Internet and it covers the port, .* The port is still open to the internet where an allow lists 0\.0\.0\.0/0, ::/0 or other public prefixes the client did not name or already allow on purpose, such as 0\.0\.0\.0/1 and 128\.0\.0\.0/1, no deny that stops internet sources on that port comes before it in the same group, and the other group on the path, if there is one, lets the same connection through\. .* Leave the ports of a rule this change left unchanged and noted in the change record out of the deny on the network interfaces behind it, since that rule stays open until the client agrees a path, and note them with it\. For every other management port found open, add a deny rule with protocol TCP, Source set to Service Tag and Internet, Destination port ranges set to those ports .* Give it a free priority number from 100 to 4096 that is higher than every allow rule in that group for those ports from the named addresses or another source the client already allows on purpose, and lower than the allow that lets the internet in where that allow is a custom rule in the same group\. Default rules, numbered 65000 and above, always come after it\.' -Because 'another allow, such as the default rule for the virtual network behind a 0.0.0.0/0 route, can still let the internet in'
        $impl | Should -Contain '5. Go to Settings > Inbound security rules and find the rule. If its priority, access, direction, protocol, source, ports or destination no longer read as listed, or the group is no longer attached to what is listed, leave it unchanged and note it in the change record for the next pack.' -Because 'a rule changed since collection, such as TCP 22 turned into UDP 22, is no longer the one checked'
        (Get-Section $text 'B) TESTING PLAN') -join "`n" | Should -Match 'Any rule added for the private ranges allows only the management ports, from the ranges the client confirmed\.'
        (Get-Section $text 'B) TESTING PLAN') -join "`n" | Should -Match 'select Networking, select the network interface and select Effective security rules under Help\. .* For each of 22, 3389, 5985 and 5986, confirm that no allow rule that covers the port and lists 0\.0\.0\.0/0, ::/0 or other public prefixes the client did not name or already allow on purpose, such as 0\.0\.0\.0/1 and 128\.0\.0\.0/1, lets an internet source through under those rules, apart from the Azure platform address 168\.63\.129\.16 and the ports of a rule this change left unchanged and noted in the change record, so no other internet source reaches those ports\.' -Because 'the listed rules alone do not show what the effective rules still let in'
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

    It 'turns plain FTP off on the App Service apps whose FTP state reads All allowed, reading the recorded state again before each change' {
        $text = & $read 'CR-17-app-service-ftps.txt'
        $text | Should -Match '^Title: Set the FTP state to FTPS only or Disabled on App Service apps\r?\n'
        @(Get-Section $text 'A) CHANGE DESCRIPTION') | Should -Be 'Set the FTP state to FTPS only, or to Disabled where the client confirms nothing uses FTP or FTPS, on the 3 App Service and Function apps listed below.'
        @(Get-Section $text 'C) RESOURCES') | Should -Be @(
            'The 3 apps below are listed with the FTP state each one has today.'
            "Subscription: Example Production ($s1)"
            '- app-portal, resource group rg-web, FTP state All allowed, minimum TLS 1.0'
            '- func-jobs, resource group rg-web, FTP state All allowed'
            "Subscription: Example, Dev Test ($s2)"
            '- app-partners, resource group rg-api, FTP state All allowed') -Because 'the app below TLS 1.2 shows its minimum, since FTPS only needs 1.2'
        $text | Should -Not -Match 'app-blank' -Because 'an app whose FTP state reads empty is not changed on a guess'
        $impl = @(Get-Section $text 'A) IMPLEMENTATION PLAN')
        $impl[0] | Should -Be '1. In the Azure portal, go to App Services and open the first app listed in the RESOURCES section.'
        $impl[1] | Should -Be '2. Go to Settings > Configuration and select the General settings tab.'
        $impl[2] | Should -Match '^3\. Under Platform settings, read FTP state\. If it no longer shows All allowed, the state recorded for the app in the RESOURCES section, the app has changed since collection, so leave it unchanged, note it in the change record for the next pack and skip the remaining steps for it\.$' -Because 'an app changed since collection is skipped'
        $impl[3] | Should -Match '^4\. If the client chose FTPS only for the app, read Minimum Inbound TLS Version\. FTPS only does not support TLS 1\.0 or 1\.1, so if it shows 1\.0 or 1\.1, leave the app unchanged until CR-04 has set 1\.2 on it'
        $impl[4] | Should -Be '5. Set FTP state to FTPS only, or to Disabled only where the client confirmed that no tool, process or person uses FTP or FTPS on the app, to upload files or to download files or logs, select Apply and confirm.' -Because 'Disabled also ends FTPS downloads, such as log retrieval'
        $impl[5] | Should -Be '6. Repeat steps 1 to 5 for each remaining app listed.'
        @(Get-Section $text 'B) TESTING PLAN')[-1] | Should -Be '2. Confirm FTP state shows FTPS only or Disabled under Platform settings, as agreed with the client for the app.'
        @(Get-Section $text 'C) ROLLBACK PLAN')[-1] | Should -Match '^2\. Set FTP state back to All allowed, the state recorded for the app in the RESOURCES section, select Apply and confirm\.'
        (Get-Section $text 'E) MITIGATION') -join '|' | Should -Be 'If changes need to be reverted, follow the rollback plan.'
        @(Get-Section $text 'A) REFERENCES')[0] | Should -Be '- Deploy your app to Azure App Service using FTP/S, enforce FTPS: https://learn.microsoft.com/azure/app-service/deploy-ftp#enforce-ftps'
        @(Get-Section $text 'C) DEPENDENCIES') | Should -Be 'Tools, processes and people that use plain FTP, or FTP or FTPS on an app set to Disabled, to upload or download files can no longer connect once the change is applied.'
    }

    It 'names in the index the apps without a recorded FTP state, the uncovered slots, the apps below TLS 1.2 and the basic authentication part this pack does not record' {
        $index | Should -Match '\| 17 \| Plain FTP and FTP basic authentication turned off on App Service apps \| 3 \| Change request and client email \| CR-17-app-service-ftps\.txt, CR-17-app-service-ftps\.email\.txt \|'
        $index | Should -Match '- 1 App Service app left out of CR-17 because Resource Graph returned an empty FTP state, or one Microsoft Learn does not list, and Learn documents no state App Service applies when none is set, so it may still accept plain FTP: app-blank \(resource group rg-web\)\. Check its FTP state under Settings > Configuration > General settings in the portal, and raise the change for any that shows All allowed\.'
        $index | Should -Match '- NB\.5-FTPS-DETAIL reads the production site of each app\. Deployment slots have a configuration of their own, which the pack does not read, so CR-17 does not cover them\. Check the FTP state of each slot in the portal\.'
        $index | Should -Match '- 1 App Service app in CR-17 has a minimum inbound TLS version below 1\.2: app-portal \(resource group rg-web\)\. FTPS only does not support TLS 1\.0 or 1\.1, so CR-04 sets 1\.2 on it first, or the client chooses Disabled\.'
        $index | Should -Match '- NB\.5-FTPAUTH-DETAIL is not in this pack, so CR-17 covers the FTP state only\. Recollect with CyberSOC collector 1\.14\.0 or later for the FTP basic authentication part\.' -Because 'the fixture pack predates the FTP basic authentication read'
        $index | Should -Match '- FTP Basic Auth Publishing Credentials, under the same General settings tab, is a separate setting and not part of CR-17 in this pack\. Turning it off stops sign-in to the FTP and FTPS endpoint with deployment credentials, and CR-17 covers it on a pack that records it\.'
    }

    It 'asks for approval to turn off plain FTP, whether anything still uses FTP or FTPS to upload or download and whether FTPS only or Disabled suits each app' {
        $email = & $read 'CR-17-app-service-ftps.email.txt'
        Assert-ApprovalEmail $email 'CR-17'
        $email | Should -Match '^Subject: Approval requested: turning off plain FTP on Azure App Service applications\r?\n'
        $email | Should -Match 'I would like your approval to stop plain FTP connections to 3 of your App Service and Function applications by setting the FTP state of each to FTPS only, or to Disabled where nothing connects to it over FTP or FTPS\. FTP is an older way to upload files to an application, and FTPS is the same with the connection encrypted\.'
        $email | Should -Match 'I recommend this change because plain FTP sends the deployment user name, password and files unencrypted'
        $email | Should -Match 'will be refused once the change is applied, and will need to connect over FTPS'
        $email | Should -Match 'Disabled also turns off FTPS, so it suits only an application that nothing connects to over FTP or FTPS, to upload files or to download files or logs\.'
        $email | Should -Match 'FTPS only needs a minimum inbound TLS version of 1\.2, and app-portal still allows an older version, so for it I would set the minimum to 1\.2 first'
        $email | Should -Match "The applications are listed below by subscription, each with its FTP state today:\r?\n\r?\nSubscription Example Production \($s1\):\r?\n\r?\n- app-portal \(resource group rg-web, FTP state All allowed\)\r?\n- func-jobs \(resource group rg-web, FTP state All allowed\)\r?\n\r?\nSubscription Example, Dev Test \($s2\):\r?\n\r?\n- app-partners \(resource group rg-api, FTP state All allowed\)\r?\n"
        $email | Should -Match '\r?\n\r?\nThe FTP state can be set back to All allowed, the state each application has today, at any time\.\r?\n'
        $email | Should -Match '\r?\n\r?\nCould you let me know whether any deployment tool, scheduled process or person still connects to these applications over FTP or FTPS, to upload files or to download files or logs, and whether FTPS only or Disabled suits each one\? With that agreed, could you approve this change for \w+day, [^?]+\? Please reply by [^.]+\d{4}\. If something still uses plain FTP, I will hold the change for that application until it uses FTPS, and I will set Disabled only where nothing uses FTP or FTPS at all\.' -Because 'Disabled also ends FTPS downloads, so the client confirms every use of FTP and FTPS'
        $email | Should -Not -Match 'app-blank|minimum TLS 1\.0' -Because 'the email lists only the apps in the change, each with its FTP state'
    }

    It 'sets the containers anyone can read today to private, account by account, reading the account and each level again first' {
        $text = & $read 'CR-18-storage-private-containers.txt'
        @(Get-Section $text 'A) CHANGE DESCRIPTION') | Should -Be @('Set the anonymous access level of the 2 blob containers listed below to Private, in a storage account that allows anonymous access.')
        @(Get-Section $text 'B) PURPOSE') | Should -Be @('Anyone can read these containers today without signing in, so setting them to Private stops those anonymous reads straight away. A private container also stays closed if the account setting is relaxed later.')
        @(Get-Section $text 'C) RESOURCES') | Should -Be @(
            'The 2 containers below are set to Blob or Container access in a storage account that allows anonymous access, so anyone can read them today. The account lists its containers with the level recorded at collection. CR-07 turns anonymous access off at the account level only where no container is set to Blob or Container, so a later pack picks the account up for CR-07 once every container in it reads Private.'
            "Subscription: Example Production ($s1)"
            '- stweb, resource group rg-web, 2 containers: downloads (Container), images (Blob)') -Because 'the containers are grouped and counted under their account'
        $text | Should -Not -Match 'starchive|legacy-exports' -Because 'the portal cannot change a container whose account blocks anonymous access'
        @(Get-Section $text 'B) USER EXPERIENCE') | Should -Be @('Anyone who reads these containers without signing in, such as a website, an application, a CDN or a shared link, is refused once the change is applied.')
        @(Get-Section $text 'C) DEPENDENCIES') | Should -Be @('Needs the owner of each container to confirm it serves no public content, or to move that content to shared access signatures, on their own or through a CDN that adds one, before the change.')
        (Get-Section $text 'E) MITIGATION') -join '|' | Should -Be 'If changes need to be reverted, follow the rollback plan.'
        @(Get-Section $text 'A) IMPLEMENTATION PLAN') | Should -Be @(
            '1. In the Azure portal, go to Storage accounts and open the storage account listed in the RESOURCES section.'
            '2. Go to Settings > Configuration and read Allow Blob anonymous access. If it shows Disabled, the account has blocked anonymous access since collection, so its containers can no longer be read anonymously and the portal cannot change their access level. Leave the account unchanged, note it in the change record for the next pack and skip the remaining steps for it.'
            '3. Go to Data storage > Containers and read the Anonymous access level of each container listed for the account in the RESOURCES section. A container that no longer shows its recorded level has changed since collection, so leave it unchanged and note it in the change record. Leave out too any container the client asked to keep out of the change.'
            '4. Select the remaining listed containers, select Change access level, set Anonymous access level to Private (no anonymous access) and select OK.'
            '5. If another container in the account, other than $web, shows Blob or Container, it was opened after collection and is not part of this change, so note it in the change record for the next pack.') -Because 'the account and each container are read again at change time, before the change'
        @(Get-Section $text 'B) TESTING PLAN') | Should -Be @(
            '1. In the Azure portal, open the storage account listed in the RESOURCES section and go to Data storage > Containers.'
            '2. Confirm the Anonymous access level column shows Private for each container listed for the account, apart from any left unchanged and noted in the change record.')
        @(Get-Section $text 'C) ROLLBACK PLAN') | Should -Be @(
            '1. In the Azure portal, open the storage account to revert and go to Settings > Configuration. A container can be set to Blob or Container only while Allow Blob anonymous access shows Enabled. If it shows Disabled, for example after CR-07, enabling it again opens every container in the account that is set to Blob or Container, so agree that with the client first.'
            '2. Go to Data storage > Containers, select the container to revert, select Change access level, set Anonymous access level back to the level recorded for it in the RESOURCES section and select OK. A container left unchanged during the change needs no rollback.') -Because 'Microsoft Learn says a container can be opened only while the account allows anonymous access'
        $text | Should -Match '- Static website hosting in Azure Storage, impact of setting the access level on the web container: https://learn\.microsoft\.com/azure/storage/blobs/storage-blob-static-website#impact-of-setting-the-access-level-on-the-web-container'
        $text | Should -Match '- Configure anonymous read access for containers and blobs, set the anonymous access level for a container: https://learn\.microsoft\.com/azure/storage/blobs/anonymous-read-access-configure#set-the-anonymous-access-level-for-a-container'
    }

    It 'names in the index the containers the account setting already blocks and the FileStorage accounts, and points CR-07 at CR-18' {
        $index | Should -Match ([regex]::Escape('- 1 container set to Blob or Container access in a storage account that blocks anonymous access left out of CR-18: starchive (resource group rg-data), 1 container: legacy-exports (Container). The account setting keeps it closed, so no one can read it anonymously today, and Microsoft Learn notes that the portal cannot change the access level of a container while its account blocks anonymous access. It would open again as soon as the account allowed anonymous access, so any change that relaxes the account setting also sets it to Private.'))
        $index | Should -Match ([regex]::Escape('- 1 FileStorage account left out of CR-18 because it holds no blob service, so it has no blob containers to change: stpremfiles (resource group rg-files).'))
        $index | Should -Match ([regex]::Escape('so CR-18 asks the owner of each container to confirm first that it serves no public content, and sets the container to private. A later pack picks each account up for CR-07 once every container in it is private.')) -Because 'the CR-07 note for an account with a public container names CR-18'
        $index | Should -Match ([regex]::Escape('- Before CR-18 is sent, the metrics of each account show whether anything still reads it without signing in. In the Azure portal, open Monitoring > Metrics on the account, choose the Blob metric namespace and the Transactions metric, and add a filter of Authentication equal to Anonymous.')) -Because 'the owners can see what still reads anonymously before they confirm'
        $index | Should -Not -Match 'static website container' -Because 'no $web container is public in this pack'
        $index | Should -Not -Match 'CR-18 was written without' -Because 'DP.1-CONTAINERS was read'
    }

    It 'asks for approval to set the containers to private, listing them by account, and asks each owner to confirm first' {
        $email = & $read 'CR-18-storage-private-containers.email.txt'
        Assert-ApprovalEmail $email 'CR-18'
        $email | Should -Match '^Subject: Approval requested: private access for Azure Blob Storage containers\r?\n\r?\nHello Dana,'
        $email | Should -Match 'I would like your approval to set 2 of your Azure Blob Storage containers to private access, so they can no longer be read without signing in\. Each of them is set to public access today, and its storage account allows it, so anyone who has the address of a file there can read it\.'
        $email | Should -Match 'I recommend this change because anyone can read these containers today without signing in'
        $email | Should -Match 'Setting these containers to private stops anonymous reads straight away\. A website, an application, a content delivery network or a link that reads files from them without signing in, such as images, downloads or documents shared by link, will get an error once the change is applied\.' -Because 'the client is told anonymous reads stop at once'
        $email | Should -Match 'A static website hosted in a storage account is served from its own web address, which the container access level does not control'
        $email | Should -Match "The 2 containers are listed below by subscription and storage account, with the number in each account and the access level of each container today\. Anyone can read every one of them without signing in:\r?\n\r?\nSubscription Example Production \($s1\):\r?\n\r?\n- stweb \(resource group rg-web\), 2 containers: downloads \(Container\), images \(Blob\)\r?\n"
        $email | Should -Match 'Each container can be set back to the access level it has today at any time, as long as its storage account still allows anonymous access\.'
        $email | Should -Match 'Before I schedule the change, could you ask the owner of each container to confirm that it serves no public content\? Where a container does, its files can move to shared access signatures, which give time-limited links, either on their own or through a content delivery network such as Azure Front Door that adds the signature, and I will leave that container out until they have moved\. With that confirmed, could you approve this change for \w+day, ' -Because 'a CDN in front of a private container still needs a signature'
        $email | Should -Not -Match 'starchive|legacy-exports|stpremfiles|\$web'
    }

    It 'removes the roles held by disabled accounts, Azure by subscription and scope and Entra separately, after reading each account again' {
        $text = & $read 'CR-19-disabled-account-roles.txt'
        @(Get-Section $text 'A) CHANGE DESCRIPTION')[0] | Should -Be 'Remove the 5 Azure role assignments and 3 Microsoft Entra role assignments assigned directly to the 3 disabled user accounts listed below, at the scope where each was made, and remove 2 of them from 2 groups through which they hold 4 more role assignments.'
        @(Get-Section $text 'B) PURPOSE')[0] | Should -Match 'Removing the roles, and the group memberships that carry them, closes that path'
        @(Get-Section $text 'A) AVAILABILITY/PERFORMANCE')[0] | Should -Be 'No impact on any service, since the accounts are disabled and cannot sign in, and a group keeps its roles and its other members.'
        $res = @(Get-Section $text 'C) RESOURCES')
        $res[0] | Should -Be 'The 3 accounts below are recorded as disabled at collection. Each role listed is assigned directly to one of them, or reaches the account through the group it is removed from. The CSV carries every assignment and membership in full for the rollback.'
        $res[1] | Should -Be 'Azure role assignments, removed at the scope where each was made:'
        $res[2] | Should -Be "Subscription: Example Production ($s1)"
        $res[3] | Should -Match "^- Morgan Reyes \(morgan\.reyes@contoso\.com\), object ID $morgan`: Owner on the subscription, role definition $($roleIds.Owner), scope /subscriptions/$s1, assignment [0-9a-f-]{36}$"
        $res[4] | Should -Match ': Contributor on resource group rg-app, '
        $res[5] | Should -Match ': Key Vault Administrator on resource kv-app in resource group rg-app, role definition 00482a5a-887f-4fb3-b363-3b7fe8e74483, scope /subscriptions/.+/providers/Microsoft\.KeyVault/vaults/kv-app, '
        $res[6] | Should -Be "Subscription: Example, Dev Test ($s2)"
        $res[7] | Should -Match '^- Lee Ashford .+: Storage Blob Data Contributor on resource stdataprod in resource group rg-data, '
        $res[8] | Should -Be 'Management group: mg-contoso-platform' -Because 'a management group sits after the subscriptions, under its own name'
        $res[9] | Should -Match "^- Morgan Reyes .+: Reader on the management group, role definition $($roleIds.Reader), scope $([regex]::Escape($mgScope)), "
        $res[10] | Should -Be 'Microsoft Entra role assignments:'
        @($res | Select-Object -Skip 11 -First 3) | Should -Match '^- (Morgan Reyes .+: User Administrator, Standing|Lee Ashford .+: Security Reader, (Activated|Eligible)), role definition [0-9a-f-]{36}, directory scope /, assignment '
        $res[14] | Should -Be 'Group memberships removed, which take the roles the group holds away from the account:'
        $res[15] | Should -Be "- Kim Osei (kim.osei@contoso.com), object ID $kim`: removed from group platform-operators ($($opsGroup.Id)), which holds Azure Contributor on /subscriptions/$s2/resourceGroups/rg-ops and Microsoft Entra Helpdesk Administrator (in administrative unit 4b5c6d7e-8f90-4a1b-b2c3-d4e5f6a7b8c9)" -Because 'a member of the role group itself leaves that group'
        $res[16] | Should -Be "- Lee Ashford (lee.ashford@contoso.com), object ID $lee`: removed from group ops-tier2 ($($tier2Group.Id)), nested in platform-operators ($($opsGroup.Id)), which holds Azure Contributor on /subscriptions/$s2/resourceGroups/rg-ops and Microsoft Entra Helpdesk Administrator (in administrative unit 4b5c6d7e-8f90-4a1b-b2c3-d4e5f6a7b8c9)" -Because 'a member of a nested group leaves the nested group, named with the role group it is nested in'
        $res.Count | Should -Be 17
        $impl = @(Get-Section $text 'A) IMPLEMENTATION PLAN')
        $impl[0] | Should -Be '1. In the Azure portal, go to Microsoft Entra ID > Users and open the first account listed in the RESOURCES section.'
        $impl[1] | Should -Match '^2\. On the Overview page, read Account status, .+If it shows the account as enabled, the account has been turned back on since collection, so leave every role it holds unchanged, note it in the change record for the next pack and skip the remaining steps for it\. Leave out too any account the client asked to keep out of the change\.$'
        $impl[2] | Should -Match 'go to Access control \(IAM\) and select the Role assignments tab\.$'
        $impl[3] | Should -Match 'whose Scope column reads This resource\. Where the tab shows a State column and it reads Active time-bound, record in the change record the end time of the assignment, shown by selecting Edit columns and then End time, since the collection does not hold it and the rollback restores the assignment as time-bound with that end\. A resource scope shows no State column, so for an assignment on a resource, where the client uses Privileged Identity Management, read its end on the Active roles tab of Privileged Identity Management > Azure resources > the resource > Roles > the role instead\. Select Remove and then Yes\. An assignment shown as Inherited was made at a parent scope and is removed there'
        $impl[4] | Should -Match 'Microsoft Entra ID > Roles and administrators, open the role, select the account, select Remove assignment'
        $impl[5] | Should -Be '6. For each Microsoft Entra role listed as Eligible for the account, go to Privileged Identity Management > Microsoft Entra roles > Roles, open the role, find the account on the Eligible assignments tab, with the scope listed for the role, and select Remove. A role listed as Activated comes from an eligible assignment and ends when its activation expires, so remove that eligible assignment the same way, and where the Active assignments tab still lists the activation with a Remove link, select it as well.' -Because 'an Activated role with its Eligible row keeps the wording it had'
        $impl[6] | Should -Be '7. For each group membership listed for the account, first confirm that it still gives the account a role on its line: go to Microsoft Entra ID > Groups > All groups, open each group the line says holds a role and check under Azure role assignments or Assigned roles that it still holds the roles listed, then, where the line says the account sits in a group nested in it, open that nested group and each group named between them and confirm under Group memberships that each is still a member of the one above it. Where the membership still carries at least one of the roles listed, remove it as follows, and note in the change record any role on the line that was already gone. Only where every role on the line is gone, or the chain to every group holding one is broken, does the membership no longer give the account a role, so leave it unchanged and note it in the change record. To remove it, open the group the account is removed from, the first group named on its line, which is the group that holds the role or a group nested in it. Select Members, find the account, select it, select Remove and then Yes. If Membership type on the group reads Dynamic User or Dynamic Device, or Source reads Windows server AD, a member cannot be removed here, so leave the membership unchanged and note it in the change record for a review with the group owner.'
        $impl[7] | Should -Be '8. Repeat steps 1 to 7 for each remaining account listed.'
        ($impl -join ' ') | Should -Not -Match 'az role' -Because 'only an assignment at the root scope needs the command line'
        $testing = @(Get-Section $text 'B) TESTING PLAN')
        $testing[0] | Should -Be '1. In the Azure portal, go to Microsoft Entra ID > Users and open each account listed in the RESOURCES section.'
        $testing[1] | Should -Match 'Select Azure role assignments, choose each subscription listed for the account in turn'
        $testing[2] | Should -Match 'Select Assigned roles and confirm that none of the Microsoft Entra roles recorded for the account appears under Active assignments or Eligible assignments'
        $testing[3] | Should -Be '4. Select Groups and confirm that no group recorded for the account under group memberships is listed, apart from any left unchanged and noted in the change record, then confirm under Azure role assignments and Assigned roles that the roles those groups hold no longer reach the account.'
        $rollback = (@(Get-Section $text 'C) ROLLBACK PLAN') -join "`n")
        $rollback | Should -Match 'Access control \(IAM\) > Add > Add role assignment, select the recorded role'
        $azureRollback = @(Get-Section $text 'C) ROLLBACK PLAN')[0]
        $azureRollback | Should -Match '^1\. For an Azure role assignment, open the scope recorded for it in the RESOURCES section, go to Access control \(IAM\) > Add > Add role assignment, select the recorded role, select User, group, or service principal and select the account by its object ID\. Where step 4 recorded the assignment in the change record as Active time-bound, select Active on the Assignment type tab and set Assignment duration to Time bound with the recorded end date and time, never Permanent, so the role is not restored for longer than it was held\. A resource scope has no Assignment type tab, so recreate a time-bound assignment on a resource from Privileged Identity Management > Azure resources > the resource > Roles > Add assignments instead, as Active with the recorded end date and time\. Then select Review \+ assign\.$' -Because 'the time bound is set before Review + assign creates the assignment'
        $rollback | Should -Not -Match 'Review \+ assign\.[^\n]*\n[^\n]*Active time-bound at step' -Because 'no time-bound step follows an assignment already created as permanent'
        $rollback | Should -Match 'set Assignment type to Eligible with the recorded end date'
        $rollback | Should -Match 'A role recorded as Activated needs no rollback of its own, since it came from the eligible assignment recorded with it\.'
        $rollback | Should -Not -Match 'no Eligible line|recorded in the change record at step|Permanently eligible'
        $text | Should -Not -Match 'no Eligible line|pim-how-to-add-role-to-user#assign-a-role'
        $rollback | Should -Match 'For a group membership, go to Microsoft Entra ID > Groups > All groups, open the recorded group, select Members, select Add members, find the account by its object ID, select it and select Select\. Every role the group holds, itself or through the groups it is nested in, reaches the account again at once\.'
        $rollback | Should -Match 'change-requests\.csv carries each assignment in full, with the role, role definition ID, scope, any condition and the account object ID, and each group membership with the group the account is removed from and the roles it holds, and the change record carries each end time or schedule recorded before removal\.'
        foreach ($r in @(Get-Section $text 'A) REFERENCES')) { $r | Should -Match '^- [^:]+: https://learn\.microsoft\.com/(azure|entra)/' }
        $text | Should -Match 'learn\.microsoft\.com/entra/identity/role-based-access-control/groups-remove-assignment'
        $text | Should -Match 'learn\.microsoft\.com/entra/fundamentals/how-to-manage-groups#remove-members-or-owners-of-a-group'
        $text | Should -Match 'learn\.microsoft\.com/entra/fundamentals/how-to-manage-groups#add-members-or-owners-of-a-group'
    }

    It 'never lists an enabled account or a disabled account without roles, and removes an account from the group that gives it a role' {
        foreach ($f in 'CR-19-disabled-account-roles.txt', 'CR-19-disabled-account-roles.email.txt', 'CR-19-disabled-account-roles.email.csv') {
            $t = & $read $f
            $t | Should -Not -Match 'Ann Larsen|ann\.larsen|Global Administrator' -Because "$f names no enabled account, whatever its role results hold"
            $t | Should -Not -Match 'Pat Moreno' -Because "$f lists only accounts that hold a role"
        }
        (& $read 'CR-19-disabled-account-roles.txt') | Should -Match 'Kim Osei' -Because 'an account that holds a role only through a group is removed from the group'
        (& $read 'CR-19-disabled-account-roles.email.txt') | Should -Not -Match 'Morgan Reyes|morgan\.reyes|Kim Osei|kim\.osei|Lee Ashford|lee\.ashford|platform-operators|ops-tier2' -Because 'the email counts the accounts and names them in the attached CSV only'
        @($csv | Where-Object CR -eq 'CR-19' | Where-Object { $_.Resource -match 'ann\.' -or $_.CurrentSetting -match $ann }).Count | Should -Be 0
        $kimRows = @($csv | Where-Object CR -eq 'CR-19' | Where-Object { $_.Resource -match 'kim\.' })
        @($kimRows.Resource) | Should -Be @('kim.osei@contoso.com, member of group platform-operators') -Because 'a role held through a group is tracked as the membership that carries it, not as an assignment'
        $kimRows[0].CurrentSetting | Should -Be "Membership of group platform-operators ($($opsGroup.Id)), which holds Azure Contributor on /subscriptions/$s2/resourceGroups/rg-ops and Microsoft Entra Helpdesk Administrator (in administrative unit 4b5c6d7e-8f90-4a1b-b2c3-d4e5f6a7b8c9), held by kim.osei@contoso.com (object ID $kim)"
        $kimRows[0].ResourceId | Should -Be "/groups/$($opsGroup.Id)/members/$kim/`$ref" -Because 'the resource ID is the Graph path that removes the member'
        $leeRows = @($csv | Where-Object CR -eq 'CR-19' | Where-Object { $_.Resource -match 'member of group' -and $_.Resource -match 'lee\.' })
        @($leeRows.Resource) | Should -Be @('lee.ashford@contoso.com, member of group ops-tier2')
        $leeRows[0].CurrentSetting | Should -Match "^Membership of group ops-tier2 \($($tier2Group.Id)\), nested in platform-operators \($($opsGroup.Id)\), which holds Azure Contributor on "
        $leeRows[0].ResourceId | Should -Be "/groups/$($tier2Group.Id)/members/$lee/`$ref"
    }

    It 'names in the index the roles held through groups, the synced accounts, the Azure eligible assignments it cannot read and the service principals' {
        $index | Should -Match '\| 19 \| Roles removed from disabled accounts \| 10 \| Change request and client email \| CR-19-disabled-account-roles\.txt, CR-19-disabled-account-roles\.email\.txt, CR-19-disabled-account-roles\.email\.csv \|' -Because 'CR-19 counts one row per assignment and per group membership, and lists the CSV its email attaches'
        $index | Should -Match "- 2 disabled accounts hold roles through group membership, and CR-19 removes each one from the group it sits in: Kim Osei \(kim\.osei@contoso\.com\) from group platform-operators \($($opsGroup.Id)\), which holds Azure Contributor on /subscriptions/$s2/resourceGroups/rg-ops and Microsoft Entra Helpdesk Administrator \(in administrative unit 4b5c6d7e-8f90-4a1b-b2c3-d4e5f6a7b8c9\) / Lee Ashford \(lee\.ashford@contoso\.com\) from group ops-tier2 \($($tier2Group.Id)\), nested in platform-operators \($($opsGroup.Id)\), which holds Azure Contributor on /subscriptions/$s2/resourceGroups/rg-ops and Microsoft Entra Helpdesk Administrator \(in administrative unit 4b5c6d7e-8f90-4a1b-b2c3-d4e5f6a7b8c9\)\."
        $index | Should -Match '- CR-19 names the accounts and their roles in CR-19-disabled-account-roles\.email\.csv rather than in its email, since the list can be long\. Attach the file to the email\.'
        $index | Should -Not -Match 'which CR-19 leaves unchanged|whose members CR-19 cannot change' -Because 'every group in the fixture can lose a member'
        $index | Should -Match '- 1 account in CR-19 is synced from on-premises Active Directory: Lee Ashford \(lee\.ashford@contoso\.com\)\. Its disabled state comes from Active Directory'
        $index | Should -Match '- IA\.15-RBAC reads the subscriptions in the pack and the management groups and root scope above them, so a role in another subscription of the tenant is not listed\. Resource Graph also holds the active Azure role assignments only, not the eligible assignments of Privileged Identity Management for Azure resources'
        $index | Should -Match '- IA\.15-DISABLED reads user accounts only\. Disabled service principals are not read'
        $index | Should -Not -Match 'Lighthouse|Eligible Microsoft Entra role assignments were not visible|is an emergency access account' -Because 'the full fixture was read directly, with PIM, and holds none of the top roles'
    }

    It 'asks for approval to remove the roles and the group memberships, counts the accounts in the email and names them in the attached CSV, and asks whether any account is coming back' {
        $email = & $read 'CR-19-disabled-account-roles.email.txt'
        Assert-ApprovalEmail $email 'CR-19'
        $email | Should -Match '^Subject: Approval requested: removing the roles held by disabled accounts\r?\n'
        $email | Should -Match 'I would like your approval to remove the Azure and Microsoft Entra roles still held by 3 disabled accounts in your tenant, by removing the roles assigned to the accounts themselves and, where a group holds a role for one of them, by removing that account from the group\. These accounts are disabled, so they cannot sign in, but each one still holds every role listed in the attached file\.'
        $email | Should -Match 'I recommend removing these roles because a disabled account keeps every role it holds'
        $email | Should -Match '\r?\n\r?\nNobody loses access today, since these accounts cannot sign in\.\r?\n'
        $email | Should -Match '\r?\n\r?\nIf one of these accounts comes back into use later, it would need its roles assigned again and its group memberships restored\.\r?\n'
        $email | Should -Match '\r?\n\r?\nWhere a group holds the role, I would remove the account concerned from the group rather than take the role away from the group, so its other members keep their access, and where an account sits in a group nested inside the one that holds the role, it is the nested group the account is removed from\. Removing an account from a group also ends anything else the group gives it, such as access to an application, which does not matter while the account is disabled\.\r?\n'
        $email | Should -Not -Match 'come from a rule|stay as they are for now' -Because 'every group in the fixture can lose a member, and the pack records the group each account sits in'
        $email | Should -Match ("The accounts and their roles are in the attached file CR-19-disabled-account-roles\.email\.csv, one line for each role with the account, the role, where it applies, how the account holds it and what I would do about it, and they add up as follows:\r?\n\r?\n" +
            "Subscription Example Production \($s1\):\r?\n\r?\n- 1 account holding 3 roles\r?\n\r?\n" +
            "Subscription Example, Dev Test \($s2\):\r?\n\r?\n- 2 accounts holding 3 roles, 2 of them through a group\r?\n\r?\n" +
            "Management group mg-contoso-platform:\r?\n\r?\n- 1 account holding 1 role\r?\n\r?\n" +
            "Microsoft Entra ID directory roles:\r?\n\r?\n- 3 accounts holding 5 roles, 2 of them through a group\r?\n") -Because 'the email counts the roles under each heading and leaves the names to the attached file'
        $email | Should -Match '\r?\n\r?\nI can restore any of these roles at any time from the record I keep of each one, with its role, where it applies and the account it belongs to, and add an account back to the group it was removed from\.'
        $email | Should -Match '\r?\n\r?\nBefore I schedule the change, could you tell me whether any of these accounts is expected to come back into use, for example for someone on leave or a seasonal worker, or is kept for emergency access\? I will leave any such account out of the change\. With that confirmed, could you approve this change for \w+day, '
        $email | Should -Not -Match '(?i)object ID|role definition|assignment ID' -Because 'the email names roles in plain words, the change request keeps the IDs'
        $file = Join-Path $out 'CR-19-disabled-account-roles.email.csv'
        (Get-Content $file -First 1) | Should -Be '"Account","SignInName","RoleType","Role","Scope","Detail","HeldThrough","Action"'
        $rows = @(Import-Csv $file)
        $rows.Count | Should -Be 12 -Because 'one line per role, assigned to the account or held through a group'
        @($rows | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Account, $_.RoleType, $_.Role, $_.HeldThrough }) | Should -Be @(
            'Kim Osei|Azure|Contributor|Group platform-operators'
            'Kim Osei|Microsoft Entra|Helpdesk Administrator|Group platform-operators'
            'Lee Ashford|Azure|Contributor|Group platform-operators, through the group ops-tier2 nested in it'
            'Lee Ashford|Azure|Storage Blob Data Contributor|Assigned to the account'
            'Lee Ashford|Microsoft Entra|Helpdesk Administrator|Group platform-operators, through the group ops-tier2 nested in it'
            'Lee Ashford|Microsoft Entra|Security Reader|Assigned to the account'
            'Lee Ashford|Microsoft Entra|Security Reader|Assigned to the account'
            'Morgan Reyes|Azure|Contributor|Assigned to the account'
            'Morgan Reyes|Azure|Key Vault Administrator|Assigned to the account'
            'Morgan Reyes|Azure|Reader|Assigned to the account'
            'Morgan Reyes|Azure|Owner|Assigned to the account'
            'Morgan Reyes|Microsoft Entra|User Administrator|Assigned to the account') -Because 'the file is sorted by account, Azure roles first, then by where the role applies'
        $kimAzure = $rows | Where-Object { $_.Account -eq 'Kim Osei' -and $_.RoleType -eq 'Azure' }
        @($kimAzure.SignInName, $kimAzure.Scope, $kimAzure.Detail, $kimAzure.Action) | Should -Be @('kim.osei@contoso.com', "resource group rg-ops in the subscription Example, Dev Test ($s2)", '', 'Remove the account from group platform-operators')
        $nested = $rows | Where-Object { $_.Account -eq 'Lee Ashford' -and $_.Role -eq 'Helpdesk Administrator' }
        @($nested.Scope, $nested.Detail, $nested.Action) | Should -Be @('administrative unit 4b5c6d7e-8f90-4a1b-b2c3-d4e5f6a7b8c9', '', 'Remove the account from group ops-tier2') -Because 'a member of a nested group is removed from the nested group'
        @($rows | Where-Object { $_.Account -eq 'Lee Ashford' -and $_.Role -eq 'Security Reader' } | ForEach-Object Detail) | Should -Be @('activated from an eligible assignment', 'eligible in Privileged Identity Management, until 2027-03-31')
        ($rows | Where-Object { $_.Role -eq 'Reader' }).Scope | Should -Be 'the management group mg-contoso-platform'
        ($rows | Where-Object { $_.Role -eq 'Owner' }).Scope | Should -Be "the subscription Example Production ($s1)"
        ($rows | Where-Object { $_.Role -eq 'Key Vault Administrator' }).Scope | Should -Be "resource kv-app in resource group rg-app in the subscription Example Production ($s1)"
        ($rows | Where-Object { $_.Role -eq 'User Administrator' }).Scope | Should -Be 'the whole directory'
        @($rows | Where-Object { $_.Action -eq 'Remove the role assignment' }).Count | Should -Be 8
        (Get-Content $file -Raw) | Should -Not -Match ';|>|<|Ann Larsen|Pat Moreno' -Because 'the file goes to the client and keeps the copy rules of an email'
    }

    It 'lists one row per resource in the CSV' {
        @($csv | Where-Object CR -eq 'CR-06').Resource | Should -Be @('kv-app', 'kv-dev')
        ($csv | Where-Object { $_.CR -eq 'CR-04' }).CurrentSetting | Should -Be 'minimum TLS 1.0, SCM minimum TLS 1.2' -Because 'the rollback restores both recorded values'
        ($csv | Where-Object { $_.CR -eq 'CR-14' }).CurrentSetting | Should -Be 'minimum TLS 1.0' -Because 'Cosmos DB writes TLS 1.0 as Tls'
        ($csv | Where-Object { $_.CR -eq 'CR-12' }).ResourceId | Should -Be "/subscriptions/$s1/resourceGroups/rg-msg/providers/Microsoft.ServiceBus/namespaces/sb-orders"
        @($csv | Where-Object CR -eq 'CR-13').Resource | Should -Be @('evh-telemetry', 'evh-audit')
        @($csv | Where-Object CR -eq 'CR-01').Count | Should -Be 2
        ($csv | Where-Object { $_.CR -eq 'CR-09' -and $_.Resource -eq 'vm-old' }).ResourceId | Should -Be "/subscriptions/$s2/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-old"
        $mgmt = @($csv | Where-Object CR -eq 'CR-16')
        @($mgmt.Resource) | Should -Be @('nsg-web/Allow-RDP', 'nsg-jump/Allow-SSH-HTTPS')
        ($mgmt | Where-Object Resource -eq 'nsg-web/Allow-RDP').ResourceId | Should -Be "/subscriptions/$s1/resourceGroups/rg-web/providers/Microsoft.Network/networkSecurityGroups/nsg-web/securityRules/Allow-RDP" -Because 'the CSV names the rule by its resource ID'
        ($mgmt | Where-Object Resource -eq 'nsg-jump/Allow-SSH-HTTPS').CurrentSetting | Should -Be 'priority 310, allow inbound, protocol TCP, source *, source ports *, destination *, destination ports (22, 443), description "Jump box access, vendor", applies to network interface nic-jump01 of virtual machine vm-jump01' -Because 'the CSV carries every property the rollback needs, cleaned to the copy rules like every file'
        $ftps = @($csv | Where-Object CR -eq 'CR-17')
        @($ftps.Resource) | Should -Be @('app-portal', 'func-jobs', 'app-partners')
        ($ftps | Where-Object Resource -eq 'app-portal').CurrentSetting | Should -Be 'FTP state All allowed, minimum TLS 1.0'
        ($ftps | Where-Object Resource -eq 'app-partners').ResourceId | Should -Be "/subscriptions/$s2/resourceGroups/rg-api/providers/Microsoft.Web/sites/app-partners"
        $private = @($csv | Where-Object CR -eq 'CR-18')
        @($private | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Subscription, $_.ResourceGroup, $_.Resource, $_.CurrentSetting }) | Should -Be @(
            "Example Production ($s1)|rg-web|stweb/downloads|anonymous access level Container, readable anonymously today"
            "Example Production ($s1)|rg-web|stweb/images|anonymous access level Blob, readable anonymously today") -Because 'CR-18 tracks one row per container, with the level the rollback restores'
        ($private | Where-Object Resource -eq 'stweb/images').ResourceId | Should -Be "/subscriptions/$s1/resourceGroups/rg-web/providers/Microsoft.Storage/storageAccounts/stweb/blobServices/default/containers/images"
        $roles = @($csv | Where-Object CR -eq 'CR-19')
        $roles.Count | Should -Be 10 -Because 'CR-19 tracks one row per assignment it removes and one per group membership'
        $mg = $roles | Where-Object { $_.CurrentSetting -match 'management group scope' }
        @($mg.Subscription, $mg.ResourceGroup, $mg.Resource) | Should -Be @('', '', 'morgan.reyes@contoso.com, Reader')
        $mg.CurrentSetting | Should -Be "Azure role Reader (/subscriptions/$s1/providers/microsoft.authorization/roledefinitions/$($roleIds.Reader)) at management group scope $mgScope, assigned to morgan.reyes@contoso.com (object ID $morgan)" -Because 'the rollback recreates each assignment from its role, scope and account'
        $mg.ResourceId | Should -Match ('^{0}/providers/Microsoft\.Authorization/roleAssignments/[0-9a-f-]{{36}}$' -f [regex]::Escape($mgScope))
        ($roles | Where-Object { $_.CurrentSetting -match 'Eligible' }).CurrentSetting | Should -Be "Microsoft Entra role Security Reader ($($roleIds.SecReader)), Eligible until 2027-03-31T00:00:00Z, directory scope /, assigned to lee.ashford@contoso.com (object ID $lee)"
        ($roles | Where-Object { $_.Resource -eq 'lee.ashford@contoso.com, Storage Blob Data Contributor' }).Subscription | Should -Be "Example, Dev Test ($s2)"
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
        $index | Should -Match 'CR-01, CR-02, CR-03, CR-04, CR-06, CR-07, CR-08, CR-11, CR-12, CR-13, CR-14, CR-16, CR-17, CR-18, CR-19 ask the client to approve the proposed date'
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

    It 'writes a client email for every change request, CR-01 to CR-19' {
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
                # An email that attaches a CSV lists it after the email, under the same base name.
                $index | Should -Match ('\| {0} \| [^|]+ \| \d+ \| Change request and client email(, partial collection scope)? \| {1}, {2}(, {3})? \|' -f $number, [regex]::Escape($cr.Name), [regex]::Escape($cr.BaseName + '.email.txt'), [regex]::Escape($cr.BaseName + '.email.csv')) -Because $cr.Name
                foreach ($attached in @(Get-ChildItem $out -Filter ($cr.BaseName + '.email.csv'))) { Get-Content $attached.FullName -Raw | Should -Not -Match ';|>|<' -Because "$($attached.Name) goes to the client with the email" }
            }
            $index | Should -Not -Match '\| Change request \|' -Because 'no change request is listed without its email'
        }
        @($written | Sort-Object -Unique) | Should -Be @(1..19) -Because 'the two packs between them write every change request'
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
        # Azure takes one rule per priority in each direction of a group.
        $row = { param($name, $protocol, $source, $port, $priority = 150) @{ subscriptionId = $s1; resourceGroup = 'rg-web'; NSG = 'nsg-v6'; NsgId = $id; RuleName = $name; RuleId = "$id/securityRules/$name"; Priority = $priority; Protocol = $protocol
                SourcePrefixes = @($source); SourcePorts = @('*'); DestinationPrefixes = @('*'); DestinationAsgs = @(); DestinationPorts = @($port); Association = 'Subnet'; Subnets = @($subnet); Nics = @(); NicVms = @(); ApplianceNicIds = @(); ApplianceSubnetIds = @() } }
        Set-PackResult $pack 'NB.2-DETAIL' @((& $row 'Allow-SSH-v6' 'Tcp' '::/0' '22'), (& $row 'Allow-App-UDP' 'Udp' '*' '22' 160), (& $row 'Allow-RDP-Any' '*' 'Internet' '3389' 170))
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        $text = Get-Content (Join-Path $out 'CR-16-management-ports.txt') -Raw
        $text | Should -Match '- nsg-v6/Allow-SSH-v6, resource group rg-web, priority 150, allow inbound, protocol TCP, source ::/0,' -Because 'the IPv6 any-address prefix is the internet too'
        $text | Should -Match '- nsg-v6/Allow-RDP-Any, resource group rg-web, priority 170, allow inbound, protocol Any, source Internet,' -Because 'a rule for any protocol carries TCP'
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
        $row = { param($name, $group, $sub, $priority, $source, [string[]]$ports, $association, $attached)
            $id = "/subscriptions/$sub/resourceGroups/rg-win/providers/Microsoft.Network/networkSecurityGroups/$group"
            @{ subscriptionId = $sub; resourceGroup = 'rg-win'; NSG = $group; NsgId = $id; RuleName = $name; RuleId = "$id/securityRules/$name"; Priority = $priority; Direction = 'Inbound'; Access = 'Allow'; Protocol = 'Tcp'
                SourcePrefixes = @($source); SourcePorts = @('*'); DestinationPrefixes = @('*'); DestinationAsgs = @(); DestinationPorts = $ports; Description = ''; Association = $association; RangeNeedsReview = $false
                Subnets = @(if ($association -eq 'Subnet') { $attached }); Nics = @(if ($association -eq 'NIC') { $attached }); NicVms = @(); ApplianceNicIds = @(); ApplianceSubnetIds = @() } }
        $subnet = @{ id = "/subscriptions/$s1/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-ops/subnets/snet-mgmt" }
        $nic = @{ id = "/subscriptions/$s2/resourceGroups/rg-win/providers/Microsoft.Network/networkInterfaces/nic-win01" }
        # A WinRM-only rule where Plan 2 is on, a mixed RDP and WinRM rule open to 0.0.0.0/0 and an SSH rule open to
        # ::/0 where Plan 2 is off, so Azure Bastion is suggested there and both broad rules need private access.
        Set-PackResult $pack 'NB.2-DETAIL' @(
            (& $row 'Allow-WinRM' 'nsg-mgmt' $s1 200 'Internet' @('5985', '5986') 'Subnet' $subnet)
            (& $row 'Allow-RDP-WinRM' 'nsg-win' $s2 200 '0.0.0.0/0' @('3389', '5986') 'NIC' $nic)
            (& $row 'Allow-SSH-v6' 'nsg-win' $s2 210 '::/0' @('22') 'NIC' $nic))
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
        $testing | Should -Match 'In each group, rules apply in priority order and the first rule that matches the source, protocol and port of a connection decides it' -Because 'a deny for one address does not stop the rest of the internet'
        $testing | Should -Match 'confirm that no allow rule that covers the port and lists 0\.0\.0\.0/0, ::/0 or other public prefixes'
        $impl[-1] | Should -Match 'a free priority number from 100 to 4096 .* Default rules, numbered 65000 and above, always come after it\.' -Because 'a custom rule can never sit after a default rule'
        $impl[-1] | Should -Not -Match 'than every rule just-in-time' -Because 'a just-in-time deny from Any already stops the internet, so no ordering against it is needed'
        $impl[-1] | Should -Match 'For a machine that just-in-time VM access covers, check only the security admin rules, since its deny rules already stop internet sources on the ports it protects once the groups decide\.' -Because 'an Always Allow admin rule comes before the just-in-time deny too'
        $impl[-1] | Should -Match 'For a rule on a subnet, find every network interface in it on the Connected devices page of its virtual network, which lists each device with its subnet\.' -Because 'a rule on a subnet names no network interfaces'
        $impl[-1] | Should -Match 'Effective security rules lists rules only while the machine is running, so treat every management port of a stopped machine as open and note it in the change record, and read its security admin rules' -Because 'a stopped machine could start with the ports open'
        $impl[-1] | Should -Not -Match 'when it next runs'
        $impl[-1] | Should -Not -Match 'Leave out a network interface behind a rule' -Because 'a rule left unchanged exempts only its own ports, and the other open ports are still denied'
        foreach ($step in $impl[-1], ((Get-Section $text 'B) TESTING PLAN') -join "`n")) { $step | Should -Match 'The page shows only the first 50 rules, so select Download and check the complete list in the file it saves\.' -Because 'a later public allow would otherwise be missed' }
        (Get-Section $text 'B) TESTING PLAN') -join "`n" | Should -Match 'For a stopped machine, confirm instead that the deny from the Internet service tag is in place and read the Security admin configurations tab of its virtual network'
        $impl[-1] | Should -Not -Match 'protocol Any' -Because 'a deny for any protocol would also stop a UDP rule left out of CR-16 for review'
        $text | Should -Match ([regex]::Escape('View effective security rules of a network interface: https://learn.microsoft.com/azure/virtual-network/virtual-network-network-interface#view-effective-security-rules'))

        # The email asks for approval, keeps WinRM off Bastion and keeps the copy rules.
        Assert-ApprovalEmail $email 'CR-16 with WinRM'
        $email | Should -Match 'In their place, administrators would connect through just-in-time VM access or Azure Bastion, and remote PowerShell over WinRM through just-in-time VM access or from addresses you name\.'
        $email | Should -Match 'It provides RDP and SSH sessions only, so it cannot replace WinRM, which remote PowerShell uses\.'
        $email | Should -Match 'I suggest just-in-time VM access where Plan 2 is on and Azure Bastion elsewhere, unless you would rather turn Plan 2 on there\. Azure Bastion does not provide WinRM, so remote PowerShell would continue through just-in-time VM access or only from addresses you name\.'
        $email | Should -Match 'and which replacement you would like, just-in-time VM access or Azure Bastion for RDP and SSH\?'
        $email | Should -Not -Match '[;>]|->|=>|<-'
    }

    It 'escalates a Virtual Network Manager Always Allow admin rule instead of counting a network security group deny as closing the port' {
        $pack = Join-Path $TestDrive 'mgmt-admin-rules'
        New-ChangeFixture $pack
        $out = Join-Path $pack '05-change-requests'
        # Without -AdminRuleOpen: the steps still read the security admin rules, and the email names no machine.
        $null = & $generator -EvidencePath $pack
        $text = Get-Content (Join-Path $out 'CR-16-management-ports.txt') -Raw
        $email = Get-Content (Join-Path $out 'CR-16-management-ports.email.txt') -Raw
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $impl = @(Get-Section $text 'A) IMPLEMENTATION PLAN')
        $testing = (Get-Section $text 'B) TESTING PLAN') -join "`n"
        foreach ($step in $impl[-1], $testing) {
            # Security admin rules show in the effective rules and apply before both groups. Always Allow and Deny end
            # the evaluation, and Allow passes the connection on to the groups.
            $step | Should -Match 'Where Azure Virtual Network Manager applies security admin rules to the virtual network, the page and the file list them too, under the name of the virtual network manager, and they apply before both groups\. The first admin rule that matches a connection decides it: Always Allow lets it in whatever the groups say, Deny stops it whatever they say, and Allow passes it on to the groups\.'
            $step | Should -Match 'For a machine that just-in-time VM access covers, check only the security admin rules' -Because 'the just-in-time deny is a network security group rule, which an Always Allow admin rule comes before'
            $step | Should -Match 'read the Security admin configurations tab of its virtual network under Settings > Network Manager|read its security admin rules on the Security admin configurations tab of its virtual network under Settings > Network Manager' -Because 'a stopped machine shows no effective rules, but an admin rule still keeps its port open once it starts'
        }
        # Always Allow on 3389 from the internet: escalated, never closed by the deny the step adds.
        $impl[-1] | Should -Match 'Where the first security admin rule that matches an internet source on the port is an Always Allow, the port stays open whatever the groups say, so no network security group change can close it: record that admin rule, with its virtual network manager, priority, source and ports, in the change record, escalate it to whoever owns the Virtual Network Manager configuration and never count the port as closed on that interface\.'
        $impl[-1] | Should -Match 'Still add the deny below for it, so the deny applies once the admin rule is gone\.' -Because 'the deny takes effect only once the Always Allow rule is removed'
        $testing | Should -Match 'Where the first security admin rule that matches an internet source on the port is an Always Allow, never report that port as closed, even with the deny in place: confirm the admin rule is recorded in the change record and escalated to whoever owns the Virtual Network Manager configuration, and report the port as still open until that owner closes it\.'
        $text | Should -Match ([regex]::Escape('Security admin rules in Azure Virtual Network Manager: https://learn.microsoft.com/azure/virtual-network-manager/concept-security-admins#how-security-admin-rules-and-network-security-groups-nsgs-are-evaluated'))
        $text | Should -Match ([regex]::Escape('Effective security rules overview: https://learn.microsoft.com/azure/network-watcher/effective-security-rules-overview'))
        $text | Should -Match ([regex]::Escape('View configurations applied by Azure Virtual Network Manager: https://learn.microsoft.com/azure/virtual-network-manager/how-to-view-applied-configurations'))
        $text | Should -Not -Match 'Kept open by an Azure Virtual Network Manager'
        $index | Should -Match '- CR-16 changes network security group rules only\. Azure Virtual Network Manager security admin rules apply before them, and one with Always Allow ends the evaluation, so a machine whose effective security rules show such a rule for 22, 3389, 5985 or 5986 from an internet source stays open whatever CR-16 changes and is outside what CR-16 can close\.'
        $email | Should -Not -Match 'central network policy|Virtual Network Manager' -Because 'an Allow or Deny admin rule leaves nothing for the client to escalate, and no machine was named'
        Assert-ApprovalEmail $email 'CR-16 without an admin rule'

        # vm-web01 behind Allow-RDP on snet-web: an Always Allow admin rule keeps 3389 open to the internet. Each
        # machine is named by its resource ID, since a machine name is unique only within its resource group.
        $vm = { param($sub, $group, $name) "/subscriptions/$sub/resourceGroups/$group/providers/Microsoft.Compute/virtualMachines/$name" }
        $web01 = & $vm $s1 'rg-web' 'vm-web01'
        $web01Label = 'vm-web01 in resource group rg-web of subscription Example Production \({0}\)' -f $s1
        $null = & $generator -EvidencePath $pack -AdminRuleOpen "$($web01):3389"
        $text = Get-Content (Join-Path $out 'CR-16-management-ports.txt') -Raw
        $email = Get-Content (Join-Path $out 'CR-16-management-ports.email.txt') -Raw
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        Assert-ApprovalEmail $email 'CR-16 with one machine an admin rule keeps open'
        $email | Should -Match ('\r?\n\r?\nOn virtual machine {0}, a central network policy, a security admin rule in Azure Virtual Network Manager, keeps port 3389 open to the internet\. That policy applies before any network security group rule, so this change cannot close that port there, and it stays open until the policy changes\. Could you tell me who manages your Virtual Network Manager configuration, so I can raise this with them\?\r?\n' -f $web01Label)
        $text | Should -Match ("Kept open by an Azure Virtual Network Manager security admin rule with Always Allow \(-AdminRuleOpen\), which CR-16 cannot close:\r?\n- {0}: port 3389" -f $web01Label)
        $text | Should -Match 'The last lines give the path that fits each subscription, and the machines a security admin rule keeps open\.'
        (Get-Section $text 'B) TESTING PLAN') -join "`n" | Should -Match ('Report {0} \(port 3389\), which -AdminRuleOpen names as held open by a security admin rule with Always Allow, as still open and escalated, never closed\.' -f $web01Label)
        $index | Should -Match ('- CR-16 names 1 machine that a security admin rule with Always Allow keeps open to the internet \(-AdminRuleOpen\): {0} \(port 3389\)\. Its email says a central network policy keeps the port open and asks who manages it\.' -f $web01Label)

        # The same machine named twice, in another case, is one machine with both ports, and a machine of the same
        # name in another resource group stays apart.
        $dev01 = & $vm $s2 'rg-dev' 'vm-web01'
        $null = & $generator -EvidencePath $pack -AdminRuleOpen "$($web01):3389", "$($dev01):3389", "$($web01.ToUpperInvariant()):22", "$($web01):3389"
        $email = Get-Content (Join-Path $out 'CR-16-management-ports.email.txt') -Raw
        Assert-ApprovalEmail $email 'CR-16 with two machines of the same name'
        $email | Should -Match ('On virtual machines {0} \(ports 22 and 3389\) and vm-web01 in resource group rg-dev of subscription Example, Dev Test \({1}\) \(port 3389\), a central network policy, a security admin rule in Azure Virtual Network Manager, keeps those ports open to the internet\. That policy applies before any network security group rule, so this change cannot close those ports there, and they stay open until the policy changes\.' -f $web01Label, $s2)
        Get-Content (Join-Path $out '00-index.md') -Raw | Should -Match '- CR-16 names 2 machines that a security admin rule with Always Allow keeps open'
        # Only the resource ID names a machine once, so a bare name, a resource group path, another resource type,
        # another port and a missing port are refused.
        foreach ($wrong in 'vm-web01:3389', 'rg-web/vm-web01:3389', "$(& $vm $s1 'rg-web' 'vm-web01')/extensions/x:3389", ($web01 -replace 'virtualMachines', 'virtualMachineScaleSets') + ':3389', "$($web01):443", $web01) {
            { & $generator -EvidencePath $pack -AdminRuleOpen $wrong } | Should -Throw '*-AdminRuleOpen takes each machine as the resource ID of the virtual machine followed by :port, with port 22, 3389, 5985 or 5986*' -Because "$wrong does not name one virtual machine and one management port"
        }

        # With nothing for CR-16 to close, the index still names the machine for escalation.
        Set-PackResult $pack 'NB.2-DETAIL' @()
        $null = & $generator -EvidencePath $pack -AdminRuleOpen "$($web01):3389"
        Get-Content (Join-Path $out '00-index.md') -Raw | Should -Match ('- -AdminRuleOpen names 1 machine that a security admin rule with Always Allow keeps open to the internet: {0} \(port 3389\)\. CR-16 has no rule to close in this pack, so no email names it\.' -f $web01Label)
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

    It 'never changes an app that already reads FtpsOnly or Disabled, writes singular wording for one app, and reads no gaps when only apps without a state remain' {
        # NB.5-FTPS-DETAIL leaves out FtpsOnly and Disabled in any case. The generator does not rely on it, so a row
        # carrying either state is never changed.
        $pack = Join-Path $TestDrive 'ftps-single'
        New-ChangeFixture $pack
        $site = { param($name, $rg, $sub) "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Web/sites/$name" }
        Set-PackResult $pack 'NB.5-FTPS-DETAIL' @(
            @{ Name = 'app-intranet'; ResourceId = (& $site 'app-intranet' 'rg-web' $s1); resourceGroup = 'rg-web'; subscriptionId = $s1; FtpsState = 'AllAllowed'; MinTlsVersion = '1.2' }
            @{ Name = 'app-secure'; ResourceId = (& $site 'app-secure' 'rg-web' $s1); resourceGroup = 'rg-web'; subscriptionId = $s1; FtpsState = 'FtpsOnly'; MinTlsVersion = '1.2' }
            @{ Name = 'func-closed'; ResourceId = (& $site 'func-closed' 'rg-web' $s2); resourceGroup = 'rg-web'; subscriptionId = $s2; FtpsState = 'Disabled'; MinTlsVersion = '1.2' })
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        $text = Get-Content (Join-Path $out 'CR-17-app-service-ftps.txt') -Raw
        $text | Should -Match 'Set the FTP state to FTPS only, or to Disabled where the client confirms nothing uses FTP or FTPS, on the App Service app listed below\.'
        $text | Should -Match 'Plain FTP sends the deployment credentials and files unencrypted, and this app still allows it\.'
        $text | Should -Match "Subscription: Example Production \($s1\)\r?\n- app-intranet, resource group rg-web, FTP state All allowed\r?\n"
        $text | Should -Not -Match 'app-secure|func-closed|Repeat steps'
        $email = Get-Content (Join-Path $out 'CR-17-app-service-ftps.email.txt') -Raw
        Assert-ApprovalEmail $email 'CR-17 for one application'
        $email | Should -Match 'I would like your approval to stop plain FTP connections to one of your App Service and Function applications by setting its FTP state to FTPS only'
        $email | Should -Match 'The application is listed below with its FTP state today:'
        $email | Should -Match 'and whether FTPS only or Disabled suits it\? With that agreed, could you approve this change for '
        $email | Should -Not -Match 'minimum inbound TLS' -Because 'the app already requires TLS 1.2'
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Not -Match 'left out of CR-17|below 1\.2: ' -Because 'no app lacks a state and none is below TLS 1.2'
        @(Import-Csv (Join-Path $out 'change-requests.csv') | Where-Object CR -eq 'CR-17').Resource | Should -Be @('app-intranet')

        Set-PackResult $pack 'NB.5-FTPS-DETAIL' @(@{ Name = 'func-flex'; ResourceId = (& $site 'func-flex' 'rg-jobs' $s2); resourceGroup = 'rg-jobs'; subscriptionId = $s2; FtpsState = ''; MinTlsVersion = '1.2' })
        $null = & $generator -EvidencePath $pack
        Test-Path (Join-Path $out 'CR-17-app-service-ftps.txt') | Should -BeFalse -Because 'an app without a recorded state is not changed'
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '\| 17 \| Plain FTP and FTP basic authentication turned off on App Service apps \|  \| Only apps without a recorded FTP state remain, the FTP basic authentication part needs recollection with CyberSOC collector 1\.14\.0 or later \|  \|'
        $index | Should -Match '1 App Service app left out of CR-17 because Resource Graph returned an empty FTP state.*: func-flex \(resource group rg-jobs\)\.'

        Set-PackResult $pack 'NB.5-FTPS-DETAIL' @()
        $null = & $generator -EvidencePath $pack
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '\| 17 \| Plain FTP and FTP basic authentication turned off on App Service apps \|  \| No FTP state gaps found, the FTP basic authentication part needs recollection with CyberSOC collector 1\.14\.0 or later \|  \|' -Because 'a pack before 1.14.0 does not record FTP basic authentication, which matters on every app'
        $index | Should -Match 'Deployment slots have a configuration of their own, which the pack does not read, so CR-17 does not cover them\.' -Because 'a slot can still allow plain FTP when every production site is enforced'
        Set-PackResult $pack 'NB.5' @(@{ Configs = 0; FtpsEnforced = 0; MinTls12 = 0 })
        $null = & $generator -EvidencePath $pack
        Get-Content (Join-Path $out '00-index.md') -Raw | Should -Not -Match 'Deployment slots' -Because 'a pack with no App Service site has no slot'
        Set-PackResult $pack 'NB.5' @(@{ Configs = 4; FtpsEnforced = 4; MinTls12 = 4 })
        $null = & $generator -EvidencePath $pack
        Get-Content (Join-Path $out '00-index.md') -Raw | Should -Match 'Deployment slots have a configuration of their own' -Because 'the sites may have slots that still allow plain FTP'
    }

    It 'reads needs recollection on a pack collected before the per-resource results, and clears stale change requests' {
        $pack = Join-Path $TestDrive 'old'
        New-ChangeFixture $pack
        $null = & $generator -EvidencePath $pack
        foreach ($id in 'P0.7', 'NB.2-DETAIL', 'NB.4-DETAIL', 'NB.5-DETAIL', 'NB.5-FTPS-DETAIL', 'NB.6-DETAIL', 'NB.6-PAAS-DETAIL', 'DP.1-DETAIL', 'DP.1-CONTAINERS-DETAIL', 'DP.2-DETAIL', 'DP.4-VMSS-ELIGIBILITY', 'IA.15-DISABLED', 'IA.15-RBAC', 'IA.15-ENTRA') { Remove-PackResult $pack $id }
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
        $index | Should -Match '\| 17 \| Plain FTP and FTP basic authentication turned off on App Service apps \|  \| Needs recollection with CyberSOC collector 1\.14\.0 or later \|' -Because 'NB.5-FTPS-DETAIL was added in 1.7.0 and NB.5-FTPAUTH-DETAIL, also missing, in 1.14.0'
        $index | Should -Match '\| 18 \| Blob containers set to private access \|  \| Needs recollection with CyberSOC collector 1\.8\.0 or later \|' -Because 'DP.1-CONTAINERS-DETAIL was added in 1.8.0'
        $index | Should -Match '\| 19 \| Roles removed from disabled accounts \|  \| Needs recollection with CyberSOC collector 1\.9\.0 or later \|' -Because 'IA.15-DISABLED was added in 1.9.0'
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
        Set-PackResult $pack 'DP.1-CONTAINERS-DETAIL' @(@{ subscriptionId = $s1; resourceGroup = 'rg-web'; Account = 'stpublic'; Container = 'assets'; AccessLevel = 'Container'; AccountAnonymousAccess = 'Allowed'; ReadableToday = $true; AccountId = (& $sa 'stpublic' 'rg-web' $s1); ResourceId = (& $sa 'stpublic' 'rg-web' $s1) + '/blobServices/default/containers/assets' }) 'PARTIAL'
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
        @($index -split "`n" | Where-Object { $_ -match 'CR-07' -and $_ -match 'stblocked|stfiles' }).Count | Should -Be 0 -Because 'an account that blocks anonymous access, or holds no blob service, is not a CR-07 gap'
    }

    It 'reads No gaps found when no account qualifies, and still names the accounts left out' {
        $pack = Join-Path $TestDrive 'containers-none'
        New-ChangeFixture $pack
        $sa = { param($name, $rg, $sub) "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Storage/storageAccounts/$name" }
        Set-PackResult $pack 'DP.1-CONTAINERS' @(
            @{ Account = 'stdata'; ResourceId = (& $sa 'stdata' 'rg-data' $s1); Containers = 2; PublicContainers = 1; ExposedContainers = 1; PublicContainerNames = 'exports (Blob)'; ReadStatus = 'OK' }
            @{ Account = 'stweb'; ResourceId = (& $sa 'stweb' 'rg-web' $s1); Containers = 3; PublicContainers = 2; ExposedContainers = 2; PublicContainerNames = 'images (Blob), downloads (Container)'; ReadStatus = 'OK' })
        $detail = { param($account, $rg, $name, $level) @{ subscriptionId = $s1; resourceGroup = $rg; Account = $account; Container = $name; AccessLevel = $level; AccountAnonymousAccess = 'Allowed'; ReadableToday = $true; AccountId = (& $sa $account $rg $s1); ResourceId = (& $sa $account $rg $s1) + "/blobServices/default/containers/$name" } }
        Set-PackResult $pack 'DP.1-CONTAINERS-DETAIL' @((& $detail 'stdata' 'rg-data' 'exports' 'Blob'), (& $detail 'stweb' 'rg-web' 'images' 'Blob'), (& $detail 'stweb' 'rg-web' 'downloads' 'Container'))
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        Test-Path (Join-Path $out 'CR-07-storage-anonymous-access.txt') | Should -BeFalse
        Test-Path (Join-Path $out 'CR-07-storage-anonymous-access.email.txt') | Should -BeFalse
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '\| 07 \| Anonymous blob access disabled on storage accounts \|  \| No gaps found \|  \|'
        $index | Should -Match ([regex]::Escape('- 2 storage accounts left out of CR-07 because each has a container set to Blob or Container access, which anyone can read today without signing in: stdata (resource group rg-data): exports (Blob) / stweb (resource group rg-web): images (Blob), downloads (Container).'))
        @(Import-Csv (Join-Path $out 'change-requests.csv') | Where-Object CR -eq 'CR-07').Count | Should -Be 0
    }

    It 'keeps CR-18 readable for a large estate, with $web, blocked, unread and FileStorage accounts named in the index' {
        $pack = Join-Path $TestDrive 'containers-large'
        New-ChangeFixture $pack
        $sa = { param($name, $rg, $sub) "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Storage/storageAccounts/$name" }
        $account = { param($name, $rg, $sub, $kind = 'StorageV2') @{ Name = $name; ResourceId = (& $sa $name $rg $sub); Kind = $kind; resourceGroup = $rg; subscriptionId = $sub; SecureTransfer = $true; MinimumTlsVersion = 'TLS1_2'; AllowBlobPublicAccess = $true; NfsV3 = $false } }
        # DP.1-DETAIL lists the accounts that allow anonymous access. starchive blocks it and passes every other check.
        Set-PackResult $pack 'DP.1-DETAIL' @(
            (& $account 'stwebassets' 'rg-web' $s1)
            (& $account 'stsite' 'rg-web' $s1)
            (& $account 'stmediaprod' 'rg-media' $s1)
            (& $account 'stpartners' 'rg-share' $s2)
            (& $account 'stdenied' 'rg-data' $s2)
            (& $account 'stpremfiles' 'rg-files' $s2 'FileStorage'))
        $listed = { param($name, $rg, $sub, $access, $count, $names, $status = 'OK')
            $public = @($names | Where-Object { $_ }).Count
            @{ subscriptionId = $sub; resourceGroup = $rg; Account = $name; AccountAnonymousAccess = $access; ResourceId = (& $sa $name $rg $sub); Containers = $count; PublicContainers = $public; ExposedContainers = $(if ($access -eq 'Disabled') { 0 } else { $public }); PublicContainerNames = (@($names | Select-Object -First 25) -join ', ') + $(if ($public -gt 25) { ', and {0} more' -f ($public - 25) } else { '' }); ReadStatus = $status } }
        $media = @(1..30 | ForEach-Object { 'media-{0:000}' -f $_ })
        $level = { param($i) if ($i % 3) { 'Blob' } else { 'Container' } }
        Set-PackResult $pack 'DP.1-CONTAINERS' @(
            (& $listed 'stwebassets' 'rg-web' $s1 'Allowed' 4 @('images (Blob)', 'downloads (Container)', '$web (Blob)'))
            (& $listed 'stsite' 'rg-web' $s1 'Allowed' 2 @('$web (Blob)'))
            (& $listed 'stmediaprod' 'rg-media' $s1 'Not set, allowed' 34 @(for ($i = 1; $i -le 30; $i++) { '{0} ({1})' -f $media[$i - 1], (& $level $i) }))
            (& $listed 'stpartners' 'rg-share' $s2 'Allowed' 2 @('partner-drop (Container)'))
            (& $listed 'starchive' 'rg-data' $s2 'Disabled' 5 @('legacy-exports (Container)', 'old-site (Blob)'))
            (& $listed 'stdenied' 'rg-data' $s2 'Allowed' 0 @() 'HTTP 403: Forbidden | AuthorizationFailed')) 'PARTIAL'
        $container = { param($account, $rg, $sub, $name, $level, $access)
            $id = & $sa $account $rg $sub
            @{ subscriptionId = $sub; resourceGroup = $rg; Account = $account; Container = $name; AccessLevel = $level; AccountAnonymousAccess = $access; ReadableToday = ($access -ne 'Disabled'); AccountId = $id; ResourceId = "$id/blobServices/default/containers/$name" } }
        Set-PackResult $pack 'DP.1-CONTAINERS-DETAIL' @(
            (& $container 'stwebassets' 'rg-web' $s1 'images' 'Blob' 'Allowed')
            (& $container 'stwebassets' 'rg-web' $s1 'downloads' 'Container' 'Allowed')
            (& $container 'stwebassets' 'rg-web' $s1 '$web' 'Blob' 'Allowed')
            (& $container 'stsite' 'rg-web' $s1 '$web' 'Blob' 'Allowed')
            @(for ($i = 1; $i -le 30; $i++) { & $container 'stmediaprod' 'rg-media' $s1 $media[$i - 1] (& $level $i) 'Not set, allowed' })
            (& $container 'stpartners' 'rg-share' $s2 'partner-drop' 'Container' 'Allowed')
            (& $container 'starchive' 'rg-data' $s2 'legacy-exports' 'Container' 'Disabled')
            (& $container 'starchive' 'rg-data' $s2 'old-site' 'Blob' 'Disabled')) 'PARTIAL'
        $null = & $generator -EvidencePath $pack -ClientContact 'Dana'
        $out = Join-Path $pack '05-change-requests'
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '\| 18 \| Blob containers set to private access \| 33 \| Change request and client email, partial collection scope \|' -Because 'a container in the account not listed may be missing'
        $text = Get-Content (Join-Path $out 'CR-18-storage-private-containers.txt') -Raw
        @(Get-Section $text 'A) CHANGE DESCRIPTION') | Should -Be @('Set the anonymous access level of the 33 blob containers listed below to Private, in 3 storage accounts that allow anonymous access.')
        $mediaLine = '- stmediaprod, resource group rg-media, 30 containers: ' + ((@(for ($i = 1; $i -le 30; $i++) { '{0} ({1})' -f $media[$i - 1], (& $level $i) })) -join ', ')
        @(Get-Section $text 'C) RESOURCES') | Should -Be @(
            'The 33 containers below are set to Blob or Container access in 3 storage accounts that allow anonymous access, so anyone can read them today. Each account lists its containers with the level recorded at collection. CR-07 turns anonymous access off at the account level only where no container is set to Blob or Container, so a later pack picks each account up for CR-07 once every container in it reads Private.'
            "Subscription: Example Production ($s1)"
            $mediaLine
            '- stwebassets, resource group rg-web, 2 containers: downloads (Container), images (Blob)'
            "Subscription: Example, Dev Test ($s2)"
            '- stpartners, resource group rg-share, 1 container: partner-drop (Container)') -Because 'a large account reads as one line, with every container named and counted'
        $text | Should -Match '6\. Repeat steps 1 to 5 for each remaining storage account listed\.'
        $text | Should -Not -Match 'starchive|stdenied|stpremfiles|legacy-exports|stsite' -Because 'only containers anyone can read today are changed, $web never'
        $text | Should -Match '5\. If another container in the account, other than \$web, shows Blob or Container' -Because '$web is never set to private by CR-18'
        $email = Get-Content (Join-Path $out 'CR-18-storage-private-containers.email.txt') -Raw
        Assert-ApprovalEmail $email 'CR-18 for a large estate'
        $email | Should -Match 'I would like your approval to set 33 of your Azure Blob Storage containers to private access, so they can no longer be read without signing in\. Each of them is set to public access today, and their storage accounts allow it'
        $email | Should -Match "The 33 containers are listed below by subscription and storage account, with the number in each account and the access level of each container today\. Anyone can read every one of them without signing in:\r?\n\r?\nSubscription Example Production \($s1\):\r?\n\r?\n- stmediaprod \(resource group rg-media\), 30 containers: media-001 \(Blob\), media-002 \(Blob\), media-003 \(Container\), [^\r\n]+, media-030 \(Container\)\r?\n- stwebassets \(resource group rg-web\), 2 containers: downloads \(Container\), images \(Blob\)\r?\n\r?\nSubscription Example, Dev Test \($s2\):\r?\n\r?\n- stpartners \(resource group rg-share\), 1 container: partner-drop \(Container\)\r?\n\r?\nEach container can be set back"
        @($email -split "`r?`n" | Where-Object { $_ -match '^- ' }).Count | Should -Be 3 -Because 'the email lists one line per account, however many containers it holds'
        $email | Should -Not -Match '\$web|starchive|stdenied|stpremfiles'
        $private = @(Import-Csv (Join-Path $out 'change-requests.csv') | Where-Object CR -eq 'CR-18')
        $private.Count | Should -Be 33 -Because 'the CSV keeps one row per container'
        @($private | Where-Object Resource -like '*$web*').Count | Should -Be 0
        @($private | Where-Object Resource -like 'stmediaprod/*').Count | Should -Be 30
        ($private | Where-Object Resource -eq 'stmediaprod/media-003').CurrentSetting | Should -Be 'anonymous access level Container, readable anonymously today'
        $index | Should -Match ([regex]::Escape('- 2 static website containers ($web) set to Blob or Container access left out of CR-18: stsite (resource group rg-web), Blob access, stwebassets (resource group rg-web), Blob access. A static website is served from the web endpoint of its account whatever the access level of $web, so setting it to Private would not close the site and would only stop anonymous reads of the same files through the blob endpoint. Set it to Private on its own once the owner confirms nothing links to the blob endpoint addresses of the site. An account that allows anonymous access stays out of CR-07 until then.'))
        $index | Should -Match ([regex]::Escape('- 2 containers set to Blob or Container access in a storage account that blocks anonymous access left out of CR-18: starchive (resource group rg-data), 2 containers: legacy-exports (Container), old-site (Blob). The account setting keeps them closed, so no one can read them anonymously today'))
        $index | Should -Match ([regex]::Escape('They would open again as soon as the account allowed anonymous access, so any change that relaxes the account setting also sets them to Private.'))
        $index | Should -Match ([regex]::Escape('- 1 storage account left out of CR-18 because DP.1-CONTAINERS could not list its containers: stdenied (resource group rg-data). A container set to Blob or Container there is not in CR-18, so recollect the pack.'))
        $index | Should -Match ([regex]::Escape('- 1 FileStorage account left out of CR-18 because it holds no blob service, so it has no blob containers to change: stpremfiles (resource group rg-files).'))
        $index | Should -Match ([regex]::Escape('- 3 storage accounts left out of CR-07 because each has a container set to Blob or Container access, which anyone can read today without signing in: ')) -Because 'the same accounts wait for CR-18 before CR-07'
        $index | Should -Match ([regex]::Escape('and sets the container to private. CR-18 leaves out the static website container ($web), which is set to Private on its own, as the CR-18 notes say. A later pack picks each account up for CR-07')) -Because 'stwebassets also has a public $web, which CR-18 does not change'
        $index | Should -Match ([regex]::Escape('- 1 storage account left out of CR-07 because its only public container is the static website container ($web), set to Blob or Container access: stsite (resource group rg-web): $web (Blob). CR-18 does not change $web, since the site is served from the web endpoint whatever its level. Set $web to Private on its own, as the CR-18 notes say, once the owner confirms nothing links to the blob endpoint addresses of the site, and a later pack picks the account up for CR-07.')) -Because 'an account whose only public container is $web never reaches CR-07 through CR-18'
        @($index -split "`n" | Where-Object { $_ -match 'CR-18 asks the owner' -and $_ -match 'stsite' }).Count | Should -Be 0
    }

    It 'writes singular wording for one container in one account' {
        $pack = Join-Path $TestDrive 'containers-one'
        New-ChangeFixture $pack
        $id = "/subscriptions/$s1/resourceGroups/rg-web/providers/Microsoft.Storage/storageAccounts/stweb"
        Set-PackResult $pack 'DP.1-CONTAINERS-DETAIL' @(@{ subscriptionId = $s1; resourceGroup = 'rg-web'; Account = 'stweb'; Container = 'images'; AccessLevel = 'Blob'; AccountAnonymousAccess = 'Allowed'; ReadableToday = $true; AccountId = $id; ResourceId = "$id/blobServices/default/containers/images" })
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        $text = Get-Content (Join-Path $out 'CR-18-storage-private-containers.txt') -Raw
        @(Get-Section $text 'A) CHANGE DESCRIPTION') | Should -Be @('Set the anonymous access level of the blob container listed below to Private, in a storage account that allows anonymous access.')
        @(Get-Section $text 'B) PURPOSE')[0] | Should -Match '^Anyone can read this container today without signing in, so setting it to Private stops'
        @(Get-Section $text 'C) RESOURCES')[0] | Should -Match '^The container below is set to Blob or Container access in a storage account that allows anonymous access, so anyone can read it today\. The account lists'
        $text | Should -Match '- stweb, resource group rg-web, 1 container: images \(Blob\)'
        $text | Should -Not -Match 'Repeat steps'
        $email = Get-Content (Join-Path $out 'CR-18-storage-private-containers.email.txt') -Raw
        Assert-ApprovalEmail $email 'CR-18 for one container'
        $email | Should -Match 'I would like your approval to set one of your Azure Blob Storage containers to private access, so it can no longer be read without signing in\. It is set to public access today, and its storage account allows it'
        $email | Should -Match 'Setting the container to private stops anonymous reads straight away\. A website, an application, a content delivery network or a link that reads files from it without signing in'
        $email | Should -Match 'Just before the change, I will check the container again and leave it unchanged if its access level has changed since my review\.'
        $email | Should -Match "The container is listed below under its storage account, with its access level today\. Anyone can read it without signing in:\r?\n\r?\nSubscription Example Production \($s1\):\r?\n\r?\n- stweb \(resource group rg-web\), 1 container: images \(Blob\)"
        $email | Should -Match 'The container can be set back to the access level it has today at any time'
        $email | Should -Match 'Before I schedule the change, could you ask the owner of the container to confirm that it serves no public content\? Where it does, its files can move to shared access signatures, [^?]+, and I will leave it out until they have moved\.'
    }

    It 'writes no CR-18 when only blocked or static website containers remain, and no gaps when no container is public' {
        $pack = Join-Path $TestDrive 'containers-closed'
        New-ChangeFixture $pack
        $id = "/subscriptions/$s2/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/starchive"
        $web = "/subscriptions/$s1/resourceGroups/rg-web/providers/Microsoft.Storage/storageAccounts/stweb"
        Set-PackResult $pack 'DP.1-CONTAINERS-DETAIL' @(
            @{ subscriptionId = $s2; resourceGroup = 'rg-data'; Account = 'starchive'; Container = 'legacy-exports'; AccessLevel = 'Container'; AccountAnonymousAccess = 'Disabled'; ReadableToday = $false; AccountId = $id; ResourceId = "$id/blobServices/default/containers/legacy-exports" }
            @{ subscriptionId = $s1; resourceGroup = 'rg-web'; Account = 'stweb'; Container = '$web'; AccessLevel = 'Blob'; AccountAnonymousAccess = 'Allowed'; ReadableToday = $true; AccountId = $web; ResourceId = "$web/blobServices/default/containers/`$web" })
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        Test-Path (Join-Path $out 'CR-18-storage-private-containers.txt') | Should -BeFalse
        Test-Path (Join-Path $out 'CR-18-storage-private-containers.email.txt') | Should -BeFalse
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '\| 18 \| Blob containers set to private access \|  \| Only containers the account setting already blocks, or static website containers, remain, see the notes \|  \|'
        $index | Should -Match ([regex]::Escape('- 1 static website container ($web) set to Blob or Container access left out of CR-18: stweb (resource group rg-web), Blob access.'))
        $index | Should -Match ([regex]::Escape('- 1 container set to Blob or Container access in a storage account that blocks anonymous access left out of CR-18: starchive (resource group rg-data), 1 container: legacy-exports (Container).'))
        @(Import-Csv (Join-Path $out 'change-requests.csv') | Where-Object CR -eq 'CR-18').Count | Should -Be 0
        Set-PackResult $pack 'DP.1-CONTAINERS-DETAIL' @()
        $null = & $generator -EvidencePath $pack
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '\| 18 \| Blob containers set to private access \|  \| No gaps found \|  \|'
        $index | Should -Not -Match 'left out of CR-18: |Before CR-18 is sent' -Because 'with nothing to change there is nothing to check first'
    }

    It 'writes CR-19 for the Azure side alone when the Entra roles could not be read, and says which side is missing and why' {
        $pack = Join-Path $TestDrive 'roles-azure-only'
        New-ChangeFixture $pack
        Set-PackResult $pack 'IA.15-ENTRA' @() 'UNAVAILABLE' 'Not a zero: the Graph token cannot read Microsoft Entra role assignments, so the Entra roles held by the disabled accounts are unknown. Needs RoleManagement.Read.Directory. Fix: az login --tenant example-tenant --scope https://graph.microsoft.com/RoleManagement.Read.Directory, then rerun.'
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '\| 19 \| Roles removed from disabled accounts \| 7 \| Change request and client email \|' -Because 'the Azure roles held through a group add a membership row each'
        $index | Should -Match '- The Microsoft Entra roles of the disabled accounts are unknown, not a zero, because IA\.15-ENTRA could not be used: it reads UNAVAILABLE: Not a zero: the Graph token cannot read Microsoft Entra role assignments.+Needs RoleManagement\.Read\.Directory\.'
        $text = Get-Content (Join-Path $out 'CR-19-disabled-account-roles.txt') -Raw
        @(Get-Section $text 'A) CHANGE DESCRIPTION')[0] | Should -Be 'Remove the 5 Azure role assignments assigned directly to the 3 disabled user accounts listed below, at the scope where each was made, and remove 2 of them from 2 groups through which they hold 2 more role assignments.'
        $text | Should -Not -Match 'Microsoft Entra role assignments:|Roles and administrators|Privileged Identity Management > Microsoft Entra'
        $email = Get-Content (Join-Path $out 'CR-19-disabled-account-roles.email.txt') -Raw
        Assert-ApprovalEmail $email 'CR-19 with the Azure side only'
        $email | Should -Match 'I would like your approval to remove the Azure roles still held by 3 disabled accounts in your tenant, by removing the roles assigned to the accounts themselves and, where a group holds a role for one of them, by removing that account from the group\.'
        $email | Should -Match 'The accounts and their roles are in the attached file CR-19-disabled-account-roles\.email\.csv, [^\r\n]+ as follows:\r?\n\r?\nSubscription Example Production'
        $email | Should -Not -Match 'Microsoft Entra ID directory roles'
        # An unreadable result file is never read as no roles.
        Set-PackResult $pack 'IA.15-ENTRA' @() 'OK'
        Set-Content (Join-Path $pack 'results/IA.15-ENTRA.json') '{ not json'
        $null = & $generator -EvidencePath $pack 3>$null
        (Get-Content (Join-Path $out '00-index.md') -Raw) | Should -Match '- The Microsoft Entra roles of the disabled accounts are unknown, not a zero, because IA\.15-ENTRA could not be used: its result file is unreadable, so recollect or restore the pack\.'
    }

    It 'writes no CR-19 when the users could not be read, and never reads a side it could not read as no gaps' {
        $pack = Join-Path $TestDrive 'roles-states'
        New-ChangeFixture $pack
        $out = Join-Path $pack '05-change-requests'
        $state = { (Get-Content (Join-Path $out '00-index.md') -Raw) -split "`n" | Where-Object { $_ -match '^\| 19 \|' } }
        $denied = 'Not a zero: the Graph token cannot read user accounts, so the disabled accounts, and the roles they hold, are unknown. Needs User.Read.All.'
        foreach ($id in 'IA.15-DISABLED', 'IA.15-RBAC', 'IA.15-ENTRA') { Set-PackResult $pack $id @() 'UNAVAILABLE' $denied }
        $null = & $generator -EvidencePath $pack
        & $state | Should -Be '| 19 | Roles removed from disabled accounts |  | Not collected (IA.15-DISABLED UNAVAILABLE) |  |'
        Test-Path (Join-Path $out 'CR-19-disabled-account-roles.txt') | Should -BeFalse
        New-ChangeFixture $pack
        Set-PackResult $pack 'IA.15-RBAC' @() 'FAILED' 'The Azure role assignments could not be read. HTTP 429'
        Set-PackResult $pack 'IA.15-ENTRA' @() 'UNAVAILABLE' 'Not a zero: Needs RoleManagement.Read.Directory.'
        $null = & $generator -EvidencePath $pack
        & $state | Should -Be '| 19 | Roles removed from disabled accounts |  | Not collected (IA.15-RBAC FAILED, IA.15-ENTRA UNAVAILABLE) |  |'
        Set-PackResult $pack 'IA.15-RBAC' @() 'EMPTY'
        $null = & $generator -EvidencePath $pack
        & $state | Should -Be '| 19 | Roles removed from disabled accounts |  | No gaps found in the Azure roles, Microsoft Entra roles not collected (IA.15-ENTRA UNAVAILABLE), see the notes |  |'
        Set-PackResult $pack 'IA.15-RBAC' @((& $azureRole "/subscriptions/$s2/resourceGroups/rg-ops" 'Contributor' $roleIds.Contributor $kim $dynGroup))
        Set-PackResult $pack 'IA.15-ENTRA' @((& $entraRole 'Global Administrator' $roleIds.Ga 'Standing' $ann))
        $null = & $generator -EvidencePath $pack
        & $state | Should -Be '| 19 | Roles removed from disabled accounts |  | Only roles held through groups whose members cannot be changed here remain, see the notes |  |' -Because 'an enabled account is never listed, and a member cannot be removed from a dynamic membership group'
        Set-PackResult $pack 'IA.15-RBAC' @((& $azureRole "/subscriptions/$s2/resourceGroups/rg-ops" 'Contributor' $roleIds.Contributor $kim $opsOld))
        $null = & $generator -EvidencePath $pack
        & $state | Should -Be '| 19 | Roles removed from disabled accounts |  | Only roles held through groups remain, see the notes |  |' -Because 'a pack collected before 1.10.0 does not record the group each account sits in'
        (Get-Content (Join-Path $out '00-index.md') -Raw) | Should -Match 'Collect again with CyberSOC collector 1\.10\.0 or later, and CR-19 removes each account from its group\.'
        foreach ($id in 'IA.15-DISABLED', 'IA.15-RBAC', 'IA.15-ENTRA') { Set-PackResult $pack $id @() }
        $null = & $generator -EvidencePath $pack
        & $state | Should -Be '| 19 | Roles removed from disabled accounts |  | No gaps found |  |'
        Set-PackResult $pack 'IA.15-RBAC' @() 'PARTIAL' "0 Azure role assignments held by 0 of the 2 disabled accounts. Read through Lighthouse, which shows the managing tenant's delegations rather than the client's own role assignments, so this is incomplete."
        Set-PackResult $pack 'IA.15-ENTRA' @() 'PARTIAL' 'Eligible assignments not visible, needs RoleManagement.Read.Directory, so only active assignments are listed and an activated one reads as Standing.'
        $null = & $generator -EvidencePath $pack
        & $state | Should -Be '| 19 | Roles removed from disabled accounts |  | No roles found in what was read, IA.15-RBAC and IA.15-ENTRA read in part, see the notes |  |' -Because 'a side read in part never reads as no gaps'
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match 'Eligible Microsoft Entra role assignments were not visible to the collection'
        $index | Should -Match 'IA\.15-RBAC was read in part, so CR-19 may miss some Azure roles: .*Lighthouse'
        Set-PackResult $pack 'IA.15-RBAC' @() 'FAILED' 'The Azure role assignments could not be read. HTTP 429'
        $null = & $generator -EvidencePath $pack
        & $state | Should -Be '| 19 | Roles removed from disabled accounts |  | No roles found in what was read, IA.15-ENTRA read in part, Azure roles not collected (IA.15-RBAC FAILED), see the notes |  |' -Because 'a side read in part never reads as no gaps when the other side is missing either'
    }

    It 'flags the eligible Entra assignments it could not see, and the Lighthouse limit on the Azure side' {
        $pack = Join-Path $TestDrive 'roles-partial'
        New-ChangeFixture $pack
        $p = Get-Content (Join-Path $pack '00-parameters.json') -Raw | ConvertFrom-Json
        $p | Add-Member -NotePropertyName AccessPath -NotePropertyValue 'Lighthouse'
        $p | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $pack '00-parameters.json')
        Set-PackResult $pack 'IA.15-ENTRA' @((& $entraRole 'User Administrator' $roleIds.UserAdmin 'Standing' $morgan -PimRead 'NoPermission'), (& $entraRole 'Security Reader' $roleIds.SecReader 'Standing' $lee -PimRead 'NoPermission')) 'PARTIAL' 'Eligible assignments not visible, needs RoleManagement.Read.Directory, so only active assignments are listed and an activated one reads as Standing. 2 Microsoft Entra role assignments held by 2 of the 4 disabled accounts, 0 through a group.'
        $rbac = Get-Content (Join-Path $pack 'results/IA.15-RBAC.json') -Raw | ConvertFrom-Json
        Set-PackResult $pack 'IA.15-RBAC' $rbac 'PARTIAL' "7 Azure role assignments held by 3 of the 4 disabled accounts, 1 through a group. Read through Lighthouse, which shows the managing tenant's delegations rather than the client's own role assignments, so this is incomplete."
        $null = & $generator -EvidencePath $pack
        $index = Get-Content (Join-Path $pack '05-change-requests/00-index.md') -Raw
        $index | Should -Match '\| 19 \| Roles removed from disabled accounts \| 9 \| Change request and client email, partial collection scope \|'
        $index | Should -Match '- Eligible Microsoft Entra role assignments were not visible to the collection \(it needs RoleManagement\.Read\.Directory\), so CR-19 lists only the active ones, an activated assignment reads as Standing, and a disabled account whose only roles are eligible is not listed at all\.'
        $index | Should -Match "- The Azure role assignments were read through Azure Lighthouse, where Resource Graph shows the managing tenant's delegations instead of the client's own role assignments, so CR-19 may miss Azure roles the disabled accounts hold\."
        $index | Should -Match '- IA\.15-ENTRA was read in part, so CR-19 may miss some Microsoft Entra roles: Eligible assignments not visible'
        $index | Should -Match '- IA\.15-RBAC was read in part, so CR-19 may miss some Azure roles: '
    }

    It 'records the eligibility schedule behind an Activated role before removing it when the eligible assignments were not read' {
        # roleAssignmentScheduleInstances read, so the activation keeps its type and expiry, but
        # roleEligibilityScheduleInstances failed, so no Eligible row holds the eligibility behind it.
        $pack = Join-Path $TestDrive 'roles-pim-error'
        New-ChangeFixture $pack
        Set-PackResult $pack 'IA.15-ENTRA' @(
            (& $entraRole 'User Administrator' $roleIds.UserAdmin 'Standing' $morgan -PimRead 'Error')
            (& $entraRole 'Security Reader' $roleIds.SecReader 'Activated' $lee -End '2026-10-12T14:30:00Z' -PimRead 'Error')) 'PARTIAL' 'Eligible assignments not visible, the PIM schedule instances could not be read (HTTP 503: Service Unavailable), so only active assignments are listed. 2 Microsoft Entra role assignments held by 2 of the 4 disabled accounts, 0 through a group.'
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        $text = Get-Content (Join-Path $out 'CR-19-disabled-account-roles.txt') -Raw
        $res = @(Get-Section $text 'C) RESOURCES')
        @($res | Where-Object { $_ -match '^- Lee Ashford .+: Security Reader, Activated, ' }) | Should -Match ', with no Eligible line, so its eligibility schedule is recorded before removal$'
        @($res | Where-Object { $_ -match 'User Administrator, Standing' }) | Should -Not -Match 'no Eligible line'
        $impl = @(Get-Section $text 'A) IMPLEMENTATION PLAN')
        $impl[4] | Should -Match '^5\. For each Microsoft Entra role listed as Standing or Time-bound'
        $impl[4] | Should -Not -Match 'could not read the Privileged Identity Management schedules' -Because 'the Activated row shows the active schedule instances were read, so Standing is trusted'
        $impl[5] | Should -Match '^6\. For each Microsoft Entra role listed as Activated with no Eligible line for the same role and directory scope, the eligible assignment it comes from was not collected'
        $impl[5] | Should -Match 'Before removing it, record in the change record its start time, end time, role and directory scope as the tab shows them, then select Remove\.'
        $impl[5] | Should -Match 'Where the eligible assignment is held by a group rather than the account, leave it in place'
        $impl[5] | Should -Not -Match 'listed as Eligible|so remove that eligible assignment the same way' -Because 'no eligibility was recorded, so none is removed unrecorded'
        $rollback = (@(Get-Section $text 'C) ROLLBACK PLAN') -join "`n")
        $rollback | Should -Match 'For a role recorded as Activated with no Eligible line, restore the eligible assignment it came from with the schedule recorded in the change record at step 6, never from change-requests\.csv, which holds only the activation''s expiry'
        $rollback | Should -Match 'set Assignment type to Eligible, clear Permanently eligible, set the recorded end date and time and select Assign\. Never restore it as permanent, unless the change record shows that it had no end date, in which case leave Permanently eligible selected\.'
        $rollback | Should -Not -Match 'needs no rollback of its own|recorded as Eligible' -Because 'the activation has no eligibility recorded with it'
        $rollback | Should -Match 'and the change record carries each end time or schedule recorded before removal\.'
        $text | Should -Match 'learn\.microsoft\.com/entra/id-governance/privileged-identity-management/pim-how-to-add-role-to-user#assign-a-role'
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '- 1 Microsoft Entra role listed as Activated in CR-19 has no Eligible line for the same account, role and directory scope, since eligible assignments were not visible to the collection: Lee Ashford \(lee\.ashford@contoso\.com\), Security Reader at directory scope /\. Step 6 of the implementation records the schedule of the eligible assignment behind it from Privileged Identity Management in the change record before removing it, and the rollback restores it from that record\.'
        $index | Should -Match '- Eligible Microsoft Entra role assignments were not visible to the collection \(the Privileged Identity Management schedules could not be read\), so CR-19 lists only the active ones, and a disabled account whose only roles are eligible is not listed at all\. Collect again, or check'
        $index | Should -Not -Match 'reads as Standing|RoleManagement\.Read\.Directory' -Because 'the active instances were read and the failure was not a permission'
        $row = @(Import-Csv (Join-Path $out 'change-requests.csv') | Where-Object CR -eq 'CR-19' | Where-Object Resource -eq 'lee.ashford@contoso.com, Security Reader')
        $row.Count | Should -Be 1
        $row[0].CurrentSetting | Should -Match 'Activated until 2026-10-12T14:30:00Z, .+, eligible assignment not collected, its schedule is recorded in the change record before removal$'
        $email = Get-Content (Join-Path $out 'CR-19-disabled-account-roles.email.txt') -Raw
        Assert-ApprovalEmail $email 'CR-19 with an Activated role and no eligibility recorded'
        $attached = @(Import-Csv (Join-Path $out 'CR-19-disabled-account-roles.email.csv') | Where-Object { $_.Account -eq 'Lee Ashford' -and $_.Role -eq 'Security Reader' })
        @($attached.Detail) | Should -Be @('activated from an eligible assignment') -Because 'the attached file names the assignment in plain words'
    }

    It 'keeps the record-first wording to the Activated role whose eligibility was not collected, matching account, role and directory scope' {
        # Morgan's activation has its Eligible row. Lee's eligibility is held at an administrative unit, not the
        # tenant scope of the activation, so it does not match.
        $pack = Join-Path $TestDrive 'roles-pim-mixed'
        New-ChangeFixture $pack
        $unit = '/administrativeUnits/7c8d9e0f-1a2b-4c3d-8e4f-5a6b7c8d9e0f'
        Set-PackResult $pack 'IA.15-ENTRA' @(
            (& $entraRole 'Helpdesk Administrator' $roleIds.Helpdesk 'Activated' $morgan -End '2026-10-12T15:00:00Z')
            (& $entraRole 'Helpdesk Administrator' $roleIds.Helpdesk 'Eligible' $morgan -End '2027-06-30T00:00:00Z')
            (& $entraRole 'Security Reader' $roleIds.SecReader 'Activated' $lee -End '2026-10-12T13:00:00Z')
            (& $entraRole 'Security Reader' $roleIds.SecReader 'Eligible' $lee -Scope $unit -End '2027-01-31T00:00:00Z'))
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        $text = Get-Content (Join-Path $out 'CR-19-disabled-account-roles.txt') -Raw
        $res = @(Get-Section $text 'C) RESOURCES')
        @($res | Where-Object { $_ -match 'no Eligible line' }).Count | Should -Be 1
        @($res | Where-Object { $_ -match 'no Eligible line' })[0] | Should -Match '^- Lee Ashford .+: Security Reader, Activated, .+directory scope /, '
        $impl = @(Get-Section $text 'A) IMPLEMENTATION PLAN')
        $impl[4] | Should -Match '^5\. For each Microsoft Entra role listed as Eligible for the account, go to Privileged Identity Management > Microsoft Entra roles > Roles, open the role, find the account on the Eligible assignments tab, with the scope listed for the role, and select Remove\. A role listed as Activated with an Eligible line for the same role and directory scope comes from that eligible assignment and ends when its activation expires, so remove that eligible assignment the same way'
        $impl[4] | Should -Match 'For each Microsoft Entra role listed as Activated with no Eligible line for the same role and directory scope, the eligible assignment it comes from was not collected'
        $rollback = (@(Get-Section $text 'C) ROLLBACK PLAN') -join "`n")
        $rollback | Should -Match 'set Assignment type to Eligible with the recorded end date, if any'
        $rollback | Should -Match 'A role recorded as Activated with an Eligible line for the same role and directory scope needs no rollback of its own'
        $rollback | Should -Match 'with the schedule recorded in the change record at step 5, never from change-requests\.csv'
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '- 1 Microsoft Entra role listed as Activated in CR-19 has no Eligible line for the same account, role and directory scope, since the collection holds no eligible assignment for it: Lee Ashford \(lee\.ashford@contoso\.com\), Security Reader at directory scope /\. Step 5 of the implementation records'
        $index | Should -Not -Match 'Activated in CR-19 ha(s|ve) no Eligible line[^\r\n]*Morgan Reyes' -Because "Morgan's activation has its Eligible row"
        $index | Should -Not -Match 'Eligible Microsoft Entra role assignments were not visible' -Because 'the eligible assignments were read'
        $email = Get-Content (Join-Path $out 'CR-19-disabled-account-roles.email.txt') -Raw
        Assert-ApprovalEmail $email 'CR-19 with matched and unmatched activations'
    }

    It 'records the end of a Standing Entra role before removing it when the active schedules were not read, and never restores it as permanent' {
        $pack = Join-Path $TestDrive 'roles-pim-standing'
        New-ChangeFixture $pack
        Set-PackResult $pack 'IA.15-ENTRA' @((& $entraRole 'User Administrator' $roleIds.UserAdmin 'Standing' $morgan -PimRead 'NoPermission')) 'PARTIAL' 'Eligible assignments not visible, needs RoleManagement.Read.Directory, so only active assignments are listed and an activated one reads as Standing. 1 Microsoft Entra role assignment held by 1 of the 4 disabled accounts, 0 through a group.'
        $null = & $generator -EvidencePath $pack
        $text = Get-Content (Join-Path $pack '05-change-requests/CR-19-disabled-account-roles.txt') -Raw
        $impl = @(Get-Section $text 'A) IMPLEMENTATION PLAN')
        $step = @($impl | Where-Object { $_ -match 'listed as Standing or Time-bound' })[0]
        $n = ($step -split '\.')[0]
        $step | Should -Match '^\d+\. The collection could not read the Privileged Identity Management schedules, so a role listed as Standing may be time-bound or activated from an eligible assignment\. Before removing one, open the role in Privileged Identity Management > Microsoft Entra roles > Roles and record in the change record the start time, end time and directory scope the Active assignments tab shows for the account, so the rollback restores what was there\. For each Microsoft Entra role listed as Standing or Time-bound' -Because 'the end is recorded before the step says to remove the role'
        $rollback = (@(Get-Section $text 'C) ROLLBACK PLAN') -join "`n")
        $rollback | Should -Match ('select the account and assign it, as active with the recorded end date where one is recorded, or, for a role listed as Standing, with the end time step {0} recorded in the change record, never as permanent where it recorded one\. A role recorded with an administrative unit' -f $n) -Because 'the end is set in the same assignment, not after it'
    }

    It 'writes singular wording for one account and names an account with a top role as a possible emergency access account' {
        $pack = Join-Path $TestDrive 'roles-single'
        New-ChangeFixture $pack
        Set-PackResult $pack 'IA.15-RBAC' @() 'FAILED' 'The Azure role assignments could not be read. HTTP 429: Too Many Requests'
        Set-PackResult $pack 'IA.15-ENTRA' @((& $entraRole 'Global Administrator' $roleIds.Ga 'Standing' $morgan))
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        $text = Get-Content (Join-Path $out 'CR-19-disabled-account-roles.txt') -Raw
        @(Get-Section $text 'A) CHANGE DESCRIPTION')[0] | Should -Be 'Remove the 1 Microsoft Entra role assignment held by the disabled user account listed below, at the scope where each was made.'
        @(Get-Section $text 'C) RESOURCES')[0] | Should -Be 'The account below is recorded as disabled at collection. Each role listed is assigned directly to it. The CSV carries every assignment in full for the rollback.'
        $text | Should -Not -Match 'Repeat steps|Access control \(IAM\)|Eligible assignments tab'
        $email = Get-Content (Join-Path $out 'CR-19-disabled-account-roles.email.txt') -Raw
        Assert-ApprovalEmail $email 'CR-19 for one account'
        $email | Should -Match 'I would like your approval to remove the Microsoft Entra roles still assigned to 1 disabled account in your tenant\. The account is disabled, so it cannot sign in, but it still holds every role listed in the attached file\.'
        $email | Should -Match 'Nobody loses access today, since the account cannot sign in\.'
        $email | Should -Match "The account and its roles are in the attached file CR-19-disabled-account-roles\.email\.csv, one line for each role with the account, the role, where it applies, how the account holds it and what I would do about it, and they add up as follows:\r?\n\r?\nMicrosoft Entra ID directory roles:\r?\n\r?\n- 1 account holding 1 role\r?\n"
        $email | Should -Not -Match '(?i)group' -Because 'no role reaches the account through a group'
        @(Import-Csv (Join-Path $out 'CR-19-disabled-account-roles.email.csv') | ForEach-Object { '{0}|{1}|{2}|{3}|{4}' -f $_.Account, $_.Role, $_.Scope, $_.HeldThrough, $_.Action }) | Should -Be @('Morgan Reyes|Global Administrator|the whole directory|Assigned to the account|Remove the role assignment')
        $email | Should -Match 'could you tell me whether the account is expected to come back into use'
        $email | Should -Match 'Just before the change, I will check the account again and leave it unchanged if it has been turned back on since my review\.'
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '- 1 account in CR-19 holds Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator or a role at the Azure root scope: Morgan Reyes \(morgan\.reyes@contoso\.com\)\. Ask the client whether any of them is an emergency access account before sending'
        $index | Should -Match '- The Azure roles of the disabled accounts are unknown, not a zero, because IA\.15-RBAC could not be used: it reads FAILED: The Azure role assignments could not be read\. HTTP 429'
        $index | Should -Not -Match 'Resource Graph also holds the active Azure role assignments only' -Because 'the Azure side was not read'
    }

    It 'keeps an ABAC condition for the rollback, and restores an application-scoped Entra role at that application only' {
        $pack = Join-Path $TestDrive 'roles-condition'
        New-ChangeFixture $pack
        $condition = "((!(ActionMatches{'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'} AND NOT SubOperationMatches{'Blob.List'})) OR (@Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags:Project<`$key_case_sensitive`$>] StringEquals 'Cascade'))"
        $blob = & $azureRole "/subscriptions/$s2/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stdataprod" 'Storage Blob Data Contributor' $roleIds.BlobContributor $lee
        $blob.Condition = $condition; $blob.ConditionVersion = '2.0'
        $app = '0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0'
        Set-PackResult $pack 'IA.15-RBAC' @($blob)
        Set-PackResult $pack 'IA.15-ENTRA' @((& $entraRole 'Application Administrator' '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' 'Standing' $lee -Scope "/$app"), (& $entraRole 'Application Administrator' '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' 'Eligible' $morgan -Scope "/$app"))
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        $row = @(Import-Csv (Join-Path $out 'change-requests.csv') | Where-Object CR -eq 'CR-19' | Where-Object Resource -eq 'lee.ashford@contoso.com, Storage Blob Data Contributor')
        $row.CurrentSetting.EndsWith(", condition version 2.0: $condition", [StringComparison]::Ordinal) | Should -BeTrue -Because 'the CSV keeps the condition exactly, angle brackets included, for the rollback'
        $text = Get-Content (Join-Path $out 'CR-19-disabled-account-roles.txt') -Raw
        $text | Should -Match ', with a condition \(version 2\.0\) kept exactly in change-requests\.csv: \(\(!\(ActionMatches'
        $rollback = @(Get-Section $text 'C) ROLLBACK PLAN') -join "`n"
        $rollback | Should -Match 'For an Azure role assignment recorded with a condition, recreate it with that condition, copied exactly from change-requests\.csv, since without it the role grants more than it did\.'
        $rollback | Should -Match 'then on the Conditions tab select Add condition, set Editor type to Code, paste the condition and select Save\. Where step 4 recorded it as Active time-bound, set it to Active and Time bound with the recorded end date and time on the Assignment type tab, then select Review \+ assign\.'
        $rollback | Should -Match 'The portal cannot add a condition at a management group or root scope, so recreate one there from Azure Cloud Shell in Bash'
        $rollback | Should -Match 'run code condition\.txt, paste the condition, save the file'
        ($rollback -split "`n") | Should -Contain '    az role assignment create --assignee-object-id OBJECT-ID --assignee-principal-type User --role ROLE-DEFINITION-ID --scope SCOPE --condition "$(cat condition.txt)" --condition-version VERSION' -Because 'the condition is read from a file, so a token such as $key_case_sensitive$ is never expanded by the shell'
        $rollback | Should -Not -Match 'For an Azure role assignment(, open| recorded without)' -Because 'the only Azure assignment has a condition, so it matches the condition step alone'
        $rollback | Should -Match 'one recorded for a single application or other object \(a directory scope of the form /OBJECT-ID\) from that object, such as App registrations > the application > Roles and administrators, never from the tenant-wide list'
        $rollback | Should -Match 'For a role recorded with an administrative unit or a single application, select that scope and the recorded unit or application on the Add assignments page'
        (@(Get-Section $text 'A) IMPLEMENTATION PLAN') -join "`n") | Should -Match 'Where the account holds the role at more than one scope, remove only the assignment whose scope matches the one listed\.'
        $text | Should -Match "Application Administrator, Standing, role definition 9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3, directory scope /$app, "
        $email = Get-Content (Join-Path $out 'CR-19-disabled-account-roles.email.txt') -Raw
        Assert-ApprovalEmail $email 'CR-19 with a condition and an application scope'
        $attached = @(Import-Csv (Join-Path $out 'CR-19-disabled-account-roles.email.csv'))
        $blobRow = $attached | Where-Object Role -eq 'Storage Blob Data Contributor'
        @($blobRow.Scope, $blobRow.Detail) | Should -Be @("resource stdataprod in resource group rg-data in the subscription Example, Dev Test ($s2)", 'with a condition that narrows what the role allows')
        @($attached | Where-Object Role -eq 'Application Administrator' | ForEach-Object { '{0}|{1}|{2}' -f $_.Account, $_.Scope, $_.Detail }) | Should -Be @("Lee Ashford|the single application or other Microsoft Entra object with ID $app|", "Morgan Reyes|the single application or other Microsoft Entra object with ID $app|eligible in Privileged Identity Management")
        ($email + (Get-Content (Join-Path $out 'CR-19-disabled-account-roles.email.csv') -Raw)) | Should -Not -Match 'ActionMatches' -Because 'the email and its file name the condition, the change request and CSV carry it'
    }

    It 'restores each Azure assignment through one rollback step only, so a conditioned root role is never restored without its condition' {
        $pack = Join-Path $TestDrive 'roles-root-condition'
        New-ChangeFixture $pack
        $root = & $azureRole '/' 'User Access Administrator' $roleIds.Uaa $lee
        $root.Condition = "((!(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})) OR (@Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {acdd72a7-3385-48ef-bd42-f606fba81ae7}))"
        $root.ConditionVersion = '2.0'
        Set-PackResult $pack 'IA.15-RBAC' @($root, (& $azureRole "/subscriptions/$s1" 'Owner' $roleIds.Owner $morgan), (& $azureRole '/' 'Reader' $roleIds.Reader $morgan))
        Set-PackResult $pack 'IA.15-ENTRA' @()
        $null = & $generator -EvidencePath $pack
        $text = Get-Content (Join-Path $pack '05-change-requests/CR-19-disabled-account-roles.txt') -Raw
        $rollback = @(Get-Section $text 'C) ROLLBACK PLAN')
        $rollback[0] | Should -Match '^1\. For an Azure role assignment recorded without a condition, open the scope recorded for it'
        $rollback[1] | Should -Match '^2\. For an Azure role assignment recorded with a condition, recreate it with that condition'
        ($rollback -join "`n") | Should -Match '\. For an assignment at the root scope recorded without a condition, run in Azure Cloud Shell' -Because 'the unconditioned root Reader still has its own step'
        $email = Get-Content (Join-Path $pack '05-change-requests/CR-19-disabled-account-roles.email.txt') -Raw
        Assert-ApprovalEmail $email 'CR-19 with a conditioned root role'
        $uaa = Import-Csv (Join-Path $pack '05-change-requests/CR-19-disabled-account-roles.email.csv') | Where-Object Role -eq 'User Access Administrator'
        @($uaa.Scope, $uaa.Detail) | Should -Be @('the root scope, above every subscription', 'with a condition that narrows what the role allows')
    }

    It 'names no removal step for a time-bound Azure assignment when every Azure role is at the root scope' {
        $pack = Join-Path $TestDrive 'roles-root-only-condition'
        New-ChangeFixture $pack
        $root = & $azureRole '/' 'User Access Administrator' $roleIds.Uaa $lee
        $root.Condition = "((!(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})) OR (@Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {acdd72a7-3385-48ef-bd42-f606fba81ae7}))"
        $root.ConditionVersion = '2.0'
        Set-PackResult $pack 'IA.15-RBAC' @($root)
        Set-PackResult $pack 'IA.15-ENTRA' @()
        $null = & $generator -EvidencePath $pack
        $text = Get-Content (Join-Path $pack '05-change-requests/CR-19-disabled-account-roles.txt') -Raw
        $text | Should -Not -Match 'step 0\b|Active time-bound' -Because 'the portal removal step is written only below the root scope'
        (@(Get-Section $text 'C) ROLLBACK PLAN') -join "`n") | Should -Match 'paste the condition and select Save\. Then select Review \+ assign\. The portal cannot add a condition'
    }

    It 'removes a role at the Azure root scope from the command line, since the portal cannot, and lists it under the root scope' {
        $pack = Join-Path $TestDrive 'roles-root'
        New-ChangeFixture $pack
        Set-PackResult $pack 'IA.15-RBAC' @((& $azureRole '/' 'User Access Administrator' $roleIds.Uaa $lee))
        Set-PackResult $pack 'IA.15-ENTRA' @()
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        $text = Get-Content (Join-Path $out 'CR-19-disabled-account-roles.txt') -Raw
        $text | Should -Match "Root scope: /\r?\n- Lee Ashford \(lee\.ashford@contoso\.com\), object ID $lee`: User Access Administrator on the root scope, role definition $($roleIds.Uaa), scope /, "
        $impl = @(Get-Section $text 'A) IMPLEMENTATION PLAN')
        ($impl -join "`n") | Should -Not -Match 'Access control \(IAM\)' -Because 'the only assignment is at the root scope'
        $impl[2] | Should -Match '^3\. The portal cannot remove an assignment at the root scope \(/\)\. As a Global Administrator with elevated access, remove each one listed for the account from Azure Cloud Shell'
        $impl[3] | Should -Be '    az role assignment delete --assignee OBJECT-ID --role ROLE-DEFINITION-ID --scope "/"'
        $impl[4] | Should -Be '    az role assignment list --assignee OBJECT-ID --scope "/"'
        @(Get-Section $text 'B) TESTING PLAN')[1] | Should -Match '^2\. Confirm that the list of assignments left at the root scope, read in the implementation, no longer shows the account\.$'
        @(Get-Section $text 'C) ROLLBACK PLAN')[0] | Should -Match 'az role assignment create --assignee-object-id OBJECT-ID --assignee-principal-type User --role ROLE-DEFINITION-ID --scope "/"$'
        $email = Get-Content (Join-Path $out 'CR-19-disabled-account-roles.email.txt') -Raw
        Assert-ApprovalEmail $email 'CR-19 at the root scope'
        $email | Should -Match "Root scope:\r?\n\r?\n- 1 account holding 1 role\r?\n"
        (Import-Csv (Join-Path $out 'CR-19-disabled-account-roles.email.csv')).Scope | Should -Be 'the root scope, above every subscription'
        (Get-Content (Join-Path $out '00-index.md') -Raw) | Should -Match 'or a role at the Azure root scope: Lee Ashford'
    }

    It 'leaves a role held through a dynamic or synced group unchanged, names it in the index and marks it in the attached file' {
        $pack = Join-Path $TestDrive 'roles-fixed-groups'
        New-ChangeFixture $pack
        Set-PackResult $pack 'IA.15-RBAC' @(
            (& $azureRole "/subscriptions/$s1" 'Owner' $roleIds.Owner $morgan)
            (& $azureRole "/subscriptions/$s2" 'Reader' $roleIds.Reader $kim $dynGroup)
            (& $azureRole "/subscriptions/$s1" 'Reader' $roleIds.Reader $lee $legacyGroup))
        Set-PackResult $pack 'IA.15-ENTRA' @()
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        $text = Get-Content (Join-Path $out 'CR-19-disabled-account-roles.txt') -Raw
        @(Get-Section $text 'A) CHANGE DESCRIPTION')[0] | Should -Be 'Remove the 1 Azure role assignment held by the disabled user account listed below, at the scope where each was made.'
        @(Get-Section $text 'C) RESOURCES')[0] | Should -Be 'The account below is recorded as disabled at collection. Each role listed is assigned directly to it. Roles held through a group the change cannot alter are left out and named in the index. The CSV carries every assignment in full for the rollback.'
        $text | Should -Not -Match 'Kim Osei|Lee Ashford|Group memberships removed|all-staff-dynamic|legacy-admins' -Because 'a membership a rule or Active Directory decides is not part of the change'
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '\| 19 \| Roles removed from disabled accounts \| 1 \| Change request and client email \|'
        $index | Should -Match "- 2 disabled accounts hold roles through a group whose members CR-19 cannot change, so they stay as they are: Kim Osei \(kim\.osei@contoso\.com\) through group all-staff-dynamic \($($dynGroup.Id)\), a dynamic membership group whose members a rule decides, which holds Azure Reader on /subscriptions/$s2 / Lee Ashford \(lee\.ashford@contoso\.com\) through group legacy-admins \($($legacyGroup.Id)\), synced from on-premises Active Directory, where its members are managed, which holds Azure Reader on /subscriptions/$s1\. Review each with the group owner, who can change the membership rule, or remove the account from the group in Active Directory so that the next sync takes the role away\."
        $email = Get-Content (Join-Path $out 'CR-19-disabled-account-roles.email.txt') -Raw
        Assert-ApprovalEmail $email 'CR-19 with dynamic and synced groups'
        $email | Should -Match 'I would like your approval to remove the Azure roles still assigned to 1 disabled account in your tenant\. The account is disabled, so it cannot sign in, but it still holds every role marked for removal in the attached file\.' -Because 'the file also lists accounts whose roles stay'
        $email | Should -Match '\r?\n\r?\n2 accounts hold a role through a group whose members come from a rule or from your on-premises directory, so those memberships cannot be changed in the group itself, and I would leave them as they are, marked in the attached file, for a separate review with you\.\r?\n'
        $email | Should -Match 'The roles of every disabled account are in the attached file CR-19-disabled-account-roles\.email\.csv, one line for each role with the account, the role, where it applies, how the account holds it and what I would do about it, and the roles I would remove add up as follows:' -Because 'the file lists more accounts than the change touches'
        $email | Should -Not -Match 'The account and its roles are' -Because 'that wording would claim the whole file for the one account in the change'
        $email | Should -Match "Subscription Example Production \($s1\):\r?\n\r?\n- 1 account holding 1 role\r?\n" -Because 'the email counts only the roles the change removes'
        $email | Should -Not -Match 'Dev Test' -Because 'the only role in that subscription is left unchanged'
        $rows = @(Import-Csv (Join-Path $out 'CR-19-disabled-account-roles.email.csv'))
        @($rows | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Account, $_.Role, $_.HeldThrough, $_.Action }) | Should -Be @(
            'Kim Osei|Reader|Group all-staff-dynamic|None in this change, the members of group all-staff-dynamic come from a rule'
            'Lee Ashford|Reader|Group legacy-admins|None in this change, group legacy-admins is synced from on-premises Active Directory'
            'Morgan Reyes|Owner|Assigned to the account|Remove the role assignment') -Because 'the client sees every role, with what the change does about it'
    }

    It 'removes the account from its group alone when every role reaches it through a group' {
        $pack = Join-Path $TestDrive 'roles-group-only'
        New-ChangeFixture $pack
        Set-PackResult $pack 'IA.15-RBAC' @((& $azureRole "/subscriptions/$s2/resourceGroups/rg-ops" 'Contributor' $roleIds.Contributor $kim $opsGroup))
        Set-PackResult $pack 'IA.15-ENTRA' @()
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        $text = Get-Content (Join-Path $out 'CR-19-disabled-account-roles.txt') -Raw
        @(Get-Section $text 'A) CHANGE DESCRIPTION')[0] | Should -Be 'Remove the disabled user account listed below from the 1 group through which it holds 1 role assignment.'
        @(Get-Section $text 'C) RESOURCES')[0] | Should -Be 'The account below is recorded as disabled at collection. Each role listed reaches the account through the group it is removed from. The CSV carries every assignment and membership in full for the rollback.'
        $text | Should -Not -Match 'Access control \(IAM\)|Roles and administrators' -Because 'no role is assigned to the account itself'
        $impl = @(Get-Section $text 'A) IMPLEMENTATION PLAN')
        $impl[2] | Should -Match '^3\. For each group membership listed for the account, first confirm that it still gives the account a role on its line: go to Microsoft Entra ID > Groups > All groups, open each group the line says holds a role and check under Azure role assignments or Assigned roles that it still holds the roles listed'
        $impl[2] | Should -Match 'Where the membership still carries at least one of the roles listed, remove it as follows, and note in the change record any role on the line that was already gone\. Only where every role on the line is gone, or the chain to every group holding one is broken, does the membership no longer give the account a role, so leave it unchanged and note it in the change record\. To remove it, open the group the account is removed from' -Because 'a membership that still carries one role is removed, however many others are gone'
        $impl.Count | Should -Be 3
        @(Get-Section $text 'B) TESTING PLAN')[1] | Should -Match '^2\. Select Groups and confirm that no group recorded for the account under group memberships is listed'
        $rollback = @(Get-Section $text 'C) ROLLBACK PLAN')
        $rollback[0] | Should -Match '^1\. For a group membership, go to Microsoft Entra ID > Groups > All groups, open the recorded group, select Members, select Add members'
        $rollback[1] | Should -Be '2. change-requests.csv carries each assignment in full, with the role, role definition ID, scope, any condition and the account object ID, and each group membership with the group the account is removed from and the roles it holds. An account left unchanged during the change needs no rollback.'
        $email = Get-Content (Join-Path $out 'CR-19-disabled-account-roles.email.txt') -Raw
        Assert-ApprovalEmail $email 'CR-19 with a group membership only'
        $email | Should -Match 'I would like your approval to remove the Azure roles that 1 disabled account still holds in your tenant through group membership, by removing it from the group that holds the role\. The account is disabled, so it cannot sign in, but it still holds every role listed in the attached file\.'
        $email | Should -Match 'Where a group holds the role, I would remove the account from the group rather than take the role away from the group, so its other members keep their access, and where the account sits in a group nested inside the one that holds the role, it is the nested group it is removed from\.'
        $email | Should -Match 'Just before the change, I will check the account again and leave it unchanged if it has been turned back on since my review\. I will also leave a group membership as it is if the group no longer gives the account any of the roles listed for it\.'
        $email | Should -Match "Subscription Example, Dev Test \($s2\):\r?\n\r?\n- 1 account holding 1 role, held through a group\r?\n"
        @(Import-Csv (Join-Path $out 'change-requests.csv') | Where-Object CR -eq 'CR-19' | ForEach-Object Resource) | Should -Be @('kim.osei@contoso.com, member of group platform-operators')
    }

    It 'counts a role once when it reaches the account through two groups, and removes the account from each' {
        # Kim is a member of platform-operators and of ops-tier2, nested in it, so the one Contributor assignment comes
        # back as two rows with the same assignment ID: two memberships to remove, one role.
        $pack = Join-Path $TestDrive 'roles-two-paths'
        New-ChangeFixture $pack
        Set-PackResult $pack 'IA.15-RBAC' @(
            (& $azureRole "/subscriptions/$s2/resourceGroups/rg-ops" 'Contributor' $roleIds.Contributor $kim $opsGroup)
            (& $azureRole "/subscriptions/$s2/resourceGroups/rg-ops" 'Contributor' $roleIds.Contributor $kim $opsNested))
        Set-PackResult $pack 'IA.15-ENTRA' @()
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        $text = Get-Content (Join-Path $out 'CR-19-disabled-account-roles.txt') -Raw
        @(Get-Section $text 'A) CHANGE DESCRIPTION')[0] | Should -Be 'Remove the disabled user account listed below from the 2 groups through which it holds 1 role assignment.'
        $res = @(Get-Section $text 'C) RESOURCES')
        @($res | Where-Object { $_ -match '^- Kim Osei' }).Count | Should -Be 2 -Because 'each group the account sits in is left'
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '\| 19 \| Roles removed from disabled accounts \| 2 \| Change request and client email \|' -Because 'one tracking row per membership'
        $email = Get-Content (Join-Path $out 'CR-19-disabled-account-roles.email.txt') -Raw
        Assert-ApprovalEmail $email 'CR-19 with a role reached through two groups'
        $email | Should -Match "one line for each role with the account, the role, where it applies, how the account holds it and what I would do about it, and a role that reaches an account through more than one group on a line for each of them, and they add up as follows:\r?\n\r?\nSubscription Example, Dev Test \($s2\):\r?\n\r?\n- 1 account holding 1 role, held through a group\r?\n" -Because 'the role is counted once, however many groups carry it'
        @(Import-Csv (Join-Path $out 'CR-19-disabled-account-roles.email.csv') | ForEach-Object { '{0}|{1}|{2}' -f $_.Role, $_.HeldThrough, $_.Action }) | Should -Be @(
            'Contributor|Group platform-operators|Remove the account from group platform-operators'
            'Contributor|Group platform-operators, through the group ops-tier2 nested in it|Remove the account from group ops-tier2')
    }

    It 'leaves the roles held through groups unchanged on a pack collected before the group membership columns, and asks for a recollection' {
        $pack = Join-Path $TestDrive 'roles-old-pack'
        New-ChangeFixture $pack
        Set-PackResult $pack 'IA.15-RBAC' @((& $azureRole "/subscriptions/$s1" 'Owner' $roleIds.Owner $morgan), (& $azureRole "/subscriptions/$s2/resourceGroups/rg-ops" 'Contributor' $roleIds.Contributor $kim $opsOld))
        Set-PackResult $pack 'IA.15-ENTRA' @((& $entraRole 'Helpdesk Administrator' $roleIds.Helpdesk 'Standing' $kim $opsOld -Scope '/administrativeUnits/4b5c6d7e-8f90-4a1b-b2c3-d4e5f6a7b8c9'))
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '\| 19 \| Roles removed from disabled accounts \| 1 \| Change request and client email \|'
        $index | Should -Match "- 1 disabled account holds roles through group membership, which CR-19 leaves unchanged because the pack does not record the group each account sits in: group platform-operators \($($opsGroup.Id)\), which holds Azure Contributor on /subscriptions/$s2/resourceGroups/rg-ops and Microsoft Entra Helpdesk Administrator \(in administrative unit 4b5c6d7e-8f90-4a1b-b2c3-d4e5f6a7b8c9\), with the disabled member Kim Osei \(kim\.osei@contoso\.com\)\. Collect again with CyberSOC collector 1\.10\.0 or later, and CR-19 removes each account from its group\."
        $text = Get-Content (Join-Path $out 'CR-19-disabled-account-roles.txt') -Raw
        $text | Should -Not -Match 'Kim Osei|Group memberships removed'
        @(Get-Section $text 'C) RESOURCES')[0] | Should -Match 'Roles held through a group the change cannot alter are left out and named in the index\.'
        $email = Get-Content (Join-Path $out 'CR-19-disabled-account-roles.email.txt') -Raw
        Assert-ApprovalEmail $email 'CR-19 on a pack without the group membership columns'
        $email | Should -Match '\r?\n\r?\nRoles that reach a disabled account through a group stay as they are for now, since my review did not record which group each account sits in, and I will come back to you about those separately\.\r?\n'
        (Get-Content (Join-Path $out 'CR-19-disabled-account-roles.email.csv') -Raw) | Should -Not -Match 'Kim Osei'
    }

    It 'speaks of the roles marked for removal when an account in the change also holds a role that stays' {
        $pack = Join-Path $TestDrive 'roles-mixed-account'
        New-ChangeFixture $pack
        Set-PackResult $pack 'IA.15-RBAC' @(
            (& $azureRole "/subscriptions/$s1" 'Owner' $roleIds.Owner $morgan)
            (& $azureRole "/subscriptions/$s2" 'Reader' $roleIds.Reader $morgan $dynGroup))
        Set-PackResult $pack 'IA.15-ENTRA' @()
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        $email = Get-Content (Join-Path $out 'CR-19-disabled-account-roles.email.txt') -Raw
        Assert-ApprovalEmail $email 'CR-19 with an account that holds a removable role and one that stays'
        $email | Should -Match 'I would like your approval to remove the Azure roles still assigned to 1 disabled account in your tenant\. The account is disabled, so it cannot sign in, but it still holds every role marked for removal in the attached file\.' -Because 'the file also lists the role that stays'
        $email | Should -Match "The account and its roles are in the attached file CR-19-disabled-account-roles\.email\.csv, one line for each role with the account, the role, where it applies, how the account holds it and what I would do about it, and the roles I would remove add up as follows:\r?\n\r?\nSubscription Example Production \($s1\):\r?\n\r?\n- 1 account holding 1 role\r?\n" -Because 'every row belongs to the account in the change, and the count covers the roles to remove'
        $email | Should -Match '\r?\n\r?\n1 account holds a role through a group whose members come from a rule or from your on-premises directory'
        @(Import-Csv (Join-Path $out 'CR-19-disabled-account-roles.email.csv') | ForEach-Object { '{0}|{1}' -f $_.Role, $_.Action }) | Should -Be @('Owner|Remove the role assignment', 'Reader|None in this change, the members of group all-staff-dynamic come from a rule')
    }

    It 'keeps a value a spreadsheet would read as a formula as text in the attached file' {
        $pack = Join-Path $TestDrive 'roles-formula'
        New-ChangeFixture $pack
        $row = & $azureRole "/subscriptions/$s1" 'Owner' $roleIds.Owner $morgan
        $row.DisplayName = '=Morgan Reyes'; $row.Role = '+Owner'
        Set-PackResult $pack 'IA.15-RBAC' @($row)
        Set-PackResult $pack 'IA.15-ENTRA' @()
        $null = & $generator -EvidencePath $pack
        $attached = @(Import-Csv (Join-Path $pack '05-change-requests/CR-19-disabled-account-roles.email.csv'))
        $attached.Count | Should -Be 1
        @($attached[0].Account, $attached[0].Role, $attached[0].SignInName) | Should -Be @("'=Morgan Reyes", "'+Owner", 'morgan.reyes@contoso.com') -Because 'an apostrophe in front keeps a spreadsheet from running the cell, and a plain value is left alone'
        (Get-Content (Join-Path $pack '05-change-requests/CR-19-disabled-account-roles.email.csv') -Raw) | Should -Match "^`"Account`",[^\r\n]*\r?\n`"'=Morgan Reyes`",`"morgan\.reyes@contoso\.com`",`"Azure`",`"'\+Owner`","
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
        Set-PackResult $pack 'DP.1-CONTAINERS-DETAIL' @() 'FAILED'
        Set-PackResult $pack 'DR.6-INITIATIVE' @(@{ DefinitionName = 'ATMO-MXDR-KV-TOSENT'; Resources = 6; Compliant = 5; NonCompliant = 1 })
        Set-PackResult $pack 'DR.6-NONCOMPLIANT' @(@{ ResourceId = "/subscriptions/$s1/resourcegroups/rg-app/providers/microsoft.keyvault/vaults/kv-app"; ResourceType = 'microsoft.keyvault/vaults'; AssignmentName = 'ATMO-MXDR-DIAG-TOSENT'; AssignmentId = "/subscriptions/$s1/providers/microsoft.authorization/policyassignments/a1"; Policies = 'ATMO-MXDR-KV-TOSENT' }) 'PARTIAL'
        Set-PackResult $pack 'DP.4-VMSS-ELIGIBILITY' @() 'FAILED'
        $null = & $generator -EvidencePath $pack
        $index = Get-Content (Join-Path $pack '05-change-requests/00-index.md') -Raw
        $index | Should -Match ([regex]::Escape('- 2 storage accounts left out of CR-07 because their containers were not read, since DP.1-CONTAINERS reads FAILED: stdata (resource group rg-data), stweb (resource group rg-web).'))
        $index | Should -Match '\| 18 \| Blob containers set to private access \|  \| Not collected \(DP\.1-CONTAINERS-DETAIL FAILED\) \|' -Because 'the collector writes the detail with every outcome of DP.1-CONTAINERS'
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
Describe 'App Service minimum TLS on the site and its SCM site (CR-04, collector 1.13.0)' {
    BeforeAll {
        # A scenario from tests/fixtures/offline-pack/app-service-tls written into a pack as NB.5-DETAIL, and the change
        # requests built from it. The pack records the collector version given, which decides how an empty list reads.
        function Build-Tls([string]$Name, [string]$Version = '1.13.0') {
            $pack = Join-Path $TestDrive "tls-$Name-$Version"
            New-ChangeFixture $pack
            $rows = if ($Name -eq 'empty') { @() } else { @((Get-Content (Join-Path $PSScriptRoot "fixtures/offline-pack/app-service-tls/$Name.json") -Raw | ConvertFrom-Json).Rows) }
            Set-PackResult $pack 'NB.5-DETAIL' $rows
            Set-Content (Join-Path $pack '00-parameters.json') ((Get-Content (Join-Path $pack '00-parameters.json') -Raw) -replace '"ScriptVersion":\s*"[^"]+"', ('"ScriptVersion": "{0}"' -f $Version))
            $null = & $generator -EvidencePath $pack
            $out = Join-Path $pack '05-change-requests'
            @{ Out = $out; Index = Get-Content (Join-Path $out '00-index.md') -Raw; Csv = @(Import-Csv (Join-Path $out 'change-requests.csv') | Where-Object CR -eq 'CR-04')
                Cr = $(if (Test-Path (Join-Path $out 'CR-04-app-service-minimum-tls.txt')) { Get-Content (Join-Path $out 'CR-04-app-service-minimum-tls.txt') -Raw })
                Email = $(if (Test-Path (Join-Path $out 'CR-04-app-service-minimum-tls.email.txt')) { Get-Content (Join-Path $out 'CR-04-app-service-minimum-tls.email.txt') -Raw }) }
        }
        $mixed = Build-Tls 'mixed'
    }

    It 'changes each part only where it is below 1.2, with both recorded values in RESOURCES and the CSV' {
        $text = $mixed.Cr
        @(Get-Section $text 'A) CHANGE DESCRIPTION')[0] | Should -Be 'Set the minimum inbound TLS version and the SCM (Kudu) site minimum inbound TLS version to 1.2 on the 5 App Service and Function apps listed below, each where it is below 1.2.'
        @(Get-Section $text 'B) PURPOSE')[0] | Should -Match 'App Service stops accepting them on May 31, 2027, on the app endpoint and on the SCM \(Kudu\) endpoint used for deployments\.'
        $resources = @(Get-Section $text 'C) RESOURCES')
        $resources[0] | Should -Be 'The 5 apps below are listed with the minimum TLS versions each one allows today, for the site and for its SCM site.'
        $resources | Should -Contain '- app-scm-only, resource group rg-web, minimum TLS 1.2, SCM minimum TLS 1.0'
        $resources | Should -Contain '- app-site-only, resource group rg-web, minimum TLS 1.1, SCM minimum TLS 1.2'
        $resources | Should -Contain '- app-both, resource group rg-api, minimum TLS 1.0, SCM minimum TLS 1.1'
        $resources | Should -Contain '- app-scm-blank, resource group rg-api, minimum TLS 1.0, SCM minimum TLS not set'
        $resources | Should -Contain '- app-site-blank, resource group rg-web, minimum TLS not set, SCM minimum TLS 1.0'
        $text | Should -Not -Match 'app-both-blank' -Because 'neither value is recorded, and App Service applies 1.2 to both'
        @(Get-Section $text 'C) DEPENDENCIES')[0] | Should -Be 'Clients and deployment tools limited to TLS 1.0 or 1.1 can no longer connect to the site or its SCM site once the change is applied.'
        @($mixed.Csv | ForEach-Object { '{0}|{1}' -f $_.Resource, $_.CurrentSetting } | Sort-Object) | Should -Be @(
            'app-both|minimum TLS 1.0, SCM minimum TLS 1.1'
            'app-scm-blank|minimum TLS 1.0, SCM minimum TLS not set'
            'app-scm-only|minimum TLS 1.2, SCM minimum TLS 1.0'
            'app-site-blank|minimum TLS not set, SCM minimum TLS 1.0'
            'app-site-only|minimum TLS 1.1, SCM minimum TLS 1.2')
        $mixed.Csv[0].ResourceId | Should -Match '^/subscriptions/[0-9a-f-]+/resourceGroups/rg-[a-z]+/providers/Microsoft\.Web/sites/app-'
    }

    It 'gives an app only the step its recorded values need, never lowers a value raised since collection, checks both values in the portal and rolls each back to its recorded value' {
        $impl = @(Get-Section $mixed.Cr 'A) IMPLEMENTATION PLAN')
        $impl | Should -Be @(
            '1. In the Azure portal, go to App Services and open the first app listed in the RESOURCES section.'
            '2. Go to Settings > Configuration and select the General settings tab.'
            '3. If the RESOURCES section lists a minimum TLS below 1.2 for the app, read Minimum Inbound TLS Version. If it still shows 1.0 or 1.1, set it to 1.2. If it shows 1.2 or later, the app has changed since collection, so leave it as it is and note it in the change record. Otherwise leave it as it is.'
            '4. If the RESOURCES section lists an SCM minimum TLS below 1.2 for the app, read SCM Minimum Inbound TLS Version. If it still shows 1.0 or 1.1, set it to 1.2. If it shows 1.2 or later, the app has changed since collection, so leave it as it is and note it in the change record. Otherwise leave it as it is.'
            '5. If a setting was changed, select Apply and confirm.'
            '6. Repeat steps 1 to 5 for each remaining app listed.')
        @(Get-Section $mixed.Cr 'B) TESTING PLAN')[1] | Should -Be '2. Confirm Minimum Inbound TLS Version and SCM Minimum Inbound TLS Version both show 1.2 or later.'
        $rollback = @(Get-Section $mixed.Cr 'C) ROLLBACK PLAN')
        $rollback[1] | Should -Be '2. Set Minimum Inbound TLS Version and SCM Minimum Inbound TLS Version back to the versions recorded for the app in the RESOURCES section, only for the settings the change set to 1.2, then select Apply and confirm.'
        ($rollback -join ' ') | Should -Not -Match '\b1\.0\b' -Because 'the rollback restores the recorded value, never a fixed 1.0'
        @(Get-Section $mixed.Cr 'A) REFERENCES') | Should -Contain '- Kudu service overview: https://learn.microsoft.com/azure/app-service/resources-kudu'
    }

    It 'names in the index the empty values, the app changed on its SCM site only and the deployment slots' {
        $mixed.Index | Should -Match '\| 04 \| Minimum TLS 1\.2 on App Service apps \| 5 \| Change request and client email \|'
        $mixed.Index | Should -Match '- 1 App Service app left out of CR-04 because Resource Graph returned no minimum TLS version, and App Service applies 1\.2 when none is set: app-both-blank\.'
        $mixed.Index | Should -Match '- 1 App Service app in CR-04 has no site minimum TLS version recorded, and App Service applies 1\.2 when none is set, so CR-04 changes only its SCM site minimum: app-site-blank \(resource group rg-web\)\.'
        $mixed.Index | Should -Match '- 2 App Service apps left out of the SCM part of CR-04 because Resource Graph returned no SCM minimum TLS version, and App Service applies 1\.2 to the SCM site when none is set: app-both-blank \(resource group rg-web\), app-scm-blank \(resource group rg-api\)\. Check SCM Minimum Inbound TLS Version under Settings > Configuration > General settings'
        $mixed.Index | Should -Match 'Deployment slots have a minimum TLS version and an SCM minimum TLS version of their own, which the pack does not read, so CR-04 does not cover them\.'
        $mixed.Index | Should -Not -Match 'Recollect with CyberSOC collector 1\.13\.0'
    }

    It 'explains the SCM site once and asks whether a deployment tool still reaches it over TLS 1.0 or 1.1 before asking for approval' {
        $email = $mixed.Email
        Assert-ApprovalEmail $email 'CR-04 with the SCM site'
        $email | Should -Match '^Subject: Approval requested: minimum TLS 1\.2 for Azure App Service applications and their SCM sites\r?\n'
        $email | Should -Match 'I would like your approval to set the minimum inbound TLS version to 1\.2 on 5 of your App Service and Function applications and on the SCM site of each, wherever either one allows an older version today\. TLS is the protocol'
        $email | Should -Match 'I recommend setting this minimum now because TLS 1\.0 and 1\.1 have known weaknesses, and App Service stops accepting them on May 31, 2027, on each application and on its SCM site alike\.'
        ([regex]::Matches($email, 'also called Kudu')).Count | Should -Be 1 -Because 'the SCM site is explained once'
        $email | Should -Match '\r?\n\r?\nThe SCM site, also called Kudu, is the deployment and management endpoint that App Service runs beside each application, which tools such as zip deploy, Web Deploy and local Git reach to upload code, stream logs and manage these applications\.\r?\n'
        $email | Should -Match 'A deployment tool, build agent or script that reaches the SCM site over TLS 1\.0 or 1\.1, for example one on an old operating system or runtime, would fail to deploy once the change is applied, and a client that can only use TLS 1\.0 or 1\.1 would no longer be able to connect to the application itself\.'
        $email | Should -Match 'The applications are listed below by subscription, each with its minimum TLS versions today, for the application and for its SCM site:'
        $email | Should -Match '- app-site-blank \(resource group rg-web, minimum TLS not set, SCM minimum TLS 1\.0\)'
        $email | Should -Match '\r?\n\r?\nEach minimum TLS version the change sets can be set back to the version each application has today, shown above\.'
        $request = @($email -split "`r?`n" | Where-Object { $_ -match '^Could you' })[0]
        $request | Should -Match '^Could you let me know whether any deployment tool, build agent or script still reaches the SCM site of these applications over TLS 1\.0 or 1\.1\? With that confirmed, could you approve this change for '
        $request | Should -Match 'If one still does, I will hold the SCM part of the change for that application until it is updated\.'
        $email | Should -Not -Match 'app-both-blank'
    }

    It 'writes only the SCM step for an app whose site minimum is already 1.2 or later' {
        $one = Build-Tls 'scm-only'
        @(Get-Section $one.Cr 'A) CHANGE DESCRIPTION')[0] | Should -Be 'Set the SCM (Kudu) site minimum inbound TLS version to 1.2 on the App Service app listed below.'
        @(Get-Section $one.Cr 'A) IMPLEMENTATION PLAN') | Should -Be @(
            '1. In the Azure portal, go to App Services and open the app listed in the RESOURCES section.'
            '2. Go to Settings > Configuration and select the General settings tab.'
            '3. Read SCM Minimum Inbound TLS Version. If it still shows 1.0 or 1.1, set it to 1.2. If it shows 1.2 or later, the app has changed since collection, so leave it as it is and note it in the change record.'
            '4. If a setting was changed, select Apply and confirm.')
        @(Get-Section $one.Cr 'C) RESOURCES') | Should -Contain '- app-deploy, resource group rg-web, minimum TLS 1.3, SCM minimum TLS 1.0'
        $one.Csv.CurrentSetting | Should -Be 'minimum TLS 1.3, SCM minimum TLS 1.0'
        Assert-ApprovalEmail $one.Email 'CR-04 for the SCM site of one application'
        $one.Email | Should -Match 'I would like your approval to set the minimum inbound TLS version of the SCM site to 1\.2 on one of your App Service and Function applications\.'
        $one.Email | Should -Match 'would fail to deploy once the change is applied, while the application itself is not affected\.'
        $one.Email | Should -Match 'still reaches the SCM site of the application over TLS 1\.0 or 1\.1\?'
        $one.Email | Should -Match 'The application is listed below with its minimum TLS versions today, for the application and for its SCM site:'
    }

    It 'writes the site part on a pack collected before 1.13.0 and says the SCM part needs recollection' {
        $old = Build-Tls 'before-scm' '1.12.0'
        $old.Cr | Should -Not -Match 'SCM' -Because 'the pack does not record the SCM minimum'
        @(Get-Section $old.Cr 'C) RESOURCES') | Should -Contain '- app-legacy, resource group rg-web, minimum TLS 1.0'
        @(Get-Section $old.Cr 'A) IMPLEMENTATION PLAN')[2] | Should -Be '3. Read Minimum Inbound TLS Version. If it still shows 1.0 or 1.1, set it to 1.2. If it shows 1.2 or later, the app has changed since collection, so leave it as it is and note it in the change record.' -Because 'a value raised to 1.3 since collection is never lowered to 1.2'
        $old.Csv.CurrentSetting | Should -Be 'minimum TLS 1.0'
        Assert-ApprovalEmail $old.Email 'CR-04 on a pack before 1.13.0'
        $old.Email | Should -Not -Match 'SCM|Kudu'
        $old.Index | Should -Match '- NB\.5-DETAIL in this pack does not record the SCM \(Kudu\) site minimum TLS version, so CR-04 covers the site minimum only\. Recollect with CyberSOC collector 1\.13\.0 or later for the SCM part\.'
        $old.Index | Should -Match 'left out of CR-04 because Resource Graph returned no minimum TLS version, and App Service applies 1\.2 when none is set: app-legacy-blank\.'
    }

    It 'reads an empty list as no gaps only on a pack that records the SCM minimum' {
        (Build-Tls 'empty' '1.13.0').Index | Should -Match '\| 04 \| Minimum TLS 1\.2 on App Service apps \|  \| No gaps found \|  \|'
        $old = Build-Tls 'empty' '1.12.0'
        $old.Index | Should -Match '\| 04 \| Minimum TLS 1\.2 on App Service apps \|  \| No site gaps found, the SCM part needs recollection with CyberSOC collector 1\.13\.0 or later \|  \|' -Because 'before 1.13.0 the list left out a site at 1.2 whatever its SCM minimum'
        $old.Index | Should -Match 'Recollect with CyberSOC collector 1\.13\.0 or later for the SCM part\.'
    }
}

Describe 'FTP basic authentication publishing credentials turned off with the FTP state (CR-17, collector 1.14.0)' {
    BeforeAll {
        # A scenario from tests/fixtures/offline-pack/app-service-ftp-auth written into a pack as NB.5-FTPS-DETAIL,
        # NB.5-FTPAUTH and NB.5-FTPAUTH-DETAIL, the detail taken from the apps read as On as the collector writes it, and
        # the change requests built from it.
        function Build-Ftp([string]$Name) {
            $pack = Join-Path $TestDrive "ftp-$Name"
            New-ChangeFixture $pack
            $fx = Get-Content (Join-Path $PSScriptRoot "fixtures/offline-pack/app-service-ftp-auth/$Name.json") -Raw | ConvertFrom-Json
            $all = @($fx.FtpAuth | Where-Object { $_ })
            $notRead = @($all | Where-Object ReadStatus -ne 'OK')
            Set-PackResult $pack 'NB.5-FTPS-DETAIL' @($fx.FtpsDetail | Where-Object { $_ })
            Set-PackResult $pack 'NB.5-FTPAUTH' $all $(if ($notRead.Count) { 'PARTIAL' })
            Set-PackResult $pack 'NB.5-FTPAUTH-DETAIL' @($all | Where-Object { $_.ReadStatus -eq 'OK' -and $_.FtpBasicAuth -eq 'On' } | Select-Object subscriptionId, resourceGroup, Name, FtpsState, FtpBasicAuth, ResourceId) $(if ($notRead.Count) { 'PARTIAL' })
            $null = & $generator -EvidencePath $pack
            $out = Join-Path $pack '05-change-requests'
            @{ Pack = $pack; Out = $out; Index = Get-Content (Join-Path $out '00-index.md') -Raw; Csv = @(Import-Csv (Join-Path $out 'change-requests.csv') | Where-Object CR -eq 'CR-17')
                Cr = $(if (Test-Path (Join-Path $out 'CR-17-app-service-ftps.txt')) { Get-Content (Join-Path $out 'CR-17-app-service-ftps.txt') -Raw })
                Email = $(if (Test-Path (Join-Path $out 'CR-17-app-service-ftps.email.txt')) { Get-Content (Join-Path $out 'CR-17-app-service-ftps.email.txt') -Raw }) }
        }
        $mixed = Build-Ftp 'mixed'
    }

    It 'turns FTP basic authentication off on every app where it is On, whatever its FTP state, beside the FTP state part' {
        $text = $mixed.Cr
        $text | Should -Match '^Title: Set the FTP state to FTPS only or Disabled and turn off FTP basic authentication on App Service apps\r?\n'
        @(Get-Section $text 'A) CHANGE DESCRIPTION') | Should -Be 'On the 4 App Service and Function apps listed below, set the FTP state to FTPS only, or to Disabled where the client confirms nothing uses FTP or FTPS, where it reads All allowed, and turn off FTP Basic Auth Publishing Credentials where it is On.'
        @(Get-Section $text 'C) RESOURCES') | Should -Be @(
            'The 4 apps below are listed with the FTP state and, where it was read, the FTP basic authentication setting each one has today.'
            "Subscription: Example Production ($s1)"
            '- app-plain-off, resource group rg-web, FTP state All allowed, FTP basic authentication Off'
            '- app-plain-on, resource group rg-web, FTP state All allowed, minimum TLS 1.0, FTP basic authentication On'
            "Subscription: Example, Dev Test ($s2)"
            '- app-ftps-on, resource group rg-api, FTP state FTPS only, FTP basic authentication On'
            '- func-closed-on, resource group rg-jobs, FTP state Disabled, FTP basic authentication On') -Because 'an app already set to FTPS only or Disabled is in CR-17 when its FTP basic authentication is On'
        $text | Should -Not -Match 'app-ftps-off|func-closed-off|app-unread' -Because 'an app read as Off, or not read, is not changed'
        @(Get-Section $text 'C) DEPENDENCIES') | Should -Be 'Tools, processes and people that use plain FTP, FTP or FTPS on an app set to Disabled, or deployment credentials for FTP, FTPS or possibly local Git where FTP basic authentication is turned off, can no longer connect once the change is applied.'
        @($mixed.Csv | ForEach-Object { '{0}|{1}' -f $_.Resource, $_.CurrentSetting }) | Should -Be @(
            'app-plain-on|FTP state All allowed, minimum TLS 1.0, FTP basic authentication On'
            'app-plain-off|FTP state All allowed, FTP basic authentication Off'
            'app-ftps-on|FTP state FTPS only, FTP basic authentication On'
            'func-closed-on|FTP state Disabled, FTP basic authentication On') -Because 'the rollback restores the recorded values'
        ($mixed.Csv | Where-Object Resource -eq 'func-closed-on').ResourceId | Should -Be "/subscriptions/$s2/resourceGroups/rg-jobs/providers/Microsoft.Web/sites/func-closed-on"
    }

    It 'reads each value again before changing it, turns basic authentication off only where the client confirmed nothing uses the credentials, and rolls back to the recorded values' {
        @(Get-Section $mixed.Cr 'A) IMPLEMENTATION PLAN') | Should -Be @(
            '1. In the Azure portal, go to App Services and open the first app listed in the RESOURCES section.'
            '2. Go to Settings > Configuration and select the General settings tab.'
            '3. If the RESOURCES section lists FTP state All allowed for the app, under Platform settings, read FTP state. If it no longer shows All allowed, the state recorded for the app in the RESOURCES section, the app has changed since collection, so leave the FTP state unchanged and note it in the change record for the next pack.'
            '4. If FTP state still shows All allowed, set it to the state the client chose for the app: FTPS only, or Disabled only where the client confirmed that no tool, process or person uses FTP or FTPS on the app, to upload files or to download files or logs. Before setting FTPS only, read Minimum Inbound TLS Version. FTPS only does not support TLS 1.0 or 1.1, so if it shows 1.0 or 1.1, leave the FTP state unchanged until CR-04 has set 1.2 on the app and note it in the change record.'
            '5. If the RESOURCES section lists FTP basic authentication On for the app, read FTP Basic Auth Publishing Credentials. If it shows Off, the app has changed since collection, so leave it as it is and note it in the change record. If it shows On, set it to Off only where the client confirmed that no deployment tool, process or person uses deployment credentials on the app to sign in to FTP or FTPS or to deploy through local Git. Otherwise leave it On and note it in the change record.'
            '6. If a setting was changed, select Save, or Apply where the portal shows it, and confirm.'
            '7. Repeat steps 1 to 6 for each remaining app listed.')
        @(Get-Section $mixed.Cr 'B) TESTING PLAN') | Should -Be @(
            '1. In the Azure portal, open each app listed in the RESOURCES section, go to Settings > Configuration and select the General settings tab.'
            '2. Where the change set the FTP state, confirm FTP state shows FTPS only or Disabled under Platform settings, as agreed with the client for the app.'
            '3. Where the change turned FTP basic authentication off, confirm FTP Basic Auth Publishing Credentials shows Off.')
        @(Get-Section $mixed.Cr 'C) ROLLBACK PLAN')[1] | Should -Be '2. Set back only the settings the change made, FTP state to All allowed and FTP Basic Auth Publishing Credentials to On, each as recorded for the app in the RESOURCES section, then select Save, or Apply where the portal shows it, and confirm. An app left unchanged during the change needs no rollback.'
        $refs = @(Get-Section $mixed.Cr 'A) REFERENCES')
        $refs | Should -Contain '- Disable basic authentication in Azure App Service deployments, deploy without basic authentication: https://learn.microsoft.com/azure/app-service/configure-basic-auth-disable#deploy-without-basic-authentication'
        $refs | Should -Contain '- Manage deployment credentials for Azure App Service: https://learn.microsoft.com/azure/app-service/deploy-configure-credentials'
        foreach ($r in $refs) { $r | Should -Match ': https://learn\.microsoft\.com/' -Because 'References lists Microsoft Learn pages only' }
    }

    It 'names in the index the app it could not read, the slots, the SCM setting it leaves out and the partial read' {
        $mixed.Index | Should -Match '\| 17 \| Plain FTP and FTP basic authentication turned off on App Service apps \| 4 \| Change request and client email, partial collection scope \|'
        $mixed.Index | Should -Match '- 1 App Service app left out of the FTP basic authentication part of CR-17 because the collector could not read its setting: app-unread \(resource group rg-api\)\. Check FTP Basic Auth Publishing Credentials under Settings > Configuration > General settings in the portal, and raise the change for any that shows On\.'
        $mixed.Index | Should -Match '- NB\.5-FTPS-DETAIL and NB\.5-FTPAUTH-DETAIL read the production site of each app\. Deployment slots have an FTP state and an FTP basic authentication setting of their own, which the pack does not read, so CR-17 does not cover them\.'
        $mixed.Index | Should -Match '- SCM Basic Auth Publishing Credentials, under the same General settings tab, is a separate setting and not part of CR-17\. It covers Web Deploy, local Git and the other deployment methods that use the SCM \(Kudu\) site'
        $mixed.Index | Should -Match 'its page on deployment credentials says that publishing through local Git or FTP/S needs both settings On, so the client email asks about local Git as well\.'
        $mixed.Index | Should -Match '- 1 App Service app in CR-17 has a minimum inbound TLS version below 1\.2: app-plain-on \(resource group rg-web\)\.'
        $mixed.Index | Should -Not -Match 'Recollect with CyberSOC collector 1\.14\.0|possible follow-up'
    }

    It 'says that FTP sign-in with the publish profile stops, that Entra sign-in is not affected, and asks about deployment credentials on every app where it is on' {
        $email = $mixed.Email
        Assert-ApprovalEmail $email 'CR-17 with FTP basic authentication'
        $email | Should -Match '^Subject: Approval requested: turning off plain FTP and FTP basic authentication on Azure App Service applications\r?\n'
        $email | Should -Match 'I would like your approval to turn off plain FTP and FTP basic authentication publishing credentials on 4 of your App Service and Function applications, wherever either one is allowed today\.'
        $email | Should -Match 'A deployment tool or a person that connects to the applications whose FTP state is All allowed over plain FTP'
        $email | Should -Match '\r?\n\r?\nTurning off FTP basic authentication means that signing in to FTP or FTPS with the user name and password in the publish profile of the applications where it is on today, or with a user''s own deployment credentials, stops working once the change is applied'
        $email | Should -Match '\r?\n\r?\nDeployment that signs in with Microsoft Entra ID is not affected, nor are deployment methods other than FTP and local Git, such as ZIP deploy, Web Deploy, GitHub Actions or an Azure DevOps pipeline without an FTP upload step, and these applications will keep serving their users as they do now\.\r?\n'
        $email | Should -Match '\r?\n\r?\nfunc-closed-on already has the FTP state Disabled, so for it the change matters only if a local Git deployment signs in with deployment credentials\.\r?\n'
        $email | Should -Match 'Microsoft notes that publishing through local Git with deployment credentials also needs this setting, so a local Git deployment that signs in that way would stop as well\.'
        $email | Should -Match 'FTPS only needs a minimum inbound TLS version of 1\.2, and app-plain-on still allows an older version'
        $email | Should -Match '- app-plain-on \(resource group rg-web, FTP state All allowed, FTP basic authentication On\)' -Because 'the email names the FTP basic authentication setting, without the minimum TLS'
        $email | Should -Match '\r?\n\r?\nEach setting the change makes can be set back to the value each application has today, shown above, at any time\.\r?\n'
        $request = @($email -split "`r?`n" | Where-Object { $_ -match '^Could you' })[0]
        $request | Should -Match 'Could you also let me know whether any deployment tool, scheduled process or person still uses deployment credentials, the user name and password from a publish profile or a user''s own, to sign in to FTP or FTPS or to deploy through local Git on the applications where FTP basic authentication is on\? With that agreed, could you approve this change for '
        $request | Should -Match 'If something still uses deployment credentials that way, I will leave FTP basic authentication on for that application until it moves to another deployment method\.'
        $email | Should -Not -Match 'app-ftps-off|func-closed-off|app-unread'
    }

    It 'writes the FTP basic authentication part alone, in singular wording, for one app already set to FTPS only' {
        $one = Build-Ftp 'ftps-only'
        $one.Cr | Should -Match '^Title: Turn off FTP basic authentication publishing credentials on App Service apps\r?\n'
        @(Get-Section $one.Cr 'A) CHANGE DESCRIPTION') | Should -Be 'Turn off FTP Basic Auth Publishing Credentials on the App Service app listed below, so no one can sign in to FTP or FTPS on it with deployment credentials.'
        @(Get-Section $one.Cr 'A) IMPLEMENTATION PLAN') | Should -Be @(
            '1. In the Azure portal, go to App Services and open the app listed in the RESOURCES section.'
            '2. Go to Settings > Configuration and select the General settings tab.'
            '3. Read FTP Basic Auth Publishing Credentials. If it shows Off, the app has changed since collection, so leave it as it is and note it in the change record. If it shows On, set it to Off only where the client confirmed that no deployment tool, process or person uses deployment credentials on the app to sign in to FTP or FTPS or to deploy through local Git. Otherwise leave it On and note it in the change record.'
            '4. If a setting was changed, select Save, or Apply where the portal shows it, and confirm.')
        @(Get-Section $one.Cr 'C) ROLLBACK PLAN')[1] | Should -Be '2. Set FTP Basic Auth Publishing Credentials back to On, the setting recorded for the app in the RESOURCES section, then select Save, or Apply where the portal shows it, and confirm. An app left unchanged during the change needs no rollback.'
        @(Get-Section $one.Cr 'A) REFERENCES')[0] | Should -Be '- Disable basic authentication in Azure App Service deployments: https://learn.microsoft.com/azure/app-service/configure-basic-auth-disable'
        $one.Cr | Should -Not -Match 'Platform settings|Minimum Inbound TLS' -Because 'the FTP state is not changed'
        Assert-ApprovalEmail $one.Email 'CR-17 FTP basic authentication for one application'
        $one.Email | Should -Match '^Subject: Approval requested: turning off FTP basic authentication on Azure App Service applications\r?\n'
        $one.Email | Should -Match 'I would like your approval to turn off FTP basic authentication publishing credentials on one of your App Service and Function applications\.'
        $one.Email | Should -Match 'I recommend turning it off because anyone who holds those credentials can sign in and change the files of the application, while signing in with Microsoft Entra ID, a more secure way to deploy, uses tokens that expire, are issued for one application and cannot be reused\.'
        $one.Email | Should -Match 'the application will keep serving its users as it does now\.'
        $one.Email | Should -Match 'The application is listed below with its FTP state and FTP basic authentication setting today:'
        $one.Email | Should -Match '\r?\n\r?\nFTP basic authentication can be turned back on, the setting the application has today, at any time\.\r?\n'
        $one.Email | Should -Match 'Could you let me know whether any deployment tool, scheduled process or person still uses deployment credentials, the user name and password from a publish profile or a user''s own, to sign in to FTP or FTPS or to deploy through local Git on the application\? With that confirmed, could you approve this change for '
        $one.Email | Should -Not -Match 'plain FTP|FTPS only or Disabled'
        $one.Index | Should -Match '\| 17 \| Plain FTP and FTP basic authentication turned off on App Service apps \| 1 \| Change request and client email \|'
    }

    It 'still asks about local Git where FTP is already Disabled, since local Git publishing also needs FTP basic authentication' {
        $closed = Build-Ftp 'disabled-only'
        @(Get-Section $closed.Cr 'A) IMPLEMENTATION PLAN')[2] | Should -Be '3. Read FTP Basic Auth Publishing Credentials. If it shows Off, the app has changed since collection, so leave it as it is and note it in the change record. If it shows On, set it to Off only where the client confirmed that no deployment tool, process or person uses deployment credentials on the app to sign in to FTP or FTPS or to deploy through local Git. Otherwise leave it On and note it in the change record.'
        Assert-ApprovalEmail $closed.Email 'CR-17 FTP basic authentication where FTP is Disabled'
        $closed.Email | Should -Match '\r?\n\r?\nWith FTP basic authentication off, signing in to FTP or FTPS with the user name and password in the publish profile of these applications, or with a user''s own deployment credentials, would no longer work even if FTP were turned back on\. Microsoft notes that publishing through local Git with deployment credentials also needs this setting'
        $closed.Email | Should -Match '\r?\n\r?\nThe FTP state of each application is already Disabled, so nothing connects over FTP or FTPS today, and the change matters only if a local Git deployment signs in with deployment credentials\.\r?\n'
        $closed.Email | Should -Match 'Could you let me know whether any deployment tool, scheduled process or person still uses deployment credentials, the user name and password from a publish profile or a user''s own, to sign in to FTP or FTPS or to deploy through local Git on these applications\? With that confirmed, could you approve this change for ' -Because 'a local Git deployment can still use the credentials where FTP is Disabled'
        $closed.Email | Should -Not -Match 'no effect|no difference'
        @($closed.Csv.Resource | Sort-Object) | Should -Be @('app-closed', 'func-closed')
    }

    It 'writes the FTP basic authentication part when the FTP state read failed, and the old state when neither part was read' {
        $pack = Join-Path $TestDrive 'ftp-state-failed'
        New-ChangeFixture $pack
        $fx = Get-Content (Join-Path $PSScriptRoot 'fixtures/offline-pack/app-service-ftp-auth/ftps-only.json') -Raw | ConvertFrom-Json
        Set-PackResult $pack 'NB.5-FTPS-DETAIL' @() 'FAILED' 'Resource Graph throttled'
        Set-PackResult $pack 'NB.5-FTPAUTH' @($fx.FtpAuth)
        Set-PackResult $pack 'NB.5-FTPAUTH-DETAIL' @($fx.FtpAuth | Select-Object subscriptionId, resourceGroup, Name, FtpsState, FtpBasicAuth, ResourceId)
        $null = & $generator -EvidencePath $pack
        $out = Join-Path $pack '05-change-requests'
        $index = Get-Content (Join-Path $out '00-index.md') -Raw
        $index | Should -Match '\| 17 \| Plain FTP and FTP basic authentication turned off on App Service apps \| 1 \| Change request and client email \|' -Because 'a failed FTP state read does not hold back the FTP basic authentication part'
        $index | Should -Match '- NB\.5-FTPS-DETAIL reads FAILED, so CR-17 covers FTP basic authentication only\. Recollect the pack for the FTP state part\.'
        Get-Content (Join-Path $out 'CR-17-app-service-ftps.txt') -Raw | Should -Match '^Title: Turn off FTP basic authentication publishing credentials on App Service apps\r?\n'
        Set-PackResult $pack 'NB.5-FTPAUTH-DETAIL' @()
        $null = & $generator -EvidencePath $pack
        Get-Content (Join-Path $out '00-index.md') -Raw | Should -Match '\| 17 \| Plain FTP and FTP basic authentication turned off on App Service apps \|  \| No FTP basic authentication gaps found, the FTP state part was not collected, see the notes \|  \|'
        Remove-PackResult $pack 'NB.5-FTPAUTH'
        Remove-PackResult $pack 'NB.5-FTPAUTH-DETAIL'
        $null = & $generator -EvidencePath $pack
        Get-Content (Join-Path $out '00-index.md') -Raw | Should -Match '\| 17 \| Plain FTP and FTP basic authentication turned off on App Service apps \|  \| Not collected \(NB\.5-FTPS-DETAIL FAILED\) \|  \|'
        Set-PackResult $pack 'NB.5-FTPS-DETAIL' @(@{ Name = 'x' })
        Set-Content (Join-Path $pack 'results/NB.5-FTPS-DETAIL.json') '{not json'
        $null = & $generator -EvidencePath $pack
        Get-Content (Join-Path $out '00-index.md') -Raw | Should -Match '\| 17 \| Plain FTP and FTP basic authentication turned off on App Service apps \|  \| Result file unreadable \(NB\.5-FTPS-DETAIL\), recollect or restore the pack \|  \|'
    }

    It 'never reads a partial read with no app to change as no gaps' {
        $pack = Join-Path $TestDrive 'ftp-partial-off'
        New-ChangeFixture $pack
        $fx = Get-Content (Join-Path $PSScriptRoot 'fixtures/offline-pack/app-service-ftp-auth/all-off.json') -Raw | ConvertFrom-Json
        $denied = [pscustomobject]@{ subscriptionId = $s1; resourceGroup = 'rg-web'; Name = 'app-denied'; FtpsState = 'FtpsOnly'; FtpBasicAuth = ''; ReadStatus = 'HTTP 403: Forbidden'; ResourceId = "/subscriptions/$s1/resourceGroups/rg-web/providers/Microsoft.Web/sites/app-denied" }
        Set-PackResult $pack 'NB.5-FTPS-DETAIL' @()
        Set-PackResult $pack 'NB.5-FTPAUTH' (@($fx.FtpAuth) + $denied) 'PARTIAL'
        Set-PackResult $pack 'NB.5-FTPAUTH-DETAIL' @() 'PARTIAL'
        $null = & $generator -EvidencePath $pack
        $index = Get-Content (Join-Path $pack '05-change-requests/00-index.md') -Raw
        $index | Should -Match '\| 17 \| Plain FTP and FTP basic authentication turned off on App Service apps \|  \| No gaps found in the apps read, partial collection scope \(NB\.5-FTPAUTH-DETAIL\), see the notes \|  \|' -Because 'an app not read may still have FTP basic authentication On'
        $index | Should -Match '- 1 App Service app left out of the FTP basic authentication part of CR-17 because the collector could not read its setting: app-denied \(resource group rg-web\)\.'
        # Resource Graph truncated the app list: every app listed was read, and the detail is still partial.
        Set-PackResult $pack 'NB.5-FTPAUTH' @($fx.FtpAuth) 'PARTIAL'
        $null = & $generator -EvidencePath $pack
        $index = Get-Content (Join-Path $pack '05-change-requests/00-index.md') -Raw
        $index | Should -Match 'No gaps found in the apps read, partial collection scope \(NB\.5-FTPAUTH-DETAIL\)'
        $index | Should -Match '- NB\.5-FTPAUTH-DETAIL is partial although NB\.5-FTPAUTH names no app it could not read, so Resource Graph may have returned only part of the app list'
    }

    It 'reads no gaps when every app has FTP basic authentication Off and plain FTP off' {
        $off = Build-Ftp 'all-off'
        $off.Cr | Should -BeNullOrEmpty
        $off.Index | Should -Match '\| 17 \| Plain FTP and FTP basic authentication turned off on App Service apps \|  \| No gaps found \|  \|'
    }

    It 'never reads a failed or partial FTP basic authentication read as Off' {
        $pack = Join-Path $TestDrive 'ftp-failed'
        New-ChangeFixture $pack
        Set-PackResult $pack 'NB.5-FTPS-DETAIL' @()
        Set-PackResult $pack 'NB.5-FTPAUTH' @() 'FAILED' 'Resource Graph throttled'
        Set-PackResult $pack 'NB.5-FTPAUTH-DETAIL' @() 'FAILED' 'Resource Graph throttled'
        $null = & $generator -EvidencePath $pack
        $index = Get-Content (Join-Path $pack '05-change-requests/00-index.md') -Raw
        $index | Should -Match '\| 17 \| Plain FTP and FTP basic authentication turned off on App Service apps \|  \| No FTP state gaps found, the FTP basic authentication part was not collected, see the notes \|  \|'
        $index | Should -Match '- NB\.5-FTPAUTH-DETAIL reads FAILED, so CR-17 covers the FTP state only\. Recollect the pack for the FTP basic authentication part\.'
        # A partial detail whose per-app list is missing still says an app may be missing.
        $fx = Get-Content (Join-Path $PSScriptRoot 'fixtures/offline-pack/app-service-ftp-auth/ftps-only.json') -Raw | ConvertFrom-Json
        Set-PackResult $pack 'NB.5-FTPAUTH-DETAIL' @($fx.FtpAuth | Select-Object subscriptionId, resourceGroup, Name, FtpsState, FtpBasicAuth, ResourceId) 'PARTIAL'
        Remove-PackResult $pack 'NB.5-FTPAUTH'
        $null = & $generator -EvidencePath $pack
        $index = Get-Content (Join-Path $pack '05-change-requests/00-index.md') -Raw
        $index | Should -Match '\| 17 \| Plain FTP and FTP basic authentication turned off on App Service apps \| 1 \| Change request and client email, partial collection scope \|'
        $index | Should -Match '- NB\.5-FTPAUTH-DETAIL is partial, and NB\.5-FTPAUTH, which names the apps the collector could not read, is not in this pack, so an app with FTP basic authentication On may be missing from CR-17\.'
    }
}

Describe 'MySQL flexible server audit parameters set with the diagnostic logging changes (CR-01 and CR-10, collector 1.15.0)' {
    BeforeAll {
        # A scenario from tests/fixtures/offline-pack/mysql-audit written into a pack as DR.6-MYSQLAUDIT, beside
        # DR.6-NONCOMPLIANT, with the initiative assigned on both subscriptions unless Initiative is given.
        function Build-MySql([string]$Name, [string]$Status, $Initiative, $Coverage) {
            $pack = Join-Path $TestDrive "mysql-$Name-$([guid]::NewGuid().ToString('N').Substring(0, 6))"
            New-ChangeFixture $pack
            $fx = Get-Content (Join-Path $PSScriptRoot "fixtures/offline-pack/mysql-audit/$Name.json") -Raw | ConvertFrom-Json
            $nc = @($fx.NonCompliant | Where-Object { $_ })
            if ($null -eq $Initiative) { $Initiative = @(@{ DefinitionName = 'ATMO-MXDR-KV-TOSENT'; Resources = 8; Compliant = 8 - $nc.Count; NonCompliant = $nc.Count }) }
            if ($null -eq $Coverage) { $Coverage = @(@{ subscriptionId = $s1; Resources = 5; Assignments = 1 }, @{ subscriptionId = $s2; Resources = 3; Assignments = 1 }) }
            Set-PackResult $pack 'DR.6-INITIATIVE' @($Initiative)
            if (@($Initiative).Count) { Set-PackResult $pack 'DR.6-COVERAGE' @($Coverage) }
            if ($nc.Count) { Set-PackResult $pack 'DR.6-NONCOMPLIANT' $nc }
            Set-PackResult $pack 'DR.6-MYSQLAUDIT' @($fx.MySqlAudit | Where-Object { $_ }) $Status
            $null = & $generator -EvidencePath $pack
            $out = Join-Path $pack '05-change-requests'
            $read = { param($f) if (Test-Path (Join-Path $out $f)) { Get-Content (Join-Path $out $f) -Raw } }
            @{ Pack = $pack; Out = $out; Index = Get-Content (Join-Path $out '00-index.md') -Raw; Csv = @(Import-Csv (Join-Path $out 'change-requests.csv'))
                Cr01 = & $read 'CR-01-diagnostic-logging.txt'; Email01 = & $read 'CR-01-diagnostic-logging.email.txt'
                Cr = & $read 'CR-10-diagnostic-remediation.txt'; Email = & $read 'CR-10-diagnostic-remediation.email.txt' }
        }
        $mixed = Build-MySql 'mixed' 'PARTIAL'
    }

    It 'sets the audit parameters on every MySQL server that needs them, compliant or not, before the remediation tasks' {
        $text = $mixed.Cr
        $text | Should -Match '^Title: Remediate resources missing ATMO-MXDR diagnostic logging and turn on the MySQL audit log\r?\n'
        @(Get-Section $text 'C) RESOURCES') | Should -Be @(
            'The 4 resources below are not compliant with the initiative, with the policies each one fails, or are MySQL flexible servers listed with their audit parameters today.'
            "Subscription: Example Production ($s1)"
            '- kv-app, resource group rg-app, Key vault, policies ATMO-MXDR-KV-TOSENT'
            '- mysql-billing, resource group rg-db, MySQL flexible server, audit_log_enabled OFF, audit_log_events CONNECTION,DDL, audit_log_exclude_users svc_backup'
            '- mysql-general, resource group rg-db, MySQL flexible server, audit_log_enabled OFF, audit_log_events CONNECTION_V2,GENERAL'
            '- mysql-orders, resource group rg-db, MySQL flexible server, policies ATMO-MXDR-MYSQL-TOSENT, audit_log_enabled OFF, audit_log_events CONNECTION') -Because 'a compliant server with audit OFF writes no audit rows, a non-compliant one is listed once with both, and a user filter is shown'
        $text | Should -Not -Match 'mysql-ledger|mysql-reports|mysql-legacy|mysql-v2|mysql-paused|mysql-new' -Because 'a server that covers the baseline, CONNECTION_V2 included, that was not read, or that is stopped, is not changed'
        $impl = @(Get-Section $text 'A) IMPLEMENTATION PLAN')
        $impl[0] | Should -Be '1. In the Azure portal, go to Azure Database for MySQL flexible servers and open the first MySQL flexible server listed with its audit parameters in the RESOURCES section.'
        $impl[1] | Should -Be '2. Go to Settings > Server parameters and search for audit_log.'
        $impl[2] | Should -Match '^3\. Read audit_log_enabled and audit_log_events\. If either no longer shows the value recorded for the server in the RESOURCES section, .*set that value back instead of the recorded one if the change is rolled back\.$'
        $text | Should -Not -Match 'parameter show|currentValue' -Because 'no server is restart pending, so the portal shows the value in effect'
        $impl[3] | Should -Be '4. Set audit_log_enabled to ON, and add to audit_log_events each of CONNECTION, ADMIN, DDL and DCL it leaves out, keeping every event already selected so no audit coverage is removed. CONNECTION_V2 already covers CONNECTION, and GENERAL already covers ADMIN, DDL and DCL.' -Because 'replacing CONNECTION_V2 or GENERAL would remove audit coverage'
        $impl[4] | Should -Be '5. Leave audit_log_include_users and audit_log_exclude_users as they are. Where the RESOURCES section shows either for the server, it audits only some users, and the filter stays until the client decides otherwise.'
        $impl[5] | Should -Match '^6\. Select Save\. Azure reported both parameters as dynamic on the server, so they apply without a restart\.'
        $impl[6] | Should -Be '7. Repeat steps 1 to 6 for each remaining MySQL flexible server listed with its audit parameters.'
        $impl[7] | Should -Be '8. In the Azure portal, go to Policy > Remediation and select the Policies to remediate tab.' -Because 'the parameters go on before the remediation tasks'
        $impl[9] | Should -Be "    - Assignment ATMO-MXDR-DIAG-TOSENT at subscription Example Production ($s1): ATMO-MXDR-KV-TOSENT, ATMO-MXDR-MYSQL-TOSENT"
        $testing = @(Get-Section $text 'B) TESTING PLAN')
        $testing[0] | Should -Match 'confirm audit_log_enabled shows ON and audit_log_events includes CONNECTION, ADMIN, DDL and DCL, or CONNECTION_V2 or GENERAL where they cover them\.$'
        $testing[1] | Should -Match 'confirm the ATMO-MXDR setting sends the MySqlAuditLogs category to the Sentinel workspace law-example-sentinel, with no slow query logs and no metrics\.$'
        $testing[2] | Should -Match '^3\. About 10 minutes after the change, .*Resource is the server name in upper case\.$'
        $testing[3] | Should -Be '    AzureDiagnostics | where Category == "MySqlAuditLogs" | summarize count() by Resource'
        @(Get-Section $text 'C) ROLLBACK PLAN')[0] | Should -Match '^1\. On each MySQL flexible server the change set, go to Settings > Server parameters, set audit_log_enabled and audit_log_events back to the values recorded for the server'
        $refs = @(Get-Section $text 'A) REFERENCES')
        $refs | Should -Contain '- Tutorial: Configure audit logs by using Azure Database for MySQL - Flexible Server: https://learn.microsoft.com/azure/mysql/flexible-server/tutorial-configure-audit'
        foreach ($r in $refs) { $r | Should -Match ': https://learn\.microsoft\.com/' -Because 'References lists Microsoft Learn pages only' }
        $refs | Should -Not -Match 'how-to-restart-server-portal' -Because 'every server reads both parameters as dynamic'
        @(Get-Section $text 'A) AVAILABILITY/PERFORMANCE') | Should -Be 'No impact, since the Azure platform applies diagnostic settings without touching the running workloads and both MySQL audit parameters apply without a restart.'
        @(Get-Section $text 'C) ROLLBACK PLAN')[0] | Should -Not -Match 'restart' -Because 'every server read both parameters as dynamic'
        @($mixed.Csv | Where-Object CR -eq 'CR-10' | ForEach-Object { '{0}|{1}' -f $_.Resource, $_.CurrentSetting }) | Should -Be @(
            'kv-app|Key vault, policies ATMO-MXDR-KV-TOSENT'
            'mysql-orders|MySQL flexible server, policies ATMO-MXDR-MYSQL-TOSENT, audit_log_enabled OFF, audit_log_events CONNECTION'
            'mysql-billing|MySQL flexible server, audit_log_enabled OFF, audit_log_events CONNECTION,DDL, audit_log_exclude_users svc_backup'
            'mysql-general|MySQL flexible server, audit_log_enabled OFF, audit_log_events CONNECTION_V2,GENERAL')
    }

    It 'names the servers it could not read and the ones that log more than the baseline, and never reads them as set' {
        $mixed.Index | Should -Match '\| 10 \| Diagnostic logging remediated on non-compliant resources \| 4 \| Change request and client email, partial collection scope \|'
        $mixed.Index | Should -Match '- 1 MySQL flexible server left out of the MySQL audit parameter step of CR-10 because the collector could not read its audit parameters: mysql-legacy \(resource group rg-fin\)\. Read audit_log_enabled and audit_log_events under Settings > Server parameters in the portal'
        $mixed.Index | Should -Match '- 2 MySQL flexible servers already have audit_log_enabled ON with every event the baseline sets, and also log more: mysql-reports \(resource group rg-fin\), audit_log_events CONNECTION,ADMIN,DDL,DCL,DML_SELECT / mysql-v2 \(resource group rg-fin\), audit_log_events CONNECTION_V2,ADMIN,DDL,DCL\. CR-10 leaves them as they are\.'
        $mixed.Index | Should -Match '- 2 MySQL flexible servers audit only some MySQL users, through audit_log_include_users or audit_log_exclude_users: mysql-billing \(resource group rg-db\), audit_log_exclude_users svc_backup / mysql-v2 \(resource group rg-fin\), audit_log_include_users app_admin\. CR-10 leaves the filters as they are, since clearing one is the client''s decision\.' -Because 'a user filter limits who is audited, so it is never read as every user audited'
        $mixed.Index | Should -Not -Match 'mysql-ledger' -Because 'a server set as the baseline sets it needs nothing'
        $mixed.Index | Should -Match '- 1 MySQL flexible server left out of the MySQL audit parameter step of CR-10 because the ATMO-MXDR initiative has no policy state for it yet, so nothing proves its diagnostic setting: mysql-new \(resource group rg-db\)\.' -Because 'subscription coverage proves nothing for a server the initiative has not evaluated'
        $mixed.Index | Should -Match '- 1 MySQL flexible server left out of the MySQL audit parameter step of CR-10 because it reads stopped, and Azure allows no change to server parameters while a server is stopped: mysql-paused \(resource group rg-db\)\. Raise the change for it once the client starts it\.'
    }

    It 'asks the client in a letter that covers the audit log, its rows in step with connections and administrative statements, and no restart' {
        $email = $mixed.Email
        Assert-ApprovalEmail $email 'CR-10 with MySQL audit parameters'
        $email | Should -Match '^Subject: Approval requested: diagnostic logging remediation for Azure resources'
        $email | Should -Match 'I would like your approval to run Azure Policy remediation tasks for the ATMO-MXDR-DIAG-TOSENT initiative on 2 of your Azure resources and turn on the MySQL audit log on the 3 MySQL flexible servers, 1 of them among those resources and 2 that need only their audit parameters\.' -Because 'only the resources DR.6-NONCOMPLIANT names get remediation tasks'
        $email | Should -Not -Match 'on 4 of your Azure resources' -Because 'a compliant server that needs only its audit parameters gets no remediation task'
        $email | Should -Match 'The MySQL audit parameters are the exception, since they change what each server logs, as set out next\.'
        $email | Should -Match 'The MySQL audit log adds rows in step with the connections and administrative statements on each server'
        $email | Should -Match 'Azure reports both parameters as dynamic, so they apply without a restart and the databases stay available\.'
        $email | Should -Match 'The events a server already has selected stay selected, so the audit log also records CONNECTION_V2 and GENERAL on mysql-general\. ' -Because 'the change adds events and never removes one'
        $email | Should -Not -Match 'everyday queries stay out' -Because 'GENERAL also logs DML'
        $email | Should -Match 'mysql-billing audits only some MySQL users today, through the user filter shown below, which the change leaves as it is, so please let me know if every user should be audited there\.'
        $email | Should -Match 'This change adds Log Analytics ingestion to your Sentinel workspace law-example-sentinel\.'
        $email | Should -Match "- mysql-billing \(resource group rg-db, MySQL flexible server, audit_log_enabled OFF, audit_log_events CONNECTION,DDL, audit_log_exclude_users svc_backup\)\r?\n- mysql-general \(resource group rg-db, MySQL flexible server, audit_log_enabled OFF, audit_log_events CONNECTION_V2,GENERAL\)\r?\n- mysql-orders \(resource group rg-db, MySQL flexible server, audit_log_enabled OFF, audit_log_events CONNECTION\)"
        $email | Should -Not -Match 'ATMO-MXDR-MYSQL-TOSENT' -Because 'the client email names the resource type, not the policy'
        $email | Should -Match ('Could you approve this change for {0}\?' -f $dayPattern) -Because 'parameters that apply without a restart need no maintenance window'
    }

    It 'counts only the remediated resources in the combined email, whether the servers are among them or need only their audit parameters' {
        $pack = (Build-MySql 'mixed' 'PARTIAL').Pack
        $rows = @((Get-Content (Join-Path $PSScriptRoot 'fixtures/offline-pack/mysql-audit/mixed.json') -Raw | ConvertFrom-Json).MySqlAudit)
        $emailPath = Join-Path $pack '05-change-requests/CR-10-diagnostic-remediation.email.txt'
        # Only the non-compliant server: every server is among the remediated resources.
        Set-PackResult $pack 'DR.6-MYSQLAUDIT' @($rows | Where-Object Name -eq 'mysql-orders')
        $null = & $generator -EvidencePath $pack
        $email = Get-Content $emailPath -Raw
        Assert-ApprovalEmail $email 'CR-10 with the MySQL server among the remediated resources'
        $email | Should -Match 'I would like your approval to run Azure Policy remediation tasks for the ATMO-MXDR-DIAG-TOSENT initiative on 2 of your Azure resources and turn on the MySQL audit log on the MySQL flexible server among them\.'
        # Only a compliant server: it needs its audit parameters and no remediation task.
        Set-PackResult $pack 'DR.6-NONCOMPLIANT' @((Get-Content (Join-Path $PSScriptRoot 'fixtures/offline-pack/mysql-audit/mixed.json') -Raw | ConvertFrom-Json).NonCompliant | Where-Object { $_.ResourceId -match '/vaults/' })
        Set-PackResult $pack 'DR.6-MYSQLAUDIT' @($rows | Where-Object Name -eq 'mysql-billing')
        $null = & $generator -EvidencePath $pack
        $email = Get-Content $emailPath -Raw
        Assert-ApprovalEmail $email 'CR-10 with an audit-only MySQL server'
        $email | Should -Match 'I would like your approval to run Azure Policy remediation tasks for the ATMO-MXDR-DIAG-TOSENT initiative on one of your Azure resources and turn on the MySQL audit log on the MySQL flexible server, which needs only its audit parameters\.' -Because 'the key vault is the only resource remediated'
    }

    It 'writes CR-10 for the audit parameters alone when every resource is compliant, and asks for a window where a parameter is static or not reported' {
        $static = Build-MySql 'static'
        $static.Index | Should -Match '\| 10 \| Diagnostic logging remediated on non-compliant resources \| 3 \| Change request and client email \|' -Because 'a server compliant with the initiative still writes no audit rows while audit_log_enabled is OFF'
        $text = $static.Cr
        $text | Should -Match '^Title: Turn on the audit log of MySQL flexible servers for ATMO-MXDR diagnostic logging\r?\n'
        @(Get-Section $text 'C) RESOURCES') | Should -Be @(
            'The 3 MySQL flexible servers below are listed with their audit parameters today.'
            "Subscription: Example Production ($s1)"
            '- mysql-pending, resource group rg-db, MySQL flexible server, audit_log_enabled ON, audit_log_events CONNECTION,ADMIN,DDL,DCL, restart pending'
            '- mysql-static, resource group rg-db, MySQL flexible server, audit_log_enabled OFF, audit_log_events CONNECTION, restart needed'
            "Subscription: Example, Dev Test ($s2)"
            '- mysql-unreported, resource group rg-fin, MySQL flexible server, audit_log_enabled ON, audit_log_events CONNECTION,ADMIN, restart not reported') -Because 'audit_log_enabled ON without DDL and DCL still leaves events out'
        $text | Should -Not -Match 'Policy > Remediation' -Because 'nothing is left to remediate'
        $impl = @(Get-Section $text 'A) IMPLEMENTATION PLAN')
        $impl[2] | Should -Match ' A server the RESOURCES section marks restart pending is the exception, since the portal shows its saved value, which waits for a restart, and not the value in effect, so read that server as the next step sets out instead\.$' -Because 'the saved value on mysql-pending is expected to differ, and setting it back would leave the audit state the change set'
        $impl[3] | Should -Match '^4\. On a server the RESOURCES section marks restart pending, open Cloud Shell in Bash and read both parameters as Azure holds them'
        $impl[3] | Should -Match 'Note the currentValue of each parameter in the change record as the value the rollback sets back, whether or not it matches the recorded one, since a restart since collection puts the saved value in effect\.' -Because 'a restart between collection and the change makes the recorded value stale, so the rollback target is read again'
        $impl[3] | Should -Match 'If the output shows no currentValue, the value in effect cannot be told apart from the saved one, so skip the remaining steps for that server, note it in the change record and recollect the pack before changing it\.$' -Because 'a rollback target that cannot be read is never guessed'
        @($impl[4..5] | ForEach-Object { $_.Trim() }) | Should -Be @(
            "az mysql flexible-server parameter show --subscription '$s1' --resource-group 'rg-db' --server-name 'mysql-pending' --name audit_log_enabled"
            "az mysql flexible-server parameter show --subscription '$s1' --resource-group 'rg-db' --server-name 'mysql-pending' --name audit_log_events") -Because 'only the restart-pending server is read again'
        $impl[8] | Should -Match 'A server marked restart pending needs that restart even when nothing is left to set, since its saved value is not in effect until then\.$' -Because 'a saved value waiting for a restart is not in effect'
        $impl[9] | Should -Be '8. Repeat steps 1 to 7 for each remaining MySQL flexible server listed.'
        @(Get-Section $text 'A) IMPLEMENTATION PLAN')[8] | Should -Match '^7\. Select Save\. A server the RESOURCES section marks restart needed, or restart not reported, may ask to be restarted, since a static parameter applies only after a restart\. Select Restart later'
        @(Get-Section $text 'A) AVAILABILITY/PERFORMANCE') | Should -Match '^No impact from the diagnostic settings, but a MySQL server that does not report both audit parameters as dynamic may need a restart, a short outage,'
        @(Get-Section $text 'C) ROLLBACK PLAN')[0] | Should -Match 'and select Save\. On a server marked restart pending, set back the currentValue noted in the change record, which was in effect before the change, and not the saved value the portal showed before the change\. A server the RESOURCES section marks restart needed' -Because 'restoring the saved value on mysql-pending would never return it to the audit state it had before the change'
        @(Get-Section $text 'C) ROLLBACK PLAN')[0] | Should -Match 'keeps the changed values until it restarts, since a static parameter applies only after a restart\. If the portal asks to restart it, select Restart later and restart it within a maintenance window the client agrees, and the rollback is complete only after that restart\.$' -Because 'a static parameter set back takes effect only after a restart too'
        @(Get-Section $text 'A) REFERENCES') | Should -Contain '- Restart an Azure Database for MySQL - Flexible Server instance by using the Azure portal: https://learn.microsoft.com/azure/mysql/flexible-server/how-to-restart-server-portal'
        @(Get-Section $text 'A) REFERENCES') | Should -Contain '- Configure server parameters in Azure Database for MySQL - Flexible Server using the Azure CLI: https://learn.microsoft.com/azure/mysql/flexible-server/how-to-configure-server-parameters-cli' -Because 'the restart-pending server is read with az mysql flexible-server parameter show'
        @(Get-Section $text 'A) REFERENCES') | Should -Not -Match 'governance/policy' -Because 'no remediation task is run'
        $email = $static.Email
        Assert-ApprovalEmail $email 'CR-10 MySQL audit parameters alone'
        $email | Should -Match '^Subject: Approval requested: turning on the MySQL audit log for Azure diagnostic logging'
        $email | Should -Match 'mysql-pending already has an audit setting saved earlier that waits for a restart, so that server needs a restart, which causes a short outage, before the audit log starts\.'
        $email | Should -Match 'Azure reports a parameter as static on mysql-static, so that server needs a restart, which causes a short outage, before the audit log starts\.'
        $email | Should -Match 'Azure did not report whether the parameters are dynamic on mysql-unreported, so that server may need a restart'
        $email | Should -Match 'Could you approve this change and suggest a maintenance window that works for you\?'
        $email | Should -Match 'The audit parameters can be set back to the values each server has today, shown above, at any time'
        $static.Index | Should -Match '- 3 MySQL flexible servers in CR-10 do not report both audit parameters as dynamic: mysql-pending \(resource group rg-db\), mysql-static \(resource group rg-db\), mysql-unreported \(resource group rg-fin\)\..* A server marked restart pending already holds a saved audit value that waits for a restart'
    }

    It 'sets the audit parameters in CR-01 on the servers of the subscriptions it assigns, and leaves them out of CR-10' {
        # Not assigned anywhere: CR-01 takes every server.
        $fresh = Build-MySql 'mixed' 'PARTIAL' @()
        $fresh.Index | Should -Match '\| 10 \| .* \| Nothing to remediate until the initiative is assigned \(CR-01\) \|'
        $text = $fresh.Cr01
        @(Get-Section $text 'A) CHANGE DESCRIPTION') | Should -Match ' Set audit_log_enabled to ON and make audit_log_events include CONNECTION, ADMIN, DDL and DCL on the MySQL flexible servers listed below, so their diagnostic settings have audit rows to send\.$'
        $text | Should -Match "MySQL flexible servers whose audit parameters this change sets, with their values today:\r?\nSubscription: Example Production \($s1\)\r?\n- mysql-billing, resource group rg-db, MySQL flexible server, audit_log_enabled OFF, audit_log_events CONNECTION,DDL, audit_log_exclude_users svc_backup\r?\n- mysql-general, "
        $impl = @(Get-Section $text 'A) IMPLEMENTATION PLAN')
        $impl[7] | Should -Be '8. In the Azure portal, go to Azure Database for MySQL flexible servers and open the first MySQL flexible server listed with its audit parameters in the RESOURCES section.' -Because 'the parameters follow the assignments'
        $impl[13] | Should -Be '14. Repeat steps 8 to 13 for each remaining MySQL flexible server listed with its audit parameters.'
        $impl[14] | Should -Match '^15\. Once the first compliance scan completes, go to Policy > Remediation' -Because 'the parameters go on before the remediation tasks'
        @(Get-Section $text 'B) TESTING PLAN') | Should -Contain '    AzureDiagnostics | where Category == "MySqlAuditLogs" | summarize count() by Resource'
        @($fresh.Csv | Where-Object { $_.CR -eq 'CR-01' -and $_.Resource -like 'mysql-*' } | ForEach-Object Resource | Sort-Object) | Should -Be @('mysql-billing', 'mysql-general', 'mysql-new', 'mysql-orders') -Because 'CR-01 assigns the initiative, so a server it has not evaluated yet is set with it'
        $email = $fresh.Email01
        Assert-ApprovalEmail $email 'CR-01 with MySQL audit parameters'
        $email | Should -Match 'On the MySQL flexible servers below, the change sets audit_log_enabled to ON and makes sure audit_log_events includes CONNECTION, ADMIN, DDL and DCL'
        $email | Should -Match "- Subscription Activity Log\r?\n- MySQL flexible server mysql-billing \(resource group rg-db, audit_log_enabled OFF, audit_log_events CONNECTION,DDL, audit_log_exclude_users svc_backup\)\r?\n- MySQL flexible server mysql-general "
        $email | Should -Match 'The MySQL audit parameters can be set back to the values shown above at any time as well\.'
        $fresh.Index | Should -Match '- 1 MySQL flexible server left out of the MySQL audit parameter step of CR-01 because the collector could not read its audit parameters: mysql-legacy'
        # Assigned on the first subscription only: CR-01 assigns the second and takes its servers, CR-10 the rest.
        $split = Build-MySql 'static' '' @(@{ DefinitionName = 'ATMO-MXDR-KV-TOSENT'; Resources = 4; Compliant = 4; NonCompliant = 0 }) @(@{ subscriptionId = $s1; Resources = 4; Assignments = 1 })
        $split.Cr01 | Should -Match '- mysql-unreported, resource group rg-fin, MySQL flexible server' -Because "CR-01 assigns $s2"
        $split.Cr01 | Should -Not -Match 'mysql-static'
        $split.Cr | Should -Match '- mysql-static, resource group rg-db, MySQL flexible server'
        $split.Cr | Should -Not -Match 'mysql-unreported' -Because 'CR-01 sets the servers of the subscriptions it assigns'
        Assert-ApprovalEmail $split.Email01 'CR-01 with a static MySQL parameter'
        $split.Email01 | Should -Match 'Could you approve this change and suggest a maintenance window that works for you\?' -Because 'a parameter not reported as dynamic may need a restart'
    }

    It 'sets the parameters only on servers the initiative has evaluated, whatever DR.6-COVERAGE reads' {
        # The servers' own policy states prove the initiative, so a partial or missing coverage list changes nothing.
        $partial = Build-MySql 'mixed' 'PARTIAL' $null @(@{ subscriptionId = $s2; Resources = 3; Assignments = 1 })
        Set-PackResult $partial.Pack 'DR.6-COVERAGE' @(@{ subscriptionId = $s2; Resources = 3; Assignments = 1 }) 'PARTIAL'
        $null = & $generator -EvidencePath $partial.Pack
        $text = Get-Content (Join-Path $partial.Out 'CR-10-diagnostic-remediation.txt') -Raw
        $text | Should -Match '- mysql-orders, resource group rg-db, MySQL flexible server, policies ATMO-MXDR-MYSQL-TOSENT, audit_log_enabled OFF' -Because 'its own non-compliant state proves the initiative, even under an assignment at resource group scope'
        $text | Should -Match '- mysql-billing, ' -Because 'its own compliant state proves its diagnostic setting'
        $text | Should -Not -Match 'mysql-new' -Because 'the initiative has not evaluated it'
        $index = Get-Content (Join-Path $partial.Out '00-index.md') -Raw
        $index | Should -Match 'because the ATMO-MXDR initiative has no policy state for it yet, so nothing proves its diagnostic setting: mysql-new \(resource group rg-db\)\.'
        Remove-PackResult $partial.Pack 'DR.6-COVERAGE'
        $null = & $generator -EvidencePath $partial.Pack
        Get-Content (Join-Path $partial.Out 'CR-10-diagnostic-remediation.txt') -Raw | Should -Match '- mysql-billing, ' -Because 'the coverage list is not needed to prove a server'
        # With nothing else to change, an unevaluated server keeps the state open.
        Set-PackResult $partial.Pack 'DR.6-NONCOMPLIANT' @()
        Set-PackResult $partial.Pack 'DR.6-INITIATIVE' @(@{ DefinitionName = 'ATMO-MXDR-KV-TOSENT'; Resources = 8; Compliant = 8; NonCompliant = 0 })
        Set-PackResult $partial.Pack 'DR.6-MYSQLAUDIT' @((Get-Content (Join-Path $PSScriptRoot 'fixtures/offline-pack/mysql-audit/mixed.json') -Raw | ConvertFrom-Json).MySqlAudit | Where-Object Name -eq 'mysql-new')
        $null = & $generator -EvidencePath $partial.Pack
        Test-Path (Join-Path $partial.Out 'CR-10-diagnostic-remediation.txt') | Should -BeFalse
        Get-Content (Join-Path $partial.Out '00-index.md') -Raw | Should -Match '\| 10 \| .* \| No gaps found, every resource is compliant with the initiative, MySQL servers without an ATMO-MXDR policy state left out, see the notes \|'
    }

    It 'keeps the truncation warning beside the servers it could not read' {
        $pack = Join-Path $TestDrive 'mysql-truncated'
        New-ChangeFixture $pack
        Set-PackResult $pack 'DR.6-INITIATIVE' @(@{ DefinitionName = 'ATMO-MXDR-KV-TOSENT'; Resources = 6; Compliant = 6; NonCompliant = 0 })
        Set-PackResult $pack 'DR.6-COVERAGE' @(@{ subscriptionId = $s1; Resources = 5; Assignments = 1 }, @{ subscriptionId = $s2; Resources = 1; Assignments = 1 })
        $denied = @{ subscriptionId = $s2; resourceGroup = 'rg-fin'; Name = 'mysql-denied'; State = 'Ready'; PolicyState = 'Compliant'; AuditLogEnabled = ''; AuditLogEvents = ''; AuditLogIncludeUsers = ''; AuditLogExcludeUsers = ''; Dynamic = ''; ReadStatus = 'audit_log_enabled: HTTP 403: Forbidden'; ResourceId = "/subscriptions/$s2/resourceGroups/rg-fin/providers/Microsoft.DBforMySQL/flexibleServers/mysql-denied" }
        Set-PackResult $pack 'DR.6-MYSQLAUDIT' @($denied) 'PARTIAL' '0 of 1 MySQL flexible servers read: audit_log_enabled ON in 0, not ON in 0. Not read: mysql-denied: audit_log_enabled: HTTP 403: Forbidden Resource Graph flagged the result as truncated.'
        $null = & $generator -EvidencePath $pack
        $index = Get-Content (Join-Path $pack '05-change-requests/00-index.md') -Raw
        $index | Should -Match 'could not read its audit parameters: mysql-denied \(resource group rg-fin\)\.'
        $index | Should -Match '- DR\.6-MYSQLAUDIT is partial because Resource Graph flagged the server list as truncated, so Resource Graph may have returned only part of the server list' -Because 'servers the truncated list left out are named by no row'
        $index | Should -Match '\| 10 \| .* \| No gaps found, every resource is compliant with the initiative, the MySQL audit parameters of some servers were not read, see the notes, partial collection scope \(DR\.6-MYSQLAUDIT\), see the notes \|'
    }

    It 'never reads a MySQL read that is missing, failed or partial as no gaps' {
        # The base fixture counts no MySQL server in P0.5, so a pack without the read has nothing to say about MySQL.
        $none = Join-Path $TestDrive 'mysql-none'
        New-ChangeFixture $none
        Set-PackResult $none 'DR.6-INITIATIVE' @(@{ DefinitionName = 'ATMO-MXDR-KV-TOSENT'; Resources = 6; Compliant = 6; NonCompliant = 0 })
        Set-PackResult $none 'DR.6-COVERAGE' @(@{ subscriptionId = $s1; Resources = 5; Assignments = 1 }, @{ subscriptionId = $s2; Resources = 1; Assignments = 1 })
        $null = & $generator -EvidencePath $none
        $index = Get-Content (Join-Path $none '05-change-requests/00-index.md') -Raw
        $index | Should -Match '\| 10 \| .* \| No gaps found, every resource is compliant with the initiative \|'
        $index | Should -Not -Match 'DR\.6-MYSQLAUDIT'
        # P0.5 counts a MySQL server, so the missing read needs recollection.
        Set-PackResult $none 'P0.5' @(@{ subscriptionId = $s1; ResourceType = 'microsoft.keyvault/vaults'; Resources = 4 }, @{ subscriptionId = $s2; ResourceType = 'microsoft.dbformysql/flexibleservers'; Resources = 1 })
        $null = & $generator -EvidencePath $none
        $index = Get-Content (Join-Path $none '05-change-requests/00-index.md') -Raw
        $index | Should -Match '\| 10 \| .* \| No gaps found, every resource is compliant with the initiative, the MySQL audit parameters need recollection with CyberSOC collector 1\.15\.0 or later \|'
        $index | Should -Match '- DR\.6-MYSQLAUDIT is not in this pack, so CR-10 does not set the MySQL flexible server audit parameters, and a server with the diagnostic setting writes no audit rows while audit_log_enabled is OFF\. Recollect with CyberSOC collector 1\.15\.0 or later\.'
        Set-PackResult $none 'DR.6-MYSQLAUDIT' @() 'FAILED' 'Resource Graph throttled'
        $null = & $generator -EvidencePath $none
        $index = Get-Content (Join-Path $none '05-change-requests/00-index.md') -Raw
        $index | Should -Match '\| 10 \| .* \| No gaps found, every resource is compliant with the initiative, the MySQL audit parameters were not read, see the notes \|'
        $index | Should -Match '- DR\.6-MYSQLAUDIT reads FAILED, so CR-10 does not set the MySQL flexible server audit parameters'
        # Every server read is set as the baseline sets it, but Resource Graph truncated the list.
        $set = @{ subscriptionId = $s2; resourceGroup = 'rg-fin'; Name = 'mysql-ledger'; State = 'Ready'; PolicyState = 'Compliant'; PendingRestart = 'No'; AuditLogEnabled = 'ON'; AuditLogEvents = 'CONNECTION,ADMIN,DDL,DCL'; Dynamic = 'Yes'; ReadStatus = 'OK'; ResourceId = "/subscriptions/$s2/resourceGroups/rg-fin/providers/Microsoft.DBforMySQL/flexibleServers/mysql-ledger" }
        Set-PackResult $none 'DR.6-MYSQLAUDIT' @($set) 'PARTIAL'
        $null = & $generator -EvidencePath $none
        $index = Get-Content (Join-Path $none '05-change-requests/00-index.md') -Raw
        $index | Should -Match '\| 10 \| .* \| No gaps found, every resource is compliant with the initiative, partial collection scope \(DR\.6-MYSQLAUDIT\), see the notes \|'
        $index | Should -Match '- DR\.6-MYSQLAUDIT is partial although it names no server it could not read, so Resource Graph may have returned only part of the server list'
        # A server not read leaves the state open too.
        Set-PackResult $none 'DR.6-MYSQLAUDIT' @($set, @{ subscriptionId = $s2; resourceGroup = 'rg-fin'; Name = 'mysql-denied'; State = 'Ready'; PolicyState = 'Compliant'; AuditLogEnabled = ''; AuditLogEvents = ''; Dynamic = ''; ReadStatus = 'audit_log_enabled: HTTP 403: Forbidden'; ResourceId = "/subscriptions/$s2/resourceGroups/rg-fin/providers/Microsoft.DBforMySQL/flexibleServers/mysql-denied" }) 'PARTIAL'
        $null = & $generator -EvidencePath $none
        Get-Content (Join-Path $none '05-change-requests/00-index.md') -Raw | Should -Match '\| 10 \| .* \| No gaps found, every resource is compliant with the initiative, the MySQL audit parameters of some servers were not read, see the notes \|'
        # A server set as the baseline sets it but with a user filter still names the filter, so it never reads as every user audited.
        $filteredRow = @{} + $set; $filteredRow.AuditLogExcludeUsers = 'svc_batch'
        Set-PackResult $none 'DR.6-MYSQLAUDIT' @($filteredRow)
        $null = & $generator -EvidencePath $none
        $index = Get-Content (Join-Path $none '05-change-requests/00-index.md') -Raw
        $index | Should -Match '\| 10 \| .* \| No gaps found, every resource is compliant with the initiative, MySQL audit user filters to confirm, see the notes \|'
        $index | Should -Match '- 1 MySQL flexible server audits only some MySQL users, through audit_log_include_users or audit_log_exclude_users: mysql-ledger \(resource group rg-fin\), audit_log_exclude_users svc_batch\.'
        # Read in full, with every server set as the baseline sets it.
        Set-PackResult $none 'DR.6-MYSQLAUDIT' @($set)
        $null = & $generator -EvidencePath $none
        Get-Content (Join-Path $none '05-change-requests/00-index.md') -Raw | Should -Match '\| 10 \| .* \| No gaps found, every resource is compliant with the initiative \|'
        Test-Path (Join-Path $none '05-change-requests/CR-10-diagnostic-remediation.txt') | Should -BeFalse
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

Describe 'Licensing check and capability gate (collector 1.11.0)' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '../report/Get-CyberSocLicensing.ps1')
        # A licensing scenario from tests/fixtures/offline-pack/licensing written into a pack, as the collector writes it.
        function Add-LicensingScenario([string]$Path, [string]$Name) {
            $sc = Get-Content (Join-Path $PSScriptRoot "fixtures/offline-pack/licensing/$Name.json") -Raw | ConvertFrom-Json
            foreach ($p in $sc.Results.PSObject.Properties) { Set-PackResult $Path $p.Name @($p.Value.Rows) -Status $p.Value.Status -Detail $p.Value.Detail }
            $sc
        }
        function Get-Index([string]$Pack) { Get-Content (Join-Path $Pack '05-change-requests/00-index.md') -Raw }
        function Get-LicensingSection([string]$Index) { ($Index -split '(?m)^## ')[1..9] | Where-Object { $_ -like 'Licensing*' } | Select-Object -First 1 }
    }

    It 'gates on Not licensed, keeps Unknown and Partly licensed with what to confirm, and reads a capability it does not hold as Unknown' {
        $matrix = @(
            [pscustomobject]@{ Kind = 'Capability'; Capability = 'EntraIdP1'; Name = 'Microsoft Entra ID P1'; State = 'Licensed'; Detail = 'In SPE_E3.' }
            [pscustomobject]@{ Kind = 'Capability'; Capability = 'MdoP1'; Name = 'Defender for Office 365 Plan 1'; State = 'Not licensed'; Detail = 'No license in the tenant carries the service plan.' }
            [pscustomobject]@{ Kind = 'Capability'; Capability = 'IntuneP1'; Name = 'Microsoft Intune Plan 1'; State = 'Unknown'; Detail = 'The licenses could not be read in full.' }
            [pscustomobject]@{ Kind = 'Capability'; Capability = 'MdeServers'; Name = 'Defender for Endpoint on servers'; State = 'Partly licensed'; Detail = '1 without a server license.' })
        (Get-CyberSocCapabilityGate -Matrix $matrix -Requires @('EntraIdP1')).Write | Should -BeTrue
        $g = Get-CyberSocCapabilityGate -Matrix $matrix -Requires @('EntraIdP1', 'MdoP1', 'IntuneP1', 'MdeServers', 'NotAKey')
        $g.Write | Should -BeFalse
        @($g.Blocked.Key) | Should -Be @('MdoP1')
        @($g.Unknown.Key) | Should -Be @('IntuneP1', 'NotAKey') -Because 'a capability the matrix does not hold is never read as licensed or not licensed'
        @($g.Partly.Key) | Should -Be @('MdeServers')
        (Get-CyberSocCapabilityGate -Matrix $matrix -Requires @()).Write | Should -BeTrue
    }

    It 'says in the index that a pack collected before the licensing check reads Unknown, and asks for the Licenses page reading' {
        $pack = Join-Path $TestDrive 'lic-old'
        New-ChangeFixture $pack
        Invoke-WithWindowsPowerShellJson { $null = & $generator -EvidencePath $pack }
        $section = Get-LicensingSection (Get-Index $pack)
        $section | Should -Match 'collected before the licensing check, so every capability reads Unknown\. Recollect with CyberSOC collector 1\.11\.0 or later'
        $section | Should -Match 'Settings > Endpoints > Licenses .*-DefenderEndpointPlan Plan1, Plan2, Business or Mixed'
        $section | Should -Not -Match '\| Capability \|'
        Test-Path (Join-Path $pack '05-change-requests/CR-16-management-ports.txt') | Should -Be (Test-Path (Join-Path $pack 'results/NB.2-DETAIL.json'))
    }

    It 'lists the plan, the devices and every capability with its seats and the change requests that depend on it' {
        $pack = Join-Path $TestDrive 'lic-plan2'
        New-ChangeFixture $pack
        $null = Add-LicensingScenario $pack 'servers-without-defender-for-servers'
        Invoke-WithWindowsPowerShellJson { $null = & $generator -EvidencePath $pack }
        $section = Get-LicensingSection (Get-Index $pack)
        $section | Should -Match 'Defender for Endpoint plan: Plan 2, from the API reads\. Licenses: Plan 2 licensed'
        $section | Should -Match '- Onboarded servers without a server license: 1\. Named in LIC\.5-SERVERS: vm-sql01\.'
        $section | Should -Match '- Client devices tagged License MDE P1: 0\.'
        $section | Should -Match '\| Microsoft Entra ID P1, for Conditional Access \| Licensed \| 250 \| 231 \| None yet \| In SPE_E5'
        $section | Should -Match '\| Defender for Servers Plan 2 \| Partly licensed \|  \|  \| CR-16 \(no gate\) \| On in 1 of 2 subscriptions\. Off in a0b1c2d3'
        $section | Should -Match '\| Defender for Endpoint Plan 2 or Defender for Servers, the vulnerability and configuration data behind EW\.3, EW\.4 and EW\.5 \| Partly licensed \|  \|  \| EW\.3, EW\.4 and EW\.5 evidence \|'
        $section | Should -Match '\| Defender for Endpoint on servers, a server license for each onboarded server \| Partly licensed \|'
    }

    It 'takes -DefenderEndpointPlan over the reading the collection recorded, and names where the API reads disagree' {
        $pack = Join-Path $TestDrive 'lic-reading'
        New-ChangeFixture $pack
        $null = Add-LicensingScenario $pack 'plan2'
        $params = Get-Content (Join-Path $pack '00-parameters.json') -Raw | ConvertFrom-Json
        $params | Add-Member -NotePropertyName Licensing -NotePropertyValue ([pscustomobject]@{ DefenderEndpointPlan = 'Plan2' })
        $params | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $pack '00-parameters.json')
        Invoke-WithWindowsPowerShellJson { $null = & $generator -EvidencePath $pack }
        $section = Get-LicensingSection (Get-Index $pack)
        $section | Should -Match 'Defender for Endpoint plan: Plan 2, from the Licenses page reading\. Read on the Licenses page \(Settings > Endpoints > Licenses\) and passed as -DefenderEndpointPlan Plan2\.'
        $section | Should -Not -Match 'No API reads the Licenses page' -Because 'a reading is recorded'
        Invoke-WithWindowsPowerShellJson { $null = & $generator -EvidencePath $pack -DefenderEndpointPlan Plan1 }
        $section = Get-LicensingSection (Get-Index $pack)
        $section | Should -Match 'Defender for Endpoint plan: Plan 1, from the Licenses page reading\..*The reading and the API reads disagree: the API reads show Plan 2\.'
        { & $generator -EvidencePath $pack -DefenderEndpointPlan 'E5' } | Should -Throw
    }

    It 'writes no change request whose capability reads Not licensed, and keeps one reading Unknown with a note to confirm it' {
        # No change request in CR-01 to CR-19 requires a license yet, so a copy of the generator gives CR-02 a requirement,
        # which exercises the gate in the generator loop itself. The fixtures here have no Defender for Office 365.
        $copy = Join-Path $TestDrive 'gate-tool'
        New-Item -ItemType Directory -Path (Join-Path $copy 'report') -Force | Out-Null
        Copy-Item (Join-Path $PSScriptRoot '../report/Read-CyberSocPackResult.ps1'), (Join-Path $PSScriptRoot '../report/Get-CyberSocLicensing.ps1'), (Join-Path $PSScriptRoot '../report/Get-CyberSocEmergencyAccess.ps1') (Join-Path $copy 'report')
        $text = Get-Content $generator -Raw
        $entry = "Change = 'Secure transfer required on storage accounts'; Sources = @('DP.1-DETAIL')"
        $text.Contains($entry) | Should -BeTrue
        Set-Content (Join-Path $copy 'New-CyberSocChangeRequests.ps1') $text.Replace($entry, "$entry; Requires = @('MdoP1')") -NoNewline
        $gated = Join-Path $copy 'New-CyberSocChangeRequests.ps1'

        $pack = Join-Path $TestDrive 'lic-gate-blocked'
        New-ChangeFixture $pack
        $null = Add-LicensingScenario $pack 'servers-without-defender-for-servers'
        $lic = Get-Content (Join-Path $pack 'results/LIC.1-SKUS.json') -Raw | ConvertFrom-Json
        foreach ($sku in @($lic)) { $sku.ServicePlans = @($sku.ServicePlans | Where-Object { $_.ServicePlanName -notin 'ATP_ENTERPRISE', 'THREAT_INTELLIGENCE' }) }
        Set-PackResult $pack 'LIC.1-SKUS' @($lic)
        Invoke-WithWindowsPowerShellJson { $null = & $gated -EvidencePath $pack }
        Test-Path (Join-Path $pack '05-change-requests/CR-02-storage-secure-transfer.txt') | Should -BeFalse
        Test-Path (Join-Path $pack '05-change-requests/CR-02-storage-secure-transfer.email.txt') | Should -BeFalse
        $index = Get-Index $pack
        $index | Should -Match '\| 02 \| Secure transfer required on storage accounts \|  \| Not written, needs Defender for Office 365 Plan 1, which reads Not licensed \|  \|'
        $index | Should -Match 'CR-02 is not written because Defender for Office 365 Plan 1 reads Not licensed\. No license in the tenant carries the service plan\.'
        $index | Should -Match '\| Defender for Office 365 Plan 1 \| Not licensed \|  \|  \| CR-02 \|'
        @(Import-Csv (Join-Path $pack '05-change-requests/change-requests.csv') | Where-Object CR -eq 'CR-02').Count | Should -Be 0
        Test-Path (Join-Path $pack '05-change-requests/CR-03-storage-minimum-tls.txt') | Should -BeTrue -Because 'a change request with no requirement is unaffected'

        $pack = Join-Path $TestDrive 'lic-gate-unknown'
        New-ChangeFixture $pack
        $null = Add-LicensingScenario $pack 'failed-read'
        Invoke-WithWindowsPowerShellJson { $null = & $gated -EvidencePath $pack }
        Test-Path (Join-Path $pack '05-change-requests/CR-02-storage-secure-transfer.email.txt') | Should -BeTrue -Because 'a failed read is Unknown, never Not licensed'
        $index = Get-Index $pack
        $index | Should -Match '\| 02 \| Secure transfer required on storage accounts \| \d+ \| Change request and client email, confirm the license before sending \|'
        $index | Should -Match 'Confirm Defender for Office 365 Plan 1 before sending CR-02: the licensing check could not establish it\. The licenses could not be read in full \(LIC\.1-SKUS UNAVAILABLE\)'

        # An older pack has no licensing reads, so the gate keeps the change request and asks to confirm.
        $pack = Join-Path $TestDrive 'lic-gate-old'
        New-ChangeFixture $pack
        Invoke-WithWindowsPowerShellJson { $null = & $gated -EvidencePath $pack }
        (Get-Index $pack) | Should -Match 'Confirm Defender for Office 365 Plan 1 before sending CR-02: .*LIC\.1-SKUS not collected, recollect with CyberSOC collector 1\.11\.0 or later'
    }
}

Describe 'Emergency access accounts (collector 1.12.0)' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '../report/Get-CyberSocEmergencyAccess.ps1')
        # A scenario from tests/fixtures/offline-pack/emergency-access written into a pack as the collector writes it: the
        # rows from the shared match, with the status the collector tests check it gives them. A string answer is a failed read.
        function Add-EaScenario([string]$Path, [string]$Name) {
            $sc = Get-Content (Join-Path $PSScriptRoot "fixtures/offline-pack/emergency-access/$Name.json") -Raw | ConvertFrom-Json
            $read = { param($v) if ($v -is [string]) { $null } else { @($v) } }
            $members = @{}
            foreach ($p in @($sc.Graph.Members.PSObject.Properties)) { $members[$p.Name] = & $read $p.Value }
            $set = ConvertTo-CyberSocEmergencyAccessRows -Users (& $read $sc.Graph.Users) -Groups (& $read $sc.Graph.Groups) -Members $members
            $bad = { param($s) $s -notin 'OK', 'PARTIAL', 'EMPTY' }
            $accStatus = $sc.Expect.'IA.16-ACCOUNTS'.Status; $grpStatus = $sc.Expect.'IA.16-GROUPS'.Status
            Set-PackResult $Path 'IA.16-ACCOUNTS' $(if (& $bad $accStatus) { @() } else { @($set.Accounts) }) -Status $accStatus -Detail $(if (& $bad $accStatus) { 'Not a zero: the Graph token cannot read user accounts. Needs User.Read.All.' } else { '' })
            Set-PackResult $Path 'IA.16-GROUPS' $(if (& $bad $grpStatus) { @() } else { @($set.Groups) }) -Status $grpStatus -Detail $(if (& $bad $grpStatus) { 'The groups could not be read in full. HTTP 500: Internal Server Error' } else { '' })
            $sc
        }
        function Get-Index([string]$Pack) { Get-Content (Join-Path $Pack '05-change-requests/00-index.md') -Raw }
        function Get-EaSection([string]$Index) { ($Index -split '(?m)^## ') | Where-Object { $_ -like 'Emergency access accounts*' } | Select-Object -First 1 }
        function Read-EaPack([string]$Pack) {
            $manifest = @(Import-Csv (Join-Path $Pack '00-manifest.csv'))
            . (Join-Path $PSScriptRoot '../report/Read-CyberSocPackResult.ps1')
            Initialize-CyberSocPackReader -Pack $Pack -Manifest $manifest
            Get-CyberSocEmergencyAccess -Read { param([string]$Id) $s = Get-Status $Id; $ok = $s -in 'OK', 'EMPTY', 'PARTIAL'; @{ Status = $s; Rows = @(if ($ok) { Get-Rows $Id }); Unreadable = ($ok -and (Test-Unreadable $Id)) } }
        }
        # No change request in CR-01 to CR-19 changes Conditional Access yet, so a copy of the generator marks CR-02 as one,
        # which exercises the emergency access gate in the generator loop itself.
        $copy = Join-Path $TestDrive 'ea-gate-tool'
        New-Item -ItemType Directory -Path (Join-Path $copy 'report') -Force | Out-Null
        Copy-Item (Join-Path $PSScriptRoot '../report/*.ps1') (Join-Path $copy 'report')
        $text = Get-Content $generator -Raw
        $entry = "Change = 'Secure transfer required on storage accounts'; Sources = @('DP.1-DETAIL')"
        $text.Contains($entry) | Should -BeTrue
        Set-Content (Join-Path $copy 'New-CyberSocChangeRequests.ps1') $text.Replace($entry, "$entry; EmergencyAccess = `$true") -NoNewline
        $script:eaGated = Join-Path $copy 'New-CyberSocChangeRequests.ps1'
    }

    It 'keeps the match in one place: Atmosera in the UPN or the group name, anywhere and in any case' {
        foreach ($upn in 'breakglass-atmosera01@contoso.onmicrosoft.com', 'jordan.lee_atmosera.com#EXT#@contoso.onmicrosoft.com', 'SOC.ATMOSERA.Analyst@contoso.onmicrosoft.com') { Test-CyberSocEmergencyAccessUpn $upn | Should -BeTrue -Because $upn }
        foreach ($upn in 'dana.finance@contoso.onmicrosoft.com', 'atmo.sera@contoso.onmicrosoft.com', '') { Test-CyberSocEmergencyAccessUpn $upn | Should -BeFalse -Because $upn }
        Test-CyberSocEmergencyAccessGroup 'SOC-atmosera-Tier0' | Should -BeTrue
        Test-CyberSocEmergencyAccessGroup 'IT Admins' | Should -BeFalse
        (Get-Content (Join-Path $PSScriptRoot '../Get-CyberSocEvidence.ps1') -Raw) | Should -Not -Match "(?i)'\*?atmosera\*?'" -Because 'the collector matches through the shared rule only'
    }

    It 'excludes each Atmosera group and each account matched by its UPN, and protects every one of them from removal' {
        $pack = Join-Path $TestDrive 'ea-complete'
        New-ChangeFixture $pack
        $sc = Add-EaScenario $pack 'complete'
        $ea = Read-EaPack $pack
        $ea.Ready | Should -BeTrue
        @($ea.ExcludeGroups) | Should -Be @($sc.Expect.ExcludeGroups)
        @($ea.ExcludeUsers) | Should -Be @($sc.Expect.ExcludeUsers | Sort-Object) -Because 'an account matched by its UPN stays excluded on its own even if it is taken out of its Atmosera group'
        @($ea.Review | ForEach-Object DisplayName) | Should -Be @('ATMOSERA Support (synced)', 'SOC-atmosera-Tier0')
        foreach ($a in @($ea.Accounts)) { Test-CyberSocEmergencyAccessId $ea $a.PrincipalId.ToUpperInvariant() | Should -BeTrue -Because $a.UserPrincipalName }
        foreach ($g in @($ea.Groups)) { Test-CyberSocEmergencyAccessId $ea $g.GroupId | Should -BeTrue -Because $g.DisplayName }
        $dana = @($sc.Graph.Users | Where-Object userPrincipalName -like 'dana*')[0].id
        Test-CyberSocEmergencyAccessId $ea $dana | Should -BeFalse
        Test-CyberSocEmergencyAccessId $ea '' | Should -BeFalse
    }

    It 'lists the groups and accounts excluded in the index, and names the dynamic and synced groups' {
        $pack = Join-Path $TestDrive 'ea-index'
        New-ChangeFixture $pack
        $sc = Add-EaScenario $pack 'complete'
        Invoke-WithWindowsPowerShellJson { $null = & $generator -EvidencePath $pack }
        $section = Get-EaSection (Get-Index $pack)
        $section | Should -Match 'every account with Atmosera in its UPN and every member of an Atmosera group, a group whose display name contains Atmosera'
        $section | Should -Match 'no change removes an existing exclusion of any of them'
        $section | Should -Match 'No change request in this build changes Conditional Access yet, and one that does is written only when the read is complete and found at least one account\.'
        $section | Should -Match ('\| Atmosera Emergency Access \| 3 \| Assigned \| {0} \|' -f @($sc.Graph.Groups)[0].id)
        $section | Should -Match '\| SOC-atmosera-Tier0 \| 1 \| Dynamic \|'
        $section | Should -Match '\| breakglass-atmosera01@contoso\.onmicrosoft\.com \| Emergency Access 01 \| Member \| Yes \| UPN \|  \| the account \|'
        $section | Should -Match '\| jordan\.lee_atmosera\.com#EXT#@contoso\.onmicrosoft\.com \| Jordan Lee \(Atmosera\) \| Guest \| Yes \| UPN \|  \| the account \|'
        $section | Should -Match '\| SOC\.ATMOSERA\.Analyst@contoso\.onmicrosoft\.com \| SOC Analyst \| Member \| No \| UPN and group \| Atmosera Emergency Access \| the account and its group \|'
        $section | Should -Match '\| tier0\.admin@contoso\.onmicrosoft\.com \| Tier 0 Admin \| Member \| Yes \| Group \| Atmosera Emergency Access, SOC-atmosera-Tier0 \| its group \|'
        $section | Should -Match '- SOC-atmosera-Tier0 has dynamic membership, so its rule adds and removes members, and an account it drops loses the exclusion\.'
        $section | Should -Match '- ATMOSERA Support \(synced\) has on-premises synced membership, so its members are managed in Active Directory'
        $section | Should -Match '- An account Atmosera uses whose UPN does not contain Atmosera is covered only when it sits in an Atmosera group\.'
        $section | Should -Not -Match 'dana\.finance|kai\.helpdesk|IT Admins|Platform Ops'
        $section | Should -Not -Match 'No Conditional Access change can be written'
    }

    It 'writes no Conditional Access change when the read failed, is partial, found nothing, or was not collected, and says why' {
        foreach ($case in @(
                @{ Name = 'failed-read'; State = 'Not written, the emergency access read is not complete \(IA\.16-ACCOUNTS UNAVAILABLE, IA\.16-GROUPS FAILED\)' }
                @{ Name = 'members-unread'; State = 'Not written, the emergency access read is not complete \(IA\.16-ACCOUNTS PARTIAL, IA\.16-GROUPS PARTIAL\)' }
                @{ Name = 'no-match'; State = 'Not written, the emergency access read found no account with Atmosera in its UPN or in an Atmosera group' }
                @{ Name = ''; State = 'Needs recollection with CyberSOC collector 1\.12\.0 or later' })) {
            $pack = Join-Path $TestDrive "ea-gate-$($case.Name)"
            New-ChangeFixture $pack
            if ($case.Name) { $null = Add-EaScenario $pack $case.Name } else { foreach ($id in 'IA.16-ACCOUNTS', 'IA.16-GROUPS') { Remove-PackResult $pack $id } }
            (Read-EaPack $pack).Ready | Should -BeFalse -Because $case.Name
            Invoke-WithWindowsPowerShellJson { $null = & $script:eaGated -EvidencePath $pack }
            Test-Path (Join-Path $pack '05-change-requests/CR-02-storage-secure-transfer.txt') | Should -BeFalse -Because $case.Name
            Test-Path (Join-Path $pack '05-change-requests/CR-02-storage-secure-transfer.email.txt') | Should -BeFalse -Because $case.Name
            $index = Get-Index $pack
            $index | Should -Match ('\| 02 \| Secure transfer required on storage accounts \|  \| {0} \|  \|' -f $case.State) -Because $case.Name
            $index | Should -Match 'CR-02 is not written because .*A Conditional Access change is written only with the emergency access accounts it excludes\.' -Because $case.Name
            Test-Path (Join-Path $pack '05-change-requests/CR-03-storage-minimum-tls.txt') | Should -BeTrue -Because 'a change request that is not a Conditional Access change is unaffected'
            $section = Get-EaSection $index
            if ($case.Name) { $section | Should -Match 'No Conditional Access change can be written: ' -Because $case.Name }
            else { $section | Should -Match 'The pack was collected before the emergency access read, so no Conditional Access change can be written\. Recollect with CyberSOC collector 1\.12\.0 or later\. CR-02 is written only with the emergency access accounts\.' }
        }
        $index | Should -Not -Match '\| Atmosera group \|'
        $pack = Join-Path $TestDrive 'ea-gate-ok'
        New-ChangeFixture $pack
        $null = Add-EaScenario $pack 'complete'
        Invoke-WithWindowsPowerShellJson { $null = & $script:eaGated -EvidencePath $pack }
        Test-Path (Join-Path $pack '05-change-requests/CR-02-storage-secure-transfer.email.txt') | Should -BeTrue -Because 'a complete read with accounts lets the change through'
        (Get-EaSection (Get-Index $pack)) | Should -Match 'CR-02 is written only when the read is complete'
    }

    Context 'CR-19 leaves the emergency access accounts out' {
        BeforeAll {
            # The disabled accounts of the cr19-disabled scenario added to the full fixture's IA.15 results, with their roles:
            # one matched by its UPN, a guest matched by its #EXT# UPN, one in a plain group nested in an Atmosera group, one in
            # prodAtmoseraOps, whose name holds the word inside another word, and one that matches nothing. Riley also holds
            # roles through platform-operators, as a member of it.
            $script:cr19 = (Get-Content (Join-Path $PSScriptRoot 'fixtures/offline-pack/emergency-access/cr19-disabled.json') -Raw | ConvertFrom-Json).Cr19
            foreach ($u in @($cr19.Disabled)) { $people[$u.PrincipalId] = @($u.DisplayName, $u.UserPrincipalName, $false) }
            function Add-Cr19Accounts([string]$Path, [string[]]$Only) {
                $keep = { param($id) -not $Only -or $id -in $Only }
                $groups = @{ ops = $opsGroup }
                $old = { param($Id) @(if (-not $Only) { Get-Content (Join-Path $Path "results/$Id.json") -Raw | ConvertFrom-Json }) }
                Set-PackResult $Path 'IA.15-DISABLED' (@(& $old 'IA.15-DISABLED') + @($cr19.Disabled | Where-Object { & $keep $_.PrincipalId }))
                Set-PackResult $Path 'IA.15-RBAC' (@(& $old 'IA.15-RBAC') + @($cr19.Azure | Where-Object { & $keep $_.Principal } | ForEach-Object {
                            & $azureRole ($_.Scope.Replace('{s1}', $s1).Replace('{s2}', $s2)) $_.Role $roleIds[$_.RoleKey] $_.Principal $(if ($_.Group) { $groups[$_.Group] }) }))
                Set-PackResult $Path 'IA.15-ENTRA' (@(& $old 'IA.15-ENTRA') + @($cr19.Entra | Where-Object { & $keep $_.Principal } | ForEach-Object {
                            & $entraRole $_.Role $roleIds[$_.RoleKey] $_.Type $_.Principal $(if ($_.Group) { $groups[$_.Group] }) }))
            }
            $script:cr19Files = 'CR-19-disabled-account-roles.txt', 'CR-19-disabled-account-roles.email.txt', 'CR-19-disabled-account-roles.email.csv'
            $script:byUpn = 'breakglass-atmosera02|Emergency Access 02|sam\.rivera|Sam Rivera'
            $script:byGroup = 'riley\.night|Riley Night|jamie\.ops|Jamie Ops'
        }

        It 'leaves out every disabled emergency access account, matched by its UPN or through a nested Atmosera group, and still removes the roles of one that matches nothing' {
            $pack = Join-Path $TestDrive 'cr19-ea-complete'
            New-ChangeFixture $pack
            $null = Add-EaScenario $pack 'cr19-disabled'
            Add-Cr19Accounts $pack
            Invoke-WithWindowsPowerShellJson { $null = & $generator -EvidencePath $pack -ClientContact 'Dana' -SenderName 'Scott Example' }
            $out = Join-Path $pack '05-change-requests'
            foreach ($f in $cr19Files) {
                $t = Get-Content (Join-Path $out $f) -Raw
                $t | Should -Not -Match "$byUpn|$byGroup" -Because "$f leaves every emergency access account out"
                if ($f -notlike '*.email.txt') { $t | Should -Match 'casey\.former' -Because "$f still lists the disabled account that matches nothing" }
            }
            $rows = @(Import-Csv (Join-Path $out 'change-requests.csv') | Where-Object CR -eq 'CR-19')
            @($rows | Where-Object { "$($_.Resource) $($_.CurrentSetting) $($_.ResourceId)" -match "$byUpn|$byGroup|$($cr19.Disabled[2].PrincipalId)" }).Count | Should -Be 0 -Because 'Riley is not removed from platform-operators either'
            @($rows | Where-Object Resource -match 'casey\.former').Count | Should -Be 2
            $index = Get-Index $pack
            $index | Should -Match '\| 19 \| Roles removed from disabled accounts \| 12 \| Change request and client email \| CR-19-disabled-account-roles\.txt, '
            $index | Should -Match ('- CR-19 leaves out 4 disabled emergency access accounts, so none of their roles is removed and they are not removed from any group: Emergency Access 02 \(breakglass-atmosera02@contoso\.onmicrosoft\.com\), Atmosera in its UPN / Jamie Ops \(jamie\.ops@contoso\.onmicrosoft\.com\), a member of the Atmosera group prodAtmoseraOps / Riley Night \(riley\.night@contoso\.onmicrosoft\.com\), a member of the Atmosera group Atmosera Responders / Sam Rivera \(Atmosera\) \(sam\.rivera_atmosera\.com#EXT#@contoso\.onmicrosoft\.com\), Atmosera in its UPN\. A disabled emergency access account cannot sign in when it is needed, so confirm with the client that each one is meant to be disabled\.')
            $index | Should -Not -Match 'Global Administrator, Privileged Role Administrator|CR-19 is not written' -Because 'the read is complete, and the only Global Administrator is left out'
            $index | Should -Not -Match 'removes each one from the group it sits in: [^\r\n]*Riley'
            $text = Get-Content (Join-Path $out 'CR-19-disabled-account-roles.txt') -Raw
            $email = Get-Content (Join-Path $out 'CR-19-disabled-account-roles.email.txt') -Raw
            Assert-ApprovalEmail $email 'CR-19 with emergency access accounts left out'
            $email | Should -Not -Match '(?i)atmosera|emergency access account|left out of' -Because 'the client email says nothing of the accounts left out'
            $email | Should -Match 'I would like your approval to remove the Azure and Microsoft Entra roles still held by 4 disabled accounts in your tenant'
        }

        It 'writes no CR-19 when IA.16 is missing, failed or partial, since an account in an Atmosera group cannot be told apart' {
            foreach ($case in @(
                    @{ Name = 'missing'; State = 'Needs recollection with CyberSOC collector 1\.12\.0 or later'; Why = 'the pack was collected before the emergency access read' }
                    @{ Name = 'failed-read'; State = 'Not written, the emergency access read is not complete \(IA\.16-ACCOUNTS UNAVAILABLE, IA\.16-GROUPS FAILED\)'; Why = 'the emergency access read is not complete \(IA\.16-ACCOUNTS UNAVAILABLE, IA\.16-GROUPS FAILED\)' }
                    @{ Name = 'members-unread'; State = 'Not written, the emergency access read is not complete \(IA\.16-ACCOUNTS PARTIAL, IA\.16-GROUPS PARTIAL\)'; Why = 'the emergency access read is not complete \(IA\.16-ACCOUNTS PARTIAL, IA\.16-GROUPS PARTIAL\)' })) {
                $pack = Join-Path $TestDrive "cr19-ea-$($case.Name)"
                New-ChangeFixture $pack
                if ($case.Name -eq 'missing') { foreach ($id in 'IA.16-ACCOUNTS', 'IA.16-GROUPS') { Remove-PackResult $pack $id } } else { $null = Add-EaScenario $pack $case.Name }
                Add-Cr19Accounts $pack
                Invoke-WithWindowsPowerShellJson { $null = & $generator -EvidencePath $pack }
                foreach ($f in $cr19Files) { Test-Path (Join-Path $pack "05-change-requests/$f") | Should -BeFalse -Because "$f ($($case.Name))" }
                @(Import-Csv (Join-Path $pack '05-change-requests/change-requests.csv') | Where-Object CR -eq 'CR-19').Count | Should -Be 0 -Because $case.Name
                $index = Get-Index $pack
                $index | Should -Match ('\| 19 \| Roles removed from disabled accounts \|  \| {0} \|  \|' -f $case.State) -Because $case.Name
                $index | Should -Match ('- CR-19 is not written because {0}\. CR-19 leaves out every disabled emergency access account, and without a complete read an account that sits in an Atmosera group cannot be told apart from the others\. Collect again with CyberSOC collector 1\.12\.0 or later' -f $case.Why) -Because $case.Name
                Test-Path (Join-Path $pack '05-change-requests/CR-03-storage-minimum-tls.txt') | Should -BeTrue -Because 'the other change requests are unaffected'
            }
            # With no disabled account there is nothing to leave out, so an older pack still reads as no gaps.
            $pack = Join-Path $TestDrive 'cr19-ea-missing-none-disabled'
            New-ChangeFixture $pack
            foreach ($id in 'IA.16-ACCOUNTS', 'IA.16-GROUPS') { Remove-PackResult $pack $id }
            foreach ($id in 'IA.15-DISABLED', 'IA.15-RBAC', 'IA.15-ENTRA') { Set-PackResult $pack $id @() }
            Invoke-WithWindowsPowerShellJson { $null = & $generator -EvidencePath $pack }
            (Get-Index $pack) | Should -Match '\| 19 \| Roles removed from disabled accounts \|  \| No gaps found \|  \|'
        }

        It 'reads as no gaps for the accounts that remain when every disabled account with roles is an emergency access account' {
            $pack = Join-Path $TestDrive 'cr19-ea-empty'
            New-ChangeFixture $pack
            $null = Add-EaScenario $pack 'cr19-disabled'
            Add-Cr19Accounts $pack -Only @($cr19.Disabled[0..3] | ForEach-Object PrincipalId)
            Invoke-WithWindowsPowerShellJson { $null = & $generator -EvidencePath $pack }
            Test-Path (Join-Path $pack '05-change-requests/CR-19-disabled-account-roles.txt') | Should -BeFalse
            $index = Get-Index $pack
            $index | Should -Match '\| 19 \| Roles removed from disabled accounts \|  \| No gaps found in the disabled accounts that remain, 4 emergency access accounts left out, see the notes \|  \|'
            $index | Should -Match '- CR-19 leaves out 4 disabled emergency access accounts'
            @(Import-Csv (Join-Path $pack '05-change-requests/change-requests.csv') | Where-Object CR -eq 'CR-19').Count | Should -Be 0
        }
    }

    It 'reads an unreadable result file as not complete' {
        $pack = Join-Path $TestDrive 'ea-unreadable'
        New-ChangeFixture $pack
        $null = Add-EaScenario $pack 'complete'
        Set-Content (Join-Path $pack 'results/IA.16-GROUPS.json') ''
        $ea = Read-EaPack $pack 3>$null
        $ea.Ready | Should -BeFalse
        $ea.Why | Should -Be 'the emergency access read is not complete (IA.16-GROUPS unreadable)'
    }
}
