<#
    Licensing check shared by Get-CyberSocEvidence.ps1 (LIC.5-MATRIX), New-CyberSocChangeRequests.ps1 (the
    capability gate and the licensing section of the index) and their tests. Offline: it reads collected results only.

    Inputs, each read through the Read script block the caller passes, which returns @{ Status; Rows; Unreadable;
    Source } for a result ID (Status MISSING when the pack does not hold it):
      LIC.1-SKUS      the tenant's licenses (Graph subscribedSkus), one row per SKU with its service plans
      LIC.2-MACHINES  the Defender for Endpoint device inventory (GET api/machines), one row per device
      LIC.3-TVM       onboarded devices by platform with the devices that have vulnerability management data
      LIC.4-DEVICES   the Microsoft Entra devices (Graph devices), one row per device with its management type
      P0.3            the Defender for Cloud plans of each subscription

    Output: the capability matrix (LIC.5-MATRIX), one row per reading, and the server coverage (LIC.5-SERVERS), one
    row per onboarded server. A read that failed, was refused, is partial or is missing reads Unknown, never Not
    licensed.

    Registering a capability for a change request: give its catalog entry in New-CyberSocChangeRequests.ps1
    Requires = @('<Key>') to gate it (Not licensed stops the change request, Unknown keeps it with a note to confirm
    the license first), or Uses = @('<Key>') to list it in the index without a gate. The keys are those of
    Get-CyberSocCapabilityCatalog below. A new capability adds an entry there with its service plan IDs from
    Microsoft Learn (Product names and service plan identifiers for licensing).
#>

# The tag Defender for Endpoint gives a client device under mixed licensing, set by the administrator or a dynamic rule.
$script:CyberSocPlan1Tag = 'License MDE P1'
# The SKU ID of Microsoft Defender for Endpoint Server (MDATP_Server), the server license sold for Defender for Endpoint.
$script:CyberSocMdeServerSkuId = '509e8ab6-0274-4cda-bcbd-bd164fd562c4'
$script:CyberSocPlanReadings = [ordered]@{ Plan1 = 'Plan 1'; Plan2 = 'Plan 2'; Business = 'Defender for Business'; Mixed = 'Mixed (Plan 1 and Plan 2)' }

function Get-CyberSocCapabilityCatalog {
    # Kind Sku: licensed when an active SKU in LIC.1-SKUS carries one of the service plans. Every ID is from Microsoft
    # Learn, Product names and service plan identifiers for licensing. A bundle carries the plans of the products in
    # it, so the match is on service plan IDs, never on SKU names. A government cloud plan with an ID of its own is listed
    # beside the commercial one, and the plans Learn shows with the commercial ID in government SKUs need nothing more.
    # SkuIds matches a SKU itself, for a license whose service plan other SKUs also carry. Kind Azure: read from the Defender for Cloud plans
    # of each subscription (P0.3). Kind Derived: built from other readings.
    @(
        [ordered]@{ Key = 'EntraIdP1'; Kind = 'Sku'; Name = 'Microsoft Entra ID P1, for Conditional Access'; Plans = @(
                '41781fb2-bc02-4b7c-bd55-b576c07bb09d'   # AAD_PREMIUM
                'eec0eb4f-6444-4f95-aba0-50c24d67f998') } # AAD_PREMIUM_P2, which includes P1
        [ordered]@{ Key = 'EntraIdP2'; Kind = 'Sku'; Name = 'Microsoft Entra ID P2'; Plans = @('eec0eb4f-6444-4f95-aba0-50c24d67f998') }
        [ordered]@{ Key = 'MdePlan1Sku'; Kind = 'Sku'; Name = 'Defender for Endpoint Plan 1 licenses'; Plans = @('292cc034-7b7c-4950-aaf5-943befd3f1d4') }  # MDE_LITE
        # The server SKU carries the same WINDEFATP plan as the user SKUs, so it is left out here and read by its SKU ID.
        [ordered]@{ Key = 'MdePlan2Sku'; Kind = 'Sku'; Name = 'Defender for Endpoint Plan 2 licenses'; Plans = @('871d91ec-ec1a-452b-a83f-bd76c7d770ef'); ExcludeSkuIds = @($script:CyberSocMdeServerSkuId) }  # WINDEFATP
        [ordered]@{ Key = 'MdeBusinessSku'; Kind = 'Sku'; Name = 'Defender for Business licenses'; Plans = @('bfc1bbd9-981b-4f71-9b82-17c35fd0e2a4') }  # MDE_SMB
        # Microsoft Defender for Endpoint Server (MDATP_Server). Learn lists no SKU for Defender for Business servers.
        [ordered]@{ Key = 'MdeServerSku'; Kind = 'Sku'; Name = 'Defender for Endpoint for servers licenses'; Plans = @(); SkuIds = @($script:CyberSocMdeServerSkuId) }
        # Security settings management needs a Defender for Endpoint user license (Plan 1, Plan 2 or Defender for Business),
        # never Defender for Servers alone. The user SKUs also carry Intune_Defender (MDE_SecurityManagement).
        [ordered]@{ Key = 'MdeUserSku'; Kind = 'Sku'; Name = 'Defender for Endpoint user licenses, Plan 1, Plan 2 or Defender for Business'; Plans = @(
                '292cc034-7b7c-4950-aaf5-943befd3f1d4', '871d91ec-ec1a-452b-a83f-bd76c7d770ef', 'bfc1bbd9-981b-4f71-9b82-17c35fd0e2a4'
                '1689aade-3d6a-4bfc-b017-46d2672df5ad'); ExcludeSkuIds = @($script:CyberSocMdeServerSkuId) }
        [ordered]@{ Key = 'TvmPremium'; Kind = 'Sku'; Name = 'Defender Vulnerability Management premium'; Plans = @('36810a13-b903-490a-aa45-afbeb7540832') }  # TVM_PREMIUM_1
        # Office 365 E3 and Microsoft 365 E3 carry ATP_ENTERPRISE from July 1, 2026 (Defender for Office 365 service description).
        [ordered]@{ Key = 'MdoP1'; Kind = 'Sku'; Name = 'Defender for Office 365 Plan 1'; Plans = @(
                'f20fedf3-f3c3-43c3-8267-2bfdd51c0939'   # ATP_ENTERPRISE
                '493ff600-6a2b-4db6-ad37-a7d4eb214516'   # ATP_ENTERPRISE_GOV
                '8e0c0a52-6a6c-4d40-8370-dd62790dcd70'   # THREAT_INTELLIGENCE, Plan 2 includes Plan 1
                '900018f1-0cdb-4ecb-94d4-90281760fdc6') } # THREAT_INTELLIGENCE_GOV
        [ordered]@{ Key = 'MdoP2'; Kind = 'Sku'; Name = 'Defender for Office 365 Plan 2'; Plans = @('8e0c0a52-6a6c-4d40-8370-dd62790dcd70', '900018f1-0cdb-4ecb-94d4-90281760fdc6') }
        [ordered]@{ Key = 'Mdi'; Kind = 'Sku'; Name = 'Defender for Identity'; Plans = @('14ab5db5-e6c4-4b20-b4bc-13e36fd2227f') }  # ATA
        [ordered]@{ Key = 'Mdca'; Kind = 'Sku'; Name = 'Defender for Cloud Apps'; Plans = @('2e2ddb96-6af9-4b1d-a3f0-d6ecfd22edb2') }  # ADALLOM_S_STANDALONE
        [ordered]@{ Key = 'DefenderXdr'; Kind = 'Sku'; Name = 'Microsoft Defender XDR'; Plans = @('bf28f719-7844-4079-9c78-c1307898e192') }  # MTP
        [ordered]@{ Key = 'IntuneP1'; Kind = 'Sku'; Name = 'Microsoft Intune Plan 1'; Plans = @('c1ec4a95-1f05-45b3-a911-aa3fa01094f5', 'd216f254-796f-4dab-bbfa-710686e646b9') }  # INTUNE_A, INTUNE_A_GOV
        [ordered]@{ Key = 'DefenderServers'; Kind = 'Azure'; Name = 'Defender for Servers, Plan 1 or Plan 2'; Plan = 'VirtualMachines'; SubPlan = '' }
        [ordered]@{ Key = 'DefenderServersP2'; Kind = 'Azure'; Name = 'Defender for Servers Plan 2'; Plan = 'VirtualMachines'; SubPlan = 'P2' }
        [ordered]@{ Key = 'DefenderContainers'; Kind = 'Azure'; Name = 'Defender for Containers'; Plan = 'Containers'; SubPlan = '' }
        [ordered]@{ Key = 'MdeServers'; Kind = 'Derived'; Name = 'Defender for Endpoint on servers, a server license for each onboarded server' }
        [ordered]@{ Key = 'MdeVulnerabilityData'; Kind = 'Derived'; Name = 'Defender for Endpoint Plan 2 or Defender for Servers, the vulnerability and configuration data behind EW.3, EW.4 and EW.5' }
        [ordered]@{ Key = 'MdeSecurityManagement'; Kind = 'Derived'; Name = 'Defender for Endpoint security settings management' }
    )
}

function Get-CyberSocLicValue {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { return $Object[$Name] }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { $null } else { $p.Value }
}
function Get-CyberSocLicText($value) { if ($null -eq $value) { '' } else { ([string]$value).Trim() } }
function Get-CyberSocLicNumber($value) { $n = 0.0; if ([double]::TryParse((Get-CyberSocLicText $value), [Globalization.NumberStyles]::Float, [cultureinfo]::InvariantCulture, [ref]$n)) { [int64]$n } else { 0 } }
function Test-CyberSocLicTrue($value) { $v = Get-CyberSocLicText $value; $v -eq '1' -or $v -ieq 'true' }
function Get-CyberSocLicList($value) {
    # A list column reads back as an array from the JSON file, or as JSON text from a CSV.
    if ($null -eq $value) { return @() }
    if ($value -is [string]) {
        $t = $value.Trim()
        if ($t.StartsWith('[')) { try { return @(($t | ConvertFrom-Json) | Where-Object { $null -ne $_ }) } catch { return @() } }
        if ($t) { return @($t) }
        return @()
    }
    @(@($value) | Where-Object { $null -ne $_ })
}
function Format-CyberSocLicCount([int64]$n, [string]$one, [string]$many) { if ($n -eq 1) { "1 $one" } else { "$n $many" } }

function Get-CyberSocDeviceClass {
    # Client, Server or Linux, from the device type Advanced Hunting records or the platform the Defender for Endpoint
    # API records (osPlatform such as Windows11, WindowsServer2022, Linux, macOS). The API records no device type, and a
    # Linux device can be a client or a server, so without a device type it reads Linux and is counted on its own.
    param([string]$OsPlatform, [string]$DeviceType = '')
    if ($DeviceType -ieq 'Server' -or $OsPlatform -match '(?i)server') { return 'Server' }
    if ($DeviceType -imatch '^(Workstation|Mobile|Tablet)$') { return 'Client' }
    if ($OsPlatform -match '(?i)linux|ubuntu|debian|redhat|rhel|centos|suse|sles|oracle|amazon|alma|rocky') { return 'Linux' }
    if ($OsPlatform -match '(?i)^(windows|macos|mac os|ios|ipados|android)') { return 'Client' }
    'Other'
}

function Get-CyberSocReadState {
    # Complete (OK or EMPTY and readable), Partial, or Unknown with the reason, for one result.
    param($Result, [string]$Id)
    $s = Get-CyberSocLicText $Result.Status
    if ($s -eq 'MISSING') { return @{ State = 'Unknown'; Why = $(if ($Id -like 'LIC.*') { "$Id not collected, recollect with CyberSOC collector 1.11.0 or later" } else { "$Id not collected" }) } }
    if ($s -in 'OK', 'EMPTY', 'PARTIAL' -and $Result.Unreadable) { return @{ State = 'Unknown'; Why = "$Id result file unreadable" } }
    if ($s -in 'OK', 'EMPTY') { return @{ State = 'Complete'; Why = '' } }
    if ($s -eq 'PARTIAL') { return @{ State = 'Partial'; Why = "$Id read in part" } }
    @{ State = 'Unknown'; Why = $(if ($s) { "$Id $s" } else { "$Id not read" }) }
}

function Get-CyberSocSkuMatch {
    # Every SKU in LIC.1-SKUS that carries one of the service plans, with whether it is active. A SKU is active while its
    # capabilityStatus reads Enabled or Warning (Warning is the grace period after expiry), and a service plan counts
    # unless its provisioningStatus reads Disabled or Error.
    param($Skus, [string[]]$Plans, [string[]]$SkuIds = @(), [string[]]$ExcludeSkuIds = @())
    $ids = @($Plans | ForEach-Object { $_.ToLowerInvariant() })
    foreach ($sku in @($Skus)) {
        $skuId = (Get-CyberSocLicText (Get-CyberSocLicValue $sku 'SkuId')).ToLowerInvariant()
        if ($skuId -and $skuId -in $ExcludeSkuIds) { continue }
        $found = @(Get-CyberSocLicList (Get-CyberSocLicValue $sku 'ServicePlans') | Where-Object {
                (Get-CyberSocLicText (Get-CyberSocLicValue $_ 'ServicePlanId')).ToLowerInvariant() -in $ids -and
                (Get-CyberSocLicText (Get-CyberSocLicValue $_ 'ProvisioningStatus')) -notin 'Disabled', 'Error' })
        $bySku = $skuId -and $skuId -in $SkuIds
        if (-not $found.Count -and -not $bySku) { continue }
        $status = Get-CyberSocLicText (Get-CyberSocLicValue $sku 'CapabilityStatus')
        [pscustomobject]@{
            Sku = Get-CyberSocLicText (Get-CyberSocLicValue $sku 'SkuPartNumber'); Status = $status; Active = $status -in 'Enabled', 'Warning'
            Plans = @(if ($found.Count) { $found | ForEach-Object { Get-CyberSocLicText (Get-CyberSocLicValue $_ 'ServicePlanName') } } else { 'the SKU itself' })
            Seats = (Get-CyberSocLicNumber (Get-CyberSocLicValue $sku 'Enabled')) + (Get-CyberSocLicNumber (Get-CyberSocLicValue $sku 'Warning'))
            Assigned = Get-CyberSocLicNumber (Get-CyberSocLicValue $sku 'Consumed')
        }
    }
}

function New-CyberSocMatrixRow {
    param([string]$Kind, [string]$Capability, [string]$Name, [string]$State, $Count = '', $Seats = '', $Assigned = '', [string]$Source = '', [string]$Detail = '', [string]$Signal = '')
    [pscustomobject][ordered]@{ Kind = $Kind; Capability = $Capability; Name = $Name; State = $State; Count = $Count; Seats = $Seats; Assigned = $Assigned; Source = $Source; Detail = $Detail; Signal = $Signal }
}

function Resolve-CyberSocDefenderPlan {
    # The Defender for Endpoint plan: the operator's reading of the Licenses page when given, otherwise what the API
    # reads show. Where both are known and differ, the detail says so.
    param([string]$Reading, [string]$Signal, [string]$Basis)
    $read = if ($Reading -and $script:CyberSocPlanReadings.Contains($Reading)) { $script:CyberSocPlanReadings[$Reading] } else { '' }
    if (-not $read) { return @{ State = $Signal; Source = 'API reads'; Detail = $Basis } }
    $detail = 'Read on the Licenses page (Settings > Endpoints > Licenses) and passed as -DefenderEndpointPlan {0}.' -f $Reading
    if ($Signal -and $Signal -ne 'Unknown' -and $Signal -ne $read) { $detail += ' The reading and the API reads disagree: the API reads show {0}. {1} Check the Licenses page again before relying on it.' -f $Signal, $Basis }
    elseif ($Basis) { $detail += ' ' + $Basis }
    @{ State = $read; Source = 'Licenses page reading'; Detail = $detail.Trim() }
}

function Get-CyberSocLicensing {
    param(
        [Parameter(Mandatory)][scriptblock]$Read,
        [string[]]$Subscriptions = @(),
        # The operator's reading of the Defender portal Licenses page: Plan1, Plan2, Business or Mixed.
        [string]$Reading = ''
    )
    $catalog = @(Get-CyberSocCapabilityCatalog)
    $byKey = @{}; foreach ($c in $catalog) { $byKey[$c.Key] = $c }
    $rows = [System.Collections.Generic.List[object]]::new()
    $subs = @($Subscriptions | ForEach-Object { (Get-CyberSocLicText $_).ToLowerInvariant() } | Where-Object { $_ })

    $skuResult = & $Read 'LIC.1-SKUS'
    $skuRead = Get-CyberSocReadState $skuResult 'LIC.1-SKUS'
    $skus = @($skuResult.Rows)
    $machineResult = & $Read 'LIC.2-MACHINES'
    $machineRead = Get-CyberSocReadState $machineResult 'LIC.2-MACHINES'
    $machines = @($machineResult.Rows)
    $tvmResult = & $Read 'LIC.3-TVM'
    $tvmRead = Get-CyberSocReadState $tvmResult 'LIC.3-TVM'
    # The Sentinel workspaces never hold the vulnerability management tables, so an answer from the workspace fallback
    # would read every device as without them. Only Advanced Hunting itself counts.
    if ((Get-CyberSocLicText $tvmResult.Source) -match '(?i)fallback') { $tvmRead = @{ State = 'Unknown'; Why = 'LIC.3-TVM answered by the Sentinel workspace fallback, which holds no vulnerability management data' } }
    $tvm = @($tvmResult.Rows)
    $deviceResult = & $Read 'LIC.4-DEVICES'
    $deviceRead = Get-CyberSocReadState $deviceResult 'LIC.4-DEVICES'
    $plansResult = & $Read 'P0.3'
    $plansRead = Get-CyberSocReadState $plansResult 'P0.3'

    # Licenses from the SKUs. A partial or failed read is Unknown, never Not licensed.
    $skuState = @{}
    foreach ($c in @($catalog | Where-Object Kind -eq 'Sku')) {
        $matched = @(Get-CyberSocSkuMatch -Skus $skus -Plans $c.Plans -SkuIds @($c.SkuIds) -ExcludeSkuIds @($c.ExcludeSkuIds))
        $active = @($matched | Where-Object Active)
        $seats = [int64]0; $assigned = [int64]0
        foreach ($a in $active) { $seats += $a.Seats; $assigned += $a.Assigned }
        $list = (@($active | ForEach-Object { '{0} ({1}, {2} seats, {3} assigned)' -f $_.Sku, ($_.Plans -join ' and '), $_.Seats, $_.Assigned })) -join ', '
        if ($active.Count) { $state = 'Licensed'; $detail = 'In ' + $list + '.' }
        elseif ($skuRead.State -ne 'Complete') { $state = 'Unknown'; $detail = 'The licenses could not be read in full ({0}), so this is not known.' -f $skuRead.Why }
        elseif ($matched.Count) { $state = 'Not licensed'; $detail = 'Only in {0}, not active.' -f ((@($matched | ForEach-Object { '{0} ({1})' -f $_.Sku, $_.Status })) -join ', ') }
        else { $state = 'Not licensed'; $detail = 'No license in the tenant carries the service plan.' }
        $skuState[$c.Key] = [pscustomobject]@{ State = $state; Seats = $(if ($active.Count) { $seats } else { '' }); Assigned = $(if ($active.Count) { $assigned } else { '' }); Detail = $detail }
    }

    # Defender for Cloud plans by subscription (P0.3). A subscription without a row, which a partial read can leave
    # out, is unknown, never off.
    $azure = @{}
    foreach ($c in @($catalog | Where-Object Kind -eq 'Azure')) {
        $on = [System.Collections.Generic.List[string]]::new(); $off = [System.Collections.Generic.List[string]]::new(); $unread = [System.Collections.Generic.List[string]]::new()
        foreach ($s in $subs) {
            $p = @(@($plansResult.Rows) | Where-Object { (Get-CyberSocLicText (Get-CyberSocLicValue $_ 'subscriptionId')).ToLowerInvariant() -eq $s -and (Get-CyberSocLicText (Get-CyberSocLicValue $_ 'Plan')) -ieq $c.Plan }) | Select-Object -First 1
            if ($plansRead.State -eq 'Unknown' -or $null -eq $p) { $unread.Add($s); continue }
            $standard = (Get-CyberSocLicText (Get-CyberSocLicValue $p 'Tier')) -ieq 'Standard'
            $subPlan = Get-CyberSocLicText (Get-CyberSocLicValue $p 'SubPlan')
            if ($standard -and (-not $c.SubPlan -or $subPlan -ieq $c.SubPlan)) { $on.Add($s) } else { $off.Add($s) }
        }
        $state = if (-not $subs.Count) { 'Unknown' } elseif ($on.Count -eq $subs.Count) { 'Licensed' } elseif ($on.Count) { 'Partly licensed' } elseif ($unread.Count) { 'Unknown' } else { 'Not licensed' }
        $detail = 'On in {0} of {1}.' -f $on.Count, (Format-CyberSocLicCount $subs.Count 'subscription' 'subscriptions')
        if ($off.Count) { $detail += ' Off in ' + ($off -join ', ') + '.' }
        if ($unread.Count) { $detail += ' Not read in {0}{1}.' -f ($unread -join ', '), $(if ($plansRead.Why) { " ($($plansRead.Why))" } else { '' }) }
        $azure[$c.Key] = [pscustomobject]@{ State = $state; On = @($on); Off = @($off); Unread = @($unread); Detail = $detail }
    }

    # Devices from the Defender for Endpoint API.
    $onboarded = @($machines | Where-Object { (Get-CyberSocLicText (Get-CyberSocLicValue $_ 'OnboardingStatus')) -ieq 'Onboarded' })
    $clients = @($onboarded | Where-Object { (Get-CyberSocLicText (Get-CyberSocLicValue $_ 'DeviceClass')) -eq 'Client' })
    # A Linux device on an Azure virtual machine is a server workload that Defender for Servers covers, so it joins the
    # servers. Any other Linux device is counted on its own, since the API cannot tell a Linux client from a server.
    $isAzure = { param($m) [bool](Get-CyberSocLicText (Get-CyberSocLicValue $m 'AzureResourceId')) }
    $linux = @($onboarded | Where-Object { (Get-CyberSocLicText (Get-CyberSocLicValue $_ 'DeviceClass')) -eq 'Linux' })
    $servers = @($onboarded | Where-Object { (Get-CyberSocLicText (Get-CyberSocLicValue $_ 'DeviceClass')) -eq 'Server' }) + @($linux | Where-Object { & $isAzure $_ })
    $otherLinux = @($linux | Where-Object { -not (& $isAzure $_) })
    $tagged = @($clients | Where-Object { Test-CyberSocLicTrue (Get-CyberSocLicValue $_ 'TaggedPlan1') })
    $machinesKnown = $machineRead.State -eq 'Complete'

    # Plan 2 capabilities seen: vulnerability management data on onboarded devices, read from Advanced Hunting.
    $tvmClass = { param($r) Get-CyberSocDeviceClass -OsPlatform (Get-CyberSocLicText (Get-CyberSocLicValue $r 'OSPlatform')) -DeviceType (Get-CyberSocLicText (Get-CyberSocLicValue $r 'DeviceType')) }
    $tvmCount = { param([string]$Class, [string]$Column) $n = 0; foreach ($r in @($tvm | Where-Object { (& $tvmClass $_) -eq $Class })) { $n += Get-CyberSocLicNumber (Get-CyberSocLicValue $r $Column) }; $n }
    $tvmClients = & $tvmCount 'Client' 'Devices'
    $tvmClientsWithData = [math]::Max((& $tvmCount 'Client' 'WithVulnerabilities'), (& $tvmCount 'Client' 'WithAssessments'))
    $tvmServersWithData = [math]::Max((& $tvmCount 'Server' 'WithVulnerabilities'), (& $tvmCount 'Server' 'WithAssessments'))
    $tvmKnown = $tvmRead.State -eq 'Complete'
    # Advanced Hunting records manual and dynamic tags in their own columns, so LIC.3-TVM also counts the clients tagged
    # by a dynamic rule, which Learn does not say the machine API returns. The larger count of the two reads is used.
    $tvmTagged = & $tvmCount 'Client' 'TaggedPlan1'
    $taggedCount = [math]::Max($tagged.Count, $(if ($tvmKnown) { $tvmTagged } else { 0 }))
    $taggedKnown = $machinesKnown -or $tvmKnown

    # The plan the API reads show. The licenses decide when they were read, and the devices back them.
    $p2 = $skuState['MdePlan2Sku'].State; $p1 = $skuState['MdePlan1Sku'].State; $smb = $skuState['MdeBusinessSku'].State
    $basis = [System.Collections.Generic.List[string]]::new()
    $signal = 'Unknown'
    # Plan 1 licenses beside Plan 2 do not make mixed mode, since Microsoft 365 E3 carries Plan 1 too. Mixed mode shows in
    # the License MDE P1 tag on client devices.
    # Defender for Business supports no mixed licensing, and a tenant holding it beside Plan 2 keeps the Defender for
    # Business experience until Microsoft Support switches it (Learn, Defender for Business FAQ), so Business decides
    # first and the Licenses page reading confirms a switch.
    if ($skuRead.State -eq 'Complete') {
        if ($smb -eq 'Licensed') { $signal = 'Defender for Business' }
        elseif ($p2 -eq 'Licensed' -and $taggedCount) { $signal = 'Mixed (Plan 1 and Plan 2)' }
        elseif ($p2 -eq 'Licensed') { $signal = 'Plan 2' }
        elseif ($p1 -eq 'Licensed') { $signal = 'Plan 1' }
        else { $signal = 'No Defender for Endpoint license' }
        $basis.Add(('Licenses: Plan 2 {0}, Plan 1 {1}, Defender for Business {2}.' -f $p2.ToLowerInvariant(), $p1.ToLowerInvariant(), $smb.ToLowerInvariant()))
        if ($smb -eq 'Licensed' -and $p2 -eq 'Licensed') { $basis.Add('Defender for Business and Plan 2 are both licensed. The tenant keeps the Defender for Business experience until Microsoft Support switches it to Plan 2, so confirm the plan on the Licenses page.') }
    }
    elseif ($taggedCount) { $signal = 'Mixed (Plan 1 and Plan 2)' }
    elseif ($tvmKnown -and $tvmClientsWithData -gt 0) { $signal = 'Plan 2' }
    elseif ($tvmKnown -and $tvmClients -gt 0) { $signal = 'Plan 1' }
    # Plan 1 and Defender for Business include no Advanced Hunting, so a read that answered points to Plan 2 or Defender
    # for Servers, and a refused one is not a Plan 1 reading on its own.
    if ($tvmKnown) {
        $basis.Add(('Plan 2 capabilities seen: vulnerability management data on {0} of {1}, and on {2}.' -f $tvmClientsWithData, (Format-CyberSocLicCount $tvmClients 'onboarded client' 'onboarded clients'), (Format-CyberSocLicCount $tvmServersWithData 'server' 'servers')))
        if ($tvmClients -gt 0 -and $tvmClientsWithData -eq 0) { $basis.Add('Plan 1 only on clients: no onboarded client has vulnerability management data.') }
    }
    else { $basis.Add('Vulnerability management data not read ({0}).' -f $tvmRead.Why) }
    if ($taggedKnown) { $basis.Add(('Mixed mode: {0} tagged {1}.' -f (Format-CyberSocLicCount $taggedCount 'client' 'clients'), $script:CyberSocPlan1Tag)) }
    if (-not $machinesKnown) { $basis.Add('Devices not read ({0}).' -f $machineRead.Why) }
    # Licenses that say Plan 2 while no onboarded client shows Plan 2 data, or Plan 1 while one does, are named too.
    if ($signal -eq 'Plan 2' -and $tvmKnown -and $tvmClients -gt 0 -and $tvmClientsWithData -eq 0 -and $skuRead.State -eq 'Complete') { $basis.Add('The licenses and the devices disagree: Plan 2 is licensed but no onboarded client shows Plan 2 data.') }
    if ($signal -eq 'Plan 1' -and $tvmKnown -and $tvmClientsWithData -gt 0 -and $skuRead.State -eq 'Complete') { $basis.Add('The licenses and the devices disagree: only Plan 1 is licensed but onboarded clients show Plan 2 data.') }
    if ($skuRead.State -ne 'Complete') { $basis.Insert(0, ('Licenses not read ({0}).' -f $skuRead.Why)) }
    $plan = Resolve-CyberSocDefenderPlan -Reading $Reading -Signal $signal -Basis ($basis -join ' ')
    $rows.Add((New-CyberSocMatrixRow -Kind 'Plan' -Capability 'DefenderEndpointPlan' -Name 'Defender for Endpoint plan' -State $plan.State -Seats $skuState['MdePlan2Sku'].Seats -Assigned $skuState['MdePlan2Sku'].Assigned -Source $plan.Source -Detail $plan.Detail -Signal $signal))

    # Server coverage: each onboarded server with the license that covers it. An Azure server in a pack subscription
    # is covered by that subscription's Defender for Servers plan. The servers outside it need a Defender for Endpoint
    # for servers license each (one per operating system environment, Learn, Microsoft Defender service description),
    # so the server seats cover them only when there are enough of them, and which server holds a seat cannot be told
    # when there are not. Defender for Business servers is a valid alternative that no license read can identify, so a
    # tenant with Defender for Business, or whose licenses were not read, leaves a server unknown, never unlicensed.
    $serverSku = $skuState['MdeServerSku'].State
    $serverSeats = if ($serverSku -eq 'Licensed') { [int64]$skuState['MdeServerSku'].Seats } else { [int64]0 }
    $businessExcluded = $smb -eq 'Not licensed'
    $servers2 = $azure['DefenderServers']
    $planOf = { param([string]$Sub) if ($Sub -and $Sub -in $servers2.On) { 'On' } elseif ($Sub -and $Sub -in $servers2.Off) { 'Off' } elseif ($Sub -and $Sub -in $subs) { 'Not read' } elseif ($Sub) { 'Outside the pack' } else { 'Not an Azure machine' } }
    $outside = @($servers | Where-Object { (& $planOf (Get-CyberSocLicText (Get-CyberSocLicValue $_ 'subscriptionId')).ToLowerInvariant()) -ne 'On' }).Count
    $seatsEnough = $serverSku -eq 'Licensed' -and $serverSeats -ge $outside
    $seatShortfall = if ($serverSku -eq 'Licensed' -and -not $seatsEnough) { $outside - $serverSeats } else { 0 }
    $serverRows = foreach ($m in $servers) {
        $sub = (Get-CyberSocLicText (Get-CyberSocLicValue $m 'subscriptionId')).ToLowerInvariant()
        $plan2 = & $planOf $sub
        $source = ''; $licensed = 'Unknown'
        if ($plan2 -eq 'On') { $source = 'Defender for Servers on the subscription'; $licensed = 'Yes' }
        elseif ($seatsEnough) { $source = 'Server licenses in the tenant, {0} for {1}' -f (Format-CyberSocLicCount $serverSeats 'seat' 'seats'), (Format-CyberSocLicCount $outside 'server outside Defender for Servers' 'servers outside Defender for Servers'); $licensed = 'Yes' }
        elseif ($seatShortfall) { $source = 'Server licenses in the tenant, {0} for {1}, so not every one is covered' -f (Format-CyberSocLicCount $serverSeats 'seat' 'seats'), (Format-CyberSocLicCount $outside 'server outside Defender for Servers' 'servers outside Defender for Servers') }
        elseif ($plan2 -eq 'Off' -and $serverSku -eq 'Not licensed' -and $businessExcluded) { $source = 'None found'; $licensed = 'No' }
        elseif ($plan2 -eq 'Off' -and $serverSku -eq 'Not licensed' -and $smb -eq 'Licensed') { $source = 'Not established, Defender for Business servers cannot be read from the licenses' }
        else { $source = 'Not established' }
        [pscustomobject][ordered]@{
            DeviceName = Get-CyberSocLicText (Get-CyberSocLicValue $m 'ComputerDnsName'); OsPlatform = Get-CyberSocLicText (Get-CyberSocLicValue $m 'OsPlatform')
            AzureResourceId = Get-CyberSocLicText (Get-CyberSocLicValue $m 'AzureResourceId'); subscriptionId = $sub; DefenderForServers = $plan2; LicenseSource = $source; Licensed = $licensed
        }
    }
    $serverRows = @($serverRows | Sort-Object Licensed, DeviceName)
    $unlicensed = @($serverRows | Where-Object Licensed -eq 'No')
    $serverUnknown = @($serverRows | Where-Object Licensed -eq 'Unknown')

    $deviceRow = { param([string]$Key, [string]$Name, $Count, [string]$Detail, [bool]$Known, [string]$Why)
        if ($Known) { New-CyberSocMatrixRow -Kind 'Devices' -Capability $Key -Name $Name -State 'Read' -Count $Count -Source 'Defender for Endpoint API' -Detail $Detail }
        else { New-CyberSocMatrixRow -Kind 'Devices' -Capability $Key -Name $Name -State 'Unknown' -Source 'Defender for Endpoint API' -Detail ('Not read ({0}).' -f $Why) } }
    $rows.Add((& $deviceRow 'OnboardedClients' 'Onboarded client devices' $clients.Count ('{0} onboarded of {1} listed by the Defender for Endpoint API.' -f $onboarded.Count, (Format-CyberSocLicCount $machines.Count 'device' 'devices')) $machinesKnown $machineRead.Why))
    $rows.Add((& $deviceRow 'OnboardedServers' 'Onboarded servers' $servers.Count 'Windows Server devices, and Linux devices on Azure virtual machines.' $machinesKnown $machineRead.Why))
    $rows.Add((& $deviceRow 'OnboardedLinux' 'Other onboarded Linux devices' $otherLinux.Count 'Linux devices outside Azure. The API records no device type, so a Linux client cannot be told from a server, and each needs a check of its license.' $machinesKnown $machineRead.Why))
    $rows.Add((& $deviceRow 'TaggedPlan1' ('Client devices tagged {0}' -f $script:CyberSocPlan1Tag) $taggedCount ('Mixed licensing applies Plan 1 to the client devices with this tag. {0} from the device API, {1} from Advanced Hunting, which also records the tags a dynamic rule sets.' -f $tagged.Count, $(if ($tvmKnown) { $tvmTagged } else { 'not read' })) $taggedKnown ((@($machineRead.Why, $tvmRead.Why) | Where-Object { $_ }) -join ', ')))
    $unlicensedDetail = if ($unlicensed.Count) { 'Named in LIC.5-SERVERS: ' + ((@($unlicensed | Select-Object -First 10 | ForEach-Object DeviceName)) -join ', ') + $(if ($unlicensed.Count -gt 10) { ', and {0} more.' -f ($unlicensed.Count - 10) } else { '.' }) } else { 'None found.' }
    if ($serverUnknown.Count) { $unlicensedDetail += ' {0} not established, in LIC.5-SERVERS.' -f (Format-CyberSocLicCount $serverUnknown.Count 'server' 'servers') }
    if ($seatShortfall) { $unlicensedDetail += ' The server licenses are {0} short of the servers outside Defender for Servers.' -f (Format-CyberSocLicCount $seatShortfall 'seat' 'seats') }
    $rows.Add((& $deviceRow 'ServersWithoutLicense' 'Onboarded servers without a server license' $unlicensed.Count $unlicensedDetail $machinesKnown $machineRead.Why))
    $managed = @(@($deviceResult.Rows) | Where-Object { (Get-CyberSocLicText (Get-CyberSocLicValue $_ 'ManagementType')) -ieq 'MicrosoftSense' })
    if ($deviceRead.State -eq 'Complete') { $rows.Add((New-CyberSocMatrixRow -Kind 'Devices' -Capability 'SecuritySettingsManaged' -Name 'Devices managed by security settings management' -State 'Read' -Count $managed.Count -Source 'Microsoft Graph devices' -Detail 'Microsoft Entra devices whose management type reads MicrosoftSense. The enforcement scope (Windows Server, Linux, macOS) is a portal check.')) }
    else { $rows.Add((New-CyberSocMatrixRow -Kind 'Devices' -Capability 'SecuritySettingsManaged' -Name 'Devices managed by security settings management' -State 'Unknown' -Source 'Microsoft Graph devices' -Detail ('Not read ({0}).' -f $deviceRead.Why))) }

    # The capabilities a change request can depend on.
    foreach ($c in $catalog) {
        switch ($c.Kind) {
            'Sku' { $s = $skuState[$c.Key]; $rows.Add((New-CyberSocMatrixRow -Kind 'Capability' -Capability $c.Key -Name $c.Name -State $s.State -Seats $s.Seats -Assigned $s.Assigned -Source 'Licenses (LIC.1-SKUS)' -Detail $s.Detail)) }
            'Azure' { $a = $azure[$c.Key]; $rows.Add((New-CyberSocMatrixRow -Kind 'Capability' -Capability $c.Key -Name $c.Name -State $a.State -Source 'Defender for Cloud plans (P0.3)' -Detail $a.Detail)) }
            'Derived' {
                switch ($c.Key) {
                    'MdeServers' {
                        if ($machinesKnown -and $servers.Count) {
                            # Too few server seats leaves some servers uncovered for certain, even though which ones is unknown.
                            $state = if ($unlicensed.Count -eq $servers.Count) { 'Not licensed' } elseif ($unlicensed.Count -or $seatShortfall) { 'Partly licensed' } elseif ($serverUnknown.Count) { 'Unknown' } else { 'Licensed' }
                            $detail = '{0} of {1} covered, {2} without a server license, {3} not established.' -f @($serverRows | Where-Object Licensed -eq 'Yes').Count, (Format-CyberSocLicCount $servers.Count 'onboarded server' 'onboarded servers'), $unlicensed.Count, $serverUnknown.Count
                            if ($seatShortfall) { $detail += ' The server licenses are {0} short of the {1}.' -f (Format-CyberSocLicCount $seatShortfall 'seat' 'seats'), (Format-CyberSocLicCount $outside 'server outside Defender for Servers' 'servers outside Defender for Servers') }
                        }
                        elseif ($serverSku -eq 'Licensed' -or $servers2.State -eq 'Licensed') { $state = 'Licensed'; $detail = $(if ($machinesKnown) { 'No onboarded server, and server licenses are in place.' } else { 'Server licenses are in place. Devices not read ({0}).' -f $machineRead.Why }) }
                        elseif ($machinesKnown -and $serverSku -eq 'Not licensed' -and $servers2.State -eq 'Not licensed' -and $businessExcluded) { $state = 'Not licensed'; $detail = 'No onboarded server, and no server license or Defender for Servers plan.' }
                        else { $state = 'Unknown'; $detail = 'Not established: ' + ((@($machineRead.Why, $(if ($serverSku -eq 'Unknown') { 'server licenses unknown' }), $(if ($servers2.State -eq 'Unknown') { 'Defender for Servers unknown' })) | Where-Object { $_ }) -join ', ') + '.' }
                        $rows.Add((New-CyberSocMatrixRow -Kind 'Capability' -Capability $c.Key -Name $c.Name -State $state -Count $(if ($machinesKnown) { $servers.Count } else { '' }) -Source 'Devices (LIC.2-MACHINES), licenses and P0.3' -Detail $detail))
                    }
                    'MdeVulnerabilityData' {
                        $planState = $plan.State
                        $servers2State = $servers2.State
                        if ($planState -eq 'Plan 2') { $state = 'Licensed'; $detail = 'Defender for Endpoint Plan 2.' }
                        elseif ($planState -like 'Mixed*') { $state = 'Partly licensed'; $detail = 'Mixed licensing: the client devices tagged {0} have no vulnerability management data.' -f $script:CyberSocPlan1Tag }
                        elseif ($planState -eq 'Defender for Business' -and -not ($tvmKnown -and ($tvmClientsWithData + $tvmServersWithData) -gt 0) -and $servers2State -notin 'Licensed', 'Partly licensed') {
                            # Learn disagrees with itself on whether Defender for Business includes vulnerability
                            # management, and it has no Advanced Hunting to show the data, so it stays unknown.
                            $state = 'Unknown'; $detail = 'Defender for Business. Learn does not settle whether it includes vulnerability management, and it has no Advanced Hunting to read the data from.'
                        }
                        elseif ($planState -in 'Plan 1', 'Defender for Business', 'No Defender for Endpoint license') {
                            if ($servers2State -in 'Licensed', 'Partly licensed' -or ($tvmKnown -and ($tvmClientsWithData + $tvmServersWithData) -gt 0)) { $state = 'Partly licensed'; $detail = '{0} on clients, with Defender for Servers or vulnerability management data on some devices.' -f $planState }
                            elseif ($servers2State -eq 'Unknown') { $state = 'Unknown'; $detail = '{0} on clients, Defender for Servers unknown.' -f $planState }
                            else { $state = 'Not licensed'; $detail = '{0}, and no Defender for Servers plan.' -f $planState }
                        }
                        elseif ($tvmKnown -and ($tvmClientsWithData + $tvmServersWithData) -gt 0) { $state = 'Partly licensed'; $detail = 'The plan is unknown, but vulnerability management data is seen on some devices.' }
                        else { $state = 'Unknown'; $detail = 'The plan is unknown.' }
                        if ($tvmKnown) { $detail += ' Vulnerability management data on {0} and {1}.' -f (Format-CyberSocLicCount $tvmClientsWithData 'client' 'clients'), (Format-CyberSocLicCount $tvmServersWithData 'server' 'servers') }
                        $rows.Add((New-CyberSocMatrixRow -Kind 'Capability' -Capability $c.Key -Name $c.Name -State $state -Source 'Defender for Endpoint plan, P0.3 and LIC.3-TVM' -Detail $detail))
                    }
                    'MdeSecurityManagement' {
                        $lic = $skuState['MdeUserSku'].State
                        if ($deviceRead.State -eq 'Complete' -and $managed.Count) { $state = 'Licensed'; $detail = '{0} managed by it.' -f (Format-CyberSocLicCount $managed.Count 'device' 'devices') }
                        elseif ($lic -eq 'Licensed') { $state = 'Licensed'; $detail = 'Licensed, ' + $(if ($deviceRead.State -eq 'Complete') { 'no device managed by it yet.' } else { 'managed devices not read ({0}).' -f $deviceRead.Why }) }
                        elseif ($lic -eq 'Not licensed' -and $deviceRead.State -eq 'Complete') { $state = 'Not licensed'; $detail = 'No Defender for Endpoint user license (Plan 1, Plan 2 or Defender for Business), which it needs even where Defender for Servers covers the servers, and no device is managed by it.' }
                        else { $state = 'Unknown'; $detail = 'Not established: ' + ((@($(if ($lic -eq 'Unknown') { 'licenses unknown' }), $(if ($deviceRead.State -ne 'Complete') { $deviceRead.Why })) | Where-Object { $_ }) -join ', ') + '.' }
                        $detail += ' The enforcement scope (Windows Server, Linux, macOS) has no API and is a portal check.'
                        $rows.Add((New-CyberSocMatrixRow -Kind 'Capability' -Capability $c.Key -Name $c.Name -State $state -Count $(if ($deviceRead.State -eq 'Complete') { $managed.Count } else { '' }) -Seats $skuState['MdeUserSku'].Seats -Assigned $skuState['MdeUserSku'].Assigned -Source 'Licenses and Microsoft Graph devices' -Detail $detail))
                    }
                }
            }
        }
    }
    [pscustomobject]@{ Matrix = $rows.ToArray(); Servers = $serverRows; Plan = $plan }
}

function Get-CyberSocCapabilityGate {
    # Decides what a change request does with the capabilities it requires. Not licensed stops it, and its index status
    # names the missing license. Unknown keeps it with a note to confirm the license before sending. Partly licensed
    # keeps it with a note saying what is not covered. A capability the matrix does not hold reads Unknown.
    param($Matrix, [string[]]$Requires)
    $blocked = [System.Collections.Generic.List[object]]::new(); $unknown = [System.Collections.Generic.List[object]]::new(); $partly = [System.Collections.Generic.List[object]]::new()
    foreach ($key in @($Requires | Where-Object { $_ })) {
        $row = @(@($Matrix) | Where-Object { (Get-CyberSocLicText (Get-CyberSocLicValue $_ 'Kind')) -eq 'Capability' -and (Get-CyberSocLicText (Get-CyberSocLicValue $_ 'Capability')) -eq $key }) | Select-Object -First 1
        $name = if ($row) { Get-CyberSocLicText (Get-CyberSocLicValue $row 'Name') } else { $key }
        $state = if ($row) { Get-CyberSocLicText (Get-CyberSocLicValue $row 'State') } else { 'Unknown' }
        $detail = if ($row) { Get-CyberSocLicText (Get-CyberSocLicValue $row 'Detail') } else { 'The licensing check holds no reading for it.' }
        $entry = [pscustomobject]@{ Key = $key; Name = $name; State = $state; Detail = $detail }
        switch ($state) { 'Not licensed' { $blocked.Add($entry) } 'Licensed' { } 'Partly licensed' { $partly.Add($entry) } default { $unknown.Add($entry) } }
    }
    [pscustomobject]@{ Write = $blocked.Count -eq 0; Blocked = $blocked.ToArray(); Unknown = $unknown.ToArray(); Partly = $partly.ToArray() }
}
