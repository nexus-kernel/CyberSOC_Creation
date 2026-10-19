<#
.SYNOPSIS
    Imports the monthly Atmosera.VulnAssessment runs into a CyberSOC evidence pack.

.DESCRIPTION
    Offline. Reads files only: no sign-in and no network request.

    Reads the vuln_assessment_<yyyyMMdd_HHmmss>.csv of each run (or the per_client and per_subscription
    CSVs of a run) with the run_metadata_<same timestamp>.json beside it, keeps the findings of the
    pack's own subscriptions only, and writes four results into the pack:

      VA.RUNS    One row per run dated inside the window, up to the posture read date: open findings by
                 severity, CISA KEV listed, public exploit, VMs, CVEs, end-of-support VMs, owner and the
                 remediation status counts. Status Complete when the run assessed every pack
                 subscription with complete data, else Partial.
      VA.CHANGE  The change between each run and the one before it, counted as the tool's own trend
                 counts it: a finding is one VM x vuln_id, and a finding only the earlier run has is "no
                 longer reported (pending validation)", never remediated. Compared only when both runs
                 are Complete and used the same severity filter.
      VA.TOP     The latest run's open findings by product, ranked like the tool's priority ranking.
      VA.KEV     The latest run's open findings whose CVEs are in the CISA KEV catalog, by product, with
                 the date CISA added them.

    Only counts and product names reach the pack's results. VM names, resource ids and file paths stay
    in the vulnerability assessment output. A CISA KEV listing means CISA has reported exploitation of
    the vulnerability in the wild, not that it was exploited in this environment.

    Get-CyberSocEvidence.ps1 -VulnAssessmentPath calls the same functions during collection. Run this
    script to add or replace the runs of a pack that was collected without them, then regenerate the
    report with New-CyberSocReport.ps1.

.PARAMETER EvidencePath
    The CyberSOC evidence pack. Its 00-parameters.json gives the subscriptions, the window and the
    posture read date, and its 00-manifest.csv and results folder receive the four results.

.PARAMETER VulnAssessmentPath
    One or more run folders, per_client or per_subscription folders, or vuln_assessment CSV files.
    A folder is read without recursion: its vuln_assessment_<timestamp>.csv files, else every
    <name>_<timestamp>.csv in it. The run metadata is looked up beside each CSV, then one folder up.

.PARAMETER LoadFunctionsOnly
    Load the functions and stop. Used by the collector and the Pester tests.

.EXAMPLE
    ./Import-CyberSocVulnAssessment.ps1 -EvidencePath ./CyberSOC-Evidence_Contoso_2026-09_20261003-090000 -VulnAssessmentPath ./output/VULN_ASSESSMENT

.EXAMPLE
    ./Import-CyberSocVulnAssessment.ps1 -EvidencePath ./CyberSOC-Evidence_Contoso_2026-09_20261003-090000 -VulnAssessmentPath ./jul/per_client/Contoso_20260701_090000.csv, ./aug/per_client/Contoso_20260801_090000.csv, ./sep/per_client/Contoso_20260901_090000.csv
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$EvidencePath,
    [string[]]$VulnAssessmentPath,
    [switch]$LoadFunctionsOnly
)

# The remediation status codes of Atmosera.VulnAssessment (RemediationStatus.ps1), in its own order.
$script:CyberSocVaStatuses = @('remediation_required', 'scheduled', 'pending_client_action', 'pending_vendor_fix',
    'mitigation_applied', 'mitigation_in_place', 'pending_validation', 'resolved')
$script:CyberSocVaSeverities = @('Critical', 'High', 'Medium', 'Low')

function ConvertFrom-CyberSocVaCell {
    # The tool prefixes a cell that starts with = + - or @ with a quote (CSV injection), so take it off.
    param($Value)
    $s = [string]$Value
    if ($s.Length -ge 2 -and $s[0] -eq "'" -and '=+-@'.Contains([string]$s[1])) { return $s.Substring(1) }
    $s
}

function Test-CyberSocVaTrue {
    param($Value)
    [string](ConvertFrom-CyberSocVaCell $Value) -eq 'True'
}

function Get-CyberSocVaVmKey {
    # A VM is its Azure resource id, as the tool counts VMs, else its subscription, resource group and name.
    param($Row)
    $id = ([string]$Row.resource_id).Trim()
    if ($id) { return $id.ToLowerInvariant() }
    ('{0}|{1}|{2}' -f ([string]$Row.subscription_id).Trim(), ([string]$Row.resource_group).Trim(), (ConvertFrom-CyberSocVaCell $Row.vm_name).Trim()).ToLowerInvariant()
}

function Get-CyberSocVaSeverity {
    # The report severity the tool's reports count (Critical when the best CVSS reaches the policy floor).
    param($Row)
    $raw = ([string]$Row.report_severity).Trim()
    if (-not $raw) { $raw = ([string]$Row.severity).Trim() }
    $match = $script:CyberSocVaSeverities | Where-Object { $_ -ieq $raw } | Select-Object -First 1
    if ($match) { $match } else { 'Low' }
}

function ConvertTo-CyberSocVaProduct {
    # The product a Defender recommendation names: "Update mirth_connect_for_linux" reads "mirth connect".
    # A simpler form of the tool's ConvertTo-VaEmailProductName, without its display name table.
    param($Row)
    $name = (ConvertFrom-CyberSocVaCell $Row.vuln_display_name).Trim()
    if (-not $name) { $name = (ConvertFrom-CyberSocVaCell $Row.software_name).Trim() }
    if (-not $name) { return 'Not named' }
    $slug = [regex]::Replace($name, '^update\s+', '', 'IgnoreCase')
    $base = [regex]::Replace($slug, '_for_(?:linux|windows|macos)(?=_|$)', '', 'IgnoreCase').Trim()
    if (-not $base) { $base = $slug }
    # A Linux package keeps its spelling, since package names are case-sensitive identifiers. Any other
    # slug reads like the tool's HTML labels, a word at a time ("apache_tomcat" reads "Apache Tomcat").
    if ($base.Length -eq $slug.Length -and $base -cmatch '^[a-z0-9._+\-]+$') {
        $base = (@($base -split '_' | Where-Object { $_ } | ForEach-Object { if ($_ -match '^\d') { $_ } else { $_.Substring(0, 1).ToUpperInvariant() + $_.Substring(1) } })) -join ' '
    }
    [regex]::Replace($base.Replace('_', ' '), '\s+', ' ').Trim()
}

function ConvertTo-CyberSocVaRunDate {
    # run_timestamp as a date. Windows PowerShell keeps it a string, PowerShell 7 reads it as a DateTime.
    param($Value)
    if ($Value -is [datetime]) { return $Value }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse([string]$Value, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$d)) { return $d }
    $null
}

function Get-CyberSocVaCves {
    param($Row)
    @(([string]$Row.cves) -split '[;,\s]+' | Where-Object { $_ -match '^CVE-\d{4}-\d{4,}$' } | ForEach-Object { $_.ToUpperInvariant() })
}

function Get-CyberSocVaRunTimestamp {
    # The yyyyMMdd_HHmmss stamp at the end of a run file name.
    param([string]$Name)
    if ($Name -match '_(\d{8}_\d{6})\.(csv|json)$') { return $Matches[1] }
    $null
}

function Find-CyberSocVaRunFiles {
    # The CSVs to read, grouped by run timestamp. A run-wide vuln_assessment CSV wins over the per_client
    # and per_subscription CSVs of the same run, which repeat its rows.
    param([string[]]$Path)
    $csvs = [System.Collections.Generic.List[object]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()
    foreach ($p in @($Path | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
        if (Test-Path -LiteralPath $p -PathType Container) {
            $runWide = @(Get-ChildItem -LiteralPath $p -File -Filter 'vuln_assessment_*.csv' | Where-Object { Get-CyberSocVaRunTimestamp $_.Name })
            $found = if ($runWide.Count) { $runWide } else { @(Get-ChildItem -LiteralPath $p -File -Filter '*.csv' | Where-Object { Get-CyberSocVaRunTimestamp $_.Name }) }
            if ($found.Count -eq 0) { $warnings.Add("Vulnerability assessment: no run CSV found in $p.") }
            foreach ($f in $found) { $csvs.Add($f) }
        }
        elseif (Test-Path -LiteralPath $p -PathType Leaf) {
            $f = Get-Item -LiteralPath $p
            if (Get-CyberSocVaRunTimestamp $f.Name) { $csvs.Add($f) } else { $warnings.Add("Vulnerability assessment: $p is not a run CSV named <name>_<yyyyMMdd_HHmmss>.csv.") }
        }
        else { $warnings.Add("Vulnerability assessment: $p was not found.") }
    }
    $runs = foreach ($g in ($csvs | Sort-Object FullName -Unique | Group-Object { Get-CyberSocVaRunTimestamp $_.Name })) {
        $runWide = @($g.Group | Where-Object { $_.Name -like 'vuln_assessment_*' })
        $files = if ($runWide.Count) { @($runWide[0]) } else { @($g.Group) }
        $meta = $null
        foreach ($f in $files) {
            foreach ($dir in @($f.Directory.FullName, $f.Directory.Parent.FullName)) {
                if (-not $dir) { continue }
                $candidate = Join-Path $dir ('run_metadata_{0}.json' -f $g.Name)
                if (Test-Path -LiteralPath $candidate -PathType Leaf) { $meta = $candidate; break }
            }
            if ($meta) { break }
        }
        [pscustomobject]@{ Timestamp = $g.Name; Files = $files; Metadata = $meta }
    }
    [pscustomobject]@{ Runs = @($runs | Sort-Object Timestamp); Warnings = $warnings.ToArray() }
}

function Read-CyberSocVaRows {
    # Every row of the run's CSVs, exact duplicates once: a subscription listed under two roster titles
    # repeats the same rows in both per_client CSVs.
    param([object[]]$Files)
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($f in $Files) {
        foreach ($row in @(Import-Csv -LiteralPath $f.FullName -Encoding UTF8)) {
            $key = ($row.PSObject.Properties | ForEach-Object { [string]$_.Value }) -join [char]31
            if ($seen.Add($key)) { $row }
        }
    }
}

function Get-CyberSocVaProp {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] } return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { $p.Value } else { $null }
}

function Get-CyberSocVaRunSummary {
    # One VA.RUNS row from a run's rows (already cut to the pack's subscriptions) and its metadata.
    param($Rows, $Metadata, [string[]]$Subscriptions, [datetime]$ReportMonth, [datetime]$RunDate)
    $inv = [cultureinfo]::InvariantCulture
    $queried = @(@(Get-CyberSocVaProp $Metadata 'subscriptions_queried') | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $covered = @($Subscriptions | Where-Object { $_ -in $queried })
    $missing = @($Subscriptions | Where-Object { $_ -notin $queried })
    $dc = Get-CyberSocVaProp $Metadata 'data_completeness'
    $incomplete = @($covered | Where-Object { $r = Get-CyberSocVaProp $dc $_; if ($null -eq $r) { $r = Get-CyberSocVaProp $dc ($_.ToUpperInvariant()) }; -not ($null -ne $r -and [string](Get-CyberSocVaProp $r 'complete') -eq 'True') })
    $mdeOk = @($covered | Where-Object { $r = Get-CyberSocVaProp $dc $_; [string](Get-CyberSocVaProp $r 'mde') -in 'ok', 'csv_import' }).Count -eq $covered.Count -and $covered.Count -gt 0
    $open = @($Rows | Where-Object { ([string]$_.status).Trim() -eq 'ACTIONABLE' })
    $sev = @{}; foreach ($s in $script:CyberSocVaSeverities) { $sev[$s] = 0 }
    foreach ($r in $open) { $sev[(Get-CyberSocVaSeverity $r)]++ }
    $kevStatus = [string](Get-CyberSocVaProp $Metadata 'kev_status')
    $kevChecked = $kevStatus -match '^(loaded|cached)\b'
    $statusCounts = @{}; foreach ($s in $script:CyberSocVaStatuses) { $statusCounts[$s] = 0 }
    foreach ($r in $Rows) { $code = ([string]$r.remediation_status).Trim().ToLowerInvariant(); if ($statusCounts.ContainsKey($code)) { $statusCounts[$code]++ } }
    $kevOpen = @($open | Where-Object { Test-CyberSocVaTrue $_.kev })
    $monthEnd = $ReportMonth.AddMonths(1)
    $policy = Get-CyberSocVaProp $Metadata 'severity_policy'
    $filter = @(Get-CyberSocVaProp $Metadata 'severity_filter') | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object
    $o = [ordered]@{
        RunDate                 = $RunDate.ToString('yyyy-MM-dd', $inv)
        RunTimestamp            = $RunDate.ToString("yyyy-MM-dd'T'HH:mm:ss", $inv)
        Status                  = $(if ($missing.Count -or $incomplete.Count) { 'Partial' } else { 'Complete' })
        SubscriptionsCovered    = $covered.Count
        SubscriptionsMissing    = $missing.Count
        SubscriptionsIncomplete = $incomplete.Count
        Findings                = @($Rows).Count
        Open                    = $open.Count
        Critical                = $sev['Critical']
        High                    = $sev['High']
        Medium                  = $sev['Medium']
        Low                     = $sev['Low']
        Vms                     = @($open | ForEach-Object { Get-CyberSocVaVmKey $_ } | Sort-Object -Unique).Count
        Cves                    = @($open | ForEach-Object { Get-CyberSocVaCves $_ } | Sort-Object -Unique).Count
        KevChecked              = $kevChecked
        KevOpen                 = $(if ($kevChecked) { $kevOpen.Count } else { $null })
        KevVms                  = $(if ($kevChecked) { @($kevOpen | ForEach-Object { Get-CyberSocVaVmKey $_ } | Sort-Object -Unique).Count } else { $null })
        KevAddedInReportMonth   = $(if ($kevChecked) { @($kevOpen | Where-Object { $d = [datetime]::MinValue; [datetime]::TryParseExact(([string]$_.kev_date_added).Trim(), 'yyyy-MM-dd', $inv, 'None', [ref]$d) -and $d -ge $ReportMonth -and $d -lt $monthEnd }).Count } else { $null })
        ExploitChecked          = $mdeOk
        ExploitOpen             = @($open | Where-Object { Test-CyberSocVaTrue $_.exploit_available }).Count
        NoVendorFix             = @($open | Where-Object { ([string]$_.fix_status).Trim() -eq 'not_available' }).Count
        EosVms                  = @($Rows | Where-Object { Test-CyberSocVaTrue $_.is_eos_vm } | ForEach-Object { Get-CyberSocVaVmKey $_ } | Sort-Object -Unique).Count
        OwnerProvider           = @($open | Where-Object { ([string]$_.owner).Trim() -eq 'PROVIDER' }).Count
        OwnerClient             = @($open | Where-Object { ([string]$_.owner).Trim() -eq 'CLIENT' }).Count
        OwnerUnknown            = @($open | Where-Object { ([string]$_.owner).Trim() -notin 'PROVIDER', 'CLIENT' }).Count
        SeverityFilter          = ($filter -join ',')
        SeverityPolicy          = $(if ($policy) { '{0}|{1}' -f [string](Get-CyberSocVaProp $policy 'elevate_to_critical'), [string](Get-CyberSocVaProp $policy 'cvss_critical_floor') } else { '' })
    }
    foreach ($s in $script:CyberSocVaStatuses) { $o[('Status_' + $s)] = $statusCounts[$s] }
    [pscustomobject]$o
}

function Get-CyberSocVaChange {
    # The tool's own trend count between two runs: a finding is one VM x vuln_id, a VM x vuln_id on two
    # rows counts once per row, so Earlier + New - NoLongerReported = Current.
    param($EarlierRows, $LaterRows)
    $count = { param($rows) $t = @{}; foreach ($r in @($rows)) { $k = '{0}|{1}' -f (Get-CyberSocVaVmKey $r), ([string]$r.vuln_id).Trim().ToLowerInvariant(); $t[$k] = 1 + [int]$t[$k] }; $t }
    $a = & $count $EarlierRows
    $b = & $count $LaterRows
    $new = 0; $gone = 0; $kept = 0
    foreach ($k in $b.Keys) { $n = $b[$k] - [int]$a[$k]; if ($n -gt 0) { $new += $n }; $kept += [math]::Min($b[$k], [int]$a[$k]) }
    foreach ($k in $a.Keys) { $n = $a[$k] - [int]$b[$k]; if ($n -gt 0) { $gone += $n } }
    # Open findings (ACTIONABLE) as distinct VM x vuln_id keys, for the open movement beside the tool's count.
    $openKeys = {
        param($rows)
        $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($r in @($rows)) { if (([string]$r.status).Trim() -eq 'ACTIONABLE') { [void]$set.Add(('{0}|{1}' -f (Get-CyberSocVaVmKey $r), ([string]$r.vuln_id).Trim().ToLowerInvariant())) } }
        , $set
    }
    $openA = & $openKeys $EarlierRows
    $openB = & $openKeys $LaterRows
    $openNew = 0; foreach ($k in $openB) { if (-not $openA.Contains($k)) { $openNew++ } }
    $openGone = 0; foreach ($k in $openA) { if (-not $openB.Contains($k)) { $openGone++ } }
    [pscustomobject]@{
        Earlier = @($EarlierRows).Count; Current = @($LaterRows).Count; New = $new; NoLongerReported = $gone; Persistent = $kept
        OpenEarlier = $openA.Count; OpenCurrent = $openB.Count; OpenNew = $openNew; OpenNoLonger = $openGone
    }
}

function Get-CyberSocVaTopProducts {
    # Open findings by product, ranked like the tool's priority ranking: a CISA KEV listing, public
    # exploit code, maximum CVSS (a missing score at the low end of its severity band), more VMs, a
    # vendor fix available, report severity.
    param($Rows, [int]$Top = 10)
    $band = @{ Critical = 9.0; High = 7.0; Medium = 4.0; Low = 0.1 }
    $rank = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
    $open = @($Rows | Where-Object { ([string]$_.status).Trim() -eq 'ACTIONABLE' })
    $products = foreach ($g in ($open | Group-Object { (ConvertTo-CyberSocVaProduct $_).ToLowerInvariant() })) {
        $items = @($g.Group)
        $sevs = @($items | ForEach-Object { Get-CyberSocVaSeverity $_ })
        $worst = $sevs | Sort-Object { $rank[$_] } | Select-Object -First 1
        $cvss = @($items | ForEach-Object { $v = 0.0; if ([double]::TryParse(([string]$_.cvss_score).Trim(), [System.Globalization.NumberStyles]::Float, [cultureinfo]::InvariantCulture, [ref]$v)) { $v } else { $band[(Get-CyberSocVaSeverity $_)] } } | Measure-Object -Maximum).Maximum
        $fix = @($items | ForEach-Object { ([string]$_.fix_status).Trim() })
        $owners = @($items | ForEach-Object { ([string]$_.owner).Trim() } | Where-Object { $_ } | Sort-Object -Unique)
        [pscustomobject][ordered]@{
            Product      = ConvertTo-CyberSocVaProduct $items[0]
            Severity     = $worst
            Vms          = @($items | ForEach-Object { Get-CyberSocVaVmKey $_ } | Sort-Object -Unique).Count
            Findings     = $items.Count
            Cves         = @($items | ForEach-Object { Get-CyberSocVaCves $_ } | Sort-Object -Unique).Count
            Kev          = @($items | Where-Object { Test-CyberSocVaTrue $_.kev }).Count -gt 0
            Exploit      = @($items | Where-Object { Test-CyberSocVaTrue $_.exploit_available }).Count -gt 0
            MaxCvss      = [math]::Round([double]$cvss, 1)
            FixStatus    = $(if ($fix -contains 'available') { 'available' } elseif ($fix.Count -and @($fix | Where-Object { $_ -ne 'not_available' }).Count -eq 0) { 'not_available' } else { 'unknown' })
            Owner        = $(if ($owners.Count -eq 1 -and $owners[0] -in 'PROVIDER', 'CLIENT') { $owners[0] } elseif (@($owners | Where-Object { $_ -in 'PROVIDER', 'CLIENT' }).Count -eq 2) { 'SHARED' } else { 'UNKNOWN' })
        }
    }
    @($products | Sort-Object @{ Expression = { -not $_.Kev } }, @{ Expression = { -not $_.Exploit } }, @{ Expression = { -$_.MaxCvss } }, @{ Expression = { -$_.Vms } }, @{ Expression = { $_.FixStatus -ne 'available' } }, @{ Expression = { $rank[$_.Severity] } }, Product | Select-Object -First $Top)
}

function Get-CyberSocVaKevProducts {
    # Open findings with a CISA KEV-listed CVE, by product, with the earliest date CISA added one of them.
    param($Rows, [datetime]$ReportMonth)
    $inv = [cultureinfo]::InvariantCulture
    $kev = @($Rows | Where-Object { ([string]$_.status).Trim() -eq 'ACTIONABLE' -and (Test-CyberSocVaTrue $_.kev) })
    $rank = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
    $out = foreach ($g in ($kev | Group-Object { (ConvertTo-CyberSocVaProduct $_).ToLowerInvariant() })) {
        $dates = @($g.Group | ForEach-Object { ([string]$_.kev_date_added).Trim() } | Where-Object { $_ -match '^\d{4}-\d{2}-\d{2}$' } | Sort-Object)
        $first = if ($dates.Count) { $dates[0] } else { '' }
        $d = [datetime]::MinValue
        $inMonth = $first -and [datetime]::TryParseExact($first, 'yyyy-MM-dd', $inv, 'None', [ref]$d) -and $d -ge $ReportMonth -and $d -lt $ReportMonth.AddMonths(1)
        [pscustomobject][ordered]@{
            Product        = ConvertTo-CyberSocVaProduct $g.Group[0]
            Severity       = (@($g.Group | ForEach-Object { Get-CyberSocVaSeverity $_ }) | Sort-Object { $rank[$_] } | Select-Object -First 1)
            Vms            = @($g.Group | ForEach-Object { Get-CyberSocVaVmKey $_ } | Sort-Object -Unique).Count
            Findings       = $g.Count
            KevDateAdded   = $first
            AddedThisMonth = [bool]$inMonth
        }
    }
    @($out | Sort-Object @{ Expression = { -not $_.AddedThisMonth } }, @{ Expression = { $rank[$_.Severity] } }, @{ Expression = { -$_.Vms } }, Product)
}

function New-CyberSocVaResult {
    # The collector's New-EbrResult shape, so the collector can add these results like any other.
    param([string]$ResultId, [string]$Status, $Rows = @(), [string[]]$Columns = @(), [string]$Source = '', [string]$Detail = '')
    [pscustomobject]@{ ResultId = $ResultId; Status = $Status; Rows = @($Rows); Columns = @($Columns); Source = $Source; Detail = $Detail; ReadTimeUtc = (Get-Date).ToUniversalTime(); DurationSec = 0 }
}

function Get-CyberSocVaItems {
    $phase = 'P5 Vulnerability exposure'
    @(
        [pscustomobject]@{ Id = 'VA.RUNS'; Phase = $phase; Title = 'Vulnerability assessment runs in the window'; Engine = 'VULN-ASSESS'; Notes = 'CyberSOC. One row per Atmosera.VulnAssessment run dated inside the window, cut to the pack subscriptions. Open means the ACTIONABLE validation status. KevOpen is empty when the run did not check the CISA KEV catalog. Partial means the run left out or had incomplete data for a pack subscription.' }
        [pscustomobject]@{ Id = 'VA.CHANGE'; Phase = $phase; Title = 'Vulnerability findings changed between runs'; Engine = 'VULN-ASSESS'; Notes = 'CyberSOC. A finding is one VM x vuln_id. A finding only the earlier run has is no longer reported (pending validation), never remediated. Compared only between Complete runs with the same severity filter.' }
        [pscustomobject]@{ Id = 'VA.TOP'; Phase = $phase; Title = 'Open vulnerability findings by product, latest run'; Engine = 'VULN-ASSESS'; Notes = 'CyberSOC. Ranked by CISA KEV listing, public exploit code, maximum CVSS, VMs, fix availability and severity. Product names and counts only.' }
        [pscustomobject]@{ Id = 'VA.KEV'; Phase = $phase; Title = 'Open findings with a CISA KEV-listed CVE, latest run'; Engine = 'VULN-ASSESS'; Notes = 'CyberSOC. A CISA KEV listing means CISA has reported exploitation in the wild, not that the vulnerability was exploited in this environment.' }
    )
}

function Get-CyberSocVulnAssessmentResults {
    <#
    .SYNOPSIS
        VA.RUNS, VA.CHANGE, VA.TOP and VA.KEV from Atmosera.VulnAssessment runs, for one pack.
    .DESCRIPTION
        Returns Results (the four results), Items (their manifest titles and notes), Parameters (the
        VulnAssessment block of 00-parameters.json) and Warnings. Never throws for a bad run: a run that
        cannot be used is skipped and named in Warnings and in the VA.RUNS detail.
    #>
    param(
        [string[]]$Path,
        [string[]]$Subscriptions,
        [datetime]$WindowStart,
        [datetime]$ReadDate,
        [Nullable[datetime]]$ReportMonth
    )
    $inv = [cultureinfo]::InvariantCulture
    $subs = @($Subscriptions | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique)
    $month = if ($ReportMonth) { [datetime]::new(([datetime]$ReportMonth).Year, ([datetime]$ReportMonth).Month, 1) } else { [datetime]::new($ReadDate.Year, $ReadDate.Month, 1).AddMonths(-1) }
    $source = 'Atmosera.VulnAssessment run files'
    $found = Find-CyberSocVaRunFiles -Path $Path
    $warnings = [System.Collections.Generic.List[string]]::new()
    foreach ($w in $found.Warnings) { $warnings.Add($w) }
    $skipped = [System.Collections.Generic.List[string]]::new()
    $used = [System.Collections.Generic.List[object]]::new()
    foreach ($run in $found.Runs) {
        if (-not $run.Metadata) { $skipped.Add("$($run.Timestamp): no run_metadata_$($run.Timestamp).json beside the CSV or one folder up, so its data completeness cannot be checked"); continue }
        try { $meta = Get-Content -LiteralPath $run.Metadata -Raw -Encoding UTF8 | ConvertFrom-Json }
        catch { $skipped.Add("$($run.Timestamp): run metadata could not be read"); continue }
        if ([string](Get-CyberSocVaProp $meta 'urgent_only') -eq 'True') { $skipped.Add("$($run.Timestamp): an -UrgentOnly run, which reviews only exploitable findings"); continue }
        $runDate = ConvertTo-CyberSocVaRunDate (Get-CyberSocVaProp $meta 'run_timestamp')
        if ($null -eq $runDate) { $skipped.Add("$($run.Timestamp): run_timestamp is missing or unreadable"); continue }
        if ($runDate.Date -lt $WindowStart.Date -or $runDate.Date -gt $ReadDate.Date) { $skipped.Add(('{0}: dated {1}, outside {2} to {3}' -f $run.Timestamp, $runDate.ToString('yyyy-MM-dd', $inv), $WindowStart.ToString('yyyy-MM-dd', $inv), $ReadDate.ToString('yyyy-MM-dd', $inv))); continue }
        if ($null -eq (Get-CyberSocVaProp $meta 'data_completeness')) { $skipped.Add("$($run.Timestamp): written before data_completeness existed"); continue }
        $queried = @(@(Get-CyberSocVaProp $meta 'subscriptions_queried') | ForEach-Object { ([string]$_).ToLowerInvariant() })
        if (@($subs | Where-Object { $_ -in $queried }).Count -eq 0) { $skipped.Add("$($run.Timestamp): assessed none of this pack's subscriptions"); continue }
        try { $all = @(Read-CyberSocVaRows -Files $run.Files) }
        catch { $skipped.Add("$($run.Timestamp): the CSV could not be read"); continue }
        $mine = @($all | Where-Object { ([string]$_.subscription_id).Trim().ToLowerInvariant() -in $subs })
        $used.Add([pscustomobject]@{ Timestamp = $run.Timestamp; Date = $runDate; Meta = $meta; Rows = $mine; Other = $all.Count - $mine.Count; Files = @($run.Files | ForEach-Object { $_.Name }) })
    }
    foreach ($s in $skipped) { $warnings.Add("Vulnerability assessment run skipped: $s.") }
    $runs = @($used | Sort-Object Date)
    $summaries = @(foreach ($r in $runs) { Get-CyberSocVaRunSummary -Rows $r.Rows -Metadata $r.Meta -Subscriptions $subs -ReportMonth $month -RunDate $r.Date })
    $runDetail = (@(
            $(if ($runs.Count) { 'Runs used: ' + ((@($runs | ForEach-Object { '{0} ({1})' -f $_.Date.ToString('yyyy-MM-dd', $inv), ($_.Files -join ', ') })) -join ', ') + '.' })
            $(if (@($runs | Where-Object Other).Count) { 'Findings of other subscriptions left out: ' + ((@($runs | Where-Object Other | ForEach-Object { '{0} in {1}' -f $_.Other, $_.Date.ToString('yyyy-MM-dd', $inv) })) -join ', ') + '.' })
            $(if ($skipped.Count) { 'Skipped: ' + ($skipped -join ', ') + '.' })
        ) | Where-Object { $_ }) -join ' '
    $runColumns = @('RunDate', 'RunTimestamp', 'Status', 'SubscriptionsCovered', 'SubscriptionsMissing', 'SubscriptionsIncomplete', 'Findings', 'Open', 'Critical', 'High', 'Medium', 'Low', 'Vms', 'Cves', 'KevChecked', 'KevOpen', 'KevVms', 'KevAddedInReportMonth', 'ExploitChecked', 'ExploitOpen', 'NoVendorFix', 'EosVms', 'OwnerProvider', 'OwnerClient', 'OwnerUnknown', 'SeverityFilter', 'SeverityPolicy') + @($script:CyberSocVaStatuses | ForEach-Object { 'Status_' + $_ })
    $results = [System.Collections.Generic.List[object]]::new()
    if ($runs.Count -eq 0) {
        $why = if ($runDetail) { $runDetail } else { 'No run CSV was found.' }
        foreach ($id in 'VA.RUNS', 'VA.CHANGE', 'VA.TOP', 'VA.KEV') { $results.Add((New-CyberSocVaResult -ResultId $id -Status 'UNAVAILABLE' -Source $source -Detail ("Not a zero: no usable vulnerability assessment run. $why"))) }
    }
    else {
        $latest = $runs[-1]
        $latestSummary = $summaries[-1]
        $partial = $latestSummary.Status -ne 'Complete'
        $results.Add((New-CyberSocVaResult -ResultId 'VA.RUNS' -Status $(if (@($summaries | Where-Object Status -ne 'Complete').Count) { 'PARTIAL' } else { 'OK' }) -Rows $summaries -Columns $runColumns -Source $source -Detail $runDetail))
        $changes = @(for ($i = 1; $i -lt $runs.Count; $i++) {
                $a = $summaries[$i - 1]; $b = $summaries[$i]
                $reason = if ($a.Status -ne 'Complete') { 'earlier run partial' } elseif ($b.Status -ne 'Complete') { 'later run partial' } elseif ($a.SeverityFilter -ne $b.SeverityFilter) { 'different severity filters' } else { '' }
                $c = if (-not $reason) { Get-CyberSocVaChange -EarlierRows $runs[$i - 1].Rows -LaterRows $runs[$i].Rows } else { $null }
                [pscustomobject][ordered]@{
                    FromRun = $a.RunDate; ToRun = $b.RunDate; Compared = -not $reason; Reason = $reason
                    SeverityCompared = (-not $reason) -and $a.SeverityPolicy -eq $b.SeverityPolicy -and $a.SeverityPolicy -ne ''
                    Earlier = $(if ($c) { $c.Earlier } else { $null }); Current = $(if ($c) { $c.Current } else { $null })
                    New = $(if ($c) { $c.New } else { $null }); NoLongerReported = $(if ($c) { $c.NoLongerReported } else { $null }); Persistent = $(if ($c) { $c.Persistent } else { $null })
                    OpenEarlier = $(if ($c) { $c.OpenEarlier } else { $null }); OpenCurrent = $(if ($c) { $c.OpenCurrent } else { $null })
                    OpenNew = $(if ($c) { $c.OpenNew } else { $null }); OpenNoLonger = $(if ($c) { $c.OpenNoLonger } else { $null })
                }
            })
        $changeColumns = @('FromRun', 'ToRun', 'Compared', 'Reason', 'SeverityCompared', 'Earlier', 'Current', 'New', 'NoLongerReported', 'Persistent', 'OpenEarlier', 'OpenCurrent', 'OpenNew', 'OpenNoLonger')
        $changeStatus = if ($changes.Count -eq 0) { 'EMPTY' } elseif (@($changes | Where-Object { -not $_.Compared }).Count) { 'PARTIAL' } else { 'OK' }
        $changeDetail = if ($changes.Count -eq 0) { 'One run in the window, so there is nothing to compare.' } else { '' }
        $results.Add((New-CyberSocVaResult -ResultId 'VA.CHANGE' -Status $changeStatus -Rows $changes -Columns $changeColumns -Source $source -Detail $changeDetail))
        $top = @(Get-CyberSocVaTopProducts -Rows $latest.Rows)
        $latestNote = 'Latest run {0}.' -f $latest.Date.ToString('yyyy-MM-dd', $inv)
        if ($partial) { $latestNote += ' The run is partial for this pack, so products on the missing or incomplete subscriptions are not in it.' }
        $results.Add((New-CyberSocVaResult -ResultId 'VA.TOP' -Status $(if ($partial) { 'PARTIAL' } elseif ($top.Count) { 'OK' } else { 'EMPTY' }) -Rows $top -Columns @('Product', 'Severity', 'Vms', 'Findings', 'Cves', 'Kev', 'Exploit', 'MaxCvss', 'FixStatus', 'Owner') -Source $source -Detail $latestNote))
        if (-not $latestSummary.KevChecked) {
            $results.Add((New-CyberSocVaResult -ResultId 'VA.KEV' -Status 'UNAVAILABLE' -Source $source -Detail ('Not a zero: the latest run did not check the CISA KEV catalog (kev_status {0}).' -f [string](Get-CyberSocVaProp $latest.Meta 'kev_status'))))
        }
        else {
            $kev = @(Get-CyberSocVaKevProducts -Rows $latest.Rows -ReportMonth $month)
            $kevNote = $latestNote + ' CISA KEV catalog ' + [string](Get-CyberSocVaProp $latest.Meta 'kev_status') + '.'
            $results.Add((New-CyberSocVaResult -ResultId 'VA.KEV' -Status $(if ($partial) { 'PARTIAL' } elseif ($kev.Count) { 'OK' } else { 'EMPTY' }) -Rows $kev -Columns @('Product', 'Severity', 'Vms', 'Findings', 'KevDateAdded', 'AddedThisMonth') -Source $source -Detail $kevNote))
        }
    }
    $params = [ordered]@{
        Source = 'Atmosera.VulnAssessment'
        Runs = @($summaries | ForEach-Object { [ordered]@{ RunDate = $_.RunDate; Status = $_.Status } })
        Files = @($runs | ForEach-Object { $_.Files } | ForEach-Object { $_ })
        Skipped = $skipped.ToArray()
    }
    [pscustomobject]@{ Results = $results.ToArray(); Items = Get-CyberSocVaItems; Parameters = $params; Warnings = $warnings.ToArray() }
}

function ConvertTo-CyberSocVaCsvText {
    # The collector's CSV form: every field quoted, CRLF, written with a BOM by the caller.
    param($Rows, [string[]]$Columns)
    $rows = @($Rows | Where-Object { $null -ne $_ })
    if ($rows.Count -eq 0) { return ((@($Columns) | ForEach-Object { '"' + $_.Replace('"', '""') + '"' }) -join ',') + "`r`n" }
    $flat = foreach ($r in $rows) {
        $o = [ordered]@{}
        foreach ($p in $r.PSObject.Properties) {
            $v = $p.Value
            $o[$p.Name] = if ($null -eq $v) { '' } elseif ($v -is [bool]) { $(if ($v) { 'True' } else { 'False' }) } elseif ($v -is [double]) { $v.ToString('G15', [cultureinfo]::InvariantCulture) } else { [string]$v }
        }
        [pscustomobject]$o
    }
    ((@($flat | ConvertTo-Csv -NoTypeInformation)) -join "`r`n") + "`r`n"
}

function Write-CyberSocVaPack {
    # Writes the results into the pack, replaces their manifest rows and the VulnAssessment block of
    # 00-parameters.json. Every other manifest row and parameter is kept as it is.
    param([string]$Pack, $Import)
    $bom = [System.Text.UTF8Encoding]::new($true)
    $noBom = [System.Text.UTF8Encoding]::new($false)
    $resultsDir = Join-Path $Pack 'results'
    [void][IO.Directory]::CreateDirectory($resultsDir)
    foreach ($r in $Import.Results) {
        [IO.File]::WriteAllText((Join-Path $resultsDir "$($r.ResultId).csv"), (ConvertTo-CyberSocVaCsvText -Rows $r.Rows -Columns $r.Columns), $bom)
        [IO.File]::WriteAllText((Join-Path $resultsDir "$($r.ResultId).json"), (ConvertTo-Json -InputObject @($r.Rows) -Depth 6), $noBom)
    }
    $manifestPath = Join-Path $Pack '00-manifest.csv'
    $ids = @($Import.Results | ForEach-Object ResultId)
    $kept = @(Import-Csv -LiteralPath $manifestPath -Encoding UTF8 | Where-Object { $_.ResultId -notin $ids })
    $added = foreach ($r in $Import.Results) {
        $item = $Import.Items | Where-Object Id -eq $r.ResultId | Select-Object -First 1
        [pscustomobject][ordered]@{
            ResultId = $r.ResultId; Phase = $item.Phase; Title = $item.Title; Engine = $item.Engine; Source = $r.Source; Status = $r.Status
            Rows = @($r.Rows).Count; ReadTimeUtc = $r.ReadTimeUtc.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [cultureinfo]::InvariantCulture); DurationSec = 0; Detail = $r.Detail; Guidance = $item.Notes
        }
    }
    $columns = if ($kept.Count) { @($kept[0].PSObject.Properties.Name) } else { @('ResultId', 'Phase', 'Title', 'Engine', 'Source', 'Status', 'Rows', 'ReadTimeUtc', 'DurationSec', 'Detail', 'Guidance') }
    $rows = @($kept) + @($added | ForEach-Object { $a = $_; $o = [ordered]@{}; foreach ($c in $columns) { $o[$c] = if ($a.PSObject.Properties[$c]) { $a.$c } else { '' } }; [pscustomobject]$o })
    [IO.File]::WriteAllText($manifestPath, (ConvertTo-CyberSocVaCsvText -Rows $rows -Columns $columns), $bom)
    $paramsPath = Join-Path $Pack '00-parameters.json'
    $params = Get-Content -LiteralPath $paramsPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $params | Add-Member -NotePropertyName VulnAssessment -NotePropertyValue $Import.Parameters -Force
    [IO.File]::WriteAllText($paramsPath, (ConvertTo-Json -InputObject $params -Depth 8), $noBom)
}

if ($LoadFunctionsOnly) { return }

$ErrorActionPreference = 'Stop'
if (-not $EvidencePath) { throw 'Pass -EvidencePath, the CyberSOC evidence pack to import into.' }
if (-not $VulnAssessmentPath) { throw 'Pass -VulnAssessmentPath, the vulnerability assessment run folders or CSV files.' }
$pack = (Resolve-Path -LiteralPath $EvidencePath).Path
foreach ($required in '00-parameters.json', '00-manifest.csv') {
    if (-not (Test-Path -LiteralPath (Join-Path $pack $required) -PathType Leaf)) { throw "Evidence pack is missing $required." }
}
$parameters = Get-Content -LiteralPath (Join-Path $pack '00-parameters.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$inv = [cultureinfo]::InvariantCulture
$start = [datetime]::ParseExact([string]$parameters.WindowStart, 'yyyy-MM-dd', $inv)
$end = [datetime]::ParseExact([string]$parameters.WindowEnd, 'yyyy-MM-dd', $inv)
$read = [datetime]::ParseExact([string]$parameters.PostureReadDate, 'yyyy-MM-dd', $inv)
$import = Get-CyberSocVulnAssessmentResults -Path $VulnAssessmentPath -Subscriptions @($parameters.Subscriptions) -WindowStart $start -ReadDate $read -ReportMonth ([datetime]::new($end.Year, $end.Month, 1))
foreach ($w in $import.Warnings) { Write-Warning $w }
Write-CyberSocVaPack -Pack $pack -Import $import
foreach ($r in $import.Results) { Write-Output ('{0} {1} ({2} rows)' -f $r.ResultId, $r.Status, @($r.Rows).Count) }
Write-Output 'Regenerate the report with New-CyberSocReport.ps1 -EvidencePath to include the vulnerability assessment.'
