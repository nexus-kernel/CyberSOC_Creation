# Pester 5 tests for Import-CyberSocVulnAssessment.ps1
# Run: Invoke-Pester ./tests/Import-CyberSocVulnAssessment.Tests.ps1 -Output Detailed
# The runs in fixtures/vuln-assessment are synthetic. Nothing here signs in or reads a real assessment.

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'Import-CyberSocVulnAssessment.ps1') -LoadFunctionsOnly
    $script:fixture = Join-Path $PSScriptRoot 'fixtures/vuln-assessment'
    $script:subs = @('5f1c2a9e-3b7d-4e21-9a6c-0d8e4f2b7c11', 'a0b1c2d3-e4f5-4a6b-8c7d-9e0f1a2b3c4d')
    $script:allRuns = @('2026-06', '2026-07', '2026-08', '2026-09', '2026-09-urgent', '2026-10/per_client') | ForEach-Object { Join-Path $script:fixture $_ }
    function Get-Import([string[]]$Path = $script:allRuns, [string[]]$Subscriptions = $script:subs) {
        Get-CyberSocVulnAssessmentResults -Path $Path -Subscriptions $Subscriptions -WindowStart ([datetime]'2026-07-01') -ReadDate ([datetime]'2026-10-08') -ReportMonth ([datetime]'2026-09-01')
    }
    function Get-R($Import, [string]$Id) { $Import.Results | Where-Object ResultId -eq $Id }
}

Describe 'Reading the tool output' {
    It 'takes the quote off a cell the tool protected against formula injection, and nothing else' {
        ConvertFrom-CyberSocVaCell "'@types/node" | Should -Be '@types/node'
        ConvertFrom-CyberSocVaCell "'=SUM(A1)" | Should -Be '=SUM(A1)'
        ConvertFrom-CyberSocVaCell "'quoted" | Should -Be "'quoted"
    }
    It 'names products as the tool does: a Linux package keeps its spelling, other slugs read word by word' {
        ConvertTo-CyberSocVaProduct ([pscustomobject]@{ vuln_display_name = 'Update openssl_for_linux' }) | Should -BeExactly 'openssl'
        ConvertTo-CyberSocVaProduct ([pscustomobject]@{ vuln_display_name = 'Update apache_tomcat' }) | Should -BeExactly 'Apache Tomcat'
        ConvertTo-CyberSocVaProduct ([pscustomobject]@{ vuln_display_name = 'Update windows_server_2019' }) | Should -BeExactly 'Windows Server 2019'
        ConvertTo-CyberSocVaProduct ([pscustomobject]@{ vuln_display_name = "'@types/node" }) | Should -BeExactly '@types/node'
        ConvertTo-CyberSocVaProduct ([pscustomobject]@{ vuln_display_name = ''; software_name = 'curl' }) | Should -BeExactly 'Curl'
    }
    It 'keys a VM by its resource id, case-insensitively, else by subscription, resource group and name' {
        Get-CyberSocVaVmKey ([pscustomobject]@{ resource_id = '/subscriptions/A/resourceGroups/RG/providers/x/VM1' }) | Should -Be '/subscriptions/a/resourcegroups/rg/providers/x/vm1'
        Get-CyberSocVaVmKey ([pscustomobject]@{ resource_id = ''; subscription_id = 'S'; resource_group = 'RG'; vm_name = 'Web01' }) | Should -Be 's|rg|web01'
    }
    It 'reads run_timestamp whether ConvertFrom-Json left it a string or made it a DateTime' {
        (ConvertTo-CyberSocVaRunDate '2026-09-01T09:00:00').ToString('yyyy-MM-dd HH:mm') | Should -Be '2026-09-01 09:00'
        (ConvertTo-CyberSocVaRunDate ([datetime]'2026-09-01T09:00:00')).Day | Should -Be 1
        ConvertTo-CyberSocVaRunDate 'not a date' | Should -BeNullOrEmpty
    }
    It 'prefers the run-wide CSV of a folder and finds the run metadata one folder up for a per_client CSV' {
        $found = Find-CyberSocVaRunFiles -Path $script:allRuns
        @($found.Runs).Count | Should -Be 6
        $oct = $found.Runs | Where-Object Timestamp -eq '20261001_090000'
        $oct.Files.Name | Should -Be 'Synthetic_20261001_090000.csv'
        $oct.Metadata | Should -Match '2026-10[\\/]run_metadata_20261001_090000\.json$'
        (Find-CyberSocVaRunFiles -Path (Join-Path $script:fixture 'missing')).Warnings | Should -Match 'was not found'
    }
}

Describe 'Choosing the runs' {
    BeforeAll { $script:import = Get-Import }
    It 'uses the runs dated inside the window up to the read date, and names the ones it skipped' {
        $runs = Get-R $script:import 'VA.RUNS'
        $runs.Status | Should -Be 'OK'
        @($runs.Rows.RunDate) | Should -Be @('2026-07-01', '2026-08-01', '2026-09-01', '2026-10-01')
        $script:import.Parameters.Skipped | Should -Contain '20260601_090000: dated 2026-06-01, outside 2026-07-01 to 2026-10-08'
        @($script:import.Parameters.Skipped | Where-Object { $_ -match 'UrgentOnly' }).Count | Should -Be 1 -Because 'an urgent-only run reviews only exploitable findings'
        @($script:import.Warnings | Where-Object { $_ -match 'skipped' }).Count | Should -Be 2
    }
    It "keeps only the pack's subscriptions and says how many findings of others were left out" {
        (Get-R $script:import 'VA.RUNS').Detail | Should -Match 'Findings of other subscriptions left out: 1 in 2026-07-01, 2 in 2026-08-01'
        $jul = (Get-R $script:import 'VA.RUNS').Rows | Where-Object RunDate -eq '2026-07-01'
        $jul.Findings | Should -Be 6
    }
    It 'reads a run that covers only some pack subscriptions as partial, and one that covers none as skipped' {
        $one = Get-Import -Subscriptions @($script:subs[0], '77777777-7777-4777-8777-777777777777')
        @((Get-R $one 'VA.RUNS').Rows.Status | Sort-Object -Unique) | Should -Be 'Partial'
        (Get-R $one 'VA.RUNS').Status | Should -Be 'PARTIAL'
        (Get-R $one 'VA.TOP').Status | Should -Be 'PARTIAL'
        $none = Get-Import -Subscriptions @('77777777-7777-4777-8777-777777777777')
        foreach ($id in 'VA.RUNS', 'VA.CHANGE', 'VA.TOP', 'VA.KEV') { (Get-R $none $id).Status | Should -Be 'UNAVAILABLE' -Because $id }
        (Get-R $none 'VA.RUNS').Detail | Should -Match '^Not a zero: no usable vulnerability assessment run.*assessed none of this pack'
    }
    It 'skips a run without metadata rather than trusting its completeness' {
        $dir = Join-Path $TestDrive 'nometa'
        New-Item -ItemType Directory -Path $dir | Out-Null
        Copy-Item (Join-Path $script:fixture '2026-09/vuln_assessment_20260901_090000.csv') $dir
        $x = Get-Import -Path @($dir)
        (Get-R $x 'VA.RUNS').Status | Should -Be 'UNAVAILABLE'
        $x.Parameters.Skipped | Should -Match 'no run_metadata_20260901_090000.json'
    }
}

Describe 'What each run holds' {
    BeforeAll { $script:runs = (Get-R (Get-Import) 'VA.RUNS').Rows }
    It 'counts open (ACTIONABLE) findings by report severity, with VMs and CVEs by identity' {
        $oct = $script:runs | Where-Object RunDate -eq '2026-10-01'
        @($oct.Findings, $oct.Open, $oct.Critical, $oct.High, $oct.Medium, $oct.Low, $oct.Vms, $oct.Cves) | Should -Be @(8, 7, 3, 2, 1, 1, 4, 6)
        @($oct.OwnerProvider, $oct.OwnerClient, $oct.EosVms, $oct.NoVendorFix) | Should -Be @(2, 5, 1, 1)
        @($oct.Status_remediation_required, $oct.Status_pending_client_action, $oct.Status_pending_vendor_fix) | Should -Be @(3, 3, 1)
    }
    It 'leaves the KEV counts empty when the run did not check the catalog, never zero' {
        $jul = $script:runs | Where-Object RunDate -eq '2026-07-01'
        $jul.KevChecked | Should -BeFalse
        $jul.KevOpen | Should -BeNullOrEmpty
        $oct = $script:runs | Where-Object RunDate -eq '2026-10-01'
        @($oct.KevOpen, $oct.KevVms, $oct.KevAddedInReportMonth) | Should -Be @(4, 2, 2)
    }
}

Describe 'Change between runs' {
    BeforeAll { $script:import = Get-Import; $script:changes = (Get-R $script:import 'VA.CHANGE').Rows }
    It 'counts as the tool does: earlier plus new minus no longer reported is current' {
        foreach ($c in $script:changes) {
            $c.Compared | Should -BeTrue
            ($c.Earlier + $c.New - $c.NoLongerReported) | Should -Be $c.Current -Because "$($c.FromRun) to $($c.ToRun)"
        }
        $last = $script:changes | Where-Object ToRun -eq '2026-10-01'
        @($last.New, $last.NoLongerReported, $last.Persistent, $last.OpenNew, $last.OpenNoLonger, $last.OpenCurrent) | Should -Be @(3, 1, 5, 3, 2, 7)
    }
    It 'compares only complete runs with the same severity filter' {
        $a = [pscustomobject]@{ status = 'ACTIONABLE'; resource_id = '/x/vm1'; vuln_id = 'V1' }
        $b = [pscustomobject]@{ status = 'ACTIONABLE'; resource_id = '/x/vm1'; vuln_id = 'V2' }
        $c = Get-CyberSocVaChange -EarlierRows @($a, $a) -LaterRows @($a, $b)
        @($c.New, $c.NoLongerReported, $c.Persistent) | Should -Be @(1, 1, 1) -Because 'a VM x vuln_id on two rows counts once per row'
        $one = Get-Import -Subscriptions @($script:subs[0], '77777777-7777-4777-8777-777777777777')
        $rows = (Get-R $one 'VA.CHANGE').Rows
        @($rows | Where-Object Compared).Count | Should -Be 0
        $rows[0].Reason | Should -Be 'earlier run partial'
        (Get-R $one 'VA.CHANGE').Status | Should -Be 'PARTIAL'
    }
    It 'has nothing to compare with one run' {
        $x = Get-Import -Path @(Join-Path $script:fixture '2026-09')
        (Get-R $x 'VA.CHANGE').Status | Should -Be 'EMPTY'
        (Get-R $x 'VA.CHANGE').Detail | Should -Match 'One run in the window'
    }
}

Describe 'Products and CISA KEV in the latest run' {
    BeforeAll { $script:import = Get-Import }
    It 'ranks KEV first, then public exploit, then CVSS, and carries product names only' {
        $top = (Get-R $script:import 'VA.TOP').Rows
        @($top.Product) | Should -Be @('Log4j Core', 'Apache Tomcat', 'Windows Server 2019', 'libxml2', '@types/node')
        ($top | Where-Object Product -eq 'libxml2').FixStatus | Should -Be 'not_available'
        ($top | Where-Object Product -eq 'Windows Server 2019').Owner | Should -Be 'PROVIDER'
        (ConvertTo-Json -InputObject $top -Depth 4) | Should -Not -Match 'vm-|/subscriptions/|rg-'
    }
    It 'lists KEV products with the date CISA added them and flags the report month' {
        $kev = (Get-R $script:import 'VA.KEV').Rows
        @($kev.Product) | Should -Be @('Log4j Core', 'Apache Tomcat')
        @($kev.KevDateAdded) | Should -Be @('2026-09-10', '2025-12-01')
        @($kev.AddedThisMonth) | Should -Be @($true, $false)
        (Get-R $script:import 'VA.KEV').Detail | Should -Match 'CISA KEV catalog loaded 2026.09.30'
    }
    It 'reads KEV as unavailable, not zero, when the latest run did not check the catalog' {
        $x = Get-Import -Path @(Join-Path $script:fixture '2026-07')
        (Get-R $x 'VA.KEV').Status | Should -Be 'UNAVAILABLE'
        (Get-R $x 'VA.KEV').Detail | Should -Match '^Not a zero: the latest run did not check the CISA KEV catalog \(kev_status disabled\)'
    }
}

Describe 'Writing into an evidence pack' {
    BeforeAll {
        $script:pack = Join-Path $TestDrive 'pack'
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'fixtures/offline-pack') -Destination $script:pack -Recurse
        $script:out = @(& (Join-Path $PSScriptRoot '..' 'Import-CyberSocVulnAssessment.ps1') -EvidencePath $script:pack -VulnAssessmentPath (Join-Path $script:fixture '2026-08'), (Join-Path $script:fixture '2026-09') 3>$null)
        $script:manifest = @(Import-Csv (Join-Path $script:pack '00-manifest.csv'))
    }
    It 'replaces the four manifest rows and keeps every other row' {
        @($script:manifest | Where-Object ResultId -like 'VA.*' | ForEach-Object ResultId | Sort-Object) | Should -Be @('VA.1', 'VA.2', 'VA.3', 'VA.CHANGE', 'VA.KEV', 'VA.RUNS', 'VA.TOP')
        ($script:manifest | Where-Object ResultId -eq 'VA.RUNS').Rows | Should -Be '2'
        $script:manifest | Where-Object ResultId -eq 'OUT.1' | Should -Not -BeNullOrEmpty
        $before = @(Import-Csv (Join-Path $PSScriptRoot 'fixtures/offline-pack/00-manifest.csv')).Count
        $script:manifest.Count | Should -Be $before
    }
    It 'writes the results as CSV and JSON and the runs into 00-parameters.json' {
        $runs = Get-Content (Join-Path $script:pack 'results/VA.RUNS.json') -Raw | ConvertFrom-Json
        @($runs.RunDate) | Should -Be @('2026-08-01', '2026-09-01')
        (Get-Content (Join-Path $script:pack 'results/VA.RUNS.csv') -Raw) | Should -Match '^﻿?"RunDate","RunTimestamp","Status"'
        $p = Get-Content (Join-Path $script:pack '00-parameters.json') -Raw | ConvertFrom-Json
        @($p.VulnAssessment.Runs.RunDate) | Should -Be @('2026-08-01', '2026-09-01')
        $p.ClientName | Should -Be 'Synthetic validation only'
        $script:out[-1] | Should -Match 'New-CyberSocReport.ps1'
    }
    It 'refuses to run without a pack or a path' {
        { & (Join-Path $PSScriptRoot '..' 'Import-CyberSocVulnAssessment.ps1') -VulnAssessmentPath $script:fixture } | Should -Throw '*EvidencePath*'
        { & (Join-Path $PSScriptRoot '..' 'Import-CyberSocVulnAssessment.ps1') -EvidencePath $script:pack } | Should -Throw '*VulnAssessmentPath*'
    }
    It 'keeps every guidance and detail line to the copy rules' {
        foreach ($i in Get-CyberSocVaItems) { $i.Notes | Should -Not -Match ';' -Because $i.Id; $i.Title | Should -Not -Match ';' }
        foreach ($r in (Get-Import).Results) { $r.Detail | Should -Not -Match ';' -Because $r.ResultId }
    }
}
