BeforeAll {
    . (Join-Path $PSScriptRoot '../report/Read-CyberSocPackResult.ps1')
    # Windows PowerShell 5.1 writes the array ConvertFrom-Json parses to the pipeline as one object.
    # PowerShell 7 does the same with -NoEnumerate, so this runs a script block as 5.1 reads JSON.
    function Invoke-WithWindowsPowerShellJson([scriptblock]$Script) {
        function ConvertFrom-Json { param([Parameter(ValueFromPipeline, Position = 0)]$InputObject) process { Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $InputObject -NoEnumerate } }
        & $Script
    }
    function New-ReaderPack {
        param([string]$Path)
        New-Item -ItemType Directory -Path (Join-Path $Path 'results') -Force | Out-Null
        $results = [ordered]@{
            'OUT.1-OPEN' = @('OK', '[{"Name":"alert-1","resourceGroup":"rg-a"},{"Name":"alert-2","resourceGroup":"client-aznativesol0-rg"},null,{"Name":"alert-3","resourceGroup":"rg-c"}]')
            'NB.1' = @('EMPTY', '[]')
            'DP.5b' = @('OK', '{invalid')
            'DP.4-DETAIL' = @('PARTIAL', '')
            'EW.7-DETAIL' = @('OK', $null)
            'DFC.1-DETAIL' = @('UNAVAILABLE', $null)
        }
        $manifest = foreach ($id in $results.Keys) {
            [pscustomobject]@{ ResultId = $id; Status = $results[$id][0]; Rows = 0; ReadTimeUtc = '2026-10-12T06:10:00Z' }
            if ($null -ne $results[$id][1]) { [IO.File]::WriteAllText((Join-Path $Path "results/$id.json"), $results[$id][1]) }
        }
        # A second manifest row for the same result never overrides the first.
        @($manifest) + [pscustomobject]@{ ResultId = 'OUT.1-OPEN'; Status = 'FAILED'; Rows = 0; ReadTimeUtc = '2026-10-12T06:10:00Z' }
    }
}
Describe 'Evidence pack result reader' {
    BeforeEach {
        $pack = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        $manifest = New-ReaderPack $pack
        Initialize-CyberSocPackReader -Pack $pack -Manifest $manifest
    }
    It 'reads every row of a JSON array as its own row and drops null rows' {
        $rows = @(Get-Rows 'OUT.1-OPEN')
        $rows.Count | Should -Be 3
        $rows.Name | Should -Be @('alert-1', 'alert-2', 'alert-3')
    }
    It 'keeps only the rows the filter accepts' {
        Initialize-CyberSocPackReader -Pack $pack -Manifest $manifest -RowFilter { param($row) $row.resourceGroup -notmatch 'aznativesol0' }
        @(Get-Rows 'OUT.1-OPEN').Name | Should -Be @('alert-1', 'alert-3')
    }
    It 'reads the status of the first manifest row, and MISSING for a result the manifest does not list' {
        Get-Status 'OUT.1-OPEN' | Should -Be 'OK'
        Get-Status 'DP.4-DETAIL' | Should -Be 'PARTIAL'
        Get-Status 'IA.8-SIGNINS' | Should -Be 'MISSING'
    }
    It 'reads an empty JSON array as no rows' {
        @(Get-Rows 'NB.1').Count | Should -Be 0
        Test-Unreadable 'NB.1' | Should -BeFalse
    }
    It 'flags an OK or PARTIAL result whose file is malformed, empty or missing, and warns once for each' {
        Mock Write-Warning {}
        foreach ($id in 'DP.5b', 'DP.4-DETAIL', 'EW.7-DETAIL') {
            @(Get-Rows $id).Count | Should -Be 0 -Because $id
            Test-Unreadable $id | Should -BeTrue -Because $id
            Test-Unreadable $id | Should -BeTrue -Because "$id is read from the cache the second time"
        }
        Should -Invoke Write-Warning -Times 3 -Exactly
        Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter { $Message -eq 'DP.5b could not be read. Recollect or restore this result.' }
        Get-UnreadableState 'DP.5b', 'EW.7-DETAIL' | Should -Be 'Result file unreadable (DP.5b, EW.7-DETAIL), recollect or restore the pack'
    }
    It 'reads a result that was not collected as no rows, without a warning' {
        Mock Write-Warning {}
        foreach ($id in 'DFC.1-DETAIL', 'IA.8-SIGNINS') {
            @(Get-Rows $id).Count | Should -Be 0 -Because $id
            Test-Unreadable $id | Should -BeFalse -Because $id
        }
        Should -Invoke Write-Warning -Times 0 -Exactly
    }
    It 'parses each result file once' {
        $real = Get-Command ConvertFrom-Json -CommandType Cmdlet
        Mock ConvertFrom-Json { $InputObject | & $real }
        $null = Get-Rows 'OUT.1-OPEN'
        @(Get-Rows 'OUT.1-OPEN').Count | Should -Be 3
        Should -Invoke ConvertFrom-Json -Times 1 -Exactly
    }
    It 'reads true as 1 or true in any case, and text trimmed' {
        Test-True '1' | Should -BeTrue
        Test-True ' TRUE ' | Should -BeTrue
        Test-True 'False' | Should -BeFalse
        Test-True $null | Should -BeFalse
        Get-Text '  value ' | Should -Be 'value'
        Get-Text $null | Should -Be ''
    }
}
Describe 'Windows PowerShell 5.1, where ConvertFrom-Json writes a JSON array as one object' {
    BeforeEach {
        $pack = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        $manifest = New-ReaderPack $pack
    }
    It 'reads JSON as Windows PowerShell 5.1 does, so the tests below cannot pass by accident' {
        $merged = Invoke-WithWindowsPowerShellJson { , @('[{"Name":"a"},{"Name":"b"},{"Name":"c"}]' | ConvertFrom-Json | Where-Object { $null -ne $_ }) }
        $merged.Count | Should -Be 1
        $merged[0].Name -join ',' | Should -Be 'a,b,c'
    }
    It 'still reads every row of a JSON array as its own row' {
        $rows = Invoke-WithWindowsPowerShellJson {
            Initialize-CyberSocPackReader -Pack $pack -Manifest $manifest -RowFilter { param($row) $row.resourceGroup -notmatch 'aznativesol0' }
            , @(Get-Rows 'OUT.1-OPEN')
        }
        $rows.Count | Should -Be 2
        $rows[0].Name | Should -Be 'alert-1'
        $rows[1].Name | Should -Be 'alert-3'
    }
    It 'still reads an empty JSON array as no rows' {
        $rows = Invoke-WithWindowsPowerShellJson {
            Initialize-CyberSocPackReader -Pack $pack -Manifest $manifest
            , @(Get-Rows 'NB.1')
        }
        $rows.Count | Should -Be 0
    }
}
Describe 'Scripts that read JSON arrays' {
    It 'never pipe a parsed array straight on, which Windows PowerShell 5.1 hands over as one object' {
        $root = Join-Path $PSScriptRoot '..'
        $scripts = @(Get-ChildItem -LiteralPath $root -Filter *.ps1) + @(Get-ChildItem -LiteralPath (Join-Path $root 'report') -Filter *.ps1)
        $scripts.Count | Should -BeGreaterThan 5
        # A pipe after the parse, unless the parse is parenthesised or ForEach-Object { $_ } unrolls it, and
        # @(... | ConvertFrom-Json), which wraps the one object 5.1 writes in a one-element array.
        $pipedOn = 'ConvertFrom-Json[^|)};]*\|(?!\s*ForEach-Object \{ \$_ \})'
        $wrapped = '@\([^()]*\|\s*ConvertFrom-Json[^|()]*\)'
        $offending = @($scripts | Select-String -Pattern $pipedOn, $wrapped | ForEach-Object { '{0}:{1}: {2}' -f $_.Filename, $_.LineNumber, $_.Line.Trim() })
        $offending | Should -BeNullOrEmpty -Because 'the parse must be parenthesised, as in @((Get-Content -Raw | ConvertFrom-Json) | Where-Object { ... })'
    }
}
