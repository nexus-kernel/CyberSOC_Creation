<#
    Evidence pack reading shared by the generators that read row-level results, New-CyberSocSecOpsWorklist.ps1
    and New-CyberSocChangeRequests.ps1. Offline. Dot-source this file, then call Initialize-CyberSocPackReader
    once with the pack folder and its manifest before reading a result.

    Every result file holds a JSON array. Windows PowerShell 5.1 writes the array ConvertFrom-Json returns
    to the pipeline as one object, where PowerShell 7 enumerates it, so a parse piped straight into
    Where-Object hands the filter the whole array and the rows come back as one item with merged values.
    Read-Result parenthesises the parse, which enumerates the array on both editions.
#>

function Get-Text($value) { if ($null -eq $value) { '' } else { ([string]$value).Trim() } }
function Test-True($value) { $v = Get-Text $value; $v -eq '1' -or $v -ieq 'true' }

function Initialize-CyberSocPackReader {
    # RowFilter keeps or drops each row of every result, for example the worklist's managed resource
    # group exclusion. Null rows are always dropped.
    param([Parameter(Mandatory)][string]$Pack, $Manifest, [scriptblock]$RowFilter = { $true })
    $script:CyberSocPack = $Pack
    $script:CyberSocRowFilter = $RowFilter
    $script:CyberSocResultCache = @{}
    $script:CyberSocStatusById = @{}
    foreach ($row in @($Manifest)) {
        $id = [string]$row.ResultId
        if ($id -and -not $script:CyberSocStatusById.ContainsKey($id)) { $script:CyberSocStatusById[$id] = [string]$row.Status }
    }
}
function Get-Status([string]$id) { if ($script:CyberSocStatusById.ContainsKey($id)) { $script:CyberSocStatusById[$id] } else { 'MISSING' } }
# Each result file is parsed once.
function Read-Result([string]$id) {
    if ($script:CyberSocResultCache.ContainsKey($id)) { return $script:CyberSocResultCache[$id] }
    $entry = @{ Rows = @(); Unreadable = $false }
    $file = Join-Path $script:CyberSocPack "results/$id.json"
    $filter = $script:CyberSocRowFilter
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { $entry.Unreadable = $true }
    else {
        try {
            $raw = Get-Content -LiteralPath $file -Raw
            if ([string]::IsNullOrWhiteSpace($raw)) { $entry.Unreadable = $true }
            else { $entry.Rows = @(($raw | ConvertFrom-Json) | Where-Object { $null -ne $_ -and (& $filter $_) }) }
        }
        catch { $entry.Unreadable = $true }
    }
    if ($entry.Unreadable -and (Get-Status $id) -in 'OK', 'PARTIAL') { Write-Warning "$id could not be read. Recollect or restore this result." }
    $script:CyberSocResultCache[$id] = $entry
    $entry
}
function Get-Rows([string]$id) { (Read-Result $id).Rows }
# A result the manifest reads as OK or PARTIAL needs a file that parses, or a damaged pack would read
# as nothing found.
function Test-Unreadable([string]$id) { (Get-Status $id) -in 'OK', 'PARTIAL' -and (Read-Result $id).Unreadable }
function Get-UnreadableState([string[]]$ids) { 'Result file unreadable ({0}), recollect or restore the pack' -f ($ids -join ', ') }
