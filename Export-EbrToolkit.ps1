<#
.SYNOPSIS
    Packages the EBR evidence toolkit into one zip that runs on a fresh machine.

.DESCRIPTION
    Writes dist/EBR-Evidence-Toolkit_v<version>_<timestamp>.zip with the collector, the report,
    worklist and controls standard generators, the report assets and the pptxgenjs node_modules,
    so the target only needs PowerShell, Azure CLI and Node.js. The zip also carries SETUP.md
    (prerequisites and first commands) and MANIFEST.sha256 (a hash for every file).

    Only the paths listed in this script are read, so evidence packs, .report-build, scratch CSVs
    and reference decks never reach the zip. Any file whose path names an evidence pack or
    .report-build stops the build. After writing, the zip is reopened and checked for every
    required file.

.PARAMETER OutputDirectory
    Folder for the zip. Defaults to dist beside this script.

.PARAMETER IncludeTests
    Adds the Pester and node:test suites, so the install can be checked on the target.

.PARAMETER IncludeDocs
    Adds docs (the controls baseline, design records and The Controls That Matter).

.PARAMETER SkipNodeModules
    Leaves node_modules out for a smaller zip. The target then runs npm ci once before the
    PowerPoint editions can be written.

.EXAMPLE
    pwsh ./Export-EbrToolkit.ps1

.EXAMPLE
    pwsh ./Export-EbrToolkit.ps1 -IncludeTests -OutputDirectory ~/Desktop
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'dist'),
    [switch]$IncludeTests,
    [switch]$IncludeDocs,
    [switch]$SkipNodeModules
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem

$root = $PSScriptRoot
$junkNames = '.DS_Store', 'Thumbs.db', 'desktop.ini'
# Client data lives in evidence packs and .report-build. Nothing under either may be packaged.
$forbidden = '(^|/)(EBR-Evidence_[^/]*|\.report-build)(/|$)'

# Path, whether the build fails without it, and an optional filter for folders.
$items = [System.Collections.Generic.List[object]]::new()
function Add-PackageItem([string]$Path, [bool]$Required = $true, [scriptblock]$Filter = { $true }) {
    $items.Add([pscustomobject]@{ Path = $Path; Required = $Required; Filter = $Filter })
}
Add-PackageItem 'Get-EbrSecurityEvidence.ps1'
Add-PackageItem 'New-EbrSecurityReport.ps1'
Add-PackageItem 'New-EbrSecOpsWorklist.ps1'
Add-PackageItem 'New-EbrControlsStandard.ps1'
Add-PackageItem 'report'
Add-PackageItem 'package.json'
Add-PackageItem 'package-lock.json'
Add-PackageItem 'Get-EbrSecurityEvidence.README.md' $false
Add-PackageItem 'New-EbrSecurityReport.README.md' $false
Add-PackageItem 'New-EbrSecOpsWorklist.README.md' $false
Add-PackageItem 'EBR Security Evidence Collection Runbook.md' $false
# .bin holds symlinks to package CLIs, which the decks never call.
if (-not $SkipNodeModules) { Add-PackageItem 'node_modules' $true { $args[0] -notmatch '^node_modules/\.bin/' } }
# The Python tests cover scripts that live outside this folder.
if ($IncludeTests) { Add-PackageItem 'tests' $true { $args[0] -match '\.(Tests\.ps1|test\.cjs)$' } }
if ($IncludeDocs) { Add-PackageItem 'docs' }

$collector = Get-Content -LiteralPath (Join-Path $root 'Get-EbrSecurityEvidence.ps1') -Raw
if ($collector -notmatch "\`$script:EbrVersion\s*=\s*'([^']+)'") { throw 'Could not read $script:EbrVersion from Get-EbrSecurityEvidence.ps1.' }
$version = $Matches[1]

if (-not $SkipNodeModules) {
    # A partial node_modules only shows up on the target as a missing deck, so check it here.
    # The lock names the root package "", which ConvertFrom-Json rejects without -AsHashtable (7.x only).
    $lock = (Get-Content -LiteralPath (Join-Path $root 'package-lock.json') -Raw) -replace '"":\s*\{', '"(root)": {' | ConvertFrom-Json
    foreach ($package in $lock.packages.PSObject.Properties) {
        if ($package.Name -eq '(root)' -or $package.Value.optional -or $package.Value.dev) { continue }
        $manifest = Join-Path $root "$($package.Name)/package.json"
        if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { throw "$($package.Name) is missing. Run npm ci, then package again." }
        $installed = (Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json).version
        if ($installed -ne $package.Value.version) { throw "$($package.Name) is $installed but package-lock.json pins $($package.Value.version). Run npm ci, then package again." }
    }
}

# Resolve every file first, so a missing or forbidden path stops the build before anything is written.
$files = [System.Collections.Generic.List[object]]::new()
foreach ($item in $items) {
    $full = Join-Path $root $item.Path
    if (-not (Test-Path -LiteralPath $full)) {
        if ($item.Required) { throw "$($item.Path) is missing from $root." }
        Write-Warning "$($item.Path) was not found and is left out."
        continue
    }
    $found = if (Test-Path -LiteralPath $full -PathType Leaf) { @(Get-Item -LiteralPath $full) } else { @(Get-ChildItem -LiteralPath $full -Recurse -File -Force) }
    foreach ($file in $found) {
        $relative = $file.FullName.Substring($root.Length).TrimStart('\', '/').Replace('\', '/')
        if ($junkNames -contains $file.Name -or $file.Name.StartsWith('._') -or $relative -match '(^|/)__pycache__/') { continue }
        if ($relative -match $forbidden) { throw "$relative looks like client evidence and must not be packaged. Move it out of $($item.Path) first." }
        if (-not (& $item.Filter $relative)) { continue }
        $files.Add([pscustomobject]@{ Relative = $relative; File = $file })
    }
}

$nodeLine = if ($SkipNodeModules) { 'node_modules is not bundled. Run `npm ci` in this folder once, before the first report.' } else { 'node_modules is bundled, so no npm install is needed.' }
$setup = @"
# EBR Security Evidence Toolkit v$version

Packaged $((Get-Date).ToString('yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture)).

## Prerequisites

- PowerShell 7.x (Windows PowerShell 5.1 also works).
- Azure CLI 2.50 or later (``brew install azure-cli`` or ``winget install Microsoft.AzureCLI``).
- Node.js 18 or later, for the PowerPoint editions. Without it the HTML report is still written.
- The ExchangeOnlineManagement module, installed for the current user on the first run unless you pass ``-SkipExchange``.

$nodeLine

## Windows

Files extracted from a downloaded zip are marked as coming from the internet, and PowerShell blocks them under the RemoteSigned policy. Run this once from the extracted folder:

``````powershell
Get-ChildItem -Recurse -File | Unblock-File
``````

## Check the install

This writes the controls standard as HTML and PPTX without signing in anywhere. Both files appearing means the report assets, Node.js and pptxgenjs all work.

``````powershell
pwsh ./New-EbrControlsStandard.ps1 -OutputPath ./install-check/standard.html
``````

## Collect evidence

``````powershell
pwsh ./Get-EbrSecurityEvidence.ps1 -TenantId <tenant> -SubscriptionId <subscription>
``````

Each run writes an evidence pack with the report (``03-security-report.html`` and ``.pptx``) and the SecOps worklist (``04-secops-worklist.md`` and ``.csv``). The worklist names client resources and is internal only, so it never goes to the client. Get-EbrSecurityEvidence.README.md covers parameters, permissions and sign-ins.

## Integrity

MANIFEST.sha256 holds the SHA-256 of every other file in this folder. On macOS or Linux, check it with ``shasum -a 256 -c MANIFEST.sha256``.
"@

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$top = "EBR-Evidence-Toolkit_v$version"
[void](New-Item -ItemType Directory -Path $OutputDirectory -Force)
$zipPath = Join-Path (Resolve-Path -LiteralPath $OutputDirectory).Path "${top}_$stamp.zip"

function Add-Entry([System.IO.Compression.ZipArchive]$Zip, [string]$Name, [byte[]]$Bytes, [datetime]$Modified) {
    $entry = $Zip.CreateEntry("$top/$Name", [System.IO.Compression.CompressionLevel]::Optimal)
    # Zip dates start in 1980.
    $entry.LastWriteTime = if ($Modified.Year -lt 1980) { [datetime]'1980-01-01' } else { $Modified }
    # Regular file, mode 644. Without it, unzip on macOS and Linux can extract files nobody can read.
    $entry.ExternalAttributes = [int]0x81A4 -shl 16
    $stream = $entry.Open()
    try { $stream.Write($Bytes, 0, $Bytes.Length) } finally { $stream.Dispose() }
}

$sha = [System.Security.Cryptography.SHA256]::Create()
$hashes = [System.Text.StringBuilder]::new()
$utf8 = [System.Text.UTF8Encoding]::new($false)
$zip = [System.IO.Compression.ZipFile]::Open($zipPath, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    $setupBytes = $utf8.GetBytes($setup.Replace("`r`n", "`n"))
    foreach ($file in @($files) + [pscustomobject]@{ Relative = 'SETUP.md'; Bytes = $setupBytes }) {
        $bytes = if ($file.File) { [IO.File]::ReadAllBytes($file.File.FullName) } else { $file.Bytes }
        $modified = if ($file.File) { $file.File.LastWriteTime } else { Get-Date }
        Add-Entry $zip $file.Relative $bytes $modified
        $hash = -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
        [void]$hashes.Append("$hash  $($file.Relative)`n")
    }
    Add-Entry $zip 'MANIFEST.sha256' $utf8.GetBytes($hashes.ToString()) (Get-Date)
}
catch {
    $zip.Dispose()
    Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue
    throw
}
finally { $zip.Dispose(); $sha.Dispose() }

# Reopen the zip and confirm it can run on its own.
$expected = @(
    'Get-EbrSecurityEvidence.ps1', 'New-EbrSecurityReport.ps1', 'New-EbrSecOpsWorklist.ps1', 'New-EbrControlsStandard.ps1',
    'report/Get-EbrCaEvaluation.ps1', 'report/report-model.js', 'report/report-render.js', 'report/report-story.js',
    'report/report.html', 'report/report.css', 'report/standard.html', 'report/standard-render.js', 'report/controls-standard.json',
    'report/deck-common.cjs', 'report/build-report-deck.cjs', 'report/build-controls-deck.cjs', 'report/assets/template-background.jpg',
    'package.json', 'SETUP.md', 'MANIFEST.sha256'
)
if (-not $SkipNodeModules) { $expected += 'node_modules/pptxgenjs/package.json', 'node_modules/jszip/package.json' }
$check = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
try {
    $names = @($check.Entries | ForEach-Object { $_.FullName.Substring($top.Length + 1) })
    $sizeMb = [math]::Round((Get-Item -LiteralPath $zipPath).Length / 1MB, 2)
}
finally { $check.Dispose() }
$missing = @($expected | Where-Object { $names -notcontains $_ })
$leaked = @($names | Where-Object { $_ -match $forbidden })
if ($missing -or $leaked) {
    Remove-Item -LiteralPath $zipPath -Force
    throw "The zip failed its check and was deleted. Missing: $($missing -join ', '). Client evidence: $($leaked -join ', ')."
}

[pscustomobject]@{
    Zip     = $zipPath
    Version = $version
    Files   = $names.Count
    SizeMB  = $sizeMb
}
