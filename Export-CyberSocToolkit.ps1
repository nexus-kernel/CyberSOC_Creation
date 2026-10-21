<#
.SYNOPSIS
    Packages the CyberSOC monthly report toolkit into one zip that runs on a fresh machine.

.DESCRIPTION
    Writes dist/CyberSOC-Toolkit_v<version>_<timestamp>.zip with the collector, the vulnerability
    assessment importer, the report, worklist, change request and controls standard generators, the report assets and the pptxgenjs node_modules,
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
    pwsh ./Export-CyberSocToolkit.ps1

.EXAMPLE
    pwsh ./Export-CyberSocToolkit.ps1 -IncludeTests -OutputDirectory ~/Desktop
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
$forbidden = '(^|/)((CyberSOC|EBR)-Evidence_[^/]*|\.report-build)(/|$)'

# Path, whether the build fails without it, and an optional filter for folders.
$items = [System.Collections.Generic.List[object]]::new()
function Add-PackageItem([string]$Path, [bool]$Required = $true, [scriptblock]$Filter = { $true }) {
    $items.Add([pscustomobject]@{ Path = $Path; Required = $Required; Filter = $Filter })
}
Add-PackageItem 'Get-CyberSocEvidence.ps1'
Add-PackageItem 'Import-CyberSocVulnAssessment.ps1'
Add-PackageItem 'New-CyberSocReport.ps1'
Add-PackageItem 'New-CyberSocSecOpsWorklist.ps1'
Add-PackageItem 'New-CyberSocChangeRequests.ps1'
Add-PackageItem 'New-CyberSocControlsStandard.ps1'
Add-PackageItem 'report'
Add-PackageItem 'package.json'
Add-PackageItem 'package-lock.json'
Add-PackageItem 'Get-CyberSocEvidence.README.md' $false
Add-PackageItem 'New-CyberSocReport.README.md' $false
Add-PackageItem 'New-CyberSocSecOpsWorklist.README.md' $false
Add-PackageItem 'New-CyberSocChangeRequests.README.md' $false
Add-PackageItem 'EBR Security Evidence Collection Runbook.md' $false
Add-PackageItem 'CyberSOC Monthly Report Runbook.md' $false
Add-PackageItem 'README.md' $false
# .bin holds symlinks to package CLIs, which the decks never call.
if (-not $SkipNodeModules) { Add-PackageItem 'node_modules' $true { $args[0] -notmatch '^node_modules/\.bin/' } }
# The Python tests cover scripts that live outside this folder.
# The edition tests generate both report editions from the synthetic offline fixture and its context file.
# This script is not packaged, so its own tests are left out too.
if ($IncludeTests) { Add-PackageItem 'tests' $true { $args[0] -ne 'tests/Export-CyberSocToolkit.Tests.ps1' -and $args[0] -match '\.(Tests\.ps1|test\.cjs)$|^tests/fixtures/(offline-pack/|vuln-assessment/|offline-context\.json$)' } }
if ($IncludeDocs) { Add-PackageItem 'docs' }

$collector = Get-Content -LiteralPath (Join-Path $root 'Get-CyberSocEvidence.ps1') -Raw
if ($collector -notmatch "\`$script:EbrVersion\s*=\s*'([^']+)'") { throw 'Could not read $script:EbrVersion from Get-CyberSocEvidence.ps1.' }
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
# CyberSOC Monthly Report Toolkit v$version

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
pwsh ./New-CyberSocControlsStandard.ps1 -OutputPath ./install-check/standard.html
``````

## Collect evidence

``````powershell
pwsh ./Get-CyberSocEvidence.ps1 -TenantId <tenant> -SubscriptionId <subscription> -ReportMonth <yyyy-MM> -VulnAssessmentPath <vulnerability assessment run folders>
``````

The window is the report month and the two full months before it, the 90-day trend. The report month defaults to the last full month. ``-VulnAssessmentPath`` imports the monthly Atmosera.VulnAssessment runs of that window for these subscriptions. A pack collected without them takes them later with ``Import-CyberSocVulnAssessment.ps1 -EvidencePath <pack> -VulnAssessmentPath <runs>``, then ``New-CyberSocReport.ps1 -EvidencePath <pack>``.

Each run writes an evidence pack with the report in two HTML editions and a deck, the SecOps worklist (``04-secops-worklist.md`` and ``.csv``) and the hardening change requests (``05-change-requests``). Send the client ``03-security-report.client.html`` and ``03-security-report.pptx``. ``03-security-report.html`` is the internal edition, with the presenter notes, the evidence review, the collection register and the subscription and workspace IDs, so it never goes to the client. The client edition and the deck need Node.js. The worklist names client resources and is internal only, so it never goes to the client either. Get-CyberSocEvidence.README.md covers parameters, permissions and sign-ins.

## Raise the hardening change requests

The collection run writes ``05-change-requests`` into the pack: one change request for each low-impact hardening item that still has resources to fix, and a ready-to-send client email for each one. Every email asks for the client's approval, of a proposed date or, where the change restarts machines, of a maintenance window, and no change is scheduled without it. Pass ``-ClientContact`` and ``-SenderName`` to the collection run for the emails, or write them again on their own:

``````powershell
pwsh ./New-CyberSocChangeRequests.ps1 -EvidencePath <pack> -ClientContact <name> -SenderName <name>
``````

New-CyberSocChangeRequests.README.md covers the changes, the emails and the options.

## Integrity

MANIFEST.sha256 holds the SHA-256 of every other file in this folder. On macOS or Linux, check it with ``shasum -a 256 -c MANIFEST.sha256``.
"@

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$top = "CyberSOC-Toolkit_v$version"
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
    'Get-CyberSocEvidence.ps1', 'Import-CyberSocVulnAssessment.ps1', 'New-CyberSocReport.ps1', 'New-CyberSocSecOpsWorklist.ps1', 'New-CyberSocChangeRequests.ps1', 'New-CyberSocControlsStandard.ps1',
    'report/Get-EbrCaEvaluation.ps1', 'report/Get-CyberSocLicensing.ps1', 'report/Get-CyberSocEmergencyAccess.ps1', 'report/Read-CyberSocPackResult.ps1', 'report/report-model.js', 'report/cybersoc-model.js', 'report/report-render.js', 'report/report-review.js', 'report/report-controls.js', 'report/build-client-report.cjs', 'report/report-story.js',
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
