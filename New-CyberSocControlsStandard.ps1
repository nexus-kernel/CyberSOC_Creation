<#
.SYNOPSIS
    Writes the controls standard for executives: every control on the report's controls page
    (04 The controls that matter) by pillar and tier, with the reading that grades it. Informational,
    it outlines the controls and invites feedback rather than asking for sign-off.
.DESCRIPTION
    Offline, and holds no client data. Builds the report model on an empty evidence pack in standards
    mode, so the control list, tiers and measure text come from report/report-model.js and never drift
    from the client report. The title and version come from report/controls-standard.json.
    Also writes the PowerPoint edition beside it (report/build-controls-deck.cjs) when Node.js and
    pptxgenjs are available. -SkipDeck writes the HTML only. Regenerate after any change to a control, its tier or its measure.
.EXAMPLE
    ./New-CyberSocControlsStandard.ps1
.EXAMPLE
    ./New-CyberSocControlsStandard.ps1 -OutputPath ./out/controls-standard.html -SkipDeck
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot 'docs/The Controls That Matter.html'),
    [string]$InfoPath = (Join-Path $PSScriptRoot 'report/controls-standard.json'),
    [switch]$SkipDeck
)

$ErrorActionPreference = 'Stop'
$assets = Join-Path $PSScriptRoot 'report'
$info = Get-Content -LiteralPath $InfoPath -Raw | ConvertFrom-Json
$data = [ordered]@{
    version = '2.0.0'
    standard = $true
    standardInfo = $info | Select-Object Title, Version
    parameters = [ordered]@{ ClientName = 'MXDR controls standard' }
    manifest = @()
    results = @{}
}
# Escape HTML-sensitive characters even inside application/json script elements.
$json = ConvertTo-Json -InputObject $data -Depth 10 -Compress
$json = $json.Replace('&', '\u0026').Replace('<', '\u003c').Replace('>', '\u003e')
$json = $json.Replace([string][char]0x2028, '\u2028').Replace([string][char]0x2029, '\u2029')
$html = Get-Content -LiteralPath (Join-Path $assets 'standard.html') -Raw
$css = Get-Content -LiteralPath (Join-Path $assets 'report.css') -Raw
$background = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $assets 'assets/template-background.jpg')))
$css = $css.Replace('__BACKGROUND__', $background)
$model = Get-Content -LiteralPath (Join-Path $assets 'report-model.js') -Raw
$render = Get-Content -LiteralPath (Join-Path $assets 'standard-render.js') -Raw
$html = $html.Replace('__CSS__', $css).Replace('__MODEL__', $model).Replace('__RENDER__', $render).Replace('__DATA__', $json)
$destination = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
if ([IO.Path]::GetExtension($destination) -ine '.html') { throw 'OutputPath must end in .html.' }
$parent = Split-Path -Parent $destination
if (-not (Test-Path -LiteralPath $parent -PathType Container)) { [void](New-Item -ItemType Directory -Path $parent -Force) }
[IO.File]::WriteAllText($destination, $html, [Text.UTF8Encoding]::new($false))
Write-Output $destination
if (-not $SkipDeck) {
    # The PowerPoint edition reads the same model and settings. It needs Node.js and pptxgenjs.
    $deck = [IO.Path]::ChangeExtension($destination, '.pptx')
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) { Write-Warning 'Node.js was not found, so the PowerPoint edition was not written.' }
    else {
        $built = & node (Join-Path $assets 'build-controls-deck.cjs') $deck 2>&1
        if ($LASTEXITCODE -ne 0) { Write-Warning "The PowerPoint edition was not written. $built" } else { Write-Output $deck }
    }
}
