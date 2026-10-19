# Pester 5 tests for Export-CyberSocToolkit.ps1
# Run: Invoke-Pester ./tests/Export-CyberSocToolkit.Tests.ps1 -Output Detailed
# Packages a scratch copy of the toolkit into TestDrive. Nothing here signs in or calls Azure.

BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    # The packaged paths, without node_modules, so the scratch copy exports with -SkipNodeModules.
    $packaged = @(
        'Export-CyberSocToolkit.ps1', 'Get-CyberSocEvidence.ps1', 'Import-CyberSocVulnAssessment.ps1', 'New-CyberSocReport.ps1',
        'New-CyberSocSecOpsWorklist.ps1', 'New-CyberSocChangeRequests.ps1', 'New-CyberSocControlsStandard.ps1',
        'report', 'package.json', 'package-lock.json',
        'Get-CyberSocEvidence.README.md', 'New-CyberSocReport.README.md', 'New-CyberSocSecOpsWorklist.README.md',
        'New-CyberSocChangeRequests.README.md', 'EBR Security Evidence Collection Runbook.md', 'CyberSOC Monthly Report Runbook.md', 'README.md'
    )
    function New-ScratchToolkit([string]$Path) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        foreach ($item in $packaged) { Copy-Item -LiteralPath (Join-Path $repoRoot $item) -Destination (Join-Path $Path $item) -Recurse }
        New-Item -ItemType Directory -Path (Join-Path $Path 'tests') -Force | Out-Null
        Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.Tests.ps1' -File | Copy-Item -Destination (Join-Path $Path 'tests')
        $Path
    }
    function Read-ZipText([string]$ZipPath, [string]$Name) {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
        try {
            $entry = @($zip.Entries | Where-Object { $_.FullName -match "^[^/]+/$([regex]::Escape($Name))$" })[0]
            $reader = [System.IO.StreamReader]::new($entry.Open())
            try { $reader.ReadToEnd() } finally { $reader.Dispose() }
        }
        finally { $zip.Dispose() }
    }
}

Describe 'Repository root' {
    It 'carries no MANIFEST.sha256, which only a release zip has' {
        # The root copy was the EBR 1.14.0 release manifest. Export-CyberSocToolkit.ps1 writes the zip's own.
        Join-Path $repoRoot 'MANIFEST.sha256' | Should -Not -Exist
    }
}

Describe 'Export-CyberSocToolkit.ps1' {
    It 'packages the change request generator and hashes it in the zip manifest' {
        $scratch = New-ScratchToolkit (Join-Path $TestDrive 'complete')
        $out = Join-Path $TestDrive 'complete-dist'
        $result = & (Join-Path $scratch 'Export-CyberSocToolkit.ps1') -OutputDirectory $out -SkipNodeModules -IncludeTests
        $result.Zip | Should -Exist
        $manifest = Read-ZipText $result.Zip 'MANIFEST.sha256'
        $generator = [IO.File]::ReadAllBytes((Join-Path $scratch 'New-CyberSocChangeRequests.ps1'))
        $hash = -join ([Security.Cryptography.SHA256]::Create().ComputeHash($generator) | ForEach-Object { $_.ToString('x2') })
        $manifest -split "`n" | Should -Contain "$hash  New-CyberSocChangeRequests.ps1"
        # The export script stays out of the zip, so its tests do too.
        $manifest | Should -Not -Match 'Export-CyberSocToolkit'
    }

    It 'fails and writes no zip when the change request generator is missing' {
        $scratch = New-ScratchToolkit (Join-Path $TestDrive 'missing')
        Remove-Item -LiteralPath (Join-Path $scratch 'New-CyberSocChangeRequests.ps1')
        $out = Join-Path $TestDrive 'missing-dist'
        { & (Join-Path $scratch 'Export-CyberSocToolkit.ps1') -OutputDirectory $out -SkipNodeModules } | Should -Throw '*New-CyberSocChangeRequests.ps1*'
        @(Get-ChildItem -LiteralPath $out -Filter '*.zip' -ErrorAction SilentlyContinue) | Should -BeNullOrEmpty
    }
}
