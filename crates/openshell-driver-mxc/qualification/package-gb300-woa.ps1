# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build one portable, hash-manifested GB300 qualification ZIP. The extracted
# collector remains outside the checkout and targets a clean OpenShell worktree
# through -RepoRoot / OPENSHELL_GB300_REPO_ROOT.

[CmdletBinding()]
param(
    [string] $OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

$qualificationDir = $PSScriptRoot
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $qualificationDir "..\..\..")).Path

function Invoke-Git([string[]] $Arguments) {
    $savedErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & git -C $repoRoot @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }
    if ($exitCode -ne 0) {
        throw "git $($Arguments -join ' ') failed: $($output -join [Environment]::NewLine)"
    }
    return @($output | ForEach-Object { $_.ToString() })
}

function Get-Sha256([string] $Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

$headSha = (@(Invoke-Git @("rev-parse", "HEAD")))[0].Trim()
$baseSha = (@(Invoke-Git @("merge-base", "HEAD", "refs/remotes/origin/windows")))[0].Trim()
$status = @(Invoke-Git @("status", "--porcelain=v1"))
if ($status.Count -gt 0 -and ($status -join "").Trim()) {
    throw "Qualification packaging requires a clean worktree."
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path (Split-Path -Parent $repoRoot) `
        "OpenShell-GB300-Qualification-$($headSha.Substring(0, 12)).zip"
}
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
if ([System.IO.Path]::GetExtension($OutputPath) -ne ".zip") {
    throw "OutputPath must name a .zip file: $OutputPath"
}
if (Test-Path -LiteralPath $OutputPath) {
    throw "OutputPath already exists: $OutputPath"
}

$sourceFiles = [ordered]@{
    "Run-Qualification.ps1" = "run-gb300-woa.ps1"
    "gb300-woa.json" = "gb300-woa.json"
    "validate.py" = "validate.py"
    "README.md" = "README.md"
}
foreach ($sourceName in $sourceFiles.Values) {
    $sourcePath = Join-Path $qualificationDir $sourceName
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
        throw "Qualification package input is missing: $sourcePath"
    }
}

$uv = Get-Command uv -ErrorAction Stop
& $uv.Source run python (Join-Path $qualificationDir "validate.py") `
    --repo-root $repoRoot contract
if ($LASTEXITCODE -ne 0) {
    throw "Qualification contract validation failed."
}

$stagingRoot = Join-Path ([System.IO.Path]::GetTempPath()) `
    ("openshell-gb300-package-" + [guid]::NewGuid().ToString("N"))
$packageRoot = Join-Path $stagingRoot "OpenShell-GB300-Qualification"
try {
    New-Item -ItemType Directory -Path $packageRoot -Force | Out-Null
    foreach ($entry in $sourceFiles.GetEnumerator()) {
        Copy-Item -LiteralPath (Join-Path $qualificationDir $entry.Value) `
            -Destination (Join-Path $packageRoot $entry.Key)
    }

    $startHere = @"
OpenShell GB300 Windows ARM64 MXC qualification
================================================

1. Use an elevated native ARM64 PowerShell session on the GB300 host.
2. Keep this directory outside the OpenShell checkout.
3. Set the required environment variables shown in README.md.
4. Set OPENSHELL_GB300_REPO_ROOT to the clean OpenShell checkout to test.
5. Run:

   powershell -NoProfile -ExecutionPolicy Bypass -File .\Run-Qualification.ps1

Return the evidence directory printed by the runner. A required SKIP or missing
artifact fails qualification.
"@
    [System.IO.File]::WriteAllText(
        (Join-Path $packageRoot "START-HERE.txt"),
        $startHere,
        [System.Text.UTF8Encoding]::new($false)
    )

    $fileRows = @(
        Get-ChildItem -LiteralPath $packageRoot -File | Sort-Object Name | ForEach-Object {
            [ordered]@{
                name = $_.Name
                size = $_.Length
                sha256 = Get-Sha256 $_.FullName
            }
        }
    )
    $manifest = [ordered]@{
        schema_version = 1
        contract_id = "nvbug-6643699-gb300-woa-mxc"
        package_purpose = "portable external qualification collector"
        entrypoint = "Run-Qualification.ps1"
        source_repository = "https://github.com/NVIDIA/OpenShell"
        qualification_source_sha = $headSha
        reviewed_windows_base_sha = $baseSha
        generated_at = (Get-Date).ToUniversalTime().ToString("o")
        files = $fileRows
    }
    $manifest | ConvertTo-Json -Depth 6 | Out-File `
        -LiteralPath (Join-Path $packageRoot "QUALIFICATION-PACKAGE-MANIFEST.json") `
        -Encoding utf8

    $outputParent = Split-Path -Parent $OutputPath
    if (-not (Test-Path -LiteralPath $outputParent)) {
        New-Item -ItemType Directory -Path $outputParent -Force | Out-Null
    }
    Compress-Archive -LiteralPath $packageRoot -DestinationPath $OutputPath -CompressionLevel Optimal
} finally {
    if (Test-Path -LiteralPath $stagingRoot) {
        Remove-Item -LiteralPath $stagingRoot -Recurse -Force
    }
}

$receipt = [ordered]@{
    path = $OutputPath
    size = (Get-Item -LiteralPath $OutputPath).Length
    sha256 = Get-Sha256 $OutputPath
    qualification_source_sha = $headSha
    reviewed_windows_base_sha = $baseSha
}
$receipt | ConvertTo-Json -Depth 4
