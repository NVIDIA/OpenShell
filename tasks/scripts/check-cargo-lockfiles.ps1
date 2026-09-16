# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = "Stop"

$repoRoot = (& git rev-parse --show-toplevel).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($repoRoot)) {
    throw "Unable to resolve the repository root"
}
Set-Location -LiteralPath $repoRoot

$lockfiles = @(& git ls-files -- ':(glob)**/Cargo.lock')
if ($LASTEXITCODE -ne 0) {
    throw "Unable to enumerate tracked Cargo.lock files"
}
if ($lockfiles.Count -eq 0) {
    throw "No tracked Cargo.lock files found"
}

$failed = $false
foreach ($lockfile in $lockfiles) {
    $lockfileDirectory = Split-Path -Parent $lockfile
    $manifest = if ([string]::IsNullOrEmpty($lockfileDirectory)) {
        "Cargo.toml"
    } else {
        Join-Path $lockfileDirectory "Cargo.toml"
    }
    if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
        Write-Error "Tracked lockfile $lockfile has no adjacent Cargo.toml"
        $failed = $true
        continue
    }

    Write-Output "Checking $lockfile"
    & cargo metadata --locked --format-version 1 --manifest-path $manifest | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Validation failed for $lockfile"
        $failed = $true
    }
}

if ($failed) {
    throw "Resolve the reported errors. If a lockfile needs updating, refresh it with Cargo and commit the result."
}
