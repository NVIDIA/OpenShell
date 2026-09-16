# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$nodeArchitecture = (& node -p "process.arch").Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Unable to determine the Node.js process architecture (exit code $LASTEXITCODE)."
}
if ($nodeArchitecture -notin @('x64', 'arm64')) {
    throw "Unsupported Windows Node.js architecture '$nodeArchitecture'."
}

$previousCpu = $env:npm_config_cpu
try {
    $env:npm_config_cpu = $nodeArchitecture
    & npm ci
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to install TypeScript SDK dependencies (exit code $LASTEXITCODE)."
    }
}
finally {
    $env:npm_config_cpu = $previousCpu
}

$nativePackages = @(
    "@biomejs/cli-win32-$nodeArchitecture",
    "@bufbuild/buf-win32-$nodeArchitecture",
    "@rolldown/binding-win32-$nodeArchitecture-msvc"
)
foreach ($package in $nativePackages) {
    $manifest = Join-Path 'node_modules' (Join-Path $package 'package.json')
    if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
        throw "The lockfile-pinned native dependency '$package' was not installed."
    }
}
