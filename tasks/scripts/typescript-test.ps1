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

if ($nodeArchitecture -eq 'arm64') {
    $bindingVersion = (& node -p "require('./package-lock.json').packages['node_modules/rolldown'].version").Trim()
    if ($LASTEXITCODE -ne 0 -or $bindingVersion -notmatch '^\d+\.\d+\.\d+([+-][0-9A-Za-z.-]+)?$') {
        throw 'Unable to determine the locked Rolldown version.'
    }
    $previousCpu = $env:npm_config_cpu
    try {
        $env:npm_config_cpu = 'arm64'
        # Keep lockfile resolution enabled: disabling it silently upgrades
        # unrelated test dependencies instead of testing the pinned SDK tree.
        & npm install --no-save "@rolldown/binding-win32-arm64-msvc@$bindingVersion"
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to install the ARM64 Rolldown test binding (exit code $LASTEXITCODE)."
        }
    }
    finally {
        $env:npm_config_cpu = $previousCpu
    }
}

& npm test
exit $LASTEXITCODE
