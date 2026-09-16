# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repository = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$sdkRoot = Join-Path $repository 'sdk\typescript'
$sourceTemplate = Join-Path $sdkRoot 'buf.gen.yaml'
$buf = (Resolve-Path (Join-Path $sdkRoot 'node_modules\.bin\buf.cmd')).Path
$plugin = (Resolve-Path (Join-Path $sdkRoot 'node_modules\.bin\protoc-gen-es.cmd')).Path
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) "openshell-ts-proto-$([guid]::NewGuid().ToString('N'))"
$windowsTemplate = Join-Path $temporaryRoot 'buf.gen.windows.yaml'
$tempPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
if (-not [IO.Path]::GetFullPath($temporaryRoot).StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Protobuf temporary directory escaped the temporary root'
}

New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
try {
    $pluginPath = $plugin.Replace('\', '/')
    $template = [IO.File]::ReadAllText($sourceTemplate).Replace(
        './node_modules/.bin/protoc-gen-es',
        $pluginPath
    )
    [IO.File]::WriteAllText(
        $windowsTemplate,
        $template,
        [Text.UTF8Encoding]::new($false)
    )

    Push-Location $sdkRoot
    try {
        & $buf generate --template $windowsTemplate
        if ($LASTEXITCODE -ne 0) {
            throw "TypeScript protobuf generation failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }
}
finally {
    if (
        (Test-Path -LiteralPath $temporaryRoot) -and
        (Split-Path -Leaf $temporaryRoot) -like 'openshell-ts-proto-*'
    ) {
        $resolvedTemp = (Resolve-Path -LiteralPath $temporaryRoot).ProviderPath
        if (-not $resolvedTemp.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            ((Get-Item -LiteralPath $temporaryRoot).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Refusing to remove an unexpected protobuf temporary directory'
        }
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
