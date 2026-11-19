# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# GHCR transports the ZIP as an OCI artifact. Native Windows consumers need
# only HTTPS and PowerShell; no container engine or registry CLI is required.
function Invoke-Z3PackageDownload([string] $Uri, [hashtable] $Headers, [string] $OutFile) {
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $Uri -Headers $Headers -OutFile $OutFile -TimeoutSec 180 | Out-Null
        return $true
    } catch {
        Write-Warning "Pinned Z3 package is unavailable at $Uri; using the pinned source fallback."
        return $false
    }
}

function Assert-Z3Package([string] $Directory, [string] $RustTarget, $Pin) {
    # Pin the manifest independently so CI caches only the extracted library,
    # without storing a second compressed copy of the same large payload.
    $manifestPath = Join-Path $Directory 'build.json'
    if ((Get-Sha256 $manifestPath).ToLowerInvariant() -ne $Pin.buildManifestSha256) { throw 'Z3 package build manifest checksum mismatch.' }
    $build = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($build.version -ne $Z3Version -or $build.target -ne $RustTarget -or $build.runtime -ne 'MT' -or $build.lto -ne $false -or $build.configuration -ne 'Release' -or $build.sourceSha256 -ne $Z3SourceSha256 -or $build.msvcToolset -notlike "$($Z3Pin.msvcToolset).*") {
        throw 'Z3 package version, architecture, source, compiler, or static runtime does not match the pin.'
    }
    foreach ($file in $build.files) {
        if ($file.path -match '(^[/\\]|(^|[/\\])\.\.([/\\]|$)|:)') { throw 'Invalid Z3 package file path.' }
        $path = Join-Path $Directory $file.path
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Sha256 $path).ToLowerInvariant() -ne $file.sha256) { throw "Z3 package file checksum mismatch: $($file.path)" }
    }
    foreach ($required in @('lib/libz3.lib', 'include/z3.h', 'LICENSE.txt')) {
        if (-not (Test-Path -LiteralPath (Join-Path $Directory $required) -PathType Leaf)) { throw "Incomplete Z3 package: $required" }
    }
}

function Resolve-Z3Package([string] $RustTarget) {
    $property = $Z3Pin.packages.PSObject.Properties[$RustTarget]
    if ($null -eq $property) { return $null }
    $pin = $property.Value
    if ($pin.manifestDigest -notmatch '^sha256:[0-9a-f]{64}$' -or $pin.archiveSha256 -notmatch '^[0-9a-f]{64}$' -or $pin.buildManifestSha256 -notmatch '^[0-9a-f]{64}$') { throw 'Invalid Z3 package digest pin.' }
    $cacheRoot = Join-Path $RepoRoot '.cache/windows-z3'
    $destination = Join-Path $cacheRoot "$RustTarget-$($pin.archiveSha256)"
    if (Test-Path -LiteralPath $destination -PathType Container) {
        Assert-Z3Package $destination $RustTarget $pin
        Write-Host "==> Z3: cached static /MT $Z3Version package for $RustTarget"
        return $destination
    }
    $repository = $Z3Pin.repository
    if ($repository -notmatch '^ghcr\.io/(nvidia/openshell/[a-z0-9/-]+)$') { throw 'Invalid OpenShell Z3 registry repository.' }
    $name = $Matches[1]
    $scope = [uri]::EscapeDataString("repository:${name}:pull")
    try {
        # Public packages keep developer machines and external CI credential-free.
        $token = (Invoke-RestMethod -Uri "https://ghcr.io/token?service=ghcr.io&scope=$scope" -TimeoutSec 30).token
    } catch {
        Write-Warning "Pinned static Z3 $Z3Version package is unavailable from GHCR; using the pinned source fallback."
        return $null
    }
    $headers = @{ Authorization = "Bearer $token"; Accept = 'application/vnd.oci.image.manifest.v1+json' }
    $staging = Join-Path $cacheRoot ('download-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    try {
        $manifestPath = Join-Path $staging 'manifest.json'
        if (-not (Invoke-Z3PackageDownload "https://ghcr.io/v2/$name/manifests/$($pin.manifestDigest)" $headers $manifestPath)) { return $null }
        if ('sha256:' + (Get-Sha256 $manifestPath).ToLowerInvariant() -ne $pin.manifestDigest) { throw 'Z3 OCI manifest checksum mismatch.' }
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        if ($manifest.artifactType -ne $Z3Pin.artifactType -or @($manifest.layers).Count -ne 1) { throw 'Unexpected Z3 OCI artifact layout.' }
        $layer = $manifest.layers[0]
        if ($layer.mediaType -ne 'application/zip' -or $layer.digest -ne "sha256:$($pin.archiveSha256)") { throw 'Z3 OCI layer does not match the package pin.' }
        $archive = Join-Path $staging 'package.zip'
        if (-not (Invoke-Z3PackageDownload "https://ghcr.io/v2/$name/blobs/$($layer.digest)" $headers $archive)) { return $null }
        if ((Get-Sha256 $archive).ToLowerInvariant() -ne $pin.archiveSha256) { throw 'Downloaded Z3 package checksum mismatch.' }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $unpack = Join-Path $staging 'unpack'
        [IO.Compression.ZipFile]::ExtractToDirectory($archive, $unpack)
        Assert-Z3Package $unpack $RustTarget $pin
        # Another native task may have populated this same immutable cache.
        $installed = $false
        if (-not (Test-Path -LiteralPath $destination)) {
            try { [IO.Directory]::Move($unpack, $destination); $installed = $true } catch {
                if (-not (Test-Path -LiteralPath $destination)) { throw }
            }
        }
        if (-not $installed) { Assert-Z3Package $destination $RustTarget $pin }
        Write-Host "==> Z3: downloaded static /MT $Z3Version package for $RustTarget ($($pin.manifestDigest))"
        return $destination
    } finally { Remove-Item -LiteralPath $staging -Recurse -Force }
}
