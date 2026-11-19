# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'windows-z3.ps1')
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'windows-msvc.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$function = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-Sha256' }, $true)
Invoke-Expression $function.Extent.Text

$fixture = Join-Path ([IO.Path]::GetTempPath()) ('openshell-z3-package-' + [guid]::NewGuid().ToString('N'))
$Z3Version = '5.1.0'
$Z3SourceSha256 = 'e7ab3f8b682d5f55e813f951c7f9bb4fb9a48567ce6143d7adae23027e0e42a0'
$target = 'aarch64-pc-windows-msvc'
$count = 0
function Expect-Rejection([scriptblock] $Action, [string] $Message) {
    $rejected = $false
    try { & $Action | Out-Null } catch {
        if ($_.Exception.Message -notmatch $Message) { throw }
        $rejected = $true
    }
    if (-not $rejected) { throw "Expected rejection matching: $Message" }
}
try {
    $inputDir = Join-Path $fixture 'input'
    New-Item -ItemType Directory -Path (Join-Path $inputDir 'lib'), (Join-Path $inputDir 'include') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $inputDir 'lib/libz3.lib') -Value 'static-library-fixture'
    Set-Content -LiteralPath (Join-Path $inputDir 'include/z3.h') -Value 'header-fixture'
    Set-Content -LiteralPath (Join-Path $inputDir 'LICENSE.txt') -Value 'license-fixture'
    $files = @(Get-ChildItem -LiteralPath $inputDir -File -Recurse | ForEach-Object {
        @{ path = $_.FullName.Substring($inputDir.Length + 1).Replace('\', '/'); sha256 = (Get-Sha256 $_.FullName).ToLowerInvariant(); size = $_.Length }
    })
    $build = @{ version = $Z3Version; sourceSha256 = $Z3SourceSha256; target = $target; runtime = 'MT'; lto = $false; configuration = 'Release'; msvcToolset = '14.44.35207'; files = $files }
    $build | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $inputDir 'build.json') -Encoding UTF8
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $testArchive = Join-Path $fixture 'package.zip'
    [IO.Compression.ZipFile]::CreateFromDirectory($inputDir, $testArchive)
    $testArchiveHash = (Get-Sha256 $testArchive).ToLowerInvariant()
    $testManifestPath = Join-Path $fixture 'manifest.json'
    $manifest = @{ artifactType = 'application/vnd.nvidia.openshell.z3.v1'; layers = @(@{ mediaType = 'application/zip'; digest = "sha256:$testArchiveHash" }) }
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $testManifestPath -Encoding UTF8
    $pin = @{ manifestDigest = 'sha256:' + (Get-Sha256 $testManifestPath).ToLowerInvariant(); archiveSha256 = $testArchiveHash; buildManifestSha256 = (Get-Sha256 (Join-Path $inputDir 'build.json')).ToLowerInvariant() }
    $Z3Pin = [pscustomobject]@{ repository = 'ghcr.io/nvidia/openshell/z3'; artifactType = $manifest.artifactType; msvcToolset = '14.44'; packages = [pscustomobject]@{ $target = [pscustomobject]$pin } }
    $script:requests = @()
    $script:unavailable = $false
    $script:corruptManifest = $false
    $script:corruptBlob = $false
    function Invoke-RestMethod([string] $Uri, [int] $TimeoutSec) {
        $script:requests += $Uri
        if ($script:unavailable) { throw 'Registry unavailable' }
        return @{ token = 'anonymous-test-token' }
    }
    function Invoke-WebRequest([switch] $UseBasicParsing, [string] $Uri, [hashtable] $Headers, [string] $OutFile, [int] $TimeoutSec) {
        $script:requests += $Uri
        if ($script:unavailable) { throw 'Registry unavailable' }
        if ($Headers.Authorization -ne 'Bearer anonymous-test-token') { throw 'Wrong registry authorization' }
        if ($Uri -match '/manifests/') {
            Copy-Item -LiteralPath $testManifestPath -Destination $OutFile
            if ($script:corruptManifest) { Add-Content -LiteralPath $OutFile -Value 'tampered' }
        } else {
            Copy-Item -LiteralPath $testArchive -Destination $OutFile
            if ($script:corruptBlob) { Add-Content -LiteralPath $OutFile -Value 'tampered' }
        }
    }
    $RepoRoot = Join-Path $fixture 'cold'
    $resolved = Resolve-Z3Package $target
    if (-not $resolved -or $script:requests.Count -ne 3) { throw 'Cold package download failed' }
    if (Test-Path -LiteralPath (Join-Path $resolved 'package.zip')) { throw 'Cache retains a redundant compressed library copy' }
    if ($script:requests[1] -notlike "*/manifests/$($pin.manifestDigest)" -or $script:requests[2] -notlike "*/blobs/sha256:$testArchiveHash") { throw 'Package download did not use immutable digest pins' }
    $count++
    $script:unavailable = $true
    if ((Resolve-Z3Package $target) -ne $resolved -or $script:requests.Count -ne 3) { throw 'Verified package cache was not reused offline' }
    $count++
    Add-Content -LiteralPath (Join-Path $resolved 'lib/libz3.lib') -Value 'corruption'
    Expect-Rejection { Resolve-Z3Package $target } 'file checksum mismatch'
    $count++
    Copy-Item -LiteralPath (Join-Path $inputDir 'lib/libz3.lib') -Destination (Join-Path $resolved 'lib/libz3.lib') -Force
    Add-Content -LiteralPath (Join-Path $resolved 'build.json') -Value 'corruption'
    Expect-Rejection { Resolve-Z3Package $target } 'build manifest checksum mismatch'
    $count++
    $RepoRoot = Join-Path $fixture 'offline'
    if ($null -ne (Resolve-Z3Package $target)) { throw 'Unavailable package did not permit source fallback' }
    $count++
    $script:unavailable = $false
    $script:corruptManifest = $true
    $RepoRoot = Join-Path $fixture 'bad-manifest'
    Expect-Rejection { Resolve-Z3Package $target } 'manifest checksum mismatch'
    $count++
    $script:corruptManifest = $false
    $script:corruptBlob = $true
    $RepoRoot = Join-Path $fixture 'bad-blob'
    Expect-Rejection { Resolve-Z3Package $target } 'package checksum mismatch'
    $count++
    $requestsBefore = $script:requests.Count
    if ($null -ne (Resolve-Z3Package 'x86_64-pc-windows-msvc') -or $script:requests.Count -ne $requestsBefore) { throw 'Unpublished architecture did not permit source fallback before networking' }
    $count++
    Copy-Item -LiteralPath (Join-Path $inputDir 'build.json') -Destination (Join-Path $resolved 'build.json') -Force
    Expect-Rejection { Assert-Z3Package $resolved 'x86_64-pc-windows-msvc' ([pscustomobject]$pin) } 'does not match the pin'
    $count++
    $Z3Version = '5.3.2'
    Expect-Rejection { Assert-Z3Package $resolved $target ([pscustomobject]$pin) } 'does not match the pin'
    $count++
    $Z3Version = '5.1.0'
    $Z3Pin.msvcToolset = '14.52'
    Expect-Rejection { Assert-Z3Package $resolved $target ([pscustomobject]$pin) } 'does not match the pin'
    $Z3Pin.msvcToolset = '14.44'
    $count++

    # Exercise the command boundary: target changes must clear a prior library,
    # and source feature/config options must reach Cargo rather than the harness.
    $function = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-VsCargo' }, $true)
    Invoke-Expression $function.Extent.Text
    $UserZ3Environment = @{ Z3_LIBRARY_PATH_OVERRIDE = $null; Z3_SYS_Z3_HEADER = $null; Z3_SRC_SOURCE_DIR = $null }
    $StaticRuntime = $true
    $WindowsBuildJobs = 2
    $TargetDir = Join-Path $fixture 'cargo-target'
    $LogDir = $fixture
    $WindowsCargoMutex = [Threading.Mutex]::new($false)
    $script:forceSource = $false
    $script:commands = @()
    $script:libraries = @()
    function Configure-Z3([string[]] $RustTargets) {
        if ($env:Z3_LIBRARY_PATH_OVERRIDE) { throw 'A previous target leaked its Z3 library' }
        $env:Z3_LIBRARY_PATH_OVERRIDE = "C:\z3\$($RustTargets[0])\lib"
        $feature = if ($script:forceSource) { '--features openshell-prover/vendored-z3' } else { '' }
        return [pscustomobject]@{ FromSource = $script:forceSource; WorkspaceFeatures = $feature; ServerFeatures = $feature; GatewayFeatures = $feature }
    }
    function rustup { $global:LASTEXITCODE = 0 }
    function Resolve-VsDevCmd([string] $RustTarget) { return 'C:\vs\VsDevCmd.bat' }
    function Get-VsTargetArch([string] $RustTarget) { if ($RustTarget -eq 'aarch64-pc-windows-msvc') { return 'arm64' }; return 'amd64' }
    function Get-HostArch { return 'amd64' }
    function Resolve-NinjaPath { return 'C:\tools\ninja.exe' }
    function Add-PathEntry([string] $Directory) { }
    function Reset-WindowsCMakeGeneratorCache([string] $RustTarget) { }
    function cmd {
        $script:commands += $args[-1]
        $script:libraries += $env:Z3_LIBRARY_PATH_OVERRIDE
        $global:LASTEXITCODE = 0
    }
    try {
        foreach ($rustTarget in @('x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc')) {
            Invoke-VsCargo -RustTarget $rustTarget -CargoArgs "cargo build --target $rustTarget" -LogName "$rustTarget.log"
        }
        if ($script:libraries[0] -eq $script:libraries[1] -or $script:libraries[1] -notlike '*aarch64-pc-windows-msvc*') { throw 'Cargo targets did not resolve separate Z3 packages' }
        $count++
        $script:forceSource = $true
        Invoke-VsCargo -RustTarget $target -CargoArgs 'cargo clippy --workspace -- -D warnings' -LogName 'clippy.log'
        if ($script:commands[-1] -notmatch '--features openshell-prover/vendored-z3 -- -D warnings') { throw 'Source feature reached the Clippy arguments instead of Cargo' }
        $count++
        Invoke-VsCargo -RustTarget $target -CargoArgs 'cargo nextest run --workspace' -LogName 'nextest.log'
        if ($script:commands[-1] -notmatch 'cargo nextest run --config ' -or $script:commands[-1] -notmatch 'windows-static.toml') { throw 'Nextest did not receive static/source Cargo configuration' }
        $count++
    } finally { $WindowsCargoMutex.Dispose() }
} finally { Remove-Item -LiteralPath $fixture -Recurse -Force }
Write-Host "$count pinned Z3 OCI download/cache/integrity checks passed."
