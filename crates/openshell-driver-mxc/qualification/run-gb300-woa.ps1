# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Execute the NVBug 6643699 GB300 native Windows ARM64 qualification contract.
# Evidence is written outside the checkout and hash-bound by validate.py.

[CmdletBinding()]
param(
    [string] $ExpectedBaseSha = $env:OPENSHELL_GB300_BASE_SHA,
    [string] $WxcExecPath = $env:OPENSHELL_WXC_EXEC_PATH,
    [string] $NodeExePath = $env:OPENSHELL_GB300_NODE_PATH,
    [string] $OpenClawInstallDir = $env:OPENSHELL_GB300_OPENCLAW_DIR,
    [string] $EvidenceDir = $env:OPENSHELL_GB300_EVIDENCE_DIR,
    [ValidateSet("GB300")]
    [string] $Hardware = $env:OPENSHELL_GB300_HARDWARE_ATTESTATION
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$ManifestPath = Join-Path $PSScriptRoot "gb300-woa.json"
$ValidatorPath = Join-Path $PSScriptRoot "validate.py"
$WindowsWrapper = Join-Path $RepoRoot "tasks\scripts\windows-msvc.ps1"
$ExampleSource = Join-Path $RepoRoot "crates\openshell-driver-mxc\examples"
$RustTarget = "aarch64-pc-windows-msvc"
$PowerShellExe = (Get-Process -Id $PID).Path
$Durations = @{}

if ([string]::IsNullOrWhiteSpace($EvidenceDir)) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $EvidenceDir = Join-Path $env:TEMP "openshell-gb300-qualification-$stamp"
}
$EvidenceDir = [System.IO.Path]::GetFullPath($EvidenceDir)
$repoPrefix = $RepoRoot.TrimEnd('\') + '\'
if ($EvidenceDir.StartsWith($repoPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "EvidenceDir must be outside the source checkout: $RepoRoot"
}
if (Test-Path $EvidenceDir) {
    if (@(Get-ChildItem -LiteralPath $EvidenceDir -Force).Count -gt 0) {
        throw "EvidenceDir must be new or empty: $EvidenceDir"
    }
} else {
    New-Item -ItemType Directory -Path $EvidenceDir | Out-Null
}
$EvidenceDir = (Resolve-Path $EvidenceDir).Path

function Invoke-LoggedProcess(
    [string] $CoverageId,
    [string] $LogName,
    [string] $FilePath,
    [string[]] $Arguments
) {
    $logPath = Join-Path $EvidenceDir $LogName
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Host "==> $CoverageId"
    Write-Host "    log: $logPath"
    $savedErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $FilePath @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }
    $timer.Stop()
    $Durations[$CoverageId] = [Math]::Round($timer.Elapsed.TotalSeconds, 3)
    @($output | ForEach-Object { $_.ToString() }) | Out-File -FilePath $logPath -Encoding utf8
    @($output) | ForEach-Object { Write-Host $_ }
    if ($exitCode -ne 0) {
        throw "$CoverageId failed with exit code $exitCode. See $logPath"
    }
}

function Invoke-Git([string[]] $Arguments) {
    $savedErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & git -C $RepoRoot @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }
    if ($exitCode -ne 0) {
        throw "git $($Arguments -join ' ') failed: $($output -join [Environment]::NewLine)"
    }
    return @($output | ForEach-Object { $_.ToString() })
}

function Assert-Arm64Pe([string] $Path, [string] $Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label was not found: $Path"
    }
    $stream = [System.IO.File]::OpenRead((Resolve-Path -LiteralPath $Path).Path)
    try {
        $reader = New-Object System.IO.BinaryReader($stream)
        try {
            $stream.Position = 0x3c
            $peOffset = $reader.ReadInt32()
            $stream.Position = $peOffset + 4
            $machine = $reader.ReadUInt16()
        } finally {
            $reader.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
    if ($machine -ne 0xaa64) {
        throw "$Label must be an ARM64 PE (machine 0xAA64); found 0x$($machine.ToString('X4')) at $Path"
    }
}

function Write-Json([object] $Value, [string] $Path) {
    $Value | ConvertTo-Json -Depth 20 | Out-File -FilePath $Path -Encoding utf8
}

function Get-Sha256([string] $Path) {
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            return [BitConverter]::ToString($sha256.ComputeHash($stream)).Replace("-", "").ToLowerInvariant()
        } finally {
            $sha256.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

function Get-DirectorySha256([string] $Path) {
    $root = (Resolve-Path -LiteralPath $Path).Path.TrimEnd('\') + '\'
    $entries = @(
        Get-ChildItem -LiteralPath $Path -File -Recurse -Force | ForEach-Object {
            [pscustomobject]@{
                RelativePath = $_.FullName.Substring($root.Length).Replace('\', '/')
                Sha256 = Get-Sha256 $_.FullName
            }
        } | Sort-Object RelativePath
    )
    if ($entries.Count -eq 0) {
        throw "Package directory contains no files: $Path"
    }
    $manifest = (($entries | ForEach-Object { "$($_.RelativePath)`0$($_.Sha256)" }) -join "`n") + "`n"
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($manifest)
        return [BitConverter]::ToString($sha256.ComputeHash($bytes)).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

function New-EvidenceArtifact([string] $Role, [string] $Path) {
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $evidencePrefix = $EvidenceDir.TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($evidencePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Artifact is outside EvidenceDir: $resolved"
    }
    $relative = $resolved.Substring($evidencePrefix.Length).Replace('\', '/')
    return [ordered]@{
        role = $Role
        path = $relative
        sha256 = Get-Sha256 $resolved
    }
}

if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
    [System.Runtime.InteropServices.OSPlatform]::Windows
)) {
    throw "GB300 qualification requires Windows."
}
$osArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
$processArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
if ($osArchitecture -ne "Arm64" -or $processArchitecture -ne "Arm64") {
    throw "GB300 qualification requires native ARM64; OS=$osArchitecture process=$processArchitecture"
}
if ($env:WSL_DISTRO_NAME -or $env:WSL_INTEROP) {
    throw "WSL cannot satisfy the native GB300 Windows ARM64 contract."
}
if ($Hardware -ne "GB300") {
    throw "Set OPENSHELL_GB300_HARDWARE_ATTESTATION=GB300 or pass -Hardware GB300 after verifying the host."
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run the qualification from an elevated PowerShell session."
}
if ([string]::IsNullOrWhiteSpace($WxcExecPath)) {
    throw "Set OPENSHELL_WXC_EXEC_PATH or pass -WxcExecPath."
}
if ([string]::IsNullOrWhiteSpace($NodeExePath)) {
    throw "Set OPENSHELL_GB300_NODE_PATH to a native ARM64 node.exe or pass -NodeExePath."
}
if ([string]::IsNullOrWhiteSpace($OpenClawInstallDir)) {
    throw "Set OPENSHELL_GB300_OPENCLAW_DIR or pass -OpenClawInstallDir."
}
$WxcExecPath = (Resolve-Path -LiteralPath $WxcExecPath).Path
$NodeExePath = (Resolve-Path -LiteralPath $NodeExePath).Path
$OpenClawInstallDir = (Resolve-Path -LiteralPath $OpenClawInstallDir).Path
if (-not (Test-Path -LiteralPath (Join-Path $OpenClawInstallDir "openclaw.mjs") -PathType Leaf)) {
    throw "OpenClawInstallDir must directly contain openclaw.mjs: $OpenClawInstallDir"
}
Assert-Arm64Pe $WxcExecPath "wxc-exec"
Assert-Arm64Pe $NodeExePath "Node.js"

$sourceTimer = [System.Diagnostics.Stopwatch]::StartNew()
if ([string]::IsNullOrWhiteSpace($ExpectedBaseSha)) {
    throw "ExpectedBaseSha is required. Set OPENSHELL_GB300_BASE_SHA to the reviewed origin/windows commit."
}
if ($ExpectedBaseSha -notmatch '^[0-9a-f]{40}$') {
    throw "ExpectedBaseSha must be a full lowercase Git SHA."
}
$originUrl = (@(Invoke-Git @("remote", "get-url", "origin")))[0].Trim()
$normalizedOriginUrl = $originUrl.TrimEnd('/').ToLowerInvariant()
$canonicalOriginUrls = @(
    "https://github.com/nvidia/openshell.git",
    "https://github.com/nvidia/openshell",
    "git@github.com:nvidia/openshell.git",
    "ssh://git@github.com/nvidia/openshell.git"
)
if ($canonicalOriginUrls -notcontains $normalizedOriginUrl) {
    throw "origin must be the canonical NVIDIA/OpenShell GitHub repository; found: $originUrl"
}
Invoke-Git @("fetch", "--prune", "origin", "windows") | ForEach-Object { Write-Host $_ }
$fetchedBaseSha = (@(Invoke-Git @("rev-parse", "refs/remotes/origin/windows")))[0].Trim()
if ($fetchedBaseSha -ne $ExpectedBaseSha) {
    throw "origin/windows moved: expected $ExpectedBaseSha, fetched $fetchedBaseSha"
}
$headSha = (@(Invoke-Git @("rev-parse", "HEAD")))[0].Trim()
$mergeBase = (@(Invoke-Git @("merge-base", "HEAD", "refs/remotes/origin/windows")))[0].Trim()
if ($mergeBase -ne $ExpectedBaseSha) {
    throw "HEAD is not based directly on the expected origin/windows tip: merge-base=$mergeBase expected=$ExpectedBaseSha"
}
$worktreeStatus = @(Invoke-Git @("status", "--porcelain=v1"))
if ($worktreeStatus.Count -gt 0 -and ($worktreeStatus -join '').Trim()) {
    throw "Qualification requires a clean worktree. Commit or preserve changes first."
}
$sourceTimer.Stop()
$Durations["source-provenance"] = [Math]::Round($sourceTimer.Elapsed.TotalSeconds, 3)

$uv = Get-Command uv -ErrorAction Stop
Invoke-LoggedProcess "contract-integrity" "contract-validation.log" $uv.Source @(
    "run", "python", $ValidatorPath, "contract"
)

$probePath = Join-Path $ExampleSource "probe-mxc-host.ps1"
$probeReport = Join-Path $EvidenceDir "mxc-host-capabilities.json"
Invoke-LoggedProcess "gb300-arm64-host" "mxc-host-probe.log" $PowerShellExe @(
    "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $probePath,
    "-WxcExecPath", $WxcExecPath, "-OutFile", $probeReport, "-Full"
)
$probe = Get-Content -LiteralPath $probeReport -Raw | ConvertFrom-Json
if ($probe.verdicts.processcontainer -ne "live" -or $probe.verdicts.dryRun -ne "ok") {
    throw "MXC preflight must report processcontainer=live and dryRun=ok. See $probeReport"
}

$openClawSnapshotDir = Join-Path $EvidenceDir "openclaw-package"
New-Item -ItemType Directory -Path $openClawSnapshotDir | Out-Null
Get-ChildItem -LiteralPath $OpenClawInstallDir -Force | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination $openClawSnapshotDir -Recurse -Force
}
$OpenClawInstallDir = (Resolve-Path -LiteralPath $openClawSnapshotDir).Path
if (-not (Test-Path -LiteralPath (Join-Path $OpenClawInstallDir "openclaw.mjs") -PathType Leaf)) {
    throw "The staged OpenClaw package must directly contain openclaw.mjs: $OpenClawInstallDir"
}

$packageJsonPath = Join-Path $OpenClawInstallDir "package.json"
if (-not (Test-Path -LiteralPath $packageJsonPath -PathType Leaf)) {
    throw "OpenClawInstallDir must contain a versioned package.json: $OpenClawInstallDir"
}
try {
    $openClawPackage = Get-Content -LiteralPath $packageJsonPath -Raw | ConvertFrom-Json
    $openClawVersion = [string]$openClawPackage.version
} catch {
    throw "OpenClaw package.json is invalid or has no version: $packageJsonPath"
}
if ([string]::IsNullOrWhiteSpace($openClawVersion)) {
    throw "OpenClaw package.json must declare a non-empty version: $packageJsonPath"
}
$openClawPackageSha256 = Get-DirectorySha256 $OpenClawInstallDir
$environmentPath = Join-Path $EvidenceDir "environment.json"
$environment = [ordered]@{
    contract_id = "nvbug-6643699-gb300-woa-mxc"
    captured_at = (Get-Date).ToUniversalTime().ToString("o")
    hardware = $Hardware
    operating_system = "windows"
    os_version = [System.Environment]::OSVersion.Version.ToString()
    os_architecture = $osArchitecture
    process_architecture = $processArchitecture
    native = $true
    wsl = $false
    elevated = $true
    origin_url = $originUrl
    base_ref = "refs/remotes/origin/windows"
    base_sha = $ExpectedBaseSha
    head_sha = $headSha
    merge_base = $mergeBase
    worktree_clean = $true
    rust_version = (& rustc --version).ToString()
    node_version = (& $NodeExePath --version).ToString()
    openclaw_version = $openClawVersion
    openclaw_package_sha256 = $openClawPackageSha256
    openclaw_package_json_sha256 = Get-Sha256 $packageJsonPath
    wxc_exec_path = $WxcExecPath
    wxc_exec_sha256 = Get-Sha256 $WxcExecPath
    node_path = $NodeExePath
    node_sha256 = Get-Sha256 $NodeExePath
}
Write-Json $environment $environmentPath

$env:OPENSHELL_WXC_EXEC_PATH = $WxcExecPath
$commonWrapperArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $WindowsWrapper)
Invoke-LoggedProcess "arm64-msvc-check" "arm64-check-command.log" $PowerShellExe @(
    $commonWrapperArgs + @("check", $RustTarget, "-LogDir", $EvidenceDir)
)
Invoke-LoggedProcess "arm64-release-build" "arm64-build-command.log" $PowerShellExe @(
    $commonWrapperArgs + @("build", $RustTarget, "-LogDir", $EvidenceDir)
)
Invoke-LoggedProcess "arm64-native-tests" "arm64-tests-command.log" $PowerShellExe @(
    $commonWrapperArgs + @("test-precommit", $RustTarget, "-LogDir", $EvidenceDir)
)
Invoke-LoggedProcess "arm64-unsupported-driver-contracts" "arm64-unsupported.log" $PowerShellExe @(
    $commonWrapperArgs + @("test-unsupported", $RustTarget, "-LogDir", $EvidenceDir)
)
Invoke-LoggedProcess "processcontainer-real-mxc" "strict-real-mxc.log" $PowerShellExe @(
    $commonWrapperArgs + @("test-mxc-gb300", $RustTarget, "-LogDir", $EvidenceDir)
)

$targetRoot = $env:CARGO_TARGET_DIR
if ([string]::IsNullOrWhiteSpace($targetRoot)) {
    $targetRoot = Join-Path $RepoRoot "target"
} elseif (-not [System.IO.Path]::IsPathRooted($targetRoot)) {
    $targetRoot = Join-Path $RepoRoot $targetRoot
}
$releaseDir = Join-Path $targetRoot "$RustTarget\release"
$binaryRows = @()
foreach ($binary in @("openshell-gateway.exe", "openshell.exe", "openshell-supervisor-relay.exe", "libz3.dll")) {
    $path = Join-Path $releaseDir $binary
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required ARM64 release artifact is missing: $path"
    }
    $item = Get-Item -LiteralPath $path
    $binaryRows += [ordered]@{
        name = $binary
        path = $item.FullName
        size = $item.Length
        sha256 = Get-Sha256 $path
    }
}
$binaryManifestPath = Join-Path $EvidenceDir "arm64-binary-manifest.json"
Write-Json $binaryRows $binaryManifestPath

$packageDir = Join-Path $EvidenceDir "package"
New-Item -ItemType Directory -Path $packageDir | Out-Null
$examplePrefix = "crates/openshell-driver-mxc/examples/"
$trackedExamples = @(Invoke-Git @("ls-files", "--", "$examplePrefix*"))
foreach ($relative in $trackedExamples) {
    $packageRelative = $relative.Substring($examplePrefix.Length)
    $destination = Join-Path $packageDir $packageRelative
    $destinationParent = Split-Path -Parent $destination
    if (-not (Test-Path $destinationParent)) {
        New-Item -ItemType Directory -Force -Path $destinationParent | Out-Null
    }
    Copy-Item -LiteralPath (Join-Path $RepoRoot $relative) -Destination $destination
}
foreach ($binary in $binaryRows) {
    Copy-Item -LiteralPath $binary.path -Destination (Join-Path $packageDir $binary.name)
}

$runStamp = Get-Date -Format "yyyyMMddHHmmss"
$mxcWorkDir = "C:\osq-mxc-$runStamp-$PID"
$openClawShareDir = "C:\osq-claw-$runStamp-$PID"
$mxcRunner = Join-Path $packageDir "run-mxc-e2e.ps1"
Invoke-LoggedProcess "processcontainer-policy-e2e" "mxc-policy-e2e.log" $PowerShellExe @(
    "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $mxcRunner,
    "-WxcExecPath", $WxcExecPath, "-Backend", "process_container", "-DemoDir", $mxcWorkDir
)
$mxcLog = Get-Content -LiteralPath (Join-Path $EvidenceDir "mxc-policy-e2e.log") -Raw
if ($mxcLog -notmatch 'PASS=4\s+FAIL=0\s+SKIP=0') {
    throw "The required MXC E2E scenarios did not report PASS=4 FAIL=0 SKIP=0."
}
$mxcBundle = Get-ChildItem -LiteralPath $packageDir -Filter "results-e2e-*.zip" -File |
    Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
if (-not $mxcBundle) {
    throw "The MXC E2E runner did not produce a results bundle."
}
$mxcBundlePath = Join-Path $EvidenceDir "mxc-policy-e2e.zip"
Copy-Item -LiteralPath $mxcBundle.FullName -Destination $mxcBundlePath

$openClawRunner = Join-Path $packageDir "run-openclaw-forward-test.ps1"
$openClawPreRunSha256 = Get-DirectorySha256 $OpenClawInstallDir
if ($openClawPreRunSha256 -ne $openClawPackageSha256) {
    throw "The staged OpenClaw package changed before execution: expected $openClawPackageSha256, found $openClawPreRunSha256"
}
Invoke-LoggedProcess "openclaw-arm64-forward" "openclaw-forward.log" $PowerShellExe @(
    "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $openClawRunner,
    "-Backend", "process_container", "-WxcExecPath", $WxcExecPath,
    "-NodeExePath", $NodeExePath, "-OpenClawInstallDir", $OpenClawInstallDir,
    "-ShareDir", $openClawShareDir
)
$openClawPostRunSha256 = Get-DirectorySha256 $OpenClawInstallDir
if ($openClawPostRunSha256 -ne $openClawPackageSha256) {
    throw "The staged OpenClaw package changed during execution: expected $openClawPackageSha256, found $openClawPostRunSha256"
}
$openClawBundle = Get-ChildItem -LiteralPath $packageDir -Filter "results-openclaw-forward-*.zip" -File |
    Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
if (-not $openClawBundle) {
    throw "The OpenClaw runner did not produce a results bundle."
}
$openClawBundlePath = Join-Path $EvidenceDir "openclaw-forward.zip"
Copy-Item -LiteralPath $openClawBundle.FullName -Destination $openClawBundlePath

$requiredArtifacts = @{
    "contract-integrity" = @(
        New-EvidenceArtifact "contract_validation_log" (Join-Path $EvidenceDir "contract-validation.log")
    )
    "source-provenance" = @(
        New-EvidenceArtifact "environment_and_source_provenance" $environmentPath
    )
    "gb300-arm64-host" = @(
        New-EvidenceArtifact "environment_and_source_provenance" $environmentPath
        New-EvidenceArtifact "mxc_host_capabilities" $probeReport
        New-EvidenceArtifact "mxc_host_probe_log" (Join-Path $EvidenceDir "mxc-host-probe.log")
    )
    "arm64-msvc-check" = @(
        New-EvidenceArtifact "arm64_check_log" (Join-Path $EvidenceDir "build-$RustTarget-check.log")
    )
    "arm64-release-build" = @(
        New-EvidenceArtifact "arm64_build_log" (Join-Path $EvidenceDir "build-$RustTarget-release.log")
        New-EvidenceArtifact "arm64_binary_manifest" $binaryManifestPath
    )
    "arm64-native-tests" = @(
        New-EvidenceArtifact "arm64_test_log" (Join-Path $EvidenceDir "test-$RustTarget-precommit.log")
    )
    "arm64-unsupported-driver-contracts" = @(
        New-EvidenceArtifact "unsupported_driver_contract_log" (Join-Path $EvidenceDir "arm64-unsupported.log")
    )
    "processcontainer-real-mxc" = @(
        New-EvidenceArtifact "strict_real_mxc_log" (Join-Path $EvidenceDir "strict-real-mxc.log")
    )
    "processcontainer-policy-e2e" = @(
        New-EvidenceArtifact "mxc_policy_e2e_log" (Join-Path $EvidenceDir "mxc-policy-e2e.log")
        New-EvidenceArtifact "mxc_policy_e2e_bundle" $mxcBundlePath
    )
    "openclaw-arm64-forward" = @(
        New-EvidenceArtifact "openclaw_forward_log" (Join-Path $EvidenceDir "openclaw-forward.log")
        New-EvidenceArtifact "openclaw_forward_bundle" $openClawBundlePath
    )
}
$contract = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
$results = @()
foreach ($row in $contract.matrix) {
    if ($row.disposition -eq "required") {
        $duration = $Durations[$row.id]
        if ($null -eq $duration) { $duration = 0 }
        $results += [ordered]@{
            coverage_id = $row.id
            status = "pass"
            architecture = "arm64"
            command = ($row.commands -join " ; ")
            exit_code = 0
            skip_count = 0
            duration_seconds = $duration
            artifacts = @($requiredArtifacts[$row.id])
        }
    } elseif ($row.disposition -eq "optional") {
        $results += [ordered]@{
            coverage_id = $row.id
            status = "not_run"
            reason = "Optional coverage was not selected for this required GB300 ProcessContainer gate."
            artifacts = @()
        }
    } else {
        $results += [ordered]@{
            coverage_id = $row.id
            status = "not_applicable"
            reason = $row.reason
            artifacts = @()
        }
    }
}
$recordPath = Join-Path $EvidenceDir "evidence.json"
$record = [ordered]@{
    schema_version = 1
    contract_id = "nvbug-6643699-gb300-woa-mxc"
    base_sha = $ExpectedBaseSha
    head_sha = $headSha
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    environment = [ordered]@{
        operating_system = "windows"
        architecture = "arm64"
        native = $true
        wsl = $false
        hardware = $Hardware
    }
    results = $results
}
Write-Json $record $recordPath
Invoke-LoggedProcess "evidence-validation" "evidence-validation.log" $uv.Source @(
    "run", "python", $ValidatorPath, "evidence", "--record", $recordPath,
    "--artifact-root", $EvidenceDir, "--expected-base-sha", $ExpectedBaseSha
)

Write-Host "PASS: complete GB300 Windows ARM64 MXC evidence is valid."
Write-Host "Evidence: $EvidenceDir"
