// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Selectively ported Windows policy and harness regressions. These are not
//! substitutes for real MXC WebSocket, `OpenClaw`, or inference runtime coverage.
#![cfg(target_os = "windows")]

use std::path::{Path, PathBuf};
use std::process::Command;

use openshell_core::proto::{NetworkAccessPreset, NetworkEnforcementMode, SandboxPolicy};
use openshell_driver_mxc::{EmbeddedPolicyMapper, MapCtx, MappedConfig, PolicyMapper};
use openshell_policy::{parse_sandbox_policy, validate_sandbox_policy};

fn examples() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples")
}

fn map_fixture(yaml: &str) -> (SandboxPolicy, MappedConfig) {
    let policy = parse_sandbox_policy(yaml).expect("valid authored policy");
    validate_sandbox_policy(&policy).expect("valid policy semantics");
    let mapped = EmbeddedPolicyMapper
        .map(
            Some(&policy),
            &MapCtx {
                sandbox_id: "windows-policy-fixture".into(),
                egress: Some("127.0.0.1:18080".parse().unwrap()),
                containment: "processcontainer".into(),
            },
        )
        .expect("policy maps with supervisor-owned egress");
    (policy, mapped)
}

#[test]
fn websocket_fixture_grants_read_only_workload_without_egress() {
    let yaml = std::fs::read_to_string(examples().join("e2e-policies/ws-agent.yaml")).unwrap();
    let (policy, mapped) = map_fixture(&yaml);
    assert!(policy.network_policies.is_empty());
    assert_eq!(mapped.readonly_paths, [r"C:\work\openshell-mxc-ws"]);
    assert!(mapped.readwrite_paths.is_empty());
    assert!(mapped.ui.unwrap().disable);
}

#[test]
fn https_fixture_authorizes_direct_curl_with_read_only_https() {
    let yaml = std::fs::read_to_string(examples().join("e2e-policies/https-ca.yaml"))
        .unwrap()
        .replace("__CURL_EXE__", r"C:\Windows\System32\curl.exe");
    let (policy, mapped) = map_fixture(&yaml);
    let rule = &policy.network_policies["https_example"];
    assert_eq!(rule.binaries[0].path, r"C:\Windows\System32\curl.exe");
    assert_eq!(rule.endpoints[0].host, "example.com");
    assert_eq!(rule.endpoints[0].ports, [443]);
    assert_eq!(
        rule.endpoints[0].access,
        NetworkAccessPreset::ReadOnly as i32
    );
    assert_eq!(
        rule.endpoints[0].enforcement,
        NetworkEnforcementMode::Enforce as i32
    );
    assert_eq!(
        mapped.trimmed_policy.unwrap().network_policies,
        policy.network_policies
    );
}

#[test]
fn host_service_scoring_records_success_and_rejects_false_responses() {
    let root = tempfile::tempdir().unwrap();
    let script = r#"
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:OPENSHELL_MXC_RUNNER, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw "runner parse errors: $($errors.Message -join '; ')" }
foreach ($name in @('Quote-NativeArgument', 'Invoke-NativeCaptured', 'Wait-File', 'Write-HostServiceBatch', 'Test-HostServiceResult')) {
    $helper = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if (!$helper) { throw "missing $name" }
    Invoke-Expression $helper.Extent.Text
}
$work = Join-Path $env:OPENSHELL_MXC_SCORE_ROOT 'work with spaces'
New-Item -ItemType Directory $work | Out-Null
$requestLog = Join-Path $env:OPENSHELL_MXC_SCORE_ROOT 'host.requests'
$nonce = 'unique-host-service-response'
$batch = Join-Path $work 'host-service.cmd'
Write-HostServiceBatch $batch 'C:/Windows/System32/curl.exe' 'http://127.0.0.1:49152' $work $nonce
$recordLine = @(Get-Content -LiteralPath $batch | Where-Object { $_.StartsWith('echo %errorlevel%') })[0]
foreach ($code in @(0, 22)) {
    $probeBatch = Join-Path $work 'record-exit.cmd'
    Set-Content -LiteralPath $probeBatch -Encoding ASCII -Value ("@echo off`r`ncmd.exe /d /c exit $code`r`n$recordLine`r`nexit /b 0")
    $result = Invoke-NativeCaptured 'cmd.exe' @('/d', '/c', $probeBatch) 10
    if ($result.ExitCode -ne 0) { throw "batch exit probe failed: $($result.Output -join '; ')" }
    $recorded = Get-Content -LiteralPath (Join-Path $work 'host-service.one.exit') -Raw
    if (!$recorded -or $recorded.Trim() -ne "$code") { throw "generated batch failed to record curl exit $code" }
}
function Reset-Proofs {
    foreach ($name in @('one', 'two')) {
        [IO.File]::WriteAllText((Join-Path $work "host-service.$name.body"), "${nonce}:/$name")
        [IO.File]::WriteAllText((Join-Path $work "host-service.$name.exit"), '0')
    }
    [IO.File]::WriteAllText((Join-Path $work 'host-service.done'), $nonce)
    [IO.File]::WriteAllText($requestLog, "/health`n/one`n/two`n")
}
Reset-Proofs
if ((Test-HostServiceResult $work $nonce $requestLog) -notmatch '127.0.0.1') { throw 'valid host-service run must pass' }
foreach ($case in @('transport', 'unexpected-request', 'wrong-response', 'wrong-workload')) {
    Reset-Proofs
    switch ($case) {
        'transport' {
            [IO.File]::WriteAllText((Join-Path $work 'host-service.one.exit'), '7')
        }
        'unexpected-request' { [IO.File]::AppendAllText($requestLog, "/unexpected`n") }
        'wrong-response' { [IO.File]::WriteAllText((Join-Path $work 'host-service.one.body'), 'unrelated service') }
        'wrong-workload' { [IO.File]::WriteAllText((Join-Path $work 'host-service.done'), 'stale-run') }
    }
    $rejected = $false
    try { Test-HostServiceResult $work $nonce $requestLog | Out-Null } catch { $rejected = $true }
    if (!$rejected) { throw "invalid run $case must fail" }
}
"#;
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", script])
        .env("OPENSHELL_MXC_RUNNER", examples().join("run-mxc-e2e.ps1"))
        .env("OPENSHELL_MXC_SCORE_ROOT", root.path())
        .output()
        .expect("launch PowerShell host-service regression");
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn openclaw_fixture_preserves_explicit_ui_and_node_network_grants() {
    let yaml =
        std::fs::read_to_string(examples().join("e2e-policies/openclaw-gateway.yaml")).unwrap();
    let (policy, mapped) = map_fixture(&yaml);
    assert_eq!(mapped.readwrite_paths, [r"C:\openshell-openclaw"]);
    assert!(mapped.readonly_paths.is_empty());
    let ui = mapped.ui.unwrap();
    assert!(!ui.disable);
    assert!(!ui.injection);
    let config = openshell_driver_mxc::map_to_mxc(
        &policy,
        &openshell_driver_mxc::MxcMappingOptions::default(),
    );
    assert_eq!(config.config["ui"]["clipboard"], "none");
    let rule = &policy.network_policies["qualification_allowed"];
    assert_eq!(rule.binaries[0].path, "C:/openshell-openclaw/node.exe");
    assert_eq!(rule.endpoints[0].host, "example.com");
    assert_eq!(rule.endpoints[0].ports, [443]);
    assert_eq!(
        mapped.trimmed_policy.unwrap().network_policies,
        policy.network_policies
    );
}

#[test]
fn inference_template_authorizes_socket_owning_curl_not_cmd() {
    let yaml = std::fs::read_to_string(examples().join("inference.yaml"))
        .unwrap()
        .replace("__OPENSHELL_DEMO_SHARE__", "C:/work/inference")
        .replace("__CURL_EXE__", r"C:\Windows\System32\curl.exe")
        .replace("__INFERENCE_HOST__", "integrate.api.nvidia.com")
        .replace("__INFERENCE_PORT__", "443");
    assert!(!yaml.contains("__"));
    let (policy, mapped) = map_fixture(&yaml);
    assert_eq!(mapped.readwrite_paths, [r"C:\work\inference"]);
    let rule = &policy.network_policies["nvidia_inference"];
    assert_eq!(rule.binaries.len(), 1);
    assert_eq!(rule.binaries[0].path, r"C:\Windows\System32\curl.exe");
    let endpoint = &rule.endpoints[0];
    assert_eq!(endpoint.access, NetworkAccessPreset::ReadWrite as i32);
    assert_eq!(endpoint.enforcement, NetworkEnforcementMode::Enforce as i32);
    assert_eq!(endpoint.protocol, "rest");
    assert_eq!(
        mapped.trimmed_policy.unwrap().network_policies,
        policy.network_policies
    );
}

#[test]
fn runners_isolate_and_restore_exact_process_environment() {
    // Parse the actual runners, but execute only their environment helpers:
    // no gateway, executor, firewall, ETW session, or caller CLI state is touched.
    let script = r#"
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:OPENSHELL_MXC_RUNNER, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "runner parse errors: $($errors.Message -join '; ')" }
foreach ($functionName in @("Set-ProcessEnvironmentVariableExact", "Enter-IsolatedCliEnvironment", "Exit-IsolatedCliEnvironment")) {
    $function = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName
    }, $true)
    if ($null -eq $function) { throw "missing $functionName" }
    Invoke-Expression $function.Extent.Text
}
$cliStateRoot = $null
$cliEnvironmentSnapshot = @{}
$cliEnvironmentNames = @(
    "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME",
    "OPENSHELL_GATEWAY", "OPENSHELL_GATEWAY_ENDPOINT", "OPENSHELL_GATEWAY_INSECURE",
    "OPENSHELL_GATEWAY_CONFIG", "OPENSHELL_GATEWAY_NAME")
$KeepRunning = $false
$gw = $null
$before = [Environment]::GetEnvironmentVariables("Process")
if (-not $before.Contains("OPENSHELL_GATEWAY") -or ([string]$before["OPENSHELL_GATEWAY"]).Length -ne 0) {
    throw "empty entry was not inherited"
}
Enter-IsolatedCliEnvironment
try {
    $isolated = [Environment]::GetEnvironmentVariables("Process")
    foreach ($name in $cliEnvironmentNames) {
        if ($name.StartsWith("OPENSHELL_")) {
            if ($isolated.Contains($name)) { throw "$name not removed" }
        } elseif (-not ([string]$isolated[$name]).StartsWith($cliStateRoot)) {
            throw "$name not isolated"
        }
    }
} finally { Exit-IsolatedCliEnvironment }
$after = [Environment]::GetEnvironmentVariables("Process")
foreach ($name in $cliEnvironmentNames) {
    if ($before.Contains($name) -ne $after.Contains($name) -or $before[$name] -cne $after[$name]) {
        throw "environment entry $name not restored exactly"
    }
}
if (Test-Path -LiteralPath $cliStateRoot) { throw "temporary state not removed" }
"#;
    for runner in ["run-mxc-e2e.ps1", "run-ocsf-audit.ps1"] {
        let output = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ])
            .env("OPENSHELL_MXC_RUNNER", examples().join(runner))
            .env("OPENSHELL_GATEWAY", "")
            .env("OPENSHELL_GATEWAY_ENDPOINT", "http://127.0.0.1:1")
            .env_remove("OPENSHELL_GATEWAY_NAME")
            .output()
            .expect("launch Windows PowerShell");
        assert!(
            output.status.success(),
            "{runner} environment regression failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn windows_static_runtime_and_dependency_selection() {
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(examples().join("../../../tasks/scripts/windows-runtime-tests.ps1"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Windows dependency/runtime regression failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn windows_build_stages_only_unambiguous_target_matching_z3() {
    // Synthetic PE headers exercise packaging checks, not MXC containment.
    let root = tempfile::tempdir().unwrap();
    let script = r#"
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:OPENSHELL_BUILD_SCRIPT, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw "build script parse errors: $($errors.Message -join '; ')" }
foreach ($name in @('Get-Sha256', 'Stage-Z3Runtime')) {
    $function = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if ($null -eq $function) { throw "missing function: $name" }
    Invoke-Expression $function.Extent.Text
}
# Mise's Windows PowerShell may not expose this module cmdlet. Packaging must
# retain its checksum checks without depending on it.
function Get-FileHash { throw 'Get-FileHash must not be used' }
$TargetDir = $env:OPENSHELL_TEST_ROOT
$PrebuiltZ3Version = '5.1.0'
$env:Z3_LIBRARY_PATH_OVERRIDE = $null
$release = Join-Path $TargetDir 'aarch64-pc-windows-msvc/release'
$sourceDir = Join-Path $release 'build/z3-sys-first/out/z3-5.1.0/bin'
New-Item -ItemType Directory -Path $sourceDir -Force | Out-Null
$source = Join-Path $sourceDir 'libz3.dll'
$bytes = New-Object byte[] 128
$bytes[0] = 0x4D; $bytes[1] = 0x5A; $bytes[60] = 64
$bytes[64] = 0x50; $bytes[65] = 0x45
$bytes[68] = 0x64; $bytes[69] = 0xAA
[IO.File]::WriteAllBytes($source, $bytes)
Stage-Z3Runtime 'aarch64-pc-windows-msvc'
$destination = Join-Path $release 'libz3.dll'
if ((Get-Sha256 $destination) -ne (Get-Sha256 $source)) { throw 'copy mismatch' }
# A stale adjacent DLL must be overwritten from the pinned cache.
[IO.File]::WriteAllBytes($destination, (New-Object byte[] 128))
Stage-Z3Runtime 'aarch64-pc-windows-msvc'
if ((Get-Sha256 $destination) -ne (Get-Sha256 $source)) { throw 'stale DLL retained' }
$bytes[68] = 0x64; $bytes[69] = 0x86
[IO.File]::WriteAllBytes($source, $bytes)
$rejected = $false
try { Stage-Z3Runtime 'aarch64-pc-windows-msvc' } catch {
    if ($_.Exception.Message -notmatch 'architecture') { throw }
    $rejected = $true
}
if (-not $rejected) { throw 'wrong architecture accepted' }
$secondDir = Join-Path $release 'build/z3-sys-second/out/z3-5.1.0/bin'
New-Item -ItemType Directory -Path $secondDir -Force | Out-Null
$bytes[69] = 0xAA
[IO.File]::WriteAllBytes((Join-Path $secondDir 'libz3.dll'), $bytes)
$rejected = $false
try { Stage-Z3Runtime 'aarch64-pc-windows-msvc' } catch {
    if ($_.Exception.Message -notmatch 'Ambiguous') { throw }
    $rejected = $true
}
if (-not $rejected) { throw 'conflicting runtimes accepted' }
"#;
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", script])
        .env(
            "OPENSHELL_BUILD_SCRIPT",
            examples().join("../../../tasks/scripts/windows-msvc.ps1"),
        )
        .env("OPENSHELL_TEST_ROOT", root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Z3 staging regression failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn audit_coverage_uses_structured_events_and_rejects_missing_or_wrong_classes() {
    let script = r#"
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:OPENSHELL_MXC_RUNNER, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw "parse errors: $errors" }
$function = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Get-MxcAuditCoverage'
}, $true)
if (!$function) { throw 'missing coverage function' }
Invoke-Expression $function.Extent.Text
foreach ($name in @('Quote-NativeArgument', 'Invoke-NativeCaptured')) {
    $helper = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if (!$helper) { throw "missing $name" }
    Invoke-Expression $helper.Extent.Text
}
foreach ($code in @(0, 7)) {
    $result = Invoke-NativeCaptured 'powershell.exe' @('-NoProfile', '-Command',
        "[Console]::Error.WriteLine('status on stderr'); exit $code") 10
    if ($result.ExitCode -ne $code -or ($result.Output -join '') -notmatch 'status on stderr') {
        throw 'native stderr must be captured without hiding the exit code'
    }
}
$events = @(
    @{ class_uid=6002; message="MXC sandbox 'test' created with policy enforcement" },
    @{ class_uid=5019; message='MXC sandbox OS policy enforced' },
    @{ class_uid=5019; message='MXC sandbox OS policy configured' },
    @{ class_uid=5019; message='MXC sandbox win32k lockdown applied' },
    @{ class_uid=5019; message='MXC sandbox UI restrictions applied' },
    @{ class_uid=5019; message='MXC sandbox console reference plumbed' },
    @{ class_uid=1007; message='MXC sandbox launched process: cmd.exe' }
) | ForEach-Object { $_ | ConvertTo-Json -Compress | ConvertFrom-Json }
$coverage = Get-MxcAuditCoverage $events
if ($coverage.Count -ne 7 -or @($coverage.Values | Where-Object { $_ }).Count -ne 7) {
    throw 'complete structured audit must satisfy seven event types'
}
foreach ($index in 0..6) {
    $subset = @(for ($i=0; $i -lt 7; $i++) { if ($i -ne $index) { $events[$i] } })
    if (@((Get-MxcAuditCoverage $subset).Values | Where-Object { $_ }).Count -ne 6) {
        throw "missing event $index must fail coverage"
    }
}
$events[6].class_uid = 5019
if ((Get-MxcAuditCoverage $events)['process launch (executable identity)']) {
    throw 'matching text with wrong class must not pass'
}
if (@((Get-MxcAuditCoverage @()).Values | Where-Object { $_ }).Count -ne 0) {
    throw 'empty audit must not pass'
}
"#;
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", script])
        .env(
            "OPENSHELL_MXC_RUNNER",
            examples().join("run-ocsf-audit.ps1"),
        )
        .output()
        .expect("launch PowerShell coverage regression");
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
