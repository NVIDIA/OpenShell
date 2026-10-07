// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "windows")]

use std::path::Path;

#[test]
fn task_harnesses_isolate_and_restore_gateway_configuration() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let scripts_root = repo_root.join("tasks/scripts");
    for name in [
        "windows-mxc-provider-credential-e2e.ps1",
        "windows-mxc-ocsf-audit-e2e.ps1",
        "windows-mxc-aggregate-e2e.ps1",
    ] {
        let source = std::fs::read_to_string(scripts_root.join(name))
            .unwrap_or_else(|error| panic!("failed to read {name}: {error}"));
        assert!(source.contains("Push-OpenShellMxcE2eEnvironment"));
        assert!(source.contains("Pop-OpenShellMxcE2eEnvironment"));
    }

    let helper = scripts_root.join("windows-mxc-e2e-environment.ps1");
    let temp = tempfile::tempdir().expect("temporary directory");
    let stage = temp.path().join("artifact root with spaces").join("stage");
    let script = r#"
$ErrorActionPreference = "Stop"
. $env:OPENSHELL_MXC_ENVIRONMENT_HELPER
$nonEmptyValues = @{
    APPDATA = "caller-APPDATA"
    LOCALAPPDATA = "caller-LOCALAPPDATA"
    XDG_CONFIG_HOME = "caller-XDG_CONFIG_HOME"
    XDG_STATE_HOME = "caller-XDG_STATE_HOME"
    XDG_DATA_HOME = "caller-XDG_DATA_HOME"
    OPENSHELL_GATEWAY_ENDPOINT = "http://127.0.0.1:1"
    OPENSHELL_GATEWAY_INSECURE = "caller-OPENSHELL_GATEWAY_INSECURE"
    OPENSHELL_GATEWAY_CONFIG = "caller-OPENSHELL_GATEWAY_CONFIG"
}
foreach ($entry in $nonEmptyValues.GetEnumerator()) {
    [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, "Process")
}
$before = [Environment]::GetEnvironmentVariables("Process")
if (-not $before.Contains("OPENSHELL_GATEWAY") -or ([string] $before["OPENSHELL_GATEWAY"]).Length -ne 0) {
    throw "OPENSHELL_GATEWAY did not start as an empty entry"
}
if ($before.Contains("OPENSHELL_GATEWAY_NAME")) {
    throw "OPENSHELL_GATEWAY_NAME did not start absent"
}

$snapshot = Push-OpenShellMxcE2eEnvironment -StageDir $env:OPENSHELL_MXC_ENVIRONMENT_STAGE
try {
    foreach ($name in @("APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME")) {
        $value = [System.Environment]::GetEnvironmentVariable($name, "Process")
        if (-not $value.StartsWith($env:OPENSHELL_MXC_ENVIRONMENT_STAGE, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "$name escaped the staging directory: $value"
        }
    }
    $isolatedEnvironment = [Environment]::GetEnvironmentVariables("Process")
    foreach ($name in @("OPENSHELL_GATEWAY", "OPENSHELL_GATEWAY_ENDPOINT", "OPENSHELL_GATEWAY_INSECURE", "OPENSHELL_GATEWAY_CONFIG", "OPENSHELL_GATEWAY_NAME")) {
        if ($isolatedEnvironment.Contains($name)) {
            throw "$name was inherited by the isolated harness"
        }
    }
} finally {
    Pop-OpenShellMxcE2eEnvironment -Snapshot $snapshot
}

foreach ($entry in $nonEmptyValues.GetEnumerator()) {
    $value = [Environment]::GetEnvironmentVariable($entry.Key, "Process")
    if ($value -ne $entry.Value) {
        throw "$($entry.Key) was not restored: $value"
    }
}
$restored = [Environment]::GetEnvironmentVariables("Process")
if (-not $restored.Contains("OPENSHELL_GATEWAY") -or ([string] $restored["OPENSHELL_GATEWAY"]).Length -ne 0) {
    throw "empty OPENSHELL_GATEWAY was not restored exactly"
}
if ($restored.Contains("OPENSHELL_GATEWAY_NAME")) {
    throw "absent OPENSHELL_GATEWAY_NAME was restored"
}
"#;

    for shell in ["powershell.exe", "pwsh.exe"] {
        let output = std::process::Command::new(shell)
            .args([
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ])
            .env("OPENSHELL_MXC_ENVIRONMENT_HELPER", &helper)
            .env("OPENSHELL_MXC_ENVIRONMENT_STAGE", &stage)
            .env("OPENSHELL_GATEWAY", "")
            .env_remove("OPENSHELL_GATEWAY_NAME")
            .output()
            .unwrap_or_else(|error| panic!("failed to launch {shell}: {error}"));
        assert!(
            output.status.success(),
            "environment isolation check failed under {shell}:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn shipped_runners_remove_empty_overrides_in_both_powershell_versions() {
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    let script = r#"
$ErrorActionPreference = "Stop"
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:OPENSHELL_MXC_RUNNER,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count -gt 0) { throw ($errors.Message -join "; ") }
foreach ($functionName in @("Set-ProcessEnvironmentVariableExact", "Enter-IsolatedCliEnvironment", "Exit-IsolatedCliEnvironment")) {
    $function = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $functionName
    }, $true)
    if ($null -eq $function) { throw "$functionName was not found" }
    Invoke-Expression $function.Extent.Text
}

$cliStateRoot = $null
$cliEnvironmentSnapshot = @{}
$cliEnvironmentNames = @(
    "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME",
    "OPENSHELL_GATEWAY", "OPENSHELL_GATEWAY_ENDPOINT", "OPENSHELL_GATEWAY_INSECURE",
    "OPENSHELL_GATEWAY_CONFIG", "OPENSHELL_GATEWAY_NAME"
)
$env:OPENSHELL_GATEWAY_ENDPOINT = "http://127.0.0.1:1"
$before = [Environment]::GetEnvironmentVariables("Process")
if (-not $before.Contains("OPENSHELL_GATEWAY") -or ([string] $before["OPENSHELL_GATEWAY"]).Length -ne 0) {
    throw "OPENSHELL_GATEWAY did not start as an empty entry"
}
if ($before.Contains("OPENSHELL_GATEWAY_NAME")) {
    throw "OPENSHELL_GATEWAY_NAME did not start absent"
}

Enter-IsolatedCliEnvironment
try {
    $isolatedEnvironment = [Environment]::GetEnvironmentVariables("Process")
    foreach ($name in @("OPENSHELL_GATEWAY", "OPENSHELL_GATEWAY_ENDPOINT", "OPENSHELL_GATEWAY_NAME")) {
        if ($isolatedEnvironment.Contains($name)) {
            throw "$name was not removed"
        }
    }
} finally {
    Exit-IsolatedCliEnvironment
}

if ($env:OPENSHELL_GATEWAY_ENDPOINT -ne "http://127.0.0.1:1") {
    throw "OPENSHELL_GATEWAY_ENDPOINT was not restored"
}
$restored = [Environment]::GetEnvironmentVariables("Process")
if (-not $restored.Contains("OPENSHELL_GATEWAY") -or ([string] $restored["OPENSHELL_GATEWAY"]).Length -ne 0) {
    throw "empty OPENSHELL_GATEWAY snapshot was not restored exactly"
}
if ($restored.Contains("OPENSHELL_GATEWAY_NAME")) {
    throw "absent OPENSHELL_GATEWAY_NAME snapshot was restored"
}
"#;

    for runner in ["run-mxc-e2e.ps1", "run-ocsf-audit.ps1"] {
        for shell in ["powershell.exe", "pwsh.exe"] {
            let output = std::process::Command::new(shell)
                .args([
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    script,
                ])
                .env("OPENSHELL_MXC_RUNNER", examples.join(runner))
                .env("OPENSHELL_GATEWAY", "")
                .env_remove("OPENSHELL_GATEWAY_NAME")
                .output()
                .unwrap_or_else(|error| panic!("failed to launch {shell}: {error}"));
            assert!(
                output.status.success(),
                "{runner} environment isolation failed under {shell}:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

#[test]
fn aggregate_and_ocsf_harnesses_preserve_caller_gateway_state() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for name in [
        "windows-mxc-aggregate-e2e.ps1",
        "windows-mxc-ocsf-audit-e2e.ps1",
    ] {
        let source = std::fs::read_to_string(repo_root.join("tasks/scripts").join(name))
            .unwrap_or_else(|error| panic!("failed to read {name}: {error}"));
        for required in [
            "$sentinelEndpoint",
            "OPENSHELL_GATEWAY_ENDPOINT",
            "gateway list -o json",
            "$sentinel.active",
            "pwsh.exe",
        ] {
            assert!(source.contains(required), "{name} is missing {required}");
        }
    }
}

#[test]
fn aggregate_harness_exercises_a_staging_path_with_spaces() {
    let harness = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tasks/scripts/windows-mxc-aggregate-e2e.ps1");
    let source = std::fs::read_to_string(harness).expect("aggregate harness source");
    assert!(source.contains("openshell mxc aggregate e2e-$Target"));

    let runner_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/run-mxc-e2e.ps1");
    let runner = std::fs::read_to_string(&runner_path).expect("aggregate example runner source");
    assert!(runner.contains("function New-CmdWriteCommand"));

    let temp = tempfile::tempdir().expect("temporary directory");
    let stage = temp.path().join("artifact root with spaces");
    std::fs::create_dir_all(&stage).expect("create staging directory");
    let script = r#"
$ErrorActionPreference = "Stop"
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:OPENSHELL_MXC_RUNNER,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count -gt 0) {
    throw "runner has PowerShell syntax errors: $($errors.Message -join '; ')"
}
$function = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq "New-CmdWriteCommand"
}, $true)
if ($null -eq $function) { throw "New-CmdWriteCommand was not found" }
Invoke-Expression $function.Extent.Text

$target = Join-Path $env:OPENSHELL_MXC_SPACE_STAGE "write proof.txt"
$command = New-CmdWriteCommand "ok" $target
& $env:ComSpec /d /s /c $command
if ($LASTEXITCODE -ne 0) { throw "cmd.exe failed with exit $LASTEXITCODE" }
if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
    throw "quoted command did not create the expected artifact: $target"
}
if ((Get-Content -LiteralPath $target -Raw).Trim() -ne "ok") {
    throw "quoted command wrote unexpected contents"
}
"#;
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", script])
        .env("OPENSHELL_MXC_RUNNER", runner_path)
        .env("OPENSHELL_MXC_SPACE_STAGE", stage)
        .output()
        .expect("failed to launch Windows PowerShell");
    assert!(
        output.status.success(),
        "space-path command check failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
