// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(windows)]
#[test]
fn shipped_runners_preserve_driver_config_json_in_windows_powershell() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let directory = tempfile::tempdir().expect("create native-argument test directory");
    let receiver = directory.path().join("capture native arguments.ps1");
    std::fs::write(
        &receiver,
        r#"
param(
    [Parameter(Mandatory = $true, Position = 0)] [string] $Before,
    [Parameter(Mandatory = $true, Position = 1)] [string] $DriverConfigJson,
    [Parameter(Mandatory = $true, Position = 2)] [string] $After
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Write-Output "BEFORE=$Before"
Write-Output "JSON=$DriverConfigJson"
Write-Output "AFTER=$After"
"#,
    )
    .expect("write native-argument receiver");

    let verifier = r#"
$ErrorActionPreference = "Stop"
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:OPENSHELL_RUNNER_PATH,
    [ref] $tokens,
    [ref] $errors
)
if ($errors.Count -gt 0) {
    throw "runner has PowerShell syntax errors: $($errors.Message -join '; ')"
}

foreach ($name in @("Quote-NativeArgument", "Invoke-NativeCaptured")) {
    $functionAst = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $name
    }, $true)
    if ($null -eq $functionAst) { throw "$name is missing" }
    Invoke-Expression $functionAst.Extent.Text
}

$expected = @{
    mxc = @{
        command = @("C:/Program Files/OpenShell/agent.exe", "server mode")
        cwd = "C:/work/path with spaces"
    }
} | ConvertTo-Json -Compress -Depth 4
$powershell = Join-Path $env:SystemRoot "System32/WindowsPowerShell/v1.0/powershell.exe"
$result = Invoke-NativeCaptured $powershell @(
    "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
    $env:OPENSHELL_ARGUMENT_RECEIVER,
    "before value", $expected, "after value"
)
if ($result.ExitCode -ne 0) {
    throw "argument receiver exited $($result.ExitCode): $($result.Output -join [Environment]::NewLine)"
}

$lines = @(($result.Output -join "`n") -split "`r?`n")
$before = $lines | Where-Object { $_ -like "BEFORE=*" } | Select-Object -First 1
$json = $lines | Where-Object { $_ -like "JSON=*" } | Select-Object -First 1
$after = $lines | Where-Object { $_ -like "AFTER=*" } | Select-Object -First 1
if ($before -ne "BEFORE=before value") { throw "leading argument changed: $before" }
if ($null -eq $json -or $json.Substring(5) -cne $expected) {
    throw "driver config JSON changed: expected '$expected', captured '$json'"
}
if ($after -ne "AFTER=after value") { throw "trailing argument changed: $after" }
"#;

    for runner in ["run-ws-agent-test.ps1", "run-openclaw-forward-test.ps1"] {
        let runner_path = root.join("examples").join(runner);
        let output = std::process::Command::new("powershell.exe")
            .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"])
            .arg(verifier)
            .env("OPENSHELL_RUNNER_PATH", &runner_path)
            .env("OPENSHELL_ARGUMENT_RECEIVER", &receiver)
            .output()
            .unwrap_or_else(|error| {
                panic!("failed to launch Windows PowerShell for {runner}: {error}")
            });
        assert!(
            output.status.success(),
            "{runner} corrupted a native argument:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}
