// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Drift guards for the shipped mTLS control-channel scenario and MXC runbook.

use std::path::{Path, PathBuf};

fn examples_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples")
}

fn read_example(name: &str) -> String {
    let path = examples_root().join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

#[test]
fn shipped_mtls_and_runbook_assets_are_present() {
    for name in [
        "README-mtls.txt",
        "run-mtls-test.ps1",
        "mxc-demo-runbook.md",
    ] {
        let path = examples_root().join(name);
        assert!(
            path.is_file(),
            "shipped example asset is missing: {}",
            path.display()
        );
    }
}

#[test]
fn mtls_runner_uses_isolated_state_and_valid_mock_mxc_startup() {
    let source = read_example("run-mtls-test.ps1");

    for required in [
        "$env:XDG_CONFIG_HOME = $xdgConfigHome",
        "$env:XDG_STATE_HOME = $xdgStateHome",
        "$env:OPENSHELL_SYSTEM_GATEWAY_DIR = $systemConfigHome",
        "$env:OPENSHELL_GATEWAY_CONFIG = $gatewayConfig",
        "$env:OPENSHELL_COMPUTE_DRIVER = \"mxc\"",
        "$env:OPENSHELL_MXC_MOCK_WXC = \"1\"",
        "version = 2",
        "wxc_exec_path = \"$escapedMockWxc\"",
        "sqlite::memory:",
        "Restore-ProcessEnvironment $environmentSnapshot",
    ] {
        assert!(source.contains(required), "runner is missing: {required}");
    }

    assert!(!source.contains("OPENSHELL_DRIVERS"));
    assert!(!source.contains("Get-Process -Id"));
    assert!(!source.contains("@(\"gateway\", \"remove\""));
    assert!(source.contains("Stop-Process -Id $gw.Id"));
    assert!(source.contains("No process was stopped"));
}

#[test]
fn runbook_uses_current_mxc_configuration_contract() {
    let source = read_example("mxc-demo-runbook.md");

    for required in [
        "`process_container` is the default",
        "`wxc_exec_path` is required and must be absolute",
        "`--driver-config-json`",
        "mxc.command",
        "command = @($cmdExe",
        "cwd = $share",
        "rejects policies with non-empty filesystem",
    ] {
        assert!(source.contains(required), "runbook is missing: {required}");
    }

    for obsolete in [
        "agent_command =",
        "agent_cwd =",
        "agent_env =",
        "share_dir =",
        "`isolation_session` (default)",
        "run-demo.ps1",
        "mxc-demo-agent.exe",
    ] {
        assert!(
            !source.contains(obsolete),
            "runbook still relies on obsolete content: {obsolete}"
        );
    }
}

#[cfg(target_os = "windows")]
#[test]
fn mtls_runner_parses_in_windows_powershell() {
    let path = examples_root().join("run-mtls-test.ps1");
    let script = r"
$errors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($env:OPENSHELL_MTLS_SCRIPT_TO_PARSE, [ref]$null, [ref]$errors)
if ($errors.Count -gt 0) {
    $errors | ForEach-Object { [Console]::Error.WriteLine($_.Message) }
    exit 1
}
";
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", script])
        .env("OPENSHELL_MTLS_SCRIPT_TO_PARSE", &path)
        .output()
        .unwrap_or_else(|error| panic!("failed to launch PowerShell: {error}"));
    assert!(
        output.status.success(),
        "run-mtls-test.ps1 has PowerShell syntax errors:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
