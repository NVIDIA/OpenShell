// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Drift guards for the two shipped Windows inference demos.

use std::path::{Path, PathBuf};

use openshell_policy::{parse_sandbox_policy, validate_sandbox_policy};
use toml::Value;

fn examples_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples")
}

#[test]
fn shipped_inference_demo_assets_are_present() {
    let root = examples_root();
    for name in [
        "mxc-ollama.toml",
        "ollama.yaml",
        "run-ollama-test.ps1",
        "mxc-inference.toml",
        "inference.yaml",
        "run-inference-test.ps1",
    ] {
        let path = root.join(name);
        assert!(
            path.is_file(),
            "shipped demo asset is missing: {}",
            path.display()
        );
    }
}

fn read_example(name: &str) -> String {
    let path = examples_root().join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

#[test]
fn shipped_inference_configs_declare_required_mxc_settings() {
    for name in ["mxc-ollama.toml", "mxc-inference.toml"] {
        let source = read_example(name);
        let parsed: Value = toml::from_str(&source)
            .unwrap_or_else(|error| panic!("failed to parse {name}: {error}"));
        let openshell = parsed
            .get("openshell")
            .and_then(Value::as_table)
            .unwrap_or_else(|| panic!("{name} is missing [openshell]"));
        assert_eq!(
            openshell.get("version").and_then(Value::as_integer),
            Some(2),
            "{name} must use schema version 2"
        );
        let mxc = openshell
            .get("drivers")
            .and_then(Value::as_table)
            .and_then(|drivers| drivers.get("mxc"))
            .and_then(Value::as_table)
            .unwrap_or_else(|| panic!("{name} is missing [openshell.drivers.mxc]"));
        assert_eq!(
            mxc.get("backend").and_then(Value::as_str),
            Some("process_container"),
            "{name} must use the filesystem-policy-capable backend"
        );
        assert_eq!(mxc.get("egress_proxy").and_then(Value::as_bool), Some(true));
        assert!(
            matches!(
                mxc.get("egress_proxy_addr").and_then(Value::as_str),
                Some(address) if address.starts_with("127.0.0.1:")
            ),
            "{name} must route network policy through governed loopback egress"
        );
        for removed in ["share_dir", "agent_cwd", "agent_command", "agent_env"] {
            assert!(
                !mxc.contains_key(removed),
                "{name} contains removed gateway field {removed}"
            );
        }
    }
}

#[test]
fn shipped_inference_policies_are_narrow_and_valid_after_rendering() {
    let share = if cfg!(windows) {
        "C:/portable/demo"
    } else {
        "/portable/demo"
    };
    let fixtures = [
        ("ollama.yaml", "local_ollama", "127.0.0.1", share),
        (
            "inference.yaml",
            "nvidia_inference",
            "integrate.api.nvidia.com",
            share,
        ),
    ];
    for (name, rule_name, endpoint, share) in fixtures {
        let rendered = read_example(name)
            .replace("__OPENSHELL_DEMO_SHARE__", share)
            .replace("__OLLAMA_HOST__", "127.0.0.1")
            .replace("__OLLAMA_PORT__", "11434")
            .replace("__CMD_EXE__", r"C:\Windows\System32\cmd.exe");
        let policy = parse_sandbox_policy(&rendered)
            .unwrap_or_else(|error| panic!("failed to parse rendered {name}: {error}"));
        validate_sandbox_policy(&policy)
            .unwrap_or_else(|error| panic!("rendered {name} is invalid: {error:?}"));
        let filesystem = policy
            .filesystem
            .as_ref()
            .unwrap_or_else(|| panic!("{name} must have a filesystem policy"));
        assert_eq!(filesystem.read_write, vec![share]);
        assert_eq!(policy.network_policies.len(), 1);
        let rule = policy
            .network_policies
            .get(rule_name)
            .unwrap_or_else(|| panic!("{name} is missing rule {rule_name}"));
        assert_eq!(rule.endpoints.len(), 1);
        assert_eq!(rule.endpoints[0].host, endpoint);
        assert_eq!(rule.binaries.len(), 1);
        assert_eq!(
            rule.binaries[0].path.to_ascii_lowercase(),
            r"c:\windows\system32\cmd.exe"
        );
    }
}

#[test]
fn shipped_runners_supply_sandbox_scoped_workload_configuration() {
    for name in ["run-ollama-test.ps1", "run-inference-test.ps1"] {
        let source = read_example(name);
        assert!(
            source.contains("--driver-config-json"),
            "{name} must pass command/cwd at sandbox creation"
        );
        assert!(
            !source.contains("C:\\mxc-kit"),
            "{name} must not pin wxc-exec to a machine path"
        );
        assert!(
            !source.contains("C:\\work"),
            "{name} must not pin its share to a machine path"
        );
        assert!(
            !source.contains("17670"),
            "{name} must not pin the gateway to the historical fixed port"
        );
        assert!(!source.contains("isolation_session"));
    }
    let cloud = read_example("run-inference-test.ps1");
    assert!(cloud.contains("--env-from"));
    assert!(cloud.contains("NV_API_KEY"));
    assert!(!cloud.contains("[string] $ApiKey"));
    assert!(!cloud.contains("pass -ApiKey"));
    assert!(cloud.contains("nvidia/nemotron-3.5-lightning-30b-a3b"));
    assert!(!cloud.contains("nvidia/nvidia-nemotron-nano-9b-v2"));
}

#[cfg(target_os = "windows")]
#[test]
fn shipped_runners_parse_in_windows_powershell() {
    for name in ["run-ollama-test.ps1", "run-inference-test.ps1"] {
        let path = examples_root().join(name);
        let script = r"
$errors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($env:OPENSHELL_DEMO_SCRIPT_TO_PARSE, [ref]$null, [ref]$errors)
if ($errors.Count -gt 0) {
    $errors | ForEach-Object { [Console]::Error.WriteLine($_.Message) }
    exit 1
}
";
        let output = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", script])
            .env("OPENSHELL_DEMO_SCRIPT_TO_PARSE", &path)
            .output()
            .unwrap_or_else(|error| panic!("failed to launch PowerShell for {name}: {error}"));
        assert!(
            output.status.success(),
            "{name} has PowerShell syntax errors:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
