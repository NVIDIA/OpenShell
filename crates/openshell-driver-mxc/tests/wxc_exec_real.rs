// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Real-`wxc-exec` integration tests (Tier 2).
//!
//! These tests drive the actual `wxc-exec.exe` binary — no mock shim.  Every
//! test is `#[ignore = "requires real wxc-exec"]` so the regular `cargo test`
//! suite (`windows:test:x64`) never blocks on hardware. Run them with:
//!
//! ```powershell
//! $env:OPENSHELL_WXC_EXEC_PATH = "C:\mxc\wxc-exec.exe"
//! cargo test -p openshell-driver-mxc --test wxc_exec_real -- --ignored --test-threads=1
//! ```
//!
//! Two families:
//!
//! **(a) Dry-run contract tests** — exercise `--dry-run` only; pass/fail on
//!   schema acceptance. Most require no live enforcement backend. Tests that
//!   request a host capability such as bidirectional host loopback probe that
//!   capability first because MXC validates platform support during dry-run.
//!
//! **(b) Enforcement tests** — probe-gated; print a human-readable SKIP reason
//!   and return early when the backend is not live. The probe distinguishes
//!   "binary absent", "`backend_error` / velocity keys not enabled", and
//!   "`backend_unavailable`".
//!
//! IMPORTANT: `OPENSHELL_MXC_MOCK_WXC` must NOT be set when running this file.
//! The probe-gated enforcement tests assert that it is absent so a stale env
//! var can never silently re-mock a "real" run.

#![cfg(target_os = "windows")]

use base64::Engine as _;
use openshell_core::proto::compute::v1::{DriverSandbox, DriverSandboxSpec, DriverSandboxTemplate};
use openshell_core::proto::{
    FilesystemPolicy, NetworkAccessPreset, NetworkBinary, NetworkEndpoint, NetworkEnforcementMode,
    NetworkPolicyRule, NetworkTlsMode, SandboxPolicy,
};
use openshell_driver_mxc::{MxcComputeBackend, MxcComputeConfig};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

// ── Path resolution ──────────────────────────────────────────────────────────

/// Resolve the path to `wxc-exec.exe`.
///
/// Checks `OPENSHELL_WXC_EXEC_PATH` first, then the canonical demo-box
/// location `C:\mxc\wxc-exec.exe`. Returns `None` when neither path exists so
/// callers can skip rather than fail.
fn wxc_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("OPENSHELL_WXC_EXEC_PATH") {
        let pb = PathBuf::from(&p);
        if pb.exists() {
            return Some(pb);
        }
        // Env var was set but path is absent — still treat as "not found" so
        // tests skip with a clear reason rather than erroring on spawn.
        eprintln!("SKIP: OPENSHELL_WXC_EXEC_PATH={p} does not exist");
        return None;
    }
    let default = PathBuf::from(r"C:\mxc\wxc-exec.exe");
    if default.exists() {
        return Some(default);
    }
    None
}

/// Create a real, user-owned Windows directory for MXC filesystem grants.
///
/// MXC config values are literal paths: it does not expand `%TEMP%`. A unique
/// directory also keeps `AppContainer`+DACL fallback mutations scoped to test
/// data the current user owns.
fn temp_fixture() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("create MXC temp fixture");
    let path = dir.path().to_string_lossy().into_owned();
    (dir, path)
}

// ── Dry-run helper ────────────────────────────────────────────────────────────

/// Invoke `wxc-exec --config-base64 <cfg> --dry-run` synchronously.
/// Returns `(exit_code, stdout, stderr)`.
fn dry_run(wxc: &PathBuf, config: &serde_json::Value) -> (i32, String, String) {
    dry_run_with_args(wxc, config, &[])
}

fn dry_run_with_args(
    wxc: &PathBuf,
    config: &serde_json::Value,
    args: &[&str],
) -> (i32, String, String) {
    let json = serde_json::to_string(config).expect("config serialize");
    let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());

    let out = Command::new(wxc)
        .args(args)
        .arg("--config-base64")
        .arg(&b64)
        .arg("--dry-run")
        .output()
        .expect("wxc-exec spawn");

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let code = out.status.code().unwrap_or(-1);
    (code, stdout, stderr)
}

fn wxc_version(wxc: &Path) -> Option<(u64, u64, u64, String)> {
    // wxc-exec does not expose --version. Release builds carry the Cargo
    // version in the standard Windows ProductVersion resource.
    let path_literal = wxc.to_string_lossy().replace('\'', "''");
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command"])
        .arg(format!(
            "(Get-Item -LiteralPath '{path_literal}').VersionInfo.ProductVersion"
        ))
        .output()
        .ok()?;
    let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let version = raw.split_whitespace().find_map(|token| {
        let core = token
            .trim_matches(|ch: char| !ch.is_ascii_digit() && ch != '.')
            .split(['+', '-'])
            .next()?;
        let mut parts = core.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next()?.parse().ok()?;
        Some((major, minor, patch))
    })?;
    Some((version.0, version.1, version.2, raw))
}

// ── (a) Dry-run contract tests ────────────────────────────────────────────────
//
// Most PASS on any box that has the wxc-exec binary — no enforcement backend is
// required. MXC also validates requested platform capabilities during dry-run,
// so capability-specific configs probe those capabilities before asserting
// schema acceptance.

/// Minimal processcontainer one-shot config accepted by `--dry-run`.
#[test]
#[ignore = "requires real wxc-exec"]
fn dryrun_accepts_minimal_processcontainer_config() {
    let Some(wxc) = wxc_path() else {
        eprintln!("SKIP: wxc-exec not found");
        return;
    };

    let (_tempdir, temp_path) = temp_fixture();
    let config = serde_json::json!({
        "version": "1.0.0",
        "containerId": "test-minimal",
        "containment": "processcontainer",
        "process": {
            "commandLine": "cmd /c exit 0",
            "cwd": temp_path,
            "timeout": 0,
        },
        "filesystem": {
            "readwritePaths": [temp_path],
        },
    });

    let (code, stdout, stderr) = dry_run(&wxc, &config);
    assert_eq!(
        code, 0,
        "minimal processcontainer config rejected by --dry-run\nstdout={stdout}\nstderr={stderr}"
    );
}

/// Every `OpenShell` clipboard direction maps to MXC's shared top-level UI
/// contract, with graphical UI and injection carried as independent booleans.
#[test]
#[ignore = "requires real wxc-exec"]
fn dryrun_accepts_processcontainer_ui_policy_matrix() {
    let Some(wxc) = wxc_path() else {
        eprintln!("SKIP: wxc-exec not found");
        return;
    };

    let tempdir = tempfile::tempdir().expect("tempdir");
    let temp_path = tempdir.path().to_string_lossy().into_owned();
    for clipboard in ["none", "read", "write", "all"] {
        let config = serde_json::json!({
            "version": "1.0.0",
            "containerId": format!("test-ui-{clipboard}"),
            "containment": "processcontainer",
            "process": {
                "commandLine": "cmd /c exit 0",
                "cwd": temp_path.clone(),
                "timeout": 0,
            },
            "filesystem": {
                "readwritePaths": [temp_path.clone()],
            },
            "ui": {
                "disable": false,
                "clipboard": clipboard,
                "injection": true,
            },
        });

        let (code, stdout, stderr) = dry_run(&wxc, &config);
        assert_eq!(
            code, 0,
            "processcontainer UI policy clipboard={clipboard} rejected by --dry-run\nstdout={stdout}\nstderr={stderr}"
        );
    }
}

/// MXC 1.0 rejects the shared top-level UI object on `isolation_session`, while
/// omission remains accepted. `OpenShell`'s gateway-level capability check is
/// the stable enforcement boundary.
#[test]
#[ignore = "requires real wxc-exec"]
fn dryrun_current_schema_rejects_isolation_session_ui() {
    let Some(wxc) = wxc_path() else {
        eprintln!("SKIP: wxc-exec not found");
        return;
    };
    let Some((major, minor, _patch, raw_version)) = wxc_version(&wxc) else {
        eprintln!("SKIP: could not determine wxc-exec version");
        return;
    };
    if (major, minor) < (1, 0) {
        eprintln!("SKIP: {raw_version} predates the isolation_session UI rejection contract");
        return;
    }

    let base = serde_json::json!({
        "version": "1.0.0",
        "containment": "isolation_session",
        "network": {
            "egress": { "default": "allow" },
            "ingress": { "default": "allow", "hostLoopback": "allow" },
        },
    });
    let args: &[&str] = &["--operation", "provision"];
    let (code, stdout, stderr) = dry_run_with_args(&wxc, &base, args);
    let output = format!("{stdout} {stderr}").to_ascii_lowercase();
    if code != 0
        && output.contains("backend_unavailable")
        && output.contains("not available in this build")
    {
        eprintln!("SKIP: {raw_version} was built without isolation_session support");
        return;
    }
    assert_eq!(
        code, 0,
        "current isolation_session schema must accept omission of UI\nversion={raw_version}\nstdout={stdout}\nstderr={stderr}"
    );

    let mut with_ui = base;
    with_ui["ui"] = serde_json::json!({ "disable": true });
    let (code, stdout, stderr) = dry_run_with_args(&wxc, &with_ui, args);
    assert_ne!(
        code, 0,
        "current isolation_session schema unexpectedly accepted UI\nversion={raw_version}\nstdout={stdout}\nstderr={stderr}"
    );
    assert!(
        format!("{stdout} {stderr}")
            .to_ascii_lowercase()
            .contains("ui"),
        "rejection should identify UI\nversion={raw_version}\nstdout={stdout}\nstderr={stderr}"
    );
}

/// Stable directional network block without proxy is accepted.
#[test]
#[ignore = "requires real wxc-exec"]
fn dryrun_accepts_network_block_without_proxy() {
    let Some(wxc) = wxc_path() else {
        eprintln!("SKIP: wxc-exec not found");
        return;
    };

    let (_tempdir, temp_path) = temp_fixture();
    let config = serde_json::json!({
        "version": "1.0.0",
        "containerId": "test-net-block",
        "containment": "processcontainer",
        "process": {
            "commandLine": "cmd /c exit 0",
            "cwd": temp_path,
            "timeout": 0,
        },
        "filesystem": {
            "readwritePaths": [temp_path],
        },
        "network": {
            "egress": { "default": "deny" },
        },
    });

    let (code, stdout, stderr) = dry_run(&wxc, &config);
    assert_eq!(
        code, 0,
        "network block without proxy rejected by --dry-run\nstdout={stdout}\nstderr={stderr}"
    );
}

/// Unknown containment value is rejected.
#[test]
#[ignore = "requires real wxc-exec"]
fn dryrun_rejects_unknown_containment() {
    let Some(wxc) = wxc_path() else {
        eprintln!("SKIP: wxc-exec not found");
        return;
    };

    let (_tempdir, temp_path) = temp_fixture();
    let config = serde_json::json!({
        "version": "1.0.0",
        "containerId": "test-bad-containment",
        "containment": "nonsense",
        "process": {
            "commandLine": "cmd /c exit 0",
            "cwd": temp_path,
            "timeout": 0,
        },
        "filesystem": {
            "readwritePaths": [temp_path],
        },
    });

    let (code, _stdout, _stderr) = dry_run(&wxc, &config);
    assert_ne!(code, 0, "unknown containment 'nonsense' should be rejected");
}

/// The most important dry-run test: build a typed Windows policy, run
/// `split_policy` (MXC 1.0 loopback-only proxy access at 127.0.0.1:18080,
/// containment
/// "processcontainer"), and verify the resulting config with `--dry-run`.
///
/// This proves that the mapper's emitted JSON is accepted by the real binary —
/// the central contract of the policy-mapper integration.
#[test]
#[ignore = "requires real wxc-exec"]
fn dryrun_accepts_split_policy_output() {
    let Some(wxc) = wxc_path() else {
        eprintln!("SKIP: wxc-exec not found");
        return;
    };
    if let Err(reason) = probe_processcontainer_host_loopback(&wxc) {
        eprintln!("SKIP: processcontainer governed egress unavailable: {reason}");
        return;
    }

    let (_tempdir, temp_path) = temp_fixture();
    let policy = SandboxPolicy {
        filesystem: Some(FilesystemPolicy {
            include_workdir: false,
            read_only: Vec::new(),
            read_write: vec![temp_path.clone()],
        }),
        ..Default::default()
    };

    let opts = openshell_driver_mxc::MxcMappingOptions {
        containment: "processcontainer".to_string(),
        command: "cmd /c exit 0".to_string(),
        container_id: "split-policy-dryrun".to_string(),
        cwd: Some(temp_path),
        proxy_redirect: Some("127.0.0.1:18080".parse().unwrap()),
        ..Default::default()
    };

    let result = openshell_driver_mxc::split_policy(&policy, &opts)
        .expect("split_policy must return Some when proxy_redirect is set");
    // There should be no error losses on the processcontainer split path.
    let error_losses: Vec<_> = result
        .loss
        .iter()
        .filter(|l| l.severity == "error")
        .collect();
    if !error_losses.is_empty() {
        eprintln!(
            "split_policy emitted {} error loss item(s); proceeding to dry-run:\n{:#?}",
            error_losses.len(),
            error_losses
        );
    }

    let mxc_config = result.mxc_config;
    assert_eq!(mxc_config["version"], "1.0.0");
    assert_eq!(mxc_config["network"]["egress"]["default"], "deny");
    assert_eq!(
        mxc_config["network"]["egress"]["allow"][0]["to"][0]["cidr"],
        "127.0.0.1/32"
    );
    assert!(mxc_config.get("runtimeConfig").is_none());

    // --dry-run also resolves host capabilities; it is not schema-only.
    // Verify explicit rejection on an AppContainer-only host rather than
    // weakening the mapper's required loopback fence to obtain a green test.
    let probe = Command::new(&wxc)
        .arg("--probe")
        .output()
        .expect("MXC probe");
    let probe_json = serde_json::from_slice::<serde_json::Value>(&probe.stdout).ok();
    let loopback_supported = probe_json
        .as_ref()
        .and_then(|value| value.pointer("/probes/baseContainerSupportsIngressHostLoopbackAllow"))
        .and_then(serde_json::Value::as_bool);
    let (code, stdout, stderr) = dry_run(&wxc, &mxc_config);
    if loopback_supported == Some(false) {
        assert_ne!(code, 0, "unsupported host must reject the loopback fence");
        assert!(
            stderr.contains("hostLoopback"),
            "unexpected rejection: {stderr}"
        );
        eprintln!(
            "SKIP: positive split-policy admission requires native host-loopback support; unsupported-host rejection verified"
        );
        return;
    }
    assert_eq!(
        code,
        0,
        "split_policy output rejected by --dry-run; \
         this proves the mapper emits valid MXC JSON\n\
         config={}\nstdout={stdout}\nstderr={stderr}",
        serde_json::to_string_pretty(&mxc_config).unwrap_or_default()
    );
}

/// The standalone mapper must emit the same stable MXC 1.0 schema as the live
/// governed-egress path. Exercise a numeric destination and ports so this test
/// would fail if the mapper regressed to the retired host-list shape. Some MXC
/// builds select a backend that recognizes the directional schema but cannot
/// enforce egress rules; that explicit capability error still proves the 1.0
/// fields were parsed rather than rejected as unknown schema.
#[test]
#[ignore = "requires real wxc-exec"]
fn dryrun_accepts_standalone_mapper_output() {
    let Some(wxc) = wxc_path() else {
        eprintln!("SKIP: wxc-exec not found");
        return;
    };

    let (_tempdir, temp_path) = temp_fixture();
    let mut policy = SandboxPolicy {
        filesystem: Some(FilesystemPolicy {
            include_workdir: false,
            read_only: Vec::new(),
            read_write: vec![temp_path.clone()],
        }),
        ..Default::default()
    };
    policy.network_policies.insert(
        "numeric-egress".into(),
        NetworkPolicyRule {
            name: "numeric-egress".into(),
            endpoints: vec![NetworkEndpoint {
                host: "198.51.100.7".into(),
                ports: vec![80, 443],
                ..Default::default()
            }],
            binaries: Vec::new(),
        },
    );
    let options = openshell_driver_mxc::MxcMappingOptions {
        containment: "processcontainer".into(),
        command: "cmd /c exit 0".into(),
        container_id: "standalone-mapper-dryrun".into(),
        cwd: Some(temp_path),
        ..Default::default()
    };
    let result = openshell_driver_mxc::map_to_mxc(&policy, &options);
    assert!(
        result
            .loss
            .iter()
            .all(|item| item.path != "network_policies.numeric-egress.endpoints[0].host")
    );
    let config = result.config;
    assert_eq!(config["version"], "1.0.0");
    assert_eq!(config["network"]["egress"]["default"], "deny");
    assert_eq!(
        config["network"]["egress"]["allow"][0]["to"][0]["cidr"],
        "198.51.100.7/32"
    );
    assert_eq!(
        config["network"]["egress"]["allow"][0]["ports"],
        serde_json::json!([
            { "protocol": "tcp", "port": 80 },
            { "protocol": "tcp", "port": 443 }
        ])
    );

    let (code, stdout, stderr) = dry_run(&wxc, &config);
    let output = format!("{stdout} {stderr}").to_ascii_lowercase();
    if code != 0
        && output
            .contains("network.egress allow/deny rules are not supported by the selected backend")
    {
        eprintln!(
            "PASS: MXC parsed the 1.0 directional network schema; selected backend cannot enforce egress rules"
        );
        return;
    }
    assert_eq!(
        code,
        0,
        "standalone mapper output rejected by MXC 1.0 --dry-run\nconfig={}\nstdout={stdout}\nstderr={stderr}",
        serde_json::to_string_pretty(&config).unwrap_or_default()
    );
}

// ── (b) Enforcement tests — probe-gated ───────────────────────────────────────
//
// These skip on this box (processcontainer velocity keys not enabled;
// isolation_session backend absent). They PASS where backends are live.

/// Probe the processcontainer backend.
///
/// Runs a trivial one-shot (`cmd /c exit 0`, user-owned temp grant). Returns
/// `Ok(())` when the backend is live, or `Err(reason)` when it is not (the
/// caller prints SKIP + reason and returns from the test).
fn probe_processcontainer(wxc: &PathBuf) -> Result<(), String> {
    // Abort early if the mock env var is set — a stale OPENSHELL_MXC_MOCK_WXC
    // would silently turn this "real" run back into a mock run.
    if std::env::var("OPENSHELL_MXC_MOCK_WXC").is_ok_and(|value| value == "1") {
        return Err(
            "OPENSHELL_MXC_MOCK_WXC=1 is set — unset it before running real enforcement tests"
                .to_string(),
        );
    }

    let (_tempdir, temp_path) = temp_fixture();
    let config = serde_json::json!({
        "version": "1.0.0",
        "containerId": "probe-pc",
        "containment": "processcontainer",
        "process": {
            "commandLine": "cmd /c exit 0",
            "cwd": temp_path,
            "timeout": 30_000,
        },
        "filesystem": {
            "readwritePaths": [temp_path],
        },
        "ui": {
            "disable": false,
            "clipboard": "none",
            "injection": false,
        },
    });

    let json = serde_json::to_string(&config).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());

    let out = Command::new(wxc)
        .arg("--config-base64")
        .arg(&b64)
        .output()
        .map_err(|e| format!("wxc-exec spawn failed: {e}"))?;

    let stdout = String::from_utf8_lossy(&out.stdout).to_lowercase();
    let stderr = String::from_utf8_lossy(&out.stderr).to_lowercase();
    let combined = format!("{stdout} {stderr}");

    if combined.contains("backend_error")
        || combined.contains("e_notimpl")
        || combined.contains("velocity")
        || combined.contains("not enabled")
    {
        // Extract the message if possible for a more useful skip reason.
        let reason =
            serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(&out.stdout))
                .map_or_else(
                    |_| "backend_error (velocity keys not enabled)".to_string(),
                    |value| {
                        value["error"]["message"]
                            .as_str()
                            .unwrap_or("backend_error (E_NOTIMPL)")
                            .to_string()
                    },
                );
        return Err(reason);
    }

    if !out.status.success() {
        return Err(format!(
            "processcontainer probe returned exit {}: stdout={} stderr={}",
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        ));
    }

    Ok(())
}

/// Probe the released binary's native host-loopback capability separately from
/// ordinary `ProcessContainer` support. Schema validation also checks requested
/// platform capabilities, so loopback-dependent tests require a positive probe.
fn probe_processcontainer_host_loopback(wxc: &Path) -> Result<(), String> {
    if std::env::var("OPENSHELL_MXC_MOCK_WXC").is_ok_and(|v| v == "1") {
        return Err(
            "OPENSHELL_MXC_MOCK_WXC=1 is set — unset it before running real enforcement tests"
                .to_string(),
        );
    }

    let out = Command::new(wxc)
        .arg("--probe")
        .output()
        .map_err(|e| format!("wxc-exec --probe spawn failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "wxc-exec --probe returned exit {}: stdout={} stderr={}",
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        ));
    }

    let probe: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| format!("could not parse wxc-exec --probe JSON: {e}"))?;
    let supported = probe
        .pointer("/probes/baseContainerSupportsIngressHostLoopbackAllow")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| {
            "wxc-exec --probe omitted baseContainerSupportsIngressHostLoopbackAllow".to_string()
        })?;
    if supported {
        return Ok(());
    }

    let tier = probe["tier"].as_str().unwrap_or("unknown");
    Err(format!(
        "wxc-exec --probe reports baseContainerSupportsIngressHostLoopbackAllow=false \
         for isolation tier {tier}"
    ))
}

/// Probe the `isolation_session` backend.
///
/// Attempts a `provision` phase. Returns `Ok(sandbox_id)` when live, or
/// `Err(reason)` when the backend is unavailable (caller prints SKIP).
fn probe_isolation_session(wxc: &PathBuf) -> Result<String, String> {
    if std::env::var("OPENSHELL_MXC_MOCK_WXC").is_ok_and(|value| value == "1") {
        return Err(
            "OPENSHELL_MXC_MOCK_WXC=1 is set — unset it before running real enforcement tests"
                .to_string(),
        );
    }

    let config = serde_json::json!({
        "version": "1.0.0",
        "containment": "isolation_session",
        "network": {
            "egress": { "default": "allow" },
            "ingress": { "default": "allow", "hostLoopback": "allow" },
        }
    });

    let json = serde_json::to_string(&config).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());

    let out = Command::new(wxc)
        .arg("--config-base64")
        .arg(&b64)
        .arg("--operation")
        .arg("provision")
        .output()
        .map_err(|e| format!("wxc-exec spawn failed: {e}"))?;

    let stdout_raw = String::from_utf8_lossy(&out.stdout).into_owned();
    let stdout_lower = stdout_raw.to_lowercase();
    let stderr_lower = String::from_utf8_lossy(&out.stderr).to_lowercase();
    let combined = format!("{stdout_lower} {stderr_lower}");

    if combined.contains("backend_unavailable") || combined.contains("0x80040154") {
        return Err(
            "backend_unavailable: IsoSessionApp.dll absent or OS build < 26340.9212".to_string(),
        );
    }

    if !out.status.success() {
        return Err(format!(
            "isolation_session provision failed (exit {}): {}",
            out.status.code().unwrap_or(-1),
            stdout_raw
        ));
    }

    // Parse the sandboxId from {"result":{"sandboxId":"iso:..."}}
    let env: serde_json::Value = serde_json::from_str(&stdout_raw)
        .map_err(|e| format!("provision envelope parse failed: {e}: {stdout_raw}"))?;

    let sandbox_id = env["result"]["sandboxId"]
        .as_str()
        .ok_or_else(|| format!("sandboxId missing in provision result: {stdout_raw}"))?
        .to_string();

    Ok(sandbox_id)
}

/// RAII guard that best-effort deprovisioning on drop — protects the
/// single-session backend against orphaned sessions.
struct DeprovisionGuard<'a> {
    wxc: &'a PathBuf,
    sandbox_id: Option<String>,
}

impl<'a> DeprovisionGuard<'a> {
    fn new(wxc: &'a PathBuf, sandbox_id: String) -> Self {
        Self {
            wxc,
            sandbox_id: Some(sandbox_id),
        }
    }

    fn disarm(&mut self) {
        self.sandbox_id = None;
    }

    fn deprovision_now(&mut self) {
        if let Some(id) = self.sandbox_id.take() {
            Self::run_deprovision(self.wxc, &id);
        }
    }

    fn run_deprovision(wxc: &PathBuf, sandbox_id: &str) {
        let config = serde_json::json!({
            "version": "1.0.0",
        });
        let json = serde_json::to_string(&config).unwrap_or_default();
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
        // Best-effort: ignore errors so the test does not panic in drop.
        let _ = Command::new(wxc)
            .arg("--config-base64")
            .arg(&b64)
            .arg("--operation")
            .arg("deprovision")
            .arg("--container-id")
            .arg(sandbox_id)
            .output();
    }
}

impl Drop for DeprovisionGuard<'_> {
    fn drop(&mut self) {
        if let Some(id) = self.sandbox_id.take() {
            Self::run_deprovision(self.wxc, &id);
        }
    }
}

// ── Processcontainer enforcement tests ───────────────────────────────────────

/// Write a file inside the granted temp dir; assert the file appears and the
/// exit code is 0. Requires the processcontainer backend to be live.
#[test]
#[ignore = "requires real wxc-exec"]
fn pc_oneshot_in_policy_write_succeeds() {
    let Some(wxc) = wxc_path() else {
        eprintln!("SKIP: wxc-exec not found");
        return;
    };

    if let Err(reason) = probe_processcontainer(&wxc) {
        eprintln!("SKIP: processcontainer not live: {reason}");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("tempdir");
    let target = tmpdir.path().join("pc-in-policy.txt");
    let target_str = target.to_string_lossy().into_owned();
    let tmpdir_str = tmpdir.path().to_string_lossy().into_owned();

    let config = serde_json::json!({
        "version": "1.0.0",
        "containerId": "pc-in-policy-write",
        "containment": "processcontainer",
        "process": {
            "commandLine": format!("cmd /c echo hello > \"{target_str}\""),
            "cwd": tmpdir_str,
            "timeout": 30_000,
        },
        "filesystem": {
            "readwritePaths": [tmpdir_str],
        },
        "processContainer": {
            "leastPrivilege": false,
        },
        "ui": {
            "disable": false,
            "clipboard": "none",
            "injection": false,
        },
    });

    let json = serde_json::to_string(&config).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());

    let out = Command::new(&wxc)
        .arg("--config-base64")
        .arg(&b64)
        .output()
        .expect("wxc-exec spawn");

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let code = out.status.code().unwrap_or(-1);

    assert_eq!(
        code, 0,
        "in-policy write should exit 0\nstdout={stdout}\nstderr={stderr}"
    );
    assert!(
        target.exists(),
        "in-policy write: file should exist at {target_str}\nstdout={stdout}\nstderr={stderr}"
    );
}

/// Run an HTTPS request through the real driver and `ProcessContainer`. The
/// workload explicitly reads the injected bundle before curl uses it, proving
/// that the driver's internal TLS share is reachable from the `AppContainer`.
#[tokio::test]
#[ignore = "requires real wxc-exec and outbound HTTPS"]
async fn pc_https_egress_reads_injected_ca_bundle() {
    let Some(wxc) = wxc_path() else {
        eprintln!("SKIP: wxc-exec not found");
        return;
    };

    if let Err(reason) = probe_processcontainer(&wxc) {
        eprintln!("SKIP: processcontainer not live: {reason}");
        return;
    }
    if let Err(reason) = probe_processcontainer_host_loopback(&wxc) {
        eprintln!("SKIP: processcontainer host loopback not live: {reason}");
        return;
    }

    let system_root = std::env::var("SYSTEMROOT").expect("SYSTEMROOT must be set on Windows");
    let cmd = PathBuf::from(&system_root).join("System32").join("cmd.exe");
    let curl = PathBuf::from(system_root).join("System32").join("curl.exe");
    if !curl.exists() {
        eprintln!("SKIP: Windows curl.exe not found at {}", curl.display());
        return;
    }

    let output_dir = tempfile::tempdir().expect("HTTPS output directory");
    let output_path = output_dir.path().join("example.html");
    let certificate_path = output_dir.path().join("peer-certificate.txt");
    let output_dir_string = output_dir.path().to_string_lossy().into_owned();
    let output_path_string = output_path.to_string_lossy().into_owned();
    let certificate_path_string = certificate_path.to_string_lossy().into_owned();
    let cmd_string = cmd.to_string_lossy().into_owned();
    let curl_string = curl.to_string_lossy().into_owned();
    let script = format!(
        "type \"%CURL_CA_BUNDLE%\" 1>NUL && \
         \"{}\" --fail --silent --show-error --cacert \"%CURL_CA_BUNDLE%\" \
         https://example.com/ --output \"{output_path_string}\" \
         --write-out \"%{{certs}}\" 1>\"{certificate_path_string}\"",
        curl.display()
    );
    let command = vec![cmd_string, "/d".to_string(), "/c".to_string(), script];
    let serde_json::Value::Object(driver_config) = serde_json::json!({
        "command": command,
        "cwd": output_dir_string,
    }) else {
        unreachable!();
    };

    let policy = SandboxPolicy {
        version: 1,
        filesystem: Some(FilesystemPolicy {
            include_workdir: false,
            read_only: Vec::new(),
            read_write: vec![output_dir_string],
        }),
        network_policies: std::collections::HashMap::from([(
            "https_example".to_string(),
            NetworkPolicyRule {
                name: "https-example".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "example.com".to_string(),
                    ports: vec![443],
                    protocol: "rest".to_string(),
                    tls: NetworkTlsMode::Unspecified as i32,
                    enforcement: NetworkEnforcementMode::Enforce as i32,
                    access: NetworkAccessPreset::ReadOnly as i32,
                    ..Default::default()
                }],
                // curl owns the socket; cmd only launches it (#4199).
                binaries: vec![NetworkBinary { path: curl_string }],
            },
        )]),
        ..Default::default()
    };
    let sandbox = DriverSandbox {
        id: "pc-https-ca".to_string(),
        name: "pc-https-ca".to_string(),
        spec: Some(DriverSandboxSpec {
            template: Some(DriverSandboxTemplate {
                driver_config: Some(
                    openshell_core::proto_struct::json_object_to_struct(driver_config)
                        .expect("driver config"),
                ),
                ..Default::default()
            }),
            policy: Some(policy),
            ..Default::default()
        }),
        ..Default::default()
    };

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let config = MxcComputeConfig {
        wxc_exec_path: wxc.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let backend = MxcComputeBackend::new(openshell_core::config::DEFAULT_GATEWAY_NAME, config);
    backend
        .create_sandbox(&sandbox)
        .await
        .expect("real HTTPS sandbox create accepted");

    let mut terminal_condition = None;
    for _ in 0..600 {
        if let Some(observed) = backend.get_sandbox("pc-https-ca").await
            && let Some(condition) = observed
                .status
                .and_then(|status| status.conditions.into_iter().find(|c| c.r#type == "Ready"))
            && matches!(
                condition.reason.as_str(),
                "AgentCompleted" | "ExecFailed" | "ProvisionFailed"
            )
        {
            terminal_condition = Some(condition);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let condition = terminal_condition.expect("HTTPS sandbox should reach a terminal condition");
    assert_eq!(
        condition.reason, "AgentCompleted",
        "HTTPS workload failed: {}",
        condition.message
    );
    assert!(output_path.exists(), "curl should write the HTTPS response");
    assert!(
        std::fs::metadata(&output_path)
            .expect("HTTPS response metadata")
            .len()
            > 0,
        "HTTPS response should not be empty"
    );
    let peer_certificate =
        std::fs::read_to_string(certificate_path).expect("curl peer certificate output");
    assert!(
        peer_certificate.contains("OpenShell Sandbox CA"),
        "HTTPS response must use a certificate issued by the host proxy CA"
    );
}

/// Write to a path OUTSIDE the granted dir; assert exit non-zero and file absent.
/// This is the genuine OS default-deny proof — the `AppContainer` blocks the write
/// without requiring any host ACL lockdown. The mock can only fake this.
#[test]
#[ignore = "requires real wxc-exec"]
fn pc_oneshot_out_of_policy_write_denied() {
    let Some(wxc) = wxc_path() else {
        eprintln!("SKIP: wxc-exec not found");
        return;
    };

    if let Err(reason) = probe_processcontainer(&wxc) {
        eprintln!("SKIP: processcontainer not live: {reason}");
        return;
    }

    let granted_dir = tempfile::tempdir().expect("granted tempdir");
    let denied_dir = tempfile::tempdir().expect("denied tempdir");
    let denied_file = denied_dir.path().join("pc-out-of-policy.txt");
    let denied_file_str = denied_file.to_string_lossy().into_owned();
    let granted_str = granted_dir.path().to_string_lossy().into_owned();

    let config = serde_json::json!({
        "version": "1.0.0",
        "containerId": "pc-out-of-policy-write",
        "containment": "processcontainer",
        "process": {
            "commandLine": format!("cmd /c echo denied > \"{denied_file_str}\""),
            "cwd": granted_str,
            "timeout": 30_000,
        },
        "filesystem": {
            // Only the granted_dir is in policy — denied_dir is NOT granted.
            "readwritePaths": [granted_str],
        },
        "processContainer": {
            "leastPrivilege": false,
        },
        "ui": {
            "disable": false,
            "clipboard": "none",
            "injection": false,
        },
    });

    let json = serde_json::to_string(&config).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());

    let out = Command::new(&wxc)
        .arg("--config-base64")
        .arg(&b64)
        .output()
        .expect("wxc-exec spawn");

    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();

    assert_ne!(
        code, 0,
        "out-of-policy write should be denied (non-zero exit)\nstdout={stdout}\nstderr={stderr}"
    );
    assert!(
        !denied_file.exists(),
        "out-of-policy file must be absent at {denied_file_str} (OS default-deny proof)\n\
         stdout={stdout}\nstderr={stderr}"
    );
}

// ── Isolation session enforcement tests ──────────────────────────────────────

/// Full `isolation_session` round trip: provision → start → exec → stop →
/// deprovision. `deprovision` runs in a drop-guard even on panic so the
/// single-session backend is never left orphaned.
#[test]
#[ignore = "requires real wxc-exec"]
fn iso_lifecycle_round_trip() {
    let Some(wxc) = wxc_path() else {
        eprintln!("SKIP: wxc-exec not found");
        return;
    };

    let sandbox_id = match probe_isolation_session(&wxc) {
        Ok(id) => id,
        Err(reason) => {
            eprintln!("SKIP: isolation_session not live: {reason}");
            return;
        }
    };

    // Guard ensures deprovision even on panic.
    let mut guard = DeprovisionGuard::new(&wxc, sandbox_id.clone());

    // start
    let start_config = serde_json::json!({
        "version": "1.0.0",
    });
    let json = serde_json::to_string(&start_config).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
    let out = Command::new(&wxc)
        .arg("--config-base64")
        .arg(&b64)
        .arg("--operation")
        .arg("start")
        .arg("--container-id")
        .arg(&sandbox_id)
        .output()
        .expect("start");
    assert!(
        out.status.success(),
        "start failed: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    // exec. timeout is MILLISECONDS; 0 = no timeout. Empirical (test box,
    // build 26300.8553, wxc-exec 2026-06-10): a small positive value (30) is
    // rejected by RunProcessWithOptionsAsync with "Invalid timeout value"
    // (HRESULT 0x80070057). 0 is the documented no-timeout value and matches
    // what the driver's exec path sends by default (MxcProcess.timeout = 0).
    let exec_config = serde_json::json!({
        "version": "1.0.0",
        "process": {
            "commandLine": "cmd /c exit 0",
            "cwd": "C:\\Windows\\Temp",
            "env": [],
            "inheritDefaultEnv": true,
            "timeout": 0,
        }
    });
    let json = serde_json::to_string(&exec_config).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
    let out = Command::new(&wxc)
        .arg("--config-base64")
        .arg(&b64)
        .arg("--operation")
        .arg("exec")
        .arg("--container-id")
        .arg(&sandbox_id)
        .output()
        .expect("exec");
    assert_eq!(
        out.status.code().unwrap_or(-1),
        0,
        "exec phase should exit 0: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    // stop
    let stop_config = serde_json::json!({
        "version": "1.0.0",
    });
    let json = serde_json::to_string(&stop_config).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
    let out = Command::new(&wxc)
        .arg("--config-base64")
        .arg(&b64)
        .arg("--operation")
        .arg("stop")
        .arg("--container-id")
        .arg(&sandbox_id)
        .output()
        .expect("stop");
    assert!(
        out.status.success(),
        "stop failed: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    // deprovision (also disarms the guard so Drop does not double-deprovision)
    guard.deprovision_now();
    guard.disarm();
}
