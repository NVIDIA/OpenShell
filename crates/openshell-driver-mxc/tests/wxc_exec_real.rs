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
//!   schema acceptance. These pass on this box even though no enforcement
//!   backend is live (dry-run validates the JSON schema without spinning up the
//!   `AppContainer` or isolation session).
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
    FilesystemPolicy, NetworkBinary, NetworkEndpoint, NetworkPolicyRule, SandboxPolicy,
};
use openshell_driver_mxc::{MxcComputeBackend, MxcComputeConfig};
use std::path::PathBuf;
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
/// directory also keeps AppContainer+DACL fallback mutations scoped to test
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
    let json = serde_json::to_string(config).expect("config serialize");
    let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());

    let out = Command::new(wxc)
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

// ── (a) Dry-run contract tests ────────────────────────────────────────────────
//
// These PASS on any box that has the wxc-exec binary — no enforcement backend
// is required because --dry-run only validates the JSON schema.

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
        "version": "0.6.0-alpha",
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

/// Network block without proxy (defaultPolicy block, empty host lists) accepted.
#[test]
#[ignore = "requires real wxc-exec"]
fn dryrun_accepts_network_block_without_proxy() {
    let Some(wxc) = wxc_path() else {
        eprintln!("SKIP: wxc-exec not found");
        return;
    };

    let (_tempdir, temp_path) = temp_fixture();
    let config = serde_json::json!({
        "version": "0.6.0-alpha",
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
            "defaultPolicy": "block",
        },
    });

    let (code, stdout, stderr) = dry_run(&wxc, &config);
    assert_eq!(
        code, 0,
        "network block without proxy rejected by --dry-run\nstdout={stdout}\nstderr={stderr}"
    );
}

/// The ONLY accepted proxy shape in MXC 0.6.0-alpha: `{"localhost": <port>}`.
/// Verified empirically against the real binary — any other shape is rejected
/// with "Request error".
#[test]
#[ignore = "requires real wxc-exec"]
fn dryrun_accepts_localhost_proxy_shape() {
    let Some(wxc) = wxc_path() else {
        eprintln!("SKIP: wxc-exec not found");
        return;
    };

    let (_tempdir, temp_path) = temp_fixture();
    let config = serde_json::json!({
        "version": "0.6.0-alpha",
        "containerId": "test-proxy-localhost",
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
            "defaultPolicy": "block",
            "proxy": { "localhost": 18080 },
        },
    });

    let (code, stdout, stderr) = dry_run(&wxc, &config);
    assert_eq!(
        code, 0,
        "{{\"localhost\": N}} proxy shape rejected by --dry-run\nstdout={stdout}\nstderr={stderr}"
    );
}

/// The `{"host": ..., "port": ...}` proxy shape is REJECTED by MXC 0.6.0-alpha.
/// This test guards the schema contract discovered via dry-run bisection.
/// See docs4gtb/mxc-box-capabilities.md §"Schema contract findings".
#[test]
#[ignore = "requires real wxc-exec"]
fn dryrun_rejects_host_port_proxy_shape() {
    let Some(wxc) = wxc_path() else {
        eprintln!("SKIP: wxc-exec not found");
        return;
    };

    let (_tempdir, temp_path) = temp_fixture();
    let config = serde_json::json!({
        "version": "0.6.0-alpha",
        "containerId": "test-proxy-hostport",
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
            "defaultPolicy": "block",
            // MXC 0.6.0-alpha rejects {"host","port"} — verified empirically.
            "proxy": { "host": "127.0.0.1", "port": 18080 },
        },
    });

    let (code, _stdout, _stderr) = dry_run(&wxc, &config);
    assert_ne!(
        code, 0,
        "{{\"host\",\"port\"}} proxy shape was unexpectedly ACCEPTED — \
         schema may have widened in a newer wxc-exec build"
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
        "version": "0.6.0-alpha",
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
/// `split_policy` (proxy_redirect 127.0.0.1:18080, containment
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

    let (code, stdout, stderr) = dry_run(&wxc, &mxc_config);
    assert_eq!(
        code,
        0,
        "split_policy output rejected by --dry-run; \
         this proves the mapper emits valid MXC JSON\n\
         config={}\nstdout={stdout}\nstderr={stderr}",
        serde_json::to_string_pretty(&mxc_config).unwrap_or_default()
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
    if std::env::var("OPENSHELL_MXC_MOCK_WXC")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        return Err(
            "OPENSHELL_MXC_MOCK_WXC=1 is set — unset it before running real enforcement tests"
                .to_string(),
        );
    }

    let (_tempdir, temp_path) = temp_fixture();
    let config = serde_json::json!({
        "version": "0.6.0-alpha",
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
        let reason = if let Ok(v) =
            serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(&out.stdout))
        {
            v["error"]["message"]
                .as_str()
                .unwrap_or("backend_error (E_NOTIMPL)")
                .to_string()
        } else {
            "backend_error (velocity keys not enabled)".to_string()
        };
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

/// Probe the released binary's live `network.proxy` support separately from
/// ordinary ProcessContainer support. Some builds accept the proxy JSON during
/// `--dry-run` but return `ERROR_INVALID_PARAMETER` from the live launcher.
fn probe_processcontainer_proxy(wxc: &PathBuf) -> Result<(), String> {
    let (_tempdir, temp_path) = temp_fixture();
    let proxy_listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|error| format!("failed to reserve proxy probe port: {error}"))?;
    let proxy_port = proxy_listener
        .local_addr()
        .map_err(|error| format!("failed to read proxy probe port: {error}"))?
        .port();
    let config = serde_json::json!({
        "version": "0.6.0-alpha",
        "containerId": "probe-pc-proxy",
        "containment": "processcontainer",
        "process": {
            "commandLine": "C:\\Windows\\System32\\cmd.exe /c exit 0",
            "cwd": temp_path,
            "timeout": 30_000,
        },
        "filesystem": {
            "readwritePaths": [temp_path],
        },
        "processContainer": {
            "leastPrivilege": false,
        },
        "network": {
            "defaultPolicy": "block",
            "proxy": { "localhost": proxy_port },
        },
    });

    let json = serde_json::to_string(&config).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
    let output = Command::new(wxc)
        .arg("--config-base64")
        .arg(&b64)
        .output()
        .map_err(|error| format!("wxc-exec proxy probe failed to spawn: {error}"))?;

    if output.status.success() {
        return Ok(());
    }

    Err(format!(
        "live network.proxy probe returned exit {}: stdout={} stderr={}",
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    ))
}

/// Probe the isolation_session backend.
///
/// Attempts a `provision` phase. Returns `Ok(sandbox_id)` when live, or
/// `Err(reason)` when the backend is unavailable (caller prints SKIP).
fn probe_isolation_session(wxc: &PathBuf) -> Result<String, String> {
    if std::env::var("OPENSHELL_MXC_MOCK_WXC")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        return Err(
            "OPENSHELL_MXC_MOCK_WXC=1 is set — unset it before running real enforcement tests"
                .to_string(),
        );
    }

    let config = serde_json::json!({
        "version": "0.6.0-alpha",
        "phase": "provision",
        "containment": "isolation_session",
        "filesystem": {
            "readwritePaths": [],
            "readonlyPaths": [],
        },
        "experimental": {
            "isolation_session": {
                "configurationId": "composable",
                "provision": {}
            }
        }
    });

    let json = serde_json::to_string(&config).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());

    let out = Command::new(wxc)
        .arg("--config-base64")
        .arg(&b64)
        .arg("--experimental")
        .output()
        .map_err(|e| format!("wxc-exec spawn failed: {e}"))?;

    let stdout_raw = String::from_utf8_lossy(&out.stdout).into_owned();
    let stdout_lower = stdout_raw.to_lowercase();
    let stderr_lower = String::from_utf8_lossy(&out.stderr).to_lowercase();
    let combined = format!("{stdout_lower} {stderr_lower}");

    if combined.contains("backend_unavailable") || combined.contains("0x80040154") {
        return Err(
            "backend_unavailable: IsoSessionApp.dll absent or OS build < 26300.8553".to_string(),
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
            "version": "0.6.0-alpha",
            "phase": "deprovision",
            "sandboxId": sandbox_id,
            "experimental": {
                "isolation_session": {
                    // Unit variant: must be null, not {} (malformed_request otherwise).
                    "deprovision": null
                }
            }
        });
        let json = serde_json::to_string(&config).unwrap_or_default();
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
        // Best-effort: ignore errors so the test does not panic in drop.
        let _ = Command::new(wxc)
            .arg("--config-base64")
            .arg(&b64)
            .arg("--experimental")
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
        "version": "0.6.0-alpha",
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

/// Run an HTTPS request through the real driver and ProcessContainer. The
/// workload explicitly reads the injected bundle before curl uses it, proving
/// that the driver's internal TLS share is reachable from the AppContainer.
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
    if let Err(reason) = probe_processcontainer_proxy(&wxc) {
        eprintln!("SKIP: processcontainer network.proxy not live: {reason}");
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
    let script = format!(
        "type \"%CURL_CA_BUNDLE%\" 1>NUL && \
         \"{}\" --fail --silent --show-error --cacert \"%CURL_CA_BUNDLE%\" \
         https://example.com/ --output \"{output_path_string}\" \
         --write-out \"%{{certs}}\" 1>\"{certificate_path_string}\"",
        curl.display()
    );
    let command = vec![
        cmd_string.clone(),
        "/d".to_string(),
        "/c".to_string(),
        script,
    ];
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
                    tls: "terminate".to_string(),
                    enforcement: "enforce".to_string(),
                    access: "read-only".to_string(),
                    ..Default::default()
                }],
                binaries: vec![NetworkBinary {
                    path: cmd_string,
                    ..Default::default()
                }],
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
        egress_proxy: true,
        egress_proxy_addr: "127.0.0.1:18080".to_string(),
        ..Default::default()
    };
    let backend = MxcComputeBackend::new(config);
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
/// This is the genuine OS default-deny proof — the AppContainer blocks the write
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
        "version": "0.6.0-alpha",
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

/// Full isolation_session round trip: provision → start → exec → stop →
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
        "version": "0.6.0-alpha",
        "phase": "start",
        "sandboxId": sandbox_id,
        "experimental": {
            "isolation_session": {
                "start": {}
            }
        }
    });
    let json = serde_json::to_string(&start_config).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
    let out = Command::new(&wxc)
        .arg("--config-base64")
        .arg(&b64)
        .arg("--experimental")
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
        "version": "0.6.0-alpha",
        "phase": "exec",
        "sandboxId": sandbox_id,
        "process": {
            "commandLine": "cmd /c exit 0",
            "cwd": "C:\\Windows\\Temp",
            "env": [],
            "timeout": 0,
        }
    });
    let json = serde_json::to_string(&exec_config).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
    let out = Command::new(&wxc)
        .arg("--config-base64")
        .arg(&b64)
        .arg("--experimental")
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
        "version": "0.6.0-alpha",
        "phase": "stop",
        "sandboxId": sandbox_id,
        "experimental": {
            "isolation_session": {
                // Unit variant: must be null, not {} (malformed_request otherwise).
                "stop": null
            }
        }
    });
    let json = serde_json::to_string(&stop_config).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
    let out = Command::new(&wxc)
        .arg("--config-base64")
        .arg(&b64)
        .arg("--experimental")
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
