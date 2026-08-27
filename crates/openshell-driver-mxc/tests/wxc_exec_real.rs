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
//!   schema acceptance. Some `wxc-exec` builds select the DACL fallback during
//!   dry-run and validate filesystem grants, so these tests use owned temporary
//!   directories with concrete Windows paths.
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
use std::path::PathBuf;
use std::process::Command;

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

    let tmpdir = tempfile::tempdir().expect("tempdir");
    let tmpdir_str = tmpdir.path().to_string_lossy().into_owned();
    let config = serde_json::json!({
        "version": "0.6.0-alpha",
        "containerId": "test-minimal",
        "containment": "processcontainer",
        "process": {
            "commandLine": "cmd /c exit 0",
            "cwd": tmpdir_str,
            "timeout": 0,
        },
        "filesystem": {
            "readwritePaths": [tmpdir_str],
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

    let tmpdir = tempfile::tempdir().expect("tempdir");
    let tmpdir_str = tmpdir.path().to_string_lossy().into_owned();
    let config = serde_json::json!({
        "version": "0.6.0-alpha",
        "containerId": "test-net-block",
        "containment": "processcontainer",
        "process": {
            "commandLine": "cmd /c exit 0",
            "cwd": tmpdir_str,
            "timeout": 0,
        },
        "filesystem": {
            "readwritePaths": [tmpdir_str],
        },
        "network": {
            "defaultPolicy": "block",
            "allowedHosts": [],
            "blockedHosts": [],
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

    let tmpdir = tempfile::tempdir().expect("tempdir");
    let tmpdir_str = tmpdir.path().to_string_lossy().into_owned();
    let config = serde_json::json!({
        "version": "0.6.0-alpha",
        "containerId": "test-proxy-localhost",
        "containment": "processcontainer",
        "process": {
            "commandLine": "cmd /c exit 0",
            "cwd": tmpdir_str,
            "timeout": 0,
        },
        "filesystem": {
            "readwritePaths": [tmpdir_str],
        },
        "network": {
            "defaultPolicy": "block",
            "allowedHosts": [],
            "blockedHosts": [],
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

    let config = serde_json::json!({
        "version": "0.6.0-alpha",
        "containerId": "test-proxy-hostport",
        "containment": "processcontainer",
        "process": {
            "commandLine": "cmd /c exit 0",
            "cwd": "%TEMP%",
            "timeout": 0,
        },
        "filesystem": {
            "readwritePaths": ["%TEMP%"],
        },
        "network": {
            "defaultPolicy": "block",
            "allowedHosts": [],
            "blockedHosts": [],
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

    let config = serde_json::json!({
        "version": "0.6.0-alpha",
        "containerId": "test-bad-containment",
        "containment": "nonsense",
        "process": {
            "commandLine": "cmd /c exit 0",
            "cwd": "%TEMP%",
            "timeout": 0,
        },
        "filesystem": {
            "readwritePaths": ["%TEMP%"],
        },
    });

    let (code, _stdout, _stderr) = dry_run(&wxc, &config);
    assert_ne!(code, 0, "unknown containment 'nonsense' should be rejected");
}

/// The most important dry-run test: parse the quickstart example policy with
/// `openshell_policy`, run `split_policy` (`proxy_redirect` 127.0.0.1:18080,
/// containment "processcontainer"), take the resulting `mxc_config`, inject a
/// real process block with a valid cwd, and verify that `--dry-run` exits 0.
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

    // Find the quickstart policy relative to CARGO_MANIFEST_DIR.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let policy_path = manifest_dir.join("../../examples/sandbox-policy-quickstart/policy.yaml");

    if !policy_path.exists() {
        eprintln!(
            "SKIP: quickstart policy not found at {}",
            policy_path.display()
        );
        return;
    }

    let yaml = std::fs::read_to_string(&policy_path).expect("read policy YAML");
    let policy = openshell_policy::parse_sandbox_policy(&yaml).expect("parse quickstart policy");

    let opts = openshell_driver_mxc::MxcMappingOptions {
        containment: "processcontainer".to_string(),
        proxy_redirect: Some("127.0.0.1:18080".parse().unwrap()),
        ..Default::default()
    };

    let result = openshell_driver_mxc::split_policy(&policy, &opts)
        .expect("split_policy must return Some when proxy_redirect is set");
    // The quickstart policy has network_policies with error-level losses on
    // isolation_session, but on processcontainer there should be zero error
    // losses from the split itself. Warn if there are any error losses so the
    // test is informative even when it proceeds.
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

    // Take the mapper's MXC config and inject the required process block.
    // The split config does not include a process block (that comes from the
    // gateway TOML at runtime); wxc-exec --dry-run requires one.
    //
    // The quickstart policy uses sandbox-internal Unix paths. Replace only the
    // environment-dependent filesystem paths with an owned Windows directory:
    // this test verifies the mapper's MXC JSON shape, while mapper unit tests
    // cover the exact filesystem translation.
    let tmpdir = tempfile::tempdir().expect("tempdir");
    let tmpdir_str = tmpdir.path().to_string_lossy().into_owned();
    let mut mxc_config = result.mxc_config.clone();
    mxc_config["filesystem"] = serde_json::json!({
        "readwritePaths": [tmpdir_str],
        "readonlyPaths": [],
        "deniedPaths": [],
    });
    mxc_config["process"] = serde_json::json!({
        "commandLine": "cmd /c exit 0",
        "cwd": tmpdir_str,
        "timeout": 0,
    });
    // containerId is also required for processcontainer.
    mxc_config["containerId"] = serde_json::json!("split-policy-dryrun");

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
/// Runs a trivial one-shot (`cmd /c exit 0`, owned temporary-directory grant).
/// Returns `Ok(())` when the backend is live, or `Err(reason)` when it is not (the
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

    let tmpdir = tempfile::tempdir().map_err(|error| format!("tempdir failed: {error}"))?;
    let tmpdir_str = tmpdir.path().to_string_lossy().into_owned();
    let config = serde_json::json!({
        "version": "0.6.0-alpha",
        "containerId": "probe-pc",
        "containment": "processcontainer",
        "process": {
            "commandLine": "cmd /c exit 0",
            "cwd": tmpdir_str,
            "timeout": 10,
        },
        "filesystem": {
            "readwritePaths": [tmpdir_str],
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
            "timeout": 30,
        },
        "filesystem": {
            "readwritePaths": [tmpdir_str],
        },
        "processContainer": {
            "leastPrivilege": false,
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
        "version": "0.6.0-alpha",
        "containerId": "pc-out-of-policy-write",
        "containment": "processcontainer",
        "process": {
            "commandLine": format!("cmd /c echo denied > \"{denied_file_str}\""),
            "cwd": granted_str,
            "timeout": 30,
        },
        "filesystem": {
            // Only the granted_dir is in policy — denied_dir is NOT granted.
            "readwritePaths": [granted_str],
        },
        "processContainer": {
            "leastPrivilege": false,
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
