// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `wxc-exec` invoker and MXC request/response types.
//!
//! Builds state-aware MXC config JSON, base64-encodes it, runs `wxc-exec`,
//! and parses the response envelope. The exec phase is special: its stdout is
//! live process output (not JSON) and its exit code is the agent exit code.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use thiserror::Error;
use tokio::process::Command;
use tracing::debug;

/// MXC config schema version.
pub const MXC_SCHEMA_VERSION: &str = "0.6.0-alpha";

/// Default `configurationId` for isolation session. Never use `"small"` (known OS bug).
pub const DEFAULT_CONFIGURATION_ID: &str = "composable";

/// Environment flag selecting the in-process mock `wxc-exec` shim. When set to
/// `"1"`, the invoker does NOT spawn the real `wxc-exec.exe`; instead it emits
/// canned provision/start/stop/deprovision results and simulates AppContainer
/// filesystem-policy enforcement for the exec phase. This is what makes the
/// full create → Ready → policy-proof round trip runnable off the demo box.
pub const MOCK_ENV_VAR: &str = "OPENSHELL_MXC_MOCK_WXC";

fn mock_enabled() -> bool {
    std::env::var(MOCK_ENV_VAR).map(|v| v == "1").unwrap_or(false)
}

/// Normalize a path/command fragment to lowercase backslash form for the mock's
/// in-policy substring check.
fn mock_normalize(s: &str) -> String {
    s.replace('/', "\\").to_lowercase()
}

/// Per-process mock state: `iso:` sandbox id → granted read-write paths
/// (normalized). Populated by the mock provision, consumed by the mock exec to
/// decide whether the agent's write target is in-policy.
fn mock_grants() -> &'static Mutex<HashMap<String, Vec<String>>> {
    static GRANTS: OnceLock<Mutex<HashMap<String, Vec<String>>>> = OnceLock::new();
    GRANTS.get_or_init(|| Mutex::new(HashMap::new()))
}

// ── Request types ─────────────────────────────────────────────────────────────

/// Filesystem shares for the sandbox (MXC provision-time only).
#[derive(Debug, Default, Serialize)]
pub struct MxcFilesystem {
    #[serde(rename = "readwritePaths", skip_serializing_if = "Vec::is_empty")]
    pub readwrite_paths: Vec<String>,
    #[serde(rename = "readonlyPaths", skip_serializing_if = "Vec::is_empty")]
    pub readonly_paths: Vec<String>,
}

/// Process config for the exec phase.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MxcProcess {
    pub command_line: String,
    pub cwd: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    /// 0 = no timeout (long-lived agent).
    pub timeout: u64,
}

// ── Response envelope ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ProvisionResult {
    #[serde(rename = "sandboxId")]
    pub sandbox_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum MxcEnvelope {
    Ok {
        #[allow(dead_code)]
        result: serde_json::Value,
    },
    Err { error: MxcErrorBody },
}

#[derive(Debug, Deserialize)]
pub struct MxcErrorBody {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct ProvisionEnvelope {
    pub result: Option<ProvisionResult>,
    pub error: Option<MxcErrorBody>,
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum InvokerError {
    #[error("wxc-exec spawn failed: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("wxc-exec config serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("wxc-exec envelope parse failed (stdout={stdout:?}): {source}")]
    Parse {
        stdout: String,
        source: serde_json::Error,
    },
    #[error("wxc-exec process failed with no envelope (exit={exit_code}, stderr={stderr:?})")]
    NoEnvelope { exit_code: i32, stderr: String },
    #[error("MXC error [{code}]: {message}")]
    Mxc { code: String, message: String },
    /// Exec phase returned a non-zero exit code (the agent's own exit status).
    /// Surfaced through the watch stream rather than as a gRPC error.
    #[allow(dead_code)]
    #[error("wxc-exec exec phase exited with code {0}")]
    ExecNonZero(i32),
}

impl InvokerError {
    #[allow(dead_code)]
    pub fn to_tonic_status(&self) -> tonic::Status {
        match self {
            Self::Mxc { code, message } => match code.as_str() {
                "malformed_request" | "unsupported_phase" => {
                    tonic::Status::internal(format!("driver bug: {message}"))
                }
                "unsupported_containment" | "not_provisioned" | "not_started"
                | "already_started" | "already_stopped" => {
                    tonic::Status::failed_precondition(message.clone())
                }
                "malformed_id" | "stale_id" => tonic::Status::not_found(message.clone()),
                "policy_validation" => tonic::Status::invalid_argument(message.clone()),
                "backend_unavailable" => tonic::Status::unavailable(message.clone()),
                _ => tonic::Status::internal(message.clone()),
            },
            Self::Spawn(e) => tonic::Status::internal(format!("wxc-exec spawn: {e}")),
            Self::Serialize(e) => tonic::Status::internal(format!("config serialize: {e}")),
            Self::Parse { .. } | Self::NoEnvelope { .. } => {
                tonic::Status::internal(self.to_string())
            }
            Self::ExecNonZero(code) => {
                tonic::Status::internal(format!("agent exited with code {code}"))
            }
        }
    }
}

// ── Invoker ───────────────────────────────────────────────────────────────────

/// Wraps `wxc-exec` invocations for the MXC state-aware lifecycle.
#[derive(Debug, Clone)]
pub struct WxcExecInvoker {
    exec_path: PathBuf,
    debug: bool,
    /// When true, use the in-process mock instead of spawning `wxc-exec.exe`.
    mock: bool,
}

impl WxcExecInvoker {
    pub fn new(exec_path: impl Into<PathBuf>, debug: bool) -> Self {
        Self {
            exec_path: exec_path.into(),
            debug,
            mock: mock_enabled(),
        }
    }

    /// Test-only constructor that forces mock mode without touching the
    /// process-global `OPENSHELL_MXC_MOCK_WXC` env var (avoids races/UB across
    /// parallel tests under edition 2024's `unsafe` `set_var`).
    #[cfg(test)]
    pub(crate) fn mocked(exec_path: impl Into<PathBuf>) -> Self {
        Self {
            exec_path: exec_path.into(),
            debug: false,
            mock: true,
        }
    }

    /// Encode `config` as base64 and invoke wxc-exec, returning the parsed envelope.
    /// Use this for all **non-exec** phases (provision/start/stop/deprovision).
    pub async fn run_phase(&self, config: &serde_json::Value) -> Result<(), InvokerError> {
        if self.mock {
            // Mock start/stop/deprovision: canned `{"result":{}}` success.
            debug!(phase = ?config.get("phase"), "mock wxc-exec phase (no-op success)");
            return Ok(());
        }
        let json = serde_json::to_string(config)?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());

        let mut cmd = Command::new(&self.exec_path);
        cmd.arg("--config-base64").arg(&b64).arg("--experimental");
        if self.debug {
            cmd.arg("--debug");
        }

        debug!(config = %json, "wxc-exec phase");
        let output = cmd.output().await?;

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

        if !output.status.success() {
            if let Ok(env) = serde_json::from_str::<MxcEnvelope>(&stdout) {
                if let MxcEnvelope::Err { error } = env {
                    return Err(InvokerError::Mxc {
                        code: error.code,
                        message: error.message,
                    });
                }
            }
            let code = output.status.code().unwrap_or(-1);
            return Err(InvokerError::NoEnvelope {
                exit_code: code,
                stderr,
            });
        }

        // Success — parse envelope to surface any embedded error field.
        match serde_json::from_str::<MxcEnvelope>(&stdout) {
            Ok(MxcEnvelope::Err { error }) => Err(InvokerError::Mxc {
                code: error.code,
                message: error.message,
            }),
            Ok(MxcEnvelope::Ok { .. }) => Ok(()),
            Err(_) if stdout.trim().is_empty() => {
                // Some phases return empty stdout on success.
                Ok(())
            }
            Err(e) => Err(InvokerError::Parse { stdout, source: e }),
        }
    }

    /// Run the provision phase and return the `sandboxId` from the response.
    pub async fn provision(
        &self,
        configuration_id: &str,
        filesystem: MxcFilesystem,
    ) -> Result<String, InvokerError> {
        if self.mock {
            // Mock provision: mint a synthetic `iso:` id and record the granted
            // read-write paths so the mock exec can enforce the policy.
            let id = format!("iso:mock-{}", uuid::Uuid::new_v4());
            let grants: Vec<String> = filesystem
                .readwrite_paths
                .iter()
                .map(|p| mock_normalize(p))
                .collect();
            mock_grants().lock().unwrap().insert(id.clone(), grants);
            debug!(sandbox_id = %id, "mock wxc-exec provision");
            return Ok(id);
        }
        let config = serde_json::json!({
            "version": MXC_SCHEMA_VERSION,
            "phase": "provision",
            "containment": "isolation_session",
            "filesystem": {
                "readwritePaths": filesystem.readwrite_paths,
                "readonlyPaths": filesystem.readonly_paths,
            },
            "experimental": {
                "isolation_session": {
                    "configurationId": configuration_id,
                    "provision": {}
                }
            }
        });

        let json = serde_json::to_string(&config)?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());

        let mut cmd = Command::new(&self.exec_path);
        cmd.arg("--config-base64").arg(&b64).arg("--experimental");
        if self.debug {
            cmd.arg("--debug");
        }

        debug!(config = %json, "wxc-exec provision");
        let output = cmd.output().await?;

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

        if !output.status.success() {
            let code = output.status.code().unwrap_or(-1);
            if let Ok(env) = serde_json::from_str::<ProvisionEnvelope>(&stdout) {
                if let Some(err) = env.error {
                    return Err(InvokerError::Mxc {
                        code: err.code,
                        message: err.message,
                    });
                }
            }
            return Err(InvokerError::NoEnvelope {
                exit_code: code,
                stderr,
            });
        }

        let env: ProvisionEnvelope = serde_json::from_str(&stdout).map_err(|e| {
            InvokerError::Parse {
                stdout: stdout.clone(),
                source: e,
            }
        })?;

        if let Some(err) = env.error {
            return Err(InvokerError::Mxc {
                code: err.code,
                message: err.message,
            });
        }

        env.result.map(|r| r.sandbox_id).ok_or_else(|| {
            InvokerError::NoEnvelope {
                exit_code: 0,
                stderr: "provision result missing sandboxId".to_string(),
            }
        })
    }

    /// Run the start phase for an already-provisioned sandbox.
    pub async fn start(&self, iso_sandbox_id: &str) -> Result<(), InvokerError> {
        let config = serde_json::json!({
            "version": MXC_SCHEMA_VERSION,
            "phase": "start",
            "sandboxId": iso_sandbox_id,
            "experimental": {
                "isolation_session": {
                    "start": {}
                }
            }
        });
        self.run_phase(&config).await
    }

    /// Spawn the exec phase (agent command). Returns the child process handle.
    /// **Stdout is raw agent output, not a JSON envelope. Exit code == agent exit code.**
    pub async fn spawn_exec(
        &self,
        iso_sandbox_id: &str,
        process: MxcProcess,
    ) -> Result<tokio::process::Child, InvokerError> {
        if self.mock {
            return self.mock_spawn_exec(iso_sandbox_id, &process);
        }
        let config = serde_json::json!({
            "version": MXC_SCHEMA_VERSION,
            "phase": "exec",
            "sandboxId": iso_sandbox_id,
            "process": {
                "commandLine": process.command_line,
                "cwd": process.cwd,
                "env": process.env,
                "timeout": process.timeout,
            }
        });

        let json = serde_json::to_string(&config)?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());

        let mut cmd = Command::new(&self.exec_path);
        cmd.arg("--config-base64")
            .arg(&b64)
            .arg("--experimental")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        if self.debug {
            cmd.arg("--debug");
        }

        debug!(sandbox_id = %iso_sandbox_id, command = %process.command_line, "wxc-exec exec spawn");
        let child = cmd.spawn()?;
        Ok(child)
    }

    /// Mock exec: simulate AppContainer filesystem-policy enforcement.
    ///
    /// The agent's write target is considered **in-policy** iff the command line
    /// references one of the granted read-write paths recorded at mock provision.
    /// In-policy → run the real agent command (so the positive-proof artifact,
    /// e.g. `hello.txt`, actually appears on the host shared folder). Out-of-policy
    /// → refuse with an access-denied message on stderr and a non-zero exit,
    /// mirroring how the AppContainer denies the write on the demo box.
    fn mock_spawn_exec(
        &self,
        iso_sandbox_id: &str,
        process: &MxcProcess,
    ) -> Result<tokio::process::Child, InvokerError> {
        let grants = mock_grants()
            .lock()
            .unwrap()
            .get(iso_sandbox_id)
            .cloned()
            .unwrap_or_default();
        let cmd_norm = mock_normalize(&process.command_line);
        let in_policy = grants.iter().any(|g| !g.is_empty() && cmd_norm.contains(g));

        let mut cmd = Command::new("cmd");
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        if in_policy {
            debug!(sandbox_id = %iso_sandbox_id, command = %process.command_line, "mock exec: in-policy, running agent");
            cmd.arg("/c").arg(&process.command_line);
        } else {
            debug!(sandbox_id = %iso_sandbox_id, command = %process.command_line, "mock exec: OUT-OF-POLICY, denying");
            // Emit an access-denied message to stderr and exit non-zero.
            cmd.arg("/c")
                .arg("echo Access is denied. (out-of-policy write blocked by AppContainer) 1>&2& exit 1");
        }
        let child = cmd.spawn()?;
        Ok(child)
    }

    /// Run the stop phase.
    pub async fn stop(&self, iso_sandbox_id: &str) -> Result<(), InvokerError> {
        let config = serde_json::json!({
            "version": MXC_SCHEMA_VERSION,
            "phase": "stop",
            "sandboxId": iso_sandbox_id,
            "experimental": {
                "isolation_session": {
                    "stop": {}
                }
            }
        });
        self.run_phase(&config).await
    }

    /// Run the deprovision phase.
    pub async fn deprovision(&self, iso_sandbox_id: &str) -> Result<(), InvokerError> {
        let config = serde_json::json!({
            "version": MXC_SCHEMA_VERSION,
            "phase": "deprovision",
            "sandboxId": iso_sandbox_id,
            "experimental": {
                "isolation_session": {
                    "deprovision": {}
                }
            }
        });
        self.run_phase(&config).await
    }
}

// ── Tests (pure serde — compile and run cross-platform) ──────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provision_envelope_parse_success() {
        let json = r#"{"result":{"sandboxId":"iso:wxc-abc123","metadata":{}}}"#;
        let env: ProvisionEnvelope = serde_json::from_str(json).unwrap();
        assert_eq!(env.result.unwrap().sandbox_id, "iso:wxc-abc123");
        assert!(env.error.is_none());
    }

    #[test]
    fn provision_envelope_parse_error() {
        let json = r#"{"error":{"code":"backend_unavailable","message":"IsoSessionApp.dll missing"}}"#;
        let env: ProvisionEnvelope = serde_json::from_str(json).unwrap();
        assert!(env.result.is_none());
        let err = env.error.unwrap();
        assert_eq!(err.code, "backend_unavailable");
    }

    #[test]
    fn mxc_envelope_success_variant() {
        let json = r#"{"result":{}}"#;
        let env: MxcEnvelope = serde_json::from_str(json).unwrap();
        assert!(matches!(env, MxcEnvelope::Ok { .. }));
    }

    #[test]
    fn mxc_envelope_error_variant() {
        let json = r#"{"error":{"code":"not_provisioned","message":"call provision first"}}"#;
        let env: MxcEnvelope = serde_json::from_str(json).unwrap();
        assert!(matches!(env, MxcEnvelope::Err { .. }));
    }

    #[test]
    fn provision_config_json_shape() {
        // Verify the JSON we send wxc-exec has the expected shape.
        let config = serde_json::json!({
            "version": MXC_SCHEMA_VERSION,
            "phase": "provision",
            "containment": "isolation_session",
            "filesystem": {
                "readwritePaths": ["C:\\work\\demo"],
                "readonlyPaths": [],
            },
            "experimental": {
                "isolation_session": {
                    "configurationId": DEFAULT_CONFIGURATION_ID,
                    "provision": {}
                }
            }
        });
        assert_eq!(config["phase"], "provision");
        assert_eq!(config["containment"], "isolation_session");
        assert_eq!(
            config["experimental"]["isolation_session"]["configurationId"],
            "composable"
        );
        assert_eq!(config["filesystem"]["readwritePaths"][0], "C:\\work\\demo");
    }

    #[test]
    fn invoker_error_maps_backend_unavailable_to_unavailable() {
        let err = InvokerError::Mxc {
            code: "backend_unavailable".into(),
            message: "missing DLL".into(),
        };
        let status = err.to_tonic_status();
        assert_eq!(status.code(), tonic::Code::Unavailable);
    }

    #[test]
    fn invoker_error_maps_policy_validation_to_invalid_argument() {
        let err = InvokerError::Mxc {
            code: "policy_validation".into(),
            message: "path denied".into(),
        };
        let status = err.to_tonic_status();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn invoker_error_maps_stale_id_to_not_found() {
        let err = InvokerError::Mxc {
            code: "stale_id".into(),
            message: "session expired".into(),
        };
        let status = err.to_tonic_status();
        assert_eq!(status.code(), tonic::Code::NotFound);
    }
}
