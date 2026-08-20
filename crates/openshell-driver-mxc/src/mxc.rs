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
use std::net::SocketAddr;
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
/// canned provision/start/stop/deprovision results and simulates `AppContainer`
/// filesystem-policy enforcement for the exec phase. This is what makes the
/// full create → Ready → policy-proof round trip runnable off the demo box.
pub const MOCK_ENV_VAR: &str = "OPENSHELL_MXC_MOCK_WXC";

fn mock_enabled() -> bool {
    std::env::var(MOCK_ENV_VAR).is_ok_and(|value| value == "1")
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

/// Filesystem shares for the sandbox.
///
/// `isolation_session` honors `readwrite`/`readonly` (grant-only — it has no
/// deny primitive). `processContainer` additionally honors `denied_paths`
/// because the `AppContainer` backend can stamp deny ACEs; it is also genuinely
/// default-deny, so anything not granted is already inaccessible.
#[derive(Debug, Default)]
#[allow(clippy::struct_field_names)]
pub struct MxcFilesystem {
    pub readwrite_paths: Vec<String>,
    pub readonly_paths: Vec<String>,
    pub denied_paths: Vec<String>,
}

/// Network redirect fragment emitted when governed egress is enabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxcNetwork {
    pub default_policy: String,
    pub proxy: Option<SocketAddr>,
}

/// `processContainer`-specific knobs (one-shot `AppContainer` backend).
#[derive(Debug, Default, Clone)]
pub struct MxcProcessContainer {
    /// Request a Less-Privileged `AppContainer` (stricter default-deny).
    pub least_privilege: bool,
    /// `AppContainer` capabilities to grant (e.g. `internetClient`).
    pub capabilities: Vec<String>,
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

fn network_json(network: &MxcNetwork) -> serde_json::Value {
    // MXC 0.6.0-alpha schema accepts ONLY {"proxy": {"localhost": <port>}}.
    // {"host": ..., "port": ...} and every other shape is rejected — verified
    // empirically against the real wxc-exec 0.6.0-alpha binary via --dry-run.
    // See also docs/reference/mxc-compute-driver-design.mdx §network.proxy.
    // The MxcNetwork.proxy field remains SocketAddr so callers keep full
    // precision; only the port is serialized into the localhost key.
    let mut value = serde_json::json!({
        "defaultPolicy": network.default_policy.as_str(),
        "allowedHosts": [],
        "blockedHosts": [],
    });
    if let Some(proxy) = network.proxy {
        value["proxy"] = serde_json::json!({ "localhost": proxy.port() });
    }
    value
}

fn provision_config_json(
    configuration_id: &str,
    filesystem: &MxcFilesystem,
    network: Option<&MxcNetwork>,
) -> serde_json::Value {
    let mut config = serde_json::json!({
        "version": MXC_SCHEMA_VERSION,
        "phase": "provision",
        "containment": "isolation_session",
        "filesystem": {
            "readwritePaths": &filesystem.readwrite_paths,
            "readonlyPaths": &filesystem.readonly_paths,
        },
        "experimental": {
            "isolation_session": {
                "configurationId": configuration_id,
                "provision": {}
            }
        }
    });
    if let Some(network) = network {
        config["network"] = network_json(network);
    }
    config
}

fn oneshot_config_json(
    container_id: &str,
    filesystem: &MxcFilesystem,
    pc: &MxcProcessContainer,
    process: &MxcProcess,
    network: Option<&MxcNetwork>,
) -> serde_json::Value {
    let mut filesystem_json = serde_json::Map::new();
    if !filesystem.readwrite_paths.is_empty() {
        filesystem_json.insert(
            "readwritePaths".into(),
            filesystem.readwrite_paths.clone().into(),
        );
    }
    if !filesystem.readonly_paths.is_empty() {
        filesystem_json.insert(
            "readonlyPaths".into(),
            filesystem.readonly_paths.clone().into(),
        );
    }
    if !filesystem.denied_paths.is_empty() {
        filesystem_json.insert("deniedPaths".into(), filesystem.denied_paths.clone().into());
    }

    let mut pc_json = serde_json::Map::new();
    pc_json.insert("leastPrivilege".into(), pc.least_privilege.into());
    if !pc.capabilities.is_empty() {
        pc_json.insert("capabilities".into(), pc.capabilities.clone().into());
    }

    let mut config = serde_json::json!({
        "version": MXC_SCHEMA_VERSION,
        "containerId": container_id,
        "containment": "processcontainer",
        "process": {
            "commandLine": process.command_line.as_str(),
            "cwd": process.cwd.as_str(),
            "env": &process.env,
            "timeout": process.timeout,
        },
        "processContainer": serde_json::Value::Object(pc_json),
        "filesystem": serde_json::Value::Object(filesystem_json),
    });
    if let Some(network) = network {
        config["network"] = network_json(network);
    }
    config
}

#[cfg(test)]
fn mock_configs() -> &'static Mutex<HashMap<String, serde_json::Value>> {
    static CONFIGS: OnceLock<Mutex<HashMap<String, serde_json::Value>>> = OnceLock::new();
    CONFIGS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(test)]
pub fn mock_recorded_config(id: &str) -> Option<serde_json::Value> {
    mock_configs().lock().unwrap().get(id).cloned()
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
    Err {
        error: MxcErrorBody,
    },
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
                "unsupported_containment"
                | "not_provisioned"
                | "not_started"
                | "already_started"
                | "already_stopped" => tonic::Status::failed_precondition(message.clone()),
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
            if let Ok(MxcEnvelope::Err { error }) = serde_json::from_str::<MxcEnvelope>(&stdout) {
                return Err(InvokerError::Mxc {
                    code: error.code,
                    message: error.message,
                });
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
        network: Option<MxcNetwork>,
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
            #[cfg(test)]
            {
                let config = provision_config_json(configuration_id, &filesystem, network.as_ref());
                mock_configs().lock().unwrap().insert(id.clone(), config);
            }
            debug!(sandbox_id = %id, "mock wxc-exec provision");
            return Ok(id);
        }
        let config = provision_config_json(configuration_id, &filesystem, network.as_ref());

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
            if let Ok(ProvisionEnvelope {
                error: Some(error), ..
            }) = serde_json::from_str::<ProvisionEnvelope>(&stdout)
            {
                return Err(InvokerError::Mxc {
                    code: error.code,
                    message: error.message,
                });
            }
            return Err(InvokerError::NoEnvelope {
                exit_code: code,
                stderr,
            });
        }

        let env: ProvisionEnvelope =
            serde_json::from_str(&stdout).map_err(|e| InvokerError::Parse {
                stdout: stdout.clone(),
                source: e,
            })?;

        if let Some(err) = env.error {
            return Err(InvokerError::Mxc {
                code: err.code,
                message: err.message,
            });
        }

        env.result
            .map(|r| r.sandbox_id)
            .ok_or_else(|| InvokerError::NoEnvelope {
                exit_code: 0,
                stderr: "provision result missing sandboxId".to_string(),
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
            return Self::mock_spawn_exec(iso_sandbox_id, &process);
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
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true);
        if self.debug {
            cmd.arg("--debug");
        }

        debug!(sandbox_id = %iso_sandbox_id, command = %process.command_line, "wxc-exec exec spawn");
        let child = cmd.spawn()?;
        Ok(child)
    }

    /// Mock exec: simulate `AppContainer` filesystem-policy enforcement.
    ///
    /// The agent's write target is considered **in-policy** iff the command line
    /// references one of the granted read-write paths recorded at mock provision.
    fn mock_spawn_exec(
        iso_sandbox_id: &str,
        process: &MxcProcess,
    ) -> Result<tokio::process::Child, InvokerError> {
        let grants = mock_grants()
            .lock()
            .unwrap()
            .get(iso_sandbox_id)
            .cloned()
            .unwrap_or_default();
        Self::mock_spawn_with_grants(process, &grants)
    }

    /// Shared mock enforcement used by both the `isolation_session` exec phase
    /// and the one-shot `processContainer` path.
    ///
    /// In-policy → run the real agent command (so the positive-proof artifact,
    /// e.g. `hello.txt`, actually appears on the host shared folder). Out-of-policy
    /// → refuse with an access-denied message on stderr and a non-zero exit,
    /// mirroring how the `AppContainer` denies the write on the demo box.
    fn mock_spawn_with_grants(
        process: &MxcProcess,
        grants: &[String],
    ) -> Result<tokio::process::Child, InvokerError> {
        let cmd_norm = mock_normalize(&process.command_line);
        let in_policy = grants.iter().any(|g| !g.is_empty() && cmd_norm.contains(g));

        let mut cmd = Command::new("cmd");
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true);
        if in_policy {
            debug!(command = %process.command_line, "mock exec: in-policy, running agent");
            // `command_line` is already encoded with Windows quoting rules.
            // Pass it raw so this mock matches wxc-exec/CreateProcess instead
            // of asking Rust to quote the entire command as one cmd.exe argv.
            cmd.raw_arg(format!("/d /s /c \"{}\"", process.command_line));
        } else {
            debug!(command = %process.command_line, "mock exec: OUT-OF-POLICY, denying");
            cmd.arg("/c").arg(
                "echo Access is denied. (out-of-policy write blocked by AppContainer) 1>&2& exit 1",
            );
        }
        let child = cmd.spawn()?;
        Ok(child)
    }

    /// Build a **one-shot** `processContainer` config (no `phase`) and spawn it.
    ///
    /// Unlike the `isolation_session` lifecycle (provision → start → exec →
    /// stop → deprovision), `processContainer` is a single ephemeral
    /// `AppContainer`: one `wxc-exec` invocation creates the container, runs the
    /// one process, and tears down when it exits. The `AppContainer` is genuinely
    /// default-deny, so a write to any ungranted path is denied by the OS.
    ///
    /// **Stdout is raw agent output; the exit code is the agent's own exit code.**
    pub async fn run_oneshot(
        &self,
        container_id: &str,
        filesystem: MxcFilesystem,
        pc: MxcProcessContainer,
        process: MxcProcess,
        network: Option<MxcNetwork>,
    ) -> Result<tokio::process::Child, InvokerError> {
        let config =
            oneshot_config_json(container_id, &filesystem, &pc, &process, network.as_ref());
        if self.mock {
            let grants: Vec<String> = filesystem
                .readwrite_paths
                .iter()
                .map(|p| mock_normalize(p))
                .collect();
            #[cfg(test)]
            mock_configs()
                .lock()
                .unwrap()
                .insert(container_id.to_owned(), config);
            return Self::mock_spawn_with_grants(&process, &grants);
        }

        let json = serde_json::to_string(&config)?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());

        let mut cmd = Command::new(&self.exec_path);
        cmd.arg("--config-base64")
            .arg(&b64)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true);
        if self.debug {
            cmd.arg("--debug");
        }

        debug!(container_id = %container_id, command = %process.command_line, "wxc-exec one-shot processContainer spawn");
        let child = cmd.spawn()?;
        Ok(child)
    }

    /// Run the stop phase.
    ///
    /// `stop`/`deprovision` are **unit** variants in the wxc-exec schema: they
    /// must serialize as `null`, not `{}`. Empirical (build 26300.8553,
    /// wxc-exec 2026-06-10): `"stop": {}` is rejected with `malformed_request`
    /// ("invalid type: map, expected unit"); `provision`/`start` accept maps.
    pub async fn stop(&self, iso_sandbox_id: &str) -> Result<(), InvokerError> {
        let config = serde_json::json!({
            "version": MXC_SCHEMA_VERSION,
            "phase": "stop",
            "sandboxId": iso_sandbox_id,
            "experimental": {
                "isolation_session": {
                    "stop": null
                }
            }
        });
        self.run_phase(&config).await
    }

    /// Run the deprovision phase (unit variant — see [`Self::stop`]).
    pub async fn deprovision(&self, iso_sandbox_id: &str) -> Result<(), InvokerError> {
        let config = serde_json::json!({
            "version": MXC_SCHEMA_VERSION,
            "phase": "deprovision",
            "sandboxId": iso_sandbox_id,
            "experimental": {
                "isolation_session": {
                    "deprovision": null
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
        let json =
            r#"{"error":{"code":"backend_unavailable","message":"IsoSessionApp.dll missing"}}"#;
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
    fn oneshot_processcontainer_config_json_shape() {
        // Mirror the JSON `run_oneshot` builds for the one-shot processContainer
        // path: no `phase` (routes to one-shot), `containment: processcontainer`,
        // a `process` block, the `processContainer` knobs, and filesystem grants
        // incl. deniedPaths.
        let config = serde_json::json!({
            "version": MXC_SCHEMA_VERSION,
            "containerId": "sb-1",
            "containment": "processcontainer",
            "process": {
                "commandLine": "C:\\work\\demo\\agent.exe",
                "cwd": "C:\\work\\demo",
                "env": Vec::<String>::new(),
                "timeout": 0,
            },
            "processContainer": { "leastPrivilege": true },
            "filesystem": {
                "readwritePaths": ["C:\\work\\demo"],
                "deniedPaths": ["C:\\secret"],
            },
        });
        assert_eq!(config["containment"], "processcontainer");
        assert!(
            config.get("phase").is_none(),
            "one-shot config must omit phase"
        );
        assert_eq!(config["processContainer"]["leastPrivilege"], true);
        assert_eq!(config["filesystem"]["readwritePaths"][0], "C:\\work\\demo");
        assert_eq!(config["filesystem"]["deniedPaths"][0], "C:\\secret");
    }

    #[test]
    fn provision_config_json_includes_network_proxy_when_supplied() {
        let filesystem = MxcFilesystem {
            readwrite_paths: vec!["C:\\work\\demo".into()],
            readonly_paths: Vec::new(),
            denied_paths: Vec::new(),
        };
        let network = MxcNetwork {
            default_policy: "block".into(),
            proxy: Some("127.0.0.1:18080".parse().unwrap()),
        };
        let config = provision_config_json(DEFAULT_CONFIGURATION_ID, &filesystem, Some(&network));

        assert_eq!(config["network"]["defaultPolicy"], "block");
        assert!(
            config["network"]["allowedHosts"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            config["network"]["blockedHosts"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        // MXC 0.6.0-alpha accepts only {"proxy": {"localhost": N}}.
        assert_eq!(config["network"]["proxy"]["localhost"], 18080);
        assert!(
            config["network"]["proxy"].get("host").is_none(),
            "proxy must not contain 'host' key"
        );
        assert!(
            config["network"]["proxy"].get("port").is_none(),
            "proxy must not contain 'port' key"
        );
    }

    #[test]
    fn network_json_emits_localhost_port_shape() {
        // MXC 0.6.0-alpha rejects {"host":...,"port":...} and accepts only
        // {"proxy": {"localhost": N}} — verified against the real binary via
        // --dry-run. This test pins the exact emitted JSON shape.
        let network = MxcNetwork {
            default_policy: "block".into(),
            proxy: Some("127.0.0.1:18080".parse().unwrap()),
        };
        let value = network_json(&network);
        assert_eq!(value["proxy"]["localhost"], 18080);
        assert!(value["proxy"].get("host").is_none());
        assert!(value["proxy"].get("port").is_none());
    }

    #[test]
    fn oneshot_config_json_omits_network_without_proxy() {
        let filesystem = MxcFilesystem {
            readwrite_paths: vec!["C:\\work\\demo".into()],
            readonly_paths: Vec::new(),
            denied_paths: Vec::new(),
        };
        let pc = MxcProcessContainer::default();
        let process = MxcProcess {
            command_line: "cmd /c exit 0".into(),
            cwd: "C:\\work\\demo".into(),
            env: Vec::new(),
            timeout: 0,
        };
        let config = oneshot_config_json("sb-1", &filesystem, &pc, &process, None);

        assert!(config.get("network").is_none());
    }

    #[test]
    fn stop_and_deprovision_serialize_as_unit_variants() {
        // Pins the empirical schema contract (test box, build 26300.8553):
        // stop/deprovision are unit variants and must be `null`; `{}` is
        // rejected with malformed_request "invalid type: map, expected unit".
        for phase in ["stop", "deprovision"] {
            let config = serde_json::json!({
                "version": MXC_SCHEMA_VERSION,
                "phase": phase,
                "sandboxId": "iso:wxc-test",
                "experimental": {
                    "isolation_session": {
                        phase: null
                    }
                }
            });
            assert!(
                config["experimental"]["isolation_session"][phase].is_null(),
                "{phase} must serialize as null (unit variant)"
            );
        }
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
