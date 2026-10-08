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
use tracing::{debug, info};

/// Stable MXC config schema version shared by the mapper and live launcher.
pub const MXC_SCHEMA_VERSION: &str = "1.0.0";

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
/// in-policy path check.
fn mock_normalize(s: &str) -> String {
    s.replace('/', "\\").to_lowercase()
}

fn mock_command_references_grant(command: &str, grant: &str) -> bool {
    if grant.is_empty() {
        return false;
    }

    command.match_indices(grant).any(|(start, _)| {
        let before = command[..start].chars().next_back();
        let after = command[start + grant.len()..].chars().next();
        let is_shell_boundary = |ch: char| {
            ch.is_whitespace()
                || matches!(
                    ch,
                    '"' | '\'' | '=' | '>' | '<' | '(' | ')' | '&' | '|' | ';'
                )
        };
        let starts_at_boundary = before.is_none_or(is_shell_boundary);
        let ends_at_boundary =
            grant.ends_with('\\') || after.is_none_or(|ch| ch == '\\' || is_shell_boundary(ch));
        starts_at_boundary && ends_at_boundary
    })
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
/// `processContainer` honors `readwrite`/`readonly` and `denied_paths`. The
/// `AppContainer` backend is genuinely default-deny, so anything not granted is
/// already inaccessible. `isolation_session` rejects non-empty filesystem
/// grants; its backend defaults determine visibility when no grants are present.
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
    /// MXC 1.0 `network.egress.default` action.
    pub egress_default: String,
    pub proxy: Option<SocketAddr>,
    /// When true, permits inbound/private-network and host-loopback traffic
    /// through the MXC 1.0 directional `network.ingress` policy. Required for
    /// node.js to initialize inside a processcontainer — without it, node.exe
    /// DLL initialization fails with `STATUS_DLL_INIT_FAILED`.
    pub allow_local_network: bool,
}

/// Directional clipboard access in the MXC top-level `ui` policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MxcClipboardAccess {
    None,
    Read,
    Write,
    All,
}

impl MxcClipboardAccess {
    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Read => "read",
            Self::Write => "write",
            Self::All => "all",
        }
    }
}

/// Cross-platform MXC UI policy emitted for a process container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxcUi {
    pub disable: bool,
    pub clipboard: MxcClipboardAccess,
    pub injection: bool,
}

fn ui_json(ui: &MxcUi) -> serde_json::Value {
    serde_json::json!({
        "disable": ui.disable,
        "clipboard": ui.clipboard.as_str(),
        "injection": ui.injection,
    })
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

/// Redacts `process.env` and `process.commandLine` from a wxc-config JSON
/// before it's ever logged or written to a sandbox-readable path (only
/// under `self.debug`, but debug output still isn't a safe place for it).
/// Both can carry host secrets verbatim -- `env` e.g. the shipped
/// `OpenClaw` example config's `OPENCLAW_GATEWAY_TOKEN`, `commandLine`
/// whenever a secret is passed as a literal CLI argument -- and both debug
/// sinks (gateway logs, and for `run_oneshot` a file inside the sandbox's
/// own readwrite path) are places an attacker or an over-broad log
/// retention policy could read from. Everything else debug tooling might
/// need to compare (filesystem grants, network policy, ...) is left intact.
fn redact_env_for_debug(config: &serde_json::Value) -> serde_json::Value {
    let mut redacted = config.clone();
    if let Some(env) = redacted.get_mut("process").and_then(|p| p.get_mut("env")) {
        let count = env.as_array().map_or(0, Vec::len);
        *env = serde_json::json!(format!("<redacted: {count} entries>"));
    }
    if let Some(command_line) = redacted
        .get_mut("process")
        .and_then(|p| p.get_mut("commandLine"))
    {
        *command_line = serde_json::json!("<redacted>");
    }
    redacted
}

fn network_json(network: &MxcNetwork) -> serde_json::Value {
    let mut value = if network.proxy.is_some() {
        // Use direct loopback egress rather than runtimeConfig.networkProxy proxy
        // mode. Proxy mode routes all outbound TCP through processmodel.dll's WFP
        // redirect, which in practice blocks loopback connects from the relay to
        // its target process (127.0.0.1:port) even with networkLoopback capability
        // in the PSEC spec. Direct allow for 127.0.0.1/32 (not the broader 127.0.0.0/8
        // range -- openshell-supervisor-relay only ever dials the literal
        // 127.0.0.1, see imp.rs) lets the relay reach:
        //   - the target it spawns (loopback inside AppContainer)
        //   - the host relay listener (also 127.0.0.1 via egress allow)
        // PSEC tier is still selected because requires_psec_networking() returns
        // true when egress.allow is non-empty (no NetworkIsolationSetAppContainerConfig
        // call needed — no elevation required).
        //
        // Deliberately no `ports` restriction: `openshell forward service`'s
        // dynamic bridge (imp.rs's "forward" control-channel op) connects the
        // relay out to a fresh, per-request ephemeral host port chosen at
        // forward-call time (data.relay_addr), not a port known when this
        // config is generated -- confirmed 2026-09-10 that scoping `ports` to
        // just [proxy.port(), relay_target_port] breaks that dynamic forward
        // (ws-echo failed with a "forbidden by access permissions" / 10013
        // relay-connect error). Any-port-on-127.0.0.1 is the correct scope
        // here, not a narrower static list.
        serde_json::json!({
            "egress": {
                "default": "deny",
                "allow": [{"to": [{"cidr": "127.0.0.1/32"}]}]
            },
            "ingress": { "default": "allow", "hostLoopback": "allow" },
        })
    } else {
        serde_json::json!({ "egress": { "default": network.egress_default } })
    };
    if network.proxy.is_none() && network.allow_local_network {
        value["ingress"] = serde_json::json!({ "default": "allow", "hostLoopback": "allow" });
    }
    value
}

fn provision_config_json() -> serde_json::Value {
    serde_json::json!({
        "version": MXC_SCHEMA_VERSION,
        "containment": "isolation_session",
        // IsolationSession cannot restrict networking. MXC 1.0.0 requires the
        // provision request to declare that actual all-allow posture exactly.
        "network": {
            "egress": { "default": "allow" },
            "ingress": { "default": "allow", "hostLoopback": "allow" },
        }
    })
}

fn lifecycle_config_json() -> serde_json::Value {
    serde_json::json!({ "version": MXC_SCHEMA_VERSION })
}

fn exec_config_json(process: &MxcProcess) -> serde_json::Value {
    serde_json::json!({
        "version": MXC_SCHEMA_VERSION,
        "process": {
            "commandLine": process.command_line,
            "cwd": process.cwd,
            "env": process.env,
            // IsolationSession always starts from the agent user's default
            // environment. MXC 1.0.0 rejects a supplied env array unless
            // callers explicitly request layering instead of replacement.
            "inheritDefaultEnv": true,
            "timeout": process.timeout,
        }
    })
}

fn oneshot_config_json(
    container_id: &str,
    filesystem: &MxcFilesystem,
    pc: &MxcProcessContainer,
    process: &MxcProcess,
    network: Option<&MxcNetwork>,
    ui: Option<&MxcUi>,
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
    // Root-level ui section required by mxc-fixes-env-vars build. Comes from
    // the typed SandboxPolicy via `ui` -- EmbeddedPolicyMapper always
    // populates this for process_container (with restrictive defaults --
    // disable=true, Win32k syscall lockdown -- when the policy has no
    // explicit `ui:` section), so `None` here only happens in tests that
    // bypass the mapper; omit the section entirely rather than guess.
    if let Some(ui) = ui {
        config["ui"] = ui_json(ui);
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

    /// Encode a lifecycle config as base64 and invoke `wxc-exec`.
    ///
    /// MXC 1.0.0 takes the operation and sandbox identity as command-line
    /// routing arguments. The config must omit the legacy `phase` and
    /// `sandboxId` fields because the executor injects them before validation.
    async fn run_phase(
        &self,
        operation: &str,
        sandbox_id: &str,
        config: &serde_json::Value,
    ) -> Result<(), InvokerError> {
        if self.mock {
            // Mock start/stop/deprovision: canned `{"result":{}}` success.
            debug!(operation, sandbox_id, "mock wxc-exec phase (no-op success)");
            return Ok(());
        }
        let json = serde_json::to_string(config)?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());

        let mut cmd = Command::new(&self.exec_path);
        cmd.arg("--config-base64")
            .arg(&b64)
            .arg("--operation")
            .arg(operation)
            .arg("--container-id")
            .arg(sandbox_id);
        if self.debug {
            cmd.arg("--debug");
        }

        debug!(operation, sandbox_id, config = %redact_env_for_debug(config), "wxc-exec phase");
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
    pub async fn provision(&self, filesystem: MxcFilesystem) -> Result<String, InvokerError> {
        if !filesystem.readwrite_paths.is_empty()
            || !filesystem.readonly_paths.is_empty()
            || !filesystem.denied_paths.is_empty()
        {
            return Err(InvokerError::Mxc {
                code: "policy_validation".into(),
                message: "MXC 1.0 isolation_session cannot enforce filesystem grants".into(),
            });
        }
        if self.mock {
            // Mock provision: mint a synthetic `iso:` id. IsolationSession has
            // no filesystem grants in MXC 1.0, so the recorded grant set is empty.
            let id = format!("iso:mock-{}", uuid::Uuid::new_v4());
            let grants: Vec<String> = filesystem
                .readwrite_paths
                .iter()
                .map(|p| mock_normalize(p))
                .collect();
            mock_grants().lock().unwrap().insert(id.clone(), grants);
            #[cfg(test)]
            {
                let config = provision_config_json();
                mock_configs().lock().unwrap().insert(id.clone(), config);
            }
            debug!(sandbox_id = %id, "mock wxc-exec provision");
            return Ok(id);
        }
        let config = provision_config_json();

        let json = serde_json::to_string(&config)?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());

        let mut cmd = Command::new(&self.exec_path);
        cmd.arg("--config-base64")
            .arg(&b64)
            .arg("--operation")
            .arg("provision");
        if self.debug {
            cmd.arg("--debug");
        }

        let redacted = redact_env_for_debug(&config);
        if self.debug {
            let pretty = serde_json::to_string_pretty(&redacted).unwrap_or_else(|_| json.clone());
            info!("generated wxc-config (provision):\n{pretty}");
        } else {
            debug!(config = %redacted, "wxc-exec provision");
        }
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
        let config = lifecycle_config_json();
        self.run_phase("start", iso_sandbox_id, &config).await
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
        let config = exec_config_json(&process);

        let json = serde_json::to_string(&config)?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());

        let mut cmd = Command::new(&self.exec_path);
        cmd.arg("--config-base64")
            .arg(&b64)
            .arg("--operation")
            .arg("exec")
            .arg("--container-id")
            .arg(iso_sandbox_id)
            // Piped (not null): mirrors the ProcessContainer one-shot spawn
            // below -- with STDIO passthrough, wxc-exec forwards this handle
            // down to the exec'd child, giving the driver a control channel
            // into the isolation_session sandbox with no network capability
            // required. Without this, pc_relay_spawner_path's control channel
            // (and therefore dynamic `openshell forward service`) silently
            // has nothing to attach to on this backend.
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        if self.debug {
            cmd.arg("--debug");
        }

        if self.debug {
            let redacted = redact_env_for_debug(&config);
            let pretty = serde_json::to_string_pretty(&redacted).unwrap_or_else(|_| json.clone());
            info!(sandbox_id = %iso_sandbox_id, "generated wxc-config (exec):\n{pretty}");
        }
        info!(sandbox_id = %iso_sandbox_id, "wxc-exec exec spawn");
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
        let in_policy = grants
            .iter()
            .any(|grant| mock_command_references_grant(&cmd_norm, grant));

        let command_shell = std::env::var_os("COMSPEC")
            .unwrap_or_else(|| std::ffi::OsString::from(r"C:\Windows\System32\cmd.exe"));
        let mut cmd = Command::new(command_shell);
        cmd.env_clear();
        for entry in &process.env {
            if let Some((key, value)) = entry.split_once('=') {
                cmd.env(key, value);
            }
        }
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
        ui: Option<MxcUi>,
    ) -> Result<tokio::process::Child, InvokerError> {
        let config = oneshot_config_json(
            container_id,
            &filesystem,
            &pc,
            &process,
            network.as_ref(),
            ui.as_ref(),
        );
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
        if self.debug {
            // Redacted before either sink: the readwrite path is inside the
            // sandbox itself (readable by whatever untrusted code runs
            // there), and gateway logs may have broader retention/access
            // than the secrets in `process.env` (e.g. OPENCLAW_GATEWAY_TOKEN
            // in the shipped OpenClaw example config) should get.
            let redacted = redact_env_for_debug(&config);
            let redacted_json = serde_json::to_string(&redacted).unwrap_or_else(|_| json.clone());
            // Dump into the first readwrite path for comparison.
            if let Some(rw) = config
                .get("filesystem")
                .and_then(|f| f.get("readwritePaths"))
                .and_then(|a| a.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
            {
                let _ = std::fs::write(
                    std::path::Path::new(rw).join("wxc-exec-config-debug.json"),
                    &redacted_json,
                );
            }
            let pretty =
                serde_json::to_string_pretty(&redacted).unwrap_or_else(|_| redacted_json.clone());
            info!(container_id = %container_id, "generated wxc-config:\n{pretty}");
        }
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());

        let mut cmd = Command::new(&self.exec_path);
        cmd.arg("--config-base64")
            .arg(&b64)
            // Piped (not null): with STDIO passthrough, wxc-exec forwards this
            // handle down to the sandboxed child, giving the driver a write
            // channel into the AppContainer with no network capability
            // required at all -- see openshell-supervisor-relay's stdin/stdout
            // JSON control protocol.
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        if self.debug {
            cmd.arg("--debug");
        }

        info!(container_id = %container_id, "wxc-exec one-shot processContainer spawn");
        let child = cmd.spawn()?;
        Ok(child)
    }

    /// Run the stop phase.
    ///
    /// MXC 1.0.0 selects the operation and sandbox through CLI arguments, so
    /// the config carries only the stable contract version.
    pub async fn stop(&self, iso_sandbox_id: &str) -> Result<(), InvokerError> {
        let config = lifecycle_config_json();
        self.run_phase("stop", iso_sandbox_id, &config).await
    }

    /// Run the deprovision phase.
    pub async fn deprovision(&self, iso_sandbox_id: &str) -> Result<(), InvokerError> {
        let config = lifecycle_config_json();
        self.run_phase("deprovision", iso_sandbox_id, &config).await
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
        let config = provision_config_json();
        assert_eq!(config["version"], "1.0.0");
        assert_eq!(config["containment"], "isolation_session");
        assert_eq!(config["network"]["egress"]["default"], "allow");
        assert_eq!(config["network"]["ingress"]["default"], "allow");
        assert_eq!(config["network"]["ingress"]["hostLoopback"], "allow");
        for legacy in ["phase", "sandboxId", "filesystem", "experimental"] {
            assert!(
                config.get(legacy).is_none(),
                "legacy field {legacy} must be omitted"
            );
        }
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
    fn isolation_exec_config_layers_environment_and_omits_cli_routing() {
        let process = MxcProcess {
            command_line: "cmd /c exit 0".into(),
            cwd: "C:\\Windows\\Temp".into(),
            env: vec!["MODE=test".into()],
            timeout: 0,
        };
        let config = exec_config_json(&process);
        assert_eq!(config["version"], "1.0.0");
        assert_eq!(config["process"]["inheritDefaultEnv"], true);
        assert_eq!(config["process"]["env"][0], "MODE=test");
        assert!(config.get("phase").is_none());
        assert!(config.get("sandboxId").is_none());
    }

    #[test]
    fn network_json_emits_directional_format() {
        // MXC 1.0.0: egress/ingress replaces the legacy
        // defaultPolicy / allowedHosts / proxy.localhost shape.
        let network = MxcNetwork {
            egress_default: "deny".into(),
            proxy: Some("127.0.0.1:18080".parse().unwrap()),
            allow_local_network: false,
        };
        let value = network_json(&network);
        // Loopback-allow mode: egress.default="deny" with 127.0.0.1/32 allow rule.
        // Allows relay to reach both the spawned target (intra-container loopback)
        // and the host relay listener (host loopback) without proxy-mode WFP issues.
        assert_eq!(value["egress"]["default"], "deny");
        assert_eq!(value["egress"]["allow"][0]["to"][0]["cidr"], "127.0.0.1/32");
        // ingress.hostLoopback="allow" grants networkLoopback PSEC capability.
        assert_eq!(value["ingress"]["default"], "allow");
        assert_eq!(value["ingress"]["hostLoopback"], "allow");
        assert!(value.get("proxy").is_none());
        assert!(value.get("defaultPolicy").is_none());
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
        let config = oneshot_config_json("sb-1", &filesystem, &pc, &process, None, None);

        assert!(config.get("network").is_none());
        assert!(config.get("ui").is_none());
    }

    #[tokio::test]
    async fn mock_exec_uses_only_the_mxc_process_environment() {
        const KEY: &str = "OPENSHELL_MXC_MOCK_ENV_TEST";
        let workdir = tempfile::tempdir().expect("temporary workdir");
        let output = workdir.path().join("mock-env.txt");
        let process = MxcProcess {
            command_line: format!("echo %{KEY}%,%SystemRoot% 1> \"{}\"", output.display()),
            cwd: workdir.path().to_string_lossy().into_owned(),
            env: vec![format!("{KEY}=process-value")],
            timeout: 0,
        };

        let mut child = WxcExecInvoker::mock_spawn_with_grants(
            &process,
            &[mock_normalize(&workdir.path().to_string_lossy())],
        )
        .expect("mock process should launch");
        let status = child.wait().await.expect("mock process should finish");

        assert!(status.success());
        assert_eq!(
            std::fs::read_to_string(output).expect("mock output").trim(),
            "process-value,%SystemRoot%"
        );
    }

    #[test]
    fn mock_grant_matching_respects_path_component_boundaries() {
        let grant = mock_normalize(r"C:\work\demo");

        for command in [
            r"echo ok > C:\work\demo",
            r"echo ok > C:\work\demo\result.txt",
            r#"echo ok > "C:/work/demo/result.txt""#,
        ] {
            assert!(mock_command_references_grant(
                &mock_normalize(command),
                &grant
            ));
        }

        for command in [
            r"echo denied > C:\work\demo-ro-src\result.txt",
            r"echo denied > C:\work\demonstration\result.txt",
            r"echo denied > XC:\work\demo\result.txt",
        ] {
            assert!(!mock_command_references_grant(
                &mock_normalize(command),
                &grant
            ));
        }
    }

    #[test]
    fn oneshot_config_json_emits_typed_ui_policy() {
        let filesystem = MxcFilesystem::default();
        let pc = MxcProcessContainer::default();
        let process = MxcProcess {
            command_line: "cmd /c exit 0".into(),
            cwd: "C:\\work\\demo".into(),
            env: Vec::new(),
            timeout: 0,
        };
        let ui = MxcUi {
            disable: false,
            clipboard: MxcClipboardAccess::Write,
            injection: true,
        };
        let config = oneshot_config_json("sb-ui", &filesystem, &pc, &process, None, Some(&ui));

        assert_eq!(config["ui"]["disable"], false);
        assert_eq!(config["ui"]["clipboard"], "write");
        assert_eq!(config["ui"]["injection"], true);
    }

    #[test]
    fn isolation_provision_config_never_synthesizes_ui() {
        let config = provision_config_json();
        assert!(config.get("ui").is_none());
    }

    #[test]
    fn lifecycle_config_omits_operation_and_sandbox_id() {
        let config = lifecycle_config_json();
        assert_eq!(config["version"], "1.0.0");
        assert!(config.get("phase").is_none());
        assert!(config.get("sandboxId").is_none());
    }

    #[tokio::test]
    async fn isolation_provision_rejects_filesystem_grants() {
        let invoker = WxcExecInvoker::mocked("unused");
        let error = invoker
            .provision(MxcFilesystem {
                readwrite_paths: vec![r"C:\work\demo".into()],
                ..Default::default()
            })
            .await
            .expect_err("isolation_session must not silently drop filesystem grants");
        match error {
            InvokerError::Mxc { code, message } => {
                assert_eq!(code, "policy_validation");
                assert!(message.contains("cannot enforce filesystem grants"));
            }
            other => panic!("expected MXC policy validation error, got {other}"),
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
