// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `wxc-exec` ProcessContainer launcher and request types.

use base64::Engine as _;
use serde::Serialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use thiserror::Error;
use tokio::process::Command;
use tracing::{debug, info};

/// MXC config schema version. The mapper and one-shot launcher share the
/// MXC 0.8 directional network schema.
pub const MXC_SCHEMA_VERSION: &str = "0.8.0-alpha";

/// Environment flag selecting the in-process mock `wxc-exec` shim. When set to
/// `"1"`, the invoker does not spawn `wxc-exec.exe`; it simulates AppContainer
/// filesystem enforcement for the one-shot ProcessContainer launch.
pub const MOCK_ENV_VAR: &str = "OPENSHELL_MXC_MOCK_WXC";

fn mock_enabled() -> bool {
    std::env::var(MOCK_ENV_VAR).is_ok_and(|value| value == "1")
}

/// Normalize a path/command fragment to lowercase backslash form for the mock's
/// in-policy substring check.
fn mock_normalize(s: &str) -> String {
    s.replace('/', "\\").to_lowercase()
}

// ── Request types ─────────────────────────────────────────────────────────────

/// Filesystem shares for the sandbox.
///
/// ProcessContainer honors `readwrite`/`readonly` grants and `denied_paths`.
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
    /// When true, includes `"allowLocalNetwork": true` in the network JSON.
    /// Required for node.js to initialize inside a processcontainer — without
    /// it, node.exe DLL initialization fails with `STATUS_DLL_INIT_FAILED`.
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
    // MXC 0.8.0-alpha schema uses a directional egress/ingress format.
    // "block" default_policy maps to egress.default "deny"; "allow" maps to "allow".
    let egress_default = if network.default_policy == "block" {
        "deny"
    } else {
        "allow"
    };
    let mut value = if network.proxy.is_some() {
        // Use direct loopback egress rather than runtimeConfig.networkProxy proxy
        // mode. Proxy mode routes all outbound TCP through processmodel.dll's WFP
        // redirect, which can block the authenticated Sandbox Protocol and
        // explicit proxy connections to their host loopback listeners. Limit the
        // exception to 127.0.0.1/32 rather than the broader 127.0.0.0/8 range.
        // PSEC tier is still selected because requires_psec_networking() returns
        // true when egress.allow is non-empty (no NetworkIsolationSetAppContainerConfig
        // call needed — no elevation required).
        //
        // Deliberately no `ports` restriction: the authenticated Sandbox
        // Protocol listener, generation-scoped supervisor proxy, and dynamic
        // forwarding listeners all use independently allocated loopback ports.
        serde_json::json!({
            "egress": {
                "default": "deny",
                "allow": [{"to": [{"cidr": "127.0.0.1/32"}]}]
            },
            "ingress": { "default": "allow", "hostLoopback": "allow" },
        })
    } else {
        serde_json::json!({ "egress": { "default": egress_default } })
    };
    if network.proxy.is_none() && network.allow_local_network {
        value["ingress"] = serde_json::json!({ "default": "allow", "hostLoopback": "allow" });
    }
    value
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

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum InvokerError {
    #[error("wxc-exec spawn failed: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("wxc-exec config serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

// ── Invoker ───────────────────────────────────────────────────────────────────

/// Wraps the one-shot `wxc-exec` ProcessContainer invocation.
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

    pub(crate) const fn is_mock(&self) -> bool {
        self.mock
    }

    /// Mock enforcement for the one-shot `processContainer` path.
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
    /// `processContainer` is a single ephemeral `AppContainer`: one `wxc-exec`
    /// invocation creates the container, runs the sandbox runtime, and tears it
    /// down when that runtime exits. The `AppContainer` is genuinely
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
            // Retain child output so the gateway can surface sandbox logs.
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
}

// ── Tests (pure serde — compile and run cross-platform) ──────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
    fn network_json_emits_directional_format() {
        // MXC 0.8.0-alpha: egress/ingress replaces the legacy
        // defaultPolicy / allowedHosts / proxy.localhost shape.
        let network = MxcNetwork {
            default_policy: "block".into(),
            proxy: Some("127.0.0.1:18080".parse().unwrap()),
            allow_local_network: false,
        };
        let value = network_json(&network);
        // Loopback-allow mode: egress.default="deny" with 127.0.0.1/32 allow rule.
        // Allows the sandbox to reach its authenticated host-side listeners
        // without enabling direct Internet access.
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
}
