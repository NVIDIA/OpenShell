// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! MXC compute backend: lifecycle logic, in-memory registry, exec-in-driver,
//! and self-reported readiness.

use crate::control_channel::ControlChannel;
use crate::mxc::{MxcFilesystem, MxcNetwork, MxcProcess, MxcProcessContainer, WxcExecInvoker};
use crate::policy::{EmbeddedPolicyMapper, MapCtx, MappedConfig, PolicyMapper};
use crate::relay;
use base64::Engine as _;
use futures::Stream;
use openshell_core::gpu::{driver_gpu_requirements, effective_driver_gpu_count};
use openshell_core::proto::SandboxPolicy;
use openshell_core::proto::compute::v1::{
    DriverCondition, DriverPlatformEvent, DriverSandbox, DriverSandboxStatus,
    GetCapabilitiesResponse, WatchSandboxesDeletedEvent, WatchSandboxesEvent,
    WatchSandboxesPlatformEvent, WatchSandboxesSandboxEvent, watch_sandboxes_event,
};
use openshell_core::proto_struct::struct_to_json_value;
use openshell_core::provider_credentials::ProviderCredentialState;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Child;
use tokio::sync::{Mutex, broadcast, mpsc, oneshot, watch};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{info, warn};

const DRIVER_NAME: &str = "mxc";
const DRIVER_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Sentinel image name — MXC has no OCI image; this string must be non-empty
/// so the gateway's `default_image` cache is satisfied, but it is not pullable.
const DEFAULT_IMAGE_SENTINEL: &str = "mxc:process-container";

// ── Config ────────────────────────────────────────────────────────────────────

/// Which MXC backend the driver targets.
///
/// - `IsolationSession`: persistent, attachable session
///   (provision → start → exec → stop → deprovision). Grant-only filesystem
///   policy — it has no deny primitive and is NOT default-deny.
/// - `ProcessContainer` (default): one-shot `AppContainer`. Genuinely default-deny: a
///   write to any ungranted path is denied by the OS. No persistent session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MxcBackend {
    IsolationSession,
    #[default]
    ProcessContainer,
}

impl MxcBackend {
    const fn containment(self) -> &'static str {
        match self {
            Self::IsolationSession => "isolation_session",
            Self::ProcessContainer => "processcontainer",
        }
    }
}

/// Configuration for the MXC compute driver.
///
/// Loaded from `[openshell.drivers.mxc]` in the gateway TOML file, or from
/// environment variables / CLI flags via the standard gateway precedence chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // Independent, existing gateway TOML options.
pub struct MxcComputeConfig {
    /// Path to `wxc-exec.exe`. Required for live runs.
    pub wxc_exec_path: String,
    /// Backend to target. Default: `process_container`.
    pub backend: MxcBackend,
    /// `processContainer` only: request a Less-Privileged `AppContainer`.
    pub pc_least_privilege: bool,
    /// `processContainer` only: `AppContainer` capabilities to grant.
    pub pc_capabilities: Vec<String>,
    /// `processContainer` only: inject a network section with
    /// `defaultPolicy: "allow"` so the `AppContainer` has unrestricted outbound
    /// TCP access.  Required when `pc_capabilities` alone is insufficient to
    /// enable network access in the target wxc-exec build. When `egress_proxy`
    /// is also enabled, sandbox policies without explicit network rules are
    /// rejected instead of falling back from governed egress to unrestricted
    /// access.
    pub pc_network_allow: bool,
    /// `processContainer` only: include `"allowLocalNetwork": true` in the
    /// MXC network section.  Required for node.js (and other runtimes that
    /// need loopback during DLL initialization) to start inside a
    /// processcontainer.
    pub pc_allow_local_network: bool,
    /// `processContainer` only: when `true`, start with an EMPTY process env
    /// (not even `MINIMAL_WINDOWS_BOOTSTRAP_ENV`) instead of the safe
    /// default -- only the sandbox's explicit per-request environment is
    /// passed to the process.
    /// Use for agents like Node.js that fail with `STATUS_DLL_INIT_FAILED`
    /// when unrecognised host env vars are present; the caller is then
    /// responsible for supplying `SYSTEMROOT`/`WINDIR`/`PATH`/`COMSPEC`/
    /// `LOCALAPPDATA` through `sandbox create --env/--env-from` if needed
    /// (`CreateProcessW` itself won't succeed without `LOCALAPPDATA` at
    /// least -- see `MINIMAL_WINDOWS_BOOTSTRAP_ENV`).
    ///
    /// The sandbox's explicit per-request environment is layered on top.
    pub pc_minimal_env: bool,
    /// `processContainer` only: path to a generic spawn+relay-bridge binary
    /// (see the `openshell-supervisor-relay` crate). When non-empty (and
    /// `pc_relay_target_port != 0`), the driver launches this binary instead
    /// of the per-sandbox workload command directly, sending the command/env
    /// over the control channel once the spawner announces readiness (the
    /// "launch" handshake) rather than writing them to the workload directory. This
    /// decouples the relay-bridging logic from the target application (e.g.
    /// `OpenClaw`) entirely — the target needs no awareness of the relay
    /// protocol. It's also what gives the driver a control channel into the
    /// sandbox at all, which `ForwardSink::open_dynamic_forward` (dynamic
    /// `openshell forward service` bridging) depends on regardless of any
    /// particular port being pre-declared.
    pub pc_relay_spawner_path: String,
    /// `processContainer` only: the TCP port the workload's target process
    /// binds, which `pc_relay_spawner_path` bridges to the gateway relay.
    /// Ignored unless `pc_relay_spawner_path` is set. `0` disables spawner
    /// wrapping (default) — the per-sandbox command runs directly.
    pub pc_relay_target_port: u16,
    /// MXC `configurationId` for isolation session. Default: `"composable"`.
    /// Never use `"small"` (known OS bug).
    pub default_configuration_id: String,
    /// Enable Pattern-C governed egress for sandbox policies that contain
    /// explicit network rules. MXC permits loopback-only egress, the driver
    /// injects proxy environment variables, and the host CONNECT proxy receives
    /// the full network policy. Policies without network rules do not start a
    /// listener or receive proxy environment variables.
    pub egress_proxy: bool,
    /// Loopback `IP:PORT` seed for MXC `network.proxy` while governed egress is
    /// enabled. The driver preserves the loopback IP and allocates a unique
    /// ephemeral port per sandbox.
    pub egress_proxy_addr: String,

    /// Enable `--debug` flag on `wxc-exec` invocations.
    pub debug: bool,
    /// Enable the in-process ETW → OCSF audit consumer (Plane A). Consumes the OS
    /// Sandboxing provider MXC drives and emits OCSF into the gateway trail.
    /// Requires the gateway account to be in "Performance Log Users" (or admin).
    pub etw_audit: bool,
}

impl Default for MxcComputeConfig {
    fn default() -> Self {
        Self {
            wxc_exec_path: "wxc-exec.exe".into(),
            backend: MxcBackend::default(),
            pc_least_privilege: false,
            pc_capabilities: Vec::new(),
            pc_network_allow: false,
            pc_relay_spawner_path: String::new(),
            pc_relay_target_port: 0,
            pc_allow_local_network: false,
            pc_minimal_env: false,
            default_configuration_id: crate::mxc::DEFAULT_CONFIGURATION_ID.into(),
            egress_proxy: false,
            egress_proxy_addr: String::new(),

            debug: false,
            etw_audit: false,
        }
    }
}

/// Per-sandbox MXC workload settings supplied through
/// `template.driver_config.mxc` / `--driver-config-json`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MxcSandboxConfig {
    command: Vec<String>,
    #[serde(default)]
    cwd: String,
}

// ── Registry entry ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhaseState {
    Starting,
    Running,
    Stopped,
    Failed(String),
}

struct SandboxEntry {
    sandbox: DriverSandbox,
    iso_sandbox_id: Option<String>,
    isolation_stopped: bool,
    phase_state: PhaseState,
    /// Serializes stop/delete with provisioning and process launch: taken as
    /// an owned guard (`startup_guard`) in `create_sandbox` before the entry
    /// is published, and only released once `run_lifecycle` has installed
    /// `exec_child`/`shutdown_tx`/`terminated_rx`/`control_channel` (or
    /// failed). `stop_sandbox`/`delete_sandbox` block on this same gate
    /// before touching any of those fields, so a stop/delete arriving while
    /// a sandbox is still starting can't race a launch that hasn't finished
    /// wiring the kill/shutdown machinery yet.
    lifecycle_gate: Arc<Mutex<()>>,
    exec_child: Option<Child>,
    /// Fires when `delete_sandbox` is called on a `ProcessContainer` sandbox so
    /// `monitor_exec` can kill the `wxc-exec` child and release all resources
    /// (including ports bound inside the `AppContainer`) before the entry is
    /// removed from the registry.
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// Set to `true` (from `monitor_exec`) once the `wxc-exec` child has
    /// genuinely exited -- whether that's a natural exit or the forced kill
    /// triggered via `shutdown_tx` above. Lets `stop_sandbox`/`delete_sandbox`
    /// await *confirmed* termination (bounded by a timeout) instead of firing
    /// the kill signal and immediately reporting success regardless of
    /// whether the process actually died.
    ///
    /// A `watch::Receiver` rather than a `oneshot::Receiver` deliberately:
    /// it's `.clone()`d (never `.take()`n) by callers, so it survives a
    /// caller that times out and retries -- unlike a consumed oneshot, the
    /// retry can still observe the same underlying completion instead of
    /// silently skipping the wait because the field looks empty.
    terminated_rx: Option<watch::Receiver<bool>>,
    /// Path to the shutdown signal file written by `delete_sandbox` so
    /// `mxc-ws-agent.rs` (set directly as the sandbox command, no control
    /// channel) can detect a deletion and exit cleanly. Only set for that
    /// case -- when spawner wrapping is active, `delete_sandbox` sends a
    /// `"shutdown"` control-channel request to `openshell-supervisor-relay`
    /// instead, so this stays `None`.
    signal_file: Option<PathBuf>,
    trimmed_policy: Option<SandboxPolicy>,
    proxy_addr: Option<SocketAddr>,
    host_proxy: Option<openshell_supervisor_network::host::HostProxyHandle>,
    /// JSON request/response control channel over the spawner's inherited
    /// stdin/stdout (see `control_channel.rs`). Only present when spawner
    /// wrapping is active (`pc_relay_spawner_path` configured); dropped on
    /// delete, which closes the child's stdin.
    control_channel: Option<Arc<ControlChannel>>,
}

impl std::fmt::Debug for SandboxEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxEntry")
            .field("sandbox_id", &self.sandbox.id)
            .field("iso_sandbox_id", &self.iso_sandbox_id)
            .field("isolation_stopped", &self.isolation_stopped)
            .field("phase_state", &self.phase_state)
            .finish_non_exhaustive()
    }
}

// ── Watch stream helpers ──────────────────────────────────────────────────────

pub type WatchStream = Pin<
    Box<dyn Stream<Item = Result<WatchSandboxesEvent, openshell_core::ComputeDriverError>> + Send>,
>;

fn sandbox_event(sandbox: DriverSandbox) -> WatchSandboxesEvent {
    WatchSandboxesEvent {
        payload: Some(watch_sandboxes_event::Payload::Sandbox(
            WatchSandboxesSandboxEvent {
                sandbox: Some(sandbox),
            },
        )),
    }
}

fn deleted_event(sandbox_id: String) -> WatchSandboxesEvent {
    WatchSandboxesEvent {
        payload: Some(watch_sandboxes_event::Payload::Deleted(
            WatchSandboxesDeletedEvent { sandbox_id },
        )),
    }
}

fn platform_event(sandbox_id: String, reason: &str, message: String) -> WatchSandboxesEvent {
    WatchSandboxesEvent {
        payload: Some(watch_sandboxes_event::Payload::PlatformEvent(
            WatchSandboxesPlatformEvent {
                sandbox_id,
                event: Some(DriverPlatformEvent {
                    timestamp_ms: 0,
                    source: "mxc-driver".into(),
                    r#type: "Warning".into(),
                    reason: reason.to_string(),
                    message,
                    metadata: HashMap::new(),
                }),
            },
        )),
    }
}

// ── Driver ────────────────────────────────────────────────────────────────────

/// In-process MXC compute driver.
pub struct MxcComputeBackend {
    config: MxcComputeConfig,
    invoker: WxcExecInvoker,
    registry: Arc<Mutex<HashMap<String, SandboxEntry>>>,
    watch_tx: Arc<broadcast::Sender<WatchSandboxesEvent>>,
    policy_mapper: Arc<dyn PolicyMapper>,
    /// Provider resolver snapshots staged by the gateway immediately before
    /// create. The driver consumes each entry exactly once; only placeholder
    /// child environment values cross into MXC.
    pending_provider_credentials: Arc<StdMutex<HashMap<String, ProviderCredentialState>>>,
    /// In-process ETW → OCSF audit consumer (Plane A). `Some` only when
    /// `config.etw_audit` is set and the session started; kept alive here so it
    /// stops when the backend is dropped (held purely for its `Drop`, hence
    /// never read directly).
    #[allow(dead_code)]
    etw_session: Option<crate::etw_consumer::EtwSession>,
    /// Shared MXC-ETW → `sandbox_id` attribution index. Seeded by the driver
    /// (`pid → sandbox_id`) as it launches sandboxes and read by the ETW
    /// consumer thread to map/emit OCSF. `Arc` even when audit is off so the
    /// launch path is branch-free.
    attribution: Arc<std::sync::Mutex<crate::etw_consumer::AttributionIndex>>,
}

impl std::fmt::Debug for MxcComputeBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MxcComputeBackend")
            .field("wxc_exec_path", &self.config.wxc_exec_path)
            .finish_non_exhaustive()
    }
}

fn sandbox_config(sandbox: &DriverSandbox) -> Result<MxcSandboxConfig, tonic::Status> {
    let config = sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
        .and_then(|template| template.driver_config.as_ref())
        .ok_or_else(|| {
            tonic::Status::invalid_argument(
                "mxc requires template.driver_config.mxc with a non-empty command array",
            )
        })?;
    let config: MxcSandboxConfig =
        serde_json::from_value(struct_to_json_value(config)).map_err(|error| {
            tonic::Status::invalid_argument(format!("invalid mxc driver_config: {error}"))
        })?;
    if config.command.is_empty() || config.command[0].is_empty() {
        return Err(tonic::Status::invalid_argument(
            "mxc driver_config.command must contain a non-empty executable",
        ));
    }
    Ok(config)
}

fn sandbox_environment(sandbox: &DriverSandbox) -> Vec<String> {
    let mut environment = HashMap::new();
    if let Some(spec) = sandbox.spec.as_ref() {
        if let Some(template) = spec.template.as_ref() {
            environment.extend(template.environment.clone());
        }
        environment.extend(spec.environment.clone());
    }
    let mut environment = environment
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>();
    environment.sort_unstable();
    environment
}

/// Merge provider-owned child environment values into MXC `process.env`.
///
/// Provider entries win case-insensitively, matching Windows environment
/// semantics. Secret values have already been replaced by revision-scoped
/// placeholders; explicitly classified GCP configuration is resolved by the
/// shared credential state because SDKs consume it before making a request.
fn append_provider_child_env(
    env: &mut Vec<String>,
    provider_credentials: Option<&ProviderCredentialState>,
) {
    let Some(provider_credentials) = provider_credentials else {
        return;
    };
    let mut provider_env = provider_credentials
        .child_env_with_gcp_resolved()
        .into_iter()
        .collect::<Vec<_>>();
    provider_env.sort_by(|(left, _), (right, _)| left.cmp(right));
    env.retain(|entry| {
        let key = entry.split_once('=').map_or(entry.as_str(), |(key, _)| key);
        !provider_env
            .iter()
            .any(|(provider_key, _)| key.eq_ignore_ascii_case(provider_key))
    });
    env.extend(
        provider_env
            .into_iter()
            .map(|(key, value)| format!("{key}={value}")),
    );
}

/// Rejects provider credential environment keys that would collide once
/// injected into the sandbox process, before any staging or launch happens.
///
/// Windows environment variables are case-insensitive, so two provider keys
/// that differ only by case (or shadow one of the reserved TLS trust keys
/// `append_tls_env_vars` injects later) would otherwise merge or get silently
/// overwritten with no diagnostic, leaving the sandbox with an ambiguous,
/// wrong, or missing credential.
fn validate_provider_child_env_keys(
    provider_credentials: Option<&ProviderCredentialState>,
) -> Result<(), tonic::Status> {
    let Some(provider_credentials) = provider_credentials else {
        return Ok(());
    };
    let mut seen: HashMap<String, String> = HashMap::new();
    let mut collisions: Vec<String> = Vec::new();
    let mut keys = provider_credentials
        .child_env_with_gcp_resolved()
        .into_keys()
        .collect::<Vec<_>>();
    keys.sort_unstable();
    for key in keys {
        let folded = key.to_ascii_uppercase();
        if TLS_ENV_KEYS.iter().any(|reserved| folded == *reserved) {
            collisions.push(format!("{key} (reserved for TLS trust configuration)"));
            continue;
        }
        if let Some(existing) = seen.insert(folded, key.clone())
            && existing != key
        {
            collisions.push(format!("{key} (collides with {existing})"));
        }
    }
    if collisions.is_empty() {
        Ok(())
    } else {
        Err(tonic::Status::failed_precondition(format!(
            "provider credential environment keys are ambiguous on Windows (case-insensitive) \
             or reserved: {}",
            collisions.join(", ")
        )))
    }
}

fn configured_egress_addr(config: &MxcComputeConfig) -> Result<Option<SocketAddr>, tonic::Status> {
    if !config.egress_proxy {
        return Ok(None);
    }
    if config.backend == MxcBackend::IsolationSession {
        return Err(tonic::Status::invalid_argument(
            "mxc governed egress requires process_container; isolation_session cannot enforce the loopback-only proxy path",
        ));
    }
    let raw = config.egress_proxy_addr.trim();
    if raw.is_empty() {
        return Err(tonic::Status::invalid_argument(
            "mxc egress_proxy_addr is required when egress_proxy is enabled",
        ));
    }
    let addr = raw.parse::<SocketAddr>().map_err(|error| {
        tonic::Status::invalid_argument(format!(
            "mxc egress_proxy_addr must be an IP:PORT socket address: {error}"
        ))
    })?;
    if addr.ip() != std::net::IpAddr::from([127, 0, 0, 1]) {
        return Err(tonic::Status::invalid_argument(format!(
            "mxc egress_proxy_addr must be 127.0.0.1:PORT because the sandbox reaches the unpackaged OpenShell host proxy over loopback (got {})",
            addr.ip()
        )));
    }
    Ok(Some(addr))
}

fn policy_activates_governed_egress(policy: Option<&SandboxPolicy>) -> bool {
    policy.is_some_and(|policy| {
        !policy.network_policies.is_empty() || !policy.network_middlewares.is_empty()
    })
}

fn governed_egress_addr(
    config: &MxcComputeConfig,
    policy: Option<&SandboxPolicy>,
) -> Result<Option<SocketAddr>, tonic::Status> {
    let configured = configured_egress_addr(config)?;
    let policy_activates_egress = policy_activates_governed_egress(policy);
    if configured.is_some() && !policy_activates_egress && config.pc_network_allow {
        return Err(tonic::Status::invalid_argument(
            "mxc egress_proxy cannot be combined with pc_network_allow for a sandbox policy without explicit network rules; refusing unrestricted egress fallback",
        ));
    }
    Ok(configured.filter(|_| policy_activates_egress))
}

fn allocate_sandbox_proxy_addr(
    configured: SocketAddr,
) -> std::io::Result<(SocketAddr, std::net::TcpListener)> {
    let reservation = std::net::TcpListener::bind(SocketAddr::new(configured.ip(), 0))?;
    let addr = reservation.local_addr()?;
    Ok((addr, reservation))
}

/// Minimum Windows environment variables required just for `CreateProcessW`
/// / `AppContainer`-DACL process creation to succeed at all -- independent of
/// whatever per-sandbox runtime command is selected. Confirmed empirically:
/// without `LOCALAPPDATA` specifically, `CreateProcessW` itself fails with
/// `ERROR_ENVVAR_NOT_FOUND` (Win32 203) under the appcontainer-dacl fallback
/// tier, before the agent binary is ever reached -- a Windows `AppContainer`
/// requirement, not specific to Node.js or any other agent. None of these
/// are secrets, so resolving them from the gateway host is safe; this is
/// the per-sandbox environment layers on top of. See `pc_minimal_env` on
/// `MxcComputeConfig` for the explicit empty-baseline option.
const MINIMAL_WINDOWS_BOOTSTRAP_ENV: [&str; 5] =
    ["SYSTEMROOT", "WINDIR", "PATH", "COMSPEC", "LOCALAPPDATA"];

fn host_proxy_binary_path(config: &MxcSandboxConfig) -> PathBuf {
    config
        .command
        .first()
        .filter(|command| !command.trim().is_empty())
        .map_or_else(|| PathBuf::from("mxc-agent"), PathBuf::from)
}

const TLS_ENV_KEYS: [&str; 6] = [
    "NODE_EXTRA_CA_CERTS",
    "DENO_CERT",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "GIT_SSL_CAINFO",
];

/// Replace client trust overrides with the proxy's public CA paths.
/// Curated `ProcessContainers` receive copies staged under the authorized share,
/// rather than paths inside the host proxy's private temporary directory.
fn append_tls_env_vars(env: &mut Vec<String>, ca_paths: Option<&(PathBuf, PathBuf)>) {
    let Some((ca_cert_path, combined_bundle_path)) = ca_paths else {
        return;
    };
    env.retain(|entry| {
        let key = entry.split_once('=').map_or(entry.as_str(), |(key, _)| key);
        !TLS_ENV_KEYS
            .iter()
            .any(|candidate| key.eq_ignore_ascii_case(candidate))
    });
    let ca_cert_path = ca_cert_path.display().to_string();
    let combined_bundle_path = combined_bundle_path.display().to_string();
    env.extend([
        format!("NODE_EXTRA_CA_CERTS={ca_cert_path}"),
        format!("DENO_CERT={ca_cert_path}"),
        format!("SSL_CERT_FILE={combined_bundle_path}"),
        format!("REQUESTS_CA_BUNDLE={combined_bundle_path}"),
        format!("CURL_CA_BUNDLE={combined_bundle_path}"),
        format!("GIT_SSL_CAINFO={combined_bundle_path}"),
    ]);
}

fn stage_tls_ca_files(
    ca_paths: Option<&(PathBuf, PathBuf)>,
    workload_dir: &str,
    sandbox_id: &str,
) -> std::io::Result<Option<(PathBuf, PathBuf)>> {
    let Some((ca_cert_path, combined_bundle_path)) = ca_paths else {
        return Ok(None);
    };
    if workload_dir.trim().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "mxc driver_config.cwd must be set when staging proxy CA files",
        ));
    }
    if sandbox_id.is_empty()
        || !sandbox_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "sandbox_id must be a non-empty alphanumeric, hyphen or underscore component",
        ));
    }
    let target_dir = PathBuf::from(workload_dir)
        .join(".openshell-proxy")
        .join(sandbox_id);
    std::fs::create_dir_all(&target_dir)?;
    let staged_ca = target_dir.join("openshell-ca.pem");
    let staged_bundle = target_dir.join("ca-bundle.pem");
    std::fs::copy(ca_cert_path, &staged_ca)?;
    std::fs::copy(combined_bundle_path, &staged_bundle)?;
    Ok(Some((staged_ca, staged_bundle)))
}

/// PROTOTYPE (2026-09-10): env-var-based governed egress, as an alternative
/// to MXC's own `network.proxy`/`runtimeConfig.networkProxy` transparent
/// redirect (both confirmed broken for this driver's use case -- see
/// `network_json()` in mxc.rs for the elevation/loopback-block history).
/// `HTTP_PROXY`/`HTTPS_PROXY` are honored voluntarily by well-behaved HTTP
/// clients (curl, most language HTTP libraries, Node fetch, git, etc.), not
/// enforced by the OS -- but paired with the sandbox's own default-deny
/// egress (only 127.0.0.1 allowed, see `network_json()`), that's actually
/// sufficient: compliant agents route through the host CONNECT proxy this
/// way, and anything that ignores these vars and tries to connect directly
/// just hits the WFP deny-by-default wall instead of silently bypassing
/// governance. Lowercase forms included too since some tools (e.g. curl)
/// prefer them, and both are common in the wild.
const PROXY_ENV_KEYS: [&str; 6] = [
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
];

const SANDBOX_PROXY_USERNAME: &str = "openshell";

struct SandboxProxyAuth {
    password: String,
}

impl SandboxProxyAuth {
    fn generate() -> Self {
        let random: [u8; 32] = rand::random();
        Self {
            password: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random),
        }
    }

    fn proxy_url(&self, addr: SocketAddr) -> String {
        format!("http://{SANDBOX_PROXY_USERNAME}:{}@{addr}", self.password)
    }

    fn host_client_auth(&self) -> openshell_supervisor_network::host::HostProxyClientAuth {
        openshell_supervisor_network::host::HostProxyClientAuth::basic(
            SANDBOX_PROXY_USERNAME,
            &self.password,
        )
    }
}

fn append_proxy_env_vars(
    env: &mut Vec<String>,
    proxy_addr: Option<SocketAddr>,
    proxy_auth: Option<&SandboxProxyAuth>,
) {
    let (Some(addr), Some(proxy_auth)) = (proxy_addr, proxy_auth) else {
        return;
    };
    env.retain(|entry| {
        let key = entry.split_once('=').map_or(entry.as_str(), |(key, _)| key);
        !PROXY_ENV_KEYS
            .iter()
            .any(|candidate| key.eq_ignore_ascii_case(candidate))
    });
    let proxy_url = proxy_auth.proxy_url(addr);
    env.extend([
        format!("HTTP_PROXY={proxy_url}"),
        format!("http_proxy={proxy_url}"),
        format!("HTTPS_PROXY={proxy_url}"),
        format!("https_proxy={proxy_url}"),
        "NO_PROXY=".to_string(),
        "no_proxy=".to_string(),
    ]);
}

/// Not called: the release wxc-exec (`BaseContainer` dispatcher) requires
/// write-DAC permission on every path in `readonlyPaths` to set up
/// `AppContainer` ACLs, and adding the TLS CA cert temp directory here
/// causes it to fail with a DACL error (empirically confirmed) -- the CA
/// cert paths are available to the agent via TLS env vars instead (see
/// `append_tls_env_vars`). Kept for a future build where that DACL
/// requirement no longer applies.
#[allow(dead_code)]
fn append_tls_readonly_grant(
    readonly_paths: &mut Vec<String>,
    ca_paths: Option<&(PathBuf, PathBuf)>,
) {
    let Some((ca_cert_path, _)) = ca_paths else {
        return;
    };
    let Some(dir) = ca_cert_path.parent().map(Path::to_path_buf) else {
        return;
    };
    let dir = dir.display().to_string();
    if !readonly_paths
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(&dir))
    {
        readonly_paths.push(dir);
    }
}
fn encode_windows_command_line(args: &[String]) -> String {
    if args
        .first()
        .and_then(|executable| executable.rsplit(['\\', '/']).next())
        .is_some_and(|executable| {
            executable.eq_ignore_ascii_case("cmd") || executable.eq_ignore_ascii_case("cmd.exe")
        })
        && let Some(command_index) = args
            .iter()
            .position(|arg| arg.eq_ignore_ascii_case("/c") || arg.eq_ignore_ascii_case("/k"))
    {
        let mut encoded = args[..=command_index]
            .iter()
            .map(|arg| quote_windows_argument(arg))
            .collect::<Vec<_>>()
            .join(" ");
        if command_index + 1 < args.len() {
            encoded.push(' ');
            // cmd.exe parses the command tail with its own grammar. Escaping
            // embedded quotes as C argv would leave literal backslashes in
            // paths and redirections (for example `\"C:\\work file\"`).
            encoded.push_str(&args[command_index + 1..].join(" "));
        }
        return encoded;
    }

    args.iter()
        .map(|arg| quote_windows_argument(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote_windows_argument(arg: &str) -> String {
    if !arg.is_empty() && !arg.chars().any(|ch| ch.is_whitespace() || ch == '"') {
        return arg.to_string();
    }

    let mut quoted = String::from("\"");
    let mut backslashes = 0;
    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
                quoted.push(ch);
            }
        }
    }
    quoted.push_str(&"\\".repeat(backslashes * 2));
    quoted.push('"');
    quoted
}
fn append_tls_readwrite_grant(
    readwrite_paths: &mut Vec<String>,
    ca_paths: Option<&(PathBuf, PathBuf)>,
) {
    let Some((ca_cert_path, _)) = ca_paths else {
        return;
    };
    let Some(dir) = ca_cert_path.parent() else {
        return;
    };
    let dir = dir.display().to_string();
    if !readwrite_paths
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(&dir))
    {
        readwrite_paths.push(dir);
    }
}

impl MxcComputeBackend {
    pub fn new(config: MxcComputeConfig) -> Self {
        let invoker = WxcExecInvoker::new(&config.wxc_exec_path, config.debug);
        let (watch_tx, _) = broadcast::channel(256);

        // Start the Plane-A ETW → OCSF consumer if enabled. The consumer thread
        // attributes each event to a `sandbox_id` via `attribution` (seeded by
        // the launch path) and emits OCSF for the mapped classes.
        // Failure is non-fatal — the driver still runs, just without ETW audit.
        let attribution = Arc::new(std::sync::Mutex::new(
            crate::etw_consumer::AttributionIndex::new(),
        ));
        let etw_session = if config.etw_audit {
            match crate::etw_consumer::start_session(attribution.clone()) {
                Ok(session) => Some(session),
                Err(e) => {
                    warn!(error = %e, "MXC ETW audit consumer failed to start; continuing without it");
                    None
                }
            }
        } else {
            None
        };

        Self {
            invoker,
            config,
            registry: Arc::new(Mutex::new(HashMap::new())),
            watch_tx: Arc::new(watch_tx),
            // Production policy translation is always handled by the embedded
            // mapper before any MXC lifecycle side effects begin.
            policy_mapper: Arc::new(EmbeddedPolicyMapper),
            pending_provider_credentials: Arc::new(StdMutex::new(HashMap::new())),
            etw_session,
            attribution,
        }
    }

    /// Returns a cheap, cloneable handle exposing MXC's dynamic port-forward
    /// capability, so the gateway's `ComputeRuntime` can grab it (before
    /// `self` is consumed into `Arc<dyn ComputeDriver>`) and call it directly
    /// from `handle_forward_tcp` for sandboxes with no `ConnectSupervisor`
    /// session -- MXC has no supervisor at all, so that path is otherwise
    /// permanently dead for it.
    pub fn forward_sink(&self) -> ForwardSink {
        ForwardSink {
            registry: self.registry.clone(),
        }
    }

    /// Return the in-process create-time provider credential side channel.
    pub fn provider_credentials_sink(
        &self,
    ) -> Arc<StdMutex<HashMap<String, ProviderCredentialState>>> {
        self.pending_provider_credentials.clone()
    }

    /// Test-only constructor wiring the in-process mock `wxc-exec` shim.
    #[cfg(test)]
    pub(crate) fn new_mocked(config: MxcComputeConfig) -> Self {
        let mut backend = Self::new(config);
        backend.invoker = WxcExecInvoker::mocked(&backend.config.wxc_exec_path);
        backend
    }

    pub fn capabilities(&self) -> GetCapabilitiesResponse {
        GetCapabilitiesResponse {
            driver_name: DRIVER_NAME.to_string(),
            driver_version: DRIVER_VERSION.to_string(),
            default_image: DEFAULT_IMAGE_SENTINEL.to_string(),
            gateway_manages_lifecycle: false,
            supports_sandbox_authentication: false,
            driver_reports_runtime_readiness: true,
            resource_capabilities: None,
            rootfs_tar_staging_dir: String::new(),
            rootfs_tar_max_bytes: 0,
            supports_ui_policy: self.config.backend == MxcBackend::ProcessContainer,
        }
    }

    fn validate_sandbox_fields(sandbox: &DriverSandbox) -> Result<(), tonic::Status> {
        if let Some(spec) = &sandbox.spec {
            if effective_driver_gpu_count(driver_gpu_requirements(
                spec.resource_requirements.as_ref(),
            ))
            .map_err(tonic::Status::invalid_argument)?
            .is_some()
            {
                return Err(tonic::Status::invalid_argument(
                    "mxc driver does not support GPU sandboxes",
                ));
            }
            if let Some(tmpl) = &spec.template
                && !tmpl.agent_socket_path.is_empty()
            {
                return Err(tonic::Status::invalid_argument(
                    "mxc driver does not support agent_socket_path (no in-sandbox supervisor)",
                ));
            }
        }
        sandbox_config(sandbox)?;
        Ok(())
    }

    fn map_sandbox_policy(
        &self,
        sandbox_id: &str,
        policy: Option<&SandboxPolicy>,
        egress: Option<SocketAddr>,
    ) -> Result<MappedConfig, tonic::Status> {
        self.policy_mapper
            .map(
                policy,
                &MapCtx {
                    sandbox_id: sandbox_id.to_string(),
                    egress,
                    containment: self.config.backend.containment().into(),
                },
            )
            .map_err(|error| tonic::Status::invalid_argument(error.to_string()))
    }

    pub fn validate_sandbox_create(&self, sandbox: &DriverSandbox) -> Result<(), tonic::Status> {
        Self::validate_sandbox_fields(sandbox)?;
        let policy = sandbox.spec.as_ref().and_then(|spec| spec.policy.as_ref());
        let egress_addr = governed_egress_addr(&self.config, policy)?;
        self.map_sandbox_policy(&sandbox.id, policy, egress_addr)?;
        Ok(())
    }
    pub async fn get_sandbox(&self, sandbox_name: &str) -> Option<DriverSandbox> {
        let registry = self.registry.lock().await;
        registry
            .values()
            .find(|e| e.sandbox.name == sandbox_name)
            .map(|e| e.sandbox.clone())
    }

    pub async fn list_sandboxes(&self) -> Vec<DriverSandbox> {
        let registry = self.registry.lock().await;
        registry.values().map(|e| e.sandbox.clone()).collect()
    }

    pub async fn create_sandbox(&self, sandbox: &DriverSandbox) -> Result<(), tonic::Status> {
        let sandbox_id = sandbox.id.clone();

        // Consume before any fallible validation so rejected creates cannot
        // retain real provider material in the staging map.
        let provider_credentials = self
            .pending_provider_credentials
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&sandbox_id);
        validate_provider_child_env_keys(provider_credentials.as_ref())?;

        Self::validate_sandbox_fields(sandbox)?;
        let sandbox_config = sandbox_config(sandbox)?;
        let policy = sandbox.spec.as_ref().and_then(|spec| spec.policy.as_ref());
        let (egress_addr, reserved_proxy_listener) = match governed_egress_addr(
            &self.config,
            policy,
        )? {
            Some(configured_addr) => {
                let (addr, reservation) = allocate_sandbox_proxy_addr(configured_addr).map_err(
                    |error| {
                        tonic::Status::internal(format!(
                            "failed to allocate sandbox-unique MXC host egress proxy address from {configured_addr}: {error}"
                        ))
                    },
                )?;
                (Some(addr), Some(reservation))
            }
            None => (None, None),
        };

        // Policy translation is deterministic and side-effect free. Do it before
        // inserting the registry entry or launching MXC so invalid requests fail
        // synchronously at the CreateSandbox boundary.
        let mapped = self.map_sandbox_policy(&sandbox_id, policy, egress_addr)?;
        if provider_credentials
            .as_ref()
            .is_some_and(ProviderCredentialState::requires_proxy_resolution)
            && egress_addr.is_none()
        {
            return Err(tonic::Status::failed_precondition(
                "mxc provider credentials require governed egress; enable egress_proxy and configure at least one network policy so placeholders can be resolved by the host proxy",
            ));
        }

        if sandbox
            .spec
            .as_ref()
            .is_none_or(|spec| spec.sandbox_token.is_empty())
        {
            tracing::debug!(
                sandbox = %sandbox.name,
                "no sandbox_token minted (no supervisor consumer on MXC)"
            );
        }

        let sandbox_name = sandbox.name.clone();
        let lifecycle_gate = Arc::new(Mutex::new(()));
        // Take the gate before publishing the entry. stop/delete can discover the
        // sandbox immediately, but cannot pass this guard until startup has either
        // installed a cancellable child monitor or failed.
        let startup_guard = lifecycle_gate.clone().lock_owned().await;
        {
            let mut registry = self.registry.lock().await;
            if registry.contains_key(&sandbox_id) {
                return Err(tonic::Status::already_exists(format!(
                    "sandbox {sandbox_name} already exists"
                )));
            }
            let initial = make_sandbox_with_condition(
                sandbox,
                &DriverCondition {
                    r#type: "Ready".into(),
                    status: "False".into(),
                    reason: "Starting".into(),
                    message: "MXC lifecycle starting".into(),
                    last_transition_time: String::new(),
                },
                false,
            );
            let _ = self.watch_tx.send(sandbox_event(initial.clone()));
            registry.insert(
                sandbox_id.clone(),
                SandboxEntry {
                    sandbox: initial,
                    iso_sandbox_id: None,
                    isolation_stopped: false,
                    phase_state: PhaseState::Starting,
                    lifecycle_gate,
                    exec_child: None,
                    shutdown_tx: None,
                    terminated_rx: None,
                    signal_file: None,
                    trimmed_policy: mapped.trimmed_policy.clone(),
                    proxy_addr: mapped.proxy_addr,
                    host_proxy: None,
                    control_channel: None,
                },
            );
        }

        let invoker = self.invoker.clone();
        let config = self.config.clone();
        let registry = self.registry.clone();
        let watch_tx = self.watch_tx.clone();
        let attribution = self.attribution.clone();
        let sandbox = sandbox.clone();
        tokio::spawn(async move {
            run_lifecycle(
                invoker,
                config,
                registry,
                watch_tx,
                attribution,
                sandbox,
                sandbox_config,
                mapped,
                provider_credentials,
                reserved_proxy_listener,
                startup_guard,
            )
            .await;
        });

        Ok(())
    }
    pub async fn stop_sandbox(&self, sandbox_name: &str) -> Result<(), tonic::Status> {
        let (sandbox_id, lifecycle_gate) = {
            let registry = self.registry.lock().await;
            let entry = registry
                .values()
                .find(|entry| entry.sandbox.name == sandbox_name)
                .ok_or_else(|| {
                    tonic::Status::not_found(format!("sandbox {sandbox_name} not found"))
                })?;
            (entry.sandbox.id.clone(), entry.lifecycle_gate.clone())
        };

        // Blocks until any in-flight create_sandbox/run_lifecycle has either
        // finished wiring shutdown_tx/control_channel or failed -- closes the
        // race where a stop arriving mid-startup would otherwise find both
        // `None` and silently no-op (see the `lifecycle_gate` field doc).
        let _lifecycle_guard = lifecycle_gate.lock().await;
        let (
            iso_id,
            mut isolation_stopped,
            shutdown_tx,
            terminated_rx,
            control_channel,
            host_proxy,
        ) = {
            let mut registry = self.registry.lock().await;
            let entry = registry.get_mut(&sandbox_id).ok_or_else(|| {
                tonic::Status::not_found(format!("sandbox {sandbox_name} not found"))
            })?;
            (
                entry.iso_sandbox_id.clone(),
                entry.isolation_stopped,
                // Only ProcessContainer entries have these; isolation_session
                // relies on invoker.stop() below instead. .take() the kill
                // signal so a concurrent stop can't double-fire it, but
                // .clone() terminated_rx (a watch::Receiver, not a oneshot)
                // and the control channel (an Arc) -- both need to survive a
                // caller that times out below and retries: a fresh clone of
                // the same watch::Receiver still observes the SAME
                // underlying completion, whereas .take()-ing it would make a
                // retry silently skip the wait (see the matching fix in
                // delete_sandbox and MR !98's review thread on this).
                entry.shutdown_tx.take(),
                entry.terminated_rx.clone(),
                entry.control_channel.clone(),
                entry.host_proxy.take(),
            )
        };
        drop(host_proxy);

        if let Some(ref iso_id) = iso_id {
            if !isolation_stopped {
                self.invoker.stop(iso_id).await.map_err(|error| {
                    tonic::Status::internal(format!("wxc-exec stop failed: {error}"))
                })?;
                isolation_stopped = true;
            }
        } else {
            // ProcessContainer has no persistent iso id -- the sandbox IS
            // the one-shot wxc-exec process, so without this block stop had
            // nothing to act on and just relabeled the sandbox Stopped while
            // wxc-exec (and everything inside the AppContainer) kept
            // running. Ask nicely first over the control channel (bounded
            // by request()'s own 3s timeout, same as delete_sandbox), then
            // trigger the shutdown_tx kill backstop.
            if let Some(channel) = control_channel {
                match channel
                    .request(
                        "shutdown",
                        serde_json::Value::Null,
                        std::time::Duration::from_secs(3),
                    )
                    .await
                {
                    Ok(_) => {
                        info!(sandbox = %sandbox_name, "control-channel shutdown acknowledged");
                    }
                    Err(e) => {
                        warn!(sandbox = %sandbox_name, "control-channel shutdown failed: {e}");
                    }
                }
            }
            if let Some(tx) = shutdown_tx {
                let _ = tx.send(());
            }
            // Await *confirmed* termination via terminated_rx -- not just
            // firing the kill signal and reporting success regardless --
            // before this returns Ok. This runs whenever terminated_rx is
            // present, independent of whether THIS call sent the kill
            // signal above: shutdown_tx is None either because the process
            // already exited naturally, or because an earlier (possibly
            // timed-out) stop/delete attempt already sent it -- either way,
            // this call still needs to observe genuine completion, not
            // assume it.
            if let Some(mut rx) = terminated_rx
                && !wait_for_termination(&mut rx).await
            {
                warn!(sandbox = %sandbox_name, "timed out waiting for ProcessContainer termination on stop");
                return Err(tonic::Status::deadline_exceeded(format!(
                    "sandbox {sandbox_name} did not terminate within the stop timeout"
                )));
            }
        }

        let mut registry = self.registry.lock().await;
        if let Some(entry) = registry.get_mut(&sandbox_id) {
            entry.isolation_stopped = isolation_stopped;
            entry.host_proxy = None;
            entry.phase_state = PhaseState::Stopped;
            entry.sandbox = make_sandbox_with_condition(
                &entry.sandbox,
                &DriverCondition {
                    r#type: "Ready".into(),
                    status: "False".into(),
                    reason: "Stopped".into(),
                    message: "MXC sandbox stopped".into(),
                    last_transition_time: String::new(),
                },
                false,
            );
            let snapshot = entry.sandbox.clone();
            drop(registry);
            let _ = self.watch_tx.send(sandbox_event(snapshot));
        }
        Ok(())
    }
    pub async fn delete_sandbox(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<bool, tonic::Status> {
        let lifecycle_gate = {
            let registry = self.registry.lock().await;
            let Some(entry) = registry.get(sandbox_id) else {
                return Ok(false);
            };
            if entry.sandbox.name != sandbox_name {
                return Err(tonic::Status::failed_precondition(
                    "sandbox_id did not match sandbox_name",
                ));
            }
            entry.lifecycle_gate.clone()
        };

        // See stop_sandbox's matching comment on lifecycle_gate.
        let _lifecycle_guard = lifecycle_gate.lock().await;
        let (
            iso_id,
            isolation_stopped,
            shutdown_tx,
            terminated_rx,
            signal_file,
            control_channel,
            host_proxy,
        ) = {
            let mut registry = self.registry.lock().await;
            let Some(entry) = registry.get_mut(sandbox_id) else {
                return Ok(false);
            };
            (
                entry.iso_sandbox_id.clone(),
                entry.isolation_stopped,
                entry.shutdown_tx.take(),
                // .clone(), not .take() -- see stop_sandbox's matching
                // comment: a watch::Receiver survives a caller that times
                // out and retries, unlike a consumed oneshot.
                entry.terminated_rx.clone(),
                entry.signal_file.take(),
                entry.control_channel.take(),
                entry.host_proxy.take(),
            )
        };
        drop(host_proxy);
        if let Some(ref iso_id) = iso_id {
            if !isolation_stopped {
                self.invoker.stop(iso_id).await.map_err(|error| {
                    tonic::Status::internal(format!("wxc-exec stop failed: {error}"))
                })?;
                // Persist phase progress before deprovision. If deprovision
                // fails, a retry resumes here instead of stopping twice.
                let mut registry = self.registry.lock().await;
                if let Some(entry) = registry.get_mut(sandbox_id) {
                    entry.isolation_stopped = true;
                }
            }
            self.invoker.deprovision(iso_id).await.map_err(|error| {
                tonic::Status::internal(format!("wxc-exec deprovision failed: {error}"))
            })?;
        } else {
            // Prefer telling the spawner directly over the control channel
            // (a "shutdown" request -- see the launch handshake) so it can
            // proactively kill its target and exit before the AppContainer
            // teardown below, since that teardown alone can leave sandboxed
            // processes running well past this call returning. Awaited
            // (bounded by request()'s own 3s timeout) rather than
            // fire-and-forget: a detached task races the shutdown_tx
            // backstop below instead of being superseded by it, so the
            // graceful path can lose to its own fallback. The backstop
            // still always runs afterward regardless of outcome here --
            // this only orders "ask nicely" before "force it". Only
            // present when the driver launched openshell-supervisor-relay
            // (spawner wrapping); mxc-ws-agent.rs (no control channel)
            // still uses the older signal-file mechanism.
            if let Some(channel) = control_channel {
                match channel
                    .request(
                        "shutdown",
                        serde_json::Value::Null,
                        std::time::Duration::from_secs(3),
                    )
                    .await
                {
                    Ok(_) => {
                        info!(sandbox = %sandbox_name, "control-channel shutdown acknowledged");
                    }
                    Err(e) => {
                        warn!(sandbox = %sandbox_name, "control-channel shutdown failed: {e}");
                    }
                }
            }
            // Write the shutdown signal file so the spawner inside the
            // AppContainer detects deletion and exits cleanly, freeing ports
            // and child processes even if MXC does not cascade-kill them when
            // wxc-exec is terminated. Only set for mxc-ws-agent.rs (no
            // control channel) -- see above.
            if let Some(ref path) = signal_file
                && let Err(e) = std::fs::write(path, b"")
            {
                warn!(sandbox = %sandbox_name, path = %path.display(), error = %e,
                          "failed to write ProcessContainer shutdown signal file");
            }
            // Signal monitor_exec to kill wxc-exec as a backstop.
            if let Some(tx) = shutdown_tx {
                let _ = tx.send(());
            }
            // Await *confirmed* termination via terminated_rx -- not just
            // firing the signal and reporting success regardless -- before
            // this removes the registry entry and returns Ok(true). Without
            // this, delete_sandbox could report success while the
            // ProcessContainer (and whatever it launched) is still alive,
            // retaining ports and file locks (see stop_sandbox's matching
            // comment). Runs whenever terminated_rx is present, independent
            // of whether THIS call sent the kill signal above -- shutdown_tx
            // is None either because the process already exited naturally,
            // or because an earlier (possibly timed-out) stop/delete attempt
            // already sent it. A retry must still confirm genuine
            // completion via the persisted watch value rather than assuming
            // it, or it can remove the registry entry and report success
            // while the process is still alive (MR !98 review thread).
            if let Some(mut rx) = terminated_rx
                && !wait_for_termination(&mut rx).await
            {
                warn!(sandbox = %sandbox_name, "timed out waiting for ProcessContainer termination on delete");
                return Err(tonic::Status::deadline_exceeded(format!(
                    "sandbox {sandbox_name} did not terminate within the delete timeout"
                )));
            }
        }

        let mut registry = self.registry.lock().await;
        if registry.remove(sandbox_id).is_some() {
            if let Ok(mut idx) = self.attribution.lock() {
                idx.forget(sandbox_id);
            }
            let _ = self.watch_tx.send(deleted_event(sandbox_id.to_string()));
            return Ok(true);
        }
        Ok(false)
    }
    /// Returns a stream of watch events.
    ///
    /// First emits a snapshot of all current sandboxes, then forwards live
    /// events from the broadcast channel.
    pub async fn watch_sandboxes(&self) -> WatchStream {
        let (tx, rx) =
            mpsc::channel::<Result<WatchSandboxesEvent, openshell_core::ComputeDriverError>>(256);

        // Subscribe while holding the registry lock. Every transition is then
        // represented by either this snapshot or the live receiver.
        let (snapshots, mut broadcast_rx): (Vec<DriverSandbox>, _) = {
            let registry = self.registry.lock().await;
            let broadcast_rx = self.watch_tx.subscribe();
            let snapshots = registry
                .values()
                .map(|entry| entry.sandbox.clone())
                .collect();
            (snapshots, broadcast_rx)
        };

        let tx_clone = tx.clone();
        tokio::spawn(async move {
            // Deliver initial snapshots.
            for sb in snapshots {
                if tx_clone.send(Ok(sandbox_event(sb))).await.is_err() {
                    return;
                }
            }
            // Forward live events.
            loop {
                match broadcast_rx.recv().await {
                    Ok(event) => {
                        if tx_clone.send(Ok(event)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Drop lagged events — the gateway re-syncs via Get/List.
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        Box::pin(ReceiverStream::new(rx))
    }
}

// ── Dynamic port forwarding ───────────────────────────────────────────────────
//
// Closes the `openshell forward service` gap for MXC: `handle_forward_tcp`
// normally requires a live `ConnectSupervisor` session, which MXC's
// exec-in-driver design never registers (no in-sandbox supervisor process
// exists). This gives the gateway an alternate path straight into a running
// sandbox's control channel instead, bypassing that requirement entirely.

#[derive(Debug, thiserror::Error)]
pub enum OpenDynamicForwardError {
    #[error("sandbox {0} not found")]
    SandboxNotFound(String),
    #[error(
        "sandbox {0} has no control channel (not launched via a relay spawner, or not yet Ready)"
    )]
    NoControlChannel(String),
    #[error("failed to bind ephemeral relay listener: {0}")]
    RelayBind(#[source] std::io::Error),
    #[error("control channel request failed: {0}")]
    ControlChannel(#[from] crate::control_channel::ControlChannelError),
    #[error("sandbox rejected forward request: {0}")]
    Rejected(String),
}

/// Cheap, cloneable handle exposing MXC's dynamic port-forward capability —
/// see `MxcComputeBackend::forward_sink`.
#[derive(Clone)]
pub struct ForwardSink {
    registry: Arc<Mutex<HashMap<String, SandboxEntry>>>,
}

impl ForwardSink {
    /// Open a new, independent relay bridge to `target_port` inside the
    /// given sandbox's `AppContainer`, on demand (not pre-declared in the
    /// gateway TOML). Returns the ephemeral relay's address — reachable
    /// directly by the gateway process itself, no `AppContainer` boundary on
    /// that leg — a per-forward auth nonce the caller MUST send as the first
    /// bytes on its own connection to that address (see `relay.rs` module
    /// docs: the relay is host-interface-bound, so another reachable process
    /// could otherwise race to connect first and hijack the forward), and a
    /// [`relay::RelayHandle`] the caller must hold for as long as the
    /// forward should stay open, then `.stop()` (or just drop) to tear it
    /// down.
    ///
    /// Target host is always `127.0.0.1` inside the `AppContainer` (matching
    /// `TcpRelayTarget`'s existing loopback-only restriction at the gRPC
    /// layer), so there's no separate `target_host` parameter to thread
    /// through — the sandbox-side `forward` op only ever dials loopback.
    pub async fn open_dynamic_forward(
        &self,
        sandbox_id: &str,
        target_port: u16,
    ) -> Result<(SocketAddr, [u8; relay::NONCE_LEN], relay::RelayHandle), OpenDynamicForwardError>
    {
        let (control_channel, sandbox_name) = {
            let reg = self.registry.lock().await;
            let entry = reg
                .get(sandbox_id)
                .ok_or_else(|| OpenDynamicForwardError::SandboxNotFound(sandbox_id.to_string()))?;
            let channel = entry
                .control_channel
                .clone()
                .ok_or_else(|| OpenDynamicForwardError::NoControlChannel(sandbox_id.to_string()))?;
            (channel, entry.sandbox.name.clone())
        };

        // Fresh per forward -- see relay.rs module docs for why this matters
        // on a host-interface listener.
        let nonce: [u8; relay::NONCE_LEN] = rand::random();

        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (relay_handle, relay_addr) = relay::start_control_channel_relay(
            bind_addr,
            sandbox_name,
            nonce,
            control_channel,
            target_port,
        )
        .await
        .map_err(OpenDynamicForwardError::RelayBind)?;

        Ok((relay_addr, nonce, relay_handle))
    }
}

// ── Lifecycle task ────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn run_lifecycle(
    invoker: WxcExecInvoker,
    config: MxcComputeConfig,
    registry: Arc<Mutex<HashMap<String, SandboxEntry>>>,
    watch_tx: Arc<broadcast::Sender<WatchSandboxesEvent>>,
    attribution: Arc<std::sync::Mutex<crate::etw_consumer::AttributionIndex>>,
    sandbox: DriverSandbox,
    sandbox_config: MxcSandboxConfig,
    mapped: MappedConfig,
    provider_credentials: Option<ProviderCredentialState>,
    mut reserved_proxy_listener: Option<std::net::TcpListener>,
    startup_guard: tokio::sync::OwnedMutexGuard<()>,
) {
    let sandbox_id = sandbox.id.clone();
    let sandbox_name = sandbox.name.clone();
    let proxy_addr = mapped.proxy_addr;
    let proxy_auth = proxy_addr.map(|_| SandboxProxyAuth::generate());
    let trimmed_policy = mapped.trimmed_policy.clone();
    let host_proxy = if let (Some(addr), Some(proxy_policy), Some(proxy_auth)) =
        (proxy_addr, trimmed_policy.clone(), proxy_auth.as_ref())
    {
        drop(reserved_proxy_listener.take());
        match openshell_supervisor_network::host::start_host_proxy(
            openshell_supervisor_network::host::HostProxyConfig {
                bind_addr: addr,
                policy: proxy_policy,
                binary_path: host_proxy_binary_path(&sandbox_config),
                client_auth: proxy_auth.host_client_auth(),
                sandbox_id: Some(sandbox_id.clone()),
                sandbox_name: Some(sandbox_name.clone()),
                openshell_endpoint: None,
                provider_credentials: provider_credentials.clone(),
                agent_proposals: openshell_core::proposals::AgentProposals::default(),
                denial_tx: None,
                activity_tx: None,
            },
        )
        .await
        {
            Ok(handle) => {
                info!(
                    sandbox = %sandbox_name,
                    address = %addr,
                    "MXC host egress proxy started"
                );
                Some(handle)
            }
            Err(error) => {
                set_failed(
                    &registry,
                    &watch_tx,
                    &sandbox,
                    &sandbox_id,
                    &format!("failed to start MXC host egress proxy at {addr}: {error}"),
                )
                .await;
                return;
            }
        }
    } else {
        None
    };
    let host_proxy_ca_paths = host_proxy
        .as_ref()
        .and_then(openshell_supervisor_network::host::HostProxyHandle::ca_file_paths);
    // A curated ProcessContainer cannot read the host's private temp folder.
    // Stage only the public CA material beneath the per-sandbox working directory,
    // DACL is already granted by the policy, so HTTPS clients can authenticate
    // the OpenShell inspection proxy without broadening filesystem access.
    let agent_proxy_ca_paths = if config.pc_minimal_env && host_proxy_ca_paths.is_some() {
        match stage_tls_ca_files(
            host_proxy_ca_paths.as_ref(),
            &sandbox_config.cwd,
            &sandbox_id,
        ) {
            Ok(paths) => paths,
            Err(error) => {
                set_failed(
                    &registry,
                    &watch_tx,
                    &sandbox,
                    &sandbox_id,
                    &format!("failed to stage MXC egress proxy CA files: {error}"),
                )
                .await;
                return;
            }
        }
    } else {
        host_proxy_ca_paths.clone()
    };
    if let Some(addr) = proxy_addr {
        {
            let mut registry = registry.lock().await;
            if let Some(entry) = registry.get_mut(&sandbox_id) {
                entry.trimmed_policy = trimmed_policy;
                entry.proxy_addr = Some(addr);
                entry.host_proxy = host_proxy;
            }
        }
        let _ = watch_tx.send(platform_event(
            sandbox_id.clone(),
            "EgressRedirect",
            format!("MXC egress redirected to OpenShell host CONNECT proxy at {addr}"),
        ));
    }

    let mut readwrite_paths = mapped.readwrite_paths;
    if !config.pc_minimal_env {
        append_tls_readwrite_grant(&mut readwrite_paths, host_proxy_ca_paths.as_ref());
    }
    let readonly_paths = mapped.readonly_paths;
    let ui = mapped.ui;
    let filesystem = MxcFilesystem {
        readwrite_paths,
        readonly_paths,
        // OpenShell's policy model has no explicit deny field; default-deny is
        // implicit and enforced by processContainer at the OS boundary.
        denied_paths: Vec::new(),
    };
    let command_line = encode_windows_command_line(&sandbox_config.command);
    // ProcessContainer starts with a completely blank environment — no PATH,
    // no SystemRoot, nothing. Start with either an empty environment or the
    // safe Windows bootstrap set, then layer the per-request environment from
    // the CreateSandbox spec and the TLS/proxy variables required by governed
    // egress.
    let mut env_map: HashMap<String, String> = if config.pc_minimal_env {
        HashMap::new()
    } else {
        MINIMAL_WINDOWS_BOOTSTRAP_ENV
            .iter()
            .filter_map(|&key| std::env::var(key).ok().map(|v| (key.to_string(), v)))
            .collect()
    };

    for entry in sandbox_environment(&sandbox) {
        if let Some(pos) = entry.find('=') {
            env_map.insert(entry[..pos].to_string(), entry[pos + 1..].to_string());
        }
    }

    let mut env: Vec<String> = env_map
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    append_provider_child_env(&mut env, provider_credentials.as_ref());
    // Layer proxy configuration for every env tier. Curated ProcessContainers
    // use the staged CA copies above; other tiers use the original paths.
    append_tls_env_vars(&mut env, agent_proxy_ca_paths.as_ref());
    append_proxy_env_vars(&mut env, proxy_addr, proxy_auth.as_ref());
    env.sort(); // deterministic order for logging / debugging
    info!(sandbox = %sandbox_name, count = env.len(), "MXC process env vars");

    // When spawner wrapping is configured, launch openshell-supervisor-relay
    // instead of the per-sandbox command directly. The real command/env are sent over
    // the control channel once the spawner announces readiness (see the
    // "launch" handshake below) rather than written to the working directory as
    // agent-cmd.txt/agent-env.txt -- this keeps command/env (which can carry
    // secrets, e.g. OPENCLAW_GATEWAY_TOKEN) off disk entirely and eliminates
    // the file-staleness/namespace-mismatch bug class that existed when they
    // were file-based. The target application (e.g. OpenClaw)
    // stays entirely unaware of the relay protocol either way.
    let spawner_wrapping_active =
        !config.pc_relay_spawner_path.is_empty() && config.pc_relay_target_port != 0;
    let effective_command_line = if spawner_wrapping_active {
        // Quoted: pc_relay_spawner_path is a filesystem path and may contain
        // spaces (e.g. under "Program Files"); unquoted, wxc-exec would
        // parse the executable path incorrectly and the launch would fail
        // before the control-channel handshake ever starts.
        format!(
            "\"{}\" {}",
            config.pc_relay_spawner_path, config.pc_relay_target_port
        )
    } else {
        command_line.clone()
    };

    // Downstream logging/ETW attribution should reflect what's actually
    // launched (openshell-supervisor-relay, when wrapping is active), not
    // the original workload command -- shadow command_line with the effective
    // value.
    let command_line = effective_command_line;
    let process = MxcProcess {
        command_line: command_line.clone(),
        cwd: sandbox_config.cwd.clone(),
        // Cloned: the launch handshake below (spawner_wrapping_active case)
        // needs its own copy of `env` to send over the control channel.
        env: env.clone(),
        timeout: 0,
    };
    let network = proxy_addr.map(|addr| MxcNetwork {
        default_policy: "block".into(),
        proxy: Some(addr),
        allow_local_network: false,
    });

    let child = match config.backend {
        MxcBackend::IsolationSession => {
            let iso_sandbox_id = match invoker
                .provision(&config.default_configuration_id, filesystem, network)
                .await
            {
                Ok(id) => id,
                Err(error) => {
                    set_failed(
                        &registry,
                        &watch_tx,
                        &sandbox,
                        &sandbox_id,
                        &error.to_string(),
                    )
                    .await;
                    return;
                }
            };
            info!(sandbox = %sandbox_name, iso_id = %iso_sandbox_id, "MXC provisioned");
            {
                let mut registry = registry.lock().await;
                if let Some(entry) = registry.get_mut(&sandbox_id) {
                    // Publish cleanup identity before any later lifecycle await.
                    entry.iso_sandbox_id = Some(iso_sandbox_id.clone());
                    entry.isolation_stopped = false;
                }
            }
            if let Err(error) = invoker.start(&iso_sandbox_id).await {
                set_failed(
                    &registry,
                    &watch_tx,
                    &sandbox,
                    &sandbox_id,
                    &error.to_string(),
                )
                .await;
                return;
            }
            info!(sandbox = %sandbox_name, "MXC started");
            match invoker.spawn_exec(&iso_sandbox_id, process).await {
                Ok(child) => child,
                Err(error) => {
                    set_failed(
                        &registry,
                        &watch_tx,
                        &sandbox,
                        &sandbox_id,
                        &error.to_string(),
                    )
                    .await;
                    return;
                }
            }
        }
        MxcBackend::ProcessContainer => {
            let process_container = MxcProcessContainer {
                least_privilege: config.pc_least_privilege,
                capabilities: config.pc_capabilities.clone(),
            };
            // Build the effective network config:
            // - egress_proxy: use the proxy-based network (already in `network`)
            // - pc_network_allow: inject allow-all (fallback for builds without capability support)
            // - pc_allow_local_network: block-default but with allowLocalNetwork=true so
            //   intra-container loopback works and the spawner can reach the relay on the
            //   host's route-selected private interface without a full egress proxy.
            let effective_network = if network.is_none()
                && (config.pc_allow_local_network || config.pc_network_allow)
            {
                // Both flags apply to the same no-proxy startup case and
                // aren't mutually exclusive -- honor both instead of letting
                // pc_allow_local_network's branch silently force
                // default_policy back to "block" and drop pc_network_allow's
                // unrestricted-egress intent.
                Some(MxcNetwork {
                    default_policy: if config.pc_network_allow {
                        "allow".into()
                    } else {
                        "block".into()
                    },
                    proxy: None,
                    allow_local_network: config.pc_allow_local_network,
                })
            } else {
                // `network` is Some here (egress_proxy configured). Preserve
                // config.pc_allow_local_network instead of unconditionally
                // clearing it -- MxcNetwork already carries both `proxy` and
                // `allow_local_network` together, so a proxy and local-network
                // access aren't mutually exclusive.
                network.map(|mut n| {
                    n.allow_local_network = config.pc_allow_local_network;
                    n
                })
            };
            match invoker
                .run_oneshot(
                    &sandbox_id,
                    filesystem,
                    process_container,
                    process,
                    effective_network,
                    ui,
                )
                .await
            {
                Ok(child) => child,
                Err(error) => {
                    set_failed(
                        &registry,
                        &watch_tx,
                        &sandbox,
                        &sandbox_id,
                        &error.to_string(),
                    )
                    .await;
                    return;
                }
            }
        }
    };
    info!(sandbox = %sandbox_name, command = %command_line, backend = ?config.backend, "MXC agent launched");

    // Stream wxc-exec's stdout/stderr into the gateway log as it runs, so the
    // agent's live output is visible in the gateway console instead of sitting
    // unread in the OS pipe until the process exits.
    let mut child = child;

    // Control channel: correlate JSON responses in the stdout stream with
    // pending requests sent over stdin (see control_channel.rs). Only
    // meaningful when the process on the other end is
    // openshell-supervisor-relay (spawner wrapping active) -- an arbitrary
    // workload target wouldn't understand this protocol, so stdin is
    // left untouched (and unpiped expectations unaffected) otherwise.
    let control_channel: Option<Arc<ControlChannel>> = if spawner_wrapping_active {
        if let Some(stdin) = child.stdin.take() {
            Some(Arc::new(ControlChannel::new(stdin)))
        } else {
            // wxc-exec didn't give us a piped stdin even though spawner
            // wrapping was requested. Without a control channel,
            // openshell-supervisor-relay would wait forever for a
            // "launch" request that can never arrive -- a silent hang,
            // not a failure. Fail the sandbox now instead.
            let err = "wxc-exec stdin is not piped; control-channel launch cannot proceed";
            set_failed(&registry, &watch_tx, &sandbox, &sandbox_id, err).await;
            let _ = child.kill().await;
            let _ = child.wait().await;
            return;
        }
    } else {
        // No control channel on the direct-agent path. Both spawn_exec and
        // run_oneshot now always pipe stdin (needed for the control-channel
        // case above), so without this the write end stays open inside
        // `child` for the sandbox's full lifetime -- any workload that
        // reads stdin until EOF would then block forever, since EOF never
        // arrives. Drop it so stdin readers see EOF immediately instead.
        drop(child.stdin.take());
        None
    };
    let pending_responses = control_channel.as_ref().map(|c| c.pending_handle());
    // Startup-ready signal from the spawner (see control_channel.rs's
    // try_route_ready). Fired once, before the "launch" handshake below.
    // Carries Err(reason) instead of firing at all when the spawner's
    // reported protocol_version doesn't match what this driver requires --
    // see try_route_ready's doc comment.
    let (ready_slot, ready_rx) = if spawner_wrapping_active {
        let (tx, rx) = oneshot::channel::<Result<(), String>>();
        (Some(Arc::new(Mutex::new(Some(tx)))), Some(rx))
    } else {
        (None, None)
    };
    // Target-ready signal from the spawner (see control_channel.rs's
    // try_route_target_ready) -- fired once the target is actually running
    // and its configured port is accepting connections, distinct from the
    // "launch" response below (which only confirms the command/env
    // arrived). Awaited after "launch" succeeds and before publishing
    // Ready=True, so Ready can't be reported while the target is still
    // unreachable. Always Ok(()) when it fires (no version gate on this
    // event -- see try_route_target_ready).
    let (target_ready_slot, target_ready_rx) = if spawner_wrapping_active {
        let (tx, rx) = oneshot::channel::<Result<(), String>>();
        (Some(Arc::new(Mutex::new(Some(tx)))), Some(rx))
    } else {
        (None, None)
    };

    if let Some(stdout) = child.stdout.take() {
        let sandbox_name_out = sandbox_name.clone();
        let ready_slot = ready_slot.clone();
        let target_ready_slot = target_ready_slot.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            loop {
                match lines.next_line().await {
                    Ok(Some(line)) => {
                        let routed_ready = match &ready_slot {
                            Some(slot) => ControlChannel::try_route_ready(slot, &line).await,
                            None => false,
                        };
                        let routed_target_ready = match &target_ready_slot {
                            Some(slot) => ControlChannel::try_route_target_ready(slot, &line).await,
                            None => false,
                        };
                        let routed = routed_ready
                            || routed_target_ready
                            || match &pending_responses {
                                Some(pending) => {
                                    ControlChannel::try_route_response(pending, &line).await
                                }
                                None => false,
                            };
                        if !routed {
                            info!(sandbox = %sandbox_name_out, "wxc-exec stdout: {line}");
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        warn!(sandbox = %sandbox_name_out, "wxc-exec stdout read error: {e}");
                        break;
                    }
                }
            }
            // Stdout is gone (EOF or read error): no control-channel response
            // will ever arrive again. Fail any still-pending requests now
            // instead of leaving them to time out individually.
            if let Some(pending) = &pending_responses {
                ControlChannel::fail_all_pending(pending).await;
            }
        });
    }
    // Drop this scope's Arc clones now that the stdout task holds its own:
    // if the spawner exits before ever sending "ready"/"target_ready", the
    // stdout task's clone is the only thing keeping the
    // Mutex<Option<Sender>> alive, so its loop ending (EOF) drops the last
    // reference -- which drops the still-`Some` Sender and makes
    // ready_rx/target_ready_rx below observe a dropped sender immediately
    // instead of waiting out the full timeout.
    drop(ready_slot);
    drop(target_ready_slot);
    if let Some(stderr) = child.stderr.take() {
        let sandbox_name_err = sandbox_name.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            loop {
                match lines.next_line().await {
                    Ok(Some(line)) => warn!(sandbox = %sandbox_name_err, "wxc-exec stderr: {line}"),
                    Ok(None) => break,
                    Err(e) => {
                        warn!(sandbox = %sandbox_name_err, "wxc-exec stderr read error: {e}");
                        break;
                    }
                }
            }
        });
    }
    // Publish a cancellable handle (exec_child, and for ProcessContainer
    // shutdown_tx/terminated_rx too) and release the startup gate now,
    // rather than holding it until the target-readiness wait below (up to
    // ~430s worst case: 120s ready + 310s target_ready) completes or times
    // out. stop_sandbox/delete_sandbox block on lifecycle_gate before doing
    // anything else, so holding it this long meant a stop/delete arriving
    // while a target is slow to (or never does) come up had no way to
    // interrupt that wait -- it just queued up behind it. See also imp.rs's
    // matching fix: openshell-supervisor-relay now races its own
    // port-readiness wait against a "shutdown" request instead of only
    // observing shutdown once that wait finishes.
    let shutdown_rx = {
        let mut reg = registry.lock().await;
        let Some(entry) = reg.get_mut(&sandbox_id) else {
            // The sandbox was deleted between agent launch and now. `delete`
            // already tore down the *previous* process entry, but `child`
            // here was spawned after that -- it was never registered, so
            // nothing else will kill it. `tokio::process::Child` does not
            // kill-on-drop, so without this the wxc-exec process (and its
            // AppContainer) would keep running past `delete` reporting
            // success.
            drop(reg);
            let _ = child.kill().await;
            let _ = child.wait().await;
            return;
        };

        // Seed ETW attribution while holding the registry lock so a concurrent
        // `delete` cannot remove the sandbox after we register (which would leave
        // a stale key). The `wxc-exec` pid we just spawned is the collision-proof
        // anchor that ties the `Sandboxing` provider's events back to this
        // `sandbox_id` while the exact process generation is alive. Command
        // text is never an attribution key.
        if config.etw_audit
            && let Some(pid) = child.id()
        {
            match crate::etw_consumer::child_process_start_key(&child) {
                Ok(process_start_key) => {
                    if let Ok(mut idx) = attribution.lock() {
                        idx.register_launch(&sandbox_id, &sandbox_name, pid, process_start_key);
                    }
                }
                Err(error) => {
                    warn!(sandbox = %sandbox_name, pid, error,
                        "failed to obtain wxc-exec process generation key; ETW attribution disabled for this launch");
                }
            }
        }

        entry.exec_child = Some(child);
        entry.control_channel.clone_from(&control_channel);

        // For ProcessContainer, wire a kill channel so stop_sandbox/
        // delete_sandbox can terminate the wxc-exec process and cause the
        // AppContainer (and all in-sandbox processes, including long-lived
        // servers) to be torn down, as a backstop regardless of how shutdown
        // is signaled below. `terminated_rx` is the other half of the pair
        // `monitor_exec` uses to report back once the process has actually
        // exited, so callers can await confirmed termination instead of
        // just firing the kill and hoping.
        if matches!(config.backend, MxcBackend::ProcessContainer) {
            let (tx, rx) = oneshot::channel::<()>();
            let (done_tx, done_rx) = watch::channel(false);
            entry.shutdown_tx = Some(tx);
            entry.terminated_rx = Some(done_rx);
            // The generic spawner (openshell-supervisor-relay) gets its
            // shutdown notice over the control channel (see delete_sandbox's
            // "shutdown" request) -- no file needed. Only mxc-ws-agent.rs
            // (set directly as the sandbox command, not spawner-wrapped, no
            // control channel) still polls a signal file for it.
            if !spawner_wrapping_active && !sandbox_config.cwd.is_empty() {
                entry.signal_file =
                    Some(PathBuf::from(&sandbox_config.cwd).join("openshell-shutdown.signal"));
            }
            Some((rx, done_tx))
        } else {
            None
        }
    };

    // 6. Monitor exec completion in background.
    let registry2 = registry.clone();
    let watch_tx2 = watch_tx.clone();
    let sandbox2 = sandbox.clone();
    let sandbox_id2 = sandbox_id.clone();
    tokio::spawn(async move {
        monitor_exec(
            registry2,
            watch_tx2,
            attribution,
            sandbox2,
            sandbox_id2,
            shutdown_rx,
        )
        .await;
    });

    // A cancellable handle now exists in the registry (exec_child, plus
    // shutdown_tx/terminated_rx for ProcessContainer) -- stop_sandbox/
    // delete_sandbox arriving from here on can act immediately instead of
    // waiting out the target-readiness wait below.
    drop(startup_guard);

    // When spawner wrapping is active, openshell-supervisor-relay.rs hasn't
    // spawned the real target yet -- it waits for a "launch" request over
    // the control channel instead of reading agent-cmd.txt/agent-env.txt
    // from files in the workload directory (see its module docs). Wait for its startup-ready
    // event, then send the real command/env directly; this keeps them off
    // disk (they can carry secrets, e.g. OPENCLAW_GATEWAY_TOKEN) and also
    // proves the correlated request/response path works end to end -- the
    // old unconditional "ping" this replaces only logged a warning on
    // failure, but failure here is fatal: nothing was ever spawned.
    if let (Some(channel), Some(ready_rx), Some(target_ready_rx)) =
        (control_channel.clone(), ready_rx, target_ready_rx)
    {
        // Generous timeout: this fires right after spawn, so it's racing UAC
        // elevation + AppContainer creation (observed up to several
        // seconds), not just the control channel itself. The `forward` path
        // won't have this constraint -- it only runs once the sandbox is
        // already Ready, long past this window.
        let ready_timeout = std::time::Duration::from_mins(2);
        let ready_err = match tokio::time::timeout(ready_timeout, ready_rx).await {
            Ok(Ok(Ok(()))) => None,
            // Protocol version mismatch (see try_route_ready) -- an
            // independently staged, out-of-sync relay binary. Reject fast
            // and clearly instead of proceeding into a "launch" handshake
            // it may not understand.
            Ok(Ok(Err(version_err))) => Some(version_err),
            Ok(Err(_)) => Some("spawner exited before sending its ready event".to_string()),
            Err(_) => Some(format!(
                "timed out after {ready_timeout:?} waiting for spawner ready event"
            )),
        };
        let launch_err = if let Some(e) = ready_err {
            Some(e)
        } else {
            let launch_data = serde_json::json!({
                "command": sandbox_config.command,
                "env": env,
            });
            match channel
                .request("launch", launch_data, std::time::Duration::from_mins(2))
                .await
            {
                Ok(resp) if resp.get("ok").and_then(serde_json::Value::as_bool) == Some(true) => {
                    info!(sandbox = %sandbox_name, "control-channel launch acknowledged");
                    // The "launch" response above only confirms the
                    // command/env reached the spawner -- it still needs
                    // to spawn the target and confirm its configured
                    // port is accepting connections
                    // (openshell-supervisor-relay's own
                    // wait_for_port_ready, up to ~300s worst case across
                    // its own retries). Await that distinct
                    // "target_ready" event before treating launch as
                    // successful, so a caller acting on Ready=True below
                    // can never race a target that hasn't bound its port
                    // yet.
                    let target_ready_timeout = std::time::Duration::from_secs(310);
                    match tokio::time::timeout(target_ready_timeout, target_ready_rx).await {
                        Ok(Ok(Ok(()))) => {
                            info!(sandbox = %sandbox_name, "control-channel target ready");
                            None
                        }
                        // No version gate on this event, so this arm
                        // never actually fires today -- see
                        // try_route_target_ready -- but match it
                        // explicitly rather than unreachable!(), in case
                        // that ever changes.
                        Ok(Ok(Err(target_err))) => Some(target_err),
                        Ok(Err(_)) => {
                            Some("spawner exited before its target became ready".to_string())
                        }
                        Err(_) => Some(format!(
                            "timed out after {target_ready_timeout:?} waiting for target to become ready"
                        )),
                    }
                }
                Ok(resp) => Some(
                    resp.get("error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("launch rejected")
                        .to_string(),
                ),
                Err(e) => Some(e.to_string()),
            }
        };
        if let Some(err) = launch_err {
            warn!(sandbox = %sandbox_name, "control-channel launch failed: {err}");
            set_failed(&registry, &watch_tx, &sandbox, &sandbox_id, &err).await;
            // `child` was already moved into the registry (and possibly
            // already claimed by monitor_exec, spawned above) once a
            // cancellable handle was published. ProcessContainer has
            // shutdown_tx/terminated_rx for exactly this: signal it and
            // await confirmed termination, the same way stop_sandbox/
            // delete_sandbox would. Otherwise fall back to reclaiming
            // exec_child directly and killing it (a monitor_exec race that
            // hasn't claimed exec_child yet -- rare, but possible), or, for
            // isolation_session (which has neither shutdown_tx/terminated_rx
            // nor -- by this point -- a leftover exec_child, since
            // monitor_exec almost always already claimed it), an explicit
            // invoker.stop() on the isolation session.
            let (shutdown_tx, terminated_rx, leftover_child, iso_id, isolation_stopped) = {
                let mut reg = registry.lock().await;
                match reg.get_mut(&sandbox_id) {
                    Some(entry) => (
                        entry.shutdown_tx.take(),
                        // .clone(), not .take(): see stop_sandbox's matching
                        // comment on terminated_rx.
                        entry.terminated_rx.clone(),
                        entry.exec_child.take(),
                        entry.iso_sandbox_id.clone(),
                        entry.isolation_stopped,
                    ),
                    None => (None, None, None, None, false),
                }
            };
            if let Some(tx) = shutdown_tx {
                let _ = tx.send(());
            }
            if let Some(mut child) = leftover_child {
                // We raced monitor_exec for exec_child and this branch's
                // earlier `entry.exec_child.take()` won: monitor_exec will
                // find the registry slot already empty and return before
                // ever reaching its `done_tx.send(true)` (MR !98 review
                // thread). Waiting on terminated_rx here would therefore
                // wait out the full timeout for a signal that never comes,
                // while `child` -- which does not kill-on-drop -- leaks.
                // Kill and reap it directly instead.
                let _ = child.kill().await;
                let _ = child.wait().await;
            } else if let Some(mut rx) = terminated_rx {
                // leftover_child was None, so monitor_exec already claimed
                // exec_child and is the one racing shutdown_tx against
                // child.wait(); await its confirmed termination.
                if !wait_for_termination(&mut rx).await {
                    warn!(sandbox = %sandbox_name, "timed out waiting for ProcessContainer termination after launch failure");
                }
            } else if let Some(iso_id) = iso_id {
                // isolation_session: no shutdown_tx/terminated_rx (those are
                // ProcessContainer-only -- see the wiring site above) and no
                // leftover_child either at this point, so without this the
                // MXC session (and the wxc-exec `exec` child monitor_exec's
                // own child.wait() is blocked on) would keep running
                // indefinitely after a launch/target-ready failure here
                // (MR !98 review thread). Best-effort: log rather than
                // propagate, since this cleanup runs inside an
                // already-failing path.
                if !isolation_stopped {
                    if let Err(error) = invoker.stop(&iso_id).await {
                        warn!(sandbox = %sandbox_name, %error, "failed to stop isolation session after launch failure");
                    } else {
                        let mut reg = registry.lock().await;
                        if let Some(entry) = reg.get_mut(&sandbox_id) {
                            entry.isolation_stopped = true;
                        }
                    }
                }
            }
            return;
        }
    }

    // 5. Self-report Ready=True. The cancellable handle (exec_child, and for
    // ProcessContainer shutdown_tx/terminated_rx) was already published to
    // the registry and monitor_exec already spawned, above -- this only
    // updates the sandbox's condition now that the target is confirmed
    // reachable.
    let ready_sandbox = make_sandbox_with_condition(
        &sandbox,
        &DriverCondition {
            r#type: "Ready".into(),
            status: "True".into(),
            reason: "AgentRunning".into(),
            message: format!("Agent exec launched: {command_line}"),
            last_transition_time: String::new(),
        },
        false,
    );
    {
        let mut reg = registry.lock().await;
        let Some(entry) = reg.get_mut(&sandbox_id) else {
            return;
        };
        // Only Starting -> Running is valid here. This publish runs after
        // run_lifecycle released its startup gate (see drop(startup_guard)
        // above) specifically so a stop/delete arriving during the
        // target-readiness wait isn't blocked behind it -- but that means a
        // stop/delete may have already moved this sandbox past Starting by
        // the time this runs. Overwriting that final state with a stale
        // Running, or emitting a Ready event for an already-Stopped
        // sandbox, would be wrong (MR !98 review thread; same reasoning as
        // set_failed's matching guard).
        if entry.phase_state != PhaseState::Starting {
            return;
        }
        entry.sandbox = ready_sandbox.clone();
        entry.phase_state = PhaseState::Running;
    }
    let _ = watch_tx.send(sandbox_event(ready_sandbox));
}

async fn wait_for_termination(rx: &mut watch::Receiver<bool>) -> bool {
    matches!(
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            rx.wait_for(|done| *done)
        )
        .await,
        Ok(Ok(_))
    )
}

async fn monitor_exec(
    registry: Arc<Mutex<HashMap<String, SandboxEntry>>>,
    watch_tx: Arc<broadcast::Sender<WatchSandboxesEvent>>,
    attribution: Arc<std::sync::Mutex<crate::etw_consumer::AttributionIndex>>,
    sandbox: DriverSandbox,
    sandbox_id: String,
    shutdown: Option<(oneshot::Receiver<()>, watch::Sender<bool>)>,
) {
    let child = {
        let mut reg = registry.lock().await;
        reg.get_mut(&sandbox_id).and_then(|e| e.exec_child.take())
    };
    let Some(mut child) = child else {
        return;
    };
    let wxc_pid = child.id();

    // For ProcessContainer sandboxes a stop/delete can arrive while the
    // agent is still running. Race child exit against the kill signal so
    // that the wxc-exec process — and therefore the entire AppContainer
    // (including any long-lived servers bound to ports) — is terminated
    // promptly. `done_tx`, when present, is signaled once the process has
    // genuinely exited (natural exit or the forced kill below) so
    // stop_sandbox/delete_sandbox can await *confirmed* termination instead
    // of firing the kill signal and immediately reporting success.
    let (wait_result, done_tx) = if let Some((rx, done_tx)) = shutdown {
        tokio::select! {
            res = child.wait() => (res, Some(done_tx)),
            _ = rx => {
                if let Err(error) = child.kill().await {
                    warn!(sandbox = %sandbox.name, %error, "failed to terminate MXC process");
                    return;
                }
                if let Err(error) = child.wait().await {
                    warn!(sandbox = %sandbox.name, %error, "failed to confirm MXC process termination");
                    return;
                }
                if let Some(pid) = wxc_pid
                    && let Ok(mut idx) = attribution.lock()
                {
                    idx.retire_launch(&sandbox_id, pid);
                }
                info!(sandbox = %sandbox.name, "MXC ProcessContainer terminated for sandbox stop/delete");
                let _ = done_tx.send(true);
                return;
            }
        }
    } else {
        (child.wait().await, None)
    };
    if wait_result.is_ok() {
        if let Some(pid) = wxc_pid
            && let Ok(mut idx) = attribution.lock()
        {
            idx.retire_launch(&sandbox_id, pid);
        }
        if let Some(done_tx) = done_tx {
            let _ = done_tx.send(true);
        }
    }

    match wait_result {
        Ok(status) if status.success() => {
            info!(sandbox = %sandbox.name, "MXC agent exec completed successfully");
            let done = make_sandbox_with_condition(
                &sandbox,
                &DriverCondition {
                    r#type: "Ready".into(),
                    status: "True".into(),
                    reason: "AgentCompleted".into(),
                    message: "Agent exec finished successfully (exit code 0)".into(),
                    last_transition_time: String::new(),
                },
                false,
            );
            let mut registry = registry.lock().await;
            if let Some(entry) = registry.get_mut(&sandbox_id) {
                entry.host_proxy = None;
                entry.sandbox = done.clone();
                entry.phase_state = PhaseState::Running;
            }
            drop(registry);
            let _ = watch_tx.send(sandbox_event(done));
        }
        Ok(status) => {
            let code = status.code().unwrap_or(-1);
            warn!(sandbox = %sandbox.name, exit_code = code, "MXC agent exec exited non-zero");
            let _ = watch_tx.send(platform_event(
                sandbox_id.clone(),
                "AgentExecFailed",
                format!("agent exited with code {code}; possible out-of-policy write"),
            ));
            let failed = make_sandbox_with_condition(
                &sandbox,
                &DriverCondition {
                    r#type: "Ready".into(),
                    status: "False".into(),
                    reason: "ExecFailed".into(),
                    message: format!("Agent exec exited {code}"),
                    last_transition_time: String::new(),
                },
                false,
            );
            let mut registry = registry.lock().await;
            if let Some(entry) = registry.get_mut(&sandbox_id) {
                entry.host_proxy = None;
                entry.sandbox = failed.clone();
                entry.phase_state = PhaseState::Failed(format!("exit code {code}"));
            }
            drop(registry);
            let _ = watch_tx.send(sandbox_event(failed));
        }
        Err(error) => {
            warn!(sandbox = %sandbox.name, error = %error, "MXC agent exec wait error");
        }
    }
}
async fn set_failed(
    registry: &Arc<Mutex<HashMap<String, SandboxEntry>>>,
    watch_tx: &Arc<broadcast::Sender<WatchSandboxesEvent>>,
    sandbox: &DriverSandbox,
    sandbox_id: &str,
    message: &str,
) {
    warn!(sandbox = %sandbox.name, error = %message, "MXC lifecycle failed");
    let failed = make_sandbox_with_condition(
        sandbox,
        &DriverCondition {
            r#type: "Ready".into(),
            status: "False".into(),
            reason: "ProvisionFailed".into(),
            message: message.to_string(),
            last_transition_time: String::new(),
        },
        false,
    );
    let mut reg = registry.lock().await;
    let Some(entry) = reg.get_mut(sandbox_id) else {
        return;
    };
    // Only Starting -> Failed is valid here. Every call site before
    // run_lifecycle releases its startup gate is safe by construction
    // (phase_state is provably still Starting -- stop_sandbox/delete_sandbox
    // can't touch the entry until the gate opens). The one call site after
    // the gate is released (the control-channel launch-failure path) is not:
    // a concurrent stop/delete may have already moved this sandbox past
    // Starting while this lifecycle was still waiting on target-readiness,
    // and overwriting that final state with a stale Failed -- or emitting a
    // Failed event for an already-Stopped sandbox -- would be wrong
    // (MR !98 review thread).
    if entry.phase_state != PhaseState::Starting {
        return;
    }
    entry.sandbox = failed.clone();
    entry.phase_state = PhaseState::Failed(message.to_string());
    drop(reg);
    let _ = watch_tx.send(sandbox_event(failed));
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_sandbox_with_condition(
    base: &DriverSandbox,
    condition: &DriverCondition,
    deleting: bool,
) -> DriverSandbox {
    DriverSandbox {
        id: base.id.clone(),
        name: base.name.clone(),
        namespace: base.namespace.clone(),
        workspace: base.workspace.clone(),
        spec: base.spec.clone(),
        status: Some(DriverSandboxStatus {
            sandbox_name: base.name.clone(),
            instance_id: String::new(),
            agent_fd: String::new(),
            sandbox_fd: String::new(),
            conditions: vec![condition.clone()],
            deleting,
        }),
    }
}

// ── Lifecycle + policy-proof tests (mock wxc-exec) ─────────────────────────────
//
// These drive the full create → provision → start → exec → self-report Ready
// flow against the in-process mock shim, proving the positive (in-policy write
// succeeds, Ready reached) and negative (out-of-policy write denied + denial
// event) paths WITHOUT the demo box. Windows-only (the crate is Windows-gated),
// run by the `windows:test:x64` mise lane.
#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use futures::StreamExt;
    use openshell_core::proto::compute::v1::{DriverSandboxSpec, DriverSandboxTemplate};
    use openshell_core::proto::{
        FilesystemPolicy, MiddlewareEndpointSelector, NetworkBinary, NetworkEndpoint,
        NetworkMiddlewareConfig, NetworkPolicyRule, SandboxPolicy, StaticCredentialBinding,
        StaticCredentialEndpointBinding, UiClipboardAccess, UiPolicy,
    };
    use std::time::Duration;

    fn driver_sandbox(id: &str) -> DriverSandbox {
        let shell =
            std::env::var("COMSPEC").unwrap_or_else(|_| r"C:\Windows\System32\cmd.exe".to_string());
        driver_sandbox_with_command(id, "", vec![shell, "/c".into(), "exit 0".into()])
    }

    #[tokio::test]
    async fn termination_confirmation_rejects_closed_unconfirmed_channel() {
        let (tx, mut rx) = watch::channel(false);
        drop(tx);
        assert!(!wait_for_termination(&mut rx).await);
    }

    #[tokio::test]
    async fn termination_confirmation_accepts_confirmed_exit() {
        let (tx, mut rx) = watch::channel(false);
        tx.send(true).unwrap();
        drop(tx);
        assert!(wait_for_termination(&mut rx).await);
    }

    #[test]
    fn ui_policy_capability_tracks_configured_backend() {
        let process_container = MxcComputeBackend::new_mocked(MxcComputeConfig::default());
        assert!(process_container.capabilities().supports_ui_policy);

        let isolation_session = MxcComputeBackend::new_mocked(MxcComputeConfig {
            backend: MxcBackend::IsolationSession,
            ..Default::default()
        });
        assert!(!isolation_session.capabilities().supports_ui_policy);
    }

    fn driver_sandbox_with_command(id: &str, cwd: &str, command: Vec<String>) -> DriverSandbox {
        let serde_json::Value::Object(driver_config) = serde_json::json!({
            "command": command,
            "cwd": cwd,
        }) else {
            unreachable!();
        };
        DriverSandbox {
            id: id.to_string(),
            name: id.to_string(),
            namespace: String::new(),
            workspace: String::new(),
            spec: Some(DriverSandboxSpec {
                sandbox_token: "test-token".into(),
                template: Some(DriverSandboxTemplate {
                    driver_config: Some(
                        openshell_core::proto_struct::json_object_to_struct(driver_config).unwrap(),
                    ),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            status: None,
        }
    }
    fn fs_policy(read_write: &[&str]) -> SandboxPolicy {
        SandboxPolicy {
            filesystem: Some(FilesystemPolicy {
                include_workdir: false,
                read_only: Vec::new(),
                read_write: read_write.iter().map(ToString::to_string).collect(),
            }),
            ..Default::default()
        }
    }

    fn long_running_command(share: &str) -> (String, Vec<String>) {
        let shell =
            std::env::var("COMSPEC").unwrap_or_else(|_| r"C:\Windows\System32\cmd.exe".to_string());
        let command = vec![
            shell.clone(),
            "/d".into(),
            "/s".into(),
            "/c".into(),
            format!(r#"cd /d "{share}" && ping -n 61 127.0.0.1 >nul"#),
        ];
        (shell, command)
    }

    fn github_provider_credentials() -> ProviderCredentialState {
        ProviderCredentialState::from_bound_environment(
            42,
            HashMap::from([(
                "GITHUB_TOKEN".to_string(),
                "raw-test-token-must-not-enter-mxc".to_string(),
            )]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "GITHUB_TOKEN".to_string(),
                StaticCredentialBinding {
                    endpoints: vec![StaticCredentialEndpointBinding {
                        host: "api.github.com".to_string(),
                        port: 443,
                        path: "/**".to_string(),
                    }],
                    credential_identity: "provider-github:GITHUB_TOKEN".to_string(),
                    workload_credential_handle: String::new(),
                },
            )]),
            Vec::new(),
        )
        .expect("valid GitHub provider credential state")
    }

    fn with_policy(mut sandbox: DriverSandbox, policy: SandboxPolicy) -> DriverSandbox {
        sandbox.spec.as_mut().unwrap().policy = Some(policy);
        sandbox
    }

    fn ready_condition(sb: &DriverSandbox) -> Option<DriverCondition> {
        sb.status
            .as_ref()?
            .conditions
            .iter()
            .find(|c| c.r#type == "Ready")
            .cloned()
    }

    /// Poll the backend registry until the predicate matches or the deadline hits.
    async fn wait_for<F>(
        backend: &MxcComputeBackend,
        name: &str,
        mut pred: F,
    ) -> Option<DriverSandbox>
    where
        F: FnMut(&DriverSandbox) -> bool,
    {
        for _ in 0..100 {
            if let Some(sandbox) = backend.get_sandbox(name).await
                && pred(&sandbox)
            {
                return Some(sandbox);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        None
    }

    #[test]
    fn mxc_config_defaults_to_default_deny_process_container() {
        let config = MxcComputeConfig::default();
        assert_eq!(config.backend, MxcBackend::ProcessContainer);
        assert!(!config.egress_proxy);
        assert!(config.egress_proxy_addr.is_empty());
    }

    #[test]
    fn gateway_config_rejects_per_sandbox_workload_fields() {
        for field in ["agent_command", "agent_cwd", "agent_env", "share_dir"] {
            let mut config = serde_json::Map::new();
            config.insert(field.to_string(), serde_json::json!([]));
            let error = serde_json::from_value::<MxcComputeConfig>(config.into())
                .expect_err("workload fields must not be accepted in gateway config");
            assert!(error.to_string().contains(field));
        }
    }

    #[test]
    fn sandbox_proxy_addr_uses_ephemeral_loopback_port() {
        let configured = "127.0.0.1:18080".parse().unwrap();
        let (addr, _reservation) = allocate_sandbox_proxy_addr(configured).unwrap();
        assert_eq!(addr.ip(), configured.ip());
        assert_ne!(addr.port(), 0);
    }

    #[test]
    fn governed_egress_rejects_non_loopback_and_isolation_session() {
        let mut config = MxcComputeConfig {
            egress_proxy: true,
            egress_proxy_addr: "10.0.0.1:18080".into(),
            ..Default::default()
        };
        assert!(
            configured_egress_addr(&config)
                .unwrap_err()
                .message()
                .contains("127.0.0.1")
        );

        config.egress_proxy_addr = "127.0.0.1:18080".into();
        config.backend = MxcBackend::IsolationSession;
        let error = configured_egress_addr(&config).unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(error.message().contains("requires process_container"));
    }

    #[test]
    fn provider_child_environment_overrides_agent_values_with_placeholders() {
        let credentials = github_provider_credentials();
        let placeholder = credentials
            .snapshot()
            .child_env
            .get("GITHUB_TOKEN")
            .cloned()
            .expect("GitHub placeholder");
        let mut env = vec![
            "github_token=agent-value".to_string(),
            "UNCHANGED=value".to_string(),
        ];

        append_provider_child_env(&mut env, Some(&credentials));

        assert!(env.contains(&"UNCHANGED=value".to_string()));
        assert!(!env.iter().any(|entry| entry == "github_token=agent-value"));
        assert!(env.contains(&format!("GITHUB_TOKEN={placeholder}")));
        assert!(!env.iter().any(|entry| entry.contains("raw-test-token")));
    }

    #[test]
    fn provider_child_env_keys_reject_case_insensitive_collision() {
        let credentials = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([
                ("github_token".to_string(), "a".to_string()),
                ("GITHUB_TOKEN".to_string(), "b".to_string()),
            ]),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            vec!["github_token".to_string(), "GITHUB_TOKEN".to_string()],
        )
        .expect("valid provider credential state");

        let error = validate_provider_child_env_keys(Some(&credentials))
            .expect_err("case-colliding provider keys must fail closed");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("collides"));
    }

    #[test]
    fn provider_child_env_keys_reject_tls_reserved_name() {
        let credentials = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([("SSL_CERT_FILE".to_string(), "not-a-ca-bundle".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            vec!["SSL_CERT_FILE".to_string()],
        )
        .expect("valid provider credential state");

        let error = validate_provider_child_env_keys(Some(&credentials))
            .expect_err("TLS-reserved provider keys must fail closed");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("reserved for TLS"));
    }

    #[test]
    fn provider_child_env_keys_allow_distinct_names() {
        let credentials = github_provider_credentials();
        validate_provider_child_env_keys(Some(&credentials))
            .expect("non-colliding, non-reserved provider keys are allowed");
    }

    #[tokio::test]
    async fn provider_state_requiring_resolution_fails_closed_without_governed_egress() {
        let backend = MxcComputeBackend::new_mocked(MxcComputeConfig::default());
        let sink = backend.provider_credentials_sink();
        sink.lock()
            .expect("provider credential staging lock poisoned")
            .insert(
                "sb-provider-no-proxy".to_string(),
                github_provider_credentials(),
            );

        let error = backend
            .create_sandbox(&with_policy(
                driver_sandbox("sb-provider-no-proxy"),
                fs_policy(&[]),
            ))
            .await
            .expect_err("provider credentials must require governed egress");

        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("enable egress_proxy"));
        assert!(
            sink.lock()
                .expect("provider credential staging lock poisoned")
                .is_empty(),
            "the driver must consume staged credential material on every create attempt"
        );
    }

    #[tokio::test]
    async fn governed_egress_puts_only_provider_placeholder_in_mxc_process_env() {
        let mut config = MxcComputeConfig {
            egress_proxy: true,
            egress_proxy_addr: "127.0.0.1:18080".to_string(),
            ..Default::default()
        };
        config.backend = MxcBackend::ProcessContainer;
        let backend = MxcComputeBackend::new_mocked(config);
        let credentials = github_provider_credentials();
        let placeholder = credentials
            .snapshot()
            .child_env
            .get("GITHUB_TOKEN")
            .cloned()
            .expect("GitHub placeholder");
        backend
            .provider_credentials_sink()
            .lock()
            .expect("provider credential staging lock poisoned")
            .insert("sb-provider-env".to_string(), credentials);

        let shell =
            std::env::var("COMSPEC").unwrap_or_else(|_| r"C:\Windows\System32\cmd.exe".to_string());
        let mut policy = fs_policy(&[]);
        policy.network_policies.insert(
            "github".to_string(),
            NetworkPolicyRule {
                name: "github".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "api.github.com".to_string(),
                    port: 443,
                    protocol: "rest".to_string(),
                    enforcement: "enforce".to_string(),
                    access: "full".to_string(),
                    provider_credentialed: true,
                    ..Default::default()
                }],
                binaries: vec![NetworkBinary { path: shell }],
            },
        );
        let mut sandbox = with_policy(driver_sandbox("sb-provider-env"), policy);
        sandbox
            .spec
            .as_mut()
            .expect("sandbox spec")
            .environment
            .extend([
                (
                    "GITHUB_TOKEN".to_string(),
                    "raw-agent-env-token".to_string(),
                ),
                ("UNCHANGED".to_string(), "value".to_string()),
            ]);

        backend
            .create_sandbox(&sandbox)
            .await
            .expect("create accepted");
        let recorded = wait_for(&backend, "sb-provider-env", |_| {
            crate::mxc::mock_recorded_config("sb-provider-env").is_some()
        })
        .await;
        assert!(
            recorded.is_some(),
            "MXC config should be recorded; sandbox: {:#?}",
            backend.get_sandbox("sb-provider-env").await
        );

        let recorded =
            crate::mxc::mock_recorded_config("sb-provider-env").expect("mock recorded config");
        let env = recorded["process"]["env"]
            .as_array()
            .expect("MXC process env")
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>();
        assert!(env.contains(&"UNCHANGED=value"));
        assert!(env.contains(&format!("GITHUB_TOKEN={placeholder}").as_str()));
        let encoded = recorded.to_string();
        assert!(!encoded.contains("raw-agent-env-token"));
        assert!(!encoded.contains("raw-test-token-must-not-enter-mxc"));
    }

    #[test]
    fn tls_state_replaces_user_trust_overrides_and_grants_ca_directory_once() {
        let tls_dir = std::env::temp_dir().join("openshell-mxc-tls-test");
        let ca_cert = tls_dir.join("openshell-ca.pem");
        let bundle = tls_dir.join("ca-bundle.pem");
        let mut env = vec![
            "FOO=bar".to_string(),
            "SSL_CERT_FILE=C:\\old\\bundle.pem".to_string(),
        ];
        append_tls_env_vars(&mut env, Some(&(ca_cert.clone(), bundle.clone())));
        assert!(env.contains(&"FOO=bar".to_string()));
        assert!(
            !env.iter()
                .any(|entry| entry == "SSL_CERT_FILE=C:\\old\\bundle.pem")
        );
        assert!(env.contains(&format!("SSL_CERT_FILE={}", bundle.display())));

        let existing = tls_dir.display().to_string().to_ascii_lowercase();
        let mut readonly = vec![existing.clone()];
        append_tls_readonly_grant(&mut readonly, Some(&(ca_cert, bundle)));
        assert_eq!(readonly, vec![existing]);
    }

    #[test]
    fn tls_ca_files_are_staged_under_the_authorized_share() {
        let source = tempfile::tempdir().unwrap();
        let share = tempfile::tempdir().unwrap();
        let ca = source.path().join("source-ca.pem");
        let bundle = source.path().join("source-bundle.pem");
        std::fs::write(&ca, b"ca").unwrap();
        std::fs::write(&bundle, b"bundle").unwrap();

        let staged = stage_tls_ca_files(
            Some(&(ca, bundle)),
            share.path().to_str().expect("UTF-8 test path"),
            "sandbox-a",
        )
        .unwrap()
        .expect("staged paths");

        assert_eq!(
            staged.0.parent().unwrap(),
            share.path().join(".openshell-proxy").join("sandbox-a")
        );
        assert_eq!(std::fs::read(staged.0).unwrap(), b"ca");
        assert_eq!(std::fs::read(staged.1).unwrap(), b"bundle");
    }

    #[test]
    fn tls_ca_staging_keeps_sandboxes_in_the_same_share_independent() {
        let source = tempfile::tempdir().unwrap();
        let share = tempfile::tempdir().unwrap();
        let paths = (
            source.path().join("ca.pem"),
            source.path().join("bundle.pem"),
        );
        std::fs::write(&paths.0, b"first-ca").unwrap();
        std::fs::write(&paths.1, b"first-bundle").unwrap();
        let first = stage_tls_ca_files(Some(&paths), share.path().to_str().unwrap(), "sandbox-a")
            .unwrap()
            .unwrap();
        std::fs::write(&paths.0, b"second-ca").unwrap();
        std::fs::write(&paths.1, b"second-bundle").unwrap();
        let second = stage_tls_ca_files(Some(&paths), share.path().to_str().unwrap(), "sandbox-b")
            .unwrap()
            .unwrap();

        assert_ne!(first, second);
        assert_eq!(std::fs::read(first.0).unwrap(), b"first-ca");
        assert_eq!(std::fs::read(first.1).unwrap(), b"first-bundle");
        assert_eq!(std::fs::read(second.0).unwrap(), b"second-ca");
        assert_eq!(std::fs::read(second.1).unwrap(), b"second-bundle");
    }

    #[test]
    fn tls_ca_staging_rejects_empty_shares_and_unsafe_sandbox_components() {
        let share = tempfile::tempdir().unwrap();
        let paths = (PathBuf::from("unused-ca"), PathBuf::from("unused-bundle"));
        for empty in ["", "  ", "\t"] {
            assert_eq!(
                stage_tls_ca_files(Some(&paths), empty, "sandbox-a")
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::InvalidInput
            );
        }
        for id in [
            "",
            ".",
            "..",
            "../outside",
            "..\\outside",
            "C:\\outside",
            "file:stream",
        ] {
            assert_eq!(
                stage_tls_ca_files(Some(&paths), share.path().to_str().unwrap(), id)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::InvalidInput
            );
        }
        assert_eq!(std::fs::read_dir(share.path()).unwrap().count(), 0);
        assert_eq!(stage_tls_ca_files(None, "", "").unwrap(), None);
    }

    #[test]
    fn proxy_env_replaces_inherited_values_and_clears_bypass_rules() {
        let mut env = vec![
            "PATH=C:\\Windows".to_owned(),
            "HTTP_PROXY=http://stale.invalid:1".to_owned(),
            "https_proxy=http://stale.invalid:2".to_owned(),
            "NO_PROXY=example.com".to_owned(),
            "no_proxy=example.org".to_owned(),
        ];

        let proxy_auth = SandboxProxyAuth {
            password: "sandbox-secret".to_owned(),
        };
        append_proxy_env_vars(
            &mut env,
            Some("127.0.0.1:18080".parse().unwrap()),
            Some(&proxy_auth),
        );

        assert!(env.contains(&"PATH=C:\\Windows".to_owned()));
        for key in PROXY_ENV_KEYS {
            assert_eq!(
                env.iter()
                    .filter(|entry| entry.starts_with(&format!("{key}=")))
                    .count(),
                1,
                "{key} must be emitted exactly once"
            );
        }
        assert!(
            env.contains(&"HTTP_PROXY=http://openshell:sandbox-secret@127.0.0.1:18080".to_owned())
        );
        assert!(
            env.contains(&"HTTPS_PROXY=http://openshell:sandbox-secret@127.0.0.1:18080".to_owned())
        );
        assert!(env.contains(&"NO_PROXY=".to_owned()));
        assert!(env.contains(&"no_proxy=".to_owned()));
    }

    #[test]
    fn sandbox_environment_uses_sandbox_scope_with_spec_precedence() {
        let mut sandbox = driver_sandbox("sb-env");
        let spec = sandbox.spec.as_mut().unwrap();
        spec.template
            .as_mut()
            .unwrap()
            .environment
            .insert("SHARED".into(), "template".into());
        spec.environment.insert("SHARED".into(), "spec".into());
        spec.environment.insert("TOKEN".into(), "value".into());
        let environment = sandbox_environment(&sandbox);
        assert!(environment.contains(&"SHARED=spec".to_string()));
        assert!(environment.contains(&"TOKEN=value".to_string()));
        assert!(environment.iter().all(|entry| {
            let key = entry.split_once('=').map_or(entry.as_str(), |(key, _)| key);
            key == "SHARED" || key == "TOKEN"
        }));
    }

    #[test]
    fn tls_env_vars_replace_user_trust_overrides() {
        let tls_dir = std::env::temp_dir().join("openshell-mxc-tls-test");
        let ca_cert = tls_dir.join("openshell-ca.pem");
        let bundle = tls_dir.join("ca-bundle.pem");
        let ca_cert_path = ca_cert.display().to_string();
        let bundle_path = bundle.display().to_string();
        let mut env = vec![
            "FOO=bar".to_string(),
            "SSL_CERT_FILE=C:\\old\\bundle.pem".to_string(),
            "node_extra_ca_certs=C:\\old\\ca.pem".to_string(),
        ];

        append_tls_env_vars(&mut env, Some(&(ca_cert, bundle)));

        assert!(env.contains(&"FOO=bar".to_string()));
        assert!(
            !env.iter()
                .any(|entry| entry == "SSL_CERT_FILE=C:\\old\\bundle.pem")
        );
        assert!(
            !env.iter()
                .any(|entry| entry == "node_extra_ca_certs=C:\\old\\ca.pem")
        );
        assert!(env.contains(&format!("NODE_EXTRA_CA_CERTS={ca_cert_path}")));
        assert!(env.contains(&format!("DENO_CERT={ca_cert_path}")));
        assert!(env.contains(&format!("SSL_CERT_FILE={bundle_path}")));
        assert!(env.contains(&format!("REQUESTS_CA_BUNDLE={bundle_path}")));
        assert!(env.contains(&format!("CURL_CA_BUNDLE={bundle_path}")));
        assert!(env.contains(&format!("GIT_SSL_CAINFO={bundle_path}")));
    }

    #[test]
    fn tls_readwrite_grant_adds_ca_directory_once() {
        let tls_dir = std::env::temp_dir().join("openshell-mxc-tls-test");
        let ca_cert = tls_dir.join("openshell-ca.pem");
        let bundle = tls_dir.join("ca-bundle.pem");
        let existing = tls_dir.display().to_string().to_ascii_lowercase();
        let mut readwrite = vec![existing.clone()];

        append_tls_readwrite_grant(&mut readwrite, Some(&(ca_cert, bundle)));

        assert_eq!(readwrite, vec![existing]);
    }

    #[test]
    fn windows_command_line_preserves_argument_boundaries() {
        assert_eq!(
            encode_windows_command_line(&[
                r"C:\Program Files\Agent\agent.exe".into(),
                "hello world".into(),
                String::new(),
            ]),
            r#""C:\Program Files\Agent\agent.exe" "hello world" """#
        );
        assert_eq!(
            quote_windows_argument(r#"say "hello""#),
            r#""say \"hello\"""#
        );
        assert_eq!(
            quote_windows_argument("trailing slash\\ "),
            r#""trailing slash\ ""#
        );
        assert_eq!(
            encode_windows_command_line(&[
                r"C:\Windows\System32\CMD.EXE".into(),
                "/d".into(),
                "/c".into(),
                r#"echo hello > "C:\work dir\output.txt""#.into(),
            ]),
            r#"C:\Windows\System32\CMD.EXE /d /c echo hello > "C:\work dir\output.txt""#
        );
    }
    #[tokio::test]
    async fn positive_in_policy_write_reaches_ready_and_materializes_file() {
        let tmp = tempfile::tempdir().unwrap();
        let share = tmp.path().to_string_lossy().replace('\\', "/");
        let hello = format!("{share}/hello.txt");
        let cmd = vec![
            "powershell".into(),
            "-NoProfile".into(),
            "-Command".into(),
            format!("Set-Content -LiteralPath {hello} -Value hi"),
        ];
        let backend = MxcComputeBackend::new_mocked(MxcComputeConfig::default());

        let policy = fs_policy(&[&share]);
        let sb = with_policy(driver_sandbox_with_command("sb-pos", &share, cmd), policy);
        backend.create_sandbox(&sb).await.expect("create accepted");

        // Self-reported Ready=True (no supervisor) once the agent exec launches.
        let ready = wait_for(&backend, "sb-pos", |s| {
            ready_condition(s).is_some_and(|c| c.status == "True" && c.reason == "AgentRunning")
        })
        .await;
        assert!(ready.is_some(), "sandbox should self-report Ready=True");

        // Positive proof: the in-policy write materializes the host artifact.
        let host_path = tmp.path().join("hello.txt");
        let mut found = false;
        for _ in 0..100 {
            if host_path.exists() {
                found = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(found, "hello.txt should appear in the granted share folder");

        // A successful one-shot agent (exit 0) must STAY Ready, not demote to
        // Error. Assert the terminal condition is Ready=True/AgentCompleted so the
        // positive demo shows a green Ready phase, not a red Error.
        let completed = wait_for(&backend, "sb-pos", |s| {
            ready_condition(s).is_some_and(|c| c.status == "True" && c.reason == "AgentCompleted")
        })
        .await;
        assert!(
            completed.is_some(),
            "sandbox should remain Ready=True (AgentCompleted) after a successful exec, never demote to Error"
        );
        assert!(
            !backend
                .attribution
                .lock()
                .unwrap()
                .has_live_pid_for_sandbox("sb-pos"),
            "the process monitor must retire the wxc-exec PID before publishing completion"
        );
    }

    #[tokio::test]
    async fn processcontainer_one_shot_in_policy_write_reaches_ready() {
        // The processContainer backend skips provision/start and runs a single
        // one-shot. The mock routes through `run_oneshot`, deriving grants from
        // the filesystem (not a provision step), so the in-policy write should
        // materialize and the sandbox should reach Ready=True.
        let tmp = tempfile::tempdir().unwrap();
        let share = tmp.path().to_string_lossy().replace('\\', "/");
        let hello = format!("{share}/hello.txt");
        let cmd = vec![
            "powershell".into(),
            "-NoProfile".into(),
            "-Command".into(),
            format!("Set-Content -LiteralPath {hello} -Value hi"),
        ];
        let backend = MxcComputeBackend::new_mocked(MxcComputeConfig::default());

        let policy = fs_policy(&[&share]);
        let sb = with_policy(driver_sandbox_with_command("sb-pc", &share, cmd), policy);
        backend.create_sandbox(&sb).await.expect("create accepted");

        let ready = wait_for(&backend, "sb-pc", |s| {
            ready_condition(s).is_some_and(|c| c.status == "True" && c.reason == "AgentRunning")
        })
        .await;
        assert!(
            ready.is_some(),
            "processContainer sandbox should self-report Ready=True"
        );
        let recorded = crate::mxc::mock_recorded_config("sb-pc").expect("mock recorded config");
        assert!(
            recorded.get("network").is_none(),
            "coarse path must not emit an MXC network block"
        );
        assert_eq!(recorded["ui"]["disable"], true);
        assert_eq!(recorded["ui"]["clipboard"], "none");
        assert_eq!(recorded["ui"]["injection"], false);

        let host_path = tmp.path().join("hello.txt");
        let mut found = false;
        for _ in 0..100 {
            if host_path.exists() {
                found = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            found,
            "in-policy write should materialize under processContainer"
        );
    }

    #[tokio::test]
    async fn explicit_network_policies_start_and_cleanup_host_proxy() {
        for (sandbox_id, host, pc_network_allow) in [
            ("sb-egress-allow", "example.com", false),
            ("sb-egress-no-match", "allowed.invalid", true),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let share = tmp.path().to_string_lossy().replace('\\', "/");
            let (shell, command) = long_running_command(&share);
            let config = MxcComputeConfig {
                backend: MxcBackend::ProcessContainer,
                pc_network_allow,
                egress_proxy: true,
                egress_proxy_addr: "127.0.0.1:18080".into(),
                ..Default::default()
            };
            let backend = MxcComputeBackend::new_mocked(config);

            let mut policy = fs_policy(&[&share]);
            policy.network_policies.insert(
                "explicit".into(),
                NetworkPolicyRule {
                    name: "explicit".into(),
                    endpoints: vec![NetworkEndpoint {
                        host: host.into(),
                        ports: vec![443],
                        protocol: "tcp".into(),
                        ..Default::default()
                    }],
                    binaries: vec![NetworkBinary { path: shell }],
                },
            );
            let sandbox = with_policy(
                driver_sandbox_with_command(sandbox_id, &share, command),
                policy.clone(),
            );

            backend
                .create_sandbox(&sandbox)
                .await
                .expect("create accepted");
            wait_for(&backend, sandbox_id, |sandbox| {
                ready_condition(sandbox).is_some_and(|condition| condition.reason == "AgentRunning")
            })
            .await
            .expect("explicit network policy sandbox should reach Ready=True");

            let recorded =
                crate::mxc::mock_recorded_config(sandbox_id).expect("mock recorded config");
            assert_eq!(recorded["network"]["egress"]["default"], "deny");
            assert_eq!(
                recorded["network"]["egress"]["allow"],
                serde_json::json!([{"to": [{"cidr": "127.0.0.1/32"}]}])
            );
            assert!(recorded["network"].get("proxy").is_none());

            let proxy_addr = {
                let registry = backend.registry.lock().await;
                let entry = registry.get(sandbox_id).expect("registry entry");
                assert!(
                    entry.host_proxy.is_some(),
                    "{sandbox_id}: governed egress must hold a live host proxy"
                );
                assert_eq!(
                    entry.trimmed_policy.as_ref().unwrap().network_policies,
                    policy.network_policies
                );
                entry.proxy_addr.expect("proxy address")
            };
            tokio::time::timeout(
                Duration::from_secs(2),
                tokio::net::TcpStream::connect(proxy_addr),
            )
            .await
            .expect("proxy listener connect timed out")
            .expect("proxy listener must accept connections");

            let child_env = recorded["process"]["env"].as_array().expect("child env");
            let proxy_env = child_env
                .iter()
                .filter_map(serde_json::Value::as_str)
                .find_map(|entry| entry.strip_prefix("HTTP_PROXY="))
                .expect("HTTP_PROXY must direct clients to the authenticated proxy");
            let (credentials, address) = proxy_env
                .strip_prefix("http://openshell:")
                .and_then(|value| value.split_once('@'))
                .expect("proxy URL must contain the per-sandbox credential");
            assert!(!credentials.is_empty());
            assert_eq!(address, proxy_addr.to_string());

            backend
                .stop_sandbox(sandbox_id)
                .await
                .expect("stop should clean up the governed egress proxy");
            assert!(
                backend
                    .registry
                    .lock()
                    .await
                    .get(sandbox_id)
                    .is_some_and(|entry| entry.host_proxy.is_none()),
                "{sandbox_id}: stop must drop the host proxy handle"
            );
            assert!(
                backend
                    .delete_sandbox(&sandbox.id, &sandbox.name)
                    .await
                    .expect("delete after stop"),
                "sandbox should be removed"
            );
        }
    }

    #[tokio::test]
    async fn empty_network_policy_does_not_activate_host_proxy() {
        let tmp = tempfile::tempdir().unwrap();
        let share = tmp.path().to_string_lossy().replace('\\', "/");
        let (_shell, command) = long_running_command(&share);
        let backend = MxcComputeBackend::new_mocked(MxcComputeConfig {
            backend: MxcBackend::ProcessContainer,
            egress_proxy: true,
            egress_proxy_addr: "127.0.0.1:18080".into(),
            ..Default::default()
        });
        let sandbox = with_policy(
            driver_sandbox_with_command("sb-egress-default", &share, command),
            fs_policy(&[&share]),
        );

        backend
            .create_sandbox(&sandbox)
            .await
            .expect("create accepted");
        wait_for(&backend, &sandbox.name, |sandbox| {
            ready_condition(sandbox).is_some_and(|condition| condition.reason == "AgentRunning")
        })
        .await
        .expect("default-policy sandbox should reach Ready=True");

        let recorded = crate::mxc::mock_recorded_config(&sandbox.id).expect("mock recorded config");
        let registry = backend.registry.lock().await;
        let entry = registry.get(&sandbox.id).expect("registry entry");
        assert!(entry.proxy_addr.is_none());
        assert!(entry.host_proxy.is_none());
        assert!(entry.trimmed_policy.is_none());
        drop(registry);
        assert!(recorded.get("network").is_none());
        assert!(
            recorded["process"]["env"]
                .as_array()
                .expect("child env")
                .iter()
                .filter_map(serde_json::Value::as_str)
                .all(|entry| !PROXY_ENV_KEYS.iter().any(|key| {
                    entry
                        .split_once('=')
                        .is_some_and(|(entry_key, _)| entry_key.eq_ignore_ascii_case(key))
                }))
        );

        backend.stop_sandbox(&sandbox.name).await.expect("stop");
        assert!(
            backend
                .delete_sandbox(&sandbox.id, &sandbox.name)
                .await
                .expect("delete after stop")
        );
    }

    #[test]
    fn empty_network_policy_rejects_unrestricted_fallback() {
        let backend = MxcComputeBackend::new_mocked(MxcComputeConfig {
            backend: MxcBackend::ProcessContainer,
            pc_network_allow: true,
            egress_proxy: true,
            egress_proxy_addr: "127.0.0.1:18080".into(),
            ..Default::default()
        });
        let sandbox = with_policy(
            driver_sandbox("sb-egress-unrestricted-fallback"),
            fs_policy(&[]),
        );

        let error = backend
            .validate_sandbox_create(&sandbox)
            .expect_err("mixed egress configuration must fail closed without network rules");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(error.message().contains("egress_proxy"));
        assert!(error.message().contains("pc_network_allow"));
        assert!(error.message().contains("unrestricted egress fallback"));
    }

    #[tokio::test]
    async fn processcontainer_live_config_carries_explicit_ui_policy() {
        let backend = MxcComputeBackend::new_mocked(MxcComputeConfig::default());
        let mut policy = fs_policy(&[]);
        policy.ui = Some(UiPolicy {
            allow_graphical_ui: true,
            clipboard: UiClipboardAccess::All as i32,
            allow_input_injection: true,
        });
        let sandbox = with_policy(driver_sandbox("sb-pc-ui"), policy);
        backend
            .create_sandbox(&sandbox)
            .await
            .expect("create accepted");
        let _ = wait_for(&backend, "sb-pc-ui", |_| {
            crate::mxc::mock_recorded_config("sb-pc-ui").is_some()
        })
        .await;
        let recorded = crate::mxc::mock_recorded_config("sb-pc-ui")
            .expect("mock recorded processContainer config");
        assert_eq!(recorded["ui"]["disable"], false);
        assert_eq!(recorded["ui"]["clipboard"], "all");
        assert_eq!(recorded["ui"]["injection"], true);
    }

    #[tokio::test]
    async fn isolation_session_rejects_ui_before_lifecycle_side_effects() {
        let backend = MxcComputeBackend::new_mocked(MxcComputeConfig {
            backend: MxcBackend::IsolationSession,
            ..Default::default()
        });
        let policy = SandboxPolicy {
            ui: Some(UiPolicy::default()),
            ..Default::default()
        };
        let sandbox = with_policy(driver_sandbox("sb-iso-ui"), policy);
        let error = backend
            .create_sandbox(&sandbox)
            .await
            .expect_err("isolation UI must be rejected synchronously");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(error.message().contains("ui"));
        assert!(backend.list_sandboxes().await.is_empty());
        assert!(crate::mxc::mock_recorded_config("sb-iso-ui").is_none());
    }

    #[tokio::test]
    async fn negative_out_of_policy_write_is_denied_with_event() {
        let share_tmp = tempfile::tempdir().unwrap();
        let out_tmp = tempfile::tempdir().unwrap();
        let share = share_tmp.path().to_string_lossy().replace('\\', "/");
        let out_path = format!(
            "{}/hello.txt",
            out_tmp.path().to_string_lossy().replace('\\', "/")
        );
        let cmd = vec![
            "powershell".into(),
            "-NoProfile".into(),
            "-Command".into(),
            format!("Set-Content -LiteralPath {out_path} -Value hi"),
        ];
        let backend = MxcComputeBackend::new_mocked(MxcComputeConfig::default());

        // Subscribe to the watch stream BEFORE create so we catch the denial event.
        let mut stream = backend.watch_sandboxes().await;

        let policy = fs_policy(&[&share]);
        let sandbox = with_policy(driver_sandbox_with_command("sb-neg", &share, cmd), policy);
        backend
            .create_sandbox(&sandbox)
            .await
            .expect("create accepted");

        // Collect events until we observe the AgentExecFailed platform event.
        let mut saw_denial = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(500), stream.next()).await {
                Ok(Some(Ok(ev))) => {
                    if let Some(watch_sandboxes_event::Payload::PlatformEvent(event)) = ev.payload
                        && event
                            .event
                            .as_ref()
                            .is_some_and(|event| event.reason == "AgentExecFailed")
                    {
                        saw_denial = true;
                        break;
                    }
                }
                Ok(_) => break,
                Err(_) => {}
            }
        }
        assert!(
            saw_denial,
            "expected an AgentExecFailed denial platform event"
        );

        // The out-of-policy artifact must NOT have been written by the mock.
        let out_fs = out_tmp.path().join("hello.txt");
        assert!(!out_fs.exists(), "out-of-policy write must be denied");

        // And the sandbox surfaces a terminal ExecFailed Ready=False condition.
        let failed = wait_for(&backend, "sb-neg", |s| {
            ready_condition(s).is_some_and(|c| c.status == "False" && c.reason == "ExecFailed")
        })
        .await;
        assert!(failed.is_some(), "sandbox should report ExecFailed");
    }

    #[tokio::test]
    async fn stop_terminates_and_reaps_a_running_process_container() {
        let tmp = tempfile::tempdir().unwrap();
        let share = tmp.path().to_string_lossy().replace('\\', "/");
        let command = vec![
            "powershell".into(),
            "-NoProfile".into(),
            "-Command".into(),
            format!("$null = '{share}'; Start-Sleep -Seconds 60"),
        ];
        let backend = MxcComputeBackend::new_mocked(MxcComputeConfig::default());
        let policy = fs_policy(&[&share]);
        let sandbox = with_policy(driver_sandbox_with_command("sb-stop", "", command), policy);
        backend
            .create_sandbox(&sandbox)
            .await
            .expect("create accepted");
        wait_for(&backend, "sb-stop", |sandbox| {
            ready_condition(sandbox).is_some_and(|condition| condition.reason == "AgentRunning")
        })
        .await
        .expect("long-running child should start");
        tokio::time::sleep(Duration::from_millis(250)).await;
        let running = backend.get_sandbox("sb-stop").await.unwrap();
        assert_eq!(ready_condition(&running).unwrap().reason, "AgentRunning");

        tokio::time::timeout(Duration::from_secs(5), backend.stop_sandbox("sb-stop"))
            .await
            .expect("stop should not wait for the child sleep")
            .expect("stop should terminate and reap the child");
        let stopped = backend.get_sandbox("sb-stop").await.unwrap();
        assert_eq!(ready_condition(&stopped).unwrap().reason, "Stopped");
    }

    /// `delete_sandbox` must await *confirmed* `ProcessContainer` termination
    /// before removing the registry entry and reporting success -- not just
    /// fire the kill signal and report success regardless (which could
    /// leave the process retaining ports and file locks past a successful
    /// delete). Bounded well under the child's own sleep duration: if
    /// delete stopped awaiting `terminated_rx`, this would still return
    /// quickly (the bug was reporting success *too early*, not hanging), so
    /// the meaningful assertion is that the sandbox is confirmed gone from
    /// the registry immediately after -- a second delete finds nothing.
    #[tokio::test]
    async fn delete_terminates_and_reaps_a_running_process_container() {
        let tmp = tempfile::tempdir().unwrap();
        let share = tmp.path().to_string_lossy().replace('\\', "/");
        let command = vec![
            "powershell".into(),
            "-NoProfile".into(),
            "-Command".into(),
            format!("$null = '{share}'; Start-Sleep -Seconds 60"),
        ];
        let backend = MxcComputeBackend::new_mocked(MxcComputeConfig::default());
        let policy = fs_policy(&[&share]);
        let sandbox = with_policy(
            driver_sandbox_with_command("sb-delete", "", command),
            policy,
        );
        backend
            .create_sandbox(&sandbox)
            .await
            .expect("create accepted");
        wait_for(&backend, "sb-delete", |sandbox| {
            ready_condition(sandbox).is_some_and(|condition| condition.reason == "AgentRunning")
        })
        .await
        .expect("long-running child should start");
        tokio::time::sleep(Duration::from_millis(250)).await;

        let deleted = tokio::time::timeout(
            Duration::from_secs(5),
            backend.delete_sandbox(&sandbox.id, "sb-delete"),
        )
        .await
        .expect("delete should not wait for the child sleep")
        .expect("delete should terminate and reap the child");
        assert!(deleted, "delete should report the sandbox as removed");
        assert!(
            backend.get_sandbox("sb-delete").await.is_none(),
            "sandbox should be gone from the registry after delete"
        );
    }

    /// `delete_sandbox` must confirm genuine termination via `terminated_rx`
    /// even when `shutdown_tx` was already consumed by an earlier attempt (a
    /// timed-out delete/stop, or -- as constructed directly here -- any
    /// other caller that got to the field first). `terminated_rx` must
    /// therefore be `.clone()`d, not `.take()`n, from the registry entry:
    /// taking it would make this call's own None-shutdown_tx branch skip
    /// the wait entirely and report success (and remove the registry entry)
    /// before termination was ever confirmed -- exactly the MR !98 review
    /// thread this regression-tests ("delete timeout loses termination
    /// state").
    #[tokio::test]
    async fn delete_confirms_termination_even_when_shutdown_tx_already_taken() {
        let tmp = tempfile::tempdir().unwrap();
        let share = tmp.path().to_string_lossy().replace('\\', "/");
        let command = vec![
            "powershell".into(),
            "-NoProfile".into(),
            "-Command".into(),
            format!("$null = '{share}'; Start-Sleep -Seconds 60"),
        ];
        let backend = MxcComputeBackend::new_mocked(MxcComputeConfig::default());
        let policy = fs_policy(&[&share]);
        let sandbox = with_policy(
            driver_sandbox_with_command("sb-delete-retry", "", command),
            policy,
        );
        backend
            .create_sandbox(&sandbox)
            .await
            .expect("create accepted");
        wait_for(&backend, "sb-delete-retry", |sandbox| {
            ready_condition(sandbox).is_some_and(|condition| condition.reason == "AgentRunning")
        })
        .await
        .expect("long-running child should start");
        tokio::time::sleep(Duration::from_millis(250)).await;

        // Simulate an earlier delete/stop attempt that already consumed and
        // fired shutdown_tx (e.g. one that then timed out before
        // confirming termination) -- take a fresh watch subscription first
        // so this test can observe the SAME completion delete_sandbox
        // itself must wait for.
        let terminated = {
            let registry = backend.registry.lock().await;
            registry
                .get(&sandbox.id)
                .expect("sandbox should be registered")
                .terminated_rx
                .clone()
                .expect("ProcessContainer entry should have terminated_rx wired")
        };
        {
            let mut registry = backend.registry.lock().await;
            let entry = registry
                .get_mut(&sandbox.id)
                .expect("sandbox should be registered");
            let tx = entry
                .shutdown_tx
                .take()
                .expect("ProcessContainer entry should have shutdown_tx wired");
            let _ = tx.send(());
        }

        let deleted = tokio::time::timeout(
            Duration::from_secs(5),
            backend.delete_sandbox(&sandbox.id, "sb-delete-retry"),
        )
        .await
        .expect("delete should still confirm termination within the timeout, not hang")
        .expect("delete should succeed even with shutdown_tx already taken");
        assert!(deleted, "delete should report the sandbox as removed");

        // The regression this guards against: delete_sandbox used to
        // .take() terminated_rx too, so finding shutdown_tx already None
        // made it skip waiting entirely and return success immediately --
        // well before the real OS process had actually been killed and
        // reaped. If that bug were back, this watch value could still be
        // false right here.
        assert!(
            *terminated.borrow(),
            "delete_sandbox must not report success before terminated_rx confirms the process died"
        );
        assert!(
            backend.get_sandbox("sb-delete-retry").await.is_none(),
            "sandbox should be gone from the registry after delete"
        );
    }

    #[tokio::test]
    async fn unmappable_network_policy_fails_create_lifecycle() {
        use openshell_core::proto::{NetworkEndpoint, NetworkPolicyRule};
        let tmp = tempfile::tempdir().unwrap();
        let share = tmp.path().to_string_lossy().replace('\\', "/");

        let backend = MxcComputeBackend::new_mocked(MxcComputeConfig::default());

        let mut policy = fs_policy(&[&share]);
        policy.network_policies.insert(
            "api".into(),
            NetworkPolicyRule {
                name: "api".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "example.com".into(),
                    ..Default::default()
                }],
                binaries: Vec::new(),
            },
        );
        let sandbox = with_policy(driver_sandbox("sb-net"), policy);
        let error = backend
            .create_sandbox(&sandbox)
            .await
            .expect_err("unmappable policy must fail CreateSandbox synchronously");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(backend.get_sandbox("sb-net").await.is_none());
    }

    #[tokio::test]
    async fn governed_egress_rejects_network_middleware_before_lifecycle() {
        let config = MxcComputeConfig {
            egress_proxy: true,
            egress_proxy_addr: "127.0.0.1:18080".into(),
            ..Default::default()
        };
        let backend = MxcComputeBackend::new_mocked(config);

        let mut policy = fs_policy(&[]);
        policy.network_middlewares.insert(
            "redactor".into(),
            NetworkMiddlewareConfig {
                name: "redactor".into(),
                middleware: "openshell/regex".into(),
                on_error: "fail_closed".into(),
                endpoints: Some(MiddlewareEndpointSelector {
                    include: vec!["api.example.com".into()],
                    exclude: Vec::new(),
                }),
                ..Default::default()
            },
        );
        let sandbox = with_policy(driver_sandbox("sb-middleware"), policy);

        let error = backend.create_sandbox(&sandbox).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(error.message().contains("network_middlewares"));
        assert!(backend.get_sandbox("sb-middleware").await.is_none());
    }
}
