// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! MXC compute backend: lifecycle logic, in-memory registry, exec-in-driver,
//! and self-reported readiness.

use crate::mxc::{MxcFilesystem, MxcProcess, MxcProcessContainer, WxcExecInvoker};
use crate::policy::{EmbeddedPolicyMapper, MapCtx, MappedConfig, PolicyMapper};
use futures::Stream;
use openshell_core::gpu::{driver_gpu_requirements, effective_driver_gpu_count};
use openshell_core::proto::SandboxPolicy;
use openshell_core::proto::compute::v1::{
    DriverCondition, DriverPlatformEvent, DriverSandbox, DriverSandboxStatus,
    GetCapabilitiesResponse, WatchSandboxesDeletedEvent, WatchSandboxesEvent,
    WatchSandboxesPlatformEvent, WatchSandboxesSandboxEvent, watch_sandboxes_event,
};
use openshell_core::proto_struct::struct_to_json_value;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{Mutex, broadcast, mpsc, watch};
use tokio::task::JoinHandle;
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

/// Configuration for the MXC compute driver.
///
/// Loaded from `[openshell.drivers.mxc]` in the gateway TOML file, or from
/// environment variables / CLI flags via the standard gateway precedence chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MxcComputeConfig {
    /// Path to `wxc-exec.exe`. Required for live runs.
    pub wxc_exec_path: String,
    /// Backend to target. Default: `process_container`.
    pub backend: MxcBackend,
    /// `processContainer` only: request a Less-Privileged `AppContainer`.
    pub pc_least_privilege: bool,
    /// `processContainer` only: `AppContainer` capabilities to grant.
    pub pc_capabilities: Vec<String>,
    /// MXC `configurationId` for isolation session. Default: `"composable"`.
    /// Never use `"small"` (known OS bug).
    pub default_configuration_id: String,

    /// Enable `--debug` flag on `wxc-exec` invocations.
    pub debug: bool,
}

impl Default for MxcComputeConfig {
    fn default() -> Self {
        Self {
            wxc_exec_path: "wxc-exec.exe".into(),
            backend: MxcBackend::default(),
            pc_least_privilege: false,
            pc_capabilities: Vec::new(),
            default_configuration_id: crate::mxc::DEFAULT_CONFIGURATION_ID.into(),

            debug: false,
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
    /// Serializes stop/delete with provisioning and process launch.
    lifecycle_gate: Arc<Mutex<()>>,
    monitor_cancel: Option<watch::Sender<bool>>,
    monitor_task: Option<JoinHandle<()>>,
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
    let Some(spec) = sandbox.spec.as_ref() else {
        return Vec::new();
    };
    let mut environment = spec
        .template
        .as_ref()
        .map_or_else(HashMap::new, |template| template.environment.clone());
    environment.extend(spec.environment.clone());
    let mut environment = environment
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>();
    environment.sort_unstable();
    environment
}

fn encode_windows_command_line(args: &[String]) -> String {
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
impl MxcComputeBackend {
    pub fn new(config: MxcComputeConfig) -> Self {
        let invoker = WxcExecInvoker::new(&config.wxc_exec_path, config.debug);
        let (watch_tx, _) = broadcast::channel(256);
        Self {
            invoker,
            config,
            registry: Arc::new(Mutex::new(HashMap::new())),
            watch_tx: Arc::new(watch_tx),
            // Production policy translation is always handled by the embedded
            // mapper before any MXC lifecycle side effects begin.
            policy_mapper: Arc::new(EmbeddedPolicyMapper),
        }
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
        }
    }

    fn validate_sandbox_fields(&self, sandbox: &DriverSandbox) -> Result<(), tonic::Status> {
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
    ) -> Result<MappedConfig, tonic::Status> {
        self.policy_mapper
            .map(
                policy,
                &MapCtx {
                    sandbox_id: sandbox_id.to_string(),
                    egress: None,
                },
            )
            .map_err(|error| tonic::Status::invalid_argument(error.to_string()))
    }

    pub fn validate_sandbox_create(&self, sandbox: &DriverSandbox) -> Result<(), tonic::Status> {
        self.validate_sandbox_fields(sandbox)?;
        let policy = sandbox.spec.as_ref().and_then(|spec| spec.policy.as_ref());
        self.map_sandbox_policy(&sandbox.id, policy)?;
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

        self.validate_sandbox_fields(sandbox)?;
        let sandbox_config = sandbox_config(sandbox)?;

        // Policy translation is deterministic and side-effect free. Do it before
        // inserting the registry entry or launching MXC so invalid requests fail
        // synchronously at the CreateSandbox boundary.
        let policy = sandbox.spec.as_ref().and_then(|spec| spec.policy.as_ref());
        let mapped = self.map_sandbox_policy(&sandbox_id, policy)?;

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
                    monitor_cancel: None,
                    monitor_task: None,
                },
            );
        }

        let invoker = self.invoker.clone();
        let config = self.config.clone();
        let registry = self.registry.clone();
        let watch_tx = self.watch_tx.clone();
        let sandbox = sandbox.clone();
        tokio::spawn(async move {
            run_lifecycle(
                invoker,
                config,
                registry,
                watch_tx,
                sandbox,
                sandbox_config,
                mapped,
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

        let _lifecycle_guard = lifecycle_gate.lock().await;
        let (iso_id, mut isolation_stopped, cancel, monitor_task) = {
            let mut registry = self.registry.lock().await;
            let entry = registry.get_mut(&sandbox_id).ok_or_else(|| {
                tonic::Status::not_found(format!("sandbox {sandbox_name} not found"))
            })?;
            (
                entry.iso_sandbox_id.clone(),
                entry.isolation_stopped,
                entry.monitor_cancel.take(),
                entry.monitor_task.take(),
            )
        };
        if let Some(cancel) = cancel {
            let _ = cancel.send(true);
        }
        if let Some(task) = monitor_task {
            task.await.map_err(|error| {
                tonic::Status::internal(format!("mxc process monitor failed: {error}"))
            })?;
        }
        if let Some(ref iso_id) = iso_id
            && !isolation_stopped
        {
            self.invoker.stop(iso_id).await.map_err(|error| {
                tonic::Status::internal(format!("wxc-exec stop failed: {error}"))
            })?;
            isolation_stopped = true;
        }

        let mut registry = self.registry.lock().await;
        if let Some(entry) = registry.get_mut(&sandbox_id) {
            entry.isolation_stopped = isolation_stopped;
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

        let _lifecycle_guard = lifecycle_gate.lock().await;
        let (iso_id, isolation_stopped, cancel, monitor_task) = {
            let mut registry = self.registry.lock().await;
            let Some(entry) = registry.get_mut(sandbox_id) else {
                return Ok(false);
            };
            (
                entry.iso_sandbox_id.clone(),
                entry.isolation_stopped,
                entry.monitor_cancel.take(),
                entry.monitor_task.take(),
            )
        };
        if let Some(cancel) = cancel {
            let _ = cancel.send(true);
        }
        if let Some(task) = monitor_task {
            task.await.map_err(|error| {
                tonic::Status::internal(format!("mxc process monitor failed: {error}"))
            })?;
        }
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
        }

        let mut registry = self.registry.lock().await;
        if registry.remove(sandbox_id).is_some() {
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

// ── Lifecycle task ────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn run_lifecycle(
    invoker: WxcExecInvoker,
    config: MxcComputeConfig,
    registry: Arc<Mutex<HashMap<String, SandboxEntry>>>,
    watch_tx: Arc<broadcast::Sender<WatchSandboxesEvent>>,
    sandbox: DriverSandbox,
    sandbox_config: MxcSandboxConfig,
    mapped: MappedConfig,
    _startup_guard: tokio::sync::OwnedMutexGuard<()>,
) {
    let sandbox_id = sandbox.id.clone();
    let sandbox_name = sandbox.name.clone();
    let filesystem = MxcFilesystem {
        readwrite_paths: mapped.readwrite_paths,
        readonly_paths: mapped.readonly_paths,
        // OpenShell's policy model has no explicit deny field; default-deny is
        // implicit and enforced by processContainer at the OS boundary.
        denied_paths: Vec::new(),
    };
    let command_line = encode_windows_command_line(&sandbox_config.command);
    let process = MxcProcess {
        command_line: command_line.clone(),
        cwd: sandbox_config.cwd,
        env: sandbox_environment(&sandbox),
        timeout: 0,
    };

    let child = match config.backend {
        MxcBackend::IsolationSession => {
            let iso_sandbox_id = match invoker
                .provision(&config.default_configuration_id, filesystem, None)
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
            match invoker
                .run_oneshot(&sandbox_id, filesystem, process_container, process, None)
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
    let (cancel_tx, cancel_rx) = watch::channel(false);
    {
        // Publish cancellation state before the monitor can observe a fast
        // process exit. Holding the registry lock while spawning prevents a
        // completed child from being overwritten with AgentRunning.
        let mut registry_guard = registry.lock().await;
        if let Some(entry) = registry_guard.get_mut(&sandbox_id) {
            entry.sandbox = ready_sandbox.clone();
            entry.phase_state = PhaseState::Running;
            entry.monitor_cancel = Some(cancel_tx);
            entry.monitor_task = Some(tokio::spawn(monitor_exec(
                registry.clone(),
                watch_tx.clone(),
                sandbox.clone(),
                sandbox_id.clone(),
                cancel_rx,
                child,
            )));
        }
    }
    let _ = watch_tx.send(sandbox_event(ready_sandbox));
}

async fn monitor_exec(
    registry: Arc<Mutex<HashMap<String, SandboxEntry>>>,
    watch_tx: Arc<broadcast::Sender<WatchSandboxesEvent>>,
    sandbox: DriverSandbox,
    sandbox_id: String,
    mut cancel_rx: watch::Receiver<bool>,
    mut child: tokio::process::Child,
) {
    let status = tokio::select! {
        status = child.wait() => status,
        changed = cancel_rx.changed() => {
            let should_kill = changed.is_ok() && *cancel_rx.borrow_and_update();
            if should_kill {
                if let Err(error) = child.kill().await {
                    warn!(sandbox = %sandbox.name, error = %error, "failed to terminate MXC agent process");
                }
                // `kill` waits on current Tokio releases, but an explicit wait is
                // harmless and guarantees the OS process handle is reaped.
                let _ = child.wait().await;
            }
            return;
        }
    };

    match status {
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
    if let Some(entry) = reg.get_mut(sandbox_id) {
        entry.sandbox = failed.clone();
        entry.phase_state = PhaseState::Failed(message.to_string());
    }
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
    use openshell_core::proto::{FilesystemPolicy, SandboxPolicy};
    use std::time::Duration;

    fn driver_sandbox(id: &str) -> DriverSandbox {
        driver_sandbox_with_command(id, "", vec!["cmd".into(), "/c".into(), "exit 0".into()])
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
        assert_eq!(
            MxcComputeConfig::default().backend,
            MxcBackend::ProcessContainer
        );
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
        assert_eq!(
            sandbox_environment(&sandbox),
            vec!["SHARED=spec".to_string(), "TOKEN=value".to_string()]
        );
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
        let host_path = std::path::Path::new(tmp.path()).join("hello.txt");
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

        let host_path = std::path::Path::new(tmp.path()).join("hello.txt");
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
        let out_fs = std::path::Path::new(out_tmp.path()).join("hello.txt");
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
}
