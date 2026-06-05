// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! MXC compute backend: lifecycle logic, in-memory registry, exec-in-driver,
//! and self-reported readiness.

use crate::mxc::{MxcFilesystem, MxcProcess, WxcExecInvoker};
use crate::policy::{MapCtx, PolicyMapper, StubPolicyMapper};
use openshell_core::proto::compute::v1::{
    DriverCondition, DriverPlatformEvent, DriverSandbox, DriverSandboxStatus,
    GetCapabilitiesResponse, WatchSandboxesDeletedEvent, WatchSandboxesEvent,
    WatchSandboxesPlatformEvent, WatchSandboxesSandboxEvent, watch_sandboxes_event,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use tokio::process::Child;
use futures::Stream;
use tokio::sync::{Mutex, broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{info, warn};

const DRIVER_NAME: &str = "mxc";
const DRIVER_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Sentinel image name — MXC has no OCI image; this string must be non-empty
/// so the gateway's `default_image` cache is satisfied, but it is not pullable.
const DEFAULT_IMAGE_SENTINEL: &str = "mxc:isolation-session";

// ── Config ────────────────────────────────────────────────────────────────────

/// Configuration for the MXC compute driver.
///
/// Loaded from `[openshell.drivers.mxc]` in the gateway TOML file, or from
/// environment variables / CLI flags via the standard gateway precedence chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MxcComputeConfig {
    /// Path to `wxc-exec.exe`. Required for live runs.
    pub wxc_exec_path: String,
    /// MXC `configurationId` for isolation session. Default: `"composable"`.
    /// Never use `"small"` (known OS bug).
    pub default_configuration_id: String,
    /// Agent command executed inside the sandbox (exec-in-driver).
    /// For the June 15 demo this writes `hello.txt`; a follow-up skill
    /// swaps in a richer agent. Must be non-empty for `CreateSandbox` to
    /// succeed.
    pub agent_command: Vec<String>,
    /// Working directory for the agent command inside the sandbox.
    pub agent_cwd: String,
    /// Host directory mapped into the sandbox as a read-write grant.
    /// Appears in the shared host folder for the positive-proof artifact.
    pub share_dir: String,
    /// Enable `--debug` flag on `wxc-exec` invocations.
    pub debug: bool,
}

impl Default for MxcComputeConfig {
    fn default() -> Self {
        Self {
            wxc_exec_path: "wxc-exec.exe".into(),
            default_configuration_id: crate::mxc::DEFAULT_CONFIGURATION_ID.into(),
            agent_command: Vec::new(),
            agent_cwd: String::new(),
            share_dir: String::new(),
            debug: false,
        }
    }
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
    phase_state: PhaseState,
    exec_child: Option<Child>,
}

impl std::fmt::Debug for SandboxEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxEntry")
            .field("sandbox_id", &self.sandbox.id)
            .field("iso_sandbox_id", &self.iso_sandbox_id)
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

impl MxcComputeBackend {
    pub fn new(config: MxcComputeConfig) -> Self {
        let invoker = WxcExecInvoker::new(&config.wxc_exec_path, config.debug);
        let (watch_tx, _) = broadcast::channel(256);
        Self {
            invoker,
            config,
            registry: Arc::new(Mutex::new(HashMap::new())),
            watch_tx: Arc::new(watch_tx),
            policy_mapper: Arc::new(StubPolicyMapper),
        }
    }

    pub fn capabilities(&self) -> GetCapabilitiesResponse {
        openshell_core::driver_utils::build_capabilities_response(
            DRIVER_NAME,
            DRIVER_VERSION,
            DEFAULT_IMAGE_SENTINEL,
            false,
        )
    }

    pub fn validate_sandbox_create(&self, sandbox: &DriverSandbox) -> Result<(), tonic::Status> {
        if let Some(spec) = &sandbox.spec {
            if spec.gpu {
                return Err(tonic::Status::invalid_argument(
                    "mxc driver does not support GPU sandboxes",
                ));
            }
            if let Some(tmpl) = &spec.template {
                if !tmpl.agent_socket_path.is_empty() {
                    return Err(tonic::Status::invalid_argument(
                        "mxc driver does not support agent_socket_path (no in-sandbox supervisor)",
                    ));
                }
            }
        }
        if self.config.agent_command.is_empty() {
            return Err(tonic::Status::invalid_argument(
                "mxc driver: agent_command is required in [openshell.drivers.mxc]",
            ));
        }
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
        self.validate_sandbox_create(sandbox)?;

        if sandbox
            .spec
            .as_ref()
            .map_or(true, |s| s.sandbox_token.is_empty())
        {
            return Err(tonic::Status::invalid_argument("sandbox_token is required"));
        }

        let sandbox_id = sandbox.id.clone();
        let sandbox_name = sandbox.name.clone();

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
                    phase_state: PhaseState::Starting,
                    exec_child: None,
                },
            );
        }

        let invoker = self.invoker.clone();
        let config = self.config.clone();
        let registry = self.registry.clone();
        let watch_tx = self.watch_tx.clone();
        let policy_mapper = self.policy_mapper.clone();
        let sandbox = sandbox.clone();

        tokio::spawn(async move {
            run_lifecycle(invoker, config, policy_mapper, registry, watch_tx, sandbox).await;
        });

        Ok(())
    }

    pub async fn stop_sandbox(&self, sandbox_name: &str) -> Result<(), tonic::Status> {
        let (iso_id, sandbox_id) = {
            let registry = self.registry.lock().await;
            let entry = registry
                .values()
                .find(|e| e.sandbox.name == sandbox_name)
                .ok_or_else(|| {
                    tonic::Status::not_found(format!("sandbox {sandbox_name} not found"))
                })?;
            (entry.iso_sandbox_id.clone(), entry.sandbox.id.clone())
        };

        if let Some(ref iso_id) = iso_id {
            if let Err(e) = self.invoker.stop(iso_id).await {
                warn!(sandbox = %sandbox_name, error = %e, "wxc-exec stop failed");
            }
        }

        let watch_tx = self.watch_tx.clone();
        let mut registry = self.registry.lock().await;
        if let Some(entry) = registry.get_mut(&sandbox_id) {
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
            let _ = watch_tx.send(sandbox_event(snapshot));
        }
        Ok(())
    }

    pub async fn delete_sandbox(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<bool, tonic::Status> {
        let iso_id = {
            let registry = self.registry.lock().await;
            registry
                .get(sandbox_id)
                .and_then(|e| e.iso_sandbox_id.clone())
        };

        if let Some(iso_id) = iso_id {
            let _ = self.invoker.stop(&iso_id).await;
            if let Err(e) = self.invoker.deprovision(&iso_id).await {
                warn!(sandbox = %sandbox_name, error = %e, "wxc-exec deprovision failed");
            }
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
        let (tx, rx) = mpsc::channel::<Result<WatchSandboxesEvent, openshell_core::ComputeDriverError>>(256);

        // Send initial snapshots before subscribing so we don't miss live events.
        let snapshots: Vec<DriverSandbox> = {
            let registry = self.registry.lock().await;
            registry.values().map(|e| e.sandbox.clone()).collect()
        };
        let mut broadcast_rx = self.watch_tx.subscribe();

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
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        Box::pin(ReceiverStream::new(rx))
    }
}

// ── Lifecycle task ────────────────────────────────────────────────────────────

async fn run_lifecycle(
    invoker: WxcExecInvoker,
    config: MxcComputeConfig,
    policy_mapper: Arc<dyn PolicyMapper>,
    registry: Arc<Mutex<HashMap<String, SandboxEntry>>>,
    watch_tx: Arc<broadcast::Sender<WatchSandboxesEvent>>,
    sandbox: DriverSandbox,
) {
    let sandbox_id = sandbox.id.clone();
    let sandbox_name = sandbox.name.clone();

    // 1. Map policy → MXC filesystem config.
    let map_ctx = MapCtx {
        sandbox_id: sandbox_id.clone(),
        share_dir: if config.share_dir.is_empty() {
            None
        } else {
            Some(config.share_dir.clone())
        },
    };
    let mapped = match policy_mapper.map(&map_ctx) {
        Ok(m) => m,
        Err(e) => {
            set_failed(&registry, &watch_tx, &sandbox, &sandbox_id, &e.to_string()).await;
            return;
        }
    };

    // 2. Provision.
    let filesystem = MxcFilesystem {
        readwrite_paths: mapped.readwrite_paths,
        readonly_paths: mapped.readonly_paths,
    };
    let iso_sandbox_id = match invoker
        .provision(&config.default_configuration_id, filesystem)
        .await
    {
        Ok(id) => id,
        Err(e) => {
            set_failed(&registry, &watch_tx, &sandbox, &sandbox_id, &e.to_string()).await;
            return;
        }
    };
    info!(sandbox = %sandbox_name, iso_id = %iso_sandbox_id, "MXC provisioned");

    {
        let mut reg = registry.lock().await;
        if let Some(entry) = reg.get_mut(&sandbox_id) {
            entry.iso_sandbox_id = Some(iso_sandbox_id.clone());
        }
    }

    // 3. Start.
    if let Err(e) = invoker.start(&iso_sandbox_id).await {
        set_failed(&registry, &watch_tx, &sandbox, &sandbox_id, &e.to_string()).await;
        return;
    }
    info!(sandbox = %sandbox_name, "MXC started");

    // 4. Exec agent command — spawn (don't await).
    let command_line = config.agent_command.join(" ");
    let cwd = if config.agent_cwd.is_empty() {
        config.share_dir.clone()
    } else {
        config.agent_cwd.clone()
    };
    let process = MxcProcess {
        command_line: command_line.clone(),
        cwd,
        env: Vec::new(),
        timeout: 0,
    };
    let child = match invoker.spawn_exec(&iso_sandbox_id, process).await {
        Ok(c) => c,
        Err(e) => {
            set_failed(&registry, &watch_tx, &sandbox, &sandbox_id, &e.to_string()).await;
            return;
        }
    };
    info!(sandbox = %sandbox_name, command = %command_line, "MXC agent exec launched");

    // 5. Self-report Ready=True.
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
        if let Some(entry) = reg.get_mut(&sandbox_id) {
            entry.sandbox = ready_sandbox.clone();
            entry.phase_state = PhaseState::Running;
            entry.exec_child = Some(child);
        }
    }
    let _ = watch_tx.send(sandbox_event(ready_sandbox));

    // 6. Monitor exec completion in background.
    let registry2 = registry.clone();
    let watch_tx2 = watch_tx.clone();
    let sandbox2 = sandbox.clone();
    let sandbox_id2 = sandbox_id.clone();
    tokio::spawn(async move {
        monitor_exec(registry2, watch_tx2, sandbox2, sandbox_id2).await;
    });
}

async fn monitor_exec(
    registry: Arc<Mutex<HashMap<String, SandboxEntry>>>,
    watch_tx: Arc<broadcast::Sender<WatchSandboxesEvent>>,
    sandbox: DriverSandbox,
    sandbox_id: String,
) {
    let child = {
        let mut reg = registry.lock().await;
        reg.get_mut(&sandbox_id).and_then(|e| e.exec_child.take())
    };
    let Some(mut child) = child else {
        return;
    };

    match child.wait().await {
        Ok(status) if status.success() => {
            info!(sandbox = %sandbox.name, "MXC agent exec completed successfully");
            let done = make_sandbox_with_condition(
                &sandbox,
                &DriverCondition {
                    r#type: "Ready".into(),
                    status: "False".into(),
                    reason: "ExecCompleted".into(),
                    message: "Agent exec finished with exit code 0".into(),
                    last_transition_time: String::new(),
                },
                false,
            );
            let mut reg = registry.lock().await;
            if let Some(entry) = reg.get_mut(&sandbox_id) {
                entry.sandbox = done.clone();
                entry.phase_state = PhaseState::Stopped;
            }
            drop(reg);
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
            let mut reg = registry.lock().await;
            if let Some(entry) = reg.get_mut(&sandbox_id) {
                entry.sandbox = failed.clone();
                entry.phase_state = PhaseState::Failed(format!("exit code {code}"));
            }
            drop(reg);
            let _ = watch_tx.send(sandbox_event(failed));
        }
        Err(e) => {
            warn!(sandbox = %sandbox.name, error = %e, "MXC agent exec wait error");
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
