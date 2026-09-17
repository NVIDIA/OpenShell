// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! MXC compute backend using the RFC 0012 supervisor/sandbox architecture.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

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
use openshell_sandbox_backend::boundary_protocol::{
    GatewayVerificationKey, SandboxTlsClientConfig, SandboxTlsServerConfig,
    generate_sandbox_tls_material,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt as _, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, broadcast, mpsc, oneshot, watch};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{info, warn};

use crate::isolation::MxcBoundarySpec;
use crate::mxc::{MxcFilesystem, MxcNetwork, MxcProcess, MxcProcessContainer, WxcExecInvoker};
use crate::policy::{EmbeddedPolicyMapper, MapCtx, MappedConfig, PolicyMapper};

const DRIVER_NAME: &str = "mxc";
const DRIVER_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_IMAGE_SENTINEL: &str = "mxc:process-container";
const HOST_AUTH_BUNDLE_FILE: &str = "supervisor-auth.json";
const HOST_RUNTIME_DESCRIPTOR_FILE: &str = "runtime-descriptor.json";
const BOUNDARY_CONFIG_FILE: &str = "boundary.json";
const BOUNDARY_TLS_CERT_FILE: &str = "sandbox.crt";
const BOUNDARY_TLS_KEY_FILE: &str = "sandbox.key";
const DIRECT_PROXY_USERNAME: &str = "openshell";

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MxcComputeConfig {
    pub wxc_exec_path: String,
    pub supervisor_binary_path: String,
    pub sandbox_binary_path: String,
    pub state_dir: PathBuf,
    pub grpc_endpoint: String,
    pub backend: MxcBackend,
    pub pc_least_privilege: bool,
    pub pc_capabilities: Vec<String>,
    pub pc_allow_local_network: bool,
    pub pc_minimal_env: bool,
    pub debug: bool,
    pub etw_audit: bool,
}

impl Default for MxcComputeConfig {
    fn default() -> Self {
        let state_dir = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("OpenShell")
            .join("mxc");
        let executable_dir = std::env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(Path::to_path_buf));
        let sibling_binary = |name: &str| {
            executable_dir.as_ref().map_or_else(
                || name.to_string(),
                |dir| dir.join(name).display().to_string(),
            )
        };
        Self {
            wxc_exec_path: "wxc-exec.exe".into(),
            supervisor_binary_path: sibling_binary("openshell-supervisor.exe"),
            sandbox_binary_path: sibling_binary("openshell-sandbox.exe"),
            state_dir,
            grpc_endpoint: String::new(),
            backend: MxcBackend::ProcessContainer,
            pc_least_privilege: false,
            pc_capabilities: Vec::new(),
            pc_allow_local_network: true,
            pc_minimal_env: false,
            debug: false,
            etw_audit: false,
        }
    }
}

#[derive(Debug, Clone)]
struct GatewayConnection {
    endpoint: String,
    tls: Option<(PathBuf, PathBuf, PathBuf)>,
    tls_server_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MxcSandboxConfig {
    command: Vec<String>,
    #[serde(default)]
    cwd: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhaseState {
    Starting,
    Running,
    Stopped,
    Failed(String),
}

struct SandboxEntry {
    sandbox: DriverSandbox,
    phase_state: PhaseState,
    lifecycle_gate: Arc<Mutex<()>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    terminated_rx: Option<watch::Receiver<bool>>,
    host_state_dir: PathBuf,
    boundary_state_dir: PathBuf,
}

pub type WatchStream = Pin<
    Box<dyn Stream<Item = Result<WatchSandboxesEvent, openshell_core::ComputeDriverError>> + Send>,
>;

pub struct MxcComputeBackend {
    config: MxcComputeConfig,
    gateway: GatewayConnection,
    invoker: WxcExecInvoker,
    registry: Arc<Mutex<HashMap<String, SandboxEntry>>>,
    watch_tx: Arc<broadcast::Sender<WatchSandboxesEvent>>,
    policy_mapper: Arc<dyn PolicyMapper>,
    #[allow(dead_code)]
    etw_session: Option<crate::etw_consumer::EtwSession>,
    attribution: Arc<std::sync::Mutex<crate::etw_consumer::AttributionIndex>>,
}

impl std::fmt::Debug for MxcComputeBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MxcComputeBackend")
            .field("wxc_exec_path", &self.config.wxc_exec_path)
            .field(
                "supervisor_binary_path",
                &self.config.supervisor_binary_path,
            )
            .field("sandbox_binary_path", &self.config.sandbox_binary_path)
            .finish_non_exhaustive()
    }
}

impl MxcComputeBackend {
    pub fn new(config: MxcComputeConfig) -> Self {
        let endpoint = config.grpc_endpoint.clone();
        Self::new_with_gateway(config, endpoint, None, None)
    }

    pub fn new_with_gateway(
        config: MxcComputeConfig,
        endpoint: String,
        tls: Option<(PathBuf, PathBuf, PathBuf)>,
        tls_server_name: Option<String>,
    ) -> Self {
        let invoker = WxcExecInvoker::new(&config.wxc_exec_path, config.debug);
        let (watch_tx, _) = broadcast::channel(256);
        let attribution = Arc::new(std::sync::Mutex::new(
            crate::etw_consumer::AttributionIndex::new(),
        ));
        let etw_session = if config.etw_audit {
            crate::etw_consumer::start_session(attribution.clone())
                .inspect_err(|error| warn!(%error, "MXC ETW audit consumer failed to start"))
                .ok()
        } else {
            None
        };
        Self {
            config,
            gateway: GatewayConnection {
                endpoint,
                tls,
                tls_server_name,
            },
            invoker,
            registry: Arc::new(Mutex::new(HashMap::new())),
            watch_tx: Arc::new(watch_tx),
            policy_mapper: Arc::new(EmbeddedPolicyMapper),
            etw_session,
            attribution,
        }
    }

    pub fn capabilities(&self) -> GetCapabilitiesResponse {
        GetCapabilitiesResponse {
            driver_name: DRIVER_NAME.to_string(),
            driver_version: DRIVER_VERSION.to_string(),
            default_image: DEFAULT_IMAGE_SENTINEL.to_string(),
            gateway_manages_lifecycle: false,
            supports_sandbox_authentication: false,
            driver_reports_runtime_readiness: false,
            resource_capabilities: None,
            rootfs_tar_staging_dir: String::new(),
            rootfs_tar_max_bytes: 0,
            supports_ui_policy: true,
        }
    }

    pub fn validate_sandbox_create(&self, sandbox: &DriverSandbox) -> Result<(), tonic::Status> {
        if self.config.backend != MxcBackend::ProcessContainer {
            return Err(tonic::Status::failed_precondition(
                "the RFC 0012 MXC runtime currently requires process_container",
            ));
        }
        if self.gateway.endpoint.trim().is_empty() {
            return Err(tonic::Status::failed_precondition(
                "mxc grpc_endpoint is required for the host supervisor",
            ));
        }
        if !self.invoker.is_mock()
            && (!Path::new(&self.config.supervisor_binary_path).is_file()
                || !Path::new(&self.config.sandbox_binary_path).is_file())
        {
            return Err(tonic::Status::failed_precondition(format!(
                "MXC requires supervisor and sandbox binaries at '{}' and '{}'",
                self.config.supervisor_binary_path, self.config.sandbox_binary_path
            )));
        }
        if let Some(spec) = &sandbox.spec
            && effective_driver_gpu_count(driver_gpu_requirements(
                spec.resource_requirements.as_ref(),
            ))
            .map_err(tonic::Status::invalid_argument)?
            .is_some()
        {
            return Err(tonic::Status::invalid_argument(
                "mxc driver does not support GPU sandboxes",
            ));
        }
        let config = sandbox_config(sandbox)?;
        if config.cwd.trim().is_empty() {
            return Err(tonic::Status::invalid_argument(
                "mxc driver_config.cwd is required for boundary staging",
            ));
        }
        if !Path::new(&config.cwd).is_absolute() {
            return Err(tonic::Status::invalid_argument(
                "mxc driver_config.cwd must be an absolute Windows path",
            ));
        }
        if !self.config.state_dir.is_absolute() {
            return Err(tonic::Status::failed_precondition(
                "mxc state_dir must be an absolute Windows path",
            ));
        }
        launch_authentication(sandbox)?
            .validate()
            .map_err(|error| tonic::Status::failed_precondition(error.to_string()))?;
        let policy = sandbox.spec.as_ref().and_then(|spec| spec.policy.as_ref());
        self.map_sandbox_policy(
            &sandbox.id,
            policy,
            "127.0.0.1:3128".parse().expect("fixed proxy address"),
        )?;
        Ok(())
    }

    fn map_sandbox_policy(
        &self,
        sandbox_id: &str,
        policy: Option<&SandboxPolicy>,
        proxy_addr: SocketAddr,
    ) -> Result<MappedConfig, tonic::Status> {
        self.policy_mapper
            .map(
                policy,
                &MapCtx {
                    sandbox_id: sandbox_id.to_string(),
                    egress: Some(proxy_addr),
                    containment: self.config.backend.containment().into(),
                },
            )
            .map_err(|error| tonic::Status::invalid_argument(error.to_string()))
    }

    pub async fn get_sandbox(&self, sandbox_name: &str) -> Option<DriverSandbox> {
        self.registry
            .lock()
            .await
            .values()
            .find(|entry| entry.sandbox.name == sandbox_name)
            .map(|entry| entry.sandbox.clone())
    }

    pub async fn list_sandboxes(&self) -> Vec<DriverSandbox> {
        self.registry
            .lock()
            .await
            .values()
            .map(|entry| entry.sandbox.clone())
            .collect()
    }

    pub async fn create_sandbox(&self, sandbox: &DriverSandbox) -> Result<(), tonic::Status> {
        self.validate_sandbox_create(sandbox)?;
        let sandbox_id = sandbox.id.clone();
        let sandbox_config = sandbox_config(sandbox)?;
        let generation = uuid::Uuid::new_v4().to_string();
        let host_state_dir = self
            .config
            .state_dir
            .join(safe_component(&sandbox_id)?)
            .join(&generation);
        let boundary_state_dir = PathBuf::from(&sandbox_config.cwd)
            .join(".openshell-runtime")
            .join(&generation);
        let gate = Arc::new(Mutex::new(()));
        let startup_guard = gate.clone().lock_owned().await;
        let starting = make_sandbox_with_condition(
            sandbox,
            &condition("Ready", "False", "Starting", "MXC runtime starting"),
            false,
        );
        {
            let mut registry = self.registry.lock().await;
            if registry.contains_key(&sandbox_id) {
                return Err(tonic::Status::already_exists(format!(
                    "sandbox {} already exists",
                    sandbox.name
                )));
            }
            registry.insert(
                sandbox_id.clone(),
                SandboxEntry {
                    sandbox: starting.clone(),
                    phase_state: PhaseState::Starting,
                    lifecycle_gate: gate,
                    shutdown_tx: None,
                    terminated_rx: None,
                    host_state_dir: host_state_dir.clone(),
                    boundary_state_dir: boundary_state_dir.clone(),
                },
            );
        }
        let _ = self.watch_tx.send(sandbox_event(starting));
        let context = LifecycleContext {
            invoker: self.invoker.clone(),
            config: self.config.clone(),
            gateway: self.gateway.clone(),
            registry: self.registry.clone(),
            watch_tx: self.watch_tx.clone(),
            attribution: self.attribution.clone(),
            sandbox: sandbox.clone(),
            sandbox_config,
            generation,
            host_state_dir,
            boundary_state_dir,
            policy_mapper: self.policy_mapper.clone(),
        };
        tokio::spawn(async move { run_lifecycle(context, startup_guard).await });
        Ok(())
    }

    pub async fn stop_sandbox(&self, sandbox_name: &str) -> Result<(), tonic::Status> {
        let (sandbox_id, gate) = {
            let registry = self.registry.lock().await;
            let entry = registry
                .values()
                .find(|entry| entry.sandbox.name == sandbox_name)
                .ok_or_else(|| {
                    tonic::Status::not_found(format!("sandbox {sandbox_name} not found"))
                })?;
            (entry.sandbox.id.clone(), entry.lifecycle_gate.clone())
        };
        let _guard = gate.lock().await;
        let (shutdown, terminated) = {
            let mut registry = self.registry.lock().await;
            let entry = registry.get_mut(&sandbox_id).ok_or_else(|| {
                tonic::Status::not_found(format!("sandbox {sandbox_name} not found"))
            })?;
            (entry.shutdown_tx.take(), entry.terminated_rx.clone())
        };
        if let Some(shutdown) = shutdown {
            let _ = shutdown.send(());
        }
        wait_for_termination(terminated, sandbox_name).await?;
        let mut registry = self.registry.lock().await;
        if let Some(entry) = registry.get_mut(&sandbox_id) {
            entry.phase_state = PhaseState::Stopped;
            entry.sandbox = make_sandbox_with_condition(
                &entry.sandbox,
                &condition("Ready", "False", "Stopped", "MXC sandbox stopped"),
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
        let gate = {
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
        let _guard = gate.lock().await;
        let (shutdown, terminated, host_state, boundary_state) = {
            let mut registry = self.registry.lock().await;
            let entry = registry.get_mut(sandbox_id).expect("entry checked above");
            (
                entry.shutdown_tx.take(),
                entry.terminated_rx.clone(),
                entry.host_state_dir.clone(),
                entry.boundary_state_dir.clone(),
            )
        };
        if let Some(shutdown) = shutdown {
            let _ = shutdown.send(());
        }
        wait_for_termination(terminated, sandbox_name).await?;
        cleanup_runtime_directory(&host_state);
        cleanup_runtime_directory(&boundary_state);
        let removed = self.registry.lock().await.remove(sandbox_id).is_some();
        if removed {
            if let Ok(mut attribution) = self.attribution.lock() {
                attribution.forget(sandbox_id);
            }
            let _ = self.watch_tx.send(deleted_event(sandbox_id.to_string()));
        }
        Ok(removed)
    }

    pub async fn watch_sandboxes(&self) -> WatchStream {
        let (tx, rx) = mpsc::channel(256);
        let (snapshots, mut updates) = {
            let registry = self.registry.lock().await;
            (
                registry
                    .values()
                    .map(|entry| entry.sandbox.clone())
                    .collect::<Vec<_>>(),
                self.watch_tx.subscribe(),
            )
        };
        tokio::spawn(async move {
            for sandbox in snapshots {
                if tx.send(Ok(sandbox_event(sandbox))).await.is_err() {
                    return;
                }
            }
            loop {
                match updates.recv().await {
                    Ok(event) => {
                        if tx.send(Ok(event)).await.is_err() {
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        });
        Box::pin(ReceiverStream::new(rx))
    }
}

#[derive(Clone)]
struct LifecycleContext {
    invoker: WxcExecInvoker,
    config: MxcComputeConfig,
    gateway: GatewayConnection,
    registry: Arc<Mutex<HashMap<String, SandboxEntry>>>,
    watch_tx: Arc<broadcast::Sender<WatchSandboxesEvent>>,
    attribution: Arc<std::sync::Mutex<crate::etw_consumer::AttributionIndex>>,
    sandbox: DriverSandbox,
    sandbox_config: MxcSandboxConfig,
    generation: String,
    host_state_dir: PathBuf,
    boundary_state_dir: PathBuf,
    policy_mapper: Arc<dyn PolicyMapper>,
}

async fn run_lifecycle(context: LifecycleContext, startup_guard: tokio::sync::OwnedMutexGuard<()>) {
    if let Err(error) = run_lifecycle_inner(&context, startup_guard).await {
        set_failed(&context, &error).await;
    }
}

async fn run_lifecycle_inner(
    context: &LifecycleContext,
    startup_guard: tokio::sync::OwnedMutexGuard<()>,
) -> Result<(), String> {
    create_restricted_state_dir(&context.host_state_dir, "host")?;
    // This directory briefly contains the boundary TLS private key and direct
    // proxy credential. Restrict host access before writing either secret;
    // MXC adds the ProcessContainer grant when it applies the read-write path.
    create_restricted_state_dir(&context.boundary_state_dir, "boundary")?;
    let launch = launch_authentication(&context.sandbox).map_err(|error| error.to_string())?;
    let (control_addr, control_reservation) = reserve_loopback_port()
        .map_err(|error| format!("reserve MXC Sandbox Protocol port: {error}"))?;
    let (proxy_addr, proxy_reservation) = reserve_loopback_port()
        .map_err(|error| format!("reserve MXC supervisor proxy port: {error}"))?;
    let mapped = context
        .policy_mapper
        .map(
            context
                .sandbox
                .spec
                .as_ref()
                .and_then(|spec| spec.policy.as_ref()),
            &MapCtx {
                sandbox_id: context.sandbox.id.clone(),
                egress: Some(proxy_addr),
                containment: MxcBackend::ProcessContainer.containment().to_string(),
            },
        )
        .map_err(|error| error.to_string())?;
    let tls = generate_sandbox_tls_material(launch.supervisor.session_id)
        .map_err(|error| error.to_string())?;
    let tls_cert_path = context.boundary_state_dir.join(BOUNDARY_TLS_CERT_FILE);
    let tls_key_path = context.boundary_state_dir.join(BOUNDARY_TLS_KEY_FILE);
    std::fs::write(&tls_cert_path, tls.certificate_chain_pem.as_bytes())
        .map_err(|error| format!("write MXC boundary TLS certificate: {error}"))?;
    std::fs::write(&tls_key_path, tls.private_key_pem.as_bytes())
        .map_err(|error| format!("write MXC boundary TLS private key: {error}"))?;
    let proxy_password =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let authorization = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD
            .encode(format!("{DIRECT_PROXY_USERNAME}:{proxy_password}"))
    );
    let proxy_url = format!("http://{DIRECT_PROXY_USERNAME}:{proxy_password}@{proxy_addr}");
    let verification_keys = launch
        .verification_keys
        .iter()
        .map(|key| {
            String::from_utf8(key.public_key_pem.clone())
                .map(|public_key_pem| GatewayVerificationKey {
                    key_id: key.key_id.clone(),
                    public_key_pem,
                })
                .map_err(|error| format!("MXC verification key is not UTF-8 PEM: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let provisioning = MxcBoundarySpec {
        boundary_id: context.sandbox.id.clone(),
        generation: context.generation.clone(),
        session_id: launch.supervisor.session_id,
        session_rotation: launch.supervisor.session_rotation,
        auth_epoch: launch.supervisor.auth_epoch,
        gateway_id: launch.gateway_id.clone(),
        verification_keys,
        control_addr,
        supervisor_tls: SandboxTlsClientConfig {
            server_name: tls.server_name,
            trust_anchor_pem: tls.trust_anchor_pem,
        },
        sandbox_tls: SandboxTlsServerConfig {
            certificate_chain_path: tls_cert_path,
            private_key_path: tls_key_path,
        },
        proxy_addr,
        proxy_authorization: authorization,
        proxy_url,
        workload_binary: resolve_workload_binary(&context.sandbox_config.command[0])?,
        child_env: sandbox_environment(&context.sandbox),
    }
    .provision()
    .map_err(|error| error.to_string())?;
    let boundary_config_path = context.boundary_state_dir.join(BOUNDARY_CONFIG_FILE);
    std::fs::write(
        &boundary_config_path,
        provisioning
            .boundary_config
            .encode()
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("write MXC boundary configuration: {error}"))?;
    let auth_bundle_path = context.host_state_dir.join(HOST_AUTH_BUNDLE_FILE);
    std::fs::write(
        &auth_bundle_path,
        serde_json::to_vec(&launch.supervisor)
            .map_err(|error| format!("encode MXC supervisor auth bundle: {error}"))?,
    )
    .map_err(|error| format!("write MXC supervisor auth bundle: {error}"))?;
    let descriptor_path = context.host_state_dir.join(HOST_RUNTIME_DESCRIPTOR_FILE);
    std::fs::write(
        &descriptor_path,
        provisioning
            .runtime_descriptor
            .backend_descriptor()
            .map_err(|error| error.to_string())?
            .payload,
    )
    .map_err(|error| format!("write MXC runtime descriptor: {error}"))?;
    // The supervisor owns the proxy listener. Release only that reservation
    // before spawning it; keep the Sandbox Protocol port reserved until the
    // ProcessContainer launch so unrelated local processes cannot squat it
    // during the more expensive host-side setup.
    drop(proxy_reservation);
    let mut supervisor = spawn_supervisor(context, &descriptor_path, &auth_bundle_path)?;
    let sandbox_command = encode_windows_command_line(&[
        context.config.sandbox_binary_path.clone(),
        "--bootstrap".to_string(),
        boundary_config_path.display().to_string(),
        "--log-level".to_string(),
        openshell_core::driver_utils::sandbox_log_level(&context.sandbox, "warn"),
    ]);
    let mut filesystem = MxcFilesystem {
        readwrite_paths: mapped.readwrite_paths,
        readonly_paths: mapped.readonly_paths,
        denied_paths: Vec::new(),
    };
    push_unique_path(
        &mut filesystem.readwrite_paths,
        context.boundary_state_dir.display().to_string(),
    );
    push_unique_path(
        &mut filesystem.readonly_paths,
        context.config.sandbox_binary_path.clone(),
    );
    let process = MxcProcess {
        command_line: sandbox_command,
        cwd: context.sandbox_config.cwd.clone(),
        env: trusted_sandbox_environment(context.config.pc_minimal_env),
        timeout: 0,
    };
    let network = MxcNetwork {
        default_policy: "block".to_string(),
        proxy: Some(proxy_addr),
        allow_local_network: context.config.pc_allow_local_network,
    };
    drop(control_reservation);
    let mut boundary = context
        .invoker
        .run_oneshot(
            &context.sandbox.id,
            filesystem,
            MxcProcessContainer {
                least_privilege: context.config.pc_least_privilege,
                capabilities: context.config.pc_capabilities.clone(),
            },
            process,
            Some(network),
            mapped.ui,
        )
        .await
        .map_err(|error| format!("start MXC ProcessContainer: {error}"))?;
    attach_child_logs(&context.sandbox.name, "sandbox", &mut boundary);
    attach_child_logs(&context.sandbox.name, "supervisor", &mut supervisor);
    if context.config.etw_audit
        && let Some(pid) = boundary.id()
        && let Ok(process_start_key) = crate::etw_consumer::child_process_start_key(&boundary)
        && let Ok(mut attribution) = context.attribution.lock()
    {
        attribution.register_launch(
            &context.sandbox.id,
            &context.sandbox.name,
            pid,
            process_start_key,
        );
    }
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (terminated_tx, terminated_rx) = watch::channel(false);
    {
        let mut registry = context.registry.lock().await;
        let entry = registry
            .get_mut(&context.sandbox.id)
            .ok_or_else(|| "MXC sandbox was deleted during startup".to_string())?;
        entry.shutdown_tx = Some(shutdown_tx);
        entry.terminated_rx = Some(terminated_rx);
        entry.phase_state = PhaseState::Running;
    }
    drop(startup_guard);
    let result = monitor_runtime_pair(boundary, supervisor, shutdown_rx).await;
    let _ = terminated_tx.send(true);
    if let Ok(mut attribution) = context.attribution.lock() {
        attribution.forget(&context.sandbox.id);
    }
    match result {
        RuntimePairExit::Shutdown => Ok(()),
        RuntimePairExit::Boundary(status) => Err(format!(
            "MXC ProcessContainer exited before supervisor shutdown: {status}"
        )),
        RuntimePairExit::Supervisor(status) => Err(format!(
            "MXC supervisor exited while ProcessContainer was active: {status}"
        )),
        RuntimePairExit::Wait(error) => Err(error),
    }
}

fn spawn_supervisor(
    context: &LifecycleContext,
    descriptor_path: &Path,
    auth_bundle_path: &Path,
) -> Result<Child, String> {
    let main_process_spec = openshell_core::sandbox_env::MainProcessConfig::encode_driver_spec(
        context.sandbox.spec.as_ref(),
    )
    .map_err(|error| format!("encode MXC main process spec: {error}"))?;
    let mut command = Command::new(&context.config.supervisor_binary_path);
    command
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .arg("--role")
        .arg("isolation-backend")
        .arg("--backend-descriptor-file")
        .arg(descriptor_path)
        .arg("--auth-bundle-file")
        .arg(auth_bundle_path)
        .env(
            openshell_core::sandbox_env::ADMITTED_ISOLATION_BACKEND,
            openshell_sandbox_backend::BACKEND_NAME,
        )
        .env(
            openshell_core::sandbox_env::MAIN_PROCESS_SPEC,
            main_process_spec,
        )
        .env(
            openshell_core::sandbox_env::ENDPOINT,
            &context.gateway.endpoint,
        )
        .env(openshell_core::sandbox_env::SANDBOX_ID, &context.sandbox.id)
        .env(openshell_core::sandbox_env::SANDBOX, &context.sandbox.name)
        .env(
            openshell_core::sandbox_env::LOG_LEVEL,
            openshell_core::driver_utils::sandbox_log_level(&context.sandbox, "warn"),
        );
    if let Some((ca, cert, key)) = &context.gateway.tls {
        command
            .env(openshell_core::sandbox_env::TLS_CA, ca)
            .env(openshell_core::sandbox_env::TLS_CERT, cert)
            .env(openshell_core::sandbox_env::TLS_KEY, key);
    }
    if let Some(server_name) = &context.gateway.tls_server_name {
        command.env(
            openshell_core::sandbox_env::GATEWAY_TLS_SERVER_NAME,
            server_name,
        );
    }
    command
        .spawn()
        .map_err(|error| format!("start host openshell-supervisor: {error}"))
}

enum RuntimePairExit {
    Shutdown,
    Boundary(std::process::ExitStatus),
    Supervisor(std::process::ExitStatus),
    Wait(String),
}

async fn monitor_runtime_pair(
    mut boundary: Child,
    mut supervisor: Child,
    mut shutdown: oneshot::Receiver<()>,
) -> RuntimePairExit {
    tokio::select! {
        _ = &mut shutdown => {
            let _ = supervisor.kill().await;
            let _ = boundary.kill().await;
            let _ = supervisor.wait().await;
            let _ = boundary.wait().await;
            RuntimePairExit::Shutdown
        }
        result = boundary.wait() => {
            let _ = supervisor.kill().await;
            let _ = supervisor.wait().await;
            result.map_or_else(
                |error| RuntimePairExit::Wait(format!("wait for MXC ProcessContainer: {error}")),
                RuntimePairExit::Boundary,
            )
        }
        result = supervisor.wait() => {
            let _ = boundary.kill().await;
            let _ = boundary.wait().await;
            result.map_or_else(
                |error| RuntimePairExit::Wait(format!("wait for MXC supervisor: {error}")),
                RuntimePairExit::Supervisor,
            )
        }
    }
}

async fn set_failed(context: &LifecycleContext, message: &str) {
    warn!(sandbox = %context.sandbox.name, %message, "MXC lifecycle failed");
    let failed = make_sandbox_with_condition(
        &context.sandbox,
        &condition("Ready", "False", "RuntimeFailed", message),
        false,
    );
    let mut registry = context.registry.lock().await;
    if let Some(entry) = registry.get_mut(&context.sandbox.id)
        && !matches!(entry.phase_state, PhaseState::Stopped)
    {
        entry.phase_state = PhaseState::Failed(message.to_string());
        entry.sandbox = failed.clone();
        drop(registry);
        let _ = context.watch_tx.send(sandbox_event(failed));
        let _ = context.watch_tx.send(platform_event(
            context.sandbox.id.clone(),
            "RuntimeFailed",
            message.to_string(),
        ));
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
                "mxc requires template.driver_config.mxc with command and cwd",
            )
        })?;
    let config: MxcSandboxConfig =
        serde_json::from_value(struct_to_json_value(config)).map_err(|error| {
            tonic::Status::invalid_argument(format!("invalid mxc driver_config: {error}"))
        })?;
    if config.command.first().is_none_or(String::is_empty) {
        return Err(tonic::Status::invalid_argument(
            "mxc driver_config.command must contain an executable",
        ));
    }
    Ok(config)
}

fn launch_authentication(
    sandbox: &DriverSandbox,
) -> Result<openshell_core::jwt::SandboxLaunchAuthentication, tonic::Status> {
    let encoded = sandbox
        .spec
        .as_ref()
        .map(|spec| spec.launch_authentication.as_slice())
        .filter(|encoded| !encoded.is_empty())
        .ok_or_else(|| {
            tonic::Status::failed_precondition("MXC sandbox launch authentication is required")
        })?;
    serde_json::from_slice(encoded).map_err(|error| {
        tonic::Status::failed_precondition(format!(
            "decode MXC sandbox launch authentication: {error}"
        ))
    })
}

fn sandbox_environment(sandbox: &DriverSandbox) -> HashMap<String, String> {
    let mut environment = HashMap::new();
    if let Some(spec) = &sandbox.spec {
        if let Some(template) = &spec.template {
            environment.extend(template.environment.clone());
        }
        environment.extend(spec.environment.clone());
    }
    environment
}

fn trusted_sandbox_environment(minimal: bool) -> Vec<String> {
    if minimal {
        return Vec::new();
    }
    ["SYSTEMROOT", "WINDIR", "PATH", "COMSPEC", "LOCALAPPDATA"]
        .into_iter()
        .filter_map(|key| {
            std::env::var(key)
                .ok()
                .map(|value| format!("{key}={value}"))
        })
        .collect()
}

fn reserve_loopback_port() -> io::Result<(SocketAddr, std::net::TcpListener)> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok((listener.local_addr()?, listener))
}

fn resolve_workload_binary(command: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(command);
    if path.is_absolute() {
        return Ok(path);
    }
    let output = std::process::Command::new("where.exe")
        .arg(command)
        .output()
        .map_err(|error| format!("resolve MXC workload executable {command:?}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "MXC workload executable {command:?} is relative and was not found on PATH"
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|error| format!("decode resolved MXC workload executable: {error}"))?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(PathBuf::from)
        .find(|candidate| candidate.is_absolute())
        .ok_or_else(|| format!("where.exe returned no absolute path for {command:?}"))
}

fn safe_component(value: &str) -> Result<&str, tonic::Status> {
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Ok(value)
    } else {
        Err(tonic::Status::invalid_argument(
            "sandbox ID is not safe for MXC state paths",
        ))
    }
}

fn push_unique_path(paths: &mut Vec<String>, path: String) {
    if !paths
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(&path))
    {
        paths.push(path);
    }
}

fn cleanup_runtime_directory(path: &Path) {
    if let Err(error) = std::fs::remove_dir_all(path)
        && error.kind() != io::ErrorKind::NotFound
    {
        warn!(path = %path.display(), %error, "failed to remove MXC runtime state");
    }
}

/// Create a state directory whose DACL grants access only to the gateway's
/// Windows identity until MXC applies any explicit ProcessContainer grant.
/// Secret-bearing state must not inherit permissive ACLs from its parent.
fn create_restricted_state_dir(path: &Path, kind: &str) -> Result<(), String> {
    std::fs::create_dir_all(path)
        .map_err(|error| format!("create MXC {kind} state directory: {error}"))?;
    let identity = std::process::Command::new("whoami.exe")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .map_err(|error| format!("resolve gateway Windows identity: {error}"))?;
    if !identity.status.success() {
        return Err("whoami failed while restricting MXC host state".to_string());
    }
    let identity = String::from_utf8(identity.stdout)
        .map_err(|error| format!("decode gateway Windows identity: {error}"))?;
    let sid = identity
        .trim()
        .rsplit_once(',')
        .map(|(_, sid)| sid.trim().trim_matches('"'))
        .filter(|sid| sid.starts_with("S-1-"))
        .ok_or_else(|| "whoami returned no Windows SID".to_string())?;
    let grant = format!("*{sid}:(OI)(CI)F");
    let status = std::process::Command::new("icacls.exe")
        .arg(path)
        .args(["/inheritance:r", "/grant:r", &grant, "/q"])
        .status()
        .map_err(|error| format!("restrict MXC host state ACL: {error}"))?;
    if !status.success() {
        return Err(format!(
            "icacls failed to restrict MXC {kind} state directory {}",
            path.display()
        ));
    }
    Ok(())
}

async fn wait_for_termination(
    terminated: Option<watch::Receiver<bool>>,
    sandbox_name: &str,
) -> Result<(), tonic::Status> {
    let Some(mut terminated) = terminated else {
        return Ok(());
    };
    match tokio::time::timeout(Duration::from_secs(15), terminated.wait_for(|done| *done)).await {
        Ok(Ok(_)) => Ok(()),
        _ => Err(tonic::Status::deadline_exceeded(format!(
            "sandbox {sandbox_name} did not terminate within the MXC stop timeout"
        ))),
    }
}

fn attach_child_logs(sandbox_name: &str, component: &'static str, child: &mut Child) {
    if let Some(stdout) = child.stdout.take() {
        let sandbox_name = sandbox_name.to_string();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                info!(sandbox = %sandbox_name, component, "{line}");
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        let sandbox_name = sandbox_name.to_string();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                warn!(sandbox = %sandbox_name, component, "{line}");
            }
        });
    }
}

fn encode_windows_command_line(args: &[String]) -> String {
    args.iter()
        .map(|argument| quote_windows_argument(argument))
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote_windows_argument(argument: &str) -> String {
    if !argument.is_empty()
        && !argument
            .chars()
            .any(|character| character.is_whitespace() || character == '"')
    {
        return argument.to_string();
    }
    let mut quoted = String::from("\"");
    let mut backslashes = 0;
    for character in argument.chars() {
        match character {
            '\\' => backslashes += 1,
            '"' => {
                quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
                quoted.push(character);
            }
        }
    }
    quoted.push_str(&"\\".repeat(backslashes * 2));
    quoted.push('"');
    quoted
}

fn condition(kind: &str, status: &str, reason: &str, message: &str) -> DriverCondition {
    DriverCondition {
        r#type: kind.to_string(),
        status: status.to_string(),
        reason: reason.to_string(),
        message: message.to_string(),
        transition_time: None,
    }
}

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
            conditions: vec![condition.clone()],
            deleting,
            ..Default::default()
        }),
    }
}

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
                    source: "mxc-driver".into(),
                    r#type: "Warning".into(),
                    reason: reason.to_string(),
                    message,
                    metadata: HashMap::new(),
                    ..Default::default()
                }),
            },
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_delegate_readiness_to_supervisor() {
        let backend = MxcComputeBackend::new(MxcComputeConfig::default());
        assert!(!backend.capabilities().driver_reports_runtime_readiness);
    }

    #[test]
    fn command_line_quotes_spaces() {
        assert_eq!(
            encode_windows_command_line(&[
                "C:\\Program Files\\OpenShell\\openshell-sandbox.exe".to_string(),
                "--bootstrap".to_string(),
            ]),
            "\"C:\\Program Files\\OpenShell\\openshell-sandbox.exe\" --bootstrap"
        );
    }
}
