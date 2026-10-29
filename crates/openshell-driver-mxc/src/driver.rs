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
    DriverCondition, DriverPlatformEvent, DriverSandbox, DriverSandboxSpec, DriverSandboxStatus,
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
/// Directory under the workload `cwd` that holds each generation's boundary
/// staging directory.
const BOUNDARY_STAGING_DIR: &str = ".openshell-runtime";
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
#[allow(clippy::struct_excessive_bools)] // independent operator options in the existing TOML schema
pub struct MxcComputeConfig {
    /// Permit caller-supplied driver JSON. Does not waive workload policy.
    pub allow_driver_config: bool,
    /// Path to `wxc-exec.exe`. Required for live runs.
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
            .map_or_else(std::env::temp_dir, PathBuf::from)
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
            allow_driver_config: false,
            supervisor_binary_path: sibling_binary("openshell-supervisor.exe"),
            sandbox_binary_path: sibling_binary("openshell-windows-sandbox.exe"),
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

impl MxcComputeConfig {
    /// MXC does not implement external-resource label admission. Keep the
    /// independent caller configuration gate in the gateway/driver contract.
    pub fn admission_policy(&self) -> openshell_core::resource_admission::DriverAdmissionConfig {
        openshell_core::resource_admission::DriverAdmissionConfig {
            allow_driver_config: self.allow_driver_config,
            resource_admission: openshell_core::resource_admission::ResourceAdmissionConfig {
                enabled: false,
                required_labels: std::collections::BTreeMap::new(),
            },
        }
    }

    /// Validate static MXC configuration without requiring launch credentials.
    ///
    /// Keep executable lookup independent of the gateway's PATH, as in the
    /// Windows driver lane. Runtime file availability is checked at launch.
    pub fn validate_configuration(&self) -> openshell_core::Result<()> {
        if self.wxc_exec_path.trim().is_empty() || !Path::new(&self.wxc_exec_path).is_absolute() {
            return Err(openshell_core::Error::config(
                "[openshell.drivers.mxc] wxc_exec_path must be set to an absolute path to wxc-exec.exe",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct GatewayConnection {
    endpoint: String,
    tls: Option<PathBuf>,
    tls_server_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MxcSandboxConfig {
    command: Vec<String>,
    #[serde(default)]
    cwd: String,
    /// Files and directories the workload cannot read, write, list, or
    /// create, including inside filesystem grants. Sent to MXC as
    /// `filesystem.deniedPaths`.
    #[serde(default)]
    denied_paths: Vec<String>,
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
    /// Compose the driver's host connection from generic gateway inputs.
    /// MXC endpoint defaults and TLS server-name selection stay in the driver.
    pub fn for_gateway(
        gateway_name: &str,
        mut config: MxcComputeConfig,
        gateway_port: u16,
        gateway_tls_enabled: bool,
        tls_ca: Option<PathBuf>,
    ) -> Self {
        let use_internal_endpoint = config.grpc_endpoint.trim().is_empty();
        if use_internal_endpoint {
            let scheme = if gateway_tls_enabled { "https" } else { "http" };
            config.grpc_endpoint = format!("{scheme}://127.0.0.1:{gateway_port}");
        }
        let endpoint = config.grpc_endpoint.clone();
        let tls_server_name =
            (use_internal_endpoint && gateway_tls_enabled).then(|| "localhost".to_string());
        Self::new_with_gateway(gateway_name, config, endpoint, tls_ca, tls_server_name)
    }

    pub fn new(gateway_name: &str, config: MxcComputeConfig) -> Self {
        let endpoint = config.grpc_endpoint.clone();
        Self::new_with_gateway(gateway_name, config, endpoint, None, None)
    }

    pub fn new_with_gateway(
        gateway_name: &str,
        config: MxcComputeConfig,
        endpoint: String,
        tls: Option<PathBuf>,
        tls_server_name: Option<String>,
    ) -> Self {
        let invoker = WxcExecInvoker::new(&config.wxc_exec_path, config.debug);
        let (watch_tx, _) = broadcast::channel(256);
        let attribution = Arc::new(std::sync::Mutex::new(
            crate::etw_consumer::AttributionIndex::new(),
        ));
        let etw_session = if config.etw_audit {
            crate::etw_consumer::start_session(attribution.clone(), gateway_name.to_string())
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
            resource_admission_policy: self.config.admission_policy().acknowledgement(),
            extension: Some(openshell_core::extension_protocol::extension_metadata(
                openshell_core::extension_protocol::ExtensionFamily::Compute,
                "openshell/mxc",
                openshell_core::VERSION,
                (self.config.backend == MxcBackend::ProcessContainer)
                    .then(|| openshell_core::extension_protocol::POLICY_UI_V1.to_string()),
            )),
            driver_name: DRIVER_NAME.to_string(),
            driver_version: DRIVER_VERSION.to_string(),
            default_image: DEFAULT_IMAGE_SENTINEL.to_string(),
            gateway_manages_lifecycle: false,
            supports_sandbox_authentication: false,
            driver_reports_runtime_readiness: false,
            resource_capabilities: None,
            rootfs_tar_staging_dir: String::new(),
            rootfs_tar_max_bytes: 0,
        }
    }

    pub fn validate_sandbox_create(&self, sandbox: &DriverSandbox) -> Result<(), tonic::Status> {
        if sandbox
            .spec
            .as_ref()
            .is_some_and(|spec| spec.await_main_process_attachment)
        {
            return Err(tonic::Status::failed_precondition(
                "MXC does not support foreground attachment to the main process. Create the sandbox with --detach.",
            ));
        }
        openshell_core::resource_admission::check_sandbox_driver_config(
            self.config.allow_driver_config,
            sandbox,
        )?;
        if !self.invoker.is_mock() {
            self.config
                .validate_configuration()
                .map_err(|error| tonic::Status::failed_precondition(error.to_string()))?;
        }
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
        let policy = sandbox.spec.as_ref().and_then(|spec| spec.policy.as_ref());
        let mapped = self.map_sandbox_policy(
            &sandbox.id,
            policy,
            "127.0.0.1:3128".parse().expect("fixed proxy address"),
        )?;
        // Denied paths are checked against every grant MXC receives: the
        // policy grants, the generation staging directory under `cwd`, and the
        // sandbox executable.
        let staging_root = Path::new(&config.cwd)
            .join(BOUNDARY_STAGING_DIR)
            .display()
            .to_string();
        let grants: Vec<&str> = mapped
            .readwrite_paths
            .iter()
            .chain(&mapped.readonly_paths)
            .chain([&staging_root, &self.config.sandbox_binary_path])
            .map(String::as_str)
            .collect();
        check_denied_paths(&config.denied_paths, &grants)?;
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
        // Gateway preflight runs before it mints generation-scoped credentials.
        // Require authentication at the provisioning boundary, before any state
        // directories, registry entries, or runtime processes are created.
        let launch = launch_authentication(sandbox)?;
        launch
            .validate()
            .map_err(|error| tonic::Status::failed_precondition(error.to_string()))?;
        let sandbox_id = sandbox.id.clone();
        let sandbox_config = sandbox_config(sandbox)?;
        // The gateway owns the authenticated generation. A driver-local UUID
        // would make the boundary descriptor disagree with the signed bundle.
        let generation = safe_component(launch.supervisor.runtime_generation.as_str())?.to_string();
        let host_state_dir = self
            .config
            .state_dir
            .join(safe_component(&sandbox_id)?)
            .join(&generation);
        let boundary_state_dir = PathBuf::from(&sandbox_config.cwd)
            .join(BOUNDARY_STAGING_DIR)
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
    let main = mxc_main_process_config(
        context.sandbox.spec.as_ref(),
        &context.sandbox_config.command,
    );
    let workload_binary = resolve_workload_binary(
        main.command
            .first()
            .ok_or_else(|| "MXC workload command is empty".to_string())?,
    )?;
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
        workload_binary,
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
        serde_json::to_vec(&provisioning.runtime_descriptor)
            .map_err(|error| format!("encode MXC launch data: {error}"))?,
    )
    .map_err(|error| format!("write MXC runtime descriptor: {error}"))?;
    // The supervisor owns the proxy listener. Release only that reservation
    // before spawning it; keep the Sandbox Protocol port reserved until the
    // ProcessContainer launch so unrelated local processes cannot squat it
    // during the more expensive host-side setup.
    drop(proxy_reservation);
    let mut supervisor = spawn_supervisor(context, &descriptor_path, &auth_bundle_path, &main)?;
    let sandbox_command = encode_windows_command_line(&[
        context.config.sandbox_binary_path.clone(),
        "--bootstrap".to_string(),
        boundary_config_path.display().to_string(),
        "--log-level".to_string(),
        openshell_core::driver_utils::sandbox_log_level(&context.sandbox, "info"),
    ]);
    let filesystem = boundary_filesystem(
        &mapped,
        &context.sandbox_config,
        &context.boundary_state_dir,
        &context.config.sandbox_binary_path,
    );
    let process = MxcProcess {
        command_line: sandbox_command,
        cwd: context.sandbox_config.cwd.clone(),
        env: trusted_sandbox_environment(context.config.pc_minimal_env),
        timeout: 0,
    };
    let network = MxcNetwork {
        egress_default: "deny".to_string(),
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
    if context.config.etw_audit {
        match boundary
            .id()
            .ok_or_else(|| "MXC child PID is unavailable".to_string())
            .and_then(|pid| {
                crate::etw_consumer::child_process_start_key(&boundary).map(|key| (pid, key))
            }) {
            Ok((pid, process_start_key)) => {
                let mut attribution = context
                    .attribution
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                attribution.register_launch(
                    &context.sandbox.id,
                    &context.sandbox.name,
                    pid,
                    process_start_key,
                );
                tracing::debug!(target: "mxc_etw", pid, process_start_key,
                    sandbox_id = %context.sandbox.id, "registered driver-owned MXC audit launch");
            }
            Err(error) => tracing::warn!(sandbox_id = %context.sandbox.id, %error,
                "MXC ETW audit launch registration failed"),
        }
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
    main: &openshell_core::sandbox_env::MainProcessConfig,
) -> Result<Child, String> {
    let main_process_spec = mxc_main_process_spec(main)?;
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
        .arg("--workdir")
        .arg(&context.sandbox_config.cwd)
        .env(
            openshell_core::sandbox_env::ADMITTED_ISOLATION_BACKEND,
            openshell_mxc_boundary::BACKEND_NAME,
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
            openshell_core::driver_utils::sandbox_log_level(&context.sandbox, "info"),
        );
    if let Some(ca) = &context.gateway.tls {
        command.env(openshell_core::sandbox_env::TLS_CA, ca);
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

fn mxc_main_process_spec(
    main: &openshell_core::sandbox_env::MainProcessConfig,
) -> Result<String, String> {
    serde_json::to_string(main).map_err(|error| format!("encode MXC main process spec: {error}"))
}

fn mxc_main_process_config(
    spec: Option<&DriverSandboxSpec>,
    driver_command: &[String],
) -> openshell_core::sandbox_env::MainProcessConfig {
    let mut main = openshell_core::sandbox_env::MainProcessConfig::from_driver_spec(spec);
    // Match windows: the MXC driver-config command remains a supported launch
    // source when no canonical command was supplied by the CLI.
    if main.command.is_empty() {
        main.command = driver_command.to_vec();
    }
    main
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
    let mut denied_paths = Vec::with_capacity(config.denied_paths.len());
    for entry in &config.denied_paths {
        let path = normalize_denied_path(entry).map_err(|reason| {
            tonic::Status::invalid_argument(format!(
                "mxc driver_config.denied_paths entry '{entry}' {reason}"
            ))
        })?;
        push_unique_path(&mut denied_paths, path);
    }
    Ok(MxcSandboxConfig {
        denied_paths,
        ..config
    })
}

/// Normalize a `driver_config.mxc.denied_paths` entry to the form sent to
/// MXC: a path that starts with a drive letter, with backslash separators and
/// no repeated or trailing separator. Rejects `.` and `..` components,
/// components that end in a dot or space (Windows strips those), and
/// characters Windows does not allow in file names. Aliases such as 8.3 short
/// names and junctions are resolved when the entry is compared with the
/// grants (`check_denied_paths`).
fn normalize_denied_path(path: &str) -> Result<String, &'static str> {
    let normalized = crate::policy::normalize_path(path);
    if !has_drive_root(&normalized) {
        return Err("is not an absolute path on a local drive, such as C:\\work\\.env");
    }
    let components: Vec<&str> = normalized[3..]
        .split('\\')
        .filter(|component| !component.is_empty())
        .collect();
    if components
        .iter()
        .any(|component| component.ends_with(['.', ' ']))
    {
        // Covers `.` and `..`; Windows also drops a trailing dot or space.
        return Err("has a '.' or '..' component or one ending in a dot or space");
    }
    if components.iter().any(|component| {
        component
            .chars()
            .any(|character| character.is_control() || "<>:\"|?*".contains(character))
    }) {
        return Err("contains a character Windows does not allow in file names");
    }
    Ok(format!("{}{}", &normalized[..3], components.join("\\")))
}

/// Whether a backslash-separated path starts with a drive letter and a root,
/// as in `C:\`.
fn has_drive_root(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\'
}

/// Check denied paths against the grants MXC receives and the host file
/// system before any sandbox state is created.
///
/// MXC resolves overlapping rules by the file system object each path names:
/// a denied path equal to a grant removes the whole grant, while a grant
/// nested in a denied directory keeps its access. Neither matches a request
/// to hide part of a grant, so a denied path must not equal or contain a
/// grant, compared after resolving 8.3 short names, junctions and symbolic
/// links, and ignoring letter case. MXC also refuses to start a
/// `ProcessContainer` that denies a path whose parent directory does not
/// exist; the denied path itself may be absent, and MXC then prevents its
/// creation.
fn check_denied_paths(denied_paths: &[String], grants: &[&str]) -> Result<(), tonic::Status> {
    if denied_paths.is_empty() {
        return Ok(());
    }
    let grants: Vec<(&str, Vec<String>)> = grants
        .iter()
        .map(|grant| (*grant, resolved_path_key(grant)))
        .collect();
    for denied in denied_paths {
        let denied_key = resolved_path_key(denied);
        if let Some((grant, _)) = grants
            .iter()
            .find(|(_, grant_key)| grant_key.starts_with(&denied_key))
        {
            return Err(tonic::Status::invalid_argument(format!(
                "mxc driver_config.denied_paths entry '{denied}' equals or contains the filesystem grant '{grant}'; deny paths below the grant instead"
            )));
        }
        let path = Path::new(denied);
        if !path.parent().is_some_and(Path::is_dir) {
            // Denying the outermost missing directory covers the entry, and
            // MXC accepts it because that directory's own parent exists.
            let remedy = path
                .ancestors()
                .skip(1)
                .take_while(|ancestor| !ancestor.exists())
                .last()
                .filter(|missing| missing.parent().is_some_and(Path::is_dir))
                .map_or_else(String::new, |missing| {
                    format!(
                        "; deny the missing directory '{}' instead",
                        missing.display()
                    )
                });
            return Err(tonic::Status::failed_precondition(format!(
                "mxc driver_config.denied_paths entry '{denied}' has no existing parent directory, which MXC requires{remedy}"
            )));
        }
    }
    Ok(())
}

/// Prefix of the verbatim paths `std::fs::canonicalize` returns on Windows.
const VERBATIM_PREFIX: &str = r"\\?\";

/// Path components that identify the file system object a Windows path
/// names, for comparing denied paths with grants. A path that starts with a
/// drive letter is resolved with `std::fs::canonicalize`, which follows
/// junctions and symbolic links and returns the long name and on-disk letter
/// case of every component. When the path does not exist, its deepest
/// existing ancestor is resolved and the remaining components are appended
/// as written. Components that cannot be resolved this way, and paths without
/// a drive letter, are compared as written.
fn resolved_path_key(path: &str) -> Vec<String> {
    let path = crate::policy::normalize_path(path);
    let path = path.strip_prefix(VERBATIM_PREFIX).unwrap_or(&path);
    if has_drive_root(path)
        && let Some(resolved) = resolve_existing_prefix(Path::new(path))
    {
        let resolved = resolved.display().to_string();
        return path_key(resolved.strip_prefix(VERBATIM_PREFIX).unwrap_or(&resolved));
    }
    path_key(path)
}

/// Canonicalize the deepest existing ancestor of `path` and append the
/// remaining components as written.
fn resolve_existing_prefix(path: &Path) -> Option<PathBuf> {
    let mut missing = Vec::new();
    for ancestor in path.ancestors() {
        if let Ok(resolved) = std::fs::canonicalize(ancestor) {
            return Some(
                missing
                    .iter()
                    .rev()
                    .fold(resolved, |resolved, component| resolved.join(component)),
            );
        }
        missing.push(ancestor.file_name()?);
    }
    None
}

/// Case-insensitive path components for comparing Windows paths. Letter case
/// is ignored for all Unicode letters, not only ASCII.
fn path_key(path: &str) -> Vec<String> {
    crate::policy::normalize_path(path)
        .split('\\')
        .filter(|component| !component.is_empty() && *component != ".")
        .map(str::to_lowercase)
        .collect()
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

/// MXC filesystem rules for the boundary `ProcessContainer`: the policy
/// grants, the generation staging directory, the sandbox executable, and the
/// caller's denied paths.
fn boundary_filesystem(
    mapped: &MappedConfig,
    sandbox_config: &MxcSandboxConfig,
    boundary_state_dir: &Path,
    sandbox_binary_path: &str,
) -> MxcFilesystem {
    let mut filesystem = MxcFilesystem {
        readwrite_paths: mapped.readwrite_paths.clone(),
        readonly_paths: mapped.readonly_paths.clone(),
        denied_paths: sandbox_config.denied_paths.clone(),
    };
    push_unique_path(
        &mut filesystem.readwrite_paths,
        boundary_state_dir.display().to_string(),
    );
    push_unique_path(
        &mut filesystem.readonly_paths,
        sandbox_binary_path.to_string(),
    );
    filesystem
}

fn cleanup_runtime_directory(path: &Path) {
    if let Err(error) = std::fs::remove_dir_all(path)
        && error.kind() != io::ErrorKind::NotFound
    {
        warn!(path = %path.display(), %error, "failed to remove MXC runtime state");
    }
}

/// Create a state directory whose DACL grants access only to the gateway's
/// Windows identity until MXC applies any explicit `ProcessContainer` grant.
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

// The RFC 0012 replacement above owns create/stop/delete/watch and paired
// process monitoring. Resource admission remains in validate_sandbox_create;
// readiness is reported through the authenticated supervisor session, not by
// the driver. Keep lifecycle/security tests below during their migration.
#[cfg(test)]
mod tests {
    #[test]
    fn mxc_driver_command_reaches_supervisor_without_generic_command() {
        let command = vec![
            "cmd.exe".into(),
            "/c".into(),
            "echo ok 1> C:/work/result.txt".into(),
        ];
        let encoded = mxc_main_process_spec(&mxc_main_process_config(None, &command)).unwrap();
        let main = openshell_core::sandbox_env::MainProcessConfig::decode(&encoded).unwrap();
        assert_eq!(main.command, command);
        assert!(!main.await_main_process_attachment);
        let spec = DriverSandboxSpec {
            command: vec!["explicit.exe".into()],
            ..Default::default()
        };
        let encoded =
            mxc_main_process_spec(&mxc_main_process_config(Some(&spec), &command)).unwrap();
        assert_eq!(
            openshell_core::sandbox_env::MainProcessConfig::decode(&encoded)
                .unwrap()
                .command,
            spec.command
        );
    }

    #[test]
    fn proxy_identity_uses_the_canonical_workload_command() {
        let canonical = std::env::var("COMSPEC").unwrap();
        let spec = DriverSandboxSpec {
            command: vec![canonical.clone(), "/C".into(), "exit 0".into()],
            ..Default::default()
        };
        let fallback = vec!["not-the-workload.exe".into()];
        let main = mxc_main_process_config(Some(&spec), &fallback);
        assert_eq!(main.command, spec.command);
        assert_eq!(
            resolve_workload_binary(&main.command[0]).unwrap(),
            resolve_workload_binary(&canonical).unwrap()
        );
        assert_eq!(
            openshell_core::sandbox_env::MainProcessConfig::decode(
                &mxc_main_process_spec(&main).unwrap()
            )
            .unwrap()
            .command,
            main.command
        );
    }
    use super::*;

    #[test]
    fn gateway_connection_defaults_are_driver_owned() {
        for (tls_enabled, scheme, server_name) in
            [(false, "http", None), (true, "https", Some("localhost"))]
        {
            let ca = PathBuf::from("C:\\gateway\\ca.pem");
            let backend = MxcComputeBackend::for_gateway(
                "test",
                MxcComputeConfig::default(),
                9000,
                tls_enabled,
                Some(ca.clone()),
            );
            assert_eq!(
                backend.gateway.endpoint,
                format!("{scheme}://127.0.0.1:9000")
            );
            assert_eq!(backend.gateway.tls_server_name.as_deref(), server_name);
            assert_eq!(backend.gateway.tls, Some(ca));
            assert_eq!(backend.config.grpc_endpoint, backend.gateway.endpoint);
        }
    }

    #[test]
    fn gateway_connection_preserves_explicit_endpoint() {
        let config = MxcComputeConfig {
            grpc_endpoint: "https://gateway.example:9443".to_string(),
            ..Default::default()
        };
        let backend = MxcComputeBackend::for_gateway("test", config, 9000, true, None);
        assert_eq!(backend.gateway.endpoint, "https://gateway.example:9443");
        assert_eq!(backend.gateway.tls_server_name, None);
    }

    fn host_grants_config() -> MxcComputeConfig {
        MxcComputeConfig {
            allow_driver_config: true,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn driver_config_gate_remains_required_without_resource_admission() {
        let (mut backend, sandbox, _dir) = preflight_fixture();
        assert!(backend.validate_sandbox_create(&sandbox).is_ok());
        backend.config.allow_driver_config = false;
        let error = backend.validate_sandbox_create(&sandbox).unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(backend.create_sandbox(&sandbox).await.is_err());
        assert!(backend.get_sandbox(&sandbox.id).await.is_none());
        assert!(!backend.config.state_dir.exists());
    }

    #[tokio::test]
    async fn foreground_attachment_is_rejected_before_provisioning() {
        let (backend, mut sandbox, _dir) = preflight_fixture();
        sandbox.spec.as_mut().unwrap().command =
            vec!["cmd.exe".into(), "/c".into(), "exit 0".into()];
        sandbox.spec.as_mut().unwrap().await_main_process_attachment = true;
        let error = backend.validate_sandbox_create(&sandbox).unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("--detach"));
        let error = backend.create_sandbox(&sandbox).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("foreground attachment"));
        assert!(backend.get_sandbox(&sandbox.id).await.is_none());
        assert!(!backend.config.state_dir.exists());
        sandbox.spec.as_mut().unwrap().await_main_process_attachment = false;
        assert!(backend.validate_sandbox_create(&sandbox).is_ok());
    }

    #[test]
    fn resource_admission_is_unsupported_and_acknowledged() {
        let config = MxcComputeConfig::default();
        let policy = config.admission_policy();
        assert!(!policy.resource_admission.enabled);
        assert!(policy.resource_admission.required_labels.is_empty());
        assert!(!policy.allow_driver_config);
        policy
            .verify_acknowledgement(&policy.acknowledgement())
            .unwrap();
        assert!(
            serde_json::from_value::<MxcComputeConfig>(serde_json::json!({
                "resource_admission": { "enabled": true }
            }))
            .is_err()
        );
    }

    #[test]
    fn static_configuration_requires_an_absolute_wxc_path() {
        for path in ["", "wxc-exec.exe", "relative\\wxc-exec.exe"] {
            let config = MxcComputeConfig {
                wxc_exec_path: path.to_string(),
                ..Default::default()
            };
            assert!(config.validate_configuration().is_err());
        }
        let config = MxcComputeConfig {
            wxc_exec_path: "C:\\mxc-kit\\bin\\wxc-exec.exe".to_string(),
            ..Default::default()
        };
        assert!(config.validate_configuration().is_ok());
    }

    fn preflight_fixture() -> (MxcComputeBackend, DriverSandbox, tempfile::TempDir) {
        use openshell_core::proto::compute::v1::{DriverSandboxSpec, DriverSandboxTemplate};
        let dir = tempfile::tempdir().expect("test directory");
        let binary = std::env::current_exe().expect("test executable");
        let backend = MxcComputeBackend::new(
            openshell_core::config::DEFAULT_GATEWAY_NAME,
            MxcComputeConfig {
                wxc_exec_path: binary.display().to_string(),
                grpc_endpoint: "http://127.0.0.1:1".into(),
                supervisor_binary_path: binary.display().to_string(),
                sandbox_binary_path: binary.display().to_string(),
                state_dir: dir.path().join("not-created"),
                ..host_grants_config()
            },
        );
        let serde_json::Value::Object(config) = serde_json::json!({
            "command": ["C:\\Windows\\System32\\cmd.exe", "/c", "exit 0"],
            "cwd": dir.path(),
        }) else {
            unreachable!()
        };
        let sandbox = DriverSandbox {
            id: "preflight".into(),
            name: "preflight".into(),
            spec: Some(DriverSandboxSpec {
                policy: Some(SandboxPolicy {
                    version: 1,
                    ..Default::default()
                }),
                template: Some(DriverSandboxTemplate {
                    driver_config: Some(
                        openshell_core::proto_struct::json_object_to_struct(config)
                            .expect("config"),
                    ),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        (backend, sandbox, dir)
    }

    #[test]
    fn preflight_does_not_require_not_yet_minted_authentication() {
        let (backend, sandbox, _dir) = preflight_fixture();
        backend
            .validate_sandbox_create(&sandbox)
            .expect("static preflight");
        assert!(!backend.config.state_dir.exists());
    }

    fn with_ui_policy(
        mut sandbox: DriverSandbox,
        ui: openshell_core::proto::UiPolicy,
    ) -> DriverSandbox {
        sandbox.spec.as_mut().unwrap().policy.as_mut().unwrap().ui = Some(ui);
        sandbox
    }

    #[test]
    fn ui_policy_reaches_mapper_and_capability_is_advertised() {
        use openshell_core::proto::{UiClipboardAccess, UiPolicy};
        let (backend, sandbox, _dir) = preflight_fixture();
        assert!(
            backend
                .capabilities()
                .extension
                .unwrap()
                .supported_capabilities
                .iter()
                .any(|capability| capability == openshell_core::extension_protocol::POLICY_UI_V1)
        );
        for clipboard in [
            UiClipboardAccess::None,
            UiClipboardAccess::Read,
            UiClipboardAccess::Write,
            UiClipboardAccess::All,
        ] {
            let sandbox = with_ui_policy(
                sandbox.clone(),
                UiPolicy {
                    allow_graphical_ui: true,
                    clipboard: clipboard as i32,
                    allow_input_injection: true,
                },
            );
            backend
                .validate_sandbox_create(&sandbox)
                .expect("valid UI policy");
            let mapped = backend
                .map_sandbox_policy(
                    &sandbox.id,
                    sandbox.spec.as_ref().unwrap().policy.as_ref(),
                    "127.0.0.1:3128".parse().unwrap(),
                )
                .unwrap();
            let ui = mapped.ui.unwrap();
            assert!(!ui.disable);
            assert!(ui.injection);
            assert!(!backend.config.state_dir.exists());
        }
    }

    #[test]
    fn ui_policy_rejects_invalid_settings_before_provisioning() {
        use openshell_core::proto::{UiClipboardAccess, UiPolicy};
        let (backend, sandbox, _dir) = preflight_fixture();
        for ui in [
            UiPolicy {
                clipboard: 999,
                ..Default::default()
            },
            UiPolicy {
                clipboard: UiClipboardAccess::Read as i32,
                ..Default::default()
            },
            UiPolicy {
                allow_input_injection: true,
                ..Default::default()
            },
        ] {
            let sandbox = with_ui_policy(sandbox.clone(), ui);
            let error = backend.validate_sandbox_create(&sandbox).unwrap_err();
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
            assert!(!backend.config.state_dir.exists());
        }
    }

    fn with_denied_paths(mut sandbox: DriverSandbox, denied_paths: &[String]) -> DriverSandbox {
        let template = sandbox.spec.as_mut().unwrap().template.as_mut().unwrap();
        let mut config = struct_to_json_value(template.driver_config.as_ref().unwrap());
        config["denied_paths"] = serde_json::json!(denied_paths);
        let serde_json::Value::Object(config) = config else {
            unreachable!()
        };
        template.driver_config =
            Some(openshell_core::proto_struct::json_object_to_struct(config).expect("config"));
        sandbox
    }

    fn with_filesystem_grants(
        mut sandbox: DriverSandbox,
        read_write: &[&Path],
        read_only: &[&Path],
    ) -> DriverSandbox {
        let strings = |paths: &[&Path]| -> Vec<String> {
            paths
                .iter()
                .map(|path| path.display().to_string())
                .collect()
        };
        sandbox
            .spec
            .as_mut()
            .unwrap()
            .policy
            .as_mut()
            .unwrap()
            .filesystem = Some(openshell_core::proto::FilesystemPolicy {
            read_write: strings(read_write),
            read_only: strings(read_only),
            ..Default::default()
        });
        sandbox
    }

    fn display(path: &Path) -> String {
        path.display().to_string()
    }

    #[test]
    fn driver_config_denied_paths_inside_a_grant_pass_preflight() {
        let (backend, sandbox, dir) = preflight_fixture();
        let profile = dir.path().join("profile");
        std::fs::create_dir(&profile).unwrap();
        std::fs::write(profile.join(".env"), "fixture").unwrap();
        let sandbox = with_filesystem_grants(sandbox, &[&profile], &[]);
        // A denied path may be absent while its parent directory exists.
        let sandbox = with_denied_paths(
            sandbox,
            &[
                display(&profile.join(".env")),
                display(&profile.join("auth.json")),
            ],
        );
        backend
            .validate_sandbox_create(&sandbox)
            .expect("denied paths inside a grant pass preflight");
        assert!(!backend.config.state_dir.exists());
    }

    #[test]
    fn driver_config_denied_paths_reach_the_mxc_request() {
        let (backend, sandbox, dir) = preflight_fixture();
        let profile = dir.path().join("profile");
        std::fs::create_dir(&profile).unwrap();
        let env = display(&profile.join(".env"));
        let auth = display(&profile.join("auth.json"));
        let sandbox = with_filesystem_grants(sandbox, &[&profile], &[]);
        let process = MxcProcess {
            command_line: "cmd /c exit 0".into(),
            cwd: display(dir.path()),
            env: Vec::new(),
            timeout: 0,
        };
        let staging = dir.path().join(BOUNDARY_STAGING_DIR).join("generation");
        let mxc_request = |sandbox: &DriverSandbox| {
            backend
                .validate_sandbox_create(sandbox)
                .expect("valid preflight");
            let config = sandbox_config(sandbox).unwrap();
            let mapped = backend
                .map_sandbox_policy(
                    &sandbox.id,
                    sandbox.spec.as_ref().unwrap().policy.as_ref(),
                    "127.0.0.1:3128".parse().unwrap(),
                )
                .unwrap();
            let filesystem = boundary_filesystem(
                &mapped,
                &config,
                &staging,
                &backend.config.sandbox_binary_path,
            );
            crate::mxc::oneshot_config_json(
                &sandbox.id,
                &filesystem,
                &MxcProcessContainer::default(),
                &process,
                None,
                None,
            )
        };

        // Without denied paths the request carries no deniedPaths or fallback
        // field.
        let request = mxc_request(&sandbox);
        assert!(request["filesystem"].get("deniedPaths").is_none());
        assert!(request.get("fallback").is_none());

        // Forward slashes, a trailing separator, and a case-only duplicate
        // normalize to one backslash path per entry.
        let sandbox = with_denied_paths(
            sandbox,
            &[
                env.replace('\\', "/"),
                format!("{env}\\"),
                env.to_ascii_uppercase(),
                auth.clone(),
            ],
        );
        let request = mxc_request(&sandbox);
        assert_eq!(
            request["filesystem"]["deniedPaths"],
            serde_json::json!([env, auth])
        );
        assert_eq!(
            request["filesystem"]["readwritePaths"],
            serde_json::json!([display(&profile), display(&staging)])
        );
        // MXC must not fall back to changing host ACLs to enforce the denies.
        assert_eq!(
            request["fallback"],
            serde_json::json!({ "allowDaclMutation": false })
        );
    }

    #[test]
    fn driver_config_denied_paths_must_be_absolute_local_paths() {
        let (backend, sandbox, dir) = preflight_fixture();
        let base = display(dir.path());
        for path in [
            String::new(),
            "relative\\.env".into(),
            "\\work\\.env".into(),
            "C:work\\.env".into(),
            "\\\\server\\share\\.env".into(),
            "\\\\?\\C:\\work\\.env".into(),
            format!(" {base}\\.env"),
            format!("{base}\\.env "),
            format!("{base}\\.env."),
            format!("{base}\\.\\.env"),
            format!("{base}\\profile\\..\\.env"),
            format!("{base}\\.env:stream"),
            format!("{base}\\*.env"),
        ] {
            let error = backend
                .validate_sandbox_create(&with_denied_paths(
                    sandbox.clone(),
                    std::slice::from_ref(&path),
                ))
                .expect_err("ambiguous denied path must be rejected");
            assert_eq!(error.code(), tonic::Code::InvalidArgument, "{path:?}");
            assert!(
                error
                    .message()
                    .starts_with("mxc driver_config.denied_paths entry"),
                "{path:?}: {}",
                error.message()
            );
        }
        assert!(!backend.config.state_dir.exists());
    }

    #[test]
    fn driver_config_denied_paths_must_not_cover_a_grant() {
        let (backend, sandbox, dir) = preflight_fixture();
        let work = dir.path().join("work");
        let tools = dir.path().join("tools");
        std::fs::create_dir(&work).unwrap();
        std::fs::create_dir(&tools).unwrap();
        let sandbox = with_filesystem_grants(sandbox, &[&work], &[&tools]);
        let staging = display(&dir.path().join(BOUNDARY_STAGING_DIR));
        let binary = backend.config.sandbox_binary_path.clone();
        for (denied, grant) in [
            (display(&work), display(&work)),
            (
                display(&work).to_ascii_uppercase().replace('\\', "/"),
                display(&work),
            ),
            (display(dir.path()), display(&work)),
            (display(&tools), display(&tools)),
            (staging.clone(), staging),
            (binary.clone(), binary),
        ] {
            let error = backend
                .validate_sandbox_create(&with_denied_paths(
                    sandbox.clone(),
                    std::slice::from_ref(&denied),
                ))
                .expect_err("a denied path must not cover a grant");
            assert_eq!(error.code(), tonic::Code::InvalidArgument, "{denied}");
            assert!(
                error.message().contains(&format!(
                    "equals or contains the filesystem grant '{grant}'"
                )),
                "{denied}: {}",
                error.message()
            );
        }
        // A grant written as a verbatim path names the same directory.
        let verbatim = PathBuf::from(format!(r"\\?\{}", display(&work)));
        let sandbox = with_filesystem_grants(sandbox, &[&verbatim], &[]);
        assert_denied_path_covers_grant(&backend, &sandbox, &display(&work), &verbatim);
        assert!(!backend.config.state_dir.exists());
    }

    #[test]
    fn driver_config_denied_path_parent_must_exist() {
        let (backend, sandbox, dir) = preflight_fixture();
        std::fs::write(dir.path().join("file.txt"), "fixture").unwrap();
        let missing = dir.path().join("missing");
        // No directory to suggest when the parent is a file or the drive is
        // missing.
        let no_volume = PathBuf::from(format!("{}:\\missing\\.env", unused_drive_letter()));
        for (denied, remedy) in [
            (missing.join(".env"), Some(&missing)),
            (missing.join("nested").join(".env"), Some(&missing)),
            (dir.path().join("file.txt").join(".env"), None),
            (no_volume, None),
        ] {
            let sandbox = with_denied_paths(sandbox.clone(), &[display(&denied)]);
            let error = backend.validate_sandbox_create(&sandbox).unwrap_err();
            assert_eq!(error.code(), tonic::Code::FailedPrecondition);
            assert!(
                error.message().contains("has no existing parent directory"),
                "{}",
                error.message()
            );
            // The error names the missing directory to deny instead.
            let suggestion = remedy.map(|directory| {
                format!(
                    "; deny the missing directory '{}' instead",
                    display(directory)
                )
            });
            assert_eq!(
                error.message().split_once("which MXC requires").unwrap().1,
                suggestion.as_deref().unwrap_or_default(),
                "{}",
                error.message()
            );
        }
        // Denying the missing directory itself passes preflight.
        let sandbox = with_denied_paths(sandbox, &[display(&missing)]);
        backend
            .validate_sandbox_create(&sandbox)
            .expect("a missing directory under an existing one can be denied");
        assert!(!backend.config.state_dir.exists());
    }

    /// A drive letter with no volume behind it.
    fn unused_drive_letter() -> char {
        (b'D'..=b'Z')
            .rev()
            .map(char::from)
            .find(|letter| !Path::new(&format!("{letter}:\\")).exists())
            .expect("an unused drive letter")
    }

    /// Run `cmd.exe /d /c <command>` and return its trimmed output.
    fn run_cmd(command: &str) -> (bool, String) {
        use std::os::windows::process::CommandExt as _;
        let output = std::process::Command::new("cmd.exe")
            .args(["/d", "/c"])
            .raw_arg(command)
            .output()
            .expect("run cmd.exe");
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).trim().to_string(),
        )
    }

    /// The 8.3 short spelling of an existing path, or `None` when the volume
    /// has no short name for it (8.3 name creation disabled).
    fn short_path(path: &Path) -> Option<String> {
        let (_, short) = run_cmd(&format!("for %I in (\"{}\") do @echo %~sI", path.display()));
        let same_object =
            std::fs::canonicalize(&short).ok()? == std::fs::canonicalize(path).ok()?;
        (same_object && !short.eq_ignore_ascii_case(&display(path))).then_some(short)
    }

    fn assert_denied_path_covers_grant(
        backend: &MxcComputeBackend,
        sandbox: &DriverSandbox,
        denied: &str,
        grant: &Path,
    ) {
        let error = backend
            .validate_sandbox_create(&with_denied_paths(sandbox.clone(), &[denied.to_string()]))
            .expect_err("a denied path must not cover a grant");
        assert_eq!(error.code(), tonic::Code::InvalidArgument, "{denied}");
        assert!(
            error.message().contains(&format!(
                "equals or contains the filesystem grant '{}'",
                display(grant)
            )),
            "{denied}: {}",
            error.message()
        );
    }

    #[test]
    fn driver_config_denied_paths_resolve_short_names() {
        let (backend, sandbox, dir) = preflight_fixture();
        let long_dir = dir.path().join("denied paths long name");
        let work = long_dir.join("work");
        let pending = long_dir.join("pending").join("nested");
        std::fs::create_dir_all(work.join("profile")).unwrap();
        let Some(short_dir) = short_path(&long_dir) else {
            eprintln!(
                "SKIP: no 8.3 short name for {}; enable 8.3 name creation on its volume to run this test",
                long_dir.display()
            );
            return;
        };
        // `pending\nested` is a grant that does not exist yet, nor does its
        // parent.
        let sandbox = with_filesystem_grants(sandbox, &[&work, &pending], &[]);
        // The same directories through the 8.3 name of their parent: equal to
        // a grant, containing a grant, and equal to the grant that does not
        // exist.
        for (denied, grant) in [
            (format!("{short_dir}\\work"), &work),
            (short_dir.clone(), &work),
            (format!("{short_dir}\\pending\\nested"), &pending),
        ] {
            assert_denied_path_covers_grant(&backend, &sandbox, &denied, grant);
        }
        // The reverse: a grant spelled with the 8.3 name, denied by its long
        // name.
        let short_grant = PathBuf::from(format!("{short_dir}\\work"));
        let reversed = with_filesystem_grants(sandbox.clone(), &[&short_grant], &[]);
        assert_denied_path_covers_grant(&backend, &reversed, &display(&work), &short_grant);
        // A file inside the grant can be denied through the 8.3 name.
        backend
            .validate_sandbox_create(&with_denied_paths(
                sandbox,
                &[format!("{short_dir}\\work\\profile\\.env")],
            ))
            .expect("a short spelling of a path inside a grant passes preflight");
        assert!(!backend.config.state_dir.exists());
    }

    #[test]
    fn driver_config_denied_paths_resolve_junctions() {
        let (backend, sandbox, dir) = preflight_fixture();
        let work = dir.path().join("work");
        std::fs::create_dir_all(work.join("profile")).unwrap();
        let link = dir.path().join("link");
        let (created, output) = run_cmd(&format!(
            "mklink /J \"{}\" \"{}\"",
            link.display(),
            work.display()
        ));
        assert!(created, "mklink /J failed: {output}");
        let sandbox = with_filesystem_grants(sandbox, &[&work], &[]);
        // A junction whose target is the grant names the grant.
        assert_denied_path_covers_grant(&backend, &sandbox, &display(&link), &work);
        // A grant spelled through the junction is the same directory.
        let through_link = with_filesystem_grants(sandbox.clone(), &[&link], &[]);
        assert_denied_path_covers_grant(&backend, &through_link, &display(&work), &link);
        // A file inside the grant can be denied through the junction.
        backend
            .validate_sandbox_create(&with_denied_paths(
                sandbox,
                &[display(&link.join("profile").join(".env"))],
            ))
            .expect("a path below the grant through a junction passes preflight");
        assert!(!backend.config.state_dir.exists());
    }

    #[test]
    fn driver_config_denied_paths_ignore_unicode_case() {
        let (backend, sandbox, dir) = preflight_fixture();
        let existing = dir.path().join("\u{e4}rger");
        std::fs::create_dir(&existing).unwrap();
        // A grant that does not exist yet keeps the letter case as written.
        let pending = dir.path().join("\u{f6}l");
        let sandbox = with_filesystem_grants(sandbox, &[&existing, &pending], &[]);
        for (denied, grant) in [
            (dir.path().join("\u{c4}RGER"), &existing),
            (dir.path().join("\u{d6}L"), &pending),
        ] {
            assert_denied_path_covers_grant(&backend, &sandbox, &display(&denied), grant);
        }
        assert!(!backend.config.state_dir.exists());
    }

    #[test]
    fn driver_config_denied_paths_compare_unresolvable_paths_as_written() {
        let (backend, sandbox, _dir) = preflight_fixture();
        // Nothing on a drive letter without a volume can be resolved.
        let drive = unused_drive_letter();
        let grant = PathBuf::from(format!("{drive}:\\Work"));
        let sandbox = with_filesystem_grants(sandbox, &[&grant], &[]);
        let denied = format!("{}:/WORK/", drive.to_ascii_lowercase());
        assert_denied_path_covers_grant(&backend, &sandbox, &denied, &grant);
        // A resolved path drops the `\\?\` prefix `canonicalize` adds, so it
        // compares in the same form as a path compared as written.
        assert_eq!(resolved_path_key(r"C:\"), path_key(r"C:\"));
        assert!(!backend.config.state_dir.exists());
    }

    #[test]
    fn isolation_session_does_not_advertise_ui_policy() {
        let (mut backend, _sandbox, _dir) = preflight_fixture();
        backend.config.backend = MxcBackend::IsolationSession;
        assert!(
            !backend
                .capabilities()
                .extension
                .unwrap()
                .supported_capabilities
                .iter()
                .any(|capability| capability == openshell_core::extension_protocol::POLICY_UI_V1)
        );
    }

    #[tokio::test]
    async fn provisioning_rejects_missing_authentication_before_side_effects() {
        let (backend, sandbox, _dir) = preflight_fixture();
        let error = backend
            .create_sandbox(&sandbox)
            .await
            .expect_err("authentication required");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("launch authentication"));
        assert!(!backend.config.state_dir.exists());
        assert!(backend.get_sandbox(&sandbox.id).await.is_none());
    }

    #[test]
    fn capabilities_delegate_readiness_to_supervisor() {
        let backend = MxcComputeBackend::new(
            openshell_core::config::DEFAULT_GATEWAY_NAME,
            MxcComputeConfig::default(),
        );
        assert!(!backend.capabilities().driver_reports_runtime_readiness);
    }

    #[test]
    fn gateway_config_rejects_pre_1_0_configuration_id() {
        let error = serde_json::from_value::<MxcComputeConfig>(serde_json::json!({
            "backend": "process_container",
            "default_configuration_id": "composable",
        }))
        .expect_err("MXC pre-1.0 configurationId must not be accepted");
        assert!(error.to_string().contains("default_configuration_id"));
    }

    #[test]
    fn command_line_quotes_spaces() {
        assert_eq!(
            encode_windows_command_line(&[
                "C:\\Program Files\\OpenShell\\openshell-windows-sandbox.exe".to_string(),
                "--bootstrap".to_string(),
            ]),
            "\"C:\\Program Files\\OpenShell\\openshell-windows-sandbox.exe\" --bootstrap"
        );
    }

    #[test]
    fn sandbox_environment_preserves_spec_precedence_without_host_secrets() {
        let (_backend, mut sandbox, _dir) = preflight_fixture();
        let spec = sandbox.spec.as_mut().unwrap();
        spec.template
            .as_mut()
            .unwrap()
            .environment
            .insert("SHARED".into(), "template".into());
        spec.environment.insert("SHARED".into(), "spec".into());
        spec.environment.insert("TOKEN".into(), "explicit".into());
        assert_eq!(
            sandbox_environment(&sandbox),
            HashMap::from([
                ("SHARED".into(), "spec".into()),
                ("TOKEN".into(), "explicit".into()),
            ])
        );
    }

    #[test]
    fn proxy_port_is_reserved_on_loopback() {
        let (address, reservation) = reserve_loopback_port().unwrap();
        assert!(address.ip().is_loopback());
        assert_ne!(address.port(), 0);
        assert!(std::net::TcpListener::bind(address).is_err());
        drop(reservation);
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
    }

    #[tokio::test]
    async fn stop_terminates_and_reaps_both_runtime_processes() {
        let spawn = || {
            Command::new("powershell.exe")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Start-Sleep -Seconds 60",
                ])
                .kill_on_drop(true)
                .spawn()
                .expect("real test process")
        };
        let boundary = spawn();
        let supervisor = spawn();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        shutdown_tx.send(()).unwrap();
        let exit = tokio::time::timeout(
            Duration::from_secs(5),
            monitor_runtime_pair(boundary, supervisor, shutdown_rx),
        )
        .await
        .expect("stop reaps both processes promptly");
        assert!(matches!(exit, RuntimePairExit::Shutdown));
    }
}
