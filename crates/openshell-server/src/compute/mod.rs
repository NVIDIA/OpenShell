// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-owned compute orchestration over a pluggable compute backend.

pub mod driver_config;
pub mod lease;
pub mod vm;

pub use openshell_driver_docker::DockerComputeConfig;
pub use openshell_driver_kubernetes::KubernetesComputeConfig;
pub use openshell_driver_podman::PodmanComputeConfig;
pub use vm::VmComputeConfig;

use crate::grpc::policy::SANDBOX_SETTINGS_OBJECT_TYPE;
use crate::persistence::{ObjectId, ObjectName, ObjectRecord, ObjectType, Store, WriteCondition};
use crate::sandbox_index::SandboxIndex;
use crate::sandbox_watch::SandboxWatchBus;
use crate::supervisor_session::SupervisorSessionRegistry;
use crate::tracing_bus::TracingLogBus;
use futures::{Stream, StreamExt};
use hyper_util::rt::TokioIo;
use openshell_core::ComputeDriverKind;
use openshell_core::proto::compute::v1::{
    CreateSandboxRequest, DeleteSandboxRequest, DriverCondition, DriverPlatformEvent,
    DriverResourceRequirements, DriverSandbox, DriverSandboxSpec, DriverSandboxStatus,
    DriverSandboxTemplate, GetCapabilitiesRequest, GetSandboxRequest,
    GpuResourceRequirements as DriverGpuResourceRequirements, ListSandboxesRequest,
    ResourceRequirements as DriverSandboxResourceRequirements, ValidateSandboxCreateRequest,
    WatchSandboxesEvent, WatchSandboxesRequest, compute_driver_client::ComputeDriverClient,
    compute_driver_server::ComputeDriver, watch_sandboxes_event,
};
use openshell_core::proto::{
    PlatformEvent, Sandbox, SandboxCondition, SandboxPhase, SandboxSpec, SandboxStatus,
    SandboxTemplate, SshSession,
};
use openshell_driver_docker::DockerComputeDriver;
use openshell_driver_kubernetes::{
    ComputeDriverService as KubernetesDriverService, KubernetesComputeDriver,
};
use openshell_driver_podman::{ComputeDriverService as PodmanDriverService, PodmanComputeDriver};
use prost::Message;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::sync::{Mutex, watch};
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Request, Status};
use tower::service_fn;
use tracing::{debug, info, warn};

type DriverWatchStream = Pin<Box<dyn Stream<Item = Result<WatchSandboxesEvent, Status>> + Send>>;
type SharedComputeDriver =
    Arc<dyn ComputeDriver<WatchSandboxesStream = DriverWatchStream> + Send + Sync>;

const DELETE_PHASE_CAS_RETRY_LIMIT: usize = 3;

#[tonic::async_trait]
trait ShutdownCleanup: Send + Sync {
    async fn cleanup_on_shutdown(&self) -> Result<(), String>;
}

#[tonic::async_trait]
impl ShutdownCleanup for DockerComputeDriver {
    async fn cleanup_on_shutdown(&self) -> Result<(), String> {
        let stopped = self
            .stop_managed_containers_on_shutdown()
            .await
            .map_err(|err| err.to_string())?;
        info!(
            stopped_containers = stopped,
            "Stopped Docker sandbox containers during gateway shutdown"
        );
        Ok(())
    }
}

/// Resume a single sandbox whose store record indicates it should be
/// running. Implemented by drivers (currently only Docker) where compute
/// resources do not auto-restart with the gateway. Returns `Ok(true)` if
/// the backend resource was found and resumed (or was already running),
/// `Ok(false)` if no backend resource exists.
#[tonic::async_trait]
trait StartupResume: Send + Sync {
    async fn resume_sandbox(&self, sandbox_id: &str, sandbox_name: &str) -> Result<bool, String>;
}

#[tonic::async_trait]
impl StartupResume for DockerComputeDriver {
    async fn resume_sandbox(&self, sandbox_id: &str, sandbox_name: &str) -> Result<bool, String> {
        Self::resume_sandbox(self, sandbox_id, sandbox_name)
            .await
            .map_err(|err| err.to_string())
    }
}
/// Interval between store-vs-backend reconciliation sweeps.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(60);

/// How long a sandbox can remain provisioning in the store without a
/// corresponding backend resource before it is considered orphaned.
const ORPHAN_GRACE_PERIOD: Duration = Duration::from_secs(300);

// Re-export the shared error type under the name used by this module.
pub use openshell_core::ComputeDriverError as ComputeError;

#[derive(Debug)]
pub struct ManagedDriverProcess {
    child: std::sync::Mutex<Option<tokio::process::Child>>,
    socket_path: PathBuf,
}

impl ManagedDriverProcess {
    pub(crate) fn new(child: tokio::process::Child, socket_path: PathBuf) -> Self {
        Self {
            child: std::sync::Mutex::new(Some(child)),
            socket_path,
        }
    }
}

impl Drop for ManagedDriverProcess {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            let _ = child.take();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

#[derive(Debug)]
pub struct AcquiredRemoteDriverEndpoint {
    pub(crate) name: String,
    pub(crate) channel: Channel,
    pub(crate) driver_process: Option<Arc<ManagedDriverProcess>>,
}

impl AcquiredRemoteDriverEndpoint {
    pub(crate) fn managed_builtin(
        driver_kind: ComputeDriverKind,
        channel: Channel,
        driver_process: Arc<ManagedDriverProcess>,
    ) -> Self {
        Self {
            name: driver_kind.as_str().to_string(),
            channel,
            driver_process: Some(driver_process),
        }
    }

    pub(crate) fn unmanaged(name: impl Into<String>, channel: Channel) -> Self {
        Self {
            name: name.into(),
            channel,
            driver_process: None,
        }
    }
}

#[derive(Debug, Clone)]
struct RemoteComputeDriver {
    channel: Channel,
}

impl RemoteComputeDriver {
    fn new(channel: Channel) -> Self {
        Self { channel }
    }

    fn client(&self) -> ComputeDriverClient<Channel> {
        ComputeDriverClient::new(self.channel.clone())
    }
}

#[tonic::async_trait]
impl ComputeDriver for RemoteComputeDriver {
    type WatchSandboxesStream = DriverWatchStream;

    async fn get_capabilities(
        &self,
        request: Request<GetCapabilitiesRequest>,
    ) -> Result<tonic::Response<openshell_core::proto::compute::v1::GetCapabilitiesResponse>, Status>
    {
        let mut client = self.client();
        client.get_capabilities(request).await
    }

    async fn validate_sandbox_create(
        &self,
        request: Request<ValidateSandboxCreateRequest>,
    ) -> Result<
        tonic::Response<openshell_core::proto::compute::v1::ValidateSandboxCreateResponse>,
        Status,
    > {
        let mut client = self.client();
        client.validate_sandbox_create(request).await
    }

    async fn get_sandbox(
        &self,
        request: Request<GetSandboxRequest>,
    ) -> Result<tonic::Response<openshell_core::proto::compute::v1::GetSandboxResponse>, Status>
    {
        let mut client = self.client();
        client.get_sandbox(request).await
    }

    async fn list_sandboxes(
        &self,
        request: Request<ListSandboxesRequest>,
    ) -> Result<tonic::Response<openshell_core::proto::compute::v1::ListSandboxesResponse>, Status>
    {
        let mut client = self.client();
        client.list_sandboxes(request).await
    }

    async fn create_sandbox(
        &self,
        request: Request<CreateSandboxRequest>,
    ) -> Result<tonic::Response<openshell_core::proto::compute::v1::CreateSandboxResponse>, Status>
    {
        let mut client = self.client();
        client.create_sandbox(request).await
    }

    async fn stop_sandbox(
        &self,
        request: Request<openshell_core::proto::compute::v1::StopSandboxRequest>,
    ) -> Result<tonic::Response<openshell_core::proto::compute::v1::StopSandboxResponse>, Status>
    {
        let mut client = self.client();
        client.stop_sandbox(request).await
    }

    async fn delete_sandbox(
        &self,
        request: Request<DeleteSandboxRequest>,
    ) -> Result<tonic::Response<openshell_core::proto::compute::v1::DeleteSandboxResponse>, Status>
    {
        let mut client = self.client();
        client.delete_sandbox(request).await
    }

    async fn watch_sandboxes(
        &self,
        request: Request<WatchSandboxesRequest>,
    ) -> Result<tonic::Response<Self::WatchSandboxesStream>, Status> {
        let mut client = self.client();
        let response = client.watch_sandboxes(request).await?;
        let stream = response.into_inner();
        Ok(tonic::Response::new(Box::pin(stream)))
    }
}

#[derive(Clone)]
pub struct ComputeRuntime {
    driver: SharedComputeDriver,
    driver_name: String,
    shutdown_cleanup: Option<Arc<dyn ShutdownCleanup>>,
    startup_resume: Option<Arc<dyn StartupResume>>,
    _driver_process: Option<Arc<ManagedDriverProcess>>,
    default_image: String,
    store: Arc<Store>,
    sandbox_index: SandboxIndex,
    sandbox_watch_bus: SandboxWatchBus,
    tracing_log_bus: TracingLogBus,
    supervisor_sessions: Arc<SupervisorSessionRegistry>,
    sync_lock: Arc<Mutex<()>>,
    gateway_bind_addresses: Vec<SocketAddr>,
    replica_id: String,
}

impl fmt::Debug for ComputeRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ComputeRuntime").finish_non_exhaustive()
    }
}

impl ComputeRuntime {
    #[allow(clippy::too_many_arguments)]
    async fn from_driver(
        driver_name: String,
        driver: SharedComputeDriver,
        shutdown_cleanup: Option<Arc<dyn ShutdownCleanup>>,
        startup_resume: Option<Arc<dyn StartupResume>>,
        driver_process: Option<Arc<ManagedDriverProcess>>,
        store: Arc<Store>,
        sandbox_index: SandboxIndex,
        sandbox_watch_bus: SandboxWatchBus,
        tracing_log_bus: TracingLogBus,
        supervisor_sessions: Arc<SupervisorSessionRegistry>,
        gateway_bind_addresses: Vec<SocketAddr>,
    ) -> Result<Self, ComputeError> {
        let capabilities = driver
            .get_capabilities(Request::new(GetCapabilitiesRequest {}))
            .await
            .map_err(compute_error_from_status)?
            .into_inner();
        let driver_kind = driver_name.parse::<ComputeDriverKind>().ok();
        info!(
            configured_driver = %driver_name,
            advertised_driver = %capabilities.driver_name,
            in_tree = driver_kind.is_some(),
            "Compute driver connected"
        );
        let default_image = capabilities.default_image;
        Ok(Self {
            driver,
            driver_name,
            shutdown_cleanup,
            startup_resume,
            _driver_process: driver_process,
            default_image,
            store,
            sandbox_index,
            sandbox_watch_bus,
            tracing_log_bus,
            supervisor_sessions,
            sync_lock: Arc::new(Mutex::new(())),
            gateway_bind_addresses,
            replica_id: lease::replica_id(),
        })
    }

    /// Serializes sandbox/provider-profile invariant checks and object writes
    /// within this gateway process.
    ///
    /// This is a temporary single-gateway guard for cross-object invariants.
    /// It is not HA-safe; replace it with DB-backed CAS/resource-version writes
    /// tracked by #1255 before enabling multiple gateway writers.
    pub(crate) async fn sandbox_sync_guard(&self) -> tokio::sync::OwnedMutexGuard<()> {
        self.sync_lock.clone().lock_owned().await
    }

    pub async fn new_docker(
        config: openshell_core::Config,
        docker_config: DockerComputeConfig,
        store: Arc<Store>,
        sandbox_index: SandboxIndex,
        sandbox_watch_bus: SandboxWatchBus,
        tracing_log_bus: TracingLogBus,
        supervisor_sessions: Arc<SupervisorSessionRegistry>,
    ) -> Result<Self, ComputeError> {
        let driver = Arc::new(
            DockerComputeDriver::new(&config, &docker_config, supervisor_sessions.clone())
                .await
                .map_err(|err| ComputeError::Message(err.to_string()))?,
        );
        let gateway_bind_addresses = driver.gateway_bind_addresses();
        let shutdown_cleanup: Arc<dyn ShutdownCleanup> = driver.clone();
        let startup_resume: Arc<dyn StartupResume> = driver.clone();
        let driver: SharedComputeDriver = driver;
        Self::from_driver(
            ComputeDriverKind::Docker.as_str().to_string(),
            driver,
            Some(shutdown_cleanup),
            Some(startup_resume),
            None,
            store,
            sandbox_index,
            sandbox_watch_bus,
            tracing_log_bus,
            supervisor_sessions,
            gateway_bind_addresses,
        )
        .await
    }

    pub async fn new_kubernetes(
        config: KubernetesComputeConfig,
        store: Arc<Store>,
        sandbox_index: SandboxIndex,
        sandbox_watch_bus: SandboxWatchBus,
        tracing_log_bus: TracingLogBus,
        supervisor_sessions: Arc<SupervisorSessionRegistry>,
    ) -> Result<Self, ComputeError> {
        let driver = KubernetesComputeDriver::new(config)
            .await
            .map_err(|err| ComputeError::Message(err.to_string()))?;
        let driver: SharedComputeDriver = Arc::new(KubernetesDriverService::new(driver));
        Self::from_driver(
            ComputeDriverKind::Kubernetes.as_str().to_string(),
            driver,
            None,
            None,
            None,
            store,
            sandbox_index,
            sandbox_watch_bus,
            tracing_log_bus,
            supervisor_sessions,
            Vec::new(),
        )
        .await
    }

    pub(crate) async fn new_remote_driver(
        endpoint: AcquiredRemoteDriverEndpoint,
        store: Arc<Store>,
        sandbox_index: SandboxIndex,
        sandbox_watch_bus: SandboxWatchBus,
        tracing_log_bus: TracingLogBus,
        supervisor_sessions: Arc<SupervisorSessionRegistry>,
    ) -> Result<Self, ComputeError> {
        let driver: SharedComputeDriver = Arc::new(RemoteComputeDriver::new(endpoint.channel));
        Self::from_driver(
            endpoint.name,
            driver,
            None,
            None,
            endpoint.driver_process,
            store,
            sandbox_index,
            sandbox_watch_bus,
            tracing_log_bus,
            supervisor_sessions,
            Vec::new(),
        )
        .await
    }

    pub async fn new_podman(
        config: PodmanComputeConfig,
        store: Arc<Store>,
        sandbox_index: SandboxIndex,
        sandbox_watch_bus: SandboxWatchBus,
        tracing_log_bus: TracingLogBus,
        supervisor_sessions: Arc<SupervisorSessionRegistry>,
    ) -> Result<Self, ComputeError> {
        let driver = PodmanComputeDriver::new(config)
            .await
            .map_err(|err| ComputeError::Message(err.to_string()))?;
        let driver: SharedComputeDriver = Arc::new(PodmanDriverService::new(driver));
        Self::from_driver(
            ComputeDriverKind::Podman.as_str().to_string(),
            driver,
            None,
            None,
            None,
            store,
            sandbox_index,
            sandbox_watch_bus,
            tracing_log_bus,
            supervisor_sessions,
            Vec::new(),
        )
        .await
    }

    #[must_use]
    pub fn default_image(&self) -> &str {
        &self.default_image
    }

    #[must_use]
    pub fn driver_kind(&self) -> Option<ComputeDriverKind> {
        self.driver_name.parse().ok()
    }

    #[must_use]
    pub fn gateway_bind_addresses(&self) -> &[SocketAddr] {
        &self.gateway_bind_addresses
    }

    pub async fn validate_sandbox_create(&self, sandbox: &Sandbox) -> Result<(), Status> {
        let driver_sandbox =
            driver_sandbox_from_public(sandbox, &self.driver_name).map_err(|status| *status)?;
        self.driver
            .validate_sandbox_create(Request::new(ValidateSandboxCreateRequest {
                sandbox: Some(driver_sandbox),
            }))
            .await
            .map(|_| ())
    }

    pub async fn create_sandbox(
        &self,
        sandbox: Sandbox,
        sandbox_token: Option<String>,
    ) -> Result<Sandbox, Status> {
        let sandbox_id = sandbox.object_id().to_string();
        let mut driver_sandbox =
            driver_sandbox_from_public(&sandbox, &self.driver_name).map_err(|status| *status)?;

        // Create with MustCreate condition to prevent duplicate creation race
        self.sandbox_index.update_from_sandbox(&sandbox);
        let mut sandbox = sandbox;
        let result = self
            .store
            .put_if(
                Sandbox::object_type(),
                &sandbox_id,
                sandbox.object_name(),
                &sandbox.encode_to_vec(),
                None,
                WriteCondition::MustCreate,
            )
            .await
            .map_err(|e| {
                if matches!(
                    e,
                    crate::persistence::PersistenceError::UniqueViolation { .. }
                ) {
                    Status::already_exists(format!(
                        "sandbox '{}' already exists",
                        sandbox.object_name()
                    ))
                } else {
                    Status::internal(format!("persist sandbox failed: {e}"))
                }
            })?;

        if let Some(token) = sandbox_token
            && let Some(spec) = driver_sandbox.spec.as_mut()
        {
            spec.sandbox_token = token;
        }
        match self
            .driver
            .create_sandbox(Request::new(CreateSandboxRequest {
                sandbox: Some(driver_sandbox),
            }))
            .await
        {
            Ok(_) => {
                self.sandbox_watch_bus.notify(sandbox.object_id());
                if let Some(metadata) = sandbox.metadata.as_mut() {
                    metadata.resource_version = result.resource_version;
                }
                Ok(sandbox)
            }
            Err(status) if status.code() == Code::AlreadyExists => {
                let _ = self
                    .store
                    .delete(Sandbox::object_type(), sandbox.object_id())
                    .await;
                self.sandbox_index.remove_sandbox(sandbox.object_id());
                Err(Status::already_exists("sandbox already exists"))
            }
            Err(status) if status.code() == Code::FailedPrecondition => {
                let _ = self
                    .store
                    .delete(Sandbox::object_type(), sandbox.object_id())
                    .await;
                self.sandbox_index.remove_sandbox(sandbox.object_id());
                Err(Status::failed_precondition(status.message().to_string()))
            }
            Err(err) => {
                let _ = self
                    .store
                    .delete(Sandbox::object_type(), sandbox.object_id())
                    .await;
                self.sandbox_index.remove_sandbox(sandbox.object_id());
                Err(Status::internal(format!(
                    "create sandbox failed: {}",
                    err.message()
                )))
            }
        }
    }

    pub async fn delete_sandbox(&self, name: &str) -> Result<bool, Status> {
        let _guard = self.sync_lock.lock().await;

        // Resolve sandbox ID from name
        let sandbox = self
            .store
            .get_message_by_name::<Sandbox>(name)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?;

        let Some(sandbox) = sandbox else {
            return Err(Status::not_found("sandbox not found"));
        };

        let id = sandbox.object_id().to_string();

        let sandbox = self.set_sandbox_phase_deleting_with_retry(&id).await?;

        self.sandbox_index.update_from_sandbox(&sandbox);
        self.sandbox_watch_bus.notify(&id);
        self.cleanup_sandbox_owned_records(&sandbox).await;

        let deleted = self
            .driver
            .delete_sandbox(Request::new(DeleteSandboxRequest {
                sandbox_id: sandbox.object_id().to_string(),
                sandbox_name: sandbox.object_name().to_string(),
            }))
            .await
            .map(|response| response.into_inner().deleted)
            .map_err(|err| Status::internal(format!("delete sandbox failed: {}", err.message())))?;

        if !deleted && let Err(e) = self.store.delete(Sandbox::object_type(), &id).await {
            warn!(sandbox_id = %id, error = %e, "Failed to clean up store after delete");
        }

        self.cleanup_sandbox_state(&id);
        Ok(deleted)
    }

    async fn set_sandbox_phase_deleting_with_retry(
        &self,
        sandbox_id: &str,
    ) -> Result<Sandbox, Status> {
        self.set_sandbox_phase_deleting_with_initial_snapshot(sandbox_id, None)
            .await
    }

    async fn set_sandbox_phase_deleting_with_initial_snapshot(
        &self,
        sandbox_id: &str,
        mut initial_snapshot: Option<Sandbox>,
    ) -> Result<Sandbox, Status> {
        let operation = "set sandbox phase to Deleting";

        for attempt in 1..=DELETE_PHASE_CAS_RETRY_LIMIT {
            let sandbox = match initial_snapshot.take() {
                Some(sandbox) => sandbox,
                None => self
                    .store
                    .get_message::<Sandbox>(sandbox_id)
                    .await
                    .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
                    .ok_or_else(|| Status::not_found("sandbox not found"))?,
            };

            match self
                .write_sandbox_phase_deleting_from_snapshot(sandbox)
                .await
            {
                Ok(sandbox) => {
                    if attempt > 1 {
                        debug!(
                            sandbox_id,
                            attempt, "Retried sandbox delete phase transition after CAS conflict"
                        );
                    }
                    return Ok(sandbox);
                }
                Err(crate::persistence::PersistenceError::Conflict {
                    current_resource_version,
                }) => {
                    let err = crate::persistence::PersistenceError::Conflict {
                        current_resource_version,
                    };
                    if attempt == DELETE_PHASE_CAS_RETRY_LIMIT {
                        return Err(crate::grpc::persistence_error_to_status(err, operation));
                    }
                    debug!(
                        sandbox_id,
                        attempt,
                        current_resource_version,
                        "Sandbox delete phase transition conflicted; retrying"
                    );
                    tokio::task::yield_now().await;
                }
                Err(err) => return Err(crate::grpc::persistence_error_to_status(err, operation)),
            }
        }

        unreachable!("delete phase retry loop always returns")
    }

    async fn write_sandbox_phase_deleting_from_snapshot(
        &self,
        mut sandbox: Sandbox,
    ) -> crate::persistence::PersistenceResult<Sandbox> {
        let id = sandbox.object_id().to_string();
        let name = sandbox.object_name().to_string();
        let expected_resource_version = sandbox
            .metadata
            .as_ref()
            .map_or(0, |metadata| metadata.resource_version);

        sandbox.set_phase(SandboxPhase::Deleting as i32);

        let labels_json = sandbox
            .metadata
            .as_ref()
            .map(|metadata| &metadata.labels)
            .filter(|labels| !labels.is_empty())
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| {
                crate::persistence::PersistenceError::Encode(format!(
                    "failed to serialize labels: {e}"
                ))
            })?;

        let result = self
            .store
            .put_if(
                Sandbox::object_type(),
                &id,
                &name,
                &sandbox.encode_to_vec(),
                labels_json.as_deref(),
                WriteCondition::MatchResourceVersion(expected_resource_version),
            )
            .await?;

        if let Some(metadata) = sandbox.metadata.as_mut() {
            metadata.resource_version = result.resource_version;
        }

        Ok(sandbox)
    }

    pub fn spawn_watchers(&self, shutdown_rx: watch::Receiver<bool>) {
        let runtime = Arc::new(self.clone());
        if self.store.is_single_replica() {
            let watch_runtime = runtime.clone();
            let watch_shutdown = shutdown_rx.clone();
            tokio::spawn(async move {
                watch_runtime.watch_loop(watch_shutdown).await;
            });
            tokio::spawn(async move {
                runtime.reconcile_loop(shutdown_rx).await;
            });
        } else {
            tokio::spawn(async move {
                runtime.lease_coordinator(shutdown_rx).await;
            });
        }
    }

    pub async fn cleanup_on_shutdown(&self) -> Result<(), String> {
        let Some(cleanup) = &self.shutdown_cleanup else {
            return Ok(());
        };
        cleanup.cleanup_on_shutdown().await
    }

    /// Resume sandboxes whose store records say they should be running.
    /// Drivers that do not auto-restart compute resources across gateway
    /// restarts (currently only Docker) implement `StartupResume`. For
    /// each sandbox in the store whose phase is not `Deleting` or
    /// `Error`, we ask the driver to resume the underlying resource. If
    /// the driver reports that the resource no longer exists or fails to
    /// start, the sandbox is moved to the `Error` phase so the failure
    /// surfaces in the UI.
    ///
    /// Should be called once at gateway startup, before watchers spawn,
    /// so the watch loop sees the post-resume state on its first poll.
    pub async fn resume_persisted_sandboxes(&self) -> Result<(), String> {
        let Some(resume) = &self.startup_resume else {
            return Ok(());
        };

        let records = self
            .store
            .list(Sandbox::object_type(), 1000, 0)
            .await
            .map_err(|e| e.to_string())?;

        let mut resumed = 0usize;
        let mut missing = 0usize;
        let mut failed = 0usize;

        for record in records {
            let sandbox = match Sandbox::decode(record.payload.as_slice()) {
                Ok(sandbox) => sandbox,
                Err(err) => {
                    warn!(error = %err, "Failed to decode sandbox record during startup resume");
                    continue;
                }
            };

            let phase = SandboxPhase::try_from(sandbox.phase()).unwrap_or(SandboxPhase::Unknown);
            if !sandbox_phase_should_be_running(phase) {
                continue;
            }

            match resume
                .resume_sandbox(sandbox.object_id(), sandbox.object_name())
                .await
            {
                Ok(true) => {
                    info!(
                        sandbox_id = %sandbox.object_id(),
                        sandbox_name = %sandbox.object_name(),
                        ?phase,
                        "Resumed sandbox during gateway startup"
                    );
                    resumed += 1;
                }
                Ok(false) => {
                    // Backend resource is gone but the store still
                    // remembers the sandbox. Mark Error so the UI
                    // surfaces the inconsistency; the reconcile loop
                    // will eventually prune it after the orphan grace
                    // period.
                    warn!(
                        sandbox_id = %sandbox.object_id(),
                        sandbox_name = %sandbox.object_name(),
                        "Cannot resume sandbox: backend resource is missing"
                    );
                    self.mark_sandbox_error(
                        &sandbox,
                        "BackendResourceMissing",
                        "Sandbox container disappeared while the gateway was offline",
                    )
                    .await;
                    missing += 1;
                }
                Err(err) => {
                    warn!(
                        sandbox_id = %sandbox.object_id(),
                        sandbox_name = %sandbox.object_name(),
                        error = %err,
                        "Failed to resume sandbox during gateway startup"
                    );
                    self.mark_sandbox_error(
                        &sandbox,
                        "ResumeFailed",
                        &format!("Failed to resume sandbox during gateway startup: {err}"),
                    )
                    .await;
                    failed += 1;
                }
            }
        }

        if resumed > 0 || missing > 0 || failed > 0 {
            info!(
                resumed,
                missing_backend = missing,
                failed,
                "Sandbox resume sweep complete"
            );
        }
        Ok(())
    }

    async fn mark_sandbox_error(&self, sandbox: &Sandbox, reason: &str, message: &str) {
        let _guard = self.sync_lock.lock().await;
        let sandbox_id = sandbox.object_id().to_string();
        let reason = reason.to_string();
        let message = message.to_string();
        match self
            .store
            .update_message_cas::<Sandbox, _>(&sandbox_id, 0, |s| {
                s.set_phase(SandboxPhase::Error as i32);
                let name = s.object_name().to_string();
                upsert_ready_condition(
                    &mut s.status,
                    &name,
                    SandboxCondition {
                        r#type: "Ready".to_string(),
                        status: "False".to_string(),
                        reason: reason.clone(),
                        message: message.clone(),
                        last_transition_time: String::new(),
                    },
                );
            })
            .await
        {
            Ok(updated) => {
                self.sandbox_index.update_from_sandbox(&updated);
                self.sandbox_watch_bus.notify(&sandbox_id);
            }
            Err(err) => {
                warn!(
                    sandbox_id = %sandbox_id,
                    error = %err,
                    "Failed to persist sandbox error state during startup resume"
                );
            }
        }
    }

    async fn lease_coordinator(self: Arc<Self>, mut shutdown_rx: watch::Receiver<bool>) {
        use lease::{LEASE_ACQUIRE_INTERVAL, LEASE_TTL, ReconcilerLease};

        let lease = ReconcilerLease::new(self.store.clone(), self.replica_id.clone(), LEASE_TTL);
        info!(replica = %lease.replica_id(), "reconciler lease coordinator started");

        loop {
            if *shutdown_rx.borrow() {
                break;
            }

            match lease.acquire_or_steal().await {
                Ok(guard) => {
                    info!(replica = %lease.replica_id(), "acquired reconciler lease");
                    self.run_as_holder(&lease, guard, &mut shutdown_rx).await;
                }
                Err(e) => {
                    debug!(
                        replica = %lease.replica_id(),
                        error = %e,
                        "reconciler lease acquisition attempt failed"
                    );
                    tokio::select! {
                        () = tokio::time::sleep(LEASE_ACQUIRE_INTERVAL) => {}
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                break;
                            }
                        }
                    }
                }
            }
        }

        info!(replica = %lease.replica_id(), "reconciler lease coordinator stopped");
    }

    async fn run_as_holder(
        self: &Arc<Self>,
        lease: &lease::ReconcilerLease,
        mut guard: lease::LeaseGuard,
        shutdown_rx: &mut watch::Receiver<bool>,
    ) {
        use lease::LEASE_RENEWAL_INTERVAL;

        let (cancel_tx, cancel_rx) = watch::channel(false);

        let runtime = self.clone();
        let watch_cancel = cancel_rx.clone();
        let watch_handle = tokio::spawn(async move {
            runtime.watch_loop(watch_cancel).await;
        });

        let runtime = self.clone();
        let reconcile_handle = tokio::spawn(async move {
            runtime.reconcile_loop(cancel_rx).await;
        });

        loop {
            tokio::select! {
                () = tokio::time::sleep(LEASE_RENEWAL_INTERVAL) => {
                    match lease.renew(&mut guard).await {
                        Ok(()) => {
                            debug!(replica = %lease.replica_id(), "renewed reconciler lease");
                        }
                        Err(e) => {
                            warn!(
                                replica = %lease.replica_id(),
                                error = %e,
                                "reconciler lease renewal failed — releasing holder role"
                            );
                            break;
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!(replica = %lease.replica_id(), "shutdown — releasing reconciler lease");
                        if let Err(e) = lease.release(guard).await {
                            warn!(error = %e, "failed to release reconciler lease on shutdown");
                        }
                        let _ = cancel_tx.send(true);
                        let _ = watch_handle.await;
                        let _ = reconcile_handle.await;
                        return;
                    }
                }
            }
        }

        let _ = cancel_tx.send(true);
        let _ = watch_handle.await;
        let _ = reconcile_handle.await;
        info!(replica = %lease.replica_id(), "reconciler lease lost — returning to standby");
    }

    async fn watch_loop(self: Arc<Self>, mut cancel: watch::Receiver<bool>) {
        loop {
            let mut stream = match self
                .driver
                .watch_sandboxes(Request::new(WatchSandboxesRequest {}))
                .await
            {
                Ok(response) => response.into_inner(),
                Err(err) => {
                    warn!(error = %err, "Compute driver watch stream failed to start");
                    tokio::select! {
                        () = tokio::time::sleep(Duration::from_secs(2)) => {}
                        _ = cancel.changed() => return,
                    }
                    continue;
                }
            };

            let mut restart = false;
            loop {
                tokio::select! {
                    item = stream.next() => {
                        match item {
                            Some(Ok(event)) => {
                                if let Err(err) = self.apply_watch_event(event).await {
                                    warn!(error = %err, "Failed to apply compute driver event");
                                }
                            }
                            Some(Err(err)) => {
                                warn!(error = %err, "Compute driver watch stream errored");
                                restart = true;
                                break;
                            }
                            None => break,
                        }
                    }
                    _ = cancel.changed() => return,
                }
            }

            if !restart {
                warn!("Compute driver watch stream ended unexpectedly");
            }
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs(2)) => {}
                _ = cancel.changed() => return,
            }
        }
    }

    async fn reconcile_loop(self: Arc<Self>, mut cancel: watch::Receiver<bool>) {
        loop {
            if let Err(err) = self.reconcile_store_with_backend(ORPHAN_GRACE_PERIOD).await {
                warn!(error = %err, "Store reconciliation sweep failed");
            }
            tokio::select! {
                () = tokio::time::sleep(RECONCILE_INTERVAL) => {}
                _ = cancel.changed() => return,
            }
        }
    }

    async fn reconcile_store_with_backend(&self, grace_period: Duration) -> Result<(), String> {
        let sweep_started_at_ms = openshell_core::time::now_ms();
        let backend_sandboxes = self
            .driver
            .list_sandboxes(Request::new(ListSandboxesRequest {}))
            .await
            .map_err(|e| e.to_string())?
            .into_inner()
            .sandboxes;
        let backend_ids = backend_sandboxes
            .iter()
            .map(|sandbox| sandbox.id.clone())
            .collect::<std::collections::HashSet<_>>();

        for sandbox in backend_sandboxes {
            self.reconcile_snapshot_sandbox(sandbox, sweep_started_at_ms)
                .await?;
        }

        let records = self
            .store
            .list(Sandbox::object_type(), 500, 0)
            .await
            .map_err(|e| e.to_string())?;

        let grace_ms = grace_period.as_millis().try_into().unwrap_or(i64::MAX);

        for record in records {
            let sandbox = match Sandbox::decode(record.payload.as_slice()) {
                Ok(sandbox) => sandbox,
                Err(err) => {
                    warn!(error = %err, "Failed to decode sandbox record during reconciliation");
                    continue;
                }
            };

            if backend_ids.contains(sandbox.object_id()) {
                continue;
            }

            self.prune_missing_sandbox(record, sweep_started_at_ms, grace_ms)
                .await?;
        }

        Ok(())
    }

    async fn apply_watch_event(&self, event: WatchSandboxesEvent) -> Result<(), String> {
        match event.payload {
            Some(watch_sandboxes_event::Payload::Sandbox(sandbox)) => {
                if let Some(sandbox) = sandbox.sandbox {
                    self.apply_sandbox_update(sandbox).await?;
                }
            }
            Some(watch_sandboxes_event::Payload::Deleted(deleted)) => {
                self.apply_deleted(&deleted.sandbox_id).await?;
            }
            Some(watch_sandboxes_event::Payload::PlatformEvent(platform_event)) => {
                if let Some(event) = platform_event.event {
                    self.tracing_log_bus.platform_event_bus.publish(
                        &platform_event.sandbox_id,
                        openshell_core::proto::SandboxStreamEvent {
                            payload: Some(
                                openshell_core::proto::sandbox_stream_event::Payload::Event(
                                    public_platform_event_from_driver(&event),
                                ),
                            ),
                        },
                    );
                }
            }
            None => {}
        }
        Ok(())
    }

    async fn apply_sandbox_update(&self, incoming: DriverSandbox) -> Result<(), String> {
        let _guard = self.sync_lock.lock().await;
        let existing = self
            .store
            .get(Sandbox::object_type(), &incoming.id)
            .await
            .map_err(|e| e.to_string())?;
        self.apply_sandbox_update_locked(incoming, existing).await
    }

    async fn apply_sandbox_update_locked(
        &self,
        incoming: DriverSandbox,
        existing_record: Option<ObjectRecord>,
    ) -> Result<(), String> {
        let existing = existing_record
            .as_ref()
            .map(decode_sandbox_record)
            .transpose()?;

        // If no existing record, create initial sandbox (first watch event for this sandbox)
        if existing.is_none() {
            use crate::persistence::WriteCondition;
            let now_ms = openshell_core::time::now_ms();

            let session_connected = self.supervisor_sessions.has_session(&incoming.id);
            let mut phase = derive_phase(incoming.status.as_ref());
            let sandbox_name = incoming.name.clone();

            let supervisor_promoted = session_connected
                && matches!(phase, SandboxPhase::Provisioning | SandboxPhase::Unknown);
            if supervisor_promoted {
                phase = SandboxPhase::Ready;
            }

            let mut status = incoming
                .status
                .as_ref()
                .map(|s| public_status_from_driver(s, phase, 0));
            rewrite_user_facing_conditions(&mut status, None);
            if supervisor_promoted {
                ensure_supervisor_ready_status(&mut status, &sandbox_name);
            }
            let mut sandbox = Sandbox {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: incoming.id.clone(),
                    name: sandbox_name,
                    created_at_ms: now_ms,
                    labels: std::collections::HashMap::new(),
                    resource_version: 0,
                }),
                spec: None,
                status,
            };
            sandbox.set_phase(phase as i32);

            self.store
                .put_if(
                    Sandbox::object_type(),
                    &incoming.id,
                    sandbox.object_name(),
                    &sandbox.encode_to_vec(),
                    None,
                    WriteCondition::MustCreate,
                )
                .await
                .map_err(|e| match e {
                    crate::persistence::PersistenceError::Conflict {
                        current_resource_version,
                    } => format!(
                        "concurrent modification detected during sandbox creation (current resource_version: {})",
                        current_resource_version
                            .map_or_else(|| "unknown".to_string(), |v| v.to_string())
                    ),
                    other => other.to_string(),
                })?;

            self.sandbox_index.update_from_sandbox(&sandbox);
            self.sandbox_watch_bus.notify(sandbox.object_id());
            return Ok(());
        }

        // Single-attempt CAS: on conflict, the next watch event will naturally retry
        let session_connected = self.supervisor_sessions.has_session(&incoming.id);
        let sandbox_name = incoming.name.clone();

        let sandbox = self
            .store
            .update_message_cas::<Sandbox, _>(&incoming.id, 0, |sandbox| {
                let old_phase =
                    SandboxPhase::try_from(sandbox.phase()).unwrap_or(SandboxPhase::Unknown);
                let mut phase = incoming
                    .status
                    .as_ref()
                    .map_or(old_phase, |status| derive_phase(Some(status)));
                let supervisor_promoted = session_connected
                    && matches!(phase, SandboxPhase::Provisioning | SandboxPhase::Unknown);
                if supervisor_promoted {
                    phase = SandboxPhase::Ready;
                }

                let cpv = sandbox.current_policy_version();
                let mut status = incoming
                    .status
                    .as_ref()
                    .map(|s| public_status_from_driver(s, phase, cpv))
                    .or_else(|| sandbox.status.clone());
                rewrite_user_facing_conditions(&mut status, sandbox.spec.as_ref());
                if supervisor_promoted {
                    ensure_supervisor_ready_status(&mut status, &sandbox_name);
                }

                if let Some(s) = status.as_mut()
                    && s.sandbox_name.is_empty()
                {
                    s.sandbox_name.clone_from(&sandbox_name);
                }

                if old_phase != phase {
                    info!(
                        sandbox_id = %incoming.id,
                        sandbox_name = %sandbox_name,
                        old_phase = ?old_phase,
                        new_phase = ?phase,
                        "Sandbox phase changed"
                    );
                }

                if phase == SandboxPhase::Error
                    && let Some(ref status) = status
                {
                    for condition in &status.conditions {
                        if condition.r#type == "Ready"
                            && condition.status.eq_ignore_ascii_case("false")
                            && is_terminal_failure_reason(&condition.reason)
                        {
                            warn!(
                                sandbox_id = %incoming.id,
                                sandbox_name = %sandbox_name,
                                reason = %condition.reason,
                                message = %condition.message,
                                "Sandbox failed to become ready"
                            );
                        }
                    }
                }

                // Update metadata fields
                if let Some(metadata) = sandbox.metadata.as_mut() {
                    metadata.name.clone_from(&sandbox_name);
                }
                sandbox.status = status;
                sandbox.set_phase(phase as i32);
                sandbox.set_current_policy_version(cpv);
            })
            .await
            .map_err(|e| match e {
                crate::persistence::PersistenceError::Conflict {
                    current_resource_version,
                } => format!(
                    "concurrent modification detected during sandbox reconciliation (current resource_version: {})",
                    current_resource_version
                        .map_or_else(|| "unknown".to_string(), |v| v.to_string())
                ),
                other => other.to_string(),
            })?;

        self.sandbox_index.update_from_sandbox(&sandbox);
        self.sandbox_watch_bus.notify(sandbox.object_id());
        Ok(())
    }

    pub async fn supervisor_session_connected(&self, sandbox_id: &str) -> Result<(), String> {
        self.set_supervisor_session_state(sandbox_id, true).await
    }

    pub async fn supervisor_session_disconnected(&self, sandbox_id: &str) -> Result<(), String> {
        self.set_supervisor_session_state(sandbox_id, false).await
    }

    async fn set_supervisor_session_state(
        &self,
        sandbox_id: &str,
        connected: bool,
    ) -> Result<(), String> {
        let _guard = self.sync_lock.lock().await;

        // Use CAS to update sandbox phase based on supervisor session state
        let result = self
            .store
            .update_message_cas::<Sandbox, _>(sandbox_id, 0, |sandbox| {
                let current_phase =
                    SandboxPhase::try_from(sandbox.phase()).unwrap_or(SandboxPhase::Unknown);

                // Skip if sandbox is in terminal state
                if current_phase == SandboxPhase::Deleting || current_phase == SandboxPhase::Error {
                    return;
                }

                let sandbox_name = sandbox.object_name().to_string();
                if connected {
                    ensure_supervisor_ready_status(&mut sandbox.status, &sandbox_name);
                    sandbox.set_phase(SandboxPhase::Ready as i32);
                } else if current_phase == SandboxPhase::Ready {
                    ensure_supervisor_not_ready_status(&mut sandbox.status, &sandbox_name);
                    sandbox.set_phase(SandboxPhase::Provisioning as i32);
                }
            })
            .await;

        // Handle not found gracefully (sandbox may have been deleted)
        let sandbox = match result {
            Ok(s) => s,
            Err(crate::persistence::PersistenceError::Database(ref msg))
                if msg.contains("not found") =>
            {
                return Ok(());
            }
            Err(crate::persistence::PersistenceError::Conflict {
                current_resource_version,
            }) => {
                return Err(format!(
                    "concurrent modification detected (current resource_version: {})",
                    current_resource_version
                        .map_or_else(|| "unknown".to_string(), |v| v.to_string())
                ));
            }
            Err(e) => return Err(e.to_string()),
        };

        self.sandbox_index.update_from_sandbox(&sandbox);
        self.sandbox_watch_bus.notify(sandbox_id);
        Ok(())
    }

    async fn apply_deleted(&self, sandbox_id: &str) -> Result<(), String> {
        let _guard = self.sync_lock.lock().await;
        self.apply_deleted_locked(sandbox_id).await
    }

    async fn apply_deleted_locked(&self, sandbox_id: &str) -> Result<(), String> {
        let sandbox = self
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .map_err(|e| e.to_string())?;
        if let Some(sandbox) = sandbox.as_ref() {
            self.cleanup_sandbox_owned_records(sandbox).await;
        }

        let _ = self
            .store
            .delete(Sandbox::object_type(), sandbox_id)
            .await
            .map_err(|e| e.to_string())?;
        self.sandbox_index.remove_sandbox(sandbox_id);
        self.sandbox_watch_bus.notify(sandbox_id);
        self.cleanup_sandbox_state(sandbox_id);
        Ok(())
    }

    async fn cleanup_sandbox_owned_records(&self, sandbox: &Sandbox) {
        self.cleanup_sandbox_ssh_sessions(sandbox.object_id()).await;

        if let Err(e) = self
            .store
            .delete_by_name(SANDBOX_SETTINGS_OBJECT_TYPE, sandbox.object_name())
            .await
        {
            warn!(
                sandbox_id = %sandbox.object_id(),
                sandbox_name = %sandbox.object_name(),
                error = %e,
                "Failed to delete sandbox settings during cleanup"
            );
        }
    }

    async fn cleanup_sandbox_ssh_sessions(&self, sandbox_id: &str) {
        if let Ok(records) = self.store.list(SshSession::object_type(), 1000, 0).await {
            for record in records {
                if let Ok(session) = SshSession::decode(record.payload.as_slice())
                    && session.sandbox_id == sandbox_id
                    && let Err(e) = self
                        .store
                        .delete(SshSession::object_type(), session.object_id())
                        .await
                {
                    warn!(
                        sandbox_id = %sandbox_id,
                        session_id = %session.object_id(),
                        error = %e,
                        "Failed to delete SSH session during sandbox cleanup"
                    );
                }
            }
        }
    }

    fn cleanup_sandbox_state(&self, sandbox_id: &str) {
        self.tracing_log_bus.remove(sandbox_id);
        self.tracing_log_bus.platform_event_bus.remove(sandbox_id);
        self.sandbox_watch_bus.remove(sandbox_id);
    }

    async fn reconcile_snapshot_sandbox(
        &self,
        snapshot: DriverSandbox,
        sweep_started_at_ms: i64,
    ) -> Result<(), String> {
        let _guard = self.sync_lock.lock().await;
        let Some(existing) = self
            .store
            .get(Sandbox::object_type(), &snapshot.id)
            .await
            .map_err(|e| e.to_string())?
        else {
            return Ok(());
        };

        if existing.updated_at_ms > sweep_started_at_ms {
            return Ok(());
        }

        let Some(current) = self
            .get_driver_sandbox(&snapshot.id, &snapshot.name)
            .await?
        else {
            return Ok(());
        };

        self.apply_sandbox_update_locked(current, Some(existing))
            .await
    }

    async fn prune_missing_sandbox(
        &self,
        record: ObjectRecord,
        sweep_started_at_ms: i64,
        grace_ms: i64,
    ) -> Result<(), String> {
        let _guard = self.sync_lock.lock().await;
        let Some(current_record) = self
            .store
            .get(Sandbox::object_type(), &record.id)
            .await
            .map_err(|e| e.to_string())?
        else {
            return Ok(());
        };

        if current_record.updated_at_ms > sweep_started_at_ms {
            return Ok(());
        }

        let sandbox = decode_sandbox_record(&current_record)?;
        let age_ms = openshell_core::time::now_ms().saturating_sub(current_record.created_at_ms);
        if age_ms < grace_ms {
            return Ok(());
        }

        if let Some(current) = self
            .get_driver_sandbox(sandbox.object_id(), sandbox.object_name())
            .await?
        {
            return self
                .apply_sandbox_update_locked(current, Some(current_record))
                .await;
        }

        info!(
            sandbox_id = %sandbox.object_id(),
            sandbox_name = %sandbox.object_name(),
            age_secs = age_ms / 1000,
            "Removing sandbox from store after it disappeared from the compute driver snapshot"
        );
        self.apply_deleted_locked(sandbox.object_id()).await
    }

    async fn get_driver_sandbox(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<Option<DriverSandbox>, String> {
        match self
            .driver
            .get_sandbox(Request::new(GetSandboxRequest {
                sandbox_id: sandbox_id.to_string(),
                sandbox_name: sandbox_name.to_string(),
            }))
            .await
        {
            Ok(response) => Ok(response.into_inner().sandbox),
            Err(status) if status.code() == Code::NotFound => Ok(None),
            Err(status) => Err(status.to_string()),
        }
    }
}

/// Connect to an unmanaged remote compute driver that is already listening on
/// `socket_path` and return the acquired endpoint.
///
/// The gateway does not spawn or own the driver process — the operator is
/// responsible for placing the driver alongside the gateway and granting the
/// gateway uid read/write on the socket. The host portion of the URL is
/// ignored because the connector resolves to the UDS rather than DNS.
#[cfg(unix)]
pub async fn connect_remote_compute_driver(
    name: impl Into<String>,
    socket_path: &Path,
) -> Result<AcquiredRemoteDriverEndpoint, ComputeError> {
    let socket_path: PathBuf = socket_path.to_path_buf();
    let display_path = socket_path.clone();
    let channel = Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(service_fn(move |_: tonic::transport::Uri| {
            let socket_path = socket_path.clone();
            async move { UnixStream::connect(socket_path).await.map(TokioIo::new) }
        }))
        .await
        .map_err(|e| {
            ComputeError::Message(format!(
                "failed to connect to remote compute driver socket '{}': {e}",
                display_path.display()
            ))
        })?;
    Ok(AcquiredRemoteDriverEndpoint::unmanaged(name, channel))
}

#[cfg(not(unix))]
pub async fn connect_remote_compute_driver(
    _name: impl Into<String>,
    _socket_path: &Path,
) -> Result<AcquiredRemoteDriverEndpoint, ComputeError> {
    Err(ComputeError::Message(
        "remote compute driver endpoints require unix domain socket support".to_string(),
    ))
}

fn driver_sandbox_from_public(
    sandbox: &Sandbox,
    driver_name: &str,
) -> Result<DriverSandbox, Box<Status>> {
    Ok(DriverSandbox {
        id: sandbox.object_id().to_string(),
        name: sandbox.object_name().to_string(),
        namespace: String::new(), // Namespace is set by the driver based on its config
        spec: sandbox
            .spec
            .as_ref()
            .map(|spec| driver_sandbox_spec_from_public(spec, driver_name))
            .transpose()?,
        status: sandbox.status.as_ref().map(driver_status_from_public),
    })
}

fn driver_sandbox_spec_from_public(
    spec: &SandboxSpec,
    driver_name: &str,
) -> Result<DriverSandboxSpec, Box<Status>> {
    Ok(DriverSandboxSpec {
        log_level: spec.log_level.clone(),
        environment: spec.environment.clone(),
        template: spec
            .template
            .as_ref()
            .map(|template| driver_sandbox_template_from_public(template, driver_name))
            .transpose()?,
        resource_requirements: spec.resource_requirements.as_ref().map(|requirements| {
            DriverSandboxResourceRequirements {
                gpu: requirements
                    .gpu
                    .as_ref()
                    .map(|gpu| DriverGpuResourceRequirements { count: gpu.count }),
            }
        }),
        sandbox_token: String::new(),
    })
}

fn driver_sandbox_template_from_public(
    template: &SandboxTemplate,
    driver_name: &str,
) -> Result<DriverSandboxTemplate, Box<Status>> {
    Ok(DriverSandboxTemplate {
        image: template.image.clone(),
        agent_socket_path: template.agent_socket.clone(),
        labels: template.labels.clone(),
        environment: template.environment.clone(),
        resources: extract_typed_resources(&template.resources),
        platform_config: build_platform_config(template),
        driver_config: select_driver_config(&template.driver_config, driver_name)?,
    })
}

fn select_driver_config(
    config: &Option<prost_types::Struct>,
    driver_name: &str,
) -> Result<Option<prost_types::Struct>, Box<Status>> {
    let Some(config) = config else {
        return Ok(None);
    };
    let Some(value) = config.fields.get(driver_name) else {
        return Ok(None);
    };
    match value.kind.as_ref() {
        Some(prost_types::value::Kind::StructValue(inner)) => Ok(Some(inner.clone())),
        _ => Err(Box::new(Status::invalid_argument(format!(
            "template.driver_config.{driver_name} must be an object"
        )))),
    }
}

/// Extract typed CPU/memory quantities from the public `resources` Struct.
///
/// The public API exposes resources as an untyped `google.protobuf.Struct`
/// with the Kubernetes limits/requests shape. We pull out the well-known
/// keys into the typed `DriverResourceRequirements` message.
fn extract_typed_resources(
    resources: &Option<prost_types::Struct>,
) -> Option<DriverResourceRequirements> {
    fn get_quantity(s: &prost_types::Struct, section: &str, key: &str) -> String {
        s.fields
            .get(section)
            .and_then(|v| match v.kind.as_ref() {
                Some(prost_types::value::Kind::StructValue(inner)) => inner.fields.get(key),
                _ => None,
            })
            .and_then(|v| match v.kind.as_ref() {
                Some(prost_types::value::Kind::StringValue(val)) => Some(val.clone()),
                _ => None,
            })
            .unwrap_or_default()
    }

    let s = resources.as_ref()?;

    let req = DriverResourceRequirements {
        cpu_request: get_quantity(s, "requests", "cpu"),
        cpu_limit: get_quantity(s, "limits", "cpu"),
        memory_request: get_quantity(s, "requests", "memory"),
        memory_limit: get_quantity(s, "limits", "memory"),
    };

    // Return None when all fields are empty so drivers can distinguish
    // "no resource requirements" from "zero requirements".
    if req.cpu_request.is_empty()
        && req.cpu_limit.is_empty()
        && req.memory_request.is_empty()
        && req.memory_limit.is_empty()
    {
        None
    } else {
        Some(req)
    }
}

/// Build the opaque `platform_config` Struct from platform-specific public
/// template fields (`runtime_class_name`, annotations, `volume_claim_templates`)
/// plus any resource fields beyond CPU/memory.
fn build_platform_config(template: &SandboxTemplate) -> Option<prost_types::Struct> {
    use prost_types::{Struct, Value, value::Kind};

    let mut fields = std::collections::BTreeMap::new();

    if !template.runtime_class_name.is_empty() {
        fields.insert(
            "runtime_class_name".to_string(),
            Value {
                kind: Some(Kind::StringValue(template.runtime_class_name.clone())),
            },
        );
    }

    if !template.annotations.is_empty() {
        let annotation_fields = template
            .annotations
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    Value {
                        kind: Some(Kind::StringValue(v.clone())),
                    },
                )
            })
            .collect();
        fields.insert(
            "annotations".to_string(),
            Value {
                kind: Some(Kind::StructValue(Struct {
                    fields: annotation_fields,
                })),
            },
        );
    }

    // Pass through the raw volume_claim_templates Struct as a nested value.
    if let Some(ref vct) = template.volume_claim_templates {
        fields.insert(
            "volume_claim_templates".to_string(),
            Value {
                kind: Some(Kind::StructValue(vct.clone())),
            },
        );
    }

    // Invert: the public API uses `user_namespaces: true` (positive sense)
    // while the K8s driver expects `host_users: false` (K8s convention).
    // The driver inverts this back via `!host_users` to resolve the final
    // pod-level `hostUsers` field.
    if let Some(user_ns) = template.user_namespaces {
        fields.insert(
            "host_users".to_string(),
            Value {
                kind: Some(Kind::BoolValue(!user_ns)),
            },
        );
    }

    // Pass through any resource fields that do not map to the typed
    // DriverResourceRequirements so platform-specific drivers can still see
    // custom resources such as GPU limits.
    if let Some(res) = build_platform_resources_config(&template.resources) {
        fields.insert(
            "resources_raw".to_string(),
            Value {
                kind: Some(Kind::StructValue(res)),
            },
        );
    }

    if fields.is_empty() {
        None
    } else {
        Some(Struct { fields })
    }
}

fn build_platform_resources_config(
    resources: &Option<prost_types::Struct>,
) -> Option<prost_types::Struct> {
    use prost_types::{Struct, Value, value::Kind};

    let resources = resources.as_ref()?;
    let mut fields = std::collections::BTreeMap::new();

    for (section_name, value) in &resources.fields {
        if !matches!(section_name.as_str(), "limits" | "requests") {
            fields.insert(section_name.clone(), value.clone());
            continue;
        }

        let Some(Kind::StructValue(section)) = value.kind.as_ref() else {
            fields.insert(section_name.clone(), value.clone());
            continue;
        };

        let section_fields = section
            .fields
            .iter()
            .filter_map(|(resource_name, resource_value)| {
                let is_typed_quantity = matches!(resource_name.as_str(), "cpu" | "memory")
                    && matches!(resource_value.kind.as_ref(), Some(Kind::StringValue(_)));
                if is_typed_quantity {
                    None
                } else {
                    Some((resource_name.clone(), resource_value.clone()))
                }
            })
            .collect::<std::collections::BTreeMap<_, _>>();

        if !section_fields.is_empty() {
            fields.insert(
                section_name.clone(),
                Value {
                    kind: Some(Kind::StructValue(Struct {
                        fields: section_fields,
                    })),
                },
            );
        }
    }

    if fields.is_empty() {
        None
    } else {
        Some(Struct { fields })
    }
}

fn driver_status_from_public(status: &SandboxStatus) -> DriverSandboxStatus {
    DriverSandboxStatus {
        sandbox_name: status.sandbox_name.clone(),
        instance_id: status.agent_pod.clone(),
        agent_fd: status.agent_fd.clone(),
        sandbox_fd: status.sandbox_fd.clone(),
        conditions: status
            .conditions
            .iter()
            .map(driver_condition_from_public)
            .collect(),
        deleting: SandboxPhase::try_from(status.phase) == Ok(SandboxPhase::Deleting),
    }
}

fn driver_condition_from_public(condition: &SandboxCondition) -> DriverCondition {
    DriverCondition {
        r#type: condition.r#type.clone(),
        status: condition.status.clone(),
        reason: condition.reason.clone(),
        message: condition.message.clone(),
        last_transition_time: condition.last_transition_time.clone(),
    }
}

impl ObjectType for Sandbox {
    fn object_type() -> &'static str {
        "sandbox"
    }
}

fn compute_error_from_status(status: Status) -> ComputeError {
    match status.code() {
        Code::AlreadyExists => ComputeError::AlreadyExists,
        Code::FailedPrecondition => ComputeError::Precondition(status.message().to_string()),
        _ => ComputeError::Message(status.message().to_string()),
    }
}

fn decode_sandbox_record(record: &ObjectRecord) -> Result<Sandbox, String> {
    Sandbox::decode(record.payload.as_slice()).map_err(|e| e.to_string())
}

fn public_status_from_driver(
    status: &DriverSandboxStatus,
    phase: SandboxPhase,
    current_policy_version: u32,
) -> SandboxStatus {
    SandboxStatus {
        sandbox_name: status.sandbox_name.clone(),
        agent_pod: status.instance_id.clone(),
        agent_fd: status.agent_fd.clone(),
        sandbox_fd: status.sandbox_fd.clone(),
        conditions: status
            .conditions
            .iter()
            .map(public_condition_from_driver)
            .collect(),
        phase: phase as i32,
        current_policy_version,
    }
}

fn ensure_supervisor_ready_status(status: &mut Option<SandboxStatus>, sandbox_name: &str) {
    upsert_ready_condition(
        status,
        sandbox_name,
        SandboxCondition {
            r#type: "Ready".to_string(),
            status: "True".to_string(),
            reason: "DependenciesReady".to_string(),
            message: "Supervisor session connected".to_string(),
            last_transition_time: String::new(),
        },
    );
}

fn ensure_supervisor_not_ready_status(status: &mut Option<SandboxStatus>, sandbox_name: &str) {
    upsert_ready_condition(
        status,
        sandbox_name,
        SandboxCondition {
            r#type: "Ready".to_string(),
            status: "False".to_string(),
            reason: "DependenciesNotReady".to_string(),
            message: "Supervisor session disconnected".to_string(),
            last_transition_time: String::new(),
        },
    );
}

fn upsert_ready_condition(
    status: &mut Option<SandboxStatus>,
    sandbox_name: &str,
    condition: SandboxCondition,
) {
    let status = status.get_or_insert_with(|| SandboxStatus {
        sandbox_name: sandbox_name.to_string(),
        ..Default::default()
    });

    if let Some(existing) = status
        .conditions
        .iter_mut()
        .find(|existing| existing.r#type == "Ready")
    {
        *existing = condition;
    } else {
        status.conditions.push(condition);
    }
}

fn public_condition_from_driver(condition: &DriverCondition) -> SandboxCondition {
    SandboxCondition {
        r#type: condition.r#type.clone(),
        status: condition.status.clone(),
        reason: condition.reason.clone(),
        message: condition.message.clone(),
        last_transition_time: condition.last_transition_time.clone(),
    }
}

fn public_platform_event_from_driver(event: &DriverPlatformEvent) -> PlatformEvent {
    PlatformEvent {
        timestamp_ms: event.timestamp_ms,
        source: event.source.clone(),
        r#type: event.r#type.clone(),
        reason: event.reason.clone(),
        message: event.message.clone(),
        metadata: event.metadata.clone(),
    }
}

fn derive_phase(status: Option<&DriverSandboxStatus>) -> SandboxPhase {
    if let Some(status) = status {
        if status.deleting {
            return SandboxPhase::Deleting;
        }

        for condition in &status.conditions {
            if condition.r#type == "Ready" {
                return if condition.status.eq_ignore_ascii_case("true") {
                    SandboxPhase::Ready
                } else if condition.status.eq_ignore_ascii_case("false") {
                    if is_terminal_failure_reason(&condition.reason) {
                        SandboxPhase::Error
                    } else {
                        SandboxPhase::Provisioning
                    }
                } else {
                    SandboxPhase::Provisioning
                };
            }
        }
        return SandboxPhase::Provisioning;
    }

    SandboxPhase::Unknown
}

fn rewrite_user_facing_conditions(status: &mut Option<SandboxStatus>, spec: Option<&SandboxSpec>) {
    let gpu_requested = spec
        .and_then(|sandbox_spec| sandbox_spec.resource_requirements.as_ref())
        .is_some_and(|requirements| openshell_core::gpu::sandbox_gpu_requested(Some(requirements)));
    if !gpu_requested {
        return;
    }

    if let Some(status) = status {
        for condition in &mut status.conditions {
            if condition.r#type == "Ready"
                && condition.status.eq_ignore_ascii_case("false")
                && condition.reason.eq_ignore_ascii_case("Unschedulable")
            {
                condition.message = "GPU sandbox could not be scheduled on the active gateway. Another GPU sandbox may already be using the available GPU, or the gateway may not currently be able to satisfy GPU placement. Please refer to documentation and use `openshell doctor` commands to inspect GPU support and gateway configuration.".to_string();
            }
        }
    }
}

/// Phases for which a sandbox should have a running compute resource.
/// `Deleting` and `Error` are intentionally excluded: deletion is in
/// progress, or the sandbox has already failed and should not be
/// silently revived. `Unspecified` is included because it is the proto
/// default value; persisted rows with that value should be reconciled
/// from the live driver state rather than skipped forever.
fn sandbox_phase_should_be_running(phase: SandboxPhase) -> bool {
    matches!(
        phase,
        SandboxPhase::Unspecified
            | SandboxPhase::Provisioning
            | SandboxPhase::Ready
            | SandboxPhase::Unknown
    )
}

fn is_terminal_failure_reason(reason: &str) -> bool {
    let reason = reason.to_ascii_lowercase();
    let transient_reasons = [
        "reconcilererror",
        "dependenciesnotready",
        "starting",
        "containerstarting",
        "containercreated",
        "healthcheckstarting",
        "inspectfailed",
    ];
    !transient_reasons.contains(&reason.as_str())
}

#[cfg(test)]
#[derive(Debug, Default)]
pub struct NoopTestDriver;

#[cfg(test)]
#[tonic::async_trait]
impl ComputeDriver for NoopTestDriver {
    type WatchSandboxesStream = DriverWatchStream;

    async fn get_capabilities(
        &self,
        _request: Request<GetCapabilitiesRequest>,
    ) -> Result<tonic::Response<openshell_core::proto::compute::v1::GetCapabilitiesResponse>, Status>
    {
        Ok(tonic::Response::new(
            openshell_core::proto::compute::v1::GetCapabilitiesResponse {
                driver_name: "noop-test-driver".to_string(),
                driver_version: "test".to_string(),
                default_image: "openshell/sandbox:test".to_string(),
            },
        ))
    }

    async fn validate_sandbox_create(
        &self,
        _request: Request<ValidateSandboxCreateRequest>,
    ) -> Result<
        tonic::Response<openshell_core::proto::compute::v1::ValidateSandboxCreateResponse>,
        Status,
    > {
        Ok(tonic::Response::new(
            openshell_core::proto::compute::v1::ValidateSandboxCreateResponse {},
        ))
    }

    async fn get_sandbox(
        &self,
        _request: Request<GetSandboxRequest>,
    ) -> Result<tonic::Response<openshell_core::proto::compute::v1::GetSandboxResponse>, Status>
    {
        Err(Status::not_found("sandbox not found"))
    }

    async fn list_sandboxes(
        &self,
        _request: Request<ListSandboxesRequest>,
    ) -> Result<tonic::Response<openshell_core::proto::compute::v1::ListSandboxesResponse>, Status>
    {
        Ok(tonic::Response::new(
            openshell_core::proto::compute::v1::ListSandboxesResponse {
                sandboxes: Vec::new(),
            },
        ))
    }

    async fn create_sandbox(
        &self,
        _request: Request<CreateSandboxRequest>,
    ) -> Result<tonic::Response<openshell_core::proto::compute::v1::CreateSandboxResponse>, Status>
    {
        Ok(tonic::Response::new(
            openshell_core::proto::compute::v1::CreateSandboxResponse {},
        ))
    }

    async fn stop_sandbox(
        &self,
        _request: Request<openshell_core::proto::compute::v1::StopSandboxRequest>,
    ) -> Result<tonic::Response<openshell_core::proto::compute::v1::StopSandboxResponse>, Status>
    {
        Ok(tonic::Response::new(
            openshell_core::proto::compute::v1::StopSandboxResponse {},
        ))
    }

    async fn delete_sandbox(
        &self,
        _request: Request<DeleteSandboxRequest>,
    ) -> Result<tonic::Response<openshell_core::proto::compute::v1::DeleteSandboxResponse>, Status>
    {
        Ok(tonic::Response::new(
            openshell_core::proto::compute::v1::DeleteSandboxResponse { deleted: true },
        ))
    }

    async fn watch_sandboxes(
        &self,
        _request: Request<WatchSandboxesRequest>,
    ) -> Result<tonic::Response<Self::WatchSandboxesStream>, Status> {
        Ok(tonic::Response::new(Box::pin(futures::stream::empty())))
    }
}

#[cfg(test)]
pub async fn new_test_runtime(store: Arc<Store>) -> ComputeRuntime {
    ComputeRuntime {
        driver: Arc::new(NoopTestDriver),
        driver_name: "test".to_string(),
        shutdown_cleanup: None,
        startup_resume: None,
        _driver_process: None,
        default_image: "openshell/sandbox:test".to_string(),
        store,
        sandbox_index: SandboxIndex::new(),
        sandbox_watch_bus: SandboxWatchBus::new(),
        tracing_log_bus: TracingLogBus::new(),
        supervisor_sessions: Arc::new(SupervisorSessionRegistry::new()),
        sync_lock: Arc::new(Mutex::new(())),
        gateway_bind_addresses: Vec::new(),
        replica_id: "test-replica".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream;
    use openshell_core::proto::compute::v1::{
        CreateSandboxResponse, DeleteSandboxResponse, GetCapabilitiesResponse, GetSandboxRequest,
        GetSandboxResponse, StopSandboxRequest, StopSandboxResponse, ValidateSandboxCreateResponse,
    };
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::{mpsc, oneshot};

    fn string_value(value: &str) -> prost_types::Value {
        prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue(value.to_string())),
        }
    }

    fn number_value(value: f64) -> prost_types::Value {
        prost_types::Value {
            kind: Some(prost_types::value::Kind::NumberValue(value)),
        }
    }

    fn struct_value(
        fields: impl IntoIterator<Item = (impl Into<String>, prost_types::Value)>,
    ) -> prost_types::Value {
        prost_types::Value {
            kind: Some(prost_types::value::Kind::StructValue(prost_types::Struct {
                fields: fields
                    .into_iter()
                    .map(|(key, value)| (key.into(), value))
                    .collect(),
            })),
        }
    }

    #[test]
    fn driver_sandbox_spec_from_public_preserves_gpu_requirement() {
        let public = SandboxSpec {
            resource_requirements: Some(openshell_core::proto::ResourceRequirements {
                gpu: Some(openshell_core::proto::GpuResourceRequirements { count: Some(2) }),
            }),
            ..Default::default()
        };

        let driver = driver_sandbox_spec_from_public(&public, "test-driver")
            .expect("driver spec should map");

        let gpu = driver
            .resource_requirements
            .as_ref()
            .and_then(|requirements| requirements.gpu.as_ref())
            .expect("driver GPU requirement should be set");
        assert_eq!(gpu.count, Some(2));
    }

    #[test]
    fn select_driver_config_forwards_only_matching_driver_block() {
        let config = prost_types::Struct {
            fields: [
                (
                    "kubernetes".to_string(),
                    struct_value([("node", string_value("gpu"))]),
                ),
                (
                    "docker".to_string(),
                    struct_value([("network_mode", string_value("bridge"))]),
                ),
            ]
            .into_iter()
            .collect(),
        };

        let selected = select_driver_config(&Some(config), "kubernetes").unwrap();
        let selected = selected.expect("kubernetes config should be selected");

        assert!(selected.fields.contains_key("node"));
        assert!(!selected.fields.contains_key("network_mode"));
    }

    #[test]
    fn select_driver_config_ignores_non_matching_driver_blocks() {
        let config = prost_types::Struct {
            fields: std::iter::once((
                "docker".to_string(),
                struct_value([("network_mode", string_value("bridge"))]),
            ))
            .collect(),
        };

        let selected = select_driver_config(&Some(config), "kubernetes").unwrap();

        assert!(selected.is_none());
    }

    #[test]
    fn select_driver_config_forwards_named_remote_driver_block() {
        let config = prost_types::Struct {
            fields: std::iter::once((
                "kyma".to_string(),
                struct_value([("pool", string_value("gpu"))]),
            ))
            .collect(),
        };

        let selected = select_driver_config(&Some(config), "kyma").unwrap();
        let selected = selected.expect("named remote config should be selected");

        assert!(selected.fields.contains_key("pool"));
    }

    #[test]
    fn select_driver_config_rejects_non_object_matching_driver_block() {
        let config = prost_types::Struct {
            fields: std::iter::once(("kubernetes".to_string(), string_value("not-an-object")))
                .collect(),
        };

        let err = select_driver_config(&Some(config), "kubernetes").unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("template.driver_config.kubernetes"));
    }

    #[derive(Debug, Default)]
    struct TestDriver {
        listed_sandboxes: Vec<DriverSandbox>,
        current_sandboxes: Vec<DriverSandbox>,
    }

    #[tonic::async_trait]
    impl ComputeDriver for TestDriver {
        type WatchSandboxesStream = DriverWatchStream;

        async fn get_capabilities(
            &self,
            _request: Request<GetCapabilitiesRequest>,
        ) -> Result<tonic::Response<GetCapabilitiesResponse>, Status> {
            Ok(tonic::Response::new(GetCapabilitiesResponse {
                driver_name: "test-driver".to_string(),
                driver_version: "test".to_string(),
                default_image: "openshell/sandbox:test".to_string(),
            }))
        }

        async fn validate_sandbox_create(
            &self,
            _request: Request<ValidateSandboxCreateRequest>,
        ) -> Result<tonic::Response<ValidateSandboxCreateResponse>, Status> {
            Ok(tonic::Response::new(ValidateSandboxCreateResponse {}))
        }

        async fn get_sandbox(
            &self,
            request: Request<GetSandboxRequest>,
        ) -> Result<tonic::Response<GetSandboxResponse>, Status> {
            let request = request.into_inner();
            let current = if self.current_sandboxes.is_empty() {
                &self.listed_sandboxes
            } else {
                &self.current_sandboxes
            };
            let sandbox = current
                .iter()
                .find(|sandbox| {
                    sandbox.name == request.sandbox_name
                        && (request.sandbox_id.is_empty() || sandbox.id == request.sandbox_id)
                })
                .cloned()
                .ok_or_else(|| Status::not_found("sandbox not found"))?;

            if !request.sandbox_id.is_empty() && request.sandbox_id != sandbox.id {
                return Err(Status::failed_precondition(
                    "sandbox_id did not match the fetched sandbox",
                ));
            }

            Ok(tonic::Response::new(GetSandboxResponse {
                sandbox: Some(sandbox),
            }))
        }

        async fn list_sandboxes(
            &self,
            _request: Request<ListSandboxesRequest>,
        ) -> Result<
            tonic::Response<openshell_core::proto::compute::v1::ListSandboxesResponse>,
            Status,
        > {
            Ok(tonic::Response::new(
                openshell_core::proto::compute::v1::ListSandboxesResponse {
                    sandboxes: self.listed_sandboxes.clone(),
                },
            ))
        }

        async fn create_sandbox(
            &self,
            _request: Request<CreateSandboxRequest>,
        ) -> Result<tonic::Response<CreateSandboxResponse>, Status> {
            Ok(tonic::Response::new(CreateSandboxResponse {}))
        }

        async fn stop_sandbox(
            &self,
            _request: Request<StopSandboxRequest>,
        ) -> Result<tonic::Response<StopSandboxResponse>, Status> {
            Ok(tonic::Response::new(StopSandboxResponse {}))
        }

        async fn delete_sandbox(
            &self,
            _request: Request<DeleteSandboxRequest>,
        ) -> Result<tonic::Response<DeleteSandboxResponse>, Status> {
            Ok(tonic::Response::new(DeleteSandboxResponse {
                deleted: true,
            }))
        }

        async fn watch_sandboxes(
            &self,
            _request: Request<WatchSandboxesRequest>,
        ) -> Result<tonic::Response<Self::WatchSandboxesStream>, Status> {
            Ok(tonic::Response::new(Box::pin(stream::empty())))
        }
    }

    async fn test_runtime(driver: SharedComputeDriver) -> ComputeRuntime {
        test_runtime_with_resume(driver, None).await
    }

    async fn test_runtime_with_resume(
        driver: SharedComputeDriver,
        startup_resume: Option<Arc<dyn StartupResume>>,
    ) -> ComputeRuntime {
        let store = Arc::new(Store::connect("sqlite::memory:").await.unwrap());
        ComputeRuntime {
            driver,
            driver_name: "test-driver".to_string(),
            shutdown_cleanup: None,
            startup_resume,
            _driver_process: None,
            default_image: "openshell/sandbox:test".to_string(),
            store,
            sandbox_index: SandboxIndex::new(),
            sandbox_watch_bus: SandboxWatchBus::new(),
            tracing_log_bus: TracingLogBus::new(),
            supervisor_sessions: Arc::new(SupervisorSessionRegistry::new()),
            sync_lock: Arc::new(Mutex::new(())),
            gateway_bind_addresses: Vec::new(),
            replica_id: "test-replica".to_string(),
        }
    }

    fn register_test_supervisor_session(runtime: &ComputeRuntime, sandbox_id: &str) {
        let (tx, _rx) = mpsc::channel(1);
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();
        runtime.supervisor_sessions.register(
            sandbox_id.to_string(),
            "session-1".to_string(),
            tx,
            shutdown_tx,
        );
    }

    fn sandbox_record(id: &str, name: &str, phase: SandboxPhase) -> Sandbox {
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: id.to_string(),
                name: name.to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
                resource_version: 0,
            }),
            ..Default::default()
        };
        sandbox.set_phase(phase as i32);
        sandbox
    }

    fn ssh_session_record(id: &str, sandbox_id: &str) -> SshSession {
        SshSession {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: id.to_string(),
                name: format!("session-{id}"),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
                resource_version: 0,
            }),
            sandbox_id: sandbox_id.to_string(),
            token: format!("token-{id}"),
            revoked: false,
            expires_at_ms: 0,
        }
    }

    fn make_driver_condition(reason: &str, message: &str) -> DriverCondition {
        DriverCondition {
            r#type: "Ready".to_string(),
            status: "False".to_string(),
            reason: reason.to_string(),
            message: message.to_string(),
            last_transition_time: String::new(),
        }
    }

    fn make_driver_status(condition: DriverCondition) -> DriverSandboxStatus {
        DriverSandboxStatus {
            sandbox_name: "test".to_string(),
            instance_id: "test-pod".to_string(),
            agent_fd: String::new(),
            sandbox_fd: String::new(),
            conditions: vec![condition],
            deleting: false,
        }
    }

    #[tokio::test]
    async fn sqlite_store_is_single_replica() {
        let store = Arc::new(Store::connect("sqlite::memory:").await.unwrap());
        assert!(store.is_single_replica());
    }

    #[test]
    fn terminal_failure_treats_unknown_reasons_as_terminal() {
        let terminal_cases = [
            ("Failed", "Something went wrong"),
            ("CrashLoopBackOff", "Container keeps crashing"),
            ("ImagePullBackOff", "Failed to pull image"),
            ("ErrImagePull", "Error pulling image"),
            ("Unschedulable", "No nodes match"),
            ("SomeOtherReason", "Any other reason is terminal"),
        ];

        for (reason, message) in terminal_cases {
            assert!(
                is_terminal_failure_reason(reason),
                "Expected terminal failure for reason={reason}, message={message}"
            );
        }
    }

    #[test]
    fn terminal_failure_ignores_transient_reasons() {
        let transient_cases = [
            (
                "ReconcilerError",
                "Error seen: failed to update pod: Operation cannot be fulfilled",
            ),
            ("reconcilererror", "lowercase also works"),
            ("RECONCILERERROR", "uppercase also works"),
            (
                "DependenciesNotReady",
                "Pod exists with phase: Pending; Service Exists",
            ),
            ("dependenciesnotready", "lowercase also works"),
            ("Starting", "VM is starting"),
            (
                "ContainerCreated",
                "Podman created the container before starting it",
            ),
        ];

        for (reason, message) in transient_cases {
            assert!(
                !is_terminal_failure_reason(reason),
                "Expected transient (non-terminal) for reason={reason}, message={message}"
            );
        }
    }

    #[test]
    fn derive_phase_returns_unknown_without_status() {
        assert_eq!(derive_phase(None), SandboxPhase::Unknown);
    }

    #[test]
    fn derive_phase_returns_deleting_when_driver_marks_deleting() {
        let status = DriverSandboxStatus {
            deleting: true,
            ..make_driver_status(make_driver_condition(
                "DependenciesNotReady",
                "Pod still pending",
            ))
        };

        assert_eq!(derive_phase(Some(&status)), SandboxPhase::Deleting);
    }

    #[test]
    fn derive_phase_returns_provisioning_for_transient_conditions() {
        let transient_conditions = [
            ("ReconcilerError", "Error seen: failed to update pod"),
            (
                "DependenciesNotReady",
                "Pod exists with phase: Pending; Service Exists",
            ),
            ("Starting", "VM is starting"),
            (
                "ContainerCreated",
                "Container exists but has not started yet",
            ),
        ];

        for (reason, message) in transient_conditions {
            let status = make_driver_status(make_driver_condition(reason, message));
            assert_eq!(
                derive_phase(Some(&status)),
                SandboxPhase::Provisioning,
                "Expected Provisioning for transient reason={reason}"
            );
        }
    }

    #[test]
    fn derive_phase_returns_error_for_terminal_ready_false() {
        let status = make_driver_status(make_driver_condition(
            "ImagePullBackOff",
            "Failed to pull image",
        ));

        assert_eq!(derive_phase(Some(&status)), SandboxPhase::Error);
    }

    #[test]
    fn derive_phase_returns_ready_for_ready_true() {
        let status = DriverSandboxStatus {
            conditions: vec![DriverCondition {
                r#type: "Ready".to_string(),
                status: "True".to_string(),
                reason: "DependenciesReady".to_string(),
                message: "Pod is Ready; Service Exists".to_string(),
                last_transition_time: String::new(),
            }],
            ..make_driver_status(make_driver_condition("", ""))
        };

        assert_eq!(derive_phase(Some(&status)), SandboxPhase::Ready);
    }

    #[test]
    fn build_platform_config_omits_typed_cpu_and_memory_resources() {
        let template = SandboxTemplate {
            resources: Some(prost_types::Struct {
                fields: [
                    (
                        "limits",
                        struct_value([("cpu", string_value("2")), ("memory", string_value("1Gi"))]),
                    ),
                    (
                        "requests",
                        struct_value([
                            ("cpu", string_value("500m")),
                            ("memory", string_value("512Mi")),
                        ]),
                    ),
                ]
                .into_iter()
                .map(|(key, value)| (key.to_string(), value))
                .collect(),
            }),
            ..Default::default()
        };

        assert!(build_platform_config(&template).is_none());
    }

    #[test]
    fn build_platform_config_preserves_non_typed_resource_fields() {
        let template = SandboxTemplate {
            resources: Some(prost_types::Struct {
                fields: [
                    (
                        "limits",
                        struct_value([
                            ("cpu", string_value("2")),
                            ("memory", string_value("1Gi")),
                            ("nvidia.com/gpu", string_value("1")),
                        ]),
                    ),
                    (
                        "requests",
                        struct_value([
                            ("cpu", string_value("500m")),
                            ("memory", string_value("512Mi")),
                            ("hugepages-2Mi", string_value("4Mi")),
                        ]),
                    ),
                    ("opaque_cpu", number_value(2.0)),
                ]
                .into_iter()
                .map(|(key, value)| (key.to_string(), value))
                .collect(),
            }),
            ..Default::default()
        };

        let platform_config = build_platform_config(&template).unwrap();
        let resources_raw = platform_config
            .fields
            .get("resources_raw")
            .and_then(|value| value.kind.as_ref())
            .and_then(|kind| match kind {
                prost_types::value::Kind::StructValue(inner) => Some(inner),
                _ => None,
            })
            .unwrap();

        let limits = resources_raw
            .fields
            .get("limits")
            .and_then(|value| value.kind.as_ref())
            .and_then(|kind| match kind {
                prost_types::value::Kind::StructValue(inner) => Some(inner),
                _ => None,
            })
            .unwrap();
        assert!(!limits.fields.contains_key("cpu"));
        assert!(!limits.fields.contains_key("memory"));
        assert_eq!(
            limits
                .fields
                .get("nvidia.com/gpu")
                .and_then(|value| value.kind.as_ref())
                .and_then(|kind| match kind {
                    prost_types::value::Kind::StringValue(value) => Some(value.as_str()),
                    _ => None,
                }),
            Some("1")
        );

        let requests = resources_raw
            .fields
            .get("requests")
            .and_then(|value| value.kind.as_ref())
            .and_then(|kind| match kind {
                prost_types::value::Kind::StructValue(inner) => Some(inner),
                _ => None,
            })
            .unwrap();
        assert!(!requests.fields.contains_key("cpu"));
        assert!(!requests.fields.contains_key("memory"));
        assert_eq!(
            requests
                .fields
                .get("hugepages-2Mi")
                .and_then(|value| value.kind.as_ref())
                .and_then(|kind| match kind {
                    prost_types::value::Kind::StringValue(value) => Some(value.as_str()),
                    _ => None,
                }),
            Some("4Mi")
        );

        assert!(resources_raw.fields.contains_key("opaque_cpu"));
    }

    #[test]
    fn rewrite_user_facing_conditions_rewrites_gpu_unschedulable_message() {
        let mut status = Some(SandboxStatus {
            sandbox_name: "test".to_string(),
            agent_pod: "test-pod".to_string(),
            conditions: vec![SandboxCondition {
                r#type: "Ready".to_string(),
                status: "False".to_string(),
                reason: "Unschedulable".to_string(),
                message: "0/1 nodes are available: 1 Insufficient nvidia.com/gpu.".to_string(),
                last_transition_time: String::new(),
            }],
            ..Default::default()
        });

        rewrite_user_facing_conditions(
            &mut status,
            Some(&SandboxSpec {
                resource_requirements: Some(openshell_core::proto::ResourceRequirements {
                    gpu: Some(openshell_core::proto::GpuResourceRequirements { count: None }),
                }),
                ..Default::default()
            }),
        );

        let message = &status.unwrap().conditions[0].message;
        assert_eq!(
            message,
            "GPU sandbox could not be scheduled on the active gateway. Another GPU sandbox may already be using the available GPU, or the gateway may not currently be able to satisfy GPU placement. Please refer to documentation and use `openshell doctor` commands to inspect GPU support and gateway configuration."
        );
    }

    #[test]
    fn rewrite_user_facing_conditions_leaves_non_gpu_unschedulable_message_unchanged() {
        let original = "0/1 nodes are available: 1 Insufficient cpu.";
        let mut status = Some(SandboxStatus {
            sandbox_name: "test".to_string(),
            agent_pod: "test-pod".to_string(),
            conditions: vec![SandboxCondition {
                r#type: "Ready".to_string(),
                status: "False".to_string(),
                reason: "Unschedulable".to_string(),
                message: original.to_string(),
                last_transition_time: String::new(),
            }],
            ..Default::default()
        });

        rewrite_user_facing_conditions(&mut status, Some(&SandboxSpec::default()));

        assert_eq!(status.unwrap().conditions[0].message, original);
    }

    #[test]
    fn compute_error_from_status_preserves_driver_status_codes() {
        assert!(matches!(
            compute_error_from_status(Status::already_exists("sandbox already exists")),
            ComputeError::AlreadyExists
        ));

        assert!(matches!(
            compute_error_from_status(Status::failed_precondition("sandbox agent pod IP is not available")),
            ComputeError::Precondition(message) if message == "sandbox agent pod IP is not available"
        ));
    }

    #[tokio::test]
    async fn set_sandbox_phase_deleting_retries_after_stale_snapshot_conflict() {
        let runtime = test_runtime(Arc::new(TestDriver::default())).await;
        let sandbox = sandbox_record("sb-1", "sandbox-a", SandboxPhase::Ready);
        runtime.store.put_message(&sandbox).await.unwrap();

        let stale_snapshot = runtime
            .store
            .get_message::<Sandbox>("sb-1")
            .await
            .unwrap()
            .unwrap();

        runtime
            .store
            .update_message_cas::<Sandbox, _>("sb-1", 0, |sandbox| {
                sandbox.set_current_policy_version(7);
            })
            .await
            .unwrap();

        let updated = runtime
            .set_sandbox_phase_deleting_with_initial_snapshot("sb-1", Some(stale_snapshot))
            .await
            .unwrap();

        assert_eq!(
            SandboxPhase::try_from(updated.phase()).unwrap(),
            SandboxPhase::Deleting
        );
        assert_eq!(updated.current_policy_version(), 7);
        assert_eq!(
            updated
                .metadata
                .as_ref()
                .map_or(0, |metadata| metadata.resource_version),
            3
        );

        let stored = runtime
            .store
            .get_message::<Sandbox>("sb-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            SandboxPhase::try_from(stored.phase()).unwrap(),
            SandboxPhase::Deleting
        );
        assert_eq!(stored.current_policy_version(), 7);
    }

    #[tokio::test]
    async fn apply_sandbox_update_allows_delete_failures_to_recover() {
        let runtime = test_runtime(Arc::new(TestDriver::default())).await;
        let sandbox = sandbox_record("sb-1", "sandbox-a", SandboxPhase::Deleting);
        runtime.store.put_message(&sandbox).await.unwrap();

        runtime
            .apply_sandbox_update(DriverSandbox {
                id: "sb-1".to_string(),
                name: "sandbox-a".to_string(),
                namespace: "default".to_string(),
                spec: None,
                status: Some(DriverSandboxStatus {
                    sandbox_name: "sandbox-a".to_string(),
                    instance_id: "agent-pod".to_string(),
                    agent_fd: String::new(),
                    sandbox_fd: String::new(),
                    conditions: vec![DriverCondition {
                        r#type: "Ready".to_string(),
                        status: "True".to_string(),
                        reason: "DependenciesReady".to_string(),
                        message: "Pod is Ready".to_string(),
                        last_transition_time: String::new(),
                    }],
                    deleting: false,
                }),
            })
            .await
            .unwrap();

        let stored = runtime
            .store
            .get_message::<Sandbox>("sb-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            SandboxPhase::try_from(stored.phase()).unwrap(),
            SandboxPhase::Ready
        );
    }

    #[tokio::test]
    async fn apply_sandbox_update_without_status_preserves_existing_status() {
        let runtime = test_runtime(Arc::new(TestDriver::default())).await;
        let mut sandbox = sandbox_record("sb-1", "sandbox-a", SandboxPhase::Ready);
        sandbox.status = Some(SandboxStatus {
            sandbox_name: "sandbox-a".to_string(),
            conditions: vec![SandboxCondition {
                r#type: "Ready".to_string(),
                status: "True".to_string(),
                reason: "DependenciesReady".to_string(),
                message: "Pod is Ready".to_string(),
                last_transition_time: String::new(),
            }],
            current_policy_version: 7,
            ..Default::default()
        });
        sandbox.set_phase(SandboxPhase::Ready as i32);
        runtime.store.put_message(&sandbox).await.unwrap();

        runtime
            .apply_sandbox_update(DriverSandbox {
                id: "sb-1".to_string(),
                name: "sandbox-a".to_string(),
                namespace: "default".to_string(),
                spec: None,
                status: None,
            })
            .await
            .unwrap();

        let stored = runtime
            .store
            .get_message::<Sandbox>("sb-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            SandboxPhase::try_from(stored.phase()).unwrap(),
            SandboxPhase::Ready
        );
        assert_eq!(stored.current_policy_version(), 7);
        let ready = stored
            .status
            .as_ref()
            .and_then(|status| {
                status
                    .conditions
                    .iter()
                    .find(|condition| condition.r#type == "Ready")
            })
            .unwrap();
        assert_eq!(ready.status, "True");
        assert_eq!(ready.reason, "DependenciesReady");
        assert_eq!(ready.message, "Pod is Ready");
    }

    #[tokio::test]
    async fn apply_sandbox_update_promotes_connected_supervisor_session_to_ready() {
        let runtime = test_runtime(Arc::new(TestDriver::default())).await;
        let sandbox = sandbox_record("sb-1", "sandbox-a", SandboxPhase::Provisioning);
        runtime.store.put_message(&sandbox).await.unwrap();

        register_test_supervisor_session(&runtime, "sb-1");

        runtime
            .apply_sandbox_update(DriverSandbox {
                id: "sb-1".to_string(),
                name: "sandbox-a".to_string(),
                namespace: "default".to_string(),
                spec: None,
                status: Some(make_driver_status(make_driver_condition(
                    "Starting",
                    "VM is starting",
                ))),
            })
            .await
            .unwrap();

        let stored = runtime
            .store
            .get_message::<Sandbox>("sb-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            SandboxPhase::try_from(stored.phase()).unwrap(),
            SandboxPhase::Ready
        );
        let ready = stored
            .status
            .as_ref()
            .and_then(|status| {
                status
                    .conditions
                    .iter()
                    .find(|condition| condition.r#type == "Ready")
            })
            .unwrap();
        assert_eq!(ready.status, "True");
        assert_eq!(ready.reason, "DependenciesReady");
        assert_eq!(ready.message, "Supervisor session connected");
    }

    #[tokio::test]
    async fn supervisor_session_connected_promotes_store_state_without_driver_refresh() {
        let runtime = test_runtime(Arc::new(TestDriver::default())).await;
        let sandbox = sandbox_record("sb-1", "sandbox-a", SandboxPhase::Provisioning);
        runtime.store.put_message(&sandbox).await.unwrap();

        runtime.supervisor_session_connected("sb-1").await.unwrap();

        let stored = runtime
            .store
            .get_message::<Sandbox>("sb-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            SandboxPhase::try_from(stored.phase()).unwrap(),
            SandboxPhase::Ready
        );
    }

    #[tokio::test]
    async fn supervisor_session_disconnected_demotes_ready_sandbox() {
        let runtime = test_runtime(Arc::new(TestDriver::default())).await;
        let mut sandbox = sandbox_record("sb-1", "sandbox-a", SandboxPhase::Ready);
        sandbox.status = Some(SandboxStatus {
            sandbox_name: "sandbox-a".to_string(),
            conditions: vec![SandboxCondition {
                r#type: "Ready".to_string(),
                status: "True".to_string(),
                reason: "DependenciesReady".to_string(),
                message: "Supervisor session connected".to_string(),
                last_transition_time: String::new(),
            }],
            ..Default::default()
        });
        sandbox.set_phase(SandboxPhase::Ready as i32);
        runtime.store.put_message(&sandbox).await.unwrap();

        runtime
            .supervisor_session_disconnected("sb-1")
            .await
            .unwrap();

        let stored = runtime
            .store
            .get_message::<Sandbox>("sb-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            SandboxPhase::try_from(stored.phase()).unwrap(),
            SandboxPhase::Provisioning
        );
        let ready = stored
            .status
            .as_ref()
            .and_then(|status| {
                status
                    .conditions
                    .iter()
                    .find(|condition| condition.r#type == "Ready")
            })
            .unwrap();
        assert_eq!(ready.status, "False");
        assert_eq!(ready.reason, "DependenciesNotReady");
        assert_eq!(ready.message, "Supervisor session disconnected");
    }

    #[tokio::test]
    async fn reconcile_store_with_backend_applies_driver_snapshot() {
        let runtime = test_runtime(Arc::new(TestDriver {
            listed_sandboxes: vec![DriverSandbox {
                id: "sb-1".to_string(),
                name: "sandbox-a".to_string(),
                namespace: "default".to_string(),
                spec: None,
                status: Some(DriverSandboxStatus {
                    sandbox_name: "sandbox-a".to_string(),
                    instance_id: "agent-pod".to_string(),
                    agent_fd: String::new(),
                    sandbox_fd: String::new(),
                    conditions: vec![DriverCondition {
                        r#type: "Ready".to_string(),
                        status: "False".to_string(),
                        reason: "DependenciesNotReady".to_string(),
                        message: "Pod is Pending".to_string(),
                        last_transition_time: String::new(),
                    }],
                    deleting: false,
                }),
            }],
            current_sandboxes: vec![DriverSandbox {
                id: "sb-1".to_string(),
                name: "sandbox-a".to_string(),
                namespace: "default".to_string(),
                spec: None,
                status: Some(DriverSandboxStatus {
                    sandbox_name: "sandbox-a".to_string(),
                    instance_id: "agent-pod".to_string(),
                    agent_fd: String::new(),
                    sandbox_fd: String::new(),
                    conditions: vec![DriverCondition {
                        r#type: "Ready".to_string(),
                        status: "True".to_string(),
                        reason: "DependenciesReady".to_string(),
                        message: "Pod is Ready".to_string(),
                        last_transition_time: String::new(),
                    }],
                    deleting: false,
                }),
            }],
        }))
        .await;

        let sandbox = Sandbox {
            spec: Some(SandboxSpec {
                resource_requirements: Some(openshell_core::proto::ResourceRequirements {
                    gpu: Some(openshell_core::proto::GpuResourceRequirements { count: None }),
                }),
                ..Default::default()
            }),
            ..sandbox_record("sb-1", "sandbox-a", SandboxPhase::Provisioning)
        };
        runtime.store.put_message(&sandbox).await.unwrap();
        runtime.sandbox_index.update_from_sandbox(&sandbox);

        runtime
            .reconcile_store_with_backend(Duration::ZERO)
            .await
            .unwrap();

        let stored = runtime
            .store
            .get_message::<Sandbox>("sb-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            SandboxPhase::try_from(stored.phase()).unwrap(),
            SandboxPhase::Ready
        );
        assert!(stored.spec.as_ref().is_some_and(|spec| {
            openshell_core::gpu::sandbox_gpu_requested(spec.resource_requirements.as_ref())
        }));
    }

    #[tokio::test]
    async fn reconcile_store_with_backend_does_not_recreate_missing_record_from_snapshot() {
        let runtime = test_runtime(Arc::new(TestDriver {
            listed_sandboxes: vec![DriverSandbox {
                id: "sb-1".to_string(),
                name: "sandbox-a".to_string(),
                namespace: "default".to_string(),
                spec: None,
                status: Some(make_driver_status(make_driver_condition(
                    "DependenciesNotReady",
                    "Pod exists with phase: Pending; Service Exists",
                ))),
            }],
            current_sandboxes: vec![DriverSandbox {
                id: "sb-1".to_string(),
                name: "sandbox-a".to_string(),
                namespace: "default".to_string(),
                spec: None,
                status: Some(make_driver_status(DriverCondition {
                    r#type: "Ready".to_string(),
                    status: "True".to_string(),
                    reason: "DependenciesReady".to_string(),
                    message: "Pod is Ready".to_string(),
                    last_transition_time: String::new(),
                })),
            }],
        }))
        .await;

        runtime
            .reconcile_store_with_backend(Duration::ZERO)
            .await
            .unwrap();

        assert!(
            runtime
                .store
                .get_message::<Sandbox>("sb-1")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn reconcile_store_with_backend_rechecks_driver_before_pruning() {
        let runtime = test_runtime(Arc::new(TestDriver {
            current_sandboxes: vec![DriverSandbox {
                id: "sb-1".to_string(),
                name: "sandbox-a".to_string(),
                namespace: "default".to_string(),
                spec: None,
                status: Some(DriverSandboxStatus {
                    sandbox_name: "sandbox-a".to_string(),
                    instance_id: "agent-pod".to_string(),
                    agent_fd: String::new(),
                    sandbox_fd: String::new(),
                    conditions: vec![DriverCondition {
                        r#type: "Ready".to_string(),
                        status: "True".to_string(),
                        reason: "DependenciesReady".to_string(),
                        message: "Pod is Ready".to_string(),
                        last_transition_time: String::new(),
                    }],
                    deleting: false,
                }),
            }],
            ..Default::default()
        }))
        .await;

        let sandbox = sandbox_record("sb-1", "sandbox-a", SandboxPhase::Provisioning);
        runtime.store.put_message(&sandbox).await.unwrap();
        runtime.sandbox_index.update_from_sandbox(&sandbox);

        runtime
            .reconcile_store_with_backend(Duration::ZERO)
            .await
            .unwrap();

        let stored = runtime
            .store
            .get_message::<Sandbox>("sb-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            SandboxPhase::try_from(stored.phase()).unwrap(),
            SandboxPhase::Ready
        );
    }

    #[tokio::test]
    async fn reconcile_store_with_backend_removes_stale_provisioning_records() {
        let runtime = test_runtime(Arc::new(TestDriver::default())).await;
        let sandbox = sandbox_record("sb-1", "sandbox-a", SandboxPhase::Provisioning);
        runtime.store.put_message(&sandbox).await.unwrap();
        runtime.sandbox_index.update_from_sandbox(&sandbox);
        runtime
            .store
            .put(
                SANDBOX_SETTINGS_OBJECT_TYPE,
                "settings-sb-1",
                sandbox.object_name(),
                br#"{"revision":1,"settings":{}}"#,
                None,
            )
            .await
            .unwrap();
        let session = ssh_session_record("session-1", sandbox.object_id());
        runtime.store.put_message(&session).await.unwrap();

        let mut watch_rx = runtime.sandbox_watch_bus.subscribe(sandbox.object_id());

        runtime
            .reconcile_store_with_backend(Duration::ZERO)
            .await
            .unwrap();

        assert!(
            runtime
                .store
                .get_message::<Sandbox>(sandbox.object_id())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            runtime
                .sandbox_index
                .sandbox_id_for_sandbox_name(sandbox.object_name())
                .is_none()
        );
        assert!(
            runtime
                .store
                .get_by_name(SANDBOX_SETTINGS_OBJECT_TYPE, sandbox.object_name())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            runtime
                .store
                .get_message::<SshSession>(session.object_id())
                .await
                .unwrap()
                .is_none()
        );
        let _ = watch_rx.try_recv();
        assert!(matches!(
            watch_rx.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Closed)
        ));
    }

    #[derive(Default)]
    struct RecordingResume {
        calls: Mutex<Vec<(String, String)>>,
        results: Mutex<HashMap<String, Result<bool, String>>>,
    }

    impl RecordingResume {
        async fn set_result(&self, sandbox_id: &str, result: Result<bool, String>) {
            self.results
                .lock()
                .await
                .insert(sandbox_id.to_string(), result);
        }

        async fn calls(&self) -> Vec<(String, String)> {
            self.calls.lock().await.clone()
        }
    }

    #[tonic::async_trait]
    impl StartupResume for RecordingResume {
        async fn resume_sandbox(
            &self,
            sandbox_id: &str,
            sandbox_name: &str,
        ) -> Result<bool, String> {
            self.calls
                .lock()
                .await
                .push((sandbox_id.to_string(), sandbox_name.to_string()));
            self.results
                .lock()
                .await
                .get(sandbox_id)
                .cloned()
                .unwrap_or(Ok(true))
        }
    }

    #[tokio::test]
    async fn resume_persisted_sandboxes_resumes_running_phases() {
        let resume = Arc::new(RecordingResume::default());
        let runtime =
            test_runtime_with_resume(Arc::new(TestDriver::default()), Some(resume.clone())).await;

        for (id, name, phase) in [
            ("sb-unspecified", "unspecified", SandboxPhase::Unspecified),
            ("sb-prov", "prov", SandboxPhase::Provisioning),
            ("sb-ready", "ready", SandboxPhase::Ready),
            ("sb-unknown", "unknown", SandboxPhase::Unknown),
            ("sb-deleting", "deleting", SandboxPhase::Deleting),
            ("sb-error", "error", SandboxPhase::Error),
        ] {
            let sandbox = sandbox_record(id, name, phase);
            runtime.store.put_message(&sandbox).await.unwrap();
        }

        runtime.resume_persisted_sandboxes().await.unwrap();

        let mut called_ids = resume
            .calls()
            .await
            .into_iter()
            .map(|(id, _)| id)
            .collect::<Vec<_>>();
        called_ids.sort();
        assert_eq!(
            called_ids,
            vec![
                "sb-prov".to_string(),
                "sb-ready".to_string(),
                "sb-unknown".to_string(),
                "sb-unspecified".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn resume_persisted_sandboxes_marks_missing_backend_as_error() {
        let resume = Arc::new(RecordingResume::default());
        resume.set_result("sb-1", Ok(false)).await;
        let runtime =
            test_runtime_with_resume(Arc::new(TestDriver::default()), Some(resume.clone())).await;

        let sandbox = sandbox_record("sb-1", "missing", SandboxPhase::Ready);
        runtime.store.put_message(&sandbox).await.unwrap();

        runtime.resume_persisted_sandboxes().await.unwrap();

        let stored = runtime
            .store
            .get_message::<Sandbox>("sb-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            SandboxPhase::try_from(stored.phase()).unwrap(),
            SandboxPhase::Error
        );
        let ready = stored
            .status
            .as_ref()
            .and_then(|s| s.conditions.iter().find(|c| c.r#type == "Ready"))
            .expect("Ready condition present");
        assert_eq!(ready.reason, "BackendResourceMissing");
    }

    #[tokio::test]
    async fn resume_persisted_sandboxes_marks_failed_resume_as_error() {
        let resume = Arc::new(RecordingResume::default());
        resume
            .set_result("sb-1", Err("docker daemon angry".to_string()))
            .await;
        let runtime =
            test_runtime_with_resume(Arc::new(TestDriver::default()), Some(resume.clone())).await;

        let sandbox = sandbox_record("sb-1", "broken", SandboxPhase::Provisioning);
        runtime.store.put_message(&sandbox).await.unwrap();

        runtime.resume_persisted_sandboxes().await.unwrap();

        let stored = runtime
            .store
            .get_message::<Sandbox>("sb-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            SandboxPhase::try_from(stored.phase()).unwrap(),
            SandboxPhase::Error
        );
        let ready = stored
            .status
            .as_ref()
            .and_then(|s| s.conditions.iter().find(|c| c.r#type == "Ready"))
            .expect("Ready condition present");
        assert_eq!(ready.reason, "ResumeFailed");
        assert!(ready.message.contains("docker daemon angry"));
    }

    #[tokio::test]
    async fn resume_persisted_sandboxes_is_noop_without_resume_hook() {
        let runtime = test_runtime(Arc::new(TestDriver::default())).await;
        let sandbox = sandbox_record("sb-1", "anywhere", SandboxPhase::Ready);
        runtime.store.put_message(&sandbox).await.unwrap();

        runtime.resume_persisted_sandboxes().await.unwrap();

        let stored = runtime
            .store
            .get_message::<Sandbox>("sb-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            SandboxPhase::try_from(stored.phase()).unwrap(),
            SandboxPhase::Ready
        );
    }

    #[test]
    fn build_platform_config_inverts_user_namespaces_to_host_users() {
        use prost_types::value::Kind;

        // user_namespaces: true  → host_users: false
        let mut template = SandboxTemplate {
            user_namespaces: Some(true),
            ..SandboxTemplate::default()
        };
        let config = build_platform_config(&template).expect("config should be Some");
        let host_users = config
            .fields
            .get("host_users")
            .expect("host_users must exist");
        assert_eq!(
            host_users.kind,
            Some(Kind::BoolValue(false)),
            "user_namespaces: true must produce host_users: false"
        );

        // user_namespaces: false → host_users: true
        template.user_namespaces = Some(false);
        let config = build_platform_config(&template).expect("config should be Some");
        let host_users = config
            .fields
            .get("host_users")
            .expect("host_users must exist");
        assert_eq!(
            host_users.kind,
            Some(Kind::BoolValue(true)),
            "user_namespaces: false must produce host_users: true"
        );

        // user_namespaces: None → host_users absent
        template.user_namespaces = None;
        let config = build_platform_config(&template);
        assert!(
            config.is_none() || !config.as_ref().unwrap().fields.contains_key("host_users"),
            "unset user_namespaces must not produce host_users"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn remote_compute_driver_forwards_lifecycle_calls_over_uds() {
        use crate::test_support::{FakeComputeDriver, FakeComputeDriverCall};

        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("compute-driver.sock");
        let driver = FakeComputeDriver::new()
            .with_driver_name("fake-remote-driver")
            .with_default_image("openshell/sandbox:remote");
        let _server = driver.serve_uds(&socket_path).unwrap();

        let endpoint = connect_remote_compute_driver("external-test", &socket_path)
            .await
            .unwrap();
        let store = Arc::new(Store::connect("sqlite::memory:").await.unwrap());
        let runtime = ComputeRuntime::new_remote_driver(
            endpoint,
            store,
            SandboxIndex::new(),
            SandboxWatchBus::new(),
            TracingLogBus::new(),
            Arc::new(SupervisorSessionRegistry::new()),
        )
        .await
        .unwrap();

        let mut sandbox = sandbox_record("sb-uds", "uds-sandbox", SandboxPhase::Provisioning);
        sandbox.spec = Some(SandboxSpec {
            log_level: "debug".to_string(),
            template: Some(SandboxTemplate {
                image: "ghcr.io/nvidia/openshell/sandbox:test".to_string(),
                driver_config: Some(prost_types::Struct {
                    fields: [
                        (
                            "external-test".to_string(),
                            struct_value([("pool", string_value("ci"))]),
                        ),
                        (
                            "docker".to_string(),
                            struct_value([("network_mode", string_value("bridge"))]),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                }),
                ..Default::default()
            }),
            ..Default::default()
        });

        runtime.validate_sandbox_create(&sandbox).await.unwrap();
        runtime.create_sandbox(sandbox, None).await.unwrap();
        assert!(runtime.delete_sandbox("uds-sandbox").await.unwrap());

        let calls = driver.calls();
        assert_eq!(calls.len(), 4, "unexpected calls: {calls:?}");
        assert!(matches!(calls[0], FakeComputeDriverCall::GetCapabilities));

        let validated = match &calls[1] {
            FakeComputeDriverCall::ValidateSandboxCreate {
                sandbox: Some(sandbox),
            } => sandbox,
            other => panic!("expected ValidateSandboxCreate call, got {other:?}"),
        };
        assert_eq!(validated.id, "sb-uds");
        assert_eq!(validated.name, "uds-sandbox");
        let driver_config = validated
            .spec
            .as_ref()
            .and_then(|spec| spec.template.as_ref())
            .and_then(|template| template.driver_config.as_ref())
            .expect("selected driver_config should be forwarded");
        assert!(driver_config.fields.contains_key("pool"));
        assert!(!driver_config.fields.contains_key("network_mode"));

        let created = match &calls[2] {
            FakeComputeDriverCall::CreateSandbox {
                sandbox: Some(sandbox),
            } => sandbox,
            other => panic!("expected CreateSandbox call, got {other:?}"),
        };
        assert_eq!(created.id, "sb-uds");
        assert_eq!(created.name, "uds-sandbox");

        match &calls[3] {
            FakeComputeDriverCall::DeleteSandbox {
                sandbox_id,
                sandbox_name,
            } => {
                assert_eq!(sandbox_id, "sb-uds");
                assert_eq!(sandbox_name, "uds-sandbox");
            }
            other => panic!("expected DeleteSandbox call, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_sandbox_returns_resource_version_one() {
        let runtime = test_runtime(Arc::new(TestDriver::default())).await;

        let mut sandbox = sandbox_record("sb-new", "test-sandbox", SandboxPhase::Provisioning);
        // Clear metadata to simulate incoming request
        sandbox.metadata = Some(openshell_core::proto::datamodel::v1::ObjectMeta {
            id: "sb-new".to_string(),
            name: "test-sandbox".to_string(),
            created_at_ms: 1_000_000,
            labels: HashMap::new(),
            resource_version: 0,
        });

        let created = runtime.create_sandbox(sandbox, None).await.unwrap();

        assert_eq!(
            created.metadata.as_ref().unwrap().resource_version,
            1,
            "create_sandbox should return resource_version: 1 after insert"
        );

        // Verify database also has resource_version: 1
        let created_id = created.metadata.as_ref().unwrap().id.clone();
        let stored = runtime
            .store
            .get_message::<Sandbox>(&created_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.metadata.as_ref().unwrap().resource_version,
            1,
            "database should have resource_version: 1 after create"
        );
    }

    #[tokio::test]
    async fn concurrent_create_sandbox_rejects_duplicate() {
        let runtime = Arc::new(test_runtime(Arc::new(TestDriver::default())).await);

        let sandbox = sandbox_record(
            "sb-concurrent",
            "test-concurrent",
            SandboxPhase::Provisioning,
        );

        // Spawn two concurrent creation attempts for the same sandbox
        let runtime1 = runtime.clone();
        let sandbox1 = sandbox.clone();
        let handle1 = tokio::spawn(async move { runtime1.create_sandbox(sandbox1, None).await });

        let runtime2 = runtime.clone();
        let sandbox2 = sandbox.clone();
        let handle2 = tokio::spawn(async move { runtime2.create_sandbox(sandbox2, None).await });

        // Wait for both to complete
        let result1 = handle1.await.unwrap();
        let result2 = handle2.await.unwrap();

        // Exactly one should succeed, one should fail with AlreadyExists
        let success_count = [&result1, &result2].iter().filter(|r| r.is_ok()).count();
        let already_exists_count = [&result1, &result2]
            .iter()
            .filter(|r| {
                r.as_ref()
                    .err()
                    .is_some_and(|e| e.code() == Code::AlreadyExists)
            })
            .count();

        assert_eq!(
            success_count, 1,
            "exactly one creation should succeed, got results: {result1:?} {result2:?}"
        );
        assert_eq!(
            already_exists_count, 1,
            "exactly one creation should fail with AlreadyExists, got results: {result1:?} {result2:?}"
        );

        // Verify the successful sandbox can be retrieved by name
        let created_sandbox = [result1, result2]
            .into_iter()
            .find_map(Result::ok)
            .expect("should have one successful creation");
        let retrieved = runtime
            .store
            .get_message_by_name::<Sandbox>("test-concurrent")
            .await
            .unwrap();
        assert!(
            retrieved.is_some(),
            "created sandbox should be retrievable by name"
        );
        assert_eq!(
            retrieved.unwrap().object_id(),
            created_sandbox.object_id(),
            "retrieved sandbox should match created sandbox"
        );
    }
}
