// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Docker compute driver.

#![allow(clippy::result_large_err)]

pub mod otel_tracing;

use bollard::errors::Error as BollardError;
use bollard::models::{
    ContainerCreateBody, ContainerInspectResponse, ContainerState, ContainerStateStatusEnum,
    ContainerSummary, ContainerSummaryStateEnum, CreateImageInfo, DeviceRequest, EndpointSettings,
    HostConfig, Mount, MountTmpfsOptions, MountTypeEnum, MountVolumeOptions, NetworkCreateRequest,
    NetworkingConfig, ProgressDetail, SystemInfo,
};
use bollard::query_parameters::{
    CreateContainerOptionsBuilder, CreateImageOptions, DownloadFromContainerOptionsBuilder,
    ListContainersOptionsBuilder, RemoveContainerOptionsBuilder, RenameContainerOptionsBuilder,
    StopContainerOptionsBuilder, UploadToContainerOptionsBuilder,
};
use bollard::{Docker, body_try_stream};
use bytes::Bytes;
use futures::{Stream, StreamExt};
use openshell_core::config::DEFAULT_STOP_TIMEOUT_SECS;
use openshell_core::driver_mounts;
use openshell_core::driver_utils::{
    CONDITION_EXITED, CONDITION_RUNTIME_RESTART, CONDITION_WORKSPACE_VALIDATION_FAILED,
    GatewayCallbackTopology, LABEL_MANAGED_BY, LABEL_MANAGED_BY_VALUE, LABEL_SANDBOX_ID,
    LABEL_SANDBOX_NAME, LABEL_SANDBOX_NAMESPACE, LABEL_SANDBOX_WORKSPACE,
    SUPERVISOR_EXIT_WORKSPACE_VALIDATION_FAILED, SUPERVISOR_IMAGE_BINARY_PATH,
    extract_first_tar_entry, gateway_callback_endpoint, supervisor_image_should_refresh,
    temp_extract_container_name, validate_linux_elf_binary, write_cache_binary_atomic,
};
use openshell_core::gpu::{
    CdiGpuDefaultSelector, CdiGpuInventory, CdiGpuSelectionError, driver_gpu_requirements,
    effective_driver_gpu_count, validate_specific_gpu_device_request,
};
use openshell_core::network_trust::{
    NETWORK_SUPERVISOR_TRUST_GENERATION_KEY, NETWORK_SUPERVISOR_TRUST_GENERATION_NONE,
};
use openshell_core::progress::{
    PROGRESS_STEP_PULLING_IMAGE, PROGRESS_STEP_REQUESTING_SANDBOX, PROGRESS_STEP_STARTING_SANDBOX,
    format_bytes, mark_progress_active, mark_progress_complete, mark_progress_detail,
};
use openshell_core::proto::compute::v1::{
    CpuResourceCapabilities, CreateSandboxRequest, CreateSandboxResponse, DeleteSandboxRequest,
    DeleteSandboxResponse, DeleteWorkspaceRequest, DeleteWorkspaceResponse, DriverCondition,
    DriverPlatformEvent, DriverSandbox, DriverSandboxStatus, DriverSandboxTemplate,
    EnsureWorkspaceRequest, EnsureWorkspaceResponse, GatewayListenerRequirement,
    GetCapabilitiesRequest, GetCapabilitiesResponse, GetGatewayListenerRequirementsRequest,
    GetGatewayListenerRequirementsResponse, GetSandboxRequest, GetSandboxResponse,
    GpuResourceCapabilities, GpuResourceRequirements, ListSandboxesRequest, ListSandboxesResponse,
    MemoryResourceCapabilities, ResourceCapabilities, StartSandboxRequest, StartSandboxResponse,
    StopSandboxRequest, StopSandboxResponse, ValidateSandboxCreateRequest,
    ValidateSandboxCreateResponse, WatchSandboxesDeletedEvent, WatchSandboxesEvent,
    WatchSandboxesPlatformEvent, WatchSandboxesRequest, WatchSandboxesSandboxEvent,
    compute_driver_server::ComputeDriver, gateway_listener_requirement::Selector,
    watch_sandboxes_event,
};
use openshell_core::proto_struct::{
    deserialize_optional_non_empty_string_list, struct_to_json_value,
};
use openshell_core::{
    AppArmorProfile, Error, ImagePullPolicy, NetworkSupervisorTrustBundle, Result as CoreResult,
    UpstreamProxyConfig,
};
use opentelemetry::trace::TraceContextExt as _;
use std::collections::{HashMap, HashSet};
use std::io::{SeekFrom, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{
    Arc, Mutex as StdMutex, Weak,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tokio::io::AsyncReadExt as _;
use tokio::sync::{Mutex, Semaphore, broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{Instrument as _, debug, info, warn};
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use url::Url;
use uuid::Uuid;

const WATCH_BUFFER: usize = 128;
const WATCH_POLL_INTERVAL: Duration = Duration::from_secs(2);
const WATCH_POLL_MAX_BACKOFF: Duration = Duration::from_secs(30);

const SUPERVISOR_MOUNT_PATH: &str = openshell_core::driver_utils::SUPERVISOR_CONTAINER_BINARY;
const NETWORK_ADDITIONAL_CA_BUNDLE_PATH: &str =
    openshell_core::container_paths::NETWORK_ADDITIONAL_CA_BUNDLE_PATH;
const TLS_CA_MOUNT_PATH: &str = openshell_core::driver_utils::TLS_CA_MOUNT_PATH;
const TLS_CERT_MOUNT_PATH: &str = openshell_core::driver_utils::TLS_CERT_MOUNT_PATH;
const TLS_KEY_MOUNT_PATH: &str = openshell_core::driver_utils::TLS_KEY_MOUNT_PATH;
const SANDBOX_TOKEN_MOUNT_PATH: &str = openshell_core::driver_utils::SANDBOX_TOKEN_MOUNT_PATH;
const UPSTREAM_PROXY_AUTH_MOUNT_PATH: &str =
    openshell_core::driver_utils::UPSTREAM_PROXY_AUTH_MOUNT_PATH;
const PROVIDER_SPIFFE_WORKLOAD_API_SOCKET_MOUNT_DIR: &str =
    openshell_core::driver_utils::PROVIDER_SPIFFE_WORKLOAD_API_SOCKET_MOUNT_DIR;
const SUPERVISOR_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const HOST_OPENSHELL_INTERNAL: &str = "host.openshell.internal";
const HOST_DOCKER_INTERNAL: &str = "host.docker.internal";
const DOCKER_NETWORK_DRIVER: &str = "bridge";

/// Docker labels have no length restriction comparable to Kubernetes labels,
/// so this can hold the full `sha256:<hex>` startup generation.
const DOCKER_SANDBOX_WORKSPACE_ROOT_LABEL: &str = "openshell.ai/docker-workspace-root";

/// A stopped sandbox's writable workspace can contain source code and other
/// private user data. Keep its transient Docker archive bounded and in an
/// unlinked owner-only file rather than retaining it in process memory.
const MAX_DOCKER_WORKSPACE_ARCHIVE_BYTES: u64 = 10 * 1024 * 1024 * 1024;
const DOCKER_WORKSPACE_ARCHIVE_CHUNK_BYTES: usize = 64 * 1024;
const DOCKER_WORKSPACE_ARCHIVE_CHANNEL_CAPACITY: usize = 1;
const MAX_CONCURRENT_DOCKER_WORKSPACE_ARCHIVES: usize = 1;
const DOCKER_REPLACEMENT_NAME_ATTEMPTS: usize = 3;

fn provisioning_span(
    parent: &opentelemetry::Context,
    sandbox: &DriverSandbox,
    image_ref: &str,
) -> tracing::Span {
    let span = tracing::info_span!(
        parent: None,
        "docker.provision",
        otel.name = "docker.provision",
        otel.status_code = tracing::field::Empty,
        sandbox.id = %sandbox.id,
        sandbox.name = %sandbox.name,
        image.ref = %image_ref,
    );
    let parent_span_context = parent.span().span_context().clone();
    if parent_span_context.is_valid() {
        let parent = opentelemetry::Context::new().with_remote_span_context(parent_span_context);
        let _ = span.set_parent(parent);
    }
    span
}

/// Gateway-local configuration for the Docker compute driver.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DockerComputeConfig {
    /// Docker API Unix socket. When unset, use the socket selected by gateway
    /// auto-detection, falling back to `/var/run/docker.sock` for an explicitly
    /// configured Docker driver.
    pub socket_path: Option<PathBuf>,

    /// Default OCI image for sandboxes.
    pub default_image: String,

    /// Image pull policy for sandbox images.
    pub image_pull_policy: ImagePullPolicy,

    /// Value of the `openshell.sandbox_namespace` label applied to Docker sandboxes.
    pub sandbox_label: String,

    /// Gateway gRPC endpoint the sandbox connects back to.
    pub grpc_endpoint: String,

    /// Optional override for the Linux `openshell-sandbox` binary mounted into containers.
    pub supervisor_bin: Option<PathBuf>,

    /// Optional image used to extract the Linux `openshell-sandbox` binary.
    /// Ignored when `supervisor_bin` is set. See `resolve_supervisor_bin` for
    /// the full resolution order.
    pub supervisor_image: Option<String>,

    /// Host-side CA certificate for Docker sandbox mTLS.
    pub guest_tls_ca: Option<PathBuf>,

    /// Host-side client certificate for Docker sandbox mTLS.
    pub guest_tls_cert: Option<PathBuf>,

    /// Host-side private key for Docker sandbox mTLS.
    pub guest_tls_key: Option<PathBuf>,

    /// Docker bridge network that sandbox containers join.
    pub network_name: String,

    /// Host gateway IP used for sandbox host aliases.
    pub host_gateway_ip: String,

    /// Unix socket path the in-container supervisor bridges relay traffic to.
    pub ssh_socket_path: String,

    /// Container cgroup PID limit for Docker-managed sandboxes.
    ///
    /// Omit the field to use `OpenShell`'s 2048-process sandbox limit. Explicit
    /// zero is invalid.
    #[serde(
        default = "openshell_core::config::default_sandbox_pids_limit",
        skip_serializing_if = "Option::is_none"
    )]
    pub sandbox_pids_limit: Option<std::num::NonZeroI64>,

    /// Allow sandbox requests to attach host bind mounts through
    /// `template.driver_config`.
    #[serde(default)]
    pub enable_bind_mounts: bool,

    /// Corporate forward-proxy settings supplied to the supervisor on argv.
    /// The flattened fields retain the common `https_proxy`, `no_proxy`, and
    /// `proxy_auth_*` gateway TOML contract.
    #[serde(flatten)]
    pub upstream_proxy: UpstreamProxyConfig,

    /// Host UNIX socket to project into sandbox supervisors for provider
    /// SPIFFE token exchange.
    pub provider_spiffe_workload_api_socket: Option<PathBuf>,

    /// `AppArmor` confinement requested for sandbox containers. The explicit
    /// default preserves the prior supervisor-compatible Docker behavior.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_armor_profile: Option<AppArmorProfile>,
}

impl DockerComputeConfig {
    /// Validate startup configuration without connecting to Docker.
    pub fn validate_configuration(&self, gateway_bind_address: SocketAddr) -> CoreResult<()> {
        if let Some(socket_path) = self.socket_path.as_deref()
            && socket_path.to_str().is_none()
        {
            return Err(Error::config(format!(
                "Docker socket path is not valid UTF-8: {}",
                socket_path.display()
            )));
        }
        validate_sandbox_pids_limit(self.sandbox_pids_limit)?;
        validate_image_pull_policy(self.image_pull_policy)?;
        self.upstream_proxy.validate().map_err(Error::config)?;
        if let Some(socket) = self.provider_spiffe_workload_api_socket.as_deref() {
            openshell_core::driver_utils::validate_provider_spiffe_unix_socket(socket)
                .map_err(Error::config)?;
        }
        parse_optional_host_gateway_ip(&self.host_gateway_ip)?;
        if gateway_bind_address.port() == 0 {
            return Err(Error::config(
                "docker compute driver requires a fixed non-zero gateway bind port",
            ));
        }
        Ok(())
    }
}

impl Default for DockerComputeConfig {
    fn default() -> Self {
        Self {
            socket_path: None,
            default_image: openshell_core::image::default_sandbox_image(),
            image_pull_policy: ImagePullPolicy::default(),
            sandbox_label: "default".to_string(),
            grpc_endpoint: String::new(),
            supervisor_bin: None,
            supervisor_image: None,
            guest_tls_ca: None,
            guest_tls_cert: None,
            guest_tls_key: None,
            network_name: DEFAULT_DOCKER_NETWORK_NAME.to_string(),
            host_gateway_ip: String::new(),
            ssh_socket_path: openshell_core::container_paths::SSH_SOCKET_PATH.to_string(),
            sandbox_pids_limit: openshell_core::config::default_sandbox_pids_limit(),
            enable_bind_mounts: false,
            upstream_proxy: UpstreamProxyConfig::default(),
            provider_spiffe_workload_api_socket: None,
            app_armor_profile: Some(AppArmorProfile::Unconfined),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DockerGuestTlsPaths {
    pub(crate) ca: PathBuf,
    pub(crate) cert: PathBuf,
    pub(crate) key: PathBuf,
}

#[derive(Debug, Clone)]
struct DockerDriverRuntimeConfig {
    default_image: String,
    image_pull_policy: ImagePullPolicy,
    sandbox_label: String,
    grpc_endpoint: String,
    network_name: String,
    gateway_route: DockerGatewayRoute,
    gateway_callback_bind_address: Option<SocketAddr>,
    ssh_socket_path: String,
    stop_timeout_secs: u32,
    log_level: String,
    supervisor_bin: PathBuf,
    guest_tls: Option<DockerGuestTlsPaths>,
    /// Gateway-owned normalized destination trust material. The driver keeps
    /// the immutable startup snapshot so stopped-container reconciliation can
    /// compare and verify its generation without reading user configuration.
    network_trust_bundle: Option<NetworkSupervisorTrustBundle>,
    daemon_version: String,
    gpu: DockerGpuRuntimeCapabilities,
    sandbox_pids_limit: Option<std::num::NonZeroI64>,
    enable_bind_mounts: bool,
    upstream_proxy: UpstreamProxyConfig,
    provider_spiffe_workload_api_socket: Option<PathBuf>,
    app_armor_profile: Option<AppArmorProfile>,
}

#[derive(Debug, Clone, Copy)]
struct DockerGpuRuntimeCapabilities {
    cdi_supported: bool,
    wsl_all_gpu_fallback_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DockerGatewayRoute {
    Bridge {
        bind_address: SocketAddr,
        host_alias_ip: IpAddr,
    },
    HostGateway,
}

#[derive(Clone)]
pub struct DockerComputeDriver {
    docker: Arc<Docker>,
    config: DockerDriverRuntimeConfig,
    events: broadcast::Sender<WatchSandboxesEvent>,
    pending: Arc<Mutex<HashMap<String, PendingSandboxRecord>>>,
    gpu_selector: Arc<CdiGpuDefaultSelector>,
    lifecycle_event_fences: DockerLifecycleEventFences,
    /// A replacement briefly has both the old and new containers present.
    /// A gate keyed by stable sandbox ID prevents concurrent starts from
    /// racing that hand-off while allowing unrelated sandboxes to proceed.
    start_operation_gates: Arc<DockerStartGateRegistry>,
    /// Workspace export/filter pipelines are globally bounded because their
    /// private archive files consume gateway temporary storage. The raw
    /// daemon stream is filtered through a bounded channel, so each permit
    /// accounts for at most one on-disk archive.
    workspace_archive_transfers: Arc<Semaphore>,
}

/// Serializes full start/reconciliation transactions for one sandbox without
/// retaining an entry for every sandbox ever started. A caller holds a strong
/// reference to its gate while waiting and while executing; the registry keeps
/// only a weak reference and prunes stale entries on subsequent lookups.
#[derive(Debug, Default)]
struct DockerStartGateRegistry {
    gates: StdMutex<HashMap<String, Weak<Mutex<()>>>>,
}

impl DockerStartGateRegistry {
    async fn lock_for(&self, sandbox_id: &str, sandbox_name: &str) -> DockerStartGuard {
        let key = if sandbox_id.is_empty() {
            sandbox_name
        } else {
            sandbox_id
        };
        let gate = self.gate_for(key);
        DockerStartGuard {
            _guard: gate.lock_owned().await,
        }
    }

    fn gate_for(&self, key: &str) -> Arc<Mutex<()>> {
        let mut gates = self
            .gates
            .lock()
            .expect("Docker start gate registry lock poisoned");
        gates.retain(|_, gate| gate.strong_count() > 0);
        if let Some(gate) = gates.get(key).and_then(Weak::upgrade) {
            return gate;
        }

        let gate = Arc::new(Mutex::new(()));
        gates.insert(key.to_string(), Arc::downgrade(&gate));
        gate
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.gates
            .lock()
            .expect("Docker start gate registry lock poisoned")
            .len()
    }
}

/// Proof that this start/reconciliation transaction holds its sandbox gate.
#[derive(Debug)]
struct DockerStartGuard {
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

/// Per-sandbox container exit timestamps that fence snapshots from an earlier run.
///
/// Docker's polling loop can observe the stopped container before a restart and
/// publish that snapshot after the gateway has moved the sandbox to `Starting`.
/// Comparing the container's transition timestamp prevents that old observation
/// from regressing the new lifecycle operation to `Error`.
#[derive(Clone, Debug, Default)]
struct DockerLifecycleEventFences {
    state: Arc<std::sync::Mutex<DockerLifecycleFenceState>>,
}

#[derive(Debug, Default)]
struct DockerLifecycleFenceState {
    previous_finished_at: HashMap<String, String>,
    starts_in_progress: HashSet<String>,
    /// Stable IDs of stopped containers successfully replaced during the
    /// latest start. A poll may have captured one before removal and publish
    /// it after the start transaction completes, when timestamp inspection is
    /// no longer possible because that exact container no longer exists.
    superseded_instance_ids: HashMap<String, HashSet<String>>,
}

impl DockerLifecycleEventFences {
    fn begin_start(&self, sandbox_id: &str) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .starts_in_progress
            .insert(sandbox_id.to_string());
    }

    fn finish_start(&self, sandbox_id: &str) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .starts_in_progress
            .remove(sandbox_id);
    }

    fn start_in_progress(&self, sandbox_id: &str) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .starts_in_progress
            .contains(sandbox_id)
    }

    fn record_previous_exit(&self, sandbox_id: &str, finished_at: Option<&str>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match finished_at.filter(|finished_at| !finished_at.is_empty()) {
            Some(finished_at) => {
                state
                    .previous_finished_at
                    .insert(sandbox_id.to_string(), finished_at.to_string());
            }
            None => {
                state.previous_finished_at.remove(sandbox_id);
            }
        }
    }

    fn previous_exit(&self, sandbox_id: &str) -> Option<String> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .previous_finished_at
            .get(sandbox_id)
            .cloned()
    }

    fn record_superseded_instance(&self, sandbox_id: &str, instance_id: &str) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .superseded_instance_ids
            .entry(sandbox_id.to_string())
            .or_default()
            .insert(instance_id.to_string());
    }

    fn is_superseded_instance(&self, sandbox_id: &str, instance_id: &str) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .superseded_instance_ids
            .get(sandbox_id)
            .is_some_and(|instances| instances.contains(instance_id))
    }

    fn clear_superseded_instances(&self, sandbox_id: &str) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .superseded_instance_ids
            .remove(sandbox_id);
    }

    fn remove(&self, sandbox_id: &str) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.previous_finished_at.remove(sandbox_id);
        state.starts_in_progress.remove(sandbox_id);
        state.superseded_instance_ids.remove(sandbox_id);
    }
}

struct PendingSandboxRecord {
    sandbox: DriverSandbox,
    task: Option<JoinHandle<()>>,
}

#[derive(Debug, Clone)]
struct DockerProvisioningFailure {
    reason: &'static str,
    message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DockerImageMetadata {
    id: String,
    user: String,
    working_dir: String,
    volumes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct DockerResourceLimits {
    nano_cpus: Option<i64>,
    memory_bytes: Option<i64>,
}

/// An anonymous owner-only file holding a Docker workspace archive. Keeping
/// the file descriptor alive makes the archive unreachable by pathname and
/// guarantees cleanup on every return path.
struct DockerWorkspaceArchive {
    file: std::fs::File,
    byte_len: u64,
}

impl DockerWorkspaceArchive {
    const fn len(&self) -> u64 {
        self.byte_len
    }

    fn into_upload_stream(
        self,
    ) -> impl Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static {
        let file = tokio::fs::File::from_std(self.file);
        futures::stream::try_unfold(file, |mut file| async move {
            let mut buffer = vec![0_u8; DOCKER_WORKSPACE_ARCHIVE_CHUNK_BYTES];
            let read = file.read(&mut buffer).await?;
            if read == 0 {
                return Ok(None);
            }
            buffer.truncate(read);
            Ok(Some((Bytes::from(buffer), file)))
        })
    }
}

/// Archive failures deliberately retain no I/O, Docker, pathname, or archive
/// payload text. Workspace archives can contain private user content and the
/// API error must never echo it through an intermediary error message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DockerWorkspaceArchiveError {
    TemporaryStorage,
    Download,
    TooLarge { limit: u64 },
    Write,
    Rewind,
    FilterTask,
    InvalidTar,
    CompressedTar,
    UnsupportedTarFeature,
    InvalidEntryPath,
    UnexpectedRoot,
    MissingRootDirectory,
    UnsafeHardLink,
}

impl DockerWorkspaceArchiveError {
    fn status(self) -> Status {
        match self {
            Self::TooLarge { limit } => Status::failed_precondition(format!(
                "Docker sandbox workspace archive exceeds the strict {limit}-byte limit"
            )),
            Self::TemporaryStorage => Status::internal(
                "could not create private Docker sandbox workspace archive storage",
            ),
            Self::Download => {
                Status::internal("could not download Docker sandbox workspace archive")
            }
            Self::Write => {
                Status::internal("could not write private Docker sandbox workspace archive")
            }
            Self::Rewind => {
                Status::internal("could not rewind private Docker sandbox workspace archive")
            }
            Self::FilterTask => {
                Status::internal("could not schedule Docker sandbox workspace archive filtering")
            }
            Self::InvalidTar => Status::failed_precondition(
                "could not filter Docker sandbox workspace archive: archive is malformed or truncated",
            ),
            Self::CompressedTar => Status::failed_precondition(
                "could not filter Docker sandbox workspace archive: compressed tar streams are not safely supported",
            ),
            Self::UnsupportedTarFeature => Status::failed_precondition(
                "could not filter Docker sandbox workspace archive: tar metadata extension cannot be preserved safely",
            ),
            Self::InvalidEntryPath => Status::failed_precondition(
                "could not filter Docker sandbox workspace archive: archive entry path is not normalized",
            ),
            Self::UnexpectedRoot => Status::failed_precondition(
                "could not filter Docker sandbox workspace archive: archive entry is outside the protected workspace root",
            ),
            Self::MissingRootDirectory => Status::failed_precondition(
                "could not filter Docker sandbox workspace archive: expected workspace root directory is missing",
            ),
            Self::UnsafeHardLink => Status::failed_precondition(
                "could not filter Docker sandbox workspace archive: hard-link metadata cannot be preserved safely",
            ),
        }
    }
}

/// A writer that refuses to let a repacked archive cross its hard byte bound.
/// The shared flag lets the caller distinguish its deliberately injected write
/// error from an ordinary temporary-file I/O failure without retaining either
/// error text in a user-visible status.
struct BoundedDockerArchiveWriter {
    file: std::fs::File,
    byte_len: u64,
    limit: u64,
    limit_exceeded: Arc<AtomicBool>,
}

impl BoundedDockerArchiveWriter {
    fn new(file: std::fs::File, limit: u64, limit_exceeded: Arc<AtomicBool>) -> Self {
        Self {
            file,
            byte_len: 0,
            limit,
            limit_exceeded,
        }
    }

    fn into_parts(self) -> (std::fs::File, u64) {
        (self.file, self.byte_len)
    }
}

impl std::io::Write for BoundedDockerArchiveWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let byte_len = u64::try_from(buffer.len()).unwrap_or(u64::MAX);
        if byte_len > self.limit.saturating_sub(self.byte_len) {
            self.limit_exceeded.store(true, Ordering::Relaxed);
            return Err(std::io::Error::other("Docker archive size limit exceeded"));
        }
        let written = self.file.write(buffer)?;
        self.byte_len += u64::try_from(written).unwrap_or(u64::MAX);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

/// Count a tar entry while it is copied so a malformed final entry cannot be
/// retained with a header whose declared size exceeds its actual bytes.
struct CountedDockerArchiveReader<'a, R> {
    reader: &'a mut R,
    byte_len: u64,
}

impl<R> std::io::Read for CountedDockerArchiveReader<'_, R>
where
    R: std::io::Read,
{
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.reader.read(buffer)?;
        self.byte_len += u64::try_from(read).unwrap_or(u64::MAX);
        Ok(read)
    }
}

/// Components of a path from a tar header. They are bytes rather than host
/// paths so filtering neither decodes user filenames nor follows symlinks.
type DockerArchivePath = Vec<Vec<u8>>;

struct DockerWorkspaceArchiveFilter {
    archive_root: Vec<u8>,
    excluded_mounts: Vec<DockerArchivePath>,
}

impl DockerWorkspaceArchiveFilter {
    fn new(
        workspace_root: &str,
        excluded_mounts: Vec<DockerArchivePath>,
    ) -> Result<Self, DockerWorkspaceArchiveError> {
        let archive_root = workspace_root
            .rsplit('/')
            .next()
            .filter(|component| !component.is_empty())
            .map(str::as_bytes)
            .map(ToOwned::to_owned)
            .ok_or(DockerWorkspaceArchiveError::InvalidEntryPath)?;
        Ok(Self {
            archive_root,
            excluded_mounts,
        })
    }

    fn excludes(&self, path_under_root: &[Vec<u8>]) -> bool {
        self.excluded_mounts.iter().any(|mount| {
            path_under_root.len() >= mount.len()
                && path_under_root
                    .iter()
                    .zip(mount)
                    .all(|(path, mount)| path == mount)
        })
    }
}

/// Return normalized relative components without using host filesystem path
/// resolution. Tar's slash-separated names are interpreted lexically only.
fn docker_archive_path_components(
    bytes: &[u8],
) -> Result<DockerArchivePath, DockerWorkspaceArchiveError> {
    if bytes.is_empty() || bytes.starts_with(b"/") {
        return Err(DockerWorkspaceArchiveError::InvalidEntryPath);
    }

    // Docker emits a trailing slash for directory entries. Retain it in the
    // copied header but remove one terminator for lexical comparison; a second
    // slash remains an invalid empty component below.
    let bytes = bytes.strip_suffix(b"/").unwrap_or(bytes);
    if bytes.is_empty() {
        return Err(DockerWorkspaceArchiveError::InvalidEntryPath);
    }

    let mut components = Vec::new();
    for component in bytes.split(|byte| *byte == b'/') {
        if component.is_empty() {
            return Err(DockerWorkspaceArchiveError::InvalidEntryPath);
        }
        if matches!(component, b"." | b"..") {
            return Err(DockerWorkspaceArchiveError::InvalidEntryPath);
        }
        components.push(component.to_vec());
    }
    if components.is_empty() {
        return Err(DockerWorkspaceArchiveError::InvalidEntryPath);
    }
    Ok(components)
}

fn docker_workspace_archive_prefix_is_compressed(prefix: &[u8]) -> bool {
    prefix.starts_with(&[0x1f, 0x8b])
        || prefix.starts_with(b"BZh")
        || prefix.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00])
        || prefix.starts_with(&[0x28, 0xb5, 0x2f, 0xfd])
}

fn prefixed_docker_workspace_archive_reader<R>(
    mut reader: R,
) -> Result<impl std::io::Read, DockerWorkspaceArchiveError>
where
    R: std::io::Read,
{
    let mut prefix = Vec::with_capacity(6);
    while prefix.len() < 6 {
        let mut buffer = [0_u8; 6];
        let read = reader
            .read(&mut buffer[..6 - prefix.len()])
            .map_err(|_| DockerWorkspaceArchiveError::InvalidTar)?;
        if read == 0 {
            break;
        }
        prefix.extend_from_slice(&buffer[..read]);
    }
    if docker_workspace_archive_prefix_is_compressed(&prefix) {
        return Err(DockerWorkspaceArchiveError::CompressedTar);
    }
    Ok(std::io::Read::chain(std::io::Cursor::new(prefix), reader))
}

fn copy_docker_archive_entry<R>(
    entry: &mut R,
    expected_size: u64,
    builder: &mut tar::Builder<BoundedDockerArchiveWriter>,
    header: &tar::Header,
    limit: u64,
    limit_exceeded: &AtomicBool,
) -> Result<(), DockerWorkspaceArchiveError>
where
    R: std::io::Read,
{
    let mut counted = CountedDockerArchiveReader {
        reader: entry,
        byte_len: 0,
    };
    builder.append(header, &mut counted).map_err(|_| {
        if limit_exceeded.load(Ordering::Relaxed) {
            DockerWorkspaceArchiveError::TooLarge { limit }
        } else {
            DockerWorkspaceArchiveError::Write
        }
    })?;
    if counted.byte_len != expected_size {
        return Err(DockerWorkspaceArchiveError::InvalidTar);
    }
    Ok(())
}

fn discard_docker_archive_entry<R>(
    entry: &mut R,
    expected_size: u64,
) -> Result<(), DockerWorkspaceArchiveError>
where
    R: std::io::Read,
{
    let discarded = std::io::copy(entry, &mut std::io::sink())
        .map_err(|_| DockerWorkspaceArchiveError::InvalidTar)?;
    if discarded != expected_size {
        return Err(DockerWorkspaceArchiveError::InvalidTar);
    }
    Ok(())
}

/// Repack a daemon-provided workspace tar while omitting the durable
/// sandbox's nested user mounts. Only standard entries whose raw headers can
/// be copied byte-for-byte are accepted; extension records are rejected rather
/// than silently dropping metadata or resolving a symlink on the gateway.
#[cfg(test)]
fn filter_docker_workspace_archive(
    mut archive: DockerWorkspaceArchive,
    filter: DockerWorkspaceArchiveFilter,
    limit: u64,
) -> Result<DockerWorkspaceArchive, DockerWorkspaceArchiveError> {
    // `byte_len` is normally set while the daemon response is streamed, but
    // enforce the cap again from the anonymous file itself before parsing.
    // This keeps the parser bounded even if a future caller constructs an
    // archive through a different path.
    let input_len = archive
        .file
        .metadata()
        .map_err(|_| DockerWorkspaceArchiveError::Rewind)?
        .len();
    if input_len > limit || archive.byte_len > limit {
        return Err(DockerWorkspaceArchiveError::TooLarge { limit });
    }
    std::io::Seek::seek(&mut archive.file, SeekFrom::Start(0))
        .map_err(|_| DockerWorkspaceArchiveError::Rewind)?;
    filter_docker_workspace_archive_reader(archive.file, filter, limit)
}

fn filter_docker_workspace_archive_reader<R>(
    reader: R,
    filter: DockerWorkspaceArchiveFilter,
    limit: u64,
) -> Result<DockerWorkspaceArchive, DockerWorkspaceArchiveError>
where
    R: std::io::Read,
{
    let reader = prefixed_docker_workspace_archive_reader(reader)?;
    let output = private_docker_workspace_archive_file()?;
    let limit_exceeded = Arc::new(AtomicBool::new(false));
    let writer = BoundedDockerArchiveWriter::new(output, limit, limit_exceeded.clone());
    let mut builder = tar::Builder::new(writer);
    let mut input = tar::Archive::new(reader);
    let entries = input
        .entries()
        .map_err(|_| DockerWorkspaceArchiveError::InvalidTar)?;
    let mut root_seen = false;
    let mut seen_paths = HashSet::new();

    for entry in entries {
        let mut entry = entry.map_err(|_| DockerWorkspaceArchiveError::InvalidTar)?;
        if entry
            .pax_extensions()
            .map_err(|_| DockerWorkspaceArchiveError::InvalidTar)?
            .is_some()
        {
            return Err(DockerWorkspaceArchiveError::UnsupportedTarFeature);
        }

        let header = entry.header().clone();
        let entry_type = header.entry_type();
        if !(entry_type.is_file()
            || entry_type.is_dir()
            || entry_type.is_symlink()
            || entry_type.is_hard_link())
        {
            return Err(DockerWorkspaceArchiveError::UnsupportedTarFeature);
        }
        if entry_type.is_gnu_sparse() {
            return Err(DockerWorkspaceArchiveError::UnsupportedTarFeature);
        }

        // `entries()` hides GNU/PAX long-name records. Copying the ordinary
        // header in that case would silently truncate the effective path or
        // link target, so reject it rather than rewriting metadata.
        let entry_path = entry.path_bytes().into_owned();
        if entry_path.as_slice() != header.path_bytes().as_ref() {
            return Err(DockerWorkspaceArchiveError::UnsupportedTarFeature);
        }
        let entry_link = entry.link_name_bytes().map(std::borrow::Cow::into_owned);
        let header_link = header.link_name_bytes().map(std::borrow::Cow::into_owned);
        if entry_link != header_link {
            return Err(DockerWorkspaceArchiveError::UnsupportedTarFeature);
        }

        let expected_size = header
            .entry_size()
            .map_err(|_| DockerWorkspaceArchiveError::InvalidTar)?;
        if entry.size() != expected_size {
            return Err(DockerWorkspaceArchiveError::UnsupportedTarFeature);
        }
        let path = docker_archive_path_components(&entry_path)?;
        if !seen_paths.insert(path.clone()) {
            return Err(DockerWorkspaceArchiveError::InvalidEntryPath);
        }
        if path.first() != Some(&filter.archive_root) {
            return Err(DockerWorkspaceArchiveError::UnexpectedRoot);
        }
        if path.len() == 1 {
            if root_seen || !entry_type.is_dir() {
                return Err(DockerWorkspaceArchiveError::MissingRootDirectory);
            }
            root_seen = true;
        } else if !root_seen {
            return Err(DockerWorkspaceArchiveError::MissingRootDirectory);
        }

        if entry_type.is_symlink() && entry_link.is_none() {
            return Err(DockerWorkspaceArchiveError::UnsupportedTarFeature);
        }
        if entry_type.is_hard_link() {
            let link = entry_link.ok_or(DockerWorkspaceArchiveError::UnsafeHardLink)?;
            let link_path = docker_archive_path_components(&link)?;
            if link_path.first() != Some(&filter.archive_root) || filter.excludes(&link_path[1..]) {
                return Err(DockerWorkspaceArchiveError::UnsafeHardLink);
            }
        }

        if filter.excludes(&path[1..]) {
            discard_docker_archive_entry(&mut entry, expected_size)?;
        } else {
            copy_docker_archive_entry(
                &mut entry,
                expected_size,
                &mut builder,
                &header,
                limit,
                &limit_exceeded,
            )?;
        }
    }

    // Do not let the blocking parser return while the asynchronous producer
    // still owns unread daemon bytes. Draining through EOF keeps the raw input
    // bound authoritative and ensures the channel holds at most one chunk.
    std::io::copy(&mut input.into_inner(), &mut std::io::sink())
        .map_err(|_| DockerWorkspaceArchiveError::InvalidTar)?;
    if !root_seen {
        return Err(DockerWorkspaceArchiveError::MissingRootDirectory);
    }
    builder.finish().map_err(|_| {
        if limit_exceeded.load(Ordering::Relaxed) {
            DockerWorkspaceArchiveError::TooLarge { limit }
        } else {
            DockerWorkspaceArchiveError::Write
        }
    })?;
    let writer = builder.into_inner().map_err(|_| {
        if limit_exceeded.load(Ordering::Relaxed) {
            DockerWorkspaceArchiveError::TooLarge { limit }
        } else {
            DockerWorkspaceArchiveError::Write
        }
    })?;
    let (mut file, byte_len) = writer.into_parts();
    file.flush()
        .map_err(|_| DockerWorkspaceArchiveError::Write)?;
    std::io::Seek::seek(&mut file, SeekFrom::Start(0))
        .map_err(|_| DockerWorkspaceArchiveError::Rewind)?;
    Ok(DockerWorkspaceArchive { file, byte_len })
}

struct DockerWorkspaceArchiveStreamReader {
    receiver: mpsc::Receiver<Bytes>,
    current: Bytes,
    offset: usize,
}

impl DockerWorkspaceArchiveStreamReader {
    fn new(receiver: mpsc::Receiver<Bytes>) -> Self {
        Self {
            receiver,
            current: Bytes::new(),
            offset: 0,
        }
    }
}

impl std::io::Read for DockerWorkspaceArchiveStreamReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        while self.offset == self.current.len() {
            let Some(chunk) = self.receiver.blocking_recv() else {
                return Ok(0);
            };
            self.current = chunk;
            self.offset = 0;
        }

        let available = &self.current[self.offset..];
        let read = available.len().min(buffer.len());
        buffer[..read].copy_from_slice(&available[..read]);
        self.offset += read;
        Ok(read)
    }
}

async fn download_and_filter_docker_workspace_archive<S, E>(
    mut stream: S,
    filter: DockerWorkspaceArchiveFilter,
    limit: u64,
) -> Result<DockerWorkspaceArchive, DockerWorkspaceArchiveError>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
{
    // Feed the blocking tar parser directly from the daemon stream. Only the
    // filtered archive reaches disk; the bounded channel permits one raw
    // response chunk in memory and applies backpressure to Docker.
    let (sender, receiver) = mpsc::channel(DOCKER_WORKSPACE_ARCHIVE_CHANNEL_CAPACITY);
    let filter_task = tokio::task::spawn_blocking(move || {
        filter_docker_workspace_archive_reader(
            DockerWorkspaceArchiveStreamReader::new(receiver),
            filter,
            limit,
        )
    });

    let mut byte_len = 0_u64;
    let producer_result = loop {
        let Some(chunk) = stream.next().await else {
            break Ok(());
        };
        let Ok(chunk) = chunk else {
            break Err(DockerWorkspaceArchiveError::Download);
        };
        let Ok(chunk_len) = u64::try_from(chunk.len()) else {
            break Err(DockerWorkspaceArchiveError::TooLarge { limit });
        };
        if chunk_len > limit.saturating_sub(byte_len) {
            break Err(DockerWorkspaceArchiveError::TooLarge { limit });
        }
        byte_len += chunk_len;
        if sender.send(chunk).await.is_err() {
            // The parser already reached a more specific terminal result.
            break Ok(());
        }
    };
    drop(sender);

    let filter_result = filter_task
        .await
        .map_err(|_| DockerWorkspaceArchiveError::FilterTask)?;
    producer_result?;
    filter_result
}

fn private_docker_workspace_archive_file() -> Result<std::fs::File, DockerWorkspaceArchiveError> {
    let file = tempfile::tempfile().map_err(|_| DockerWorkspaceArchiveError::TemporaryStorage)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|_| DockerWorkspaceArchiveError::TemporaryStorage)?;
    }
    Ok(file)
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DockerSandboxDriverConfig {
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_empty_string_list"
    )]
    cdi_devices: Option<Vec<String>>,
    mounts: Vec<DockerDriverMountConfig>,
}

struct ValidatedDockerSandbox<'a> {
    template: &'a DriverSandboxTemplate,
    driver_config: DockerSandboxDriverConfig,
    gpu_requirements: Option<&'a GpuResourceRequirements>,
}

impl DockerSandboxDriverConfig {
    fn from_template(template: &DriverSandboxTemplate) -> Result<Self, String> {
        let Some(config) = template.driver_config.as_ref() else {
            return Ok(Self::default());
        };

        serde_json::from_value(struct_to_json_value(config))
            .map_err(|err| format!("invalid docker driver_config: {err}"))
    }
}

use openshell_core::driver_mounts::SelinuxLabel;

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum DockerDriverMountConfig {
    Bind {
        source: String,
        target: String,
        #[serde(default = "default_true")]
        read_only: bool,
        #[serde(default)]
        selinux_label: Option<SelinuxLabel>,
    },
    Volume {
        source: String,
        target: String,
        #[serde(default = "default_true")]
        read_only: bool,
        #[serde(default)]
        subpath: Option<String>,
    },
    Tmpfs {
        target: String,
        #[serde(default)]
        options: Vec<String>,
        #[serde(default)]
        size_bytes: Option<f64>,
        #[serde(default)]
        mode: Option<f64>,
    },
    Image {
        source: String,
        target: String,
        #[serde(default = "default_true")]
        read_only: bool,
        #[serde(default)]
        subpath: Option<String>,
    },
}

fn default_true() -> bool {
    true
}

type WatchStream =
    Pin<Box<dyn Stream<Item = Result<WatchSandboxesEvent, Status>> + Send + 'static>>;

#[cfg(test)]
type TracedWatchStream = openshell_otel::TracedGrpcStream<WatchStream>;

/// Compute-driver service wrapper that preserves the standalone RPC trace
/// boundary while Docker runs in the gateway process.
#[derive(Clone)]
pub struct ComputeDriverService {
    driver: DockerComputeDriver,
    rpc_tracer: openshell_otel::InProcessRpcTracer,
}

impl ComputeDriverService {
    #[must_use]
    pub fn new(driver: DockerComputeDriver) -> Self {
        Self {
            driver,
            rpc_tracer: openshell_otel::InProcessRpcTracer::disabled(),
        }
    }

    #[must_use]
    pub fn new_in_process(driver: DockerComputeDriver) -> Self {
        Self {
            driver,
            rpc_tracer: openshell_otel::InProcessRpcTracer::enabled(),
        }
    }
}

/// Return the first responsive local Docker API socket.
#[must_use]
pub fn detect_socket() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(host) = std::env::var("DOCKER_HOST")
        && let Some(path) = host.trim().strip_prefix("unix://")
        && !path.is_empty()
    {
        candidates.push(PathBuf::from(path));
    }
    candidates.push(PathBuf::from("/var/run/docker.sock"));
    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(PathBuf::from(home).join(".docker/run/docker.sock"));
    }
    if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        candidates.push(PathBuf::from(runtime_dir).join("docker.sock"));
    }
    openshell_core::local_api_socket::first_responsive_socket(&candidates, |response| {
        openshell_core::local_api_socket::http_response_is_success(response)
            && openshell_core::local_api_socket::contains_ascii(response, b"Api-Version:")
            && !openshell_core::local_api_socket::contains_ascii(response, b"Libpod-Api-Version:")
    })
}

#[must_use]
pub fn is_available() -> bool {
    detect_socket().is_some()
}

impl DockerComputeDriver {
    pub async fn new(
        gateway_bind_address: SocketAddr,
        gateway_log_level: &str,
        docker_config: &DockerComputeConfig,
        network_trust_bundle: Option<NetworkSupervisorTrustBundle>,
    ) -> CoreResult<Self> {
        docker_config.validate_configuration(gateway_bind_address)?;
        let socket_path = docker_config
            .socket_path
            .clone()
            .or_else(detect_socket)
            .unwrap_or_else(|| PathBuf::from("/var/run/docker.sock"));
        let socket_path_str = socket_path.to_str().ok_or_else(|| {
            Error::config(format!(
                "Docker socket path is not valid UTF-8: {}",
                socket_path.display()
            ))
        })?;
        let docker =
            Docker::connect_with_socket(socket_path_str, 120, bollard::API_DEFAULT_VERSION)
                .map_err(|err| {
                    Error::execution(format!("failed to create Docker client: {err}"))
                })?;
        let version = docker.version().await.map_err(|err| {
            Error::execution(format!("failed to query Docker daemon version: {err}"))
        })?;
        let info = docker.info().await.map_err(|err| {
            Error::execution(format!("failed to query Docker daemon info: {err}"))
        })?;
        let cdi_supported = info
            .cdi_spec_dirs
            .as_ref()
            .is_some_and(|dirs| !dirs.is_empty());
        let cdi_gpu_inventory = docker_cdi_gpu_inventory(&info);
        let wsl_all_gpu_fallback_enabled = docker_info_reports_wsl2(&info);
        let gpu = DockerGpuRuntimeCapabilities {
            cdi_supported,
            wsl_all_gpu_fallback_enabled,
        };
        validate_docker_proxy_auth_file(&docker_config.upstream_proxy)?;
        validate_docker_app_armor_profile(docker_config.app_armor_profile.as_ref(), &info)?;
        let gateway_port = gateway_bind_address.port();
        let network_name = docker_network_name(docker_config);
        let bridge_gateway_ip = ensure_bridge_network(&docker, &network_name).await?;
        let host_gateway_ip = parse_optional_host_gateway_ip(&docker_config.host_gateway_ip)?;
        let gateway_route =
            docker_gateway_route(&info, bridge_gateway_ip, gateway_port, host_gateway_ip);
        let gateway_callback_bind_address =
            docker_gateway_callback_bind_address(&gateway_route, gateway_bind_address);
        let mut docker_config = docker_config.clone();
        if docker_config.grpc_endpoint.trim().is_empty() {
            docker_config.grpc_endpoint = gateway_callback_endpoint(
                GatewayCallbackTopology::Docker,
                gateway_port,
                docker_guest_tls_configured(&docker_config),
            );
        }
        let grpc_endpoint = docker_container_openshell_endpoint(
            &docker_config.grpc_endpoint,
            HOST_OPENSHELL_INTERNAL,
            gateway_port,
        );
        let daemon_arch = normalize_docker_arch(version.arch.as_deref().unwrap_or_default());
        let supervisor_bin = resolve_supervisor_bin(&docker, &docker_config, &daemon_arch).await?;
        let guest_tls = docker_guest_tls_paths(&docker_config)?;

        let driver = Self {
            docker: Arc::new(docker),
            config: DockerDriverRuntimeConfig {
                default_image: docker_config.default_image.clone(),
                image_pull_policy: docker_config.image_pull_policy,
                sandbox_label: docker_config.sandbox_label.clone(),
                grpc_endpoint,
                network_name,
                gateway_route,
                gateway_callback_bind_address,
                ssh_socket_path: docker_config.ssh_socket_path.clone(),
                stop_timeout_secs: DEFAULT_STOP_TIMEOUT_SECS,
                log_level: gateway_log_level.to_string(),
                supervisor_bin,
                guest_tls,
                network_trust_bundle,
                daemon_version: version.version.unwrap_or_else(|| "unknown".to_string()),
                gpu,
                sandbox_pids_limit: docker_config.sandbox_pids_limit,
                enable_bind_mounts: docker_config.enable_bind_mounts,
                upstream_proxy: docker_config.upstream_proxy.clone(),
                provider_spiffe_workload_api_socket: docker_config
                    .provider_spiffe_workload_api_socket
                    .clone(),
                app_armor_profile: docker_config.app_armor_profile.clone(),
            },
            events: broadcast::channel(WATCH_BUFFER).0,
            pending: Arc::new(Mutex::new(HashMap::new())),
            gpu_selector: Arc::new(CdiGpuDefaultSelector::new(
                cdi_gpu_inventory,
                gpu.wsl_all_gpu_fallback_enabled,
            )),
            lifecycle_event_fences: DockerLifecycleEventFences::default(),
            start_operation_gates: Arc::new(DockerStartGateRegistry::default()),
            workspace_archive_transfers: Arc::new(Semaphore::new(
                MAX_CONCURRENT_DOCKER_WORKSPACE_ARCHIVES,
            )),
        };

        let poll_driver = driver.clone();
        tokio::spawn(async move {
            poll_driver.poll_loop().await;
        });

        Ok(driver)
    }

    fn capabilities(&self) -> GetCapabilitiesResponse {
        GetCapabilitiesResponse {
            driver_name: "docker".to_string(),
            driver_version: self.config.daemon_version.clone(),
            default_image: self.config.default_image.clone(),
            gateway_manages_lifecycle: true,
            supports_sandbox_authentication: false,
            driver_reports_runtime_readiness: false,
            resource_capabilities: Some(ResourceCapabilities {
                cpu: Some(CpuResourceCapabilities {
                    limit_supported: true,
                }),
                memory: Some(MemoryResourceCapabilities {
                    limit_supported: true,
                }),
                gpu: Some(GpuResourceCapabilities {
                    default_selection_supported: self.config.gpu.cdi_supported,
                    count_selection_supported: self.config.gpu.cdi_supported,
                }),
            }),
            rootfs_tar_staging_dir: String::new(),
            rootfs_tar_max_bytes: 0,
        }
    }

    #[cfg(test)]
    fn validate_sandbox(
        sandbox: &DriverSandbox,
        config: &DockerDriverRuntimeConfig,
    ) -> Result<(), Status> {
        let _ = Self::validated_sandbox(sandbox, config)?;
        Ok(())
    }

    fn validated_sandbox<'a>(
        sandbox: &'a DriverSandbox,
        config: &DockerDriverRuntimeConfig,
    ) -> Result<ValidatedDockerSandbox<'a>, Status> {
        let spec = sandbox
            .spec
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("sandbox.spec is required"))?;
        let template = spec
            .template
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("sandbox.spec.template is required"))?;

        Self::validate_sandbox_template_base(template)?;
        let _ = docker_resource_limits(template)?;
        let driver_config =
            DockerSandboxDriverConfig::from_template(template).map_err(Status::invalid_argument)?;
        validate_docker_driver_mounts(&driver_config.mounts, config.enable_bind_mounts)?;
        let gpu_requirements = driver_gpu_requirements(spec.resource_requirements.as_ref());
        Self::validate_gpu_request(gpu_requirements, config.gpu.cdi_supported, &driver_config)?;
        Ok(ValidatedDockerSandbox {
            template,
            driver_config,
            gpu_requirements,
        })
    }

    fn validate_sandbox_template_base(template: &DriverSandboxTemplate) -> Result<(), Status> {
        if template.image.trim().is_empty() {
            return Err(Status::failed_precondition(
                "docker sandboxes require a template image",
            ));
        }
        if !template.agent_socket_path.trim().is_empty() {
            return Err(Status::failed_precondition(
                "docker compute driver does not support template.agent_socket_path",
            ));
        }
        if template
            .platform_config
            .as_ref()
            .is_some_and(|config| !config.fields.is_empty())
        {
            return Err(Status::failed_precondition(
                "docker compute driver does not support template.platform_config",
            ));
        }

        Ok(())
    }

    fn validate_sandbox_auth(sandbox: &DriverSandbox) -> Result<(), Status> {
        let token_present = sandbox
            .spec
            .as_ref()
            .is_some_and(|spec| !spec.sandbox_token.trim().is_empty());
        if token_present {
            return Ok(());
        }

        Err(Status::failed_precondition(
            "docker sandboxes require gateway JWT auth; configure [openshell.gateway.gateway_jwt]",
        ))
    }

    fn validate_gpu_request(
        gpu_requirements: Option<&GpuResourceRequirements>,
        supports_gpu: bool,
        driver_config: &DockerSandboxDriverConfig,
    ) -> Result<(), Status> {
        let requested_count =
            effective_driver_gpu_count(gpu_requirements).map_err(Status::invalid_argument)?;
        if requested_count.is_some() && !supports_gpu {
            return Err(Status::failed_precondition(
                "docker GPU sandboxes require Docker CDI support. Enable CDI on the Docker daemon, then restart the OpenShell gateway/server so GPU capability is detected.",
            ));
        }

        if let Some(cdi_devices) = driver_config.cdi_devices.as_deref() {
            validate_specific_gpu_device_request(
                gpu_requirements,
                cdi_devices,
                "driver_config.cdi_devices",
            )
            .map_err(Status::invalid_argument)?;
        }

        Ok(())
    }

    async fn validate_user_volume_mounts_available(
        &self,
        driver_config: &DockerSandboxDriverConfig,
    ) -> Result<(), Status> {
        for mount in &driver_config.mounts {
            if let DockerDriverMountConfig::Volume { source, .. } = mount {
                match self.docker.inspect_volume(source).await {
                    Ok(volume) => {
                        if !self.config.enable_bind_mounts && docker_volume_is_bind_backed(&volume)
                        {
                            return Err(Status::failed_precondition(format!(
                                "docker volume '{source}' is backed by a host bind mount and requires enable_bind_mounts = true in [openshell.drivers.docker]"
                            )));
                        }
                    }
                    Err(err) if is_not_found_error(&err) => {
                        return Err(Status::failed_precondition(format!(
                            "docker volume '{source}' does not exist"
                        )));
                    }
                    Err(err) => {
                        return Err(internal_status("inspect docker volume", err));
                    }
                }
            }
        }
        Ok(())
    }

    async fn refresh_gpu_inventory(&self) -> Result<(), Status> {
        let info = self
            .docker
            .info()
            .await
            .map_err(|err| internal_status("query Docker daemon info", err))?;
        self.gpu_selector.refresh(
            docker_cdi_gpu_inventory(&info),
            self.config.gpu.wsl_all_gpu_fallback_enabled,
        );
        Ok(())
    }

    async fn resolve_gpu_cdi_devices(
        &self,
        gpu_requirements: Option<&GpuResourceRequirements>,
        driver_config: &DockerSandboxDriverConfig,
        select_default_devices: fn(
            &CdiGpuDefaultSelector,
            u32,
        ) -> Result<Vec<String>, CdiGpuSelectionError>,
    ) -> Result<Option<Vec<String>>, Status> {
        if let Some(cdi_devices) = driver_config.cdi_devices.as_deref() {
            validate_specific_gpu_device_request(
                gpu_requirements,
                cdi_devices,
                "driver_config.cdi_devices",
            )
            .map_err(Status::invalid_argument)?;
            return Ok(Some(cdi_devices.to_vec()));
        }

        let Some(count) =
            effective_driver_gpu_count(gpu_requirements).map_err(Status::invalid_argument)?
        else {
            return Ok(None);
        };

        self.refresh_gpu_inventory().await?;
        select_default_devices(&self.gpu_selector, count)
            .map(Some)
            .map_err(docker_gpu_selection_status)
    }

    async fn get_sandbox_snapshot(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<Option<DriverSandbox>, Status> {
        let container = self
            .find_managed_container_summary(sandbox_id, sandbox_name)
            .await?;
        if let Some(sandbox) =
            container.and_then(|summary| sandbox_from_container_summary(&summary))
        {
            return Ok(Some(sandbox));
        }

        self.pending_snapshot(sandbox_id, sandbox_name).await
    }

    async fn current_snapshots(&self) -> Result<Vec<DriverSandbox>, Status> {
        let containers = self.list_managed_container_summaries().await?;
        let mut container_sandboxes = Vec::with_capacity(containers.len());
        for summary in &containers {
            let Some(mut sandbox) = sandbox_from_container_summary(summary) else {
                continue;
            };
            // Docker's list summary carries no exit code, so an exited
            // container is reported as the generic terminal `ContainerExited`.
            // Inspect it to tell a machine/daemon-restart signal kill apart
            // from an ordinary application exit, mirroring the Podman driver,
            // so startup recovery can revive restart victims while leaving
            // crashes terminal.
            if summary.state == Some(ContainerSummaryStateEnum::EXITED)
                && let Some(container_id) = summary.id.as_deref()
            {
                match self.docker.inspect_container(container_id, None).await {
                    Ok(inspected) => {
                        if let Some(state) = inspected.state.as_ref() {
                            apply_docker_exit_classification(&mut sandbox, state);
                        }
                    }
                    Err(err) => {
                        debug!(
                            container_id,
                            error = %err,
                            "Could not inspect exited Docker container to classify its exit"
                        );
                    }
                }
            }
            container_sandboxes.push(sandbox);
        }
        let mut by_id = self.pending_snapshot_map().await;
        for sandbox in container_sandboxes {
            by_id.insert(sandbox.id.clone(), sandbox);
        }
        let mut sandboxes = by_id.into_values().collect::<Vec<_>>();
        sandboxes.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(sandboxes)
    }

    async fn create_sandbox_inner(&self, sandbox: &DriverSandbox) -> Result<(), Status> {
        let validated = Self::validated_sandbox(sandbox, &self.config)?;
        Self::validate_sandbox_auth(sandbox)?;
        self.validate_user_volume_mounts_available(&validated.driver_config)
            .await?;
        let _ = self
            .resolve_gpu_cdi_devices(
                validated.gpu_requirements,
                &validated.driver_config,
                CdiGpuDefaultSelector::peek_device_ids,
            )
            .await?;

        if self
            .find_managed_container_summary(&sandbox.id, &sandbox.name)
            .await?
            .is_some()
        {
            return Err(Status::already_exists("sandbox already exists"));
        }

        self.reserve_pending_sandbox(sandbox).await?;
        let image = sandbox_image(sandbox).unwrap_or_default();
        self.publish_docker_progress(
            &sandbox.id,
            "Scheduled",
            format!("Docker sandbox accepted for image \"{image}\""),
            HashMap::from([("image_ref".to_string(), image.clone())]),
        );
        self.publish_sandbox_snapshot(pending_sandbox_snapshot(
            sandbox,
            &self.config.sandbox_label,
            provisioning_condition(),
            false,
        ));

        let driver = self.clone();
        let sandbox_for_task = sandbox.clone();
        let sandbox_id = sandbox.id.clone();
        let parent = tracing::Span::current().context();
        let provisioning_span = provisioning_span(&parent, sandbox, &image);
        let task = tokio::spawn(
            async move {
                driver.provision_sandbox(sandbox_for_task).await;
            }
            .instrument(provisioning_span),
        );

        let mut pending = self.pending.lock().await;
        if let Some(record) = pending.get_mut(&sandbox_id) {
            record.task = Some(task);
        } else {
            task.abort();
        }

        Ok(())
    }

    async fn provision_sandbox(&self, sandbox: DriverSandbox) {
        match self.provision_sandbox_inner(&sandbox).await {
            Ok(()) => {
                self.clear_pending_sandbox(&sandbox.id).await;
            }
            Err(failure) => {
                self.fail_pending_sandbox(&sandbox, &failure).await;
            }
        }
    }

    async fn provision_sandbox_inner(
        &self,
        sandbox: &DriverSandbox,
    ) -> Result<(), DockerProvisioningFailure> {
        let span_status = openshell_otel::ErrorStatusGuard::current();
        let validated = Self::validated_sandbox(sandbox, &self.config).map_err(|status| {
            DockerProvisioningFailure::new("ContainerCreateFailed", status.message())
        })?;
        let template = validated.template;
        let image = async {
            openshell_otel::record_error_result(
                self.ensure_image_available(&sandbox.id, &template.image)
                    .await
                    .map_err(|status| {
                        DockerProvisioningFailure::new("ImagePullFailed", status.message())
                    }),
            )
        }
        .instrument(tracing::info_span!(
            "docker.prepare_image",
            otel.name = "docker.prepare_image",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %sandbox.id,
            image.ref = %template.image,
        ))
        .await?;
        let token_file_created = write_sandbox_token_file(sandbox, &self.config)
            .await
            .map_err(|status| {
                DockerProvisioningFailure::new("SandboxTokenWriteFailed", status.message())
            })?;

        let container_name = container_name_for_sandbox(sandbox);
        let gpu_devices = self
            .resolve_gpu_cdi_devices(
                validated.gpu_requirements,
                &validated.driver_config,
                CdiGpuDefaultSelector::next_device_ids,
            )
            .await
            .map_err(|status| {
                if token_file_created {
                    cleanup_sandbox_token_file(sandbox, &self.config);
                }
                DockerProvisioningFailure::new("ContainerCreateFailed", status.message())
            })?;
        let create_body = build_container_create_body_for_image(
            sandbox,
            &self.config,
            &validated.driver_config,
            gpu_devices.as_deref(),
            &image,
        )
        .map_err(|status| {
            if token_file_created {
                cleanup_sandbox_token_file(sandbox, &self.config);
            }
            DockerProvisioningFailure::new("ContainerCreateFailed", status.message())
        })?;
        async {
            openshell_otel::record_error_result(
                self.docker
                    .create_container(
                        Some(
                            CreateContainerOptionsBuilder::default()
                                .name(container_name.as_str())
                                .build(),
                        ),
                        create_body,
                    )
                    .await
                    .map_err(|err| {
                        if token_file_created {
                            cleanup_sandbox_token_file(sandbox, &self.config);
                        }
                        DockerProvisioningFailure::from_status(
                            "ContainerCreateFailed",
                            create_status_from_docker_error("create docker sandbox container", err),
                        )
                    }),
            )
        }
        .instrument(tracing::info_span!(
            "docker.create_container",
            otel.name = "docker.create_container",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %sandbox.id,
            container.name = %container_name,
        ))
        .await?;
        self.publish_docker_progress(
            &sandbox.id,
            "Created",
            format!("Created Docker container \"{container_name}\""),
            HashMap::from([("container_name".to_string(), container_name.clone())]),
        );

        let start_result = async {
            openshell_otel::record_error_result(
                self.docker.start_container(&container_name, None).await,
            )
        }
        .instrument(tracing::info_span!(
            "docker.start_container",
            otel.name = "docker.start_container",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %sandbox.id,
            container.name = %container_name,
        ))
        .await;
        if let Err(err) = start_result {
            let cleanup = self
                .docker
                .remove_container(
                    &container_name,
                    Some(RemoveContainerOptionsBuilder::default().force(true).build()),
                )
                .await;
            if let Err(cleanup_err) = cleanup {
                warn!(
                    sandbox_id = %sandbox.id,
                    container_name,
                    error = %cleanup_err,
                    "Failed to clean up Docker container after start failure"
                );
            }
            if token_file_created {
                cleanup_sandbox_token_file(sandbox, &self.config);
            }
            return Err(DockerProvisioningFailure::from_status(
                "ContainerStartFailed",
                create_status_from_docker_error("start docker sandbox container", err),
            ));
        }
        self.publish_docker_progress(
            &sandbox.id,
            "Started",
            format!("Started Docker container \"{container_name}\""),
            HashMap::from([("container_name".to_string(), container_name)]),
        );
        if let Err(err) = self
            .publish_container_snapshot(&sandbox.id, &sandbox.name)
            .await
        {
            warn!(
                sandbox_id = %sandbox.id,
                error = %err,
                "Failed to publish Docker sandbox snapshot after start"
            );
        }

        span_status.finish(Ok(()))
    }

    async fn delete_sandbox_inner(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<bool, Status> {
        let pending = self
            .remove_pending_sandbox(sandbox_id, sandbox_name)
            .await?;
        if let Some(record) = pending.as_ref()
            && let Some(task) = record.task.as_ref()
        {
            task.abort();
        }

        let Some(container) = self
            .find_managed_container_summary(sandbox_id, sandbox_name)
            .await?
        else {
            if let Some(record) = pending {
                let container_name = container_name_for_sandbox(&record.sandbox);
                match self
                    .docker
                    .remove_container(
                        &container_name,
                        Some(RemoveContainerOptionsBuilder::default().force(true).build()),
                    )
                    .await
                {
                    Ok(()) => {
                        cleanup_sandbox_token_file(&record.sandbox, &self.config);
                        return Ok(true);
                    }
                    Err(err) if is_not_found_error(&err) => {
                        cleanup_sandbox_token_file(&record.sandbox, &self.config);
                        return Ok(true);
                    }
                    Err(err) => {
                        return Err(internal_status("delete docker sandbox container", err));
                    }
                }
            }
            // Container gone and no in-memory record survived (gateway
            // restarted after an out-of-band `docker rm`). DeleteSandbox is
            // the only thing that ever reclaims the token file, so reclaim it
            // here too.
            cleanup_sandbox_token_file_for_delete(sandbox_id, None, &self.config);
            return Ok(false);
        };
        let Some(target) = summary_container_target(&container) else {
            return Ok(pending.is_some());
        };

        match self
            .docker
            .remove_container(
                &target,
                Some(RemoveContainerOptionsBuilder::default().force(true).build()),
            )
            .await
        {
            Ok(()) => {
                cleanup_sandbox_token_file_for_delete(sandbox_id, pending.as_ref(), &self.config);
                Ok(true)
            }
            Err(err) if is_not_found_error(&err) => {
                cleanup_sandbox_token_file_for_delete(sandbox_id, pending.as_ref(), &self.config);
                Ok(pending.is_some())
            }
            Err(err) => Err(internal_status("delete docker sandbox container", err)),
        }
    }

    async fn stop_sandbox_inner(&self, sandbox_id: &str, sandbox_name: &str) -> Result<(), Status> {
        let Some(container) = self
            .find_managed_container_summary(sandbox_id, sandbox_name)
            .await?
        else {
            if let Some(record) = self
                .remove_pending_sandbox(sandbox_id, sandbox_name)
                .await?
            {
                if let Some(task) = record.task {
                    task.abort();
                }
                cleanup_sandbox_token_file(&record.sandbox, &self.config);
                self.publish_deleted(record.sandbox.id);
                return Ok(());
            }
            return Err(Status::not_found("sandbox not found"));
        };
        let Some(target) = summary_container_target(&container) else {
            return Err(Status::not_found("sandbox container has no id or name"));
        };

        match self
            .docker
            .stop_container(
                &target,
                Some(
                    StopContainerOptionsBuilder::default()
                        .t(docker_stop_timeout_secs(self.config.stop_timeout_secs))
                        .build(),
                ),
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(err) if is_not_modified_error(&err) => Ok(()),
            Err(err) if is_not_found_error(&err) => Err(Status::not_found("sandbox not found")),
            Err(err) => Err(internal_status("stop docker sandbox container", err)),
        }
    }

    /// Start a managed sandbox container that was previously stopped. Used
    /// by the gateway to start sandboxes after a restart so that running
    /// state in the gateway store is matched by an actually-running
    /// container.
    ///
    /// Returns `Ok(true)` when a container existed and was started (or was
    /// already running), `Ok(false)` when no managed container is found for
    /// the sandbox, and `Err(...)` for any Docker failure.
    #[tracing::instrument(
        name = "docker.start_sandbox",
        skip(self),
        fields(
            otel.name = "docker.start_sandbox",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %sandbox_id,
            sandbox.name = %sandbox_name,
        )
    )]
    pub async fn start_sandbox(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<bool, Status> {
        self.start_sandbox_with_snapshot(sandbox_id, sandbox_name, None)
            .await
    }

    /// Start a sandbox using optional durable gateway provisioning input.
    ///
    /// A supplied snapshot is only used to rebuild an explicitly stopped
    /// container whose gateway-owned startup generation changed. Existing
    /// callers without a snapshot retain the historical ID/name-only start
    /// semantics.
    async fn start_sandbox_with_snapshot(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
        sandbox: Option<&DriverSandbox>,
    ) -> Result<bool, Status> {
        let span_status = openshell_otel::ErrorStatusGuard::current();
        require_sandbox_identifier(sandbox_id, sandbox_name)?;
        if let Some(sandbox) = sandbox {
            validate_start_snapshot_request_identity(sandbox_id, sandbox_name, sandbox)?;
        }

        // A replacement keeps the old stopped container while a temporary
        // successor is created and populated. The gate spans the entire
        // transaction, including archive transfer and recovery, but is keyed
        // so a slow sandbox cannot serialize unrelated starts.
        let _start_operation_guard = self
            .start_operation_gates
            .lock_for(sandbox_id, sandbox_name)
            .await;
        self.lifecycle_event_fences.begin_start(sandbox_id);
        let result = self
            .start_sandbox_with_lifecycle_fence(sandbox_id, sandbox_name, sandbox)
            .await;
        self.lifecycle_event_fences.finish_start(sandbox_id);
        span_status.finish(result)
    }

    async fn start_sandbox_with_lifecycle_fence(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
        sandbox: Option<&DriverSandbox>,
    ) -> Result<bool, Status> {
        let Some(container) = self
            .find_managed_container_summary(sandbox_id, sandbox_name)
            .await?
        else {
            return Ok(false);
        };
        let Some(target) = summary_container_target(&container) else {
            return Ok(false);
        };

        let Some(sandbox) = sandbox else {
            return self
                .start_summary_container(sandbox_id, &target, &container)
                .await;
        };

        // The list response only locates a candidate. All decisions that can
        // start or replace a container use a fresh inspection to prove the
        // canonical name, ownership labels, state, and protected metadata.
        let source = self
            .inspect_durable_sandbox_source(&target, sandbox)
            .await?;
        if !matches!(
            source.state,
            ContainerStateStatusEnum::EXITED | ContainerStateStatusEnum::CREATED
        ) {
            // A live or otherwise non-startable sandbox is intentionally left
            // untouched, even if its gateway-owned trust generation changed.
            return Ok(true);
        }

        // A configured artifact is mounted directly into every Docker
        // sandbox. Reverify it before either a normal start or a replacement
        // so a changed host file cannot be consumed by a stopped container.
        validate_docker_network_trust_artifact(self.config.network_trust_bundle.as_ref())?;

        let desired_generation = docker_network_trust_generation(&self.config);
        if source.trust_generation.as_deref() == Some(desired_generation) {
            return self
                .start_container_after_fencing(sandbox_id, &target, source.finished_at.as_deref())
                .await;
        }

        // Docker's `created` state has never run and is not an explicit stop.
        // Do not replace it based on a stale/missing generation marker: only
        // an inspected Exited container may have its writable layer copied.
        if source.state != ContainerStateStatusEnum::EXITED {
            return Err(Status::failed_precondition(
                "Docker sandbox trust reconciliation requires an explicitly stopped container",
            ));
        }

        self.replace_stopped_sandbox_for_network_trust(sandbox_id, &target, sandbox, source)
            .await
    }

    async fn start_summary_container(
        &self,
        sandbox_id: &str,
        target: &str,
        container: &ContainerSummary,
    ) -> Result<bool, Status> {
        let state = container.state.unwrap_or(ContainerSummaryStateEnum::EMPTY);
        if !container_state_needs_start(state) {
            return Ok(true);
        }

        let previous_finished_at = if state == ContainerSummaryStateEnum::EXITED {
            let inspected = self
                .docker
                .inspect_container(target, None)
                .await
                .map_err(|err| internal_status("inspect docker sandbox before start", err))?;
            inspected
                .state
                .as_ref()
                .filter(|state| state.status == Some(ContainerStateStatusEnum::EXITED))
                .and_then(|state| state.finished_at.clone())
        } else {
            None
        };
        self.start_container_after_fencing(sandbox_id, target, previous_finished_at.as_deref())
            .await
    }

    async fn start_container_after_fencing(
        &self,
        sandbox_id: &str,
        target: &str,
        previous_finished_at: Option<&str>,
    ) -> Result<bool, Status> {
        // Fence a poll that observed this stopped run but has not published it
        // yet. A later genuine exit has a different transition timestamp.
        self.lifecycle_event_fences
            .record_previous_exit(sandbox_id, previous_finished_at);

        match self.docker.start_container(target, None).await {
            Ok(()) => Ok(true),
            // Already running — race with another start path or the restart
            // policy. Treat this ordinary idempotency result as success.
            Err(err) if is_not_modified_error(&err) => Ok(true),
            Err(err) if is_not_found_error(&err) => Ok(false),
            Err(err) => Err(internal_status("start docker sandbox container", err)),
        }
    }

    /// Inspect only immutable identity/state metadata from a candidate. The
    /// returned workspace root is derived exclusively from a driver-created
    /// label (or the historical `/sandbox` fallback), never Container.Config's
    /// mutable runtime command, working directory, or mounts.
    async fn inspect_durable_sandbox_source(
        &self,
        target: &str,
        sandbox: &DriverSandbox,
    ) -> Result<DockerSandboxInspection, Status> {
        let inspected = self
            .docker
            .inspect_container(target, None)
            .await
            .map_err(|_| {
                Status::internal(
                    "could not inspect Docker sandbox identity before trust reconciliation",
                )
            })?;
        docker_sandbox_inspection_from_container(&inspected, sandbox, &self.config.sandbox_label)
    }

    /// Replace an owned, explicitly stopped container whose immutable
    /// supervisor-start trust generation differs from the gateway's current
    /// startup snapshot. The replacement body is generated only from durable
    /// gateway input and current driver configuration; inspect data is never
    /// used as configuration.
    async fn replace_stopped_sandbox_for_network_trust(
        &self,
        sandbox_id: &str,
        old_target: &str,
        sandbox: &DriverSandbox,
        source: DockerSandboxInspection,
    ) -> Result<bool, Status> {
        let desired_generation = docker_network_trust_generation(&self.config).to_string();
        if source.state != ContainerStateStatusEnum::EXITED
            || source.trust_generation.as_deref() == Some(desired_generation.as_str())
        {
            return Err(Status::failed_precondition(
                "Docker sandbox changed before trust reconciliation could begin",
            ));
        }

        let validated = Self::validated_sandbox(sandbox, &self.config)?;
        // A public start snapshot deliberately omits the raw JWT. Reuse only
        // its deterministic driver-owned token file, without reading or
        // copying an old container's environment/mount configuration.
        validate_existing_sandbox_token_file(sandbox_id, &self.config)?;
        let nested_mounts = docker_workspace_nested_mount_destinations(
            &validated.driver_config,
            &source.workspace_root,
        )?;
        let archive_filter =
            DockerWorkspaceArchiveFilter::new(&source.workspace_root, nested_mounts)
                .map_err(DockerWorkspaceArchiveError::status)?;

        // Export and validate the entire old workspace before a Docker image
        // pull, replacement create, rename, remove, or start. Globally admit
        // one archive pipeline at a time, then filter the bounded raw daemon
        // stream directly into one anonymous private tempfile. Keep the
        // permit through upload so no second on-disk archive overlaps it.
        let workspace_archive_transfer = self
            .workspace_archive_transfers
            .acquire()
            .await
            .map_err(|_| Status::internal("Docker workspace archive admission is unavailable"))?;
        let workspace_archive = self
            .download_filtered_workspace_archive(old_target, &source.workspace_root, archive_filter)
            .await?;

        // All remaining launch preparation is still read-only with respect to
        // the old sandbox. A reinspection after the potentially long archive
        // transfer prevents a concurrently started/tampered source from ever
        // reaching a name mutation.
        let current_source = self
            .inspect_durable_sandbox_source(old_target, sandbox)
            .await?;
        validate_replacement_source_unchanged(&current_source, &source, &desired_generation)?;
        self.validate_user_volume_mounts_available(&validated.driver_config)
            .await?;
        let image = self
            .ensure_image_available(sandbox_id, &validated.template.image)
            .await?;
        let replacement_workspace_root = docker_workspace_root(&image)?;
        if replacement_workspace_root != source.workspace_root {
            return Err(Status::failed_precondition(
                "Docker replacement image workspace root differs from protected stopped sandbox metadata",
            ));
        }
        let gpu_devices = self
            .resolve_gpu_cdi_devices(
                validated.gpu_requirements,
                &validated.driver_config,
                CdiGpuDefaultSelector::next_device_ids,
            )
            .await?;
        let create_body = build_replacement_container_create_body_for_image(
            sandbox,
            &self.config,
            &validated.driver_config,
            gpu_devices.as_deref(),
            &image,
        )?;
        let canonical_name = container_name_for_sandbox(sandbox);
        let replacement_target = self
            .create_prepared_replacement(&canonical_name, create_body)
            .await?;

        let archive_bytes = workspace_archive.len();
        let restore = self
            .docker
            .upload_to_container(
                &replacement_target,
                Some(
                    UploadToContainerOptionsBuilder::default()
                        .path(workspace_archive_restore_parent(&source.workspace_root)?)
                        // Refuse a type-changing overwrite during daemon-side
                        // extraction of the filtered archive.
                        .no_overwrite_dir_non_dir("true")
                        // Preserve archive uid/gid headers rather than making
                        // them match the destination container root user.
                        .copy_uidgid("false")
                        .build(),
                ),
                body_try_stream(workspace_archive.into_upload_stream()),
            )
            .await;
        if restore.is_err() {
            self.remove_unstarted_replacement(&replacement_target).await;
            return Err(Status::internal(
                "could not restore filtered Docker sandbox workspace into replacement container",
            ));
        }
        drop(workspace_archive_transfer);
        debug!(
            sandbox_id,
            workspace_archive_bytes = archive_bytes,
            "prepared replacement Docker sandbox workspace archive"
        );

        // The source must remain the same explicitly stopped owned container
        // through restore. Inspection is identity/state-only; no old runtime
        // configuration is read or cloned.
        let current_source = self
            .inspect_durable_sandbox_source(old_target, sandbox)
            .await?;
        if let Err(error) =
            validate_replacement_source_unchanged(&current_source, &source, &desired_generation)
        {
            self.remove_unstarted_replacement(&replacement_target).await;
            return Err(error);
        }
        self.lifecycle_event_fences
            .record_previous_exit(sandbox_id, current_source.finished_at.as_deref());

        let result = self
            .swap_and_start_replacement(old_target, &canonical_name, &replacement_target)
            .await;
        if result.is_ok() {
            // The polling loop may already hold an exit snapshot for the old
            // ID. Retain that exact ID until the canonical successor snapshot
            // is published; the removed container can no longer be inspected
            // by timestamp to prove that its exit predates this start.
            self.lifecycle_event_fences
                .record_superseded_instance(sandbox_id, old_target);
        }
        result
    }

    /// Create an unstarted successor before touching the canonical source
    /// name. Random UUID components make a collision impractical; bounded
    /// retries still handle a stale failed operation without looping forever.
    async fn create_prepared_replacement(
        &self,
        canonical_name: &str,
        create_body: ContainerCreateBody,
    ) -> Result<String, Status> {
        for _ in 0..DOCKER_REPLACEMENT_NAME_ATTEMPTS {
            let replacement_name = temporary_replacement_container_name(canonical_name);
            match self
                .docker
                .create_container(
                    Some(
                        CreateContainerOptionsBuilder::default()
                            .name(&replacement_name)
                            .build(),
                    ),
                    create_body.clone(),
                )
                .await
            {
                Ok(replacement) if !replacement.id.is_empty() => {
                    return Ok(replacement.id);
                }
                Ok(_) => {
                    self.remove_unstarted_replacement(&replacement_name).await;
                    return Err(Status::internal(
                        "Docker did not return an ID for the replacement sandbox container",
                    ));
                }
                Err(error) if is_conflict_error(&error) => {}
                Err(_) => {
                    return Err(Status::internal(
                        "could not create unstarted Docker replacement sandbox container",
                    ));
                }
            }
        }
        Err(Status::failed_precondition(
            "could not reserve a temporary Docker replacement container name",
        ))
    }

    async fn download_filtered_workspace_archive(
        &self,
        target: &str,
        workspace_root: &str,
        filter: DockerWorkspaceArchiveFilter,
    ) -> Result<DockerWorkspaceArchive, Status> {
        let stream = self.docker.download_from_container(
            target,
            Some(
                DownloadFromContainerOptionsBuilder::default()
                    .path(workspace_root)
                    .build(),
            ),
        );
        download_and_filter_docker_workspace_archive(
            stream,
            filter,
            MAX_DOCKER_WORKSPACE_ARCHIVE_BYTES,
        )
        .await
        .map_err(DockerWorkspaceArchiveError::status)
    }

    async fn remove_unstarted_replacement(&self, target: &str) {
        match self
            .docker
            .remove_container(
                target,
                Some(
                    RemoveContainerOptionsBuilder::default()
                        .force(false)
                        .v(false)
                        .build(),
                ),
            )
            .await
        {
            Ok(())
            | Err(BollardError::DockerResponseServerError {
                status_code: 404, ..
            }) => {}
            Err(_) => warn!(
                replacement_container = target,
                "Failed to remove unstarted Docker replacement container"
            ),
        }
    }

    /// Inspect the IDs retained across a replacement operation. This is kept
    /// deliberately narrower than normal durable-source inspection: recovery
    /// needs only a name and state and must work after a name hand-off.
    async fn inspect_replacement_recovery_container(
        &self,
        target: &str,
    ) -> Result<Option<DockerReplacementRecoveryContainer>, Status> {
        match self.docker.inspect_container(target, None).await {
            Ok(container) => Ok(Some(DockerReplacementRecoveryContainer {
                name: container.name.unwrap_or_default(),
                state: container.state.and_then(|state| state.status),
            })),
            Err(error) if is_not_found_error(&error) => Ok(None),
            Err(_) => Err(Status::internal(
                "could not inspect Docker replacement recovery state",
            )),
        }
    }

    /// Compensate an uncertain rename or removal using stable IDs, never a
    /// guessed name. It only removes the known successor after proving it is
    /// stopped, always sends `force=false,v=false`, and verifies the result
    /// rather than trusting an ambiguous daemon/transport response.
    async fn rollback_replacement_swap(
        &self,
        old_target: &str,
        canonical_name: &str,
        replacement_target: &str,
    ) -> Result<ReplacementRecovery, Status> {
        let old = self
            .inspect_replacement_recovery_container(old_target)
            .await?;
        let replacement = self
            .inspect_replacement_recovery_container(replacement_target)
            .await?;

        let Some(old) = old else {
            let Some(replacement) = replacement else {
                return Err(Status::internal(
                    "could not recover Docker replacement: neither stable container ID remains",
                ));
            };
            // An ambiguous old-container removal is only recoverable by
            // starting the successor when its stable ID proves it received
            // the canonical name. Do not claim retryability for a temporary
            // successor that would leave no canonical sandbox to retry.
            if replacement.name.trim_start_matches('/') != canonical_name {
                return Err(Status::internal(
                    "could not recover Docker replacement: previous container disappeared without a canonical successor",
                ));
            }
            if !matches!(
                replacement.state,
                Some(ContainerStateStatusEnum::CREATED | ContainerStateStatusEnum::EXITED)
            ) {
                return Err(Status::failed_precondition(
                    "could not recover Docker replacement: canonical successor is not safely stopped",
                ));
            }
            return Ok(ReplacementRecovery::OldGone);
        };
        if old.state != Some(ContainerStateStatusEnum::EXITED) {
            return Err(Status::failed_precondition(
                "could not recover Docker replacement: previous container is no longer explicitly stopped",
            ));
        }

        if let Some(replacement) = replacement {
            if !matches!(
                replacement.state,
                Some(ContainerStateStatusEnum::CREATED | ContainerStateStatusEnum::EXITED)
            ) {
                return Err(Status::failed_precondition(
                    "could not recover Docker replacement: replacement container is not safely stopped",
                ));
            }
            // The create response ID is stable even if the replacement rename
            // was applied before its error reached us. Removing it by ID first
            // frees the canonical name without touching volumes.
            let _ = self
                .docker
                .remove_container(
                    replacement_target,
                    Some(
                        RemoveContainerOptionsBuilder::default()
                            .force(false)
                            .v(false)
                            .build(),
                    ),
                )
                .await;
            if self
                .inspect_replacement_recovery_container(replacement_target)
                .await?
                .is_some()
            {
                return Err(Status::internal(
                    "could not recover Docker replacement: stopped replacement remains after non-forced removal",
                ));
            }
        }

        if old.name.trim_start_matches('/') != canonical_name {
            let _ = self
                .docker
                .rename_container(
                    old_target,
                    RenameContainerOptionsBuilder::default()
                        .name(canonical_name)
                        .build(),
                )
                .await;
            let Some(old) = self
                .inspect_replacement_recovery_container(old_target)
                .await?
            else {
                return Err(Status::internal(
                    "could not recover Docker replacement: previous container disappeared while restoring its name",
                ));
            };
            if old.name.trim_start_matches('/') != canonical_name {
                return Err(Status::internal(
                    "could not recover Docker replacement: previous stopped container remains under a recovery name",
                ));
            }
        }

        Ok(ReplacementRecovery::OldRestored)
    }

    /// Atomically hand the canonical name from an old stopped source to its
    /// restored successor. The old container is removed with `v=false` before
    /// start, so a later start failure leaves the fully prepared replacement
    /// stopped under the ordinary canonical name for retry.
    async fn swap_and_start_replacement(
        &self,
        old_target: &str,
        canonical_name: &str,
        replacement_target: &str,
    ) -> Result<bool, Status> {
        let backup_name = temporary_replacement_backup_name(canonical_name);
        if self
            .docker
            .rename_container(
                old_target,
                RenameContainerOptionsBuilder::default()
                    .name(&backup_name)
                    .build(),
            )
            .await
            .is_err()
        {
            return Err(
                match self
                    .rollback_replacement_swap(old_target, canonical_name, replacement_target)
                    .await
                {
                    Ok(ReplacementRecovery::OldRestored) => Status::internal(
                        "could not rename stopped Docker sandbox before replacement; restored the original stopped sandbox",
                    ),
                    Ok(ReplacementRecovery::OldGone) => Status::internal(
                        "could not rename stopped Docker sandbox before replacement; previous container was already removed",
                    ),
                    Err(status) => status,
                },
            );
        }

        if self
            .docker
            .rename_container(
                replacement_target,
                RenameContainerOptionsBuilder::default()
                    .name(canonical_name)
                    .build(),
            )
            .await
            .is_err()
        {
            return Err(
                match self
                    .rollback_replacement_swap(old_target, canonical_name, replacement_target)
                    .await
                {
                    Ok(ReplacementRecovery::OldRestored) => Status::internal(
                        "could not rename prepared Docker replacement; restored the original stopped sandbox",
                    ),
                    Ok(ReplacementRecovery::OldGone) => Status::internal(
                        "could not rename prepared Docker replacement; previous container was already removed",
                    ),
                    Err(status) => status,
                },
            );
        }

        if self
            .docker
            .remove_container(
                old_target,
                Some(
                    RemoveContainerOptionsBuilder::default()
                        .force(false)
                        .v(false)
                        .build(),
                ),
            )
            .await
            .is_err()
        {
            // A transport error is not proof that Docker retained the old
            // stopped ID. Re-inspect both stable IDs before deciding whether
            // to start the canonical successor or compensate the swap.
            match self
                .rollback_replacement_swap(old_target, canonical_name, replacement_target)
                .await
            {
                Ok(ReplacementRecovery::OldGone) => {}
                Ok(ReplacementRecovery::OldRestored) => {
                    return Err(Status::internal(
                        "could not confirm removal of the previous stopped Docker sandbox; restored the original stopped sandbox",
                    ));
                }
                Err(status) => return Err(status),
            }
        }

        match self.docker.start_container(canonical_name, None).await {
            Ok(())
            | Err(BollardError::DockerResponseServerError {
                status_code: 304, ..
            }) => Ok(true),
            Err(_) => Err(Status::internal(
                "could not start the restored Docker replacement sandbox; the replacement remains stopped for retry",
            )),
        }
    }

    async fn reserve_pending_sandbox(&self, sandbox: &DriverSandbox) -> Result<(), Status> {
        let mut pending = self.pending.lock().await;
        if pending.values().any(|record| {
            record.sandbox.id == sandbox.id
                || (record.sandbox.name == sandbox.name
                    && record.sandbox.workspace == sandbox.workspace)
        }) {
            return Err(Status::already_exists("sandbox already exists"));
        }

        pending.insert(
            sandbox.id.clone(),
            PendingSandboxRecord {
                sandbox: pending_sandbox_snapshot(
                    sandbox,
                    &self.config.sandbox_label,
                    provisioning_condition(),
                    false,
                ),
                task: None,
            },
        );
        Ok(())
    }

    async fn pending_snapshot(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<Option<DriverSandbox>, Status> {
        let pending = self.pending.lock().await;
        let Some(id) = resolve_pending_id(&pending, sandbox_id, sandbox_name)? else {
            return Ok(None);
        };
        Ok(pending.get(&id).map(|record| record.sandbox.clone()))
    }

    async fn pending_snapshot_map(&self) -> HashMap<String, DriverSandbox> {
        let pending = self.pending.lock().await;
        pending
            .iter()
            .map(|(sandbox_id, record)| (sandbox_id.clone(), record.sandbox.clone()))
            .collect()
    }

    async fn clear_pending_sandbox(&self, sandbox_id: &str) {
        let mut pending = self.pending.lock().await;
        pending.remove(sandbox_id);
    }

    async fn remove_pending_sandbox(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<Option<PendingSandboxRecord>, Status> {
        let mut pending = self.pending.lock().await;
        let Some(id) = resolve_pending_id(&pending, sandbox_id, sandbox_name)? else {
            return Ok(None);
        };
        Ok(pending.remove(&id))
    }

    async fn fail_pending_sandbox(
        &self,
        sandbox: &DriverSandbox,
        failure: &DockerProvisioningFailure,
    ) {
        cleanup_sandbox_token_file(sandbox, &self.config);
        let snapshot = pending_sandbox_snapshot(
            sandbox,
            &self.config.sandbox_label,
            error_condition(failure.reason, &failure.message),
            false,
        );
        {
            let mut pending = self.pending.lock().await;
            if let Some(record) = pending.get_mut(&sandbox.id) {
                record.sandbox = snapshot.clone();
                record.task = None;
            } else {
                return;
            }
        }

        self.publish_platform_event(
            sandbox.id.clone(),
            platform_event(
                "docker",
                "Warning",
                failure.reason,
                format!("Docker sandbox provisioning failed: {}", failure.message),
            ),
        );
        self.publish_sandbox_snapshot(snapshot);
    }

    async fn publish_container_snapshot(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<(), Status> {
        if let Some(summary) = self
            .find_managed_container_summary(sandbox_id, sandbox_name)
            .await?
            && let Some(sandbox) = sandbox_from_container_summary(&summary)
        {
            if !driver_sandbox_reports_container_exit(&sandbox) {
                // The canonical successor is now observable, so a later poll
                // cannot legitimately rediscover a removed predecessor.
                self.lifecycle_event_fences
                    .clear_superseded_instances(sandbox_id);
            }
            self.publish_sandbox_snapshot(sandbox);
        }
        Ok(())
    }

    fn publish_sandbox_snapshot(&self, sandbox: DriverSandbox) {
        let _ = self.events.send(WatchSandboxesEvent {
            payload: Some(watch_sandboxes_event::Payload::Sandbox(
                WatchSandboxesSandboxEvent {
                    sandbox: Some(sandbox),
                },
            )),
        });
    }

    fn publish_deleted(&self, sandbox_id: String) {
        let _ = self.events.send(WatchSandboxesEvent {
            payload: Some(watch_sandboxes_event::Payload::Deleted(
                WatchSandboxesDeletedEvent { sandbox_id },
            )),
        });
    }

    fn publish_platform_event(&self, sandbox_id: String, event: DriverPlatformEvent) {
        let _ = self.events.send(WatchSandboxesEvent {
            payload: Some(watch_sandboxes_event::Payload::PlatformEvent(
                WatchSandboxesPlatformEvent {
                    sandbox_id,
                    event: Some(event),
                },
            )),
        });
    }

    fn publish_docker_progress(
        &self,
        sandbox_id: &str,
        reason: &str,
        message: String,
        mut metadata: HashMap<String, String>,
    ) {
        attach_docker_progress_metadata(&mut metadata, reason, &message);
        self.publish_platform_event(
            sandbox_id.to_string(),
            DriverPlatformEvent {
                timestamp_ms: openshell_core::time::now_ms(),
                source: "docker".to_string(),
                r#type: "Normal".to_string(),
                reason: reason.to_string(),
                message,
                metadata,
            },
        );
    }

    async fn poll_loop(self) {
        let mut previous = match self.current_snapshot_map().await {
            Ok(snapshots) => snapshots,
            Err(err) => {
                warn!(error = %err, "Failed to seed Docker sandbox watch state");
                HashMap::new()
            }
        };

        // Exponential backoff on consecutive Docker failures to avoid a 2s
        // warn-log flood when the daemon is unreachable for an extended
        // period (e.g. restart, socket removed).
        let mut backoff = WATCH_POLL_INTERVAL;
        loop {
            tokio::time::sleep(backoff).await;
            match self.current_snapshot_map().await {
                Ok(current) => {
                    self.publish_snapshot_diff(&previous, &current).await;
                    previous = current;
                    backoff = WATCH_POLL_INTERVAL;
                }
                Err(err) => {
                    warn!(
                        error = %err,
                        backoff_secs = backoff.as_secs(),
                        "Failed to poll Docker sandboxes"
                    );
                    backoff = (backoff * 2).min(WATCH_POLL_MAX_BACKOFF);
                }
            }
        }
    }

    async fn current_snapshot_map(&self) -> Result<HashMap<String, DriverSandbox>, Status> {
        self.current_snapshots().await.map(|snapshots| {
            snapshots
                .into_iter()
                .map(|sandbox| (sandbox.id.clone(), sandbox))
                .collect()
        })
    }

    async fn publish_snapshot_diff(
        &self,
        previous: &HashMap<String, DriverSandbox>,
        current: &HashMap<String, DriverSandbox>,
    ) {
        for (sandbox_id, sandbox) in current {
            if previous.get(sandbox_id) == Some(sandbox) {
                continue;
            }
            if self.stale_polled_exit(sandbox).await {
                continue;
            }
            self.publish_sandbox_snapshot(sandbox.clone());
        }

        for sandbox_id in previous.keys() {
            if current.contains_key(sandbox_id) {
                continue;
            }
            self.publish_deleted(sandbox_id.clone());
        }
    }

    async fn stale_polled_exit(&self, sandbox: &DriverSandbox) -> bool {
        if !driver_sandbox_reports_container_exit(sandbox) {
            return false;
        }
        if self.lifecycle_event_fences.start_in_progress(&sandbox.id) {
            debug!(
                sandbox_id = %sandbox.id,
                "Ignoring Docker container exit snapshot while sandbox start is in progress"
            );
            return true;
        }
        let Some(container_id) = sandbox
            .status
            .as_ref()
            .map(|status| status.instance_id.as_str())
            .filter(|container_id| !container_id.is_empty())
        else {
            return false;
        };
        if self
            .lifecycle_event_fences
            .is_superseded_instance(&sandbox.id, container_id)
        {
            debug!(
                sandbox_id = %sandbox.id,
                container_id,
                "Ignoring Docker container exit snapshot for a replaced instance"
            );
            return true;
        }
        let Some(previous_finished_at) = self.lifecycle_event_fences.previous_exit(&sandbox.id)
        else {
            return false;
        };

        let inspected = match self.docker.inspect_container(container_id, None).await {
            Ok(inspected) => inspected,
            Err(err) => {
                debug!(
                    sandbox_id = %sandbox.id,
                    container_id,
                    error = %err,
                    "Could not verify whether polled Docker exit predates sandbox start"
                );
                return false;
            }
        };
        if !docker_polled_exit_is_stale(&previous_finished_at, inspected.state.as_ref()) {
            return false;
        }

        debug!(
            sandbox_id = %sandbox.id,
            container_id,
            previous_finished_at,
            "Ignoring Docker container exit snapshot from before the latest sandbox start"
        );
        true
    }

    async fn list_managed_container_summaries(&self) -> Result<Vec<ContainerSummary>, Status> {
        let filters = managed_container_label_filters(&self.config.sandbox_label, []);
        self.docker
            .list_containers(Some(
                ListContainersOptionsBuilder::default()
                    .all(true)
                    .filters(&filters)
                    .build(),
            ))
            .await
            .map_err(|err| internal_status("list Docker sandbox containers", err))
    }

    async fn find_managed_container_summary(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<Option<ContainerSummary>, Status> {
        let mut label_filter_values = Vec::new();
        if !sandbox_id.is_empty() {
            label_filter_values.push(format!("{LABEL_SANDBOX_ID}={sandbox_id}"));
        } else if !sandbox_name.is_empty() {
            label_filter_values.push(format!("{LABEL_SANDBOX_NAME}={sandbox_name}"));
        }

        let filters =
            managed_container_label_filters(&self.config.sandbox_label, label_filter_values);
        let containers = self
            .docker
            .list_containers(Some(
                ListContainersOptionsBuilder::default()
                    .all(true)
                    .filters(&filters)
                    .build(),
            ))
            .await
            .map_err(|err| internal_status("find Docker sandbox container", err))?;

        Ok(containers.into_iter().find(|summary| {
            summary.labels.as_ref().is_some_and(|labels| {
                managed_container_identity_matches(
                    labels,
                    &self.config.sandbox_label,
                    sandbox_id,
                    sandbox_name,
                )
            })
        }))
    }

    async fn ensure_image_available(
        &self,
        sandbox_id: &str,
        image: &str,
    ) -> Result<DockerImageMetadata, Status> {
        let inspect = match self.config.image_pull_policy {
            ImagePullPolicy::IfNotPresent => {
                if let Ok(inspect) = self.docker.inspect_image(image).await {
                    self.publish_docker_progress(
                        sandbox_id,
                        "ImagePresent",
                        format!("Docker image \"{image}\" is already present"),
                        HashMap::from([("image_ref".to_string(), image.to_string())]),
                    );
                    inspect
                } else {
                    self.pull_image(sandbox_id, image).await?;
                    self.docker
                        .inspect_image(image)
                        .await
                        .map_err(|err| internal_status("inspect Docker image after pull", err))?
                }
            }
            ImagePullPolicy::Always => {
                self.pull_image(sandbox_id, image).await?;
                self.docker
                    .inspect_image(image)
                    .await
                    .map_err(|err| internal_status("inspect Docker image after pull", err))?
            }
            ImagePullPolicy::Never => match self.docker.inspect_image(image).await {
                Ok(inspect) => {
                    self.publish_docker_progress(
                        sandbox_id,
                        "ImagePresent",
                        format!("Docker image \"{image}\" is already present"),
                        HashMap::from([("image_ref".to_string(), image.to_string())]),
                    );
                    inspect
                }
                Err(err) if is_not_found_error(&err) => {
                    return Err(Status::failed_precondition(format!(
                        "docker image '{image}' is not present locally and image_pull_policy = \"never\""
                    )));
                }
                Err(err) => return Err(internal_status("inspect Docker image", err)),
            },
            ImagePullPolicy::Newer => {
                return Err(Status::failed_precondition(
                    "image_pull_policy = \"newer\" is supported only by the Podman compute driver",
                ));
            }
        };

        let id = inspect.id.ok_or_else(|| {
            Status::failed_precondition(format!(
                "docker image '{image}' inspection did not return an immutable image ID"
            ))
        })?;
        let (user, working_dir, volumes) = inspect.config.map_or_else(
            || (String::new(), String::new(), Vec::new()),
            |config| {
                (
                    config.user.unwrap_or_default(),
                    config.working_dir.unwrap_or_default(),
                    config.volumes.unwrap_or_default(),
                )
            },
        );
        Ok(DockerImageMetadata {
            id,
            user,
            working_dir,
            volumes,
        })
    }

    async fn pull_image(&self, sandbox_id: &str, image: &str) -> Result<(), Status> {
        self.publish_docker_progress(
            sandbox_id,
            "Pulling",
            format!("Pulling Docker image \"{image}\""),
            HashMap::from([("image_ref".to_string(), image.to_string())]),
        );
        let mut stream = self.docker.create_image(
            Some(CreateImageOptions {
                from_image: Some(image.to_string()),
                ..Default::default()
            }),
            None,
            None,
        );
        while let Some(result) = stream.next().await {
            let info = result.map_err(|err| internal_status("pull Docker image", err))?;
            if let Some(message) = info
                .error_detail
                .as_ref()
                .and_then(|detail| detail.message.as_ref())
            {
                return Err(Status::failed_precondition(format!(
                    "pull Docker image '{image}' failed: {message}"
                )));
            }
            if let Some(event) = docker_pull_progress_event(image, &info) {
                self.publish_platform_event(sandbox_id.to_string(), event);
            }
        }
        self.publish_docker_progress(
            sandbox_id,
            "Pulled",
            format!("Pulled Docker image \"{image}\""),
            HashMap::from([("image_ref".to_string(), image.to_string())]),
        );
        Ok(())
    }
}

// Standalone and in-process servers both use this wrapper. Delegating to the
// driver's canonical tonic implementation keeps request validation and Docker
// operation spans identical across both deployment modes.
#[tonic::async_trait]
impl ComputeDriver for ComputeDriverService {
    type WatchSandboxesStream = WatchStream;

    async fn authenticate_sandbox(
        &self,
        request: Request<openshell_core::proto::compute::v1::AuthenticateSandboxRequest>,
    ) -> Result<Response<openshell_core::proto::compute::v1::AuthenticateSandboxResponse>, Status>
    {
        self.rpc_tracer
            .trace(
                openshell_otel::rpc::AUTHENTICATE_SANDBOX,
                ComputeDriver::authenticate_sandbox(&self.driver, request),
            )
            .await
    }

    async fn get_capabilities(
        &self,
        request: Request<GetCapabilitiesRequest>,
    ) -> Result<Response<GetCapabilitiesResponse>, Status> {
        self.rpc_tracer
            .trace(
                openshell_otel::rpc::GET_CAPABILITIES,
                ComputeDriver::get_capabilities(&self.driver, request),
            )
            .await
    }

    async fn get_gateway_listener_requirements(
        &self,
        request: Request<GetGatewayListenerRequirementsRequest>,
    ) -> Result<Response<GetGatewayListenerRequirementsResponse>, Status> {
        self.rpc_tracer
            .trace(
                openshell_otel::rpc::GET_GATEWAY_LISTENER_REQUIREMENTS,
                ComputeDriver::get_gateway_listener_requirements(&self.driver, request),
            )
            .await
    }

    async fn validate_sandbox_create(
        &self,
        request: Request<ValidateSandboxCreateRequest>,
    ) -> Result<Response<ValidateSandboxCreateResponse>, Status> {
        self.rpc_tracer
            .trace(
                openshell_otel::rpc::VALIDATE_SANDBOX_CREATE,
                ComputeDriver::validate_sandbox_create(&self.driver, request),
            )
            .await
    }

    async fn get_sandbox(
        &self,
        request: Request<GetSandboxRequest>,
    ) -> Result<Response<GetSandboxResponse>, Status> {
        self.rpc_tracer
            .trace(
                openshell_otel::rpc::GET_SANDBOX,
                ComputeDriver::get_sandbox(&self.driver, request),
            )
            .await
    }

    async fn list_sandboxes(
        &self,
        request: Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        self.rpc_tracer
            .trace(
                openshell_otel::rpc::LIST_SANDBOXES,
                ComputeDriver::list_sandboxes(&self.driver, request),
            )
            .await
    }

    async fn create_sandbox(
        &self,
        request: Request<CreateSandboxRequest>,
    ) -> Result<Response<CreateSandboxResponse>, Status> {
        self.rpc_tracer
            .trace(
                openshell_otel::rpc::CREATE_SANDBOX,
                ComputeDriver::create_sandbox(&self.driver, request),
            )
            .await
    }

    async fn stop_sandbox(
        &self,
        request: Request<StopSandboxRequest>,
    ) -> Result<Response<StopSandboxResponse>, Status> {
        self.rpc_tracer
            .trace(
                openshell_otel::rpc::STOP_SANDBOX,
                ComputeDriver::stop_sandbox(&self.driver, request),
            )
            .await
    }

    async fn start_sandbox(
        &self,
        request: Request<StartSandboxRequest>,
    ) -> Result<Response<StartSandboxResponse>, Status> {
        self.rpc_tracer
            .trace(
                openshell_otel::rpc::START_SANDBOX,
                ComputeDriver::start_sandbox(&self.driver, request),
            )
            .await
    }

    async fn delete_sandbox(
        &self,
        request: Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        self.rpc_tracer
            .trace(
                openshell_otel::rpc::DELETE_SANDBOX,
                ComputeDriver::delete_sandbox(&self.driver, request),
            )
            .await
    }

    async fn watch_sandboxes(
        &self,
        request: Request<WatchSandboxesRequest>,
    ) -> Result<Response<Self::WatchSandboxesStream>, Status> {
        let create_stream = async {
            ComputeDriver::watch_sandboxes(&self.driver, request)
                .await
                .map(Response::into_inner)
        };
        self.rpc_tracer
            .trace_stream(openshell_otel::rpc::WATCH_SANDBOXES, create_stream)
            .await
            .map(Response::new)
    }

    async fn ensure_workspace(
        &self,
        request: Request<EnsureWorkspaceRequest>,
    ) -> Result<Response<EnsureWorkspaceResponse>, Status> {
        self.rpc_tracer
            .trace(
                openshell_otel::rpc::ENSURE_WORKSPACE,
                ComputeDriver::ensure_workspace(&self.driver, request),
            )
            .await
    }

    async fn delete_workspace(
        &self,
        request: Request<DeleteWorkspaceRequest>,
    ) -> Result<Response<DeleteWorkspaceResponse>, Status> {
        self.rpc_tracer
            .trace(
                openshell_otel::rpc::DELETE_WORKSPACE,
                ComputeDriver::delete_workspace(&self.driver, request),
            )
            .await
    }
}

#[tonic::async_trait]
impl ComputeDriver for DockerComputeDriver {
    async fn authenticate_sandbox(
        &self,
        _request: Request<openshell_core::proto::compute::v1::AuthenticateSandboxRequest>,
    ) -> Result<Response<openshell_core::proto::compute::v1::AuthenticateSandboxResponse>, Status>
    {
        Err(Status::unimplemented(
            "docker does not authenticate sandbox credentials",
        ))
    }

    type WatchSandboxesStream = WatchStream;

    async fn get_capabilities(
        &self,
        _request: Request<GetCapabilitiesRequest>,
    ) -> Result<Response<GetCapabilitiesResponse>, Status> {
        Ok(Response::new(self.capabilities()))
    }

    async fn get_gateway_listener_requirements(
        &self,
        _request: Request<GetGatewayListenerRequirementsRequest>,
    ) -> Result<Response<GetGatewayListenerRequirementsResponse>, Status> {
        let requirements =
            self.config
                .gateway_callback_bind_address
                .map_or_else(Vec::new, |bind_address| {
                    vec![GatewayListenerRequirement {
                        reason: match self.config.gateway_route {
                            DockerGatewayRoute::Bridge { .. } => "docker managed bridge gateway",
                            DockerGatewayRoute::HostGateway => "docker host-gateway IPv4 loopback",
                        }
                        .to_string(),
                        selector: Some(Selector::ExactBindAddress(bind_address.to_string())),
                    }]
                });
        Ok(Response::new(GetGatewayListenerRequirementsResponse {
            requirements,
        }))
    }

    async fn validate_sandbox_create(
        &self,
        request: Request<ValidateSandboxCreateRequest>,
    ) -> Result<Response<ValidateSandboxCreateResponse>, Status> {
        let sandbox = request
            .into_inner()
            .sandbox
            .ok_or_else(|| Status::invalid_argument("sandbox is required"))?;
        let validated = Self::validated_sandbox(&sandbox, &self.config)?;
        self.validate_user_volume_mounts_available(&validated.driver_config)
            .await?;
        let _ = self
            .resolve_gpu_cdi_devices(
                validated.gpu_requirements,
                &validated.driver_config,
                CdiGpuDefaultSelector::peek_device_ids,
            )
            .await?;
        Ok(Response::new(ValidateSandboxCreateResponse {}))
    }

    async fn get_sandbox(
        &self,
        request: Request<GetSandboxRequest>,
    ) -> Result<Response<GetSandboxResponse>, Status> {
        let request = request.into_inner();
        require_sandbox_identifier(&request.sandbox_id, &request.sandbox_name)?;

        let sandbox = self
            .get_sandbox_snapshot(&request.sandbox_id, &request.sandbox_name)
            .await?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;

        if !request.sandbox_id.is_empty() && request.sandbox_id != sandbox.id {
            return Err(Status::failed_precondition(
                "sandbox_id did not match the fetched sandbox",
            ));
        }

        Ok(Response::new(GetSandboxResponse {
            sandbox: Some(sandbox),
        }))
    }

    async fn list_sandboxes(
        &self,
        _request: Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        Ok(Response::new(ListSandboxesResponse {
            sandboxes: self.current_snapshots().await?,
        }))
    }

    #[tracing::instrument(
        name = "docker.schedule_sandbox",
        skip(self, request),
        fields(
            otel.name = "docker.schedule_sandbox",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %request.get_ref().sandbox.as_ref().map_or("", |sandbox| sandbox.id.as_str()),
            sandbox.name = %request.get_ref().sandbox.as_ref().map_or("", |sandbox| sandbox.name.as_str()),
        )
    )]
    async fn create_sandbox(
        &self,
        request: Request<CreateSandboxRequest>,
    ) -> Result<Response<CreateSandboxResponse>, Status> {
        let span_status = openshell_otel::ErrorStatusGuard::current();
        let sandbox = request
            .into_inner()
            .sandbox
            .ok_or_else(|| Status::invalid_argument("sandbox is required"))?;
        self.create_sandbox_inner(&sandbox).await?;
        span_status.finish(Ok(Response::new(CreateSandboxResponse {})))
    }

    #[tracing::instrument(
        name = "docker.stop_sandbox",
        skip(self, request),
        fields(
            otel.name = "docker.stop_sandbox",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %request.get_ref().sandbox_id,
            sandbox.name = %request.get_ref().sandbox_name,
        )
    )]
    async fn stop_sandbox(
        &self,
        request: Request<StopSandboxRequest>,
    ) -> Result<Response<StopSandboxResponse>, Status> {
        let span_status = openshell_otel::ErrorStatusGuard::current();
        let request = request.into_inner();
        require_sandbox_identifier(&request.sandbox_id, &request.sandbox_name)?;

        self.stop_sandbox_inner(&request.sandbox_id, &request.sandbox_name)
            .await?;
        self.publish_container_snapshot(&request.sandbox_id, &request.sandbox_name)
            .await?;
        span_status.finish(Ok(Response::new(StopSandboxResponse {})))
    }

    #[tracing::instrument(
        name = "docker.start_sandbox",
        skip(self, request),
        fields(
            otel.name = "docker.start_sandbox",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %request.get_ref().sandbox_id,
            sandbox.name = %request.get_ref().sandbox_name,
        )
    )]
    async fn start_sandbox(
        &self,
        request: Request<StartSandboxRequest>,
    ) -> Result<Response<StartSandboxResponse>, Status> {
        let span_status = openshell_otel::ErrorStatusGuard::current();
        let request = request.into_inner();
        if !Self::start_sandbox_with_snapshot(
            self,
            &request.sandbox_id,
            &request.sandbox_name,
            request.sandbox.as_ref(),
        )
        .await?
        {
            return span_status.finish(Err(Status::not_found("sandbox not found")));
        }
        self.publish_container_snapshot(&request.sandbox_id, &request.sandbox_name)
            .await?;
        span_status.finish(Ok(Response::new(StartSandboxResponse {})))
    }

    #[tracing::instrument(
        name = "docker.delete_sandbox",
        skip(self, request),
        fields(
            otel.name = "docker.delete_sandbox",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %request.get_ref().sandbox_id,
            sandbox.name = %request.get_ref().sandbox_name,
        )
    )]
    async fn delete_sandbox(
        &self,
        request: Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        let span_status = openshell_otel::ErrorStatusGuard::current();
        let request = request.into_inner();
        require_sandbox_identifier(&request.sandbox_id, &request.sandbox_name)?;

        let event_sandbox_id = request.sandbox_id.clone();
        let deleted = self
            .delete_sandbox_inner(&request.sandbox_id, &request.sandbox_name)
            .await?;
        self.lifecycle_event_fences.remove(&event_sandbox_id);
        if deleted && !event_sandbox_id.is_empty() {
            let _ = self.events.send(WatchSandboxesEvent {
                payload: Some(watch_sandboxes_event::Payload::Deleted(
                    WatchSandboxesDeletedEvent {
                        sandbox_id: event_sandbox_id,
                    },
                )),
            });
        }

        span_status.finish(Ok(Response::new(DeleteSandboxResponse { deleted })))
    }

    async fn watch_sandboxes(
        &self,
        _request: Request<WatchSandboxesRequest>,
    ) -> Result<Response<Self::WatchSandboxesStream>, Status> {
        // Subscribe before taking the initial snapshot so any event emitted
        // between the snapshot and this subscriber becoming active is still
        // delivered. Downstream consumers treat sandbox events as
        // idempotent (keyed by sandbox id), so a duplicate event is benign
        // while a missed one leaks state.
        let mut rx = self.events.subscribe();
        let initial = self.current_snapshots().await?;
        let (tx, out_rx) = mpsc::channel(WATCH_BUFFER);
        tokio::spawn(async move {
            for sandbox in initial {
                if tx
                    .send(Ok(WatchSandboxesEvent {
                        payload: Some(watch_sandboxes_event::Payload::Sandbox(
                            WatchSandboxesSandboxEvent {
                                sandbox: Some(sandbox),
                            },
                        )),
                    }))
                    .await
                    .is_err()
                {
                    return;
                }
            }

            loop {
                match rx.recv().await {
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

        Ok(Response::new(Box::pin(ReceiverStream::new(out_rx))))
    }

    async fn ensure_workspace(
        &self,
        _request: Request<EnsureWorkspaceRequest>,
    ) -> Result<Response<EnsureWorkspaceResponse>, Status> {
        Ok(Response::new(EnsureWorkspaceResponse {}))
    }

    async fn delete_workspace(
        &self,
        _request: Request<DeleteWorkspaceRequest>,
    ) -> Result<Response<DeleteWorkspaceResponse>, Status> {
        Ok(Response::new(DeleteWorkspaceResponse {}))
    }
}

impl DockerProvisioningFailure {
    fn new(reason: &'static str, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }

    fn from_status(reason: &'static str, status: Status) -> Self {
        Self::new(reason, status.message())
    }
}

fn sandbox_image(sandbox: &DriverSandbox) -> Option<String> {
    sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
        .map(|template| template.image.clone())
        .filter(|image| !image.trim().is_empty())
}

fn pending_sandbox_snapshot(
    sandbox: &DriverSandbox,
    namespace: &str,
    condition: DriverCondition,
    deleting: bool,
) -> DriverSandbox {
    DriverSandbox {
        id: sandbox.id.clone(),
        name: sandbox.name.clone(),
        namespace: namespace.to_string(),
        spec: None,
        status: Some(DriverSandboxStatus {
            sandbox_name: sandbox.name.clone(),
            instance_id: String::new(),
            agent_fd: String::new(),
            sandbox_fd: String::new(),
            conditions: vec![condition],
            deleting,
        }),
        workspace: sandbox.workspace.clone(),
    }
}

/// Decides whether a managed container satisfies a lifecycle request.
///
/// `sandbox_id` is authoritative, matching [`resolve_pending_id`]. Requiring
/// the name to agree as well would discard a correct id match whenever the
/// caller pairs it with a stale name, leaving the container and its token file
/// behind while the driver reports the sandbox as absent.
///
/// A request with no identifier matches nothing. `require_sandbox_identifier`
/// rejects that upstream, but the label filters degenerate to "every managed
/// container in the namespace", so this does not rely on the caller to guard it.
fn managed_container_identity_matches(
    labels: &HashMap<String, String>,
    namespace: &str,
    sandbox_id: &str,
    sandbox_name: &str,
) -> bool {
    if labels
        .get(LABEL_SANDBOX_NAMESPACE)
        .is_none_or(|value| value != namespace)
    {
        return false;
    }
    if !sandbox_id.is_empty() {
        return labels
            .get(LABEL_SANDBOX_ID)
            .is_some_and(|value| value == sandbox_id);
    }
    !sandbox_name.is_empty()
        && labels
            .get(LABEL_SANDBOX_NAME)
            .is_some_and(|value| value == sandbox_name)
}

/// Resolves a lifecycle request to at most one pending sandbox id.
///
/// `sandbox_id` is authoritative: when the caller supplies one, the name is
/// never consulted as an alternative. The name fallback rejects ambiguity
/// instead of letting `HashMap` iteration order pick a match, because sandbox
/// names are unique per workspace and the driver request carries no workspace.
fn resolve_pending_id(
    pending: &HashMap<String, PendingSandboxRecord>,
    sandbox_id: &str,
    sandbox_name: &str,
) -> Result<Option<String>, Status> {
    if !sandbox_id.is_empty() {
        return Ok(pending
            .contains_key(sandbox_id)
            .then(|| sandbox_id.to_string()));
    }
    if sandbox_name.is_empty() {
        return Ok(None);
    }

    let mut matches = pending
        .iter()
        .filter(|(_, record)| record.sandbox.name == sandbox_name)
        .map(|(id, _)| id.clone());

    let Some(id) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err(Status::failed_precondition(
            "sandbox_name matches multiple pending sandboxes; specify sandbox_id",
        ));
    }
    Ok(Some(id))
}

fn provisioning_condition() -> DriverCondition {
    DriverCondition {
        r#type: "Ready".to_string(),
        status: "False".to_string(),
        reason: "Starting".to_string(),
        message: "Docker container is starting".to_string(),
        last_transition_time: String::new(),
    }
}

fn error_condition(reason: &str, message: &str) -> DriverCondition {
    DriverCondition {
        r#type: "Ready".to_string(),
        status: "False".to_string(),
        reason: reason.to_string(),
        message: message.to_string(),
        last_transition_time: String::new(),
    }
}

fn platform_event(
    source: &str,
    event_type: &str,
    reason: &str,
    message: String,
) -> DriverPlatformEvent {
    DriverPlatformEvent {
        timestamp_ms: openshell_core::time::now_ms(),
        source: source.to_string(),
        r#type: event_type.to_string(),
        reason: reason.to_string(),
        message,
        metadata: HashMap::new(),
    }
}

fn docker_pull_progress_event(image: &str, info: &CreateImageInfo) -> Option<DriverPlatformEvent> {
    let status = info.status.as_deref().map(str::trim)?;
    if status.is_empty() {
        return None;
    }

    let mut metadata = HashMap::from([
        ("image_ref".to_string(), image.to_string()),
        ("docker_status".to_string(), status.to_string()),
    ]);
    if let Some(layer_id) = info.id.as_deref().filter(|id| !id.is_empty()) {
        metadata.insert("layer_id".to_string(), layer_id.to_string());
    }
    if let Some(detail) = docker_pull_progress_detail(info) {
        metadata.insert("detail".to_string(), detail);
    }
    attach_docker_progress_metadata(&mut metadata, "PullingLayer", status);

    Some(DriverPlatformEvent {
        timestamp_ms: openshell_core::time::now_ms(),
        source: "docker".to_string(),
        r#type: "Normal".to_string(),
        reason: "PullingLayer".to_string(),
        message: docker_pull_message(info, status),
        metadata,
    })
}

fn docker_pull_message(info: &CreateImageInfo, status: &str) -> String {
    info.id.as_deref().filter(|id| !id.is_empty()).map_or_else(
        || format!("Docker image pull: {status}"),
        |layer_id| format!("Docker image pull {layer_id}: {status}"),
    )
}

fn docker_pull_progress_detail(info: &CreateImageInfo) -> Option<String> {
    let status = info.status.as_deref().unwrap_or("Pulling");
    let layer_id = info.id.as_deref().filter(|id| !id.is_empty());
    let progress = info
        .progress_detail
        .as_ref()
        .and_then(format_progress_detail);

    match (layer_id, progress) {
        (Some(layer_id), Some(progress)) => Some(format!("{status} {layer_id} ({progress})")),
        (Some(layer_id), None) => Some(format!("{status} {layer_id}")),
        (None, Some(progress)) => Some(format!("{status} ({progress})")),
        (None, None) => (!status.is_empty()).then(|| status.to_string()),
    }
}

fn format_progress_detail(progress: &ProgressDetail) -> Option<String> {
    let current = progress.current.and_then(|value| u64::try_from(value).ok());
    let total = progress
        .total
        .and_then(|value| u64::try_from(value).ok())
        .filter(|value| *value > 0);

    match (current, total) {
        (Some(current), Some(total)) => {
            Some(format!("{}/{}", format_bytes(current), format_bytes(total)))
        }
        (Some(current), _) if current > 0 => Some(format_bytes(current)),
        _ => None,
    }
}

fn attach_docker_progress_metadata(
    metadata: &mut HashMap<String, String>,
    reason: &str,
    message: &str,
) {
    match reason {
        "Scheduled" => {
            mark_progress_complete(
                metadata,
                PROGRESS_STEP_REQUESTING_SANDBOX,
                "Sandbox allocated",
            );
            mark_progress_active(metadata, PROGRESS_STEP_PULLING_IMAGE);
            if let Some(image) = metadata.get("image_ref").cloned() {
                mark_progress_detail(metadata, image);
            }
        }
        "Pulling" => {
            mark_progress_active(metadata, PROGRESS_STEP_PULLING_IMAGE);
            if let Some(image) = metadata.get("image_ref").cloned() {
                mark_progress_detail(metadata, image);
            }
        }
        "PullingLayer" => {
            mark_progress_active(metadata, PROGRESS_STEP_PULLING_IMAGE);
            if let Some(detail) = metadata
                .get("detail")
                .cloned()
                .filter(|detail| !detail.is_empty())
            {
                mark_progress_detail(metadata, detail);
            } else if !message.is_empty() {
                mark_progress_detail(metadata, message);
            }
        }
        "ImagePresent" => {
            mark_progress_complete(
                metadata,
                PROGRESS_STEP_PULLING_IMAGE,
                "Image already present",
            );
            mark_progress_active(metadata, PROGRESS_STEP_STARTING_SANDBOX);
        }
        "Pulled" => {
            mark_progress_complete(metadata, PROGRESS_STEP_PULLING_IMAGE, "Image pulled");
            mark_progress_active(metadata, PROGRESS_STEP_STARTING_SANDBOX);
        }
        "Created" => {
            mark_progress_active(metadata, PROGRESS_STEP_STARTING_SANDBOX);
            mark_progress_detail(metadata, "Container created");
        }
        "Started" => {
            mark_progress_active(metadata, PROGRESS_STEP_STARTING_SANDBOX);
            mark_progress_detail(metadata, "Waiting for supervisor relay");
        }
        _ => {}
    }
}

#[cfg(test)]
fn docker_driver_config(
    template: &DriverSandboxTemplate,
    enable_bind_mounts: bool,
) -> Result<DockerSandboxDriverConfig, Status> {
    let config =
        DockerSandboxDriverConfig::from_template(template).map_err(Status::invalid_argument)?;
    validate_docker_driver_mounts(&config.mounts, enable_bind_mounts)?;
    Ok(config)
}

/// Collect user-supplied bind mounts as string-format binds.
///
/// Bind mounts use the legacy `Binds` field (`-v` syntax) rather than the
/// structured `Mount` API because the Docker Engine Mount object does not
/// support `SELinux` relabelling (`:z` / `:Z`).  The string format does.
fn docker_driver_bind_strings(config: &DockerSandboxDriverConfig) -> Result<Vec<String>, Status> {
    config
        .mounts
        .iter()
        .filter_map(|m| match m {
            DockerDriverMountConfig::Bind {
                source,
                target,
                read_only,
                selinux_label,
            } => Some(docker_bind_string(
                source,
                target,
                *read_only,
                *selinux_label,
            )),
            _ => None,
        })
        .collect()
}

fn docker_bind_string(
    source: &str,
    target: &str,
    read_only: bool,
    selinux_label: Option<SelinuxLabel>,
) -> Result<String, Status> {
    driver_mounts::validate_absolute_mount_source(source, "bind source")
        .map_err(Status::failed_precondition)?;
    // Legacy `-v` binds silently create missing source directories as empty,
    // root-owned paths.  The structured `--mount` API that was used before this
    // change rejected missing sources at container-create time.  Preserve that
    // fail-fast behaviour with an explicit existence check.
    if !Path::new(source).exists() {
        return Err(Status::failed_precondition(format!(
            "bind source path does not exist: {source}"
        )));
    }
    driver_mounts::validate_container_mount_target(target).map_err(Status::failed_precondition)?;
    let normalized_target = driver_mounts::normalize_mount_target(target);

    let mut opts = Vec::new();
    if read_only {
        opts.push("ro");
    }
    match selinux_label {
        Some(SelinuxLabel::Shared) => opts.push("z"),
        Some(SelinuxLabel::Private) => opts.push("Z"),
        None => {}
    }

    if opts.is_empty() {
        Ok(format!("{source}:{normalized_target}"))
    } else {
        Ok(format!("{source}:{normalized_target}:{}", opts.join(",")))
    }
}

/// Collect user-supplied non-bind mounts as structured `Mount` objects.
fn docker_driver_mounts(config: &DockerSandboxDriverConfig) -> Result<Vec<Mount>, Status> {
    config
        .mounts
        .iter()
        .filter_map(|m| docker_mount_from_config(m).transpose())
        .collect()
}

fn docker_mount_from_config(config: &DockerDriverMountConfig) -> Result<Option<Mount>, Status> {
    match config {
        DockerDriverMountConfig::Bind { .. } => {
            // Bind mounts are handled via docker_driver_bind_strings.
            Ok(None)
        }
        DockerDriverMountConfig::Volume {
            source,
            target,
            read_only,
            subpath,
        } => Ok(Some(Mount {
            typ: Some(MountTypeEnum::VOLUME),
            source: Some(source.clone()),
            target: Some(target.clone()),
            read_only: Some(*read_only),
            volume_options: subpath.as_ref().map(|subpath| MountVolumeOptions {
                subpath: Some(subpath.clone()),
                ..Default::default()
            }),
            ..Default::default()
        })),
        DockerDriverMountConfig::Tmpfs {
            target,
            options,
            size_bytes,
            mode,
        } => Ok(Some(Mount {
            typ: Some(MountTypeEnum::TMPFS),
            target: Some(target.clone()),
            tmpfs_options: Some(MountTmpfsOptions {
                size_bytes: validate_optional_positive_integral_i64(
                    *size_bytes,
                    "tmpfs size_bytes",
                )?,
                mode: validate_optional_nonnegative_integral_i64(*mode, "tmpfs mode")?,
                options: (!options.is_empty())
                    .then(|| {
                        options
                            .iter()
                            .map(|option| docker_tmpfs_option(option))
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .transpose()?,
            }),
            ..Default::default()
        })),
        DockerDriverMountConfig::Image { .. } => Err(Status::failed_precondition(
            "invalid docker driver_config: docker image mounts are not supported",
        )),
    }
}

fn validate_docker_driver_mounts(
    mounts: &[DockerDriverMountConfig],
    enable_bind_mounts: bool,
) -> Result<(), Status> {
    let mut targets = HashSet::new();
    for mount in mounts {
        let target = match mount {
            DockerDriverMountConfig::Bind { source, target, .. } => {
                if !enable_bind_mounts {
                    return Err(Status::failed_precondition(
                        "docker bind mounts require enable_bind_mounts = true in [openshell.drivers.docker]",
                    ));
                }
                driver_mounts::validate_absolute_mount_source(source, "bind source")
                    .map_err(Status::failed_precondition)?;
                target
            }
            DockerDriverMountConfig::Volume {
                source,
                target,
                subpath,
                ..
            } => {
                driver_mounts::validate_mount_source(source, "volume source")
                    .map_err(Status::failed_precondition)?;
                if let Some(subpath) = subpath {
                    driver_mounts::validate_mount_subpath(subpath)
                        .map_err(Status::failed_precondition)?;
                }
                target
            }
            DockerDriverMountConfig::Tmpfs {
                target,
                options,
                size_bytes,
                mode,
            } => {
                validate_optional_positive_integral_i64(*size_bytes, "tmpfs size_bytes")?;
                validate_optional_nonnegative_integral_i64(*mode, "tmpfs mode")?;
                for option in options {
                    docker_tmpfs_option(option)?;
                }
                target
            }
            DockerDriverMountConfig::Image {
                source,
                target,
                read_only,
                subpath,
            } => {
                let _ = (source, target, read_only, subpath);
                return Err(Status::failed_precondition(
                    "invalid docker driver_config: docker image mounts are not supported",
                ));
            }
        };
        driver_mounts::validate_container_mount_target(target)
            .map_err(Status::failed_precondition)?;
        let normalized_target = driver_mounts::normalize_mount_target(target);
        if !targets.insert(normalized_target.clone()) {
            return Err(Status::failed_precondition(format!(
                "duplicate docker driver_config mount target '{normalized_target}'"
            )));
        }
    }
    Ok(())
}

fn validate_optional_positive_integral_i64(
    value: Option<f64>,
    field: &str,
) -> Result<Option<i64>, Status> {
    let Some(value) = validate_optional_integral_i64(value, field)? else {
        return Ok(None);
    };
    if value <= 0 {
        return Err(Status::failed_precondition(format!(
            "{field} must be positive"
        )));
    }
    Ok(Some(value))
}

fn validate_optional_nonnegative_integral_i64(
    value: Option<f64>,
    field: &str,
) -> Result<Option<i64>, Status> {
    let Some(value) = validate_optional_integral_i64(value, field)? else {
        return Ok(None);
    };
    if value < 0 {
        return Err(Status::failed_precondition(format!(
            "{field} must be zero or greater"
        )));
    }
    Ok(Some(value))
}

fn validate_optional_integral_i64(value: Option<f64>, field: &str) -> Result<Option<i64>, Status> {
    let Some(value) = value else {
        return Ok(None);
    };
    if !value.is_finite() || value.fract() != 0.0 {
        return Err(Status::failed_precondition(format!(
            "{field} must be an integer"
        )));
    }
    value.to_string().parse::<i64>().map(Some).map_err(|_| {
        Status::failed_precondition(format!("{field} must be representable as an i64"))
    })
}

fn docker_tmpfs_option(option: &str) -> Result<Vec<String>, Status> {
    let option = option.trim();
    if option.is_empty() {
        return Err(Status::failed_precondition(
            "tmpfs options must not contain empty values",
        ));
    }
    if let Some((key, value)) = option.split_once('=') {
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() || value.is_empty() {
            return Err(Status::failed_precondition(
                "tmpfs key=value options must include both key and value",
            ));
        }
        Ok(vec![key.to_string(), value.to_string()])
    } else {
        Ok(vec![option.to_string()])
    }
}

fn docker_volume_is_bind_backed(volume: &bollard::models::Volume) -> bool {
    volume.driver == "local"
        && volume.options.get("o").is_some_and(|options| {
            options.split(',').any(|option| {
                let option = option.trim();
                option.eq_ignore_ascii_case("bind") || option.eq_ignore_ascii_case("rbind")
            })
        })
}

/// Verify the configured credential without exposing its contents. Docker
/// bind-mounts the root-owned file directly, unlike Podman which uses a native
/// secret object; this preflight makes a bad file fail before any sandbox is
/// created.
fn validate_docker_proxy_auth_file(config: &UpstreamProxyConfig) -> CoreResult<()> {
    let Some(path) = config.proxy_auth_file.as_ref() else {
        return Ok(());
    };
    let raw = openshell_core::driver_utils::read_upstream_proxy_credential_file(
        path.to_str()
            .ok_or_else(|| Error::config("proxy_auth_file must be valid UTF-8"))?,
    )
    .map_err(Error::config)?;
    openshell_core::driver_utils::parse_upstream_proxy_credential(&raw)
        .map_err(|error| Error::config(format!("proxy_auth_file is invalid: {error}")))?;
    Ok(())
}

/// Build immutable operator-owned proxy arguments. Credentials never appear on
/// argv: only the fixed in-container root-only file path is supplied.
fn docker_upstream_proxy_cli_args(config: &UpstreamProxyConfig) -> Vec<String> {
    let mut args = Vec::new();
    if let Some(url) = config.https_proxy.as_ref() {
        args.extend(["--upstream-proxy".to_string(), url.clone()]);
    }
    if let Some(no_proxy) = config.no_proxy.as_ref() {
        args.extend(["--upstream-no-proxy".to_string(), no_proxy.clone()]);
    }
    if config.proxy_auth_file.is_some() {
        args.extend([
            "--upstream-proxy-auth-file".to_string(),
            UPSTREAM_PROXY_AUTH_MOUNT_PATH.to_string(),
        ]);
    }
    if config.proxy_auth_allow_insecure == Some(true) {
        args.push("--upstream-proxy-auth-allow-insecure".to_string());
    }
    if config.proxy_connect_by_hostname == Some(true) {
        args.push("--upstream-proxy-connect-by-hostname".to_string());
    }
    args
}

fn docker_network_trust_cli_args(
    network_trust_bundle: Option<&NetworkSupervisorTrustBundle>,
) -> Vec<String> {
    network_trust_bundle.map_or_else(Vec::new, |bundle| {
        vec![
            "--network-additional-ca-bundle".to_string(),
            NETWORK_ADDITIONAL_CA_BUNDLE_PATH.to_string(),
            "--network-additional-ca-digest".to_string(),
            bundle.digest().to_string(),
        ]
    })
}

fn docker_network_trust_generation(config: &DockerDriverRuntimeConfig) -> &str {
    config.network_trust_bundle.as_ref().map_or(
        NETWORK_SUPERVISOR_TRUST_GENERATION_NONE,
        NetworkSupervisorTrustBundle::digest,
    )
}

/// Revalidate the immutable gateway startup snapshot immediately before a
/// container is built. The verifier deliberately emits only its path/digest,
/// never certificate bytes.
fn validate_docker_network_trust_artifact(
    network_trust_bundle: Option<&NetworkSupervisorTrustBundle>,
) -> Result<(), Status> {
    let Some(bundle) = network_trust_bundle else {
        return Ok(());
    };
    bundle.verify_artifact().map_err(|error| {
        Status::failed_precondition(format!(
            "gateway-owned network additional CA artifact failed validation: {error}"
        ))
    })
}

fn docker_network_trust_bind(bundle: &NetworkSupervisorTrustBundle) -> Result<String, Status> {
    validate_docker_network_trust_artifact(Some(bundle))?;
    let path = bundle.artifact_path();
    let source = path.to_str().ok_or_else(|| {
        Status::failed_precondition(format!(
            "network additional CA artifact path is not valid UTF-8: {}",
            path.display()
        ))
    })?;
    driver_mounts::validate_absolute_mount_source(source, "network additional CA artifact")
        .map_err(Status::failed_precondition)?;
    Ok(format!(
        "{}:{NETWORK_ADDITIONAL_CA_BUNDLE_PATH}:ro,z",
        path.display()
    ))
}

fn sandbox_has_request_token(sandbox: &DriverSandbox) -> bool {
    sandbox
        .spec
        .as_ref()
        .is_some_and(|spec| !spec.sandbox_token.is_empty())
}

#[cfg(test)]
fn build_binds(
    sandbox: &DriverSandbox,
    config: &DockerDriverRuntimeConfig,
) -> Result<Vec<String>, Status> {
    build_binds_with_sandbox_token_file(sandbox, config, sandbox_has_request_token(sandbox))
}

/// Build driver-owned bind mounts. `include_sandbox_token_file` is true for a
/// stopped-container replacement because the gateway deliberately removes the
/// bearer token from the durable public snapshot; the existing driver-owned
/// token file is reused without reading or exposing its contents.
fn build_binds_with_sandbox_token_file(
    sandbox: &DriverSandbox,
    config: &DockerDriverRuntimeConfig,
    include_sandbox_token_file: bool,
) -> Result<Vec<String>, Status> {
    let mut binds = vec![format!(
        "{}:{}:ro,z",
        config.supervisor_bin.display(),
        SUPERVISOR_MOUNT_PATH
    )];
    if let Some(network_trust_bundle) = config.network_trust_bundle.as_ref() {
        binds.push(docker_network_trust_bind(network_trust_bundle)?);
    }
    if let Some(tls) = &config.guest_tls {
        binds.push(format!("{}:{}:ro,z", tls.ca.display(), TLS_CA_MOUNT_PATH));
        binds.push(format!(
            "{}:{}:ro,z",
            tls.cert.display(),
            TLS_CERT_MOUNT_PATH
        ));
        binds.push(format!("{}:{}:ro,z", tls.key.display(), TLS_KEY_MOUNT_PATH));
    }
    if include_sandbox_token_file {
        binds.push(format!(
            "{}:{}:ro,z",
            sandbox_token_host_path(sandbox, config)?.display(),
            SANDBOX_TOKEN_MOUNT_PATH
        ));
    }
    if let Some(path) = config.upstream_proxy.proxy_auth_file.as_ref() {
        binds.push(format!(
            "{}:{}:ro,z",
            path.display(),
            UPSTREAM_PROXY_AUTH_MOUNT_PATH
        ));
    }
    if let Some(socket) = config.provider_spiffe_workload_api_socket.as_ref() {
        let parent = socket.parent().ok_or_else(|| {
            Status::failed_precondition("provider SPIFFE socket has no parent directory")
        })?;
        binds.push(format!(
            "{}:{}:ro",
            parent.display(),
            PROVIDER_SPIFFE_WORKLOAD_API_SOCKET_MOUNT_DIR
        ));
    }
    Ok(binds)
}

fn sandbox_token_host_path(
    sandbox: &DriverSandbox,
    config: &DockerDriverRuntimeConfig,
) -> Result<PathBuf, Status> {
    sandbox_token_host_path_by_id(&sandbox.id, config)
}

fn sandbox_token_host_path_by_id(
    sandbox_id: &str,
    config: &DockerDriverRuntimeConfig,
) -> Result<PathBuf, Status> {
    openshell_core::driver_utils::sandbox_token_path(
        "docker-sandbox-tokens",
        Some(&config.sandbox_label),
        sandbox_id,
    )
    .map_err(|err| {
        Status::internal(format!(
            "resolve sandbox token state directory failed: {err}"
        ))
    })
}

/// A durable public start snapshot intentionally omits the sandbox JWT. Before
/// rebuilding, ensure the original driver-owned bind source is still a regular
/// file rather than letting Docker follow a substituted path or create a new
/// empty source. The bearer is never read or included in diagnostics.
fn validate_existing_sandbox_token_file(
    sandbox_id: &str,
    config: &DockerDriverRuntimeConfig,
) -> Result<(), Status> {
    let path = sandbox_token_host_path_by_id(sandbox_id, config)?;
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| {
        Status::failed_precondition(
            "Docker stopped sandbox replacement requires its existing driver-owned authentication state",
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(Status::failed_precondition(
            "Docker stopped sandbox replacement authentication state is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Status::failed_precondition(
                "Docker stopped sandbox replacement authentication state is not owner-restricted",
            ));
        }
    }
    Ok(())
}

async fn write_sandbox_token_file(
    sandbox: &DriverSandbox,
    config: &DockerDriverRuntimeConfig,
) -> Result<bool, Status> {
    let Some(spec) = sandbox.spec.as_ref() else {
        return Ok(false);
    };
    if spec.sandbox_token.is_empty() {
        return Ok(false);
    }
    let path = sandbox_token_host_path(sandbox, config)?;
    if let Some(parent) = path.parent() {
        openshell_core::paths::create_dir_restricted(parent).map_err(|err| {
            Status::internal(format!(
                "create sandbox token directory {} failed: {err}",
                parent.display()
            ))
        })?;
    }
    tokio::fs::write(&path, format!("{}\n", spec.sandbox_token))
        .await
        .map_err(|err| {
            Status::internal(format!(
                "write sandbox token file {} failed: {err}",
                path.display()
            ))
        })?;
    openshell_core::paths::set_file_owner_only(&path).map_err(|err| {
        Status::internal(format!(
            "restrict sandbox token file {} failed: {err}",
            path.display()
        ))
    })?;
    Ok(true)
}

fn cleanup_sandbox_token_file(sandbox: &DriverSandbox, config: &DockerDriverRuntimeConfig) {
    cleanup_sandbox_token_file_by_id(&sandbox.id, config);
}

fn cleanup_sandbox_token_file_for_delete(
    sandbox_id: &str,
    pending: Option<&PendingSandboxRecord>,
    config: &DockerDriverRuntimeConfig,
) {
    if !sandbox_id.is_empty() {
        cleanup_sandbox_token_file_by_id(sandbox_id, config);
    } else if let Some(record) = pending {
        cleanup_sandbox_token_file(&record.sandbox, config);
    }
}

fn cleanup_sandbox_token_file_by_id(sandbox_id: &str, config: &DockerDriverRuntimeConfig) {
    let Ok(path) = sandbox_token_host_path_by_id(sandbox_id, config) else {
        return;
    };
    if let Err(err) = std::fs::remove_file(&path)
        && err.kind() != std::io::ErrorKind::NotFound
    {
        warn!(
            sandbox_id = %sandbox_id,
            path = %path.display(),
            error = %err,
            "Failed to remove Docker sandbox token file"
        );
    }
    if let Some(dir) = path.parent() {
        let _ = std::fs::remove_dir(dir);
    }
}

#[cfg(test)]
fn build_environment(sandbox: &DriverSandbox, config: &DockerDriverRuntimeConfig) -> Vec<String> {
    build_environment_for_oci_user(sandbox, config, "")
}

#[cfg(test)]
fn build_environment_for_oci_user(
    sandbox: &DriverSandbox,
    config: &DockerDriverRuntimeConfig,
    oci_user: &str,
) -> Vec<String> {
    build_environment_for_oci_user_with_sandbox_token_file(
        sandbox,
        config,
        oci_user,
        sandbox_has_request_token(sandbox),
    )
}

fn build_environment_for_oci_user_with_sandbox_token_file(
    sandbox: &DriverSandbox,
    config: &DockerDriverRuntimeConfig,
    oci_user: &str,
    include_sandbox_token_file: bool,
) -> Vec<String> {
    let mut environment = HashMap::from([
        ("HOME".to_string(), "/root".to_string()),
        ("PATH".to_string(), SUPERVISOR_PATH.to_string()),
        ("TERM".to_string(), "xterm".to_string()),
        (
            "OPENSHELL_LOG_LEVEL".to_string(),
            openshell_core::driver_utils::sandbox_log_level(sandbox, &config.log_level),
        ),
    ]);

    if let Some(spec) = sandbox.spec.as_ref() {
        let mut user_env = HashMap::new();
        if let Some(template) = spec.template.as_ref() {
            user_env.extend(template.environment.clone());
        }
        user_env.extend(spec.environment.clone());
        environment.extend(user_env.clone());
        if !user_env.is_empty()
            && let Ok(json) = serde_json::to_string(&user_env)
        {
            environment.insert(
                openshell_core::sandbox_env::USER_ENVIRONMENT.to_string(),
                json,
            );
        }
    }

    environment.insert(
        openshell_core::sandbox_env::ENDPOINT.to_string(),
        config.grpc_endpoint.clone(),
    );
    environment.insert(
        openshell_core::sandbox_env::SANDBOX_ID.to_string(),
        sandbox.id.clone(),
    );
    environment.insert(
        openshell_core::sandbox_env::SANDBOX.to_string(),
        sandbox.name.clone(),
    );
    environment.insert(
        openshell_core::sandbox_env::SSH_SOCKET_PATH.to_string(),
        config.ssh_socket_path.clone(),
    );
    let main_process =
        openshell_core::sandbox_env::MainProcessConfig::encode_driver_spec(sandbox.spec.as_ref())
            .expect("main process config serialization cannot fail");
    environment.insert(
        openshell_core::sandbox_env::MAIN_PROCESS_SPEC.to_string(),
        main_process,
    );
    environment.insert(
        openshell_core::sandbox_env::TELEMETRY_ENABLED.to_string(),
        openshell_core::telemetry::enabled_env_value().to_string(),
    );
    environment.insert(
        openshell_core::sandbox_env::NETWORK_RUNTIME_CAPABILITIES.to_string(),
        openshell_core::sandbox_env::POLICY_DNS_TRANSPARENT_TCP_CAPABILITY.to_string(),
    );
    // The root supervisor executes namespace helpers during bootstrap; keep
    // their search path driver-owned even when the template/spec set PATH.
    environment.insert("PATH".to_string(), SUPERVISOR_PATH.to_string());
    if config.guest_tls.is_some() {
        environment.insert(
            openshell_core::sandbox_env::TLS_CA.to_string(),
            TLS_CA_MOUNT_PATH.to_string(),
        );
        environment.insert(
            openshell_core::sandbox_env::TLS_CERT.to_string(),
            TLS_CERT_MOUNT_PATH.to_string(),
        );
        environment.insert(
            openshell_core::sandbox_env::TLS_KEY.to_string(),
            TLS_KEY_MOUNT_PATH.to_string(),
        );
    }
    if let Some(socket) = config.provider_spiffe_workload_api_socket.as_ref()
        && let Ok(path) =
            openshell_core::driver_utils::projected_provider_spiffe_socket_path(socket)
    {
        environment.insert(
            openshell_core::sandbox_env::PROVIDER_SPIFFE_WORKLOAD_API_SOCKET.to_string(),
            path,
        );
    }

    environment.remove(openshell_core::sandbox_env::SANDBOX_TOKEN);
    environment.remove(openshell_core::sandbox_env::SANDBOX_TOKEN_FILE);
    // Prevent user-supplied environment from overriding the TLS server name
    // the supervisor verifies — a sandbox user who can redirect the gateway
    // hostname could otherwise present a certificate for a name they control
    // and intercept the sandbox JWT.
    environment.remove(openshell_core::sandbox_env::GATEWAY_TLS_SERVER_NAME);
    environment.insert(
        openshell_core::sandbox_env::OCI_IMAGE_USER.to_string(),
        oci_user.to_string(),
    );
    environment.insert(
        openshell_core::sandbox_env::SANDBOX_UID.to_string(),
        String::new(),
    );
    environment.insert(
        openshell_core::sandbox_env::SANDBOX_GID.to_string(),
        String::new(),
    );

    // Gateway-minted sandbox JWT. Keep the raw bearer out of container
    // metadata; the supervisor reads it from this driver-owned bind mount.
    if include_sandbox_token_file {
        environment.insert(
            openshell_core::sandbox_env::SANDBOX_TOKEN_FILE.to_string(),
            SANDBOX_TOKEN_MOUNT_PATH.to_string(),
        );
    }

    let mut pairs = environment.into_iter().collect::<Vec<_>>();
    pairs.sort_by(|left, right| left.0.cmp(&right.0));
    pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect()
}

fn docker_cdi_gpu_inventory(info: &SystemInfo) -> CdiGpuInventory {
    CdiGpuInventory::new(
        info.discovered_devices
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter(|device| device.source.as_deref() == Some("cdi"))
            .filter_map(|device| device.id.as_deref()),
    )
}

fn docker_info_reports_wsl2(info: &SystemInfo) -> bool {
    [
        info.kernel_version.as_deref(),
        info.operating_system.as_deref(),
    ]
    .into_iter()
    .flatten()
    .any(os_or_kernel_reports_wsl2)
}

fn os_or_kernel_reports_wsl2(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("wsl2") || value.contains("microsoft-standard")
}

fn docker_gpu_selection_status(err: CdiGpuSelectionError) -> Status {
    Status::failed_precondition(err.to_string())
}

#[cfg(test)]
fn build_container_create_body(
    sandbox: &DriverSandbox,
    config: &DockerDriverRuntimeConfig,
) -> Result<ContainerCreateBody, Status> {
    let template = sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
        .ok_or_else(|| Status::invalid_argument("sandbox.spec.template is required"))?;
    let driver_config = docker_driver_config(template, config.enable_bind_mounts)?;
    let gpu_requirements = sandbox
        .spec
        .as_ref()
        .and_then(|spec| driver_gpu_requirements(spec.resource_requirements.as_ref()));
    let cdi_devices = if let Some(cdi_devices) = driver_config.cdi_devices.as_ref() {
        validate_specific_gpu_device_request(
            gpu_requirements,
            cdi_devices,
            "driver_config.cdi_devices",
        )
        .map_err(Status::invalid_argument)?;
        Some(cdi_devices.as_slice())
    } else {
        None
    };
    build_container_create_body_with_gpu_devices(sandbox, config, &driver_config, cdi_devices)
}

#[cfg(test)]
fn build_container_create_body_with_gpu_devices(
    sandbox: &DriverSandbox,
    config: &DockerDriverRuntimeConfig,
    driver_config: &DockerSandboxDriverConfig,
    gpu_device_ids: Option<&[String]>,
) -> Result<ContainerCreateBody, Status> {
    let template = sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
        .ok_or_else(|| Status::invalid_argument("sandbox.spec.template is required"))?;
    build_container_create_body_for_image(
        sandbox,
        config,
        driver_config,
        gpu_device_ids,
        &DockerImageMetadata {
            id: template.image.clone(),
            user: String::new(),
            working_dir: String::new(),
            volumes: Vec::new(),
        },
    )
}

fn build_container_create_body_for_image(
    sandbox: &DriverSandbox,
    config: &DockerDriverRuntimeConfig,
    driver_config: &DockerSandboxDriverConfig,
    gpu_device_ids: Option<&[String]>,
    image: &DockerImageMetadata,
) -> Result<ContainerCreateBody, Status> {
    build_container_create_body_for_image_with_sandbox_token_file(
        sandbox,
        config,
        driver_config,
        gpu_device_ids,
        image,
        sandbox_has_request_token(sandbox),
    )
}

/// Build a replacement body from durable gateway input. Unlike an initial
/// create request, a durable start snapshot deliberately has no raw JWT; its
/// existing driver-owned token file is therefore mounted explicitly.
fn build_replacement_container_create_body_for_image(
    sandbox: &DriverSandbox,
    config: &DockerDriverRuntimeConfig,
    driver_config: &DockerSandboxDriverConfig,
    gpu_device_ids: Option<&[String]>,
    image: &DockerImageMetadata,
) -> Result<ContainerCreateBody, Status> {
    build_container_create_body_for_image_with_sandbox_token_file(
        sandbox,
        config,
        driver_config,
        gpu_device_ids,
        image,
        true,
    )
}

fn build_container_create_body_for_image_with_sandbox_token_file(
    sandbox: &DriverSandbox,
    config: &DockerDriverRuntimeConfig,
    driver_config: &DockerSandboxDriverConfig,
    gpu_device_ids: Option<&[String]>,
    image: &DockerImageMetadata,
    include_sandbox_token_file: bool,
) -> Result<ContainerCreateBody, Status> {
    let spec = sandbox
        .spec
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("sandbox.spec is required"))?;
    let template = spec
        .template
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("sandbox.spec.template is required"))?;
    let resource_limits = docker_resource_limits(template)?;
    let workspace_root = driver_mounts::resolve_oci_workspace_root(&image.working_dir)
        .map_err(Status::failed_precondition)?;
    driver_mounts::validate_workspace_control_path(&workspace_root, &config.ssh_socket_path)
        .map_err(Status::failed_precondition)?;
    for volume in &image.volumes {
        driver_mounts::validate_container_mount_target(volume).map_err(|error| {
            Status::failed_precondition(format!(
                "invalid image-declared volume '{volume}': {error}"
            ))
        })?;
        driver_mounts::validate_workspace_mount_target(volume, &workspace_root).map_err(|_| {
            Status::failed_precondition(format!(
                "image-declared volume '{volume}' masks OCI WorkingDir '{workspace_root}' before workspace validation"
            ))
        })?;
        driver_mounts::validate_mount_control_path(volume, &config.ssh_socket_path)
            .map_err(Status::failed_precondition)?;
    }
    for mount in &driver_config.mounts {
        let target = match mount {
            DockerDriverMountConfig::Bind { target, .. }
            | DockerDriverMountConfig::Volume { target, .. }
            | DockerDriverMountConfig::Tmpfs { target, .. }
            | DockerDriverMountConfig::Image { target, .. } => target,
        };
        driver_mounts::validate_workspace_mount_target(target, &workspace_root)
            .map_err(Status::failed_precondition)?;
        driver_mounts::validate_mount_control_path(target, &config.ssh_socket_path)
            .map_err(Status::failed_precondition)?;
    }
    let user_mounts = docker_driver_mounts(driver_config)?;
    let user_bind_strings = docker_driver_bind_strings(driver_config)?;
    let device_requests = gpu_device_ids.map(|device_ids| {
        vec![DeviceRequest {
            driver: Some("cdi".to_string()),
            device_ids: Some(device_ids.to_vec()),
            ..Default::default()
        }]
    });
    let mut labels = template.labels.clone();
    labels.insert(
        LABEL_MANAGED_BY.to_string(),
        LABEL_MANAGED_BY_VALUE.to_string(),
    );
    labels.insert(LABEL_SANDBOX_ID.to_string(), sandbox.id.clone());
    labels.insert(LABEL_SANDBOX_NAME.to_string(), sandbox.name.clone());
    labels.insert(
        LABEL_SANDBOX_WORKSPACE.to_string(),
        sandbox.workspace.clone(),
    );
    // Record the resolved container path as immutable driver metadata. The
    // durable gateway snapshot intentionally contains no inspected OCI image
    // configuration, so this lets a future stopped replacement reject a
    // mutable image working-directory change instead of copying the wrong
    // writable layer.
    labels.insert(
        DOCKER_SANDBOX_WORKSPACE_ROOT_LABEL.to_string(),
        workspace_root.clone(),
    );
    // This protected label must overwrite any user-supplied template value.
    // `none` is intentional: it differentiates a current no-CA sandbox from
    // an old resource created before generation reconciliation existed.
    labels.insert(
        NETWORK_SUPERVISOR_TRUST_GENERATION_KEY.to_string(),
        docker_network_trust_generation(config).to_string(),
    );
    // The list/get/find paths filter by `config.sandbox_label`, so use
    // the same value here. `DriverSandbox.namespace` is unset on the request
    // path (the gateway elides it), and using it would produce containers
    // that the driver itself cannot find afterwards.
    labels.insert(
        LABEL_SANDBOX_NAMESPACE.to_string(),
        config.sandbox_label.clone(),
    );

    Ok(ContainerCreateBody {
        image: Some(image.id.clone()),
        user: Some("0".to_string()),
        // The image workspace may need to be created or rejected by the
        // supervisor, so do not let the OCI runtime chdir there first.
        working_dir: Some("/".to_string()),
        env: Some(build_environment_for_oci_user_with_sandbox_token_file(
            sandbox,
            config,
            &image.user,
            include_sandbox_token_file,
        )),
        entrypoint: Some(vec![SUPERVISOR_MOUNT_PATH.to_string()]),
        // Replace the image CMD with the supervisor's resolved workspace
        // argument so Docker cannot append inherited image arguments.
        cmd: {
            let mut args = vec!["--workdir".to_string(), workspace_root];
            args.extend(docker_upstream_proxy_cli_args(&config.upstream_proxy));
            args.extend(docker_network_trust_cli_args(
                config.network_trust_bundle.as_ref(),
            ));
            Some(args)
        },
        labels: Some(labels),
        host_config: Some(HostConfig {
            nano_cpus: resource_limits.nano_cpus,
            memory: resource_limits.memory_bytes,
            pids_limit: docker_pids_limit(config.sandbox_pids_limit)?,
            device_requests,
            binds: {
                let mut binds = build_binds_with_sandbox_token_file(
                    sandbox,
                    config,
                    include_sandbox_token_file,
                )?;
                binds.extend(user_bind_strings);
                Some(binds)
            },
            mounts: Some(user_mounts),
            // Canonical main-process exit is terminal. Runtime restart would
            // silently create a new process generation behind the gateway.
            restart_policy: None,
            cap_add: Some(vec![
                "SYS_ADMIN".to_string(),
                "NET_ADMIN".to_string(),
                "SYS_PTRACE".to_string(),
                "SYSLOG".to_string(),
            ]),
            // The default is explicitly Unconfined because the supervisor
            // needs mount operations commonly denied by docker-default.
            security_opt: config
                .app_armor_profile
                .as_ref()
                .and_then(AppArmorProfile::oci_security_opt)
                .map(|option| vec![option]),
            network_mode: Some(config.network_name.clone()),
            extra_hosts: Some(docker_extra_hosts(&config.gateway_route)),
            ..Default::default()
        }),
        networking_config: Some(NetworkingConfig {
            endpoints_config: Some(HashMap::from([(
                config.network_name.clone(),
                EndpointSettings::default(),
            )])),
        }),
        ..Default::default()
    })
}

/// Validate that gateway durable start input names exactly the resource in the
/// lifecycle request. ID/name-only starts intentionally remain supported for
/// independently versioned callers, but a rebuild must never pick a resource
/// by just one mutable label.
fn validate_start_snapshot_request_identity(
    sandbox_id: &str,
    sandbox_name: &str,
    sandbox: &DriverSandbox,
) -> Result<(), Status> {
    if sandbox.id != sandbox_id {
        return Err(Status::invalid_argument(
            "start sandbox snapshot identity does not match sandbox_id",
        ));
    }
    if sandbox.name != sandbox_name {
        return Err(Status::invalid_argument(
            "start sandbox snapshot identity does not match sandbox_name",
        ));
    }
    Ok(())
}

/// Require the labels that make a Docker container a resource of this driver,
/// not merely a similarly named container. This is used after a list lookup and
/// again after an inspect so an out-of-band relabel/rename cannot become a
/// replacement source.
fn validate_docker_managed_container_labels(
    labels: &HashMap<String, String>,
    sandbox: &DriverSandbox,
    namespace: &str,
) -> Result<(), Status> {
    let expected = [
        (LABEL_MANAGED_BY, LABEL_MANAGED_BY_VALUE),
        (LABEL_SANDBOX_NAMESPACE, namespace),
        (LABEL_SANDBOX_ID, sandbox.id.as_str()),
        (LABEL_SANDBOX_NAME, sandbox.name.as_str()),
        (LABEL_SANDBOX_WORKSPACE, sandbox.workspace.as_str()),
    ];
    if expected
        .into_iter()
        .any(|(key, value)| labels.get(key).map(String::as_str) != Some(value))
    {
        return Err(Status::failed_precondition(
            "resolved Docker container is not owned by the requested durable sandbox",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct DockerSandboxInspection {
    state: ContainerStateStatusEnum,
    finished_at: Option<String>,
    trust_generation: Option<String>,
    workspace_root: String,
}

/// Minimal state used only to resolve an ambiguous Docker response during the
/// replacement name hand-off. Container IDs—not names—address these probes.
struct DockerReplacementRecoveryContainer {
    name: String,
    state: Option<ContainerStateStatusEnum>,
}

#[derive(Clone, Copy)]
enum ReplacementRecovery {
    /// The old ID was absent after an uncertain old-container removal, so the
    /// canonical successor is already the only viable container to start.
    OldGone,
    /// The successor was safely discarded and the stopped old ID is canonical.
    OldRestored,
}

/// Extract only the protected, driver-owned metadata needed for a durable
/// start. The inspected container's command, environment, working directory,
/// image, and mount configuration are deliberately not used as input to a
/// replacement.
fn docker_sandbox_inspection_from_container(
    container: &ContainerInspectResponse,
    sandbox: &DriverSandbox,
    namespace: &str,
) -> Result<DockerSandboxInspection, Status> {
    let labels = container
        .config
        .as_ref()
        .and_then(|config| config.labels.as_ref())
        .ok_or_else(|| {
            Status::failed_precondition(
                "resolved Docker container did not report managed sandbox labels",
            )
        })?;
    validate_docker_managed_container_labels(labels, sandbox, namespace)?;

    let canonical_name = container_name_for_sandbox(sandbox);
    let actual_name = container
        .name
        .as_deref()
        .and_then(|name| name.strip_prefix('/').or(Some(name)));
    if actual_name != Some(canonical_name.as_str()) {
        return Err(Status::failed_precondition(
            "resolved Docker container name does not match durable sandbox identity",
        ));
    }

    let state = container
        .state
        .as_ref()
        .and_then(|state| state.status)
        .ok_or_else(|| {
            Status::failed_precondition(
                "resolved Docker container did not report a container state",
            )
        })?;
    Ok(DockerSandboxInspection {
        finished_at: container
            .state
            .as_ref()
            .filter(|state| state.status == Some(ContainerStateStatusEnum::EXITED))
            .and_then(|state| state.finished_at.clone()),
        state,
        trust_generation: labels.get(NETWORK_SUPERVISOR_TRUST_GENERATION_KEY).cloned(),
        workspace_root: docker_workspace_root_from_protected_labels(labels)?,
    })
}

/// Resolve a workspace archive root from a protected driver label. A missing
/// label is the sole legacy case and deliberately means the old fixed
/// `/sandbox`; an empty, root, or otherwise non-normalized label is rejected.
fn docker_workspace_root_from_protected_labels(
    labels: &HashMap<String, String>,
) -> Result<String, Status> {
    let Some(root) = labels.get(DOCKER_SANDBOX_WORKSPACE_ROOT_LABEL) else {
        return Ok(driver_mounts::DEFAULT_WORKSPACE_ROOT.to_string());
    };
    let normalized = driver_mounts::resolve_oci_workspace_root(root).map_err(|_| {
        Status::failed_precondition(
            "Docker sandbox protected workspace-root metadata is not a normalized workspace path",
        )
    })?;
    if normalized != *root {
        return Err(Status::failed_precondition(
            "Docker sandbox protected workspace-root metadata is not a normalized workspace path",
        ));
    }
    Ok(normalized)
}

fn validate_replacement_source_unchanged(
    current: &DockerSandboxInspection,
    original: &DockerSandboxInspection,
    desired_generation: &str,
) -> Result<(), Status> {
    if current.state != ContainerStateStatusEnum::EXITED {
        return Err(Status::failed_precondition(
            "Docker sandbox is no longer explicitly stopped; refusing trust replacement",
        ));
    }
    if current.workspace_root != original.workspace_root
        || current.trust_generation != original.trust_generation
    {
        return Err(Status::failed_precondition(
            "Docker sandbox protected metadata changed during trust reconciliation",
        ));
    }
    if current.trust_generation.as_deref() == Some(desired_generation) {
        return Err(Status::failed_precondition(
            "Docker sandbox trust generation changed during reconciliation",
        ));
    }
    Ok(())
}

/// Reject driver requests that arrive with neither a sandbox id nor a
/// sandbox name. Without this guard, downstream label filters degenerate
/// to "match every managed container in the namespace", which would let
/// `delete_sandbox`/`stop_sandbox`/`get_sandbox` pick an arbitrary
/// sandbox out of the set the driver manages.
fn require_sandbox_identifier(sandbox_id: &str, sandbox_name: &str) -> Result<(), Status> {
    if sandbox_id.is_empty() && sandbox_name.is_empty() {
        return Err(Status::invalid_argument(
            "sandbox_id or sandbox_name is required",
        ));
    }
    Ok(())
}

fn docker_workspace_root(image: &DockerImageMetadata) -> Result<String, Status> {
    driver_mounts::resolve_oci_workspace_root(&image.working_dir)
        .map_err(Status::failed_precondition)
}

/// Determine the nested user mount paths solely from the durable gateway
/// snapshot. Docker's archive endpoint includes mounted content, so these
/// paths are removed from the old writable-layer archive before it is restored
/// into a replacement that reconstructs the mounts from the same snapshot.
fn docker_workspace_nested_mount_destinations(
    driver_config: &DockerSandboxDriverConfig,
    workspace_root: &str,
) -> Result<Vec<DockerArchivePath>, Status> {
    let normalized_workspace_root = driver_mounts::normalize_mount_target(workspace_root);
    let workspace = Path::new(&normalized_workspace_root);
    let mut nested = Vec::new();

    for mount in &driver_config.mounts {
        let target = docker_driver_mount_target(mount);
        driver_mounts::validate_container_mount_target(target).map_err(|_| {
            Status::failed_precondition(
                "Docker trust reconciliation requires valid durable user mount destinations",
            )
        })?;
        // Create validation accepts a trailing slash. Normalize only for the
        // semantic workspace and archive-path comparison below; validation
        // above remains responsible for rejecting unsafe path segments.
        let normalized = driver_mounts::normalize_mount_target(target);
        let normalized_path = Path::new(&normalized);
        if driver_mounts::path_is_or_under(workspace, normalized_path) {
            return Err(Status::failed_precondition(
                "Docker durable user mount masks the protected workspace root during trust reconciliation",
            ));
        }
        if !driver_mounts::path_is_or_under(normalized_path, workspace) {
            continue;
        }

        let relative = normalized
            .strip_prefix(&normalized_workspace_root)
            .and_then(|path| path.strip_prefix('/'))
            .ok_or_else(|| {
                Status::failed_precondition(
                    "Docker durable user mount does not have an unambiguous protected workspace destination",
                )
            })?;
        let components = docker_archive_path_components(relative.as_bytes()).map_err(|_| {
            Status::failed_precondition(
                "Docker trust reconciliation requires normalized nested user mount destinations",
            )
        })?;
        nested.push(components);
    }

    nested.sort();
    if nested.windows(2).any(|pair| {
        pair[1].len() >= pair[0].len()
            && pair[0]
                .iter()
                .zip(&pair[1])
                .all(|(left, right)| left == right)
    }) {
        return Err(Status::failed_precondition(
            "Docker durable nested user mount destinations overlap and cannot be reconciled safely",
        ));
    }
    Ok(nested)
}

fn docker_driver_mount_target(mount: &DockerDriverMountConfig) -> &str {
    match mount {
        DockerDriverMountConfig::Bind { target, .. }
        | DockerDriverMountConfig::Volume { target, .. }
        | DockerDriverMountConfig::Tmpfs { target, .. }
        | DockerDriverMountConfig::Image { target, .. } => target,
    }
}

/// Docker rebases `GET /archive?path=<workspace>` to the workspace basename.
/// Extract it into the parent to recreate that exact path without interpreting
/// the archive locally.
fn workspace_archive_restore_parent(workspace_root: &str) -> Result<&str, Status> {
    if workspace_root == driver_mounts::DEFAULT_WORKSPACE_ROOT {
        return Ok("/");
    }
    workspace_root.rsplit_once('/').map_or_else(
        || {
            Err(Status::failed_precondition(
                "Docker workspace path has no archive restoration parent",
            ))
        },
        |(parent, _)| Ok(if parent.is_empty() { "/" } else { parent }),
    )
}

fn docker_container_openshell_endpoint(endpoint: &str, host: &str, port: u16) -> String {
    let Ok(mut url) = Url::parse(endpoint) else {
        return endpoint.to_string();
    };

    if url.set_host(Some(host)).is_ok() && url.set_port(Some(port)).is_ok() {
        return url.to_string();
    }

    endpoint.to_string()
}

fn docker_network_name(config: &DockerComputeConfig) -> String {
    let name = config.network_name.trim();
    if name.is_empty() {
        return DEFAULT_DOCKER_NETWORK_NAME.to_string();
    }
    name.to_string()
}

fn parse_optional_host_gateway_ip(value: &str) -> CoreResult<Option<IpAddr>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    trimmed
        .parse()
        .map(Some)
        .map_err(|err| Error::config(format!("invalid host_gateway_ip value '{trimmed}': {err}")))
}

fn docker_gateway_route(
    info: &SystemInfo,
    bridge_gateway_ip: IpAddr,
    port: u16,
    host_gateway_ip: Option<IpAddr>,
) -> DockerGatewayRoute {
    docker_gateway_route_for_host(
        info,
        bridge_gateway_ip,
        port,
        host_gateway_ip,
        host_runtime_requires_host_gateway_alias(),
    )
}

fn docker_gateway_route_for_host(
    info: &SystemInfo,
    bridge_gateway_ip: IpAddr,
    port: u16,
    host_gateway_ip: Option<IpAddr>,
    host_requires_host_gateway_alias: bool,
) -> DockerGatewayRoute {
    if let Some(host_alias_ip) = host_gateway_ip {
        return DockerGatewayRoute::Bridge {
            bind_address: SocketAddr::new(host_alias_ip, port),
            host_alias_ip,
        };
    }

    if host_requires_host_gateway_alias || uses_host_gateway_alias(info) {
        DockerGatewayRoute::HostGateway
    } else {
        DockerGatewayRoute::Bridge {
            bind_address: SocketAddr::new(bridge_gateway_ip, port),
            host_alias_ip: bridge_gateway_ip,
        }
    }
}

fn docker_gateway_callback_bind_address(
    route: &DockerGatewayRoute,
    primary_bind_address: SocketAddr,
) -> Option<SocketAddr> {
    match route {
        DockerGatewayRoute::Bridge { bind_address, .. } => Some(*bind_address),
        DockerGatewayRoute::HostGateway => match primary_bind_address.ip() {
            IpAddr::V4(ip) if ip.is_unspecified() || ip == Ipv4Addr::LOCALHOST => None,
            _ => Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                primary_bind_address.port(),
            )),
        },
    }
}

fn host_runtime_requires_host_gateway_alias() -> bool {
    cfg!(target_os = "macos")
}

/// Detect Docker Desktop and behaviourally compatible runtimes - Colima,
/// Lima, Rancher Desktop, and `OrbStack` - that share Docker Desktop's routing
/// constraint: the bridge gateway IP is reachable from inside containers but
/// not from the `OpenShell` server process running on the host, so callbacks
/// must traverse `host-gateway`.
///
/// Each runtime is detected via the daemon's reported OS string or hostname,
/// supplemented by labels where the runtime publishes them.
fn uses_host_gateway_alias(info: &SystemInfo) -> bool {
    let operating_system = info
        .operating_system
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if operating_system.contains("docker desktop") {
        return true;
    }

    let name = info
        .name
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name.starts_with("colima")
        || name.starts_with("lima-")
        || name.starts_with("rancher-desktop")
        || name.starts_with("orbstack")
    {
        return true;
    }

    info.labels.as_ref().is_some_and(|labels| {
        labels.iter().any(|label| {
            label.starts_with("com.docker.desktop.")
                || label.starts_with("dev.rancherdesktop.")
                || label.starts_with("dev.orbstack.")
        })
    })
}

fn docker_extra_hosts(route: &DockerGatewayRoute) -> Vec<String> {
    match route {
        DockerGatewayRoute::Bridge { host_alias_ip, .. } => vec![
            format!("{HOST_DOCKER_INTERNAL}:{host_alias_ip}"),
            format!("{HOST_OPENSHELL_INTERNAL}:{host_alias_ip}"),
        ],
        DockerGatewayRoute::HostGateway => vec![
            format!("{HOST_DOCKER_INTERNAL}:host-gateway"),
            format!("{HOST_OPENSHELL_INTERNAL}:host-gateway"),
        ],
    }
}

async fn ensure_bridge_network(docker: &Docker, network_name: &str) -> CoreResult<IpAddr> {
    match docker.inspect_network(network_name, None).await {
        Ok(network) => return validate_bridge_network(network_name, &network),
        Err(err) if !is_not_found_error(&err) => {
            return Err(Error::execution(format!(
                "failed to inspect Docker network '{network_name}': {err}"
            )));
        }
        Err(_) => {}
    }

    docker
        .create_network(NetworkCreateRequest {
            name: network_name.to_string(),
            driver: Some(DOCKER_NETWORK_DRIVER.to_string()),
            attachable: Some(true),
            labels: Some(HashMap::from([(
                LABEL_MANAGED_BY.to_string(),
                LABEL_MANAGED_BY_VALUE.to_string(),
            )])),
            ..Default::default()
        })
        .await
        .map(|_| ())
        .or_else(|err| {
            if is_conflict_error(&err) {
                Ok(())
            } else {
                Err(Error::execution(format!(
                    "failed to create Docker network '{network_name}': {err}"
                )))
            }
        })?;

    let network = docker
        .inspect_network(network_name, None)
        .await
        .map_err(|err| {
            Error::execution(format!(
                "failed to inspect Docker network '{network_name}' after create: {err}"
            ))
        })?;
    validate_bridge_network(network_name, &network)
}

fn validate_bridge_network(
    network_name: &str,
    network: &bollard::models::NetworkInspect,
) -> CoreResult<IpAddr> {
    if network.driver.as_deref() != Some(DOCKER_NETWORK_DRIVER) {
        return Err(Error::config(format!(
            "Docker network '{network_name}' must use the '{DOCKER_NETWORK_DRIVER}' driver, found '{}'",
            network.driver.as_deref().unwrap_or("unknown")
        )));
    }

    docker_bridge_gateway_ip(network_name, network)
}

fn docker_bridge_gateway_ip(
    network_name: &str,
    network: &bollard::models::NetworkInspect,
) -> CoreResult<IpAddr> {
    let Some(configs) = network.ipam.as_ref().and_then(|ipam| ipam.config.as_ref()) else {
        return Err(Error::config(format!(
            "Docker bridge network '{network_name}' does not expose IPAM gateway configuration"
        )));
    };

    for config in configs {
        let Some(gateway) = config.gateway.as_deref() else {
            continue;
        };
        let ip = gateway.parse::<IpAddr>().map_err(|err| {
            Error::config(format!(
                "Docker bridge network '{network_name}' has invalid gateway '{gateway}': {err}"
            ))
        })?;
        if matches!(ip, IpAddr::V4(_)) {
            return Ok(ip);
        }
    }

    Err(Error::config(format!(
        "Docker bridge network '{network_name}' does not have an IPv4 IPAM gateway"
    )))
}

fn docker_resource_limits(
    template: &DriverSandboxTemplate,
) -> Result<DockerResourceLimits, Status> {
    let Some(resources) = template.resources.as_ref() else {
        return Ok(DockerResourceLimits::default());
    };

    if !resources.cpu_request.trim().is_empty() {
        return Err(Status::failed_precondition(
            "docker compute driver does not support resources.requests.cpu",
        ));
    }
    if !resources.memory_request.trim().is_empty() {
        return Err(Status::failed_precondition(
            "docker compute driver does not support resources.requests.memory",
        ));
    }

    Ok(DockerResourceLimits {
        nano_cpus: parse_cpu_limit(&resources.cpu_limit)?,
        memory_bytes: parse_memory_limit(&resources.memory_limit)?,
    })
}

fn validate_sandbox_pids_limit(value: Option<std::num::NonZeroI64>) -> CoreResult<()> {
    if value.is_some_and(|limit| limit.get() < 0) {
        return Err(Error::config(
            "docker sandbox_pids_limit must be positive when set",
        ));
    }
    Ok(())
}

fn validate_image_pull_policy(policy: ImagePullPolicy) -> CoreResult<()> {
    if policy == ImagePullPolicy::Newer {
        return Err(Error::config(
            "docker image_pull_policy = \"newer\" is supported only by the Podman compute driver",
        ));
    }
    Ok(())
}

fn validate_docker_app_armor_profile(
    profile: Option<&AppArmorProfile>,
    info: &SystemInfo,
) -> CoreResult<()> {
    let requires_apparmor = matches!(
        profile,
        Some(AppArmorProfile::RuntimeDefault | AppArmorProfile::Localhost(_))
    );
    if !requires_apparmor {
        return Ok(());
    }
    let available = info.security_options.as_ref().is_some_and(|options| {
        options
            .iter()
            .any(|option| option.to_ascii_lowercase().contains("apparmor"))
    });
    if !available {
        return Err(Error::config(
            "app_armor_profile requires AppArmor, but Docker reports it is unavailable; enable AppArmor on the daemon host or set app_armor_profile = \"Unconfined\" explicitly",
        ));
    }
    Ok(())
}

fn docker_pids_limit(value: Option<std::num::NonZeroI64>) -> Result<Option<i64>, Status> {
    if value.is_some_and(|limit| limit.get() < 0) {
        return Err(Status::failed_precondition(
            "docker sandbox_pids_limit must be positive when set",
        ));
    }
    Ok(value.map(std::num::NonZeroI64::get))
}

#[allow(clippy::cast_possible_truncation)]
fn parse_cpu_limit(value: &str) -> Result<Option<i64>, Status> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if let Some(millicores) = value.strip_suffix('m') {
        let millicores = millicores.parse::<i64>().map_err(|_| {
            Status::failed_precondition(format!(
                "invalid docker cpu_limit '{value}'; expected an integer or millicore quantity",
            ))
        })?;
        if millicores <= 0 {
            return Err(Status::failed_precondition(
                "docker cpu_limit must be greater than zero",
            ));
        }
        return Ok(Some(millicores.saturating_mul(1_000_000)));
    }

    let cores = value.parse::<f64>().map_err(|_| {
        Status::failed_precondition(format!(
            "invalid docker cpu_limit '{value}'; expected an integer or millicore quantity",
        ))
    })?;
    if !cores.is_finite() || cores <= 0.0 {
        return Err(Status::failed_precondition(
            "docker cpu_limit must be greater than zero",
        ));
    }

    Ok(Some((cores * 1_000_000_000.0).round() as i64))
}

#[allow(clippy::cast_possible_truncation)]
fn parse_memory_limit(value: &str) -> Result<Option<i64>, Status> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }

    let number_end = value
        .find(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .unwrap_or(value.len());
    let (number, suffix) = value.split_at(number_end);
    let amount = number.parse::<f64>().map_err(|_| {
        Status::failed_precondition(format!(
            "invalid docker memory_limit '{value}'; expected a Kubernetes-style quantity",
        ))
    })?;
    if !amount.is_finite() || amount <= 0.0 {
        return Err(Status::failed_precondition(
            "docker memory_limit must be greater than zero",
        ));
    }

    let multiplier = match suffix {
        "" => 1_f64,
        "Ki" => 1024_f64,
        "Mi" => 1024_f64.powi(2),
        "Gi" => 1024_f64.powi(3),
        "Ti" => 1024_f64.powi(4),
        "Pi" => 1024_f64.powi(5),
        "Ei" => 1024_f64.powi(6),
        "K" => 1000_f64,
        "M" => 1000_f64.powi(2),
        "G" => 1000_f64.powi(3),
        "T" => 1000_f64.powi(4),
        "P" => 1000_f64.powi(5),
        "E" => 1000_f64.powi(6),
        _ => {
            return Err(Status::failed_precondition(format!(
                "invalid docker memory_limit suffix '{suffix}'",
            )));
        }
    };

    Ok(Some((amount * multiplier).round() as i64))
}

fn sandbox_from_container_summary(summary: &ContainerSummary) -> Option<DriverSandbox> {
    let labels = summary.labels.as_ref()?;
    let id = labels.get(LABEL_SANDBOX_ID)?.clone();
    let name = labels.get(LABEL_SANDBOX_NAME)?.clone();
    let namespace = labels
        .get(LABEL_SANDBOX_NAMESPACE)
        .cloned()
        .unwrap_or_default();
    let workspace = labels
        .get(LABEL_SANDBOX_WORKSPACE)
        .cloned()
        .unwrap_or_default();

    Some(DriverSandbox {
        id,
        name: name.clone(),
        namespace,
        spec: None,
        status: Some(driver_status_from_summary(summary, &name)),
        workspace,
    })
}

fn driver_status_from_summary(
    summary: &ContainerSummary,
    sandbox_name: &str,
) -> DriverSandboxStatus {
    let state = summary.state.unwrap_or(ContainerSummaryStateEnum::EMPTY);
    let (ready, reason, message, deleting) = container_ready_condition(state);

    DriverSandboxStatus {
        sandbox_name: summary_container_name(summary).unwrap_or_else(|| sandbox_name.to_string()),
        instance_id: summary.id.clone().unwrap_or_default(),
        agent_fd: String::new(),
        sandbox_fd: String::new(),
        conditions: vec![DriverCondition {
            r#type: "Ready".to_string(),
            status: ready.to_string(),
            reason: reason.to_string(),
            message: message.to_string(),
            last_transition_time: String::new(),
        }],
        deleting,
    }
}

/// Refine an exited Docker sandbox's `Ready` condition from inspected state.
///
/// A workspace-validation exit is reported distinctly so users can repair the
/// OCI working directory rather than diagnose a generic crash. A signal kill
/// (exit 137/143 = SIGKILL/SIGTERM, not OOM) is the signature of a
/// machine/daemon restart terminating a running container. Reclassify it from
/// the generic terminal `ContainerExited` to the recoverable
/// `ContainerRuntimeRestart` so gateway startup can revive it. OOM kills and
/// ordinary application exits stay `ContainerExited` and terminal.
fn apply_docker_exit_classification(sandbox: &mut DriverSandbox, state: &ContainerState) {
    if state.oom_killed == Some(true) {
        return;
    }
    let Some(code) = state.exit_code else {
        return;
    };
    let Some(condition) = sandbox
        .status
        .as_mut()
        .and_then(|status| status.conditions.iter_mut().find(|c| c.r#type == "Ready"))
    else {
        return;
    };
    if condition.reason != CONDITION_EXITED {
        return;
    }
    if code == i64::from(SUPERVISOR_EXIT_WORKSPACE_VALIDATION_FAILED) {
        condition.reason = CONDITION_WORKSPACE_VALIDATION_FAILED.to_string();
        condition.message = "OCI WorkingDir is not usable by the sandbox identity".to_string();
    } else if matches!(code, 137 | 143) {
        condition.reason = CONDITION_RUNTIME_RESTART.to_string();
        condition.message = format!("Container terminated by signal (exit code {code})");
    }
}

fn container_ready_condition(
    state: ContainerSummaryStateEnum,
) -> (&'static str, &'static str, &'static str, bool) {
    match state {
        ContainerSummaryStateEnum::RUNNING => {
            ("True", "BackendReady", "Container is running", false)
        }
        ContainerSummaryStateEnum::CREATED => ("False", "Starting", "Container created", false),
        ContainerSummaryStateEnum::RESTARTING => (
            "False",
            "ContainerRestarting",
            "Container is restarting after a failure",
            false,
        ),
        ContainerSummaryStateEnum::EMPTY => {
            ("False", "Starting", "Container state is unknown", false)
        }
        ContainerSummaryStateEnum::REMOVING => {
            ("False", "Deleting", "Container is being removed", true)
        }
        ContainerSummaryStateEnum::PAUSED => {
            ("False", "ContainerPaused", "Container is paused", false)
        }
        ContainerSummaryStateEnum::EXITED => ("False", CONDITION_EXITED, "Container exited", false),
        ContainerSummaryStateEnum::DEAD => ("False", "ContainerDead", "Container is dead", false),
    }
}

fn summary_container_name(summary: &ContainerSummary) -> Option<String> {
    summary
        .names
        .as_ref()
        .and_then(|names| names.first())
        .map(|name| name.trim_start_matches('/').to_string())
        .filter(|name| !name.is_empty())
}

fn summary_container_target(summary: &ContainerSummary) -> Option<String> {
    // Prefer the container ID: it's stable while the container exists and is
    // accepted by Docker APIs just like a name. Fall back to the parsed name
    // for transient summaries that do not include an ID.
    summary
        .id
        .as_deref()
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .or_else(|| summary_container_name(summary))
}

/// States from which a managed container can be brought back to running by
/// `start_container`. Skip `Restarting` (already coming up), `Removing`,
/// `Dead` (terminal), `Paused` (needs `unpause`, not `start`), and
/// `Running` (nothing to do).
fn container_state_needs_start(state: ContainerSummaryStateEnum) -> bool {
    matches!(
        state,
        ContainerSummaryStateEnum::EXITED | ContainerSummaryStateEnum::CREATED
    )
}

fn docker_stop_timeout_secs(timeout_secs: u32) -> i32 {
    i32::try_from(timeout_secs).unwrap_or(i32::MAX)
}

fn driver_sandbox_reports_container_exit(sandbox: &DriverSandbox) -> bool {
    sandbox.status.as_ref().is_some_and(|status| {
        status.conditions.iter().any(|condition| {
            condition.r#type == "Ready"
                && condition.status.eq_ignore_ascii_case("false")
                && condition.reason == "ContainerExited"
        })
    })
}

fn docker_polled_exit_is_stale(
    previous_finished_at: &str,
    current_state: Option<&ContainerState>,
) -> bool {
    let Some(current_state) = current_state else {
        return false;
    };

    if current_state.status != Some(ContainerStateStatusEnum::EXITED) {
        // The list response said Exited, but inspect has already observed a
        // newer state. Publishing the older list result would regress it.
        return true;
    }

    current_state.finished_at.as_deref() == Some(previous_finished_at)
}

fn label_filters(values: impl IntoIterator<Item = String>) -> HashMap<String, Vec<String>> {
    HashMap::from([("label".to_string(), values.into_iter().collect())])
}

fn managed_container_label_filters(
    sandbox_label: &str,
    extra_values: impl IntoIterator<Item = String>,
) -> HashMap<String, Vec<String>> {
    let mut values = vec![
        format!("{LABEL_MANAGED_BY}={LABEL_MANAGED_BY_VALUE}"),
        format!("{LABEL_SANDBOX_NAMESPACE}={sandbox_label}"),
    ];
    values.extend(extra_values);
    label_filters(values)
}

/// Maximum Docker container name length. Docker's own limit is 253 bytes, but
/// we cap at a conservative 200 to leave headroom for tooling that truncates
/// names further.
const MAX_CONTAINER_NAME_LEN: usize = 200;
const CONTAINER_NAME_PREFIX: &str = "openshell-";

fn container_name_for_sandbox(sandbox: &DriverSandbox) -> String {
    let id_suffix = sanitize_docker_name(&sandbox.id);
    let workspace = sanitize_docker_name(&sandbox.workspace);
    let name = sanitize_docker_name(&sandbox.name);

    // Format: openshell-{workspace}--{name}-{id}
    // The workspace and id are never truncated — they ensure uniqueness.
    // Only the sandbox name portion is truncated when the total exceeds
    // MAX_CONTAINER_NAME_LEN.

    if name.is_empty() {
        let mut base = format!("{CONTAINER_NAME_PREFIX}{workspace}---{id_suffix}");
        if base.len() > MAX_CONTAINER_NAME_LEN {
            base.truncate(MAX_CONTAINER_NAME_LEN);
        }
        return trim_container_name_tail(base);
    }

    // Reserve space for fixed parts: prefix + workspace + "--" + "-" + id
    let reserved = CONTAINER_NAME_PREFIX.len() + workspace.len() + 2 + 1 + id_suffix.len();
    if reserved >= MAX_CONTAINER_NAME_LEN {
        let mut base = format!("{CONTAINER_NAME_PREFIX}{workspace}---{id_suffix}");
        base.truncate(MAX_CONTAINER_NAME_LEN);
        return trim_container_name_tail(base);
    }

    let name_budget = MAX_CONTAINER_NAME_LEN - reserved;
    let truncated_name = if name.len() > name_budget {
        trim_container_name_tail(name[..name_budget].to_string())
    } else {
        name
    };
    format!("{CONTAINER_NAME_PREFIX}{workspace}--{truncated_name}-{id_suffix}")
}

/// Derive a bounded collision-resistant temporary name without changing the
/// durable container identity. The UUID never enters gateway state and avoids
/// stale-name collisions across gateway processes as well as concurrent calls.
fn temporary_replacement_container_name(canonical_name: &str) -> String {
    temporary_replacement_name(canonical_name, "replacement")
}

fn temporary_replacement_backup_name(canonical_name: &str) -> String {
    temporary_replacement_name(canonical_name, "backup")
}

fn temporary_replacement_name(canonical_name: &str, purpose: &str) -> String {
    let suffix = format!("-reconcile-{purpose}-{}", Uuid::new_v4().simple());
    let prefix_len = MAX_CONTAINER_NAME_LEN.saturating_sub(suffix.len());
    // Canonical Docker names are ASCII after `sanitize_docker_name`, so byte
    // truncation cannot split UTF-8 and preserves the length contract.
    let prefix = trim_container_name_tail(
        canonical_name[..canonical_name.len().min(prefix_len)].to_string(),
    );
    format!("{prefix}{suffix}")
}

/// Docker container names may not end with `-`, `.`, or `_`. Truncation can
/// leave one of those trailing, so strip them before returning.
fn trim_container_name_tail(mut value: String) -> String {
    while value
        .chars()
        .last()
        .is_some_and(|ch| matches!(ch, '-' | '.' | '_'))
    {
        value.pop();
    }
    value
}

fn sanitize_docker_name(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-') {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

fn normalize_docker_arch(arch: &str) -> String {
    match arch {
        "x86_64" => "amd64".to_string(),
        "aarch64" => "arm64".to_string(),
        other => other.to_ascii_lowercase(),
    }
}

#[derive(Debug, Eq, PartialEq)]
enum SupervisorBinSource {
    Binary(PathBuf),
    Image(String),
}

fn resolve_supervisor_bin_source(
    docker_config: &DockerComputeConfig,
    current_exe: Option<&Path>,
    target_candidates: &[PathBuf],
) -> CoreResult<SupervisorBinSource> {
    // Tier 1: explicit supervisor_bin in [openshell.drivers.docker].
    if let Some(path) = docker_config.supervisor_bin.clone() {
        let path = canonicalize_existing_file(&path, "docker supervisor binary")?;
        validate_linux_elf_binary(&path).map_err(Error::config)?;
        return Ok(SupervisorBinSource::Binary(path));
    }

    // Tier 2: explicit supervisor_image in [openshell.drivers.docker].
    // A configured image should be the source of truth even when a local
    // developer build is present under target/.
    if let Some(image) = docker_config.supervisor_image.clone() {
        return Ok(SupervisorBinSource::Image(image));
    }

    // Tier 3: sibling `openshell-sandbox` next to the running gateway
    // (release artifact layout). Linux-only because the sibling must be a
    // Linux ELF to bind-mount into a Linux container.
    if cfg!(target_os = "linux")
        && let Some(current_exe) = current_exe
        && let Some(parent) = current_exe.parent()
    {
        let sibling = parent.join("openshell-sandbox");
        if sibling.is_file() {
            let path = canonicalize_existing_file(&sibling, "docker supervisor binary")?;
            if validate_linux_elf_binary(&path).is_ok() {
                return Ok(SupervisorBinSource::Binary(path));
            }
        }
    }

    // Tier 4: local cargo target build (developer workflow). Preferred
    // over the default registry image when available because it matches
    // whatever the developer just built.
    for candidate in target_candidates {
        if candidate.is_file() {
            let path = canonicalize_existing_file(candidate, "docker supervisor binary")?;
            if validate_linux_elf_binary(&path).is_ok() {
                return Ok(SupervisorBinSource::Binary(path));
            }
        }
    }

    // Tier 5: pull the release-matched default supervisor image and extract
    // the binary to a host-side cache keyed by image content digest.
    Ok(SupervisorBinSource::Image(
        openshell_core::config::default_supervisor_image(),
    ))
}

pub(crate) async fn resolve_supervisor_bin(
    docker: &Docker,
    docker_config: &DockerComputeConfig,
    daemon_arch: &str,
) -> CoreResult<PathBuf> {
    let current_exe =
        if cfg!(target_os = "linux")
            && docker_config.supervisor_bin.is_none()
            && docker_config.supervisor_image.is_none()
        {
            Some(std::env::current_exe().map_err(|err| {
                Error::config(format!("failed to resolve current executable: {err}"))
            })?)
        } else {
            None
        };
    let target_candidates = linux_supervisor_candidates(daemon_arch);

    match resolve_supervisor_bin_source(docker_config, current_exe.as_deref(), &target_candidates)?
    {
        SupervisorBinSource::Binary(path) => Ok(path),
        SupervisorBinSource::Image(image) => {
            extract_supervisor_bin_from_image(docker, &image).await
        }
    }
}

fn linux_supervisor_candidates(daemon_arch: &str) -> Vec<PathBuf> {
    match daemon_arch {
        "arm64" => vec![PathBuf::from(
            "target/aarch64-unknown-linux-gnu/release/openshell-sandbox",
        )],
        "amd64" => vec![PathBuf::from(
            "target/x86_64-unknown-linux-gnu/release/openshell-sandbox",
        )],
        _ => Vec::new(),
    }
}

/// Pull the supervisor image (if not already local), extract
/// `/openshell-sandbox` to a host cache keyed by the image's content
/// digest, and return the cache path.
///
/// The extraction is atomic: the binary is written to a sibling temp file
/// inside the digest-keyed directory and renamed into place, so concurrent
/// gateway starts don't observe a partial file.
async fn extract_supervisor_bin_from_image(docker: &Docker, image: &str) -> CoreResult<PathBuf> {
    let refresh_attempted = if supervisor_image_should_refresh(image) {
        info!(image = image, "Refreshing mutable docker supervisor image");
        match pull_supervisor_image(docker, image).await {
            Ok(()) => true,
            Err(err) => {
                warn!(
                    image = image,
                    error = %err,
                    "failed to refresh mutable docker supervisor image; falling back to local image if present",
                );
                true
            }
        }
    } else {
        false
    };

    // Inspect first to see if the image is already present; only pull on miss.
    let inspect = match docker.inspect_image(image).await {
        Ok(inspect) => inspect,
        Err(err) if is_not_found_error(&err) && !refresh_attempted => {
            info!(image = image, "Pulling docker supervisor image");
            pull_supervisor_image(docker, image).await?;
            docker.inspect_image(image).await.map_err(|err| {
                Error::config(format!(
                    "failed to inspect docker supervisor image '{image}' after pull: {err}",
                ))
            })?
        }
        Err(err) if is_not_found_error(&err) => {
            return Err(Error::config(format!(
                "docker supervisor image '{image}' is not present locally after refresh attempt",
            )));
        }
        Err(err) => {
            return Err(Error::config(format!(
                "failed to inspect docker supervisor image '{image}': {err}",
            )));
        }
    };

    let digest = inspect.id.clone().ok_or_else(|| {
        Error::config(format!(
            "docker supervisor image '{image}' inspect response has no Id",
        ))
    })?;

    let cache_path =
        openshell_core::driver_utils::supervisor_cache_path("docker-supervisor", &digest)
            .map_err(Error::config)?;
    if cache_path.is_file() {
        validate_linux_elf_binary(&cache_path).map_err(Error::config)?;
        return Ok(cache_path);
    }

    info!(
        image = image,
        digest = digest,
        cache_path = %cache_path.display(),
        "Extracting supervisor binary from image to host cache",
    );

    let binary_bytes = extract_supervisor_binary_bytes(docker, image).await?;
    write_cache_binary_atomic(&cache_path, &binary_bytes).map_err(Error::config)?;
    validate_linux_elf_binary(&cache_path).map_err(Error::config)?;
    Ok(cache_path)
}

async fn pull_supervisor_image(docker: &Docker, image: &str) -> CoreResult<()> {
    let mut stream = docker.create_image(
        Some(CreateImageOptions {
            from_image: Some(image.to_string()),
            ..Default::default()
        }),
        None,
        None,
    );
    while let Some(result) = stream.next().await {
        result.map_err(|err| {
            Error::config(format!(
                "failed to pull docker supervisor image '{image}': {err}",
            ))
        })?;
    }
    Ok(())
}

/// Create a short-lived container from `image`, stream out the supervisor
/// binary as a tar archive, and return the untarred file bytes. The
/// container is always removed, even on error paths.
async fn extract_supervisor_binary_bytes(docker: &Docker, image: &str) -> CoreResult<Vec<u8>> {
    let container_name = temp_extract_container_name();
    docker
        .create_container(
            Some(
                CreateContainerOptionsBuilder::default()
                    .name(container_name.as_str())
                    .build(),
            ),
            ContainerCreateBody {
                image: Some(image.to_string()),
                entrypoint: Some(vec![SUPERVISOR_IMAGE_BINARY_PATH.to_string()]),
                cmd: Some(Vec::new()),
                ..Default::default()
            },
        )
        .await
        .map_err(|err| {
            Error::config(format!(
                "failed to create extractor container from '{image}': {err}",
            ))
        })?;

    // Always tear down the extractor container, even if extraction fails.
    let result = download_binary_from_container(docker, &container_name).await;
    if let Err(remove_err) = docker
        .remove_container(
            &container_name,
            Some(RemoveContainerOptionsBuilder::default().force(true).build()),
        )
        .await
    {
        warn!(
            container = container_name,
            error = %remove_err,
            "Failed to remove supervisor extractor container",
        );
    }
    result
}

async fn download_binary_from_container(
    docker: &Docker,
    container_name: &str,
) -> CoreResult<Vec<u8>> {
    let options = DownloadFromContainerOptionsBuilder::default()
        .path(SUPERVISOR_IMAGE_BINARY_PATH)
        .build();
    let mut stream = docker.download_from_container(container_name, Some(options));

    let mut tar_bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk: Bytes = chunk.map_err(|err| {
            Error::config(format!(
                "failed to read supervisor binary stream from '{container_name}': {err}",
            ))
        })?;
        tar_bytes.extend_from_slice(&chunk);
    }

    extract_first_tar_entry(&tar_bytes).map_err(|err| {
        Error::config(format!(
            "failed to extract supervisor binary from tar archive returned by '{container_name}': {err}",
        ))
    })
}

fn canonicalize_existing_file(path: &Path, description: &str) -> CoreResult<PathBuf> {
    if !path.is_file() {
        return Err(Error::config(format!(
            "{description} '{}' does not exist or is not a file",
            path.display()
        )));
    }
    std::fs::canonicalize(path).map_err(|err| {
        Error::config(format!(
            "failed to resolve {description} '{}': {err}",
            path.display()
        ))
    })
}

fn docker_guest_tls_configured(docker_config: &DockerComputeConfig) -> bool {
    docker_config.guest_tls_ca.is_some()
        || docker_config.guest_tls_cert.is_some()
        || docker_config.guest_tls_key.is_some()
}

pub(crate) fn docker_guest_tls_paths(
    docker_config: &DockerComputeConfig,
) -> CoreResult<Option<DockerGuestTlsPaths>> {
    let tls_flags_provided = docker_config.guest_tls_ca.is_some()
        || docker_config.guest_tls_cert.is_some()
        || docker_config.guest_tls_key.is_some();

    if !docker_config.grpc_endpoint.starts_with("https://") {
        if tls_flags_provided {
            return Err(Error::config(format!(
                "guest_tls_ca/guest_tls_cert/guest_tls_key were provided but grpc_endpoint is '{}'; TLS materials require an https:// endpoint",
                docker_config.grpc_endpoint,
            )));
        }
        return Ok(None);
    }

    let provided = [
        docker_config.guest_tls_ca.as_ref(),
        docker_config.guest_tls_cert.as_ref(),
        docker_config.guest_tls_key.as_ref(),
    ];
    if provided.iter().all(Option::is_none) {
        return Err(Error::config(
            "docker compute driver requires guest_tls_ca, guest_tls_cert, and guest_tls_key when grpc_endpoint uses https://",
        ));
    }

    let Some(ca) = docker_config.guest_tls_ca.clone() else {
        return Err(Error::config(
            "guest_tls_ca is required when Docker sandbox TLS materials are configured",
        ));
    };
    let Some(cert) = docker_config.guest_tls_cert.clone() else {
        return Err(Error::config(
            "guest_tls_cert is required when Docker sandbox TLS materials are configured",
        ));
    };
    let Some(key) = docker_config.guest_tls_key.clone() else {
        return Err(Error::config(
            "guest_tls_key is required when Docker sandbox TLS materials are configured",
        ));
    };

    Ok(Some(DockerGuestTlsPaths {
        ca: canonicalize_existing_file(&ca, "docker TLS CA certificate")?,
        cert: canonicalize_existing_file(&cert, "docker TLS client certificate")?,
        key: canonicalize_existing_file(&key, "docker TLS client private key")?,
    }))
}

fn is_not_found_error(err: &BollardError) -> bool {
    matches!(
        err,
        BollardError::DockerResponseServerError {
            status_code: 404,
            ..
        }
    )
}

fn is_conflict_error(err: &BollardError) -> bool {
    matches!(
        err,
        BollardError::DockerResponseServerError {
            status_code: 409,
            ..
        }
    )
}

fn is_not_modified_error(err: &BollardError) -> bool {
    matches!(
        err,
        BollardError::DockerResponseServerError {
            status_code: 304,
            ..
        }
    )
}

fn create_status_from_docker_error(operation: &str, err: BollardError) -> Status {
    if matches!(
        err,
        BollardError::DockerResponseServerError {
            status_code: 409,
            ..
        }
    ) {
        Status::already_exists("sandbox already exists")
    } else {
        internal_status(operation, err)
    }
}

fn internal_status(operation: &str, err: BollardError) -> Status {
    Status::internal(format!("{operation} failed: {err}"))
}

#[cfg(test)]
mod tests;
pub const DEFAULT_DOCKER_NETWORK_NAME: &str = "openshell-docker";
