// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Docker compute driver.

#![allow(clippy::result_large_err)]

mod isolation;
pub mod otel_tracing;

use bollard::Docker;
use bollard::errors::Error as BollardError;
use bollard::models::{
    ContainerCreateBody, ContainerState, ContainerStateStatusEnum, ContainerSummary,
    ContainerSummaryStateEnum, CreateImageInfo, DeviceRequest, HealthConfig, HealthStatusEnum,
    HostConfig, Mount, MountTmpfsOptions, MountTypeEnum, MountVolumeOptions, NetworkCreateRequest,
    ProgressDetail, SystemInfo, VolumeCreateRequest,
};
use bollard::query_parameters::{
    CreateContainerOptionsBuilder, CreateImageOptions, DownloadFromContainerOptionsBuilder,
    ListContainersOptionsBuilder, ListVolumesOptionsBuilder, LogsOptionsBuilder,
    RemoveContainerOptionsBuilder, StopContainerOptionsBuilder, UploadToContainerOptionsBuilder,
};
use bytes::Bytes;
use futures::{Stream, StreamExt};
use openshell_core::config::{DEFAULT_SANDBOX_PIDS_LIMIT, DEFAULT_STOP_TIMEOUT_SECS};
use openshell_core::driver_mounts;
use openshell_core::driver_utils::{
    CONDITION_EXITED, CONDITION_RUNTIME_RESTART, LABEL_MANAGED_BY, LABEL_MANAGED_BY_VALUE,
    LABEL_SANDBOX_ID, LABEL_SANDBOX_NAME, LABEL_SANDBOX_NAMESPACE, LABEL_SANDBOX_WORKSPACE,
    SUPERVISOR_IMAGE_BINARY_PATH, extract_first_tar_entry, supervisor_image_should_refresh,
    temp_extract_container_name,
};
use openshell_core::gpu::{
    CdiGpuDefaultSelector, CdiGpuInventory, CdiGpuSelectionError, driver_gpu_requirements,
    effective_driver_gpu_count, validate_specific_gpu_device_request,
};
use openshell_core::progress::{
    PROGRESS_STEP_PULLING_IMAGE, PROGRESS_STEP_REQUESTING_SANDBOX, PROGRESS_STEP_STARTING_SANDBOX,
    format_bytes, mark_progress_active, mark_progress_complete, mark_progress_detail,
};
use openshell_core::proto::compute::v1::{
    CreateSandboxRequest, CreateSandboxResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    DeleteWorkspaceRequest, DeleteWorkspaceResponse, DriverCondition, DriverPlatformEvent,
    DriverSandbox, DriverSandboxStatus, DriverSandboxTemplate, EnsureWorkspaceRequest,
    EnsureWorkspaceResponse, GatewayListenerRequirement, GetCapabilitiesRequest,
    GetCapabilitiesResponse, GetGatewayListenerRequirementsRequest,
    GetGatewayListenerRequirementsResponse, GetSandboxRequest, GetSandboxResponse,
    GpuResourceRequirements, ListSandboxesRequest, ListSandboxesResponse, StartSandboxRequest,
    StartSandboxResponse, StopSandboxRequest, StopSandboxResponse, ValidateSandboxCreateRequest,
    ValidateSandboxCreateResponse, WatchSandboxesDeletedEvent, WatchSandboxesEvent,
    WatchSandboxesPlatformEvent, WatchSandboxesRequest, WatchSandboxesSandboxEvent,
    compute_driver_server::ComputeDriver, gateway_listener_requirement::Selector,
    watch_sandboxes_event,
};
use openshell_core::proto_struct::{
    deserialize_optional_non_empty_string_list, struct_to_json_value,
};
use openshell_core::{Error, Result as CoreResult};
use openshell_isolation_interface::boundary_protocol::{
    BoundaryClientTls, BoundaryServerTls, BoundaryTopology, generate_boundary_mutual_tls_material,
};
use openshell_isolation_interface::contract::ResolvedWorkloadIdentity;
use opentelemetry::trace::TraceContextExt as _;
use sha2::{Digest as _, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(unix)]
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{Instrument as _, debug, info, warn};
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use url::Url;

const WATCH_BUFFER: usize = 128;
const WATCH_POLL_INTERVAL: Duration = Duration::from_secs(2);
const WATCH_POLL_MAX_BACKOFF: Duration = Duration::from_secs(30);
const SUPERVISOR_READY_TIMEOUT: Duration = Duration::from_secs(90);
const SUPERVISOR_HEALTH_INTERVAL_NS: i64 = 250_000_000;
const SUPERVISOR_HEALTH_TIMEOUT_NS: i64 = 2_000_000_000;
const SUPERVISOR_HEALTH_START_PERIOD_NS: i64 = 60_000_000_000;

const SANDBOX_BINARY_PATH: &str = "/.openshell/runtime/openshell-sandbox";
const SUPERVISOR_IMAGE_CONTROL_BINARY_PATH: &str = "/openshell-supervisor";
const SUPERVISOR_HEALTH_SOCKET_PATH: &str = "/run/openshell/health.sock";
const SUPERVISOR_UID: u32 = 65_534;
const SUPERVISOR_GID: u32 = 65_534;
const BOUNDARY_MOUNT_PATH: &str = "/.openshell/channel";
const BOUNDARY_CONFIG_MOUNT_PATH: &str = "/.openshell/channel/sandbox/bootstrap.json";
const BOUNDARY_SOCKET_MOUNT_PATH: &str = "/.openshell/channel/sandbox/control.sock";
const BOUNDARY_CERTIFICATE_MOUNT_PATH: &str = "/.openshell/channel/sandbox/server.crt";
const BOUNDARY_PRIVATE_KEY_MOUNT_PATH: &str = "/.openshell/channel/sandbox/server.key";
const BOUNDARY_CLIENT_CA_MOUNT_PATH: &str = "/.openshell/channel/sandbox/client-ca.crt";
const SUPERVISOR_STATE_MOUNT_PATH: &str = "/.openshell/channel/supervisor";
const DRIVER_ADMITTED_BACKEND: &str = "docker";
const LABEL_ISOLATION_TOPOLOGY: &str = "openshell.ai/isolation-topology";
const LABEL_ISOLATION_TOPOLOGY_CAPABILITY_FREE: &str = "capability-free";
const LABEL_ISOLATION_ROLE: &str = "openshell.ai/isolation-role";
const LABEL_ISOLATION_ROLE_SANDBOX: &str = "sandbox";
const LABEL_ISOLATION_ROLE_SUPERVISOR: &str = "supervisor";
const LABEL_ISOLATION_ROLE_STAGING: &str = "staging";
const LABEL_ISOLATION_ROLE_IDENTITY: &str = "identity";
const TOPOLOGY_PAYLOAD_FILE: &str = "topology.payload";
const MAIN_PROCESS_SPEC_FILE: &str = "main-process.json";
const WORKSPACE_ROOT_FILE: &str = "workspace-root";
const BOUNDARY_CONFIG_FILE: &str = "boundary-bootstrap.json";
const BOUNDARY_CERTIFICATE_FILE: &str = "boundary-server.crt";
const BOUNDARY_PRIVATE_KEY_FILE: &str = "boundary-server.key";
const BOUNDARY_CLIENT_CA_FILE: &str = "boundary-client-ca.crt";
const HOST_OPENSHELL_INTERNAL: &str = "host.openshell.internal";
const HOST_DOCKER_INTERNAL: &str = "host.docker.internal";
const DOCKER_NETWORK_DRIVER: &str = "bridge";

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
    pub image_pull_policy: String,

    /// Namespace label applied to Docker sandboxes.
    pub sandbox_namespace: String,

    /// Gateway gRPC endpoint the sandbox connects back to.
    pub grpc_endpoint: String,

    /// Image containing the trusted `openshell-sandbox` and
    /// `openshell-supervisor` binaries.
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

    /// Container cgroup PID limit for Docker-managed sandboxes.
    ///
    /// Set to `0` to leave Docker's runtime/default PID limit unchanged.
    pub sandbox_pids_limit: i64,

    /// Allow sandbox requests to attach host bind mounts through
    /// `template.driver_config`.
    #[serde(default)]
    pub enable_bind_mounts: bool,
}

impl Default for DockerComputeConfig {
    fn default() -> Self {
        Self {
            socket_path: None,
            default_image: openshell_core::image::default_sandbox_image(),
            image_pull_policy: String::new(),
            sandbox_namespace: "default".to_string(),
            grpc_endpoint: String::new(),
            supervisor_image: None,
            guest_tls_ca: None,
            guest_tls_cert: None,
            guest_tls_key: None,
            network_name: DEFAULT_DOCKER_NETWORK_NAME.to_string(),
            host_gateway_ip: String::new(),
            sandbox_pids_limit: DEFAULT_SANDBOX_PIDS_LIMIT,
            enable_bind_mounts: false,
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
    image_pull_policy: String,
    sandbox_namespace: String,
    gateway_route: DockerGatewayRoute,
    gateway_callback_bind_address: Option<SocketAddr>,
    stop_timeout_secs: u32,
    log_level: String,
    sandbox_binary: Arc<Vec<u8>>,
    supervisor_image_id: String,
    network_name: String,
    supervisor_grpc_endpoint: String,
    gateway_tls_server_name: Option<String>,
    guest_tls: Option<DockerGuestTlsPaths>,
    daemon_version: String,
    supports_gpu: bool,
    allow_all_default_gpu: bool,
    sandbox_pids_limit: i64,
    enable_bind_mounts: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DockerGatewayRoute {
    Bridge { bind_address: SocketAddr },
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
    control_processes: Arc<Mutex<HashMap<String, DockerControlProcess>>>,
    runtime_failures: Arc<Mutex<HashMap<String, DockerRuntimeFailure>>>,
}

struct DockerControlProcess {
    shutdown: Option<oneshot::Sender<()>>,
    intentional_shutdown: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

#[derive(Clone)]
struct DockerRuntimeFailure {
    reason: &'static str,
    message: String,
}

#[derive(Clone)]
struct DockerRuntimeFailureContext {
    docker: Arc<Docker>,
    events: broadcast::Sender<WatchSandboxesEvent>,
    failures: Arc<Mutex<HashMap<String, DockerRuntimeFailure>>>,
    sandbox: DriverSandbox,
    sandbox_namespace: String,
    container_id: String,
    stop_timeout_secs: u32,
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

    fn remove(&self, sandbox_id: &str) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.previous_finished_at.remove(sandbox_id);
        state.starts_in_progress.remove(sandbox_id);
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct DockerPasswdEntry {
    name: String,
    uid: u32,
    gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DockerGroupEntry {
    name: String,
    gid: u32,
    members: Vec<String>,
}

fn parse_docker_passwd(bytes: &[u8]) -> Result<Vec<DockerPasswdEntry>, Status> {
    let contents = std::str::from_utf8(bytes).map_err(|error| {
        Status::failed_precondition(format!("image /etc/passwd is not UTF-8: {error}"))
    })?;
    let mut entries = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() < 4 || fields[0].is_empty() {
            return Err(Status::failed_precondition(format!(
                "image /etc/passwd line {} is malformed",
                index + 1
            )));
        }
        let uid = fields[2].parse::<u32>().map_err(|_| {
            Status::failed_precondition(format!(
                "image /etc/passwd line {} has an invalid UID",
                index + 1
            ))
        })?;
        let gid = fields[3].parse::<u32>().map_err(|_| {
            Status::failed_precondition(format!(
                "image /etc/passwd line {} has an invalid GID",
                index + 1
            ))
        })?;
        entries.push(DockerPasswdEntry {
            name: fields[0].to_string(),
            uid,
            gid,
        });
    }
    Ok(entries)
}

fn parse_docker_group(bytes: &[u8]) -> Result<Vec<DockerGroupEntry>, Status> {
    let contents = std::str::from_utf8(bytes).map_err(|error| {
        Status::failed_precondition(format!("image /etc/group is not UTF-8: {error}"))
    })?;
    let mut entries = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() < 4 || fields[0].is_empty() {
            return Err(Status::failed_precondition(format!(
                "image /etc/group line {} is malformed",
                index + 1
            )));
        }
        let gid = fields[2].parse::<u32>().map_err(|_| {
            Status::failed_precondition(format!(
                "image /etc/group line {} has an invalid GID",
                index + 1
            ))
        })?;
        entries.push(DockerGroupEntry {
            name: fields[0].to_string(),
            gid,
            members: fields[3]
                .split(',')
                .filter(|member| !member.is_empty())
                .map(str::to_string)
                .collect(),
        });
    }
    Ok(entries)
}

fn resolve_numeric_or_named_user<'a>(
    selector: &str,
    passwd: &'a [DockerPasswdEntry],
) -> Result<(u32, Option<&'a DockerPasswdEntry>), Status> {
    if let Ok(uid) = selector.parse::<u32>() {
        return Ok((uid, passwd.iter().find(|entry| entry.uid == uid)));
    }
    let entry = passwd
        .iter()
        .find(|entry| entry.name == selector)
        .ok_or_else(|| {
            Status::failed_precondition(format!(
                "workload user '{selector}' does not exist in the pinned image"
            ))
        })?;
    Ok((entry.uid, Some(entry)))
}

fn resolve_numeric_or_named_group(
    selector: &str,
    groups: &[DockerGroupEntry],
) -> Result<u32, Status> {
    if let Ok(gid) = selector.parse::<u32>() {
        return Ok(gid);
    }
    groups
        .iter()
        .find(|entry| entry.name == selector)
        .map(|entry| entry.gid)
        .ok_or_else(|| {
            Status::failed_precondition(format!(
                "workload group '{selector}' does not exist in the pinned image"
            ))
        })
}

fn resolve_docker_identity_from_accounts(
    sandbox: &DriverSandbox,
    image: &DockerImageMetadata,
    passwd_bytes: &[u8],
    group_bytes: &[u8],
) -> Result<ResolvedWorkloadIdentity, Status> {
    let passwd = parse_docker_passwd(passwd_bytes)?;
    let groups = parse_docker_group(group_bytes)?;
    let request = sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.workload_identity.as_ref());
    let requested_user = request.map_or("", |request| request.user.trim());
    let requested_group = request.map_or("", |request| request.group.trim());
    let (image_user, image_group) = image.user.split_once(':').unwrap_or((&image.user, ""));
    let user_selector = if requested_user.is_empty() {
        image_user.trim()
    } else {
        requested_user
    };
    if user_selector.is_empty() {
        return Err(Status::failed_precondition(
            "the pinned image defaults to root; configure a non-root process.run_as_user",
        ));
    }
    let (uid, passwd_entry) = resolve_numeric_or_named_user(user_selector, &passwd)?;
    let username = passwd_entry.map(|entry| entry.name.as_str());
    let group_selector = if requested_group.is_empty() {
        image_group.trim()
    } else {
        requested_group
    };
    let gid = if group_selector.is_empty() {
        passwd_entry.map(|entry| entry.gid).ok_or_else(|| {
            Status::failed_precondition(format!(
                "numeric workload UID {uid} has no passwd entry; configure process.run_as_group"
            ))
        })?
    } else {
        resolve_numeric_or_named_group(group_selector, &groups)?
    };
    let supplementary_gids = username.map_or_else(Vec::new, |username| {
        groups
            .iter()
            .filter(|entry| {
                entry.gid != gid && entry.members.iter().any(|member| member == username)
            })
            .map(|entry| entry.gid)
            .collect()
    });
    let source = if !requested_user.is_empty() || !requested_group.is_empty() {
        "policy"
    } else {
        "image"
    };
    ResolvedWorkloadIdentity::new(
        uid,
        gid,
        supplementary_gids,
        source.to_string(),
        image.id.clone(),
    )
    .map_err(|error| Status::failed_precondition(error.to_string()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct DockerResourceLimits {
    nano_cpus: Option<i64>,
    memory_bytes: Option<i64>,
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
    ) -> CoreResult<Self> {
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
        let supports_gpu = info
            .cdi_spec_dirs
            .as_ref()
            .is_some_and(|dirs| !dirs.is_empty());
        let cdi_gpu_inventory = docker_cdi_gpu_inventory(&info);
        let allow_all_default_gpu = docker_info_reports_wsl2(&info);
        validate_sandbox_pids_limit(docker_config.sandbox_pids_limit)?;
        let gateway_port = gateway_bind_address.port();
        if gateway_port == 0 {
            return Err(Error::config(
                "docker compute driver requires a fixed non-zero gateway bind port",
            ));
        }
        let network_name = docker_network_name(docker_config);
        let bridge_gateway_ip = ensure_bridge_network(&docker, &network_name).await?;
        let host_gateway_ip = parse_optional_host_gateway_ip(&docker_config.host_gateway_ip)?;
        let gateway_route =
            docker_gateway_route(&info, bridge_gateway_ip, gateway_port, host_gateway_ip);
        let gateway_callback_bind_address =
            docker_gateway_callback_bind_address(&gateway_route, gateway_bind_address);
        let mut docker_config = docker_config.clone();
        if docker_config.grpc_endpoint.trim().is_empty() {
            let scheme = if docker_guest_tls_configured(&docker_config) {
                "https"
            } else {
                "http"
            };
            docker_config.grpc_endpoint =
                format!("{scheme}://{HOST_OPENSHELL_INTERNAL}:{gateway_port}");
        }
        let host_grpc_endpoint =
            docker_host_openshell_endpoint(&docker_config.grpc_endpoint, &gateway_route)?;
        let original_gateway_url = Url::parse(&docker_config.grpc_endpoint).map_err(|error| {
            Error::config(format!(
                "invalid docker grpc_endpoint '{}': {error}",
                docker_config.grpc_endpoint
            ))
        })?;
        let host_gateway_url = Url::parse(&host_grpc_endpoint).map_err(|error| {
            Error::config(format!(
                "invalid normalized Docker host grpc_endpoint '{host_grpc_endpoint}': {error}"
            ))
        })?;
        let gateway_tls_server_name = (original_gateway_url.scheme() == "https"
            && original_gateway_url.host_str() != host_gateway_url.host_str())
        .then(|| {
            original_gateway_url
                .host_str()
                .unwrap_or_default()
                .to_string()
        });
        let supervisor_grpc_endpoint = match &gateway_route {
            DockerGatewayRoute::Bridge { .. } => host_grpc_endpoint,
            DockerGatewayRoute::HostGateway => docker_config.grpc_endpoint.clone(),
        };
        let supervisor_image = docker_config
            .supervisor_image
            .clone()
            .unwrap_or_else(openshell_core::config::default_supervisor_image);
        let supervisor_image_id =
            ensure_supervisor_container_image(&docker, &supervisor_image).await?;
        let sandbox_binary = Arc::new(
            extract_supervisor_binary_bytes(&docker, &supervisor_image_id)
                .await
                .map_err(|error| {
                    Error::config(format!(
                        "failed to load trusted sandbox binary from Docker image '{supervisor_image}': {error}"
                    ))
                })?,
        );
        let guest_tls = docker_guest_tls_paths(&docker_config)?;
        let driver = Self {
            docker: Arc::new(docker),
            config: DockerDriverRuntimeConfig {
                default_image: docker_config.default_image.clone(),
                image_pull_policy: docker_config.image_pull_policy.clone(),
                sandbox_namespace: docker_config.sandbox_namespace.clone(),
                gateway_route,
                gateway_callback_bind_address,
                stop_timeout_secs: DEFAULT_STOP_TIMEOUT_SECS,
                log_level: gateway_log_level.to_string(),
                sandbox_binary,
                supervisor_image_id,
                network_name,
                supervisor_grpc_endpoint,
                gateway_tls_server_name,
                guest_tls,
                daemon_version: version.version.unwrap_or_else(|| "unknown".to_string()),
                supports_gpu,
                allow_all_default_gpu,
                sandbox_pids_limit: docker_config.sandbox_pids_limit,
                enable_bind_mounts: docker_config.enable_bind_mounts,
            },
            events: broadcast::channel(WATCH_BUFFER).0,
            pending: Arc::new(Mutex::new(HashMap::new())),
            gpu_selector: Arc::new(CdiGpuDefaultSelector::new(
                cdi_gpu_inventory,
                allow_all_default_gpu,
            )),
            lifecycle_event_fences: DockerLifecycleEventFences::default(),
            control_processes: Arc::new(Mutex::new(HashMap::new())),
            runtime_failures: Arc::new(Mutex::new(HashMap::new())),
        };

        Box::pin(driver.reconcile_runtime_resources_at_startup())
            .await
            .map_err(|error| {
                Error::config(format!(
                    "failed to reconcile Docker isolation resources: {}",
                    error.message()
                ))
            })?;

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
        Self::validate_gpu_request(gpu_requirements, config.supports_gpu, &driver_config)?;
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
            self.config.allow_all_default_gpu,
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

    async fn resolve_docker_workload_identity(
        &self,
        sandbox: &DriverSandbox,
        image: &DockerImageMetadata,
    ) -> Result<ResolvedWorkloadIdentity, Status> {
        let container_name = format!("{}-identity", temp_extract_container_name());
        self.docker
            .create_container(
                Some(
                    CreateContainerOptionsBuilder::default()
                        .name(container_name.as_str())
                        .build(),
                ),
                ContainerCreateBody {
                    image: Some(image.id.clone()),
                    labels: Some(docker_auxiliary_container_labels(
                        sandbox,
                        &self.config,
                        LABEL_ISOLATION_ROLE_IDENTITY,
                    )),
                    ..Default::default()
                },
            )
            .await
            .map_err(|error| {
                Status::failed_precondition(format!(
                    "create Docker identity resolver container: {error}"
                ))
            })?;

        let result = async {
            let passwd =
                download_path_from_container(&self.docker, &container_name, "/etc/passwd", true)
                    .await
                    .map_err(|error| {
                        Status::failed_precondition(format!(
                            "read immutable image /etc/passwd for workload identity: {error}"
                        ))
                    })?;
            let group =
                download_path_from_container(&self.docker, &container_name, "/etc/group", true)
                    .await
                    .map_err(|error| {
                        Status::failed_precondition(format!(
                            "read immutable image /etc/group for workload identity: {error}"
                        ))
                    })?;
            resolve_docker_identity_from_accounts(sandbox, image, &passwd, &group)
        }
        .await;

        if let Err(error) = self
            .docker
            .remove_container(
                &container_name,
                Some(RemoveContainerOptionsBuilder::default().force(true).build()),
            )
            .await
        {
            warn!(
                container = container_name,
                %error,
                "Failed to remove Docker identity resolver container"
            );
        }
        result
    }

    async fn get_sandbox_snapshot(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<Option<DriverSandbox>, Status> {
        if let Some(pending) = self.pending_snapshot(sandbox_id, sandbox_name).await {
            return Ok(Some(pending));
        }
        let container = self
            .find_managed_container_summary(sandbox_id, sandbox_name)
            .await?;
        if let Some(mut sandbox) =
            container.and_then(|summary| sandbox_from_container_summary(&summary))
        {
            self.apply_runtime_failure(&mut sandbox).await;
            return Ok(Some(sandbox));
        }

        Ok(None)
    }

    async fn current_snapshots(&self) -> Result<Vec<DriverSandbox>, Status> {
        let containers = self.list_managed_container_summaries().await?;
        let mut container_sandboxes = Vec::with_capacity(containers.len());
        for summary in &containers {
            let Some(mut sandbox) = sandbox_from_container_summary(summary) else {
                continue;
            };
            if let Some(container_id) = summary.id.as_deref() {
                match self.docker.inspect_container(container_id, None).await {
                    Ok(inspected) if summary.state == Some(ContainerSummaryStateEnum::EXITED) => {
                        // Docker's list summary carries no exit code. Inspect
                        // exited containers so daemon-restart kills remain
                        // distinguishable from terminal application exits.
                        if let Some(state) = inspected.state.as_ref() {
                            apply_docker_exit_classification(&mut sandbox, state);
                        }
                    }
                    Ok(inspected) if summary.state == Some(ContainerSummaryStateEnum::RUNNING) => {
                        if let Err(status) = validate_docker_outer_fence(&inspected) {
                            let context = self
                                .control_failure_context(sandbox.clone(), container_id.to_string());
                            handle_docker_runtime_failure(
                                context,
                                "OuterFenceViolation",
                                status.message().to_string(),
                            )
                            .await;
                        }
                    }
                    Ok(_) => {}
                    Err(err) => {
                        debug!(
                            container_id,
                            error = %err,
                            "Could not inspect Docker sandbox container during reconciliation"
                        );
                    }
                }
            }
            self.apply_runtime_failure(&mut sandbox).await;
            container_sandboxes.push(sandbox);
        }
        let mut by_id = container_sandboxes
            .into_iter()
            .map(|sandbox| (sandbox.id.clone(), sandbox))
            .collect::<HashMap<_, _>>();
        // Provisioning state is authoritative until the supervisor has
        // attached to both the sandbox and gateway. A running workload
        // container alone is not a usable sandbox.
        by_id.extend(self.pending_snapshot_map().await);
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
            &self.config.sandbox_namespace,
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
                Box::pin(driver.provision_sandbox(sandbox_for_task)).await;
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
        match Box::pin(self.provision_sandbox_inner(&sandbox)).await {
            Ok(()) => {
                self.clear_pending_sandbox(&sandbox.id).await;
                if let Err(error) = self
                    .publish_container_snapshot(&sandbox.id, &sandbox.name)
                    .await
                {
                    warn!(
                        sandbox_id = %sandbox.id,
                        %error,
                        "Failed to publish Docker sandbox snapshot after provisioning"
                    );
                }
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
        let workload_identity = self
            .resolve_docker_workload_identity(sandbox, &image)
            .await
            .map_err(|status| {
                DockerProvisioningFailure::new("IdentityResolutionFailed", status.message())
            })?;
        prepare_docker_boundary_state_dir(sandbox, &self.config).map_err(|status| {
            DockerProvisioningFailure::new("BoundaryStateCreateFailed", status.message())
        })?;
        create_docker_channel_volume(&self.docker, sandbox, &self.config)
            .await
            .map_err(|status| {
                cleanup_docker_boundary_state(sandbox, &self.config);
                DockerProvisioningFailure::new("BoundaryChannelCreateFailed", status.message())
            })?;
        let token_file_created = match write_sandbox_token_file(sandbox, &self.config).await {
            Ok(created) => created,
            Err(status) => {
                let _ = remove_docker_channel_volume_by_id(&self.docker, &sandbox.id, &self.config)
                    .await;
                cleanup_docker_boundary_state(sandbox, &self.config);
                return Err(DockerProvisioningFailure::new(
                    "SandboxTokenWriteFailed",
                    status.message(),
                ));
            }
        };
        if !token_file_created {
            let _ =
                remove_docker_channel_volume_by_id(&self.docker, &sandbox.id, &self.config).await;
            cleanup_docker_boundary_state(sandbox, &self.config);
            return Err(DockerProvisioningFailure::new(
                "SandboxTokenWriteFailed",
                "Docker control mode requires a gateway sandbox token",
            ));
        }

        let container_name = container_name_for_sandbox(sandbox);
        let gpu_devices = match self
            .resolve_gpu_cdi_devices(
                validated.gpu_requirements,
                &validated.driver_config,
                CdiGpuDefaultSelector::next_device_ids,
            )
            .await
        {
            Ok(devices) => devices,
            Err(status) => {
                let _ = remove_docker_channel_volume_by_id(&self.docker, &sandbox.id, &self.config)
                    .await;
                cleanup_docker_boundary_state(sandbox, &self.config);
                return Err(DockerProvisioningFailure::new(
                    "ContainerCreateFailed",
                    status.message(),
                ));
            }
        };
        let create_body = match build_container_create_body_for_image(
            sandbox,
            &self.config,
            &validated.driver_config,
            gpu_devices.as_deref(),
            &image,
            &workload_identity,
        ) {
            Ok(body) => body,
            Err(status) => {
                let _ = remove_docker_channel_volume_by_id(&self.docker, &sandbox.id, &self.config)
                    .await;
                cleanup_docker_boundary_state(sandbox, &self.config);
                return Err(DockerProvisioningFailure::new(
                    "ContainerCreateFailed",
                    status.message(),
                ));
            }
        };
        let create_result = async {
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
                    .await,
            )
        }
        .instrument(tracing::info_span!(
            "docker.create_container",
            otel.name = "docker.create_container",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %sandbox.id,
            container.name = %container_name,
        ))
        .await;
        let created = match create_result {
            Ok(created) => created,
            Err(error) => {
                let _ = remove_docker_channel_volume_by_id(&self.docker, &sandbox.id, &self.config)
                    .await;
                cleanup_docker_boundary_state(sandbox, &self.config);
                return Err(DockerProvisioningFailure::from_status(
                    "ContainerCreateFailed",
                    create_status_from_docker_error("create docker sandbox container", error),
                ));
            }
        };
        let inspected = match self.docker.inspect_container(&created.id, None).await {
            Ok(inspected) => inspected,
            Err(error) => {
                let _ = self
                    .docker
                    .remove_container(
                        &created.id,
                        Some(RemoveContainerOptionsBuilder::default().force(true).build()),
                    )
                    .await;
                let _ = remove_docker_channel_volume_by_id(&self.docker, &sandbox.id, &self.config)
                    .await;
                cleanup_docker_boundary_state(sandbox, &self.config);
                return Err(DockerProvisioningFailure::from_status(
                    "OuterFenceInspectFailed",
                    internal_status("inspect Docker sandbox outer fence", error),
                ));
            }
        };
        let outer_fence_error = validate_docker_outer_fence(&inspected).err();
        drop(inspected);
        if let Some(status) = outer_fence_error {
            let _ = self
                .docker
                .remove_container(
                    &created.id,
                    Some(RemoveContainerOptionsBuilder::default().force(true).build()),
                )
                .await;
            let _ =
                remove_docker_channel_volume_by_id(&self.docker, &sandbox.id, &self.config).await;
            cleanup_docker_boundary_state(sandbox, &self.config);
            return Err(DockerProvisioningFailure::from_status(
                "OuterFenceRejected",
                status,
            ));
        }
        self.publish_docker_progress(
            &sandbox.id,
            "Created",
            format!("Created Docker container \"{container_name}\""),
            HashMap::from([("container_name".to_string(), container_name.clone())]),
        );

        let topology = match prepare_docker_boundary_files(
            &self.docker,
            sandbox,
            &self.config,
            &created.id,
            &image,
            &workload_identity,
        )
        .await
        {
            Ok(topology) => topology,
            Err(status) => {
                let _ = self
                    .docker
                    .remove_container(
                        &container_name,
                        Some(RemoveContainerOptionsBuilder::default().force(true).build()),
                    )
                    .await;
                let _ = remove_docker_channel_volume_by_id(&self.docker, &sandbox.id, &self.config)
                    .await;
                cleanup_docker_boundary_state(sandbox, &self.config);
                return Err(DockerProvisioningFailure::new(
                    "BoundaryConfigWriteFailed",
                    status.message(),
                ));
            }
        };

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
            cleanup_docker_boundary_state(sandbox, &self.config);
            let _ =
                remove_docker_channel_volume_by_id(&self.docker, &sandbox.id, &self.config).await;
            return Err(DockerProvisioningFailure::from_status(
                "ContainerStartFailed",
                create_status_from_docker_error("start docker sandbox container", err),
            ));
        }
        self.clear_runtime_failure(&sandbox.id).await;
        let failure_context = self.control_failure_context(sandbox.clone(), created.id.clone());
        let control = match spawn_docker_control_process(
            &self.docker,
            sandbox,
            &self.config,
            &topology,
            failure_context,
        )
        .await
        {
            Ok(control) => control,
            Err(status) => {
                let _ = self
                    .docker
                    .remove_container(
                        &container_name,
                        Some(RemoveContainerOptionsBuilder::default().force(true).build()),
                    )
                    .await;
                let _ = remove_docker_channel_volume_by_id(&self.docker, &sandbox.id, &self.config)
                    .await;
                cleanup_docker_boundary_state(sandbox, &self.config);
                return Err(DockerProvisioningFailure::new(
                    "ControlSupervisorStartFailed",
                    status.message(),
                ));
            }
        };
        self.replace_control_process(&sandbox.id, control).await;
        self.publish_docker_progress(
            &sandbox.id,
            "Started",
            format!("Started Docker container \"{container_name}\""),
            HashMap::from([("container_name".to_string(), container_name)]),
        );
        span_status.finish(Ok(()))
    }

    async fn replace_control_process(&self, sandbox_id: &str, process: DockerControlProcess) {
        let previous = self
            .control_processes
            .lock()
            .await
            .insert(sandbox_id.to_string(), process);
        if let Some(previous) = previous {
            stop_docker_control_process(previous).await;
        }
    }

    async fn clear_runtime_failure(&self, sandbox_id: &str) {
        self.runtime_failures.lock().await.remove(sandbox_id);
    }

    fn control_failure_context(
        &self,
        sandbox: DriverSandbox,
        container_id: String,
    ) -> DockerRuntimeFailureContext {
        DockerRuntimeFailureContext {
            docker: self.docker.clone(),
            events: self.events.clone(),
            failures: self.runtime_failures.clone(),
            sandbox,
            sandbox_namespace: self.config.sandbox_namespace.clone(),
            container_id,
            stop_timeout_secs: self.config.stop_timeout_secs,
        }
    }

    async fn apply_runtime_failure(&self, sandbox: &mut DriverSandbox) {
        let container_is_running = sandbox.status.as_ref().is_some_and(|status| {
            status.conditions.iter().any(|condition| {
                condition.r#type == "Ready"
                    && condition.status == "True"
                    && condition.reason == "BackendReady"
            })
        });
        if !container_is_running {
            return;
        }
        let failure = self.runtime_failures.lock().await.get(&sandbox.id).cloned();
        if let Some(failure) = failure {
            set_sandbox_ready_condition(sandbox, error_condition(failure.reason, &failure.message));
        }
    }

    async fn stop_control_process(&self, sandbox_id: &str) {
        let process = self.control_processes.lock().await.remove(sandbox_id);
        if let Some(process) = process {
            stop_docker_control_process(process).await;
        }
    }

    async fn remove_auxiliary_containers_for_sandbox(
        &self,
        sandbox_id: &str,
    ) -> Result<bool, Status> {
        let filters = managed_resource_label_filters(
            &self.config.sandbox_namespace,
            [format!("{LABEL_SANDBOX_ID}={sandbox_id}")],
        );
        let containers = self
            .docker
            .list_containers(Some(
                ListContainersOptionsBuilder::default()
                    .all(true)
                    .filters(&filters)
                    .build(),
            ))
            .await
            .map_err(|error| internal_status("list Docker auxiliary containers", error))?;
        let mut removed = false;
        for container in containers {
            let role = container
                .labels
                .as_ref()
                .and_then(|labels| labels.get(LABEL_ISOLATION_ROLE))
                .map(String::as_str);
            if !matches!(
                role,
                Some(
                    LABEL_ISOLATION_ROLE_SUPERVISOR
                        | LABEL_ISOLATION_ROLE_STAGING
                        | LABEL_ISOLATION_ROLE_IDENTITY
                )
            ) {
                continue;
            }
            let Some(target) = summary_container_target(&container) else {
                continue;
            };
            self.docker
                .remove_container(
                    &target,
                    Some(RemoveContainerOptionsBuilder::default().force(true).build()),
                )
                .await
                .or_else(|error| {
                    if is_not_found_error(&error) || is_removal_in_progress_error(&error) {
                        Ok(())
                    } else {
                        Err(error)
                    }
                })
                .map_err(|error| internal_status("remove Docker auxiliary container", error))?;
            removed = true;
        }
        Ok(removed)
    }

    async fn reconcile_runtime_resources_at_startup(&self) -> Result<(), Status> {
        let sandboxes = self.list_managed_container_summaries().await?;
        let sandbox_ids = sandboxes
            .iter()
            .filter_map(|container| {
                container
                    .labels
                    .as_ref()
                    .and_then(|labels| labels.get(LABEL_SANDBOX_ID))
                    .cloned()
            })
            .collect::<HashSet<_>>();

        let filters = managed_resource_label_filters(&self.config.sandbox_namespace, []);
        let auxiliary = self
            .docker
            .list_containers(Some(
                ListContainersOptionsBuilder::default()
                    .all(true)
                    .filters(&filters)
                    .build(),
            ))
            .await
            .map_err(|error| internal_status("list Docker startup resources", error))?;
        for container in auxiliary {
            let role = container
                .labels
                .as_ref()
                .and_then(|labels| labels.get(LABEL_ISOLATION_ROLE))
                .map(String::as_str);
            if !matches!(
                role,
                Some(
                    LABEL_ISOLATION_ROLE_SUPERVISOR
                        | LABEL_ISOLATION_ROLE_STAGING
                        | LABEL_ISOLATION_ROLE_IDENTITY
                )
            ) {
                continue;
            }
            let Some(target) = summary_container_target(&container) else {
                continue;
            };
            self.docker
                .remove_container(
                    &target,
                    Some(RemoveContainerOptionsBuilder::default().force(true).build()),
                )
                .await
                .or_else(|error| {
                    if is_not_found_error(&error) {
                        Ok(())
                    } else {
                        Err(error)
                    }
                })
                .map_err(|error| internal_status("remove stale Docker auxiliary", error))?;
        }

        let volume_filters = label_filters([
            format!("{LABEL_MANAGED_BY}={LABEL_MANAGED_BY_VALUE}"),
            format!(
                "{LABEL_SANDBOX_NAMESPACE}={}",
                self.config.sandbox_namespace
            ),
            format!("{LABEL_ISOLATION_TOPOLOGY}={LABEL_ISOLATION_TOPOLOGY_CAPABILITY_FREE}"),
        ]);
        let volumes = self
            .docker
            .list_volumes(Some(
                ListVolumesOptionsBuilder::default()
                    .filters(&volume_filters)
                    .build(),
            ))
            .await
            .map_err(|error| internal_status("list Docker startup volumes", error))?;
        for volume in volumes.volumes.unwrap_or_default() {
            let sandbox_id = volume.labels.get(LABEL_SANDBOX_ID);
            if sandbox_id.is_some_and(|id| sandbox_ids.contains(id)) {
                continue;
            }
            self.docker
                .remove_volume(
                    &volume.name,
                    None::<bollard::query_parameters::RemoveVolumeOptions>,
                )
                .await
                .or_else(|error| {
                    if is_not_found_error(&error) {
                        Ok(())
                    } else {
                        Err(error)
                    }
                })
                .map_err(|error| internal_status("remove orphan Docker channel volume", error))?;
        }

        for sandbox in &sandboxes {
            if sandbox.state == Some(ContainerSummaryStateEnum::RUNNING)
                && let Err(error) = self.ensure_control_process_for_container(sandbox).await
            {
                warn!(
                    sandbox_id = sandbox
                        .labels
                        .as_ref()
                        .and_then(|labels| labels.get(LABEL_SANDBOX_ID))
                        .map_or("unknown", String::as_str),
                    %error,
                    "Failed to restore Docker supervisor during startup reconciliation"
                );
            }
        }
        Ok(())
    }

    async fn ensure_control_process_for_container(
        &self,
        container: &ContainerSummary,
    ) -> Result<(), Status> {
        let Some(sandbox) = sandbox_from_container_summary(container) else {
            return Err(Status::internal(
                "managed Docker container is missing sandbox identity labels",
            ));
        };
        let stale = {
            let mut processes = self.control_processes.lock().await;
            match processes.get(&sandbox.id) {
                Some(process) if !process.task.is_finished() => return Ok(()),
                Some(_) => processes.remove(&sandbox.id),
                None => None,
            }
        };
        if let Some(stale) = stale {
            stop_docker_control_process(stale).await;
        }
        let Some(topology) = read_docker_boundary_topology(&sandbox.id, &self.config).await? else {
            let container_id = summary_container_target(container)
                .ok_or_else(|| Status::internal("managed Docker container has no id or name"))?;
            let failure_context = self.control_failure_context(sandbox.clone(), container_id);
            let status = Status::failed_precondition(
                "Docker sandbox topology is missing; refusing to leave the workload running without its supervisor",
            );
            handle_docker_runtime_failure(
                failure_context,
                "ControlSupervisorExited",
                status.message().to_string(),
            )
            .await;
            return Err(status);
        };
        let container_id = summary_container_target(container)
            .ok_or_else(|| Status::internal("managed Docker container has no id or name"))?;
        self.clear_runtime_failure(&sandbox.id).await;
        let failure_context = self.control_failure_context(sandbox.clone(), container_id);
        let process = match spawn_docker_control_process(
            &self.docker,
            &sandbox,
            &self.config,
            &topology,
            failure_context.clone(),
        )
        .await
        {
            Ok(process) => process,
            Err(status) => {
                handle_docker_runtime_failure(
                    failure_context,
                    "ControlSupervisorExited",
                    format!(
                        "failed to start Docker control supervisor: {}",
                        status.message()
                    ),
                )
                .await;
                return Err(status);
            }
        };
        self.replace_control_process(&sandbox.id, process).await;
        Ok(())
    }

    async fn delete_sandbox_inner(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<bool, Status> {
        let pending = self.remove_pending_sandbox(sandbox_id, sandbox_name).await;
        if let Some(record) = pending.as_ref()
            && let Some(task) = record.task.as_ref()
        {
            task.abort();
        }
        if let Some(record) = pending.as_ref() {
            self.stop_control_process(&record.sandbox.id).await;
            self.remove_auxiliary_containers_for_sandbox(&record.sandbox.id)
                .await?;
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
                        self.clear_runtime_failure(&record.sandbox.id).await;
                        remove_docker_channel_volume_by_id(
                            &self.docker,
                            &record.sandbox.id,
                            &self.config,
                        )
                        .await?;
                        cleanup_docker_boundary_state(&record.sandbox, &self.config);
                        return Ok(true);
                    }
                    Err(err) if is_not_found_error(&err) => {
                        self.clear_runtime_failure(&record.sandbox.id).await;
                        let _ = remove_docker_channel_volume_by_id(
                            &self.docker,
                            &record.sandbox.id,
                            &self.config,
                        )
                        .await;
                        cleanup_docker_boundary_state(&record.sandbox, &self.config);
                        return Ok(true);
                    }
                    Err(err) => {
                        return Err(internal_status("delete docker sandbox container", err));
                    }
                }
            }
            if !sandbox_id.is_empty() {
                self.stop_control_process(sandbox_id).await;
                let removed = self
                    .remove_auxiliary_containers_for_sandbox(sandbox_id)
                    .await?;
                remove_docker_channel_volume_by_id(&self.docker, sandbox_id, &self.config).await?;
                cleanup_docker_boundary_state_by_id(sandbox_id, &self.config);
                self.clear_runtime_failure(sandbox_id).await;
                return Ok(removed);
            }
            return Ok(false);
        };
        let Some(target) = summary_container_target(&container) else {
            return Ok(pending.is_some());
        };
        let resolved_sandbox_id = container
            .labels
            .as_ref()
            .and_then(|labels| labels.get(LABEL_SANDBOX_ID))
            .map_or(sandbox_id, String::as_str);
        self.stop_control_process(resolved_sandbox_id).await;
        self.remove_auxiliary_containers_for_sandbox(resolved_sandbox_id)
            .await?;

        match self
            .docker
            .remove_container(
                &target,
                Some(RemoveContainerOptionsBuilder::default().force(true).build()),
            )
            .await
        {
            Ok(()) => {
                self.clear_runtime_failure(resolved_sandbox_id).await;
                remove_docker_channel_volume_by_id(&self.docker, resolved_sandbox_id, &self.config)
                    .await?;
                cleanup_docker_boundary_state_by_id(resolved_sandbox_id, &self.config);
                Ok(true)
            }
            Err(err) if is_not_found_error(&err) => {
                self.clear_runtime_failure(resolved_sandbox_id).await;
                let _ = remove_docker_channel_volume_by_id(
                    &self.docker,
                    resolved_sandbox_id,
                    &self.config,
                )
                .await;
                cleanup_docker_boundary_state_by_id(resolved_sandbox_id, &self.config);
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
            if let Some(record) = self.remove_pending_sandbox(sandbox_id, sandbox_name).await {
                self.stop_control_process(&record.sandbox.id).await;
                self.remove_auxiliary_containers_for_sandbox(&record.sandbox.id)
                    .await?;
                self.clear_runtime_failure(&record.sandbox.id).await;
                if let Some(task) = record.task {
                    task.abort();
                }
                remove_docker_channel_volume_by_id(&self.docker, &record.sandbox.id, &self.config)
                    .await?;
                cleanup_docker_boundary_state(&record.sandbox, &self.config);
                self.publish_deleted(record.sandbox.id);
                return Ok(());
            }
            return Err(Status::not_found("sandbox not found"));
        };
        let Some(target) = summary_container_target(&container) else {
            return Err(Status::not_found("sandbox container has no id or name"));
        };
        let resolved_sandbox_id = container
            .labels
            .as_ref()
            .and_then(|labels| labels.get(LABEL_SANDBOX_ID))
            .map_or(sandbox_id, String::as_str);
        self.stop_control_process(resolved_sandbox_id).await;
        self.remove_auxiliary_containers_for_sandbox(resolved_sandbox_id)
            .await?;

        let result = match self
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
        };
        if result.is_ok() {
            self.clear_runtime_failure(resolved_sandbox_id).await;
        }
        result
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
        let span_status = openshell_otel::ErrorStatusGuard::current();
        require_sandbox_identifier(sandbox_id, sandbox_name)?;
        self.lifecycle_event_fences.begin_start(sandbox_id);
        let result =
            Box::pin(self.start_sandbox_with_lifecycle_fence(sandbox_id, sandbox_name)).await;
        self.lifecycle_event_fences.finish_start(sandbox_id);
        span_status.finish(result)
    }

    async fn start_sandbox_with_lifecycle_fence(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
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
        let inspected = self
            .docker
            .inspect_container(&target, None)
            .await
            .map_err(|error| internal_status("inspect Docker sandbox outer fence", error))?;
        validate_docker_outer_fence(&inspected)?;
        let state = container.state.unwrap_or(ContainerSummaryStateEnum::EMPTY);
        let previous_finished_at = if state == ContainerSummaryStateEnum::EXITED {
            inspected
                .state
                .as_ref()
                .filter(|state| state.status == Some(ContainerStateStatusEnum::EXITED))
                .and_then(|state| state.finished_at.clone())
        } else {
            None
        };
        drop(inspected);
        if !container_state_needs_start(state) {
            self.ensure_control_process_for_container(&container)
                .await?;
            return Ok(true);
        }

        // Fence a poll that observed this stopped run but has not published it
        // yet. Use Docker's transition timestamp so a later, genuine exit from
        // the restarted container remains observable.
        self.lifecycle_event_fences
            .record_previous_exit(sandbox_id, previous_finished_at.as_deref());

        let resolved_sandbox_id = container
            .labels
            .as_ref()
            .and_then(|labels| labels.get(LABEL_SANDBOX_ID))
            .map_or(sandbox_id, String::as_str);
        let Some(topology) =
            read_docker_boundary_topology(resolved_sandbox_id, &self.config).await?
        else {
            return Err(Status::failed_precondition(
                "Docker sandbox topology is missing; refusing to start the workload without its supervisor",
            ));
        };
        let boundary_config = tokio::fs::read(
            docker_boundary_state_dir_by_id(resolved_sandbox_id, &self.config)?
                .join(BOUNDARY_CONFIG_FILE),
        )
        .await
        .map_err(|error| {
            Status::failed_precondition(format!(
                "read Docker sandbox bootstrap for restart: {error}"
            ))
        })?;
        let boundary_directory =
            docker_boundary_state_dir_by_id(resolved_sandbox_id, &self.config)?;
        let boundary_certificate =
            tokio::fs::read(boundary_directory.join(BOUNDARY_CERTIFICATE_FILE))
                .await
                .map_err(|error| {
                    Status::failed_precondition(format!(
                        "read Docker sandbox channel certificate for restart: {error}"
                    ))
                })?;
        let boundary_private_key =
            tokio::fs::read(boundary_directory.join(BOUNDARY_PRIVATE_KEY_FILE))
                .await
                .map_err(|error| {
                    Status::failed_precondition(format!(
                        "read Docker sandbox channel private key for restart: {error}"
                    ))
                })?;
        let boundary_client_ca = tokio::fs::read(boundary_directory.join(BOUNDARY_CLIENT_CA_FILE))
            .await
            .map_err(|error| {
                Status::failed_precondition(format!(
                    "read Docker sandbox channel client CA for restart: {error}"
                ))
            })?;
        let workspace_root = tokio::fs::read_to_string(
            docker_boundary_state_dir_by_id(resolved_sandbox_id, &self.config)?
                .join(WORKSPACE_ROOT_FILE),
        )
        .await
        .map_err(|error| {
            Status::failed_precondition(format!(
                "read Docker sandbox workspace for restart: {error}"
            ))
        })?;
        stage_docker_sandbox_bundle(
            &self.docker,
            &target,
            &self.config,
            &topology.workload_identity,
            &boundary_config,
            DockerSandboxTls {
                certificate: &boundary_certificate,
                private_key: &boundary_private_key,
                client_ca: &boundary_client_ca,
            },
            &workspace_root,
        )
        .await?;

        match self.docker.start_container(&target, None).await {
            Ok(()) => {}
            // Already running — race with another start path or the
            // restart policy. Treat as success.
            Err(err) if is_not_modified_error(&err) => {}
            Err(err) if is_not_found_error(&err) => return Ok(false),
            Err(err) => return Err(internal_status("start docker sandbox container", err)),
        }
        self.ensure_control_process_for_container(&container)
            .await?;
        Ok(true)
    }

    async fn reserve_pending_sandbox(&self, sandbox: &DriverSandbox) -> Result<(), Status> {
        let mut pending = self.pending.lock().await;
        if pending
            .values()
            .any(|record| record.sandbox.id == sandbox.id || record.sandbox.name == sandbox.name)
        {
            return Err(Status::already_exists("sandbox already exists"));
        }

        pending.insert(
            sandbox.id.clone(),
            PendingSandboxRecord {
                sandbox: pending_sandbox_snapshot(
                    sandbox,
                    &self.config.sandbox_namespace,
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
    ) -> Option<DriverSandbox> {
        let pending = self.pending.lock().await;
        pending
            .values()
            .find(|record| pending_sandbox_matches(&record.sandbox, sandbox_id, sandbox_name))
            .map(|record| record.sandbox.clone())
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
    ) -> Option<PendingSandboxRecord> {
        let mut pending = self.pending.lock().await;
        let id = pending.iter().find_map(|(id, record)| {
            pending_sandbox_matches(&record.sandbox, sandbox_id, sandbox_name).then(|| id.clone())
        })?;
        pending.remove(&id)
    }

    async fn fail_pending_sandbox(
        &self,
        sandbox: &DriverSandbox,
        failure: &DockerProvisioningFailure,
    ) {
        cleanup_docker_boundary_state(sandbox, &self.config);
        let snapshot = pending_sandbox_snapshot(
            sandbox,
            &self.config.sandbox_namespace,
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
        if let Some(pending) = self.pending_snapshot(sandbox_id, sandbox_name).await {
            self.publish_sandbox_snapshot(pending);
            return Ok(());
        }
        if let Some(summary) = self
            .find_managed_container_summary(sandbox_id, sandbox_name)
            .await?
            && let Some(mut sandbox) = sandbox_from_container_summary(&summary)
        {
            self.apply_runtime_failure(&mut sandbox).await;
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
        let Some(previous_finished_at) = self.lifecycle_event_fences.previous_exit(&sandbox.id)
        else {
            return false;
        };
        let Some(container_id) = sandbox
            .status
            .as_ref()
            .map(|status| status.instance_id.as_str())
            .filter(|container_id| !container_id.is_empty())
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
        let filters = managed_container_label_filters(&self.config.sandbox_namespace, []);
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
            managed_container_label_filters(&self.config.sandbox_namespace, label_filter_values);
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
            let Some(labels) = summary.labels.as_ref() else {
                return false;
            };
            let namespace_matches = labels
                .get(LABEL_SANDBOX_NAMESPACE)
                .is_some_and(|value| value == &self.config.sandbox_namespace);
            let id_matches = sandbox_id.is_empty()
                || labels
                    .get(LABEL_SANDBOX_ID)
                    .is_some_and(|value| value == sandbox_id);
            let name_matches = sandbox_name.is_empty()
                || labels
                    .get(LABEL_SANDBOX_NAME)
                    .is_some_and(|value| value == sandbox_name);
            namespace_matches && id_matches && name_matches
        }))
    }

    async fn ensure_image_available(
        &self,
        sandbox_id: &str,
        image: &str,
    ) -> Result<DockerImageMetadata, Status> {
        let policy = self.config.image_pull_policy.trim().to_ascii_lowercase();
        let inspect = match policy.as_str() {
            "" | "ifnotpresent" => {
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
            "always" => {
                self.pull_image(sandbox_id, image).await?;
                self.docker
                    .inspect_image(image)
                    .await
                    .map_err(|err| internal_status("inspect Docker image after pull", err))?
            }
            "never" => match self.docker.inspect_image(image).await {
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
                        "docker image '{image}' is not present locally and image_pull_policy=Never"
                    )));
                }
                Err(err) => return Err(internal_status("inspect Docker image", err)),
            },
            other => {
                return Err(Status::failed_precondition(format!(
                    "unsupported docker image_pull_policy '{other}'; expected Always, IfNotPresent, or Never",
                )));
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
fn validate_docker_outer_fence(
    inspected: &bollard::models::ContainerInspectResponse,
) -> Result<(), Status> {
    let network_mode = inspected
        .host_config
        .as_ref()
        .and_then(|config| config.network_mode.as_deref());
    if network_mode != Some("none") {
        return Err(Status::failed_precondition(format!(
            "Docker sandbox outer fence requires network_mode=none, got {}",
            network_mode.unwrap_or("<unset>")
        )));
    }
    let unexpected_networks = inspected
        .network_settings
        .as_ref()
        .and_then(|settings| settings.networks.as_ref())
        .into_iter()
        .flat_map(HashMap::keys)
        .filter(|network| network.as_str() != "none")
        .cloned()
        .collect::<Vec<_>>();
    if !unexpected_networks.is_empty() {
        return Err(Status::failed_precondition(format!(
            "Docker sandbox outer fence found attached networks: {}",
            unexpected_networks.join(", ")
        )));
    }
    Ok(())
}
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

    async fn start_sandbox(
        &self,
        request: Request<StartSandboxRequest>,
    ) -> Result<Response<StartSandboxResponse>, Status> {
        let request = request.into_inner();
        if !Box::pin(Self::start_sandbox(
            self,
            &request.sandbox_id,
            &request.sandbox_name,
        ))
        .await?
        {
            return Err(Status::not_found("sandbox not found"));
        }
        self.publish_container_snapshot(&request.sandbox_id, &request.sandbox_name)
            .await?;
        Ok(Response::new(StartSandboxResponse {}))
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
            ..Default::default()
        }),
        workspace: sandbox.workspace.clone(),
    }
}

fn pending_sandbox_matches(sandbox: &DriverSandbox, sandbox_id: &str, sandbox_name: &str) -> bool {
    (!sandbox_id.is_empty() && sandbox.id == sandbox_id)
        || (!sandbox_name.is_empty() && sandbox.name == sandbox_name)
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

fn set_sandbox_ready_condition(sandbox: &mut DriverSandbox, condition: DriverCondition) {
    let Some(status) = sandbox.status.as_mut() else {
        return;
    };
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

fn build_binds(_sandbox: &DriverSandbox, _config: &DockerDriverRuntimeConfig) -> Vec<String> {
    Vec::new()
}

fn docker_boundary_state_dir(
    sandbox: &DriverSandbox,
    config: &DockerDriverRuntimeConfig,
) -> Result<PathBuf, Status> {
    docker_boundary_state_dir_by_id(&sandbox.id, config)
}

fn docker_boundary_state_dir_by_id(
    sandbox_id: &str,
    config: &DockerDriverRuntimeConfig,
) -> Result<PathBuf, Status> {
    sandbox_token_host_path_by_id(sandbox_id, config).and_then(|path| {
        path.parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| Status::internal("docker boundary state path has no parent"))
    })
}

fn docker_channel_volume_name(
    sandbox: &DriverSandbox,
    config: &DockerDriverRuntimeConfig,
) -> String {
    docker_channel_volume_name_by_id(&sandbox.id, config)
}

fn docker_channel_volume_name_by_id(
    sandbox_id: &str,
    config: &DockerDriverRuntimeConfig,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(config.sandbox_namespace.as_bytes());
    hasher.update([0]);
    hasher.update(sandbox_id.as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    format!("openshell-channel-{}", &digest[..32])
}

async fn create_docker_channel_volume(
    docker: &Docker,
    sandbox: &DriverSandbox,
    config: &DockerDriverRuntimeConfig,
) -> Result<(), Status> {
    let name = docker_channel_volume_name(sandbox, config);
    let expected_labels = HashMap::from([
        (
            LABEL_MANAGED_BY.to_string(),
            LABEL_MANAGED_BY_VALUE.to_string(),
        ),
        (LABEL_SANDBOX_ID.to_string(), sandbox.id.clone()),
        (
            LABEL_SANDBOX_NAMESPACE.to_string(),
            config.sandbox_namespace.clone(),
        ),
        (
            LABEL_ISOLATION_TOPOLOGY.to_string(),
            LABEL_ISOLATION_TOPOLOGY_CAPABILITY_FREE.to_string(),
        ),
    ]);
    docker
        .create_volume(VolumeCreateRequest {
            name: Some(name.clone()),
            labels: Some(expected_labels.clone()),
            ..Default::default()
        })
        .await
        .map_err(|error| {
            Status::internal(format!("create Docker sandbox channel volume: {error}"))
        })?;
    let volume = docker.inspect_volume(&name).await.map_err(|error| {
        Status::internal(format!("inspect Docker sandbox channel volume: {error}"))
    })?;
    if volume.driver != "local"
        || !volume.options.is_empty()
        || expected_labels
            .iter()
            .any(|(key, value)| volume.labels.get(key) != Some(value))
    {
        return Err(Status::failed_precondition(format!(
            "Docker sandbox channel volume '{name}' already exists without the expected local-driver ownership labels"
        )));
    }
    Ok(())
}

async fn remove_docker_channel_volume_by_id(
    docker: &Docker,
    sandbox_id: &str,
    config: &DockerDriverRuntimeConfig,
) -> Result<(), Status> {
    let name = docker_channel_volume_name_by_id(sandbox_id, config);
    docker
        .remove_volume(
            &name,
            None::<bollard::query_parameters::RemoveVolumeOptions>,
        )
        .await
        .or_else(|error| {
            if is_not_found_error(&error) {
                Ok(())
            } else {
                Err(error)
            }
        })
        .map_err(|error| Status::internal(format!("remove Docker sandbox channel volume: {error}")))
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
        Some(&config.sandbox_namespace),
        sandbox_id,
    )
    .map_err(|err| {
        Status::internal(format!(
            "resolve sandbox token state directory failed: {err}"
        ))
    })
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

fn prepare_docker_boundary_state_dir(
    sandbox: &DriverSandbox,
    config: &DockerDriverRuntimeConfig,
) -> Result<PathBuf, Status> {
    let directory = docker_boundary_state_dir(sandbox, config)?;
    openshell_core::paths::create_dir_restricted(&directory).map_err(|error| {
        Status::internal(format!(
            "create Docker boundary state directory {}: {error}",
            directory.display()
        ))
    })?;
    Ok(directory)
}

async fn write_docker_boundary_file(path: &Path, contents: &[u8]) -> Result<(), Status> {
    tokio::fs::write(path, contents).await.map_err(|error| {
        Status::internal(format!(
            "write Docker boundary file {}: {error}",
            path.display()
        ))
    })?;
    openshell_core::paths::set_file_owner_only(path).map_err(|error| {
        Status::internal(format!(
            "restrict Docker boundary file {}: {error}",
            path.display()
        ))
    })
}

fn append_docker_archive_directory(
    archive: &mut tar::Builder<Vec<u8>>,
    path: &str,
    mode: u32,
    uid: u32,
    gid: u32,
) -> Result<(), Status> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_mode(mode);
    header.set_uid(u64::from(uid));
    header.set_gid(u64::from(gid));
    header.set_mtime(0);
    header.set_size(0);
    header.set_cksum();
    archive
        .append_data(&mut header, path, std::io::empty())
        .map_err(|error| Status::internal(format!("build Docker sandbox archive: {error}")))
}

fn append_docker_archive_file(
    archive: &mut tar::Builder<Vec<u8>>,
    path: &str,
    mode: u32,
    uid: u32,
    gid: u32,
    contents: &[u8],
) -> Result<(), Status> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(mode);
    header.set_uid(u64::from(uid));
    header.set_gid(u64::from(gid));
    header.set_mtime(0);
    header.set_size(contents.len() as u64);
    header.set_cksum();
    archive
        .append_data(&mut header, path, contents)
        .map_err(|error| Status::internal(format!("build Docker sandbox archive: {error}")))
}

#[derive(Clone, Copy)]
struct DockerSandboxTls<'a> {
    certificate: &'a [u8],
    private_key: &'a [u8],
    client_ca: &'a [u8],
}

fn docker_sandbox_bundle_archive(
    sandbox_binary: &[u8],
    boundary_config: &[u8],
    boundary_tls: DockerSandboxTls<'_>,
    identity: &ResolvedWorkloadIdentity,
    workspace_root: &str,
) -> Result<Vec<u8>, Status> {
    let mut archive = tar::Builder::new(Vec::new());
    append_docker_archive_directory(&mut archive, ".openshell", 0o755, 0, 0)?;
    append_docker_archive_directory(&mut archive, ".openshell/runtime", 0o555, 0, 0)?;
    append_docker_archive_directory(&mut archive, ".openshell/channel", 0o755, 0, 0)?;
    append_docker_archive_directory(
        &mut archive,
        ".openshell/channel/sandbox",
        // The sandbox owns this directory so it can consume bootstrap files
        // and create the control socket. The separate non-root supervisor
        // needs execute-only traversal to that known socket path; mutual TLS
        // authenticates the endpoint and the files beneath remain 0600.
        0o711,
        identity.uid,
        identity.gid,
    )?;
    append_docker_archive_file(
        &mut archive,
        ".openshell/runtime/openshell-sandbox",
        0o555,
        0,
        0,
        sandbox_binary,
    )?;
    append_docker_archive_file(
        &mut archive,
        ".openshell/channel/sandbox/bootstrap.json",
        0o600,
        identity.uid,
        identity.gid,
        boundary_config,
    )?;
    for (path, contents) in [
        (
            ".openshell/channel/sandbox/server.crt",
            boundary_tls.certificate,
        ),
        (
            ".openshell/channel/sandbox/server.key",
            boundary_tls.private_key,
        ),
        (
            ".openshell/channel/sandbox/client-ca.crt",
            boundary_tls.client_ca,
        ),
    ] {
        append_docker_archive_file(
            &mut archive,
            path,
            0o600,
            identity.uid,
            identity.gid,
            contents,
        )?;
    }
    if workspace_root == driver_mounts::DEFAULT_WORKSPACE_ROOT {
        // The default workspace is driver-managed. Create it before the
        // capability-free sandbox starts because that process deliberately
        // has no authority to create or chown a directory beneath `/`.
        append_docker_archive_directory(
            &mut archive,
            workspace_root.trim_start_matches('/'),
            0o700,
            identity.uid,
            identity.gid,
        )?;
    }
    archive
        .into_inner()
        .map_err(|error| Status::internal(format!("finish Docker sandbox archive: {error}")))
}

async fn stage_docker_sandbox_bundle(
    docker: &Docker,
    container_id: &str,
    config: &DockerDriverRuntimeConfig,
    identity: &ResolvedWorkloadIdentity,
    boundary_config: &[u8],
    boundary_tls: DockerSandboxTls<'_>,
    workspace_root: &str,
) -> Result<(), Status> {
    let archive = docker_sandbox_bundle_archive(
        config.sandbox_binary.as_slice(),
        boundary_config,
        boundary_tls,
        identity,
        workspace_root,
    )?;
    let options = UploadToContainerOptionsBuilder::default()
        .path("/")
        .copy_uidgid("true")
        .build();
    docker
        .upload_to_container(
            container_id,
            Some(options),
            bollard::body_full(Bytes::from(archive)),
        )
        .await
        .map_err(|error| Status::internal(format!("stage Docker sandbox bundle: {error}")))
}

async fn prepare_docker_boundary_files(
    docker: &Docker,
    sandbox: &DriverSandbox,
    config: &DockerDriverRuntimeConfig,
    container_id: &str,
    image: &DockerImageMetadata,
    workload_identity: &ResolvedWorkloadIdentity,
) -> Result<BoundaryTopology, Status> {
    let directory = docker_boundary_state_dir(sandbox, config)?;
    let workspace_root = driver_mounts::resolve_oci_workspace_root(&image.working_dir)
        .map_err(Status::failed_precondition)?;
    let bootstrap_token = random_boundary_token();
    let host_gateway_ip = Some(match config.gateway_route {
        DockerGatewayRoute::Bridge { bind_address, .. } => bind_address.ip(),
        DockerGatewayRoute::HostGateway => IpAddr::V4(Ipv4Addr::LOCALHOST),
    });
    let tls = generate_boundary_mutual_tls_material()
        .map_err(|error| Status::internal(format!("generate Docker boundary TLS: {error}")))?;
    let provisioning = isolation::DockerBoundarySpec {
        boundary_id: sandbox.id.clone(),
        bootstrap_token,
        generation: random_boundary_token(),
        session_epoch: random_boundary_token(),
        container_id: container_id.to_string(),
        image_identity: image.id.clone(),
        listener_socket: PathBuf::from(BOUNDARY_SOCKET_MOUNT_PATH),
        control_socket: PathBuf::from(BOUNDARY_SOCKET_MOUNT_PATH),
        sandbox_tls: BoundaryServerTls {
            certificate_chain_path: PathBuf::from(BOUNDARY_CERTIFICATE_MOUNT_PATH),
            private_key_path: PathBuf::from(BOUNDARY_PRIVATE_KEY_MOUNT_PATH),
            client_ca_certificate_path: PathBuf::from(BOUNDARY_CLIENT_CA_MOUNT_PATH),
        },
        supervisor_tls: BoundaryClientTls {
            server_name: tls.server_name.clone(),
            ca_certificate_pem: tls.ca_certificate_pem.clone(),
            certificate_chain_pem: tls.supervisor_certificate_pem.clone(),
            private_key_pem: tls.supervisor_private_key_pem.clone(),
        },
        host_gateway_ip,
        workload_identity: workload_identity.clone(),
        child_env: docker_child_environment(sandbox),
    }
    .provision();
    let boundary_config = provisioning
        .boundary_config
        .encode()
        .map_err(|error| Status::internal(error.to_string()))?;
    write_docker_boundary_file(&directory.join(BOUNDARY_CONFIG_FILE), &boundary_config).await?;
    write_docker_boundary_file(
        &directory.join(BOUNDARY_CERTIFICATE_FILE),
        tls.sandbox_certificate_pem.as_bytes(),
    )
    .await?;
    write_docker_boundary_file(
        &directory.join(BOUNDARY_PRIVATE_KEY_FILE),
        tls.sandbox_private_key_pem.as_bytes(),
    )
    .await?;
    write_docker_boundary_file(
        &directory.join(BOUNDARY_CLIENT_CA_FILE),
        tls.ca_certificate_pem.as_bytes(),
    )
    .await?;
    stage_docker_sandbox_bundle(
        docker,
        container_id,
        config,
        workload_identity,
        &boundary_config,
        DockerSandboxTls {
            certificate: tls.sandbox_certificate_pem.as_bytes(),
            private_key: tls.sandbox_private_key_pem.as_bytes(),
            client_ca: tls.ca_certificate_pem.as_bytes(),
        },
        &workspace_root,
    )
    .await?;
    let descriptor = provisioning
        .topology
        .descriptor(DRIVER_ADMITTED_BACKEND)
        .map_err(|error| Status::internal(error.to_string()))?;
    write_docker_boundary_file(&directory.join(TOPOLOGY_PAYLOAD_FILE), &descriptor.payload).await?;
    let main_process_spec = openshell_core::sandbox_env::MainProcessConfig::encode_driver_spec(
        sandbox.spec.as_ref(),
    )
    .map_err(|error| Status::internal(format!("encode Docker main process spec: {error}")))?;
    write_docker_boundary_file(
        &directory.join(MAIN_PROCESS_SPEC_FILE),
        main_process_spec.as_bytes(),
    )
    .await?;
    write_docker_boundary_file(
        &directory.join(WORKSPACE_ROOT_FILE),
        workspace_root.as_bytes(),
    )
    .await?;
    Ok(provisioning.topology)
}

async fn docker_supervisor_bundle_archive(
    sandbox: &DriverSandbox,
    config: &DockerDriverRuntimeConfig,
) -> Result<Vec<u8>, Status> {
    let directory = docker_boundary_state_dir(sandbox, config)?;
    let topology = tokio::fs::read(directory.join(TOPOLOGY_PAYLOAD_FILE))
        .await
        .map_err(|error| Status::internal(format!("read Docker topology payload: {error}")))?;
    let token = tokio::fs::read(sandbox_token_host_path(sandbox, config)?)
        .await
        .map_err(|error| {
            Status::failed_precondition(format!("read Docker sandbox JWT: {error}"))
        })?;
    if token.iter().all(u8::is_ascii_whitespace) {
        return Err(Status::failed_precondition(
            "Docker supervisor requires a sandbox JWT",
        ));
    }
    let mut archive = tar::Builder::new(Vec::new());
    append_docker_archive_directory(
        &mut archive,
        ".openshell/channel/supervisor",
        0o700,
        SUPERVISOR_UID,
        SUPERVISOR_GID,
    )?;
    append_docker_archive_file(
        &mut archive,
        ".openshell/channel/supervisor/topology.payload",
        0o600,
        SUPERVISOR_UID,
        SUPERVISOR_GID,
        &topology,
    )?;
    append_docker_archive_file(
        &mut archive,
        ".openshell/channel/supervisor/sandbox.jwt",
        0o600,
        SUPERVISOR_UID,
        SUPERVISOR_GID,
        &token,
    )?;
    if let Some(tls) = &config.guest_tls {
        append_docker_archive_directory(
            &mut archive,
            ".openshell/channel/supervisor/tls",
            0o700,
            SUPERVISOR_UID,
            SUPERVISOR_GID,
        )?;
        for (name, path) in [
            ("ca.pem", &tls.ca),
            ("cert.pem", &tls.cert),
            ("key.pem", &tls.key),
        ] {
            let contents = tokio::fs::read(path).await.map_err(|error| {
                Status::internal(format!(
                    "read Docker supervisor TLS file {}: {error}",
                    path.display()
                ))
            })?;
            append_docker_archive_file(
                &mut archive,
                &format!(".openshell/channel/supervisor/tls/{name}"),
                0o600,
                SUPERVISOR_UID,
                SUPERVISOR_GID,
                &contents,
            )?;
        }
    }
    archive
        .into_inner()
        .map_err(|error| Status::internal(format!("finish Docker supervisor archive: {error}")))
}

async fn read_docker_boundary_topology(
    sandbox_id: &str,
    config: &DockerDriverRuntimeConfig,
) -> Result<Option<BoundaryTopology>, Status> {
    let path = docker_boundary_state_dir_by_id(sandbox_id, config)?.join(TOPOLOGY_PAYLOAD_FILE);
    let bytes = match tokio::fs::read(&path).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(Status::internal(format!(
                "read Docker boundary topology {}: {error}",
                path.display()
            )));
        }
    };
    serde_json::from_slice(&bytes).map(Some).map_err(|error| {
        Status::internal(format!(
            "decode Docker boundary topology {}: {error}",
            path.display()
        ))
    })
}

async fn stage_docker_supervisor_bundle(
    docker: &Docker,
    sandbox: &DriverSandbox,
    config: &DockerDriverRuntimeConfig,
    archive: Vec<u8>,
) -> Result<(), Status> {
    let stager_name = format!("{}-supervisor-stage", container_name_for_sandbox(sandbox));
    let _ = docker
        .remove_container(
            &stager_name,
            Some(RemoveContainerOptionsBuilder::default().force(true).build()),
        )
        .await;
    let created = docker
        .create_container(
            Some(
                CreateContainerOptionsBuilder::default()
                    .name(stager_name.as_str())
                    .build(),
            ),
            ContainerCreateBody {
                image: Some(config.supervisor_image_id.clone()),
                entrypoint: Some(vec![SUPERVISOR_IMAGE_CONTROL_BINARY_PATH.to_string()]),
                labels: Some(docker_auxiliary_container_labels(
                    sandbox,
                    config,
                    LABEL_ISOLATION_ROLE_STAGING,
                )),
                host_config: Some(HostConfig {
                    network_mode: Some("none".to_string()),
                    mounts: Some(vec![Mount {
                        target: Some(BOUNDARY_MOUNT_PATH.to_string()),
                        source: Some(docker_channel_volume_name(sandbox, config)),
                        typ: Some(MountTypeEnum::VOLUME),
                        read_only: Some(false),
                        volume_options: Some(MountVolumeOptions {
                            no_copy: Some(true),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }]),
                    cap_drop: Some(vec!["ALL".to_string()]),
                    security_opt: Some(vec!["no-new-privileges:true".to_string()]),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .map_err(|error| {
            Status::internal(format!(
                "create Docker supervisor staging container: {error}"
            ))
        })?;
    let options = UploadToContainerOptionsBuilder::default()
        .path("/")
        .copy_uidgid("true")
        .build();
    let result = docker
        .upload_to_container(
            &created.id,
            Some(options),
            bollard::body_full(Bytes::from(archive)),
        )
        .await
        .map_err(|error| Status::internal(format!("stage Docker supervisor bundle: {error}")));
    let cleanup = docker
        .remove_container(
            &created.id,
            Some(RemoveContainerOptionsBuilder::default().force(true).build()),
        )
        .await
        .map_err(|error| {
            Status::internal(format!(
                "remove Docker supervisor staging container: {error}"
            ))
        });
    result?;
    cleanup
}

fn docker_auxiliary_container_labels(
    sandbox: &DriverSandbox,
    config: &DockerDriverRuntimeConfig,
    role: &str,
) -> HashMap<String, String> {
    HashMap::from([
        (
            LABEL_MANAGED_BY.to_string(),
            LABEL_MANAGED_BY_VALUE.to_string(),
        ),
        (LABEL_SANDBOX_ID.to_string(), sandbox.id.clone()),
        (LABEL_SANDBOX_NAME.to_string(), sandbox.name.clone()),
        (
            LABEL_SANDBOX_NAMESPACE.to_string(),
            config.sandbox_namespace.clone(),
        ),
        (LABEL_ISOLATION_ROLE.to_string(), role.to_string()),
    ])
}

async fn spawn_docker_control_process(
    docker: &Docker,
    sandbox: &DriverSandbox,
    config: &DockerDriverRuntimeConfig,
    topology: &BoundaryTopology,
    failure_context: DockerRuntimeFailureContext,
) -> Result<DockerControlProcess, Status> {
    let directory = docker_boundary_state_dir(sandbox, config)?;
    let descriptor = topology
        .descriptor(DRIVER_ADMITTED_BACKEND)
        .map_err(|error| Status::internal(error.to_string()))?;
    let main_process_spec = tokio::fs::read_to_string(directory.join(MAIN_PROCESS_SPEC_FILE))
        .await
        .map_err(|error| Status::internal(format!("read Docker main process spec: {error}")))?;
    let workspace_root = tokio::fs::read_to_string(directory.join(WORKSPACE_ROOT_FILE))
        .await
        .map_err(|error| Status::internal(format!("read Docker workspace root: {error}")))?;
    let supervisor_name = format!("{}-supervisor", container_name_for_sandbox(sandbox));
    let _ = docker
        .remove_container(
            &supervisor_name,
            Some(RemoveContainerOptionsBuilder::default().force(true).build()),
        )
        .await;
    let topology_path = format!("{SUPERVISOR_STATE_MOUNT_PATH}/topology.payload");
    let token_path = format!("{SUPERVISOR_STATE_MOUNT_PATH}/sandbox.jwt");
    let mut environment = vec![
        format!(
            "{}={DRIVER_ADMITTED_BACKEND}",
            openshell_core::sandbox_env::ADMITTED_ISOLATION_BACKEND
        ),
        format!(
            "{}={main_process_spec}",
            openshell_core::sandbox_env::MAIN_PROCESS_SPEC
        ),
        format!(
            "{}={}",
            openshell_core::sandbox_env::ENDPOINT,
            config.supervisor_grpc_endpoint
        ),
        format!("{}={}", openshell_core::sandbox_env::SANDBOX_ID, sandbox.id),
        format!("{}={}", openshell_core::sandbox_env::SANDBOX, sandbox.name),
        format!(
            "{}={token_path}",
            openshell_core::sandbox_env::SANDBOX_TOKEN_FILE
        ),
        format!(
            "{}=/run/openshell/ssh.sock",
            openshell_core::sandbox_env::SSH_SOCKET_PATH
        ),
        format!(
            "{}=/run/openshell/proxy-tls",
            openshell_core::sandbox_env::PROXY_TLS_DIR
        ),
        format!(
            "{}={}",
            openshell_core::sandbox_env::NETWORK_RUNTIME_CAPABILITIES,
            openshell_core::sandbox_env::POLICY_DNS_TRANSPARENT_TCP_CAPABILITY
        ),
        format!(
            "{}={}",
            openshell_core::sandbox_env::LOG_LEVEL,
            openshell_core::driver_utils::sandbox_log_level(sandbox, &config.log_level)
        ),
        format!(
            "{}={}",
            openshell_core::sandbox_env::TELEMETRY_ENABLED,
            openshell_core::telemetry::enabled_env_value()
        ),
    ];
    if let Some(server_name) = config.gateway_tls_server_name.as_deref() {
        environment.push(format!(
            "{}={server_name}",
            openshell_core::sandbox_env::GATEWAY_TLS_SERVER_NAME
        ));
    }
    if config.guest_tls.is_some() {
        environment.extend([
            format!(
                "{}={SUPERVISOR_STATE_MOUNT_PATH}/tls/ca.pem",
                openshell_core::sandbox_env::TLS_CA
            ),
            format!(
                "{}={SUPERVISOR_STATE_MOUNT_PATH}/tls/cert.pem",
                openshell_core::sandbox_env::TLS_CERT
            ),
            format!(
                "{}={SUPERVISOR_STATE_MOUNT_PATH}/tls/key.pem",
                openshell_core::sandbox_env::TLS_KEY
            ),
        ]);
    }
    let supervisor_archive = docker_supervisor_bundle_archive(sandbox, config).await?;
    stage_docker_supervisor_bundle(docker, sandbox, config, supervisor_archive).await?;
    let labels = HashMap::from([
        (LABEL_MANAGED_BY.to_string(), "openshell".to_string()),
        (LABEL_SANDBOX_ID.to_string(), sandbox.id.clone()),
        (LABEL_SANDBOX_NAME.to_string(), sandbox.name.clone()),
        (
            LABEL_SANDBOX_NAMESPACE.to_string(),
            config.sandbox_namespace.clone(),
        ),
        (
            LABEL_ISOLATION_ROLE.to_string(),
            LABEL_ISOLATION_ROLE_SUPERVISOR.to_string(),
        ),
    ]);
    let create = ContainerCreateBody {
        image: Some(config.supervisor_image_id.clone()),
        user: Some(format!("{SUPERVISOR_UID}:{SUPERVISOR_GID}")),
        entrypoint: Some(vec![SUPERVISOR_IMAGE_CONTROL_BINARY_PATH.to_string()]),
        cmd: Some(vec![
            format!("--topology-backend-name={}", descriptor.backend_name),
            "--topology-payload-file".to_string(),
            topology_path.clone(),
            "--workdir".to_string(),
            workspace_root,
            format!("--health-socket-path={SUPERVISOR_HEALTH_SOCKET_PATH}"),
        ]),
        env: Some(environment),
        labels: Some(labels),
        healthcheck: Some(HealthConfig {
            test: Some(vec![
                "CMD".to_string(),
                SUPERVISOR_IMAGE_CONTROL_BINARY_PATH.to_string(),
                "health".to_string(),
                "--socket".to_string(),
                SUPERVISOR_HEALTH_SOCKET_PATH.to_string(),
            ]),
            interval: Some(SUPERVISOR_HEALTH_INTERVAL_NS),
            timeout: Some(SUPERVISOR_HEALTH_TIMEOUT_NS),
            retries: Some(3),
            start_period: Some(SUPERVISOR_HEALTH_START_PERIOD_NS),
            start_interval: Some(SUPERVISOR_HEALTH_INTERVAL_NS),
        }),
        host_config: Some(HostConfig {
            network_mode: Some(config.network_name.clone()),
            mounts: Some(vec![Mount {
                target: Some(BOUNDARY_MOUNT_PATH.to_string()),
                source: Some(docker_channel_volume_name(sandbox, config)),
                typ: Some(MountTypeEnum::VOLUME),
                read_only: Some(true),
                volume_options: Some(MountVolumeOptions {
                    no_copy: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            cap_drop: Some(vec!["ALL".to_string()]),
            cap_add: None,
            security_opt: Some(vec!["no-new-privileges:true".to_string()]),
            readonly_rootfs: Some(true),
            tmpfs: Some(HashMap::from([
                (
                    "/run".to_string(),
                    format!(
                        "rw,noexec,nosuid,size=64m,uid={SUPERVISOR_UID},gid={SUPERVISOR_GID},mode=0700"
                    ),
                ),
                (
                    "/tmp".to_string(),
                    "rw,noexec,nosuid,size=64m,mode=1777".to_string(),
                ),
                (
                    "/var/log".to_string(),
                    format!(
                        "rw,noexec,nosuid,size=64m,uid={SUPERVISOR_UID},gid={SUPERVISOR_GID},mode=0700"
                    ),
                ),
            ])),
            extra_hosts: Some(vec![
                format!(
                    "{HOST_OPENSHELL_INTERNAL}:{}",
                    docker_supervisor_host_alias(&config.gateway_route)
                ),
                format!(
                    "{HOST_DOCKER_INTERNAL}:{}",
                    docker_supervisor_host_alias(&config.gateway_route)
                ),
            ]),
            restart_policy: None,
            ..Default::default()
        }),
        ..Default::default()
    };
    let created = docker
        .create_container(
            Some(
                CreateContainerOptionsBuilder::default()
                    .name(supervisor_name.as_str())
                    .build(),
            ),
            create,
        )
        .await
        .map_err(|error| {
            Status::internal(format!("create Docker supervisor container: {error}"))
        })?;
    if let Err(error) = docker.start_container(&created.id, None).await {
        let _ = docker
            .remove_container(
                &created.id,
                Some(RemoveContainerOptionsBuilder::default().force(true).build()),
            )
            .await;
        return Err(Status::internal(format!(
            "start Docker supervisor container: {error}"
        )));
    }
    let sandbox_id = sandbox.id.clone();
    let (shutdown, mut shutdown_requested) = oneshot::channel();
    let intentional_shutdown = Arc::new(AtomicBool::new(false));
    let monitored_shutdown = intentional_shutdown.clone();
    let supervisor_id = created.id;
    let monitored_supervisor_id = supervisor_id.clone();
    let monitored_docker = failure_context.docker.clone();
    let task = tokio::spawn(async move {
        let wait = async {
            let mut stream = monitored_docker.wait_container(
                &monitored_supervisor_id,
                None::<bollard::query_parameters::WaitContainerOptions>,
            );
            stream.next().await
        };
        tokio::select! {
            biased;
            _ = &mut shutdown_requested => {
                let _ = monitored_docker.stop_container(
                    &monitored_supervisor_id,
                    Some(StopContainerOptionsBuilder::default().t(5).build()),
                ).await;
                let _ = monitored_docker.remove_container(
                    &monitored_supervisor_id,
                    Some(RemoveContainerOptionsBuilder::default().force(true).build()),
                ).await;
            }
            result = wait => {
                if monitored_shutdown.load(Ordering::Acquire) {
                    let _ = monitored_docker.remove_container(
                        &monitored_supervisor_id,
                        Some(RemoveContainerOptionsBuilder::default().force(true).build()),
                    ).await;
                    return;
                }
                let mut message = match result {
                    Some(Ok(status)) => {
                    warn!(%sandbox_id, status = status.status_code, "Docker supervisor container exited unexpectedly");
                        format!("Docker supervisor container exited with status {}", status.status_code)
                    }
                    Some(Err(error)) => {
                    warn!(%sandbox_id, %error, "Failed to wait for Docker supervisor container");
                        format!("failed to wait for Docker supervisor container: {error}")
                    }
                    None => "Docker supervisor wait stream ended unexpectedly".to_string(),
                };
                let log_tail =
                    docker_container_log_tail(&monitored_docker, &monitored_supervisor_id).await;
                if !log_tail.is_empty() {
                    write!(message, "; log tail: {log_tail}").ok();
                }
                let sandbox_log_tail =
                    docker_container_log_tail(&monitored_docker, &failure_context.container_id)
                        .await;
                if !sandbox_log_tail.is_empty() {
                    write!(message, "; sandbox log tail: {sandbox_log_tail}").ok();
                }
                let _ = monitored_docker.remove_container(
                    &monitored_supervisor_id,
                    Some(RemoveContainerOptionsBuilder::default().force(true).build()),
                ).await;
                // The gateway can close the supervisor session as soon as it
                // commits Stopping. Re-check after collecting diagnostics so
                // an overlapping driver stop cannot be published as an
                // unexpected control failure.
                if monitored_shutdown.load(Ordering::Acquire) {
                    return;
                }
                handle_docker_runtime_failure(
                    failure_context,
                    "ControlSupervisorExited",
                    message,
                )
                .await;
            },
        }
    });
    let process = DockerControlProcess {
        shutdown: Some(shutdown),
        intentional_shutdown,
        task,
    };
    if let Err(error) = wait_for_docker_supervisor_ready(docker, &supervisor_id).await {
        stop_docker_control_process(process).await;
        return Err(error);
    }
    Ok(process)
}

async fn wait_for_docker_supervisor_ready(
    docker: &Docker,
    supervisor_id: &str,
) -> Result<(), Status> {
    let wait = async {
        loop {
            let inspected = docker
                .inspect_container(supervisor_id, None)
                .await
                .map_err(|error| {
                    Status::internal(format!("inspect Docker supervisor container: {error}"))
                })?;
            let state = inspected.state.unwrap_or_default();
            match state.health.and_then(|health| health.status) {
                Some(HealthStatusEnum::HEALTHY) => return Ok(()),
                Some(HealthStatusEnum::UNHEALTHY) => {
                    let log_tail = docker_container_log_tail(docker, supervisor_id).await;
                    return Err(Status::unavailable(format!(
                        "Docker supervisor failed its readiness check{}",
                        format_log_tail(&log_tail)
                    )));
                }
                _ if state.running == Some(false) => {
                    let log_tail = docker_container_log_tail(docker, supervisor_id).await;
                    return Err(Status::unavailable(format!(
                        "Docker supervisor exited before becoming ready{}",
                        format_log_tail(&log_tail)
                    )));
                }
                _ => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    };

    if let Ok(result) = tokio::time::timeout(SUPERVISOR_READY_TIMEOUT, wait).await {
        result
    } else {
        let log_tail = docker_container_log_tail(docker, supervisor_id).await;
        Err(Status::deadline_exceeded(format!(
            "Docker supervisor did not become ready within {} seconds{}",
            SUPERVISOR_READY_TIMEOUT.as_secs(),
            format_log_tail(&log_tail)
        )))
    }
}

fn format_log_tail(log_tail: &str) -> String {
    if log_tail.is_empty() {
        String::new()
    } else {
        format!("; log tail: {log_tail}")
    }
}

async fn docker_container_log_tail(docker: &Docker, container_id: &str) -> String {
    const MAX_LOG_TAIL_BYTES: usize = 16 * 1024;
    let options = LogsOptionsBuilder::default()
        .stdout(true)
        .stderr(true)
        .tail("80")
        .build();
    let mut stream = docker.logs(container_id, Some(options));
    let mut output = Vec::new();
    while let Some(result) = stream.next().await {
        let Ok(chunk) = result else {
            break;
        };
        output.extend_from_slice(chunk.as_ref());
        if output.len() > MAX_LOG_TAIL_BYTES {
            output.drain(..output.len() - MAX_LOG_TAIL_BYTES);
        }
    }
    String::from_utf8_lossy(&output).trim().to_string()
}

async fn handle_docker_runtime_failure(
    context: DockerRuntimeFailureContext,
    reason: &'static str,
    message: String,
) {
    context.failures.lock().await.insert(
        context.sandbox.id.clone(),
        DockerRuntimeFailure {
            reason,
            message: message.clone(),
        },
    );

    let mut snapshot = pending_sandbox_snapshot(
        &context.sandbox,
        &context.sandbox_namespace,
        error_condition(reason, &message),
        false,
    );
    if let Some(status) = snapshot.status.as_mut() {
        status.instance_id.clone_from(&context.container_id);
    }
    let _ = context.events.send(WatchSandboxesEvent {
        payload: Some(watch_sandboxes_event::Payload::Sandbox(
            WatchSandboxesSandboxEvent {
                sandbox: Some(snapshot),
            },
        )),
    });
    let _ = context.events.send(WatchSandboxesEvent {
        payload: Some(watch_sandboxes_event::Payload::PlatformEvent(
            WatchSandboxesPlatformEvent {
                sandbox_id: context.sandbox.id.clone(),
                event: Some(platform_event(
                    "docker",
                    "Warning",
                    reason,
                    format!("{message}; stopping the isolated workload container"),
                )),
            },
        )),
    });

    match context
        .docker
        .stop_container(
            &context.container_id,
            Some(
                StopContainerOptionsBuilder::default()
                    .t(docker_stop_timeout_secs(context.stop_timeout_secs))
                    .build(),
            ),
        )
        .await
    {
        Ok(()) => info!(
            sandbox_id = %context.sandbox.id,
            container_id = %context.container_id,
            "Stopped Docker sandbox after control supervisor failure"
        ),
        Err(error) if is_not_found_error(&error) || is_not_modified_error(&error) => {}
        Err(error) => warn!(
            sandbox_id = %context.sandbox.id,
            container_id = %context.container_id,
            %error,
            "Failed to stop Docker sandbox after control supervisor failure"
        ),
    }
}

async fn stop_docker_control_process(mut process: DockerControlProcess) {
    process.intentional_shutdown.store(true, Ordering::Release);
    if let Some(shutdown) = process.shutdown.take() {
        let _ = shutdown.send(());
    }
    let _ = process.task.await;
}

fn cleanup_docker_boundary_state(sandbox: &DriverSandbox, config: &DockerDriverRuntimeConfig) {
    cleanup_docker_boundary_state_by_id(&sandbox.id, config);
}

fn cleanup_docker_boundary_state_by_id(sandbox_id: &str, config: &DockerDriverRuntimeConfig) {
    let Ok(directory) = docker_boundary_state_dir_by_id(sandbox_id, config) else {
        return;
    };
    if let Err(error) = std::fs::remove_dir_all(&directory)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        warn!(
            %sandbox_id,
            path = %directory.display(),
            %error,
            "Failed to remove Docker boundary state directory"
        );
    }
}

fn random_boundary_token() -> String {
    let mut token = String::with_capacity(64);
    for byte in rand::random::<[u8; 32]>() {
        write!(&mut token, "{byte:02x}").expect("writing to String cannot fail");
    }
    token
}

fn docker_child_environment(sandbox: &DriverSandbox) -> HashMap<String, String> {
    let mut environment = sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
        .map_or_else(HashMap::new, |template| template.environment.clone());
    if let Some(spec) = sandbox.spec.as_ref() {
        environment.extend(spec.environment.clone());
    }
    for protected in [
        openshell_core::sandbox_env::ENDPOINT,
        openshell_core::sandbox_env::GATEWAY_TLS_SERVER_NAME,
        openshell_core::sandbox_env::MAIN_PROCESS_SPEC,
        openshell_core::sandbox_env::NETWORK_RUNTIME_CAPABILITIES,
        openshell_core::sandbox_env::OCI_IMAGE_USER,
        openshell_core::sandbox_env::SANDBOX,
        openshell_core::sandbox_env::SANDBOX_GID,
        openshell_core::sandbox_env::SANDBOX_ID,
        openshell_core::sandbox_env::SANDBOX_TOKEN,
        openshell_core::sandbox_env::SANDBOX_TOKEN_FILE,
        openshell_core::sandbox_env::SANDBOX_UID,
        openshell_core::sandbox_env::SSH_SOCKET_PATH,
        openshell_core::sandbox_env::TLS_CA,
        openshell_core::sandbox_env::TLS_CERT,
        openshell_core::sandbox_env::TLS_KEY,
        openshell_core::sandbox_env::USER_ENVIRONMENT,
    ] {
        environment.remove(protected);
    }
    environment
}

fn build_boundary_environment(
    sandbox: &DriverSandbox,
    config: &DockerDriverRuntimeConfig,
) -> Vec<String> {
    vec![
        format!(
            "{}={}",
            openshell_core::sandbox_env::LOG_LEVEL,
            openshell_core::driver_utils::sandbox_log_level(sandbox, &config.log_level)
        ),
        format!(
            "{}={}",
            openshell_core::sandbox_env::TELEMETRY_ENABLED,
            openshell_core::telemetry::enabled_env_value()
        ),
    ]
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
    let workload_identity = ResolvedWorkloadIdentity::new(
        1000,
        1000,
        Vec::new(),
        "test".to_string(),
        template.image.clone(),
    )
    .map_err(|error| Status::internal(error.to_string()))?;
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
        &workload_identity,
    )
}

fn build_container_create_body_for_image(
    sandbox: &DriverSandbox,
    config: &DockerDriverRuntimeConfig,
    driver_config: &DockerSandboxDriverConfig,
    gpu_device_ids: Option<&[String]>,
    image: &DockerImageMetadata,
    workload_identity: &ResolvedWorkloadIdentity,
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
    driver_mounts::validate_workspace_control_path(&workspace_root, BOUNDARY_MOUNT_PATH)
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
        driver_mounts::validate_mount_control_path(volume, BOUNDARY_MOUNT_PATH)
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
        driver_mounts::validate_mount_control_path(target, BOUNDARY_MOUNT_PATH)
            .map_err(Status::failed_precondition)?;
    }
    let mut user_mounts = docker_driver_mounts(driver_config)?;
    user_mounts.push(Mount {
        target: Some(BOUNDARY_MOUNT_PATH.to_string()),
        source: Some(docker_channel_volume_name(sandbox, config)),
        typ: Some(MountTypeEnum::VOLUME),
        read_only: Some(false),
        volume_options: Some(MountVolumeOptions {
            no_copy: Some(true),
            ..Default::default()
        }),
        ..Default::default()
    });
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
    // The list/get/find paths filter by `config.sandbox_namespace`, so use
    // the same value here. `DriverSandbox.namespace` is unset on the request
    // path (the gateway elides it), and using it would produce containers
    // that the driver itself cannot find afterwards.
    labels.insert(
        LABEL_SANDBOX_NAMESPACE.to_string(),
        config.sandbox_namespace.clone(),
    );
    labels.insert(
        LABEL_ISOLATION_TOPOLOGY.to_string(),
        LABEL_ISOLATION_TOPOLOGY_CAPABILITY_FREE.to_string(),
    );
    labels.insert(
        LABEL_ISOLATION_ROLE.to_string(),
        LABEL_ISOLATION_ROLE_SANDBOX.to_string(),
    );

    Ok(ContainerCreateBody {
        image: Some(image.id.clone()),
        user: Some(format!(
            "{}:{}",
            workload_identity.uid, workload_identity.gid
        )),
        // The image workspace may need to be created or rejected by the
        // supervisor, so do not let the OCI runtime chdir there first.
        working_dir: Some("/".to_string()),
        env: Some(build_boundary_environment(sandbox, config)),
        entrypoint: Some(vec![SANDBOX_BINARY_PATH.to_string()]),
        // The image cannot append inherited arguments or select either role.
        cmd: Some(vec![
            "--bootstrap".to_string(),
            BOUNDARY_CONFIG_MOUNT_PATH.to_string(),
        ]),
        labels: Some(labels),
        host_config: Some(HostConfig {
            nano_cpus: resource_limits.nano_cpus,
            memory: resource_limits.memory_bytes,
            pids_limit: docker_pids_limit(config.sandbox_pids_limit)?,
            device_requests,
            binds: {
                let mut binds = build_binds(sandbox, config);
                binds.extend(user_bind_strings);
                Some(binds)
            },
            mounts: Some(user_mounts),
            // Canonical main-process exit is terminal. Runtime restart would
            // silently create a new process generation behind the gateway.
            restart_policy: None,
            group_add: Some(
                workload_identity
                    .supplementary_gids
                    .iter()
                    .map(u32::to_string)
                    .collect(),
            ),
            cap_drop: Some(vec!["ALL".to_string()]),
            cap_add: None,
            security_opt: Some(vec!["no-new-privileges:true".to_string()]),
            network_mode: Some("none".to_string()),
            dns: Some(vec!["127.0.0.53".to_string()]),
            tmpfs: Some(HashMap::from([(
                "/run".to_string(),
                format!(
                    "rw,noexec,nosuid,size=64m,uid={},gid={},mode=0755",
                    workload_identity.uid, workload_identity.gid
                ),
            )])),
            sysctls: Some(HashMap::from([(
                "net.ipv4.ip_unprivileged_port_start".to_string(),
                "0".to_string(),
            )])),
            extra_hosts: None,
            ..Default::default()
        }),
        networking_config: None,
        ..Default::default()
    })
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

fn docker_host_openshell_endpoint(
    endpoint: &str,
    route: &DockerGatewayRoute,
) -> CoreResult<String> {
    let mut url = Url::parse(endpoint)
        .map_err(|error| Error::config(format!("invalid docker grpc_endpoint: {error}")))?;
    if !matches!(
        url.host_str(),
        Some(HOST_OPENSHELL_INTERNAL | HOST_DOCKER_INTERNAL)
    ) {
        return Ok(url.to_string());
    }
    let host = match route {
        DockerGatewayRoute::Bridge { bind_address, .. } => bind_address.ip(),
        DockerGatewayRoute::HostGateway => IpAddr::V4(Ipv4Addr::LOCALHOST),
    };
    url.set_host(Some(&host.to_string())).map_err(|error| {
        Error::config(format!(
            "failed to map Docker gateway alias to its host listener: {error}"
        ))
    })?;
    Ok(url.to_string())
}

fn docker_supervisor_host_alias(route: &DockerGatewayRoute) -> String {
    match route {
        DockerGatewayRoute::Bridge { bind_address } => bind_address.ip().to_string(),
        DockerGatewayRoute::HostGateway => "host-gateway".to_string(),
    }
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
        };
    }

    if host_requires_host_gateway_alias || uses_host_gateway_alias(info) {
        DockerGatewayRoute::HostGateway
    } else {
        DockerGatewayRoute::Bridge {
            bind_address: SocketAddr::new(bridge_gateway_ip, port),
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

fn validate_sandbox_pids_limit(value: i64) -> CoreResult<()> {
    if value < 0 {
        return Err(Error::config(
            "docker sandbox_pids_limit must be zero or greater",
        ));
    }
    Ok(())
}

fn docker_pids_limit(value: i64) -> Result<Option<i64>, Status> {
    if value < 0 {
        return Err(Status::failed_precondition(
            "docker sandbox_pids_limit must be zero or greater",
        ));
    }
    if value == 0 {
        Ok(None)
    } else {
        Ok(Some(value))
    }
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
        ..Default::default()
    }
}

/// Refine an exited Docker sandbox's `Ready` condition from inspected state.
///
/// A signal kill (exit 137/143 = SIGKILL/SIGTERM, not OOM) is the signature of
/// a machine/daemon restart terminating a running container. Reclassify it from
/// the generic terminal `ContainerExited` to the recoverable
/// `ContainerRuntimeRestart` so gateway startup can revive it. OOM kills and
/// ordinary application exits stay `ContainerExited` and terminal.
fn apply_docker_exit_classification(sandbox: &mut DriverSandbox, state: &ContainerState) {
    if state.oom_killed == Some(true) {
        return;
    }
    let Some(code) = state.exit_code.filter(|&code| matches!(code, 137 | 143)) else {
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
    condition.reason = CONDITION_RUNTIME_RESTART.to_string();
    condition.message = format!("Container terminated by signal (exit code {code})");
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
    sandbox_namespace: &str,
    extra_values: impl IntoIterator<Item = String>,
) -> HashMap<String, Vec<String>> {
    let mut values = vec![format!(
        "{LABEL_ISOLATION_ROLE}={LABEL_ISOLATION_ROLE_SANDBOX}"
    )];
    values.extend(extra_values);
    managed_resource_label_filters(sandbox_namespace, values)
}

fn managed_resource_label_filters(
    sandbox_namespace: &str,
    extra_values: impl IntoIterator<Item = String>,
) -> HashMap<String, Vec<String>> {
    let mut values = vec![
        format!("{LABEL_MANAGED_BY}={LABEL_MANAGED_BY_VALUE}"),
        format!("{LABEL_SANDBOX_NAMESPACE}={sandbox_namespace}"),
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

async fn ensure_supervisor_container_image(docker: &Docker, image: &str) -> CoreResult<String> {
    let local_image_present = docker.inspect_image(image).await.is_ok();
    if supervisor_image_should_refresh(image) {
        info!(image = image, "Refreshing mutable docker supervisor image");
        if let Err(error) = pull_supervisor_image(docker, image).await {
            if !local_image_present {
                return Err(error);
            }
            warn!(
                image = image,
                error = %error,
                "failed to refresh mutable Docker supervisor image; using the local image",
            );
        }
    } else if !local_image_present {
        pull_supervisor_image(docker, image).await?;
    }
    let inspect = docker.inspect_image(image).await.map_err(|error| {
        Error::config(format!(
            "failed to inspect Docker supervisor image '{image}': {error}"
        ))
    })?;
    inspect.id.filter(|id| !id.is_empty()).ok_or_else(|| {
        Error::config(format!(
            "Docker supervisor image '{image}' has no immutable image ID"
        ))
    })
}

/// Create a short-lived container from `image`, stream out the supervisor
/// binary as a tar archive, and return the untarred file bytes. The
/// container is always removed, even on error paths.
async fn extract_supervisor_binary_bytes(docker: &Docker, image: &str) -> CoreResult<Vec<u8>> {
    let bytes =
        extract_supervisor_path_archive(docker, image, SUPERVISOR_IMAGE_BINARY_PATH, true).await?;
    if !bytes.starts_with(b"\x7fELF") {
        return Err(Error::config(format!(
            "Docker supervisor image '{image}' contains an invalid sandbox binary"
        )));
    }
    Ok(bytes)
}

async fn extract_supervisor_path_archive(
    docker: &Docker,
    image: &str,
    path: &str,
    extract_single_file: bool,
) -> CoreResult<Vec<u8>> {
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
    let result =
        download_path_from_container(docker, &container_name, path, extract_single_file).await;
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

async fn download_path_from_container(
    docker: &Docker,
    container_name: &str,
    path: &str,
    extract_single_file: bool,
) -> CoreResult<Vec<u8>> {
    let options = DownloadFromContainerOptionsBuilder::default()
        .path(path)
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

    if extract_single_file {
        extract_first_tar_entry(&tar_bytes).map_err(|err| {
            Error::config(format!(
                "failed to extract supervisor binary from tar archive returned by '{container_name}': {err}",
            ))
        })
    } else {
        Ok(tar_bytes)
    }
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
        && docker_config.guest_tls_cert.is_some()
        && docker_config.guest_tls_key.is_some()
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

fn is_removal_in_progress_error(err: &BollardError) -> bool {
    matches!(
        err,
        BollardError::DockerResponseServerError {
            status_code: 409,
            message,
        } if message.contains("removal of container") && message.contains("is already in progress")
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
