// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Docker compute driver.

#![allow(clippy::result_large_err)]

use bollard::Docker;
use bollard::errors::Error as BollardError;
use bollard::models::{
    ContainerCreateBody, ContainerSummary, ContainerSummaryStateEnum, CreateImageInfo,
    DeviceRequest, EndpointSettings, HostConfig, Mount, MountTmpfsOptions, MountTypeEnum,
    MountVolumeOptions, NetworkCreateRequest, NetworkingConfig, ProgressDetail, RestartPolicy,
    RestartPolicyNameEnum, SystemInfo,
};
use bollard::query_parameters::{
    CreateContainerOptionsBuilder, CreateImageOptions, DownloadFromContainerOptionsBuilder,
    ListContainersOptionsBuilder, RemoveContainerOptionsBuilder, StopContainerOptionsBuilder,
};
use bytes::Bytes;
use futures::{Stream, StreamExt};
use openshell_core::config::{
    DEFAULT_DOCKER_NETWORK_NAME, DEFAULT_SANDBOX_PIDS_LIMIT, DEFAULT_STOP_TIMEOUT_SECS,
};
use openshell_core::driver_mounts;
use openshell_core::driver_utils::{
    LABEL_MANAGED_BY, LABEL_MANAGED_BY_VALUE, LABEL_SANDBOX_ID, LABEL_SANDBOX_NAME,
    LABEL_SANDBOX_NAMESPACE, SUPERVISOR_IMAGE_BINARY_PATH, supervisor_image_should_refresh,
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
    DriverCondition, DriverPlatformEvent, DriverSandbox, DriverSandboxStatus,
    DriverSandboxTemplate, GetCapabilitiesRequest, GetCapabilitiesResponse, GetSandboxRequest,
    GetSandboxResponse, GpuResourceRequirements, ListSandboxesRequest, ListSandboxesResponse,
    StopSandboxRequest, StopSandboxResponse, ValidateSandboxCreateRequest,
    ValidateSandboxCreateResponse, WatchSandboxesDeletedEvent, WatchSandboxesEvent,
    WatchSandboxesPlatformEvent, WatchSandboxesRequest, WatchSandboxesSandboxEvent,
    compute_driver_server::ComputeDriver, watch_sandboxes_event,
};
use openshell_core::proto_struct::{
    deserialize_optional_non_empty_string_list, struct_to_json_value,
};
use openshell_core::{Config, Error, Result as CoreResult};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};
use url::Url;

const WATCH_BUFFER: usize = 128;
const WATCH_POLL_INTERVAL: Duration = Duration::from_secs(2);
const WATCH_POLL_MAX_BACKOFF: Duration = Duration::from_secs(30);

const SUPERVISOR_MOUNT_PATH: &str = openshell_core::driver_utils::SUPERVISOR_CONTAINER_BINARY;
const TLS_CA_MOUNT_PATH: &str = openshell_core::driver_utils::TLS_CA_MOUNT_PATH;
const TLS_CERT_MOUNT_PATH: &str = openshell_core::driver_utils::TLS_CERT_MOUNT_PATH;
const TLS_KEY_MOUNT_PATH: &str = openshell_core::driver_utils::TLS_KEY_MOUNT_PATH;
const SANDBOX_TOKEN_MOUNT_PATH: &str = openshell_core::driver_utils::SANDBOX_TOKEN_MOUNT_PATH;
const SANDBOX_COMMAND: &str = "sleep infinity";
const SUPERVISOR_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const HOST_OPENSHELL_INTERNAL: &str = "host.openshell.internal";
const HOST_DOCKER_INTERNAL: &str = "host.docker.internal";
const DOCKER_NETWORK_DRIVER: &str = "bridge";

/// Default image holding the Linux `openshell-sandbox` binary. The gateway
/// pulls this image and extracts the binary to a host-side cache when no
/// explicit `supervisor_bin`, configured `supervisor_image`, sibling binary,
/// or local build is available.
const DEFAULT_DOCKER_SUPERVISOR_IMAGE_REPO: &str = "ghcr.io/nvidia/openshell/supervisor";

/// Return the default `ghcr.io/nvidia/openshell/supervisor:<tag>` reference
/// used when no supervisor binary override is provided.
pub fn default_docker_supervisor_image() -> String {
    format!(
        "{DEFAULT_DOCKER_SUPERVISOR_IMAGE_REPO}:{}",
        default_docker_supervisor_image_tag()
    )
}

/// Image tag baked in at compile time to pair the gateway with a matching
/// supervisor image.
///
/// Build pipelines pass `OPENSHELL_IMAGE_TAG` explicitly. The `IMAGE_TAG`
/// fallback covers image build wrappers that already tag the gateway and
/// supervisor together. Standalone release binaries also patch the Cargo
/// package version, so use it when it has been set to a real release value.
fn default_docker_supervisor_image_tag() -> String {
    resolve_default_docker_supervisor_image_tag(
        option_env!("OPENSHELL_IMAGE_TAG"),
        option_env!("IMAGE_TAG"),
        env!("CARGO_PKG_VERSION"),
    )
}

fn resolve_default_docker_supervisor_image_tag(
    openshell_image_tag: Option<&'static str>,
    image_tag: Option<&'static str>,
    cargo_pkg_version: &'static str,
) -> String {
    let tag = openshell_image_tag
        .filter(|tag| !tag.is_empty())
        .or_else(|| image_tag.filter(|tag| !tag.is_empty()))
        .unwrap_or_else(|| {
            if cargo_pkg_version.is_empty() || cargo_pkg_version == "0.0.0" {
                "dev"
            } else {
                cargo_pkg_version
            }
        });

    tag.replace('+', "-")
}

/// Queried by the Docker driver to decide when a sandbox's supervisor
/// relay is live. Implementations return `true` once a sandbox has an
/// active `ConnectSupervisor` session registered.
///
/// The driver cannot observe the supervisor's SSH socket directly (it
/// lives inside the container), so it leans on this signal to flip the
/// Ready condition from `DependenciesNotReady` to `True`.
pub trait SupervisorReadiness: Send + Sync + 'static {
    fn is_supervisor_connected(&self, sandbox_id: &str) -> bool;
}

/// Gateway-local configuration for the Docker compute driver.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DockerComputeConfig {
    /// Default OCI image for sandboxes.
    pub default_image: String,

    /// Image pull policy for sandbox images.
    pub image_pull_policy: String,

    /// Namespace label applied to Docker sandboxes.
    pub sandbox_namespace: String,

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
            default_image: openshell_core::image::default_sandbox_image(),
            image_pull_policy: String::new(),
            sandbox_namespace: "default".to_string(),
            grpc_endpoint: String::new(),
            supervisor_bin: None,
            supervisor_image: None,
            guest_tls_ca: None,
            guest_tls_cert: None,
            guest_tls_key: None,
            network_name: DEFAULT_DOCKER_NETWORK_NAME.to_string(),
            host_gateway_ip: String::new(),
            ssh_socket_path: "/run/openshell/ssh.sock".to_string(),
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
    grpc_endpoint: String,
    network_name: String,
    gateway_route: DockerGatewayRoute,
    ssh_socket_path: String,
    stop_timeout_secs: u32,
    log_level: String,
    supervisor_bin: PathBuf,
    guest_tls: Option<DockerGuestTlsPaths>,
    daemon_version: String,
    supports_gpu: bool,
    allow_all_default_gpu: bool,
    sandbox_pids_limit: i64,
    enable_bind_mounts: bool,
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
    supervisor_readiness: Arc<dyn SupervisorReadiness>,
    gpu_selector: Arc<CdiGpuDefaultSelector>,
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

impl DockerComputeDriver {
    pub async fn new(
        config: &Config,
        docker_config: &DockerComputeConfig,
        supervisor_readiness: Arc<dyn SupervisorReadiness>,
    ) -> CoreResult<Self> {
        let docker = Docker::connect_with_local_defaults()
            .map_err(|err| Error::execution(format!("failed to create Docker client: {err}")))?;
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
        let gateway_port = config.bind_address.port();
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
                image_pull_policy: docker_config.image_pull_policy.clone(),
                sandbox_namespace: docker_config.sandbox_namespace.clone(),
                grpc_endpoint,
                network_name,
                gateway_route,
                ssh_socket_path: docker_config.ssh_socket_path.clone(),
                stop_timeout_secs: DEFAULT_STOP_TIMEOUT_SECS,
                log_level: config.log_level.clone(),
                supervisor_bin,
                guest_tls,
                daemon_version: version.version.unwrap_or_else(|| "unknown".to_string()),
                supports_gpu,
                allow_all_default_gpu,
                sandbox_pids_limit: docker_config.sandbox_pids_limit,
                enable_bind_mounts: docker_config.enable_bind_mounts,
            },
            events: broadcast::channel(WATCH_BUFFER).0,
            pending: Arc::new(Mutex::new(HashMap::new())),
            supervisor_readiness,
            gpu_selector: Arc::new(CdiGpuDefaultSelector::new(
                cdi_gpu_inventory,
                allow_all_default_gpu,
            )),
        };

        let poll_driver = driver.clone();
        tokio::spawn(async move {
            poll_driver.poll_loop().await;
        });

        Ok(driver)
    }

    #[must_use]
    pub fn gateway_bind_addresses(&self) -> Vec<SocketAddr> {
        match self.config.gateway_route {
            DockerGatewayRoute::Bridge { bind_address, .. } => vec![bind_address],
            DockerGatewayRoute::HostGateway => Vec::new(),
        }
    }

    fn capabilities(&self) -> GetCapabilitiesResponse {
        openshell_core::driver_utils::build_capabilities_response(
            "docker",
            &self.config.daemon_version,
            &self.config.default_image,
        )
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

    async fn get_sandbox_snapshot(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<Option<DriverSandbox>, Status> {
        let container = self
            .find_managed_container_summary(sandbox_id, sandbox_name)
            .await?;
        if let Some(sandbox) = container.and_then(|summary| {
            sandbox_from_container_summary(&summary, self.supervisor_readiness.as_ref())
        }) {
            return Ok(Some(sandbox));
        }

        Ok(self.pending_snapshot(sandbox_id, sandbox_name).await)
    }

    async fn current_snapshots(&self) -> Result<Vec<DriverSandbox>, Status> {
        let containers = self.list_managed_container_summaries().await?;
        let container_sandboxes = containers
            .iter()
            .filter_map(|summary| {
                sandbox_from_container_summary(summary, self.supervisor_readiness.as_ref())
            })
            .collect::<Vec<_>>();
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
        let gpu_devices = self
            .resolve_gpu_cdi_devices(
                validated.gpu_requirements,
                &validated.driver_config,
                CdiGpuDefaultSelector::peek_device_ids,
            )
            .await?;
        let _ = build_container_create_body_with_gpu_devices(
            sandbox,
            &self.config,
            &validated.driver_config,
            gpu_devices.as_deref(),
        )?;

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
            HashMap::from([("image_ref".to_string(), image)]),
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
        let task = tokio::spawn(async move {
            driver.provision_sandbox(sandbox_for_task).await;
        });

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
        let validated = Self::validated_sandbox(sandbox, &self.config).map_err(|status| {
            DockerProvisioningFailure::new("ContainerCreateFailed", status.message())
        })?;
        let template = validated.template;
        self.ensure_image_available(&sandbox.id, &template.image)
            .await
            .map_err(|status| {
                DockerProvisioningFailure::new("ImagePullFailed", status.message())
            })?;
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
        let create_body = build_container_create_body_with_gpu_devices(
            sandbox,
            &self.config,
            &validated.driver_config,
            gpu_devices.as_deref(),
        )
        .map_err(|status| {
            if token_file_created {
                cleanup_sandbox_token_file(sandbox, &self.config);
            }
            DockerProvisioningFailure::new("ContainerCreateFailed", status.message())
        })?;
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
            })?;
        self.publish_docker_progress(
            &sandbox.id,
            "Created",
            format!("Created Docker container \"{container_name}\""),
            HashMap::from([("container_name".to_string(), container_name.clone())]),
        );

        if let Err(err) = self.docker.start_container(&container_name, None).await {
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
            if let Some(record) = self.remove_pending_sandbox(sandbox_id, sandbox_name).await {
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
    /// by the gateway to resume sandboxes after a restart so that running
    /// state in the gateway store is matched by an actually-running
    /// container.
    ///
    /// Returns `Ok(true)` when a container existed and was started (or was
    /// already running), `Ok(false)` when no managed container is found for
    /// the sandbox, and `Err(...)` for any Docker failure.
    pub async fn resume_sandbox(
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
        let state = container.state.unwrap_or(ContainerSummaryStateEnum::EMPTY);
        if !container_state_needs_resume(state) {
            return Ok(true);
        }

        match self.docker.start_container(&target, None).await {
            Ok(()) => Ok(true),
            // Already running — race with another resume path or the
            // restart policy. Treat as success.
            Err(err) if is_not_modified_error(&err) => Ok(true),
            Err(err) if is_not_found_error(&err) => Ok(false),
            Err(err) => Err(internal_status("start docker sandbox container", err)),
        }
    }

    pub async fn stop_managed_containers_on_shutdown(&self) -> Result<usize, Status> {
        let containers = self.list_managed_container_summaries().await?;
        let targets = containers
            .into_iter()
            .filter_map(|container| {
                let state = container.state.unwrap_or(ContainerSummaryStateEnum::EMPTY);
                if container_state_needs_shutdown_stop(state) {
                    summary_container_target(&container)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let target_count = targets.len();
        let mut stopped = 0usize;
        let mut failures = Vec::new();
        let stop_timeout_secs = self.config.stop_timeout_secs;

        let mut stop_results = futures::stream::iter(targets.into_iter().map(|target| {
            let docker = self.docker.clone();
            async move {
                let result = docker
                    .stop_container(
                        &target,
                        Some(
                            StopContainerOptionsBuilder::default()
                                .t(docker_stop_timeout_secs(stop_timeout_secs))
                                .build(),
                        ),
                    )
                    .await;
                (target, result)
            }
        }))
        .buffer_unordered(16);

        while let Some((target, result)) = stop_results.next().await {
            match result {
                Ok(()) => {
                    stopped += 1;
                }
                Err(err) if is_not_found_error(&err) || is_not_modified_error(&err) => {}
                Err(err) => {
                    warn!(
                        container = %target,
                        error = %err,
                        "Failed to stop Docker sandbox container during shutdown"
                    );
                    failures.push(target);
                }
            }
        }

        if !failures.is_empty() {
            return Err(Status::internal(format!(
                "failed to stop {} of {target_count} Docker sandbox containers during shutdown",
                failures.len()
            )));
        }

        Ok(stopped)
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
        cleanup_sandbox_token_file(sandbox, &self.config);
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
        if let Some(summary) = self
            .find_managed_container_summary(sandbox_id, sandbox_name)
            .await?
            && let Some(sandbox) =
                sandbox_from_container_summary(&summary, self.supervisor_readiness.as_ref())
        {
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
                    emit_snapshot_diff(&self.events, &previous, &current);
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

    async fn ensure_image_available(&self, sandbox_id: &str, image: &str) -> Result<(), Status> {
        let policy = self.config.image_pull_policy.trim().to_ascii_lowercase();
        match policy.as_str() {
            "" | "ifnotpresent" => {
                if self.docker.inspect_image(image).await.is_ok() {
                    self.publish_docker_progress(
                        sandbox_id,
                        "ImagePresent",
                        format!("Docker image \"{image}\" is already present"),
                        HashMap::from([("image_ref".to_string(), image.to_string())]),
                    );
                    return Ok(());
                }
                self.pull_image(sandbox_id, image).await
            }
            "always" => self.pull_image(sandbox_id, image).await,
            "never" => match self.docker.inspect_image(image).await {
                Ok(_) => {
                    self.publish_docker_progress(
                        sandbox_id,
                        "ImagePresent",
                        format!("Docker image \"{image}\" is already present"),
                        HashMap::from([("image_ref".to_string(), image.to_string())]),
                    );
                    Ok(())
                }
                Err(err) if is_not_found_error(&err) => Err(Status::failed_precondition(format!(
                    "docker image '{image}' is not present locally and image_pull_policy=Never"
                ))),
                Err(err) => Err(internal_status("inspect Docker image", err)),
            },
            other => Err(Status::failed_precondition(format!(
                "unsupported docker image_pull_policy '{other}'; expected Always, IfNotPresent, or Never",
            ))),
        }
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

#[tonic::async_trait]
impl ComputeDriver for DockerComputeDriver {
    type WatchSandboxesStream = WatchStream;

    async fn get_capabilities(
        &self,
        _request: Request<GetCapabilitiesRequest>,
    ) -> Result<Response<GetCapabilitiesResponse>, Status> {
        Ok(Response::new(self.capabilities()))
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

    async fn create_sandbox(
        &self,
        request: Request<CreateSandboxRequest>,
    ) -> Result<Response<CreateSandboxResponse>, Status> {
        let sandbox = request
            .into_inner()
            .sandbox
            .ok_or_else(|| Status::invalid_argument("sandbox is required"))?;
        self.create_sandbox_inner(&sandbox).await?;
        Ok(Response::new(CreateSandboxResponse {}))
    }

    async fn stop_sandbox(
        &self,
        request: Request<StopSandboxRequest>,
    ) -> Result<Response<StopSandboxResponse>, Status> {
        let request = request.into_inner();
        require_sandbox_identifier(&request.sandbox_id, &request.sandbox_name)?;

        self.stop_sandbox_inner(&request.sandbox_id, &request.sandbox_name)
            .await?;
        Ok(Response::new(StopSandboxResponse {}))
    }

    async fn delete_sandbox(
        &self,
        request: Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        let request = request.into_inner();
        require_sandbox_identifier(&request.sandbox_id, &request.sandbox_name)?;

        let event_sandbox_id = request.sandbox_id.clone();
        let deleted = self
            .delete_sandbox_inner(&request.sandbox_id, &request.sandbox_name)
            .await?;
        if deleted && !event_sandbox_id.is_empty() {
            let _ = self.events.send(WatchSandboxesEvent {
                payload: Some(watch_sandboxes_event::Payload::Deleted(
                    WatchSandboxesDeletedEvent {
                        sandbox_id: event_sandbox_id,
                    },
                )),
            });
        }

        Ok(Response::new(DeleteSandboxResponse { deleted }))
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

fn build_binds(
    sandbox: &DriverSandbox,
    config: &DockerDriverRuntimeConfig,
) -> Result<Vec<String>, Status> {
    let mut binds = vec![format!(
        "{}:{}:ro,z",
        config.supervisor_bin.display(),
        SUPERVISOR_MOUNT_PATH
    )];
    if let Some(tls) = &config.guest_tls {
        binds.push(format!("{}:{}:ro,z", tls.ca.display(), TLS_CA_MOUNT_PATH));
        binds.push(format!(
            "{}:{}:ro,z",
            tls.cert.display(),
            TLS_CERT_MOUNT_PATH
        ));
        binds.push(format!("{}:{}:ro,z", tls.key.display(), TLS_KEY_MOUNT_PATH));
    }
    if sandbox
        .spec
        .as_ref()
        .is_some_and(|spec| !spec.sandbox_token.is_empty())
    {
        binds.push(format!(
            "{}:{}:ro,z",
            sandbox_token_host_path(sandbox, config)?.display(),
            SANDBOX_TOKEN_MOUNT_PATH
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

fn build_environment(sandbox: &DriverSandbox, config: &DockerDriverRuntimeConfig) -> Vec<String> {
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
    environment.insert(
        openshell_core::sandbox_env::SANDBOX_COMMAND.to_string(),
        SANDBOX_COMMAND.to_string(),
    );
    environment.insert(
        openshell_core::sandbox_env::TELEMETRY_ENABLED.to_string(),
        openshell_core::telemetry::enabled_env_value().to_string(),
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

    environment.remove(openshell_core::sandbox_env::SANDBOX_TOKEN);
    environment.remove(openshell_core::sandbox_env::SANDBOX_TOKEN_FILE);

    // Gateway-minted sandbox JWT. Keep the raw bearer out of container
    // metadata; the supervisor reads it from this driver-owned bind mount.
    if let Some(spec) = sandbox.spec.as_ref()
        && !spec.sandbox_token.is_empty()
    {
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

fn build_container_create_body_with_gpu_devices(
    sandbox: &DriverSandbox,
    config: &DockerDriverRuntimeConfig,
    driver_config: &DockerSandboxDriverConfig,
    gpu_device_ids: Option<&[String]>,
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
    // The list/get/find paths filter by `config.sandbox_namespace`, so use
    // the same value here. `DriverSandbox.namespace` is unset on the request
    // path (the gateway elides it), and using it would produce containers
    // that the driver itself cannot find afterwards.
    labels.insert(
        LABEL_SANDBOX_NAMESPACE.to_string(),
        config.sandbox_namespace.clone(),
    );

    Ok(ContainerCreateBody {
        image: Some(template.image.clone()),
        user: Some("0".to_string()),
        env: Some(build_environment(sandbox, config)),
        entrypoint: Some(vec![SUPERVISOR_MOUNT_PATH.to_string()]),
        // Clear the image CMD so Docker does not append inherited args to the
        // supervisor entrypoint.
        cmd: Some(Vec::new()),
        labels: Some(labels),
        host_config: Some(HostConfig {
            nano_cpus: resource_limits.nano_cpus,
            memory: resource_limits.memory_bytes,
            pids_limit: docker_pids_limit(config.sandbox_pids_limit)?,
            device_requests,
            binds: {
                let mut binds = build_binds(sandbox, config)?;
                binds.extend(user_bind_strings);
                Some(binds)
            },
            mounts: Some(user_mounts),
            restart_policy: Some(RestartPolicy {
                name: Some(RestartPolicyNameEnum::UNLESS_STOPPED),
                maximum_retry_count: None,
            }),
            cap_add: Some(vec![
                "SYS_ADMIN".to_string(),
                "NET_ADMIN".to_string(),
                "SYS_PTRACE".to_string(),
                "SYSLOG".to_string(),
            ]),
            // The sandbox supervisor needs to bind-mount `/run/netns`,
            // mark it shared, and create per-process network namespaces.
            // Docker's default AppArmor profile (`docker-default`) denies
            // these mount operations even with CAP_SYS_ADMIN, so we opt
            // out of AppArmor confinement for sandbox containers. The
            // sandbox enforces its own security boundary via Landlock,
            // seccomp, OPA policy evaluation, and the dedicated network
            // namespace it sets up for the agent — AppArmor at the
            // container layer is redundant relative to those controls
            // and conflicts with them in this case.
            security_opt: Some(vec!["apparmor=unconfined".to_string()]),
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

fn sandbox_from_container_summary(
    summary: &ContainerSummary,
    readiness: &dyn SupervisorReadiness,
) -> Option<DriverSandbox> {
    let labels = summary.labels.as_ref()?;
    let id = labels.get(LABEL_SANDBOX_ID)?.clone();
    let name = labels.get(LABEL_SANDBOX_NAME)?.clone();
    let namespace = labels
        .get(LABEL_SANDBOX_NAMESPACE)
        .cloned()
        .unwrap_or_default();

    let supervisor_connected = readiness.is_supervisor_connected(&id);
    Some(DriverSandbox {
        id,
        name: name.clone(),
        namespace,
        spec: None,
        status: Some(driver_status_from_summary(
            summary,
            &name,
            supervisor_connected,
        )),
    })
}

fn driver_status_from_summary(
    summary: &ContainerSummary,
    sandbox_name: &str,
    supervisor_connected: bool,
) -> DriverSandboxStatus {
    let state = summary.state.unwrap_or(ContainerSummaryStateEnum::EMPTY);
    let (ready, reason, message, deleting) = container_ready_condition(state, supervisor_connected);

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

fn container_ready_condition(
    state: ContainerSummaryStateEnum,
    supervisor_connected: bool,
) -> (&'static str, &'static str, &'static str, bool) {
    match state {
        ContainerSummaryStateEnum::RUNNING => {
            if supervisor_connected {
                (
                    "True",
                    "SupervisorConnected",
                    "Supervisor relay is live",
                    false,
                )
            } else {
                (
                    "False",
                    "DependenciesNotReady",
                    "Container is running; waiting for supervisor relay",
                    false,
                )
            }
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
        ContainerSummaryStateEnum::EXITED => {
            ("False", "ContainerExited", "Container exited", false)
        }
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

fn container_state_needs_shutdown_stop(state: ContainerSummaryStateEnum) -> bool {
    matches!(
        state,
        ContainerSummaryStateEnum::RUNNING
            | ContainerSummaryStateEnum::RESTARTING
            | ContainerSummaryStateEnum::PAUSED
    )
}

/// States from which a managed container can be brought back to running by
/// `start_container`. Skip `Restarting` (already coming up), `Removing`,
/// `Dead` (terminal), `Paused` (needs `unpause`, not `start`), and
/// `Running` (nothing to do).
fn container_state_needs_resume(state: ContainerSummaryStateEnum) -> bool {
    matches!(
        state,
        ContainerSummaryStateEnum::EXITED | ContainerSummaryStateEnum::CREATED
    )
}

fn docker_stop_timeout_secs(timeout_secs: u32) -> i32 {
    i32::try_from(timeout_secs).unwrap_or(i32::MAX)
}

fn emit_snapshot_diff(
    events: &broadcast::Sender<WatchSandboxesEvent>,
    previous: &HashMap<String, DriverSandbox>,
    current: &HashMap<String, DriverSandbox>,
) {
    for (sandbox_id, sandbox) in current {
        if previous.get(sandbox_id) == Some(sandbox) {
            continue;
        }
        let _ = events.send(WatchSandboxesEvent {
            payload: Some(watch_sandboxes_event::Payload::Sandbox(
                WatchSandboxesSandboxEvent {
                    sandbox: Some(sandbox.clone()),
                },
            )),
        });
    }

    for sandbox_id in previous.keys() {
        if current.contains_key(sandbox_id) {
            continue;
        }
        let _ = events.send(WatchSandboxesEvent {
            payload: Some(watch_sandboxes_event::Payload::Deleted(
                WatchSandboxesDeletedEvent {
                    sandbox_id: sandbox_id.clone(),
                },
            )),
        });
    }
}

fn label_filters(values: impl IntoIterator<Item = String>) -> HashMap<String, Vec<String>> {
    HashMap::from([("label".to_string(), values.into_iter().collect())])
}

fn managed_container_label_filters(
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
    let name = sanitize_docker_name(&sandbox.name);
    if name.is_empty() {
        let mut base = format!("{CONTAINER_NAME_PREFIX}{id_suffix}");
        // The prefix is always < MAX_CONTAINER_NAME_LEN. Truncate the id
        // suffix only if the sandbox id itself is pathologically long.
        if base.len() > MAX_CONTAINER_NAME_LEN {
            base.truncate(MAX_CONTAINER_NAME_LEN);
        }
        return base;
    }

    // Reserve space for the prefix and the `-<id_suffix>` tail so the id
    // suffix — which is what makes the name unique between sandboxes that
    // share a human-readable prefix — is never truncated away.
    let reserved = CONTAINER_NAME_PREFIX.len() + 1 + id_suffix.len();
    if reserved >= MAX_CONTAINER_NAME_LEN {
        // Pathological sandbox id. Fall back to `<prefix><id>` and truncate.
        let mut base = format!("{CONTAINER_NAME_PREFIX}{id_suffix}");
        base.truncate(MAX_CONTAINER_NAME_LEN);
        return trim_container_name_tail(base);
    }

    let name_budget = MAX_CONTAINER_NAME_LEN - reserved;
    let truncated_name = if name.len() > name_budget {
        trim_container_name_tail(name[..name_budget].to_string())
    } else {
        name
    };
    format!("{CONTAINER_NAME_PREFIX}{truncated_name}-{id_suffix}")
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
        validate_linux_elf_binary(&path)?;
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
    Ok(SupervisorBinSource::Image(default_docker_supervisor_image()))
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

    let cache_path = supervisor_cache_path(&digest)?;
    if cache_path.is_file() {
        validate_linux_elf_binary(&cache_path)?;
        return Ok(cache_path);
    }

    let cache_dir = cache_path.parent().ok_or_else(|| {
        Error::config(format!(
            "docker supervisor cache path '{}' has no parent directory",
            cache_path.display(),
        ))
    })?;
    std::fs::create_dir_all(cache_dir).map_err(|err| {
        Error::config(format!(
            "failed to create docker supervisor cache dir '{}': {err}",
            cache_dir.display(),
        ))
    })?;

    info!(
        image = image,
        digest = digest,
        cache_path = %cache_path.display(),
        "Extracting supervisor binary from image to host cache",
    );

    let binary_bytes = extract_supervisor_binary_bytes(docker, image).await?;
    write_cache_binary_atomic(&cache_path, &binary_bytes)?;
    validate_linux_elf_binary(&cache_path)?;
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

/// Extract the payload of the first regular-file entry in a tar archive.
/// Docker's `/containers/<id>/archive` endpoint returns a single-file tar
/// when `path` points to a file, so we only need the first entry.
fn extract_first_tar_entry(tar_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut archive = tar::Archive::new(std::io::Cursor::new(tar_bytes));
    let mut entries = archive
        .entries()
        .map_err(|err| format!("open tar archive: {err}"))?;
    let mut entry = entries
        .next()
        .ok_or_else(|| "tar archive was empty".to_string())?
        .map_err(|err| format!("read tar entry: {err}"))?;
    let mut bytes = Vec::new();
    entry
        .read_to_end(&mut bytes)
        .map_err(|err| format!("read tar entry payload: {err}"))?;
    Ok(bytes)
}

fn write_cache_binary_atomic(final_path: &Path, bytes: &[u8]) -> CoreResult<()> {
    let dir = final_path.parent().ok_or_else(|| {
        Error::config(format!(
            "docker supervisor cache path '{}' has no parent directory",
            final_path.display(),
        ))
    })?;
    let mut temp = tempfile::Builder::new()
        .prefix(".openshell-sandbox-")
        .tempfile_in(dir)
        .map_err(|err| {
            Error::config(format!(
                "failed to create temp file for supervisor binary in '{}': {err}",
                dir.display(),
            ))
        })?;
    std::io::Write::write_all(&mut temp, bytes).map_err(|err| {
        Error::config(format!(
            "failed to write supervisor binary to temp file: {err}",
        ))
    })?;
    temp.as_file().sync_all().map_err(|err| {
        Error::config(format!("failed to sync supervisor binary temp file: {err}"))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755)).map_err(
            |err| {
                Error::config(format!(
                    "failed to chmod supervisor binary temp file: {err}",
                ))
            },
        )?;
    }

    temp.persist(final_path).map_err(|err| {
        Error::config(format!(
            "failed to rename supervisor binary into '{}': {}",
            final_path.display(),
            err.error,
        ))
    })?;
    Ok(())
}

/// Cache path for an extracted supervisor binary, keyed by the image's
/// content-addressable digest (e.g. `sha256:abc123…`). The digest-prefixed
/// directory keeps stale extractions from earlier releases isolated so they
/// can be GC'd without affecting the active binary.
fn supervisor_cache_path(digest: &str) -> CoreResult<PathBuf> {
    let base = openshell_core::paths::xdg_data_dir()
        .map_err(|err| Error::config(format!("failed to resolve XDG data dir: {err}")))?;
    Ok(supervisor_cache_path_with_base(&base, digest))
}

fn supervisor_cache_path_with_base(base: &Path, digest: &str) -> PathBuf {
    let sanitized = digest.replace(':', "-");
    base.join("openshell")
        .join("docker-supervisor")
        .join(sanitized)
        .join("openshell-sandbox")
}

fn temp_extract_container_name() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let pid = std::process::id();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("openshell-supervisor-extract-{pid}-{seq}")
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

pub(crate) fn validate_linux_elf_binary(path: &Path) -> CoreResult<()> {
    let mut file = std::fs::File::open(path).map_err(|err| {
        Error::config(format!(
            "failed to open docker supervisor binary '{}': {err}",
            path.display()
        ))
    })?;
    let mut magic = [0_u8; 4];
    file.read_exact(&mut magic).map_err(|err| {
        Error::config(format!(
            "failed to read docker supervisor binary '{}': {err}",
            path.display()
        ))
    })?;
    if magic != [0x7f, b'E', b'L', b'F'] {
        return Err(Error::config(format!(
            "docker supervisor binary '{}' must be a Linux ELF executable",
            path.display()
        )));
    }
    Ok(())
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
