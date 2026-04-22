// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bundled Docker compute driver.

use bollard::Docker;
use bollard::errors::Error as BollardError;
use bollard::models::{
    ContainerCreateBody, ContainerSummary, ContainerSummaryStateEnum, HostConfig, Mount,
    MountTypeEnum, RestartPolicy, RestartPolicyNameEnum,
};
use bollard::query_parameters::{
    CreateContainerOptionsBuilder, CreateImageOptions, DownloadFromContainerOptionsBuilder,
    ListContainersOptionsBuilder, RemoveContainerOptionsBuilder,
};
use bytes::Bytes;
use futures::{Stream, StreamExt};
use openshell_core::proto::compute::v1::{
    CreateSandboxRequest, CreateSandboxResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    DriverCondition, DriverSandbox, DriverSandboxStatus, DriverSandboxTemplate,
    GetCapabilitiesRequest, GetCapabilitiesResponse, GetSandboxRequest, GetSandboxResponse,
    ListSandboxesRequest, ListSandboxesResponse, StopSandboxRequest, StopSandboxResponse,
    ValidateSandboxCreateRequest, ValidateSandboxCreateResponse, WatchSandboxesDeletedEvent,
    WatchSandboxesEvent, WatchSandboxesRequest, WatchSandboxesSandboxEvent,
    compute_driver_server::ComputeDriver, watch_sandboxes_event,
};
use openshell_core::{Config, Error, Result as CoreResult};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};
use url::{Host, Url};

const WATCH_BUFFER: usize = 128;
const WATCH_POLL_INTERVAL: Duration = Duration::from_secs(2);
const WATCH_POLL_MAX_BACKOFF: Duration = Duration::from_secs(30);

const MANAGED_BY_LABEL_KEY: &str = "openshell.ai/managed-by";
const MANAGED_BY_LABEL_VALUE: &str = "openshell";
const SANDBOX_ID_LABEL_KEY: &str = "openshell.ai/sandbox-id";
const SANDBOX_NAME_LABEL_KEY: &str = "openshell.ai/sandbox-name";
const SANDBOX_NAMESPACE_LABEL_KEY: &str = "openshell.ai/sandbox-namespace";

const SUPERVISOR_MOUNT_PATH: &str = "/opt/openshell/bin/openshell-sandbox";
#[cfg(test)]
const TLS_MOUNT_DIR: &str = "/etc/openshell/tls/client";
const TLS_CA_MOUNT_PATH: &str = "/etc/openshell/tls/client/ca.crt";
const TLS_CERT_MOUNT_PATH: &str = "/etc/openshell/tls/client/tls.crt";
const TLS_KEY_MOUNT_PATH: &str = "/etc/openshell/tls/client/tls.key";
const SANDBOX_COMMAND: &str = "sleep infinity";
const HOST_OPENSHELL_INTERNAL: &str = "host.openshell.internal";
const HOST_DOCKER_INTERNAL: &str = "host.docker.internal";

/// Default image holding the Linux `openshell-sandbox` binary. The gateway
/// pulls this image and extracts the binary to a host-side cache when no
/// explicit `--docker-supervisor-bin` override or local build is available.
const DEFAULT_DOCKER_SUPERVISOR_IMAGE_REPO: &str = "ghcr.io/nvidia/openshell/supervisor";

/// Image tag baked in at compile time to pair the gateway with a matching
/// supervisor image. Mirrors the pattern used by `openshell-bootstrap`:
/// defaults to `"dev"`; CI overrides with a release version via the
/// `OPENSHELL_IMAGE_TAG` env var during `cargo build`.
const DEFAULT_DOCKER_SUPERVISOR_IMAGE_TAG: &str = match option_env!("OPENSHELL_IMAGE_TAG") {
    Some(tag) => tag,
    None => "dev",
};

/// Path to the supervisor binary inside the `openshell/supervisor` image.
const SUPERVISOR_IMAGE_BINARY_PATH: &str = "/usr/local/bin/openshell-sandbox";

/// Return the default `ghcr.io/nvidia/openshell/supervisor:<tag>` reference
/// used when no supervisor binary override is provided.
pub fn default_docker_supervisor_image() -> String {
    format!("{DEFAULT_DOCKER_SUPERVISOR_IMAGE_REPO}:{DEFAULT_DOCKER_SUPERVISOR_IMAGE_TAG}")
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

/// Gateway-local configuration for the bundled Docker compute driver.
#[derive(Debug, Clone, Default)]
pub struct DockerComputeConfig {
    /// Optional override for the Linux `openshell-sandbox` binary mounted into containers.
    pub supervisor_bin: Option<PathBuf>,

    /// Optional override for the image the gateway pulls to extract the
    /// Linux `openshell-sandbox` binary when no explicit binary path or
    /// local build is available. Defaults to
    /// `ghcr.io/nvidia/openshell/supervisor:<OPENSHELL_IMAGE_TAG>`.
    pub supervisor_image: Option<String>,

    /// Host-side CA certificate for Docker sandbox mTLS.
    pub guest_tls_ca: Option<PathBuf>,

    /// Host-side client certificate for Docker sandbox mTLS.
    pub guest_tls_cert: Option<PathBuf>,

    /// Host-side private key for Docker sandbox mTLS.
    pub guest_tls_key: Option<PathBuf>,
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
    grpc_endpoint: String,
    ssh_socket_path: String,
    ssh_handshake_secret: String,
    ssh_handshake_skew_secs: u64,
    log_level: String,
    supervisor_bin: PathBuf,
    guest_tls: Option<DockerGuestTlsPaths>,
    daemon_version: String,
}

#[derive(Clone)]
pub struct DockerComputeDriver {
    docker: Arc<Docker>,
    config: DockerDriverRuntimeConfig,
    events: broadcast::Sender<WatchSandboxesEvent>,
    supervisor_readiness: Arc<dyn SupervisorReadiness>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct DockerResourceLimits {
    nano_cpus: Option<i64>,
    memory_bytes: Option<i64>,
}

type WatchStream =
    Pin<Box<dyn Stream<Item = Result<WatchSandboxesEvent, Status>> + Send + 'static>>;

impl DockerComputeDriver {
    pub async fn new(
        config: &Config,
        docker_config: &DockerComputeConfig,
        supervisor_readiness: Arc<dyn SupervisorReadiness>,
    ) -> CoreResult<Self> {
        if config.grpc_endpoint.trim().is_empty() {
            return Err(Error::config(
                "grpc_endpoint is required when using the docker compute driver",
            ));
        }

        let docker = Docker::connect_with_local_defaults()
            .map_err(|err| Error::execution(format!("failed to create Docker client: {err}")))?;
        let version = docker.version().await.map_err(|err| {
            Error::execution(format!("failed to query Docker daemon version: {err}"))
        })?;
        let daemon_arch = normalize_docker_arch(version.arch.as_deref().unwrap_or_default());
        let supervisor_bin = resolve_supervisor_bin(&docker, docker_config, &daemon_arch).await?;
        let guest_tls = docker_guest_tls_paths(config, docker_config)?;

        let driver = Self {
            docker: Arc::new(docker),
            config: DockerDriverRuntimeConfig {
                default_image: config.sandbox_image.clone(),
                image_pull_policy: config.sandbox_image_pull_policy.clone(),
                grpc_endpoint: config.grpc_endpoint.clone(),
                ssh_socket_path: config.sandbox_ssh_socket_path.clone(),
                ssh_handshake_secret: config.ssh_handshake_secret.clone(),
                ssh_handshake_skew_secs: config.ssh_handshake_skew_secs,
                log_level: config.log_level.clone(),
                supervisor_bin,
                guest_tls,
                daemon_version: version.version.unwrap_or_else(|| "unknown".to_string()),
            },
            events: broadcast::channel(WATCH_BUFFER).0,
            supervisor_readiness,
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
            supports_gpu: false,
        }
    }

    fn validate_sandbox(&self, sandbox: &DriverSandbox) -> Result<(), Status> {
        let spec = sandbox
            .spec
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("sandbox.spec is required"))?;
        let template = spec
            .template
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("sandbox.spec.template is required"))?;

        if template.image.trim().is_empty() {
            return Err(Status::failed_precondition(
                "docker sandboxes require a template image",
            ));
        }
        if spec.gpu {
            return Err(Status::failed_precondition(
                "docker compute driver does not support gpu sandboxes",
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

        let _ = docker_resource_limits(template)?;
        Ok(())
    }

    async fn get_sandbox_snapshot(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<Option<DriverSandbox>, Status> {
        let container = self
            .find_managed_container_summary(sandbox_id, sandbox_name)
            .await?;
        Ok(container.and_then(|summary| {
            sandbox_from_container_summary(&summary, self.supervisor_readiness.as_ref())
        }))
    }

    async fn current_snapshots(&self) -> Result<Vec<DriverSandbox>, Status> {
        let containers = self.list_managed_container_summaries().await?;
        let mut sandboxes = containers
            .iter()
            .filter_map(|summary| {
                sandbox_from_container_summary(summary, self.supervisor_readiness.as_ref())
            })
            .collect::<Vec<_>>();
        sandboxes.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(sandboxes)
    }

    async fn create_sandbox_inner(&self, sandbox: &DriverSandbox) -> Result<(), Status> {
        self.validate_sandbox(sandbox)?;

        if self
            .find_managed_container_summary(&sandbox.id, &sandbox.name)
            .await?
            .is_some()
        {
            return Err(Status::already_exists("sandbox already exists"));
        }

        let template = sandbox
            .spec
            .as_ref()
            .and_then(|spec| spec.template.as_ref())
            .expect("validated sandbox has template");
        self.ensure_image_available(&template.image).await?;

        let container_name = container_name_for_sandbox(sandbox);
        let create_body = self.build_container_create_body(sandbox)?;
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
                create_status_from_docker_error("create docker sandbox container", err)
            })?;

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
            return Err(create_status_from_docker_error(
                "start docker sandbox container",
                err,
            ));
        }

        Ok(())
    }

    async fn delete_sandbox_inner(
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
        // Prefer the container ID: it's always populated in ContainerSummary,
        // remains valid while the container exists, and is accepted by
        // `remove_container` just like a name. Falling back to the parsed
        // name covers any transient where `id` is missing.
        let Some(target) = container
            .id
            .as_deref()
            .filter(|id| !id.is_empty())
            .map(str::to_string)
            .or_else(|| summary_container_name(&container))
        else {
            return Ok(false);
        };

        match self
            .docker
            .remove_container(
                &target,
                Some(RemoveContainerOptionsBuilder::default().force(true).build()),
            )
            .await
        {
            Ok(()) => Ok(true),
            Err(err) if is_not_found_error(&err) => Ok(false),
            Err(err) => Err(internal_status("delete docker sandbox container", err)),
        }
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
        let filters = label_filters([format!("{MANAGED_BY_LABEL_KEY}={MANAGED_BY_LABEL_VALUE}")]);
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
        let mut label_filter_values =
            vec![format!("{MANAGED_BY_LABEL_KEY}={MANAGED_BY_LABEL_VALUE}")];
        if !sandbox_id.is_empty() {
            label_filter_values.push(format!("{SANDBOX_ID_LABEL_KEY}={sandbox_id}"));
        } else if !sandbox_name.is_empty() {
            label_filter_values.push(format!("{SANDBOX_NAME_LABEL_KEY}={sandbox_name}"));
        }

        let filters = label_filters(label_filter_values);
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
            let id_matches = sandbox_id.is_empty()
                || labels
                    .get(SANDBOX_ID_LABEL_KEY)
                    .is_some_and(|value| value == sandbox_id);
            let name_matches = sandbox_name.is_empty()
                || labels
                    .get(SANDBOX_NAME_LABEL_KEY)
                    .is_some_and(|value| value == sandbox_name);
            id_matches && name_matches
        }))
    }

    async fn ensure_image_available(&self, image: &str) -> Result<(), Status> {
        let policy = self.config.image_pull_policy.trim().to_ascii_lowercase();
        match policy.as_str() {
            "" | "ifnotpresent" => {
                if self.docker.inspect_image(image).await.is_ok() {
                    return Ok(());
                }
                self.pull_image(image).await
            }
            "always" => self.pull_image(image).await,
            "never" => match self.docker.inspect_image(image).await {
                Ok(_) => Ok(()),
                Err(err) if is_not_found_error(&err) => Err(Status::failed_precondition(format!(
                    "docker image '{image}' is not present locally and sandbox_image_pull_policy=Never"
                ))),
                Err(err) => Err(internal_status("inspect Docker image", err)),
            },
            other => Err(Status::failed_precondition(format!(
                "unsupported docker sandbox_image_pull_policy '{other}'; expected Always, IfNotPresent, or Never",
            ))),
        }
    }

    async fn pull_image(&self, image: &str) -> Result<(), Status> {
        let mut stream = self.docker.create_image(
            Some(CreateImageOptions {
                from_image: Some(image.to_string()),
                ..Default::default()
            }),
            None,
            None,
        );
        while let Some(result) = stream.next().await {
            result.map_err(|err| internal_status("pull Docker image", err))?;
        }
        Ok(())
    }

    fn build_container_create_body(
        &self,
        sandbox: &DriverSandbox,
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
        let mut labels = template.labels.clone();
        labels.insert(
            MANAGED_BY_LABEL_KEY.to_string(),
            MANAGED_BY_LABEL_VALUE.to_string(),
        );
        labels.insert(SANDBOX_ID_LABEL_KEY.to_string(), sandbox.id.clone());
        labels.insert(SANDBOX_NAME_LABEL_KEY.to_string(), sandbox.name.clone());
        labels.insert(
            SANDBOX_NAMESPACE_LABEL_KEY.to_string(),
            sandbox.namespace.clone(),
        );

        Ok(ContainerCreateBody {
            image: Some(template.image.clone()),
            user: Some("0".to_string()),
            env: Some(build_environment(sandbox, &self.config)),
            entrypoint: Some(vec![SUPERVISOR_MOUNT_PATH.to_string()]),
            labels: Some(labels),
            host_config: Some(HostConfig {
                nano_cpus: resource_limits.nano_cpus,
                memory: resource_limits.memory_bytes,
                mounts: Some(build_mounts(&self.config)),
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
                extra_hosts: Some(vec![
                    format!("{HOST_DOCKER_INTERNAL}:host-gateway"),
                    format!("{HOST_OPENSHELL_INTERNAL}:host-gateway"),
                ]),
                ..Default::default()
            }),
            ..Default::default()
        })
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
        self.validate_sandbox(&sandbox)?;
        Ok(Response::new(ValidateSandboxCreateResponse {}))
    }

    async fn get_sandbox(
        &self,
        request: Request<GetSandboxRequest>,
    ) -> Result<Response<GetSandboxResponse>, Status> {
        let request = request.into_inner();
        if request.sandbox_id.is_empty() && request.sandbox_name.is_empty() {
            return Err(Status::invalid_argument(
                "sandbox_id or sandbox_name is required",
            ));
        }

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
        _request: Request<StopSandboxRequest>,
    ) -> Result<Response<StopSandboxResponse>, Status> {
        Err(Status::unimplemented(
            "stop sandbox is not implemented by the docker compute driver",
        ))
    }

    async fn delete_sandbox(
        &self,
        request: Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        let request = request.into_inner();
        Ok(Response::new(DeleteSandboxResponse {
            deleted: self
                .delete_sandbox_inner(&request.sandbox_id, &request.sandbox_name)
                .await?,
        }))
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
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(out_rx))))
    }
}

fn build_mounts(config: &DockerDriverRuntimeConfig) -> Vec<Mount> {
    let mut mounts = vec![bind_mount(
        &config.supervisor_bin,
        SUPERVISOR_MOUNT_PATH,
        true,
    )];
    if let Some(tls) = &config.guest_tls {
        mounts.push(bind_mount(&tls.ca, TLS_CA_MOUNT_PATH, true));
        mounts.push(bind_mount(&tls.cert, TLS_CERT_MOUNT_PATH, true));
        mounts.push(bind_mount(&tls.key, TLS_KEY_MOUNT_PATH, true));
    }
    mounts
}

fn bind_mount(source: &Path, target: &str, read_only: bool) -> Mount {
    Mount {
        target: Some(target.to_string()),
        source: Some(source.display().to_string()),
        typ: Some(MountTypeEnum::BIND),
        read_only: Some(read_only),
        ..Default::default()
    }
}

fn build_environment(sandbox: &DriverSandbox, config: &DockerDriverRuntimeConfig) -> Vec<String> {
    let mut environment = HashMap::from([
        ("HOME".to_string(), "/root".to_string()),
        (
            "PATH".to_string(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        ),
        ("TERM".to_string(), "xterm".to_string()),
        (
            "OPENSHELL_LOG_LEVEL".to_string(),
            sandbox_log_level(sandbox, &config.log_level),
        ),
    ]);

    if let Some(spec) = sandbox.spec.as_ref() {
        if let Some(template) = spec.template.as_ref() {
            environment.extend(template.environment.clone());
        }
        environment.extend(spec.environment.clone());
    }

    environment.insert(
        "OPENSHELL_ENDPOINT".to_string(),
        container_visible_openshell_endpoint(&config.grpc_endpoint),
    );
    environment.insert("OPENSHELL_SANDBOX_ID".to_string(), sandbox.id.clone());
    environment.insert("OPENSHELL_SANDBOX".to_string(), sandbox.name.clone());
    environment.insert(
        "OPENSHELL_SSH_SOCKET_PATH".to_string(),
        config.ssh_socket_path.clone(),
    );
    environment.insert(
        "OPENSHELL_SANDBOX_COMMAND".to_string(),
        SANDBOX_COMMAND.to_string(),
    );
    environment.insert(
        "OPENSHELL_SSH_HANDSHAKE_SECRET".to_string(),
        config.ssh_handshake_secret.clone(),
    );
    environment.insert(
        "OPENSHELL_SSH_HANDSHAKE_SKEW_SECS".to_string(),
        config.ssh_handshake_skew_secs.to_string(),
    );
    if config.guest_tls.is_some() {
        environment.insert(
            "OPENSHELL_TLS_CA".to_string(),
            TLS_CA_MOUNT_PATH.to_string(),
        );
        environment.insert(
            "OPENSHELL_TLS_CERT".to_string(),
            TLS_CERT_MOUNT_PATH.to_string(),
        );
        environment.insert(
            "OPENSHELL_TLS_KEY".to_string(),
            TLS_KEY_MOUNT_PATH.to_string(),
        );
    }

    let mut pairs = environment.into_iter().collect::<Vec<_>>();
    pairs.sort_by(|left, right| left.0.cmp(&right.0));
    pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect()
}

fn sandbox_log_level(sandbox: &DriverSandbox, default_level: &str) -> String {
    sandbox
        .spec
        .as_ref()
        .map(|spec| spec.log_level.as_str())
        .filter(|level| !level.is_empty())
        .unwrap_or(default_level)
        .to_string()
}

fn container_visible_openshell_endpoint(endpoint: &str) -> String {
    let Ok(mut url) = Url::parse(endpoint) else {
        return endpoint.to_string();
    };

    let should_rewrite = match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback() || ip.is_unspecified(),
        Some(Host::Ipv6(ip)) => ip.is_loopback() || ip.is_unspecified(),
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        None => false,
    };

    if should_rewrite && url.set_host(Some(HOST_OPENSHELL_INTERNAL)).is_ok() {
        return url.to_string();
    }

    endpoint.to_string()
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
    let id = labels.get(SANDBOX_ID_LABEL_KEY)?.clone();
    let name = labels.get(SANDBOX_NAME_LABEL_KEY)?.clone();
    let namespace = labels
        .get(SANDBOX_NAMESPACE_LABEL_KEY)
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
        ContainerSummaryStateEnum::RESTARTING => {
            ("False", "Starting", "Container restarting", false)
        }
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

pub(crate) async fn resolve_supervisor_bin(
    docker: &Docker,
    docker_config: &DockerComputeConfig,
    daemon_arch: &str,
) -> CoreResult<PathBuf> {
    // Tier 1: explicit --docker-supervisor-bin / OPENSHELL_DOCKER_SUPERVISOR_BIN.
    if let Some(path) = docker_config.supervisor_bin.clone() {
        let path = canonicalize_existing_file(&path, "docker supervisor binary")?;
        validate_linux_elf_binary(&path)?;
        return Ok(path);
    }

    // Tier 2: sibling `openshell-sandbox` next to the running gateway
    // (release artifact layout). Linux-only because the sibling must be a
    // Linux ELF to bind-mount into a Linux container.
    if cfg!(target_os = "linux") {
        let current_exe = std::env::current_exe()
            .map_err(|err| Error::config(format!("failed to resolve current executable: {err}")))?;
        if let Some(parent) = current_exe.parent() {
            let sibling = parent.join("openshell-sandbox");
            if sibling.is_file() {
                let path = canonicalize_existing_file(&sibling, "docker supervisor binary")?;
                if validate_linux_elf_binary(&path).is_ok() {
                    return Ok(path);
                }
            }
        }
    }

    // Tier 3: local cargo target build (developer workflow). Preferred
    // over a registry pull when available because it matches whatever the
    // developer just built.
    let target_candidates = linux_supervisor_candidates(daemon_arch);
    for candidate in &target_candidates {
        if candidate.is_file() {
            let path = canonicalize_existing_file(candidate, "docker supervisor binary")?;
            if validate_linux_elf_binary(&path).is_ok() {
                return Ok(path);
            }
        }
    }

    // Tier 4: pull the supervisor image from a registry and extract the
    // binary to a host-side cache keyed by image content digest. This is
    // the default path for released gateway binaries.
    let image = docker_config
        .supervisor_image
        .clone()
        .unwrap_or_else(default_docker_supervisor_image);
    extract_supervisor_bin_from_image(docker, &image).await
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
/// `/usr/local/bin/openshell-sandbox` to a host cache keyed by the image's
/// content digest, and return the cache path.
///
/// The extraction is atomic: the binary is written to a sibling temp file
/// inside the digest-keyed directory and renamed into place, so concurrent
/// gateway starts don't observe a partial file.
async fn extract_supervisor_bin_from_image(docker: &Docker, image: &str) -> CoreResult<PathBuf> {
    // Inspect first to see if the image is already present; only pull on miss.
    let inspect = match docker.inspect_image(image).await {
        Ok(inspect) => inspect,
        Err(err) if is_not_found_error(&err) => {
            info!(image = image, "Pulling docker supervisor image");
            pull_supervisor_image(docker, image).await?;
            docker.inspect_image(image).await.map_err(|err| {
                Error::config(format!(
                    "failed to inspect docker supervisor image '{image}' after pull: {err}",
                ))
            })?
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
                entrypoint: Some(vec!["/bin/true".to_string()]),
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
    let mut bytes = Vec::with_capacity(entry.size() as usize);
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
        Error::config(format!("failed to sync supervisor binary temp file: {err}",))
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

pub(crate) fn docker_guest_tls_paths(
    config: &Config,
    docker_config: &DockerComputeConfig,
) -> CoreResult<Option<DockerGuestTlsPaths>> {
    let tls_flags_provided = docker_config.guest_tls_ca.is_some()
        || docker_config.guest_tls_cert.is_some()
        || docker_config.guest_tls_key.is_some();

    if !config.grpc_endpoint.starts_with("https://") {
        if tls_flags_provided {
            return Err(Error::config(format!(
                "--docker-tls-ca/--docker-tls-cert/--docker-tls-key were provided but OPENSHELL_GRPC_ENDPOINT is '{}'; TLS materials require an https:// endpoint",
                config.grpc_endpoint,
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
            "docker compute driver requires --docker-tls-ca, --docker-tls-cert, and --docker-tls-key when OPENSHELL_GRPC_ENDPOINT uses https://",
        ));
    }

    let Some(ca) = docker_config.guest_tls_ca.clone() else {
        return Err(Error::config(
            "--docker-tls-ca is required when Docker sandbox TLS materials are configured",
        ));
    };
    let Some(cert) = docker_config.guest_tls_cert.clone() else {
        return Err(Error::config(
            "--docker-tls-cert is required when Docker sandbox TLS materials are configured",
        ));
    };
    let Some(key) = docker_config.guest_tls_key.clone() else {
        return Err(Error::config(
            "--docker-tls-key is required when Docker sandbox TLS materials are configured",
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
mod tests {
    use super::*;
    use openshell_core::proto::compute::v1::{
        DriverResourceRequirements, DriverSandboxSpec, DriverSandboxTemplate,
    };
    use std::fs;
    use tempfile::TempDir;

    fn test_sandbox() -> DriverSandbox {
        DriverSandbox {
            id: "sbx-123".to_string(),
            name: "demo".to_string(),
            namespace: "default".to_string(),
            spec: Some(DriverSandboxSpec {
                log_level: "debug".to_string(),
                environment: HashMap::from([("SPEC_ENV".to_string(), "spec".to_string())]),
                template: Some(DriverSandboxTemplate {
                    image: "ghcr.io/nvidia/openshell/sandbox:dev".to_string(),
                    agent_socket_path: String::new(),
                    labels: HashMap::new(),
                    environment: HashMap::from([(
                        "TEMPLATE_ENV".to_string(),
                        "template".to_string(),
                    )]),
                    resources: None,
                    platform_config: None,
                }),
                gpu: false,
            }),
            status: None,
        }
    }

    fn runtime_config() -> DockerDriverRuntimeConfig {
        DockerDriverRuntimeConfig {
            default_image: "image:latest".to_string(),
            image_pull_policy: String::new(),
            grpc_endpoint: "https://localhost:8443".to_string(),
            ssh_socket_path: "/run/openshell/ssh.sock".to_string(),
            ssh_handshake_secret: "secret".to_string(),
            ssh_handshake_skew_secs: 300,
            log_level: "info".to_string(),
            supervisor_bin: PathBuf::from("/tmp/openshell-sandbox"),
            guest_tls: Some(DockerGuestTlsPaths {
                ca: PathBuf::from("/tmp/ca.crt"),
                cert: PathBuf::from("/tmp/tls.crt"),
                key: PathBuf::from("/tmp/tls.key"),
            }),
            daemon_version: "28.0.0".to_string(),
        }
    }

    #[test]
    fn container_visible_endpoint_rewrites_loopback_hosts() {
        assert_eq!(
            container_visible_openshell_endpoint("https://localhost:8443"),
            "https://host.openshell.internal:8443/"
        );
        assert_eq!(
            container_visible_openshell_endpoint("http://127.0.0.1:8080"),
            "http://host.openshell.internal:8080/"
        );
        assert_eq!(
            container_visible_openshell_endpoint("https://gateway.internal:8443"),
            "https://gateway.internal:8443"
        );
    }

    #[test]
    fn parse_cpu_limit_supports_cores_and_millicores() {
        assert_eq!(parse_cpu_limit("250m").unwrap(), Some(250_000_000));
        assert_eq!(parse_cpu_limit("2").unwrap(), Some(2_000_000_000));
        assert!(parse_cpu_limit("0").is_err());
    }

    #[test]
    fn parse_memory_limit_supports_binary_quantities() {
        assert_eq!(parse_memory_limit("512Mi").unwrap(), Some(536_870_912));
        assert_eq!(parse_memory_limit("1G").unwrap(), Some(1_000_000_000));
        assert!(parse_memory_limit("12XB").is_err());
    }

    #[test]
    fn docker_resource_limits_rejects_requests() {
        let template = DriverSandboxTemplate {
            image: "img".to_string(),
            agent_socket_path: String::new(),
            labels: HashMap::new(),
            environment: HashMap::new(),
            resources: Some(DriverResourceRequirements {
                cpu_request: "250m".to_string(),
                cpu_limit: String::new(),
                memory_request: String::new(),
                memory_limit: String::new(),
            }),
            platform_config: None,
        };

        let err = docker_resource_limits(&template).unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("resources.requests.cpu"));
    }

    #[test]
    fn build_environment_sets_docker_tls_paths() {
        let env = build_environment(&test_sandbox(), &runtime_config());
        assert!(env.contains(&format!("OPENSHELL_TLS_CA={TLS_CA_MOUNT_PATH}")));
        assert!(env.contains(&format!("OPENSHELL_TLS_CERT={TLS_CERT_MOUNT_PATH}")));
        assert!(env.contains(&format!("OPENSHELL_TLS_KEY={TLS_KEY_MOUNT_PATH}")));
        assert!(env.contains(&"TEMPLATE_ENV=template".to_string()));
        assert!(env.contains(&"SPEC_ENV=spec".to_string()));
        assert!(env.contains(&"OPENSHELL_SANDBOX_COMMAND=sleep infinity".to_string()));
    }

    #[test]
    fn build_mounts_uses_docker_tls_directory() {
        let mounts = build_mounts(&runtime_config());
        let targets = mounts
            .iter()
            .filter_map(|mount| mount.target.clone())
            .collect::<Vec<_>>();
        assert!(targets.contains(&SUPERVISOR_MOUNT_PATH.to_string()));
        assert!(targets.contains(&TLS_CA_MOUNT_PATH.to_string()));
        assert!(targets.contains(&TLS_CERT_MOUNT_PATH.to_string()));
        assert!(targets.contains(&TLS_KEY_MOUNT_PATH.to_string()));
        assert!(
            targets
                .iter()
                .all(|target| target.starts_with(TLS_MOUNT_DIR) || target == SUPERVISOR_MOUNT_PATH)
        );
    }

    #[test]
    fn driver_status_keeps_running_sandboxes_provisioning_with_stable_message() {
        let running = ContainerSummary {
            id: Some("cid".to_string()),
            names: Some(vec!["/openshell-demo".to_string()]),
            labels: Some(HashMap::from([
                (SANDBOX_ID_LABEL_KEY.to_string(), "sbx-1".to_string()),
                (SANDBOX_NAME_LABEL_KEY.to_string(), "demo".to_string()),
                (
                    SANDBOX_NAMESPACE_LABEL_KEY.to_string(),
                    "default".to_string(),
                ),
            ])),
            state: Some(ContainerSummaryStateEnum::RUNNING),
            status: Some("Up 2 seconds".to_string()),
            ..Default::default()
        };
        let exited = ContainerSummary {
            state: Some(ContainerSummaryStateEnum::EXITED),
            status: Some("Exited (1) 3 seconds ago".to_string()),
            ..running.clone()
        };
        let running_later = ContainerSummary {
            status: Some("Up 4 seconds".to_string()),
            ..running.clone()
        };

        let running_status = driver_status_from_summary(&running, "demo", false);
        let running_later_status = driver_status_from_summary(&running_later, "demo", false);
        assert_eq!(running_status.conditions[0].status, "False");
        assert_eq!(running_status.conditions[0].reason, "DependenciesNotReady");
        assert_eq!(
            running_status.conditions[0].message,
            "Container is running; waiting for supervisor relay"
        );
        assert_eq!(running_status.conditions, running_later_status.conditions);

        let exited_status = driver_status_from_summary(&exited, "demo", false);
        assert_eq!(exited_status.conditions[0].status, "False");
        assert_eq!(exited_status.conditions[0].reason, "ContainerExited");
        assert_eq!(exited_status.conditions[0].message, "Container exited");

        // With a live supervisor session, a RUNNING container flips Ready=True
        // so ExecSandbox and other "sandbox must be ready" gates can proceed.
        let running_connected = driver_status_from_summary(&running, "demo", true);
        assert_eq!(running_connected.conditions[0].status, "True");
        assert_eq!(
            running_connected.conditions[0].reason,
            "SupervisorConnected"
        );

        // Supervisor readiness is ignored for non-RUNNING states — an exited
        // container must not report Ready=True.
        let exited_connected = driver_status_from_summary(&exited, "demo", true);
        assert_eq!(exited_connected.conditions[0].status, "False");
    }

    #[test]
    fn validate_linux_elf_binary_rejects_non_elf_files() {
        let tempdir = TempDir::new().unwrap();
        let path = tempdir.path().join("openshell-sandbox");
        fs::write(&path, b"not-elf").unwrap();

        let err = validate_linux_elf_binary(&path).unwrap_err();
        assert!(err.to_string().contains("Linux ELF executable"));
    }

    #[test]
    fn docker_guest_tls_paths_require_all_files_for_https() {
        let config = Config::new(None).with_grpc_endpoint("https://localhost:8443");
        let tempdir = TempDir::new().unwrap();
        let ca = tempdir.path().join("ca.crt");
        fs::write(&ca, b"ca").unwrap();

        let err = docker_guest_tls_paths(
            &config,
            &DockerComputeConfig {
                guest_tls_ca: Some(ca),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("--docker-tls-cert"));
    }

    #[test]
    fn linux_supervisor_candidates_follow_daemon_arch() {
        assert_eq!(
            linux_supervisor_candidates("amd64"),
            vec![PathBuf::from(
                "target/x86_64-unknown-linux-gnu/release/openshell-sandbox",
            )]
        );
        assert_eq!(
            linux_supervisor_candidates("arm64"),
            vec![PathBuf::from(
                "target/aarch64-unknown-linux-gnu/release/openshell-sandbox",
            )]
        );
    }

    #[test]
    fn container_name_preserves_id_suffix_for_long_names() {
        // Names up to 253 chars are permitted by the gRPC layer. The id
        // suffix is what makes the container name unique between sandboxes
        // sharing a prefix, so it must always appear in the final name.
        let long_name = "a".repeat(253);
        let first = DriverSandbox {
            id: "sbx-first-1234567890".to_string(),
            name: long_name.clone(),
            namespace: "default".to_string(),
            spec: None,
            status: None,
        };
        let second = DriverSandbox {
            id: "sbx-second-0987654321".to_string(),
            ..first.clone()
        };

        let first_container = container_name_for_sandbox(&first);
        let second_container = container_name_for_sandbox(&second);

        assert!(
            first_container.len() <= MAX_CONTAINER_NAME_LEN,
            "container name {} exceeded {MAX_CONTAINER_NAME_LEN} chars: {first_container}",
            first_container.len(),
        );
        assert!(
            first_container.ends_with(&first.id),
            "container name should end with sandbox id: {first_container}",
        );
        assert_ne!(
            first_container, second_container,
            "container names must differ for sandboxes with distinct ids",
        );
    }

    #[test]
    fn container_name_empty_sandbox_name_uses_id_only() {
        let sandbox = DriverSandbox {
            id: "sbx-abc".to_string(),
            name: String::new(),
            namespace: "default".to_string(),
            spec: None,
            status: None,
        };
        assert_eq!(container_name_for_sandbox(&sandbox), "openshell-sbx-abc",);
    }

    #[test]
    fn trim_container_name_tail_strips_separators() {
        assert_eq!(trim_container_name_tail("foo-".to_string()), "foo");
        assert_eq!(trim_container_name_tail("foo-.".to_string()), "foo");
        assert_eq!(trim_container_name_tail("foo_-.".to_string()), "foo");
        assert_eq!(trim_container_name_tail("foo".to_string()), "foo");
    }

    #[test]
    fn docker_guest_tls_paths_rejects_tls_flags_without_https() {
        let config = Config::new(None).with_grpc_endpoint("http://localhost:8080");
        let tempdir = TempDir::new().unwrap();
        let ca = tempdir.path().join("ca.crt");
        fs::write(&ca, b"ca").unwrap();

        let err = docker_guest_tls_paths(
            &config,
            &DockerComputeConfig {
                guest_tls_ca: Some(ca),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("https://"));
    }

    #[test]
    fn docker_guest_tls_paths_allows_plain_http_without_tls_flags() {
        let config = Config::new(None).with_grpc_endpoint("http://localhost:8080");
        let result = docker_guest_tls_paths(
            &config,
            &DockerComputeConfig {
                ..Default::default()
            },
        )
        .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn default_docker_supervisor_image_uses_nvidia_ghcr_repo() {
        let image = default_docker_supervisor_image();
        assert!(
            image.starts_with("ghcr.io/nvidia/openshell/supervisor:"),
            "unexpected default image reference: {image}",
        );
    }

    #[test]
    fn supervisor_cache_path_namespaces_by_digest_under_openshell_data_dir() {
        let base = PathBuf::from("/var/cache/share");
        let path = supervisor_cache_path_with_base(
            &base,
            "sha256:abc123deadbeef0123456789cafe0123456789fe",
        );

        assert_eq!(
            path,
            PathBuf::from(
                "/var/cache/share/openshell/docker-supervisor/sha256-abc123deadbeef0123456789cafe0123456789fe/openshell-sandbox",
            ),
        );
    }

    #[test]
    fn supervisor_cache_path_isolates_different_digests() {
        let base = PathBuf::from("/data");
        let left = supervisor_cache_path_with_base(&base, "sha256:aaaaaaaa");
        let right = supervisor_cache_path_with_base(&base, "sha256:bbbbbbbb");
        assert_ne!(
            left.parent().unwrap(),
            right.parent().unwrap(),
            "digest-keyed directories must differ so rollouts are isolated",
        );
    }

    #[test]
    fn write_cache_binary_atomic_materializes_file_with_executable_mode() {
        let tempdir = TempDir::new().unwrap();
        let target = tempdir.path().join("nested").join("openshell-sandbox");
        fs::create_dir_all(target.parent().unwrap()).unwrap();

        write_cache_binary_atomic(&target, b"\x7fELFpayload").unwrap();

        assert!(target.is_file());
        assert_eq!(fs::read(&target).unwrap(), b"\x7fELFpayload");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o755, "expected 0755, got {mode:04o}");
        }
    }

    #[test]
    fn write_cache_binary_atomic_overwrites_existing_file() {
        let tempdir = TempDir::new().unwrap();
        let target = tempdir.path().join("openshell-sandbox");
        fs::write(&target, b"stale").unwrap();

        write_cache_binary_atomic(&target, b"\x7fELFfresh").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"\x7fELFfresh");
    }

    #[test]
    fn temp_extract_container_names_are_unique_per_call() {
        let first = temp_extract_container_name();
        let second = temp_extract_container_name();
        assert_ne!(first, second);
        assert!(first.starts_with("openshell-supervisor-extract-"));
    }

    #[test]
    fn extract_first_tar_entry_returns_payload_of_single_file_archive() {
        // Build a tar archive with the same shape Docker returns from
        // `/containers/<id>/archive` for a single file.
        let payload = b"\x7fELFtest-binary-bytes";
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            let mut header = tar::Header::new_gnu();
            header.set_path("openshell-sandbox").unwrap();
            header.set_size(payload.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append(&header, payload.as_slice()).unwrap();
            builder.finish().unwrap();
        }

        let extracted = extract_first_tar_entry(&tar_buf).unwrap();
        assert_eq!(extracted, payload);
    }

    #[test]
    fn extract_first_tar_entry_rejects_empty_archive() {
        let mut tar_buf = Vec::new();
        tar::Builder::new(&mut tar_buf).finish().unwrap();
        let err = extract_first_tar_entry(&tar_buf).unwrap_err();
        assert!(err.contains("empty"), "unexpected error message: {err}");
    }
}
