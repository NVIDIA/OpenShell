// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Podman compute driver.

use crate::client::{ContainerListEntry, PodmanApiError, PodmanClient, VolumeInspect};
use crate::config::{PodmanComputeConfig, podman_image_pull_policy};
use crate::container::{self, LABEL_MANAGED_FILTER, LABEL_SANDBOX_ID, PodmanSandboxDriverConfig};
use crate::watcher::{
    self, LifecycleEventFences, WatchStream, driver_sandbox_from_inspect,
    driver_sandbox_from_list_entry,
};
use openshell_core::ComputeDriverError;
use openshell_core::config::CDI_GPU_DEVICE_ALL;
use openshell_core::driver_utils::{
    SANDBOX_RUNTIME_IMAGE_BINARY_PATH, extract_first_tar_entry, supervisor_image_should_refresh,
    temp_extract_container_name, validate_linux_elf_binary, write_cache_binary_atomic,
};
use openshell_core::gpu::{
    CdiGpuDefaultSelector, CdiGpuInventory, CdiGpuSelectionError, driver_gpu_requirements,
    effective_driver_gpu_count, validate_specific_gpu_device_request,
};
use openshell_core::proto::compute::v1::{
    CpuResourceCapabilities, DriverSandbox, GetCapabilitiesResponse, GpuResourceCapabilities,
    GpuResourceRequirements, MemoryResourceCapabilities, ResourceCapabilities,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::{Instrument as _, debug, info, warn};

const STOP_COMPLETION_POLL_INTERVAL: Duration = Duration::from_millis(50);
const STOP_COMPLETION_TIMEOUT_HEADROOM: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PodmanEndpointEnvironment {
    LinuxHost,
    PodmanMachine,
}

impl PodmanEndpointEnvironment {
    const fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::LinuxHost
        } else {
            Self::PodmanMachine
        }
    }

    const fn gateway_host(self) -> &'static str {
        match self {
            Self::LinuxHost => "127.0.0.1",
            Self::PodmanMachine => "host.containers.internal",
        }
    }
}

fn select_grpc_endpoint(
    config: &PodmanComputeConfig,
    environment: PodmanEndpointEnvironment,
) -> String {
    if !config.grpc_endpoint.is_empty() {
        return config.grpc_endpoint.clone();
    }

    let scheme = if config.tls_enabled() {
        "https"
    } else {
        "http"
    };
    format!(
        "{scheme}://{}:{}",
        environment.gateway_host(),
        config.gateway_port
    )
}

fn decode_launch_authentication(
    encoded: &[u8],
) -> Result<openshell_core::jwt::SandboxLaunchAuthentication, ComputeDriverError> {
    let authentication =
        serde_json::from_slice::<openshell_core::jwt::SandboxLaunchAuthentication>(encoded)
            .map_err(|error| {
                ComputeDriverError::Precondition(format!(
                    "decode Podman sandbox launch authentication: {error}"
                ))
            })?;
    authentication.validate().map_err(|error| {
        ComputeDriverError::Precondition(format!(
            "validate Podman sandbox launch authentication: {error}"
        ))
    })?;
    Ok(authentication)
}

impl From<PodmanApiError> for ComputeDriverError {
    fn from(value: PodmanApiError) -> Self {
        match value {
            PodmanApiError::Conflict(_) => Self::AlreadyExists,
            PodmanApiError::NotFound(_) => Self::NotFound,
            other => Self::Message(other.to_string()),
        }
    }
}

/// Podman compute driver managing sandbox containers via the Podman REST API.
#[derive(Clone)]
pub struct PodmanComputeDriver {
    client: PodmanClient,
    config: PodmanComputeConfig,
    /// Whether Podman's service is running without root privileges.
    rootless: bool,
    gpu_selector: Arc<CdiGpuDefaultSelector>,
    gpu_inventory_refresh: Arc<dyn Fn() -> (CdiGpuInventory, bool) + Send + Sync>,
    lifecycle_event_fences: LifecycleEventFences,
}

impl std::fmt::Debug for PodmanComputeDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PodmanComputeDriver")
            .field("socket_path", &self.config.socket_path)
            .field("default_image", &self.config.default_image)
            .field("network_name", &self.config.network_name)
            .field("rootless", &self.rootless)
            .field("gpu_inventory", &self.gpu_selector.device_ids())
            .finish()
    }
}

struct ValidatedPodmanSandbox<'a> {
    driver_config: PodmanSandboxDriverConfig,
    gpu_requirements: Option<&'a GpuResourceRequirements>,
}

/// Construct and validate a container name from a sandbox.
///
/// Combines the prefix with workspace, name, and ID, then validates the
/// result against Podman's naming rules before any resources are created.
fn validated_container_name(sandbox: &DriverSandbox) -> Result<String, ComputeDriverError> {
    let name = container::container_name(&sandbox.workspace, &sandbox.name, &sandbox.id);
    crate::client::validate_name(&name)
        .map_err(|e| ComputeDriverError::Precondition(e.to_string()))?;
    Ok(name)
}

fn podman_volume_is_bind_backed(volume: &VolumeInspect) -> bool {
    (volume.driver.is_empty() || volume.driver == "local")
        && volume.options.get("o").is_some_and(|options| {
            options.split(',').any(|option| {
                let option = option.trim();
                option.eq_ignore_ascii_case("bind") || option.eq_ignore_ascii_case("rbind")
            })
        })
}

async fn create_sandbox_token_secret(
    client: &PodmanClient,
    sandbox: &DriverSandbox,
) -> Result<Option<String>, ComputeDriverError> {
    let Some(token) = sandbox
        .spec
        .as_ref()
        .map(|spec| spec.sandbox_token.trim())
        .filter(|token| !token.is_empty())
    else {
        return Ok(None);
    };

    let secret_name = container::token_secret_name(&sandbox.id);
    client
        .create_secret(&secret_name, format!("{token}\n").as_bytes())
        .await
        .map_err(ComputeDriverError::from)?;
    Ok(Some(secret_name))
}

async fn cleanup_sandbox_token_secret(client: &PodmanClient, secret_name: &str) {
    if let Err(err) = client.remove_secret(secret_name).await {
        warn!(
            secret = %secret_name,
            error = %err,
            "Failed to remove Podman sandbox token secret"
        );
    }
}

/// Read the operator's proxy credentials file and stage it as a per-sandbox
/// Podman secret, so the credentials reach the supervisor through a root-only
/// mount rather than the container environment.
///
/// Fails closed: when `proxy_auth_file` is configured but cannot be read or
/// does not hold a valid `user:pass` credential, the sandbox is not created.
/// Credential validation is shared with the in-container supervisor through
/// [`openshell_core::driver_utils::parse_upstream_proxy_credential`], so a
/// credential staged here can never be rejected at supervisor startup.
async fn create_sandbox_proxy_auth_secret(
    client: &PodmanClient,
    config: &PodmanComputeConfig,
    sandbox: &DriverSandbox,
) -> Result<Option<String>, ComputeDriverError> {
    let Some(path) = config.proxy_auth_file.as_deref() else {
        return Ok(None);
    };

    // Bounded, blocking read shared with the supervisor: rejects non-regular
    // files (e.g. /dev/zero) and caps the size so a hostile path cannot
    // exhaust gateway memory.
    let path_owned = path.to_string();
    let raw = tokio::task::spawn_blocking(move || {
        openshell_core::driver_utils::read_upstream_proxy_credential_file(&path_owned)
    })
    .await
    .map_err(|e| ComputeDriverError::Message(format!("proxy_auth_file read task failed: {e}")))?
    .map_err(ComputeDriverError::Message)?;
    let credential =
        openshell_core::driver_utils::parse_upstream_proxy_credential(&raw).map_err(|err| {
            ComputeDriverError::InvalidArgument(format!("proxy_auth_file '{path}': {err}"))
        })?;

    let secret_name = container::proxy_auth_secret_name(&sandbox.id);
    client
        .create_secret(&secret_name, format!("{credential}\n").as_bytes())
        .await
        .map_err(ComputeDriverError::from)?;
    Ok(Some(secret_name))
}

/// Fail-closed readability check for the corporate proxy CA bundle.
///
/// When `proxy_ca_bundle` is configured the host PEM is bind-mounted read-only
/// into the sandbox; verifying up front that it exists and is a non-empty
/// regular file turns a missing path into a clear `proxy_ca_bundle` error at
/// sandbox-create time instead of an opaque bind-mount failure. The supervisor
/// independently validates the certificate content (fail-closed) at startup.
async fn validate_sandbox_proxy_ca_bundle(
    config: &PodmanComputeConfig,
) -> Result<(), ComputeDriverError> {
    let Some(path) = config.proxy_ca_bundle.as_deref() else {
        return Ok(());
    };
    let path_owned = path.to_string();
    let metadata = tokio::task::spawn_blocking(move || std::fs::metadata(&path_owned))
        .await
        .map_err(|e| ComputeDriverError::Message(format!("proxy_ca_bundle stat task failed: {e}")))?
        .map_err(|err| {
            ComputeDriverError::InvalidArgument(format!(
                "proxy_ca_bundle '{path}' could not be read: {err}"
            ))
        })?;
    if !metadata.is_file() {
        return Err(ComputeDriverError::InvalidArgument(format!(
            "proxy_ca_bundle '{path}' is not a regular file"
        )));
    }
    if metadata.len() == 0 {
        return Err(ComputeDriverError::InvalidArgument(format!(
            "proxy_ca_bundle '{path}' is empty"
        )));
    }
    Ok(())
}

async fn cleanup_sandbox_proxy_auth_secret(client: &PodmanClient, secret_name: &str) {
    if let Err(err) = client.remove_secret(secret_name).await {
        warn!(
            secret = %secret_name,
            error = %err,
            "Failed to remove Podman sandbox proxy-auth secret"
        );
    }
}

async fn create_tls_secrets(
    client: &PodmanClient,
    config: &PodmanComputeConfig,
    names: &[String; 3],
) -> Result<(), ComputeDriverError> {
    let paths = [
        config.guest_tls_ca.as_deref(),
        config.guest_tls_cert.as_deref(),
        config.guest_tls_key.as_deref(),
    ];
    let mut created = 0usize;
    for (name, path) in names.iter().zip(paths.iter()) {
        let Some(p) = path else { continue };
        let result = async {
            let data = std::fs::read(p).map_err(|e| {
                ComputeDriverError::Message(format!("read TLS file '{}': {e}", p.display()))
            })?;
            client
                .create_secret(name, &data)
                .await
                .map_err(ComputeDriverError::from)
        }
        .await;
        if let Err(e) = result {
            for prev in &names[..created] {
                let _ = client.remove_secret(prev).await;
            }
            return Err(e);
        }
        created += 1;
    }
    Ok(())
}

async fn cleanup_tls_secrets(client: &PodmanClient, names: &[String; 3]) {
    for name in names {
        if let Err(err) = client.remove_secret(name).await {
            warn!(
                secret = %name,
                error = %err,
                "Failed to remove TLS secret"
            );
        }
    }
}

fn local_podman_cdi_gpu_inventory_from(dev_root: &Path) -> CdiGpuInventory {
    let mut device_ids = std::fs::read_dir(dev_root)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_str()?;
            let index = name.strip_prefix("nvidia")?;
            (!index.is_empty() && index.chars().all(|ch| ch.is_ascii_digit()))
                .then(|| format!("nvidia.com/gpu={index}"))
        })
        .collect::<Vec<_>>();
    if local_podman_all_gpu_default_supported_from(dev_root) {
        device_ids.push(CDI_GPU_DEVICE_ALL.to_string());
    }

    CdiGpuInventory::new(device_ids)
}

fn local_podman_cdi_gpu_inventory() -> CdiGpuInventory {
    local_podman_cdi_gpu_inventory_from(Path::new("/dev"))
}

fn local_podman_all_gpu_default_supported_from(dev_root: &Path) -> bool {
    dev_root.join("dxg").exists()
}

fn local_podman_all_gpu_default_supported() -> bool {
    local_podman_all_gpu_default_supported_from(Path::new("/dev"))
}

fn local_podman_gpu_selector_state() -> (CdiGpuInventory, bool) {
    (
        local_podman_cdi_gpu_inventory(),
        local_podman_all_gpu_default_supported(),
    )
}

fn podman_gpu_selection_error(err: CdiGpuSelectionError) -> ComputeDriverError {
    ComputeDriverError::Precondition(err.to_string())
}

/// Return the first responsive local Podman API socket.
#[must_use]
pub fn detect_socket() -> Option<PathBuf> {
    crate::socket_discovery::detect_socket()
}

#[must_use]
pub fn is_available() -> bool {
    detect_socket().is_some()
}

/// Resolve the socket to connect to: explicit configuration wins, otherwise
/// fall back to `detect`. Returns an error if neither resolves.
///
/// Takes `detect` as a parameter so tests can
/// exercise the precedence deterministically, without touching real
/// environment variables or the filesystem.
fn resolve_socket_path(
    configured: Option<PathBuf>,
    detect: impl FnOnce() -> Option<PathBuf>,
) -> Result<PathBuf, PodmanApiError> {
    configured.or_else(detect).ok_or_else(|| {
        PodmanApiError::InvalidInput(
            "no responsive Podman API socket found; set OPENSHELL_PODMAN_SOCKET \
             or configure socket_path"
                .to_string(),
        )
    })
}

impl PodmanComputeDriver {
    /// Create a new driver, verifying the Podman socket is reachable.
    pub async fn new(mut config: PodmanComputeConfig) -> Result<Self, PodmanApiError> {
        const MAX_PING_RETRIES: u32 = 5;
        const PING_RETRY_DELAY: Duration = Duration::from_secs(2);

        let socket_path = resolve_socket_path(config.socket_path.clone(), detect_socket)?;
        config.socket_path = Some(socket_path.clone());

        if !socket_path.exists() {
            if cfg!(target_os = "macos") {
                warn!(
                    path = %socket_path.display(),
                    "Podman socket not found; is podman machine running? \
                     Try `podman machine start` or set OPENSHELL_PODMAN_SOCKET to override."
                );
            } else {
                warn!(
                    path = %socket_path.display(),
                    "Podman socket not found; is the Podman service running? \
                     Set OPENSHELL_PODMAN_SOCKET or XDG_RUNTIME_DIR to override."
                );
            }
        }

        // Validate and normalize configuration before connecting. Partial TLS
        // and invalid resource, proxy, SPIFFE, AppArmor, or userns settings
        // fail before the runtime is contacted.
        config.validate_configuration()?;

        let client = PodmanClient::new(socket_path);

        // Verify connectivity, retrying briefly to tolerate transient socket
        // unavailability (e.g. podman.socket restarting after a package
        // upgrade). The systemd unit uses Wants=podman.socket (not Requires),
        // so the gateway may start while the socket is briefly re-activating.
        let mut attempts = 0;
        loop {
            match client.ping().await {
                Ok(()) => break,
                Err(e) if attempts < MAX_PING_RETRIES => {
                    attempts += 1;
                    warn!(
                        attempt = attempts,
                        max_retries = MAX_PING_RETRIES,
                        error = %e,
                        "Podman socket not ready, retrying"
                    );
                    tokio::time::sleep(PING_RETRY_DELAY).await;
                }
                Err(e) => return Err(e),
            }
        }

        // Verify cgroups v2, detect rootless mode, and log system info.
        let rootless = match client.system_info().await {
            Ok(info) => {
                if info.host.cgroup_version != "v2" {
                    return Err(PodmanApiError::Connection(format!(
                        "cgroups v2 is required; detected cgroups '{}'. \
                         Ensure your host uses a unified cgroup hierarchy \
                         (systemd.unified_cgroup_hierarchy=1).",
                        info.host.cgroup_version
                    )));
                }
                validate_apparmor_support(
                    config.app_armor_profile.as_ref(),
                    info.host.security.apparmor_enabled,
                )?;
                info!(
                    cgroup_version = %info.host.cgroup_version,
                    network_backend = %info.host.network_backend,
                    rootless = info.host.security.rootless,
                    rootless_network_cmd = %info.host.rootless_network_cmd,
                    apparmor_enabled = info.host.security.apparmor_enabled,
                    "Connected to Podman"
                );
                info.host.security.rootless
            }
            Err(e) => {
                return Err(PodmanApiError::Connection(format!(
                    "failed to query Podman system info: {e}"
                )));
            }
        };

        // Rootless pre-flight: warn if subuid/subgid ranges look missing.
        // Not a hard error because some systems configure these via LDAP or
        // other mechanisms that /etc/subuid does not reflect.
        if !cfg!(target_os = "macos") && rustix::process::getuid().as_raw() != 0 {
            check_subuid_range();
        }

        // The supervisor shares the Podman host network. Linux supervisors can
        // therefore use gateway loopback directly; Podman Machine retains its
        // standard desktop-host alias.
        let endpoint_was_selected = config.grpc_endpoint.is_empty();
        config.grpc_endpoint = select_grpc_endpoint(&config, PodmanEndpointEnvironment::current());
        if endpoint_was_selected {
            info!(
                grpc_endpoint = %config.grpc_endpoint,
                tls = config.tls_enabled(),
                "Auto-detected gRPC endpoint"
            );
        }

        client.ensure_network(&config.network_name).await?;
        info!(network = %config.network_name, "Podman network ready");

        let (gpu_inventory, allow_all_default_gpu) = local_podman_gpu_selector_state();
        if !gpu_inventory.is_empty() {
            info!(
                device_count = gpu_inventory.as_slice().len(),
                "Discovered local Podman NVIDIA CDI GPU devices"
            );
        }

        let driver = Self {
            client,
            config,
            rootless,
            gpu_selector: Arc::new(CdiGpuDefaultSelector::new(
                gpu_inventory,
                allow_all_default_gpu,
            )),
            gpu_inventory_refresh: Arc::new(local_podman_gpu_selector_state),
            lifecycle_event_fences: LifecycleEventFences::default(),
        };
        let reconciler = driver.clone();
        tokio::spawn(async move {
            loop {
                reconciler.reconcile_resource_admission().await;
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
        Ok(driver)
    }

    /// Report driver capabilities.
    pub fn capabilities(&self) -> Result<GetCapabilitiesResponse, ComputeDriverError> {
        Ok(GetCapabilitiesResponse {
            resource_admission_policy: openshell_core::resource_admission::DriverAdmissionConfig {
                allow_driver_config: self.config.allow_driver_config,
                resource_admission: self.config.resource_admission.clone(),
            }
            .acknowledgement(),
            driver_name: "podman".to_string(),
            driver_version: openshell_core::VERSION.to_string(),
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
                    default_selection_supported: true,
                    count_selection_supported: true,
                }),
            }),
            rootfs_tar_staging_dir: String::new(),
            rootfs_tar_max_bytes: 0,
            extension: Some(openshell_core::extension_protocol::extension_metadata(
                openshell_core::extension_protocol::ExtensionFamily::Compute,
                "openshell/podman",
                openshell_core::VERSION,
                [],
            )),
        })
    }

    #[must_use]
    pub fn default_image(&self) -> &str {
        &self.config.default_image
    }

    /// Validate a sandbox before creation.
    pub async fn validate_sandbox_create(
        &self,
        sandbox: &DriverSandbox,
    ) -> Result<(), ComputeDriverError> {
        let _ = self.validated_sandbox_create(sandbox).await?;
        Ok(())
    }

    async fn validated_sandbox_create<'a>(
        &self,
        sandbox: &'a DriverSandbox,
    ) -> Result<ValidatedPodmanSandbox<'a>, ComputeDriverError> {
        openshell_core::resource_admission::check_sandbox_driver_config(
            self.config.allow_driver_config,
            sandbox,
        )
        .map_err(|error| ComputeDriverError::Precondition(error.message().into()))?;
        let gpu_requirements = sandbox
            .spec
            .as_ref()
            .and_then(|spec| spec.resource_requirements.as_ref())
            .and_then(|requirements| driver_gpu_requirements(Some(requirements)));
        let driver_config = PodmanSandboxDriverConfig::from_sandbox(sandbox)?;
        driver_config.admit_mount_types(&self.config.resource_admission)?;
        Self::validate_gpu_request(gpu_requirements, &driver_config)?;
        self.validate_user_volume_mounts_available(sandbox).await?;
        let _ = self.resolve_gpu_cdi_devices(
            gpu_requirements,
            &driver_config,
            CdiGpuDefaultSelector::peek_device_ids,
        )?;
        Ok(ValidatedPodmanSandbox {
            driver_config,
            gpu_requirements,
        })
    }

    fn validate_gpu_request(
        gpu_requirements: Option<&GpuResourceRequirements>,
        driver_config: &PodmanSandboxDriverConfig,
    ) -> Result<(), ComputeDriverError> {
        let _ = effective_driver_gpu_count(gpu_requirements)
            .map_err(ComputeDriverError::InvalidArgument)?;
        if let Some(cdi_devices) = driver_config.cdi_devices.as_deref() {
            validate_specific_gpu_device_request(
                gpu_requirements,
                cdi_devices,
                "driver_config.cdi_devices",
            )
            .map_err(ComputeDriverError::InvalidArgument)?;
        }

        Ok(())
    }

    fn refresh_gpu_inventory(&self) {
        let (inventory, allow_all_default_gpu) = (self.gpu_inventory_refresh)();
        self.gpu_selector.refresh(inventory, allow_all_default_gpu);
    }

    fn resolve_gpu_cdi_devices(
        &self,
        gpu_requirements: Option<&GpuResourceRequirements>,
        driver_config: &PodmanSandboxDriverConfig,
        select_default_devices: fn(
            &CdiGpuDefaultSelector,
            u32,
        ) -> Result<Vec<String>, CdiGpuSelectionError>,
    ) -> Result<Option<Vec<String>>, ComputeDriverError> {
        if let Some(cdi_devices) = driver_config.cdi_devices.as_deref() {
            validate_specific_gpu_device_request(
                gpu_requirements,
                cdi_devices,
                "driver_config.cdi_devices",
            )
            .map_err(ComputeDriverError::InvalidArgument)?;
            return Ok(Some(cdi_devices.to_vec()));
        }

        let Some(count) = effective_driver_gpu_count(gpu_requirements)
            .map_err(ComputeDriverError::InvalidArgument)?
        else {
            return Ok(None);
        };

        self.refresh_gpu_inventory();
        select_default_devices(&self.gpu_selector, count)
            .map(Some)
            .map_err(podman_gpu_selection_error)
    }

    async fn validate_user_volume_mounts_available(
        &self,
        sandbox: &DriverSandbox,
    ) -> Result<std::collections::BTreeMap<String, serde_json::Value>, ComputeDriverError> {
        let mut identities = std::collections::BTreeMap::new();
        let volumes =
            container::podman_driver_volume_mount_sources(sandbox, self.config.enable_bind_mounts)
                .map_err(ComputeDriverError::Precondition)?;
        for volume in volumes {
            match self.client.inspect_volume(&volume).await {
                Ok(volume_info) => {
                    identities.insert(volume.clone(), volume_info.admission_identity());
                    self.config
                        .resource_admission
                        .admit(
                            &sandbox.workspace,
                            volume_info
                                .labels
                                .as_ref()
                                .into_iter()
                                .flat_map(|labels| labels.iter()),
                        )
                        .map_err(|error| {
                            ComputeDriverError::Precondition(format!(
                                "podman volume '{volume}': {}",
                                error.message()
                            ))
                        })?;
                    if !self.config.enable_bind_mounts && podman_volume_is_bind_backed(&volume_info)
                    {
                        return Err(ComputeDriverError::Precondition(format!(
                            "podman volume '{volume}' is backed by a host bind mount and requires enable_bind_mounts = true in [openshell.drivers.podman]"
                        )));
                    }
                }
                Err(PodmanApiError::NotFound(_)) => {
                    return Err(ComputeDriverError::Precondition(format!(
                        "podman volume '{volume}' does not exist"
                    )));
                }
                Err(err) => return Err(ComputeDriverError::from(err)),
            }
        }
        Ok(identities)
    }

    /// Create a sandbox container.
    async fn admit_container_resources(&self, id: &str) -> Result<(), ComputeDriverError> {
        if self.config.allow_driver_config && !self.config.resource_admission.enabled {
            return Ok(());
        }
        let inspect = self.client.inspect_container(id).await?;
        let labels = &inspect.config.labels;
        let precondition =
            |error: tonic::Status| ComputeDriverError::Precondition(error.message().into());
        openshell_core::resource_admission::check_config_provenance(
            self.config.allow_driver_config,
            labels
                .get(openshell_core::resource_admission::CONFIG_USED_LABEL)
                .map(String::as_str),
        )
        .map_err(precondition)?;
        if !self.config.resource_admission.enabled {
            return Ok(());
        }
        let missing =
            || ComputeDriverError::Precondition("sandbox lacks attachment provenance".into());
        let workspace = labels
            .get(container::LABEL_SANDBOX_WORKSPACE)
            .ok_or_else(missing)?;
        let sandbox_id = labels.get(LABEL_SANDBOX_ID).ok_or_else(missing)?;
        let mounts = inspect.mounts.as_ref().ok_or_else(missing)?;
        let expected: std::collections::BTreeMap<String, serde_json::Value> = labels
            .get(openshell_core::resource_admission::IDENTITIES_LABEL)
            .and_then(|value| serde_json::from_str(value).ok())
            .ok_or_else(missing)?;
        let mut actual = std::collections::BTreeMap::new();
        for mount in mounts {
            match mount["Type"].as_str() {
                Some("volume") => {
                    let name = mount["Name"].as_str().ok_or_else(missing)?;
                    let volume =
                        self.client
                            .inspect_volume(name)
                            .await
                            .map_err(|error| match error {
                                PodmanApiError::NotFound(_) => ComputeDriverError::Precondition(
                                    "attached volume no longer exists".into(),
                                ),
                                other => ComputeDriverError::from(other),
                            })?;
                    if volume.name != name {
                        return Err(missing());
                    }
                    if name == container::volume_name(sandbox_id)
                        || name == crate::isolation::channel_volume_name(sandbox_id)
                    {
                        let owned = volume.labels.as_ref().is_some_and(|labels| {
                            labels.get(LABEL_SANDBOX_ID) == Some(sandbox_id)
                                && labels.get(container::LABEL_SANDBOX_WORKSPACE) == Some(workspace)
                        });
                        if !owned || volume.driver != "local" || !volume.options.is_empty() {
                            return Err(missing());
                        }
                    } else {
                        actual.insert(name.to_string(), volume.admission_identity());
                        self.config
                            .resource_admission
                            .admit(
                                workspace,
                                volume
                                    .labels
                                    .as_ref()
                                    .into_iter()
                                    .flat_map(|labels| labels.iter()),
                            )
                            .map_err(|error| {
                                ComputeDriverError::Precondition(format!(
                                    "podman volume '{name}': {}",
                                    error.message()
                                ))
                            })?;
                        if !self.config.enable_bind_mounts && podman_volume_is_bind_backed(&volume)
                        {
                            return Err(ComputeDriverError::Precondition(
                                "bind-backed volume is disabled".into(),
                            ));
                        }
                    }
                }
                Some("tmpfs") => {}
                Some("bind")
                    if mount["Destination"].as_str()
                        == Some(openshell_core::driver_utils::SUPERVISOR_CONTAINER_BINARY)
                        && mount["RW"].as_bool() == Some(false)
                        && labels
                            .get("openshell.ai/runtime-binary-source")
                            .filter(|path| !path.is_empty())
                            .map(String::as_str)
                            == mount["Source"].as_str() => {}
                _ => self
                    .config
                    .resource_admission
                    .reject_unlabelable("effective Podman mount")
                    .map_err(precondition)?,
            }
        }
        if actual != expected {
            return Err(ComputeDriverError::Precondition(
                "external volume identity or attachment inventory changed".into(),
            ));
        }
        Ok(())
    }

    /// Revalidate running grants every 30 seconds. Outages block launches but
    /// only confirmed denials stop existing workloads.
    async fn reconcile_resource_admission(&self) {
        let Ok(entries) = self
            .client
            .list_containers(&[LABEL_MANAGED_FILTER, crate::isolation::WORKLOAD_FILTER])
            .await
        else {
            return;
        };
        for entry in entries.iter().filter(|entry| entry.state == "running") {
            if let Err(ComputeDriverError::Precondition(reason)) =
                self.admit_container_resources(&entry.id).await
            {
                warn!(container = %entry.id, %reason, "Stopping sandbox after resource admission denial");
                let _ = self.client.stop_container(&entry.id, 0).await;
                if let Some(id) = entry.labels.get(LABEL_SANDBOX_ID) {
                    let _ = self
                        .client
                        .stop_container(&crate::isolation::supervisor_name(id), 0)
                        .await;
                }
            }
        }
    }

    /// Create a sandbox container.
    #[tracing::instrument(
        name = "podman.provision",
        skip(self, sandbox),
        fields(
            otel.name = "podman.provision",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %sandbox.id,
            sandbox.name = %sandbox.name,
        )
    )]
    pub async fn create_sandbox(&self, sandbox: &DriverSandbox) -> Result<(), ComputeDriverError> {
        let span_status = openshell_otel::ErrorStatusGuard::current();
        if sandbox.name.is_empty() {
            return Err(ComputeDriverError::Precondition(
                "sandbox name is required".into(),
            ));
        }
        if sandbox.id.is_empty() {
            return Err(ComputeDriverError::Precondition(
                "sandbox id is required".into(),
            ));
        }

        // Validate the composed container name early, before creating any
        // resources (volume), so we don't leave orphans when the name is
        // invalid.
        let name = validated_container_name(sandbox)?;
        let validated = self.validated_sandbox_create(sandbox).await?;

        let vol_name = container::volume_name(&sandbox.id);

        info!(
            sandbox_id = %sandbox.id,
            sandbox_name = %sandbox.name,
            container = %name,
            "Creating sandbox container"
        );

        let (image, immutable_image_id, image_user, image_env) = async {
            let phase_status = openshell_otel::ErrorStatusGuard::current();
            let result = async {
                // The sandbox runtime is shipped in a standalone OCI image.
                // The driver extracts and verifies its binary before bind-mounting
                // it into the workload container.
                let sandbox_runtime_pull_policy =
                    runtime_image_pull_policy(&self.config.sandbox_runtime_image);
                info!(
                    image = %self.config.sandbox_runtime_image,
                    policy = sandbox_runtime_pull_policy,
                    "Ensuring sandbox runtime image"
                );
                self.client
                    .pull_image(
                        &self.config.sandbox_runtime_image,
                        sandbox_runtime_pull_policy,
                    )
                    .await
                    .map_err(ComputeDriverError::from)?;

                let supervisor_pull_policy =
                    runtime_image_pull_policy(&self.config.supervisor_image);
                info!(
                    image = %self.config.supervisor_image,
                    policy = supervisor_pull_policy,
                    "Ensuring supervisor image"
                );
                self.client
                    .pull_image(&self.config.supervisor_image, supervisor_pull_policy)
                    .await
                    .map_err(ComputeDriverError::from)?;

                // Podman does not pull the sandbox image on container creation.
                let image = container::resolve_image(sandbox, &self.config);
                if image.is_empty() {
                    return Err(ComputeDriverError::Precondition(
                        "no sandbox image configured: set default_image in \
                         [openshell.drivers.podman] or provide an image in the sandbox template"
                            .to_string(),
                    ));
                }
                let pull_policy = podman_image_pull_policy(self.config.image_pull_policy);
                info!(image = %image, policy = %pull_policy, "Ensuring sandbox image");
                self.client
                    .pull_image(image, pull_policy)
                    .await
                    .map_err(ComputeDriverError::from)?;
                let inspected_image = self
                    .client
                    .inspect_image(image)
                    .await
                    .map_err(ComputeDriverError::from)?;
                if inspected_image.id.is_empty() {
                    return Err(ComputeDriverError::Precondition(format!(
                        "podman image '{image}' inspection did not return an immutable image ID"
                    )));
                }
                let image_user = inspected_image
                    .config
                    .as_ref()
                    .map_or_else(String::new, |config| config.user.clone());

                for mount_image in container::podman_driver_image_mount_sources(
                    sandbox,
                    self.config.enable_bind_mounts,
                )
                .map_err(ComputeDriverError::Precondition)?
                {
                    info!(image = %mount_image, policy = %pull_policy, "Ensuring image mount source");
                    self.client
                        .pull_image(&mount_image, pull_policy)
                        .await
                        .map_err(ComputeDriverError::from)?;
                }

                let image_env = inspected_image.config.as_ref().map_or_else(Vec::new, |config| config.env.clone());
                Ok((image.to_string(), inspected_image.id, image_user, image_env))
            }
            .await;
            phase_status.finish(result)
        }
        .instrument(tracing::info_span!(
            "podman.prepare_images",
            otel.name = "podman.prepare_images",
            otel.status_code = tracing::field::Empty,
        ))
        .await?;

        // Fail closed on a missing/unreadable corporate proxy CA bundle before
        // creating any resources, so the operator gets a clear error
        // attributable to `proxy_ca_bundle` rather than an opaque bind-mount
        // failure. The supervisor independently validates the certificate
        // content at startup.
        validate_sandbox_proxy_ca_bundle(&self.config).await?;

        let identity = self
            .resolve_workload_identity(sandbox, &immutable_image_id, &image_user)
            .await?;
        let channel_volume = crate::isolation::channel_volume_name(&sandbox.id);
        let mut runtime_config = self.config.clone();
        runtime_config.sandbox_runtime_image = self
            .client
            .inspect_image(&self.config.sandbox_runtime_image)
            .await?
            .id;
        if runtime_config.sandbox_runtime_image.is_empty() {
            return Err(ComputeDriverError::Precondition(
                "sandbox runtime image inspection returned no immutable image ID".into(),
            ));
        }
        runtime_config.supervisor_image = self
            .client
            .inspect_image(&self.config.supervisor_image)
            .await?
            .id;
        if runtime_config.supervisor_image.is_empty() {
            return Err(ComputeDriverError::Precondition(
                "supervisor image inspection returned no immutable image ID".into(),
            ));
        }

        // Create workspace volume and per-sandbox token secret.
        let (token_secret_name, proxy_auth_secret_name) = async {
            let phase_status = openshell_otel::ErrorStatusGuard::current();
            let result = async {
                self.client
                    .create_owned_volume(&vol_name, &sandbox.id, &sandbox.workspace)
                    .await
                    .map_err(ComputeDriverError::from)?;
                let token_secret_name =
                    match create_sandbox_token_secret(&self.client, sandbox).await {
                        Ok(name) => name,
                        Err(e) => {
                            let _ = self.client.remove_volume(&vol_name).await;
                            return Err(e);
                        }
                    };
                let proxy_auth_secret_name =
                    match create_sandbox_proxy_auth_secret(&self.client, &self.config, sandbox)
                        .await
                    {
                        Ok(name) => name,
                        Err(e) => {
                            let _ = self.client.remove_volume(&vol_name).await;
                            if let Some(secret) = token_secret_name.as_deref() {
                                cleanup_sandbox_token_secret(&self.client, secret).await;
                            }
                            return Err(e);
                        }
                    };
                Ok((token_secret_name, proxy_auth_secret_name))
            }
            .await;
            phase_status.finish(result)
        }
        .instrument(tracing::info_span!(
            "podman.prepare_storage",
            otel.name = "podman.prepare_storage",
            otel.status_code = tracing::field::Empty,
            volume.name = %vol_name,
        ))
        .await?;

        // Clean up the volume and both per-sandbox secrets on any failure past
        // this point.
        let channel_owned = std::sync::atomic::AtomicBool::new(false);
        let cleanup_created = || async {
            if channel_owned.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = self.client.remove_volume(&channel_volume).await;
            }
            let _ = self.client.remove_volume(&vol_name).await;
            if let Some(secret) = token_secret_name.as_deref() {
                cleanup_sandbox_token_secret(&self.client, secret).await;
            }
            if let Some(secret) = proxy_auth_secret_name.as_deref() {
                cleanup_sandbox_proxy_auth_secret(&self.client, secret).await;
            }
        };

        // Prepare and create the container.
        async {
            let phase_status = openshell_otel::ErrorStatusGuard::current();
            let result = async {
                let gpu_devices = match self.resolve_gpu_cdi_devices(
                    validated.gpu_requirements,
                    &validated.driver_config,
                    CdiGpuDefaultSelector::next_device_ids,
                ) {
                    Ok(devices) => devices,
                    Err(e) => {
                        cleanup_created().await;
                        return Err(e);
                    }
                };
                // Podman's image-volume support varies across libpod/runtime
                // combinations. Always use the verified extraction cache so
                // workload startup does not depend on type=image mounts.
                let supervisor_bin_path =
                    match extract_sandbox_bin(&self.client, &runtime_config).await {
                        Ok(path) => Some(path),
                        Err(e) => {
                            cleanup_created().await;
                            return Err(e);
                        }
                    };

                let tls_secret_names = if self.config.tls_enabled() {
                    let names = container::tls_secret_names(&sandbox.id);
                    if let Err(e) = create_tls_secrets(&self.client, &self.config, &names).await {
                        cleanup_created().await;
                        return Err(e);
                    }
                    Some(names)
                } else {
                    None
                };

                let cleanup_all = || async {
                    cleanup_created().await;
                    if let Some(names) = &tls_secret_names {
                        cleanup_tls_secrets(&self.client, names).await;
                    }
                };

                let specs = container::build_isolation_specs(container::IsolationSpecInput {
                    sandbox,
                    config: &runtime_config,
                    token_secret: token_secret_name.as_deref(),
                    gpu_devices: gpu_devices.as_deref(),
                    requested_image: &image,
                    image_id: &immutable_image_id,
                    image_user: &image_user,
                    image_env: &image_env,
                    supervisor_bin: supervisor_bin_path.as_deref(),
                    tls_secrets: tls_secret_names.as_ref(),
                    identity: &identity,
                    rootless: self.rootless,
                });
                let mut specs = match specs {
                    Ok(spec) => spec,
                    Err(e) => {
                        cleanup_all().await;
                        return Err(e);
                    }
                };
                let mut created_workload = None;
                let mut created_supervisor = None;
                let create_result = async {
                    let identities = self.validate_user_volume_mounts_available(sandbox).await?;
                    specs.record_resource_identities(&identities)?;
                    self.client
                        .create_owned_volume(&channel_volume, &sandbox.id, &sandbox.workspace)
                        .await?;
                    channel_owned.store(true, std::sync::atomic::Ordering::Relaxed);
                    let workload_id = self.client.create_typed_container(&specs.workload).await?;
                    created_workload = Some(workload_id.clone());
                    self.client.verify_isolation_fence(&workload_id).await?;
                    self.admit_container_resources(&workload_id).await?;
                    let child_env = podman_child_environment(sandbox, &image_env);
                    let launch_authentication = sandbox
                        .spec
                        .as_ref()
                        .filter(|spec| !spec.launch_authentication.is_empty())
                        .ok_or_else(|| {
                            ComputeDriverError::Precondition(
                                "Podman sandbox launch authentication is required".to_string(),
                            )
                        })
                        .and_then(|spec| {
                            decode_launch_authentication(&spec.launch_authentication)
                        })?;
                    let archives = crate::isolation::bootstrap_archives(
                        &sandbox.id,
                        &workload_id,
                        &uuid::Uuid::new_v4().to_string(),
                        &identity,
                        child_env,
                        &launch_authentication,
                    )?;
                    self.client
                        .copy_to_container(
                            &workload_id,
                            crate::isolation::CHANNEL_ROOT,
                            archives.channel,
                        )
                        .await?;
                    self.client
                        .copy_to_container(&workload_id, "/sandbox", archives.workspace)
                        .await?;
                    let supervisor_id = self
                        .client
                        .create_typed_container(&specs.supervisor)
                        .await?;
                    created_supervisor = Some(supervisor_id.clone());
                    self.client
                        .copy_to_container(&supervisor_id, "/", archives.supervisor)
                        .await?;
                    // Start the sandbox only after both containers and their
                    // bootstrap material exist. It keeps the agent stopped
                    // until the authenticated supervisor confirms the boundary.
                    self.client.start_container(&workload_id).await?;
                    self.client.start_container(&supervisor_id).await?;
                    Ok::<(), ComputeDriverError>(())
                }
                .await;
                if create_result.is_err() {
                    for id in [created_supervisor, created_workload].into_iter().flatten() {
                        let _ = self.client.remove_container(&id, 0).await;
                    }
                }
                match create_result {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        cleanup_all().await;
                        Err(e)
                    }
                }
            }
            .await;
            phase_status.finish(result)
        }
        .instrument(tracing::info_span!(
            "podman.prepare_container",
            otel.name = "podman.prepare_container",
            otel.status_code = tracing::field::Empty,
            container.name = %name,
        ))
        .await?;

        info!(
            sandbox_id = %sandbox.id,
            sandbox_name = %sandbox.name,
            "Sandbox container started"
        );

        span_status.finish(Ok(()))
    }

    /// Resolve image accounts without executing any image-supplied program.
    async fn resolve_workload_identity(
        &self,
        sandbox: &DriverSandbox,
        image: &str,
        image_user: &str,
    ) -> Result<openshell_isolation_interface::contract::ResolvedWorkloadIdentity, ComputeDriverError>
    {
        #[derive(serde::Serialize)]
        struct InspectionSpec<'a> {
            name: String,
            image: &'a str,
        }
        // Inspect a stopped, unexecuted container pinned to the final image ID.
        let id = self
            .client
            .create_typed_container(&InspectionSpec {
                name: format!("openshell-identity-{}", uuid::Uuid::new_v4()),
                image,
            })
            .await?;
        let result =
            async {
                // Do not let image-controlled symlinks alias the protected channel
                // into an agent-readable subtree before Podman mounts it.
                match self.client.copy_from_container(&id, "/.openshell").await {
                    Err(PodmanApiError::NotFound(_)) => {}
                    Ok(_) => return Err(ComputeDriverError::Precondition(
                        "workload images must not prepopulate the reserved /.openshell hierarchy"
                            .into(),
                    )),
                    Err(error) => return Err(error.into()),
                }
                let mut accounts = Vec::new();
                for path in ["/etc/passwd", "/etc/group"] {
                    let content = match self.client.copy_from_container(&id, path).await {
                        Ok(archive) => extract_first_tar_entry(&archive)
                            .map_err(ComputeDriverError::Precondition)?,
                        Err(PodmanApiError::NotFound(_)) => Vec::new(),
                        Err(error) => return Err(error.into()),
                    };
                    accounts.push(content);
                }
                let [passwd, group] = accounts.as_slice() else {
                    return Err(ComputeDriverError::Precondition(
                        "image account inspection was incomplete".into(),
                    ));
                };
                crate::isolation::resolve_identity(sandbox, image, image_user, passwd, group)
            }
            .await;
        let cleanup = self.client.remove_container(&id, 0).await;
        if let Err(error) = cleanup {
            warn!(container = %id, %error, "Failed to remove stopped identity inspection container");
        }
        result
    }

    /// Find only the workload, never its supervisor companion.
    async fn find_container_id(
        &self,
        sandbox_id: &str,
    ) -> Result<Option<String>, ComputeDriverError> {
        Ok(self.find_container(sandbox_id).await?.map(|entry| entry.id))
    }

    async fn find_container(
        &self,
        sandbox_id: &str,
    ) -> Result<Option<ContainerListEntry>, ComputeDriverError> {
        let id_filter = format!("{LABEL_SANDBOX_ID}={sandbox_id}");
        let entries = self
            .client
            .list_containers(&[
                LABEL_MANAGED_FILTER,
                &id_filter,
                crate::isolation::WORKLOAD_FILTER,
            ])
            .await
            .map_err(ComputeDriverError::from)?;
        Ok(entries.into_iter().next())
    }

    async fn wait_for_container_stopped(
        &self,
        sandbox_id: &str,
        container_id: &str,
    ) -> Result<Option<String>, ComputeDriverError> {
        let timeout = Duration::from_secs(u64::from(self.config.stop_timeout_secs))
            + STOP_COMPLETION_TIMEOUT_HEADROOM;
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            let inspect = self
                .client
                .inspect_container(container_id)
                .await
                .map_err(ComputeDriverError::from)?;
            if matches!(inspect.state.status.as_str(), "exited" | "stopped") {
                return Ok(inspect.state.finished_at);
            }

            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(ComputeDriverError::Message(format!(
                    "container {container_id} for sandbox {sandbox_id} did not finish stopping within {timeout:?} (last state: {})",
                    inspect.state.status,
                )));
            }
            tokio::time::sleep(STOP_COMPLETION_POLL_INTERVAL.min(deadline - now)).await;
        }
    }

    /// Stop a sandbox container without deleting it.
    #[tracing::instrument(
        name = "podman.stop_sandbox",
        skip(self),
        fields(
            otel.name = "podman.stop_sandbox",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %sandbox_id,
        )
    )]
    pub async fn stop_sandbox(&self, sandbox_id: &str) -> Result<(), ComputeDriverError> {
        let span_status = openshell_otel::ErrorStatusGuard::current();
        let container = self.find_container(sandbox_id).await?;
        let supervisor = crate::isolation::supervisor_name(sandbox_id);
        match self
            .client
            .stop_container(&supervisor, self.config.stop_timeout_secs)
            .await
        {
            Ok(()) | Err(PodmanApiError::NotFound(_)) => {}
            Err(error) => return Err(error.into()),
        }
        let container = container.ok_or(ComputeDriverError::NotFound)?;
        let container_id = container.id;
        if container.state == "stopping" {
            let result = async {
                let finished_at = self
                    .wait_for_container_stopped(sandbox_id, &container_id)
                    .await?;
                self.lifecycle_event_fences
                    .record_previous_exit(sandbox_id, finished_at.as_deref());
                Ok(())
            }
            .await;
            return span_status.finish(result);
        }
        if container.state != "running" {
            return span_status.finish(Ok(()));
        }
        info!(sandbox_id = %sandbox_id, container = %container_id, "Stopping sandbox container");

        let result = async {
            self.client
                .stop_container(&container_id, self.config.stop_timeout_secs)
                .await
                .map_err(ComputeDriverError::from)?;

            // Podman can return from the stop request before inspect reports the
            // container as exited. If start runs during that interval, the exit
            // event from the previous run can arrive after the gateway has moved
            // the same sandbox to Starting, causing it to regress to Error. Wait
            // for the terminal container state before allowing a restart.
            let finished_at = self
                .wait_for_container_stopped(sandbox_id, &container_id)
                .await?;

            // Record the completed run before returning the stop RPC. The server
            // may begin a restart as soon as this method returns, while Podman's
            // stop/die event can still be queued. Recording the fence here keeps
            // that delayed event from regressing the new run from Starting to
            // Error. Keep the start-side recording as a fallback for restarts
            // after a driver or gateway process restart.
            self.lifecycle_event_fences
                .record_previous_exit(sandbox_id, finished_at.as_deref());
            Ok(())
        }
        .await;
        span_status.finish(result)
    }

    /// Start a previously stopped sandbox container.
    #[tracing::instrument(
        name = "podman.start_sandbox",
        skip_all,
        fields(
            otel.name = "podman.start_sandbox",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %sandbox_id,
        )
    )]
    pub async fn start_sandbox(
        &self,
        sandbox_id: &str,
        generation_id: &str,
        encoded_authentication: &[u8],
    ) -> Result<(), ComputeDriverError> {
        let span_status = openshell_otel::ErrorStatusGuard::current();
        let generation = openshell_core::sandbox_generation::SandboxGenerationId::parse(
            generation_id.to_string(),
        )
        .map_err(|error| ComputeDriverError::InvalidArgument(error.to_string()))?;
        let launch_authentication = decode_launch_authentication(encoded_authentication)?;
        let container = self
            .find_container(sandbox_id)
            .await?
            .ok_or(ComputeDriverError::NotFound)?;
        self.admit_container_resources(&container.id).await?;
        if container.state == "running" {
            let supervisor = self
                .client
                .inspect_container(&crate::isolation::supervisor_name(sandbox_id))
                .await;
            if supervisor
                .as_ref()
                .is_ok_and(|inspect| inspect.state.running)
            {
                let archive = self
                    .client
                    .copy_from_container(
                        &crate::isolation::supervisor_name(sandbox_id),
                        crate::isolation::RESTART_METADATA_PATH,
                    )
                    .await?;
                let bundle =
                    extract_first_tar_entry(&archive).map_err(ComputeDriverError::Precondition)?;
                let metadata = crate::isolation::restart_metadata_from_slice(&bundle)?;
                if metadata.generation == generation.as_str() && encoded_authentication.is_empty() {
                    return span_status.finish(Ok(()));
                }
                if metadata.generation != generation.as_str() {
                    return span_status.finish(Err(ComputeDriverError::Precondition(format!(
                        "Podman sandbox is already running generation {}",
                        metadata.generation
                    ))));
                }
                // A non-empty bundle for the same generation comes from
                // gateway startup recovery. Restart both containers so the
                // in-memory launch session changes atomically on both sides.
            }
            self.client.stop_container(&container.id, 0).await?;
            self.wait_for_container_stopped(sandbox_id, &container.id)
                .await?;
        }
        let container_id = container.id;
        info!(sandbox_id = %sandbox_id, container = %container_id, "Starting sandbox container");

        // Fence delayed stop/die events from the previous container run before
        // issuing the start. Podman's event stream can deliver those events
        // after this API call has begun. Use the container's own transition
        // timestamp so this remains correct for remote Podman services whose
        // wall clock may differ from the gateway host.
        let previous = self
            .client
            .inspect_container(&container_id)
            .await
            .map_err(ComputeDriverError::from)?;
        self.lifecycle_event_fences
            .record_previous_exit(sandbox_id, previous.state.finished_at.as_deref());
        let result = async {
            let supervisor = crate::isolation::supervisor_name(sandbox_id);
            self.client
                .stop_container(&supervisor, self.config.stop_timeout_secs)
                .await?;
            self.wait_for_container_stopped(sandbox_id, &supervisor)
                .await?;
            let archive = self
                .client
                .copy_from_container(&supervisor, crate::isolation::RESTART_METADATA_PATH)
                .await?;
            let bundle =
                extract_first_tar_entry(&archive).map_err(ComputeDriverError::Precondition)?;
            let restart_metadata = crate::isolation::restart_metadata_from_slice(&bundle)?;
            let archives = crate::isolation::bootstrap_archives(
                sandbox_id,
                &container_id,
                generation.as_str(),
                &restart_metadata.workload_identity,
                restart_metadata.child_env,
                &launch_authentication,
            )?;
            self.client
                .copy_to_container(
                    &container_id,
                    crate::isolation::CHANNEL_ROOT,
                    archives.channel,
                )
                .await?;
            self.client
                .copy_to_container(&supervisor, "/", archives.supervisor)
                .await?;
            self.client.verify_isolation_fence(&container_id).await?;
            self.client.start_container(&container_id).await?;
            if let Err(error) = self.client.start_container(&supervisor).await {
                let _ = self.client.stop_container(&container_id, 0).await;
                return Err(error.into());
            }
            Ok(())
        }
        .await;
        span_status.finish(result)
    }

    /// Delete a sandbox container and its workspace volume.
    #[tracing::instrument(
        name = "podman.delete_sandbox",
        skip(self),
        fields(
            otel.name = "podman.delete_sandbox",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %sandbox_id,
        )
    )]
    pub async fn delete_sandbox(&self, sandbox_id: &str) -> Result<bool, ComputeDriverError> {
        let span_status = openshell_otel::ErrorStatusGuard::current();
        if sandbox_id.is_empty() {
            return Err(ComputeDriverError::Precondition(
                "sandbox id is required".into(),
            ));
        }

        let supervisor = crate::isolation::supervisor_name(sandbox_id);
        match self
            .client
            .remove_container(&supervisor, self.config.stop_timeout_secs)
            .await
        {
            Ok(()) | Err(PodmanApiError::NotFound(_)) => {}
            Err(error) => return Err(error.into()),
        }
        match self
            .client
            .remove_volume(&crate::isolation::channel_volume_name(sandbox_id))
            .await
        {
            Ok(()) | Err(PodmanApiError::NotFound(_)) => {}
            // The workload still owns the volume until its removal below.
            Err(error) => debug!(%error, "Channel volume is still attached to workload"),
        }

        let Some(container_id) = self.find_container_id(sandbox_id).await? else {
            debug!(sandbox_id = %sandbox_id, "Sandbox container not found (already deleted)");
            let vol = container::volume_name(sandbox_id);
            if let Err(e) = self.client.remove_volume(&vol).await {
                warn!(sandbox_id = %sandbox_id, volume = %vol, error = %e, "Failed to remove workspace volume");
            }
            cleanup_sandbox_token_secret(&self.client, &container::token_secret_name(sandbox_id))
                .await;
            cleanup_sandbox_proxy_auth_secret(
                &self.client,
                &container::proxy_auth_secret_name(sandbox_id),
            )
            .await;
            cleanup_tls_secrets(&self.client, &container::tls_secret_names(sandbox_id)).await;
            self.lifecycle_event_fences.remove(sandbox_id);
            return span_status.finish(Ok(false));
        };
        info!(sandbox_id = %sandbox_id, container = %container_id, "Deleting sandbox container");

        // Keep stop, timeout, and removal in one Podman operation. Splitting
        // stop and remove can race with another container starting an image
        // mount when the stop reaches its timeout.
        let container_existed = match self
            .client
            .remove_container(&container_id, self.config.stop_timeout_secs)
            .await
        {
            Ok(()) => true,
            Err(PodmanApiError::NotFound(_)) => false,
            Err(e) => return Err(ComputeDriverError::from(e)),
        };

        // Remove workspace volume.
        if let Err(error) = self
            .client
            .remove_volume(&crate::isolation::channel_volume_name(sandbox_id))
            .await
        {
            warn!(%sandbox_id, %error, "Failed to remove private channel volume");
        }
        let vol = container::volume_name(sandbox_id);
        if let Err(e) = self.client.remove_volume(&vol).await {
            warn!(
                sandbox_id = %sandbox_id,
                volume = %vol,
                error = %e,
                "Failed to remove workspace volume"
            );
        }
        cleanup_sandbox_token_secret(&self.client, &container::token_secret_name(sandbox_id)).await;
        cleanup_sandbox_proxy_auth_secret(
            &self.client,
            &container::proxy_auth_secret_name(sandbox_id),
        )
        .await;
        cleanup_tls_secrets(&self.client, &container::tls_secret_names(sandbox_id)).await;
        self.lifecycle_event_fences.remove(sandbox_id);

        span_status.finish(Ok(container_existed))
    }

    /// Check whether a sandbox container exists.
    pub async fn sandbox_exists(&self, sandbox_id: &str) -> Result<bool, ComputeDriverError> {
        let id_filter = format!("{LABEL_SANDBOX_ID}={sandbox_id}");
        let entries = self
            .client
            .list_containers(&[
                LABEL_MANAGED_FILTER,
                &id_filter,
                crate::isolation::WORKLOAD_FILTER,
            ])
            .await
            .map_err(ComputeDriverError::from)?;
        Ok(!entries.is_empty())
    }

    /// Fetch a single sandbox by ID.
    pub async fn get_sandbox(
        &self,
        sandbox_id: &str,
    ) -> Result<Option<DriverSandbox>, ComputeDriverError> {
        let id_filter = format!("{LABEL_SANDBOX_ID}={sandbox_id}");
        let entries = self
            .client
            .list_containers(&[
                LABEL_MANAGED_FILTER,
                &id_filter,
                crate::isolation::WORKLOAD_FILTER,
            ])
            .await
            .map_err(ComputeDriverError::from)?;
        let Some(entry) = entries.first() else {
            return Ok(None);
        };
        if entry.state == "running" {
            Ok(watcher::inspect_workload(&self.client, &entry.id)
                .await
                .ok()
                .and_then(|inspect| driver_sandbox_from_inspect(&inspect))
                .or_else(|| driver_sandbox_from_list_entry(entry)))
        } else {
            Ok(driver_sandbox_from_list_entry(entry))
        }
    }

    /// List all managed sandboxes.
    ///
    /// Only inspects running containers (to get health status). Non-running
    /// containers are built directly from the list entry data.
    pub async fn list_sandboxes(&self) -> Result<Vec<DriverSandbox>, ComputeDriverError> {
        let entries = self
            .client
            .list_containers(&[LABEL_MANAGED_FILTER, crate::isolation::WORKLOAD_FILTER])
            .await
            .map_err(ComputeDriverError::from)?;

        let mut sandboxes = Vec::with_capacity(entries.len());
        for entry in &entries {
            if entry.state == "running" {
                // Running containers need inspect for health check status.
                match watcher::inspect_workload(&self.client, &entry.id).await {
                    Ok(inspect) => {
                        if let Some(sandbox) = driver_sandbox_from_inspect(&inspect) {
                            sandboxes.push(sandbox);
                            continue;
                        }
                    }
                    Err(e) => {
                        let name = entry.names.first().cloned().unwrap_or_default();
                        warn!(
                            container = %name,
                            error = %e,
                            "Failed to inspect running container during list, falling back to list entry"
                        );
                    }
                }
            }
            // Non-running containers (or inspect fallback): build from list data.
            if let Some(sandbox) = driver_sandbox_from_list_entry(entry) {
                sandboxes.push(sandbox);
            }
        }

        sandboxes.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
        Ok(sandboxes)
    }

    /// Start watching all managed sandbox containers.
    pub async fn watch_sandboxes(&self) -> Result<WatchStream, ComputeDriverError> {
        watcher::start_watch(self.client.clone(), self.lifecycle_event_fences.clone())
            .await
            .map_err(ComputeDriverError::from)
    }
}

#[cfg(test)]
impl PodmanComputeDriver {
    pub(crate) fn for_tests(config: PodmanComputeConfig) -> Self {
        Self::for_tests_with_gpu_inventory(config, CdiGpuInventory::default())
    }

    pub(crate) fn for_tests_with_gpu_inventory(
        config: PodmanComputeConfig,
        gpu_inventory: CdiGpuInventory,
    ) -> Self {
        Self::for_tests_with_gpu_inventory_and_all_fallback(config, gpu_inventory, false)
    }

    pub(crate) fn for_tests_with_gpu_inventory_and_all_fallback(
        config: PodmanComputeConfig,
        gpu_inventory: CdiGpuInventory,
        allow_all_default_gpu: bool,
    ) -> Self {
        let client = PodmanClient::new(config.socket_path.clone().unwrap_or_default());
        let refresh_inventory = gpu_inventory.clone();
        Self {
            client,
            config,
            rootless: false,
            gpu_selector: Arc::new(CdiGpuDefaultSelector::new(
                gpu_inventory,
                allow_all_default_gpu,
            )),
            gpu_inventory_refresh: Arc::new(move || {
                (refresh_inventory.clone(), allow_all_default_gpu)
            }),
            lifecycle_event_fences: LifecycleEventFences::default(),
        }
    }
}

fn validate_apparmor_support(
    profile: Option<&openshell_core::AppArmorProfile>,
    apparmor_enabled: bool,
) -> Result<(), PodmanApiError> {
    let requires_apparmor = matches!(
        profile,
        Some(
            openshell_core::AppArmorProfile::RuntimeDefault
                | openshell_core::AppArmorProfile::Localhost(_)
        )
    );
    if requires_apparmor && !apparmor_enabled {
        return Err(PodmanApiError::InvalidInput(
            "app_armor_profile requires AppArmor, but Podman reports AppArmor is unavailable; install/enable AppArmor or use Unconfined explicitly"
                .to_string(),
        ));
    }
    Ok(())
}

fn runtime_image_pull_policy(image: &str) -> &'static str {
    if supervisor_image_should_refresh(image) {
        "newer"
    } else {
        "missing"
    }
}

/// Check whether the current user has subuid/subgid ranges configured.
///
/// Rootless Podman requires entries in `/etc/subuid` and `/etc/subgid` for
/// the running user. If missing, container creation fails with an obscure
/// error. This pre-flight check emits a warning to guide operators.
fn check_subuid_range() {
    let uid = nix::unistd::getuid().as_raw();
    let username = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name);

    let has_range = |path: &str| -> bool {
        let Ok(content) = std::fs::read_to_string(path) else {
            return false;
        };
        let uid_str = uid.to_string();
        content.lines().any(|line| {
            let Some(entry) = line.split(':').next() else {
                return false;
            };
            entry == uid_str || username.as_deref() == Some(entry)
        })
    };

    if !has_range("/etc/subuid") || !has_range("/etc/subgid") {
        let user_display = username.as_deref().map_or_else(
            || format!("UID {uid}"),
            |name| format!("{name} (UID {uid})"),
        );
        warn!(
            user = %user_display,
            "Rootless Podman detected but no /etc/subuid or /etc/subgid entry found. \
             Container creation may fail. Add entries with: \
             sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $(whoami)"
        );
    }
}

// ── Sandbox binary extraction (userns fallback) ────────────────────────

async fn extract_sandbox_bin(
    client: &PodmanClient,
    config: &PodmanComputeConfig,
) -> Result<PathBuf, ComputeDriverError> {
    let mut inspect = client
        .inspect_image(&config.sandbox_runtime_image)
        .await
        .map_err(ComputeDriverError::from)?;

    if supervisor_image_should_refresh(&config.sandbox_runtime_image) {
        info!(
            image = %config.sandbox_runtime_image,
            "Refreshing mutable Podman sandbox runtime image"
        );
        match client
            .pull_image(&config.sandbox_runtime_image, "always")
            .await
        {
            Ok(()) => {
                inspect = client
                    .inspect_image(&config.sandbox_runtime_image)
                    .await
                    .map_err(ComputeDriverError::from)?;
            }
            Err(err) => {
                warn!(
                    image = %config.sandbox_runtime_image,
                    error = %err,
                    "Failed to refresh mutable Podman sandbox runtime image; \
                     falling back to local image if present",
                );
            }
        }
    }

    let digest = if inspect.id.is_empty() {
        return Err(ComputeDriverError::Precondition(format!(
            "sandbox runtime image '{}' has no ID",
            config.sandbox_runtime_image,
        )));
    } else {
        &inspect.id
    };

    let cache_path = openshell_core::driver_utils::supervisor_cache_path("podman-sandbox", digest)
        .map_err(ComputeDriverError::Precondition)?;
    // Unit tests use ordered Podman API stubs and intentionally exercise the
    // extraction path on every create. Production reuses the immutable cache.
    #[cfg(not(test))]
    if cache_path.is_file() {
        validate_linux_elf_binary(&cache_path).map_err(ComputeDriverError::Precondition)?;
        info!(
            cache_path = %cache_path.display(),
            "Using cached sandbox binary"
        );
        return Ok(cache_path);
    }

    info!(
        image = %config.sandbox_runtime_image,
        cache_path = %cache_path.display(),
        "Extracting sandbox binary from image"
    );

    let container_name = temp_extract_container_name();
    let spec = serde_json::json!({
        "image": config.sandbox_runtime_image,
        "name": container_name,
        "entrypoint": [SANDBOX_RUNTIME_IMAGE_BINARY_PATH],
        "command": [],
    });
    client
        .create_container(&spec)
        .await
        .map_err(ComputeDriverError::from)?;

    let result = extract_binary_from_container(client, &container_name, &cache_path).await;

    if let Err(err) = client.remove_container(&container_name, 0).await {
        warn!(
            container = container_name,
            error = %err,
            "Failed to remove sandbox runtime extractor container"
        );
    }

    result
}

async fn extract_binary_from_container(
    client: &PodmanClient,
    container_name: &str,
    cache_path: &Path,
) -> Result<PathBuf, ComputeDriverError> {
    let tar_bytes = client
        .copy_from_container(container_name, SANDBOX_RUNTIME_IMAGE_BINARY_PATH)
        .await
        .map_err(ComputeDriverError::from)?;

    let binary_bytes = extract_first_tar_entry(&tar_bytes).map_err(|err| {
        ComputeDriverError::Precondition(format!(
            "failed to extract sandbox binary from tar: {err}"
        ))
    })?;

    write_cache_binary_atomic(cache_path, &binary_bytes)
        .map_err(ComputeDriverError::Precondition)?;
    validate_linux_elf_binary(cache_path).map_err(ComputeDriverError::Precondition)?;
    Ok(cache_path.to_path_buf())
}

fn podman_child_environment(
    sandbox: &DriverSandbox,
    image_env: &[String],
) -> HashMap<String, String> {
    let mut environment = image_env
        .iter()
        .filter_map(|entry| {
            entry
                .split_once('=')
                .map(|(key, value)| (key.to_string(), value.to_string()))
        })
        .collect::<HashMap<_, _>>();
    if let Some(spec) = sandbox.spec.as_ref() {
        if let Some(template) = spec.template.as_ref() {
            environment.extend(template.environment.clone());
        }
        environment.extend(spec.environment.clone());
    }
    environment.retain(|key, _| !key.starts_with("OPENSHELL_"));
    environment
}

/// Returns `true` when userns remaps all UIDs, making host-owned bind mounts
/// unreadable from inside the container. `auto` and `no-map` remap every UID;
/// `keep-id` preserves the host user's UID; `host` uses the host namespace.
#[cfg(test)]
fn userns_remaps_uids(userns: Option<&str>) -> bool {
    userns.is_some_and(|mode| {
        let base = mode.split(':').next().unwrap_or(mode);
        !matches!(base.to_ascii_lowercase().as_str(), "host" | "keep-id")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{StubResponse, spawn_podman_stub};
    use hyper::StatusCode;
    use openshell_core::jwt::{
        CredentialEpoch, SandboxLaunchAuthentication, SecretJwt, SessionVerificationKey,
        SupervisorAuthBundle,
    };
    use openshell_core::proto::compute::v1::{
        DriverSandboxSpec, DriverSandboxTemplate, ResourceRequirements,
    };
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn launch_authentication() -> SandboxLaunchAuthentication {
        SandboxLaunchAuthentication {
            supervisor: SupervisorAuthBundle {
                session_id: openshell_core::SandboxSessionId::new(),
                runtime_generation: openshell_core::sandbox_generation::SandboxGenerationId::parse(
                    "generation-1",
                )
                .unwrap(),
                session_rotation: openshell_core::jwt::SessionRotation::new(1).unwrap(),
                auth_epoch: CredentialEpoch::new(1).unwrap(),
                gateway_token: SecretJwt::parse("gateway.token.value").unwrap(),
                gateway_expires_at: i64::MAX,
                sandbox_token: SecretJwt::parse("sandbox.token.value").unwrap(),
                sandbox_expires_at: i64::MAX,
            },
            gateway_id: "gateway-test".to_string(),
            verification_keys: vec![SessionVerificationKey {
                key_id: "test-key".to_string(),
                public_key_pem: b"public-key".to_vec(),
            }],
        }
    }

    fn encoded_launch_authentication() -> Vec<u8> {
        serde_json::to_vec(&launch_authentication()).unwrap()
    }

    // ── socket resolution ───────────────────────────────────────────────
    //
    // These test resolve_socket_path directly with an injected detector, so
    // they are deterministic regardless of the host's real environment
    // variables or whether a Podman socket happens to be running.

    #[test]
    fn resolve_socket_path_prefers_explicit_configuration() {
        let path = resolve_socket_path(Some(PathBuf::from("/explicit.sock")), || {
            Some(PathBuf::from("/detected.sock"))
        })
        .unwrap();

        assert_eq!(path, PathBuf::from("/explicit.sock"));
    }

    #[test]
    fn resolve_socket_path_uses_detected_socket_when_unconfigured() {
        let path = resolve_socket_path(None, || Some(PathBuf::from("/detected.sock"))).unwrap();

        assert_eq!(path, PathBuf::from("/detected.sock"));
    }

    #[test]
    fn resolve_socket_path_errors_when_neither_source_resolves() {
        let err = resolve_socket_path(None, || None).unwrap_err();

        assert!(err.to_string().contains("no responsive Podman API socket"));
    }

    fn cdi_devices_config(device_ids: &[&str]) -> prost_types::Struct {
        prost_types::Struct {
            fields: std::iter::once((
                "cdi_devices".to_string(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::ListValue(
                        prost_types::ListValue {
                            values: device_ids
                                .iter()
                                .map(|device_id| prost_types::Value {
                                    kind: Some(prost_types::value::Kind::StringValue(
                                        (*device_id).to_string(),
                                    )),
                                })
                                .collect(),
                        },
                    )),
                },
            ))
            .collect(),
        }
    }

    fn gpu_resources(count: Option<u32>) -> ResourceRequirements {
        ResourceRequirements {
            gpu: Some(GpuResourceRequirements { count }),
        }
    }

    #[test]
    fn podman_driver_error_from_conflict() {
        let err = ComputeDriverError::from(PodmanApiError::Conflict("exists".into()));
        assert!(matches!(err, ComputeDriverError::AlreadyExists));
    }

    #[test]
    fn podman_driver_error_from_not_found() {
        let err = ComputeDriverError::from(PodmanApiError::NotFound("gone".into()));
        assert!(matches!(err, ComputeDriverError::NotFound));
    }

    #[tokio::test]
    async fn stop_missing_workload_still_reclaims_supervisor() {
        let (socket, requests, handle) = spawn_podman_stub(
            "stop-orphan-supervisor",
            vec![
                StubResponse::new(StatusCode::OK, "[]"),
                StubResponse::new(StatusCode::NO_CONTENT, ""),
            ],
        );
        let result = test_driver(socket).stop_sandbox("sandbox-1").await;
        assert!(matches!(result, Err(ComputeDriverError::NotFound)));
        handle.await.unwrap();
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("/stop?timeout=10"));
        assert!(requests[1].contains(&crate::isolation::supervisor_name("sandbox-1")));
    }

    #[tokio::test]
    async fn stop_and_start_target_the_existing_container() {
        let (stop_socket, stop_requests, stop_handle) = spawn_podman_stub(
            "lifecycle-stop",
            vec![
                StubResponse::new(StatusCode::OK, r#"[{"Id":"ctr-1","State":"running"}]"#),
                StubResponse::new(StatusCode::NO_CONTENT, ""), // companion stop
                StubResponse::new(StatusCode::NO_CONTENT, ""),
                StubResponse::new(
                    StatusCode::OK,
                    r#"{"Id":"ctr-1","Name":"sandbox","State":{"Status":"exited","Running":false,"FinishedAt":"2026-08-12T16:39:13Z"},"Config":{}}"#,
                ),
            ],
        );
        test_driver(stop_socket.clone())
            .stop_sandbox("sandbox-1")
            .await
            .expect("stop should succeed");
        stop_handle.await.expect("stop stub should finish");
        assert_eq!(
            stop_requests
                .lock()
                .expect("request log lock should not be poisoned")[2],
            format!(
                "POST {}",
                api_path("/libpod/containers/ctr-1/stop?timeout=10")
            )
        );
        assert_eq!(
            stop_requests
                .lock()
                .expect("request log lock should not be poisoned")[3],
            format!("GET {}", api_path("/libpod/containers/ctr-1/json"))
        );

        let (start_socket, start_requests, start_handle) = spawn_podman_stub(
            "lifecycle-start",
            vec![
                StubResponse::new(StatusCode::OK, r#"[{"Id":"ctr-1","State":"stopped"}]"#),
                StubResponse::new(
                    StatusCode::OK,
                    r#"{"Id":"ctr-1","Name":"sandbox","State":{"Status":"exited","Running":false,"FinishedAt":"2026-08-12T16:39:13Z"},"Config":{}}"#,
                ),
            ].into_iter().chain(restart_responses()).collect(),
        );
        let authentication = encoded_launch_authentication();
        test_driver(start_socket.clone())
            .start_sandbox("sandbox-1", "generation-1", &authentication)
            .await
            .expect("start should succeed");
        start_handle.await.expect("start stub should finish");
        let restart_requests = start_requests.lock().unwrap().clone();
        assert_eq!(
            restart_requests
                .iter()
                .filter(|request| request.starts_with("PUT "))
                .cloned()
                .collect::<Vec<_>>(),
            vec![
                format!(
                    "PUT {}",
                    api_path("/libpod/containers/ctr-1/archive?path=%2F.openshell%2Fchannel")
                ),
                format!(
                    "PUT {}",
                    api_path("/libpod/containers/openshell-supervisor-sandbox-1/archive?path=%2F")
                ),
            ]
        );
        assert!(
            !restart_requests
                .iter()
                .any(|request| request.contains("/volumes/create")
                    || request.contains("/containers/create"))
        );
        assert_eq!(
            start_requests
                .lock()
                .expect("request log lock should not be poisoned")[1],
            format!("GET {}", api_path("/libpod/containers/ctr-1/json"))
        );
        assert_eq!(
            start_requests
                .lock()
                .expect("request log lock should not be poisoned")[2],
            format!(
                "POST {}",
                api_path("/libpod/containers/openshell-supervisor-sandbox-1/stop?timeout=10")
            )
        );

        let _ = fs::remove_file(stop_socket);
        let _ = fs::remove_file(start_socket);
    }

    #[tokio::test]
    async fn stop_waits_for_the_container_to_leave_stopping_state() {
        let (socket, requests, handle) = spawn_podman_stub(
            "lifecycle-stop-wait",
            vec![
                StubResponse::new(StatusCode::OK, r#"[{"Id":"ctr-1","State":"running"}]"#),
                StubResponse::new(StatusCode::NO_CONTENT, ""), // companion stop
                StubResponse::new(StatusCode::NO_CONTENT, ""),
                StubResponse::new(
                    StatusCode::OK,
                    r#"{"Id":"ctr-1","Name":"sandbox","State":{"Status":"stopping","Running":true},"Config":{}}"#,
                ),
                StubResponse::new(
                    StatusCode::OK,
                    r#"{"Id":"ctr-1","Name":"sandbox","State":{"Status":"exited","Running":false,"FinishedAt":"2026-08-12T16:39:13Z"},"Config":{}}"#,
                ),
            ],
        );

        test_driver(socket.clone())
            .stop_sandbox("sandbox-1")
            .await
            .expect("stop should wait for the terminal container state");
        handle.await.expect("stop stub should finish");

        let requests = requests
            .lock()
            .expect("request log lock should not be poisoned");
        assert_eq!(requests.len(), 5);
        assert_eq!(
            requests[3],
            format!("GET {}", api_path("/libpod/containers/ctr-1/json"))
        );
        assert_eq!(requests[4], requests[3]);

        let _ = fs::remove_file(socket);
    }

    #[tokio::test]
    async fn stop_retry_waits_for_an_existing_stopping_container() {
        let (socket, requests, handle) = spawn_podman_stub(
            "lifecycle-stop-retry",
            vec![
                StubResponse::new(StatusCode::OK, r#"[{"Id":"ctr-1","State":"stopping"}]"#),
                StubResponse::new(StatusCode::NO_CONTENT, ""), // companion stop
                StubResponse::new(
                    StatusCode::OK,
                    r#"{"Id":"ctr-1","Name":"sandbox","State":{"Status":"exited","Running":false,"FinishedAt":"2026-08-12T16:39:13Z"},"Config":{}}"#,
                ),
            ],
        );

        test_driver(socket.clone())
            .stop_sandbox("sandbox-1")
            .await
            .expect("stop retry should wait for the terminal container state");
        handle.await.expect("stop retry stub should finish");

        let requests = requests
            .lock()
            .expect("request log lock should not be poisoned");
        assert_eq!(requests.len(), 3);
        assert_eq!(
            requests[2],
            format!("GET {}", api_path("/libpod/containers/ctr-1/json"))
        );

        let _ = fs::remove_file(socket);
    }

    #[tokio::test]
    async fn stop_sandbox_exports_a_podman_operation_span() {
        use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
        use tracing::instrument::WithSubscriber as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        let _tracing_lock = openshell_otel_test_support::tracing_test_lock().await;
        let (socket_path, _requests, handle) = spawn_podman_stub(
            "trace-stop",
            vec![
                StubResponse::new(StatusCode::OK, r#"[{"Id":"ctr-1","State":"running"}]"#),
                StubResponse::new(StatusCode::NO_CONTENT, ""), // companion stop
                StubResponse::new(StatusCode::NO_CONTENT, ""),
                StubResponse::new(
                    StatusCode::OK,
                    r#"{"Id":"ctr-1","Name":"sandbox","State":{"Status":"exited","Running":false,"FinishedAt":"2026-08-12T16:39:13Z"},"Config":{}}"#,
                ),
            ],
        );
        let exporter = InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber =
            tracing_subscriber::registry().with(crate::otel_tracing::TRACING.layer(&provider));

        test_driver(socket_path.clone())
            .stop_sandbox("sandbox-1")
            .with_subscriber(subscriber)
            .await
            .expect("stop should succeed");
        handle.await.expect("stub should finish");
        provider.force_flush().unwrap();

        let spans = exporter.get_finished_spans().unwrap();
        let span = spans
            .iter()
            .find(|span| span.name == "podman.stop_sandbox")
            .expect("stop operation should be exported");
        assert_eq!(
            span.attributes
                .iter()
                .find(|attribute| attribute.key.as_str() == "sandbox.id")
                .map(|attribute| attribute.value.to_string())
                .as_deref(),
            Some("sandbox-1")
        );
        provider.shutdown().unwrap();
        let _ = fs::remove_file(socket_path);
    }

    #[tokio::test]
    async fn start_sandbox_span_does_not_capture_launch_authentication() {
        use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
        use tracing::instrument::WithSubscriber as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        let _tracing_lock = openshell_otel_test_support::tracing_test_lock().await;
        let exporter = InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber =
            tracing_subscriber::registry().with(crate::otel_tracing::TRACING.layer(&provider));

        test_driver(PathBuf::from("/nonexistent/podman.sock"))
            .start_sandbox(
                "sandbox-1",
                "invalid-generation",
                b"secret-launch-authentication",
            )
            .with_subscriber(subscriber)
            .await
            .expect_err("invalid generation must fail before contacting Podman");
        provider.force_flush().unwrap();

        let spans = exporter.get_finished_spans().unwrap();
        let span = spans
            .iter()
            .find(|span| span.name == "podman.start_sandbox")
            .expect("start operation span");
        assert!(span.attributes.iter().all(|attribute| {
            !matches!(
                attribute.key.as_str(),
                "launch_authentication" | "encoded_authentication"
            )
        }));
        provider.shutdown().unwrap();
    }

    #[tokio::test]
    async fn create_sandbox_exports_nested_preparation_spans() {
        use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
        use tracing::instrument::WithSubscriber as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        let _tracing_lock = openshell_otel_test_support::tracing_test_lock().await;
        let (socket_path, requests, handle) = spawn_podman_stub(
            "trace-create",
            create_setup_responses(false, "sandbox-trace")
                .into_iter()
                .chain(create_launch_responses())
                .collect(),
        );
        let exporter = InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber =
            tracing_subscriber::registry().with(crate::otel_tracing::TRACING.layer(&provider));

        let mut sandbox = plain_sandbox("sandbox-trace", "demo");
        sandbox.spec = Some(DriverSandboxSpec {
            launch_authentication: encoded_launch_authentication(),
            ..DriverSandboxSpec::default()
        });
        test_driver(socket_path.clone())
            .create_sandbox(&sandbox)
            .with_subscriber(subscriber)
            .await
            .expect("create should succeed");
        handle.await.expect("stub should finish");
        let uploads: Vec<_> = requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.starts_with("PUT "))
            .cloned()
            .collect();
        assert_eq!(
            uploads,
            [
                "/libpod/containers/workload/archive?path=%2F.openshell%2Fchannel",
                "/libpod/containers/workload/archive?path=%2Fsandbox",
                "/libpod/containers/supervisor/archive?path=%2F",
            ]
            .map(|path| format!("PUT {}", api_path(path)))
        );
        provider.force_flush().unwrap();

        let spans = exporter.get_finished_spans().unwrap();
        let create = spans
            .iter()
            .find(|span| span.name == "podman.provision")
            .expect("create operation should be exported");
        for name in [
            "podman.prepare_images",
            "podman.prepare_storage",
            "podman.prepare_container",
        ] {
            let child = spans
                .iter()
                .find(|span| span.name == name)
                .unwrap_or_else(|| panic!("{name} should be exported"));
            assert_eq!(
                child.parent_span_id,
                create.span_context.span_id(),
                "{name}"
            );
        }
        provider.shutdown().unwrap();
        let _ = fs::remove_file(socket_path);
    }

    #[tokio::test]
    async fn prepare_images_span_covers_and_marks_sandbox_image_pull_failure() {
        use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
        use tracing::instrument::WithSubscriber as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        let _tracing_lock = openshell_otel_test_support::tracing_test_lock().await;
        let (socket_path, _requests, handle) = spawn_podman_stub(
            "trace-image-failure",
            vec![
                StubResponse::new(StatusCode::OK, "{}"),
                StubResponse::new(StatusCode::INTERNAL_SERVER_ERROR, "pull failed"),
            ],
        );
        let exporter = InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber =
            tracing_subscriber::registry().with(crate::otel_tracing::TRACING.layer(&provider));

        test_driver(socket_path.clone())
            .create_sandbox(&plain_sandbox("sandbox-trace", "demo"))
            .with_subscriber(subscriber)
            .await
            .expect_err("sandbox image pull should fail");
        handle.await.expect("stub should finish");
        provider.force_flush().unwrap();

        let spans = exporter.get_finished_spans().unwrap();
        let phase = spans
            .iter()
            .find(|span| span.name == "podman.prepare_images")
            .expect("image preparation should be exported");
        assert!(matches!(
            phase.status,
            opentelemetry::trace::Status::Error { .. }
        ));
        provider.shutdown().unwrap();
        let _ = fs::remove_file(socket_path);
    }

    #[tokio::test]
    async fn start_and_delete_export_podman_operation_spans() {
        use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
        use tracing::instrument::WithSubscriber as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        let _tracing_lock = openshell_otel_test_support::tracing_test_lock().await;
        let exporter = InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber =
            tracing_subscriber::registry().with(crate::otel_tracing::TRACING.layer(&provider));

        let (start_socket, _requests, start_handle) = spawn_podman_stub(
            "trace-start",
            vec![
                StubResponse::new(StatusCode::OK, r#"[{"Id":"ctr-1","State":"stopped"}]"#),
                StubResponse::new(
                    StatusCode::OK,
                    r#"{"Id":"ctr-1","Name":"sandbox","State":{"Status":"exited","Running":false,"FinishedAt":"2026-08-12T16:39:13Z"},"Config":{}}"#,
                ),
            ].into_iter().chain(restart_responses()).collect(),
        );
        let authentication = encoded_launch_authentication();
        test_driver(start_socket.clone())
            .start_sandbox("sandbox-1", "generation-1", &authentication)
            .with_subscriber(subscriber)
            .await
            .expect("start should succeed");
        start_handle.await.expect("start stub should finish");

        let (delete_socket, _requests, delete_handle) = spawn_podman_stub(
            "trace-delete",
            vec![
                StubResponse::new(StatusCode::NO_CONTENT, ""), // remove companion
                StubResponse::new(StatusCode::NO_CONTENT, ""), // remove channel if detached
                StubResponse::new(StatusCode::OK, "[]"),
                StubResponse::new(StatusCode::NO_CONTENT, ""),
            ],
        );
        let subscriber =
            tracing_subscriber::registry().with(crate::otel_tracing::TRACING.layer(&provider));
        test_driver(delete_socket.clone())
            .delete_sandbox("sandbox-1")
            .with_subscriber(subscriber)
            .await
            .expect("delete should succeed");
        delete_handle.await.expect("delete stub should finish");
        provider.force_flush().unwrap();

        let spans = exporter.get_finished_spans().unwrap();
        assert!(spans.iter().any(|span| span.name == "podman.start_sandbox"));
        assert!(
            spans
                .iter()
                .any(|span| span.name == "podman.delete_sandbox")
        );
        provider.shutdown().unwrap();
        let _ = fs::remove_file(start_socket);
        let _ = fs::remove_file(delete_socket);
    }

    #[test]
    fn validate_gpu_request_accepts_gpu_count_request_shape() {
        let gpu = GpuResourceRequirements { count: Some(2) };
        let driver_config = PodmanSandboxDriverConfig::default();

        PodmanComputeDriver::validate_gpu_request(Some(&gpu), &driver_config)
            .expect("default GPU count shape should be accepted before inventory selection");
    }

    #[test]
    fn validate_gpu_request_accepts_single_cdi_device_without_gpu_count() {
        let gpu = GpuResourceRequirements { count: None };
        let mut driver_config = PodmanSandboxDriverConfig::default();
        driver_config.cdi_devices = Some(vec!["nvidia.com/gpu=0".to_string()]);

        PodmanComputeDriver::validate_gpu_request(Some(&gpu), &driver_config)
            .expect("single exact CDI device should pass count validation");
    }

    #[test]
    fn validate_gpu_request_rejects_multiple_cdi_devices_without_gpu_count() {
        let gpu = GpuResourceRequirements { count: None };
        let mut driver_config = PodmanSandboxDriverConfig::default();
        driver_config.cdi_devices = Some(vec![
            "nvidia.com/gpu=0".to_string(),
            "nvidia.com/gpu=1".to_string(),
        ]);
        let err = PodmanComputeDriver::validate_gpu_request(Some(&gpu), &driver_config)
            .expect_err("missing CDI device count should be rejected for multiple devices");

        assert!(matches!(err, ComputeDriverError::InvalidArgument(_)));
        assert!(
            err.to_string()
                .contains("gpu count (1) must match driver_config.cdi_devices length (2)")
        );
    }

    #[test]
    fn validate_gpu_request_rejects_cdi_devices_without_gpu_request() {
        let mut driver_config = PodmanSandboxDriverConfig::default();
        driver_config.cdi_devices = Some(vec!["nvidia.com/gpu=0".to_string()]);
        let err = PodmanComputeDriver::validate_gpu_request(None, &driver_config)
            .expect_err("missing GPU request should be rejected");

        assert!(matches!(err, ComputeDriverError::InvalidArgument(_)));
        assert!(err.to_string().contains("requires a gpu request"));
    }

    #[test]
    fn validate_gpu_request_rejects_mismatched_cdi_device_count() {
        let gpu = GpuResourceRequirements { count: Some(2) };
        let mut driver_config = PodmanSandboxDriverConfig::default();
        driver_config.cdi_devices = Some(vec!["nvidia.com/gpu=0".to_string()]);
        let err = PodmanComputeDriver::validate_gpu_request(Some(&gpu), &driver_config)
            .expect_err("mismatched CDI device count should be rejected");

        assert!(matches!(err, ComputeDriverError::InvalidArgument(_)));
        assert!(
            err.to_string()
                .contains("gpu count (2) must match driver_config.cdi_devices length (1)")
        );
    }

    // ── grpc_endpoint auto-detection ───────────────────────────────────
    //
    // PodmanComputeDriver::new() fills grpc_endpoint through
    // select_grpc_endpoint() when it is empty.

    #[test]
    fn grpc_endpoint_uses_loopback_on_linux() {
        let cfg = PodmanComputeConfig {
            gateway_port: 8081,
            ..PodmanComputeConfig::default()
        };
        assert_eq!(
            select_grpc_endpoint(&cfg, PodmanEndpointEnvironment::LinuxHost),
            "http://127.0.0.1:8081"
        );
    }

    #[test]
    fn grpc_endpoint_uses_host_alias_on_podman_machine() {
        let cfg = PodmanComputeConfig {
            gateway_port: 8080,
            guest_tls_ca: Some(PathBuf::from("/tls/ca.crt")),
            guest_tls_cert: Some(PathBuf::from("/tls/tls.crt")),
            guest_tls_key: Some(PathBuf::from("/tls/tls.key")),
            ..PodmanComputeConfig::default()
        };
        assert_eq!(
            select_grpc_endpoint(&cfg, PodmanEndpointEnvironment::PodmanMachine),
            "https://host.containers.internal:8080"
        );
    }

    #[test]
    fn partial_tls_config_returns_error() {
        let cfg = PodmanComputeConfig {
            gateway_port: 8080,
            guest_tls_ca: Some(PathBuf::from("/tls/ca.crt")),
            // guest_tls_cert and guest_tls_key not set — incomplete TLS config.
            ..PodmanComputeConfig::default()
        };
        assert!(!cfg.tls_enabled());
        let err = cfg
            .validate_tls_config()
            .expect_err("partial TLS config should be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("OPENSHELL_PODMAN_TLS_CERT"),
            "error should name the missing cert: {msg}"
        );
        assert!(
            msg.contains("OPENSHELL_PODMAN_TLS_KEY"),
            "error should name the missing key: {msg}"
        );
    }

    #[test]
    fn explicit_grpc_endpoint_takes_precedence() {
        let cfg = PodmanComputeConfig {
            grpc_endpoint: "https://gateway.internal:9000".to_string(),
            gateway_port: 8081,
            ..PodmanComputeConfig::default()
        };
        assert_eq!(
            select_grpc_endpoint(&cfg, PodmanEndpointEnvironment::LinuxHost),
            "https://gateway.internal:9000"
        );
    }

    #[test]
    fn confined_apparmor_profiles_follow_podman_capability() {
        use openshell_core::AppArmorProfile;

        for profile in [
            AppArmorProfile::RuntimeDefault,
            AppArmorProfile::Localhost("openshell-supervisor".to_string()),
        ] {
            validate_apparmor_support(Some(&profile), true)
                .expect("confined profile should be accepted when Podman reports AppArmor");
            let error = validate_apparmor_support(Some(&profile), false)
                .expect_err("confined profile must fail when AppArmor is unavailable");
            assert!(error.to_string().contains("AppArmor is unavailable"));
        }
        validate_apparmor_support(Some(&AppArmorProfile::Unconfined), false)
            .expect("Unconfined does not require AppArmor support");
        validate_apparmor_support(None, false)
            .expect("an omitted profile preserves Podman's runtime behavior");
    }

    #[test]
    fn local_podman_cdi_gpu_inventory_maps_nvidia_device_nodes() {
        let root = std::env::temp_dir().join(format!(
            "openshell-podman-gpu-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be after unix epoch")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("create temp dev root");
        fs::write(root.join("nvidia2"), "").expect("create nvidia2");
        fs::write(root.join("nvidiactl"), "").expect("create nvidiactl");
        fs::write(root.join("nvidia0"), "").expect("create nvidia0");

        let inventory = local_podman_cdi_gpu_inventory_from(&root);

        fs::remove_dir_all(&root).expect("remove temp dev root");
        assert_eq!(
            inventory.as_slice(),
            &vec![
                "nvidia.com/gpu=0".to_string(),
                "nvidia.com/gpu=2".to_string()
            ]
        );
    }

    #[test]
    fn local_podman_cdi_gpu_inventory_maps_dxg_to_all_gpu_fallback() {
        let root = std::env::temp_dir().join(format!(
            "openshell-podman-dxg-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be after unix epoch")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("create temp dev root");
        fs::write(root.join("dxg"), "").expect("create dxg");

        let inventory = local_podman_cdi_gpu_inventory_from(&root);
        let allow_all_default = local_podman_all_gpu_default_supported_from(&root);

        fs::remove_dir_all(&root).expect("remove temp dev root");
        assert_eq!(inventory.as_slice(), &vec![CDI_GPU_DEVICE_ALL.to_string()]);
        assert!(allow_all_default);
    }

    #[tokio::test]
    async fn validate_sandbox_create_accepts_default_gpu_with_inventory() {
        use openshell_core::proto::compute::v1::DriverSandboxSpec;

        let driver = PodmanComputeDriver::for_tests_with_gpu_inventory(
            PodmanComputeConfig::default(),
            CdiGpuInventory::new(["nvidia.com/gpu=0"]),
        );
        let sandbox = DriverSandbox {
            spec: Some(DriverSandboxSpec {
                resource_requirements: Some(gpu_resources(None)),
                ..Default::default()
            }),
            ..Default::default()
        };

        driver.validate_sandbox_create(&sandbox).await.unwrap();
    }

    #[tokio::test]
    async fn validate_sandbox_create_accepts_all_only_inventory_when_dxg_fallback_allowed() {
        use openshell_core::proto::compute::v1::DriverSandboxSpec;

        let driver = PodmanComputeDriver::for_tests_with_gpu_inventory_and_all_fallback(
            PodmanComputeConfig::default(),
            CdiGpuInventory::new([CDI_GPU_DEVICE_ALL]),
            true,
        );
        let sandbox = DriverSandbox {
            spec: Some(DriverSandboxSpec {
                resource_requirements: Some(gpu_resources(None)),
                ..Default::default()
            }),
            ..Default::default()
        };

        driver.validate_sandbox_create(&sandbox).await.unwrap();
    }

    #[tokio::test]
    async fn validate_sandbox_create_rejects_all_only_inventory_without_dxg_fallback() {
        use openshell_core::proto::compute::v1::DriverSandboxSpec;

        let driver = PodmanComputeDriver::for_tests_with_gpu_inventory(
            PodmanComputeConfig::default(),
            CdiGpuInventory::new([CDI_GPU_DEVICE_ALL]),
        );
        let sandbox = DriverSandbox {
            spec: Some(DriverSandboxSpec {
                resource_requirements: Some(gpu_resources(None)),
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = driver.validate_sandbox_create(&sandbox).await.unwrap_err();

        assert!(err.to_string().contains("nvidia.com/gpu=all"));
    }

    #[tokio::test]
    async fn validate_sandbox_create_passes_explicit_cdi_device_id_without_inventory() {
        use openshell_core::proto::compute::v1::{DriverSandboxSpec, DriverSandboxTemplate};

        let driver = PodmanComputeDriver::for_tests(PodmanComputeConfig {
            allow_driver_config: true,
            ..Default::default()
        });
        let sandbox = DriverSandbox {
            spec: Some(DriverSandboxSpec {
                resource_requirements: Some(gpu_resources(None)),
                template: Some(DriverSandboxTemplate {
                    driver_config: Some(cdi_devices_config(&["nvidia.com/gpu=0"])),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        driver.validate_sandbox_create(&sandbox).await.unwrap();
    }

    #[test]
    fn driver_default_gpu_selection_consumes_distinct_devices_for_creates() {
        use openshell_core::proto::compute::v1::DriverSandboxSpec;

        let driver = PodmanComputeDriver::for_tests_with_gpu_inventory(
            PodmanComputeConfig::default(),
            CdiGpuInventory::new(["nvidia.com/gpu=0", "nvidia.com/gpu=1"]),
        );
        let first_sandbox = DriverSandbox {
            id: "sbx-first".to_string(),
            name: "first".to_string(),
            spec: Some(DriverSandboxSpec {
                resource_requirements: Some(gpu_resources(None)),
                ..Default::default()
            }),
            ..Default::default()
        };
        let second_sandbox = DriverSandbox {
            id: "sbx-second".to_string(),
            name: "second".to_string(),
            spec: Some(DriverSandboxSpec {
                resource_requirements: Some(gpu_resources(None)),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(
            driver.gpu_selector.peek_device_ids(1).unwrap(),
            vec!["nvidia.com/gpu=0".to_string()]
        );
        let first_devices = driver.gpu_selector.next_device_ids(1).unwrap();
        let first_spec = container::build_container_spec_with_token_and_gpu_devices(
            &first_sandbox,
            &driver.config,
            None,
            Some(&first_devices),
        )
        .unwrap();

        assert_eq!(
            driver.gpu_selector.peek_device_ids(1).unwrap(),
            vec!["nvidia.com/gpu=1".to_string()]
        );
        let second_devices = driver.gpu_selector.next_device_ids(1).unwrap();
        let second_spec = container::build_container_spec_with_token_and_gpu_devices(
            &second_sandbox,
            &driver.config,
            None,
            Some(&second_devices),
        )
        .unwrap();

        assert_eq!(
            first_spec["devices"][0]["path"].as_str(),
            Some("nvidia.com/gpu=0")
        );
        assert_eq!(
            second_spec["devices"][0]["path"].as_str(),
            Some("nvidia.com/gpu=1")
        );
    }

    #[test]
    fn supervisor_pull_policy_refreshes_mutable_tags_only() {
        assert_eq!(
            runtime_image_pull_policy("ghcr.io/nvidia/openshell/supervisor:dev"),
            "newer"
        );
        assert_eq!(
            runtime_image_pull_policy("ghcr.io/nvidia/openshell/supervisor:latest"),
            "newer"
        );
        assert_eq!(
            runtime_image_pull_policy("ghcr.io/nvidia/openshell/supervisor"),
            "newer"
        );
        assert_eq!(
            runtime_image_pull_policy(
                "ghcr.io/nvidia/openshell/supervisor:0.0.47-dev.13-g57b71c68f"
            ),
            "missing"
        );
        assert_eq!(
            runtime_image_pull_policy("ghcr.io/nvidia/openshell/supervisor@sha256:abc123"),
            "missing"
        );
    }

    fn test_driver(socket_path: PathBuf) -> PodmanComputeDriver {
        let config = PodmanComputeConfig {
            allow_driver_config: true,
            resource_admission: openshell_core::resource_admission::ResourceAdmissionConfig {
                enabled: false,
                ..Default::default()
            },
            socket_path: Some(socket_path),
            stop_timeout_secs: 10,
            ..PodmanComputeConfig::default()
        };
        PodmanComputeDriver::for_tests(config)
    }

    fn test_driver_with_config(mut config: PodmanComputeConfig) -> PodmanComputeDriver {
        config.allow_driver_config = true;
        config.resource_admission.enabled = false;
        PodmanComputeDriver::for_tests(config)
    }

    fn json_struct(value: serde_json::Value) -> prost_types::Struct {
        let serde_json::Value::Object(object) = value else {
            panic!("expected JSON object");
        };
        openshell_core::proto_struct::json_object_to_struct(object)
            .expect("test JSON must convert to a protobuf Struct")
    }

    fn sandbox_with_volume_mount(volume: &str) -> DriverSandbox {
        DriverSandbox {
            id: "sandbox-123".to_string(),
            name: "demo".to_string(),
            namespace: String::new(),
            spec: Some(DriverSandboxSpec {
                template: Some(DriverSandboxTemplate {
                    driver_config: Some(json_struct(serde_json::json!({
                        "mounts": [{
                            "type": "volume",
                            "source": volume,
                            "target": "/sandbox/work"
                        }]
                    }))),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            status: None,
            workspace: String::new(),
        }
    }

    #[tokio::test]
    async fn private_volume_collision_is_not_adopted_or_relabelled() {
        let (socket, requests, handle) = spawn_podman_stub(
            "admission-collision",
            vec![StubResponse::new(
                StatusCode::OK,
                serde_json::json!({
                    "Name":"private-collision", "Driver":"local", "Options":{}, "Labels":{}
                })
                .to_string(),
            )],
        );
        let driver = test_driver(socket.clone());
        assert!(
            driver
                .client
                .create_owned_volume("private-collision", "sandbox-123", "team-a")
                .await
                .is_err()
        );
        handle.await.unwrap();
        let logged = requests.lock().unwrap();
        assert_eq!(logged.len(), 1);
        assert!(logged[0].starts_with("GET "));
        let _ = fs::remove_file(socket);
    }

    #[tokio::test]
    async fn admission_requires_explicit_volume_labels_and_workspace_match() {
        for (labels, allowed) in [
            (serde_json::json!(null), false),
            (serde_json::json!({}), false),
            (
                serde_json::json!({"openshell.ai/sandbox-attachable":"true","openshell.ai/sandbox-attachable-workspace":"other"}),
                false,
            ),
            (
                serde_json::json!({"openshell.ai/sandbox-attachable":"true","openshell.ai/sandbox-attachable-workspace":"team-a"}),
                true,
            ),
        ] {
            let (socket, requests, handle) = spawn_podman_stub("admission-labels", vec![StubResponse::new(StatusCode::OK,
                serde_json::json!({"Name":"existing","Driver":"local","Options":{},"Labels":labels}).to_string())]);
            let driver = PodmanComputeDriver::for_tests(PodmanComputeConfig {
                socket_path: Some(socket.clone()),
                allow_driver_config: true,
                ..Default::default()
            });
            let mut sandbox = sandbox_with_volume_mount("existing");
            sandbox.workspace = "team-a".into();
            let result = driver.validate_sandbox_create(&sandbox).await;
            if !allowed {
                assert!(
                    result
                        .as_ref()
                        .unwrap_err()
                        .to_string()
                        .contains("podman volume 'existing'")
                );
            }
            assert_eq!(result.is_ok(), allowed);
            handle.await.unwrap();
            assert!(
                requests
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|request| request.starts_with("GET "))
            );
            let _ = fs::remove_file(socket);
        }
    }

    #[tokio::test]
    async fn admission_driver_config_denial_does_not_contact_podman() {
        for enabled in [true, false] {
            let driver = PodmanComputeDriver::for_tests(PodmanComputeConfig {
                resource_admission: openshell_core::resource_admission::ResourceAdmissionConfig {
                    enabled,
                    ..Default::default()
                },
                ..Default::default()
            });
            let error = driver
                .validate_sandbox_create(&sandbox_with_volume_mount("existing"))
                .await
                .unwrap_err();
            assert!(error.to_string().contains("allow_driver_config"));
        }
    }

    fn api_path(path: &str) -> String {
        format!("/v5.0.0{path}")
    }

    #[test]
    fn podman_local_volume_with_bind_option_is_bind_backed() {
        let volume = VolumeInspect {
            created_at: None,
            labels: None,
            name: String::new(),
            driver: "local".to_string(),
            options: HashMap::from([("o".to_string(), "rw,bind".to_string())]),
        };

        assert!(podman_volume_is_bind_backed(&volume));
    }

    #[test]
    fn podman_local_volume_with_rbind_option_is_bind_backed() {
        let volume = VolumeInspect {
            created_at: None,
            labels: None,
            name: String::new(),
            driver: "local".to_string(),
            options: HashMap::from([("o".to_string(), "rw,rbind".to_string())]),
        };

        assert!(podman_volume_is_bind_backed(&volume));
    }

    #[test]
    fn podman_empty_driver_volume_with_bind_option_is_bind_backed() {
        let volume = VolumeInspect {
            created_at: None,
            labels: None,
            name: String::new(),
            driver: String::new(),
            options: HashMap::from([("o".to_string(), "bind".to_string())]),
        };

        assert!(podman_volume_is_bind_backed(&volume));
    }

    #[test]
    fn podman_local_volume_without_bind_option_is_not_bind_backed() {
        let volume = VolumeInspect {
            created_at: None,
            labels: None,
            name: String::new(),
            driver: "local".to_string(),
            options: HashMap::from([("o".to_string(), "addr=127.0.0.1,rw".to_string())]),
        };

        assert!(!podman_volume_is_bind_backed(&volume));
    }

    #[test]
    fn podman_nonlocal_volume_with_bind_option_is_not_bind_backed() {
        let volume = VolumeInspect {
            created_at: None,
            labels: None,
            name: String::new(),
            driver: "custom".to_string(),
            options: HashMap::from([("o".to_string(), "bind".to_string())]),
        };

        assert!(!podman_volume_is_bind_backed(&volume));
    }

    #[tokio::test]
    async fn validate_sandbox_rejects_bind_backed_named_volume_unless_enabled() {
        let (socket_path, request_log, handle) = spawn_podman_stub(
            "bind-volume-disabled",
            vec![StubResponse::new(
                StatusCode::OK,
                r#"{"Name":"work-bind","Driver":"local","Options":{"type":"none","o":"rw,bind","device":"/srv/work"}}"#,
            )],
        );
        let driver = test_driver(socket_path.clone());
        let sandbox = sandbox_with_volume_mount("work-bind");

        let err = driver
            .validate_sandbox_create(&sandbox)
            .await
            .expect_err("bind-backed volume should require bind mount opt-in");

        match err {
            ComputeDriverError::Precondition(message) => {
                assert!(message.contains("enable_bind_mounts = true"));
            }
            other => panic!("expected precondition error, got {other:?}"),
        }
        handle.await.expect("stub task should finish");
        assert_eq!(
            request_log
                .lock()
                .expect("request log lock should not be poisoned")
                .as_slice(),
            [format!(
                "GET {}",
                api_path("/libpod/volumes/work-bind/json")
            )]
        );
        let _ = fs::remove_file(socket_path);
    }

    #[tokio::test]
    async fn validate_sandbox_rejects_rbind_backed_named_volume_unless_enabled() {
        let (socket_path, request_log, handle) = spawn_podman_stub(
            "rbind-volume-disabled",
            vec![StubResponse::new(
                StatusCode::OK,
                r#"{"Name":"work-rbind","Driver":"local","Options":{"type":"none","o":"rw,rbind","device":"/srv/work"}}"#,
            )],
        );
        let driver = test_driver(socket_path.clone());
        let sandbox = sandbox_with_volume_mount("work-rbind");

        let err = driver
            .validate_sandbox_create(&sandbox)
            .await
            .expect_err("rbind-backed volume should require bind mount opt-in");

        match err {
            ComputeDriverError::Precondition(message) => {
                assert!(message.contains("enable_bind_mounts = true"));
            }
            other => panic!("expected precondition error, got {other:?}"),
        }
        handle.await.expect("stub task should finish");
        assert_eq!(
            request_log
                .lock()
                .expect("request log lock should not be poisoned")
                .as_slice(),
            [format!(
                "GET {}",
                api_path("/libpod/volumes/work-rbind/json")
            )]
        );
        let _ = fs::remove_file(socket_path);
    }

    #[tokio::test]
    async fn validate_sandbox_allows_bind_backed_named_volume_when_enabled() {
        let (socket_path, _request_log, handle) = spawn_podman_stub(
            "bind-volume-enabled",
            vec![StubResponse::new(
                StatusCode::OK,
                r#"{"Name":"work-bind","Driver":"local","Options":{"type":"none","o":"rw,bind","device":"/srv/work"}}"#,
            )],
        );
        let config = PodmanComputeConfig {
            socket_path: Some(socket_path.clone()),
            enable_bind_mounts: true,
            ..PodmanComputeConfig::default()
        };
        let driver = test_driver_with_config(config);
        let sandbox = sandbox_with_volume_mount("work-bind");

        driver
            .validate_sandbox_create(&sandbox)
            .await
            .expect("bind-backed volume should be allowed when bind mounts are enabled");

        handle.await.expect("stub task should finish");
        let _ = fs::remove_file(socket_path);
    }

    #[tokio::test]
    async fn delete_sandbox_cleans_up_volume_when_container_is_already_gone() {
        let sandbox_id = "sandbox-123";
        let volume_name = container::volume_name(sandbox_id);
        let (socket_path, request_log, handle) = spawn_podman_stub(
            "delete-not-found",
            vec![
                StubResponse::new(StatusCode::NO_CONTENT, ""), // remove companion
                StubResponse::new(StatusCode::NO_CONTENT, ""), // remove channel if detached
                // list_containers returns empty (container already gone)
                StubResponse::new(StatusCode::OK, "[]"),
                // remove_volume
                StubResponse::new(StatusCode::NO_CONTENT, ""),
            ],
        );
        let driver = test_driver(socket_path.clone());

        let deleted = driver
            .delete_sandbox(sandbox_id)
            .await
            .expect("delete should succeed");

        assert!(!deleted, "missing container should report deleted=false");
        handle.await.expect("stub task should finish");
        let requests = request_log
            .lock()
            .expect("request log lock should not be poisoned")
            .clone();
        assert!(requests[2].contains("/libpod/containers/json"));
        assert_eq!(
            requests[3],
            format!(
                "DELETE {}",
                api_path(&format!("/libpod/volumes/{volume_name}"))
            )
        );
        let _ = fs::remove_file(socket_path);
    }

    /// Write a valid `user:pass` credential to a unique path for proxy-auth
    /// secret tests. Caller removes it.
    fn write_proxy_auth_file(test_name: &str) -> PathBuf {
        let path = crate::test_utils::unique_socket_path(test_name).with_extension("auth");
        fs::write(&path, "user:pass\n").expect("write proxy auth file");
        path
    }

    fn proxy_auth_config(socket_path: PathBuf, auth_file: &Path) -> PodmanComputeConfig {
        PodmanComputeConfig {
            socket_path: Some(socket_path),
            stop_timeout_secs: 10,
            proxy_auth_file: Some(auth_file.to_string_lossy().into_owned()),
            proxy_auth_allow_insecure: Some(true),
            ..PodmanComputeConfig::default()
        }
    }

    fn plain_sandbox(id: &str, name: &str) -> DriverSandbox {
        DriverSandbox {
            id: id.to_string(),
            name: name.to_string(),
            namespace: String::new(),
            workspace: String::new(),
            spec: Some(DriverSandboxSpec {
                launch_authentication: encoded_launch_authentication(),
                ..Default::default()
            }),
            status: None,
        }
    }

    #[test]
    fn child_environment_preserves_precedence_and_strips_control_keys() {
        let mut sandbox = plain_sandbox("sandbox", "agent");
        sandbox.spec = Some(DriverSandboxSpec {
            template: Some(DriverSandboxTemplate {
                environment: HashMap::from([
                    ("TEMPLATE_ONLY".to_string(), "template".to_string()),
                    ("OVERRIDE".to_string(), "template".to_string()),
                ]),
                ..Default::default()
            }),
            environment: HashMap::from([
                ("REQUEST_ONLY".to_string(), "request".to_string()),
                ("OVERRIDE".to_string(), "request".to_string()),
                ("OPENSHELL_SANDBOX_TOKEN".to_string(), "spoofed".to_string()),
            ]),
            ..Default::default()
        });
        let image_env = vec![
            "IMAGE_ONLY=image".to_string(),
            "OVERRIDE=image".to_string(),
            "OPENSHELL_ENDPOINT=spoofed".to_string(),
        ];

        let environment = podman_child_environment(&sandbox, &image_env);

        assert_eq!(
            environment.get("IMAGE_ONLY").map(String::as_str),
            Some("image")
        );
        assert_eq!(
            environment.get("TEMPLATE_ONLY").map(String::as_str),
            Some("template")
        );
        assert_eq!(
            environment.get("REQUEST_ONLY").map(String::as_str),
            Some("request")
        );
        assert_eq!(
            environment.get("OVERRIDE").map(String::as_str),
            Some("request")
        );
        assert!(!environment.keys().any(|key| key.starts_with("OPENSHELL_")));
    }

    fn secret_delete_request(sandbox_id: &str) -> String {
        format!(
            "DELETE {}",
            api_path(&format!(
                "/libpod/secrets/{}",
                container::proxy_auth_secret_name(sandbox_id)
            ))
        )
    }

    fn restart_responses() -> Vec<StubResponse> {
        let mut archive = tar::Builder::new(Vec::new());
        let identity = openshell_isolation_interface::contract::ResolvedWorkloadIdentity::new(
            1000,
            1001,
            vec![],
            "image".into(),
            "sha256:image".into(),
        )
        .unwrap();
        let bundle = serde_json::to_vec(&crate::isolation::RestartMetadata {
            generation: "generation-1".to_string(),
            workload_identity: identity,
            child_env: HashMap::new(),
        })
        .unwrap();
        let mut header = tar::Header::new_gnu();
        header.set_size(bundle.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        archive
            .append_data(&mut header, "restart-metadata.json", bundle.as_slice())
            .unwrap();
        vec![
            StubResponse::new(StatusCode::NO_CONTENT, ""), // supervisor stop
            StubResponse::new(
                StatusCode::OK,
                r#"{"Id":"supervisor","Name":"supervisor","State":{"Status":"exited","Running":false},"Config":{}}"#,
            ),
            StubResponse::new(StatusCode::OK, archive.into_inner().unwrap()),
            StubResponse::new(StatusCode::OK, "").with_archive_members(channel_archive_members()),
            StubResponse::new(StatusCode::OK, ""), // refreshed supervisor auth and runtime descriptor
            fence_response(),
            StubResponse::new(StatusCode::NO_CONTENT, ""), // workload start
            StubResponse::new(StatusCode::NO_CONTENT, ""), // supervisor start
        ]
    }

    fn fence_response() -> StubResponse {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "PascalCase")]
        struct HostConfig {
            network_mode: &'static str,
            privileged: bool,
        }
        #[derive(serde::Serialize)]
        #[serde(rename_all = "PascalCase")]
        struct Networks {
            networks: std::collections::BTreeMap<String, String>,
        }
        #[derive(serde::Serialize)]
        #[serde(rename_all = "PascalCase")]
        struct Fence {
            host_config: HostConfig,
            network_settings: Networks,
        }
        StubResponse::new(
            StatusCode::OK,
            serde_json::to_vec(&Fence {
                host_config: HostConfig {
                    network_mode: "none",
                    privileged: false,
                },
                network_settings: Networks {
                    networks: std::collections::BTreeMap::default(),
                },
            })
            .unwrap(),
        )
    }

    fn created_response(id: &'static str) -> StubResponse {
        #[derive(serde::Serialize)]
        struct Created {
            #[serde(rename = "Id")]
            id: &'static str,
        }
        StubResponse::new(
            StatusCode::CREATED,
            serde_json::to_vec(&Created { id }).unwrap(),
        )
    }

    fn image_response(id: &'static str) -> StubResponse {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "PascalCase")]
        struct Config {
            user: &'static str,
        }
        #[derive(serde::Serialize)]
        #[serde(rename_all = "PascalCase")]
        struct Image {
            id: &'static str,
            config: Config,
        }
        StubResponse::new(
            StatusCode::OK,
            serde_json::to_vec(&Image {
                id,
                config: Config { user: "1234:1235" },
            })
            .unwrap(),
        )
    }

    fn sandbox_binary_archive_response() -> StubResponse {
        let mut archive = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut archive);
            let payload = b"\x7fELF-test-sandbox";
            let mut header = tar::Header::new_gnu();
            header.set_path("openshell-sandbox").unwrap();
            header.set_size(payload.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append(&header, payload.as_slice()).unwrap();
            builder.finish().unwrap();
        }
        StubResponse::new(StatusCode::OK, archive)
    }

    fn create_setup_responses(proxy_secret: bool, sandbox_id: &str) -> Vec<StubResponse> {
        let mut responses = vec![
            StubResponse::new(StatusCode::OK, "{}"), // sandbox runtime pull
            StubResponse::new(StatusCode::OK, "{}"), // supervisor pull
            StubResponse::new(StatusCode::OK, "{}"), // workload pull
            image_response("sha256:sandbox"),
            created_response("identity-reader"),
            StubResponse::new(StatusCode::NOT_FOUND, ""), // reserved hierarchy absent
            StubResponse::new(StatusCode::NOT_FOUND, ""), // optional passwd
            StubResponse::new(StatusCode::NOT_FOUND, ""), // optional group
            StubResponse::new(StatusCode::NO_CONTENT, ""), // remove stopped reader
            image_response("sha256:sandbox-runtime"),
            image_response("sha256:supervisor"),
            StubResponse::new(StatusCode::NOT_FOUND, ""), // no existing private workspace
            StubResponse::new(StatusCode::CREATED, "{}"), // workspace volume
            owned_volume_response(&container::volume_name(sandbox_id), sandbox_id),
        ];
        if proxy_secret {
            responses.push(StubResponse::new(StatusCode::CREATED, "{}"));
        }
        responses.extend([
            image_response("sha256:sandbox-runtime"),
            created_response("sandbox-runtime-extractor"),
            sandbox_binary_archive_response(),
            StubResponse::new(StatusCode::NO_CONTENT, ""), // remove extractor
        ]);
        responses.push(StubResponse::new(StatusCode::NOT_FOUND, ""));
        responses.push(StubResponse::new(StatusCode::CREATED, "{}")); // channel volume
        responses.push(owned_volume_response(
            &crate::isolation::channel_volume_name(sandbox_id),
            sandbox_id,
        ));
        responses
    }

    fn owned_volume_response(name: &str, sandbox_id: &str) -> StubResponse {
        StubResponse::new(
            StatusCode::OK,
            serde_json::json!({
                "Name": name, "Driver": "local", "Options": {},
                "Labels": {LABEL_SANDBOX_ID: sandbox_id, container::LABEL_SANDBOX_WORKSPACE: ""}
            })
            .to_string(),
        )
    }

    fn create_launch_responses() -> Vec<StubResponse> {
        vec![
            created_response("workload"),
            fence_response(),
            StubResponse::new(StatusCode::OK, "").with_archive_members(channel_archive_members()),
            StubResponse::new(StatusCode::OK, "").with_archive_members(&["."]),
            created_response("supervisor"),
            StubResponse::new(StatusCode::OK, ""), // supervisor archive
            StubResponse::new(StatusCode::NO_CONTENT, ""), // workload start
            StubResponse::new(StatusCode::NO_CONTENT, ""), // supervisor start
        ]
    }

    fn channel_archive_members() -> &'static [&'static str] {
        &[
            ".",
            "sandbox",
            "sandbox/bootstrap.json",
            "sandbox/server.crt",
            "sandbox/server.key",
        ]
    }

    #[tokio::test]
    async fn reserved_image_control_root_fails_before_workload_or_secrets() {
        let (path, requests, handle) = spawn_podman_stub(
            "reserved-control-root",
            vec![
                StubResponse::new(StatusCode::OK, "{}"),
                StubResponse::new(StatusCode::OK, "{}"),
                StubResponse::new(StatusCode::OK, "{}"),
                image_response("sha256:image"),
                created_response("identity-reader"),
                StubResponse::new(StatusCode::OK, "existing reserved path"),
                StubResponse::new(StatusCode::NO_CONTENT, ""),
            ],
        );
        let error = test_driver(path.clone())
            .create_sandbox(&plain_sandbox("id", "name"))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("reserved /.openshell"));
        handle.await.unwrap();
        assert!(
            !requests
                .lock()
                .unwrap()
                .iter()
                .any(|request| request.contains("/libpod/volumes")
                    || request.contains("/libpod/secrets"))
        );
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn create_sandbox_removes_proxy_auth_secret_on_container_create_failure() {
        // A credential secret is staged before the container is created, so a
        // container-create failure must remove it — no credential residue.
        let sandbox_id = "sandbox-cc";
        let auth_file = write_proxy_auth_file("create-fail");
        let (socket_path, request_log, handle) = spawn_podman_stub(
            "create-container-fail",
            create_setup_responses(true, sandbox_id)
                .into_iter()
                .chain([
                    StubResponse::new(StatusCode::INTERNAL_SERVER_ERROR, "create failed"),
                    StubResponse::new(StatusCode::NO_CONTENT, ""), // channel
                    StubResponse::new(StatusCode::NO_CONTENT, ""), // workspace
                    StubResponse::new(StatusCode::NO_CONTENT, ""), // proxy secret
                ])
                .collect(),
        );
        let driver = test_driver_with_config(proxy_auth_config(socket_path.clone(), &auth_file));
        let mut sandbox = plain_sandbox(sandbox_id, "demo");
        sandbox.spec = Some(DriverSandboxSpec {
            launch_authentication: encoded_launch_authentication(),
            ..DriverSandboxSpec::default()
        });

        driver
            .create_sandbox(&sandbox)
            .await
            .expect_err("container create should fail");

        handle.await.expect("stub task should finish");
        let requests = request_log
            .lock()
            .expect("request log lock should not be poisoned")
            .clone();
        assert!(
            requests.contains(&secret_delete_request(sandbox_id)),
            "proxy-auth secret must be removed on container-create failure: {requests:?}"
        );
        let _ = fs::remove_file(&auth_file);
        let _ = fs::remove_file(socket_path);
    }

    #[tokio::test]
    async fn create_sandbox_removes_proxy_auth_secret_on_start_failure() {
        // The container is created but fails to start; the staged credential
        // secret must still be removed.
        let sandbox_id = "sandbox-sf";
        let auth_file = write_proxy_auth_file("start-fail");
        let (socket_path, request_log, handle) = spawn_podman_stub(
            "create-start-fail",
            create_setup_responses(true, sandbox_id)
                .into_iter()
                .chain(create_launch_responses().into_iter().take(7))
                .chain([
                    StubResponse::new(StatusCode::INTERNAL_SERVER_ERROR, "supervisor start failed"),
                    StubResponse::new(StatusCode::NO_CONTENT, ""), // supervisor
                    StubResponse::new(StatusCode::NO_CONTENT, ""), // workload
                    StubResponse::new(StatusCode::NO_CONTENT, ""), // channel
                    StubResponse::new(StatusCode::NO_CONTENT, ""), // workspace
                    StubResponse::new(StatusCode::NO_CONTENT, ""), // proxy secret
                ])
                .collect(),
        );
        let driver = test_driver_with_config(proxy_auth_config(socket_path.clone(), &auth_file));
        let mut sandbox = plain_sandbox(sandbox_id, "demo");
        sandbox.spec = Some(DriverSandboxSpec {
            launch_authentication: encoded_launch_authentication(),
            ..DriverSandboxSpec::default()
        });

        driver
            .create_sandbox(&sandbox)
            .await
            .expect_err("container start should fail");

        handle.await.expect("stub task should finish");
        let requests = request_log
            .lock()
            .expect("request log lock should not be poisoned")
            .clone();
        assert!(
            requests.contains(&secret_delete_request(sandbox_id)),
            "proxy-auth secret must be removed on start failure: {requests:?}"
        );
        let _ = fs::remove_file(&auth_file);
        let _ = fs::remove_file(socket_path);
    }

    #[tokio::test]
    async fn delete_sandbox_removes_proxy_auth_secret() {
        // Deleting a sandbox (here already gone out of band) must remove the
        // per-sandbox proxy-auth secret so credentials never outlive it.
        let sandbox_id = "sandbox-del";
        let (socket_path, request_log, handle) = spawn_podman_stub(
            "delete-proxy-auth",
            vec![
                StubResponse::new(StatusCode::NO_CONTENT, ""), // remove companion
                StubResponse::new(StatusCode::NO_CONTENT, ""), // remove channel if detached
                StubResponse::new(StatusCode::OK, "[]"),       // list_containers (not found)
                StubResponse::new(StatusCode::NO_CONTENT, ""), // remove volume
                StubResponse::new(StatusCode::NO_CONTENT, ""), // remove token secret
                StubResponse::new(StatusCode::NO_CONTENT, ""), // remove proxy-auth secret
            ],
        );
        let driver = test_driver(socket_path.clone());

        driver
            .delete_sandbox(sandbox_id)
            .await
            .expect("delete should succeed");

        handle.await.expect("stub task should finish");
        let requests = request_log
            .lock()
            .expect("request log lock should not be poisoned")
            .clone();
        assert!(
            requests.contains(&secret_delete_request(sandbox_id)),
            "proxy-auth secret must be removed on delete: {requests:?}"
        );
        let _ = fs::remove_file(socket_path);
    }

    #[tokio::test]
    async fn delete_sandbox_finds_container_by_label_and_removes() {
        let sandbox_id = "sandbox-request-id";
        let container_id = "abc123def456";
        let container_name = "openshell-default--demo-sandbox-request-id";
        let volume_name = container::volume_name(sandbox_id);
        let list_body = serde_json::json!([{
            "Id": container_id,
            "Names": [container_name],
            "State": "running",
            "Labels": {
                LABEL_SANDBOX_ID: sandbox_id
            }
        }])
        .to_string();
        let (socket_path, request_log, handle) = spawn_podman_stub(
            "delete-label-lookup",
            vec![
                StubResponse::new(StatusCode::NO_CONTENT, ""), // remove companion
                StubResponse::new(StatusCode::NO_CONTENT, ""), // remove channel if detached
                // list_containers by label
                StubResponse::new(StatusCode::OK, list_body),
                // single timed remove_container operation
                StubResponse::new(StatusCode::NO_CONTENT, ""),
                // channel volume, now detached
                StubResponse::new(StatusCode::NO_CONTENT, ""),
                // remove_volume
                StubResponse::new(StatusCode::NO_CONTENT, ""),
            ],
        );
        let driver = test_driver(socket_path.clone());

        let deleted = driver
            .delete_sandbox(sandbox_id)
            .await
            .expect("delete should succeed");

        assert!(deleted, "existing container should report deleted=true");
        handle.await.expect("stub task should finish");
        let requests = request_log
            .lock()
            .expect("request log lock should not be poisoned")
            .clone();
        assert!(requests[2].contains("/libpod/containers/json"));
        assert_eq!(
            requests[3],
            format!(
                "DELETE {}",
                api_path(&format!(
                    "/libpod/containers/{container_id}?force=true&volumes=true&timeout=10"
                ))
            )
        );
        assert_eq!(
            requests[5],
            format!(
                "DELETE {}",
                api_path(&format!("/libpod/volumes/{volume_name}"))
            )
        );
        let _ = fs::remove_file(socket_path);
    }

    #[test]
    fn userns_remaps_uids_cases() {
        assert!(!userns_remaps_uids(None));
        assert!(!userns_remaps_uids(Some("host")));
        assert!(!userns_remaps_uids(Some("keep-id")));
        assert!(userns_remaps_uids(Some("auto")));
        assert!(userns_remaps_uids(Some("auto:size=65536")));
        assert!(userns_remaps_uids(Some("no-map")));
        assert!(userns_remaps_uids(Some("private")));
    }

    #[test]
    fn capabilities_report_static_resource_support() {
        let driver = PodmanComputeDriver::for_tests(PodmanComputeConfig::default());
        let resources = driver
            .capabilities()
            .unwrap()
            .resource_capabilities
            .unwrap();
        assert!(resources.cpu.unwrap().limit_supported);
        assert!(resources.memory.unwrap().limit_supported);
        let gpu = resources.gpu.unwrap();
        assert!(gpu.default_selection_supported);
        assert!(gpu.count_selection_supported);
    }
}
