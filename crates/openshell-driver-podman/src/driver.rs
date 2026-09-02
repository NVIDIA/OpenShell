// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Podman compute driver.

use crate::client::{ContainerListEntry, PodmanApiError, PodmanClient, VolumeInspect};
use crate::config::PodmanComputeConfig;
use crate::container::{self, LABEL_MANAGED_FILTER, LABEL_SANDBOX_ID, PodmanSandboxDriverConfig};
use crate::watcher::{
    self, LifecycleEventFences, WatchStream, driver_sandbox_from_inspect,
    driver_sandbox_from_list_entry,
};
use openshell_core::ComputeDriverError;
use openshell_core::config::CDI_GPU_DEVICE_ALL;
use openshell_core::driver_utils::{
    SUPERVISOR_IMAGE_BINARY_PATH, extract_first_tar_entry, supervisor_image_should_refresh,
    temp_extract_container_name, validate_linux_elf_binary, write_cache_binary_atomic,
};
use openshell_core::gpu::{
    CdiGpuDefaultSelector, CdiGpuInventory, CdiGpuSelectionError, driver_gpu_requirements,
    effective_driver_gpu_count, validate_specific_gpu_device_request,
};
#[cfg(target_os = "linux")]
use openshell_core::proto::compute::v1::GatewayDefaultRouteInterfaceRequirement;
#[cfg(target_os = "macos")]
use openshell_core::proto::compute::v1::GatewayLoopbackInterfaceRequirement;
use openshell_core::proto::compute::v1::{
    DriverSandbox, GatewayListenerRequirement, GetCapabilitiesResponse, GpuResourceRequirements,
    gateway_listener_requirement::Selector,
};
#[cfg(target_os = "linux")]
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::{Instrument as _, debug, info, warn};
use url::Url;

const STOP_COMPLETION_POLL_INTERVAL: Duration = Duration::from_millis(50);
const STOP_COMPLETION_TIMEOUT_HEADROOM: Duration = Duration::from_secs(5);

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
    /// The host's IP on the bridge network, when that bridge exists in the
    /// gateway's network namespace (notably rootful Podman).
    network_gateway_ip: Option<String>,
    /// Whether Podman's service is running without root privileges.
    rootless: bool,
    /// Rootless network helper reported by Podman, such as `pasta`.
    rootless_network_cmd: String,
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
            .field("rootless_network_cmd", &self.rootless_network_cmd)
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

        // Validate TLS configuration before connecting.  Partial configs
        // (e.g. CA set but cert/key missing) are rejected early so operators
        // get a clear error instead of a silent fallback to plaintext HTTP.
        config.validate_tls_config()?;
        config.validate_runtime_limits()?;
        config.validate_host_gateway_ip()?;
        config.validate_proxy_config()?;
        config.canonicalize_userns()?;
        config.validate_userns_mappings()?;

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
        let (rootless, rootless_network_cmd) = match client.system_info().await {
            Ok(info) => {
                if info.host.cgroup_version != "v2" {
                    return Err(PodmanApiError::Connection(format!(
                        "cgroups v2 is required; detected cgroups '{}'. \
                         Ensure your host uses a unified cgroup hierarchy \
                         (systemd.unified_cgroup_hierarchy=1).",
                        info.host.cgroup_version
                    )));
                }
                info!(
                    cgroup_version = %info.host.cgroup_version,
                    network_backend = %info.host.network_backend,
                    rootless = info.host.security.rootless,
                    rootless_network_cmd = %info.host.rootless_network_cmd,
                    "Connected to Podman"
                );
                (info.host.security.rootless, info.host.rootless_network_cmd)
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

        // Auto-detect the gRPC callback endpoint before deciding whether this
        // topology needs the Podman bridge gateway address.
        if config.grpc_endpoint.is_empty() {
            let scheme = if config.tls_enabled() {
                "https"
            } else {
                "http"
            };
            config.grpc_endpoint = format!(
                "{scheme}://host.containers.internal:{}",
                config.gateway_port
            );
            info!(
                grpc_endpoint = %config.grpc_endpoint,
                tls = config.tls_enabled(),
                "Auto-detected gRPC endpoint"
            );
        }

        // Ensure the bridge network exists. Inspect its gateway only when the
        // selected Linux callback topology will bind that exact address.
        client.ensure_network(&config.network_name).await?;
        let uses_local_callback_alias = Url::parse(&config.grpc_endpoint)
            .ok()
            .as_ref()
            .is_some_and(callback_endpoint_uses_local_alias);
        let needs_network_gateway_ip = cfg!(target_os = "linux")
            && uses_local_callback_alias
            && !rootless
            && config.host_gateway_ip.trim().is_empty();
        let network_gateway_ip = if needs_network_gateway_ip {
            client.network_gateway_ip(&config.network_name).await?
        } else {
            None
        };
        info!(
            network = %config.network_name,
            gateway_ip = ?network_gateway_ip,
            "Bridge network ready"
        );

        let (gpu_inventory, allow_all_default_gpu) = local_podman_gpu_selector_state();
        if !gpu_inventory.is_empty() {
            info!(
                device_count = gpu_inventory.as_slice().len(),
                "Discovered local Podman NVIDIA CDI GPU devices"
            );
        }

        Ok(Self {
            client,
            config,
            network_gateway_ip,
            rootless,
            rootless_network_cmd,
            gpu_selector: Arc::new(CdiGpuDefaultSelector::new(
                gpu_inventory,
                allow_all_default_gpu,
            )),
            gpu_inventory_refresh: Arc::new(local_podman_gpu_selector_state),
            lifecycle_event_fences: LifecycleEventFences::default(),
        })
    }

    /// The host's IP on the bridge network, if available.
    ///
    /// Used to request the exact rootful gateway callback listener when no
    /// explicit host-gateway override is configured.
    #[must_use]
    pub fn network_gateway_ip(&self) -> Option<&str> {
        self.network_gateway_ip.as_deref()
    }

    /// Report driver capabilities.
    pub fn capabilities(&self) -> Result<GetCapabilitiesResponse, ComputeDriverError> {
        Ok(GetCapabilitiesResponse {
            driver_name: "podman".to_string(),
            driver_version: openshell_core::VERSION.to_string(),
            default_image: self.config.default_image.clone(),
            gateway_manages_lifecycle: true,
            supports_sandbox_authentication: false,
            driver_reports_runtime_readiness: false,
        })
    }

    /// Report the gateway exposure needed by Podman's standard local callback aliases.
    ///
    /// Rootful Podman binds the exact bridge address behind the sandbox alias.
    /// Rootless pasta follows the host's default-route interface, while Podman
    /// Machine forwards the alias to gateway loopback. Other rootless helpers
    /// cannot use a direct host listener.
    pub fn gateway_listener_requirements(
        &self,
    ) -> Result<Vec<GatewayListenerRequirement>, ComputeDriverError> {
        let endpoint = Url::parse(&self.config.grpc_endpoint).map_err(|err| {
            ComputeDriverError::Precondition(format!(
                "invalid Podman gateway callback endpoint '{}': {err}",
                self.config.grpc_endpoint
            ))
        })?;
        let uses_local_callback_alias = callback_endpoint_uses_local_alias(&endpoint);
        if !uses_local_callback_alias {
            return Ok(Vec::new());
        }
        let callback_port = endpoint.port_or_known_default().ok_or_else(|| {
            ComputeDriverError::Precondition(format!(
                "Podman gateway callback endpoint '{}' has no port",
                self.config.grpc_endpoint
            ))
        })?;
        if callback_port != self.config.gateway_port {
            return Err(ComputeDriverError::Precondition(format!(
                "Podman local callback endpoint '{}' uses port {callback_port}, but the gateway primary listener uses port {}; configure grpc_endpoint with the gateway primary listener port",
                self.config.grpc_endpoint, self.config.gateway_port
            )));
        }

        #[cfg(target_os = "linux")]
        {
            if self.rootless {
                validate_rootless_local_callback_helper(&self.rootless_network_cmd)?;

                if self.config.host_gateway_ip.trim().is_empty() {
                    return Ok(vec![GatewayListenerRequirement {
                        reason:
                            "Podman rootless pasta callback uses the host default-route interface"
                                .to_string(),
                        selector: Some(Selector::DefaultRouteInterface(
                            GatewayDefaultRouteInterfaceRequirement {},
                        )),
                    }]);
                }
            }

            let gateway_ip = if self.config.host_gateway_ip.trim().is_empty() {
                self.network_gateway_ip.as_deref().ok_or_else(|| {
                    ComputeDriverError::Precondition(format!(
                        "Podman network '{}' did not report a host bridge gateway address for local callback alias '{}'",
                        self.config.network_name,
                        endpoint.host_str().unwrap_or_default()
                    ))
                })?
            } else {
                self.config.host_gateway_ip.trim()
            };
            let gateway_ip = gateway_ip.parse::<IpAddr>().map_err(|err| {
                ComputeDriverError::Precondition(format!(
                    "Podman callback gateway address '{gateway_ip}' is invalid: {err}"
                ))
            })?;
            Ok(vec![GatewayListenerRequirement {
                reason: format!("Podman network '{}' host gateway", self.config.network_name),
                selector: Some(Selector::ExactBindAddress(
                    SocketAddr::new(gateway_ip, callback_port).to_string(),
                )),
            }])
        }
        #[cfg(target_os = "macos")]
        {
            Ok(vec![GatewayListenerRequirement {
                reason: "Podman machine callback forwarding terminates on gateway loopback"
                    .to_string(),
                selector: Some(Selector::LoopbackInterface(
                    GatewayLoopbackInterfaceRequirement {},
                )),
            }])
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Ok(Vec::new())
        }
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
        let gpu_requirements = sandbox
            .spec
            .as_ref()
            .and_then(|spec| spec.resource_requirements.as_ref())
            .and_then(|requirements| driver_gpu_requirements(Some(requirements)));
        let driver_config = PodmanSandboxDriverConfig::from_sandbox(sandbox)?;
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
    ) -> Result<(), ComputeDriverError> {
        let volumes =
            container::podman_driver_volume_mount_sources(sandbox, self.config.enable_bind_mounts)
                .map_err(ComputeDriverError::Precondition)?;
        for volume in volumes {
            match self.client.inspect_volume(&volume).await {
                Ok(volume_info) => {
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
        Ok(())
    }

    /// Create a sandbox container.
    #[tracing::instrument(
        name = "podman.create_sandbox",
        skip(self, sandbox),
        fields(
            otel.name = "podman.create_sandbox",
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

        let (image, immutable_image_id, image_user) = async {
            let phase_status = openshell_otel::ErrorStatusGuard::current();
            let result = async {
                // The supervisor binary is shipped in a standalone OCI image and
                // mounted into sandbox containers via Podman's type=image mount.
                let supervisor_pull_policy =
                    supervisor_image_pull_policy(&self.config.supervisor_image);
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
                let pull_policy = self.config.image_pull_policy.as_str();
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

                Ok((image.to_string(), inspected_image.id, image_user))
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

        // Create workspace volume and per-sandbox token secret.
        let (token_secret_name, proxy_auth_secret_name) = async {
            let phase_status = openshell_otel::ErrorStatusGuard::current();
            let result = async {
                self.client
                    .create_volume(&vol_name)
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
        let cleanup_created = || async {
            let _ = self.client.remove_volume(&vol_name).await;
            if let Some(secret) = token_secret_name.as_deref() {
                cleanup_sandbox_token_secret(&self.client, secret).await;
            }
            if let Some(secret) = proxy_auth_secret_name.as_deref() {
                cleanup_sandbox_proxy_auth_secret(&self.client, secret).await;
            }
        };

        // Prepare and create the container.
        let tls_secret_names = async {
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
                let supervisor_bin_path = if userns_needs_extraction(self.config.userns.as_deref())
                {
                    match extract_supervisor_bin(&self.client, &self.config).await {
                        Ok(path) => Some(path),
                        Err(e) => {
                            cleanup_created().await;
                            return Err(e);
                        }
                    }
                } else {
                    None
                };

                let tls_secret_names = if userns_remaps_uids(self.config.userns.as_deref())
                    && self.config.tls_enabled()
                {
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

                let spec = match container::build_container_spec_for_image(
                    sandbox,
                    &self.config,
                    token_secret_name.as_deref(),
                    gpu_devices.as_deref(),
                    &image,
                    &immutable_image_id,
                    &image_user,
                    supervisor_bin_path.as_deref(),
                    tls_secret_names.as_ref(),
                ) {
                    Ok(spec) => spec,
                    Err(e) => {
                        cleanup_all().await;
                        return Err(e);
                    }
                };
                match self.client.create_container(&spec).await {
                    Ok(_) => Ok(tls_secret_names),
                    Err(PodmanApiError::Conflict(_)) => {
                        cleanup_all().await;
                        Err(ComputeDriverError::AlreadyExists)
                    }
                    Err(e) => {
                        cleanup_all().await;
                        Err(ComputeDriverError::from(e))
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

        let cleanup_all = || async {
            cleanup_created().await;
            if let Some(names) = &tls_secret_names {
                cleanup_tls_secrets(&self.client, names).await;
            }
        };

        // Start container.
        let start_result = async {
            let phase_status = openshell_otel::ErrorStatusGuard::current();
            let result = self
                .client
                .start_container(&name)
                .await
                .map_err(ComputeDriverError::from);
            phase_status.finish(result)
        }
        .instrument(tracing::info_span!(
            "podman.start_container",
            otel.name = "podman.start_container",
            otel.status_code = tracing::field::Empty,
            container.name = %name,
        ))
        .await;
        if let Err(e) = start_result {
            warn!(
                sandbox_name = %sandbox.name,
                error = %e,
                "Failed to start container; cleaning up"
            );
            let _ = self
                .client
                .remove_container(&name, self.config.stop_timeout_secs)
                .await;
            cleanup_all().await;
            return Err(e);
        }

        info!(
            sandbox_id = %sandbox.id,
            sandbox_name = %sandbox.name,
            "Sandbox container started"
        );

        span_status.finish(Ok(()))
    }

    /// Find the Podman container ID for a sandbox by its sandbox ID using label lookup.
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
            .list_containers(&[LABEL_MANAGED_FILTER, &id_filter])
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
        let container = self
            .find_container(sandbox_id)
            .await?
            .ok_or(ComputeDriverError::NotFound)?;
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
        skip(self),
        fields(
            otel.name = "podman.start_sandbox",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %sandbox_id,
        )
    )]
    pub async fn start_sandbox(&self, sandbox_id: &str) -> Result<(), ComputeDriverError> {
        let span_status = openshell_otel::ErrorStatusGuard::current();
        let container = self
            .find_container(sandbox_id)
            .await?
            .ok_or(ComputeDriverError::NotFound)?;
        if container.state == "running" {
            return span_status.finish(Ok(()));
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
        let result = self
            .client
            .start_container(&container_id)
            .await
            .map_err(ComputeDriverError::from);
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
            .list_containers(&[LABEL_MANAGED_FILTER, &id_filter])
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
            .list_containers(&[LABEL_MANAGED_FILTER, &id_filter])
            .await
            .map_err(ComputeDriverError::from)?;
        let Some(entry) = entries.first() else {
            return Ok(None);
        };
        if entry.state == "running" {
            Ok(self
                .client
                .inspect_container(&entry.id)
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
            .list_containers(&[LABEL_MANAGED_FILTER])
            .await
            .map_err(ComputeDriverError::from)?;

        let mut sandboxes = Vec::with_capacity(entries.len());
        for entry in &entries {
            if entry.state == "running" {
                // Running containers need inspect for health check status.
                match self.client.inspect_container(&entry.id).await {
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
            network_gateway_ip: None,
            rootless: false,
            rootless_network_cmd: String::new(),
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

fn supervisor_image_pull_policy(image: &str) -> &'static str {
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

fn callback_endpoint_uses_local_alias(endpoint: &Url) -> bool {
    endpoint
        .host_str()
        .is_some_and(|host| matches!(host, "host.containers.internal" | "host.openshell.internal"))
}

#[cfg(any(target_os = "linux", test))]
fn validate_rootless_local_callback_helper(
    rootless_network_cmd: &str,
) -> Result<(), ComputeDriverError> {
    let rootless_network_cmd = rootless_network_cmd.trim();
    if rootless_network_cmd == "pasta" {
        return Ok(());
    }

    let reported = if rootless_network_cmd.is_empty() {
        "<missing>"
    } else {
        rootless_network_cmd
    };
    Err(ComputeDriverError::Precondition(format!(
        "Podman rootless network helper '{reported}' does not support direct local gateway callbacks; configure pasta or use an explicitly remote grpc_endpoint"
    )))
}

// ── Supervisor binary extraction (userns fallback) ─────────────────────

async fn extract_supervisor_bin(
    client: &PodmanClient,
    config: &PodmanComputeConfig,
) -> Result<PathBuf, ComputeDriverError> {
    let mut inspect = client
        .inspect_image(&config.supervisor_image)
        .await
        .map_err(ComputeDriverError::from)?;

    if supervisor_image_should_refresh(&config.supervisor_image) {
        info!(
            image = %config.supervisor_image,
            "Refreshing mutable podman supervisor image"
        );
        match client.pull_image(&config.supervisor_image, "always").await {
            Ok(()) => {
                inspect = client
                    .inspect_image(&config.supervisor_image)
                    .await
                    .map_err(ComputeDriverError::from)?;
            }
            Err(err) => {
                warn!(
                    image = %config.supervisor_image,
                    error = %err,
                    "Failed to refresh mutable podman supervisor image; \
                     falling back to local image if present",
                );
            }
        }
    }

    let digest = if inspect.id.is_empty() {
        return Err(ComputeDriverError::Precondition(format!(
            "supervisor image '{}' has no ID",
            config.supervisor_image,
        )));
    } else {
        &inspect.id
    };

    let cache_path =
        openshell_core::driver_utils::supervisor_cache_path("podman-supervisor", digest)
            .map_err(ComputeDriverError::Precondition)?;
    if cache_path.is_file() {
        validate_linux_elf_binary(&cache_path).map_err(ComputeDriverError::Precondition)?;
        info!(
            cache_path = %cache_path.display(),
            "Using cached supervisor binary"
        );
        return Ok(cache_path);
    }

    info!(
        image = %config.supervisor_image,
        cache_path = %cache_path.display(),
        "Extracting supervisor binary from image"
    );

    let container_name = temp_extract_container_name();
    let spec = serde_json::json!({
        "image": config.supervisor_image,
        "name": container_name,
        "entrypoint": [SUPERVISOR_IMAGE_BINARY_PATH],
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
            "Failed to remove supervisor extractor container"
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
        .copy_from_container(container_name, SUPERVISOR_IMAGE_BINARY_PATH)
        .await
        .map_err(ComputeDriverError::from)?;

    let binary_bytes = extract_first_tar_entry(&tar_bytes).map_err(|err| {
        ComputeDriverError::Precondition(format!(
            "failed to extract supervisor binary from tar: {err}"
        ))
    })?;

    write_cache_binary_atomic(cache_path, &binary_bytes)
        .map_err(ComputeDriverError::Precondition)?;
    validate_linux_elf_binary(cache_path).map_err(ComputeDriverError::Precondition)?;
    Ok(cache_path.to_path_buf())
}

fn userns_needs_extraction(userns: Option<&str>) -> bool {
    userns.is_some_and(|mode| {
        let base = mode.split(':').next().unwrap_or(mode);
        !base.eq_ignore_ascii_case("host")
    })
}

/// Returns `true` when userns remaps all UIDs, making host-owned bind mounts
/// unreadable from inside the container. `auto` and `no-map` remap every UID;
/// `keep-id` preserves the host user's UID; `host` uses the host namespace.
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
    use openshell_core::proto::compute::v1::{
        DriverSandboxSpec, DriverSandboxTemplate, ResourceRequirements,
    };
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Path, PathBuf};

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
    async fn stop_and_start_target_the_existing_container() {
        let (stop_socket, stop_requests, stop_handle) = spawn_podman_stub(
            "lifecycle-stop",
            vec![
                StubResponse::new(StatusCode::OK, r#"[{"Id":"ctr-1","State":"running"}]"#),
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
                .expect("request log lock should not be poisoned")[1],
            format!(
                "POST {}",
                api_path("/libpod/containers/ctr-1/stop?timeout=10")
            )
        );
        assert_eq!(
            stop_requests
                .lock()
                .expect("request log lock should not be poisoned")[2],
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
                StubResponse::new(StatusCode::NO_CONTENT, ""),
            ],
        );
        test_driver(start_socket.clone())
            .start_sandbox("sandbox-1")
            .await
            .expect("start should succeed");
        start_handle.await.expect("start stub should finish");
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
            format!("POST {}", api_path("/libpod/containers/ctr-1/start"))
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
        assert_eq!(requests.len(), 4);
        assert_eq!(
            requests[2],
            format!("GET {}", api_path("/libpod/containers/ctr-1/json"))
        );
        assert_eq!(requests[3], requests[2]);

        let _ = fs::remove_file(socket);
    }

    #[tokio::test]
    async fn stop_retry_waits_for_an_existing_stopping_container() {
        let (socket, requests, handle) = spawn_podman_stub(
            "lifecycle-stop-retry",
            vec![
                StubResponse::new(StatusCode::OK, r#"[{"Id":"ctr-1","State":"stopping"}]"#),
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
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[1],
            format!("GET {}", api_path("/libpod/containers/ctr-1/json"))
        );

        let _ = fs::remove_file(socket);
    }

    #[tokio::test]
    async fn stop_sandbox_exports_a_podman_operation_span() {
        use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
        use tracing::instrument::WithSubscriber as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        let _tracing_lock = crate::otel_tracing::test_lock().await;
        let (socket_path, _requests, handle) = spawn_podman_stub(
            "trace-stop",
            vec![
                StubResponse::new(StatusCode::OK, r#"[{"Id":"ctr-1","State":"running"}]"#),
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
        let subscriber = tracing_subscriber::registry().with(crate::otel_tracing::layer(&provider));

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
    async fn create_sandbox_exports_nested_preparation_spans() {
        use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
        use tracing::instrument::WithSubscriber as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        let _tracing_lock = crate::otel_tracing::test_lock().await;
        let (socket_path, _requests, handle) = spawn_podman_stub(
            "trace-create",
            vec![
                StubResponse::new(StatusCode::OK, "{}"),
                StubResponse::new(StatusCode::OK, "{}"),
                StubResponse::new(
                    StatusCode::OK,
                    r#"{"Id":"sha256:sandbox","Config":{"User":"1234:1235"}}"#,
                ),
                StubResponse::new(StatusCode::CREATED, "{}"),
                StubResponse::new(StatusCode::CREATED, "{}"),
                StubResponse::new(StatusCode::NO_CONTENT, ""),
            ],
        );
        let exporter = InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry().with(crate::otel_tracing::layer(&provider));

        test_driver(socket_path.clone())
            .create_sandbox(&plain_sandbox("sandbox-trace", "demo"))
            .with_subscriber(subscriber)
            .await
            .expect("create should succeed");
        handle.await.expect("stub should finish");
        provider.force_flush().unwrap();

        let spans = exporter.get_finished_spans().unwrap();
        let create = spans
            .iter()
            .find(|span| span.name == "podman.create_sandbox")
            .expect("create operation should be exported");
        for name in [
            "podman.prepare_images",
            "podman.prepare_storage",
            "podman.prepare_container",
            "podman.start_container",
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

        let _tracing_lock = crate::otel_tracing::test_lock().await;
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
        let subscriber = tracing_subscriber::registry().with(crate::otel_tracing::layer(&provider));

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

        let _tracing_lock = crate::otel_tracing::test_lock().await;
        let exporter = InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry().with(crate::otel_tracing::layer(&provider));

        let (start_socket, _requests, start_handle) = spawn_podman_stub(
            "trace-start",
            vec![
                StubResponse::new(StatusCode::OK, r#"[{"Id":"ctr-1","State":"stopped"}]"#),
                StubResponse::new(
                    StatusCode::OK,
                    r#"{"Id":"ctr-1","Name":"sandbox","State":{"Status":"exited","Running":false,"FinishedAt":"2026-08-12T16:39:13Z"},"Config":{}}"#,
                ),
                StubResponse::new(StatusCode::NO_CONTENT, ""),
            ],
        );
        test_driver(start_socket.clone())
            .start_sandbox("sandbox-1")
            .with_subscriber(subscriber)
            .await
            .expect("start should succeed");
        start_handle.await.expect("start stub should finish");

        let (delete_socket, _requests, delete_handle) = spawn_podman_stub(
            "trace-delete",
            vec![
                StubResponse::new(StatusCode::OK, "[]"),
                StubResponse::new(StatusCode::NO_CONTENT, ""),
            ],
        );
        let subscriber = tracing_subscriber::registry().with(crate::otel_tracing::layer(&provider));
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
    // PodmanComputeDriver::new() fills grpc_endpoint when it is empty.
    // The scheme (http vs https) depends on whether TLS client certs are
    // configured. These tests simulate the auto-detection logic.

    #[test]
    fn grpc_endpoint_http_without_tls() {
        let mut cfg = PodmanComputeConfig {
            gateway_port: 8081,
            ..PodmanComputeConfig::default()
        };
        if cfg.grpc_endpoint.is_empty() {
            let scheme = if cfg.tls_enabled() { "https" } else { "http" };
            cfg.grpc_endpoint = format!("{scheme}://host.containers.internal:{}", cfg.gateway_port);
        }
        assert_eq!(cfg.grpc_endpoint, "http://host.containers.internal:8081");
    }

    #[test]
    fn grpc_endpoint_https_with_tls() {
        let mut cfg = PodmanComputeConfig {
            gateway_port: 8080,
            guest_tls_ca: Some(PathBuf::from("/tls/ca.crt")),
            guest_tls_cert: Some(PathBuf::from("/tls/tls.crt")),
            guest_tls_key: Some(PathBuf::from("/tls/tls.key")),
            ..PodmanComputeConfig::default()
        };
        if cfg.grpc_endpoint.is_empty() {
            let scheme = if cfg.tls_enabled() { "https" } else { "http" };
            cfg.grpc_endpoint = format!("{scheme}://host.containers.internal:{}", cfg.gateway_port);
        }
        assert_eq!(cfg.grpc_endpoint, "https://host.containers.internal:8080");
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
        let mut cfg = PodmanComputeConfig {
            grpc_endpoint: "https://gateway.internal:9000".to_string(),
            gateway_port: 8081,
            ..PodmanComputeConfig::default()
        };
        if cfg.grpc_endpoint.is_empty() {
            let scheme = if cfg.tls_enabled() { "https" } else { "http" };
            cfg.grpc_endpoint = format!("{scheme}://host.containers.internal:{}", cfg.gateway_port);
        }
        assert_eq!(cfg.grpc_endpoint, "https://gateway.internal:9000");
    }

    #[test]
    fn rootless_slirp_allows_remote_callback_endpoint() {
        let mut driver = PodmanComputeDriver::for_tests(PodmanComputeConfig {
            grpc_endpoint: "https://gateway.internal:9000".to_string(),
            ..PodmanComputeConfig::default()
        });
        driver.rootless = true;
        driver.rootless_network_cmd = "slirp4netns".to_string();

        let requirements = driver.gateway_listener_requirements().unwrap();

        assert!(requirements.is_empty());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn rootful_local_callback_alias_requests_discovered_network_gateway() {
        let mut driver = PodmanComputeDriver::for_tests(PodmanComputeConfig {
            grpc_endpoint: "http://host.openshell.internal:17670".to_string(),
            ..PodmanComputeConfig::default()
        });
        driver.network_gateway_ip = Some("10.89.1.1".to_string());

        let requirements = driver.gateway_listener_requirements().unwrap();

        assert_eq!(requirements.len(), 1);
        assert_eq!(
            requirements[0].selector,
            Some(Selector::ExactBindAddress("10.89.1.1:17670".to_string()))
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn configured_host_gateway_overrides_discovered_network_gateway() {
        let mut driver = PodmanComputeDriver::for_tests(PodmanComputeConfig {
            grpc_endpoint: "http://host.containers.internal:17670".to_string(),
            host_gateway_ip: "10.90.1.1".to_string(),
            ..PodmanComputeConfig::default()
        });
        driver.network_gateway_ip = Some("10.89.1.1".to_string());
        driver.rootless = true;
        driver.rootless_network_cmd = "pasta".to_string();

        let requirements = driver.gateway_listener_requirements().unwrap();

        assert_eq!(
            requirements[0].selector,
            Some(Selector::ExactBindAddress("10.90.1.1:17670".to_string()))
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn rootless_pasta_requests_default_route_interface() {
        let mut driver = PodmanComputeDriver::for_tests(PodmanComputeConfig {
            grpc_endpoint: "http://host.openshell.internal:17670".to_string(),
            ..PodmanComputeConfig::default()
        });
        driver.rootless = true;
        driver.rootless_network_cmd = "pasta".to_string();

        let requirements = driver.gateway_listener_requirements().unwrap();

        assert!(matches!(
            requirements[0].selector,
            Some(Selector::DefaultRouteInterface(_))
        ));
    }

    #[test]
    fn rootless_non_pasta_helpers_are_rejected() {
        for (rootless_network_cmd, reported) in [
            ("slirp4netns", "slirp4netns"),
            ("", "<missing>"),
            ("unknown-helper", "unknown-helper"),
        ] {
            let err = validate_rootless_local_callback_helper(rootless_network_cmd).unwrap_err();

            assert!(matches!(err, ComputeDriverError::Precondition(_)));
            assert!(err.to_string().contains(reported));
            assert!(err.to_string().contains("configure pasta"));
            assert!(err.to_string().contains("remote grpc_endpoint"));
        }
    }

    #[test]
    fn rootless_pasta_is_accepted_for_local_callbacks() {
        validate_rootless_local_callback_helper("pasta").unwrap();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn rootless_slirp_rejects_explicit_host_gateway_override() {
        let mut driver = PodmanComputeDriver::for_tests(PodmanComputeConfig {
            grpc_endpoint: "http://host.openshell.internal:17670".to_string(),
            host_gateway_ip: "10.90.1.1".to_string(),
            ..PodmanComputeConfig::default()
        });
        driver.rootless = true;
        driver.rootless_network_cmd = "slirp4netns".to_string();

        let err = driver.gateway_listener_requirements().unwrap_err();

        assert!(matches!(err, ComputeDriverError::Precondition(_)));
        assert!(err.to_string().contains("slirp4netns"));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn constructor_preserves_required_network_gateway_discovery_error() {
        let (socket_path, _request_log, handle) = spawn_podman_stub(
            "network-gateway-error",
            vec![
                StubResponse::new(StatusCode::OK, ""),
                StubResponse::new(
                    StatusCode::OK,
                    r#"{
                        "host": {
                            "cgroupVersion": "v2",
                            "networkBackend": "netavark",
                            "security": {"rootless": false},
                            "remoteSocket": {"path": "/run/podman/podman.sock"}
                        },
                        "version": {"Version": "5.0.0"}
                    }"#,
                ),
                StubResponse::new(StatusCode::CREATED, "{}"),
                StubResponse::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    r#"{"message":"network gateway inspection failed"}"#,
                ),
            ],
        );
        let config = PodmanComputeConfig {
            socket_path: Some(socket_path.clone()),
            grpc_endpoint: "http://host.containers.internal:8080".to_string(),
            ..PodmanComputeConfig::default()
        };

        let Err(err) = PodmanComputeDriver::new(config).await else {
            panic!("required network gateway discovery failure should prevent startup");
        };

        assert!(
            err.to_string()
                .contains("network gateway inspection failed"),
            "unexpected startup error: {err}"
        );
        handle.await.expect("stub task should finish");
    }

    #[tokio::test]
    async fn constructor_skips_network_gateway_discovery_for_remote_callback() {
        let (socket_path, request_log, handle) = spawn_podman_stub(
            "remote-callback-no-network-gateway",
            vec![
                StubResponse::new(StatusCode::OK, ""),
                StubResponse::new(
                    StatusCode::OK,
                    r#"{
                        "host": {
                            "cgroupVersion": "v2",
                            "networkBackend": "netavark",
                            "security": {"rootless": false}
                        }
                    }"#,
                ),
                StubResponse::new(StatusCode::CREATED, "{}"),
            ],
        );
        let config = PodmanComputeConfig {
            socket_path: Some(socket_path.clone()),
            grpc_endpoint: "https://gateway.example.test:9443".to_string(),
            ..PodmanComputeConfig::default()
        };

        let driver = PodmanComputeDriver::new(config)
            .await
            .expect("remote callbacks must not require bridge gateway inspection");

        assert!(driver.network_gateway_ip().is_none());
        assert!(driver.gateway_listener_requirements().unwrap().is_empty());
        handle.await.expect("stub task should finish");
        assert_eq!(
            request_log
                .lock()
                .expect("request log lock should not be poisoned")
                .as_slice(),
            [
                "GET /_ping".to_string(),
                format!("GET {}", api_path("/libpod/info")),
                format!("POST {}", api_path("/libpod/networks/create")),
            ]
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn rootful_local_callback_alias_requires_concrete_gateway_address() {
        let driver = PodmanComputeDriver::for_tests(PodmanComputeConfig {
            grpc_endpoint: "http://host.openshell.internal:17670".to_string(),
            ..PodmanComputeConfig::default()
        });

        let err = driver.gateway_listener_requirements().unwrap_err();

        assert!(
            err.to_string()
                .contains("did not report a host bridge gateway address")
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn podman_machine_callback_alias_requests_loopback_listener() {
        let driver = PodmanComputeDriver::for_tests(PodmanComputeConfig {
            grpc_endpoint: "http://host.openshell.internal:17670".to_string(),
            ..PodmanComputeConfig::default()
        });

        let requirements = driver.gateway_listener_requirements().unwrap();

        assert_eq!(requirements.len(), 1);
        assert!(matches!(
            requirements[0].selector,
            Some(Selector::LoopbackInterface(_))
        ));
    }

    #[test]
    fn explicit_remote_callback_does_not_request_gateway_listener() {
        let driver = PodmanComputeDriver::for_tests(PodmanComputeConfig {
            grpc_endpoint: "https://gateway.example.test:9443".to_string(),
            gateway_port: 17670,
            ..PodmanComputeConfig::default()
        });

        assert!(driver.gateway_listener_requirements().unwrap().is_empty());
    }

    #[test]
    fn local_callback_alias_requires_primary_listener_port() {
        for grpc_endpoint in [
            "http://host.openshell.internal:17671",
            "http://host.containers.internal",
        ] {
            let driver = PodmanComputeDriver::for_tests(PodmanComputeConfig {
                grpc_endpoint: grpc_endpoint.to_string(),
                gateway_port: 17670,
                ..PodmanComputeConfig::default()
            });

            let err = driver.gateway_listener_requirements().unwrap_err();

            assert!(
                matches!(err, ComputeDriverError::Precondition(_)),
                "mismatched local callback port should fail precondition: {err}"
            );
            assert!(
                err.to_string()
                    .contains("gateway primary listener uses port 17670"),
                "unexpected error for {grpc_endpoint}: {err}"
            );
        }
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

        let driver = PodmanComputeDriver::for_tests(PodmanComputeConfig::default());
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
            supervisor_image_pull_policy("ghcr.io/nvidia/openshell/supervisor:dev"),
            "newer"
        );
        assert_eq!(
            supervisor_image_pull_policy("ghcr.io/nvidia/openshell/supervisor:latest"),
            "newer"
        );
        assert_eq!(
            supervisor_image_pull_policy("ghcr.io/nvidia/openshell/supervisor"),
            "newer"
        );
        assert_eq!(
            supervisor_image_pull_policy(
                "ghcr.io/nvidia/openshell/supervisor:0.0.47-dev.13-g57b71c68f"
            ),
            "missing"
        );
        assert_eq!(
            supervisor_image_pull_policy("ghcr.io/nvidia/openshell/supervisor@sha256:abc123"),
            "missing"
        );
    }

    fn test_driver(socket_path: PathBuf) -> PodmanComputeDriver {
        let config = PodmanComputeConfig {
            socket_path: Some(socket_path),
            stop_timeout_secs: 10,
            ..PodmanComputeConfig::default()
        };
        PodmanComputeDriver::for_tests(config)
    }

    fn test_driver_with_config(config: PodmanComputeConfig) -> PodmanComputeDriver {
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

    fn api_path(path: &str) -> String {
        format!("/v5.0.0{path}")
    }

    #[test]
    fn podman_local_volume_with_bind_option_is_bind_backed() {
        let volume = VolumeInspect {
            driver: "local".to_string(),
            options: HashMap::from([("o".to_string(), "rw,bind".to_string())]),
        };

        assert!(podman_volume_is_bind_backed(&volume));
    }

    #[test]
    fn podman_local_volume_with_rbind_option_is_bind_backed() {
        let volume = VolumeInspect {
            driver: "local".to_string(),
            options: HashMap::from([("o".to_string(), "rw,rbind".to_string())]),
        };

        assert!(podman_volume_is_bind_backed(&volume));
    }

    #[test]
    fn podman_empty_driver_volume_with_bind_option_is_bind_backed() {
        let volume = VolumeInspect {
            driver: String::new(),
            options: HashMap::from([("o".to_string(), "bind".to_string())]),
        };

        assert!(podman_volume_is_bind_backed(&volume));
    }

    #[test]
    fn podman_local_volume_without_bind_option_is_not_bind_backed() {
        let volume = VolumeInspect {
            driver: "local".to_string(),
            options: HashMap::from([("o".to_string(), "addr=127.0.0.1,rw".to_string())]),
        };

        assert!(!podman_volume_is_bind_backed(&volume));
    }

    #[test]
    fn podman_nonlocal_volume_with_bind_option_is_not_bind_backed() {
        let volume = VolumeInspect {
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
        assert!(requests[0].contains("/libpod/containers/json"));
        assert_eq!(
            requests[1],
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
            spec: None,
            status: None,
        }
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

    #[tokio::test]
    async fn create_sandbox_removes_proxy_auth_secret_on_container_create_failure() {
        // A credential secret is staged before the container is created, so a
        // container-create failure must remove it — no credential residue.
        let sandbox_id = "sandbox-cc";
        let auth_file = write_proxy_auth_file("create-fail");
        let (socket_path, request_log, handle) = spawn_podman_stub(
            "create-container-fail",
            vec![
                StubResponse::new(StatusCode::OK, "{}"), // pull supervisor image
                StubResponse::new(StatusCode::OK, "{}"), // pull sandbox image
                StubResponse::new(
                    StatusCode::OK,
                    r#"{"Id":"sha256:sandbox","Config":{"User":"1234:1235"}}"#,
                ), // inspect sandbox image
                StubResponse::new(StatusCode::CREATED, "{}"), // create volume
                StubResponse::new(StatusCode::CREATED, "{}"), // create proxy-auth secret
                StubResponse::new(StatusCode::INTERNAL_SERVER_ERROR, r#"{"message":"boom"}"#), // create container
                StubResponse::new(StatusCode::NO_CONTENT, ""), // cleanup: remove volume
                StubResponse::new(StatusCode::NO_CONTENT, ""), // cleanup: remove proxy-auth secret
            ],
        );
        let driver = test_driver_with_config(proxy_auth_config(socket_path.clone(), &auth_file));

        driver
            .create_sandbox(&plain_sandbox(sandbox_id, "demo"))
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
            vec![
                StubResponse::new(StatusCode::OK, "{}"), // pull supervisor image
                StubResponse::new(StatusCode::OK, "{}"), // pull sandbox image
                StubResponse::new(
                    StatusCode::OK,
                    r#"{"Id":"sha256:sandbox","Config":{"User":"1234:1235"}}"#,
                ), // inspect sandbox image
                StubResponse::new(StatusCode::CREATED, "{}"), // create volume
                StubResponse::new(StatusCode::CREATED, "{}"), // create proxy-auth secret
                StubResponse::new(StatusCode::CREATED, "{}"), // create container
                StubResponse::new(StatusCode::INTERNAL_SERVER_ERROR, r#"{"message":"boom"}"#), // start container
                StubResponse::new(StatusCode::NO_CONTENT, ""), // cleanup: remove container
                StubResponse::new(StatusCode::NO_CONTENT, ""), // cleanup: remove volume
                StubResponse::new(StatusCode::NO_CONTENT, ""), // cleanup: remove proxy-auth secret
            ],
        );
        let driver = test_driver_with_config(proxy_auth_config(socket_path.clone(), &auth_file));

        driver
            .create_sandbox(&plain_sandbox(sandbox_id, "demo"))
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
                StubResponse::new(StatusCode::OK, "[]"), // list_containers (not found)
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
                // list_containers by label
                StubResponse::new(StatusCode::OK, list_body),
                // single timed remove_container operation
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
        assert!(requests[0].contains("/libpod/containers/json"));
        assert_eq!(
            requests[1],
            format!(
                "DELETE {}",
                api_path(&format!(
                    "/libpod/containers/{container_id}?force=true&volumes=true&timeout=10"
                ))
            )
        );
        assert_eq!(
            requests[2],
            format!(
                "DELETE {}",
                api_path(&format!("/libpod/volumes/{volume_name}"))
            )
        );
        let _ = fs::remove_file(socket_path);
    }

    #[test]
    fn userns_needs_extraction_cases() {
        assert!(!userns_needs_extraction(None));
        assert!(!userns_needs_extraction(Some("host")));
        assert!(!userns_needs_extraction(Some("Host")));
        assert!(userns_needs_extraction(Some("auto")));
        assert!(userns_needs_extraction(Some("auto:size=65536")));
        assert!(userns_needs_extraction(Some("keep-id")));
        assert!(userns_needs_extraction(Some("keep-id:uid=1000")));
        assert!(userns_needs_extraction(Some("no-map")));
        assert!(userns_needs_extraction(Some("private")));
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
}
