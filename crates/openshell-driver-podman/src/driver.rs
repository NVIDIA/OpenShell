// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Podman compute driver.

use crate::client::{PodmanApiError, PodmanClient, VolumeInspect};
use crate::config::PodmanComputeConfig;
use crate::container::{self, LABEL_MANAGED_FILTER, LABEL_SANDBOX_ID, PodmanSandboxDriverConfig};
use crate::watcher::{
    self, WatchStream, driver_sandbox_from_inspect, driver_sandbox_from_list_entry,
};
use openshell_core::ComputeDriverError;
use openshell_core::config::CDI_GPU_DEVICE_ALL;
use openshell_core::driver_utils::supervisor_image_should_refresh;
use openshell_core::gpu::{CdiGpuInventory, CdiGpuRoundRobin, CdiGpuSelectionError};
use openshell_core::proto::compute::v1::{DriverSandbox, GetCapabilitiesResponse};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

impl From<PodmanApiError> for ComputeDriverError {
    fn from(value: PodmanApiError) -> Self {
        match value {
            PodmanApiError::Conflict(_) => Self::AlreadyExists,
            PodmanApiError::NotFound(msg) => Self::Message(format!("not found: {msg}")),
            other => Self::Message(other.to_string()),
        }
    }
}

/// Podman compute driver managing sandbox containers via the Podman REST API.
#[derive(Clone)]
pub struct PodmanComputeDriver {
    client: PodmanClient,
    config: PodmanComputeConfig,
    /// The host's IP on the bridge network. Sandbox containers use this to
    /// reach the gateway server when no explicit gRPC endpoint is configured.
    network_gateway_ip: Option<String>,
    gpu_inventory: CdiGpuInventory,
    allow_all_default_gpu: bool,
    gpu_selector: Arc<CdiGpuRoundRobin>,
}

impl std::fmt::Debug for PodmanComputeDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PodmanComputeDriver")
            .field("socket_path", &self.config.socket_path)
            .field("default_image", &self.config.default_image)
            .field("network_name", &self.config.network_name)
            .field("gpu_inventory", &self.gpu_inventory)
            .field("allow_all_default_gpu", &self.allow_all_default_gpu)
            .finish()
    }
}

/// Construct and validate a container name from a sandbox name.
///
/// Combines the prefix with the sandbox name and validates the result
/// against Podman's naming rules before any resources are created.
fn validated_container_name(sandbox_name: &str) -> Result<String, ComputeDriverError> {
    let name = container::container_name(sandbox_name);
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

fn sandbox_token_host_path(sandbox_id: &str) -> Result<PathBuf, ComputeDriverError> {
    openshell_core::driver_utils::sandbox_token_path("podman-sandbox-tokens", None, sandbox_id)
        .map_err(|err| ComputeDriverError::Message(format!("resolve state dir failed: {err}")))
}

async fn write_sandbox_token_file(
    sandbox: &DriverSandbox,
) -> Result<Option<PathBuf>, ComputeDriverError> {
    let Some(spec) = sandbox.spec.as_ref() else {
        return Ok(None);
    };
    if spec.sandbox_token.is_empty() {
        return Ok(None);
    }
    let path = sandbox_token_host_path(&sandbox.id)?;
    if let Some(parent) = path.parent() {
        openshell_core::paths::create_dir_restricted(parent).map_err(|err| {
            ComputeDriverError::Message(format!(
                "create sandbox token directory {} failed: {err}",
                parent.display()
            ))
        })?;
    }
    tokio::fs::write(&path, format!("{}\n", spec.sandbox_token))
        .await
        .map_err(|err| {
            ComputeDriverError::Message(format!(
                "write sandbox token file {} failed: {err}",
                path.display()
            ))
        })?;
    openshell_core::paths::set_file_owner_only(&path).map_err(|err| {
        ComputeDriverError::Message(format!(
            "restrict sandbox token file {} failed: {err}",
            path.display()
        ))
    })?;
    Ok(Some(path))
}

fn cleanup_sandbox_token_file(sandbox_id: &str) {
    let Ok(path) = sandbox_token_host_path(sandbox_id) else {
        return;
    };
    if let Err(err) = std::fs::remove_file(&path)
        && err.kind() != std::io::ErrorKind::NotFound
    {
        warn!(
            sandbox_id = %sandbox_id,
            path = %path.display(),
            error = %err,
            "Failed to remove Podman sandbox token file"
        );
    }
    if let Some(dir) = path.parent() {
        let _ = std::fs::remove_dir(dir);
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

fn podman_gpu_selection_error(err: CdiGpuSelectionError) -> ComputeDriverError {
    ComputeDriverError::Precondition(err.to_string())
}

impl PodmanComputeDriver {
    /// Create a new driver, verifying the Podman socket is reachable.
    pub async fn new(mut config: PodmanComputeConfig) -> Result<Self, PodmanApiError> {
        const MAX_PING_RETRIES: u32 = 5;
        const PING_RETRY_DELAY: Duration = Duration::from_secs(2);

        if !config.socket_path.exists() {
            if cfg!(target_os = "macos") {
                warn!(
                    path = %config.socket_path.display(),
                    "Podman socket not found; is podman machine running? \
                     Try `podman machine start` or set OPENSHELL_PODMAN_SOCKET to override."
                );
            } else {
                warn!(
                    path = %config.socket_path.display(),
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

        let client = PodmanClient::new(config.socket_path.clone());

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
        match client.system_info().await {
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
                    "Connected to Podman"
                );
            }
            Err(e) => {
                return Err(PodmanApiError::Connection(format!(
                    "failed to query Podman system info: {e}"
                )));
            }
        }

        // Rootless pre-flight: warn if subuid/subgid ranges look missing.
        // Not a hard error because some systems configure these via LDAP or
        // other mechanisms that /etc/subuid does not reflect.
        if !cfg!(target_os = "macos") && rustix::process::getuid().as_raw() != 0 {
            check_subuid_range();
        }

        // Ensure the bridge network exists.
        client.ensure_network(&config.network_name).await?;
        let network_gateway_ip = client
            .network_gateway_ip(&config.network_name)
            .await
            .unwrap_or(None);
        info!(
            network = %config.network_name,
            gateway_ip = ?network_gateway_ip,
            "Bridge network ready"
        );

        let gpu_inventory = local_podman_cdi_gpu_inventory();
        let allow_all_default_gpu = local_podman_all_gpu_default_supported();
        if !gpu_inventory.is_empty() {
            info!(
                device_count = gpu_inventory.as_slice().len(),
                "Discovered local Podman NVIDIA CDI GPU devices"
            );
        }

        // Auto-detect the gRPC callback endpoint when not explicitly
        // configured. Sandbox containers use host.containers.internal
        // (injected via hostadd with host-gateway in the container spec)
        // to reach the gateway server on the host. The scheme is
        // determined by whether TLS client certs are configured: when
        // all three TLS paths are set, the endpoint uses https so the
        // supervisor connects with mTLS.
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

        Ok(Self {
            client,
            config,
            network_gateway_ip,
            gpu_inventory,
            allow_all_default_gpu,
            gpu_selector: Arc::new(CdiGpuRoundRobin::new()),
        })
    }

    /// The host's IP on the bridge network, if available.
    ///
    /// Used by the server to auto-detect the gRPC callback endpoint when
    /// no explicit `--grpc-endpoint` is configured.
    #[must_use]
    pub fn network_gateway_ip(&self) -> Option<&str> {
        self.network_gateway_ip.as_deref()
    }

    /// Report driver capabilities.
    pub fn capabilities(&self) -> Result<GetCapabilitiesResponse, ComputeDriverError> {
        Ok(openshell_core::driver_utils::build_capabilities_response(
            "podman",
            openshell_core::VERSION,
            &self.config.default_image,
        ))
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
        let gpu_requested = sandbox.spec.as_ref().is_some_and(|s| s.gpu);
        let driver_config = PodmanSandboxDriverConfig::from_sandbox(sandbox)?;
        if !gpu_requested && driver_config.cdi_devices.is_some() {
            return Err(ComputeDriverError::InvalidArgument(
                "driver_config.cdi_devices requires gpu=true".to_string(),
            ));
        }
        self.validate_user_volume_mounts_available(sandbox).await?;
        let _ = self.peek_default_gpu_device(sandbox)?;
        Ok(())
    }

    fn peek_default_gpu_device(
        &self,
        sandbox: &DriverSandbox,
    ) -> Result<Option<String>, ComputeDriverError> {
        self.selected_default_gpu_device(sandbox, false)
    }

    fn next_default_gpu_device(
        &self,
        sandbox: &DriverSandbox,
    ) -> Result<Option<String>, ComputeDriverError> {
        self.selected_default_gpu_device(sandbox, true)
    }

    fn selected_default_gpu_device(
        &self,
        sandbox: &DriverSandbox,
        consume: bool,
    ) -> Result<Option<String>, ComputeDriverError> {
        let Some(spec) = sandbox.spec.as_ref() else {
            return Ok(None);
        };
        let driver_config = PodmanSandboxDriverConfig::from_sandbox(sandbox)?;
        if !spec.gpu || driver_config.cdi_devices.is_some() {
            return Ok(None);
        }

        let selected = if consume {
            self.gpu_selector
                .next_default_device_id(&self.gpu_inventory, self.allow_all_default_gpu)
        } else {
            self.gpu_selector
                .peek_default_device_id(&self.gpu_inventory, self.allow_all_default_gpu)
        }
        .map_err(podman_gpu_selection_error)?;
        Ok(Some(selected))
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
    pub async fn create_sandbox(&self, sandbox: &DriverSandbox) -> Result<(), ComputeDriverError> {
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
        let name = validated_container_name(&sandbox.name)?;
        self.validate_sandbox_create(sandbox).await?;

        let vol_name = container::volume_name(&sandbox.id);

        info!(
            sandbox_id = %sandbox.id,
            sandbox_name = %sandbox.name,
            container = %name,
            "Creating sandbox container"
        );

        // 1a. Pull the supervisor image if needed. The supervisor binary
        //     is shipped in a standalone OCI image and mounted into sandbox
        //     containers via Podman's type=image mount. Refresh mutable tags
        //     like latest/dev, but avoid registry checks for pinned images.
        let supervisor_pull_policy = supervisor_image_pull_policy(&self.config.supervisor_image);
        info!(
            image = %self.config.supervisor_image,
            policy = supervisor_pull_policy,
            "Ensuring supervisor image"
        );
        self.client
            .pull_image(&self.config.supervisor_image, supervisor_pull_policy)
            .await
            .map_err(ComputeDriverError::from)?;

        // 1b. Pull the sandbox image if needed (Podman does not pull on create).
        let image = container::resolve_image(sandbox, &self.config);
        if image.is_empty() {
            return Err(ComputeDriverError::Precondition(
                "no sandbox image configured: set default_image in [openshell.drivers.podman] \
                 or provide an image in the sandbox template"
                    .to_string(),
            ));
        }
        let pull_policy = self.config.image_pull_policy.as_str();
        info!(image = %image, policy = %pull_policy, "Ensuring sandbox image");
        self.client
            .pull_image(image, pull_policy)
            .await
            .map_err(ComputeDriverError::from)?;

        for image in
            container::podman_driver_image_mount_sources(sandbox, self.config.enable_bind_mounts)
                .map_err(ComputeDriverError::Precondition)?
        {
            info!(image = %image, policy = %pull_policy, "Ensuring image mount source");
            self.client
                .pull_image(&image, pull_policy)
                .await
                .map_err(ComputeDriverError::from)?;
        }

        // 2. Create workspace volume.
        if let Err(e) = self.client.create_volume(&vol_name).await {
            return Err(ComputeDriverError::from(e));
        }
        let token_host_path = match write_sandbox_token_file(sandbox).await {
            Ok(path) => path,
            Err(e) => {
                let _ = self.client.remove_volume(&vol_name).await;
                return Err(e);
            }
        };

        // 3. Create container.
        let selected_default_gpu = match self.next_default_gpu_device(sandbox) {
            Ok(device) => device,
            Err(e) => {
                let _ = self.client.remove_volume(&vol_name).await;
                cleanup_sandbox_token_file(&sandbox.id);
                return Err(e);
            }
        };
        let spec = match container::build_container_spec_with_token_and_gpu_default(
            sandbox,
            &self.config,
            token_host_path.as_deref(),
            selected_default_gpu.as_deref(),
        ) {
            Ok(spec) => spec,
            Err(e) => {
                let _ = self.client.remove_volume(&vol_name).await;
                cleanup_sandbox_token_file(&sandbox.id);
                return Err(e);
            }
        };
        match self.client.create_container(&spec).await {
            Ok(_) => {}
            Err(PodmanApiError::Conflict(_)) => {
                // Clean up the volume we just created. It is keyed by *this*
                // sandbox's ID, not the conflicting container's ID (which
                // has the same name but a different ID), so it would be
                // orphaned otherwise.
                let _ = self.client.remove_volume(&vol_name).await;
                cleanup_sandbox_token_file(&sandbox.id);
                return Err(ComputeDriverError::AlreadyExists);
            }
            Err(e) => {
                let _ = self.client.remove_volume(&vol_name).await;
                cleanup_sandbox_token_file(&sandbox.id);
                return Err(ComputeDriverError::from(e));
            }
        }

        // 5. Start container.
        if let Err(e) = self.client.start_container(&name).await {
            warn!(
                sandbox_name = %sandbox.name,
                error = %e,
                "Failed to start container; cleaning up"
            );
            let _ = self.client.remove_container(&name).await;
            let _ = self.client.remove_volume(&vol_name).await;
            cleanup_sandbox_token_file(&sandbox.id);
            return Err(ComputeDriverError::from(e));
        }

        info!(
            sandbox_id = %sandbox.id,
            sandbox_name = %sandbox.name,
            "Sandbox container started"
        );

        Ok(())
    }

    /// Stop a sandbox container without deleting it.
    pub async fn stop_sandbox(&self, sandbox_name: &str) -> Result<(), ComputeDriverError> {
        let name = validated_container_name(sandbox_name)?;
        info!(sandbox_name = %sandbox_name, container = %name, "Stopping sandbox container");

        self.client
            .stop_container(&name, self.config.stop_timeout_secs)
            .await
            .map_err(ComputeDriverError::from)
    }

    /// Delete a sandbox container and its workspace volume.
    pub async fn delete_sandbox(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<bool, ComputeDriverError> {
        if sandbox_id.is_empty() {
            return Err(ComputeDriverError::Precondition(
                "sandbox id is required".into(),
            ));
        }
        let name = validated_container_name(sandbox_name)?;
        info!(
            sandbox_id = %sandbox_id,
            sandbox_name = %sandbox_name,
            container = %name,
            "Deleting sandbox container"
        );

        // Use the request's stable sandbox ID as the source of truth for
        // cleanup. Inspect is only used as a best-effort cross-check so
        // cleanup still works if the container is already gone or mislabeled.
        match self.client.inspect_container(&name).await {
            Ok(inspect) => match inspect.config.labels.get(LABEL_SANDBOX_ID) {
                Some(label_id) if label_id != sandbox_id => {
                    warn!(
                        sandbox_id = %sandbox_id,
                        sandbox_name = %sandbox_name,
                        container = %name,
                        label_sandbox_id = %label_id,
                        "Container label sandbox ID did not match delete request; cleaning up using request sandbox_id"
                    );
                }
                None => {
                    warn!(
                        sandbox_id = %sandbox_id,
                        sandbox_name = %sandbox_name,
                        container = %name,
                        "Container missing '{}' label; cleaning up using request sandbox_id",
                        LABEL_SANDBOX_ID,
                    );
                }
                Some(_) => {}
            },
            Err(PodmanApiError::NotFound(_)) => {}
            Err(e) => return Err(ComputeDriverError::from(e)),
        }

        // Stop (best-effort).
        let _ = self
            .client
            .stop_container(&name, self.config.stop_timeout_secs)
            .await;

        // Remove container. If NotFound, the container was removed between
        // inspect and here (TOCTOU race); proceed with volume cleanup
        // since the workspace volume is idempotent to remove.
        let container_existed = match self.client.remove_container(&name).await {
            Ok(()) => true,
            Err(PodmanApiError::NotFound(_)) => false,
            Err(e) => return Err(ComputeDriverError::from(e)),
        };

        // Remove workspace volume.
        let vol = container::volume_name(sandbox_id);
        if let Err(e) = self.client.remove_volume(&vol).await {
            warn!(
                sandbox_id = %sandbox_id,
                sandbox_name = %sandbox_name,
                volume = %vol,
                error = %e,
                "Failed to remove workspace volume"
            );
        }
        cleanup_sandbox_token_file(sandbox_id);

        Ok(container_existed)
    }

    /// Check whether a sandbox container exists.
    pub async fn sandbox_exists(&self, sandbox_name: &str) -> Result<bool, ComputeDriverError> {
        let name = container::container_name(sandbox_name);
        match self.client.inspect_container(&name).await {
            Ok(_) => Ok(true),
            Err(PodmanApiError::NotFound(_)) => Ok(false),
            Err(e) => Err(ComputeDriverError::from(e)),
        }
    }

    /// Fetch a single sandbox by name.
    pub async fn get_sandbox(
        &self,
        sandbox_name: &str,
    ) -> Result<Option<DriverSandbox>, ComputeDriverError> {
        let name = container::container_name(sandbox_name);
        match self.client.inspect_container(&name).await {
            Ok(inspect) => Ok(driver_sandbox_from_inspect(&inspect)),
            Err(PodmanApiError::NotFound(_)) => Ok(None),
            Err(e) => Err(ComputeDriverError::from(e)),
        }
    }

    /// List all managed sandboxes.
    ///
    /// Only inspects running containers (to get health status). Non-running
    /// containers are built directly from the list entry data.
    pub async fn list_sandboxes(&self) -> Result<Vec<DriverSandbox>, ComputeDriverError> {
        let entries = self
            .client
            .list_containers(LABEL_MANAGED_FILTER)
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
        watcher::start_watch(self.client.clone())
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
        let client = PodmanClient::new(config.socket_path.clone());
        Self {
            client,
            config,
            network_gateway_ip: None,
            gpu_inventory,
            allow_all_default_gpu,
            gpu_selector: Arc::new(CdiGpuRoundRobin::new()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{StubResponse, spawn_podman_stub};
    use hyper::StatusCode;
    use openshell_core::proto::compute::v1::{DriverSandboxSpec, DriverSandboxTemplate};
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;

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

    #[test]
    fn podman_driver_error_from_conflict() {
        let err = ComputeDriverError::from(PodmanApiError::Conflict("exists".into()));
        assert!(matches!(err, ComputeDriverError::AlreadyExists));
    }

    #[test]
    fn podman_driver_error_from_not_found() {
        let err = ComputeDriverError::from(PodmanApiError::NotFound("gone".into()));
        assert!(matches!(err, ComputeDriverError::Message(_)));
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
                gpu: true,
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
                gpu: true,
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
                gpu: true,
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
                gpu: true,
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
                gpu: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let second_sandbox = DriverSandbox {
            id: "sbx-second".to_string(),
            name: "second".to_string(),
            spec: Some(DriverSandboxSpec {
                gpu: true,
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(
            driver.peek_default_gpu_device(&first_sandbox).unwrap(),
            Some("nvidia.com/gpu=0".to_string())
        );
        let first_device = driver.next_default_gpu_device(&first_sandbox).unwrap();
        let first_spec = container::build_container_spec_with_token_and_gpu_default(
            &first_sandbox,
            &driver.config,
            None,
            first_device.as_deref(),
        )
        .unwrap();

        assert_eq!(
            driver.peek_default_gpu_device(&second_sandbox).unwrap(),
            Some("nvidia.com/gpu=1".to_string())
        );
        let second_device = driver.next_default_gpu_device(&second_sandbox).unwrap();
        let second_spec = container::build_container_spec_with_token_and_gpu_default(
            &second_sandbox,
            &driver.config,
            None,
            second_device.as_deref(),
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
            socket_path,
            stop_timeout_secs: 10,
            ..PodmanComputeConfig::default()
        };
        PodmanComputeDriver::for_tests(config)
    }

    fn test_driver_with_config(config: PodmanComputeConfig) -> PodmanComputeDriver {
        PodmanComputeDriver::for_tests(config)
    }

    fn json_value(value: serde_json::Value) -> prost_types::Value {
        match value {
            serde_json::Value::Null => prost_types::Value { kind: None },
            serde_json::Value::Bool(value) => prost_types::Value {
                kind: Some(prost_types::value::Kind::BoolValue(value)),
            },
            serde_json::Value::Number(value) => prost_types::Value {
                kind: value.as_f64().map(prost_types::value::Kind::NumberValue),
            },
            serde_json::Value::String(value) => prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue(value)),
            },
            serde_json::Value::Array(values) => prost_types::Value {
                kind: Some(prost_types::value::Kind::ListValue(
                    prost_types::ListValue {
                        values: values.into_iter().map(json_value).collect(),
                    },
                )),
            },
            serde_json::Value::Object(values) => prost_types::Value {
                kind: Some(prost_types::value::Kind::StructValue(prost_types::Struct {
                    fields: values
                        .into_iter()
                        .map(|(key, value)| (key, json_value(value)))
                        .collect(),
                })),
            },
        }
    }

    fn json_struct(value: serde_json::Value) -> prost_types::Struct {
        match json_value(value).kind {
            Some(prost_types::value::Kind::StructValue(value)) => value,
            _ => panic!("expected JSON object"),
        }
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
            socket_path: socket_path.clone(),
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
    async fn delete_sandbox_cleans_up_with_request_id_when_container_is_already_gone() {
        let sandbox_id = "sandbox-123";
        let sandbox_name = "demo";
        let container_name = container::container_name(sandbox_name);
        let volume_name = container::volume_name(sandbox_id);
        let (socket_path, request_log, handle) = spawn_podman_stub(
            "delete-not-found",
            vec![
                StubResponse::new(StatusCode::NOT_FOUND, r#"{"message":"gone"}"#),
                StubResponse::new(StatusCode::NOT_FOUND, r#"{"message":"gone"}"#),
                StubResponse::new(StatusCode::NOT_FOUND, r#"{"message":"gone"}"#),
                StubResponse::new(StatusCode::NO_CONTENT, ""),
            ],
        );
        let driver = test_driver(socket_path.clone());

        let deleted = driver
            .delete_sandbox(sandbox_id, sandbox_name)
            .await
            .expect("delete should succeed");

        assert!(!deleted, "missing container should report deleted=false");
        handle.await.expect("stub task should finish");
        let requests = request_log
            .lock()
            .expect("request log lock should not be poisoned")
            .clone();
        assert_eq!(
            requests,
            vec![
                format!(
                    "GET {}",
                    api_path(&format!("/libpod/containers/{container_name}/json"))
                ),
                format!(
                    "POST {}",
                    api_path(&format!(
                        "/libpod/containers/{container_name}/stop?timeout=10"
                    ))
                ),
                format!(
                    "DELETE {}",
                    api_path(&format!(
                        "/libpod/containers/{container_name}?force=true&v=true"
                    ))
                ),
                format!(
                    "DELETE {}",
                    api_path(&format!("/libpod/volumes/{volume_name}"))
                ),
            ]
        );
        let _ = fs::remove_file(socket_path);
    }

    #[tokio::test]
    async fn delete_sandbox_uses_request_id_when_container_label_disagrees() {
        let sandbox_id = "sandbox-request-id";
        let sandbox_name = "demo";
        let container_name = container::container_name(sandbox_name);
        let volume_name = container::volume_name(sandbox_id);
        let inspect_body = serde_json::json!({
            "Id": "container-id",
            "Name": format!("/{container_name}"),
            "State": {
                "Status": "running",
                "Running": true
            },
            "Config": {
                "Labels": {
                    LABEL_SANDBOX_ID: "sandbox-label-id"
                }
            }
        })
        .to_string();
        let (socket_path, request_log, handle) = spawn_podman_stub(
            "delete-mismatch",
            vec![
                StubResponse::new(StatusCode::OK, inspect_body),
                StubResponse::new(StatusCode::NO_CONTENT, ""),
                StubResponse::new(StatusCode::NO_CONTENT, ""),
                StubResponse::new(StatusCode::NO_CONTENT, ""),
            ],
        );
        let driver = test_driver(socket_path.clone());

        let deleted = driver
            .delete_sandbox(sandbox_id, sandbox_name)
            .await
            .expect("delete should succeed");

        assert!(deleted, "existing container should report deleted=true");
        handle.await.expect("stub task should finish");
        let requests = request_log
            .lock()
            .expect("request log lock should not be poisoned")
            .clone();
        assert_eq!(
            requests[3..],
            [format!(
                "DELETE {}",
                api_path(&format!("/libpod/volumes/{volume_name}"))
            )]
        );
        let _ = fs::remove_file(socket_path);
    }
}
