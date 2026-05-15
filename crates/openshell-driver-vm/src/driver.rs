// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::gpu::{
    GpuInventory, SubnetAllocator, allocate_vsock_cid, mac_from_sandbox_id, tap_device_name,
};
use crate::rootfs::{
    clone_or_copy_sparse_file, create_ext4_image_from_dir_with_size, create_rootfs_image_from_dir,
    extract_rootfs_archive_to, prepare_sandbox_rootfs_from_image_root, sandbox_guest_init_path,
    set_rootfs_image_file_mode, write_rootfs_image_file,
};
use bollard::Docker;
use bollard::errors::Error as BollardError;
use bollard::models::ContainerCreateBody;
use bollard::query_parameters::{CreateContainerOptionsBuilder, RemoveContainerOptionsBuilder};
use flate2::read::GzDecoder;
use futures::{Stream, StreamExt, TryStreamExt};
use nix::errno::Errno;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use oci_client::client::{Client as OciClient, ClientConfig};
use oci_client::manifest::{
    ImageIndexEntry, OCI_IMAGE_MEDIA_TYPE, OciDescriptor, OciImageManifest,
};
use oci_client::secrets::RegistryAuth;
use oci_client::{Reference, RegistryOperation};
use openshell_core::progress::{
    PROGRESS_STEP_PULLING_IMAGE, PROGRESS_STEP_REQUESTING_SANDBOX, PROGRESS_STEP_STARTING_SANDBOX,
    mark_progress_active, mark_progress_complete, mark_progress_detail,
};
use openshell_core::proto::compute::v1::{
    CreateSandboxRequest, CreateSandboxResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    DriverCondition as SandboxCondition, DriverPlatformEvent as PlatformEvent,
    DriverSandbox as Sandbox, DriverSandboxStatus as SandboxStatus, GetCapabilitiesRequest,
    GetCapabilitiesResponse, GetSandboxRequest, GetSandboxResponse, ListSandboxesRequest,
    ListSandboxesResponse, StopSandboxRequest, StopSandboxResponse, ValidateSandboxCreateRequest,
    ValidateSandboxCreateResponse, WatchSandboxesDeletedEvent, WatchSandboxesEvent,
    WatchSandboxesPlatformEvent, WatchSandboxesRequest, WatchSandboxesSandboxEvent,
    compute_driver_server::ComputeDriver, watch_sandboxes_event,
};
use openshell_vfio::SysfsRoot;
use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::net::Ipv4Addr;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};
use url::{Host, Url};

const DRIVER_NAME: &str = "openshell-driver-vm";
const WATCH_BUFFER: usize = 256;
const DEFAULT_VCPUS: u8 = 2;
const DEFAULT_MEM_MIB: u32 = 2048;
const DEFAULT_OVERLAY_DISK_MIB: u64 = 4096;
const DEFAULT_REGISTRY_LAYER_DOWNLOAD_CONCURRENCY: usize = 4;
const MAX_REGISTRY_LAYER_DOWNLOAD_CONCURRENCY: usize = 16;
/// gvproxy host-loopback IP — gvproxy's TCP/UDP/ICMP forwarder NAT-rewrites
/// this destination to the host's `127.0.0.1` and dials out from the host
/// process. This is the only address that transparently reaches host-bound
/// services without explicit `expose` rules.
///
/// See gvisor-tap-vsock `cmd/gvproxy/config.go` (default NAT entry
/// `HostIP -> 127.0.0.1`) and `pkg/services/forwarder/tcp.go` (NAT lookup
/// before `net.Dial`).
///
/// Code paths route via `GVPROXY_HOST_LOOPBACK_ALIAS` (DNS / /etc/hosts)
/// instead so logs stay readable; this constant is kept for documentation
/// and parity with the guest init script.
#[allow(dead_code)]
const GVPROXY_HOST_LOOPBACK_IP: &str = "192.168.127.254";
const OPENSHELL_HOST_GATEWAY_ALIAS: &str = "host.openshell.internal";
/// Hostname gvproxy resolves (via its embedded DNS) to the host-loopback IP.
///
/// We rewrite loopback URLs to this hostname rather than the bare IP because:
///   * the guest init script seeds /etc/hosts with the same mapping, so it
///     resolves even when gvproxy's DNS is not in resolv.conf;
///   * keeping a recognisable hostname makes log messages clearer than a bare
///     192.168.127.254 reference;
///   * `host.docker.internal` works the same way for Docker-flavoured tooling.
///
/// Both names ultimately route through the gvproxy NAT path on
/// `GVPROXY_HOST_LOOPBACK_IP` — they do **not** go through the gateway IP.
const GVPROXY_HOST_LOOPBACK_ALIAS: &str = "host.containers.internal";
const GUEST_SSH_SOCKET_PATH: &str = "/run/openshell/ssh.sock";
const GUEST_TLS_CA_PATH: &str = "/opt/openshell/tls/ca.crt";
const GUEST_TLS_CERT_PATH: &str = "/opt/openshell/tls/tls.crt";
const GUEST_TLS_KEY_PATH: &str = "/opt/openshell/tls/tls.key";
const IMAGE_CACHE_ROOT_DIR: &str = "images";
const IMAGE_CACHE_ROOTFS_IMAGE: &str = "rootfs.ext4";
const OVERLAY_TEMPLATE_CACHE_DIR: &str = "overlay-templates";
const OVERLAY_TEMPLATE_CACHE_LAYOUT_VERSION: &str = "sandbox-overlay-ext4-v1";
const SANDBOX_OVERLAY_IMAGE: &str = "overlay.ext4";
const SANDBOX_REQUEST_FILE: &str = "sandbox.pb";
const GUEST_IMAGE_CONFIG_DIR: &str = "openshell-image";
const GUEST_IMAGE_OCI_LAYOUT_DIR: &str = "oci";
const GUEST_IMAGE_OCI_REF: &str = "openshell";
const IMAGE_EXPORT_ROOTFS_ARCHIVE: &str = "source-rootfs.tar";
const BOOTSTRAP_IMAGE_CACHE_LAYOUT_VERSION: &str = "sandbox-bootstrap-rootfs-ext4-v2";
const PREPARED_IMAGE_CACHE_LAYOUT_VERSION: &str = "sandbox-prepared-rootfs-ext4-umoci-v2";
const IMAGE_IDENTITY_FILE: &str = "image-identity";
const IMAGE_REFERENCE_FILE: &str = "image-reference";
const IMAGE_PREP_INIT_MODE: &str = "image-prep";
static IMAGE_CACHE_BUILD_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
struct VmDriverTlsPaths {
    ca: PathBuf,
    cert: PathBuf,
    key: PathBuf,
}

#[derive(Debug, Clone)]
struct RuntimeImagePlan {
    root_disk: PathBuf,
    image_disk: Option<PathBuf>,
    image_identity: String,
    bootstrap_image_identity: String,
}

#[derive(Debug, Clone)]
struct PreparedImageDisk {
    image_identity: String,
    disk_path: PathBuf,
}

#[derive(Debug, Clone)]
struct GuestImagePayload {
    image_ref: String,
    image_identity: String,
    source: GuestImagePayloadSource,
}

#[derive(Debug, Clone)]
enum GuestImagePayloadSource {
    RegistryOciLayout { layout_dir: PathBuf },
    LocalDocker { rootfs_archive: PathBuf },
}

#[derive(Debug, Clone)]
pub struct VmDriverConfig {
    pub openshell_endpoint: String,
    pub state_dir: PathBuf,
    pub launcher_bin: Option<PathBuf>,
    pub default_image: String,
    pub bootstrap_image: String,
    pub log_level: String,
    pub krun_log_level: u32,
    pub vcpus: u8,
    pub mem_mib: u32,
    pub overlay_disk_mib: u64,
    pub guest_tls_ca: Option<PathBuf>,
    pub guest_tls_cert: Option<PathBuf>,
    pub guest_tls_key: Option<PathBuf>,
    pub gpu_enabled: bool,
    pub gpu_mem_mib: u32,
    pub gpu_vcpus: u8,
}

impl Default for VmDriverConfig {
    fn default() -> Self {
        Self {
            openshell_endpoint: String::new(),
            state_dir: PathBuf::from("target/openshell-vm-driver"),
            launcher_bin: None,
            default_image: String::new(),
            bootstrap_image: String::new(),
            log_level: "info".to_string(),
            krun_log_level: 1,
            vcpus: DEFAULT_VCPUS,
            mem_mib: DEFAULT_MEM_MIB,
            overlay_disk_mib: DEFAULT_OVERLAY_DISK_MIB,
            guest_tls_ca: None,
            guest_tls_cert: None,
            guest_tls_key: None,
            gpu_enabled: false,
            gpu_mem_mib: 8192,
            gpu_vcpus: 4,
        }
    }
}

impl VmDriverConfig {
    fn requires_tls_materials(&self) -> bool {
        self.openshell_endpoint.starts_with("https://")
    }

    fn tls_paths(&self) -> Result<Option<VmDriverTlsPaths>, String> {
        let provided = [
            self.guest_tls_ca.as_ref(),
            self.guest_tls_cert.as_ref(),
            self.guest_tls_key.as_ref(),
        ];
        if provided.iter().all(Option::is_none) {
            return if self.requires_tls_materials() {
                Err(
                    "https:// openshell endpoint requires OPENSHELL_VM_TLS_CA, OPENSHELL_VM_TLS_CERT, and OPENSHELL_VM_TLS_KEY so sandbox VMs can authenticate to the gateway"
                        .to_string(),
                )
            } else {
                Ok(None)
            };
        }

        let Some(ca) = self.guest_tls_ca.clone() else {
            return Err(
                "OPENSHELL_VM_TLS_CA is required when TLS materials are configured".to_string(),
            );
        };
        let Some(cert) = self.guest_tls_cert.clone() else {
            return Err(
                "OPENSHELL_VM_TLS_CERT is required when TLS materials are configured".to_string(),
            );
        };
        let Some(key) = self.guest_tls_key.clone() else {
            return Err(
                "OPENSHELL_VM_TLS_KEY is required when TLS materials are configured".to_string(),
            );
        };

        for path in [&ca, &cert, &key] {
            if !path.is_file() {
                return Err(format!(
                    "TLS material '{}' does not exist or is not a file",
                    path.display()
                ));
            }
        }

        Ok(Some(VmDriverTlsPaths { ca, cert, key }))
    }
}

fn validate_openshell_endpoint(endpoint: &str) -> Result<(), String> {
    let url = Url::parse(endpoint)
        .map_err(|err| format!("invalid openshell endpoint '{endpoint}': {err}"))?;
    let Some(host) = url.host() else {
        return Err(format!("openshell endpoint '{endpoint}' is missing a host"));
    };

    let invalid_from_vm = match host {
        Host::Domain(_) => false,
        Host::Ipv4(ip) => ip.is_unspecified(),
        Host::Ipv6(ip) => ip.is_unspecified(),
    };

    if invalid_from_vm {
        return Err(format!(
            "openshell endpoint '{endpoint}' is not reachable from sandbox VMs; use a concrete host such as 127.0.0.1, {OPENSHELL_HOST_GATEWAY_ALIAS}, or another routable address"
        ));
    }

    Ok(())
}

#[derive(Debug)]
struct VmProcess {
    child: Child,
    deleting: bool,
}

struct SandboxRecord {
    snapshot: Sandbox,
    state_dir: PathBuf,
    process: Option<Arc<Mutex<VmProcess>>>,
    provisioning_task: Option<JoinHandle<()>>,
    gpu_bdf: Option<String>,
    deleting: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OverlayPreparation {
    Fresh,
    PreserveExisting,
}

#[derive(Clone)]
pub struct VmDriver {
    config: VmDriverConfig,
    launcher_bin: PathBuf,
    registry: Arc<Mutex<HashMap<String, SandboxRecord>>>,
    image_cache_lock: Arc<Mutex<()>>,
    events: broadcast::Sender<WatchSandboxesEvent>,
    gpu_inventory: Option<Arc<std::sync::Mutex<GpuInventory>>>,
    subnet_allocator: Arc<std::sync::Mutex<SubnetAllocator>>,
}

impl VmDriver {
    pub async fn new(config: VmDriverConfig) -> Result<Self, String> {
        if config.openshell_endpoint.trim().is_empty() {
            return Err("openshell endpoint is required".to_string());
        }
        validate_openshell_endpoint(&config.openshell_endpoint)?;
        let _ = config.tls_paths()?;

        #[cfg(target_os = "linux")]
        if config.gpu_enabled {
            check_gpu_privileges()?;
            tokio::task::spawn_blocking(crate::cleanup_stale_tap_interfaces)
                .await
                .map_err(|e| format!("cleanup stale TAP interfaces panicked: {e}"))?;
        }

        let state_root = sandboxes_root_dir(&config.state_dir);
        create_private_dir_all(&state_root).await.map_err(|err| {
            format!(
                "failed to create state dir '{}': {err}",
                state_root.display()
            )
        })?;
        let image_cache_root = image_cache_root_dir(&config.state_dir);
        tokio::fs::create_dir_all(&image_cache_root)
            .await
            .map_err(|err| {
                format!(
                    "failed to create state dir '{}': {err}",
                    image_cache_root.display()
                )
            })?;

        let launcher_bin = if let Some(path) = config.launcher_bin.clone() {
            path
        } else {
            std::env::current_exe()
                .map_err(|err| format!("failed to resolve vm driver executable: {err}"))?
        };

        let gpu_inventory = if config.gpu_enabled {
            let sysfs = SysfsRoot::system();
            let inventory = GpuInventory::new(sysfs, &config.state_dir);
            tracing::info!(
                gpu_count = inventory.gpu_count(),
                "GPU inventory initialized"
            );
            Some(Arc::new(std::sync::Mutex::new(inventory)))
        } else {
            None
        };

        let subnet_allocator = Arc::new(std::sync::Mutex::new(SubnetAllocator::new(
            Ipv4Addr::new(10, 0, 128, 0),
            17,
        )));

        let (events, _) = broadcast::channel(WATCH_BUFFER);
        let driver = Self {
            config,
            launcher_bin,
            registry: Arc::new(Mutex::new(HashMap::new())),
            image_cache_lock: Arc::new(Mutex::new(())),
            events,
            gpu_inventory,
            subnet_allocator,
        };
        driver.restore_persisted_sandboxes().await;
        Ok(driver)
    }

    #[must_use]
    pub fn capabilities(&self) -> GetCapabilitiesResponse {
        let gpu_count = self
            .gpu_inventory
            .as_ref()
            .and_then(|inv| inv.lock().ok())
            .map_or(0, |inv| inv.gpu_count());
        GetCapabilitiesResponse {
            driver_name: DRIVER_NAME.to_string(),
            driver_version: openshell_core::VERSION.to_string(),
            default_image: self.config.default_image.clone(),
            supports_gpu: self.gpu_inventory.is_some(),
            gpu_count,
        }
    }

    // `tonic::Status` is large but is the standard error type across the
    // gRPC API surface; boxing here would diverge from every other handler.
    #[allow(clippy::result_large_err)]
    pub fn validate_sandbox(&self, sandbox: &Sandbox) -> Result<(), Status> {
        validate_vm_sandbox(sandbox, self.config.gpu_enabled)?;
        if self.resolved_sandbox_image(sandbox).is_none() {
            return Err(Status::failed_precondition(
                "vm sandboxes require template.image or a configured default sandbox image",
            ));
        }
        Ok(())
    }

    // `tonic::Status` is large but is the standard error type across the
    // gRPC API surface; boxing here would diverge from every other handler.
    #[allow(clippy::result_large_err)]
    pub async fn create_sandbox(&self, sandbox: &Sandbox) -> Result<CreateSandboxResponse, Status> {
        info!(
            sandbox_id = %sandbox.id,
            sandbox_name = %sandbox.name,
            "vm driver: create_sandbox received"
        );
        validate_vm_sandbox(sandbox, self.config.gpu_enabled)?;

        let state_dir = sandbox_state_dir(&self.config.state_dir, &sandbox.id)?;
        let image_ref = self.resolved_sandbox_image(sandbox).ok_or_else(|| {
            Status::failed_precondition(
                "vm sandboxes require template.image or a configured default sandbox image",
            )
        })?;
        info!(
            sandbox_id = %sandbox.id,
            image_ref = %image_ref,
            state_dir = %state_dir.display(),
            "vm driver: resolved image ref, preparing disks"
        );

        let snapshot = sandbox_snapshot(sandbox, provisioning_condition(), false);
        {
            let mut registry = self.registry.lock().await;
            if registry.contains_key(&sandbox.id) {
                return Err(Status::already_exists("sandbox already exists"));
            }
            registry.insert(
                sandbox.id.clone(),
                SandboxRecord {
                    snapshot: snapshot.clone(),
                    state_dir: state_dir.clone(),
                    process: None,
                    provisioning_task: None,
                    gpu_bdf: None,
                    deleting: false,
                },
            );
        }

        let tls_paths = match self.config.tls_paths() {
            Ok(paths) => paths,
            Err(err) => {
                let mut registry = self.registry.lock().await;
                registry.remove(&sandbox.id);
                return Err(Status::failed_precondition(err));
            }
        };

        if let Err(err) = create_private_dir_all(&state_dir).await {
            let mut registry = self.registry.lock().await;
            registry.remove(&sandbox.id);
            return Err(Status::internal(format!("create state dir failed: {err}")));
        }

        if let Err(err) = write_sandbox_request(&state_dir, sandbox).await {
            let mut registry = self.registry.lock().await;
            registry.remove(&sandbox.id);
            let _ = tokio::fs::remove_dir_all(&state_dir).await;
            return Err(Status::internal(format!(
                "write sandbox resume metadata failed: {err}"
            )));
        }

        self.publish_platform_event(
            sandbox.id.clone(),
            platform_event(
                "vm",
                "Normal",
                "Scheduled",
                format!("Sandbox accepted by vm driver to image \"{image_ref}\""),
            ),
        );
        self.publish_snapshot(snapshot);

        let driver = self.clone();
        let sandbox_for_task = sandbox.clone();
        let sandbox_id = sandbox.id.clone();
        let image_ref_for_task = image_ref.clone();
        let state_dir_for_task = state_dir.clone();
        let task = tokio::spawn(async move {
            driver
                .provision_sandbox(
                    sandbox_for_task,
                    image_ref_for_task,
                    state_dir_for_task,
                    tls_paths,
                    OverlayPreparation::Fresh,
                )
                .await;
        });

        let mut registry = self.registry.lock().await;
        if let Some(record) = registry.get_mut(&sandbox_id) {
            if record.deleting {
                task.abort();
            } else {
                record.provisioning_task = Some(task);
            }
        } else {
            task.abort();
        }

        Ok(CreateSandboxResponse {})
    }

    async fn provision_sandbox(
        &self,
        sandbox: Sandbox,
        image_ref: String,
        state_dir: PathBuf,
        tls_paths: Option<VmDriverTlsPaths>,
        overlay_preparation: OverlayPreparation,
    ) {
        let sandbox_id = sandbox.id.clone();
        if let Err(err) = self
            .provision_sandbox_inner(
                sandbox,
                image_ref,
                state_dir.clone(),
                tls_paths,
                overlay_preparation,
            )
            .await
        {
            if err.code() == tonic::Code::Cancelled {
                if overlay_preparation == OverlayPreparation::Fresh {
                    let _ = tokio::fs::remove_dir_all(&state_dir).await;
                }
                return;
            }

            warn!(
                sandbox_id = %sandbox_id,
                error = %err.message(),
                "vm driver: sandbox provisioning failed"
            );
            self.fail_provisioning(
                &sandbox_id,
                &state_dir,
                "ProvisioningFailed",
                err.message(),
                overlay_preparation == OverlayPreparation::Fresh,
            )
            .await;
        }
    }

    #[allow(clippy::result_large_err)]
    async fn provision_sandbox_inner(
        &self,
        sandbox: Sandbox,
        image_ref: String,
        state_dir: PathBuf,
        tls_paths: Option<VmDriverTlsPaths>,
        overlay_preparation: OverlayPreparation,
    ) -> Result<(), Status> {
        self.ensure_provisioning_active(&sandbox.id).await?;
        self.publish_platform_event(
            sandbox.id.clone(),
            platform_event(
                "vm",
                "Normal",
                "ResolvingImage",
                format!("Resolving VM sandbox image \"{image_ref}\""),
            ),
        );

        let image_plan = self.prepare_runtime_images(&sandbox.id, &image_ref).await?;
        let image_identity = image_plan.image_identity.clone();
        self.ensure_provisioning_active(&sandbox.id).await?;
        info!(
            sandbox_id = %sandbox.id,
            image_identity = %image_identity,
            bootstrap_image_identity = %image_plan.bootstrap_image_identity,
            image_disk = image_plan.image_disk.as_ref().map(|path| path.display().to_string()).unwrap_or_default(),
            "vm driver: sandbox root disk plan resolved"
        );
        let disk_paths = sandbox_runtime_disk_paths(&state_dir);
        let root_disk = image_plan.root_disk;
        let image_disk = image_plan.image_disk;
        let overlay_disk = disk_paths.overlay_disk;

        self.publish_platform_event(
            sandbox.id.clone(),
            platform_event(
                "vm",
                "Normal",
                "PreparingOverlay",
                "Preparing writable VM overlay disk".to_string(),
            ),
        );
        if let Err(err) = self
            .prepare_runtime_overlay(&overlay_disk, tls_paths.as_ref(), overlay_preparation)
            .await
        {
            return Err(Status::internal(format!(
                "prepare guest overlay disk failed: {err}"
            )));
        }
        self.ensure_provisioning_active(&sandbox.id).await?;

        if let Err(err) =
            write_sandbox_image_metadata(&state_dir, &image_ref, &image_identity).await
        {
            return Err(Status::internal(format!(
                "write sandbox image metadata failed: {err}"
            )));
        }

        let spec = sandbox.spec.as_ref();
        let is_gpu = spec.is_some_and(|s| s.gpu);
        let gpu_device = spec.map_or("", |s| s.gpu_device.as_str());
        let gpu_bdf = if is_gpu {
            Some(self.assign_gpu_to_record(&sandbox.id, gpu_device).await?)
        } else {
            None
        };

        let console_output = state_dir.join("rootfs-console.log");
        let mut command = Command::new(&self.launcher_bin);
        command.kill_on_drop(true);
        command.stdin(Stdio::null());
        command.stdout(Stdio::inherit());
        command.stderr(Stdio::inherit());
        command.arg("--internal-run-vm");
        command.arg("--vm-root-disk").arg(&root_disk);
        command.arg("--vm-overlay-disk").arg(&overlay_disk);
        if let Some(image_disk) = &image_disk {
            command.arg("--vm-image-disk").arg(image_disk);
        }
        command.arg("--vm-exec").arg(sandbox_guest_init_path());
        command.arg("--vm-workdir").arg("/");
        command.arg("--vm-console-output").arg(&console_output);

        // Compute the endpoint override before building the env so
        // there is a single OPENSHELL_ENDPOINT value in the env list.
        let endpoint_override = if let Some(bdf) = gpu_bdf.as_ref() {
            let subnet = match self
                .subnet_allocator
                .lock()
                .map_err(|e| Status::internal(format!("subnet allocator lock poisoned: {e}")))
                .and_then(|mut alloc| {
                    alloc
                        .allocate(&sandbox.id)
                        .map_err(Status::failed_precondition)
                }) {
                Ok(s) => s,
                Err(err) => {
                    self.release_gpu_and_subnet(&sandbox.id);
                    return Err(err);
                }
            };
            let vsock_cid = allocate_vsock_cid();
            let mac = mac_from_sandbox_id(&sandbox.id);
            let mac_str = format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            );
            let tap = tap_device_name(&sandbox.id);

            let tap_endpoint = guest_visible_openshell_endpoint_for_tap(
                &self.config.openshell_endpoint,
                &subnet.host_ip.to_string(),
            );

            command.arg("--vm-backend").arg("qemu");
            command
                .arg("--vm-vcpus")
                .arg(self.config.gpu_vcpus.to_string());
            command
                .arg("--vm-mem-mib")
                .arg(self.config.gpu_mem_mib.to_string());
            command.arg("--vm-gpu-bdf").arg(bdf);
            command.arg("--vm-tap-device").arg(&tap);
            command
                .arg("--vm-guest-ip")
                .arg(subnet.guest_ip.to_string());
            command.arg("--vm-host-ip").arg(subnet.host_ip.to_string());
            command.arg("--vm-vsock-cid").arg(vsock_cid.to_string());
            command.arg("--vm-guest-mac").arg(&mac_str);

            if let Some(port) = gateway_port_from_endpoint(&self.config.openshell_endpoint) {
                command.arg("--vm-gateway-port").arg(port.to_string());
            }

            Some(tap_endpoint)
        } else {
            command.arg("--vm-vcpus").arg(self.config.vcpus.to_string());
            command
                .arg("--vm-mem-mib")
                .arg(self.config.mem_mib.to_string());
            None
        };
        self.ensure_provisioning_active(&sandbox.id).await?;

        command
            .arg("--vm-krun-log-level")
            .arg(self.config.krun_log_level.to_string());

        for env in build_guest_environment(&sandbox, &self.config, endpoint_override.as_deref()) {
            command.arg("--vm-env").arg(env);
        }

        info!(
            sandbox_id = %sandbox.id,
            launcher = %self.launcher_bin.display(),
            console_output = %console_output.display(),
            "vm driver: spawning VM launcher"
        );
        let child = match command.spawn() {
            Ok(child) => child,
            Err(err) => {
                warn!(
                    sandbox_id = %sandbox.id,
                    error = %err,
                    "vm driver: launcher spawn failed"
                );
                if gpu_bdf.is_some() {
                    self.release_gpu_and_subnet(&sandbox.id);
                }
                return Err(Status::internal(format!(
                    "failed to launch vm helper '{}': {err}",
                    self.launcher_bin.display()
                )));
            }
        };
        info!(
            sandbox_id = %sandbox.id,
            launcher_pid = child.id().unwrap_or(0),
                "vm driver: launcher spawned"
        );
        let process = Arc::new(Mutex::new(VmProcess {
            child,
            deleting: false,
        }));

        let mut process_to_stop = None;
        let mut snapshot_to_publish = None;
        {
            let mut registry = self.registry.lock().await;
            match registry.get_mut(&sandbox.id) {
                Some(record) if !record.deleting => {
                    record.process = Some(process.clone());
                    record.gpu_bdf.clone_from(&gpu_bdf);
                    record.provisioning_task = None;
                    snapshot_to_publish = Some(record.snapshot.clone());
                }
                _ => {
                    process_to_stop = Some(process.clone());
                }
            }
        }

        if let Some(process) = process_to_stop {
            {
                let mut process = process.lock().await;
                process.deleting = true;
                terminate_vm_process(&mut process.child)
                    .await
                    .map_err(|err| Status::internal(format!("failed to stop vm: {err}")))?;
            }
            self.release_gpu_and_subnet(&sandbox.id);
            return Err(Status::cancelled("sandbox provisioning cancelled"));
        }

        self.publish_platform_event(
            sandbox.id.clone(),
            platform_event("vm", "Normal", "Started", "Started VM launcher".to_string()),
        );
        if let Some(snapshot) = snapshot_to_publish {
            self.publish_snapshot(snapshot);
        }
        tokio::spawn({
            let driver = self.clone();
            let sandbox_id = sandbox.id.clone();
            async move {
                driver.monitor_sandbox(sandbox_id).await;
            }
        });

        Ok(())
    }

    pub async fn delete_sandbox(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<DeleteSandboxResponse, Status> {
        if !sandbox_id.is_empty() {
            validate_sandbox_id(sandbox_id)?;
        }

        let record_id = {
            let registry = self.registry.lock().await;
            if let Some((id, _record)) = registry.get_key_value(sandbox_id) {
                Some(id.clone())
            } else {
                registry
                    .iter()
                    .find(|(_, record)| record.snapshot.name == sandbox_name)
                    .map(|(id, _)| id.clone())
            }
        };

        let Some(record_id) = record_id else {
            return Ok(DeleteSandboxResponse { deleted: false });
        };

        let (state_dir, process, gpu_bdf, provisioning_task) = {
            let mut registry = self.registry.lock().await;
            let Some(record) = registry.get_mut(&record_id) else {
                return Ok(DeleteSandboxResponse { deleted: false });
            };
            record.deleting = true;
            (
                record.state_dir.clone(),
                record.process.clone(),
                record.gpu_bdf.clone(),
                record.provisioning_task.take(),
            )
        };

        if let Some(snapshot) = self
            .set_snapshot_condition(&record_id, deleting_condition(), true)
            .await
        {
            self.publish_snapshot(snapshot);
        }

        if let Some(task) = provisioning_task {
            task.abort();
        }

        if let Some(process) = process {
            let mut process = process.lock().await;
            process.deleting = true;
            terminate_vm_process(&mut process.child)
                .await
                .map_err(|err| Status::internal(format!("failed to stop vm: {err}")))?;
        }

        if gpu_bdf.is_some() {
            self.release_gpu_and_subnet(&record_id);
        }

        remove_sandbox_state_dir(&self.config.state_dir, &state_dir).await?;

        {
            let mut registry = self.registry.lock().await;
            registry.remove(&record_id);
        }

        self.publish_deleted(record_id);
        Ok(DeleteSandboxResponse { deleted: true })
    }

    pub async fn get_sandbox(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<Option<Sandbox>, Status> {
        if !sandbox_id.is_empty() {
            validate_sandbox_id(sandbox_id)?;
        }

        let registry = self.registry.lock().await;
        let sandbox = if sandbox_id.is_empty() {
            registry
                .values()
                .find(|record| record.snapshot.name == sandbox_name)
                .map(|record| record.snapshot.clone())
        } else {
            registry
                .get(sandbox_id)
                .map(|record| record.snapshot.clone())
        };
        Ok(sandbox)
    }

    pub async fn current_snapshots(&self) -> Vec<Sandbox> {
        let registry = self.registry.lock().await;
        let mut snapshots = registry
            .values()
            .map(|record| record.snapshot.clone())
            .collect::<Vec<_>>();
        snapshots.sort_by(|left, right| left.name.cmp(&right.name));
        snapshots
    }

    async fn restore_persisted_sandboxes(&self) {
        let state_root = sandboxes_root_dir(&self.config.state_dir);
        let mut entries = match tokio::fs::read_dir(&state_root).await {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return,
            Err(err) => {
                warn!(
                    state_root = %state_root.display(),
                    error = %err,
                    "vm driver: failed to scan persisted sandboxes"
                );
                return;
            }
        };

        loop {
            let entry = match entries.next_entry().await {
                Ok(Some(entry)) => entry,
                Ok(None) => break,
                Err(err) => {
                    warn!(
                        state_root = %state_root.display(),
                        error = %err,
                        "vm driver: failed to continue scanning persisted sandboxes"
                    );
                    break;
                }
            };
            let state_dir = entry.path();
            let is_dir = match entry.file_type().await {
                Ok(file_type) => file_type.is_dir(),
                Err(err) => {
                    warn!(
                        state_dir = %state_dir.display(),
                        error = %err,
                        "vm driver: failed to inspect persisted sandbox state dir"
                    );
                    continue;
                }
            };
            if !is_dir {
                continue;
            }

            let request_path = state_dir.join(SANDBOX_REQUEST_FILE);
            let sandbox = match read_sandbox_request(&request_path).await {
                Ok(sandbox) => sandbox,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => {
                    warn!(
                        state_dir = %state_dir.display(),
                        error = %err,
                        "vm driver: failed to read persisted sandbox request"
                    );
                    continue;
                }
            };

            if let Err(status) =
                validate_restored_sandbox_state(&self.config.state_dir, &state_dir, &sandbox)
            {
                warn!(
                    sandbox_id = %sandbox.id,
                    state_dir = %state_dir.display(),
                    error = %status.message(),
                    "vm driver: ignoring invalid persisted sandbox state"
                );
                continue;
            }

            self.restore_persisted_sandbox(sandbox, state_dir).await;
        }
    }

    async fn restore_persisted_sandbox(&self, sandbox: Sandbox, state_dir: PathBuf) {
        let Some(image_ref) = self.resolved_sandbox_image(&sandbox) else {
            warn!(
                sandbox_id = %sandbox.id,
                sandbox_name = %sandbox.name,
                "vm driver: cannot restore persisted sandbox without image"
            );
            return;
        };
        let tls_paths = match self.config.tls_paths() {
            Ok(paths) => paths,
            Err(err) => {
                warn!(
                    sandbox_id = %sandbox.id,
                    sandbox_name = %sandbox.name,
                    error = %err,
                    "vm driver: cannot restore persisted sandbox TLS configuration"
                );
                return;
            }
        };

        let snapshot = sandbox_snapshot(&sandbox, provisioning_condition(), false);
        {
            let mut registry = self.registry.lock().await;
            if registry.contains_key(&sandbox.id) {
                return;
            }
            registry.insert(
                sandbox.id.clone(),
                SandboxRecord {
                    snapshot: snapshot.clone(),
                    state_dir: state_dir.clone(),
                    process: None,
                    provisioning_task: None,
                    gpu_bdf: None,
                    deleting: false,
                },
            );
        }

        self.publish_platform_event(
            sandbox.id.clone(),
            platform_event(
                "vm",
                "Normal",
                "Restoring",
                "Restoring persisted VM sandbox after driver restart".to_string(),
            ),
        );
        self.publish_snapshot(snapshot);

        let driver = self.clone();
        let sandbox_id = sandbox.id.clone();
        let task = tokio::spawn(async move {
            driver
                .provision_sandbox(
                    sandbox,
                    image_ref,
                    state_dir,
                    tls_paths,
                    OverlayPreparation::PreserveExisting,
                )
                .await;
        });

        let mut registry = self.registry.lock().await;
        if let Some(record) = registry.get_mut(&sandbox_id) {
            if record.deleting {
                task.abort();
            } else {
                record.provisioning_task = Some(task);
            }
        } else {
            task.abort();
        }
    }

    fn release_gpu_and_subnet(&self, sandbox_id: &str) {
        if let Some(inventory) = self.gpu_inventory.as_ref()
            && let Ok(mut inv) = inventory.lock()
        {
            inv.release(sandbox_id);
        }
        if let Ok(mut alloc) = self.subnet_allocator.lock() {
            alloc.release(sandbox_id);
        }
    }

    async fn ensure_provisioning_active(&self, sandbox_id: &str) -> Result<(), Status> {
        let registry = self.registry.lock().await;
        match registry.get(sandbox_id) {
            Some(record) if !record.deleting => Ok(()),
            _ => Err(Status::cancelled("sandbox provisioning cancelled")),
        }
    }

    async fn assign_gpu_to_record(
        &self,
        sandbox_id: &str,
        gpu_device: &str,
    ) -> Result<String, Status> {
        let mut registry = self.registry.lock().await;
        match registry.get_mut(sandbox_id) {
            Some(record) if !record.deleting => {}
            _ => return Err(Status::cancelled("sandbox provisioning cancelled")),
        }

        let inventory = self
            .gpu_inventory
            .as_ref()
            .ok_or_else(|| Status::internal("GPU inventory not initialized"))?;
        let assignment = inventory
            .lock()
            .map_err(|e| Status::internal(format!("GPU inventory lock poisoned: {e}")))?
            .assign(sandbox_id, gpu_device)
            .map_err(Status::failed_precondition)?;

        let record = registry
            .get_mut(sandbox_id)
            .expect("sandbox record exists while registry lock is held");
        record.gpu_bdf = Some(assignment.bdf.clone());
        tracing::info!(
            sandbox_id = %sandbox_id,
            bdf = %assignment.bdf,
            gpu_name = %assignment.name,
            iommu_group = assignment.iommu_group,
            "assigned GPU to sandbox"
        );
        Ok(assignment.bdf)
    }

    async fn fail_provisioning(
        &self,
        sandbox_id: &str,
        state_dir: &Path,
        reason: &str,
        message: &str,
        remove_state: bool,
    ) {
        self.release_gpu_and_subnet(sandbox_id);
        let snapshot = {
            let mut registry = self.registry.lock().await;
            let Some(record) = registry.get_mut(sandbox_id) else {
                return;
            };
            if record.deleting {
                return;
            }
            record.process = None;
            record.provisioning_task = None;
            record.gpu_bdf = None;
            record.snapshot.status = Some(status_with_condition(
                &record.snapshot,
                error_condition(reason, message),
                false,
            ));
            Some(record.snapshot.clone())
        };

        if remove_state {
            let _ = tokio::fs::remove_dir_all(state_dir).await;
        }
        self.publish_platform_event(
            sandbox_id.to_string(),
            platform_event(
                "vm",
                "Warning",
                reason,
                format!("VM provisioning failed: {message}"),
            ),
        );
        if let Some(snapshot) = snapshot {
            self.publish_snapshot(snapshot);
        }
    }

    async fn prepare_runtime_images(
        &self,
        sandbox_id: &str,
        image_ref: &str,
    ) -> Result<RuntimeImagePlan, Status> {
        let bootstrap_image_ref = self.bootstrap_image_ref(image_ref);
        let bootstrap_image_identity = self
            .ensure_cached_bootstrap_rootfs_image(sandbox_id, &bootstrap_image_ref)
            .await?;
        let root_disk = image_cache_rootfs_image(&self.config.state_dir, &bootstrap_image_identity);

        if image_ref.trim() == bootstrap_image_ref.trim() {
            return Ok(RuntimeImagePlan {
                root_disk,
                image_disk: None,
                image_identity: bootstrap_image_identity.clone(),
                bootstrap_image_identity,
            });
        }

        let prepared = self
            .ensure_prepared_image_disk(sandbox_id, image_ref, &root_disk)
            .await?;
        Ok(RuntimeImagePlan {
            root_disk,
            image_disk: Some(prepared.disk_path),
            image_identity: prepared.image_identity,
            bootstrap_image_identity,
        })
    }

    fn bootstrap_image_ref(&self, sandbox_image_ref: &str) -> String {
        let configured = self.config.bootstrap_image.trim();
        if !configured.is_empty() {
            return configured.to_string();
        }
        let default = self.config.default_image.trim();
        if !default.is_empty() {
            return default.to_string();
        }
        sandbox_image_ref.to_string()
    }

    async fn prepare_runtime_overlay(
        &self,
        overlay_disk: &Path,
        tls_paths: Option<&VmDriverTlsPaths>,
        preparation: OverlayPreparation,
    ) -> Result<(), String> {
        let tls_materials = match tls_paths {
            Some(paths) => Some(read_guest_tls_materials(paths).await?),
            None => None,
        };
        let overlay_disk = overlay_disk.to_path_buf();
        let overlay_size_bytes = self
            .config
            .overlay_disk_mib
            .checked_mul(1024 * 1024)
            .ok_or_else(|| {
                format!(
                    "overlay disk size {} MiB is too large",
                    self.config.overlay_disk_mib
                )
            })?;

        let template_path = overlay_template_image(&self.config.state_dir, overlay_size_bytes);
        if !overlay_template_image_ready(&template_path, overlay_size_bytes).await? {
            let _cache_guard = self.image_cache_lock.lock().await;
            let template_path = template_path.clone();
            tokio::task::spawn_blocking(move || {
                ensure_sandbox_overlay_template_image(&template_path, overlay_size_bytes)
            })
            .await
            .map_err(|err| format!("overlay template preparation panicked: {err}"))??;
        }

        tokio::task::spawn_blocking(move || {
            prepare_sandbox_overlay_image(
                &template_path,
                &overlay_disk,
                tls_materials.as_ref(),
                preparation,
                overlay_size_bytes,
            )
        })
        .await
        .map_err(|err| format!("overlay image preparation panicked: {err}"))?
    }

    fn resolved_sandbox_image(&self, sandbox: &Sandbox) -> Option<String> {
        requested_sandbox_image(sandbox)
            .map(ToOwned::to_owned)
            .or_else(|| {
                let image = self.config.default_image.trim();
                (!image.is_empty()).then(|| image.to_string())
            })
    }

    async fn ensure_cached_bootstrap_rootfs_image(
        &self,
        sandbox_id: &str,
        image_ref: &str,
    ) -> Result<String, Status> {
        if let Some((engine, image_identity)) =
            self.resolve_local_container_image(image_ref).await?
        {
            return self
                .ensure_cached_local_image_rootfs_image(
                    sandbox_id,
                    image_ref,
                    &engine,
                    &image_identity,
                )
                .await;
        }

        info!(image_ref = %image_ref, "vm driver: ensuring cached root disk image (registry)");
        let reference = parse_registry_reference(image_ref)?;
        let client = registry_client();
        let auth = registry_auth(image_ref)?;
        info!(image_ref = %image_ref, "vm driver: authenticating with registry");
        self.publish_vm_progress(
            sandbox_id,
            "AuthenticatingRegistry",
            format!("Authenticating registry access for image \"{image_ref}\""),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), "registry".to_string()),
            ]),
        );
        client
            .auth(&reference, &auth, RegistryOperation::Pull)
            .await
            .map_err(|err| {
                Status::failed_precondition(format!(
                    "failed to authenticate registry access for vm sandbox image '{image_ref}': {err}"
                ))
            })?;
        info!(image_ref = %image_ref, "vm driver: fetching manifest digest");
        self.publish_vm_progress(
            sandbox_id,
            "FetchingManifest",
            format!("Fetching manifest for image \"{image_ref}\""),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), "registry".to_string()),
            ]),
        );
        let source_image_identity = client
            .fetch_manifest_digest(&reference, &auth)
            .await
            .map_err(|err| {
                Status::failed_precondition(format!(
                    "failed to resolve vm sandbox image '{image_ref}': {err}"
                ))
            })?;
        info!(
            image_ref = %image_ref,
            image_identity = %source_image_identity,
            "vm driver: manifest digest resolved"
        );
        let image_identity = bootstrap_image_cache_identity(&source_image_identity);
        let image_path = image_cache_rootfs_image(&self.config.state_dir, &image_identity);

        // Emit a driver progress hint for cache hits too and immediately
        // follow with `Pulled` so the image step still advances cleanly.
        self.publish_platform_event(
            sandbox_id.to_string(),
            platform_event(
                "vm",
                "Normal",
                "Pulling",
                format!("Pulling image \"{image_ref}\""),
            ),
        );

        if tokio::fs::metadata(&image_path).await.is_ok() {
            info!(
                image_identity = %image_identity,
                image_path = %image_path.display(),
                "vm driver: root disk image cache hit (no build needed)"
            );
            self.publish_vm_progress(
                sandbox_id,
                "CacheHit",
                format!("Using cached VM root disk for image \"{image_ref}\""),
                HashMap::from([
                    ("image_ref".to_string(), image_ref.to_string()),
                    ("image_source".to_string(), "registry".to_string()),
                    ("cache_hit".to_string(), "true".to_string()),
                    ("image_identity".to_string(), image_identity.clone()),
                ]),
            );
            self.publish_pulled_event(sandbox_id, image_ref, &image_path)
                .await;
            return Ok(image_identity);
        }

        info!(
            image_identity = %image_identity,
            "vm driver: root disk image cache miss, acquiring build lock"
        );
        self.publish_vm_progress(
            sandbox_id,
            "CacheMiss",
            format!("Preparing VM root disk cache for image \"{image_ref}\""),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), "registry".to_string()),
                ("cache_hit".to_string(), "false".to_string()),
                ("image_identity".to_string(), image_identity.clone()),
            ]),
        );
        self.publish_vm_progress(
            sandbox_id,
            "WaitingForImageCacheLock",
            "Waiting for VM image cache build lock".to_string(),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_identity".to_string(), image_identity.clone()),
            ]),
        );
        let _cache_guard = self.image_cache_lock.lock().await;
        info!(
            image_identity = %image_identity,
            "vm driver: build lock acquired"
        );
        if tokio::fs::metadata(&image_path).await.is_ok() {
            info!(
                image_identity = %image_identity,
                "vm driver: root disk image cache hit after lock (built by another task)"
            );
            self.publish_vm_progress(
                sandbox_id,
                "CacheHit",
                format!("Using cached VM root disk for image \"{image_ref}\""),
                HashMap::from([
                    ("image_ref".to_string(), image_ref.to_string()),
                    ("image_source".to_string(), "registry".to_string()),
                    ("cache_hit".to_string(), "true".to_string()),
                    ("image_identity".to_string(), image_identity.clone()),
                ]),
            );
            self.publish_pulled_event(sandbox_id, image_ref, &image_path)
                .await;
            return Ok(image_identity);
        }

        self.build_cached_registry_image_rootfs_image(
            sandbox_id,
            &client,
            &reference,
            &auth,
            image_ref,
            &image_identity,
        )
        .await?;
        self.publish_pulled_event(sandbox_id, image_ref, &image_path)
            .await;
        Ok(image_identity)
    }

    async fn resolve_local_container_image(
        &self,
        image_ref: &str,
    ) -> Result<Option<(Docker, String)>, Status> {
        let required_local_image = is_openshell_local_build_image_ref(image_ref);
        let engine = match connect_local_container_engine().await {
            Some(engine) => engine,
            None if required_local_image => {
                return Err(Status::failed_precondition(format!(
                    "no container engine (Docker/Podman) available for locally built sandbox image '{image_ref}'"
                )));
            }
            None => {
                warn!(
                    image_ref = %image_ref,
                    "vm driver: no local container engine available, falling back to registry"
                );
                return Ok(None);
            }
        };

        match engine.inspect_image(image_ref).await {
            Ok(inspect) => {
                if let Some(message) = local_image_platform_mismatch(
                    image_ref,
                    inspect.os.as_deref(),
                    inspect.architecture.as_deref(),
                ) {
                    if required_local_image {
                        return Err(Status::failed_precondition(message));
                    }
                    warn!(
                        image_ref = %image_ref,
                        %message,
                        "vm driver: local container image platform mismatch, falling back to registry"
                    );
                    return Ok(None);
                }

                let image_identity = inspect.id.filter(|id| !id.trim().is_empty()).ok_or_else(
                    || {
                        Status::failed_precondition(format!(
                            "local container image '{image_ref}' inspect response has no image ID"
                        ))
                    },
                )?;
                info!(
                    image_ref = %image_ref,
                    image_identity = %image_identity,
                    "vm driver: resolved image from local container engine"
                );
                Ok(Some((engine, image_identity)))
            }
            Err(err) if is_docker_not_found_error(&err) && required_local_image => {
                Err(Status::failed_precondition(format!(
                    "locally built sandbox image '{image_ref}' is not present in the local container engine"
                )))
            }
            Err(err) if is_docker_not_found_error(&err) => Ok(None),
            Err(err) if required_local_image => Err(Status::failed_precondition(format!(
                "failed to inspect locally built sandbox image '{image_ref}': {err}"
            ))),
            Err(err) => {
                warn!(
                    image_ref = %image_ref,
                    error = %err,
                    "vm driver: local container image inspection failed, falling back to registry"
                );
                Ok(None)
            }
        }
    }

    async fn ensure_cached_local_image_rootfs_image(
        &self,
        sandbox_id: &str,
        image_ref: &str,
        docker: &Docker,
        image_identity: &str,
    ) -> Result<String, Status> {
        let cache_identity = bootstrap_image_cache_identity(image_identity);
        let image_path = image_cache_rootfs_image(&self.config.state_dir, &cache_identity);

        self.publish_platform_event(
            sandbox_id.to_string(),
            platform_event(
                "vm",
                "Normal",
                "Pulling",
                format!("Pulling image \"{image_ref}\""),
            ),
        );

        if tokio::fs::metadata(&image_path).await.is_ok() {
            self.publish_vm_progress(
                sandbox_id,
                "CacheHit",
                format!("Using cached VM root disk for local image \"{image_ref}\""),
                HashMap::from([
                    ("image_ref".to_string(), image_ref.to_string()),
                    ("image_source".to_string(), "local_docker".to_string()),
                    ("cache_hit".to_string(), "true".to_string()),
                    ("image_identity".to_string(), cache_identity.clone()),
                ]),
            );
            self.publish_pulled_event(sandbox_id, image_ref, &image_path)
                .await;
            return Ok(cache_identity);
        }

        self.publish_vm_progress(
            sandbox_id,
            "CacheMiss",
            format!("Preparing VM root disk cache for local image \"{image_ref}\""),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), "local_docker".to_string()),
                ("cache_hit".to_string(), "false".to_string()),
                ("image_identity".to_string(), cache_identity.clone()),
            ]),
        );
        self.publish_vm_progress(
            sandbox_id,
            "WaitingForImageCacheLock",
            "Waiting for VM image cache build lock".to_string(),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_identity".to_string(), cache_identity.clone()),
            ]),
        );
        let _cache_guard = self.image_cache_lock.lock().await;
        if tokio::fs::metadata(&image_path).await.is_ok() {
            self.publish_vm_progress(
                sandbox_id,
                "CacheHit",
                format!("Using cached VM root disk for local image \"{image_ref}\""),
                HashMap::from([
                    ("image_ref".to_string(), image_ref.to_string()),
                    ("image_source".to_string(), "local_docker".to_string()),
                    ("cache_hit".to_string(), "true".to_string()),
                    ("image_identity".to_string(), cache_identity.clone()),
                ]),
            );
            self.publish_pulled_event(sandbox_id, image_ref, &image_path)
                .await;
            return Ok(cache_identity);
        }

        self.build_cached_local_image_rootfs_image(sandbox_id, docker, image_ref, &cache_identity)
            .await?;
        self.publish_pulled_event(sandbox_id, image_ref, &image_path)
            .await;
        Ok(cache_identity)
    }

    async fn ensure_prepared_image_disk(
        &self,
        sandbox_id: &str,
        image_ref: &str,
        bootstrap_root_disk: &Path,
    ) -> Result<PreparedImageDisk, Status> {
        if let Some((docker, image_identity)) =
            self.resolve_local_container_image(image_ref).await?
        {
            return self
                .ensure_prepared_local_image_disk(
                    sandbox_id,
                    image_ref,
                    &docker,
                    &image_identity,
                    bootstrap_root_disk,
                )
                .await;
        }

        self.ensure_prepared_registry_image_disk(sandbox_id, image_ref, bootstrap_root_disk)
            .await
    }

    async fn ensure_prepared_local_image_disk(
        &self,
        sandbox_id: &str,
        image_ref: &str,
        docker: &Docker,
        image_identity: &str,
        bootstrap_root_disk: &Path,
    ) -> Result<PreparedImageDisk, Status> {
        let cache_identity = prepared_image_cache_identity(image_identity);
        let image_path = image_cache_rootfs_image(&self.config.state_dir, &cache_identity);

        if tokio::fs::metadata(&image_path).await.is_ok() {
            self.publish_prepared_cache_hit(sandbox_id, image_ref, "local_docker", &cache_identity);
            return Ok(PreparedImageDisk {
                image_identity: cache_identity,
                disk_path: image_path,
            });
        }

        self.publish_prepared_cache_miss(sandbox_id, image_ref, "local_docker", &cache_identity);
        let _cache_guard = self.image_cache_lock.lock().await;
        if tokio::fs::metadata(&image_path).await.is_ok() {
            self.publish_prepared_cache_hit(sandbox_id, image_ref, "local_docker", &cache_identity);
            return Ok(PreparedImageDisk {
                image_identity: cache_identity,
                disk_path: image_path,
            });
        }

        let staging_dir = image_cache_staging_dir(&self.config.state_dir, &cache_identity);
        let rootfs_archive = staging_dir.join(IMAGE_EXPORT_ROOTFS_ARCHIVE);
        self.reset_image_staging_dir(&staging_dir).await?;

        self.publish_vm_progress(
            sandbox_id,
            "ExportingRootfs",
            format!("Exporting rootfs from local image \"{image_ref}\""),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), "local_docker".to_string()),
                ("image_identity".to_string(), cache_identity.clone()),
            ]),
        );
        if let Err(err) =
            export_local_image_rootfs_to_path(docker, image_ref, &rootfs_archive).await
        {
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Err(err);
        }

        let payload = GuestImagePayload {
            image_ref: image_ref.to_string(),
            image_identity: cache_identity.clone(),
            source: GuestImagePayloadSource::LocalDocker { rootfs_archive },
        };
        self.build_prepared_image_disk(
            sandbox_id,
            image_ref,
            "local_docker",
            &cache_identity,
            bootstrap_root_disk,
            &staging_dir,
            &payload,
        )
        .await?;

        Ok(PreparedImageDisk {
            image_identity: cache_identity,
            disk_path: image_path,
        })
    }

    async fn ensure_prepared_registry_image_disk(
        &self,
        sandbox_id: &str,
        image_ref: &str,
        bootstrap_root_disk: &Path,
    ) -> Result<PreparedImageDisk, Status> {
        let reference = parse_registry_reference(image_ref)?;
        let client = registry_client();
        let auth = registry_auth(image_ref)?;

        self.publish_vm_progress(
            sandbox_id,
            "AuthenticatingRegistry",
            format!("Authenticating registry access for image \"{image_ref}\""),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), "registry".to_string()),
            ]),
        );
        client
            .auth(&reference, &auth, RegistryOperation::Pull)
            .await
            .map_err(|err| {
                Status::failed_precondition(format!(
                    "failed to authenticate registry access for vm sandbox image '{image_ref}': {err}"
                ))
            })?;

        self.publish_vm_progress(
            sandbox_id,
            "FetchingManifest",
            format!("Fetching manifest for image \"{image_ref}\""),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), "registry".to_string()),
            ]),
        );
        let source_image_identity = client
            .fetch_manifest_digest(&reference, &auth)
            .await
            .map_err(|err| {
                Status::failed_precondition(format!(
                    "failed to resolve vm sandbox image '{image_ref}': {err}"
                ))
            })?;
        let cache_identity = prepared_image_cache_identity(&source_image_identity);
        let image_path = image_cache_rootfs_image(&self.config.state_dir, &cache_identity);

        if tokio::fs::metadata(&image_path).await.is_ok() {
            self.publish_prepared_cache_hit(sandbox_id, image_ref, "registry", &cache_identity);
            return Ok(PreparedImageDisk {
                image_identity: cache_identity,
                disk_path: image_path,
            });
        }

        self.publish_prepared_cache_miss(sandbox_id, image_ref, "registry", &cache_identity);
        let _cache_guard = self.image_cache_lock.lock().await;
        if tokio::fs::metadata(&image_path).await.is_ok() {
            self.publish_prepared_cache_hit(sandbox_id, image_ref, "registry", &cache_identity);
            return Ok(PreparedImageDisk {
                image_identity: cache_identity,
                disk_path: image_path,
            });
        }

        let staging_dir = image_cache_staging_dir(&self.config.state_dir, &cache_identity);
        self.reset_image_staging_dir(&staging_dir).await?;
        let layout_dir = staging_dir.join(GUEST_IMAGE_OCI_LAYOUT_DIR);

        let (manifest, _) = client
            .pull_image_manifest(&reference, &auth)
            .await
            .map_err(|err| {
                Status::failed_precondition(format!(
                    "failed to pull vm sandbox image manifest '{image_ref}': {err}"
                ))
            })?;
        tokio::fs::create_dir_all(oci_layout_blobs_dir(&layout_dir))
            .await
            .map_err(|err| Status::internal(format!("create guest OCI layout failed: {err}")))?;

        download_registry_descriptor_blob_file(
            &client,
            &reference,
            image_ref,
            &layout_dir,
            &manifest.config,
            "config",
        )
        .await?;

        let total_layers = manifest.layers.len();
        let total_bytes: i64 = manifest.layers.iter().map(|layer| layer.size.max(0)).sum();
        futures::stream::iter(manifest.layers.iter().cloned().enumerate())
            .map(|(index, layer)| {
                let client = client.clone();
                let reference = reference.clone();
                let layout_dir = layout_dir.clone();
                async move {
                    self.publish_registry_layer_progress(
                        sandbox_id,
                        image_ref,
                        &layer,
                        index,
                        total_layers,
                        total_bytes,
                    );
                    download_registry_descriptor_blob_file(
                        &client,
                        &reference,
                        image_ref,
                        &layout_dir,
                        &layer,
                        &format!("layer {}", index + 1),
                    )
                    .await
                }
            })
            .buffer_unordered(registry_layer_download_concurrency())
            .try_collect::<Vec<_>>()
            .await?;

        write_oci_layout_for_manifest(&layout_dir, GUEST_IMAGE_OCI_REF, &manifest)
            .map_err(|err| Status::internal(format!("write OCI layout failed: {err}")))?;

        let payload = GuestImagePayload {
            image_ref: image_ref.to_string(),
            image_identity: cache_identity.clone(),
            source: GuestImagePayloadSource::RegistryOciLayout { layout_dir },
        };
        self.build_prepared_image_disk(
            sandbox_id,
            image_ref,
            "registry",
            &cache_identity,
            bootstrap_root_disk,
            &staging_dir,
            &payload,
        )
        .await?;

        Ok(PreparedImageDisk {
            image_identity: cache_identity,
            disk_path: image_path,
        })
    }

    async fn reset_image_staging_dir(&self, staging_dir: &Path) -> Result<(), Status> {
        tokio::fs::create_dir_all(image_cache_root_dir(&self.config.state_dir))
            .await
            .map_err(|err| Status::internal(format!("create image cache dir failed: {err}")))?;
        if tokio::fs::metadata(staging_dir).await.is_ok() {
            tokio::fs::remove_dir_all(staging_dir)
                .await
                .map_err(|err| {
                    Status::internal(format!(
                        "remove stale image cache staging dir failed: {err}"
                    ))
                })?;
        }
        tokio::fs::create_dir_all(staging_dir).await.map_err(|err| {
            Status::internal(format!("create image cache staging dir failed: {err}"))
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn build_prepared_image_disk(
        &self,
        sandbox_id: &str,
        image_ref: &str,
        image_source: &str,
        image_identity: &str,
        bootstrap_root_disk: &Path,
        staging_dir: &Path,
        payload: &GuestImagePayload,
    ) -> Result<(), Status> {
        let cache_dir = image_cache_dir(&self.config.state_dir, image_identity);
        let image_path = image_cache_rootfs_image(&self.config.state_dir, image_identity);
        let prepared_image = staging_dir.join(IMAGE_CACHE_ROOTFS_IMAGE);
        tokio::fs::create_dir_all(&cache_dir).await.map_err(|err| {
            Status::internal(format!("create prepared image cache dir failed: {err}"))
        })?;

        let payload_for_size = payload.clone();
        let min_size = self
            .config
            .overlay_disk_mib
            .checked_mul(1024 * 1024)
            .ok_or_else(|| Status::internal("prepared image disk size overflow"))?;
        let image_size = tokio::task::spawn_blocking(move || {
            prepared_image_disk_size_bytes(&payload_for_size, min_size)
        })
        .await
        .map_err(|err| {
            Status::internal(format!("prepared image size calculation panicked: {err}"))
        })?
        .map_err(Status::internal)?;

        let payload_for_disk = payload.clone();
        let prepared_image_for_disk = prepared_image.clone();
        self.publish_vm_progress(
            sandbox_id,
            "CreatingRootDisk",
            "Formatting prepared VM image disk".to_string(),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), image_source.to_string()),
                ("image_identity".to_string(), image_identity.to_string()),
            ]),
        );
        tokio::task::spawn_blocking(move || {
            create_image_prep_disk(&prepared_image_for_disk, image_size, &payload_for_disk)
        })
        .await
        .map_err(|err| Status::internal(format!("prepared image disk build panicked: {err}")))?
        .map_err(Status::failed_precondition)?;

        self.publish_vm_progress(
            sandbox_id,
            "PreparingRootfs",
            format!("Preparing VM image rootfs for \"{image_ref}\""),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), image_source.to_string()),
                ("image_identity".to_string(), image_identity.to_string()),
            ]),
        );
        if let Err(err) = self
            .run_image_prep_vm(bootstrap_root_disk, &prepared_image, staging_dir)
            .await
        {
            let _ = tokio::fs::remove_dir_all(staging_dir).await;
            return Err(err);
        }

        if tokio::fs::metadata(&image_path).await.is_ok() {
            let _ = tokio::fs::remove_dir_all(staging_dir).await;
            return Ok(());
        }
        tokio::fs::rename(&prepared_image, &image_path)
            .await
            .map_err(|err| Status::internal(format!("store prepared image disk failed: {err}")))?;
        let _ = tokio::fs::remove_dir_all(staging_dir).await;
        Ok(())
    }

    async fn run_image_prep_vm(
        &self,
        bootstrap_root_disk: &Path,
        prep_disk: &Path,
        run_dir: &Path,
    ) -> Result<(), Status> {
        let console_output = run_dir.join("image-prep-console.log");
        let mut command = Command::new(&self.launcher_bin);
        command.kill_on_drop(true);
        command.stdin(Stdio::null());
        command.stdout(Stdio::inherit());
        command.stderr(Stdio::inherit());
        command.arg("--internal-run-vm");
        command.arg("--vm-root-disk").arg(bootstrap_root_disk);
        command.arg("--vm-overlay-disk").arg(prep_disk);
        command.arg("--vm-exec").arg(sandbox_guest_init_path());
        command.arg("--vm-workdir").arg("/");
        command.arg("--vm-console-output").arg(&console_output);
        command.arg("--vm-vcpus").arg(self.config.vcpus.to_string());
        command
            .arg("--vm-mem-mib")
            .arg(self.config.mem_mib.to_string());
        command
            .arg("--vm-krun-log-level")
            .arg(self.config.krun_log_level.to_string());
        command
            .arg("--vm-env")
            .arg(format!("OPENSHELL_VM_INIT_MODE={IMAGE_PREP_INIT_MODE}"));

        let mut child = command
            .spawn()
            .map_err(|err| Status::internal(format!("failed to run image-prep vm: {err}")))?;
        let status = child
            .wait()
            .await
            .map_err(|err| Status::internal(format!("failed to wait for image-prep vm: {err}")))?;
        if status.success() {
            return Ok(());
        }
        let console = tokio::fs::read_to_string(&console_output)
            .await
            .unwrap_or_default();
        Err(Status::failed_precondition(format!(
            "image-prep vm exited with status {status}: {console}"
        )))
    }

    fn publish_prepared_cache_hit(
        &self,
        sandbox_id: &str,
        image_ref: &str,
        image_source: &str,
        image_identity: &str,
    ) {
        self.publish_vm_progress(
            sandbox_id,
            "CacheHit",
            format!("Using cached prepared VM image disk for \"{image_ref}\""),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), image_source.to_string()),
                ("cache_hit".to_string(), "true".to_string()),
                ("image_identity".to_string(), image_identity.to_string()),
            ]),
        );
    }

    fn publish_prepared_cache_miss(
        &self,
        sandbox_id: &str,
        image_ref: &str,
        image_source: &str,
        image_identity: &str,
    ) {
        self.publish_vm_progress(
            sandbox_id,
            "CacheMiss",
            format!("Preparing VM image disk cache for \"{image_ref}\""),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), image_source.to_string()),
                ("cache_hit".to_string(), "false".to_string()),
                ("image_identity".to_string(), image_identity.to_string()),
            ]),
        );
    }

    async fn build_cached_local_image_rootfs_image(
        &self,
        sandbox_id: &str,
        docker: &Docker,
        image_ref: &str,
        image_identity: &str,
    ) -> Result<(), Status> {
        let cache_dir = image_cache_dir(&self.config.state_dir, image_identity);
        let image_path = image_cache_rootfs_image(&self.config.state_dir, image_identity);
        let staging_dir = image_cache_staging_dir(&self.config.state_dir, image_identity);
        let exported_rootfs = staging_dir.join(IMAGE_EXPORT_ROOTFS_ARCHIVE);
        let prepared_rootfs = staging_dir.join("rootfs");
        let prepared_image = staging_dir.join(IMAGE_CACHE_ROOTFS_IMAGE);

        tokio::fs::create_dir_all(image_cache_root_dir(&self.config.state_dir))
            .await
            .map_err(|err| Status::internal(format!("create image cache dir failed: {err}")))?;
        tokio::fs::create_dir_all(&cache_dir)
            .await
            .map_err(|err| Status::internal(format!("create image cache dir failed: {err}")))?;

        if tokio::fs::metadata(&staging_dir).await.is_ok() {
            tokio::fs::remove_dir_all(&staging_dir)
                .await
                .map_err(|err| {
                    Status::internal(format!(
                        "remove stale image cache staging dir failed: {err}"
                    ))
                })?;
        }
        tokio::fs::create_dir_all(&staging_dir)
            .await
            .map_err(|err| {
                Status::internal(format!("create image cache staging dir failed: {err}"))
            })?;

        self.publish_vm_progress(
            sandbox_id,
            "ExportingRootfs",
            format!("Exporting rootfs from local image \"{image_ref}\""),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), "local_docker".to_string()),
                ("image_identity".to_string(), image_identity.to_string()),
            ]),
        );
        if let Err(err) =
            export_local_image_rootfs_to_path(docker, image_ref, &exported_rootfs).await
        {
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Err(err);
        }

        let image_ref_owned = image_ref.to_string();
        let image_identity_owned = image_identity.to_string();
        let exported_rootfs_for_build = exported_rootfs.clone();
        let prepared_rootfs_for_build = prepared_rootfs.clone();
        self.publish_vm_progress(
            sandbox_id,
            "PreparingRootfs",
            format!("Preparing VM rootfs for local image \"{image_ref}\""),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), "local_docker".to_string()),
                ("image_identity".to_string(), image_identity.to_string()),
            ]),
        );
        let prepare_result = tokio::task::spawn_blocking(move || {
            extract_rootfs_archive_to(&exported_rootfs_for_build, &prepared_rootfs_for_build)?;
            prepare_sandbox_rootfs_from_image_root(
                &prepared_rootfs_for_build,
                &image_identity_owned,
            )
            .map_err(|err| {
                format!("vm sandbox image '{image_ref_owned}' is not base-compatible: {err}")
            })
        })
        .await
        .map_err(|err| Status::internal(format!("local image preparation panicked: {err}")))?;

        if let Err(err) = prepare_result {
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Err(Status::failed_precondition(err));
        }

        self.publish_vm_progress(
            sandbox_id,
            "CreatingRootDisk",
            "Formatting VM root disk image".to_string(),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), "local_docker".to_string()),
                ("image_identity".to_string(), image_identity.to_string()),
            ]),
        );
        let prepared_rootfs_for_build = prepared_rootfs.clone();
        let prepared_image_for_build = prepared_image.clone();
        let build_result = tokio::task::spawn_blocking(move || {
            create_rootfs_image_from_dir(&prepared_rootfs_for_build, &prepared_image_for_build)
        })
        .await
        .map_err(|err| Status::internal(format!("rootfs image build panicked: {err}")))?;

        if let Err(err) = build_result {
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Err(Status::failed_precondition(err));
        }

        if tokio::fs::metadata(&image_path).await.is_ok() {
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Ok(());
        }

        tokio::fs::rename(&prepared_image, &image_path)
            .await
            .map_err(|err| Status::internal(format!("store cached rootfs image failed: {err}")))?;
        let _ = tokio::fs::remove_dir_all(&staging_dir).await;
        Ok(())
    }

    async fn build_cached_registry_image_rootfs_image(
        &self,
        sandbox_id: &str,
        client: &OciClient,
        reference: &Reference,
        auth: &RegistryAuth,
        image_ref: &str,
        image_identity: &str,
    ) -> Result<(), Status> {
        let cache_dir = image_cache_dir(&self.config.state_dir, image_identity);
        let image_path = image_cache_rootfs_image(&self.config.state_dir, image_identity);
        let staging_dir = image_cache_staging_dir(&self.config.state_dir, image_identity);
        let prepared_rootfs = staging_dir.join("rootfs");
        let prepared_image = staging_dir.join(IMAGE_CACHE_ROOTFS_IMAGE);

        tokio::fs::create_dir_all(image_cache_root_dir(&self.config.state_dir))
            .await
            .map_err(|err| Status::internal(format!("create image cache dir failed: {err}")))?;
        tokio::fs::create_dir_all(&cache_dir)
            .await
            .map_err(|err| Status::internal(format!("create image cache dir failed: {err}")))?;

        if tokio::fs::metadata(&staging_dir).await.is_ok() {
            tokio::fs::remove_dir_all(&staging_dir)
                .await
                .map_err(|err| {
                    Status::internal(format!(
                        "remove stale image cache staging dir failed: {err}"
                    ))
                })?;
        }
        tokio::fs::create_dir_all(&staging_dir)
            .await
            .map_err(|err| {
                Status::internal(format!("create image cache staging dir failed: {err}"))
            })?;

        info!(
            image_ref = %image_ref,
            staging_dir = %staging_dir.display(),
            "vm driver: pulling registry image layers"
        );
        if let Err(err) = self
            .pull_registry_image_rootfs(
                sandbox_id,
                client,
                reference,
                auth,
                image_ref,
                &staging_dir,
                &prepared_rootfs,
            )
            .await
        {
            warn!(
                image_ref = %image_ref,
                error = %err.message(),
                "vm driver: pull_registry_image_rootfs failed"
            );
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Err(err);
        }
        info!(
            image_ref = %image_ref,
            "vm driver: image layers pulled, preparing rootfs image"
        );

        let image_ref_owned = image_ref.to_string();
        let image_identity_owned = image_identity.to_string();
        let prepared_rootfs_for_build = prepared_rootfs.clone();
        self.publish_vm_progress(
            sandbox_id,
            "PreparingRootfs",
            format!("Preparing VM rootfs for image \"{image_ref}\""),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), "registry".to_string()),
                ("image_identity".to_string(), image_identity.to_string()),
            ]),
        );
        let prepare_result = tokio::task::spawn_blocking(move || {
            prepare_sandbox_rootfs_from_image_root(
                &prepared_rootfs_for_build,
                &image_identity_owned,
            )
            .map_err(|err| {
                format!("vm sandbox image '{image_ref_owned}' is not base-compatible: {err}")
            })
        })
        .await
        .map_err(|err| Status::internal(format!("image rootfs preparation panicked: {err}")))?;

        if let Err(err) = prepare_result {
            warn!(
                image_ref = %image_ref,
                error = %err,
                "vm driver: rootfs preparation failed"
            );
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Err(Status::failed_precondition(err));
        }

        self.publish_vm_progress(
            sandbox_id,
            "CreatingRootDisk",
            "Formatting VM root disk image".to_string(),
            HashMap::from([
                ("image_ref".to_string(), image_ref.to_string()),
                ("image_source".to_string(), "registry".to_string()),
                ("image_identity".to_string(), image_identity.to_string()),
            ]),
        );
        let prepared_rootfs_for_build = prepared_rootfs.clone();
        let prepared_image_for_build = prepared_image.clone();
        let build_result = tokio::task::spawn_blocking(move || {
            create_rootfs_image_from_dir(&prepared_rootfs_for_build, &prepared_image_for_build)
        })
        .await
        .map_err(|err| Status::internal(format!("image rootfs build panicked: {err}")))?;

        if let Err(err) = build_result {
            warn!(
                image_ref = %image_ref,
                error = %err,
                "vm driver: rootfs image build failed"
            );
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Err(Status::failed_precondition(err));
        }

        if tokio::fs::metadata(&image_path).await.is_ok() {
            info!(
                image_identity = %image_identity,
                "vm driver: another task wrote image while we were building, discarding ours"
            );
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Ok(());
        }

        tokio::fs::rename(&prepared_image, &image_path)
            .await
            .map_err(|err| Status::internal(format!("store cached rootfs image failed: {err}")))?;
        info!(
            image_identity = %image_identity,
            image_path = %image_path.display(),
            "vm driver: root disk image committed to cache"
        );
        let _ = tokio::fs::remove_dir_all(&staging_dir).await;
        Ok(())
    }

    /// Watch the launcher child process and surface errors as driver
    /// conditions.
    ///
    /// The driver no longer owns the `Ready` transition — the gateway
    /// promotes a sandbox to `Ready` the moment its supervisor session
    /// lands (see `openshell-server/src/compute/mod.rs`). This loop only
    /// handles the sad paths: the child process failing to start, exiting
    /// abnormally, or becoming unpollable. Those still surface as driver
    /// `Error` conditions so the gateway can reason about a dead VM.
    async fn monitor_sandbox(&self, sandbox_id: String) {
        loop {
            let process = {
                let registry = self.registry.lock().await;
                let Some(record) = registry.get(&sandbox_id) else {
                    return;
                };
                let Some(process) = record.process.as_ref() else {
                    return;
                };
                process.clone()
            };

            let exit_status = {
                let mut process = process.lock().await;
                if process.deleting {
                    return;
                }
                match process.child.try_wait() {
                    Ok(status) => status,
                    Err(err) => {
                        if let Some(snapshot) = self
                            .set_snapshot_condition(
                                &sandbox_id,
                                error_condition("ProcessPollFailed", &err.to_string()),
                                false,
                            )
                            .await
                        {
                            self.publish_snapshot(snapshot);
                        }
                        self.publish_platform_event(
                            sandbox_id.clone(),
                            platform_event(
                                "vm",
                                "Warning",
                                "ProcessPollFailed",
                                format!("Failed to poll VM helper process: {err}"),
                            ),
                        );
                        return;
                    }
                }
            };

            if let Some(status) = exit_status {
                let message = status.code().map_or_else(
                    || "VM process exited".to_string(),
                    |code| format!("VM process exited with status {code}"),
                );
                if let Some(snapshot) = self
                    .set_snapshot_condition(
                        &sandbox_id,
                        error_condition("ProcessExited", &message),
                        false,
                    )
                    .await
                {
                    self.publish_snapshot(snapshot);
                }
                self.publish_platform_event(
                    sandbox_id.clone(),
                    platform_event("vm", "Warning", "ProcessExited", message),
                );
                let has_gpu = {
                    let registry = self.registry.lock().await;
                    registry
                        .get(&sandbox_id)
                        .and_then(|r| r.gpu_bdf.as_ref())
                        .is_some()
                };
                if has_gpu {
                    self.release_gpu_and_subnet(&sandbox_id);
                }
                return;
            }

            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    async fn set_snapshot_condition(
        &self,
        sandbox_id: &str,
        condition: SandboxCondition,
        deleting: bool,
    ) -> Option<Sandbox> {
        let mut registry = self.registry.lock().await;
        let record = registry.get_mut(sandbox_id)?;
        record.snapshot.status = Some(status_with_condition(&record.snapshot, condition, deleting));
        Some(record.snapshot.clone())
    }

    fn publish_snapshot(&self, sandbox: Sandbox) {
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

    fn publish_platform_event(&self, sandbox_id: String, event: PlatformEvent) {
        let _ = self.events.send(WatchSandboxesEvent {
            payload: Some(watch_sandboxes_event::Payload::PlatformEvent(
                WatchSandboxesPlatformEvent {
                    sandbox_id,
                    event: Some(event),
                },
            )),
        });
    }

    fn publish_vm_progress(
        &self,
        sandbox_id: &str,
        reason: &str,
        message: String,
        metadata: HashMap<String, String>,
    ) {
        let mut event = platform_event("vm", "Normal", reason, message);
        event.metadata = metadata;
        attach_vm_progress_metadata(&mut event);
        self.publish_platform_event(sandbox_id.to_string(), event);
    }
}

#[tonic::async_trait]
impl ComputeDriver for VmDriver {
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

    async fn create_sandbox(
        &self,
        request: Request<CreateSandboxRequest>,
    ) -> Result<Response<CreateSandboxResponse>, Status> {
        let sandbox = request
            .into_inner()
            .sandbox
            .ok_or_else(|| Status::invalid_argument("sandbox is required"))?;
        let response = self.create_sandbox(&sandbox).await?;
        Ok(Response::new(response))
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
            .get_sandbox(&request.sandbox_id, &request.sandbox_name)
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
            sandboxes: self.current_snapshots().await,
        }))
    }

    async fn stop_sandbox(
        &self,
        _request: Request<StopSandboxRequest>,
    ) -> Result<Response<StopSandboxResponse>, Status> {
        Err(Status::unimplemented(
            "stop sandbox is not implemented by the vm compute driver",
        ))
    }

    async fn delete_sandbox(
        &self,
        request: Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        let request = request.into_inner();
        let response = self
            .delete_sandbox(&request.sandbox_id, &request.sandbox_name)
            .await?;
        Ok(Response::new(response))
    }

    type WatchSandboxesStream =
        Pin<Box<dyn Stream<Item = Result<WatchSandboxesEvent, Status>> + Send + 'static>>;

    async fn watch_sandboxes(
        &self,
        _request: Request<WatchSandboxesRequest>,
    ) -> Result<Response<Self::WatchSandboxesStream>, Status> {
        let initial = self.current_snapshots().await;
        let mut rx = self.events.subscribe();
        let (tx, out_rx) = mpsc::channel(WATCH_BUFFER);
        tokio::spawn(async move {
            let mut sent = HashSet::new();
            for sandbox in initial {
                sent.insert(sandbox.id.clone());
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
                        if let Some(watch_sandboxes_event::Payload::Sandbox(sandbox_event)) =
                            &event.payload
                            && let Some(sandbox) = &sandbox_event.sandbox
                            && !sent.insert(sandbox.id.clone())
                        {
                            // duplicate snapshots are still forwarded
                        }
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

#[cfg(target_os = "linux")]
#[allow(unsafe_code)] // libc::geteuid is a thin syscall wrapper
fn check_gpu_privileges() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(
            "GPU support requires root privileges for VFIO bind/unbind and TAP networking. \
             Run with sudo or ensure CAP_SYS_ADMIN + CAP_NET_ADMIN capabilities are set."
                .to_string(),
        );
    }
    Ok(())
}

// `tonic::Status` is ~176 bytes; it's the standard error type across the
// gRPC API surface, so boxing here would diverge from every other handler.
#[allow(clippy::result_large_err)]
fn validate_vm_sandbox(sandbox: &Sandbox, gpu_enabled: bool) -> Result<(), Status> {
    validate_sandbox_id(&sandbox.id)?;

    let spec = sandbox
        .spec
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("sandbox spec is required"))?;

    if spec.gpu && !gpu_enabled {
        return Err(Status::failed_precondition(
            "GPU support is not enabled on this driver; start with --gpu",
        ));
    }

    if !spec.gpu && !spec.gpu_device.is_empty() {
        return Err(Status::invalid_argument("gpu_device requires gpu=true"));
    }

    if let Some(template) = spec.template.as_ref() {
        if !template.agent_socket_path.is_empty() {
            return Err(Status::failed_precondition(
                "vm sandboxes do not support template.agent_socket_path",
            ));
        }
        if template.platform_config.is_some() {
            return Err(Status::failed_precondition(
                "vm sandboxes do not support template.platform_config",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::result_large_err)]
fn validate_sandbox_id(sandbox_id: &str) -> Result<(), Status> {
    if sandbox_id.is_empty() {
        return Err(Status::invalid_argument("sandbox id is required"));
    }
    if sandbox_id.len() > 128 {
        return Err(Status::invalid_argument(
            "sandbox id exceeds maximum length (128 bytes)",
        ));
    }
    if matches!(sandbox_id, "." | "..") {
        return Err(Status::invalid_argument(
            "sandbox id must match [A-Za-z0-9._-]{1,128}",
        ));
    }
    if !sandbox_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(Status::invalid_argument(
            "sandbox id must match [A-Za-z0-9._-]{1,128}",
        ));
    }
    Ok(())
}

#[allow(clippy::result_large_err)]
fn parse_registry_reference(image_ref: &str) -> Result<Reference, Status> {
    Reference::try_from(image_ref).map_err(|err| {
        Status::failed_precondition(format!(
            "invalid vm sandbox image reference '{image_ref}': {err}"
        ))
    })
}

/// Try to connect to a local container engine (Docker or Podman).
///
/// Tries Docker first (`connect_with_local_defaults`, which respects
/// `DOCKER_HOST`). If Docker is unavailable, falls back to the Podman
/// socket, which exposes a Docker-compatible API.
async fn connect_local_container_engine() -> Option<Docker> {
    if let Ok(docker) = Docker::connect_with_local_defaults()
        && docker.ping().await.is_ok()
    {
        return Some(docker);
    }

    let podman_socket = podman_socket_path();
    if podman_socket.exists()
        && let Ok(docker) =
            Docker::connect_with_unix(podman_socket.to_str()?, 120, bollard::API_DEFAULT_VERSION)
        && docker.ping().await.is_ok()
    {
        info!(
            socket = %podman_socket.display(),
            "vm driver: connected to Podman (Docker-compatible API)"
        );
        return Some(docker);
    }

    None
}

/// Podman user socket path for the current platform.
fn podman_socket_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_default();
        PathBuf::from(home).join(".local/share/containers/podman/machine/podman.sock")
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var("XDG_RUNTIME_DIR").map_or_else(
            |_| {
                let uid = nix::unistd::getuid();
                PathBuf::from(format!("/run/user/{uid}/podman/podman.sock"))
            },
            |xdg| PathBuf::from(xdg).join("podman/podman.sock"),
        )
    }
}

fn is_openshell_local_build_image_ref(image_ref: &str) -> bool {
    image_ref.starts_with("openshell/sandbox-from:")
}

fn local_image_platform_mismatch(
    image_ref: &str,
    actual_os: Option<&str>,
    actual_arch: Option<&str>,
) -> Option<String> {
    let actual_os = actual_os.unwrap_or("unknown");
    let actual_arch = actual_arch.unwrap_or("unknown");
    let expected_os = "linux";
    let expected_arch = linux_oci_arch();

    (actual_os != expected_os || actual_arch != expected_arch).then(|| {
        format!(
            "local Docker image '{image_ref}' is {actual_os}/{actual_arch}, but VM sandboxes require {expected_os}/{expected_arch}"
        )
    })
}

fn is_docker_not_found_error(err: &BollardError) -> bool {
    matches!(
        err,
        BollardError::DockerResponseServerError {
            status_code: 404,
            ..
        }
    )
}

async fn export_local_image_rootfs_to_path(
    docker: &Docker,
    image_ref: &str,
    tar_path: &Path,
) -> Result<(), Status> {
    let container_name = format!(
        "openshell-vm-rootfs-export-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let create_options = CreateContainerOptionsBuilder::default()
        .name(container_name.as_str())
        .build();
    let container = docker
        .create_container(
            Some(create_options),
            ContainerCreateBody {
                image: Some(image_ref.to_string()),
                ..Default::default()
            },
        )
        .await
        .map_err(|err| {
            Status::failed_precondition(format!(
                "failed to create temporary export container for local Docker image '{image_ref}': {err}"
            ))
        })?;
    let container_id = container.id;

    let export_result = async {
        if let Some(parent) = tar_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|err| {
                Status::internal(format!(
                    "create export dir {} failed: {err}",
                    parent.display()
                ))
            })?;
        }
        let mut file = tokio::fs::File::create(tar_path).await.map_err(|err| {
            Status::internal(format!("create {} failed: {err}", tar_path.display()))
        })?;
        let mut stream = docker.export_container(&container_id);
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|err| {
                Status::failed_precondition(format!(
                    "failed to export local Docker image '{image_ref}': {err}"
                ))
            })?;
            file.write_all(&chunk).await.map_err(|err| {
                Status::internal(format!("write {} failed: {err}", tar_path.display()))
            })?;
        }
        file.flush()
            .await
            .map_err(|err| Status::internal(format!("flush {} failed: {err}", tar_path.display())))
    }
    .await;

    let cleanup_result = docker
        .remove_container(
            &container_id,
            Some(RemoveContainerOptionsBuilder::default().force(true).build()),
        )
        .await;

    match (export_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(err), _) => Err(err),
        (Ok(()), Err(err)) => Err(Status::internal(format!(
            "failed to remove temporary export container for local Docker image '{image_ref}': {err}"
        ))),
    }
}

fn registry_client() -> OciClient {
    OciClient::new(ClientConfig {
        platform_resolver: Some(Box::new(linux_platform_resolver)),
        ..Default::default()
    })
}

fn linux_platform_resolver(manifests: &[ImageIndexEntry]) -> Option<String> {
    let expected_arch = linux_oci_arch();
    manifests
        .iter()
        .find_map(|entry| {
            let platform = entry.platform.as_ref()?;
            (platform.os.to_string() == "linux"
                && platform.architecture.to_string() == expected_arch)
                .then(|| entry.digest.clone())
        })
        .or_else(|| {
            manifests.iter().find_map(|entry| {
                let platform = entry.platform.as_ref()?;
                (platform.os.to_string() == "linux").then(|| entry.digest.clone())
            })
        })
}

fn linux_oci_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "arm" => "arm",
        other => other,
    }
}

#[allow(clippy::result_large_err)]
fn registry_auth(image_ref: &str) -> Result<RegistryAuth, Status> {
    let username = env_non_empty("OPENSHELL_REGISTRY_USERNAME");
    let token = env_non_empty("OPENSHELL_REGISTRY_TOKEN");

    match token {
        Some(token) => {
            let username = match username {
                Some(username) => username,
                None if image_reference_registry_host(image_ref)
                    .eq_ignore_ascii_case("ghcr.io") =>
                {
                    "__token__".to_string()
                }
                None => {
                    return Err(Status::failed_precondition(
                        "OPENSHELL_REGISTRY_USERNAME is required when OPENSHELL_REGISTRY_TOKEN is set for non-GHCR registries",
                    ));
                }
            };
            Ok(RegistryAuth::Basic(username, token))
        }
        None => Ok(RegistryAuth::Anonymous),
    }
}

fn env_non_empty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn image_reference_registry_host(image_ref: &str) -> &str {
    let mut parts = image_ref.splitn(2, '/');
    let first = parts.next().unwrap_or(image_ref);
    let has_path = parts.next().is_some();
    if has_path
        && (first.contains('.') || first.contains(':') || first.eq_ignore_ascii_case("localhost"))
    {
        first
    } else {
        "docker.io"
    }
}

impl VmDriver {
    #[allow(clippy::too_many_arguments)]
    async fn pull_registry_image_rootfs(
        &self,
        sandbox_id: &str,
        client: &OciClient,
        reference: &Reference,
        auth: &RegistryAuth,
        image_ref: &str,
        staging_dir: &Path,
        rootfs: &Path,
    ) -> Result<(), Status> {
        client
            .auth(reference, auth, RegistryOperation::Pull)
            .await
            .map_err(|err| {
                Status::failed_precondition(format!(
                    "failed to authenticate registry access for vm sandbox image '{image_ref}': {err}"
                ))
            })?;
        let (manifest, _) = client
            .pull_image_manifest(reference, auth)
            .await
            .map_err(|err| {
                Status::failed_precondition(format!(
                    "failed to pull vm sandbox image manifest '{image_ref}': {err}"
                ))
            })?;

        tokio::fs::create_dir_all(rootfs)
            .await
            .map_err(|err| Status::internal(format!("create rootfs dir failed: {err}")))?;
        tokio::fs::create_dir_all(staging_dir.join("layers"))
            .await
            .map_err(|err| Status::internal(format!("create layer staging dir failed: {err}")))?;

        let total_layers = manifest.layers.len();
        let total_bytes: i64 = manifest.layers.iter().map(|layer| layer.size.max(0)).sum();
        let mut layers = futures::stream::iter(manifest.layers.iter().cloned().enumerate())
            .map(|(index, layer)| async move {
                self.publish_registry_layer_progress(
                    sandbox_id,
                    image_ref,
                    &layer,
                    index,
                    total_layers,
                    total_bytes,
                );
                download_registry_layer_blob(
                    client,
                    reference,
                    image_ref,
                    staging_dir,
                    layer,
                    index,
                )
                .await
            })
            .buffer_unordered(registry_layer_download_concurrency())
            .try_collect::<Vec<_>>()
            .await?;
        layers.sort_by_key(|layer| layer.index);

        for layer in &layers {
            apply_registry_layer_blob(image_ref, rootfs, layer).await?;
        }

        Ok(())
    }

    fn publish_registry_layer_progress(
        &self,
        sandbox_id: &str,
        image_ref: &str,
        layer: &OciDescriptor,
        index: usize,
        total_layers: usize,
        total_bytes: i64,
    ) {
        let mut metadata = HashMap::new();
        metadata.insert("layer_index".to_string(), (index + 1).to_string());
        metadata.insert("layer_total".to_string(), total_layers.to_string());
        metadata.insert("layer_digest".to_string(), layer.digest.clone());
        metadata.insert("layer_size_bytes".to_string(), layer.size.to_string());
        metadata.insert("image_ref".to_string(), image_ref.to_string());
        if total_bytes > 0 {
            metadata.insert("image_size_bytes".to_string(), total_bytes.to_string());
        }
        let mut event = platform_event(
            "vm",
            "Normal",
            "PullingLayer",
            format!(
                "Pulling layer {}/{} ({} bytes) for image \"{image_ref}\"",
                index + 1,
                total_layers,
                layer.size
            ),
        );
        event.metadata = metadata;
        attach_vm_progress_metadata(&mut event);
        self.publish_platform_event(sandbox_id.to_string(), event);
    }

    /// Emit a `Pulled` platform event with progress metadata for the CLI.
    async fn publish_pulled_event(&self, sandbox_id: &str, image_ref: &str, image_path: &Path) {
        let mut metadata = HashMap::from([("image_ref".to_string(), image_ref.to_string())]);
        let size_suffix = tokio::fs::metadata(image_path).await.map_or_else(
            |_| String::new(),
            |meta| {
                metadata.insert("image_size_bytes".to_string(), meta.len().to_string());
                format!(" Image size: {} bytes.", meta.len())
            },
        );
        self.publish_vm_progress(
            sandbox_id,
            "Pulled",
            format!("Successfully pulled image \"{image_ref}\".{size_suffix}"),
            metadata,
        );
    }
}

struct DownloadedRegistryLayer {
    index: usize,
    digest: String,
    layer_root: PathBuf,
}

async fn download_registry_layer_blob(
    client: &OciClient,
    reference: &Reference,
    image_ref: &str,
    staging_dir: &Path,
    layer: OciDescriptor,
    index: usize,
) -> Result<DownloadedRegistryLayer, Status> {
    let digest_component = sanitize_image_identity(&layer.digest);
    let blob_path = staging_dir
        .join("layers")
        .join(format!("{index:02}-{digest_component}.blob"));
    let layer_root = staging_dir
        .join("layers")
        .join(format!("{index:02}-{digest_component}.root"));

    let mut file = tokio::fs::File::create(&blob_path)
        .await
        .map_err(|err| Status::internal(format!("create layer blob failed: {err}")))?;
    client
        .pull_blob(reference, &layer, &mut file)
        .await
        .map_err(|err| {
            Status::failed_precondition(format!(
                "failed to download layer '{}' for vm sandbox image '{image_ref}': {err}",
                layer.digest
            ))
        })?;
    file.flush()
        .await
        .map_err(|err| Status::internal(format!("flush layer blob failed: {err}")))?;

    let blob_path_for_digest = blob_path.clone();
    let expected_digest = layer.digest.clone();
    tokio::task::spawn_blocking(move || {
        verify_descriptor_digest(&blob_path_for_digest, &expected_digest)
    })
    .await
    .map_err(|err| Status::internal(format!("layer digest verification panicked: {err}")))?
    .map_err(|err| {
        Status::failed_precondition(format!(
            "vm sandbox image layer verification failed for '{}': {err}",
            layer.digest
        ))
    })?;

    let blob_path_for_unpack = blob_path.clone();
    let layer_root_for_unpack = layer_root.clone();
    let media_type = layer.media_type.clone();
    tokio::task::spawn_blocking(move || {
        extract_layer_blob_to_dir(&blob_path_for_unpack, &media_type, &layer_root_for_unpack)
    })
    .await
    .map_err(|err| Status::internal(format!("layer extraction panicked: {err}")))?
    .map_err(|err| {
        Status::failed_precondition(format!(
            "failed to extract layer '{}' for vm sandbox image '{image_ref}': {err}",
            layer.digest
        ))
    })?;

    Ok(DownloadedRegistryLayer {
        index,
        digest: layer.digest,
        layer_root,
    })
}

async fn apply_registry_layer_blob(
    image_ref: &str,
    rootfs: &Path,
    layer: &DownloadedRegistryLayer,
) -> Result<(), Status> {
    let layer_root_for_unpack = layer.layer_root.clone();
    let rootfs_for_unpack = rootfs.to_path_buf();
    tokio::task::spawn_blocking(move || {
        apply_layer_dir_to_rootfs(&layer_root_for_unpack, &rootfs_for_unpack)
    })
    .await
    .map_err(|err| Status::internal(format!("layer application panicked: {err}")))?
    .map_err(|err| {
        Status::failed_precondition(format!(
            "failed to apply layer '{}' for vm sandbox image '{image_ref}': {err}",
            layer.digest
        ))
    })
}

async fn download_registry_descriptor_blob_file(
    client: &OciClient,
    reference: &Reference,
    image_ref: &str,
    layout_dir: &Path,
    descriptor: &OciDescriptor,
    kind: &str,
) -> Result<(), Status> {
    let blob_path = oci_layout_blob_path(layout_dir, &descriptor.digest)
        .map_err(|err| Status::failed_precondition(format!("invalid {kind} digest: {err}")))?;
    if let Some(parent) = blob_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|err| Status::internal(format!("create OCI blob dir failed: {err}")))?;
    }

    let mut file = tokio::fs::File::create(&blob_path)
        .await
        .map_err(|err| Status::internal(format!("create OCI {kind} blob failed: {err}")))?;
    client
        .pull_blob(reference, descriptor, &mut file)
        .await
        .map_err(|err| {
            Status::failed_precondition(format!(
                "failed to download {kind} '{}' for vm sandbox image '{image_ref}': {err}",
                descriptor.digest
            ))
        })?;
    file.flush()
        .await
        .map_err(|err| Status::internal(format!("flush OCI {kind} blob failed: {err}")))?;

    let blob_path_for_digest = blob_path.clone();
    let expected_digest = descriptor.digest.clone();
    tokio::task::spawn_blocking(move || {
        verify_descriptor_digest(&blob_path_for_digest, &expected_digest)
    })
    .await
    .map_err(|err| Status::internal(format!("OCI {kind} digest verification panicked: {err}")))?
    .map_err(|err| {
        Status::failed_precondition(format!(
            "vm sandbox image {kind} verification failed for '{}': {err}",
            descriptor.digest
        ))
    })
}

fn verify_descriptor_digest(path: &Path, expected_digest: &str) -> Result<(), String> {
    let expected = expected_digest
        .strip_prefix("sha256:")
        .ok_or_else(|| format!("unsupported layer digest '{expected_digest}'"))?;
    let actual = compute_file_sha256_hex(path)?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "digest mismatch for {}: expected sha256:{expected}, got sha256:{actual}",
            path.display()
        ))
    }
}

fn compute_file_sha256_hex(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|err| format!("open {}: {err}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|err| format!("read {}: {err}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn compute_bytes_sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn extract_layer_blob_to_dir(
    blob_path: &Path,
    media_type: &str,
    dest: &Path,
) -> Result<(), String> {
    if dest.exists() {
        fs::remove_dir_all(dest).map_err(|err| format!("remove {}: {err}", dest.display()))?;
    }
    fs::create_dir_all(dest).map_err(|err| format!("create {}: {err}", dest.display()))?;

    let file =
        fs::File::open(blob_path).map_err(|err| format!("open {}: {err}", blob_path.display()))?;
    match layer_compression_from_media_type(media_type)? {
        LayerCompression::None => extract_tar_reader_to_dir(file, dest),
        LayerCompression::Gzip => extract_tar_reader_to_dir(GzDecoder::new(file), dest),
        LayerCompression::Zstd => {
            let decoder = zstd::stream::read::Decoder::new(file)
                .map_err(|err| format!("decompress {}: {err}", blob_path.display()))?;
            extract_tar_reader_to_dir(decoder, dest)
        }
    }
}

fn extract_tar_reader_to_dir(reader: impl Read, dest: &Path) -> Result<(), String> {
    let mut archive = tar::Archive::new(reader);
    archive
        .unpack(dest)
        .map_err(|err| format!("extract layer into {}: {err}", dest.display()))
}

// `media_type` is an OCI media type string (e.g. `application/vnd.oci.image.layer.v1.tar+gzip`),
// not a filesystem path, so case-sensitive comparison is correct.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn layer_compression_from_media_type(media_type: &str) -> Result<LayerCompression, String> {
    if media_type.is_empty() {
        return Err("layer media type is missing".to_string());
    }
    if media_type.ends_with("+zstd") {
        return Ok(LayerCompression::Zstd);
    }
    if media_type.ends_with("+gzip") || media_type.ends_with(".gzip") {
        return Ok(LayerCompression::Gzip);
    }
    if media_type.ends_with(".tar")
        || media_type.ends_with("tar")
        || media_type == "application/vnd.oci.image.layer.v1.tar"
        || media_type == "application/vnd.oci.image.layer.nondistributable.v1.tar"
    {
        return Ok(LayerCompression::None);
    }
    Err(format!("unsupported layer media type '{media_type}'"))
}

fn apply_layer_dir_to_rootfs(layer_root: &Path, rootfs: &Path) -> Result<(), String> {
    merge_layer_directory(layer_root, rootfs)
}

fn merge_layer_directory(source_dir: &Path, target_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(target_dir)
        .map_err(|err| format!("create {}: {err}", target_dir.display()))?;

    let mut entries = fs::read_dir(source_dir)
        .map_err(|err| format!("read {}: {err}", source_dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("read {}: {err}", source_dir.display()))?;
    entries.sort_by_key(fs::DirEntry::file_name);

    if entries
        .iter()
        .any(|entry| entry.file_name().to_string_lossy() == ".wh..wh..opq")
    {
        clear_directory_contents(target_dir)?;
    }

    for entry in entries {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if name == ".wh..wh..opq" {
            continue;
        }
        if let Some(hidden_name) = name.strip_prefix(".wh.") {
            remove_path_if_exists(&target_dir.join(hidden_name))?;
            continue;
        }

        let source_path = entry.path();
        let dest_path = target_dir.join(&file_name);
        let metadata = fs::symlink_metadata(&source_path)
            .map_err(|err| format!("stat {}: {err}", source_path.display()))?;
        let file_type = metadata.file_type();

        if file_type.is_dir() {
            if let Ok(dest_metadata) = fs::symlink_metadata(&dest_path)
                && !dest_metadata.file_type().is_dir()
                && !path_is_dir_or_symlink_to_dir(&dest_path)?
            {
                remove_path_if_exists(&dest_path)?;
            }
            fs::create_dir_all(&dest_path)
                .map_err(|err| format!("create {}: {err}", dest_path.display()))?;
            merge_layer_directory(&source_path, &dest_path)?;
            if fs::symlink_metadata(&dest_path)
                .map_err(|err| format!("stat {}: {err}", dest_path.display()))?
                .file_type()
                .is_dir()
            {
                fs::set_permissions(&dest_path, metadata.permissions())
                    .map_err(|err| format!("chmod {}: {err}", dest_path.display()))?;
            }
        } else if file_type.is_file() {
            remove_path_if_exists(&dest_path)?;
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|err| format!("create {}: {err}", parent.display()))?;
            }
            fs::copy(&source_path, &dest_path).map_err(|err| {
                format!(
                    "copy {} to {}: {err}",
                    source_path.display(),
                    dest_path.display()
                )
            })?;
            fs::set_permissions(&dest_path, metadata.permissions())
                .map_err(|err| format!("chmod {}: {err}", dest_path.display()))?;
        } else if file_type.is_symlink() {
            copy_symlink(&source_path, &dest_path)?;
        } else {
            return Err(format!(
                "unsupported layer entry type at {}",
                source_path.display()
            ));
        }
    }

    Ok(())
}

fn path_is_dir_or_symlink_to_dir(path: &Path) -> Result<bool, String> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_dir()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!("stat {}: {err}", path.display())),
    }
}

fn clear_directory_contents(dir: &Path) -> Result<(), String> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir).map_err(|err| format!("read {}: {err}", dir.display()))? {
        let entry = entry.map_err(|err| format!("read {}: {err}", dir.display()))?;
        remove_path_if_exists(&entry.path())?;
    }
    Ok(())
}

fn remove_path_if_exists(path: &Path) -> Result<(), String> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if metadata.file_type().is_dir() {
        fs::remove_dir_all(path).map_err(|err| format!("remove {}: {err}", path.display()))
    } else {
        fs::remove_file(path).map_err(|err| format!("remove {}: {err}", path.display()))
    }
}

#[cfg(unix)]
fn copy_symlink(source_path: &Path, dest_path: &Path) -> Result<(), String> {
    let target = fs::read_link(source_path)
        .map_err(|err| format!("readlink {}: {err}", source_path.display()))?;
    remove_path_if_exists(dest_path)?;
    if let Some(parent) = dest_path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("create {}: {err}", parent.display()))?;
    }
    std::os::unix::fs::symlink(&target, dest_path).map_err(|err| {
        format!(
            "symlink {} to {}: {err}",
            target.display(),
            dest_path.display()
        )
    })
}

#[cfg(not(unix))]
fn copy_symlink(_source_path: &Path, _dest_path: &Path) -> Result<(), String> {
    Err("symlink layers are only supported on Unix hosts".to_string())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LayerCompression {
    None,
    Gzip,
    Zstd,
}

fn requested_sandbox_image(sandbox: &Sandbox) -> Option<&str> {
    sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
        .map(|template| template.image.trim())
        .filter(|image| !image.is_empty())
}

fn merged_environment(sandbox: &Sandbox) -> HashMap<String, String> {
    let mut environment = sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
        .map_or_else(HashMap::new, |template| template.environment.clone());
    if let Some(spec) = sandbox.spec.as_ref() {
        environment.extend(spec.environment.clone());
    }
    environment
}

/// Rewrites loopback host references in a gateway URL to a hostname the guest
/// can reach via gvproxy.
///
/// The driver receives the gateway endpoint from `--openshell-endpoint`, which
/// in local/dev/e2e setups is typically `http://127.0.0.1:<port>`. That URL is
/// useless inside the guest because the guest's loopback interface is its own,
/// not the host's. Inside the guest we need a name that gvproxy will translate
/// into the host's loopback address.
///
/// We rewrite to `host.containers.internal`, which gvproxy's embedded DNS resolves
/// to the host-loopback IP `192.168.127.254`. gvproxy installs a default NAT entry
/// rewriting that destination to the host's `127.0.0.1` and dialing out from the
/// host process, so any port the host is listening on becomes reachable. The
/// gateway IP `192.168.127.1` does **not** do this — it only listens on gvproxy's
/// own service ports (DNS, DHCP, HTTP API). The guest init script also seeds the
/// hostname in `/etc/hosts` so resolution works even if gvproxy's DNS isn't in
/// resolv.conf (e.g. when DHCP fails).
///
/// Non-loopback URLs are returned unchanged.
fn guest_visible_openshell_endpoint(endpoint: &str) -> String {
    let Ok(mut url) = Url::parse(endpoint) else {
        return endpoint.to_string();
    };

    let should_rewrite = match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        None => false,
    };

    if should_rewrite && url.set_host(Some(GVPROXY_HOST_LOOPBACK_ALIAS)).is_ok() {
        return url.to_string();
    }

    endpoint.to_string()
}

fn gateway_port_from_endpoint(endpoint: &str) -> Option<u16> {
    Url::parse(endpoint).ok().and_then(|url| url.port())
}

fn guest_visible_openshell_endpoint_for_tap(endpoint: &str, host_ip: &str) -> String {
    let Ok(mut url) = Url::parse(endpoint) else {
        return endpoint.to_string();
    };
    if url.set_host(Some(host_ip)).is_ok() {
        url.to_string()
    } else {
        endpoint.to_string()
    }
}

fn build_guest_environment(
    sandbox: &Sandbox,
    config: &VmDriverConfig,
    endpoint_override: Option<&str>,
) -> Vec<String> {
    let openshell_endpoint = endpoint_override.map_or_else(
        || guest_visible_openshell_endpoint(&config.openshell_endpoint),
        String::from,
    );
    let mut environment = HashMap::from([
        ("HOME".to_string(), "/root".to_string()),
        (
            "PATH".to_string(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        ),
        ("TERM".to_string(), "xterm".to_string()),
        (
            openshell_core::sandbox_env::ENDPOINT.to_string(),
            openshell_endpoint,
        ),
        (
            openshell_core::sandbox_env::SANDBOX_ID.to_string(),
            sandbox.id.clone(),
        ),
        (
            openshell_core::sandbox_env::SANDBOX.to_string(),
            sandbox.name.clone(),
        ),
        (
            openshell_core::sandbox_env::SSH_SOCKET_PATH.to_string(),
            GUEST_SSH_SOCKET_PATH.to_string(),
        ),
        (
            openshell_core::sandbox_env::SANDBOX_COMMAND.to_string(),
            "tail -f /dev/null".to_string(),
        ),
        (
            openshell_core::sandbox_env::LOG_LEVEL.to_string(),
            openshell_core::driver_utils::sandbox_log_level(sandbox, &config.log_level),
        ),
    ]);
    if config.requires_tls_materials() {
        environment.extend(HashMap::from([
            (
                openshell_core::sandbox_env::TLS_CA.to_string(),
                GUEST_TLS_CA_PATH.to_string(),
            ),
            (
                openshell_core::sandbox_env::TLS_CERT.to_string(),
                GUEST_TLS_CERT_PATH.to_string(),
            ),
            (
                openshell_core::sandbox_env::TLS_KEY.to_string(),
                GUEST_TLS_KEY_PATH.to_string(),
            ),
        ]));
    }
    environment.extend(merged_environment(sandbox));

    let mut pairs = environment.into_iter().collect::<Vec<_>>();
    pairs.sort_by(|left, right| left.0.cmp(&right.0));
    pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect()
}

fn sandboxes_root_dir(root: &Path) -> PathBuf {
    root.join("sandboxes")
}

async fn create_private_dir_all(path: &Path) -> Result<(), std::io::Error> {
    tokio::fs::create_dir_all(path).await?;
    restrict_owner_only_dir(path).await
}

#[cfg(unix)]
async fn restrict_owner_only_dir(path: &Path) -> Result<(), std::io::Error> {
    tokio::fs::set_permissions(path, fs::Permissions::from_mode(0o700)).await
}

#[cfg(not(unix))]
async fn restrict_owner_only_dir(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[allow(clippy::result_large_err)]
fn sandbox_state_dir(root: &Path, sandbox_id: &str) -> Result<PathBuf, Status> {
    validate_sandbox_id(sandbox_id)?;
    Ok(sandboxes_root_dir(root).join(sandbox_id))
}

fn sandbox_overlay_image(state_dir: &Path) -> PathBuf {
    state_dir.join(SANDBOX_OVERLAY_IMAGE)
}

fn overlay_template_image(root: &Path, size_bytes: u64) -> PathBuf {
    image_cache_root_dir(root)
        .join(OVERLAY_TEMPLATE_CACHE_DIR)
        .join(OVERLAY_TEMPLATE_CACHE_LAYOUT_VERSION)
        .join(format!("{size_bytes}.ext4"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SandboxRuntimeDiskPaths {
    overlay_disk: PathBuf,
}

fn sandbox_runtime_disk_paths(state_dir: &Path) -> SandboxRuntimeDiskPaths {
    SandboxRuntimeDiskPaths {
        overlay_disk: sandbox_overlay_image(state_dir),
    }
}

#[allow(clippy::result_large_err)]
fn validate_sandbox_state_dir(root: &Path, state_dir: &Path) -> Result<(), Status> {
    let sandboxes_root = sandboxes_root_dir(root);
    let relative = state_dir.strip_prefix(&sandboxes_root).map_err(|_| {
        Status::internal(format!(
            "refusing to use sandbox state path outside vm state root: {}",
            state_dir.display()
        ))
    })?;

    let mut components = relative.components();
    match components.next() {
        Some(Component::Normal(_)) => {}
        _ => {
            return Err(Status::internal(format!(
                "refusing to use malformed sandbox state path: {}",
                state_dir.display()
            )));
        }
    }
    if components.next().is_some() {
        return Err(Status::internal(format!(
            "refusing to use nested sandbox state path: {}",
            state_dir.display()
        )));
    }

    Ok(())
}

async fn remove_sandbox_state_dir(root: &Path, state_dir: &Path) -> Result<(), Status> {
    validate_sandbox_state_dir(root, state_dir)?;

    let metadata = match tokio::fs::symlink_metadata(state_dir).await {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(Status::internal(format!(
                "failed to stat sandbox state dir: {err}"
            )));
        }
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(Status::internal(format!(
            "refusing to remove symlinked sandbox state dir: {}",
            state_dir.display()
        )));
    }
    if !file_type.is_dir() {
        return Err(Status::internal(format!(
            "sandbox state path is not a directory: {}",
            state_dir.display()
        )));
    }

    tokio::fs::remove_dir_all(state_dir)
        .await
        .map_err(|err| Status::internal(format!("failed to remove state dir: {err}")))
}

fn image_cache_root_dir(root: &Path) -> PathBuf {
    root.join(IMAGE_CACHE_ROOT_DIR)
}

fn image_cache_dir(root: &Path, image_identity: &str) -> PathBuf {
    image_cache_root_dir(root).join(sanitize_image_identity(image_identity))
}

fn image_cache_rootfs_image(root: &Path, image_identity: &str) -> PathBuf {
    image_cache_dir(root, image_identity).join(IMAGE_CACHE_ROOTFS_IMAGE)
}

fn image_cache_staging_dir(root: &Path, image_identity: &str) -> PathBuf {
    image_cache_root_dir(root).join(format!(
        "{}.staging-{}",
        sanitize_image_identity(image_identity),
        unique_image_cache_suffix()
    ))
}

fn oci_layout_blobs_dir(layout_dir: &Path) -> PathBuf {
    layout_dir.join("blobs").join("sha256")
}

fn oci_layout_blob_path(layout_dir: &Path, digest: &str) -> Result<PathBuf, String> {
    let hex = sha256_digest_hex(digest)?;
    Ok(oci_layout_blobs_dir(layout_dir).join(hex))
}

fn sha256_digest_hex(digest: &str) -> Result<&str, String> {
    let Some((algorithm, hex)) = digest.split_once(':') else {
        return Err(format!("digest '{digest}' is missing an algorithm"));
    };
    if algorithm != "sha256" {
        return Err(format!("unsupported digest algorithm '{algorithm}'"));
    }
    if hex.is_empty() || !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!("digest '{digest}' is not a valid sha256 digest"));
    }
    Ok(hex)
}

fn write_oci_layout_for_manifest(
    layout_dir: &Path,
    ref_name: &str,
    manifest: &OciImageManifest,
) -> Result<(), String> {
    fs::create_dir_all(oci_layout_blobs_dir(layout_dir))
        .map_err(|err| format!("create OCI layout blobs dir failed: {err}"))?;

    fs::write(
        layout_dir.join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .map_err(|err| format!("write OCI layout marker failed: {err}"))?;

    let manifest_bytes = serde_json::to_vec(manifest)
        .map_err(|err| format!("serialize OCI manifest failed: {err}"))?;
    let manifest_digest = format!("sha256:{}", compute_bytes_sha256_hex(&manifest_bytes));
    let manifest_blob = oci_layout_blob_path(layout_dir, &manifest_digest)
        .map_err(|err| format!("compute OCI manifest blob path failed: {err}"))?;
    fs::write(&manifest_blob, &manifest_bytes)
        .map_err(|err| format!("write OCI manifest blob failed: {err}"))?;

    let media_type = manifest
        .media_type
        .clone()
        .unwrap_or_else(|| OCI_IMAGE_MEDIA_TYPE.to_string());
    let index = serde_json::json!({
        "schemaVersion": 2,
        "manifests": [
            {
                "mediaType": media_type,
                "digest": manifest_digest,
                "size": manifest_bytes.len(),
                "annotations": {
                    "org.opencontainers.image.ref.name": ref_name
                }
            }
        ]
    });
    let index_bytes = serde_json::to_vec_pretty(&index)
        .map_err(|err| format!("serialize OCI index failed: {err}"))?;
    fs::write(layout_dir.join("index.json"), index_bytes)
        .map_err(|err| format!("write OCI index failed: {err}"))?;

    Ok(())
}

fn bootstrap_image_cache_identity(image_identity: &str) -> String {
    format!("{BOOTSTRAP_IMAGE_CACHE_LAYOUT_VERSION}:{image_identity}")
}

fn prepared_image_cache_identity(image_identity: &str) -> String {
    format!("{PREPARED_IMAGE_CACHE_LAYOUT_VERSION}:{image_identity}")
}

fn registry_layer_download_concurrency() -> usize {
    let value = std::env::var("OPENSHELL_VM_IMAGE_PULL_CONCURRENCY").ok();
    registry_layer_download_concurrency_value(value.as_deref())
}

fn registry_layer_download_concurrency_value(value: Option<&str>) -> usize {
    value
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .map_or(DEFAULT_REGISTRY_LAYER_DOWNLOAD_CONCURRENCY, |value| {
            value.min(MAX_REGISTRY_LAYER_DOWNLOAD_CONCURRENCY)
        })
}

fn sanitize_image_identity(image_identity: &str) -> String {
    image_identity
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

fn unique_image_cache_suffix() -> String {
    let counter = IMAGE_CACHE_BUILD_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}-{counter}", openshell_core::time::now_ms())
}

async fn write_sandbox_image_metadata(
    state_dir: &Path,
    image_ref: &str,
    image_identity: &str,
) -> Result<(), std::io::Error> {
    tokio::fs::write(
        state_dir.join(IMAGE_IDENTITY_FILE),
        format!("{image_identity}\n"),
    )
    .await?;
    tokio::fs::write(
        state_dir.join(IMAGE_REFERENCE_FILE),
        format!("{image_ref}\n"),
    )
    .await?;

    Ok(())
}

async fn write_sandbox_request(state_dir: &Path, sandbox: &Sandbox) -> Result<(), std::io::Error> {
    restrict_owner_only_dir(state_dir).await?;
    write_private_file(
        &state_dir.join(SANDBOX_REQUEST_FILE),
        sandbox.encode_to_vec(),
    )
    .await
}

async fn read_sandbox_request(path: &Path) -> Result<Sandbox, std::io::Error> {
    let bytes = tokio::fs::read(path).await?;
    Sandbox::decode(bytes.as_slice()).map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("decode persisted sandbox request: {err}"),
        )
    })
}

async fn write_private_file(path: &Path, bytes: Vec<u8>) -> Result<(), std::io::Error> {
    tokio::fs::write(path, bytes).await?;
    restrict_owner_read_write(path).await
}

#[cfg(unix)]
async fn restrict_owner_read_write(path: &Path) -> Result<(), std::io::Error> {
    tokio::fs::set_permissions(path, fs::Permissions::from_mode(0o600)).await
}

#[cfg(not(unix))]
async fn restrict_owner_read_write(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[allow(clippy::result_large_err)]
fn validate_restored_sandbox_state(
    root: &Path,
    state_dir: &Path,
    sandbox: &Sandbox,
) -> Result<(), Status> {
    validate_sandbox_id(&sandbox.id)?;
    validate_sandbox_state_dir(root, state_dir)?;
    let Some(dir_name) = state_dir.file_name().and_then(|name| name.to_str()) else {
        return Err(Status::internal(format!(
            "sandbox state path has no valid directory name: {}",
            state_dir.display()
        )));
    };
    if dir_name != sandbox.id {
        return Err(Status::internal(format!(
            "sandbox state dir '{}' does not match persisted sandbox id '{}'",
            dir_name, sandbox.id
        )));
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct GuestTlsMaterials {
    ca: Vec<u8>,
    cert: Vec<u8>,
    key: Vec<u8>,
}

async fn read_guest_tls_materials(paths: &VmDriverTlsPaths) -> Result<GuestTlsMaterials, String> {
    let ca = tokio::fs::read(&paths.ca)
        .await
        .map_err(|err| format!("read {}: {err}", paths.ca.display()))?;
    let cert = tokio::fs::read(&paths.cert)
        .await
        .map_err(|err| format!("read {}: {err}", paths.cert.display()))?;
    let key = tokio::fs::read(&paths.key)
        .await
        .map_err(|err| format!("read {}: {err}", paths.key.display()))?;
    Ok(GuestTlsMaterials { ca, cert, key })
}

async fn overlay_template_image_ready(path: &Path, size_bytes: u64) -> Result<bool, String> {
    match tokio::fs::metadata(path).await {
        Ok(metadata) => Ok(metadata.is_file() && metadata.len() == size_bytes),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!("stat overlay template {}: {err}", path.display())),
    }
}

fn ensure_sandbox_overlay_template_image(
    template_path: &Path,
    size_bytes: u64,
) -> Result<(), String> {
    if let Ok(metadata) = fs::metadata(template_path)
        && metadata.is_file()
        && metadata.len() == size_bytes
    {
        return Ok(());
    }

    let parent = template_path.parent().ok_or_else(|| {
        format!(
            "overlay template path has no parent: {}",
            template_path.display()
        )
    })?;
    fs::create_dir_all(parent).map_err(|err| {
        format!(
            "create overlay template cache dir {}: {err}",
            parent.display()
        )
    })?;

    let staging_image = parent.join(format!(
        ".{}.staging-{}-{}",
        template_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("overlay-template.ext4"),
        std::process::id(),
        openshell_core::time::now_ms()
    ));

    let result = (|| {
        create_empty_sandbox_overlay_image(&staging_image, size_bytes)?;
        fs::rename(&staging_image, template_path).map_err(|err| {
            format!(
                "move overlay template {} to {}: {err}",
                staging_image.display(),
                template_path.display()
            )
        })
    })();

    if result.is_err() {
        let _ = fs::remove_file(&staging_image);
    }
    result
}

fn create_empty_sandbox_overlay_image(overlay_disk: &Path, size_bytes: u64) -> Result<(), String> {
    let staging_dir = overlay_staging_dir(overlay_disk);
    if staging_dir.exists() {
        fs::remove_dir_all(&staging_dir)
            .map_err(|err| format!("remove stale overlay staging dir: {err}"))?;
    }

    let result = (|| {
        fs::create_dir_all(staging_dir.join("upper"))
            .map_err(|err| format!("create overlay upper dir: {err}"))?;
        fs::create_dir_all(staging_dir.join("work"))
            .map_err(|err| format!("create overlay work dir: {err}"))?;
        fs::create_dir_all(staging_dir.join("config"))
            .map_err(|err| format!("create overlay config dir: {err}"))?;

        create_ext4_image_from_dir_with_size(&staging_dir, overlay_disk, size_bytes)
    })();

    let _ = fs::remove_dir_all(&staging_dir);
    result
}

fn create_sandbox_overlay_image_from_template(
    template_path: &Path,
    overlay_disk: &Path,
    tls_materials: Option<&GuestTlsMaterials>,
) -> Result<(), String> {
    clone_or_copy_sparse_file(template_path, overlay_disk)?;
    if let Some(tls) = tls_materials {
        inject_guest_tls_materials(overlay_disk, tls)?;
    }
    Ok(())
}

fn prepare_sandbox_overlay_image(
    template_path: &Path,
    overlay_disk: &Path,
    tls_materials: Option<&GuestTlsMaterials>,
    preparation: OverlayPreparation,
    expected_size_bytes: u64,
) -> Result<(), String> {
    if preparation == OverlayPreparation::PreserveExisting {
        match fs::metadata(overlay_disk) {
            Ok(metadata) if metadata.is_file() && metadata.len() == expected_size_bytes => {
                if let Some(tls) = tls_materials {
                    inject_guest_tls_materials(overlay_disk, tls)?;
                }
                return Ok(());
            }
            Ok(metadata) if metadata.is_file() => {
                return Err(format!(
                    "existing overlay disk '{}' has size {}, expected {}",
                    overlay_disk.display(),
                    metadata.len(),
                    expected_size_bytes
                ));
            }
            Ok(_) => {
                return Err(format!(
                    "existing overlay path '{}' is not a file",
                    overlay_disk.display()
                ));
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(format!(
                    "stat overlay disk {}: {err}",
                    overlay_disk.display()
                ));
            }
        }
    }

    create_sandbox_overlay_image_from_template(template_path, overlay_disk, tls_materials)
}

fn inject_guest_tls_materials(
    overlay_disk: &Path,
    materials: &GuestTlsMaterials,
) -> Result<(), String> {
    write_rootfs_image_file(
        overlay_disk,
        &overlay_upper_path(GUEST_TLS_CA_PATH),
        &materials.ca,
    )?;
    write_rootfs_image_file(
        overlay_disk,
        &overlay_upper_path(GUEST_TLS_CERT_PATH),
        &materials.cert,
    )?;
    let key_path = overlay_upper_path(GUEST_TLS_KEY_PATH);
    write_rootfs_image_file(overlay_disk, &key_path, &materials.key)?;
    set_rootfs_image_file_mode(overlay_disk, &key_path, 0o600)
}

fn overlay_upper_path(guest_path: &str) -> String {
    format!("/upper/{}", guest_path.trim_start_matches('/'))
}

fn create_image_prep_disk(
    image_path: &Path,
    size_bytes: u64,
    payload: &GuestImagePayload,
) -> Result<(), String> {
    let staging_dir = overlay_staging_dir(image_path);
    if staging_dir.exists() {
        fs::remove_dir_all(&staging_dir)
            .map_err(|err| format!("remove stale image-prep staging dir: {err}"))?;
    }

    let result = (|| {
        fs::create_dir_all(staging_dir.join("upper").join("srv"))
            .map_err(|err| format!("create image-prep env dir: {err}"))?;
        fs::create_dir_all(staging_dir.join("work"))
            .map_err(|err| format!("create image-prep work dir: {err}"))?;
        fs::create_dir_all(staging_dir.join("config"))
            .map_err(|err| format!("create image-prep config dir: {err}"))?;
        stage_guest_image_payload(&staging_dir, payload)?;
        create_ext4_image_from_dir_with_size(&staging_dir, image_path, size_bytes)
    })();

    let _ = fs::remove_dir_all(&staging_dir);
    result
}

fn stage_guest_image_payload(
    staging_dir: &Path,
    payload: &GuestImagePayload,
) -> Result<(), String> {
    let image_dir = staging_dir.join("config").join(GUEST_IMAGE_CONFIG_DIR);
    fs::create_dir_all(&image_dir).map_err(|err| {
        format!(
            "create guest image config dir {}: {err}",
            image_dir.display()
        )
    })?;
    fs::write(image_dir.join("ref"), payload.image_ref.as_bytes())
        .map_err(|err| format!("write guest image ref: {err}"))?;
    fs::write(
        image_dir.join("identity"),
        payload.image_identity.as_bytes(),
    )
    .map_err(|err| format!("write guest image identity: {err}"))?;

    match &payload.source {
        GuestImagePayloadSource::RegistryOciLayout { layout_dir } => {
            fs::write(image_dir.join("source"), b"oci-layout")
                .map_err(|err| format!("write guest image source: {err}"))?;
            copy_dir_recursive(layout_dir, &image_dir.join(GUEST_IMAGE_OCI_LAYOUT_DIR))?;
        }
        GuestImagePayloadSource::LocalDocker { rootfs_archive } => {
            fs::write(image_dir.join("source"), b"local-docker")
                .map_err(|err| format!("write guest image source: {err}"))?;
            let dest = image_dir.join(IMAGE_EXPORT_ROOTFS_ARCHIVE);
            fs::copy(rootfs_archive, &dest).map_err(|err| {
                format!(
                    "copy guest image rootfs archive {} to {}: {err}",
                    rootfs_archive.display(),
                    dest.display()
                )
            })?;
        }
    }

    Ok(())
}

fn copy_dir_recursive(source: &Path, dest: &Path) -> Result<(), String> {
    fs::create_dir_all(dest).map_err(|err| format!("create {}: {err}", dest.display()))?;
    for entry in fs::read_dir(source).map_err(|err| format!("read {}: {err}", source.display()))? {
        let entry = entry.map_err(|err| format!("read {}: {err}", source.display()))?;
        let source_path = entry.path();
        let dest_path = dest.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)
            .map_err(|err| format!("stat {}: {err}", source_path.display()))?;
        if metadata.file_type().is_dir() {
            copy_dir_recursive(&source_path, &dest_path)?;
        } else if metadata.file_type().is_file() {
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|err| format!("create {}: {err}", parent.display()))?;
            }
            fs::copy(&source_path, &dest_path).map_err(|err| {
                format!(
                    "copy {} to {}: {err}",
                    source_path.display(),
                    dest_path.display()
                )
            })?;
        } else {
            return Err(format!(
                "unsupported payload entry type at {}",
                source_path.display()
            ));
        }
    }
    Ok(())
}

fn prepared_image_disk_size_bytes(
    payload: &GuestImagePayload,
    minimum_size_bytes: u64,
) -> Result<u64, String> {
    let payload_size = match &payload.source {
        GuestImagePayloadSource::RegistryOciLayout { layout_dir } => dir_size_bytes(layout_dir)?,
        GuestImagePayloadSource::LocalDocker { rootfs_archive } => fs::metadata(rootfs_archive)
            .map_err(|err| format!("stat {}: {err}", rootfs_archive.display()))?
            .len(),
    };
    let requested = payload_size
        .saturating_mul(3)
        .saturating_add(512 * 1024 * 1024);
    Ok(minimum_size_bytes.max(requested))
}

fn dir_size_bytes(path: &Path) -> Result<u64, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|err| format!("stat {}: {err}", path.display()))?;
    if metadata.file_type().is_file() {
        return Ok(metadata.len());
    }
    if metadata.file_type().is_symlink() {
        return Ok(0);
    }
    let mut total = 0_u64;
    for entry in fs::read_dir(path).map_err(|err| format!("read {}: {err}", path.display()))? {
        let entry = entry.map_err(|err| format!("read {}: {err}", path.display()))?;
        total = total.saturating_add(dir_size_bytes(&entry.path())?);
    }
    Ok(total)
}

#[cfg(test)]
fn stage_guest_tls_materials(
    staging_dir: &Path,
    materials: &GuestTlsMaterials,
) -> Result<(), String> {
    let tls_dir = staging_dir
        .join("upper")
        .join(GUEST_TLS_CA_PATH.trim_start_matches('/'))
        .parent()
        .ok_or_else(|| "guest TLS CA path has no parent".to_string())?
        .to_path_buf();
    fs::create_dir_all(&tls_dir)
        .map_err(|err| format!("create guest TLS dir {}: {err}", tls_dir.display()))?;

    let ca_path = staging_dir
        .join("upper")
        .join(GUEST_TLS_CA_PATH.trim_start_matches('/'));
    let cert_path = staging_dir
        .join("upper")
        .join(GUEST_TLS_CERT_PATH.trim_start_matches('/'));
    let key_path = staging_dir
        .join("upper")
        .join(GUEST_TLS_KEY_PATH.trim_start_matches('/'));
    fs::write(&ca_path, &materials.ca)
        .map_err(|err| format!("write guest TLS CA {}: {err}", ca_path.display()))?;
    fs::write(&cert_path, &materials.cert)
        .map_err(|err| format!("write guest TLS cert {}: {err}", cert_path.display()))?;
    fs::write(&key_path, &materials.key)
        .map_err(|err| format!("write guest TLS key {}: {err}", key_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .map_err(|err| format!("chmod guest TLS key {}: {err}", key_path.display()))?;
    }

    Ok(())
}

fn overlay_staging_dir(overlay_disk: &Path) -> PathBuf {
    let parent = overlay_disk.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!(
        ".openshell-overlay-staging-{}-{}",
        std::process::id(),
        openshell_core::time::now_ms()
    ))
}

async fn terminate_vm_process(child: &mut Child) -> Result<(), std::io::Error> {
    if let Some(pid) = child.id()
        && let Err(err) = kill(Pid::from_raw(pid.cast_signed()), Signal::SIGTERM)
        && err != Errno::ESRCH
    {
        return Err(std::io::Error::other(format!(
            "send SIGTERM to vm process {pid}: {err}"
        )));
    }

    match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(err)) => Err(err),
        Err(_) => {
            child.kill().await?;
            child.wait().await.map(|_| ())
        }
    }
}

fn sandbox_snapshot(sandbox: &Sandbox, condition: SandboxCondition, deleting: bool) -> Sandbox {
    Sandbox {
        id: sandbox.id.clone(),
        name: sandbox.name.clone(),
        namespace: sandbox.namespace.clone(),
        status: Some(SandboxStatus {
            sandbox_name: sandbox.name.clone(),
            instance_id: String::new(),
            agent_fd: String::new(),
            sandbox_fd: String::new(),
            conditions: vec![condition],
            deleting,
        }),
        ..Default::default()
    }
}

fn status_with_condition(
    snapshot: &Sandbox,
    condition: SandboxCondition,
    deleting: bool,
) -> SandboxStatus {
    SandboxStatus {
        sandbox_name: snapshot.name.clone(),
        instance_id: String::new(),
        agent_fd: String::new(),
        sandbox_fd: String::new(),
        conditions: vec![condition],
        deleting,
    }
}

fn provisioning_condition() -> SandboxCondition {
    SandboxCondition {
        r#type: "Ready".to_string(),
        status: "False".to_string(),
        reason: "Starting".to_string(),
        message: "VM is starting".to_string(),
        last_transition_time: String::new(),
    }
}

fn deleting_condition() -> SandboxCondition {
    SandboxCondition {
        r#type: "Ready".to_string(),
        status: "False".to_string(),
        reason: "Deleting".to_string(),
        message: "Sandbox is being deleted".to_string(),
        last_transition_time: String::new(),
    }
}

fn error_condition(reason: &str, message: &str) -> SandboxCondition {
    SandboxCondition {
        r#type: "Ready".to_string(),
        status: "False".to_string(),
        reason: reason.to_string(),
        message: message.to_string(),
        last_transition_time: String::new(),
    }
}

fn platform_event(source: &str, event_type: &str, reason: &str, message: String) -> PlatformEvent {
    let mut event = PlatformEvent {
        timestamp_ms: openshell_core::time::now_ms(),
        source: source.to_string(),
        r#type: event_type.to_string(),
        reason: reason.to_string(),
        message,
        metadata: HashMap::new(),
    };
    attach_vm_progress_metadata(&mut event);
    event
}

fn attach_vm_progress_metadata(event: &mut PlatformEvent) {
    if event.source != "vm" {
        return;
    }

    match event.reason.as_str() {
        "Scheduled" => {
            mark_progress_complete(
                &mut event.metadata,
                PROGRESS_STEP_REQUESTING_SANDBOX,
                "Sandbox allocated",
            );
            mark_progress_active(&mut event.metadata, PROGRESS_STEP_PULLING_IMAGE);
        }
        "Pulling" => {
            mark_progress_active(&mut event.metadata, PROGRESS_STEP_PULLING_IMAGE);
            if let Some(image_ref) = event.metadata.get("image_ref").cloned() {
                mark_progress_detail(&mut event.metadata, image_ref);
            } else if let Some(image_ref) = pulling_image_from_message(&event.message) {
                mark_progress_detail(&mut event.metadata, image_ref);
            }
        }
        "Pulled" => {
            let label = pulled_label(event);
            mark_progress_complete(&mut event.metadata, PROGRESS_STEP_PULLING_IMAGE, label);
            mark_progress_active(&mut event.metadata, PROGRESS_STEP_STARTING_SANDBOX);
        }
        "PullingLayer" => {
            if let Some(detail) = pulling_layer_detail(&event.metadata) {
                mark_progress_detail(&mut event.metadata, detail);
            }
        }
        "ResolvingImage" => mark_progress_detail(&mut event.metadata, "Resolving image"),
        "AuthenticatingRegistry" => {
            mark_progress_detail(&mut event.metadata, "Authenticating registry");
        }
        "FetchingManifest" => mark_progress_detail(&mut event.metadata, "Fetching image manifest"),
        "CacheHit" => mark_progress_detail(&mut event.metadata, "Using cached root disk"),
        "CacheMiss" => mark_progress_detail(&mut event.metadata, "Preparing image cache"),
        "WaitingForImageCacheLock" => {
            mark_progress_detail(&mut event.metadata, "Waiting for image cache lock");
        }
        "ExportingRootfs" => {
            mark_progress_detail(&mut event.metadata, "Exporting local image rootfs");
        }
        "PreparingRootfs" => mark_progress_detail(&mut event.metadata, "Preparing rootfs"),
        "CreatingRootDisk" => mark_progress_detail(&mut event.metadata, "Formatting root disk"),
        "PreparingOverlay" => mark_progress_detail(&mut event.metadata, "Preparing overlay disk"),
        "Started" => mark_progress_detail(&mut event.metadata, "Waiting for VM supervisor"),
        _ => {}
    }
}

fn pulling_image_from_message(message: &str) -> Option<String> {
    let image = message
        .strip_prefix("Pulling image ")
        .map(str::trim)
        .map(|value| value.trim_matches('"'))?;
    (!image.is_empty()).then(|| image.to_string())
}

fn pulled_label(event: &PlatformEvent) -> String {
    event
        .metadata
        .get("image_size_bytes")
        .and_then(|value| value.parse::<u64>().ok())
        .map_or_else(
            || "Image pulled".to_string(),
            |bytes| format!("Image pulled ({})", format_bytes(bytes)),
        )
}

fn pulling_layer_detail(metadata: &HashMap<String, String>) -> Option<String> {
    let index = metadata.get("layer_index")?;
    let total = metadata.get("layer_total")?;
    let size = metadata
        .get("layer_size_bytes")
        .and_then(|value| value.parse::<u64>().ok())
        .map(format_bytes);
    Some(size.map_or_else(
        || format!("Layer {index}/{total}"),
        |size| format!("Layer {index}/{total} ({size})"),
    ))
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        #[allow(clippy::cast_precision_loss)]
        let gb = bytes as f64 / GB as f64;
        format!("{gb:.1} GB")
    } else if bytes >= MB {
        format!("{} MB", bytes / MB)
    } else if bytes >= KB {
        format!("{} KB", bytes / KB)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpu::{SubnetAllocator, allocate_vsock_cid, mac_from_sandbox_id, tap_device_name};
    use openshell_core::progress::{
        PROGRESS_ACTIVE_DETAIL_KEY, PROGRESS_ACTIVE_STEP_KEY, PROGRESS_COMPLETE_LABEL_KEY,
        PROGRESS_COMPLETE_STEP_KEY,
    };
    use openshell_core::proto::compute::v1::{
        DriverSandboxSpec as SandboxSpec, DriverSandboxTemplate as SandboxTemplate,
    };
    use prost_types::{Struct, Value, value::Kind};
    use std::fs;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tonic::Code;

    #[test]
    fn vm_pulling_layer_event_adds_progress_detail_metadata() {
        let mut event = platform_event(
            "vm",
            "Normal",
            "PullingLayer",
            "Pulling layer 3/8 for image".to_string(),
        );
        event.metadata = HashMap::from([
            ("layer_index".to_string(), "3".to_string()),
            ("layer_total".to_string(), "8".to_string()),
            ("layer_size_bytes".to_string(), "44040192".to_string()),
        ]);

        attach_vm_progress_metadata(&mut event);

        assert_eq!(
            event
                .metadata
                .get(PROGRESS_ACTIVE_DETAIL_KEY)
                .map(String::as_str),
            Some("Layer 3/8 (42 MB)")
        );
    }

    #[test]
    fn vm_pulled_event_adds_completed_image_progress_metadata() {
        let mut event = platform_event(
            "vm",
            "Normal",
            "Pulled",
            "Successfully pulled image".to_string(),
        );
        event
            .metadata
            .insert("image_size_bytes".to_string(), "44040192".to_string());

        attach_vm_progress_metadata(&mut event);

        assert_eq!(
            event
                .metadata
                .get(PROGRESS_COMPLETE_STEP_KEY)
                .map(String::as_str),
            Some(PROGRESS_STEP_PULLING_IMAGE)
        );
        assert_eq!(
            event
                .metadata
                .get(PROGRESS_COMPLETE_LABEL_KEY)
                .map(String::as_str),
            Some("Image pulled (42 MB)")
        );
        assert_eq!(
            event
                .metadata
                .get(PROGRESS_ACTIVE_STEP_KEY)
                .map(String::as_str),
            Some(PROGRESS_STEP_STARTING_SANDBOX)
        );
    }

    #[test]
    fn validate_vm_sandbox_rejects_gpu_when_not_enabled() {
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                gpu: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = validate_vm_sandbox(&sandbox, false)
            .expect_err("gpu should be rejected when not enabled");
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("GPU support is not enabled"));
    }

    #[test]
    fn validate_vm_sandbox_accepts_gpu_when_enabled() {
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                gpu: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        validate_vm_sandbox(&sandbox, true).expect("gpu should be accepted when enabled");
    }

    #[test]
    fn validate_vm_sandbox_rejects_gpu_device_without_gpu() {
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                gpu: false,
                gpu_device: "0000:2d:00.0".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = validate_vm_sandbox(&sandbox, true)
            .expect_err("gpu_device without gpu should be rejected");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("gpu_device requires gpu=true"));
    }

    #[test]
    fn validate_vm_sandbox_rejects_platform_config() {
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate {
                    platform_config: Some(Struct {
                        fields: std::iter::once((
                            "runtime_class_name".to_string(),
                            Value {
                                kind: Some(Kind::StringValue("kata".to_string())),
                            },
                        ))
                        .collect(),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err =
            validate_vm_sandbox(&sandbox, false).expect_err("platform config should be rejected");
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("platform_config"));
    }

    #[test]
    fn validate_vm_sandbox_accepts_template_image() {
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate {
                    image: "ghcr.io/example/sandbox:latest".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        validate_vm_sandbox(&sandbox, false).expect("template.image should be accepted");
    }

    #[test]
    fn validate_vm_sandbox_accepts_template_resources_as_noop() {
        use openshell_core::proto::compute::v1::DriverResourceRequirements;

        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate {
                    resources: Some(DriverResourceRequirements {
                        cpu_limit: "2".to_string(),
                        memory_limit: "4Gi".to_string(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        validate_vm_sandbox(&sandbox, false)
            .expect("template.resources should be accepted and ignored");
    }

    #[test]
    fn validate_vm_sandbox_rejects_path_unsafe_ids() {
        let mut unsafe_ids = [
            "",
            ".",
            "..",
            "../escape",
            "/tmp/escape",
            "nested/path",
            "nested\\path",
            "bad\nid",
            "bad id",
            "unicodé",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
        unsafe_ids.push("a".repeat(129));

        for sandbox_id in unsafe_ids {
            let sandbox = Sandbox {
                id: sandbox_id.clone(),
                spec: Some(SandboxSpec {
                    template: Some(SandboxTemplate {
                        image: "ghcr.io/example/sandbox:latest".to_string(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let err = validate_vm_sandbox(&sandbox, false)
                .expect_err("path-unsafe sandbox id should be rejected");
            assert_eq!(err.code(), Code::InvalidArgument, "id={sandbox_id:?}");
            assert!(err.message().contains("sandbox id"), "id={sandbox_id:?}");
        }
    }

    #[test]
    fn sandbox_state_dir_rejects_path_unsafe_ids() {
        let err = sandbox_state_dir(Path::new("/tmp/openshell-vm"), "../escape")
            .expect_err("path traversal should be rejected");
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[test]
    fn sandbox_runtime_disk_paths_use_per_sandbox_overlay() {
        let driver_state = Path::new("/tmp/openshell-vm");
        let state_dir = driver_state.join("sandboxes").join("sandbox-123");

        let disks = sandbox_runtime_disk_paths(&state_dir);

        assert_eq!(disks.overlay_disk, state_dir.join(SANDBOX_OVERLAY_IMAGE));
    }

    #[test]
    fn overlay_template_image_is_keyed_by_size_and_layout() {
        let path = overlay_template_image(Path::new("/tmp/openshell-vm"), 4 * 1024 * 1024);

        assert_eq!(
            path,
            Path::new("/tmp/openshell-vm")
                .join(IMAGE_CACHE_ROOT_DIR)
                .join(OVERLAY_TEMPLATE_CACHE_DIR)
                .join(OVERLAY_TEMPLATE_CACHE_LAYOUT_VERSION)
                .join("4194304.ext4")
        );
    }

    #[tokio::test]
    async fn sandbox_request_metadata_round_trips_for_resume() {
        let base = unique_temp_dir();
        let state_dir = base.join("sandboxes").join("sandbox-123");
        std::fs::create_dir_all(&state_dir).unwrap();
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            name: "resume-sandbox".to_string(),
            namespace: "vm-dev".to_string(),
            spec: Some(SandboxSpec {
                environment: HashMap::from([("KEY".to_string(), "value".to_string())]),
                template: Some(SandboxTemplate {
                    image: "ghcr.io/example/sandbox:latest".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        write_sandbox_request(&state_dir, &sandbox)
            .await
            .expect("write sandbox request");
        let restored = read_sandbox_request(&state_dir.join(SANDBOX_REQUEST_FILE))
            .await
            .expect("read sandbox request");

        assert_eq!(restored, sandbox);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let dir_mode = std::fs::metadata(&state_dir).unwrap().permissions().mode() & 0o777;
            let file_mode = std::fs::metadata(state_dir.join(SANDBOX_REQUEST_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700);
            assert_eq!(file_mode, 0o600);
        }
        validate_restored_sandbox_state(&base, &state_dir, &restored)
            .expect("restored state should validate");

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn prepare_sandbox_overlay_preserves_existing_overlay_on_resume() {
        let base = unique_temp_dir();
        std::fs::create_dir_all(&base).unwrap();
        let template = base.join("template.ext4");
        let overlay = base.join("overlay.ext4");
        std::fs::write(&template, b"fresh-overlay").unwrap();
        std::fs::write(&overlay, b"saved-overlay").unwrap();

        prepare_sandbox_overlay_image(
            &template,
            &overlay,
            None,
            OverlayPreparation::PreserveExisting,
            "saved-overlay".len() as u64,
        )
        .expect("preserve existing overlay");

        assert_eq!(std::fs::read(&overlay).unwrap(), b"saved-overlay");

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn prepare_sandbox_overlay_creates_missing_overlay_on_resume() {
        let base = unique_temp_dir();
        std::fs::create_dir_all(&base).unwrap();
        let template = base.join("template.ext4");
        let overlay = base.join("overlay.ext4");
        std::fs::write(&template, b"fresh-overlay").unwrap();

        prepare_sandbox_overlay_image(
            &template,
            &overlay,
            None,
            OverlayPreparation::PreserveExisting,
            "fresh-overlay".len() as u64,
        )
        .expect("create missing overlay");

        assert_eq!(std::fs::read(&overlay).unwrap(), b"fresh-overlay");

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn overlay_upper_path_targets_overlay_upperdir() {
        assert_eq!(
            overlay_upper_path(GUEST_TLS_KEY_PATH),
            "/upper/opt/openshell/tls/tls.key"
        );
    }

    #[test]
    fn capabilities_report_configured_default_image() {
        let driver = VmDriver {
            config: VmDriverConfig {
                default_image: "openshell/sandbox:dev".to_string(),
                ..Default::default()
            },
            launcher_bin: PathBuf::from("/tmp/openshell-driver-vm"),
            registry: Arc::new(Mutex::new(HashMap::new())),
            image_cache_lock: Arc::new(Mutex::new(())),
            events: broadcast::channel(WATCH_BUFFER).0,
            gpu_inventory: None,
            subnet_allocator: Arc::new(std::sync::Mutex::new(SubnetAllocator::new(
                Ipv4Addr::new(10, 0, 128, 0),
                17,
            ))),
        };

        assert_eq!(driver.capabilities().default_image, "openshell/sandbox:dev");
    }

    #[test]
    fn resolved_sandbox_image_prefers_template_image() {
        let driver = VmDriver {
            config: VmDriverConfig {
                default_image: "openshell/sandbox:default".to_string(),
                ..Default::default()
            },
            launcher_bin: PathBuf::from("/tmp/openshell-driver-vm"),
            registry: Arc::new(Mutex::new(HashMap::new())),
            image_cache_lock: Arc::new(Mutex::new(())),
            events: broadcast::channel(WATCH_BUFFER).0,
            gpu_inventory: None,
            subnet_allocator: Arc::new(std::sync::Mutex::new(SubnetAllocator::new(
                Ipv4Addr::new(10, 0, 128, 0),
                17,
            ))),
        };
        let sandbox = Sandbox {
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate {
                    image: "ghcr.io/example/custom:latest".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(
            driver.resolved_sandbox_image(&sandbox).as_deref(),
            Some("ghcr.io/example/custom:latest")
        );
    }

    #[test]
    fn resolved_sandbox_image_falls_back_to_driver_default() {
        let driver = VmDriver {
            config: VmDriverConfig {
                default_image: "openshell/sandbox:default".to_string(),
                ..Default::default()
            },
            launcher_bin: PathBuf::from("/tmp/openshell-driver-vm"),
            registry: Arc::new(Mutex::new(HashMap::new())),
            image_cache_lock: Arc::new(Mutex::new(())),
            events: broadcast::channel(WATCH_BUFFER).0,
            gpu_inventory: None,
            subnet_allocator: Arc::new(std::sync::Mutex::new(SubnetAllocator::new(
                Ipv4Addr::new(10, 0, 128, 0),
                17,
            ))),
        };
        let sandbox = Sandbox {
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate::default()),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(
            driver.resolved_sandbox_image(&sandbox).as_deref(),
            Some("openshell/sandbox:default")
        );
    }

    #[test]
    fn resolved_sandbox_image_returns_none_without_template_or_default() {
        let driver = VmDriver {
            config: VmDriverConfig::default(),
            launcher_bin: PathBuf::from("/tmp/openshell-driver-vm"),
            registry: Arc::new(Mutex::new(HashMap::new())),
            image_cache_lock: Arc::new(Mutex::new(())),
            events: broadcast::channel(WATCH_BUFFER).0,
            gpu_inventory: None,
            subnet_allocator: Arc::new(std::sync::Mutex::new(SubnetAllocator::new(
                Ipv4Addr::new(10, 0, 128, 0),
                17,
            ))),
        };
        let sandbox = Sandbox {
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate::default()),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert!(driver.resolved_sandbox_image(&sandbox).is_none());
    }

    #[test]
    fn bootstrap_image_ref_prefers_explicit_bootstrap_image() {
        let driver = VmDriver {
            config: VmDriverConfig {
                default_image: "openshell/sandbox:default".to_string(),
                bootstrap_image: "openshell/sandbox-bootstrap:latest".to_string(),
                ..Default::default()
            },
            launcher_bin: PathBuf::from("/tmp/openshell-driver-vm"),
            registry: Arc::new(Mutex::new(HashMap::new())),
            image_cache_lock: Arc::new(Mutex::new(())),
            events: broadcast::channel(WATCH_BUFFER).0,
            gpu_inventory: None,
            subnet_allocator: Arc::new(std::sync::Mutex::new(SubnetAllocator::new(
                Ipv4Addr::new(10, 0, 128, 0),
                17,
            ))),
        };

        assert_eq!(
            driver.bootstrap_image_ref("ghcr.io/example/app:latest"),
            "openshell/sandbox-bootstrap:latest"
        );
    }

    #[test]
    fn bootstrap_image_ref_falls_back_to_default_image() {
        let driver = VmDriver {
            config: VmDriverConfig {
                default_image: "openshell/sandbox:default".to_string(),
                ..Default::default()
            },
            launcher_bin: PathBuf::from("/tmp/openshell-driver-vm"),
            registry: Arc::new(Mutex::new(HashMap::new())),
            image_cache_lock: Arc::new(Mutex::new(())),
            events: broadcast::channel(WATCH_BUFFER).0,
            gpu_inventory: None,
            subnet_allocator: Arc::new(std::sync::Mutex::new(SubnetAllocator::new(
                Ipv4Addr::new(10, 0, 128, 0),
                17,
            ))),
        };

        assert_eq!(
            driver.bootstrap_image_ref("ghcr.io/example/app:latest"),
            "openshell/sandbox:default"
        );
    }

    #[test]
    fn bootstrap_image_ref_falls_back_to_requested_image() {
        let driver = VmDriver {
            config: VmDriverConfig::default(),
            launcher_bin: PathBuf::from("/tmp/openshell-driver-vm"),
            registry: Arc::new(Mutex::new(HashMap::new())),
            image_cache_lock: Arc::new(Mutex::new(())),
            events: broadcast::channel(WATCH_BUFFER).0,
            gpu_inventory: None,
            subnet_allocator: Arc::new(std::sync::Mutex::new(SubnetAllocator::new(
                Ipv4Addr::new(10, 0, 128, 0),
                17,
            ))),
        };

        assert_eq!(
            driver.bootstrap_image_ref("ghcr.io/example/app:latest"),
            "ghcr.io/example/app:latest"
        );
    }

    #[test]
    fn merged_environment_prefers_spec_values() {
        let sandbox = Sandbox {
            spec: Some(SandboxSpec {
                environment: HashMap::from([("A".to_string(), "spec".to_string())]),
                template: Some(SandboxTemplate {
                    environment: HashMap::from([
                        ("A".to_string(), "template".to_string()),
                        ("B".to_string(), "template".to_string()),
                    ]),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let merged = merged_environment(&sandbox);
        assert_eq!(merged.get("A"), Some(&"spec".to_string()));
        assert_eq!(merged.get("B"), Some(&"template".to_string()));
    }

    #[test]
    fn build_guest_environment_sets_supervisor_defaults() {
        let config = VmDriverConfig {
            openshell_endpoint: "http://127.0.0.1:8080".to_string(),
            ..Default::default()
        };
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            name: "breezy-rhinoceros".to_string(),
            spec: Some(SandboxSpec::default()),
            ..Default::default()
        };

        let env = build_guest_environment(&sandbox, &config, None);
        assert!(env.contains(&"HOME=/root".to_string()));
        assert!(env.contains(&format!(
            "OPENSHELL_ENDPOINT=http://{GVPROXY_HOST_LOOPBACK_ALIAS}:8080/"
        )));
        assert!(env.contains(&"OPENSHELL_SANDBOX_ID=sandbox-123".to_string()));
        assert!(env.contains(&"OPENSHELL_SANDBOX=breezy-rhinoceros".to_string()));
        assert!(env.contains(&format!(
            "OPENSHELL_SSH_SOCKET_PATH={GUEST_SSH_SOCKET_PATH}"
        )));
    }

    #[test]
    fn build_guest_environment_uses_endpoint_override_for_tap() {
        let config = VmDriverConfig {
            openshell_endpoint: "http://127.0.0.1:8080".to_string(),
            ..Default::default()
        };
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            name: "sandbox-123".to_string(),
            spec: Some(SandboxSpec::default()),
            ..Default::default()
        };

        let env = build_guest_environment(&sandbox, &config, Some("http://10.0.128.1:8080"));
        assert!(
            env.contains(&"OPENSHELL_ENDPOINT=http://10.0.128.1:8080".to_string()),
            "TAP endpoint override must replace the default"
        );
        let endpoint_count = env
            .iter()
            .filter(|e| e.starts_with("OPENSHELL_ENDPOINT="))
            .count();
        assert_eq!(
            endpoint_count, 1,
            "must have exactly one OPENSHELL_ENDPOINT"
        );
    }

    #[test]
    fn guest_visible_openshell_endpoint_rewrites_loopback_hosts_to_gvproxy_host_alias() {
        assert_eq!(
            guest_visible_openshell_endpoint("http://127.0.0.1:8080"),
            format!("http://{GVPROXY_HOST_LOOPBACK_ALIAS}:8080/")
        );
        assert_eq!(
            guest_visible_openshell_endpoint("http://localhost:8080"),
            format!("http://{GVPROXY_HOST_LOOPBACK_ALIAS}:8080/")
        );
        assert_eq!(
            guest_visible_openshell_endpoint("https://[::1]:8443"),
            format!("https://{GVPROXY_HOST_LOOPBACK_ALIAS}:8443/")
        );
    }

    #[test]
    fn guest_visible_openshell_endpoint_preserves_non_loopback_hosts() {
        assert_eq!(
            guest_visible_openshell_endpoint(&format!(
                "http://{OPENSHELL_HOST_GATEWAY_ALIAS}:8080"
            )),
            format!("http://{OPENSHELL_HOST_GATEWAY_ALIAS}:8080")
        );
        assert_eq!(
            guest_visible_openshell_endpoint(&format!("http://{GVPROXY_HOST_LOOPBACK_ALIAS}:8080")),
            format!("http://{GVPROXY_HOST_LOOPBACK_ALIAS}:8080")
        );
        assert_eq!(
            guest_visible_openshell_endpoint("http://192.168.127.1:8080"),
            "http://192.168.127.1:8080"
        );
        assert_eq!(
            guest_visible_openshell_endpoint("https://gateway.internal:8443"),
            "https://gateway.internal:8443"
        );
    }

    #[test]
    fn image_reference_registry_host_defaults_to_docker_hub() {
        assert_eq!(image_reference_registry_host("ubuntu:24.04"), "docker.io");
        assert_eq!(
            image_reference_registry_host("library/ubuntu:24.04"),
            "docker.io"
        );
        assert_eq!(
            image_reference_registry_host("ghcr.io/nvidia/openshell/base:latest"),
            "ghcr.io"
        );
        assert_eq!(
            image_reference_registry_host("localhost/example:dev"),
            "localhost"
        );
        assert_eq!(
            image_reference_registry_host("localhost:5000/example/sandbox:dev"),
            "localhost:5000"
        );
    }

    #[test]
    fn openshell_local_build_image_ref_matches_cli_tags() {
        assert!(is_openshell_local_build_image_ref(
            "openshell/sandbox-from:123"
        ));
        assert!(!is_openshell_local_build_image_ref("ubuntu:24.04"));
        assert!(!is_openshell_local_build_image_ref(
            "ghcr.io/nvidia/openshell/base:latest"
        ));
    }

    #[test]
    fn local_image_platform_mismatch_checks_guest_platform() {
        assert!(
            local_image_platform_mismatch(
                "openshell/sandbox-from:123",
                Some("linux"),
                Some(linux_oci_arch()),
            )
            .is_none()
        );

        let err = local_image_platform_mismatch(
            "openshell/sandbox-from:123",
            Some("linux"),
            Some("wrong-arch"),
        )
        .expect("architecture mismatch should be reported");
        assert!(err.contains("wrong-arch"));
        assert!(err.contains(linux_oci_arch()));

        let err = local_image_platform_mismatch("openshell/sandbox-from:123", None, None)
            .expect("unknown platform should be reported");
        assert!(err.contains("unknown/unknown"));
    }

    #[test]
    fn apply_layer_dir_to_rootfs_honors_whiteouts() {
        let base = unique_temp_dir();
        let rootfs = base.join("rootfs");
        let layer = base.join("layer");

        fs::create_dir_all(rootfs.join("dir")).unwrap();
        fs::write(rootfs.join("removed.txt"), "old").unwrap();
        fs::write(rootfs.join("dir/old.txt"), "old").unwrap();

        fs::create_dir_all(layer.join("dir")).unwrap();
        fs::write(layer.join(".wh.removed.txt"), "").unwrap();
        fs::write(layer.join("dir/.wh..wh..opq"), "").unwrap();
        fs::write(layer.join("dir/new.txt"), "new").unwrap();

        apply_layer_dir_to_rootfs(&layer, &rootfs).unwrap();

        assert!(!rootfs.join("removed.txt").exists());
        assert!(!rootfs.join("dir/old.txt").exists());
        assert_eq!(
            fs::read_to_string(rootfs.join("dir/new.txt")).unwrap(),
            "new"
        );

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn apply_layer_dir_to_rootfs_preserves_lower_symlink_dirs() {
        let base = unique_temp_dir();
        let rootfs = base.join("rootfs");
        let layer = base.join("layer");

        fs::create_dir_all(rootfs.join("usr/bin")).unwrap();
        fs::write(rootfs.join("usr/bin/bash"), "bash").unwrap();
        std::os::unix::fs::symlink("usr/bin", rootfs.join("bin")).unwrap();

        fs::create_dir_all(layer.join("bin")).unwrap();
        fs::write(layer.join("bin/foo"), "foo").unwrap();

        apply_layer_dir_to_rootfs(&layer, &rootfs).unwrap();

        assert!(
            fs::symlink_metadata(rootfs.join("bin"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "lower /bin symlink should be preserved"
        );
        assert_eq!(
            fs::read_to_string(rootfs.join("usr/bin/bash")).unwrap(),
            "bash"
        );
        assert_eq!(
            fs::read_to_string(rootfs.join("usr/bin/foo")).unwrap(),
            "foo"
        );

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn layer_compression_from_media_type_supports_common_formats() {
        assert_eq!(
            layer_compression_from_media_type("application/vnd.oci.image.layer.v1.tar").unwrap(),
            LayerCompression::None
        );
        assert_eq!(
            layer_compression_from_media_type("application/vnd.oci.image.layer.v1.tar+gzip")
                .unwrap(),
            LayerCompression::Gzip
        );
        assert_eq!(
            layer_compression_from_media_type("application/vnd.oci.image.layer.v1.tar+zstd")
                .unwrap(),
            LayerCompression::Zstd
        );
    }

    #[test]
    fn build_guest_environment_includes_tls_paths_for_https_endpoint() {
        let config = VmDriverConfig {
            openshell_endpoint: "https://127.0.0.1:8443".to_string(),
            guest_tls_ca: Some(PathBuf::from("/host/ca.crt")),
            guest_tls_cert: Some(PathBuf::from("/host/tls.crt")),
            guest_tls_key: Some(PathBuf::from("/host/tls.key")),
            ..Default::default()
        };
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            name: "sandbox-123".to_string(),
            spec: Some(SandboxSpec::default()),
            ..Default::default()
        };

        let env = build_guest_environment(&sandbox, &config, None);
        assert!(env.contains(&format!("OPENSHELL_TLS_CA={GUEST_TLS_CA_PATH}")));
        assert!(env.contains(&format!("OPENSHELL_TLS_CERT={GUEST_TLS_CERT_PATH}")));
        assert!(env.contains(&format!("OPENSHELL_TLS_KEY={GUEST_TLS_KEY_PATH}")));
    }

    #[test]
    fn vm_driver_config_requires_tls_materials_for_https_endpoint() {
        let config = VmDriverConfig {
            openshell_endpoint: "https://127.0.0.1:8443".to_string(),
            ..Default::default()
        };
        let err = config
            .tls_paths()
            .expect_err("https endpoint should require TLS materials");
        assert!(err.contains("OPENSHELL_VM_TLS_CA"));
    }

    #[tokio::test]
    async fn delete_sandbox_keeps_registry_entry_when_cleanup_fails() {
        let base = unique_temp_dir();
        let driver_state = base.join("driver-state");
        let (events, _) = broadcast::channel(WATCH_BUFFER);
        let driver = VmDriver {
            config: VmDriverConfig {
                state_dir: driver_state.clone(),
                ..Default::default()
            },
            launcher_bin: PathBuf::from("openshell-driver-vm"),
            registry: Arc::new(Mutex::new(HashMap::new())),
            image_cache_lock: Arc::new(Mutex::new(())),
            events,
            gpu_inventory: None,
            subnet_allocator: Arc::new(std::sync::Mutex::new(SubnetAllocator::new(
                Ipv4Addr::new(10, 0, 128, 0),
                17,
            ))),
        };

        let state_file = sandbox_state_dir(&driver_state, "sandbox-123").unwrap();
        std::fs::create_dir_all(state_file.parent().unwrap()).unwrap();
        std::fs::write(&state_file, "not a directory").unwrap();

        insert_test_record(
            &driver,
            "sandbox-123",
            state_file.clone(),
            spawn_exited_child(),
        )
        .await;

        let err = driver
            .delete_sandbox("sandbox-123", "sandbox-123")
            .await
            .expect_err("state dir cleanup should fail for a file path");
        assert!(err.message().contains("not a directory"));
        assert!(driver.registry.lock().await.contains_key("sandbox-123"));

        std::fs::remove_file(&state_file).unwrap();
        let retry_state_dir = sandbox_state_dir(&driver_state, "sandbox-123").unwrap();
        std::fs::create_dir_all(&retry_state_dir).unwrap();
        {
            let mut registry = driver.registry.lock().await;
            let record = registry.get_mut("sandbox-123").unwrap();
            record.state_dir = retry_state_dir;
            record.process = Some(Arc::new(Mutex::new(VmProcess {
                child: spawn_exited_child(),
                deleting: false,
            })));
        }

        let response = driver
            .delete_sandbox("sandbox-123", "sandbox-123")
            .await
            .expect("delete retry should succeed once cleanup works");
        assert!(response.deleted);
        assert!(!driver.registry.lock().await.contains_key("sandbox-123"));

        let _ = std::fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn delete_sandbox_cleans_provisioning_record_without_process() {
        let base = unique_temp_dir();
        let driver_state = base.join("driver-state");
        let (events, _) = broadcast::channel(WATCH_BUFFER);
        let driver = VmDriver {
            config: VmDriverConfig {
                state_dir: driver_state.clone(),
                ..Default::default()
            },
            launcher_bin: PathBuf::from("openshell-driver-vm"),
            registry: Arc::new(Mutex::new(HashMap::new())),
            image_cache_lock: Arc::new(Mutex::new(())),
            events,
            gpu_inventory: None,
            subnet_allocator: Arc::new(std::sync::Mutex::new(SubnetAllocator::new(
                Ipv4Addr::new(10, 0, 128, 0),
                17,
            ))),
        };

        let state_dir = sandbox_state_dir(&driver_state, "sandbox-123").unwrap();
        std::fs::create_dir_all(&state_dir).unwrap();
        {
            let mut registry = driver.registry.lock().await;
            registry.insert(
                "sandbox-123".to_string(),
                SandboxRecord {
                    snapshot: Sandbox {
                        id: "sandbox-123".to_string(),
                        name: "sandbox-123".to_string(),
                        ..Default::default()
                    },
                    state_dir: state_dir.clone(),
                    process: None,
                    provisioning_task: None,
                    gpu_bdf: None,
                    deleting: false,
                },
            );
        }

        let response = driver
            .delete_sandbox("sandbox-123", "sandbox-123")
            .await
            .expect("delete should handle accepted-but-not-started sandboxes");
        assert!(response.deleted);
        assert!(!driver.registry.lock().await.contains_key("sandbox-123"));
        assert!(!state_dir.exists());

        let _ = std::fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn duplicate_create_keeps_existing_state_dir() {
        let base = unique_temp_dir();
        let driver_state = base.join("driver-state");
        let (events, _) = broadcast::channel(WATCH_BUFFER);
        let driver = VmDriver {
            config: VmDriverConfig {
                state_dir: driver_state.clone(),
                default_image: "ghcr.io/example/sandbox:latest".to_string(),
                ..Default::default()
            },
            launcher_bin: PathBuf::from("openshell-driver-vm"),
            registry: Arc::new(Mutex::new(HashMap::new())),
            image_cache_lock: Arc::new(Mutex::new(())),
            events,
            gpu_inventory: None,
            subnet_allocator: Arc::new(std::sync::Mutex::new(SubnetAllocator::new(
                Ipv4Addr::new(10, 0, 128, 0),
                17,
            ))),
        };

        let state_dir = sandbox_state_dir(&driver_state, "sandbox-123").unwrap();
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::write(state_dir.join("overlay.ext4"), b"live overlay").unwrap();
        {
            let mut registry = driver.registry.lock().await;
            registry.insert(
                "sandbox-123".to_string(),
                SandboxRecord {
                    snapshot: Sandbox {
                        id: "sandbox-123".to_string(),
                        name: "sandbox-123".to_string(),
                        ..Default::default()
                    },
                    state_dir: state_dir.clone(),
                    process: None,
                    provisioning_task: None,
                    gpu_bdf: None,
                    deleting: false,
                },
            );
        }

        let err = driver
            .create_sandbox(&Sandbox {
                id: "sandbox-123".to_string(),
                name: "sandbox-123".to_string(),
                spec: Some(SandboxSpec::default()),
                ..Default::default()
            })
            .await
            .expect_err("duplicate create should fail");

        assert_eq!(err.code(), Code::AlreadyExists);
        assert!(state_dir.join("overlay.ext4").exists());
        assert!(driver.registry.lock().await.contains_key("sandbox-123"));

        let _ = std::fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn remove_sandbox_state_dir_rejects_paths_outside_state_root() {
        let base = unique_temp_dir();
        let state_root = base.join("driver-state");
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).unwrap();

        let err = remove_sandbox_state_dir(&state_root, &outside)
            .await
            .expect_err("outside state paths should be rejected");
        assert!(err.message().contains("outside vm state root"));

        let _ = std::fs::remove_dir_all(base);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn remove_sandbox_state_dir_rejects_symlinked_state_dir() {
        let base = unique_temp_dir();
        let state_root = base.join("driver-state");
        let target = base.join("target");
        let state_dir = sandbox_state_dir(&state_root, "sandbox-123").unwrap();
        std::fs::create_dir_all(&target).unwrap();
        std::fs::create_dir_all(state_dir.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &state_dir).unwrap();

        let err = remove_sandbox_state_dir(&state_root, &state_dir)
            .await
            .expect_err("symlinked state dir should be rejected");
        assert!(err.message().contains("symlinked sandbox state dir"));

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn validate_openshell_endpoint_accepts_loopback_hosts() {
        validate_openshell_endpoint("http://127.0.0.1:8080")
            .expect("ipv4 loopback should be allowed for TSI");
        validate_openshell_endpoint("http://localhost:8080")
            .expect("localhost should be allowed for TSI");
        validate_openshell_endpoint("http://[::1]:8080")
            .expect("ipv6 loopback should be allowed for TSI");
    }

    #[test]
    fn validate_openshell_endpoint_rejects_unspecified_hosts() {
        let err = validate_openshell_endpoint("http://0.0.0.0:8080")
            .expect_err("unspecified endpoint should fail");
        assert!(err.contains("not reachable from sandbox VMs"));
    }

    #[test]
    fn validate_openshell_endpoint_accepts_host_gateway() {
        validate_openshell_endpoint("http://host.containers.internal:8080")
            .expect("guest-reachable host alias should be accepted");
        validate_openshell_endpoint("http://192.168.127.1:8080")
            .expect("gateway IP should be accepted");
        validate_openshell_endpoint(&format!("http://{OPENSHELL_HOST_GATEWAY_ALIAS}:8080"))
            .expect("openshell host alias should be accepted");
        validate_openshell_endpoint("https://gateway.internal:8443")
            .expect("dns endpoint should be accepted");
    }

    #[test]
    fn prepared_image_cache_identity_includes_rootfs_layout_version() {
        assert_eq!(
            prepared_image_cache_identity("sha256:local-image"),
            "sandbox-prepared-rootfs-ext4-umoci-v2:sha256:local-image"
        );
    }

    #[test]
    fn bootstrap_image_cache_identity_includes_rootfs_layout_version() {
        assert_eq!(
            bootstrap_image_cache_identity("sha256:bootstrap-image"),
            "sandbox-bootstrap-rootfs-ext4-v2:sha256:bootstrap-image"
        );
    }

    #[test]
    fn stage_guest_image_payload_copies_registry_oci_layout() {
        let base = unique_temp_dir();
        let staging_dir = base.join("staging");
        let layout_dir = base.join("layout");
        let blob_dir = layout_dir.join("blobs").join("sha256");
        fs::create_dir_all(&blob_dir).unwrap();
        fs::write(
            layout_dir.join("oci-layout"),
            r#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();
        fs::write(layout_dir.join("index.json"), "{}").unwrap();
        fs::write(blob_dir.join("abc"), "blob").unwrap();

        stage_guest_image_payload(
            &staging_dir,
            &GuestImagePayload {
                image_ref: "ghcr.io/example/app:latest".to_string(),
                image_identity: prepared_image_cache_identity("sha256:abc"),
                source: GuestImagePayloadSource::RegistryOciLayout { layout_dir },
            },
        )
        .unwrap();

        let image_dir = staging_dir.join("config").join(GUEST_IMAGE_CONFIG_DIR);
        assert_eq!(
            fs::read_to_string(image_dir.join("source")).unwrap(),
            "oci-layout"
        );
        assert_eq!(
            fs::read_to_string(image_dir.join("ref")).unwrap(),
            "ghcr.io/example/app:latest"
        );
        assert_eq!(
            fs::read_to_string(
                image_dir
                    .join(GUEST_IMAGE_OCI_LAYOUT_DIR)
                    .join("blobs")
                    .join("sha256")
                    .join("abc")
            )
            .unwrap(),
            "blob"
        );

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn registry_layer_download_concurrency_is_bounded() {
        assert_eq!(
            registry_layer_download_concurrency_value(None),
            DEFAULT_REGISTRY_LAYER_DOWNLOAD_CONCURRENCY
        );
        assert_eq!(
            registry_layer_download_concurrency_value(Some("0")),
            DEFAULT_REGISTRY_LAYER_DOWNLOAD_CONCURRENCY
        );
        assert_eq!(registry_layer_download_concurrency_value(Some("8")), 8);
        assert_eq!(
            registry_layer_download_concurrency_value(Some("999")),
            MAX_REGISTRY_LAYER_DOWNLOAD_CONCURRENCY
        );
    }

    #[test]
    fn sanitize_image_identity_rewrites_path_separators() {
        assert_eq!(
            sanitize_image_identity("sha256:abc/def@ghi"),
            "sha256-abc-def-ghi"
        );
    }

    #[tokio::test]
    async fn read_guest_tls_materials_reports_missing_input() {
        let base = unique_temp_dir();
        let source_dir = base.join("missing-source");

        let err = read_guest_tls_materials(&VmDriverTlsPaths {
            ca: source_dir.join("ca.crt"),
            cert: source_dir.join("tls.crt"),
            key: source_dir.join("tls.key"),
        })
        .await
        .expect_err("missing TLS materials should fail before image injection");

        assert!(err.contains("ca.crt"));

        let _ = std::fs::remove_dir_all(base);
    }

    #[cfg(unix)]
    #[test]
    fn stage_guest_tls_materials_places_files_in_overlay_upper_with_private_key_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let base = unique_temp_dir();
        let materials = GuestTlsMaterials {
            ca: b"ca".to_vec(),
            cert: b"cert".to_vec(),
            key: b"key".to_vec(),
        };

        stage_guest_tls_materials(&base, &materials).expect("stage TLS materials");

        assert_eq!(
            fs::read(
                base.join("upper")
                    .join(GUEST_TLS_CA_PATH.trim_start_matches('/'))
            )
            .unwrap(),
            b"ca"
        );
        assert_eq!(
            fs::read(
                base.join("upper")
                    .join(GUEST_TLS_CERT_PATH.trim_start_matches('/'))
            )
            .unwrap(),
            b"cert"
        );
        let key_path = base
            .join("upper")
            .join(GUEST_TLS_KEY_PATH.trim_start_matches('/'));
        assert_eq!(fs::read(&key_path).unwrap(), b"key");
        assert_eq!(
            fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn subnet_allocator_assigns_and_releases() {
        let mut alloc = SubnetAllocator::new(Ipv4Addr::new(10, 0, 128, 0), 17);
        let s1 = alloc.allocate("sandbox-1").unwrap();
        assert_eq!(s1.host_ip, Ipv4Addr::new(10, 0, 128, 1));
        assert_eq!(s1.guest_ip, Ipv4Addr::new(10, 0, 128, 2));
        assert_eq!(s1.prefix_len, 30);

        let s2 = alloc.allocate("sandbox-2").unwrap();
        assert_ne!(s1.host_ip, s2.host_ip);

        alloc.release("sandbox-1");
        let s3 = alloc.allocate("sandbox-3").unwrap();
        assert!(s3.host_ip != s2.host_ip);
    }

    #[test]
    fn tap_device_name_fits_ifnamsiz() {
        let name = tap_device_name("sandbox-abc-def-ghi");
        assert!(name.len() <= 15);
        assert!(name.starts_with("vmtap-"));
    }

    #[test]
    fn mac_address_is_locally_administered() {
        let mac = mac_from_sandbox_id("test-sandbox");
        assert_eq!(mac[0] & 0x02, 0x02);
        assert_eq!(mac[0] & 0x01, 0x00);
    }

    #[test]
    fn vsock_cid_monotonically_increases() {
        let cid1 = allocate_vsock_cid();
        let cid2 = allocate_vsock_cid();
        assert!(cid2 > cid1);
    }

    fn unique_temp_dir() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let suffix = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "openshell-vm-driver-test-{}-{nanos}-{suffix}",
            std::process::id()
        ))
    }

    fn spawn_exited_child() -> Child {
        Command::new("sh")
            .arg("-c")
            .arg("exit 0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    async fn insert_test_record(
        driver: &VmDriver,
        sandbox_id: &str,
        state_dir: PathBuf,
        child: Child,
    ) {
        let sandbox = Sandbox {
            id: sandbox_id.to_string(),
            name: sandbox_id.to_string(),
            ..Default::default()
        };
        let process = Arc::new(Mutex::new(VmProcess {
            child,
            deleting: false,
        }));

        let mut registry = driver.registry.lock().await;
        registry.insert(
            sandbox_id.to_string(),
            SandboxRecord {
                snapshot: sandbox,
                state_dir,
                process: Some(process),
                provisioning_task: None,
                gpu_bdf: None,
                deleting: false,
            },
        );
    }
}
