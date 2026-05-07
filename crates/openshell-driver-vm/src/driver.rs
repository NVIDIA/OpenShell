// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::gpu::{
    GpuInventory, SubnetAllocator, allocate_vsock_cid, mac_from_sandbox_id, tap_device_name,
};
use crate::rootfs::{
    create_rootfs_archive_from_dir, extract_rootfs_archive_to,
    prepare_sandbox_rootfs_from_image_root, sandbox_guest_init_path,
};
use bollard::Docker;
use bollard::errors::Error as BollardError;
use bollard::models::ContainerCreateBody;
use bollard::query_parameters::{CreateContainerOptionsBuilder, RemoveContainerOptionsBuilder};
use flate2::read::GzDecoder;
use futures::{Stream, StreamExt};
use nix::errno::Errno;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use oci_client::client::{Client as OciClient, ClientConfig};
use oci_client::manifest::{ImageIndexEntry, OciDescriptor};
use oci_client::secrets::RegistryAuth;
use oci_client::{Reference, RegistryOperation};
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
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};
use url::{Host, Url};

const DRIVER_NAME: &str = "openshell-driver-vm";
const WATCH_BUFFER: usize = 256;
const DEFAULT_VCPUS: u8 = 2;
const DEFAULT_MEM_MIB: u32 = 2048;
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
const GUEST_TLS_DIR: &str = "/opt/openshell/tls";
const GUEST_TLS_CA_PATH: &str = "/opt/openshell/tls/ca.crt";
const GUEST_TLS_CERT_PATH: &str = "/opt/openshell/tls/tls.crt";
const GUEST_TLS_KEY_PATH: &str = "/opt/openshell/tls/tls.key";
const IMAGE_CACHE_ROOT_DIR: &str = "images";
const IMAGE_CACHE_ROOTFS_ARCHIVE: &str = "rootfs.tar";
const IMAGE_EXPORT_ROOTFS_ARCHIVE: &str = "source-rootfs.tar";
const IMAGE_IDENTITY_FILE: &str = "image-identity";
const IMAGE_REFERENCE_FILE: &str = "image-reference";
static IMAGE_CACHE_BUILD_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
struct VmDriverTlsPaths {
    ca: PathBuf,
    cert: PathBuf,
    key: PathBuf,
}

#[derive(Debug, Clone)]
pub struct VmDriverConfig {
    pub openshell_endpoint: String,
    pub state_dir: PathBuf,
    pub launcher_bin: Option<PathBuf>,
    pub default_image: String,
    pub ssh_handshake_secret: String,
    pub ssh_handshake_skew_secs: u64,
    pub log_level: String,
    pub krun_log_level: u32,
    pub vcpus: u8,
    pub mem_mib: u32,
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
            ssh_handshake_secret: String::new(),
            ssh_handshake_skew_secs: 300,
            log_level: "info".to_string(),
            krun_log_level: 1,
            vcpus: DEFAULT_VCPUS,
            mem_mib: DEFAULT_MEM_MIB,
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

#[derive(Debug)]
struct SandboxRecord {
    snapshot: Sandbox,
    state_dir: PathBuf,
    process: Arc<Mutex<VmProcess>>,
    gpu_bdf: Option<String>,
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
        tokio::fs::create_dir_all(&state_root)
            .await
            .map_err(|err| {
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
        Ok(Self {
            config,
            launcher_bin,
            registry: Arc::new(Mutex::new(HashMap::new())),
            image_cache_lock: Arc::new(Mutex::new(())),
            events,
            gpu_inventory,
            subnet_allocator,
        })
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

        if self.registry.lock().await.contains_key(&sandbox.id) {
            return Err(Status::already_exists("sandbox already exists"));
        }

        let spec = sandbox.spec.as_ref();
        let is_gpu = spec.is_some_and(|s| s.gpu);
        let gpu_device = spec.map_or("", |s| s.gpu_device.as_str());

        let state_dir = sandbox_state_dir(&self.config.state_dir, &sandbox.id);
        let rootfs = state_dir.join("rootfs");
        let image_ref = self.resolved_sandbox_image(sandbox).ok_or_else(|| {
            Status::failed_precondition(
                "vm sandboxes require template.image or a configured default sandbox image",
            )
        })?;
        info!(
            sandbox_id = %sandbox.id,
            image_ref = %image_ref,
            state_dir = %state_dir.display(),
            "vm driver: resolved image ref, preparing rootfs"
        );

        tokio::fs::create_dir_all(&state_dir)
            .await
            .map_err(|err| Status::internal(format!("create state dir failed: {err}")))?;

        let tls_paths = self
            .config
            .tls_paths()
            .map_err(Status::failed_precondition)?;
        // Mirror the K8s `Scheduled` event so the CLI can complete the
        // "Requesting sandbox" step and switch the spinner over to the
        // image-pull phase before we block on the registry.
        self.publish_platform_event(
            sandbox.id.clone(),
            platform_event(
                "vm",
                "Normal",
                "Scheduled",
                format!("Sandbox accepted by vm driver to image \"{image_ref}\""),
            ),
        );

        let image_identity = match self
            .prepare_runtime_rootfs(&sandbox.id, &image_ref, &rootfs)
            .await
        {
            Ok(image_identity) => {
                info!(
                    sandbox_id = %sandbox.id,
                    image_identity = %image_identity,
                    "vm driver: rootfs prepared"
                );
                image_identity
            }
            Err(err) => {
                warn!(
                    sandbox_id = %sandbox.id,
                    error = %err.message(),
                    "vm driver: rootfs preparation failed"
                );
                let _ = tokio::fs::remove_dir_all(&state_dir).await;
                return Err(err);
            }
        };
        if let Some(tls_paths) = tls_paths.as_ref()
            && let Err(err) = prepare_guest_tls_materials(&rootfs, tls_paths).await
        {
            let _ = tokio::fs::remove_dir_all(&state_dir).await;
            return Err(Status::internal(format!(
                "prepare guest TLS materials failed: {err}"
            )));
        }

        if let Err(err) =
            write_sandbox_image_metadata(&state_dir, &image_ref, &image_identity).await
        {
            let _ = tokio::fs::remove_dir_all(&state_dir).await;
            return Err(Status::internal(format!(
                "write sandbox image metadata failed: {err}"
            )));
        }

        let gpu_bdf = if is_gpu {
            let inventory = self
                .gpu_inventory
                .as_ref()
                .ok_or_else(|| Status::internal("GPU inventory not initialized"))?;
            match inventory
                .lock()
                .map_err(|e| Status::internal(format!("GPU inventory lock poisoned: {e}")))
                .and_then(|mut inv| {
                    inv.assign(&sandbox.id, gpu_device)
                        .map_err(Status::failed_precondition)
                }) {
                Ok(assignment) => {
                    tracing::info!(
                        sandbox_id = %sandbox.id,
                        bdf = %assignment.bdf,
                        gpu_name = %assignment.name,
                        iommu_group = assignment.iommu_group,
                        "assigned GPU to sandbox"
                    );
                    Some(assignment.bdf)
                }
                Err(err) => {
                    let _ = tokio::fs::remove_dir_all(&state_dir).await;
                    return Err(err);
                }
            }
        } else {
            None
        };

        let console_output = state_dir.join("rootfs-console.log");
        let mut command = Command::new(&self.launcher_bin);
        command.stdin(Stdio::null());
        command.stdout(Stdio::inherit());
        command.stderr(Stdio::inherit());
        command.arg("--internal-run-vm");
        command.arg("--vm-rootfs").arg(&rootfs);
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
                    let _ = tokio::fs::remove_dir_all(&state_dir).await;
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

        command
            .arg("--vm-krun-log-level")
            .arg(self.config.krun_log_level.to_string());

        for env in build_guest_environment(sandbox, &self.config, endpoint_override.as_deref()) {
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
                let _ = tokio::fs::remove_dir_all(&state_dir).await;
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
        // Mirror the K8s `Started` event so the CLI can complete the
        // "Starting sandbox" step. The supervisor-ready transition still
        // promotes the sandbox to `Ready` separately.
        self.publish_platform_event(
            sandbox.id.clone(),
            platform_event("vm", "Normal", "Started", "Started VM launcher".to_string()),
        );
        let snapshot = sandbox_snapshot(sandbox, provisioning_condition(), false);
        let process = Arc::new(Mutex::new(VmProcess {
            child,
            deleting: false,
        }));

        {
            let mut registry = self.registry.lock().await;
            registry.insert(
                sandbox.id.clone(),
                SandboxRecord {
                    snapshot: snapshot.clone(),
                    state_dir: state_dir.clone(),
                    process: process.clone(),
                    gpu_bdf: gpu_bdf.clone(),
                },
            );
        }

        self.publish_snapshot(snapshot.clone());
        tokio::spawn({
            let driver = self.clone();
            let sandbox_id = sandbox.id.clone();
            async move {
                driver.monitor_sandbox(sandbox_id).await;
            }
        });

        Ok(CreateSandboxResponse {})
    }

    pub async fn delete_sandbox(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<DeleteSandboxResponse, Status> {
        let record = {
            let registry = self.registry.lock().await;
            if let Some((id, record)) = registry.get_key_value(sandbox_id) {
                Some((
                    id.clone(),
                    record.state_dir.clone(),
                    record.process.clone(),
                    record.gpu_bdf.clone(),
                ))
            } else {
                let matched_id = registry
                    .iter()
                    .find(|(_, record)| record.snapshot.name == sandbox_name)
                    .map(|(id, _)| id.clone());
                matched_id.and_then(|id| {
                    registry.get(&id).map(|record| {
                        (
                            id,
                            record.state_dir.clone(),
                            record.process.clone(),
                            record.gpu_bdf.clone(),
                        )
                    })
                })
            }
        };

        let Some((record_id, state_dir, process, gpu_bdf)) = record else {
            return Ok(DeleteSandboxResponse { deleted: false });
        };

        if let Some(snapshot) = self
            .set_snapshot_condition(&record_id, deleting_condition(), true)
            .await
        {
            self.publish_snapshot(snapshot);
        }

        {
            let mut process = process.lock().await;
            process.deleting = true;
            terminate_vm_process(&mut process.child)
                .await
                .map_err(|err| Status::internal(format!("failed to stop vm: {err}")))?;
        }

        if gpu_bdf.is_some() {
            self.release_gpu_and_subnet(&record_id);
        }

        if let Err(err) = tokio::fs::remove_dir_all(&state_dir).await
            && err.kind() != std::io::ErrorKind::NotFound
        {
            return Err(Status::internal(format!(
                "failed to remove state dir: {err}"
            )));
        }

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

    async fn prepare_runtime_rootfs(
        &self,
        sandbox_id: &str,
        image_ref: &str,
        rootfs: &Path,
    ) -> Result<String, Status> {
        let image_identity = self
            .ensure_cached_image_rootfs_archive(sandbox_id, image_ref)
            .await?;
        let archive_path = image_cache_rootfs_archive(&self.config.state_dir, &image_identity);
        let rootfs_dest = rootfs.to_path_buf();
        tokio::task::spawn_blocking(move || extract_rootfs_archive_to(&archive_path, &rootfs_dest))
            .await
            .map_err(|err| Status::internal(format!("sandbox rootfs extraction panicked: {err}")))?
            .map_err(|err| Status::internal(format!("extract sandbox rootfs failed: {err}")))?;

        Ok(image_identity)
    }

    fn resolved_sandbox_image(&self, sandbox: &Sandbox) -> Option<String> {
        requested_sandbox_image(sandbox)
            .map(ToOwned::to_owned)
            .or_else(|| {
                let image = self.config.default_image.trim();
                (!image.is_empty()).then(|| image.to_string())
            })
    }

    async fn ensure_cached_image_rootfs_archive(
        &self,
        sandbox_id: &str,
        image_ref: &str,
    ) -> Result<String, Status> {
        if let Some((docker, image_identity)) = self.resolve_local_docker_image(image_ref).await? {
            return self
                .ensure_cached_local_image_rootfs_archive(
                    sandbox_id,
                    image_ref,
                    &docker,
                    &image_identity,
                )
                .await;
        }

        info!(image_ref = %image_ref, "vm driver: ensuring cached image rootfs archive (registry)");
        let reference = parse_registry_reference(image_ref)?;
        let client = registry_client();
        let auth = registry_auth(image_ref)?;
        info!(image_ref = %image_ref, "vm driver: authenticating with registry");
        client
            .auth(&reference, &auth, RegistryOperation::Pull)
            .await
            .map_err(|err| {
                Status::failed_precondition(format!(
                    "failed to authenticate registry access for vm sandbox image '{image_ref}': {err}"
                ))
            })?;
        info!(image_ref = %image_ref, "vm driver: fetching manifest digest");
        let image_identity = client
            .fetch_manifest_digest(&reference, &auth)
            .await
            .map_err(|err| {
                Status::failed_precondition(format!(
                    "failed to resolve vm sandbox image '{image_ref}': {err}"
                ))
            })?;
        info!(
            image_ref = %image_ref,
            image_identity = %image_identity,
            "vm driver: manifest digest resolved"
        );
        let archive_path = image_cache_rootfs_archive(&self.config.state_dir, &image_identity);

        // Mirror the K8s `Pulling` event so the CLI flips to the
        // image-pull spinner with the image name as detail. We emit it
        // for cache hits too and immediately follow with `Pulled` so the
        // spinner step still advances cleanly.
        self.publish_platform_event(
            sandbox_id.to_string(),
            platform_event(
                "vm",
                "Normal",
                "Pulling",
                format!("Pulling image \"{image_ref}\""),
            ),
        );

        if tokio::fs::metadata(&archive_path).await.is_ok() {
            info!(
                image_identity = %image_identity,
                archive_path = %archive_path.display(),
                "vm driver: image rootfs archive cache hit (no build needed)"
            );
            self.publish_pulled_event(sandbox_id, image_ref, &archive_path)
                .await;
            return Ok(image_identity);
        }

        info!(
            image_identity = %image_identity,
            "vm driver: image rootfs archive cache miss, acquiring build lock"
        );
        let _cache_guard = self.image_cache_lock.lock().await;
        info!(
            image_identity = %image_identity,
            "vm driver: build lock acquired"
        );
        if tokio::fs::metadata(&archive_path).await.is_ok() {
            info!(
                image_identity = %image_identity,
                "vm driver: image rootfs archive cache hit after lock (built by another task)"
            );
            self.publish_pulled_event(sandbox_id, image_ref, &archive_path)
                .await;
            return Ok(image_identity);
        }

        self.build_cached_registry_image_rootfs_archive(
            sandbox_id,
            &client,
            &reference,
            &auth,
            image_ref,
            &image_identity,
        )
        .await?;
        self.publish_pulled_event(sandbox_id, image_ref, &archive_path)
            .await;
        Ok(image_identity)
    }

    async fn resolve_local_docker_image(
        &self,
        image_ref: &str,
    ) -> Result<Option<(Docker, String)>, Status> {
        let required_local_image = is_openshell_local_build_image_ref(image_ref);
        let docker = match Docker::connect_with_local_defaults() {
            Ok(docker) => docker,
            Err(err) if required_local_image => {
                return Err(Status::failed_precondition(format!(
                    "failed to connect to local Docker daemon for locally built sandbox image '{image_ref}': {err}"
                )));
            }
            Err(err) => {
                warn!(
                    image_ref = %image_ref,
                    error = %err,
                    "vm driver: local Docker daemon unavailable, falling back to registry"
                );
                return Ok(None);
            }
        };

        match docker.inspect_image(image_ref).await {
            Ok(inspect) => {
                if let Some(message) = local_docker_image_platform_mismatch(
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
                        "vm driver: local Docker image platform mismatch, falling back to registry"
                    );
                    return Ok(None);
                }

                let image_identity =
                    inspect
                        .id
                        .filter(|id| !id.trim().is_empty())
                        .ok_or_else(|| {
                            Status::failed_precondition(format!(
                                "local Docker image '{image_ref}' inspect response has no image ID"
                            ))
                        })?;
                info!(
                    image_ref = %image_ref,
                    image_identity = %image_identity,
                    "vm driver: resolved image from local Docker daemon"
                );
                Ok(Some((docker, image_identity)))
            }
            Err(err) if is_docker_not_found_error(&err) && required_local_image => {
                Err(Status::failed_precondition(format!(
                    "locally built sandbox image '{image_ref}' is not present in the local Docker daemon"
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
                    "vm driver: local Docker image inspection failed, falling back to registry"
                );
                Ok(None)
            }
        }
    }

    async fn ensure_cached_local_image_rootfs_archive(
        &self,
        sandbox_id: &str,
        image_ref: &str,
        docker: &Docker,
        image_identity: &str,
    ) -> Result<String, Status> {
        let archive_path = image_cache_rootfs_archive(&self.config.state_dir, image_identity);

        self.publish_platform_event(
            sandbox_id.to_string(),
            platform_event(
                "vm",
                "Normal",
                "Pulling",
                format!("Pulling image \"{image_ref}\""),
            ),
        );

        if tokio::fs::metadata(&archive_path).await.is_ok() {
            self.publish_pulled_event(sandbox_id, image_ref, &archive_path)
                .await;
            return Ok(image_identity.to_string());
        }

        let _cache_guard = self.image_cache_lock.lock().await;
        if tokio::fs::metadata(&archive_path).await.is_ok() {
            self.publish_pulled_event(sandbox_id, image_ref, &archive_path)
                .await;
            return Ok(image_identity.to_string());
        }

        self.build_cached_local_image_rootfs_archive(docker, image_ref, image_identity)
            .await?;
        self.publish_pulled_event(sandbox_id, image_ref, &archive_path)
            .await;
        Ok(image_identity.to_string())
    }

    async fn build_cached_local_image_rootfs_archive(
        &self,
        docker: &Docker,
        image_ref: &str,
        image_identity: &str,
    ) -> Result<(), Status> {
        let cache_dir = image_cache_dir(&self.config.state_dir, image_identity);
        let archive_path = image_cache_rootfs_archive(&self.config.state_dir, image_identity);
        let staging_dir = image_cache_staging_dir(&self.config.state_dir, image_identity);
        let exported_rootfs = staging_dir.join(IMAGE_EXPORT_ROOTFS_ARCHIVE);
        let prepared_rootfs = staging_dir.join("rootfs");
        let prepared_archive = staging_dir.join(IMAGE_CACHE_ROOTFS_ARCHIVE);

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
        let prepared_archive_for_build = prepared_archive.clone();
        let build_result = tokio::task::spawn_blocking(move || {
            prepare_exported_rootfs_archive(
                &image_ref_owned,
                &image_identity_owned,
                &exported_rootfs_for_build,
                &prepared_rootfs_for_build,
                &prepared_archive_for_build,
            )
        })
        .await
        .map_err(|err| Status::internal(format!("local image preparation panicked: {err}")))?;

        if let Err(err) = build_result {
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Err(Status::failed_precondition(err));
        }

        if tokio::fs::metadata(&archive_path).await.is_ok() {
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Ok(());
        }

        tokio::fs::rename(&prepared_archive, &archive_path)
            .await
            .map_err(|err| Status::internal(format!("store cached image rootfs failed: {err}")))?;
        let _ = tokio::fs::remove_dir_all(&staging_dir).await;
        Ok(())
    }

    async fn build_cached_registry_image_rootfs_archive(
        &self,
        sandbox_id: &str,
        client: &OciClient,
        reference: &Reference,
        auth: &RegistryAuth,
        image_ref: &str,
        image_identity: &str,
    ) -> Result<(), Status> {
        let cache_dir = image_cache_dir(&self.config.state_dir, image_identity);
        let archive_path = image_cache_rootfs_archive(&self.config.state_dir, image_identity);
        let staging_dir = image_cache_staging_dir(&self.config.state_dir, image_identity);
        let prepared_rootfs = staging_dir.join("rootfs");
        let prepared_archive = staging_dir.join(IMAGE_CACHE_ROOTFS_ARCHIVE);

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
            "vm driver: image layers pulled, preparing rootfs archive"
        );

        let image_ref_owned = image_ref.to_string();
        let image_identity_owned = image_identity.to_string();
        let prepared_rootfs_for_build = prepared_rootfs.clone();
        let prepared_archive_for_build = prepared_archive.clone();
        let build_result = tokio::task::spawn_blocking(move || {
            prepare_sandbox_rootfs_from_image_root(
                &prepared_rootfs_for_build,
                &image_identity_owned,
            )
            .map_err(|err| {
                format!("vm sandbox image '{image_ref_owned}' is not base-compatible: {err}")
            })?;
            create_rootfs_archive_from_dir(&prepared_rootfs_for_build, &prepared_archive_for_build)
        })
        .await
        .map_err(|err| Status::internal(format!("image rootfs preparation panicked: {err}")))?;

        if let Err(err) = build_result {
            warn!(
                image_ref = %image_ref,
                error = %err,
                "vm driver: rootfs archive build failed"
            );
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Err(Status::failed_precondition(err));
        }

        if tokio::fs::metadata(&archive_path).await.is_ok() {
            info!(
                image_identity = %image_identity,
                "vm driver: another task wrote archive while we were building, discarding ours"
            );
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Ok(());
        }

        tokio::fs::rename(&prepared_archive, &archive_path)
            .await
            .map_err(|err| Status::internal(format!("store cached image rootfs failed: {err}")))?;
        info!(
            image_identity = %image_identity,
            archive_path = %archive_path.display(),
            "vm driver: image rootfs archive committed to cache"
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
                record.process.clone()
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
        if template.resources.is_some() {
            return Err(Status::failed_precondition(
                "vm sandboxes do not support template.resources",
            ));
        }
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

fn is_openshell_local_build_image_ref(image_ref: &str) -> bool {
    image_ref.starts_with("openshell/sandbox-from:")
}

fn local_docker_image_platform_mismatch(
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

fn prepare_exported_rootfs_archive(
    image_ref: &str,
    image_identity: &str,
    exported_rootfs: &Path,
    prepared_rootfs: &Path,
    prepared_archive: &Path,
) -> Result<(), String> {
    extract_rootfs_archive_to(exported_rootfs, prepared_rootfs)?;
    prepare_sandbox_rootfs_from_image_root(prepared_rootfs, image_identity)
        .map_err(|err| format!("vm sandbox image '{image_ref}' is not base-compatible: {err}"))?;
    create_rootfs_archive_from_dir(prepared_rootfs, prepared_archive)
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
        for (index, layer) in manifest.layers.iter().enumerate() {
            // Emit a per-layer progress event so the CLI can show
            // "Layer 3/8 (12.4 MB)" as detail under the spinner.
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
            self.publish_platform_event(sandbox_id.to_string(), event);

            pull_registry_layer(
                client,
                reference,
                image_ref,
                staging_dir,
                rootfs,
                layer,
                index,
            )
            .await?;
        }

        Ok(())
    }

    /// Emit a `Pulled` platform event with a message that mirrors the
    /// kubelet's `Successfully pulled image ... Image size: N bytes.`
    /// format so the CLI's `extract_image_size` parser works unchanged.
    async fn publish_pulled_event(&self, sandbox_id: &str, image_ref: &str, archive_path: &Path) {
        let size_suffix = tokio::fs::metadata(archive_path).await.map_or_else(
            |_| String::new(),
            |meta| format!(" Image size: {} bytes.", meta.len()),
        );
        self.publish_platform_event(
            sandbox_id.to_string(),
            platform_event(
                "vm",
                "Normal",
                "Pulled",
                format!("Successfully pulled image \"{image_ref}\".{size_suffix}"),
            ),
        );
    }
}

async fn pull_registry_layer(
    client: &OciClient,
    reference: &Reference,
    image_ref: &str,
    staging_dir: &Path,
    rootfs: &Path,
    layer: &OciDescriptor,
    index: usize,
) -> Result<(), Status> {
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
        .pull_blob(reference, layer, &mut file)
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
    let rootfs_for_unpack = rootfs.to_path_buf();
    let media_type = layer.media_type.clone();
    tokio::task::spawn_blocking(move || {
        extract_layer_blob_to_dir(&blob_path_for_unpack, &media_type, &layer_root_for_unpack)?;
        apply_layer_dir_to_rootfs(&layer_root_for_unpack, &rootfs_for_unpack)
    })
    .await
    .map_err(|err| Status::internal(format!("layer extraction panicked: {err}")))?
    .map_err(|err| {
        Status::failed_precondition(format!(
            "failed to apply layer '{}' for vm sandbox image '{image_ref}': {err}",
            layer.digest
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
        ("OPENSHELL_ENDPOINT".to_string(), openshell_endpoint),
        ("OPENSHELL_SANDBOX_ID".to_string(), sandbox.id.clone()),
        ("OPENSHELL_SANDBOX".to_string(), sandbox.name.clone()),
        (
            "OPENSHELL_SSH_SOCKET_PATH".to_string(),
            GUEST_SSH_SOCKET_PATH.to_string(),
        ),
        (
            "OPENSHELL_SANDBOX_COMMAND".to_string(),
            "tail -f /dev/null".to_string(),
        ),
        (
            "OPENSHELL_LOG_LEVEL".to_string(),
            sandbox_log_level(sandbox, &config.log_level),
        ),
        (
            "OPENSHELL_SSH_HANDSHAKE_SECRET".to_string(),
            config.ssh_handshake_secret.clone(),
        ),
    ]);
    if config.requires_tls_materials() {
        environment.extend(HashMap::from([
            (
                "OPENSHELL_TLS_CA".to_string(),
                GUEST_TLS_CA_PATH.to_string(),
            ),
            (
                "OPENSHELL_TLS_CERT".to_string(),
                GUEST_TLS_CERT_PATH.to_string(),
            ),
            (
                "OPENSHELL_TLS_KEY".to_string(),
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

fn sandbox_log_level(sandbox: &Sandbox, default_level: &str) -> String {
    sandbox
        .spec
        .as_ref()
        .map(|spec| spec.log_level.as_str())
        .filter(|level| !level.is_empty())
        .unwrap_or(default_level)
        .to_string()
}

fn sandboxes_root_dir(root: &Path) -> PathBuf {
    root.join("sandboxes")
}

fn sandbox_state_dir(root: &Path, sandbox_id: &str) -> PathBuf {
    sandboxes_root_dir(root).join(sandbox_id)
}

fn image_cache_root_dir(root: &Path) -> PathBuf {
    root.join(IMAGE_CACHE_ROOT_DIR)
}

fn image_cache_dir(root: &Path, image_identity: &str) -> PathBuf {
    image_cache_root_dir(root).join(sanitize_image_identity(image_identity))
}

fn image_cache_rootfs_archive(root: &Path, image_identity: &str) -> PathBuf {
    image_cache_dir(root, image_identity).join(IMAGE_CACHE_ROOTFS_ARCHIVE)
}

fn image_cache_staging_dir(root: &Path, image_identity: &str) -> PathBuf {
    image_cache_root_dir(root).join(format!(
        "{}.staging-{}",
        sanitize_image_identity(image_identity),
        unique_image_cache_suffix()
    ))
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
    format!("{}-{counter}", current_time_ms())
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

async fn prepare_guest_tls_materials(
    rootfs: &Path,
    paths: &VmDriverTlsPaths,
) -> Result<(), std::io::Error> {
    let guest_tls_dir = rootfs.join(GUEST_TLS_DIR.trim_start_matches('/'));
    tokio::fs::create_dir_all(&guest_tls_dir).await?;

    copy_guest_tls_material(&paths.ca, &guest_tls_dir.join("ca.crt"), 0o644).await?;
    copy_guest_tls_material(&paths.cert, &guest_tls_dir.join("tls.crt"), 0o644).await?;
    copy_guest_tls_material(&paths.key, &guest_tls_dir.join("tls.key"), 0o600).await?;
    Ok(())
}

async fn copy_guest_tls_material(
    source: &Path,
    dest: &Path,
    mode: u32,
) -> Result<(), std::io::Error> {
    tokio::fs::copy(source, dest).await?;
    tokio::fs::set_permissions(dest, fs::Permissions::from_mode(mode)).await?;
    Ok(())
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
    PlatformEvent {
        timestamp_ms: current_time_ms(),
        source: source.to_string(),
        r#type: event_type.to_string(),
        reason: reason.to_string(),
        message,
        metadata: HashMap::new(),
    }
}

fn current_time_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpu::{SubnetAllocator, allocate_vsock_cid, mac_from_sandbox_id, tap_device_name};
    use openshell_core::proto::compute::v1::{
        DriverSandboxSpec as SandboxSpec, DriverSandboxTemplate as SandboxTemplate,
    };
    use prost_types::{Struct, Value, value::Kind};
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tonic::Code;

    #[test]
    fn validate_vm_sandbox_rejects_gpu_when_not_enabled() {
        let sandbox = Sandbox {
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
            ssh_handshake_secret: "secret".to_string(),
            ..Default::default()
        };
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            name: "sandbox-123".to_string(),
            spec: Some(SandboxSpec::default()),
            ..Default::default()
        };

        let env = build_guest_environment(&sandbox, &config, None);
        assert!(env.contains(&"HOME=/root".to_string()));
        assert!(env.contains(&format!(
            "OPENSHELL_ENDPOINT=http://{GVPROXY_HOST_LOOPBACK_ALIAS}:8080/"
        )));
        assert!(env.contains(&"OPENSHELL_SANDBOX_ID=sandbox-123".to_string()));
        assert!(env.contains(&format!(
            "OPENSHELL_SSH_SOCKET_PATH={GUEST_SSH_SOCKET_PATH}"
        )));
        assert!(
            env.contains(&"OPENSHELL_SSH_HANDSHAKE_SECRET=secret".to_string()),
            "SSH handshake secret must be passed to the guest"
        );
    }

    #[test]
    fn build_guest_environment_uses_endpoint_override_for_tap() {
        let config = VmDriverConfig {
            openshell_endpoint: "http://127.0.0.1:8080".to_string(),
            ssh_handshake_secret: "secret".to_string(),
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
    fn local_docker_image_platform_mismatch_checks_guest_platform() {
        assert!(
            local_docker_image_platform_mismatch(
                "openshell/sandbox-from:123",
                Some("linux"),
                Some(linux_oci_arch()),
            )
            .is_none()
        );

        let err = local_docker_image_platform_mismatch(
            "openshell/sandbox-from:123",
            Some("linux"),
            Some("wrong-arch"),
        )
        .expect("architecture mismatch should be reported");
        assert!(err.contains("wrong-arch"));
        assert!(err.contains(linux_oci_arch()));

        let err = local_docker_image_platform_mismatch("openshell/sandbox-from:123", None, None)
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
            ssh_handshake_secret: "secret".to_string(),
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
        let (events, _) = broadcast::channel(WATCH_BUFFER);
        let driver = VmDriver {
            config: VmDriverConfig::default(),
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

        let base = unique_temp_dir();
        std::fs::create_dir_all(&base).unwrap();
        let state_file = base.join("state-file");
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
        assert!(err.message().contains("failed to remove state dir"));
        assert!(driver.registry.lock().await.contains_key("sandbox-123"));

        let retry_state_dir = base.join("state-dir");
        std::fs::create_dir_all(&retry_state_dir).unwrap();
        {
            let mut registry = driver.registry.lock().await;
            let record = registry.get_mut("sandbox-123").unwrap();
            record.state_dir = retry_state_dir;
            record.process = Arc::new(Mutex::new(VmProcess {
                child: spawn_exited_child(),
                deleting: false,
            }));
        }

        let response = driver
            .delete_sandbox("sandbox-123", "sandbox-123")
            .await
            .expect("delete retry should succeed once cleanup works");
        assert!(response.deleted);
        assert!(!driver.registry.lock().await.contains_key("sandbox-123"));

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
    fn prepare_exported_rootfs_archive_rewrites_docker_exported_rootfs() {
        let base = unique_temp_dir();
        let source_rootfs = base.join("source-rootfs");
        let exported_rootfs = base.join("exported-rootfs.tar");
        let prepared_rootfs = base.join("prepared-rootfs");
        let prepared_archive = base.join("prepared-rootfs.tar");
        let extracted = base.join("extracted");

        for path in [
            "bin/bash",
            "bin/mount",
            "bin/sed",
            "sbin/ip",
            "opt/openshell/bin/openshell-sandbox",
        ] {
            let path = source_rootfs.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, "").unwrap();
        }

        create_rootfs_archive_from_dir(&source_rootfs, &exported_rootfs).unwrap();
        prepare_exported_rootfs_archive(
            "openshell/sandbox-from:123",
            "sha256:local-image",
            &exported_rootfs,
            &prepared_rootfs,
            &prepared_archive,
        )
        .unwrap();
        extract_rootfs_archive_to(&prepared_archive, &extracted).unwrap();

        assert!(extracted.join("srv/openshell-vm-sandbox-init.sh").is_file());
        assert!(
            extracted
                .join("opt/openshell/bin/openshell-sandbox")
                .is_file()
        );
        assert_eq!(
            fs::read_to_string(extracted.join("opt/openshell/.rootfs-type")).unwrap(),
            "sandbox\n"
        );
        assert!(
            fs::read_to_string(extracted.join(".openshell-rootfs-variant"))
                .unwrap()
                .contains("sha256:local-image")
        );

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn sanitize_image_identity_rewrites_path_separators() {
        assert_eq!(
            sanitize_image_identity("sha256:abc/def@ghi"),
            "sha256-abc-def-ghi"
        );
    }

    #[tokio::test]
    async fn prepare_guest_tls_materials_copies_bundle_into_rootfs() {
        let base = unique_temp_dir();
        let source_dir = base.join("source");
        let rootfs = base.join("rootfs");
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::create_dir_all(&rootfs).unwrap();

        let ca = source_dir.join("ca.crt");
        let cert = source_dir.join("tls.crt");
        let key = source_dir.join("tls.key");
        std::fs::write(&ca, "ca").unwrap();
        std::fs::write(&cert, "cert").unwrap();
        std::fs::write(&key, "key").unwrap();

        prepare_guest_tls_materials(
            &rootfs,
            &VmDriverTlsPaths {
                ca: ca.clone(),
                cert: cert.clone(),
                key: key.clone(),
            },
        )
        .await
        .unwrap();

        let guest_dir = rootfs.join(GUEST_TLS_DIR.trim_start_matches('/'));
        assert_eq!(
            std::fs::read_to_string(guest_dir.join("ca.crt")).unwrap(),
            "ca"
        );
        assert_eq!(
            std::fs::read_to_string(guest_dir.join("tls.crt")).unwrap(),
            "cert"
        );
        assert_eq!(
            std::fs::read_to_string(guest_dir.join("tls.key")).unwrap(),
            "key"
        );
        let key_mode = std::fs::metadata(guest_dir.join("tls.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(key_mode, 0o600);

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
                process,
                gpu_bdf: None,
            },
        );
    }
}
