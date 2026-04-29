// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::gpu::{
    GpuInventory, SubnetAllocator, allocate_vsock_cid, mac_from_sandbox_id, tap_device_name,
};
use crate::rootfs::{
    extract_gpu_sandbox_rootfs_to, extract_sandbox_rootfs_to, sandbox_guest_init_path,
};
use futures::Stream;
use nix::errno::Errno;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
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
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use url::{Host, Url};

const DRIVER_NAME: &str = "openshell-driver-vm";
const WATCH_BUFFER: usize = 256;
const DEFAULT_VCPUS: u8 = 2;
const DEFAULT_MEM_MIB: u32 = 2048;
const GVPROXY_GATEWAY_IP: &str = "192.168.127.1";
const OPENSHELL_HOST_GATEWAY_ALIAS: &str = "host.openshell.internal";
const GUEST_SSH_SOCKET_PATH: &str = "/run/openshell/ssh.sock";
const GUEST_TLS_DIR: &str = "/opt/openshell/tls";
const GUEST_TLS_CA_PATH: &str = "/opt/openshell/tls/ca.crt";
const GUEST_TLS_CERT_PATH: &str = "/opt/openshell/tls/tls.crt";
const GUEST_TLS_KEY_PATH: &str = "/opt/openshell/tls/tls.key";

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

        let state_root = config.state_dir.join("sandboxes");
        tokio::fs::create_dir_all(&state_root)
            .await
            .map_err(|err| {
                format!(
                    "failed to create state dir '{}': {err}",
                    state_root.display()
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
            default_image: String::new(),
            supports_gpu: self.gpu_inventory.is_some(),
            gpu_count,
        }
    }

    pub async fn validate_sandbox(&self, sandbox: &Sandbox) -> Result<(), Status> {
        validate_vm_sandbox(sandbox, self.config.gpu_enabled)
    }

    pub async fn create_sandbox(&self, sandbox: &Sandbox) -> Result<CreateSandboxResponse, Status> {
        validate_vm_sandbox(sandbox, self.config.gpu_enabled)?;

        if self.registry.lock().await.contains_key(&sandbox.id) {
            return Err(Status::already_exists("sandbox already exists"));
        }

        let spec = sandbox.spec.as_ref();
        let is_gpu = spec.is_some_and(|s| s.gpu);
        let gpu_device = spec.map_or("", |s| s.gpu_device.as_str());

        let state_dir = sandbox_state_dir(&self.config.state_dir, &sandbox.id);
        let rootfs = state_dir.join("rootfs");

        tokio::fs::create_dir_all(&state_dir)
            .await
            .map_err(|err| Status::internal(format!("create state dir failed: {err}")))?;

        let tls_paths = self
            .config
            .tls_paths()
            .map_err(Status::failed_precondition)?;
        let rootfs_for_extract = rootfs.clone();
        let extract_fn = if is_gpu {
            extract_gpu_sandbox_rootfs_to
        } else {
            extract_sandbox_rootfs_to
        };
        tokio::task::spawn_blocking(move || extract_fn(&rootfs_for_extract))
            .await
            .map_err(|err| Status::internal(format!("sandbox rootfs extraction panicked: {err}")))?
            .map_err(|err| Status::internal(format!("extract sandbox rootfs failed: {err}")))?;
        if let Some(tls_paths) = tls_paths.as_ref() {
            prepare_guest_tls_materials(&rootfs, tls_paths)
                .await
                .map_err(|err| {
                    Status::internal(format!("prepare guest TLS materials failed: {err}"))
                })?;
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
                        .map_err(|e| Status::failed_precondition(e))
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
        let endpoint_override = if gpu_bdf.is_some() {
            let subnet = match self
                .subnet_allocator
                .lock()
                .map_err(|e| Status::internal(format!("subnet allocator lock poisoned: {e}")))
                .and_then(|mut alloc| {
                    alloc
                        .allocate(&sandbox.id)
                        .map_err(|e| Status::failed_precondition(e))
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
            command.arg("--vm-gpu-bdf").arg(gpu_bdf.as_ref().unwrap());
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

        let child = match command.spawn() {
            Ok(child) => child,
            Err(err) => {
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
        let sandbox = if !sandbox_id.is_empty() {
            registry
                .get(sandbox_id)
                .map(|record| record.snapshot.clone())
        } else {
            registry
                .values()
                .find(|record| record.snapshot.name == sandbox_name)
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
        if let Some(ref inventory) = self.gpu_inventory {
            if let Ok(mut inv) = inventory.lock() {
                inv.release(sandbox_id);
            }
        }
        if let Ok(mut alloc) = self.subnet_allocator.lock() {
            alloc.release(sandbox_id);
        }
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
                let message = match status.code() {
                    Some(code) => format!("VM process exited with status {code}"),
                    None => "VM process exited".to_string(),
                };
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
        self.validate_sandbox(&sandbox).await?;
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
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(out_rx))))
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
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
        if !template.image.is_empty() {
            return Err(Status::failed_precondition(
                "vm sandboxes do not support template.image",
            ));
        }
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

    if should_rewrite && url.set_host(Some(GVPROXY_GATEWAY_IP)).is_ok() {
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
    let openshell_endpoint = endpoint_override
        .map(String::from)
        .unwrap_or_else(|| guest_visible_openshell_endpoint(&config.openshell_endpoint));
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

fn sandbox_state_dir(root: &Path, sandbox_id: &str) -> PathBuf {
    root.join("sandboxes").join(sandbox_id)
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
    tokio::fs::set_permissions(dest, std::fs::Permissions::from_mode(mode)).await?;
    Ok(())
}

async fn terminate_vm_process(child: &mut Child) -> Result<(), std::io::Error> {
    if let Some(pid) = child.id()
        && let Err(err) = kill(Pid::from_raw(pid as i32), Signal::SIGTERM)
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
        .map_or(0, |duration| duration.as_millis() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpu::{SubnetAllocator, allocate_vsock_cid, mac_from_sandbox_id, tap_device_name};
    use openshell_core::proto::compute::v1::{
        DriverSandboxSpec as SandboxSpec, DriverSandboxTemplate as SandboxTemplate,
    };
    use prost_types::{Struct, Value, value::Kind};
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
                        fields: [(
                            "runtime_class_name".to_string(),
                            Value {
                                kind: Some(Kind::StringValue("kata".to_string())),
                            },
                        )]
                        .into_iter()
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
            "OPENSHELL_ENDPOINT=http://{GVPROXY_GATEWAY_IP}:8080/"
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
    fn guest_visible_openshell_endpoint_rewrites_loopback_hosts_to_gvproxy_gateway() {
        assert_eq!(
            guest_visible_openshell_endpoint("http://127.0.0.1:8080"),
            format!("http://{GVPROXY_GATEWAY_IP}:8080/")
        );
        assert_eq!(
            guest_visible_openshell_endpoint("http://localhost:8080"),
            format!("http://{GVPROXY_GATEWAY_IP}:8080/")
        );
        assert_eq!(
            guest_visible_openshell_endpoint("https://[::1]:8443"),
            format!("https://{GVPROXY_GATEWAY_IP}:8443/")
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
            guest_visible_openshell_endpoint("http://host.containers.internal:8080"),
            "http://host.containers.internal:8080"
        );
        assert_eq!(
            guest_visible_openshell_endpoint(&format!("http://{GVPROXY_GATEWAY_IP}:8080")),
            format!("http://{GVPROXY_GATEWAY_IP}:8080")
        );
        assert_eq!(
            guest_visible_openshell_endpoint("https://gateway.internal:8443"),
            "https://gateway.internal:8443"
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
        validate_openshell_endpoint(&format!("http://{GVPROXY_GATEWAY_IP}:8080"))
            .expect("gateway IP should be accepted");
        validate_openshell_endpoint(&format!("http://{OPENSHELL_HOST_GATEWAY_ALIAS}:8080"))
            .expect("openshell host alias should be accepted");
        validate_openshell_endpoint("https://gateway.internal:8443")
            .expect("dns endpoint should be accepted");
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
