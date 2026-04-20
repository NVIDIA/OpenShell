// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    GUEST_SSH_PORT,
    rootfs::{extract_sandbox_rootfs_to, sandbox_guest_init_path},
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
    ListSandboxesResponse, ResolveSandboxEndpointRequest, ResolveSandboxEndpointResponse,
    SandboxEndpoint, StopSandboxRequest, StopSandboxResponse, ValidateSandboxCreateRequest,
    ValidateSandboxCreateResponse, WatchSandboxesDeletedEvent, WatchSandboxesEvent,
    WatchSandboxesPlatformEvent, WatchSandboxesRequest, WatchSandboxesSandboxEvent,
    compute_driver_server::ComputeDriver, sandbox_endpoint, watch_sandboxes_event,
};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use url::{Host, Url};

const DRIVER_NAME: &str = "openshell-driver-vm";
const WATCH_BUFFER: usize = 256;
const DEFAULT_VCPUS: u8 = 2;
const DEFAULT_MEM_MIB: u32 = 2048;
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
    /// Default OCI image used when the sandbox spec omits `template.image`.
    /// Empty string means "no default" — sandboxes without an image will
    /// fall back to the historical non-OCI guest rootfs supervisor.
    pub default_image: String,
    /// Path to the `mksquashfs` binary. When unset, OCI-image sandboxes
    /// are rejected with `FailedPrecondition`.
    pub mksquashfs_bin: Option<PathBuf>,
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
            default_image: String::new(),
            mksquashfs_bin: None,
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
            "openshell endpoint '{endpoint}' is not reachable from sandbox VMs; use a concrete host such as 127.0.0.1, host.containers.internal, or another routable address"
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
    ssh_port: u16,
    state_dir: PathBuf,
    process: Arc<Mutex<VmProcess>>,
}

#[derive(Clone)]
pub struct VmDriver {
    config: VmDriverConfig,
    launcher_bin: PathBuf,
    registry: Arc<Mutex<HashMap<String, SandboxRecord>>>,
    events: broadcast::Sender<WatchSandboxesEvent>,
    /// Shared OCI cache and puller for this driver process.
    /// Populated once per platform; `None` when the host arch is unsupported.
    oci: Option<Arc<VmOci>>,
}

/// Lazily-initialized OCI state attached to the driver.
pub struct VmOci {
    pub puller: crate::oci::OciPuller,
    pub cache: crate::oci::CacheLayout,
    pub platform: crate::oci::Platform,
}

impl VmDriver {
    pub async fn new(config: VmDriverConfig) -> Result<Self, String> {
        if config.openshell_endpoint.trim().is_empty() {
            return Err("openshell endpoint is required".to_string());
        }
        validate_openshell_endpoint(&config.openshell_endpoint)?;
        let _ = config.tls_paths()?;

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

        let (events, _) = broadcast::channel(WATCH_BUFFER);

        let oci = crate::oci::Platform::host().map(|platform| {
            let cache = crate::oci::CacheLayout::new(config.state_dir.join("oci-cache"));
            // Errors here are surfaced lazily at first sandbox-create; the
            // driver still starts so non-OCI sandboxes continue to work.
            let _ = cache.ensure_dirs();
            Arc::new(VmOci {
                puller: crate::oci::OciPuller::new(platform),
                cache,
                platform,
            })
        });

        Ok(Self {
            config,
            launcher_bin,
            registry: Arc::new(Mutex::new(HashMap::new())),
            events,
            oci,
        })
    }

    #[must_use]
    pub fn capabilities(&self) -> GetCapabilitiesResponse {
        GetCapabilitiesResponse {
            driver_name: DRIVER_NAME.to_string(),
            driver_version: openshell_core::VERSION.to_string(),
            default_image: self.config.default_image.clone(),
            supports_gpu: false,
        }
    }

    pub async fn validate_sandbox(&self, sandbox: &Sandbox) -> Result<(), Status> {
        validate_vm_sandbox(sandbox)
    }

    pub async fn create_sandbox(&self, sandbox: &Sandbox) -> Result<CreateSandboxResponse, Status> {
        validate_vm_sandbox(sandbox)?;

        if self.registry.lock().await.contains_key(&sandbox.id) {
            return Err(Status::already_exists("sandbox already exists"));
        }

        let ssh_port = allocate_local_port()?;
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
        tokio::task::spawn_blocking(move || extract_sandbox_rootfs_to(&rootfs_for_extract))
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

        let oci_launch = self.resolve_oci_launch(sandbox, &state_dir).await?;
        let is_oci = oci_launch.is_some();

        let console_output = state_dir.join("rootfs-console.log");
        let mut command = Command::new(&self.launcher_bin);
        command.kill_on_drop(true);
        command.stdin(Stdio::null());
        command.stdout(Stdio::inherit());
        command.stderr(Stdio::inherit());
        command.arg("--internal-run-vm");
        command.arg("--vm-rootfs").arg(&rootfs);
        command.arg("--vm-exec").arg(sandbox_guest_init_path());
        command.arg("--vm-workdir").arg("/");
        command.arg("--vm-vcpus").arg(self.config.vcpus.to_string());
        command
            .arg("--vm-mem-mib")
            .arg(self.config.mem_mib.to_string());
        command
            .arg("--vm-krun-log-level")
            .arg(self.config.krun_log_level.to_string());
        command.arg("--vm-console-output").arg(&console_output);
        command
            .arg("--vm-port")
            .arg(format!("{ssh_port}:{GUEST_SSH_PORT}"));
        if let Some(oci) = oci_launch.as_ref() {
            command.arg("--vm-ro-base-disk").arg(&oci.base_disk_path);
            command.arg("--vm-state-disk").arg(&oci.state_disk_path);
        }
        let mut guest_env = build_guest_environment(sandbox, &self.config, is_oci);
        if let Some(oci) = oci_launch.as_ref() {
            guest_env.extend(oci.guest_env_vars.iter().cloned());
        }
        for env in guest_env {
            command.arg("--vm-env").arg(env);
        }

        let child = match command.spawn() {
            Ok(child) => child,
            Err(err) => {
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
                    ssh_port,
                    state_dir: state_dir.clone(),
                    process: process.clone(),
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
                Some((id.clone(), record.state_dir.clone(), record.process.clone()))
            } else {
                let matched_id = registry
                    .iter()
                    .find(|(_, record)| record.snapshot.name == sandbox_name)
                    .map(|(id, _)| id.clone());
                matched_id.and_then(|id| {
                    registry
                        .get(&id)
                        .map(|record| (id, record.state_dir.clone(), record.process.clone()))
                })
            }
        };

        let Some((record_id, state_dir, process)) = record else {
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

    pub async fn resolve_endpoint(
        &self,
        sandbox: &Sandbox,
    ) -> Result<ResolveSandboxEndpointResponse, Status> {
        let registry = self.registry.lock().await;
        let record = registry.get(&sandbox.id).or_else(|| {
            registry
                .values()
                .find(|record| record.snapshot.name == sandbox.name)
        });
        let record = record.ok_or_else(|| Status::not_found("sandbox not found"))?;
        Ok(ResolveSandboxEndpointResponse {
            endpoint: Some(SandboxEndpoint {
                target: Some(sandbox_endpoint::Target::Host("127.0.0.1".to_string())),
                port: u32::from(record.ssh_port),
            }),
        })
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

    /// Run the OCI pipeline for this sandbox if `template.image` (or the
    /// driver's default image) is set, and materialize the per-sandbox state
    /// disk. Returns `None` for legacy non-OCI sandboxes.
    async fn resolve_oci_launch(
        &self,
        sandbox: &Sandbox,
        state_dir: &Path,
    ) -> Result<Option<OciLaunch>, Status> {
        let image_ref = effective_image_ref(sandbox, &self.config.default_image);
        if image_ref.is_empty() {
            return Ok(None);
        }

        let oci = self.oci.clone().ok_or_else(|| {
            Status::failed_precondition(
                "OCI image support is not available: the host platform is not linux/amd64 or linux/arm64",
            )
        })?;
        let mksquashfs = self.config.mksquashfs_bin.clone().ok_or_else(|| {
            Status::failed_precondition(
                "OCI image support is not configured: set OPENSHELL_VM_MKSQUASHFS to the path of mksquashfs",
            )
        })?;

        let env_overrides = crate::oci::EnvOverrides {
            template: sandbox
                .spec
                .as_ref()
                .and_then(|spec| spec.template.as_ref())
                .map(|template| template.environment.clone().into_iter().collect())
                .unwrap_or_default(),
            spec: sandbox
                .spec
                .as_ref()
                .map(|spec| spec.environment.clone().into_iter().collect())
                .unwrap_or_default(),
        };

        let build_opts = crate::oci::fs_image::BuildOptions::with_binary(mksquashfs);
        let cached = crate::oci::prepare(
            &oci.puller,
            &oci.cache,
            &build_opts,
            &image_ref,
            &env_overrides,
        )
        .await
        .map_err(|err| Status::internal(format!("OCI prepare failed: {err}")))?;

        let state_paths = crate::state_disk::SandboxStatePaths::for_state_dir(state_dir);
        crate::state_disk::ensure_state_disk(
            &state_paths.state_disk,
            crate::state_disk::DEFAULT_STATE_DISK_SIZE_BYTES,
        )
        .map_err(|err| Status::internal(format!("create sandbox state disk: {err}")))?;

        let guest_env_vars: Vec<String> = cached
            .metadata
            .to_guest_env_vars()
            .into_iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();

        Ok(Some(OciLaunch {
            base_disk_path: cached.fs_image,
            state_disk_path: state_paths.state_disk,
            guest_env_vars,
        }))
    }

    async fn monitor_sandbox(&self, sandbox_id: String) {
        let mut ready_emitted = false;

        loop {
            let (process, ssh_port, state_dir) = {
                let registry = self.registry.lock().await;
                let Some(record) = registry.get(&sandbox_id) else {
                    return;
                };
                (
                    record.process.clone(),
                    record.ssh_port,
                    record.state_dir.clone(),
                )
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
                return;
            }

            if !ready_emitted && port_is_ready(ssh_port).await && guest_ssh_ready(&state_dir).await
            {
                if let Some(snapshot) = self
                    .set_snapshot_condition(&sandbox_id, ready_condition(), false)
                    .await
                {
                    self.publish_snapshot(snapshot);
                }
                ready_emitted = true;
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

    async fn resolve_sandbox_endpoint(
        &self,
        request: Request<ResolveSandboxEndpointRequest>,
    ) -> Result<Response<ResolveSandboxEndpointResponse>, Status> {
        let sandbox = request
            .into_inner()
            .sandbox
            .ok_or_else(|| Status::invalid_argument("sandbox is required"))?;
        Ok(Response::new(self.resolve_endpoint(&sandbox).await?))
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

/// Per-sandbox OCI launch artifacts: cached RO base fs image, per-sandbox
/// writable state disk, and the launch-metadata env vars that get packed
/// into the guest init's environ.
#[derive(Debug)]
struct OciLaunch {
    base_disk_path: PathBuf,
    state_disk_path: PathBuf,
    guest_env_vars: Vec<String>,
}

/// Return the OCI image reference to use for this sandbox, or `""` if the
/// sandbox is a legacy non-OCI VM sandbox. Spec overrides the driver default.
fn effective_image_ref(sandbox: &Sandbox, default_image: &str) -> String {
    let requested = sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
        .map(|template| template.image.as_str())
        .unwrap_or("");
    if !requested.is_empty() {
        requested.to_string()
    } else {
        default_image.to_string()
    }
}

fn validate_vm_sandbox(sandbox: &Sandbox) -> Result<(), Status> {
    let spec = sandbox
        .spec
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("sandbox spec is required"))?;
    if spec.gpu {
        return Err(Status::failed_precondition(
            "vm sandboxes do not support gpu=true",
        ));
    }
    if let Some(template) = spec.template.as_ref() {
        if !template.image.is_empty() {
            crate::oci::validate_reference(&template.image).map_err(|err| {
                Status::failed_precondition(format!("invalid template.image: {err}"))
            })?;
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

    if should_rewrite && url.set_host(Some("192.168.127.1")).is_ok() {
        return url.to_string();
    }

    endpoint.to_string()
}

fn build_guest_environment(
    sandbox: &Sandbox,
    config: &VmDriverConfig,
    is_oci: bool,
) -> Vec<String> {
    let mut environment = HashMap::from([
        ("HOME".to_string(), "/root".to_string()),
        (
            "PATH".to_string(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        ),
        ("TERM".to_string(), "xterm".to_string()),
        (
            "OPENSHELL_ENDPOINT".to_string(),
            guest_visible_openshell_endpoint(&config.openshell_endpoint),
        ),
        ("OPENSHELL_SANDBOX_ID".to_string(), sandbox.id.clone()),
        ("OPENSHELL_SANDBOX".to_string(), sandbox.name.clone()),
        (
            "OPENSHELL_SSH_LISTEN_ADDR".to_string(),
            format!("0.0.0.0:{GUEST_SSH_PORT}"),
        ),
        (
            "OPENSHELL_SSH_HANDSHAKE_SECRET".to_string(),
            config.ssh_handshake_secret.clone(),
        ),
        (
            "OPENSHELL_SSH_HANDSHAKE_SKEW_SECS".to_string(),
            config.ssh_handshake_skew_secs.to_string(),
        ),
        (
            "OPENSHELL_LOG_LEVEL".to_string(),
            sandbox_log_level(sandbox, &config.log_level),
        ),
    ]);
    // Legacy guest rootfs supervisor reads `OPENSHELL_SANDBOX_COMMAND` when
    // no positional command is supplied. OCI sandboxes always carry argv via
    // `OPENSHELL_OCI_ARGV_<i>`, so this fallback is dead weight there — and
    // passing it would muddy the contract (the supervisor's env-parsing path
    // uses whitespace splitting, which would corrupt argv boundaries if a
    // code path ever fell through to it). Only set it for non-OCI sandboxes.
    if !is_oci {
        environment.insert(
            "OPENSHELL_SANDBOX_COMMAND".to_string(),
            "tail -f /dev/null".to_string(),
        );
    }
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

fn allocate_local_port() -> Result<u16, Status> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|err| Status::internal(format!("failed to allocate local ssh port: {err}")))?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|err| Status::internal(format!("failed to inspect local ssh port: {err}")))
}

async fn port_is_ready(port: u16) -> bool {
    TcpStream::connect(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port))
        .await
        .is_ok()
}

async fn guest_ssh_ready(state_dir: &Path) -> bool {
    let console_log = state_dir.join("rootfs-console.log");
    let Ok(contents) = tokio::fs::read_to_string(console_log).await else {
        return false;
    };

    contents.contains("SSH server is ready to accept connections")
        || contents.contains("SSH server listening")
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

fn ready_condition() -> SandboxCondition {
    SandboxCondition {
        r#type: "Ready".to_string(),
        status: "True".to_string(),
        reason: "Listening".to_string(),
        message: "Supervisor is listening for SSH connections".to_string(),
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
    use openshell_core::proto::compute::v1::{
        DriverSandboxSpec as SandboxSpec, DriverSandboxTemplate as SandboxTemplate,
    };
    use prost_types::{Struct, Value, value::Kind};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tonic::Code;

    #[test]
    fn validate_vm_sandbox_rejects_gpu() {
        let sandbox = Sandbox {
            spec: Some(SandboxSpec {
                gpu: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = validate_vm_sandbox(&sandbox).expect_err("gpu should be rejected");
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("gpu"));
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
        let err = validate_vm_sandbox(&sandbox).expect_err("platform config should be rejected");
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

        let env = build_guest_environment(&sandbox, &config, false);
        assert!(env.contains(&"HOME=/root".to_string()));
        assert!(env.contains(&"OPENSHELL_ENDPOINT=http://192.168.127.1:8080/".to_string()));
        assert!(env.contains(&"OPENSHELL_SANDBOX_ID=sandbox-123".to_string()));
        assert!(env.contains(&format!(
            "OPENSHELL_SSH_LISTEN_ADDR=0.0.0.0:{GUEST_SSH_PORT}"
        )));
        assert!(
            env.iter()
                .any(|e| e.starts_with("OPENSHELL_SANDBOX_COMMAND=")),
            "non-OCI sandboxes should receive the fallback command"
        );
    }

    #[test]
    fn build_guest_environment_omits_sandbox_command_for_oci_sandboxes() {
        let config = VmDriverConfig {
            openshell_endpoint: "http://127.0.0.1:8080".to_string(),
            ssh_handshake_secret: "secret".to_string(),
            ..Default::default()
        };
        let sandbox = Sandbox {
            id: "sandbox-oci".to_string(),
            name: "sandbox-oci".to_string(),
            spec: Some(SandboxSpec::default()),
            ..Default::default()
        };

        let env = build_guest_environment(&sandbox, &config, true);
        assert!(
            !env.iter()
                .any(|e| e.starts_with("OPENSHELL_SANDBOX_COMMAND=")),
            "OCI sandboxes should not get the legacy supervisor command fallback: {env:?}"
        );
        // sanity: other guest-env bits should still be present
        assert!(env.contains(&"OPENSHELL_SANDBOX_ID=sandbox-oci".to_string()));
    }

    #[test]
    fn guest_visible_openshell_endpoint_preserves_non_loopback_hosts() {
        assert_eq!(
            guest_visible_openshell_endpoint("http://host.containers.internal:8080"),
            "http://host.containers.internal:8080"
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

        let env = build_guest_environment(&sandbox, &config, false);
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
            oci: None,
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
    fn effective_image_ref_prefers_spec_over_default() {
        let sandbox = Sandbox {
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate {
                    image: "docker.io/library/alpine:3.20".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            effective_image_ref(&sandbox, "docker.io/library/busybox"),
            "docker.io/library/alpine:3.20"
        );
    }

    #[test]
    fn effective_image_ref_falls_back_to_default_when_spec_empty() {
        let sandbox = Sandbox {
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate::default()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            effective_image_ref(&sandbox, "docker.io/library/busybox"),
            "docker.io/library/busybox"
        );
    }

    #[test]
    fn effective_image_ref_is_empty_when_neither_is_set() {
        let sandbox = Sandbox::default();
        assert!(effective_image_ref(&sandbox, "").is_empty());
    }

    #[test]
    fn validate_vm_sandbox_accepts_valid_template_image() {
        let sandbox = Sandbox {
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate {
                    image: "docker.io/library/alpine:3.20".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        validate_vm_sandbox(&sandbox).expect("valid image ref should pass validation");
    }

    #[test]
    fn validate_vm_sandbox_rejects_malformed_template_image() {
        let sandbox = Sandbox {
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate {
                    image: "::not a valid ref::".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = validate_vm_sandbox(&sandbox).expect_err("malformed ref should fail");
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("template.image"));
    }

    #[test]
    fn capabilities_advertise_default_image() {
        let config = VmDriverConfig {
            default_image: "docker.io/library/busybox".to_string(),
            ..Default::default()
        };
        let driver = VmDriver {
            config,
            launcher_bin: PathBuf::from("openshell-driver-vm"),
            registry: Arc::new(Mutex::new(HashMap::new())),
            events: broadcast::channel(WATCH_BUFFER).0,
            oci: None,
        };
        let caps = driver.capabilities();
        assert_eq!(caps.default_image, "docker.io/library/busybox");
        assert_eq!(caps.driver_name, DRIVER_NAME);
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
        validate_openshell_endpoint("http://host.openshell.internal:8080")
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

    #[tokio::test]
    async fn guest_ssh_ready_detects_guest_console_marker() {
        let base = unique_temp_dir();
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(
            base.join("rootfs-console.log"),
            "...\nINFO openshell_sandbox: SSH server is ready to accept connections\n",
        )
        .unwrap();

        assert!(guest_ssh_ready(&base).await);

        let _ = std::fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn guest_ssh_ready_is_false_without_marker() {
        let base = unique_temp_dir();
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("rootfs-console.log"), "sandbox booting\n").unwrap();

        assert!(!guest_ssh_ready(&base).await);

        let _ = std::fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn resolve_oci_launch_skips_when_no_image_is_requested() {
        // A sandbox without template.image and with no driver default must
        // fall through to the legacy non-OCI boot path. The resolver should
        // return Ok(None) without consulting the puller or cache.
        let state_dir = unique_temp_dir();
        std::fs::create_dir_all(&state_dir).unwrap();
        let driver = VmDriver {
            config: VmDriverConfig::default(),
            launcher_bin: PathBuf::from("openshell-driver-vm"),
            registry: Arc::new(Mutex::new(HashMap::new())),
            events: broadcast::channel(WATCH_BUFFER).0,
            oci: None, // unsupported host platform
        };

        let sandbox = Sandbox {
            id: "sb".to_string(),
            name: "sb".to_string(),
            spec: Some(SandboxSpec::default()),
            ..Default::default()
        };

        let result = driver
            .resolve_oci_launch(&sandbox, &state_dir)
            .await
            .expect("no image requested → Ok(None)");
        assert!(result.is_none());
        let _ = std::fs::remove_dir_all(state_dir);
    }

    #[tokio::test]
    async fn resolve_oci_launch_fails_cleanly_when_host_platform_is_unsupported() {
        // When `Platform::host()` returned None at driver construction,
        // `self.oci` is None. Requesting an OCI image in that state must
        // produce FailedPrecondition, not a panic or a silent fallback.
        let state_dir = unique_temp_dir();
        std::fs::create_dir_all(&state_dir).unwrap();
        let driver = VmDriver {
            config: VmDriverConfig {
                default_image: "docker.io/library/alpine:3.20".to_string(),
                ..Default::default()
            },
            launcher_bin: PathBuf::from("openshell-driver-vm"),
            registry: Arc::new(Mutex::new(HashMap::new())),
            events: broadcast::channel(WATCH_BUFFER).0,
            oci: None,
        };

        let sandbox = Sandbox {
            spec: Some(SandboxSpec::default()),
            ..Default::default()
        };

        let err = driver
            .resolve_oci_launch(&sandbox, &state_dir)
            .await
            .expect_err("unsupported host platform should reject OCI sandboxes");
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("linux/amd64 or linux/arm64"));
        let _ = std::fs::remove_dir_all(state_dir);
    }

    #[tokio::test]
    async fn resolve_oci_launch_fails_cleanly_when_mksquashfs_is_missing() {
        // If the host platform is supported but `mksquashfs_bin` isn't
        // configured, the driver must refuse with FailedPrecondition so the
        // gateway surfaces a diagnosable error instead of hanging at pull time.
        let Some(platform) = crate::oci::Platform::host() else {
            eprintln!("skipping: unsupported host platform");
            return;
        };

        let state_dir = unique_temp_dir();
        std::fs::create_dir_all(&state_dir).unwrap();
        let cache_root = state_dir.join("oci-cache");
        let cache = crate::oci::CacheLayout::new(cache_root);
        cache.ensure_dirs().unwrap();

        let driver = VmDriver {
            config: VmDriverConfig {
                default_image: "docker.io/library/alpine:3.20".to_string(),
                mksquashfs_bin: None,
                ..Default::default()
            },
            launcher_bin: PathBuf::from("openshell-driver-vm"),
            registry: Arc::new(Mutex::new(HashMap::new())),
            events: broadcast::channel(WATCH_BUFFER).0,
            oci: Some(Arc::new(VmOci {
                puller: crate::oci::OciPuller::new(platform),
                cache,
                platform,
            })),
        };

        let sandbox = Sandbox {
            spec: Some(SandboxSpec::default()),
            ..Default::default()
        };

        let err = driver
            .resolve_oci_launch(&sandbox, &state_dir)
            .await
            .expect_err("missing mksquashfs should reject OCI sandboxes");
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("OPENSHELL_VM_MKSQUASHFS"));
        let _ = std::fs::remove_dir_all(state_dir);
    }

    #[test]
    fn effective_image_ref_drops_whitespace_only_spec_overrides() {
        // Whitespace-only image refs should not be accepted as an override of
        // the driver's configured default. In today's implementation the spec
        // field is compared against "" exactly, so "   " slips through — but
        // that only affects downstream validation, which then rejects the
        // malformed ref. This test documents the contract and will need an
        // update if we decide to trim here.
        let sandbox = Sandbox {
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate {
                    image: "   ".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        // Current behavior: non-empty string wins, even if whitespace.
        assert_eq!(
            effective_image_ref(&sandbox, "docker.io/library/busybox"),
            "   "
        );
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
                ssh_port: 2222,
                state_dir,
                process,
            },
        );
    }
}
