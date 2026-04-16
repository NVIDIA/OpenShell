// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use futures::Stream;
use nix::errno::Errno;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use openshell_core::proto::compute_driver_server::ComputeDriver;
use openshell_core::proto::{
    ComputeCreateSandboxRequest, ComputeCreateSandboxResponse, ComputeDeleteSandboxRequest,
    ComputeDeleteSandboxResponse, DriverPolicyProfile, GetCapabilitiesRequest,
    GetCapabilitiesResponse, PlatformEvent, ResolveSandboxEndpointRequest,
    ResolveSandboxEndpointResponse, Sandbox, SandboxCondition, SandboxEndpoint, SandboxPhase,
    SandboxStatus, ValidateSandboxCreateRequest, ValidateSandboxCreateResponse,
    WatchSandboxesDeletedEvent, WatchSandboxesEvent, WatchSandboxesPlatformEvent,
    WatchSandboxesRequest, WatchSandboxesSandboxEvent,
};
use prost_types::{Struct, Value, value::Kind};
use std::collections::{BTreeMap, HashMap, HashSet};
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

use crate::{RootfsVariant, extract_rootfs_variant_to};

const DRIVER_NAME: &str = "openshell-driver-vm";
const WATCH_BUFFER: usize = 256;
const GUEST_SSH_PORT: u16 = 2222;
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
    pub vm_bin: PathBuf,
    pub openshell_endpoint: String,
    pub state_dir: PathBuf,
    pub ssh_handshake_secret: String,
    pub ssh_handshake_skew_secs: u64,
    pub log_level: String,
    pub krun_log_level: u32,
    pub vcpus: u8,
    pub mem_mib: u32,
    pub tls_ca: Option<PathBuf>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
}

impl Default for VmDriverConfig {
    fn default() -> Self {
        Self {
            vm_bin: PathBuf::from("openshell-vm"),
            openshell_endpoint: String::new(),
            state_dir: PathBuf::from("target/openshell-vm-driver"),
            ssh_handshake_secret: String::new(),
            ssh_handshake_skew_secs: 300,
            log_level: "info".to_string(),
            krun_log_level: 1,
            vcpus: DEFAULT_VCPUS,
            mem_mib: DEFAULT_MEM_MIB,
            tls_ca: None,
            tls_cert: None,
            tls_key: None,
        }
    }
}

impl VmDriverConfig {
    fn requires_tls_materials(&self) -> bool {
        self.openshell_endpoint.starts_with("https://")
    }

    fn tls_paths(&self) -> Result<Option<VmDriverTlsPaths>, String> {
        let provided = [
            self.tls_ca.as_ref(),
            self.tls_cert.as_ref(),
            self.tls_key.as_ref(),
        ];
        if provided.iter().all(Option::is_none) {
            return if self.requires_tls_materials() {
                Err(
                    "https:// openshell endpoint requires OPENSHELL_TLS_CA, OPENSHELL_TLS_CERT, and OPENSHELL_TLS_KEY so sandbox VMs can authenticate to the gateway"
                        .to_string(),
                )
            } else {
                Ok(None)
            };
        }

        let Some(ca) = self.tls_ca.clone() else {
            return Err(
                "OPENSHELL_TLS_CA is required when TLS materials are configured".to_string(),
            );
        };
        let Some(cert) = self.tls_cert.clone() else {
            return Err(
                "OPENSHELL_TLS_CERT is required when TLS materials are configured".to_string(),
            );
        };
        let Some(key) = self.tls_key.clone() else {
            return Err(
                "OPENSHELL_TLS_KEY is required when TLS materials are configured".to_string(),
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

#[derive(Debug, Clone)]
pub struct VmDriver {
    config: VmDriverConfig,
    registry: Arc<Mutex<HashMap<String, SandboxRecord>>>,
    events: broadcast::Sender<WatchSandboxesEvent>,
}

impl VmDriver {
    pub async fn new(config: VmDriverConfig) -> Result<Self, String> {
        if config.openshell_endpoint.trim().is_empty() {
            return Err("openshell endpoint is required".to_string());
        }
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

        let (events, _) = broadcast::channel(WATCH_BUFFER);
        Ok(Self {
            config,
            registry: Arc::new(Mutex::new(HashMap::new())),
            events,
        })
    }

    #[must_use]
    pub fn capabilities(&self) -> GetCapabilitiesResponse {
        GetCapabilitiesResponse {
            driver_name: DRIVER_NAME.to_string(),
            driver_version: openshell_core::VERSION.to_string(),
            default_image: String::new(),
            supports_gpu: false,
            policy_profile: DriverPolicyProfile::Container as i32,
            default_process_user: "sandbox".to_string(),
            default_process_group: "sandbox".to_string(),
        }
    }

    pub async fn validate_sandbox(&self, sandbox: &Sandbox) -> Result<(), Status> {
        validate_vm_sandbox(sandbox)
    }

    pub async fn create_sandbox(
        &self,
        sandbox: &Sandbox,
    ) -> Result<ComputeCreateSandboxResponse, Status> {
        validate_vm_sandbox(sandbox)?;

        if self.registry.lock().await.contains_key(&sandbox.id) {
            return Err(Status::already_exists("sandbox already exists"));
        }

        let ssh_port = allocate_local_port()?;
        let state_dir = sandbox_state_dir(&self.config.state_dir, &sandbox.id);
        let rootfs = state_dir.join("rootfs");
        let console_log = default_console_log_path(&rootfs);

        tokio::fs::create_dir_all(&state_dir)
            .await
            .map_err(|err| Status::internal(format!("create state dir failed: {err}")))?;

        let tls_paths = self
            .config
            .tls_paths()
            .map_err(Status::failed_precondition)?;
        let rootfs_for_extract = rootfs.clone();
        tokio::task::spawn_blocking(move || {
            extract_rootfs_variant_to(RootfsVariant::Sandbox, &rootfs_for_extract)
        })
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

        let mut command = Command::new(&self.config.vm_bin);
        command.kill_on_drop(true);
        command.stdin(Stdio::null());
        command.stdout(Stdio::inherit());
        command.stderr(Stdio::inherit());
        command.arg("--rootfs").arg(&rootfs);
        command.arg("--name").arg(&sandbox.id);
        command
            .arg("--exec")
            .arg(RootfsVariant::Sandbox.guest_init_path());
        command.arg("--workdir").arg("/");
        command.arg("--vcpus").arg(self.config.vcpus.to_string());
        command.arg("--mem").arg(self.config.mem_mib.to_string());
        command
            .arg("--krun-log-level")
            .arg(self.config.krun_log_level.to_string());
        command.arg("--net").arg("gvproxy");
        command
            .arg("--port")
            .arg(format!("{ssh_port}:{GUEST_SSH_PORT}"));
        for env in build_guest_environment(sandbox, &self.config) {
            command.arg("--env").arg(env);
        }

        let child = match command.spawn() {
            Ok(child) => child,
            Err(err) => {
                let _ = tokio::fs::remove_dir_all(&state_dir).await;
                return Err(Status::internal(format!(
                    "failed to launch openshell-vm '{}': {err}",
                    self.config.vm_bin.display()
                )));
            }
        };
        let pid = child
            .id()
            .ok_or_else(|| Status::internal("openshell-vm pid is unavailable"))?;

        let snapshot = sandbox_snapshot(
            sandbox,
            SandboxPhase::Provisioning,
            provisioning_condition(),
            Some(build_driver_config(
                "127.0.0.1",
                ssh_port,
                pid,
                &rootfs,
                &console_log,
                &state_dir,
            )),
        );
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

        Ok(ComputeCreateSandboxResponse {
            status: snapshot.status,
        })
    }

    pub async fn delete_sandbox(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<ComputeDeleteSandboxResponse, Status> {
        let record = {
            let mut registry = self.registry.lock().await;
            if let Some(record) = registry.remove(sandbox_id) {
                Some(record)
            } else {
                let matched_id = registry
                    .iter()
                    .find(|(_, record)| record.snapshot.name == sandbox_name)
                    .map(|(id, _)| id.clone());
                matched_id.and_then(|id| registry.remove(&id))
            }
        };

        let Some(record) = record else {
            return Ok(ComputeDeleteSandboxResponse { deleted: false });
        };

        let mut deleting_snapshot = record.snapshot.clone();
        deleting_snapshot.phase = SandboxPhase::Deleting as i32;
        deleting_snapshot.status = Some(status_with_condition(
            &record.snapshot,
            deleting_condition(),
        ));
        self.publish_snapshot(deleting_snapshot);

        {
            let mut process = record.process.lock().await;
            process.deleting = true;
            terminate_vm_process(&mut process.child)
                .await
                .map_err(|err| Status::internal(format!("failed to stop vm: {err}")))?;
        }

        if let Err(err) = tokio::fs::remove_dir_all(&record.state_dir).await
            && err.kind() != std::io::ErrorKind::NotFound
        {
            return Err(Status::internal(format!(
                "failed to remove state dir: {err}"
            )));
        }

        self.publish_deleted(sandbox_id.to_string());
        Ok(ComputeDeleteSandboxResponse { deleted: true })
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
                target: Some(openshell_core::proto::sandbox_endpoint::Target::Host(
                    "127.0.0.1".to_string(),
                )),
                port: u32::from(record.ssh_port),
            }),
        })
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

    async fn monitor_sandbox(&self, sandbox_id: String) {
        let mut ready_emitted = false;

        loop {
            let (process, ssh_port) = {
                let registry = self.registry.lock().await;
                let Some(record) = registry.get(&sandbox_id) else {
                    return;
                };
                (record.process.clone(), record.ssh_port)
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
                                SandboxPhase::Error,
                                error_condition("ProcessPollFailed", &err.to_string()),
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
                                format!("Failed to poll openshell-vm child: {err}"),
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
                        SandboxPhase::Error,
                        error_condition("ProcessExited", &message),
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

            if !ready_emitted && port_is_ready(ssh_port).await {
                if let Some(snapshot) = self
                    .set_snapshot_condition(&sandbox_id, SandboxPhase::Ready, ready_condition())
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
        phase: SandboxPhase,
        condition: SandboxCondition,
    ) -> Option<Sandbox> {
        let mut registry = self.registry.lock().await;
        let record = registry.get_mut(sandbox_id)?;
        record.snapshot.phase = phase as i32;
        record.snapshot.status = Some(status_with_condition(&record.snapshot, condition));
        Some(record.snapshot.clone())
    }

    fn publish_snapshot(&self, sandbox: Sandbox) {
        let _ = self.events.send(WatchSandboxesEvent {
            payload: Some(
                openshell_core::proto::watch_sandboxes_event::Payload::Sandbox(
                    WatchSandboxesSandboxEvent {
                        sandbox: Some(sandbox),
                    },
                ),
            ),
        });
    }

    fn publish_deleted(&self, sandbox_id: String) {
        let _ = self.events.send(WatchSandboxesEvent {
            payload: Some(
                openshell_core::proto::watch_sandboxes_event::Payload::Deleted(
                    WatchSandboxesDeletedEvent { sandbox_id },
                ),
            ),
        });
    }

    fn publish_platform_event(&self, sandbox_id: String, event: PlatformEvent) {
        let _ = self.events.send(WatchSandboxesEvent {
            payload: Some(
                openshell_core::proto::watch_sandboxes_event::Payload::PlatformEvent(
                    WatchSandboxesPlatformEvent {
                        sandbox_id,
                        event: Some(event),
                    },
                ),
            ),
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
        request: Request<ComputeCreateSandboxRequest>,
    ) -> Result<Response<ComputeCreateSandboxResponse>, Status> {
        let sandbox = request
            .into_inner()
            .sandbox
            .ok_or_else(|| Status::invalid_argument("sandbox is required"))?;
        let response = self.create_sandbox(&sandbox).await?;
        Ok(Response::new(response))
    }

    async fn delete_sandbox(
        &self,
        request: Request<ComputeDeleteSandboxRequest>,
    ) -> Result<Response<ComputeDeleteSandboxResponse>, Status> {
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
                        payload: Some(
                            openshell_core::proto::watch_sandboxes_event::Payload::Sandbox(
                                WatchSandboxesSandboxEvent {
                                    sandbox: Some(sandbox),
                                },
                            ),
                        ),
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
                        if let Some(openshell_core::proto::watch_sandboxes_event::Payload::Sandbox(
                            sandbox_event,
                        )) = &event.payload
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
            return Err(Status::failed_precondition(
                "vm sandboxes do not support template.image",
            ));
        }
        if !template.runtime_class_name.is_empty() {
            return Err(Status::failed_precondition(
                "vm sandboxes do not support template.runtime_class_name",
            ));
        }
        if !template.agent_socket.is_empty() {
            return Err(Status::failed_precondition(
                "vm sandboxes do not support template.agent_socket",
            ));
        }
        if template.volume_claim_templates.is_some() {
            return Err(Status::failed_precondition(
                "vm sandboxes do not support template.volume_claim_templates",
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

fn build_guest_environment(sandbox: &Sandbox, config: &VmDriverConfig) -> Vec<String> {
    let mut environment = HashMap::from([
        ("HOME".to_string(), "/root".to_string()),
        (
            "PATH".to_string(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        ),
        ("TERM".to_string(), "xterm".to_string()),
        (
            "OPENSHELL_ENDPOINT".to_string(),
            config.openshell_endpoint.clone(),
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
            "OPENSHELL_SANDBOX_COMMAND".to_string(),
            "tail -f /dev/null".to_string(),
        ),
        (
            "OPENSHELL_LOG_LEVEL".to_string(),
            sandbox_log_level(sandbox, &config.log_level),
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

fn default_console_log_path(rootfs: &Path) -> PathBuf {
    rootfs.parent().unwrap_or(rootfs).join("rootfs-console.log")
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

fn sandbox_snapshot(
    sandbox: &Sandbox,
    phase: SandboxPhase,
    condition: SandboxCondition,
    driver_config: Option<Struct>,
) -> Sandbox {
    Sandbox {
        id: sandbox.id.clone(),
        name: sandbox.name.clone(),
        namespace: sandbox.namespace.clone(),
        status: Some(SandboxStatus {
            sandbox_name: sandbox.name.clone(),
            agent_pod: String::new(),
            agent_fd: String::new(),
            sandbox_fd: String::new(),
            conditions: vec![condition],
            driver_name: DRIVER_NAME.to_string(),
            driver_config,
        }),
        phase: phase as i32,
        ..Default::default()
    }
}

fn status_with_condition(snapshot: &Sandbox, condition: SandboxCondition) -> SandboxStatus {
    SandboxStatus {
        sandbox_name: snapshot.name.clone(),
        agent_pod: String::new(),
        agent_fd: String::new(),
        sandbox_fd: String::new(),
        conditions: vec![condition],
        driver_name: DRIVER_NAME.to_string(),
        driver_config: snapshot
            .status
            .as_ref()
            .and_then(|status| status.driver_config.clone()),
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

fn build_driver_config(
    host: &str,
    port: u16,
    pid: u32,
    rootfs: &Path,
    console_log: &Path,
    state_dir: &Path,
) -> Struct {
    Struct {
        fields: BTreeMap::from([
            ("endpoint_host".to_string(), string_value(host)),
            ("endpoint_port".to_string(), number_value(f64::from(port))),
            ("vm_pid".to_string(), number_value(f64::from(pid))),
            (
                "rootfs_path".to_string(),
                string_value(rootfs.display().to_string()),
            ),
            (
                "console_log_path".to_string(),
                string_value(console_log.display().to_string()),
            ),
            (
                "state_dir".to_string(),
                string_value(state_dir.display().to_string()),
            ),
        ]),
    }
}

fn string_value(value: impl Into<String>) -> Value {
    Value {
        kind: Some(Kind::StringValue(value.into())),
    }
}

fn number_value(value: f64) -> Value {
    Value {
        kind: Some(Kind::NumberValue(value)),
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
    use openshell_core::proto::{SandboxSpec, SandboxTemplate};
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
    fn validate_vm_sandbox_rejects_runtime_class() {
        let sandbox = Sandbox {
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate {
                    runtime_class_name: "kata".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = validate_vm_sandbox(&sandbox).expect_err("runtime class should be rejected");
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("runtime_class_name"));
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

        let env = build_guest_environment(&sandbox, &config);
        assert!(env.contains(&"HOME=/root".to_string()));
        assert!(env.contains(&"OPENSHELL_ENDPOINT=http://127.0.0.1:8080".to_string()));
        assert!(env.contains(&"OPENSHELL_SANDBOX_ID=sandbox-123".to_string()));
        assert!(env.contains(&format!(
            "OPENSHELL_SSH_LISTEN_ADDR=0.0.0.0:{GUEST_SSH_PORT}"
        )));
    }

    #[test]
    fn build_guest_environment_includes_tls_paths_for_https_endpoint() {
        let config = VmDriverConfig {
            openshell_endpoint: "https://127.0.0.1:8443".to_string(),
            ssh_handshake_secret: "secret".to_string(),
            tls_ca: Some(PathBuf::from("/host/ca.crt")),
            tls_cert: Some(PathBuf::from("/host/tls.crt")),
            tls_key: Some(PathBuf::from("/host/tls.key")),
            ..Default::default()
        };
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            name: "sandbox-123".to_string(),
            spec: Some(SandboxSpec::default()),
            ..Default::default()
        };

        let env = build_guest_environment(&sandbox, &config);
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
        assert!(err.contains("OPENSHELL_TLS_CA"));
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
    fn build_driver_config_contains_paths() {
        let config = build_driver_config(
            "127.0.0.1",
            2200,
            42,
            Path::new("/tmp/rootfs"),
            Path::new("/tmp/rootfs-console.log"),
            Path::new("/tmp/state"),
        );

        assert_eq!(
            config.fields.get("vm_pid").and_then(number_field),
            Some(42.0)
        );
        assert_eq!(
            config.fields.get("rootfs_path").and_then(string_field),
            Some("/tmp/rootfs")
        );
        assert_eq!(
            config.fields.get("console_log_path").and_then(string_field),
            Some("/tmp/rootfs-console.log")
        );
    }

    fn string_field(value: &Value) -> Option<&str> {
        match &value.kind {
            Some(Kind::StringValue(value)) => Some(value.as_str()),
            _ => None,
        }
    }

    fn number_field(value: &Value) -> Option<f64> {
        match &value.kind {
            Some(Kind::NumberValue(value)) => Some(*value),
            _ => None,
        }
    }

    fn unique_temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("openshell-vm-driver-test-{nanos}"))
    }
}
