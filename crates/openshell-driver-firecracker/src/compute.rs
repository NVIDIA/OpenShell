// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Experimental gateway compute-driver adapter for the Firecracker backend.

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use base64::Engine as _;
use futures::Stream;
use openshell_core::proto::compute::v1::{
    CreateSandboxRequest, CreateSandboxResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    DriverCondition, DriverSandbox, DriverSandboxStatus, GetCapabilitiesRequest,
    GetCapabilitiesResponse, GetGatewayListenerRequirementsRequest,
    GetGatewayListenerRequirementsResponse, GetSandboxRequest, GetSandboxResponse,
    ListSandboxesRequest, ListSandboxesResponse, StopSandboxRequest, StopSandboxResponse,
    ValidateSandboxCreateRequest, ValidateSandboxCreateResponse, WatchSandboxesDeletedEvent,
    WatchSandboxesEvent, WatchSandboxesRequest, WatchSandboxesSandboxEvent,
    compute_driver_server::ComputeDriver, watch_sandboxes_event,
};
use openshell_core::proto_struct::struct_to_json_value;
use openshell_isolation::contract::INTERFACE_VERSION;
use serde::Deserialize;
use tokio::sync::{Mutex, broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::{FirecrackerLaunchConfig, FirecrackerTopology, FirecrackerVm, GuestConfig};

const WATCH_BUFFER: usize = 128;
const DEFAULT_AGENT_UID: u32 = 10_001;
const DEFAULT_AGENT_GID: u32 = 10_001;

#[derive(Debug, Clone)]
pub struct FirecrackerComputeConfig {
    pub gateway_endpoint: String,
    pub state_dir: PathBuf,
    pub firecracker_binary: PathBuf,
    pub kernel_image: PathBuf,
    pub root_disk: PathBuf,
    pub supervisor_binary: PathBuf,
    pub driver_binary: PathBuf,
    pub default_image: String,
    pub vcpus: u8,
    pub mem_mib: u32,
}

#[derive(Clone)]
pub struct FirecrackerComputeDriver {
    config: Arc<FirecrackerComputeConfig>,
    records: Arc<Mutex<HashMap<String, SandboxRecord>>>,
    events: broadcast::Sender<WatchSandboxesEvent>,
    next_cid: Arc<AtomicU32>,
}

struct SandboxRecord {
    snapshot: DriverSandbox,
    vm: FirecrackerVm,
    supervisor: Child,
    run_dir: PathBuf,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FirecrackerSandboxConfig {
    command: Option<Vec<String>>,
    workdir: Option<String>,
}

impl FirecrackerComputeDriver {
    pub fn new(config: FirecrackerComputeConfig) -> Result<Self, String> {
        for (label, path) in [
            ("Firecracker binary", &config.firecracker_binary),
            ("kernel image", &config.kernel_image),
            ("root disk", &config.root_disk),
            ("sandbox supervisor", &config.supervisor_binary),
            ("Firecracker driver", &config.driver_binary),
        ] {
            if !path.is_file() {
                return Err(format!("{label} not found: {}", path.display()));
            }
        }
        std::fs::create_dir_all(&config.state_dir)
            .map_err(|error| format!("create state directory: {error}"))?;
        std::fs::set_permissions(&config.state_dir, Permissions::from_mode(0o700))
            .map_err(|error| format!("restrict state directory: {error}"))?;
        let (events, _) = broadcast::channel(WATCH_BUFFER);
        Ok(Self {
            config: Arc::new(config),
            records: Arc::new(Mutex::new(HashMap::new())),
            events,
            next_cid: Arc::new(AtomicU32::new(3)),
        })
    }

    fn validate(sandbox: &DriverSandbox) -> Result<FirecrackerSandboxConfig, Status> {
        validate_id(&sandbox.id)?;
        let spec = sandbox
            .spec
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("sandbox spec is required"))?;
        if spec.sandbox_token.trim().is_empty() {
            return Err(Status::failed_precondition(
                "firecracker sandboxes require gateway JWT auth",
            ));
        }
        if spec
            .resource_requirements
            .as_ref()
            .and_then(|value| value.gpu.as_ref())
            .is_some()
        {
            return Err(Status::failed_precondition(
                "the Firecracker prototype does not support GPUs",
            ));
        }
        let template = spec
            .template
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("sandbox template is required"))?;
        if !template.agent_socket_path.is_empty() {
            return Err(Status::failed_precondition(
                "the Firecracker prototype does not support agent_socket_path",
            ));
        }
        if template
            .platform_config
            .as_ref()
            .is_some_and(|value| !value.fields.is_empty())
        {
            return Err(Status::failed_precondition(
                "the Firecracker prototype does not support platform_config",
            ));
        }
        let driver = template.driver_config.as_ref().map_or_else(
            || Ok(FirecrackerSandboxConfig::default()),
            |value| {
                serde_json::from_value(struct_to_json_value(value)).map_err(|error| {
                    Status::invalid_argument(format!("invalid firecracker driver_config: {error}"))
                })
            },
        )?;
        if driver.command.as_ref().is_some_and(Vec::is_empty) {
            return Err(Status::invalid_argument(
                "firecracker driver_config.command must not be empty",
            ));
        }
        Ok(driver)
    }

    async fn snapshots(&self) -> Vec<DriverSandbox> {
        let records = self.records.lock().await;
        let mut snapshots = records
            .values()
            .map(|record| record.snapshot.clone())
            .collect::<Vec<_>>();
        snapshots.sort_by(|left, right| left.id.cmp(&right.id));
        snapshots
    }

    fn publish_snapshot(&self, snapshot: DriverSandbox) {
        let _ = self.events.send(WatchSandboxesEvent {
            payload: Some(watch_sandboxes_event::Payload::Sandbox(
                WatchSandboxesSandboxEvent {
                    sandbox: Some(snapshot),
                },
            )),
        });
    }

    fn provision(
        &self,
        sandbox: &DriverSandbox,
        driver: FirecrackerSandboxConfig,
    ) -> Result<SandboxRecord, Status> {
        let run_dir = self.config.state_dir.join(&sandbox.id);
        std::fs::create_dir(&run_dir)
            .map_err(|error| Status::internal(format!("create sandbox state: {error}")))?;
        std::fs::set_permissions(&run_dir, Permissions::from_mode(0o700))
            .map_err(|error| Status::internal(format!("restrict sandbox state: {error}")))?;

        let root_disk = run_dir.join("root.ext4");
        run_checked(
            "cp",
            &[
                "--reflink=auto".as_ref(),
                self.config.root_disk.as_os_str(),
                root_disk.as_os_str(),
            ],
        )?;
        let bootstrap_token = random_token();
        let guest_config_path = run_dir.join("firecracker.json");
        let guest_config = GuestConfig {
            boundary_id: sandbox.id.clone(),
            bootstrap_token: bootstrap_token.clone(),
            control_port: 5500,
            agent_uid: DEFAULT_AGENT_UID,
            agent_gid: DEFAULT_AGENT_GID,
        };
        let bytes = serde_json::to_vec(&guest_config)
            .map_err(|error| Status::internal(format!("encode guest config: {error}")))?;
        std::fs::write(&guest_config_path, bytes)
            .map_err(|error| Status::internal(format!("write guest config: {error}")))?;
        inject_guest_file(
            &root_disk,
            &guest_config_path,
            "/etc/openshell/firecracker.json",
        )?;
        inject_guest_file(
            &root_disk,
            &self.config.driver_binary,
            "/opt/openshell/bin/openshell-driver-firecracker",
        )?;
        run_debugfs(
            &root_disk,
            "set_inode_field /opt/openshell/bin/openshell-driver-firecracker mode 0100755",
        )?;

        let console = run_dir.join("console.log");
        let cid = self.next_cid.fetch_add(1, Ordering::Relaxed);
        let vm = FirecrackerVm::launch(&FirecrackerLaunchConfig {
            firecracker_binary: self.config.firecracker_binary.clone(),
            kernel_image: self.config.kernel_image.clone(),
            root_disk,
            run_dir: run_dir.clone(),
            console_output: console,
            guest_init: "/opt/openshell/bin/openshell-driver-firecracker".to_string(),
            vcpus: self.config.vcpus,
            mem_mib: self.config.mem_mib,
            vsock_cid: cid,
        })
        .map_err(Status::internal)?;

        let sandbox_token_path = run_dir.join("sandbox.jwt");
        let sandbox_token = &sandbox.spec.as_ref().expect("validated spec").sandbox_token;
        std::fs::write(&sandbox_token_path, format!("{sandbox_token}\n"))
            .map_err(|error| Status::internal(format!("write sandbox token: {error}")))?;
        std::fs::set_permissions(&sandbox_token_path, Permissions::from_mode(0o600))
            .map_err(|error| Status::internal(format!("restrict sandbox token: {error}")))?;
        let topology = FirecrackerTopology {
            boundary_id: sandbox.id.clone(),
            vsock_uds_path: vm.vsock_uds_path().to_path_buf(),
            control_port: 5500,
            bootstrap_token,
        };
        let payload = topology
            .encode()
            .map_err(|error| Status::internal(error.to_string()))?;
        let command = driver.command.unwrap_or_else(|| {
            vec![
                "/bin/sh".to_string(),
                "-lc".to_string(),
                "while :; do sleep 3600; done".to_string(),
            ]
        });
        let mut supervisor_command = Command::new(&self.config.supervisor_binary);
        supervisor_command
            .arg(format!("--topology-backend-name={}", crate::BACKEND_NAME))
            .arg(format!("--topology-version={INTERFACE_VERSION}"))
            .arg(format!(
                "--topology-payload-base64={}",
                base64::engine::general_purpose::STANDARD.encode(payload)
            ))
            .arg("--workdir")
            .arg(driver.workdir.unwrap_or_else(|| "/sandbox".to_string()))
            .arg("--")
            .args(command)
            .env(
                openshell_core::sandbox_env::ENDPOINT,
                &self.config.gateway_endpoint,
            )
            .env(openshell_core::sandbox_env::SANDBOX_ID, &sandbox.id)
            .env(openshell_core::sandbox_env::SANDBOX, &sandbox.name)
            .env(
                openshell_core::sandbox_env::SANDBOX_TOKEN_FILE,
                &sandbox_token_path,
            )
            .env(
                openshell_core::sandbox_env::SSH_SOCKET_PATH,
                run_dir.join("ssh.sock"),
            )
            .env(
                openshell_core::sandbox_env::SANDBOX_UID,
                DEFAULT_AGENT_UID.to_string(),
            )
            .env(
                openshell_core::sandbox_env::SANDBOX_GID,
                DEFAULT_AGENT_GID.to_string(),
            )
            .env(openshell_core::sandbox_env::OCI_IMAGE_USER, "")
            .env(
                openshell_core::sandbox_env::LOG_LEVEL,
                sandbox
                    .spec
                    .as_ref()
                    .expect("validated spec")
                    .log_level
                    .clone(),
            )
            .stdout(Stdio::from(
                std::fs::File::create(run_dir.join("supervisor.log"))
                    .map_err(|error| Status::internal(error.to_string()))?,
            ))
            .stderr(Stdio::from(
                std::fs::File::create(run_dir.join("supervisor.err.log"))
                    .map_err(|error| Status::internal(error.to_string()))?,
            ));
        unsafe {
            supervisor_command.pre_exec(|| {
                nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGKILL)
                    .map_err(|error| std::io::Error::other(error.to_string()))
            });
        }
        let supervisor = supervisor_command
            .spawn()
            .map_err(|error| Status::internal(format!("start host supervisor: {error}")))?;
        Ok(SandboxRecord {
            snapshot: ready_snapshot(sandbox),
            vm,
            supervisor,
            run_dir,
        })
    }
}

#[tonic::async_trait]
impl ComputeDriver for FirecrackerComputeDriver {
    async fn get_capabilities(
        &self,
        _: Request<GetCapabilitiesRequest>,
    ) -> Result<Response<GetCapabilitiesResponse>, Status> {
        Ok(Response::new(GetCapabilitiesResponse {
            driver_name: crate::BACKEND_NAME.to_string(),
            driver_version: openshell_core::VERSION.to_string(),
            default_image: self.config.default_image.clone(),
        }))
    }

    async fn get_gateway_listener_requirements(
        &self,
        _: Request<GetGatewayListenerRequirementsRequest>,
    ) -> Result<Response<GetGatewayListenerRequirementsResponse>, Status> {
        Ok(Response::new(GetGatewayListenerRequirementsResponse {
            requirements: Vec::new(),
        }))
    }

    async fn validate_sandbox_create(
        &self,
        request: Request<ValidateSandboxCreateRequest>,
    ) -> Result<Response<ValidateSandboxCreateResponse>, Status> {
        let sandbox = request
            .into_inner()
            .sandbox
            .ok_or_else(|| Status::invalid_argument("sandbox is required"))?;
        Self::validate(&sandbox)?;
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
        let driver = Self::validate(&sandbox)?;
        let mut records = self.records.lock().await;
        if records.contains_key(&sandbox.id) {
            return Err(Status::already_exists("sandbox already exists"));
        }
        let record = self.provision(&sandbox, driver)?;
        let snapshot = record.snapshot.clone();
        records.insert(sandbox.id.clone(), record);
        drop(records);
        self.publish_snapshot(snapshot);
        Ok(Response::new(CreateSandboxResponse {}))
    }

    async fn get_sandbox(
        &self,
        request: Request<GetSandboxRequest>,
    ) -> Result<Response<GetSandboxResponse>, Status> {
        let request = request.into_inner();
        let records = self.records.lock().await;
        let sandbox = records
            .values()
            .find(|record| {
                (!request.sandbox_id.is_empty() && record.snapshot.id == request.sandbox_id)
                    || (!request.sandbox_name.is_empty()
                        && record.snapshot.name == request.sandbox_name)
            })
            .map(|record| record.snapshot.clone())
            .ok_or_else(|| Status::not_found("sandbox not found"))?;
        Ok(Response::new(GetSandboxResponse {
            sandbox: Some(sandbox),
        }))
    }

    async fn list_sandboxes(
        &self,
        _: Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        Ok(Response::new(ListSandboxesResponse {
            sandboxes: self.snapshots().await,
        }))
    }

    async fn stop_sandbox(
        &self,
        _: Request<StopSandboxRequest>,
    ) -> Result<Response<StopSandboxResponse>, Status> {
        Err(Status::unimplemented(
            "stop is not implemented by the Firecracker prototype",
        ))
    }

    async fn delete_sandbox(
        &self,
        request: Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        let request = request.into_inner();
        let mut records = self.records.lock().await;
        let id = if request.sandbox_id.is_empty() {
            records
                .values()
                .find(|record| record.snapshot.name == request.sandbox_name)
                .map(|record| record.snapshot.id.clone())
                .unwrap_or_default()
        } else {
            request.sandbox_id
        };
        let Some(mut record) = records.remove(&id) else {
            return Ok(Response::new(DeleteSandboxResponse { deleted: false }));
        };
        let _ = record.supervisor.kill();
        let _ = record.supervisor.wait();
        let _ = record.vm.terminate();
        let run_dir = record.run_dir.clone();
        drop(record);
        let _ = std::fs::remove_dir_all(run_dir);
        let _ = self.events.send(WatchSandboxesEvent {
            payload: Some(watch_sandboxes_event::Payload::Deleted(
                WatchSandboxesDeletedEvent { sandbox_id: id },
            )),
        });
        Ok(Response::new(DeleteSandboxResponse { deleted: true }))
    }

    type WatchSandboxesStream =
        Pin<Box<dyn Stream<Item = Result<WatchSandboxesEvent, Status>> + Send + 'static>>;

    async fn watch_sandboxes(
        &self,
        _: Request<WatchSandboxesRequest>,
    ) -> Result<Response<Self::WatchSandboxesStream>, Status> {
        let initial = self.snapshots().await;
        let mut events = self.events.subscribe();
        let (tx, rx) = mpsc::channel(WATCH_BUFFER);
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
                match events.recv().await {
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
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

fn ready_snapshot(sandbox: &DriverSandbox) -> DriverSandbox {
    DriverSandbox {
        id: sandbox.id.clone(),
        name: sandbox.name.clone(),
        namespace: sandbox.namespace.clone(),
        spec: None,
        status: Some(DriverSandboxStatus {
            sandbox_name: sandbox.name.clone(),
            instance_id: sandbox.id.clone(),
            agent_fd: String::new(),
            sandbox_fd: String::new(),
            conditions: vec![DriverCondition {
                r#type: "Ready".to_string(),
                status: "True".to_string(),
                reason: "FirecrackerStarted".to_string(),
                message: "Firecracker VM and host supervisor started".to_string(),
                last_transition_time: String::new(),
            }],
            deleting: false,
        }),
        workspace: sandbox.workspace.clone(),
    }
}

fn validate_id(id: &str) -> Result<(), Status> {
    if id.is_empty()
        || id.len() > 128
        || matches!(id, "." | "..")
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(Status::invalid_argument(
            "sandbox id must match [A-Za-z0-9._-]{1,128}",
        ));
    }
    Ok(())
}

fn random_token() -> String {
    let mut token = String::with_capacity(64);
    for byte in rand::random::<[u8; 32]>() {
        write!(&mut token, "{byte:02x}").expect("writing to String cannot fail");
    }
    token
}

fn inject_guest_file(disk: &Path, source: &Path, destination: &str) -> Result<(), Status> {
    run_debugfs(disk, &format!("rm {destination}")).ok();
    run_debugfs(disk, &format!("write {} {destination}", source.display()))
}

fn run_debugfs(disk: &Path, operation: &str) -> Result<(), Status> {
    run_checked(
        "debugfs",
        &[
            "-w".as_ref(),
            "-R".as_ref(),
            operation.as_ref(),
            disk.as_os_str(),
        ],
    )
}

fn run_checked(program: &str, args: &[&std::ffi::OsStr]) -> Result<(), Status> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| Status::internal(format!("run {program}: {error}")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Status::internal(format!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_token_is_32_random_bytes_in_hex() {
        let token = random_token();
        assert_eq!(token.len(), 64);
        assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn sandbox_ids_are_safe_state_directory_components() {
        assert!(validate_id("sandbox-123._ok").is_ok());
        assert!(validate_id("../escape").is_err());
        assert!(validate_id("").is_err());
    }
}
