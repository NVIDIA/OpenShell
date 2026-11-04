// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Single-sandbox local compute placement. The backend is a separate process.
use crate::{
    guest::read_script,
    launch::{Launch, write_private},
    protocol::BACKEND,
};
use anyhow::{Result, ensure};
use openshell_core::{
    extension_protocol::{self, ExtensionFamily},
    jwt::SandboxLaunchAuthentication,
    proto::compute::v1::*,
};
use openshell_isolation_interface::contract::ProvisioningEvidence;
use openshell_sandbox_backend::{
    boundary_protocol::{SandboxTlsClientConfig, generate_sandbox_tls_material},
    delegated::DelegatedLaunch,
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};

pub struct Driver {
    pub state_dir: PathBuf,
    pub supervisor: PathBuf,
    pub script: PathBuf,
    pub gateway: String,
    pub policy_rules: PathBuf,
    entry: Mutex<Option<Entry>>,
    deleted: tokio::sync::watch::Sender<Option<String>>,
}
struct Entry {
    sandbox: DriverSandbox,
    supervisor: tokio::process::Child,
    boundary: DelegatedLaunch,
}
impl Driver {
    pub fn new(
        state_dir: PathBuf,
        supervisor: PathBuf,
        script: PathBuf,
        gateway: String,
        policy_rules: PathBuf,
    ) -> Result<Self> {
        ensure!(
            !rustix::process::geteuid().is_root(),
            "run this local example as a non-root user"
        );
        ensure!(
            !state_dir.join("launch.json").exists(),
            "previous launch is still present; stop the old demo and use a fresh state directory"
        );
        std::fs::create_dir_all(&state_dir)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            state_dir: state_dir.canonicalize()?,
            supervisor: supervisor.canonicalize()?,
            script: script.canonicalize()?,
            gateway,
            policy_rules: policy_rules.canonicalize()?,
            entry: Mutex::new(None),
            deleted: tokio::sync::watch::channel(None).0,
        })
    }
    fn validate(&self, sandbox: &DriverSandbox) -> Result<(), Status> {
        let spec = sandbox
            .spec
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("sandbox spec is required"))?;
        let registration = spec
            .isolation_backend
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("configure the driver isolation_backend"))?;
        if registration.name != BACKEND {
            return Err(Status::failed_precondition("this driver requires js-sbx"));
        }
        if spec.command != ["/work/guest.js"] || spec.tty {
            return Err(Status::invalid_argument(
                "use /work/guest.js without args or TTY",
            ));
        }
        if spec.resource_requirements.is_some() || !spec.environment.is_empty() {
            return Err(Status::invalid_argument(
                "resource requests and workload environment are not supported",
            ));
        }
        if let Some(template) = &spec.template
            && (!template.environment.is_empty()
                || template.driver_config.is_some()
                || template.platform_config.is_some()
                || template.resources.is_some()
                || (!template.image.is_empty() && template.image != "js-sbx:example"))
        {
            return Err(Status::invalid_argument(
                "template overrides are unsupported",
            ));
        }
        Ok(())
    }
    fn observation(entry: &mut Entry) -> DriverSandbox {
        let exited = entry.supervisor.try_wait().ok().flatten();
        let mut sandbox = entry.sandbox.clone();
        let identity = &entry.boundary.workload_identity;
        sandbox.spec = None;
        sandbox.status = Some(DriverSandboxStatus {
            name: sandbox.name.clone(),
            instance_id: sandbox.id.clone(),
            conditions: vec![DriverCondition {
                r#type: if exited.is_some() { "Stopped" } else { "Ready" }.into(),
                status: "True".into(),
                ..Default::default()
            }],
            resolved_identity: Some(ResolvedWorkloadIdentity {
                uid: identity.uid,
                gid: identity.gid,
                supplementary_gids: identity.supplementary_gids.clone(),
                source: identity.source.clone(),
                resource_digest: identity.resource_digest.clone(),
            }),
            fence_evidence: Some(DriverFenceEvidence {
                generation: entry.boundary.generation.clone(),
                evidence_digest: entry
                    .boundary
                    .provisioning_evidence
                    .evidence_digest
                    .to_string(),
                resource_claims: Default::default(),
            }),
            ..Default::default()
        });
        sandbox
    }
    async fn stop_entry(&self, entry: &mut Entry) -> Result<(), Status> {
        let _ = entry.supervisor.start_kill();
        let _ = entry.supervisor.wait().await;
        self.retire_boundary().await
    }
    async fn retire_boundary(&self) -> Result<(), Status> {
        match std::fs::remove_file(self.state_dir.join("launch.json")) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Status::internal("remove backend launch")),
        }
        // Backend closes TLS, interrupts its guest, then acknowledges file deletion.
        for _ in 0..100 {
            if !self.state_dir.join("active").exists() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Err(Status::deadline_exceeded(
            "backend did not acknowledge termination",
        ))
    }
    async fn launch(&self, sandbox: DriverSandbox) -> Result<Entry, Status> {
        self.validate(&sandbox)?;
        let spec = sandbox.spec.as_ref().unwrap();
        let auth: SandboxLaunchAuthentication = serde_json::from_slice(&spec.launch_authentication)
            .map_err(|_| Status::failed_precondition("gateway launch credentials required"))?;
        auth.validate()
            .map_err(|_| Status::failed_precondition("invalid gateway launch credentials"))?;
        let bytes = read_script(&self.script).map_err(internal)?;
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let descriptor =
            serde_json::to_vec(&serde_json::json!({"script_sha256":digest})).map_err(internal)?;
        let identity = crate::launch::host_identity(digest).map_err(internal)?;
        let evidence = crate::launch::capability_evidence(&identity.resource_digest);
        let fence = ProvisioningEvidence::from_enforcement_evidence(
            auth.supervisor.runtime_generation.to_string(),
            &evidence,
        )
        .map_err(internal)?;
        let tls = generate_sandbox_tls_material(auth.supervisor.session_id).map_err(internal)?;
        let boundary = DelegatedLaunch {
            backend_name: BACKEND.into(),
            sandbox_id: sandbox.id.clone(),
            generation: auth.supervisor.runtime_generation.to_string(),
            session_id: auth.supervisor.session_id,
            workload_identity: identity,
            tls: SandboxTlsClientConfig {
                server_name: tls.server_name,
                trust_anchor_pem: tls.trust_anchor_pem,
            },
            host_gateway_ip: None,
            resource_claims: BTreeMap::new(),
            provisioning_evidence: fence,
        };
        let launch = Launch {
            boundary: boundary.clone(),
            script: self.script.clone(),
            descriptor: descriptor.clone(),
            gateway_id: auth.gateway_id,
            keys: auth.verification_keys,
            epoch: auth.supervisor.auth_epoch,
            rotation: auth.supervisor.session_rotation,
            certificate: tls.certificate_chain_pem,
            private_key: tls.private_key_pem,
        };
        let selected = spec.isolation_backend.as_ref().unwrap();
        let Some(isolation_backend_registration::Endpoint::UnixSocketPath(path)) =
            &selected.endpoint
        else {
            return Err(Status::invalid_argument(
                "the local example requires a Unix backend socket",
            ));
        };
        if std::path::Path::new(path) != self.state_dir.join("backend.sock") {
            return Err(Status::invalid_argument(
                "register backend.sock in the shared demo state directory",
            ));
        }
        let registration = openshell_core::isolation_registration::BackendRegistration {
            name: selected.name.clone(),
            endpoint: openshell_core::isolation_registration::SandboxTransport::Unix {
                socket_path: path.into(),
            },
        };
        let result = async {
            for (name, bytes) in [
                (
                    "auth.json",
                    serde_json::to_vec(&auth.supervisor).map_err(internal)?,
                ),
                (
                    "boundary.json",
                    serde_json::to_vec(&boundary).map_err(internal)?,
                ),
                ("descriptor.json", descriptor),
                (
                    "registrations.json",
                    serde_json::to_vec(&serde_json::json!({"backends":[registration]}))
                        .map_err(internal)?,
                ),
                (
                    "launch.json",
                    serde_json::to_vec(&launch).map_err(internal)?,
                ),
            ] {
                write_private(&self.state_dir.join(name), &bytes).map_err(internal)?;
            }
            for attempt in 0..100 {
                if self.state_dir.join("active").exists() {
                    break;
                }
                if attempt == 99 {
                    return Err(Status::deadline_exceeded(
                        "start js-sbx serve before creating the sandbox",
                    ));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let output =
                std::fs::File::create(self.state_dir.join("supervisor.log")).map_err(internal)?;
            let errors = std::fs::File::create(self.state_dir.join("supervisor.err.log"))
                .map_err(internal)?;
            let mut command = tokio::process::Command::new(&self.supervisor);
            command
                .kill_on_drop(true)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &self.state_dir)
                .env(
                    openshell_core::sandbox_env::MAIN_PROCESS_SPEC,
                    openshell_core::sandbox_env::MainProcessConfig::encode_driver_spec(Some(spec))
                        .map_err(internal)?,
                )
                .env(
                    openshell_core::sandbox_env::ADMITTED_ISOLATION_BACKEND,
                    BACKEND,
                )
                .env(
                    openshell_core::sandbox_env::PROXY_TLS_DIR,
                    self.state_dir.join("proxy-tls"),
                )
                .args([
                    "--sandbox-id",
                    &sandbox.id,
                    "--sandbox",
                    &sandbox.name,
                    "--openshell-endpoint",
                    &self.gateway,
                    "--workdir",
                    "/work",
                    "--log-level",
                    "info",
                ])
                .arg("--policy-rules")
                .arg(&self.policy_rules)
                .arg("--ssh-socket-path")
                .arg(self.state_dir.join("ssh.sock"))
                .arg("--health-socket-path")
                .arg(self.state_dir.join("ready.sock"))
                .arg("--auth-bundle-file")
                .arg(self.state_dir.join("auth.json"))
                .arg("--backend-descriptor-file")
                .arg(self.state_dir.join("descriptor.json"))
                .arg("--boundary-launch-file")
                .arg(self.state_dir.join("boundary.json"))
                .arg("--isolation-backends-file")
                .arg(self.state_dir.join("registrations.json"))
                .arg("--parent-liveness-stdin")
                .stdin(std::process::Stdio::piped())
                .stdout(output)
                .stderr(errors);
            let supervisor = command.spawn().map_err(internal)?;
            Ok(supervisor)
        }
        .await;
        let supervisor = match result {
            Ok(supervisor) => supervisor,
            Err(error) => {
                self.retire_boundary().await?;
                return Err(error);
            }
        };
        Ok(Entry {
            sandbox,
            supervisor,
            boundary,
        })
    }
}
fn internal(error: impl std::fmt::Display) -> Status {
    Status::internal(error.to_string())
}

pub struct DriverService(Arc<Driver>);
impl std::ops::Deref for DriverService {
    type Target = Driver;
    fn deref(&self) -> &Driver {
        &self.0
    }
}
#[tonic::async_trait]
impl compute_driver_server::ComputeDriver for DriverService {
    async fn get_capabilities(
        &self,
        _: Request<GetCapabilitiesRequest>,
    ) -> Result<Response<GetCapabilitiesResponse>, Status> {
        let mut extension = extension_protocol::extension_metadata(
            ExtensionFamily::Compute,
            "js-sbx",
            "0.0.0",
            [
                extension_protocol::COMPUTE_LAUNCH_AUTHENTICATION.into(),
                extension_protocol::COMPUTE_ISOLATION_BACKEND.into(),
            ],
        );
        extension
            .required_capabilities
            .push(extension_protocol::COMPUTE_LAUNCH_AUTHENTICATION.into());
        Ok(Response::new(GetCapabilitiesResponse {
            driver_name: "js-sbx-example".into(),
            driver_version: "0.0.0".into(),
            default_image: "js-sbx:example".into(),
            gateway_manages_lifecycle: true,
            driver_reports_runtime_readiness: false,
            extension: Some(extension),
            resource_admission_policy:
                openshell_core::resource_admission::DriverAdmissionConfig::default()
                    .acknowledgement(),
            ..Default::default()
        }))
    }
    async fn authenticate_sandbox(
        &self,
        _: Request<AuthenticateSandboxRequest>,
    ) -> Result<Response<AuthenticateSandboxResponse>, Status> {
        Err(Status::unimplemented(
            "gateway-minted credentials are provisioned directly",
        ))
    }
    async fn validate_sandbox_create(
        &self,
        q: Request<ValidateSandboxCreateRequest>,
    ) -> Result<Response<ValidateSandboxCreateResponse>, Status> {
        self.validate(
            q.get_ref()
                .sandbox
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("sandbox required"))?,
        )?;
        Ok(Response::new(ValidateSandboxCreateResponse {}))
    }
    async fn create_sandbox(
        &self,
        q: Request<CreateSandboxRequest>,
    ) -> Result<Response<CreateSandboxResponse>, Status> {
        let sandbox = q
            .into_inner()
            .sandbox
            .ok_or_else(|| Status::invalid_argument("sandbox required"))?;
        let mut entry = self.entry.lock().await;
        if let Some(current) = entry.as_ref() {
            if current.sandbox.id == sandbox.id {
                return Ok(Response::new(CreateSandboxResponse {
                    runtime_identity: sandbox.id,
                }));
            }
            return Err(Status::resource_exhausted(
                "this example supports one sandbox; delete it first",
            ));
        }
        let created = self.launch(sandbox).await?;
        let identity = created.sandbox.id.clone();
        *entry = Some(created);
        Ok(Response::new(CreateSandboxResponse {
            runtime_identity: identity,
        }))
    }
    async fn get_sandbox(
        &self,
        q: Request<GetSandboxRequest>,
    ) -> Result<Response<GetSandboxResponse>, Status> {
        let mut entry = self.entry.lock().await;
        let entry = entry
            .as_mut()
            .filter(|e| e.sandbox.id == q.get_ref().sandbox_id)
            .ok_or_else(|| Status::not_found("sandbox not found"))?;
        Ok(Response::new(GetSandboxResponse {
            sandbox: Some(Driver::observation(entry)),
        }))
    }
    async fn list_sandboxes(
        &self,
        _: Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        let mut entry = self.entry.lock().await;
        Ok(Response::new(ListSandboxesResponse {
            sandboxes: entry
                .as_mut()
                .map(|e| vec![Driver::observation(e)])
                .unwrap_or_default(),
        }))
    }
    async fn stop_sandbox(
        &self,
        q: Request<StopSandboxRequest>,
    ) -> Result<Response<StopSandboxResponse>, Status> {
        let mut entry = self.entry.lock().await;
        if let Some(entry) = entry
            .as_mut()
            .filter(|e| e.sandbox.id == q.get_ref().sandbox_id)
        {
            self.stop_entry(entry).await?;
        }
        Ok(Response::new(StopSandboxResponse {}))
    }
    async fn suspend_sandbox(
        &self,
        _: Request<SuspendSandboxRequest>,
    ) -> Result<Response<SuspendSandboxResponse>, Status> {
        Err(Status::unimplemented(
            "the V8 example compute driver does not support sandbox suspend",
        ))
    }
    async fn delete_sandbox(
        &self,
        q: Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        let mut entry = self.entry.lock().await;
        if entry
            .as_ref()
            .is_some_and(|e| e.sandbox.id == q.get_ref().sandbox_id)
        {
            self.stop_entry(entry.as_mut().unwrap()).await?;
            *entry = None;
            self.deleted
                .send_replace(Some(q.get_ref().sandbox_id.clone()));
        }
        Ok(Response::new(DeleteSandboxResponse { deleted: true }))
    }
    async fn start_sandbox(
        &self,
        q: Request<StartSandboxRequest>,
    ) -> Result<Response<StartSandboxResponse>, Status> {
        let q = q.into_inner();
        if q.resume {
            return Err(Status::unimplemented(
                "the V8 example compute driver does not support sandbox resume",
            ));
        }
        let mut entry = self.entry.lock().await;
        let current = entry
            .as_mut()
            .filter(|e| e.sandbox.id == q.sandbox_id)
            .ok_or_else(|| Status::not_found("sandbox not found"))?;
        if current.boundary.generation == q.generation_id
            && current.supervisor.try_wait().map_err(internal)?.is_none()
        {
            return Ok(Response::new(StartSandboxResponse {
                runtime_identity: q.sandbox_id,
            }));
        }
        self.stop_entry(current).await?;
        let mut sandbox = current.sandbox.clone();
        let spec = sandbox.spec.as_mut().unwrap();
        spec.launch_authentication = q.launch_authentication;
        spec.isolation_backend = q.isolation_backend;
        let launched = self.launch(sandbox).await?;
        *entry = Some(launched);
        Ok(Response::new(StartSandboxResponse {
            runtime_identity: q.sandbox_id,
        }))
    }
    type WatchSandboxesStream = std::pin::Pin<
        Box<dyn tokio_stream::Stream<Item = Result<WatchSandboxesEvent, Status>> + Send>,
    >;
    async fn watch_sandboxes(
        &self,
        _: Request<WatchSandboxesRequest>,
    ) -> Result<Response<Self::WatchSandboxesStream>, Status> {
        let driver = self.0.clone();
        let mut deleted = self.deleted.subscribe();
        let stream = async_stream::stream! {
            let mut last_deleted = None;
            loop {
                let removed = deleted.borrow_and_update().clone();
                if removed != last_deleted {
                    if let Some(id) = &removed { yield Ok(WatchSandboxesEvent { payload: Some(watch_sandboxes_event::Payload::Deleted(WatchSandboxesDeletedEvent { sandbox_id: id.clone() })) }); }
                    last_deleted = removed;
                }
                let snapshot = {
                    let mut entry = driver.entry.lock().await;
                    entry.as_mut().map(Driver::observation)
                };
                if let Some(sandbox) = snapshot { yield Ok(WatchSandboxesEvent { payload: Some(watch_sandboxes_event::Payload::Sandbox(WatchSandboxesSandboxEvent { sandbox: Some(sandbox) })) }); }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        };
        Ok(Response::new(Box::pin(stream)))
    }
    async fn ensure_workspace(
        &self,
        _: Request<EnsureWorkspaceRequest>,
    ) -> Result<Response<EnsureWorkspaceResponse>, Status> {
        Ok(Response::new(EnsureWorkspaceResponse {}))
    }
    async fn delete_workspace(
        &self,
        _: Request<DeleteWorkspaceRequest>,
    ) -> Result<Response<DeleteWorkspaceResponse>, Status> {
        Ok(Response::new(DeleteWorkspaceResponse {}))
    }
}

pub async fn serve(driver: Arc<Driver>, socket: PathBuf) -> Result<()> {
    ensure!(!socket.exists(), "driver socket already exists");
    let listener = tokio::net::UnixListener::bind(&socket)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
    tonic::transport::Server::builder()
        .add_service(compute_driver_server::ComputeDriverServer::new(
            DriverService(driver),
        ))
        .serve_with_incoming_shutdown(
            tokio_stream::wrappers::UnixListenerStream::new(listener),
            async {
                let _ = tokio::signal::ctrl_c().await;
            },
        )
        .await?;
    std::fs::remove_file(socket)?;
    Ok(())
}
