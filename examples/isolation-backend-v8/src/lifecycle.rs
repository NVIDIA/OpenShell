// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor-facing lifecycle for the network-disabled JavaScript runtime.
use crate::{
    guest::{Guest, GuestResult, GuestStatus, read_script},
    launch::Launch,
    protocol::{self, BACKEND, boundary::*, control::*},
};
use anyhow::{Result, ensure};
use openshell_core::jwt::{SandboxId, SessionJwtVerifier, SessionTokenProfile, SystemJwtClock};
use openshell_isolation_interface::contract::BoundaryConfirmation;
use openshell_sandbox_backend::{boundary_protocol as wire, sandbox_auth::*};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Mutex, watch};
use tonic::{Request, Response, Status, Streaming};

type Chunks =
    std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<ExchangeFrame, Status>> + Send>>;
struct State {
    policy: Option<wire::SandboxPolicyWire>,
    ledger: HashMap<String, (String, wire::Response)>,
    publications: (u64, u64),
    running: bool,
    terminal: bool,
}

pub struct Runtime {
    launch: Launch,
    guest: Arc<Guest>,
    authenticator: SandboxProtocolAuthenticator,
    pub registry: Arc<SandboxConnectionRegistry>,
    opened: Mutex<HashSet<SandboxConnectionId>>,
    state: Mutex<State>,
    mutation: Mutex<()>,
    output: Arc<std::sync::Mutex<Option<(crate::guest::Output, crate::guest::Output)>>>,
    result: watch::Sender<Option<Arc<GuestResult>>>,
    ended: watch::Sender<bool>,
}

impl Runtime {
    pub fn new(launch: Launch) -> Result<Arc<Self>> {
        let bytes = read_script(&launch.script)?;
        let digest = format!("{:x}", Sha256::digest(&bytes));
        ensure!(
            serde_json::from_slice::<serde_json::Value>(&launch.descriptor)?["script_sha256"]
                == digest,
            "script binding changed"
        );
        ensure!(
            launch.boundary.workload_identity.resource_digest == digest,
            "script identity changed"
        );
        ensure!(
            launch.boundary.workload_identity == crate::launch::host_identity(digest.clone())?,
            "backend identity differs from the admitted host identity"
        );
        use openshell_isolation_interface::contract::ProvisioningEvidence;
        let fence = ProvisioningEvidence::from_enforcement_evidence(
            launch.boundary.generation.clone(),
            &crate::launch::capability_evidence(&digest),
        )?;
        ensure!(
            fence == launch.boundary.provisioning_evidence,
            "native V8 capability evidence differs from driver fence"
        );
        let verifier = SessionJwtVerifier::new(
            &launch.gateway_id,
            SessionTokenProfile::Sandbox,
            launch.keys.clone(),
            Arc::new(SystemJwtClock),
        )?;
        let authenticator = SandboxProtocolAuthenticator::new(
            verifier,
            SandboxId::parse(launch.boundary.sandbox_id.clone())?,
            openshell_core::sandbox_generation::SandboxGenerationId::parse(
                launch.boundary.generation.clone(),
            )?,
            launch.epoch,
        );
        let registry = Arc::new(SandboxConnectionRegistry::new(
            launch.boundary.session_id,
            launch.rotation,
        ));
        Ok(Arc::new(Self {
            launch,
            guest: Arc::new(Guest::new(&bytes)?),
            authenticator,
            registry,
            opened: Mutex::new(HashSet::new()),
            mutation: Mutex::new(()),
            state: Mutex::new(State {
                policy: None,
                ledger: HashMap::new(),
                publications: (0, 0),
                running: false,
                terminal: false,
            }),
            output: Arc::new(std::sync::Mutex::new(None)),
            result: watch::channel(None).0,
            ended: watch::channel(false).0,
        }))
    }
    fn authenticate<T>(&self, request: &Request<T>) -> Result<SandboxProtocolPrincipal, Status> {
        let id = *request
            .extensions()
            .get::<SandboxConnectionId>()
            .ok_or_else(|| Status::unauthenticated("TLS connection identity missing"))?;
        self.authenticator
            .authenticate(id, request.metadata())
            .map_err(|_| Status::unauthenticated("invalid sandbox launch credential"))
    }
    async fn route<F: prost::Message + Default>(
        &self,
        mut request: Request<Streaming<F>>,
        binding: fn(F) -> Option<String>,
    ) -> Result<(SandboxProtocolPrincipal, Streaming<F>), Status> {
        let principal = self.authenticate(&request)?;
        if !self
            .opened
            .lock()
            .await
            .contains(&principal.connection_id())
        {
            return Err(Status::failed_precondition(
                "OpenBoundary required on this connection",
            ));
        }
        let first = request.get_mut().message().await?;
        if first.and_then(binding) != Some(self.launch.boundary.generation.clone()) {
            return Err(Status::permission_denied("wrong boundary handle"));
        }
        Ok((principal, request.into_inner()))
    }
    async fn result(&self) -> Result<Arc<GuestResult>, Status> {
        let mut receiver = self.result.subscribe();
        loop {
            if let Some(result) = receiver.borrow_and_update().clone() {
                return Ok(result);
            }
            receiver
                .changed()
                .await
                .map_err(|_| Status::unavailable("guest completion lost"))?;
        }
    }
    fn exit(result: &GuestResult) -> wire::ExitStatusWire {
        match result.status {
            GuestStatus::Terminated => wire::ExitStatusWire::Signaled(15),
            _ => wire::ExitStatusWire::Exited(result.exit_code.unwrap_or(1)),
        }
    }
    pub async fn stop(&self) {
        self.guest.terminate();
        if self.state.lock().await.running {
            let _ = self.result().await;
        }
        self.state.lock().await.terminal = true;
        self.ended.send_replace(true);
        self.registry.mark_terminal();
    }
    fn validate_policy(&self, policy: &wire::SandboxPolicyWire) -> Result<(), Status> {
        for (selector, expected) in [
            (
                &policy.run_as_user,
                self.launch.boundary.workload_identity.uid,
            ),
            (
                &policy.run_as_group,
                self.launch.boundary.workload_identity.gid,
            ),
        ] {
            if selector
                .as_ref()
                .is_some_and(|value| value != &expected.to_string())
            {
                return Err(Status::permission_denied(
                    "process identity differs from admitted host identity",
                ));
            }
        }
        Ok(())
    }
    async fn control(
        self: &Arc<Self>,
        principal: &SandboxProtocolPrincipal,
        envelope: &wire::RequestEnvelope,
    ) -> Result<wire::Response, Status> {
        use wire::{Request as Q, Response as R};
        envelope
            .validate_payload_digest()
            .map_err(|_| Status::invalid_argument("request digest mismatch"))?;
        // Serialize mutations through validation, effects, and ledger commit.
        let _mutation = if envelope.request.is_replayable_mutation() {
            Some(self.mutation.lock().await)
        } else {
            None
        };
        let cached = {
            let state = self.state.lock().await;
            if let Some((digest, response)) = state.ledger.get(&envelope.request_id) {
                if digest != &envelope.payload_digest {
                    return Err(Status::invalid_argument(
                        "request ID reused with different payload",
                    ));
                }
                Some(response.clone())
            } else {
                if state.terminal
                    && !matches!(envelope.request, Q::Wait { .. } | Q::AttachProcess { .. })
                {
                    return Err(Status::failed_precondition("boundary is terminal"));
                }
                if envelope.request.is_replayable_mutation() && state.ledger.len() >= 1024 {
                    return Err(Status::resource_exhausted("replay ledger full"));
                }
                None
            }
        };
        match &envelope.request {
            Q::DiscoverPolicy => {
                return Ok(R::ImagePolicy {
                    yaml: None,
                    invalid: false,
                });
            }
            Q::Attach {
                supervisor_instance_id,
                ..
            } => {
                self.registry
                    .attach(principal, *supervisor_instance_id)
                    .map_err(|e| Status::failed_precondition(e.to_string()))?;
            }
            Q::Confirm => self
                .registry
                .require_attached(principal)
                .map_err(|e| Status::failed_precondition(e.to_string()))?,
            _ => self
                .registry
                .require_active(principal)
                .map_err(|e| Status::failed_precondition(e.to_string()))?,
        }
        if let Some(response) = cached {
            if matches!(envelope.request, Q::Confirm) {
                self.registry
                    .confirm(principal)
                    .map_err(|e| Status::failed_precondition(e.to_string()))?;
            }
            return Ok(response);
        }
        match &envelope.request {
            Q::Wait { process_id } | Q::Signal { process_id, .. } | Q::Terminate { process_id } => {
                self.check_process(process_id)?
            }
            _ => {}
        }
        if matches!(envelope.request, Q::Wait { .. }) {
            return Ok(R::Exited {
                status: Self::exit(self.result().await?.as_ref()),
            });
        }
        if let Q::Signal { signal, .. } = &envelope.request
            && !matches!(signal, wire::SignalWire::Term)
        {
            return Err(Status::unimplemented("js-sbx supports TERM only"));
        }
        if matches!(
            envelope.request,
            Q::TerminateBoundary | Q::Terminate { .. } | Q::Signal { .. }
        ) {
            self.guest.terminate();
            if self.state.lock().await.running {
                let _ = self.result().await?;
            }
        }
        let mut state = self.state.lock().await;
        let response = match &envelope.request {
            Q::Attach { policy, .. } => {
                self.validate_policy(policy)?;
                if state
                    .policy
                    .as_ref()
                    .is_some_and(|old| old != policy.as_ref())
                {
                    return Err(Status::failed_precondition(
                        "policy changed during attachment",
                    ));
                }
                state.policy = Some(*policy.clone());
                R::Attached {
                    snapshot: wire::SessionSnapshotWire {
                        generation: self.launch.boundary.generation.clone(),
                        processes: vec![],
                    },
                }
            }
            Q::Confirm => {
                if state.policy.is_none() {
                    return Err(Status::failed_precondition("attach required"));
                }
                self.registry
                    .confirm(principal)
                    .map_err(|e| Status::failed_precondition(e.to_string()))?;
                R::Confirmed {
                    confirmation: Box::new(BoundaryConfirmation {
                        generation: self.launch.boundary.generation.clone(),
                        session_id: self.launch.boundary.session_id,
                        identity: self.launch.boundary.workload_identity.clone(),
                        resource_claims: self.launch.boundary.resource_claims.clone(),
                        provisioning_evidence_digest: self
                            .launch
                            .boundary
                            .provisioning_evidence
                            .evidence_digest,
                        backend_audit: serde_json::json!({"script_sha256": self.launch.boundary.workload_identity.resource_digest, "network": "disabled", "filesystem": "no-host-access"}),
                    }),
                }
            }
            Q::StartAgent {
                sandbox_id,
                spec,
                provider_env_revision,
                provider_env,
                provider_files,
                ..
            } => {
                if sandbox_id != &self.launch.boundary.sandbox_id || state.policy.is_none() {
                    return Err(Status::permission_denied("admitted launch changed"));
                }
                if spec.timeout_secs != 0
                    || spec.workdir.as_deref().is_some_and(|path| path != "/work")
                    || spec.program != "/work/guest.js"
                    || !spec.args.is_empty()
                    || spec.interactive
                    || !provider_env.is_empty()
                    || !provider_files.is_empty()
                {
                    return Err(Status::unimplemented(
                        "this example accepts only the provisioned script, without args, providers or PTY",
                    ));
                }
                if state.running {
                    return Err(Status::failed_precondition("main process already started"));
                }
                state.running = true;
                state.publications = (*provider_env_revision, 1);
                let runtime = self.clone();
                let guest = self.guest.clone();
                let output = self.output.clone();
                tokio::spawn(async move {
                    let result = tokio::task::spawn_blocking(move || {
                        guest.run(|stdout, stderr| {
                            *output.lock().unwrap() = Some((stdout, stderr));
                        })
                    })
                    .await;
                    let result = match result {
                        Ok(Ok(result)) => result,
                        error => GuestResult {
                            status: GuestStatus::Failed,
                            exit_code: None,
                            stdout: vec![],
                            stderr: format!("guest failed: {error:?}").into_bytes(),
                            script_sha256: String::new(),
                        },
                    };
                    println!(
                        "Guest completed: {:?}, exit code {:?}",
                        result.status, result.exit_code
                    );
                    for line in String::from_utf8_lossy(&result.stdout).lines() {
                        println!("guest: {line}");
                    }
                    for line in String::from_utf8_lossy(&result.stderr).lines() {
                        eprintln!("guest: {line}");
                    }
                    runtime.result.send_replace(Some(Arc::new(result)));
                });
                R::Started {
                    process_id: self.process_id(),
                    provider_env_revision: *provider_env_revision,
                    provider_env_generation: 1,
                }
            }
            Q::AttachProcess { process_id } => {
                self.check_process(process_id)?;
                R::ProcessAttached { terminal: false }
            }
            Q::UpdateProviderEnvironment {
                revision,
                generation,
                provider_env,
                provider_files,
            } => {
                if !provider_env.is_empty() || !provider_files.is_empty() {
                    return Err(Status::unimplemented(
                        "provider injection is not supported in this example",
                    ));
                }
                if *generation <= state.publications.1 || *revision < state.publications.0 {
                    return Err(Status::failed_precondition("stale publication"));
                }
                state.publications = (*revision, *generation);
                R::ProviderEnvironmentUpdated {
                    revision: *revision,
                    generation: *generation,
                    applied: true,
                }
            }
            Q::Signal { process_id, .. } => {
                self.check_process(process_id)?;
                R::Signaled
            }
            Q::Terminate { process_id } => {
                self.check_process(process_id)?;
                R::Terminated
            }
            Q::TerminateBoundary => {
                state.terminal = true;
                self.ended.send_replace(true);
                R::BoundaryTerminated
            }
            Q::OpenMediation => R::MediationReady,
            _ => {
                return Err(Status::unimplemented(
                    "operation is not supported by js-sbx",
                ));
            }
        };
        if envelope.request.is_replayable_mutation() {
            state.ledger.insert(
                envelope.request_id.clone(),
                (envelope.payload_digest.clone(), response.clone()),
            );
        }
        Ok(response)
    }
    fn process_output(self: Arc<Self>) -> Chunks {
        Box::pin(async_stream::try_stream! {
            let mut offsets = [0usize, 0usize];
            loop {
                let complete = self.result.borrow().clone();
                let buffers = if let Some(result) = &complete {
                    [result.stdout.clone(), result.stderr.clone()]
                } else {
                    self.output.lock().unwrap().as_ref()
                        .map(|(out, err)| [out.contents(), err.contents()])
                        .unwrap_or_default()
                };
                for (index, data) in buffers.into_iter().enumerate() {
                    let channel = if index == 0 {
                        wire::STREAM_STDOUT
                    } else {
                        wire::STREAM_STDERR
                    };
                    let pending = data.get(offsets[index]..)
                        .ok_or_else(|| Status::internal("guest output was truncated"))?;
                    for piece in pending.chunks(wire::MAX_STREAM_FRAME_BYTES) {
                        yield protocol::stream_frame(channel, piece)?;
                    }
                    offsets[index] = data.len();
                }
                if let Some(result) = complete {
                    let bytes = openshell_sandbox_backend::protobuf::encode(&Runtime::exit(&result))
                        .map_err(|_| Status::internal("encode exit status"))?;
                    yield protocol::stream_frame(wire::STREAM_EXIT, &bytes)?;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
    }
    fn process_id(&self) -> String {
        format!("{}:main", self.launch.boundary.generation)
    }
    fn check_process(&self, id: &str) -> Result<(), Status> {
        if id == self.process_id() {
            Ok(())
        } else {
            Err(Status::not_found("unknown guest process"))
        }
    }
}

#[tonic::async_trait]
impl isolation_backend_server::IsolationBackend for Arc<Runtime> {
    async fn describe(
        &self,
        request: Request<DescribeIsolationBackendRequest>,
    ) -> Result<Response<DescribeIsolationBackendResponse>, Status> {
        let peer = request
            .into_inner()
            .supervisor
            .ok_or_else(|| Status::failed_precondition("peer metadata required"))?;
        let capability = protocol::CAPABILITY.to_string();
        if peer.protocol_version.map(|v| v.major) != Some(1)
            || !peer.supported_capabilities.contains(&capability)
            || peer.required_capabilities.iter().any(|c| c != &capability)
        {
            return Err(Status::failed_precondition(
                "incompatible Sandbox Protocol peer",
            ));
        }
        Ok(Response::new(DescribeIsolationBackendResponse {
            backend: Some(protocol::metadata()),
        }))
    }
    async fn open_boundary(
        &self,
        request: Request<OpenBoundaryRequest>,
    ) -> Result<Response<OpenBoundaryResponse>, Status> {
        let principal = self.authenticate(&request)?;
        let q = request.into_inner();
        let b = &self.launch.boundary;
        if q.session_id != b.session_id.to_string()
            || q.backend_name != BACKEND
            || q.driver_descriptor != self.launch.descriptor
        {
            return Err(Status::permission_denied(
                "immutable launch binding changed",
            ));
        }
        self.opened.lock().await.insert(principal.connection_id());
        Ok(Response::new(OpenBoundaryResponse {
            boundary_id: b.generation.clone(),
            outcome: 1,
        }))
    }
    async fn suspend_boundary(
        &self,
        request: Request<SuspendBoundaryRequest>,
    ) -> Result<Response<SuspendBoundaryResponse>, Status> {
        self.authenticate(&request)?;
        Err(Status::unimplemented("suspend is unsupported"))
    }
    async fn resume_boundary(
        &self,
        request: Request<ResumeBoundaryRequest>,
    ) -> Result<Response<OpenBoundaryResponse>, Status> {
        self.authenticate(&request)?;
        Err(Status::unimplemented("resume is unsupported"))
    }
}

#[tonic::async_trait]
impl sandbox_protocol_server::SandboxProtocol for Arc<Runtime> {
    type ExchangeStream = Chunks;
    type MediateStream =
        std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<MediateFrame, Status>> + Send>>;
    async fn mediate(
        &self,
        request: Request<Streaming<MediateFrame>>,
    ) -> Result<Response<Self::MediateStream>, Status> {
        let (principal, mut input) = self
            .route(request, |f| match f.payload {
                Some(mediate_frame::Payload::BoundaryId(id)) => Some(id),
                _ => None,
            })
            .await?;
        let runtime = self.clone();
        let stream = async_stream::try_stream! {
            let envelope = protocol::read_mediation_request(&mut input).await?;
            let response = runtime.control(&principal, &envelope).await?;
            yield protocol::mediation_response(envelope.request_id, response)?;
            let mut ended = runtime.ended.subscribe();
            while !*ended.borrow_and_update() {
                ended.changed().await.map_err(|_| Status::unavailable("boundary closed"))?;
            }
        };
        Ok(Response::new(Box::pin(stream)))
    }
    async fn exchange(
        &self,
        request: Request<Streaming<ExchangeFrame>>,
    ) -> Result<Response<Chunks>, Status> {
        let (principal, mut input) = self
            .route(request, |f| match f.payload {
                Some(exchange_frame::Payload::BoundaryId(id)) => Some(id),
                _ => None,
            })
            .await?;
        let runtime = self.clone();
        let stream = async_stream::try_stream! {
            let envelope = protocol::read_request(&mut input).await?;
            if matches!(envelope.request, wire::Request::AcceptNetwork) {
                envelope.validate_payload_digest()
                    .map_err(|_| Status::invalid_argument("request digest mismatch"))?;
                runtime.registry.require_active(&principal)
                    .map_err(|e| Status::failed_precondition(e.to_string()))?;
                let mut ended = runtime.ended.subscribe();
                // The guest has no socket bindings. Keep the network accept
                // pending until shutdown or the supervisor disconnects.
                tokio::select! {
                    _ = ended.wait_for(|value| *value) => {},
                    _ = input.message() => {},
                }
                return;
            }
            let response = match runtime.control(&principal, &envelope).await {
                Ok(response) => response,
                Err(error) => wire::Response::Error {
                    kind: match error.code() {
                        tonic::Code::InvalidArgument => wire::BoundaryErrorKind::Invalid,
                        tonic::Code::Unavailable => wire::BoundaryErrorKind::Unavailable,
                        tonic::Code::Unimplemented => wire::BoundaryErrorKind::Unsupported,
                        _ => wire::BoundaryErrorKind::Denied,
                    },
                    message: error.message().to_string(),
                },
            };
            let attached = matches!(response, wire::Response::ProcessAttached { .. });
            let mediation = matches!(response, wire::Response::MediationReady);
            yield protocol::response(envelope.request_id, response)?;
            if attached {
                use tokio_stream::StreamExt;
                let mut output = runtime.clone().process_output();
                while let Some(chunk) = output.next().await {
                    yield chunk?;
                }
            }
            if mediation {
                let mut ended = runtime.ended.subscribe();
                while !*ended.borrow_and_update() {
                    ended.changed().await
                        .map_err(|_| Status::unavailable("boundary closed"))?;
                }
            }
        };
        Ok(Response::new(Box::pin(stream)))
    }
}

pub async fn serve(state_dir: PathBuf) -> Result<()> {
    let state_dir = state_dir.canonicalize()?;
    let socket_path = state_dir.join("backend.sock");
    println!(
        "js-sbx waiting for driver provisioning in {} on {}",
        state_dir.display(),
        socket_path.display()
    );
    loop {
        let path = state_dir.join("launch.json");
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let launch: Launch = serde_json::from_slice(&std::fs::read(&path)?)?;
        let certs = rustls_pemfile::certs(&mut launch.certificate.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let key = rustls_pemfile::private_key(&mut launch.private_key.as_bytes())?
            .ok_or_else(|| anyhow::anyhow!("missing TLS key"))?;
        let mut tls =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(certs, key)?;
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let runtime = Runtime::new(launch)?;
        println!(
            "JavaScript runtime provisioned: {}",
            runtime.launch.boundary.sandbox_id
        );
        let registry = runtime.registry.clone();
        let listener = tokio::net::UnixListener::bind(&socket_path)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
        crate::launch::write_private(&state_dir.join("active"), b"ready")?;
        let incoming = async_stream::stream! { loop {
            let (socket,_)=match listener.accept().await { Ok(v)=>v,Err(e)=>{yield Err(e);continue} };
            match tokio::time::timeout(Duration::from_secs(5),acceptor.accept(socket)).await {
                Ok(Ok(stream))=>yield Ok(crate::transport::Connection {stream,id:SandboxConnectionId::new(),registry:registry.clone()}),
                _=>continue,
            }
        }};
        let shutdown = async {
            while path.exists() {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            runtime.stop().await;
        };
        tonic::transport::Server::builder()
            .add_service(
                isolation_backend_server::IsolationBackendServer::new(runtime.clone())
                    .max_decoding_message_size(64 * 1024)
                    .max_encoding_message_size(64 * 1024),
            )
            .add_service(
                sandbox_protocol_server::SandboxProtocolServer::new(runtime.clone())
                    .max_decoding_message_size(
                        openshell_sandbox_backend::stream_adapter::MAX_MESSAGE_BYTES,
                    )
                    .max_encoding_message_size(
                        openshell_sandbox_backend::stream_adapter::MAX_MESSAGE_BYTES,
                    ),
            )
            .serve_with_incoming_shutdown(incoming, shutdown)
            .await?;
        std::fs::remove_file(&socket_path)?;
        std::fs::remove_file(state_dir.join("active"))?;
    }
}
