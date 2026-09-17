// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Windows ProcessContainer implementation of the authenticated Sandbox Protocol.
//!
//! MXC owns the outer filesystem and network fence. This process owns the
//! authenticated lifecycle channel, launches the admitted workload only after
//! confirmation, retains process output, and provides exec and loopback access.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::mem::size_of_val;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use openshell_core::jwt::{
    SandboxId, SessionJwtVerifier, SessionTokenProfile, SessionVerificationKey, SystemJwtClock,
};
use openshell_isolation_interface::contract::BoundaryConfirmation;
use openshell_sandbox_backend::boundary_protocol::{
    AgentSpecWire, BoundaryConfig, BoundaryErrorKind, BoundaryListener, ExecSpecWire,
    ExitStatusWire, MxcSandboxAuditEvidence, OpenShellBoundaryAuditEvidence, OutputWindowWire,
    ProcessKindWire, ProcessSnapshotWire, Request, RequestEnvelope, Response, ResponseEnvelope,
    STREAM_EXIT, STREAM_STDERR, STREAM_STDIN, STREAM_STDIN_CLOSED, STREAM_STDOUT,
    SandboxPolicyWire, SessionSnapshotWire, SignalWire, encode_frame, read_frame_async,
    read_stream_frame, write_stream_frame,
};
use openshell_sandbox_backend::proto::{
    BoundaryChunk,
    isolation_boundary_server::{IsolationBoundary, IsolationBoundaryServer},
};
use openshell_sandbox_backend::sandbox_auth::{
    SandboxConnectionId, SandboxConnectionRegistry, SandboxProtocolAuthenticator,
    SandboxProtocolPrincipal,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::{Child, Command};
use tokio_stream::wrappers::ReceiverStream;

const CONTROL_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
const CONTROL_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
const AUTHENTICATED_RECONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const OUTPUT_BUFFER_BYTES: usize = 1024 * 1024;
const MAX_REPLAY_ENTRIES: usize = 4096;

pub(super) fn run_boundary(
    config_path: &Path,
    _qualification: crate::RuntimeQualification,
) -> Result<(), String> {
    let bytes = std::fs::read(config_path)
        .map_err(|error| format!("read boundary config {}: {error}", config_path.display()))?;
    let config: BoundaryConfig = serde_json::from_slice(&bytes)
        .map_err(|error| format!("decode boundary config {}: {error}", config_path.display()))?;
    validate_config(&config)?;
    std::fs::remove_file(config_path)
        .map_err(|error| format!("consume boundary config {}: {error}", config_path.display()))?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("create Windows boundary runtime: {error}"))?;
    runtime.block_on(async move {
        let (address, tls) = match &config.listener {
            BoundaryListener::TlsTcp { address, tls } => (*address, tls.clone()),
            BoundaryListener::Unix { .. } | BoundaryListener::Vsock { .. } => {
                return Err("MXC requires a TLS TCP boundary listener".to_string());
            }
        };
        let tls = Arc::new(load_tls_server_config(&tls)?);
        let listener = tokio::net::TcpListener::bind(address)
            .await
            .map_err(|error| format!("bind MXC boundary listener at {address}: {error}"))?;
        let boundary = Arc::new(BoundaryRuntime::new(config)?);
        tracing::info!(%address, "MXC Sandbox Protocol listener ready");
        loop {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|error| format!("accept MXC boundary connection: {error}"))?;
            openshell_core::net::set_tcp_nodelay_best_effort(&stream);
            let acceptor = tokio_rustls::TlsAcceptor::from(tls.clone());
            let boundary = boundary.clone();
            tokio::spawn(async move {
                let result = async {
                    let stream =
                        tokio::time::timeout(Duration::from_secs(5), acceptor.accept(stream))
                            .await
                            .map_err(|_| "MXC boundary TLS handshake timed out".to_string())?
                            .map_err(|error| {
                                format!("MXC boundary TLS handshake failed: {error}")
                            })?;
                    serve_grpc(Box::new(stream), boundary, SandboxConnectionId::new()).await
                }
                .await;
                if let Err(error) = result {
                    tracing::debug!(%error, "MXC boundary connection ended");
                }
            });
        }
    })
}

fn validate_config(config: &BoundaryConfig) -> Result<(), String> {
    if config.boundary_id.trim().is_empty()
        || config.generation.trim().is_empty()
        || config.gateway_id.trim().is_empty()
        || config.verification_keys.is_empty()
    {
        return Err("MXC boundary identity and verification keys are required".to_string());
    }
    config
        .outer_fence
        .validate(&config.generation)
        .map_err(|error| error.to_string())?;
    match &config.listener {
        BoundaryListener::TlsTcp { address, tls }
            if address.port() != 0
                && tls.certificate_chain_path.is_absolute()
                && tls.private_key_path.is_absolute() => {}
        BoundaryListener::TlsTcp { .. } => {
            return Err("MXC boundary TLS listener configuration is invalid".to_string());
        }
        BoundaryListener::Unix { .. } | BoundaryListener::Vsock { .. } => {
            return Err("MXC boundary supports only TLS TCP transport".to_string());
        }
    }
    let Some(proxy_url) = config.direct_proxy_url.as_deref() else {
        return Err("MXC boundary requires a generation-scoped direct proxy".to_string());
    };
    let url = proxy_url
        .parse::<url::Url>()
        .map_err(|error| format!("validate MXC direct proxy URL: {error}"))?;
    if url.scheme() != "http"
        || url.host_str() != Some("127.0.0.1")
        || url.port().is_none()
        || url.username().is_empty()
        || url.password().is_none()
    {
        return Err("MXC direct proxy must be an authenticated 127.0.0.1 HTTP URL".to_string());
    }
    Ok(())
}

fn load_tls_server_config(
    tls: &openshell_sandbox_backend::boundary_protocol::SandboxTlsServerConfig,
) -> Result<rustls::ServerConfig, String> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let certificate_bytes = std::fs::read(&tls.certificate_chain_path)
        .map_err(|error| format!("read MXC boundary TLS certificate: {error}"))?;
    let certificates = rustls_pemfile::certs(&mut certificate_bytes.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("parse MXC boundary TLS certificate: {error}"))?;
    let private_key_bytes = std::fs::read(&tls.private_key_path)
        .map_err(|error| format!("read MXC boundary TLS private key: {error}"))?;
    let private_key = rustls_pemfile::private_key(&mut private_key_bytes.as_slice())
        .map_err(|error| format!("parse MXC boundary TLS private key: {error}"))?
        .ok_or_else(|| "MXC boundary TLS private key is empty".to_string())?;
    let mut server =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .map_err(|error| format!("configure MXC boundary TLS: {error}"))?;
    server.alpn_protocols = vec![b"h2".to_vec()];
    for path in [&tls.certificate_chain_path, &tls.private_key_path] {
        std::fs::remove_file(path).map_err(|error| {
            format!("consume MXC boundary TLS file {}: {error}", path.display())
        })?;
    }
    Ok(server)
}

async fn serve_grpc(
    stream: openshell_isolation_interface::contract::BoundaryDuplexStream,
    runtime: Arc<BoundaryRuntime>,
    connection_id: SandboxConnectionId,
) -> Result<(), String> {
    let (connection_shutdown, mut connection_closed) = tokio::sync::watch::channel(());
    runtime.register_connection(connection_id, connection_shutdown.clone());
    let incoming = tokio_stream::StreamExt::chain(
        tokio_stream::iter([Ok::<_, io::Error>(GrpcServerIo {
            stream,
            _connection_alive: connection_shutdown,
            _disconnect: DisconnectGuard {
                runtime: Arc::downgrade(&runtime),
                connection_id,
            },
        })]),
        tokio_stream::pending(),
    );
    let result = tonic::transport::Server::builder()
        .http2_keepalive_interval(Some(CONTROL_KEEPALIVE_INTERVAL))
        .http2_keepalive_timeout(Some(CONTROL_KEEPALIVE_TIMEOUT))
        .add_service(IsolationBoundaryServer::new(GrpcBoundaryService {
            runtime: runtime.clone(),
            connection_id,
        }))
        .serve_with_incoming_shutdown(incoming, async move {
            let _ = connection_closed.changed().await;
        })
        .await;
    runtime.transport_disconnected(connection_id);
    result.map_err(|error| format!("serve MXC boundary gRPC: {error}"))
}

struct GrpcServerIo {
    stream: openshell_isolation_interface::contract::BoundaryDuplexStream,
    _connection_alive: tokio::sync::watch::Sender<()>,
    _disconnect: DisconnectGuard,
}

struct DisconnectGuard {
    runtime: std::sync::Weak<BoundaryRuntime>,
    connection_id: SandboxConnectionId,
}

impl Drop for DisconnectGuard {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.upgrade() {
            runtime.transport_disconnected(self.connection_id);
        }
    }
}

impl tokio::io::AsyncRead for GrpcServerIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl tokio::io::AsyncWrite for GrpcServerIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

impl tonic::transport::server::Connected for GrpcServerIo {
    type ConnectInfo = ();
    fn connect_info(&self) -> Self::ConnectInfo {}
}

#[derive(Clone)]
struct GrpcBoundaryService {
    runtime: Arc<BoundaryRuntime>,
    connection_id: SandboxConnectionId,
}

type GrpcResponseStream = ReceiverStream<Result<BoundaryChunk, tonic::Status>>;

#[tonic::async_trait]
impl IsolationBoundary for GrpcBoundaryService {
    type ExchangeStream = GrpcResponseStream;
    type MediateStream = GrpcResponseStream;

    async fn exchange(
        &self,
        request: tonic::Request<tonic::Streaming<BoundaryChunk>>,
    ) -> Result<tonic::Response<Self::ExchangeStream>, tonic::Status> {
        let principal = self
            .runtime
            .authenticate_request(self.connection_id, request.metadata())?;
        let (stream, response) = bridge_grpc_stream(request.into_inner());
        let runtime = self.runtime.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_one(stream, runtime, principal).await {
                tracing::warn!(%error, "MXC Sandbox Protocol exchange failed");
            }
        });
        Ok(tonic::Response::new(response))
    }

    async fn mediate(
        &self,
        request: tonic::Request<tonic::Streaming<BoundaryChunk>>,
    ) -> Result<tonic::Response<Self::MediateStream>, tonic::Status> {
        let _ = self
            .runtime
            .authenticate_request(self.connection_id, request.metadata())?;
        Err(tonic::Status::failed_precondition(
            "MXC uses the supervisor-owned authenticated explicit proxy",
        ))
    }
}

fn bridge_grpc_stream(
    mut inbound: tonic::Streaming<BoundaryChunk>,
) -> (tokio::io::DuplexStream, GrpcResponseStream) {
    let (application, bridge) = tokio::io::duplex(256 * 1024);
    let (mut reader, mut writer) = tokio::io::split(bridge);
    let (outbound, outbound_rx) = tokio::sync::mpsc::channel(64);
    tokio::spawn(async move {
        loop {
            match inbound.message().await {
                Ok(Some(chunk)) if writer.write_all(&chunk.data).await.is_ok() => {}
                Ok(Some(_)) | Err(_) => return,
                Ok(None) => {
                    let _ = writer.shutdown().await;
                    return;
                }
            }
        }
    });
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            let Ok(read) = reader.read(&mut buffer).await else {
                return;
            };
            if read == 0
                || outbound
                    .send(Ok(BoundaryChunk {
                        data: buffer[..read].to_vec(),
                    }))
                    .await
                    .is_err()
            {
                return;
            }
        }
    });
    (application, ReceiverStream::new(outbound_rx))
}

#[derive(Clone)]
struct ReplayRecord {
    digest: String,
    response: Response,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Lifecycle {
    AwaitingAttach,
    Bound,
    Ready,
    Running,
    Terminal,
}

struct BoundaryRuntime {
    config: BoundaryConfig,
    authenticator: SandboxProtocolAuthenticator,
    connections: SandboxConnectionRegistry,
    connection_shutdowns: Mutex<HashMap<SandboxConnectionId, tokio::sync::watch::Sender<()>>>,
    active_connection: Mutex<Option<SandboxConnectionId>>,
    lifecycle: Mutex<Lifecycle>,
    attached_policy: Mutex<Option<SandboxPolicyWire>>,
    processes: Mutex<HashMap<String, Arc<ManagedProcess>>>,
    main_process: Mutex<Option<String>>,
    provider_environment: Mutex<(u64, HashMap<String, String>)>,
    replay: Mutex<HashMap<String, ReplayRecord>>,
    replay_order: Mutex<VecDeque<String>>,
    exec_requests: Mutex<HashSet<String>>,
    next_exec: AtomicU64,
}

impl BoundaryRuntime {
    fn new(config: BoundaryConfig) -> Result<Self, String> {
        let sandbox_id = SandboxId::parse(config.boundary_id.clone())
            .map_err(|error| format!("validate MXC sandbox ID: {error}"))?;
        let generation = openshell_core::sandbox_generation::SandboxGenerationId::parse(
            config.generation.clone(),
        )
        .map_err(|error| format!("validate MXC runtime generation: {error}"))?;
        let verifier = SessionJwtVerifier::new(
            &config.gateway_id,
            SessionTokenProfile::Sandbox,
            config
                .verification_keys
                .iter()
                .map(|key| SessionVerificationKey {
                    key_id: key.key_id.clone(),
                    public_key_pem: key.public_key_pem.as_bytes().to_vec(),
                }),
            Arc::new(SystemJwtClock),
        )
        .map_err(|error| format!("configure MXC Sandbox Protocol verifier: {error}"))?;
        Ok(Self {
            authenticator: SandboxProtocolAuthenticator::new(
                verifier,
                sandbox_id,
                generation,
                config.auth_epoch,
            ),
            connections: SandboxConnectionRegistry::new(config.session_id, config.session_rotation),
            config,
            connection_shutdowns: Mutex::new(HashMap::new()),
            active_connection: Mutex::new(None),
            lifecycle: Mutex::new(Lifecycle::AwaitingAttach),
            attached_policy: Mutex::new(None),
            processes: Mutex::new(HashMap::new()),
            main_process: Mutex::new(None),
            provider_environment: Mutex::new((0, HashMap::new())),
            replay: Mutex::new(HashMap::new()),
            replay_order: Mutex::new(VecDeque::new()),
            exec_requests: Mutex::new(HashSet::new()),
            next_exec: AtomicU64::new(1),
        })
    }

    fn authenticate_request(
        &self,
        connection_id: SandboxConnectionId,
        metadata: &tonic::metadata::MetadataMap,
    ) -> Result<SandboxProtocolPrincipal, tonic::Status> {
        self.authenticator
            .authenticate(connection_id, metadata)
            .map_err(|error| tonic::Status::unauthenticated(error.to_string()))
    }

    fn authorize(
        &self,
        principal: &SandboxProtocolPrincipal,
        request: &Request,
    ) -> Result<(), String> {
        if matches!(request, Request::Attach { .. }) {
            return Ok(());
        }
        if matches!(request, Request::Confirm) {
            self.connections
                .require_attached(principal)
                .map_err(|error| error.to_string())
        } else {
            self.connections
                .require_active(principal)
                .map_err(|error| error.to_string())
        }
    }

    fn register_connection(
        &self,
        id: SandboxConnectionId,
        shutdown: tokio::sync::watch::Sender<()>,
    ) {
        lock(&self.connection_shutdowns).insert(id, shutdown);
    }

    fn close_connection(&self, id: SandboxConnectionId) {
        if let Some(shutdown) = lock(&self.connection_shutdowns).remove(&id) {
            let _ = shutdown.send(());
        }
    }

    fn transport_disconnected(self: &Arc<Self>, id: SandboxConnectionId) {
        lock(&self.connection_shutdowns).remove(&id);
        if !self.connections.disconnect(id) {
            return;
        }
        *lock(&self.active_connection) = None;
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            tokio::time::sleep(AUTHENTICATED_RECONNECT_TIMEOUT).await;
            let Some(runtime) = weak.upgrade() else {
                return;
            };
            if lock(&runtime.active_connection).is_none() {
                tracing::error!("MXC supervisor recovery expired; terminating workload");
                runtime.terminate_all().await;
            }
        });
    }

    fn commit_attach(
        &self,
        principal: &SandboxProtocolPrincipal,
        instance: openshell_sandbox_backend::boundary_protocol::SupervisorInstanceId,
    ) -> Result<(), String> {
        if let Some(replaced) = self
            .connections
            .attach(principal, instance)
            .map_err(|error| error.to_string())?
        {
            self.close_connection(replaced);
        }
        Ok(())
    }

    fn commit_confirm(&self, principal: &SandboxProtocolPrincipal) -> Result<(), String> {
        if let Some(replaced) = self
            .connections
            .confirm(principal)
            .map_err(|error| error.to_string())?
        {
            self.close_connection(replaced);
        }
        *lock(&self.active_connection) = Some(principal.connection_id());
        Ok(())
    }

    fn snapshot(&self) -> SessionSnapshotWire {
        let mut processes = lock(&self.processes)
            .values()
            .map(|process| ProcessSnapshotWire {
                process_id: process.id.clone(),
                kind: process.kind,
                terminal: false,
                status: process.exit_status(),
                retained_output: process.output.window(),
            })
            .collect::<Vec<_>>();
        processes.sort_by(|left, right| left.process_id.cmp(&right.process_id));
        SessionSnapshotWire {
            generation: self.config.generation.clone(),
            processes,
        }
    }

    fn confirmation(&self) -> Result<BoundaryConfirmation, String> {
        let evidence = MxcSandboxAuditEvidence {
            process_container: current_process_is_appcontainer()?,
            appcontainer_profile: self
                .config
                .resource_claims
                .get("mxc.appcontainer_profile")
                .cloned()
                .unwrap_or_else(|| self.config.generation.clone()),
            default_deny_filesystem: true,
            default_deny_egress: true,
            loopback_proxy_only: self.config.direct_proxy_url.is_some(),
            authenticated_control: true,
            generation_scoped_attribution: true,
        };
        evidence.validate().map_err(|error| error.to_string())?;
        let properties = evidence.properties();
        let backend_audit =
            serde_json::to_value(OpenShellBoundaryAuditEvidence::WindowsMxc(evidence))
                .map_err(|error| format!("encode MXC audit evidence: {error}"))?;
        Ok(BoundaryConfirmation {
            generation: self.config.generation.clone(),
            identity: self.config.workload_identity.clone(),
            properties,
            authenticated_supervisor: true,
            session_id: self.config.session_id,
            outer_fence: self.config.outer_fence.clone(),
            runtime_exit_terminates_workload: true,
            resource_claims: self.config.resource_claims.clone(),
            backend_audit,
        })
    }

    fn dispatch(&self, envelope: &RequestEnvelope) -> Response {
        if envelope.validate_payload_digest().is_err() {
            return guest_error(BoundaryErrorKind::Denied, "control payload digest mismatch");
        }
        if envelope.request.is_replayable_mutation()
            && let Some(record) = lock(&self.replay).get(&envelope.request_id)
        {
            return if record.digest == envelope.payload_digest {
                record.response.clone()
            } else {
                guest_error(
                    BoundaryErrorKind::Denied,
                    "control request ID reused with a different payload",
                )
            };
        }
        let response = match &envelope.request {
            Request::Attach {
                policy,
                resource_claims,
                ..
            } => {
                if resource_claims != &self.config.resource_claims {
                    guest_error(BoundaryErrorKind::Denied, "MXC resource claims mismatch")
                } else {
                    let mut lifecycle = lock(&self.lifecycle);
                    let mut attached_policy = lock(&self.attached_policy);
                    if *lifecycle == Lifecycle::AwaitingAttach {
                        *attached_policy = Some((**policy).clone());
                        *lifecycle = Lifecycle::Bound;
                    }
                    if attached_policy.as_ref() == Some(policy) {
                        Response::Attached {
                            snapshot: self.snapshot(),
                        }
                    } else {
                        guest_error(BoundaryErrorKind::Denied, "MXC attach policy changed")
                    }
                }
            }
            Request::Confirm => {
                let mut lifecycle = lock(&self.lifecycle);
                match *lifecycle {
                    Lifecycle::Bound | Lifecycle::Ready | Lifecycle::Running => {
                        match self.confirmation() {
                            Ok(confirmation) => {
                                if *lifecycle == Lifecycle::Bound {
                                    *lifecycle = Lifecycle::Ready;
                                }
                                Response::Confirmed {
                                    confirmation: Box::new(confirmation),
                                }
                            }
                            Err(error) => guest_error(BoundaryErrorKind::Process, error),
                        }
                    }
                    Lifecycle::AwaitingAttach | Lifecycle::Terminal => guest_error(
                        BoundaryErrorKind::Invalid,
                        "MXC boundary must be attached before confirmation",
                    ),
                }
            }
            Request::UpdateProviderEnvironment {
                expected_revision,
                revision,
                provider_env,
            } => {
                let mut current = lock(&self.provider_environment);
                if current.0 != *expected_revision || *revision <= *expected_revision {
                    guest_error(
                        BoundaryErrorKind::Denied,
                        "provider environment revision compare-and-swap failed",
                    )
                } else {
                    *current = (*revision, provider_env.clone());
                    Response::ProviderEnvironmentUpdated {
                        revision: *revision,
                    }
                }
            }
            Request::Resize { .. } => guest_error(
                BoundaryErrorKind::Invalid,
                "Windows ConPTY is not enabled for the MXC boundary",
            ),
            Request::OpenMediation | Request::AcceptNetwork => guest_error(
                BoundaryErrorKind::Invalid,
                "MXC uses the supervisor-owned authenticated explicit proxy",
            ),
            Request::StartAgent { .. }
            | Request::AttachProcess { .. }
            | Request::Wait { .. }
            | Request::Signal { .. }
            | Request::Terminate { .. }
            | Request::TerminateBoundary
            | Request::Exec { .. }
            | Request::ExecSignal { .. }
            | Request::LoopbackConnect { .. } => guest_error(
                BoundaryErrorKind::Invalid,
                "streaming request used on the non-streaming path",
            ),
        };
        if envelope.request.is_replayable_mutation() {
            self.remember_replay(envelope, &response);
        }
        response
    }

    fn remember_replay(&self, envelope: &RequestEnvelope, response: &Response) {
        let mut replay = lock(&self.replay);
        let mut order = lock(&self.replay_order);
        if !replay.contains_key(&envelope.request_id) {
            while replay.len() >= MAX_REPLAY_ENTRIES {
                if let Some(oldest) = order.pop_front() {
                    replay.remove(&oldest);
                }
            }
            order.push_back(envelope.request_id.clone());
        }
        replay.insert(
            envelope.request_id.clone(),
            ReplayRecord {
                digest: envelope.payload_digest.clone(),
                response: response.clone(),
            },
        );
    }

    async fn start_agent(&self, envelope: &RequestEnvelope) -> Response {
        let Request::StartAgent {
            spec,
            policy,
            ca_cert,
            ca_bundle,
            provider_env_revision,
            provider_env,
            ..
        } = &envelope.request
        else {
            return guest_error(BoundaryErrorKind::Invalid, "expected StartAgent");
        };
        {
            let lifecycle = *lock(&self.lifecycle);
            if lifecycle == Lifecycle::Running {
                if let Some(id) = lock(&self.main_process).clone() {
                    return Response::Started {
                        process_id: id,
                        provider_env_revision: lock(&self.provider_environment).0,
                    };
                }
            }
            if lifecycle != Lifecycle::Ready {
                return guest_error(
                    BoundaryErrorKind::Invalid,
                    "MXC boundary must be confirmed before agent start",
                );
            }
            if lock(&self.attached_policy).as_ref() != Some(policy) {
                return guest_error(BoundaryErrorKind::Denied, "MXC start policy changed");
            }
        }
        let mut environment = self.config.child_env.clone();
        environment.extend(provider_env.clone());
        if let Some(proxy_url) = &self.config.direct_proxy_url {
            for key in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"] {
                environment.insert(key.to_string(), proxy_url.clone());
            }
            environment.insert("NO_PROXY".to_string(), String::new());
            environment.insert("no_proxy".to_string(), String::new());
        }
        match install_ca_material(
            &self.config.generation,
            ca_cert.as_deref(),
            ca_bundle.as_deref(),
        ) {
            Ok(Some((certificate, bundle))) => {
                environment.insert(
                    "NODE_EXTRA_CA_CERTS".to_string(),
                    certificate.display().to_string(),
                );
                environment.insert("DENO_CERT".to_string(), certificate.display().to_string());
                for key in [
                    "SSL_CERT_FILE",
                    "REQUESTS_CA_BUNDLE",
                    "CURL_CA_BUNDLE",
                    "GIT_SSL_CAINFO",
                ] {
                    environment.insert(key.to_string(), bundle.display().to_string());
                }
            }
            Ok(None) => {}
            Err(error) => return guest_error(BoundaryErrorKind::Process, error),
        }
        let process_id = format!("{}:main:0", self.config.generation);
        let (program, args) = agent_command(spec.clone());
        let process = match ManagedProcess::spawn(
            process_id.clone(),
            ProcessKindWire::Main,
            program,
            args,
            spec.workdir.clone(),
            environment,
        )
        .await
        {
            Ok(process) => Arc::new(process),
            Err(error) => return guest_error(BoundaryErrorKind::Process, error),
        };
        lock(&self.processes).insert(process_id.clone(), process);
        *lock(&self.main_process) = Some(process_id.clone());
        *lock(&self.provider_environment) = (*provider_env_revision, provider_env.clone());
        *lock(&self.lifecycle) = Lifecycle::Running;
        let response = Response::Started {
            process_id,
            provider_env_revision: *provider_env_revision,
        };
        self.remember_replay(envelope, &response);
        response
    }

    async fn start_exec(&self, envelope: &RequestEnvelope, spec: ExecSpecWire) -> Response {
        if spec.pty {
            return guest_error(
                BoundaryErrorKind::Invalid,
                "Windows ConPTY is not enabled for MXC exec",
            );
        }
        {
            let mut requests = lock(&self.exec_requests);
            if !requests.insert(envelope.request_id.clone()) {
                return guest_error(
                    BoundaryErrorKind::Denied,
                    "exec request was already consumed",
                );
            }
        }
        let id = format!(
            "{}:exec:{}",
            self.config.generation,
            self.next_exec.fetch_add(1, Ordering::Relaxed)
        );
        let mut environment = self.config.child_env.clone();
        environment.extend(lock(&self.provider_environment).1.clone());
        environment.extend(spec.env.iter().cloned());
        let process = match ManagedProcess::spawn(
            id.clone(),
            ProcessKindWire::Exec,
            spec.program,
            spec.args,
            spec.workdir,
            environment,
        )
        .await
        {
            Ok(process) => Arc::new(process),
            Err(error) => return guest_error(BoundaryErrorKind::Process, error),
        };
        lock(&self.processes).insert(id.clone(), process);
        Response::ExecStarted {
            process_id: id,
            pty: false,
        }
    }

    fn process(&self, id: &str) -> Result<Arc<ManagedProcess>, Response> {
        lock(&self.processes)
            .get(id)
            .cloned()
            .ok_or_else(|| guest_error(BoundaryErrorKind::Invalid, "unknown MXC process ID"))
    }

    async fn terminate_all(&self) {
        self.connections.mark_terminal();
        let processes = lock(&self.processes).values().cloned().collect::<Vec<_>>();
        for process in processes {
            let _ = process.terminate().await;
        }
        *lock(&self.lifecycle) = Lifecycle::Terminal;
    }
}

fn current_process_is_appcontainer() -> Result<bool, String> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TokenIsAppContainer};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: the token handle is initialized by OpenProcessToken, queried into
    // a correctly sized u32 buffer, and closed on every path after acquisition.
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .map_err(|error| format!("open MXC sandbox process token: {error}"))?;
        let mut is_appcontainer = 0_u32;
        let mut returned = 0_u32;
        let query = GetTokenInformation(
            token,
            TokenIsAppContainer,
            Some(std::ptr::from_mut(&mut is_appcontainer).cast()),
            size_of_val(&is_appcontainer) as u32,
            &mut returned,
        );
        let close = CloseHandle(token);
        query.map_err(|error| format!("query MXC sandbox AppContainer token: {error}"))?;
        close.map_err(|error| format!("close MXC sandbox process token: {error}"))?;
        if returned != size_of_val(&is_appcontainer) as u32 {
            return Err(format!(
                "query MXC sandbox AppContainer token returned {returned} bytes"
            ));
        }
        Ok(is_appcontainer != 0)
    }
}

async fn serve_one(
    mut stream: tokio::io::DuplexStream,
    runtime: Arc<BoundaryRuntime>,
    principal: SandboxProtocolPrincipal,
) -> Result<(), String> {
    let envelope: RequestEnvelope = read_frame_async(&mut stream)
        .await
        .map_err(|error| format!("read MXC control request: {error}"))?;
    runtime.authorize(&principal, &envelope.request)?;
    if envelope.validate_payload_digest().is_err() {
        return write_response(
            &mut stream,
            &envelope.request_id,
            guest_error(BoundaryErrorKind::Denied, "control payload digest mismatch"),
        )
        .await;
    }

    match envelope.request.clone() {
        Request::Attach {
            supervisor_instance_id,
            ..
        } => {
            let response = runtime.dispatch(&envelope);
            if matches!(response, Response::Attached { .. }) {
                runtime.commit_attach(&principal, supervisor_instance_id)?;
            }
            write_response(&mut stream, &envelope.request_id, response).await
        }
        Request::Confirm => {
            let response = runtime.dispatch(&envelope);
            if matches!(response, Response::Confirmed { .. }) {
                runtime.commit_confirm(&principal)?;
            }
            write_response(&mut stream, &envelope.request_id, response).await
        }
        Request::StartAgent { .. } => {
            let response = runtime.start_agent(&envelope).await;
            write_response(&mut stream, &envelope.request_id, response).await
        }
        Request::Exec { spec } => {
            let response = runtime.start_exec(&envelope, spec).await;
            let process_id = match &response {
                Response::ExecStarted { process_id, .. } => Some(process_id.clone()),
                _ => None,
            };
            write_response(&mut stream, &envelope.request_id, response).await?;
            if let Some(process_id) = process_id {
                let process = runtime.process(&process_id).map_err(response_error)?;
                bridge_process(stream, process).await?;
            }
            Ok(())
        }
        Request::AttachProcess { process_id } => {
            let process = runtime.process(&process_id).map_err(response_error)?;
            write_response(
                &mut stream,
                &envelope.request_id,
                Response::ProcessAttached { terminal: false },
            )
            .await?;
            bridge_process(stream, process).await
        }
        Request::Wait { process_id } => {
            let response = match runtime.process(&process_id) {
                Ok(process) => Response::Exited {
                    status: process.wait().await,
                },
                Err(response) => response,
            };
            write_response(&mut stream, &envelope.request_id, response).await
        }
        Request::Signal { process_id, signal } | Request::ExecSignal { process_id, signal } => {
            let response = match runtime.process(&process_id) {
                Ok(process) => process.signal(signal).await.map_or_else(
                    |error| guest_error(BoundaryErrorKind::Process, error),
                    |()| Response::Signaled,
                ),
                Err(response) => response,
            };
            write_response(&mut stream, &envelope.request_id, response).await
        }
        Request::Terminate { process_id } => {
            let response = match runtime.process(&process_id) {
                Ok(process) => process.terminate().await.map_or_else(
                    |error| guest_error(BoundaryErrorKind::Process, error),
                    |()| Response::Terminated,
                ),
                Err(response) => response,
            };
            write_response(&mut stream, &envelope.request_id, response).await
        }
        Request::TerminateBoundary => {
            runtime.terminate_all().await;
            write_response(
                &mut stream,
                &envelope.request_id,
                Response::BoundaryTerminated,
            )
            .await
        }
        Request::LoopbackConnect { host, port } => {
            if !host.is_loopback() || port == 0 {
                return write_response(
                    &mut stream,
                    &envelope.request_id,
                    guest_error(BoundaryErrorKind::Denied, "forward target is not loopback"),
                )
                .await;
            }
            match tokio::net::TcpStream::connect((host, port)).await {
                Ok(mut target) => {
                    openshell_core::net::set_tcp_nodelay_best_effort(&target);
                    write_response(&mut stream, &envelope.request_id, Response::PortConnected)
                        .await?;
                    tokio::io::copy_bidirectional(&mut stream, &mut target)
                        .await
                        .map(|_| ())
                        .map_err(|error| format!("bridge MXC loopback connection: {error}"))
                }
                Err(error) => {
                    write_response(
                        &mut stream,
                        &envelope.request_id,
                        guest_error(BoundaryErrorKind::Process, error.to_string()),
                    )
                    .await
                }
            }
        }
        _ => {
            let response = runtime.dispatch(&envelope);
            write_response(&mut stream, &envelope.request_id, response).await
        }
    }
}

async fn write_response(
    stream: &mut tokio::io::DuplexStream,
    request_id: &str,
    response: Response,
) -> Result<(), String> {
    let frame = encode_frame(&ResponseEnvelope {
        request_id: request_id.to_string(),
        response,
    })
    .map_err(|error| format!("encode MXC control response: {error}"))?;
    stream
        .write_all(&frame)
        .await
        .map_err(|error| format!("write MXC control response: {error}"))?;
    stream
        .flush()
        .await
        .map_err(|error| format!("flush MXC control response: {error}"))
}

fn response_error(response: Response) -> String {
    match response {
        Response::Error { message, .. } => message,
        other => format!("unexpected MXC process response: {other:?}"),
    }
}

fn agent_command(spec: AgentSpecWire) -> (String, Vec<String>) {
    if spec.program.trim().is_empty() {
        (
            std::env::var("COMSPEC")
                .unwrap_or_else(|_| "C:\\Windows\\System32\\cmd.exe".to_string()),
            vec!["/D".to_string(), "/Q".to_string()],
        )
    } else {
        (spec.program, spec.args)
    }
}

fn install_ca_material(
    generation: &str,
    certificate: Option<&[u8]>,
    bundle: Option<&[u8]>,
) -> Result<Option<(PathBuf, PathBuf)>, String> {
    let (Some(certificate), Some(bundle)) = (certificate, bundle) else {
        return Ok(None);
    };
    let directory = std::env::temp_dir().join(format!("openshell-ca-{generation}"));
    std::fs::create_dir_all(&directory)
        .map_err(|error| format!("create MXC CA directory: {error}"))?;
    let certificate_path = directory.join("openshell-ca.pem");
    let bundle_path = directory.join("ca-bundle.pem");
    std::fs::write(&certificate_path, certificate)
        .map_err(|error| format!("write MXC proxy CA: {error}"))?;
    std::fs::write(&bundle_path, bundle)
        .map_err(|error| format!("write MXC proxy CA bundle: {error}"))?;
    Ok(Some((certificate_path, bundle_path)))
}

struct ManagedProcess {
    id: String,
    kind: ProcessKindWire,
    child: Arc<tokio::sync::Mutex<Child>>,
    stdin: tokio::sync::Mutex<Option<tokio::process::ChildStdin>>,
    output: Arc<OutputLog>,
    exit: tokio::sync::watch::Receiver<Option<ExitStatusWire>>,
    attached: Arc<AtomicBool>,
}

impl ManagedProcess {
    async fn spawn(
        id: String,
        kind: ProcessKindWire,
        program: String,
        args: Vec<String>,
        workdir: Option<String>,
        environment: HashMap<String, String>,
    ) -> Result<Self, String> {
        if program.trim().is_empty() {
            return Err("MXC workload program is empty".to_string());
        }
        let mut command = Command::new(&program);
        command
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .envs(environment);
        if let Some(workdir) = workdir.filter(|path| !path.trim().is_empty()) {
            command.current_dir(workdir);
        }
        let mut child = command
            .spawn()
            .map_err(|error| format!("spawn MXC workload executable {program:?}: {error}"))?;
        let stdin = child.stdin.take();
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "MXC workload stdout pipe is unavailable".to_string())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "MXC workload stderr pipe is unavailable".to_string())?;
        let output = OutputLog::new();
        output.spawn_reader(stdout, STREAM_STDOUT);
        output.spawn_reader(stderr, STREAM_STDERR);
        let (exit_tx, exit) = tokio::sync::watch::channel(None);
        let process = Self {
            id,
            kind,
            child: Arc::new(tokio::sync::Mutex::new(child)),
            stdin: tokio::sync::Mutex::new(stdin),
            output,
            exit,
            attached: Arc::new(AtomicBool::new(false)),
        };
        process.start_monitor(exit_tx);
        Ok(process)
    }

    fn start_monitor(&self, exit_tx: tokio::sync::watch::Sender<Option<ExitStatusWire>>) {
        let child = self.child.clone();
        let output = self.output.clone();
        tokio::spawn(async move {
            loop {
                let result = {
                    let mut child = child.lock().await;
                    child.try_wait()
                };
                match result {
                    Ok(Some(status)) => {
                        let status = ExitStatusWire::Exited(status.code().unwrap_or(1));
                        output.publish_exit(status);
                        exit_tx.send_replace(Some(status));
                        return;
                    }
                    Ok(None) => tokio::time::sleep(Duration::from_millis(25)).await,
                    Err(_) => {
                        let status = ExitStatusWire::Exited(1);
                        output.publish_exit(status);
                        exit_tx.send_replace(Some(status));
                        return;
                    }
                }
            }
        });
    }

    fn acquire_attachment(&self) -> Result<AttachmentGuard, String> {
        self.attached
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "MXC process already has an active attachment".to_string())?;
        Ok(AttachmentGuard(self.attached.clone()))
    }

    async fn wait(&self) -> ExitStatusWire {
        let mut exit = self.exit.clone();
        loop {
            if let Some(status) = *exit.borrow_and_update() {
                return status;
            }
            if exit.changed().await.is_err() {
                return ExitStatusWire::Exited(1);
            }
        }
    }

    fn exit_status(&self) -> Option<ExitStatusWire> {
        *self.exit.borrow()
    }

    async fn signal(&self, signal: SignalWire) -> Result<(), String> {
        match signal {
            SignalWire::Term | SignalWire::Kill => self.terminate().await,
            SignalWire::Int | SignalWire::Hup => Err(
                "MXC ProcessContainer does not provide POSIX interrupt or hangup signals"
                    .to_string(),
            ),
        }
    }

    async fn terminate(&self) -> Result<(), String> {
        if self.exit_status().is_some() {
            return Ok(());
        }
        self.child
            .lock()
            .await
            .start_kill()
            .map_err(|error| format!("terminate MXC process: {error}"))
    }
}

struct AttachmentGuard(Arc<AtomicBool>);

impl Drop for AttachmentGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[derive(Clone)]
struct OutputEvent {
    sequence: u64,
    channel: u8,
    payload: Vec<u8>,
}

struct OutputState {
    events: VecDeque<OutputEvent>,
    retained_bytes: usize,
    next_sequence: u64,
}

struct OutputLog {
    state: Mutex<OutputState>,
    version: tokio::sync::watch::Sender<u64>,
}

impl OutputLog {
    fn new() -> Arc<Self> {
        let (version, _) = tokio::sync::watch::channel(0);
        Arc::new(Self {
            state: Mutex::new(OutputState {
                events: VecDeque::new(),
                retained_bytes: 0,
                next_sequence: 0,
            }),
            version,
        })
    }

    fn spawn_reader(
        self: &Arc<Self>,
        mut reader: impl tokio::io::AsyncRead + Send + Unpin + 'static,
        channel: u8,
    ) {
        let output = self.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0_u8; 16 * 1024];
            loop {
                match reader.read(&mut buffer).await {
                    Ok(0) | Err(_) => return,
                    Ok(read) => output.publish(channel, buffer[..read].to_vec()),
                }
            }
        });
    }

    fn publish_exit(&self, status: ExitStatusWire) {
        if let Ok(payload) = serde_json::to_vec(&status) {
            self.publish(STREAM_EXIT, payload);
        }
    }

    fn publish(&self, channel: u8, payload: Vec<u8>) {
        let version = {
            let mut state = lock(&self.state);
            let sequence = state.next_sequence;
            state.next_sequence = state.next_sequence.saturating_add(1);
            state.retained_bytes = state.retained_bytes.saturating_add(payload.len());
            state.events.push_back(OutputEvent {
                sequence,
                channel,
                payload,
            });
            while state.retained_bytes > OUTPUT_BUFFER_BYTES {
                let Some(removed) = state.events.pop_front() else {
                    break;
                };
                state.retained_bytes = state.retained_bytes.saturating_sub(removed.payload.len());
            }
            state.next_sequence
        };
        self.version.send_replace(version);
    }

    fn cursor(self: &Arc<Self>) -> OutputCursor {
        let state = lock(&self.state);
        let next_sequence = state
            .events
            .front()
            .map_or(state.next_sequence, |event| event.sequence);
        drop(state);
        OutputCursor {
            output: self.clone(),
            next_sequence,
            version: self.version.subscribe(),
        }
    }

    fn window(&self) -> OutputWindowWire {
        let state = lock(&self.state);
        let first_sequence = state
            .events
            .front()
            .map_or(state.next_sequence, |event| event.sequence);
        OutputWindowWire {
            first_sequence,
            next_sequence: state.next_sequence,
            truncated: first_sequence != 0,
        }
    }
}

struct OutputCursor {
    output: Arc<OutputLog>,
    next_sequence: u64,
    version: tokio::sync::watch::Receiver<u64>,
}

impl OutputCursor {
    async fn recv(&mut self) -> Option<OutputEvent> {
        loop {
            let event = {
                let state = lock(&self.output.state);
                let oldest = state
                    .events
                    .front()
                    .map_or(state.next_sequence, |event| event.sequence);
                if self.next_sequence < oldest {
                    self.next_sequence = oldest;
                }
                state
                    .events
                    .get(usize::try_from(self.next_sequence.saturating_sub(oldest)).ok()?)
                    .cloned()
            };
            if let Some(event) = event {
                self.next_sequence = event.sequence.saturating_add(1);
                return Some(event);
            }
            if self.version.changed().await.is_err() {
                return None;
            }
        }
    }
}

async fn bridge_process(
    stream: tokio::io::DuplexStream,
    process: Arc<ManagedProcess>,
) -> Result<(), String> {
    let _guard = process.acquire_attachment()?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let input_process = process.clone();
    let mut input = tokio::spawn(async move {
        while let Some((channel, payload)) = read_stream_frame(&mut reader).await? {
            match channel {
                STREAM_STDIN => {
                    let mut stdin = input_process.stdin.lock().await;
                    let Some(stdin) = stdin.as_mut() else {
                        return Err(io::Error::new(io::ErrorKind::BrokenPipe, "stdin closed"));
                    };
                    stdin.write_all(&payload).await?;
                    stdin.flush().await?;
                }
                STREAM_STDIN_CLOSED => {
                    input_process.stdin.lock().await.take();
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected MXC input stream channel",
                    ));
                }
            }
        }
        Ok::<(), io::Error>(())
    });
    let mut cursor = process.output.cursor();
    loop {
        tokio::select! {
            result = &mut input => {
                return result
                    .map_err(|error| format!("join MXC process input: {error}"))?
                    .map_err(|error| format!("read MXC process input: {error}"));
            }
            event = cursor.recv() => {
                let Some(event) = event else { return Ok(()) };
                write_stream_frame(&mut writer, event.channel, &event.payload)
                    .await
                    .map_err(|error| format!("write MXC process output: {error}"))?;
                if event.channel == STREAM_EXIT {
                    return Ok(());
                }
            }
        }
    }
}

fn guest_error(kind: BoundaryErrorKind, message: impl Into<String>) -> Response {
    Response::Error {
        kind,
        message: message.into(),
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
