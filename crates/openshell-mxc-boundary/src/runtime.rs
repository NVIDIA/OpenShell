// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Windows `ProcessContainer` implementation of the authenticated Sandbox Protocol.
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

use crate::audit::MxcSandboxAuditEvidence;
use openshell_core::jwt::{
    SandboxId, SessionJwtVerifier, SessionTokenProfile, SessionVerificationKey, SystemJwtClock,
};
use openshell_isolation_interface::contract::BoundaryConfirmation;
use openshell_sandbox_backend::boundary_protocol::{
    AgentSpecWire, BoundaryConfig, BoundaryErrorKind, BoundaryListener, ExecSpecWire,
    ExitStatusWire, OutputWindowWire, ProcessKindWire, ProcessSnapshotWire, Request,
    RequestEnvelope, Response, ResponseEnvelope, STREAM_EXIT, STREAM_STDERR, STREAM_STDIN,
    STREAM_STDIN_CLOSED, STREAM_STDOUT, SandboxPolicyWire, SessionSnapshotWire, SignalWire,
    encode_frame, read_frame_async, read_stream_frame, write_stream_frame,
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
const OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

pub fn run_boundary(config_path: &Path) -> Result<(), String> {
    let bytes = std::fs::read(config_path)
        .map_err(|error| format!("read boundary config {}: {error}", config_path.display()))?;
    let config: BoundaryConfig = serde_json::from_slice(&bytes)
        .map_err(|error| format!("decode boundary config {}: {error}", config_path.display()))?;
    validate_config(&config)?;
    let runtime_directory = config_path
        .parent()
        .filter(|path| path.is_absolute())
        .ok_or_else(|| "MXC bootstrap requires an absolute runtime directory".to_string())?
        .to_path_buf();
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
        let boundary = Arc::new(BoundaryRuntime::new(config, runtime_directory)?);
        tracing::info!(%address, "MXC Sandbox Protocol reverse control ready");
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
    let connection_expiry = Arc::new(ConnectionExpiry::new(connection_shutdown.clone()));
    runtime.register_connection(connection_id, connection_shutdown.clone());
    let incoming = tokio_stream::StreamExt::chain(
        tokio_stream::iter([Ok::<_, io::Error>(GrpcServerIo {
            stream,
            _disconnect: DisconnectGuard {
                runtime: Arc::downgrade(&runtime),
                connection_id,
                connection_shutdown,
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
            connection_expiry,
            connection_closed: connection_closed.clone(),
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
    _disconnect: DisconnectGuard,
}

struct DisconnectGuard {
    runtime: std::sync::Weak<BoundaryRuntime>,
    connection_id: SandboxConnectionId,
    connection_shutdown: tokio::sync::watch::Sender<()>,
}

impl Drop for DisconnectGuard {
    fn drop(&mut self) {
        // Expiry owns a sender too, so dropping the physical socket alone no
        // longer closes the watch channel. Wake the server and every exchange
        // explicitly, including a discovery connection before attachment.
        let _ = self.connection_shutdown.send(());
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
    connection_expiry: Arc<ConnectionExpiry>,
    connection_closed: tokio::sync::watch::Receiver<()>,
}

type GrpcResponseStream = ReceiverStream<Result<BoundaryChunk, tonic::Status>>;

// Match the Linux boundary: renewed RPC credentials update the physical
// connection deadline, and expiry cancels every open exchange on it.
struct ConnectionExpiry {
    deadline: tokio::sync::watch::Sender<Option<tokio::time::Instant>>,
    worker: tokio::task::AbortHandle,
}

impl ConnectionExpiry {
    fn new(connection_shutdown: tokio::sync::watch::Sender<()>) -> Self {
        let (deadline, mut updates) = tokio::sync::watch::channel(None);
        let worker = tokio::spawn(async move {
            loop {
                let deadline = *updates.borrow_and_update();
                if let Some(deadline) = deadline {
                    tokio::select! {
                        () = tokio::time::sleep_until(deadline) => {
                            let _ = connection_shutdown.send(());
                            return;
                        }
                        result = updates.changed() => {
                            if result.is_err() { return; }
                        }
                    }
                } else if updates.changed().await.is_err() {
                    return;
                }
            }
        })
        .abort_handle();
        Self { deadline, worker }
    }

    fn update(&self, expires_at: i64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        self.deadline.send_replace((expires_at != 0).then(|| {
            tokio::time::Instant::now()
                + Duration::from_secs(
                    u64::try_from(expires_at)
                        .unwrap_or_default()
                        .saturating_sub(now),
                )
        }));
    }
}

impl Drop for ConnectionExpiry {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

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
        self.connection_expiry
            .update(principal.session().expires_at);
        let (stream, response) =
            bridge_grpc_stream(request.into_inner(), self.connection_closed.clone());
        let runtime = self.runtime.clone();
        let mut connection_closed = self.connection_closed.clone();
        tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = connection_closed.changed() => {}
                result = serve_one(stream, runtime, principal) => {
                    if let Err(error) = result {
                        tracing::warn!(%error, "MXC Sandbox Protocol exchange failed");
                    }
                }
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
    mut inbound: impl tokio_stream::Stream<Item = Result<BoundaryChunk, tonic::Status>>
    + Send
    + Unpin
    + 'static,
    connection_closed: tokio::sync::watch::Receiver<()>,
) -> (tokio::io::DuplexStream, GrpcResponseStream) {
    let (application, bridge) = tokio::io::duplex(256 * 1024);
    let (mut reader, mut writer) = tokio::io::split(bridge);
    let (outbound, outbound_rx) = tokio::sync::mpsc::channel(64);
    let mut inbound_closed = connection_closed.clone();
    tokio::spawn(async move {
        tokio::select! {
            biased;
            _ = inbound_closed.changed() => {}
            () = async {
                loop {
                    match tokio_stream::StreamExt::next(&mut inbound).await {
                        Some(Ok(chunk)) if writer.write_all(&chunk.data).await.is_ok() => {}
                        Some(Ok(_) | Err(_)) => return,
                        None => {
                            let _ = writer.shutdown().await;
                            return;
                        }
                    }
                }
            } => {}
        }
    });
    let mut outbound_closed = connection_closed;
    tokio::spawn(async move {
        tokio::select! {
            biased;
            _ = outbound_closed.changed() => {}
            () = async {
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
            } => {}
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
    runtime_directory: PathBuf,
    proxy_url: String,
    authenticator: SandboxProtocolAuthenticator,
    connections: SandboxConnectionRegistry,
    connection_shutdowns: Mutex<HashMap<SandboxConnectionId, tokio::sync::watch::Sender<()>>>,
    active_connection: Mutex<Option<SandboxConnectionId>>,
    lifecycle: Mutex<Lifecycle>,
    attached_policy: Mutex<Option<SandboxPolicyWire>>,
    processes: Mutex<HashMap<String, Arc<ManagedProcess>>>,
    main_process: Mutex<Option<String>>,
    provider_environment: Mutex<(u64, HashMap<String, String>, u64)>,
    ca_paths: Mutex<Option<(PathBuf, PathBuf)>>,
    replay: Mutex<HashMap<String, ReplayRecord>>,
    replay_order: Mutex<VecDeque<String>>,
    exec_requests: Mutex<HashSet<String>>,
    next_exec: AtomicU64,
}

impl BoundaryRuntime {
    fn new(
        launch: crate::launch::MxcBoundaryConfig,
        runtime_directory: PathBuf,
    ) -> Result<Self, String> {
        let config = launch.runtime;
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
            runtime_directory,
            proxy_url: launch.proxy_url,
            connection_shutdowns: Mutex::new(HashMap::new()),
            active_connection: Mutex::new(None),
            lifecycle: Mutex::new(Lifecycle::AwaitingAttach),
            attached_policy: Mutex::new(None),
            processes: Mutex::new(HashMap::new()),
            main_process: Mutex::new(None),
            provider_environment: Mutex::new((0, HashMap::new(), 0)),
            ca_paths: Mutex::new(None),
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
        if matches!(request, Request::Attach { .. } | Request::DiscoverPolicy) {
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
        let shutdown = lock(&self.connection_shutdowns).remove(&id);
        if let Some(shutdown) = shutdown {
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
            serde_json::to_value(crate::audit::MxcBoundaryAuditEvidence::WindowsMxc(evidence))
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
            // MXC has no rootfs image policy; discovery is authenticated above.
            Request::DiscoverPolicy => Response::ImagePolicy {
                yaml: None,
                invalid: false,
            },
            Request::ProbeProviderFiles => guest_error(
                BoundaryErrorKind::Invalid,
                "MXC provider file delivery is not supported",
            ),
            Request::Attach {
                policy,
                resource_claims,
                ..
            } => {
                if resource_claims == &self.config.resource_claims {
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
                } else {
                    guest_error(BoundaryErrorKind::Denied, "MXC resource claims mismatch")
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
                generation,
                revision,
                provider_env,
                provider_files,
            } => {
                if !provider_files.is_empty() {
                    return guest_error(
                        BoundaryErrorKind::Invalid,
                        "MXC provider file delivery is not supported",
                    );
                }
                if *lock(&self.lifecycle) != Lifecycle::Running {
                    return guest_error(
                        BoundaryErrorKind::Invalid,
                        "agent must be running before provider updates",
                    );
                }
                let mut current = lock(&self.provider_environment);
                publish_provider_environment(&mut current, *generation, *revision, provider_env)
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
            provider_files,
            ..
        } = &envelope.request
        else {
            return guest_error(BoundaryErrorKind::Invalid, "expected StartAgent");
        };
        if !provider_files.is_empty() {
            return guest_error(
                BoundaryErrorKind::Invalid,
                "MXC provider file delivery is not supported",
            );
        }
        {
            let lifecycle = *lock(&self.lifecycle);
            let main_process = lock(&self.main_process).clone();
            if lifecycle == Lifecycle::Running
                && let Some(id) = main_process
            {
                let installed = lock(&self.provider_environment);
                return Response::Started {
                    process_id: id,
                    provider_env_revision: installed.0,
                    provider_env_generation: installed.2,
                };
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
        let ca_paths = match install_ca_material(
            &self.runtime_directory,
            &self.config.generation,
            ca_cert.as_deref().map(str::as_bytes),
            ca_bundle.as_deref().map(str::as_bytes),
        ) {
            Ok(paths) => paths,
            Err(error) => return guest_error(BoundaryErrorKind::Process, error),
        };
        let environment = workload_environment(
            &self.config.child_env,
            provider_env,
            &[],
            &self.proxy_url,
            ca_paths.as_ref(),
        );
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
        *lock(&self.ca_paths) = ca_paths;
        *lock(&self.provider_environment) = (*provider_env_revision, provider_env.clone(), 0);
        *lock(&self.lifecycle) = Lifecycle::Running;
        let response = Response::Started {
            process_id,
            provider_env_revision: *provider_env_revision,
            provider_env_generation: 0,
        };
        self.remember_replay(envelope, &response);
        response
    }

    async fn start_exec(&self, envelope: &RequestEnvelope, spec: ExecSpecWire) -> Response {
        if spec.shell.is_some() || spec.runtime_helper.is_some() {
            return guest_error(
                BoundaryErrorKind::Invalid,
                "MXC does not support shell exec intent or runtime helpers",
            );
        }
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
        let environment = workload_environment(
            &self.config.child_env,
            &lock(&self.provider_environment).1,
            &spec.env,
            &self.proxy_url,
            lock(&self.ca_paths).as_ref(),
        );
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

    #[allow(
        clippy::result_large_err,
        reason = "errors are shared Sandbox Protocol responses"
    )]
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

#[allow(unsafe_code)]
fn current_process_is_appcontainer() -> Result<bool, String> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TokenIsAppContainer};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut is_appcontainer = 0_u32;
    let buffer_size = u32::try_from(size_of_val(&is_appcontainer))
        .map_err(|error| format!("size MXC AppContainer token buffer: {error}"))?;
    // SAFETY: the token handle is initialized by OpenProcessToken, queried into
    // a correctly sized u32 buffer, and closed on every path after acquisition.
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token)
            .map_err(|error| format!("open MXC sandbox process token: {error}"))?;
        let mut returned = 0_u32;
        let query = GetTokenInformation(
            token,
            TokenIsAppContainer,
            Some(std::ptr::from_mut(&mut is_appcontainer).cast()),
            buffer_size,
            &raw mut returned,
        );
        let close = CloseHandle(token);
        query.map_err(|error| format!("query MXC sandbox AppContainer token: {error}"))?;
        close.map_err(|error| format!("close MXC sandbox process token: {error}"))?;
        if returned != buffer_size {
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
            forward_loopback(stream, &envelope.request_id, host, port).await
        }
        _ => {
            let response = runtime.dispatch(&envelope);
            write_response(&mut stream, &envelope.request_id, response).await
        }
    }
}

// Only the authenticated request dispatcher calls this operation in production.
// Forwarding stays on the shared protocol stream; no reverse host listener or
// separate relay process is needed for an independently allocated target port.
async fn forward_loopback(
    mut stream: tokio::io::DuplexStream,
    request_id: &str,
    host: std::net::IpAddr,
    port: u16,
) -> Result<(), String> {
    if !host.is_loopback() || port == 0 {
        return write_response(
            &mut stream,
            request_id,
            guest_error(BoundaryErrorKind::Denied, "forward target is not loopback"),
        )
        .await;
    }
    match tokio::net::TcpStream::connect((host, port)).await {
        Ok(mut target) => {
            openshell_core::net::set_tcp_nodelay_best_effort(&target);
            write_response(&mut stream, request_id, Response::PortConnected).await?;
            tokio::io::copy_bidirectional(&mut stream, &mut target)
                .await
                .map(|_| ())
                .map_err(|error| format!("bridge MXC loopback connection: {error}"))
        }
        Err(error) => {
            write_response(
                &mut stream,
                request_id,
                guest_error(BoundaryErrorKind::Process, error.to_string()),
            )
            .await
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

fn install_ca_environment(
    environment: &mut HashMap<String, String>,
    certificate: &Path,
    bundle: &Path,
) {
    for (key, path) in [
        ("NODE_EXTRA_CA_CERTS", certificate),
        ("DENO_CERT", certificate),
        ("SSL_CERT_FILE", bundle),
        ("REQUESTS_CA_BUNDLE", bundle),
        ("CURL_CA_BUNDLE", bundle),
        ("GIT_SSL_CAINFO", bundle),
    ] {
        // Windows environment names are case-insensitive. Remove aliases so
        // HashMap iteration cannot reinstall a caller's trust override.
        environment.retain(|existing, _| !existing.eq_ignore_ascii_case(key));
        environment.insert(key.to_string(), path.display().to_string());
    }
}

fn workload_environment(
    child: &HashMap<String, String>,
    providers: &HashMap<String, String>,
    overrides: &[(String, String)],
    proxy_url: &str,
    ca_paths: Option<&(PathBuf, PathBuf)>,
) -> HashMap<String, String> {
    let mut environment = child.clone();
    environment.extend(providers.clone());
    environment.extend(overrides.iter().cloned());
    for (key, value) in [
        ("HTTP_PROXY", proxy_url),
        ("HTTPS_PROXY", proxy_url),
        ("NO_PROXY", ""),
    ] {
        environment.retain(|existing, _| !existing.eq_ignore_ascii_case(key));
        environment.insert(key.to_string(), value.to_string());
        environment.insert(key.to_ascii_lowercase(), value.to_string());
    }
    if let Some((certificate, bundle)) = ca_paths {
        install_ca_environment(&mut environment, certificate, bundle);
    }
    environment
}

fn install_ca_material(
    runtime_directory: &Path,
    generation: &str,
    certificate: Option<&[u8]>,
    bundle: Option<&[u8]>,
) -> Result<Option<(PathBuf, PathBuf)>, String> {
    let (Some(certificate), Some(bundle)) = (certificate, bundle) else {
        return Ok(None);
    };
    // The driver already grants and protects the generation's boundary state.
    // Host APPDATA/TEMP may be isolated or inaccessible inside ProcessContainer;
    // never rely on those ambient paths or broaden workload filesystem grants.
    let directory = runtime_directory.join(format!("openshell-ca-{generation}"));
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

async fn drain_output(readers: &mut [tokio::task::JoinHandle<()>; 2]) {
    // A descendant can inherit the pipes after its parent exits. Bound the
    // drain, then stop readers before publishing EXIT so no data follows it.
    let drained = tokio::time::timeout(OUTPUT_DRAIN_TIMEOUT, async {
        for reader in readers.iter_mut() {
            let _ = reader.await;
        }
    })
    .await;
    if drained.is_err() {
        for reader in readers.iter() {
            reader.abort();
        }
        for reader in readers.iter_mut() {
            if !reader.is_finished() {
                let _ = reader.await;
            }
        }
    }
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
        let readers = [
            output.spawn_reader(stdout, STREAM_STDOUT),
            output.spawn_reader(stderr, STREAM_STDERR),
        ];
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
        process.start_monitor(exit_tx, readers);
        Ok(process)
    }

    fn start_monitor(
        &self,
        exit_tx: tokio::sync::watch::Sender<Option<ExitStatusWire>>,
        mut readers: [tokio::task::JoinHandle<()>; 2],
    ) {
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
                        drain_output(&mut readers).await;
                        output.publish_exit(status);
                        exit_tx.send_replace(Some(status));
                        return;
                    }
                    Ok(None) => tokio::time::sleep(Duration::from_millis(25)).await,
                    Err(_) => {
                        let status = ExitStatusWire::Exited(1);
                        drain_output(&mut readers).await;
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
            let status = *exit.borrow_and_update();
            if let Some(status) = status {
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
    ) -> tokio::task::JoinHandle<()> {
        let output = self.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0_u8; 16 * 1024];
            loop {
                match reader.read(&mut buffer).await {
                    Ok(0) | Err(_) => return,
                    Ok(read) => output.publish(channel, buffer[..read].to_vec()),
                }
            }
        })
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
    let input = async move {
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
    };
    tokio::pin!(input);
    let mut cursor = process.output.cursor();
    loop {
        tokio::select! {
            result = &mut input => {
                return result.map_err(|error| format!("read MXC process input: {error}"));
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

fn publish_provider_environment(
    installed: &mut (u64, HashMap<String, String>, u64),
    generation: u64,
    revision: u64,
    environment: &HashMap<String, String>,
) -> Response {
    // The revision is an opaque fingerprint, not publication order. A newer
    // generation can repair an identical revision or install a smaller value.
    let applied = generation > installed.2;
    if applied {
        *installed = (revision, environment.clone(), generation);
    }
    Response::ProviderEnvironmentUpdated {
        revision: installed.0,
        generation: installed.2,
        applied,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_environment_keeps_proxy_and_ca_with_refreshed_providers() {
        let ca_paths = (
            PathBuf::from(r"C:\trusted\ca.pem"),
            PathBuf::from(r"C:\trusted\bundle.pem"),
        );
        let child = HashMap::from([("BASE".into(), "bootstrap".into())]);
        let providers = HashMap::from([("TOKEN".into(), "refreshed".into())]);
        let overrides = vec![
            ("OTHER".into(), "exec".into()),
            ("Https_Proxy".into(), "http://untrusted".into()),
            ("ssl_cert_file".into(), "untrusted-ca".into()),
        ];
        let proxy = "http://user:secret@127.0.0.1:3128";
        let environment =
            workload_environment(&child, &providers, &overrides, proxy, Some(&ca_paths));
        for key in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"] {
            assert_eq!(environment[key], proxy);
        }
        assert_eq!(environment["NO_PROXY"], "");
        assert_eq!(
            environment["SSL_CERT_FILE"],
            ca_paths.1.display().to_string()
        );
        assert_eq!(
            environment["NODE_EXTRA_CA_CERTS"],
            ca_paths.0.display().to_string()
        );
        assert!(!environment.contains_key("Https_Proxy"));
        assert!(!environment.contains_key("ssl_cert_file"));
        assert_eq!(environment["TOKEN"], "refreshed");
        assert_eq!(environment["BASE"], "bootstrap");
        assert_eq!(environment["OTHER"], "exec");
        assert!(
            !workload_environment(&child, &HashMap::new(), &[], proxy, Some(&ca_paths))
                .contains_key("TOKEN")
        );
    }

    #[tokio::test]
    async fn connection_expiry_closes_the_authenticated_connection() {
        let (shutdown, mut closed) = tokio::sync::watch::channel(());
        let expiry = ConnectionExpiry::new(shutdown);
        expiry.update(1); // Already expired: terminate immediately.
        tokio::time::timeout(Duration::from_secs(2), closed.changed())
            .await
            .expect("expiry fires")
            .expect("shutdown notification");
    }

    #[tokio::test]
    async fn expired_connection_cancels_idle_exchange_streams() {
        let (shutdown, closed) = tokio::sync::watch::channel(());
        let expiry = ConnectionExpiry::new(shutdown);
        let (inbound, inbound_rx) = tokio::sync::mpsc::channel(1);
        let (mut application, mut response) =
            bridge_grpc_stream(ReceiverStream::new(inbound_rx), closed);
        expiry.update(1);
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut byte = [0];
            assert_eq!(application.read(&mut byte).await.unwrap(), 0);
            assert!(tokio_stream::StreamExt::next(&mut response).await.is_none());
            assert!(
                inbound
                    .send(Ok(BoundaryChunk { data: vec![1] }))
                    .await
                    .is_err()
            );
        })
        .await
        .expect("expired exchanges must close without client activity");
    }

    #[tokio::test]
    async fn physical_disconnect_closes_discovery_even_with_an_expiry_worker() {
        let (shutdown, mut closed) = tokio::sync::watch::channel(());
        let _expiry = ConnectionExpiry::new(shutdown.clone());
        let guard = DisconnectGuard {
            runtime: std::sync::Weak::new(),
            connection_id: SandboxConnectionId::new(),
            connection_shutdown: shutdown,
        };
        drop(guard);
        tokio::time::timeout(Duration::from_secs(2), closed.changed())
            .await
            .expect("disconnected discovery must not wait for JWT expiry")
            .expect("explicit disconnect notification");
    }

    #[tokio::test]
    async fn renewed_credentials_replace_the_connection_deadline() {
        let (shutdown, mut closed) = tokio::sync::watch::channel(());
        let expiry = ConnectionExpiry::new(shutdown);
        expiry.deadline.send_replace(Some(
            tokio::time::Instant::now() + Duration::from_millis(20),
        ));
        expiry
            .deadline
            .send_replace(Some(tokio::time::Instant::now() + Duration::from_mins(1)));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), closed.changed())
                .await
                .is_err()
        );
        expiry.update(1);
        tokio::time::timeout(Duration::from_secs(2), closed.changed())
            .await
            .expect("new deadline fires")
            .expect("shutdown notification");
    }

    #[test]
    fn ca_material_stays_under_the_explicit_boundary_runtime_directory() {
        let root = std::env::temp_dir().join(format!(
            "openshell-ca-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let paths = install_ca_material(&root, "test-generation", Some(b"cert"), Some(b"bundle"))
            .unwrap()
            .unwrap();
        assert_eq!(
            paths.0,
            root.join("openshell-ca-test-generation/openshell-ca.pem")
        );
        assert_eq!(
            paths.1,
            root.join("openshell-ca-test-generation/ca-bundle.pem")
        );
        assert_eq!(std::fs::read(&paths.0).unwrap(), b"cert");
        assert_eq!(std::fs::read(&paths.1).unwrap(), b"bundle");
        assert!(
            install_ca_material(&root, "unused", None, Some(b"bundle"))
                .unwrap()
                .is_none()
        );
        assert!(!root.join("openshell-ca-unused").exists());
        std::fs::remove_file(paths.0).unwrap();
        std::fs::remove_file(paths.1).unwrap();
        std::fs::remove_dir(root.join("openshell-ca-test-generation")).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn installed_ca_replaces_case_insensitive_trust_overrides() {
        let certificate = Path::new(r"C:\trusted\ca.pem");
        let bundle = Path::new(r"C:\trusted\bundle.pem");
        let mut environment = HashMap::from([
            ("SSL_CERT_FILE".into(), "old-bundle".into()),
            ("node_extra_ca_certs".into(), "old-cert".into()),
            ("FOO".into(), "bar".into()),
        ]);
        install_ca_environment(&mut environment, certificate, bundle);
        assert_eq!(environment["FOO"], "bar");
        assert!(!environment.contains_key("node_extra_ca_certs"));
        for key in ["NODE_EXTRA_CA_CERTS", "DENO_CERT"] {
            assert_eq!(environment[key], certificate.display().to_string());
        }
        for key in [
            "SSL_CERT_FILE",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
            "GIT_SSL_CAINFO",
        ] {
            assert_eq!(environment[key], bundle.display().to_string());
        }
    }

    #[test]
    fn provider_publications_are_ordered_independently_of_opaque_revisions() {
        let mut installed = (99, HashMap::new(), 0);
        for (generation, revision, value) in [(1, 99, "first"), (2, 99, "repair"), (3, 1, "new")] {
            let environment = HashMap::from([("KEY".into(), value.into())]);
            assert!(matches!(
                publish_provider_environment(&mut installed, generation, revision, &environment),
                Response::ProviderEnvironmentUpdated { applied: true, .. }
            ));
            assert_eq!(installed, (revision, environment, generation));
        }
        let retained = installed.clone();
        for generation in [0, 1, 2, 3] {
            assert!(matches!(
                publish_provider_environment(&mut installed, generation, 100, &HashMap::new()),
                Response::ProviderEnvironmentUpdated {
                    revision: 1,
                    generation: 3,
                    applied: false
                }
            ));
            assert_eq!(installed, retained);
        }
    }

    #[tokio::test]
    async fn forwarding_bridges_a_dynamic_target_over_the_shared_stream() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind real forwarding target");
            let address = listener.local_addr().expect("target address");
            let echo = tokio::spawn(async move {
                let (mut socket, _) = listener
                    .accept()
                    .await
                    .expect("accept forwarded connection");
                let mut request = [0_u8; 4];
                socket
                    .read_exact(&mut request)
                    .await
                    .expect("read target data");
                assert_eq!(&request, b"ping");
                socket.write_all(b"pong").await.expect("write target data");
                socket.shutdown().await.expect("close target output");
            });
            let (mut client, server) = tokio::io::duplex(4096);
            let bridge = tokio::spawn(forward_loopback(
                server,
                "forward-1",
                address.ip(),
                address.port(),
            ));
            let response: ResponseEnvelope = read_frame_async(&mut client)
                .await
                .expect("protocol response");
            assert_eq!(response.request_id, "forward-1");
            assert!(matches!(response.response, Response::PortConnected));
            client
                .write_all(b"ping")
                .await
                .expect("send forwarded data");
            client.shutdown().await.expect("close client output");
            let mut reply = Vec::new();
            client
                .read_to_end(&mut reply)
                .await
                .expect("receive forwarded data");
            assert_eq!(reply, b"pong");
            bridge
                .await
                .expect("join bridge")
                .expect("bridge succeeded");
            echo.await.expect("join real target");
        })
        .await
        .expect("forwarding completes without stalling");
    }

    #[tokio::test]
    async fn forwarding_rejects_non_loopback_and_zero_ports() {
        for (host, port) in [("192.0.2.1", 80), ("127.0.0.1", 0), ("::1", 0)] {
            let (mut client, server) = tokio::io::duplex(4096);
            forward_loopback(server, "denied", host.parse().expect("IP address"), port)
                .await
                .expect("write denial");
            let response: ResponseEnvelope = read_frame_async(&mut client)
                .await
                .expect("denial response");
            assert!(matches!(
                response.response,
                Response::Error {
                    kind: BoundaryErrorKind::Denied,
                    ..
                }
            ));
        }
    }

    #[tokio::test]
    async fn managed_launch_preserves_arguments_and_retains_real_process_output() {
        let process = ManagedProcess::spawn(
            "launch-test".to_string(),
            ProcessKindWire::Main,
            std::env::var("COMSPEC").expect("Windows command interpreter"),
            vec![
                "/D".to_string(),
                "/C".to_string(),
                "echo relay-free launch".to_string(),
            ],
            None,
            HashMap::new(),
        )
        .await
        .expect("launch real Windows process");
        let guard = process.acquire_attachment().expect("first attachment");
        assert!(process.acquire_attachment().is_err());
        drop(guard);
        let _guard = process
            .acquire_attachment()
            .expect("attachment can reconnect");
        let status = tokio::time::timeout(Duration::from_secs(10), process.wait())
            .await
            .expect("process exits");
        assert!(matches!(status, ExitStatusWire::Exited(0)));
        // Production attachments stop at EXIT; all output must precede it.
        let mut cursor = process.output.cursor();
        let output = tokio::time::timeout(Duration::from_secs(10), async {
            let mut output = Vec::new();
            loop {
                let event = cursor.recv().await.expect("retained output event");
                if event.channel == STREAM_STDOUT {
                    output.extend(event.payload);
                }
                if event.channel == STREAM_EXIT {
                    return output;
                }
            }
        })
        .await
        .expect("stdout is retained");
        assert!(String::from_utf8_lossy(&output).contains("relay-free launch"));
    }

    #[tokio::test]
    async fn process_bridge_drains_stdout_and_stderr_before_exit() {
        let process = Arc::new(
            ManagedProcess::spawn(
                "drain-test".into(),
                ProcessKindWire::Exec,
                std::env::var("COMSPEC").unwrap(),
                vec![
                    "/D".into(),
                    "/C".into(),
                    "(for /L %i in (1,1,2000) do @echo output-line) & echo last-error 1>&2".into(),
                ],
                None,
                HashMap::new(),
            )
            .await
            .expect("launch real command"),
        );
        let (mut client, server) = tokio::io::duplex(4096);
        let bridge = tokio::spawn(bridge_process(server, process));
        let (stdout, stderr) = tokio::time::timeout(Duration::from_secs(10), async {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            while let Some((channel, payload)) = read_stream_frame(&mut client).await.unwrap() {
                match channel {
                    STREAM_STDOUT => stdout.extend(payload),
                    STREAM_STDERR => stderr.extend(payload),
                    STREAM_EXIT => break,
                    _ => panic!("unexpected output channel"),
                }
            }
            (stdout, stderr)
        })
        .await
        .expect("attachment finishes");
        bridge.await.unwrap().unwrap();
        assert_eq!(
            String::from_utf8_lossy(&stdout)
                .matches("output-line")
                .count(),
            2000
        );
        assert!(String::from_utf8_lossy(&stderr).contains("last-error"));
    }

    #[test]
    fn output_retention_is_bounded_and_reports_truncation() {
        let output = OutputLog::new();
        output.publish(STREAM_STDOUT, vec![1; OUTPUT_BUFFER_BYTES]);
        output.publish(STREAM_STDOUT, vec![2; 1]);
        let window = output.window();
        assert!(window.truncated);
        assert_eq!(window.first_sequence, 1);
        assert_eq!(window.next_sequence, 2);
    }
}
