// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Controlled peers for tests of the real RPC client. Not a backend extension API.

use crate::boundary_protocol::{self as w, Request, RequestEnvelope, Response, ResponseEnvelope};
use crate::proto::{
    self as p,
    exchange_frame::Payload,
    sandbox_protocol_server::{SandboxProtocol, SandboxProtocolServer},
};
use crate::protobuf::WireMessage as _;
use crate::runtime::BoundaryClient;
use crate::stream_adapter::{Mode, ProtocolFrame};
use async_trait::async_trait;
use openshell_core::jwt::{CredentialEpoch, SecretJwt, SessionBearerTokenSlot};
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_isolation_interface::contract::{
    BackendError, BackendErrorKind, BoundaryDuplexStream, BoundaryExitStatus, BoundaryInput,
    BoundaryOutput, BoundarySignal, ExecSpec, LoopbackTarget, PendingDnsQuery, PendingTcpOpen,
    ProviderEnvironmentInstallation, ProvisioningEvidence, ResolvedWorkloadIdentity,
    SandboxContext, TcpOpenDecision,
};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::{StreamExt as _, wrappers::ReceiverStream};

#[async_trait]
pub trait BoundaryProcess: Send + Sync {
    /// Attach to the admitted process's retained standard I/O. The boundary
    /// remains the process owner and may permit only one control attachment.
    async fn attach(&self) -> Result<ProcessAttachment, BackendError> {
        Err(BackendError::Unsupported(
            "process attachment is not supported".to_string(),
        ))
    }
    /// Await terminal status (stable across repeated calls).
    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError>;
    /// Deliver a signal to the process or its group.
    async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError>;
    /// Terminate the process and its backend-owned process group.
    async fn terminate(&self) -> Result<(), BackendError>;
}

pub use crate::ProcessAttachment;

#[async_trait]
pub trait BoundaryTerminal: Send + Sync {
    /// Resize the terminal.
    async fn resize(&self, cols: u16, rows: u16) -> Result<(), BackendError>;
}

pub struct ExecSession {
    pub process: Arc<dyn BoundaryProcess>,
    pub stdin: Option<BoundaryInput>,
    pub stdout: BoundaryOutput,
    pub stderr: Option<BoundaryOutput>,
    pub terminal: Option<Arc<dyn BoundaryTerminal>>,
    pub output_status: Option<oneshot::Receiver<BoundaryExitStatus>>,
}

#[async_trait]
pub trait BoundaryExec: Send + Sync {
    /// Spawn `spec` inside the boundary, returning an owned session.
    async fn exec(&self, spec: ExecSpec) -> Result<ExecSession, BackendError>;

    /// Install the current provider environment for future process launches.
    ///
    /// Success requires an authenticated acknowledgment from the running
    /// boundary. Implementations serialize this operation with exec so an
    /// older publication cannot replace the acknowledged environment.
    async fn synchronize_provider_environment(
        &self,
    ) -> Result<ProviderEnvironmentInstallation, BackendError> {
        Err(BackendError::Unsupported(
            "provider environment installation acknowledgment is unavailable".to_string(),
        ))
    }
}

#[async_trait]
pub trait BoundaryLoopbackConnector: Send + Sync {
    /// Connect to `target` inside the boundary.
    async fn connect(&self, target: LoopbackTarget) -> Result<BoundaryDuplexStream, BackendError>;
}

#[async_trait]
pub trait NetworkMediationSource: Send + Sync {
    /// Await the next staged workload TCP open.
    async fn accept_tcp(&self) -> Result<PendingTcpOpen, BackendError>;

    /// Await the next workload DNS query.
    async fn accept_dns(&self) -> Result<PendingDnsQuery, BackendError>;
}

type Handler = Arc<dyn Fn(Request) -> Result<Response, BackendError> + Send + Sync>;

#[derive(Default)]
struct Peer {
    handler: Mutex<Option<Handler>>,
    process: Option<Arc<dyn BoundaryProcess>>,
    exec: Option<Arc<dyn BoundaryExec>>,
    loopback: Option<Arc<dyn BoundaryLoopbackConnector>>,
    network: Option<Arc<dyn NetworkMediationSource>>,
    terminal: Option<Arc<dyn BoundaryTerminal>>,
    processes: Mutex<HashMap<String, Arc<dyn BoundaryProcess>>>,
    terminals: Mutex<HashMap<String, Arc<dyn BoundaryTerminal>>>,
}

type Stream<F = p::ExchangeFrame> =
    Pin<Box<dyn tokio_stream::Stream<Item = Result<F, tonic::Status>> + Send>>;
type Sender<F = p::ExchangeFrame> = mpsc::Sender<Result<F, tonic::Status>>;

fn chunk(payload: Payload) -> p::ExchangeFrame {
    p::ExchangeFrame {
        payload: Some(payload),
    }
}
async fn send(out: &Sender, payload: Payload) {
    let _ = out.send(Ok(chunk(payload))).await;
}
fn unsupported() -> BackendError {
    BackendError::Unsupported("test peer operation".into())
}
impl Peer {
    fn process(&self, id: &str) -> Result<Arc<dyn BoundaryProcess>, BackendError> {
        self.processes
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .or_else(|| self.process.clone())
            .ok_or_else(unsupported)
    }
    async fn exchange(
        self: Arc<Self>,
        mut input: tonic::Streaming<p::ExchangeFrame>,
        out: Sender,
        request: RequestEnvelope,
    ) -> Result<(), BackendError> {
        let id = request.request_id;
        let mut io = None;
        let mut network = None;
        let mut relay = None;
        let handler = self.handler.lock().unwrap().clone();
        if let Some(handler) = handler {
            if matches!(request.request, Request::AcceptNetwork) {
                drop(handler);
                return std::future::pending().await;
            }
            let response = handler(request.request).unwrap_or_else(|e| Response::Error {
                kind: match e.kind() {
                    BackendErrorKind::Unsupported => w::BoundaryErrorKind::Unsupported,
                    BackendErrorKind::Denied => w::BoundaryErrorKind::Denied,
                    _ => w::BoundaryErrorKind::Process,
                },
                message: e.to_string(),
            });
            send(
                &out,
                Payload::Response(
                    ResponseEnvelope {
                        request_id: id,
                        response,
                    }
                    .to_proto()
                    .unwrap(),
                ),
            )
            .await;
            return Ok(());
        }
        let response = match request.request {
            Request::Wait { process_id } => Response::Exited {
                status: self.process(&process_id)?.wait().await?.into(),
            },
            Request::Signal {
                process_id,
                signal: w::SignalWire::Kill,
            } => {
                self.process(&process_id)?.terminate().await?;
                Response::Signaled
            }
            Request::Signal { process_id, signal } => {
                self.process(&process_id)?.signal(signal.into()).await?;
                Response::Signaled
            }
            Request::Terminate { process_id } => {
                self.process(&process_id)?.terminate().await?;
                Response::Terminated
            }
            Request::Resize {
                process_id,
                cols,
                rows,
            } => {
                let terminal = self
                    .terminals
                    .lock()
                    .unwrap()
                    .get(&process_id)
                    .cloned()
                    .or_else(|| self.terminal.clone())
                    .ok_or_else(unsupported)?;
                terminal.resize(cols, rows).await?;
                Response::Resized
            }
            Request::AttachProcess { process_id } => {
                let process = self.process(&process_id)?;
                let a = process.attach().await?;
                let terminal = a.terminal.is_some();
                if let Some(t) = a.terminal {
                    self.terminals.lock().unwrap().insert(process_id, t);
                }
                io = Some((Some(a.stdin), a.stdout, a.stderr, process, None));
                Response::ProcessAttached { terminal }
            }
            Request::UpdateProviderEnvironment {
                revision,
                generation,
                ..
            } => {
                // Exercise the peer's acknowledgment hook when a test controls it.
                if let Some(exec) = &self.exec {
                    match exec.synchronize_provider_environment().await {
                        Ok(_) | Err(BackendError::Unsupported(_)) => (),
                        Err(e) => return Err(e),
                    }
                }
                Response::ProviderEnvironmentUpdated {
                    revision,
                    generation,
                    applied: true,
                }
            }
            Request::Exec { spec } => {
                let a = self
                    .exec
                    .as_ref()
                    .ok_or_else(unsupported)?
                    .exec(spec.into())
                    .await?;
                let process_id = uuid::Uuid::new_v4().to_string();
                let pty = a.terminal.is_some();
                self.processes
                    .lock()
                    .unwrap()
                    .insert(process_id.clone(), a.process.clone());
                if let Some(t) = a.terminal {
                    self.terminals.lock().unwrap().insert(process_id.clone(), t);
                }
                io = Some((a.stdin, a.stdout, a.stderr, a.process, a.output_status));
                Response::ExecStarted { process_id, pty }
            }
            Request::LoopbackConnect { host, port } => {
                relay = Some(
                    self.loopback
                        .as_ref()
                        .ok_or_else(unsupported)?
                        .connect(LoopbackTarget::new(host, port)?)
                        .await?,
                );
                Response::LoopbackConnected
            }
            Request::AcceptNetwork => {
                let open = self
                    .network
                    .as_ref()
                    .ok_or_else(unsupported)?
                    .accept_tcp()
                    .await?;
                let response = Response::NetworkConnected {
                    identity: open.binary_identity.clone().into(),
                    destination: open.destination,
                    socket: open.socket,
                    policy_generation: open.policy_generation,
                    timing: w::MediationTimingWire::default(),
                };
                network = Some(open);
                response
            }
            _ => return Err(unsupported()),
        };
        send(
            &out,
            Payload::Response(
                ResponseEnvelope {
                    request_id: id,
                    response,
                }
                .to_proto()
                .unwrap(),
            ),
        )
        .await;
        if let Some((stdin, stdout, stderr, process, completion)) = io {
            process_io(input, out, stdin, stdout, stderr, process, completion).await;
        } else if let Some(open) = network {
            if let Some(Payload::TcpOpenDecision(decision)) =
                input.message().await.ok().flatten().and_then(|c| c.payload)
            {
                let decision = TcpOpenDecision::from_proto(decision).unwrap();
                let _ = open.decision.send(decision);
                if decision == TcpOpenDecision::RelayReady {
                    relay_io(input, out, open.stream).await;
                }
            }
        } else if let Some(stream) = relay {
            relay_io(input, out, stream).await;
        }
        Ok(())
    }
}
#[derive(Clone)]
struct Service(Arc<Peer>);
#[tonic::async_trait]
impl SandboxProtocol for Service {
    type ExchangeStream = Stream;
    type MediateStream = Stream<p::MediateFrame>;
    async fn exchange(
        &self,
        request: tonic::Request<tonic::Streaming<p::ExchangeFrame>>,
    ) -> Result<tonic::Response<Stream>, tonic::Status> {
        let (out, rx) = mpsc::channel(8);
        let peer = self.0.clone();
        tokio::spawn(async move {
            let mut input = request.into_inner();
            let request = match read_request(&mut input).await {
                Ok(r) => r,
                Err(e) => {
                    let _ = out.send(Err(e)).await;
                    return;
                }
            };
            let id = request.request_id.clone();
            tokio::select! {
                ()=out.closed()=>(),
                result=peer.exchange(input,out.clone(),request)=>{
                    if let Err(e)=result {send_response(&out,id,error_response(e)).await;}
                }
            }
        });
        Ok(tonic::Response::new(Box::pin(ReceiverStream::new(rx))))
    }
    async fn mediate(
        &self,
        request: tonic::Request<tonic::Streaming<p::MediateFrame>>,
    ) -> Result<tonic::Response<Stream<p::MediateFrame>>, tonic::Status> {
        let (out, rx) = mpsc::channel(8);
        let source = self.0.network.clone();
        tokio::spawn(async move {
            let mut input = request.into_inner();
            let request = match read_request(&mut input).await {
                Ok(r) => r,
                Err(e) => {
                    let _ = out.send(Err(e)).await;
                    return;
                }
            };
            let id = request.request_id;
            let Some(source) = source else {
                send_response(&out, id, error_response(unsupported())).await;
                return;
            };
            let first = match source.accept_dns().await {
                Ok(q) => q,
                Err(e) => {
                    send_response(&out, id, error_response(e)).await;
                    return;
                }
            };
            send_response(&out, id, Response::MediationReady).await;
            let mut pending = HashMap::new();
            let mut stream_id = 1;
            let mut next = Some(first);
            loop {
                if let Some(query) = next.take() {
                    let message = crate::mediation::DnsQueryWire {
                        request: query.message,
                        transport: query.transport,
                        identity: query.binary_identity.into(),
                        timing: w::MediationTimingWire::default(),
                    };
                    let mut wire = message.to_proto().unwrap();
                    wire.stream_id = stream_id;
                    pending.insert(stream_id, query.response);
                    if out
                        .send(Ok(p::MediateFrame {
                            payload: Some(p::mediate_frame::Payload::DnsQuery(wire)),
                        }))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    stream_id += 1;
                }
                tokio::select! {
                    ()=out.closed()=>break,
                    query=source.accept_dns(), if pending.len()<32=>{
                        match query {Ok(q)=>next=Some(q),Err(_)=>break}
                    },
                    response=input.message()=>{
                        if let Ok(Some(p::MediateFrame{payload:Some(p::mediate_frame::Payload::DnsResponse(r))}))=response {
                            if let Some(sender)=pending.remove(&r.stream_id){
                                let result=match r.result {Some(p::dns_response::Result::Response(v))=>Ok(v),_=>Err(unsupported())};
                                let _=sender.send(result);
                            }
                        }else{break;}
                    }
                }
            }
        });
        Ok(tonic::Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}
async fn read_request<F: ProtocolFrame>(
    input: &mut tonic::Streaming<F>,
) -> Result<RequestEnvelope, tonic::Status> {
    let first = input
        .message()
        .await?
        .ok_or_else(|| tonic::Status::invalid_argument("missing boundary binding"))?;
    assert!(first.boundary_id().is_some());
    let request = input
        .message()
        .await?
        .ok_or_else(|| tonic::Status::invalid_argument("missing request"))?;
    let bytes = request
        .receive(&mut Mode::Request)
        .map_err(|e| tonic::Status::invalid_argument(e.to_string()))?;
    w::decode_frame(&bytes).map_err(|e| tonic::Status::invalid_argument(e.to_string()))
}
fn error_response(e: BackendError) -> Response {
    Response::Error {
        kind: match e.kind() {
            BackendErrorKind::Unsupported => w::BoundaryErrorKind::Unsupported,
            BackendErrorKind::Unavailable => w::BoundaryErrorKind::Unavailable,
            BackendErrorKind::Terminated => w::BoundaryErrorKind::Terminated,
            BackendErrorKind::Denied => w::BoundaryErrorKind::Denied,
            _ => w::BoundaryErrorKind::Process,
        },
        message: e.to_string(),
    }
}
async fn send_response<F: ProtocolFrame>(out: &Sender<F>, id: String, response: Response) {
    let bytes = w::encode_frame(&ResponseEnvelope {
        request_id: id,
        response,
    })
    .unwrap();
    let frame = F::send(&mut bytes.as_slice(), &mut Mode::Response)
        .await
        .unwrap()
        .unwrap();
    let _ = out.send(Ok(frame)).await;
}

async fn output(mut reader: BoundaryOutput, out: Sender, stderr: bool) {
    let mut b = vec![0; 16384];
    while let Ok(n) = reader.read(&mut b).await {
        if n == 0 {
            break;
        }
        if out
            .send(Ok(chunk(if stderr {
                Payload::Stderr(b[..n].to_vec())
            } else {
                Payload::Stdout(b[..n].to_vec())
            })))
            .await
            .is_err()
        {
            break;
        }
    }
}
async fn process_io(
    mut input: tonic::Streaming<p::ExchangeFrame>,
    out: Sender,
    stdin: Option<BoundaryInput>,
    stdout: BoundaryOutput,
    stderr: Option<BoundaryOutput>,
    process: Arc<dyn BoundaryProcess>,
    completion: Option<oneshot::Receiver<BoundaryExitStatus>>,
) {
    let (input_error, input_failed) = oneshot::channel();
    let read = tokio::spawn(async move {
        if let Some(mut stdin) = stdin {
            while let Ok(Some(c)) = input.message().await {
                match c.payload {
                    Some(Payload::Stdin(v)) => {
                        if stdin.write_all(&v).await.is_err() {
                            let _ = input_error.send(());
                            return;
                        }
                    }
                    _ => break,
                }
            }
            let _ = stdin.shutdown().await;
        }
    });

    let a = output(stdout, out.clone(), false);
    let b = async {
        if let Some(stderr) = stderr {
            output(stderr, out.clone(), true).await;
        }
    };
    let output = async {
        tokio::join!(a, b);
    };
    tokio::pin!(output);
    let wait = process.wait();
    tokio::pin!(wait);
    let failed = async {
        if input_failed.await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    let waited = tokio::select! {
        () = failed => {
            read.abort();

            let _ = process.terminate().await;

            send(&out, Payload::Exit(w::ExitStatusWire::Exited(74).to_proto().unwrap())).await;
            return;
        },
        r = &mut wait => {read.abort(); output.await; Some(r)},
        () = &mut output => None,
    };
    let exit = if let Some(completion) = completion {
        completion.await.ok()
    } else {
        match waited {
            Some(r) => r.ok(),
            None => wait.await.ok(),
        }
    };
    if let Some(exit) = exit {
        let wire: w::ExitStatusWire = exit.into();
        send(&out, Payload::Exit(wire.to_proto().unwrap())).await;
    }
    read.abort();
}
async fn relay_io(
    mut input: tonic::Streaming<p::ExchangeFrame>,
    out: Sender,
    stream: BoundaryDuplexStream,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let write = async {
        while let Ok(Some(c)) = input.message().await {
            if let Some(Payload::RelayData(v)) = c.payload {
                writer.write_all(&v).await?;
            }
        }
        writer.shutdown().await
    };
    let read = async {
        let mut b = vec![0; 16384];
        loop {
            let n = reader.read(&mut b).await?;
            if n == 0 {
                break;
            }
            if out
                .send(Ok(chunk(Payload::RelayData(b[..n].to_vec()))))
                .await
                .is_err()
            {
                break;
            }
        }
        Ok::<_, std::io::Error>(())
    };
    let _ = tokio::join!(write, read);
}

struct TestTlsIo(BoundaryDuplexStream);
impl tokio::io::AsyncRead for TestTlsIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(context, buffer)
    }
}
impl tokio::io::AsyncWrite for TestTlsIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(context)
    }
}
impl tonic::transport::server::Connected for TestTlsIo {
    type ConnectInfo = ();

    fn connect_info(&self) -> Self::ConnectInfo {}
}

struct Connector {
    peer: Arc<Peer>,
    address: std::net::SocketAddr,
    task: tokio::task::JoinHandle<()>,
}
impl std::fmt::Debug for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestConnector")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}
impl Drop for Connector {
    fn drop(&mut self) {
        self.peer.handler.lock().unwrap().take();
        self.task.abort();
    }
}
#[async_trait]
impl super::BoundaryTransportConnector for Connector {
    async fn connect(
        &self,
        _: &w::SandboxRuntimeDescriptor,
    ) -> Result<BoundaryDuplexStream, BackendError> {
        Ok(Box::new(
            openshell_core::net::connect_tcp_nodelay_best_effort(&[self.address])
                .await
                .map_err(|e| BackendError::Unavailable(e.to_string()))?,
        ))
    }
}
fn client(peer: Peer) -> Arc<BoundaryClient> {
    let session_id = "550e8400-e29b-41d4-a716-446655440000".parse().unwrap();
    let material = w::generate_sandbox_tls_material(session_id).unwrap();
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let certs = rustls_pemfile::certs(&mut material.certificate_chain_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut material.private_key_pem.as_bytes())
        .unwrap()
        .unwrap();
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
    let accept = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener).then(move |stream| {
        let accept = accept.clone();
        async move {
            let stream = stream?;
            openshell_core::net::set_tcp_nodelay_best_effort(&stream);
            accept.accept(stream).await.map(|s| TestTlsIo(Box::new(s)))
        }
    });
    let peer = Arc::new(peer);
    let server_peer = peer.clone();
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(
                crate::backend_proto::isolation_backend_server::IsolationBackendServer::new(
                    Service(Arc::new(Peer::default())),
                ),
            )
            .add_service(SandboxProtocolServer::new(Service(server_peer)))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    let identity =
        ResolvedWorkloadIdentity::new(1000, 1000, vec![], "test".into(), "test".into()).unwrap();
    let descriptor = w::SandboxRuntimeDescriptor {
        boundary_id: "test".into(),
        generation: "test".into(),
        session_id,
        workload_identity: identity,
        transport: w::SandboxTransport::Tcp {
            authority: "test".into(),
            addresses: vec![address],
        },
        tls: w::SandboxTlsClientConfig {
            server_name: material.server_name,
            trust_anchor_pem: material.trust_anchor_pem,
        },
        host_gateway_ip: None,
        resource_claims: std::collections::BTreeMap::default(),
        provisioning_evidence: ProvisioningEvidence::from_enforcement_evidence("test", b"test")
            .unwrap(),
    };
    let bearer = SessionBearerTokenSlot::new(
        SecretJwt::parse("a".repeat(32)).unwrap(),
        i64::MAX,
        CredentialEpoch::new(1).unwrap(),
    )
    .unwrap();
    let mut client =
        BoundaryClient::with_backend(descriptor, bearer, crate::BACKEND_NAME.into(), vec![]);
    client.connector = Some(Arc::new(Connector {
        peer,
        address,
        task,
    }));
    client.boundary_handle.set("test".into()).unwrap();
    Arc::new(client)
}
pub fn process(process: Arc<dyn BoundaryProcess>) -> Arc<crate::BoundaryProcess> {
    Arc::new(crate::BoundaryProcess {
        client: client(Peer {
            process: Some(process),
            ..Peer::default()
        }),
        process_id: "main".into(),
        exec: false,
    })
}
pub fn terminal(terminal: Arc<dyn BoundaryTerminal>) -> Arc<crate::BoundaryTerminal> {
    Arc::new(crate::BoundaryTerminal {
        client: client(Peer {
            terminal: Some(terminal),
            ..Peer::default()
        }),
        process_id: "main".into(),
    })
}
pub fn exec(exec: Arc<dyn BoundaryExec>) -> Arc<crate::BoundaryExec> {
    exec_with_credentials(
        exec,
        ProviderCredentialState::from_child_env_snapshot(0, HashMap::new()),
    )
}
pub fn exec_with_credentials(
    exec: Arc<dyn BoundaryExec>,
    credentials: ProviderCredentialState,
) -> Arc<crate::BoundaryExec> {
    Arc::new(crate::BoundaryExec {
        client: client(Peer {
            exec: Some(exec),
            ..Peer::default()
        }),
        provider_credentials: credentials,
        publication_generation: tokio::sync::Mutex::new(0),
    })
}
pub fn loopback(
    loopback: Arc<dyn BoundaryLoopbackConnector>,
) -> Arc<crate::BoundaryLoopbackConnector> {
    Arc::new(crate::BoundaryLoopbackConnector {
        client: client(Peer {
            loopback: Some(loopback),
            ..Peer::default()
        }),
    })
}
pub fn network(network: Arc<dyn NetworkMediationSource>) -> Arc<crate::NetworkMediationSource> {
    Arc::new(crate::NetworkMediationSource {
        client: client(Peer {
            network: Some(network),
            ..Peer::default()
        }),
    })
}

#[async_trait]
impl BoundaryTerminal for crate::BoundaryTerminal {
    async fn resize(&self, c: u16, r: u16) -> Result<(), BackendError> {
        self.resize(c, r).await
    }
}

#[tonic::async_trait]
impl crate::backend_proto::isolation_backend_server::IsolationBackend for Service {
    async fn describe(
        &self,
        _: tonic::Request<crate::backend_proto::DescribeIsolationBackendRequest>,
    ) -> Result<
        tonic::Response<crate::backend_proto::DescribeIsolationBackendResponse>,
        tonic::Status,
    > {
        Ok(tonic::Response::new(
            crate::backend_proto::DescribeIsolationBackendResponse {
                backend: Some(crate::isolation_protocol::metadata("test-peer")),
            },
        ))
    }
    async fn open_boundary(
        &self,
        _: tonic::Request<crate::backend_proto::OpenBoundaryRequest>,
    ) -> Result<tonic::Response<crate::backend_proto::OpenBoundaryResponse>, tonic::Status> {
        Ok(tonic::Response::new(
            crate::backend_proto::OpenBoundaryResponse {
                boundary_id: "test".into(),
                outcome: crate::backend_proto::open_boundary_response::LaunchOutcome::Fresh as i32,
            },
        ))
    }
    async fn suspend_boundary(
        &self,
        _: tonic::Request<crate::backend_proto::SuspendBoundaryRequest>,
    ) -> Result<tonic::Response<crate::backend_proto::SuspendBoundaryResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("test peer"))
    }
    async fn resume_boundary(
        &self,
        _: tonic::Request<crate::backend_proto::ResumeBoundaryRequest>,
    ) -> Result<tonic::Response<crate::backend_proto::OpenBoundaryResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("test peer"))
    }
}

#[allow(clippy::too_many_arguments)]
pub fn backend(
    name: String,
    sandbox: SandboxContext,
    generation: String,
    payload: Vec<u8>,
    ca: Arc<Mutex<Option<(std::path::PathBuf, std::path::PathBuf)>>>,
    credentials: ProviderCredentialState,
    bearer: SessionBearerTokenSlot,
    handler: Handler,
) -> crate::OpenShellRuntimeBackend {
    let peer = client(Peer {
        handler: Mutex::new(Some(handler)),
        ..Peer::default()
    });
    let mut descriptor = peer.runtime_descriptor.clone();
    descriptor.boundary_id = sandbox.sandbox_id;
    descriptor.session_id = sandbox.session_id;
    descriptor.generation.clone_from(&generation);
    descriptor.workload_identity = sandbox.identity;
    descriptor.provisioning_evidence = ProvisioningEvidence::from_enforcement_evidence(
        generation,
        b"in-process-enforcement-evidence",
    )
    .unwrap();
    let mut backend = crate::OpenShellRuntimeBackend::new(ca, credentials, bearer);
    backend.connector.clone_from(&peer.connector);
    backend.delegated = Some(crate::runtime::DelegatedRuntime {
        backend_name: name,
        descriptor,
        driver_descriptor: payload,
    });
    backend
}

#[cfg(test)]
mod tests {
    use super::*;

    struct UnsupportedExec;

    #[async_trait]
    impl BoundaryExec for UnsupportedExec {
        async fn exec(&self, _: ExecSpec) -> Result<ExecSession, BackendError> {
            Err(BackendError::Unsupported(
                "exec is optional for this peer".into(),
            ))
        }
    }

    #[tokio::test]
    async fn optional_operation_error_survives_the_rpc() {
        let client = exec(Arc::new(UnsupportedExec));
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.exec(ExecSpec {
                program: "/bin/true".into(),
                args: Vec::new(),
                shell: None,
                runtime_helper: None,
                env: Vec::new(),
                workdir: None,
                pty: false,
            }),
        )
        .await
        .expect("optional operation must return an error without transport retries");
        assert!(
            matches!(result, Err(BackendError::Unsupported(message)) if message.contains("exec is optional"))
        );
    }
}
