// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::boundary_protocol::{
    BinaryIdentityWire, BoundaryErrorKind, MediationTimingWire, STREAM_NETWORK_DECISION,
    SessionSnapshotWire,
};
use openshell_isolation_interface::contract::NetworkSocketMetadata;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use tokio_stream::StreamExt as _;

#[derive(Clone, Copy)]
enum Reply {
    Disconnect { pending_accepts: usize },
    Leaf(BoundaryErrorKind),
    Idle,
}

struct PeerState {
    reply: Reply,
    connections: AtomicUsize,
    first_accepts: AtomicUsize,
    decisions: AtomicUsize,
    active: Mutex<Option<usize>>,
    events: Mutex<Vec<(usize, &'static str)>>,
    accepting: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[derive(Clone)]
struct NetworkPeer {
    state: Arc<PeerState>,
    connection: usize,
    attached: Arc<AtomicBool>,
    disconnect: Arc<tokio::sync::Notify>,
}

#[tonic::async_trait]
impl IsolationBoundary for NetworkPeer {
    type ExchangeStream = TestGrpcStream;
    type MediateStream = TestGrpcStream;

    async fn exchange(
        &self,
        request: tonic::Request<tonic::Streaming<BoundaryChunk>>,
    ) -> Result<tonic::Response<Self::ExchangeStream>, tonic::Status> {
        if request.metadata().get("authorization").unwrap()
            != format!("Bearer {}", "a".repeat(32)).as_str()
        {
            return Err(tonic::Status::unauthenticated("unexpected test bearer"));
        }
        let peer = self.clone();
        let (outbound, receiver) = tokio::sync::mpsc::channel(2);
        let closed = outbound.clone();
        tokio::spawn(async move {
            tokio::select! {
                result = peer.respond(request.into_inner(), outbound) => result.unwrap(),
                () = closed.closed() => {},
            }
        });
        Ok(tonic::Response::new(Box::pin(ReceiverStream::new(
            receiver,
        ))))
    }

    async fn mediate(
        &self,
        _request: tonic::Request<tonic::Streaming<BoundaryChunk>>,
    ) -> Result<tonic::Response<Self::MediateStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("TCP fixture"))
    }
}

impl NetworkPeer {
    async fn respond(
        &self,
        mut inbound: tonic::Streaming<BoundaryChunk>,
        outbound: tokio::sync::mpsc::Sender<Result<BoundaryChunk, tonic::Status>>,
    ) -> Result<(), tonic::Status> {
        let mut frame = Vec::new();
        while !complete_control_frame(&frame) {
            frame.extend_from_slice(&inbound.message().await?.expect("control request").data);
        }
        let envelope: RequestEnvelope = decode_frame(&frame).unwrap();
        let kind = match envelope.request {
            Request::Attach { .. } => "attach",
            Request::Confirm => "confirm",
            Request::AcceptNetwork => "accept",
            _ => panic!("unexpected network fixture request"),
        };
        self.state
            .events
            .lock()
            .unwrap()
            .push((self.connection, kind));
        let response = match envelope.request {
            Request::Attach { .. } => {
                // An equal-epoch connection cannot displace an active peer.
                // This rejects reconnect storms that a stateless mock permits.
                let active = *self.state.active.lock().unwrap();
                if active.is_some_and(|active| active != self.connection) {
                    Response::Error {
                        kind: BoundaryErrorKind::Denied,
                        message: "credential epoch is already active".into(),
                    }
                } else {
                    self.attached.store(true, Ordering::Release);
                    Response::Attached {
                        snapshot: SessionSnapshotWire {
                            generation: "test-generation".into(),
                            processes: Vec::new(),
                        },
                    }
                }
            }
            Request::Confirm => {
                assert!(self.attached.load(Ordering::Acquire));
                *self.state.active.lock().unwrap() = Some(self.connection);
                Response::Confirmed {
                    confirmation: Box::new(test_confirmation()),
                }
            }
            Request::AcceptNetwork => {
                assert_eq!(
                    *self.state.active.lock().unwrap(),
                    Some(self.connection),
                    "accept requires confirmation on its physical connection"
                );
                self.state.accepting.notify_one();
                match self.state.reply {
                    Reply::Disconnect { pending_accepts } if self.connection == 1 => {
                        if self.state.first_accepts.fetch_add(1, Ordering::AcqRel) + 1
                            == pending_accepts
                        {
                            self.disconnect.notify_one();
                        }
                        // The TLS bridge closes while these responses are pending.
                        return std::future::pending().await;
                    }
                    Reply::Leaf(kind) => Response::Error {
                        kind,
                        message: "network mediation unavailable".into(),
                    },
                    Reply::Idle => {
                        self.state.release.notified().await;
                        network_response()
                    }
                    Reply::Disconnect { .. } => network_response(),
                }
            }
            _ => unreachable!(),
        };
        let connected = matches!(response, Response::NetworkConnected { .. });
        let bytes = encode_frame(&ResponseEnvelope {
            request_id: envelope.request_id,
            response,
        })
        .unwrap();
        outbound
            .send(Ok(BoundaryChunk { data: bytes }))
            .await
            .unwrap();
        if connected {
            let state = self.state.clone();
            tokio::spawn(async move {
                let (mut reader, writer) = tokio::io::duplex(4096);
                let pump = tokio::spawn(pump_from_grpc(inbound, writer));
                let result = tokio::time::timeout(Duration::from_secs(3), async {
                    let (channel, payload) = read_stream_frame(&mut reader).await.unwrap().unwrap();
                    assert_eq!(channel, STREAM_NETWORK_DECISION);
                    assert_eq!(
                        serde_json::from_slice::<TcpOpenDecision>(&payload).unwrap(),
                        TcpOpenDecision::RelayReady
                    );
                    state.decisions.fetch_add(1, Ordering::AcqRel);
                    let mut ping = [0; 4];
                    reader.read_exact(&mut ping).await.unwrap();
                    assert_eq!(&ping, b"ping");
                    outbound
                        .send(Ok(BoundaryChunk {
                            data: b"pong".to_vec(),
                        }))
                        .await
                        .unwrap();
                })
                .await;
                pump.abort();
                result.expect("accepted network stream must receive its decision and payload");
            });
        }
        Ok(())
    }
}

fn network_response() -> Response {
    Response::NetworkConnected {
        identity: BinaryIdentityWire::Resolved {
            executable: crate::boundary_protocol::ExecutableIdentityWire {
                path: PathBuf::from("/usr/bin/curl"),
                digest: None,
            },
            ancestors: Vec::new(),
            cmdline_paths: Vec::new(),
        },
        destination: "203.0.113.1:443".parse().unwrap(),
        socket: NetworkSocketMetadata {
            socket_cookie: 42,
            nonblocking: true,
            process_generation: 7,
        },
        policy_generation: 9,
        timing: MediationTimingWire {
            notification_to_queue_us: 11,
            queue_wait_us: 13,
        },
    }
}

struct Fixture {
    source: RemoteNetworkMediation,
    state: Arc<PeerState>,
    server: tokio::task::JoinHandle<()>,
}

impl Fixture {
    async fn new(reply: Reply) -> Self {
        let certificate = test_certificate();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(PeerState {
            reply,
            connections: AtomicUsize::new(0),
            first_accepts: AtomicUsize::new(0),
            decisions: AtomicUsize::new(0),
            active: Mutex::new(None),
            events: Mutex::new(Vec::new()),
            accepting: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let connection = server_state.connections.fetch_add(1, Ordering::AcqRel) + 1;
                let state = server_state.clone();
                let config = certificate.server_config.clone();
                connections.spawn(async move {
                    let mut tls = tokio_rustls::TlsAcceptor::from(config)
                        .accept(socket)
                        .await
                        .unwrap();
                    let (application, mut bridge) = tokio::io::duplex(64 * 1024);
                    let disconnect = Arc::new(tokio::sync::Notify::new());
                    let peer = NetworkPeer {
                        state: state.clone(),
                        connection,
                        attached: Arc::new(AtomicBool::new(false)),
                        disconnect: disconnect.clone(),
                    };
                    // Keep the incoming stream open: the server can finish
                    // accepting before its connection task finishes serving.
                    let incoming = tokio_stream::iter([Ok::<_, std::io::Error>(TestTlsIo(
                        Box::new(application),
                    ))])
                    .chain(tokio_stream::pending());
                    let serving = tonic::transport::Server::builder()
                        .add_service(IsolationBoundaryServer::new(peer))
                        .serve_with_incoming(incoming);
                    tokio::select! {
                        result = serving => result.unwrap(),
                        _ = tokio::io::copy_bidirectional(&mut tls, &mut bridge) => {},
                        () = disconnect.notified() => {},
                    }
                    let mut active = state.active.lock().unwrap();
                    if *active == Some(connection) {
                        *active = None;
                    }
                    // Dropping TLS after retiring the owner models the server's
                    // disconnect callback before a same-epoch replacement attach.
                });
            }
        });
        let client = Arc::new(BoundaryClient::new(
            tls_runtime_descriptor(address, certificate.client_tls),
            test_bearer(&"a".repeat(32)),
        ));
        tokio::time::timeout(Duration::from_secs(3), async {
            client
                .call_idempotent(Request::Attach {
                    supervisor_instance_id: client.supervisor_instance_id,
                    policy: Box::new(SandboxPolicyWire::from(sandbox().policy)),
                    resource_claims: std::collections::BTreeMap::new(),
                })
                .await
                .unwrap();
            client.call_idempotent(Request::Confirm).await.unwrap();
        })
        .await
        .expect("fixture must attach and confirm");
        Self {
            source: RemoteNetworkMediation { client },
            state,
            server,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn verify_connection(mut pending: PendingTcpOpen) {
    assert_eq!(pending.destination, "203.0.113.1:443".parse().unwrap());
    assert_eq!(
        pending.binary_identity.unwrap().executable.path,
        PathBuf::from("/usr/bin/curl")
    );
    assert_eq!(
        pending.socket,
        NetworkSocketMetadata {
            socket_cookie: 42,
            nonblocking: true,
            process_generation: 7
        }
    );
    assert_eq!(pending.policy_generation, 9);
    assert_eq!(
        pending.timing.sandbox_notification_to_queue,
        Duration::from_micros(11)
    );
    assert_eq!(pending.timing.sandbox_queue_wait, Duration::from_micros(13));
    pending.decision.send(TcpOpenDecision::RelayReady).unwrap();
    pending.stream.write_all(b"ping").await.unwrap();
    let mut pong = [0; 4];
    pending.stream.read_exact(&mut pong).await.unwrap();
    assert_eq!(&pong, b"pong");
}

#[tokio::test]
async fn tcp_accept_recovers_a_lost_tls_connection() {
    let fixture = Fixture::new(Reply::Disconnect { pending_accepts: 1 }).await;
    tokio::time::timeout(Duration::from_secs(3), async {
        verify_connection(fixture.source.accept_tcp().await.unwrap()).await;
    })
    .await
    .unwrap_or_else(|error| {
        panic!(
            "TCP mediation must recover and relay: {error}; events: {:?}",
            fixture.state.events.lock().unwrap()
        )
    });
    assert_eq!(fixture.state.connections.load(Ordering::Acquire), 2);
    assert_eq!(fixture.state.decisions.load(Ordering::Acquire), 1);
    assert_eq!(
        *fixture.state.events.lock().unwrap(),
        vec![
            (1, "attach"),
            (1, "confirm"),
            (1, "accept"),
            (2, "attach"),
            (2, "confirm"),
            (2, "accept")
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_tcp_accepts_recover_a_lost_tls_connection() {
    const ACCEPTS: usize = 4;
    let fixture = Fixture::new(Reply::Disconnect {
        pending_accepts: ACCEPTS,
    })
    .await;
    let mut accepts = tokio::task::JoinSet::new();
    for _ in 0..ACCEPTS {
        let source = RemoteNetworkMediation {
            client: fixture.source.client.clone(),
        };
        accepts.spawn(async move { verify_connection(source.accept_tcp().await.unwrap()).await });
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(result) = accepts.join_next().await {
            result.unwrap();
        }
    })
    .await
    .expect("all concurrent TCP accepts must recover");
    assert_eq!(fixture.state.connections.load(Ordering::Acquire), 2);
    assert_eq!(fixture.state.decisions.load(Ordering::Acquire), ACCEPTS);
}

#[tokio::test]
async fn tcp_accept_preserves_boundary_leaf_errors() {
    for kind in [
        BoundaryErrorKind::Unavailable,
        BoundaryErrorKind::Denied,
        BoundaryErrorKind::Terminated,
        BoundaryErrorKind::Invalid,
        BoundaryErrorKind::Process,
    ] {
        let fixture = Fixture::new(Reply::Leaf(kind)).await;
        let error = tokio::time::timeout(Duration::from_secs(3), fixture.source.accept_tcp())
            .await
            .expect("leaf error must not retry")
            .err()
            .expect("boundary leaf must fail");
        assert!(matches!(
            (kind, error),
            (BoundaryErrorKind::Unavailable, BackendError::Unavailable(_))
                | (BoundaryErrorKind::Denied, BackendError::Denied(_))
                | (BoundaryErrorKind::Terminated, BackendError::Terminated(_))
                | (BoundaryErrorKind::Invalid, BackendError::Descriptor(_))
                | (BoundaryErrorKind::Process, BackendError::Process(_))
        ));
        assert_eq!(fixture.state.connections.load(Ordering::Acquire), 1);
        assert_eq!(
            *fixture.state.events.lock().unwrap(),
            vec![(1, "attach"), (1, "confirm"), (1, "accept")]
        );
    }
}

#[tokio::test]
async fn tcp_accept_has_no_idle_operation_timeout() {
    let fixture = Fixture::new(Reply::Idle).await;
    let source = RemoteNetworkMediation {
        client: fixture.source.client.clone(),
    };
    let pending = tokio::spawn(async move { source.accept_tcp().await });
    tokio::time::timeout(Duration::from_secs(3), fixture.state.accepting.notified())
        .await
        .expect("TCP accept must reach the peer");
    tokio::time::sleep(REQUEST_TIMEOUT + Duration::from_millis(100)).await;
    assert!(
        !pending.is_finished(),
        "healthy idle acceptance must outlive ordinary requests"
    );
    fixture.state.release.notify_one();
    tokio::time::timeout(Duration::from_secs(3), async {
        verify_connection(pending.await.unwrap().unwrap()).await;
    })
    .await
    .expect("idle acceptance must deliver the next connection");
    assert_eq!(fixture.state.connections.load(Ordering::Acquire), 1);
}
