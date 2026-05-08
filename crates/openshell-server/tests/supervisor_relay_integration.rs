// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the supervisor relay gRPC path.
//!
//! Stands up an in-process tonic server hosting the real `handle_relay_stream`
//! handler, plus a mock "supervisor" client that calls `relay_stream` over a
//! real `Channel`. Exercises the wire contract (typed `RelayFrame { Init | Data }`),
//! `SupervisorSessionRegistry::open_relay` → `claim_relay` pairing, and the
//! bidirectional byte bridge inside the handler.
//!
//! These tests complement the unit tests in `supervisor_session.rs` (which
//! exercise registry state only) and the live cluster tests (which exercise
//! the full CLI → gateway → sandbox path). They catch regressions in the gRPC
//! wire layer that unit tests can't see and that are expensive to catch in
//! E2E.

use std::sync::Arc;
use std::time::Duration;

use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use openshell_core::proto::{
    GatewayMessage, RelayFrame, RelayInit, SupervisorMessage,
    open_shell_client::OpenShellClient,
    open_shell_server::{OpenShell, OpenShellServer},
};
use openshell_server::supervisor_session::SupervisorSessionRegistry;
use openshell_server::{MultiplexedService, health_router};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Endpoint};
use tonic::{Response, Status};

// ---------------------------------------------------------------------------
// Gateway service: only relay_stream does real work; everything else stubs.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct RelayGateway {
    registry: Arc<SupervisorSessionRegistry>,
}

#[tonic::async_trait]
impl OpenShell for RelayGateway {
    type RelayStreamStream = std::pin::Pin<
        Box<dyn tokio_stream::Stream<Item = Result<RelayFrame, Status>> + Send + 'static>,
    >;

    async fn relay_stream(
        &self,
        request: tonic::Request<tonic::Streaming<RelayFrame>>,
    ) -> Result<Response<Self::RelayStreamStream>, Status> {
        openshell_server::supervisor_session::handle_relay_stream(&self.registry, request).await
    }

    // ------ unused stubs ------

    type ConnectSupervisorStream = ReceiverStream<Result<GatewayMessage, Status>>;
    async fn connect_supervisor(
        &self,
        _: tonic::Request<tonic::Streaming<SupervisorMessage>>,
    ) -> Result<Response<Self::ConnectSupervisorStream>, Status> {
        Err(Status::unimplemented("unused"))
    }

    type WatchSandboxStream =
        ReceiverStream<Result<openshell_core::proto::SandboxStreamEvent, Status>>;
    async fn watch_sandbox(
        &self,
        _: tonic::Request<openshell_core::proto::WatchSandboxRequest>,
    ) -> Result<Response<Self::WatchSandboxStream>, Status> {
        Err(Status::unimplemented("unused"))
    }

    type ExecSandboxStream =
        ReceiverStream<Result<openshell_core::proto::ExecSandboxEvent, Status>>;
    async fn exec_sandbox(
        &self,
        _: tonic::Request<openshell_core::proto::ExecSandboxRequest>,
    ) -> Result<Response<Self::ExecSandboxStream>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn health(
        &self,
        _: tonic::Request<openshell_core::proto::HealthRequest>,
    ) -> Result<Response<openshell_core::proto::HealthResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn create_sandbox(
        &self,
        _: tonic::Request<openshell_core::proto::CreateSandboxRequest>,
    ) -> Result<Response<openshell_core::proto::SandboxResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn get_sandbox(
        &self,
        _: tonic::Request<openshell_core::proto::GetSandboxRequest>,
    ) -> Result<Response<openshell_core::proto::SandboxResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn list_sandboxes(
        &self,
        _: tonic::Request<openshell_core::proto::ListSandboxesRequest>,
    ) -> Result<Response<openshell_core::proto::ListSandboxesResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn delete_sandbox(
        &self,
        _: tonic::Request<openshell_core::proto::DeleteSandboxRequest>,
    ) -> Result<Response<openshell_core::proto::DeleteSandboxResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn get_sandbox_config(
        &self,
        _: tonic::Request<openshell_core::proto::GetSandboxConfigRequest>,
    ) -> Result<Response<openshell_core::proto::GetSandboxConfigResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn get_gateway_config(
        &self,
        _: tonic::Request<openshell_core::proto::GetGatewayConfigRequest>,
    ) -> Result<Response<openshell_core::proto::GetGatewayConfigResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn get_sandbox_provider_environment(
        &self,
        _: tonic::Request<openshell_core::proto::GetSandboxProviderEnvironmentRequest>,
    ) -> Result<Response<openshell_core::proto::GetSandboxProviderEnvironmentResponse>, Status>
    {
        Err(Status::unimplemented("unused"))
    }
    async fn create_ssh_session(
        &self,
        _: tonic::Request<openshell_core::proto::CreateSshSessionRequest>,
    ) -> Result<Response<openshell_core::proto::CreateSshSessionResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn revoke_ssh_session(
        &self,
        _: tonic::Request<openshell_core::proto::RevokeSshSessionRequest>,
    ) -> Result<Response<openshell_core::proto::RevokeSshSessionResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn create_provider(
        &self,
        _: tonic::Request<openshell_core::proto::CreateProviderRequest>,
    ) -> Result<Response<openshell_core::proto::ProviderResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn update_provider(
        &self,
        _: tonic::Request<openshell_core::proto::UpdateProviderRequest>,
    ) -> Result<Response<openshell_core::proto::ProviderResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn get_provider(
        &self,
        _: tonic::Request<openshell_core::proto::GetProviderRequest>,
    ) -> Result<Response<openshell_core::proto::ProviderResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn list_providers(
        &self,
        _: tonic::Request<openshell_core::proto::ListProvidersRequest>,
    ) -> Result<Response<openshell_core::proto::ListProvidersResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn list_provider_profiles(
        &self,
        _: tonic::Request<openshell_core::proto::ListProviderProfilesRequest>,
    ) -> Result<Response<openshell_core::proto::ListProviderProfilesResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_provider_profile(
        &self,
        _: tonic::Request<openshell_core::proto::GetProviderProfileRequest>,
    ) -> Result<Response<openshell_core::proto::ProviderProfileResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn import_provider_profiles(
        &self,
        _: tonic::Request<openshell_core::proto::ImportProviderProfilesRequest>,
    ) -> Result<Response<openshell_core::proto::ImportProviderProfilesResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn lint_provider_profiles(
        &self,
        _: tonic::Request<openshell_core::proto::LintProviderProfilesRequest>,
    ) -> Result<Response<openshell_core::proto::LintProviderProfilesResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn delete_provider_profile(
        &self,
        _: tonic::Request<openshell_core::proto::DeleteProviderProfileRequest>,
    ) -> Result<Response<openshell_core::proto::DeleteProviderProfileResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn delete_provider(
        &self,
        _: tonic::Request<openshell_core::proto::DeleteProviderRequest>,
    ) -> Result<Response<openshell_core::proto::DeleteProviderResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn update_config(
        &self,
        _: tonic::Request<openshell_core::proto::UpdateConfigRequest>,
    ) -> Result<Response<openshell_core::proto::UpdateConfigResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn get_sandbox_policy_status(
        &self,
        _: tonic::Request<openshell_core::proto::GetSandboxPolicyStatusRequest>,
    ) -> Result<Response<openshell_core::proto::GetSandboxPolicyStatusResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn list_sandbox_policies(
        &self,
        _: tonic::Request<openshell_core::proto::ListSandboxPoliciesRequest>,
    ) -> Result<Response<openshell_core::proto::ListSandboxPoliciesResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn report_policy_status(
        &self,
        _: tonic::Request<openshell_core::proto::ReportPolicyStatusRequest>,
    ) -> Result<Response<openshell_core::proto::ReportPolicyStatusResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn get_sandbox_logs(
        &self,
        _: tonic::Request<openshell_core::proto::GetSandboxLogsRequest>,
    ) -> Result<Response<openshell_core::proto::GetSandboxLogsResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn push_sandbox_logs(
        &self,
        _: tonic::Request<tonic::Streaming<openshell_core::proto::PushSandboxLogsRequest>>,
    ) -> Result<Response<openshell_core::proto::PushSandboxLogsResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn submit_policy_analysis(
        &self,
        _: tonic::Request<openshell_core::proto::SubmitPolicyAnalysisRequest>,
    ) -> Result<Response<openshell_core::proto::SubmitPolicyAnalysisResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn get_draft_policy(
        &self,
        _: tonic::Request<openshell_core::proto::GetDraftPolicyRequest>,
    ) -> Result<Response<openshell_core::proto::GetDraftPolicyResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn approve_draft_chunk(
        &self,
        _: tonic::Request<openshell_core::proto::ApproveDraftChunkRequest>,
    ) -> Result<Response<openshell_core::proto::ApproveDraftChunkResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn reject_draft_chunk(
        &self,
        _: tonic::Request<openshell_core::proto::RejectDraftChunkRequest>,
    ) -> Result<Response<openshell_core::proto::RejectDraftChunkResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn approve_all_draft_chunks(
        &self,
        _: tonic::Request<openshell_core::proto::ApproveAllDraftChunksRequest>,
    ) -> Result<Response<openshell_core::proto::ApproveAllDraftChunksResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn edit_draft_chunk(
        &self,
        _: tonic::Request<openshell_core::proto::EditDraftChunkRequest>,
    ) -> Result<Response<openshell_core::proto::EditDraftChunkResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn undo_draft_chunk(
        &self,
        _: tonic::Request<openshell_core::proto::UndoDraftChunkRequest>,
    ) -> Result<Response<openshell_core::proto::UndoDraftChunkResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn clear_draft_chunks(
        &self,
        _: tonic::Request<openshell_core::proto::ClearDraftChunksRequest>,
    ) -> Result<Response<openshell_core::proto::ClearDraftChunksResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn get_draft_history(
        &self,
        _: tonic::Request<openshell_core::proto::GetDraftHistoryRequest>,
    ) -> Result<Response<openshell_core::proto::GetDraftHistoryResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

async fn spawn_gateway(registry: Arc<SupervisorSessionRegistry>) -> Channel {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let grpc = OpenShellServer::new(RelayGateway { registry });
    let service = MultiplexedService::new(grpc, health_router());

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let svc = service.clone();
            tokio::spawn(async move {
                let _ = Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .expect("client connect")
}

fn register_session(
    registry: &SupervisorSessionRegistry,
    sandbox_id: &str,
) -> mpsc::Receiver<GatewayMessage> {
    register_session_with_capacity(registry, sandbox_id, 8)
}

fn register_session_with_capacity(
    registry: &SupervisorSessionRegistry,
    sandbox_id: &str,
    capacity: usize,
) -> mpsc::Receiver<GatewayMessage> {
    let (tx, rx) = mpsc::channel(capacity);
    let (shutdown_tx, _shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    registry.register(
        sandbox_id.to_string(),
        "sess-1".to_string(),
        tx,
        shutdown_tx,
    );
    rx
}

/// Mock supervisor that opens a `RelayStream`, sends `Init`, then echoes every
/// data frame it receives. Returns when the gateway drops the stream or when
/// the supervisor's own outbound channel closes.
async fn run_echo_supervisor(channel: Channel, channel_id: String) {
    let mut client = OpenShellClient::new(channel);
    let (out_tx, out_rx) = mpsc::channel::<RelayFrame>(16);
    let outbound = ReceiverStream::new(out_rx);

    out_tx
        .send(RelayFrame {
            payload: Some(openshell_core::proto::relay_frame::Payload::Init(
                RelayInit { channel_id },
            )),
        })
        .await
        .expect("send init");

    let response = client
        .relay_stream(outbound)
        .await
        .expect("relay_stream rpc");
    let mut inbound = response.into_inner();

    while let Some(msg) = inbound.next().await {
        let Ok(frame) = msg else { break };
        let Some(openshell_core::proto::relay_frame::Payload::Data(data)) = frame.payload else {
            continue;
        };
        let echoed = RelayFrame {
            payload: Some(openshell_core::proto::relay_frame::Payload::Data(data)),
        };
        if out_tx.send(echoed).await.is_err() {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn relay_round_trips_bytes() {
    let registry = Arc::new(SupervisorSessionRegistry::new());
    let channel = spawn_gateway(Arc::clone(&registry)).await;
    let mut session_rx = register_session(&registry, "sbx");

    let (channel_id, relay_rx) = registry
        .open_relay("sbx", Duration::from_secs(2))
        .await
        .expect("open_relay");

    let opened = match session_rx.recv().await.expect("RelayOpen").payload {
        Some(openshell_core::proto::gateway_message::Payload::RelayOpen(r)) => r.channel_id,
        other => panic!("expected RelayOpen, got {other:?}"),
    };
    assert_eq!(opened, channel_id);

    tokio::spawn(run_echo_supervisor(channel, channel_id));

    let relay = relay_rx.await.expect("relay duplex");
    let (mut read_half, mut write_half) = tokio::io::split(relay);

    write_half.write_all(b"hello relay").await.expect("write");
    write_half.flush().await.expect("flush");

    let mut buf = [0u8; 11];
    read_half.read_exact(&mut buf).await.expect("read echoed");
    assert_eq!(&buf, b"hello relay");
}

#[tokio::test]
async fn relay_closes_cleanly_when_gateway_drops() {
    let registry = Arc::new(SupervisorSessionRegistry::new());
    let channel = spawn_gateway(Arc::clone(&registry)).await;
    let mut session_rx = register_session(&registry, "sbx");

    let (channel_id, relay_rx) = registry
        .open_relay("sbx", Duration::from_secs(2))
        .await
        .expect("open_relay");
    let _ = session_rx.recv().await.expect("RelayOpen");

    let supervisor = tokio::spawn(run_echo_supervisor(channel, channel_id));

    let relay = relay_rx.await.expect("relay duplex");
    drop(relay);

    // The supervisor's inbound stream should terminate shortly after the
    // gateway side drops — its echo loop exits and the task finishes.
    tokio::time::timeout(Duration::from_secs(5), supervisor)
        .await
        .expect("supervisor should terminate after gateway drop")
        .expect("supervisor task");
}

#[tokio::test]
async fn relay_sees_eof_when_supervisor_closes() {
    let registry = Arc::new(SupervisorSessionRegistry::new());
    let channel = spawn_gateway(Arc::clone(&registry)).await;
    let mut session_rx = register_session(&registry, "sbx");

    let (channel_id, relay_rx) = registry
        .open_relay("sbx", Duration::from_secs(2))
        .await
        .expect("open_relay");
    let _ = session_rx.recv().await.expect("RelayOpen");

    // Supervisor sends init, then drops its outbound sender → gateway reader
    // should see EOF.
    let supervisor = {
        let channel_id = channel_id.clone();
        tokio::spawn(async move {
            let mut client = OpenShellClient::new(channel);
            let (out_tx, out_rx) = mpsc::channel::<RelayFrame>(4);
            let outbound = ReceiverStream::new(out_rx);
            out_tx
                .send(RelayFrame {
                    payload: Some(openshell_core::proto::relay_frame::Payload::Init(
                        RelayInit { channel_id },
                    )),
                })
                .await
                .expect("send init");
            let _response = client.relay_stream(outbound).await.expect("rpc");
            drop(out_tx);
            tokio::time::sleep(Duration::from_millis(200)).await;
        })
    };

    let relay = relay_rx.await.expect("relay duplex");
    let (mut read_half, _write_half) = tokio::io::split(relay);
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), read_half.read(&mut buf))
        .await
        .expect("read should complete")
        .expect("read ok");
    assert_eq!(n, 0, "gateway-side read should see EOF");

    supervisor.await.expect("supervisor task");
}

#[tokio::test]
async fn open_relay_times_out_when_no_session() {
    let registry = Arc::new(SupervisorSessionRegistry::new());
    let _channel = spawn_gateway(Arc::clone(&registry)).await;

    let err = registry
        .open_relay("missing", Duration::from_millis(100))
        .await
        .expect_err("should time out");
    assert_eq!(err.code(), tonic::Code::Unavailable);
}

#[tokio::test]
async fn concurrent_relays_multiplex_independently() {
    let registry = Arc::new(SupervisorSessionRegistry::new());
    let channel = spawn_gateway(Arc::clone(&registry)).await;
    let mut session_rx = register_session(&registry, "sbx");

    let (id_a, rx_a) = registry
        .open_relay("sbx", Duration::from_secs(2))
        .await
        .expect("open_relay a");
    let _ = session_rx.recv().await.expect("RelayOpen a");

    let (id_b, rx_b) = registry
        .open_relay("sbx", Duration::from_secs(2))
        .await
        .expect("open_relay b");
    let _ = session_rx.recv().await.expect("RelayOpen b");
    assert_ne!(id_a, id_b);

    tokio::spawn(run_echo_supervisor(channel.clone(), id_a));
    tokio::spawn(run_echo_supervisor(channel, id_b));

    let relay_a = rx_a.await.expect("relay a");
    let relay_b = rx_b.await.expect("relay b");

    let (mut ra, mut wa) = tokio::io::split(relay_a);
    let (mut rb, mut wb) = tokio::io::split(relay_b);

    wa.write_all(b"stream-A").await.unwrap();
    wb.write_all(b"stream-B").await.unwrap();
    wa.flush().await.unwrap();
    wb.flush().await.unwrap();

    let mut buf_a = [0u8; 8];
    let mut buf_b = [0u8; 8];
    ra.read_exact(&mut buf_a).await.unwrap();
    rb.read_exact(&mut buf_b).await.unwrap();
    assert_eq!(&buf_a, b"stream-A");
    assert_eq!(&buf_b, b"stream-B");
}

/// Bursts more `open_relay` calls than the per-sandbox cap allows in parallel
/// and asserts the registry enforces the ceiling cleanly. A well-behaved
/// caller inside the cap still succeeds; overflow calls return `ResourceExhausted`
/// rather than racing the pending map into an inconsistent state.
#[tokio::test]
async fn open_relay_enforces_per_sandbox_cap_under_concurrent_burst() {
    let registry = Arc::new(SupervisorSessionRegistry::new());
    let _channel = spawn_gateway(Arc::clone(&registry)).await;
    // Oversized mpsc so the session doesn't backpressure the burst — the cap,
    // not the channel, is what we're testing.
    let _session_rx = register_session_with_capacity(&registry, "sbx", 256);

    // Fire 64 concurrent opens. Per-sandbox cap is 32, global cap is 256,
    // so exactly 32 should succeed and 32 should be rejected with
    // `ResourceExhausted` carrying the per-sandbox message.
    let mut handles = Vec::with_capacity(64);
    for _ in 0..64 {
        let r = Arc::clone(&registry);
        handles.push(tokio::spawn(async move {
            r.open_relay("sbx", Duration::from_secs(1)).await
        }));
    }

    let mut ok = 0usize;
    let mut exhausted = 0usize;
    for h in handles {
        match h.await.expect("task joined") {
            Ok(_pair) => ok += 1,
            Err(status) if status.code() == tonic::Code::ResourceExhausted => {
                assert!(
                    status.message().contains("per-sandbox relay limit"),
                    "expected per-sandbox error message, got: {}",
                    status.message()
                );
                exhausted += 1;
            }
            Err(other) => panic!("unexpected open_relay error: {other:?}"),
        }
    }
    assert_eq!(ok, 32, "exactly per-sandbox cap should succeed");
    assert_eq!(exhausted, 32, "overflow should be rejected, not dropped");

    // A different sandbox still has headroom — the per-sandbox cap doesn't
    // leak onto unrelated tenants.
    let _other_rx = register_session_with_capacity(&registry, "sbx-other", 8);
    registry
        .open_relay("sbx-other", Duration::from_secs(1))
        .await
        .expect("other sandbox should not be affected by sbx cap");
}
