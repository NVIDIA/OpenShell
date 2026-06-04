// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the WebSocket tunnel (`/_ws_tunnel`).
//!
//! These tests verify that gRPC traffic can be tunneled through a WebSocket
//! connection, which is the mechanism used to bypass Cloudflare Access POST
//! rejection.  The architecture mirrors production but avoids needing a full
//! `ServerState`:
//!
//! ```text
//! gRPC client ──TCP──▶ local proxy (port C)
//!                          │
//!                     WebSocket (ws://)
//!                          │
//!                     WS tunnel server (port B)  ──/_ws_tunnel handler──▶
//!                          │
//!                     in-memory duplex stream
//!                          │
//!                     MultiplexedService ──▶ TestOpenShell
//! ```
//!
//! The WS tunnel handler is kept standalone so it stays isolated from the full
//! `ServerState` dependency while still matching the production bridge logic.

mod common;

use axum::{
    Router,
    extract::{State, WebSocketUpgrade, ws::Message},
    response::IntoResponse,
    routing::get,
};
use bytes::Bytes;
use common::TestOpenShell;
use futures_util::{SinkExt, StreamExt};
use http_body_util::Empty;
use hyper::{Request, StatusCode};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use openshell_core::proto::{
    HealthRequest, ServiceStatus, open_shell_client::OpenShellClient,
    open_shell_server::OpenShellServer,
};
use openshell_server::{MultiplexedService, Store, health_router};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite;

// ---------------------------------------------------------------------------
// Test WS tunnel handler (standalone, no ServerState dependency)
// ---------------------------------------------------------------------------

/// Standalone WS tunnel router for testing.
///
/// Functionally identical to `ws_tunnel::router()` in the server, but takes a
/// ready-made multiplex service instead of the full server state.
fn test_ws_tunnel_router(service: TestTunnelService) -> Router {
    Router::new()
        .route("/_ws_tunnel", get(test_ws_tunnel_handler))
        .with_state(TestTunnelState { service })
}

#[derive(Clone)]
struct TestTunnelState {
    service: TestTunnelService,
}

type TestTunnelService = MultiplexedService<OpenShellServer<TestOpenShell>, Router>;

async fn test_ws_tunnel_handler(
    State(state): State<TestTunnelState>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| async move {
        if let Err(e) = handle_ws_tunnel(socket, state.service).await {
            eprintln!("WS tunnel error: {e}");
        }
    })
}

/// Bridge bytes between a WebSocket and an in-memory multiplex service.
///
/// This is the same logic as `ws_tunnel::handle_ws_tunnel` in the server.
async fn handle_ws_tunnel(
    ws: axum::extract::ws::WebSocket,
    service: TestTunnelService,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (tunnel_stream, service_stream) = tokio::io::duplex(64 * 1024);
    let (ws_sink, ws_source) = ws.split();
    let (tunnel_read, tunnel_write) = tokio::io::split(tunnel_stream);

    let service_task = tokio::spawn(async move {
        let _ = Builder::new(TokioExecutor::new())
            .serve_connection_with_upgrades(TokioIo::new(service_stream), service)
            .await;
    });
    let mut tunnel_to_ws = tokio::spawn(copy_reader_to_ws(tunnel_read, ws_sink));
    let mut ws_to_tunnel = tokio::spawn(copy_ws_to_writer(ws_source, tunnel_write));

    tokio::select! {
        res = &mut tunnel_to_ws => {
            if let Ok(Err(e)) = res {
                eprintln!("tunnel->ws error: {e}");
            }
            ws_to_tunnel.abort();
        }
        res = &mut ws_to_tunnel => {
            if let Ok(Err(e)) = res {
                eprintln!("ws->tunnel error: {e}");
            }
            tunnel_to_ws.abort();
        }
    }
    service_task.abort();

    Ok(())
}

async fn copy_reader_to_ws<R>(
    mut reader: R,
    mut ws_sink: futures_util::stream::SplitSink<axum::extract::ws::WebSocket, Message>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => {
                let _ = ws_sink.close().await;
                break;
            }
            Ok(n) => {
                if ws_sink
                    .send(Message::Binary(buf[..n].to_vec().into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
    Ok(())
}

async fn copy_ws_to_writer<W>(
    mut ws_source: futures_util::stream::SplitStream<axum::extract::ws::WebSocket>,
    mut writer: W,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    W: AsyncWrite + Unpin,
{
    while let Some(msg) = ws_source.next().await {
        match msg {
            Ok(Message::Binary(data)) => {
                if writer.write_all(&data).await.is_err() {
                    break;
                }
            }
            Ok(Message::Text(text)) => {
                if writer.write_all(text.as_bytes()).await.is_err() {
                    break;
                }
            }
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(Message::Ping(_) | Message::Pong(_)) => {}
        }
    }
    let _ = writer.shutdown().await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Test client-side TCP↔WS bridge (mirrors edge_tunnel.rs from openshell-cli)
// ---------------------------------------------------------------------------

/// Start a local TCP listener that bridges each connection to the WS tunnel.
///
/// Returns the local address the proxy is listening on.
async fn start_ws_proxy(ws_url: String) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((tcp_stream, _)) = listener.accept().await else {
                continue;
            };
            let ws_url = ws_url.clone();
            tokio::spawn(async move {
                let _ = proxy_connection(tcp_stream, &ws_url).await;
            });
        }
    });

    local_addr
}

/// Bridge a single local TCP connection through a WebSocket to the tunnel.
async fn proxy_connection(
    tcp_stream: TcpStream,
    ws_url: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (ws_stream, _response) = tokio_tungstenite::connect_async(ws_url).await?;
    let (ws_sink, ws_source) = ws_stream.split();
    let (tcp_read, tcp_write) = tokio::io::split(tcp_stream);

    let mut tcp_to_ws = tokio::spawn(proxy_tcp_to_ws(tcp_read, ws_sink));
    let mut ws_to_tcp = tokio::spawn(proxy_ws_to_tcp(ws_source, tcp_write));

    tokio::select! {
        _ = &mut tcp_to_ws => {
            ws_to_tcp.abort();
        }
        _ = &mut ws_to_tcp => {
            tcp_to_ws.abort();
        }
    }

    Ok(())
}

async fn proxy_tcp_to_ws(
    mut tcp_read: tokio::io::ReadHalf<TcpStream>,
    mut ws_sink: futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
        tungstenite::Message,
    >,
) {
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        match tcp_read.read(&mut buf).await {
            Ok(0) | Err(_) => {
                let _ = ws_sink.close().await;
                break;
            }
            Ok(n) => {
                if ws_sink
                    .send(tungstenite::Message::Binary(buf[..n].to_vec().into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}

async fn proxy_ws_to_tcp(
    mut ws_source: futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    >,
    mut tcp_write: tokio::io::WriteHalf<TcpStream>,
) {
    while let Some(msg) = ws_source.next().await {
        match msg {
            Ok(tungstenite::Message::Binary(data)) => {
                if tcp_write.write_all(&data).await.is_err() {
                    break;
                }
            }
            Ok(tungstenite::Message::Text(text)) => {
                if tcp_write.write_all(text.as_bytes()).await.is_err() {
                    break;
                }
            }
            Ok(tungstenite::Message::Close(_)) | Err(_) => break,
            Ok(_) => {}
        }
    }
    let _ = tcp_write.shutdown().await;
}

// ---------------------------------------------------------------------------
// Helpers: start the gRPC target server + WS tunnel server
// ---------------------------------------------------------------------------

/// Start a plaintext gRPC+HTTP server using `MultiplexedService` with upgrades.
///
/// Returns the bound address and a handle to abort the server.
async fn start_grpc_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let grpc_service = OpenShellServer::new(TestOpenShell);
    let http_service = health_router(test_health_store().await);
    let service = MultiplexedService::new(grpc_service, http_service);

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let svc = service.clone();
            tokio::spawn(async move {
                let _ = Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    (addr, handle)
}

/// Start the standalone WS tunnel axum server backed by an in-memory service.
///
/// Returns the bound address and a handle to abort the server.
async fn start_ws_tunnel_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let grpc_service = OpenShellServer::new(TestOpenShell);
    let http_service = health_router(test_health_store().await);
    let app = test_ws_tunnel_router(MultiplexedService::new(grpc_service, http_service));

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, handle)
}

/// Start the full test stack: gRPC server + WS tunnel + local proxy.
///
/// Returns:
/// - `proxy_addr`: connect gRPC clients here (traffic is tunneled through WS)
/// - `grpc_addr`: direct gRPC server address (for baseline/bypass tests)
/// - handles to abort both servers
struct TestStack {
    /// Connect gRPC clients here — traffic flows through the WS tunnel.
    proxy_addr: SocketAddr,
    /// Direct address of the gRPC server (bypass tunnel for baseline checks).
    grpc_addr: SocketAddr,
    /// WS tunnel server address (kept for diagnostics).
    #[allow(dead_code)]
    ws_tunnel_addr: SocketAddr,
    grpc_server: tokio::task::JoinHandle<()>,
    ws_tunnel_server: tokio::task::JoinHandle<()>,
}

impl TestStack {
    async fn start() -> Self {
        let (grpc_addr, grpc_server) = start_grpc_server().await;
        let (ws_tunnel_addr, ws_tunnel_server) = start_ws_tunnel_server().await;
        let ws_url = format!("ws://127.0.0.1:{}/_ws_tunnel", ws_tunnel_addr.port());
        let proxy_addr = start_ws_proxy(ws_url).await;

        // Give servers a moment to start accepting connections.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        Self {
            proxy_addr,
            grpc_addr,
            ws_tunnel_addr,
            grpc_server,
            ws_tunnel_server,
        }
    }

    fn abort(&self) {
        self.grpc_server.abort();
        self.ws_tunnel_server.abort();
    }
}

// ===========================================================================
// Tests
// ===========================================================================

/// Test 1: gRPC health check piped through the WebSocket tunnel.
///
/// Verifies the full path: gRPC client → local TCP proxy → WebSocket →
/// WS tunnel handler → loopback TCP → `MultiplexedService` → `TestOpenShell`.
#[tokio::test]
async fn ws_tunnel_grpc_health_through_websocket() {
    let stack = TestStack::start().await;

    // Baseline: direct gRPC works
    let mut direct_client = OpenShellClient::connect(format!("http://{}", stack.grpc_addr))
        .await
        .expect("direct gRPC connect failed");
    let resp = direct_client
        .health(HealthRequest {})
        .await
        .expect("direct health RPC failed");
    assert_eq!(resp.get_ref().status, ServiceStatus::Healthy as i32);

    // Through the WS tunnel
    let mut tunnel_client = OpenShellClient::connect(format!("http://{}", stack.proxy_addr))
        .await
        .expect("tunnel gRPC connect failed");
    let resp = tunnel_client
        .health(HealthRequest {})
        .await
        .expect("tunneled health RPC failed");
    assert_eq!(
        resp.get_ref().status,
        ServiceStatus::Healthy as i32,
        "gRPC health check through WS tunnel should return Healthy"
    );

    // Also verify HTTP /healthz works directly (not through tunnel — WS is
    // for gRPC; HTTP healthz goes through the multiplexed service directly).
    let stream = TcpStream::connect(stack.grpc_addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .method("GET")
        .uri(format!("http://{}/healthz", stack.grpc_addr))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    stack.abort();
}

/// Test 2: Data integrity through the WS tunnel with multiple sequential RPCs.
///
/// Sends multiple health RPCs through the same tunnel to verify that the
/// TCP↔WS↔TCP bridge correctly handles multiple request/response cycles
/// on a single HTTP/2 connection.
#[tokio::test]
async fn ws_tunnel_bidirectional_data_integrity() {
    let stack = TestStack::start().await;

    let mut client = OpenShellClient::connect(format!("http://{}", stack.proxy_addr))
        .await
        .expect("tunnel gRPC connect failed");

    // Send 20 sequential health RPCs through the tunnel.
    for i in 0..20 {
        let resp = client
            .health(HealthRequest {})
            .await
            .unwrap_or_else(|e| panic!("health RPC #{i} failed: {e}"));
        assert_eq!(
            resp.get_ref().status,
            ServiceStatus::Healthy as i32,
            "health RPC #{i} returned unexpected status"
        );
        assert_eq!(
            resp.get_ref().version,
            "test",
            "health RPC #{i} returned unexpected version"
        );
    }

    stack.abort();
}

/// Test 3: Multiple concurrent WS tunnel connections.
///
/// Opens 5 independent gRPC clients, each going through its own WS tunnel
/// connection, and sends health RPCs concurrently.
#[tokio::test]
async fn ws_tunnel_concurrent_connections() {
    let stack = TestStack::start().await;

    let mut handles = Vec::new();
    for i in 0..5 {
        let proxy_addr = stack.proxy_addr;
        handles.push(tokio::spawn(async move {
            let mut client = OpenShellClient::connect(format!("http://{proxy_addr}"))
                .await
                .unwrap_or_else(|e| panic!("client #{i} connect failed: {e}"));

            for j in 0..5 {
                let resp = client
                    .health(HealthRequest {})
                    .await
                    .unwrap_or_else(|e| panic!("client #{i} RPC #{j} failed: {e}"));
                assert_eq!(
                    resp.get_ref().status,
                    ServiceStatus::Healthy as i32,
                    "client #{i} RPC #{j} returned unexpected status"
                );
            }
        }));
    }

    for (i, handle) in handles.into_iter().enumerate() {
        handle
            .await
            .unwrap_or_else(|e| panic!("client task #{i} panicked: {e}"));
    }

    stack.abort();
}

/// Test 4: Graceful close — after a WS tunnel connection is used and dropped,
/// subsequent connections through the same tunnel server still work.
#[tokio::test]
async fn ws_tunnel_graceful_close() {
    let stack = TestStack::start().await;

    // First connection: use and drop
    {
        let mut client = OpenShellClient::connect(format!("http://{}", stack.proxy_addr))
            .await
            .expect("first tunnel connect failed");
        let resp = client.health(HealthRequest {}).await.unwrap();
        assert_eq!(resp.get_ref().status, ServiceStatus::Healthy as i32);
        // client dropped here, triggering WS close
    }

    // Brief pause to let the close propagate
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Second connection: should still work
    {
        let mut client = OpenShellClient::connect(format!("http://{}", stack.proxy_addr))
            .await
            .expect("second tunnel connect failed");
        let resp = client.health(HealthRequest {}).await.unwrap();
        assert_eq!(
            resp.get_ref().status,
            ServiceStatus::Healthy as i32,
            "second connection after graceful close should work"
        );
    }

    // Third connection: verify repeated close/reconnect cycle
    {
        let mut client = OpenShellClient::connect(format!("http://{}", stack.proxy_addr))
            .await
            .expect("third tunnel connect failed");
        let resp = client.health(HealthRequest {}).await.unwrap();
        assert_eq!(
            resp.get_ref().status,
            ServiceStatus::Healthy as i32,
            "third connection after repeated close/reconnect should work"
        );
    }

    stack.abort();
}

/// Build an in-memory store sufficient for wiring `health_router` in tests
/// where the persistence layer itself is not under test.
async fn test_health_store() -> Arc<Store> {
    Arc::new(
        Store::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite store for tests"),
    )
}
