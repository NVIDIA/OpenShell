// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! WebSocket tunnel endpoint for Cloudflare Access bypass.
//!
//! When the gateway is behind a Cloudflare Tunnel with CF Access enabled,
//! gRPC POST requests are rejected because CF Access only authenticates
//! browser-like GET requests.  The client-side proxy (`cf_tunnel.rs` in
//! `navigator-cli`) opens a WebSocket to this endpoint — the upgrade is a
//! GET so CF Access passes it — and then pipes raw TCP bytes through binary
//! WebSocket frames.
//!
//! This handler:
//! 1. Accepts a WebSocket upgrade on `/_ws_tunnel`.
//! 2. Opens a TCP connection back to itself (`127.0.0.1:<bind_port>`).
//! 3. Bidirectionally copies bytes between the WebSocket and the TCP stream.
//!
//! The loopback TCP connection enters the normal `MultiplexedService` path,
//! which inspects `content-type` and routes gRPC traffic to the gRPC service.

use axum::{
    Router,
    extract::{State, WebSocketUpgrade, ws::Message},
    response::IntoResponse,
    routing::get,
};
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::ServerState;

/// Create the WebSocket tunnel router.
pub fn router(state: Arc<ServerState>) -> Router {
    Router::new()
        .route("/_ws_tunnel", get(ws_tunnel_handler))
        .with_state(state)
}

/// Handle the WebSocket upgrade request.
async fn ws_tunnel_handler(
    State(state): State<Arc<ServerState>>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    let bind_addr = state.config.bind_address;
    ws.on_upgrade(move |socket| async move {
        if let Err(e) = handle_ws_tunnel(socket, bind_addr).await {
            warn!(error = %e, "WebSocket tunnel connection failed");
        }
    })
}

/// Pipe bytes between the WebSocket and a loopback TCP connection.
async fn handle_ws_tunnel(
    ws: axum::extract::ws::WebSocket,
    bind_addr: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Connect back to ourselves on the loopback interface.
    let loopback = format!("127.0.0.1:{}", bind_addr.port());
    debug!(target = %loopback, "WS tunnel: opening loopback TCP connection");

    let tcp_stream = TcpStream::connect(&loopback).await?;
    tcp_stream.set_nodelay(true)?;

    debug!("WS tunnel: loopback connected, starting bidirectional copy");

    let (ws_sink, ws_source) = ws.split();
    let (tcp_read, tcp_write) = tokio::io::split(tcp_stream);

    let tcp_to_ws = tokio::spawn(copy_tcp_to_ws(tcp_read, ws_sink));
    let ws_to_tcp = tokio::spawn(copy_ws_to_tcp(ws_source, tcp_write));

    // When either direction finishes, the other is implicitly cancelled
    // by dropping the join handle.
    tokio::select! {
        res = tcp_to_ws => {
            if let Ok(Err(e)) = res {
                debug!(error = %e, "WS tunnel: tcp->ws error");
            }
        }
        res = ws_to_tcp => {
            if let Ok(Err(e)) = res {
                debug!(error = %e, "WS tunnel: ws->tcp error");
            }
        }
    }

    Ok(())
}

/// Copy bytes from the loopback TCP stream into WebSocket binary frames.
async fn copy_tcp_to_ws(
    mut tcp_read: tokio::io::ReadHalf<TcpStream>,
    mut ws_sink: futures::stream::SplitSink<axum::extract::ws::WebSocket, Message>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        match tcp_read.read(&mut buf).await {
            Ok(0) => {
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
            Err(e) => {
                debug!(error = %e, "WS tunnel: tcp read error");
                let _ = ws_sink.close().await;
                break;
            }
        }
    }
    Ok(())
}

/// Copy bytes from WebSocket binary frames into the loopback TCP stream.
async fn copy_ws_to_tcp(
    mut ws_source: futures::stream::SplitStream<axum::extract::ws::WebSocket>,
    mut tcp_write: tokio::io::WriteHalf<TcpStream>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    while let Some(msg) = ws_source.next().await {
        match msg {
            Ok(Message::Binary(data)) => {
                if tcp_write.write_all(&data).await.is_err() {
                    break;
                }
            }
            Ok(Message::Text(text)) => {
                // Some proxies send text frames — treat as binary.
                if tcp_write.write_all(text.as_bytes()).await.is_err() {
                    break;
                }
            }
            Ok(Message::Close(_)) => break,
            Ok(Message::Ping(_) | Message::Pong(_)) => {
                // Handled automatically by axum's WebSocket.
            }
            Err(e) => {
                debug!(error = %e, "WS tunnel: ws read error");
                break;
            }
        }
    }
    let _ = tcp_write.shutdown().await;
    Ok(())
}
