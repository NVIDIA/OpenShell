// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! WebSocket tunnel endpoint for edge-authenticated connections.
//!
//! When the gateway is behind an edge proxy that only authenticates
//! browser-like GET requests, gRPC POST requests are rejected.  The
//! client-side proxy (`edge_tunnel.rs` in `openshell-cli`) opens a WebSocket
//! to this endpoint — the upgrade is a GET so the edge proxy passes it —
//! and then pipes raw TCP bytes through binary WebSocket frames.
//!
//! This handler:
//! 1. Accepts a WebSocket upgrade on `/_ws_tunnel`.
//! 2. Spawns an in-memory connection into the normal `MultiplexedService`.
//! 3. Bidirectionally copies bytes between the WebSocket and that stream.
//!
//! Using an in-memory stream keeps the tunnel mode-independent: it works for
//! both plaintext gateways and TLS-backed gateways without needing to re-enter
//! the public listener or negotiate a second local TLS hop.

use axum::{
    Router,
    extract::{State, WebSocketUpgrade, ws::Message},
    response::IntoResponse,
    routing::get,
};
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
    ws.on_upgrade(move |socket| async move {
        if let Err(e) = handle_ws_tunnel(socket, state).await {
            warn!(error = %e, "WebSocket tunnel connection failed");
        }
    })
}

/// Pipe bytes between the WebSocket and an in-memory `MultiplexService` stream.
async fn handle_ws_tunnel(
    ws: axum::extract::ws::WebSocket,
    state: Arc<ServerState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let service = crate::MultiplexService::new(state);
    let (tunnel_stream, service_stream) = tokio::io::duplex(64 * 1024);
    debug!("WS tunnel: spawned in-memory multiplex connection");

    let (ws_sink, ws_source) = ws.split();
    let (tunnel_read, tunnel_write) = tokio::io::split(tunnel_stream);

    let service_task = tokio::spawn(async move {
        if let Err(e) = service.serve(service_stream).await {
            debug!(error = %e, "WS tunnel: multiplex service error");
        }
    });
    let mut tunnel_to_ws = tokio::spawn(copy_reader_to_ws(tunnel_read, ws_sink));
    let mut ws_to_tunnel = tokio::spawn(copy_ws_to_writer(ws_source, tunnel_write));

    tokio::select! {
        res = &mut tunnel_to_ws => {
            if let Ok(Err(e)) = res {
                debug!(error = %e, "WS tunnel: tunnel->ws error");
            }
            ws_to_tunnel.abort();
        }
        res = &mut ws_to_tunnel => {
            if let Ok(Err(e)) = res {
                debug!(error = %e, "WS tunnel: ws->tunnel error");
            }
            tunnel_to_ws.abort();
        }
    }
    service_task.abort();

    Ok(())
}

/// Copy bytes from an async reader into WebSocket binary frames.
async fn copy_reader_to_ws<R>(
    mut reader: R,
    mut ws_sink: futures::stream::SplitSink<axum::extract::ws::WebSocket, Message>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        match reader.read(&mut buf).await {
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
                debug!(error = %e, "WS tunnel: read error");
                let _ = ws_sink.close().await;
                break;
            }
        }
    }
    Ok(())
}

/// Copy bytes from WebSocket binary/text frames into an async writer.
async fn copy_ws_to_writer<W>(
    mut ws_source: futures::stream::SplitStream<axum::extract::ws::WebSocket>,
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
                // Some proxies send text frames — treat as binary.
                if writer.write_all(text.as_bytes()).await.is_err() {
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
    let _ = writer.shutdown().await;
    Ok(())
}
