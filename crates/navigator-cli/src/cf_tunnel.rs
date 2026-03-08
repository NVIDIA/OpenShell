// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cloudflare Access tunnel proxy.
//!
//! When the gateway sits behind a Cloudflare Tunnel with Cloudflare Access
//! enabled, gRPC (HTTP/2 POST) requests are rejected at the CF edge because
//! Access auth operates at the HTTP layer and does not support non-browser POST
//! traffic with browser-flow JWTs.
//!
//! `cloudflared access tcp` solves this by opening a **WebSocket** to the edge
//! (WebSocket upgrades are GET requests, which Access authenticates normally)
//! and then piping raw TCP bytes through WebSocket binary frames.
//!
//! This module implements the same pattern:
//!
//! 1. Bind a local TCP listener on an ephemeral port.
//! 2. For each accepted connection, open a WebSocket (`wss://`) to the CF
//!    tunnel hostname with the JWT in the `Cf-Access-Token` header.
//! 3. Bidirectionally pipe bytes between the local TCP stream and the
//!    WebSocket.
//!
//! The gRPC [`Channel`] then connects to `http://127.0.0.1:<local_port>`
//! (plaintext) — Cloudflare handles TLS on the edge, and the WebSocket
//! carries the raw bytes to the origin.

use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use miette::{IntoDiagnostic, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tracing::{debug, error, warn};

/// A running Cloudflare tunnel proxy.
///
/// The proxy listens on a local TCP port and tunnels each connection over a
/// WebSocket to the Cloudflare edge.  Drop the handle to shut down the
/// listener (the background task is detached via `tokio::spawn`).
pub struct CfTunnelProxy {
    /// Local address the proxy is listening on (e.g. `127.0.0.1:54321`).
    pub local_addr: SocketAddr,
}

/// Configuration for establishing the WebSocket tunnel.
#[derive(Clone)]
struct TunnelConfig {
    /// The `wss://` URL to connect to (derived from the gateway endpoint).
    ws_url: String,
    /// The CF Access JWT token.
    cf_token: String,
}

/// Start the local tunnel proxy.
///
/// Returns a [`CfTunnelProxy`] with the local address to connect to.
/// The proxy runs as a background tokio task.
pub async fn start_tunnel_proxy(gateway_endpoint: &str, cf_token: &str) -> Result<CfTunnelProxy> {
    let listener = TcpListener::bind("127.0.0.1:0").await.into_diagnostic()?;
    let local_addr = listener.local_addr().into_diagnostic()?;

    // Convert the gateway endpoint to a WebSocket URL.
    // https://foo.com -> wss://foo.com
    // http://foo.com  -> ws://foo.com  (shouldn't happen with CF, but handle it)
    let ws_url = format!(
        "{}/_ws_tunnel",
        gateway_endpoint
            .replace("https://", "wss://")
            .replace("http://", "ws://")
            .trim_end_matches('/')
    );

    let config = Arc::new(TunnelConfig {
        ws_url,
        cf_token: cf_token.to_string(),
    });

    debug!(
        local_addr = %local_addr,
        gateway = %gateway_endpoint,
        "starting Cloudflare tunnel proxy"
    );

    // Spawn the accept loop.
    tokio::spawn(accept_loop(listener, config));

    Ok(CfTunnelProxy { local_addr })
}

/// Accept loop: for each incoming TCP connection, spawn a handler that
/// opens a WebSocket to the CF edge and pipes bytes bidirectionally.
async fn accept_loop(listener: TcpListener, config: Arc<TunnelConfig>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                debug!(peer = %peer, "accepted local tunnel connection");
                let config = Arc::clone(&config);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, &config).await {
                        warn!(peer = %peer, error = %e, "tunnel connection failed");
                    }
                });
            }
            Err(e) => {
                error!(error = %e, "failed to accept tunnel connection");
                // Brief backoff to avoid tight error loops.
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// Handle a single tunneled connection: open a WebSocket to the CF edge and
/// bidirectionally copy bytes.
async fn handle_connection(tcp_stream: TcpStream, config: &TunnelConfig) -> Result<()> {
    let ws_stream = open_ws(config).await?;
    let (ws_sink, ws_source) = ws_stream.split();
    let (tcp_read, tcp_write) = tokio::io::split(tcp_stream);

    // Two tasks: TCP->WS and WS->TCP.  When either direction finishes (EOF or
    // error), we drop the other to clean up.
    let tcp_to_ws = tokio::spawn(copy_tcp_to_ws(tcp_read, ws_sink));
    let ws_to_tcp = tokio::spawn(copy_ws_to_tcp(ws_source, tcp_write));

    // Wait for either direction to finish, then cancel the other.
    tokio::select! {
        res = tcp_to_ws => {
            if let Err(e) = res {
                debug!(error = %e, "tcp->ws task panicked");
            }
        }
        res = ws_to_tcp => {
            if let Err(e) = res {
                debug!(error = %e, "ws->tcp task panicked");
            }
        }
    }

    Ok(())
}

/// Open a WebSocket connection to the Cloudflare edge.
async fn open_ws(config: &TunnelConfig) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>> {
    let mut request = (&config.ws_url).into_client_request().into_diagnostic()?;

    // Inject the CF Access token via multiple headers for maximum compatibility.
    // cloudflared uses `Cf-Access-Token`, but CF Access also checks the
    // `CF_Authorization` cookie and `Cf-Access-Jwt-Assertion` header.
    let token_val = HeaderValue::from_str(&config.cf_token)
        .map_err(|e| miette::miette!("invalid CF token header value: {e}"))?;
    request
        .headers_mut()
        .insert("Cf-Access-Token", token_val.clone());
    request
        .headers_mut()
        .insert("Cf-Access-Jwt-Assertion", token_val);
    request.headers_mut().insert(
        "Cookie",
        HeaderValue::from_str(&format!("CF_Authorization={}", config.cf_token))
            .map_err(|e| miette::miette!("invalid CF cookie value: {e}"))?,
    );

    debug!(url = %config.ws_url, "opening WebSocket to CF edge");

    let (ws_stream, response) = tokio_tungstenite::connect_async(request)
        .await
        .map_err(|e| miette::miette!("WebSocket connect failed: {e}"))?;

    debug!(
        status = %response.status(),
        "WebSocket connected to CF edge"
    );

    Ok(ws_stream)
}

/// Copy bytes from a local TCP reader into WebSocket binary frames.
async fn copy_tcp_to_ws(
    mut tcp_read: tokio::io::ReadHalf<TcpStream>,
    mut ws_sink: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
) {
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        match tcp_read.read(&mut buf).await {
            Ok(0) => {
                // EOF — send a close frame.
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
                debug!(error = %e, "tcp read error");
                let _ = ws_sink.close().await;
                break;
            }
        }
    }
}

/// Copy bytes from WebSocket binary frames into a local TCP writer.
async fn copy_ws_to_tcp(
    mut ws_source: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    mut tcp_write: tokio::io::WriteHalf<TcpStream>,
) {
    while let Some(msg) = ws_source.next().await {
        match msg {
            Ok(Message::Binary(data)) => {
                if tcp_write.write_all(&data).await.is_err() {
                    break;
                }
            }
            Ok(Message::Close(_)) => break,
            Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => {
                // Handled automatically by tungstenite.
            }
            Ok(Message::Text(text)) => {
                // Some proxies send text frames — treat as binary.
                if tcp_write.write_all(text.as_bytes()).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                debug!(error = %e, "ws read error");
                break;
            }
        }
    }
    let _ = tcp_write.shutdown().await;
}
