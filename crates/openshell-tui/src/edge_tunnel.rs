// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Edge-authenticated WebSocket tunnel proxy for TUI gateway switching.

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

pub struct EdgeTunnelProxy {
    pub local_addr: SocketAddr,
}

#[derive(Clone)]
struct TunnelConfig {
    ws_url: String,
    edge_token: String,
}

pub async fn start_tunnel_proxy(
    gateway_endpoint: &str,
    edge_token: &str,
) -> Result<EdgeTunnelProxy> {
    let listener = TcpListener::bind("127.0.0.1:0").await.into_diagnostic()?;
    let local_addr = listener.local_addr().into_diagnostic()?;
    let ws_url = format!(
        "{}/_ws_tunnel",
        gateway_endpoint
            .replacen("https://", "wss://", 1)
            .replacen("http://", "ws://", 1)
            .trim_end_matches('/')
    );
    let config = Arc::new(TunnelConfig {
        ws_url,
        edge_token: edge_token.to_string(),
    });

    debug!(
        local_addr = %local_addr,
        gateway = %gateway_endpoint,
        "starting TUI edge tunnel proxy"
    );
    tokio::spawn(accept_loop(listener, config));
    Ok(EdgeTunnelProxy { local_addr })
}

async fn accept_loop(listener: TcpListener, config: Arc<TunnelConfig>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let config = Arc::clone(&config);
                tokio::spawn(async move {
                    if let Err(err) = handle_connection(stream, &config).await {
                        warn!(peer = %peer, error = %err, "TUI edge tunnel connection failed");
                    }
                });
            }
            Err(err) => {
                error!(error = %err, "failed to accept TUI edge tunnel connection");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

async fn handle_connection(tcp_stream: TcpStream, config: &TunnelConfig) -> Result<()> {
    let ws_stream = open_ws(config).await?;
    let (ws_sink, ws_source) = ws_stream.split();
    let (tcp_read, tcp_write) = tokio::io::split(tcp_stream);

    let mut tcp_to_ws = tokio::spawn(copy_tcp_to_ws(tcp_read, ws_sink));
    let mut ws_to_tcp = tokio::spawn(copy_ws_to_tcp(ws_source, tcp_write));

    tokio::select! {
        res = &mut tcp_to_ws => {
            if let Err(err) = res {
                debug!(error = %err, "TUI tcp->ws task panicked");
            }
            ws_to_tcp.abort();
        }
        res = &mut ws_to_tcp => {
            if let Err(err) = res {
                debug!(error = %err, "TUI ws->tcp task panicked");
            }
            tcp_to_ws.abort();
        }
    }

    Ok(())
}

async fn open_ws(config: &TunnelConfig) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>> {
    let mut request = (&config.ws_url).into_client_request().into_diagnostic()?;
    let token_val = HeaderValue::from_str(&config.edge_token)
        .map_err(|err| miette::miette!("invalid edge token header value: {err}"))?;
    request
        .headers_mut()
        .insert("Cf-Access-Token", token_val.clone());
    request
        .headers_mut()
        .insert("Cf-Access-Jwt-Assertion", token_val);
    request.headers_mut().insert(
        "Cookie",
        HeaderValue::from_str(&format!("CF_Authorization={}", config.edge_token))
            .map_err(|err| miette::miette!("invalid edge token cookie value: {err}"))?,
    );

    let (ws_stream, response) = tokio_tungstenite::connect_async(request)
        .await
        .map_err(|err| miette::miette!("WebSocket connect failed: {err}"))?;
    debug!(status = %response.status(), "TUI edge WebSocket connected");
    Ok(ws_stream)
}

async fn copy_tcp_to_ws(
    mut tcp_read: tokio::io::ReadHalf<TcpStream>,
    mut ws_sink: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
) {
    let mut buf = vec![0_u8; 32 * 1024];
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
            Err(err) => {
                debug!(error = %err, "TUI tcp read error");
                let _ = ws_sink.close().await;
                break;
            }
        }
    }
}

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
            Ok(Message::Ping(_) | Message::Pong(_) | Message::Text(_) | Message::Frame(_)) => {}
            Err(err) => {
                debug!(error = %err, "TUI WebSocket read error");
                break;
            }
        }
    }
    let _ = tcp_write.shutdown().await;
}
