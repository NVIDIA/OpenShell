// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SSH tunnel handler for the multiplexed gateway.

use axum::{Router, extract::State, http::Method, response::IntoResponse, routing::any};
use http::StatusCode;
use hyper::Request;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use navigator_core::proto::{Sandbox, SandboxPhase, SshSession};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{info, warn};
use uuid::Uuid;

use crate::ServerState;
use crate::persistence::{ObjectId, ObjectName, ObjectType};

const HEADER_SANDBOX_ID: &str = "x-sandbox-id";
const HEADER_TOKEN: &str = "x-sandbox-token";
const PREFACE_MAGIC: &str = "NSSH1";

pub fn router(state: Arc<ServerState>) -> Router {
    Router::new()
        .route("/connect/ssh", any(ssh_connect))
        .with_state(state)
}

async fn ssh_connect(
    State(state): State<Arc<ServerState>>,
    req: Request<axum::body::Body>,
) -> impl IntoResponse {
    if req.method() != Method::CONNECT {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }

    let sandbox_id = match header_value(req.headers(), HEADER_SANDBOX_ID) {
        Ok(value) => value,
        Err(status) => return status.into_response(),
    };
    let token = match header_value(req.headers(), HEADER_TOKEN) {
        Ok(value) => value,
        Err(status) => return status.into_response(),
    };

    let session = match state.store.get_message::<SshSession>(&token).await {
        Ok(Some(session)) => session,
        Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(err) => {
            warn!(error = %err, "Failed to fetch SSH session");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if session.revoked || session.sandbox_id != sandbox_id {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let sandbox = match state.store.get_message::<Sandbox>(&sandbox_id).await {
        Ok(Some(sandbox)) => sandbox,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            warn!(error = %err, "Failed to fetch sandbox");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if SandboxPhase::try_from(sandbox.phase).ok() != Some(SandboxPhase::Ready) {
        return StatusCode::PRECONDITION_FAILED.into_response();
    }

    let connect_target = if let Some(status) = sandbox.status.as_ref()
        && !status.agent_pod.is_empty()
    {
        match state.sandbox_client.agent_pod_ip(&status.agent_pod).await {
            Ok(Some(ip)) => ConnectTarget::Ip(SocketAddr::new(ip, state.config.sandbox_ssh_port)),
            Ok(None) => return StatusCode::BAD_GATEWAY.into_response(),
            Err(err) => {
                warn!(error = %err, "Failed to resolve agent pod IP");
                return StatusCode::BAD_GATEWAY.into_response();
            }
        }
    } else if !sandbox.name.is_empty() {
        let service_host = format!(
            "{}.{}.svc.cluster.local",
            sandbox.name, state.config.sandbox_namespace
        );
        ConnectTarget::Host(service_host, state.config.sandbox_ssh_port)
    } else {
        return StatusCode::PRECONDITION_FAILED.into_response();
    };
    let handshake_secret = state.config.ssh_handshake_secret.clone();
    let sandbox_id_clone = sandbox_id.clone();

    let upgrade = hyper::upgrade::on(req);
    tokio::spawn(async move {
        match upgrade.await {
            Ok(mut upgraded) => {
                if let Err(err) = handle_tunnel(
                    &mut upgraded,
                    connect_target,
                    &token,
                    &handshake_secret,
                    &sandbox_id_clone,
                )
                .await
                {
                    warn!(error = %err, "SSH tunnel failure");
                }
            }
            Err(err) => {
                warn!(error = %err, "SSH upgrade failed");
            }
        }
    });

    StatusCode::OK.into_response()
}

async fn handle_tunnel(
    upgraded: &mut Upgraded,
    target: ConnectTarget,
    token: &str,
    secret: &str,
    sandbox_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // The sandbox pod may not be network-reachable immediately after the CRD
    // reports Ready (DNS propagation, pod IP assignment, SSH server startup).
    // Retry the TCP connection with exponential backoff.
    let mut upstream = None;
    let mut last_err = None;
    let delays = [
        Duration::from_millis(100),
        Duration::from_millis(250),
        Duration::from_millis(500),
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(10),
        Duration::from_secs(15),
    ];
    let target_desc = match &target {
        ConnectTarget::Ip(addr) => format!("{addr}"),
        ConnectTarget::Host(host, port) => format!("{host}:{port}"),
    };
    info!(sandbox_id = %sandbox_id, target = %target_desc, "SSH tunnel: connecting to sandbox");
    for (attempt, delay) in std::iter::once(&Duration::ZERO)
        .chain(delays.iter())
        .enumerate()
    {
        if !delay.is_zero() {
            info!(sandbox_id = %sandbox_id, attempt = attempt + 1, delay_ms = delay.as_millis() as u64, "SSH tunnel: retrying TCP connect");
            tokio::time::sleep(*delay).await;
        }
        let result = match &target {
            ConnectTarget::Ip(addr) => TcpStream::connect(addr).await,
            ConnectTarget::Host(host, port) => TcpStream::connect((host.as_str(), *port)).await,
        };
        match result {
            Ok(stream) => {
                info!(
                    sandbox_id = %sandbox_id,
                    attempts = attempt + 1,
                    "SSH tunnel: TCP connected to sandbox"
                );
                upstream = Some(stream);
                break;
            }
            Err(err) => {
                info!(sandbox_id = %sandbox_id, attempt = attempt + 1, error = %err, "SSH tunnel: TCP connect failed");
                last_err = Some(err);
            }
        }
    }
    let mut upstream = upstream.ok_or_else(|| {
        let err = last_err.unwrap();
        format!("failed to connect to sandbox after retries: {err}")
    })?;
    upstream.set_nodelay(true)?;
    info!(sandbox_id = %sandbox_id, "SSH tunnel: sending NSSH1 handshake preface");
    let preface = build_preface(token, secret)?;
    upstream.write_all(preface.as_bytes()).await?;

    info!(sandbox_id = %sandbox_id, "SSH tunnel: waiting for handshake response");
    let mut response = String::new();
    read_line(&mut upstream, &mut response).await?;
    info!(sandbox_id = %sandbox_id, response = %response.trim(), "SSH tunnel: handshake response received");
    if response.trim() != "OK" {
        return Err("sandbox handshake rejected".into());
    }

    info!(sandbox_id = %sandbox_id, "SSH tunnel established");
    let mut upgraded = TokioIo::new(upgraded);
    // Discard the result entirely – connection-close errors are expected when
    // the SSH session ends and do not represent a failure worth propagating.
    let _ = tokio::io::copy_bidirectional(&mut upgraded, &mut upstream).await;
    // Gracefully shut down the write-half of the upgraded connection so the
    // client receives a clean EOF instead of a TCP RST.  This gives SSH time
    // to read any remaining protocol data (e.g. exit-status) from its buffer.
    let _ = AsyncWriteExt::shutdown(&mut upgraded).await;
    Ok(())
}

fn header_value(headers: &http::HeaderMap, name: &str) -> Result<String, StatusCode> {
    let value = headers
        .get(name)
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_str()
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .trim()
        .to_string();
    if value.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(value)
}

fn build_preface(
    token: &str,
    secret: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let timestamp = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "time error")?
            .as_secs(),
    )
    .map_err(|_| "time error")?;
    let nonce = Uuid::new_v4().to_string();
    let payload = format!("{token}|{timestamp}|{nonce}");
    let signature = hmac_sha256(secret.as_bytes(), payload.as_bytes());
    Ok(format!(
        "{PREFACE_MAGIC} {token} {timestamp} {nonce} {signature}\n"
    ))
}

async fn read_line(
    stream: &mut TcpStream,
    buf: &mut String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        bytes.push(byte[0]);
        if bytes.len() > 1024 {
            break;
        }
    }
    *buf = String::from_utf8_lossy(&bytes).to_string();
    Ok(())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac key");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    hex::encode(result)
}

impl ObjectType for SshSession {
    fn object_type() -> &'static str {
        "ssh_session"
    }
}

impl ObjectId for SshSession {
    fn object_id(&self) -> &str {
        &self.id
    }
}

impl ObjectName for SshSession {
    fn object_name(&self) -> &str {
        &self.name
    }
}

enum ConnectTarget {
    Ip(SocketAddr),
    Host(String, u16),
}
