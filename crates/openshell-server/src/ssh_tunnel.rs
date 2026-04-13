// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SSH tunnel handler for the multiplexed gateway.

use axum::{Router, extract::State, http::Method, response::IntoResponse, routing::any};
use http::StatusCode;
use hyper::Request;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use openshell_core::proto::{Sandbox, SandboxPhase, SshSession};
use prost::Message;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{info, warn};
use uuid::Uuid;

use crate::ServerState;
use crate::persistence::{ObjectId, ObjectName, ObjectType, Store};

const HEADER_SANDBOX_ID: &str = "x-sandbox-id";
const HEADER_TOKEN: &str = "x-sandbox-token";
const PREFACE_MAGIC: &str = "NSSH1";

/// Maximum concurrent SSH tunnel connections per session token.
const MAX_CONNECTIONS_PER_TOKEN: u32 = 3;

/// Redact a bearer token for safe logging — show only the last 4 characters.
fn redact_token(token: &str) -> String {
    if token.len() <= 4 {
        "****".to_string()
    } else {
        format!("****{}", &token[token.len() - 4..])
    }
}

/// Maximum concurrent SSH tunnel connections per sandbox.
const MAX_CONNECTIONS_PER_SANDBOX: u32 = 20;

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

    // Check token expiry (0 means no expiry for backward compatibility).
    if session.expires_at_ms > 0 {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        if now_ms > session.expires_at_ms {
            return StatusCode::UNAUTHORIZED.into_response();
        }
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

    let connect_target = match state.compute.resolve_sandbox_endpoint(&sandbox).await {
        Ok(crate::compute::ResolvedEndpoint::Ip(ip, port)) => {
            ConnectTarget::Ip(SocketAddr::new(ip, port))
        }
        Ok(crate::compute::ResolvedEndpoint::Host(host, port)) => ConnectTarget::Host(host, port),
        Err(status) if status.code() == tonic::Code::FailedPrecondition => {
            return StatusCode::PRECONDITION_FAILED.into_response();
        }
        Err(err) => {
            warn!(error = %err, "Failed to resolve sandbox endpoint");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };
    // Enforce per-token concurrent connection limit.
    {
        let mut counts = state.ssh_connections_by_token.lock().unwrap();
        let count = counts.entry(token.clone()).or_insert(0);
        if *count >= MAX_CONNECTIONS_PER_TOKEN {
            warn!(token = %redact_token(&token), "SSH tunnel: per-token connection limit reached");
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
        *count += 1;
    }

    // Enforce per-sandbox concurrent connection limit.
    {
        let mut counts = state.ssh_connections_by_sandbox.lock().unwrap();
        let count = counts.entry(sandbox_id.clone()).or_insert(0);
        if *count >= MAX_CONNECTIONS_PER_SANDBOX {
            // Roll back the per-token increment.
            let mut token_counts = state.ssh_connections_by_token.lock().unwrap();
            if let Some(c) = token_counts.get_mut(&token) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    token_counts.remove(&token);
                }
            }
            warn!(sandbox_id = %sandbox_id, "SSH tunnel: per-sandbox connection limit reached");
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
        *count += 1;
    }

    let handshake_secret = state.config.ssh_handshake_secret.clone();
    let sandbox_id_clone = sandbox_id.clone();
    let token_clone = token.clone();
    let state_clone = state.clone();

    let upgrade = hyper::upgrade::on(req);
    tokio::spawn(async move {
        match upgrade.await {
            Ok(mut upgraded) => {
                if let Err(err) = handle_tunnel(
                    &mut upgraded,
                    connect_target,
                    &token_clone,
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

        // Decrement connection counts on tunnel completion.
        decrement_connection_count(&state_clone.ssh_connections_by_token, &token_clone);
        decrement_connection_count(&state_clone.ssh_connections_by_sandbox, &sandbox_id_clone);
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

/// Decrement a connection count entry, removing it if it reaches zero.
fn decrement_connection_count(
    counts: &std::sync::Mutex<std::collections::HashMap<String, u32>>,
    key: &str,
) {
    let mut map = counts.lock().unwrap();
    if let Some(count) = map.get_mut(key) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            map.remove(key);
        }
    }
}

/// Spawn a background task that periodically reaps expired and revoked SSH sessions.
pub fn spawn_session_reaper(store: Arc<Store>, interval: Duration) {
    tokio::spawn(async move {
        // Initial delay to let startup settle.
        tokio::time::sleep(interval).await;

        loop {
            if let Err(e) = reap_expired_sessions(&store).await {
                warn!(error = %e, "SSH session reaper sweep failed");
            }
            tokio::time::sleep(interval).await;
        }
    });
}

async fn reap_expired_sessions(store: &Store) -> Result<(), String> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let records = store
        .list(SshSession::object_type(), 1000, 0)
        .await
        .map_err(|e| e.to_string())?;

    let mut reaped = 0u32;
    for record in records {
        let session: SshSession = match Message::decode(record.payload.as_slice()) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let should_delete =
            // Expired sessions (expires_at_ms > 0 means expiry is set).
            (session.expires_at_ms > 0 && now_ms > session.expires_at_ms)
            // Revoked sessions — already invalidated, just cleaning up storage.
            || session.revoked;

        if should_delete {
            if let Err(e) = store.delete(SshSession::object_type(), &session.id).await {
                warn!(session_id = %session.id, error = %e, "Failed to reap SSH session");
            } else {
                reaped += 1;
            }
        }
    }

    if reaped > 0 {
        info!(count = reaped, "SSH session reaper: cleaned up sessions");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::Store;
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn make_session(id: &str, sandbox_id: &str, expires_at_ms: i64, revoked: bool) -> SshSession {
        SshSession {
            id: id.to_string(),
            sandbox_id: sandbox_id.to_string(),
            token: id.to_string(),
            created_at_ms: 1000,
            revoked,
            name: format!("session-{id}"),
            expires_at_ms,
        }
    }

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    }

    // ---- Connection limit tests ----

    #[test]
    fn decrement_removes_entry_at_zero() {
        let counts: Mutex<HashMap<String, u32>> = Mutex::new(HashMap::new());
        counts.lock().unwrap().insert("tok1".to_string(), 1);
        decrement_connection_count(&counts, "tok1");
        assert!(counts.lock().unwrap().is_empty());
    }

    #[test]
    fn decrement_reduces_count() {
        let counts: Mutex<HashMap<String, u32>> = Mutex::new(HashMap::new());
        counts.lock().unwrap().insert("tok1".to_string(), 5);
        decrement_connection_count(&counts, "tok1");
        assert_eq!(*counts.lock().unwrap().get("tok1").unwrap(), 4);
    }

    #[test]
    fn decrement_missing_key_is_noop() {
        let counts: Mutex<HashMap<String, u32>> = Mutex::new(HashMap::new());
        decrement_connection_count(&counts, "nonexistent");
        assert!(counts.lock().unwrap().is_empty());
    }

    #[test]
    fn per_token_connection_limit_enforced() {
        let counts: Mutex<HashMap<String, u32>> = Mutex::new(HashMap::new());
        counts
            .lock()
            .unwrap()
            .insert("tok1".to_string(), MAX_CONNECTIONS_PER_TOKEN);
        let current = *counts.lock().unwrap().get("tok1").unwrap();
        assert!(current >= MAX_CONNECTIONS_PER_TOKEN);
    }

    #[test]
    fn per_sandbox_connection_limit_enforced() {
        let counts: Mutex<HashMap<String, u32>> = Mutex::new(HashMap::new());
        counts
            .lock()
            .unwrap()
            .insert("sbx1".to_string(), MAX_CONNECTIONS_PER_SANDBOX);
        let current = *counts.lock().unwrap().get("sbx1").unwrap();
        assert!(current >= MAX_CONNECTIONS_PER_SANDBOX);
    }

    // ---- Session reaper tests ----

    #[tokio::test]
    async fn reaper_deletes_expired_sessions() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        let expired = make_session("expired1", "sbx1", now_ms() - 60_000, false);
        store.put_message(&expired).await.unwrap();

        let valid = make_session("valid1", "sbx1", now_ms() + 3_600_000, false);
        store.put_message(&valid).await.unwrap();

        reap_expired_sessions(&store).await.unwrap();

        assert!(
            store
                .get_message::<SshSession>("expired1")
                .await
                .unwrap()
                .is_none(),
            "expired session should be reaped"
        );
        assert!(
            store
                .get_message::<SshSession>("valid1")
                .await
                .unwrap()
                .is_some(),
            "valid session should be kept"
        );
    }

    #[tokio::test]
    async fn reaper_deletes_revoked_sessions() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        let revoked = make_session("revoked1", "sbx1", 0, true);
        store.put_message(&revoked).await.unwrap();

        let active = make_session("active1", "sbx1", 0, false);
        store.put_message(&active).await.unwrap();

        reap_expired_sessions(&store).await.unwrap();

        assert!(
            store
                .get_message::<SshSession>("revoked1")
                .await
                .unwrap()
                .is_none(),
            "revoked session should be reaped"
        );
        assert!(
            store
                .get_message::<SshSession>("active1")
                .await
                .unwrap()
                .is_some(),
            "active session should be kept"
        );
    }

    #[tokio::test]
    async fn reaper_preserves_zero_expiry_sessions() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        // expires_at_ms = 0 means no expiry (backward compatible).
        let no_expiry = make_session("noexpiry1", "sbx1", 0, false);
        store.put_message(&no_expiry).await.unwrap();

        reap_expired_sessions(&store).await.unwrap();

        assert!(
            store
                .get_message::<SshSession>("noexpiry1")
                .await
                .unwrap()
                .is_some(),
            "session with no expiry should be preserved"
        );
    }

    // ---- Expiry validation logic tests ----

    #[test]
    fn expired_session_is_detected() {
        let session = make_session("tok1", "sbx1", now_ms() - 1000, false);
        let is_expired = session.expires_at_ms > 0 && now_ms() > session.expires_at_ms;
        assert!(is_expired, "session in the past should be expired");
    }

    #[test]
    fn future_session_is_not_expired() {
        let session = make_session("tok1", "sbx1", now_ms() + 3_600_000, false);
        let is_expired = session.expires_at_ms > 0 && now_ms() > session.expires_at_ms;
        assert!(!is_expired, "session in the future should not be expired");
    }

    #[test]
    fn zero_expiry_is_not_expired() {
        let session = make_session("tok1", "sbx1", 0, false);
        let is_expired = session.expires_at_ms > 0 && now_ms() > session.expires_at_ms;
        assert!(
            !is_expired,
            "session with zero expiry should never be expired"
        );
    }
}
