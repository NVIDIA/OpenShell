// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! WebSocket relay embedded in the gateway for MXC `ProcessContainer` sandboxes.
//!
//! When `egress_proxy = true` the `AppContainer` has outbound TCP via the
//! `OpenShell` host CONNECT proxy. The driver binds a relay listener on demand
//! (`start_relay`, e.g. from `ForwardSink::open_dynamic_forward`) and tells
//! the in-sandbox spawner its address over the stdin/stdout control channel;
//! the spawner connects outward to it as a WebSocket CLIENT (Phase A). Host
//! clients connect as raw TCP (Phase B); the relay tunnels their bytes
//! through Phase A so the in-sandbox agent can pipe them directly to the
//! target service. Each relay is per-request and short-lived — bound fresh
//! for each `openshell forward service` call, torn down when that forward
//! ends.
//!
//! ```text
//! host TCP client  ->  relay (gateway, raw TCP accept)
//!                          |  tunnel via Phase A WS
//!                      sandbox agent  ->  local service (openclaw:18889)
//! ```
//!
//! The listener is bound to the host's route-selected IPv4 interface rather
//! than loopback. `AppContainer` fallback does not map its `127.0.0.1` to the
//! host, so a loopback listener is unreachable unless traffic is sent through
//! the CONNECT proxy; that proxy can also capture the bridge's separate
//! sandbox-local target connection. Binding one concrete host interface keeps
//! the target hop on sandbox loopback and lets `allowLocalNetwork` authorize
//! only the host callback. In principle another host or local process could
//! race to connect before the real Phase A/B peer does and
//! hijack or inject traffic into the forward. Both phases are authenticated
//! against a fresh, unguessable per-forward nonce (`ForwardSink::
//! open_dynamic_forward` generates it) instead of trusting connection order:
//!
//!   Phase A (sandbox spawner, WS client) must send `TEXT "AUTH:<hex
//!            nonce>"` as its first message, before anything else is
//!            accepted from that connection -- see openshell-supervisor-
//!            relay's `run_relay_bridge`, which sends this immediately
//!            after connecting.
//!   Phase B (host client, raw TCP -- normally the gateway process itself,
//!            connecting right after `open_dynamic_forward` returns) must
//!            write the raw nonce bytes as the first bytes on the
//!            connection, before any tunneled application data -- see
//!            openshell-server's `ForwardTcp` handler.
//!
//! A connection that fails or times out on this check is closed and the
//! relay keeps waiting for the real peer, rather than treating the first
//! comer as authoritative or tearing the whole relay down (a wrong guess
//! shouldn't be a viable way to deny service to the real caller either).
//!
//! Protocol over Phase A (WS connection from sandbox to relay), after auth:
//!   TEXT  "`SESSION_START`" — relay opened a Phase B TCP connection
//!   BINARY <bytes>        — bytes from Phase B TCP stream
//!   TEXT  "`SESSION_END`"   — Phase B TCP connection closed
//!   WS Close              — relay shutting down (`delete_sandbox` or error)
//!
//! Phase B (host client), after the nonce prefix, is a plain byte stream —
//! no WS handshake — so the client's full byte stream (including any WS
//! upgrade request and frames) is tunneled transparently to the in-sandbox
//! service from that point on.

use crate::control_channel::ControlChannel;
use base64::Engine;
use futures::{SinkExt, StreamExt};
use openshell_core::net::set_tcp_nodelay_best_effort;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_tungstenite::{accept_async, tungstenite::Message};
use tracing::{info, warn};

/// Length in bytes of the per-forward auth nonce (see module docs). Must
/// match `NONCE_LEN` in `driver.rs` (which generates it) and
/// `openshell-supervisor-relay`'s copy (which echoes it back on Phase A) --
/// duplicated rather than shared via a common crate, matching how the rest
/// of this wire protocol (e.g. the "`SESSION_START`"/"`SESSION_END`" literals)
/// is already duplicated across the two sides.
pub const NONCE_LEN: usize = 32;

/// How long to wait for a freshly-accepted connection to present its auth
/// nonce before giving up on it and going back to waiting for the real peer.
/// Generous: this is a local host round-trip, but a slow/malicious
/// connector shouldn't be able to stall the relay for the legitimate peer
/// for long either.
const AUTH_TIMEOUT: Duration = Duration::from_secs(5);

/// Select the concrete host IPv4 address used to reach the machine's default
/// route. UDP `connect` performs route selection without sending a packet, so
/// this does not depend on the probe endpoint being reachable. Binding the
/// relay to that exact interface avoids exposing it on every interface while
/// still making it reachable from an `AppContainer` whose loopback is isolated
/// from the host's loopback.
/// Fixed-time byte comparison so a wrong guess doesn't leak how many
/// leading bytes it got right via response timing. The nonce is one-shot
/// (a fresh relay per forward) so this is defense in depth rather than
/// closing a practically exploitable channel, but it's free.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Hex-encode `bytes` (lowercase, unpadded). `pub` (crate-visible in
/// practice, since `relay` isn't a `pub mod`) so `ForwardSink::
/// open_dynamic_forward` in `driver.rs` can use the exact same encoding to
/// build the "forward" control-channel request's `nonce` field that this
/// module expects back from the sandbox on Phase A.
pub fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Render the first `n` bytes of `data` as a printable-ASCII preview
/// (non-printable bytes shown as `.`), for hop-by-hop diagnostic logging.
/// Not a general-purpose formatter -- just enough to eyeball whether e.g. an
/// HTTP/WS handshake looks intact versus corrupted or empty.
///
/// Not called anywhere: forwarded traffic can carry auth headers, cookies, or
/// other sensitive payload, and this relay's own logs are gateway logs, so no
/// byte preview is ever logged, at any level. Kept only so a future opt-in
/// diagnostic mode has a ready-made (still-redaction-worthy) formatter to
/// start from.
#[allow(dead_code)]
fn byte_preview(data: &[u8]) -> String {
    const MAX: usize = 120;
    let n = data.len().min(MAX);
    let mut s: String = data[..n]
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        })
        .collect();
    if data.len() > MAX {
        s.push_str("...");
    }
    s
}

// ── Public handle ─────────────────────────────────────────────────────────────

/// Owned handle returned by [`start_relay`].  Drop or call [`stop`] to
/// shut down the relay task and release the listener port.
pub struct RelayHandle {
    shutdown_tx: oneshot::Sender<()>,
}

impl RelayHandle {
    pub fn stop(self) {
        let _ = self.shutdown_tx.send(());
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Bind a TCP listener on `bind_addr` and spawn the relay task. The caller
/// communicates the returned address (and `nonce`) to the sandbox directly
/// (over the control channel) — this doesn't touch the filesystem at all.
/// `nonce` must be freshly generated per call (see module docs) — it's what
/// lets this host-interface relay tell the real Phase A/B peers apart from
/// any other local process that might race to connect first.
pub async fn start_relay(
    bind_addr: SocketAddr,
    sandbox_name: String,
    nonce: [u8; NONCE_LEN],
) -> std::io::Result<(RelayHandle, SocketAddr)> {
    let listener = TcpListener::bind(bind_addr).await?;
    let actual = listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    tokio::spawn(relay_task(
        listener,
        sandbox_name.clone(),
        nonce,
        shutdown_rx,
    ));
    info!(sandbox = %sandbox_name, relay = %actual, "MXC relay started");
    Ok((RelayHandle { shutdown_tx }, actual))
}

/// Start a host-loopback listener whose sandbox leg is multiplexed over the
/// inherited stdin/stdout control channel. Unlike [`start_relay`], this path
/// never asks the `AppContainer` to connect back to a host network address.
pub async fn start_control_channel_relay(
    bind_addr: SocketAddr,
    sandbox_name: String,
    nonce: [u8; NONCE_LEN],
    control_channel: Arc<ControlChannel>,
    target_port: u16,
) -> std::io::Result<(RelayHandle, SocketAddr)> {
    let listener = TcpListener::bind(bind_addr).await?;
    let actual = listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    tokio::spawn(control_channel_relay_task(
        listener,
        sandbox_name.clone(),
        nonce,
        control_channel,
        target_port,
        shutdown_rx,
    ));
    info!(sandbox = %sandbox_name, relay = %actual, "MXC control-channel relay started");
    Ok((RelayHandle { shutdown_tx }, actual))
}

async fn control_channel_relay_task(
    listener: TcpListener,
    sandbox_name: String,
    nonce: [u8; NONCE_LEN],
    control_channel: Arc<ControlChannel>,
    target_port: u16,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    loop {
        let mut host_stream = tokio::select! {
            result = listener.accept() => match result {
                Ok((stream, addr)) => {
                    info!(sandbox = %sandbox_name, %addr, "MXC control-channel relay: host client connected");
                    set_tcp_nodelay_best_effort(&stream);
                    stream
                }
                Err(error) => {
                    warn!(sandbox = %sandbox_name, "MXC control-channel relay listener error: {error}");
                    return;
                }
            },
            _ = &mut shutdown_rx => return,
        };

        let mut auth_buf = [0_u8; NONCE_LEN];
        match tokio::time::timeout(AUTH_TIMEOUT, host_stream.read_exact(&mut auth_buf)).await {
            Ok(Ok(_)) if constant_time_eq(&auth_buf, &nonce) => {}
            Ok(Ok(_) | Err(_)) | Err(_) => continue,
        }

        let session_id = encode_hex(&rand::random::<[u8; NONCE_LEN]>());
        let open = control_channel
            .request(
                "forward_open",
                serde_json::json!({"session_id": session_id, "target_port": target_port}),
                Duration::from_secs(10),
            )
            .await;
        if !control_response_ok(&open) {
            warn!(sandbox = %sandbox_name, "MXC control-channel relay: sandbox rejected session open");
            continue;
        }

        let (mut host_read, mut host_write) = host_stream.into_split();
        let mut host_buf = vec![0_u8; 8192];
        let mut host_to_sandbox_bytes = 0_u64;
        let mut sandbox_to_host_bytes = 0_u64;
        let mut shutting_down = false;
        loop {
            tokio::select! {
                result = host_read.read(&mut host_buf) => match result {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let bytes = base64::engine::general_purpose::STANDARD.encode(&host_buf[..n]);
                        let response = control_channel.request(
                            "forward_write",
                            serde_json::json!({"session_id": session_id, "bytes": bytes}),
                            Duration::from_secs(10),
                        ).await;
                        if !control_response_ok(&response) {
                            break;
                        }
                        host_to_sandbox_bytes += n as u64;
                    }
                },
                response = control_channel.request(
                    "forward_read",
                    serde_json::json!({"session_id": session_id}),
                    Duration::from_secs(10),
                ) => {
                    let Ok(response) = response else { break };
                    if response.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
                        break;
                    }
                    let data = response.get("data").unwrap_or(&serde_json::Value::Null);
                    if data.get("eof").and_then(serde_json::Value::as_bool) == Some(true) {
                        break;
                    }
                    let Some(encoded) = data.get("bytes").and_then(serde_json::Value::as_str) else {
                        break;
                    };
                    if !encoded.is_empty() {
                        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
                            break;
                        };
                        if host_write.write_all(&bytes).await.is_err() {
                            break;
                        }
                        sandbox_to_host_bytes += bytes.len() as u64;
                    }
                },
                _ = &mut shutdown_rx => {
                    shutting_down = true;
                    break;
                },
            }
        }
        let _ = control_channel
            .request(
                "forward_close",
                serde_json::json!({"session_id": session_id}),
                Duration::from_secs(5),
            )
            .await;
        if shutting_down {
            return;
        }
        info!(
            sandbox = %sandbox_name,
            host_to_sandbox_bytes,
            sandbox_to_host_bytes,
            "MXC control-channel relay: host client disconnected"
        );
    }
}

fn control_response_ok(
    response: &Result<serde_json::Value, crate::control_channel::ControlChannelError>,
) -> bool {
    matches!(
        response,
        Ok(value) if value.get("ok").and_then(serde_json::Value::as_bool) == Some(true)
    )
}

async fn relay_task(
    listener: TcpListener,
    sandbox_name: String,
    nonce: [u8; NONCE_LEN],
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    let expected_auth = format!("AUTH:{}", encode_hex(&nonce));

    // Phase A: wait for the sandbox agent's outbound WS connection, and
    // require it to prove it's the real peer (see module docs) before
    // trusting anything else from it. A connection that fails or times out
    // on this is closed; the relay keeps waiting rather than accepting the
    // first comer or giving up entirely.
    let mut sandbox_ws = loop {
        tokio::select! {
            result = listener.accept() => match result {
                Ok((stream, addr)) => {
                    // Latency-sensitive request/response tunnel, including on
                    // a same-host interface -- small WS frames can otherwise
                    // stall behind delayed ACK behavior. Best-effort, before
                    // the WS upgrade so it applies to the whole connection.
                    set_tcp_nodelay_best_effort(&stream);
                    match tokio::time::timeout(AUTH_TIMEOUT, accept_async(stream)).await {
                        Ok(Ok(mut ws)) => {
                            match tokio::time::timeout(AUTH_TIMEOUT, ws.next()).await {
                                Ok(Some(Ok(Message::Text(t))))
                                    if constant_time_eq(t.as_bytes(), expected_auth.as_bytes()) =>
                                {
                                    info!(sandbox = %sandbox_name, %addr, "MXC relay: sandbox connected (authenticated)");
                                    break ws;
                                }
                                Ok(Some(Ok(_))) => {
                                    warn!(sandbox = %sandbox_name, %addr,
                                        "MXC relay: sandbox WS auth message did not match; closing and continuing to wait");
                                    let _ = ws.close(None).await;
                                }
                                Ok(_) => {
                                    warn!(sandbox = %sandbox_name, %addr,
                                        "MXC relay: sandbox WS closed/errored before authenticating; continuing to wait");
                                }
                                Err(_) => {
                                    warn!(sandbox = %sandbox_name, %addr,
                                        "MXC relay: sandbox WS auth timed out; closing and continuing to wait");
                                    let _ = ws.close(None).await;
                                }
                            }
                        }
                        Ok(Err(e)) => warn!(sandbox = %sandbox_name, %addr,
                            "MXC relay: sandbox WS handshake failed: {e}"),
                        Err(_) => warn!(sandbox = %sandbox_name, %addr,
                            "MXC relay: sandbox WS handshake timed out; continuing to wait"),
                    }
                }
                Err(e) => {
                    warn!(sandbox = %sandbox_name, "MXC relay: listener error: {e}");
                    return;
                }
            },
            _ = &mut shutdown_rx => {
                info!(sandbox = %sandbox_name, "MXC relay: shutdown before sandbox connected");
                return;
            }
        }
    };

    // Phase B: accept raw TCP host clients one at a time and tunnel their
    // byte stream through the Phase A WS connection.
    loop {
        let mut host_stream = tokio::select! {
            result = listener.accept() => match result {
                Ok((stream, addr)) => {
                    info!(sandbox = %sandbox_name, %addr, "MXC relay: host client connected");
                    // See the matching comment on the Phase A accept above.
                    set_tcp_nodelay_best_effort(&stream);
                    stream
                }
                Err(e) => {
                    warn!(sandbox = %sandbox_name, "MXC relay: listener error: {e}");
                    return;
                }
            },
            _ = &mut shutdown_rx => {
                info!(sandbox = %sandbox_name, "MXC relay: shutdown");
                // Send a proper WS Close frame instead of just dropping the
                // connection -- otherwise the sandbox sees an abrupt TCP
                // reset ("Connection reset without closing handshake")
                // instead of a clean close, even though nothing actually
                // went wrong.
                let _ = sandbox_ws.close(None).await;
                return;
            }
        };

        // Authenticate before treating this as the real host client (see
        // module docs): the raw nonce bytes must arrive first, ahead of any
        // tunneled application data. A mismatch or timeout closes this
        // connection and goes back to waiting for the next accept -- it
        // must never fall through to tunneling a stranger's traffic.
        let mut auth_buf = [0u8; NONCE_LEN];
        match tokio::time::timeout(AUTH_TIMEOUT, host_stream.read_exact(&mut auth_buf)).await {
            Ok(Ok(_)) if constant_time_eq(&auth_buf, &nonce) => {}
            Ok(Ok(_)) => {
                warn!(sandbox = %sandbox_name,
                    "MXC relay: host client auth bytes did not match; closing and continuing to wait");
                continue;
            }
            Ok(Err(e)) => {
                warn!(sandbox = %sandbox_name,
                    "MXC relay: host client closed/errored before authenticating: {e}");
                continue;
            }
            Err(_) => {
                warn!(sandbox = %sandbox_name,
                    "MXC relay: host client auth timed out; closing and continuing to wait");
                continue;
            }
        }

        let (mut host_read, mut host_write) = host_stream.into_split();

        // Notify in-sandbox agent that a new session is starting.
        if sandbox_ws
            .send(Message::Text("SESSION_START".into()))
            .await
            .is_err()
        {
            info!(sandbox = %sandbox_name, "MXC relay: sandbox gone at session start");
            return;
        }

        // Bridge until Phase B or Phase A closes. Byte counters + first-chunk
        // size events exist purely for diagnosing WHERE in the hop chain
        // (host <-> this relay <-> Phase A WS <-> sandbox <-> target) bytes
        // stop flowing, since a silent drop anywhere looks identical from the
        // outside (client just times out) without this instrumentation. No
        // payload content is ever logged -- see the module-level note on
        // `byte_preview`.
        let mut buf = vec![0u8; 8192];
        let mut host_to_sandbox_bytes: u64 = 0;
        let mut sandbox_to_host_bytes: u64 = 0;
        let mut host_to_sandbox_chunks: u64 = 0;
        let mut sandbox_to_host_chunks: u64 = 0;
        let sandbox_gone = loop {
            tokio::select! {
                // Phase B → Phase A: TCP bytes wrapped as WS Binary.
                result = host_read.read(&mut buf) => match result {
                    Ok(0) => break false, // Phase B EOF
                    Ok(n) => {
                        host_to_sandbox_chunks += 1;
                        host_to_sandbox_bytes += n as u64;
                        if host_to_sandbox_chunks == 1 {
                            info!(sandbox = %sandbox_name, bytes = n, "MXC relay: first host->sandbox chunk");
                        }
                        if sandbox_ws
                            .send(Message::Binary(buf[..n].to_vec().into()))
                            .await
                            .is_err()
                        {
                            break true; // Phase A gone
                        }
                    }
                    Err(e) => {
                        warn!(sandbox = %sandbox_name, "MXC relay: host read error: {e}");
                        break false;
                    }
                },
                // Phase A → Phase B: WS Binary bytes written to TCP.
                msg = sandbox_ws.next() => match msg {
                    Some(Ok(Message::Binary(b))) => {
                        sandbox_to_host_chunks += 1;
                        sandbox_to_host_bytes += b.len() as u64;
                        if sandbox_to_host_chunks == 1 {
                            info!(sandbox = %sandbox_name, bytes = b.len(), "MXC relay: first sandbox->host chunk");
                        }
                        if host_write.write_all(&b).await.is_err() {
                            break false; // Phase B gone
                        }
                    }
                    Some(Ok(Message::Text(t))) => {
                        if let Some(reason) = t.strip_prefix("SESSION_FAILED:") {
                            // Sandbox couldn't reach the target port. Close
                            // Phase B now instead of leaving the host client
                            // hanging until its own timeout.
                            warn!(sandbox = %sandbox_name, reason,
                                "MXC relay: sandbox failed to connect to target");
                            break false;
                        } else if t == "SESSION_END" {
                            // Target closed its end (EOF) -- see
                            // openshell-supervisor-relay's matching send on
                            // Ok(0). Close Phase B now instead of leaving
                            // the host client waiting for bytes that will
                            // never arrive until its own timeout.
                            info!(sandbox = %sandbox_name, "MXC relay: target closed its end of the session");
                            break false;
                        }
                        // otherwise ignore (shouldn't arrive from sandbox)
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        info!(sandbox = %sandbox_name, "MXC relay: sandbox WS closed");
                        break true;
                    }
                    Some(Ok(_)) => {} // ping/pong handled by tungstenite
                    Some(Err(e)) => {
                        warn!(sandbox = %sandbox_name, "MXC relay: sandbox read error: {e}");
                        break true;
                    }
                },
                _ = &mut shutdown_rx => {
                    let _ = sandbox_ws.close(None).await;
                    return;
                }
            }
        };

        // Signal session end to the in-sandbox agent (if Phase A still alive).
        if !sandbox_gone {
            let _ = sandbox_ws.send(Message::Text("SESSION_END".into())).await;
        }

        info!(sandbox = %sandbox_name,
            host_to_sandbox_bytes, host_to_sandbox_chunks,
            sandbox_to_host_bytes, sandbox_to_host_chunks,
            "MXC relay: host client disconnected");
        if sandbox_gone {
            info!(sandbox = %sandbox_name, "MXC relay: sandbox gone, stopping relay");
            return;
        }
        // Phase A still alive — wait for the next Phase B client.
    }
}

#[cfg(test)]
mod control_relay_cleanup_tests {
    use super::*;
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::TcpStream;

    /// Exercise the real control-channel writer and relay with a child that
    /// echoes request lines. The test supplies the sandbox's matching replies.
    async fn check_forward_cleanup(interrupt_active: bool) {
        let mut child = tokio::process::Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "while ($null -ne ($line = [Console]::ReadLine())) { [Console]::WriteLine($line) }",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let control = Arc::new(ControlChannel::new(child.stdin.take().unwrap()));
        let pending = control.pending_handle();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let (observed_tx, mut observed_rx) = tokio::sync::mpsc::unbounded_channel();
        let responder = tokio::spawn(async move {
            while let Some(line) = lines.next_line().await.unwrap() {
                let request: serde_json::Value = serde_json::from_str(&line).unwrap();
                let op = request["op"].as_str().unwrap().to_string();
                let response = serde_json::json!({
                    "id": request["id"], "ok": true,
                    "data": {"bytes": "", "eof": false},
                });
                ControlChannel::try_route_response(&pending, &response.to_string()).await;
                observed_tx
                    .send((op.clone(), request["data"]["session_id"].clone()))
                    .unwrap();
                if op == "forward_close" {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let nonce = [7; NONCE_LEN];
        let relay = tokio::spawn(control_channel_relay_task(
            listener,
            "cleanup-test".into(),
            nonce,
            control,
            12345,
            shutdown_rx,
        ));
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&nonce).await.unwrap();
        let opened = tokio::time::timeout(Duration::from_secs(20), observed_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(opened.0, "forward_open");
        let mut shutdown_tx = Some(shutdown_tx);
        if interrupt_active {
            shutdown_tx.take().unwrap().send(()).unwrap();
        } else {
            client.shutdown().await.unwrap();
        }
        let closed_id = tokio::time::timeout(Duration::from_secs(10), async {
            while let Some((op, id)) = observed_rx.recv().await {
                if op == "forward_close" {
                    return id;
                }
            }
            panic!("control channel ended without closing the forward");
        })
        .await
        .expect("active forward must close on shutdown or EOF");
        assert_eq!(closed_id, opened.1);
        if let Some(shutdown_tx) = shutdown_tx {
            shutdown_tx.send(()).unwrap();
        }
        tokio::time::timeout(Duration::from_secs(10), relay)
            .await
            .unwrap()
            .unwrap();
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        responder.await.unwrap();
        child.kill().await.unwrap();
        child.wait().await.unwrap();
    }

    #[tokio::test]
    async fn active_forward_is_closed_before_relay_shutdown_returns() {
        check_forward_cleanup(true).await;
    }

    #[tokio::test]
    async fn ordinary_client_eof_still_closes_the_forward() {
        check_forward_cleanup(false).await;
    }
}

// ── Relay task ────────────────────────────────────────────────────────────────
