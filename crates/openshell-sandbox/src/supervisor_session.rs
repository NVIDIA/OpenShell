// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Persistent supervisor-to-gateway session.
//!
//! Maintains a long-lived `ConnectSupervisor` bidirectional gRPC stream to the
//! gateway. When the gateway sends `RelayOpen`, the supervisor initiates a
//! `RelayStream` gRPC call (a new HTTP/2 stream multiplexed over the same
//! TCP+TLS connection as the control stream) and bridges it to the local SSH
//! daemon. The supervisor is a dumb byte bridge — it has no protocol awareness
//! of the SSH or NSSH1 bytes flowing through.

use std::time::Duration;

use openshell_core::proto::open_shell_client::OpenShellClient;
use openshell_core::proto::{
    GatewayMessage, RelayChunk, SupervisorHeartbeat, SupervisorHello, SupervisorMessage,
    gateway_message, supervisor_message,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tonic::transport::Channel;
use tracing::{info, warn};

use crate::grpc_client;

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Size of chunks read from the local SSH socket when forwarding bytes back
/// to the gateway over the gRPC response stream. 16 KiB matches the default
/// HTTP/2 frame size so each `RelayChunk` fits in one frame.
const RELAY_CHUNK_SIZE: usize = 16 * 1024;

/// Spawn the supervisor session task.
///
/// The task runs for the lifetime of the sandbox process, reconnecting with
/// exponential backoff on failures.
pub fn spawn(
    endpoint: String,
    sandbox_id: String,
    ssh_socket_path: std::path::PathBuf,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_session_loop(endpoint, sandbox_id, ssh_socket_path))
}

async fn run_session_loop(
    endpoint: String,
    sandbox_id: String,
    ssh_socket_path: std::path::PathBuf,
) {
    let mut backoff = INITIAL_BACKOFF;
    let mut attempt: u64 = 0;

    loop {
        attempt += 1;

        match run_single_session(&endpoint, &sandbox_id, &ssh_socket_path).await {
            Ok(()) => {
                info!(sandbox_id = %sandbox_id, "supervisor session ended cleanly");
                break;
            }
            Err(e) => {
                warn!(
                    sandbox_id = %sandbox_id,
                    attempt = attempt,
                    backoff_ms = backoff.as_millis() as u64,
                    error = %e,
                    "supervisor session failed, reconnecting"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

async fn run_single_session(
    endpoint: &str,
    sandbox_id: &str,
    ssh_socket_path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Connect to the gateway. The same `Channel` is used for both the
    // long-lived control stream and all data-plane `RelayStream` calls, so
    // every relay rides the same TCP+TLS+HTTP/2 connection — no new TLS
    // handshake per relay.
    let channel = grpc_client::connect_channel_pub(endpoint)
        .await
        .map_err(|e| format!("connect failed: {e}"))?;
    let mut client = OpenShellClient::new(channel.clone());

    // Create the outbound message stream.
    let (tx, rx) = mpsc::channel::<SupervisorMessage>(64);
    let outbound = tokio_stream::wrappers::ReceiverStream::new(rx);

    // Send hello as the first message.
    let instance_id = uuid::Uuid::new_v4().to_string();
    tx.send(SupervisorMessage {
        payload: Some(supervisor_message::Payload::Hello(SupervisorHello {
            sandbox_id: sandbox_id.to_string(),
            instance_id: instance_id.clone(),
        })),
    })
    .await
    .map_err(|_| "failed to queue hello")?;

    // Open the bidirectional stream.
    let response = client
        .connect_supervisor(outbound)
        .await
        .map_err(|e| format!("connect_supervisor RPC failed: {e}"))?;
    let mut inbound = response.into_inner();

    // Wait for SessionAccepted.
    let accepted = match inbound.message().await? {
        Some(msg) => match msg.payload {
            Some(gateway_message::Payload::SessionAccepted(a)) => a,
            Some(gateway_message::Payload::SessionRejected(r)) => {
                return Err(format!("session rejected: {}", r.reason).into());
            }
            _ => return Err("expected SessionAccepted or SessionRejected".into()),
        },
        None => return Err("stream closed before session accepted".into()),
    };

    let heartbeat_secs = accepted.heartbeat_interval_secs.max(5);
    info!(
        sandbox_id = %sandbox_id,
        session_id = %accepted.session_id,
        instance_id = %instance_id,
        heartbeat_secs = heartbeat_secs,
        "supervisor session established"
    );

    // Main loop: receive gateway messages + send heartbeats.
    let mut heartbeat_interval =
        tokio::time::interval(Duration::from_secs(u64::from(heartbeat_secs)));
    heartbeat_interval.tick().await; // skip immediate tick

    loop {
        tokio::select! {
            msg = inbound.message() => {
                match msg {
                    Ok(Some(msg)) => {
                        handle_gateway_message(
                            &msg,
                            sandbox_id,
                            ssh_socket_path,
                            &channel,
                        ).await;
                    }
                    Ok(None) => {
                        info!(sandbox_id = %sandbox_id, "supervisor session: gateway closed stream");
                        return Ok(());
                    }
                    Err(e) => {
                        return Err(format!("stream error: {e}").into());
                    }
                }
            }
            _ = heartbeat_interval.tick() => {
                let hb = SupervisorMessage {
                    payload: Some(supervisor_message::Payload::Heartbeat(
                        SupervisorHeartbeat {},
                    )),
                };
                if tx.send(hb).await.is_err() {
                    return Err("outbound channel closed".into());
                }
            }
        }
    }
}

async fn handle_gateway_message(
    msg: &GatewayMessage,
    sandbox_id: &str,
    ssh_socket_path: &std::path::Path,
    channel: &Channel,
) {
    match &msg.payload {
        Some(gateway_message::Payload::Heartbeat(_)) => {
            // Gateway heartbeat — nothing to do.
        }
        Some(gateway_message::Payload::RelayOpen(open)) => {
            let channel_id = open.channel_id.clone();
            let sandbox_id = sandbox_id.to_string();
            let channel = channel.clone();
            let ssh_socket_path = ssh_socket_path.to_path_buf();

            info!(
                sandbox_id = %sandbox_id,
                channel_id = %channel_id,
                "supervisor session: relay open request, spawning bridge"
            );

            tokio::spawn(async move {
                if let Err(e) = handle_relay_open(&channel_id, &ssh_socket_path, channel).await {
                    warn!(
                        sandbox_id = %sandbox_id,
                        channel_id = %channel_id,
                        error = %e,
                        "supervisor session: relay bridge failed"
                    );
                }
            });
        }
        Some(gateway_message::Payload::RelayClose(close)) => {
            info!(
                sandbox_id = %sandbox_id,
                channel_id = %close.channel_id,
                reason = %close.reason,
                "supervisor session: relay close from gateway"
            );
        }
        _ => {
            warn!(sandbox_id = %sandbox_id, "supervisor session: unexpected gateway message");
        }
    }
}

/// Handle a `RelayOpen` by initiating a `RelayStream` RPC on the gateway and
/// bridging that stream to the local SSH daemon.
///
/// This opens a new HTTP/2 stream on the existing `Channel` — no new TCP or
/// TLS handshake. The first `RelayChunk` we send identifies the channel via
/// `channel_id`; subsequent chunks carry raw SSH bytes.
async fn handle_relay_open(
    channel_id: &str,
    ssh_socket_path: &std::path::Path,
    channel: Channel,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut client = OpenShellClient::new(channel);

    // Outbound chunks to the gateway.
    let (out_tx, out_rx) = mpsc::channel::<RelayChunk>(16);
    let outbound = tokio_stream::wrappers::ReceiverStream::new(out_rx);

    // First frame: identify the channel. No payload on this frame.
    out_tx
        .send(RelayChunk {
            channel_id: channel_id.to_string(),
            data: Vec::new(),
        })
        .await
        .map_err(|_| "outbound channel closed before init")?;

    // Initiate the RPC. This rides the existing HTTP/2 connection.
    let response = client
        .relay_stream(outbound)
        .await
        .map_err(|e| format!("relay_stream RPC failed: {e}"))?;
    let mut inbound = response.into_inner();

    // Connect to the local SSH daemon on its Unix socket.
    let ssh = tokio::net::UnixStream::connect(ssh_socket_path).await?;
    let (mut ssh_r, mut ssh_w) = ssh.into_split();

    info!(
        channel_id = %channel_id,
        socket = %ssh_socket_path.display(),
        "relay bridge: connected to local SSH daemon"
    );

    // SSH → gRPC (out_tx): read local SSH, forward as `RelayChunk`s.
    let out_tx_writer = out_tx.clone();
    let ssh_to_grpc = tokio::spawn(async move {
        let mut buf = vec![0u8; RELAY_CHUNK_SIZE];
        loop {
            match ssh_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let chunk = RelayChunk {
                        channel_id: String::new(),
                        data: buf[..n].to_vec(),
                    };
                    if out_tx_writer.send(chunk).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // gRPC (inbound) → SSH: drain inbound chunks into the local SSH socket.
    let mut inbound_err: Option<String> = None;
    while let Some(next) = inbound.next().await {
        match next {
            Ok(chunk) => {
                if chunk.data.is_empty() {
                    continue;
                }
                if let Err(e) = ssh_w.write_all(&chunk.data).await {
                    inbound_err = Some(format!("write to ssh failed: {e}"));
                    break;
                }
            }
            Err(e) => {
                inbound_err = Some(format!("relay inbound errored: {e}"));
                break;
            }
        }
    }

    // Half-close the SSH socket's write side so the daemon sees EOF.
    let _ = ssh_w.shutdown().await;

    // Dropping out_tx closes the outbound gRPC stream, letting the gateway
    // observe EOF on its side too.
    drop(out_tx);
    let _ = ssh_to_grpc.await;

    if let Some(e) = inbound_err {
        return Err(e.into());
    }
    Ok(())
}
