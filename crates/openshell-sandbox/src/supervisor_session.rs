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
    GatewayMessage, RelayFrame, RelayInit, SupervisorHeartbeat, SupervisorHello, SupervisorMessage,
    gateway_message, supervisor_message,
};
use openshell_ocsf::{
    ActivityId, Endpoint, NetworkActivityBuilder, OcsfEvent, SandboxContext, SeverityId, StatusId,
    ocsf_emit,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tonic::transport::Channel;
use tracing::{debug, warn};

use crate::grpc_client;

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Parse a gRPC endpoint URI into an OCSF `Endpoint` (host + port). Falls back
/// to treating the whole string as a domain if parsing fails.
fn ocsf_gateway_endpoint(endpoint: &str) -> Endpoint {
    let without_scheme = endpoint
        .split_once("://")
        .map_or(endpoint, |(_, rest)| rest);
    let host_and_port = without_scheme.split('/').next().unwrap_or(without_scheme);
    if let Some((host, port)) = host_and_port.rsplit_once(':')
        && let Ok(port) = port.parse::<u16>()
    {
        return Endpoint::from_domain(host, port);
    }
    Endpoint::from_domain(host_and_port, 0)
}

fn session_established_event(
    ctx: &SandboxContext,
    endpoint: &str,
    session_id: &str,
    heartbeat_secs: u32,
) -> OcsfEvent {
    NetworkActivityBuilder::new(ctx)
        .activity(ActivityId::Open)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .dst_endpoint(ocsf_gateway_endpoint(endpoint))
        .message(format!(
            "supervisor session established (session_id={session_id}, heartbeat_secs={heartbeat_secs})"
        ))
        .build()
}

fn session_closed_event(ctx: &SandboxContext, endpoint: &str, sandbox_id: &str) -> OcsfEvent {
    NetworkActivityBuilder::new(ctx)
        .activity(ActivityId::Close)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .dst_endpoint(ocsf_gateway_endpoint(endpoint))
        .message(format!("supervisor session ended cleanly ({sandbox_id})"))
        .build()
}

fn session_failed_event(
    ctx: &SandboxContext,
    endpoint: &str,
    attempt: u64,
    error: &str,
) -> OcsfEvent {
    NetworkActivityBuilder::new(ctx)
        .activity(ActivityId::Fail)
        .severity(SeverityId::Low)
        .status(StatusId::Failure)
        .dst_endpoint(ocsf_gateway_endpoint(endpoint))
        .message(format!(
            "supervisor session failed, reconnecting (attempt {attempt}): {error}"
        ))
        .build()
}

fn relay_open_event(ctx: &SandboxContext, channel_id: &str) -> OcsfEvent {
    NetworkActivityBuilder::new(ctx)
        .activity(ActivityId::Open)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .message(format!("relay open (channel_id={channel_id})"))
        .build()
}

fn relay_closed_event(ctx: &SandboxContext, channel_id: &str) -> OcsfEvent {
    NetworkActivityBuilder::new(ctx)
        .activity(ActivityId::Close)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .message(format!("relay closed (channel_id={channel_id})"))
        .build()
}

fn relay_failed_event(ctx: &SandboxContext, channel_id: &str, error: &str) -> OcsfEvent {
    NetworkActivityBuilder::new(ctx)
        .activity(ActivityId::Fail)
        .severity(SeverityId::Low)
        .status(StatusId::Failure)
        .message(format!(
            "relay bridge failed (channel_id={channel_id}): {error}"
        ))
        .build()
}

fn relay_close_from_gateway_event(
    ctx: &SandboxContext,
    channel_id: &str,
    reason: &str,
) -> OcsfEvent {
    NetworkActivityBuilder::new(ctx)
        .activity(ActivityId::Close)
        .severity(SeverityId::Informational)
        .message(format!(
            "relay close from gateway (channel_id={channel_id}, reason={reason})"
        ))
        .build()
}

/// Size of chunks read from the local SSH socket when forwarding bytes back
/// to the gateway over the gRPC response stream. 16 KiB matches the default
/// HTTP/2 frame size so each `RelayFrame::data` fits in one frame.
const RELAY_CHUNK_SIZE: usize = 16 * 1024;

fn map_stream_message<T>(
    message: Result<Option<T>, tonic::Status>,
    eof_error: &'static str,
) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
    match message {
        Ok(Some(msg)) => Ok(msg),
        Ok(None) => Err(eof_error.into()),
        Err(e) => Err(format!("stream error: {e}").into()),
    }
}

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
                let event = session_closed_event(crate::ocsf_ctx(), &endpoint, &sandbox_id);
                ocsf_emit!(event);
                break;
            }
            Err(e) => {
                let event =
                    session_failed_event(crate::ocsf_ctx(), &endpoint, attempt, &e.to_string());
                ocsf_emit!(event);
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
    let accepted = match map_stream_message(
        inbound.message().await,
        "stream closed before session accepted",
    )?
    .payload
    {
        Some(gateway_message::Payload::SessionAccepted(a)) => a,
        Some(gateway_message::Payload::SessionRejected(r)) => {
            return Err(format!("session rejected: {}", r.reason).into());
        }
        _ => return Err("expected SessionAccepted or SessionRejected".into()),
    };

    let heartbeat_secs = accepted.heartbeat_interval_secs.max(5);
    let event = session_established_event(
        crate::ocsf_ctx(),
        endpoint,
        &accepted.session_id,
        heartbeat_secs,
    );
    ocsf_emit!(event);

    // Main loop: receive gateway messages + send heartbeats.
    let mut heartbeat_interval =
        tokio::time::interval(Duration::from_secs(u64::from(heartbeat_secs)));
    heartbeat_interval.tick().await; // skip immediate tick

    loop {
        tokio::select! {
            msg = inbound.message() => {
                let msg = map_stream_message(msg, "gateway closed stream")?;
                handle_gateway_message(
                    &msg,
                    sandbox_id,
                    ssh_socket_path,
                    &channel,
                );
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

fn handle_gateway_message(
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

            let event = relay_open_event(crate::ocsf_ctx(), &channel_id);
            ocsf_emit!(event);

            tokio::spawn(async move {
                match handle_relay_open(&channel_id, &ssh_socket_path, channel).await {
                    Ok(()) => {
                        let event = relay_closed_event(crate::ocsf_ctx(), &channel_id);
                        ocsf_emit!(event);
                    }
                    Err(e) => {
                        let event =
                            relay_failed_event(crate::ocsf_ctx(), &channel_id, &e.to_string());
                        ocsf_emit!(event);
                        warn!(
                            sandbox_id = %sandbox_id,
                            channel_id = %channel_id,
                            error = %e,
                            "supervisor session: relay bridge failed"
                        );
                    }
                }
            });
        }
        Some(gateway_message::Payload::RelayClose(close)) => {
            let event =
                relay_close_from_gateway_event(crate::ocsf_ctx(), &close.channel_id, &close.reason);
            ocsf_emit!(event);
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
/// TLS handshake. The first `RelayFrame` we send is a `RelayInit`; subsequent
/// frames carry raw SSH bytes in `data`.
async fn handle_relay_open(
    channel_id: &str,
    ssh_socket_path: &std::path::Path,
    channel: Channel,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut client = OpenShellClient::new(channel);

    // Outbound chunks to the gateway.
    let (out_tx, out_rx) = mpsc::channel::<RelayFrame>(16);
    let outbound = tokio_stream::wrappers::ReceiverStream::new(out_rx);

    // First frame: identify the channel.
    out_tx
        .send(RelayFrame {
            payload: Some(openshell_core::proto::relay_frame::Payload::Init(
                RelayInit {
                    channel_id: channel_id.to_string(),
                },
            )),
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

    debug!(
        channel_id = %channel_id,
        socket = %ssh_socket_path.display(),
        "relay bridge: connected to local SSH daemon"
    );

    // SSH → gRPC (out_tx): read local SSH, forward as `RelayFrame::data`.
    let out_tx_writer = out_tx.clone();
    let ssh_to_grpc = tokio::spawn(async move {
        let mut buf = vec![0u8; RELAY_CHUNK_SIZE];
        loop {
            match ssh_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let chunk = RelayFrame {
                        payload: Some(openshell_core::proto::relay_frame::Payload::Data(
                            buf[..n].to_vec(),
                        )),
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
            Ok(frame) => {
                let Some(openshell_core::proto::relay_frame::Payload::Data(data)) = frame.payload
                else {
                    inbound_err = Some("relay inbound received non-data frame".to_string());
                    break;
                };
                if data.is_empty() {
                    continue;
                }
                if let Err(e) = ssh_w.write_all(&data).await {
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

#[cfg(test)]
mod ocsf_event_tests {
    use super::*;

    fn ctx() -> SandboxContext {
        SandboxContext {
            sandbox_id: "sbx-1".into(),
            sandbox_name: "sandbox".into(),
            container_image: "img".into(),
            hostname: "host".into(),
            product_version: "0.0.1".into(),
            proxy_ip: "127.0.0.1".parse().unwrap(),
            proxy_port: 3128,
        }
    }

    #[test]
    fn gateway_endpoint_parses_https_with_port() {
        let e = ocsf_gateway_endpoint("https://gateway.openshell:8443");
        assert_eq!(e.domain.as_deref(), Some("gateway.openshell"));
        assert_eq!(e.port, Some(8443));
    }

    #[test]
    fn gateway_endpoint_parses_http_with_port_and_path() {
        let e = ocsf_gateway_endpoint("http://gw:7000/grpc");
        assert_eq!(e.domain.as_deref(), Some("gw"));
        assert_eq!(e.port, Some(7000));
    }

    #[test]
    fn gateway_endpoint_falls_back_without_port() {
        let e = ocsf_gateway_endpoint("gateway.openshell");
        assert_eq!(e.domain.as_deref(), Some("gateway.openshell"));
        assert_eq!(e.port, Some(0));
    }

    fn network_activity(event: &OcsfEvent) -> &openshell_ocsf::NetworkActivityEvent {
        match event {
            OcsfEvent::NetworkActivity(n) => n,
            other => panic!("expected NetworkActivity, got {other:?}"),
        }
    }

    #[test]
    fn session_established_emits_network_open_success() {
        let event = session_established_event(&ctx(), "https://gw:443", "sess-1", 30);
        let na = network_activity(&event);
        assert_eq!(na.base.activity_id, ActivityId::Open.as_u8());
        assert_eq!(na.base.severity, SeverityId::Informational);
        assert_eq!(na.base.status, Some(StatusId::Success));
        assert_eq!(
            na.dst_endpoint.as_ref().and_then(|e| e.domain.as_deref()),
            Some("gw")
        );
        let msg = na.base.message.as_deref().unwrap_or_default();
        assert!(msg.contains("sess-1"), "message missing session_id: {msg}");
        assert!(msg.contains("heartbeat_secs=30"), "message: {msg}");
    }

    #[test]
    fn session_closed_emits_network_close_success() {
        let event = session_closed_event(&ctx(), "https://gw:443", "sbx-1");
        let na = network_activity(&event);
        assert_eq!(na.base.activity_id, ActivityId::Close.as_u8());
        assert_eq!(na.base.severity, SeverityId::Informational);
        assert_eq!(na.base.status, Some(StatusId::Success));
    }

    #[test]
    fn session_failed_emits_network_fail_low() {
        let event = session_failed_event(&ctx(), "https://gw:443", 3, "connect refused");
        let na = network_activity(&event);
        assert_eq!(na.base.activity_id, ActivityId::Fail.as_u8());
        assert_eq!(na.base.severity, SeverityId::Low);
        assert_eq!(na.base.status, Some(StatusId::Failure));
        let msg = na.base.message.as_deref().unwrap_or_default();
        assert!(msg.contains("attempt 3"), "message: {msg}");
        assert!(msg.contains("connect refused"), "message: {msg}");
    }

    #[test]
    fn relay_open_emits_network_open_success() {
        let event = relay_open_event(&ctx(), "ch-42");
        let na = network_activity(&event);
        assert_eq!(na.base.activity_id, ActivityId::Open.as_u8());
        assert_eq!(na.base.severity, SeverityId::Informational);
        assert!(
            na.base
                .message
                .as_deref()
                .unwrap_or_default()
                .contains("ch-42")
        );
    }

    #[test]
    fn relay_closed_emits_network_close_success() {
        let event = relay_closed_event(&ctx(), "ch-42");
        let na = network_activity(&event);
        assert_eq!(na.base.activity_id, ActivityId::Close.as_u8());
        assert_eq!(na.base.status, Some(StatusId::Success));
    }

    #[test]
    fn relay_failed_emits_network_fail_low() {
        let event = relay_failed_event(&ctx(), "ch-42", "write to ssh failed");
        let na = network_activity(&event);
        assert_eq!(na.base.activity_id, ActivityId::Fail.as_u8());
        assert_eq!(na.base.severity, SeverityId::Low);
        assert_eq!(na.base.status, Some(StatusId::Failure));
        let msg = na.base.message.as_deref().unwrap_or_default();
        assert!(msg.contains("ch-42"), "message: {msg}");
        assert!(msg.contains("write to ssh failed"), "message: {msg}");
    }

    #[test]
    fn relay_close_from_gateway_is_network_close_informational() {
        let event = relay_close_from_gateway_event(&ctx(), "ch-42", "sandbox deleted");
        let na = network_activity(&event);
        assert_eq!(na.base.activity_id, ActivityId::Close.as_u8());
        assert_eq!(na.base.severity, SeverityId::Informational);
        let msg = na.base.message.as_deref().unwrap_or_default();
        assert!(msg.contains("sandbox deleted"), "message: {msg}");
    }

    #[test]
    fn map_stream_message_treats_eof_as_reconnectable_error() {
        let err = map_stream_message::<SupervisorMessage>(Ok(None), "gateway closed stream")
            .expect_err("eof should force reconnect");
        assert_eq!(err.to_string(), "gateway closed stream");
    }
}
