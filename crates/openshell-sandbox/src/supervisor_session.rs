// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Persistent supervisor-to-gateway session.
//!
//! Maintains a long-lived `ConnectSupervisor` bidirectional gRPC stream to the
//! gateway. When the gateway sends `RelayOpen`, the supervisor dials the
//! requested local target, initiates a `RelayStream` gRPC call (a new HTTP/2
//! stream multiplexed over the same TCP+TLS connection as the control stream),
//! and bridges bytes. The supervisor is a dumb byte bridge after target
//! selection — it has no protocol awareness of the bytes flowing through.

use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::os::fd::RawFd;
use std::time::Duration;

use openshell_core::proto::open_shell_client::OpenShellClient;
use openshell_core::proto::{
    GatewayMessage, RelayFrame, RelayInit, RelayOpen, RelayOpenResult, SupervisorHeartbeat,
    SupervisorHello, SupervisorMessage, TcpRelayTarget, gateway_message, relay_open,
    supervisor_message,
};
use openshell_ocsf::{
    ActivityId, ConnectionInfo, Endpoint, NetworkActivityBuilder, OcsfEvent, SandboxContext,
    SeverityId, StatusId, ocsf_emit,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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

fn relay_target_endpoint(open: &RelayOpen) -> Option<Endpoint> {
    let relay_open::Target::Tcp(target) = open.target.as_ref()? else {
        return None;
    };
    let host = target.host.trim();
    let port = u16::try_from(target.port).ok()?;
    host.parse::<IpAddr>().map_or_else(
        |_| Some(Endpoint::from_domain(host, port)),
        |ip| Some(Endpoint::from_ip(ip, port)),
    )
}

fn relay_target_kind(open: &RelayOpen) -> &'static str {
    match open.target.as_ref() {
        Some(relay_open::Target::Tcp(_)) => "tcp relay",
        Some(relay_open::Target::Ssh(_)) | None => "ssh relay",
    }
}

fn relay_target_message(
    open: &RelayOpen,
    state: &str,
    ssh_socket_path: &std::path::Path,
) -> String {
    let target = match open.target.as_ref() {
        Some(relay_open::Target::Tcp(target)) => {
            format!("{}:{}", target.host.trim(), target.port)
        }
        Some(relay_open::Target::Ssh(_)) | None => {
            format!("unix:{}", ssh_socket_path.display())
        }
    };

    format!(
        "{} {state} (channel_id={}, target={target})",
        relay_target_kind(open),
        open.channel_id
    )
}

fn relay_open_event(
    ctx: &SandboxContext,
    open: &RelayOpen,
    ssh_socket_path: &std::path::Path,
) -> OcsfEvent {
    let mut builder = NetworkActivityBuilder::new(ctx)
        .activity(ActivityId::Open)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .message(relay_target_message(open, "open", ssh_socket_path));
    if let Some(endpoint) = relay_target_endpoint(open) {
        builder = builder
            .dst_endpoint(endpoint)
            .connection_info(ConnectionInfo::new("tcp"));
    }
    builder.build()
}

fn relay_closed_event(
    ctx: &SandboxContext,
    open: &RelayOpen,
    ssh_socket_path: &std::path::Path,
) -> OcsfEvent {
    let mut builder = NetworkActivityBuilder::new(ctx)
        .activity(ActivityId::Close)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .message(relay_target_message(open, "closed", ssh_socket_path));
    if let Some(endpoint) = relay_target_endpoint(open) {
        builder = builder
            .dst_endpoint(endpoint)
            .connection_info(ConnectionInfo::new("tcp"));
    }
    builder.build()
}

fn relay_failed_event(
    ctx: &SandboxContext,
    open: &RelayOpen,
    ssh_socket_path: &std::path::Path,
    error: &str,
) -> OcsfEvent {
    let mut builder = NetworkActivityBuilder::new(ctx)
        .activity(ActivityId::Fail)
        .severity(SeverityId::Low)
        .status(StatusId::Failure)
        .message(format!(
            "{}: {error}",
            relay_target_message(open, "bridge failed", ssh_socket_path)
        ));
    if let Some(endpoint) = relay_target_endpoint(open) {
        builder = builder
            .dst_endpoint(endpoint)
            .connection_info(ConnectionInfo::new("tcp"));
    }
    builder.build()
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

trait TargetStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> TargetStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

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
    netns_fd: Option<i32>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_session_loop(
        endpoint,
        sandbox_id,
        ssh_socket_path,
        netns_fd,
    ))
}

async fn run_session_loop(
    endpoint: String,
    sandbox_id: String,
    ssh_socket_path: std::path::PathBuf,
    netns_fd: Option<i32>,
) {
    let mut backoff = INITIAL_BACKOFF;
    let mut attempt: u64 = 0;

    loop {
        attempt += 1;

        match run_single_session(&endpoint, &sandbox_id, &ssh_socket_path, netns_fd).await {
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
    netns_fd: Option<i32>,
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
                    netns_fd,
                    &channel,
                    &tx,
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
    netns_fd: Option<i32>,
    channel: &Channel,
    tx: &mpsc::Sender<SupervisorMessage>,
) {
    match &msg.payload {
        Some(gateway_message::Payload::Heartbeat(_)) => {
            // Gateway heartbeat — nothing to do.
        }
        Some(gateway_message::Payload::RelayOpen(open)) => {
            let channel_id = open.channel_id.clone();
            let relay_open = open.clone();
            let sandbox_id = sandbox_id.to_string();
            let channel = channel.clone();
            let ssh_socket_path = ssh_socket_path.to_path_buf();
            let tx = tx.clone();

            let event = relay_open_event(crate::ocsf_ctx(), &relay_open, &ssh_socket_path);
            ocsf_emit!(event);

            tokio::spawn(async move {
                let event_open = relay_open.clone();
                match handle_relay_open(relay_open, &ssh_socket_path, netns_fd, channel, tx).await {
                    Ok(()) => {
                        let event =
                            relay_closed_event(crate::ocsf_ctx(), &event_open, &ssh_socket_path);
                        ocsf_emit!(event);
                    }
                    Err(e) => {
                        let event = relay_failed_event(
                            crate::ocsf_ctx(),
                            &event_open,
                            &ssh_socket_path,
                            &e.to_string(),
                        );
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
    relay_open: RelayOpen,
    ssh_socket_path: &std::path::Path,
    netns_fd: Option<i32>,
    channel: Channel,
    tx: mpsc::Sender<SupervisorMessage>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let channel_id = relay_open.channel_id.clone();
    let target = match open_target(&relay_open, ssh_socket_path, netns_fd).await {
        Ok(target) => target,
        Err(err) => {
            send_relay_open_result(&tx, &channel_id, false, err.to_string()).await;
            return Err(err);
        }
    };

    send_relay_open_result(&tx, &channel_id, true, String::new()).await;

    let mut client = OpenShellClient::new(channel);

    // Outbound chunks to the gateway.
    let (out_tx, out_rx) = mpsc::channel::<RelayFrame>(16);
    let outbound = tokio_stream::wrappers::ReceiverStream::new(out_rx);

    // First frame: identify the channel.
    out_tx
        .send(RelayFrame {
            payload: Some(openshell_core::proto::relay_frame::Payload::Init(
                RelayInit {
                    channel_id: channel_id.clone(),
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
    let (mut target_r, mut target_w) = tokio::io::split(target);

    debug!(
        channel_id = %channel_id,
        "relay bridge: connected to local target"
    );

    // Target → gRPC (out_tx): read local target, forward as `RelayFrame::data`.
    let out_tx_writer = out_tx.clone();
    let target_to_grpc = tokio::spawn(async move {
        let mut buf = vec![0u8; RELAY_CHUNK_SIZE];
        loop {
            match target_r.read(&mut buf).await {
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

    // gRPC (inbound) → target: drain inbound chunks into the local target socket.
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
                if let Err(e) = target_w.write_all(&data).await {
                    inbound_err = Some(format!("write to target failed: {e}"));
                    break;
                }
            }
            Err(e) => {
                inbound_err = Some(format!("relay inbound errored: {e}"));
                break;
            }
        }
    }

    // Half-close the target socket's write side so the service sees EOF.
    let _ = target_w.shutdown().await;

    // Dropping out_tx closes the outbound gRPC stream, letting the gateway
    // observe EOF on its side too.
    drop(out_tx);
    let _ = target_to_grpc.await;

    if let Some(e) = inbound_err {
        return Err(e.into());
    }
    Ok(())
}

async fn send_relay_open_result(
    tx: &mpsc::Sender<SupervisorMessage>,
    channel_id: &str,
    success: bool,
    error: String,
) {
    let _ = tx
        .send(SupervisorMessage {
            payload: Some(supervisor_message::Payload::RelayOpenResult(
                RelayOpenResult {
                    channel_id: channel_id.to_string(),
                    success,
                    error,
                },
            )),
        })
        .await;
}

async fn open_target(
    relay_open: &RelayOpen,
    ssh_socket_path: &std::path::Path,
    netns_fd: Option<i32>,
) -> Result<Box<dyn TargetStream>, Box<dyn std::error::Error + Send + Sync>> {
    match relay_open.target.as_ref() {
        Some(relay_open::Target::Tcp(target)) => open_tcp_target(target, netns_fd).await,
        Some(relay_open::Target::Ssh(_)) | None => {
            let stream = tokio::net::UnixStream::connect(ssh_socket_path).await?;
            Ok(Box::new(stream))
        }
    }
}

async fn open_tcp_target(
    target: &TcpRelayTarget,
    netns_fd: Option<i32>,
) -> Result<Box<dyn TargetStream>, Box<dyn std::error::Error + Send + Sync>> {
    let host = normalize_tcp_target_host(target)?;
    let port = u16::try_from(target.port).map_err(|_| "tcp target port must fit in u16")?;
    let stream = connect_tcp_target(host, port, netns_fd).await?;
    Ok(Box::new(stream))
}

#[cfg(target_os = "linux")]
async fn connect_tcp_target(
    host: String,
    port: u16,
    netns_fd: Option<RawFd>,
) -> Result<tokio::net::TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(fd) = netns_fd {
        let (tx, rx) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let result = (|| -> std::io::Result<std::net::TcpStream> {
                #[allow(unsafe_code)]
                let rc = unsafe { libc::setns(fd, libc::CLONE_NEWNET) };
                if rc != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                std::net::TcpStream::connect((host.as_str(), port))
            })();
            let _ = tx.send(result);
        });

        let stream = rx
            .await
            .map_err(|_| "netns tcp connect thread panicked")??;
        stream.set_nonblocking(true)?;
        return Ok(tokio::net::TcpStream::from_std(stream)?);
    }

    Ok(tokio::net::TcpStream::connect((host.as_str(), port)).await?)
}

#[cfg(not(target_os = "linux"))]
async fn connect_tcp_target(
    host: String,
    port: u16,
    _netns_fd: Option<i32>,
) -> Result<tokio::net::TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    Ok(tokio::net::TcpStream::connect((host.as_str(), port)).await?)
}

#[cfg(test)]
fn validate_tcp_target(target: &TcpRelayTarget) -> Result<(), String> {
    normalize_tcp_target_host(target).map(|_| ())
}

fn normalize_tcp_target_host(target: &TcpRelayTarget) -> Result<String, String> {
    if target.port == 0 || target.port > u32::from(u16::MAX) {
        return Err("tcp target port must be between 1 and 65535".to_string());
    }

    let host = target.host.trim();
    if host.is_empty() {
        return Err("tcp target host is required".to_string());
    }
    if host.eq_ignore_ascii_case("localhost") {
        return Ok("127.0.0.1".to_string());
    }

    let ip: IpAddr = host
        .parse()
        .map_err(|_| "tcp target host must be loopback".to_string())?;
    if ip.is_loopback() {
        Ok(ip.to_string())
    } else {
        Err("tcp target host must be loopback".to_string())
    }
}

#[cfg(test)]
mod target_tests {
    use super::*;

    fn tcp(host: &str, port: u32) -> TcpRelayTarget {
        TcpRelayTarget {
            host: host.to_string(),
            port,
        }
    }

    #[test]
    fn tcp_target_allows_loopback_hosts() {
        validate_tcp_target(&tcp("127.0.0.1", 8080)).expect("ipv4 loopback");
        validate_tcp_target(&tcp("::1", 8080)).expect("ipv6 loopback");
        validate_tcp_target(&tcp("localhost", 8080)).expect("localhost");
    }

    #[test]
    fn tcp_target_normalizes_localhost_before_dialing() {
        assert_eq!(
            normalize_tcp_target_host(&tcp("localhost", 8080)).expect("localhost"),
            "127.0.0.1"
        );
        assert_eq!(
            normalize_tcp_target_host(&tcp("LOCALHOST", 8080)).expect("localhost"),
            "127.0.0.1"
        );
    }

    #[test]
    fn tcp_target_rejects_non_loopback_hosts() {
        let err = validate_tcp_target(&tcp("10.0.0.1", 8080)).expect_err("private ip rejected");
        assert_eq!(err, "tcp target host must be loopback");

        let err = validate_tcp_target(&tcp("example.com", 8080)).expect_err("hostname rejected");
        assert_eq!(err, "tcp target host must be loopback");
    }

    #[test]
    fn tcp_target_rejects_invalid_ports() {
        let err = validate_tcp_target(&tcp("127.0.0.1", 0)).expect_err("zero rejected");
        assert_eq!(err, "tcp target port must be between 1 and 65535");

        let err = validate_tcp_target(&tcp("127.0.0.1", 70000)).expect_err("too large rejected");
        assert_eq!(err, "tcp target port must be between 1 and 65535");
    }
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

    fn ssh_relay_open(channel_id: &str) -> RelayOpen {
        RelayOpen {
            channel_id: channel_id.to_string(),
            target: Some(relay_open::Target::Ssh(
                openshell_core::proto::SshRelayTarget::default(),
            )),
            service_id: String::new(),
        }
    }

    fn tcp_relay_open(channel_id: &str, host: &str, port: u32) -> RelayOpen {
        RelayOpen {
            channel_id: channel_id.to_string(),
            target: Some(relay_open::Target::Tcp(TcpRelayTarget {
                host: host.to_string(),
                port,
            })),
            service_id: String::new(),
        }
    }

    fn ssh_socket_path() -> &'static std::path::Path {
        std::path::Path::new("/run/openshell/ssh.sock")
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
        let event = relay_open_event(&ctx(), &ssh_relay_open("ch-42"), ssh_socket_path());
        let na = network_activity(&event);
        assert_eq!(na.base.activity_id, ActivityId::Open.as_u8());
        assert_eq!(na.base.severity, SeverityId::Informational);
        let msg = na.base.message.as_deref().unwrap_or_default();
        assert!(msg.contains("ch-42"), "message: {msg}");
        assert!(
            msg.contains("target=unix:/run/openshell/ssh.sock"),
            "message: {msg}"
        );
    }

    #[test]
    fn tcp_relay_open_emits_target_endpoint() {
        let event = relay_open_event(
            &ctx(),
            &tcp_relay_open("ch-42", "127.0.0.1", 8765),
            ssh_socket_path(),
        );
        let na = network_activity(&event);
        assert_eq!(na.base.activity_id, ActivityId::Open.as_u8());
        assert_eq!(
            na.dst_endpoint.as_ref().and_then(|e| e.ip.as_deref()),
            Some("127.0.0.1")
        );
        assert_eq!(na.dst_endpoint.as_ref().and_then(|e| e.port), Some(8765));
        assert_eq!(
            na.connection_info
                .as_ref()
                .map(|c| c.protocol_name.as_str()),
            Some("tcp")
        );
    }

    #[test]
    fn relay_closed_emits_network_close_success() {
        let event = relay_closed_event(&ctx(), &ssh_relay_open("ch-42"), ssh_socket_path());
        let na = network_activity(&event);
        assert_eq!(na.base.activity_id, ActivityId::Close.as_u8());
        assert_eq!(na.base.status, Some(StatusId::Success));
    }

    #[test]
    fn relay_failed_emits_network_fail_low() {
        let event = relay_failed_event(
            &ctx(),
            &ssh_relay_open("ch-42"),
            ssh_socket_path(),
            "write to ssh failed",
        );
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
