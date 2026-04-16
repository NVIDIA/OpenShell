// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Persistent supervisor-to-gateway session.
//!
//! Maintains a long-lived `ConnectSupervisor` bidirectional gRPC stream to the
//! gateway. When the gateway sends `RelayOpen`, the supervisor opens a reverse
//! HTTP CONNECT tunnel back to the gateway and bridges it to the local SSH
//! daemon. The supervisor is a dumb byte bridge — it has no protocol awareness
//! of the SSH or NSSH1 bytes flowing through the tunnel.

use std::time::Duration;

use openshell_core::proto::open_shell_client::OpenShellClient;
use openshell_core::proto::{
    GatewayMessage, SupervisorHeartbeat, SupervisorHello, SupervisorMessage, gateway_message,
    supervisor_message,
};
use tokio::sync::mpsc;
use tonic::transport::Channel;
use tracing::{info, warn};

use crate::grpc_client;

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Spawn the supervisor session task.
///
/// The task runs for the lifetime of the sandbox process, reconnecting with
/// exponential backoff on failures.
pub fn spawn(
    endpoint: String,
    sandbox_id: String,
    ssh_listen_port: u16,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_session_loop(endpoint, sandbox_id, ssh_listen_port))
}

async fn run_session_loop(endpoint: String, sandbox_id: String, ssh_listen_port: u16) {
    let mut backoff = INITIAL_BACKOFF;
    let mut attempt: u64 = 0;

    loop {
        attempt += 1;

        match run_single_session(&endpoint, &sandbox_id, ssh_listen_port).await {
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
    ssh_listen_port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Connect to the gateway.
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
                            &endpoint,
                            ssh_listen_port,
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
    endpoint: &str,
    ssh_listen_port: u16,
    _channel: &Channel,
) {
    match &msg.payload {
        Some(gateway_message::Payload::Heartbeat(_)) => {
            // Gateway heartbeat — nothing to do.
        }
        Some(gateway_message::Payload::RelayOpen(open)) => {
            let channel_id = open.channel_id.clone();
            let endpoint = endpoint.to_string();
            let sandbox_id = sandbox_id.to_string();

            info!(
                sandbox_id = %sandbox_id,
                channel_id = %channel_id,
                "supervisor session: relay open request, spawning bridge"
            );

            tokio::spawn(async move {
                if let Err(e) = handle_relay_open(&channel_id, &endpoint, ssh_listen_port).await {
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

/// Handle a RelayOpen by opening a reverse HTTP CONNECT to the gateway and
/// bridging it to the local SSH daemon.
async fn handle_relay_open(
    channel_id: &str,
    endpoint: &str,
    ssh_listen_port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Build the relay URL from the gateway endpoint.
    // The endpoint is like "https://gateway:8080" or "http://gateway:8080".
    let relay_url = format!("{endpoint}/relay/{channel_id}");

    // Open a reverse HTTP CONNECT to the gateway's relay endpoint.
    let mut relay_stream = open_reverse_connect(&relay_url).await?;

    // Connect to the local SSH daemon on loopback.
    let mut ssh_conn = tokio::net::TcpStream::connect(("127.0.0.1", ssh_listen_port)).await?;

    info!(channel_id = %channel_id, "relay bridge: connected to local SSH daemon, bridging");

    // Bridge the relay stream to the local SSH connection.
    // The gateway sends NSSH1 preface + SSH bytes through the relay.
    // The SSH daemon receives them as if the gateway connected directly.
    let _ = tokio::io::copy_bidirectional(&mut relay_stream, &mut ssh_conn).await;

    Ok(())
}

/// Open an HTTP CONNECT tunnel to the given URL and return the upgraded stream.
///
/// This uses a raw hyper HTTP/1.1 client to send a CONNECT request and upgrade
/// the connection to a raw byte stream.
async fn open_reverse_connect(
    url: &str,
) -> Result<
    hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>,
    Box<dyn std::error::Error + Send + Sync>,
> {
    let uri: http::Uri = url.parse()?;
    let host = uri.host().ok_or("missing host")?;
    let port = uri
        .port_u16()
        .unwrap_or(if uri.scheme_str() == Some("https") {
            443
        } else {
            80
        });
    let authority = format!("{host}:{port}");
    let path = uri.path().to_string();
    let use_tls = uri.scheme_str() == Some("https");

    // Connect TCP.
    let tcp = tokio::net::TcpStream::connect(&authority).await?;
    tcp.set_nodelay(true)?;

    if use_tls {
        // Build TLS connector using the same env-var certs as the gRPC client.
        let tls_stream = connect_tls(tcp, host).await?;
        send_connect_request(tls_stream, &authority, &path).await
    } else {
        send_connect_request(tcp, &authority, &path).await
    }
}

async fn send_connect_request<IO>(
    io: IO,
    authority: &str,
    path: &str,
) -> Result<
    hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>,
    Box<dyn std::error::Error + Send + Sync>,
>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use http::Method;

    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(io)).await?;

    // Spawn the connection driver.
    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            warn!(error = %e, "relay CONNECT connection driver error");
        }
    });

    let req = http::Request::builder()
        .method(Method::CONNECT)
        .uri(path)
        .header(http::header::HOST, authority)
        .body(http_body_util::Empty::<bytes::Bytes>::new())?;

    let resp = sender.send_request(req).await?;

    if resp.status() != http::StatusCode::OK
        && resp.status() != http::StatusCode::SWITCHING_PROTOCOLS
    {
        return Err(format!("relay CONNECT failed: {}", resp.status()).into());
    }

    let upgraded = hyper::upgrade::on(resp).await?;
    Ok(hyper_util::rt::TokioIo::new(upgraded))
}

/// Connect TLS using the same cert env vars as the gRPC client.
async fn connect_tls(
    tcp: tokio::net::TcpStream,
    host: &str,
) -> Result<
    tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    Box<dyn std::error::Error + Send + Sync>,
> {
    use rustls::pki_types::ServerName;
    use std::sync::Arc;

    let ca_path = std::env::var("OPENSHELL_TLS_CA")?;
    let cert_path = std::env::var("OPENSHELL_TLS_CERT")?;
    let key_path = std::env::var("OPENSHELL_TLS_KEY")?;

    let ca_pem = std::fs::read(&ca_path)?;
    let cert_pem = std::fs::read(&cert_path)?;
    let key_pem = std::fs::read(&key_path)?;

    let mut root_store = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_pem.as_slice()) {
        root_store.add(cert?)?;
    }

    let certs: Vec<_> =
        rustls_pemfile::certs(&mut cert_pem.as_slice()).collect::<Result<_, _>>()?;
    let key =
        rustls_pemfile::private_key(&mut key_pem.as_slice())?.ok_or("no private key found")?;

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)?;

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(host.to_string())?;
    let tls_stream = connector.connect(server_name, tcp).await?;

    Ok(tls_stream)
}
