// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Version-locked boundary bootstrap over a launch-pinned TLS channel.
//! The supervisor stages one immutable launch; only its bootstrap JWT may fetch it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use openshell_core::jwt::{
    SessionJwtVerifier, SessionTokenProfile, SessionVerificationKey, SystemJwtClock,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::boundary_protocol::BoundaryConfig;

pub const PORT: u16 = 5502;
pub const SERVER_FILE: &str = "boundary-bootstrap-server.json";
pub const TOKEN_ENV: &str = "OPENSHELL_BOUNDARY_BOOTSTRAP_TOKEN";
pub const ADDRESS_ENV: &str = "OPENSHELL_BOUNDARY_BOOTSTRAP_ADDRESS";
pub const CA_ENV: &str = "OPENSHELL_BOUNDARY_BOOTSTRAP_CA";
pub const SERVER_NAME_ENV: &str = "OPENSHELL_BOUNDARY_BOOTSTRAP_SERVER_NAME";
pub const ROUTE_ENV: &str = "OPENSHELL_BOUNDARY_BOOTSTRAP_ROUTE";
pub const ENV_KEYS: [(&str, &str); 5] = [
    (TOKEN_ENV, "bootstrap-token"),
    (ROUTE_ENV, "bootstrap-route"),
    (ADDRESS_ENV, "bootstrap-address"),
    (CA_ENV, "bootstrap-ca"),
    (SERVER_NAME_ENV, "bootstrap-server-name"),
];
const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_TOKEN_BYTES: usize = 8192;
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// Trusted supervisor-only input, mounted through its existing Secret.
/// Deliberately has no Debug implementation: it includes workload secrets.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapServerConfig {
    pub listen: SocketAddr,
    pub config: BoundaryConfig,
    pub verification_key: SessionVerificationKey,
    pub token_id: String,
    pub certificate_pem: String,
    pub private_key_pem: String,
}

/// Validate and prepare the immutable launch before accepting connections.
pub(crate) fn prepare(config: BootstrapServerConfig) -> Result<Exchange, String> {
    let verifier = SessionJwtVerifier::new(
        &config.config.gateway_id,
        SessionTokenProfile::Bootstrap,
        [config.verification_key.clone()],
        Arc::new(SystemJwtClock),
    )
    .map_err(|_| "invalid bootstrap verification key")?;
    let certs = CertificateDer::pem_slice_iter(config.certificate_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid bootstrap TLS certificate")?;
    let key = PrivateKeyDer::from_pem_slice(config.private_key_pem.as_bytes())
        .map_err(|_| "invalid bootstrap TLS key")?;
    let tls = openshell_crypto::tls::try_server_builder()
        .map_err(|_| "bootstrap TLS provider unavailable")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| "invalid bootstrap TLS identity")?;
    let response = serde_json::to_vec(&config.config).map_err(|_| "encode boundary bootstrap")?;
    if response.len() > MAX_CONFIG_BYTES {
        return Err("boundary bootstrap exceeds 1 MiB".into());
    }
    Ok(Exchange {
        acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(tls)),
        verifier,
        config,
        response,
        redeemed: tokio::sync::Mutex::new(false),
        pending: tokio::sync::Semaphore::new(4),
    })
}

/// A serialized, launch-pinned exchange, also served through the shared router.
pub(crate) struct Exchange {
    acceptor: tokio_rustls::TlsAcceptor,
    verifier: SessionJwtVerifier,
    config: BootstrapServerConfig,
    response: Vec<u8>,
    redeemed: tokio::sync::Mutex<bool>,
    pending: tokio::sync::Semaphore,
}

impl Exchange {
    pub(crate) async fn exchange(&self, stream: tokio::net::TcpStream) -> Result<(), String> {
        let _permit = self
            .pending
            .try_acquire()
            .map_err(|_| "bootstrap exchange limit reached")?;
        let exchange = async {
            let mut redeemed = self.redeemed.lock().await;
            if *redeemed {
                return Err("bootstrap already acknowledged".to_string());
            }
            let mut stream = self
                .acceptor
                .accept(stream)
                .await
                .map_err(|_| "bootstrap TLS handshake")?;
            let token = read_frame(&mut stream, MAX_TOKEN_BYTES)
                .await
                .map_err(|_| "read bootstrap token")?;
            let token = std::str::from_utf8(&token).map_err(|_| "invalid bootstrap token")?;
            let identity = self
                .verifier
                .verify(token)
                .map_err(|_| "unauthorized bootstrap token")?;
            if identity.token_id.to_string() != self.config.token_id
                || identity.sandbox_id.to_string() != self.config.config.boundary_id
                || identity.runtime_generation.to_string() != self.config.config.generation
                || identity.auth_epoch != self.config.config.auth_epoch
            {
                return Err("bootstrap token does not name this launch".into());
            }
            write_frame(&mut stream, &self.response)
                .await
                .map_err(|_| "write bootstrap config")?;
            if stream
                .read_u8()
                .await
                .map_err(|_| "read bootstrap acknowledgment")?
                != 1
            {
                return Err("invalid bootstrap acknowledgment".into());
            }
            *redeemed = true;
            Ok(())
        };
        tokio::time::timeout(EXCHANGE_TIMEOUT, exchange)
            .await
            .map_err(|_| "bootstrap exchange timed out")?
    }
}

/// Starts before normal admission, avoiding a dependency on sandbox readiness.
/// Dropping the returned handle stops the listener and all pending exchanges.
pub async fn serve(config: BootstrapServerConfig) -> Result<BootstrapServer, String> {
    let listen = config.listen;
    let exchange = prepare(config)?;
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|error| format!("bind bootstrap listener: {error}"))?;
    let address = listener.local_addr().map_err(|error| error.to_string())?;
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            openshell_core::net::set_tcp_nodelay_best_effort(&stream);
            if exchange.exchange(stream).await.is_ok() {
                break;
            }
        }
    });
    Ok(BootstrapServer { address, task })
}

pub struct BootstrapServer {
    pub address: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for BootstrapServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Fetch configuration without writing it to disk. Endpoint, trust and token
/// are protected launch inputs; a bootstrap failure never falls back to a file.
pub async fn fetch(
    address: SocketAddr,
    server_name: String,
    ca_pem: &str,
    token: &str,
    route: Option<&str>,
) -> Result<BoundaryConfig, String> {
    if let Some(route) = route {
        crate::runtime_routed::validate_route_handle(route).map_err(|error| error.to_string())?;
    }
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return Err("invalid bootstrap token length".into());
    }
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        roots
            .add(cert.map_err(|_| "invalid bootstrap CA")?)
            .map_err(|_| "invalid bootstrap CA")?;
    }
    if roots.is_empty() {
        return Err("bootstrap CA is empty".into());
    }
    let tls = openshell_crypto::tls::try_client_builder()
        .map_err(|_| "bootstrap TLS provider unavailable")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls));
    let name = ServerName::try_from(server_name).map_err(|_| "invalid bootstrap server name")?;
    // Covers service/pod startup races; each exchange is independently bounded.
    tokio::time::timeout(Duration::from_mins(2), async {
        let mut target = address;
        let mut redirects = 0;
        loop {
            let exchange = async {
                let mut stream = openshell_core::net::connect_tcp_nodelay_best_effort(target)
                    .await
                    .map_err(|_| "connect bootstrap supervisor")?;
                if let Some(route) = route {
                    use crate::runtime_routed::{RouteReply, negotiate_route};
                    match negotiate_route(&mut stream, route)
                        .await
                        .map_err(|_| "bootstrap route negotiation")?
                    {
                        RouteReply::Accept(_) => {}
                        RouteReply::Redirect(owner) => {
                            redirects += 1;
                            target = if redirects <= 8 {
                                owner
                            } else {
                                redirects = 0;
                                address
                            };
                            return Err("bootstrap route redirected");
                        }
                        RouteReply::Unknown => {
                            target = address;
                            return Err("bootstrap route not yet assigned");
                        }
                    }
                }
                let mut stream = connector
                    .connect(name.clone(), stream)
                    .await
                    .map_err(|_| "authenticate bootstrap supervisor")?;
                write_frame(&mut stream, token.as_bytes())
                    .await
                    .map_err(|_| "send bootstrap token")?;
                let response = read_frame(&mut stream, MAX_CONFIG_BYTES)
                    .await
                    .map_err(|_| "receive boundary bootstrap")?;
                let config =
                    serde_json::from_slice(&response).map_err(|_| "decode boundary bootstrap")?;
                stream
                    .write_u8(1)
                    .await
                    .map_err(|_| "acknowledge boundary bootstrap")?;
                stream
                    .flush()
                    .await
                    .map_err(|_| "flush bootstrap acknowledgment")?;
                Ok::<BoundaryConfig, &str>(config)
            };
            match tokio::time::timeout(EXCHANGE_TIMEOUT, exchange).await {
                Ok(Ok(config)) => return config,
                Ok(Err("bootstrap route redirected")) => {}
                // Reconsult the Service's directory if an owner vanished or
                // lost the route while this boundary was still bootstrapping.
                _ => {
                    target = address;
                    redirects = 0;
                }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .map_err(|_| "boundary bootstrap timed out".to_string())
}

async fn write_frame(stream: &mut (impl AsyncWrite + Unpin), bytes: &[u8]) -> std::io::Result<()> {
    stream
        .write_u32(u32::try_from(bytes.len()).map_err(std::io::Error::other)?)
        .await?;
    stream.write_all(bytes).await?;
    stream.flush().await
}

async fn read_frame(
    stream: &mut (impl AsyncRead + Unpin),
    limit: usize,
) -> std::io::Result<Vec<u8>> {
    let length = stream.read_u32().await? as usize;
    if length > limit {
        return Err(std::io::Error::other("bootstrap frame exceeds limit"));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}
