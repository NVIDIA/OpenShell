// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Launch authentication on the existing runtime-initiated control connection.
//! TLS authenticates the supervisor before either launch credential is sent.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use openshell_core::jwt::{
    SandboxId, SandboxRuntimeIdentity, SessionJwtIssuer, SessionJwtVerifier, SessionTokenProfile,
    SessionVerificationKey, SystemJwtClock,
};
use openshell_isolation_interface::contract::BoundaryDuplexStream;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::boundary_protocol::{BoundaryConfig, generate_sandbox_tls_material};

pub const SERVER_FILE: &str = "runtime-launch.json";
pub const SERVER_ENV: &str = "OPENSHELL_RUNTIME_LAUNCH_FILE";
pub const TOKEN_ENV: &str = "OPENSHELL_JOIN_TOKEN";
pub const ADDRESS_ENV: &str = "OPENSHELL_SUPERVISOR_ADDRESS";
pub const ENV_KEYS: [(&str, &str); 2] = [
    (TOKEN_ENV, "join-token"),
    (ADDRESS_ENV, "supervisor-address"),
];
const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_AUTH_BYTES: usize = 16384;
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// Small protected launch capability, consumed before workload execution.
/// Contains no workload configuration. Deliberately has no Debug implementation.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub address: String,
    pub join_token: String,
}

/// Trusted launch envelope: the pin authenticates TLS before the bearer is sent.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JoinToken {
    server_name: String,
    ca_digest: [u8; 32],
    token: String,
    route: String,
}

/// Supervisor-only immutable launch material, persisted by the compute driver.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinServerConfig {
    pub config: BoundaryConfig,
    pub verification_key: SessionVerificationKey,
    pub signing_key_pem: String,
    pub token_id: String,
    pub certificate_pem: String,
    pub private_key_pem: String,
}

/// Driver-private recovery record. Only `credentials` is staged for the runtime.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Launch {
    pub credentials: Credentials,
    pub server: JoinServerConfig,
}
impl Launch {
    pub fn provision(
        config: BoundaryConfig,
        address: String,
        route: String,
    ) -> Result<Self, String> {
        let (credentials, server) = provision(config, address, route)?;
        Ok(Self {
            credentials,
            server,
        })
    }
}

pub fn provision(
    config: BoundaryConfig,
    address: String,
    route: String,
) -> Result<(Credentials, JoinServerConfig), String> {
    let tls =
        generate_sandbox_tls_material(config.session_id).map_err(|error| error.to_string())?;
    let key = openshell_crypto::pki::generate_jwt_keypair().map_err(|error| error.to_string())?;
    let signing_key_pem = key.serialize_pem().map_err(|error| error.to_string())?;
    let verification_key = SessionVerificationKey {
        key_id: "runtime-launch".into(),
        public_key_pem: key.public_key_pem().into_bytes(),
    };
    let issuer = SessionJwtIssuer::from_ed25519_pem(
        signing_key_pem.as_bytes(),
        &verification_key.key_id,
        &config.gateway_id,
        None,
        Arc::new(SystemJwtClock),
    )
    .map_err(|error| error.to_string())?;
    let token = issuer
        .mint_join_token(&identity(&config)?)
        .map_err(|error| error.to_string())?;
    let ca = CertificateDer::from_pem_slice(tls.trust_anchor_pem.as_bytes())
        .map_err(|_| "decode join trust anchor")?;
    let join_token = JoinToken {
        server_name: tls.server_name,
        ca_digest: openshell_crypto::sha256(ca.as_ref()).map_err(|error| error.to_string())?,
        token: token.token.expose_secret().to_string(),
        route,
    };
    let join_token = format!(
        "OSJOIN1.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&join_token).map_err(|_| "encode Join token")?)
    );
    Ok((
        Credentials {
            address,
            join_token,
        },
        JoinServerConfig {
            config,
            verification_key,
            signing_key_pem,
            token_id: token.token_id.to_string(),
            certificate_pem: format!("{}{}", tls.certificate_chain_pem, tls.trust_anchor_pem),
            private_key_pem: tls.private_key_pem,
        },
    ))
}

fn identity(config: &BoundaryConfig) -> Result<SandboxRuntimeIdentity, String> {
    Ok(SandboxRuntimeIdentity {
        sandbox_id: SandboxId::parse(config.boundary_id.clone())
            .map_err(|error| error.to_string())?,
        runtime_generation: openshell_core::sandbox_generation::SandboxGenerationId::parse(
            config.generation.clone(),
        )
        .map_err(|error| error.to_string())?,
        auth_epoch: config.auth_epoch,
    })
}

/// Gateway-backed, atomic redemption for this exact launch generation.
pub trait Redemption: Send + Sync {
    fn redeem(&self) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>>;
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Authentication {
    Join { token: String },
    Session { token: String },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authenticated {
    config: Option<BoundaryConfig>,
    session_token: String,
}

pub(crate) struct Exchange {
    acceptor: tokio_rustls::TlsAcceptor,
    bootstrap: SessionJwtVerifier,
    session: SessionJwtVerifier,
    issuer: SessionJwtIssuer,
    config: JoinServerConfig,
    redemption: Arc<dyn Redemption>,
}

impl Exchange {
    pub(crate) async fn authenticate(
        &self,
        raw: BoundaryDuplexStream,
    ) -> Result<BoundaryDuplexStream, String> {
        let exchange = async {
            let mut stream = self
                .acceptor
                .accept(raw)
                .await
                .map_err(|_| "runtime TLS handshake failed")?;
            let request: Authentication = serde_json::from_slice(
                &read_frame(&mut stream, MAX_AUTH_BYTES)
                    .await
                    .map_err(|_| "read runtime credential")?,
            )
            .map_err(|_| "decode runtime credential")?;
            let (token, verifier, bootstrap) = match &request {
                Authentication::Join { token } => (token, &self.bootstrap, true),
                Authentication::Session { token } => (token, &self.session, false),
            };
            let principal = verifier
                .verify(token)
                .map_err(|_| "unauthorized runtime credential")?;
            if principal.sandbox_id.to_string() != self.config.config.boundary_id
                || principal.runtime_generation.to_string() != self.config.config.generation
                || principal.auth_epoch != self.config.config.auth_epoch
                || (bootstrap && principal.token_id.to_string() != self.config.token_id)
            {
                return Err("runtime credential does not name this launch".into());
            }
            if bootstrap {
                self.redemption.redeem().await?;
            }
            let token = self
                .issuer
                .mint_runtime_session(&identity(&self.config.config)?)
                .map_err(|error| error.to_string())?;
            let response = Authenticated {
                config: bootstrap.then(|| self.config.config.clone()),
                session_token: token.token.expose_secret().to_string(),
            };
            let bytes =
                serde_json::to_vec(&response).map_err(|_| "encode runtime configuration")?;
            if bytes.len() > MAX_CONFIG_BYTES {
                return Err("runtime configuration exceeds limit".into());
            }
            write_frame(&mut stream, &bytes)
                .await
                .map_err(|_| "write runtime configuration")?;
            // This same TLS stream now carries HTTP/2 and the Sandbox Protocol.
            let stream: BoundaryDuplexStream = Box::new(stream);
            Ok(stream)
        };
        tokio::time::timeout(EXCHANGE_TIMEOUT, exchange)
            .await
            .map_err(|_| "runtime authentication timed out")?
    }
}

fn registry() -> &'static Mutex<HashMap<String, Arc<Exchange>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, Arc<Exchange>>>> = OnceLock::new();
    REGISTRY.get_or_init(Mutex::default)
}

pub struct Registration {
    key: String,
    exchange: Arc<Exchange>,
}
impl Drop for Registration {
    fn drop(&mut self) {
        let mut entries = registry()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if entries
            .get(&self.key)
            .is_some_and(|entry| Arc::ptr_eq(entry, &self.exchange))
        {
            entries.remove(&self.key);
        }
    }
}

pub fn register(
    config: JoinServerConfig,
    redemption: Arc<dyn Redemption>,
) -> Result<Registration, String> {
    let verifier = |profile| {
        SessionJwtVerifier::new(
            &config.config.gateway_id,
            profile,
            [config.verification_key.clone()],
            Arc::new(SystemJwtClock),
        )
        .map_err(|error| error.to_string())
    };
    let bootstrap = verifier(SessionTokenProfile::Join)?;
    let session = verifier(SessionTokenProfile::Runtime)?;
    let issuer = SessionJwtIssuer::from_ed25519_pem(
        config.signing_key_pem.as_bytes(),
        &config.verification_key.key_id,
        &config.config.gateway_id,
        None,
        Arc::new(SystemJwtClock),
    )
    .map_err(|error| error.to_string())?;
    let certs = CertificateDer::pem_slice_iter(config.certificate_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid runtime certificate")?;
    let key = PrivateKeyDer::from_pem_slice(config.private_key_pem.as_bytes())
        .map_err(|_| "invalid runtime key")?;
    let tls = openshell_crypto::tls::try_server_builder()
        .map_err(|_| "runtime TLS unavailable")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| "invalid runtime TLS identity")?;
    let key = config.config.session_id.to_string();
    let exchange = Arc::new(Exchange {
        acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(tls)),
        bootstrap,
        session,
        issuer,
        config,
        redemption,
    });
    let mut entries = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if entries.contains_key(&key) {
        return Err("runtime launch is already registered".into());
    }
    entries.insert(key.clone(), exchange.clone());
    Ok(Registration { key, exchange })
}

pub(crate) fn lookup(session: impl ToString) -> Option<Arc<Exchange>> {
    registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&session.to_string())
        .cloned()
}

pub(crate) fn lookup_tls(
    tls: &crate::boundary_protocol::SandboxTlsClientConfig,
) -> Option<Arc<Exchange>> {
    let session = tls
        .server_name
        .strip_prefix("sandbox.")?
        .strip_suffix(".openshell.internal")?;
    lookup(session)
}

pub struct Client {
    address: String,
    credentials: JoinToken,
    session: Mutex<String>,
    tls: Arc<rustls::ClientConfig>,
}

impl Client {
    pub fn new(credentials: Credentials) -> Result<Arc<Self>, String> {
        if credentials.join_token.len() > MAX_AUTH_BYTES {
            return Err("Join token exceeds limit".into());
        }
        let encoded = credentials
            .join_token
            .strip_prefix("OSJOIN1.")
            .ok_or("unsupported Join token")?;
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| "decode Join token")?;
        let join: JoinToken = serde_json::from_slice(&bytes).map_err(|_| "decode Join token")?;
        if !join.route.is_empty() {
            crate::runtime_routed::validate_route_handle(&join.route)
                .map_err(|error| error.to_string())?;
        }
        let tls = openshell_crypto::tls::try_client_builder()
            .map_err(|_| "runtime TLS unavailable")?
            .dangerous()
            .with_custom_certificate_verifier(openshell_crypto::tls::pinned_ca_verifier(
                join.ca_digest,
            ))
            .with_no_client_auth();
        Ok(Arc::new(Self {
            address: credentials.address,
            credentials: join,
            session: Mutex::new(String::new()),
            tls: Arc::new(tls),
        }))
    }

    pub async fn authenticate(
        &self,
        raw: BoundaryDuplexStream,
    ) -> Result<(BoundaryDuplexStream, Option<BoundaryConfig>), String> {
        let (stream, config) = self.authenticate_inner(raw).await?;
        Ok((Box::new(stream), config))
    }

    async fn authenticate_inner<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        raw: S,
    ) -> Result<(tokio_rustls::client::TlsStream<S>, Option<BoundaryConfig>), String> {
        let name = ServerName::try_from(self.credentials.server_name.clone())
            .map_err(|_| "invalid runtime server name")?;
        let mut stream = tokio_rustls::TlsConnector::from(self.tls.clone())
            .connect(name, raw)
            .await
            .map_err(|error| format!("authenticate supervisor TLS: {error}"))?;
        let token = self
            .session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let request = if token.is_empty() {
            Authentication::Join {
                token: self.credentials.token.clone(),
            }
        } else {
            Authentication::Session { token }
        };
        write_frame(
            &mut stream,
            &serde_json::to_vec(&request).map_err(|_| "encode runtime credential")?,
        )
        .await
        .map_err(|_| "send runtime credential")?;
        let response: Authenticated = serde_json::from_slice(
            &read_frame(&mut stream, MAX_CONFIG_BYTES)
                .await
                .map_err(|_| "receive runtime configuration")?,
        )
        .map_err(|_| "decode runtime configuration")?;
        *self
            .session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = response.session_token;
        Ok((stream, response.config))
    }

    /// Detach the socket from the temporary single-thread runtime before the
    /// workload launcher forks. Reattach the same TLS session afterward.
    #[cfg(unix)]
    pub async fn bootstrap(&self) -> Result<(BoundaryConfig, Detached), String> {
        tokio::time::timeout(Duration::from_mins(2), async {
            let original = self.address.clone();
            let mut target = original.clone();
            let mut redirects = 0;
            loop {
                let attempt = async {
                    let mut socket = Socket::connect(&target)
                        .await
                        .map_err(|error| error.to_string())?;
                    let mut member = None;
                    if !self.credentials.route.is_empty() {
                        use crate::runtime_routed::{RouteReply, negotiate_route};
                        match negotiate_route(&mut socket, &self.credentials.route)
                            .await
                            .map_err(|error| error.to_string())?
                        {
                            RouteReply::Accept(owner) => {
                                member = owner.or_else(|| target.parse().ok());
                            }
                            RouteReply::Redirect(owner) if redirects < 8 => {
                                redirects += 1;
                                target = owner.to_string();
                                return Err("redirect".into());
                            }
                            _ => return Err("runtime route unavailable".into()),
                        }
                    }
                    let (stream, config) = self.authenticate_inner(socket).await?;
                    let config =
                        config.ok_or("runtime bootstrap response omitted configuration")?;
                    let (socket, connection) = stream.into_inner();
                    Ok::<_, String>((
                        config,
                        Detached {
                            socket: socket.detach().map_err(|error| error.to_string())?,
                            connection,
                            member,
                        },
                    ))
                };
                match tokio::time::timeout(EXCHANGE_TIMEOUT, attempt).await {
                    Ok(Ok(result)) => return result,
                    Ok(Err(error)) if error == "redirect" => {}
                    _ => {
                        target = original.clone();
                        redirects = 0;
                    }
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .map_err(|_| "runtime bootstrap timed out".to_string())
    }
}

#[cfg(unix)]
pub struct Detached {
    socket: DetachedSocket,
    connection: rustls::ClientConnection,
    pub member: Option<SocketAddr>,
}
#[cfg(unix)]
impl Detached {
    pub async fn attach(self, client: &Client) -> Result<BoundaryDuplexStream, String> {
        let raw = self.socket.attach().map_err(|error| error.to_string())?;
        let name = ServerName::try_from(client.credentials.server_name.clone())
            .map_err(|_| "invalid runtime server name")?;
        let stream = tokio_rustls::TlsConnector::from(client.tls.clone())
            .connect_with(name, raw, |connection| *connection = self.connection)
            .await
            .map_err(|error| error.to_string())?;
        Ok(Box::new(stream))
    }
}

#[cfg(unix)]
enum Socket {
    Tcp(tokio::net::TcpStream),
    Unix(tokio::net::UnixStream),
}
#[cfg(unix)]
enum DetachedSocket {
    Tcp(std::net::TcpStream),
    Unix(std::os::unix::net::UnixStream),
}
#[cfg(unix)]
impl DetachedSocket {
    fn attach(self) -> std::io::Result<Socket> {
        match self {
            Self::Tcp(stream) => tokio::net::TcpStream::from_std(stream).map(Socket::Tcp),
            Self::Unix(stream) => tokio::net::UnixStream::from_std(stream).map(Socket::Unix),
        }
    }
}
#[cfg(unix)]
impl Socket {
    fn detach(self) -> std::io::Result<DetachedSocket> {
        match self {
            Self::Tcp(stream) => stream.into_std().map(DetachedSocket::Tcp),
            Self::Unix(stream) => stream.into_std().map(DetachedSocket::Unix),
        }
    }
    async fn connect(address: &str) -> std::io::Result<Self> {
        if let Some(path) = address.strip_prefix("unix:") {
            return tokio::net::UnixStream::connect(path).await.map(Self::Unix);
        }
        #[cfg(target_os = "linux")]
        if let Some(port) = address.strip_prefix("vsock:") {
            let port = port
                .parse()
                .map_err(|_| std::io::Error::other("invalid vsock port"))?;
            let socket = socket2::Socket::new(socket2::Domain::VSOCK, socket2::Type::STREAM, None)?;
            socket.set_nonblocking(true)?;
            match socket.connect(&socket2::SockAddr::vsock(libc::VMADDR_CID_HOST, port)) {
                Ok(()) => {}
                Err(error) if error.raw_os_error() == Some(libc::EINPROGRESS) => {}
                Err(error) => return Err(error),
            }
            let stream =
                tokio::net::UnixStream::from_std(std::os::unix::net::UnixStream::from(socket))?;
            stream.writable().await?;
            if let Some(error) = stream.take_error()? {
                return Err(error);
            }
            return Ok(Self::Unix(stream));
        }
        let address: SocketAddr = address
            .parse()
            .map_err(|_| std::io::Error::other("invalid runtime address"))?;
        openshell_core::net::connect_tcp_nodelay_best_effort(address)
            .await
            .map(Self::Tcp)
    }
}
#[cfg(unix)]
impl AsyncRead for Socket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}
#[cfg(unix)]
impl AsyncWrite for Socket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Self::Unix(stream) => Pin::new(stream).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
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
        return Err(std::io::Error::other(
            "runtime authentication frame exceeds limit",
        ));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}
