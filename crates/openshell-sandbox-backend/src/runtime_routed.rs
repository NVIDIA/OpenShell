// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! One supervisor listener for many sandbox instances' runtime-initiated
//! connections.
//!
//! A runtime that dials a shared supervisor first sends a fixed, bounded
//! routing preface naming an opaque route handle. The handle is only a hint:
//! it selects which sandbox instance's generation-pinned TLS identity the
//! supervisor expects, and the supervisor then completes the same pinned TLS
//! client handshake as for a dedicated listener. A peer that names another
//! instance's handle cannot present that instance's TLS identity, so it is
//! rejected before any request is carried. Every Sandbox Protocol request
//! still carries the instance's session bearer token. Unknown, removed, and
//! replaced handles are closed without a handshake, and authenticated
//! connections only fill the target instance's bounded spare queue, so no
//! peer can displace a live channel.
//!
//! In a supervisor pool one member hosts each route, but a runtime reaches
//! an arbitrary member. A version 2 preface is answered before any TLS: the
//! member that hosts the route accepts, naming itself, and the TLS handshake
//! follows, while any other member names the owner from its gateway-provided
//! route directory, or reports the route unknown, and closes. The directory
//! wins over a local registration it no longer agrees with, which is being
//! released. Replies are hints like the handle itself: the owner must still
//! complete the pinned TLS handshake, and every request still carries the
//! bearer token.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openshell_isolation_interface::contract::{BackendError, BoundaryDuplexStream};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

use crate::boundary_protocol::SandboxTlsClientConfig;

/// First bytes of a routing preface.
pub const ROUTE_PREFACE_MAGIC: [u8; 4] = *b"OSRP";
/// Routing preface layout version that receives no reply.
pub const ROUTE_PREFACE_VERSION: u8 = 1;
/// Routing preface layout version that the supervisor answers with a
/// [`RouteReply`] before the TLS handshake.
pub const ROUTE_PREFACE_VERSION_V2: u8 = 2;
/// Longest accepted route handle, in bytes.
pub const MAX_ROUTE_HANDLE_LEN: usize = 64;
const MIN_ROUTE_HANDLE_LEN: usize = 16;
/// Status bytes of a version 2 reply. An accept and a redirect are followed
/// by a length byte and a runtime listener address as ASCII `ip:port`: the
/// accepting member's own (empty while it knows no directory) or the owner's.
const ROUTE_REPLY_ACCEPT: u8 = 0x01;
const ROUTE_REPLY_REDIRECT: u8 = 0x02;
const ROUTE_REPLY_UNKNOWN: u8 = 0x03;

/// Unauthenticated sockets the listener handshakes at once, across sandbox
/// instances.
const MAX_PENDING_HANDSHAKES: usize = 64;
/// Unauthenticated sockets naming one handle; one handle cannot exhaust the
/// listener for every other sandbox instance.
const MAX_PENDING_HANDSHAKES_PER_ROUTE: usize = 4;
/// Bound on reading the preface and completing TLS for one socket.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Authenticated connections queued for a sandbox instance but not yet claimed.
const MAX_QUEUED_CONNECTIONS: usize = 2;

/// Validate an opaque route handle: 16 to 64 lowercase ASCII letters, digits,
/// or hyphens.
pub fn validate_route_handle(handle: &str) -> Result<(), BackendError> {
    let valid = (MIN_ROUTE_HANDLE_LEN..=MAX_ROUTE_HANDLE_LEN).contains(&handle.len())
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if valid {
        Ok(())
    } else {
        Err(BackendError::Descriptor(
            "runtime route handle must be 16 to 64 lowercase letters, digits, or hyphens"
                .to_string(),
        ))
    }
}

/// Generate a fresh opaque route handle for one runtime generation.
#[must_use]
pub fn new_route_handle() -> String {
    format!("rt-{}", uuid::Uuid::new_v4().simple())
}

/// Encode the routing preface a runtime sends before its TLS handshake.
pub fn encode_route_preface(handle: &str) -> Result<Vec<u8>, BackendError> {
    encode_versioned_preface(ROUTE_PREFACE_VERSION, handle)
}

/// Encode a version 2 routing preface, which the supervisor answers before
/// the TLS handshake (see [`negotiate_route`]).
pub fn encode_route_preface_v2(handle: &str) -> Result<Vec<u8>, BackendError> {
    encode_versioned_preface(ROUTE_PREFACE_VERSION_V2, handle)
}

fn encode_versioned_preface(version: u8, handle: &str) -> Result<Vec<u8>, BackendError> {
    validate_route_handle(handle)?;
    let length = u8::try_from(handle.len())
        .map_err(|_| BackendError::Descriptor("runtime route handle is too long".to_string()))?;
    let mut preface = Vec::with_capacity(ROUTE_PREFACE_MAGIC.len() + 2 + handle.len());
    preface.extend_from_slice(&ROUTE_PREFACE_MAGIC);
    preface.push(version);
    preface.push(length);
    preface.extend_from_slice(handle.as_bytes());
    Ok(preface)
}

/// Read and validate one routing preface, returning its version and route
/// handle. Reads only the declared bytes.
async fn read_route_preface<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<(u8, String)> {
    let invalid = |message: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, message);
    let mut header = [0_u8; 6];
    stream.read_exact(&mut header).await?;
    if header[..4] != ROUTE_PREFACE_MAGIC {
        return Err(invalid("missing runtime routing preface"));
    }
    let version = header[4];
    if version != ROUTE_PREFACE_VERSION && version != ROUTE_PREFACE_VERSION_V2 {
        return Err(invalid("unsupported runtime routing preface version"));
    }
    let length = usize::from(header[5]);
    if length > MAX_ROUTE_HANDLE_LEN {
        return Err(invalid("runtime route handle is too long"));
    }
    let mut handle = vec![0_u8; length];
    stream.read_exact(&mut handle).await?;
    let handle = String::from_utf8(handle).map_err(|_| invalid("invalid runtime route handle"))?;
    validate_route_handle(&handle).map_err(|error| invalid(&error.to_string()))?;
    Ok((version, handle))
}

/// A supervisor's answer to a version 2 routing preface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteReply {
    /// This supervisor hosts the route; the TLS handshake follows on the same
    /// connection. Names the member's runtime listener as its route directory
    /// does, when it has one; unauthenticated, like everything before TLS.
    Accept(Option<SocketAddr>),
    /// Another pool member hosts the route, at this runtime listener address.
    /// Unauthenticated, like the handle that selected it.
    Redirect(SocketAddr),
    /// No pool member is known to host the route.
    Unknown,
}

/// Name `handle` in a version 2 routing preface and read the reply.
///
/// Only the reply's declared bytes are read, so after
/// [`RouteReply::Accept`] the stream is positioned at the TLS handshake. The
/// caller bounds the exchange in time.
pub async fn negotiate_route<S>(stream: &mut S, handle: &str) -> std::io::Result<RouteReply>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let invalid = |message: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, message);
    let preface = encode_route_preface_v2(handle).map_err(|error| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
    })?;
    stream.write_all(&preface).await?;
    stream.flush().await?;
    match stream.read_u8().await? {
        ROUTE_REPLY_ACCEPT => {
            let member = read_reply_address(stream).await?;
            Ok(RouteReply::Accept(member))
        }
        ROUTE_REPLY_UNKNOWN => Ok(RouteReply::Unknown),
        ROUTE_REPLY_REDIRECT => read_reply_address(stream)
            .await?
            .map(RouteReply::Redirect)
            .ok_or_else(|| invalid("invalid runtime route redirect")),
        _ => Err(invalid("unknown runtime route reply")),
    }
}

/// Read a reply's length-prefixed listener address; empty reads as `None`.
async fn read_reply_address<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> std::io::Result<Option<SocketAddr>> {
    let mut address = vec![0_u8; usize::from(stream.read_u8().await?)];
    if address.is_empty() {
        return Ok(None);
    }
    stream.read_exact(&mut address).await?;
    std::str::from_utf8(&address)
        .ok()
        .and_then(|address| address.parse().ok())
        .map(Some)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid runtime route reply address",
            )
        })
}

/// Encode a version 2 reply carrying a listener address.
fn address_reply(status: u8, address: Option<SocketAddr>) -> Result<Vec<u8>, String> {
    let address = address
        .map(|address| address.to_string())
        .unwrap_or_default();
    let length = u8::try_from(address.len())
        .map_err(|_| "runtime listener address is too long".to_string())?;
    let mut reply = Vec::with_capacity(2 + address.len());
    reply.push(status);
    reply.push(length);
    reply.extend_from_slice(address.as_bytes());
    Ok(reply)
}

/// Encode a version 2 redirect to `owner`.
fn redirect_reply(owner: SocketAddr) -> Result<Vec<u8>, String> {
    address_reply(ROUTE_REPLY_REDIRECT, Some(owner))
}

struct Route {
    /// Distinguishes a re-registered handle from the registration it replaced.
    id: u64,
    tls: SandboxTlsClientConfig,
    spares: mpsc::Sender<BoundaryDuplexStream>,
    pending: Arc<Semaphore>,
}

#[derive(Default)]
struct Routes {
    next_id: u64,
    by_handle: HashMap<String, Route>,
    /// This listener's address, as the route directory names it.
    own_address: Option<SocketAddr>,
    /// Runtime listener of the pool member that hosts each route.
    owners: HashMap<String, SocketAddr>,
}

/// Where a routing preface's handle leads.
enum Destination {
    /// A sandbox instance registered on this listener, which the directory
    /// names as `own`.
    Local {
        tls: SandboxTlsClientConfig,
        spares: mpsc::Sender<BoundaryDuplexStream>,
        pending: Arc<Semaphore>,
        own: Option<SocketAddr>,
    },
    /// Another pool member's runtime listener.
    Owner(SocketAddr),
    Unknown,
}

impl Routes {
    /// The directory never sends a runtime back to this listener. For a
    /// runtime that follows redirects, the directory also wins over a local
    /// registration naming another owner: the gateway moved the route, and
    /// the registration is being released. A runtime that cannot follow one
    /// reaches the registration, as before pools existed.
    fn destination(&self, handle: &str, follows_redirects: bool) -> Destination {
        let owner = self
            .owners
            .get(handle)
            .copied()
            .filter(|owner| Some(*owner) != self.own_address);
        match (self.by_handle.get(handle), owner) {
            (Some(_), Some(owner)) if follows_redirects => Destination::Owner(owner),
            (Some(route), _) => Destination::Local {
                tls: route.tls.clone(),
                spares: route.spares.clone(),
                pending: route.pending.clone(),
                own: self.own_address,
            },
            (None, Some(owner)) => Destination::Owner(owner),
            (None, None) => Destination::Unknown,
        }
    }
}

/// Shared listener that routes runtime connections to registered sandbox
/// instances.
pub struct RuntimeRouter {
    routes: Arc<Mutex<Routes>>,
    local_addr: SocketAddr,
    accept_task: tokio::task::AbortHandle,
}

impl std::fmt::Debug for RuntimeRouter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeRouter")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl RuntimeRouter {
    /// Bind `listen` and start routing authenticated runtime connections.
    pub fn bind(listen: SocketAddr) -> Result<Arc<Self>, BackendError> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            BackendError::Unavailable("runtime router requires a Tokio runtime".into())
        })?;
        let _entered = runtime.enter();
        let listener = bind_tcp(listen).map_err(|error| {
            BackendError::Unavailable(format!("runtime router listener: {error}"))
        })?;
        let local_addr = listener.local_addr().map_err(|error| {
            BackendError::Unavailable(format!("runtime router listener: {error}"))
        })?;
        let routes = Arc::new(Mutex::new(Routes::default()));
        let accept_task = runtime
            .spawn(accept_loop(listener, routes.clone()))
            .abort_handle();
        tracing::info!(%local_addr, "Routed runtime-initiated Sandbox Protocol listener ready");
        Ok(Arc::new(Self {
            routes,
            local_addr,
            accept_task,
        }))
    }

    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Accept connections for `handle`, authenticated with `tls`. A handle
    /// that is already registered is refused; the existing instance keeps it.
    pub fn register(
        &self,
        handle: &str,
        tls: &SandboxTlsClientConfig,
    ) -> Result<Arc<RouteRegistration>, BackendError> {
        validate_route_handle(handle)?;
        crate::runtime::validate_client_tls(tls)?;
        let mut routes = lock(&self.routes);
        if routes.by_handle.contains_key(handle) {
            return Err(BackendError::Denied(
                "runtime route handle is already registered".to_string(),
            ));
        }
        routes.next_id += 1;
        let id = routes.next_id;
        let (sender, spares) = mpsc::channel(MAX_QUEUED_CONNECTIONS);
        routes.by_handle.insert(
            handle.to_string(),
            Route {
                id,
                tls: tls.clone(),
                spares: sender,
                pending: Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES_PER_ROUTE)),
            },
        );
        Ok(Arc::new(RouteRegistration {
            routes: Arc::downgrade(&self.routes),
            handle: handle.to_string(),
            id,
            tls: tls.clone(),
            spares: tokio::sync::Mutex::new(spares),
            connected: AtomicBool::new(false),
        }))
    }

    /// Replace the route directory of a supervisor pool: the runtime listener
    /// of the member that hosts each route. A runtime whose version 2 preface
    /// names a route not registered here is redirected to that member. `own`
    /// is this listener's address as the directory names it; an entry naming
    /// it reports the route unknown instead, so a runtime is never redirected
    /// back here.
    pub fn set_directory(&self, own: Option<SocketAddr>, owners: HashMap<String, SocketAddr>) {
        let mut routes = lock(&self.routes);
        routes.own_address = own;
        routes.owners = owners;
    }
}

impl Drop for RuntimeRouter {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

/// One sandbox instance's claim on a route handle. Dropping it unregisters the handle
/// and closes connections queued for it.
pub struct RouteRegistration {
    routes: std::sync::Weak<Mutex<Routes>>,
    handle: String,
    id: u64,
    tls: SandboxTlsClientConfig,
    spares: tokio::sync::Mutex<mpsc::Receiver<BoundaryDuplexStream>>,
    /// The runtime has delivered at least one authenticated connection.
    connected: AtomicBool,
}

impl std::fmt::Debug for RouteRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RouteRegistration")
            .field("handle", &self.handle)
            .finish_non_exhaustive()
    }
}

impl RouteRegistration {
    #[must_use]
    pub fn handle(&self) -> &str {
        &self.handle
    }

    /// Wait for one authenticated connection for this sandbox instance,
    /// whose generation-pinned identity `tls` must name.
    pub async fn accept(
        &self,
        tls: &SandboxTlsClientConfig,
    ) -> Result<BoundaryDuplexStream, BackendError> {
        if *tls != self.tls {
            return Err(BackendError::Descriptor(
                "runtime route is registered for a different sandbox instance".to_string(),
            ));
        }
        let stream = self
            .spares
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| BackendError::Unavailable("runtime router stopped".to_string()))?;
        self.connected.store(true, Ordering::Relaxed);
        Ok(stream)
    }

    /// Whether the runtime has connected for this sandbox instance before.
    pub(crate) fn has_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }
}

impl Drop for RouteRegistration {
    fn drop(&mut self) {
        if let Some(routes) = self.routes.upgrade() {
            let mut routes = lock(&routes);
            if routes
                .by_handle
                .get(&self.handle)
                .is_some_and(|route| route.id == self.id)
            {
                routes.by_handle.remove(&self.handle);
            }
        }
    }
}

fn lock(routes: &Mutex<Routes>) -> std::sync::MutexGuard<'_, Routes> {
    routes
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn bind_tcp(address: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(address),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(128)?;
    tokio::net::TcpListener::from_std(socket.into())
}

/// Route each accepted socket within global and per-handle handshake bounds.
async fn accept_loop(listener: tokio::net::TcpListener, routes: Arc<Mutex<Routes>>) {
    let pending = Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES));
    // Owned here so aborting the listener also cancels pending handshakes.
    let mut handshakes = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let stream = match accepted {
                    Ok((stream, _)) => stream,
                    Err(error) => {
                        // Descriptor exhaustion and similar errors are transient.
                        tracing::warn!(%error, "routed runtime accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let Ok(permit) = pending.clone().try_acquire_owned() else {
                    tracing::debug!("routed runtime handshake limit reached; closing connection");
                    continue;
                };
                openshell_core::net::set_tcp_nodelay_best_effort(&stream);
                crate::runtime::enable_boundary_tcp_keepalive(&stream);
                let routes = routes.clone();
                handshakes.spawn(async move {
                    if let Err(error) = route_connection(stream, &routes, permit).await {
                        tracing::debug!(%error, "rejected routed runtime connection");
                    }
                });
            }
            Some(_) = handshakes.join_next(), if !handshakes.is_empty() => {}
        }
    }
}

async fn route_connection(
    mut stream: tokio::net::TcpStream,
    routes: &Mutex<Routes>,
    _listener_permit: OwnedSemaphorePermit,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
    let (version, handle) = tokio::time::timeout_at(deadline, read_route_preface(&mut stream))
        .await
        .map_err(|_| "routing preface timed out".to_string())?
        .map_err(|error| format!("routing preface: {error}"))?;
    // Only a version 2 runtime reads a reply.
    let negotiated = version == ROUTE_PREFACE_VERSION_V2;
    // The handle only selects which pinned identity to expect, or which pool
    // member to name.
    let destination = lock(routes).destination(&handle, negotiated);
    let (tls, spares, route_pending, own) = match destination {
        Destination::Local {
            tls,
            spares,
            pending,
            own,
        } => (tls, spares, pending, own),
        Destination::Owner(owner) if negotiated => {
            send_reply(&mut stream, deadline, &redirect_reply(owner)?).await?;
            tracing::debug!(%owner, "redirected routed runtime connection to the route's owner");
            return Ok(());
        }
        Destination::Owner(_) | Destination::Unknown => {
            if negotiated {
                send_reply(&mut stream, deadline, &[ROUTE_REPLY_UNKNOWN]).await?;
            }
            return Err("unknown or retired runtime route handle".to_string());
        }
    };
    let Ok(_route_permit) = route_pending.try_acquire_owned() else {
        return Err("runtime route handshake limit reached".to_string());
    };
    // Accept only once the TLS handshake can proceed.
    if negotiated {
        send_reply(
            &mut stream,
            deadline,
            &address_reply(ROUTE_REPLY_ACCEPT, own)?,
        )
        .await?;
    }
    let stream: BoundaryDuplexStream = Box::new(stream);
    let authenticated = tokio::time::timeout_at(
        deadline,
        crate::runtime::authenticate_boundary_stream(&tls, stream),
    )
    .await
    .map_err(|_| "runtime TLS handshake timed out".to_string())?
    .map_err(|error| error.to_string())?;
    // A sender captured before its registration was removed or replaced has
    // no receiver, so the stream cannot reach another generation.
    spares
        .try_send(authenticated)
        .map_err(|_| "runtime route has no free spare slot".to_string())
}

/// Write one version 2 reply within the handshake deadline.
async fn send_reply(
    stream: &mut tokio::net::TcpStream,
    deadline: tokio::time::Instant,
    reply: &[u8],
) -> Result<(), String> {
    tokio::time::timeout_at(deadline, stream.write_all(reply))
        .await
        .map_err(|_| "routing reply timed out".to_string())?
        .map_err(|error| format!("routing reply: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary_protocol::{SandboxTlsMaterial, generate_sandbox_tls_material};

    /// A runtime: dial the router, name `route`, and serve `identity`'s TLS.
    async fn runtime_dial(
        router: SocketAddr,
        route: &str,
        identity: &SandboxTlsMaterial,
    ) -> std::io::Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>> {
        let mut stream = tokio::net::TcpStream::connect(router).await?;
        stream
            .write_all(&encode_route_preface(route).unwrap())
            .await?;
        serve_tls(stream, identity).await
    }

    /// A redirect-aware runtime: negotiate `route` with the router.
    async fn negotiate(router: SocketAddr, route: &str) -> (tokio::net::TcpStream, RouteReply) {
        let mut stream = tokio::net::TcpStream::connect(router).await.unwrap();
        let reply = negotiate_route(&mut stream, route).await.unwrap();
        (stream, reply)
    }

    async fn serve_tls(
        stream: tokio::net::TcpStream,
        identity: &SandboxTlsMaterial,
    ) -> std::io::Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>> {
        let mut config = rustls::ServerConfig::builder_with_provider(
            openshell_crypto::tls::configuration_provider(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            rustls_pemfile::certs(&mut identity.certificate_chain_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            rustls_pemfile::private_key(&mut identity.private_key_pem.as_bytes())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        tokio_rustls::TlsAcceptor::from(Arc::new(config))
            .accept(stream)
            .await
    }

    fn client_tls(identity: &SandboxTlsMaterial) -> SandboxTlsClientConfig {
        SandboxTlsClientConfig {
            server_name: identity.server_name.clone(),
            trust_anchor_pem: identity.trust_anchor_pem.clone(),
        }
    }

    async fn delivered(registration: &RouteRegistration, tls: &SandboxTlsClientConfig) -> bool {
        tokio::time::timeout(Duration::from_millis(300), registration.accept(tls))
            .await
            .is_ok_and(|accepted| accepted.is_ok())
    }

    #[tokio::test]
    async fn routes_only_authenticated_runtimes_to_their_own_live_instance() {
        let router = RuntimeRouter::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = router.local_addr();
        let alpha = generate_sandbox_tls_material(openshell_core::SandboxSessionId::new()).unwrap();
        let beta = generate_sandbox_tls_material(openshell_core::SandboxSessionId::new()).unwrap();
        let (alpha_route, beta_route) = (new_route_handle(), new_route_handle());
        let alpha_registration = router.register(&alpha_route, &client_tls(&alpha)).unwrap();
        let beta_registration = router.register(&beta_route, &client_tls(&beta)).unwrap();
        assert!(
            router.register(&beta_route, &client_tls(&alpha)).is_err(),
            "a live route cannot be claimed again"
        );

        // A runtime holding the named instance's identity is delivered to it.
        let alpha_tls = client_tls(&alpha);
        let (runtime, accepted) = tokio::join!(
            runtime_dial(address, &alpha_route, &alpha),
            alpha_registration.accept(&alpha_tls)
        );
        assert!(runtime.is_ok() && accepted.is_ok());

        // Naming another instance without its identity fails TLS, and
        // nothing reaches either instance.
        assert!(runtime_dial(address, &beta_route, &alpha).await.is_err());
        assert!(!delivered(&beta_registration, &client_tls(&beta)).await);
        assert!(!delivered(&alpha_registration, &client_tls(&alpha)).await);

        // Unknown and retired routes are closed before any TLS handshake.
        assert!(
            runtime_dial(address, &new_route_handle(), &beta)
                .await
                .is_err()
        );
        drop(alpha_registration);
        assert!(runtime_dial(address, &alpha_route, &alpha).await.is_err());

        // The other instance is unaffected and keeps accepting its runtime.
        let beta_tls = client_tls(&beta);
        let (runtime, accepted) = tokio::join!(
            runtime_dial(address, &beta_route, &beta),
            beta_registration.accept(&beta_tls)
        );
        assert!(runtime.is_ok() && accepted.is_ok());

        // A retired route can be registered again by a new owner.
        assert!(router.register(&alpha_route, &client_tls(&alpha)).is_ok());
    }

    #[tokio::test]
    async fn negotiated_runtimes_are_accepted_redirected_or_refused_by_route_directory() {
        let router = RuntimeRouter::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = router.local_addr();
        let identity =
            generate_sandbox_tls_material(openshell_core::SandboxSessionId::new()).unwrap();
        let tls = client_tls(&identity);
        let (hosted, elsewhere, looped) =
            (new_route_handle(), new_route_handle(), new_route_handle());
        let registration = router.register(&hosted, &tls).unwrap();
        let owner: SocketAddr = "10.0.0.2:7443".parse().unwrap();
        router.set_directory(
            Some(address),
            HashMap::from([
                (hosted.clone(), owner),
                (elsewhere.clone(), owner),
                (looped.clone(), address),
            ]),
        );

        // A registration the directory moved elsewhere is being released:
        // a runtime that follows redirects goes to the new owner, and one
        // that cannot still reaches the registration.
        assert_eq!(
            negotiate(address, &hosted).await.1,
            RouteReply::Redirect(owner)
        );
        let (runtime, accepted) = tokio::join!(
            runtime_dial(address, &hosted, &identity),
            registration.accept(&tls)
        );
        assert!(runtime.is_ok() && accepted.is_ok());

        // A route registered here that the directory agrees with is
        // accepted, naming this member, then authenticated and delivered as
        // for version 1.
        router.set_directory(
            Some(address),
            HashMap::from([
                (hosted.clone(), address),
                (elsewhere.clone(), owner),
                (looped.clone(), address),
            ]),
        );
        let (stream, reply) = negotiate(address, &hosted).await;
        assert_eq!(reply, RouteReply::Accept(Some(address)));
        let (runtime, accepted) =
            tokio::join!(serve_tls(stream, &identity), registration.accept(&tls));
        assert!(runtime.is_ok() && accepted.is_ok());

        // A route hosted elsewhere is redirected to its owner. A directory
        // entry naming this listener, or no entry at all, is unknown.
        assert_eq!(
            negotiate(address, &elsewhere).await.1,
            RouteReply::Redirect(owner)
        );
        assert_eq!(negotiate(address, &looped).await.1, RouteReply::Unknown);
        assert_eq!(
            negotiate(address, &new_route_handle()).await.1,
            RouteReply::Unknown
        );

        // A version 1 runtime cannot follow a redirect and gets no reply.
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream
            .write_all(&encode_route_preface(&elsewhere).unwrap())
            .await
            .unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).await.unwrap();
        assert!(reply.is_empty());

        // A replacement directory takes effect for the next connection.
        let moved: SocketAddr = "[fd00::3]:7443".parse().unwrap();
        router.set_directory(Some(address), HashMap::from([(looped.clone(), moved)]));
        assert_eq!(
            negotiate(address, &looped).await.1,
            RouteReply::Redirect(moved)
        );
        assert_eq!(negotiate(address, &elsewhere).await.1, RouteReply::Unknown);
        assert!(!delivered(&registration, &tls).await);
    }

    #[tokio::test]
    async fn preface_round_trips_and_rejects_malformed_input() {
        let handle = new_route_handle();
        for (encoded, version) in [
            (
                encode_route_preface(&handle).unwrap(),
                ROUTE_PREFACE_VERSION,
            ),
            (
                encode_route_preface_v2(&handle).unwrap(),
                ROUTE_PREFACE_VERSION_V2,
            ),
        ] {
            assert_eq!(
                read_route_preface(&mut encoded.as_slice()).await.unwrap(),
                (version, handle.clone())
            );
        }
        let mut wrong_version = encode_route_preface(&handle).unwrap();
        wrong_version[4] = 3;
        for malformed in [
            b"TLS\x16\x03\x01".to_vec(),
            wrong_version,
            [b"OSRP\x01\x41".as_slice(), &[b'a'; 65]].concat(),
            [b"OSRP\x02\x10".as_slice(), b"UPPERCASE-HANDLE"].concat(),
            [b"OSRP\x02\x20".as_slice(), b"truncated-handle"].concat(),
        ] {
            assert!(read_route_preface(&mut malformed.as_slice()).await.is_err());
        }
        assert!(encode_route_preface("short").is_err());
        assert!(encode_route_preface_v2("short").is_err());
    }

    /// Negotiate against a supervisor that answers `reply`, returning the
    /// outcome and the bytes left unread after it.
    async fn negotiate_scripted(reply: &[u8]) -> (std::io::Result<RouteReply>, Vec<u8>) {
        let handle = new_route_handle();
        let (mut runtime, mut supervisor) = tokio::io::duplex(1024);
        supervisor.write_all(reply).await.unwrap();
        supervisor.shutdown().await.unwrap();
        let outcome = negotiate_route(&mut runtime, &handle).await;
        let mut preface = vec![0_u8; encode_route_preface_v2(&handle).unwrap().len()];
        supervisor.read_exact(&mut preface).await.unwrap();
        assert_eq!(preface, encode_route_preface_v2(&handle).unwrap());
        let mut rest = Vec::new();
        runtime.read_to_end(&mut rest).await.unwrap();
        (outcome, rest)
    }

    #[tokio::test]
    async fn negotiation_reads_only_the_declared_reply_and_rejects_malformed_replies() {
        // The TLS handshake starts right after an accept.
        let (outcome, rest) = negotiate_scripted(b"\x01\x00\x16\x03\x01").await;
        assert_eq!(outcome.unwrap(), RouteReply::Accept(None));
        assert_eq!(rest, b"\x16\x03\x01");
        let (outcome, rest) = negotiate_scripted(b"\x01\x0d10.0.0.4:7443\x16").await;
        assert_eq!(
            outcome.unwrap(),
            RouteReply::Accept(Some("10.0.0.4:7443".parse().unwrap()))
        );
        assert_eq!(rest, b"\x16");
        let (outcome, rest) = negotiate_scripted(b"\x02\x0d10.0.0.2:7443trailing").await;
        assert_eq!(
            outcome.unwrap(),
            RouteReply::Redirect("10.0.0.2:7443".parse().unwrap())
        );
        assert_eq!(rest, b"trailing");
        assert_eq!(
            negotiate_scripted(&redirect_reply("[fd00::2]:7443".parse().unwrap()).unwrap())
                .await
                .0
                .unwrap(),
            RouteReply::Redirect("[fd00::2]:7443".parse().unwrap())
        );
        assert_eq!(
            negotiate_scripted(b"\x03").await.0.unwrap(),
            RouteReply::Unknown
        );
        for malformed in [
            b"".as_slice(),
            b"\x01",
            b"\x01\x05local",
            b"\x04",
            b"\x02",
            b"\x02\x00",
            b"\x02\x0810.0.0.2",
            b"\x02\x0d10.0.0.2",
            b"\x02\x0enot-an-address",
        ] {
            assert!(negotiate_scripted(malformed).await.0.is_err());
        }
    }
}
