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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openshell_isolation_interface::contract::{BackendError, BoundaryDuplexStream};
use tokio::io::{AsyncRead, AsyncReadExt as _};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

use crate::boundary_protocol::SandboxTlsClientConfig;

/// First bytes of a routing preface.
pub const ROUTE_PREFACE_MAGIC: [u8; 4] = *b"OSRP";
/// Routing preface layout version.
pub const ROUTE_PREFACE_VERSION: u8 = 1;
/// Longest accepted route handle, in bytes.
pub const MAX_ROUTE_HANDLE_LEN: usize = 64;
const MIN_ROUTE_HANDLE_LEN: usize = 16;

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
    validate_route_handle(handle)?;
    let length = u8::try_from(handle.len())
        .map_err(|_| BackendError::Descriptor("runtime route handle is too long".to_string()))?;
    let mut preface = Vec::with_capacity(ROUTE_PREFACE_MAGIC.len() + 2 + handle.len());
    preface.extend_from_slice(&ROUTE_PREFACE_MAGIC);
    preface.push(ROUTE_PREFACE_VERSION);
    preface.push(length);
    preface.extend_from_slice(handle.as_bytes());
    Ok(preface)
}

/// Read and validate one routing preface. Reads only the declared bytes.
async fn read_route_preface<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<String> {
    let invalid = |message: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, message);
    let mut header = [0_u8; 6];
    stream.read_exact(&mut header).await?;
    if header[..4] != ROUTE_PREFACE_MAGIC {
        return Err(invalid("missing runtime routing preface"));
    }
    if header[4] != ROUTE_PREFACE_VERSION {
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
    Ok(handle)
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

    /// Wait for one authenticated connection for `descriptor`'s sandbox
    /// instance.
    pub(crate) async fn accept(
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
    let handle = tokio::time::timeout_at(deadline, read_route_preface(&mut stream))
        .await
        .map_err(|_| "routing preface timed out".to_string())?
        .map_err(|error| format!("routing preface: {error}"))?;
    // The handle only selects which pinned identity to expect.
    let (tls, spares, route_pending) = {
        let routes = lock(routes);
        let route = routes
            .by_handle
            .get(&handle)
            .ok_or_else(|| "unknown or retired runtime route handle".to_string())?;
        (
            route.tls.clone(),
            route.spares.clone(),
            route.pending.clone(),
        )
    };
    let Ok(_route_permit) = route_pending.try_acquire_owned() else {
        return Err("runtime route handshake limit reached".to_string());
    };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary_protocol::{SandboxTlsMaterial, generate_sandbox_tls_material};
    use tokio::io::AsyncWriteExt as _;

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
    async fn preface_round_trips_and_rejects_malformed_input() {
        let handle = new_route_handle();
        let encoded = encode_route_preface(&handle).unwrap();
        assert_eq!(
            read_route_preface(&mut encoded.as_slice()).await.unwrap(),
            handle
        );
        let mut wrong_version = encoded.clone();
        wrong_version[4] = 2;
        for malformed in [
            b"TLS\x16\x03\x01".to_vec(),
            wrong_version,
            [b"OSRP\x01\x41".as_slice(), &[b'a'; 65]].concat(),
            [b"OSRP\x01\x10".as_slice(), b"UPPERCASE-HANDLE"].concat(),
        ] {
            assert!(read_route_preface(&mut malformed.as_slice()).await.is_err());
        }
        assert!(encode_route_preface("short").is_err());
    }
}
