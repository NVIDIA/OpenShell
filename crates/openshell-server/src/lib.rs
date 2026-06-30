// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OpenShell` Server library.
//!
//! This crate provides the server implementation for `OpenShell`, including:
//! - gRPC service implementation
//! - HTTP health endpoints
//! - Protocol multiplexing (gRPC + HTTP on same port)
//! - mTLS support
//!
//! TODO(driver-abstraction): `build_compute_runtime` still switches on
//! built-in driver names and calls driver-specific constructors
//! ([`ComputeRuntime::new_kubernetes`], [`ComputeRuntime::new_docker`],
//! [`compute::vm::spawn`] + [`ComputeRuntime::new_remote_driver`],
//! [`ComputeRuntime::new_podman`]). Endpoint-backed drivers now share the
//! remote `compute_driver.proto` path, so new remote drivers should enter
//! through named endpoint acquisition rather than gateway-wide socket side
//! channels. Once we have a generalized compute-driver registry, the remaining
//! per-arm wiring here should collapse to driver construction records that
//! produce either an in-process `SharedComputeDriver` or an acquired remote
//! endpoint, then hand the rest of the gateway a uniform [`ComputeRuntime`].
//! The VM launch plumbing now lives in [`compute::vm`]; keep this file limited
//! to selecting and acquiring drivers.

mod auth;
pub mod certgen;
pub mod cli;
mod compute;
pub mod config_file;
mod defaults;
mod grpc;
mod http;
mod inference;
mod multiplex;
mod persistence;
pub(crate) mod policy_store;
mod provider_refresh;
mod readiness;
mod sandbox_index;
mod sandbox_watch;
mod service_routing;
mod ssh_sessions;
pub mod supervisor_session;
mod telemetry;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
mod tls;
#[cfg(test)]
pub(crate) mod tls_test_utils;
pub mod tracing_bus;
mod ws_tunnel;

use metrics_exporter_prometheus::PrometheusBuilder;
use openshell_core::{ComputeDriverKind, Config, Error, Result};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
#[cfg(test)]
use std::sync::LazyLock;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

use compute::ComputeRuntime;
pub use grpc::OpenShellService;
pub use http::{health_router, http_router, metrics_router, service_http_router};
pub use multiplex::{MultiplexService, MultiplexedService};
pub use persistence::Store;
use sandbox_index::SandboxIndex;
use sandbox_watch::SandboxWatchBus;
pub use tls::TlsAcceptor;
use tracing_bus::TracingLogBus;

pub(crate) struct ServerStartupConfig {
    pub config: Config,
    pub config_file: Option<config_file::ConfigFile>,
    pub guest_tls: Option<compute::driver_config::GuestTlsPaths>,
}

/// Server state shared across handlers.
#[derive(Debug)]
pub struct ServerState {
    /// Server configuration.
    pub config: Config,

    /// Persistence store.
    pub store: Arc<Store>,

    /// Compute orchestration over the configured driver.
    pub compute: ComputeRuntime,

    /// In-memory sandbox correlation index.
    pub sandbox_index: SandboxIndex,

    /// In-memory bus for sandbox update notifications.
    pub sandbox_watch_bus: SandboxWatchBus,

    /// In-memory bus for server process logs.
    pub tracing_log_bus: TracingLogBus,

    /// In-memory anonymous telemetry accounting for active sandbox sessions.
    pub(crate) telemetry: telemetry::TelemetryState,

    /// Active SSH tunnel connection counts per session token.
    pub ssh_connections_by_token: Mutex<HashMap<String, u32>>,

    /// Active SSH tunnel connection counts per sandbox id.
    pub ssh_connections_by_sandbox: Mutex<HashMap<String, u32>>,

    /// Serializes settings mutations (global and sandbox) to prevent
    /// read-modify-write races. Held for the duration of any setting
    /// set/delete operation, including the precedence check on sandbox
    /// mutations that reads global state.
    pub settings_mutex: tokio::sync::Mutex<()>,

    /// Registry of active supervisor sessions and pending relay channels.
    ///
    /// Stored as `Arc` so compute drivers (e.g. the Docker driver)
    /// can be constructed before `ServerState` and still
    /// query session state to surface supervisor readiness.
    pub supervisor_sessions: Arc<supervisor_session::SupervisorSessionRegistry>,

    /// OIDC JWKS cache for JWT validation. `None` when OIDC is not configured.
    pub oidc_cache: Option<Arc<auth::oidc::JwksCache>>,

    /// Gateway-minted sandbox JWT issuer. `None` when `config.gateway_jwt`
    /// is not configured; in that mode `IssueSandboxToken` returns
    /// `Status::unavailable`. Populated at startup from the on-disk key
    /// material that `certgen` writes.
    pub sandbox_jwt_issuer: Option<Arc<auth::sandbox_jwt::SandboxJwtIssuer>>,

    /// Authenticator that validates gateway-minted sandbox JWTs on every
    /// inbound request. Always set when `sandbox_jwt_issuer` is, so callers
    /// presenting a freshly minted token are recognized.
    pub sandbox_jwt_authenticator: Option<Arc<auth::sandbox_jwt::SandboxJwtAuthenticator>>,

    /// Optional K8s `ServiceAccount` authenticator that backs the
    /// `IssueSandboxToken` bootstrap path. Only present when the gateway
    /// runs in-cluster.
    pub k8s_sa_authenticator: Option<Arc<auth::k8s_sa::K8sServiceAccountAuthenticator>>,

    /// Gateway-wide gRPC request rate limiter shared by every multiplex path.
    pub(crate) grpc_rate_limiter: Option<multiplex::GrpcRateLimiter>,
}

fn is_benign_tls_handshake_failure(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset
    )
}

fn is_benign_connection_close(error: &(dyn std::error::Error + 'static)) -> bool {
    let msg = error.to_string();
    msg.contains("connection closed")
        || msg.contains("connection reset")
        || msg.contains("connection error")
        || msg.contains("error reading a body from connection")
        || msg.contains("broken pipe")
}

impl ServerState {
    /// Create new server state.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Config,
        store: Arc<Store>,
        compute: ComputeRuntime,
        sandbox_index: SandboxIndex,
        sandbox_watch_bus: SandboxWatchBus,
        tracing_log_bus: TracingLogBus,
        supervisor_sessions: Arc<supervisor_session::SupervisorSessionRegistry>,
        oidc_cache: Option<Arc<auth::oidc::JwksCache>>,
    ) -> Self {
        let grpc_rate_limiter = multiplex::GrpcRateLimiter::from_config(&config);
        Self {
            config,
            store,
            compute,
            sandbox_index,
            sandbox_watch_bus,
            tracing_log_bus,
            telemetry: telemetry::TelemetryState::new(),
            ssh_connections_by_token: Mutex::new(HashMap::new()),
            ssh_connections_by_sandbox: Mutex::new(HashMap::new()),
            settings_mutex: tokio::sync::Mutex::new(()),
            supervisor_sessions,
            oidc_cache,
            sandbox_jwt_issuer: None,
            sandbox_jwt_authenticator: None,
            k8s_sa_authenticator: None,
            grpc_rate_limiter,
        }
    }
}

/// Run the `OpenShell` server.
///
/// This starts a multiplexed gRPC/HTTP server on the configured bind address.
///
/// # Errors
///
/// Returns an error if the server fails to start or encounters a fatal error.
pub(crate) async fn run_server(
    startup: ServerStartupConfig,
    tracing_log_bus: TracingLogBus,
) -> Result<()> {
    let ServerStartupConfig {
        config,
        config_file,
        guest_tls,
    } = startup;

    let database_url = config.database_url.trim();
    if database_url.is_empty() {
        return Err(Error::config("database_url is required"));
    }

    let store = Arc::new(Store::connect(database_url).await?);

    let oidc_cache = if let Some(ref oidc) = config.oidc {
        // Validate RBAC configuration before starting.
        let policy = auth::authz::AuthzPolicy {
            admin_role: oidc.admin_role.clone(),
            user_role: oidc.user_role.clone(),
            scopes_enabled: !oidc.scopes_claim.is_empty(),
        };
        policy.validate().map_err(Error::config)?;

        let cache = auth::oidc::JwksCache::new(oidc)
            .await
            .map_err(|e| Error::config(format!("OIDC initialization failed: {e}")))?;
        info!("OIDC JWT validation enabled (issuer: {})", oidc.issuer);
        Some(Arc::new(cache))
    } else {
        None
    };

    let sandbox_index = SandboxIndex::new();
    let sandbox_watch_bus = SandboxWatchBus::new();
    let supervisor_sessions = Arc::new(supervisor_session::SupervisorSessionRegistry::new());
    let driver_startup = compute::driver_config::DriverStartupContext {
        file: config_file.as_ref(),
        guest_tls: guest_tls.as_ref(),
        gateway_port: config.bind_address.port(),
        gateway_tls_enabled: config.tls.is_some(),
        endpoint_overrides: &config.compute_driver_endpoints,
    };
    let compute = build_compute_runtime(
        &config,
        driver_startup,
        store.clone(),
        sandbox_index.clone(),
        sandbox_watch_bus.clone(),
        tracing_log_bus.clone(),
        supervisor_sessions.clone(),
    )
    .await?;
    let mut state = ServerState::new(
        config.clone(),
        store.clone(),
        compute,
        sandbox_index,
        sandbox_watch_bus,
        tracing_log_bus,
        supervisor_sessions,
        oidc_cache,
    );

    // Load the gateway-minted sandbox JWT signing key when configured.
    // Optional so single-driver dev deployments without certgen continue
    // to start. The helm-deployed gateway and the RPM init script populate
    // `gateway_jwt` once `certgen` has produced the on-disk material.
    if let Some(ref jwt) = config.gateway_jwt {
        let signing_pem = std::fs::read(&jwt.signing_key_path).map_err(|e| {
            Error::config(format!(
                "failed to read sandbox JWT signing key from {}: {e}",
                jwt.signing_key_path.display()
            ))
        })?;
        let public_pem = std::fs::read(&jwt.public_key_path).map_err(|e| {
            Error::config(format!(
                "failed to read sandbox JWT public key from {}: {e}",
                jwt.public_key_path.display()
            ))
        })?;
        let kid = std::fs::read_to_string(&jwt.kid_path)
            .map_err(|e| {
                Error::config(format!(
                    "failed to read sandbox JWT kid from {}: {e}",
                    jwt.kid_path.display()
                ))
            })?
            .trim()
            .to_string();
        if kid.is_empty() {
            return Err(Error::config(format!(
                "sandbox JWT kid file {} is empty",
                jwt.kid_path.display()
            )));
        }
        let issuer = auth::sandbox_jwt::SandboxJwtIssuer::from_pem(
            &signing_pem,
            kid.clone(),
            &jwt.gateway_id,
            Duration::from_secs(jwt.ttl_secs),
        )
        .map_err(Error::config)?;
        let authenticator =
            auth::sandbox_jwt::SandboxJwtAuthenticator::from_pem(&public_pem, kid, &jwt.gateway_id)
                .map_err(Error::config)?;
        info!(
            gateway_id = %jwt.gateway_id,
            ttl_secs = jwt.ttl_secs,
            "gateway-minted sandbox JWT enabled"
        );
        state.sandbox_jwt_issuer = Some(Arc::new(issuer));
        state.sandbox_jwt_authenticator = Some(Arc::new(authenticator));
    }

    // K8s ServiceAccount bootstrap authenticator. Only constructed when
    // the gateway is running in-cluster (kubelet provides the API host
    // env var) and has a sandbox JWT issuer to mint replacements against;
    // outside the cluster we can't call the apiserver's TokenReview API,
    // and without the issuer there's nothing to exchange the SA token for.
    if state.sandbox_jwt_issuer.is_some() && std::env::var_os("KUBERNETES_SERVICE_HOST").is_some() {
        // Pod lookups and TokenReview identity checks must match the sandbox
        // namespace and service account used by the Kubernetes driver.
        let kubernetes_config =
            compute::driver_config::kubernetes_config_for_k8s_sa_bootstrap(config_file.as_ref())?;
        let sandbox_namespace = kubernetes_config.namespace;
        let sandbox_service_account = kubernetes_config.service_account_name;
        match kube::Client::try_default().await {
            Ok(client) => {
                let resolver = Arc::new(auth::k8s_sa::LiveK8sResolver::new(
                    client,
                    &sandbox_namespace,
                    "openshell-gateway".to_string(),
                    sandbox_service_account.clone(),
                ));
                let authenticator = auth::k8s_sa::K8sServiceAccountAuthenticator::new(resolver);
                state.k8s_sa_authenticator = Some(Arc::new(authenticator));
                info!(
                    namespace = %sandbox_namespace,
                    service_account = %sandbox_service_account,
                    "K8s ServiceAccount bootstrap authenticator enabled"
                );
            }
            Err(e) => warn!(
                error = %e,
                "in-cluster K8s client construction failed; \
                 K8s ServiceAccount bootstrap is disabled"
            ),
        }
    }

    let state = Arc::new(state);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Resume sandboxes that were stopped during the previous gateway
    // shutdown so the running compute state matches the persisted store.
    // Runs before watchers spawn so the watch loop sees the post-resume
    // snapshot on its first poll.
    if let Err(err) = state.compute.resume_persisted_sandboxes().await {
        warn!(error = %err, "Failed to resume persisted sandboxes during startup");
    }

    state.compute.spawn_watchers(shutdown_rx.clone());
    ssh_sessions::spawn_session_reaper(store.clone(), Duration::from_secs(3600));
    supervisor_session::spawn_relay_reaper(state.clone(), Duration::from_secs(30));
    provider_refresh::spawn_refresh_worker(state.clone(), Duration::from_secs(60));

    // Create the multiplexed service
    let service = MultiplexService::new(state.clone());

    let gateway_listener_addresses =
        gateway_listener_addresses(config.bind_address, state.compute.gateway_bind_addresses());
    let mut gateway_listeners = Vec::with_capacity(gateway_listener_addresses.len());
    for address in gateway_listener_addresses {
        let listener = TcpListener::bind(address)
            .await
            .map_err(|e| Error::transport(format!("failed to bind to {address}: {e}")))?;
        let local_addr = listener.local_addr().unwrap_or(address);
        info!(address = %local_addr, "Server listening");
        gateway_listeners.push((listener, local_addr));
    }

    // Bind the unauthenticated health endpoint on a separate port when configured.
    if let Some(health_bind_address) = config.health_bind_address {
        let health_listener = TcpListener::bind(health_bind_address).await.map_err(|e| {
            Error::transport(format!(
                "failed to bind health port {health_bind_address}: {e}"
            ))
        })?;
        info!(address = %health_bind_address, "Health server listening");
        // `health_router` returns immediately; the listener serves
        // `Initializing → 503` until the background monitor publishes the
        // first real probe outcome, so the endpoint is always responsive.
        let router = health_router(store.clone());
        tokio::spawn(async move {
            if let Err(e) = axum::serve(health_listener, router.into_make_service()).await {
                error!("Health server error: {e}");
            }
        });
    } else {
        info!("Health server disabled");
    }

    // Bind the Prometheus metrics endpoint on a dedicated port when configured.
    if let Some(metrics_bind_address) = config.metrics_bind_address {
        let prometheus_handle = PrometheusBuilder::new()
            .install_recorder()
            .map_err(|e| Error::config(format!("failed to install metrics recorder: {e}")))?;
        let metrics_listener = TcpListener::bind(metrics_bind_address).await.map_err(|e| {
            Error::transport(format!(
                "failed to bind metrics port {metrics_bind_address}: {e}",
            ))
        })?;
        info!(address = %metrics_bind_address, "Metrics server listening");
        tokio::spawn(async move {
            if let Err(e) = axum::serve(
                metrics_listener,
                metrics_router(prometheus_handle).into_make_service(),
            )
            .await
            {
                error!("Metrics server error: {e}");
            }
        });
    } else {
        info!("Metrics server disabled");
    }

    // Build TLS acceptor when TLS is configured; otherwise serve plaintext.
    let tls_acceptor = if let Some(tls) = &config.tls {
        let acceptor = TlsAcceptor::from_files(
            &tls.cert_path,
            &tls.key_path,
            tls.client_ca_path.as_deref(),
            tls.require_client_auth,
        )?;

        // Spawn file-watcher-based TLS certificate reload worker.
        // Watches parent directories of cert/key/CA files and atomically
        // reloads when changes are detected.
        acceptor.spawn_reload_worker(shutdown_rx.clone());

        Some(acceptor)
    } else {
        info!("TLS disabled — accepting plaintext connections");
        None
    };

    let mut listener_tasks = Vec::with_capacity(gateway_listeners.len());
    let enable_loopback_service_http = config.service_routing.enable_loopback_service_http;
    for (listener, listen_addr) in gateway_listeners {
        listener_tasks.push(tokio::spawn(serve_gateway_listener(
            listener,
            listen_addr,
            service.clone(),
            tls_acceptor.clone(),
            enable_loopback_service_http,
            shutdown_rx.clone(),
        )));
    }

    shutdown_signal().await;
    info!("Shutdown signal received; stopping gateway");
    let _ = shutdown_tx.send(true);

    for task in listener_tasks {
        if let Err(err) = task.await {
            warn!(error = %err, "Gateway listener task failed during shutdown");
        }
    }

    state
        .compute
        .cleanup_on_shutdown()
        .await
        .map_err(|err| Error::execution(format!("gateway shutdown cleanup failed: {err}")))?;

    Ok(())
}

fn gateway_listener_addresses(
    bind_address: SocketAddr,
    extra_addresses: &[SocketAddr],
) -> Vec<SocketAddr> {
    let mut addresses = vec![bind_address];
    for address in extra_addresses {
        if !addresses
            .iter()
            .any(|existing| listener_covers(*existing, *address))
        {
            addresses.push(*address);
        }
    }
    addresses
}

fn listener_covers(existing: SocketAddr, requested: SocketAddr) -> bool {
    if existing == requested {
        return true;
    }
    if existing.port() != requested.port() {
        return false;
    }

    match (existing.ip(), requested.ip()) {
        (std::net::IpAddr::V4(existing), std::net::IpAddr::V4(_)) => existing.is_unspecified(),
        (std::net::IpAddr::V6(existing), std::net::IpAddr::V6(_)) => existing.is_unspecified(),
        _ => false,
    }
}

async fn serve_gateway_listener(
    listener: TcpListener,
    listen_addr: SocketAddr,
    service: MultiplexService,
    tls_acceptor: Option<TlsAcceptor>,
    enable_loopback_service_http: bool,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let accepted = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
            accepted = listener.accept() => accepted,
        };

        let (stream, addr) = match accepted {
            Ok(conn) => conn,
            Err(e) => {
                error!(error = %e, listen = %listen_addr, "Failed to accept connection");
                continue;
            }
        };

        spawn_gateway_connection(
            stream,
            addr,
            listen_addr,
            service.clone(),
            tls_acceptor.clone(),
            enable_loopback_service_http,
        );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionProtocol {
    Tls,
    PlainHttp,
    Unknown,
}

async fn classify_connection_protocol(stream: &TcpStream) -> std::io::Result<ConnectionProtocol> {
    let mut prefix = [0_u8; 8];
    let read = stream.peek(&mut prefix).await?;
    Ok(classify_initial_bytes(&prefix[..read]))
}

fn classify_initial_bytes(prefix: &[u8]) -> ConnectionProtocol {
    if looks_like_tls(prefix) {
        ConnectionProtocol::Tls
    } else if looks_like_http(prefix) {
        ConnectionProtocol::PlainHttp
    } else {
        ConnectionProtocol::Unknown
    }
}

fn looks_like_tls(prefix: &[u8]) -> bool {
    prefix.len() >= 3 && prefix[0] == 0x16 && prefix[1] == 0x03
}

fn looks_like_http(prefix: &[u8]) -> bool {
    const METHODS: [&[u8]; 10] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"PATCH ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"TRACE ",
        b"CONNECT ",
        b"PRI ",
    ];

    if prefix.is_empty() {
        return false;
    }
    METHODS
        .iter()
        .any(|method| method.starts_with(prefix) || prefix.starts_with(method))
}

fn allow_plaintext_service_http(
    enabled: bool,
    listen_addr: SocketAddr,
    peer_addr: SocketAddr,
) -> bool {
    enabled && listen_addr.ip().is_loopback() && peer_addr.ip().is_loopback()
}

fn spawn_gateway_connection(
    stream: TcpStream,
    addr: SocketAddr,
    listen_addr: SocketAddr,
    service: MultiplexService,
    tls_acceptor: Option<TlsAcceptor>,
    enable_loopback_service_http: bool,
) {
    if let Some(acceptor) = tls_acceptor {
        tokio::spawn(async move {
            match classify_connection_protocol(&stream).await {
                Ok(ConnectionProtocol::PlainHttp)
                    if allow_plaintext_service_http(
                        enable_loopback_service_http,
                        listen_addr,
                        addr,
                    ) =>
                {
                    if let Err(e) = service.serve_service_http(stream).await {
                        if is_benign_connection_close(e.as_ref()) {
                            debug!(error = %e, client = %addr, listen = %listen_addr, "Plaintext service HTTP connection closed");
                        } else {
                            error!(error = %e, client = %addr, listen = %listen_addr, "Plaintext service HTTP connection error");
                        }
                    }
                }
                Ok(ConnectionProtocol::PlainHttp) => {
                    warn!(client = %addr, listen = %listen_addr, "Rejected plaintext HTTP on non-loopback gateway listener");
                }
                Ok(ConnectionProtocol::Tls | ConnectionProtocol::Unknown) => {
                    // acceptor.acceptor() snapshots the current TLS config;
                    // the returned acceptor owns an Arc that stays alive for
                    // the full duration of the handshake.
                    match acceptor.acceptor().accept(stream).await {
                        Ok(tls_stream) => {
                            let peer_identity = multiplex::extract_peer_identity(&tls_stream);
                            if let Err(e) = service
                                .serve_with_peer_identity(tls_stream, peer_identity)
                                .await
                            {
                                if is_benign_connection_close(e.as_ref()) {
                                    debug!(error = %e, client = %addr, "Connection closed");
                                } else {
                                    error!(error = %e, client = %addr, "Connection error");
                                }
                            }
                        }
                        Err(e) => {
                            if is_benign_tls_handshake_failure(&e) {
                                debug!(error = %e, client = %addr, "TLS handshake closed early");
                            } else {
                                error!(error = %e, client = %addr, "TLS handshake failed");
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!(error = %e, client = %addr, "Failed to inspect connection preface");
                }
            }
        });
    } else {
        tokio::spawn(async move {
            if let Err(e) = service.serve(stream).await {
                if is_benign_connection_close(e.as_ref()) {
                    debug!(error = %e, client = %addr, "Connection closed");
                } else {
                    error!(error = %e, client = %addr, "Connection error");
                }
            }
        });
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        tokio::select! {
            () = ctrl_c_signal() => {}
            () = terminate_signal() => {}
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c_signal().await;
    }
}

async fn ctrl_c_signal() {
    if let Err(err) = tokio::signal::ctrl_c().await {
        warn!(error = %err, "Failed to install Ctrl-C signal handler");
        std::future::pending::<()>().await;
    }
}

#[cfg(unix)]
async fn terminate_signal() {
    let Ok(mut signal) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    else {
        warn!("Failed to install SIGTERM signal handler");
        std::future::pending::<()>().await;
        return;
    };
    let _ = signal.recv().await;
}

// Internal wiring helper: each argument is a distinct piece of runtime state
// that must be passed through, so the count is justified.
#[allow(clippy::too_many_arguments)]
async fn build_compute_runtime(
    config: &Config,
    driver_startup: compute::driver_config::DriverStartupContext<'_>,
    store: Arc<Store>,
    sandbox_index: SandboxIndex,
    sandbox_watch_bus: SandboxWatchBus,
    tracing_log_bus: TracingLogBus,
    supervisor_sessions: Arc<supervisor_session::SupervisorSessionRegistry>,
) -> Result<ComputeRuntime> {
    let driver = configured_compute_driver(config, driver_startup)?;
    info!(driver = %driver.name(), "Using compute driver");

    let runtime = match driver {
        ConfiguredComputeDriver::Builtin(ComputeDriverKind::Kubernetes) => {
            warn_if_kubernetes_sandbox_jwt_expiry_disabled(config);
            let k8s_config =
                compute::driver_config::kubernetes_config_from_context(driver_startup)?;
            ComputeRuntime::new_kubernetes(
                k8s_config,
                store,
                sandbox_index,
                sandbox_watch_bus,
                tracing_log_bus,
                supervisor_sessions.clone(),
            )
            .await
        }
        ConfiguredComputeDriver::Builtin(ComputeDriverKind::Docker) => {
            let docker_config = compute::driver_config::docker_config_from_context(driver_startup)?;
            ComputeRuntime::new_docker(
                config.clone(),
                docker_config,
                store,
                sandbox_index,
                sandbox_watch_bus,
                tracing_log_bus,
                supervisor_sessions,
            )
            .await
        }
        ConfiguredComputeDriver::Builtin(ComputeDriverKind::Podman) => {
            let podman_config = compute::driver_config::podman_config_from_context(driver_startup)?;
            ComputeRuntime::new_podman(
                podman_config,
                store,
                sandbox_index,
                sandbox_watch_bus,
                tracing_log_bus,
                supervisor_sessions,
            )
            .await
        }
        ConfiguredComputeDriver::Builtin(ComputeDriverKind::Vm) => {
            let vm_config = compute::driver_config::vm_config_from_context(driver_startup)?;
            let endpoint = compute::vm::spawn(config, &vm_config).await?;
            ComputeRuntime::new_remote_driver(
                endpoint,
                store,
                sandbox_index,
                sandbox_watch_bus,
                tracing_log_bus,
                supervisor_sessions,
            )
            .await
        }
        ConfiguredComputeDriver::Remote { name } => {
            let remote_config =
                compute::driver_config::remote_driver_config_from_context(driver_startup, &name)?;
            info!(
                driver = %name,
                socket = %remote_config.socket_path.display(),
                "Using remote compute driver endpoint"
            );
            let endpoint = compute::connect_remote_compute_driver(name, &remote_config.socket_path)
                .await
                .map_err(|e| Error::execution(format!("failed to create compute runtime: {e}")))?;
            ComputeRuntime::new_remote_driver(
                endpoint,
                store,
                sandbox_index,
                sandbox_watch_bus,
                tracing_log_bus,
                supervisor_sessions,
            )
            .await
        }
    };

    runtime.map_err(|e| Error::execution(format!("failed to create compute runtime: {e}")))
}

#[derive(Debug, Clone)]
enum ConfiguredComputeDriver {
    Builtin(ComputeDriverKind),
    Remote { name: String },
}

impl ConfiguredComputeDriver {
    fn name(&self) -> &str {
        match self {
            Self::Builtin(kind) => kind.as_str(),
            Self::Remote { name } => name,
        }
    }
}

fn configured_compute_driver(
    config: &Config,
    driver_startup: compute::driver_config::DriverStartupContext<'_>,
) -> Result<ConfiguredComputeDriver> {
    match config.compute_drivers.as_slice() {
        [] => match openshell_core::config::detect_driver() {
            Some(ComputeDriverKind::Vm) => Err(Error::config(
                "vm compute driver is opt-in only; set --drivers vm or OPENSHELL_DRIVERS=vm",
            )),
            Some(driver) => Ok(ConfiguredComputeDriver::Builtin(driver)),
            None => Err(Error::config(
                "no compute driver configured and auto-detection found no suitable driver; \
                set --drivers or OPENSHELL_DRIVERS to kubernetes, podman, docker, or vm",
            )),
        },
        [driver] => resolve_configured_compute_driver(driver, driver_startup),
        drivers => Err(Error::config(format!(
            "multiple compute drivers are not supported yet; configured drivers: {}",
            drivers.join(",")
        ))),
    }
}

fn resolve_configured_compute_driver(
    driver_name: &str,
    driver_startup: compute::driver_config::DriverStartupContext<'_>,
) -> Result<ConfiguredComputeDriver> {
    let name = openshell_core::config::normalize_compute_driver_name(driver_name)
        .map_err(Error::config)?;
    let driver_kind = builtin_compute_driver(&name);
    if driver_kind.is_some() && driver_startup.endpoint_overrides.contains_key(&name) {
        return Err(Error::config(format!(
            "compute driver '{name}' is a reserved built-in driver and cannot be selected with a socket endpoint"
        )));
    }

    if let Some(kind) = driver_kind {
        return Ok(ConfiguredComputeDriver::Builtin(kind));
    }

    Ok(ConfiguredComputeDriver::Remote { name })
}

fn builtin_compute_driver(name: &str) -> Option<ComputeDriverKind> {
    name.parse().ok()
}

fn kubernetes_sandbox_jwt_expiry_disabled(config: &Config) -> bool {
    config
        .gateway_jwt
        .as_ref()
        .is_some_and(|jwt| jwt.ttl_secs == 0)
}

fn warn_if_kubernetes_sandbox_jwt_expiry_disabled(config: &Config) {
    if kubernetes_sandbox_jwt_expiry_disabled(config) {
        warn!(
            "Kubernetes gateway configured with non-expiring sandbox JWTs (gateway_jwt.ttl_secs = 0); set ttl_secs > 0 for shared Kubernetes deployments"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ConfiguredComputeDriver, ConnectionProtocol, MultiplexService, ServerState, TlsAcceptor,
        allow_plaintext_service_http, classify_initial_bytes, configured_compute_driver,
        gateway_listener_addresses, is_benign_tls_handshake_failure,
        kubernetes_sandbox_jwt_expiry_disabled, serve_gateway_listener,
    };
    use openshell_core::{
        ComputeDriverKind, Config,
        proto::{HealthRequest, open_shell_client::OpenShellClient},
    };
    use std::io::{Error, ErrorKind};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::{TempDir, tempdir};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::watch;

    use crate::tls_test_utils::{generate_test_certs_with_ca, install_rustls_provider};

    fn test_driver_startup<'a>(
        config: &'a Config,
        file: Option<&'a super::config_file::ConfigFile>,
    ) -> crate::compute::driver_config::DriverStartupContext<'a> {
        crate::compute::driver_config::DriverStartupContext {
            file,
            guest_tls: None,
            gateway_port: openshell_core::config::DEFAULT_SERVER_PORT,
            gateway_tls_enabled: false,
            endpoint_overrides: &config.compute_driver_endpoints,
        }
    }

    fn test_tls_acceptor() -> (TempDir, TlsAcceptor) {
        install_rustls_provider();

        let dir = tempdir().expect("failed to create tempdir");
        generate_test_certs_with_ca(dir.path());

        let acceptor = TlsAcceptor::from_files(
            &dir.path().join("server-cert.pem"),
            &dir.path().join("server-key.pem"),
            Some(&dir.path().join("ca.pem")),
            false,
        )
        .expect("failed to build tls acceptor");

        (dir, acceptor)
    }

    async fn test_state(
        bind_addr: SocketAddr,
        enable_loopback_service_http: bool,
    ) -> Arc<ServerState> {
        let store = Arc::new(
            crate::persistence::Store::connect("sqlite::memory:?cache=shared")
                .await
                .expect("failed to create test store"),
        );
        let compute = crate::compute::new_test_runtime(store.clone()).await;
        Arc::new(ServerState::new(
            Config::new(None)
                .with_database_url("sqlite::memory:?cache=shared")
                .with_bind_address(bind_addr)
                .with_server_sans(["*.dev.openshell.localhost"])
                .with_loopback_service_http(enable_loopback_service_http),
            store,
            compute,
            crate::sandbox_index::SandboxIndex::new(),
            crate::sandbox_watch::SandboxWatchBus::new(),
            crate::tracing_bus::TracingLogBus::new(),
            Arc::new(crate::supervisor_session::SupervisorSessionRegistry::new()),
            None,
        ))
    }

    async fn start_tls_gateway_listener(
        bind_addr: &str,
        enable_loopback_service_http: bool,
    ) -> (
        SocketAddr,
        watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
        TempDir,
    ) {
        let listener = TcpListener::bind(bind_addr)
            .await
            .expect("failed to bind test listener");
        let listen_addr = listener.local_addr().expect("failed to read local addr");
        let state = test_state(listen_addr, enable_loopback_service_http).await;
        let service = MultiplexService::new(state);
        let (tls_dir, tls_acceptor) = test_tls_acceptor();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(serve_gateway_listener(
            listener,
            listen_addr,
            service,
            Some(tls_acceptor),
            enable_loopback_service_http,
            shutdown_rx,
        ));
        (listen_addr, shutdown_tx, handle, tls_dir)
    }

    async fn send_plain_http(addr: SocketAddr, request: String) -> String {
        let connect_addr: SocketAddr = format!("127.0.0.1:{}", addr.port())
            .parse()
            .expect("failed to build loopback connect addr");
        let mut stream = TcpStream::connect(connect_addr)
            .await
            .expect("failed to connect to test listener");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("failed to write request");

        let mut response = Vec::new();
        let read_result =
            tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
                .await
                .expect("timed out reading response");
        if let Err(err) = read_result
            && err.kind() != ErrorKind::ConnectionReset
        {
            panic!("failed to read response: {err}");
        }
        String::from_utf8_lossy(&response).into_owned()
    }

    fn service_request(addr: SocketAddr, extra_headers: &[(&str, &str)]) -> String {
        let mut request = format!(
            "GET / HTTP/1.1\r\nHost: my-sandbox--web.dev.openshell.localhost:{}\r\nConnection: close\r\n",
            addr.port()
        );
        for (name, value) in extra_headers {
            request.push_str(name);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        request
    }

    async fn stop_listener(shutdown: watch::Sender<bool>, handle: tokio::task::JoinHandle<()>) {
        let _ = shutdown.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    #[test]
    fn classifies_probe_style_tls_disconnects_as_benign() {
        for kind in [ErrorKind::UnexpectedEof, ErrorKind::ConnectionReset] {
            let error = Error::new(kind, "probe disconnected");
            assert!(is_benign_tls_handshake_failure(&error));
        }
    }

    #[test]
    fn preserves_real_tls_failures_as_errors() {
        for kind in [
            ErrorKind::InvalidData,
            ErrorKind::PermissionDenied,
            ErrorKind::Other,
        ] {
            let error = Error::new(kind, "real tls failure");
            assert!(!is_benign_tls_handshake_failure(&error));
        }
    }

    #[test]
    fn classifies_tls_and_plain_http_prefaces() {
        assert_eq!(
            classify_initial_bytes(&[0x16, 0x03, 0x01, 0x00]),
            ConnectionProtocol::Tls
        );
        assert_eq!(
            classify_initial_bytes(b"GET / HTTP/1.1\r\n"),
            ConnectionProtocol::PlainHttp
        );
        assert_eq!(classify_initial_bytes(b"G"), ConnectionProtocol::PlainHttp);
        assert_eq!(
            classify_initial_bytes(b"\x00\x01\x02"),
            ConnectionProtocol::Unknown
        );
    }

    #[test]
    fn plaintext_service_http_requires_loopback_listener_and_peer() {
        let loopback: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let peer: SocketAddr = "127.0.0.1:54000".parse().unwrap();
        let wildcard: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let remote_peer: SocketAddr = "192.0.2.10:54000".parse().unwrap();

        assert!(allow_plaintext_service_http(true, loopback, peer));
        assert!(!allow_plaintext_service_http(false, loopback, peer));
        assert!(!allow_plaintext_service_http(true, wildcard, peer));
        assert!(!allow_plaintext_service_http(true, loopback, remote_peer));
    }

    #[tokio::test]
    async fn plaintext_service_http_listener_rejects_non_loopback_bind() {
        let (addr, shutdown, handle, _tls_dir) =
            start_tls_gateway_listener("0.0.0.0:0", true).await;

        let response = send_plain_http(addr, service_request(addr, &[])).await;

        assert!(
            response.is_empty(),
            "non-loopback gateway listener should drop plaintext service HTTP, got: {response:?}"
        );
        stop_listener(shutdown, handle).await;
    }

    #[tokio::test]
    async fn plaintext_service_http_rejects_cross_origin_browser_contexts() {
        let (addr, shutdown, handle, _tls_dir) =
            start_tls_gateway_listener("127.0.0.1:0", true).await;
        let cases = [
            (
                "cross-site fetch metadata",
                vec![("Sec-Fetch-Site", "cross-site")],
            ),
            (
                "same-site sibling fetch metadata",
                vec![("Sec-Fetch-Site", "same-site")],
            ),
            (
                "mismatched origin",
                vec![(
                    "Origin",
                    "http://other-sandbox--web.dev.openshell.localhost:8080",
                )],
            ),
            (
                "mismatched referer",
                vec![(
                    "Referer",
                    "http://other-sandbox--web.dev.openshell.localhost:8080/page",
                )],
            ),
        ];

        for (name, headers) in cases {
            let response = send_plain_http(addr, service_request(addr, &headers)).await;

            assert!(
                response.starts_with("HTTP/1.1 403 Forbidden"),
                "{name} should be rejected before service lookup, got: {response:?}"
            );
            assert!(
                response.contains("Cross-origin service request rejected"),
                "{name} should explain the service rejection, got: {response:?}"
            );
        }
        stop_listener(shutdown, handle).await;
    }

    #[tokio::test]
    async fn plaintext_service_http_allows_same_origin_browser_context_to_reach_service_lookup() {
        let (addr, shutdown, handle, _tls_dir) =
            start_tls_gateway_listener("127.0.0.1:0", true).await;
        let origin = format!(
            "http://my-sandbox--web.dev.openshell.localhost:{}",
            addr.port()
        );
        let response = send_plain_http(
            addr,
            service_request(
                addr,
                &[("Sec-Fetch-Site", "same-origin"), ("Origin", &origin)],
            ),
        )
        .await;

        assert!(
            response.starts_with("HTTP/1.1 404 Not Found"),
            "same-origin browser context should pass CSRF guard and miss only because no endpoint exists, got: {response:?}"
        );
        assert!(
            !response.contains("Cross-origin service request rejected"),
            "same-origin browser context should not be rejected as cross-origin, got: {response:?}"
        );
        stop_listener(shutdown, handle).await;
    }

    #[tokio::test]
    async fn plaintext_service_http_does_not_expose_grpc_gateway() {
        let (addr, shutdown, handle, _tls_dir) =
            start_tls_gateway_listener("127.0.0.1:0", true).await;
        let grpc_endpoint = format!("http://127.0.0.1:{}", addr.port());
        let grpc_succeeded = tokio::time::timeout(Duration::from_secs(2), async {
            match OpenShellClient::connect(grpc_endpoint).await {
                Ok(mut client) => client.health(HealthRequest {}).await.is_ok(),
                Err(_) => false,
            }
        })
        .await
        .expect("timed out checking plaintext gRPC exposure");

        assert!(
            !grpc_succeeded,
            "plaintext service HTTP must not expose successful gateway gRPC"
        );

        let request = format!(
            "POST /openshell.v1.OpenShell/Health HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/grpc\r\nTE: trailers\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            addr.port()
        );

        let response = send_plain_http(addr, request).await;

        assert!(
            response.starts_with("HTTP/1.1 404 Not Found"),
            "plaintext service HTTP router should not serve gateway gRPC, got: {response:?}"
        );
        assert!(
            !response.contains("grpc-status: 0"),
            "plaintext service HTTP must not return a successful gRPC response: {response:?}"
        );
        stop_listener(shutdown, handle).await;
    }

    #[test]
    fn configured_compute_driver_triggers_auto_detection_when_empty() {
        let config = Config::new(None).with_compute_drivers(std::iter::empty::<String>());
        // Empty drivers triggers auto-detection, which may return Some or None
        // depending on the environment. This test verifies the auto-detection path
        // is taken rather than immediately returning an error.
        let result = configured_compute_driver(&config, test_driver_startup(&config, None));
        // Either we get a detected driver or an error about none being detected.
        match result {
            Ok(ConfiguredComputeDriver::Builtin(driver)) => {
                assert!(
                    matches!(
                        driver,
                        ComputeDriverKind::Kubernetes
                            | ComputeDriverKind::Docker
                            | ComputeDriverKind::Podman
                    ),
                    "auto-detected unexpected driver: {driver:?}"
                );
            }
            Ok(ConfiguredComputeDriver::Remote { name }) => {
                panic!("auto-detection returned remote driver: {name}");
            }
            Err(e) => {
                assert!(
                    e.to_string()
                        .contains("auto-detection found no suitable driver"),
                    "unexpected error: {e}"
                );
            }
        }
    }

    #[test]
    fn configured_compute_driver_rejects_multiple_entries() {
        let config = Config::new(None)
            .with_compute_drivers([ComputeDriverKind::Kubernetes, ComputeDriverKind::Podman]);
        let err =
            configured_compute_driver(&config, test_driver_startup(&config, None)).unwrap_err();
        assert!(
            err.to_string()
                .contains("multiple compute drivers are not supported yet")
        );
        assert!(err.to_string().contains("kubernetes,podman"));
    }

    #[test]
    fn configured_compute_driver_accepts_podman() {
        let config = Config::new(None).with_compute_drivers([ComputeDriverKind::Podman]);
        let driver =
            configured_compute_driver(&config, test_driver_startup(&config, None)).unwrap();
        assert!(matches!(
            driver,
            ConfiguredComputeDriver::Builtin(ComputeDriverKind::Podman)
        ));
    }

    #[test]
    fn configured_compute_driver_accepts_vm() {
        let config = Config::new(None).with_compute_drivers([ComputeDriverKind::Vm]);
        let driver =
            configured_compute_driver(&config, test_driver_startup(&config, None)).unwrap();
        assert!(matches!(
            driver,
            ConfiguredComputeDriver::Builtin(ComputeDriverKind::Vm)
        ));
    }

    #[test]
    fn configured_compute_driver_accepts_docker() {
        let config = Config::new(None).with_compute_drivers([ComputeDriverKind::Docker]);
        let driver =
            configured_compute_driver(&config, test_driver_startup(&config, None)).unwrap();
        assert!(matches!(
            driver,
            ConfiguredComputeDriver::Builtin(ComputeDriverKind::Docker)
        ));
    }

    #[test]
    fn configured_compute_driver_resolves_named_remote() {
        let config = Config::new(None).with_compute_drivers(["kyma"]);

        let driver =
            configured_compute_driver(&config, test_driver_startup(&config, None)).unwrap();

        match driver {
            ConfiguredComputeDriver::Remote { name } => {
                assert_eq!(name, "kyma");
            }
            ConfiguredComputeDriver::Builtin(other) => {
                panic!("expected remote driver, got builtin driver {other:?}")
            }
        }
    }

    #[test]
    fn configured_compute_driver_rejects_vm_endpoint_from_config() {
        let config = Config::new(None)
            .with_compute_drivers([ComputeDriverKind::Vm])
            .with_compute_driver_endpoint("vm", "/run/openshell/vm.sock");

        let err =
            configured_compute_driver(&config, test_driver_startup(&config, None)).unwrap_err();

        assert!(
            err.to_string()
                .contains("reserved built-in driver and cannot be selected with a socket endpoint"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn configured_compute_driver_rejects_builtin_endpoint() {
        let config = Config::new(None)
            .with_compute_drivers([ComputeDriverKind::Docker])
            .with_compute_driver_endpoint("docker", "/run/openshell/docker.sock");

        let err =
            configured_compute_driver(&config, test_driver_startup(&config, None)).unwrap_err();

        assert!(
            err.to_string()
                .contains("cannot be selected with a socket endpoint"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn kubernetes_sandbox_jwt_expiry_disabled_warns_for_zero_ttl() {
        fn config_with_jwt_ttl(ttl_secs: u64) -> Config {
            let mut config = Config::new(None);
            config.gateway_jwt = Some(openshell_core::GatewayJwtConfig {
                signing_key_path: "/tmp/signing.pem".into(),
                public_key_path: "/tmp/public.pem".into(),
                kid_path: "/tmp/kid".into(),
                gateway_id: "openshell".to_string(),
                ttl_secs,
            });
            config
        }

        assert!(kubernetes_sandbox_jwt_expiry_disabled(
            &config_with_jwt_ttl(0)
        ));
        assert!(!kubernetes_sandbox_jwt_expiry_disabled(
            &config_with_jwt_ttl(3600)
        ));
        assert!(!kubernetes_sandbox_jwt_expiry_disabled(&Config::new(None)));
    }

    #[test]
    fn gateway_listener_addresses_skip_driver_address_covered_by_wildcard() {
        let primary: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let docker: SocketAddr = "172.18.0.1:8080".parse().unwrap();

        assert_eq!(
            gateway_listener_addresses(primary, &[docker, docker]),
            vec![primary]
        );
    }

    #[test]
    fn gateway_listener_addresses_include_driver_address_on_distinct_ip() {
        let primary: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let docker: SocketAddr = "172.18.0.1:8080".parse().unwrap();

        assert_eq!(
            gateway_listener_addresses(primary, &[docker, docker]),
            vec![primary, docker]
        );
    }
}
