//! Navigator Server library.
//!
//! This crate provides the server implementation for Navigator, including:
//! - gRPC service implementation
//! - HTTP health endpoints
//! - Protocol multiplexing (gRPC + HTTP on same port)
//! - Optional TLS support

mod grpc;
mod http;
mod inference;
mod multiplex;
mod persistence;
mod sandbox;
mod sandbox_index;
mod sandbox_watch;
mod ssh_tunnel;
mod tls;
pub mod tracing_bus;

use navigator_core::{Config, Error, Result};
use navigator_router::Router;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};

pub use grpc::NavigatorService;
pub use http::{health_router, http_router};
pub use multiplex::{MultiplexService, MultiplexedService};
use persistence::Store;
use sandbox::{SandboxClient, spawn_sandbox_watcher};
use sandbox_index::SandboxIndex;
use sandbox_watch::{SandboxWatchBus, spawn_kube_event_tailer};
pub use tls::TlsAcceptor;
use tracing_bus::TracingLogBus;

/// Server state shared across handlers.
#[derive(Debug)]
pub struct ServerState {
    /// Server configuration.
    pub config: Config,

    /// Persistence store.
    pub store: Arc<Store>,

    /// Kubernetes sandbox client.
    pub sandbox_client: SandboxClient,

    /// In-memory sandbox correlation index.
    pub sandbox_index: SandboxIndex,

    /// In-memory bus for sandbox update notifications.
    pub sandbox_watch_bus: SandboxWatchBus,

    /// In-memory bus for server process logs.
    pub tracing_log_bus: TracingLogBus,

    /// Inference router (None if not configured).
    pub router: Option<Router>,
}

impl ServerState {
    /// Create new server state.
    #[must_use]
    pub fn new(
        config: Config,
        store: Arc<Store>,
        sandbox_client: SandboxClient,
        sandbox_index: SandboxIndex,
        sandbox_watch_bus: SandboxWatchBus,
        tracing_log_bus: TracingLogBus,
        router: Option<Router>,
    ) -> Self {
        Self {
            config,
            store,
            sandbox_client,
            sandbox_index,
            sandbox_watch_bus,
            tracing_log_bus,
            router,
        }
    }
}

/// Run the Navigator server.
///
/// This starts a multiplexed gRPC/HTTP server on the configured bind address.
///
/// # Errors
///
/// Returns an error if the server fails to start or encounters a fatal error.
pub async fn run_server(
    config: Config,
    tracing_log_bus: TracingLogBus,
    router: Option<Router>,
) -> Result<()> {
    let database_url = config.database_url.trim();
    if database_url.is_empty() {
        return Err(Error::config("database_url is required"));
    }

    let store = Store::connect(database_url).await?;
    let sandbox_client = SandboxClient::new(
        config.sandbox_namespace.clone(),
        config.sandbox_image.clone(),
        config.grpc_endpoint.clone(),
        format!("0.0.0.0:{}", config.sandbox_ssh_port),
        config.ssh_handshake_secret.clone(),
        config.ssh_handshake_skew_secs,
    )
    .await
    .map_err(|e| Error::execution(format!("failed to create kubernetes client: {e}")))?;
    let store = Arc::new(store);

    let sandbox_index = SandboxIndex::new();
    let sandbox_watch_bus = SandboxWatchBus::new();
    let state = Arc::new(ServerState::new(
        config.clone(),
        store.clone(),
        sandbox_client,
        sandbox_index,
        sandbox_watch_bus,
        tracing_log_bus,
        router,
    ));

    spawn_sandbox_watcher(
        store.clone(),
        state.sandbox_client.clone(),
        state.sandbox_index.clone(),
        state.sandbox_watch_bus.clone(),
    );
    spawn_kube_event_tailer(state.clone());

    // Create the multiplexed service
    let service = MultiplexService::new(state.clone());

    // Bind the TCP listener
    let listener = TcpListener::bind(config.bind_address)
        .await
        .map_err(|e| Error::transport(format!("failed to bind to {}: {e}", config.bind_address)))?;

    info!(address = %config.bind_address, "Server listening");

    let tls_acceptor = if let Some(tls) = &config.tls {
        Some(TlsAcceptor::from_files(&tls.cert_path, &tls.key_path)?)
    } else {
        None
    };

    // Accept connections
    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!(error = %e, "Failed to accept connection");
                continue;
            }
        };

        let service = service.clone();
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            if let Some(tls) = tls_acceptor {
                match tls.inner().accept(stream).await {
                    Ok(tls_stream) => {
                        if let Err(e) = service.serve(tls_stream).await {
                            error!(error = %e, client = %addr, "Connection error");
                        }
                    }
                    Err(e) => {
                        error!(error = %e, client = %addr, "TLS handshake failed");
                    }
                }
            } else if let Err(e) = service.serve(stream).await {
                error!(error = %e, client = %addr, "Connection error");
            }
        });
    }
}
