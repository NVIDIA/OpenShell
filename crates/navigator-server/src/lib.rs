// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OpenShell` Server library.
//!
//! This crate provides the server implementation for `OpenShell`, including:
//! - gRPC service implementation
//! - HTTP health endpoints
//! - Protocol multiplexing (gRPC + HTTP on same port)
//! - mTLS support

mod auth;
mod grpc;
mod http;
mod inference;
pub mod mechanistic_mapper;
mod multiplex;
mod persistence;
mod sandbox;
mod sandbox_index;
mod sandbox_watch;
mod ssh_tunnel;
mod tls;
pub mod tracing_bus;
mod ws_tunnel;

use navigator_core::{Config, Error, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tracing::{error, info};

pub use grpc::NavigatorService;
pub use http::{health_router, http_router};
pub use multiplex::{MultiplexService, MultiplexedService};
use persistence::Store;
use sandbox::{SandboxClient, spawn_sandbox_watcher, spawn_store_reconciler};
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

    /// Active SSH tunnel connection counts per session token.
    pub ssh_connections_by_token: Mutex<HashMap<String, u32>>,

    /// Active SSH tunnel connection counts per sandbox id.
    pub ssh_connections_by_sandbox: Mutex<HashMap<String, u32>>,
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
    ) -> Self {
        Self {
            config,
            store,
            sandbox_client,
            sandbox_index,
            sandbox_watch_bus,
            tracing_log_bus,
            ssh_connections_by_token: Mutex::new(HashMap::new()),
            ssh_connections_by_sandbox: Mutex::new(HashMap::new()),
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
pub async fn run_server(config: Config, tracing_log_bus: TracingLogBus) -> Result<()> {
    let database_url = config.database_url.trim();
    if database_url.is_empty() {
        return Err(Error::config("database_url is required"));
    }
    if config.ssh_handshake_secret.is_empty() {
        return Err(Error::config(
            "ssh_handshake_secret is required. Set --ssh-handshake-secret or OPENSHELL_SSH_HANDSHAKE_SECRET",
        ));
    }

    let store = Store::connect(database_url).await?;
    let sandbox_client = SandboxClient::new(
        config.sandbox_namespace.clone(),
        config.sandbox_image.clone(),
        config.grpc_endpoint.clone(),
        format!("0.0.0.0:{}", config.sandbox_ssh_port),
        config.ssh_handshake_secret.clone(),
        config.ssh_handshake_skew_secs,
        config.client_tls_secret_name.clone(),
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
    ));

    spawn_sandbox_watcher(
        store.clone(),
        state.sandbox_client.clone(),
        state.sandbox_index.clone(),
        state.sandbox_watch_bus.clone(),
        state.tracing_log_bus.clone(),
    );
    spawn_store_reconciler(
        store.clone(),
        state.sandbox_client.clone(),
        state.sandbox_index.clone(),
        state.sandbox_watch_bus.clone(),
        state.tracing_log_bus.clone(),
    );
    spawn_kube_event_tailer(state.clone());
    ssh_tunnel::spawn_session_reaper(store.clone(), std::time::Duration::from_secs(3600));

    // Create the multiplexed service
    let service = MultiplexService::new(state.clone());

    // Bind the TCP listener
    let listener = TcpListener::bind(config.bind_address)
        .await
        .map_err(|e| Error::transport(format!("failed to bind to {}: {e}", config.bind_address)))?;

    info!(address = %config.bind_address, "Server listening");

    // Build TLS acceptor when TLS is configured; otherwise serve plaintext.
    let tls_acceptor = if let Some(tls) = &config.tls {
        Some(TlsAcceptor::from_files(
            &tls.cert_path,
            &tls.key_path,
            &tls.client_ca_path,
            tls.allow_unauthenticated,
        )?)
    } else {
        info!("TLS disabled — accepting plaintext connections");
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

        if let Some(ref acceptor) = tls_acceptor {
            let tls_acceptor = acceptor.clone();
            tokio::spawn(async move {
                match tls_acceptor.inner().accept(stream).await {
                    Ok(tls_stream) => {
                        if let Err(e) = service.serve(tls_stream).await {
                            error!(error = %e, client = %addr, "Connection error");
                        }
                    }
                    Err(e) => {
                        error!(error = %e, client = %addr, "TLS handshake failed");
                    }
                }
            });
        } else {
            tokio::spawn(async move {
                if let Err(e) = service.serve(stream).await {
                    error!(error = %e, client = %addr, "Connection error");
                }
            });
        }
    }
}
