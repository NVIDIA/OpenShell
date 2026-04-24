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
//! [`ComputeDriverKind`] and calls driver-specific constructors
//! ([`ComputeRuntime::new_kubernetes`], [`compute::vm::spawn`] +
//! [`ComputeRuntime::new_remote_vm`]). Once we have a generalized compute
//! driver interface, the per-arm wiring here should collapse to a single
//! driver-agnostic path that asks each registered driver to produce a
//! [`Channel`](tonic::transport::Channel) and hands the rest of the gateway a
//! uniform [`ComputeRuntime`]. The remaining VM plumbing now lives in
//! [`compute::vm`]; keep this file driver-agnostic going forward.

mod auth;
pub mod cli;
mod compute;
mod grpc;
mod http;
mod inference;
mod multiplex;
mod persistence;
mod sandbox_index;
mod sandbox_watch;
mod ssh_tunnel;
pub mod supervisor_session;
mod tls;
pub mod tracing_bus;
mod ws_tunnel;

use metrics_exporter_prometheus::PrometheusBuilder;
use openshell_core::{ComputeDriverKind, Config, Error, Result};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{debug, error, info};

use compute::{ComputeRuntime, VmComputeConfig};
pub use grpc::OpenShellService;
pub use http::{health_router, http_router, metrics_router};
pub use multiplex::{MultiplexService, MultiplexedService};
use openshell_driver_kubernetes::KubernetesComputeConfig;
use persistence::Store;
use sandbox_index::SandboxIndex;
use sandbox_watch::SandboxWatchBus;
pub use tls::TlsAcceptor;
use tracing_bus::TracingLogBus;

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
    pub supervisor_sessions: Arc<supervisor_session::SupervisorSessionRegistry>,
}

fn is_benign_tls_handshake_failure(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset
    )
}

impl ServerState {
    /// Create new server state.
    #[must_use]
    pub fn new(
        config: Config,
        store: Arc<Store>,
        compute: ComputeRuntime,
        sandbox_index: SandboxIndex,
        sandbox_watch_bus: SandboxWatchBus,
        tracing_log_bus: TracingLogBus,
        supervisor_sessions: Arc<supervisor_session::SupervisorSessionRegistry>,
    ) -> Self {
        Self {
            config,
            store,
            compute,
            sandbox_index,
            sandbox_watch_bus,
            tracing_log_bus,
            ssh_connections_by_token: Mutex::new(HashMap::new()),
            ssh_connections_by_sandbox: Mutex::new(HashMap::new()),
            settings_mutex: tokio::sync::Mutex::new(()),
            supervisor_sessions,
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
pub async fn run_server(
    config: Config,
    vm_config: VmComputeConfig,
    tracing_log_bus: TracingLogBus,
) -> Result<()> {
    let database_url = config.database_url.trim();
    if database_url.is_empty() {
        return Err(Error::config("database_url is required"));
    }
    if config.ssh_handshake_secret.is_empty() {
        return Err(Error::config(
            "ssh_handshake_secret is required. Set --ssh-handshake-secret or OPENSHELL_SSH_HANDSHAKE_SECRET",
        ));
    }

    let store = Arc::new(Store::connect(database_url).await?);

    let sandbox_index = SandboxIndex::new();
    let sandbox_watch_bus = SandboxWatchBus::new();
    let supervisor_sessions = Arc::new(supervisor_session::SupervisorSessionRegistry::new());
    let compute = build_compute_runtime(
        &config,
        &vm_config,
        store.clone(),
        sandbox_index.clone(),
        sandbox_watch_bus.clone(),
        tracing_log_bus.clone(),
        supervisor_sessions.clone(),
    )
    .await?;
    let state = Arc::new(ServerState::new(
        config.clone(),
        store.clone(),
        compute,
        sandbox_index,
        sandbox_watch_bus,
        tracing_log_bus,
        supervisor_sessions,
    ));

    state.compute.spawn_watchers();
    ssh_tunnel::spawn_session_reaper(store.clone(), Duration::from_secs(3600));
    supervisor_session::spawn_relay_reaper(state.clone(), Duration::from_secs(30));

    // Create the multiplexed service
    let service = MultiplexService::new(state.clone());

    // Bind the TCP listener
    let listener = TcpListener::bind(config.bind_address)
        .await
        .map_err(|e| Error::transport(format!("failed to bind to {}: {e}", config.bind_address)))?;

    info!(address = %config.bind_address, "Server listening");

    // Bind the unauthenticated health endpoint on a separate port when configured.
    if let Some(health_bind_address) = config.health_bind_address {
        let health_listener = TcpListener::bind(health_bind_address).await.map_err(|e| {
            Error::transport(format!(
                "failed to bind health port {}: {e}",
                health_bind_address
            ))
        })?;
        info!(address = %health_bind_address, "Health server listening");
        tokio::spawn(async move {
            if let Err(e) = axum::serve(health_listener, health_router().into_make_service()).await
            {
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
                        if is_benign_tls_handshake_failure(&e) {
                            debug!(error = %e, client = %addr, "TLS handshake closed early");
                        } else {
                            error!(error = %e, client = %addr, "TLS handshake failed");
                        }
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

async fn build_compute_runtime(
    config: &Config,
    vm_config: &VmComputeConfig,
    store: Arc<Store>,
    sandbox_index: SandboxIndex,
    sandbox_watch_bus: SandboxWatchBus,
    tracing_log_bus: TracingLogBus,
    supervisor_sessions: Arc<supervisor_session::SupervisorSessionRegistry>,
) -> Result<ComputeRuntime> {
    let driver = configured_compute_driver(config)?;
    info!(driver = %driver, "Using compute driver");

    match driver {
        ComputeDriverKind::Kubernetes => ComputeRuntime::new_kubernetes(
            KubernetesComputeConfig {
                namespace: config.sandbox_namespace.clone(),
                default_image: config.sandbox_image.clone(),
                image_pull_policy: config.sandbox_image_pull_policy.clone(),
                grpc_endpoint: config.grpc_endpoint.clone(),
                // Filesystem path to the supervisor's Unix-socket SSH daemon.
                // The path lives in a root-only directory so only the
                // supervisor can connect; the gateway reaches it through the
                // RelayStream bridge, not directly. Override via
                // `sandbox_ssh_socket_path` in the config for deployments
                // where multiple supervisors share a filesystem.
                ssh_socket_path: config.sandbox_ssh_socket_path.clone(),
                ssh_handshake_secret: config.ssh_handshake_secret.clone(),
                ssh_handshake_skew_secs: config.ssh_handshake_skew_secs,
                client_tls_secret_name: config.client_tls_secret_name.clone(),
                host_gateway_ip: config.host_gateway_ip.clone(),
            },
            store,
            sandbox_index,
            sandbox_watch_bus,
            tracing_log_bus,
            supervisor_sessions.clone(),
        )
        .await
        .map_err(|e| Error::execution(format!("failed to create compute runtime: {e}"))),
        ComputeDriverKind::Vm => {
            let (channel, driver_process) = compute::vm::spawn(config, vm_config).await?;
            ComputeRuntime::new_remote_vm(
                channel,
                Some(driver_process),
                store,
                sandbox_index,
                sandbox_watch_bus,
                tracing_log_bus,
                supervisor_sessions,
            )
            .await
            .map_err(|e| Error::execution(format!("failed to create compute runtime: {e}")))
        }
        ComputeDriverKind::Podman => {
            let socket_path = std::env::var("OPENSHELL_PODMAN_SOCKET")
                .ok()
                .filter(|s| !s.is_empty())
                .map(std::path::PathBuf::from)
                .unwrap_or_else(openshell_driver_podman::PodmanComputeConfig::default_socket_path);

            let network_name = std::env::var("OPENSHELL_NETWORK_NAME")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| openshell_core::config::DEFAULT_NETWORK_NAME.to_string());

            let stop_timeout_secs: u32 = std::env::var("OPENSHELL_STOP_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(openshell_core::config::DEFAULT_STOP_TIMEOUT_SECS);

            let supervisor_image = std::env::var("OPENSHELL_SUPERVISOR_IMAGE")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| openshell_core::config::DEFAULT_SUPERVISOR_IMAGE.to_string());

            ComputeRuntime::new_podman(
                openshell_driver_podman::PodmanComputeConfig {
                    socket_path,
                    default_image: config.sandbox_image.clone(),
                    image_pull_policy: config.sandbox_image_pull_policy.parse().unwrap_or_default(),
                    grpc_endpoint: config.grpc_endpoint.clone(),
                    gateway_port: config.bind_address.port(),
                    sandbox_ssh_socket_path: config.sandbox_ssh_socket_path.clone(),
                    network_name,
                    ssh_listen_addr: format!("0.0.0.0:{}", config.sandbox_ssh_port),
                    ssh_port: config.sandbox_ssh_port,
                    ssh_handshake_secret: config.ssh_handshake_secret.clone(),
                    ssh_handshake_skew_secs: config.ssh_handshake_skew_secs,
                    stop_timeout_secs,
                    supervisor_image,
                },
                store,
                sandbox_index,
                sandbox_watch_bus,
                tracing_log_bus,
                supervisor_sessions,
            )
            .await
            .map_err(|e| Error::execution(format!("failed to create compute runtime: {e}")))
        }
    }
}

fn configured_compute_driver(config: &Config) -> Result<ComputeDriverKind> {
    match config.compute_drivers.as_slice() {
        [] => Err(Error::config(
            "at least one compute driver must be configured",
        )),
        [
            driver @ (ComputeDriverKind::Kubernetes
            | ComputeDriverKind::Vm
            | ComputeDriverKind::Podman),
        ] => Ok(*driver),
        drivers => Err(Error::config(format!(
            "multiple compute drivers are not supported yet; configured drivers: {}",
            drivers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{configured_compute_driver, is_benign_tls_handshake_failure};
    use openshell_core::{ComputeDriverKind, Config};
    use std::io::{Error, ErrorKind};

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
    fn configured_compute_driver_rejects_empty_drivers() {
        let config = Config::new(None).with_compute_drivers([]);
        let err = configured_compute_driver(&config).unwrap_err();
        assert!(err.to_string().contains("at least one compute driver"));
    }

    #[test]
    fn configured_compute_driver_rejects_multiple_entries() {
        let config = Config::new(None)
            .with_compute_drivers([ComputeDriverKind::Kubernetes, ComputeDriverKind::Podman]);
        let err = configured_compute_driver(&config).unwrap_err();
        assert!(
            err.to_string()
                .contains("multiple compute drivers are not supported yet")
        );
        assert!(err.to_string().contains("kubernetes,podman"));
    }

    #[test]
    fn configured_compute_driver_accepts_podman() {
        let config = Config::new(None).with_compute_drivers([ComputeDriverKind::Podman]);
        assert_eq!(
            configured_compute_driver(&config).unwrap(),
            ComputeDriverKind::Podman
        );
    }

    #[test]
    fn configured_compute_driver_accepts_vm() {
        let config = Config::new(None).with_compute_drivers([ComputeDriverKind::Vm]);
        assert_eq!(
            configured_compute_driver(&config).unwrap(),
            ComputeDriverKind::Vm
        );
    }
}
