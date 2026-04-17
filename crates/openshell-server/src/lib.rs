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
mod tls;
pub mod tracing_bus;
mod ws_tunnel;

use openshell_core::{ComputeDriverKind, Config, Error, Result};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{debug, error, info};

use compute::{ComputeRuntime, VmComputeConfig};
pub use grpc::OpenShellService;
pub use http::{health_router, http_router};
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
    let compute = build_compute_runtime(
        &config,
        &vm_config,
        store.clone(),
        sandbox_index.clone(),
        sandbox_watch_bus.clone(),
        tracing_log_bus.clone(),
    )
    .await?;
    let state = Arc::new(ServerState::new(
        config.clone(),
        store.clone(),
        compute,
        sandbox_index,
        sandbox_watch_bus,
        tracing_log_bus,
    ));

    state.compute.spawn_watchers();
    ssh_tunnel::spawn_session_reaper(store.clone(), Duration::from_secs(3600));

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
                ssh_listen_addr: format!("0.0.0.0:{}", config.sandbox_ssh_port),
                ssh_port: config.sandbox_ssh_port,
                ssh_handshake_secret: config.ssh_handshake_secret.clone(),
                ssh_handshake_skew_secs: config.ssh_handshake_skew_secs,
                client_tls_secret_name: config.client_tls_secret_name.clone(),
                host_gateway_ip: config.host_gateway_ip.clone(),
            },
            store,
            sandbox_index,
            sandbox_watch_bus,
            tracing_log_bus,
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
            )
            .await
            .map_err(|e| Error::execution(format!("failed to create compute runtime: {e}")))
        }
        ComputeDriverKind::Podman => Err(Error::config(
            "compute driver 'podman' is not implemented yet",
        )),
    }
}

fn configured_compute_driver(config: &Config) -> Result<ComputeDriverKind> {
    match config.compute_drivers.as_slice() {
        [] => Err(Error::config(
            "at least one compute driver must be configured",
        )),
        [driver @ ComputeDriverKind::Kubernetes] | [driver @ ComputeDriverKind::Vm] => Ok(*driver),
        [ComputeDriverKind::Podman] => Err(Error::config(
            "compute driver 'podman' is not implemented yet",
        )),
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
    fn configured_compute_driver_defaults_to_kubernetes() {
        assert_eq!(
            configured_compute_driver(&Config::new(None)).unwrap(),
            ComputeDriverKind::Kubernetes
        );
    }

    #[test]
    fn configured_compute_driver_requires_at_least_one_entry() {
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
    fn configured_compute_driver_rejects_unimplemented_driver() {
        let config = Config::new(None).with_compute_drivers([ComputeDriverKind::Podman]);
        let err = configured_compute_driver(&config).unwrap_err();
        assert!(
            err.to_string()
                .contains("compute driver 'podman' is not implemented yet")
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
