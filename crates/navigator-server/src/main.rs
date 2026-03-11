// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OpenShell` Server - gRPC/HTTP server with protocol multiplexing.

use clap::Parser;
use miette::{IntoDiagnostic, Result};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

use navigator_server::{run_server, tracing_bus::TracingLogBus};

/// `OpenShell` Server - gRPC and HTTP server with protocol multiplexing.
#[derive(Parser, Debug)]
#[command(name = "navigator-server")]
#[command(about = "OpenShell gRPC/HTTP server", long_about = None)]
struct Args {
    /// Port to bind the server to (all interfaces).
    #[arg(long, default_value_t = 8080, env = "OPENSHELL_SERVER_PORT")]
    port: u16,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = "info", env = "OPENSHELL_LOG_LEVEL")]
    log_level: String,

    /// Path to TLS certificate file (required unless --disable-tls).
    #[arg(long, env = "OPENSHELL_TLS_CERT")]
    tls_cert: Option<PathBuf>,

    /// Path to TLS private key file (required unless --disable-tls).
    #[arg(long, env = "OPENSHELL_TLS_KEY")]
    tls_key: Option<PathBuf>,

    /// Path to CA certificate for client certificate verification (mTLS).
    #[arg(long, env = "OPENSHELL_TLS_CLIENT_CA")]
    tls_client_ca: Option<PathBuf>,

    /// Database URL for persistence.
    #[arg(long, env = "OPENSHELL_DB_URL", required = true)]
    db_url: String,

    /// Kubernetes namespace for sandboxes.
    #[arg(long, env = "OPENSHELL_SANDBOX_NAMESPACE", default_value = "default")]
    sandbox_namespace: String,

    /// Default container image for sandboxes.
    #[arg(long, env = "OPENSHELL_SANDBOX_IMAGE")]
    sandbox_image: Option<String>,

    /// gRPC endpoint for sandboxes to callback to `OpenShell`.
    /// This should be reachable from within the Kubernetes cluster.
    #[arg(long, env = "OPENSHELL_GRPC_ENDPOINT")]
    grpc_endpoint: Option<String>,

    /// Public host for the SSH gateway.
    #[arg(long, env = "OPENSHELL_SSH_GATEWAY_HOST", default_value = "127.0.0.1")]
    ssh_gateway_host: String,

    /// Public port for the SSH gateway.
    #[arg(long, env = "OPENSHELL_SSH_GATEWAY_PORT", default_value_t = 8080)]
    ssh_gateway_port: u16,

    /// HTTP path for SSH CONNECT/upgrade.
    #[arg(
        long,
        env = "OPENSHELL_SSH_CONNECT_PATH",
        default_value = "/connect/ssh"
    )]
    ssh_connect_path: String,

    /// SSH port inside sandbox pods.
    #[arg(long, env = "OPENSHELL_SANDBOX_SSH_PORT", default_value_t = 2222)]
    sandbox_ssh_port: u16,

    /// Shared secret for gateway-to-sandbox SSH handshake.
    #[arg(long, env = "OPENSHELL_SSH_HANDSHAKE_SECRET")]
    ssh_handshake_secret: Option<String>,

    /// Allowed clock skew in seconds for SSH handshake.
    #[arg(long, env = "OPENSHELL_SSH_HANDSHAKE_SKEW_SECS", default_value_t = 300)]
    ssh_handshake_skew_secs: u64,

    /// Kubernetes secret name containing client TLS materials for sandbox pods.
    #[arg(long, env = "OPENSHELL_CLIENT_TLS_SECRET_NAME")]
    client_tls_secret_name: Option<String>,

    /// Disable TLS entirely — listen on plaintext HTTP.
    /// Use this when the gateway sits behind a reverse proxy or tunnel
    /// (e.g. Cloudflare Tunnel) that terminates TLS at the edge.
    #[arg(long, env = "OPENSHELL_DISABLE_TLS")]
    disable_tls: bool,

    /// Disable gateway authentication (mTLS client certificate requirement).
    /// When set, the TLS handshake accepts connections without a client
    /// certificate. Ignored when --disable-tls is set.
    #[arg(long, env = "OPENSHELL_DISABLE_GATEWAY_AUTH")]
    disable_gateway_auth: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|e| miette::miette!("failed to install rustls crypto provider: {e:?}"))?;

    let args = Args::parse();

    // Initialize tracing
    let tracing_log_bus = TracingLogBus::new();
    tracing_log_bus.install_subscriber(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
    );

    // Build configuration
    let bind = SocketAddr::from(([0, 0, 0, 0], args.port));

    let tls = if args.disable_tls {
        None
    } else {
        let cert_path = args.tls_cert.ok_or_else(|| {
            miette::miette!(
                "--tls-cert is required when TLS is enabled (use --disable-tls to skip)"
            )
        })?;
        let key_path = args.tls_key.ok_or_else(|| {
            miette::miette!("--tls-key is required when TLS is enabled (use --disable-tls to skip)")
        })?;
        let client_ca_path = args.tls_client_ca.ok_or_else(|| {
            miette::miette!(
                "--tls-client-ca is required when TLS is enabled (use --disable-tls to skip)"
            )
        })?;
        Some(navigator_core::TlsConfig {
            cert_path,
            key_path,
            client_ca_path,
            allow_unauthenticated: args.disable_gateway_auth,
        })
    };

    let mut config = navigator_core::Config::new(tls)
        .with_bind_address(bind)
        .with_log_level(&args.log_level);

    config = config
        .with_database_url(args.db_url)
        .with_sandbox_namespace(args.sandbox_namespace)
        .with_ssh_gateway_host(args.ssh_gateway_host)
        .with_ssh_gateway_port(args.ssh_gateway_port)
        .with_ssh_connect_path(args.ssh_connect_path)
        .with_sandbox_ssh_port(args.sandbox_ssh_port)
        .with_ssh_handshake_skew_secs(args.ssh_handshake_skew_secs);

    if let Some(image) = args.sandbox_image {
        config = config.with_sandbox_image(image);
    }

    if let Some(endpoint) = args.grpc_endpoint {
        config = config.with_grpc_endpoint(endpoint);
    }

    if let Some(secret) = args.ssh_handshake_secret {
        config = config.with_ssh_handshake_secret(secret);
    }

    if let Some(name) = args.client_tls_secret_name {
        config = config.with_client_tls_secret_name(name);
    }

    if args.disable_tls {
        info!("TLS disabled — listening on plaintext HTTP");
    } else if args.disable_gateway_auth {
        info!("Gateway auth disabled — accepting connections without client certificates");
    }

    info!(bind = %config.bind_address, "Starting OpenShell server");

    run_server(config, tracing_log_bus).await.into_diagnostic()
}
