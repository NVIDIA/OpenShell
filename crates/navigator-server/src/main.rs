// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Navigator Server - gRPC/HTTP server with protocol multiplexing.

use clap::Parser;
use miette::{IntoDiagnostic, Result};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

use navigator_server::{run_server, tracing_bus::TracingLogBus};

/// Navigator Server - gRPC and HTTP server with protocol multiplexing.
#[derive(Parser, Debug)]
#[command(name = "navigator-server")]
#[command(about = "Navigator gRPC/HTTP server", long_about = None)]
struct Args {
    /// Port to bind the server to (all interfaces).
    #[arg(long, default_value_t = 8080, env = "NAVIGATOR_SERVER_PORT")]
    port: u16,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = "info", env = "NAVIGATOR_LOG_LEVEL")]
    log_level: String,

    /// Path to TLS certificate file.
    #[arg(long, env = "NAVIGATOR_TLS_CERT")]
    tls_cert: PathBuf,

    /// Path to TLS private key file.
    #[arg(long, env = "NAVIGATOR_TLS_KEY")]
    tls_key: PathBuf,

    /// Path to CA certificate for client certificate verification (mTLS).
    #[arg(long, env = "NAVIGATOR_TLS_CLIENT_CA")]
    tls_client_ca: PathBuf,

    /// Database URL for persistence.
    #[arg(long, env = "NAVIGATOR_DB_URL", required = true)]
    db_url: String,

    /// Kubernetes namespace for sandboxes.
    #[arg(long, env = "NAVIGATOR_SANDBOX_NAMESPACE", default_value = "default")]
    sandbox_namespace: String,

    /// Default container image for sandboxes.
    #[arg(long, env = "NAVIGATOR_SANDBOX_IMAGE")]
    sandbox_image: Option<String>,

    /// gRPC endpoint for sandboxes to callback to Navigator.
    /// This should be reachable from within the Kubernetes cluster.
    #[arg(long, env = "NAVIGATOR_GRPC_ENDPOINT")]
    grpc_endpoint: Option<String>,

    /// Public host for the SSH gateway.
    #[arg(long, env = "NAVIGATOR_SSH_GATEWAY_HOST", default_value = "127.0.0.1")]
    ssh_gateway_host: String,

    /// Public port for the SSH gateway.
    #[arg(long, env = "NAVIGATOR_SSH_GATEWAY_PORT", default_value_t = 8080)]
    ssh_gateway_port: u16,

    /// HTTP path for SSH CONNECT/upgrade.
    #[arg(
        long,
        env = "NAVIGATOR_SSH_CONNECT_PATH",
        default_value = "/connect/ssh"
    )]
    ssh_connect_path: String,

    /// SSH port inside sandbox pods.
    #[arg(long, env = "NAVIGATOR_SANDBOX_SSH_PORT", default_value_t = 2222)]
    sandbox_ssh_port: u16,

    /// Shared secret for gateway-to-sandbox SSH handshake.
    #[arg(long, env = "NAVIGATOR_SSH_HANDSHAKE_SECRET")]
    ssh_handshake_secret: Option<String>,

    /// Allowed clock skew in seconds for SSH handshake.
    #[arg(long, env = "NAVIGATOR_SSH_HANDSHAKE_SKEW_SECS", default_value_t = 300)]
    ssh_handshake_skew_secs: u64,

    /// Kubernetes secret name containing client TLS materials for sandbox pods.
    #[arg(long, env = "NAVIGATOR_CLIENT_TLS_SECRET_NAME")]
    client_tls_secret_name: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
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

    let tls = navigator_core::TlsConfig {
        cert_path: args.tls_cert,
        key_path: args.tls_key,
        client_ca_path: args.tls_client_ca,
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

    info!(bind = %config.bind_address, "Starting Navigator server");

    run_server(config, tracing_log_bus).await.into_diagnostic()
}
