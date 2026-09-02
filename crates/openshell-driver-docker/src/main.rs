// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use miette::{IntoDiagnostic, Result};
use openshell_core::VERSION;
use openshell_core::proto::compute::v1::compute_driver_server::ComputeDriverServer;
use openshell_driver_docker::otel_tracing::compute_driver_rpc_layer;
use openshell_driver_docker::{ComputeDriverService, DockerComputeConfig, DockerComputeDriver};
use tracing::info;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

#[derive(Debug, Parser)]
#[command(name = "openshell-driver-docker", version = VERSION)]
struct Args {
    /// Public compute-driver Unix socket used by the gateway.
    #[arg(long, env = "OPENSHELL_COMPUTE_DRIVER_SOCKET")]
    bind_socket: PathBuf,

    /// TOML file containing a serialized `DockerComputeConfig` table.
    #[arg(long, env = "OPENSHELL_DOCKER_DRIVER_CONFIG")]
    config: PathBuf,

    /// Gateway listener address used to derive sandbox callback routing.
    #[arg(
        long,
        env = "OPENSHELL_GATEWAY_BIND",
        default_value = "127.0.0.1:50051"
    )]
    gateway_bind: SocketAddr,

    #[arg(long, env = "OPENSHELL_LOG_LEVEL", default_value = "info")]
    log_level: String,

    #[arg(long, env = "OPENSHELL_OTLP_ENDPOINT")]
    otlp_endpoint: Option<String>,

    #[arg(long, env = "OPENSHELL_GATEWAY_NAME")]
    gateway_name: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let (tracer_provider, setup_error) = openshell_driver_docker::otel_tracing::provider_for(
        args.otlp_endpoint.as_deref(),
        args.gateway_name.as_deref(),
    );
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level)))
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracer_provider
                .as_ref()
                .map(openshell_driver_docker::otel_tracing::layer),
        )
        .init();
    if let Some(error) = setup_error {
        tracing::error!(%error, "OTLP exporting could not be started");
    } else if let Some(endpoint) = &args.otlp_endpoint {
        info!(endpoint, "OTLP exporting enabled");
    }

    let config_source = std::fs::read_to_string(&args.config).into_diagnostic()?;
    let docker_config: DockerComputeConfig = toml::from_str(&config_source).into_diagnostic()?;
    let driver = DockerComputeDriver::new(args.gateway_bind, &args.log_level, &docker_config)
        .await
        .into_diagnostic()?;

    let listener = openshell_core::external_driver_socket::bind_private(&args.bind_socket)
        .map_err(|err| miette::miette!("{err}"))?;
    let _cleanup =
        openshell_core::external_driver_socket::SocketCleanup::new(args.bind_socket.clone());
    info!(socket = %args.bind_socket.display(), "Starting Docker compute driver");
    let result = tonic::transport::Server::builder()
        .layer(compute_driver_rpc_layer())
        .add_service(ComputeDriverServer::new(ComputeDriverService::new(driver)))
        .serve_with_incoming_shutdown(
            openshell_core::external_driver_socket::SameUidUnixIncoming::new(listener),
            shutdown_signal(),
        )
        .await
        .into_diagnostic();
    if let Some(provider) = &tracer_provider
        && let Err(error) = provider.shutdown()
    {
        tracing::warn!(%error, "OTLP tracer provider shutdown failed");
    }
    result
}

async fn shutdown_signal() {
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        () = terminate => {}
    }
    info!("Received shutdown signal, draining in-flight requests");
}
