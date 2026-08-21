// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use miette::{IntoDiagnostic, Result};
use openshell_core::proto::compute::v1::compute_driver_server::ComputeDriverServer;
use openshell_core::{Config, VERSION};
use openshell_driver_docker::{DockerComputeConfig, DockerComputeDriver};
use tracing::info;
use tracing_subscriber::EnvFilter;

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
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
        )
        .init();

    let config_source = std::fs::read_to_string(&args.config).into_diagnostic()?;
    let docker_config: DockerComputeConfig = toml::from_str(&config_source).into_diagnostic()?;
    let gateway_config = Config::new(None).with_bind_address(args.gateway_bind);
    let driver = DockerComputeDriver::new(&gateway_config, &docker_config)
        .await
        .into_diagnostic()?;

    let listener = openshell_core::external_driver_socket::bind_private(&args.bind_socket)
        .map_err(|err| miette::miette!("{err}"))?;
    let _cleanup =
        openshell_core::external_driver_socket::SocketCleanup::new(args.bind_socket.clone());
    info!(socket = %args.bind_socket.display(), "Starting Docker compute driver");
    tonic::transport::Server::builder()
        .add_service(ComputeDriverServer::new(driver))
        .serve_with_incoming_shutdown(
            openshell_core::external_driver_socket::SameUidUnixIncoming::new(listener),
            shutdown_signal(),
        )
        .await
        .into_diagnostic()
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
