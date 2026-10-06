// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use miette::{IntoDiagnostic, Result};
use ryno_core::VERSION;
use ryno_core::proto::compute::v1::compute_driver_server::ComputeDriverServer;
use ryno_driver_docker::{ComputeDriverService, DockerComputeConfig, DockerComputeDriver};
use tracing::info;

#[derive(Debug, Parser)]
#[command(name = "ryno-driver-docker", version = VERSION)]
struct Args {
    /// Override the operator admission policy in the driver TOML file.
    #[arg(long, env = "RYNO_DRIVER_ADMISSION_CONFIG_JSON")]
    admission_config_json: Option<ryno_core::resource_admission::DriverAdmissionConfig>,
    /// Public compute-driver Unix socket used by the gateway.
    #[arg(long, env = "RYNO_COMPUTE_DRIVER_SOCKET")]
    bind_socket: PathBuf,

    /// TOML file containing a serialized `DockerComputeConfig` table.
    #[arg(long, env = "RYNO_DOCKER_DRIVER_CONFIG")]
    config: PathBuf,

    /// Gateway listener address used to derive the supervisor endpoint.
    #[arg(long, env = "RYNO_GATEWAY_BIND", default_value = "127.0.0.1:50051")]
    gateway_bind: SocketAddr,

    #[arg(long, env = "RYNO_LOG_LEVEL", default_value = "info")]
    log_level: String,

    #[arg(long, env = "RYNO_OTLP_ENDPOINT")]
    otlp_endpoint: Option<String>,

    #[arg(long, env = "RYNO_GATEWAY_NAME")]
    gateway_name: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    ryno_core::compat::apply_legacy_env();
    let args = Args::parse();
    let _tracing = ryno_otel::install_driver_tracing(
        ryno_driver_docker::otel_tracing::TRACING,
        ryno_otel::DriverTracingConfig {
            endpoint: args.otlp_endpoint.as_deref(),
            gateway_name: args.gateway_name.as_deref(),
            service_version: VERSION,
            log_level: &args.log_level,
        },
    );

    let config_source = std::fs::read_to_string(&args.config).into_diagnostic()?;
    let mut docker_config: DockerComputeConfig =
        toml::from_str(&config_source).into_diagnostic()?;
    if let Some(policy) = args.admission_config_json {
        docker_config.allow_driver_config = policy.allow_driver_config;
        docker_config.resource_admission = policy.resource_admission;
    }
    let driver = DockerComputeDriver::new(args.gateway_bind, &args.log_level, &docker_config)
        .await
        .into_diagnostic()?;

    let listener = ryno_core::external_driver_socket::bind_private(&args.bind_socket)
        .map_err(|err| miette::miette!("{err}"))?;
    let _cleanup = ryno_core::external_driver_socket::SocketCleanup::new(args.bind_socket.clone());
    info!(socket = %args.bind_socket.display(), "Starting Docker compute driver");
    tonic::transport::Server::builder()
        .layer(ryno_otel::compute_driver_rpc_layer())
        .add_service(ComputeDriverServer::new(ComputeDriverService::new(driver)))
        .serve_with_incoming_shutdown(
            ryno_core::external_driver_socket::SameUidUnixIncoming::new(listener),
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
