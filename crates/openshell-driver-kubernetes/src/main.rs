// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use miette::{IntoDiagnostic, Result};
use std::net::SocketAddr;
use tracing::info;
use tracing_subscriber::EnvFilter;

use openshell_core::VERSION;
use openshell_core::proto::compute::v1::compute_driver_server::ComputeDriverServer;
use openshell_driver_kubernetes::{
    ComputeDriverService, KubernetesComputeConfig, KubernetesComputeDriver,
};

#[derive(Parser, Debug)]
#[command(name = "openshell-driver-kubernetes")]
#[command(version = VERSION)]
struct Args {
    #[arg(
        long,
        env = "OPENSHELL_COMPUTE_DRIVER_BIND",
        default_value = "127.0.0.1:50061"
    )]
    bind_address: SocketAddr,

    #[arg(long, env = "OPENSHELL_LOG_LEVEL", default_value = "info")]
    log_level: String,

    #[arg(long, env = "OPENSHELL_SANDBOX_NAMESPACE", default_value = "default")]
    sandbox_namespace: String,

    #[arg(long, env = "OPENSHELL_SANDBOX_IMAGE")]
    sandbox_image: Option<String>,

    #[arg(long, env = "OPENSHELL_SANDBOX_IMAGE_PULL_POLICY")]
    sandbox_image_pull_policy: Option<String>,

    #[arg(long, env = "OPENSHELL_GRPC_ENDPOINT")]
    grpc_endpoint: Option<String>,

    #[arg(long, env = "OPENSHELL_SANDBOX_SSH_PORT", default_value_t = 2222)]
    sandbox_ssh_port: u16,

    #[arg(long, env = "OPENSHELL_SSH_HANDSHAKE_SECRET")]
    ssh_handshake_secret: String,

    #[arg(long, env = "OPENSHELL_SSH_HANDSHAKE_SKEW_SECS", default_value_t = 300)]
    ssh_handshake_skew_secs: u64,

    #[arg(long, env = "OPENSHELL_CLIENT_TLS_SECRET_NAME")]
    client_tls_secret_name: Option<String>,

    #[arg(long, env = "OPENSHELL_HOST_GATEWAY_IP")]
    host_gateway_ip: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
        )
        .init();

    let driver = KubernetesComputeDriver::new(KubernetesComputeConfig {
        namespace: args.sandbox_namespace,
        default_image: args.sandbox_image.unwrap_or_default(),
        image_pull_policy: args.sandbox_image_pull_policy.unwrap_or_default(),
        grpc_endpoint: args.grpc_endpoint.unwrap_or_default(),
        ssh_listen_addr: format!("0.0.0.0:{}", args.sandbox_ssh_port),
        ssh_port: args.sandbox_ssh_port,
        ssh_handshake_secret: args.ssh_handshake_secret,
        ssh_handshake_skew_secs: args.ssh_handshake_skew_secs,
        client_tls_secret_name: args.client_tls_secret_name.unwrap_or_default(),
        host_gateway_ip: args.host_gateway_ip.unwrap_or_default(),
    })
    .await
    .into_diagnostic()?;

    info!(address = %args.bind_address, "Starting Kubernetes compute driver");
    tonic::transport::Server::builder()
        .add_service(ComputeDriverServer::new(ComputeDriverService::new(driver)))
        .serve(args.bind_address)
        .await
        .into_diagnostic()
}
