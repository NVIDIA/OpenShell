// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use miette::{IntoDiagnostic, Result};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

use openshell_core::VERSION;
use openshell_core::config::{
    DEFAULT_NETWORK_NAME, DEFAULT_SSH_HANDSHAKE_SKEW_SECS, DEFAULT_SSH_PORT,
    DEFAULT_STOP_TIMEOUT_SECS,
};
use openshell_core::proto::compute::v1::compute_driver_server::ComputeDriverServer;
use openshell_driver_podman::config::ImagePullPolicy;
use openshell_driver_podman::{ComputeDriverService, PodmanComputeConfig, PodmanComputeDriver};

#[derive(Parser)]
#[command(name = "openshell-driver-podman")]
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

    /// Path to the Podman API Unix socket.
    #[arg(long, env = "OPENSHELL_PODMAN_SOCKET")]
    podman_socket: Option<PathBuf>,

    #[arg(long, env = "OPENSHELL_SANDBOX_IMAGE")]
    sandbox_image: Option<String>,

    #[arg(
        long,
        env = "OPENSHELL_SANDBOX_IMAGE_PULL_POLICY",
        default_value_t = ImagePullPolicy::Missing
    )]
    sandbox_image_pull_policy: ImagePullPolicy,

    #[arg(long, env = "OPENSHELL_GRPC_ENDPOINT")]
    grpc_endpoint: Option<String>,

    #[arg(
        long,
        env = "OPENSHELL_SANDBOX_SSH_SOCKET_PATH",
        default_value = "/run/openshell/ssh.sock"
    )]
    sandbox_ssh_socket_path: String,

    /// Podman bridge network name.
    #[arg(long, env = "OPENSHELL_NETWORK_NAME", default_value = DEFAULT_NETWORK_NAME)]
    network_name: String,

    #[arg(long, env = "OPENSHELL_SANDBOX_SSH_PORT", default_value_t = DEFAULT_SSH_PORT)]
    sandbox_ssh_port: u16,

    #[arg(long, env = "OPENSHELL_SSH_HANDSHAKE_SECRET")]
    ssh_handshake_secret: String,

    #[arg(long, env = "OPENSHELL_SSH_HANDSHAKE_SKEW_SECS", default_value_t = DEFAULT_SSH_HANDSHAKE_SKEW_SECS)]
    ssh_handshake_skew_secs: u64,

    /// Container stop timeout in seconds (SIGTERM → SIGKILL).
    #[arg(long, env = "OPENSHELL_STOP_TIMEOUT", default_value_t = DEFAULT_STOP_TIMEOUT_SECS)]
    stop_timeout: u32,

    /// OCI image containing the openshell-sandbox supervisor binary.
    #[arg(long, env = "OPENSHELL_SUPERVISOR_IMAGE")]
    supervisor_image: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
        )
        .init();

    let socket_path = args
        .podman_socket
        .unwrap_or_else(PodmanComputeConfig::default_socket_path);

    let driver = PodmanComputeDriver::new(PodmanComputeConfig {
        socket_path,
        default_image: args.sandbox_image.unwrap_or_default(),
        image_pull_policy: args.sandbox_image_pull_policy,
        grpc_endpoint: args.grpc_endpoint.unwrap_or_default(),
        sandbox_ssh_socket_path: args.sandbox_ssh_socket_path,
        network_name: args.network_name,
        ssh_listen_addr: format!("0.0.0.0:{}", args.sandbox_ssh_port),
        ssh_port: args.sandbox_ssh_port,
        ssh_handshake_secret: args.ssh_handshake_secret,
        ssh_handshake_skew_secs: args.ssh_handshake_skew_secs,
        stop_timeout_secs: args.stop_timeout,
        supervisor_image: args.supervisor_image,
    })
    .await
    .into_diagnostic()?;

    info!(address = %args.bind_address, "Starting Podman compute driver");
    tonic::transport::Server::builder()
        .add_service(ComputeDriverServer::new(ComputeDriverService::new(driver)))
        .serve_with_shutdown(args.bind_address, async {
            tokio::signal::ctrl_c().await.ok();
            info!("Received shutdown signal, draining in-flight requests");
        })
        .await
        .into_diagnostic()
}
