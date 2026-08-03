// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use miette::{IntoDiagnostic, Result};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

use openshell_core::VERSION;
use openshell_core::proto::compute::v1::compute_driver_server::ComputeDriverServer;
use openshell_driver_oci::config::{
    DEFAULT_CONTAINERD_NAMESPACE, DEFAULT_CONTAINERD_SOCKET_PATH, DEFAULT_RUNTIME_BINARY,
    DEFAULT_SNAPSHOTTER,
};
use openshell_driver_oci::{ComputeDriverService, OciComputeConfig, OciComputeDriver};

#[derive(Parser)]
#[command(name = "openshell-driver-oci")]
#[command(version = VERSION)]
struct Args {
    #[arg(
        long,
        env = "OPENSHELL_COMPUTE_DRIVER_BIND",
        default_value = "127.0.0.1:50062"
    )]
    bind_address: SocketAddr,

    #[arg(long, env = "OPENSHELL_LOG_LEVEL", default_value = "info")]
    log_level: String,

    /// Path to the system containerd gRPC Unix socket.
    #[arg(long, env = "OPENSHELL_CONTAINERD_SOCKET", default_value = DEFAULT_CONTAINERD_SOCKET_PATH)]
    containerd_socket: PathBuf,

    /// containerd namespace this driver operates in.
    #[arg(long, env = "OPENSHELL_CONTAINERD_NAMESPACE", default_value = DEFAULT_CONTAINERD_NAMESPACE)]
    containerd_namespace: String,

    /// Low-level OCI runtime binary name (or absolute path) this driver
    /// execs directly. Never bundled: must already be installed and
    /// resolvable on the gateway host. containerd is never involved in
    /// invoking it.
    #[arg(long, env = "OPENSHELL_RUNTIME_BINARY", default_value = DEFAULT_RUNTIME_BINARY)]
    runtime_binary: String,

    #[arg(long, env = "OPENSHELL_SNAPSHOTTER", default_value = DEFAULT_SNAPSHOTTER)]
    snapshotter: String,

    #[arg(long, env = "OPENSHELL_SANDBOX_IMAGE")]
    sandbox_image: Option<String>,

    #[arg(long, env = "OPENSHELL_STATE_DIR")]
    state_dir: Option<PathBuf>,

    #[arg(long, env = "OPENSHELL_GRPC_ENDPOINT")]
    grpc_endpoint: Option<String>,

    /// Port the gateway server is listening on.
    #[arg(
        long,
        env = "OPENSHELL_GATEWAY_PORT",
        default_value_t = openshell_core::config::DEFAULT_SERVER_PORT
    )]
    gateway_port: u16,

    #[arg(
        long,
        env = "OPENSHELL_SANDBOX_SSH_SOCKET_PATH",
        default_value = "/run/openshell/ssh.sock"
    )]
    sandbox_ssh_socket_path: String,

    /// Host path to a prebuilt `openshell-sandbox` supervisor binary,
    /// bind-mounted read-only into sandboxes.
    #[arg(long, env = "OPENSHELL_SUPERVISOR_BINARY_PATH")]
    supervisor_binary_path: Option<PathBuf>,

    /// Enable the per-sandbox Linux user namespace (rootless mode). Off by
    /// default: see `OciComputeConfig::rootless` for a known gap that
    /// currently makes this fail container start.
    #[arg(
        long,
        env = "OPENSHELL_OCI_EXPERIMENTAL_ROOTLESS",
        default_value_t = false
    )]
    experimental_rootless: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
        )
        .init();

    let mut config = OciComputeConfig {
        containerd_socket_path: args.containerd_socket,
        containerd_namespace: args.containerd_namespace,
        runtime_binary: args.runtime_binary,
        snapshotter: args.snapshotter,
        default_image: args.sandbox_image.unwrap_or_default(),
        grpc_endpoint: args.grpc_endpoint.unwrap_or_default(),
        gateway_port: args.gateway_port,
        sandbox_ssh_socket_path: args.sandbox_ssh_socket_path,
        supervisor_binary_path: args.supervisor_binary_path,
        rootless: args.experimental_rootless,
        ..OciComputeConfig::default()
    };
    if let Some(state_dir) = args.state_dir {
        config.state_dir = state_dir;
    }

    let driver = OciComputeDriver::new(config).await.into_diagnostic()?;

    info!(address = %args.bind_address, "Starting OCI compute driver");
    tonic::transport::Server::builder()
        .add_service(ComputeDriverServer::new(ComputeDriverService::new(driver)))
        .serve_with_shutdown(args.bind_address, async {
            tokio::signal::ctrl_c().await.ok();
            info!("Received shutdown signal, draining in-flight requests");
        })
        .await
        .into_diagnostic()
}
