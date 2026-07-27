// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use miette::{IntoDiagnostic, Result};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

use openshell_core::VERSION;
use openshell_core::config::DEFAULT_STOP_TIMEOUT_SECS;
use openshell_core::proto::compute::v1::compute_driver_server::ComputeDriverServer;
use openshell_driver_podman::config::{
    DEFAULT_NETWORK_NAME, DEFAULT_SANDBOX_PIDS_LIMIT, ImagePullPolicy,
};
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

    /// Port the gateway server is listening on.
    ///
    /// Used when `--grpc-endpoint` is not set to auto-detect the endpoint
    /// that sandbox containers dial back to.
    #[arg(
        long,
        env = "OPENSHELL_GATEWAY_PORT",
        default_value_t = openshell_core::config::DEFAULT_SERVER_PORT
    )]
    gateway_port: u16,

    /// Host gateway IP used for sandbox host aliases.
    ///
    /// Empty uses Podman's `host-gateway` resolver.
    #[arg(long, env = "OPENSHELL_PODMAN_HOST_GATEWAY_IP")]
    host_gateway_ip: Option<String>,

    #[arg(
        long,
        env = "OPENSHELL_SANDBOX_SSH_SOCKET_PATH",
        default_value = "/run/openshell/ssh.sock"
    )]
    sandbox_ssh_socket_path: String,

    /// Podman bridge network name.
    #[arg(long, env = "OPENSHELL_NETWORK_NAME", default_value = DEFAULT_NETWORK_NAME)]
    network_name: String,

    /// Container stop timeout in seconds (SIGTERM → SIGKILL).
    #[arg(long, env = "OPENSHELL_STOP_TIMEOUT", default_value_t = DEFAULT_STOP_TIMEOUT_SECS)]
    stop_timeout: u32,

    /// Container cgroup PID limit for sandbox containers. Set 0 to inherit
    /// Podman's runtime/default PID limit.
    #[arg(
        long,
        env = "OPENSHELL_SANDBOX_PIDS_LIMIT",
        default_value_t = DEFAULT_SANDBOX_PIDS_LIMIT
    )]
    sandbox_pids_limit: i64,

    /// OCI image containing the openshell-sandbox supervisor binary.
    #[arg(long, env = "OPENSHELL_SUPERVISOR_IMAGE")]
    supervisor_image: Option<String>,

    /// Host path to the CA certificate for sandbox mTLS.
    #[arg(long, env = "OPENSHELL_PODMAN_TLS_CA")]
    podman_tls_ca: Option<PathBuf>,

    /// Host path to the client certificate for sandbox mTLS.
    #[arg(long, env = "OPENSHELL_PODMAN_TLS_CERT")]
    podman_tls_cert: Option<PathBuf>,

    /// Host path to the client private key for sandbox mTLS.
    #[arg(long, env = "OPENSHELL_PODMAN_TLS_KEY")]
    podman_tls_key: Option<PathBuf>,

    /// Corporate forward proxy URL for the supervisor's upstream TLS dials,
    /// in explicit `http://host:port` form (scheme and port required).
    /// Credentials must not be embedded in the URL; use
    /// `--sandbox-proxy-auth-file` instead.
    #[arg(long, env = "OPENSHELL_SANDBOX_HTTPS_PROXY")]
    sandbox_https_proxy: Option<String>,

    /// Comma-separated `NO_PROXY` list injected alongside the proxy URL.
    #[arg(long, env = "OPENSHELL_SANDBOX_NO_PROXY")]
    sandbox_no_proxy: Option<String>,

    /// Path to a file containing the corporate proxy credentials as
    /// `user:pass`. Delivered to the supervisor through a root-only secret
    /// mount so the credentials never appear in config or container metadata.
    #[arg(long, env = "OPENSHELL_SANDBOX_PROXY_AUTH_FILE")]
    sandbox_proxy_auth_file: Option<String>,

    /// Explicit acknowledgement (`true`) that the proxy credential is sent
    /// as cleartext Basic auth over the plain-TCP connection to the http://
    /// proxy. Required when `--sandbox-proxy-auth-file` is set.
    #[arg(long, env = "OPENSHELL_SANDBOX_PROXY_AUTH_ALLOW_INSECURE")]
    sandbox_proxy_auth_allow_insecure: Option<bool>,

    /// Send the destination hostname in CONNECT requests to the corporate
    /// proxy instead of a validated IP. Only for proxies whose ACLs filter
    /// on hostnames: the proxy then resolves the name itself, so sandbox
    /// SSRF/`allowed_ips` validation no longer binds the connection.
    #[arg(long, env = "OPENSHELL_SANDBOX_PROXY_CONNECT_BY_HOSTNAME")]
    sandbox_proxy_connect_by_hostname: Option<bool>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
        )
        .init();

    let driver = PodmanComputeDriver::new(PodmanComputeConfig {
        socket_path: args.podman_socket,
        default_image: args.sandbox_image.unwrap_or_default(),
        image_pull_policy: args.sandbox_image_pull_policy,
        grpc_endpoint: args.grpc_endpoint.unwrap_or_default(),
        gateway_port: args.gateway_port,
        host_gateway_ip: args
            .host_gateway_ip
            .unwrap_or_else(PodmanComputeConfig::default_host_gateway_ip),
        sandbox_ssh_socket_path: args.sandbox_ssh_socket_path,
        network_name: args.network_name,
        stop_timeout_secs: args.stop_timeout,
        supervisor_image: args
            .supervisor_image
            .unwrap_or_else(openshell_core::config::default_supervisor_image),
        guest_tls_ca: args.podman_tls_ca,
        guest_tls_cert: args.podman_tls_cert,
        guest_tls_key: args.podman_tls_key,
        sandbox_pids_limit: args.sandbox_pids_limit,
        https_proxy: args.sandbox_https_proxy,
        no_proxy: args.sandbox_no_proxy,
        proxy_auth_file: args.sandbox_proxy_auth_file,
        proxy_auth_allow_insecure: args.sandbox_proxy_auth_allow_insecure,
        proxy_connect_by_hostname: args.sandbox_proxy_connect_by_hostname,
        ..PodmanComputeConfig::default()
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
