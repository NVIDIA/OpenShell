// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use miette::{IntoDiagnostic, Result};
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

use openshell_core::VERSION;
use openshell_core::proto::compute::v1::compute_driver_server::ComputeDriverServer;
use openshell_driver_podman::config::{
    DEFAULT_NETWORK_NAME, DEFAULT_PODMAN_STOP_TIMEOUT_SECS, DEFAULT_SANDBOX_PIDS_LIMIT,
    ImagePullPolicy,
};
use openshell_driver_podman::otel_tracing::compute_driver_rpc_layer;
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

    #[arg(long, env = "OPENSHELL_OTLP_ENDPOINT")]
    otlp_endpoint: Option<String>,

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
        default_value = openshell_core::container_paths::SSH_SOCKET_PATH
    )]
    sandbox_ssh_socket_path: String,

    /// Podman bridge network name.
    #[arg(long, env = "OPENSHELL_NETWORK_NAME", default_value = DEFAULT_NETWORK_NAME)]
    network_name: String,

    /// Container stop timeout in seconds (SIGTERM → SIGKILL).
    #[arg(long, env = "OPENSHELL_STOP_TIMEOUT", default_value_t = DEFAULT_PODMAN_STOP_TIMEOUT_SECS)]
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

    /// User namespace mode for sandbox containers (e.g. `auto`).
    /// When unset, containers use the default user namespace.
    #[arg(long, env = "OPENSHELL_PODMAN_USERNS")]
    userns: Option<String>,

    /// Explicit UID mappings for `userns = "private"`.
    /// Each entry is `"container_id:host_id:size"`.
    #[arg(long = "uidmap")]
    uidmap: Vec<String>,

    /// Explicit GID mappings for `userns = "private"`.
    /// Each entry is `"container_id:host_id:size"`.
    #[arg(long = "gidmap")]
    gidmap: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let (tracer_provider, setup_error) =
        openshell_driver_podman::otel_tracing::provider_for(args.otlp_endpoint.as_deref());
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level)))
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracer_provider
                .as_ref()
                .map(openshell_driver_podman::otel_tracing::layer),
        )
        .init();
    if let Some(error) = setup_error {
        tracing::error!(%error, "OTLP exporting could not be started");
    } else if let Some(endpoint) = &args.otlp_endpoint {
        info!(endpoint, "OTLP exporting enabled");
    }

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
        userns: args.userns,
        uidmap: args.uidmap,
        gidmap: args.gidmap,
        ..PodmanComputeConfig::default()
    })
    .await
    .into_diagnostic()?;

    info!(address = %args.bind_address, "Starting Podman compute driver");
    let result = tonic::transport::Server::builder()
        .layer(compute_driver_rpc_layer())
        .add_service(ComputeDriverServer::new(ComputeDriverService::new(driver)))
        .serve_with_shutdown(args.bind_address, async {
            shutdown_signal().await;
            info!("Received shutdown signal, draining in-flight requests");
        })
        .await
        .into_diagnostic();
    if let Some(provider) = &tracer_provider
        && let Err(error) = provider.shutdown()
    {
        tracing::warn!(%error, "OTLP tracer provider shutdown failed");
    }
    result
}

async fn select_shutdown_signal(
    ctrl_c: impl Future<Output = ()>,
    terminate: impl Future<Output = ()>,
) {
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}

async fn ctrl_c_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::warn!(%error, "Failed to install Ctrl-C signal handler");
        std::future::pending::<()>().await;
    }
}

#[cfg(unix)]
async fn terminate_signal() {
    let Ok(mut signal) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    else {
        tracing::warn!("Failed to install SIGTERM signal handler");
        std::future::pending::<()>().await;
        return;
    };
    let _ = signal.recv().await;
}

async fn shutdown_signal() {
    #[cfg(unix)]
    select_shutdown_signal(ctrl_c_signal(), terminate_signal()).await;

    #[cfg(not(unix))]
    ctrl_c_signal().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_completes_when_termination_signal_arrives() {
        select_shutdown_signal(std::future::pending(), std::future::ready(())).await;
    }

    #[test]
    fn accepts_gateway_otlp_endpoint() {
        let args = Args::try_parse_from([
            "openshell-driver-podman",
            "--otlp-endpoint",
            "http://collector.internal:4317",
        ])
        .expect("OTLP endpoint should be accepted");

        assert_eq!(
            args.otlp_endpoint.as_deref(),
            Some("http://collector.internal:4317")
        );
    }
}
