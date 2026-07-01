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
    AppArmorProfile, ComputeDriverService, DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME,
    KubernetesComputeConfig, KubernetesComputeDriver, SupervisorSideloadMethod, SupervisorTopology,
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

    #[arg(
        long,
        env = "OPENSHELL_K8S_SANDBOX_SERVICE_ACCOUNT",
        default_value = DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME
    )]
    sandbox_service_account: String,

    #[arg(long, env = "OPENSHELL_SANDBOX_IMAGE")]
    sandbox_image: Option<String>,

    #[arg(long, env = "OPENSHELL_SANDBOX_IMAGE_PULL_POLICY")]
    sandbox_image_pull_policy: Option<String>,

    #[arg(
        long,
        env = "OPENSHELL_SANDBOX_IMAGE_PULL_SECRETS",
        value_delimiter = ','
    )]
    sandbox_image_pull_secrets: Vec<String>,

    #[arg(long, env = "OPENSHELL_GRPC_ENDPOINT")]
    grpc_endpoint: Option<String>,

    #[arg(
        long,
        env = "OPENSHELL_SANDBOX_SSH_SOCKET_PATH",
        default_value = "/run/openshell/ssh.sock"
    )]
    sandbox_ssh_socket_path: String,

    #[arg(long, env = "OPENSHELL_CLIENT_TLS_SECRET_NAME")]
    client_tls_secret_name: Option<String>,

    #[arg(long, env = "OPENSHELL_HOST_GATEWAY_IP")]
    host_gateway_ip: Option<String>,

    #[arg(long, env = "OPENSHELL_SUPERVISOR_IMAGE")]
    supervisor_image: Option<String>,

    #[arg(long, env = "OPENSHELL_SUPERVISOR_IMAGE_PULL_POLICY")]
    supervisor_image_pull_policy: Option<String>,

    #[arg(
        long,
        env = "OPENSHELL_SUPERVISOR_SIDELOAD_METHOD",
        default_value = "image-volume"
    )]
    supervisor_sideload_method: SupervisorSideloadMethod,

    #[arg(
        long,
        env = "OPENSHELL_SUPERVISOR_TOPOLOGY",
        default_value = "combined"
    )]
    supervisor_topology: SupervisorTopology,

    #[arg(long, env = "OPENSHELL_ENABLE_USER_NAMESPACES")]
    enable_user_namespaces: bool,

    #[arg(long, env = "OPENSHELL_K8S_APP_ARMOR_PROFILE")]
    app_armor_profile: Option<AppArmorProfile>,

    /// Lifetime (seconds) of the projected `ServiceAccount` token
    /// kubelet writes into each sandbox pod for the `IssueSandboxToken`
    /// bootstrap exchange. Kubelet enforces a minimum of 600s; the
    /// gateway clamps values outside `[600, 86400]`. Default 3600.
    #[arg(long, env = "OPENSHELL_K8S_SA_TOKEN_TTL_SECS", default_value_t = 3600)]
    sa_token_ttl_secs: i64,

    #[arg(long, env = "OPENSHELL_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET")]
    provider_spiffe_workload_api_socket_path: Option<String>,
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
        service_account_name: args.sandbox_service_account,
        default_image: args.sandbox_image.unwrap_or_default(),
        image_pull_policy: args.sandbox_image_pull_policy.unwrap_or_default(),
        image_pull_secrets: args.sandbox_image_pull_secrets,
        supervisor_image: args
            .supervisor_image
            .unwrap_or_else(openshell_core::config::default_supervisor_image),
        supervisor_image_pull_policy: args.supervisor_image_pull_policy.unwrap_or_default(),
        supervisor_sideload_method: args.supervisor_sideload_method,
        supervisor_topology: args.supervisor_topology,
        grpc_endpoint: args.grpc_endpoint.unwrap_or_default(),
        ssh_socket_path: args.sandbox_ssh_socket_path,
        client_tls_secret_name: args.client_tls_secret_name.unwrap_or_default(),
        host_gateway_ip: args.host_gateway_ip.unwrap_or_default(),
        enable_user_namespaces: args.enable_user_namespaces,
        app_armor_profile: args.app_armor_profile,
        workspace_default_storage_size: std::env::var(
            "OPENSHELL_K8S_WORKSPACE_DEFAULT_STORAGE_SIZE",
        )
        .unwrap_or_else(|_| {
            openshell_driver_kubernetes::DEFAULT_WORKSPACE_STORAGE_SIZE.to_string()
        }),
        default_runtime_class_name: std::env::var("OPENSHELL_K8S_DEFAULT_RUNTIME_CLASS_NAME")
            .unwrap_or_default(),
        sa_token_ttl_secs: args.sa_token_ttl_secs,
        provider_spiffe_workload_api_socket_path: args
            .provider_spiffe_workload_api_socket_path
            .unwrap_or_default(),
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
