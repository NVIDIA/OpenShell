// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::{ArgAction, Parser};
use miette::{IntoDiagnostic, Result};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

use openshell_core::VERSION;
use openshell_core::proto::compute::v1::compute_driver_server::ComputeDriverServer;
use openshell_driver_kubernetes::otel_tracing::compute_driver_rpc_layer;
use openshell_driver_kubernetes::{
    AppArmorProfile, ComputeDriverService, DEFAULT_GATEWAY_ID, DEFAULT_PROXY_UID,
    DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME, KubernetesComputeConfig, KubernetesComputeDriver,
    KubernetesSidecarConfig, ManagedSshIngressConfig, SupervisorSideloadMethod, SupervisorTopology,
    WorkspaceMode,
};

#[derive(Parser, Debug)]
#[command(name = "openshell-driver-kubernetes")]
#[command(version = VERSION)]
#[allow(clippy::struct_excessive_bools)]
struct Args {
    /// Public compute-driver Unix socket used by an external gateway.
    #[arg(long, env = "OPENSHELL_COMPUTE_DRIVER_SOCKET")]
    bind_socket: Option<PathBuf>,

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

    #[arg(long, env = "OPENSHELL_GATEWAY_NAME")]
    gateway_name: Option<String>,

    #[arg(long, env = "OPENSHELL_WORKSPACE_MODE", default_value = "shared")]
    workspace_mode: WorkspaceMode,

    #[arg(
        long,
        env = "OPENSHELL_GATEWAY_ID",
        default_value = DEFAULT_GATEWAY_ID
    )]
    gateway_id: String,

    #[arg(long, env = "OPENSHELL_SANDBOX_NAMESPACE", default_value = "default")]
    sandbox_namespace: String,

    #[arg(long, env = "OPENSHELL_OPERATOR_NAMESPACE_LABEL")]
    operator_namespace_label: Option<String>,

    #[arg(long, env = "OPENSHELL_OPERATOR_NAMESPACE_FILE")]
    operator_namespace_file: Option<String>,

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

    #[arg(long, env = "OPENSHELL_MANAGED_SSH_INGRESS_ENABLED")]
    managed_ssh_ingress_enabled: bool,

    #[arg(long, env = "OPENSHELL_MANAGED_SSH_GATEWAY_NAMESPACE")]
    managed_ssh_gateway_namespace: Option<String>,

    #[arg(
        long,
        env = "OPENSHELL_MANAGED_SSH_GATEWAY_POD_SELECTOR",
        value_delimiter = ','
    )]
    managed_ssh_gateway_pod_selector: Vec<String>,

    #[arg(long, env = "OPENSHELL_GRPC_ENDPOINT")]
    grpc_endpoint: Option<String>,

    #[arg(
        long,
        env = "OPENSHELL_SANDBOX_SSH_SOCKET_PATH",
        default_value = openshell_core::container_paths::SSH_SOCKET_PATH
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

    #[arg(long, env = "OPENSHELL_K8S_TOPOLOGY", default_value = "combined")]
    topology: SupervisorTopology,

    #[arg(
        long = "sidecar-proxy-uid",
        alias = "proxy-uid",
        env = "OPENSHELL_K8S_SIDECAR_PROXY_UID",
        default_value_t = DEFAULT_PROXY_UID
    )]
    sidecar_proxy_uid: u32,

    #[arg(
        long = "sidecar-process-binary-aware-network-policy",
        env = "OPENSHELL_K8S_SIDECAR_PROCESS_BINARY_AWARE_NETWORK_POLICY",
        default_value_t = true,
        action = ArgAction::Set
    )]
    sidecar_process_binary_aware_network_policy: bool,

    /// Corporate HTTP forward proxy for policy-approved TLS CONNECT egress.
    #[arg(long, env = "OPENSHELL_UPSTREAM_PROXY")]
    https_proxy: Option<String>,

    /// Comma-separated destinations that bypass the corporate proxy.
    #[arg(long, env = "OPENSHELL_UPSTREAM_NO_PROXY")]
    no_proxy: Option<String>,

    /// Kubernetes Secret name containing the upstream proxy credential.
    #[arg(long, env = "OPENSHELL_UPSTREAM_PROXY_AUTH_SECRET_NAME")]
    proxy_auth_secret_name: Option<String>,

    /// Kubernetes Secret key containing the upstream proxy credential.
    #[arg(long, env = "OPENSHELL_UPSTREAM_PROXY_AUTH_SECRET_KEY")]
    proxy_auth_secret_key: Option<String>,

    /// Acknowledge cleartext Basic auth to an http:// upstream proxy.
    #[arg(long, env = "OPENSHELL_UPSTREAM_PROXY_AUTH_ALLOW_INSECURE", action = ArgAction::SetTrue)]
    proxy_auth_allow_insecure: bool,

    /// Send destination hostnames rather than validated IPs in CONNECT.
    #[arg(long, env = "OPENSHELL_UPSTREAM_PROXY_CONNECT_BY_HOSTNAME", action = ArgAction::SetTrue)]
    proxy_connect_by_hostname: bool,

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

    #[arg(long, env = "OPENSHELL_K8S_SANDBOX_UID")]
    sandbox_uid: Option<u32>,

    #[arg(long, env = "OPENSHELL_K8S_SANDBOX_GID")]
    sandbox_gid: Option<u32>,
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
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
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let (tracer_provider, setup_error) = openshell_driver_kubernetes::otel_tracing::provider_for(
        args.otlp_endpoint.as_deref(),
        args.gateway_name.as_deref(),
    );
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level)))
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracer_provider
                .as_ref()
                .map(openshell_driver_kubernetes::otel_tracing::layer),
        )
        .init();
    if let Some(error) = setup_error {
        tracing::error!(%error, "OTLP exporting could not be started");
    } else if let Some(endpoint) = &args.otlp_endpoint {
        info!(endpoint, "OTLP exporting enabled");
    }

    let managed_ssh_gateway_pod_selector = args
        .managed_ssh_gateway_pod_selector
        .iter()
        .map(|entry| {
            entry
                .split_once('=')
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .ok_or_else(|| {
                    miette::miette!("managed SSH gateway pod selector must use key=value: {entry}")
                })
        })
        .collect::<Result<BTreeMap<_, _>>>()?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let driver = KubernetesComputeDriver::new(
        KubernetesComputeConfig {
            workspace_mode: args.workspace_mode,
            gateway_id: args.gateway_id,
            namespace: args.sandbox_namespace,
            operator_namespace_label: args.operator_namespace_label,
            operator_namespace_file: args.operator_namespace_file,
            service_account_name: args.sandbox_service_account,
            default_image: args.sandbox_image.unwrap_or_default(),
            image_pull_policy: args.sandbox_image_pull_policy.unwrap_or_default(),
            image_pull_secrets: args.sandbox_image_pull_secrets,
            managed_ssh_ingress: ManagedSshIngressConfig {
                enabled: args.managed_ssh_ingress_enabled,
                gateway_namespace: args.managed_ssh_gateway_namespace.unwrap_or_default(),
                gateway_pod_selector: managed_ssh_gateway_pod_selector,
            },
            supervisor_image: args
                .supervisor_image
                .unwrap_or_else(openshell_core::config::default_supervisor_image),
            supervisor_image_pull_policy: args.supervisor_image_pull_policy.unwrap_or_default(),
            supervisor_sideload_method: args.supervisor_sideload_method,
            topology: args.topology,
            sidecar: KubernetesSidecarConfig {
                proxy_uid: args.sidecar_proxy_uid,
                process_binary_aware_network_policy: args
                    .sidecar_process_binary_aware_network_policy,
            },
            https_proxy: args.https_proxy,
            no_proxy: args.no_proxy,
            proxy_auth_secret_name: args.proxy_auth_secret_name,
            proxy_auth_secret_key: args.proxy_auth_secret_key,
            proxy_auth_allow_insecure: args.proxy_auth_allow_insecure.then_some(true),
            proxy_connect_by_hostname: args.proxy_connect_by_hostname.then_some(true),
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
            workspace_storage_class: std::env::var("OPENSHELL_K8S_WORKSPACE_STORAGE_CLASS")
                .unwrap_or_default(),
            default_runtime_class_name: std::env::var("OPENSHELL_K8S_DEFAULT_RUNTIME_CLASS_NAME")
                .unwrap_or_default(),
            sa_token_ttl_secs: args.sa_token_ttl_secs,
            provider_spiffe_workload_api_socket_path: args
                .provider_spiffe_workload_api_socket_path
                .unwrap_or_default(),
            sandbox_uid: args.sandbox_uid,
            sandbox_gid: args.sandbox_gid,
        },
        shutdown_rx,
    )
    .await
    .into_diagnostic()?;

    let service = ComputeDriverServer::new(ComputeDriverService::new(driver));
    let shutdown = async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    };
    let result = if let Some(socket_path) = args.bind_socket {
        let listener = openshell_core::external_driver_socket::bind_private(&socket_path)
            .map_err(|err| miette::miette!("{err}"))?;
        let _cleanup =
            openshell_core::external_driver_socket::SocketCleanup::new(socket_path.clone());
        info!(socket = %socket_path.display(), "Starting Kubernetes compute driver");
        tonic::transport::Server::builder()
            .layer(compute_driver_rpc_layer())
            .add_service(service)
            .serve_with_incoming_shutdown(
                openshell_core::external_driver_socket::SameUidUnixIncoming::new(listener),
                shutdown,
            )
            .await
            .into_diagnostic()
    } else {
        info!(address = %args.bind_address, "Starting Kubernetes compute driver");
        tonic::transport::Server::builder()
            .layer(compute_driver_rpc_layer())
            .add_service(service)
            .serve_with_shutdown(args.bind_address, shutdown)
            .await
            .into_diagnostic()
    };
    if let Some(provider) = &tracer_provider
        && let Err(error) = provider.shutdown()
    {
        tracing::warn!(%error, "OTLP tracer provider shutdown failed");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_gateway_otlp_configuration() {
        let args = Args::try_parse_from([
            "openshell-driver-kubernetes",
            "--otlp-endpoint",
            "http://collector.example:4317",
            "--gateway-name",
            "kubernetes-dev",
        ])
        .expect("OTLP endpoint should parse");

        assert_eq!(
            args.otlp_endpoint.as_deref(),
            Some("http://collector.example:4317")
        );
        assert_eq!(args.gateway_name.as_deref(), Some("kubernetes-dev"));
    }
}
