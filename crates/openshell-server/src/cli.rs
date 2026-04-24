// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared CLI entrypoint for the gateway binaries.

use clap::{Command, CommandFactory, FromArgMatches, Parser};
use miette::{IntoDiagnostic, Result};
use openshell_core::ComputeDriverKind;
use openshell_core::config::{
    DEFAULT_SERVER_PORT, DEFAULT_SSH_HANDSHAKE_SKEW_SECS, DEFAULT_SSH_PORT,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::compute::{DockerComputeConfig, VmComputeConfig};
use crate::{run_server, tracing_bus::TracingLogBus};

/// `OpenShell` gateway process - gRPC and HTTP server with protocol multiplexing.
#[derive(Parser, Debug)]
#[command(version = openshell_core::VERSION)]
#[command(about = "OpenShell gRPC/HTTP server", long_about = None)]
struct Args {
    /// Port to bind the server to (all interfaces).
    #[arg(long, default_value_t = DEFAULT_SERVER_PORT, env = "OPENSHELL_SERVER_PORT")]
    port: u16,

    /// Port for unauthenticated health endpoints (healthz, readyz).
    /// Set to 0 to disable the dedicated health listener.
    #[arg(long, default_value_t = 0, env = "OPENSHELL_HEALTH_PORT")]
    health_port: u16,

    /// Port for the Prometheus metrics endpoint (/metrics).
    /// Set to 0 to disable the dedicated metrics listener.
    #[arg(long, default_value_t = 0, env = "OPENSHELL_METRICS_PORT")]
    metrics_port: u16,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = "info", env = "OPENSHELL_LOG_LEVEL")]
    log_level: String,

    /// Path to TLS certificate file (required unless --disable-tls).
    #[arg(long, env = "OPENSHELL_TLS_CERT")]
    tls_cert: Option<PathBuf>,

    /// Path to TLS private key file (required unless --disable-tls).
    #[arg(long, env = "OPENSHELL_TLS_KEY")]
    tls_key: Option<PathBuf>,

    /// Path to CA certificate for client certificate verification (mTLS).
    #[arg(long, env = "OPENSHELL_TLS_CLIENT_CA")]
    tls_client_ca: Option<PathBuf>,

    /// Database URL for persistence.
    #[arg(long, env = "OPENSHELL_DB_URL", required = true)]
    db_url: String,

    /// Compute drivers configured for this gateway.
    ///
    /// Accepts a comma-delimited list such as `kubernetes` or
    /// `kubernetes,podman`. The configuration format is future-proofed for
    /// multiple drivers, but the gateway currently requires exactly one.
    #[arg(
        long,
        alias = "driver",
        env = "OPENSHELL_DRIVERS",
        value_delimiter = ',',
        default_value = "kubernetes",
        value_parser = parse_compute_driver
    )]
    drivers: Vec<ComputeDriverKind>,

    /// Kubernetes namespace for sandboxes.
    #[arg(long, env = "OPENSHELL_SANDBOX_NAMESPACE", default_value = "default")]
    sandbox_namespace: String,

    /// Default container image for sandboxes.
    #[arg(long, env = "OPENSHELL_SANDBOX_IMAGE")]
    sandbox_image: Option<String>,

    /// Kubernetes `imagePullPolicy` for sandbox pods (Always, `IfNotPresent`, Never).
    #[arg(long, env = "OPENSHELL_SANDBOX_IMAGE_PULL_POLICY")]
    sandbox_image_pull_policy: Option<String>,

    /// gRPC endpoint for sandboxes to callback to `OpenShell`.
    /// This should be reachable from within the Kubernetes cluster.
    #[arg(long, env = "OPENSHELL_GRPC_ENDPOINT")]
    grpc_endpoint: Option<String>,

    /// Public host for the SSH gateway.
    #[arg(long, env = "OPENSHELL_SSH_GATEWAY_HOST", default_value = "127.0.0.1")]
    ssh_gateway_host: String,

    /// Public port for the SSH gateway.
    #[arg(long, env = "OPENSHELL_SSH_GATEWAY_PORT", default_value_t = DEFAULT_SERVER_PORT)]
    ssh_gateway_port: u16,

    /// HTTP path for SSH CONNECT/upgrade.
    #[arg(
        long,
        env = "OPENSHELL_SSH_CONNECT_PATH",
        default_value = "/connect/ssh"
    )]
    ssh_connect_path: String,

    /// SSH port inside sandbox pods.
    #[arg(long, env = "OPENSHELL_SANDBOX_SSH_PORT", default_value_t = DEFAULT_SSH_PORT)]
    sandbox_ssh_port: u16,
    /// Shared secret for gateway-to-sandbox SSH handshake.
    #[arg(long, env = "OPENSHELL_SSH_HANDSHAKE_SECRET")]
    ssh_handshake_secret: Option<String>,

    /// Allowed clock skew in seconds for SSH handshake.
    #[arg(long, env = "OPENSHELL_SSH_HANDSHAKE_SKEW_SECS", default_value_t = DEFAULT_SSH_HANDSHAKE_SKEW_SECS)]
    ssh_handshake_skew_secs: u64,

    /// Kubernetes secret name containing client TLS materials for sandbox pods.
    #[arg(long, env = "OPENSHELL_CLIENT_TLS_SECRET_NAME")]
    client_tls_secret_name: Option<String>,

    /// Host gateway IP for sandbox pod hostAliases.
    /// When set, sandbox pods get hostAliases entries mapping
    /// host.docker.internal and host.openshell.internal to this IP.
    #[arg(long, env = "OPENSHELL_HOST_GATEWAY_IP")]
    host_gateway_ip: Option<String>,

    /// Working directory for VM driver sandbox state.
    #[arg(
        long,
        env = "OPENSHELL_VM_DRIVER_STATE_DIR",
        default_value_os_t = VmComputeConfig::default_state_dir()
    )]
    vm_driver_state_dir: PathBuf,

    /// Directory searched for compute-driver binaries (e.g.
    /// `openshell-driver-vm`) when an explicit binary override isn't
    /// configured. When unset, the gateway searches
    /// `$HOME/.local/libexec/openshell`, `/usr/local/libexec/openshell`,
    /// `/usr/local/libexec`, then a sibling of the gateway binary.
    #[arg(long, env = "OPENSHELL_DRIVER_DIR")]
    driver_dir: Option<PathBuf>,

    /// libkrun log level used by the VM helper.
    #[arg(
        long,
        env = "OPENSHELL_VM_KRUN_LOG_LEVEL",
        default_value_t = VmComputeConfig::default_krun_log_level()
    )]
    vm_krun_log_level: u32,

    /// Default vCPU count for VM sandboxes.
    #[arg(
        long,
        env = "OPENSHELL_VM_DRIVER_VCPUS",
        default_value_t = VmComputeConfig::default_vcpus()
    )]
    vm_vcpus: u8,

    /// Default memory allocation for VM sandboxes, in MiB.
    #[arg(
        long,
        env = "OPENSHELL_VM_DRIVER_MEM_MIB",
        default_value_t = VmComputeConfig::default_mem_mib()
    )]
    vm_mem_mib: u32,

    /// CA certificate installed into VM sandboxes for gateway mTLS.
    #[arg(long, env = "OPENSHELL_VM_TLS_CA")]
    vm_tls_ca: Option<PathBuf>,

    /// Client certificate installed into VM sandboxes for gateway mTLS.
    #[arg(long, env = "OPENSHELL_VM_TLS_CERT")]
    vm_tls_cert: Option<PathBuf>,

    /// Client private key installed into VM sandboxes for gateway mTLS.
    #[arg(long, env = "OPENSHELL_VM_TLS_KEY")]
    vm_tls_key: Option<PathBuf>,

    /// Linux `openshell-sandbox` binary bind-mounted into Docker sandboxes.
    ///
    /// When unset the gateway falls back to (in order) a sibling
    /// `openshell-sandbox` next to the gateway binary, a local cargo build,
    /// or extracting the binary from `--docker-supervisor-image`.
    #[arg(long, env = "OPENSHELL_DOCKER_SUPERVISOR_BIN")]
    docker_supervisor_bin: Option<PathBuf>,

    /// Image the Docker driver pulls to extract the Linux
    /// `openshell-sandbox` binary when no explicit `--docker-supervisor-bin`
    /// override or local build is available. Defaults to
    /// `ghcr.io/nvidia/openshell/supervisor:<gateway-image-tag>`.
    #[arg(long, env = "OPENSHELL_DOCKER_SUPERVISOR_IMAGE")]
    docker_supervisor_image: Option<String>,

    /// CA certificate bind-mounted into Docker sandboxes for gateway mTLS.
    #[arg(long, env = "OPENSHELL_DOCKER_TLS_CA")]
    docker_tls_ca: Option<PathBuf>,

    /// Client certificate bind-mounted into Docker sandboxes for gateway mTLS.
    #[arg(long, env = "OPENSHELL_DOCKER_TLS_CERT")]
    docker_tls_cert: Option<PathBuf>,

    /// Client private key bind-mounted into Docker sandboxes for gateway mTLS.
    #[arg(long, env = "OPENSHELL_DOCKER_TLS_KEY")]
    docker_tls_key: Option<PathBuf>,

    /// Disable TLS entirely — listen on plaintext HTTP.
    /// Use this when the gateway sits behind a reverse proxy or tunnel
    /// (e.g. Cloudflare Tunnel) that terminates TLS at the edge.
    #[arg(long, env = "OPENSHELL_DISABLE_TLS")]
    disable_tls: bool,

    /// Disable gateway authentication (mTLS client certificate requirement).
    /// When set, the TLS handshake accepts connections without a client
    /// certificate. Ignored when --disable-tls is set.
    #[arg(long, env = "OPENSHELL_DISABLE_GATEWAY_AUTH")]
    disable_gateway_auth: bool,

    /// OIDC issuer URL for JWT-based authentication.
    /// When set, the server validates `authorization: Bearer` tokens on gRPC
    /// requests against the issuer's JWKS endpoint.
    #[arg(long, env = "OPENSHELL_OIDC_ISSUER")]
    oidc_issuer: Option<String>,

    /// Expected OIDC audience claim (typically the client ID).
    #[arg(long, env = "OPENSHELL_OIDC_AUDIENCE", default_value = "openshell-cli")]
    oidc_audience: String,

    /// JWKS key cache TTL in seconds.
    #[arg(long, env = "OPENSHELL_OIDC_JWKS_TTL", default_value_t = 3600)]
    oidc_jwks_ttl: u64,

    /// Dot-separated path to the roles array in the JWT claims.
    /// Keycloak: `realm_access.roles` (default). Entra ID: "roles". Okta: "groups".
    #[arg(
        long,
        env = "OPENSHELL_OIDC_ROLES_CLAIM",
        default_value = "realm_access.roles"
    )]
    oidc_roles_claim: String,

    /// Role name that grants admin access.
    #[arg(
        long,
        env = "OPENSHELL_OIDC_ADMIN_ROLE",
        default_value = "openshell-admin"
    )]
    oidc_admin_role: String,

    /// Role name that grants standard user access.
    #[arg(
        long,
        env = "OPENSHELL_OIDC_USER_ROLE",
        default_value = "openshell-user"
    )]
    oidc_user_role: String,

    /// Dot-separated path to the scopes value in the JWT claims.
    /// When set, the server enforces scope-based permissions on top of roles.
    /// Keycloak: "scope". Okta: "scp". Leave empty to disable scope enforcement.
    #[arg(long, env = "OPENSHELL_OIDC_SCOPES_CLAIM", default_value = "")]
    oidc_scopes_claim: String,
}

pub fn command() -> Command {
    Args::command()
        .name("openshell-gateway")
        .bin_name("openshell-gateway")
}

pub async fn run_cli() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|e| miette::miette!("failed to install rustls crypto provider: {e:?}"))?;

    let args = Args::from_arg_matches(&command().get_matches()).expect("clap validated args");

    run_from_args(args).await
}

async fn run_from_args(args: Args) -> Result<()> {
    let tracing_log_bus = TracingLogBus::new();
    tracing_log_bus.install_subscriber(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
    );

    let bind = SocketAddr::from(([0, 0, 0, 0], args.port));

    let tls = if args.disable_tls {
        None
    } else {
        let cert_path = args.tls_cert.ok_or_else(|| {
            miette::miette!(
                "--tls-cert is required when TLS is enabled (use --disable-tls to skip)"
            )
        })?;
        let key_path = args.tls_key.ok_or_else(|| {
            miette::miette!("--tls-key is required when TLS is enabled (use --disable-tls to skip)")
        })?;
        let client_ca_path = args.tls_client_ca.ok_or_else(|| {
            miette::miette!(
                "--tls-client-ca is required when TLS is enabled (use --disable-tls to skip)"
            )
        })?;
        Some(openshell_core::TlsConfig {
            cert_path,
            key_path,
            client_ca_path,
            allow_unauthenticated: args.disable_gateway_auth,
        })
    };

    let mut config = openshell_core::Config::new(tls)
        .with_bind_address(bind)
        .with_log_level(&args.log_level);

    if args.health_port != 0 {
        if args.port == args.health_port {
            return Err(miette::miette!(
                "--port and --health-port must be different (both set to {})",
                args.port
            ));
        }
        let health_bind = SocketAddr::from(([0, 0, 0, 0], args.health_port));
        config = config.with_health_bind_address(health_bind);
    }

    if args.metrics_port != 0 {
        if args.port == args.metrics_port {
            return Err(miette::miette!(
                "--port and --metrics-port must be different (both set to {})",
                args.port
            ));
        }
        if args.health_port != 0 && args.health_port == args.metrics_port {
            return Err(miette::miette!(
                "--health-port and --metrics-port must be different (both set to {})",
                args.health_port
            ));
        }
        let metrics_bind = SocketAddr::from(([0, 0, 0, 0], args.metrics_port));
        config = config.with_metrics_bind_address(metrics_bind);
    }

    config = config
        .with_database_url(args.db_url)
        .with_compute_drivers(args.drivers)
        .with_sandbox_namespace(args.sandbox_namespace)
        .with_ssh_gateway_host(args.ssh_gateway_host)
        .with_ssh_gateway_port(args.ssh_gateway_port)
        .with_ssh_connect_path(args.ssh_connect_path)
        .with_sandbox_ssh_port(args.sandbox_ssh_port)
        .with_ssh_handshake_skew_secs(args.ssh_handshake_skew_secs);

    if let Some(image) = args.sandbox_image {
        config = config.with_sandbox_image(image);
    }

    if let Some(policy) = args.sandbox_image_pull_policy {
        config = config.with_sandbox_image_pull_policy(policy);
    }

    if let Some(endpoint) = args.grpc_endpoint {
        config = config.with_grpc_endpoint(endpoint);
    }

    if let Some(secret) = args.ssh_handshake_secret {
        config = config.with_ssh_handshake_secret(secret);
    }

    if let Some(name) = args.client_tls_secret_name {
        config = config.with_client_tls_secret_name(name);
    }

    if let Some(ip) = args.host_gateway_ip {
        config = config.with_host_gateway_ip(ip);
    }

    if let Some(issuer) = args.oidc_issuer {
        config = config.with_oidc(openshell_core::OidcConfig {
            issuer,
            audience: args.oidc_audience,
            jwks_ttl_secs: args.oidc_jwks_ttl,
            roles_claim: args.oidc_roles_claim,
            admin_role: args.oidc_admin_role,
            user_role: args.oidc_user_role,
            scopes_claim: args.oidc_scopes_claim,
        });
    }

    let vm_config = VmComputeConfig {
        state_dir: args.vm_driver_state_dir,
        driver_dir: args.driver_dir,
        krun_log_level: args.vm_krun_log_level,
        vcpus: args.vm_vcpus,
        mem_mib: args.vm_mem_mib,
        guest_tls_ca: args.vm_tls_ca,
        guest_tls_cert: args.vm_tls_cert,
        guest_tls_key: args.vm_tls_key,
    };

    let docker_config = DockerComputeConfig {
        supervisor_bin: args.docker_supervisor_bin,
        supervisor_image: args.docker_supervisor_image,
        guest_tls_ca: args.docker_tls_ca,
        guest_tls_cert: args.docker_tls_cert,
        guest_tls_key: args.docker_tls_key,
    };

    if args.disable_tls {
        info!("TLS disabled — listening on plaintext HTTP");
    } else if args.disable_gateway_auth {
        info!("Gateway auth disabled — accepting connections without client certificates");
    }

    info!(bind = %config.bind_address, "Starting OpenShell server");

    run_server(config, vm_config, docker_config, tracing_log_bus)
        .await
        .into_diagnostic()
}

fn parse_compute_driver(value: &str) -> std::result::Result<ComputeDriverKind, String> {
    value.parse()
}

#[cfg(test)]
mod tests {
    use super::command;

    #[test]
    fn command_uses_gateway_binary_name() {
        let mut help = Vec::new();
        command().write_long_help(&mut help).unwrap();
        let help = String::from_utf8(help).unwrap();
        assert!(help.contains("openshell-gateway"));
    }

    #[test]
    fn command_exposes_version() {
        let cmd = command();
        let version = cmd.get_version().unwrap();
        assert_eq!(version.to_string(), openshell_core::VERSION);
    }
}
