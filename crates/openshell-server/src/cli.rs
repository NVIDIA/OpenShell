// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared CLI entrypoint for the gateway binaries.

use clap::{ArgAction, Command, CommandFactory, FromArgMatches, Parser};
use miette::{IntoDiagnostic, Result};
use openshell_core::ComputeDriverKind;
use openshell_core::config::{DEFAULT_DOCKER_NETWORK_NAME, DEFAULT_SERVER_PORT, DEFAULT_SSH_PORT};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::certgen;
use crate::compute::{DockerComputeConfig, VmComputeConfig};
use crate::{run_server, tracing_bus::TracingLogBus};

/// `OpenShell` gateway process - gRPC and HTTP server with protocol multiplexing.
///
/// Top-level CLI. When invoked without a subcommand the binary runs the
/// gateway server using `RunArgs`. The `generate-certs` subcommand is used by
/// the Helm pre-install hook to bootstrap mTLS Secrets.
#[derive(Parser, Debug)]
#[command(version = openshell_core::VERSION)]
#[command(about = "OpenShell gRPC/HTTP server", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[command(flatten)]
    run: RunArgs,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Generate mTLS PKI and write Kubernetes Secrets (Helm pre-install hook).
    GenerateCerts(certgen::CertgenArgs),
}

#[derive(clap::Args, Debug)]
#[allow(clippy::struct_excessive_bools)]
struct RunArgs {
    /// IP address to bind the server, health, and metrics listeners to.
    #[arg(long, default_value = "127.0.0.1", env = "OPENSHELL_BIND_ADDRESS")]
    bind_address: IpAddr,

    /// Port to bind the server to.
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
    ///
    /// Required when running the gateway. Validated at the call site rather
    /// than as a clap-level requirement so the `generate-certs` subcommand
    /// (which does not need a database) can run without it.
    #[arg(long, env = "OPENSHELL_DB_URL")]
    db_url: Option<String>,

    /// Compute drivers configured for this gateway.
    ///
    /// Accepts a comma-delimited list such as `kubernetes` or
    /// `kubernetes,podman`. The configuration format is future-proofed for
    /// multiple drivers, but the gateway currently requires exactly one.
    /// When unset, the gateway auto-detects the driver based on the runtime
    /// environment (Kubernetes → Podman → Docker CLI or socket). VM is never
    /// auto-detected and requires explicit configuration.
    #[arg(
        long,
        alias = "driver",
        env = "OPENSHELL_DRIVERS",
        value_delimiter = ',',
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

    /// SSH port inside sandbox pods.
    #[arg(long, env = "OPENSHELL_SANDBOX_SSH_PORT", default_value_t = DEFAULT_SSH_PORT)]
    sandbox_ssh_port: u16,

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
    /// `$HOME/.local/libexec/openshell`, `/usr/libexec/openshell`,
    /// `/usr/local/libexec/openshell`, `/usr/local/libexec`, then a sibling
    /// of the gateway binary.
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

    /// Docker bridge network used for sandbox containers.
    #[arg(
        long,
        env = "OPENSHELL_DOCKER_NETWORK_NAME",
        default_value = DEFAULT_DOCKER_NETWORK_NAME
    )]
    docker_network_name: String,

    /// Enable Kubernetes user namespace isolation (hostUsers: false) for
    /// sandbox pods.
    #[arg(long, env = "OPENSHELL_ENABLE_USER_NAMESPACES")]
    enable_user_namespaces: bool,

    /// Disable TLS entirely — listen on plaintext HTTP.
    /// Use this when the gateway sits behind a reverse proxy or tunnel
    /// (e.g. Cloudflare Tunnel) that terminates TLS at the edge.
    #[arg(long, env = "OPENSHELL_DISABLE_TLS")]
    disable_tls: bool,

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

    /// Subject Alternative Names configured on the gateway server certificate.
    /// Wildcard DNS SANs also enable sandbox service URLs under that domain.
    #[arg(
        long = "server-san",
        env = "OPENSHELL_SERVER_SAN",
        value_delimiter = ','
    )]
    server_sans: Vec<String>,

    /// Enable plaintext HTTP routing for loopback sandbox service URLs.
    #[arg(
        long,
        env = "OPENSHELL_ENABLE_LOOPBACK_SERVICE_HTTP",
        default_value_t = true,
        action = ArgAction::Set
    )]
    enable_loopback_service_http: bool,
}

pub fn command() -> Command {
    Cli::command()
        .name("openshell-gateway")
        .bin_name("openshell-gateway")
}

pub async fn run_cli() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|e| miette::miette!("failed to install rustls crypto provider: {e:?}"))?;

    let cli = Cli::from_arg_matches(&command().get_matches()).expect("clap validated args");

    match cli.command {
        Some(Commands::GenerateCerts(args)) => certgen::run(args).await,
        None => Box::pin(run_from_args(cli.run)).await,
    }
}

async fn run_from_args(args: RunArgs) -> Result<()> {
    let tracing_log_bus = TracingLogBus::new();
    tracing_log_bus.install_subscriber(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
    );

    let bind = SocketAddr::new(args.bind_address, args.port);

    let has_client_ca = args.tls_client_ca.is_some();
    let has_oidc = args.oidc_issuer.is_some();

    if args.disable_tls && has_client_ca {
        return Err(miette::miette!(
            "--disable-tls and --tls-client-ca are mutually exclusive.  Client mTLS authentication requires that TLS be enabled."
        ));
    }

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
        Some(openshell_core::TlsConfig {
            cert_path,
            key_path,
            require_client_auth: has_client_ca && !has_oidc,
            client_ca_path: args.tls_client_ca,
        })
    };

    let db_url = args
        .db_url
        .ok_or_else(|| miette::miette!("--db-url is required (or set OPENSHELL_DB_URL)"))?;

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
        let health_bind = SocketAddr::new(args.bind_address, args.health_port);
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
        let metrics_bind = SocketAddr::new(args.bind_address, args.metrics_port);
        config = config.with_metrics_bind_address(metrics_bind);
    }

    config = config
        .with_database_url(db_url)
        .with_compute_drivers(args.drivers)
        .with_sandbox_namespace(args.sandbox_namespace)
        .with_ssh_gateway_host(args.ssh_gateway_host)
        .with_ssh_gateway_port(args.ssh_gateway_port)
        .with_sandbox_ssh_port(args.sandbox_ssh_port)
        .with_server_sans(args.server_sans)
        .with_loopback_service_http(args.enable_loopback_service_http);

    if let Some(image) = args.sandbox_image {
        config = config.with_sandbox_image(image);
    }

    if let Some(policy) = args.sandbox_image_pull_policy {
        config = config.with_sandbox_image_pull_policy(policy);
    }

    if let Some(endpoint) = args.grpc_endpoint {
        config = config.with_grpc_endpoint(endpoint);
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

    config.enable_user_namespaces = args.enable_user_namespaces;

    let vm_config = VmComputeConfig {
        state_dir: args.vm_driver_state_dir,
        driver_dir: args.driver_dir,
        default_image: config.sandbox_image.clone(),
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
        network_name: args.docker_network_name,
    };

    if args.disable_tls {
        warn!("TLS disabled — listening on plaintext HTTP");
    } else {
        info!("TLS enabled — listening on encrypted HTTPS");
    }

    if has_client_ca {
        info!("mTLS authentication enabled");
    }
    if has_oidc {
        info!("OIDC authentication enabled");
    }

    if !has_client_ca && !has_oidc {
        warn!(
            "Neither mTLS (--tls-client-ca) nor OIDC (--oidc-issuer) is configured — \
             the gateway has no authentication mechanism"
        );
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
    use super::{Cli, command};
    use clap::Parser;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{LazyLock, Mutex};

    static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    struct EnvVarGuard {
        key: &'static str,
        original: Option<String>,
    }

    impl EnvVarGuard {
        #[allow(unsafe_code)]
        fn set(key: &'static str, value: &str) -> Self {
            let original = std::env::var(key).ok();
            // SAFETY: tests serialize environment mutation with ENV_LOCK.
            unsafe { std::env::set_var(key, value) };
            Self { key, original }
        }

        #[allow(unsafe_code)]
        fn remove(key: &'static str) -> Self {
            let original = std::env::var(key).ok();
            // SAFETY: tests serialize environment mutation with ENV_LOCK.
            unsafe { std::env::remove_var(key) };
            Self { key, original }
        }
    }

    impl Drop for EnvVarGuard {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            match self.original.as_deref() {
                // SAFETY: tests serialize environment mutation with ENV_LOCK.
                Some(value) => unsafe { std::env::set_var(self.key, value) },
                // SAFETY: tests serialize environment mutation with ENV_LOCK.
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

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

    #[test]
    fn command_defaults_bind_address_to_loopback() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _guard = EnvVarGuard::remove("OPENSHELL_BIND_ADDRESS");
        let cli =
            Cli::try_parse_from(["openshell-gateway", "--db-url", "sqlite::memory:"]).unwrap();
        assert_eq!(cli.run.bind_address, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn command_parses_bind_address() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _guard = EnvVarGuard::remove("OPENSHELL_BIND_ADDRESS");
        let cli = Cli::try_parse_from([
            "openshell-gateway",
            "--db-url",
            "sqlite::memory:",
            "--bind-address",
            "127.0.0.1",
        ])
        .unwrap();
        assert_eq!(cli.run.bind_address, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn command_reads_bind_address_from_env() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _guard = EnvVarGuard::set("OPENSHELL_BIND_ADDRESS", "0.0.0.0");

        let cli = Cli::try_parse_from(["openshell-gateway", "--db-url", "sqlite::memory:"])
            .expect("env should provide bind address");

        assert_eq!(cli.run.bind_address, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn command_enables_loopback_service_http_by_default() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _guard = EnvVarGuard::remove("OPENSHELL_ENABLE_LOOPBACK_SERVICE_HTTP");

        let cli =
            Cli::try_parse_from(["openshell-gateway", "--db-url", "sqlite::memory:"]).unwrap();

        assert!(cli.run.enable_loopback_service_http);
    }

    #[test]
    fn command_disables_loopback_service_http_with_false_value() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _guard = EnvVarGuard::remove("OPENSHELL_ENABLE_LOOPBACK_SERVICE_HTTP");

        let cli = Cli::try_parse_from([
            "openshell-gateway",
            "--db-url",
            "sqlite::memory:",
            "--enable-loopback-service-http=false",
        ])
        .unwrap();

        assert!(!cli.run.enable_loopback_service_http);
    }

    #[test]
    fn command_reads_loopback_service_http_from_env() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _guard = EnvVarGuard::set("OPENSHELL_ENABLE_LOOPBACK_SERVICE_HTTP", "false");

        let cli =
            Cli::try_parse_from(["openshell-gateway", "--db-url", "sqlite::memory:"]).unwrap();

        assert!(!cli.run.enable_loopback_service_http);
    }

    #[test]
    fn command_reads_server_san_from_env() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _guard = EnvVarGuard::set("OPENSHELL_SERVER_SAN", "*.apps.example.com");

        let cli =
            Cli::try_parse_from(["openshell-gateway", "--db-url", "sqlite::memory:"]).unwrap();

        assert_eq!(cli.run.server_sans, vec!["*.apps.example.com".to_string()]);
    }

    #[test]
    fn generate_certs_subcommand_parses_without_db_url() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _g1 = EnvVarGuard::remove("OPENSHELL_DB_URL");
        let _g2 = EnvVarGuard::remove("POD_NAMESPACE");

        let cli = Cli::try_parse_from([
            "openshell-gateway",
            "generate-certs",
            "--namespace",
            "openshell",
            "--server-secret-name",
            "openshell-server-tls",
            "--client-secret-name",
            "openshell-client-tls",
            "--server-san",
            "openshell.example.com",
            "--server-san",
            "10.0.0.1",
        ])
        .expect("generate-certs should parse without --db-url");

        assert!(matches!(
            cli.command,
            Some(super::Commands::GenerateCerts(_))
        ));
    }

    #[test]
    fn generate_certs_local_mode_parses_without_kube_flags() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _g1 = EnvVarGuard::remove("OPENSHELL_DB_URL");
        let _g2 = EnvVarGuard::remove("POD_NAMESPACE");

        let cli = Cli::try_parse_from([
            "openshell-gateway",
            "generate-certs",
            "--output-dir",
            "/tmp/openshell-certgen",
        ])
        .expect("--output-dir should make namespace/secret-name flags optional");

        assert!(matches!(
            cli.command,
            Some(super::Commands::GenerateCerts(_))
        ));
    }

    #[test]
    fn bare_invocation_with_no_db_url_errors_at_runtime_not_parse_time() {
        // db_url is Option<String> at the clap level so subcommand parsing
        // does not require it. The Run path validates it inside
        // run_from_args. This test asserts the parse step succeeds with no
        // --db-url, mirroring what the runtime check sees.
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _g = EnvVarGuard::remove("OPENSHELL_DB_URL");

        let cli = Cli::try_parse_from(["openshell-gateway"]).expect("parses without --db-url");
        assert!(cli.command.is_none());
        assert!(cli.run.db_url.is_none());
    }
}
