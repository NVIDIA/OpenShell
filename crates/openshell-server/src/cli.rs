// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared CLI entrypoint for the gateway binaries.

use clap::parser::ValueSource;
use clap::{ArgAction, ArgMatches, Command, CommandFactory, FromArgMatches, Parser};
use miette::{IntoDiagnostic, Result};
use openshell_core::ComputeDriverKind;
use openshell_core::config::{DEFAULT_DOCKER_NETWORK_NAME, DEFAULT_SERVER_PORT, DEFAULT_SSH_PORT};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::certgen;
use crate::compute::{DockerComputeConfig, VmComputeConfig};
use crate::config_file::{self, ConfigFile, GatewayFileSection};
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
    /// Path to a TOML configuration file (see RFC 0003).
    ///
    /// When set, gateway-wide settings and per-driver tables are read from
    /// the file. Command-line flags and `OPENSHELL_*` environment variables
    /// continue to take precedence over file values.
    #[arg(long, env = "OPENSHELL_GATEWAY_CONFIG")]
    config: Option<PathBuf>,

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

    /// gRPC endpoint that sandboxes use to call back into the gateway.
    /// Must be reachable from wherever the sandbox runs (Kubernetes pod,
    /// Docker/Podman container, or VM), and is applied to every compute
    /// driver.
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

    let matches = command().get_matches();
    let cli = Cli::from_arg_matches(&matches).expect("clap validated args");

    match cli.command {
        Some(Commands::GenerateCerts(args)) => certgen::run(args).await,
        None => Box::pin(run_from_args(cli.run, matches)).await,
    }
}

async fn run_from_args(mut args: RunArgs, matches: ArgMatches) -> Result<()> {
    // Load TOML file when --config / OPENSHELL_GATEWAY_CONFIG is set.
    // File values are applied below for any argument that is still at its
    // built-in default — CLI flags and OPENSHELL_* env vars always win.
    let file: Option<ConfigFile> = if let Some(path) = args.config.clone() {
        Some(config_file::load(&path).map_err(|e| miette::miette!("{e}"))?)
    } else {
        None
    };
    if let Some(file) = file.as_ref() {
        merge_file_into_args(&mut args, &file.openshell.gateway, &matches);
    }

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
        let cert_path = args.tls_cert.clone().ok_or_else(|| {
            miette::miette!(
                "--tls-cert is required when TLS is enabled (use --disable-tls to skip)"
            )
        })?;
        let key_path = args.tls_key.clone().ok_or_else(|| {
            miette::miette!("--tls-key is required when TLS is enabled (use --disable-tls to skip)")
        })?;
        Some(openshell_core::TlsConfig {
            cert_path,
            key_path,
            require_client_auth: has_client_ca && !has_oidc,
            client_ca_path: args.tls_client_ca.clone(),
        })
    };

    let db_url = args
        .db_url
        .clone()
        .ok_or_else(|| miette::miette!("--db-url is required (or set OPENSHELL_DB_URL)"))?;

    let mut config = openshell_core::Config::new(tls)
        .with_bind_address(bind)
        .with_log_level(&args.log_level);

    // Listener addresses for the health and metrics endpoints. The file may
    // pin a different interface than the main listener (e.g. health on
    // 127.0.0.1 while gRPC binds 0.0.0.0); the full `SocketAddr` from the
    // file is preserved unless CLI/env supplied an explicit `--health-port` /
    // `--metrics-port`, in which case the port overrides the file value
    // while the IP defaults to `args.bind_address`.
    let file_gateway = file.as_ref().map(|f| &f.openshell.gateway);
    let health_bind = resolve_aux_listener(
        args.bind_address,
        args.health_port,
        &matches,
        "health_port",
        || file_gateway.and_then(|g| g.health_bind_address),
    );
    let metrics_bind = resolve_aux_listener(
        args.bind_address,
        args.metrics_port,
        &matches,
        "metrics_port",
        || file_gateway.and_then(|g| g.metrics_bind_address),
    );

    if let Some(addr) = health_bind {
        if args.port == addr.port() {
            return Err(miette::miette!(
                "--port and --health-port must be different (both set to {})",
                args.port
            ));
        }
        config = config.with_health_bind_address(addr);
    }

    if let Some(addr) = metrics_bind {
        if args.port == addr.port() {
            return Err(miette::miette!(
                "--port and --metrics-port must be different (both set to {})",
                args.port
            ));
        }
        if let Some(health) = health_bind
            && health.port() == addr.port()
        {
            return Err(miette::miette!(
                "--health-port and --metrics-port must be different (both set to {})",
                health.port()
            ));
        }
        config = config.with_metrics_bind_address(addr);
    }

    config = config
        .with_database_url(db_url)
        .with_compute_drivers(args.drivers.clone())
        .with_sandbox_namespace(args.sandbox_namespace.clone())
        .with_ssh_gateway_host(args.ssh_gateway_host.clone())
        .with_ssh_gateway_port(args.ssh_gateway_port)
        .with_sandbox_ssh_port(args.sandbox_ssh_port)
        .with_server_sans(args.server_sans.clone())
        .with_loopback_service_http(args.enable_loopback_service_http);

    if let Some(ttl) = file
        .as_ref()
        .and_then(|f| f.openshell.gateway.ssh_session_ttl_secs)
    {
        config = config.with_ssh_session_ttl_secs(ttl);
    }

    if let Some(image) = args.sandbox_image.clone() {
        config = config.with_sandbox_image(image);
    }

    if let Some(policy) = args.sandbox_image_pull_policy.clone() {
        config = config.with_sandbox_image_pull_policy(policy);
    }

    if let Some(endpoint) = args.grpc_endpoint.clone() {
        config = config.with_grpc_endpoint(endpoint);
    }

    if let Some(name) = args.client_tls_secret_name.clone() {
        config = config.with_client_tls_secret_name(name);
    }

    if let Some(ip) = args.host_gateway_ip.clone() {
        config = config.with_host_gateway_ip(ip);
    }

    if let Some(issuer) = args.oidc_issuer.clone() {
        config = config.with_oidc(openshell_core::OidcConfig {
            issuer,
            audience: args.oidc_audience.clone(),
            jwks_ttl_secs: args.oidc_jwks_ttl,
            roles_claim: args.oidc_roles_claim.clone(),
            admin_role: args.oidc_admin_role.clone(),
            user_role: args.oidc_user_role.clone(),
            scopes_claim: args.oidc_scopes_claim.clone(),
        });
    }

    config.enable_user_namespaces = args.enable_user_namespaces;

    let vm_config = build_vm_config(&args, &matches, &config, file.as_ref())?;
    let docker_config = build_docker_config(&args, &matches, file.as_ref())?;

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

    Box::pin(run_server(
        config,
        vm_config,
        docker_config,
        file,
        tracing_log_bus,
    ))
    .await
    .into_diagnostic()
}

fn parse_compute_driver(value: &str) -> std::result::Result<ComputeDriverKind, String> {
    value.parse()
}

/// Returns `true` when an argument's value came from clap's built-in default
/// (or was never supplied at all). When the predicate is `true`, the loader
/// is free to replace the value with one read from the TOML config file.
fn arg_defaulted(matches: &ArgMatches, id: &str) -> bool {
    matches!(
        matches.value_source(id),
        None | Some(ValueSource::DefaultValue)
    )
}

/// Resolve the bind address for an auxiliary listener (health / metrics).
///
/// The precedence is:
///   1. CLI flag or `OPENSHELL_*` env var explicitly set on the corresponding
///      port argument → `bind_address:port` (port from CLI, IP from the main
///      listener interface).
///   2. Full `SocketAddr` from `[openshell.gateway].{health,metrics}_bind_address`
///      → used as-is (this is how operators pin a loopback-only health port
///      on a gateway whose gRPC listener is bound publicly).
///   3. Otherwise the listener is disabled (returns `None`).
fn resolve_aux_listener(
    bind_ip: IpAddr,
    port_arg: u16,
    matches: &ArgMatches,
    port_id: &str,
    file_addr: impl FnOnce() -> Option<SocketAddr>,
) -> Option<SocketAddr> {
    if !arg_defaulted(matches, port_id) {
        if port_arg == 0 {
            return None;
        }
        return Some(SocketAddr::new(bind_ip, port_arg));
    }
    if let Some(addr) = file_addr() {
        return Some(addr);
    }
    if port_arg == 0 {
        None
    } else {
        Some(SocketAddr::new(bind_ip, port_arg))
    }
}

/// Apply gateway-wide values from `[openshell.gateway]` onto `RunArgs` for
/// every argument that is still sourced from clap's built-in default.
///
/// The function intentionally does not touch `database_url` — that secret is
/// env-only and the loader already rejected it when it appears in the file.
fn merge_file_into_args(args: &mut RunArgs, file: &GatewayFileSection, matches: &ArgMatches) {
    if let Some(addr) = file.bind_address {
        if arg_defaulted(matches, "bind_address") {
            args.bind_address = addr.ip();
        }
        if arg_defaulted(matches, "port") {
            args.port = addr.port();
        }
    }
    // Note: file's full health_bind_address / metrics_bind_address are
    // consumed in `run_from_args`'s listener-resolution block so the IP
    // half of the SocketAddr is preserved. Copying only the port here
    // would silently relocate a loopback-intended listener onto the
    // public bind address.
    if let Some(level) = &file.log_level
        && arg_defaulted(matches, "log_level")
    {
        args.log_level.clone_from(level);
    }
    if let Some(drivers) = &file.compute_drivers
        && arg_defaulted(matches, "drivers")
    {
        args.drivers.clone_from(drivers);
    }
    if let Some(ns) = &file.sandbox_namespace
        && arg_defaulted(matches, "sandbox_namespace")
    {
        args.sandbox_namespace.clone_from(ns);
    }
    if let Some(port) = file.sandbox_ssh_port
        && arg_defaulted(matches, "sandbox_ssh_port")
    {
        args.sandbox_ssh_port = port;
    }
    if let Some(host) = &file.ssh_gateway_host
        && arg_defaulted(matches, "ssh_gateway_host")
    {
        args.ssh_gateway_host.clone_from(host);
    }
    if let Some(port) = file.ssh_gateway_port
        && arg_defaulted(matches, "ssh_gateway_port")
    {
        args.ssh_gateway_port = port;
    }
    if let Some(image) = &file.default_image
        && args.sandbox_image.is_none()
        && arg_defaulted(matches, "sandbox_image")
    {
        args.sandbox_image = Some(image.clone());
    }
    if let Some(secret) = &file.client_tls_secret_name
        && args.client_tls_secret_name.is_none()
        && arg_defaulted(matches, "client_tls_secret_name")
    {
        args.client_tls_secret_name = Some(secret.clone());
    }
    if let Some(ip) = &file.host_gateway_ip
        && args.host_gateway_ip.is_none()
        && arg_defaulted(matches, "host_gateway_ip")
    {
        args.host_gateway_ip = Some(ip.clone());
    }
    if let Some(enabled) = file.enable_user_namespaces
        && arg_defaulted(matches, "enable_user_namespaces")
    {
        args.enable_user_namespaces = enabled;
    }
    if let Some(sans) = &file.server_sans
        && args.server_sans.is_empty()
        && arg_defaulted(matches, "server_sans")
    {
        args.server_sans.clone_from(sans);
    }
    if let Some(enabled) = file.enable_loopback_service_http
        && arg_defaulted(matches, "enable_loopback_service_http")
    {
        args.enable_loopback_service_http = enabled;
    }
    if let Some(disabled) = file.disable_tls
        && arg_defaulted(matches, "disable_tls")
    {
        args.disable_tls = disabled;
    }
    // TLS gateway listener fields
    if let Some(tls) = &file.tls {
        if args.tls_cert.is_none() && arg_defaulted(matches, "tls_cert") {
            args.tls_cert = Some(tls.cert_path.clone());
        }
        if args.tls_key.is_none() && arg_defaulted(matches, "tls_key") {
            args.tls_key = Some(tls.key_path.clone());
        }
        if args.tls_client_ca.is_none() && arg_defaulted(matches, "tls_client_ca") {
            args.tls_client_ca = tls.client_ca_path.clone();
        }
    }
    // OIDC fields
    if let Some(oidc) = &file.oidc {
        if args.oidc_issuer.is_none() && arg_defaulted(matches, "oidc_issuer") {
            args.oidc_issuer = Some(oidc.issuer.clone());
        }
        if arg_defaulted(matches, "oidc_audience") {
            args.oidc_audience.clone_from(&oidc.audience);
        }
        if arg_defaulted(matches, "oidc_jwks_ttl") {
            args.oidc_jwks_ttl = oidc.jwks_ttl_secs;
        }
        if arg_defaulted(matches, "oidc_roles_claim") {
            args.oidc_roles_claim.clone_from(&oidc.roles_claim);
        }
        if arg_defaulted(matches, "oidc_admin_role") {
            args.oidc_admin_role.clone_from(&oidc.admin_role);
        }
        if arg_defaulted(matches, "oidc_user_role") {
            args.oidc_user_role.clone_from(&oidc.user_role);
        }
        if arg_defaulted(matches, "oidc_scopes_claim") {
            args.oidc_scopes_claim.clone_from(&oidc.scopes_claim);
        }
    }
}

/// Build [`VmComputeConfig`] by overlaying CLI args on top of the
/// `[openshell.drivers.vm]` table inherited from `[openshell.gateway]`.
fn build_vm_config(
    args: &RunArgs,
    matches: &ArgMatches,
    config: &openshell_core::Config,
    file: Option<&ConfigFile>,
) -> Result<VmComputeConfig> {
    let mut cfg = if let Some(file) = file {
        let merged = config_file::driver_table(
            ComputeDriverKind::Vm,
            &file.openshell.gateway,
            file.openshell.drivers.get("vm"),
        );
        merged
            .try_into::<VmComputeConfig>()
            .map_err(|e| miette::miette!("invalid [openshell.drivers.vm] table: {e}"))?
    } else {
        VmComputeConfig::default()
    };

    // CLI/env overrides — and `state_dir` is also pulled from RunArgs when the
    // file did not set it, so the gateway always has a working directory.
    if !arg_defaulted(matches, "vm_driver_state_dir") || cfg.state_dir.as_os_str().is_empty() {
        cfg.state_dir.clone_from(&args.vm_driver_state_dir);
    }
    if !arg_defaulted(matches, "driver_dir") || cfg.driver_dir.is_none() {
        cfg.driver_dir.clone_from(&args.driver_dir);
    }
    if !arg_defaulted(matches, "vm_krun_log_level") {
        cfg.krun_log_level = args.vm_krun_log_level;
    }
    if !arg_defaulted(matches, "vm_vcpus") {
        cfg.vcpus = args.vm_vcpus;
    }
    if !arg_defaulted(matches, "vm_mem_mib") {
        cfg.mem_mib = args.vm_mem_mib;
    }
    if let Some(p) = args.vm_tls_ca.clone() {
        cfg.guest_tls_ca = Some(p);
    }
    if let Some(p) = args.vm_tls_cert.clone() {
        cfg.guest_tls_cert = Some(p);
    }
    if let Some(p) = args.vm_tls_key.clone() {
        cfg.guest_tls_key = Some(p);
    }
    // Fall through: image inherited from gateway-wide `sandbox_image` when
    // the merged table did not supply `default_image`.
    if cfg.default_image.is_empty() {
        cfg.default_image.clone_from(&config.sandbox_image);
    }
    Ok(cfg)
}

/// Build [`DockerComputeConfig`] using the same inheritance pattern as
/// [`build_vm_config`].
fn build_docker_config(
    args: &RunArgs,
    matches: &ArgMatches,
    file: Option<&ConfigFile>,
) -> Result<DockerComputeConfig> {
    let mut cfg = if let Some(file) = file {
        let merged = config_file::driver_table(
            ComputeDriverKind::Docker,
            &file.openshell.gateway,
            file.openshell.drivers.get("docker"),
        );
        merged
            .try_into::<DockerComputeConfig>()
            .map_err(|e| miette::miette!("invalid [openshell.drivers.docker] table: {e}"))?
    } else {
        DockerComputeConfig::default()
    };

    if args.docker_supervisor_bin.is_some() {
        cfg.supervisor_bin.clone_from(&args.docker_supervisor_bin);
    }
    if args.docker_supervisor_image.is_some() {
        cfg.supervisor_image
            .clone_from(&args.docker_supervisor_image);
    }
    if args.docker_tls_ca.is_some() {
        cfg.guest_tls_ca.clone_from(&args.docker_tls_ca);
    }
    if args.docker_tls_cert.is_some() {
        cfg.guest_tls_cert.clone_from(&args.docker_tls_cert);
    }
    if args.docker_tls_key.is_some() {
        cfg.guest_tls_key.clone_from(&args.docker_tls_key);
    }
    if !arg_defaulted(matches, "docker_network_name") {
        cfg.network_name.clone_from(&args.docker_network_name);
    }
    Ok(cfg)
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

    // ── Config-file merge tests ──────────────────────────────────────────
    //
    // `merge_file_into_args` is the bridge between `config_file::ConfigFile`
    // and `RunArgs`. These cases lock in the precedence rule:
    //
    //   CLI flag  >  OPENSHELL_* env var  >  TOML file  >  built-in default
    //
    // by exercising each combination on representative gateway fields.

    use super::{ConfigFile, merge_file_into_args};
    use clap::FromArgMatches;

    fn parse_with_args(argv: &[&str]) -> (super::RunArgs, clap::ArgMatches) {
        let matches = command().try_get_matches_from(argv).expect("parses");
        let cli = Cli::from_arg_matches(&matches).expect("from arg matches");
        (cli.run, matches)
    }

    fn config_file_from_toml(toml: &str) -> ConfigFile {
        toml::from_str(toml).expect("valid TOML in test fixture")
    }

    #[test]
    fn file_value_applies_when_cli_uses_default() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _g1 = EnvVarGuard::remove("OPENSHELL_BIND_ADDRESS");
        let _g2 = EnvVarGuard::remove("OPENSHELL_SERVER_PORT");
        let _g3 = EnvVarGuard::remove("OPENSHELL_LOG_LEVEL");

        let (mut args, matches) =
            parse_with_args(&["openshell-gateway", "--db-url", "sqlite::memory:"]);
        let file = config_file_from_toml(
            r#"
[openshell.gateway]
bind_address = "0.0.0.0:9090"
log_level = "debug"
"#,
        );
        merge_file_into_args(&mut args, &file.openshell.gateway, &matches);

        assert_eq!(args.bind_address, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(args.port, 9090);
        assert_eq!(args.log_level, "debug");
    }

    #[test]
    fn cli_flag_overrides_file_value() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _g1 = EnvVarGuard::remove("OPENSHELL_BIND_ADDRESS");
        let _g2 = EnvVarGuard::remove("OPENSHELL_LOG_LEVEL");

        let (mut args, matches) = parse_with_args(&[
            "openshell-gateway",
            "--db-url",
            "sqlite::memory:",
            "--log-level",
            "warn",
        ]);
        let file = config_file_from_toml(
            r#"
[openshell.gateway]
log_level = "debug"
"#,
        );
        merge_file_into_args(&mut args, &file.openshell.gateway, &matches);

        assert_eq!(args.log_level, "warn", "CLI flag must win over file");
    }

    #[test]
    fn env_var_overrides_file_value() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _g = EnvVarGuard::set("OPENSHELL_LOG_LEVEL", "trace");

        let (mut args, matches) =
            parse_with_args(&["openshell-gateway", "--db-url", "sqlite::memory:"]);
        let file = config_file_from_toml(
            r#"
[openshell.gateway]
log_level = "debug"
"#,
        );
        merge_file_into_args(&mut args, &file.openshell.gateway, &matches);

        assert_eq!(args.log_level, "trace", "env var must win over file");
    }

    #[test]
    fn file_oidc_block_populates_oidc_args() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _g1 = EnvVarGuard::remove("OPENSHELL_OIDC_ISSUER");
        let _g2 = EnvVarGuard::remove("OPENSHELL_OIDC_AUDIENCE");

        let (mut args, matches) =
            parse_with_args(&["openshell-gateway", "--db-url", "sqlite::memory:"]);
        let file = config_file_from_toml(
            r#"
[openshell.gateway.oidc]
issuer = "https://idp.example.com"
audience = "openshell-cli"
"#,
        );
        merge_file_into_args(&mut args, &file.openshell.gateway, &matches);

        assert_eq!(args.oidc_issuer.as_deref(), Some("https://idp.example.com"));
        assert_eq!(args.oidc_audience, "openshell-cli");
    }

    #[test]
    fn aux_listener_preserves_file_ip_against_public_bind() {
        use std::net::SocketAddr;
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _g = EnvVarGuard::remove("OPENSHELL_HEALTH_PORT");

        let (_args, matches) =
            parse_with_args(&["openshell-gateway", "--db-url", "sqlite::memory:"]);
        let file_addr: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        let resolved = super::resolve_aux_listener(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0,
            &matches,
            "health_port",
            || Some(file_addr),
        );
        assert_eq!(
            resolved,
            Some(file_addr),
            "TOML health_bind_address 127.0.0.1:8081 must not be relocated to 0.0.0.0:8081"
        );
    }

    #[test]
    fn aux_listener_cli_port_overrides_file_addr() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _g = EnvVarGuard::remove("OPENSHELL_HEALTH_PORT");

        let (_args, matches) = parse_with_args(&[
            "openshell-gateway",
            "--db-url",
            "sqlite::memory:",
            "--health-port",
            "9999",
        ]);
        let file_addr: std::net::SocketAddr = "127.0.0.1:8081".parse().unwrap();
        let resolved = super::resolve_aux_listener(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            9999,
            &matches,
            "health_port",
            || Some(file_addr),
        );
        assert_eq!(
            resolved,
            Some("0.0.0.0:9999".parse().unwrap()),
            "CLI flag must win over file value"
        );
    }

    #[test]
    fn file_disable_tls_applies() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _g = EnvVarGuard::remove("OPENSHELL_DISABLE_TLS");

        let (mut args, matches) =
            parse_with_args(&["openshell-gateway", "--db-url", "sqlite::memory:"]);
        let file = config_file_from_toml(
            r"
[openshell.gateway]
disable_tls = true
",
        );
        merge_file_into_args(&mut args, &file.openshell.gateway, &matches);

        assert!(args.disable_tls);
    }

    #[test]
    fn file_ssh_session_ttl_secs_is_parsed() {
        // The loader must accept and surface the documented key. The actual
        // wiring into `Config` happens in `run_from_args` against the parsed
        // file (not via `merge_file_into_args`, since there is no matching
        // `RunArgs` field), so this test pins the schema half.
        let file = config_file_from_toml(
            r"
[openshell.gateway]
ssh_session_ttl_secs = 1234
",
        );
        assert_eq!(file.openshell.gateway.ssh_session_ttl_secs, Some(1234));
    }

    #[test]
    fn file_populates_service_routing_fields() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _g1 = EnvVarGuard::remove("OPENSHELL_SERVER_SAN");
        let _g2 = EnvVarGuard::remove("OPENSHELL_ENABLE_LOOPBACK_SERVICE_HTTP");

        let (mut args, matches) =
            parse_with_args(&["openshell-gateway", "--db-url", "sqlite::memory:"]);
        let file = config_file_from_toml(
            r#"
[openshell.gateway]
server_sans                  = ["gateway.local", "*.dev.openshell.localhost"]
enable_loopback_service_http = false
"#,
        );
        merge_file_into_args(&mut args, &file.openshell.gateway, &matches);

        assert_eq!(
            args.server_sans,
            vec![
                "gateway.local".to_string(),
                "*.dev.openshell.localhost".to_string()
            ]
        );
        assert!(!args.enable_loopback_service_http);
    }

    #[test]
    fn env_var_overrides_file_loopback_service_http() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _g = EnvVarGuard::set("OPENSHELL_ENABLE_LOOPBACK_SERVICE_HTTP", "true");

        let (mut args, matches) =
            parse_with_args(&["openshell-gateway", "--db-url", "sqlite::memory:"]);
        let file = config_file_from_toml(
            r"
[openshell.gateway]
enable_loopback_service_http = false
",
        );
        merge_file_into_args(&mut args, &file.openshell.gateway, &matches);

        assert!(
            args.enable_loopback_service_http,
            "env var must win over file"
        );
    }

    #[test]
    fn driver_inherits_shared_image_from_gateway_section() {
        // [openshell.gateway].default_image inherits into the K8s driver
        // table when the driver-specific table does not set it.
        let file = config_file_from_toml(
            r#"
[openshell.gateway]
default_image = "ghcr.io/nvidia/openshell/sandbox:1.0"

[openshell.drivers.kubernetes]
namespace = "agents"
"#,
        );
        let merged = crate::config_file::driver_table(
            super::ComputeDriverKind::Kubernetes,
            &file.openshell.gateway,
            file.openshell.drivers.get("kubernetes"),
        );
        let parsed = merged
            .try_into::<openshell_driver_kubernetes::KubernetesComputeConfig>()
            .expect("merged table deserializes");
        assert_eq!(parsed.default_image, "ghcr.io/nvidia/openshell/sandbox:1.0");
        assert_eq!(parsed.namespace, "agents");
    }

    #[test]
    fn driver_specific_value_overrides_gateway_inheritance() {
        let file = config_file_from_toml(
            r#"
[openshell.gateway]
default_image = "gateway-default:1.0"

[openshell.drivers.kubernetes]
default_image = "k8s-specific:1.0"
"#,
        );
        let merged = crate::config_file::driver_table(
            super::ComputeDriverKind::Kubernetes,
            &file.openshell.gateway,
            file.openshell.drivers.get("kubernetes"),
        );
        let parsed = merged
            .try_into::<openshell_driver_kubernetes::KubernetesComputeConfig>()
            .expect("deserializes");
        assert_eq!(parsed.default_image, "k8s-specific:1.0");
    }
}
