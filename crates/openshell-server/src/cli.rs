// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared CLI entrypoint for the gateway binaries.

use clap::{ArgAction, Command, CommandFactory, FromArgMatches, Parser};
use miette::{Context, IntoDiagnostic, Result};
use openshell_core::ComputeDriverKind;
use openshell_core::config::{
    DEFAULT_DOCKER_NETWORK_NAME, DEFAULT_SERVER_PORT, DEFAULT_SSH_HANDSHAKE_SKEW_SECS,
    DEFAULT_SSH_PORT,
};
use rand::Rng;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use tracing::info;
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

    /// Create or repair a gateway environment file with generated local secrets.
    InitEnv(InitEnvArgs),
}

#[derive(clap::Args, Debug)]
struct InitEnvArgs {
    /// Environment file to create or repair.
    #[arg(long, value_name = "PATH")]
    output: PathBuf,

    /// Compute driver to write when `OPENSHELL_DRIVERS` is absent.
    #[arg(long, value_parser = parse_compute_driver)]
    driver: Option<ComputeDriverKind>,
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
        Some(Commands::InitEnv(args)) => run_init_env(args),
        None => Box::pin(run_from_args(cli.run)).await,
    }
}

fn run_init_env(args: InitEnvArgs) -> Result<()> {
    let result = init_gateway_env(&args.output, args.driver)?;
    info!(
        path = %args.output.display(),
        created = result.created,
        added_secret = result.added_secret,
        added_driver = result.added_driver,
        "gateway environment initialized"
    );
    Ok(())
}

#[derive(Debug, Default, PartialEq, Eq)]
struct InitEnvResult {
    created: bool,
    added_secret: bool,
    added_driver: bool,
}

fn init_gateway_env(path: &Path, driver: Option<ComputeDriverKind>) -> Result<InitEnvResult> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("create parent directory for {}", path.display()))?;
    }

    let mut result = InitEnvResult::default();
    let mut contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            result.created = true;
            gateway_env_header().to_string()
        }
        Err(err) => {
            return Err(err)
                .into_diagnostic()
                .wrap_err_with(|| format!("read {}", path.display()));
        }
    };

    if !env_file_has_key(&contents, "OPENSHELL_SSH_HANDSHAKE_SECRET") {
        ensure_trailing_newline(&mut contents);
        contents.push_str("# Shared secret for gateway-to-sandbox RPC authentication.\n");
        contents
            .push_str("# Auto-generated on first bootstrap. To regenerate: openssl rand -hex 32\n");
        contents.push_str("OPENSHELL_SSH_HANDSHAKE_SECRET=");
        contents.push_str(&generate_secret_hex());
        contents.push('\n');
        result.added_secret = true;
    }

    if let Some(driver) = driver
        && !env_file_has_key(&contents, "OPENSHELL_DRIVERS")
    {
        ensure_trailing_newline(&mut contents);
        contents.push_str("# Compute driver selected for this local gateway.\n");
        contents.push_str("OPENSHELL_DRIVERS=");
        contents.push_str(driver.as_str());
        contents.push('\n');
        result.added_driver = true;
    }

    if result.created || result.added_secret || result.added_driver {
        write_gateway_env(path, &contents)?;
    }

    Ok(result)
}

fn gateway_env_header() -> &'static str {
    "# OpenShell Gateway Environment Configuration\n\
# Generated on first bootstrap. Edit freely; this file is not overwritten.\n\
# Run 'openshell-gateway --help' for the full list of options.\n\n"
}

fn env_file_has_key(contents: &str, key: &str) -> bool {
    let prefix = format!("{key}=");
    contents
        .lines()
        .map(str::trim_start)
        .any(|line| line.starts_with(&prefix))
}

fn ensure_trailing_newline(contents: &mut String) {
    if !contents.is_empty() && !contents.ends_with('\n') {
        contents.push('\n');
    }
}

fn generate_secret_hex() -> String {
    let mut rng = rand::rng();
    let secret: [u8; 32] = rng.random();
    hex::encode(secret)
}

fn write_gateway_env(path: &Path, contents: &str) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options
        .open(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("open {}", path.display()))?;
    file.write_all(contents.as_bytes())
        .into_diagnostic()
        .wrap_err_with(|| format!("write {}", path.display()))?;
    file.sync_all()
        .into_diagnostic()
        .wrap_err_with(|| format!("sync {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, permissions)
            .into_diagnostic()
            .wrap_err_with(|| format!("set permissions on {}", path.display()))?;
    }

    Ok(())
}

async fn run_from_args(args: RunArgs) -> Result<()> {
    let tracing_log_bus = TracingLogBus::new();
    tracing_log_bus.install_subscriber(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
    );

    let bind = SocketAddr::new(args.bind_address, args.port);

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
        .with_ssh_handshake_skew_secs(args.ssh_handshake_skew_secs)
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
    use super::{Cli, ComputeDriverKind, command, init_gateway_env};
    use clap::Parser;
    use std::fs;
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
    fn init_env_subcommand_parses_without_db_url() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _g = EnvVarGuard::remove("OPENSHELL_DB_URL");

        let cli = Cli::try_parse_from([
            "openshell-gateway",
            "init-env",
            "--output",
            "/tmp/openshell-gateway.env",
            "--driver",
            "vm",
        ])
        .expect("init-env should parse without --db-url");

        assert!(matches!(cli.command, Some(super::Commands::InitEnv(_))));
    }

    #[test]
    fn init_gateway_env_creates_secret_and_default_driver() {
        let temp = tempfile::tempdir().unwrap();
        let env_path = temp.path().join("gateway.env");

        let result = init_gateway_env(&env_path, Some(ComputeDriverKind::Vm)).unwrap();
        let contents = fs::read_to_string(&env_path).unwrap();

        assert!(result.created);
        assert!(result.added_secret);
        assert!(result.added_driver);
        assert!(contents.contains("OPENSHELL_SSH_HANDSHAKE_SECRET="));
        assert!(contents.contains("OPENSHELL_DRIVERS=vm"));
    }

    #[test]
    fn init_gateway_env_repairs_partial_file_without_overriding_driver() {
        let temp = tempfile::tempdir().unwrap();
        let env_path = temp.path().join("gateway.env");
        fs::write(&env_path, "OPENSHELL_DRIVERS=podman\n").unwrap();

        let result = init_gateway_env(&env_path, Some(ComputeDriverKind::Vm)).unwrap();
        let contents = fs::read_to_string(&env_path).unwrap();

        assert!(!result.created);
        assert!(result.added_secret);
        assert!(!result.added_driver);
        assert!(contents.contains("OPENSHELL_DRIVERS=podman"));
        assert!(!contents.contains("OPENSHELL_DRIVERS=vm"));
        assert!(contents.contains("OPENSHELL_SSH_HANDSHAKE_SECRET="));
    }

    #[test]
    fn init_gateway_env_preserves_complete_file() {
        let temp = tempfile::tempdir().unwrap();
        let env_path = temp.path().join("gateway.env");
        let original = "OPENSHELL_DRIVERS=docker\nOPENSHELL_SSH_HANDSHAKE_SECRET=existing\n";
        fs::write(&env_path, original).unwrap();

        let result = init_gateway_env(&env_path, Some(ComputeDriverKind::Vm)).unwrap();
        let contents = fs::read_to_string(&env_path).unwrap();

        assert_eq!(result, super::InitEnvResult::default());
        assert_eq!(contents, original);
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
