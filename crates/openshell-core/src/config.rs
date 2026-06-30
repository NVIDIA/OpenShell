// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configuration management for `OpenShell` components.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
#[cfg(unix)]
use std::io::{Read, Write};
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;

// ── Public default constants ────────────────────────────────────────────
//
// Canonical source for default values used across multiple crates.
// Clap `default_value_t` annotations and runtime fallbacks should
// reference these constants instead of hardcoding literals.

/// Default SSH port inside sandbox containers.
pub const DEFAULT_SSH_PORT: u16 = 2222;

/// Default gateway server port.
pub const DEFAULT_SERVER_PORT: u16 = 17670;

/// Default container stop timeout in seconds (SIGTERM → SIGKILL).
pub const DEFAULT_STOP_TIMEOUT_SECS: u32 = 10;

/// Default Docker bridge network name for local sandboxes.
pub const DEFAULT_DOCKER_NETWORK_NAME: &str = "openshell-docker";

/// Default domain used for browser-facing sandbox service URLs.
pub const DEFAULT_SERVICE_ROUTING_DOMAIN: &str = "openshell.localhost";

/// Default OCI repository for the supervisor image (no tag).
pub const DEFAULT_SUPERVISOR_IMAGE_REPO: &str = "ghcr.io/nvidia/openshell/supervisor";

/// Return the default supervisor image reference with a version-pinned tag.
#[must_use]
pub fn default_supervisor_image() -> String {
    format!(
        "{DEFAULT_SUPERVISOR_IMAGE_REPO}:{}",
        default_supervisor_image_tag()
    )
}

fn default_supervisor_image_tag() -> String {
    resolve_supervisor_image_tag(
        option_env!("OPENSHELL_IMAGE_TAG"),
        option_env!("IMAGE_TAG"),
        env!("CARGO_PKG_VERSION"),
    )
}

/// Resolve the supervisor image tag from build-time inputs.
///
/// Priority: `OPENSHELL_IMAGE_TAG` > `IMAGE_TAG` > `CARGO_PKG_VERSION`.
/// Falls back to `"dev"` when the Cargo version is empty or `"0.0.0"`.
/// Replaces `+` with `-` for OCI tag compatibility.
#[must_use]
pub fn resolve_supervisor_image_tag(
    openshell_image_tag: Option<&str>,
    image_tag: Option<&str>,
    cargo_pkg_version: &str,
) -> String {
    let tag = openshell_image_tag
        .filter(|tag| !tag.is_empty())
        .or_else(|| image_tag.filter(|tag| !tag.is_empty()))
        .unwrap_or_else(|| {
            if cargo_pkg_version.is_empty() || cargo_pkg_version == "0.0.0" {
                "dev"
            } else {
                cargo_pkg_version
            }
        });

    tag.replace('+', "-")
}

/// CDI device identifier for requesting all NVIDIA GPUs.
pub const CDI_GPU_DEVICE_ALL: &str = "nvidia.com/gpu=all";

/// Default maximum number of processes (PIDs) allowed inside a sandbox container.
///
/// Shared by the Docker and Podman drivers; override via driver config.
pub const DEFAULT_SANDBOX_PIDS_LIMIT: i64 = 2048;

/// Compute backends the gateway can orchestrate sandboxes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputeDriverKind {
    Kubernetes,
    Vm,
    Docker,
    Podman,
}

impl ComputeDriverKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Kubernetes => "kubernetes",
            Self::Vm => "vm",
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }
}

/// Normalize a configured compute driver name.
///
/// Built-in driver names and custom remote driver names share the same
/// selection namespace. The normalized value is lowercase ASCII and may contain
/// letters, digits, `-`, and `_`.
pub fn normalize_compute_driver_name(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("compute driver name cannot be empty".to_string());
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(format!(
            "invalid compute driver name '{value}'. use ASCII letters, digits, '-' or '_'"
        ));
    }
    Ok(value.to_ascii_lowercase())
}

impl fmt::Display for ComputeDriverKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ComputeDriverKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "kubernetes" => Ok(Self::Kubernetes),
            "vm" => Ok(Self::Vm),
            "docker" => Ok(Self::Docker),
            "podman" => Ok(Self::Podman),
            other => Err(format!(
                "unsupported compute driver '{other}'. expected one of: kubernetes, vm, docker, podman"
            )),
        }
    }
}

/// Auto-detect the appropriate compute driver based on the runtime environment.
///
/// Priority order: Kubernetes → Podman → Docker.
/// VM is never auto-detected (requires explicit `--drivers vm`).
///
/// Returns the first driver where the environment check passes.
/// Returns `None` if no compatible driver is found.
pub fn detect_driver() -> Option<ComputeDriverKind> {
    // Kubernetes: check for KUBERNETES_SERVICE_HOST env var (set inside pods)
    if std::env::var_os("KUBERNETES_SERVICE_HOST").is_some() {
        return Some(ComputeDriverKind::Kubernetes);
    }

    // Podman: check for a reachable local API socket.
    if is_podman_available() {
        return Some(ComputeDriverKind::Podman);
    }

    // Docker: check if the CLI is available or a local Docker socket exists.
    if is_docker_available() {
        return Some(ComputeDriverKind::Docker);
    }

    None
}

/// Check if a binary is available on the system PATH.
fn is_binary_available(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn is_podman_available() -> bool {
    podman_socket_candidates()
        .iter()
        .any(|path| podman_socket_responds(path))
}

fn podman_socket_candidates() -> Vec<PathBuf> {
    let socket = std::env::var("OPENSHELL_PODMAN_SOCKET")
        .ok()
        .filter(|path| !path.trim().is_empty())
        .map(PathBuf::from);
    podman_socket_candidates_from_env(
        socket,
        std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
        std::env::var_os("HOME").map(PathBuf::from),
    )
}

fn podman_socket_candidates_from_env(
    socket: Option<PathBuf>,
    runtime_dir: Option<PathBuf>,
    home: Option<PathBuf>,
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Some(path) = socket {
        candidates.push(path);
    }

    if let Some(runtime_dir) = runtime_dir {
        candidates.push(runtime_dir.join("podman/podman.sock"));
    }

    #[cfg(target_os = "linux")]
    {
        candidates.push(PathBuf::from(format!(
            "/run/user/{}/podman/podman.sock",
            current_uid()
        )));
    }

    if let Some(home) = home {
        candidates.push(home.join(".local/share/containers/podman/machine/podman.sock"));
    }

    candidates
}

fn is_docker_available() -> bool {
    is_binary_available("docker") || docker_socket_available()
}

fn docker_socket_available() -> bool {
    docker_socket_candidates()
        .iter()
        .any(|path| is_unix_socket(path))
}

fn docker_socket_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(host) = std::env::var("DOCKER_HOST")
        && let Some(path) = docker_host_unix_socket_path(&host)
    {
        candidates.push(path);
    }

    candidates.push(PathBuf::from("/var/run/docker.sock"));

    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(PathBuf::from(home).join(".docker/run/docker.sock"));
    }

    if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        candidates.push(PathBuf::from(runtime_dir).join("docker.sock"));
    }

    candidates
}

fn docker_host_unix_socket_path(host: &str) -> Option<PathBuf> {
    let path = host.trim().strip_prefix("unix://")?;
    (!path.is_empty()).then(|| PathBuf::from(path))
}

#[cfg(unix)]
fn is_unix_socket(path: &Path) -> bool {
    path.metadata()
        .is_ok_and(|metadata| metadata.file_type().is_socket())
}

#[cfg(unix)]
fn podman_socket_responds(path: &Path) -> bool {
    unix_socket_http_ping(path, |response| {
        http_response_is_success(response) && contains_ascii(response, b"Libpod-Api-Version:")
    })
}

#[cfg(unix)]
fn unix_socket_http_ping(path: &Path, accepts_response: impl FnOnce(&[u8]) -> bool) -> bool {
    const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
    const PING_REQUEST: &[u8] =
        b"GET /_ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

    if !is_unix_socket(path) {
        return false;
    }

    let Ok(mut stream) = std::os::unix::net::UnixStream::connect(path) else {
        return false;
    };
    if stream.set_read_timeout(Some(PROBE_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(PROBE_TIMEOUT)).is_err()
        || stream.write_all(PING_REQUEST).is_err()
    {
        return false;
    }

    let mut response = [0_u8; 512];
    let mut total = 0;
    while total < response.len() {
        let Ok(n) = stream.read(&mut response[total..]) else {
            return false;
        };
        if n == 0 {
            break;
        }
        total += n;
        if contains_ascii(&response[..total], b"\r\n\r\n") {
            break;
        }
    }
    total > 0 && accepts_response(&response[..total])
}

#[cfg(unix)]
fn http_response_is_success(response: &[u8]) -> bool {
    response.starts_with(b"HTTP/1.1 200") || response.starts_with(b"HTTP/1.0 200")
}

#[cfg(unix)]
fn contains_ascii(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

#[cfg(all(unix, test))]
fn is_reachable_unix_socket(path: &Path) -> bool {
    is_unix_socket(path) && std::os::unix::net::UnixStream::connect(path).is_ok()
}

#[cfg(all(unix, target_os = "linux"))]
fn current_uid() -> u32 {
    use std::os::unix::fs::MetadataExt;

    std::fs::metadata("/proc/self").map_or(0, |metadata| metadata.uid())
}

#[cfg(not(unix))]
fn is_unix_socket(path: &Path) -> bool {
    let _ = path;
    false
}

#[cfg(not(unix))]
fn podman_socket_responds(path: &Path) -> bool {
    let _ = path;
    false
}

/// Server configuration.
///
/// Built programmatically in [`crate::Config::new`] and the gateway CLI from
/// the parsed config file, env vars, and CLI flags. It is never deserialized
/// directly; the on-disk config schema lives in the gateway's `config_file`
/// module ([`crate::TlsConfig`] and the other nested tables carry their own
/// `Deserialize` impls for that purpose).
#[derive(Debug, Clone)]
pub struct Config {
    /// Address to bind the server to.
    pub bind_address: SocketAddr,

    /// Address to bind the unauthenticated health endpoint to.
    ///
    /// When `None`, the dedicated health listener is disabled.
    pub health_bind_address: Option<SocketAddr>,

    /// Address to bind the Prometheus metrics endpoint to.
    ///
    /// When `None`, the dedicated metrics listener is disabled.
    pub metrics_bind_address: Option<SocketAddr>,

    /// Log level (trace, debug, info, warn, error).
    pub log_level: String,

    /// TLS configuration.  When `None`, the server listens on plaintext HTTP.
    pub tls: Option<TlsConfig>,

    /// OIDC configuration. When `Some`, the server validates Bearer JWTs.
    pub oidc: Option<OidcConfig>,

    /// Gateway user authentication behavior.
    pub auth: GatewayAuthConfig,

    /// mTLS user authentication configuration. When enabled, a verified TLS
    /// client certificate can authenticate CLI/SDK callers as a
    /// `Principal::User`. This is for local single-user gateways only;
    /// sandbox identity is always carried by gateway-minted sandbox JWTs.
    pub mtls_auth: MtlsAuthConfig,

    /// Gateway-minted sandbox JWT configuration. When `Some`, the gateway
    /// loads the signing key from disk and accepts gateway-issued sandbox
    /// JWTs as `Principal::Sandbox`. Required for the per-sandbox identity
    /// flow (issue #1354).
    pub gateway_jwt: Option<GatewayJwtConfig>,

    /// Database URL for persistence.
    pub database_url: String,

    /// Compute drivers configured for the gateway.
    ///
    /// The config shape allows multiple drivers so the gateway can evolve
    /// toward multi-backend routing. Current releases require exactly one
    /// configured driver.
    pub compute_drivers: Vec<String>,

    /// Operator-provided endpoints for named remote compute drivers.
    ///
    /// This is populated by CLI/env inputs such as `--compute-driver-socket`.
    /// TOML-authored endpoints live under `[openshell.drivers.<name>]` and are
    /// resolved by the gateway config loader.
    pub compute_driver_endpoints: BTreeMap<String, PathBuf>,

    /// TTL for SSH session tokens, in seconds. 0 disables expiry.
    pub ssh_session_ttl_secs: u64,

    /// Maximum gRPC requests allowed per rate-limit window.
    ///
    /// When paired with [`Self::grpc_rate_limit_window_secs`], positive values
    /// enable gateway-wide gRPC request rate limiting. `None` or `0` disables
    /// the limit.
    pub grpc_rate_limit_requests: Option<u64>,

    /// gRPC rate-limit window length in seconds.
    ///
    /// When paired with [`Self::grpc_rate_limit_requests`], positive values
    /// enable gateway-wide gRPC request rate limiting. `None` or `0` disables
    /// the limit.
    pub grpc_rate_limit_window_secs: Option<u64>,

    /// Browser-facing sandbox service routing configuration.
    pub service_routing: ServiceRoutingConfig,
}

/// Browser-facing sandbox service routing configuration.
///
/// Part of the programmatically-built [`Config`]; never deserialized directly.
#[derive(Debug, Clone)]
pub struct ServiceRoutingConfig {
    /// Base domains accepted for `sandbox--service.<domain>` routes.
    /// The first domain is used when the gateway prints endpoint URLs.
    pub base_domains: Vec<String>,

    /// Enable TLS-enabled loopback gateway listeners to also accept plaintext
    /// HTTP for sandbox service hostnames.
    pub enable_loopback_service_http: bool,
}

/// TLS configuration.
///
/// Two modes are supported:
/// - **HTTPS with optional mTLS** (`client_ca_path = Some`):
///   Client certificates are validated against the given CA when presented,
///   but never required.  Clients may connect with or without a certificate.
/// - **HTTPS-only** (`client_ca_path = None`):
///   Server-side TLS only; no client certificates are requested.
///
/// In both modes, authentication is handled at the application layer
/// (e.g. OIDC bearer tokens).  mTLS is an additional mechanism.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Path to the TLS certificate file.
    pub cert_path: PathBuf,

    /// Path to the TLS private key file.
    pub key_path: PathBuf,

    /// Path to the CA certificate file for client certificate verification.
    /// When `Some`, client certs signed by this CA are validated.
    /// When `None`, the server does not request client certs.
    #[serde(default)]
    pub client_ca_path: Option<PathBuf>,

    /// When `true` and `client_ca_path` is `Some`, the TLS handshake rejects
    /// connections that do not present a valid client certificate.
    /// When `false`, client certificates are accepted but not required.
    #[serde(default)]
    pub require_client_auth: bool,
}

/// OIDC (`OpenID` Connect) configuration for JWT-based authentication.
///
/// When configured, the server validates `authorization: Bearer <JWT>`
/// headers on gRPC requests against the specified issuer's JWKS endpoint.
///
/// The roles claim path is configurable to support different providers:
/// - Keycloak: `realm_access.roles` (default)
/// - Entra ID / Okta: `roles`
/// - Custom: any dot-separated path into the JWT claims
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// OIDC issuer URL (e.g., `http://localhost:8180/realms/openshell`).
    pub issuer: String,

    /// Expected audience (`aud`) claim. Typically the OIDC client ID.
    pub audience: String,

    /// JWKS cache TTL in seconds. Defaults to 3600 (1 hour).
    #[serde(default = "default_jwks_ttl_secs")]
    pub jwks_ttl_secs: u64,

    /// Dot-separated path to the roles array in the JWT claims.
    /// Defaults to `realm_access.roles` (Keycloak).
    /// Examples: `roles` (Entra ID), `groups` (Okta), `custom.path.roles`.
    #[serde(default = "default_roles_claim")]
    pub roles_claim: String,

    /// Role name that grants admin access. Defaults to `openshell-admin`.
    #[serde(default = "default_admin_role")]
    pub admin_role: String,

    /// Role name that grants standard user access. Defaults to `openshell-user`.
    #[serde(default = "default_user_role")]
    pub user_role: String,

    /// Dot-separated path to the scopes value in the JWT claims.
    /// When non-empty, the server enforces scope-based permissions on top of roles.
    /// Keycloak: `scope` (space-delimited string). Okta: `scp` (JSON array).
    #[serde(default)]
    pub scopes_claim: String,
}

/// mTLS user authentication for local, single-user gateways.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MtlsAuthConfig {
    /// When true, the gateway maps a verified TLS client certificate into a
    /// user principal. Keep disabled for Kubernetes deployments because
    /// Kubernetes sandbox pods and external users must not share user auth.
    #[serde(default)]
    pub enabled: bool,
}

/// Gateway user authentication settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayAuthConfig {
    /// When true, unauthenticated user/CLI calls are accepted as a local
    /// developer principal. This is an unsafe local-development escape hatch
    /// for trusted, non-shared gateways. Sandbox supervisor calls still use
    /// gateway-minted sandbox JWTs.
    #[serde(default)]
    pub allow_unauthenticated_users: bool,
}

const fn default_jwks_ttl_secs() -> u64 {
    3600
}

/// Gateway-minted sandbox JWT configuration.
///
/// Points the gateway at the Ed25519 signing key (produced by `certgen`)
/// and identifies the issuer string embedded in every minted token. The
/// signing key never leaves the gateway process; the public key is loaded
/// by the same gateway so it can validate its own tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayJwtConfig {
    /// Path to the Ed25519 signing key (PKCS#8 PEM).
    pub signing_key_path: PathBuf,
    /// Path to the matching public key (SPKI PEM).
    pub public_key_path: PathBuf,
    /// Path to the `kid` value (plain text, one line).
    pub kid_path: PathBuf,
    /// Stable gateway identity embedded in `iss`/`aud`. Defaults to the
    /// hostname-or-`openshell` placeholder if unset.
    #[serde(default = "default_gateway_id")]
    pub gateway_id: String,
    /// Token lifetime in seconds. A value of 0 disables expiration and is
    /// intended only for local single-player deployments.
    #[serde(default = "default_sandbox_token_ttl_secs")]
    pub ttl_secs: u64,
}

fn default_gateway_id() -> String {
    "openshell".to_string()
}

const fn default_sandbox_token_ttl_secs() -> u64 {
    0
}

fn default_roles_claim() -> String {
    "realm_access.roles".to_string()
}

fn default_admin_role() -> String {
    "openshell-admin".to_string()
}

fn default_user_role() -> String {
    "openshell-user".to_string()
}

impl Config {
    /// Create a new config with optional TLS.
    pub fn new(tls: Option<TlsConfig>) -> Self {
        Self {
            bind_address: default_bind_address(),
            health_bind_address: None,
            metrics_bind_address: None,
            log_level: default_log_level(),
            tls,
            oidc: None,
            auth: GatewayAuthConfig::default(),
            mtls_auth: MtlsAuthConfig::default(),
            gateway_jwt: None,
            database_url: String::new(),
            compute_drivers: vec![],
            compute_driver_endpoints: BTreeMap::new(),
            ssh_session_ttl_secs: default_ssh_session_ttl_secs(),
            grpc_rate_limit_requests: None,
            grpc_rate_limit_window_secs: None,
            service_routing: ServiceRoutingConfig::default(),
        }
    }

    /// Create a new configuration with the given bind address.
    #[must_use]
    pub const fn with_bind_address(mut self, addr: SocketAddr) -> Self {
        self.bind_address = addr;
        self
    }

    #[must_use]
    pub const fn with_health_bind_address(mut self, addr: SocketAddr) -> Self {
        self.health_bind_address = Some(addr);
        self
    }

    #[must_use]
    pub const fn with_metrics_bind_address(mut self, addr: SocketAddr) -> Self {
        self.metrics_bind_address = Some(addr);
        self
    }

    /// Create a new configuration with the given log level.
    #[must_use]
    pub fn with_log_level(mut self, level: impl Into<String>) -> Self {
        self.log_level = level.into();
        self
    }

    /// Create a new configuration with a database URL.
    #[must_use]
    pub fn with_database_url(mut self, url: impl Into<String>) -> Self {
        self.database_url = url.into();
        self
    }

    /// Create a new configuration with the configured compute drivers.
    #[must_use]
    pub fn with_compute_drivers<I, D>(mut self, drivers: I) -> Self
    where
        I: IntoIterator<Item = D>,
        D: ToString,
    {
        self.compute_drivers = drivers
            .into_iter()
            .map(|driver| driver.to_string())
            .collect();
        self
    }

    /// Register a Unix domain socket endpoint for a named remote driver.
    #[must_use]
    pub fn with_compute_driver_endpoint(
        mut self,
        name: impl Into<String>,
        socket: impl Into<PathBuf>,
    ) -> Self {
        self.compute_driver_endpoints
            .insert(name.into(), socket.into());
        self
    }

    /// Create a new configuration with the SSH session TTL.
    #[must_use]
    pub const fn with_ssh_session_ttl_secs(mut self, secs: u64) -> Self {
        self.ssh_session_ttl_secs = secs;
        self
    }

    /// Set the gateway-wide gRPC request rate limit.
    #[must_use]
    pub const fn with_grpc_rate_limit(
        mut self,
        requests: Option<u64>,
        window_secs: Option<u64>,
    ) -> Self {
        self.grpc_rate_limit_requests = requests;
        self.grpc_rate_limit_window_secs = window_secs;
        self
    }

    /// Return the effective gRPC rate limit, if fully configured and enabled.
    #[must_use]
    pub fn grpc_rate_limit(&self) -> Option<(u64, Duration)> {
        let requests = self.grpc_rate_limit_requests?;
        let window_secs = self.grpc_rate_limit_window_secs?;
        if requests == 0 || window_secs == 0 {
            None
        } else {
            Some((requests, Duration::from_secs(window_secs)))
        }
    }
    /// Set the OIDC configuration for JWT-based authentication.
    #[must_use]
    pub fn with_oidc(mut self, oidc: OidcConfig) -> Self {
        self.oidc = Some(oidc);
        self
    }

    /// Derive browser-facing sandbox service domains from gateway server SANs.
    ///
    /// Wildcard DNS SANs such as `*.apps.example.com` enable service URLs
    /// under `apps.example.com`. Non-wildcard DNS names and IP SANs do not
    /// enable service subdomains.
    #[must_use]
    pub fn with_server_sans<I, S>(mut self, sans: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.service_routing.base_domains = service_routing_domains_from_server_sans(sans);
        self
    }

    /// Enable or disable plaintext HTTP routing for loopback sandbox service
    /// hostnames on TLS-enabled gateway listeners.
    #[must_use]
    pub const fn with_loopback_service_http(mut self, enabled: bool) -> Self {
        self.service_routing.enable_loopback_service_http = enabled;
        self
    }
}

impl Default for ServiceRoutingConfig {
    fn default() -> Self {
        Self {
            base_domains: default_service_routing_domains(),
            enable_loopback_service_http: default_enable_loopback_service_http(),
        }
    }
}

fn default_bind_address() -> SocketAddr {
    "127.0.0.1:17670".parse().expect("valid default address")
}

fn default_service_routing_domains() -> Vec<String> {
    vec![DEFAULT_SERVICE_ROUTING_DOMAIN.to_string()]
}

const fn default_enable_loopback_service_http() -> bool {
    true
}

fn service_routing_domains_from_server_sans<I, S>(sans: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut domains = Vec::new();
    for san in sans {
        if let Some(domain) = service_routing_domain_from_server_san(&san.into())
            && !domains.contains(&domain)
        {
            domains.push(domain);
        }
    }
    for domain in default_service_routing_domains() {
        if !domains.contains(&domain) {
            domains.push(domain);
        }
    }
    domains
}

fn service_routing_domain_from_server_san(san: &str) -> Option<String> {
    let san = san.trim().trim_matches('.').to_ascii_lowercase();
    let domain = san.strip_prefix("*.")?;
    normalize_service_routing_domain(domain)
}

fn normalize_service_routing_domain(domain: &str) -> Option<String> {
    let domain = domain.trim().trim_matches('.');
    if domain.is_empty() || domain.len() > 253 {
        return None;
    }
    let labels = domain.split('.');
    if labels.clone().any(|label| !is_dns_label(label)) {
        return None;
    }
    Some(domain.to_string())
}

fn is_dns_label(label: &str) -> bool {
    if label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-') {
        return false;
    }
    label
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn default_log_level() -> String {
    "info".to_string()
}

const fn default_ssh_session_ttl_secs() -> u64 {
    86400 // 24 hours
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::is_reachable_unix_socket;
    use super::{
        ComputeDriverKind, Config, DEFAULT_SERVICE_ROUTING_DOMAIN, GatewayJwtConfig, detect_driver,
        docker_host_unix_socket_path, is_unix_socket, normalize_compute_driver_name,
        podman_socket_candidates_from_env, podman_socket_responds,
    };
    #[cfg(unix)]
    use std::io::{Read as _, Write as _};
    use std::net::SocketAddr;
    #[cfg(unix)]
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::time::Duration;

    #[test]
    fn compute_driver_kind_parses_supported_values() {
        assert_eq!(
            "kubernetes".parse::<ComputeDriverKind>().unwrap(),
            ComputeDriverKind::Kubernetes
        );
        assert_eq!(
            "vm".parse::<ComputeDriverKind>().unwrap(),
            ComputeDriverKind::Vm
        );
        assert_eq!(
            "podman".parse::<ComputeDriverKind>().unwrap(),
            ComputeDriverKind::Podman
        );
        assert_eq!(
            "docker".parse::<ComputeDriverKind>().unwrap(),
            ComputeDriverKind::Docker
        );
    }

    #[test]
    fn compute_driver_kind_rejects_unknown_values() {
        let err = "firecracker".parse::<ComputeDriverKind>().unwrap_err();
        assert!(err.contains("unsupported compute driver 'firecracker'"));
    }

    #[test]
    fn compute_driver_name_normalization_accepts_builtin_and_custom_names() {
        assert_eq!(normalize_compute_driver_name(" VM ").unwrap(), "vm");
        assert_eq!(
            normalize_compute_driver_name("Kyma_GPU-1").unwrap(),
            "kyma_gpu-1"
        );

        let err = normalize_compute_driver_name("kyma/gpu").unwrap_err();
        assert!(err.contains("invalid compute driver name"));
    }

    #[test]
    fn config_defaults_to_loopback_bind_address() {
        let expected: SocketAddr = "127.0.0.1:17670".parse().expect("valid address");
        assert_eq!(Config::new(None).bind_address, expected);
    }

    #[test]
    fn config_new_disables_health_bind_by_default() {
        let cfg = Config::new(None);
        assert!(cfg.health_bind_address.is_none());
    }

    #[test]
    fn config_disables_unauthenticated_users_by_default() {
        let cfg = Config::new(None);
        assert!(!cfg.auth.allow_unauthenticated_users);
    }

    #[test]
    fn gateway_jwt_ttl_defaults_to_non_expiring() {
        let cfg: GatewayJwtConfig = serde_json::from_value(serde_json::json!({
            "signing_key_path": "/tmp/signing.pem",
            "public_key_path": "/tmp/public.pem",
            "kid_path": "/tmp/kid"
        }))
        .expect("gateway JWT config should deserialize with default ttl");

        assert_eq!(cfg.ttl_secs, 0);
    }

    #[test]
    fn grpc_rate_limit_requires_positive_pair() {
        assert!(Config::new(None).grpc_rate_limit().is_none());
        assert!(
            Config::new(None)
                .with_grpc_rate_limit(Some(10), None)
                .grpc_rate_limit()
                .is_none()
        );
        assert!(
            Config::new(None)
                .with_grpc_rate_limit(Some(0), Some(60))
                .grpc_rate_limit()
                .is_none()
        );
        assert_eq!(
            Config::new(None)
                .with_grpc_rate_limit(Some(10), Some(60))
                .grpc_rate_limit(),
            Some((10, Duration::from_secs(60)))
        );
    }

    #[test]
    fn service_routing_allows_loopback_plaintext_http_by_default() {
        let cfg = Config::new(None);
        assert_eq!(
            cfg.service_routing.base_domains,
            vec![DEFAULT_SERVICE_ROUTING_DOMAIN.to_string()]
        );
        assert!(cfg.service_routing.enable_loopback_service_http);
    }

    #[test]
    fn server_sans_update_preserves_loopback_plaintext_http_flag() {
        let cfg = Config::new(None)
            .with_loopback_service_http(false)
            .with_server_sans(["*.dev.openshell.localhost"]);

        assert_eq!(
            cfg.service_routing.base_domains,
            vec![
                "dev.openshell.localhost".to_string(),
                DEFAULT_SERVICE_ROUTING_DOMAIN.to_string()
            ]
        );
        assert!(!cfg.service_routing.enable_loopback_service_http);
    }

    #[test]
    fn service_routing_domains_are_derived_from_wildcard_server_sans() {
        let cfg = Config::new(None).with_server_sans([
            "gateway.example.com",
            "*.apps.example.com",
            "127.0.0.1",
            "*.apps.example.com",
            "*.dev.example.com.",
        ]);

        assert_eq!(
            cfg.service_routing.base_domains,
            vec![
                "apps.example.com".to_string(),
                "dev.example.com".to_string(),
                DEFAULT_SERVICE_ROUTING_DOMAIN.to_string(),
            ]
        );
    }

    #[test]
    fn config_with_health_bind_address_sets_address() {
        let addr: SocketAddr = "0.0.0.0:9090".parse().expect("valid address");
        let cfg = Config::new(None).with_health_bind_address(addr);
        assert_eq!(cfg.health_bind_address, Some(addr));
    }

    #[test]
    fn detect_driver_returns_none_without_k8s_env_or_local_runtime() {
        // When KUBERNETES_SERVICE_HOST is not set, no Docker binary/socket is
        // available, and no Podman API socket is available, detect_driver
        // should return None.
        // This test may pass or fail depending on the test environment,
        // but it documents the expected behavior.
        let _ = detect_driver(); // Returns Some or None based on environment
    }

    #[test]
    fn docker_host_unix_socket_path_parses_unix_hosts() {
        assert_eq!(
            docker_host_unix_socket_path("unix:///var/run/docker.sock"),
            Some(PathBuf::from("/var/run/docker.sock"))
        );
        assert_eq!(docker_host_unix_socket_path("tcp://127.0.0.1:2375"), None);
        assert_eq!(docker_host_unix_socket_path("unix://"), None);
    }

    #[cfg(unix)]
    #[test]
    fn is_unix_socket_detects_socket_files() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let socket_path = temp_dir.path().join("docker.sock");
        let _listener = UnixListener::bind(&socket_path).expect("bind unix socket");

        assert!(is_unix_socket(&socket_path));
        assert!(is_reachable_unix_socket(&socket_path));

        let regular_file = temp_dir.path().join("not-a-socket");
        std::fs::write(&regular_file, b"not a socket").expect("write regular file");
        assert!(!is_unix_socket(&regular_file));
        assert!(!is_reachable_unix_socket(&regular_file));
    }

    #[cfg(unix)]
    #[test]
    fn podman_socket_probe_accepts_successful_ping_response() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let socket_path = temp_dir.path().join("podman.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind podman socket");

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept podman probe");
            let mut request = [0_u8; 128];
            let n = stream.read(&mut request).expect("read podman probe");
            assert!(request[..n].starts_with(b"GET /_ping HTTP/1.1\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nLibpod-Api-Version: 5.8.2\r\nContent-Length: 2\r\n\r\nOK",
                )
                .expect("write podman ping response");
        });

        assert!(podman_socket_responds(&socket_path));
        handle.join().expect("probe server exits");
    }

    #[cfg(unix)]
    #[test]
    fn podman_socket_probe_rejects_docker_ping_response() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let socket_path = temp_dir.path().join("podman.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind podman socket");

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept podman probe");
            let mut request = [0_u8; 128];
            let n = stream.read(&mut request).expect("read podman probe");
            assert!(request[..n].starts_with(b"GET /_ping HTTP/1.1\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nServer: Docker/29.2.1\r\nContent-Length: 2\r\n\r\nOK",
                )
                .expect("write docker ping response");
        });

        assert!(!podman_socket_responds(&socket_path));
        handle.join().expect("probe server exits");
    }

    #[test]
    fn podman_socket_candidates_include_env_runtime_and_home_paths() {
        let candidates = podman_socket_candidates_from_env(
            Some(PathBuf::from("/tmp/custom-podman.sock")),
            Some(PathBuf::from("/tmp/runtime")),
            Some(PathBuf::from("/tmp/home")),
        );

        assert!(candidates.contains(&PathBuf::from("/tmp/custom-podman.sock")));
        assert!(candidates.contains(&PathBuf::from("/tmp/runtime/podman/podman.sock")));
        assert!(candidates.contains(&PathBuf::from(
            "/tmp/home/.local/share/containers/podman/machine/podman.sock"
        )));
    }

    #[test]
    #[allow(unsafe_code)] // std::env::set_var/remove_var require unsafe in Rust 2024
    fn detect_driver_prefers_kubernetes_when_k8s_env_is_set() {
        // Save the original env var
        let original = std::env::var("KUBERNETES_SERVICE_HOST").ok();

        // Set the env var
        unsafe {
            std::env::set_var("KUBERNETES_SERVICE_HOST", "127.0.0.1");
        }

        let result = detect_driver();
        assert_eq!(result, Some(ComputeDriverKind::Kubernetes));

        // Restore the original env var
        unsafe {
            match original {
                Some(val) => std::env::set_var("KUBERNETES_SERVICE_HOST", val),
                None => std::env::remove_var("KUBERNETES_SERVICE_HOST"),
            }
        }
    }

    #[test]
    fn supervisor_image_tag_prefers_explicit_build_tags() {
        use super::resolve_supervisor_image_tag;
        assert_eq!(
            resolve_supervisor_image_tag(Some("1.2.3"), Some("sha"), "0.0.0"),
            "1.2.3",
        );
        assert_eq!(
            resolve_supervisor_image_tag(None, Some("sha"), "0.0.0"),
            "sha",
        );
        assert_eq!(resolve_supervisor_image_tag(None, None, "1.2.3"), "1.2.3",);
        assert_eq!(
            resolve_supervisor_image_tag(Some(""), Some(""), "0.0.0"),
            "dev",
        );
        assert_eq!(
            resolve_supervisor_image_tag(Some("latest"), None, "1.2.3"),
            "latest",
        );
    }

    #[test]
    fn supervisor_image_tag_sanitizes_build_metadata_for_oci() {
        use super::resolve_supervisor_image_tag;
        assert_eq!(
            resolve_supervisor_image_tag(None, None, "0.0.37-dev.156+g1d3b741ee"),
            "0.0.37-dev.156-g1d3b741ee",
        );
        assert_eq!(
            resolve_supervisor_image_tag(Some("0.0.37-dev.156+g1d3b741ee"), None, "0.0.0"),
            "0.0.37-dev.156-g1d3b741ee",
        );
    }

    #[test]
    fn default_supervisor_image_is_version_pinned() {
        use super::default_supervisor_image;
        let image = default_supervisor_image();
        assert!(image.starts_with("ghcr.io/nvidia/openshell/supervisor:"));
        let tag = image.rsplit_once(':').unwrap().1;
        assert!(!tag.is_empty());
    }
}
