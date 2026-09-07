// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configuration management for `OpenShell` components.

use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
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

/// Default operator-facing name for a gateway installation.
pub const DEFAULT_GATEWAY_NAME: &str = "openshell";

/// Default container stop timeout in seconds (SIGTERM → SIGKILL).
pub const DEFAULT_STOP_TIMEOUT_SECS: u32 = 10;

/// Default domain used for browser-facing sandbox service URLs.
pub const DEFAULT_SERVICE_ROUTING_DOMAIN: &str = "openshell.localhost";

/// Gateway posture when a sandbox rejects a candidate policy generation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyValidationFailureMode {
    /// Deactivate the previous policy and deny new egress until a valid
    /// generation is loaded.
    #[default]
    FailClosed,
    /// Keep the last valid generation active when a newer candidate fails
    /// validation. Startup still fails closed when no valid generation exists.
    RetainLastValid,
}

impl PolicyValidationFailureMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::RetainLastValid => "retain_last_valid",
        }
    }
}

impl FromStr for PolicyValidationFailureMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "fail_closed" => Ok(Self::FailClosed),
            "retain_last_valid" => Ok(Self::RetainLastValid),
            _ => Err(format!(
                "invalid policy validation failure mode '{value}'; expected fail_closed or retain_last_valid"
            )),
        }
    }
}

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
    resolve_supervisor_image_tag(&[
        option_env!("OPENSHELL_IMAGE_TAG").unwrap_or(""),
        option_env!("IMAGE_TAG").unwrap_or(""),
        env!("CARGO_PKG_VERSION"),
    ])
}

/// Resolve the supervisor image tag from an ordered list of candidates.
///
/// Returns the first non-empty, non-`"0.0.0"` candidate, falling back to
/// `"dev"` when none qualifies. Replaces `+` with `-` for OCI tag
/// compatibility.
#[must_use]
pub fn resolve_supervisor_image_tag(candidates: &[&str]) -> String {
    candidates
        .iter()
        .copied()
        .find(|t| !t.is_empty() && *t != "0.0.0")
        .unwrap_or("dev")
        .replace('+', "-")
}

/// CDI device identifier for requesting all NVIDIA GPUs.
pub const CDI_GPU_DEVICE_ALL: &str = "nvidia.com/gpu=all";

/// Default maximum number of processes (PIDs) allowed inside a sandbox container.
///
/// Compute drivers may override this through backend configuration.
pub const DEFAULT_SANDBOX_PIDS_LIMIT: i64 = 2048;

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

/// Server configuration.
///
/// Built programmatically in [`crate::Config::new`] and the gateway CLI from
/// the parsed config file, env vars, and CLI flags. It is never deserialized
/// directly; the on-disk config schema lives in the gateway's `config_file`
/// module ([`crate::TlsConfig`] and the other nested tables carry their own
/// `Deserialize` impls for that purpose).
#[derive(Debug, Clone)]
pub struct Config {
    /// Operator-assigned name for this gateway installation.
    pub name: String,

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

    /// Security posture for rejected sandbox policy generations.
    pub policy_validation_failure_mode: PolicyValidationFailureMode,

    /// TLS configuration.  When `None`, the server listens on plaintext HTTP.
    pub tls: Option<TlsConfig>,

    /// OIDC configuration. When `Some`, the server validates Bearer JWTs.
    pub oidc: Option<OidcConfig>,

    /// Gateway user authentication behavior.
    pub auth: GatewayAuthConfig,

    /// Disabled-by-default gateway interceptor service configs.
    pub gateway_interceptors: Vec<GatewayInterceptorConfig>,

    /// Ordered provider-profile sources used to build the effective catalog.
    pub provider_profile_sources: Vec<GatewayProviderProfileSourceConfig>,

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

    /// Credential drivers enabled for provider credential storage.
    pub credential_drivers: Vec<String>,

    /// Optional credential-driver default retained for compatibility. When
    /// set, it must match the single enabled credential driver.
    pub default_credential_driver: Option<String>,

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

    /// Path to an external TLS certificate file (e.g. ACME/publicly-trusted).
    /// When set, the server uses SNI-based certificate selection: connections
    /// whose SNI hostname matches `external_server_names` receive this cert,
    /// all others receive the primary (internal) cert.
    #[serde(default)]
    pub external_cert_path: Option<PathBuf>,

    /// Path to the private key for the external TLS certificate.
    #[serde(default)]
    pub external_key_path: Option<PathBuf>,

    /// Hostnames that should be served with the external certificate.
    /// Connections whose SNI matches one of these names receive the external
    /// cert; all other connections (including those with no SNI) receive the
    /// primary (internal) cert.
    #[serde(default)]
    pub external_server_names: Vec<String>,
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

/// One configured gateway interceptor service.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GatewayInterceptorConfig {
    /// Operator-assigned instance name used in logs and config overrides.
    pub name: String,
    /// Interceptor gRPC endpoint. Supports `http://`, `https://`, and
    /// `unix://` endpoints.
    pub grpc_endpoint: String,
    /// Optional PEM trust-root bundle for an HTTPS endpoint. The gateway
    /// loads this file during interceptor initialization.
    #[serde(default)]
    pub tls_ca_cert_path: Option<PathBuf>,
    /// Exact JWT audience for this service. When omitted, a kind-scoped value
    /// is derived from the configured registration name.
    #[serde(default)]
    pub audience: Option<String>,
    /// Opt out of extension authentication for this interceptor, permitting a
    /// plaintext `http://` endpoint with no bearer credential. Development and
    /// trusted-network deployments only.
    #[serde(default)]
    pub allow_insecure_transport: bool,
    /// Deterministic service ordering. Lower values run first.
    #[serde(default)]
    pub order: i32,
    /// Default failure policy for this configured service.
    #[serde(default)]
    pub failure_policy: Option<GatewayInterceptorFailurePolicy>,
    /// RFC-style timeout string such as `500ms` or `2s`.
    #[serde(default)]
    pub timeout: Option<String>,
    /// Maximum accepted encoded `Evaluate` response size.
    #[serde(default)]
    pub max_response_bytes: Option<usize>,
    /// Maximum JSON patches accepted from one evaluation result.
    #[serde(default)]
    pub max_patches: Option<usize>,
    /// Controls whether manifest bindings are dynamic, allowlisted, or must
    /// exactly match operator configuration.
    #[serde(default)]
    pub binding_policy: GatewayInterceptorBindingPolicy,
    /// Binding configuration. Its validation and authorization semantics are
    /// selected by `binding_policy`.
    #[serde(default)]
    pub bindings: Vec<GatewayInterceptorBindingOverride>,
}

impl GatewayInterceptorConfig {
    /// Resolve the configured JWT audience to its deterministic default.
    pub fn resolved_audience(&self) -> Cow<'_, str> {
        self.audience
            .as_deref()
            .filter(|audience| !audience.is_empty())
            .map_or_else(
                || Cow::Owned(format!("urn:openshell:extension:interceptor:{}", self.name)),
                Cow::Borrowed,
            )
    }
}

/// Operator policy for authorizing interceptor manifest bindings.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayInterceptorBindingPolicy {
    /// Preserve manifest-controlled binding discovery. Configured bindings
    /// may narrow or disable manifest declarations.
    #[default]
    Dynamic,
    /// Enable only configured RPC selectors and phases. Extra manifest
    /// declarations are ignored.
    Allowlist,
    /// Require configured and manifest RPC selectors and phases to match.
    Exact,
}

/// One configured source in the gateway's effective provider-profile catalog.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum GatewayProviderProfileSourceConfig {
    /// Profiles bundled with the `OpenShell` build.
    Builtin,
    /// Profiles managed through the provider profile mutation APIs.
    User,
    /// Profiles vended by a configured gateway interceptor instance.
    Interceptor { name: String },
}

/// Failure behavior when an interceptor evaluation cannot produce a valid
/// result.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayInterceptorFailurePolicy {
    FailClosed,
    FailOpen,
}

/// Configured binding authorization or dynamic-manifest override.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GatewayInterceptorBindingOverride {
    /// Binding id from the interceptor manifest.
    #[serde(default)]
    pub id: Option<String>,
    /// Full selector form: `openshell.v1.OpenShell/CreateSandbox`.
    #[serde(default)]
    pub rpc: Option<String>,
    /// Structured selector service, e.g. `openshell.v1.OpenShell`.
    #[serde(default)]
    pub service: Option<String>,
    /// Structured selector method, e.g. `CreateSandbox`.
    #[serde(default)]
    pub method: Option<String>,
    /// Narrowed phase set.
    #[serde(default)]
    pub phases: Option<Vec<GatewayInterceptorPhaseConfig>>,
    /// Disable the selected binding.
    #[serde(default)]
    pub disabled: bool,
    /// Binding-specific failure policy override.
    #[serde(default)]
    pub failure_policy: Option<GatewayInterceptorFailurePolicy>,
}

/// Config file phase names.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum GatewayInterceptorPhaseConfig {
    ModifyOperation,
    Validate,
    PostCommit,
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
    /// Stable gateway identity embedded in `iss`/`aud`. Defaults to
    /// `openshell`.
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
            name: DEFAULT_GATEWAY_NAME.to_string(),
            bind_address: default_bind_address(),
            health_bind_address: None,
            metrics_bind_address: None,
            log_level: default_log_level(),
            policy_validation_failure_mode: PolicyValidationFailureMode::default(),
            tls,
            oidc: None,
            auth: GatewayAuthConfig::default(),
            gateway_interceptors: Vec::new(),
            provider_profile_sources: vec![
                GatewayProviderProfileSourceConfig::Builtin,
                GatewayProviderProfileSourceConfig::User,
            ],
            mtls_auth: MtlsAuthConfig::default(),
            gateway_jwt: None,
            database_url: String::new(),
            compute_drivers: vec![],
            compute_driver_endpoints: BTreeMap::new(),
            credential_drivers: Vec::new(),
            default_credential_driver: None,
            ssh_session_ttl_secs: default_ssh_session_ttl_secs(),
            grpc_rate_limit_requests: None,
            grpc_rate_limit_window_secs: None,
            service_routing: ServiceRoutingConfig::default(),
        }
    }

    /// Create a new configuration with the gateway installation name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
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

    /// Create a new configuration with the configured credential drivers.
    #[must_use]
    pub fn with_credential_drivers<I, S>(mut self, drivers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.credential_drivers = drivers.into_iter().map(Into::into).collect();
        self
    }

    /// Create a new configuration with the default credential driver.
    #[must_use]
    pub fn with_default_credential_driver(mut self, driver: Option<impl Into<String>>) -> Self {
        self.default_credential_driver = driver.map(Into::into);
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

    /// Set configured gateway interceptors.
    #[must_use]
    pub fn with_gateway_interceptors<I>(mut self, interceptors: I) -> Self
    where
        I: IntoIterator<Item = GatewayInterceptorConfig>,
    {
        self.gateway_interceptors = interceptors.into_iter().collect();
        self
    }

    /// Set the ordered provider-profile sources used by the gateway.
    #[must_use]
    pub fn with_provider_profile_sources<I>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = GatewayProviderProfileSourceConfig>,
    {
        self.provider_profile_sources = sources.into_iter().collect();
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
    use super::{
        Config, DEFAULT_SERVICE_ROUTING_DOMAIN, GatewayInterceptorBindingPolicy,
        GatewayInterceptorConfig, GatewayInterceptorFailurePolicy, GatewayJwtConfig,
        GatewayProviderProfileSourceConfig, PolicyValidationFailureMode,
        normalize_compute_driver_name,
    };
    use std::net::SocketAddr;
    use std::time::Duration;

    #[test]
    fn policy_validation_failure_mode_is_secure_by_default() {
        assert_eq!(
            Config::new(None).policy_validation_failure_mode,
            PolicyValidationFailureMode::FailClosed
        );
        assert_eq!(
            "retain_last_valid"
                .parse::<PolicyValidationFailureMode>()
                .unwrap(),
            PolicyValidationFailureMode::RetainLastValid
        );
        assert!("keep_old".parse::<PolicyValidationFailureMode>().is_err());
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
    fn config_defaults_to_builtin_and_user_provider_profile_sources() {
        let cfg = Config::new(None);
        assert_eq!(
            cfg.provider_profile_sources,
            vec![
                GatewayProviderProfileSourceConfig::Builtin,
                GatewayProviderProfileSourceConfig::User,
            ]
        );
    }

    #[test]
    fn config_defaults_to_internal_credential_storage() {
        let cfg = Config::new(None);
        assert!(cfg.credential_drivers.is_empty());
        assert!(cfg.default_credential_driver.is_none());
    }

    #[test]
    fn config_accepts_credential_driver_settings() {
        let cfg = Config::new(None)
            .with_credential_drivers(["kubernetes-secrets", "vault"])
            .with_default_credential_driver(Some("kubernetes-secrets"));

        assert_eq!(
            cfg.credential_drivers,
            vec!["kubernetes-secrets".to_string(), "vault".to_string()]
        );
        assert_eq!(
            cfg.default_credential_driver.as_deref(),
            Some("kubernetes-secrets")
        );
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
    fn name_defaults_and_can_be_overridden() {
        assert_eq!(Config::new(None).name, "openshell");
        assert_eq!(
            Config::new(None).with_name("production-us-west").name,
            "production-us-west"
        );
    }

    #[test]
    fn gateway_interceptor_failure_policy_rejects_ignore() {
        let err =
            serde_json::from_value::<GatewayInterceptorFailurePolicy>(serde_json::json!("ignore"))
                .unwrap_err();

        assert!(err.to_string().contains("unknown variant `ignore`"));
    }

    #[test]
    fn gateway_interceptor_binding_policy_defaults_and_parses_strict_modes() {
        let defaulted: GatewayInterceptorConfig = serde_json::from_value(serde_json::json!({
            "name": "governance",
            "grpc_endpoint": "unix:///tmp/governance.sock"
        }))
        .unwrap();
        let allowlist: GatewayInterceptorBindingPolicy =
            serde_json::from_value(serde_json::json!("allowlist")).unwrap();
        let exact: GatewayInterceptorBindingPolicy =
            serde_json::from_value(serde_json::json!("exact")).unwrap();

        assert_eq!(
            defaulted.binding_policy,
            GatewayInterceptorBindingPolicy::Dynamic
        );
        assert_eq!(
            defaulted.resolved_audience(),
            "urn:openshell:extension:interceptor:governance"
        );
        let explicitly_empty = GatewayInterceptorConfig {
            name: "governance".to_string(),
            audience: Some(String::new()),
            ..GatewayInterceptorConfig::default()
        };
        assert_eq!(
            explicitly_empty.resolved_audience(),
            "urn:openshell:extension:interceptor:governance"
        );
        assert_eq!(allowlist, GatewayInterceptorBindingPolicy::Allowlist);
        assert_eq!(exact, GatewayInterceptorBindingPolicy::Exact);
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
    fn supervisor_image_tag_prefers_explicit_build_tags() {
        use super::resolve_supervisor_image_tag;
        assert_eq!(
            resolve_supervisor_image_tag(&["1.2.3", "sha", "0.0.0"]),
            "1.2.3"
        );
        assert_eq!(resolve_supervisor_image_tag(&["", "sha", "0.0.0"]), "sha");
        assert_eq!(resolve_supervisor_image_tag(&["", "", "1.2.3"]), "1.2.3");
        assert_eq!(resolve_supervisor_image_tag(&["", "", "0.0.0"]), "dev");
        assert_eq!(
            resolve_supervisor_image_tag(&["latest", "", "1.2.3"]),
            "latest"
        );
    }

    #[test]
    fn supervisor_image_tag_sanitizes_build_metadata_for_oci() {
        use super::resolve_supervisor_image_tag;
        assert_eq!(
            resolve_supervisor_image_tag(&["", "", "0.0.37-dev.156+g1d3b741ee"]),
            "0.0.37-dev.156-g1d3b741ee",
        );
        assert_eq!(
            resolve_supervisor_image_tag(&["0.0.37-dev.156+g1d3b741ee", "", "0.0.0"]),
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
