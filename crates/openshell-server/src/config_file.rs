// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! TOML configuration file loader for the gateway.
//!
//! See `rfc/0003-gateway-configuration/README.md` for the file format. This
//! module parses the file into [`ConfigFile`], rejects fields that must be
//! supplied via env/CLI (database URL), and provides
//! [`driver_table`] which returns a driver-owned
//! `[openshell.drivers.<name>]` table without gateway-level inheritance.
//!
//! The merge precedence for gateway process settings is:
//! ```text
//! CLI flag  >  OPENSHELL_* env var  >  TOML file  >  built-in default
//! ```
//! Driver implementation settings are configured in the TOML driver tables.
//! Per-field application of gateway file values happens in [`crate::cli`],
//! which uses clap's `ArgMatches::value_source` to detect arguments that fell
//! back to their default and are therefore eligible for replacement by file
//! values.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Read as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use openshell_core::proto::{
    SupervisorMiddlewareBinding, SupervisorMiddlewareBindingPolicy, SupervisorMiddlewareService,
};
use openshell_core::sandbox_env::OtlpProtocol;
use openshell_core::{
    ExtensionBindingPolicy, GatewayAuthConfig, GatewayInterceptorConfig, GatewayJwtConfig,
    GatewayProviderProfileSourceConfig, MtlsAuthConfig, OidcConfig,
};
use rustls::pki_types::pem::{PemObject, SectionKind};
use serde::{Deserialize, Serialize};

/// Gateway configuration schema version supported by this build.
pub const SCHEMA_VERSION: u32 = 2;

/// Root of the gateway TOML config file.
///
/// The file is rooted at `[openshell]` to reserve room for future components
/// (CLI, sandbox, router) to share a single config file without key
/// collisions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    #[serde(default)]
    pub openshell: OpenShellRoot,
}

/// `[openshell]` table.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenShellRoot {
    /// Gateway configuration schema version. Loaded files must set this to
    /// [`SCHEMA_VERSION`].
    #[serde(default)]
    pub version: Option<u32>,

    #[serde(default)]
    pub gateway: GatewayFileSection,

    #[serde(default)]
    pub supervisor: SupervisorFileSection,

    /// `[openshell.drivers.<name>]` tables — passed to each driver crate's
    /// `Deserialize` impl after removing common gateway controls. Stored as
    /// raw [`toml::Value`] so each driver can evolve its schema independently.
    #[serde(default)]
    pub drivers: BTreeMap<String, toml::Value>,

    /// `[openshell.credential_drivers.<name>]` tables — passed verbatim to
    /// credential driver implementations after gateway-level selection.
    #[serde(default)]
    pub credential_drivers: BTreeMap<String, toml::Value>,
}

/// `[openshell.gateway]` section.
///
/// All fields are `Option<T>` so the loader can tell whether a key was set
/// in the file (`Some`) or not (`None` — value is taken from CLI/env/default).
/// Driver-specific settings belong exclusively in
/// `[openshell.drivers.<name>]` tables.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayFileSection {
    // ── Identity ─────────────────────────────────────────────────────────
    /// Operator-assigned name for this gateway installation.
    #[serde(default)]
    pub name: Option<String>,

    // ── Listeners ────────────────────────────────────────────────────────
    #[serde(default)]
    pub bind_address: Option<SocketAddr>,
    #[serde(default)]
    pub health_bind_address: Option<SocketAddr>,
    #[serde(default)]
    pub metrics_bind_address: Option<SocketAddr>,

    // ── Logging ──────────────────────────────────────────────────────────
    #[serde(default)]
    pub log_level: Option<String>,

    // ── Database ─────────────────────────────────────────────────────────
    /// Connection ceiling for the persistence pool. One shared pool serves
    /// every database-backed RPC, so this is also the gateway's ceiling on
    /// concurrent database work. On Postgres, each replica also opens up to
    /// `database_lock_max_connections` lock connections, so total server
    /// connections are `(database_max_connections +
    /// database_lock_max_connections) × replica_count`, plus rollout pods,
    /// which must stay under the server's own `max_connections`. Omit to keep
    /// the backend default (10 for Postgres, 5 for on-disk `SQLite`); an
    /// in-memory `SQLite` database is always a single connection. Postgres
    /// needs at least 2, because the SSH identity lock keeps one connection
    /// while it queries the pool.
    #[serde(default)]
    pub database_max_connections: Option<u32>,

    /// Connection ceiling for the Postgres mutation lock pool. Each mutation
    /// guard holds one lock connection, so this bounds how many guarded
    /// mutations a replica runs or waits on in Postgres at once. Omit to keep
    /// the default of 4; `SQLite` has no lock pool and ignores it.
    #[serde(default)]
    pub database_lock_max_connections: Option<u32>,

    // ── Drivers ──────────────────────────────────────────────────────────
    /// Explicit compute driver selection. `None` enables auto-detection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compute_driver: Option<String>,
    #[serde(default)]
    pub credential_drivers: Option<Vec<String>>,
    #[serde(default)]
    pub default_credential_driver: Option<String>,
    #[serde(default)]
    pub credential_storage: Option<toml::Table>,

    // ── Sandbox / SSH ────────────────────────────────────────────────────
    #[serde(default)]
    pub ssh_session_ttl_secs: Option<u64>,
    /// Absolute preparation budget for new attempts; existing deadlines persist.
    #[serde(default)]
    pub image_preparation_timeout_seconds: Option<u32>,
    /// Explicit activation only after the compatible deployment rollout ends.
    #[serde(default)]
    pub enable_sandbox_updates: Option<bool>,
    #[serde(default)]
    pub grpc_rate_limit_requests: Option<u64>,
    #[serde(default)]
    pub grpc_rate_limit_window_seconds: Option<u64>,
    /// Security posture when a sandbox rejects a candidate policy generation.
    #[serde(default)]
    pub policy_validation_failure_mode: Option<openshell_core::PolicyValidationFailureMode>,
    /// Supervisor configuration delivery; omitted uses the release default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_delivery_mode: Option<openshell_core::config::ConfigDeliveryMode>,

    // ── Service routing ──────────────────────────────────────────────────
    /// Subject Alternative Names configured on the gateway server certificate.
    /// Wildcard DNS SANs also enable sandbox service URLs under that domain.
    #[serde(default)]
    pub server_sans: Option<Vec<String>>,
    /// Enable plaintext HTTP routing for loopback sandbox service URLs.
    #[serde(default)]
    pub enable_loopback_service_http: Option<bool>,
    /// Hostname format for exposed sandbox services: `readable` (default) or
    /// `hashed` (opaque one-label hostnames discriminated by the gateway
    /// installation name).
    #[serde(default)]
    pub service_hostname_format: Option<openshell_core::config::ServiceHostnameFormat>,
    /// Enable the WebSocket tunnel for an authenticated edge proxy.
    #[serde(default)]
    pub enable_websocket_tunnel: Option<bool>,

    // ── Sandbox client TLS ───────────────────────────────────────────────
    #[serde(default)]
    pub guest_tls_ca: Option<PathBuf>,

    // ── TLS toggle ───────────────────────────────────────────────────────
    /// When `true`, the gateway listens on plaintext HTTP and ignores any
    /// `[openshell.gateway.tls]` table. Mirrors `--disable-tls`.
    #[serde(default)]
    pub disable_tls: Option<bool>,

    // ── Nested tables ────────────────────────────────────────────────────
    #[serde(default)]
    pub tls: Option<GatewayTlsFileConfig>,
    #[serde(default)]
    pub oidc: Option<OidcConfig>,
    #[serde(default)]
    pub auth: Option<GatewayAuthConfig>,
    #[serde(default)]
    pub interceptors: Vec<GatewayInterceptorConfig>,
    #[serde(default)]
    pub provider_profile_sources: Option<Vec<GatewayProviderProfileSourceConfig>>,
    #[serde(default)]
    pub mtls_auth: Option<MtlsAuthConfig>,
    #[serde(default)]
    pub gateway_jwt: Option<GatewayJwtConfig>,
    #[serde(default)]
    pub otlp: Option<OtlpConfig>,
    #[serde(default)]
    pub ocsf_log: Option<OcsfLogConfig>,
    /// Tuning of the shared supervisor pool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supervisor_pool: Option<SupervisorPoolConfig>,

    // ── Disallowed-in-file fields ────────────────────────────────────────
    //
    // Captured so we can produce a friendly "set this via env/CLI instead"
    // error rather than a generic "unknown field" message. Validated and
    // rejected in [`load`].
    #[serde(default)]
    pub database_url: Option<String>,
}

/// `[openshell.gateway.supervisor_pool]`: optional tuning of the shared
/// supervisor pool.
///
/// The shared supervisor always runs as a pool that the gateway coordinates
/// for high availability: it places each sandbox instance on a live member by
/// consistent hash, records its owner durably, and moves the instances of a
/// failed or leaving member to another member, which adopts their running
/// workloads. Without this table the defaults apply.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorPoolConfig {
    /// Seconds a sandbox runtime keeps its workload frozen after losing its
    /// supervisor before terminating it, from 30 to 300. The pool's
    /// supervisors offer it to each runtime; unset offers
    /// [`openshell_supervisor_control::POOL_RECOVERY_TIMEOUT_SECS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_timeout_secs: Option<u32>,
}

/// Gateway listener TLS fields accepted in `gateway.toml`.
///
/// Client-certificate handshake policy is derived from the presence of a
/// client CA and OIDC configuration. It is intentionally not operator-settable
/// in TOML because changing it can either weaken CA-only gateways or require a
/// second credential from OIDC clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayTlsFileConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    #[serde(default)]
    pub client_ca_path: Option<PathBuf>,
    #[serde(default)]
    pub external_cert_path: Option<PathBuf>,
    #[serde(default)]
    pub external_key_path: Option<PathBuf>,
    #[serde(default)]
    pub external_server_names: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcsfLogRotation {
    Never,
    #[default]
    Daily,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "RawOcsfLogConfig")]
pub struct OcsfLogConfig {
    pub path: PathBuf,
    /// Deprecated and ignored: `OpenShell` emits OCSF 1.8.0 only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<String>,
    pub rotation: OcsfLogRotation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_files: Option<std::num::NonZeroUsize>,
    pub queue_capacity: std::num::NonZeroUsize,
    pub queue_max_bytes: std::num::NonZeroUsize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOcsfLogConfig {
    path: PathBuf,
    schema_version: Option<String>,
    #[serde(default)]
    rotation: OcsfLogRotation,
    max_files: Option<std::num::NonZeroUsize>,
    queue_capacity: Option<std::num::NonZeroUsize>,
    queue_max_bytes: Option<std::num::NonZeroUsize>,
}

impl TryFrom<RawOcsfLogConfig> for OcsfLogConfig {
    type Error = &'static str;

    fn try_from(raw: RawOcsfLogConfig) -> Result<Self, Self::Error> {
        if raw.path.as_os_str().is_empty() {
            return Err("ocsf_log.path must not be empty");
        }
        if raw.rotation == OcsfLogRotation::Never && raw.max_files.is_some() {
            return Err("ocsf_log.max_files requires daily rotation");
        }
        Ok(Self {
            path: raw.path,
            schema_version: raw.schema_version,
            rotation: raw.rotation,
            max_files: (raw.rotation == OcsfLogRotation::Daily).then(|| {
                raw.max_files
                    .unwrap_or(std::num::NonZeroUsize::new(7).unwrap())
            }),
            queue_capacity: raw
                .queue_capacity
                .unwrap_or(std::num::NonZeroUsize::new(10_000).unwrap()),
            queue_max_bytes: raw
                .queue_max_bytes
                .unwrap_or(std::num::NonZeroUsize::new(16 * 1024 * 1024).unwrap()),
        })
    }
}
/// `[openshell.gateway.otlp]` section and its per-signal tables.
///
/// `endpoint` is the collector for every enabled signal, and on its own
/// enables trace export. `[otlp.traces]` overrides the trace endpoint,
/// `[otlp.ocsf]` with `enabled = true` exports OCSF events as log records, and
/// `[otlp.agent]` with `enabled = true` relays workload traces, each
/// optionally to a different endpoint. SDK tuning knobs are deliberately absent — see
/// [`crate::otel_tracing`] for what this table owns and what the `OTEL_*`
/// environment variables own.
///
/// Endpoints are resolved when parsing, so each enabled signal carries its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawOtlpConfig")]
pub struct OtlpConfig {
    /// `service.name` resource attribute. Defaults to `openshell-gateway`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,

    /// Trace export, when enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traces: Option<OtlpTracesConfig>,

    /// OCSF event export as OTLP log records, when enabled.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_enabled"
    )]
    pub ocsf: Option<OcsfOtlpConfig>,

    /// Relay of workload traces from sandboxes, when enabled.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_enabled"
    )]
    pub agent: Option<AgentOtlpConfig>,
}

/// Writes `enabled = true` so that a serialized config parses back to the
/// same export.
fn serialize_enabled<T: Serialize, S: serde::Serializer>(
    table: &Option<T>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Enabled<'a, T> {
        enabled: bool,
        #[serde(flatten)]
        table: &'a T,
    }
    table
        .as_ref()
        .map(|table| Enabled {
            enabled: true,
            table,
        })
        .serialize(serializer)
}

impl OtlpConfig {
    /// The collector that receives traces, when trace export is enabled.
    pub fn traces_endpoint(&self) -> Option<&str> {
        self.traces
            .as_ref()
            .map(|traces| traces.collector.endpoint.as_str())
    }

    /// The collector that receives relayed workload traces, when the agent
    /// trace relay is enabled.
    pub fn agent_endpoint(&self) -> Option<&str> {
        self.agent
            .as_ref()
            .map(|agent| agent.collector.endpoint.as_str())
    }

    /// The exports that compute drivers pass to supervisors.
    pub fn supervisor_otlp(&self) -> openshell_core::sandbox_env::SupervisorOtlp {
        openshell_core::sandbox_env::SupervisorOtlp {
            traces: self.traces.as_ref().map(|traces| traces.collector.export()),
            ocsf: self.ocsf.as_ref().map(|ocsf| ocsf.collector.export()),
            agent: self.agent.as_ref().map(|agent| agent.collector.export()),
        }
    }
}

/// One OTLP collector. A lane table with its own `endpoint` describes its
/// own collector; one without inherits the whole `[openshell.gateway.otlp]`
/// collector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtlpCollectorConfig {
    /// Collector endpoint, e.g.
    /// `http://otel-collector.observability.svc:4317`.
    pub endpoint: String,

    /// Transport to the collector. Defaults to gRPC.
    #[serde(default, skip_serializing_if = "is_grpc")]
    pub protocol: OtlpProtocol,

    /// Headers sent with every export request, such as an authorization
    /// token.
    #[serde(default, skip_serializing_if = "OtlpHeaders::is_unserialized")]
    pub headers: OtlpHeaders,

    /// File the headers are read from, one `name=value` per line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers_file: Option<PathBuf>,
}

/// Headers the exporters set themselves, or that HTTP/2 forbids.
const RESERVED_HEADERS: &[&str] = &[
    "connection",
    "content-encoding",
    "content-length",
    "content-type",
    "host",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Most bytes read from a `headers_file`.
const MAX_HEADERS_FILE_BYTES: u64 = 64 * 1024;

/// Collector request headers, validated as HTTP headers when the config is
/// parsed. Headers read from a `headers_file` are not serialized.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "BTreeMap<String, String>", into = "BTreeMap<String, String>")]
pub struct OtlpHeaders {
    headers: BTreeMap<String, String>,
    from_file: bool,
}

impl OtlpHeaders {
    /// The headers of table `table`, from its `headers` or its
    /// `headers_file`.
    fn resolve(
        table: &str,
        headers: Option<BTreeMap<String, String>>,
        file: Option<&Path>,
    ) -> Result<Self, String> {
        let Some(path) = file else {
            return Self::validated(&format!("{table}.headers"), headers.unwrap_or_default());
        };
        if headers.is_some() {
            return Err(format!("{table} sets both headers and headers_file"));
        }
        let field = format!("{table}.headers_file");
        let headers = Self::validated(&field, read_headers_file(&field, path)?)?;
        Ok(Self {
            from_file: true,
            ..headers
        })
    }

    /// Accepts headers that every exporter sends the same way: valid names,
    /// sent once each, with non-empty, visible-ASCII values.
    fn validated(field: &str, headers: BTreeMap<String, String>) -> Result<Self, String> {
        let mut seen = std::collections::BTreeSet::new();
        for (name, value) in &headers {
            let header = http::HeaderName::try_from(name.as_str())
                .map_err(|_| format!("{field}: invalid header name {name:?}"))?;
            if !seen.insert(header.as_str().to_string()) {
                return Err(format!(
                    "{field}: header {:?} is set more than once",
                    header.as_str()
                ));
            }
            if RESERVED_HEADERS.contains(&header.as_str()) || header.as_str().starts_with("grpc-") {
                return Err(format!(
                    "{field}: header {:?} is set by the exporter",
                    header.as_str()
                ));
            }
            if header.as_str().ends_with("-bin") {
                return Err(format!("{field}: binary header {name:?} is not supported"));
            }
            if value.is_empty() {
                return Err(format!("{field}: empty value for header {name:?}"));
            }
            if !value
                .bytes()
                .all(|byte| byte == b' ' || byte.is_ascii_graphic())
            {
                return Err(format!("{field}: invalid value for header {name:?}"));
            }
        }
        Ok(Self {
            headers,
            from_file: false,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// Whether serialization omits these headers: there are none, or they
    /// came from a `headers_file`.
    fn is_unserialized(&self) -> bool {
        self.from_file || self.is_empty()
    }

    pub fn header_map(&self) -> http::HeaderMap {
        self.headers
            .iter()
            .filter_map(|(name, value)| {
                Some((
                    http::HeaderName::try_from(name.as_str()).ok()?,
                    http::HeaderValue::try_from(value.as_str()).ok()?,
                ))
            })
            .collect()
    }
}

#[cfg(test)]
impl<const N: usize> From<[(&str, &str); N]> for OtlpHeaders {
    fn from(headers: [(&str, &str); N]) -> Self {
        Self::from(
            headers
                .into_iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect::<BTreeMap<_, _>>(),
        )
    }
}

impl From<BTreeMap<String, String>> for OtlpHeaders {
    fn from(headers: BTreeMap<String, String>) -> Self {
        Self {
            headers,
            from_file: false,
        }
    }
}

impl From<OtlpHeaders> for BTreeMap<String, String> {
    fn from(headers: OtlpHeaders) -> Self {
        headers.headers
    }
}

/// Reads one `name=value` header per line, skipping blank lines.
fn read_headers_file(field: &str, path: &Path) -> Result<BTreeMap<String, String>, String> {
    let mut contents = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| {
            file.take(MAX_HEADERS_FILE_BYTES + 1)
                .read_to_end(&mut contents)
        })
        .map_err(|error| format!("{field}: cannot read {}: {error}", path.display()))?;
    if contents.len() as u64 > MAX_HEADERS_FILE_BYTES {
        return Err(format!(
            "{field}: {} is larger than {MAX_HEADERS_FILE_BYTES} bytes",
            path.display()
        ));
    }
    let contents = String::from_utf8(contents)
        .map_err(|_| format!("{field}: {} is not UTF-8", path.display()))?;
    let mut headers = BTreeMap::new();
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| format!("{field}: line {} is not name=value", index + 1))?;
        let name = name.trim();
        if headers
            .insert(name.to_string(), value.trim().to_string())
            .is_some()
        {
            return Err(format!("{field}: header {name:?} is set more than once"));
        }
    }
    Ok(headers)
}

impl std::fmt::Debug for OtlpHeaders {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_map()
            .entries(self.headers.keys().map(|name| (name, "[REDACTED]")))
            .finish()
    }
}

impl OtlpCollectorConfig {
    /// Rejects an `https://` endpoint for `http/protobuf`, which has no TLS.
    fn checked(self, table: &str) -> Result<Self, String> {
        let https = self
            .endpoint
            .trim()
            .get(..8)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"));
        if https && self.protocol == OtlpProtocol::HttpProtobuf {
            return Err(format!(
                "{table} uses an https:// endpoint, which http/protobuf does not support"
            ));
        }
        Ok(self)
    }

    fn export(&self) -> openshell_core::sandbox_env::OtlpExport {
        openshell_core::sandbox_env::OtlpExport {
            endpoint: self.endpoint.clone(),
            protocol: self.protocol,
        }
    }
}

// Signature dictated by serde's `skip_serializing_if`.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_grpc(protocol: &OtlpProtocol) -> bool {
    *protocol == OtlpProtocol::Grpc
}

/// `[openshell.gateway.otlp.traces]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtlpTracesConfig {
    #[serde(flatten)]
    pub collector: OtlpCollectorConfig,
}

/// `[openshell.gateway.otlp.ocsf]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OcsfOtlpConfig {
    #[serde(flatten)]
    pub collector: OtlpCollectorConfig,

    /// Deprecated and ignored: `OpenShell` emits OCSF 1.8.0 only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<String>,
}

/// `[openshell.gateway.otlp.agent]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentOtlpConfig {
    /// The collector that sandbox supervisors forward workload traces to.
    #[serde(flatten)]
    pub collector: OtlpCollectorConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOtlpConfig {
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    protocol: Option<OtlpProtocol>,
    #[serde(default)]
    headers: Option<BTreeMap<String, String>>,
    #[serde(default)]
    headers_file: Option<PathBuf>,
    #[serde(default)]
    service_name: Option<String>,
    #[serde(default)]
    traces: Option<RawOtlpTraces>,
    #[serde(default)]
    ocsf: Option<RawOcsfOtlp>,
    #[serde(default)]
    agent: Option<RawAgentOtlp>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgentOtlp {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    protocol: Option<OtlpProtocol>,
    #[serde(default)]
    headers: Option<BTreeMap<String, String>>,
    #[serde(default)]
    headers_file: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOtlpTraces {
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    protocol: Option<OtlpProtocol>,
    #[serde(default)]
    headers: Option<BTreeMap<String, String>>,
    #[serde(default)]
    headers_file: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOcsfOtlp {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    protocol: Option<OtlpProtocol>,
    #[serde(default)]
    headers: Option<BTreeMap<String, String>>,
    #[serde(default)]
    headers_file: Option<PathBuf>,
    #[serde(default)]
    schema_version: Option<String>,
}

/// The collector keys every OTLP table accepts.
struct RawCollector {
    endpoint: Option<String>,
    protocol: Option<OtlpProtocol>,
    headers: Option<BTreeMap<String, String>>,
    headers_file: Option<PathBuf>,
}

macro_rules! raw_collector {
    ($raw:expr) => {
        RawCollector {
            endpoint: $raw.endpoint,
            protocol: $raw.protocol,
            headers: $raw.headers,
            headers_file: $raw.headers_file,
        }
    };
}

impl RawCollector {
    /// The collector for table `otlp.{table}`: its own when it sets an
    /// endpoint, otherwise the whole `shared` one.
    fn resolve(
        self,
        table: &str,
        shared: Option<&OtlpCollectorConfig>,
    ) -> Result<OtlpCollectorConfig, String> {
        let Some(endpoint) = self.endpoint else {
            let set = [
                ("protocol", self.protocol.is_some()),
                ("headers", self.headers.is_some()),
                ("headers_file", self.headers_file.is_some()),
            ]
            .into_iter()
            .find_map(|(key, set)| set.then_some(key));
            if let Some(key) = set {
                return Err(format!(
                    "{table} sets {key} without its own endpoint; a table without an \
                     endpoint inherits the whole otlp collector"
                ));
            }
            return shared.cloned().ok_or_else(|| {
                format!("{table} needs an endpoint, or otlp.endpoint to default to")
            });
        };
        OtlpCollectorConfig {
            endpoint,
            protocol: self.protocol.unwrap_or_default(),
            headers: OtlpHeaders::resolve(table, self.headers, self.headers_file.as_deref())?,
            headers_file: self.headers_file,
        }
        .checked(table)
    }
}

impl TryFrom<RawOtlpConfig> for OtlpConfig {
    type Error = String;

    fn try_from(raw: RawOtlpConfig) -> Result<Self, Self::Error> {
        if raw.endpoint.is_none() {
            let set = [
                ("protocol", raw.protocol.is_some()),
                ("headers", raw.headers.is_some()),
                ("headers_file", raw.headers_file.is_some()),
            ]
            .into_iter()
            .find_map(|(key, set)| set.then_some(key));
            if let Some(key) = set {
                return Err(format!(
                    "otlp sets {key} without its own endpoint; a table with its own \
                     endpoint takes nothing from otlp"
                ));
            }
        }
        let shared = raw.endpoint.is_some().then(|| {
            RawCollector {
                endpoint: raw.endpoint,
                protocol: raw.protocol,
                headers: raw.headers,
                headers_file: raw.headers_file,
            }
            .resolve("otlp", None)
        });
        let shared = shared.transpose()?;
        let traces = match raw.traces {
            Some(traces) => Some(raw_collector!(traces).resolve("otlp.traces", shared.as_ref())?),
            None => shared.clone(),
        }
        .map(|collector| OtlpTracesConfig { collector });
        let ocsf = raw
            .ocsf
            .filter(|ocsf| ocsf.enabled)
            .map(|ocsf| {
                Ok::<_, String>(OcsfOtlpConfig {
                    schema_version: ocsf.schema_version,
                    collector: raw_collector!(ocsf).resolve("otlp.ocsf", shared.as_ref())?,
                })
            })
            .transpose()?;
        let agent = raw
            .agent
            .filter(|agent| agent.enabled)
            .map(|agent| {
                Ok::<_, String>(AgentOtlpConfig {
                    collector: raw_collector!(agent).resolve("otlp.agent", shared.as_ref())?,
                })
            })
            .transpose()?;
        if traces.is_none() && ocsf.is_none() && agent.is_none() {
            return Err(
                "otlp needs an endpoint, or otlp.ocsf or otlp.agent with enabled = true"
                    .to_string(),
            );
        }
        Ok(Self {
            service_name: raw.service_name,
            traces,
            ocsf,
            agent,
        })
    }
}

/// `[openshell.supervisor]` section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorFileSection {
    /// Operator-owned external isolation routes, reachable by supervisors.
    #[serde(default)]
    pub isolation_backends: Vec<openshell_core::isolation_registration::BackendRegistration>,
    /// Statically registered supervisor middleware services. Registration is
    /// operator-owned and changes require a gateway restart.
    #[serde(default)]
    pub middleware: Vec<MiddlewareServiceFileConfig>,
    /// Shared network-supervisor configuration. This is intentionally outside
    /// the compute-driver tables so every supported driver consumes the same
    /// startup contract.
    #[serde(default)]
    pub network: SupervisorNetworkFileSection,
}

/// `[openshell.supervisor.network]` configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorNetworkFileSection {
    /// Gateway-local pre-assembled PEM bundle whose certificates augment the
    /// supervisor's destination trust roots. The gateway validates and stages
    /// this single file during startup before any compute driver is constructed.
    #[serde(default)]
    pub additional_ca_bundle: Option<PathBuf>,
}

impl ConfigFile {
    /// Deprecated `schema_version` fields that are set; they are ignored.
    pub fn deprecated_ocsf_schema_versions(&self) -> Vec<&'static str> {
        let gateway = &self.openshell.gateway;
        let mut set = Vec::new();
        if gateway
            .ocsf_log
            .as_ref()
            .is_some_and(|ocsf| ocsf.schema_version.is_some())
        {
            set.push("openshell.gateway.ocsf_log.schema_version");
        }
        if gateway
            .otlp
            .as_ref()
            .and_then(|otlp| otlp.ocsf.as_ref())
            .is_some_and(|ocsf| ocsf.schema_version.is_some())
        {
            set.push("openshell.gateway.otlp.ocsf.schema_version");
        }
        set
    }

    /// Resolve the selected driver's exact backend name without sandbox input.
    pub(crate) fn isolation_backend(
        &self,
        driver_name: &str,
    ) -> Result<Option<&openshell_core::isolation_registration::BackendRegistration>, &'static str>
    {
        use openshell_core::isolation_registration::{
            BUILTIN_BACKEND_NAME, validate_backend_name, validate_registrations,
        };
        let registrations = &self.openshell.supervisor.isolation_backends;
        validate_registrations(registrations)?;
        let Some(value) = self
            .openshell
            .drivers
            .get(driver_name)
            .and_then(|driver| driver.get("isolation_backend"))
        else {
            return Ok(None);
        };
        let name = value
            .as_str()
            .ok_or("driver isolation_backend must be a string")?;
        if name == BUILTIN_BACKEND_NAME {
            return Ok(None);
        }
        validate_backend_name(name)?;
        registrations
            .iter()
            .find(|registration| registration.name == name)
            .map(Some)
            .ok_or("selected isolation backend is not registered")
    }
}

/// One `[[openshell.supervisor.middleware]]` supervisor middleware registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MiddlewareServiceFileConfig {
    /// Operator-facing name used for diagnostics.
    pub name: String,
    /// HTTP or HTTPS gRPC endpoint reachable by the gateway and supervisors.
    pub grpc_endpoint: String,
    /// Optional PEM trust-root bundle for an HTTPS endpoint.
    #[serde(default)]
    pub tls_ca_cert_path: Option<PathBuf>,
    /// Exact JWT audience for this service. Defaults to a kind-scoped value
    /// derived from the registration name.
    #[serde(default)]
    pub audience: Option<String>,
    /// Opt out of extension authentication for this registration, permitting a
    /// plaintext `http://` endpoint with no bearer credential. Development and
    /// trusted-network deployments only.
    #[serde(default)]
    pub allow_insecure_transport: bool,
    /// Operator-owned logical payload limit for every binding exposed by this
    /// service, including HTTP bodies and complete WebSocket messages.
    #[serde(alias = "max_body_bytes")]
    pub max_payload_bytes: u64,
    /// Default RPC timeout using an integer with an `ms` or `s` suffix.
    #[serde(default)]
    pub timeout: Option<String>,
    /// Which advertised operation/phase pairs the operator authorizes.
    #[serde(default)]
    pub binding_policy: ExtensionBindingPolicy,
    /// Required operation/phase pairs for an allowlist or exact policy.
    #[serde(default)]
    pub bindings: Vec<SupervisorMiddlewareBinding>,
}

impl TryFrom<&MiddlewareServiceFileConfig> for SupervisorMiddlewareService {
    type Error = ConfigFileError;

    fn try_from(config: &MiddlewareServiceFileConfig) -> Result<Self, Self::Error> {
        let tls_ca_cert_pem = match &config.tls_ca_cert_path {
            Some(path) => {
                let pem =
                    std::fs::read(path).map_err(|source| ConfigFileError::MiddlewareTlsCaRead {
                        name: config.name.clone(),
                        path: path.clone(),
                        source,
                    })?;
                sanitize_ca_cert_pem(&config.name, path, &pem)?
            }
            None => Vec::new(),
        };

        let binding_policy = match config.binding_policy {
            // Preserve the wire config and revision of registrations using the default.
            ExtensionBindingPolicy::Dynamic => SupervisorMiddlewareBindingPolicy::Unspecified,
            ExtensionBindingPolicy::Allowlist => SupervisorMiddlewareBindingPolicy::Allowlist,
            ExtensionBindingPolicy::Exact => SupervisorMiddlewareBindingPolicy::Exact,
        };
        // Binding order has no meaning and must not change the configuration revision.
        // Keep duplicates so registration validation can report them.
        let mut bindings: Vec<_> = config
            .bindings
            .iter()
            .map(|binding| *binding as i32)
            .collect();
        bindings.sort_unstable();
        Ok(Self {
            name: config.name.clone(),
            grpc_endpoint: config.grpc_endpoint.clone(),
            binding_policy: binding_policy.into(),
            bindings,
            max_payload_bytes: config.max_payload_bytes,
            request_timeout: config
                .timeout
                .as_deref()
                .map(openshell_core::middleware::parse_middleware_timeout)
                .transpose()
                .map_err(|_| ConfigFileError::InvalidValue {
                    field: "openshell.supervisor_middleware.services.timeout",
                    message: "must be a duration between 10ms and 30s",
                })?
                .map(openshell_core::time::duration_from_std)
                .transpose()
                .map_err(|_| ConfigFileError::InvalidValue {
                    field: "openshell.supervisor_middleware.services.timeout",
                    message: "duration is outside the protobuf range",
                })?,
            tls_ca_cert_pem,
            audience: config
                .audience
                .as_deref()
                .filter(|audience| !audience.is_empty())
                .map_or_else(
                    || format!("urn:openshell:extension:middleware:{}", config.name),
                    ToString::to_string,
                ),
            allow_insecure_transport: config.allow_insecure_transport,
        })
    }
}

fn sanitize_ca_cert_pem(name: &str, path: &Path, pem: &[u8]) -> Result<Vec<u8>, ConfigFileError> {
    let mut sanitized = Vec::new();
    let mut certificate_count = 0;
    for item in <(SectionKind, Vec<u8>)>::pem_slice_iter(pem) {
        let item = item.map_err(|source| ConfigFileError::MiddlewareTlsCaInvalid {
            name: name.to_string(),
            path: path.to_path_buf(),
            message: source.to_string(),
        })?;
        let (SectionKind::Certificate, certificate) = item else {
            return Err(ConfigFileError::MiddlewareTlsCaInvalid {
                name: name.to_string(),
                path: path.to_path_buf(),
                message: "PEM bundle contains a non-certificate block".to_string(),
            });
        };
        certificate_count += 1;
        sanitized.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
        let encoded = base64::engine::general_purpose::STANDARD.encode(&certificate);
        for line in encoded.as_bytes().chunks(64) {
            sanitized.extend_from_slice(line);
            sanitized.push(b'\n');
        }
        sanitized.extend_from_slice(b"-----END CERTIFICATE-----\n");
    }
    if certificate_count == 0 {
        return Err(ConfigFileError::MiddlewareTlsCaInvalid {
            name: name.to_string(),
            path: path.to_path_buf(),
            message: "PEM bundle does not contain a certificate".to_string(),
        });
    }
    Ok(sanitized)
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigFileError {
    #[error("failed to read gateway config file '{}': {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("gateway config path '{}' is not a regular file ({kind})", path.display())]
    NonRegular { path: PathBuf, kind: &'static str },
    /// Names the location and the parser's message but never quotes the
    /// file, which can hold credentials such as collector headers.
    #[error("failed to parse gateway config file '{}': {detail}", path.display())]
    Parse { path: PathBuf, detail: String },
    #[error(
        "gateway config schema version is required; add `[openshell]` and `version = {SCHEMA_VERSION}`"
    )]
    MissingVersion,
    #[error(
        "unsupported gateway config version {version}; this build requires version {SCHEMA_VERSION}; migrate legacy fields to the version {SCHEMA_VERSION} schema"
    )]
    UnsupportedVersion { version: u32 },
    #[error(
        "`{field}` is not allowed in the gateway config file — set the {env} env var or pass {cli} on the command line"
    )]
    SecretInFile {
        field: &'static str,
        env: &'static str,
        cli: &'static str,
    },
    #[error("invalid gateway config field `{field}`: {message}")]
    InvalidValue {
        field: &'static str,
        message: &'static str,
    },
    #[error("invalid gateway config field `openshell.drivers.{name}`: expected a TOML table")]
    InvalidDriverTable { name: String },
    #[error("invalid gateway config field `openshell.drivers.{name}.isolation_backend`: {message}")]
    InvalidIsolationBackend { name: String, message: &'static str },
    #[error(
        "failed to read TLS CA certificate for supervisor middleware '{name}' from '{}': {source}",
        path.display()
    )]
    MiddlewareTlsCaRead {
        name: String,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "invalid TLS CA certificate for supervisor middleware '{name}' at '{}': {message}",
        path.display()
    )]
    MiddlewareTlsCaInvalid {
        name: String,
        path: PathBuf,
        message: String,
    },
}

const CONFIG_MIGRATION_URL: &str = "https://docs.nvidia.com/openshell/latest/how-it-works/gateways/configuration#migrate-to-schema-version-2";

/// Stable package-preflight failure with no configuration contents attached.
#[derive(Debug, thiserror::Error)]
#[error(
    "gateway config preflight failed: path='{}' category={} detected_version={}; the file was preserved unchanged; migrate it before restarting the gateway: {CONFIG_MIGRATION_URL}",
    path.display(),
    category,
    detected_version
)]
pub struct ConfigPreflightError {
    path: PathBuf,
    category: &'static str,
    detected_version: String,
}

impl ConfigPreflightError {
    pub(crate) fn invalid_current(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            category: "malformed",
            detected_version: SCHEMA_VERSION.to_string(),
        }
    }

    #[cfg(test)]
    fn category(&self) -> &'static str {
        self.category
    }

    #[cfg(test)]
    fn detected_version(&self) -> &str {
        &self.detected_version
    }
}

fn non_regular_kind(metadata: &std::fs::Metadata) -> &'static str {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        "symlink"
    } else if file_type.is_dir() {
        "directory"
    } else {
        "non-regular"
    }
}

fn read_config_contents(path: &Path) -> Result<String, ConfigFileError> {
    let path_buf = path.to_path_buf();
    let metadata = std::fs::symlink_metadata(path).map_err(|source| ConfigFileError::Io {
        path: path_buf.clone(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(ConfigFileError::NonRegular {
            path: path_buf,
            kind: non_regular_kind(&metadata),
        });
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options.open(path).map_err(|source| ConfigFileError::Io {
        path: path_buf.clone(),
        source,
    })?;
    let opened_metadata = file.metadata().map_err(|source| ConfigFileError::Io {
        path: path_buf.clone(),
        source,
    })?;
    if !opened_metadata.file_type().is_file() {
        return Err(ConfigFileError::NonRegular {
            path: path_buf,
            kind: non_regular_kind(&opened_metadata),
        });
    }

    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|source| ConfigFileError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(contents)
}

/// `error`'s message, prefixed with its line and column in `contents`.
fn parse_error_detail(contents: &str, error: &toml::de::Error) -> String {
    let message = error.message().trim_end();
    let Some(span) = error.span() else {
        return message.to_string();
    };
    let before = &contents[..span.start.min(contents.len())];
    let line = before.matches('\n').count() + 1;
    let column = before.len() - before.rfind('\n').map_or(0, |newline| newline + 1) + 1;
    format!("line {line}, column {column}: {message}")
}

fn parse_and_validate(path: &Path, contents: &str) -> Result<ConfigFile, ConfigFileError> {
    if contents.trim().is_empty() {
        return Err(ConfigFileError::MissingVersion);
    }
    let file: ConfigFile = toml::from_str(contents).map_err(|error| ConfigFileError::Parse {
        path: path.to_path_buf(),
        detail: parse_error_detail(contents, &error),
    })?;

    match file.openshell.version {
        Some(SCHEMA_VERSION) => {}
        Some(version) => return Err(ConfigFileError::UnsupportedVersion { version }),
        None => return Err(ConfigFileError::MissingVersion),
    }

    if file.openshell.gateway.database_url.is_some() {
        return Err(ConfigFileError::SecretInFile {
            field: "database_url",
            env: "OPENSHELL_DB_URL",
            cli: "--db-url",
        });
    }
    // A zero-sized pool would deadlock every `acquire` rather than degrade,
    // so reject it at load instead of starting a gateway that cannot serve.
    if file.openshell.gateway.database_max_connections == Some(0) {
        return Err(ConfigFileError::InvalidValue {
            field: "openshell.gateway.database_max_connections",
            message: "must be greater than zero; omit the key to use the built-in default",
        });
    }
    // A zero-sized lock pool would time out every guarded mutation.
    if file.openshell.gateway.database_lock_max_connections == Some(0) {
        return Err(ConfigFileError::InvalidValue {
            field: "openshell.gateway.database_lock_max_connections",
            message: "must be greater than zero; omit the key to use the built-in default",
        });
    }
    if file
        .openshell
        .gateway
        .credential_drivers
        .as_ref()
        .is_some_and(Vec::is_empty)
    {
        return Err(ConfigFileError::InvalidValue {
            field: "openshell.gateway.credential_drivers",
            message: "omit the field to use default encrypted gateway credential storage, or specify exactly one external credential driver",
        });
    }
    if file
        .openshell
        .gateway
        .supervisor_pool
        .and_then(|pool| pool.recovery_timeout_secs)
        .is_some_and(|timeout| {
            !openshell_supervisor_control::POOL_RECOVERY_TIMEOUT_RANGE.contains(&timeout)
        })
    {
        return Err(ConfigFileError::InvalidValue {
            field: "openshell.gateway.supervisor_pool.recovery_timeout_secs",
            message: "must be between 30 and 300 seconds",
        });
    }
    if let Some((name, _)) = file
        .openshell
        .drivers
        .iter()
        .find(|(_, value)| !value.is_table())
    {
        return Err(ConfigFileError::InvalidDriverTable { name: name.clone() });
    }
    if file
        .openshell
        .supervisor
        .network
        .additional_ca_bundle
        .as_ref()
        .is_some_and(|path| path.as_os_str().is_empty())
    {
        return Err(ConfigFileError::InvalidValue {
            field: "openshell.supervisor.network.additional_ca_bundle",
            message: "path must not be empty",
        });
    }

    openshell_core::isolation_registration::validate_registrations(
        &file.openshell.supervisor.isolation_backends,
    )
    .map_err(|message| ConfigFileError::InvalidValue {
        field: "openshell.supervisor.isolation_backends",
        message,
    })?;
    for driver_name in file.openshell.drivers.keys() {
        file.isolation_backend(driver_name).map_err(|message| {
            ConfigFileError::InvalidIsolationBackend {
                name: driver_name.clone(),
                message,
            }
        })?;
    }
    Ok(file)
}

fn detected_version(contents: &str) -> String {
    let Ok(value) = contents.parse::<toml::Value>() else {
        return "unavailable".to_string();
    };
    let Some(openshell) = value.get("openshell") else {
        return "missing".to_string();
    };
    let Some(openshell) = openshell.as_table() else {
        return "unavailable".to_string();
    };
    openshell.get("version").map_or_else(
        || "missing".to_string(),
        |version| {
            version
                .as_integer()
                .map_or_else(|| "unavailable".to_string(), |version| version.to_string())
        },
    )
}

fn preflight_error(
    path: &Path,
    detected_version: String,
    source: ConfigFileError,
) -> ConfigPreflightError {
    let category = match &source {
        ConfigFileError::NonRegular { .. } => "non_regular_path",
        ConfigFileError::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound => {
            "missing_path"
        }
        ConfigFileError::Io { source, .. } if source.kind() == std::io::ErrorKind::InvalidData => {
            "malformed"
        }
        ConfigFileError::Io { .. } => "unreadable_path",
        ConfigFileError::MissingVersion => "missing_version",
        ConfigFileError::UnsupportedVersion { version: 1 } => "legacy_schema_v1",
        ConfigFileError::UnsupportedVersion { version } if *version > SCHEMA_VERSION => {
            "future_version"
        }
        ConfigFileError::UnsupportedVersion { .. } => "unsupported_version",
        ConfigFileError::Parse { .. }
        | ConfigFileError::SecretInFile { .. }
        | ConfigFileError::InvalidValue { .. }
        | ConfigFileError::InvalidDriverTable { .. }
        | ConfigFileError::InvalidIsolationBackend { .. }
        | ConfigFileError::MiddlewareTlsCaRead { .. }
        | ConfigFileError::MiddlewareTlsCaInvalid { .. } => "malformed",
    };
    ConfigPreflightError {
        path: path.to_path_buf(),
        category,
        detected_version,
    }
}

/// Validate a gateway configuration without starting the gateway or writing state.
#[cfg_attr(target_os = "windows", allow(clippy::result_large_err))]
pub fn preflight(path: &Path) -> Result<ConfigFile, ConfigPreflightError> {
    let contents = read_config_contents(path)
        .map_err(|source| preflight_error(path, "unavailable".to_string(), source))?;
    let version = detected_version(&contents);
    if version == "missing" {
        return Err(preflight_error(
            path,
            version,
            ConfigFileError::MissingVersion,
        ));
    }
    if let Ok(version_number) = version.parse::<u32>()
        && version_number != SCHEMA_VERSION
    {
        return Err(preflight_error(
            path,
            version,
            ConfigFileError::UnsupportedVersion {
                version: version_number,
            },
        ));
    }
    parse_and_validate(path, &contents).map_err(|source| preflight_error(path, version, source))
}

/// Load and validate a TOML config file.
///
/// Configuration files must declare exactly [`SCHEMA_VERSION`]. Running
/// without a config file still uses CLI, environment, and built-in defaults.
#[cfg_attr(target_os = "windows", allow(clippy::result_large_err))]
pub fn load(path: &Path) -> Result<ConfigFile, ConfigFileError> {
    let contents = read_config_contents(path)?;
    parse_and_validate(path, &contents)
}

/// Return a driver's table without gateway-level inheritance.
///
/// Driver-specific configuration belongs exclusively to
/// `[openshell.drivers.<name>]` in schema version 2. The gateway resolves and
/// removes the common `isolation_backend` selector before driver decoding.
pub fn driver_table(
    _driver_name: &str,
    _gateway: &GatewayFileSection,
    raw: Option<&toml::Value>,
) -> toml::Value {
    match raw {
        Some(toml::Value::Table(table)) => {
            let mut table = table.clone();
            // Resolved by the gateway, not part of the driver's own schema.
            table.remove("isolation_backend");
            toml::Value::Table(table)
        }
        _ => toml::Value::Table(toml::Table::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn isolation_backend_selection_follows_the_driver_and_matches_exactly() {
        let tmp = write_tmp(
            r#"
[openshell.gateway]
compute_driver = "external"
[openshell.drivers.external]
isolation_backend = "agent-substrate"
[openshell.drivers.alternative]
isolation_backend = "other-backend"
[openshell.drivers.builtin]
isolation_backend = "openshell-sandbox"
[[openshell.supervisor.isolation_backends]]
name = "agent-substrate"
endpoint = { kind = "tcp", authority = "backend.example:443", addresses = ["127.0.0.1:47000"] }
[[openshell.supervisor.isolation_backends]]
name = "other-backend"
endpoint = { kind = "unix", socket_path = "/run/other.sock" }
"#,
        );
        let file = load(tmp.path()).unwrap();
        for (driver, backend) in [
            ("external", "agent-substrate"),
            ("alternative", "other-backend"),
        ] {
            assert_eq!(
                file.isolation_backend(driver).unwrap().unwrap().name,
                backend
            );
        }
        for driver in ["builtin", "absent"] {
            assert!(file.isolation_backend(driver).unwrap().is_none());
        }
        let mut file = file;
        file.openshell.drivers.get_mut("external").unwrap()["isolation_backend"] =
            toml::Value::String("Agent-substrate".into());
        assert!(file.isolation_backend("external").is_err());
    }

    #[test]
    fn isolation_backend_invalid_registration_fails_load_and_preflight() {
        for contents in [
            "[openshell.gateway]\nisolation_backend = 'agent-substrate'",
            "[openshell.drivers.external]\nisolation_backend = 'missing'",
            "[openshell.drivers.unused]\nisolation_backend = ''",
            "[openshell.drivers.external]\nisolation_backend = 42",
            "[[openshell.supervisor.isolation_backends]]\nname = 'openshell-sandbox'\nendpoint = { kind = 'unix', socket_path = '/run/backend.sock' }",
            "[[openshell.supervisor.isolation_backends]]\nname = 'unused'\nendpoint = { kind = 'unix', socket_path = 'relative.sock' }",
            "[[openshell.supervisor.isolation_backends]]\nname = 'duplicate'\nendpoint = { kind = 'unix', socket_path = '/run/a.sock' }\n[[openshell.supervisor.isolation_backends]]\nname = 'duplicate'\nendpoint = { kind = 'unix', socket_path = '/run/b.sock' }",
        ] {
            let tmp = write_tmp(contents);
            assert!(load(tmp.path()).is_err(), "{contents}");
            assert!(preflight(tmp.path()).is_err(), "{contents}");
        }
    }

    fn write_raw_tmp(contents: &str) -> tempfile::NamedTempFile {
        let mut tmp = tempfile::Builder::new()
            .suffix(".toml")
            .tempfile()
            .expect("tempfile");
        tmp.write_all(contents.as_bytes()).expect("write");
        tmp
    }

    fn write_tmp(contents: &str) -> tempfile::NamedTempFile {
        if contents.contains("[openshell]") {
            write_raw_tmp(contents)
        } else {
            write_raw_tmp(&format!("[openshell]\nversion = 2\n\n{contents}"))
        }
    }

    #[test]
    fn empty_file_requires_schema_version() {
        let tmp = write_raw_tmp("");
        assert!(matches!(
            load(tmp.path()),
            Err(ConfigFileError::MissingVersion)
        ));
    }

    #[test]
    fn compute_driver_entries_must_be_tables() {
        for value in ["\"not-a-table\"", "[\"also\", \"not-a-table\"]", "42"] {
            let tmp = write_raw_tmp(&format!(
                "[openshell]\nversion = 2\n\n[openshell.drivers]\ndocker = {value}\n"
            ));
            assert!(matches!(
                load(tmp.path()),
                Err(ConfigFileError::InvalidDriverTable { ref name }) if name == "docker"
            ));
        }
    }

    #[test]
    fn gateway_rate_limits_reject_negative_values_during_toml_parsing() {
        for field in ["grpc_rate_limit_requests", "grpc_rate_limit_window_seconds"] {
            let tmp = write_tmp(&format!("[openshell.gateway]\n{field} = -1\n"));
            assert!(
                matches!(load(tmp.path()), Err(ConfigFileError::Parse { .. })),
                "{field} must reject negative values because gateway rate limits are unsigned"
            );
        }
    }

    #[test]
    fn canonical_compute_driver_is_singular() {
        let file: ConfigFile = toml::from_str(
            r#"
[openshell.gateway]
compute_driver = "docker"
"#,
        )
        .expect("canonical compute driver parses");

        assert_eq!(
            file.openshell.gateway.compute_driver.as_deref(),
            Some("docker")
        );
    }

    #[test]
    fn legacy_compute_drivers_list_is_rejected() {
        let error =
            toml::from_str::<ConfigFile>("[openshell.gateway]\ncompute_drivers = [\"docker\"]\n")
                .expect_err("legacy compute_drivers must be rejected");
        assert!(error.to_string().contains("compute_drivers"));
    }

    #[test]
    fn compute_driver_rejects_non_string_values() {
        let error = toml::from_str::<ConfigFile>(
            r"
[openshell.gateway]
compute_driver = 42
",
        )
        .expect_err("compute driver must be a string");
        assert!(error.to_string().contains("invalid type"));
    }

    #[test]
    fn compute_driver_serialization_uses_scalar_name() {
        let file = ConfigFile {
            openshell: OpenShellRoot {
                gateway: GatewayFileSection {
                    compute_driver: Some("docker".to_string()),
                    ..Default::default()
                },
                ..Default::default()
            },
        };

        let serialized = toml::to_string(&file).expect("config serializes");
        assert!(serialized.contains("compute_driver = \"docker\""));
    }

    #[test]
    fn service_hostname_format_parses_and_serializes() {
        let file = toml::from_str::<ConfigFile>(
            r#"
[openshell]
version = 2

[openshell.gateway]
service_hostname_format = "hashed"
"#,
        )
        .expect("service hostname format parses");

        assert_eq!(
            file.openshell.gateway.service_hostname_format,
            Some(openshell_core::config::ServiceHostnameFormat::Hashed)
        );

        let serialized = toml::to_string(&file).expect("config serializes");
        assert!(serialized.contains("service_hostname_format = \"hashed\""));

        let unset = toml::from_str::<ConfigFile>("[openshell]\nversion = 2\n")
            .expect("file without the field parses");
        assert!(unset.openshell.gateway.service_hostname_format.is_none());
    }

    #[test]
    fn parses_full_example() {
        let toml = r#"
[openshell]
version = 2

[openshell.gateway]
bind_address = "0.0.0.0:8080"
health_bind_address = "0.0.0.0:8081"
log_level = "info"
compute_driver = "kubernetes"
credential_drivers = ["kubernetes-secrets"]
grpc_rate_limit_requests = 120
grpc_rate_limit_window_seconds = 60
policy_validation_failure_mode = "retain_last_valid"

[openshell.gateway.tls]
cert_path = "/etc/openshell/certs/gateway.pem"
key_path = "/etc/openshell/certs/gateway-key.pem"
client_ca_path = "/etc/openshell/certs/client-ca.pem"

[openshell.gateway.oidc]
issuer = "https://idp.example.com/realms/openshell"
audience = "openshell-cli"
jwks_allowed_origins = ["https://keys.example.com"]
dangerously_allow_insecure_http = false

[openshell.drivers.kubernetes]
namespace = "agents"
default_image = "ghcr.io/nvidia/openshell/sandbox:latest"
supervisor_image = "ghcr.io/nvidia/openshell/supervisor:latest"
client_tls_secret_name = "openshell-sandbox-tls"
service_account_name = "openshell-sandbox"
grpc_endpoint = "https://openshell-gateway.agents.svc:8080"

[openshell.credential_drivers.kubernetes-secrets]
namespace = "agents"
"#;
        let tmp = write_tmp(toml);
        let file = load(tmp.path()).expect("valid file parses");
        let gw = &file.openshell.gateway;
        assert_eq!(gw.log_level.as_deref(), Some("info"));
        assert_eq!(gw.grpc_rate_limit_requests, Some(120));
        assert_eq!(gw.grpc_rate_limit_window_seconds, Some(60));
        assert_eq!(
            gw.policy_validation_failure_mode,
            Some(openshell_core::PolicyValidationFailureMode::RetainLastValid)
        );
        assert!(gw.tls.is_some());
        let oidc = gw.oidc.as_ref().expect("OIDC config parses");
        assert!(!oidc.dangerously_allow_insecure_http);
        assert_eq!(
            oidc.jwks_allowed_origins,
            ["https://keys.example.com".to_string()]
        );
        assert_eq!(
            gw.credential_drivers.as_deref(),
            Some(&["kubernetes-secrets".to_string()][..])
        );
        assert!(gw.default_credential_driver.is_none());
        let kubernetes = file
            .openshell
            .drivers
            .get("kubernetes")
            .and_then(toml::Value::as_table)
            .expect("kubernetes driver table");
        assert_eq!(
            kubernetes
                .get("default_image")
                .and_then(toml::Value::as_str),
            Some("ghcr.io/nvidia/openshell/sandbox:latest")
        );
        assert!(
            file.openshell
                .credential_drivers
                .contains_key("kubernetes-secrets")
        );
    }

    #[test]
    fn rejects_explicit_empty_credential_drivers() {
        let tmp = write_tmp(
            r"
[openshell.gateway]
credential_drivers = []
",
        );

        let err = load(tmp.path()).unwrap_err();

        assert!(err.to_string().contains("credential_drivers"));
        assert!(err.to_string().contains("omit the field"));
    }

    #[test]
    fn parses_gateway_otlp_config() {
        let toml = r#"
[openshell.gateway.otlp]
endpoint = "http://otel-collector.observability.svc:4317"
service_name = "openshell-gateway-dev"
"#;
        let tmp = write_tmp(toml);
        let file = load(tmp.path()).expect("valid otlp config parses");
        let otlp = file.openshell.gateway.otlp.expect("otlp config");
        assert_eq!(
            otlp.traces_endpoint(),
            Some("http://otel-collector.observability.svc:4317")
        );
        assert_eq!(otlp.service_name.as_deref(), Some("openshell-gateway-dev"));
    }

    #[test]
    fn gateway_accepts_a_single_ocsf_log_destination() {
        let tmp = write_tmp("[openshell.gateway.ocsf_log]\npath = 'events.jsonl'\n");
        let config = load(tmp.path())
            .unwrap()
            .openshell
            .gateway
            .ocsf_log
            .unwrap();
        assert_eq!(config.rotation, OcsfLogRotation::Daily);
        assert_eq!(config.schema_version, None);
        assert_eq!(config.max_files.unwrap().get(), 7);
        assert_eq!(config.queue_capacity.get(), 10_000);
        assert_eq!(config.queue_max_bytes.get(), 16 * 1024 * 1024);
        assert!(ConfigFile::default().openshell.gateway.ocsf_log.is_none());
    }

    #[test]
    fn names_the_deprecated_schema_versions_that_are_set() {
        assert!(
            ConfigFile::default()
                .deprecated_ocsf_schema_versions()
                .is_empty()
        );
        let tmp = write_tmp(
            "[openshell.gateway.ocsf_log]\npath = 'events.jsonl'\nschema_version = '1.3'\n\n\
             [openshell.gateway.otlp.ocsf]\nenabled = true\nendpoint = 'http://siem:4317'\nschema_version = '1.3'\n",
        );
        assert_eq!(
            load(tmp.path()).unwrap().deprecated_ocsf_schema_versions(),
            [
                "openshell.gateway.ocsf_log.schema_version",
                "openshell.gateway.otlp.ocsf.schema_version"
            ]
        );
    }

    #[test]
    fn ocsf_log_accepts_the_deprecated_schema_version() {
        let tmp = write_tmp(
            "[openshell.gateway.ocsf_log]\npath = 'events.jsonl'\nschema_version = '1.3'\n",
        );
        let config = load(tmp.path())
            .unwrap()
            .openshell
            .gateway
            .ocsf_log
            .unwrap();
        assert_eq!(config.schema_version.as_deref(), Some("1.3"));
    }

    #[test]
    fn ocsf_log_rejects_invalid_and_unshipped_options() {
        for settings in [
            "",
            "path = ''",
            "path = 'log'\nqueue_capacity = 0",
            "path = 'log'\nqueue_max_bytes = 0",
            "path = 'log'\nmax_files = 0",
            "path = 'log'\nrotation = 'hourly'",
            "path = 'log'\nkind = 'jsonl'",
            "path = 'log'\nrotation = 'never'\nmax_files = 7",
        ] {
            let tmp = write_tmp(&format!("[openshell.gateway.ocsf_log]\n{settings}\n"));
            assert!(load(tmp.path()).is_err(), "accepted {settings}");
        }
        let tmp = write_tmp("[openshell.gateway.ocsf_log]\npath = 'log'\nrotation = 'never'\n");
        let config = load(tmp.path()).unwrap();
        let encoded = toml::to_string(&config).unwrap();
        assert!(toml::from_str::<ConfigFile>(&encoded).is_ok());
    }

    fn otlp(table: &str) -> OtlpConfig {
        let tmp = write_tmp(table);
        load(tmp.path())
            .unwrap_or_else(|error| panic!("{table}: {error:#}"))
            .openshell
            .gateway
            .otlp
            .expect("otlp config")
    }

    #[test]
    fn otlp_endpoint_alone_exports_traces_only() {
        let otlp = otlp("[openshell.gateway.otlp]\nendpoint = 'http://127.0.0.1:4317'\n");
        assert_eq!(otlp.traces_endpoint(), Some("http://127.0.0.1:4317"));
        assert!(otlp.service_name.is_none());
        assert_eq!(otlp.ocsf, None);
    }

    #[test]
    fn otlp_ocsf_defaults_to_the_shared_endpoint() {
        let otlp = otlp(
            "[openshell.gateway.otlp]\nendpoint = 'http://127.0.0.1:4317'\n\n\
             [openshell.gateway.otlp.ocsf]\nenabled = true\n",
        );
        assert_eq!(otlp.traces_endpoint(), Some("http://127.0.0.1:4317"));
        assert_eq!(
            otlp.ocsf,
            Some(OcsfOtlpConfig {
                collector: OtlpCollectorConfig {
                    endpoint: "http://127.0.0.1:4317".into(),
                    protocol: OtlpProtocol::Grpc,
                    headers: OtlpHeaders::default(),
                    headers_file: None,
                },
                schema_version: None,
            })
        );
    }

    #[test]
    fn otlp_signal_tables_override_the_shared_endpoint() {
        let otlp = otlp(
            "[openshell.gateway.otlp]\nendpoint = 'http://shared:4317'\n\n\
             [openshell.gateway.otlp.traces]\nendpoint = 'http://traces:4317'\n\n\
             [openshell.gateway.otlp.ocsf]\nenabled = true\nendpoint = 'http://siem:4317'\n",
        );
        assert_eq!(otlp.traces_endpoint(), Some("http://traces:4317"));
        assert_eq!(
            otlp.ocsf,
            Some(OcsfOtlpConfig {
                collector: OtlpCollectorConfig {
                    endpoint: "http://siem:4317".into(),
                    protocol: OtlpProtocol::Grpc,
                    headers: OtlpHeaders::default(),
                    headers_file: None,
                },
                schema_version: None,
            })
        );
    }

    #[test]
    fn otlp_ocsf_accepts_the_deprecated_schema_version() {
        let otlp = otlp(
            "[openshell.gateway.otlp.ocsf]\nenabled = true\nendpoint = 'http://siem:4317'\nschema_version = '1.3'\n",
        );
        assert_eq!(
            otlp.ocsf.and_then(|ocsf| ocsf.schema_version).as_deref(),
            Some("1.3")
        );
    }

    #[test]
    fn otlp_ocsf_exports_without_traces() {
        let otlp =
            otlp("[openshell.gateway.otlp.ocsf]\nenabled = true\nendpoint = 'http://siem:4317'\n");
        assert_eq!(otlp.traces_endpoint(), None);
        assert_eq!(
            otlp.ocsf.map(|ocsf| ocsf.collector.endpoint).as_deref(),
            Some("http://siem:4317")
        );
    }

    #[test]
    fn otlp_ocsf_is_off_unless_enabled() {
        for ocsf in ["", "enabled = false\n", "endpoint = 'http://siem:4317'\n"] {
            let otlp = otlp(&format!(
                "[openshell.gateway.otlp]\nendpoint = 'http://127.0.0.1:4317'\n\n\
                 [openshell.gateway.otlp.ocsf]\n{ocsf}"
            ));
            assert_eq!(otlp.ocsf, None, "enabled OCSF export with {ocsf:?}");
        }
    }

    #[test]
    fn otlp_agent_relay_is_off_unless_enabled() {
        for agent in ["", "enabled = false\n", "endpoint = 'http://agents:4317'\n"] {
            let otlp = otlp(&format!(
                "[openshell.gateway.otlp]\nendpoint = 'http://127.0.0.1:4317'\n\n\
                 [openshell.gateway.otlp.agent]\n{agent}"
            ));
            assert_eq!(
                otlp.agent_endpoint(),
                None,
                "enabled the relay with {agent:?}"
            );
        }
        let otlp = otlp("[openshell.gateway.otlp]\nendpoint = 'http://127.0.0.1:4317'\n");
        assert_eq!(otlp.agent_endpoint(), None);
    }

    #[test]
    fn otlp_agent_relay_defaults_to_the_shared_endpoint() {
        let otlp = otlp(
            "[openshell.gateway.otlp]\nendpoint = 'http://shared:4317'\n\n\
             [openshell.gateway.otlp.traces]\nendpoint = 'http://traces:4317'\n\n\
             [openshell.gateway.otlp.agent]\nenabled = true\n",
        );
        assert_eq!(otlp.traces_endpoint(), Some("http://traces:4317"));
        assert_eq!(otlp.agent_endpoint(), Some("http://shared:4317"));
    }

    #[test]
    fn otlp_agent_relay_uses_its_own_endpoint() {
        let otlp = otlp(
            "[openshell.gateway.otlp.agent]\nenabled = true\nendpoint = 'http://agents:4317'\n",
        );
        assert_eq!(otlp.traces_endpoint(), None);
        assert_eq!(otlp.agent_endpoint(), Some("http://agents:4317"));

        let tmp = write_tmp("[openshell.gateway.otlp.agent]\nenabled = true\n");
        let error = load(tmp.path()).expect_err("an enabled relay needs an endpoint");
        assert!(format!("{error:#}").contains("otlp.agent needs an endpoint"));
    }

    #[test]
    fn otlp_lanes_inherit_the_whole_shared_collector_or_none_of_it() {
        use openshell_core::sandbox_env::{OtlpExport, SupervisorOtlp};

        let export = |endpoint: &str, protocol| {
            Some(OtlpExport {
                endpoint: endpoint.into(),
                protocol,
            })
        };
        let shared = otlp(
            "[openshell.gateway.otlp]\nendpoint = 'http://shared:4318'\n\
             protocol = 'http/protobuf'\n\n\
             [openshell.gateway.otlp.ocsf]\nenabled = true\n\n\
             [openshell.gateway.otlp.agent]\nenabled = true\nendpoint = 'http://agents:4317'\n",
        );
        assert_eq!(
            shared.supervisor_otlp(),
            SupervisorOtlp {
                traces: export("http://shared:4318", OtlpProtocol::HttpProtobuf),
                ocsf: export("http://shared:4318", OtlpProtocol::HttpProtobuf),
                agent: export("http://agents:4317", OtlpProtocol::Grpc),
            },
            "lanes without an endpoint inherit the shared protocol; a lane \
             with its own endpoint does not"
        );

        let separate = otlp(
            "[openshell.gateway.otlp.traces]\nendpoint = 'http://traces:4318'\n\
             protocol = 'http/protobuf'\n\n\
             [openshell.gateway.otlp.agent]\nenabled = true\nendpoint = 'http://agents:4318'\n\
             protocol = 'http/protobuf'\n",
        );
        assert_eq!(
            separate.supervisor_otlp(),
            SupervisorOtlp {
                traces: export("http://traces:4318", OtlpProtocol::HttpProtobuf),
                agent: export("http://agents:4318", OtlpProtocol::HttpProtobuf),
                ..SupervisorOtlp::default()
            }
        );
    }

    #[test]
    fn otlp_lane_protocol_needs_its_own_endpoint() {
        for table in [
            "[openshell.gateway.otlp.traces]\nprotocol = 'http/protobuf'\n",
            "[openshell.gateway.otlp.ocsf]\nenabled = true\nprotocol = 'http/protobuf'\n",
            "[openshell.gateway.otlp.agent]\nenabled = true\nprotocol = 'http/protobuf'\n",
        ] {
            let tmp = write_tmp(&format!(
                "[openshell.gateway.otlp]\nendpoint = 'http://shared:4317'\n\n{table}"
            ));
            let error = load(tmp.path()).expect_err("protocol without endpoint");
            assert!(
                format!("{error:#}").contains("protocol without its own endpoint"),
                "{table}: {error:#}"
            );
        }
        let tmp = write_tmp(
            "[openshell.gateway.otlp]\nprotocol = 'http/protobuf'\n\n\
             [openshell.gateway.otlp.traces]\nendpoint = 'http://traces:4318'\n",
        );
        let error = load(tmp.path()).expect_err("a shared protocol without a shared endpoint");
        assert!(
            format!("{error:#}").contains("otlp sets protocol without its own endpoint"),
            "{error:#}"
        );
        let tmp = write_tmp(
            "[openshell.gateway.otlp.agent]\nenabled = true\n\
             endpoint = 'http://agents:4318'\nprotocol = 'http/json'\n",
        );
        let error = load(tmp.path()).expect_err("http/json is not supported");
        assert!(format!("{error:#}").contains("http/json"), "{error:#}");

        for table in [
            "[openshell.gateway.otlp]\nendpoint = 'https://shared:4318'\nprotocol = 'http/protobuf'\n",
            "[openshell.gateway.otlp.agent]\nenabled = true\nendpoint = 'HTTPS://agents:4318'\n\
             protocol = 'http/protobuf'\n",
        ] {
            let tmp = write_tmp(table);
            let error = load(tmp.path()).expect_err("https is not supported over http/protobuf");
            assert!(
                format!("{error:#}").contains("which http/protobuf does not support"),
                "{table}: {error:#}"
            );
        }
    }

    #[test]
    fn otlp_lane_headers_follow_the_collector_they_belong_to() {
        let headers = |otlp: &Option<_>| {
            otlp.as_ref()
                .map(|collector: &OtlpCollectorConfig| collector.headers.header_map())
                .unwrap_or_default()
        };
        let otlp = otlp(
            "[openshell.gateway.otlp]\nendpoint = 'http://shared:4318'\n\
             headers = { authorization = 'Bearer shared', X-Tenant = 'blue' }\n\n\
             [openshell.gateway.otlp.ocsf]\nenabled = true\n\n\
             [openshell.gateway.otlp.agent]\nenabled = true\nendpoint = 'http://mlflow:5000'\n\
             headers = { x-mlflow-experiment-id = '0' }\n",
        );
        let traces = headers(&otlp.traces.map(|traces| traces.collector));
        assert_eq!(traces["authorization"], "Bearer shared");
        assert_eq!(traces["x-tenant"], "blue");
        assert_eq!(headers(&otlp.ocsf.map(|ocsf| ocsf.collector)), traces);
        let agent = headers(&otlp.agent.map(|agent| agent.collector));
        assert_eq!(
            agent.len(),
            1,
            "a lane with its own endpoint inherits no headers"
        );
        assert_eq!(agent["x-mlflow-experiment-id"], "0");
    }

    #[test]
    fn otlp_lane_headers_need_their_own_endpoint() {
        for table in [
            "[openshell.gateway.otlp.traces]\nheaders = { a = 'b' }\n",
            "[openshell.gateway.otlp.ocsf]\nenabled = true\nheaders = { a = 'b' }\n",
            "[openshell.gateway.otlp.agent]\nenabled = true\nheaders = { a = 'b' }\n",
            "[openshell.gateway.otlp.traces]\nheaders_file = '/run/otlp/headers'\n",
        ] {
            let tmp = write_tmp(&format!(
                "[openshell.gateway.otlp]\nendpoint = 'http://shared:4317'\n\n{table}"
            ));
            let error = load(tmp.path()).expect_err("headers without endpoint");
            assert!(
                format!("{error:#}").contains("without its own endpoint"),
                "{table}: {error:#}"
            );
        }
        let tmp = write_tmp(
            "[openshell.gateway.otlp]\nheaders = { authorization = 'Bearer t' }\n\n\
             [openshell.gateway.otlp.traces]\nendpoint = 'http://traces:4317'\n",
        );
        let error = load(tmp.path()).expect_err("shared headers without a shared endpoint");
        assert!(
            format!("{error:#}").contains("otlp sets headers without its own endpoint"),
            "{error:#}"
        );
    }

    #[test]
    fn otlp_headers_must_be_valid_http_headers() {
        for (headers, problem) in [
            (
                "{ x-empty = '' }",
                "otlp.headers: empty value for header \"x-empty\"",
            ),
            (
                "{ x-text = 'café' }",
                "otlp.headers: invalid value for header \"x-text\"",
            ),
            (
                "{ Authorization = 'a', authorization = 'b' }",
                "otlp.headers: header \"authorization\" is set more than once",
            ),
            (
                "{ x-data-bin = 'AAAA' }",
                "otlp.headers: binary header \"x-data-bin\"",
            ),
            (
                "{ Content-Type = 'application/json' }",
                "otlp.headers: header \"content-type\" is set by the exporter",
            ),
            (
                "{ grpc-timeout = '1S' }",
                "otlp.headers: header \"grpc-timeout\" is set by the exporter",
            ),
            (
                "{ 'bad name' = 'x' }",
                "otlp.headers: invalid header name \"bad name\"",
            ),
            (
                "{ authorization = \"line\\nbreak\" }",
                "otlp.headers: invalid value for header \"authorization\"",
            ),
        ] {
            let tmp = write_tmp(&format!(
                "[openshell.gateway.otlp]\nendpoint = 'http://shared:4317'\nheaders = {headers}\n"
            ));
            let error = load(tmp.path()).expect_err("invalid header");
            assert!(format!("{error:#}").contains(problem), "{error:#}");
            assert!(!format!("{error:#}").contains("break"), "{error:#}");
        }
    }

    fn headers_file(contents: &[u8]) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), contents).unwrap();
        file
    }

    #[test]
    fn otlp_headers_file_supplies_the_collector_headers() {
        let file = headers_file(b"authorization = Bearer file-token\n\nx-tenant=blue\n");
        let path = file.path().display();
        let otlp = otlp(&format!(
            "[openshell.gateway.otlp]\nendpoint = 'http://shared:4317'\nheaders_file = '{path}'\n\n\
             [openshell.gateway.otlp.agent]\nenabled = true\nendpoint = 'http://agents:4318'\n\
             headers_file = '{path}'\n"
        ));
        let expected =
            OtlpHeaders::from([("authorization", "Bearer file-token"), ("x-tenant", "blue")])
                .header_map();
        let traces = otlp.traces.as_ref().unwrap();
        assert_eq!(traces.collector.headers.header_map(), expected);
        assert_eq!(
            otlp.agent.as_ref().unwrap().collector.headers.header_map(),
            expected
        );

        let encoded = toml::to_string(&otlp).unwrap();
        assert!(encoded.contains("headers_file"), "{encoded}");
        assert!(!encoded.contains("file-token"), "{encoded}");
    }

    #[test]
    fn otlp_headers_file_excludes_inline_headers() {
        let file = headers_file(b"authorization=Bearer t\n");
        let tmp = write_tmp(&format!(
            "[openshell.gateway.otlp]\nendpoint = 'http://shared:4317'\n\
             headers = {{ x-tenant = 'blue' }}\nheaders_file = '{}'\n",
            file.path().display()
        ));
        let error = load(tmp.path()).expect_err("headers and headers_file");
        assert!(
            format!("{error:#}").contains("otlp sets both headers and headers_file"),
            "{error:#}"
        );
    }

    #[test]
    fn otlp_headers_file_is_validated_like_inline_headers() {
        let too_large = format!("x-big={}\n", "a".repeat(64 * 1024));
        for (contents, problem) in [
            (
                b"authorization: Bearer secret-value\n".as_slice(),
                "otlp.headers_file: line 1 is not name=value",
            ),
            (
                b"x-empty=\n",
                "otlp.headers_file: empty value for header \"x-empty\"",
            ),
            (
                b"a=1\nA=2\n",
                "otlp.headers_file: header \"a\" is set more than once",
            ),
            (
                b"content-type=text/plain\n",
                "otlp.headers_file: header \"content-type\" is set by the exporter",
            ),
            (
                b"x-text=caf\xc3\xa9\n",
                "otlp.headers_file: invalid value for header \"x-text\"",
            ),
            (b"x-bytes=\xff\n", "is not UTF-8"),
            (too_large.as_bytes(), "is larger than 65536 bytes"),
        ] {
            let file = headers_file(contents);
            let tmp = write_tmp(&format!(
                "[openshell.gateway.otlp]\nendpoint = 'http://shared:4317'\nheaders_file = '{}'\n",
                file.path().display()
            ));
            let error = format!("{:#}", load(tmp.path()).expect_err(problem));
            assert!(error.contains(problem), "{error}");
            assert!(error.contains("otlp.headers_file: "), "{error}");
            assert!(!error.contains("secret-value"), "{error}");
        }

        let tmp = write_tmp(
            "[openshell.gateway.otlp]\nendpoint = 'http://shared:4317'\n\
             headers_file = '/nonexistent/otlp-headers'\n",
        );
        let error = format!("{:#}", load(tmp.path()).expect_err("missing file"));
        assert!(
            error.contains("otlp.headers_file: cannot read /nonexistent/otlp-headers"),
            "{error}"
        );
    }

    #[test]
    fn parse_errors_locate_the_problem_without_quoting_the_file() {
        let tmp = write_tmp(
            "[openshell.gateway.otlp]\nendpoint = 'http://shared:4317'\n\
             headers = { authorization = 'Bearer example-secret', x-tenant = 42 }\n",
        );
        let error = load(tmp.path()).expect_err("a non-string header value");
        let mut report = error.to_string();
        let mut source = std::error::Error::source(&error);
        while let Some(error) = source {
            report = format!("{report}\n{error}");
            source = error.source();
        }
        assert!(report.contains("line 6"), "{report}");
        assert!(report.contains("expected a string"), "{report}");
        assert!(!report.contains("example-secret"), "{report}");
    }

    #[test]
    fn otlp_header_values_are_redacted_from_debug_output() {
        let otlp = otlp(
            "[openshell.gateway.otlp]\nendpoint = 'http://shared:4317'\n\
             headers = { authorization = 'Bearer secret-token' }\n",
        );
        let debug = format!("{otlp:?}");
        assert!(debug.contains("authorization"), "{debug}");
        assert!(!debug.contains("secret-token"), "{debug}");
    }

    #[test]
    fn otlp_config_round_trips() {
        let tmp = write_tmp(
            "[openshell.gateway.otlp]\nendpoint = 'http://shared:4317'\nservice_name = 'gw'\n\n\
             [openshell.gateway.otlp.ocsf]\nenabled = true\n\n\
             [openshell.gateway.otlp.agent]\nenabled = true\nendpoint = 'http://agents:4318'\n\
             protocol = 'http/protobuf'\nheaders = { x-mlflow-experiment-id = '0' }\n",
        );
        let file = load(tmp.path()).unwrap();
        let encoded = toml::to_string(&file).unwrap();
        let decoded = toml::from_str::<ConfigFile>(&encoded).unwrap();
        assert_eq!(decoded.openshell.gateway.otlp, file.openshell.gateway.otlp);
    }

    #[test]
    fn otlp_config_rejects_missing_endpoints_and_unsupported_settings() {
        for table in [
            "[openshell.gateway.otlp]\n",
            "[openshell.gateway.otlp.traces]\n",
            "[openshell.gateway.otlp.ocsf]\n",
            "[openshell.gateway.otlp.ocsf]\nenabled = true\n",
            "[openshell.gateway.otlp.ocsf]\nenabled = 'yes'\nendpoint = 'http://siem:4317'\n",
            "[openshell.gateway.otlp.metrics]\nendpoint = 'http://metrics:4317'\n",
            "[openshell.gateway.otlp]\nendpoint = 'http://127.0.0.1:4317'\nocsf_logs = true\n",
        ] {
            let tmp = write_tmp(table);
            assert!(load(tmp.path()).is_err(), "accepted {table}");
        }
    }

    #[test]
    fn otlp_config_rejects_unknown_fields() {
        let toml = r#"
[openshell.gateway.otlp]
endpoint = "http://127.0.0.1:4317"
protocol = "http"
"#;
        let tmp = write_tmp(toml);
        assert!(load(tmp.path()).is_err(), "unknown otlp field is rejected");
    }

    #[test]
    fn otlp_config_rejects_sdk_tuning_keys() {
        // Sampling, batching, and limits are the SDK's env-var surface. A
        // `deny_unknown_fields` rejection is the signal that they do not
        // belong in the config file.
        let toml = r#"
[openshell.gateway.otlp]
endpoint = "http://127.0.0.1:4317"
sampler = "traceidratio"
"#;
        let tmp = write_tmp(toml);
        assert!(
            load(tmp.path()).is_err(),
            "sampler is configured via OTEL_TRACES_SAMPLER, not TOML"
        );
    }

    #[test]
    fn rejects_unknown_policy_validation_failure_mode() {
        let tmp = write_tmp(
            r#"
[openshell.gateway]
policy_validation_failure_mode = "keep_old"
"#,
        );
        let error = load(tmp.path()).expect_err("unknown posture must fail TOML validation");
        let error = error.to_string();
        assert!(error.contains("line 6, column 34"), "{error}");
        assert!(error.contains("unknown variant `keep_old`"), "{error}");
    }

    #[test]
    fn parses_delivery_mode_and_rejects_unknown_value() {
        let tmp = write_tmp(
            r#"
[openshell.gateway]
config_delivery_mode = "push"
"#,
        );
        let file = load(tmp.path()).unwrap();
        assert_eq!(
            file.openshell.gateway.config_delivery_mode,
            Some(openshell_core::config::ConfigDeliveryMode::Push)
        );

        let tmp = write_tmp(
            r#"
[openshell.gateway]
config_delivery_mode = "enabled"
"#,
        );
        assert!(load(tmp.path()).is_err());
    }

    #[test]
    fn parses_gateway_auth_config() {
        let toml = r"
[openshell.gateway.auth]
allow_unauthenticated_users = true
";
        let tmp = write_tmp(toml);
        let file = load(tmp.path()).expect("valid auth config parses");
        let auth = file.openshell.gateway.auth.expect("auth config");
        assert!(auth.allow_unauthenticated_users);
    }

    #[test]
    fn parses_supervisor_network_additional_ca_bundle() {
        let tmp = write_tmp(
            r#"
[openshell.supervisor.network]
additional_ca_bundle = "/etc/openshell/ca-bundle.crt"
"#,
        );

        let file = load(tmp.path()).expect("network supervisor config parses");
        assert_eq!(
            file.openshell.supervisor.network.additional_ca_bundle,
            Some(PathBuf::from("/etc/openshell/ca-bundle.crt"))
        );
    }

    #[test]
    fn supervisor_network_additional_ca_bundle_defaults_to_unset() {
        let file: ConfigFile = toml::from_str("[openshell.supervisor]\n").expect("valid config");
        assert!(
            file.openshell
                .supervisor
                .network
                .additional_ca_bundle
                .is_none()
        );
    }

    #[test]
    fn supervisor_network_rejects_unknown_fields() {
        let tmp = write_tmp(
            r"
[openshell.supervisor.network]
unknown = true
",
        );
        assert!(matches!(
            load(tmp.path()),
            Err(ConfigFileError::Parse { .. })
        ));
    }

    #[test]
    fn supervisor_network_rejects_empty_ca_bundle_path() {
        let tmp = write_tmp(
            r#"
[openshell.supervisor.network]
additional_ca_bundle = ""
"#,
        );
        let error = load(tmp.path()).expect_err("empty source paths must fail");
        assert!(
            error
                .to_string()
                .contains("openshell.supervisor.network.additional_ca_bundle")
        );
        assert!(error.to_string().contains("must not be empty"));
    }

    #[test]
    fn parses_supervisor_middleware_registration() {
        let certificate =
            openshell_crypto::pki::generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("test certificate");
        let mut ca = tempfile::Builder::new()
            .suffix(".pem")
            .tempfile()
            .expect("CA tempfile");
        ca.write_all(certificate.cert.pem().as_bytes())
            .expect("write CA");
        let toml = r#"
[[openshell.supervisor.middleware]]
name = "local-guard"
grpc_endpoint = "https://127.0.0.1:50051"
tls_ca_cert_path = 'CA_PATH'
audience = "urn:openshell:middleware:local-guard"
max_payload_bytes = 262144
timeout = "2s"
"#
        .replace("CA_PATH", &ca.path().display().to_string());
        let tmp = write_tmp(&toml);
        let file = load(tmp.path()).expect("valid middleware registration parses");
        assert_eq!(
            file.openshell.supervisor.middleware,
            vec![MiddlewareServiceFileConfig {
                name: "local-guard".into(),
                grpc_endpoint: "https://127.0.0.1:50051".into(),
                tls_ca_cert_path: Some(ca.path().to_path_buf()),
                audience: Some("urn:openshell:middleware:local-guard".into()),
                allow_insecure_transport: false,
                max_payload_bytes: 262_144,
                timeout: Some("2s".into()),
                binding_policy: ExtensionBindingPolicy::Dynamic,
                bindings: vec![],
            }]
        );
        let registration =
            SupervisorMiddlewareService::try_from(&file.openshell.supervisor.middleware[0])
                .expect("valid CA resolves");
        assert_eq!(registration.request_timeout.unwrap().seconds, 2);
        let registered_pem = String::from_utf8(registration.tls_ca_cert_pem)
            .expect("registered CA remains PEM text")
            .replace("\r\n", "\n");
        let generated_pem = certificate.cert.pem().replace("\r\n", "\n");
        assert_eq!(registered_pem, generated_pem);
        assert_eq!(
            registration.audience,
            "urn:openshell:middleware:local-guard"
        );
    }

    #[test]
    fn supervisor_middleware_binding_policy_reaches_wire_configuration() {
        use SupervisorMiddlewareBinding::{HttpRequestPreCredentials, HttpResponsePreReturn};
        use SupervisorMiddlewareBindingPolicy::{Allowlist, Unspecified};

        let toml = r#"
name = "guard"
grpc_endpoint = "https://guard.example:50051"
max_payload_bytes = 1024
"#;
        let parse = |text: &str| {
            let config: MiddlewareServiceFileConfig = ::toml::from_str(text).unwrap();
            SupervisorMiddlewareService::try_from(&config).unwrap()
        };
        let default = parse(toml);
        assert_eq!(default.binding_policy, Unspecified as i32);
        assert!(default.bindings.is_empty());

        let registration = parse(&format!(
            r#"{toml}
binding_policy = "allowlist"
bindings = ["http_response_pre_return", "http_request_pre_credentials"]
"#
        ));
        assert_eq!(registration.binding_policy, Allowlist as i32);
        assert_eq!(
            registration.bindings,
            [
                HttpRequestPreCredentials as i32,
                HttpResponsePreReturn as i32
            ]
        );
    }

    #[test]
    fn middleware_registration_defaults_audience_to_name() {
        let mut config = MiddlewareServiceFileConfig {
            name: "local-guard".into(),
            grpc_endpoint: "https://guard.example:50051".into(),
            tls_ca_cert_path: None,
            audience: None,
            allow_insecure_transport: false,
            max_payload_bytes: 262_144,
            timeout: None,
            binding_policy: ExtensionBindingPolicy::Dynamic,
            bindings: vec![],
        };

        let registration = SupervisorMiddlewareService::try_from(&config).unwrap();
        assert_eq!(
            registration.audience,
            "urn:openshell:extension:middleware:local-guard"
        );
        assert!(registration.tls_ca_cert_pem.is_empty());

        config.audience = Some(String::new());
        let registration = SupervisorMiddlewareService::try_from(&config).unwrap();
        assert_eq!(
            registration.audience,
            "urn:openshell:extension:middleware:local-guard"
        );
    }

    #[test]
    fn middleware_registration_rejects_invalid_ca_pem() {
        let mut ca = tempfile::Builder::new()
            .suffix(".pem")
            .tempfile()
            .expect("CA tempfile");
        ca.write_all(b"not a certificate").expect("write CA");
        let config = MiddlewareServiceFileConfig {
            name: "local-guard".into(),
            grpc_endpoint: "https://guard.example:50051".into(),
            tls_ca_cert_path: Some(ca.path().to_path_buf()),
            audience: None,
            allow_insecure_transport: false,
            max_payload_bytes: 262_144,
            timeout: None,
            binding_policy: ExtensionBindingPolicy::Dynamic,
            bindings: vec![],
        };

        let error = SupervisorMiddlewareService::try_from(&config)
            .expect_err("invalid CA must fail before service connection");
        assert!(matches!(
            error,
            ConfigFileError::MiddlewareTlsCaInvalid { .. }
        ));
    }

    #[test]
    fn middleware_registration_rejects_ca_bundle_with_private_key() {
        use std::io::Write as _;

        let certificate =
            openshell_crypto::pki::generate_simple_self_signed(vec!["localhost".into()])
                .expect("test certificate");
        let mut ca = tempfile::Builder::new()
            .suffix(".pem")
            .tempfile()
            .expect("CA tempfile");
        ca.write_all(certificate.cert.pem().as_bytes())
            .expect("write certificate");
        ca.write_all(certificate.key_pair.serialize_pem().unwrap().as_bytes())
            .expect("write private key");
        let config = MiddlewareServiceFileConfig {
            name: "local-guard".into(),
            grpc_endpoint: "https://guard.example:50051".into(),
            tls_ca_cert_path: Some(ca.path().to_path_buf()),
            audience: None,
            allow_insecure_transport: false,
            max_payload_bytes: 262_144,
            timeout: None,
            binding_policy: ExtensionBindingPolicy::Dynamic,
            bindings: vec![],
        };

        let error = SupervisorMiddlewareService::try_from(&config)
            .expect_err("private key material must never be distributed to a sandbox");
        assert!(matches!(
            error,
            ConfigFileError::MiddlewareTlsCaInvalid { .. }
        ));
        assert!(error.to_string().contains("non-certificate block"));
    }

    #[test]
    fn parses_gateway_interceptor_tls_and_audience() {
        let tmp = write_tmp(
            r#"
[[openshell.gateway.interceptors]]
name = "quota"
grpc_endpoint = "https://quota.example:50051"
tls_ca_cert_path = "/etc/openshell/quota-ca.pem"
audience = "urn:openshell:interceptor:quota"
"#,
        );

        let file = load(tmp.path()).expect("valid interceptor config parses");
        let interceptor = &file.openshell.gateway.interceptors[0];
        assert_eq!(
            interceptor.tls_ca_cert_path.as_deref(),
            Some(Path::new("/etc/openshell/quota-ca.pem"))
        );
        assert_eq!(
            interceptor.resolved_audience(),
            "urn:openshell:interceptor:quota"
        );
    }

    #[test]
    fn parses_legacy_supervisor_middleware_payload_limit() {
        let toml = r#"
[[openshell.supervisor.middleware]]
name = "local-guard"
grpc_endpoint = "http://127.0.0.1:50051"
max_body_bytes = 262144
"#;
        let tmp = write_tmp(toml);
        let file = load(tmp.path()).expect("legacy middleware registration parses");
        assert_eq!(
            file.openshell.supervisor.middleware[0].max_payload_bytes,
            262_144
        );
    }

    #[test]
    fn parses_provider_profile_source_composition() {
        let toml = r#"
[openshell.gateway]
provider_profile_sources = [
  { type = "user" },
  { type = "interceptor", name = "provider-governance" },
]
"#;
        let tmp = write_tmp(toml);
        let file = load(tmp.path()).expect("valid provider profile sources parse");
        assert_eq!(
            file.openshell.gateway.provider_profile_sources,
            Some(vec![
                GatewayProviderProfileSourceConfig::User,
                GatewayProviderProfileSourceConfig::Interceptor {
                    name: "provider-governance".to_string(),
                },
            ])
        );
    }

    #[test]
    fn rejects_the_removed_builtin_provider_profile_source() {
        let toml = r#"
[openshell.gateway]
provider_profile_sources = [
  { type = "builtin" },
  { type = "user" },
]
"#;
        let tmp = write_tmp(toml);
        let error = load(tmp.path()).expect_err("the builtin source was removed");
        let message = error.to_string();
        assert!(message.contains("import-only"), "{message}");
        assert!(
            message.contains("openshell provider profile import"),
            "{message}"
        );
    }

    #[test]
    fn rejects_database_url_in_file() {
        let toml = r#"
[openshell.gateway]
database_url = "sqlite::memory:"
"#;
        let tmp = write_tmp(toml);
        let err = load(tmp.path()).expect_err("database_url must be rejected");
        assert!(matches!(
            err,
            ConfigFileError::SecretInFile {
                field: "database_url",
                ..
            }
        ));
    }

    #[test]
    fn parses_database_max_connections() {
        let toml = r"
[openshell.gateway]
database_max_connections = 64
";
        let tmp = write_tmp(toml);
        let file = load(tmp.path()).expect("a positive pool ceiling parses");
        assert_eq!(file.openshell.gateway.database_max_connections, Some(64));
    }

    #[test]
    fn rejects_zero_database_max_connections() {
        let toml = r"
[openshell.gateway]
database_max_connections = 0
";
        let tmp = write_tmp(toml);
        let err = load(tmp.path()).expect_err("a zero pool ceiling must be rejected");
        assert!(matches!(
            err,
            ConfigFileError::InvalidValue {
                field: "openshell.gateway.database_max_connections",
                ..
            }
        ));
    }

    #[test]
    fn parses_database_lock_max_connections() {
        let toml = r"
[openshell.gateway]
database_lock_max_connections = 8
";
        let tmp = write_tmp(toml);
        let file = load(tmp.path()).expect("a positive lock pool ceiling parses");
        assert_eq!(
            file.openshell.gateway.database_lock_max_connections,
            Some(8)
        );
    }

    #[test]
    fn rejects_zero_database_lock_max_connections() {
        let toml = r"
[openshell.gateway]
database_lock_max_connections = 0
";
        let tmp = write_tmp(toml);
        let err = load(tmp.path()).expect_err("a zero lock pool ceiling must be rejected");
        assert!(matches!(
            err,
            ConfigFileError::InvalidValue {
                field: "openshell.gateway.database_lock_max_connections",
                ..
            }
        ));
    }

    #[test]
    fn parses_the_supervisor_pool_tuning() {
        let pool = |table: &str| {
            let tmp = write_tmp(&format!("[openshell.gateway.supervisor_pool]\n{table}"));
            load(tmp.path()).map(|file| file.openshell.gateway.supervisor_pool)
        };
        let configured = pool("recovery_timeout_secs = 90\n").unwrap().unwrap();
        assert_eq!(configured.recovery_timeout_secs, Some(90));
        assert_eq!(pool("").unwrap().unwrap().recovery_timeout_secs, None);
        let tmp = write_tmp("[openshell.gateway]\n");
        assert!(
            load(tmp.path())
                .unwrap()
                .openshell
                .gateway
                .supervisor_pool
                .is_none()
        );
        // Recovery stays bounded, and unknown keys, including the removed
        // `enabled` switch, are refused.
        assert_eq!(
            pool("recovery_timeout_secs = 30\n")
                .unwrap()
                .unwrap()
                .recovery_timeout_secs,
            Some(30)
        );
        for out_of_range in ["10", "29", "301"] {
            assert!(matches!(
                pool(&format!("recovery_timeout_secs = {out_of_range}\n")),
                Err(ConfigFileError::InvalidValue {
                    field: "openshell.gateway.supervisor_pool.recovery_timeout_secs",
                    ..
                })
            ));
        }
        for unknown in ["enabled = true\n", "high_availability = true\n"] {
            assert!(
                matches!(pool(unknown), Err(ConfigFileError::Parse { .. })),
                "{unknown}"
            );
        }
    }

    #[test]
    fn rejects_unknown_gateway_field() {
        let toml = r"
[openshell.gateway]
nonsense = true
";
        let tmp = write_tmp(toml);
        let err = load(tmp.path()).expect_err("unknown field must be rejected");
        assert!(matches!(err, ConfigFileError::Parse { .. }));
    }

    #[test]
    fn rejects_operator_selected_tls_client_auth_policy() {
        let toml = r#"
[openshell.gateway.tls]
cert_path = "/tls/server.crt"
key_path = "/tls/server.key"
client_ca_path = "/tls/ca.crt"
require_client_auth = false
"#;
        let tmp = write_tmp(toml);
        let error = load(tmp.path()).expect_err("derived TLS client-auth policy must be rejected");
        assert!(matches!(error, ConfigFileError::Parse { .. }));
        assert!(error.to_string().contains("require_client_auth"));
    }

    #[test]
    fn rejects_removed_driver_fields_at_gateway_scope() {
        for field in [
            "sandbox_namespace = \"agents\"",
            "default_image = \"sandbox:latest\"",
            "supervisor_image = \"supervisor:latest\"",
            "client_tls_secret_name = \"sandbox-tls\"",
            "service_account_name = \"sandbox-sa\"",
            "host_gateway_ip = \"10.0.0.1\"",
            "enable_user_namespaces = true",
            "sa_token_ttl_secs = 3600",
        ] {
            let tmp = write_tmp(&format!("[openshell.gateway]\n{field}\n"));
            let err = load(tmp.path()).expect_err("gateway-scoped driver field must be rejected");
            assert!(
                matches!(err, ConfigFileError::Parse { .. }),
                "field: {field}"
            );
        }
    }

    #[test]
    fn rejects_unknown_field_in_nested_gateway_jwt_table() {
        // Regression guard for the class of silent-misconfig bug fixed in
        // PR #1661: a key indented under the wrong table header (here,
        // `sandbox_namespace` landing under `[openshell.gateway.gateway_jwt]`
        // instead of `[openshell.gateway]`) must be rejected rather than
        // silently ignored.
        let toml = r#"
[openshell.gateway.gateway_jwt]
signing_key_path = "/tmp/jwt/signing.pem"
public_key_path = "/tmp/jwt/public.pem"
kid_path = "/tmp/jwt/kid"
sandbox_namespace = "agents"
"#;
        let tmp = write_tmp(toml);
        let err = load(tmp.path())
            .expect_err("unknown field in nested gateway_jwt table must be rejected");
        assert!(matches!(err, ConfigFileError::Parse { .. }));
    }

    #[test]
    fn rejects_removed_ssh_endpoint_fields() {
        let toml = r"
[openshell.gateway]
ssh_gateway_port = 8080
";
        let tmp = write_tmp(toml);
        let err = load(tmp.path()).expect_err("removed SSH endpoint keys must be rejected");
        assert!(matches!(err, ConfigFileError::Parse { .. }));
    }

    #[test]
    fn rejects_legacy_version() {
        let tmp = write_raw_tmp("[openshell]\nversion = 1\n");
        let err = load(tmp.path()).expect_err("version 1 must be rejected");
        assert!(matches!(
            err,
            ConfigFileError::UnsupportedVersion { version: 1 }
        ));
    }

    #[test]
    fn rejects_missing_version_in_nonempty_file() {
        let tmp = write_raw_tmp("[openshell]\n\n[openshell.gateway]\nname = \"test\"\n");
        assert!(matches!(
            load(tmp.path()),
            Err(ConfigFileError::MissingVersion)
        ));
    }

    #[test]
    fn rejects_future_version() {
        let tmp = write_raw_tmp("[openshell]\nversion = 3\n");
        assert!(matches!(
            load(tmp.path()),
            Err(ConfigFileError::UnsupportedVersion { version: 3 })
        ));
    }

    #[test]
    fn accepts_current_version() {
        let tmp = write_raw_tmp("[openshell]\nversion = 2\n");
        load(tmp.path()).expect("schema version 2 must be accepted");
        preflight(tmp.path()).expect("schema version 2 must pass preflight");
    }

    #[test]
    fn preflight_classifies_versions_and_malformed_files_without_disclosing_contents() {
        for (contents, category, version) in [
            ("[openshell]\nversion = 1\n", "legacy_schema_v1", "1"),
            ("[openshell]\n", "missing_version", "missing"),
            ("[openshell]\nversion = 3\n", "future_version", "3"),
            ("[openshell]\nversion = 0\n", "unsupported_version", "0"),
            ("[openshell]\nversion = 'two'\n", "malformed", "unavailable"),
            (
                "[openshell]\nversion = 2\nsecret-value = [",
                "malformed",
                "unavailable",
            ),
            (
                "[openshell]\nversion = 2\n[openshell.gateway]\nunknown = 'secret-value'\n",
                "malformed",
                "2",
            ),
        ] {
            let tmp = write_raw_tmp(contents);
            let error = preflight(tmp.path()).expect_err("preflight must reject fixture");
            assert_eq!(error.category(), category, "contents: {contents}");
            assert_eq!(error.detected_version(), version, "contents: {contents}");
            let diagnostic = error.to_string();
            assert!(diagnostic.contains(&format!("category={category}")));
            assert!(diagnostic.contains(&format!("detected_version={version}")));
            assert!(diagnostic.contains("the file was preserved unchanged"));
            assert!(diagnostic.contains(CONFIG_MIGRATION_URL));
            assert!(!diagnostic.contains("secret-value"));
            assert!(!format!("{error:?}").contains("secret-value"));
            assert!(std::error::Error::source(&error).is_none());
        }
    }

    #[test]
    fn preflight_classifies_missing_path() {
        let path = Path::new("/nonexistent/openshell-preflight.toml");
        let error = preflight(path).expect_err("missing explicit path must fail");
        assert_eq!(error.category(), "missing_path");
        assert_eq!(error.detected_version(), "unavailable");
        assert!(error.to_string().contains(&path.display().to_string()));
    }

    #[test]
    fn preflight_rejects_directory_as_non_regular() {
        let tmp = tempfile::tempdir().unwrap();
        let error = preflight(tmp.path()).expect_err("directory must fail preflight");
        assert_eq!(error.category(), "non_regular_path");
        assert_eq!(error.detected_version(), "unavailable");
    }

    #[cfg(unix)]
    #[test]
    fn preflight_and_runtime_reject_symlinks_without_following_them() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.toml");
        let link = dir.path().join("gateway.toml");
        std::fs::write(&target, "[openshell]\nversion = 2\n").unwrap();
        symlink(&target, &link).unwrap();

        let error = preflight(&link).expect_err("symlink must fail preflight");
        assert_eq!(error.category(), "non_regular_path");
        assert!(matches!(
            load(&link),
            Err(ConfigFileError::NonRegular { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn preflight_rejects_fifo_without_blocking() {
        use nix::sys::stat::Mode;
        use nix::unistd::mkfifo;

        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("gateway.toml");
        mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
        let error = preflight(&fifo).expect_err("FIFO must fail preflight");
        assert_eq!(error.category(), "non_regular_path");
    }

    #[test]
    fn preflight_classifies_non_utf8_as_malformed() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), [0xff, 0xfe]).unwrap();
        let error = preflight(tmp.path()).expect_err("non-UTF-8 config must fail");
        assert_eq!(error.category(), "malformed");
        assert_eq!(error.detected_version(), "unavailable");
    }

    #[test]
    fn driver_table_uses_only_driver_owned_values() {
        let raw = toml::toml! {
            default_image = "driver-specific"
            socket_path = "/run/openshell/driver.sock"
        };
        let table = driver_table(
            "alpha",
            &GatewayFileSection::default(),
            Some(&toml::Value::Table(raw)),
        );
        let table = table.as_table().expect("driver table");
        assert_eq!(
            table.get("default_image").and_then(toml::Value::as_str),
            Some("driver-specific")
        );
        assert_eq!(
            table.get("socket_path").and_then(toml::Value::as_str),
            Some("/run/openshell/driver.sock")
        );
    }

    #[test]
    fn driver_table_does_not_inject_gateway_values() {
        let table = driver_table("alpha", &GatewayFileSection::default(), None);
        assert!(table.as_table().expect("driver table").is_empty());
    }

    #[test]
    fn missing_path_is_io_error() {
        let err = load(Path::new("/nonexistent/openshell-gateway.toml"))
            .expect_err("missing file must be io error");
        assert!(matches!(err, ConfigFileError::Io { .. }));
    }

    /// Contract test: the RPM default config template must parse against the
    /// current schema and must pin the settings that Podman deployments require.
    ///
    /// This test loads `deploy/rpm/gateway.toml.default` through the same
    /// `load()` path that the gateway uses at runtime, catching:
    ///   - template corruption or unknown fields (`deny_unknown_fields`)
    ///   - schema drift (version bump or field renames)
    ///   - accidental addition of a wildcard bind-address override
    ///   - accidental changes to the configured compute driver
    #[test]
    fn rpm_default_config_parses_and_has_podman_defaults() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/rpm/gateway.toml.default");
        let config =
            load(&path).expect("deploy/rpm/gateway.toml.default must parse against current schema");
        let gw = &config.openshell.gateway;

        if let Some(addr) = gw.bind_address {
            assert!(
                !addr.ip().is_unspecified(),
                "RPM default config must not expose the primary listener on every interface"
            );
        }

        assert_eq!(
            gw.compute_driver.as_deref(),
            Some("podman"),
            "RPM default must pin compute_driver to podman to prevent unexpected \
             driver selection when Docker is also installed"
        );

        let podman = driver_table(
            "podman",
            &config.openshell.gateway,
            config.openshell.drivers.get("podman"),
        );
        assert_eq!(
            podman
                .get("health_check_interval_secs")
                .and_then(toml::Value::as_integer),
            Some(10),
            "RPM defaults must retain Podman's readiness health check"
        );
    }
}
