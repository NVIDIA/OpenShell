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
use std::io::Cursor;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use openshell_core::proto::SupervisorMiddlewareService;
use openshell_core::{
    GatewayAuthConfig, GatewayInterceptorConfig, GatewayJwtConfig,
    GatewayProviderProfileSourceConfig, MtlsAuthConfig, OidcConfig, TlsConfig,
};
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

    /// `[openshell.drivers.<name>]` tables — passed verbatim to each driver
    /// crate's `Deserialize` impl. Stored as raw [`toml::Value`] so each
    /// driver can evolve its schema
    /// independently of this crate.
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
    #[serde(default)]
    pub grpc_rate_limit_requests: Option<u64>,
    #[serde(default)]
    pub grpc_rate_limit_window_seconds: Option<u64>,
    /// Security posture when a sandbox rejects a candidate policy generation.
    #[serde(default)]
    pub policy_validation_failure_mode: Option<openshell_core::PolicyValidationFailureMode>,

    // ── Service routing ──────────────────────────────────────────────────
    /// Subject Alternative Names configured on the gateway server certificate.
    /// Wildcard DNS SANs also enable sandbox service URLs under that domain.
    #[serde(default)]
    pub server_sans: Option<Vec<String>>,
    /// Enable plaintext HTTP routing for loopback sandbox service URLs.
    #[serde(default)]
    pub enable_loopback_service_http: Option<bool>,

    // ── Sandbox client TLS ───────────────────────────────────────────────
    #[serde(default)]
    pub guest_tls_ca: Option<PathBuf>,
    #[serde(default)]
    pub guest_tls_cert: Option<PathBuf>,
    #[serde(default)]
    pub guest_tls_key: Option<PathBuf>,

    // ── TLS toggle ───────────────────────────────────────────────────────
    /// When `true`, the gateway listens on plaintext HTTP and ignores any
    /// `[openshell.gateway.tls]` table. Mirrors `--disable-tls`.
    #[serde(default)]
    pub disable_tls: Option<bool>,

    // ── Nested tables ────────────────────────────────────────────────────
    #[serde(default)]
    pub tls: Option<TlsConfig>,
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

    // ── Disallowed-in-file fields ────────────────────────────────────────
    //
    // Captured so we can produce a friendly "set this via env/CLI instead"
    // error rather than a generic "unknown field" message. Validated and
    // rejected in [`load`].
    #[serde(default)]
    pub database_url: Option<String>,
}

/// `[openshell.gateway.otlp]` section.
///
/// Presence of this table enables OTLP export; there is no `enabled` flag.
/// SDK tuning knobs are deliberately absent — see [`crate::otel_tracing`] for what
/// this table owns and what the `OTEL_*` environment variables own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OtlpConfig {
    /// OTLP/gRPC collector endpoint, e.g.
    /// `http://otel-collector.observability.svc:4317`.
    pub endpoint: String,

    /// `service.name` resource attribute. Defaults to `openshell-gateway`.
    #[serde(default)]
    pub service_name: Option<String>,
}

/// `[openshell.supervisor]` section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorFileSection {
    /// Statically registered supervisor middleware services. Registration is
    /// operator-owned and changes require a gateway restart.
    #[serde(default)]
    pub middleware: Vec<MiddlewareServiceFileConfig>,
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

        Ok(Self {
            name: config.name.clone(),
            grpc_endpoint: config.grpc_endpoint.clone(),
            max_payload_bytes: config.max_payload_bytes,
            timeout: config.timeout.clone().unwrap_or_default(),
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
    for item in rustls_pemfile::read_all(&mut Cursor::new(pem)) {
        let item = item.map_err(|source| ConfigFileError::MiddlewareTlsCaInvalid {
            name: name.to_string(),
            path: path.to_path_buf(),
            message: source.to_string(),
        })?;
        let rustls_pemfile::Item::X509Certificate(certificate) = item else {
            return Err(ConfigFileError::MiddlewareTlsCaInvalid {
                name: name.to_string(),
                path: path.to_path_buf(),
                message: "PEM bundle contains a non-certificate block".to_string(),
            });
        };
        certificate_count += 1;
        sanitized.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
        let encoded = base64::engine::general_purpose::STANDARD.encode(certificate.as_ref());
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
    #[error("failed to parse gateway config file '{}': {source}", path.display())]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
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

/// Load and validate a TOML config file.
///
/// Configuration files must declare exactly [`SCHEMA_VERSION`]. Running
/// without a config file still uses CLI, environment, and built-in defaults.
#[cfg_attr(target_os = "windows", allow(clippy::result_large_err))]
pub fn load(path: &Path) -> Result<ConfigFile, ConfigFileError> {
    let contents = std::fs::read_to_string(path).map_err(|source| ConfigFileError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if contents.trim().is_empty() {
        return Err(ConfigFileError::MissingVersion);
    }
    let file: ConfigFile = toml::from_str(&contents).map_err(|source| ConfigFileError::Parse {
        path: path.to_path_buf(),
        source,
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
    if let Some((name, _)) = file
        .openshell
        .drivers
        .iter()
        .find(|(_, value)| !value.is_table())
    {
        return Err(ConfigFileError::InvalidDriverTable { name: name.clone() });
    }

    Ok(file)
}

/// Return a driver's table without gateway-level inheritance.
/// Driver-specific configuration belongs exclusively to
/// `[openshell.drivers.<name>]` in schema version 2.
pub fn driver_table(
    _driver_name: &str,
    _gateway: &GatewayFileSection,
    raw: Option<&toml::Value>,
) -> toml::Value {
    match raw {
        Some(toml::Value::Table(table)) => toml::Value::Table(table.clone()),
        _ => toml::Value::Table(toml::Table::new()),
    }
}

pub(crate) fn driver_table_with_inherited_keys(
    driver_name: &str,
    gateway: &GatewayFileSection,
    raw: Option<&toml::Value>,
    _inherited_config_keys: &[&str],
) -> toml::Value {
    driver_table(driver_name, gateway, raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

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
default_image = "ghcr.io/nvidia/openshell-community/sandboxes/base:latest"
supervisor_image = "ghcr.io/nvidia/openshell/supervisor:latest"
client_tls_secret_name = "openshell-sandbox-tls"
service_account_name = "openshell-sandbox"

[openshell.gateway.tls]
cert_path = "/etc/openshell/certs/gateway.pem"
key_path = "/etc/openshell/certs/gateway-key.pem"
client_ca_path = "/etc/openshell/certs/client-ca.pem"

[openshell.gateway.oidc]
issuer = "https://idp.example.com/realms/openshell"
audience = "openshell-cli"

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
        assert_eq!(
            gw.default_image.as_deref(),
            Some("ghcr.io/nvidia/openshell-community/sandboxes/base:latest")
        );
        assert_eq!(gw.grpc_rate_limit_requests, Some(120));
        assert_eq!(gw.grpc_rate_limit_window_seconds, Some(60));
        assert_eq!(
            gw.policy_validation_failure_mode,
            Some(openshell_core::PolicyValidationFailureMode::RetainLastValid)
        );
        assert!(gw.tls.is_some());
        assert!(gw.oidc.is_some());
        assert_eq!(
            gw.credential_drivers.as_deref(),
            Some(&["kubernetes-secrets".to_string()][..])
        );
        assert!(gw.default_credential_driver.is_none());
        assert!(file.openshell.drivers.contains_key("kubernetes"));
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
            otlp.endpoint,
            "http://otel-collector.observability.svc:4317"
        );
        assert_eq!(otlp.service_name.as_deref(), Some("openshell-gateway-dev"));
    }

    #[test]
    fn otlp_config_requires_only_endpoint() {
        let toml = r#"
[openshell.gateway.otlp]
endpoint = "http://127.0.0.1:4317"
"#;
        let tmp = write_tmp(toml);
        let file = load(tmp.path()).expect("minimal otlp config parses");
        let otlp = file.openshell.gateway.otlp.expect("otlp config");
        assert_eq!(otlp.endpoint, "http://127.0.0.1:4317");
        assert!(otlp.service_name.is_none());
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
        assert!(error.to_string().contains("policy_validation_failure_mode"));
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
    fn parses_supervisor_middleware_registration() {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
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
            }]
        );
        let registration =
            SupervisorMiddlewareService::try_from(&file.openshell.supervisor.middleware[0])
                .expect("valid CA resolves");
        assert_eq!(registration.timeout, "2s");
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
    fn middleware_registration_defaults_audience_to_name() {
        let mut config = MiddlewareServiceFileConfig {
            name: "local-guard".into(),
            grpc_endpoint: "https://guard.example:50051".into(),
            tls_ca_cert_path: None,
            audience: None,
            allow_insecure_transport: false,
            max_payload_bytes: 262_144,
            timeout: None,
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
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("test certificate");
        let mut ca = tempfile::Builder::new()
            .suffix(".pem")
            .tempfile()
            .expect("CA tempfile");
        ca.write_all(certificate.cert.pem().as_bytes())
            .expect("write certificate");
        ca.write_all(certificate.key_pair.serialize_pem().as_bytes())
            .expect("write private key");
        let config = MiddlewareServiceFileConfig {
            name: "local-guard".into(),
            grpc_endpoint: "https://guard.example:50051".into(),
            tls_ca_cert_path: Some(ca.path().to_path_buf()),
            audience: None,
            allow_insecure_transport: false,
            max_payload_bytes: 262_144,
            timeout: None,
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
  { type = "builtin" },
  { type = "user" },
  { type = "interceptor", name = "provider-governance" },
]
"#;
        let tmp = write_tmp(toml);
        let file = load(tmp.path()).expect("valid provider profile sources parse");
        assert_eq!(
            file.openshell.gateway.provider_profile_sources,
            Some(vec![
                GatewayProviderProfileSourceConfig::Builtin,
                GatewayProviderProfileSourceConfig::User,
                GatewayProviderProfileSourceConfig::Interceptor {
                    name: "provider-governance".to_string(),
                },
            ])
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
