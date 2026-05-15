// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! TOML configuration file loader for the gateway.
//!
//! See `rfc/0003-gateway-configuration/README.md` for the file format. This
//! module parses the file into [`ConfigFile`], rejects fields that must be
//! supplied via env/CLI (database URL), and provides
//! [`driver_table`] which overlays shared `[openshell.gateway]` defaults onto
//! a `[openshell.drivers.<name>]` table so each driver crate's
//! `Deserialize` impl sees a fully-populated table.
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
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use openshell_core::config::ComputeDriverKind;
use openshell_core::{OidcConfig, TlsConfig};
use serde::{Deserialize, Serialize};

/// Latest schema version this build understands.
pub const SCHEMA_VERSION: u32 = 1;

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
    /// Reserved for future schema migrations. Versions greater than
    /// [`SCHEMA_VERSION`] are rejected at load time.
    #[serde(default)]
    pub version: Option<u32>,

    #[serde(default)]
    pub gateway: GatewayFileSection,

    /// `[openshell.drivers.<name>]` tables — passed verbatim to each driver
    /// crate's `Deserialize` impl after the gateway-side inheritance merge.
    /// Stored as raw [`toml::Value`] so each driver can evolve its schema
    /// independently of this crate.
    #[serde(default)]
    pub drivers: BTreeMap<String, toml::Value>,
}

/// `[openshell.gateway]` section.
///
/// All fields are `Option<T>` so the loader can tell whether a key was set
/// in the file (`Some`) or not (`None` — value is taken from CLI/env/default).
///
/// The fields under "Shared driver defaults" are inherited into
/// `[openshell.drivers.<name>]` tables per [`inheritable_keys`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayFileSection {
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
    #[serde(default)]
    pub compute_drivers: Option<Vec<ComputeDriverKind>>,

    // ── Sandbox / SSH ────────────────────────────────────────────────────
    #[serde(default)]
    pub sandbox_namespace: Option<String>,
    #[serde(default)]
    pub ssh_session_ttl_secs: Option<u64>,

    // ── Service routing ──────────────────────────────────────────────────
    /// Subject Alternative Names configured on the gateway server certificate.
    /// Wildcard DNS SANs also enable sandbox service URLs under that domain.
    #[serde(default)]
    pub server_sans: Option<Vec<String>>,
    /// Enable plaintext HTTP routing for loopback sandbox service URLs.
    #[serde(default)]
    pub enable_loopback_service_http: Option<bool>,

    // ── Shared driver defaults (inherited into [openshell.drivers.<name>]) ─
    #[serde(default)]
    pub default_image: Option<String>,
    #[serde(default)]
    pub supervisor_image: Option<String>,
    #[serde(default)]
    pub client_tls_secret_name: Option<String>,
    #[serde(default)]
    pub host_gateway_ip: Option<String>,
    #[serde(default)]
    pub enable_user_namespaces: Option<bool>,
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

    // ── Disallowed-in-file fields ────────────────────────────────────────
    //
    // Captured so we can produce a friendly "set this via env/CLI instead"
    // error rather than a generic "unknown field" message. Validated and
    // rejected in [`load`].
    #[serde(default)]
    pub database_url: Option<String>,
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
        "unsupported gateway config version {version}; this build only supports version {SCHEMA_VERSION}"
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
}

/// Load and validate a TOML config file.
///
/// Returns `Ok(ConfigFile::default())` for an empty file (the gateway then
/// falls back entirely to CLI/env/built-in defaults).
pub fn load(path: &Path) -> Result<ConfigFile, ConfigFileError> {
    let contents = std::fs::read_to_string(path).map_err(|source| ConfigFileError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if contents.trim().is_empty() {
        return Ok(ConfigFile::default());
    }
    let file: ConfigFile = toml::from_str(&contents).map_err(|source| ConfigFileError::Parse {
        path: path.to_path_buf(),
        source,
    })?;

    if let Some(version) = file.openshell.version
        && version > SCHEMA_VERSION
    {
        return Err(ConfigFileError::UnsupportedVersion { version });
    }

    if file.openshell.gateway.database_url.is_some() {
        return Err(ConfigFileError::SecretInFile {
            field: "database_url",
            env: "OPENSHELL_DB_URL",
            cli: "--db-url",
        });
    }

    Ok(file)
}

/// Build the merged TOML table for `driver` by overlaying inheritable
/// `[openshell.gateway]` defaults onto `[openshell.drivers.<name>]`.
///
/// The returned [`toml::Value`] is a Table ready to feed into the driver's
/// `Deserialize` impl — keys present in `raw` win over the gateway defaults.
/// Keys outside [`inheritable_keys`] for this driver are never copied from
/// the gateway section, which keeps each driver's `deny_unknown_fields`
/// invariant intact.
pub fn driver_table(
    driver: ComputeDriverKind,
    gateway: &GatewayFileSection,
    raw: Option<&toml::Value>,
) -> toml::Value {
    let mut merged = match raw {
        Some(toml::Value::Table(table)) => table.clone(),
        _ => toml::Table::new(),
    };

    for key in inheritable_keys(driver) {
        if merged.contains_key(*key) {
            continue;
        }
        if let Some(value) = gateway_inherited_value(gateway, key) {
            merged.insert((*key).to_string(), value);
        }
    }

    toml::Value::Table(merged)
}

/// Inheritance allowlist (the Q4 "high-overlap set"). Each driver opts in
/// to a specific subset so a gateway-wide default does not accidentally land
/// in a driver table that does not understand the field.
fn inheritable_keys(driver: ComputeDriverKind) -> &'static [&'static str] {
    match driver {
        ComputeDriverKind::Kubernetes => &[
            "namespace",
            "default_image",
            "supervisor_image",
            "client_tls_secret_name",
            "host_gateway_ip",
            "enable_user_namespaces",
        ],
        ComputeDriverKind::Docker => &[
            "sandbox_namespace",
            "default_image",
            "supervisor_image",
            "host_gateway_ip",
            "guest_tls_ca",
            "guest_tls_cert",
            "guest_tls_key",
        ],
        ComputeDriverKind::Podman => &[
            "default_image",
            "supervisor_image",
            "guest_tls_ca",
            "guest_tls_cert",
            "guest_tls_key",
        ],
        ComputeDriverKind::Vm => &[
            "default_image",
            "guest_tls_ca",
            "guest_tls_cert",
            "guest_tls_key",
        ],
    }
}

fn gateway_inherited_value(g: &GatewayFileSection, key: &str) -> Option<toml::Value> {
    match key {
        "namespace" | "sandbox_namespace" => g.sandbox_namespace.as_deref().map(string_value),
        "default_image" => g.default_image.as_deref().map(string_value),
        "supervisor_image" => g.supervisor_image.as_deref().map(string_value),
        "client_tls_secret_name" => g.client_tls_secret_name.as_deref().map(string_value),
        "host_gateway_ip" => g.host_gateway_ip.as_deref().map(string_value),
        "enable_user_namespaces" => g.enable_user_namespaces.map(toml::Value::Boolean),
        "guest_tls_ca" => g.guest_tls_ca.as_deref().map(path_value),
        "guest_tls_cert" => g.guest_tls_cert.as_deref().map(path_value),
        "guest_tls_key" => g.guest_tls_key.as_deref().map(path_value),
        _ => None,
    }
}

fn string_value(s: &str) -> toml::Value {
    toml::Value::String(s.to_owned())
}

fn path_value(p: &Path) -> toml::Value {
    toml::Value::String(p.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(contents: &str) -> tempfile::NamedTempFile {
        let mut tmp = tempfile::Builder::new()
            .suffix(".toml")
            .tempfile()
            .expect("tempfile");
        tmp.write_all(contents.as_bytes()).expect("write");
        tmp
    }

    #[test]
    fn empty_file_yields_default_config() {
        let tmp = write_tmp("");
        let file = load(tmp.path()).expect("empty file parses");
        assert!(file.openshell.version.is_none());
        assert!(file.openshell.gateway.bind_address.is_none());
        assert!(file.openshell.drivers.is_empty());
    }

    #[test]
    fn parses_full_example() {
        let toml = r#"
[openshell]
version = 1

[openshell.gateway]
bind_address = "0.0.0.0:8080"
health_bind_address = "0.0.0.0:8081"
log_level = "info"
compute_drivers = ["kubernetes"]
sandbox_namespace = "agents"
default_image = "ghcr.io/nvidia/openshell/sandbox:latest"
supervisor_image = "ghcr.io/nvidia/openshell/supervisor:latest"
client_tls_secret_name = "openshell-sandbox-tls"

[openshell.gateway.tls]
cert_path = "/etc/openshell/certs/gateway.pem"
key_path = "/etc/openshell/certs/gateway-key.pem"
client_ca_path = "/etc/openshell/certs/client-ca.pem"

[openshell.gateway.oidc]
issuer = "https://idp.example.com/realms/openshell"
audience = "openshell-cli"

[openshell.drivers.kubernetes]
namespace = "agents"
grpc_endpoint = "https://openshell-gateway.agents.svc:8080"
"#;
        let tmp = write_tmp(toml);
        let file = load(tmp.path()).expect("valid file parses");
        let gw = &file.openshell.gateway;
        assert_eq!(gw.log_level.as_deref(), Some("info"));
        assert_eq!(
            gw.default_image.as_deref(),
            Some("ghcr.io/nvidia/openshell/sandbox:latest")
        );
        assert!(gw.tls.is_some());
        assert!(gw.oidc.is_some());
        assert!(file.openshell.drivers.contains_key("kubernetes"));
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
    fn rejects_unsupported_version() {
        let toml = r"
[openshell]
version = 2
";
        let tmp = write_tmp(toml);
        let err = load(tmp.path()).expect_err("version > 1 must be rejected");
        assert!(matches!(
            err,
            ConfigFileError::UnsupportedVersion { version: 2 }
        ));
    }

    #[test]
    fn driver_table_inherits_gateway_defaults() {
        let gateway = GatewayFileSection {
            default_image: Some("ghcr.io/nvidia/openshell/sandbox:0.9".to_string()),
            supervisor_image: Some("ghcr.io/nvidia/openshell/supervisor:0.9".to_string()),
            ..Default::default()
        };
        let raw = toml::toml! {
            namespace = "agents"
        };
        let merged = driver_table(
            ComputeDriverKind::Kubernetes,
            &gateway,
            Some(&toml::Value::Table(raw)),
        );
        let table = merged.as_table().expect("table");
        assert_eq!(
            table.get("namespace").and_then(|v| v.as_str()),
            Some("agents")
        );
        assert_eq!(
            table.get("default_image").and_then(|v| v.as_str()),
            Some("ghcr.io/nvidia/openshell/sandbox:0.9")
        );
        assert_eq!(
            table.get("supervisor_image").and_then(|v| v.as_str()),
            Some("ghcr.io/nvidia/openshell/supervisor:0.9")
        );
    }

    #[test]
    fn docker_driver_table_inherits_gateway_defaults() {
        let gateway = GatewayFileSection {
            sandbox_namespace: Some("agents".to_string()),
            default_image: Some("ghcr.io/nvidia/openshell/sandbox:0.9".to_string()),
            host_gateway_ip: Some("10.0.0.1".to_string()),
            ..Default::default()
        };
        let merged = driver_table(ComputeDriverKind::Docker, &gateway, None);
        let table = merged.as_table().expect("table");
        assert_eq!(
            table.get("sandbox_namespace").and_then(|v| v.as_str()),
            Some("agents")
        );
        assert_eq!(
            table.get("default_image").and_then(|v| v.as_str()),
            Some("ghcr.io/nvidia/openshell/sandbox:0.9")
        );
        assert_eq!(
            table.get("host_gateway_ip").and_then(|v| v.as_str()),
            Some("10.0.0.1")
        );
    }

    #[test]
    fn driver_table_specific_value_overrides_gateway_default() {
        let gateway = GatewayFileSection {
            default_image: Some("gateway-default".to_string()),
            ..Default::default()
        };
        let raw = toml::toml! {
            default_image = "driver-specific"
        };
        let merged = driver_table(
            ComputeDriverKind::Podman,
            &gateway,
            Some(&toml::Value::Table(raw)),
        );
        assert_eq!(
            merged
                .as_table()
                .unwrap()
                .get("default_image")
                .and_then(|v| v.as_str()),
            Some("driver-specific")
        );
    }

    #[test]
    fn driver_table_does_not_leak_keys_outside_allowlist() {
        // `client_tls_secret_name` is K8s-only; Docker must not receive it
        // even when set at gateway scope.
        let gateway = GatewayFileSection {
            client_tls_secret_name: Some("openshell-sandbox-tls".to_string()),
            ..Default::default()
        };
        let merged = driver_table(ComputeDriverKind::Docker, &gateway, None);
        assert!(
            !merged
                .as_table()
                .unwrap()
                .contains_key("client_tls_secret_name")
        );
    }

    #[test]
    fn missing_path_is_io_error() {
        let err = load(Path::new("/nonexistent/openshell-gateway.toml"))
            .expect_err("missing file must be io error");
        assert!(matches!(err, ConfigFileError::Io { .. }));
    }
}
