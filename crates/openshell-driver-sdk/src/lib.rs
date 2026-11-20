// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Contract between the `OpenShell` gateway and the compute drivers it launches.
//!
//! The gateway writes one [`StartupDocument`] and passes its path to the driver
//! with `--config <path>`. The document has a `schema_version`, a fixed
//! [`GatewayContext`], and the operator's `driver_config` table, which the
//! gateway does not interpret.
//!
//! This crate defines its own types and depends on neither `openshell-core`
//! nor the gateway, so operator-facing configuration changes never change the
//! contract and drivers in other repositories can use it on its own.
//!
//! # Versioning
//!
//! [`SCHEMA_VERSION`] must change whenever a change would make an existing
//! document fail to parse or change its meaning. A driver accepts exactly the
//! version it was built with, and [`StartupDocument::parse`] checks the version
//! before decoding the rest, so a mismatch reports both versions instead of an
//! unrelated field error.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Schema version this crate reads and writes.
pub const SCHEMA_VERSION: u32 = 1;

/// Largest document [`StartupDocument::parse`] accepts, in bytes.
pub const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// Reasons a startup document cannot be read or written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DocumentError {
    #[error("startup document is {size} bytes, over the {limit} byte limit")]
    TooLarge { size: usize, limit: usize },
    #[error("startup document is not valid TOML: {0}")]
    Syntax(String),
    #[error("startup document has no integer `schema_version`")]
    MissingSchemaVersion,
    #[error("startup document schema version {document}, this driver supports {supported}")]
    UnsupportedSchemaVersion { document: i64, supported: u32 },
    #[error("startup document is invalid: {0}")]
    Invalid(String),
    #[error("startup document cannot be serialized: {0}")]
    Serialize(String),
}

/// The document the gateway passes to a launched driver.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartupDocument {
    pub schema_version: u32,
    pub gateway: GatewayContext,
    /// The selected driver's `driver_config` table, opaque to the gateway.
    /// The driver deserializes and validates it.
    #[serde(default)]
    pub driver_config: toml::Table,
}

impl StartupDocument {
    /// Build a document at the current [`SCHEMA_VERSION`].
    #[must_use]
    pub fn new(gateway: GatewayContext, driver_config: toml::Table) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            gateway,
            driver_config,
        }
    }

    /// Parse a document, refusing oversized input and any schema version other
    /// than [`SCHEMA_VERSION`].
    ///
    /// # Errors
    ///
    /// Returns [`DocumentError`] when the input is too large, is not TOML,
    /// names an unsupported version, or does not match the schema.
    pub fn parse(text: &str) -> Result<Self, DocumentError> {
        if text.len() > MAX_DOCUMENT_BYTES {
            return Err(DocumentError::TooLarge {
                size: text.len(),
                limit: MAX_DOCUMENT_BYTES,
            });
        }
        let table: toml::Table =
            toml::from_str(text).map_err(|error| DocumentError::Syntax(error.to_string()))?;
        let document = table
            .get("schema_version")
            .and_then(toml::Value::as_integer)
            .ok_or(DocumentError::MissingSchemaVersion)?;
        if document != i64::from(SCHEMA_VERSION) {
            return Err(DocumentError::UnsupportedSchemaVersion {
                document,
                supported: SCHEMA_VERSION,
            });
        }
        toml::Value::Table(table)
            .try_into()
            .map_err(|error: toml::de::Error| DocumentError::Invalid(error.to_string()))
    }

    /// Render the document as TOML.
    ///
    /// # Errors
    ///
    /// Returns [`DocumentError::Serialize`] when the document cannot be
    /// represented as TOML.
    pub fn to_toml(&self) -> Result<String, DocumentError> {
        toml::to_string(self).map_err(|error| DocumentError::Serialize(error.to_string()))
    }
}

/// Settings the gateway resolves for every launched driver.
///
/// Scalars come before tables so the value serializes as valid TOML.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayContext {
    /// Unix socket the driver binds for the gateway's `ComputeDriver` channel.
    pub bind_socket: PathBuf,
    /// Process id of the gateway, which the driver expects on its socket.
    pub expected_peer_pid: u32,
    pub log_level: String,
    pub gateway_name: String,
    /// CA certificate the gateway's TLS endpoints chain to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ca: Option<PathBuf>,
    pub admission: Admission,
    #[serde(default, skip_serializing_if = "Telemetry::is_empty")]
    pub telemetry: Telemetry,
    #[serde(default, skip_serializing_if = "UpstreamProxy::is_empty")]
    pub upstream_proxy: UpstreamProxy,
    /// Staged network trust artifact. Only its location and identity cross the
    /// process boundary, never the certificate bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_trust: Option<NetworkTrust>,
}

/// Resource admission policy the driver must apply and acknowledge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    pub allow_driver_config: bool,
    pub resource_admission: ResourceAdmission,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceAdmission {
    pub enabled: bool,
    pub required_labels: BTreeMap<String, String>,
}

/// OTLP exports the driver and the supervisors it starts must use.
///
/// Export headers are secrets and are not part of the document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Telemetry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traces: Option<OtlpExport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ocsf: Option<OtlpExport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<OtlpExport>,
    /// TLS material for the trace collector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collector: Option<CollectorTls>,
}

impl Telemetry {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OtlpExport {
    pub endpoint: String,
    pub protocol: OtlpProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OtlpProtocol {
    #[serde(rename = "grpc")]
    Grpc,
    #[serde(rename = "http/protobuf")]
    HttpProtobuf,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorTls {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_file: Option<PathBuf>,
}

/// Corporate forward proxy the driver reaches the network through.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamProxy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub https_proxy: Option<String>,
    /// Comma-separated bypass list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_proxy: Option<String>,
    /// Path to a `user:pass` credential file, not the credential itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub auth_allow_insecure: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub connect_by_hostname: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_bundle: Option<PathBuf>,
}

impl UpstreamProxy {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Location and identity of the staged network trust bundle.
///
/// The driver reads the file, verifies it against `digest` and
/// `certificate_count`, and keeps its own snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkTrust {
    pub path: PathBuf,
    pub digest: String,
    pub certificate_count: u32,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's `skip_serializing_if` passes a reference.
fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../tests/fixtures/startup-v1.toml");

    fn minimal_gateway() -> GatewayContext {
        GatewayContext {
            bind_socket: "/run/driver.sock".into(),
            expected_peer_pid: 1,
            log_level: "info".into(),
            gateway_name: "gateway".into(),
            tls_ca: None,
            admission: Admission {
                allow_driver_config: false,
                resource_admission: ResourceAdmission {
                    enabled: false,
                    required_labels: BTreeMap::new(),
                },
            },
            telemetry: Telemetry::default(),
            upstream_proxy: UpstreamProxy::default(),
            network_trust: None,
        }
    }

    /// Removing or renaming a field fails here: the fixture lists every field,
    /// and `deny_unknown_fields` rejects any the types no longer define. A
    /// field the types define but the fixture omits does not fail this test, so
    /// the fixture must keep every optional field populated.
    #[test]
    fn fixture_round_trips_without_losing_fields() {
        let document = StartupDocument::parse(FIXTURE).expect("fixture parses");
        let written = document.to_toml().expect("document serializes");

        let original: toml::Table = toml::from_str(FIXTURE).unwrap();
        let round_tripped: toml::Table = toml::from_str(&written).unwrap();
        assert_eq!(original, round_tripped);
        assert_eq!(StartupDocument::parse(&written).unwrap(), document);
    }

    #[test]
    fn driver_config_passes_through_unchanged() {
        let document = StartupDocument::parse(FIXTURE).unwrap();
        assert_eq!(document.driver_config["vcpus"].as_integer(), Some(2));
        assert_eq!(
            document.driver_config["nested"]["key"].as_str(),
            Some("value")
        );
    }

    #[test]
    fn minimal_document_omits_unset_optional_tables() {
        let text = StartupDocument::new(minimal_gateway(), toml::Table::new())
            .to_toml()
            .unwrap();
        for absent in ["telemetry", "upstream_proxy", "network_trust", "tls_ca"] {
            assert!(
                !text.contains(absent),
                "{absent} should be omitted:\n{text}"
            );
        }
        assert_eq!(
            StartupDocument::parse(&text).unwrap().gateway,
            minimal_gateway()
        );
    }

    #[test]
    fn refuses_other_schema_version_naming_both() {
        let text = FIXTURE.replace("schema_version = 1", "schema_version = 2");
        let error = StartupDocument::parse(&text).unwrap_err();
        assert_eq!(
            error,
            DocumentError::UnsupportedSchemaVersion {
                document: 2,
                supported: SCHEMA_VERSION
            }
        );
        let message = error.to_string();
        assert!(message.contains('2') && message.contains(&SCHEMA_VERSION.to_string()));
    }

    #[test]
    fn version_is_checked_before_the_rest_is_decoded() {
        let text = "schema_version = 99\n[gateway]\nfuture_field = true\n";
        assert!(matches!(
            StartupDocument::parse(text),
            Err(DocumentError::UnsupportedSchemaVersion { document: 99, .. })
        ));
    }

    #[test]
    fn refuses_missing_schema_version() {
        assert_eq!(
            StartupDocument::parse("[gateway]\n").unwrap_err(),
            DocumentError::MissingSchemaVersion
        );
    }

    #[test]
    fn refuses_unknown_gateway_field() {
        let text = FIXTURE.replace("[gateway]\n", "[gateway]\nsurprise = true\n");
        assert!(matches!(
            StartupDocument::parse(&text),
            Err(DocumentError::Invalid(_))
        ));
    }

    #[test]
    fn refuses_oversized_document() {
        let text = format!("# {}\n", "x".repeat(MAX_DOCUMENT_BYTES));
        assert!(matches!(
            StartupDocument::parse(&text),
            Err(DocumentError::TooLarge { .. })
        ));
    }

    #[test]
    fn refuses_invalid_toml() {
        assert!(matches!(
            StartupDocument::parse("schema_version = ["),
            Err(DocumentError::Syntax(_))
        ));
    }
}
