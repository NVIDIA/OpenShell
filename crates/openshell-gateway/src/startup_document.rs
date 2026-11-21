// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builds the startup document the gateway passes to a launched driver.
//!
//! The document types live in `openshell-driver-sdk`, which shares none of the
//! gateway's configuration types. This module is the single place that
//! converts the gateway's resolved configuration into them.

use std::path::Path;

use openshell_core::{Error, NetworkSupervisorTrustBundle, Result};
use openshell_driver_sdk as sdk;
use openshell_server::config_file::OtlpConfig;

/// Resolved gateway values a launched driver needs.
pub struct GatewayStartup<'a> {
    pub bind_socket: &'a Path,
    pub log_level: &'a str,
    pub gateway_name: &'a str,
    pub gateway_port: u16,
    /// The gateway's `guest_tls_ca`, when the driver should use it.
    pub tls_ca: Option<&'a Path>,
    pub otlp: Option<&'a OtlpConfig>,
    pub network_trust: Option<&'a NetworkSupervisorTrustBundle>,
}

impl GatewayStartup<'_> {
    /// Combine the gateway context with the selected driver's `driver_config`
    /// table, which the gateway passes through without interpreting.
    ///
    /// # Errors
    ///
    /// Returns an error when the trust bundle's certificate count does not fit
    /// the document.
    pub fn into_document(self, driver_config: toml::Table) -> Result<sdk::StartupDocument> {
        let supervisor_otlp = self
            .otlp
            .map(OtlpConfig::supervisor_otlp)
            .unwrap_or_default();
        let network_trust = self
            .network_trust
            .map(|bundle| {
                Ok::<_, Error>(sdk::NetworkTrust {
                    path: bundle.artifact_path().to_path_buf(),
                    digest: bundle.digest().to_string(),
                    certificate_count: u32::try_from(bundle.certificate_count()).map_err(|_| {
                        Error::config("network trust bundle has too many certificates")
                    })?,
                })
            })
            .transpose()?;

        let gateway = sdk::GatewayContext {
            bind_socket: self.bind_socket.to_path_buf(),
            expected_peer_pid: std::process::id(),
            log_level: self.log_level.to_string(),
            gateway_name: self.gateway_name.to_string(),
            gateway_port: self.gateway_port,
            tls_ca: self.tls_ca.map(Path::to_path_buf),
            telemetry: sdk::Telemetry {
                traces: supervisor_otlp.traces,
                ocsf: supervisor_otlp.ocsf,
                agent: supervisor_otlp.agent,
                collector: self.otlp.and_then(collector_tls),
            },
            network_trust,
        };
        Ok(sdk::StartupDocument::new(gateway, driver_config))
    }
}

/// TLS file paths for the trace collector, as the VM launch forwards them. The
/// other lanes use their own collectors and are not covered by these paths.
fn collector_tls(otlp: &OtlpConfig) -> Option<sdk::CollectorTls> {
    let collector = &otlp.traces.as_ref()?.collector;
    let tls = sdk::CollectorTls {
        ca_file: collector.ca_file().map(Path::to_path_buf),
        cert_file: collector.cert_file().map(Path::to_path_buf),
        key_file: collector.key_file().map(Path::to_path_buf),
    };
    (tls != sdk::CollectorTls::default()).then_some(tls)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::sandbox_env::OtlpProtocol;
    use openshell_server::config_file::{
        AgentOtlpConfig, OcsfOtlpConfig, OtlpCollectorConfig, OtlpTracesConfig,
    };
    use std::path::PathBuf;

    fn collector_with_tls(dir: &Path) -> OtlpCollectorConfig {
        let certified = rcgen::generate_simple_self_signed(vec!["collector".into()]).unwrap();
        let [ca, cert, key] = ["ca.pem", "client.pem", "client-key.pem"].map(|name| {
            let path = dir.join(name);
            let pem = if name == "client-key.pem" {
                certified.signing_key.serialize_pem()
            } else {
                certified.cert.pem()
            };
            std::fs::write(&path, pem).unwrap();
            path
        });
        OtlpCollectorConfig::new("https://collector.example:4317", OtlpProtocol::Grpc)
            .with_tls_files(Some(ca), Some(cert), Some(key))
            .unwrap()
    }

    /// Every field the gateway can resolve is set, so a field added to the
    /// document and left out of the conversion shows up as a difference from
    /// the fixture.
    #[test]
    fn a_fully_populated_gateway_converts_to_the_golden_fixture() {
        let dir = tempfile::tempdir().unwrap();
        let otlp = OtlpConfig {
            metrics: None,
            service_name: None,
            traces: Some(OtlpTracesConfig {
                collector: collector_with_tls(dir.path()),
            }),
            ocsf: Some(OcsfOtlpConfig {
                collector: OtlpCollectorConfig::new(
                    "https://collector.example:4318",
                    OtlpProtocol::HttpProtobuf,
                ),
                schema_version: None,
            }),
            agent: Some(AgentOtlpConfig {
                collector: OtlpCollectorConfig::new(
                    "https://collector.example:4319",
                    OtlpProtocol::Grpc,
                ),
            }),
        };
        let trust = NetworkSupervisorTrustBundle::new(
            b"pem".to_vec(),
            3,
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            PathBuf::from("/var/lib/openshell/trust/bundle.pem"),
        );
        let driver_config: toml::Table = toml::from_str(
            "state_dir = \"/var/lib/openshell/vm\"\nvcpus = 2\n[nested]\nkey = \"value\"\n",
        )
        .unwrap();

        let mut document = GatewayStartup {
            bind_socket: Path::new("/var/lib/openshell/run/compute-driver.sock"),
            log_level: "info",
            gateway_name: "gateway-a",
            gateway_port: 8080,
            tls_ca: Some(Path::new("/etc/openshell/tls/ca.pem")),
            otlp: Some(&otlp),
            network_trust: Some(&trust),
        }
        .into_document(driver_config)
        .unwrap();

        // The gateway's own pid and the temporary TLS file locations are the
        // only values that differ from the committed fixture.
        assert_eq!(document.gateway.expected_peer_pid, std::process::id());
        document.gateway.expected_peer_pid = 4242;
        let tls = document.gateway.telemetry.collector.as_mut().unwrap();
        for (path, fixed) in [
            (&mut tls.ca_file, "/etc/openshell/otlp/ca.pem"),
            (&mut tls.cert_file, "/etc/openshell/otlp/cert.pem"),
            (&mut tls.key_file, "/etc/openshell/otlp/key.pem"),
        ] {
            assert!(path.as_deref().unwrap().starts_with(dir.path()));
            *path = Some(fixed.into());
        }

        let fixture = sdk::StartupDocument::parse(include_str!(
            "../../openshell-driver-sdk/tests/fixtures/startup-v1.toml"
        ))
        .unwrap();
        assert_eq!(document, fixture);
    }

    #[test]
    fn an_unconfigured_gateway_omits_optional_settings() {
        let document = GatewayStartup {
            bind_socket: Path::new("/run/driver.sock"),
            log_level: "debug",
            gateway_name: "gateway",
            gateway_port: 8080,
            tls_ca: None,
            otlp: None,
            network_trust: None,
        }
        .into_document(toml::Table::new())
        .unwrap();

        let text = document.to_toml().unwrap();
        for absent in ["telemetry", "network_trust", "tls_ca"] {
            assert!(
                !text.contains(absent),
                "{absent} should be omitted:\n{text}"
            );
        }
        assert!(document.driver_config.is_empty());
    }

    #[test]
    fn the_document_carries_trust_artifact_metadata_not_certificate_bytes() {
        let trust = NetworkSupervisorTrustBundle::new(
            b"private-fixture-bytes".to_vec(),
            1,
            "sha256:abc",
            PathBuf::from("/var/lib/openshell/trust/bundle.pem"),
        );
        let text = GatewayStartup {
            bind_socket: Path::new("/run/driver.sock"),
            log_level: "info",
            gateway_name: "gateway",
            gateway_port: 8080,
            tls_ca: None,
            otlp: None,
            network_trust: Some(&trust),
        }
        .into_document(toml::Table::new())
        .unwrap()
        .to_toml()
        .unwrap();
        assert!(!text.contains("private-fixture-bytes"));
        assert!(text.contains("sha256:abc"));
    }
}
