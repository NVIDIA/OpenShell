// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Launching the VM compute driver through the generic launcher.
//!
//! The gateway reads only the launcher's own keys (`driver_dir`, `state_dir`)
//! from the operator's `[openshell.drivers.vm]` table. The VM driver owns and
//! validates the rest of the table, which the gateway passes through as the
//! startup document's `driver_config`.

use crate::launcher::{self, DriverProcess};
use openshell_core::{Error, NetworkSupervisorTrustBundle, Result};
use openshell_server::AcquiredRemoteDriverEndpoint;
use openshell_server::config_file::OtlpConfig;
use std::path::{Path, PathBuf};

const DRIVER_BIN_NAME: &str = "openshell-driver-vm";
const DRIVER_DIR_KEY: &str = "[openshell.drivers.vm].driver_dir";

/// The launcher's view of `[openshell.drivers.vm]`.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct VmLaunchSettings {
    /// Directory to search for compute-driver binaries before the gateway
    /// falls back to its conventional install paths and sibling binary.
    pub driver_dir: Option<PathBuf>,
    /// Working directory for VM driver state, which holds the private run
    /// directory with the driver socket and startup document.
    pub state_dir: Option<PathBuf>,
}

impl VmLaunchSettings {
    /// Default working directory for VM driver state.
    #[must_use]
    pub fn default_state_dir() -> PathBuf {
        openshell_core::paths::openshell_state_dir().map_or_else(
            |_| PathBuf::from("target/openshell-vm-driver"),
            |dir| dir.join("vm-driver"),
        )
    }

    /// Read the launcher's keys from the operator's driver table.
    ///
    /// # Errors
    ///
    /// Returns an error when `driver_dir` or `state_dir` has the wrong type.
    pub fn from_table(table: &toml::Table) -> Result<Self> {
        let mut settings: Self =
            toml::Value::Table(table.clone())
                .try_into()
                .map_err(|error: toml::de::Error| {
                    Error::config(format!("invalid [openshell.drivers.vm] table: {error}"))
                })?;
        if settings
            .state_dir
            .as_ref()
            .is_none_or(|dir| dir.as_os_str().is_empty())
        {
            settings.state_dir = Some(Self::default_state_dir());
        }
        Ok(settings)
    }

    fn state_dir(&self) -> PathBuf {
        self.state_dir
            .clone()
            .unwrap_or_else(Self::default_state_dir)
    }
}

/// Everything the gateway supplies to launch the VM driver.
pub struct VmLaunch<'a> {
    pub gateway_log_level: &'a str,
    pub gateway_name: &'a str,
    pub gateway_port: u16,
    /// The gateway's `guest_tls_ca`, when it serves TLS.
    pub tls_ca: Option<&'a Path>,
    pub otlp_config: Option<&'a OtlpConfig>,
    pub network_trust: Option<&'a NetworkSupervisorTrustBundle>,
    pub settings: &'a VmLaunchSettings,
    /// The operator's `[openshell.drivers.vm]` table, passed through.
    pub driver_config: toml::Table,
}

/// Launch the VM driver and return a managed endpoint for it.
pub async fn spawn(launch: VmLaunch<'_>) -> Result<AcquiredRemoteDriverEndpoint> {
    let settings = launch.settings;
    let state_dir = settings.state_dir();
    let process = DriverProcess {
        name: "vm",
        binary_name: DRIVER_BIN_NAME,
        driver_dir: settings.driver_dir.as_deref(),
        driver_dir_key: Some(DRIVER_DIR_KEY),
        state_dir: &state_dir,
    };
    let otlp_config = launch.otlp_config;
    launcher::launch(&process, otlp_config, |socket_path| {
        vm_startup_document(launch, socket_path)
    })
    .await
}

/// The VM driver's `[driver_config]`: the operator's table, passed through,
/// without the launcher-owned `driver_dir`.
fn vm_driver_config_table(mut table: toml::Table) -> toml::Table {
    table.remove("driver_dir");
    table
}

fn vm_startup_document(
    launch: VmLaunch<'_>,
    socket_path: &Path,
) -> Result<openshell_driver_sdk::StartupDocument> {
    crate::startup_document::GatewayStartup {
        bind_socket: socket_path,
        log_level: launch.gateway_log_level,
        gateway_name: launch.gateway_name,
        gateway_port: launch.gateway_port,
        tls_ca: launch.tls_ca,
        otlp: launch.otlp_config,
        network_trust: launch.network_trust,
    }
    .into_document(vm_driver_config_table(launch.driver_config))
}

#[cfg(all(test, unix))]
mod tests {
    use super::{VmLaunch, VmLaunchSettings, vm_driver_config_table, vm_startup_document};
    use openshell_core::NetworkSupervisorTrustBundle;
    use openshell_core::sandbox_env::OtlpProtocol;
    use openshell_server::config_file::{
        AgentOtlpConfig, OcsfOtlpConfig, OtlpCollectorConfig, OtlpConfig, OtlpTracesConfig,
    };
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;

    const VM_STARTUP_FIXTURE: &str =
        include_str!("../../openshell-driver-vm/tests/fixtures/startup-vm.toml");

    fn fixture_driver_config() -> toml::Table {
        openshell_driver_sdk::StartupDocument::parse(VM_STARTUP_FIXTURE)
            .unwrap()
            .driver_config
    }

    /// The gateway passes the operator's table through unchanged, apart from
    /// the launcher-owned `driver_dir`, and adds the gateway context the
    /// driver's own tests read from the same fixture.
    #[test]
    fn the_gateway_writes_the_documented_startup_document() {
        let dir = tempdir().unwrap();
        let certified = rcgen::generate_simple_self_signed(vec!["collector".into()]).unwrap();
        let [ca, cert, key] = ["ca.pem", "client.pem", "client-key.pem"].map(|name| {
            let path = dir.path().join(name);
            let pem = if name == "client-key.pem" {
                certified.signing_key.serialize_pem()
            } else {
                certified.cert.pem()
            };
            std::fs::write(&path, pem).unwrap();
            path
        });
        let otlp = OtlpConfig {
            metrics: None,
            service_name: None,
            traces: Some(OtlpTracesConfig {
                collector: OtlpCollectorConfig::new(
                    "https://collector.example:4317",
                    OtlpProtocol::Grpc,
                )
                .with_tls_files(Some(ca), Some(cert), Some(key))
                .unwrap(),
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
        let mut operator_table = fixture_driver_config();
        operator_table.insert("driver_dir".into(), "/usr/libexec/openshell".into());
        let settings = VmLaunchSettings::from_table(&operator_table).unwrap();

        let mut document = vm_startup_document(
            VmLaunch {
                gateway_log_level: "debug",
                gateway_name: "gateway-a",
                gateway_port: 8080,
                tls_ca: Some(Path::new("/etc/openshell/tls/ca.pem")),
                otlp_config: Some(&otlp),
                network_trust: Some(&trust),
                settings: &settings,
                driver_config: operator_table,
            },
            Path::new("/var/lib/openshell/vm/run/compute-driver.sock"),
        )
        .unwrap();

        document.gateway.expected_peer_pid = 4242;
        let tls = document.gateway.telemetry.collector.as_mut().unwrap();
        tls.ca_file = Some("/etc/openshell/otlp/ca.pem".into());
        tls.cert_file = Some("/etc/openshell/otlp/cert.pem".into());
        tls.key_file = Some("/etc/openshell/otlp/key.pem".into());

        let fixture = openshell_driver_sdk::StartupDocument::parse(VM_STARTUP_FIXTURE).unwrap();
        assert_eq!(document, fixture);
    }

    #[test]
    fn only_the_launcher_owned_key_is_removed_from_the_operator_table() {
        let mut table = fixture_driver_config();
        let before = table.clone();
        table.insert("driver_dir".into(), "/opt/drivers".into());
        assert_eq!(vm_driver_config_table(table), before);
    }

    #[test]
    fn launch_settings_default_the_state_dir_and_read_the_driver_dir() {
        let settings = VmLaunchSettings::from_table(&toml::Table::new()).unwrap();
        assert_eq!(settings.state_dir(), VmLaunchSettings::default_state_dir());
        assert!(settings.driver_dir.is_none());

        let table: toml::Table =
            toml::from_str("driver_dir = '/opt/drivers'\nstate_dir = '/var/lib/vm'\nvcpus = 4\n")
                .unwrap();
        let settings = VmLaunchSettings::from_table(&table).unwrap();
        assert_eq!(
            settings.driver_dir.as_deref(),
            Some(Path::new("/opt/drivers"))
        );
        assert_eq!(settings.state_dir(), PathBuf::from("/var/lib/vm"));
    }
}
