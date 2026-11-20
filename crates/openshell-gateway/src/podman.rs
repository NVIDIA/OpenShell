// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Launching the Podman compute driver through the generic launcher.
//!
//! The gateway passes the operator's `[openshell.drivers.podman]` table through
//! unchanged as the startup document's `driver_config`. The Podman driver
//! deserializes and validates it.

use crate::launcher::{self, DriverProcess};
use openshell_core::{NetworkSupervisorTrustBundle, Result};
use openshell_server::AcquiredRemoteDriverEndpoint;
use openshell_server::config_file::OtlpConfig;
use std::path::{Path, PathBuf};

const DRIVER_BIN_NAME: &str = "openshell-driver-podman";

/// Everything the gateway supplies to launch the Podman driver.
pub struct PodmanLaunch<'a> {
    pub gateway_log_level: &'a str,
    pub gateway_name: &'a str,
    pub gateway_port: u16,
    /// The gateway's `guest_tls_ca`, when it serves TLS.
    pub tls_ca: Option<&'a Path>,
    pub otlp_config: Option<&'a OtlpConfig>,
    pub network_trust: Option<&'a NetworkSupervisorTrustBundle>,
    /// The operator's `[openshell.drivers.podman]` table, passed through.
    pub driver_config: toml::Table,
}

/// Directory whose `run/` subdirectory holds the driver socket and startup
/// document.
#[must_use]
pub fn default_state_dir() -> PathBuf {
    openshell_core::paths::openshell_state_dir().map_or_else(
        |_| PathBuf::from("target/openshell-podman-driver"),
        |dir| dir.join("podman-driver"),
    )
}

/// Launch the Podman driver and return a managed endpoint for it.
pub async fn spawn(launch: PodmanLaunch<'_>) -> Result<AcquiredRemoteDriverEndpoint> {
    let state_dir = default_state_dir();
    let process = DriverProcess {
        name: "podman",
        binary_name: DRIVER_BIN_NAME,
        driver_dir: None,
        driver_dir_key: None,
        state_dir: &state_dir,
    };
    let otlp_config = launch.otlp_config;
    launcher::launch(&process, otlp_config, |socket_path| {
        podman_startup_document(launch, socket_path)
    })
    .await
}

fn podman_startup_document(
    launch: PodmanLaunch<'_>,
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
    .into_document(launch.driver_config)
}

#[cfg(all(test, unix))]
mod tests {
    use super::{PodmanLaunch, podman_startup_document};
    use openshell_core::NetworkSupervisorTrustBundle;
    use openshell_core::sandbox_env::OtlpProtocol;
    use openshell_server::config_file::{OtlpCollectorConfig, OtlpConfig, OtlpTracesConfig};
    use std::path::{Path, PathBuf};

    const FIXTURE: &str =
        include_str!("../../openshell-driver-podman/tests/fixtures/startup-podman.toml");

    /// The gateway passes the operator's table through unchanged and adds the
    /// gateway context the driver's own tests read from the same fixture.
    #[test]
    fn the_gateway_writes_the_documented_startup_document() {
        let fixture = openshell_driver_sdk::StartupDocument::parse(FIXTURE).unwrap();
        let otlp = OtlpConfig {
            metrics: None,
            service_name: None,
            traces: Some(OtlpTracesConfig {
                collector: OtlpCollectorConfig::new(
                    "https://collector.example:4317",
                    OtlpProtocol::Grpc,
                ),
            }),
            ocsf: None,
            agent: None,
        };
        let trust = NetworkSupervisorTrustBundle::new(
            b"pem".to_vec(),
            3,
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            PathBuf::from("/var/lib/openshell/trust/bundle.pem"),
        );

        let mut document = podman_startup_document(
            PodmanLaunch {
                gateway_log_level: "debug",
                gateway_name: "gateway-a",
                gateway_port: 8080,
                tls_ca: None,
                otlp_config: Some(&otlp),
                network_trust: Some(&trust),
                driver_config: fixture.driver_config.clone(),
            },
            Path::new("/var/lib/openshell/podman-driver/run/compute-driver.sock"),
        )
        .unwrap();
        document.gateway.expected_peer_pid = 4242;

        assert_eq!(document, fixture);
    }
}
