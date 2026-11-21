// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Building the Podman driver configuration from the gateway startup document.
//!
//! The document's `[driver_config]` table is the operator's
//! `[openshell.drivers.podman]` table, passed through unchanged. The driver
//! deserializes it into [`PodmanComputeConfig`], applies the gateway context,
//! and validates the result before it starts.

use openshell_core::NetworkSupervisorTrustBundle;
use openshell_driver_sdk::StartupDocument;

use crate::PodmanComputeConfig;

/// Environment variable that overrides the Podman API socket path.
pub const PODMAN_SOCKET_ENV: &str = "OPENSHELL_PODMAN_SOCKET";

/// Build and validate the driver configuration and the network trust bundle
/// from a startup document.
///
/// # Errors
///
/// Returns a message when `driver_config` is invalid, validation fails, or the
/// staged network trust artifact cannot be loaded and verified.
pub fn config_from_document(
    document: &StartupDocument,
) -> Result<(PodmanComputeConfig, Option<NetworkSupervisorTrustBundle>), String> {
    let gateway = &document.gateway;
    let mut config: PodmanComputeConfig = toml::Value::Table(document.driver_config.clone())
        .try_into()
        .map_err(|error: toml::de::Error| {
            format!("invalid [driver_config] in startup document: {error}")
        })?;

    config.gateway_port = gateway.gateway_port;
    config.supervisor_otlp = gateway.telemetry.supervisor_otlp();
    config.supervisor_gateway_name = Some(gateway.gateway_name.clone());
    if config.guest_tls_ca.is_none() {
        config.guest_tls_ca.clone_from(&gateway.tls_ca);
    }
    apply_environment(&mut config, |name| std::env::var(name).ok());
    config
        .validate_configuration()
        .map_err(|error| error.to_string())?;

    let trust = gateway
        .network_trust
        .as_ref()
        .map(|trust| {
            let count = usize::try_from(trust.certificate_count)
                .map_err(|_| "network trust certificate count is too large".to_string())?;
            openshell_driver_sdk::network_trust::load_staged_bundle(
                &trust.path,
                &trust.digest,
                count,
            )
        })
        .transpose()?;
    Ok((config, trust))
}

/// Environment overrides the gateway applied to an in-process driver. A
/// launched driver inherits the gateway's environment, so it applies them here.
fn apply_environment(
    config: &mut PodmanComputeConfig,
    environment: impl Fn(&str) -> Option<String>,
) {
    if let Some(image) = environment(openshell_core::config::SANDBOX_RUNTIME_IMAGE_ENV) {
        config.sandbox_runtime_image = image;
    }
    if let Some(image) = environment(openshell_core::config::SUPERVISOR_IMAGE_ENV) {
        config.supervisor_image = image;
    }
    if let Some(path) = environment(PODMAN_SOCKET_ENV) {
        config.socket_path = Some(path.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../tests/fixtures/startup-podman.toml");

    fn document() -> StartupDocument {
        StartupDocument::parse(FIXTURE).unwrap()
    }

    #[test]
    fn the_fixture_builds_a_validated_configuration() {
        let (config, trust) = {
            // The trust artifact does not exist here, so exercise the driver
            // configuration without it.
            let mut document = document();
            document.gateway.network_trust = None;
            config_from_document(&document).unwrap()
        };
        assert!(trust.is_none());
        assert_eq!(config.gateway_port, 8080);
        assert_eq!(config.supervisor_gateway_name.as_deref(), Some("gateway-a"));
        assert_eq!(config.network_name, "openshell-test");
        assert!(config.allow_driver_config);
        assert_eq!(
            config
                .supervisor_otlp
                .traces
                .as_ref()
                .map(|t| t.endpoint.as_str()),
            Some("https://collector.example:4317")
        );
        assert!(config.guest_tls_ca.is_none());
    }

    #[test]
    fn the_gateway_ca_is_used_when_the_driver_table_sets_none() {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, "ca").unwrap();
        let mut document = document();
        document.gateway.network_trust = None;
        document.gateway.tls_ca = Some(ca.clone());
        let (config, _) = config_from_document(&document).unwrap();
        assert_eq!(config.guest_tls_ca.as_deref(), Some(ca.as_path()));
    }

    #[test]
    fn unknown_driver_config_keys_are_rejected() {
        let mut document = document();
        document.gateway.network_trust = None;
        document.driver_config = toml::from_str("surprise = 1").unwrap();
        let error = config_from_document(&document).unwrap_err();
        assert!(error.contains("surprise"), "{error}");
    }

    #[test]
    fn the_environment_overrides_configured_images_and_socket() {
        let mut config = PodmanComputeConfig::default();
        apply_environment(&mut config, |name| match name {
            openshell_core::config::SANDBOX_RUNTIME_IMAGE_ENV => Some("runtime:env".into()),
            openshell_core::config::SUPERVISOR_IMAGE_ENV => Some("supervisor:env".into()),
            PODMAN_SOCKET_ENV => Some("/run/podman.sock".into()),
            _ => None,
        });
        assert_eq!(config.sandbox_runtime_image, "runtime:env");
        assert_eq!(config.supervisor_image, "supervisor:env");
        assert_eq!(
            config.socket_path.as_deref(),
            Some(std::path::Path::new("/run/podman.sock"))
        );
    }
}
