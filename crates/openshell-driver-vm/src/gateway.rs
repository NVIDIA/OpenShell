// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Optional adapter from the standalone VM driver to the gateway registry.

use crate::{VmComputeConfig, spawn_managed_vm_driver};
use openshell_core::telemetry::TelemetryComputeDriver;
use openshell_core::{Error, Result};
use openshell_server::{
    ComputeDriverBuildContext, ComputeDriverConfigContext, ComputeDriverFactory,
    ComputeDriverInstance, ComputeDriverRegistration, connect_managed_compute_driver,
};
use std::path::{Path, PathBuf};

const DRIVER_NAME: &str = "vm";

/// Build the VM driver's self-contained gateway registration.
pub fn gateway_registration() -> Result<ComputeDriverRegistration> {
    ComputeDriverRegistration::new(DRIVER_NAME, u16::MAX, None, VmFactory).map(|registration| {
        registration
            .with_telemetry_category(TelemetryComputeDriver::anonymous_category(DRIVER_NAME))
            .with_local_singleplayer()
    })
}

#[derive(Clone, Copy)]
struct VmFactory;

#[async_trait::async_trait]
impl ComputeDriverFactory for VmFactory {
    fn supports_config_preflight(&self) -> bool {
        true
    }

    fn validate_config(&self, context: ComputeDriverConfigContext<'_>) -> Result<()> {
        let mut config = vm_config(context)?;
        apply_default_grpc_endpoint(
            &mut config,
            context.gateway_tls_enabled(),
            context.gateway_port(),
        );
        config.validate_configuration()
    }

    async fn build(&self, context: ComputeDriverBuildContext<'_>) -> Result<ComputeDriverInstance> {
        let mut config = vm_config(context.config_context())?;
        require_guest_tls(&context)?;
        if !context.gateway_tls_enabled() || context.guest_tls_paths().is_some() {
            apply_default_grpc_endpoint(
                &mut config,
                context.gateway_tls_enabled(),
                context.gateway_port(),
            );
        }
        apply_guest_tls(
            &mut config.guest_tls_ca,
            &mut config.guest_tls_cert,
            &mut config.guest_tls_key,
            context.guest_tls_paths(),
        );
        let launch = spawn_managed_vm_driver(
            context.gateway_log_level(),
            context.gateway_name(),
            &config,
            context.otlp_config().map(|config| config.endpoint.as_str()),
        )?;
        let (child, socket_path) = launch.into_parts();
        let endpoint = connect_managed_compute_driver(DRIVER_NAME, socket_path, child)
            .await
            .map_err(|error| Error::execution(error.to_string()))?;
        Ok(ComputeDriverInstance::ManagedRemote(endpoint))
    }
}

fn vm_config(context: ComputeDriverConfigContext<'_>) -> Result<VmComputeConfig> {
    let mut config: VmComputeConfig = context.driver_config()?;
    if config.state_dir.as_os_str().is_empty() {
        config.state_dir = VmComputeConfig::default_state_dir();
    }
    Ok(config)
}

fn apply_default_grpc_endpoint(config: &mut VmComputeConfig, tls_enabled: bool, port: u16) {
    if config.grpc_endpoint.trim().is_empty() {
        let scheme = if tls_enabled { "https" } else { "http" };
        config.grpc_endpoint = format!("{scheme}://127.0.0.1:{port}");
    }
}

fn require_guest_tls(context: &ComputeDriverBuildContext<'_>) -> Result<()> {
    if context.gateway_tls_enabled() && context.guest_tls_paths().is_none() {
        return Err(Error::config(format!(
            "gateway TLS requires guest_tls_ca, guest_tls_cert, and guest_tls_key in [openshell.gateway] when using the {DRIVER_NAME} compute driver"
        )));
    }
    Ok(())
}

fn apply_guest_tls(
    ca: &mut Option<PathBuf>,
    cert: &mut Option<PathBuf>,
    key: &mut Option<PathBuf>,
    defaults: Option<(&Path, &Path, &Path)>,
) {
    if ca.is_none()
        && cert.is_none()
        && key.is_none()
        && let Some((default_ca, default_cert, default_key)) = defaults
    {
        *ca = Some(default_ca.to_owned());
        *cert = Some(default_cert.to_owned());
        *key = Some(default_key.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::apply_guest_tls;
    use std::path::{Path, PathBuf};

    #[test]
    fn package_managed_guest_bundle_is_injected_when_driver_paths_are_absent() {
        let mut ca = None;
        let mut cert = None;
        let mut key = None;
        apply_guest_tls(
            &mut ca,
            &mut cert,
            &mut key,
            Some((
                Path::new("ca.pem"),
                Path::new("client.pem"),
                Path::new("client-key.pem"),
            )),
        );

        assert_eq!(ca, Some(PathBuf::from("ca.pem")));
        assert_eq!(cert, Some(PathBuf::from("client.pem")));
        assert_eq!(key, Some(PathBuf::from("client-key.pem")));
    }
}
