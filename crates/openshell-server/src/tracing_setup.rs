// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-wide tracing subscriber setup for the gateway.
//!
//! This module routes gateway logs and spans to configured diagnostic outputs.
//! `OpenShell` product telemetry collected for maintainers is handled by
//! [`crate::telemetry`].

use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

use crate::ConfiguredComputeDriver;
use crate::config_file::OtlpConfig;
use crate::otel_tracing::SetupError;
use crate::tracing_bus::TracingLogBus;

pub struct TracingHandle {
    tracer_provider: Option<SdkTracerProvider>,
    podman_tracer_provider: Option<SdkTracerProvider>,
}

impl TracingHandle {
    pub fn shutdown(&self) {
        if let Some(provider) = &self.tracer_provider
            && let Err(err) = provider.shutdown()
        {
            tracing::warn!(error = %err, "OTLP tracer provider shutdown failed");
        }
        if let Some(provider) = &self.podman_tracer_provider
            && let Err(err) = provider.shutdown()
        {
            tracing::warn!(error = %err, "Podman OTLP tracer provider shutdown failed");
        }
    }
}

#[must_use]
pub fn podman_export_enabled(driver: &ConfiguredComputeDriver) -> bool {
    matches!(
        driver,
        ConfiguredComputeDriver::Builtin(openshell_core::ComputeDriverKind::Podman)
    )
}

pub fn install(
    env_filter: EnvFilter,
    tracing_log_bus: &TracingLogBus,
    otlp_config: Option<&OtlpConfig>,
    enable_podman_export: bool,
) -> (TracingHandle, Option<SetupError>) {
    let (tracer_provider, setup_error) = crate::otel_tracing::provider_for(otlp_config);
    let podman_endpoint = enable_podman_export
        .then_some(otlp_config)
        .flatten()
        .map(|config| config.endpoint.as_str());
    let (podman_tracer_provider, podman_setup_error) =
        openshell_driver_podman::otel_tracing::provider_for(podman_endpoint);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_log_bus.layer())
        .with(tracer_provider.as_ref().map(crate::otel_tracing::layer))
        .with(
            podman_tracer_provider
                .as_ref()
                .map(openshell_driver_podman::otel_tracing::in_process_layer),
        )
        .init();

    (
        TracingHandle {
            tracer_provider,
            podman_tracer_provider,
        },
        setup_error.or(podman_setup_error),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn podman_export_is_enabled_only_when_podman_is_selected() {
        use crate::ConfiguredComputeDriver;
        use openshell_core::ComputeDriverKind;

        assert!(podman_export_enabled(&ConfiguredComputeDriver::Builtin(
            ComputeDriverKind::Podman
        )));
        assert!(!podman_export_enabled(&ConfiguredComputeDriver::Builtin(
            ComputeDriverKind::Docker
        )));
        assert!(!podman_export_enabled(&ConfiguredComputeDriver::Builtin(
            ComputeDriverKind::Kubernetes
        )));
        assert!(!podman_export_enabled(&ConfiguredComputeDriver::Remote {
            name: "custom".to_string(),
        }));
    }
}
