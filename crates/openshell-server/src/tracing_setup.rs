// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-wide tracing subscriber setup for the gateway.
//!
//! This module routes gateway logs and spans to configured diagnostic outputs.
//! `OpenShell` product telemetry collected for maintainers is handled by
//! [`crate::telemetry`].

use openshell_ocsf::OcsfJsonlLayer;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

use crate::ConfiguredComputeDriver;
use crate::config_file::OtlpConfig;
use crate::otel_tracing::{GatewayResourceAttributes, SetupError};
use crate::tracing_bus::TracingLogBus;

pub struct TracingHandle {
    tracer_provider: Option<SdkTracerProvider>,
    driver_tracer_provider: Option<SdkTracerProvider>,
}

impl TracingHandle {
    pub fn shutdown(&self) {
        if let Some(provider) = &self.tracer_provider
            && let Err(err) = provider.shutdown()
        {
            tracing::warn!(error = %err, "OTLP tracer provider shutdown failed");
        }
        if let Some(provider) = &self.driver_tracer_provider
            && let Err(err) = provider.shutdown()
        {
            tracing::warn!(error = %err, "compute-driver OTLP tracer provider shutdown failed");
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InProcessDriverTracing {
    #[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
    Docker,
    #[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
    Kubernetes,
    #[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
    Podman,
}

impl InProcessDriverTracing {
    #[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
    fn target_prefix(self) -> &'static str {
        match self {
            Self::Docker => openshell_driver_docker::otel_tracing::IN_PROCESS_TARGET_PREFIX,
            Self::Kubernetes => openshell_driver_kubernetes::otel_tracing::IN_PROCESS_TARGET_PREFIX,
            Self::Podman => openshell_driver_podman::otel_tracing::IN_PROCESS_TARGET_PREFIX,
        }
    }
}

fn in_process_driver_tracing(driver: &ConfiguredComputeDriver) -> Option<InProcessDriverTracing> {
    #[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
    match driver {
        ConfiguredComputeDriver::Registered(registration) if registration.name == "docker" => {
            Some(InProcessDriverTracing::Docker)
        }
        ConfiguredComputeDriver::Registered(registration) if registration.name == "podman" => {
            Some(InProcessDriverTracing::Podman)
        }
        ConfiguredComputeDriver::Registered(registration) if registration.name == "kubernetes" => {
            Some(InProcessDriverTracing::Kubernetes)
        }
        _ => None,
    }
    #[cfg(not(all(not(target_os = "windows"), feature = "in-tree-compute-drivers")))]
    {
        let _ = driver;
        None
    }
}

fn in_process_driver_target_prefix(driver: Option<InProcessDriverTracing>) -> Option<&'static str> {
    #[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
    {
        driver.map(InProcessDriverTracing::target_prefix)
    }
    #[cfg(not(all(not(target_os = "windows"), feature = "in-tree-compute-drivers")))]
    {
        let _ = driver;
        None
    }
}

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
fn in_process_driver_provider(
    driver: Option<InProcessDriverTracing>,
    endpoint: Option<&str>,
    gateway_name: Option<&str>,
) -> (Option<SdkTracerProvider>, Option<SetupError>) {
    match driver {
        Some(InProcessDriverTracing::Docker) => {
            openshell_driver_docker::otel_tracing::provider_for(endpoint, gateway_name)
        }
        Some(InProcessDriverTracing::Kubernetes) => {
            openshell_driver_kubernetes::otel_tracing::provider_for(endpoint, gateway_name)
        }
        Some(InProcessDriverTracing::Podman) => {
            openshell_driver_podman::otel_tracing::provider_for(endpoint, gateway_name)
        }
        None => (None, None),
    }
}

#[cfg(not(all(not(target_os = "windows"), feature = "in-tree-compute-drivers")))]
fn in_process_driver_provider(
    _driver: Option<InProcessDriverTracing>,
    _endpoint: Option<&str>,
    _gateway_name: Option<&str>,
) -> (Option<SdkTracerProvider>, Option<SetupError>) {
    (None, None)
}

#[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
fn in_process_driver_layer<S>(
    provider: &Option<SdkTracerProvider>,
    driver: Option<InProcessDriverTracing>,
) -> Option<openshell_otel::TargetOtlpLayer<S>>
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    provider.as_ref().map(|provider| match driver {
        Some(InProcessDriverTracing::Docker) => {
            openshell_driver_docker::otel_tracing::in_process_layer(provider)
        }
        Some(InProcessDriverTracing::Kubernetes) => {
            openshell_driver_kubernetes::otel_tracing::in_process_layer(provider)
        }
        Some(InProcessDriverTracing::Podman) => {
            openshell_driver_podman::otel_tracing::in_process_layer(provider)
        }
        None => unreachable!("a driver provider requires a selected driver"),
    })
}

#[cfg(not(all(not(target_os = "windows"), feature = "in-tree-compute-drivers")))]
fn in_process_driver_layer<S>(
    _provider: &Option<SdkTracerProvider>,
    _driver: Option<InProcessDriverTracing>,
) -> Option<openshell_otel::TargetOtlpLayer<S>>
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    None
}

pub fn install(
    env_filter: EnvFilter,
    tracing_log_bus: &TracingLogBus,
    otlp_config: Option<&OtlpConfig>,
    driver: &ConfiguredComputeDriver,
    gateway: GatewayResourceAttributes<'_>,
) -> (TracingHandle, Option<SetupError>) {
    let (tracer_provider, setup_error) = crate::otel_tracing::provider_for(otlp_config, gateway);
    let selected_driver = in_process_driver_tracing(driver);
    let driver_endpoint = selected_driver
        .is_some()
        .then_some(otlp_config)
        .flatten()
        .map(|config| config.endpoint.as_str());
    let (driver_tracer_provider, driver_setup_error) =
        in_process_driver_provider(selected_driver, driver_endpoint, gateway.name());
    let (jsonl_layer, jsonl_dir) = build_ocsf_jsonl_layer();

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_log_bus.layer())
        .with(jsonl_layer)
        .with(tracer_provider.as_ref().map(|provider| {
            crate::otel_tracing::layer_excluding_driver(
                provider,
                in_process_driver_target_prefix(selected_driver),
            )
        }))
        .with(in_process_driver_layer(
            &driver_tracer_provider,
            selected_driver,
        ))
        .init();

    match jsonl_dir {
        Some(dir) => tracing::info!(
            target: "openshell_server",
            ocsf_jsonl_dir = %dir.display(),
            "OCSF JSONL audit log enabled (openshell-ocsf.<date>.log, daily rotation, keep 3)"
        ),
        None => tracing::debug!(
            target: "openshell_server",
            "OCSF JSONL audit log disabled"
        ),
    }

    (
        TracingHandle {
            tracer_provider,
            driver_tracer_provider,
        },
        setup_error.or(driver_setup_error),
    )
}

/// Build the OCSF JSONL audit layer for the gateway, plus the directory it
/// writes into (for a one-line startup log). Returns `(None, None)` when
/// disabled via `OPENSHELL_OCSF_JSON` or when the target directory/appender
/// cannot be opened.
///
/// The appender is *synchronous* (not wrapped in `tracing_appender::non_blocking`)
/// so each event is written straight through to the OS on emit. This trades a
/// little throughput for durability: unlike the sandbox supervisor (which flushes
/// its non-blocking guard on graceful shutdown), the gateway's ETW capture path
/// can be force-killed by the harness, and we do not want to lose the tail of the
/// audit trail.
fn build_ocsf_jsonl_layer() -> (
    Option<OcsfJsonlLayer<tracing_appender::rolling::RollingFileAppender>>,
    Option<std::path::PathBuf>,
) {
    let disabled = std::env::var("OPENSHELL_OCSF_JSON")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "off" | "no"
            )
        })
        .unwrap_or(false);
    if disabled {
        return (None, None);
    }

    let dir = ocsf_log_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!(
            "openshell: could not create OCSF JSONL log dir {}: {e}",
            dir.display()
        );
        return (None, None);
    }

    match tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("openshell-ocsf")
        .filename_suffix("log")
        .max_log_files(3)
        .build(&dir)
    {
        Ok(roller) => (Some(OcsfJsonlLayer::new(roller)), Some(dir)),
        Err(e) => {
            eprintln!(
                "openshell: could not open OCSF JSONL appender in {}: {e}",
                dir.display()
            );
            (None, None)
        }
    }
}

/// Resolve the directory for the OCSF JSONL audit file.
///
/// Precedence: `OPENSHELL_OCSF_LOG_DIR` (harness / operator override) →
/// `%PROGRAMDATA%\OpenShell\logs` on Windows → `/var/log` elsewhere.
fn ocsf_log_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("OPENSHELL_OCSF_LOG_DIR") {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            return std::path::PathBuf::from(trimmed);
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(pd) = std::env::var("ProgramData") {
            return std::path::PathBuf::from(pd).join("OpenShell").join("logs");
        }
        std::env::temp_dir().join("openshell").join("logs")
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::path::PathBuf::from("/var/log")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(not(target_os = "windows"), feature = "in-tree-compute-drivers"))]
    #[test]
    fn in_process_driver_tracing_selects_registered_compute_drivers() {
        let registry = crate::install_default_compute_drivers();
        let registered = |name| {
            ConfiguredComputeDriver::Registered(
                registry
                    .get(name)
                    .unwrap_or_else(|| panic!("{name} driver is registered"))
                    .clone(),
            )
        };
        assert_eq!(
            in_process_driver_tracing(&registered("podman")),
            Some(InProcessDriverTracing::Podman)
        );
        assert_eq!(
            in_process_driver_tracing(&registered("docker")),
            Some(InProcessDriverTracing::Docker)
        );
        assert_eq!(
            in_process_driver_tracing(&registered("kubernetes")),
            Some(InProcessDriverTracing::Kubernetes)
        );
        assert_eq!(
            in_process_driver_tracing(&ConfiguredComputeDriver::Remote {
                name: "custom".to_string(),
            }),
            None
        );
    }
}
