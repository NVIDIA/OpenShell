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

pub fn install(
    env_filter: EnvFilter,
    tracing_log_bus: &TracingLogBus,
    otlp_config: Option<&OtlpConfig>,
    driver: Option<openshell_otel::ComputeDriverTracing>,
    gateway: GatewayResourceAttributes<'_>,
) -> (TracingHandle, Option<SetupError>) {
    let (tracer_provider, setup_error) = crate::otel_tracing::provider_for(otlp_config, gateway);
    let driver_endpoint = driver
        .is_some()
        .then_some(otlp_config)
        .flatten()
        .map(|config| config.endpoint.as_str());
    let (driver_tracer_provider, driver_setup_error) = driver.map_or_else(
        || (None, None),
        |descriptor| {
            descriptor.provider_for(
                driver_endpoint,
                openshell_core::VERSION,
                gateway.name(),
                gateway.compute_driver(),
            )
        },
    );
    let (jsonl_layer, jsonl_dir) = build_ocsf_jsonl_layer();

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_log_bus.layer())
        .with(jsonl_layer)
        .with(
            tracer_provider
                .as_ref()
                .map(|provider| crate::otel_tracing::layer(provider, driver)),
        )
        .with(driver_tracer_provider.as_ref().map(|provider| {
            driver
                .expect("a driver provider requires a selected driver")
                .in_process_layer(provider)
        }))
        .init();

    if let Some(dir) = jsonl_dir {
        tracing::info!(
            target: "openshell_server",
            ocsf_jsonl_dir = %dir.display(),
            "OCSF JSONL audit log enabled (openshell-ocsf.<date>.log, daily rotation, keep 3)"
        );
    } else {
        tracing::debug!(
            target: "openshell_server",
            "OCSF JSONL audit log disabled"
        );
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
    let disabled = std::env::var("OPENSHELL_OCSF_JSON").is_ok_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        )
    });
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
