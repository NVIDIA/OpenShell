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
    let (jsonl_layer, jsonl_dir) = build_ocsf_jsonl_layer(gateway.compute_driver());

    // Keep the audit sink independent from the operator's diagnostic log
    // level. An explicit JSONL opt-in must keep every OCSF event even when the
    // console and routed diagnostic logs are restricted to `warn` or `error`.
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_filter(env_filter.clone()))
        .with(tracing_log_bus.layer().with_filter(env_filter.clone()))
        .with(jsonl_layer)
        .with(
            tracer_provider
                .as_ref()
                .map(|provider| crate::otel_tracing::layer(provider, driver))
                .with_filter(env_filter.clone()),
        )
        .with(
            driver_tracer_provider
                .as_ref()
                .map(|provider| {
                    driver
                        .expect("a driver provider requires a selected driver")
                        .in_process_layer(provider)
                })
                .with_filter(env_filter),
        )
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
/// the target is not Windows, the selected compute driver is not MXC, the sink
/// was not explicitly enabled through `OPENSHELL_OCSF_JSON`, or the target
/// directory/appender cannot be opened.
///
/// The appender is *synchronous* (not wrapped in `tracing_appender::non_blocking`)
/// so each event is written straight through to the OS on emit. This trades a
/// little throughput for durability: unlike the sandbox supervisor (which flushes
/// its non-blocking guard on graceful shutdown), the gateway's ETW capture path
/// can be force-killed by the harness, and we do not want to lose the tail of the
/// audit trail.
#[cfg(not(target_os = "windows"))]
fn build_ocsf_jsonl_layer(
    _compute_driver: Option<&str>,
) -> (
    Option<OcsfJsonlLayer<tracing_appender::rolling::RollingFileAppender>>,
    Option<std::path::PathBuf>,
) {
    // The gateway-local JSONL sink belongs to the Windows/MXC ETW path. A
    // cross-platform sink needs an explicit storage and configuration contract.
    (None, None)
}

#[cfg(target_os = "windows")]
fn build_ocsf_jsonl_layer(
    compute_driver: Option<&str>,
) -> (
    Option<OcsfJsonlLayer<tracing_appender::rolling::RollingFileAppender>>,
    Option<std::path::PathBuf>,
) {
    let requested = std::env::var("OPENSHELL_OCSF_JSON").ok();
    if !mxc_ocsf_jsonl_requested(compute_driver, requested.as_deref()) {
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

/// Whether this gateway explicitly requested the Windows/MXC JSONL sink.
/// Unknown values fail closed so a typo cannot unexpectedly retain audit data.
#[cfg(any(target_os = "windows", test))]
fn mxc_ocsf_jsonl_requested(compute_driver: Option<&str>, value: Option<&str>) -> bool {
    compute_driver == Some("mxc")
        && value.is_some_and(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "on" | "yes"
            )
        })
}

/// Resolve the directory for the OCSF JSONL audit file.
///
/// Precedence: `OPENSHELL_OCSF_LOG_DIR` (harness / operator override) then
/// `%PROGRAMDATA%\OpenShell\logs`.
#[cfg(target_os = "windows")]
fn ocsf_log_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("OPENSHELL_OCSF_LOG_DIR") {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            return std::path::PathBuf::from(trimmed);
        }
    }
    if let Ok(pd) = std::env::var("ProgramData") {
        return std::path::PathBuf::from(pd).join("OpenShell").join("logs");
    }
    std::env::temp_dir().join("openshell").join("logs")
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use openshell_ocsf::{
        AppLifecycleBuilder, OcsfJsonlLayer, SandboxContext, emit_ocsf_event_routed,
    };
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::prelude::*;

    use super::mxc_ocsf_jsonl_requested;

    #[derive(Clone)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn diagnostic_filter_does_not_suppress_ocsf_jsonl() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::sink)
                    .with_filter(EnvFilter::new("warn")),
            )
            .with(OcsfJsonlLayer::new(SharedWriter(output.clone())));
        let ctx = SandboxContext {
            sandbox_id: "sandbox-filter-test".into(),
            sandbox_name: "filter-test".into(),
            container_image: String::new(),
            hostname: "gateway-host".into(),
            product_version: openshell_core::VERSION.into(),
            proxy_ip: "127.0.0.1".parse().unwrap(),
            proxy_port: 0,
        };

        tracing::subscriber::with_default(subscriber, || {
            emit_ocsf_event_routed(
                "sandbox-filter-test",
                AppLifecycleBuilder::new(&ctx).build(),
            );
        });

        assert!(
            !output.lock().unwrap().is_empty(),
            "warn-level diagnostic filtering must not suppress informational audit records"
        );
    }

    #[test]
    fn gateway_ocsf_jsonl_requires_explicit_opt_in() {
        assert!(!mxc_ocsf_jsonl_requested(Some("mxc"), None));
        assert!(!mxc_ocsf_jsonl_requested(Some("mxc"), Some("")));
        assert!(!mxc_ocsf_jsonl_requested(Some("mxc"), Some("enabled")));
        for value in ["0", "false", "FALSE", " off ", "no"] {
            assert!(!mxc_ocsf_jsonl_requested(Some("mxc"), Some(value)));
        }

        for value in ["1", "true", "TRUE", " on ", "yes"] {
            assert!(
                mxc_ocsf_jsonl_requested(Some("mxc"), Some(value)),
                "expected {value:?} to opt in"
            );
        }
    }

    #[test]
    fn gateway_ocsf_jsonl_rejects_non_mxc_drivers() {
        for driver in [
            None,
            Some("docker"),
            Some("kubernetes"),
            Some("podman"),
            Some("vm"),
        ] {
            assert!(!mxc_ocsf_jsonl_requested(driver, Some("1")));
        }
    }
}
