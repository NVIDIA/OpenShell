// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-wide tracing subscriber setup for the gateway.
//!
//! This module routes gateway logs and spans to configured diagnostic outputs.
//! `OpenShell` product telemetry collected for maintainers is handled by
//! [`crate::telemetry`].

use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::{FilterExt, filter_fn};
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

fn filter_from(directives: &str) -> EnvFilter {
    EnvFilter::try_new(directives).unwrap_or_else(|_| EnvFilter::new("info"))
}

struct GatewayEventFormat;

impl<S, N> tracing_subscriber::fmt::FormatEvent<S, N> for GatewayEventFormat
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'a> tracing_subscriber::fmt::FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        context: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: tracing_subscriber::fmt::format::Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        if event.metadata().target() == openshell_ocsf::OCSF_TARGET
            && let Some(ocsf) = openshell_ocsf::clone_current_event()
        {
            return writeln!(
                writer,
                "{} OCSF {}",
                chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ"),
                ocsf.format_shorthand()
            );
        }
        tracing_subscriber::fmt::format().format_event(context, writer, event)
    }
}

pub fn install(
    filter_directives: &str,
    tracing_log_bus: &TracingLogBus,
    ocsf_log: Option<&crate::ocsf_log::OcsfLog>,
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

    tracing_subscriber::registry()
        .with(
            ocsf_log
                .map(crate::ocsf_log::OcsfLog::layer)
                .with_filter(filter_fn(|metadata| {
                    metadata.target() == openshell_ocsf::OCSF_TARGET
                })),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .event_format(GatewayEventFormat)
                .with_filter(filter_from(filter_directives)),
        )
        .with(
            tracing_log_bus
                .layer()
                .with_filter(filter_from(filter_directives).or(filter_fn(|metadata| {
                    metadata.target() == openshell_ocsf::OCSF_TARGET
                }))),
        )
        .with(
            tracer_provider
                .as_ref()
                .map(|provider| crate::otel_tracing::layer(provider, driver))
                .with_filter(filter_from(filter_directives)),
        )
        .with(
            driver_tracer_provider
                .as_ref()
                .map(|provider| {
                    driver
                        .expect("a driver provider requires a selected driver")
                        .in_process_layer(provider)
                })
                .with_filter(filter_from(filter_directives)),
        )
        .init();

    (
        TracingHandle {
            tracer_provider,
            driver_tracer_provider,
        },
        setup_error.or(driver_setup_error),
    )
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek};

    use super::*;

    #[test]
    fn gateway_ocsf_console_preserves_details_without_jsonl() {
        let file = tempfile::tempfile().unwrap();
        let reader = file.try_clone().unwrap();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .event_format(GatewayEventFormat)
                .with_ansi(false)
                .with_writer(std::sync::Arc::new(file))
                .with_filter(filter_from("info")),
        );
        let event =
            openshell_ocsf::ConfigStateChangeBuilder::new(&crate::gateway_ocsf::context("", ""))
                .message("TLS certificate config reloaded successfully")
                .build();
        let expected = event.format_shorthand();
        tracing::subscriber::with_default(subscriber, || {
            openshell_ocsf::ocsf_emit!(event);
            tracing::info!(answer = 42, "ordinary diagnostic");
        });
        let mut reader = reader;
        reader.rewind().unwrap();
        let mut output = String::new();
        reader.read_to_string(&mut output).unwrap();
        assert!(output.contains(&expected), "missing OCSF details: {output}");
        assert!(!output.contains("ocsf_event"));
        assert!(output.contains("ordinary diagnostic"));
        assert!(output.contains("answer=42"));
        assert_eq!(output.lines().count(), 2);
    }
}
