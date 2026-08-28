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

use crate::config_file::OtlpConfig;
use crate::otel_tracing::GatewayResourceAttributes;
use crate::tracing_bus::TracingLogBus;
use crate::{ComputeDriverTracingSetup, ComputeDriverTracingShutdown};

pub struct TracingHandle {
    tracer_provider: Option<SdkTracerProvider>,
    compute_driver_shutdown: Option<ComputeDriverTracingShutdown>,
}

impl TracingHandle {
    pub fn shutdown(&self) {
        if let Some(provider) = &self.tracer_provider
            && let Err(err) = provider.shutdown()
        {
            tracing::warn!(error = %err, "OTLP tracer provider shutdown failed");
        }
        if let Some(shutdown) = &self.compute_driver_shutdown
            && let Err(err) = shutdown()
        {
            tracing::warn!(error = %err, "Compute driver tracing shutdown failed");
        }
    }
}

pub fn install(
    env_filter: EnvFilter,
    tracing_log_bus: &TracingLogBus,
    otlp_config: Option<&OtlpConfig>,
    compute_driver_tracing: ComputeDriverTracingSetup,
    gateway: GatewayResourceAttributes<'_>,
) -> (TracingHandle, Option<String>) {
    let (tracer_provider, setup_error) = crate::otel_tracing::provider_for(otlp_config, gateway);
    let ComputeDriverTracingSetup {
        layer,
        shutdown,
        error,
        target_prefix,
    } = compute_driver_tracing;

    tracing_subscriber::registry()
        .with(layer)
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_log_bus.layer())
        .with(
            tracer_provider
                .as_ref()
                .map(|provider| crate::otel_tracing::layer(provider, target_prefix)),
        )
        .init();

    (
        TracingHandle {
            tracer_provider,
            compute_driver_shutdown: shutdown,
        },
        setup_error.map(|error| error.to_string()).or(error),
    )
}
