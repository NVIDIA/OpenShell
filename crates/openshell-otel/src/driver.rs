// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared compute-driver tracing setup and in-process RPC instrumentation.

use std::future::Future;
use std::pin::Pin;

use futures::Stream;
use tracing::Instrument as _;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;

use crate::{OtlpTraceConfig, SdkTracerProvider, ServiceName, SetupError};

/// Target used by every in-process compute-driver RPC boundary.
pub const IN_PROCESS_COMPUTE_DRIVER_TARGET: &str = "openshell_otel::in_process_compute_driver";

/// Define the calling driver crate's [`ComputeDriverTracing`] identity from
/// its Cargo package and crate names.
#[macro_export]
macro_rules! compute_driver_tracing {
    () => {
        $crate::ComputeDriverTracing::new(env!("CARGO_PKG_NAME"), env!("CARGO_CRATE_NAME"))
    };
}

/// Tracing identity and layer factory for one compute-driver service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComputeDriverTracing {
    service_name: &'static str,
    crate_target_prefix: &'static str,
}

impl ComputeDriverTracing {
    /// `crate_target_prefix` must be the driver's Rust crate name; it routes
    /// that crate's spans to the driver's provider. Prefer
    /// [`compute_driver_tracing!`](crate::compute_driver_tracing).
    #[must_use]
    pub const fn new(service_name: &'static str, crate_target_prefix: &'static str) -> Self {
        Self {
            service_name,
            crate_target_prefix,
        }
    }

    #[must_use]
    pub const fn service_name(self) -> &'static str {
        self.service_name
    }

    /// Canonical compute-driver name derived from `service.name`.
    #[must_use]
    pub fn compute_driver(self) -> &'static str {
        self.service_name
            .strip_prefix("openshell-driver-")
            .unwrap_or(self.service_name)
    }

    #[must_use]
    pub const fn in_process_target(self) -> &'static str {
        IN_PROCESS_COMPUTE_DRIVER_TARGET
    }

    /// Targets routed to this driver's provider when it runs in-process.
    #[must_use]
    pub const fn in_process_targets(self) -> [&'static str; 2] {
        [self.in_process_target(), self.crate_target_prefix]
    }

    #[must_use]
    pub fn provider_for(
        self,
        endpoint: Option<&str>,
        service_version: &'static str,
        gateway_name: Option<&str>,
        compute_driver: Option<&str>,
    ) -> (Option<SdkTracerProvider>, Option<SetupError>) {
        crate::provider_for(endpoint.map(|endpoint| OtlpTraceConfig {
            endpoint,
            service_name: ServiceName::Fixed(self.service_name),
            service_version: Some(service_version),
            resource_attributes: crate::gateway_resource_attributes(gateway_name, compute_driver),
        }))
    }

    pub fn layer<S>(self, provider: &SdkTracerProvider) -> crate::OtlpLayer<S>
    where
        S: tracing::Subscriber + for<'span> LookupSpan<'span>,
    {
        crate::layer(provider, self.service_name)
    }

    pub fn in_process_layer<S>(self, provider: &SdkTracerProvider) -> crate::TargetOtlpLayer<S>
    where
        S: tracing::Subscriber + for<'span> LookupSpan<'span>,
    {
        crate::layer_for_target_prefixes(provider, self.service_name, self.in_process_targets())
    }
}

/// Optional in-process server boundary tracing for a compute-driver service.
#[derive(Debug, Clone, Copy)]
pub struct InProcessRpcTracer {
    enabled: bool,
}

impl InProcessRpcTracer {
    #[must_use]
    pub const fn disabled() -> Self {
        Self { enabled: false }
    }

    #[must_use]
    pub const fn enabled() -> Self {
        Self { enabled: true }
    }

    fn span(self, rpc: crate::ComputeDriverRpc) -> Option<tracing::Span> {
        self.enabled.then(|| {
            tracing::info_span!(
                target: IN_PROCESS_COMPUTE_DRIVER_TARGET,
                "driver_rpc",
                otel.name = rpc.operation,
                otel.kind = "server",
                otel.status_code = tracing::field::Empty,
                rpc.system.name = "grpc",
                rpc.method = rpc.operation,
                rpc.response.status_code = tracing::field::Empty,
                error.type = tracing::field::Empty,
            )
        })
    }

    pub async fn trace<T>(
        self,
        rpc: crate::ComputeDriverRpc,
        future: impl Future<Output = Result<T, tonic::Status>>,
    ) -> Result<T, tonic::Status> {
        let Some(span) = self.span(rpc) else {
            return future.await;
        };
        let result = future.instrument(span.clone()).await;
        record_result(&span, &result);
        result
    }

    pub async fn trace_stream<T>(
        self,
        rpc: crate::ComputeDriverRpc,
        future: impl Future<Output = Result<BoxGrpcStream<T>, tonic::Status>>,
    ) -> Result<BoxGrpcStream<T>, tonic::Status>
    where
        T: 'static,
    {
        let Some(span) = self.span(rpc) else {
            return future.await;
        };
        match future.instrument(span.clone()).await {
            Ok(stream) => Ok(Box::pin(crate::TracedGrpcStream::new(stream, span))),
            Err(status) => {
                crate::record_grpc_status(&span, status.code());
                Err(status)
            }
        }
    }
}

pub type BoxGrpcStream<T> = Pin<Box<dyn Stream<Item = Result<T, tonic::Status>> + Send + 'static>>;

fn record_result<T>(span: &tracing::Span, result: &Result<T, tonic::Status>) {
    crate::record_grpc_status(
        span,
        result
            .as_ref()
            .map_or_else(tonic::Status::code, |_| tonic::Code::Ok),
    );
}

/// Owns and shuts down a standalone compute driver's tracer provider.
pub struct DriverTracingHandle {
    provider: Option<SdkTracerProvider>,
}

/// Named inputs for standalone compute-driver tracing installation.
#[derive(Debug, Clone, Copy)]
pub struct DriverTracingConfig<'a> {
    pub endpoint: Option<&'a str>,
    pub gateway_name: Option<&'a str>,
    pub service_version: &'static str,
    pub log_level: &'a str,
}

impl Drop for DriverTracingHandle {
    fn drop(&mut self) {
        if let Some(provider) = &self.provider
            && let Err(error) = provider.shutdown()
        {
            tracing::warn!(%error, "OTLP tracer provider shutdown failed");
        }
    }
}

/// Install standalone compute-driver logging and OTLP tracing.
#[must_use]
pub fn install_driver_tracing(
    descriptor: ComputeDriverTracing,
    config: DriverTracingConfig<'_>,
) -> DriverTracingHandle {
    let (provider, setup_error) = descriptor.provider_for(
        config.endpoint,
        config.service_version,
        config.gateway_name,
        Some(descriptor.compute_driver()),
    );
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(config.log_level)),
        )
        .with(tracing_subscriber::fmt::layer())
        .with(provider.as_ref().map(|provider| descriptor.layer(provider)))
        .init();

    if let Some(error) = setup_error {
        tracing::error!(%error, "OTLP exporting could not be started");
    } else if let Some(endpoint) = config.endpoint {
        tracing::info!(endpoint, "OTLP exporting enabled");
    }

    DriverTracingHandle { provider }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracing_macro_derives_identity_from_the_calling_crate() {
        const TRACING: ComputeDriverTracing = crate::compute_driver_tracing!();

        assert_eq!(TRACING.service_name(), "openshell-otel");
        assert_eq!(TRACING.in_process_targets()[1], "openshell_otel");
    }

    #[tokio::test]
    async fn disabled_stream_tracing_returns_the_original_box() {
        let stream: BoxGrpcStream<()> = Box::pin(futures::stream::empty());
        let original = std::ptr::from_ref(stream.as_ref().get_ref());

        let returned = InProcessRpcTracer::disabled()
            .trace_stream(crate::rpc::WATCH_SANDBOXES, async move { Ok(stream) })
            .await
            .unwrap();

        assert!(std::ptr::eq(original, returned.as_ref().get_ref()));
    }
}
