// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenTelemetry trace exporting for the Docker compute driver.

use http::Request;
use openshell_otel::{
    HeaderMapExtractor, OtlpTraceConfig, RecordGrpcFailure, RecordGrpcStatus, SdkTracerProvider,
    ServiceName, SetupError,
};
use opentelemetry::propagation::TextMapPropagator as _;
use opentelemetry::trace::TraceContextExt as _;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tower_http::trace::{GrpcMakeClassifier, MakeSpan, TraceLayer};
use tracing::{Span, Subscriber};
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use tracing_subscriber::registry::LookupSpan;

const SERVICE_NAME: &str = "openshell-driver-docker";
const INSTRUMENTATION_SCOPE: &str = "openshell-driver-docker";
const COMPUTE_DRIVER_SERVICE: &str = "openshell.compute.v1.ComputeDriver";
pub const IN_PROCESS_TARGET_PREFIX: &str = "openshell_driver_docker";

/// Trace inbound standalone compute-driver RPCs and continue gateway context.
pub fn compute_driver_rpc_layer() -> TraceLayer<
    GrpcMakeClassifier,
    ComputeDriverRpcSpan,
    (),
    RecordGrpcStatus,
    (),
    RecordGrpcStatus,
    RecordGrpcFailure,
> {
    TraceLayer::new_for_grpc()
        .make_span_with(ComputeDriverRpcSpan)
        .on_request(())
        .on_response(RecordGrpcStatus)
        .on_body_chunk(())
        .on_eos(RecordGrpcStatus)
        .on_failure(RecordGrpcFailure)
}

#[derive(Debug, Clone, Copy)]
pub struct ComputeDriverRpcSpan;

impl<B> MakeSpan<B> for ComputeDriverRpcSpan {
    fn make_span(&mut self, request: &Request<B>) -> Span {
        let (operation, method) = compute_driver_rpc_operation(request.uri().path());
        let span = tracing::info_span!(
            "driver_rpc",
            otel.name = operation,
            otel.kind = "server",
            otel.status_code = tracing::field::Empty,
            rpc.system = "grpc",
            rpc.service = COMPUTE_DRIVER_SERVICE,
            rpc.method = method,
            rpc.grpc.status_code = tracing::field::Empty,
        );
        let parent = TraceContextPropagator::new().extract_with_context(
            &opentelemetry::Context::new(),
            &HeaderMapExtractor::new(request.headers()),
        );
        if parent.span().span_context().is_valid() {
            let _ = span.set_parent(parent);
        }
        span
    }
}

pub(crate) fn compute_driver_rpc_operation(path: &str) -> (&'static str, &'static str) {
    match path.rsplit('/').next() {
        Some("GetCapabilities") => ("driver.get_capabilities", "get_capabilities"),
        Some("GetGatewayListenerRequirements") => (
            "driver.get_gateway_listener_requirements",
            "get_gateway_listener_requirements",
        ),
        Some("ValidateSandboxCreate") => {
            ("driver.validate_sandbox_create", "validate_sandbox_create")
        }
        Some("CreateSandbox") => ("driver.create_sandbox", "create_sandbox"),
        Some("GetSandbox") => ("driver.get_sandbox", "get_sandbox"),
        Some("ListSandboxes") => ("driver.list_sandboxes", "list_sandboxes"),
        Some("StopSandbox") => ("driver.stop_sandbox", "stop_sandbox"),
        Some("StartSandbox") => ("driver.start_sandbox", "start_sandbox"),
        Some("DeleteSandbox") => ("driver.delete_sandbox", "delete_sandbox"),
        Some("WatchSandboxes") => ("driver.watch_sandboxes", "watch_sandboxes"),
        Some("EnsureWorkspace") => ("driver.ensure_workspace", "ensure_workspace"),
        Some("DeleteWorkspace") => ("driver.delete_workspace", "delete_workspace"),
        _ => ("driver.unknown", "unknown"),
    }
}

/// Build a tracer provider for the configured OTLP/gRPC endpoint and gateway.
#[must_use]
pub fn provider_for(
    endpoint: Option<&str>,
    gateway_name: Option<&str>,
) -> (Option<SdkTracerProvider>, Option<SetupError>) {
    openshell_otel::provider_for(endpoint.map(|endpoint| {
        OtlpTraceConfig {
            endpoint,
            service_name: ServiceName::Fixed(SERVICE_NAME),
            service_version: Some(openshell_core::VERSION),
            resource_attributes: gateway_name
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(|name| {
                    vec![opentelemetry::KeyValue::new(
                        "openshell.gateway.name",
                        name.to_string(),
                    )]
                })
                .unwrap_or_default(),
        }
    }))
}

pub fn layer<S>(provider: &SdkTracerProvider) -> openshell_otel::OtlpLayer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    openshell_otel::layer(provider, INSTRUMENTATION_SCOPE)
}

pub fn in_process_layer<S>(provider: &SdkTracerProvider) -> openshell_otel::TargetOtlpLayer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    openshell_otel::layer_for_target_prefix(
        provider,
        INSTRUMENTATION_SCOPE,
        IN_PROCESS_TARGET_PREFIX,
    )
}

#[cfg(test)]
pub(crate) async fn test_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    static INITIALIZED: std::sync::LazyLock<()> = std::sync::LazyLock::new(|| {
        tracing::subscriber::set_global_default(tracing_subscriber::registry())
            .expect("test tracing subscriber installs once");
    });

    let guard = LOCK.lock().await;
    std::sync::LazyLock::force(&INITIALIZED);
    guard
}

#[cfg(test)]
mod tests {
    use openshell_otel_test_support::OtlpTestServer;
    use tracing_subscriber::layer::SubscriberExt as _;

    #[test]
    fn compute_driver_rpc_names_are_explicitly_mapped_and_schema_bounded() {
        assert_eq!(
            super::compute_driver_rpc_operation(
                "/openshell.compute.v1.ComputeDriver/CreateSandbox"
            ),
            ("driver.create_sandbox", "create_sandbox")
        );
        assert_eq!(
            super::compute_driver_rpc_operation("/openshell.compute.v1.ComputeDriver/FutureMethod"),
            ("driver.unknown", "unknown")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tracing_docker_driver_spans_reach_otlp_collector_with_resource_identity() {
        let _tracing_lock = super::test_lock().await;
        let collector = OtlpTestServer::start().await;

        let (provider, error) = super::provider_for(Some(collector.endpoint()), Some("docker-dev"));
        assert!(error.is_none());
        let provider = provider.expect("provider");
        let subscriber = tracing_subscriber::registry().with(super::layer(&provider));
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("docker.schedule_sandbox", sandbox.id = "sb-otlp");
            drop(span.enter());
            drop(span);
        });
        provider.force_flush().unwrap();
        collector.wait_for_export().await;
        provider.shutdown().unwrap();
        let received = collector.shutdown().await;

        assert!(
            received
                .spans
                .iter()
                .any(|span| span.name == "docker.schedule_sandbox")
        );
        assert_eq!(received.gateway_names, ["docker-dev"]);
        assert!(
            received
                .service_names
                .iter()
                .any(|name| name == "openshell-driver-docker")
        );
    }
}
