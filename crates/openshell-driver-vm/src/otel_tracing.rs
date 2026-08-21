// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenTelemetry trace exporting.

use http::Request;
use openshell_otel::{
    HeaderMapExtractor, OtlpTraceConfig, RecordGrpcFailure, RecordGrpcStatus, SdkTracerProvider,
    ServiceName, SetupError,
};
use opentelemetry::propagation::TextMapPropagator;
use opentelemetry::trace::TraceContextExt as _;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tower_http::trace::{GrpcMakeClassifier, MakeSpan, TraceLayer};
use tracing::{Span, Subscriber};
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use tracing_subscriber::registry::LookupSpan;

const SERVICE_NAME: &str = "openshell-driver-vm";
const INSTRUMENTATION_SCOPE: &str = "openshell-driver-vm";
const COMPUTE_DRIVER_SERVICE: &str = "openshell.compute.v1.ComputeDriver";

/// Trace every inbound compute-driver RPC at the tonic service boundary.
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

/// Creates the server span for an inbound compute-driver request.
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

fn compute_driver_rpc_operation(path: &str) -> (&'static str, &'static str) {
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
        _ => ("driver.unknown", "unknown"),
    }
}

/// Build a tracer provider for the configured OTLP/gRPC endpoint.
#[must_use]
pub fn provider_for(endpoint: Option<&str>) -> (Option<SdkTracerProvider>, Option<SetupError>) {
    openshell_otel::provider_for(endpoint.map(|endpoint| OtlpTraceConfig {
        endpoint,
        service_name: ServiceName::Fixed(SERVICE_NAME),
        service_version: Some(openshell_core::VERSION),
        resource_attributes: Vec::new(),
    }))
}

/// Build the tracing layer that exports VM-driver spans.
pub fn layer<S>(provider: &SdkTracerProvider) -> openshell_otel::OtlpLayer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    openshell_otel::layer(provider, INSTRUMENTATION_SCOPE)
}

#[cfg(test)]
mod tests {
    use openshell_otel_test_support::OtlpTestServer;
    use tracing_subscriber::layer::SubscriberExt as _;

    #[test]
    fn compute_driver_rpc_names_are_explicitly_mapped_and_schema_bounded() {
        for (rpc, operation, method) in [
            (
                "GetCapabilities",
                "driver.get_capabilities",
                "get_capabilities",
            ),
            (
                "GetGatewayListenerRequirements",
                "driver.get_gateway_listener_requirements",
                "get_gateway_listener_requirements",
            ),
            (
                "ValidateSandboxCreate",
                "driver.validate_sandbox_create",
                "validate_sandbox_create",
            ),
            ("CreateSandbox", "driver.create_sandbox", "create_sandbox"),
            ("GetSandbox", "driver.get_sandbox", "get_sandbox"),
            ("ListSandboxes", "driver.list_sandboxes", "list_sandboxes"),
            ("StopSandbox", "driver.stop_sandbox", "stop_sandbox"),
            ("StartSandbox", "driver.start_sandbox", "start_sandbox"),
            ("DeleteSandbox", "driver.delete_sandbox", "delete_sandbox"),
            (
                "WatchSandboxes",
                "driver.watch_sandboxes",
                "watch_sandboxes",
            ),
        ] {
            assert_eq!(
                super::compute_driver_rpc_operation(&format!(
                    "/openshell.compute.v1.ComputeDriver/{rpc}"
                )),
                (operation, method),
                "{rpc} must keep an explicit low-cardinality span identity"
            );
        }
        assert_eq!(
            super::compute_driver_rpc_operation(
                "/openshell.compute.v1.ComputeDriver/AttackerControlled12345"
            ),
            ("driver.unknown", "unknown"),
            "paths absent from the protobuf schema must not create span names"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn vm_driver_spans_reach_otlp_collector_with_distinct_service_name() {
        let collector = OtlpTestServer::start().await;

        let (provider, error) = super::provider_for(Some(collector.endpoint()));
        assert!(error.is_none(), "valid OTLP endpoint should configure");
        let provider = provider.expect("provider");
        let subscriber = tracing_subscriber::registry().with(super::layer(&provider));
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("vm.provision", sandbox.id = "sb-otlp");
            drop(span.enter());
            drop(span);
        });
        provider.force_flush().unwrap();
        collector.wait_for_export().await;
        provider.shutdown().unwrap();
        let received = collector.shutdown().await;

        received
            .spans
            .iter()
            .find(|span| span.name == "vm.provision")
            .expect("VM span should reach collector");
        assert!(
            received
                .service_names
                .iter()
                .any(|name| name == "openshell-driver-vm"),
            "VM spans should use a distinct service name, got {:?}",
            received.service_names
        );
    }
}
