// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared gRPC tracing adapters.

use http::Request;
use opentelemetry::propagation::TextMapPropagator as _;
use opentelemetry::trace::TraceContextExt as _;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tower_http::classify::GrpcFailureClass;
use tower_http::trace::{GrpcMakeClassifier, MakeSpan, OnEos, OnFailure, OnResponse, TraceLayer};
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

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

/// Creates a bounded server span for an inbound compute-driver request.
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
            &crate::HeaderMapExtractor::new(request.headers()),
        );
        if parent.span().span_context().is_valid() {
            let _ = span.set_parent(parent);
        }
        span
    }
}

/// Maps the generated compute-driver RPC schema to low-cardinality span names.
pub fn compute_driver_rpc_operation(path: &str) -> (&'static str, &'static str) {
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

/// Records a non-OK gRPC outcome on the request span.
#[derive(Debug, Clone, Copy)]
pub struct RecordGrpcFailure;

impl OnFailure<GrpcFailureClass> for RecordGrpcFailure {
    fn on_failure(
        &mut self,
        failure: GrpcFailureClass,
        _latency: std::time::Duration,
        span: &Span,
    ) {
        crate::mark_error(span);
        if let GrpcFailureClass::Code(code) = failure {
            span.record("rpc.grpc.status_code", code.get());
        }
    }
}

/// Records a gRPC status from response headers or trailers.
#[derive(Debug, Clone, Copy)]
pub struct RecordGrpcStatus;

impl RecordGrpcStatus {
    fn record(headers: &http::HeaderMap, span: &Span) {
        let Some(code) = headers
            .get("grpc-status")
            .and_then(|status| status.to_str().ok())
            .and_then(|status| status.parse::<i32>().ok())
        else {
            return;
        };
        if code != tonic::Code::Ok as i32 {
            crate::mark_error(span);
        }
        span.record("rpc.grpc.status_code", code);
    }
}

impl<B> OnResponse<B> for RecordGrpcStatus {
    fn on_response(self, response: &http::Response<B>, _latency: std::time::Duration, span: &Span) {
        Self::record(response.headers(), span);
    }
}

impl OnEos for RecordGrpcStatus {
    fn on_eos(
        self,
        trailers: Option<&http::HeaderMap>,
        _stream_duration: std::time::Duration,
        span: &Span,
    ) {
        if let Some(trailers) = trailers {
            Self::record(trailers, span);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
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
            (
                "EnsureWorkspace",
                "driver.ensure_workspace",
                "ensure_workspace",
            ),
            (
                "DeleteWorkspace",
                "driver.delete_workspace",
                "delete_workspace",
            ),
        ] {
            assert_eq!(
                compute_driver_rpc_operation(&format!("/openshell.compute.v1.ComputeDriver/{rpc}")),
                (operation, method)
            );
        }
        assert_eq!(
            compute_driver_rpc_operation(
                "/openshell.compute.v1.ComputeDriver/AttackerControlled12345"
            ),
            ("driver.unknown", "unknown")
        );
    }

    #[test]
    fn grpc_status_records_and_marks_non_ok_trailer_status() {
        let _tracing_lock = crate::test_lock();
        let exporter = InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry().with(crate::layer(&provider, "test"));
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", http::HeaderValue::from_static("13"));

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!(
                "rpc",
                otel.status_code = tracing::field::Empty,
                rpc.grpc.status_code = tracing::field::Empty,
            );
            RecordGrpcStatus.on_eos(Some(&trailers), std::time::Duration::ZERO, &span);
        });
        provider.force_flush().unwrap();

        let spans = exporter.get_finished_spans().unwrap();
        assert_eq!(spans.len(), 1);
        assert!(matches!(
            spans[0].status,
            opentelemetry::trace::Status::Error { .. }
        ));
        assert!(spans[0].attributes.iter().any(|attribute| {
            attribute.key.as_str() == "rpc.grpc.status_code" && attribute.value.to_string() == "13"
        }));
        provider.shutdown().unwrap();
    }

    #[test]
    fn grpc_status_records_header_status_without_eos_overwrite() {
        let _tracing_lock = crate::test_lock();
        let exporter = InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry().with(crate::layer(&provider, "test"));
        let response = http::Response::builder()
            .header("grpc-status", "13")
            .body(())
            .unwrap();

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!(
                "rpc",
                otel.status_code = tracing::field::Empty,
                rpc.grpc.status_code = tracing::field::Empty,
            );
            RecordGrpcStatus.on_response(&response, std::time::Duration::ZERO, &span);
            RecordGrpcStatus.on_eos(None, std::time::Duration::ZERO, &span);
        });
        provider.force_flush().unwrap();

        let spans = exporter.get_finished_spans().unwrap();
        assert_eq!(spans.len(), 1);
        assert!(matches!(
            spans[0].status,
            opentelemetry::trace::Status::Error { .. }
        ));
        assert!(spans[0].attributes.iter().any(|attribute| {
            attribute.key.as_str() == "rpc.grpc.status_code" && attribute.value.to_string() == "13"
        }));
        provider.shutdown().unwrap();
    }
}
