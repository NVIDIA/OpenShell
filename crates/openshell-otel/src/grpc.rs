// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared gRPC tracing adapters.

use futures::Stream;
use http::Request;
use opentelemetry::propagation::TextMapPropagator as _;
use opentelemetry::trace::TraceContextExt as _;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tower_http::classify::GrpcFailureClass;
use tower_http::trace::{GrpcMakeClassifier, MakeSpan, OnEos, OnFailure, OnResponse, TraceLayer};
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

/// Keeps a gRPC server span alive for a response stream and records its outcome.
pub struct TracedGrpcStream<S> {
    inner: S,
    span: Span,
    finished: bool,
}

impl<S> TracedGrpcStream<S> {
    #[must_use]
    pub fn new(inner: S, span: Span) -> Self {
        Self {
            inner,
            span,
            finished: false,
        }
    }
}

impl<S, T> Stream for TracedGrpcStream<S>
where
    S: Stream<Item = Result<T, tonic::Status>> + Unpin,
{
    type Item = Result<T, tonic::Status>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let span = this.span.clone();
        let _entered = span.enter();
        let result = std::pin::Pin::new(&mut this.inner).poll_next(cx);
        if !this.finished {
            match &result {
                std::task::Poll::Ready(Some(Err(status))) => {
                    record_grpc_status(&this.span, status.code());
                    this.finished = true;
                }
                std::task::Poll::Ready(None) => {
                    record_grpc_status(&this.span, tonic::Code::Ok);
                    this.finished = true;
                }
                std::task::Poll::Pending | std::task::Poll::Ready(Some(Ok(_))) => {}
            }
        }
        result
    }
}

pub const COMPUTE_DRIVER_RPC_SERVICE: &str = "openshell.compute.v1.ComputeDriver";

/// Low-cardinality semantic-convention identity for a compute-driver RPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComputeDriverRpc {
    pub service: &'static str,
    pub method: &'static str,
    pub operation: &'static str,
}

impl ComputeDriverRpc {
    const fn new(method: &'static str, operation: &'static str) -> Self {
        Self {
            service: COMPUTE_DRIVER_RPC_SERVICE,
            method,
            operation,
        }
    }
}

/// Typed identities for every RPC in the generated compute-driver service.
pub mod rpc {
    use super::ComputeDriverRpc;

    pub const AUTHENTICATE_SANDBOX: ComputeDriverRpc = ComputeDriverRpc::new(
        "AuthenticateSandbox",
        "openshell.compute.v1.ComputeDriver/AuthenticateSandbox",
    );
    pub const GET_CAPABILITIES: ComputeDriverRpc = ComputeDriverRpc::new(
        "GetCapabilities",
        "openshell.compute.v1.ComputeDriver/GetCapabilities",
    );
    pub const GET_GATEWAY_LISTENER_REQUIREMENTS: ComputeDriverRpc = ComputeDriverRpc::new(
        "GetGatewayListenerRequirements",
        "openshell.compute.v1.ComputeDriver/GetGatewayListenerRequirements",
    );
    pub const VALIDATE_SANDBOX_CREATE: ComputeDriverRpc = ComputeDriverRpc::new(
        "ValidateSandboxCreate",
        "openshell.compute.v1.ComputeDriver/ValidateSandboxCreate",
    );
    pub const CREATE_SANDBOX: ComputeDriverRpc = ComputeDriverRpc::new(
        "CreateSandbox",
        "openshell.compute.v1.ComputeDriver/CreateSandbox",
    );
    pub const GET_SANDBOX: ComputeDriverRpc = ComputeDriverRpc::new(
        "GetSandbox",
        "openshell.compute.v1.ComputeDriver/GetSandbox",
    );
    pub const LIST_SANDBOXES: ComputeDriverRpc = ComputeDriverRpc::new(
        "ListSandboxes",
        "openshell.compute.v1.ComputeDriver/ListSandboxes",
    );
    pub const STOP_SANDBOX: ComputeDriverRpc = ComputeDriverRpc::new(
        "StopSandbox",
        "openshell.compute.v1.ComputeDriver/StopSandbox",
    );
    pub const START_SANDBOX: ComputeDriverRpc = ComputeDriverRpc::new(
        "StartSandbox",
        "openshell.compute.v1.ComputeDriver/StartSandbox",
    );
    pub const DELETE_SANDBOX: ComputeDriverRpc = ComputeDriverRpc::new(
        "DeleteSandbox",
        "openshell.compute.v1.ComputeDriver/DeleteSandbox",
    );
    pub const WATCH_SANDBOXES: ComputeDriverRpc = ComputeDriverRpc::new(
        "WatchSandboxes",
        "openshell.compute.v1.ComputeDriver/WatchSandboxes",
    );
    pub const ENSURE_WORKSPACE: ComputeDriverRpc = ComputeDriverRpc::new(
        "EnsureWorkspace",
        "openshell.compute.v1.ComputeDriver/EnsureWorkspace",
    );
    pub const DELETE_WORKSPACE: ComputeDriverRpc = ComputeDriverRpc::new(
        "DeleteWorkspace",
        "openshell.compute.v1.ComputeDriver/DeleteWorkspace",
    );
}

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
        let rpc = compute_driver_rpc_operation(request.uri().path());
        let span = tracing::info_span!(
            "driver_rpc",
            otel.name = rpc.map_or("grpc", |rpc| rpc.operation),
            otel.kind = "server",
            otel.status_code = tracing::field::Empty,
            rpc.system.name = "grpc",
            rpc.method = rpc.map_or("_OTHER", |rpc| rpc.operation),
            rpc.response.status_code = tracing::field::Empty,
            error.type = tracing::field::Empty,
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
pub fn compute_driver_rpc_operation(path: &str) -> Option<ComputeDriverRpc> {
    match path.rsplit('/').next() {
        Some("AuthenticateSandbox") => Some(rpc::AUTHENTICATE_SANDBOX),
        Some("GetCapabilities") => Some(rpc::GET_CAPABILITIES),
        Some("GetGatewayListenerRequirements") => Some(rpc::GET_GATEWAY_LISTENER_REQUIREMENTS),
        Some("ValidateSandboxCreate") => Some(rpc::VALIDATE_SANDBOX_CREATE),
        Some("CreateSandbox") => Some(rpc::CREATE_SANDBOX),
        Some("GetSandbox") => Some(rpc::GET_SANDBOX),
        Some("ListSandboxes") => Some(rpc::LIST_SANDBOXES),
        Some("StopSandbox") => Some(rpc::STOP_SANDBOX),
        Some("StartSandbox") => Some(rpc::START_SANDBOX),
        Some("DeleteSandbox") => Some(rpc::DELETE_SANDBOX),
        Some("WatchSandboxes") => Some(rpc::WATCH_SANDBOXES),
        Some("EnsureWorkspace") => Some(rpc::ENSURE_WORKSPACE),
        Some("DeleteWorkspace") => Some(rpc::DELETE_WORKSPACE),
        _ => None,
    }
}

/// Return the stable OpenTelemetry spelling for a gRPC response status.
#[must_use]
pub const fn grpc_status_code_name(code: tonic::Code) -> &'static str {
    match code {
        tonic::Code::Ok => "OK",
        tonic::Code::Cancelled => "CANCELLED",
        tonic::Code::Unknown => "UNKNOWN",
        tonic::Code::InvalidArgument => "INVALID_ARGUMENT",
        tonic::Code::DeadlineExceeded => "DEADLINE_EXCEEDED",
        tonic::Code::NotFound => "NOT_FOUND",
        tonic::Code::AlreadyExists => "ALREADY_EXISTS",
        tonic::Code::PermissionDenied => "PERMISSION_DENIED",
        tonic::Code::ResourceExhausted => "RESOURCE_EXHAUSTED",
        tonic::Code::FailedPrecondition => "FAILED_PRECONDITION",
        tonic::Code::Aborted => "ABORTED",
        tonic::Code::OutOfRange => "OUT_OF_RANGE",
        tonic::Code::Unimplemented => "UNIMPLEMENTED",
        tonic::Code::Internal => "INTERNAL",
        tonic::Code::Unavailable => "UNAVAILABLE",
        tonic::Code::DataLoss => "DATA_LOSS",
        tonic::Code::Unauthenticated => "UNAUTHENTICATED",
    }
}

/// Records a complete gRPC outcome on `span`.
///
/// Non-OK codes also set `otel.status_code` to `ERROR` and record the code as
/// `error.type`. OK codes leave the OpenTelemetry span status unset.
///
/// The span must declare `otel.status_code`, `rpc.response.status_code`, and
/// `error.type` when it is created because `tracing` ignores undeclared fields.
pub fn record_grpc_status(span: &Span, code: tonic::Code) {
    let code_name = grpc_status_code_name(code);
    span.record("rpc.response.status_code", code_name);
    if code != tonic::Code::Ok {
        crate::mark_error(span);
        span.record("error.type", code_name);
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
        if let GrpcFailureClass::Code(code) = failure {
            let code = tonic::Code::from_i32(code.get());
            record_grpc_status(span, code);
        } else {
            crate::mark_error(span);
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
        let code = tonic::Code::from_i32(code);
        record_grpc_status(span, code);
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
        for rpc in [
            rpc::AUTHENTICATE_SANDBOX,
            rpc::GET_CAPABILITIES,
            rpc::GET_GATEWAY_LISTENER_REQUIREMENTS,
            rpc::VALIDATE_SANDBOX_CREATE,
            rpc::CREATE_SANDBOX,
            rpc::GET_SANDBOX,
            rpc::LIST_SANDBOXES,
            rpc::STOP_SANDBOX,
            rpc::START_SANDBOX,
            rpc::DELETE_SANDBOX,
            rpc::WATCH_SANDBOXES,
            rpc::ENSURE_WORKSPACE,
            rpc::DELETE_WORKSPACE,
        ] {
            assert_eq!(rpc.operation, format!("{}/{}", rpc.service, rpc.method));
            assert_eq!(
                compute_driver_rpc_operation(&format!("/{}/{}", rpc.service, rpc.method)),
                Some(rpc)
            );
        }
        assert_eq!(
            compute_driver_rpc_operation(
                "/openshell.compute.v1.ComputeDriver/AttackerControlled12345"
            ),
            None
        );
    }

    #[test]
    fn traced_stream_records_an_observed_cancelled_status() {
        let _tracing_lock = crate::test_lock();
        let exporter = InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry().with(crate::layer(&provider, "test"));

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!(
                "watch",
                otel.status_code = tracing::field::Empty,
                rpc.response.status_code = tracing::field::Empty,
                error.type = tracing::field::Empty,
            );
            let inner =
                futures::stream::iter([Err::<(), _>(tonic::Status::cancelled("peer cancelled"))]);
            let mut stream = TracedGrpcStream::new(inner, span);
            let mut cx = std::task::Context::from_waker(futures::task::noop_waker_ref());
            let result = std::pin::Pin::new(&mut stream).poll_next(&mut cx);
            assert!(matches!(
                result,
                std::task::Poll::Ready(Some(Err(status)))
                    if status.code() == tonic::Code::Cancelled
            ));
        });
        provider.force_flush().unwrap();

        let spans = exporter.get_finished_spans().unwrap();
        assert_eq!(spans.len(), 1);
        assert!(matches!(
            spans[0].status,
            opentelemetry::trace::Status::Error { .. }
        ));
        assert!(spans[0].attributes.iter().any(|attribute| {
            attribute.key.as_str() == "rpc.response.status_code"
                && attribute.value.to_string() == "CANCELLED"
        }));
        provider.shutdown().unwrap();
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
                rpc.response.status_code = tracing::field::Empty,
                error.type = tracing::field::Empty,
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
            attribute.key.as_str() == "rpc.response.status_code"
                && attribute.value.to_string() == "INTERNAL"
        }));
        assert!(spans[0].attributes.iter().any(|attribute| {
            attribute.key.as_str() == "error.type" && attribute.value.to_string() == "INTERNAL"
        }));
        provider.shutdown().unwrap();
    }

    #[test]
    fn grpc_status_records_ok_without_marking_an_error() {
        let _tracing_lock = crate::test_lock();
        let exporter = InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry().with(crate::layer(&provider, "test"));

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!(
                "rpc",
                otel.status_code = tracing::field::Empty,
                rpc.response.status_code = tracing::field::Empty,
                error.type = tracing::field::Empty,
            );
            record_grpc_status(&span, tonic::Code::Ok);
        });
        provider.force_flush().unwrap();

        let spans = exporter.get_finished_spans().unwrap();
        assert_eq!(spans.len(), 1);
        assert!(matches!(
            spans[0].status,
            opentelemetry::trace::Status::Unset
        ));
        assert!(spans[0].attributes.iter().any(|attribute| {
            attribute.key.as_str() == "rpc.response.status_code"
                && attribute.value.to_string() == "OK"
        }));
        assert!(
            spans[0]
                .attributes
                .iter()
                .all(|attribute| attribute.key.as_str() != "error.type")
        );
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
                rpc.response.status_code = tracing::field::Empty,
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
            attribute.key.as_str() == "rpc.response.status_code"
                && attribute.value.to_string() == "INTERNAL"
        }));
        provider.shutdown().unwrap();
    }
}
