// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared gRPC tracing adapters.

use tower_http::classify::GrpcFailureClass;
use tower_http::trace::{OnEos, OnFailure, OnResponse};
use tracing::Span;

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
