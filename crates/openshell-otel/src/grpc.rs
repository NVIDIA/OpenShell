// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared gRPC tracing adapters.

use tower_http::classify::GrpcFailureClass;
use tower_http::trace::OnFailure;
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
