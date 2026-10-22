// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Trusted, sampled trace correlation for OCSF producers.

use opentelemetry::trace::TraceContextExt as _;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

/// Extract the active span's W3C trace ID for an OCSF event.
///
/// Returns `None` unless the current span has valid, sampled context. This reads
/// the current span without extracting workload HTTP headers or environment
/// variables. A sampled ID does not guarantee export or retention.
#[must_use]
pub fn current_ocsf_trace_correlation() -> Option<openshell_ocsf::TraceCorrelation> {
    let context = tracing::Span::current().context();
    let span = context.span();
    let span_context = span.span_context();
    (span_context.is_valid() && span_context.is_sampled()).then(|| {
        openshell_ocsf::TraceCorrelation {
            uid: span_context.trace_id().to_string(),
        }
    })
}
