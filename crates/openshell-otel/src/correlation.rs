// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sampled trace correlation for OCSF producers.

use opentelemetry::trace::{SpanContext, TraceContextExt as _};

/// Extract the active span's W3C trace ID for an OCSF event.
///
/// Returns `None` unless the current span has valid, sampled context. This reads
/// the current span without extracting workload HTTP headers or environment
/// variables. The active span may already inherit a gateway caller's context,
/// including before authentication. This is a correlation hint, not proof of
/// origin. A sampled ID does not guarantee export or retention.
#[must_use]
pub fn current_ocsf_trace_correlation() -> Option<openshell_ocsf::TraceCorrelation> {
    let span_context = sampled_span_context()?;
    openshell_ocsf::TraceCorrelation::from_trace_id(span_context.trace_id().to_bytes())
}

/// The OpenTelemetry tracing layer activates a span's context on entry, so this
/// also works inside a layer, where the tracing dispatcher is busy.
pub fn sampled_span_context() -> Option<SpanContext> {
    let context = opentelemetry::Context::current();
    let span_context = context.span().span_context().clone();
    (span_context.is_valid() && span_context.is_sampled()).then_some(span_context)
}
