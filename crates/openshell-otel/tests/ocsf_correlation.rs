// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, LazyLock, Mutex};

use openshell_ocsf::{BaseEventBuilder, OcsfJsonlLayer, TraceCorrelation, ocsf_emit};
use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, Sampler, SdkTracerProvider};
use tracing_subscriber::prelude::*;

static SETUP: LazyLock<()> = LazyLock::new(|| {
    tracing::subscriber::set_global_default(tracing_subscriber::registry()).unwrap();
    assert!(openshell_ocsf::register_trace_correlation_extractor(
        openshell_otel::current_ocsf_trace_correlation,
    ));
});

#[derive(Clone)]
struct Writer(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Writer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn capture(
    sampler: Sampler,
    active: bool,
    explicit: Option<TraceCorrelation>,
) -> (serde_json::Value, Vec<opentelemetry_sdk::trace::SpanData>) {
    capture_route(sampler, active, explicit, false)
}

fn capture_route(
    sampler: Sampler,
    active: bool,
    explicit: Option<TraceCorrelation>,
    routed: bool,
) -> (serde_json::Value, Vec<opentelemetry_sdk::trace::SpanData>) {
    LazyLock::force(&SETUP);
    let exporter = InMemorySpanExporterBuilder::new().build();
    let provider = SdkTracerProvider::builder()
        .with_sampler(sampler)
        .with_simple_exporter(exporter.clone())
        .build();
    let bytes = Arc::new(Mutex::new(vec![]));
    let subscriber = tracing_subscriber::registry()
        .with(openshell_otel::layer(&provider, "ocsf-test"))
        .with(OcsfJsonlLayer::new(Writer(bytes.clone())));
    tracing::subscriber::with_default(subscriber, || {
        let emit = || {
            let ctx = openshell_ocsf::ctx::ctx();
            let mut builder = BaseEventBuilder::new(ctx);
            if let Some(trace) = explicit {
                builder = builder.trace(trace);
            }
            if routed {
                openshell_ocsf::emit_ocsf_event_routed("test-sandbox", builder.build());
            } else {
                ocsf_emit!(builder.build());
            }
        };
        if active {
            tracing::info_span!("sampled-operation").in_scope(emit);
        } else {
            emit();
        }
    });
    let value = serde_json::from_slice(&bytes.lock().unwrap()).unwrap();
    provider.force_flush().unwrap();
    let spans = exporter.get_finished_spans().unwrap();
    provider.shutdown().unwrap();
    (value, spans)
}

fn assert_no_trace(value: &serde_json::Value) {
    assert!(value.get("trace").is_none());
    assert!(
        !value["metadata"]["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p == "trace")
    );
}

#[test]
fn sampled_active_span_correlates_to_exported_w3c_trace() {
    let (value, spans) = capture(Sampler::AlwaysOn, true, None);
    let uid = value["trace"]["uid"].as_str().unwrap();
    assert_eq!(uid.len(), 32);
    assert!(
        uid.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert_eq!(uid, spans[0].span_context.trace_id().to_string());
    assert_eq!(
        value["metadata"]["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| *p == "trace")
            .count(),
        1
    );
    assert_eq!(value["trace"].as_object().unwrap().len(), 1);
}

#[test]
fn no_active_context_omits_trace_and_profile() {
    let (value, spans) = capture(Sampler::AlwaysOn, false, None);
    assert_no_trace(&value);
    assert!(spans.is_empty());
}

#[test]
fn routed_emission_also_enriches_from_sampled_context() {
    let (value, spans) = capture_route(Sampler::AlwaysOn, true, None, true);
    assert_eq!(
        value["trace"]["uid"],
        spans[0].span_context.trace_id().to_string()
    );
    assert!(
        value["metadata"]["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p == "trace")
    );
}

#[test]
fn unsampled_active_context_omits_trace_and_profile() {
    let (value, spans) = capture(Sampler::AlwaysOff, true, None);
    assert_no_trace(&value);
    assert!(spans.is_empty());
}

#[test]
fn explicit_trace_overrides_automatic_enrichment() {
    let explicit = "0af7651916cd43dd8448eb211c80319c";
    let (value, spans) = capture(
        Sampler::AlwaysOn,
        true,
        Some(TraceCorrelation {
            uid: explicit.to_string(),
        }),
    );
    assert_eq!(value["trace"]["uid"], explicit);
    assert_ne!(explicit, spans[0].span_context.trace_id().to_string());
    assert_eq!(
        value["metadata"]["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| *p == "trace")
            .count(),
        1
    );
}

#[test]
fn active_tracing_span_without_otel_context_is_invalid() {
    LazyLock::force(&SETUP);
    tracing::subscriber::with_default(tracing_subscriber::registry(), || {
        tracing::info_span!("no-otel-layer").in_scope(|| {
            assert!(openshell_otel::current_ocsf_trace_correlation().is_none());
        });
    });
}
