// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, LazyLock, Mutex};

use openshell_ocsf::{
    ApiActivityBuilder, AuthenticationBuilder, Endpoint, HttpActivityBuilder, HttpRequest,
    NetworkActivityBuilder, OcsfEvent, OcsfJsonlLayer, Service, Url, User, ocsf_emit,
};
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
) -> (serde_json::Value, Vec<opentelemetry_sdk::trace::SpanData>) {
    capture_route(sampler, active, false)
}

fn http_event() -> OcsfEvent {
    HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .http_request(HttpRequest::new(
            "GET",
            Url::new("https", "example.com", "/", 443),
        ))
        .build()
}

fn capture_event(build: fn() -> OcsfEvent) -> serde_json::Value {
    capture_context(Sampler::AlwaysOn, true, false, None, build).0
}

fn capture_route(
    sampler: Sampler,
    active: bool,
    routed: bool,
) -> (serde_json::Value, Vec<opentelemetry_sdk::trace::SpanData>) {
    capture_context(sampler, active, routed, None, http_event)
}

fn capture_context(
    sampler: Sampler,
    active: bool,
    routed: bool,
    remote_parent: Option<opentelemetry::trace::SpanContext>,
    build: fn() -> OcsfEvent,
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
            if routed {
                openshell_ocsf::emit_ocsf_event_routed("test-sandbox", build());
            } else {
                ocsf_emit!(build());
            }
        };
        if active {
            let span = tracing::info_span!("sampled-operation");
            if let Some(parent) = remote_parent {
                use opentelemetry::trace::TraceContextExt as _;
                use tracing_opentelemetry::OpenTelemetrySpanExt as _;
                span.set_parent(opentelemetry::Context::new().with_remote_span_context(parent))
                    .unwrap();
            }
            span.in_scope(emit);
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

#[test]
fn api_activity_correlation_can_inherit_sampled_or_unsampled_caller_context() {
    use opentelemetry::trace::{SpanContext, SpanId, TraceFlags, TraceId, TraceState};
    let uid = "0af7651916cd43dd8448eb211c80319c";
    for sampled in [true, false] {
        let parent = SpanContext::new(
            TraceId::from_hex(uid).unwrap(),
            SpanId::from_hex("b7ad6b7169203331").unwrap(),
            if sampled {
                TraceFlags::SAMPLED
            } else {
                TraceFlags::default()
            },
            true,
            TraceState::default(),
        );
        let (event, spans) = capture_context(
            Sampler::ParentBased(Box::new(Sampler::AlwaysOn)),
            true,
            false,
            Some(parent),
            || ApiActivityBuilder::new(openshell_ocsf::ctx::ctx(), "CreateSandbox").build(),
        );
        assert_eq!(event["class_uid"], 6003);
        if sampled {
            assert_eq!(event["trace"]["uid"], uid);
            assert_eq!(spans.len(), 1);
            assert_eq!(spans[0].span_context.trace_id().to_string(), uid);
        } else {
            assert_no_trace(&event);
            assert!(spans.is_empty());
        }
    }
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
fn classes_without_the_trace_profile_stay_uncorrelated() {
    assert_no_trace(&capture_event(|| {
        NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .dst_endpoint(Endpoint::from_domain("example.com", 443))
            .build()
    }));
    assert_no_trace(&capture_event(|| {
        AuthenticationBuilder::new(
            openshell_ocsf::ctx::ctx(),
            User::unidentified(),
            Service::new("openshell-gateway"),
        )
        .build()
    }));
}

#[test]
fn sampled_active_span_correlates_to_exported_w3c_trace() {
    let (value, spans) = capture(Sampler::AlwaysOn, true);
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
    let (value, spans) = capture(Sampler::AlwaysOn, false);
    assert_no_trace(&value);
    assert!(spans.is_empty());
}

#[test]
fn routed_emission_also_enriches_from_sampled_context() {
    let (value, spans) = capture_route(Sampler::AlwaysOn, true, true);
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
    let (value, spans) = capture(Sampler::AlwaysOff, true);
    assert_no_trace(&value);
    assert!(spans.is_empty());
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
