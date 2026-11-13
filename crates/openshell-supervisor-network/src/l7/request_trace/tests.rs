// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::l7::correlation::HttpOutcome;
use crate::test_support::request_tracing::RequestTracing;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::trace::{InMemorySpanExporter, Sampler, SdkTracerProvider, SpanData};
use tracing_subscriber::layer::SubscriberExt as _;

const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const PARENT_ID: &str = "00f067aa0ba902b7";

fn request(flags: &str) -> Vec<u8> {
    format!(
        "GET /account?secret=DO-NOT-RECORD HTTP/1.1\r\nHost: example.test\r\ntraceparent: 00-{TRACE_ID}-{PARENT_ID}-{flags}\r\ntracestate: vendor=DO-NOT-RECORD\r\nbaggage: secret=DO-NOT-RECORD\r\n\r\n"
    )
    .into_bytes()
}

fn capture(sampler: Sampler, emit: impl FnOnce()) -> Vec<SpanData> {
    let capture = RequestTracing::new(Some(sampler));
    tracing::subscriber::with_default(capture.subscriber(), emit);
    let spans = capture.spans();
    capture.shutdown();
    spans
}

fn root(spans: &[SpanData]) -> &SpanData {
    spans
        .iter()
        .find(|span| span.name == "openshell.http.request")
        .expect("one supervisor request root")
}

fn attribute<'a>(span: &'a SpanData, name: &str) -> Option<&'a opentelemetry::Value> {
    span.attributes
        .iter()
        .find(|attribute| attribute.key.as_str() == name)
        .map(|attribute| &attribute.value)
}

#[test]
fn workload_context_is_linked_not_parented_for_both_sampled_flags() {
    for flags in ["00", "01"] {
        let spans = capture(Sampler::ParentBased(Box::new(Sampler::AlwaysOn)), || {
            let unrelated = tracing::info_span!("unrelated-host-operation");
            unrelated.in_scope(|| {
                let mut trace = RequestTrace::new(
                    "test-request-id",
                    "GET",
                    "example.test",
                    443,
                    &request(flags),
                );
                trace.stage(RequestStage::PolicyEvaluate).in_scope(|| {});
                trace.record_status(403);
                trace.record_outcome(HttpOutcome::Denied);
            });
        });
        let root = root(&spans);
        assert_eq!(root.parent_span_id, opentelemetry::trace::SpanId::INVALID);
        assert_ne!(root.span_context.trace_id().to_string(), TRACE_ID);
        assert_eq!(root.links.links.len(), 1);
        let link = &root.links.links[0];
        assert_eq!(link.span_context.trace_id().to_string(), TRACE_ID);
        assert_eq!(link.span_context.span_id().to_string(), PARENT_ID);
        assert_eq!(link.span_context.is_sampled(), flags == "01");
        assert!(link.span_context.trace_state().header().is_empty());
        assert!(link.attributes.iter().any(|field| {
            field.key.as_str() == "openshell.correlation.trust"
                && field.value.as_str() == "workload"
        }));
        let policy = spans
            .iter()
            .find(|span| span.name == "openshell.policy.evaluate")
            .unwrap();
        assert_eq!(policy.parent_span_id, root.span_context.span_id());
        assert_eq!(policy.span_context.trace_id(), root.span_context.trace_id());
        assert_eq!(
            attribute(root, "openshell.request.id").unwrap().as_str(),
            "test-request-id"
        );
        assert_eq!(root.status, opentelemetry::trace::Status::Unset);
        assert!(!format!("{spans:?}").contains("DO-NOT-RECORD"));
    }
}

#[test]
fn explicit_request_root_does_not_adopt_ambient_otel_context() {
    let remote = workload_link(&request("01")).unwrap();
    let spans = capture(Sampler::AlwaysOn, || {
        let _guard = Context::new().with_remote_span_context(remote).attach();
        let mut trace = RequestTrace::new("local", "GET", "example.test", 443, &request("00"));
        trace.record_outcome(HttpOutcome::Allowed);
    });
    let root = root(&spans);
    assert_eq!(root.parent_span_id, opentelemetry::trace::SpanId::INVALID);
    assert_ne!(root.span_context.trace_id().to_string(), TRACE_ID);
    assert_eq!(root.links.links.len(), 1);
}

#[test]
fn request_completion_encloses_stages_after_an_early_root_exit() {
    let spans = capture(Sampler::AlwaysOn, || {
        let mut trace = RequestTrace::new("local", "GET", "example.test", 443, &request("01"));
        trace.span().in_scope(|| trace.record_status(200));
        trace.stage(RequestStage::Response).in_scope(|| {});
        trace.record_outcome(HttpOutcome::Allowed);
    });
    let root = root(&spans);
    let response = spans
        .iter()
        .find(|span| span.name == RequestStage::Response.name())
        .unwrap();
    assert_eq!(response.parent_span_id, root.span_context.span_id());
    assert!(response.start_time >= root.start_time);
    assert!(response.end_time <= root.end_time);
}

#[test]
fn remote_sampled_flag_cannot_override_local_always_off() {
    for flags in ["00", "01"] {
        let spans = capture(Sampler::ParentBased(Box::new(Sampler::AlwaysOff)), || {
            let mut trace = RequestTrace::new("local", "GET", "example.test", 443, &request(flags));
            trace.stage(RequestStage::PolicyEvaluate).in_scope(|| {});
            trace.record_outcome(HttpOutcome::Denied);
        });
        assert!(spans.is_empty());
    }
}

#[test]
fn every_outcome_has_the_same_root_shape_and_stages_have_fixed_names() {
    let stages = [
        RequestStage::PolicyEvaluate,
        RequestStage::RequestMiddleware,
        RequestStage::WebsocketPreflight,
        RequestStage::CredentialPrepare,
        RequestStage::UpstreamResolve,
        RequestStage::UpstreamDial,
        RequestStage::UpstreamSend,
        RequestStage::Response,
        RequestStage::ResponseMiddleware,
    ];
    for (outcome, failed) in [
        (HttpOutcome::Allowed, false),
        (HttpOutcome::Denied, false),
        (HttpOutcome::UpstreamError, true),
    ] {
        let spans = capture(Sampler::AlwaysOn, || {
            let mut trace = RequestTrace::new("local", "GET", "example.test", 443, &request("01"));
            for stage in stages {
                trace.stage(stage).in_scope(|| {});
            }
            trace.record_outcome(outcome);
        });
        let root = root(&spans);
        assert_eq!(spans.len(), stages.len() + 1);
        for stage in stages {
            let child = spans.iter().find(|span| span.name == stage.name()).unwrap();
            assert_eq!(child.parent_span_id, root.span_context.span_id());
            assert_eq!(child.span_context.trace_id(), root.span_context.trace_id());
        }
        assert_eq!(
            matches!(root.status, opentelemetry::trace::Status::Error { .. }),
            failed
        );
    }
}

#[test]
fn malformed_duplicate_oversized_and_zero_context_is_ignored() {
    let valid = String::from_utf8(request("01")).unwrap();
    let duplicate = valid.replace(
        "\r\ntracestate:",
        &format!("\r\nTraceparent: 00-{TRACE_ID}-{PARENT_ID}-00\r\ntracestate:"),
    );
    for headers in [
        b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec(),
        b"GET / HTTP/1.1\r\ntraceparent: invalid\r\n\r\n".to_vec(),
        duplicate.into_bytes(),
        valid
            .replace(TRACE_ID, "00000000000000000000000000000000")
            .into_bytes(),
        valid.replace(PARENT_ID, "0000000000000000").into_bytes(),
        format!("GET / HTTP/1.1\r\ntraceparent: {}\r\n\r\n", "a".repeat(257)).into_bytes(),
    ] {
        assert!(workload_link(&headers).is_none());
    }
}

#[test]
fn unrelated_opaque_header_values_do_not_discard_valid_trace_context() {
    let mut headers = b"GET / HTTP/1.1\r\nX-Opaque: \xff\r\n".to_vec();
    headers
        .extend_from_slice(format!("traceparent: 00-{TRACE_ID}-{PARENT_ID}-01\r\n\r\n").as_bytes());
    assert!(workload_link(&headers).is_some());
}

#[test]
fn custom_method_values_are_not_exported() {
    let spans = capture(Sampler::AlwaysOn, || {
        let mut trace = RequestTrace::new(
            "local",
            "DO-NOT-RECORD",
            "example.test",
            443,
            &request("01"),
        );
        trace.record_outcome(HttpOutcome::Allowed);
    });
    assert_eq!(
        attribute(root(&spans), "http.request.method")
            .unwrap()
            .as_str(),
        "_OTHER"
    );
    assert!(!format!("{spans:?}").contains("DO-NOT-RECORD"));
}

#[test]
fn no_exporter_does_not_change_execution() {
    tracing::subscriber::with_default(tracing_subscriber::registry(), || {
        let mut trace = RequestTrace::new("local", "GET", "example.test", 443, &request("01"));
        assert_eq!(
            trace.stage(RequestStage::PolicyEvaluate).in_scope(|| 42),
            42
        );
        trace.record_outcome(HttpOutcome::Allowed);
    });
}

#[test]
fn a_filtered_request_root_does_not_create_orphan_stage_spans() {
    use tracing_subscriber::Layer as _;

    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture).with(
        tracing_opentelemetry::layer()
            .with_tracer(provider.tracer("filtered-root-test"))
            .with_filter(tracing_subscriber::filter::filter_fn(|metadata| {
                metadata.name() != "openshell.http.request"
            })),
    );
    tracing::subscriber::with_default(subscriber, || {
        let mut trace = RequestTrace::new("local", "GET", "example.test", 443, &request("01"));
        assert!(
            !trace.span().is_disabled(),
            "another layer still enables the root"
        );
        assert!(trace.stage(RequestStage::PolicyEvaluate).is_disabled());
        trace.record_outcome(HttpOutcome::Allowed);
    });
    provider.force_flush().unwrap();
    assert!(exporter.get_finished_spans().unwrap().is_empty());
    provider.shutdown().unwrap();
}
