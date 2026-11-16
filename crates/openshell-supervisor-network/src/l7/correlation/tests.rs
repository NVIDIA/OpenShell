// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_support::request_tracing::RequestTracing;
use openshell_ocsf::test_support::OcsfCapture;
use openshell_ocsf::{
    ActionId, ActivityId, DetectionFindingBuilder, DispositionId, HttpActivityBuilder, HttpRequest,
    HttpResponse, NetworkActivityBuilder, SeverityId, StatusId,
};

fn request() -> L7Request {
    L7Request {
        action: "GET".into(),
        target: "/data".into(),
        query_params: std::collections::HashMap::new(),
        raw_header: b"GET /data HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec(),
        body_length: crate::l7::provider::BodyLength::None,
    }
}

fn context() -> L7EvalContext {
    L7EvalContext {
        host: "example.test".into(),
        port: 443,
        ..Default::default()
    }
}

fn allowed() -> OcsfEvent {
    HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .http_request(HttpRequest::new("GET", context().ocsf_url("/data")))
        .firewall_rule("protected-api", "l7")
        .action(ActionId::Allowed)
        .disposition(DispositionId::Allowed)
        .status(StatusId::Success)
        .message("HTTP request admitted by policy")
        .build()
}

fn deny() -> OcsfEvent {
    HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .http_request(HttpRequest::new("GET", context().ocsf_url("/data")))
        .http_response(HttpResponse { code: 403 })
        .firewall_rule("content-guard", "supervisor-middleware")
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .status(StatusId::Failure)
        .severity(SeverityId::Medium)
        .message("middleware blocked request")
        .unmapped("http_event_kind", "middleware_invocation")
        .unmapped("middleware_phase", "response")
        .unmapped("transformed", true)
        .build()
}

#[test]
fn records_emit_immediately_and_keep_their_original_meaning() {
    let capture = OcsfCapture::default();
    let _subscriber = capture.install();
    let correlation = RequestCorrelation::new(&request(), &context());
    for (index, source) in [allowed(), deny(), deny()].into_iter().enumerate() {
        let mut expected = source.to_json().unwrap();
        expected["metadata"]["correlation_uid"] = correlation.request_id().into();
        expected["unmapped"]["request_sequence"] = (index + 1).into();
        if index == 0 {
            expected["unmapped"]["http_event_kind"] = "decision".into();
        }
        correlation.emit(source);
        assert_eq!(capture.json_events()[index], expected);
        correlation.record_response_status(502);
    }
    drop(correlation);
    // No replacement, fallback, or late-failure suppression.
    assert_eq!(capture.json_events().len(), 3);
}

#[test]
fn unused_request_scope_does_not_create_an_audit_record() {
    let capture = OcsfCapture::default();
    let _subscriber = capture.install();
    drop(RequestCorrelation::new(&request(), &context()));
    assert!(capture.json_events().is_empty());
}

#[test]
fn request_join_does_not_depend_on_export_and_never_creates_denial_spans() {
    use opentelemetry_sdk::trace::Sampler;
    for sampler in [Some(Sampler::AlwaysOn), Some(Sampler::AlwaysOff), None] {
        let sampled = matches!(sampler, Some(Sampler::AlwaysOn));
        let capture = RequestTracing::new(sampler);
        tracing::subscriber::with_default(capture.subscriber(), || {
            let correlation = RequestCorrelation::new(&request(), &context());
            correlation.emit(allowed());
            correlation.emit(deny());
        });
        let records = capture.events.json_events();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["action"], "Allowed");
        assert_eq!(records[1]["action"], "Denied");
        assert_eq!(
            records[0]["metadata"]["correlation_uid"],
            records[1]["metadata"]["correlation_uid"]
        );
        assert!(records[0]["metadata"]["correlation_uid"].is_string());
        assert_eq!(records[0]["trace"]["uid"].is_string(), sampled);
        assert!(
            !capture
                .created_span_names()
                .contains(&"supervisor.egress.deny")
        );
        capture.shutdown();
    }
}

#[tokio::test]
async fn ambient_scope_stamps_companions_without_call_site_wiring() {
    let capture = OcsfCapture::default();
    let _subscriber = capture.install();
    scope_connection(async {
        let correlation = RequestCorrelation::new(&request(), &context());
        crate::telemetry::emit_decision(
            [
                NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
                    .activity(ActivityId::Open)
                    .action(ActionId::Denied)
                    .message("credential refused")
                    .dst_endpoint(openshell_ocsf::Endpoint::from_domain("example.test", 443))
                    .build(),
                DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
                    .finding_info(openshell_ocsf::FindingInfo::new(
                        "credential",
                        "Credential refused",
                    ))
                    .build(),
            ],
            None,
        );
        let records = capture.json_events();
        assert_eq!(records.len(), 2);
        for (index, record) in records.iter().enumerate() {
            assert_eq!(
                record["metadata"]["correlation_uid"],
                correlation.request_id()
            );
            assert_eq!(record["unmapped"]["request_sequence"], index + 1);
        }
        drop(correlation);
        crate::telemetry::emit_decision([allowed()], None);
        assert!(capture.json_events()[2]["metadata"]["correlation_uid"].is_null());
    })
    .await;
}

#[tokio::test]
async fn concurrent_connections_and_nested_requests_restore_their_own_scope() {
    let capture = OcsfCapture::default();
    let _subscriber = capture.install();
    let run = |name: &'static str| {
        scope_connection(async move {
            let outer = RequestCorrelation::with_request_id(&request(), &context(), name.into());
            crate::telemetry::emit_decision([allowed()], None);
            tokio::task::yield_now().await;
            {
                let _nested = RequestCorrelation::with_request_id(
                    &request(),
                    &context(),
                    format!("{name}-nested"),
                );
                crate::telemetry::emit_decision([allowed()], None);
            }
            crate::telemetry::emit_decision([allowed()], None);
            drop(outer);
            let _uninspected = RequestCorrelation::uninspected();
            crate::telemetry::emit_decision([allowed()], None);
        })
    };
    tokio::join!(run("first"), run("second"));
    let records = capture.json_events();
    assert_eq!(records.len(), 8);
    for name in ["first", "second"] {
        let outer: Vec<_> = records
            .iter()
            .filter(|record| record["metadata"]["correlation_uid"] == name)
            .collect();
        assert_eq!(outer.len(), 2);
        assert_eq!(outer[0]["unmapped"]["request_sequence"], 1);
        assert_eq!(outer[1]["unmapped"]["request_sequence"], 2);
        assert_eq!(
            records
                .iter()
                .filter(|record| record["metadata"]["correlation_uid"] == format!("{name}-nested"))
                .count(),
            1
        );
    }
    assert_eq!(
        records
            .iter()
            .filter(|record| record["metadata"]["correlation_uid"].is_null())
            .count(),
        2
    );
    assert!(!is_inspected_request());
}

#[tokio::test]
async fn cancelling_a_request_does_not_leak_its_context() {
    let capture = OcsfCapture::default();
    let _subscriber = capture.install();
    let (ready, started) = tokio::sync::oneshot::channel();
    let mut pending = Box::pin(scope_connection(async {
        let _correlation = RequestCorrelation::new(&request(), &context());
        ready.send(()).unwrap();
        std::future::pending::<()>().await;
    }));
    tokio::select! {
        () = &mut pending => unreachable!(),
        _ = started => {},
    }
    assert!(!is_inspected_request());
    // Drop while pending, then start a new connection on the same task.
    drop(pending);
    scope_connection(async {
        let correlation = RequestCorrelation::new(&request(), &context());
        crate::telemetry::emit_decision([allowed()], None);
        assert_eq!(
            capture.json_events()[0]["metadata"]["correlation_uid"],
            correlation.request_id()
        );
        assert_eq!(capture.json_events()[0]["unmapped"]["request_sequence"], 1);
    })
    .await;
}
