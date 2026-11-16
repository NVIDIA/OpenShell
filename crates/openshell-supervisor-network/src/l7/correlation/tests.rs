// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_support::request_tracing::{RequestTracing, span_attribute};
use openshell_ocsf::test_support::OcsfCapture;
use openshell_ocsf::{
    ActionId, ActivityId, DetectionFindingBuilder, DispositionId, HttpActivityBuilder, HttpRequest,
    HttpResponse, NetworkActivityBuilder, SeverityId, StatusId,
};
use tracing::instrument::WithSubscriber as _;

fn request() -> L7Request {
    init_request_correlation().unwrap();
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
        assert_eq!(records[0]["unmapped"]["http_event_kind"], "connection");
        assert_eq!(records[1]["unmapped"]["http_event_kind"], "finding");
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

#[test]
fn event_kinds_distinguish_decisions_from_companions() {
    for (class_uid, expected) in [
        (4002, "decision"),
        (2004, "finding"),
        (4001, "connection"),
        (4007, "connection"),
        (1007, "lifecycle"),
        (6002, "lifecycle"),
        (5019, "configuration"),
        (3002, "authentication"),
        (6003, "event"),
        (0, "event"),
    ] {
        assert_eq!(default_event_kind(class_uid), expected);
    }
}

#[tokio::test]
async fn finishing_http_restores_the_previous_scope_before_protocol_relay() {
    let capture = OcsfCapture::default();
    let _subscriber = capture.install();
    scope_connection(async {
        let outer = RequestCorrelation::with_request_id(&request(), &context(), "outer".into());
        let nested = RequestCorrelation::with_request_id(&request(), &context(), "nested".into());
        crate::telemetry::emit_decision([allowed()], None);

        nested.finish_http_request();
        crate::telemetry::emit_decision([allowed()], None);
        assert!(is_inspected_request());

        outer.finish_http_request();
        assert!(!is_inspected_request());
        assert!(current_request_span().is_none());
        tokio::task::yield_now().await;
        crate::telemetry::emit_decision([allowed()], None);
    })
    .await;
    let records = capture.json_events();
    assert_eq!(records[0]["metadata"]["correlation_uid"], "nested");
    assert_eq!(records[1]["metadata"]["correlation_uid"], "outer");
    assert_eq!(records[1]["unmapped"]["request_sequence"], 1);
    assert!(records[2]["metadata"]["correlation_uid"].is_null());
    assert!(records[2]["unmapped"]["request_sequence"].is_null());
}

#[tokio::test]
async fn stage_results_record_bounded_errors_and_preserve_a_failed_root() {
    use opentelemetry::trace::Status;
    use opentelemetry_sdk::trace::Sampler;

    let capture = RequestTracing::new(Some(Sampler::AlwaysOn));
    scope_connection(async {
        let correlation = RequestCorrelation::new_http(
            "POST",
            b"POST / HTTP/1.1\r\nX-Opaque: \xff\r\n\r\n",
            &context(),
        );
        let success = correlation.run_stage_sync(
            RequestStage::PolicyEvaluate,
            HttpOutcome::PlatformError,
            "policy_evaluation_failed",
            || Ok::<_, &str>(42),
        );
        assert_eq!(success, Ok(42));
        let failure = correlation
            .run_stage(
                RequestStage::UpstreamDial,
                HttpOutcome::UpstreamError,
                "upstream_connect_failed",
                async { Err::<(), _>("DO-NOT-RECORD-ERROR") },
            )
            .await;
        assert_eq!(failure, Err("DO-NOT-RECORD-ERROR"));
        correlation.record_failure(HttpOutcome::PlatformError, "request_failed");
        correlation.record_outcome(HttpOutcome::Allowed);
    })
    .with_subscriber(capture.subscriber())
    .await;
    let spans = capture.spans();
    let policy = spans
        .iter()
        .find(|span| span.name == "openshell.policy.evaluate")
        .unwrap();
    assert_eq!(policy.status, Status::Ok);
    let dial = spans
        .iter()
        .find(|span| span.name == "openshell.upstream.connect")
        .unwrap();
    assert!(matches!(dial.status, Status::Error { .. }));
    assert_eq!(
        span_attribute(dial, "openshell.request.failure_reason")
            .unwrap()
            .as_str(),
        "upstream_connect_failed"
    );
    let root = spans
        .iter()
        .find(|span| span.name == "openshell.http.request")
        .unwrap();
    assert!(matches!(root.status, Status::Error { .. }));
    assert_eq!(
        span_attribute(root, "openshell.request.outcome")
            .unwrap()
            .as_str(),
        "failed"
    );
    assert_eq!(
        span_attribute(root, "openshell.request.failure_reason")
            .unwrap()
            .as_str(),
        "upstream_connect_failed"
    );
    assert_eq!(
        span_attribute(root, "http.request.method")
            .unwrap()
            .as_str(),
        "POST"
    );
    assert!(!format!("{spans:?}").contains("DO-NOT-RECORD-ERROR"));
    capture.shutdown();
}

#[tokio::test]
async fn a_cancelled_stage_drops_its_future_and_closes_with_a_bounded_reason() {
    use opentelemetry::trace::Status;
    use opentelemetry_sdk::trace::Sampler;
    use std::sync::atomic::AtomicBool;

    struct Dropped(Arc<AtomicBool>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    let dropped = Arc::new(AtomicBool::new(false));
    let capture = RequestTracing::new(Some(Sampler::AlwaysOn));
    scope_connection(async {
        let correlation = RequestCorrelation::new(&request(), &context());
        let mut pending = Box::pin(correlation.run_stage(
            RequestStage::Response,
            HttpOutcome::UpstreamError,
            "response_failed",
            async {
                let _drop = Dropped(Arc::clone(&dropped));
                std::future::pending::<Result<(), &str>>().await
            },
        ));
        assert!(futures::poll!(&mut pending).is_pending());
        drop(pending);
        assert!(dropped.load(Ordering::Relaxed));
    })
    .with_subscriber(capture.subscriber())
    .await;
    assert!(!is_inspected_request());
    let spans = capture.spans();
    let response = spans
        .iter()
        .find(|span| span.name == "openshell.http.response")
        .unwrap();
    assert!(matches!(response.status, Status::Error { .. }));
    assert_eq!(
        span_attribute(response, "openshell.request.failure_reason")
            .unwrap()
            .as_str(),
        "cancelled"
    );
    let root = spans
        .iter()
        .find(|span| span.name == "openshell.http.request")
        .unwrap();
    assert!(matches!(root.status, Status::Error { .. }));
    assert_eq!(
        span_attribute(root, "openshell.request.outcome")
            .unwrap()
            .as_str(),
        "incomplete"
    );
    capture.shutdown();
}

#[tokio::test]
async fn captured_terminal_errors_keep_request_attribution_after_the_guard_drops() {
    use opentelemetry::trace::Status;
    use opentelemetry_sdk::trace::Sampler;

    for sampler in [Some(Sampler::AlwaysOn), Some(Sampler::AlwaysOff), None] {
        let sampled = matches!(sampler, Some(Sampler::AlwaysOn));
        let capture = RequestTracing::new(sampler);
        scope_connection(async {
            let correlation = RequestCorrelation::with_request_id(
                &request(),
                &context(),
                "failed-request".into(),
            );
            correlation.emit(allowed());
            correlation.record_failure(HttpOutcome::UpstreamError, "upstream_send_failed");
            let original = miette::miette!("original transfer error").wrap_err("transfer failed");
            let original_chain: Vec<_> = original.chain().map(ToString::to_string).collect();
            let captured = correlation.capture_error(original);
            assert_eq!(captured.to_string(), "transfer failed");
            assert_eq!(
                captured
                    .chain()
                    .skip(1)
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
                original_chain
            );
            let captured = correlation.capture_error(captured);
            assert_eq!(captured.chain().count(), original_chain.len() + 1);
            drop(correlation);
            assert!(!is_inspected_request());

            let next =
                RequestCorrelation::with_request_id(&request(), &context(), "next-request".into());
            emit_error_event(deny(), &captured);
            emit_error_event(
                DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
                    .finding_info(openshell_ocsf::FindingInfo::new(
                        "transfer-failed",
                        "Transfer failed",
                    ))
                    .build(),
                &captured,
            );
            crate::telemetry::emit_decision([allowed()], None);
            drop(next);
        })
        .with_subscriber(capture.subscriber())
        .await;
        let events = capture.events.json_events();
        assert_eq!(events.len(), 4);
        for (index, event) in events[..3].iter().enumerate() {
            assert_eq!(event["metadata"]["correlation_uid"], "failed-request");
            assert_eq!(event["unmapped"]["request_sequence"], index + 1);
        }
        assert_eq!(events[1]["trace"]["uid"].is_string(), sampled);
        assert_eq!(events[2]["unmapped"]["http_event_kind"], "finding");
        assert_eq!(events[3]["metadata"]["correlation_uid"], "next-request");
        assert_eq!(events[3]["unmapped"]["request_sequence"], 1);
        assert!(
            !capture
                .created_span_names()
                .contains(&"supervisor.egress.deny")
        );
        if sampled {
            let spans = capture.spans();
            let failed = spans
                .iter()
                .find(|span| {
                    span_attribute(span, "openshell.request.id")
                        .is_some_and(|id| id.as_str() == "failed-request")
                })
                .unwrap();
            assert!(matches!(failed.status, Status::Error { .. }));
            assert_eq!(
                span_attribute(failed, "openshell.request.failure_reason")
                    .unwrap()
                    .as_str(),
                "upstream_send_failed"
            );
        }
        capture.shutdown();
    }
}

#[test]
fn failed_denial_delivery_marks_the_root_failed_without_replacing_the_reason() {
    let capture = RequestTracing::new(Some(opentelemetry_sdk::trace::Sampler::AlwaysOn));
    tracing::subscriber::with_default(capture.subscriber(), || {
        let correlation = RequestCorrelation::new(&request(), &context());
        correlation.record_failure(HttpOutcome::Denied, "request_middleware_denied");
        let error = correlation.capture_error(miette::miette!("response write failed"));
        drop(correlation);
        drop(error);
    });
    let spans = capture.spans();
    let root = spans
        .iter()
        .find(|span| span.name == "openshell.http.request")
        .unwrap();
    assert_eq!(
        span_attribute(root, "openshell.request.outcome")
            .unwrap()
            .as_str(),
        "failed"
    );
    assert_eq!(
        span_attribute(root, "openshell.request.failure_reason")
            .unwrap()
            .as_str(),
        "request_middleware_denied"
    );
    assert!(matches!(
        root.status,
        opentelemetry::trace::Status::Error { .. }
    ));
    capture.shutdown();
}

#[test]
fn an_unscoped_terminal_error_does_not_borrow_a_finished_request() {
    let capture = OcsfCapture::default();
    let _subscriber = capture.install();
    let correlation = RequestCorrelation::new(&request(), &context());
    let error = correlation.capture_error(miette::miette!("request error"));
    drop(correlation);
    emit_error_event(allowed(), &error);
    emit_error_event(allowed(), &miette::miette!("unrelated connection error"));
    let records = capture.json_events();
    assert!(records[0]["metadata"]["correlation_uid"].is_string());
    assert!(records[1]["metadata"]["correlation_uid"].is_null());
    assert!(records[1]["unmapped"]["request_sequence"].is_null());
}

#[tokio::test]
async fn nested_connection_scopes_share_the_active_request_with_a_sibling_watcher() {
    let capture = OcsfCapture::default();
    let _subscriber = capture.install();
    scope_connection(async {
        let (ready, started) = tokio::sync::oneshot::channel();
        let relay = scope_connection(async {
            let _request = RequestCorrelation::with_request_id(
                &request(),
                &context(),
                "active-request".into(),
            );
            ready.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        let watcher = async {
            started.await.unwrap();
            assert!(is_inspected_request());
            record_current_failure(HttpOutcome::Denied, "policy_reloaded");
            crate::telemetry::emit_decision([deny()], None);
        };
        tokio::select! {
            () = relay => unreachable!(),
            () = watcher => {},
        }
        assert!(!is_inspected_request());
        crate::telemetry::emit_decision([allowed()], None);
    })
    .await;
    let records = capture.json_events();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["metadata"]["correlation_uid"], "active-request");
    assert_eq!(records[0]["unmapped"]["request_sequence"], 1);
    assert!(records[1]["metadata"]["correlation_uid"].is_null());
}
