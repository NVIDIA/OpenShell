// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_support::request_tracing::RequestTracing;
use openshell_ocsf::{ActivityId, NetworkActivityBuilder, Process};
use tokio::io::AsyncWriteExt as _;

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
        policy_name: "protected-api".into(),
        ..Default::default()
    }
}

fn allowed() -> OcsfEvent {
    HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .http_request(HttpRequest::new("GET", context().ocsf_url("/data")))
        .actor_process(Process::new("curl", 42).with_cmd_line("curl /data"))
        .firewall_rule("protected-api", "l7")
        .action(ActionId::Allowed)
        .disposition(DispositionId::Allowed)
        .status(StatusId::Success)
        .message("HTTP request admitted by policy")
        .status_detail("matched_rule")
        .build()
}

fn denied() -> OcsfEvent {
    HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .http_request(HttpRequest {
            http_method: "GET".parse().unwrap(),
            url: None,
        })
        .http_response(HttpResponse { code: 403 })
        .firewall_rule("protected-api", "credential-binding")
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .status(StatusId::Failure)
        .severity(SeverityId::High)
        .message("Credential use denied")
        .status_detail("credential_endpoint_mismatch")
        .build()
}

fn http_events(capture: &openshell_ocsf::test_support::OcsfCapture) -> Vec<serde_json::Value> {
    capture
        .json_events()
        .into_iter()
        .filter(|event| event["class_uid"] == 4002)
        .collect()
}

#[derive(Clone, Copy)]
enum InvocationOutcome {
    Pass,
    Transform,
    FailOpen,
    Deny,
}

fn invocation(name: &str, phase: &str, outcome: InvocationOutcome) -> OcsfEvent {
    let (action, disposition, status) = match outcome {
        InvocationOutcome::Pass | InvocationOutcome::Transform => {
            (ActionId::Allowed, DispositionId::Allowed, StatusId::Success)
        }
        InvocationOutcome::FailOpen => (ActionId::Other, DispositionId::Error, StatusId::Failure),
        InvocationOutcome::Deny => (ActionId::Denied, DispositionId::Blocked, StatusId::Failure),
    };
    HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .http_request(HttpRequest::new("POST", context().ocsf_url("/observed")))
        .http_response(HttpResponse { code: 200 })
        .firewall_rule("middleware-policy", "supervisor-middleware")
        .action(action)
        .disposition(disposition)
        .status(status)
        .severity(SeverityId::Medium)
        .status_detail(name)
        .message(format!("middleware invocation {name}"))
        .unmapped("http_event_kind", "middleware_invocation")
        .unmapped("middleware_phase", phase)
        .unmapped("middleware_config", name)
        .unmapped(
            "transformed",
            matches!(outcome, InvocationOutcome::Transform),
        )
        .unmapped("failed", matches!(outcome, InvocationOutcome::FailOpen))
        .build()
}

#[test]
fn middleware_invocations_are_retained_without_seeding_or_poisoning_the_request() {
    use opentelemetry_sdk::trace::Sampler;

    for sampler in [Some(Sampler::AlwaysOn), Some(Sampler::AlwaysOff), None] {
        let sampled = matches!(sampler, Some(Sampler::AlwaysOn));
        for phase in ["request", "response"] {
            let capture = RequestTracing::new(sampler.clone());
            let mut expected = Vec::new();
            tracing::subscriber::with_default(capture.subscriber(), || {
                let correlation = RequestCorrelation::new(&request(), &context());
                for (name, outcome) in [
                    ("pass", InvocationOutcome::Pass),
                    ("redact", InvocationOutcome::Transform),
                    ("optional", InvocationOutcome::FailOpen),
                ] {
                    let event = invocation(name, phase, outcome);
                    expected.push(event.to_json().unwrap());
                    correlation.emit(event);
                }
                correlation.emit(allowed());
                correlation.response_selected(200);
            });
            let events = http_events(&capture.events);
            assert_eq!(events.len(), 4);
            for (event, expected) in events[..3].iter().zip(&expected) {
                for field in [
                    "action",
                    "disposition",
                    "status",
                    "message",
                    "status_detail",
                    "http_request",
                    "http_response",
                    "firewall_rule",
                    "unmapped",
                ] {
                    assert_eq!(event[field], expected[field], "{field}");
                }
                assert_eq!(event["trace"]["uid"].is_string(), sampled);
            }
            let primary = &events[3];
            assert_eq!(primary["unmapped"]["http_event_kind"], "request");
            assert_eq!(primary["action"], "Allowed");
            assert_eq!(primary["status"], "Success");
            assert_eq!(primary["http_request"]["url"]["path"], "/data");
            assert_eq!(primary["actor"]["process"]["pid"], 42);
            assert_eq!(primary["firewall_rule"]["type"], "l7");
            assert!(events.iter().all(|event| {
                event["metadata"]["correlation_uid"] == primary["metadata"]["correlation_uid"]
            }));
            assert!(
                !capture
                    .created_span_names()
                    .contains(&"supervisor.egress.deny")
            );
            let spans = capture.spans();
            assert_eq!(spans.len(), usize::from(sampled));
            if sampled {
                let fields: std::collections::BTreeMap<_, _> = spans[0]
                    .attributes
                    .iter()
                    .map(|attribute| (attribute.key.as_str(), attribute.value.to_string()))
                    .collect();
                assert_eq!(fields["openshell.request.outcome"], "allowed");
                assert_eq!(fields["http.response.status_code"], "200");
            }
            capture.shutdown();
        }
    }
}

#[test]
fn denied_middleware_invocation_only_overlays_the_preheader_denial_summary() {
    for seeded in [false, true] {
        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let _subscriber = capture.install();
        let correlation = RequestCorrelation::new(&request(), &context());
        if seeded {
            correlation.emit(allowed());
        }
        correlation.record_upstream_status(200);
        correlation.emit(invocation("guard", "response", InvocationOutcome::Deny));
        correlation.response_selected(403);
        drop(correlation);
        let events = http_events(&capture);
        assert_eq!(events.len(), 2);
        let observation = &events[0];
        let primary = &events[1];
        assert_eq!(
            observation["unmapped"]["http_event_kind"],
            "middleware_invocation"
        );
        assert_eq!(observation["http_response"]["code"], 200);
        assert_eq!(observation["http_request"]["url"]["path"], "/observed");
        assert_eq!(primary["unmapped"]["http_event_kind"], "request");
        assert_eq!(primary["http_response"]["code"], 403);
        assert_eq!(primary["unmapped"]["upstream_response_code"], 200);
        assert_eq!(primary["http_request"]["url"]["path"], "/data");
        assert_eq!(primary["action"], "Denied");
        assert_eq!(primary["status"], "Failure");
        assert_eq!(primary["message"], "middleware invocation guard");
        assert_eq!(primary["status_detail"], "guard");
        if seeded {
            assert_eq!(primary["firewall_rule"]["type"], "l7");
            assert_eq!(primary["actor"]["process"]["pid"], 42);
        } else {
            assert!(primary.get("firewall_rule").is_none());
            assert!(primary.get("actor").is_none());
        }
    }
}

#[test]
fn late_middleware_invocations_do_not_consume_the_late_failure_budget() {
    use opentelemetry_sdk::trace::Sampler;

    for sampler in [Some(Sampler::AlwaysOn), Some(Sampler::AlwaysOff), None] {
        let sampled = matches!(sampler, Some(Sampler::AlwaysOn));
        for late_failure in [false, true] {
            let capture = RequestTracing::new(sampler.clone());
            tracing::subscriber::with_default(capture.subscriber(), || {
                let correlation = RequestCorrelation::new(&request(), &context());
                correlation.emit(allowed());
                correlation.response_selected(200);
                for (name, outcome) in [
                    ("optional", InvocationOutcome::FailOpen),
                    ("guard", InvocationOutcome::Deny),
                    ("pass", InvocationOutcome::Pass),
                ] {
                    correlation.emit(invocation(name, "response", outcome));
                }
                if late_failure {
                    correlation.emit(denied());
                    correlation.emit(denied());
                }
            });
            let events = http_events(&capture.events);
            assert_eq!(events.len(), 4 + usize::from(late_failure));
            assert_eq!(events[0]["unmapped"]["http_event_kind"], "request");
            assert_eq!(events[0]["action"], "Allowed");
            for event in &events[1..4] {
                assert_eq!(
                    event["unmapped"]["http_event_kind"],
                    "middleware_invocation"
                );
                assert_eq!(event["http_response"]["code"], 200);
            }
            if late_failure {
                assert!(events[4]["unmapped"].get("http_event_kind").is_none());
                assert_eq!(events[4]["status_detail"], "credential_endpoint_mismatch");
                assert_eq!(events[4]["http_response"]["code"], 200);
            }
            assert!(
                events
                    .iter()
                    .all(|event| event["metadata"]["correlation_uid"]
                        == events[0]["metadata"]["correlation_uid"])
            );
            assert!(
                !capture
                    .created_span_names()
                    .contains(&"supervisor.egress.deny")
            );
            let spans = capture.spans();
            assert_eq!(spans.len(), usize::from(sampled));
            if sampled {
                let fields: std::collections::BTreeMap<_, _> = spans[0]
                    .attributes
                    .iter()
                    .map(|attribute| (attribute.key.as_str(), attribute.value.to_string()))
                    .collect();
                assert_eq!(
                    fields["openshell.request.outcome"],
                    if late_failure { "denied" } else { "allowed" }
                );
                assert_eq!(fields["http.response.status_code"], "200");
            }
            capture.shutdown();
        }
    }
}

#[test]
fn audit_receipt_and_denial_are_independent_of_sampling_or_exporter() {
    use opentelemetry_sdk::trace::Sampler;

    crate::telemetry::tests::init_trace_extractor();
    for sampler in [Some(Sampler::AlwaysOn), Some(Sampler::AlwaysOff), None] {
        let sampled = matches!(sampler, Some(Sampler::AlwaysOn));
        let capture = RequestTracing::new(sampler);
        tracing::subscriber::with_default(capture.subscriber(), || {
            let correlation = RequestCorrelation::with_request_id(
                &request(),
                &context(),
                "00000000-0000-4000-8000-000000000001".into(),
            );
            correlation.emit(allowed());
            correlation.emit(denied());
            correlation.record_outcome(HttpOutcome::Denied);
            correlation.response_selected(403);
        });
        let events = http_events(&capture.events);
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(
            event["metadata"]["correlation_uid"],
            "00000000-0000-4000-8000-000000000001"
        );
        assert_eq!(event["action"], "Denied");
        assert_eq!(event["status"], "Failure");
        assert_eq!(event["http_response"]["code"], 403);
        assert_eq!(event["http_request"]["url"]["path"], "/data");
        assert_eq!(event["trace"]["uid"].is_string(), sampled);
        let spans = capture.spans();
        assert_eq!(spans.len(), usize::from(sampled));
        if sampled {
            assert_eq!(spans[0].name, "openshell.http.request");
            assert_eq!(
                event["trace"]["uid"],
                spans[0].span_context.trace_id().to_string()
            );
        }
        capture.shutdown();
    }
}

#[test]
fn finished_http_trace_is_not_retained_by_an_upgraded_session() {
    use opentelemetry_sdk::trace::Sampler;

    let capture = RequestTracing::new(Some(Sampler::AlwaysOn));
    tracing::subscriber::with_default(capture.subscriber(), || {
        let correlation = RequestCorrelation::new(&request(), &context());
        correlation.emit(allowed());
        correlation.response_selected(101);
        correlation.finish_http_trace();
        assert_eq!(capture.spans().len(), 1);
        assert!(correlation.trace_span().is_disabled());
        assert!(correlation.stage(RequestStage::UpstreamSend).is_disabled());
        correlation.finish_http_trace();
        drop(correlation);
        assert_eq!(capture.spans().len(), 1);
    });
    capture.shutdown();
}

#[test]
fn a_provider_without_an_exporter_still_emits_the_request_id_join() {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
    use tracing_subscriber::layer::SubscriberExt as _;

    crate::telemetry::tests::init_trace_extractor();
    let provider = SdkTracerProvider::builder()
        .with_sampler(Sampler::AlwaysOn)
        .build();
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry()
        .with(capture.clone())
        .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("no-exporter-test")));
    let mut id = None;
    tracing::subscriber::with_default(subscriber, || {
        let correlation = RequestCorrelation::new(&request(), &context());
        id = Some(correlation.request_id().to_owned());
        assert_eq!(
            correlation
                .stage(RequestStage::PolicyEvaluate)
                .in_scope(|| 42),
            42
        );
        correlation.emit(allowed());
        correlation.record_outcome(HttpOutcome::Allowed);
        correlation.response_selected(200);
    });
    let events = http_events(&capture);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["metadata"]["correlation_uid"], id.unwrap());
    assert_eq!(events[0]["http_response"]["code"], 200);
    assert_eq!(events[0]["action"], "Allowed");
    provider.shutdown().unwrap();
}

#[test]
fn request_ids_are_unique_canonical_uuids() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let first = RequestCorrelation::new(&request(), &context());
    let second = RequestCorrelation::new(&request(), &context());
    assert_ne!(first.request_id(), second.request_id());
    assert!(uuid::Uuid::parse_str(first.request_id()).is_ok());
    assert!(uuid::Uuid::parse_str(second.request_id()).is_ok());
}

#[tokio::test]
async fn primary_record_waits_for_final_response_headers_and_is_emitted_once_without_otel() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let correlation = RequestCorrelation::new(&request(), &context());
    let id = correlation.request_id().to_string();
    correlation.emit(allowed());
    let mut output = Vec::new();
    {
        let mut client = correlation.observe_response(&mut output);
        client
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n")
            .await
            .unwrap();
        assert!(capture.events().is_empty());
        client.write_all(b"\r\nbody").await.unwrap();
    }
    drop(correlation);
    let events = http_events(&capture);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["http_response"]["code"], 200);
    assert_eq!(events[0]["http_request"]["url"]["path"], "/data");
    assert_eq!(events[0]["action"], "Allowed");
    assert_eq!(events[0]["status"], "Success");
    assert_eq!(events[0]["actor"]["process"]["pid"], 42);
    assert_eq!(events[0]["metadata"]["correlation_uid"], id);
    assert!(events[0].get("trace").is_none());
    assert!(output.ends_with(b"\r\n\r\nbody"));
}

#[test]
fn later_credential_denial_preserves_policy_request_context() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let correlation = RequestCorrelation::new(&request(), &context());
    let id = correlation.request_id().to_string();
    correlation.emit(allowed());
    correlation.emit(denied());
    // A routine later middleware result cannot undo the denial.
    correlation.emit(allowed());
    correlation.response_selected(403);
    drop(correlation);
    let events = http_events(&capture);
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event["action"], "Denied");
    assert_eq!(event["disposition"], "Blocked");
    assert_eq!(event["status"], "Failure");
    assert_eq!(event["severity"], "High");
    assert_eq!(event["status_detail"], "credential_endpoint_mismatch");
    assert_eq!(event["http_response"]["code"], 403);
    assert_eq!(event["http_request"]["url"]["path"], "/data");
    assert_eq!(event["firewall_rule"]["type"], "l7");
    assert_eq!(event["actor"]["process"]["pid"], 42);
    assert_eq!(event["metadata"]["correlation_uid"], id);
}

#[test]
fn local_refusals_and_upstream_failures_are_distinct() {
    for (outcome, blocked, code, expected_action, expected_disposition) in [
        (HttpOutcome::PlatformError, true, 503, "Denied", "Blocked"),
        (HttpOutcome::UpstreamError, false, 502, "Allowed", "Allowed"),
        (HttpOutcome::PlatformError, false, 502, "Allowed", "Allowed"),
    ] {
        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let _subscriber = capture.install();
        let correlation = RequestCorrelation::new(&request(), &context());
        correlation.emit(allowed());
        if blocked {
            correlation.record_enforcement_block();
        }
        correlation.record_outcome(outcome);
        correlation.response_selected(code);
        drop(correlation);
        let events = http_events(&capture);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["action"], expected_action);
        assert_eq!(events[0]["disposition"], expected_disposition);
        assert_eq!(events[0]["status"], "Failure");
        assert_eq!(events[0]["http_response"]["code"], code);
    }
}

#[test]
fn remote_api_error_does_not_become_a_policy_denial() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let correlation = RequestCorrelation::new(&request(), &context());
    correlation.emit(allowed());
    correlation.record_outcome(HttpOutcome::Allowed);
    correlation.response_selected(500);
    drop(correlation);
    let events = http_events(&capture);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["action"], "Allowed");
    assert_eq!(events[0]["status"], "Success");
    assert_eq!(events[0]["http_response"]["code"], 500);
}

#[test]
fn pre_policy_rejection_retains_reason_without_claiming_policy_admission() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let correlation = RequestCorrelation::new(&request(), &context());
    let id = correlation.request_id().to_string();
    correlation.emit(
        NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .activity(ActivityId::Other)
            .dst_endpoint(Endpoint::from_domain("example.test", 443))
            .action(ActionId::Denied)
            .disposition(DispositionId::Blocked)
            .status(StatusId::Failure)
            .severity(SeverityId::Medium)
            .status_detail("invalid_jsonrpc_request")
            .actor_process(Process::new("curl", 42))
            .build(),
    );
    correlation.record_enforcement_block();
    correlation.record_outcome(HttpOutcome::Denied);
    correlation.response_selected(400);
    drop(correlation);
    assert_eq!(capture.events().len(), 2);
    let events = http_events(&capture);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["http_request"]["url"]["path"], "/data");
    assert_eq!(events[0]["status_detail"], "invalid_jsonrpc_request");
    assert_eq!(
        events[0]["message"],
        "HTTP request rejected before policy evaluation"
    );
    assert_eq!(events[0]["action"], "Denied");
    assert_eq!(events[0]["actor"]["process"]["pid"], 42);
    assert!(events[0].get("firewall_rule").is_none());
    assert!(
        capture
            .json_events()
            .iter()
            .all(|event| event["metadata"]["correlation_uid"] == id)
    );
}

#[test]
fn late_failure_is_preserved_once_but_routine_late_records_are_not_duplicated() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let correlation = RequestCorrelation::new(&request(), &context());
    let id = correlation.request_id().to_string();
    correlation.emit(allowed());
    correlation.response_selected(200);
    correlation.emit(allowed());
    correlation.emit(denied());
    correlation.emit(denied());
    drop(correlation);
    let events = http_events(&capture);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["action"], "Allowed");
    assert_eq!(events[0]["http_response"]["code"], 200);
    assert_eq!(events[1]["action"], "Denied");
    assert_eq!(events[1]["status_detail"], "credential_endpoint_mismatch");
    assert_eq!(events[1]["http_response"]["code"], 200);
    assert!(
        events
            .iter()
            .all(|event| event["metadata"]["correlation_uid"] == id)
    );
}

#[test]
fn unfinished_request_retains_safe_path_without_inventing_a_rule() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let mut request = request();
    request.target = "/data?secret=SENTINEL-QUERY".into();
    let id;
    {
        let correlation = RequestCorrelation::new(&request, &context());
        id = correlation.request_id().to_string();
        let mut head = ResponseHead::default();
        head.accept(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n", &correlation);
        assert!(capture.events().is_empty());
    }
    let events = http_events(&capture);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["metadata"]["correlation_uid"], id);
    assert_eq!(events[0]["status_detail"], "request_incomplete");
    assert_eq!(events[0]["http_request"]["url"]["path"], "/data");
    assert!(events[0].get("http_response").is_none());
    assert!(events[0].get("firewall_rule").is_none());
    assert!(!events[0].to_string().contains("SENTINEL-QUERY"));
}

#[test]
fn workload_traceparent_does_not_supply_audit_trace_identity() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let mut request = request();
    request.raw_header = b"GET /data HTTP/1.1\r\nHost: example.test\r\ntraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n\r\n".to_vec();
    let correlation = RequestCorrelation::new(&request, &context());
    correlation.emit(allowed());
    correlation.response_selected(200);
    drop(correlation);
    let events = http_events(&capture);
    assert_eq!(events.len(), 1);
    assert!(events[0].get("trace").is_none());
    assert!(
        !events[0]
            .to_string()
            .contains("4bf92f3577b34da6a3ce929d0e0e4736")
    );
}

#[tokio::test]
async fn uninspected_response_and_events_preserve_legacy_behavior() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let correlation = RequestCorrelation::uninspected();
    assert!(uuid::Uuid::parse_str(correlation.request_id()).is_ok());
    let mut output = Vec::new();
    {
        let mut client = correlation.observe_response(&mut output);
        client
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    }
    assert!(capture.events().is_empty());
    let expected = allowed();
    correlation.emit(expected.clone());
    drop(correlation);
    assert_eq!(capture.events(), vec![expected]);
    assert_eq!(output, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
}

#[test]
fn policy_classification_fills_an_existing_forward_request_context() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let correlation = RequestCorrelation::new(&request(), &context());
    let seed = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .http_request(HttpRequest::new("GET", context().ocsf_url("/forward")))
        .actor_process(Process::new("python3", 77))
        .message("HTTP request awaiting inspection")
        .build();
    correlation.emit(seed);
    correlation.emit(allowed());
    correlation.response_selected(200);
    drop(correlation);
    let events = http_events(&capture);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["http_request"]["url"]["path"], "/forward");
    assert_eq!(events[0]["actor"]["process"]["pid"], 77);
    assert_eq!(events[0]["action"], "Allowed");
    assert_eq!(events[0]["status"], "Success");
    assert_eq!(events[0]["firewall_rule"]["type"], "l7");
    assert_eq!(events[0]["message"], "HTTP request admitted by policy");
}

#[test]
fn failure_reason_replaces_only_a_prior_success_reason() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let correlation = RequestCorrelation::new(&request(), &context());
    correlation.emit(allowed());
    correlation.record_rejection(
        503,
        HttpOutcome::PlatformError,
        Some("middleware_admission"),
    );
    correlation.response_selected(503);
    drop(correlation);
    let events = http_events(&capture);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["status_detail"], "middleware_admission");
    assert_eq!(events[0]["action"], "Denied");
    assert_eq!(events[0]["status"], "Failure");
}

#[test]
fn unfinished_admitted_request_does_not_keep_a_success_reason() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let correlation = RequestCorrelation::new(&request(), &context());
    let id = correlation.request_id().to_string();
    correlation.emit(allowed());
    drop(correlation);
    let events = http_events(&capture);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["action"], "Allowed");
    assert_eq!(events[0]["status"], "Failure");
    assert_eq!(events[0]["status_detail"], "request_incomplete");
    assert_eq!(events[0]["metadata"]["correlation_uid"], id);
    assert_eq!(events[0]["http_request"]["url"]["path"], "/data");
    assert_eq!(events[0]["actor"]["process"]["pid"], 42);
    assert!(events[0].get("http_response").is_none());
}

#[test]
fn late_fail_open_does_not_hide_a_later_blocking_failure() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let correlation = RequestCorrelation::new(&request(), &context());
    let id = correlation.request_id().to_string();
    correlation.emit(allowed());
    correlation.response_selected(200);
    correlation.emit(
        HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .http_request(HttpRequest::new("GET", context().ocsf_url("/data")))
            .action(ActionId::Other)
            .disposition(DispositionId::Allowed)
            .status(StatusId::Failure)
            .status_detail("middleware_fail_open")
            .build(),
    );
    correlation.emit(denied());
    drop(correlation);
    let events = http_events(&capture);
    assert_eq!(events.len(), 2);
    assert_eq!(events[1]["action"], "Denied");
    assert_eq!(events[1]["status_detail"], "credential_endpoint_mismatch");
    assert_eq!(events[1]["metadata"]["correlation_uid"], id);
    assert_eq!(events[1]["http_response"]["code"], 200);
}
