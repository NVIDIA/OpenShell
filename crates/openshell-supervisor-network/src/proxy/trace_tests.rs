// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::telemetry::tests::{
    assert_deny_resolves, assert_no_deny, deny_spans, exported, span_attribute,
};
use opentelemetry_proto::tonic::common::v1::any_value::Value;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paired_credential_denial_shares_one_deny_span() {
    let (events, received) = exported("warn", || {
        emit_credential_endpoint_mismatch(
            "POST",
            "blocked.example",
            443,
            "credential-policy",
            &tracing::Span::none(),
        );
    })
    .await;
    assert_eq!(events.len(), 2);
    assert_eq!(received.spans.len(), 1);
    assert_deny_resolves(&events, &received, true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_credential_denials_keep_decision_spans_separate() {
    for level in ["warn", "debug"] {
        let (events, received) = exported(level, || {
            let connect =
                egress::connect_span(&EgressIntent::connect("blocked.example".to_string(), 443));
            // The FORWARD path passes its saved connect span without entering it.
            for _ in 0..2 {
                emit_credential_endpoint_mismatch(
                    "POST",
                    "blocked.example",
                    443,
                    "credential-policy",
                    &connect,
                );
            }
            let allowed = NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .action(ActionId::Allowed)
                .dst_endpoint(Endpoint::from_domain("allowed.example", 443))
                .build();
            egress_emit!(allowed);
        })
        .await;

        assert_eq!(events.len(), 5);
        assert_deny_resolves(&events[..4], &received, level == "warn");
        assert!(events[4].get("trace").is_none(), "deny context must exit");
        let denies = deny_spans(&received);
        assert_eq!(denies.len(), 2);
        assert_ne!(denies[0].span_id, denies[1].span_id);
        assert_eq!(received.spans.len(), if level == "debug" { 3 } else { 2 });
        if level == "debug" {
            let connect = received
                .spans
                .iter()
                .find(|span| span.name == "supervisor.egress.connect")
                .unwrap();
            for deny in denies {
                assert_eq!(deny.trace_id, connect.trace_id);
                assert_eq!(deny.parent_span_id, connect.span_id);
            }
            assert_eq!(events[0]["trace"]["uid"], events[2]["trace"]["uid"]);
        } else {
            assert_ne!(events[0]["trace"]["uid"], events[2]["trace"]["uid"]);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn network_class_forward_rejections_have_no_deny_trace() {
    let (events, received) = exported("warn", || {
        let Err(error) =
            prepare_forward_target("/%zz", crate::l7::path::CanonicalizeOptions::default())
        else {
            panic!("invalid escape must be rejected");
        };
        egress_emit!(build_forward_rejection_event(
            "blocked.example",
            443,
            format!("FORWARD rejecting non-canonical request-target: {error}")
        ));
    })
    .await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["action_id"], 2);
    assert_no_deny(&events, &received);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forward_denials_use_the_saved_connect_parent() {
    for level in ["warn", "debug"] {
        let (events, received) = crate::telemetry::tests::exported_over_otlp(level, || {
            let intent = EgressIntent::connect("blocked.example".to_string(), 443);
            let connect = egress::connect_span(&intent);
            let decision = EgressDecision {
                intent,
                action: NetworkAction::Allow {
                    matched_policy: None,
                },
                policy_generation: 1,
                identity: ProcessIdentityEvidence::Available,
                endpoint: EndpointDecision::default(),
                binary: None,
                binary_pid: None,
                ancestors: vec![],
                cmdline_paths: vec![],
            };
            let denial = DestinationDenial {
                kind: DestinationDenialKind::InternalAddress,
                reason: "private destination".to_string(),
            };
            let mut output = Vec::new();
            futures::executor::block_on(deny_forward_destination(
                &mut output,
                &connect,
                &denial,
                "127.0.0.1:41000".parse().unwrap(),
                "POST",
                "blocked.example",
                443,
                "/",
                "curl",
                "42",
                "-",
                "curl",
                "forward-policy",
                &decision,
                None,
                None,
            ))
            .unwrap();
            assert!(output.starts_with(b"HTTP/1.1 403 Forbidden"));
        })
        .await;
        assert_eq!(events.len(), 1);
        assert_deny_resolves(&events, &received, level == "warn");
        let denies = deny_spans(&received);
        assert_eq!(denies.len(), 1);
        if level == "debug" {
            let connect = received
                .spans
                .iter()
                .find(|span| span.name == "supervisor.egress.connect")
                .unwrap();
            let deny = denies[0];
            assert_eq!(deny.parent_span_id, connect.span_id);
            assert_eq!(events[0]["trace"]["uid"], hex::encode(&connect.trace_id));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forward_evaluation_error_keeps_the_http_decision_policy_context() {
    for level in ["warn", "debug"] {
        for mode in [
            crate::l7::EnforcementMode::Audit,
            crate::l7::EnforcementMode::Enforce,
        ] {
            let enforced = mode == crate::l7::EnforcementMode::Enforce;
            let (events, received) = exported(level, || {
                let connect = egress::connect_span(&EgressIntent::forward_http(
                    "blocked.example".to_string(),
                    443,
                ));
                let decision = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
                    .activity(ActivityId::Other)
                    .action(if enforced {
                        ActionId::Denied
                    } else {
                        ActionId::Allowed
                    })
                    .disposition(if enforced {
                        DispositionId::Blocked
                    } else {
                        DispositionId::Allowed
                    })
                    .http_request(HttpRequest::new(
                        "GET",
                        OcsfUrl::new("http", "blocked.example", "/", 443),
                    ))
                    .dst_endpoint(Endpoint::from_domain("blocked.example", 443))
                    .firewall_rule("forward-policy", "l7")
                    .build();
                let error = build_forward_l7_evaluation_error(
                    "blocked.example",
                    443,
                    mode,
                    "evaluation unavailable",
                );
                // Use the same grouping as the forward-proxy production path.
                emit_forward_l7_decision(decision, Some(error), &connect);
            })
            .await;

            assert_eq!(events.len(), 2);
            let http_decision = events
                .iter()
                .find(|event| event["class_uid"] == 4002)
                .unwrap();
            let evaluation_error = events
                .iter()
                .find(|event| event["class_uid"] == 4001)
                .unwrap();
            let denies = deny_spans(&received);
            if enforced {
                assert_eq!(denies.len(), 1);
                assert_eq!(received.spans.len(), if level == "debug" { 2 } else { 1 });
                assert_eq!(http_decision["action_id"], 2);
                assert_eq!(evaluation_error["action_id"], 2);
                assert_deny_resolves(&events, &received, level == "warn");
                let attribute = |key: &str| span_attribute(denies[0], key);
                assert_eq!(
                    attribute("openshell.policy.name"),
                    Some(&Value::StringValue("forward-policy".to_string())),
                    "the shared deny span must retain the HTTP decision's policy name"
                );
                assert_eq!(
                    attribute("server.address"),
                    Some(&Value::StringValue("blocked.example".to_string()))
                );
                assert_eq!(attribute("ocsf.class_uid"), Some(&Value::IntValue(4002)));
                // This production decision currently has no status_detail.
                assert!(attribute("openshell.policy.reason").is_none());
                if level == "debug" {
                    let connect = received
                        .spans
                        .iter()
                        .find(|span| span.name == "supervisor.egress.connect")
                        .unwrap();
                    assert_eq!(denies[0].parent_span_id, connect.span_id);
                    assert_eq!(denies[0].trace_id, connect.trace_id);
                }
            } else {
                assert_eq!(http_decision["action_id"], 1);
                assert_eq!(evaluation_error["action_id"], 99);
                assert_no_deny(&events, &received);
            }
        }
    }
}
