// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::telemetry::tests::{assert_deny_resolves, exported};
use opentelemetry_proto::tonic::common::v1::any_value::Value;

fn emit_staged_policy_deny(debug: bool) {
    let intent = EgressIntent::connect("blocked.example".to_string(), 443);
    let connect = egress::connect_span(&intent);
    assert_eq!(connect.is_disabled(), !debug);
    connect.in_scope(|| {
        egress::traced_authorization(
            intent,
            |intent| EgressDecision {
                intent,
                action: NetworkAction::Deny {
                    reason: "not permitted".to_string(),
                },
                policy_generation: 1,
                identity: ProcessIdentityEvidence::Unavailable(
                    IdentityUnavailableReason::LookupFailed,
                ),
                endpoint: EndpointDecision::default(),
                binary: None,
                binary_pid: None,
                ancestors: vec![],
                cmdline_paths: vec![],
            },
            |decision| decision,
        );
    });
    // Authorization has exited. The actual staged L4 emission must enter its
    // own INFO deny span, retaining the saved DEBUG parent when it is enabled.
    emit_staged_transparent_denial(
        Some(&connect),
        "192.0.2.1:443".parse().unwrap(),
        Some("blocked.example"),
        &Err(ResolveError::Failed("unavailable".to_string())),
        "not permitted",
        "transparent_tcp_policy_denied",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_level_l4_deny_uid_resolves_to_one_span_root_trace() {
    let (events, received) = exported("warn", || emit_staged_policy_deny(false)).await;
    assert_eq!(events.len(), 1);
    assert_deny_resolves(&events, &received, true);
    assert_eq!(received.spans.len(), 1);
    assert_eq!(events[0]["class_uid"], 4001);
    let attributes = received.spans[0]
        .attributes
        .iter()
        .map(|kv| {
            (
                kv.key.as_str(),
                kv.value.as_ref().unwrap().value.as_ref().unwrap(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        attributes["openshell.policy.decision"],
        &Value::StringValue("deny".to_string())
    );
    assert_eq!(
        attributes["server.address"],
        &Value::StringValue("blocked.example".to_string())
    );
    assert_eq!(attributes["server.port"], &Value::IntValue(443));
    assert_eq!(
        attributes["openshell.policy.reason"],
        &Value::StringValue("transparent_tcp_policy_denied".to_string())
    );
    assert!(!attributes.contains_key("openshell.policy.name"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn debug_level_deny_retains_connect_and_authorization_trace() {
    let (events, received) = exported("debug", || emit_staged_policy_deny(true)).await;
    assert_eq!(events.len(), 1);
    assert_eq!(
        received
            .spans
            .iter()
            .filter(|span| span.name == "supervisor.egress.deny")
            .count(),
        1
    );
    assert_deny_resolves(&events, &received, false);
    let connect = received
        .spans
        .iter()
        .find(|span| span.name == "supervisor.egress.connect")
        .unwrap();
    let deny = received
        .spans
        .iter()
        .find(|span| span.name == "supervisor.egress.deny")
        .unwrap();
    let authorize = received
        .spans
        .iter()
        .find(|span| span.name == "supervisor.egress.authorize")
        .unwrap();
    assert_eq!(deny.trace_id, connect.trace_id);
    assert_eq!(deny.parent_span_id, connect.span_id);
    assert_eq!(authorize.parent_span_id, connect.span_id);
    assert_eq!(authorize.trace_id, connect.trace_id);
    assert_eq!(events[0]["trace"]["uid"], hex::encode(&connect.trace_id));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paired_credential_denial_shares_one_deny_span() {
    let (events, received) = exported("warn", || {
        emit_credential_endpoint_mismatch("POST", "blocked.example", 443, "credential-policy");
    })
    .await;
    assert_eq!(events.len(), 2);
    assert_eq!(received.spans.len(), 1);
    assert_eq!(events[0]["trace"]["uid"], events[1]["trace"]["uid"]);
    assert_deny_resolves(&events, &received, true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_credential_denials_keep_decision_spans_separate() {
    for level in ["warn", "debug"] {
        let (events, received) = exported(level, || {
            let connect =
                egress::connect_span(&EgressIntent::connect("blocked.example".to_string(), 443));
            connect.in_scope(|| {
                for _ in 0..2 {
                    emit_credential_endpoint_mismatch(
                        "POST",
                        "blocked.example",
                        443,
                        "credential-policy",
                    );
                }
            });
            let allowed = NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .action(ActionId::Allowed)
                .dst_endpoint(Endpoint::from_domain("allowed.example", 443))
                .build();
            crate::telemetry::emit(allowed, None, false);
        })
        .await;

        assert_eq!(events.len(), 5);
        assert_deny_resolves(&events[..4], &received, level == "warn");
        for pair in events[..4].chunks_exact(2) {
            assert_eq!(pair[0]["trace"]["uid"], pair[1]["trace"]["uid"]);
        }
        assert!(events[4].get("trace").is_none(), "deny context must exit");
        let denies = received
            .spans
            .iter()
            .filter(|span| span.name == "supervisor.egress.deny")
            .collect::<Vec<_>>();
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
async fn noncanonical_forward_rejections_have_a_deny_trace() {
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
    assert_deny_resolves(&events, &received, true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_and_forward_denials_use_the_saved_connect_parent() {
    for level in ["warn", "debug"] {
        for forward in [false, true] {
            let (events, received) = exported(level, || {
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
                if forward {
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
                } else {
                    futures::executor::block_on(deny_connect_destination(
                        &mut output,
                        &connect,
                        &denial,
                        "127.0.0.1:41000".parse().unwrap(),
                        "blocked.example",
                        443,
                        "curl",
                        "42",
                        "-",
                        "curl",
                        &decision,
                        &None,
                        &None,
                    ))
                    .unwrap();
                }
                assert!(output.starts_with(b"HTTP/1.1 403 Forbidden"));
            })
            .await;
            assert_eq!(events.len(), 1);
            assert_deny_resolves(&events, &received, level == "warn");
            assert_eq!(
                received
                    .spans
                    .iter()
                    .filter(|span| span.name == "supervisor.egress.deny")
                    .count(),
                1
            );
            if level == "debug" {
                let connect = received
                    .spans
                    .iter()
                    .find(|span| span.name == "supervisor.egress.connect")
                    .unwrap();
                let deny = received
                    .spans
                    .iter()
                    .find(|span| span.name == "supervisor.egress.deny")
                    .unwrap();
                assert_eq!(deny.parent_span_id, connect.span_id);
                assert_eq!(events[0]["trace"]["uid"], hex::encode(&connect.trace_id));
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evaluation_errors_only_trace_enforced_denials() {
    for mode in [
        crate::l7::EnforcementMode::Audit,
        crate::l7::EnforcementMode::Enforce,
    ] {
        let (events, received) = exported("warn", || {
            egress_emit!(build_forward_l7_evaluation_error(
                "blocked.example",
                443,
                mode,
                "evaluation unavailable"
            ));
            tracing::info_span!("test.export-barrier").in_scope(|| {});
        })
        .await;
        assert_eq!(events.len(), 1);
        if mode == crate::l7::EnforcementMode::Enforce {
            assert_eq!(events[0]["action_id"], 2);
            assert_deny_resolves(&events, &received, true);
        } else {
            assert!(events[0].get("trace").is_none());
            assert_eq!(
                received
                    .spans
                    .iter()
                    .filter(|span| span.name == "supervisor.egress.deny")
                    .count(),
                0
            );
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
                if !enforced {
                    tracing::info_span!("test.export-barrier").in_scope(|| {});
                }
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
            let denies = received
                .spans
                .iter()
                .filter(|span| span.name == "supervisor.egress.deny")
                .collect::<Vec<_>>();
            if enforced {
                assert_eq!(denies.len(), 1);
                assert_eq!(received.spans.len(), if level == "debug" { 2 } else { 1 });
                assert_eq!(http_decision["action_id"], 2);
                assert_eq!(evaluation_error["action_id"], 2);
                assert_eq!(events[0]["trace"]["uid"], events[1]["trace"]["uid"]);
                assert_deny_resolves(&events, &received, level == "warn");
                let attribute = |key: &str| {
                    denies[0]
                        .attributes
                        .iter()
                        .find(|attribute| attribute.key == key)
                        .and_then(|attribute| attribute.value.as_ref()?.value.as_ref())
                };
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
                assert!(denies.is_empty());
                assert_eq!(http_decision["action_id"], 1);
                assert_eq!(evaluation_error["action_id"], 99);
                for event in events {
                    assert!(event.get("trace").is_none());
                }
            }
        }
    }
}
