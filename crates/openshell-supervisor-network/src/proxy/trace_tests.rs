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
}
