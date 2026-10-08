// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Legacy `EvaluateHttpRequest` behavior over the v0.1.2 wire.

use std::time::Duration;

use openshell_core::proto::{Decision, HeaderMutation, SupervisorMiddlewarePhase};
use openshell_supervisor_middleware_wire_fixture::proto::middleware::{
    ExistingHeaderAction, Finding, HttpRequestEvaluation, HttpRequestResult,
};
use openshell_supervisor_middleware_wire_fixture::{
    LegacyMiddlewareFixture, LegacyRpc, Reply, http_request_binding, results,
};
use tonic::Status;

use super::harness::{
    Engine, StageOutcome, connect, entry, registration, request, run_request, transcode,
};
use crate::{MIDDLEWARE_GRPC_MESSAGE_BYTES, OnError};

const GUARD: &str = "legacy-guard";

fn redacting_guard(request: &HttpRequestEvaluation) -> Reply<HttpRequestResult> {
    let body = String::from_utf8_lossy(&request.body);
    if body.contains("forbidden") {
        return HttpRequestResult {
            findings: vec![Finding {
                r#type: "guard.match".into(),
                label: "matched sk-secret-value".into(),
                count: 1,
                confidence: "high".into(),
                severity: "high".into(),
            }],
            ..results::deny("content_match")
        }
        .into();
    }
    if body.contains("secret") {
        return HttpRequestResult {
            header_mutations: vec![results::write_header(
                "x-guard",
                "redacted",
                ExistingHeaderAction::Overwrite,
            )],
            ..results::replace_body(body.replace("secret", "[FILTERED]"))
        }
        .into();
    }
    results::allow().into()
}

#[tokio::test]
async fn request_envelope_and_decisions_round_trip_over_the_v0_1_2_wire() {
    for engine in Engine::ALL {
        let fixture = LegacyMiddlewareFixture::new("compat/guard")
            .with_binding(http_request_binding(4096))
            .on_http_request(redacting_guard)
            .spawn()
            .await
            .expect("spawn fixture");
        let runner = connect(vec![registration(GUARD, &fixture, 4096)]).await;
        let chain = [entry("guard", GUARD, 10, OnError::FailClosed)];

        let redacted = run_request(
            engine,
            &runner,
            &chain,
            request(
                b"{\"note\":\"secret\"}",
                &[
                    ("content-type", "application/json"),
                    ("x-repeat", "one"),
                    ("x-repeat", "two"),
                ],
            ),
        )
        .await;
        assert!(redacted.allowed, "{engine:?}: {}", redacted.reason);
        assert_eq!(redacted.body, b"{\"note\":\"[FILTERED]\"}");
        let expected_mutation: HeaderMutation = transcode(&results::write_header(
            "x-guard",
            "redacted",
            ExistingHeaderAction::Overwrite,
        ));
        assert_eq!(redacted.header_mutations, vec![expected_mutation]);
        assert_eq!(
            redacted.stages,
            vec![StageOutcome {
                name: "guard".into(),
                decision: Decision::Allow,
                transformed: true,
                failed: false,
            }]
        );

        let evaluation = fixture.http_requests().remove(0);
        assert_eq!(
            evaluation.phase,
            SupervisorMiddlewarePhase::PreCredentials as i32
        );
        assert_eq!(evaluation.middleware_name, GUARD);
        assert_eq!(evaluation.body, b"{\"note\":\"secret\"}");
        let target = evaluation.target.expect("request target");
        assert_eq!(
            (
                target.scheme.as_str(),
                target.host.as_str(),
                target.port,
                target.method.as_str(),
                target.path.as_str(),
                target.query.as_str()
            ),
            (
                "https",
                "api.example.test",
                443,
                "POST",
                "/v1/messages",
                "trace=1"
            )
        );
        let context = evaluation.context.expect("request context");
        assert_eq!(context.request_id, "compat-request");
        assert_eq!(context.sandbox_id, "compat-sandbox-id");
        assert_eq!(context.sandbox, "compat-sandbox");
        assert_eq!(context.workspace, "compat-workspace");
        let headers: Vec<_> = evaluation
            .headers
            .iter()
            .map(|header| (header.name.as_str(), header.value.as_str()))
            .collect();
        assert_eq!(
            headers,
            [
                ("content-type", "application/json"),
                ("x-repeat", "one"),
                ("x-repeat", "two"),
            ],
            "headers arrive in wire order with repeated names kept"
        );
        assert_eq!(
            evaluation
                .config
                .expect("attachment config")
                .fields
                .get("attachment")
                .and_then(|value| value.kind.clone()),
            Some(prost_types::value::Kind::StringValue("guard".into()))
        );

        let denied = run_request(engine, &runner, &chain, request(b"forbidden", &[])).await;
        assert!(!denied.allowed);
        assert_eq!(denied.reason, "middleware_denied:guard:content_match");
        let denial = denied.denial.expect("explicit denial");
        assert_eq!(denial.config_name, "guard");
        assert_eq!(denial.reason_code.as_deref(), Some("content_match"));
        // Operator services keep only platform-owned finding text.
        assert_eq!(denied.findings.len(), 1);
        assert_eq!(denied.findings[0].0, "guard");
        assert_eq!(denied.findings[0].1.r#type, format!("{GUARD}.finding"));
        assert!(!denied.findings[0].1.label.contains("sk-secret-value"));
        assert_eq!(denied.findings[0].1.severity, "high");

        let unchanged = run_request(engine, &runner, &chain, request(b"plain", &[])).await;
        assert!(unchanged.allowed);
        assert_eq!(unchanged.body, b"plain");
        assert!(unchanged.header_mutations.is_empty());
        assert!(!unchanged.stages[0].transformed);
    }
}

#[tokio::test]
async fn later_stages_observe_earlier_header_mutations_in_chain_order() {
    for engine in Engine::ALL {
        let first = LegacyMiddlewareFixture::new("compat/first")
            .with_binding(http_request_binding(4096))
            .on_http_request(|_| {
                results::mutate_headers(vec![
                    results::write_header("x-shared", "first", ExistingHeaderAction::Overwrite),
                    results::write_header("x-trace", "first", ExistingHeaderAction::Append),
                    results::remove_header("x-drop"),
                ])
                .into()
            })
            .spawn()
            .await
            .expect("spawn first fixture");
        let second = LegacyMiddlewareFixture::new("compat/second")
            .with_binding(http_request_binding(4096))
            .on_http_request(|_| {
                results::mutate_headers(vec![
                    results::write_header("x-shared", "second", ExistingHeaderAction::Skip),
                    results::write_header("x-trace", "second", ExistingHeaderAction::Append),
                    results::write_header("x-second", "set", ExistingHeaderAction::Overwrite),
                ])
                .into()
            })
            .spawn()
            .await
            .expect("spawn second fixture");
        let runner = connect(vec![
            registration("legacy-first", &first, 4096),
            registration("legacy-second", &second, 4096),
        ])
        .await;
        // Declared out of order; policy order decides execution order.
        let chain = [
            entry("second", "legacy-second", 20, OnError::FailClosed),
            entry("first", "legacy-first", 10, OnError::FailClosed),
        ];

        let observed = run_request(
            engine,
            &runner,
            &chain,
            request(
                b"{}",
                &[
                    ("x-shared", "original"),
                    ("x-drop", "gone"),
                    ("x-keep", "kept"),
                ],
            ),
        )
        .await;
        assert!(observed.allowed, "{engine:?}: {}", observed.reason);
        assert_eq!(
            observed
                .stages
                .iter()
                .map(|stage| stage.name.as_str())
                .collect::<Vec<_>>(),
            ["first", "second"]
        );

        let second_saw: Vec<_> = second.http_requests()[0]
            .headers
            .iter()
            .map(|header| (header.name.clone(), header.value.clone()))
            .collect();
        // OVERWRITE removes every existing value and appends the new one.
        assert_eq!(
            second_saw,
            [
                ("x-keep".to_string(), "kept".to_string()),
                ("x-shared".to_string(), "first".to_string()),
                ("x-trace".to_string(), "first".to_string()),
            ],
            "the second stage sees the first stage's mutations applied"
        );

        let first_mutations: Vec<HeaderMutation> = [
            results::write_header("x-shared", "first", ExistingHeaderAction::Overwrite),
            results::write_header("x-trace", "first", ExistingHeaderAction::Append),
            results::remove_header("x-drop"),
        ]
        .iter()
        .map(transcode)
        .collect();
        let second_mutations: Vec<HeaderMutation> = [
            results::write_header("x-shared", "second", ExistingHeaderAction::Skip),
            results::write_header("x-trace", "second", ExistingHeaderAction::Append),
            results::write_header("x-second", "set", ExistingHeaderAction::Overwrite),
        ]
        .iter()
        .map(transcode)
        .collect();
        assert_eq!(
            observed.header_mutations,
            [first_mutations, second_mutations].concat(),
            "the relay replays every stage's mutations in chain order"
        );
    }
}

#[tokio::test]
async fn deny_short_circuits_later_stages() {
    for engine in Engine::ALL {
        let denying = LegacyMiddlewareFixture::new("compat/deny")
            .with_binding(http_request_binding(4096))
            .on_http_request(|_| {
                HttpRequestResult {
                    // A deny wins even when the rest of the result is unusable.
                    header_mutations: vec![results::write_header(
                        "authorization",
                        "forged",
                        ExistingHeaderAction::Overwrite,
                    )],
                    ..results::deny("blocked_by_guard")
                }
                .into()
            })
            .spawn()
            .await
            .expect("spawn denying fixture");
        let later = LegacyMiddlewareFixture::new("compat/later")
            .with_binding(http_request_binding(4096))
            .spawn()
            .await
            .expect("spawn later fixture");
        let runner = connect(vec![
            registration("legacy-deny", &denying, 4096),
            registration("legacy-later", &later, 4096),
        ])
        .await;
        let chain = [
            entry("deny", "legacy-deny", 10, OnError::FailOpen),
            entry("later", "legacy-later", 20, OnError::FailClosed),
        ];

        let observed = run_request(engine, &runner, &chain, request(b"{}", &[])).await;
        assert!(!observed.allowed);
        assert_eq!(observed.reason, "middleware_denied:deny:blocked_by_guard");
        assert!(observed.header_mutations.is_empty());
        assert!(later.http_requests().is_empty());
    }
}

#[tokio::test]
async fn over_capacity_bodies_skip_or_fail_each_stage_by_its_own_limit() {
    for engine in Engine::ALL {
        let small = LegacyMiddlewareFixture::new("compat/small")
            .with_binding(http_request_binding(16))
            .spawn()
            .await
            .expect("spawn small fixture");
        let large = LegacyMiddlewareFixture::new("compat/large")
            .with_binding(http_request_binding(64))
            .on_http_request(|_| results::replace_body("large-stage-ran").into())
            .spawn()
            .await
            .expect("spawn large fixture");
        let runner = connect(vec![
            registration("legacy-small", &small, 16),
            registration("legacy-large", &large, 64),
        ])
        .await;
        let body = [b'x'; 32];

        let skipped = run_request(
            engine,
            &runner,
            &[
                entry("small", "legacy-small", 10, OnError::FailOpen),
                entry("large", "legacy-large", 20, OnError::FailClosed),
            ],
            request(&body, &[]),
        )
        .await;
        assert!(skipped.allowed, "{engine:?}: {}", skipped.reason);
        assert_eq!(skipped.body, b"large-stage-ran");
        assert_eq!(
            skipped.stages[0],
            StageOutcome {
                name: "small".into(),
                decision: Decision::Allow,
                transformed: false,
                failed: true,
            }
        );
        assert!(small.http_requests().is_empty(), "fail_open skips the call");
        assert_eq!(large.http_requests().len(), 1);

        let denied = run_request(
            engine,
            &runner,
            &[entry("small", "legacy-small", 10, OnError::FailClosed)],
            request(&body, &[]),
        )
        .await;
        assert!(!denied.allowed);
        assert_eq!(
            denied.reason,
            "middleware_failed: request_body_over_capacity"
        );
        assert!(denied.denial.is_none());
        assert!(small.http_requests().is_empty());
    }
}

/// One way a legacy service can fail an evaluation, and the 0.1.x reason
/// `fail_closed` reports for it.
struct FailureCase {
    name: &'static str,
    reply: fn(&HttpRequestEvaluation) -> Reply<HttpRequestResult>,
    fail_closed_reason: &'static str,
}

const FAILURE_CASES: [FailureCase; 7] = [
    FailureCase {
        name: "grpc error status",
        reply: |_| Reply::Fail(Status::internal("guard crashed on sk-secret-value")),
        fail_closed_reason: "middleware_failed: external_service_error",
    },
    FailureCase {
        name: "slower than the registration timeout",
        reply: |_| Reply::Respond(results::allow()).after(Duration::from_secs(2)),
        fail_closed_reason: "middleware_failed: middleware_timeout",
    },
    FailureCase {
        name: "unspecified decision",
        reply: |_| HttpRequestResult::default().into(),
        fail_closed_reason: "middleware_failed: invalid_response_decision",
    },
    FailureCase {
        name: "invalid reason code",
        reply: |_| {
            HttpRequestResult {
                reason_code: "Not-Stable".into(),
                ..results::allow()
            }
            .into()
        },
        fail_closed_reason: "middleware_failed: response_reason_code_invalid",
    },
    FailureCase {
        name: "replacement over the binding limit",
        reply: |_| results::replace_body(vec![b'r'; 128]).into(),
        fail_closed_reason: "middleware_failed: response_body_over_capacity",
    },
    FailureCase {
        name: "protected header mutation",
        reply: |_| {
            results::mutate_headers(vec![results::write_header(
                "authorization",
                "forged",
                ExistingHeaderAction::Overwrite,
            )])
            .into()
        },
        fail_closed_reason: "middleware_failed: header_mutation_protected_header",
    },
    FailureCase {
        name: "result larger than the gRPC message limit",
        reply: |_| results::replace_body(vec![b'r'; MIDDLEWARE_GRPC_MESSAGE_BYTES]).into(),
        fail_closed_reason: "middleware_failed: external_service_error",
    },
];

#[tokio::test]
async fn service_failures_follow_on_error() {
    for engine in Engine::ALL {
        for case in &FAILURE_CASES {
            let fixture = LegacyMiddlewareFixture::new("compat/failing")
                .with_binding(http_request_binding(64))
                .on_http_request(case.reply)
                .spawn()
                .await
                .expect("spawn failing fixture");
            let runner = connect(vec![registration(GUARD, &fixture, 64)]).await;

            let open = run_request(
                engine,
                &runner,
                &[entry("guard", GUARD, 10, OnError::FailOpen)],
                request(b"original", &[]),
            )
            .await;
            assert!(open.allowed, "{engine:?} {}: {}", case.name, open.reason);
            assert_eq!(open.body, b"original", "{}", case.name);
            assert!(open.header_mutations.is_empty(), "{}", case.name);
            assert!(open.stages[0].failed, "{}", case.name);

            let closed = run_request(
                engine,
                &runner,
                &[entry("guard", GUARD, 10, OnError::FailClosed)],
                request(b"original", &[]),
            )
            .await;
            assert!(!closed.allowed, "{engine:?} {}", case.name);
            assert_eq!(closed.reason, case.fail_closed_reason, "{}", case.name);
            assert!(closed.denial.is_none(), "{}", case.name);
            assert!(
                !closed.reason.contains("sk-secret-value"),
                "service text never reaches the outcome"
            );
        }
    }
}

/// 0.1.x treats `UNIMPLEMENTED` like any other service error: `fail_open`
/// skips the stage and the manifest is not described again. The legacy
/// adapters fail closed on `UNIMPLEMENTED` regardless of `on_error`, so that
/// cutover changes the `fail_open` expectation below.
#[tokio::test]
async fn unimplemented_evaluate_http_request_follows_on_error() {
    for engine in Engine::ALL {
        let fixture = LegacyMiddlewareFixture::new("compat/swapped")
            .with_binding(http_request_binding(64))
            .on_http_request(|_| results::replace_body("inspected").into())
            .spawn()
            .await
            .expect("spawn fixture");
        let runner = connect(vec![registration(GUARD, &fixture, 64)]).await;
        let describes_after_registration = fixture.describe_requests().len();
        fixture.set_unimplemented(LegacyRpc::EvaluateHttpRequest, true);

        let open = run_request(
            engine,
            &runner,
            &[entry("guard", GUARD, 10, OnError::FailOpen)],
            request(b"original", &[]),
        )
        .await;
        assert!(open.allowed, "{engine:?}: {}", open.reason);
        assert_eq!(open.body, b"original");
        assert_eq!(
            open.stages,
            vec![StageOutcome {
                name: "guard".into(),
                decision: Decision::Allow,
                transformed: false,
                failed: true,
            }]
        );

        let closed = run_request(
            engine,
            &runner,
            &[entry("guard", GUARD, 10, OnError::FailClosed)],
            request(b"original", &[]),
        )
        .await;
        assert!(!closed.allowed);
        // The normalized reason does not distinguish UNIMPLEMENTED from any
        // other status.
        assert_eq!(closed.reason, "middleware_failed: external_service_error");
        assert_eq!(
            fixture.describe_requests().len(),
            describes_after_registration,
            "0.1.x keeps the cached manifest"
        );
        assert!(fixture.http_requests().is_empty());
    }
}

#[tokio::test]
async fn registration_negotiates_like_a_v0_1_2_peer() {
    let fixture = LegacyMiddlewareFixture::new("compat/guard")
        .with_binding(http_request_binding(64))
        .spawn()
        .await
        .expect("spawn fixture");
    let registry = crate::MiddlewareRegistry::connect_services(
        Vec::new(),
        vec![registration(GUARD, &fixture, 64)],
    )
    .await
    .expect("v0.1.2 service registers");
    let negotiated = &registry.negotiated_extensions()[0];
    assert_eq!(negotiated.configured_name, GUARD);
    assert_eq!(negotiated.implementation_name, "compat/guard");
    assert_eq!(
        (negotiated.protocol_major, negotiated.protocol_minor),
        (1, 0)
    );
    let gateway = fixture.describe_requests()[0]
        .gateway
        .clone()
        .expect("the registry sends gateway metadata");
    assert!(
        gateway
            .supported_capabilities
            .iter()
            .any(|capability| capability == "openshell.supervisor-middleware.contract")
    );

    let unknown_requirement = LegacyMiddlewareFixture::new("compat/strict")
        .with_binding(http_request_binding(64))
        .requiring_capability("openshell.supervisor-middleware.compat-test-unsupported")
        .spawn()
        .await
        .expect("spawn strict fixture");
    let refused = crate::MiddlewareRegistry::connect_services(
        Vec::new(),
        vec![registration(GUARD, &unknown_requirement, 64)],
    )
    .await
    .expect_err("a service requiring an unknown capability is refused at Describe");
    assert!(refused.to_string().contains("Describe failed"), "{refused}");

    let unnegotiated = LegacyMiddlewareFixture::new("compat/unnegotiated")
        .with_binding(http_request_binding(64))
        .without_extension_metadata()
        .spawn()
        .await
        .expect("spawn fixture without metadata");
    let refused = crate::MiddlewareRegistry::connect_services(
        Vec::new(),
        vec![registration(GUARD, &unnegotiated, 64)],
    )
    .await
    .expect_err("a manifest without protocol metadata is refused");
    assert!(
        refused
            .to_string()
            .contains("did not provide protocol metadata"),
        "{refused}"
    );
}
