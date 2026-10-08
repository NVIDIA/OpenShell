// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `EvaluateHttpRequest` through [`LegacyRequestStage`], mirroring
//! `crate::compat_tests::request`.

use std::sync::Arc;
use std::time::Duration;

use openshell_core::proto::{
    Decision, Finding, HeaderMutation, HttpBegin, HttpBodyLimits, HttpBodyMode, HttpBufferedBody,
    HttpHeader, HttpPreflight, HttpRequestPreflightHead, MiddlewareSessionEndReason,
    SupervisorMiddlewarePhase, http_buffered_result, http_event, http_inspect, http_preflight,
    http_preflight_result, http_result,
};
use openshell_supervisor_middleware_wire_fixture::proto::middleware::{
    ExistingHeaderAction, Finding as LegacyFinding, HttpRequestEvaluation, HttpRequestResult,
};
use openshell_supervisor_middleware_wire_fixture::{
    LegacyMiddlewareFixture, LegacyRpc, Reply, RunningFixture, http_request_binding, results,
};
use tokio::time::Instant;
use tonic::Status;

use super::{
    Out, StageDriver, connect, context, entry, fail_open_reasons, headers, registration, target,
    transcode,
};
use crate::legacy::hooks::LegacyChainClock;
use crate::legacy::request::{
    LegacyRequestExchange, LegacyRequestStage, legacy_request_collection_limit,
};
use crate::{
    ChainEntry, ChainRunner, ContractFailureKind, DescribedChainEntry,
    MAX_MIDDLEWARE_CHAIN_TIMEOUT, MIDDLEWARE_GRPC_MESSAGE_BYTES, MiddlewareDenial, OnError,
    StageReports, headers as header_rules, middleware_denial_reason,
};

const GUARD: &str = "legacy-guard";

/// One request as the relay hands it to the pipeline.
#[derive(Debug, Clone)]
struct Request {
    headers: Vec<HttpHeader>,
    body: Vec<u8>,
    /// `Content-Length`, or `None` for a chunked body.
    declared: Option<u64>,
}

fn request(body: &[u8], pairs: &[(&str, &str)]) -> Request {
    Request {
        headers: headers(pairs),
        body: body.to_vec(),
        declared: Some(body.len() as u64),
    }
}

fn exchange(reports: &Arc<StageReports>) -> LegacyRequestExchange {
    LegacyRequestExchange {
        reports: reports.clone(),
        connection_nominated_headers: Arc::from(Vec::new()),
        chain_clock: LegacyChainClock::default(),
    }
}

/// The preflight the pipeline sends a legacy request stage: BUFFERED with
/// late mutations, offered at the chain's collection limit.
fn preflight(
    entry: &DescribedChainEntry,
    headers: &[HttpHeader],
    collection_limit: u64,
    declared: Option<u64>,
) -> HttpPreflight {
    HttpPreflight {
        head: Some(http_preflight::Head::Request(HttpRequestPreflightHead {
            context: Some(context()),
            target: Some(target("POST", "/v1/messages", "trace=1")),
            headers: headers.to_vec(),
            middleware_name: entry.entry.implementation.clone(),
            config: Some(entry.entry.config.clone()),
        })),
        permitted_body_modes: vec![HttpBodyMode::Buffered as i32],
        late_header_modes: vec![HttpBodyMode::Buffered as i32],
        limits: Some(HttpBodyLimits {
            max_buffered_body_bytes: collection_limit,
            ..Default::default()
        }),
        declared_input_bytes: declared,
    }
}

fn body_events(headers: &[HttpHeader], body: &[u8]) -> [http_event::Event; 2] {
    [
        http_event::Event::Begin(HttpBegin {
            headers: headers.to_vec(),
        }),
        http_event::Event::BufferedBody(HttpBufferedBody {
            data: body.to_vec(),
            visible_trailers: Vec::new(),
        }),
    ]
}

/// One stage's outcome, recorded the way 0.1.x recorded invocations.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StageOutcome {
    name: String,
    decision: Decision,
    transformed: bool,
    failed: bool,
}

fn outcome(name: &str, decision: Decision, transformed: bool, failed: bool) -> StageOutcome {
    StageOutcome {
        name: name.into(),
        decision,
        transformed,
        failed,
    }
}

/// What a chain of legacy request stages makes observable, as the pipeline
/// derives it from version 2 results and stage reports.
#[derive(Debug, Default)]
struct ChainRun {
    allowed: bool,
    reason: String,
    denial: Option<MiddlewareDenial>,
    body: Vec<u8>,
    headers: Vec<HttpHeader>,
    late_mutations: Vec<HeaderMutation>,
    stages: Vec<StageOutcome>,
    findings: Vec<(String, Finding)>,
    fail_open: Vec<(String, String)>,
    contract: Option<ContractFailureKind>,
}

impl ChainRun {
    fn collect_fail_open(&mut self, reports: &StageReports, name: &str) -> bool {
        let reasons = fail_open_reasons(&super::reports_for(reports, name));
        let failed = !reasons.is_empty();
        self.fail_open
            .extend(reasons.into_iter().map(|reason| (name.to_string(), reason)));
        failed
    }

    fn collect_findings(&mut self, name: &str, findings: Vec<Finding>) {
        self.findings.extend(
            findings
                .into_iter()
                .map(|finding| (name.to_string(), finding)),
        );
    }

    /// Record a result that ends the chain.
    fn stop(&mut self, name: &str, result: Out) {
        self.allowed = false;
        match result {
            Out::Result(http_result::Result::Reject(reject)) => {
                let diagnostics = reject.diagnostics.unwrap_or_default();
                let reason_code =
                    (!diagnostics.reason_code.is_empty()).then_some(diagnostics.reason_code);
                self.reason = middleware_denial_reason(name, reason_code.as_deref());
                self.denial = Some(MiddlewareDenial {
                    config_name: name.into(),
                    reason_code,
                });
                self.collect_findings(name, diagnostics.findings);
                self.stages
                    .push(outcome(name, Decision::Deny, false, false));
            }
            Out::Failed(failure) => {
                self.reason = format!("middleware_failed: {}", failure.reason);
                self.stages.push(outcome(name, Decision::Deny, false, true));
            }
            Out::Contract(kind) => {
                self.reason = format!("middleware_failed: {}", kind.reason());
                self.contract = Some(kind);
                self.stages.push(outcome(name, Decision::Deny, false, true));
            }
            Out::Result(other) => panic!("{name}: unexpected result {other:?}"),
        }
    }
}

/// Run a chain of legacy request stages the way the version 2 pipeline must:
/// preflight every stage, then pass the body through each inspecting stage in
/// order, applying late mutations and replacements before the next stage.
async fn run_chain(runner: &ChainRunner, chain: &[ChainEntry], request: Request) -> ChainRun {
    let described = runner
        .describe_chain(chain)
        .await
        .expect("describe request chain");
    let limit = legacy_request_collection_limit(&described).expect("a legacy entry resolved");
    let reports = Arc::new(StageReports::default());
    let chain_clock = LegacyChainClock::default();
    let mut run = ChainRun {
        allowed: true,
        body: request.body,
        headers: request.headers,
        ..Default::default()
    };
    let mut inspecting = Vec::new();
    for entry in &described {
        let stage = LegacyRequestStage::new(
            entry,
            LegacyRequestExchange {
                chain_clock: chain_clock.clone(),
                ..exchange(&reports)
            },
        )
        .expect("legacy request");
        let mut driver = StageDriver::open(&stage).await;
        driver
            .send(http_event::Event::Preflight(preflight(
                entry,
                &run.headers,
                limit as u64,
                request.declared,
            )))
            .await;
        let name = entry.entry.name.as_str();
        match driver.result().await {
            Out::Result(http_result::Result::PreflightResult(result)) => match result.decision {
                Some(http_preflight_result::Decision::ContinueWithoutBody(_)) => {
                    let failed = run.collect_fail_open(&reports, name);
                    run.stages
                        .push(outcome(name, Decision::Allow, false, failed));
                }
                Some(http_preflight_result::Decision::Inspect(inspect)) => {
                    let Some(http_inspect::Mode::Buffered(mode)) = inspect.mode else {
                        panic!("{name}: legacy request stages select BUFFERED");
                    };
                    inspecting.push((entry, driver, mode.max_body_bytes));
                }
                None => panic!("{name}: preflight without a decision"),
            },
            other => {
                run.stop(name, other);
                return run;
            }
        }
    }
    for (entry, mut driver, max_body_bytes) in inspecting {
        let name = entry.entry.name.as_str();
        if run.body.len() as u64 > max_body_bytes {
            // The pipeline cannot buffer the body for this stage. 0.1.x denied
            // a body it could not buffer before contacting the upstream.
            run.allowed = false;
            run.reason = "request_body_unbufferable".into();
            return run;
        }
        for event in body_events(&run.headers, &run.body) {
            driver.send(event).await;
        }
        let result = driver.result().await;
        let Out::Result(http_result::Result::BufferedResult(result)) = result else {
            run.stop(name, result);
            return run;
        };
        let failed = run.collect_fail_open(&reports, name);
        let mut transformed = false;
        if !result.header_mutations.is_empty() {
            let updated = header_rules::apply(
                header_rules::HeaderAuthority::Request,
                &run.headers,
                &[],
                &result.header_mutations,
            )
            .expect("the adapter validated its late mutations");
            transformed |= updated != run.headers;
            run.headers = updated;
            run.late_mutations.extend(result.header_mutations);
        }
        if let Some(http_buffered_result::Body::Replacement(body)) = result.body {
            run.body = body;
            transformed = true;
        }
        if let Some(diagnostics) = result.diagnostics {
            run.collect_findings(name, diagnostics.findings);
        }
        run.stages
            .push(outcome(name, Decision::Allow, transformed, failed));
        driver.end(MiddlewareSessionEndReason::Normal).await;
    }
    run
}

fn redacting_guard(request: &HttpRequestEvaluation) -> Reply<HttpRequestResult> {
    let body = String::from_utf8_lossy(&request.body);
    if body.contains("forbidden") {
        return HttpRequestResult {
            findings: vec![LegacyFinding {
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

async fn guard(fixture: LegacyMiddlewareFixture, limit: u64) -> (RunningFixture, ChainRunner) {
    let fixture = fixture
        .with_binding(http_request_binding(limit))
        .spawn()
        .await
        .expect("spawn request fixture");
    let runner = connect(vec![registration(GUARD, &fixture, limit)]).await;
    (fixture, runner)
}

#[tokio::test]
async fn request_envelope_and_decisions_round_trip_through_the_adapter() {
    let (fixture, runner) = guard(
        LegacyMiddlewareFixture::new("compat/guard").on_http_request(redacting_guard),
        4096,
    )
    .await;
    let chain = [entry("guard", GUARD, 10, OnError::FailClosed)];

    let redacted = run_chain(
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
    assert!(redacted.allowed, "{}", redacted.reason);
    assert_eq!(redacted.body, b"{\"note\":\"[FILTERED]\"}");
    let expected_mutation: HeaderMutation = transcode(&results::write_header(
        "x-guard",
        "redacted",
        ExistingHeaderAction::Overwrite,
    ));
    assert_eq!(redacted.late_mutations, vec![expected_mutation]);
    assert_eq!(
        redacted.stages,
        vec![outcome("guard", Decision::Allow, true, false)]
    );

    let evaluation = fixture.http_requests().remove(0);
    assert_eq!(
        evaluation.phase,
        SupervisorMiddlewarePhase::PreCredentials as i32
    );
    assert_eq!(evaluation.middleware_name, GUARD);
    assert_eq!(evaluation.body, b"{\"note\":\"secret\"}");
    let request_target = evaluation.target.expect("request target");
    assert_eq!(
        (
            request_target.scheme.as_str(),
            request_target.host.as_str(),
            request_target.port,
            request_target.method.as_str(),
            request_target.path.as_str(),
            request_target.query.as_str()
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
    let request_context = evaluation.context.expect("request context");
    assert_eq!(request_context.request_id, "adapter-request");
    assert_eq!(request_context.sandbox_id, "adapter-sandbox-id");
    assert_eq!(request_context.sandbox, "adapter-sandbox");
    assert_eq!(request_context.workspace, "adapter-workspace");
    let seen: Vec<_> = evaluation
        .headers
        .iter()
        .map(|header| (header.name.as_str(), header.value.as_str()))
        .collect();
    assert_eq!(
        seen,
        [
            ("content-type", "application/json"),
            ("x-repeat", "one"),
            ("x-repeat", "two"),
        ],
        "the Begin head reaches the service in wire order"
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

    let denied = run_chain(&runner, &chain, request(b"forbidden", &[])).await;
    assert!(!denied.allowed);
    assert_eq!(denied.reason, "middleware_denied:guard:content_match");
    let denial = denied.denial.expect("explicit denial");
    assert_eq!(denial.config_name, "guard");
    assert_eq!(denial.reason_code.as_deref(), Some("content_match"));
    assert_eq!(denied.findings.len(), 1);
    assert_eq!(denied.findings[0].0, "guard");
    assert_eq!(denied.findings[0].1.r#type, format!("{GUARD}.finding"));
    assert!(!denied.findings[0].1.label.contains("sk-secret-value"));
    assert!(denied.findings[0].1.confidence.is_empty());
    assert_eq!(denied.findings[0].1.severity, "high");

    let unchanged = run_chain(&runner, &chain, request(b"plain", &[])).await;
    assert!(unchanged.allowed);
    assert_eq!(unchanged.body, b"plain");
    assert!(unchanged.late_mutations.is_empty());
    assert!(!unchanged.stages[0].transformed);
}

/// The adapter answers preflight itself, so the service is called once, with
/// the body, exactly like the 0.1.x unary contract.
#[tokio::test]
async fn preflight_selects_buffered_at_the_offered_collection_limit_without_calling_the_service() {
    let (fixture, runner) = guard(LegacyMiddlewareFixture::new("compat/guard"), 64).await;
    let described = runner
        .describe_chain(&[entry("guard", GUARD, 10, OnError::FailClosed)])
        .await
        .expect("describe");
    assert_eq!(legacy_request_collection_limit(&described), Some(64));
    let reports = Arc::new(StageReports::default());
    let stage = LegacyRequestStage::new(&described[0], exchange(&reports)).expect("legacy");

    for declared in [Some(64), None] {
        let mut driver = StageDriver::open(&stage).await;
        driver
            .send(http_event::Event::Preflight(preflight(
                &described[0],
                &[],
                256,
                declared,
            )))
            .await;
        let Out::Result(http_result::Result::PreflightResult(result)) = driver.result().await
        else {
            panic!("preflight result expected");
        };
        assert_eq!(
            result.decision,
            Some(http_preflight_result::Decision::Inspect(
                openshell_core::proto::HttpInspect {
                    mode: Some(http_inspect::Mode::Buffered(
                        openshell_core::proto::HttpBufferedMode {
                            max_body_bytes: 256
                        }
                    )),
                }
            )),
            "{declared:?}"
        );
        assert!(result.header_mutations.is_empty());
        driver.end(MiddlewareSessionEndReason::Cancellation).await;
    }
    assert!(fixture.http_requests().is_empty());
    assert!(reports.drain().is_empty());
}

#[tokio::test]
async fn later_stages_observe_earlier_late_mutations_in_chain_order() {
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
    let chain = [
        entry("second", "legacy-second", 20, OnError::FailClosed),
        entry("first", "legacy-first", 10, OnError::FailClosed),
    ];

    let observed = run_chain(
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
    assert!(observed.allowed, "{}", observed.reason);
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
        "the second stage sees the first stage's late mutations at Begin"
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
        observed.late_mutations,
        [first_mutations, second_mutations].concat(),
        "late mutations replay in chain order"
    );
}

#[tokio::test]
async fn deny_short_circuits_later_stages() {
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

    let observed = run_chain(&runner, &chain, request(b"{}", &[])).await;
    assert!(!observed.allowed);
    assert_eq!(observed.reason, "middleware_denied:deny:blocked_by_guard");
    assert!(observed.late_mutations.is_empty());
    assert!(observed.fail_open.is_empty());
    assert!(later.http_requests().is_empty());
}

async fn small_and_large() -> (RunningFixture, RunningFixture, ChainRunner) {
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
    (small, large, runner)
}

#[tokio::test]
async fn over_capacity_bodies_skip_or_fail_each_stage_by_its_own_limit() {
    let (small, large, runner) = small_and_large().await;
    let body = [b'x'; 32];
    for declared in [Some(32), None] {
        let skipped = run_chain(
            &runner,
            &[
                entry("small", "legacy-small", 10, OnError::FailOpen),
                entry("large", "legacy-large", 20, OnError::FailClosed),
            ],
            Request {
                declared,
                ..request(&body, &[])
            },
        )
        .await;
        assert!(skipped.allowed, "{declared:?}: {}", skipped.reason);
        assert_eq!(skipped.body, b"large-stage-ran");
        assert_eq!(
            skipped.stages,
            vec![
                outcome("small", Decision::Allow, false, true),
                outcome("large", Decision::Allow, true, false),
            ]
        );
        assert_eq!(
            skipped.fail_open,
            [(
                "small".to_string(),
                "request_body_over_capacity".to_string()
            )]
        );

        let denied = run_chain(
            &runner,
            &[entry("small", "legacy-small", 10, OnError::FailClosed)],
            Request {
                declared,
                ..request(&body, &[])
            },
        )
        .await;
        assert!(!denied.allowed);
        assert!(denied.denial.is_none());
        // Alone, the small stage is the collection limit. A declared body
        // over it fails at preflight with the 0.1.x reason; a chunked one
        // outgrows the buffer and the pipeline denies it.
        if declared.is_some() {
            assert_eq!(
                denied.reason,
                "middleware_failed: request_body_over_capacity"
            );
        }
    }
    assert!(small.http_requests().is_empty(), "the call is never made");
    assert_eq!(large.http_requests().len(), 2);
}

/// 0.1.x never buffered a body declared over the chain's largest limit: it
/// passed through untouched when every entry was `fail_open`, and was denied
/// otherwise. Each adapter decides its share at preflight.
#[tokio::test]
async fn a_body_declared_over_the_collection_limit_is_resolved_at_preflight() {
    let (small, large, runner) = small_and_large().await;
    let body = [b'x'; 100];

    let passed = run_chain(
        &runner,
        &[
            entry("small", "legacy-small", 10, OnError::FailOpen),
            entry("large", "legacy-large", 20, OnError::FailOpen),
        ],
        request(&body, &[]),
    )
    .await;
    assert!(passed.allowed, "{}", passed.reason);
    assert_eq!(passed.body, body, "the body passes through untouched");
    assert_eq!(
        passed.stages,
        vec![
            outcome("small", Decision::Allow, false, true),
            outcome("large", Decision::Allow, false, true),
        ]
    );

    let denied = run_chain(
        &runner,
        &[
            entry("small", "legacy-small", 10, OnError::FailOpen),
            entry("large", "legacy-large", 20, OnError::FailClosed),
        ],
        request(&body, &[]),
    )
    .await;
    assert!(!denied.allowed);
    assert_eq!(
        denied.reason,
        "middleware_failed: request_body_over_capacity"
    );
    assert!(small.http_requests().is_empty());
    assert!(large.http_requests().is_empty());

    let unknown = run_chain(
        &runner,
        &[
            entry("small", "legacy-small", 10, OnError::FailOpen),
            entry("large", "legacy-large", 20, OnError::FailOpen),
        ],
        Request {
            declared: None,
            ..request(&body, &[])
        },
    )
    .await;
    assert!(
        !unknown.allowed,
        "a chunked body that outgrows the collection limit is denied"
    );
    assert!(large.http_requests().is_empty());
}

/// 0.1.x checked each stage's limit against the body that stage receives, so
/// an earlier replacement can bring a body over or under a later limit.
#[tokio::test]
async fn stage_limits_apply_to_the_body_each_stage_receives() {
    for (replacement, on_error, expect_called, expect_failed) in [
        (vec![b'e'; 40], OnError::FailClosed, false, true),
        (vec![b'e'; 40], OnError::FailOpen, false, true),
        (vec![b's'; 8], OnError::FailClosed, true, false),
    ] {
        let rewriting = LegacyMiddlewareFixture::new("compat/rewrite")
            .with_binding(http_request_binding(64))
            .on_http_request({
                let replacement = replacement.clone();
                move |_| results::replace_body(replacement.clone()).into()
            })
            .spawn()
            .await
            .expect("spawn rewriting fixture");
        let small = LegacyMiddlewareFixture::new("compat/small")
            .with_binding(http_request_binding(16))
            .spawn()
            .await
            .expect("spawn small fixture");
        let runner = connect(vec![
            registration("legacy-rewrite", &rewriting, 64),
            registration("legacy-small", &small, 16),
        ])
        .await;

        let observed = run_chain(
            &runner,
            &[
                entry("rewrite", "legacy-rewrite", 10, OnError::FailClosed),
                entry("small", "legacy-small", 20, on_error),
            ],
            request(&[b'x'; 32], &[]),
        )
        .await;
        assert_eq!(small.http_requests().len(), usize::from(expect_called));
        assert_eq!(
            observed.stages[0],
            outcome("rewrite", Decision::Allow, true, false)
        );
        assert_eq!(observed.stages[1].failed, expect_failed, "{on_error:?}");
        if expect_failed && on_error == OnError::FailClosed {
            assert_eq!(
                observed.reason,
                "middleware_failed: request_body_over_capacity"
            );
        } else {
            assert!(observed.allowed, "{}", observed.reason);
            assert_eq!(observed.body, replacement);
        }
    }
}

/// One way a legacy service can fail an evaluation, and the 0.1.x reason
/// `fail_closed` reports for it.
struct FailureCase {
    name: &'static str,
    reply: fn(&HttpRequestEvaluation) -> Reply<HttpRequestResult>,
    reason: &'static str,
}

const FAILURE_CASES: [FailureCase; 7] = [
    FailureCase {
        name: "grpc error status",
        reply: |_| Reply::Fail(Status::internal("guard crashed on sk-secret-value")),
        reason: "external_service_error",
    },
    FailureCase {
        name: "slower than the registration timeout",
        reply: |_| Reply::Respond(results::allow()).after(Duration::from_secs(2)),
        reason: "middleware_timeout",
    },
    FailureCase {
        name: "unspecified decision",
        reply: |_| HttpRequestResult::default().into(),
        reason: "invalid_response_decision",
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
        reason: "response_reason_code_invalid",
    },
    FailureCase {
        name: "replacement over the binding limit",
        reply: |_| results::replace_body(vec![b'r'; 128]).into(),
        reason: "response_body_over_capacity",
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
        reason: "header_mutation_protected_header",
    },
    FailureCase {
        name: "result larger than the gRPC message limit",
        reply: |_| results::replace_body(vec![b'r'; MIDDLEWARE_GRPC_MESSAGE_BYTES]).into(),
        reason: "external_service_error",
    },
];

#[tokio::test]
async fn service_failures_follow_on_error() {
    for case in &FAILURE_CASES {
        let (_fixture, runner) = guard(
            LegacyMiddlewareFixture::new("compat/failing").on_http_request(case.reply),
            64,
        )
        .await;

        let open = run_chain(
            &runner,
            &[entry("guard", GUARD, 10, OnError::FailOpen)],
            request(b"original", &[]),
        )
        .await;
        assert!(open.allowed, "{}: {}", case.name, open.reason);
        assert_eq!(open.body, b"original", "{}", case.name);
        assert!(open.late_mutations.is_empty(), "{}", case.name);
        assert_eq!(
            open.stages,
            vec![outcome("guard", Decision::Allow, false, true)],
            "{}",
            case.name
        );
        assert_eq!(
            open.fail_open,
            [("guard".to_string(), case.reason.to_string())],
            "{}",
            case.name
        );

        let closed = run_chain(
            &runner,
            &[entry("guard", GUARD, 10, OnError::FailClosed)],
            request(b"original", &[]),
        )
        .await;
        assert!(!closed.allowed, "{}", case.name);
        assert_eq!(
            closed.reason,
            format!("middleware_failed: {}", case.reason),
            "{}",
            case.name
        );
        assert!(closed.denial.is_none(), "{}", case.name);
        assert!(closed.fail_open.is_empty(), "{}", case.name);
        assert!(!closed.reason.contains("sk-secret-value"));
    }
}

/// `UNIMPLEMENTED` passes through as a contract failure for either
/// `on_error`; the pipeline fails it closed and requests reconciliation.
#[tokio::test]
async fn unimplemented_evaluate_http_request_is_a_contract_failure_for_either_on_error() {
    let (fixture, runner) = guard(
        LegacyMiddlewareFixture::new("compat/swapped")
            .on_http_request(|_| results::replace_body("inspected").into()),
        64,
    )
    .await;
    fixture.set_unimplemented(LegacyRpc::EvaluateHttpRequest, true);

    for on_error in [OnError::FailOpen, OnError::FailClosed] {
        let observation = run_chain(
            &runner,
            &[entry("guard", GUARD, 10, on_error)],
            request(b"original", &[]),
        )
        .await;
        assert!(!observation.allowed, "{on_error:?}");
        assert_eq!(
            observation.contract,
            Some(ContractFailureKind::Unimplemented)
        );
        assert_eq!(
            observation.reason,
            "middleware_failed: middleware_contract_failure_unimplemented"
        );
        assert_eq!(
            observation.stages,
            vec![outcome("guard", Decision::Deny, false, true)]
        );
        assert!(observation.fail_open.is_empty(), "{on_error:?}");
    }
    assert!(fixture.http_requests().is_empty());
}

async fn single_stage(
    runner: &ChainRunner,
    on_error: OnError,
    exchange: LegacyRequestExchange,
) -> (DescribedChainEntry, LegacyRequestStage) {
    let described = runner
        .describe_chain(&[entry("guard", GUARD, 10, on_error)])
        .await
        .expect("describe");
    let stage = LegacyRequestStage::new(&described[0], exchange).expect("legacy request");
    (described.into_iter().next().expect("one entry"), stage)
}

/// Run one stage through preflight and its body with `late` late-header
/// modes, and return the body result.
async fn evaluate_once(
    entry: &DescribedChainEntry,
    stage: &LegacyRequestStage,
    body: &[u8],
) -> Out {
    let mut driver = StageDriver::open(stage).await;
    driver
        .send(http_event::Event::Preflight(preflight(
            entry,
            &[],
            64,
            None,
        )))
        .await;
    let Out::Result(http_result::Result::PreflightResult(_)) = driver.result().await else {
        panic!("preflight result expected");
    };
    for event in body_events(&[], body) {
        driver.send(event).await;
    }
    driver.result().await
}

/// The pipeline must offer BUFFERED with a limit and late header mutations to
/// every legacy request stage. Anything else is a pipeline bug, so the stage
/// fails closed without calling the service, whatever `on_error` says.
#[tokio::test]
async fn preflight_without_the_legacy_offer_fails_the_stage_closed() {
    let (fixture, runner) = guard(LegacyMiddlewareFixture::new("compat/guard"), 64).await;
    let reports = Arc::new(StageReports::default());
    let (entry, stage) = single_stage(&runner, OnError::FailOpen, exchange(&reports)).await;
    let offered = preflight(&entry, &[], 64, None);
    for (name, preflight, reason) in [
        (
            "BUFFERED not offered",
            HttpPreflight {
                permitted_body_modes: Vec::new(),
                ..offered.clone()
            },
            "legacy_stage_offer_invalid",
        ),
        (
            "no buffering limit",
            HttpPreflight {
                limits: Some(HttpBodyLimits::default()),
                ..offered.clone()
            },
            "legacy_stage_offer_invalid",
        ),
        (
            "no late header mutations",
            HttpPreflight {
                late_header_modes: Vec::new(),
                ..offered.clone()
            },
            "legacy_stage_late_mutations_not_offered",
        ),
    ] {
        let mut driver = StageDriver::open(&stage).await;
        driver.send(http_event::Event::Preflight(preflight)).await;
        assert_eq!(
            driver.result().await.failed_reason(),
            Some(reason),
            "{name}"
        );
    }
    assert!(fixture.http_requests().is_empty());
    assert!(reports.drain().is_empty());
}

/// 0.1.x called every stage with the buffered body, even an empty one.
#[tokio::test]
async fn bodyless_requests_still_call_the_stage() {
    let (fixture, runner) = guard(LegacyMiddlewareFixture::new("compat/guard"), 64).await;
    let observed = run_chain(
        &runner,
        &[entry("guard", GUARD, 10, OnError::FailClosed)],
        request(b"", &[("accept", "application/json")]),
    )
    .await;
    assert!(observed.allowed, "{}", observed.reason);
    assert_eq!(
        observed.stages,
        vec![outcome("guard", Decision::Allow, false, false)]
    );
    let evaluation = fixture.http_requests().remove(0);
    assert!(evaluation.body.is_empty());
    assert_eq!(evaluation.headers.len(), 1);
}

#[tokio::test]
async fn connection_nominated_headers_stay_protected() {
    let (_fixture, runner) = guard(
        LegacyMiddlewareFixture::new("compat/hop").on_http_request(|_| {
            results::mutate_headers(vec![results::write_header(
                "x-hop",
                "forged",
                ExistingHeaderAction::Overwrite,
            )])
            .into()
        }),
        64,
    )
    .await;
    let reports = Arc::new(StageReports::default());
    let (entry, stage) = single_stage(
        &runner,
        OnError::FailClosed,
        LegacyRequestExchange {
            connection_nominated_headers: Arc::from(vec!["x-hop".to_string()]),
            ..exchange(&reports)
        },
    )
    .await;
    let result = evaluate_once(&entry, &stage, b"").await;
    assert_eq!(
        result.failed_reason(),
        Some("header_mutation_hop_by_hop_header")
    );
}

/// A stage reached after the 0.1.x chain deadline fails like 0.1.x without
/// calling the service.
#[tokio::test]
async fn an_expired_chain_deadline_follows_on_error_without_a_call() {
    let (fixture, runner) = guard(LegacyMiddlewareFixture::new("compat/late"), 64).await;
    for (on_error, expected) in [
        (OnError::FailClosed, Some("middleware_chain_timeout")),
        (OnError::FailOpen, None),
    ] {
        let reports = Arc::new(StageReports::default());
        let (entry, stage) = single_stage(
            &runner,
            on_error,
            LegacyRequestExchange {
                chain_clock: LegacyChainClock::expired(),
                ..exchange(&reports)
            },
        )
        .await;
        let result = evaluate_once(&entry, &stage, b"body").await;
        assert_eq!(result.failed_reason(), expected, "{on_error:?}");
        if expected.is_none() {
            assert_eq!(
                fail_open_reasons(&super::reports_for(&reports, "guard")),
                ["middleware_chain_timeout"]
            );
        }
    }
    assert!(fixture.http_requests().is_empty());
}

/// 0.1.x started the chain deadline once the body was buffered, so a slow
/// upload never failed with `middleware_chain_timeout`. The first body
/// evaluation starts the clock, however long after preflight it arrives.
#[tokio::test(start_paused = true)]
async fn the_chain_clock_starts_at_the_first_body_evaluation() {
    let (runner, redact) = builtin_redaction();
    let described = runner.describe_chain(&[redact]).await.expect("describe");
    let reports = Arc::new(StageReports::default());
    let chain_clock = LegacyChainClock::default();
    let stage = LegacyRequestStage::new(
        &described[0],
        LegacyRequestExchange {
            chain_clock: chain_clock.clone(),
            ..exchange(&reports)
        },
    )
    .expect("legacy request");
    let mut driver = StageDriver::open(&stage).await;
    driver
        .send(http_event::Event::Preflight(preflight(
            &described[0],
            &[],
            64,
            None,
        )))
        .await;
    let Out::Result(http_result::Result::PreflightResult(_)) = driver.result().await else {
        panic!("preflight result expected");
    };

    tokio::time::sleep(MAX_MIDDLEWARE_CHAIN_TIMEOUT * 2).await;
    let uploaded = Instant::now();
    for event in body_events(&[], br#"{"api_key":"sk-1234567890abcdef"}"#) {
        driver.send(event).await;
    }
    let Out::Result(http_result::Result::BufferedResult(result)) = driver.result().await else {
        panic!("a slow upload is still evaluated");
    };
    assert!(matches!(
        result.body,
        Some(http_buffered_result::Body::Replacement(_))
    ));
    assert!(chain_clock.deadline() >= uploaded + MAX_MIDDLEWARE_CHAIN_TIMEOUT);
    assert!(reports.drain().is_empty());
}

/// The built-in `openshell/regex` service and a redacting attachment.
fn builtin_redaction() -> (ChainRunner, ChainEntry) {
    use openshell_supervisor_middleware_builtins::{BUILTIN_REGEX, services};

    let runner = ChainRunner::new(
        services()
            .into_iter()
            .next()
            .expect("built-in middleware service"),
    );
    let mut redact = entry("redact", BUILTIN_REGEX, 0, OnError::FailClosed);
    redact.config = prost_types::Struct {
        fields: std::iter::once((
            "mode".into(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue("redact".into())),
            },
        ))
        .collect(),
    };
    (runner, redact)
}

/// `openshell/regex` keeps its in-process legacy method until 0.2.0 and runs
/// through the same adapter.
#[tokio::test]
async fn in_process_builtins_run_through_the_adapter() {
    let (runner, redact) = builtin_redaction();
    let observed = run_chain(
        &runner,
        &[redact],
        request(br#"{"api_key":"sk-1234567890abcdef"}"#, &[]),
    )
    .await;
    assert!(observed.allowed, "{}", observed.reason);
    assert_eq!(observed.body, br#"{"api_key":"[REDACTED]"}"#);
    assert_eq!(observed.findings[0].1.count, 1);
    assert_eq!(
        observed.stages,
        vec![outcome("redact", Decision::Allow, true, false)]
    );
}

#[tokio::test]
async fn events_out_of_order_fail_the_stage_closed() {
    let (fixture, runner) = guard(LegacyMiddlewareFixture::new("compat/guard"), 64).await;
    let reports = Arc::new(StageReports::default());
    let (_entry, stage) = single_stage(&runner, OnError::FailOpen, exchange(&reports)).await;
    let mut driver = StageDriver::open(&stage).await;
    let [begin, _] = body_events(&[], b"body");
    driver.send(begin).await;
    assert_eq!(
        driver.result().await.failed_reason(),
        Some("legacy_stage_event_order_invalid")
    );
    assert!(fixture.http_requests().is_empty());
}
