// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! v2 HTTP hook registration rules and stage state machine.

use std::sync::{Arc, Mutex};

use openshell_core::extension_protocol::{ExtensionFamily, extension_metadata};
use openshell_core::proto::{
    ExistingHeaderAction, HeaderMutation, HttpBodyMode, HttpBufferedMode, HttpBufferedResult,
    HttpContinue, HttpEvent, HttpFinish, HttpHeader, HttpInspect, HttpOutputChunk, HttpOutputStart,
    HttpPreflightResult, HttpReject, HttpRequestResult, HttpRequestTarget, HttpResult,
    HttpStreamMode, MiddlewareBinding, MiddlewareDiagnostics, MiddlewareManifest, RequestContext,
    SupervisorMiddlewareOperation, SupervisorMiddlewarePhase, WriteHeader, header_mutation,
    http_buffered_result, http_event, http_inspect, http_preflight, http_preflight_result,
    http_result,
};
use tokio::sync::mpsc;

use crate::{
    ChainEntry, ChainRunner, HttpBodyInput, HttpBodyOutput, HttpRequestPreflightInput,
    HttpRequestView, HttpResultStream, HttpStageOutcome, InProcessMiddleware, MiddlewareRegistry,
    OnError, TransformedBodyPolicy, UninspectableTrafficInput, validate_manifest_bindings,
};

fn binding(operation: SupervisorMiddlewareOperation) -> MiddlewareBinding {
    let phase = match operation {
        SupervisorMiddlewareOperation::HttpResponse
        | SupervisorMiddlewareOperation::HttpResponseV2 => SupervisorMiddlewarePhase::PreReturn,
        _ => SupervisorMiddlewarePhase::PreCredentials,
    };
    MiddlewareBinding {
        operation: operation as i32,
        phase: phase as i32,
        max_payload_bytes: 1024,
        ..Default::default()
    }
}

fn manifest(bindings: Vec<MiddlewareBinding>) -> MiddlewareManifest {
    MiddlewareManifest {
        name: "example/guard".into(),
        bindings,
        extension: Some(extension_metadata(
            ExtensionFamily::SupervisorMiddleware,
            "example/guard",
            "test",
            [],
        )),
        ..Default::default()
    }
}

#[test]
fn registration_selects_one_http_protocol_per_service() {
    use SupervisorMiddlewareOperation::{
        HttpRequest, HttpRequestV2, HttpResponse, HttpResponseV2, WebsocketMessage,
    };
    let cases: Vec<(&str, Vec<MiddlewareBinding>, Option<&str>)> = vec![
        (
            "v1 HTTP hook",
            vec![binding(HttpRequest), binding(HttpResponse)],
            None,
        ),
        (
            "v2 HTTP hook in both directions",
            vec![binding(HttpRequestV2), binding(HttpResponseV2)],
            None,
        ),
        (
            "v2 HTTP hook with a WebSocket binding",
            vec![binding(HttpRequestV2), binding(WebsocketMessage)],
            None,
        ),
        (
            "mixed hook versions in one service",
            vec![binding(HttpRequest), binding(HttpResponseV2)],
            Some("mixes v1 and v2 HTTP hook bindings"),
        ),
        (
            "both hook versions for one stage",
            vec![binding(HttpRequest), binding(HttpRequestV2)],
            Some("mixes v1 and v2 HTTP hook bindings"),
        ),
        (
            "v2 HTTP hook request operation at the response phase",
            vec![MiddlewareBinding {
                phase: SupervisorMiddlewarePhase::PreReturn as i32,
                ..binding(HttpRequestV2)
            }],
            Some("unsupported middleware operation/phase pair"),
        ),
    ];
    for (case, bindings, expected) in cases {
        let result = validate_manifest_bindings("test service", &manifest(bindings), None);
        match expected {
            None => result.unwrap_or_else(|error| panic!("{case}: {error}")),
            Some(expected) => {
                let error = result.expect_err(case).to_string();
                assert!(error.contains(expected), "{case}: {error}");
            }
        }
    }

    // A v2 HTTP hook binding without a payload limit is preflight-only.
    let mut preflight_only = binding(HttpRequestV2);
    preflight_only.max_payload_bytes = 0;
    validate_manifest_bindings("test service", &manifest(vec![preflight_only]), Some(0))
        .expect("a preflight-only binding carries no payload");
    let mut payload = binding(HttpRequest);
    payload.max_payload_bytes = 0;
    validate_manifest_bindings("test service", &manifest(vec![payload]), None)
        .expect_err("a v1 HTTP hook binding needs a payload limit");
    validate_manifest_bindings(
        "test service",
        &manifest(vec![binding(HttpRequestV2)]),
        Some(0),
    )
    .expect_err("a v2 HTTP hook binding with a payload limit needs an operator limit");
}

/// What a scripted stage does at preflight.
#[derive(Clone)]
enum Preflight {
    Continue,
    Inspect(HttpBodyMode),
    Reject(&'static str),
    Fail(tonic::Code),
}

/// What a scripted stage does with the body it selected.
#[derive(Clone, Copy)]
enum Body {
    Unchanged,
    Replace(&'static [u8]),
    Uppercase,
}

/// In-memory v2 HTTP hook stage with a fixed script.
struct ScriptedStage {
    name: &'static str,
    preflight: Preflight,
    body: Body,
    /// Head mutation written at preflight, as `x-order: <name>-pre`.
    preflight_mutation: bool,
    /// Late head mutation, as `x-order: <name>-late`.
    late_mutation: bool,
    /// Heads this stage received in `Begin`.
    begun: Arc<Mutex<Vec<Vec<HttpHeader>>>>,
}

impl ScriptedStage {
    fn new(name: &'static str, preflight: Preflight, body: Body) -> Self {
        Self {
            name,
            preflight,
            body,
            preflight_mutation: false,
            late_mutation: false,
            begun: Arc::default(),
        }
    }

    fn order_mutation(&self, phase: &str) -> HeaderMutation {
        HeaderMutation {
            operation: Some(header_mutation::Operation::Write(WriteHeader {
                name: "x-order".into(),
                value: format!("{}-{phase}", self.name),
                on_existing: ExistingHeaderAction::Append as i32,
            })),
        }
    }
}

#[allow(clippy::unnecessary_wraps)] // Matches the stream item type.
fn result(result: http_result::Result) -> Result<HttpResult, tonic::Status> {
    Ok(HttpResult {
        result: Some(result),
    })
}

#[tonic::async_trait]
impl InProcessMiddleware for ScriptedStage {
    async fn describe(&self) -> MiddlewareManifest {
        MiddlewareManifest {
            name: self.name.into(),
            ..manifest(vec![binding(SupervisorMiddlewareOperation::HttpRequestV2)])
        }
    }

    async fn validate_config(
        &self,
        _middleware_name: &str,
        _config: &prost_types::Struct,
    ) -> miette::Result<()> {
        Ok(())
    }

    async fn evaluate_http_request(
        &self,
        _request: HttpRequestView<'_>,
    ) -> miette::Result<HttpRequestResult> {
        Err(miette::miette!("v2 HTTP hook test stage"))
    }

    async fn open_http_request_v2(
        &self,
        mut events: mpsc::Receiver<HttpEvent>,
    ) -> Result<HttpResultStream, tonic::Status> {
        let (sender, receiver) = mpsc::channel(4);
        let preflight = self.preflight.clone();
        let body = self.body;
        let preflight_mutations: Vec<_> = self
            .preflight_mutation
            .then(|| self.order_mutation("pre"))
            .into_iter()
            .collect();
        let late_mutations: Vec<_> = self
            .late_mutation
            .then(|| self.order_mutation("late"))
            .into_iter()
            .collect();
        let begun = Arc::clone(&self.begun);
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                let reply = match event.event {
                    Some(http_event::Event::Preflight(preflight_event)) => {
                        assert!(matches!(
                            preflight_event.subject,
                            Some(
                                http_preflight::Subject::Request(_)
                                    | http_preflight::Subject::Uninspectable(_)
                            )
                        ));
                        let buffered_limit = preflight_event
                            .limits
                            .map_or(0, |limits| limits.max_buffered_body_bytes);
                        match &preflight {
                            Preflight::Continue => {
                                result(http_result::Result::PreflightResult(HttpPreflightResult {
                                    decision: Some(
                                        http_preflight_result::Decision::ContinueWithoutBody(
                                            HttpContinue {},
                                        ),
                                    ),
                                    header_mutations: preflight_mutations.clone(),
                                    diagnostics: None,
                                }))
                            }
                            Preflight::Inspect(mode) => {
                                let mode = match mode {
                                    HttpBodyMode::Buffered => {
                                        http_inspect::Mode::Buffered(HttpBufferedMode {
                                            max_body_bytes: buffered_limit,
                                        })
                                    }
                                    _ => http_inspect::Mode::Stream(HttpStreamMode {}),
                                };
                                result(http_result::Result::PreflightResult(HttpPreflightResult {
                                    decision: Some(http_preflight_result::Decision::Inspect(
                                        HttpInspect { mode: Some(mode) },
                                    )),
                                    header_mutations: preflight_mutations.clone(),
                                    diagnostics: None,
                                }))
                            }
                            Preflight::Reject(code) => {
                                result(http_result::Result::Reject(HttpReject {
                                    diagnostics: Some(MiddlewareDiagnostics {
                                        reason_code: (*code).to_string(),
                                        ..Default::default()
                                    }),
                                }))
                            }
                            Preflight::Fail(code) => Err(tonic::Status::new(*code, "scripted")),
                        }
                    }
                    Some(http_event::Event::Begin(started)) => {
                        begun.lock().unwrap().push(started.headers);
                        if matches!(body, Body::Uppercase) {
                            result(http_result::Result::OutputStart(HttpOutputStart {
                                header_mutations: late_mutations.clone(),
                                output_body_bytes: None,
                            }))
                        } else {
                            continue;
                        }
                    }
                    Some(http_event::Event::BufferedBody(buffered)) => {
                        result(http_result::Result::BufferedResult(HttpBufferedResult {
                            body: Some(match body {
                                Body::Replace(replacement) => {
                                    http_buffered_result::Body::Replacement(replacement.to_vec())
                                }
                                Body::Uppercase => http_buffered_result::Body::Replacement(
                                    buffered.data.to_ascii_uppercase(),
                                ),
                                Body::Unchanged => http_buffered_result::Body::Unchanged(
                                    openshell_core::proto::HttpUnchanged {},
                                ),
                            }),
                            header_mutations: late_mutations.clone(),
                            ..Default::default()
                        }))
                    }
                    Some(http_event::Event::InputChunk(chunk)) => {
                        result(http_result::Result::OutputChunk(HttpOutputChunk {
                            data: chunk.data.to_ascii_uppercase(),
                        }))
                    }
                    Some(http_event::Event::InputEnd(_)) => {
                        result(http_result::Result::Finish(HttpFinish::default()))
                    }
                    Some(http_event::Event::SessionEnd(_)) | None => break,
                };
                let terminal = reply.is_err();
                if sender.send(reply).await.is_err() || terminal {
                    break;
                }
            }
        });
        Ok(Box::pin(tokio_stream::wrappers::ReceiverStream::new(
            receiver,
        )))
    }
}

fn chain_entry(name: &str, order: i32) -> ChainEntry {
    ChainEntry {
        name: format!("{name}-config"),
        implementation: name.to_string(),
        order,
        config: prost_types::Struct::default(),
        on_error: OnError::FailClosed,
    }
}

fn request_input(body: &[u8]) -> HttpRequestPreflightInput {
    HttpRequestPreflightInput {
        context: RequestContext {
            request_id: "request-1".into(),
            ..Default::default()
        },
        target: HttpRequestTarget {
            scheme: "https".into(),
            host: "api.example.com".into(),
            port: 443,
            method: "POST".into(),
            path: "/v1/items".into(),
            query: String::new(),
        },
        declared_body_length: Some(body.len() as u64),
        headers: vec![HttpHeader {
            name: "x-order".into(),
            value: "original".into(),
        }],
        connection_nominated_headers: Vec::new(),
    }
}

/// Outcome of one request through a scripted chain.
#[derive(Debug, PartialEq, Eq)]
struct Run {
    allowed: bool,
    reason: String,
    preflight_mutations: Vec<String>,
    late_mutations: Vec<String>,
    body: Vec<u8>,
    outcomes: Vec<HttpStageOutcome>,
}

fn mutation_values(mutations: &[HeaderMutation]) -> Vec<String> {
    mutations
        .iter()
        .filter_map(|mutation| match &mutation.operation {
            Some(header_mutation::Operation::Write(write)) => Some(write.value.clone()),
            _ => None,
        })
        .collect()
}

async fn run(stages: Vec<Arc<ScriptedStage>>, body: &[u8]) -> Run {
    let entries: Vec<_> = stages
        .iter()
        .zip(0..)
        .map(|(stage, order)| chain_entry(stage.name, order))
        .collect();
    let services: Vec<Arc<dyn InProcessMiddleware>> = stages
        .into_iter()
        .map(|stage| -> Arc<dyn InProcessMiddleware> { stage })
        .collect();
    let registry = MiddlewareRegistry::connect_services(services, Vec::new())
        .await
        .expect("registry");
    let runner = ChainRunner::from_registry(registry);
    let described = runner.describe_chain(&entries).await.expect("described");
    let preflight = runner
        .preflight_described_http_request(described, request_input(body))
        .await
        .expect("preflight");
    let mut outcomes: Vec<_> = preflight
        .diagnostics
        .invocations
        .iter()
        .map(|invocation| invocation.outcome)
        .collect();
    let preflight_mutations = mutation_values(&preflight.header_mutations);
    let Some(session) = preflight.session.filter(|_| preflight.allowed) else {
        return Run {
            allowed: preflight.allowed,
            reason: preflight.reason,
            preflight_mutations,
            late_mutations: Vec::new(),
            body: body.to_vec(),
            outcomes,
        };
    };
    let (input, inputs) = mpsc::channel(4);
    let (output, mut outputs) = mpsc::channel(4);
    let feed = async {
        for unit in body.chunks(3) {
            input
                .send(HttpBodyInput::Chunk(unit.to_vec()))
                .await
                .unwrap();
        }
        input
            .send(HttpBodyInput::End {
                trailers: Vec::new(),
            })
            .await
            .unwrap();
    };
    let collect = async {
        let mut late = Vec::new();
        let mut collected = Vec::new();
        while let Some(event) = outputs.recv().await {
            match event {
                HttpBodyOutput::Start {
                    header_mutations, ..
                } => late = mutation_values(&header_mutations),
                HttpBodyOutput::Chunk(data) => collected.extend(data),
                HttpBodyOutput::End { .. } => {}
            }
        }
        (late, collected)
    };
    let (finish, (), (late_mutations, collected)) = tokio::join!(
        session.run_with_body_policy(inputs, output, TransformedBodyPolicy::NotPolicyRelevant),
        feed,
        collect
    );
    match finish {
        Ok(finish) => {
            outcomes.extend(finish.diagnostics.invocations.iter().map(|i| i.outcome));
            Run {
                allowed: true,
                reason: String::new(),
                preflight_mutations,
                late_mutations,
                body: collected,
                outcomes,
            }
        }
        Err(failure) => {
            outcomes.extend(failure.diagnostics.invocations.iter().map(|i| i.outcome));
            Run {
                allowed: false,
                reason: failure.reason,
                preflight_mutations,
                late_mutations,
                body: collected,
                outcomes,
            }
        }
    }
}

struct Case {
    name: &'static str,
    stages: Vec<Arc<ScriptedStage>>,
    expected: Run,
}

#[tokio::test]
async fn request_stages_follow_the_protocol_2_state_machine() {
    use HttpStageOutcome as Outcome;
    let stage = |name, preflight, body| Arc::new(ScriptedStage::new(name, preflight, body));
    let cases = vec![
        Case {
            name: "preflight continue forwards the body untouched",
            stages: vec![stage("example/a", Preflight::Continue, Body::Unchanged)],
            expected: Run {
                allowed: true,
                reason: String::new(),
                preflight_mutations: Vec::new(),
                late_mutations: Vec::new(),
                body: b"hello world".to_vec(),
                outcomes: vec![Outcome::Continue],
            },
        },
        Case {
            name: "preflight reject denies before the body",
            stages: vec![
                stage("example/a", Preflight::Reject("blocked_term"), Body::Unchanged),
                stage("example/b", Preflight::Continue, Body::Unchanged),
            ],
            expected: Run {
                allowed: false,
                reason: "middleware_denied:example_a-config:blocked_term".into(),
                preflight_mutations: Vec::new(),
                late_mutations: Vec::new(),
                body: b"hello world".to_vec(),
                outcomes: vec![Outcome::Reject],
            },
        },
        Case {
            name: "BUFFERED replaces the body",
            stages: vec![stage(
                "example/a",
                Preflight::Inspect(HttpBodyMode::Buffered),
                Body::Replace(b"[redacted]"),
            )],
            expected: Run {
                allowed: true,
                reason: String::new(),
                preflight_mutations: Vec::new(),
                late_mutations: Vec::new(),
                body: b"[redacted]".to_vec(),
                outcomes: vec![Outcome::Buffered, Outcome::Replacement],
            },
        },
        Case {
            name: "STREAM transforms every chunk",
            stages: vec![stage(
                "example/a",
                Preflight::Inspect(HttpBodyMode::Stream),
                Body::Uppercase,
            )],
            expected: Run {
                allowed: true,
                reason: String::new(),
                preflight_mutations: Vec::new(),
                late_mutations: Vec::new(),
                body: b"HELLO WORLD".to_vec(),
                outcomes: vec![Outcome::Stream, Outcome::Finish],
            },
        },
        Case {
            name: "a stage error fails the chain closed",
            stages: vec![stage(
                "example/a",
                Preflight::Fail(tonic::Code::Unavailable),
                Body::Unchanged,
            )],
            expected: Run {
                allowed: false,
                // In-process services keep their status text; external
                // services get a platform-owned reason.
                reason: "middleware_failed: code: The service is currently unavailable message: scripted"
                    .into(),
                preflight_mutations: Vec::new(),
                late_mutations: Vec::new(),
                body: b"hello world".to_vec(),
                outcomes: vec![Outcome::FailClosed],
            },
        },
        Case {
            name: "FAILED_PRECONDITION means the stage cannot inspect the message",
            stages: vec![stage(
                "example/a",
                Preflight::Fail(tonic::Code::FailedPrecondition),
                Body::Unchanged,
            )],
            expected: Run {
                allowed: false,
                reason: "middleware_failed: middleware_cannot_inspect".into(),
                preflight_mutations: Vec::new(),
                late_mutations: Vec::new(),
                body: b"hello world".to_vec(),
                outcomes: vec![Outcome::FailClosed],
            },
        },
    ];
    for case in cases {
        assert_eq!(
            run(case.stages, b"hello world").await,
            case.expected,
            "{}",
            case.name
        );
    }
}

#[tokio::test]
async fn late_header_mutations_apply_after_every_preflight_mutation_in_chain_order() {
    let mut first = ScriptedStage::new(
        "example/a",
        Preflight::Inspect(HttpBodyMode::Buffered),
        Body::Unchanged,
    );
    first.preflight_mutation = true;
    first.late_mutation = true;
    let mut second = ScriptedStage::new(
        "example/b",
        Preflight::Inspect(HttpBodyMode::Stream),
        Body::Uppercase,
    );
    second.preflight_mutation = true;
    second.late_mutation = true;
    let second = Arc::new(second);
    let outcome = run(vec![Arc::new(first), Arc::clone(&second)], b"hello").await;
    assert!(outcome.allowed, "{}", outcome.reason);
    assert_eq!(
        outcome.preflight_mutations,
        ["example/a-pre", "example/b-pre"]
    );
    assert_eq!(outcome.late_mutations, ["example/a-late", "example/b-late"]);
    assert_eq!(outcome.body, b"HELLO");
    // The second stage begins on the original head, every preflight
    // mutation, and the first stage's late mutation.
    let begun = second.begun.lock().unwrap().clone();
    let values: Vec<_> = begun[0]
        .iter()
        .filter(|header| header.name == "x-order")
        .map(|header| header.value.as_str())
        .collect();
    assert_eq!(
        values,
        [
            "original",
            "example/a-pre",
            "example/b-pre",
            "example/a-late"
        ]
    );
}

/// v2 HTTP hook service with only a response binding.
struct ResponseOnlyStage;

#[tonic::async_trait]
impl InProcessMiddleware for ResponseOnlyStage {
    async fn describe(&self) -> MiddlewareManifest {
        MiddlewareManifest {
            name: "example/response-only".into(),
            ..manifest(vec![binding(SupervisorMiddlewareOperation::HttpResponseV2)])
        }
    }

    async fn validate_config(
        &self,
        _middleware_name: &str,
        _config: &prost_types::Struct,
    ) -> miette::Result<()> {
        Ok(())
    }

    async fn evaluate_http_request(
        &self,
        _request: HttpRequestView<'_>,
    ) -> miette::Result<HttpRequestResult> {
        Err(miette::miette!("v2 HTTP hook response-only test stage"))
    }
}

#[tokio::test]
async fn only_request_bindings_decide_about_uninspectable_traffic() {
    let request_stage = Arc::new(ScriptedStage::new(
        "example/request",
        Preflight::Continue,
        Body::Unchanged,
    ));
    let services: Vec<Arc<dyn InProcessMiddleware>> =
        vec![request_stage, Arc::new(ResponseOnlyStage)];
    let registry = MiddlewareRegistry::connect_services(services, Vec::new())
        .await
        .expect("registry");
    assert!(registry.decides_uninspectable_traffic("example/request"));
    assert!(!registry.decides_uninspectable_traffic("example/response-only"));

    let runner = ChainRunner::from_registry(registry);
    let input = || UninspectableTrafficInput {
        context: RequestContext::default(),
        host: "api.example.com".into(),
        port: 443,
        endpoint: "api".into(),
        reason: openshell_core::proto::UninspectableTrafficReason::TlsSkip,
    };
    let allowed = runner
        .evaluate_uninspectable(&[chain_entry("example/request", 0)], input())
        .await;
    assert!(allowed.allowed, "{}", allowed.reason);

    // A response-only service is never asked, so its fail-closed entry
    // denies the connection.
    let denied = runner
        .evaluate_uninspectable(
            &[
                chain_entry("example/request", 0),
                chain_entry("example/response-only", 1),
            ],
            input(),
        )
        .await;
    assert!(!denied.allowed);
    assert_eq!(denied.reason, "middleware_failed: traffic_uninspectable");
}
