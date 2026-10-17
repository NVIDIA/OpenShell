// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP session hook registration rules and stage state machine.

use std::sync::{Arc, Mutex};

use openshell_core::extension_protocol::{
    ExtensionFamily, SUPERVISOR_MIDDLEWARE_HTTP_SESSION, extension_metadata,
    http_session_middleware_metadata,
};
use openshell_core::proto::{
    ExistingHeaderAction, HeaderMutation, HttpBodyMode, HttpBufferedMode, HttpBufferedResult,
    HttpContinue, HttpFinish, HttpHeader, HttpInspect, HttpOutputChunk, HttpOutputStart,
    HttpPreflightResult, HttpReject, HttpRequestResult, HttpRequestSessionEvent,
    HttpRequestSessionPreflight, HttpRequestSessionResult, HttpRequestTarget, HttpStreamMode,
    MiddlewareBinding, MiddlewareDiagnostics, MiddlewareManifest, RequestContext,
    SupervisorMiddlewareOperation, SupervisorMiddlewarePhase, WriteHeader, header_mutation,
    http_buffered_result, http_inspect, http_preflight_result, http_request_session_event,
    http_request_session_preflight, http_request_session_result,
};
use tokio::sync::mpsc;

use super::pipeline::entry_failure;
use crate::{
    ChainEntry, ChainRunner, DescribedChainEntry, HttpBodyInput, HttpBodyOutput, HttpFailureCode,
    HttpRequestPreflightInput, HttpRequestSessionResultStream, HttpRequestView, HttpStageOutcome,
    InProcessMiddleware, MAX_CONCURRENT_HTTP_MIDDLEWARE_SESSIONS,
    MAX_CONCURRENT_HTTP_MIDDLEWARE_STREAMS, MAX_MIDDLEWARE_CHAIN_TIMEOUT, MiddlewareFailureDetail,
    MiddlewareRegistry, OnError, TransformedBodyPolicy, UninspectableTrafficInput,
    validate_manifest_bindings,
};

fn binding(operation: SupervisorMiddlewareOperation) -> MiddlewareBinding {
    let phase = match operation {
        SupervisorMiddlewareOperation::HttpResponse => SupervisorMiddlewarePhase::PreReturn,
        _ => SupervisorMiddlewarePhase::PreCredentials,
    };
    MiddlewareBinding {
        operation: operation as i32,
        phase: phase as i32,
        max_payload_bytes: 1024,
        ..Default::default()
    }
}

/// Manifest of a v1 HTTP hook service.
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

/// Manifest of a service that requires the HTTP session hooks capability.
fn session_manifest(bindings: Vec<MiddlewareBinding>) -> MiddlewareManifest {
    MiddlewareManifest {
        extension: Some(http_session_middleware_metadata("example/guard", "test")),
        ..manifest(bindings)
    }
}

#[test]
fn registration_requires_the_http_session_capability_it_supports() {
    use SupervisorMiddlewareOperation::{HttpRequest, HttpResponse, WebsocketMessage};
    for (case, manifest) in [
        (
            "v1 HTTP hooks",
            manifest(vec![binding(HttpRequest), binding(HttpResponse)]),
        ),
        (
            "HTTP session hooks in both directions",
            session_manifest(vec![binding(HttpRequest), binding(HttpResponse)]),
        ),
        (
            "HTTP session hooks with a WebSocket binding",
            session_manifest(vec![binding(HttpRequest), binding(WebsocketMessage)]),
        ),
    ] {
        validate_manifest_bindings("test service", &manifest, None)
            .unwrap_or_else(|error| panic!("{case}: {error}"));
    }

    // Peers that predate HTTP session hooks accept a service that only
    // supports the capability, and would call its HTTP bindings through the
    // v1 HTTP hooks.
    let mut supported_only = manifest(vec![binding(HttpRequest)]);
    supported_only
        .extension
        .as_mut()
        .expect("test manifest carries extension metadata")
        .supported_capabilities
        .push(SUPERVISOR_MIDDLEWARE_HTTP_SESSION.into());
    let error = validate_manifest_bindings("test service", &supported_only, None)
        .expect_err("a supported but not required capability is rejected")
        .to_string();
    assert!(error.contains("without requiring it"), "{error}");

    let error = validate_manifest_bindings(
        "test service",
        &session_manifest(vec![MiddlewareBinding {
            phase: SupervisorMiddlewarePhase::PreReturn as i32,
            ..binding(HttpRequest)
        }]),
        None,
    )
    .expect_err("a request operation at the response phase is rejected")
    .to_string();
    assert!(
        error.contains("unsupported middleware operation/phase pair"),
        "{error}"
    );

    // An HTTP session hook binding without a payload limit is preflight-only.
    let mut preflight_only = binding(HttpRequest);
    preflight_only.max_payload_bytes = 0;
    validate_manifest_bindings(
        "test service",
        &session_manifest(vec![preflight_only]),
        Some(0),
    )
    .expect("a preflight-only binding carries no payload");
    validate_manifest_bindings("test service", &manifest(vec![preflight_only]), None)
        .expect_err("a v1 HTTP hook binding needs a payload limit");
    validate_manifest_bindings(
        "test service",
        &session_manifest(vec![binding(HttpRequest)]),
        Some(0),
    )
    .expect_err("an HTTP session hook binding with a payload limit needs an operator limit");
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

/// In-memory HTTP session hook stage with a fixed script.
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
    /// Preflights this stage received.
    preflights: Arc<Mutex<Vec<HttpRequestSessionPreflight>>>,
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
            preflights: Arc::default(),
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
fn result(
    result: http_request_session_result::Result,
) -> Result<HttpRequestSessionResult, tonic::Status> {
    Ok(HttpRequestSessionResult {
        result: Some(result),
    })
}

#[tonic::async_trait]
impl InProcessMiddleware for ScriptedStage {
    async fn describe(&self) -> MiddlewareManifest {
        MiddlewareManifest {
            name: self.name.into(),
            ..session_manifest(vec![binding(SupervisorMiddlewareOperation::HttpRequest)])
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
        Err(miette::miette!("HTTP session hook test stage"))
    }

    async fn open_http_request_session(
        &self,
        mut events: mpsc::Receiver<HttpRequestSessionEvent>,
    ) -> Result<HttpRequestSessionResultStream, tonic::Status> {
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
        let preflights = Arc::clone(&self.preflights);
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                let reply = match event.event {
                    Some(http_request_session_event::Event::Preflight(preflight_event)) => {
                        preflights.lock().unwrap().push(preflight_event.clone());
                        assert!(matches!(
                            preflight_event.subject,
                            Some(
                                http_request_session_preflight::Subject::Request(_)
                                    | http_request_session_preflight::Subject::Uninspectable(_)
                            )
                        ));
                        let buffered_limit = preflight_event
                            .limits
                            .map_or(0, |limits| limits.max_buffered_body_bytes);
                        match &preflight {
                            Preflight::Continue => {
                                result(http_request_session_result::Result::PreflightResult(
                                    HttpPreflightResult {
                                        decision: Some(
                                            http_preflight_result::Decision::ContinueWithoutBody(
                                                HttpContinue {},
                                            ),
                                        ),
                                        header_mutations: preflight_mutations.clone(),
                                        diagnostics: None,
                                    },
                                ))
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
                                result(http_request_session_result::Result::PreflightResult(
                                    HttpPreflightResult {
                                        decision: Some(http_preflight_result::Decision::Inspect(
                                            HttpInspect { mode: Some(mode) },
                                        )),
                                        header_mutations: preflight_mutations.clone(),
                                        diagnostics: None,
                                    },
                                ))
                            }
                            Preflight::Reject(code) => {
                                result(http_request_session_result::Result::Reject(HttpReject {
                                    diagnostics: Some(MiddlewareDiagnostics {
                                        reason_code: (*code).to_string(),
                                        ..Default::default()
                                    }),
                                }))
                            }
                            Preflight::Fail(code) => Err(tonic::Status::new(*code, "scripted")),
                        }
                    }
                    Some(http_request_session_event::Event::Begin(started)) => {
                        begun.lock().unwrap().push(started.headers);
                        if matches!(body, Body::Uppercase) {
                            result(http_request_session_result::Result::OutputStart(
                                HttpOutputStart {
                                    header_mutations: late_mutations.clone(),
                                    output_body_bytes: None,
                                },
                            ))
                        } else {
                            continue;
                        }
                    }
                    Some(http_request_session_event::Event::BufferedBody(buffered)) => result(
                        http_request_session_result::Result::BufferedResult(HttpBufferedResult {
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
                        }),
                    ),
                    Some(http_request_session_event::Event::InputChunk(chunk)) => result(
                        http_request_session_result::Result::OutputChunk(HttpOutputChunk {
                            data: chunk.data.to_ascii_uppercase(),
                        }),
                    ),
                    Some(http_request_session_event::Event::InputEnd(_)) => result(
                        http_request_session_result::Result::Finish(HttpFinish::default()),
                    ),
                    Some(http_request_session_event::Event::SessionEnd(_)) | None => break,
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

/// A runner over `stages` and their chain, described in stage order.
async fn scripted_chain(
    stages: Vec<Arc<ScriptedStage>>,
) -> (ChainRunner, Vec<DescribedChainEntry>) {
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
    (runner, described)
}

async fn run(stages: Vec<Arc<ScriptedStage>>, body: &[u8]) -> Run {
    let (runner, described) = scripted_chain(stages).await;
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
    let (first, second) = (Arc::new(first), Arc::new(second));
    let outcome = run(vec![Arc::clone(&first), Arc::clone(&second)], b"hello").await;
    assert!(outcome.allowed, "{}", outcome.reason);
    assert_eq!(
        outcome.preflight_mutations,
        ["example/a-pre", "example/b-pre"]
    );
    assert_eq!(outcome.late_mutations, ["example/a-late", "example/b-late"]);
    assert_eq!(outcome.body, b"HELLO");
    let begun_order = |stage: &ScriptedStage| -> Vec<String> {
        let begun = stage.begun.lock().unwrap();
        assert_eq!(begun.len(), 1, "{} begins once", stage.name);
        begun[0]
            .iter()
            .filter(|header| header.name == "x-order")
            .map(|header| header.value.clone())
            .collect()
    };
    // Every stage begins on the original head and every preflight mutation,
    // including those of later stages, then earlier stages' late mutations.
    assert_eq!(
        begun_order(&first),
        ["original", "example/a-pre", "example/b-pre"]
    );
    assert_eq!(
        begun_order(&second),
        [
            "original",
            "example/a-pre",
            "example/b-pre",
            "example/a-late"
        ]
    );
}

/// HTTP session hook service with only a response binding.
struct ResponseOnlyStage;

#[tonic::async_trait]
impl InProcessMiddleware for ResponseOnlyStage {
    async fn describe(&self) -> MiddlewareManifest {
        MiddlewareManifest {
            name: "example/response-only".into(),
            ..session_manifest(vec![binding(SupervisorMiddlewareOperation::HttpResponse)])
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
        Err(miette::miette!(
            "HTTP session hook response-only test stage"
        ))
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

fn scripted(name: &'static str, preflight: Preflight, body: Body) -> Arc<ScriptedStage> {
    Arc::new(ScriptedStage::new(name, preflight, body))
}

/// Free HTTP session hook slots, then free STREAM slots.
fn free_slots(runner: &ChainRunner) -> (usize, usize) {
    (
        runner.registry.http_session_admission.available_permits(),
        runner.registry.http_stream_admission.available_permits(),
    )
}

#[tokio::test]
async fn a_message_holds_session_slots_only_while_a_stage_inspects_it() {
    use HttpBodyMode::{Buffered, Stream};
    let full = (
        MAX_CONCURRENT_HTTP_MIDDLEWARE_SESSIONS,
        MAX_CONCURRENT_HTTP_MIDDLEWARE_STREAMS,
    );
    for (case, stages, held) in [
        (
            "continue releases the slot after preflight",
            vec![scripted("example/a", Preflight::Continue, Body::Unchanged)],
            (full.0, full.1),
        ),
        (
            "BUFFERED keeps the preflight slot",
            vec![scripted(
                "example/a",
                Preflight::Inspect(Buffered),
                Body::Unchanged,
            )],
            (full.0 - 1, full.1),
        ),
        (
            "STREAM moves to the stream budget",
            vec![scripted(
                "example/a",
                Preflight::Inspect(Stream),
                Body::Uppercase,
            )],
            (full.0, full.1 - 1),
        ),
        (
            "BUFFERED and STREAM hold both",
            vec![
                scripted("example/a", Preflight::Inspect(Buffered), Body::Unchanged),
                scripted("example/b", Preflight::Inspect(Stream), Body::Uppercase),
            ],
            (full.0 - 1, full.1 - 1),
        ),
    ] {
        let (runner, described) = scripted_chain(stages).await;
        let preflight = runner
            .preflight_described_http_request(described, request_input(b"hello"))
            .await
            .expect("preflight");
        assert!(preflight.allowed, "{case}: {}", preflight.reason);
        assert_eq!(free_slots(&runner), held, "{case}");
        let Some(session) = preflight.session else {
            continue;
        };
        let buffers = session.withholds_output();
        let streams = session.streams();
        let (input, inputs) = mpsc::channel(4);
        input
            .send(HttpBodyInput::Chunk(b"hello".to_vec()))
            .await
            .expect("queue body");
        input
            .send(HttpBodyInput::End {
                trailers: Vec::new(),
            })
            .await
            .expect("queue end");
        let (output, mut outputs) = mpsc::channel(1);
        let run =
            session.run_with_body_policy(inputs, output, TransformedBodyPolicy::NotPolicyRelevant);
        let check = async {
            if buffers && streams {
                // The BUFFERED stage ends while the output is not read, and
                // its slot frees up before the STREAM stage ends.
                tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    while free_slots(&runner).0 != full.0 {
                        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    }
                })
                .await
                .expect("the BUFFERED slot frees up");
                assert_eq!(free_slots(&runner), (full.0, full.1 - 1), "{case}");
            }
            while outputs.recv().await.is_some() {}
        };
        let (finish, ()) = tokio::join!(run, check);
        finish.expect("body run");
        assert_eq!(free_slots(&runner), full, "{case}");
    }
}

#[tokio::test(start_paused = true)]
async fn preflight_waits_for_a_session_slot_within_the_chain_deadline() {
    let (runner, described) = scripted_chain(vec![scripted(
        "example/a",
        Preflight::Continue,
        Body::Unchanged,
    )])
    .await;
    let mut held = Arc::clone(&runner.registry.http_session_admission)
        .acquire_many_owned(
            u32::try_from(MAX_CONCURRENT_HTTP_MIDDLEWARE_SESSIONS).expect("slot count"),
        )
        .await
        .expect("hold every slot");

    let started = tokio::time::Instant::now();
    let shed = runner
        .preflight_described_http_request(described.clone(), request_input(b""))
        .await
        .expect("preflight");
    assert!(!shed.allowed);
    assert!(shed.session_capacity_exhausted);
    assert_eq!(started.elapsed(), MAX_MIDDLEWARE_CHAIN_TIMEOUT);

    let waiting = runner.preflight_described_http_request(described, request_input(b""));
    tokio::pin!(waiting);
    assert!(futures::poll!(waiting.as_mut()).is_pending());
    drop(held.split(1));
    let admitted = waiting.await.expect("preflight");
    assert!(admitted.allowed, "{}", admitted.reason);
    assert!(!admitted.session_capacity_exhausted);
}

#[tokio::test(start_paused = true)]
async fn waiting_for_a_stream_slot_does_not_hold_a_preflight_slot() {
    use HttpBodyMode::{Buffered, Stream};
    let (runner, described) = scripted_chain(vec![
        scripted(
            "example/stream",
            Preflight::Inspect(Stream),
            Body::Uppercase,
        ),
        scripted(
            "example/buffered",
            Preflight::Inspect(Buffered),
            Body::Unchanged,
        ),
    ])
    .await;
    let streaming = described[..1].to_vec();
    let buffered = described[1..].to_vec();
    let mut held = Arc::clone(&runner.registry.http_stream_admission)
        .acquire_many_owned(
            u32::try_from(MAX_CONCURRENT_HTTP_MIDDLEWARE_STREAMS).expect("slot count"),
        )
        .await
        .expect("hold every stream slot");

    // Enough waiting STREAM messages to take every preflight slot if they
    // kept theirs, plus one that also buffers.
    let spawn = |described: Vec<DescribedChainEntry>| {
        let runner = runner.clone();
        tokio::spawn(async move {
            runner
                .preflight_described_http_request(described, request_input(b"hello"))
                .await
        })
    };
    let waiting: Vec<_> = (0..MAX_CONCURRENT_HTTP_MIDDLEWARE_SESSIONS)
        .map(|_| spawn(streaming.clone()))
        .collect();
    let mixed = spawn(described.clone());
    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    assert!(waiting.iter().all(|message| !message.is_finished()));
    assert!(!mixed.is_finished());
    assert_eq!(
        free_slots(&runner),
        (MAX_CONCURRENT_HTTP_MIDDLEWARE_SESSIONS, 0),
        "waiting messages hold no preflight slot",
    );

    let started = tokio::time::Instant::now();
    let short = runner
        .preflight_described_http_request(buffered, request_input(b"hello"))
        .await
        .expect("preflight");
    assert!(short.allowed, "{}", short.reason);
    assert!(!short.session_capacity_exhausted);
    assert_eq!(started.elapsed(), std::time::Duration::ZERO);
    drop(short);

    // A freed stream slot goes to the first waiter; the mixed message takes
    // a preflight slot back once it has a stream slot.
    for message in &waiting {
        message.abort();
    }
    for message in waiting {
        assert!(message.await.is_err_and(|error| error.is_cancelled()));
    }
    drop(held.split(1));
    let mixed = mixed.await.expect("task").expect("preflight");
    assert!(mixed.allowed, "{}", mixed.reason);
    assert!(mixed.session.is_some());
    assert_eq!(
        free_slots(&runner),
        (MAX_CONCURRENT_HTTP_MIDDLEWARE_SESSIONS - 1, 0),
    );
}

#[tokio::test]
async fn failures_name_the_failed_stage_and_a_platform_code() {
    for (case, preflight, code) in [
        // No status means "cannot inspect": a proxy between OpenShell and the
        // service may rewrite status codes.
        (
            "FAILED_PRECONDITION",
            Preflight::Fail(tonic::Code::FailedPrecondition),
            HttpFailureCode::Unavailable,
        ),
        (
            "DEADLINE_EXCEEDED",
            Preflight::Fail(tonic::Code::DeadlineExceeded),
            HttpFailureCode::Timeout,
        ),
        (
            "UNIMPLEMENTED",
            Preflight::Fail(tonic::Code::Unimplemented),
            HttpFailureCode::LifecycleViolation,
        ),
        // The reason keeps an in-process service's status text; the code
        // the sandbox sees does not.
        (
            "UNAVAILABLE",
            Preflight::Fail(tonic::Code::Unavailable),
            HttpFailureCode::Unavailable,
        ),
        (
            "INTERNAL",
            Preflight::Fail(tonic::Code::Internal),
            HttpFailureCode::Unavailable,
        ),
    ] {
        let (runner, described) =
            scripted_chain(vec![scripted("example/a", preflight, Body::Unchanged)]).await;
        let preflight = runner
            .preflight_described_http_request(described, request_input(b"hello"))
            .await
            .expect("preflight");
        assert!(!preflight.allowed, "{case}");
        assert_eq!(
            preflight.failure,
            Some(MiddlewareFailureDetail {
                config_name: Some("example/a-config".into()),
                code,
            }),
            "{case}"
        );
    }

    let (runner, described) = scripted_chain(vec![scripted(
        "example/a",
        Preflight::Reject("blocked_term"),
        Body::Unchanged,
    )])
    .await;
    let rejected = runner
        .preflight_described_http_request(described, request_input(b"hello"))
        .await
        .expect("preflight");
    assert!(rejected.denial.is_some());
    assert!(rejected.failure.is_none());
}

#[tokio::test]
async fn failure_reasons_map_to_a_closed_set_of_sandbox_codes() {
    let (_, described) = scripted_chain(vec![scripted(
        "example/a",
        Preflight::Continue,
        Body::Unchanged,
    )])
    .await;
    for (reason, code) in [
        ("middleware_cannot_inspect", "middleware_cannot_inspect"),
        ("head_input_over_capacity", "middleware_cannot_inspect"),
        (
            "response_input_unrepresentable",
            "middleware_cannot_inspect",
        ),
        ("middleware_timeout", "middleware_timeout"),
        ("middleware_chain_timeout", "middleware_timeout"),
        ("middleware_body_timeout", "middleware_timeout"),
        ("middleware_stall_timeout", "stream_idle_timeout"),
        ("binding_not_described", "middleware_unavailable"),
        ("session_capacity_exhausted", "middleware_unavailable"),
        ("buffered_input_over_capacity", "body_over_limit"),
        ("buffered_output_over_capacity", "body_over_limit"),
        ("request_output_over_capacity", "body_over_limit"),
        (
            "middleware_hook_versions_mixed",
            "middleware_hook_versions_mixed",
        ),
        ("middleware_unimplemented", "middleware_lifecycle_violation"),
        (
            "middleware_result_stream_closed",
            "middleware_lifecycle_violation",
        ),
        (
            "stream_output_length_mismatch",
            "middleware_lifecycle_violation",
        ),
        ("preflight_result_unknown", "middleware_lifecycle_violation"),
    ] {
        let failure = entry_failure(&described[0], reason)
            .failure
            .expect("failure detail");
        assert_eq!(failure.code.as_str(), code, "{reason}");
    }
}

#[tokio::test]
async fn an_encoded_request_offers_no_body_mode() {
    use openshell_core::proto::{HttpBodyModeUnavailable, HttpBodyUnavailableReason};
    let encoded = |mode: HttpBodyMode| HttpBodyModeUnavailable {
        mode: mode as i32,
        reason: HttpBodyUnavailableReason::Encoded as i32,
    };
    for (coding, permitted, unavailable) in [
        (
            "gzip",
            vec![],
            vec![
                encoded(HttpBodyMode::Buffered),
                encoded(HttpBodyMode::Stream),
            ],
        ),
        (
            "identity",
            vec![HttpBodyMode::Buffered as i32, HttpBodyMode::Stream as i32],
            vec![],
        ),
    ] {
        let stage = scripted("example/a", Preflight::Continue, Body::Unchanged);
        let (runner, described) = scripted_chain(vec![Arc::clone(&stage)]).await;
        let mut input = request_input(b"hello");
        input.headers.push(HttpHeader {
            name: "Content-Encoding".into(),
            value: coding.into(),
        });
        runner
            .preflight_described_http_request(described, input)
            .await
            .expect("preflight");
        let preflights = stage.preflights.lock().unwrap();
        assert_eq!(preflights[0].permitted_body_modes, permitted, "{coding}");
        assert_eq!(
            preflights[0].unavailable_body_modes, unavailable,
            "{coding}"
        );
        assert_eq!(
            preflights[0].phase,
            SupervisorMiddlewarePhase::PreCredentials as i32
        );
    }
}

#[tokio::test]
async fn only_stages_before_an_inspecting_stage_learn_the_declared_length() {
    use HttpBodyMode::Buffered;
    for (case, first, declared) in [
        ("after a continuing stage", Preflight::Continue, Some(5)),
        (
            "after an inspecting stage",
            Preflight::Inspect(Buffered),
            None,
        ),
    ] {
        let first = scripted("example/a", first, Body::Unchanged);
        let second = scripted("example/b", Preflight::Continue, Body::Unchanged);
        let (runner, described) =
            scripted_chain(vec![Arc::clone(&first), Arc::clone(&second)]).await;
        runner
            .preflight_described_http_request(described, request_input(b"hello"))
            .await
            .expect("preflight");
        assert_eq!(
            first.preflights.lock().unwrap()[0].declared_body_bytes,
            Some(5),
            "{case}"
        );
        assert_eq!(
            second.preflights.lock().unwrap()[0].declared_body_bytes,
            declared,
            "{case}"
        );
    }
}
