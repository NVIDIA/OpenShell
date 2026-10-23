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
    HttpContinue, HttpDenial, HttpFinish, HttpHeader, HttpInspect, HttpOutputChunk,
    HttpOutputStart, HttpPreflightResult, HttpRequestResult, HttpRequestSessionEvent,
    HttpRequestSessionPreflight, HttpRequestSessionResult, HttpRequestTarget, HttpStreamMode,
    MiddlewareBinding, MiddlewareDiagnostics, MiddlewareManifest, RequestContext,
    SupervisorMiddlewareOperation, SupervisorMiddlewarePhase, WriteHeader, header_mutation,
    http_buffered_result, http_inspect, http_preflight_result, http_request_session_event,
    http_request_session_result,
};
use tokio::sync::mpsc;

use super::pipeline::entry_failure;
use crate::{
    ChainEntry, ChainRunner, DescribedChainEntry, HttpBodyInput, HttpBodyOutput, HttpFailureCode,
    HttpRequestPreflightInput, HttpRequestSessionResultStream, HttpRequestView, HttpStageOutcome,
    InProcessMiddleware, MAX_CONCURRENT_HTTP_MIDDLEWARE_SESSIONS,
    MAX_CONCURRENT_HTTP_MIDDLEWARE_STREAMS, MAX_MIDDLEWARE_CHAIN_TIMEOUT, MiddlewareFailureDetail,
    MiddlewareRegistry, OnError, TransformedBodyPolicy, validate_manifest_bindings,
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
    Deny(&'static str),
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
    inspect_content_type: Option<&'static str>,
    output_content_type: Option<&'static str>,
    output_after_input: bool,
    ended: Arc<Mutex<Vec<i32>>>,
    /// Heads this stage received in `Begin`.
    begun: Arc<Mutex<Vec<Vec<HttpHeader>>>>,
    /// Preflights this stage received.
    preflights: Arc<Mutex<Vec<HttpRequestSessionPreflight>>>,
    /// Request headers each response preflight carried.
    response_request_headers: Arc<Mutex<Vec<Vec<HttpHeader>>>>,
}

impl ScriptedStage {
    fn new(name: &'static str, preflight: Preflight, body: Body) -> Self {
        Self {
            name,
            preflight,
            body,
            preflight_mutation: false,
            late_mutation: false,
            inspect_content_type: None,
            output_content_type: None,
            output_after_input: false,
            ended: Arc::default(),
            begun: Arc::default(),
            preflights: Arc::default(),
            response_request_headers: Arc::default(),
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
            ..session_manifest(vec![
                binding(SupervisorMiddlewareOperation::HttpRequest),
                binding(SupervisorMiddlewareOperation::HttpResponse),
            ])
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
        let mut late_mutations: Vec<_> = self
            .late_mutation
            .then(|| self.order_mutation("late"))
            .into_iter()
            .collect();
        if let Some(content_type) = self.output_content_type {
            late_mutations.push(HeaderMutation {
                operation: Some(header_mutation::Operation::Write(WriteHeader {
                    name: "content-type".into(),
                    value: content_type.into(),
                    on_existing: ExistingHeaderAction::Overwrite as i32,
                })),
            });
        }
        let inspect_content_type = self.inspect_content_type;
        let output_after_input = self.output_after_input;
        let ended = Arc::clone(&self.ended);
        let begun = Arc::clone(&self.begun);
        let preflights = Arc::clone(&self.preflights);
        tokio::spawn(async move {
            let mut output_started = false;
            while let Some(event) = events.recv().await {
                let reply = match event.event {
                    Some(http_request_session_event::Event::Preflight(preflight_event)) => {
                        preflights.lock().unwrap().push(preflight_event.clone());
                        assert!(preflight_event.request.is_some());
                        let buffered_limit = preflight_event
                            .limits
                            .map_or(0, |limits| limits.max_buffered_body_bytes);
                        let applies = inspect_content_type.is_none_or(|content_type| {
                            preflight_event
                                .request
                                .as_ref()
                                .unwrap()
                                .headers
                                .iter()
                                .any(|header| {
                                    header.name.eq_ignore_ascii_case("content-type")
                                        && header.value == content_type
                                })
                        });
                        match if applies {
                            &preflight
                        } else {
                            &Preflight::Continue
                        } {
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
                            Preflight::Deny(code) => {
                                result(http_request_session_result::Result::Deny(HttpDenial {
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
                        if matches!(body, Body::Uppercase) && !output_after_input {
                            output_started = true;
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
                    Some(http_request_session_event::Event::InputChunk(chunk)) => {
                        if !output_started {
                            sender
                                .send(result(http_request_session_result::Result::OutputStart(
                                    HttpOutputStart {
                                        header_mutations: late_mutations.clone(),
                                        output_body_bytes: None,
                                    },
                                )))
                                .await
                                .unwrap();
                            output_started = true;
                        }
                        result(http_request_session_result::Result::OutputChunk(
                            HttpOutputChunk {
                                data: chunk.data.to_ascii_uppercase(),
                            },
                        ))
                    }
                    Some(http_request_session_event::Event::InputEnd(_)) => {
                        if !output_started {
                            sender
                                .send(result(http_request_session_result::Result::OutputStart(
                                    HttpOutputStart {
                                        header_mutations: late_mutations.clone(),
                                        output_body_bytes: None,
                                    },
                                )))
                                .await
                                .unwrap();
                        }
                        result(http_request_session_result::Result::Finish(
                            HttpFinish::default(),
                        ))
                    }
                    Some(http_request_session_event::Event::SessionEnd(end)) => {
                        ended.lock().unwrap().push(end.reason);
                        break;
                    }
                    None => break,
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
    async fn open_http_response_session(
        &self,
        mut events: mpsc::Receiver<openshell_core::proto::HttpResponseSessionEvent>,
    ) -> Result<crate::HttpResponseSessionResultStream, tonic::Status> {
        use futures::StreamExt as _;
        use openshell_core::proto::{
            HttpResponseSessionResult, http_response_session_event::Event as E,
            http_response_session_result::Result as R,
        };
        let response_request_headers = Arc::clone(&self.response_request_headers);
        let (sender, receiver) = mpsc::channel(4);
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                let event = event.event.map(|event| match event {
                    E::Preflight(p) => {
                        let response = p.response.unwrap();
                        response_request_headers
                            .lock()
                            .unwrap()
                            .push(response.request_headers.clone());
                        http_request_session_event::Event::Preflight(HttpRequestSessionPreflight {
                            request: Some(openshell_core::proto::HttpRequestPreflightHead {
                                target: response.target,
                                headers: response.headers,
                            }),
                            phase: p.phase,
                            context: p.context,
                            middleware_name: p.middleware_name,
                            config: p.config,
                            permitted_body_modes: p.permitted_body_modes,
                            unavailable_body_modes: p.unavailable_body_modes,
                            limits: p.limits,
                            declared_body_bytes: p.declared_body_bytes,
                        })
                    }
                    E::Begin(v) => http_request_session_event::Event::Begin(v),
                    E::BufferedBody(v) => http_request_session_event::Event::BufferedBody(v),
                    E::InputChunk(v) => http_request_session_event::Event::InputChunk(v),
                    E::InputEnd(v) => http_request_session_event::Event::InputEnd(v),
                    E::SessionEnd(v) => http_request_session_event::Event::SessionEnd(v),
                });
                if sender
                    .send(HttpRequestSessionEvent { event })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let results = self.open_http_request_session(receiver).await?;
        Ok(Box::pin(results.map(|result| {
            result.map(|result| HttpResponseSessionResult {
                result: result.result.map(|result| match result {
                    http_request_session_result::Result::PreflightResult(v) => {
                        R::PreflightResult(v)
                    }
                    http_request_session_result::Result::BufferedResult(v) => R::BufferedResult(v),
                    http_request_session_result::Result::OutputStart(v) => R::OutputStart(v),
                    http_request_session_result::Result::OutputChunk(v) => R::OutputChunk(v),
                    http_request_session_result::Result::Finish(v) => R::Finish(v),
                    http_request_session_result::Result::Deny(v) => R::BlockDelivery(v),
                }),
            })
        })))
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
        credential_reference_headers: Vec::new(),
        max_output_body_bytes: None,
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
    run_input(stages, request_input(body), body).await
}

async fn run_input(
    stages: Vec<Arc<ScriptedStage>>,
    head: HttpRequestPreflightInput,
    body: &[u8],
) -> Run {
    let (runner, described) = scripted_chain(stages).await;
    let preflight = runner
        .preflight_described_http_request(described, head)
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
            if input
                .send(HttpBodyInput::Chunk(unit.to_vec()))
                .await
                .is_err()
            {
                return;
            }
        }
        let _ = input
            .send(HttpBodyInput::End {
                trailers: Vec::new(),
            })
            .await;
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
            name: "preflight denial stops before the body",
            stages: vec![
                stage("example/a", Preflight::Deny("blocked_term"), Body::Unchanged),
                stage("example/b", Preflight::Continue, Body::Unchanged),
            ],
            expected: Run {
                allowed: false,
                reason: "middleware_denied:example_a-config:blocked_term".into(),
                preflight_mutations: Vec::new(),
                late_mutations: Vec::new(),
                body: b"hello world".to_vec(),
                outcomes: vec![Outcome::Deny],
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
async fn each_stage_sees_only_earlier_stages_complete_header_mutations() {
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
    assert_eq!(outcome.preflight_mutations, ["example/a-pre"]);
    assert_eq!(
        outcome.late_mutations,
        ["example/a-late", "example/b-pre", "example/b-late"]
    );
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
    assert_eq!(begun_order(&first), ["original", "example/a-pre"]);
    assert_eq!(
        begun_order(&second),
        [
            "original",
            "example/a-pre",
            "example/a-late",
            "example/b-pre"
        ]
    );
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
        let buffers = held.0 < full.0;
        let streams = session.may_stream();
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

    // Deferred stages reserve their preflight slot only once input is ready.
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
        (MAX_CONCURRENT_HTTP_MIDDLEWARE_SESSIONS, 0),
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
        Preflight::Deny("blocked_term"),
        Body::Unchanged,
    )])
    .await;
    let denied = runner
        .preflight_described_http_request(described, request_input(b"hello"))
        .await
        .expect("preflight");
    assert!(denied.denial.is_some());
    assert!(denied.failure.is_none());
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
async fn preflight_advertises_the_withheld_output_cap_only_with_stream() {
    const CAP: u64 = 10 * 1024 * 1024;
    for (coding, cap, advertised) in [
        ("identity", Some(CAP), Some(CAP)),
        ("identity", None, None),
        // No body mode is offered, so there is no STREAM output to cap.
        ("gzip", Some(CAP), None),
    ] {
        let stage = scripted("example/a", Preflight::Continue, Body::Unchanged);
        let (runner, described) = scripted_chain(vec![Arc::clone(&stage)]).await;
        let mut input = request_input(b"hello");
        input.max_output_body_bytes = cap;
        input.headers.push(HttpHeader {
            name: "Content-Encoding".into(),
            value: coding.into(),
        });
        runner
            .preflight_described_http_request(described, input)
            .await
            .expect("preflight");
        let preflights = stage.preflights.lock().unwrap();
        let limits = preflights[0].limits.as_ref().expect("limits");
        assert_eq!(limits.max_output_body_bytes, advertised, "{coding} {cap:?}");
    }

    // A deferred preflight, sent once the first stage starts its output,
    // carries the same cap.
    let first = scripted(
        "example/a",
        Preflight::Inspect(HttpBodyMode::Stream),
        Body::Uppercase,
    );
    let second = scripted("example/b", Preflight::Continue, Body::Unchanged);
    let mut input = request_input(b"hello");
    input.max_output_body_bytes = Some(CAP);
    let result = run_input(vec![first, Arc::clone(&second)], input, b"hello").await;
    assert!(result.allowed, "{}", result.reason);
    let preflights = second.preflights.lock().unwrap();
    let limits = preflights[0].limits.as_ref().expect("limits");
    assert_eq!(limits.max_output_body_bytes, Some(CAP));
}

#[tokio::test]
async fn downstream_preflight_receives_the_transformed_length() {
    for (preflight, body, length) in [
        (Preflight::Continue, Body::Unchanged, Some(5)),
        (
            Preflight::Inspect(HttpBodyMode::Buffered),
            Body::Replace(b"replacement"),
            Some(11),
        ),
        (
            Preflight::Inspect(HttpBodyMode::Stream),
            Body::Uppercase,
            None,
        ),
    ] {
        let first = scripted("example/a", preflight, body);
        let second = scripted("example/b", Preflight::Continue, Body::Unchanged);
        let result = run(vec![first, Arc::clone(&second)], b"hello").await;
        assert!(result.allowed, "{}", result.reason);
        assert_eq!(
            second.preflights.lock().unwrap()[0].declared_body_bytes,
            length
        );
    }
}

async fn run_response(
    stages: Vec<Arc<ScriptedStage>>,
    body: &[u8],
) -> (crate::HttpPipelineFinish, Vec<u8>) {
    let (runner, described) = scripted_chain(stages).await;
    let request = request_input(body);
    let preflight = runner
        .preflight_http_response_pipeline(
            described,
            crate::HttpResponsePreflightInput {
                context: request.context,
                target: request.target,
                status_code: 200,
                headers: request.headers,
                declared_body_length: request.declared_body_length,
                connection_nominated_headers: Vec::new(),
                request_headers: Vec::new(),
            },
            crate::HttpResponseDelivery::new(true),
        )
        .await
        .unwrap();
    assert!(preflight.allowed, "{}", preflight.reason);
    let session = preflight.session.unwrap();
    let (input, inputs) = mpsc::channel(4);
    let (output, mut outputs) = mpsc::channel(4);
    let feed = async {
        input
            .send(HttpBodyInput::Chunk(body.to_vec()))
            .await
            .unwrap();
        input
            .send(HttpBodyInput::End {
                trailers: Vec::new(),
            })
            .await
            .unwrap();
    };
    let collect = async {
        let mut body = Vec::new();
        let mut starts = 0;
        let mut ends = 0;
        while let Some(event) = outputs.recv().await {
            match event {
                HttpBodyOutput::Start { .. } => {
                    starts += 1;
                    assert_eq!(ends, 0);
                }
                HttpBodyOutput::Chunk(data) => {
                    assert_eq!(starts, 1);
                    assert_eq!(ends, 0);
                    body.extend(data);
                }
                HttpBodyOutput::End { .. } => ends += 1,
            }
        }
        assert_eq!((starts, ends), (1, 1));
        body
    };
    let (finish, (), body) = tokio::join!(
        session.run_until(inputs, output, std::future::pending()),
        feed,
        collect
    );
    (finish.expect("response pipeline"), body)
}

#[tokio::test]
async fn downstream_inspects_the_content_type_produced_by_each_body_mode() {
    for response in [false, true] {
        for mode in [HttpBodyMode::Buffered, HttpBodyMode::Stream] {
            let mut first = ScriptedStage::new(
                "example/a",
                Preflight::Inspect(mode),
                if mode == HttpBodyMode::Buffered {
                    Body::Replace(b"{\"safe\":true}")
                } else {
                    Body::Uppercase
                },
            );
            first.output_content_type = Some("application/json");
            first.output_after_input = true;
            let mut second = ScriptedStage::new(
                "example/b",
                Preflight::Inspect(HttpBodyMode::Buffered),
                Body::Unchanged,
            );
            second.inspect_content_type = Some("application/json");
            let (first, second) = (Arc::new(first), Arc::new(second));
            let original = b"{\"safe\":true}";
            let expected = if mode == HttpBodyMode::Buffered {
                original.to_vec()
            } else {
                original.to_ascii_uppercase()
            };
            if response {
                let (_, body) = run_response(vec![first, Arc::clone(&second)], original).await;
                assert_eq!(body, expected);
            } else {
                let mut head = request_input(original);
                head.headers.push(HttpHeader {
                    name: "content-type".into(),
                    value: "application/octet-stream".into(),
                });
                let outcome = run_input(vec![first, Arc::clone(&second)], head, original).await;
                assert!(outcome.allowed, "{}", outcome.reason);
                assert_eq!(outcome.body, expected);
            }
            assert_eq!(
                second.begun.lock().unwrap().len(),
                1,
                "response={response}, mode={mode:?}: JSON must be inspected"
            );
            let preflights = second.preflights.lock().unwrap();
            let head = preflights[0].request.as_ref().unwrap();
            assert!(
                head.headers
                    .iter()
                    .any(|h| h.name == "content-type" && h.value == "application/json")
            );
        }
    }
}

#[tokio::test]
async fn downstream_can_deny_after_an_earlier_stage_changes_the_content_type() {
    let mut first = ScriptedStage::new(
        "example/a",
        Preflight::Inspect(HttpBodyMode::Stream),
        Body::Uppercase,
    );
    first.output_content_type = Some("application/json");
    first.output_after_input = true;
    let mut second = ScriptedStage::new(
        "example/b",
        Preflight::Deny("json_forbidden"),
        Body::Unchanged,
    );
    second.inspect_content_type = Some("application/json");
    let third = scripted("example/c", Preflight::Continue, Body::Unchanged);
    let outcome = run(
        vec![Arc::new(first), Arc::new(second), Arc::clone(&third)],
        b"some content",
    )
    .await;
    assert!(!outcome.allowed);
    assert_eq!(
        outcome.reason,
        "middleware_denied:example_b-config:json_forbidden"
    );
    assert!(outcome.body.is_empty());
    assert!(third.preflights.lock().unwrap().is_empty());
}

#[tokio::test]
async fn adjacent_streams_preserve_all_chunks_before_completion() {
    for response in [false, true] {
        let first = scripted(
            "example/a",
            Preflight::Inspect(HttpBodyMode::Stream),
            Body::Uppercase,
        );
        let mut second = ScriptedStage::new(
            "example/b",
            Preflight::Inspect(HttpBodyMode::Stream),
            Body::Uppercase,
        );
        second.output_after_input = true;
        let body = b"abc".repeat(30000);
        let stages = vec![first, Arc::new(second)];
        if response {
            assert_eq!(
                run_response(stages, &body).await.1,
                body.to_ascii_uppercase()
            );
        } else {
            let outcome = run(stages, &body).await;
            assert!(outcome.allowed, "{}", outcome.reason);
            assert_eq!(outcome.body, body.to_ascii_uppercase());
        }
    }
}

#[tokio::test(start_paused = true)]
async fn downstream_preflight_waits_for_output_headers_without_spending_its_timeout() {
    let mut first = ScriptedStage::new(
        "example/a",
        Preflight::Inspect(HttpBodyMode::Stream),
        Body::Uppercase,
    );
    first.output_after_input = true;
    let second = scripted("example/b", Preflight::Continue, Body::Unchanged);
    let (runner, described) = scripted_chain(vec![Arc::new(first), Arc::clone(&second)]).await;
    let preflight = runner
        .preflight_described_http_request(described, request_input(b"hello"))
        .await
        .unwrap();
    assert!(second.preflights.lock().unwrap().is_empty());
    let (input, inputs) = mpsc::channel(4);
    let (output, mut outputs) = mpsc::channel(4);
    let task = tokio::spawn(preflight.session.unwrap().run_with_body_policy(
        inputs,
        output,
        TransformedBodyPolicy::NotPolicyRelevant,
    ));
    tokio::task::yield_now().await;
    tokio::time::sleep(MAX_MIDDLEWARE_CHAIN_TIMEOUT * 3).await;
    assert!(!task.is_finished());
    assert!(second.preflights.lock().unwrap().is_empty());
    input
        .send(HttpBodyInput::Chunk(b"hello".to_vec()))
        .await
        .unwrap();
    input
        .send(HttpBodyInput::End {
            trailers: Vec::new(),
        })
        .await
        .unwrap();
    let mut body = Vec::new();
    while let Some(event) = outputs.recv().await {
        if let HttpBodyOutput::Chunk(data) = event {
            body.extend(data);
        }
    }
    task.await.unwrap().unwrap();
    assert_eq!(body, b"HELLO");
    assert_eq!(second.preflights.lock().unwrap().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn adjacent_buffered_stages_share_capacity_instead_of_deadlocking() {
    let stages = vec![
        scripted(
            "example/a",
            Preflight::Inspect(HttpBodyMode::Buffered),
            Body::Unchanged,
        ),
        scripted(
            "example/b",
            Preflight::Inspect(HttpBodyMode::Buffered),
            Body::Unchanged,
        ),
    ];
    let (runner, described) = scripted_chain(stages).await;
    let preflight = runner
        .preflight_described_http_request(described, request_input(b"hello"))
        .await
        .unwrap();
    let held = Arc::clone(&runner.registry.http_session_admission)
        .acquire_many_owned(u32::try_from(MAX_CONCURRENT_HTTP_MIDDLEWARE_SESSIONS - 1).unwrap())
        .await
        .unwrap();
    let (input, inputs) = mpsc::channel(4);
    input
        .send(HttpBodyInput::Chunk(b"hello".to_vec()))
        .await
        .unwrap();
    input
        .send(HttpBodyInput::End {
            trailers: Vec::new(),
        })
        .await
        .unwrap();
    let (output, mut outputs) = mpsc::channel(4);
    let collect = async { while outputs.recv().await.is_some() {} };
    let execute = async {
        let (finish, ()) = tokio::join!(
            preflight.session.unwrap().run_with_body_policy(
                inputs,
                output,
                TransformedBodyPolicy::NotPolicyRelevant
            ),
            collect
        );
        finish.unwrap();
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), execute)
        .await
        .expect("shared permit must not wait for capacity");
    drop(held);
    assert_eq!(
        free_slots(&runner),
        (
            MAX_CONCURRENT_HTTP_MIDDLEWARE_SESSIONS,
            MAX_CONCURRENT_HTTP_MIDDLEWARE_STREAMS
        )
    );
}

#[tokio::test(start_paused = true)]
async fn deferred_preflight_capacity_wait_is_bounded_and_releases_the_stream_slot() {
    let first = scripted(
        "example/a",
        Preflight::Inspect(HttpBodyMode::Stream),
        Body::Uppercase,
    );
    let second = scripted(
        "example/b",
        Preflight::Inspect(HttpBodyMode::Buffered),
        Body::Unchanged,
    );
    let (runner, described) = scripted_chain(vec![first, Arc::clone(&second)]).await;
    let preflight = runner
        .preflight_described_http_request(described, request_input(b"hello"))
        .await
        .unwrap();
    let held = Arc::clone(&runner.registry.http_session_admission)
        .acquire_many_owned(u32::try_from(MAX_CONCURRENT_HTTP_MIDDLEWARE_SESSIONS).unwrap())
        .await
        .unwrap();
    let (input, inputs) = mpsc::channel(4);
    input
        .send(HttpBodyInput::Chunk(b"hello".to_vec()))
        .await
        .unwrap();
    input
        .send(HttpBodyInput::End {
            trailers: Vec::new(),
        })
        .await
        .unwrap();
    let (output, mut outputs) = mpsc::channel(4);
    let collect = async { while outputs.recv().await.is_some() {} };
    let (finish, ()) = tokio::join!(
        preflight.session.unwrap().run_with_body_policy(
            inputs,
            output,
            TransformedBodyPolicy::NotPolicyRelevant
        ),
        collect
    );
    let failure = finish.expect_err("no preflight capacity");
    assert_eq!(failure.failure.unwrap().code, HttpFailureCode::Unavailable);
    assert!(second.preflights.lock().unwrap().is_empty());
    drop(held);
    assert_eq!(
        free_slots(&runner),
        (
            MAX_CONCURRENT_HTTP_MIDDLEWARE_SESSIONS,
            MAX_CONCURRENT_HTTP_MIDDLEWARE_STREAMS
        )
    );
}

#[tokio::test(start_paused = true)]
async fn cancellation_closes_only_opened_stages_and_releases_capacity() {
    let mut first = ScriptedStage::new(
        "example/a",
        Preflight::Inspect(HttpBodyMode::Stream),
        Body::Uppercase,
    );
    first.output_after_input = true;
    let (first, second) = (
        Arc::new(first),
        scripted("example/b", Preflight::Continue, Body::Unchanged),
    );
    let (runner, described) = scripted_chain(vec![Arc::clone(&first), Arc::clone(&second)]).await;
    let preflight = runner
        .preflight_described_http_request(described, request_input(b"hello"))
        .await
        .unwrap();
    let (_input, inputs) = mpsc::channel(4);
    let (output, _outputs) = mpsc::channel(4);
    let task = tokio::spawn(preflight.session.unwrap().run_with_body_policy(
        inputs,
        output,
        TransformedBodyPolicy::NotPolicyRelevant,
    ));
    tokio::task::yield_now().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        *first.ended.lock().unwrap(),
        [openshell_core::proto::MiddlewareSessionEndReason::Cancellation as i32]
    );
    assert!(second.preflights.lock().unwrap().is_empty());
    assert!(second.ended.lock().unwrap().is_empty());
    assert_eq!(
        free_slots(&runner),
        (
            MAX_CONCURRENT_HTTP_MIDDLEWARE_SESSIONS,
            MAX_CONCURRENT_HTTP_MIDDLEWARE_STREAMS
        )
    );
}

#[tokio::test]
async fn response_preflight_carries_request_headers_within_head_limits() {
    let header = |name: &str, value: String| HttpHeader {
        name: name.into(),
        value,
    };
    let within = vec![header("content-type", "application/json".into())];
    let over: Vec<_> = (0..=crate::MAX_MIDDLEWARE_HEADERS)
        .map(|index| header("x-extra", index.to_string()))
        .collect();
    for (case, request_headers, allowed) in [("within", within, true), ("over", over, false)] {
        let stage = scripted("example/a", Preflight::Continue, Body::Unchanged);
        let (runner, described) = scripted_chain(vec![Arc::clone(&stage)]).await;
        let request = request_input(b"");
        let preflight = runner
            .preflight_http_response_pipeline(
                described,
                crate::HttpResponsePreflightInput {
                    context: request.context,
                    target: request.target,
                    status_code: 200,
                    headers: Vec::new(),
                    declared_body_length: Some(0),
                    connection_nominated_headers: Vec::new(),
                    request_headers: request_headers.clone(),
                },
                crate::HttpResponseDelivery::new(true),
            )
            .await
            .unwrap();

        assert_eq!(preflight.allowed, allowed, "{case}: {}", preflight.reason);
        let seen = stage.response_request_headers.lock().unwrap().clone();
        if allowed {
            assert_eq!(seen, [request_headers], "{case}");
        } else {
            // Over the head limits, the chain fails closed before any stage.
            assert!(seen.is_empty(), "{case}");
            assert_eq!(
                preflight.failure.map(|failure| failure.code),
                Some(HttpFailureCode::CannotInspect),
                "{case}"
            );
        }
    }
}

#[tokio::test]
async fn stages_cannot_change_headers_that_reference_credentials() {
    use HttpBodyMode::{Buffered, Stream};
    for (case, preflight, preflight_mutation, late_mutation) in [
        ("preflight mutation", Preflight::Continue, true, false),
        (
            "BUFFERED late mutation",
            Preflight::Inspect(Buffered),
            false,
            true,
        ),
        (
            "STREAM late mutation",
            Preflight::Inspect(Stream),
            false,
            true,
        ),
    ] {
        let stage = Arc::new(ScriptedStage {
            preflight_mutation,
            late_mutation,
            ..ScriptedStage::new("example/a", preflight, Body::Unchanged)
        });
        // The caller omits the header from the head and names it instead.
        let mut head = request_input(b"hello");
        head.headers.clear();
        head.credential_reference_headers = vec!["x-order".into()];

        let result = run_input(vec![stage], head, b"hello").await;

        assert!(!result.allowed, "{case}");
        assert!(
            result
                .reason
                .contains("cannot mutate protected header x-order"),
            "{case}: {}",
            result.reason
        );
    }
}
