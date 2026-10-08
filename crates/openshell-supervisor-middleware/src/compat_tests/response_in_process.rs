// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Main's in-process legacy response tests, written for the 0.1.x response
//! engine, run through [`super::harness`] on the response adapter.
//!
//! The services here implement the legacy `HttpResponsePreReturn` hook in
//! process. Expectations are the 0.1.x ones except where the stage pipeline
//! deliberately differs, which each such test says: output a whole-body stage
//! releases after failing open is held by a later stream stage until the
//! body ends, and stream stages are not held to the 0.1.x retained-body
//! budget because they retain nothing. Tests that probed the engine's
//! internal accounting assert the bytes delivered instead.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt as _;
use openshell_core::middleware::{HttpRequestView, InProcessMiddleware};
use openshell_core::proto::{
    Decision, ExistingHeaderAction, HeaderMutation, HttpRequestResult, HttpResponseBodyMode,
    HttpResponseBodyResult, HttpResponseBodyTransform, HttpResponseEvent, HttpResponseEventResult,
    HttpResponsePreflightInspect, HttpResponsePreflightResult, HttpResponsePreflightSkip,
    HttpResponseTrailersResult, MiddlewareBinding, MiddlewareManifest, MiddlewareSessionEndReason,
    WriteHeader, header_mutation, http_response_body_result, http_response_body_skip_remaining,
    http_response_body_transform, http_response_body_unit, http_response_event,
    http_response_event_result, http_response_preflight_result,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};

use super::harness::{ResponseCase, ResponseStep, preflight_response, run_response};
use crate::{
    ChainEntry, ChainRunner, HttpResponseInvocationOutcome, MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES,
    MAX_MIDDLEWARE_CONTEXT_BYTES, MAX_MIDDLEWARE_HEADER_BYTES, MAX_MIDDLEWARE_HEADERS,
    MAX_MIDDLEWARE_REASON_BYTES, MAX_MIDDLEWARE_TARGET_BYTES, OnError,
};

#[derive(Clone, Copy)]
enum Script {
    HeadersOnly,
    Stream,
    WholeBody,
    InvalidSequence,
    Configured,
    HangBody,
    LargeStream,
    Expansion,
    DeleteBody,
    SkipBody,
    Skip,
    InvalidSkipReason,
    TrailerMutation,
    InvalidTrailerMutation,
}

struct ResponseService {
    script: Script,
}

struct PreflightLifecycleService {
    completion_tx: mpsc::UnboundedSender<(String, Vec<MiddlewareSessionEndReason>)>,
}

#[derive(Clone)]
struct RemoteResponseService {
    session_end_tx: Option<mpsc::UnboundedSender<MiddlewareSessionEndReason>>,
}

#[tonic::async_trait]
impl openshell_core::proto::middleware::v1::supervisor_middleware_server::SupervisorMiddleware
    for RemoteResponseService
{
    type EvaluateWebSocketSessionStream = crate::WebSocketResponseStream;

    async fn describe(
        &self,
        _request: tonic::Request<openshell_core::proto::MiddlewareDescribeRequest>,
    ) -> Result<tonic::Response<MiddlewareManifest>, tonic::Status> {
        Ok(tonic::Response::new(response_manifest(
            "test/remote-response",
        )))
    }

    async fn validate_config(
        &self,
        _request: tonic::Request<openshell_core::proto::ValidateConfigRequest>,
    ) -> Result<tonic::Response<openshell_core::proto::ValidateConfigResponse>, tonic::Status> {
        Ok(tonic::Response::new(
            openshell_core::proto::ValidateConfigResponse {
                valid: true,
                reason: String::new(),
            },
        ))
    }

    async fn evaluate_http_request(
        &self,
        _request: tonic::Request<openshell_core::proto::HttpRequestEvaluation>,
    ) -> Result<tonic::Response<HttpRequestResult>, tonic::Status> {
        Ok(tonic::Response::new(HttpRequestResult {
            decision: Decision::Allow as i32,
            ..Default::default()
        }))
    }

    async fn evaluate_web_socket_session(
        &self,
        _request: tonic::Request<tonic::Streaming<openshell_core::proto::WebSocketSessionEvent>>,
    ) -> Result<tonic::Response<Self::EvaluateWebSocketSessionStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("HTTP response-only service"))
    }
}

#[tonic::async_trait]
impl openshell_core::proto::middleware::v1::http_response_pre_return_server::HttpResponsePreReturn
    for RemoteResponseService
{
    type EvaluateStream = crate::HttpResponseResultStream;
    type EvaluateHttpStream = crate::HttpResultStream;

    async fn evaluate(
        &self,
        request: tonic::Request<tonic::Streaming<HttpResponseEvent>>,
    ) -> Result<tonic::Response<Self::EvaluateStream>, tonic::Status> {
        let mut requests = request.into_inner();
        // Exercise servers that inspect the initial request before sending
        // response headers, rather than returning a stream immediately.
        let first = requests.next().await.expect("initial request");
        assert!(matches!(
            &first,
            Ok(HttpResponseEvent {
                event: Some(http_response_event::Event::Preflight(_))
            })
        ));
        let mut requests = futures::stream::iter([first]).chain(requests);
        let (sender, receiver) = mpsc::channel(4);
        let session_end_tx = self.session_end_tx.clone();
        tokio::spawn(async move {
            while let Some(Ok(event)) = requests.next().await {
                match event.event {
                    Some(http_response_event::Event::Preflight(_)) => {
                        let result = HttpResponseEventResult {
                            result: Some(http_response_event_result::Result::PreflightResult(
                                HttpResponsePreflightResult {
                                    action: Some(http_response_preflight_result::Action::Inspect(
                                        HttpResponsePreflightInspect {
                                            body_mode: HttpResponseBodyMode::HeadersOnly as i32,
                                            header_mutations: vec![write_header(
                                                "cache-control",
                                                "remote",
                                            )],
                                        },
                                    )),
                                    ..Default::default()
                                },
                            )),
                        };
                        if sender.send(Ok(result)).await.is_err() {
                            break;
                        }
                    }
                    Some(http_response_event::Event::SessionEnd(end)) => {
                        if let Some(sender) = &session_end_tx
                            && let Ok(reason) = MiddlewareSessionEndReason::try_from(end.reason)
                        {
                            let _ = sender.send(reason);
                        }
                        break;
                    }
                    None => break,
                    _ => {}
                }
            }
        });
        Ok(tonic::Response::new(Box::pin(ReceiverStream::new(
            receiver,
        ))))
    }

    async fn evaluate_http(
        &self,
        _request: tonic::Request<tonic::Streaming<openshell_core::proto::HttpEvent>>,
    ) -> Result<tonic::Response<Self::EvaluateHttpStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("legacy HTTP response service"))
    }
}

#[tonic::async_trait]
impl InProcessMiddleware for ResponseService {
    async fn describe(&self) -> MiddlewareManifest {
        MiddlewareManifest {
            name: "test/response".into(),
            service_version: "test".into(),
            bindings: vec![MiddlewareBinding {
                operation: openshell_core::proto::SupervisorMiddlewareOperation::HttpResponse
                    as i32,
                phase: openshell_core::proto::SupervisorMiddlewarePhase::PreReturn as i32,
                max_payload_bytes: if matches!(self.script, Script::LargeStream | Script::Expansion)
                {
                    128 * 1024
                } else {
                    4096
                },
                request_timeout: matches!(self.script, Script::HangBody).then(|| {
                    openshell_core::time::duration_from_std(Duration::from_millis(10))
                        .expect("test timeout is in protobuf range")
                }),
                ..Default::default()
            }],
            expected_audience: String::new(),
            extension: Some(openshell_core::extension_protocol::extension_metadata(
                openshell_core::extension_protocol::ExtensionFamily::SupervisorMiddleware,
                "openshell/test-response-middleware",
                "test",
                [],
            )),
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
        Ok(HttpRequestResult {
            decision: Decision::Allow as i32,
            ..Default::default()
        })
    }

    async fn open_http_response_pre_return(
        &self,
        mut requests: mpsc::Receiver<HttpResponseEvent>,
    ) -> Result<crate::HttpResponseResultStream, tonic::Status> {
        let (sender, receiver) = mpsc::channel(4);
        let script = self.script;
        tokio::spawn(async move {
            let mut selected_script = script;
            while let Some(event) = requests.recv().await {
                let Some(event) = event.event else {
                    break;
                };
                let result = match event {
                    http_response_event::Event::Preflight(preflight) => {
                        if matches!(script, Script::Configured) {
                            selected_script = match preflight
                                .config
                                .as_ref()
                                .and_then(|config| config.fields.get("mode"))
                                .and_then(|value| value.kind.as_ref())
                            {
                                Some(prost_types::value::Kind::StringValue(mode))
                                    if mode == "whole" =>
                                {
                                    Script::WholeBody
                                }
                                Some(prost_types::value::Kind::StringValue(mode))
                                    if mode == "stream" =>
                                {
                                    Script::Stream
                                }
                                _ => Script::HeadersOnly,
                            };
                        }
                        if matches!(selected_script, Script::Skip | Script::InvalidSkipReason) {
                            HttpResponseEventResult {
                                result: Some(http_response_event_result::Result::PreflightResult(
                                    HttpResponsePreflightResult {
                                        action: Some(http_response_preflight_result::Action::Skip(
                                            HttpResponsePreflightSkip {},
                                        )),
                                        reason: if matches!(
                                            selected_script,
                                            Script::InvalidSkipReason
                                        ) {
                                            "x".repeat(MAX_MIDDLEWARE_REASON_BYTES + 1)
                                        } else {
                                            "not selected".into()
                                        },
                                        reason_code: "path_not_selected".into(),
                                        ..Default::default()
                                    },
                                )),
                            }
                        } else {
                            let (body_mode, header_mutations) = match selected_script {
                                Script::HeadersOnly => (
                                    HttpResponseBodyMode::HeadersOnly,
                                    vec![write_header("cache-control", "private")],
                                ),
                                Script::Stream
                                | Script::InvalidSequence
                                | Script::HangBody
                                | Script::LargeStream
                                | Script::Expansion
                                | Script::DeleteBody
                                | Script::SkipBody
                                | Script::TrailerMutation
                                | Script::InvalidTrailerMutation => {
                                    (HttpResponseBodyMode::StreamBytes, Vec::new())
                                }
                                Script::WholeBody => {
                                    (HttpResponseBodyMode::WholeBodyBytes, Vec::new())
                                }
                                Script::Configured | Script::Skip | Script::InvalidSkipReason => {
                                    unreachable!()
                                }
                            };
                            HttpResponseEventResult {
                                result: Some(http_response_event_result::Result::PreflightResult(
                                    HttpResponsePreflightResult {
                                        action: Some(
                                            http_response_preflight_result::Action::Inspect(
                                                HttpResponsePreflightInspect {
                                                    body_mode: body_mode as i32,
                                                    header_mutations,
                                                },
                                            ),
                                        ),
                                        ..Default::default()
                                    },
                                )),
                            }
                        }
                    }
                    http_response_event::Event::Body(body) => {
                        if matches!(selected_script, Script::HangBody) {
                            continue;
                        }
                        let Some(http_response_body_unit::Payload::Data(data)) = body.payload
                        else {
                            break;
                        };
                        let replacement = match selected_script {
                            Script::Expansion => vec![b'x'; 128 * 1024],
                            Script::DeleteBody => Vec::new(),
                            Script::SkipBody => b"replacement".to_vec(),
                            Script::Stream
                            | Script::InvalidSequence
                            | Script::LargeStream
                            | Script::TrailerMutation
                            | Script::InvalidTrailerMutation => data.to_ascii_uppercase(),
                            Script::WholeBody => [b"whole:".as_slice(), &data].concat(),
                            Script::HeadersOnly
                            | Script::Configured
                            | Script::HangBody
                            | Script::Skip
                            | Script::InvalidSkipReason => break,
                        };
                        let transform = HttpResponseBodyTransform {
                            replacement: Some(http_response_body_transform::Replacement::Data(
                                replacement,
                            )),
                        };
                        let action = if matches!(selected_script, Script::SkipBody) {
                            http_response_body_result::Action::SkipRemaining(
                                openshell_core::proto::HttpResponseBodySkipRemaining {
                                    current: Some(
                                        http_response_body_skip_remaining::Current::Transform(
                                            transform,
                                        ),
                                    ),
                                },
                            )
                        } else {
                            http_response_body_result::Action::Transform(transform)
                        };
                        HttpResponseEventResult {
                            result: Some(http_response_event_result::Result::BodyResult(
                                HttpResponseBodyResult {
                                    sequence: if matches!(selected_script, Script::InvalidSequence)
                                    {
                                        body.sequence + 1
                                    } else {
                                        body.sequence
                                    },
                                    action: Some(action),
                                    ..Default::default()
                                },
                            )),
                        }
                    }
                    http_response_event::Event::Trailers(_) => HttpResponseEventResult {
                        result: Some(http_response_event_result::Result::TrailersResult(
                            HttpResponseTrailersResult {
                                trailer_mutations: match selected_script {
                                    Script::TrailerMutation => {
                                        vec![write_header("x-upstream", "changed")]
                                    }
                                    Script::InvalidTrailerMutation => vec![
                                        write_header("x-upstream", "changed"),
                                        write_header("x-new", "not-allowed"),
                                    ],
                                    _ => Vec::new(),
                                },
                                ..Default::default()
                            },
                        )),
                    },
                    http_response_event::Event::SessionEnd(_) => break,
                };
                if sender.send(Ok(result)).await.is_err() {
                    break;
                }
            }
        });
        Ok(Box::pin(ReceiverStream::new(receiver)))
    }
}

#[tonic::async_trait]
impl InProcessMiddleware for PreflightLifecycleService {
    async fn describe(&self) -> MiddlewareManifest {
        response_manifest("test/preflight-lifecycle")
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
        unreachable!()
    }

    async fn open_http_response_pre_return(
        &self,
        mut requests: mpsc::Receiver<HttpResponseEvent>,
    ) -> Result<crate::HttpResponseResultStream, tonic::Status> {
        let (sender, receiver) = mpsc::channel(4);
        let completion_tx = self.completion_tx.clone();
        tokio::spawn(async move {
            let Some(HttpResponseEvent {
                event: Some(http_response_event::Event::Preflight(preflight)),
            }) = requests.recv().await
            else {
                return;
            };
            let config_value = |name: &str| {
                preflight
                    .config
                    .as_ref()
                    .and_then(|config| config.fields.get(name))
                    .and_then(|value| value.kind.as_ref())
                    .and_then(|kind| match kind {
                        prost_types::value::Kind::StringValue(value) => Some(value.clone()),
                        _ => None,
                    })
                    .unwrap_or_default()
            };
            let label = config_value("label");
            let behavior = config_value("behavior");
            let inspect = |body_mode, header_mutations| HttpResponsePreflightResult {
                action: Some(http_response_preflight_result::Action::Inspect(
                    HttpResponsePreflightInspect {
                        body_mode,
                        header_mutations,
                    },
                )),
                ..Default::default()
            };
            let result = match behavior.as_str() {
                "stream" => http_response_event_result::Result::PreflightResult(inspect(
                    HttpResponseBodyMode::StreamBytes as i32,
                    Vec::new(),
                )),
                "wrong-envelope" => {
                    http_response_event_result::Result::BodyResult(HttpResponseBodyResult::default())
                }
                "invalid-diagnostics" => {
                    let mut result = inspect(HttpResponseBodyMode::HeadersOnly as i32, Vec::new());
                    result.reason = "x".repeat(MAX_MIDDLEWARE_REASON_BYTES + 1);
                    http_response_event_result::Result::PreflightResult(result)
                }
                "unsupported-body-mode" => http_response_event_result::Result::PreflightResult(
                    inspect(i32::MAX, Vec::new()),
                ),
                "invalid-header-mutation" => {
                    http_response_event_result::Result::PreflightResult(inspect(
                        HttpResponseBodyMode::HeadersOnly as i32,
                        vec![write_header("content-length", "1")],
                    ))
                }
                "no-action" => http_response_event_result::Result::PreflightResult(
                    HttpResponsePreflightResult::default(),
                ),
                behavior => panic!("unknown lifecycle test behavior: {behavior}"),
            };
            if sender
                .send(Ok(HttpResponseEventResult {
                    result: Some(result),
                }))
                .await
                .is_err()
            {
                return;
            }

            let mut terminal_reasons = Vec::new();
            while let Some(event) = requests.recv().await {
                if let Some(http_response_event::Event::SessionEnd(end)) = event.event
                    && let Ok(reason) = MiddlewareSessionEndReason::try_from(end.reason)
                {
                    terminal_reasons.push(reason);
                }
            }
            let _ = completion_tx.send((label, terminal_reasons));
        });
        Ok(Box::pin(ReceiverStream::new(receiver)))
    }
}

fn write_header(name: &str, value: &str) -> HeaderMutation {
    HeaderMutation {
        operation: Some(header_mutation::Operation::Write(WriteHeader {
            name: name.into(),
            value: value.into(),
            on_existing: ExistingHeaderAction::Overwrite as i32,
        })),
    }
}

fn response_manifest(name: &str) -> MiddlewareManifest {
    MiddlewareManifest {
        name: name.into(),
        service_version: "test".into(),
        bindings: vec![MiddlewareBinding {
            operation: openshell_core::proto::SupervisorMiddlewareOperation::HttpResponse as i32,
            phase: openshell_core::proto::SupervisorMiddlewarePhase::PreReturn as i32,
            max_payload_bytes: 4096,
            request_timeout: None,
            ..Default::default()
        }],
        expected_audience: String::new(),
        extension: Some(openshell_core::extension_protocol::extension_metadata(
            openshell_core::extension_protocol::ExtensionFamily::SupervisorMiddleware,
            name,
            "test",
            [],
        )),
    }
}

fn entry(on_error: OnError) -> ChainEntry {
    ChainEntry {
        name: "response".into(),
        implementation: "test/response".into(),
        order: 0,
        config: prost_types::Struct::default(),
        on_error,
    }
}

fn configured_entry(name: &str, order: i32, mode: &str) -> ChainEntry {
    ChainEntry {
        name: name.into(),
        implementation: "test/response".into(),
        order,
        config: prost_types::Struct {
            fields: [(
                "mode".into(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::StringValue(mode.into())),
                },
            )]
            .into(),
        },
        on_error: OnError::FailClosed,
    }
}

fn lifecycle_entry(name: &str, order: i32, behavior: &str, on_error: OnError) -> ChainEntry {
    let string_value = |value: &str| prost_types::Value {
        kind: Some(prost_types::value::Kind::StringValue(value.into())),
    };
    ChainEntry {
        name: name.into(),
        implementation: "test/preflight-lifecycle".into(),
        order,
        config: prost_types::Struct {
            fields: [
                ("label".into(), string_value(name)),
                ("behavior".into(), string_value(behavior)),
            ]
            .into(),
        },
        on_error,
    }
}

struct ReadPreflightBeforeOpening {
    failure: Option<bool>,
}

#[tonic::async_trait]
impl InProcessMiddleware for ReadPreflightBeforeOpening {
    async fn describe(&self) -> MiddlewareManifest {
        let mut manifest = response_manifest("test/response");
        manifest.bindings[0].request_timeout = Some(
            openshell_core::time::duration_from_std(Duration::from_millis(10))
                .expect("test timeout is in protobuf range"),
        );
        manifest
    }

    async fn validate_config(&self, _: &str, _: &prost_types::Struct) -> miette::Result<()> {
        Ok(())
    }

    async fn evaluate_http_request(
        &self,
        _: HttpRequestView<'_>,
    ) -> miette::Result<HttpRequestResult> {
        unreachable!()
    }

    async fn open_http_response_pre_return(
        &self,
        mut requests: mpsc::Receiver<HttpResponseEvent>,
    ) -> Result<crate::HttpResponseResultStream, tonic::Status> {
        let first = requests.recv().await.expect("initial preflight");
        assert!(matches!(
            first.event,
            Some(http_response_event::Event::Preflight(_))
        ));
        if let Some(hang) = self.failure {
            if hang {
                futures::future::pending::<()>().await;
            }
            return Err(tonic::Status::unavailable("startup failed"));
        }
        let response = HttpResponseEventResult {
            result: Some(http_response_event_result::Result::PreflightResult(
                HttpResponsePreflightResult {
                    action: Some(http_response_preflight_result::Action::Inspect(
                        HttpResponsePreflightInspect {
                            body_mode: HttpResponseBodyMode::HeadersOnly as i32,
                            header_mutations: Vec::new(),
                        },
                    )),
                    ..Default::default()
                },
            )),
        };
        Ok(Box::pin(futures::stream::iter([Ok(response)])))
    }
}

/// A `200 text/plain` response from `GET /data` with `status`.
fn case(status: u16, chunks: &[&[u8]]) -> ResponseCase {
    ResponseCase {
        status,
        path: "/data".into(),
        ..ResponseCase::ok("text/plain", chunks)
    }
}

fn runner(script: Script) -> ChainRunner {
    ChainRunner::new(Arc::new(ResponseService { script }))
}

#[tokio::test]
async fn response_preflight_envelope_limits_obey_selected_stage_policies() {
    let runner = runner(Script::HeadersOnly);
    for limit in 0..4 {
        let mut case = case(200, &[]);
        match limit {
            0 => case.request_id = "x".repeat(MAX_MIDDLEWARE_CONTEXT_BYTES + 1),
            1 => case.path = "x".repeat(MAX_MIDDLEWARE_TARGET_BYTES + 1),
            2 => case.headers = vec![case.headers[0].clone(); MAX_MIDDLEWARE_HEADERS + 1],
            _ => case.headers[0].1 = "x".repeat(MAX_MIDDLEWARE_HEADER_BYTES + 1),
        }
        for last_policy in [OnError::FailOpen, OnError::FailClosed] {
            let entries = [entry(OnError::FailOpen), entry(last_policy)];
            let (observed, held) = preflight_response(&runner, &entries, &case).await;
            assert_eq!(
                observed.preflight_allowed(),
                last_policy == OnError::FailOpen
            );
            assert_eq!(observed.headers, case.headers);
            assert!(!observed.inspected);
            assert_eq!(observed.records.len(), 2);
            assert!(
                observed
                    .records
                    .iter()
                    .all(|record| record.failed && record.stage_disabled)
            );
            assert_eq!(
                observed.records[1].failure_category.as_deref(),
                Some("payload_capacity")
            );
            held.end().await;
        }
    }
    let described = runner
        .describe_http_response_chain(&[entry(OnError::FailOpen), entry(OnError::FailClosed)])
        .await
        .unwrap();
    let outcome = runner.http_response_pipeline_input_unrepresentable(&described);
    assert!(!outcome.allowed);
    assert_eq!(outcome.diagnostics.invocations.len(), 2);
    assert!(outcome.diagnostics.invocations.iter().all(|invocation| {
        invocation
            .failure_reason
            .as_deref()
            .map(crate::legacy::response::failure_category)
            == Some("response_not_inspectable")
    }));
}

#[tokio::test]
async fn invalid_opened_preflight_stages_receive_one_failure_terminal_event() {
    for behavior in [
        "wrong-envelope",
        "invalid-diagnostics",
        "unsupported-body-mode",
        "invalid-header-mutation",
        "no-action",
    ] {
        for on_error in [OnError::FailOpen, OnError::FailClosed] {
            let (completion_tx, mut completion_rx) = mpsc::unbounded_channel();
            let runner = ChainRunner::new(Arc::new(PreflightLifecycleService { completion_tx }));
            let entries = [
                lifecycle_entry("prior", 0, "stream", OnError::FailClosed),
                lifecycle_entry("invalid", 1, behavior, on_error),
            ];
            let (observed, held) = preflight_response(&runner, &entries, &case(200, &[])).await;
            assert_eq!(observed.preflight_allowed(), on_error == OnError::FailOpen);
            held.end().await;

            let mut completions = BTreeMap::new();
            for _ in 0..2 {
                let (label, reasons) =
                    tokio::time::timeout(Duration::from_secs(1), completion_rx.recv())
                        .await
                        .expect("bounded terminal event delivery")
                        .expect("opened stage completion");
                assert!(completions.insert(label, reasons).is_none());
            }
            assert_eq!(
                completions.get("invalid").map(Vec::as_slice),
                Some([MiddlewareSessionEndReason::MiddlewareFailure].as_slice()),
                "invalid behavior: {behavior}, policy: {on_error:?}"
            );
            let prior_reason = if on_error == OnError::FailOpen {
                MiddlewareSessionEndReason::Normal
            } else {
                MiddlewareSessionEndReason::MiddlewareFailure
            };
            assert_eq!(
                completions.get("prior").map(Vec::as_slice),
                Some([prior_reason].as_slice()),
                "invalid behavior: {behavior}, policy: {on_error:?}"
            );
            assert!(completion_rx.try_recv().is_err());
        }
    }
}

#[tokio::test]
async fn preflight_can_be_read_before_open_returns() {
    let runner = ChainRunner::new(Arc::new(ReadPreflightBeforeOpening { failure: None }));
    let (observed, _held) = tokio::time::timeout(
        Duration::from_secs(1),
        preflight_response(&runner, &[entry(OnError::FailClosed)], &case(200, &[])),
    )
    .await
    .expect("bounded startup");
    assert!(observed.preflight_allowed(), "{:?}", observed.failure);
}

#[tokio::test]
async fn preflight_opening_failure_obeys_policy_and_releases_admission() {
    for hang in [false, true] {
        for on_error in [OnError::FailOpen, OnError::FailClosed] {
            let runner = ChainRunner::new(Arc::new(ReadPreflightBeforeOpening {
                failure: Some(hang),
            }));
            let permits = runner.registry.session_admission.available_permits();
            let (observed, held) = tokio::time::timeout(
                Duration::from_secs(1),
                preflight_response(&runner, &[entry(on_error)], &case(200, &[])),
            )
            .await
            .expect("bounded opening failure");
            assert_eq!(observed.preflight_allowed(), on_error == OnError::FailOpen);
            assert!(!observed.inspected);
            held.end().await;
            assert_eq!(
                runner.registry.session_admission.available_permits(),
                permits
            );
            assert!(observed.records[0].failed);
        }
    }
}

/// Two `fail_open` whole-body stages that outgrow their limit release the
/// original body through the rest of the chain. 0.1.x then resumed
/// streaming through the stream stage after them; that stage now holds its
/// output until the body ends, so the bytes arrive at the end, in order.
#[tokio::test]
async fn multiple_whole_body_barriers_release_the_original_on_overflow() {
    let runner = runner(Script::Configured);
    let mut entries = vec![
        configured_entry("first", 0, "whole"),
        configured_entry("second", 1, "whole"),
        configured_entry("stream", 2, "stream"),
    ];
    for entry in &mut entries {
        entry.on_error = OnError::FailOpen;
    }
    let chunk = vec![b'a'; 2048];
    let observed = run_response(
        &runner,
        &entries,
        case(200, &[&chunk, &chunk, &chunk, b"next"]),
    )
    .await;
    assert!(observed.failure.is_none(), "{:?}", observed.failure);
    let mut expected = vec![b'A'; 6144];
    expected.extend_from_slice(b"NEXT");
    assert_eq!(observed.body(), expected);
    let failed_open: Vec<_> = observed
        .records
        .iter()
        .filter(|record| record.outcome == HttpResponseInvocationOutcome::FailOpen)
        .map(|record| {
            (
                record.config_name.as_str(),
                record.failure_category.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        failed_open,
        [
            ("first", Some("payload_capacity")),
            ("second", Some("payload_capacity"))
        ]
    );
}

#[tokio::test]
async fn deleted_and_skip_remaining_units_release_their_output() {
    for script in [Script::DeleteBody, Script::SkipBody] {
        let observed = run_response(
            &runner(script),
            &[entry(OnError::FailClosed)],
            case(200, &[b"original", b"original", b"original"]),
        )
        .await;
        assert!(observed.failure.is_none(), "{:?}", observed.failure);
        let expected: Vec<Vec<u8>> = match script {
            Script::DeleteBody => vec![Vec::new(); 3],
            Script::SkipBody => vec![
                b"replacement".to_vec(),
                b"original".to_vec(),
                b"original".to_vec(),
            ],
            _ => unreachable!(),
        };
        assert_eq!(observed.released, expected);
        assert!(observed.finished.is_empty());
    }
}

/// Six stages that each expand every unit, including the empty final one, to
/// 128 KiB. 0.1.x retained each unit's output across the chain and failed
/// the response past its 8 MiB retained-body budget. The stage pipeline
/// streams every stage's output through bounded queues and retains none of
/// it, so the expansion streams through under either `on_error`.
#[tokio::test]
async fn expanding_stages_stream_through_without_retaining_their_output() {
    for on_error in [OnError::FailClosed, OnError::FailOpen] {
        let runner = runner(Script::Expansion);
        let permits = runner.registry.session_admission.available_permits();
        let entries = (0..6)
            .map(|order| {
                let mut entry = entry(on_error);
                entry.name = format!("expand-{order}");
                entry.order = order;
                entry
            })
            .collect::<Vec<_>>();
        let observed = tokio::time::timeout(
            Duration::from_secs(30),
            run_response(&runner, &entries, case(200, &[&[1]])),
        )
        .await
        .expect("bounded expansion");
        assert!(observed.failure.is_none(), "{:?}", observed.failure);
        // Each stage answers every 64 KiB unit it receives, and its final
        // unit, with two units.
        let units = (0..6).fold(1, |units, _| 2 * (units + 1));
        let body = observed.body();
        assert_eq!(body.len(), units * MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES);
        assert!(body.len() > crate::MAX_HTTP_RESPONSE_RETAINED_BODY_BYTES);
        assert!(body.iter().all(|byte| *byte == b'x'));
        assert_eq!(
            runner.registry.session_admission.available_permits(),
            permits
        );
    }
}

#[tokio::test]
async fn headers_only_preflight_applies_end_to_end_mutation() {
    let (observed, _held) = preflight_response(
        &runner(Script::HeadersOnly),
        &[entry(OnError::FailClosed)],
        &case(200, &[]),
    )
    .await;
    assert!(observed.preflight_allowed());
    assert_eq!(observed.header("cache-control"), Some("private"));
    assert!(!observed.inspected);
}

#[tokio::test]
async fn stream_mode_transforms_lockstep_units_and_preserves_trailers() {
    let observed = run_response(
        &runner(Script::Stream),
        &[entry(OnError::FailClosed)],
        case(200, &[b"hello"]).with_trailer("x-upstream", "retained"),
    )
    .await;
    assert!(observed.failure.is_none(), "{:?}", observed.failure);
    assert_eq!(observed.released, vec![b"HELLO".to_vec()]);
    assert!(observed.finished.is_empty());
    assert_eq!(
        observed.trailers,
        vec![("x-upstream".to_string(), "retained".to_string())]
    );
}

#[tokio::test]
async fn whole_body_mode_releases_replacement_only_at_finish() {
    let observed = run_response(
        &runner(Script::WholeBody),
        &[entry(OnError::FailClosed)],
        case(200, &[b"one", b"two"]),
    )
    .await;
    assert!(observed.failure.is_none(), "{:?}", observed.failure);
    assert_eq!(observed.released, vec![Vec::<u8>::new(), Vec::new()]);
    assert_eq!(observed.finished, b"whole:onetwo");
}

#[tokio::test]
async fn mixed_profile_chain_respects_policy_order_and_whole_body_barrier() {
    let observed = run_response(
        &runner(Script::Configured),
        &[
            configured_entry("stream", 20, "stream"),
            configured_entry("whole", 10, "whole"),
        ],
        case(200, &[b"hello"]),
    )
    .await;
    assert!(observed.failure.is_none(), "{:?}", observed.failure);
    assert_eq!(observed.released, vec![Vec::<u8>::new()]);
    assert_eq!(observed.finished, b"WHOLE:HELLO");
}

#[tokio::test]
async fn whole_body_overflow_obeys_fail_open_and_fail_closed() {
    let original = vec![b'a'; 4097];
    let later = [
        vec![b'b'; MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES],
        vec![b'c'; MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES],
    ];
    for on_error in [OnError::FailOpen, OnError::FailClosed] {
        let observed = run_response(
            &runner(Script::WholeBody),
            &[entry(on_error)],
            case(200, &[&original, &later[0], &later[1]]),
        )
        .await;
        if on_error == OnError::FailOpen {
            assert!(observed.failure.is_none(), "{:?}", observed.failure);
            assert_eq!(
                observed.released,
                vec![original.clone(), later[0].clone(), later[1].clone()],
                "the fail_open stage releases the original and every later unit"
            );
            assert!(observed.finished.is_empty());
        } else {
            let failure = observed.failure.expect("fail_closed stops delivery");
            assert_eq!(failure.step, ResponseStep::Chunk(0));
        }
    }
}

#[tokio::test]
async fn response_body_timeout_obeys_fail_open_and_fail_closed() {
    for on_error in [OnError::FailOpen, OnError::FailClosed] {
        let observed = run_response(
            &runner(Script::HangBody),
            &[entry(on_error)],
            case(200, &[b"unchanged"]),
        )
        .await;
        if on_error == OnError::FailOpen {
            assert!(observed.failure.is_none(), "{:?}", observed.failure);
            assert_eq!(observed.released, vec![b"unchanged".to_vec()]);
        } else {
            let failure = observed.failure.expect("fail_closed stops delivery");
            assert_eq!(failure.step, ResponseStep::Chunk(0));
            assert_eq!(failure.reason, "middleware_failed: middleware_timeout");
        }
    }
}

/// A stream stage never receives a unit over the 64 KiB platform cap, even
/// when its binding allows more: the relay splits a larger read. 0.1.x
/// required the relay to split it and failed an oversized unit with
/// `response_stream_unit_over_capacity`.
#[tokio::test]
async fn stream_units_never_exceed_platform_cap() {
    let maximum_unit = vec![b'A'; MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES];
    let oversized = vec![b'b'; MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES + 1];
    let observed = run_response(
        &runner(Script::LargeStream),
        &[entry(OnError::FailClosed)],
        case(200, &[&maximum_unit, &oversized]),
    )
    .await;
    assert!(observed.failure.is_none(), "{:?}", observed.failure);
    assert_eq!(
        observed.released,
        vec![maximum_unit, oversized.to_ascii_uppercase()]
    );
    let units: Vec<_> = observed
        .records
        .iter()
        .filter(|record| record.outcome == HttpResponseInvocationOutcome::Transform)
        .map(|record| record.input_size)
        .collect();
    assert_eq!(
        units,
        [
            MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES,
            MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES,
            1,
            0
        ],
        "two full units, the rest of the read, and the empty final unit"
    );
}

#[tokio::test]
async fn skip_reason_code_is_retained_and_oversized_reason_obeys_on_error() {
    let (observed, _held) = preflight_response(
        &runner(Script::Skip),
        &[entry(OnError::FailClosed)],
        &case(200, &[]),
    )
    .await;
    assert!(observed.preflight_allowed());
    assert!(!observed.inspected);
    assert_eq!(
        observed.records[0].reason_code.as_deref(),
        Some("path_not_selected")
    );

    for on_error in [OnError::FailOpen, OnError::FailClosed] {
        let (observed, _held) = preflight_response(
            &runner(Script::InvalidSkipReason),
            &[entry(on_error)],
            &case(200, &[]),
        )
        .await;
        assert_eq!(observed.preflight_allowed(), on_error == OnError::FailOpen);
        assert!(!observed.inspected);
    }
}

#[tokio::test]
async fn response_trailers_are_mutated_by_body_stage() {
    let observed = run_response(
        &runner(Script::TrailerMutation),
        &[entry(OnError::FailClosed)],
        case(200, &[b"body"]).with_trailer("x-upstream", "retained"),
    )
    .await;
    assert!(observed.failure.is_none(), "{:?}", observed.failure);
    assert_eq!(
        observed.trailers,
        vec![("x-upstream".to_string(), "changed".to_string())]
    );
}

#[tokio::test]
async fn invalid_trailer_mutations_are_atomic_and_keep_failure_diagnostics() {
    for on_error in [OnError::FailOpen, OnError::FailClosed] {
        let observed = run_response(
            &runner(Script::InvalidTrailerMutation),
            &[entry(on_error)],
            case(200, &[b"body"]).with_trailer("x-upstream", "retained"),
        )
        .await;
        let last = observed.records.last().map(|record| record.outcome);
        if on_error == OnError::FailOpen {
            assert!(observed.failure.is_none(), "{:?}", observed.failure);
            assert_eq!(
                observed.trailers,
                vec![("x-upstream".to_string(), "retained".to_string())]
            );
            assert_eq!(last, Some(HttpResponseInvocationOutcome::FailOpen));
        } else {
            let failure = observed.failure.expect("fail_closed stops delivery");
            assert_eq!(failure.step, ResponseStep::Finish);
            assert_eq!(last, Some(HttpResponseInvocationOutcome::FailClosed));
        }
    }
}

#[tokio::test]
async fn invalid_sequence_obeys_fail_open_and_fail_closed() {
    for on_error in [OnError::FailOpen, OnError::FailClosed] {
        let observed = run_response(
            &runner(Script::InvalidSequence),
            &[entry(on_error)],
            case(200, &[b"unchanged"]),
        )
        .await;
        if on_error == OnError::FailOpen {
            assert!(observed.failure.is_none(), "{:?}", observed.failure);
            assert_eq!(observed.released, vec![b"unchanged".to_vec()]);
        } else {
            let failure = observed.failure.expect("fail_closed stops delivery");
            assert_eq!(failure.step, ResponseStep::Chunk(0));
        }
    }
}

#[tokio::test]
async fn body_inspection_restrictions_obey_fail_open_and_fail_closed() {
    let mut cases = vec![case(206, &[])];
    for (name, value) in [
        ("content-range", "bytes 0-3/10"),
        ("content-type", "multipart/byteranges; boundary=test"),
        ("cache-control", "private, no-transform"),
        ("content-encoding", "gzip"),
    ] {
        cases.push(case(200, &[]).with_header(name, value));
    }
    for status in [204, 304] {
        cases.push(case(status, &[]));
    }
    cases.push(ResponseCase {
        method: "HEAD".into(),
        ..case(200, &[])
    });

    for candidate in cases {
        for on_error in [OnError::FailOpen, OnError::FailClosed] {
            let (observed, _held) =
                preflight_response(&runner(Script::Stream), &[entry(on_error)], &candidate).await;
            assert_eq!(observed.preflight_allowed(), on_error == OnError::FailOpen);
            assert!(!observed.inspected);
        }
    }
}

#[tokio::test]
async fn remote_service_executes_through_http_response_pre_return_rpc() {
    use openshell_core::proto::middleware::v1::http_response_pre_return_server::HttpResponsePreReturnServer;
    use openshell_core::proto::middleware::v1::supervisor_middleware_server::SupervisorMiddlewareServer;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind response middleware");
    let address = listener.local_addr().expect("response middleware address");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let (session_end_tx, mut session_end_rx) = mpsc::unbounded_channel();
    let service = RemoteResponseService {
        session_end_tx: Some(session_end_tx),
    };
    let server = tonic::transport::Server::builder()
        .add_service(SupervisorMiddlewareServer::new(service.clone()))
        .add_service(HttpResponsePreReturnServer::new(service))
        .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
            let _ = shutdown_rx.await;
        });
    let server_task = tokio::spawn(server);
    let registry = crate::MiddlewareRegistry::connect_services(
        Vec::new(),
        vec![openshell_core::proto::SupervisorMiddlewareService {
            name: "remote-response".into(),
            grpc_endpoint: format!("http://{address}"),
            max_payload_bytes: 4096,
            allow_insecure_transport: true,
            ..Default::default()
        }],
    )
    .await
    .expect("connect remote response middleware");
    let runner = ChainRunner::from_registry(registry);
    let (observed, _held) = preflight_response(
        &runner,
        &[ChainEntry {
            name: "response".into(),
            implementation: "remote-response".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        }],
        &case(200, &[]),
    )
    .await;

    assert!(observed.preflight_allowed());
    assert_eq!(observed.header("cache-control"), Some("remote"));
    assert!(!observed.inspected);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), session_end_rx.recv())
            .await
            .expect("bounded session end delivery"),
        Some(MiddlewareSessionEndReason::Normal)
    );
    assert!(session_end_rx.try_recv().is_err());

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .expect("bounded server shutdown")
        .expect("join response middleware server")
        .expect("serve response middleware");
}
