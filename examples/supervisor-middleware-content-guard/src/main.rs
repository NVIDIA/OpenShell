// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::ops::Range;

use clap::Parser;
use openshell_core::middleware::{HttpResponseResultStream, WebSocketResponseStream};
use openshell_core::proto::middleware::v1::http_response_pre_return_server::{
    HttpResponsePreReturn, HttpResponsePreReturnServer,
};
use openshell_core::proto::middleware::v1::supervisor_middleware_server::{
    SupervisorMiddleware, SupervisorMiddlewareServer,
};
use openshell_core::proto::{
    Decision, ExistingHeaderAction, Finding, HeaderMutation, HttpRequestEvaluation,
    HttpRequestResult, HttpResponseBodyMode, HttpResponseBodyResult, HttpResponseBodyTransform,
    HttpResponseEvent, HttpResponseEventResult, HttpResponsePreflightDecision,
    HttpResponsePreflightInspect, HttpResponsePreflightSkip, MiddlewareBinding, MiddlewareManifest,
    SupervisorMiddlewareOperation, SupervisorMiddlewarePhase, ValidateConfigRequest,
    ValidateConfigResponse, WebSocketMessage, WebSocketMessageResult, WebSocketPreflightAction,
    WebSocketPreflightDecision, WebSocketSessionEvent, WebSocketSessionEventResult, WriteHeader,
    header_mutation, http_response_body_result, http_response_body_transform,
    http_response_body_unit, http_response_event, http_response_event_result,
    http_response_preflight_decision, web_socket_message, web_socket_message_result,
    web_socket_session_event, web_socket_session_event_result,
};
use prost_types::Struct;
use prost_types::value::Kind;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt};
use tonic::transport::Server;
use tonic::{Request, Response, Status};

const MANIFEST_NAME: &str = "example/content-guard-service";
const PHASE: SupervisorMiddlewarePhase = SupervisorMiddlewarePhase::PreCredentials;
const MAX_PAYLOAD_BYTES: u64 = 256 * 1024;
const DEFAULT_REPLACEMENT: &str = "[REDACTED]";

#[derive(Debug, Parser)]
#[command(about = "Run the example OpenShell supervisor middleware service")]
struct Cli {
    /// Address on which to serve plaintext gRPC.
    #[arg(long, default_value = "127.0.0.1:50051")]
    bind: SocketAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Redact,
    Deny,
}

#[derive(Debug, PartialEq, Eq)]
struct GuardConfig {
    mode: Mode,
    terms: Vec<String>,
    replacement: String,
}

impl GuardConfig {
    fn parse(config: Option<&Struct>) -> Result<Self, String> {
        let config = config.ok_or_else(|| "config is required".to_string())?;
        if let Some(field) = config
            .fields
            .keys()
            .find(|field| !matches!(field.as_str(), "mode" | "terms" | "replacement"))
        {
            return Err(format!("unsupported config field '{field}'"));
        }

        let mode = match optional_string_field(config, "mode")?.unwrap_or("redact") {
            "redact" => Mode::Redact,
            "deny" => Mode::Deny,
            _ => return Err("config.mode must be 'redact' or 'deny'".into()),
        };

        let terms = config
            .fields
            .get("terms")
            .and_then(|value| match value.kind.as_ref() {
                Some(Kind::ListValue(value)) => Some(&value.values),
                _ => None,
            })
            .ok_or_else(|| "config.terms must be a non-empty string list".to_string())?;
        let mut unique_terms = BTreeSet::new();
        for term in terms {
            let Some(Kind::StringValue(term)) = term.kind.as_ref() else {
                return Err("config.terms must contain only strings".into());
            };
            if term.is_empty() {
                return Err("config.terms cannot contain an empty string".into());
            }
            unique_terms.insert(term.clone());
        }
        if unique_terms.is_empty() {
            return Err("config.terms must contain at least one string".into());
        }

        let replacement = optional_string_field(config, "replacement")?
            .unwrap_or(DEFAULT_REPLACEMENT)
            .to_string();
        if mode == Mode::Deny && config.fields.contains_key("replacement") {
            return Err("config.replacement is only valid in redact mode".into());
        }

        Ok(Self {
            mode,
            terms: unique_terms.into_iter().collect(),
            replacement,
        })
    }
}

fn optional_string_field<'a>(config: &'a Struct, name: &str) -> Result<Option<&'a str>, String> {
    let Some(value) = config.fields.get(name) else {
        return Ok(None);
    };
    match value.kind.as_ref() {
        Some(Kind::StringValue(value)) => Ok(Some(value.as_str())),
        _ => Err(format!("config.{name} must be a string")),
    }
}

#[derive(Debug, Default)]
struct ContentGuard;

impl ContentGuard {
    fn websocket_stream<S>(mut events: S) -> WebSocketResponseStream
    where
        S: Stream<Item = Result<WebSocketSessionEvent, Status>> + Send + Unpin + 'static,
    {
        let (results_tx, results_rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            let mut config = None;
            let mut started = false;
            let mut sequence_lower_bound = Some(1_u64);

            while let Some(event) = events.next().await {
                let event = match event {
                    Ok(event) => event,
                    Err(error) => {
                        let _ = results_tx.send(Err(error)).await;
                        break;
                    }
                };
                let result = match event.event {
                    Some(web_socket_session_event::Event::Preflight(preflight))
                        if config.is_none() && !started =>
                    {
                        if let Err(error) = validate_phase(preflight.phase) {
                            Err(Status::invalid_argument(error))
                        } else {
                            match GuardConfig::parse(preflight.config.as_ref()) {
                                Ok(selected_config) => {
                                    config = Some(selected_config);
                                    Ok(Some(WebSocketSessionEventResult {
                                        result: Some(
                                            web_socket_session_event_result::Result::PreflightDecision(
                                                WebSocketPreflightDecision {
                                                    action: WebSocketPreflightAction::Inspect
                                                        as i32,
                                                    ..Default::default()
                                                },
                                            ),
                                        ),
                                    }))
                                }
                                Err(error) => Err(Status::invalid_argument(error)),
                            }
                        }
                    }
                    Some(web_socket_session_event::Event::SessionStart(_))
                        if config.is_some() && !started =>
                    {
                        started = true;
                        Ok(None)
                    }
                    Some(web_socket_session_event::Event::Message(message)) if started => {
                        if let Err(error) = advance_sequence_lower_bound(
                            &mut sequence_lower_bound,
                            message.sequence,
                        ) {
                            Err(error)
                        } else {
                            let selected_config =
                                config.as_ref().expect("started stream has config");
                            evaluate_websocket_message(selected_config, &message).map(|result| {
                                Some(WebSocketSessionEventResult {
                                    result: Some(
                                        web_socket_session_event_result::Result::MessageResult(
                                            result,
                                        ),
                                    ),
                                })
                            })
                        }
                    }
                    Some(web_socket_session_event::Event::SessionEnd(_)) if config.is_some() => {
                        break;
                    }
                    _ => Err(Status::failed_precondition(
                        "invalid content guard WebSocket session lifecycle",
                    )),
                };

                match result {
                    Ok(Some(result)) => {
                        if results_tx.send(Ok(result)).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        let _ = results_tx.send(Err(error)).await;
                        break;
                    }
                }
            }
        });
        Box::pin(tokio_stream::wrappers::ReceiverStream::new(results_rx))
    }
}

#[tonic::async_trait]
impl SupervisorMiddleware for ContentGuard {
    type EvaluateWebSocketSessionStream = WebSocketResponseStream;

    async fn describe(
        &self,
        _request: Request<()>,
    ) -> Result<Response<MiddlewareManifest>, Status> {
        Ok(Response::new(MiddlewareManifest {
            name: MANIFEST_NAME.into(),
            service_version: env!("CARGO_PKG_VERSION").into(),
            bindings: vec![
                MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                    phase: PHASE as i32,
                    max_payload_bytes: MAX_PAYLOAD_BYTES,
                    timeout: String::new(),
                },
                MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::WebsocketMessage as i32,
                    phase: PHASE as i32,
                    max_payload_bytes: MAX_PAYLOAD_BYTES,
                    timeout: String::new(),
                },
                MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpResponse as i32,
                    phase: SupervisorMiddlewarePhase::PreReturn as i32,
                    max_payload_bytes: MAX_PAYLOAD_BYTES,
                    timeout: String::new(),
                },
            ],
            expected_audience: String::new(),
        }))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        let request = request.into_inner();
        let validation = GuardConfig::parse(request.config.as_ref());
        Ok(Response::new(match validation {
            Ok(_) => ValidateConfigResponse {
                valid: true,
                reason: String::new(),
            },
            Err(reason) => ValidateConfigResponse {
                valid: false,
                reason,
            },
        }))
    }

    async fn evaluate_http_request(
        &self,
        request: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        let request = request.into_inner();
        validate_phase(request.phase).map_err(Status::invalid_argument)?;
        let config =
            GuardConfig::parse(request.config.as_ref()).map_err(Status::invalid_argument)?;
        let body = String::from_utf8(request.body)
            .map_err(|_| Status::invalid_argument("content guard requires a UTF-8 body"))?;
        Ok(Response::new(evaluate(&config, &body)))
    }

    async fn evaluate_web_socket_session(
        &self,
        request: Request<tonic::Streaming<WebSocketSessionEvent>>,
    ) -> Result<Response<Self::EvaluateWebSocketSessionStream>, Status> {
        Ok(Response::new(Self::websocket_stream(request.into_inner())))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResponseMode {
    HeadersOnly,
    WholeBody,
    Stream,
}

#[derive(Debug, Default)]
struct ResponseSessionState {
    selected: Option<ResponseMode>,
    next_sequence: u64,
    body_ended: bool,
}

impl ResponseSessionState {
    fn preflight(
        &mut self,
        preflight: openshell_core::proto::HttpResponsePreflight,
    ) -> Result<HttpResponseEventResult, Status> {
        if self.selected.is_some() {
            return Err(Status::failed_precondition("duplicate response preflight"));
        }
        GuardConfig::parse(preflight.config.as_ref()).map_err(Status::invalid_argument)?;
        let path = preflight
            .target
            .as_ref()
            .map(|target| target.path.as_str())
            .unwrap_or_default();
        let Some(selected) = response_mode_for_path(path) else {
            return Ok(response_preflight_skip());
        };
        self.selected = Some(selected);
        self.next_sequence = 1;
        self.body_ended = false;
        Ok(response_preflight_inspect(selected))
    }

    fn body(
        &mut self,
        body: openshell_core::proto::HttpResponseBodyUnit,
    ) -> Result<HttpResponseEventResult, Status> {
        let selected = self
            .selected
            .ok_or_else(|| Status::failed_precondition("body arrived before preflight"))?;
        if selected == ResponseMode::HeadersOnly {
            return Err(Status::failed_precondition(
                "headers-only sessions do not receive body events",
            ));
        }
        if self.body_ended {
            return Err(Status::failed_precondition(
                "body arrived after end_of_stream",
            ));
        }
        if body.sequence != self.next_sequence {
            return Err(Status::invalid_argument(format!(
                "expected body sequence {}, received {}",
                self.next_sequence, body.sequence
            )));
        }
        self.next_sequence = self.next_sequence.saturating_add(1);
        let Some(http_response_body_unit::Payload::Data(data)) = body.payload else {
            return Err(Status::invalid_argument("body data is required"));
        };
        self.body_ended = body.end_of_stream;
        let replacement = match selected {
            ResponseMode::WholeBody => [b"[whole] ".as_slice(), &data].concat(),
            ResponseMode::Stream => data.to_ascii_uppercase(),
            ResponseMode::HeadersOnly => unreachable!(),
        };
        Ok(HttpResponseEventResult {
            result: Some(http_response_event_result::Result::BodyResult(
                HttpResponseBodyResult {
                    sequence: body.sequence,
                    action: Some(http_response_body_result::Action::Transform(
                        HttpResponseBodyTransform {
                            replacement: Some(http_response_body_transform::Replacement::Data(
                                replacement,
                            )),
                        },
                    )),
                    ..Default::default()
                },
            )),
        })
    }
}

fn response_mode_for_path(path: &str) -> Option<ResponseMode> {
    match path {
        "/headers-only" => Some(ResponseMode::HeadersOnly),
        "/whole-body" => Some(ResponseMode::WholeBody),
        "/stream" => Some(ResponseMode::Stream),
        _ => None,
    }
}

fn response_preflight_skip() -> HttpResponseEventResult {
    HttpResponseEventResult {
        result: Some(http_response_event_result::Result::PreflightDecision(
            HttpResponsePreflightDecision {
                action: Some(http_response_preflight_decision::Action::Skip(
                    HttpResponsePreflightSkip {},
                )),
                reason: "path is outside the response example".into(),
                reason_code: "path_not_selected".into(),
                ..Default::default()
            },
        )),
    }
}

fn response_preflight_inspect(selected: ResponseMode) -> HttpResponseEventResult {
    let body_mode = match selected {
        ResponseMode::HeadersOnly => HttpResponseBodyMode::HeadersOnly,
        ResponseMode::WholeBody => HttpResponseBodyMode::WholeBodyBytes,
        ResponseMode::Stream => HttpResponseBodyMode::StreamBytes,
    };
    let mode_name = match selected {
        ResponseMode::HeadersOnly => "headers-only",
        ResponseMode::WholeBody => "whole-body",
        ResponseMode::Stream => "stream",
    };
    HttpResponseEventResult {
        result: Some(http_response_event_result::Result::PreflightDecision(
            HttpResponsePreflightDecision {
                action: Some(http_response_preflight_decision::Action::Inspect(
                    HttpResponsePreflightInspect {
                        body_mode: body_mode as i32,
                        header_mutations: vec![write_header("x-example-response-mode", mode_name)],
                    },
                )),
                ..Default::default()
            },
        )),
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

#[tonic::async_trait]
impl HttpResponsePreReturn for ContentGuard {
    type EvaluateStream = HttpResponseResultStream;

    async fn evaluate(
        &self,
        request: Request<tonic::Streaming<HttpResponseEvent>>,
    ) -> Result<Response<Self::EvaluateStream>, Status> {
        let mut events = request.into_inner();
        let (sender, receiver) = mpsc::channel(4);
        tokio::spawn(async move {
            let mut state = ResponseSessionState::default();
            while let Some(event) = events.next().await {
                let event = match event {
                    Ok(event) => event,
                    Err(error) => {
                        let _ = sender.send(Err(error)).await;
                        break;
                    }
                };
                let result = match event.event {
                    Some(http_response_event::Event::Preflight(preflight)) => {
                        state.preflight(preflight).map(Some)
                    }
                    Some(http_response_event::Event::Body(body)) => state.body(body).map(Some),
                    Some(http_response_event::Event::SessionEnd(_)) => break,
                    None => Err(Status::invalid_argument("response event is required")),
                };
                match result {
                    Ok(Some(result)) => {
                        if sender.send(Ok(result)).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        let _ = sender.send(Err(error)).await;
                        break;
                    }
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }
}

fn validate_phase(phase: i32) -> Result<(), String> {
    if phase != PHASE as i32 {
        return Err(format!("unsupported phase '{phase}'"));
    }
    Ok(())
}

fn evaluate(config: &GuardConfig, body: &str) -> HttpRequestResult {
    let (ranges, match_count, matched_term_count) = find_match_ranges(body, &config.terms);

    if match_count == 0 {
        return allow_result();
    }

    let finding = Finding {
        r#type: "content_guard.match".into(),
        label: "configured content matched".into(),
        count: match_count,
        confidence: "high".into(),
        severity: "medium".into(),
    };
    let metadata = HashMap::from([
        ("match_count".into(), match_count.to_string()),
        ("matched_term_count".into(), matched_term_count.to_string()),
        (
            "mode".into(),
            match config.mode {
                Mode::Redact => "redact".into(),
                Mode::Deny => "deny".into(),
            },
        ),
    ]);

    match config.mode {
        Mode::Redact => HttpRequestResult {
            decision: Decision::Allow as i32,
            reason: String::new(),
            body: redact_ranges(body, &ranges, &config.replacement).into_bytes(),
            has_body: true,
            header_mutations: Vec::new(),
            findings: vec![finding],
            metadata,
            reason_code: String::new(),
        },
        Mode::Deny => HttpRequestResult {
            decision: Decision::Deny as i32,
            reason: "payload matched configured content".into(),
            body: Vec::new(),
            has_body: false,
            header_mutations: Vec::new(),
            findings: vec![finding],
            metadata,
            reason_code: "content_match".into(),
        },
    }
}

fn evaluate_websocket_message(
    config: &GuardConfig,
    message: &WebSocketMessage,
) -> Result<WebSocketMessageResult, Status> {
    let Some(web_socket_message::Payload::Text(payload)) = message.payload.as_ref() else {
        return Err(Status::invalid_argument(
            "content guard supports only WebSocket text messages",
        ));
    };
    let payload_bytes = u64::try_from(payload.len()).map_err(|_| {
        Status::invalid_argument("WebSocket text message length is not representable")
    })?;
    if payload_bytes > MAX_PAYLOAD_BYTES {
        return Err(Status::invalid_argument(format!(
            "WebSocket text message exceeds {MAX_PAYLOAD_BYTES} bytes"
        )));
    }
    let result = evaluate(config, payload);
    let replacement = if result.has_body {
        Some(web_socket_message_result::Replacement::Text(
            String::from_utf8(result.body)
                .expect("content guard replacements are constructed from UTF-8 text"),
        ))
    } else {
        None
    };
    Ok(WebSocketMessageResult {
        sequence: message.sequence,
        decision: result.decision,
        replacement,
        reason: result.reason,
        findings: result.findings,
        metadata: result.metadata,
        reason_code: result.reason_code,
    })
}

fn advance_sequence_lower_bound(
    lower_bound: &mut Option<u64>,
    sequence: u64,
) -> Result<(), Status> {
    let Some(current_lower_bound) = *lower_bound else {
        return Err(Status::invalid_argument(
            "WebSocket message sequence must be strictly increasing",
        ));
    };
    if sequence < current_lower_bound {
        return Err(Status::invalid_argument(
            "WebSocket message sequence must be strictly increasing",
        ));
    }
    *lower_bound = sequence.checked_add(1);
    Ok(())
}

fn find_match_ranges(body: &str, terms: &[String]) -> (Vec<Range<usize>>, u32, u32) {
    let mut ranges = Vec::new();
    let mut match_count = 0_u32;
    let mut matched_term_count = 0_u32;

    for term in terms {
        let mut term_matched = false;
        for (start, _) in body.char_indices() {
            if body[start..].starts_with(term) {
                ranges.push(start..start + term.len());
                match_count = match_count.saturating_add(1);
                term_matched = true;
            }
        }
        if term_matched {
            matched_term_count = matched_term_count.saturating_add(1);
        }
    }

    ranges.sort_unstable_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then_with(|| right.end.cmp(&left.end))
    });
    (
        merge_overlapping_ranges(ranges),
        match_count,
        matched_term_count,
    )
}

fn merge_overlapping_ranges(ranges: Vec<Range<usize>>) -> Vec<Range<usize>> {
    let mut merged: Vec<Range<usize>> = Vec::new();
    for range in ranges {
        if let Some(previous) = merged.last_mut()
            && range.start < previous.end
        {
            previous.end = previous.end.max(range.end);
            continue;
        }
        merged.push(range);
    }
    merged
}

fn redact_ranges(body: &str, ranges: &[Range<usize>], replacement: &str) -> String {
    let mut transformed = String::with_capacity(body.len());
    let mut cursor = 0;
    for range in ranges {
        transformed.push_str(&body[cursor..range.start]);
        transformed.push_str(replacement);
        cursor = range.end;
    }
    transformed.push_str(&body[cursor..]);
    transformed
}

fn allow_result() -> HttpRequestResult {
    HttpRequestResult {
        decision: Decision::Allow as i32,
        reason: String::new(),
        body: Vec::new(),
        has_body: false,
        header_mutations: Vec::new(),
        findings: Vec::new(),
        metadata: HashMap::new(),
        reason_code: String::new(),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    println!("serving {MANIFEST_NAME} on http://{}", cli.bind);
    Server::builder()
        .add_service(SupervisorMiddlewareServer::new(ContentGuard))
        .add_service(HttpResponsePreReturnServer::new(ContentGuard))
        .serve(cli.bind)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{
        HttpRequestTarget, HttpResponseBodyUnit, HttpResponsePreflight, MiddlewareSessionEnd,
        WebSocketPreflight, WebSocketSessionStart,
    };
    use prost_types::{ListValue, Value};
    use std::collections::BTreeMap;

    fn string(value: &str) -> Value {
        Value {
            kind: Some(Kind::StringValue(value.into())),
        }
    }

    fn config(mode: &str, terms: &[&str], replacement: Option<&str>) -> Struct {
        let mut fields = BTreeMap::from([
            ("mode".into(), string(mode)),
            (
                "terms".into(),
                Value {
                    kind: Some(Kind::ListValue(ListValue {
                        values: terms.iter().map(|term| string(term)).collect(),
                    })),
                },
            ),
        ]);
        if let Some(replacement) = replacement {
            fields.insert("replacement".into(), string(replacement));
        }
        Struct { fields }
    }

    fn event(event: web_socket_session_event::Event) -> Result<WebSocketSessionEvent, Status> {
        Ok(WebSocketSessionEvent { event: Some(event) })
    }

    #[tokio::test]
    async fn manifest_advertises_request_response_and_websocket_bindings() {
        let manifest = SupervisorMiddleware::describe(&ContentGuard, Request::new(()))
            .await
            .expect("describe")
            .into_inner();

        assert_eq!(manifest.bindings.len(), 3);
        assert_eq!(
            manifest.bindings[0].operation,
            SupervisorMiddlewareOperation::HttpRequest as i32
        );
        assert_eq!(manifest.bindings[0].max_payload_bytes, MAX_PAYLOAD_BYTES);
        assert_eq!(
            manifest.bindings[1].operation,
            SupervisorMiddlewareOperation::WebsocketMessage as i32
        );
        assert_eq!(manifest.bindings[1].max_payload_bytes, MAX_PAYLOAD_BYTES);
        assert_eq!(
            manifest.bindings[2].operation,
            SupervisorMiddlewareOperation::HttpResponse as i32
        );
        assert_eq!(
            manifest.bindings[2].phase,
            SupervisorMiddlewarePhase::PreReturn as i32
        );
        assert_eq!(manifest.bindings[2].max_payload_bytes, MAX_PAYLOAD_BYTES);
    }

    fn response_preflight(path: &str) -> HttpResponsePreflight {
        HttpResponsePreflight {
            target: Some(HttpRequestTarget {
                path: path.into(),
                ..Default::default()
            }),
            config: Some(config("redact", &["prototype-secret"], Some("[FILTERED]"))),
            ..Default::default()
        }
    }

    #[test]
    fn paths_select_all_three_response_modes() {
        for (path, expected) in [
            ("/headers-only", HttpResponseBodyMode::HeadersOnly),
            ("/whole-body", HttpResponseBodyMode::WholeBodyBytes),
            ("/stream", HttpResponseBodyMode::StreamBytes),
        ] {
            let mut state = ResponseSessionState::default();
            let result = state.preflight(response_preflight(path)).unwrap();
            let Some(http_response_event_result::Result::PreflightDecision(decision)) =
                result.result
            else {
                panic!("expected preflight decision");
            };
            let Some(http_response_preflight_decision::Action::Inspect(inspect)) = decision.action
            else {
                panic!("expected inspect decision");
            };
            assert_eq!(inspect.body_mode, expected as i32);
        }
    }

    #[test]
    fn whole_body_and_stream_transform_differently() {
        for (path, expected) in [
            ("/whole-body", b"[whole] hello".as_slice()),
            ("/stream", b"HELLO".as_slice()),
        ] {
            let mut state = ResponseSessionState::default();
            state.preflight(response_preflight(path)).unwrap();
            let result = state
                .body(HttpResponseBodyUnit {
                    sequence: 1,
                    payload: Some(http_response_body_unit::Payload::Data(b"hello".to_vec())),
                    end_of_stream: true,
                })
                .unwrap();
            let Some(http_response_event_result::Result::BodyResult(body)) = result.result else {
                panic!("expected body result");
            };
            let Some(http_response_body_result::Action::Transform(transform)) = body.action else {
                panic!("expected body transform");
            };
            let Some(http_response_body_transform::Replacement::Data(data)) = transform.replacement
            else {
                panic!("expected replacement data");
            };
            assert_eq!(data, expected);
        }
    }

    #[test]
    fn stream_tracks_end_of_stream_on_the_final_unit() {
        let mut state = ResponseSessionState::default();
        let preflight = state.preflight(response_preflight("/stream")).unwrap();
        let Some(http_response_event_result::Result::PreflightDecision(decision)) =
            preflight.result
        else {
            panic!("expected preflight decision");
        };
        let Some(http_response_preflight_decision::Action::Inspect(inspect)) = decision.action
        else {
            panic!("expected inspect decision");
        };
        assert_eq!(inspect.body_mode, HttpResponseBodyMode::StreamBytes as i32);
        state
            .body(HttpResponseBodyUnit {
                sequence: 1,
                payload: Some(http_response_body_unit::Payload::Data(b"hello".to_vec())),
                end_of_stream: true,
            })
            .unwrap();
        assert!(state.body_ended);
    }

    #[test]
    fn paths_outside_the_response_demo_are_skipped() {
        let mut state = ResponseSessionState::default();
        let result = state.preflight(response_preflight("/outside")).unwrap();
        let Some(http_response_event_result::Result::PreflightDecision(decision)) = result.result
        else {
            panic!("expected preflight decision");
        };
        let Some(http_response_preflight_decision::Action::Skip(_)) = decision.action else {
            panic!("expected skip decision");
        };
        assert_eq!(decision.reason_code, "path_not_selected");
    }

    #[tokio::test]
    async fn websocket_stream_redacts_text_messages() {
        let events = tokio_stream::iter([
            event(web_socket_session_event::Event::Preflight(
                WebSocketPreflight {
                    phase: PHASE as i32,
                    config: Some(config("redact", &["prototype-secret"], Some("[FILTERED]"))),
                    ..Default::default()
                },
            )),
            event(web_socket_session_event::Event::SessionStart(
                WebSocketSessionStart::default(),
            )),
            event(web_socket_session_event::Event::Message(WebSocketMessage {
                sequence: 1,
                payload: Some(web_socket_message::Payload::Text(
                    "contains prototype-secret".into(),
                )),
            })),
            event(web_socket_session_event::Event::SessionEnd(
                MiddlewareSessionEnd::default(),
            )),
        ]);
        let mut results = ContentGuard::websocket_stream(events);

        let preflight = results
            .next()
            .await
            .expect("preflight result")
            .expect("valid preflight result");
        assert!(matches!(
            preflight.result,
            Some(web_socket_session_event_result::Result::PreflightDecision(
                WebSocketPreflightDecision { action, .. }
            )) if action == WebSocketPreflightAction::Inspect as i32
        ));

        let message = results
            .next()
            .await
            .expect("message result")
            .expect("valid message result");
        let Some(web_socket_session_event_result::Result::MessageResult(message)) = message.result
        else {
            panic!("expected message result");
        };
        assert_eq!(message.decision, Decision::Allow as i32);
        assert_eq!(
            message.replacement,
            Some(web_socket_message_result::Replacement::Text(
                "contains [FILTERED]".into()
            ))
        );
        assert_eq!(message.findings[0].count, 1);
        assert!(results.next().await.is_none());
    }

    #[test]
    fn websocket_deny_preserves_safe_diagnostics() {
        let config = GuardConfig::parse(Some(&config("deny", &["prototype-secret"], None)))
            .expect("valid config");
        let result = evaluate_websocket_message(
            &config,
            &WebSocketMessage {
                sequence: 7,
                payload: Some(web_socket_message::Payload::Text(
                    "contains prototype-secret".into(),
                )),
            },
        )
        .expect("message result");

        assert_eq!(result.sequence, 7);
        assert_eq!(result.decision, Decision::Deny as i32);
        assert_eq!(result.reason_code, "content_match");
        assert!(!result.reason.contains("prototype-secret"));
        assert!(result.replacement.is_none());
    }

    #[test]
    fn redact_replaces_every_configured_match() {
        let config = GuardConfig::parse(Some(&config(
            "redact",
            &["prototype-secret", "internal-only"],
            Some("[FILTERED]"),
        )))
        .expect("valid config");
        let result = evaluate(
            &config,
            "prototype-secret then internal-only then prototype-secret",
        );

        assert_eq!(result.decision, Decision::Allow as i32);
        assert_eq!(
            String::from_utf8(result.body).unwrap(),
            "[FILTERED] then [FILTERED] then [FILTERED]"
        );
        assert!(result.has_body);
        assert_eq!(result.findings[0].count, 3);
    }

    #[test]
    fn redact_merges_partially_overlapping_terms() {
        let config =
            GuardConfig::parse(Some(&config("redact", &["aba", "bab"], Some("[FILTERED]"))))
                .expect("valid config");

        let result = evaluate(&config, "abab");

        assert_eq!(String::from_utf8(result.body).unwrap(), "[FILTERED]");
        assert_eq!(result.findings[0].count, 2);
        assert_eq!(result.metadata["matched_term_count"], "2");
    }

    #[test]
    fn redact_merges_self_overlapping_matches() {
        let config = GuardConfig::parse(Some(&config("redact", &["aba"], Some("[FILTERED]"))))
            .expect("valid config");

        let result = evaluate(&config, "ababa");

        assert_eq!(String::from_utf8(result.body).unwrap(), "[FILTERED]");
        assert_eq!(result.findings[0].count, 2);
        assert_eq!(result.metadata["matched_term_count"], "1");
    }

    #[test]
    fn redact_keeps_adjacent_matches_separate() {
        let config = GuardConfig::parse(Some(&config("redact", &["abc"], Some("[FILTERED]"))))
            .expect("valid config");

        let result = evaluate(&config, "abcabc");

        assert_eq!(
            String::from_utf8(result.body).unwrap(),
            "[FILTERED][FILTERED]"
        );
        assert_eq!(result.findings[0].count, 2);
    }

    #[test]
    fn deny_returns_a_generic_reason_without_echoing_the_term() {
        let config = GuardConfig::parse(Some(&config("deny", &["prototype-secret"], None)))
            .expect("valid config");
        let result = evaluate(&config, "contains prototype-secret");

        assert_eq!(result.decision, Decision::Deny as i32);
        assert!(!result.reason.contains("prototype-secret"));
        assert_eq!(result.reason_code, "content_match");
        assert!(!result.has_body);
    }

    #[test]
    fn no_match_allows_without_replacing_the_body() {
        let config =
            GuardConfig::parse(Some(&config("redact", &["blocked"], None))).expect("valid config");
        let result = evaluate(&config, "safe content");

        assert_eq!(result.decision, Decision::Allow as i32);
        assert!(!result.has_body);
        assert!(result.body.is_empty());
    }

    #[test]
    fn validation_rejects_missing_terms_and_deny_replacement() {
        let missing_terms = Struct {
            fields: BTreeMap::from([("mode".into(), string("redact"))]),
        };
        assert!(GuardConfig::parse(Some(&missing_terms)).is_err());
        assert!(
            GuardConfig::parse(Some(&config(
                "deny",
                &["prototype-secret"],
                Some("ignored")
            )))
            .is_err()
        );
    }

    #[test]
    fn validation_rejects_non_string_optional_fields() {
        for field in ["mode", "replacement"] {
            let mut config = config("redact", &["prototype-secret"], None);
            config.fields.insert(
                field.into(),
                Value {
                    kind: Some(Kind::BoolValue(true)),
                },
            );

            assert_eq!(
                GuardConfig::parse(Some(&config)),
                Err(format!("config.{field} must be a string"))
            );
        }
    }

    #[test]
    fn missing_optional_fields_use_defaults() {
        let mut config = config("redact", &["prototype-secret"], None);
        config.fields.remove("mode");

        let parsed = GuardConfig::parse(Some(&config)).expect("valid config");

        assert_eq!(parsed.mode, Mode::Redact);
        assert_eq!(parsed.replacement, DEFAULT_REPLACEMENT);
    }

    #[test]
    fn example_policy_is_valid() {
        let policy = openshell_policy::parse_sandbox_policy(include_str!("../policy.yaml"))
            .expect("example policy must parse");
        openshell_policy::validate_sandbox_policy(&policy).expect("example policy must be valid");
    }
}
