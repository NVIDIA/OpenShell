// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;

use clap::Parser;
use openshell_core::middleware::{HttpResponseResultStream, WebSocketResponseStream};
use openshell_core::proto::middleware::v1::http_response_pre_return_server::{
    HttpResponsePreReturn, HttpResponsePreReturnServer,
};
use openshell_core::proto::middleware::v1::supervisor_middleware_server::{
    SupervisorMiddleware, SupervisorMiddlewareServer,
};
use openshell_core::proto::{
    Decision, ExistingHeaderAction, HeaderMutation, HttpRequestEvaluation, HttpRequestResult,
    HttpResponseBodyMode, HttpResponseBodyResult, HttpResponseBodyTransform, HttpResponseEvent,
    HttpResponseEventResult, HttpResponsePreflightDecision, HttpResponsePreflightInspect,
    HttpResponsePreflightSkip, HttpResponseTrailersResult, MiddlewareBinding, MiddlewareManifest,
    SupervisorMiddlewareOperation, SupervisorMiddlewarePhase, ValidateConfigRequest,
    ValidateConfigResponse, WebSocketSessionEvent, WriteHeader, header_mutation,
    http_response_body_result, http_response_body_transform, http_response_body_unit,
    http_response_event, http_response_event_result, http_response_preflight_decision,
};
use tokio::sync::mpsc;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

const MANIFEST_NAME: &str = "example/response-transform-service";
const MAX_PAYLOAD_BYTES: u64 = 256 * 1024;

#[derive(Debug, Parser)]
#[command(about = "Run the example OpenShell HTTP response middleware")]
struct Cli {
    /// Address on which to serve plaintext gRPC.
    #[arg(long, default_value = "127.0.0.1:50052")]
    bind: SocketAddr,
}

#[derive(Clone, Copy, Debug, Default)]
struct ResponseTransform;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectedMode {
    HeadersOnly,
    WholeBody,
    Stream,
}

#[derive(Debug, Default)]
struct SessionState {
    selected: Option<SelectedMode>,
    next_sequence: u64,
    input_bytes: u64,
}

impl SessionState {
    fn preflight(
        &mut self,
        preflight: openshell_core::proto::HttpResponsePreflight,
    ) -> Result<HttpResponseEventResult, Status> {
        if self.selected.is_some() {
            return Err(Status::failed_precondition("duplicate response preflight"));
        }
        let path = preflight
            .target
            .as_ref()
            .map(|target| target.path.as_str())
            .unwrap_or_default();
        let Some(selected) = mode_for_path(path) else {
            return Ok(preflight_skip());
        };
        self.selected = Some(selected);
        self.next_sequence = 1;
        Ok(preflight_inspect(selected))
    }

    fn body(
        &mut self,
        body: openshell_core::proto::HttpResponseBodyUnit,
    ) -> Result<HttpResponseEventResult, Status> {
        let selected = self
            .selected
            .ok_or_else(|| Status::failed_precondition("body arrived before preflight"))?;
        if selected == SelectedMode::HeadersOnly {
            return Err(Status::failed_precondition(
                "headers-only sessions do not receive body events",
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
        self.input_bytes = self.input_bytes.saturating_add(data.len() as u64);
        let replacement = match selected {
            SelectedMode::WholeBody => [b"[whole] ".as_slice(), &data].concat(),
            SelectedMode::Stream => data.to_ascii_uppercase(),
            SelectedMode::HeadersOnly => unreachable!(),
        };
        Ok(HttpResponseEventResult {
            result: Some(http_response_event_result::Result::BodyResult(
                HttpResponseBodyResult {
                    sequence: body.sequence,
                    decision: Some(http_response_body_result::Decision::Transform(
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

    fn body_end(&self, final_sequence: u64) -> Result<(), Status> {
        let expected = self.next_sequence.saturating_sub(1);
        if final_sequence != expected {
            return Err(Status::invalid_argument(format!(
                "expected final body sequence {expected}, received {final_sequence}"
            )));
        }
        Ok(())
    }

    fn trailers(&self) -> Result<HttpResponseEventResult, Status> {
        let selected = self
            .selected
            .ok_or_else(|| Status::failed_precondition("trailers arrived before preflight"))?;
        if selected == SelectedMode::HeadersOnly {
            return Err(Status::failed_precondition(
                "headers-only sessions do not receive trailers",
            ));
        }
        let trailer_mutations = if selected == SelectedMode::Stream {
            vec![write_header(
                "x-example-body-bytes",
                &self.input_bytes.to_string(),
            )]
        } else {
            Vec::new()
        };
        Ok(HttpResponseEventResult {
            result: Some(http_response_event_result::Result::TrailersResult(
                HttpResponseTrailersResult {
                    trailer_mutations,
                    ..Default::default()
                },
            )),
        })
    }
}

fn mode_for_path(path: &str) -> Option<SelectedMode> {
    match path {
        "/headers-only" => Some(SelectedMode::HeadersOnly),
        "/whole-body" => Some(SelectedMode::WholeBody),
        "/stream" => Some(SelectedMode::Stream),
        _ => None,
    }
}

fn preflight_skip() -> HttpResponseEventResult {
    HttpResponseEventResult {
        result: Some(http_response_event_result::Result::PreflightDecision(
            HttpResponsePreflightDecision {
                decision: Some(http_response_preflight_decision::Decision::Skip(
                    HttpResponsePreflightSkip {
                        reason: "path is outside the response-transform example".into(),
                        reason_code: "path_not_selected".into(),
                        ..Default::default()
                    },
                )),
            },
        )),
    }
}

fn preflight_inspect(selected: SelectedMode) -> HttpResponseEventResult {
    let (body_mode, declared_trailer_names) = match selected {
        SelectedMode::HeadersOnly => (HttpResponseBodyMode::HeadersOnly, Vec::new()),
        SelectedMode::WholeBody => (HttpResponseBodyMode::WholeBodyBytes, Vec::new()),
        SelectedMode::Stream => (
            HttpResponseBodyMode::StreamBytes,
            vec!["x-example-body-bytes".into()],
        ),
    };
    let mode_name = match selected {
        SelectedMode::HeadersOnly => "headers-only",
        SelectedMode::WholeBody => "whole-body",
        SelectedMode::Stream => "stream",
    };
    HttpResponseEventResult {
        result: Some(http_response_event_result::Result::PreflightDecision(
            HttpResponsePreflightDecision {
                decision: Some(http_response_preflight_decision::Decision::Inspect(
                    HttpResponsePreflightInspect {
                        body_mode: body_mode as i32,
                        header_mutations: vec![write_header("x-example-response-mode", mode_name)],
                        declared_trailer_names,
                        ..Default::default()
                    },
                )),
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
impl SupervisorMiddleware for ResponseTransform {
    type EvaluateWebSocketSessionStream = WebSocketResponseStream;

    async fn describe(
        &self,
        _request: Request<()>,
    ) -> Result<Response<MiddlewareManifest>, Status> {
        Ok(Response::new(MiddlewareManifest {
            name: MANIFEST_NAME.into(),
            service_version: env!("CARGO_PKG_VERSION").into(),
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpResponse as i32,
                phase: SupervisorMiddlewarePhase::PreReturn as i32,
                max_payload_bytes: MAX_PAYLOAD_BYTES,
                timeout: String::new(),
            }],
            expected_audience: String::new(),
        }))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        let valid = request
            .get_ref()
            .config
            .as_ref()
            .is_none_or(|config| config.fields.is_empty());
        Ok(Response::new(ValidateConfigResponse {
            valid,
            reason: if valid {
                String::new()
            } else {
                "this example does not accept configuration fields".into()
            },
        }))
    }

    async fn evaluate_http_request(
        &self,
        _request: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        Ok(Response::new(HttpRequestResult {
            decision: Decision::Allow as i32,
            ..Default::default()
        }))
    }

    async fn evaluate_web_socket_session(
        &self,
        _request: Request<tonic::Streaming<WebSocketSessionEvent>>,
    ) -> Result<Response<Self::EvaluateWebSocketSessionStream>, Status> {
        Err(Status::unimplemented("HTTP response-only service"))
    }
}

#[tonic::async_trait]
impl HttpResponsePreReturn for ResponseTransform {
    type EvaluateStream = HttpResponseResultStream;

    async fn evaluate(
        &self,
        request: Request<tonic::Streaming<HttpResponseEvent>>,
    ) -> Result<Response<Self::EvaluateStream>, Status> {
        let mut events = request.into_inner();
        let (sender, receiver) = mpsc::channel(4);
        tokio::spawn(async move {
            let mut state = SessionState::default();
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
                    Some(http_response_event::Event::BodyEnd(body_end)) => {
                        state.body_end(body_end.final_sequence).map(|()| None)
                    }
                    Some(http_response_event::Event::Trailers(_)) => state.trailers().map(Some),
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    println!("response-transform middleware listening on {}", cli.bind);
    Server::builder()
        .add_service(SupervisorMiddlewareServer::new(ResponseTransform))
        .add_service(HttpResponsePreReturnServer::new(ResponseTransform))
        .serve(cli.bind)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{HttpRequestTarget, HttpResponseBodyUnit, HttpResponsePreflight};

    fn preflight(path: &str) -> openshell_core::proto::HttpResponsePreflight {
        HttpResponsePreflight {
            target: Some(HttpRequestTarget {
                path: path.into(),
                ..Default::default()
            }),
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
            let mut state = SessionState::default();
            let result = state.preflight(preflight(path)).unwrap();
            let Some(http_response_event_result::Result::PreflightDecision(decision)) =
                result.result
            else {
                panic!("expected preflight decision");
            };
            let Some(http_response_preflight_decision::Decision::Inspect(inspect)) =
                decision.decision
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
            let mut state = SessionState::default();
            state.preflight(preflight(path)).unwrap();
            let result = state
                .body(HttpResponseBodyUnit {
                    sequence: 1,
                    payload: Some(http_response_body_unit::Payload::Data(b"hello".to_vec())),
                })
                .unwrap();
            let Some(http_response_event_result::Result::BodyResult(body)) = result.result else {
                panic!("expected body result");
            };
            let Some(http_response_body_result::Decision::Transform(transform)) = body.decision
            else {
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
    fn stream_declares_and_writes_byte_count_trailer() {
        let mut state = SessionState::default();
        let preflight = state.preflight(preflight("/stream")).unwrap();
        let Some(http_response_event_result::Result::PreflightDecision(decision)) =
            preflight.result
        else {
            panic!("expected preflight decision");
        };
        let Some(http_response_preflight_decision::Decision::Inspect(inspect)) = decision.decision
        else {
            panic!("expected inspect decision");
        };
        assert_eq!(inspect.declared_trailer_names, ["x-example-body-bytes"]);
        state
            .body(HttpResponseBodyUnit {
                sequence: 1,
                payload: Some(http_response_body_unit::Payload::Data(b"hello".to_vec())),
            })
            .unwrap();
        state.body_end(1).unwrap();
        let trailers = state.trailers().unwrap();
        let Some(http_response_event_result::Result::TrailersResult(trailers)) = trailers.result
        else {
            panic!("expected trailer result");
        };
        assert_eq!(trailers.trailer_mutations.len(), 1);
    }

    #[test]
    fn paths_outside_the_demo_are_skipped() {
        let mut state = SessionState::default();
        let result = state.preflight(preflight("/outside")).unwrap();
        let Some(http_response_event_result::Result::PreflightDecision(decision)) = result.result
        else {
            panic!("expected preflight decision");
        };
        let Some(http_response_preflight_decision::Decision::Skip(skip)) = decision.decision else {
            panic!("expected skip decision");
        };
        assert_eq!(skip.reason_code, "path_not_selected");
    }

    #[test]
    fn example_policy_is_valid() {
        let policy = openshell_policy::parse_sandbox_policy(include_str!("../policy.yaml"))
            .expect("example policy must parse");
        openshell_policy::validate_sandbox_policy(&policy).expect("example policy must be valid");
    }
}
