// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResponseMode {
    HeadersOnly,
    WholeBody,
    Stream,
    StreamClose,
    Block,
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
        let path = preflight
            .target
            .as_ref()
            .map(|target| target.path.as_str())
            .unwrap_or_default();
        let Some(selected) = response_mode_for_path(path) else {
            return Ok(HttpResponseEventResult {
                result: Some(http_response_event_result::Result::PreflightResult(
                    HttpResponsePreflightResult {
                        action: Some(http_response_preflight_result::Action::Skip(
                            HttpResponsePreflightSkip {},
                        )),
                        reason_code: "path_not_selected".into(),
                        ..Default::default()
                    },
                )),
            });
        };
        self.selected = Some(selected);
        self.next_sequence = 1;
        let body_mode = match selected {
            ResponseMode::HeadersOnly => HttpResponseBodyMode::HeadersOnly,
            ResponseMode::WholeBody | ResponseMode::Block => HttpResponseBodyMode::WholeBodyBytes,
            ResponseMode::Stream | ResponseMode::StreamClose => HttpResponseBodyMode::StreamBytes,
        };
        if !preflight.permitted_body_modes.contains(&(body_mode as i32)) {
            return Err(Status::failed_precondition(
                "selected demo body mode is unavailable",
            ));
        }
        Ok(HttpResponseEventResult {
            result: Some(http_response_event_result::Result::PreflightResult(
                HttpResponsePreflightResult {
                    action: Some(http_response_preflight_result::Action::Inspect(
                        HttpResponsePreflightInspect {
                            body_mode: body_mode as i32,
                            header_mutations: vec![write_header(
                                "x-example-response-mode",
                                match selected {
                                    ResponseMode::HeadersOnly => "headers-only",
                                    ResponseMode::WholeBody => "whole-body",
                                    ResponseMode::Stream => "stream",
                                    ResponseMode::StreamClose => "stream-close",
                                    ResponseMode::Block => "block",
                                },
                            )],
                        },
                    )),
                    ..Default::default()
                },
            )),
        })
    }

    fn body(
        &mut self,
        body: openshell_core::proto::HttpResponseBodyUnit,
    ) -> Result<HttpResponseEventResult, Status> {
        let selected = self
            .selected
            .ok_or_else(|| Status::failed_precondition("body arrived before preflight"))?;
        if selected == ResponseMode::HeadersOnly || self.body_ended {
            return Err(Status::failed_precondition(
                "body event is invalid for the response session state",
            ));
        }
        if body.sequence != self.next_sequence {
            return Err(Status::invalid_argument(
                "unexpected response body sequence",
            ));
        }
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.body_ended = body.end_of_stream;
        let Some(http_response_body_unit::Payload::Data(data)) = body.payload else {
            return Err(Status::invalid_argument("body data is required"));
        };
        let (action, reason_code) = match selected {
            ResponseMode::WholeBody => (
                http_response_body_result::Action::Transform(HttpResponseBodyTransform {
                    replacement: Some(http_response_body_transform::Replacement::Data(
                        [b"[whole] ".as_slice(), &data].concat(),
                    )),
                }),
                String::new(),
            ),
            ResponseMode::Stream | ResponseMode::StreamClose => (
                http_response_body_result::Action::Transform(HttpResponseBodyTransform {
                    replacement: Some(http_response_body_transform::Replacement::Data(
                        data.to_ascii_uppercase(),
                    )),
                }),
                String::new(),
            ),
            ResponseMode::Block => (
                http_response_body_result::Action::BlockDelivery(HttpResponseBlockDelivery {}),
                "content_match".into(),
            ),
            ResponseMode::HeadersOnly => unreachable!(),
        };
        Ok(HttpResponseEventResult {
            result: Some(http_response_event_result::Result::BodyResult(
                HttpResponseBodyResult {
                    sequence: body.sequence,
                    action: Some(action),
                    reason_code,
                    ..Default::default()
                },
            )),
        })
    }

    fn trailers(&self) -> Result<HttpResponseEventResult, Status> {
        if !self.body_ended {
            return Err(Status::failed_precondition(
                "trailers arrived before the final body result",
            ));
        }
        let trailer_mutations = if self.selected == Some(ResponseMode::Stream) {
            vec![write_header("x-example-body-bytes", "11")]
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

fn response_mode_for_path(path: &str) -> Option<ResponseMode> {
    match path {
        "/headers-only" => Some(ResponseMode::HeadersOnly),
        "/whole-body" => Some(ResponseMode::WholeBody),
        "/stream" => Some(ResponseMode::Stream),
        "/stream-close" => Some(ResponseMode::StreamClose),
        "/block" => Some(ResponseMode::Block),
        _ => None,
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
impl HttpResponsePreReturn for ProtocolDemo {
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
                let result = match event {
                    Ok(event) => match event.event {
                        Some(http_response_event::Event::Preflight(preflight)) => {
                            state.preflight(preflight)
                        }
                        Some(http_response_event::Event::Body(body)) => state.body(body),
                        Some(http_response_event::Event::Trailers(_)) => state.trailers(),
                        Some(http_response_event::Event::SessionEnd(_)) => break,
                        None => Err(Status::invalid_argument("response event is required")),
                    },
                    Err(error) => Err(error),
                };
                match result {
                    Ok(result) => {
                        if sender.send(Ok(result)).await.is_err() {
                            break;
                        }
                    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{HttpRequestTarget, HttpResponseBodyUnit, HttpResponsePreflight};
    fn response_preflight(path: &str) -> HttpResponsePreflight {
        HttpResponsePreflight {
            target: Some(HttpRequestTarget {
                path: path.into(),
                ..Default::default()
            }),
            permitted_body_modes: vec![
                HttpResponseBodyMode::HeadersOnly as i32,
                HttpResponseBodyMode::WholeBodyBytes as i32,
                HttpResponseBodyMode::StreamBytes as i32,
            ],
            ..Default::default()
        }
    }

    #[test]
    fn response_paths_select_all_modes() {
        for (path, expected) in [
            ("/headers-only", HttpResponseBodyMode::HeadersOnly),
            ("/whole-body", HttpResponseBodyMode::WholeBodyBytes),
            ("/stream", HttpResponseBodyMode::StreamBytes),
            ("/stream-close", HttpResponseBodyMode::StreamBytes),
            ("/block", HttpResponseBodyMode::WholeBodyBytes),
        ] {
            let mut state = ResponseSessionState::default();
            let result = state.preflight(response_preflight(path)).unwrap();
            let Some(http_response_event_result::Result::PreflightResult(result)) = result.result
            else {
                panic!("expected preflight result");
            };
            let Some(http_response_preflight_result::Action::Inspect(inspect)) = result.action
            else {
                panic!("expected inspect action");
            };
            assert_eq!(inspect.body_mode, expected as i32);
        }
    }

    #[test]
    fn response_whole_body_transforms_and_block_is_typed() {
        let mut whole = ResponseSessionState::default();
        whole.preflight(response_preflight("/whole-body")).unwrap();
        let result = whole
            .body(HttpResponseBodyUnit {
                sequence: 1,
                payload: Some(http_response_body_unit::Payload::Data(b"body".to_vec())),
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
            panic!("expected data replacement");
        };
        assert_eq!(data, b"[whole] body");

        let mut block = ResponseSessionState::default();
        block.preflight(response_preflight("/block")).unwrap();
        let result = block
            .body(HttpResponseBodyUnit {
                sequence: 1,
                payload: Some(http_response_body_unit::Payload::Data(
                    b"prototype-secret".to_vec(),
                )),
                end_of_stream: true,
            })
            .unwrap();
        let Some(http_response_event_result::Result::BodyResult(body)) = result.result else {
            panic!("expected body result");
        };
        assert!(matches!(
            body.action,
            Some(http_response_body_result::Action::BlockDelivery(_))
        ));
        assert_eq!(body.reason_code, "content_match");
    }

    #[test]
    fn response_stream_returns_the_required_trailer_exchange() {
        let mut state = ResponseSessionState::default();
        state.preflight(response_preflight("/stream")).unwrap();
        state
            .body(HttpResponseBodyUnit {
                sequence: 1,
                payload: Some(http_response_body_unit::Payload::Data(b"body".to_vec())),
                end_of_stream: true,
            })
            .unwrap();
        let result = state.trailers().unwrap();
        let Some(http_response_event_result::Result::TrailersResult(trailers)) = result.result
        else {
            panic!("expected trailers result");
        };
        assert_eq!(trailers.trailer_mutations.len(), 1);
    }

    #[test]
    fn response_paths_outside_the_example_are_skipped() {
        let mut state = ResponseSessionState::default();
        let result = state.preflight(response_preflight("/outside")).unwrap();
        let Some(http_response_event_result::Result::PreflightResult(result)) = result.result
        else {
            panic!("expected preflight result");
        };
        assert!(matches!(
            result.action,
            Some(http_response_preflight_result::Action::Skip(_))
        ));
        assert_eq!(result.reason_code, "path_not_selected");
    }
}
