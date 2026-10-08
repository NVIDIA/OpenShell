// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP middleware protocol version 2: `HttpRequestPreCredentials.EvaluateHttp`
//! and `HttpResponsePreReturn.EvaluateHttp`. Both directions share one stage
//! lifecycle, and the guard selects BUFFERED so it always sees a complete body.
//!
//! A stage that cannot inspect a message ends with `FAILED_PRECONDITION`, which
//! OpenShell reports as `middleware_cannot_inspect`. Other gRPC errors are
//! reported as service errors. Both fail the exchange closed.

use openshell_core::middleware::HttpResultStream;
use openshell_core::proto::{
    HttpBodyMode, HttpBodyUnavailableReason, HttpBufferedMode, HttpBufferedResult, HttpContinue,
    HttpEvent, HttpInspect, HttpPreflight, HttpPreflightResult, HttpReject, HttpResult,
    HttpUnchanged, MiddlewareDiagnostics, http_buffered_result, http_event, http_inspect,
    http_preflight, http_preflight_result, http_result,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt};
use tonic::Status;

use crate::guard::{
    GuardConfig, GuardOutcome, MAX_PAYLOAD_BYTES, NotUtf8, complete_body_unavailable,
    inspect_http_body,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Direction {
    Request,
    Response,
}

pub(crate) fn stage_stream<S>(direction: Direction, mut events: S) -> HttpResultStream
where
    S: Stream<Item = Result<HttpEvent, Status>> + Send + Unpin + 'static,
{
    let (sender, receiver) = mpsc::channel(4);
    tokio::spawn(async move {
        let mut stage = Stage::new(direction);
        while let Some(event) = events.next().await {
            let result = match event {
                Ok(HttpEvent {
                    event: Some(http_event::Event::SessionEnd(_)),
                }) => break,
                Ok(event) => stage.handle(event),
                Err(error) => Err(error),
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
    Box::pin(ReceiverStream::new(receiver))
}

#[derive(Debug)]
enum State {
    Preflight,
    Begin(GuardConfig),
    BufferedBody(GuardConfig),
    Done,
}

#[derive(Debug)]
struct Stage {
    direction: Direction,
    state: State,
}

impl Stage {
    fn new(direction: Direction) -> Self {
        Self {
            direction,
            state: State::Preflight,
        }
    }

    /// Handle one event other than `session_end`. `Begin` produces no result.
    fn handle(&mut self, event: HttpEvent) -> Result<Option<HttpResult>, Status> {
        match (std::mem::replace(&mut self.state, State::Done), event.event) {
            (State::Preflight, Some(http_event::Event::Preflight(preflight))) => {
                let decision = match self.preflight(preflight)? {
                    Some((config, max_body_bytes)) => {
                        self.state = State::Begin(config);
                        http_preflight_result::Decision::Inspect(HttpInspect {
                            mode: Some(http_inspect::Mode::Buffered(HttpBufferedMode {
                                max_body_bytes,
                            })),
                        })
                    }
                    None => http_preflight_result::Decision::ContinueWithoutBody(HttpContinue {}),
                };
                Ok(Some(HttpResult {
                    result: Some(http_result::Result::PreflightResult(HttpPreflightResult {
                        decision: Some(decision),
                        ..Default::default()
                    })),
                }))
            }
            (State::Begin(config), Some(http_event::Event::Begin(_))) => {
                self.state = State::BufferedBody(config);
                Ok(None)
            }
            (State::BufferedBody(config), Some(http_event::Event::BufferedBody(body))) => {
                inspect_http_body(&config, &body.data)
                    .map(|outcome| Some(body_result(outcome)))
                    .map_err(|NotUtf8| Status::failed_precondition(NotUtf8::MESSAGE))
            }
            (_, None) => Err(Status::invalid_argument("HTTP event is required")),
            // Not FAILED_PRECONDITION, which OpenShell reads as "cannot
            // inspect".
            _ => Err(Status::invalid_argument(
                "invalid content guard HTTP lifecycle",
            )),
        }
    }

    /// Select BUFFERED with the offered limit, capped by the guard's own, or
    /// `None` to let a message without a body continue: it has nothing to
    /// guard. The guard fails every other message whose complete body
    /// OpenShell does not offer, such as an encoded, partial, or oversized
    /// one, because it never passes a body it could not inspect.
    fn preflight(&self, preflight: HttpPreflight) -> Result<Option<(GuardConfig, u64)>, Status> {
        let config = match (self.direction, &preflight.head) {
            (Direction::Request, Some(http_preflight::Head::Request(head))) => &head.config,
            (Direction::Response, Some(http_preflight::Head::Response(head))) => &head.config,
            _ => {
                return Err(Status::invalid_argument(
                    "preflight head does not match the RPC",
                ));
            }
        };
        let config = GuardConfig::from_evaluation(config.as_ref())?;
        if !preflight
            .permitted_body_modes
            .contains(&(HttpBodyMode::Buffered as i32))
        {
            return if buffered_unavailable_reason(&preflight)
                == Some(HttpBodyUnavailableReason::Bodyless)
            {
                Ok(None)
            } else {
                Err(complete_body_unavailable("BUFFERED"))
            };
        }
        let offered = preflight
            .limits
            .map_or(0, |limits| limits.max_buffered_body_bytes);
        if offered == 0 {
            return Err(Status::invalid_argument(
                "BUFFERED requires a positive max_buffered_body_bytes",
            ));
        }
        Ok(Some((config, offered.min(MAX_PAYLOAD_BYTES))))
    }
}

/// Why OpenShell does not offer BUFFERED, which the binding supports.
fn buffered_unavailable_reason(preflight: &HttpPreflight) -> Option<HttpBodyUnavailableReason> {
    preflight
        .unavailable_body_modes
        .iter()
        .find(|unavailable| unavailable.mode == HttpBodyMode::Buffered as i32)
        .and_then(|unavailable| HttpBodyUnavailableReason::try_from(unavailable.reason).ok())
}

fn body_result(outcome: GuardOutcome) -> HttpResult {
    let GuardOutcome {
        denied,
        replacement,
        reason,
        reason_code,
        findings,
        metadata,
    } = outcome;
    let diagnostics = Some(MiddlewareDiagnostics {
        reason,
        reason_code,
        findings,
        metadata,
    });
    let result = if denied {
        http_result::Result::Reject(HttpReject { diagnostics })
    } else {
        http_result::Result::BufferedResult(HttpBufferedResult {
            body: Some(replacement.map_or(
                http_buffered_result::Body::Unchanged(HttpUnchanged {}),
                |replacement| http_buffered_result::Body::Replacement(replacement.into_bytes()),
            )),
            diagnostics,
            ..Default::default()
        })
    };
    HttpResult {
        result: Some(result),
    }
}

#[cfg(test)]
mod tests {
    use openshell_core::proto::{
        HttpBegin, HttpBodyLimits, HttpBodyModeUnavailable, HttpBufferedBody, HttpInputChunk,
        HttpRequestPreflightHead, HttpResponsePreflightHead,
    };

    use super::*;
    use crate::guard::test_support::config;

    fn preflight(direction: Direction, mode: &str, max_buffered_body_bytes: u64) -> HttpEvent {
        let config = Some(config(mode, &["prototype-secret", "秘密"], None));
        let head = match direction {
            Direction::Request => http_preflight::Head::Request(HttpRequestPreflightHead {
                config,
                ..Default::default()
            }),
            Direction::Response => http_preflight::Head::Response(HttpResponsePreflightHead {
                config,
                ..Default::default()
            }),
        };
        HttpEvent {
            event: Some(http_event::Event::Preflight(HttpPreflight {
                head: Some(head),
                permitted_body_modes: vec![HttpBodyMode::Buffered as i32],
                limits: Some(HttpBodyLimits {
                    max_buffered_body_bytes,
                    ..Default::default()
                }),
                ..Default::default()
            })),
        }
    }

    fn begin() -> HttpEvent {
        HttpEvent {
            event: Some(http_event::Event::Begin(HttpBegin::default())),
        }
    }

    fn buffered_body(data: &[u8]) -> HttpEvent {
        HttpEvent {
            event: Some(http_event::Event::BufferedBody(HttpBufferedBody {
                data: data.to_vec(),
                visible_trailers: Vec::new(),
            })),
        }
    }

    fn selected_max_body_bytes(result: HttpResult) -> u64 {
        let Some(http_result::Result::PreflightResult(HttpPreflightResult {
            decision:
                Some(http_preflight_result::Decision::Inspect(HttpInspect {
                    mode: Some(http_inspect::Mode::Buffered(mode)),
                })),
            header_mutations,
            ..
        })) = result.result
        else {
            panic!("expected a BUFFERED preflight result");
        };
        assert!(header_mutations.is_empty());
        mode.max_body_bytes
    }

    #[test]
    fn preflight_selects_buffered_within_both_limits() {
        for (offered, selected) in [(1024, 1024), (MAX_PAYLOAD_BYTES * 4, MAX_PAYLOAD_BYTES)] {
            for direction in [Direction::Request, Direction::Response] {
                let result = Stage::new(direction)
                    .handle(preflight(direction, "redact", offered))
                    .unwrap()
                    .unwrap();
                assert_eq!(selected_max_body_bytes(result), selected);
            }
        }
    }

    #[test]
    fn stage_passes_redacts_and_denies_complete_bodies() {
        for direction in [Direction::Request, Direction::Response] {
            for (mode, input, expected) in [
                ("redact", "clean", None),
                (
                    "redact",
                    "a prototype-secret 秘密",
                    Some("a [REDACTED] [REDACTED]"),
                ),
                ("deny", "prototype-secret", None),
            ] {
                let mut stage = Stage::new(direction);
                stage
                    .handle(preflight(direction, mode, MAX_PAYLOAD_BYTES))
                    .unwrap();
                assert!(stage.handle(begin()).unwrap().is_none());
                let result = stage
                    .handle(buffered_body(input.as_bytes()))
                    .unwrap()
                    .unwrap();
                assert!(stage.handle(buffered_body(input.as_bytes())).is_err());

                match (mode, expected, result.result) {
                    ("deny", _, Some(http_result::Result::Reject(reject))) => {
                        let diagnostics = reject.diagnostics.unwrap();
                        assert_eq!(diagnostics.reason_code, "content_match");
                        assert!(!diagnostics.reason.contains("prototype-secret"));
                    }
                    (_, Some(expected), Some(http_result::Result::BufferedResult(result))) => {
                        assert_eq!(
                            result.body,
                            Some(http_buffered_result::Body::Replacement(
                                expected.as_bytes().to_vec()
                            ))
                        );
                        assert_eq!(result.diagnostics.unwrap().findings[0].count, 2);
                    }
                    (_, None, Some(http_result::Result::BufferedResult(result))) => {
                        assert_eq!(
                            result.body,
                            Some(http_buffered_result::Body::Unchanged(HttpUnchanged {}))
                        );
                        assert!(result.header_mutations.is_empty());
                        assert!(result.trailer_mutations.is_empty());
                    }
                    (_, _, result) => panic!("unexpected {mode} result: {result:?}"),
                }
            }
        }
    }

    /// A response preflight that offers no body, with `reason` for BUFFERED
    /// when set.
    fn without_buffered(reason: Option<HttpBodyUnavailableReason>) -> HttpEvent {
        let mut event = preflight(Direction::Response, "redact", MAX_PAYLOAD_BYTES);
        let Some(http_event::Event::Preflight(preflight)) = event.event.as_mut() else {
            unreachable!()
        };
        preflight.permitted_body_modes.clear();
        preflight.unavailable_body_modes = reason
            .into_iter()
            .map(|reason| HttpBodyModeUnavailable {
                mode: HttpBodyMode::Buffered as i32,
                reason: reason as i32,
            })
            .collect();
        event
    }

    #[test]
    fn preflight_continues_without_a_body_when_there_is_none() {
        let mut stage = Stage::new(Direction::Response);

        let result = stage
            .handle(without_buffered(Some(HttpBodyUnavailableReason::Bodyless)))
            .unwrap()
            .unwrap();

        assert_eq!(
            result.result,
            Some(http_result::Result::PreflightResult(HttpPreflightResult {
                decision: Some(http_preflight_result::Decision::ContinueWithoutBody(
                    HttpContinue {}
                )),
                ..Default::default()
            }))
        );
        assert_eq!(
            stage.handle(begin()).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn preflight_cannot_inspect_a_body_it_is_not_offered() {
        for reason in [
            None,
            Some(HttpBodyUnavailableReason::Partial),
            Some(HttpBodyUnavailableReason::NoTransform),
            Some(HttpBodyUnavailableReason::Encoded),
            Some(HttpBodyUnavailableReason::OverLimit),
            Some(HttpBodyUnavailableReason::OpenEnded),
        ] {
            let error = Stage::new(Direction::Response)
                .handle(without_buffered(reason))
                .unwrap_err();

            assert_eq!(error.code(), tonic::Code::FailedPrecondition, "{reason:?}");
        }

        let mut stream_only = without_buffered(Some(HttpBodyUnavailableReason::OverLimit));
        let Some(http_event::Event::Preflight(preflight)) = stream_only.event.as_mut() else {
            unreachable!()
        };
        preflight.permitted_body_modes = vec![HttpBodyMode::Stream as i32];
        let error = Stage::new(Direction::Response)
            .handle(stream_only)
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    }

    #[test]
    fn bodyless_preflight_still_validates_the_config() {
        let mut event = without_buffered(Some(HttpBodyUnavailableReason::Bodyless));
        let Some(http_event::Event::Preflight(HttpPreflight {
            head: Some(http_preflight::Head::Response(head)),
            ..
        })) = event.event.as_mut()
        else {
            unreachable!()
        };
        head.config = Some(config("block", &["prototype-secret"], None));

        let error = Stage::new(Direction::Response).handle(event).unwrap_err();

        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn preflight_rejects_invalid_heads_configs_and_limits() {
        let mismatched = preflight(Direction::Response, "redact", MAX_PAYLOAD_BYTES);
        let missing_limit = preflight(Direction::Request, "redact", 0);
        let mut invalid_config = preflight(Direction::Request, "redact", MAX_PAYLOAD_BYTES);
        let Some(http_event::Event::Preflight(HttpPreflight {
            head: Some(http_preflight::Head::Request(head)),
            ..
        })) = invalid_config.event.as_mut()
        else {
            unreachable!()
        };
        head.config = None;

        for event in [mismatched, missing_limit, invalid_config] {
            let error = Stage::new(Direction::Request).handle(event).unwrap_err();
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
        }
    }

    #[test]
    fn stage_enforces_lifecycle_and_utf8() {
        let mut stage = Stage::new(Direction::Request);
        assert!(stage.handle(buffered_body(b"before preflight")).is_err());

        let mut stage = Stage::new(Direction::Request);
        stage
            .handle(preflight(Direction::Request, "redact", MAX_PAYLOAD_BYTES))
            .unwrap();
        assert!(stage.handle(buffered_body(b"before begin")).is_err());

        let mut stage = Stage::new(Direction::Request);
        stage
            .handle(preflight(Direction::Request, "redact", MAX_PAYLOAD_BYTES))
            .unwrap();
        stage.handle(begin()).unwrap();
        let chunk = HttpEvent {
            event: Some(http_event::Event::InputChunk(HttpInputChunk {
                data: b"stream".to_vec(),
            })),
        };
        assert_eq!(
            stage.handle(chunk).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );

        // The guard matches text only, so it cannot inspect other bodies.
        let mut stage = Stage::new(Direction::Request);
        stage
            .handle(preflight(Direction::Request, "redact", MAX_PAYLOAD_BYTES))
            .unwrap();
        stage.handle(begin()).unwrap();
        assert_eq!(
            stage.handle(buffered_body(&[0xff])).unwrap_err().code(),
            tonic::Code::FailedPrecondition
        );
    }
}
