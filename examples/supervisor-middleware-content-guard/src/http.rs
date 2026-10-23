// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP session hooks (`HttpSessionMiddleware.EvaluateRequest` and
//! `HttpSessionMiddleware.EvaluateResponse`) for requests and responses.
//!
//! The guard selects its configured body mode, BUFFERED by default, and falls
//! back to the other mode when OpenShell offers only that one. A message
//! without a body continues. A message the guard cannot inspect, such as an
//! encoded body, is denied with reason code `cannot_inspect`.
//!
//! OpenShell leaves integrity headers such as `ETag` and `Content-Digest`
//! alone. When the guard may change a body, it removes them itself.

use std::pin::Pin;

use openshell_core::middleware::{HttpRequestSessionResultStream, HttpResponseSessionResultStream};
use openshell_core::proto::{
    HeaderMutation, HttpBodyLimits, HttpBodyMode, HttpBodyModeUnavailable,
    HttpBodyUnavailableReason, HttpBufferedBody, HttpBufferedMode, HttpBufferedResult,
    HttpContinue, HttpDenial, HttpFinish, HttpInputChunk, HttpInspect, HttpOutputChunk,
    HttpOutputStart, HttpPreflightResult, HttpRequestPreflightHead, HttpRequestSessionEvent,
    HttpRequestSessionResult, HttpResponseSessionEvent, HttpResponseSessionResult, HttpStreamMode,
    HttpUnchanged, MiddlewareDiagnostics, RemoveHeader, header_mutation, http_buffered_result,
    http_inspect, http_preflight_result, http_request_session_event, http_request_session_result,
    http_response_session_event, http_response_session_result,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt};
use tonic::Status;

use crate::guard::{
    BodyMode, GuardConfig, GuardOutcome, MAX_PAYLOAD_BYTES, Mode, StreamScanner, inspect, outcome,
};

/// Run one `HttpSessionMiddleware.EvaluateRequest` exchange.
pub(crate) fn request_stream<S>(events: S) -> HttpRequestSessionResultStream
where
    S: Stream<Item = Result<HttpRequestSessionEvent, Status>> + Send + Unpin + 'static,
{
    stage_stream(events, request_event, |reply| HttpRequestSessionResult {
        result: Some(reply.into()),
    })
}

/// Run one `HttpSessionMiddleware.EvaluateResponse` exchange.
pub(crate) fn response_stream<S>(events: S) -> HttpResponseSessionResultStream
where
    S: Stream<Item = Result<HttpResponseSessionEvent, Status>> + Send + Unpin + 'static,
{
    stage_stream(events, response_event, |reply| HttpResponseSessionResult {
        result: Some(reply.into()),
    })
}

/// Run one exchange of either RPC. The RPCs carry the same body events and
/// results, and differ only in their preflight.
fn stage_stream<S, E, R>(
    mut events: S,
    event: fn(E) -> Option<Event>,
    result: fn(Reply) -> R,
) -> Pin<Box<dyn Stream<Item = Result<R, Status>> + Send>>
where
    S: Stream<Item = Result<E, Status>> + Send + Unpin + 'static,
    E: Send + 'static,
    R: Send + 'static,
{
    let (sender, receiver) = mpsc::channel(4);
    tokio::spawn(async move {
        let mut stage = Stage::Preflight;
        while let Some(next) = events.next().await {
            let replies = match next.map(event) {
                Ok(Some(Event::SessionEnd)) => break,
                Ok(Some(event)) => stage.handle(event),
                Ok(None) => Err(Status::invalid_argument("HTTP event is required")),
                Err(error) => Err(error),
            };
            match replies {
                Ok(replies) => {
                    for reply in replies {
                        if sender.send(Ok(result(reply))).await.is_err() {
                            return;
                        }
                    }
                }
                Err(error) => {
                    let _ = sender.send(Err(error)).await;
                    return;
                }
            }
        }
    });
    Box::pin(ReceiverStream::new(receiver))
}

/// One event of either RPC.
#[derive(Debug)]
enum Event {
    Preflight(Box<Preflight>),
    Begin,
    BufferedBody(HttpBufferedBody),
    InputChunk(HttpInputChunk),
    InputEnd,
    SessionEnd,
}

/// What the guard reads from a preflight of either RPC.
#[derive(Debug, Default)]
struct Preflight {
    subject: Subject,
    config: Option<prost_types::Struct>,
    permitted_body_modes: Vec<i32>,
    unavailable_body_modes: Vec<HttpBodyModeUnavailable>,
    limits: Option<HttpBodyLimits>,
    declared_body_bytes: Option<u64>,
}

#[derive(Debug, Default)]
enum Subject {
    #[default]
    Missing,
    Request(HttpRequestPreflightHead),
    Response,
}

fn request_event(event: HttpRequestSessionEvent) -> Option<Event> {
    use http_request_session_event::Event as Wire;
    Some(match event.event? {
        Wire::Preflight(preflight) => Event::Preflight(Box::new(Preflight {
            subject: preflight.request.map_or(Subject::Missing, Subject::Request),
            config: preflight.config,
            permitted_body_modes: preflight.permitted_body_modes,
            unavailable_body_modes: preflight.unavailable_body_modes,
            limits: preflight.limits,
            declared_body_bytes: preflight.declared_body_bytes,
        })),
        Wire::Begin(_) => Event::Begin,
        Wire::BufferedBody(body) => Event::BufferedBody(body),
        Wire::InputChunk(chunk) => Event::InputChunk(chunk),
        Wire::InputEnd(_) => Event::InputEnd,
        Wire::SessionEnd(_) => Event::SessionEnd,
    })
}

fn response_event(event: HttpResponseSessionEvent) -> Option<Event> {
    use http_response_session_event::Event as Wire;
    Some(match event.event? {
        Wire::Preflight(preflight) => Event::Preflight(Box::new(Preflight {
            subject: if preflight.response.is_some() {
                Subject::Response
            } else {
                Subject::Missing
            },
            config: preflight.config,
            permitted_body_modes: preflight.permitted_body_modes,
            unavailable_body_modes: preflight.unavailable_body_modes,
            limits: preflight.limits,
            declared_body_bytes: preflight.declared_body_bytes,
        })),
        Wire::Begin(_) => Event::Begin,
        Wire::BufferedBody(body) => Event::BufferedBody(body),
        Wire::InputChunk(chunk) => Event::InputChunk(chunk),
        Wire::InputEnd(_) => Event::InputEnd,
        Wire::SessionEnd(_) => Event::SessionEnd,
    })
}

/// One result of either RPC.
#[derive(Debug)]
enum Reply {
    Preflight(HttpPreflightResult),
    Buffered(HttpBufferedResult),
    OutputStart(HttpOutputStart),
    OutputChunk(HttpOutputChunk),
    Finish(HttpFinish),
    Deny(HttpDenial),
}

impl From<Reply> for http_request_session_result::Result {
    fn from(reply: Reply) -> Self {
        match reply {
            Reply::Preflight(result) => Self::PreflightResult(result),
            Reply::Buffered(result) => Self::BufferedResult(result),
            Reply::OutputStart(start) => Self::OutputStart(start),
            Reply::OutputChunk(chunk) => Self::OutputChunk(chunk),
            Reply::Finish(finish) => Self::Finish(finish),
            Reply::Deny(deny) => Self::Deny(deny),
        }
    }
}

impl From<Reply> for http_response_session_result::Result {
    fn from(reply: Reply) -> Self {
        match reply {
            Reply::Preflight(result) => Self::PreflightResult(result),
            Reply::Buffered(result) => Self::BufferedResult(result),
            Reply::OutputStart(start) => Self::OutputStart(start),
            Reply::OutputChunk(chunk) => Self::OutputChunk(chunk),
            Reply::Finish(finish) => Self::Finish(finish),
            Reply::Deny(deny) => Self::BlockDelivery(deny),
        }
    }
}

enum Stage {
    Preflight,
    Begin(GuardConfig, Selected),
    Buffered(GuardConfig),
    /// STREAM, with the largest output chunk OpenShell accepts.
    Stream(GuardConfig, StreamScanner, usize),
    Done,
}

impl Stage {
    /// Handle one event other than `session_end` and return its replies.
    fn handle(&mut self, event: Event) -> Result<Vec<Reply>, Status> {
        match (std::mem::replace(self, Self::Done), event) {
            (Self::Preflight, Event::Preflight(preflight)) => {
                match preflight_decision(*preflight)? {
                    Decision::Continue => Ok(vec![Reply::Preflight(HttpPreflightResult {
                        decision: Some(http_preflight_result::Decision::ContinueWithoutBody(
                            HttpContinue {},
                        )),
                        ..Default::default()
                    })]),
                    Decision::Deny(diagnostics) => Ok(vec![Reply::Deny(HttpDenial {
                        diagnostics: Some(diagnostics),
                    })]),
                    Decision::Inspect(config, selected) => {
                        let mode = match selected {
                            Selected::Buffered(max_body_bytes) => {
                                http_inspect::Mode::Buffered(HttpBufferedMode { max_body_bytes })
                            }
                            Selected::Stream(_) => http_inspect::Mode::Stream(HttpStreamMode {}),
                        };
                        *self = Self::Begin(config, selected);
                        Ok(vec![Reply::Preflight(HttpPreflightResult {
                            decision: Some(http_preflight_result::Decision::Inspect(HttpInspect {
                                mode: Some(mode),
                            })),
                            ..Default::default()
                        })])
                    }
                }
            }
            (Self::Begin(config, Selected::Buffered(_)), Event::Begin) => {
                *self = Self::Buffered(config);
                Ok(Vec::new())
            }
            (Self::Begin(config, Selected::Stream(max_chunk_bytes)), Event::Begin) => {
                let scanner = StreamScanner::new(&config);
                // The head goes out before the guard knows whether it will
                // redact anything. Deny mode passes the body through unchanged.
                let header_mutations = if config.mode == Mode::Redact {
                    remove_integrity_headers()
                } else {
                    Vec::new()
                };
                *self = Self::Stream(config, scanner, max_chunk_bytes);
                Ok(vec![Reply::OutputStart(HttpOutputStart {
                    header_mutations,
                    output_body_bytes: None,
                })])
            }
            (Self::Buffered(config), Event::BufferedBody(body)) => {
                Ok(vec![buffered_result(inspect(&config, &body.data))])
            }
            (Self::Stream(config, mut scanner, max_chunk_bytes), Event::InputChunk(chunk)) => {
                match scanner.push(&chunk.data, config.mode == Mode::Deny) {
                    Ok(output) => {
                        *self = Self::Stream(config, scanner, max_chunk_bytes);
                        Ok(output_chunks(&output, max_chunk_bytes))
                    }
                    Err(_) => Ok(vec![deny(&config, &scanner)]),
                }
            }
            (Self::Stream(config, mut scanner, max_chunk_bytes), Event::InputEnd) => {
                match scanner.finish(config.mode == Mode::Deny) {
                    Ok(output) => {
                        let (match_count, matched_term_count) = scanner.counts();
                        let diagnostics = (match_count > 0).then(|| {
                            diagnostics(outcome(&config, match_count, matched_term_count))
                        });
                        let mut replies = output_chunks(&output, max_chunk_bytes);
                        replies.push(Reply::Finish(HttpFinish {
                            trailer_mutations: Vec::new(),
                            diagnostics,
                        }));
                        Ok(replies)
                    }
                    Err(_) => Ok(vec![deny(&config, &scanner)]),
                }
            }
            _ => Err(Status::invalid_argument(
                "invalid content guard HTTP lifecycle",
            )),
        }
    }
}

#[derive(Clone, Copy)]
enum Selected {
    Buffered(u64),
    /// The largest output chunk OpenShell accepts.
    Stream(usize),
}

enum Decision {
    Continue,
    Deny(MiddlewareDiagnostics),
    Inspect(GuardConfig, Selected),
}

fn preflight_decision(preflight: Preflight) -> Result<Decision, Status> {
    let config = GuardConfig::parse(preflight.config.as_ref()).map_err(Status::invalid_argument)?;
    match &preflight.subject {
        // The request target cannot be redacted, so a configured term in the
        // path or query denies the request before its body is read or the
        // upstream is contacted.
        Subject::Request(head) => {
            let target = head.target.clone().unwrap_or_default();
            let found = inspect(&config, target.path.as_bytes());
            let found = if found.findings.is_empty() {
                inspect(&config, target.query.as_bytes())
            } else {
                found
            };
            if let Some(finding) = found.findings.first() {
                let mut diagnostics = diagnostics(outcome(&config, finding.count, 1));
                diagnostics.reason = "request target matched configured content".into();
                diagnostics.reason_code = "content_match".into();
                return Ok(Decision::Deny(diagnostics));
            }
        }
        Subject::Response => {}
        Subject::Missing => return Err(Status::invalid_argument("preflight subject is required")),
    }
    // Nothing to guard in an empty body. OpenShell declares a length only
    // when no earlier stage may have replaced the body.
    if preflight.declared_body_bytes == Some(0) {
        return Ok(Decision::Continue);
    }
    let permitted = |mode: HttpBodyMode| preflight.permitted_body_modes.contains(&(mode as i32));
    let buffered = permitted(HttpBodyMode::Buffered).then(|| {
        let offered = preflight
            .limits
            .map_or(0, |limits| limits.max_buffered_body_bytes);
        Selected::Buffered(offered.min(MAX_PAYLOAD_BYTES))
    });
    let stream = permitted(HttpBodyMode::Stream).then(|| {
        let max_chunk_bytes = preflight.limits.map_or(0, |limits| limits.max_chunk_bytes);
        Selected::Stream(usize::try_from(max_chunk_bytes).unwrap_or(usize::MAX))
    });
    let selected = match config.body_mode {
        BodyMode::Buffered => buffered.or(stream),
        BodyMode::Stream => stream.or(buffered),
    };
    match selected {
        Some(Selected::Buffered(0)) => Err(Status::invalid_argument(
            "BUFFERED requires a positive max_buffered_body_bytes",
        )),
        Some(Selected::Stream(0)) => Err(Status::invalid_argument(
            "STREAM requires a positive max_chunk_bytes",
        )),
        Some(selected) => Ok(Decision::Inspect(config, selected)),
        // A message without a body has nothing to guard. The guard never
        // passes a body it could not inspect.
        None if bodyless(&preflight) => Ok(Decision::Continue),
        None => Ok(Decision::Deny(MiddlewareDiagnostics {
            reason: "content guard cannot inspect this body".into(),
            reason_code: "cannot_inspect".into(),
            ..Default::default()
        })),
    }
}

fn bodyless(preflight: &Preflight) -> bool {
    preflight
        .unavailable_body_modes
        .iter()
        .any(|unavailable| unavailable.reason == HttpBodyUnavailableReason::Bodyless as i32)
}

fn diagnostics(outcome: GuardOutcome) -> MiddlewareDiagnostics {
    MiddlewareDiagnostics {
        reason: outcome.reason,
        reason_code: outcome.reason_code,
        findings: outcome.findings,
        metadata: outcome.metadata,
    }
}

fn buffered_result(outcome: GuardOutcome) -> Reply {
    if outcome.denied {
        return Reply::Deny(HttpDenial {
            diagnostics: Some(diagnostics(outcome)),
        });
    }
    let mut outcome = outcome;
    let (body, header_mutations) = match outcome.replacement.take() {
        Some(replacement) => (
            http_buffered_result::Body::Replacement(replacement),
            remove_integrity_headers(),
        ),
        None => (
            http_buffered_result::Body::Unchanged(HttpUnchanged {}),
            Vec::new(),
        ),
    };
    let diagnostics = (!outcome.findings.is_empty()).then(|| diagnostics(outcome));
    Reply::Buffered(HttpBufferedResult {
        body: Some(body),
        header_mutations,
        diagnostics,
        ..Default::default()
    })
}

/// Headers that describe the exact body bytes and go stale when the guard
/// changes them. A service that can compute new values may write them instead.
const INTEGRITY_HEADERS: [&str; 8] = [
    "accept-ranges",
    "content-digest",
    "content-md5",
    "digest",
    "etag",
    "repr-digest",
    "signature",
    "signature-input",
];

fn remove_integrity_headers() -> Vec<HeaderMutation> {
    INTEGRITY_HEADERS
        .iter()
        .map(|name| HeaderMutation {
            operation: Some(header_mutation::Operation::Remove(RemoveHeader {
                name: (*name).to_string(),
            })),
        })
        .collect()
}

/// Output results for `data`, each within OpenShell's chunk limit: redacting
/// a short term makes the output longer than the input.
fn output_chunks(data: &[u8], max_chunk_bytes: usize) -> Vec<Reply> {
    data.chunks(max_chunk_bytes)
        .map(|data| {
            Reply::OutputChunk(HttpOutputChunk {
                data: data.to_vec(),
            })
        })
        .collect()
}

fn deny(config: &GuardConfig, scanner: &StreamScanner) -> Reply {
    let (match_count, matched_term_count) = scanner.counts();
    Reply::Deny(HttpDenial {
        diagnostics: Some(diagnostics(outcome(
            config,
            match_count.max(1),
            matched_term_count.max(1),
        ))),
    })
}

#[cfg(test)]
mod tests {
    use openshell_core::proto::{
        HttpBegin, HttpRequestSessionPreflight, HttpResponsePreflightHead,
        HttpResponseSessionPreflight,
    };

    use super::*;
    use crate::guard::test_support::config;

    fn preflight(
        subject: Subject,
        mode: &str,
        extra: &[(&str, &str)],
        permitted: &[HttpBodyMode],
    ) -> Event {
        Event::Preflight(Box::new(Preflight {
            subject,
            config: Some(config(mode, &["prototype-secret", "秘密"], extra)),
            permitted_body_modes: permitted.iter().map(|mode| *mode as i32).collect(),
            limits: Some(HttpBodyLimits {
                max_chunk_bytes: 64 * 1024,
                max_buffered_body_bytes: 1024 * 1024,
                ..Default::default()
            }),
            declared_body_bytes: Some(32),
            ..Default::default()
        }))
    }

    fn request() -> Subject {
        Subject::Request(HttpRequestPreflightHead::default())
    }

    fn only(replies: Vec<Reply>) -> Reply {
        assert_eq!(replies.len(), 1, "{replies:?}");
        replies.into_iter().next().unwrap()
    }

    fn buffered_body(data: &[u8]) -> Event {
        Event::BufferedBody(HttpBufferedBody {
            data: data.to_vec(),
            trailers: Vec::new(),
        })
    }

    #[test]
    fn buffered_stage_passes_redacts_and_denies() {
        for subject in [request, || Subject::Response] {
            for (mode, input, expected) in [
                ("redact", "clean", None),
                (
                    "redact",
                    "a prototype-secret 秘密",
                    Some("a [REDACTED] [REDACTED]"),
                ),
                ("deny", "prototype-secret", None),
            ] {
                let mut stage = Stage::Preflight;
                let selected = only(
                    stage
                        .handle(preflight(subject(), mode, &[], &[HttpBodyMode::Buffered]))
                        .unwrap(),
                );
                assert!(matches!(
                    selected,
                    Reply::Preflight(HttpPreflightResult {
                        decision: Some(http_preflight_result::Decision::Inspect(HttpInspect {
                            mode: Some(http_inspect::Mode::Buffered(HttpBufferedMode {
                                max_body_bytes: MAX_PAYLOAD_BYTES
                            })),
                        })),
                        ..
                    })
                ));
                assert!(stage.handle(Event::Begin).unwrap().is_empty());
                let body = only(stage.handle(buffered_body(input.as_bytes())).unwrap());
                match (mode, expected, body) {
                    ("deny", _, Reply::Deny(deny)) => {
                        let diagnostics = deny.diagnostics.unwrap();
                        assert_eq!(diagnostics.reason_code, "content_match");
                        assert!(!diagnostics.reason.contains("prototype-secret"));
                    }
                    (_, Some(expected), Reply::Buffered(result)) => {
                        assert_eq!(
                            result.body,
                            Some(http_buffered_result::Body::Replacement(
                                expected.as_bytes().to_vec()
                            ))
                        );
                        assert_eq!(result.header_mutations, remove_integrity_headers());
                    }
                    (_, None, Reply::Buffered(result)) => {
                        assert_eq!(
                            result.body,
                            Some(http_buffered_result::Body::Unchanged(HttpUnchanged {}))
                        );
                        assert!(result.header_mutations.is_empty());
                    }
                    (_, _, reply) => panic!("unexpected {mode} reply: {reply:?}"),
                }
            }
        }
    }

    #[test]
    fn stream_stage_redacts_chunks_and_finishes() {
        let mut stage = Stage::Preflight;
        let selected = only(
            stage
                .handle(preflight(
                    Subject::Response,
                    "redact",
                    &[("body_mode", "stream")],
                    &[HttpBodyMode::Buffered, HttpBodyMode::Stream],
                ))
                .unwrap(),
        );
        assert!(matches!(
            selected,
            Reply::Preflight(HttpPreflightResult {
                decision: Some(http_preflight_result::Decision::Inspect(HttpInspect {
                    mode: Some(http_inspect::Mode::Stream(_)),
                })),
                ..
            })
        ));
        let Reply::OutputStart(start) = only(stage.handle(Event::Begin).unwrap()) else {
            panic!("output start")
        };
        // Redaction may change the body, so the head drops integrity headers.
        assert_eq!(start.header_mutations, remove_integrity_headers());
        let mut output = Vec::new();
        for chunk in [&b"data: prototype-"[..], b"secret\n\n"] {
            for reply in stage
                .handle(Event::InputChunk(HttpInputChunk {
                    data: chunk.to_vec(),
                }))
                .unwrap()
            {
                let Reply::OutputChunk(chunk) = reply else {
                    panic!("output chunk")
                };
                output.extend(chunk.data);
            }
        }
        assert_eq!(output, b"data: [REDACTED]\n\n");
        let finished = stage.handle(Event::InputEnd).unwrap();
        let Some(Reply::Finish(finish)) = finished.into_iter().last() else {
            panic!("finish")
        };
        assert_eq!(finish.diagnostics.unwrap().findings[0].count, 1);
    }

    #[test]
    fn stream_stage_splits_expanded_output_within_the_chunk_limit() {
        let mut selected = preflight(
            Subject::Response,
            "redact",
            &[("body_mode", "stream")],
            &[HttpBodyMode::Stream],
        );
        let Event::Preflight(preflight_event) = &mut selected else {
            unreachable!()
        };
        preflight_event.limits = Some(HttpBodyLimits {
            max_chunk_bytes: 16,
            ..Default::default()
        });
        let mut stage = Stage::Preflight;
        stage.handle(selected).unwrap();
        stage.handle(Event::Begin).unwrap();
        // Each 6-byte term becomes the 10-byte marker.
        let mut replies = stage
            .handle(Event::InputChunk(HttpInputChunk {
                data: "秘密".repeat(8).into_bytes(),
            }))
            .unwrap();
        replies.extend(stage.handle(Event::InputEnd).unwrap());
        let mut output = Vec::new();
        for reply in replies {
            match reply {
                Reply::OutputChunk(chunk) => {
                    assert!((1..=16).contains(&chunk.data.len()), "{chunk:?}");
                    output.extend(chunk.data);
                }
                Reply::Finish(_) => {}
                reply => panic!("unexpected reply: {reply:?}"),
            }
        }
        assert_eq!(output, "[REDACTED]".repeat(8).as_bytes());
    }

    #[test]
    fn preflight_continues_bodyless_and_empty_messages() {
        let mut bodyless = preflight(Subject::Response, "redact", &[], &[]);
        let Event::Preflight(preflight_event) = &mut bodyless else {
            unreachable!()
        };
        preflight_event.unavailable_body_modes = vec![HttpBodyModeUnavailable {
            mode: HttpBodyMode::Buffered as i32,
            reason: HttpBodyUnavailableReason::Bodyless as i32,
        }];
        let mut empty = preflight(request(), "redact", &[], &[HttpBodyMode::Buffered]);
        let Event::Preflight(preflight_event) = &mut empty else {
            unreachable!()
        };
        preflight_event.declared_body_bytes = Some(0);
        for event in [bodyless, empty] {
            assert!(matches!(
                only(Stage::Preflight.handle(event).unwrap()),
                Reply::Preflight(HttpPreflightResult {
                    decision: Some(http_preflight_result::Decision::ContinueWithoutBody(_)),
                    ..
                })
            ));
        }
    }

    #[test]
    fn preflight_denies_a_body_it_is_not_offered() {
        // OpenShell offers no body mode for an encoded request or response.
        for subject in [request, || Subject::Response] {
            let mut encoded = preflight(subject(), "redact", &[], &[]);
            let Event::Preflight(preflight_event) = &mut encoded else {
                unreachable!()
            };
            preflight_event.unavailable_body_modes = [HttpBodyMode::Buffered, HttpBodyMode::Stream]
                .into_iter()
                .map(|mode| HttpBodyModeUnavailable {
                    mode: mode as i32,
                    reason: HttpBodyUnavailableReason::Encoded as i32,
                })
                .collect();
            let Reply::Deny(deny) = only(Stage::Preflight.handle(encoded).unwrap()) else {
                panic!("deny")
            };
            assert_eq!(deny.diagnostics.unwrap().reason_code, "cannot_inspect");
        }
    }

    #[test]
    fn preflight_denies_a_term_in_the_request_target() {
        for (path, query) in [
            ("/items/prototype-secret", ""),
            ("/items", "q=prototype-secret"),
        ] {
            let subject = Subject::Request(HttpRequestPreflightHead {
                target: Some(openshell_core::proto::HttpRequestTarget {
                    path: path.into(),
                    query: query.into(),
                    ..Default::default()
                }),
                headers: Vec::new(),
            });
            let denied = only(
                Stage::Preflight
                    .handle(preflight(subject, "redact", &[], &[HttpBodyMode::Buffered]))
                    .unwrap(),
            );
            let Reply::Deny(deny) = denied else {
                panic!("expected a denial for {path}?{query}")
            };
            let diagnostics = deny.diagnostics.unwrap();
            assert_eq!(diagnostics.reason_code, "content_match");
            assert!(!diagnostics.reason.contains("prototype-secret"));
        }
    }

    #[test]
    fn stage_enforces_its_lifecycle() {
        assert_eq!(
            Stage::Preflight
                .handle(buffered_body(b"early"))
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        let mut stage = Stage::Preflight;
        stage
            .handle(preflight(
                request(),
                "redact",
                &[],
                &[HttpBodyMode::Buffered],
            ))
            .unwrap();
        assert_eq!(
            stage.handle(buffered_body(b"early")).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }

    /// Wire preflight fields shared by both RPCs, for a BUFFERED body.
    fn buffered_offer() -> (
        Vec<i32>,
        Option<HttpBodyLimits>,
        Option<prost_types::Struct>,
    ) {
        (
            vec![HttpBodyMode::Buffered as i32],
            Some(HttpBodyLimits {
                max_chunk_bytes: 64 * 1024,
                max_buffered_body_bytes: 1024,
                ..Default::default()
            }),
            Some(config("redact", &["prototype-secret"], &[])),
        )
    }

    #[tokio::test]
    async fn both_rpcs_run_the_same_exchange() {
        let body = || HttpBufferedBody {
            data: b"a prototype-secret".to_vec(),
            trailers: Vec::new(),
        };
        let (permitted, limits, config) = buffered_offer();
        let request = request_stream(tokio_stream::iter(
            [
                http_request_session_event::Event::Preflight(HttpRequestSessionPreflight {
                    request: Some(HttpRequestPreflightHead::default()),
                    config: config.clone(),
                    permitted_body_modes: permitted.clone(),
                    limits,
                    ..Default::default()
                }),
                http_request_session_event::Event::Begin(HttpBegin::default()),
                http_request_session_event::Event::BufferedBody(body()),
            ]
            .map(|event| Ok(HttpRequestSessionEvent { event: Some(event) })),
        ));
        let request: Vec<_> = request
            .map(|result| result.unwrap().result.unwrap())
            .collect()
            .await;
        assert!(matches!(
            request.as_slice(),
            [
                http_request_session_result::Result::PreflightResult(_),
                http_request_session_result::Result::BufferedResult(_),
            ]
        ));

        let response = response_stream(tokio_stream::iter(
            [
                http_response_session_event::Event::Preflight(HttpResponseSessionPreflight {
                    response: Some(HttpResponsePreflightHead::default()),
                    config,
                    permitted_body_modes: permitted,
                    limits,
                    ..Default::default()
                }),
                http_response_session_event::Event::Begin(HttpBegin::default()),
                http_response_session_event::Event::BufferedBody(body()),
            ]
            .map(|event| Ok(HttpResponseSessionEvent { event: Some(event) })),
        ));
        let response: Vec<_> = response
            .map(|result| result.unwrap().result.unwrap())
            .collect()
            .await;
        assert!(matches!(
            response.as_slice(),
            [
                http_response_session_result::Result::PreflightResult(_),
                http_response_session_result::Result::BufferedResult(_),
            ]
        ));
    }
}
