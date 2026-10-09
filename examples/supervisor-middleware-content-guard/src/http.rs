// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP middleware protocol 2 (`EvaluateHttpRequestV2` and
//! `EvaluateHttpResponseV2`) for requests, responses, and uninspectable
//! connections.
//!
//! The guard selects its configured body mode, BUFFERED by default, and falls
//! back to the other mode when OpenShell offers only that one. A message
//! without a body continues. A stage that cannot inspect a message, such as an
//! encoded response, ends with `FAILED_PRECONDITION`, which OpenShell reports
//! as `middleware_cannot_inspect` and fails closed. Uninspectable connections
//! are rejected unless the config sets `uninspectable: allow`.

use openshell_core::middleware::HttpResultStream;
use openshell_core::proto::{
    HttpBodyMode, HttpBodyUnavailableReason, HttpBufferedMode, HttpBufferedResult, HttpContinue,
    HttpEvent, HttpFinish, HttpInspect, HttpOutputChunk, HttpOutputStart, HttpPreflight,
    HttpPreflightResult, HttpReject, HttpResult, HttpStreamMode, HttpUnchanged,
    MiddlewareDiagnostics, http_buffered_result, http_event, http_inspect, http_preflight,
    http_preflight_result, http_result,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt};
use tonic::Status;

use crate::guard::{
    BodyMode, GuardConfig, GuardOutcome, MAX_PAYLOAD_BYTES, Mode, StreamScanner, inspect, outcome,
};

/// Run one HTTP protocol 2 exchange. Both RPCs share this handler: the
/// preflight subject says whether it is a request, a response, or traffic
/// OpenShell cannot inspect.
pub(crate) fn stage_stream<S>(mut events: S) -> HttpResultStream
where
    S: Stream<Item = Result<HttpEvent, Status>> + Send + Unpin + 'static,
{
    let (sender, receiver) = mpsc::channel(4);
    tokio::spawn(async move {
        let mut stage = Stage::Preflight;
        while let Some(event) = events.next().await {
            let results = match event {
                Ok(HttpEvent {
                    event: Some(http_event::Event::SessionEnd(_)),
                }) => break,
                Ok(event) => stage.handle(event),
                Err(error) => Err(error),
            };
            match results {
                Ok(results) => {
                    for result in results {
                        if sender.send(Ok(result)).await.is_err() {
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

enum Stage {
    Preflight,
    Begin(GuardConfig, BodyMode),
    Buffered(GuardConfig),
    Stream(GuardConfig, StreamScanner),
    Done,
}

impl Stage {
    /// Handle one event other than `session_end` and return its results.
    fn handle(&mut self, event: HttpEvent) -> Result<Vec<HttpResult>, Status> {
        match (std::mem::replace(self, Self::Done), event.event) {
            (Self::Preflight, Some(http_event::Event::Preflight(preflight))) => {
                match preflight_decision(preflight)? {
                    Decision::Continue => Ok(vec![result(http_result::Result::PreflightResult(
                        HttpPreflightResult {
                            decision: Some(http_preflight_result::Decision::ContinueWithoutBody(
                                HttpContinue {},
                            )),
                            ..Default::default()
                        },
                    ))]),
                    Decision::Reject(diagnostics) => {
                        Ok(vec![result(http_result::Result::Reject(HttpReject {
                            diagnostics: Some(diagnostics),
                        }))])
                    }
                    Decision::Inspect(config, mode) => {
                        let selected = match mode {
                            Selected::Buffered(max_body_bytes) => {
                                *self = Self::Begin(config, BodyMode::Buffered);
                                http_inspect::Mode::Buffered(HttpBufferedMode { max_body_bytes })
                            }
                            Selected::Stream => {
                                *self = Self::Begin(config, BodyMode::Stream);
                                http_inspect::Mode::Stream(HttpStreamMode {})
                            }
                        };
                        Ok(vec![result(http_result::Result::PreflightResult(
                            HttpPreflightResult {
                                decision: Some(http_preflight_result::Decision::Inspect(
                                    HttpInspect {
                                        mode: Some(selected),
                                    },
                                )),
                                ..Default::default()
                            },
                        ))])
                    }
                }
            }
            (Self::Begin(config, BodyMode::Buffered), Some(http_event::Event::Begin(_))) => {
                *self = Self::Buffered(config);
                Ok(Vec::new())
            }
            (Self::Begin(config, BodyMode::Stream), Some(http_event::Event::Begin(_))) => {
                let scanner = StreamScanner::new(&config);
                *self = Self::Stream(config, scanner);
                Ok(vec![result(http_result::Result::OutputStart(
                    HttpOutputStart::default(),
                ))])
            }
            (Self::Buffered(config), Some(http_event::Event::BufferedBody(body))) => {
                Ok(vec![buffered_result(inspect(&config, &body.data))])
            }
            (Self::Stream(config, mut scanner), Some(http_event::Event::InputChunk(chunk))) => {
                match scanner.push(&chunk.data, config.mode == Mode::Deny) {
                    Ok(output) => {
                        *self = Self::Stream(config, scanner);
                        Ok(output_chunk(output).into_iter().collect())
                    }
                    Err(_) => Ok(vec![reject(&config, &scanner)]),
                }
            }
            (Self::Stream(config, mut scanner), Some(http_event::Event::InputEnd(_))) => {
                match scanner.finish(config.mode == Mode::Deny) {
                    Ok(output) => {
                        let (match_count, matched_term_count) = scanner.counts();
                        let diagnostics = (match_count > 0).then(|| {
                            diagnostics(outcome(&config, match_count, matched_term_count))
                        });
                        let mut results: Vec<_> = output_chunk(output).into_iter().collect();
                        results.push(result(http_result::Result::Finish(HttpFinish {
                            trailer_mutations: Vec::new(),
                            diagnostics,
                        })));
                        Ok(results)
                    }
                    Err(_) => Ok(vec![reject(&config, &scanner)]),
                }
            }
            (_, None) => Err(Status::invalid_argument("HTTP event is required")),
            // Not FAILED_PRECONDITION, which OpenShell reads as "cannot
            // inspect".
            _ => Err(Status::invalid_argument(
                "invalid content guard HTTP lifecycle",
            )),
        }
    }
}

enum Selected {
    Buffered(u64),
    Stream,
}

enum Decision {
    Continue,
    Reject(MiddlewareDiagnostics),
    Inspect(GuardConfig, Selected),
}

fn preflight_decision(preflight: HttpPreflight) -> Result<Decision, Status> {
    let config = GuardConfig::parse(preflight.config.as_ref()).map_err(Status::invalid_argument)?;
    match &preflight.subject {
        Some(http_preflight::Subject::Uninspectable(_)) => {
            return Ok(if config.allow_uninspectable {
                Decision::Continue
            } else {
                Decision::Reject(MiddlewareDiagnostics {
                    reason: "content guard cannot inspect this connection".into(),
                    reason_code: "uninspectable_traffic".into(),
                    ..Default::default()
                })
            });
        }
        // The request target cannot be redacted, so a configured term in the
        // path or query rejects the request before its body is read or the
        // upstream is contacted.
        Some(http_preflight::Subject::Request(head)) => {
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
                return Ok(Decision::Reject(diagnostics));
            }
        }
        Some(http_preflight::Subject::Response(_)) => {}
        None => return Err(Status::invalid_argument("preflight subject is required")),
    }
    // Nothing to guard in an empty body.
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
    let stream = permitted(HttpBodyMode::Stream).then_some(Selected::Stream);
    let selected = match config.body_mode {
        BodyMode::Buffered => buffered.or(stream),
        BodyMode::Stream => stream.or(buffered),
    };
    match selected {
        Some(Selected::Buffered(0)) => Err(Status::invalid_argument(
            "BUFFERED requires a positive max_buffered_body_bytes",
        )),
        Some(selected) => Ok(Decision::Inspect(config, selected)),
        // A message without a body has nothing to guard. The guard never
        // passes a body it could not inspect.
        None if bodyless(&preflight) => Ok(Decision::Continue),
        None => Err(Status::failed_precondition(
            "content guard cannot inspect this message body",
        )),
    }
}

fn bodyless(preflight: &HttpPreflight) -> bool {
    preflight
        .unavailable_body_modes
        .iter()
        .any(|unavailable| unavailable.reason == HttpBodyUnavailableReason::Bodyless as i32)
}

fn result(result: http_result::Result) -> HttpResult {
    HttpResult {
        result: Some(result),
    }
}

fn diagnostics(outcome: GuardOutcome) -> MiddlewareDiagnostics {
    MiddlewareDiagnostics {
        reason: outcome.reason,
        reason_code: outcome.reason_code,
        findings: outcome.findings,
        metadata: outcome.metadata,
    }
}

fn buffered_result(outcome: GuardOutcome) -> HttpResult {
    if outcome.denied {
        return result(http_result::Result::Reject(HttpReject {
            diagnostics: Some(diagnostics(outcome)),
        }));
    }
    let mut outcome = outcome;
    let body = outcome.replacement.take().map_or(
        http_buffered_result::Body::Unchanged(HttpUnchanged {}),
        http_buffered_result::Body::Replacement,
    );
    let diagnostics = (!outcome.findings.is_empty()).then(|| diagnostics(outcome));
    result(http_result::Result::BufferedResult(HttpBufferedResult {
        body: Some(body),
        diagnostics,
        ..Default::default()
    }))
}

fn output_chunk(data: Vec<u8>) -> Option<HttpResult> {
    (!data.is_empty()).then(|| result(http_result::Result::OutputChunk(HttpOutputChunk { data })))
}

fn reject(config: &GuardConfig, scanner: &StreamScanner) -> HttpResult {
    let (match_count, matched_term_count) = scanner.counts();
    result(http_result::Result::Reject(HttpReject {
        diagnostics: Some(diagnostics(outcome(
            config,
            match_count.max(1),
            matched_term_count.max(1),
        ))),
    }))
}

#[cfg(test)]
mod tests {
    use openshell_core::proto::{
        HttpBegin, HttpBodyLimits, HttpBodyModeUnavailable, HttpBufferedBody, HttpInputChunk,
        HttpInputEnd, HttpRequestPreflightHead, HttpResponsePreflightHead, UninspectableTraffic,
    };

    use super::*;
    use crate::guard::test_support::config;

    fn preflight(
        subject: http_preflight::Subject,
        mode: &str,
        extra: &[(&str, &str)],
        permitted: &[HttpBodyMode],
    ) -> HttpEvent {
        HttpEvent {
            event: Some(http_event::Event::Preflight(HttpPreflight {
                subject: Some(subject),
                config: Some(config(mode, &["prototype-secret", "秘密"], extra)),
                permitted_body_modes: permitted.iter().map(|mode| *mode as i32).collect(),
                limits: Some(HttpBodyLimits {
                    max_buffered_body_bytes: 1024 * 1024,
                    ..Default::default()
                }),
                declared_body_bytes: Some(32),
                ..Default::default()
            })),
        }
    }

    fn request() -> http_preflight::Subject {
        http_preflight::Subject::Request(HttpRequestPreflightHead::default())
    }

    fn response() -> http_preflight::Subject {
        http_preflight::Subject::Response(HttpResponsePreflightHead::default())
    }

    fn event(event: http_event::Event) -> HttpEvent {
        HttpEvent { event: Some(event) }
    }

    fn only(results: Vec<HttpResult>) -> http_result::Result {
        assert_eq!(results.len(), 1, "{results:?}");
        results.into_iter().next().unwrap().result.unwrap()
    }

    #[test]
    fn buffered_stage_passes_redacts_and_denies() {
        for subject in [request(), response()] {
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
                        .handle(preflight(
                            subject.clone(),
                            mode,
                            &[],
                            &[HttpBodyMode::Buffered],
                        ))
                        .unwrap(),
                );
                assert!(matches!(
                    selected,
                    http_result::Result::PreflightResult(HttpPreflightResult {
                        decision: Some(http_preflight_result::Decision::Inspect(HttpInspect {
                            mode: Some(http_inspect::Mode::Buffered(HttpBufferedMode {
                                max_body_bytes: MAX_PAYLOAD_BYTES
                            })),
                        })),
                        ..
                    })
                ));
                assert!(
                    stage
                        .handle(event(http_event::Event::Begin(HttpBegin::default())))
                        .unwrap()
                        .is_empty()
                );
                let body = only(
                    stage
                        .handle(event(http_event::Event::BufferedBody(HttpBufferedBody {
                            data: input.as_bytes().to_vec(),
                            trailers: Vec::new(),
                        })))
                        .unwrap(),
                );
                match (mode, expected, body) {
                    ("deny", _, http_result::Result::Reject(reject)) => {
                        let diagnostics = reject.diagnostics.unwrap();
                        assert_eq!(diagnostics.reason_code, "content_match");
                        assert!(!diagnostics.reason.contains("prototype-secret"));
                    }
                    (_, Some(expected), http_result::Result::BufferedResult(result)) => assert_eq!(
                        result.body,
                        Some(http_buffered_result::Body::Replacement(
                            expected.as_bytes().to_vec()
                        ))
                    ),
                    (_, None, http_result::Result::BufferedResult(result)) => assert_eq!(
                        result.body,
                        Some(http_buffered_result::Body::Unchanged(HttpUnchanged {}))
                    ),
                    (_, _, result) => panic!("unexpected {mode} result: {result:?}"),
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
                    response(),
                    "redact",
                    &[("body_mode", "stream")],
                    &[HttpBodyMode::Buffered, HttpBodyMode::Stream],
                ))
                .unwrap(),
        );
        assert!(matches!(
            selected,
            http_result::Result::PreflightResult(HttpPreflightResult {
                decision: Some(http_preflight_result::Decision::Inspect(HttpInspect {
                    mode: Some(http_inspect::Mode::Stream(_)),
                })),
                ..
            })
        ));
        assert!(matches!(
            only(
                stage
                    .handle(event(http_event::Event::Begin(HttpBegin::default())))
                    .unwrap()
            ),
            http_result::Result::OutputStart(_)
        ));
        let mut output = Vec::new();
        for chunk in [&b"data: prototype-"[..], b"secret\n\n"] {
            for result in stage
                .handle(event(http_event::Event::InputChunk(HttpInputChunk {
                    data: chunk.to_vec(),
                })))
                .unwrap()
            {
                let Some(http_result::Result::OutputChunk(chunk)) = result.result else {
                    panic!("output chunk")
                };
                output.extend(chunk.data);
            }
        }
        assert_eq!(output, b"data: [REDACTED]\n\n");
        let finished = stage
            .handle(event(http_event::Event::InputEnd(HttpInputEnd::default())))
            .unwrap();
        let Some(http_result::Result::Finish(finish)) = finished.last().unwrap().result.clone()
        else {
            panic!("finish")
        };
        assert_eq!(finish.diagnostics.unwrap().findings[0].count, 1);
    }

    #[test]
    fn preflight_continues_bodyless_and_empty_messages() {
        let mut bodyless = preflight(response(), "redact", &[], &[]);
        let Some(http_event::Event::Preflight(preflight_event)) = bodyless.event.as_mut() else {
            unreachable!()
        };
        preflight_event.unavailable_body_modes = vec![HttpBodyModeUnavailable {
            mode: HttpBodyMode::Buffered as i32,
            reason: HttpBodyUnavailableReason::Bodyless as i32,
        }];
        let mut empty = preflight(request(), "redact", &[], &[HttpBodyMode::Buffered]);
        let Some(http_event::Event::Preflight(preflight_event)) = empty.event.as_mut() else {
            unreachable!()
        };
        preflight_event.declared_body_bytes = Some(0);
        for event in [bodyless, empty] {
            assert!(matches!(
                only(Stage::Preflight.handle(event).unwrap()),
                http_result::Result::PreflightResult(HttpPreflightResult {
                    decision: Some(http_preflight_result::Decision::ContinueWithoutBody(_)),
                    ..
                })
            ));
        }
    }

    #[test]
    fn preflight_cannot_inspect_a_body_it_is_not_offered() {
        let mut encoded = preflight(response(), "redact", &[], &[]);
        let Some(http_event::Event::Preflight(preflight_event)) = encoded.event.as_mut() else {
            unreachable!()
        };
        preflight_event.unavailable_body_modes = vec![HttpBodyModeUnavailable {
            mode: HttpBodyMode::Buffered as i32,
            reason: HttpBodyUnavailableReason::Encoded as i32,
        }];
        assert_eq!(
            Stage::Preflight.handle(encoded).unwrap_err().code(),
            tonic::Code::FailedPrecondition
        );
    }

    #[test]
    fn preflight_rejects_a_term_in_the_request_target() {
        for (path, query) in [
            ("/items/prototype-secret", ""),
            ("/items", "q=prototype-secret"),
        ] {
            let subject = http_preflight::Subject::Request(HttpRequestPreflightHead {
                target: Some(openshell_core::proto::HttpRequestTarget {
                    path: path.into(),
                    query: query.into(),
                    ..Default::default()
                }),
                headers: Vec::new(),
            });
            let rejected = only(
                Stage::Preflight
                    .handle(preflight(subject, "redact", &[], &[HttpBodyMode::Buffered]))
                    .unwrap(),
            );
            let http_result::Result::Reject(reject) = rejected else {
                panic!("expected a rejection for {path}?{query}")
            };
            let diagnostics = reject.diagnostics.unwrap();
            assert_eq!(diagnostics.reason_code, "content_match");
            assert!(!diagnostics.reason.contains("prototype-secret"));
        }
    }

    #[test]
    fn uninspectable_traffic_is_denied_unless_allowed() {
        let subject = || http_preflight::Subject::Uninspectable(UninspectableTraffic::default());
        let denied = only(
            Stage::Preflight
                .handle(preflight(subject(), "redact", &[], &[]))
                .unwrap(),
        );
        let http_result::Result::Reject(reject) = denied else {
            panic!("expected a rejection")
        };
        assert_eq!(
            reject.diagnostics.unwrap().reason_code,
            "uninspectable_traffic"
        );
        assert!(matches!(
            only(
                Stage::Preflight
                    .handle(preflight(
                        subject(),
                        "redact",
                        &[("uninspectable", "allow")],
                        &[]
                    ))
                    .unwrap()
            ),
            http_result::Result::PreflightResult(HttpPreflightResult {
                decision: Some(http_preflight_result::Decision::ContinueWithoutBody(_)),
                ..
            })
        ));
    }

    #[test]
    fn stage_enforces_its_lifecycle() {
        let body = || {
            event(http_event::Event::BufferedBody(HttpBufferedBody {
                data: b"early".to_vec(),
                trailers: Vec::new(),
            }))
        };
        assert_eq!(
            Stage::Preflight.handle(body()).unwrap_err().code(),
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
            stage.handle(body()).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }
}
