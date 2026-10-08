// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP protocol 1 (0.1): `SupervisorMiddleware.EvaluateHttpRequest` and
//! `HttpResponsePreReturn.Evaluate`. The service uses it with peers that do
//! not advertise `http-v2`, and OpenShell 0.2.0 removes it. Delete this
//! module, and the legacy bindings in `manifest`, once the service no longer
//! supports those peers.

use openshell_core::middleware::HttpResponseResultStream;
use openshell_core::proto::{
    Decision, HttpRequestEvaluation, HttpRequestResult, HttpResponseBlockDelivery,
    HttpResponseBodyMode, HttpResponseBodyPassThrough, HttpResponseBodyResult,
    HttpResponseBodyTransform, HttpResponseBodyUnit, HttpResponseEvent, HttpResponseEventResult,
    HttpResponsePreflight, HttpResponsePreflightInspect, HttpResponsePreflightResult,
    HttpResponseTrailersResult, http_response_body_result, http_response_body_transform,
    http_response_body_unit, http_response_event, http_response_event_result,
    http_response_preflight_result,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt};
use tonic::Status;

use crate::guard::{GuardConfig, GuardOutcome, NotUtf8, complete_body_unavailable};

/// Inspect a complete body. Like v0.1.2, a body that is not UTF-8 fails with
/// `INVALID_ARGUMENT`.
fn inspect_http_body(config: &GuardConfig, body: &[u8]) -> Result<GuardOutcome, Status> {
    crate::guard::inspect_http_body(config, body)
        .map_err(|NotUtf8| Status::invalid_argument(NotUtf8::MESSAGE))
}

pub(crate) fn evaluate_request(
    request: HttpRequestEvaluation,
) -> Result<HttpRequestResult, Status> {
    crate::validate_phase(request.phase).map_err(Status::invalid_argument)?;
    let config = GuardConfig::from_evaluation(request.config.as_ref())?;
    let outcome = inspect_http_body(&config, &request.body)?;
    Ok(HttpRequestResult {
        decision: if outcome.denied {
            Decision::Deny
        } else {
            Decision::Allow
        } as i32,
        has_body: outcome.replacement.is_some(),
        body: outcome.replacement.unwrap_or_default().into_bytes(),
        reason: outcome.reason,
        reason_code: outcome.reason_code,
        findings: outcome.findings,
        metadata: outcome.metadata,
        ..Default::default()
    })
}

pub(crate) fn response_stream<S>(mut events: S) -> HttpResponseResultStream
where
    S: Stream<Item = Result<HttpResponseEvent, Status>> + Send + Unpin + 'static,
{
    let (sender, receiver) = mpsc::channel(4);
    tokio::spawn(async move {
        let mut session = ResponseSession::default();
        while let Some(event) = events.next().await {
            let result = match event {
                Ok(event) => match event.event {
                    Some(http_response_event::Event::Preflight(preflight)) => {
                        session.preflight(preflight)
                    }
                    Some(http_response_event::Event::Body(body)) => session.body(body),
                    Some(http_response_event::Event::Trailers(_)) => session.trailers(),
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
    Box::pin(ReceiverStream::new(receiver))
}

#[derive(Debug, Default)]
struct ResponseSession {
    config: Option<GuardConfig>,
    body_ended: bool,
    trailers_seen: bool,
}

impl ResponseSession {
    fn preflight(
        &mut self,
        preflight: HttpResponsePreflight,
    ) -> Result<HttpResponseEventResult, Status> {
        if self.config.is_some() {
            return Err(Status::failed_precondition("duplicate preflight"));
        }
        let config = GuardConfig::from_evaluation(preflight.config.as_ref())?;
        if !preflight
            .permitted_body_modes
            .contains(&(HttpResponseBodyMode::WholeBodyBytes as i32))
        {
            return Err(complete_body_unavailable("WHOLE_BODY_BYTES"));
        }
        self.config = Some(config);
        Ok(HttpResponseEventResult {
            result: Some(http_response_event_result::Result::PreflightResult(
                HttpResponsePreflightResult {
                    action: Some(http_response_preflight_result::Action::Inspect(
                        HttpResponsePreflightInspect {
                            body_mode: HttpResponseBodyMode::WholeBodyBytes as i32,
                            header_mutations: vec![],
                        },
                    )),
                    ..Default::default()
                },
            )),
        })
    }

    fn body(&mut self, body: HttpResponseBodyUnit) -> Result<HttpResponseEventResult, Status> {
        let config = self
            .config
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("body before preflight"))?;
        if self.body_ended || body.sequence != 1 || !body.end_of_stream {
            return Err(Status::failed_precondition(
                "expected one complete response body",
            ));
        }
        let Some(http_response_body_unit::Payload::Data(data)) = body.payload else {
            return Err(Status::invalid_argument("body data required"));
        };
        let outcome = inspect_http_body(config, &data)?;
        let action = if outcome.denied {
            http_response_body_result::Action::BlockDelivery(HttpResponseBlockDelivery {})
        } else if let Some(replacement) = outcome.replacement {
            http_response_body_result::Action::Transform(HttpResponseBodyTransform {
                replacement: Some(http_response_body_transform::Replacement::Data(
                    replacement.into_bytes(),
                )),
            })
        } else {
            http_response_body_result::Action::PassThrough(HttpResponseBodyPassThrough {})
        };
        self.body_ended = true;
        Ok(HttpResponseEventResult {
            result: Some(http_response_event_result::Result::BodyResult(
                HttpResponseBodyResult {
                    sequence: body.sequence,
                    action: Some(action),
                    reason: outcome.reason,
                    reason_code: outcome.reason_code,
                    findings: outcome.findings,
                    metadata: outcome.metadata,
                },
            )),
        })
    }

    fn trailers(&mut self) -> Result<HttpResponseEventResult, Status> {
        if !self.body_ended || self.trailers_seen {
            return Err(Status::failed_precondition("expected trailers after body"));
        }
        self.trailers_seen = true;
        Ok(HttpResponseEventResult {
            result: Some(http_response_event_result::Result::TrailersResult(
                HttpResponseTrailersResult::default(),
            )),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PHASE;
    use crate::guard::test_support::config;

    fn request(mode: &str, body: &str) -> HttpRequestEvaluation {
        HttpRequestEvaluation {
            phase: PHASE as i32,
            config: Some(config(mode, &["prototype-secret"], None)),
            body: body.as_bytes().to_vec(),
            ..Default::default()
        }
    }

    #[test]
    fn request_guard_maps_outcomes_to_legacy_results() {
        let clean = evaluate_request(request("redact", "safe content")).unwrap();
        assert_eq!(clean.decision, Decision::Allow as i32);
        assert!(!clean.has_body);
        assert!(clean.body.is_empty());

        let redacted = evaluate_request(request("redact", "a prototype-secret")).unwrap();
        assert_eq!(redacted.decision, Decision::Allow as i32);
        assert!(redacted.has_body);
        assert_eq!(redacted.body, b"a [REDACTED]");

        let denied = evaluate_request(request("deny", "a prototype-secret")).unwrap();
        assert_eq!(denied.decision, Decision::Deny as i32);
        assert_eq!(denied.reason_code, "content_match");
        assert!(!denied.has_body);
    }

    #[test]
    fn request_guard_rejects_other_phases() {
        let mut request = request("redact", "safe content");
        request.phase += 1;

        let error = evaluate_request(request).unwrap_err();

        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }

    fn response_preflight(mode: &str) -> HttpResponsePreflight {
        HttpResponsePreflight {
            config: Some(config(mode, &["prototype-secret", "秘密"], None)),
            permitted_body_modes: vec![HttpResponseBodyMode::WholeBodyBytes as i32],
            ..Default::default()
        }
    }

    #[test]
    fn response_guard_passes_redacts_and_denies() {
        for (mode, input, expected) in [
            ("redact", "clean", None),
            (
                "redact",
                "a prototype-secret 秘密",
                Some("a [REDACTED] [REDACTED]"),
            ),
            ("deny", "prototype-secret", None),
        ] {
            let mut session = ResponseSession::default();
            session.preflight(response_preflight(mode)).unwrap();
            let unit = HttpResponseBodyUnit {
                sequence: 1,
                payload: Some(http_response_body_unit::Payload::Data(
                    input.as_bytes().to_vec(),
                )),
                end_of_stream: true,
            };
            let result = session.body(unit.clone()).unwrap();
            assert!(session.body(unit).is_err());
            let Some(http_response_event_result::Result::BodyResult(result)) = result.result else {
                panic!("body result")
            };
            if mode == "deny" {
                assert!(matches!(
                    result.action,
                    Some(http_response_body_result::Action::BlockDelivery(_))
                ));
                assert_eq!(result.reason_code, "content_match");
            } else if let Some(expected) = expected {
                let Some(http_response_body_result::Action::Transform(transform)) = result.action
                else {
                    panic!("transform")
                };
                assert_eq!(
                    transform.replacement,
                    Some(http_response_body_transform::Replacement::Data(
                        expected.as_bytes().to_vec()
                    ))
                );
            } else {
                assert!(matches!(
                    result.action,
                    Some(http_response_body_result::Action::PassThrough(_))
                ));
            }
            let trailers = session.trailers().unwrap();
            let Some(http_response_event_result::Result::TrailersResult(trailers)) =
                trailers.result
            else {
                panic!("trailers")
            };
            assert!(trailers.trailer_mutations.is_empty());
            assert!(session.trailers().is_err());
        }
    }

    #[test]
    fn response_guard_rejects_unavailable_inspection_and_invalid_input() {
        let mut preflight = response_preflight("redact");
        preflight.permitted_body_modes = vec![HttpResponseBodyMode::HeadersOnly as i32];
        assert!(ResponseSession::default().preflight(preflight).is_err());
        for (sequence, end_of_stream, payload) in [
            (2, true, Some(vec![])),
            (1, false, Some(vec![])),
            (1, true, Some(vec![0xff])),
            (1, true, None),
        ] {
            let mut session = ResponseSession::default();
            assert!(session.trailers().is_err());
            session.preflight(response_preflight("redact")).unwrap();
            assert!(session.preflight(response_preflight("redact")).is_err());
            assert!(
                session
                    .body(HttpResponseBodyUnit {
                        sequence,
                        end_of_stream,
                        payload: payload.map(http_response_body_unit::Payload::Data)
                    })
                    .is_err()
            );
        }
    }
}
