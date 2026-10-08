// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Drives the served gRPC services through both HTTP protocols in the order
//! OpenShell uses, and checks that every guard behaviour has the same outcome
//! and diagnostics under both. Version 2 differs where it says more than the
//! legacy protocol can: it lets bodyless responses continue, and it reports a
//! body the guard cannot inspect with `FAILED_PRECONDITION`.

use std::collections::HashMap;

use openshell_core::proto::middleware::v1::http_request_pre_credentials_client::HttpRequestPreCredentialsClient;
use openshell_core::proto::middleware::v1::http_response_pre_return_client::HttpResponsePreReturnClient;
use openshell_core::proto::middleware::v1::supervisor_middleware_client::SupervisorMiddlewareClient;
use openshell_core::proto::{
    Decision, Finding, HttpBegin, HttpBodyLimits, HttpBodyMode, HttpBodyModeUnavailable,
    HttpBodyUnavailableReason, HttpBufferedBody, HttpEvent, HttpInspect, HttpPreflight,
    HttpRequestEvaluation, HttpRequestPreflightHead, HttpResponseBodyMode, HttpResponseBodyUnit,
    HttpResponseEvent, HttpResponseEventResult, HttpResponsePreflight, HttpResponsePreflightHead,
    HttpResponsePreflightResult, HttpResponseTrailers, HttpResult, MiddlewareDiagnostics,
    MiddlewareSessionEnd, http_buffered_result, http_event, http_inspect, http_preflight,
    http_preflight_result, http_response_body_result, http_response_body_transform,
    http_response_body_unit, http_response_event, http_response_event_result,
    http_response_preflight_result, http_result,
};
use prost_types::Struct;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use tonic::transport::server::TcpIncoming;
use tonic::{Code, Streaming};

use crate::guard::MAX_PAYLOAD_BYTES;
use crate::guard::test_support::config;
use crate::http_v2::Direction;
use crate::{PHASE, router};

/// Protocol-neutral result of one HTTP evaluation.
#[derive(Debug, PartialEq)]
enum Outcome {
    /// Version 2 only: the stage let the message continue without its body.
    Continued,
    Unchanged,
    Replaced(String),
    Denied,
    Failed(Code),
}

#[derive(Debug, Default, PartialEq)]
struct Diagnostics {
    reason: String,
    reason_code: String,
    findings: Vec<Finding>,
    metadata: HashMap<String, String>,
}

impl From<Option<MiddlewareDiagnostics>> for Diagnostics {
    fn from(diagnostics: Option<MiddlewareDiagnostics>) -> Self {
        let diagnostics = diagnostics.unwrap_or_default();
        Self {
            reason: diagnostics.reason,
            reason_code: diagnostics.reason_code,
            findings: diagnostics.findings,
            metadata: diagnostics.metadata,
        }
    }
}

#[derive(Debug, PartialEq)]
struct Observed {
    outcome: Outcome,
    diagnostics: Diagnostics,
}

impl Observed {
    fn failed(status: &tonic::Status) -> Self {
        Self {
            outcome: Outcome::Failed(status.code()),
            diagnostics: Diagnostics::default(),
        }
    }
}

async fn connect() -> Channel {
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().expect("loopback address"))
        .expect("bind loopback listener")
        .with_nodelay(Some(true));
    let address = incoming.local_addr().expect("listener address");
    tokio::spawn(router().serve_with_incoming(incoming));
    Channel::from_shared(format!("http://{address}"))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect to the content guard")
}

async fn next<T>(results: &mut Streaming<T>) -> Result<T, tonic::Status> {
    results
        .next()
        .await
        .expect("the service answers every event that requires a result")
}

async fn legacy_request(channel: &Channel, config: Struct, body: &[u8]) -> Observed {
    #[allow(deprecated)] // legacy-http-protocol-1
    let result = SupervisorMiddlewareClient::new(channel.clone())
        .evaluate_http_request(HttpRequestEvaluation {
            phase: PHASE as i32,
            config: Some(config),
            body: body.to_vec(),
            ..Default::default()
        })
        .await;
    let result = match result {
        Ok(result) => result.into_inner(),
        Err(status) => return Observed::failed(&status),
    };
    let outcome = match (Decision::try_from(result.decision), result.has_body) {
        (Ok(Decision::Allow), false) => Outcome::Unchanged,
        (Ok(Decision::Allow), true) => {
            Outcome::Replaced(String::from_utf8(result.body).expect("UTF-8 replacement"))
        }
        (Ok(Decision::Deny), false) => Outcome::Denied,
        other => panic!("unexpected legacy request result {other:?}"),
    };
    Observed {
        outcome,
        diagnostics: Diagnostics {
            reason: result.reason,
            reason_code: result.reason_code,
            findings: result.findings,
            metadata: result.metadata,
        },
    }
}

async fn legacy_response(
    channel: &Channel,
    config: Struct,
    permitted_body_modes: &[HttpResponseBodyMode],
    body: &[u8],
) -> Observed {
    let (events, receiver) = mpsc::channel(4);
    let send = |event| {
        let events = events.clone();
        async move {
            events
                .send(HttpResponseEvent { event: Some(event) })
                .await
                .expect("send response event");
        }
    };
    #[allow(deprecated)] // legacy-http-protocol-1
    let mut results = HttpResponsePreReturnClient::new(channel.clone())
        .evaluate(ReceiverStream::new(receiver))
        .await
        .expect("open legacy response stream")
        .into_inner();

    send(http_response_event::Event::Preflight(
        HttpResponsePreflight {
            status_code: 200,
            config: Some(config),
            permitted_body_modes: permitted_body_modes
                .iter()
                .map(|mode| *mode as i32)
                .collect(),
            ..Default::default()
        },
    ))
    .await;
    let preflight = match next(&mut results).await {
        Ok(result) => result.result,
        Err(status) => return Observed::failed(&status),
    };
    let Some(http_response_event_result::Result::PreflightResult(HttpResponsePreflightResult {
        action: Some(http_response_preflight_result::Action::Inspect(inspect)),
        ..
    })) = preflight
    else {
        panic!("unexpected legacy preflight result {preflight:?}");
    };
    assert_eq!(
        inspect.body_mode,
        HttpResponseBodyMode::WholeBodyBytes as i32
    );
    assert!(inspect.header_mutations.is_empty());

    send(http_response_event::Event::Body(HttpResponseBodyUnit {
        sequence: 1,
        payload: Some(http_response_body_unit::Payload::Data(body.to_vec())),
        end_of_stream: true,
    }))
    .await;
    let result = match next(&mut results).await {
        Ok(HttpResponseEventResult {
            result: Some(http_response_event_result::Result::BodyResult(result)),
        }) => result,
        Err(status) => return Observed::failed(&status),
        other => panic!("unexpected legacy body result {other:?}"),
    };

    send(http_response_event::Event::Trailers(
        HttpResponseTrailers::default(),
    ))
    .await;
    let Ok(HttpResponseEventResult {
        result: Some(http_response_event_result::Result::TrailersResult(trailers)),
    }) = next(&mut results).await
    else {
        panic!("expected a trailers result");
    };
    assert!(trailers.trailer_mutations.is_empty());
    send(http_response_event::Event::SessionEnd(
        MiddlewareSessionEnd::default(),
    ))
    .await;
    assert!(results.next().await.is_none());

    let outcome = match result.action {
        Some(http_response_body_result::Action::PassThrough(_)) => Outcome::Unchanged,
        Some(http_response_body_result::Action::Transform(transform)) => {
            let Some(http_response_body_transform::Replacement::Data(data)) = transform.replacement
            else {
                panic!("transform without replacement");
            };
            Outcome::Replaced(String::from_utf8(data).expect("UTF-8 replacement"))
        }
        Some(http_response_body_result::Action::BlockDelivery(_)) => Outcome::Denied,
        other => panic!("unexpected legacy body action {other:?}"),
    };
    Observed {
        outcome,
        diagnostics: Diagnostics {
            reason: result.reason,
            reason_code: result.reason_code,
            findings: result.findings,
            metadata: result.metadata,
        },
    }
}

/// Run one version 2 stage. `buffered_unavailable` is why the preflight does
/// not offer BUFFERED, when it does not.
async fn v2_stage(
    channel: &Channel,
    direction: Direction,
    config: Struct,
    permitted_body_modes: &[HttpBodyMode],
    buffered_unavailable: Option<HttpBodyUnavailableReason>,
    body: &[u8],
) -> Observed {
    let (events, receiver) = mpsc::channel(4);
    let send = |event| {
        let events = events.clone();
        async move {
            events
                .send(HttpEvent { event: Some(event) })
                .await
                .expect("send HTTP event");
        }
    };
    let receiver = ReceiverStream::new(receiver);
    let mut results = match direction {
        Direction::Request => {
            HttpRequestPreCredentialsClient::new(channel.clone())
                .evaluate_http(receiver)
                .await
        }
        Direction::Response => {
            HttpResponsePreReturnClient::new(channel.clone())
                .evaluate_http(receiver)
                .await
        }
    }
    .expect("open version 2 stage")
    .into_inner();

    let config = Some(config);
    send(http_event::Event::Preflight(HttpPreflight {
        head: Some(match direction {
            Direction::Request => http_preflight::Head::Request(HttpRequestPreflightHead {
                config,
                ..Default::default()
            }),
            Direction::Response => http_preflight::Head::Response(HttpResponsePreflightHead {
                status_code: 200,
                config,
                ..Default::default()
            }),
        }),
        permitted_body_modes: permitted_body_modes
            .iter()
            .map(|mode| *mode as i32)
            .collect(),
        late_header_modes: permitted_body_modes
            .iter()
            .map(|mode| *mode as i32)
            .collect(),
        limits: Some(HttpBodyLimits {
            max_buffered_body_bytes: MAX_PAYLOAD_BYTES,
            ..Default::default()
        }),
        unavailable_body_modes: buffered_unavailable
            .into_iter()
            .map(|reason| HttpBodyModeUnavailable {
                mode: HttpBodyMode::Buffered as i32,
                reason: reason as i32,
            })
            .collect(),
        ..Default::default()
    }))
    .await;
    let preflight = match next(&mut results).await {
        Ok(HttpResult {
            result: Some(http_result::Result::PreflightResult(preflight)),
        }) => preflight,
        Err(status) => return Observed::failed(&status),
        other => panic!("unexpected version 2 preflight result {other:?}"),
    };
    assert!(preflight.header_mutations.is_empty());
    match preflight.decision {
        Some(http_preflight_result::Decision::ContinueWithoutBody(_)) => {
            send(http_event::Event::SessionEnd(
                MiddlewareSessionEnd::default(),
            ))
            .await;
            assert!(results.next().await.is_none());
            return Observed {
                outcome: Outcome::Continued,
                diagnostics: preflight.diagnostics.into(),
            };
        }
        Some(http_preflight_result::Decision::Inspect(HttpInspect {
            mode: Some(http_inspect::Mode::Buffered(mode)),
        })) => assert_eq!(mode.max_body_bytes, MAX_PAYLOAD_BYTES),
        other => panic!("unexpected version 2 preflight decision {other:?}"),
    }

    send(http_event::Event::Begin(HttpBegin::default())).await;
    send(http_event::Event::BufferedBody(HttpBufferedBody {
        data: body.to_vec(),
        visible_trailers: Vec::new(),
    }))
    .await;
    let result = match next(&mut results).await {
        Ok(HttpResult {
            result: Some(result),
        }) => result,
        Err(status) => return Observed::failed(&status),
        other => panic!("unexpected version 2 body result {other:?}"),
    };
    send(http_event::Event::SessionEnd(
        MiddlewareSessionEnd::default(),
    ))
    .await;
    assert!(results.next().await.is_none());

    match result {
        http_result::Result::BufferedResult(result) => {
            assert!(result.header_mutations.is_empty());
            assert!(result.trailer_mutations.is_empty());
            Observed {
                outcome: match result.body {
                    Some(http_buffered_result::Body::Unchanged(_)) => Outcome::Unchanged,
                    Some(http_buffered_result::Body::Replacement(data)) => {
                        Outcome::Replaced(String::from_utf8(data).expect("UTF-8 replacement"))
                    }
                    None => panic!("buffered result without a body decision"),
                },
                diagnostics: result.diagnostics.into(),
            }
        }
        http_result::Result::Reject(reject) => Observed {
            outcome: Outcome::Denied,
            diagnostics: reject.diagnostics.into(),
        },
        other => panic!("unexpected version 2 body result {other:?}"),
    }
}

struct Case {
    name: &'static str,
    config: Struct,
    body: &'static [u8],
    /// Outcome under the legacy protocol, and under version 2 unless
    /// `version_2` is set.
    expected: Outcome,
    /// Version 2 outcome where it intentionally differs.
    version_2: Option<Outcome>,
}

impl Case {
    fn assert_version_2(&self, v2: &Observed, legacy: &Observed) {
        match &self.version_2 {
            None => assert_eq!(v2, legacy, "{}", self.name),
            Some(outcome) => {
                assert_eq!(&v2.outcome, outcome, "{}", self.name);
                assert_eq!(v2.diagnostics, Diagnostics::default(), "{}", self.name);
            }
        }
    }
}

fn cases() -> Vec<Case> {
    let terms = ["prototype-secret", "internal-only"];
    let redact = config("redact", &terms, Some("[FILTERED]"));
    let deny = config("deny", &terms, None);
    vec![
        Case {
            name: "redact passes clean bodies",
            config: redact.clone(),
            body: b"ordinary public text",
            expected: Outcome::Unchanged,
            version_2: None,
        },
        Case {
            name: "redact replaces every match",
            config: redact.clone(),
            body: b"contains prototype-secret and internal-only",
            expected: Outcome::Replaced("contains [FILTERED] and [FILTERED]".into()),
            version_2: None,
        },
        Case {
            name: "redact handles multibyte terms with the default replacement",
            config: config("redact", &["秘密"], None),
            body: "a 秘密 b".as_bytes(),
            expected: Outcome::Replaced("a [REDACTED] b".into()),
            version_2: None,
        },
        Case {
            name: "redact merges overlapping matches",
            config: config("redact", &["aba", "bab"], None),
            body: b"abab",
            expected: Outcome::Replaced("[REDACTED]".into()),
            version_2: None,
        },
        Case {
            name: "redact passes empty bodies",
            config: redact.clone(),
            body: b"",
            expected: Outcome::Unchanged,
            version_2: None,
        },
        Case {
            name: "deny rejects matches with content_match",
            config: deny.clone(),
            body: b"contains prototype-secret",
            expected: Outcome::Denied,
            version_2: None,
        },
        Case {
            name: "deny passes clean bodies",
            config: deny,
            body: b"ordinary public text",
            expected: Outcome::Unchanged,
            version_2: None,
        },
        Case {
            name: "non-UTF-8 bodies fail",
            config: redact,
            body: &[0xff, 0xfe],
            expected: Outcome::Failed(Code::InvalidArgument),
            // The guard cannot inspect the body.
            version_2: Some(Outcome::Failed(Code::FailedPrecondition)),
        },
        Case {
            name: "invalid configuration fails",
            config: config("block", &terms, None),
            body: b"ordinary public text",
            expected: Outcome::Failed(Code::InvalidArgument),
            version_2: None,
        },
    ]
}

fn assert_denial_diagnostics(observed: &Observed) {
    if observed.outcome == Outcome::Denied {
        assert_eq!(observed.diagnostics.reason_code, "content_match");
        assert!(!observed.diagnostics.reason.contains("prototype-secret"));
    }
}

#[tokio::test]
async fn requests_have_the_same_outcome_under_both_protocols() {
    let channel = connect().await;
    for case in cases() {
        let legacy = legacy_request(&channel, case.config.clone(), case.body).await;
        let v2 = v2_stage(
            &channel,
            Direction::Request,
            case.config.clone(),
            &[HttpBodyMode::Buffered],
            None,
            case.body,
        )
        .await;

        assert_eq!(legacy.outcome, case.expected, "{}", case.name);
        assert_denial_diagnostics(&legacy);
        case.assert_version_2(&v2, &legacy);
    }
}

#[tokio::test]
async fn responses_have_the_same_outcome_under_both_protocols() {
    let channel = connect().await;
    for case in cases() {
        let legacy = legacy_response(
            &channel,
            case.config.clone(),
            &[
                HttpResponseBodyMode::HeadersOnly,
                HttpResponseBodyMode::WholeBodyBytes,
                HttpResponseBodyMode::StreamBytes,
            ],
            case.body,
        )
        .await;
        let v2 = v2_stage(
            &channel,
            Direction::Response,
            case.config.clone(),
            &[HttpBodyMode::Buffered],
            None,
            case.body,
        )
        .await;

        assert_eq!(legacy.outcome, case.expected, "{}", case.name);
        assert_denial_diagnostics(&legacy);
        case.assert_version_2(&v2, &legacy);
    }
}

/// A response body the guard cannot see fails under both protocols, with
/// `FAILED_PRECONDITION`. The legacy policy's `on_error` then decides
/// delivery; OpenShell fails version 2 closed with `middleware_cannot_inspect`.
#[tokio::test]
async fn responses_without_a_complete_body_fail_under_both_protocols() {
    let channel = connect().await;
    let config = config("redact", &["prototype-secret"], None);

    let legacy = legacy_response(
        &channel,
        config.clone(),
        &[
            HttpResponseBodyMode::HeadersOnly,
            HttpResponseBodyMode::StreamBytes,
        ],
        b"prototype-secret",
    )
    .await;
    assert_eq!(legacy.outcome, Outcome::Failed(Code::FailedPrecondition));

    for reason in [
        HttpBodyUnavailableReason::Partial,
        HttpBodyUnavailableReason::NoTransform,
        HttpBodyUnavailableReason::Encoded,
        HttpBodyUnavailableReason::OverLimit,
        HttpBodyUnavailableReason::OpenEnded,
    ] {
        let v2 = v2_stage(
            &channel,
            Direction::Response,
            config.clone(),
            &[],
            Some(reason),
            b"prototype-secret",
        )
        .await;

        assert_eq!(v2, legacy, "{reason:?}");
    }
}

/// Version 2 says why a response has no body mode. A bodyless response, such
/// as the answer to HEAD or a 204 or 304, has nothing to guard, so the stage
/// continues. The legacy protocol does not say why, so a legacy response
/// without `WHOLE_BODY_BYTES` fails, and the policy's `on_error` decides
/// delivery.
#[tokio::test]
async fn bodyless_responses_continue_under_version_2_only() {
    let channel = connect().await;
    let config = config("deny", &["prototype-secret"], None);

    let legacy = legacy_response(
        &channel,
        config.clone(),
        &[HttpResponseBodyMode::HeadersOnly],
        b"",
    )
    .await;
    let v2 = v2_stage(
        &channel,
        Direction::Response,
        config,
        &[],
        Some(HttpBodyUnavailableReason::Bodyless),
        b"",
    )
    .await;

    assert_eq!(legacy.outcome, Outcome::Failed(Code::FailedPrecondition));
    assert_eq!(
        v2,
        Observed {
            outcome: Outcome::Continued,
            diagnostics: Diagnostics::default(),
        }
    );
}

/// A legacy request always carries the complete body, because OpenShell
/// resolves an over-limit request before it calls the service. A version 2
/// request whose body is over the stage's limit fails the same way responses
/// do.
#[tokio::test]
async fn version_2_requests_without_a_complete_body_fail() {
    let channel = connect().await;

    let v2 = v2_stage(
        &channel,
        Direction::Request,
        config("redact", &["prototype-secret"], None),
        &[],
        Some(HttpBodyUnavailableReason::OverLimit),
        b"prototype-secret",
    )
    .await;

    assert_eq!(v2.outcome, Outcome::Failed(Code::FailedPrecondition));
}
