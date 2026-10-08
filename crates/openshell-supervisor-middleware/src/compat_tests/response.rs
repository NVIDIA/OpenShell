// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Legacy `HttpResponsePreReturn.Evaluate` behavior over the v0.1.2 wire.

use std::time::Duration;

use openshell_supervisor_middleware_wire_fixture::proto::middleware::{
    ExistingHeaderAction, HttpResponseBodyMode, HttpResponseBodyResult, HttpResponseBodyUnit,
    HttpResponseEvent, HttpResponsePreflight, HttpResponsePreflightResult, HttpResponseTrailers,
    HttpResponseTrailersResult, MiddlewareSessionEndReason, http_response_body_unit,
    http_response_event,
};
use openshell_supervisor_middleware_wire_fixture::{
    LegacyMiddlewareFixture, LegacyRpc, Reply, RunningFixture, http_response_binding, results,
};
use tonic::Status;

use super::harness::{
    Engine, ResponseCase, ResponseStep, connect, entry, preflight_response, registration,
    run_response,
};
use crate::{
    ChainRunner, HttpResponseInvocationOutcome, MAX_CONCURRENT_MIDDLEWARE_SESSIONS, OnError,
};

const GUARD: &str = "legacy-response-guard";

type BodyScript = fn(&HttpResponseBodyUnit) -> Reply<HttpResponseBodyResult>;
const LIMIT: u64 = 64;
const END_TIMEOUT: Duration = Duration::from_secs(2);

async fn guard(fixture: LegacyMiddlewareFixture) -> (RunningFixture, ChainRunner) {
    let fixture = fixture
        .with_binding(http_response_binding(LIMIT))
        .spawn()
        .await
        .expect("spawn response fixture");
    let runner = connect(vec![registration(GUARD, &fixture, LIMIT)]).await;
    (fixture, runner)
}

fn inspect(mode: HttpResponseBodyMode) -> LegacyMiddlewareFixture {
    LegacyMiddlewareFixture::new("compat/response-guard")
        .on_response_preflight(move |_| results::preflight_inspect(mode, Vec::new()).into())
}

fn uppercase_units(unit: &HttpResponseBodyUnit) -> Reply<HttpResponseBodyResult> {
    let Some(http_response_body_unit::Payload::Data(data)) = unit.payload.as_ref() else {
        return Reply::Fail(Status::invalid_argument("body data required"));
    };
    if data.is_empty() {
        results::body_pass_through(unit.sequence).into()
    } else {
        results::body_transform(unit.sequence, data.to_ascii_uppercase()).into()
    }
}

fn chain(on_error: OnError) -> [crate::ChainEntry; 1] {
    [entry("response-guard", GUARD, 10, on_error)]
}

/// `(sequence, data, end_of_stream)` of every body unit the fixture received.
fn body_units(events: &[HttpResponseEvent]) -> Vec<(u64, Vec<u8>, bool)> {
    events
        .iter()
        .filter_map(|event| match &event.event {
            Some(http_response_event::Event::Body(unit)) => {
                let data = match &unit.payload {
                    Some(http_response_body_unit::Payload::Data(data)) => data.clone(),
                    None => Vec::new(),
                };
                Some((unit.sequence, data, unit.end_of_stream))
            }
            _ => None,
        })
        .collect()
}

fn trailer_events(events: &[HttpResponseEvent]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event.event, Some(http_response_event::Event::Trailers(_))))
        .count()
}

async fn session_end(fixture: &RunningFixture, index: usize) -> Option<MiddlewareSessionEndReason> {
    fixture
        .wait_for(END_TIMEOUT, |fixture| fixture.response_session_end(index))
        .await
}

/// Legacy stages keep the 0.1.x offers: `WHOLE_BODY_BYTES` needs an unknown or
/// in-limit length and a closed-ended media type, and `STREAM_BYTES` is offered
/// for any body-capable response. 0.1.x already withholds `WHOLE_BODY_BYTES`
/// from `text/event-stream`.
#[tokio::test]
async fn legacy_body_mode_offers_follow_0_1_x_eligibility() {
    const HEADERS_ONLY: i32 = HttpResponseBodyMode::HeadersOnly as i32;
    const WHOLE: i32 = HttpResponseBodyMode::WholeBodyBytes as i32;
    const STREAM: i32 = HttpResponseBodyMode::StreamBytes as i32;

    for engine in Engine::ALL {
        let (fixture, runner) = guard(LegacyMiddlewareFixture::new("compat/offers")).await;
        let cases = [
            (
                "known length within the limit",
                ResponseCase::ok("application/json", &[b"{\"ok\":1}"]).with_declared_length(),
                vec![HEADERS_ONLY, WHOLE, STREAM],
            ),
            (
                "known length over the limit",
                ResponseCase::ok("application/json", &[&[b'x'; 100]]).with_declared_length(),
                vec![HEADERS_ONLY, STREAM],
            ),
            (
                "unknown length",
                ResponseCase::ok("application/json", &[b"{}"]),
                vec![HEADERS_ONLY, WHOLE, STREAM],
            ),
            (
                "server-sent events",
                ResponseCase::ok("text/event-stream", &[b"data: one\n\n"]),
                vec![HEADERS_ONLY, STREAM],
            ),
            (
                "encoded body",
                ResponseCase::ok("application/json", &[b"{}"])
                    .with_header("content-encoding", "gzip"),
                vec![HEADERS_ONLY],
            ),
            (
                "no-transform",
                ResponseCase::ok("application/json", &[b"{}"])
                    .with_header("cache-control", "public, no-transform"),
                vec![HEADERS_ONLY],
            ),
            (
                "partial content",
                ResponseCase {
                    status: 206,
                    ..ResponseCase::ok("application/json", &[b"{}"])
                },
                vec![HEADERS_ONLY],
            ),
            (
                "HEAD request",
                ResponseCase {
                    method: "HEAD".into(),
                    ..ResponseCase::ok("application/json", &[])
                },
                vec![HEADERS_ONLY],
            ),
        ];

        for (index, (name, case, expected)) in cases.into_iter().enumerate() {
            let status = case.status;
            let observed =
                run_response(engine, &runner, &chain(OnError::FailClosed), case.clone()).await;
            assert!(observed.preflight_allowed(), "{engine:?} {name}");
            assert!(!observed.inspected, "{name}: skip leaves no session");
            assert_eq!(observed.body(), case.chunks.concat(), "{name}");
            assert_eq!(
                observed.invocations,
                vec![(
                    "response-guard".into(),
                    HttpResponseInvocationOutcome::Skip,
                    false
                )],
                "{name}"
            );

            let sessions = fixture.response_sessions();
            let Some(http_response_event::Event::Preflight(preflight)) =
                sessions[index][0].event.clone()
            else {
                panic!("{name}: the first event is preflight");
            };
            assert_eq!(preflight.permitted_body_modes, expected, "{name}");
            assert_eq!(preflight.status_code, u32::from(status), "{name}");
            assert_eq!(preflight.max_payload_bytes, LIMIT, "{name}");
            assert_eq!(preflight.middleware_name, GUARD, "{name}");
            assert_eq!(
                preflight.context.expect("context").request_id,
                "compat-request"
            );
            assert_eq!(
                session_end(&fixture, index).await,
                Some(MiddlewareSessionEndReason::StageSkipped),
                "{name}"
            );
        }
    }
}

#[tokio::test]
async fn headers_only_mutations_apply_before_commit() {
    for engine in Engine::ALL {
        let (fixture, runner) = guard(
            LegacyMiddlewareFixture::new("compat/headers").on_response_preflight(|_| {
                results::preflight_inspect(
                    HttpResponseBodyMode::HeadersOnly,
                    vec![
                        results::write_header(
                            "cache-control",
                            "private",
                            ExistingHeaderAction::Overwrite,
                        ),
                        results::remove_header("x-upstream-debug"),
                        results::write_header("x-guard", "seen", ExistingHeaderAction::Append),
                    ],
                )
                .into()
            }),
        )
        .await;
        let case = ResponseCase::ok("application/json", &[b"{\"a\":1}"])
            .with_header("cache-control", "public")
            .with_header("x-upstream-debug", "1")
            .with_declared_length();

        let observed = run_response(engine, &runner, &chain(OnError::FailClosed), case).await;
        assert!(observed.preflight_allowed());
        assert!(
            !observed.inspected,
            "HEADERS_ONLY ends the stage at preflight"
        );
        assert_eq!(observed.header("cache-control"), Some("private"));
        assert_eq!(observed.header("x-upstream-debug"), None);
        assert_eq!(observed.header("x-guard"), Some("seen"));
        assert_eq!(observed.header("content-length"), Some("7"));
        assert_eq!(observed.body(), b"{\"a\":1}");
        assert!(body_units(&fixture.response_sessions()[0]).is_empty());
        assert_eq!(
            session_end(&fixture, 0).await,
            Some(MiddlewareSessionEndReason::Normal)
        );
    }
}

#[tokio::test]
async fn whole_body_bytes_buffers_until_the_end_and_mutates_trailers() {
    for engine in Engine::ALL {
        let (fixture, runner) = guard(
            inspect(HttpResponseBodyMode::WholeBodyBytes)
                .on_response_body(uppercase_units)
                .on_response_trailers(|trailers| {
                    assert_eq!(trailers.headers.len(), 1);
                    results::trailers_mutated(vec![results::write_header(
                        "x-checksum",
                        "rewritten",
                        ExistingHeaderAction::Overwrite,
                    )])
                    .into()
                }),
        )
        .await;
        let case = ResponseCase::ok("text/plain", &[b"hello ", b"world"])
            .with_header("etag", "\"upstream\"")
            .with_trailer("x-checksum", "upstream");

        let observed = run_response(engine, &runner, &chain(OnError::FailClosed), case).await;
        assert!(
            observed.failure.is_none(),
            "{engine:?}: {:?}",
            observed.failure
        );
        assert!(observed.inspected);
        assert_eq!(
            observed.released,
            vec![Vec::<u8>::new(), Vec::new()],
            "WHOLE_BODY_BYTES withholds every chunk until the body ends"
        );
        assert_eq!(observed.finished, b"HELLO WORLD");
        assert!(observed.strip_stale_integrity_headers);
        assert_eq!(
            observed.trailers,
            vec![("x-checksum".to_string(), "rewritten".to_string())]
        );

        let events = &fixture.response_sessions()[0];
        assert_eq!(
            body_units(events),
            vec![(1, b"hello world".to_vec(), true)],
            "one complete unit with end_of_stream"
        );
        assert_eq!(trailer_events(events), 1);
        assert_eq!(
            session_end(&fixture, 0).await,
            Some(MiddlewareSessionEndReason::Normal)
        );
    }
}

#[tokio::test]
async fn whole_body_overflow_follows_on_error() {
    for engine in Engine::ALL {
        let (fixture, runner) =
            guard(inspect(HttpResponseBodyMode::WholeBodyBytes).on_response_body(uppercase_units))
                .await;
        let oversized = vec![b'a'; usize::try_from(LIMIT).unwrap() + 1];
        let case = ResponseCase::ok("text/plain", &[&oversized]);

        let open = run_response(engine, &runner, &chain(OnError::FailOpen), case.clone()).await;
        assert!(open.failure.is_none(), "{engine:?}: {:?}", open.failure);
        assert_eq!(
            open.body(),
            oversized,
            "fail_open releases the original body"
        );
        assert!(open.invocations.iter().any(|(_, outcome, failed)| {
            *outcome == HttpResponseInvocationOutcome::FailOpen && *failed
        }));

        let closed = run_response(engine, &runner, &chain(OnError::FailClosed), case).await;
        let failure = closed.failure.expect("fail_closed stops delivery");
        assert_eq!(failure.step, ResponseStep::Chunk(0));
        assert_eq!(
            failure.reason,
            "middleware_failed: whole_body_over_capacity"
        );
        assert!(body_units(&fixture.response_sessions()[1]).is_empty());
    }
}

/// Server-sent events through `STREAM_BYTES`: every upstream read is released
/// before the next one is processed, and the body ends with an empty final
/// unit followed by trailers.
#[tokio::test]
async fn stream_bytes_releases_each_unit_as_it_arrives() {
    for engine in Engine::ALL {
        let (fixture, runner) =
            guard(inspect(HttpResponseBodyMode::StreamBytes).on_response_body(uppercase_units))
                .await;
        let events: [&[u8]; 3] = [b"data: one\n\n", b"data: two\n\n", b"data: three\n\n"];
        let case = ResponseCase::ok("text/event-stream", &events).with_header("etag", "\"v1\"");

        let observed = run_response(engine, &runner, &chain(OnError::FailClosed), case).await;
        assert!(
            observed.failure.is_none(),
            "{engine:?}: {:?}",
            observed.failure
        );
        assert_eq!(
            observed.header("etag"),
            None,
            "STREAM_BYTES strips stale validators"
        );
        assert_eq!(
            observed.released,
            events
                .iter()
                .map(|event| event.to_ascii_uppercase())
                .collect::<Vec<_>>()
        );
        assert!(observed.finished.is_empty());

        let recorded = &fixture.response_sessions()[0];
        assert_eq!(
            body_units(recorded),
            vec![
                (1, events[0].to_vec(), false),
                (2, events[1].to_vec(), false),
                (3, events[2].to_vec(), false),
                (4, Vec::new(), true),
            ]
        );
        assert_eq!(trailer_events(recorded), 1);
        assert_eq!(
            session_end(&fixture, 0).await,
            Some(MiddlewareSessionEndReason::Normal)
        );
    }
}

#[tokio::test]
async fn stream_bytes_skip_remaining_passes_the_rest_through_locally() {
    for engine in Engine::ALL {
        let (fixture, runner) = guard(inspect(HttpResponseBodyMode::StreamBytes).on_response_body(
            |unit| {
                if unit.sequence == 2 {
                    results::body_skip_remaining(unit.sequence, Some(b"LAST-INSPECTED".to_vec()))
                        .into()
                } else {
                    uppercase_units(unit)
                }
            },
        ))
        .await;
        let case = ResponseCase::ok("text/plain", &[b"one", b"two", b"three"]);

        let observed = run_response(engine, &runner, &chain(OnError::FailClosed), case).await;
        assert!(
            observed.failure.is_none(),
            "{engine:?}: {:?}",
            observed.failure
        );
        assert_eq!(
            observed.released,
            vec![
                b"ONE".to_vec(),
                b"LAST-INSPECTED".to_vec(),
                b"three".to_vec()
            ]
        );
        let recorded = &fixture.response_sessions()[0];
        assert_eq!(
            body_units(recorded)
                .iter()
                .map(|(sequence, _, _)| *sequence)
                .collect::<Vec<_>>(),
            [1, 2],
            "the stage receives nothing after skip_remaining"
        );
        assert_eq!(trailer_events(recorded), 0);
        assert_eq!(
            session_end(&fixture, 0).await,
            Some(MiddlewareSessionEndReason::Normal)
        );
    }
}

/// `BLOCK_DELIVERY` stops delivery regardless of `on_error`. Before commit the
/// relay answers with the canonical 403; during `STREAM_BYTES` the head is
/// already committed, so the relay aborts.
#[tokio::test]
async fn block_delivery_stops_delivery_at_the_step_that_blocked() {
    for engine in Engine::ALL {
        let (preflight_fixture, preflight_runner) = guard(
            LegacyMiddlewareFixture::new("compat/block-preflight")
                .on_response_preflight(|_| results::preflight_block("content_match").into()),
        )
        .await;
        let observed = run_response(
            engine,
            &preflight_runner,
            &chain(OnError::FailOpen),
            ResponseCase::ok("text/plain", &[b"secret"]),
        )
        .await;
        assert!(!observed.preflight_allowed());
        let failure = observed.failure.expect("preflight block");
        assert_eq!(failure.step, ResponseStep::Preflight);
        assert_eq!(
            failure.reason,
            "middleware_denied:response-guard:content_match"
        );
        assert_eq!(
            failure.denial.and_then(|denial| denial.reason_code),
            Some("content_match".into())
        );
        assert_eq!(
            session_end(&preflight_fixture, 0).await,
            Some(MiddlewareSessionEndReason::MiddlewareDenial)
        );

        let (stream_fixture, stream_runner) = guard(
            inspect(HttpResponseBodyMode::StreamBytes).on_response_body(|unit| {
                if unit.sequence == 2 {
                    results::body_block(unit.sequence, "content_match").into()
                } else {
                    results::body_pass_through(unit.sequence).into()
                }
            }),
        )
        .await;
        let observed = run_response(
            engine,
            &stream_runner,
            &chain(OnError::FailOpen),
            ResponseCase::ok("text/plain", &[b"first", b"secret", b"never"]),
        )
        .await;
        let failure = observed.failure.expect("stream block");
        assert_eq!(failure.step, ResponseStep::Chunk(1));
        assert_eq!(
            failure.denial.and_then(|denial| denial.reason_code),
            Some("content_match".into())
        );
        assert_eq!(
            observed.released,
            vec![b"first".to_vec(), Vec::new()],
            "units before the block were already released"
        );
        assert_eq!(
            session_end(&stream_fixture, 0).await,
            Some(MiddlewareSessionEndReason::MiddlewareDenial)
        );

        let (_whole_fixture, whole_runner) = guard(
            inspect(HttpResponseBodyMode::WholeBodyBytes).on_response_body(|unit| {
                results::body_block(unit.sequence, "content_match").into()
            }),
        )
        .await;
        let observed = run_response(
            engine,
            &whole_runner,
            &chain(OnError::FailOpen),
            ResponseCase::ok("text/plain", &[b"secret"]),
        )
        .await;
        assert!(observed.body().is_empty());
        let failure = observed.failure.expect("whole-body block");
        assert_eq!(failure.step, ResponseStep::Finish, "blocked before commit");
        assert!(failure.denial.is_some());
    }
}

/// A stream stage that fails mid-body under `fail_open` releases the unit it
/// was given unchanged and is bypassed for the rest of the response.
#[tokio::test]
async fn stream_failure_mid_body_follows_on_error() {
    struct StreamFailure {
        name: &'static str,
        script: BodyScript,
        fail_closed_reason: &'static str,
        /// The service keeps reading after the failure, so the fixture shows
        /// whether the stage was sent later units.
        service_keeps_reading: bool,
    }
    let failures = [
        StreamFailure {
            name: "grpc error status",
            script: |unit| {
                if unit.sequence == 2 {
                    Reply::Fail(Status::internal("guard crashed"))
                } else {
                    uppercase_units(unit)
                }
            },
            fail_closed_reason: "middleware_failed: external_service_error",
            service_keeps_reading: false,
        },
        StreamFailure {
            name: "unit slower than the registration timeout",
            script: |unit| {
                let reply = uppercase_units(unit);
                if unit.sequence == 2 {
                    reply.after(Duration::from_secs(2))
                } else {
                    reply
                }
            },
            fail_closed_reason: "middleware_failed: middleware_timeout",
            service_keeps_reading: true,
        },
    ];
    for engine in Engine::ALL {
        for failure in &failures {
            let name = failure.name;
            let (fixture, runner) =
                guard(inspect(HttpResponseBodyMode::StreamBytes).on_response_body(failure.script))
                    .await;
            let case = ResponseCase::ok("text/event-stream", &[b"one", b"two", b"three"])
                .with_trailer("x-trailer", "kept");

            let open = run_response(engine, &runner, &chain(OnError::FailOpen), case.clone()).await;
            assert!(
                open.failure.is_none(),
                "{engine:?} {name}: {:?}",
                open.failure
            );
            assert_eq!(
                open.released,
                vec![b"ONE".to_vec(), b"two".to_vec(), b"three".to_vec()],
                "{name}"
            );
            assert_eq!(
                open.trailers,
                vec![("x-trailer".to_string(), "kept".to_string())],
                "{name}"
            );
            assert_eq!(
                open.invocations,
                [
                    HttpResponseInvocationOutcome::Stream,
                    HttpResponseInvocationOutcome::Transform,
                    HttpResponseInvocationOutcome::FailOpen,
                ]
                .into_iter()
                .enumerate()
                .map(|(index, outcome)| ("response-guard".to_string(), outcome, index == 2))
                .collect::<Vec<_>>(),
                "{name}: the failed stage is not invoked again"
            );
            if failure.service_keeps_reading {
                assert_eq!(
                    body_units(&fixture.response_sessions()[0]).len(),
                    2,
                    "{name}: the failed stage receives no later units"
                );
            }

            let closed = run_response(engine, &runner, &chain(OnError::FailClosed), case).await;
            let stop = closed.failure.expect("fail_closed stops delivery");
            assert_eq!(stop.step, ResponseStep::Chunk(1), "{name}");
            assert_eq!(stop.reason, failure.fail_closed_reason, "{name}");
            assert!(stop.denial.is_none(), "{name}");
            assert_eq!(closed.released, vec![b"ONE".to_vec(), Vec::new()], "{name}");
        }
    }
}

/// 0.1.x delivered the response uninspected when the stream answered
/// `UNIMPLEMENTED` under `fail_open`. That contract failure now fails closed
/// regardless of `on_error` and asks the supervisor to describe its services
/// again.
#[tokio::test]
async fn unimplemented_response_stream_fails_closed_regardless_of_on_error() {
    for engine in Engine::ALL {
        for remove_service in [false, true] {
            let fixture = inspect(HttpResponseBodyMode::StreamBytes);
            let fixture = if remove_service {
                fixture.without_response_service()
            } else {
                fixture
            };
            let (fixture, runner) = guard(fixture).await;
            fixture.set_unimplemented(LegacyRpc::HttpResponsePreReturn, true);
            let describes = fixture.describe_requests().len();
            let case = ResponseCase::ok("text/plain", &[b"uninspected"]);

            for on_error in [OnError::FailOpen, OnError::FailClosed] {
                let observation =
                    run_response(engine, &runner, &chain(on_error), case.clone()).await;
                assert!(
                    !observation.preflight_allowed(),
                    "{engine:?} remove={remove_service} {on_error:?}"
                );
                assert!(!observation.inspected);
                assert_eq!(
                    observation.invocations,
                    vec![(
                        "response-guard".into(),
                        HttpResponseInvocationOutcome::FailClosed,
                        true
                    )]
                );
                let failure = observation
                    .failure
                    .expect("a contract failure refuses delivery");
                assert_eq!(failure.step, ResponseStep::Preflight);
                assert_eq!(
                    failure.reason,
                    "middleware_failed: middleware_contract_failure_unimplemented"
                );
                assert!(runner.take_reconciliation_request(), "{on_error:?}");
            }
            assert_eq!(fixture.describe_requests().len(), describes);
            assert!(fixture.response_sessions().is_empty());
        }
    }
}

/// Inspected responses hold one of the supervisor's session permits for their
/// lifetime. When every permit is held, the next inspected response follows
/// `on_error` without contacting the service.
#[tokio::test]
async fn session_permits_cap_concurrent_inspected_responses() {
    for engine in Engine::ALL {
        let (fixture, runner) =
            guard(inspect(HttpResponseBodyMode::StreamBytes).on_response_body(uppercase_units))
                .await;
        let case = ResponseCase::ok("text/event-stream", &[b"data: held\n\n"]);

        let mut held = Vec::new();
        for _ in 0..MAX_CONCURRENT_MIDDLEWARE_SESSIONS {
            let (observation, session) =
                preflight_response(engine, &runner, &chain(OnError::FailClosed), &case).await;
            assert!(observation.inspected);
            held.push(session);
        }

        let (closed, _) =
            preflight_response(engine, &runner, &chain(OnError::FailClosed), &case).await;
        assert!(!closed.preflight_allowed());
        assert!(closed.session_capacity_exhausted);
        assert_eq!(
            closed.failure.expect("capacity failure").reason,
            "middleware_failed: middleware_session_capacity_exhausted"
        );

        let (open, _) = preflight_response(engine, &runner, &chain(OnError::FailOpen), &case).await;
        assert!(open.preflight_allowed());
        assert!(open.session_capacity_exhausted);
        assert!(!open.inspected);
        assert_eq!(
            fixture.response_sessions().len(),
            MAX_CONCURRENT_MIDDLEWARE_SESSIONS,
            "an exhausted budget never opens a stream"
        );

        held.pop().expect("held session").end().await;
        let (recovered, session) =
            preflight_response(engine, &runner, &chain(OnError::FailClosed), &case).await;
        assert!(recovered.inspected, "ending a session frees its permit");
        session.end().await;
        for session in held {
            session.end().await;
        }
    }
}

type PreflightScript = fn(&HttpResponsePreflight) -> Reply<HttpResponsePreflightResult>;
type TrailersScript = fn(&HttpResponseTrailers) -> Reply<HttpResponseTrailersResult>;

/// A semantically invalid legacy result and the step and reason 0.1.x reports
/// for it. Legacy stages keep `on_error` handling for semantic violations, so
/// the adapters must report the same outcomes.
struct Violation {
    name: &'static str,
    preflight: PreflightScript,
    body: BodyScript,
    trailers: TrailersScript,
    step: ResponseStep,
    reason: &'static str,
}

fn inspect_stream(_: &HttpResponsePreflight) -> Reply<HttpResponsePreflightResult> {
    results::preflight_inspect(HttpResponseBodyMode::StreamBytes, Vec::new()).into()
}

fn pass_through(unit: &HttpResponseBodyUnit) -> Reply<HttpResponseBodyResult> {
    results::body_pass_through(unit.sequence).into()
}

fn keep_trailers(_: &HttpResponseTrailers) -> Reply<HttpResponseTrailersResult> {
    results::trailers_unchanged().into()
}

const VIOLATIONS: [Violation; 8] = [
    Violation {
        name: "result for another sequence",
        preflight: inspect_stream,
        body: |unit| results::body_pass_through(unit.sequence + 1).into(),
        trailers: keep_trailers,
        step: ResponseStep::Chunk(0),
        reason: "middleware_failed: response_body_sequence_mismatch",
    },
    Violation {
        name: "replacement over the binding limit",
        preflight: inspect_stream,
        body: |unit| results::body_transform(unit.sequence, vec![b'x'; 65]).into(),
        trailers: keep_trailers,
        step: ResponseStep::Chunk(0),
        reason: "middleware_failed: response_body_replacement_over_capacity",
    },
    Violation {
        name: "body result without an action",
        preflight: inspect_stream,
        body: |unit| {
            HttpResponseBodyResult {
                sequence: unit.sequence,
                ..Default::default()
            }
            .into()
        },
        trailers: keep_trailers,
        step: ResponseStep::Chunk(0),
        reason: "middleware_failed: invalid_response_body_decision",
    },
    Violation {
        name: "oversized diagnostic reason",
        preflight: inspect_stream,
        body: |unit| {
            HttpResponseBodyResult {
                reason: "r".repeat(4097),
                ..results::body_pass_through(unit.sequence)
            }
            .into()
        },
        trailers: keep_trailers,
        step: ResponseStep::Chunk(0),
        reason: "middleware_failed: response_reason_over_capacity",
    },
    Violation {
        name: "mode that was not offered",
        preflight: |_| {
            results::preflight_inspect(HttpResponseBodyMode::WholeBodyBytes, Vec::new()).into()
        },
        body: pass_through,
        trailers: keep_trailers,
        step: ResponseStep::Preflight,
        reason: "middleware_failed: response_body_mode_not_permitted",
    },
    Violation {
        name: "preflight result without an action",
        preflight: |_| HttpResponsePreflightResult::default().into(),
        body: pass_through,
        trailers: keep_trailers,
        step: ResponseStep::Preflight,
        reason: "middleware_failed: invalid_preflight_decision",
    },
    Violation {
        name: "protected response header mutation",
        preflight: |_| {
            results::preflight_inspect(
                HttpResponseBodyMode::HeadersOnly,
                vec![results::write_header(
                    "content-length",
                    "1",
                    ExistingHeaderAction::Overwrite,
                )],
            )
            .into()
        },
        body: pass_through,
        trailers: keep_trailers,
        step: ResponseStep::Preflight,
        reason: "middleware_failed: header_mutation_protected_header",
    },
    Violation {
        name: "trailer write to an absent name",
        preflight: inspect_stream,
        body: pass_through,
        trailers: |_| {
            results::trailers_mutated(vec![results::write_header(
                "x-absent",
                "new",
                ExistingHeaderAction::Overwrite,
            )])
            .into()
        },
        step: ResponseStep::Finish,
        reason: "middleware_failed: trailer_mutation_absent_name",
    },
];

#[tokio::test]
async fn semantic_violations_follow_on_error() {
    for engine in Engine::ALL {
        for violation in &VIOLATIONS {
            let (_fixture, runner) = guard(
                LegacyMiddlewareFixture::new("compat/violations")
                    .on_response_preflight(violation.preflight)
                    .on_response_body(violation.body)
                    .on_response_trailers(violation.trailers),
            )
            .await;
            let case = ResponseCase::ok("text/event-stream", &[b"data: one\n\n"])
                .with_trailer("x-trailer", "kept");
            let name = violation.name;

            let open = run_response(engine, &runner, &chain(OnError::FailOpen), case.clone()).await;
            assert!(
                open.failure.is_none(),
                "{engine:?} {name}: {:?}",
                open.failure
            );
            assert_eq!(open.body(), b"data: one\n\n", "{name}");
            assert_eq!(
                open.header("content-type"),
                Some("text/event-stream"),
                "{name}"
            );
            assert_eq!(
                open.trailers,
                vec![("x-trailer".to_string(), "kept".to_string())],
                "{name}"
            );
            assert!(
                open.invocations.iter().any(|(_, outcome, failed)| {
                    *outcome == HttpResponseInvocationOutcome::FailOpen && *failed
                }),
                "{name}: {:?}",
                open.invocations
            );

            let closed = run_response(engine, &runner, &chain(OnError::FailClosed), case).await;
            let failure = closed.failure.expect("fail_closed stops delivery");
            assert_eq!(failure.step, violation.step, "{name}");
            assert_eq!(failure.reason, violation.reason, "{name}");
            assert!(failure.denial.is_none(), "{name}");
        }
    }
}

/// Stages run in policy order across services. A later `WHOLE_BODY_BYTES`
/// stage withholds every byte until the body ends and receives the earlier
/// stream stage's output as one unit.
#[tokio::test]
async fn mixed_stream_and_whole_body_chain_runs_in_policy_order() {
    for engine in Engine::ALL {
        let stream = inspect(HttpResponseBodyMode::StreamBytes)
            .on_response_body(uppercase_units)
            .with_binding(http_response_binding(LIMIT))
            .spawn()
            .await
            .expect("spawn stream fixture");
        let whole = inspect(HttpResponseBodyMode::WholeBodyBytes)
            .on_response_body(|unit| {
                let Some(http_response_body_unit::Payload::Data(data)) = unit.payload.as_ref()
                else {
                    return Reply::Fail(Status::invalid_argument("body data required"));
                };
                let mut wrapped = b"[".to_vec();
                wrapped.extend_from_slice(data);
                wrapped.push(b']');
                results::body_transform(unit.sequence, wrapped).into()
            })
            .with_binding(http_response_binding(LIMIT))
            .spawn()
            .await
            .expect("spawn whole-body fixture");
        let runner = connect(vec![
            registration("legacy-stream", &stream, LIMIT),
            registration("legacy-whole", &whole, LIMIT),
        ])
        .await;
        let chain = [
            entry("whole", "legacy-whole", 20, OnError::FailClosed),
            entry("stream", "legacy-stream", 10, OnError::FailClosed),
        ];

        let observed = run_response(
            engine,
            &runner,
            &chain,
            ResponseCase::ok("text/plain", &[b"one ", b"two"]),
        )
        .await;
        assert!(
            observed.failure.is_none(),
            "{engine:?}: {:?}",
            observed.failure
        );
        assert_eq!(observed.released, vec![Vec::<u8>::new(), Vec::new()]);
        assert_eq!(observed.finished, b"[ONE TWO]");
        assert_eq!(
            body_units(&whole.response_sessions()[0]),
            vec![(1, b"ONE TWO".to_vec(), true)]
        );
        assert_eq!(
            body_units(&stream.response_sessions()[0])
                .iter()
                .map(|(sequence, _, end)| (*sequence, *end))
                .collect::<Vec<_>>(),
            [(1, false), (2, false), (3, true)]
        );
    }
}
