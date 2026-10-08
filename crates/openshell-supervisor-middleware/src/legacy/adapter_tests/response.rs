// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `HttpResponsePreReturn.Evaluate` through [`LegacyResponseStage`],
//! mirroring `crate::compat_tests::response`.

use std::sync::Arc;
use std::time::Duration;

use prost::Message as _;

use openshell_core::proto::{
    Finding, HeaderMutation, HttpBegin, HttpBodyLimits, HttpBodyMode, HttpBufferedBody,
    HttpBufferedMode, HttpBufferedResult, HttpHeader, HttpInputChunk, HttpInputEnd, HttpInspect,
    HttpPreflight, HttpResponsePreflightHead, MiddlewareSessionEndReason, RemoveHeader,
    header_mutation, http_buffered_result, http_event, http_inspect, http_preflight,
    http_preflight_result, http_result,
};
use openshell_supervisor_middleware_wire_fixture::proto::middleware::{
    ExistingHeaderAction, Finding as LegacyFinding, HttpResponseBodyMode, HttpResponseBodyResult,
    HttpResponseBodyUnit, HttpResponseEvent, HttpResponsePreflight, HttpResponsePreflightResult,
    HttpResponseTrailers, HttpResponseTrailersResult,
    MiddlewareSessionEndReason as LegacyEndReason, http_response_body_unit, http_response_event,
};
use openshell_supervisor_middleware_wire_fixture::{
    LegacyMiddlewareFixture, LegacyRpc, Reply, RunningFixture, http_response_binding, results,
};
use tonic::Status;

use super::{
    Out, StageDriver, connect, context, entry, fail_open_reasons, headers, registration,
    reports_for, target, transcode,
};
use crate::legacy::response::adapter::{LegacyResponseExchange, LegacyResponseStage};
use crate::{
    ChainEntry, ChainRunner, ContractFailureKind, DescribedChainEntry, HttpResponseInvocation,
    HttpResponseInvocationOutcome, HttpResponsePreflightInput, MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES,
    OnError, StageReport, StageReports, headers as header_rules,
};

const GUARD: &str = "legacy-response-guard";
const LIMIT: u64 = 64;
const SESSION_END_TIMEOUT: Duration = Duration::from_secs(2);

type BodyScript = fn(&HttpResponseBodyUnit) -> Reply<HttpResponseBodyResult>;
type PreflightScript = fn(&HttpResponsePreflight) -> Reply<HttpResponsePreflightResult>;
type TrailersScript = fn(&HttpResponseTrailers) -> Reply<HttpResponseTrailersResult>;

/// One upstream response, as the relay hands it to the pipeline.
#[derive(Debug, Clone)]
struct ResponseCase {
    method: String,
    status: u16,
    headers: Vec<HttpHeader>,
    declared: Option<u64>,
    chunks: Vec<Vec<u8>>,
    trailers: Vec<HttpHeader>,
}

impl ResponseCase {
    fn ok(content_type: &str, chunks: &[&[u8]]) -> Self {
        Self {
            method: "GET".into(),
            status: 200,
            headers: headers(&[("content-type", content_type)]),
            declared: None,
            chunks: chunks.iter().map(|chunk| chunk.to_vec()).collect(),
            trailers: Vec::new(),
        }
    }

    fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.extend(headers(&[(name, value)]));
        self
    }

    fn with_trailer(mut self, name: &str, value: &str) -> Self {
        self.trailers.extend(headers(&[(name, value)]));
        self
    }

    fn with_declared_length(mut self) -> Self {
        let length = self.chunks.iter().map(Vec::len).sum::<usize>();
        self.declared = Some(length as u64);
        self.headers
            .extend(headers(&[("content-length", &length.to_string())]));
        self
    }

    fn original(&self) -> HttpResponsePreflightInput {
        HttpResponsePreflightInput {
            context: context(),
            target: target(&self.method, "/v1/stream", ""),
            status_code: self.status,
            declared_body_length: self.declared,
            headers: self.headers.clone(),
            connection_nominated_headers: Vec::new(),
        }
    }

    /// The preflight the pipeline sends a legacy response stage. Legacy
    /// stages are offered both body modes, and the adapter applies 0.1.x
    /// eligibility on its own.
    fn preflight(&self, entry: &DescribedChainEntry, head: &[HttpHeader]) -> HttpPreflight {
        let limit = entry.max_payload_bytes() as u64;
        let modes = vec![HttpBodyMode::Buffered as i32, HttpBodyMode::Stream as i32];
        HttpPreflight {
            head: Some(http_preflight::Head::Response(HttpResponsePreflightHead {
                context: Some(context()),
                target: Some(target(&self.method, "/v1/stream", "")),
                status_code: u32::from(self.status),
                headers: head.to_vec(),
                middleware_name: entry.entry.implementation.clone(),
                config: Some(entry.entry.config.clone()),
            })),
            permitted_body_modes: modes.clone(),
            late_header_modes: modes,
            limits: Some(HttpBodyLimits {
                max_chunk_bytes: limit.min(MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES as u64),
                max_buffered_body_bytes: limit,
                ..Default::default()
            }),
            declared_input_bytes: self.declared,
        }
    }
}

/// Everything one stage makes observable to the pipeline.
#[derive(Debug)]
struct Drive {
    preflight: Out,
    /// Results after preflight, up to the terminal one.
    body: Vec<Out>,
    reports: Vec<StageReport>,
}

impl Drive {
    fn decision(&self) -> Option<&http_preflight_result::Decision> {
        match &self.preflight {
            Out::Result(http_result::Result::PreflightResult(result)) => result.decision.as_ref(),
            _ => None,
        }
    }

    fn continued(&self) -> bool {
        matches!(
            self.decision(),
            Some(http_preflight_result::Decision::ContinueWithoutBody(_))
        )
    }

    fn preflight_mutations(&self) -> Vec<HeaderMutation> {
        match &self.preflight {
            Out::Result(http_result::Result::PreflightResult(result)) => {
                result.header_mutations.clone()
            }
            other => panic!("preflight result expected: {other:?}"),
        }
    }

    /// Output chunks, in order.
    fn released(&self) -> Vec<Vec<u8>> {
        self.body
            .iter()
            .filter_map(|out| match out {
                Out::Result(http_result::Result::OutputChunk(chunk)) => Some(chunk.data.clone()),
                _ => None,
            })
            .collect()
    }

    fn terminal(&self) -> &Out {
        self.body.last().unwrap_or(&self.preflight)
    }

    fn buffered(&self) -> &HttpBufferedResult {
        match self.terminal() {
            Out::Result(http_result::Result::BufferedResult(result)) => result,
            other => panic!("buffered result expected: {other:?}"),
        }
    }

    fn finish_trailer_mutations(&self) -> Vec<HeaderMutation> {
        match self.terminal() {
            Out::Result(http_result::Result::Finish(finish)) => finish.trailer_mutations.clone(),
            other => panic!("finish expected: {other:?}"),
        }
    }

    fn reject_code(&self) -> Option<String> {
        match self.terminal() {
            Out::Result(http_result::Result::Reject(reject)) => {
                Some(reject.diagnostics.clone().unwrap_or_default().reason_code)
            }
            _ => None,
        }
    }

    fn invocations(&self) -> Vec<HttpResponseInvocation> {
        invocations(&self.reports)
    }

    /// Findings reported with every step, in order.
    fn findings(&self) -> Vec<Finding> {
        self.reports
            .iter()
            .flat_map(|report| match report {
                StageReport::LegacyResponseInvocation { findings, .. } => findings.clone(),
                StageReport::LegacyFailOpen { .. } => Vec::new(),
            })
            .collect()
    }

    /// Diagnostics on any version 2 result. Legacy stages report theirs with
    /// their invocation records instead.
    fn result_diagnostics(&self) -> Vec<openshell_core::proto::MiddlewareDiagnostics> {
        std::iter::once(&self.preflight)
            .chain(&self.body)
            .filter_map(|out| match out {
                Out::Result(http_result::Result::PreflightResult(result)) => {
                    result.diagnostics.clone()
                }
                Out::Result(http_result::Result::BufferedResult(result)) => {
                    result.diagnostics.clone()
                }
                Out::Result(http_result::Result::Finish(finish)) => finish.diagnostics.clone(),
                _ => None,
            })
            .collect()
    }

    fn outcomes(&self) -> Vec<(HttpResponseInvocationOutcome, bool)> {
        self.invocations()
            .iter()
            .map(|invocation| (invocation.outcome, invocation.failed))
            .collect()
    }
}

fn invocations(reports: &[StageReport]) -> Vec<HttpResponseInvocation> {
    reports
        .iter()
        .filter_map(|report| match report {
            StageReport::LegacyResponseInvocation { invocation, .. } => Some(invocation.clone()),
            StageReport::LegacyFailOpen { .. } => None,
        })
        .collect()
}

fn stage_for(
    described: &DescribedChainEntry,
    case: &ResponseCase,
    reports: &Arc<StageReports>,
) -> LegacyResponseStage {
    LegacyResponseStage::new(
        described,
        LegacyResponseExchange {
            reports: reports.clone(),
            original: Arc::new(case.original()),
        },
    )
    .expect("legacy response entry")
}

async fn describe(runner: &ChainRunner, chain: &[ChainEntry]) -> Vec<DescribedChainEntry> {
    runner
        .describe_http_response_chain(chain)
        .await
        .expect("describe response chain")
}

/// Every result until the stream ends or a terminal result arrives.
async fn results_until_terminal(driver: &mut StageDriver) -> Vec<Out> {
    let mut results = Vec::new();
    while let Some(result) = driver.next().await {
        let terminal = !matches!(
            result,
            Out::Result(http_result::Result::OutputStart(_) | http_result::Result::OutputChunk(_))
        );
        results.push(result);
        if terminal {
            break;
        }
    }
    results
}

/// End the stage as the pipeline does after `result`.
fn end_reason(result: &Out) -> MiddlewareSessionEndReason {
    match result {
        Out::Result(http_result::Result::PreflightResult(_)) => {
            MiddlewareSessionEndReason::StageSkipped
        }
        Out::Result(http_result::Result::Reject(_)) => MiddlewareSessionEndReason::MiddlewareDenial,
        Out::Failed(_) | Out::Contract(_) => MiddlewareSessionEndReason::MiddlewareFailure,
        Out::Result(_) => MiddlewareSessionEndReason::Normal,
    }
}

/// Drive one stage through preflight and, when it inspects, the whole body,
/// as the pipeline would for a chain of one.
async fn drive(runner: &ChainRunner, chain_entry: ChainEntry, case: &ResponseCase) -> Drive {
    let described = describe(runner, &[chain_entry]).await;
    let reports = Arc::new(StageReports::default());
    let stage = stage_for(&described[0], case, &reports);
    let mut driver = StageDriver::open(&stage).await;
    driver
        .send(http_event::Event::Preflight(
            case.preflight(&described[0], &case.headers),
        ))
        .await;
    let preflight = driver.result().await;
    let mode = match &preflight {
        Out::Result(http_result::Result::PreflightResult(result)) => match &result.decision {
            Some(http_preflight_result::Decision::Inspect(HttpInspect { mode })) => *mode,
            _ => None,
        },
        _ => None,
    };
    let body = match mode {
        None => Vec::new(),
        Some(http_inspect::Mode::Buffered(_)) => {
            driver
                .send(http_event::Event::Begin(HttpBegin {
                    headers: case.headers.clone(),
                }))
                .await;
            driver
                .send(http_event::Event::BufferedBody(HttpBufferedBody {
                    data: case.chunks.concat(),
                    visible_trailers: case.trailers.clone(),
                }))
                .await;
            results_until_terminal(&mut driver).await
        }
        Some(http_inspect::Mode::Stream(_)) => {
            driver
                .send(http_event::Event::Begin(HttpBegin {
                    headers: case.headers.clone(),
                }))
                .await;
            for chunk in &case.chunks {
                driver
                    .send(http_event::Event::InputChunk(HttpInputChunk {
                        data: chunk.clone(),
                    }))
                    .await;
            }
            driver
                .send(http_event::Event::InputEnd(HttpInputEnd {
                    visible_trailers: case.trailers.clone(),
                }))
                .await;
            results_until_terminal(&mut driver).await
        }
    };
    driver
        .end(end_reason(body.last().unwrap_or(&preflight)))
        .await;
    Drive {
        preflight,
        body,
        reports: reports_for(&reports, "response-guard"),
    }
}

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

fn chain(on_error: OnError) -> ChainEntry {
    entry("response-guard", GUARD, 10, on_error)
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

fn trailer_events(events: &[HttpResponseEvent]) -> Vec<Vec<(String, String)>> {
    events
        .iter()
        .filter_map(|event| match &event.event {
            Some(http_response_event::Event::Trailers(trailers)) => Some(
                trailers
                    .headers
                    .iter()
                    .map(|header| (header.name.clone(), header.value.clone()))
                    .collect(),
            ),
            _ => None,
        })
        .collect()
}

async fn session_end(fixture: &RunningFixture, index: usize) -> Option<LegacyEndReason> {
    fixture
        .wait_for(SESSION_END_TIMEOUT, |fixture| {
            fixture.response_session_end(index)
        })
        .await
}

fn remove(name: &str) -> HeaderMutation {
    HeaderMutation {
        operation: Some(header_mutation::Operation::Remove(RemoveHeader {
            name: name.into(),
        })),
    }
}

/// Legacy stages keep the 0.1.x offers, derived from the original response
/// head: `WHOLE_BODY_BYTES` needs an unknown or in-limit length and a
/// closed-ended media type, and `STREAM_BYTES` is offered for any
/// body-capable response.
#[tokio::test]
async fn legacy_body_mode_offers_follow_0_1_x_eligibility() {
    const HEADERS_ONLY: i32 = HttpResponseBodyMode::HeadersOnly as i32;
    const WHOLE: i32 = HttpResponseBodyMode::WholeBodyBytes as i32;
    const STREAM: i32 = HttpResponseBodyMode::StreamBytes as i32;

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
            "multipart replace",
            ResponseCase::ok("multipart/x-mixed-replace; boundary=frame", &[b"--frame"]),
            vec![HEADERS_ONLY, STREAM],
        ),
        (
            "encoded body",
            ResponseCase::ok("application/json", &[b"{}"]).with_header("content-encoding", "gzip"),
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
        let observed = drive(&runner, chain(OnError::FailClosed), &case).await;
        assert!(observed.continued(), "{name}: {:?}", observed.preflight);
        assert!(observed.preflight_mutations().is_empty(), "{name}");
        assert_eq!(
            observed.outcomes(),
            [(HttpResponseInvocationOutcome::Skip, false)],
            "{name}"
        );

        let sessions = fixture.response_sessions();
        let Some(http_response_event::Event::Preflight(preflight)) =
            sessions[index][0].event.clone()
        else {
            panic!("{name}: the first event is preflight");
        };
        assert_eq!(preflight.permitted_body_modes, expected, "{name}");
        assert_eq!(preflight.status_code, u32::from(case.status), "{name}");
        assert_eq!(preflight.max_payload_bytes, LIMIT, "{name}");
        assert_eq!(preflight.middleware_name, GUARD, "{name}");
        assert_eq!(
            preflight.context.expect("context").request_id,
            "adapter-request"
        );
        assert_eq!(
            session_end(&fixture, index).await,
            Some(LegacyEndReason::StageSkipped),
            "{name}"
        );
    }
}

/// 0.1.x derived every stage's offer from the original head, so an earlier
/// stage's preflight mutation does not change a later legacy stage's offer.
#[tokio::test]
async fn offers_come_from_the_original_head_not_the_current_one() {
    let (fixture, runner) = guard(LegacyMiddlewareFixture::new("compat/offers")).await;
    let case = ResponseCase::ok("application/json", &[b"{}"]);
    let described = describe(&runner, &[chain(OnError::FailClosed)]).await;
    let reports = Arc::new(StageReports::default());
    let stage = stage_for(&described[0], &case, &reports);
    let mut driver = StageDriver::open(&stage).await;
    let current = headers(&[("content-type", "text/event-stream")]);
    driver
        .send(http_event::Event::Preflight(
            case.preflight(&described[0], &current),
        ))
        .await;
    driver.result().await;
    driver.end(MiddlewareSessionEndReason::StageSkipped).await;

    let Some(http_response_event::Event::Preflight(preflight)) =
        fixture.response_sessions()[0][0].event.clone()
    else {
        panic!("the first event is preflight");
    };
    assert_eq!(
        preflight.permitted_body_modes,
        [
            HttpResponseBodyMode::HeadersOnly as i32,
            HttpResponseBodyMode::WholeBodyBytes as i32,
            HttpResponseBodyMode::StreamBytes as i32,
        ]
    );
    assert_eq!(
        preflight.headers[0].value, "text/event-stream",
        "the service still sees the current head"
    );
}

#[tokio::test]
async fn headers_only_mutations_apply_before_commit() {
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

    let observed = drive(&runner, chain(OnError::FailClosed), &case).await;
    assert!(
        observed.continued(),
        "HEADERS_ONLY ends the stage at preflight"
    );
    let head = header_rules::apply(
        header_rules::HeaderAuthority::Response,
        &case.headers,
        &[],
        &observed.preflight_mutations(),
    )
    .expect("the adapter forwards validated mutations");
    let value = |name: &str| {
        head.iter()
            .find(|header| header.name == name)
            .map(|header| header.value.as_str())
    };
    assert_eq!(value("cache-control"), Some("private"));
    assert_eq!(value("x-upstream-debug"), None);
    assert_eq!(value("x-guard"), Some("seen"));
    assert_eq!(value("content-length"), Some("7"));
    assert_eq!(
        observed.outcomes(),
        [(HttpResponseInvocationOutcome::HeadersOnly, false)]
    );
    assert!(body_units(&fixture.response_sessions()[0]).is_empty());
    assert_eq!(
        session_end(&fixture, 0).await,
        Some(LegacyEndReason::Normal),
        "HEADERS_ONLY ends the legacy stream normally, not as skipped"
    );
}

#[tokio::test]
async fn whole_body_bytes_buffers_one_final_unit_and_mutates_trailers() {
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

    let observed = drive(&runner, chain(OnError::FailClosed), &case).await;
    assert_eq!(
        observed.decision(),
        Some(&http_preflight_result::Decision::Inspect(HttpInspect {
            mode: Some(http_inspect::Mode::Buffered(HttpBufferedMode {
                max_body_bytes: LIMIT
            })),
        }))
    );
    assert_eq!(
        observed.body.len(),
        1,
        "one buffered result: {:?}",
        observed.body
    );
    let result = observed.buffered();
    assert_eq!(
        result.body,
        Some(http_buffered_result::Body::Replacement(
            b"HELLO WORLD".to_vec()
        )),
        "a replacement tells the pipeline to strip stale integrity headers"
    );
    let rewritten: HeaderMutation = transcode(&results::write_header(
        "x-checksum",
        "rewritten",
        ExistingHeaderAction::Overwrite,
    ));
    assert_eq!(result.trailer_mutations, [rewritten]);
    assert_eq!(
        observed.outcomes(),
        [
            (HttpResponseInvocationOutcome::WholeBody, false),
            (HttpResponseInvocationOutcome::Transform, false),
            (HttpResponseInvocationOutcome::Trailers, false),
        ]
    );

    let events = &fixture.response_sessions()[0];
    assert_eq!(
        body_units(events),
        vec![(1, b"hello world".to_vec(), true)],
        "one complete unit with end_of_stream"
    );
    assert_eq!(trailer_events(events).len(), 1);
    assert_eq!(
        session_end(&fixture, 0).await,
        Some(LegacyEndReason::Normal)
    );
}

/// The pipeline holds a BUFFERED stage's input, so it reports an overflow
/// through the adapter's hook. `fail_open` releases the original body.
#[tokio::test]
async fn whole_body_overflow_follows_on_error() {
    let (fixture, runner) =
        guard(inspect(HttpResponseBodyMode::WholeBodyBytes).on_response_body(uppercase_units))
            .await;
    let oversized = vec![b'a'; usize::try_from(LIMIT).unwrap() + 1];
    let case = ResponseCase::ok("text/plain", &[&oversized]);

    for (index, on_error) in [OnError::FailOpen, OnError::FailClosed]
        .into_iter()
        .enumerate()
    {
        let described = describe(&runner, &[chain(on_error)]).await;
        let reports = Arc::new(StageReports::default());
        let stage = stage_for(&described[0], &case, &reports);
        let mut driver = StageDriver::open(&stage).await;
        driver
            .send(http_event::Event::Preflight(
                case.preflight(&described[0], &case.headers),
            ))
            .await;
        driver.result().await;
        assert_eq!(
            stage.buffered_input_failed("whole_body_over_capacity", oversized.len()),
            on_error == OnError::FailOpen
        );
        driver
            .end(MiddlewareSessionEndReason::MiddlewareFailure)
            .await;
        let observed = reports_for(&reports, "response-guard");
        let invocations = invocations(&observed);
        assert_eq!(invocations.len(), 2);
        assert_eq!(
            invocations[1].outcome,
            if on_error == OnError::FailOpen {
                HttpResponseInvocationOutcome::FailOpen
            } else {
                HttpResponseInvocationOutcome::FailClosed
            }
        );
        assert_eq!(invocations[1].input_size, oversized.len());
        assert_eq!(
            invocations[1].failure_category.as_deref(),
            Some("payload_capacity")
        );
        assert_eq!(
            fail_open_reasons(&observed),
            if on_error == OnError::FailOpen {
                vec!["whole_body_over_capacity".to_string()]
            } else {
                Vec::new()
            }
        );
        assert!(body_units(&fixture.response_sessions()[index]).is_empty());
        assert_eq!(
            session_end(&fixture, index).await,
            Some(LegacyEndReason::MiddlewareFailure)
        );
    }
}

/// A body over the stage limit that still reaches the adapter follows
/// `on_error` the same way, without a body exchange.
#[tokio::test]
async fn an_oversized_buffered_body_follows_on_error_without_an_exchange() {
    let (fixture, runner) =
        guard(inspect(HttpResponseBodyMode::WholeBodyBytes).on_response_body(uppercase_units))
            .await;
    let case = ResponseCase::ok("text/plain", &[&[b'a'; 65]]);

    let open = drive(&runner, chain(OnError::FailOpen), &case).await;
    assert_eq!(
        open.buffered().body,
        Some(http_buffered_result::Body::Unchanged(
            openshell_core::proto::HttpUnchanged {}
        ))
    );
    assert_eq!(
        fail_open_reasons(&open.reports),
        ["whole_body_over_capacity"]
    );

    let closed = drive(&runner, chain(OnError::FailClosed), &case).await;
    assert_eq!(
        closed.terminal().failed_reason(),
        Some("whole_body_over_capacity")
    );
    for index in 0..2 {
        assert!(body_units(&fixture.response_sessions()[index]).is_empty());
    }
}

/// Server-sent events through `STREAM_BYTES`: each input chunk is released as
/// soon as its unit returns, and the body ends with an empty final unit
/// followed by trailers.
#[tokio::test]
async fn stream_bytes_releases_each_unit_as_it_arrives() {
    let (fixture, runner) =
        guard(inspect(HttpResponseBodyMode::StreamBytes).on_response_body(uppercase_units)).await;
    let events: [&[u8]; 3] = [b"data: one\n\n", b"data: two\n\n", b"data: three\n\n"];
    let case = ResponseCase::ok("text/event-stream", &events).with_header("etag", "\"v1\"");

    let observed = drive(&runner, chain(OnError::FailClosed), &case).await;
    assert_eq!(
        observed.decision(),
        Some(&http_preflight_result::Decision::Inspect(HttpInspect {
            mode: Some(http_inspect::Mode::Stream(
                openshell_core::proto::HttpStreamMode {}
            )),
        })),
        "selecting STREAM tells the pipeline to strip stale validators"
    );
    assert!(
        matches!(
            observed.body[0],
            Out::Result(http_result::Result::OutputStart(_))
        ),
        "output starts at Begin, so the head commits after preflight"
    );
    assert_eq!(
        observed.released(),
        events
            .iter()
            .map(|event| event.to_ascii_uppercase())
            .collect::<Vec<_>>()
    );
    assert!(observed.finish_trailer_mutations().is_empty());
    assert_eq!(
        observed.outcomes(),
        [
            (HttpResponseInvocationOutcome::Stream, false),
            (HttpResponseInvocationOutcome::Transform, false),
            (HttpResponseInvocationOutcome::Transform, false),
            (HttpResponseInvocationOutcome::Transform, false),
            (HttpResponseInvocationOutcome::PassThrough, false),
            (HttpResponseInvocationOutcome::Trailers, false),
        ]
    );

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
    assert_eq!(trailer_events(recorded).len(), 1);
    assert_eq!(
        session_end(&fixture, 0).await,
        Some(LegacyEndReason::Normal)
    );
}

#[tokio::test]
async fn stream_bytes_skip_remaining_passes_the_rest_through_locally() {
    let (fixture, runner) = guard(inspect(HttpResponseBodyMode::StreamBytes).on_response_body(
        |unit| {
            if unit.sequence == 2 {
                results::body_skip_remaining(unit.sequence, Some(b"LAST-INSPECTED".to_vec())).into()
            } else {
                uppercase_units(unit)
            }
        },
    ))
    .await;
    let case = ResponseCase::ok("text/plain", &[b"one", b"two", b"three"])
        .with_trailer("digest", "sha-256=stale")
        .with_trailer("x-trailer", "kept");

    let observed = drive(&runner, chain(OnError::FailClosed), &case).await;
    assert_eq!(
        observed.released(),
        vec![
            b"ONE".to_vec(),
            b"LAST-INSPECTED".to_vec(),
            b"three".to_vec()
        ]
    );
    assert_eq!(
        observed.finish_trailer_mutations(),
        [remove("digest")],
        "0.1.x stripped stale integrity trailers after a transformed body"
    );
    assert_eq!(
        observed.outcomes(),
        [
            (HttpResponseInvocationOutcome::Stream, false),
            (HttpResponseInvocationOutcome::Transform, false),
            (HttpResponseInvocationOutcome::SkipRemaining, false),
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
    assert!(trailer_events(recorded).is_empty());
    assert_eq!(
        session_end(&fixture, 0).await,
        Some(LegacyEndReason::Normal)
    );
}

/// After a transform, the trailers event omits stale integrity trailers and
/// the stage removes them from the response, as 0.1.x did.
#[tokio::test]
async fn stale_integrity_trailers_are_stripped_after_a_transform() {
    let (fixture, runner) =
        guard(inspect(HttpResponseBodyMode::StreamBytes).on_response_body(uppercase_units)).await;
    let case = ResponseCase::ok("text/plain", &[b"body"])
        .with_trailer("digest", "sha-256=stale")
        .with_trailer("x-trailer", "kept")
        .with_trailer("digest", "sha-512=stale");

    let observed = drive(&runner, chain(OnError::FailClosed), &case).await;
    assert_eq!(observed.finish_trailer_mutations(), [remove("digest")]);
    assert_eq!(
        trailer_events(&fixture.response_sessions()[0]),
        [vec![("x-trailer".to_string(), "kept".to_string())]]
    );

    let untouched = drive(
        &runner,
        chain(OnError::FailClosed),
        &ResponseCase::ok("text/plain", &[]).with_trailer("digest", "sha-256=fresh"),
    )
    .await;
    assert!(
        untouched.finish_trailer_mutations().is_empty(),
        "untransformed bodies keep their integrity trailers"
    );
}

/// `BLOCK_DELIVERY` stops delivery regardless of `on_error`: before commit at
/// preflight or during `WHOLE_BODY_BYTES`, and after commit during
/// `STREAM_BYTES`.
#[tokio::test]
async fn block_delivery_stops_delivery_at_the_step_that_blocked() {
    let (preflight_fixture, preflight_runner) = guard(
        LegacyMiddlewareFixture::new("compat/block-preflight")
            .on_response_preflight(|_| results::preflight_block("content_match").into()),
    )
    .await;
    let observed = drive(
        &preflight_runner,
        chain(OnError::FailOpen),
        &ResponseCase::ok("text/plain", &[b"secret"]),
    )
    .await;
    assert!(observed.body.is_empty());
    assert_eq!(observed.reject_code().as_deref(), Some("content_match"));
    assert_eq!(
        observed.outcomes(),
        [(HttpResponseInvocationOutcome::BlockDelivery, false)]
    );
    assert_eq!(
        observed.invocations()[0].reason_code.as_deref(),
        Some("content_match")
    );
    assert_eq!(
        session_end(&preflight_fixture, 0).await,
        Some(LegacyEndReason::MiddlewareDenial)
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
    let observed = drive(
        &stream_runner,
        chain(OnError::FailOpen),
        &ResponseCase::ok("text/plain", &[b"first", b"secret", b"never"]),
    )
    .await;
    assert_eq!(
        observed.released(),
        vec![b"first".to_vec()],
        "units before the block were already released"
    );
    assert_eq!(observed.reject_code().as_deref(), Some("content_match"));
    assert_eq!(
        session_end(&stream_fixture, 0).await,
        Some(LegacyEndReason::MiddlewareDenial)
    );

    let (_whole_fixture, whole_runner) = guard(
        inspect(HttpResponseBodyMode::WholeBodyBytes)
            .on_response_body(|unit| results::body_block(unit.sequence, "content_match").into()),
    )
    .await;
    let observed = drive(
        &whole_runner,
        chain(OnError::FailOpen),
        &ResponseCase::ok("text/plain", &[b"secret"]),
    )
    .await;
    assert!(observed.released().is_empty(), "blocked before commit");
    assert_eq!(observed.reject_code().as_deref(), Some("content_match"));
}

/// A stream stage that fails mid-body under `fail_open` releases the unit it
/// was given unchanged and is bypassed for the rest of the response.
#[tokio::test]
async fn stream_failure_mid_body_follows_on_error() {
    struct StreamFailure {
        name: &'static str,
        script: BodyScript,
        reason: &'static str,
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
            reason: "external_service_error",
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
            reason: "middleware_timeout",
            service_keeps_reading: true,
        },
    ];
    for failure in &failures {
        let name = failure.name;
        let (fixture, runner) =
            guard(inspect(HttpResponseBodyMode::StreamBytes).on_response_body(failure.script))
                .await;
        let case = ResponseCase::ok("text/event-stream", &[b"one", b"two", b"three"])
            .with_trailer("x-trailer", "kept");

        let open = drive(&runner, chain(OnError::FailOpen), &case).await;
        assert_eq!(
            open.released(),
            vec![b"ONE".to_vec(), b"two".to_vec(), b"three".to_vec()],
            "{name}"
        );
        assert!(
            open.finish_trailer_mutations().is_empty(),
            "{name}: trailers are kept"
        );
        assert_eq!(
            open.outcomes(),
            [
                (HttpResponseInvocationOutcome::Stream, false),
                (HttpResponseInvocationOutcome::Transform, false),
                (HttpResponseInvocationOutcome::FailOpen, true),
            ],
            "{name}: the failed stage is not invoked again"
        );
        assert_eq!(fail_open_reasons(&open.reports), [failure.reason], "{name}");
        if failure.service_keeps_reading {
            assert_eq!(
                body_units(&fixture.response_sessions()[0]).len(),
                2,
                "{name}: the failed stage receives no later units"
            );
        }

        let closed = drive(&runner, chain(OnError::FailClosed), &case).await;
        assert_eq!(closed.released(), vec![b"ONE".to_vec()], "{name}");
        assert_eq!(
            closed.terminal().failed_reason(),
            Some(failure.reason),
            "{name}"
        );
    }
}

/// `UNIMPLEMENTED` passes through as a contract failure for either
/// `on_error`; the pipeline fails it closed and requests reconciliation.
#[tokio::test]
async fn unimplemented_response_stream_is_a_contract_failure_for_either_on_error() {
    for remove_service in [false, true] {
        let fixture = inspect(HttpResponseBodyMode::StreamBytes);
        let fixture = if remove_service {
            fixture.without_response_service()
        } else {
            fixture
        };
        let (fixture, runner) = guard(fixture).await;
        fixture.set_unimplemented(LegacyRpc::HttpResponsePreReturn, true);
        let case = ResponseCase::ok("text/plain", &[b"uninspected"]);

        for on_error in [OnError::FailOpen, OnError::FailClosed] {
            let observed = drive(&runner, chain(on_error), &case).await;
            assert_eq!(
                observed.preflight,
                Out::Contract(ContractFailureKind::Unimplemented),
                "remove={remove_service} {on_error:?}"
            );
            let invocations = observed.invocations();
            assert_eq!(
                observed.outcomes(),
                [(HttpResponseInvocationOutcome::FailClosed, true)]
            );
            assert_eq!(
                invocations[0].failure_category.as_deref(),
                Some("contract_failure")
            );
            assert!(fail_open_reasons(&observed.reports).is_empty());
        }
        assert!(fixture.response_sessions().is_empty());
    }
}

#[tokio::test]
async fn decode_failures_mid_stream_are_contract_failures() {
    let (_fixture, runner) = guard(inspect(HttpResponseBodyMode::StreamBytes).on_response_body(
        |_| {
            let error =
                openshell_core::proto::HttpResponseEventResult::decode(&b"\x0a\x05\x01"[..])
                    .expect_err("truncated message must not decode");
            Reply::Fail(Status::internal(error.to_string()))
        },
    ))
    .await;
    let observed = drive(
        &runner,
        chain(OnError::FailOpen),
        &ResponseCase::ok("text/plain", &[b"body"]),
    )
    .await;
    assert_eq!(
        observed.terminal(),
        &Out::Contract(ContractFailureKind::Decode)
    );
    assert!(observed.released().is_empty());
    assert_eq!(
        observed.outcomes(),
        [
            (HttpResponseInvocationOutcome::Stream, false),
            (HttpResponseInvocationOutcome::FailClosed, true),
        ]
    );
}

/// A semantically invalid legacy result and the step and reason 0.1.x
/// reports for it. Legacy stages keep `on_error` handling for semantic
/// violations.
struct Violation {
    name: &'static str,
    preflight: PreflightScript,
    body: BodyScript,
    trailers: TrailersScript,
    step: Step,
    reason: &'static str,
}

/// Where a stage failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Preflight,
    Body,
    Trailers,
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
        step: Step::Body,
        reason: "response_body_sequence_mismatch",
    },
    Violation {
        name: "replacement over the binding limit",
        preflight: inspect_stream,
        body: |unit| results::body_transform(unit.sequence, vec![b'x'; 65]).into(),
        trailers: keep_trailers,
        step: Step::Body,
        reason: "response_body_replacement_over_capacity",
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
        step: Step::Body,
        reason: "invalid_response_body_decision",
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
        step: Step::Body,
        reason: "response_reason_over_capacity",
    },
    Violation {
        name: "mode that was not offered",
        preflight: |_| {
            results::preflight_inspect(HttpResponseBodyMode::WholeBodyBytes, Vec::new()).into()
        },
        body: pass_through,
        trailers: keep_trailers,
        step: Step::Preflight,
        reason: "response_body_mode_not_permitted",
    },
    Violation {
        name: "preflight result without an action",
        preflight: |_| HttpResponsePreflightResult::default().into(),
        body: pass_through,
        trailers: keep_trailers,
        step: Step::Preflight,
        reason: "invalid_preflight_decision",
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
        step: Step::Preflight,
        reason: "header_mutation_protected_header",
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
        step: Step::Trailers,
        reason: "trailer_mutation_absent_name",
    },
];

#[tokio::test]
async fn semantic_violations_follow_on_error() {
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

        let open = drive(&runner, chain(OnError::FailOpen), &case).await;
        if violation.step == Step::Preflight {
            assert!(open.continued(), "{name}: {:?}", open.preflight);
            assert!(open.preflight_mutations().is_empty(), "{name}");
        } else {
            assert_eq!(open.released(), [b"data: one\n\n".to_vec()], "{name}");
            assert!(open.finish_trailer_mutations().is_empty(), "{name}");
        }
        assert!(
            open.outcomes()
                .contains(&(HttpResponseInvocationOutcome::FailOpen, true)),
            "{name}: {:?}",
            open.outcomes()
        );
        assert_eq!(
            fail_open_reasons(&open.reports),
            [violation.reason],
            "{name}"
        );

        let closed = drive(&runner, chain(OnError::FailClosed), &case).await;
        assert_eq!(
            closed.terminal().failed_reason(),
            Some(violation.reason),
            "{name}"
        );
        let released = closed.released();
        match violation.step {
            Step::Preflight => assert!(closed.body.is_empty(), "{name}"),
            Step::Body => assert!(released.is_empty(), "{name}"),
            Step::Trailers => assert_eq!(released, [b"data: one\n\n".to_vec()], "{name}"),
        }
    }
}

/// Findings and metadata keep the 0.1.x response normalization for operator
/// services: platform-owned text, cleared confidence, medium severity, and no
/// metadata.
#[tokio::test]
async fn operator_diagnostics_are_normalized_like_0_1_x() {
    let (_fixture, runner) = guard(
        LegacyMiddlewareFixture::new("compat/diagnostics").on_response_preflight(|_| {
            HttpResponsePreflightResult {
                findings: vec![LegacyFinding {
                    r#type: "guard.match".into(),
                    label: "matched sk-secret-value".into(),
                    count: 2,
                    confidence: "high".into(),
                    severity: "high".into(),
                }],
                metadata: std::iter::once(("secret".to_string(), "sk-secret-value".to_string()))
                    .collect(),
                reason_code: "noted".into(),
                ..results::preflight_skip()
            }
            .into()
        }),
    )
    .await;
    let observed = drive(
        &runner,
        chain(OnError::FailClosed),
        &ResponseCase::ok("text/plain", &[b"body"]),
    )
    .await;
    assert!(observed.result_diagnostics().is_empty());
    let StageReport::LegacyResponseInvocation {
        findings, metadata, ..
    } = &observed.reports[0]
    else {
        panic!("the skip is reported with its diagnostics");
    };
    assert!(metadata.is_empty());
    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding.r#type, format!("{GUARD}.finding"));
    assert_eq!(finding.label, "External middleware finding");
    assert!(finding.confidence.is_empty());
    assert_eq!(finding.severity, "medium");
    assert_eq!(finding.count, 2);
    assert_eq!(
        observed.invocations()[0].reason_code.as_deref(),
        Some("noted")
    );
}

/// Replacements larger than the offered chunk size are released as several
/// output chunks.
#[tokio::test]
async fn replacements_are_released_within_the_output_chunk_limit() {
    let (_fixture, runner) = guard(inspect(HttpResponseBodyMode::StreamBytes).on_response_body(
        |unit| {
            if unit.sequence == 1 {
                results::body_transform(unit.sequence, vec![b'r'; 40]).into()
            } else {
                results::body_pass_through(unit.sequence).into()
            }
        },
    ))
    .await;
    let case = ResponseCase::ok("text/plain", &[b"in"]);
    let described = describe(&runner, &[chain(OnError::FailClosed)]).await;
    let reports = Arc::new(StageReports::default());
    let stage = stage_for(&described[0], &case, &reports);
    let mut driver = StageDriver::open(&stage).await;
    let mut preflight = case.preflight(&described[0], &case.headers);
    preflight.limits.as_mut().expect("limits").max_chunk_bytes = 16;
    driver.send(http_event::Event::Preflight(preflight)).await;
    driver.result().await;
    for event in [
        http_event::Event::Begin(HttpBegin::default()),
        http_event::Event::InputChunk(HttpInputChunk {
            data: b"in".to_vec(),
        }),
        http_event::Event::InputEnd(HttpInputEnd::default()),
    ] {
        driver.send(event).await;
    }
    let results = results_until_terminal(&mut driver).await;
    let sizes = results
        .iter()
        .filter_map(|out| match out {
            Out::Result(http_result::Result::OutputChunk(chunk)) => Some(chunk.data.len()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(sizes, [16, 16, 8]);
    driver.end(MiddlewareSessionEndReason::Normal).await;
}

/// A completed stage keeps its legacy stream open until the pipeline ends
/// it, and receives the pipeline's reason, as 0.1.x ended every stage with
/// the chain's outcome.
#[tokio::test]
async fn completed_stages_receive_the_pipelines_session_end() {
    let (fixture, runner) =
        guard(inspect(HttpResponseBodyMode::StreamBytes).on_response_body(pass_through)).await;
    let case = ResponseCase::ok("text/plain", &[b"body"]);
    let described = describe(&runner, &[chain(OnError::FailClosed)]).await;
    let reports = Arc::new(StageReports::default());
    let stage = stage_for(&described[0], &case, &reports);
    let mut driver = StageDriver::open(&stage).await;
    driver
        .send(http_event::Event::Preflight(
            case.preflight(&described[0], &case.headers),
        ))
        .await;
    driver.result().await;
    for event in [
        http_event::Event::Begin(HttpBegin::default()),
        http_event::Event::InputChunk(HttpInputChunk {
            data: b"body".to_vec(),
        }),
        http_event::Event::InputEnd(HttpInputEnd::default()),
    ] {
        driver.send(event).await;
    }
    let results = results_until_terminal(&mut driver).await;
    assert!(matches!(
        results.last(),
        Some(Out::Result(http_result::Result::Finish(_)))
    ));
    driver
        .end(MiddlewareSessionEndReason::DownstreamDisconnect)
        .await;
    assert_eq!(
        session_end(&fixture, 0).await,
        Some(LegacyEndReason::DownstreamDisconnect),
        "the stream was still open when the pipeline ended it"
    );
}

/// Stages run in policy order across services. A later `WHOLE_BODY_BYTES`
/// stage withholds every byte until the body ends and receives the earlier
/// stream stage's output as one unit.
#[tokio::test]
async fn mixed_stream_and_whole_body_chain_runs_in_policy_order() {
    let stream = inspect(HttpResponseBodyMode::StreamBytes)
        .on_response_body(uppercase_units)
        .with_binding(http_response_binding(LIMIT))
        .spawn()
        .await
        .expect("spawn stream fixture");
    let whole = inspect(HttpResponseBodyMode::WholeBodyBytes)
        .on_response_body(|unit| {
            let Some(http_response_body_unit::Payload::Data(data)) = unit.payload.as_ref() else {
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
    let described = describe(
        &runner,
        &[
            entry("whole", "legacy-whole", 20, OnError::FailClosed),
            entry("stream", "legacy-stream", 10, OnError::FailClosed),
        ],
    )
    .await;
    let case = ResponseCase::ok("text/plain", &[b"one ", b"two"]);
    let reports = Arc::new(StageReports::default());

    let mut drivers = Vec::new();
    for entry in &described {
        let stage = stage_for(entry, &case, &reports);
        let mut driver = StageDriver::open(&stage).await;
        driver
            .send(http_event::Event::Preflight(
                case.preflight(entry, &case.headers),
            ))
            .await;
        driver.result().await;
        drivers.push(driver);
    }
    let [stream_stage, whole_stage] = &mut drivers[..] else {
        panic!("two stages");
    };
    stream_stage
        .send(http_event::Event::Begin(HttpBegin::default()))
        .await;
    for chunk in &case.chunks {
        stream_stage
            .send(http_event::Event::InputChunk(HttpInputChunk {
                data: chunk.clone(),
            }))
            .await;
    }
    stream_stage
        .send(http_event::Event::InputEnd(HttpInputEnd::default()))
        .await;
    let stream_output = results_until_terminal(stream_stage)
        .await
        .into_iter()
        .filter_map(|out| match out {
            Out::Result(http_result::Result::OutputChunk(chunk)) => Some(chunk.data),
            _ => None,
        })
        .collect::<Vec<_>>()
        .concat();

    whole_stage
        .send(http_event::Event::Begin(HttpBegin::default()))
        .await;
    whole_stage
        .send(http_event::Event::BufferedBody(HttpBufferedBody {
            data: stream_output,
            visible_trailers: Vec::new(),
        }))
        .await;
    let Out::Result(http_result::Result::BufferedResult(result)) = whole_stage.result().await
    else {
        panic!("buffered result expected");
    };
    assert_eq!(
        result.body,
        Some(http_buffered_result::Body::Replacement(
            b"[ONE TWO]".to_vec()
        ))
    );
    for driver in &mut drivers {
        driver.end(MiddlewareSessionEndReason::Normal).await;
    }
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

/// Drive one stream stage's body: `Begin`, `chunks`, and `InputEnd`, and
/// collect the results up to the terminal one.
async fn stream_body(driver: &mut StageDriver, chunks: &[&[u8]]) -> Vec<Out> {
    driver
        .send(http_event::Event::Begin(HttpBegin::default()))
        .await;
    for chunk in chunks {
        driver
            .send(http_event::Event::InputChunk(HttpInputChunk {
                data: chunk.to_vec(),
            }))
            .await;
    }
    driver
        .send(http_event::Event::InputEnd(HttpInputEnd::default()))
        .await;
    results_until_terminal(driver).await
}

/// 0.1.x withheld all output while a whole-body stage buffered, so a stream
/// stage after it ran over the whole body before the head committed, and its
/// block was the canonical denial rather than an abort.
#[tokio::test]
async fn a_stream_stage_after_a_whole_body_stage_withholds_output_until_the_end() {
    let whole = inspect(HttpResponseBodyMode::WholeBodyBytes)
        .on_response_body(uppercase_units)
        .with_binding(http_response_binding(LIMIT))
        .spawn()
        .await
        .expect("spawn whole-body fixture");
    let stream = inspect(HttpResponseBodyMode::StreamBytes)
        .on_response_body(|unit| match &unit.payload {
            Some(http_response_body_unit::Payload::Data(data)) if data == b"SECRET" => {
                results::body_block(unit.sequence, "content_match").into()
            }
            _ => results::body_pass_through(unit.sequence).into(),
        })
        .with_binding(http_response_binding(LIMIT))
        .spawn()
        .await
        .expect("spawn stream fixture");
    let runner = connect(vec![
        registration("legacy-whole", &whole, LIMIT),
        registration("legacy-stream", &stream, LIMIT),
    ])
    .await;
    let chain = [
        entry("whole", "legacy-whole", 10, OnError::FailClosed),
        entry("stream", "legacy-stream", 20, OnError::FailClosed),
    ];

    for (body, withhold) in [
        (&b"hello"[..], true),
        (&b"secret"[..], true),
        (&b"secret"[..], false),
    ] {
        let described = describe(&runner, &chain).await;
        let case = ResponseCase::ok("text/plain", &[body]);
        let reports = Arc::new(StageReports::default());
        let whole_stage = stage_for(&described[0], &case, &reports);
        let stream_stage = stage_for(&described[1], &case, &reports);
        let mut whole_driver = StageDriver::open(&whole_stage).await;
        let mut stream_driver = StageDriver::open(&stream_stage).await;
        for (driver, entry) in [
            (&mut whole_driver, &described[0]),
            (&mut stream_driver, &described[1]),
        ] {
            driver
                .send(http_event::Event::Preflight(
                    case.preflight(entry, &case.headers),
                ))
                .await;
            driver.result().await;
        }
        whole_driver
            .send(http_event::Event::Begin(HttpBegin::default()))
            .await;
        whole_driver
            .send(http_event::Event::BufferedBody(HttpBufferedBody {
                data: body.to_vec(),
                visible_trailers: Vec::new(),
            }))
            .await;
        let Out::Result(http_result::Result::BufferedResult(HttpBufferedResult {
            body: Some(http_buffered_result::Body::Replacement(upper)),
            ..
        })) = whole_driver.result().await
        else {
            panic!("the whole-body stage replaces the body");
        };
        if withhold {
            stream_stage.withhold_output_until_end();
        }
        let results = stream_body(&mut stream_driver, &[&upper]).await;
        match (body, withhold) {
            (b"hello", _) => assert_eq!(
                results,
                [
                    Out::Result(http_result::Result::OutputStart(
                        openshell_core::proto::HttpOutputStart {
                            header_mutations: Vec::new(),
                            output_body_bytes: Some(5),
                        }
                    )),
                    Out::Result(http_result::Result::OutputChunk(
                        openshell_core::proto::HttpOutputChunk {
                            data: b"HELLO".to_vec()
                        }
                    )),
                    Out::Result(http_result::Result::Finish(
                        openshell_core::proto::HttpFinish::default()
                    )),
                ],
                "output starts only once the stage has seen the whole body"
            ),
            (_, true) => assert!(
                matches!(results[..], [Out::Result(http_result::Result::Reject(_))]),
                "a block before any output is the canonical denial: {results:?}"
            ),
            (_, false) => assert!(
                matches!(
                    results[..],
                    [
                        Out::Result(http_result::Result::OutputStart(_)),
                        Out::Result(http_result::Result::Reject(_))
                    ]
                ),
                "without the hook the head commits before the block: {results:?}"
            ),
        }
        whole_driver.end(MiddlewareSessionEndReason::Normal).await;
        stream_driver
            .end(end_reason(&results[results.len() - 1]))
            .await;
    }
}

/// While withholding output, a stage keeps the 0.1.x retained-body budget:
/// a replacement that would exceed it fails the stage like 0.1.x.
#[tokio::test]
async fn withheld_output_keeps_the_0_1_x_retained_body_budget() {
    const LARGE: u64 = 4 * 1024 * 1024;
    const REPLACEMENT: usize = 3 * 1024 * 1024;
    let fixture = inspect(HttpResponseBodyMode::StreamBytes)
        .on_response_body(|unit| match &unit.payload {
            Some(http_response_body_unit::Payload::Data(data)) if !data.is_empty() => {
                results::body_transform(unit.sequence, vec![b'r'; REPLACEMENT]).into()
            }
            _ => results::body_pass_through(unit.sequence).into(),
        })
        .with_binding(http_response_binding(LARGE))
        .spawn()
        .await
        .expect("spawn response fixture");
    let runner = connect(vec![registration(GUARD, &fixture, LARGE)]).await;
    let case = ResponseCase::ok("text/plain", &[b"a", b"b", b"c"]);

    for on_error in [OnError::FailClosed, OnError::FailOpen] {
        let described = describe(&runner, &[chain(on_error)]).await;
        let reports = Arc::new(StageReports::default());
        let stage = stage_for(&described[0], &case, &reports);
        stage.withhold_output_until_end();
        let mut driver = StageDriver::open(&stage).await;
        driver
            .send(http_event::Event::Preflight(
                case.preflight(&described[0], &case.headers),
            ))
            .await;
        driver.result().await;
        let results = stream_body(&mut driver, &[b"a", b"b", b"c"]).await;
        let outcomes = invocations(&reports_for(&reports, "response-guard"))
            .iter()
            .map(|invocation| invocation.outcome)
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes,
            [
                HttpResponseInvocationOutcome::Stream,
                HttpResponseInvocationOutcome::Transform,
                HttpResponseInvocationOutcome::Transform,
                if on_error == OnError::FailOpen {
                    HttpResponseInvocationOutcome::FailOpen
                } else {
                    HttpResponseInvocationOutcome::FailClosed
                },
            ],
            "{on_error:?}"
        );
        if on_error == OnError::FailClosed {
            assert_eq!(
                results,
                [Out::Failed(crate::legacy::codec::LegacyStageFailure::new(
                    "response_body_aggregate_over_capacity"
                ))],
                "the stage fails before any output"
            );
        } else {
            let released = results
                .iter()
                .filter_map(|out| match out {
                    Out::Result(http_result::Result::OutputChunk(chunk)) => Some(chunk.data.len()),
                    _ => None,
                })
                .sum::<usize>();
            assert_eq!(released, 2 * REPLACEMENT + 1, "the failed unit passes on");
        }
        driver.end(end_reason(&results[results.len() - 1])).await;
    }
}

/// Findings from every unit and the trailers are reported as each step
/// completes, so neither the version 2 per-result limits nor a later failure
/// can drop them.
#[tokio::test]
async fn findings_are_reported_with_each_step() {
    let (_fixture, runner) = guard(inspect(HttpResponseBodyMode::StreamBytes).on_response_body(
        |unit| {
            HttpResponseBodyResult {
                findings: vec![
                    LegacyFinding {
                        r#type: "guard.match".into(),
                        label: "match".into(),
                        count: 1,
                        confidence: "high".into(),
                        severity: "high".into(),
                    };
                    20
                ],
                ..results::body_pass_through(unit.sequence)
            }
            .into()
        },
    ))
    .await;
    let observed = drive(
        &runner,
        chain(OnError::FailClosed),
        &ResponseCase::ok("text/plain", &[b"one", b"two", b"three"]),
    )
    .await;
    assert!(matches!(
        observed.terminal(),
        Out::Result(http_result::Result::Finish(_))
    ));
    assert_eq!(observed.findings().len(), 80, "four units of 20 findings");
    assert!(observed.result_diagnostics().is_empty());
}

/// A BUFFERED selection never exceeds the pipeline's offer.
#[tokio::test]
async fn a_buffered_selection_never_exceeds_the_offer() {
    let (_fixture, runner) =
        guard(inspect(HttpResponseBodyMode::WholeBodyBytes).on_response_body(uppercase_units))
            .await;
    let case = ResponseCase::ok("text/plain", &[b"small"]);
    let described = describe(&runner, &[chain(OnError::FailClosed)]).await;
    let reports = Arc::new(StageReports::default());
    let stage = stage_for(&described[0], &case, &reports);
    let mut driver = StageDriver::open(&stage).await;
    let mut preflight = case.preflight(&described[0], &case.headers);
    preflight
        .limits
        .as_mut()
        .expect("limits")
        .max_buffered_body_bytes = 16;
    driver.send(http_event::Event::Preflight(preflight)).await;
    let result = driver.result().await;
    assert_eq!(
        result,
        Out::Result(http_result::Result::PreflightResult(
            openshell_core::proto::HttpPreflightResult {
                decision: Some(http_preflight_result::Decision::Inspect(HttpInspect {
                    mode: Some(http_inspect::Mode::Buffered(HttpBufferedMode {
                        max_body_bytes: 16
                    })),
                })),
                header_mutations: Vec::new(),
                diagnostics: None,
            }
        ))
    );
    driver.end(MiddlewareSessionEndReason::Cancellation).await;
}

/// The pipeline must offer both body modes to a legacy stage. A stage that
/// selects a mode the pipeline did not offer fails closed, whatever
/// `on_error` says.
#[tokio::test]
async fn a_selected_mode_the_pipeline_did_not_offer_fails_the_stage_closed() {
    let (fixture, runner) = guard(inspect(HttpResponseBodyMode::StreamBytes)).await;
    let case = ResponseCase::ok("text/plain", &[b"body"]);
    let described = describe(&runner, &[chain(OnError::FailOpen)]).await;
    let reports = Arc::new(StageReports::default());
    let stage = stage_for(&described[0], &case, &reports);
    let mut driver = StageDriver::open(&stage).await;
    let mut preflight = case.preflight(&described[0], &case.headers);
    preflight.permitted_body_modes = vec![HttpBodyMode::Buffered as i32];
    driver.send(http_event::Event::Preflight(preflight)).await;
    assert_eq!(
        driver.result().await.failed_reason(),
        Some("legacy_stage_offer_invalid")
    );
    assert_eq!(
        session_end(&fixture, 0).await,
        Some(LegacyEndReason::MiddlewareFailure)
    );
}

/// 0.1.x ended every stage it opened. A pipeline that closes the event stream
/// without `session_end` still ends the legacy stream.
#[tokio::test]
async fn a_pipeline_that_goes_away_still_ends_the_legacy_stream() {
    let (fixture, runner) =
        guard(inspect(HttpResponseBodyMode::StreamBytes).on_response_body(pass_through)).await;
    let case = ResponseCase::ok("text/plain", &[b"body"]);
    for (index, finish) in [false, true].into_iter().enumerate() {
        let described = describe(&runner, &[chain(OnError::FailClosed)]).await;
        let reports = Arc::new(StageReports::default());
        let stage = stage_for(&described[0], &case, &reports);
        let mut driver = StageDriver::open(&stage).await;
        driver
            .send(http_event::Event::Preflight(
                case.preflight(&described[0], &case.headers),
            ))
            .await;
        driver.result().await;
        if finish {
            stream_body(&mut driver, &[b"body"]).await;
        } else {
            driver
                .send(http_event::Event::Begin(HttpBegin::default()))
                .await;
            driver
                .send(http_event::Event::InputChunk(HttpInputChunk {
                    data: b"body".to_vec(),
                }))
                .await;
            driver.result().await;
            driver.result().await;
        }
        driver.close().await;
        assert_eq!(
            session_end(&fixture, index).await,
            Some(if finish {
                LegacyEndReason::Normal
            } else {
                LegacyEndReason::Cancellation
            })
        );
    }
}

/// A trailers failure after a whole-body transform keeps the replacement and
/// still strips stale integrity trailers under `fail_open`.
#[tokio::test]
async fn a_trailers_failure_after_a_transform_keeps_the_replacement_under_fail_open() {
    let (_fixture, runner) = guard(
        inspect(HttpResponseBodyMode::WholeBodyBytes)
            .on_response_body(uppercase_units)
            .on_response_trailers(|_| Reply::Fail(Status::internal("guard crashed"))),
    )
    .await;
    let case = ResponseCase::ok("text/plain", &[b"body"])
        .with_trailer("digest", "sha-256=stale")
        .with_trailer("x-trailer", "kept");

    let open = drive(&runner, chain(OnError::FailOpen), &case).await;
    let result = open.buffered();
    assert_eq!(
        result.body,
        Some(http_buffered_result::Body::Replacement(b"BODY".to_vec()))
    );
    assert_eq!(result.trailer_mutations, [remove("digest")]);
    assert_eq!(
        open.outcomes(),
        [
            (HttpResponseInvocationOutcome::WholeBody, false),
            (HttpResponseInvocationOutcome::Transform, false),
            (HttpResponseInvocationOutcome::FailOpen, true),
        ]
    );
    assert_eq!(fail_open_reasons(&open.reports), ["external_service_error"]);

    let closed = drive(&runner, chain(OnError::FailClosed), &case).await;
    assert_eq!(
        closed.terminal().failed_reason(),
        Some("external_service_error")
    );
}
