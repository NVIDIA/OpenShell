// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Version 2 HTTP request pipeline behavior.

use std::sync::Mutex;

use futures::future::BoxFuture;
use openshell_core::extension_protocol::{ExtensionFamily, extension_metadata};
use openshell_core::proto::{
    ExistingHeaderAction, HttpBufferedMode, HttpBufferedResult, HttpContinue, HttpFinish,
    HttpInspect, HttpOutputChunk, HttpOutputStart, HttpPreflight, HttpPreflightResult, HttpReject,
    HttpRequestResult, HttpResult, HttpStreamMode, HttpUnchanged, MiddlewareDiagnostics,
    MiddlewareSessionEndReason, WriteHeader, header_mutation, http_buffered_result, http_event,
    http_inspect, http_preflight_result, http_result,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use super::*;
use crate::legacy::hooks::{LegacyStageContext, test_support};
use crate::pipeline::{PipelineSpec, PipelineTimeouts, StageHead};

const LIMIT: u64 = 64 * 1024;

/// Everything one test stage received.
#[derive(Default)]
struct StageLog {
    events: Mutex<Vec<HttpEvent>>,
}

impl StageLog {
    fn push(&self, event: HttpEvent) {
        self.events.lock().expect("stage log").push(event);
    }

    fn kinds(&self) -> Vec<&'static str> {
        self.events
            .lock()
            .expect("stage log")
            .iter()
            .map(|event| match event.event {
                Some(http_event::Event::Preflight(_)) => "preflight",
                Some(http_event::Event::Begin(_)) => "begin",
                Some(http_event::Event::InputChunk(_)) => "input_chunk",
                Some(http_event::Event::InputEnd(_)) => "input_end",
                Some(http_event::Event::BufferedBody(_)) => "buffered_body",
                Some(http_event::Event::SessionEnd(_)) => "session_end",
                None => "none",
            })
            .collect()
    }

    fn preflight(&self) -> HttpPreflight {
        self.events
            .lock()
            .expect("stage log")
            .iter()
            .find_map(|event| match &event.event {
                Some(http_event::Event::Preflight(preflight)) => Some(preflight.clone()),
                _ => None,
            })
            .expect("stage received preflight")
    }

    fn begin_headers(&self) -> Vec<HttpHeader> {
        self.events
            .lock()
            .expect("stage log")
            .iter()
            .find_map(|event| match &event.event {
                Some(http_event::Event::Begin(begin)) => Some(begin.headers.clone()),
                _ => None,
            })
            .expect("stage received begin")
    }

    fn input_chunk_sizes(&self) -> Vec<usize> {
        self.events
            .lock()
            .expect("stage log")
            .iter()
            .filter_map(|event| match &event.event {
                Some(http_event::Event::InputChunk(chunk)) => Some(chunk.data.len()),
                _ => None,
            })
            .collect()
    }

    fn session_end(&self) -> Option<MiddlewareSessionEndReason> {
        self.events
            .lock()
            .expect("stage log")
            .iter()
            .find_map(|event| match &event.event {
                Some(http_event::Event::SessionEnd(end)) => {
                    MiddlewareSessionEndReason::try_from(end.reason).ok()
                }
                _ => None,
            })
    }

    /// Wait for the stage to record its session end, which a dropped
    /// exchange delivers from a spawned task.
    async fn wait_for_session_end(&self) -> MiddlewareSessionEndReason {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(reason) = self.session_end() {
                    return reason;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("stage session end")
    }
}

/// Event and result ends of one stage exchange.
struct StageIo {
    events: mpsc::Receiver<HttpEvent>,
    results: mpsc::Sender<std::result::Result<HttpResult, TonicStatus>>,
    log: Arc<StageLog>,
}

impl StageIo {
    async fn recv(&mut self) -> Option<http_event::Event> {
        let event = self.events.recv().await?;
        self.log.push(event.clone());
        event.event
    }

    async fn send(&self, result: http_result::Result) {
        let _ = self
            .results
            .send(Ok(HttpResult {
                result: Some(result),
            }))
            .await;
    }

    async fn send_raw(&self, result: std::result::Result<HttpResult, TonicStatus>) {
        let _ = self.results.send(result).await;
    }

    /// Record every remaining event, including the session end.
    async fn drain(mut self) {
        while self.recv().await.is_some() {}
    }
}

type Handler = Arc<dyn Fn(StageIo) -> BoxFuture<'static, ()> + Send + Sync>;

/// In-process version 2 request middleware driven by a test handler.
#[derive(Clone)]
struct TestStage {
    name: &'static str,
    modes: Vec<HttpBodyMode>,
    max_payload_bytes: u64,
    handler: Handler,
    log: Arc<StageLog>,
}

impl TestStage {
    fn new<F>(
        name: &'static str,
        modes: &[HttpBodyMode],
        handler: impl Fn(StageIo) -> F + Send + Sync + 'static,
    ) -> Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        Self {
            name,
            modes: modes.to_vec(),
            max_payload_bytes: if modes.is_empty() { 0 } else { LIMIT },
            handler: Arc::new(move |io| Box::pin(handler(io))),
            log: Arc::default(),
        }
    }

    fn with_limit(mut self, max_payload_bytes: u64) -> Self {
        self.max_payload_bytes = max_payload_bytes;
        self
    }
}

#[tonic::async_trait]
impl InProcessMiddleware for TestStage {
    async fn describe(&self) -> MiddlewareManifest {
        MiddlewareManifest {
            name: self.name.into(),
            service_version: String::new(),
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                max_payload_bytes: self.max_payload_bytes,
                http_protocol_version: 2,
                supported_http_body_modes: self.modes.iter().map(|mode| *mode as i32).collect(),
                ..Default::default()
            }],
            expected_audience: String::new(),
            extension: Some(extension_metadata(
                ExtensionFamily::SupervisorMiddleware,
                self.name,
                "test",
                [],
            )),
        }
    }

    async fn validate_config(&self, _name: &str, _config: &prost_types::Struct) -> Result<()> {
        Ok(())
    }

    async fn evaluate_http_request(
        &self,
        _request: HttpRequestView<'_>,
    ) -> Result<HttpRequestResult> {
        Err(miette!("version 2 test middleware"))
    }

    async fn open_http_request_stage(
        &self,
        events: mpsc::Receiver<HttpEvent>,
    ) -> std::result::Result<HttpResultStream, TonicStatus> {
        let (results, receiver) = mpsc::channel(4);
        tokio::spawn((self.handler)(StageIo {
            events,
            results,
            log: Arc::clone(&self.log),
        }));
        Ok(Box::pin(ReceiverStream::new(receiver)))
    }
}

/// Legacy in-process request middleware that replaces the body and writes a
/// header.
struct LegacyStage {
    name: &'static str,
    suffix: &'static [u8],
}

#[tonic::async_trait]
impl InProcessMiddleware for LegacyStage {
    async fn describe(&self) -> MiddlewareManifest {
        MiddlewareManifest {
            name: self.name.into(),
            service_version: String::new(),
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                max_payload_bytes: LIMIT,
                ..Default::default()
            }],
            expected_audience: String::new(),
            extension: Some(extension_metadata(
                ExtensionFamily::SupervisorMiddleware,
                self.name,
                "test",
                [],
            )),
        }
    }

    async fn validate_config(&self, _name: &str, _config: &prost_types::Struct) -> Result<()> {
        Ok(())
    }

    async fn evaluate_http_request(
        &self,
        request: HttpRequestView<'_>,
    ) -> Result<HttpRequestResult> {
        let mut body = request.body().to_vec();
        body.extend_from_slice(self.suffix);
        Ok(HttpRequestResult {
            decision: Decision::Allow as i32,
            body,
            has_body: true,
            header_mutations: vec![write(
                &format!("x-{}", self.name.replace('/', "-")),
                "legacy",
            )],
            ..Default::default()
        })
    }
}

fn write(name: &str, value: &str) -> HeaderMutation {
    HeaderMutation {
        operation: Some(header_mutation::Operation::Write(WriteHeader {
            name: name.into(),
            value: value.into(),
            on_existing: ExistingHeaderAction::Overwrite as i32,
        })),
    }
}

fn header(name: &str, value: &str) -> HttpHeader {
    HttpHeader {
        name: name.into(),
        value: value.into(),
    }
}

fn preflight_result(
    decision: http_preflight_result::Decision,
    header_mutations: Vec<HeaderMutation>,
) -> http_result::Result {
    http_result::Result::PreflightResult(HttpPreflightResult {
        decision: Some(decision),
        header_mutations,
        diagnostics: None,
    })
}

fn continue_without_body() -> http_preflight_result::Decision {
    http_preflight_result::Decision::ContinueWithoutBody(HttpContinue {})
}

fn inspect_stream() -> http_preflight_result::Decision {
    http_preflight_result::Decision::Inspect(HttpInspect {
        mode: Some(http_inspect::Mode::Stream(HttpStreamMode {})),
    })
}

fn inspect_buffered(max_body_bytes: u64) -> http_preflight_result::Decision {
    http_preflight_result::Decision::Inspect(HttpInspect {
        mode: Some(http_inspect::Mode::Buffered(HttpBufferedMode {
            max_body_bytes,
        })),
    })
}

fn output_start(header_mutations: Vec<HeaderMutation>) -> http_result::Result {
    http_result::Result::OutputStart(HttpOutputStart {
        header_mutations,
        output_body_bytes: None,
    })
}

fn output_chunk(data: Vec<u8>) -> http_result::Result {
    http_result::Result::OutputChunk(HttpOutputChunk { data })
}

fn finish() -> http_result::Result {
    http_result::Result::Finish(HttpFinish::default())
}

fn buffered(
    replacement: Option<Vec<u8>>,
    header_mutations: Vec<HeaderMutation>,
) -> http_result::Result {
    http_result::Result::BufferedResult(HttpBufferedResult {
        body: Some(replacement.map_or(
            http_buffered_result::Body::Unchanged(HttpUnchanged {}),
            http_buffered_result::Body::Replacement,
        )),
        header_mutations,
        ..Default::default()
    })
}

fn reject(reason_code: &str) -> http_result::Result {
    http_result::Result::Reject(HttpReject {
        diagnostics: Some(MiddlewareDiagnostics {
            reason_code: reason_code.into(),
            ..Default::default()
        }),
    })
}

/// STREAM stage that maps every input chunk through `transform`.
fn stream_stage(name: &'static str, transform: fn(Vec<u8>) -> Vec<u8>) -> TestStage {
    stream_stage_with_late(name, Vec::new(), Vec::new(), transform)
}

fn stream_stage_with_late(
    name: &'static str,
    preflight_mutations: Vec<HeaderMutation>,
    late_mutations: Vec<HeaderMutation>,
    transform: fn(Vec<u8>) -> Vec<u8>,
) -> TestStage {
    TestStage::new(name, &[HttpBodyMode::Stream], move |mut io: StageIo| {
        let preflight_mutations = preflight_mutations.clone();
        let late_mutations = late_mutations.clone();
        async move {
            while let Some(event) = io.recv().await {
                match event {
                    http_event::Event::Preflight(_) => {
                        io.send(preflight_result(
                            inspect_stream(),
                            preflight_mutations.clone(),
                        ))
                        .await;
                    }
                    http_event::Event::Begin(_) => {
                        io.send(output_start(late_mutations.clone())).await;
                    }
                    http_event::Event::InputChunk(chunk) => {
                        let data = transform(chunk.data);
                        if !data.is_empty() {
                            io.send(output_chunk(data)).await;
                        }
                    }
                    http_event::Event::InputEnd(_) => {
                        io.send(finish()).await;
                        break;
                    }
                    _ => {}
                }
            }
            io.drain().await;
        }
    })
}

/// BUFFERED stage that maps the whole body through `transform`.
fn buffered_stage(
    name: &'static str,
    preflight_mutations: Vec<HeaderMutation>,
    late_mutations: Vec<HeaderMutation>,
    transform: fn(Vec<u8>) -> Option<Vec<u8>>,
) -> TestStage {
    TestStage::new(name, &[HttpBodyMode::Buffered], move |mut io: StageIo| {
        let preflight_mutations = preflight_mutations.clone();
        let late_mutations = late_mutations.clone();
        async move {
            while let Some(event) = io.recv().await {
                match event {
                    http_event::Event::Preflight(preflight) => {
                        let limit = preflight
                            .limits
                            .map_or(1, |limits| limits.max_buffered_body_bytes);
                        io.send(preflight_result(
                            inspect_buffered(limit),
                            preflight_mutations.clone(),
                        ))
                        .await;
                    }
                    http_event::Event::BufferedBody(body) => {
                        io.send(buffered(transform(body.data), late_mutations.clone()))
                            .await;
                        break;
                    }
                    _ => {}
                }
            }
            io.drain().await;
        }
    })
}

/// Preflight-only stage that continues with `mutations`.
fn header_stage(name: &'static str, mutations: Vec<HeaderMutation>) -> TestStage {
    TestStage::new(name, &[], move |mut io: StageIo| {
        let mutations = mutations.clone();
        async move {
            if let Some(http_event::Event::Preflight(_)) = io.recv().await {
                io.send(preflight_result(continue_without_body(), mutations))
                    .await;
            }
            io.drain().await;
        }
    })
}

fn uppercase(data: Vec<u8>) -> Vec<u8> {
    data.to_ascii_uppercase()
}

fn identity(data: Vec<u8>) -> Vec<u8> {
    data
}

async fn runner_for(stages: &[TestStage]) -> ChainRunner {
    let services = stages
        .iter()
        .map(|stage| -> Arc<dyn InProcessMiddleware> { Arc::new(stage.clone()) })
        .collect();
    ChainRunner::from_registry(
        MiddlewareRegistry::connect_services_with_http_v2(services, Vec::new())
            .await
            .expect("registry"),
    )
}

fn chain(names: &[&str]) -> Vec<ChainEntry> {
    names
        .iter()
        .enumerate()
        .map(|(order, name)| ChainEntry {
            name: name.replace('/', "-"),
            implementation: (*name).to_string(),
            order: i32::try_from(order).expect("order"),
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        })
        .collect()
}

fn preflight_input(declared_body_length: Option<u64>) -> HttpRequestPreflightInput {
    HttpRequestPreflightInput {
        context: RequestContext {
            request_id: "req".into(),
            ..Default::default()
        },
        target: HttpRequestTarget {
            scheme: "https".into(),
            host: "api.example.com".into(),
            port: 443,
            method: "POST".into(),
            path: "/v1/upload".into(),
            query: String::new(),
        },
        declared_body_length,
        headers: vec![header("content-type", "application/json")],
        connection_nominated_headers: Vec::new(),
    }
}

async fn preflight(
    runner: &ChainRunner,
    names: &[&str],
    declared_body_length: Option<u64>,
) -> HttpRequestPreflightOutcome {
    runner
        .preflight_http_request(&chain(names), preflight_input(declared_body_length))
        .await
        .expect("preflight")
}

/// Run `session` over `chunks`, then drain its output.
async fn run_session(
    session: HttpRequestSession,
    chunks: Vec<Vec<u8>>,
    trailers: Vec<HttpHeader>,
) -> (
    std::result::Result<HttpPipelineFinish, HttpMiddlewareFailure>,
    Vec<HttpBodyOutput>,
) {
    let (input_tx, input_rx) = mpsc::channel(4);
    let (output_tx, mut output_rx) = mpsc::channel(4);
    let feed = async move {
        for chunk in chunks {
            if input_tx.send(HttpBodyInput::Chunk(chunk)).await.is_err() {
                return;
            }
        }
        let _ = input_tx.send(HttpBodyInput::End { trailers }).await;
    };
    let collect = async move {
        let mut output = Vec::new();
        while let Some(event) = output_rx.recv().await {
            output.push(event);
        }
        output
    };
    let (finish, (), output) = tokio::join!(session.run(input_rx, output_tx), feed, collect);
    (finish, output)
}

fn output_body(output: &[HttpBodyOutput]) -> Vec<u8> {
    output
        .iter()
        .filter_map(|event| match event {
            HttpBodyOutput::Chunk(data) => Some(data.as_slice()),
            _ => None,
        })
        .flatten()
        .copied()
        .collect()
}

fn output_start_mutations(output: &[HttpBodyOutput]) -> Vec<HeaderMutation> {
    match output.first() {
        Some(HttpBodyOutput::Start {
            header_mutations, ..
        }) => header_mutations.clone(),
        other => panic!("output must begin with Start, got {other:?}"),
    }
}

#[derive(Default)]
struct RecordingObserver {
    contract_failures: Mutex<Vec<ContractFailure>>,
}

impl MiddlewareRuntimeObserver for RecordingObserver {
    fn contract_failure(&self, failure: &ContractFailure) {
        self.contract_failures
            .lock()
            .expect("contract failures")
            .push(failure.clone());
    }

    fn fail_open_not_applied(&self, _entry: &FailOpenNotApplied) {}
}

#[tokio::test]
async fn stream_stage_transforms_a_large_chunked_upload_end_to_end() {
    let stage = stream_stage("test/upper", uppercase);
    let runner = runner_for(std::slice::from_ref(&stage)).await;
    let outcome = preflight(&runner, &["test/upper"], None).await;
    assert!(outcome.allowed, "{}", outcome.reason);
    let session = outcome.session.expect("STREAM stage selected the body");
    assert!(session.streams());
    assert!(!session.withholds_output());
    assert_eq!(session.input_unit_limit(), MAX_HTTP_STREAM_UNIT_BYTES);

    // Twice the platform payload maximum: STREAM has no total byte cap.
    let total = 2 * MAX_MIDDLEWARE_PAYLOAD_BYTES + 1;
    let chunks = vec![b'a'; total]
        .chunks(session.input_unit_limit())
        .map(<[u8]>::to_vec)
        .collect();
    let (finish, output) = run_session(session, chunks, vec![header("x-trace", "done")]).await;

    let finish = finish.expect("upload completes");
    assert!(finish.body_transformed);
    assert_eq!(finish.trailers, [header("x-trace", "done")]);
    assert_eq!(
        output.first(),
        Some(&HttpBodyOutput::Start {
            header_mutations: Vec::new(),
            output_body_bytes: None,
        })
    );
    assert_eq!(
        output.last(),
        Some(&HttpBodyOutput::End {
            trailers: vec![header("x-trace", "done")],
        })
    );
    let body = output_body(&output);
    assert_eq!(body.len(), total);
    assert!(body.iter().all(|byte| *byte == b'A'));
    assert_eq!(
        finish.diagnostics.invocations[0].outcome,
        HttpStageOutcome::Finish
    );
    assert_eq!(finish.diagnostics.invocations[0].input_bytes, total);
    assert_eq!(
        stage.log.wait_for_session_end().await,
        MiddlewareSessionEndReason::Normal
    );
}

#[tokio::test(start_paused = true)]
async fn stream_upload_with_steady_progress_has_no_total_deadline() {
    let stage = stream_stage("test/upper", uppercase);
    let runner = runner_for(std::slice::from_ref(&stage)).await;
    let session = preflight(&runner, &["test/upper"], None)
        .await
        .session
        .expect("session");

    let started = tokio::time::Instant::now();
    let (input_tx, input_rx) = mpsc::channel(4);
    let (output_tx, mut output_rx) = mpsc::channel(4);
    // One chunk every 10 s for 3 minutes, past the 2-minute BUFFERED deadline.
    let feed = async move {
        for _ in 0..18 {
            tokio::time::sleep(Duration::from_secs(10)).await;
            input_tx
                .send(HttpBodyInput::Chunk(b"tick".to_vec()))
                .await
                .expect("pipeline accepts input");
        }
        input_tx
            .send(HttpBodyInput::End {
                trailers: Vec::new(),
            })
            .await
            .expect("pipeline accepts end");
    };
    let collect = async move {
        let mut output = Vec::new();
        while let Some(event) = output_rx.recv().await {
            output.push(event);
        }
        output
    };
    let (finish, (), output) = tokio::join!(session.run(input_rx, output_tx), feed, collect);

    finish.expect("a slow but steady upload succeeds");
    assert!(started.elapsed() >= Duration::from_mins(3));
    assert_eq!(output_body(&output), b"TICK".repeat(18));
}

#[tokio::test(start_paused = true)]
async fn stalled_stream_stage_fails_after_the_idle_timeout() {
    // The stage stops reading input after Begin.
    let stalled = TestStage::new(
        "test/stalled",
        &[HttpBodyMode::Stream],
        |mut io: StageIo| async move {
            loop {
                match io.recv().await {
                    Some(http_event::Event::Preflight(_)) => {
                        io.send(preflight_result(inspect_stream(), Vec::new()))
                            .await;
                    }
                    Some(http_event::Event::Begin(_)) => {
                        io.send(output_start(Vec::new())).await;
                        std::future::pending::<()>().await;
                    }
                    Some(_) => {}
                    None => return,
                }
            }
        },
    );
    let runner = runner_for(std::slice::from_ref(&stalled)).await;
    let session = preflight(&runner, &["test/stalled"], None)
        .await
        .session
        .expect("session");
    let started = tokio::time::Instant::now();
    let (finish, _output) = run_session(session, vec![b"x".to_vec(); 16], Vec::new()).await;

    let failure = finish.expect_err("a stage that stops accepting input fails");
    assert_eq!(
        failure.reason,
        "middleware_failed: middleware_stall_timeout"
    );
    assert_eq!(
        failure.end_reason,
        MiddlewareSessionEndReason::MiddlewareFailure
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed >= HTTP_STREAM_IDLE_TIMEOUT
            && elapsed < HTTP_STREAM_IDLE_TIMEOUT + Duration::from_secs(1),
        "{elapsed:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn stream_stage_that_never_finishes_fails_after_the_idle_timeout() {
    let silent = TestStage::new(
        "test/silent",
        &[HttpBodyMode::Stream],
        |mut io: StageIo| async move {
            while let Some(event) = io.recv().await {
                match event {
                    http_event::Event::Preflight(_) => {
                        io.send(preflight_result(inspect_stream(), Vec::new()))
                            .await;
                    }
                    http_event::Event::Begin(_) => io.send(output_start(Vec::new())).await,
                    _ => {}
                }
            }
        },
    );
    let runner = runner_for(std::slice::from_ref(&silent)).await;
    let session = preflight(&runner, &["test/silent"], None)
        .await
        .session
        .expect("session");
    let started = tokio::time::Instant::now();
    let (finish, _output) = run_session(session, vec![b"x".to_vec()], Vec::new()).await;

    let failure = finish.expect_err("no Finish after input end fails");
    assert_eq!(
        failure.reason,
        "middleware_failed: middleware_stall_timeout"
    );
    assert!(started.elapsed() >= HTTP_STREAM_IDLE_TIMEOUT);
    assert_eq!(
        silent.log.wait_for_session_end().await,
        MiddlewareSessionEndReason::MiddlewareFailure
    );
}

#[tokio::test(start_paused = true)]
async fn downstream_backpressure_does_not_count_as_a_middleware_stall() {
    let echo = stream_stage("test/echo", identity);
    let runner = runner_for(std::slice::from_ref(&echo)).await;
    let session = preflight(&runner, &["test/echo"], None)
        .await
        .session
        .expect("session");
    let (input_tx, input_rx) = mpsc::channel(4);
    let (output_tx, mut output_rx) = mpsc::channel(1);
    let feed = async move {
        for _ in 0..32 {
            input_tx
                .send(HttpBodyInput::Chunk(b"data".to_vec()))
                .await
                .expect("pipeline accepts input");
        }
        input_tx
            .send(HttpBodyInput::End {
                trailers: Vec::new(),
            })
            .await
            .expect("pipeline accepts end");
    };
    // The upstream accepts nothing for twice the stall timeout.
    let collect = async move {
        tokio::time::sleep(2 * HTTP_STREAM_IDLE_TIMEOUT).await;
        let mut output = Vec::new();
        while let Some(event) = output_rx.recv().await {
            output.push(event);
        }
        output
    };
    let (finish, (), output) = tokio::join!(session.run(input_rx, output_tx), feed, collect);

    finish.expect("time held back downstream is not a middleware stall");
    assert_eq!(output_body(&output), b"data".repeat(32));
}

#[tokio::test]
async fn late_header_mutations_follow_every_preflight_mutation_in_chain_order() {
    let first = stream_stage_with_late(
        "test/first",
        vec![write("x-first-pre", "1"), write("x-shared", "first-pre")],
        vec![write("x-first-late", "1"), write("x-shared", "first-late")],
        identity,
    );
    let second = buffered_stage(
        "test/second",
        vec![write("x-second-pre", "1")],
        vec![write("x-second-late", "1")],
        |mut body| {
            body.push(b'!');
            Some(body)
        },
    );
    let third = header_stage("test/third", vec![write("x-shared", "third-pre")]);
    let runner = runner_for(&[first.clone(), second.clone(), third]).await;
    let outcome = preflight(
        &runner,
        &["test/first", "test/second", "test/third"],
        Some(5),
    )
    .await;
    assert!(outcome.allowed, "{}", outcome.reason);
    assert_eq!(
        outcome.header_mutations,
        [
            write("x-first-pre", "1"),
            write("x-shared", "first-pre"),
            write("x-second-pre", "1"),
            write("x-shared", "third-pre"),
        ]
    );
    let (finish, output) = run_session(
        outcome.session.expect("session"),
        vec![b"hello".to_vec()],
        Vec::new(),
    )
    .await;
    finish.expect("pipeline completes");

    let late = output_start_mutations(&output);
    assert_eq!(
        late,
        [
            write("x-first-late", "1"),
            write("x-shared", "first-late"),
            write("x-second-late", "1"),
        ]
    );
    assert_eq!(output_body(&output), b"hello!");

    // Begin carries the stage's preflight head, its own preflight mutations,
    // and earlier stages' late mutations. The first stage's late mutation
    // proves the second stage began only after the first started output.
    let begin = second.log.begin_headers();
    let value = |name: &str| {
        begin
            .iter()
            .find(|header| header.name == name)
            .map(|header| header.value.as_str())
    };
    assert_eq!(value("x-first-late"), Some("1"));
    assert_eq!(value("x-second-pre"), Some("1"));
    assert_eq!(value("x-shared"), Some("first-late"));
    assert_eq!(value("x-second-late"), None);

    // The outgoing head applies every preflight mutation, then every late
    // mutation: an earlier stage's late write wins over a later stage's
    // preflight write to the same header.
    let mut mutations = outcome.header_mutations.clone();
    mutations.extend(late);
    let head = headers::apply(
        headers::HeaderAuthority::Request,
        &preflight_input(Some(5)).headers,
        &[],
        &mutations,
    )
    .expect("valid mutations");
    assert_eq!(
        head.iter()
            .filter(|header| header.name == "x-shared")
            .map(|header| header.value.as_str())
            .collect::<Vec<_>>(),
        ["first-late"]
    );
    assert_eq!(first.log.kinds()[..2], ["preflight", "begin"]);
}

#[tokio::test]
async fn preflight_only_binding_mutates_headers_without_seeing_the_body() {
    let stage = header_stage("test/tagger", vec![write("x-tagged", "yes")]);
    let runner = runner_for(std::slice::from_ref(&stage)).await;
    let outcome = preflight(&runner, &["test/tagger"], Some(1 << 30)).await;

    assert!(outcome.allowed);
    assert!(outcome.session.is_none(), "no stage needs the body");
    assert_eq!(outcome.header_mutations, [write("x-tagged", "yes")]);
    assert!(outcome.headers.contains(&header("x-tagged", "yes")));
    assert!(outcome.diagnostics.invocations[0].transformed);
    let offered = stage.log.preflight();
    assert!(offered.permitted_body_modes.is_empty());
    assert!(offered.late_header_modes.is_empty());
    assert_eq!(offered.declared_input_bytes, Some(1 << 30));
    assert_eq!(
        stage.log.wait_for_session_end().await,
        MiddlewareSessionEndReason::StageSkipped
    );
    assert_eq!(stage.log.kinds(), ["preflight", "session_end"]);
}

#[tokio::test]
async fn preflight_only_binding_cannot_inspect_the_body() {
    let stage = TestStage::new("test/greedy", &[], |mut io: StageIo| async move {
        if let Some(http_event::Event::Preflight(_)) = io.recv().await {
            io.send(preflight_result(inspect_stream(), Vec::new()))
                .await;
        }
        io.drain().await;
    });
    let runner = runner_for(std::slice::from_ref(&stage)).await;
    let outcome = preflight(&runner, &["test/greedy"], Some(4)).await;
    assert!(!outcome.allowed);
    assert_eq!(outcome.reason, "middleware_failed: body_mode_not_permitted");
}

#[tokio::test]
async fn reject_at_preflight_denies_before_the_body_is_read() {
    let opened = stream_stage("test/opened", identity);
    let guard = TestStage::new(
        "test/guard",
        &[HttpBodyMode::Stream],
        |mut io: StageIo| async move {
            if let Some(http_event::Event::Preflight(_)) = io.recv().await {
                io.send(reject("blocked_content")).await;
            }
            io.drain().await;
        },
    );
    let runner = runner_for(&[opened.clone(), guard.clone()]).await;
    let outcome = preflight(&runner, &["test/opened", "test/guard"], Some(5)).await;

    assert!(!outcome.allowed);
    assert!(outcome.session.is_none());
    assert_eq!(
        outcome.reason,
        "middleware_denied:test-guard:blocked_content"
    );
    assert_eq!(
        outcome.denial,
        Some(MiddlewareDenial {
            config_name: "test-guard".into(),
            reason_code: Some("blocked_content".into()),
        })
    );
    for stage in [&opened, &guard] {
        assert_eq!(
            stage.log.wait_for_session_end().await,
            MiddlewareSessionEndReason::MiddlewareDenial
        );
        assert!(!stage.log.kinds().contains(&"begin"));
    }
    assert_eq!(
        outcome
            .diagnostics
            .invocations
            .last()
            .map(|invocation| invocation.outcome),
        Some(HttpStageOutcome::Reject)
    );
}

#[tokio::test]
async fn reject_during_the_body_ends_every_stage_with_a_denial() {
    let first = stream_stage("test/first", identity);
    let guard = TestStage::new(
        "test/guard",
        &[HttpBodyMode::Stream],
        |mut io: StageIo| async move {
            while let Some(event) = io.recv().await {
                match event {
                    http_event::Event::Preflight(_) => {
                        io.send(preflight_result(inspect_stream(), Vec::new()))
                            .await;
                    }
                    http_event::Event::InputChunk(_) => {
                        io.send(reject("secret")).await;
                        break;
                    }
                    _ => {}
                }
            }
            io.drain().await;
        },
    );
    let runner = runner_for(&[first.clone(), guard.clone()]).await;
    let session = preflight(&runner, &["test/first", "test/guard"], None)
        .await
        .session
        .expect("session");
    // Input stays open, so no stage can finish before the rejection.
    let (input_tx, input_rx) = mpsc::channel(4);
    let (output_tx, mut output_rx) = mpsc::channel(4);
    input_tx
        .send(HttpBodyInput::Chunk(b"x".to_vec()))
        .await
        .expect("input");
    let collect = async move {
        let mut output = Vec::new();
        while let Some(event) = output_rx.recv().await {
            output.push(event);
        }
        output
    };
    let (finish, output) = tokio::join!(session.run(input_rx, output_tx), collect);
    drop(input_tx);

    let failure = finish.expect_err("the stage rejected the body");
    assert_eq!(failure.reason, "middleware_denied:test-guard:secret");
    assert_eq!(
        failure.end_reason,
        MiddlewareSessionEndReason::MiddlewareDenial
    );
    assert!(
        output.is_empty(),
        "nothing commits before the last stage starts"
    );
    for stage in [&first, &guard] {
        assert_eq!(
            stage.log.wait_for_session_end().await,
            MiddlewareSessionEndReason::MiddlewareDenial
        );
    }
}

/// A stage that answers `result` to its first body event and then returns,
/// closing both its event and result streams.
fn stage_that_stops_reading(
    mode: HttpBodyMode,
    result: std::result::Result<http_result::Result, TonicStatus>,
) -> TestStage {
    let result = Arc::new(result);
    TestStage::new("test/guard", &[mode], move |mut io: StageIo| {
        let result = Arc::clone(&result);
        async move {
            while let Some(event) = io.recv().await {
                match event {
                    http_event::Event::Preflight(_) => {
                        let decision = match mode {
                            HttpBodyMode::Buffered => inspect_buffered(LIMIT),
                            _ => inspect_stream(),
                        };
                        io.send(preflight_result(decision, Vec::new())).await;
                    }
                    http_event::Event::Begin(_) | http_event::Event::InputChunk(_) => {
                        io.send_raw(match &*result {
                            Ok(result) => Ok(HttpResult {
                                result: Some(result.clone()),
                            }),
                            Err(status) => Err(status.clone()),
                        })
                        .await;
                        return;
                    }
                    _ => {}
                }
            }
        }
    })
}

#[tokio::test]
async fn stages_that_stop_reading_report_their_rejection_or_status() {
    for mode in [HttpBodyMode::Stream, HttpBodyMode::Buffered] {
        for (result, reason) in [
            (Ok(reject("secret")), "middleware_denied:test-guard:secret"),
            (
                Err(TonicStatus::unimplemented("no stage RPC")),
                "middleware_failed: middleware_contract_failure_unimplemented",
            ),
        ] {
            let contract_failure = result.is_err();
            // The input send and the terminal result race; repeat to cover
            // both orders.
            for _ in 0..16 {
                let observer = Arc::new(RecordingObserver::default());
                let runner = runner_for(&[stage_that_stops_reading(mode, result.clone())])
                    .await
                    .with_runtime_observer(observer.clone());
                let session = preflight(&runner, &["test/guard"], None)
                    .await
                    .session
                    .expect("session");
                let (finish, _output) =
                    run_session(session, vec![b"x".to_vec(); 16], Vec::new()).await;
                assert_eq!(
                    finish.expect_err("the stage ended the exchange").reason,
                    reason,
                    "{mode:?}"
                );
                assert_eq!(
                    observer.contract_failures.lock().expect("failures").len(),
                    usize::from(contract_failure),
                    "{mode:?}"
                );
                assert_eq!(runner.take_reconciliation_request(), contract_failure);
            }
        }
    }
}

#[tokio::test]
async fn buffered_is_offered_only_within_the_stage_limit() {
    let both = TestStage::new(
        "test/both",
        &[HttpBodyMode::Buffered, HttpBodyMode::Stream],
        |mut io: StageIo| async move {
            if let Some(http_event::Event::Preflight(_)) = io.recv().await {
                io.send(preflight_result(continue_without_body(), Vec::new()))
                    .await;
            }
            io.drain().await;
        },
    )
    .with_limit(16);
    let runner = runner_for(std::slice::from_ref(&both)).await;
    preflight(&runner, &["test/both"], Some(17)).await;
    let offered = both.log.preflight();
    assert_eq!(offered.permitted_body_modes, [HttpBodyMode::Stream as i32]);
    assert_eq!(offered.late_header_modes, [HttpBodyMode::Stream as i32]);
    let limits = offered.limits.expect("limits");
    assert_eq!(limits.max_chunk_bytes, 16);
    assert_eq!(
        limits.idle_timeout,
        Some(prost_types::Duration {
            seconds: 30,
            nanos: 0
        })
    );
}

#[tokio::test]
async fn buffered_stage_rejects_input_over_its_limit() {
    let stage = buffered_stage("test/small", Vec::new(), Vec::new(), |_| None).with_limit(16);
    let runner = runner_for(std::slice::from_ref(&stage)).await;
    // A chunked request declares no length, so BUFFERED is offered.
    let session = preflight(&runner, &["test/small"], None)
        .await
        .session
        .expect("session");
    assert!(session.withholds_output());
    let (finish, output) = run_session(session, vec![vec![b'x'; 17]], Vec::new()).await;
    let failure = finish.expect_err("over-limit input fails closed");
    assert_eq!(
        failure.reason,
        "middleware_failed: buffered_input_over_capacity"
    );
    assert!(output.is_empty());
}

#[tokio::test]
async fn buffered_output_declares_its_length_only_without_trailers() {
    let stage = buffered_stage("test/whole", Vec::new(), Vec::new(), |_| None);
    let runner = runner_for(std::slice::from_ref(&stage)).await;
    for (trailers, declared) in [
        (Vec::new(), Some(4)),
        (vec![header("x-trace", "original")], None),
    ] {
        let session = preflight(&runner, &["test/whole"], None)
            .await
            .session
            .expect("session");
        let (finish, output) = run_session(session, vec![b"data".to_vec()], trailers.clone()).await;
        assert_eq!(finish.expect("chain completes").trailers, trailers);
        assert!(
            matches!(
                output.first(),
                Some(HttpBodyOutput::Start { output_body_bytes, .. }) if *output_body_bytes == declared
            ),
            "{output:?}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn buffered_stage_keeps_the_whole_body_deadline() {
    let stage = buffered_stage("test/whole", Vec::new(), Vec::new(), |_| None);
    let runner = runner_for(std::slice::from_ref(&stage)).await;
    let session = preflight(&runner, &["test/whole"], None)
        .await
        .session
        .expect("session");
    let started = tokio::time::Instant::now();
    let (input_tx, input_rx) = mpsc::channel(4);
    let (output_tx, _output_rx) = mpsc::channel(4);
    let feed = async move {
        // A steady trickle that would satisfy STREAM still exceeds the
        // BUFFERED whole-body deadline.
        for _ in 0..30 {
            if input_tx
                .send(HttpBodyInput::Chunk(b"x".to_vec()))
                .await
                .is_err()
            {
                return;
            }
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    };
    let run = async {
        let finish = session.run(input_rx, output_tx).await;
        (finish, started.elapsed())
    };
    let ((finish, elapsed), ()) = tokio::join!(run, feed);
    let failure = finish.expect_err("BUFFERED keeps its 2-minute limit");
    assert_eq!(failure.reason, "middleware_failed: middleware_body_timeout");
    assert!(elapsed >= HTTP_BUFFERED_BODY_TIMEOUT, "{elapsed:?}");
    assert!(
        elapsed < HTTP_BUFFERED_BODY_TIMEOUT + Duration::from_secs(1),
        "{elapsed:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn buffered_exchange_uses_the_binding_timeout() {
    let slow = TestStage::new(
        "test/slow",
        &[HttpBodyMode::Buffered],
        |mut io: StageIo| async move {
            while let Some(event) = io.recv().await {
                match event {
                    http_event::Event::Preflight(_) => {
                        io.send(preflight_result(inspect_buffered(LIMIT), Vec::new()))
                            .await;
                    }
                    http_event::Event::BufferedBody(_) => {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        io.send(buffered(None, Vec::new())).await;
                    }
                    _ => {}
                }
            }
        },
    );
    let runner = runner_for(std::slice::from_ref(&slow)).await;
    let session = preflight(&runner, &["test/slow"], Some(2))
        .await
        .session
        .expect("session");
    let (finish, _output) = run_session(session, vec![b"hi".to_vec()], Vec::new()).await;
    let failure = finish.expect_err("the exchange exceeds the 500 ms default timeout");
    assert_eq!(failure.reason, "middleware_failed: middleware_timeout");
}

#[tokio::test]
async fn unimplemented_version_2_stage_fails_closed_and_requests_reconciliation() {
    /// Advertises a version 2 binding but keeps the default stage RPC.
    struct Unimplemented;

    #[tonic::async_trait]
    impl InProcessMiddleware for Unimplemented {
        async fn describe(&self) -> MiddlewareManifest {
            stream_stage("test/missing", identity).describe().await
        }

        async fn validate_config(&self, _name: &str, _config: &prost_types::Struct) -> Result<()> {
            Ok(())
        }

        async fn evaluate_http_request(
            &self,
            _request: HttpRequestView<'_>,
        ) -> Result<HttpRequestResult> {
            Err(miette!("version 2 test middleware"))
        }
    }

    let observer = Arc::new(RecordingObserver::default());
    let runner = ChainRunner::from_registry(
        MiddlewareRegistry::connect_services_with_http_v2(
            vec![Arc::new(Unimplemented)],
            Vec::new(),
        )
        .await
        .expect("registry"),
    )
    .with_runtime_observer(observer.clone());
    let outcome = preflight(&runner, &["test/missing"], Some(1)).await;

    assert!(!outcome.allowed);
    assert_eq!(
        outcome.reason,
        "middleware_failed: middleware_contract_failure_unimplemented"
    );
    assert_eq!(
        observer.contract_failures.lock().expect("failures").clone(),
        [ContractFailure {
            config_name: "test-missing".into(),
            implementation: "test/missing".into(),
            direction: HttpDirection::Request,
            protocol: HttpProtocol::V2,
            kind: ContractFailureKind::Unimplemented,
        }]
    );
    assert!(runner.take_reconciliation_request());
}

#[tokio::test]
async fn decode_failure_mid_body_fails_closed_and_requests_reconciliation() {
    let broken = TestStage::new(
        "test/broken",
        &[HttpBodyMode::Stream],
        |mut io: StageIo| async move {
            while let Some(event) = io.recv().await {
                match event {
                    http_event::Event::Preflight(_) => {
                        io.send(preflight_result(inspect_stream(), Vec::new()))
                            .await;
                    }
                    http_event::Event::InputChunk(_) => {
                        io.send_raw(Err(TonicStatus::internal(
                        "failed to decode Protobuf message: HttpResult.result: invalid wire type",
                    )))
                    .await;
                    }
                    _ => {}
                }
            }
        },
    );
    let observer = Arc::new(RecordingObserver::default());
    let runner = runner_for(std::slice::from_ref(&broken))
        .await
        .with_runtime_observer(observer.clone());
    let session = preflight(&runner, &["test/broken"], None)
        .await
        .session
        .expect("session");
    let (finish, _output) = run_session(session, vec![b"x".to_vec()], Vec::new()).await;

    let failure = finish.expect_err("a decode failure fails closed");
    assert_eq!(
        failure.reason,
        "middleware_failed: middleware_contract_failure_decode_failure"
    );
    assert_eq!(
        observer.contract_failures.lock().expect("failures")[0].kind,
        ContractFailureKind::Decode
    );
    assert!(runner.take_reconciliation_request());
}

#[tokio::test]
async fn unknown_result_variants_are_contract_failures() {
    let unset_result = TestStage::new(
        "test/unset",
        &[HttpBodyMode::Stream],
        |mut io: StageIo| async move {
            if let Some(http_event::Event::Preflight(_)) = io.recv().await {
                io.send_raw(Ok(HttpResult { result: None })).await;
            }
            io.drain().await;
        },
    );
    let unset_mode = TestStage::new(
        "test/unset-mode",
        &[HttpBodyMode::Stream],
        |mut io: StageIo| async move {
            if let Some(http_event::Event::Preflight(_)) = io.recv().await {
                io.send(preflight_result(
                    http_preflight_result::Decision::Inspect(HttpInspect { mode: None }),
                    Vec::new(),
                ))
                .await;
            }
            io.drain().await;
        },
    );
    for (stage, name) in [
        (unset_result, "test/unset"),
        (unset_mode, "test/unset-mode"),
    ] {
        let runner = runner_for(std::slice::from_ref(&stage)).await;
        let outcome = preflight(&runner, &[name], Some(1)).await;
        assert!(!outcome.allowed, "{name}");
        assert_eq!(
            outcome.reason, "middleware_failed: middleware_contract_failure_unknown_result",
            "{name}"
        );
        assert!(runner.take_reconciliation_request(), "{name}");
    }
}

#[tokio::test]
async fn unresolved_entries_follow_on_error_before_preflight() {
    let stage = header_stage("test/tagger", vec![write("x-tagged", "yes")]);
    let runner = runner_for(std::slice::from_ref(&stage)).await;
    let mut entries = chain(&["test/missing", "test/tagger"]);
    entries[0].on_error = OnError::FailOpen;
    let outcome = runner
        .preflight_http_request(&entries, preflight_input(Some(0)))
        .await
        .expect("preflight");
    assert!(outcome.allowed);
    assert_eq!(
        outcome.diagnostics.invocations[0].outcome,
        HttpStageOutcome::FailOpen
    );
    assert_eq!(outcome.header_mutations, [write("x-tagged", "yes")]);

    entries[0].on_error = OnError::FailClosed;
    let outcome = runner
        .preflight_http_request(&entries, preflight_input(Some(0)))
        .await
        .expect("preflight");
    assert!(!outcome.allowed);
    assert_eq!(outcome.reason, "middleware_failed: binding_not_described");
}

#[tokio::test]
async fn output_is_resplit_to_the_next_stages_chunk_limit() {
    let first = stream_stage("test/first", identity);
    let small = stream_stage("test/small", identity).with_limit(1024);
    let runner = runner_for(&[first, small.clone()]).await;
    let session = preflight(&runner, &["test/first", "test/small"], None)
        .await
        .session
        .expect("session");
    let (finish, output) = run_session(session, vec![vec![b'x'; 5000]], Vec::new()).await;
    finish.expect("pipeline completes");
    assert_eq!(output_body(&output).len(), 5000);
    let sizes = small.log.input_chunk_sizes();
    assert_eq!(sizes.iter().sum::<usize>(), 5000);
    assert!(sizes.iter().all(|size| *size <= 1024), "{sizes:?}");
}

#[tokio::test]
async fn dropping_a_running_session_cancels_every_stage() {
    let first = stream_stage("test/first", identity);
    let second = stream_stage("test/second", identity);
    let runner = runner_for(&[first.clone(), second.clone()]).await;
    let session = preflight(&runner, &["test/first", "test/second"], None)
        .await
        .session
        .expect("session");
    let (input_tx, input_rx) = mpsc::channel(4);
    let (output_tx, mut output_rx) = mpsc::channel(4);
    input_tx
        .send(HttpBodyInput::Chunk(b"partial".to_vec()))
        .await
        .expect("input");
    let mut run = Box::pin(session.run(input_rx, output_tx));
    // Drive the pipeline until the upload is in flight, then drop it.
    let received = tokio::select! {
        _ = &mut run => panic!("the upload has not ended"),
        received = async {
            let mut received = Vec::new();
            while let Some(event) = output_rx.recv().await {
                let chunk = matches!(event, HttpBodyOutput::Chunk(_));
                received.push(event);
                if chunk {
                    break;
                }
            }
            received
        } => received,
    };
    assert_eq!(output_body(&received), b"partial");
    drop(run);
    for stage in [&first, &second] {
        assert_eq!(
            stage.log.wait_for_session_end().await,
            MiddlewareSessionEndReason::Cancellation
        );
    }
}

#[tokio::test]
async fn session_budget_bounds_concurrent_request_sessions() {
    let stage = stream_stage("test/upper", uppercase);
    let runner = runner_for(std::slice::from_ref(&stage)).await;
    let mut sessions = Vec::new();
    for _ in 0..MAX_CONCURRENT_MIDDLEWARE_SESSIONS {
        let outcome = preflight(&runner, &["test/upper"], None).await;
        sessions.push(outcome.session.expect("session within budget"));
    }
    let outcome = preflight(&runner, &["test/upper"], None).await;
    assert!(!outcome.allowed);
    assert!(outcome.session_capacity_exhausted);

    drop(sessions.pop());
    let outcome = preflight(&runner, &["test/upper"], None).await;
    assert!(outcome.session.is_some(), "an ended session frees its slot");
}

#[tokio::test]
async fn collector_runs_legacy_and_version_2_stages_in_chain_order() {
    let v2 = buffered_stage(
        "test/v2",
        vec![write("x-v2-pre", "1")],
        vec![write("x-v2-late", "1")],
        |mut body| {
            body.extend_from_slice(b"+v2");
            Some(body)
        },
    );
    let services: Vec<Arc<dyn InProcessMiddleware>> = vec![
        Arc::new(LegacyStage {
            name: "test/before",
            suffix: b"+before",
        }),
        Arc::new(v2),
        Arc::new(LegacyStage {
            name: "test/after",
            suffix: b"+after",
        }),
    ];
    let runner = ChainRunner::from_registry(
        MiddlewareRegistry::connect_services_with_http_v2(services, Vec::new())
            .await
            .expect("registry"),
    );
    let input = HttpRequestInput {
        request_id: "req".into(),
        sandbox_id: "sbx-id".into(),
        sandbox_name: "sbx".into(),
        workspace: "default".into(),
        scheme: "https".into(),
        host: "api.example.com".into(),
        port: 443,
        method: "POST".into(),
        path: "/v1".into(),
        query: String::new(),
        headers: Vec::new(),
        connection_nominated_headers: Vec::new(),
        body: b"body".to_vec(),
    };
    let outcome = runner
        .evaluate(&chain(&["test/before", "test/v2", "test/after"]), input)
        .await
        .expect("evaluate");

    assert!(outcome.allowed, "{}", outcome.reason);
    assert_eq!(outcome.body, b"body+before+v2+after");
    assert_eq!(
        outcome.header_mutations,
        [
            write("x-test-before", "legacy"),
            write("x-v2-pre", "1"),
            write("x-v2-late", "1"),
            write("x-test-after", "legacy"),
        ]
    );
    assert_eq!(
        outcome
            .applied
            .iter()
            .map(|invocation| (invocation.name.as_str(), invocation.transformed))
            .collect::<Vec<_>>(),
        [
            ("test-before", true),
            ("test-v2", true),
            ("test-after", true)
        ]
    );
}

/// Fake legacy request adapter. It inspects with the offered BUFFERED limit,
/// then applies its own limit to the body it receives as a `fail_open`
/// adapter does: past that limit it reports and passes the body on.
fn legacy_adapter_stage(
    context: &LegacyStageContext,
    log: Arc<StageLog>,
) -> Arc<dyn HttpStageTransport> {
    struct Adapter {
        own_limit: usize,
        config_name: String,
        reports: Arc<dyn StageReportSink>,
        log: Arc<StageLog>,
    }

    #[tonic::async_trait]
    impl HttpStageTransport for Adapter {
        async fn open(
            &self,
            events: mpsc::Receiver<HttpEvent>,
        ) -> std::result::Result<HttpResultStream, TonicStatus> {
            let (results, receiver) = mpsc::channel(4);
            let mut io = StageIo {
                events,
                results,
                log: Arc::clone(&self.log),
            };
            let own_limit = self.own_limit;
            let config_name = self.config_name.clone();
            let reports = Arc::clone(&self.reports);
            tokio::spawn(async move {
                while let Some(event) = io.recv().await {
                    match event {
                        http_event::Event::Preflight(preflight) => {
                            let limit = preflight
                                .limits
                                .map_or(1, |limits| limits.max_buffered_body_bytes);
                            io.send(preflight_result(inspect_buffered(limit), Vec::new()))
                                .await;
                        }
                        http_event::Event::BufferedBody(mut body) => {
                            if body.data.len() > own_limit {
                                reports.report(
                                    &config_name,
                                    StageReport::LegacyFailOpen {
                                        reason: "request_body_over_capacity".into(),
                                    },
                                );
                                io.send(buffered(None, Vec::new())).await;
                            } else {
                                body.data.push(b'!');
                                io.send(buffered(Some(body.data), Vec::new())).await;
                            }
                        }
                        _ => {}
                    }
                }
            });
            Ok(Box::pin(ReceiverStream::new(receiver)))
        }
    }

    Arc::new(Adapter {
        own_limit: context.entry.max_payload_bytes(),
        config_name: context.entry.entry.name.clone(),
        reports: Arc::clone(&context.reports),
        log,
    })
}

/// Legacy in-process service with `max_payload_bytes`, for adapter tests.
struct LimitedLegacy {
    name: &'static str,
    max_payload_bytes: u64,
    response: bool,
}

#[tonic::async_trait]
impl InProcessMiddleware for LimitedLegacy {
    async fn describe(&self) -> MiddlewareManifest {
        let mut manifest = LegacyStage {
            name: self.name,
            suffix: b"",
        }
        .describe()
        .await;
        manifest.bindings[0].max_payload_bytes = self.max_payload_bytes;
        if self.response {
            manifest.bindings[0].operation = SupervisorMiddlewareOperation::HttpResponse as i32;
            manifest.bindings[0].phase = SupervisorMiddlewarePhase::PreReturn as i32;
        }
        manifest
    }

    async fn validate_config(&self, _name: &str, _config: &prost_types::Struct) -> Result<()> {
        Ok(())
    }

    async fn evaluate_http_request(
        &self,
        _request: HttpRequestView<'_>,
    ) -> Result<HttpRequestResult> {
        Err(miette!("legacy RPC is reached through the adapter"))
    }
}

async fn legacy_runner(response: bool) -> ChainRunner {
    ChainRunner::from_registry(
        MiddlewareRegistry::connect_services_with_http_v2(
            vec![
                Arc::new(LimitedLegacy {
                    name: "test/small",
                    max_payload_bytes: 16,
                    response,
                }),
                Arc::new(LimitedLegacy {
                    name: "test/large",
                    max_payload_bytes: 64,
                    response,
                }),
            ],
            Vec::new(),
        )
        .await
        .expect("registry"),
    )
}

#[tokio::test]
async fn legacy_request_stages_collect_up_to_the_chain_legacy_limit() {
    let log = Arc::new(StageLog::default());
    let adapter_log = Arc::clone(&log);
    let _adapters = test_support::install(move |context| {
        assert_eq!(context.direction, HttpDirection::Request);
        legacy_adapter_stage(context, Arc::clone(&adapter_log))
    });
    let runner = legacy_runner(false).await;
    let mut entries = chain(&["test/small", "test/large"]);
    entries[0].on_error = OnError::FailOpen;
    let described = runner.describe_chain(&entries).await.expect("describe");

    for (body_len, expected) in [
        // Within every stage's limit: both stages run.
        (8, Ok(format!("{}!!", "x".repeat(8)))),
        // Past the small stage's limit: that adapter passes the body on.
        (32, Ok(format!("{}!", "x".repeat(32)))),
        // Past every legacy limit: denied before upstream contact.
        (65, Err("middleware_failed: buffered_input_over_capacity")),
    ] {
        let outcome = runner
            .preflight_described_http_request(described.clone(), preflight_input(None))
            .await
            .expect("preflight");
        let session = outcome.session.expect("session");
        let (finish, output) = run_session(session, vec![vec![b'x'; body_len]], Vec::new()).await;
        match expected {
            Ok(body) => {
                let finish = finish.expect("chain completes");
                assert_eq!(String::from_utf8(output_body(&output)).expect("utf8"), body);
                let small = &finish.diagnostics.invocations[0];
                if body_len == 32 {
                    assert_eq!(small.outcome, HttpStageOutcome::FailOpen);
                    assert!(small.failed);
                    assert_eq!(
                        small.failure_reason.as_deref(),
                        Some("request_body_over_capacity")
                    );
                    assert_eq!(
                        finish.diagnostics.reports,
                        [(
                            "test-small".to_string(),
                            StageReport::LegacyFailOpen {
                                reason: "request_body_over_capacity".into(),
                            },
                        )]
                    );
                } else {
                    assert_eq!(small.outcome, HttpStageOutcome::Replacement);
                    assert!(finish.diagnostics.reports.is_empty());
                }
            }
            Err(reason) => {
                assert_eq!(finish.expect_err("over the chain limit").reason, reason);
            }
        }
    }
    // Both stages were offered the chain's largest legacy limit.
    assert_eq!(
        log.preflight()
            .limits
            .expect("limits")
            .max_buffered_body_bytes,
        64
    );
}

#[tokio::test(start_paused = true)]
async fn legacy_request_stages_have_no_whole_body_deadline() {
    let log = Arc::new(StageLog::default());
    let _adapters =
        test_support::install(move |context| legacy_adapter_stage(context, Arc::clone(&log)));
    let runner = legacy_runner(false).await;
    let mut session = runner
        .preflight_http_request(&chain(&["test/large"]), preflight_input(None))
        .await
        .expect("preflight")
        .session
        .expect("session");
    session.set_timeouts(PipelineTimeouts {
        buffered_body: Duration::from_secs(5),
        ..PipelineTimeouts::default()
    });
    let (input_tx, input_rx) = mpsc::channel(4);
    let (output_tx, mut output_rx) = mpsc::channel(4);
    // 0.1.x collected a request body for as long as the client took.
    let feed = async move {
        input_tx
            .send(HttpBodyInput::Chunk(b"early".to_vec()))
            .await
            .expect("input");
        tokio::time::sleep(Duration::from_secs(10)).await;
        input_tx
            .send(HttpBodyInput::Chunk(b"late".to_vec()))
            .await
            .expect("input");
        input_tx
            .send(HttpBodyInput::End {
                trailers: Vec::new(),
            })
            .await
            .expect("end");
    };
    let collect = async move {
        let mut output = Vec::new();
        while let Some(event) = output_rx.recv().await {
            output.push(event);
        }
        output
    };
    let (finish, (), output) = tokio::join!(session.run(input_rx, output_tx), feed, collect);
    finish.expect("a slow legacy request body is collected");
    assert_eq!(output_body(&output), b"earlylate!");
}

struct ResponseHead;

impl StageHead for ResponseHead {
    fn preflight_head(
        &self,
        entry: &DescribedChainEntry,
        headers: &[HttpHeader],
    ) -> openshell_core::proto::http_preflight::Head {
        openshell_core::proto::http_preflight::Head::Response(
            openshell_core::proto::HttpResponsePreflightHead {
                status_code: 200,
                headers: headers.to_vec(),
                middleware_name: entry.entry.implementation.clone(),
                ..Default::default()
            },
        )
    }

    fn permitted_body_modes(&self, _entry: &DescribedChainEntry) -> Vec<HttpBodyMode> {
        Vec::new()
    }
}

/// Run one legacy response stage named `name` over `chunks`.
async fn run_legacy_response(
    on_error: OnError,
    timeouts: PipelineTimeouts,
    chunks: Vec<(Duration, Vec<u8>)>,
) -> (
    std::result::Result<HttpPipelineFinish, HttpMiddlewareFailure>,
    Vec<HttpBodyOutput>,
) {
    let runner = legacy_runner(true).await;
    let mut entries = chain(&["test/small"]);
    entries[0].on_error = on_error;
    let described = runner
        .describe_http_response_chain(&entries)
        .await
        .expect("describe");
    let mut pipeline = pipeline::preflight(
        &runner,
        &described,
        PipelineSpec {
            direction: HttpDirection::Response,
            head_authority: headers::HeaderAuthority::Response,
            trailer_authority: headers::HeaderAuthority::ResponseTrailers,
            connection_nominated: Vec::new(),
            timeouts,
        },
        Vec::new(),
        None,
        &ResponseHead,
    )
    .await
    .pipeline
    .expect("the legacy stage inspects the body");
    pipeline.set_timeouts(timeouts);
    let (input_tx, input_rx) = mpsc::channel(4);
    let (output_tx, mut output_rx) = mpsc::channel(4);
    let feed = async move {
        for (delay, chunk) in chunks {
            tokio::time::sleep(delay).await;
            if input_tx.send(HttpBodyInput::Chunk(chunk)).await.is_err() {
                return;
            }
        }
        let _ = input_tx
            .send(HttpBodyInput::End {
                trailers: Vec::new(),
            })
            .await;
    };
    let collect = async move {
        let mut output = Vec::new();
        while let Some(event) = output_rx.recv().await {
            output.push(event);
        }
        output
    };
    let (finish, (), output) = tokio::join!(pipeline.run(input_rx, output_tx), feed, collect);
    (finish, output)
}

#[tokio::test]
async fn fail_open_legacy_response_stage_releases_the_original_past_its_limit() {
    let log = Arc::new(StageLog::default());
    let _adapters =
        test_support::install(move |context| legacy_adapter_stage(context, Arc::clone(&log)));
    let body = vec![b'x'; 32];
    let (finish, output) = run_legacy_response(
        OnError::FailOpen,
        PipelineTimeouts::default(),
        vec![
            (Duration::ZERO, body[..10].to_vec()),
            (Duration::ZERO, body[10..].to_vec()),
        ],
    )
    .await;
    let finish = finish.expect("fail_open passes a large response through");
    assert_eq!(output_body(&output), body);
    assert_eq!(
        finish.diagnostics.reports,
        [(
            "test-small".to_string(),
            StageReport::LegacyFailOpen {
                reason: "whole_body_over_capacity".into(),
            },
        )]
    );
    assert_eq!(
        finish.diagnostics.invocations[0].outcome,
        HttpStageOutcome::FailOpen
    );

    let (finish, _output) = run_legacy_response(
        OnError::FailClosed,
        PipelineTimeouts::default(),
        vec![(Duration::ZERO, body)],
    )
    .await;
    assert_eq!(
        finish.expect_err("fail_closed").reason,
        "middleware_failed: buffered_input_over_capacity"
    );
}

#[tokio::test(start_paused = true)]
async fn fail_open_legacy_response_stage_releases_the_original_at_the_accumulation_deadline() {
    let log = Arc::new(StageLog::default());
    let _adapters =
        test_support::install(move |context| legacy_adapter_stage(context, Arc::clone(&log)));
    let timeouts = PipelineTimeouts {
        buffered_body: Duration::from_secs(5),
        ..PipelineTimeouts::default()
    };
    let chunks = vec![
        (Duration::ZERO, b"early".to_vec()),
        (Duration::from_secs(10), b"late".to_vec()),
    ];
    let (finish, output) = run_legacy_response(OnError::FailOpen, timeouts, chunks.clone()).await;
    let finish = finish.expect("fail_open releases the original");
    assert_eq!(output_body(&output), b"earlylate");
    assert_eq!(
        finish.diagnostics.reports,
        [(
            "test-small".to_string(),
            StageReport::LegacyFailOpen {
                reason: "whole_body_accumulation_timeout".into(),
            },
        )]
    );

    let (finish, _output) = run_legacy_response(OnError::FailClosed, timeouts, chunks).await;
    assert_eq!(
        finish.expect_err("fail_closed").reason,
        "middleware_failed: middleware_body_timeout"
    );
}

#[tokio::test]
async fn legacy_stage_context_carries_nominated_headers_a_chain_clock_and_reports() {
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&contexts);
    let _adapters = test_support::install(move |context| {
        // A fail_open adapter answering a declared length over its limit
        // continues at preflight and reports it.
        context.reports.report(
            &context.entry.entry.name,
            StageReport::LegacyFailOpen {
                reason: "request_body_over_capacity".into(),
            },
        );
        seen.lock().expect("contexts").push(context.clone());
        Arc::new(ContinueTransport)
    });
    let runner = legacy_runner(false).await;
    let mut input = preflight_input(Some(1));
    input.connection_nominated_headers = vec!["x-hop".into()];
    let outcome = runner
        .preflight_http_request(&chain(&["test/small"]), input)
        .await
        .expect("preflight");
    assert!(outcome.allowed);
    assert_eq!(
        outcome.diagnostics.invocations[0].outcome,
        HttpStageOutcome::FailOpen
    );
    assert_eq!(outcome.diagnostics.reports.len(), 1);

    let context = contexts.lock().expect("contexts")[0].clone();
    assert_eq!(
        &*context.connection_nominated_headers,
        ["x-hop".to_string()]
    );
    // The clock starts on first use, not at preflight.
    tokio::time::sleep(Duration::from_millis(20)).await;
    let before = tokio::time::Instant::now();
    let deadline = context.chain_clock.deadline();
    assert!(deadline >= before + MAX_MIDDLEWARE_CHAIN_TIMEOUT);
    assert_eq!(context.chain_clock.deadline(), deadline);
}

/// Transport that continues at preflight.
struct ContinueTransport;

#[tonic::async_trait]
impl HttpStageTransport for ContinueTransport {
    async fn open(
        &self,
        events: mpsc::Receiver<HttpEvent>,
    ) -> std::result::Result<HttpResultStream, TonicStatus> {
        let (results, receiver) = mpsc::channel(4);
        let mut io = StageIo {
            events,
            results,
            log: Arc::default(),
        };
        tokio::spawn(async move {
            if let Some(http_event::Event::Preflight(_)) = io.recv().await {
                io.send(preflight_result(continue_without_body(), Vec::new()))
                    .await;
            }
            io.drain().await;
        });
        Ok(Box::pin(ReceiverStream::new(receiver)))
    }
}

#[tokio::test]
async fn legacy_adapter_contract_failures_are_reported_as_legacy() {
    /// Adapter whose legacy RPC answers `UNIMPLEMENTED`.
    struct Unimplemented;

    #[tonic::async_trait]
    impl HttpStageTransport for Unimplemented {
        async fn open(
            &self,
            events: mpsc::Receiver<HttpEvent>,
        ) -> std::result::Result<HttpResultStream, TonicStatus> {
            let (results, receiver) = mpsc::channel(4);
            let mut io = StageIo {
                events,
                results,
                log: Arc::default(),
            };
            tokio::spawn(async move {
                while let Some(event) = io.recv().await {
                    match event {
                        http_event::Event::Preflight(preflight) => {
                            let limit = preflight
                                .limits
                                .map_or(1, |limits| limits.max_buffered_body_bytes);
                            io.send(preflight_result(inspect_buffered(limit), Vec::new()))
                                .await;
                        }
                        http_event::Event::BufferedBody(_) => {
                            io.send_raw(Err(TonicStatus::unimplemented("no legacy RPC")))
                                .await;
                        }
                        _ => {}
                    }
                }
            });
            Ok(Box::pin(ReceiverStream::new(receiver)))
        }
    }

    let _adapters = test_support::install(|_| Arc::new(Unimplemented));
    let observer = Arc::new(RecordingObserver::default());
    let runner = legacy_runner(false)
        .await
        .with_runtime_observer(observer.clone());
    let mut entries = chain(&["test/small"]);
    entries[0].on_error = OnError::FailOpen;
    let session = runner
        .preflight_http_request(&entries, preflight_input(Some(2)))
        .await
        .expect("preflight")
        .session
        .expect("session");
    let (finish, _output) = run_session(session, vec![b"hi".to_vec()], Vec::new()).await;
    assert_eq!(
        finish
            .expect_err("contract failures ignore fail_open")
            .reason,
        "middleware_failed: middleware_contract_failure_unimplemented"
    );
    let failures = observer.contract_failures.lock().expect("failures").clone();
    assert_eq!(failures[0].protocol, HttpProtocol::Legacy);
    assert!(runner.take_reconciliation_request());
}

#[tokio::test]
async fn legacy_entries_without_an_adapter_fail_closed_in_the_pipeline() {
    let runner = legacy_runner(false).await;
    let outcome = runner
        .preflight_http_request(&chain(&["test/small"]), preflight_input(Some(1)))
        .await
        .expect("preflight");
    assert!(!outcome.allowed);
    assert_eq!(
        outcome.reason,
        "middleware_failed: http_stage_not_executable"
    );
}
