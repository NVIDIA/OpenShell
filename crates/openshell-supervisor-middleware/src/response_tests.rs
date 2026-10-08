// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP response pipeline behavior, and the engine hooks legacy response
//! adapters plug into.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use futures::future::BoxFuture;
use openshell_core::extension_protocol::{ExtensionFamily, extension_metadata};
use openshell_core::proto::{
    ExistingHeaderAction, HttpBodyModeUnavailable, HttpBodyUnavailableReason, HttpBufferedMode,
    HttpBufferedResult, HttpContinue, HttpFinish, HttpHeader, HttpInspect, HttpOutputChunk,
    HttpOutputStart, HttpPreflight, HttpPreflightResult, HttpReject, HttpRequestResult,
    HttpRequestTarget, HttpResponsePreflightHead, HttpResult, HttpStreamMode, HttpUnchanged,
    MiddlewareDiagnostics, MiddlewareSessionEndReason, RequestContext, WriteHeader,
    header_mutation, http_buffered_result, http_event, http_inspect, http_preflight,
    http_preflight_result, http_result,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use super::*;
use crate::legacy::hooks::{LegacyResponseControl, LegacyStage, LegacyStageContext, test_support};
use crate::pipeline::{BodyModeOffer, Pipeline, PipelineSpec, PipelineTimeouts, StageHead};

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

fn handler<F>(handler: impl Fn(StageIo) -> F + Send + Sync + 'static) -> Handler
where
    F: Future<Output = ()> + Send + 'static,
{
    Arc::new(move |io| Box::pin(handler(io)))
}

fn open(
    handler: &Handler,
    log: &Arc<StageLog>,
    events: mpsc::Receiver<HttpEvent>,
) -> HttpResultStream {
    let (results, receiver) = mpsc::channel(4);
    tokio::spawn(handler(StageIo {
        events,
        results,
        log: Arc::clone(log),
    }));
    Box::pin(ReceiverStream::new(receiver))
}

/// In-process response middleware driven by a test handler. A legacy stage
/// only describes its binding: its transport comes from the adapter seam.
#[derive(Clone)]
struct TestStage {
    name: &'static str,
    legacy: bool,
    modes: Vec<HttpBodyMode>,
    max_payload_bytes: u64,
    handler: Handler,
    log: Arc<StageLog>,
}

impl TestStage {
    fn new<F>(
        name: &'static str,
        modes: &[HttpBodyMode],
        stage: impl Fn(StageIo) -> F + Send + Sync + 'static,
    ) -> Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        Self {
            name,
            legacy: false,
            modes: modes.to_vec(),
            max_payload_bytes: if modes.is_empty() { 0 } else { LIMIT },
            handler: handler(stage),
            log: Arc::default(),
        }
    }

    /// The same stage behind a legacy binding, run by a test adapter.
    fn legacy(mut self) -> Self {
        self.legacy = true;
        self.modes.clear();
        self.max_payload_bytes = LIMIT;
        self
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
                operation: SupervisorMiddlewareOperation::HttpResponse as i32,
                phase: SupervisorMiddlewarePhase::PreReturn as i32,
                max_payload_bytes: self.max_payload_bytes,
                http_protocol_version: if self.legacy { 0 } else { 2 },
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
        Err(miette!("response test middleware"))
    }

    async fn open_http_response_stage(
        &self,
        events: mpsc::Receiver<HttpEvent>,
    ) -> std::result::Result<HttpResultStream, TonicStatus> {
        Ok(open(&self.handler, &self.log, events))
    }
}

/// Test adapter transport for a legacy [`TestStage`].
struct AdapterTransport {
    handler: Handler,
    log: Arc<StageLog>,
}

#[tonic::async_trait]
impl HttpStageTransport for AdapterTransport {
    async fn open(
        &self,
        events: mpsc::Receiver<HttpEvent>,
    ) -> std::result::Result<HttpResultStream, TonicStatus> {
        Ok(open(&self.handler, &self.log, events))
    }
}

/// Engine callbacks of a test legacy response adapter. Like the adapter, it
/// reports `LegacyFailOpen` itself when it fails open.
struct AdapterControl {
    config_name: String,
    fail_open: bool,
    reports: Arc<dyn StageReportSink>,
    failed_inputs: Mutex<Vec<(String, usize)>>,
    withheld: AtomicBool,
}

impl LegacyResponseControl for AdapterControl {
    fn buffered_input_failed(&self, reason: &str, input_size: usize) -> bool {
        self.failed_inputs
            .lock()
            .expect("failed inputs")
            .push((reason.to_string(), input_size));
        if self.fail_open {
            self.reports.report(
                &self.config_name,
                StageReport::LegacyFailOpen {
                    reason: reason.to_string(),
                },
            );
        }
        self.fail_open
    }

    fn withhold_output_until_end(&self) {
        self.withheld.store(true, Ordering::Release);
    }
}

/// Open legacy stages from `stages` with test adapters until the guard
/// drops. Returns the adapters' engine callbacks by config name.
fn install_adapters(
    stages: &[TestStage],
    fail_open: bool,
) -> (
    test_support::FactoryGuard,
    Arc<Mutex<Vec<Arc<AdapterControl>>>>,
) {
    let stages = stages.to_vec();
    let controls = Arc::new(Mutex::new(Vec::new()));
    let opened = Arc::clone(&controls);
    let guard = test_support::install_stages(move |context: &LegacyStageContext| {
        let stage = stages
            .iter()
            .find(|stage| stage.name == context.entry.entry.implementation)
            .expect("adapter for a test stage");
        let control = Arc::new(AdapterControl {
            config_name: context.entry.entry.name.clone(),
            fail_open,
            reports: Arc::clone(&context.reports),
            failed_inputs: Mutex::default(),
            withheld: AtomicBool::new(false),
        });
        opened.lock().expect("controls").push(Arc::clone(&control));
        LegacyStage {
            transport: Arc::new(AdapterTransport {
                handler: Arc::clone(&stage.handler),
                log: Arc::clone(&stage.log),
            }),
            response: Some(control),
        }
    });
    (guard, controls)
}

fn header(name: &str, value: &str) -> HttpHeader {
    HttpHeader {
        name: name.into(),
        value: value.into(),
    }
}

fn preflight_result(decision: http_preflight_result::Decision) -> http_result::Result {
    http_result::Result::PreflightResult(HttpPreflightResult {
        decision: Some(decision),
        header_mutations: Vec::new(),
        diagnostics: None,
    })
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

fn output_start() -> http_result::Result {
    http_result::Result::OutputStart(HttpOutputStart::default())
}

fn output_chunk(data: Vec<u8>) -> http_result::Result {
    http_result::Result::OutputChunk(HttpOutputChunk { data })
}

fn buffered(replacement: Option<Vec<u8>>) -> http_result::Result {
    http_result::Result::BufferedResult(HttpBufferedResult {
        body: Some(replacement.map_or(
            http_buffered_result::Body::Unchanged(HttpUnchanged {}),
            http_buffered_result::Body::Replacement,
        )),
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

/// STREAM stage that maps every input chunk through `transform`, or rejects
/// the first chunk when `transform` returns `None`.
fn stream_stage(name: &'static str, transform: Transform) -> TestStage {
    TestStage::new(
        name,
        &[HttpBodyMode::Stream],
        move |mut io: StageIo| async move {
            while let Some(event) = io.recv().await {
                match event {
                    http_event::Event::Preflight(_) => {
                        io.send(preflight_result(inspect_stream())).await;
                    }
                    http_event::Event::Begin(_) => io.send(output_start()).await,
                    http_event::Event::InputChunk(chunk) => match transform(chunk.data) {
                        Some(data) if data.is_empty() => {}
                        Some(data) => io.send(output_chunk(data)).await,
                        None => {
                            io.send(reject("blocked_content")).await;
                            break;
                        }
                    },
                    http_event::Event::InputEnd(_) => {
                        io.send(http_result::Result::Finish(HttpFinish::default()))
                            .await;
                        break;
                    }
                    _ => {}
                }
            }
            io.drain().await;
        },
    )
}

/// BUFFERED stage that maps the whole body through `transform`.
fn buffered_stage(name: &'static str, transform: Transform) -> TestStage {
    TestStage::new(
        name,
        &[HttpBodyMode::Buffered],
        move |mut io: StageIo| async move {
            while let Some(event) = io.recv().await {
                match event {
                    http_event::Event::Preflight(preflight) => {
                        let limit = preflight
                            .limits
                            .map_or(1, |limits| limits.max_buffered_body_bytes);
                        io.send(preflight_result(inspect_buffered(limit))).await;
                    }
                    http_event::Event::BufferedBody(body) => {
                        io.send(buffered(transform(body.data))).await;
                        break;
                    }
                    _ => {}
                }
            }
            io.drain().await;
        },
    )
}

/// Body transform of a test stage. `None` keeps a BUFFERED body and rejects
/// a STREAM chunk.
type Transform = fn(Vec<u8>) -> Option<Vec<u8>>;

const UPPERCASE: Transform = |data| Some(data.to_ascii_uppercase());
const UNCHANGED: Transform = |_| None;
const BLOCK: Transform = |_| None;

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

/// Stage head that offers a version 2 stage every mode it supports, for
/// driving the pipeline directly.
struct OfferSupported;

impl StageHead for OfferSupported {
    fn preflight_head(
        &self,
        entry: &DescribedChainEntry,
        headers: &[HttpHeader],
    ) -> http_preflight::Head {
        http_preflight::Head::Response(HttpResponsePreflightHead {
            status_code: 200,
            headers: headers.to_vec(),
            middleware_name: entry.entry.implementation.clone(),
            ..Default::default()
        })
    }

    fn body_modes(&self, entry: &DescribedChainEntry) -> BodyModeOffer {
        BodyModeOffer {
            permitted: [HttpBodyMode::Buffered, HttpBodyMode::Stream]
                .into_iter()
                .filter(|mode| entry.supports_http_body_mode(*mode))
                .collect(),
            unavailable: Vec::new(),
        }
    }
}

fn response_spec() -> PipelineSpec {
    PipelineSpec {
        direction: HttpDirection::Response,
        head_authority: headers::HeaderAuthority::Response,
        trailer_authority: headers::HeaderAuthority::ResponseTrailers,
        connection_nominated: Vec::new(),
        timeouts: PipelineTimeouts::default(),
        output_trailers: true,
        reports: None,
        original_response: None,
    }
}

/// Preflight `names` directly on the stage pipeline.
async fn pipeline_for(runner: &ChainRunner, names: &[&str], spec: PipelineSpec) -> Pipeline {
    let described = runner
        .describe_http_response_chain(&chain(names))
        .await
        .expect("describe");
    pipeline::preflight(
        runner,
        &described,
        spec,
        vec![header("content-type", "text/plain")],
        None,
        &OfferSupported,
    )
    .await
    .pipeline
    .expect("a stage inspects the body")
}

/// Run `pipeline` over `chunks` with `trailers`, ending it early with
/// `abort` when that resolves first, and drain its output.
async fn run_pipeline(
    pipeline: Pipeline,
    chunks: Vec<(Duration, Vec<u8>)>,
    trailers: Vec<HttpHeader>,
    abort: impl Future<Output = MiddlewareSessionEndReason>,
) -> (
    std::result::Result<HttpPipelineFinish, HttpMiddlewareFailure>,
    Vec<HttpBodyOutput>,
) {
    let (input_tx, input_rx) = mpsc::channel(4);
    let (output_tx, mut output_rx) = mpsc::channel(4);
    let feed = async move {
        for (delay, chunk) in chunks {
            tokio::time::sleep(delay).await;
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
    let (finish, (), output) = tokio::join!(
        pipeline.run_until(input_rx, output_tx, abort),
        feed,
        collect
    );
    (finish, output)
}

fn now(chunk: &[u8]) -> (Duration, Vec<u8>) {
    (Duration::ZERO, chunk.to_vec())
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

fn output_start_of(output: &[HttpBodyOutput]) -> (Option<u64>, bool) {
    match output.first() {
        Some(HttpBodyOutput::Start {
            output_body_bytes,
            body_transformed,
            ..
        }) => (*output_body_bytes, *body_transformed),
        other => panic!("output must begin with Start, got {other:?}"),
    }
}

#[tokio::test]
async fn output_start_reports_whether_a_stage_changed_the_body() {
    for (stage, transformed) in [
        (buffered_stage("test/keep", UNCHANGED), false),
        (buffered_stage("test/upper", UPPERCASE), true),
        (stream_stage("test/upper", UPPERCASE), true),
    ] {
        let name = stage.name;
        let runner = runner_for(std::slice::from_ref(&stage)).await;
        let pipeline = pipeline_for(&runner, &[name], response_spec()).await;
        let (finish, output) = run_pipeline(
            pipeline,
            vec![now(b"body")],
            Vec::new(),
            std::future::pending(),
        )
        .await;
        finish.expect("chain completes");
        assert_eq!(output_start_of(&output).1, transformed, "{name}");
    }
}

#[tokio::test]
async fn buffered_output_declares_its_length_when_trailers_cannot_be_delivered() {
    let stage = buffered_stage("test/upper", UPPERCASE);
    let runner = runner_for(std::slice::from_ref(&stage)).await;
    let trailers = vec![header("x-checksum", "abc")];
    for (output_trailers, declared) in [(true, None), (false, Some(4))] {
        let spec = PipelineSpec {
            output_trailers,
            ..response_spec()
        };
        let pipeline = pipeline_for(&runner, &["test/upper"], spec).await;
        let (finish, output) = run_pipeline(
            pipeline,
            vec![now(b"body")],
            trailers.clone(),
            std::future::pending(),
        )
        .await;
        assert_eq!(finish.expect("chain completes").trailers, trailers);
        assert_eq!(output_start_of(&output).0, declared);
    }
}

#[tokio::test]
async fn an_external_abort_ends_every_stage_with_its_reason() {
    let stage = stream_stage("test/upper", UPPERCASE);
    let runner = runner_for(std::slice::from_ref(&stage)).await;
    let pipeline = pipeline_for(&runner, &["test/upper"], response_spec()).await;
    let (abort, aborted) = tokio::sync::oneshot::channel();
    let (input_tx, input_rx) = mpsc::channel(4);
    let (output_tx, mut output_rx) = mpsc::channel(4);
    let run = tokio::spawn(pipeline.run_until(input_rx, output_tx, async move {
        aborted
            .await
            .unwrap_or(MiddlewareSessionEndReason::Cancellation)
    }));
    input_tx
        .send(HttpBodyInput::Chunk(b"one".to_vec()))
        .await
        .expect("input");
    assert!(matches!(
        output_rx.recv().await,
        Some(HttpBodyOutput::Start { .. })
    ));
    assert_eq!(
        output_rx.recv().await,
        Some(HttpBodyOutput::Chunk(b"ONE".to_vec()))
    );
    abort
        .send(MiddlewareSessionEndReason::UpstreamDisconnect)
        .expect("abort");

    let failure = run
        .await
        .expect("join")
        .expect_err("the upstream went away");
    assert_eq!(failure.reason, "middleware_cancelled: upstream_disconnect");
    assert_eq!(
        failure.end_reason,
        MiddlewareSessionEndReason::UpstreamDisconnect
    );
    assert_eq!(
        stage.log.wait_for_session_end().await,
        MiddlewareSessionEndReason::UpstreamDisconnect
    );
}

#[tokio::test]
async fn session_end_reaches_a_stage_blocked_on_its_result_queue() {
    // After Begin, the stage writes far more output than the queues hold
    // without reading its events, then reads the rest of them.
    let flooding = TestStage::new(
        "test/flood",
        &[HttpBodyMode::Stream],
        |mut io: StageIo| async move {
            while let Some(event) = io.recv().await {
                match event {
                    http_event::Event::Preflight(_) => {
                        io.send(preflight_result(inspect_stream())).await;
                    }
                    http_event::Event::Begin(_) => {
                        io.send(output_start()).await;
                        for _ in 0..16 {
                            io.send(output_chunk(b"x".to_vec())).await;
                        }
                    }
                    _ => {}
                }
            }
        },
    );
    let runner = runner_for(std::slice::from_ref(&flooding)).await;
    let pipeline = pipeline_for(&runner, &["test/flood"], response_spec()).await;
    let (abort, aborted) = tokio::sync::oneshot::channel();
    let (input_tx, input_rx) = mpsc::channel(4);
    // The output is never read, so the stage's results back up.
    let (output_tx, _output_rx) = mpsc::channel(1);
    let run = tokio::spawn(pipeline.run_until(input_rx, output_tx, async move {
        aborted
            .await
            .unwrap_or(MiddlewareSessionEndReason::Cancellation)
    }));
    for _ in 0..8 {
        let _ = tokio::time::timeout(
            Duration::from_millis(20),
            input_tx.send(HttpBodyInput::Chunk(b"in".to_vec())),
        )
        .await;
    }
    abort
        .send(MiddlewareSessionEndReason::DownstreamDisconnect)
        .expect("abort");
    run.await.expect("join").expect_err("aborted");
    assert_eq!(
        flooding.log.wait_for_session_end().await,
        MiddlewareSessionEndReason::DownstreamDisconnect
    );
}

#[tokio::test]
async fn reports_are_forwarded_as_they_arrive_and_fail_open_ones_retained() {
    #[derive(Default)]
    struct Forwarded(Mutex<Vec<(String, StageReport)>>);

    impl StageReportSink for Forwarded {
        fn report(&self, config_name: &str, report: StageReport) {
            self.0
                .lock()
                .expect("forwarded")
                .push((config_name.to_string(), report));
        }
    }

    let stage = buffered_stage("test/legacy", UNCHANGED)
        .legacy()
        .with_limit(4);
    let runner = runner_for(std::slice::from_ref(&stage)).await;
    let (_adapters, _controls) = install_adapters(std::slice::from_ref(&stage), true);
    let forwarded = Arc::new(Forwarded::default());
    let spec = PipelineSpec {
        reports: Some(forwarded.clone()),
        ..response_spec()
    };
    let pipeline = pipeline_for(&runner, &["test/legacy"], spec).await;
    let (finish, _output) = run_pipeline(
        pipeline,
        vec![now(b"too long")],
        Vec::new(),
        std::future::pending(),
    )
    .await;
    let finish = finish.expect("fail_open releases the original");
    let report = (
        "test-legacy".to_string(),
        StageReport::LegacyFailOpen {
            reason: "whole_body_over_capacity".into(),
        },
    );
    assert_eq!(
        *forwarded.0.lock().expect("forwarded"),
        std::slice::from_ref(&report)
    );
    assert_eq!(finish.diagnostics.reports, [report]);
}

#[tokio::test]
async fn a_legacy_adapter_decides_how_its_buffered_overflow_ends() {
    let stage = buffered_stage("test/legacy", UPPERCASE)
        .legacy()
        .with_limit(4);
    let runner = runner_for(std::slice::from_ref(&stage)).await;

    let (_adapters, controls) = install_adapters(std::slice::from_ref(&stage), true);
    let pipeline = pipeline_for(&runner, &["test/legacy"], response_spec()).await;
    let (finish, output) = run_pipeline(
        pipeline,
        vec![now(b"too"), now(b" long")],
        Vec::new(),
        std::future::pending(),
    )
    .await;
    let finish = finish.expect("fail_open releases the original");
    assert_eq!(output_body(&output), b"too long");
    assert_eq!(
        *controls.lock().expect("controls")[0]
            .failed_inputs
            .lock()
            .expect("failed inputs"),
        [("whole_body_over_capacity".to_string(), 8)]
    );
    // The adapter reported the outcome; the pipeline does not repeat it.
    assert_eq!(finish.diagnostics.reports.len(), 1);
    assert_eq!(
        finish.diagnostics.invocations[0].outcome,
        HttpStageOutcome::FailOpen
    );
    assert_eq!(
        stage.log.wait_for_session_end().await,
        MiddlewareSessionEndReason::MiddlewareFailure
    );

    let stage = buffered_stage("test/legacy", UPPERCASE)
        .legacy()
        .with_limit(4);
    let runner = runner_for(std::slice::from_ref(&stage)).await;
    let (_adapters, _controls) = install_adapters(std::slice::from_ref(&stage), false);
    let pipeline = pipeline_for(&runner, &["test/legacy"], response_spec()).await;
    let (finish, _output) = run_pipeline(
        pipeline,
        vec![now(b"too long")],
        Vec::new(),
        std::future::pending(),
    )
    .await;
    assert_eq!(
        finish.expect_err("fail_closed").reason,
        "middleware_failed: whole_body_over_capacity"
    );
    assert_eq!(
        stage.log.wait_for_session_end().await,
        MiddlewareSessionEndReason::MiddlewareFailure
    );
}

#[tokio::test(start_paused = true)]
async fn a_legacy_adapter_decides_how_its_accumulation_deadline_ends() {
    let stage = buffered_stage("test/legacy", UPPERCASE).legacy();
    let runner = runner_for(std::slice::from_ref(&stage)).await;
    let (_adapters, controls) = install_adapters(std::slice::from_ref(&stage), true);
    let spec = PipelineSpec {
        timeouts: PipelineTimeouts {
            buffered_body: Duration::from_secs(5),
            ..PipelineTimeouts::default()
        },
        ..response_spec()
    };
    let pipeline = pipeline_for(&runner, &["test/legacy"], spec).await;
    let (finish, output) = run_pipeline(
        pipeline,
        vec![now(b"early"), (Duration::from_secs(10), b"late".to_vec())],
        Vec::new(),
        std::future::pending(),
    )
    .await;
    finish.expect("fail_open releases the original");
    assert_eq!(output_body(&output), b"earlylate");
    assert_eq!(
        *controls.lock().expect("controls")[0]
            .failed_inputs
            .lock()
            .expect("failed inputs"),
        [("whole_body_accumulation_timeout".to_string(), 5)]
    );
}

#[tokio::test]
async fn a_legacy_stream_stage_after_a_buffered_stage_withholds_its_output() {
    let first = stream_stage("test/first", UPPERCASE).legacy();
    let whole = buffered_stage("test/whole", UNCHANGED);
    let last = stream_stage("test/last", UPPERCASE).legacy();
    let stages = [first.clone(), whole.clone(), last.clone()];
    let runner = runner_for(&stages).await;
    let (_adapters, controls) = install_adapters(&stages, false);
    let pipeline = pipeline_for(
        &runner,
        &["test/first", "test/whole", "test/last"],
        response_spec(),
    )
    .await;
    let (finish, _output) = run_pipeline(
        pipeline,
        vec![now(b"body")],
        Vec::new(),
        std::future::pending(),
    )
    .await;
    finish.expect("chain completes");
    let controls = controls.lock().expect("controls");
    let withheld: Vec<bool> = controls
        .iter()
        .map(|control| control.withheld.load(Ordering::Acquire))
        .collect();
    assert_eq!(withheld, [false, true]);
}

#[tokio::test]
async fn completed_legacy_response_stages_end_with_the_chain_outcome() {
    for (transform, outcome) in [
        (UPPERCASE, MiddlewareSessionEndReason::Normal),
        (BLOCK, MiddlewareSessionEndReason::MiddlewareDenial),
    ] {
        let legacy = buffered_stage("test/legacy", UNCHANGED).legacy();
        let v2_buffered = buffered_stage("test/v2", UNCHANGED);
        let last = stream_stage("test/last", transform);
        let stages = [legacy.clone(), v2_buffered.clone(), last.clone()];
        let runner = runner_for(&stages).await;
        let (_adapters, _controls) = install_adapters(&stages, false);
        let pipeline = pipeline_for(
            &runner,
            &["test/legacy", "test/v2", "test/last"],
            response_spec(),
        )
        .await;
        let (_finish, _output) = run_pipeline(
            pipeline,
            vec![now(b"body")],
            Vec::new(),
            std::future::pending(),
        )
        .await;
        assert_eq!(legacy.log.wait_for_session_end().await, outcome);
        // A version 2 stage ends as soon as it completes.
        assert_eq!(
            v2_buffered.log.wait_for_session_end().await,
            MiddlewareSessionEndReason::Normal
        );
        assert_eq!(
            legacy.log.kinds(),
            ["preflight", "begin", "buffered_body", "session_end"]
        );
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

fn response_input(status_code: u16, headers: &[(&str, &str)]) -> HttpResponsePreflightInput {
    HttpResponsePreflightInput {
        context: RequestContext {
            request_id: "req".into(),
            ..Default::default()
        },
        target: HttpRequestTarget {
            scheme: "https".into(),
            host: "api.example.com".into(),
            port: 443,
            method: "GET".into(),
            path: "/v1/data".into(),
            query: String::new(),
        },
        status_code,
        declared_body_length: None,
        headers: headers
            .iter()
            .map(|(name, value)| header(name, value))
            .collect(),
        connection_nominated_headers: Vec::new(),
    }
}

async fn response_preflight(
    runner: &ChainRunner,
    entries: &[ChainEntry],
    input: HttpResponsePreflightInput,
    chunked: bool,
) -> HttpResponsePipelinePreflight {
    let described = runner
        .describe_http_response_chain(entries)
        .await
        .expect("describe");
    runner
        .preflight_http_response_pipeline(described, input, HttpResponseDelivery::new(chunked))
        .await
        .expect("preflight")
}

/// Continue at preflight, keeping what was offered in the log.
fn observer_stage(name: &'static str, modes: &[HttpBodyMode]) -> TestStage {
    TestStage::new(name, modes, |mut io: StageIo| async move {
        if let Some(http_event::Event::Preflight(_)) = io.recv().await {
            io.send(preflight_result(
                http_preflight_result::Decision::ContinueWithoutBody(HttpContinue {}),
            ))
            .await;
        }
        io.drain().await;
    })
}

fn unavailable(
    entries: &[(HttpBodyMode, HttpBodyUnavailableReason)],
) -> Vec<HttpBodyModeUnavailable> {
    entries
        .iter()
        .map(|(mode, reason)| HttpBodyModeUnavailable {
            mode: *mode as i32,
            reason: *reason as i32,
        })
        .collect()
}

#[tokio::test]
async fn response_eligibility_decides_the_offered_body_modes() {
    use HttpBodyMode::{Buffered, Stream};
    use HttpBodyUnavailableReason::{
        Bodyless, Encoded, NoTransform, OpenEnded, OverLimit, Partial, TruncationUndetectable,
    };

    let sse = [("content-type", "text/event-stream; charset=utf-8")];
    let cases: Vec<(
        &str,
        HttpResponsePreflightInput,
        bool,
        Vec<HttpBodyMode>,
        Vec<_>,
    )> = vec![
        (
            "chunked JSON",
            response_input(200, &[("content-type", "application/json")]),
            true,
            vec![Buffered, Stream],
            vec![],
        ),
        (
            "HTTP/1.0 client or upstream",
            response_input(200, &[]),
            false,
            vec![Buffered],
            vec![(Stream, TruncationUndetectable)],
        ),
        (
            "server-sent events",
            response_input(200, &sse),
            true,
            vec![Stream],
            vec![(Buffered, OpenEnded)],
        ),
        (
            "server-sent events over HTTP/1.0",
            response_input(200, &sse),
            false,
            vec![],
            vec![(Buffered, OpenEnded), (Stream, TruncationUndetectable)],
        ),
        (
            "mixed-replace stream",
            response_input(200, &[("content-type", "multipart/x-mixed-replace")]),
            true,
            vec![Stream],
            vec![(Buffered, OpenEnded)],
        ),
        (
            "HEAD",
            HttpResponsePreflightInput {
                target: HttpRequestTarget {
                    method: "HEAD".into(),
                    ..response_input(200, &[]).target
                },
                ..response_input(200, &[])
            },
            true,
            vec![],
            vec![(Buffered, Bodyless), (Stream, Bodyless)],
        ),
        (
            "204",
            response_input(204, &[]),
            true,
            vec![],
            vec![(Buffered, Bodyless), (Stream, Bodyless)],
        ),
        (
            "304",
            response_input(304, &[]),
            true,
            vec![],
            vec![(Buffered, Bodyless), (Stream, Bodyless)],
        ),
        (
            "206",
            response_input(206, &[]),
            true,
            vec![],
            vec![(Buffered, Partial), (Stream, Partial)],
        ),
        (
            "Content-Range",
            response_input(200, &[("content-range", "bytes 0-4/10")]),
            true,
            vec![],
            vec![(Buffered, Partial), (Stream, Partial)],
        ),
        (
            "byte ranges",
            response_input(200, &[("content-type", "multipart/byteranges; boundary=x")]),
            true,
            vec![],
            vec![(Buffered, Partial), (Stream, Partial)],
        ),
        (
            "no-transform",
            response_input(200, &[("cache-control", "max-age=60, No-Transform")]),
            true,
            vec![],
            vec![(Buffered, NoTransform), (Stream, NoTransform)],
        ),
        (
            "content coding",
            response_input(200, &[("content-encoding", "gzip")]),
            true,
            vec![],
            vec![(Buffered, Encoded), (Stream, Encoded)],
        ),
        (
            "identity coding",
            response_input(200, &[("content-encoding", "identity")]),
            true,
            vec![Buffered, Stream],
            vec![],
        ),
        (
            "over the limit",
            HttpResponsePreflightInput {
                declared_body_length: Some(LIMIT + 1),
                ..response_input(200, &[])
            },
            true,
            vec![Stream],
            vec![(Buffered, OverLimit)],
        ),
    ];
    for (case, input, chunked, permitted, withheld) in cases {
        let both = observer_stage("test/both", &[Buffered, Stream]);
        let headers_only = observer_stage("test/headers", &[]);
        let runner = runner_for(&[both.clone(), headers_only.clone()]).await;
        let outcome = response_preflight(
            &runner,
            &chain(&["test/both", "test/headers"]),
            input,
            chunked,
        )
        .await;
        assert!(outcome.allowed, "{case}: {}", outcome.reason);
        assert!(outcome.session.is_none(), "{case}");
        let offered = both.log.preflight();
        assert_eq!(
            offered.permitted_body_modes,
            permitted
                .iter()
                .map(|mode| *mode as i32)
                .collect::<Vec<_>>(),
            "{case}"
        );
        assert_eq!(
            offered.late_header_modes, offered.permitted_body_modes,
            "{case}"
        );
        assert_eq!(
            offered.unavailable_body_modes,
            unavailable(&withheld),
            "{case}"
        );
        // A restricted response still preflights every stage, and a
        // preflight-only binding has no mode to miss.
        let headers_only = headers_only.log.preflight();
        assert!(headers_only.permitted_body_modes.is_empty(), "{case}");
        assert!(headers_only.unavailable_body_modes.is_empty(), "{case}");
    }
}

#[tokio::test]
async fn stream_offers_carry_the_idle_timeout_and_no_total_limits() {
    let stage = observer_stage("test/stream", &[HttpBodyMode::Stream]).with_limit(16);
    let runner = runner_for(std::slice::from_ref(&stage)).await;
    response_preflight(
        &runner,
        &chain(&["test/stream"]),
        response_input(200, &[("content-type", "text/event-stream")]),
        true,
    )
    .await;
    let preflight = stage.log.preflight();
    let Some(http_preflight::Head::Response(head)) = preflight.head else {
        panic!("response head");
    };
    assert_eq!(head.status_code, 200);
    assert_eq!(head.target.expect("target").path, "/v1/data");
    assert_eq!(head.context.expect("context").request_id, "req");
    let limits = preflight.limits.expect("limits");
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
async fn legacy_stages_keep_the_0_1_offer_unless_the_body_is_restricted() {
    let legacy = observer_stage("test/legacy", &[]).legacy();
    let v2 = observer_stage("test/v2", &[HttpBodyMode::Stream]);
    let runner = runner_for(&[legacy.clone(), v2]).await;
    let (_adapters, _controls) = install_adapters(std::slice::from_ref(&legacy), false);
    let sse = [("content-type", "text/event-stream")];
    for (input, chunked, offered) in [
        // Neither the truncation nor the open-ended rule applies to legacy
        // stages, whose adapter applies 0.1.x eligibility itself.
        (
            response_input(200, &sse),
            false,
            vec![HttpBodyMode::Buffered as i32, HttpBodyMode::Stream as i32],
        ),
        (response_input(204, &[]), true, Vec::new()),
    ] {
        let outcome =
            response_preflight(&runner, &chain(&["test/legacy", "test/v2"]), input, chunked).await;
        assert!(outcome.allowed, "{}", outcome.reason);
        assert_eq!(legacy.log.preflight().permitted_body_modes, offered);
        legacy.log.events.lock().expect("stage log").clear();
    }
}

#[tokio::test]
async fn chains_with_a_version_2_entry_run_on_the_pipeline() {
    let legacy = observer_stage("test/legacy", &[]).legacy();
    let v2 = observer_stage("test/v2", &[]);
    let runner = runner_for(&[legacy, v2]).await;
    for (names, pipeline) in [
        (vec!["test/legacy"], false),
        (vec!["test/v2"], true),
        (vec!["test/legacy", "test/v2"], true),
        (vec!["test/unregistered"], false),
    ] {
        let described = runner
            .describe_http_response_chain(&chain(&names))
            .await
            .expect("describe");
        assert_eq!(
            http_response_uses_pipeline(&described),
            pipeline,
            "{names:?}"
        );
    }
}

#[tokio::test]
async fn legacy_entries_without_an_adapter_fail_a_mixed_response_chain_closed() {
    let legacy = observer_stage("test/legacy", &[]).legacy();
    let v2 = observer_stage("test/v2", &[]);
    let runner = runner_for(&[legacy, v2.clone()]).await;
    let mut entries = chain(&["test/v2", "test/legacy"]);
    entries[1].on_error = OnError::FailOpen;
    let outcome = response_preflight(&runner, &entries, response_input(200, &[]), true).await;
    assert!(!outcome.allowed);
    assert_eq!(
        outcome.reason,
        "middleware_failed: http_stage_not_executable"
    );
    assert_eq!(
        v2.log.wait_for_session_end().await,
        MiddlewareSessionEndReason::StageSkipped
    );
}

/// Run a response session over `chunks` and drain its output.
async fn run_response(
    session: HttpResponsePipelineSession,
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
    let (finish, (), output) = tokio::join!(
        session.run_until(input_rx, output_tx, std::future::pending()),
        feed,
        collect
    );
    (finish, output)
}

#[tokio::test]
async fn buffered_stage_redacts_a_json_response_with_late_headers() {
    let redactor = TestStage::new(
        "test/redact",
        &[HttpBodyMode::Buffered],
        |mut io: StageIo| async move {
            while let Some(event) = io.recv().await {
                match event {
                    http_event::Event::Preflight(preflight) => {
                        let limit = preflight
                            .limits
                            .map_or(1, |limits| limits.max_buffered_body_bytes);
                        io.send(http_result::Result::PreflightResult(HttpPreflightResult {
                            decision: Some(inspect_buffered(limit)),
                            header_mutations: vec![write("x-inspected", "redact")],
                            diagnostics: None,
                        }))
                        .await;
                    }
                    http_event::Event::BufferedBody(body) => {
                        let redacted = String::from_utf8(body.data)
                            .expect("JSON body")
                            .replace("sk-live-123", "[redacted]");
                        io.send(http_result::Result::BufferedResult(HttpBufferedResult {
                            body: Some(http_buffered_result::Body::Replacement(
                                redacted.into_bytes(),
                            )),
                            header_mutations: vec![write("x-redacted", "1")],
                            ..Default::default()
                        }))
                        .await;
                        break;
                    }
                    _ => {}
                }
            }
            io.drain().await;
        },
    );
    let runner = runner_for(std::slice::from_ref(&redactor)).await;
    let body = br#"{"id":7,"token":"sk-live-123"}"#.to_vec();
    let outcome = response_preflight(
        &runner,
        &chain(&["test/redact"]),
        HttpResponsePreflightInput {
            declared_body_length: Some(body.len() as u64),
            ..response_input(200, &[("content-type", "application/json")])
        },
        true,
    )
    .await;
    assert!(outcome.allowed);
    assert!(outcome.headers.contains(&header("x-inspected", "redact")));
    let session = outcome.session.expect("BUFFERED session");
    assert!(session.withholds_output());
    assert!(!session.streams());
    let (finish, output) = run_response(
        session,
        vec![body[..10].to_vec(), body[10..].to_vec()],
        Vec::new(),
    )
    .await;
    finish.expect("redaction completes");
    let redacted = br#"{"id":7,"token":"[redacted]"}"#;
    assert_eq!(
        output.first(),
        Some(&HttpBodyOutput::Start {
            header_mutations: vec![write("x-redacted", "1")],
            output_body_bytes: Some(redacted.len() as u64),
            body_transformed: true,
        })
    );
    assert_eq!(output_body(&output), redacted);
    assert_eq!(
        redactor.log.wait_for_session_end().await,
        MiddlewareSessionEndReason::Normal
    );
}

#[tokio::test]
async fn stream_stage_mutates_trailers_late() {
    let stage = TestStage::new(
        "test/trailers",
        &[HttpBodyMode::Stream],
        |mut io: StageIo| async move {
            while let Some(event) = io.recv().await {
                match event {
                    http_event::Event::Preflight(_) => {
                        io.send(preflight_result(inspect_stream())).await;
                    }
                    http_event::Event::Begin(_) => io.send(output_start()).await,
                    http_event::Event::InputChunk(chunk) => {
                        io.send(output_chunk(chunk.data)).await;
                    }
                    http_event::Event::InputEnd(end) => {
                        assert_eq!(end.visible_trailers, [header("x-checksum", "abc")]);
                        io.send(http_result::Result::Finish(HttpFinish {
                            trailer_mutations: vec![write("x-checksum", "def")],
                            diagnostics: None,
                        }))
                        .await;
                        break;
                    }
                    _ => {}
                }
            }
            io.drain().await;
        },
    );
    let runner = runner_for(std::slice::from_ref(&stage)).await;
    let session = response_preflight(
        &runner,
        &chain(&["test/trailers"]),
        response_input(200, &[]),
        true,
    )
    .await
    .session
    .expect("STREAM session");
    let (finish, output) = run_response(
        session,
        vec![b"data".to_vec()],
        vec![header("x-checksum", "abc")],
    )
    .await;
    assert_eq!(
        finish.expect("chain completes").trailers,
        [header("x-checksum", "def")]
    );
    assert_eq!(
        output.last(),
        Some(&HttpBodyOutput::End {
            trailers: vec![header("x-checksum", "def")],
        })
    );
}

#[tokio::test]
async fn reject_at_response_preflight_denies_before_the_body() {
    let guard = TestStage::new(
        "test/guard",
        &[HttpBodyMode::Stream],
        |mut io: StageIo| async move {
            if let Some(http_event::Event::Preflight(_)) = io.recv().await {
                io.send(reject("blocked_status")).await;
            }
            io.drain().await;
        },
    );
    let later = observer_stage("test/later", &[]);
    let runner = runner_for(&[guard.clone(), later.clone()]).await;
    let outcome = response_preflight(
        &runner,
        &chain(&["test/guard", "test/later"]),
        response_input(200, &[]),
        true,
    )
    .await;
    assert!(!outcome.allowed);
    assert!(outcome.session.is_none());
    assert_eq!(
        outcome.denial,
        Some(MiddlewareDenial {
            config_name: "test-guard".into(),
            reason_code: Some("blocked_status".into()),
        })
    );
    assert_eq!(
        guard.log.wait_for_session_end().await,
        MiddlewareSessionEndReason::MiddlewareDenial
    );
    assert!(later.log.kinds().is_empty());
}

#[tokio::test]
async fn response_contract_failures_fail_closed_and_request_reconciliation() {
    #[derive(Default)]
    struct Observer(Mutex<Vec<ContractFailure>>);

    impl MiddlewareRuntimeObserver for Observer {
        fn contract_failure(&self, failure: &ContractFailure) {
            self.0.lock().expect("failures").push(failure.clone());
        }

        fn fail_open_not_applied(&self, _entry: &FailOpenNotApplied) {}
    }

    // Advertises a version 2 response binding but keeps the default stage
    // RPC, which answers UNIMPLEMENTED.
    #[derive(Clone)]
    struct Unimplemented(TestStage);

    #[tonic::async_trait]
    impl InProcessMiddleware for Unimplemented {
        async fn describe(&self) -> MiddlewareManifest {
            self.0.describe().await
        }

        async fn validate_config(&self, _name: &str, _config: &prost_types::Struct) -> Result<()> {
            Ok(())
        }

        async fn evaluate_http_request(
            &self,
            _request: HttpRequestView<'_>,
        ) -> Result<HttpRequestResult> {
            Err(miette!("response test middleware"))
        }
    }

    let observer = Arc::new(Observer::default());
    let runner = ChainRunner::from_registry(
        MiddlewareRegistry::connect_services_with_http_v2(
            vec![Arc::new(Unimplemented(observer_stage(
                "test/missing",
                &[HttpBodyMode::Stream],
            )))],
            Vec::new(),
        )
        .await
        .expect("registry"),
    )
    .with_runtime_observer(observer.clone());
    let mut entries = chain(&["test/missing"]);
    entries[0].on_error = OnError::FailOpen;
    let outcome = response_preflight(&runner, &entries, response_input(200, &[]), true).await;
    assert_eq!(
        outcome.reason,
        "middleware_failed: middleware_contract_failure_unimplemented"
    );
    assert_eq!(
        observer.0.lock().expect("failures")[0].direction,
        HttpDirection::Response
    );
    assert!(runner.take_reconciliation_request());

    // A result the codec cannot decode, mid-stream.
    let broken = TestStage::new(
        "test/broken",
        &[HttpBodyMode::Stream],
        |mut io: StageIo| async move {
            while let Some(event) = io.recv().await {
                match event {
                    http_event::Event::Preflight(_) => {
                        io.send(preflight_result(inspect_stream())).await;
                    }
                    http_event::Event::Begin(_) => io.send(output_start()).await,
                    http_event::Event::InputChunk(_) => {
                        let error = HttpResult::decode(&b"\x0a\x05\x01"[..])
                            .expect_err("truncated message must not decode");
                        io.send_raw(Err(TonicStatus::internal(error.to_string())))
                            .await;
                    }
                    _ => {}
                }
            }
        },
    );
    let runner = runner_for(std::slice::from_ref(&broken)).await;
    let session = response_preflight(
        &runner,
        &chain(&["test/broken"]),
        response_input(200, &[]),
        true,
    )
    .await
    .session
    .expect("STREAM session");
    let (finish, _output) = run_response(session, vec![b"data".to_vec()], Vec::new()).await;
    assert_eq!(
        finish.expect_err("decode failures fail closed").reason,
        "middleware_failed: middleware_contract_failure_decode_failure"
    );
    assert!(runner.take_reconciliation_request());
}

#[tokio::test]
async fn failed_precondition_from_a_response_stage_means_it_cannot_inspect() {
    let picky = TestStage::new(
        "test/picky",
        &[HttpBodyMode::Buffered],
        |mut io: StageIo| async move {
            if let Some(http_event::Event::Preflight(_)) = io.recv().await {
                io.send_raw(Err(TonicStatus::failed_precondition("needs JSON")))
                    .await;
            }
            io.drain().await;
        },
    );
    let runner = runner_for(std::slice::from_ref(&picky)).await;
    let outcome = response_preflight(
        &runner,
        &chain(&["test/picky"]),
        response_input(200, &[]),
        true,
    )
    .await;
    assert_eq!(
        outcome.reason,
        "middleware_failed: middleware_cannot_inspect"
    );
    assert!(!runner.take_reconciliation_request());
}

#[tokio::test]
async fn unrepresentable_heads_follow_each_entry_on_error() {
    let v2 = observer_stage("test/v2", &[]);
    let runner = runner_for(std::slice::from_ref(&v2)).await;
    let mut entries = chain(&["test/unregistered", "test/v2"]);
    entries[0].on_error = OnError::FailOpen;
    let described = runner
        .describe_http_response_chain(&entries)
        .await
        .expect("describe");
    let outcome = runner.http_response_pipeline_input_unrepresentable(&described);
    assert!(!outcome.allowed);
    assert_eq!(
        outcome.reason,
        "middleware_failed: response_input_unrepresentable"
    );
    let outcomes: Vec<_> = outcome
        .diagnostics
        .invocations
        .iter()
        .map(|invocation| invocation.outcome)
        .collect();
    assert_eq!(
        outcomes,
        [HttpStageOutcome::FailOpen, HttpStageOutcome::FailClosed]
    );
}

#[tokio::test]
async fn exhausted_session_budget_applies_each_entry_on_error() {
    let holder = stream_stage("test/holder", UPPERCASE);
    let legacy = observer_stage("test/legacy", &[]).legacy();
    let runner = runner_for(&[holder, legacy.clone()]).await;
    let (_adapters, _controls) = install_adapters(std::slice::from_ref(&legacy), true);
    let mut held = Vec::new();
    for _ in 0..MAX_CONCURRENT_MIDDLEWARE_SESSIONS {
        let outcome = response_preflight(
            &runner,
            &chain(&["test/holder"]),
            response_input(200, &[]),
            true,
        )
        .await;
        held.push(outcome.session.expect("session"));
    }

    let v2 = response_preflight(
        &runner,
        &chain(&["test/holder"]),
        response_input(200, &[]),
        true,
    )
    .await;
    assert!(!v2.allowed);
    assert!(v2.session_capacity_exhausted);
    assert_eq!(v2.reason, "middleware_failed: session_capacity_exhausted");

    // HTTP protocol 1 (0.1): a fail_open legacy stage passes the
    // response on uninspected.
    let mut entries = chain(&["test/legacy"]);
    entries[0].on_error = OnError::FailOpen;
    let legacy_outcome =
        response_preflight(&runner, &entries, response_input(200, &[]), true).await;
    assert!(legacy_outcome.allowed);
    assert!(legacy_outcome.session_capacity_exhausted);
    assert_eq!(
        legacy_outcome.diagnostics.invocations[0].outcome,
        HttpStageOutcome::FailOpen
    );
    assert!(legacy.log.kinds().is_empty());

    drop(held.pop());
    let outcome = response_preflight(
        &runner,
        &chain(&["test/holder"]),
        response_input(200, &[]),
        true,
    )
    .await;
    assert!(
        outcome.session.is_some(),
        "a released permit admits one more"
    );
}

#[tokio::test]
async fn legacy_response_chains_keep_work_admission() {
    let legacy = observer_stage("test/legacy", &[]).legacy();
    let runner = runner_for(std::slice::from_ref(&legacy)).await;
    let (_adapters, _controls) = install_adapters(std::slice::from_ref(&legacy), false);
    let mut active = Vec::new();
    for _ in 0..MAX_CONCURRENT_MIDDLEWARE_WORK {
        active.push(
            runner
                .reserve_middleware_work()
                .await
                .expect("admission")
                .into_admission()
                .expect("active work"),
        );
    }
    let waiting: Vec<_> = (0..MAX_QUEUED_MIDDLEWARE_WORK)
        .map(|_| {
            let runner = runner.clone();
            tokio::spawn(async move { runner.reserve_middleware_work().await })
        })
        .collect();
    tokio::time::timeout(Duration::from_secs(5), async {
        while runner.registry.work_admission_waiters.available_permits() > 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("waiters queued");

    let outcome = response_preflight(
        &runner,
        &chain(&["test/legacy"]),
        response_input(200, &[]),
        true,
    )
    .await;
    assert!(!outcome.allowed);
    assert!(outcome.admission_exhausted);
    assert!(legacy.log.kinds().is_empty());

    drop(active);
    for waiter in waiting {
        waiter.await.expect("join").expect("admission");
    }
}

#[tokio::test]
async fn changed_bodies_drop_stale_integrity_trailers_their_stage_did_not_rewrite() {
    let rewriting = TestStage::new(
        "test/digest",
        &[HttpBodyMode::Stream],
        |mut io: StageIo| async move {
            while let Some(event) = io.recv().await {
                match event {
                    http_event::Event::Preflight(_) => {
                        io.send(preflight_result(inspect_stream())).await;
                    }
                    http_event::Event::Begin(_) => io.send(output_start()).await,
                    http_event::Event::InputChunk(chunk) => {
                        io.send(output_chunk(chunk.data.to_ascii_uppercase())).await;
                    }
                    http_event::Event::InputEnd(_) => {
                        io.send(http_result::Result::Finish(HttpFinish {
                            trailer_mutations: vec![write("content-digest", "sha-256=:fresh:")],
                            diagnostics: None,
                        }))
                        .await;
                        break;
                    }
                    _ => {}
                }
            }
            io.drain().await;
        },
    );
    let trailers = vec![
        header("content-digest", "sha-256=:stale:"),
        header("digest", "sha-256=stale"),
        header("x-trace", "kept"),
    ];
    for (stage, expected) in [
        (
            rewriting,
            vec![
                header("x-trace", "kept"),
                header("content-digest", "sha-256=:fresh:"),
            ],
        ),
        (
            buffered_stage("test/upper", UPPERCASE),
            vec![header("x-trace", "kept")],
        ),
        (buffered_stage("test/keep", UNCHANGED), trailers.clone()),
    ] {
        let name = stage.name;
        let runner = runner_for(std::slice::from_ref(&stage)).await;
        let pipeline = pipeline_for(&runner, &[name], response_spec()).await;
        let (finish, _output) = run_pipeline(
            pipeline,
            vec![now(b"body")],
            trailers.clone(),
            std::future::pending(),
        )
        .await;
        assert_eq!(
            finish.expect("chain completes").trailers,
            expected,
            "{name}"
        );
    }
}

#[tokio::test]
async fn late_mutations_of_every_stage_apply_beyond_one_stages_limit() {
    fn writer(name: &'static str) -> TestStage {
        TestStage::new(
            name,
            &[HttpBodyMode::Buffered],
            move |mut io: StageIo| async move {
                while let Some(event) = io.recv().await {
                    match event {
                        http_event::Event::Preflight(_) => {
                            io.send(preflight_result(inspect_buffered(LIMIT))).await;
                        }
                        http_event::Event::BufferedBody(_) => {
                            io.send(http_result::Result::BufferedResult(HttpBufferedResult {
                                body: Some(http_buffered_result::Body::Unchanged(HttpUnchanged {})),
                                header_mutations: (0..40)
                                    .map(|index| write(&format!("x-{name}-{index}"), "1"))
                                    .collect(),
                                ..Default::default()
                            }))
                            .await;
                            break;
                        }
                        _ => {}
                    }
                }
                io.drain().await;
            },
        )
    }
    let stages = [
        writer("first"),
        writer("second"),
        stream_stage("test/upper", UPPERCASE),
    ];
    let runner = runner_for(&stages).await;
    let pipeline = pipeline_for(&runner, &["first", "second", "test/upper"], response_spec()).await;
    let (finish, output) = run_pipeline(
        pipeline,
        vec![now(b"body")],
        Vec::new(),
        std::future::pending(),
    )
    .await;
    finish.expect("80 late mutations from two stages apply");
    match output.first() {
        Some(HttpBodyOutput::Start {
            header_mutations, ..
        }) => assert_eq!(header_mutations.len(), 80),
        other => panic!("output must begin with Start, got {other:?}"),
    }
}
