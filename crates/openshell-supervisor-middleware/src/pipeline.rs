// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Version 2 HTTP stage pipeline, shared by request and response evaluation.
//!
//! Preflight runs every selected stage in chain order. Stages that inspect
//! the body then run concurrently, linked by bounded channels. Each stage
//! waits for its upstream `Start`, sends `Begin` with its current head, and
//! forwards its own `Start` only after that. The outgoing head therefore
//! commits only on the final `Start`, once every late header mutation is
//! known: the original head, then every preflight mutation, then every late
//! mutation, each in chain order.
//!
//! BUFFERED stages hold one bounded body under a whole-body deadline. STREAM
//! stages run independent input and output pumps with no total deadline and
//! no total byte cap; a stage fails only when it stalls. The supervisor never
//! retains STREAM input for replay.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt as _;
use futures::stream::FuturesUnordered;
use prost::Message as _;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use openshell_core::proto::{
    HeaderMutation, HttpBegin, HttpBodyLimits, HttpBodyMode, HttpBufferedBody, HttpEvent,
    HttpHeader, HttpInputChunk, HttpInputEnd, HttpPreflight, HttpResult, MiddlewareDiagnostics,
    MiddlewareSessionEnd, MiddlewareSessionEndReason, http_buffered_result, http_event,
    http_inspect, http_preflight, http_preflight_result, http_result,
};

use crate::headers::{self, HeaderAuthority};
use crate::legacy::hooks::{
    self, LegacyChainClock, LegacyOverflow, LegacyStageContext, LegacyStagePolicy,
};
use crate::runtime::RuntimeHooks;
use crate::{
    ChainRunner, ContractFailure, ContractFailureKind, DescribedChainEntry, EXTERNAL_FINDING_LABEL,
    HttpDirection, HttpProtocol, HttpResultStream, MAX_MIDDLEWARE_CHAIN_TIMEOUT,
    MAX_MIDDLEWARE_FINDING_BYTES, MAX_MIDDLEWARE_FINDINGS_PER_STAGE, MAX_MIDDLEWARE_METADATA_BYTES,
    MAX_MIDDLEWARE_METADATA_ENTRIES, MAX_MIDDLEWARE_REASON_BYTES, MAX_MIDDLEWARE_REASON_CODE_BYTES,
    MiddlewareDenial, MiddlewareDiagnosticPolicy, NamespacedFinding, OnError, StageReport,
    StageReports, is_stable_reason_code, middleware_denial_reason,
};

/// Largest normalized body chunk a stage sends or receives.
pub const MAX_HTTP_STREAM_UNIT_BYTES: usize = 64 * 1024;
/// STREAM middleware-stall timeout.
///
/// A STREAM stage fails when it does not accept the next input within this
/// duration while its output is not held back downstream, or when it returns
/// nothing within this duration after it accepted the end of its input.
pub const HTTP_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// BUFFERED whole-body deadline, covering receipt, processing, and delivery
/// of one stage's body.
pub const HTTP_BUFFERED_BODY_TIMEOUT: Duration = Duration::from_mins(2);
/// Messages each link and stage queue holds.
pub const STAGE_QUEUE_MESSAGES: usize = 4;
const SESSION_END_TIMEOUT: Duration = Duration::from_millis(10);

/// Body input to a pipeline: chunks, then exactly one `End`.
#[derive(Debug)]
pub enum HttpBodyInput {
    Chunk(Vec<u8>),
    End { trailers: Vec<HttpHeader> },
}

/// Body output of a pipeline: one `Start`, chunks, then one `End`.
#[derive(Debug, PartialEq, Eq)]
pub enum HttpBodyOutput {
    /// Commit the outgoing head. Apply `header_mutations`, every stage's late
    /// mutations in chain order, after the preflight mutations. When
    /// `output_body_bytes` is present, the body has exactly that length.
    Start {
        header_mutations: Vec<HeaderMutation>,
        output_body_bytes: Option<u64>,
    },
    Chunk(Vec<u8>),
    End {
        trailers: Vec<HttpHeader>,
    },
}

/// What one stage did in one phase of an exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpStageOutcome {
    /// Preflight continued without the body.
    Continue,
    /// The stage rejected the exchange.
    Reject,
    /// Preflight selected BUFFERED.
    Buffered,
    /// Preflight selected STREAM.
    Stream,
    /// The BUFFERED result kept the body.
    Unchanged,
    /// The BUFFERED result replaced the body.
    Replacement,
    /// The STREAM stage finished.
    Finish,
    /// The stage failed and the exchange failed closed.
    FailClosed,
    /// HTTP protocol 1 (0.1). Removed in 0.2.0.
    ///
    /// The stage could not run and `on_error: fail_open` passed the original
    /// input on.
    FailOpen,
}

/// Audit record for one stage and phase. Carries no service-provided text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpStageInvocation {
    pub config_name: String,
    pub implementation: String,
    pub outcome: HttpStageOutcome,
    pub input_bytes: usize,
    pub output_bytes: Option<usize>,
    /// True when the stage changed the body or the head.
    pub transformed: bool,
    pub failed: bool,
    pub reason_code: Option<String>,
    /// Platform-owned failure reason.
    pub failure_reason: Option<String>,
}

/// Findings, metadata, invocations, and stage reports for one exchange.
#[derive(Debug, Default)]
pub struct HttpStageDiagnostics {
    pub findings: Vec<NamespacedFinding>,
    pub metadata: BTreeMap<String, BTreeMap<String, String>>,
    pub invocations: Vec<HttpStageInvocation>,
    /// Outcomes legacy adapter stages reported beside their results, keyed by
    /// policy-local config name.
    pub reports: Vec<(String, StageReport)>,
}

impl HttpStageDiagnostics {
    /// Append `other`, keeping chain order.
    pub fn extend(&mut self, other: Self) {
        self.findings.extend(other.findings);
        self.metadata.extend(other.metadata);
        self.invocations.extend(other.invocations);
        self.reports.extend(other.reports);
    }
}

/// The exchange failed closed or was rejected.
#[derive(Debug)]
pub struct HttpMiddlewareFailure {
    /// Platform-owned reason: `middleware_denied:<config>[:<code>]` for a
    /// rejection, `middleware_failed: <reason>` for a failure, and
    /// `middleware_cancelled: <reason>` when the input producer went away.
    pub reason: String,
    /// Present only when a stage rejected the exchange.
    pub denial: Option<MiddlewareDenial>,
    /// Session end every stage received.
    pub end_reason: MiddlewareSessionEndReason,
    pub diagnostics: Box<HttpStageDiagnostics>,
}

impl std::fmt::Display for HttpMiddlewareFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl std::error::Error for HttpMiddlewareFailure {}

/// A completed body pipeline.
#[derive(Debug)]
pub struct HttpPipelineFinish {
    /// Final trailers after every stage's trailer mutations.
    pub trailers: Vec<HttpHeader>,
    /// True when a stage replaced or streamed the body.
    pub body_transformed: bool,
    pub diagnostics: HttpStageDiagnostics,
}

/// Deadlines the pipeline applies. Tests shorten them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipelineTimeouts {
    pub stream_idle: Duration,
    pub buffered_body: Duration,
}

impl Default for PipelineTimeouts {
    fn default() -> Self {
        Self {
            stream_idle: HTTP_STREAM_IDLE_TIMEOUT,
            buffered_body: HTTP_BUFFERED_BODY_TIMEOUT,
        }
    }
}

/// Direction-specific rules for one exchange.
#[derive(Debug, Clone)]
pub struct PipelineSpec {
    pub direction: HttpDirection,
    pub head_authority: HeaderAuthority,
    pub trailer_authority: HeaderAuthority,
    /// Lowercased names nominated by the original message's `Connection`
    /// fields. Mutations treat them as hop-by-hop.
    pub connection_nominated: Vec<String>,
    pub timeouts: PipelineTimeouts,
}

/// Direction-specific preflight content.
pub trait StageHead: Sync {
    /// Head shown to `entry`, given the head after earlier stages' preflight
    /// mutations.
    fn preflight_head(
        &self,
        entry: &DescribedChainEntry,
        headers: &[HttpHeader],
    ) -> http_preflight::Head;

    /// Body modes `entry` may select: its supported modes intersected with
    /// runtime support, policy, and message eligibility.
    fn permitted_body_modes(&self, entry: &DescribedChainEntry) -> Vec<HttpBodyMode>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageMode {
    Buffered { max_body_bytes: usize },
    Stream,
}

/// One stage that selected a body mode.
pub struct Stage {
    entry: DescribedChainEntry,
    stream: StageStream,
    mode: StageMode,
    /// Head after preflight mutations through this stage.
    head: Vec<HttpHeader>,
    legacy: Option<LegacyStagePolicy>,
}

/// Event sender and result stream of one open stage exchange.
struct StageStream {
    sender: Option<mpsc::Sender<HttpEvent>>,
    results: HttpResultStream,
    ended: bool,
}

impl StageStream {
    /// Best-effort `SessionEnd`, then close the exchange.
    async fn end(&mut self, reason: MiddlewareSessionEndReason) {
        if self.ended {
            return;
        }
        self.ended = true;
        let Some(sender) = self.sender.take() else {
            return;
        };
        let _ = tokio::time::timeout(SESSION_END_TIMEOUT, sender.send(session_end(reason))).await;
        drop(sender);
        let _ = tokio::time::timeout(SESSION_END_TIMEOUT, async {
            while self.results.next().await.is_some() {}
        })
        .await;
    }
}

impl Drop for StageStream {
    fn drop(&mut self) {
        if self.ended {
            return;
        }
        let Some(sender) = self.sender.take() else {
            return;
        };
        let mut results = std::mem::replace(&mut self.results, Box::pin(futures::stream::empty()));
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = tokio::time::timeout(
                    SESSION_END_TIMEOUT,
                    sender.send(session_end(MiddlewareSessionEndReason::Cancellation)),
                )
                .await;
                drop(sender);
                let _ = tokio::time::timeout(SESSION_END_TIMEOUT, async {
                    while results.next().await.is_some() {}
                })
                .await;
            });
        }
    }
}

fn session_end(reason: MiddlewareSessionEndReason) -> HttpEvent {
    HttpEvent {
        event: Some(http_event::Event::SessionEnd(MiddlewareSessionEnd {
            reason: reason as i32,
            protocol_error: None,
        })),
    }
}

/// Outcome of preflight across a chain.
pub struct Preflight {
    pub allowed: bool,
    pub reason: String,
    pub denial: Option<MiddlewareDenial>,
    /// Head after every preflight mutation.
    pub headers: Vec<HttpHeader>,
    /// Preflight mutations in chain order.
    pub header_mutations: Vec<HeaderMutation>,
    /// Present when at least one stage selected a body mode.
    pub pipeline: Option<Pipeline>,
    pub diagnostics: HttpStageDiagnostics,
}

/// Run preflight for `entries` in chain order.
pub async fn preflight(
    runner: &ChainRunner,
    entries: &[DescribedChainEntry],
    spec: PipelineSpec,
    headers: Vec<HttpHeader>,
    declared_input_bytes: Option<u64>,
    head: &impl StageHead,
) -> Preflight {
    let chain_deadline = Instant::now() + MAX_MIDDLEWARE_CHAIN_TIMEOUT;
    let reports = Arc::new(StageReports::default());
    let connection_nominated: Arc<[String]> = spec.connection_nominated.clone().into();
    let chain_clock = LegacyChainClock::default();
    let mut state = PreflightState {
        headers,
        header_mutations: Vec::new(),
        stages: Vec::new(),
        diagnostics: HttpStageDiagnostics::default(),
        reports: Arc::clone(&reports),
    };
    for entry in entries {
        if !entry.is_resolved() {
            if entry.on_error() == OnError::FailOpen {
                state
                    .diagnostics
                    .invocations
                    .push(fail_open_invocation(entry, "binding_not_described"));
                continue;
            }
            return state
                .fail(entry_failure(entry, "binding_not_described"))
                .await;
        }
        let (transport, legacy, permitted) = match entry.http_protocol() {
            Some(HttpProtocol::V2) => (
                entry.http_stage_transport(),
                None,
                head.permitted_body_modes(entry),
            ),
            Some(HttpProtocol::Legacy) => (
                hooks::open_stage(&LegacyStageContext {
                    entry: entry.clone(),
                    direction: spec.direction,
                    connection_nominated_headers: Arc::clone(&connection_nominated),
                    chain_clock: chain_clock.clone(),
                    reports: reports.clone(),
                }),
                Some(LegacyStagePolicy::new(entry, entries, spec.direction)),
                hooks::permitted_body_modes(spec.direction),
            ),
            None => (None, None, Vec::new()),
        };
        let own_limit = entry.max_payload_bytes();
        let buffered_limit =
            legacy.map_or(own_limit, |policy| policy.offered_buffered_limit(own_limit));
        let Some(transport) = transport else {
            return state
                .fail(entry_failure(entry, "http_stage_not_executable"))
                .await;
        };
        let event = HttpEvent {
            event: Some(http_event::Event::Preflight(HttpPreflight {
                head: Some(head.preflight_head(entry, &state.headers)),
                permitted_body_modes: permitted.iter().map(|mode| *mode as i32).collect(),
                late_header_modes: permitted.iter().map(|mode| *mode as i32).collect(),
                limits: Some(body_limits(
                    entry,
                    &permitted,
                    buffered_limit,
                    spec.timeouts,
                )),
                declared_input_bytes,
            })),
        };
        let stage_deadline = Instant::now() + entry.timeout();
        let (deadline, timeout_reason) = if chain_deadline <= stage_deadline {
            (chain_deadline, "middleware_chain_timeout")
        } else {
            (stage_deadline, "middleware_timeout")
        };
        let (sender, receiver) = mpsc::channel(STAGE_QUEUE_MESSAGES);
        let opened = tokio::time::timeout_at(deadline, async {
            sender
                .send(event)
                .await
                .map_err(|_| tonic::Status::unavailable("middleware stage stream closed"))?;
            let mut results = transport.open(receiver).await?;
            let first = results.next().await;
            Ok::<_, tonic::Status>((results, first))
        })
        .await;
        let (results, first) = match opened {
            Ok(Ok(opened)) => opened,
            Ok(Err(status)) => {
                return state
                    .fail(status_failure(
                        &runner.runtime,
                        entry,
                        spec.direction,
                        &status,
                    ))
                    .await;
            }
            Err(_) => return state.fail(entry_failure(entry, timeout_reason)).await,
        };
        let mut stream = StageStream {
            sender: Some(sender),
            results,
            ended: false,
        };
        let result = match classify_result(&runner.runtime, entry, spec.direction, first) {
            Ok(result) => result,
            Err(failure) => {
                stream.end(failure.end_reason).await;
                return state.fail(failure).await;
            }
        };
        match result {
            http_result::Result::PreflightResult(result) => {
                let diagnostics = match validate_diagnostics(entry, result.diagnostics.as_ref()) {
                    Ok(diagnostics) => diagnostics,
                    Err(failure) => {
                        stream.end(failure.end_reason).await;
                        return state.fail(failure).await;
                    }
                };
                let headers = match headers::apply(
                    spec.head_authority,
                    &state.headers,
                    &spec.connection_nominated,
                    &result.header_mutations,
                ) {
                    Ok(headers) => headers,
                    Err(error) => {
                        let failure = mutation_failure(entry, &error);
                        stream.end(failure.end_reason).await;
                        return state.fail(failure).await;
                    }
                };
                let mode = match result.decision {
                    Some(http_preflight_result::Decision::ContinueWithoutBody(_)) => None,
                    Some(http_preflight_result::Decision::Inspect(inspect)) => {
                        let mode = match inspect.mode {
                            Some(mode) => validate_inspect(&mode, &permitted, buffered_limit)
                                .map_err(|reason| entry_failure(entry, reason)),
                            None => Err(contract_failure(
                                &runner.runtime,
                                entry,
                                spec.direction,
                                ContractFailureKind::UnknownResult,
                            )),
                        };
                        match mode {
                            Ok(mode) => Some(mode),
                            Err(failure) => {
                                stream.end(failure.end_reason).await;
                                return state.fail(failure).await;
                            }
                        }
                    }
                    None => {
                        let failure = contract_failure(
                            &runner.runtime,
                            entry,
                            spec.direction,
                            ContractFailureKind::UnknownResult,
                        );
                        stream.end(failure.end_reason).await;
                        return state.fail(failure).await;
                    }
                };
                let reason_code = nonempty(&diagnostics.reason_code);
                collect_diagnostics(entry, diagnostics, &mut state.diagnostics);
                let head_changed = headers != state.headers;
                state.headers = headers;
                state.header_mutations.extend(result.header_mutations);
                let Some(mode) = mode else {
                    let mut continued = HttpStageInvocation {
                        transformed: head_changed,
                        ..invocation(entry, HttpStageOutcome::Continue, reason_code)
                    };
                    if legacy.is_some() {
                        let stage_reports = reports.take(&entry.entry.name);
                        mark_legacy_fail_open(&mut continued, &stage_reports);
                        state.diagnostics.reports.extend(
                            stage_reports
                                .into_iter()
                                .map(|report| (entry.entry.name.clone(), report)),
                        );
                    }
                    state.diagnostics.invocations.push(continued);
                    stream.end(MiddlewareSessionEndReason::StageSkipped).await;
                    continue;
                };
                state.diagnostics.invocations.push(HttpStageInvocation {
                    transformed: head_changed,
                    ..invocation(
                        entry,
                        match mode {
                            StageMode::Buffered { .. } => HttpStageOutcome::Buffered,
                            StageMode::Stream => HttpStageOutcome::Stream,
                        },
                        reason_code,
                    )
                });
                state.stages.push(Stage {
                    entry: entry.clone(),
                    stream,
                    mode,
                    head: state.headers.clone(),
                    legacy,
                });
            }
            http_result::Result::Reject(reject) => {
                let failure = rejection(entry, reject.diagnostics.as_ref());
                stream.end(failure.end_reason).await;
                return state.fail(failure).await;
            }
            _ => {
                let failure = entry_failure(entry, "preflight_result_expected");
                stream.end(failure.end_reason).await;
                return state.fail(failure).await;
            }
        }
    }
    let PreflightState {
        headers,
        header_mutations,
        stages,
        mut diagnostics,
        reports,
    } = state;
    diagnostics.reports.extend(reports.drain());
    let pipeline = (!stages.is_empty()).then(|| Pipeline {
        spec,
        stages,
        declared_input_bytes,
        runtime: Arc::clone(&runner.runtime),
        reports,
    });
    Preflight {
        allowed: true,
        reason: String::new(),
        denial: None,
        headers,
        header_mutations,
        pipeline,
        diagnostics,
    }
}

struct PreflightState {
    headers: Vec<HttpHeader>,
    header_mutations: Vec<HeaderMutation>,
    stages: Vec<Stage>,
    diagnostics: HttpStageDiagnostics,
    reports: Arc<StageReports>,
}

impl PreflightState {
    async fn fail(mut self, failure: HttpMiddlewareFailure) -> Preflight {
        for stage in &mut self.stages {
            stage.stream.end(failure.end_reason).await;
        }
        let HttpMiddlewareFailure {
            reason,
            denial,
            diagnostics,
            ..
        } = failure;
        self.diagnostics.extend(*diagnostics);
        self.diagnostics.reports.extend(self.reports.drain());
        Preflight {
            allowed: false,
            reason,
            denial,
            headers: self.headers,
            header_mutations: self.header_mutations,
            pipeline: None,
            diagnostics: self.diagnostics,
        }
    }
}

/// Stages that selected a body mode, ready to run.
pub struct Pipeline {
    spec: PipelineSpec,
    stages: Vec<Stage>,
    declared_input_bytes: Option<u64>,
    runtime: Arc<RuntimeHooks>,
    reports: Arc<StageReports>,
}

impl Pipeline {
    /// Largest input chunk the first stage accepts.
    pub fn input_unit_limit(&self) -> usize {
        self.stages
            .first()
            .map_or(MAX_HTTP_STREAM_UNIT_BYTES, input_unit_limit)
    }

    /// True when a BUFFERED stage withholds the head until its body result.
    pub fn withholds_output(&self) -> bool {
        self.stages
            .iter()
            .any(|stage| matches!(stage.mode, StageMode::Buffered { .. }))
    }

    /// True when a STREAM stage runs without a total deadline.
    pub fn streams(&self) -> bool {
        self.stages
            .iter()
            .any(|stage| stage.mode == StageMode::Stream)
    }

    #[cfg(test)]
    pub fn set_timeouts(&mut self, timeouts: PipelineTimeouts) {
        self.spec.timeouts = timeouts;
    }

    /// End every stage without running the body.
    pub async fn end(mut self, reason: MiddlewareSessionEndReason) {
        for stage in &mut self.stages {
            stage.stream.end(reason).await;
        }
    }

    /// Run every body stage. The caller must feed `input` and drain `output`
    /// concurrently with this future. Dropping the future cancels the
    /// exchange: every open stage receives `CANCELLATION`.
    pub async fn run(
        self,
        input: mpsc::Receiver<HttpBodyInput>,
        output: mpsc::Sender<HttpBodyOutput>,
    ) -> Result<HttpPipelineFinish, HttpMiddlewareFailure> {
        let Self {
            spec,
            stages,
            declared_input_bytes,
            runtime,
            reports,
        } = self;
        let count = stages.len();
        let limits: Vec<usize> = stages
            .iter()
            .map(input_unit_limit)
            .chain(std::iter::once(MAX_HTTP_STREAM_UNIT_BYTES))
            .collect();
        let mut senders = Vec::with_capacity(count + 1);
        let mut receivers = Vec::with_capacity(count + 1);
        for _ in 0..=count {
            let (sender, receiver) = mpsc::channel::<Frame>(STAGE_QUEUE_MESSAGES);
            senders.push(Some(sender));
            receivers.push(Some(receiver));
        }
        let (abort, aborted) = watch::channel(None::<MiddlewareSessionEndReason>);
        let shared = Shared {
            spec,
            runtime,
            reports: Arc::clone(&reports),
        };

        let mut tasks: FuturesUnordered<Pin<Box<dyn Future<Output = TaskResult> + Send + '_>>> =
            FuturesUnordered::new();
        tasks.push(Box::pin(run_source(
            input,
            senders[0].take().expect("source link"),
            limits[0],
            declared_input_bytes,
            aborted.clone(),
        )));
        for (index, stage) in stages.into_iter().enumerate() {
            tasks.push(Box::pin(run_stage(
                index,
                stage,
                receivers[index].take().expect("stage input link"),
                senders[index + 1].take().expect("stage output link"),
                limits[index + 1],
                &shared,
                aborted.clone(),
            )));
        }
        tasks.push(Box::pin(run_sink(
            receivers[count].take().expect("sink link"),
            output,
            aborted.clone(),
        )));
        drop(aborted);

        let mut done: Vec<Option<StageDone>> = (0..count).map(|_| None).collect();
        let mut trailers = None;
        let mut failure: Option<HttpMiddlewareFailure> = None;
        while let Some(result) = tasks.next().await {
            match result {
                Ok(TaskDone::Stage(index, stage)) => done[index] = Some(stage),
                Ok(TaskDone::Sink(value)) => trailers = Some(value),
                Err(TaskError::Failed(error)) if failure.is_none() => {
                    abort.send_replace(Some(error.end_reason));
                    failure = Some(error);
                }
                Ok(TaskDone::Source) | Err(_) => {}
            }
        }
        drop(tasks);

        let mut diagnostics = HttpStageDiagnostics::default();
        let mut body_transformed = false;
        for stage in done.into_iter().flatten() {
            body_transformed |= stage.transformed;
            diagnostics.extend(stage.diagnostics);
        }
        diagnostics.reports.extend(reports.drain());
        if let Some(mut failure) = failure {
            diagnostics.extend(*failure.diagnostics);
            failure.diagnostics = Box::new(diagnostics);
            return Err(failure);
        }
        let Some(trailers) = trailers else {
            return Err(HttpMiddlewareFailure {
                reason: "middleware_cancelled: pipeline_incomplete".into(),
                denial: None,
                end_reason: MiddlewareSessionEndReason::Cancellation,
                diagnostics: Box::new(diagnostics),
            });
        };
        Ok(HttpPipelineFinish {
            trailers,
            body_transformed,
            diagnostics,
        })
    }
}

fn input_unit_limit(stage: &Stage) -> usize {
    match stage.mode {
        StageMode::Stream => stage_chunk_limit(&stage.entry),
        StageMode::Buffered { .. } => MAX_HTTP_STREAM_UNIT_BYTES,
    }
}

fn stage_chunk_limit(entry: &DescribedChainEntry) -> usize {
    entry
        .max_payload_bytes()
        .clamp(1, MAX_HTTP_STREAM_UNIT_BYTES)
}

/// Message on a link between pipeline tasks.
#[derive(Debug)]
enum Frame {
    /// `header_mutations` holds every earlier stage's late mutations.
    Start {
        header_mutations: Vec<HeaderMutation>,
        output_body_bytes: Option<u64>,
    },
    Chunk(Vec<u8>),
    End(Vec<HttpHeader>),
}

struct Shared {
    spec: PipelineSpec,
    runtime: Arc<RuntimeHooks>,
    reports: Arc<StageReports>,
}

struct StageDone {
    diagnostics: HttpStageDiagnostics,
    transformed: bool,
}

enum TaskDone {
    Source,
    Stage(usize, StageDone),
    Sink(Vec<HttpHeader>),
}

enum TaskError {
    /// The task caused the exchange to fail.
    Failed(HttpMiddlewareFailure),
    /// The task stopped because the exchange already failed.
    Aborted,
}

type TaskResult = Result<TaskDone, TaskError>;

/// Error inside one stage.
enum StageError {
    Failed(HttpMiddlewareFailure),
    /// A neighbouring task closed its link because the exchange failed.
    LinkClosed,
}

impl From<HttpMiddlewareFailure> for StageError {
    fn from(failure: HttpMiddlewareFailure) -> Self {
        Self::Failed(failure)
    }
}

async fn abort_reason(
    aborted: &mut watch::Receiver<Option<MiddlewareSessionEndReason>>,
) -> MiddlewareSessionEndReason {
    aborted
        .wait_for(Option::is_some)
        .await
        .ok()
        .and_then(|reason| *reason)
        .unwrap_or(MiddlewareSessionEndReason::Cancellation)
}

async fn run_source(
    mut input: mpsc::Receiver<HttpBodyInput>,
    link: mpsc::Sender<Frame>,
    limit: usize,
    declared_input_bytes: Option<u64>,
    mut aborted: watch::Receiver<Option<MiddlewareSessionEndReason>>,
) -> TaskResult {
    let work = async {
        link.send(Frame::Start {
            header_mutations: Vec::new(),
            output_body_bytes: declared_input_bytes,
        })
        .await
        .map_err(|_| TaskError::Aborted)?;
        loop {
            match input.recv().await {
                Some(HttpBodyInput::Chunk(data)) => {
                    for unit in data.chunks(limit) {
                        link.send(Frame::Chunk(unit.to_vec()))
                            .await
                            .map_err(|_| TaskError::Aborted)?;
                    }
                }
                Some(HttpBodyInput::End { trailers }) => {
                    link.send(Frame::End(trailers))
                        .await
                        .map_err(|_| TaskError::Aborted)?;
                    return Ok(TaskDone::Source);
                }
                None => {
                    return Err(TaskError::Failed(cancelled("input_ended_early")));
                }
            }
        }
    };
    tokio::select! {
        biased;
        _ = abort_reason(&mut aborted) => Err(TaskError::Aborted),
        result = work => result,
    }
}

async fn run_sink(
    mut link: mpsc::Receiver<Frame>,
    output: mpsc::Sender<HttpBodyOutput>,
    mut aborted: watch::Receiver<Option<MiddlewareSessionEndReason>>,
) -> TaskResult {
    let work = async {
        let mut started = false;
        loop {
            let event = match link.recv().await {
                Some(Frame::Start {
                    header_mutations,
                    output_body_bytes,
                }) if !started => {
                    started = true;
                    HttpBodyOutput::Start {
                        header_mutations,
                        output_body_bytes,
                    }
                }
                Some(Frame::Chunk(data)) if started => HttpBodyOutput::Chunk(data),
                Some(Frame::End(trailers)) if started => {
                    output
                        .send(HttpBodyOutput::End {
                            trailers: trailers.clone(),
                        })
                        .await
                        .map_err(|_| TaskError::Failed(cancelled("output_closed")))?;
                    return Ok(TaskDone::Sink(trailers));
                }
                Some(_) => {
                    return Err(TaskError::Failed(platform_failure(
                        "pipeline_event_order_invalid",
                    )));
                }
                None => return Err(TaskError::Aborted),
            };
            output
                .send(event)
                .await
                .map_err(|_| TaskError::Failed(cancelled("output_closed")))?;
        }
    };
    tokio::select! {
        biased;
        _ = abort_reason(&mut aborted) => Err(TaskError::Aborted),
        result = work => result,
    }
}

enum StageExit {
    Done(Result<StageDone, StageError>),
    Aborted(MiddlewareSessionEndReason),
}

async fn run_stage(
    index: usize,
    mut stage: Stage,
    mut input: mpsc::Receiver<Frame>,
    output: mpsc::Sender<Frame>,
    output_limit: usize,
    shared: &Shared,
    mut aborted: watch::Receiver<Option<MiddlewareSessionEndReason>>,
) -> TaskResult {
    let exit = tokio::select! {
        biased;
        reason = abort_reason(&mut aborted) => StageExit::Aborted(reason),
        result = drive_stage(&mut stage, &mut input, &output, output_limit, shared) => {
            StageExit::Done(result)
        }
    };
    match exit {
        StageExit::Done(Ok(done)) => {
            stage.stream.end(MiddlewareSessionEndReason::Normal).await;
            Ok(TaskDone::Stage(index, done))
        }
        StageExit::Done(Err(StageError::Failed(failure))) => {
            stage.stream.end(failure.end_reason).await;
            Err(TaskError::Failed(failure))
        }
        StageExit::Done(Err(StageError::LinkClosed)) => {
            let reason = abort_reason(&mut aborted).await;
            stage.stream.end(reason).await;
            Err(TaskError::Aborted)
        }
        StageExit::Aborted(reason) => {
            stage.stream.end(reason).await;
            Err(TaskError::Aborted)
        }
    }
}

/// `Start` received from the previous link.
struct UpstreamStart {
    header_mutations: Vec<HeaderMutation>,
    output_body_bytes: Option<u64>,
}

async fn drive_stage(
    stage: &mut Stage,
    input: &mut mpsc::Receiver<Frame>,
    output: &mpsc::Sender<Frame>,
    output_limit: usize,
    shared: &Shared,
) -> Result<StageDone, StageError> {
    let upstream = match input.recv().await {
        Some(Frame::Start {
            header_mutations,
            output_body_bytes,
        }) => UpstreamStart {
            header_mutations,
            output_body_bytes,
        },
        Some(_) => return Err(entry_failure(&stage.entry, "stage_input_order_invalid").into()),
        None => return Err(StageError::LinkClosed),
    };
    let begin_head = headers::apply(
        shared.spec.head_authority,
        &stage.head,
        &shared.spec.connection_nominated,
        &upstream.header_mutations,
    )
    .map_err(|error| mutation_failure(&stage.entry, &error))?;
    match stage.mode {
        StageMode::Buffered { max_body_bytes } => {
            drive_buffered(
                stage,
                input,
                output,
                output_limit,
                shared,
                upstream,
                begin_head,
                max_body_bytes,
            )
            .await
        }
        StageMode::Stream => {
            drive_stream(
                stage,
                input,
                output,
                output_limit,
                shared,
                upstream,
                begin_head,
            )
            .await
        }
    }
}

/// Send `event` before `deadline`.
async fn send_until(
    shared: &Shared,
    entry: &DescribedChainEntry,
    stream: &mut StageStream,
    event: HttpEvent,
    deadline: Option<Instant>,
    timeout_reason: &str,
) -> Result<(), HttpMiddlewareFailure> {
    let Some(sender) = stream.sender.as_ref() else {
        return Err(entry_failure(entry, "middleware_stream_closed"));
    };
    let sent = match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, sender.send(event))
            .await
            .map_err(|_| entry_failure(entry, timeout_reason))?,
        None => sender.send(event).await,
    };
    if sent.is_ok() {
        return Ok(());
    }
    let deadline = deadline.unwrap_or_else(|| Instant::now() + entry.timeout());
    let next = tokio::time::timeout_at(deadline, stream.results.next())
        .await
        .ok()
        .flatten();
    Err(closed_stream_failure(shared, entry, next))
}

/// The stage stopped reading events. A rejection or RPC status it ended with
/// explains why better than the closed stream does.
fn closed_stream_failure(
    shared: &Shared,
    entry: &DescribedChainEntry,
    next: Option<Result<HttpResult, tonic::Status>>,
) -> HttpMiddlewareFailure {
    match next {
        Some(Ok(HttpResult {
            result: Some(http_result::Result::Reject(reject)),
        })) => rejection(entry, reject.diagnostics.as_ref()),
        Some(Err(status)) => status_failure(&shared.runtime, entry, shared.spec.direction, &status),
        _ => entry_failure(entry, "middleware_stream_closed"),
    }
}

async fn send_frame(output: &mpsc::Sender<Frame>, frame: Frame) -> Result<(), StageError> {
    output.send(frame).await.map_err(|_| StageError::LinkClosed)
}

async fn send_body(
    output: &mpsc::Sender<Frame>,
    body: &[u8],
    output_limit: usize,
) -> Result<(), StageError> {
    for unit in body.chunks(output_limit) {
        send_frame(output, Frame::Chunk(unit.to_vec())).await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn drive_buffered(
    stage: &mut Stage,
    input: &mut mpsc::Receiver<Frame>,
    output: &mpsc::Sender<Frame>,
    output_limit: usize,
    shared: &Shared,
    upstream: UpstreamStart,
    begin_head: Vec<HttpHeader>,
    max_body_bytes: usize,
) -> Result<StageDone, StageError> {
    let Stage {
        entry,
        stream,
        legacy,
        ..
    } = stage;
    let legacy = *legacy;
    let started = Instant::now();
    // Version 2: one deadline for receipt, processing, and delivery. Legacy
    // stages keep their 0.1.x deadlines, and the adapter bounds each exchange.
    let body_deadline = legacy
        .is_none()
        .then(|| started + shared.spec.timeouts.buffered_body);
    let (collect_deadline, on_collect_deadline) =
        legacy.map_or((body_deadline, LegacyOverflow::Fail), |policy| {
            policy
                .accumulation_deadline()
                .map_or((None, LegacyOverflow::Fail), |action| {
                    (Some(started + shared.spec.timeouts.buffered_body), action)
                })
        });
    let on_overflow = legacy.map_or(LegacyOverflow::Fail, LegacyStagePolicy::overflow);
    send_until(
        shared,
        entry,
        stream,
        HttpEvent {
            event: Some(http_event::Event::Begin(HttpBegin {
                headers: begin_head.clone(),
            })),
        },
        body_deadline,
        "middleware_body_timeout",
    )
    .await?;

    let mut body = Vec::new();
    let trailers = loop {
        let frame = tokio::select! {
            biased;
            frame = input.recv() => frame,
            () = sleep_until(collect_deadline) => {
                return match on_collect_deadline {
                    LegacyOverflow::Fail => {
                        Err(entry_failure(entry, "middleware_body_timeout").into())
                    }
                    LegacyOverflow::Release { reason } => {
                        release_original(
                            entry, upstream, body, None, input, output, output_limit, reason,
                        )
                        .await
                    }
                };
            }
        };
        match frame {
            Some(Frame::Chunk(data)) => {
                if body.len().saturating_add(data.len()) > max_body_bytes {
                    return match on_overflow {
                        LegacyOverflow::Fail => {
                            Err(entry_failure(entry, "buffered_input_over_capacity").into())
                        }
                        LegacyOverflow::Release { reason } => {
                            body.extend_from_slice(&data);
                            release_original(
                                entry,
                                upstream,
                                body,
                                None,
                                input,
                                output,
                                output_limit,
                                reason,
                            )
                            .await
                        }
                    };
                }
                body.extend_from_slice(&data);
            }
            Some(Frame::End(trailers)) => break trailers,
            Some(Frame::Start { .. }) => {
                return Err(entry_failure(entry, "stage_input_order_invalid").into());
            }
            None => return Err(StageError::LinkClosed),
        }
    };

    let (exchange_deadline, timeout_reason) =
        body_deadline.map_or((None, "middleware_timeout"), |deadline| {
            let stage_deadline = Instant::now() + entry.timeout();
            if stage_deadline < deadline {
                (Some(stage_deadline), "middleware_timeout")
            } else {
                (Some(deadline), "middleware_body_timeout")
            }
        });
    let input_bytes = body.len();
    let event = HttpEvent {
        event: Some(http_event::Event::BufferedBody(HttpBufferedBody {
            data: body.clone(),
            visible_trailers: trailers.clone(),
        })),
    };
    let exchange = async {
        send_until(
            shared,
            entry,
            stream,
            event,
            exchange_deadline,
            timeout_reason,
        )
        .await?;
        Ok::<_, HttpMiddlewareFailure>(stream.results.next().await)
    };
    let next = match exchange_deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, exchange)
            .await
            .map_err(|_| entry_failure(entry, timeout_reason))??,
        None => exchange.await?,
    };
    let result = match classify_result(&shared.runtime, entry, shared.spec.direction, next)? {
        http_result::Result::BufferedResult(result) => result,
        http_result::Result::Reject(reject) => {
            return Err(rejection(entry, reject.diagnostics.as_ref()).into());
        }
        _ => return Err(entry_failure(entry, "buffered_result_expected").into()),
    };
    let diagnostics = validate_diagnostics(entry, result.diagnostics.as_ref())?;
    let late_head = headers::apply(
        shared.spec.head_authority,
        &begin_head,
        &shared.spec.connection_nominated,
        &result.header_mutations,
    )
    .map_err(|error| mutation_failure(entry, &error))?;
    let trailers = headers::apply(
        shared.spec.trailer_authority,
        &trailers,
        &shared.spec.connection_nominated,
        &result.trailer_mutations,
    )
    .map_err(|error| mutation_failure(entry, &error))?;
    let (body, outcome) = match result.body {
        Some(http_buffered_result::Body::Unchanged(_)) => (body, HttpStageOutcome::Unchanged),
        Some(http_buffered_result::Body::Replacement(replacement)) => {
            if replacement.len() > max_body_bytes {
                return Err(entry_failure(entry, "buffered_output_over_capacity").into());
            }
            (replacement, HttpStageOutcome::Replacement)
        }
        None => {
            return Err(contract_failure(
                &shared.runtime,
                entry,
                shared.spec.direction,
                ContractFailureKind::UnknownResult,
            )
            .into());
        }
    };
    let head_changed = late_head != begin_head;
    let mut header_mutations = upstream.header_mutations;
    header_mutations.extend(result.header_mutations);
    let delivery = async {
        send_frame(
            output,
            Frame::Start {
                header_mutations,
                // Content-Length framing cannot carry trailers.
                output_body_bytes: trailers.is_empty().then_some(body.len() as u64),
            },
        )
        .await?;
        send_body(output, &body, output_limit).await?;
        send_frame(output, Frame::End(trailers)).await
    };
    match body_deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, delivery)
            .await
            .map_err(|_| entry_failure(entry, "middleware_body_timeout"))??,
        None => delivery.await?,
    }
    let transformed = outcome == HttpStageOutcome::Replacement;
    let mut done = StageDone {
        diagnostics: HttpStageDiagnostics::default(),
        transformed,
    };
    let reason_code = nonempty(&diagnostics.reason_code);
    collect_diagnostics(entry, diagnostics, &mut done.diagnostics);
    let mut invocation = HttpStageInvocation {
        input_bytes,
        output_bytes: Some(body.len()),
        transformed: transformed || head_changed,
        ..invocation(entry, outcome, reason_code)
    };
    if legacy.is_some() {
        let reports = shared.reports.take(&entry.entry.name);
        mark_legacy_fail_open(&mut invocation, &reports);
        done.diagnostics.reports.extend(
            reports
                .into_iter()
                .map(|report| (entry.entry.name.clone(), report)),
        );
    }
    done.diagnostics.invocations.push(invocation);
    Ok(done)
}

/// A legacy stage that passed its input on after a failure reports it beside
/// its `Continue` or `Unchanged` result. Record the stage as failed open.
fn mark_legacy_fail_open(invocation: &mut HttpStageInvocation, reports: &[StageReport]) {
    if !matches!(
        invocation.outcome,
        HttpStageOutcome::Continue | HttpStageOutcome::Unchanged
    ) {
        return;
    }
    if let Some(reason) = reports.iter().find_map(StageReport::fail_open_reason) {
        invocation.outcome = HttpStageOutcome::FailOpen;
        invocation.failed = true;
        invocation.failure_reason = Some(reason.to_string());
    }
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// Forward the stage's original input unchanged, as `fail_open` does, and
/// report the skipped stage.
#[allow(clippy::too_many_arguments)]
async fn release_original(
    entry: &DescribedChainEntry,
    upstream: UpstreamStart,
    collected: Vec<u8>,
    trailers: Option<Vec<HttpHeader>>,
    input: &mut mpsc::Receiver<Frame>,
    output: &mpsc::Sender<Frame>,
    output_limit: usize,
    reason: &str,
) -> Result<StageDone, StageError> {
    let output_body_bytes = match &trailers {
        Some(trailers) => trailers.is_empty().then_some(collected.len() as u64),
        None => upstream.output_body_bytes,
    };
    send_frame(
        output,
        Frame::Start {
            header_mutations: upstream.header_mutations,
            output_body_bytes,
        },
    )
    .await?;
    let mut bytes = collected.len();
    send_body(output, &collected, output_limit).await?;
    let trailers = match trailers {
        Some(trailers) => trailers,
        None => loop {
            match input.recv().await {
                Some(Frame::Chunk(data)) => {
                    bytes = bytes.saturating_add(data.len());
                    send_body(output, &data, output_limit).await?;
                }
                Some(Frame::End(trailers)) => break trailers,
                Some(Frame::Start { .. }) => {
                    return Err(entry_failure(entry, "stage_input_order_invalid").into());
                }
                None => return Err(StageError::LinkClosed),
            }
        },
    };
    send_frame(output, Frame::End(trailers)).await?;
    let mut diagnostics = HttpStageDiagnostics::default();
    diagnostics.invocations.push(HttpStageInvocation {
        input_bytes: bytes,
        output_bytes: Some(bytes),
        ..fail_open_invocation(entry, reason)
    });
    diagnostics.reports.push((
        entry.entry.name.clone(),
        StageReport::LegacyFailOpen {
            reason: reason.to_string(),
        },
    ));
    Ok(StageDone {
        diagnostics,
        transformed: false,
    })
}

/// Why a STREAM stage's input pump stopped early.
enum InputStop {
    /// The stage stopped reading input.
    Closed,
    Failed(StageError),
}

/// Why sending STREAM input to a stage stopped.
enum StallError {
    Closed,
    Stalled,
}

/// Send STREAM input, failing when the stage does not accept it within
/// `idle`. Time the stage's output spends held back downstream does not
/// count, and the timer restarts when that backpressure ends.
async fn send_stalled(
    sender: &mpsc::Sender<HttpEvent>,
    event: HttpEvent,
    idle: Duration,
    output_held: &mut watch::Receiver<bool>,
) -> Result<(), StallError> {
    let pending = sender.send(event);
    tokio::pin!(pending);
    let mut deadline = Instant::now() + idle;
    let mut watching = true;
    loop {
        let held = watching && *output_held.borrow_and_update();
        tokio::select! {
            biased;
            sent = &mut pending => return sent.map_err(|_| StallError::Closed),
            changed = output_held.changed(), if watching => {
                if changed.is_err() {
                    watching = false;
                } else if !*output_held.borrow() {
                    deadline = Instant::now() + idle;
                }
            }
            () = tokio::time::sleep_until(deadline), if !held => return Err(StallError::Stalled),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn drive_stream(
    stage: &mut Stage,
    input: &mut mpsc::Receiver<Frame>,
    output: &mpsc::Sender<Frame>,
    output_limit: usize,
    shared: &Shared,
    upstream: UpstreamStart,
    begin_head: Vec<HttpHeader>,
) -> Result<StageDone, StageError> {
    let Stage { entry, stream, .. } = stage;
    let entry = &*entry;
    let idle = shared.spec.timeouts.stream_idle;
    send_until(
        shared,
        entry,
        stream,
        HttpEvent {
            event: Some(http_event::Event::Begin(HttpBegin {
                headers: begin_head.clone(),
            })),
        },
        Some(Instant::now() + idle),
        "middleware_stall_timeout",
    )
    .await?;
    let Some(sender) = stream.sender.clone() else {
        return Err(entry_failure(entry, "middleware_stream_closed").into());
    };
    let chunk_limit = stage_chunk_limit(entry);
    // Trailers are published before InputEnd is sent: a Finish can race the
    // send as soon as the stage consumes InputEnd.
    let (input_end, input_ended) = watch::channel(None::<Vec<HttpHeader>>);
    let (delivered, mut input_delivered) = watch::channel(false);
    let (held, mut output_held) = watch::channel(false);

    let input_pump = async {
        let mut input_bytes = 0usize;
        loop {
            let event = match input.recv().await {
                Some(Frame::Chunk(data)) => {
                    input_bytes = input_bytes.saturating_add(data.len());
                    http_event::Event::InputChunk(HttpInputChunk { data })
                }
                Some(Frame::End(trailers)) => {
                    input_end.send_replace(Some(trailers.clone()));
                    http_event::Event::InputEnd(HttpInputEnd {
                        visible_trailers: trailers,
                    })
                }
                Some(Frame::Start { .. }) => {
                    return Err(InputStop::Failed(
                        entry_failure(entry, "stage_input_order_invalid").into(),
                    ));
                }
                None => return Err(InputStop::Failed(StageError::LinkClosed)),
            };
            let end = matches!(event, http_event::Event::InputEnd(_));
            match send_stalled(
                &sender,
                HttpEvent { event: Some(event) },
                idle,
                &mut output_held,
            )
            .await
            {
                Ok(()) => {}
                Err(StallError::Closed) => {
                    // The output pump now reads the stage's terminal result
                    // under the idle timeout.
                    delivered.send_replace(true);
                    return Err(InputStop::Closed);
                }
                Err(StallError::Stalled) => {
                    return Err(InputStop::Failed(
                        entry_failure(entry, "middleware_stall_timeout").into(),
                    ));
                }
            }
            if end {
                delivered.send_replace(true);
                return Ok::<usize, InputStop>(input_bytes);
            }
        }
    };

    let results = &mut stream.results;
    let output_pump = async {
        let mut header_mutations = upstream.header_mutations;
        let mut started = false;
        let mut declared = None;
        let mut output_bytes = 0usize;
        loop {
            let next = if *input_delivered.borrow_and_update() {
                tokio::time::timeout(idle, results.next())
                    .await
                    .map_err(|_| entry_failure(entry, "middleware_stall_timeout"))?
            } else {
                // A stage may withhold output until all input arrives, so
                // there is no result timeout while input is still flowing.
                tokio::select! {
                    next = results.next() => next,
                    _ = input_delivered.changed() => continue,
                }
            };
            match classify_result(&shared.runtime, entry, shared.spec.direction, next)? {
                http_result::Result::OutputStart(start) if !started => {
                    headers::apply(
                        shared.spec.head_authority,
                        &begin_head,
                        &shared.spec.connection_nominated,
                        &start.header_mutations,
                    )
                    .map_err(|error| mutation_failure(entry, &error))?;
                    header_mutations.extend(start.header_mutations);
                    declared = start.output_body_bytes;
                    started = true;
                    held.send_replace(true);
                    send_frame(
                        output,
                        Frame::Start {
                            header_mutations: header_mutations.clone(),
                            output_body_bytes: declared,
                        },
                    )
                    .await?;
                    held.send_replace(false);
                }
                http_result::Result::OutputChunk(chunk) if started => {
                    if chunk.data.is_empty() || chunk.data.len() > chunk_limit {
                        return Err(entry_failure(entry, "stream_output_chunk_invalid").into());
                    }
                    output_bytes = output_bytes.saturating_add(chunk.data.len());
                    if declared.is_some_and(|declared| output_bytes as u64 > declared) {
                        return Err(entry_failure(entry, "stream_output_length_mismatch").into());
                    }
                    held.send_replace(true);
                    send_body(output, &chunk.data, output_limit).await?;
                    held.send_replace(false);
                }
                http_result::Result::Finish(finish) if started => {
                    let Some(trailers) = input_ended.borrow().clone() else {
                        return Err(entry_failure(entry, "stream_finish_before_input_end").into());
                    };
                    if declared.is_some_and(|declared| declared != output_bytes as u64) {
                        return Err(entry_failure(entry, "stream_output_length_mismatch").into());
                    }
                    let diagnostics = validate_diagnostics(entry, finish.diagnostics.as_ref())?;
                    let trailers = headers::apply(
                        shared.spec.trailer_authority,
                        &trailers,
                        &shared.spec.connection_nominated,
                        &finish.trailer_mutations,
                    )
                    .map_err(|error| mutation_failure(entry, &error))?;
                    send_frame(output, Frame::End(trailers)).await?;
                    return Ok::<_, StageError>((diagnostics, output_bytes));
                }
                http_result::Result::Reject(reject) => {
                    return Err(rejection(entry, reject.diagnostics.as_ref()).into());
                }
                _ => return Err(entry_failure(entry, "stream_result_order_invalid").into()),
            }
        }
    };

    let closed = || StageError::from(entry_failure(entry, "middleware_stream_closed"));
    let mut input_pump = std::pin::pin!(input_pump);
    let mut output_pump = std::pin::pin!(output_pump);
    let (input_bytes, (diagnostics, output_bytes)) = tokio::select! {
        input = &mut input_pump => match input {
            Ok(input_bytes) => (input_bytes, output_pump.await?),
            // A stage that rejects or fails stops reading input; its result
            // stream carries the reason.
            Err(InputStop::Closed) => {
                return Err(output_pump.await.err().unwrap_or_else(closed));
            }
            Err(InputStop::Failed(error)) => return Err(error),
        },
        output = &mut output_pump => {
            let output = output?;
            match input_pump.await {
                Ok(input_bytes) => (input_bytes, output),
                Err(InputStop::Closed) => return Err(closed()),
                Err(InputStop::Failed(error)) => return Err(error),
            }
        }
    };
    let mut done = StageDone {
        diagnostics: HttpStageDiagnostics::default(),
        transformed: true,
    };
    let reason_code = nonempty(&diagnostics.reason_code);
    collect_diagnostics(entry, diagnostics, &mut done.diagnostics);
    done.diagnostics.invocations.push(HttpStageInvocation {
        input_bytes,
        output_bytes: Some(output_bytes),
        transformed: true,
        ..invocation(entry, HttpStageOutcome::Finish, reason_code)
    });
    Ok(done)
}

/// Unwrap one stage result, classifying contract failures.
fn classify_result(
    runtime: &RuntimeHooks,
    entry: &DescribedChainEntry,
    direction: HttpDirection,
    next: Option<Result<HttpResult, tonic::Status>>,
) -> Result<http_result::Result, HttpMiddlewareFailure> {
    match next {
        Some(Ok(HttpResult {
            result: Some(result),
        })) => Ok(result),
        Some(Ok(HttpResult { result: None })) => Err(contract_failure(
            runtime,
            entry,
            direction,
            ContractFailureKind::UnknownResult,
        )),
        Some(Err(status)) => Err(status_failure(runtime, entry, direction, &status)),
        None => Err(entry_failure(entry, "middleware_result_stream_closed")),
    }
}

/// Classify an RPC status before diagnostics are normalized: a contract
/// failure must not become an ordinary service error.
fn status_failure(
    runtime: &RuntimeHooks,
    entry: &DescribedChainEntry,
    direction: HttpDirection,
    status: &tonic::Status,
) -> HttpMiddlewareFailure {
    if let Some(kind) = ContractFailureKind::from_status(status) {
        return contract_failure(runtime, entry, direction, kind);
    }
    if entry.http_protocol() == Some(HttpProtocol::Legacy)
        && let Some(reason) = hooks::failure_reason(status)
    {
        return entry_failure(entry, &reason);
    }
    if status.code() == tonic::Code::DeadlineExceeded {
        return entry_failure(entry, "middleware_timeout");
    }
    entry_failure(entry, &diagnostic_policy(entry).error_reason(status))
}

/// Report a contract failure. The exchange fails closed whatever `on_error`
/// says.
fn contract_failure(
    runtime: &RuntimeHooks,
    entry: &DescribedChainEntry,
    direction: HttpDirection,
    kind: ContractFailureKind,
) -> HttpMiddlewareFailure {
    runtime.contract_failure(&ContractFailure {
        config_name: entry.entry.name.clone(),
        implementation: entry.entry.implementation.clone(),
        direction,
        protocol: entry.http_protocol().unwrap_or(HttpProtocol::Legacy),
        kind,
    });
    entry_failure(entry, kind.reason())
}

fn diagnostic_policy(entry: &DescribedChainEntry) -> MiddlewareDiagnosticPolicy {
    entry
        .service
        .as_ref()
        .map_or(MiddlewareDiagnosticPolicy::Preserve, |service| {
            service.diagnostic_policy
        })
}

fn mutation_failure(
    entry: &DescribedChainEntry,
    error: &headers::HeaderMutationError,
) -> HttpMiddlewareFailure {
    entry_failure(
        entry,
        &diagnostic_policy(entry).header_mutation_error_reason(error),
    )
}

fn validate_inspect(
    mode: &http_inspect::Mode,
    permitted: &[HttpBodyMode],
    buffered_limit: usize,
) -> Result<StageMode, &'static str> {
    match mode {
        http_inspect::Mode::Buffered(mode)
            if permitted.contains(&HttpBodyMode::Buffered)
                && mode.max_body_bytes > 0
                && mode.max_body_bytes <= buffered_limit as u64 =>
        {
            Ok(StageMode::Buffered {
                max_body_bytes: usize::try_from(mode.max_body_bytes)
                    .map_err(|_| "body_mode_not_permitted")?,
            })
        }
        http_inspect::Mode::Stream(_) if permitted.contains(&HttpBodyMode::Stream) => {
            Ok(StageMode::Stream)
        }
        _ => Err("body_mode_not_permitted"),
    }
}

fn body_limits(
    entry: &DescribedChainEntry,
    permitted: &[HttpBodyMode],
    buffered_limit: usize,
    timeouts: PipelineTimeouts,
) -> HttpBodyLimits {
    let chunk = if permitted.is_empty() {
        0
    } else {
        stage_chunk_limit(entry) as u64
    };
    let queue_messages = STAGE_QUEUE_MESSAGES as u64;
    HttpBodyLimits {
        max_chunk_bytes: chunk,
        max_buffered_body_bytes: if permitted.contains(&HttpBodyMode::Buffered) {
            buffered_limit as u64
        } else {
            0
        },
        max_input_queue_bytes: chunk.saturating_mul(queue_messages),
        max_input_queue_messages: queue_messages,
        max_output_queue_bytes: chunk.saturating_mul(queue_messages),
        max_output_queue_messages: queue_messages,
        idle_timeout: permitted
            .contains(&HttpBodyMode::Stream)
            .then(|| duration_to_proto(timeouts.stream_idle)),
    }
}

fn duration_to_proto(duration: Duration) -> prost_types::Duration {
    prost_types::Duration {
        seconds: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        nanos: i32::try_from(duration.subsec_nanos()).unwrap_or_default(),
    }
}

fn validate_diagnostics(
    entry: &DescribedChainEntry,
    diagnostics: Option<&MiddlewareDiagnostics>,
) -> Result<MiddlewareDiagnostics, HttpMiddlewareFailure> {
    let diagnostics = diagnostics.cloned().unwrap_or_default();
    if diagnostics.reason.len() > MAX_MIDDLEWARE_REASON_BYTES {
        return Err(entry_failure(entry, "diagnostics_reason_over_capacity"));
    }
    if !diagnostics.reason_code.is_empty()
        && (diagnostics.reason_code.len() > MAX_MIDDLEWARE_REASON_CODE_BYTES
            || !is_stable_reason_code(&diagnostics.reason_code))
    {
        return Err(entry_failure(entry, "diagnostics_reason_code_invalid"));
    }
    if diagnostics.findings.len() > MAX_MIDDLEWARE_FINDINGS_PER_STAGE
        || diagnostics
            .findings
            .iter()
            .any(|finding| finding.encoded_len() > MAX_MIDDLEWARE_FINDING_BYTES)
    {
        return Err(entry_failure(entry, "diagnostics_findings_over_capacity"));
    }
    if diagnostics.metadata.len() > MAX_MIDDLEWARE_METADATA_ENTRIES
        || diagnostics
            .metadata
            .iter()
            .map(|(key, value)| key.len().saturating_add(value.len()))
            .fold(0usize, usize::saturating_add)
            > MAX_MIDDLEWARE_METADATA_BYTES
    {
        return Err(entry_failure(entry, "diagnostics_metadata_over_capacity"));
    }
    Ok(diagnostics)
}

/// Namespace one stage's findings and metadata. External services get the
/// same normalization as legacy results: no metadata and no service-chosen
/// finding text.
fn collect_diagnostics(
    entry: &DescribedChainEntry,
    mut diagnostics: MiddlewareDiagnostics,
    collected: &mut HttpStageDiagnostics,
) {
    if diagnostic_policy(entry) == MiddlewareDiagnosticPolicy::Normalize {
        diagnostics.metadata.clear();
        for finding in &mut diagnostics.findings {
            finding.r#type = format!("{}.finding", entry.entry.implementation);
            finding.label = EXTERNAL_FINDING_LABEL.to_string();
            finding.confidence.clear();
            finding.severity = match finding.severity.as_str() {
                "low" => "low",
                "high" => "high",
                _ => "medium",
            }
            .to_string();
        }
    }
    collected.findings.extend(
        diagnostics
            .findings
            .into_iter()
            .map(|finding| NamespacedFinding {
                middleware: entry.entry.name.clone(),
                finding,
            }),
    );
    if !diagnostics.metadata.is_empty() {
        collected.metadata.insert(
            entry.entry.name.clone(),
            diagnostics.metadata.into_iter().collect(),
        );
    }
}

fn rejection(
    entry: &DescribedChainEntry,
    diagnostics: Option<&MiddlewareDiagnostics>,
) -> HttpMiddlewareFailure {
    let diagnostics = match validate_diagnostics(entry, diagnostics) {
        Ok(diagnostics) => diagnostics,
        Err(failure) => return failure,
    };
    let reason_code = nonempty(&diagnostics.reason_code);
    let denial = MiddlewareDenial {
        config_name: entry.entry.name.clone(),
        reason_code: reason_code.clone(),
    };
    let mut retained = HttpStageDiagnostics::default();
    collect_diagnostics(entry, diagnostics, &mut retained);
    retained
        .invocations
        .push(invocation(entry, HttpStageOutcome::Reject, reason_code));
    HttpMiddlewareFailure {
        reason: middleware_denial_reason(&denial.config_name, denial.reason_code.as_deref()),
        denial: Some(denial),
        end_reason: MiddlewareSessionEndReason::MiddlewareDenial,
        diagnostics: Box::new(retained),
    }
}

/// The stage failed and the exchange fails closed.
pub fn entry_failure(entry: &DescribedChainEntry, reason: &str) -> HttpMiddlewareFailure {
    let mut diagnostics = HttpStageDiagnostics::default();
    diagnostics.invocations.push(HttpStageInvocation {
        failed: true,
        failure_reason: Some(reason.to_string()),
        ..invocation(entry, HttpStageOutcome::FailClosed, None)
    });
    HttpMiddlewareFailure {
        reason: format!("middleware_failed: {reason}"),
        denial: None,
        end_reason: MiddlewareSessionEndReason::MiddlewareFailure,
        diagnostics: Box::new(diagnostics),
    }
}

/// The exchange failed for a reason no single stage owns.
pub fn platform_failure(reason: &str) -> HttpMiddlewareFailure {
    HttpMiddlewareFailure {
        reason: format!("middleware_failed: {reason}"),
        denial: None,
        end_reason: MiddlewareSessionEndReason::MiddlewareFailure,
        diagnostics: Box::default(),
    }
}

fn cancelled(reason: &str) -> HttpMiddlewareFailure {
    HttpMiddlewareFailure {
        reason: format!("middleware_cancelled: {reason}"),
        denial: None,
        end_reason: MiddlewareSessionEndReason::Cancellation,
        diagnostics: Box::default(),
    }
}

pub fn invocation(
    entry: &DescribedChainEntry,
    outcome: HttpStageOutcome,
    reason_code: Option<String>,
) -> HttpStageInvocation {
    HttpStageInvocation {
        config_name: entry.entry.name.clone(),
        implementation: entry.entry.implementation.clone(),
        outcome,
        input_bytes: 0,
        output_bytes: None,
        transformed: false,
        failed: false,
        reason_code,
        failure_reason: None,
    }
}

pub fn fail_open_invocation(entry: &DescribedChainEntry, reason: &str) -> HttpStageInvocation {
    HttpStageInvocation {
        failed: true,
        failure_reason: Some(reason.to_string()),
        ..invocation(entry, HttpStageOutcome::FailOpen, None)
    }
}

fn nonempty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}
