// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP request pre-credentials middleware chain execution.
//!
//! BUFFERED stages hold one bounded body in memory. STREAM stages run input
//! and output pumps concurrently. The supervisor never retains `STREAM` input for
//! replay and never creates a middleware body spool.

use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use futures::StreamExt as _;
use prost::Message as _;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use openshell_core::proto::{
    HeaderMutation, HttpBegin, HttpBodyLimits, HttpBodyMode, HttpBufferedBody, HttpEvent,
    HttpHeader, HttpInputChunk, HttpInputEnd, HttpPreflight, HttpRequestPreflightHead,
    HttpRequestTarget, HttpResult, HttpUnchanged, MiddlewareDiagnostics, MiddlewareSessionEnd,
    MiddlewareSessionEndReason, RequestContext, http_buffered_result, http_event, http_inspect,
    http_preflight, http_preflight_result, http_result,
};

use super::{
    ChainEntry, ChainRunner, DescribedChainEntry, EXTERNAL_FINDING_LABEL,
    MAX_MIDDLEWARE_CHAIN_TIMEOUT, MAX_MIDDLEWARE_CONTEXT_BYTES, MAX_MIDDLEWARE_FINDING_BYTES,
    MAX_MIDDLEWARE_FINDINGS_PER_STAGE, MAX_MIDDLEWARE_HEADER_BYTES, MAX_MIDDLEWARE_HEADERS,
    MAX_MIDDLEWARE_METADATA_BYTES, MAX_MIDDLEWARE_METADATA_ENTRIES, MAX_MIDDLEWARE_REASON_BYTES,
    MAX_MIDDLEWARE_REASON_CODE_BYTES, MAX_MIDDLEWARE_TARGET_BYTES, MiddlewareDiagnosticPolicy,
    MiddlewareSessionAdmission, MiddlewareSessionPermit, NamespacedFinding, OnError, headers,
    is_stable_reason_code, middleware_denial_reason,
};

const STREAM_CHANNEL_CAPACITY: usize = 4;
const SESSION_END_TIMEOUT: Duration = Duration::from_millis(10);
const MAX_RECORDED_REQUEST_INVOCATIONS: usize = 1024;

/// Largest normalized STREAM chunk sent through the public contract.
pub const MAX_HTTP_REQUEST_STREAM_UNIT_BYTES: usize = 64 * 1024;

/// Compatibility limit for callers that still collect a complete body before
/// entering the two-mode session API. Complete-body protocol adapters use this
/// bound before re-evaluating transformed payloads.
pub const MAX_HTTP_REQUEST_DEFERRED_BYTES: usize = super::MAX_MIDDLEWARE_PAYLOAD_BYTES;

#[derive(Debug, Clone)]
pub struct HttpRequestPreflightInput {
    pub context: RequestContext,
    pub target: HttpRequestTarget,
    pub declared_body_length: Option<u64>,
    pub headers: Vec<HttpHeader>,
    pub connection_nominated_headers: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpRequestInvocationOutcome {
    Continue,
    Reject,
    Buffered,
    Stream,
    Unchanged,
    Replacement,
    Finish,
    FailClosed,
}

#[derive(Debug, Clone)]
pub struct HttpRequestInvocation {
    pub config_name: String,
    pub implementation: String,
    pub outcome: HttpRequestInvocationOutcome,
    pub sequence: Option<u64>,
    pub input_size: usize,
    pub output_size: Option<usize>,
    pub failed: bool,
    pub stage_disabled: bool,
    pub reason_code: Option<String>,
    pub failure_category: Option<String>,
}

pub struct HttpRequestPreflightOutcome {
    pub allowed: bool,
    pub reason: String,
    pub denial: Option<super::MiddlewareDenial>,
    pub headers: Vec<HttpHeader>,
    pub header_mutations: Vec<HeaderMutation>,
    pub session: Option<HttpRequestSession>,
    pub findings: Vec<NamespacedFinding>,
    pub metadata: BTreeMap<String, BTreeMap<String, String>>,
    pub invocations: Vec<HttpRequestInvocation>,
    pub session_capacity_exhausted: bool,
}

#[derive(Debug)]
pub struct HttpRequestMiddlewareFailure {
    pub reason: String,
    pub denial: Option<super::MiddlewareDenial>,
    pub diagnostics: Box<HttpRequestDiagnostics>,
}

impl std::fmt::Display for HttpRequestMiddlewareFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl std::error::Error for HttpRequestMiddlewareFailure {}

#[derive(Debug)]
pub struct HttpRequestFinish {
    pub body_units: Vec<Vec<u8>>,
    pub trailers: Vec<HttpHeader>,
    pub body_transformed: bool,
    pub findings: Vec<NamespacedFinding>,
    pub metadata: BTreeMap<String, BTreeMap<String, String>>,
    pub invocations: Vec<HttpRequestInvocation>,
}

#[derive(Debug, Default)]
pub struct HttpRequestDiagnostics {
    pub findings: Vec<NamespacedFinding>,
    pub metadata: BTreeMap<String, BTreeMap<String, String>>,
    pub invocations: Vec<HttpRequestInvocation>,
}

/// Input accepted by the independent request pipeline.
#[derive(Debug)]
pub enum HttpRequestBodyInput {
    Chunk(Vec<u8>),
    End(Vec<HttpHeader>),
}

/// Output produced by the independent request pipeline.
#[derive(Debug)]
pub enum HttpRequestBodyOutput {
    Start { output_body_bytes: Option<u64> },
    Chunk(Vec<u8>),
    End { trailers: Vec<HttpHeader> },
}

struct HttpStageTransport {
    sender: Option<mpsc::Sender<HttpEvent>>,
    responses: super::HttpResultStream,
    terminal_sent: bool,
}

impl HttpStageTransport {
    fn sender(&self) -> &mpsc::Sender<HttpEvent> {
        self.sender.as_ref().expect("active middleware sender")
    }

    async fn end(&mut self, reason: MiddlewareSessionEndReason) {
        if self.terminal_sent {
            return;
        }
        self.terminal_sent = true;
        let event = HttpEvent {
            event: Some(http_event::Event::SessionEnd(MiddlewareSessionEnd {
                reason: reason as i32,
                protocol_error: None,
            })),
        };
        let Some(sender) = self.sender.take() else {
            return;
        };
        let _ = tokio::time::timeout(SESSION_END_TIMEOUT, sender.send(event)).await;
        drop(sender);
        let _ = tokio::time::timeout(SESSION_END_TIMEOUT, async {
            while self.responses.next().await.is_some() {}
        })
        .await;
    }
}

impl Drop for HttpStageTransport {
    fn drop(&mut self) {
        if !self.terminal_sent {
            let Some(sender) = self.sender.take() else {
                return;
            };
            let mut responses =
                std::mem::replace(&mut self.responses, Box::pin(futures::stream::empty()));
            let task = async move {
                let event = HttpEvent {
                    event: Some(http_event::Event::SessionEnd(MiddlewareSessionEnd {
                        reason: MiddlewareSessionEndReason::Cancellation as i32,
                        protocol_error: None,
                    })),
                };
                let _ = tokio::time::timeout(SESSION_END_TIMEOUT, sender.send(event)).await;
                drop(sender);
                let _ = tokio::time::timeout(SESSION_END_TIMEOUT, async {
                    while responses.next().await.is_some() {}
                })
                .await;
            };
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(task);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StageMode {
    Buffered { max_body_bytes: usize },
    Stream,
}

struct HttpRequestStage {
    entry: DescribedChainEntry,
    transport: HttpStageTransport,
    mode: StageMode,
    connection_nominated_headers: Vec<String>,
    output_unit_limit: usize,
    deadline: Instant,
}

#[derive(Debug)]
enum StageFrame {
    Start { output_body_bytes: Option<u64> },
    Chunk(Vec<u8>),
    End(Vec<HttpHeader>),
}

#[derive(Default)]
struct StageReport {
    findings: Vec<NamespacedFinding>,
    metadata: BTreeMap<String, BTreeMap<String, String>>,
    invocations: Vec<HttpRequestInvocation>,
    transformed: bool,
}

pub struct HttpRequestSession {
    stages: Vec<HttpRequestStage>,
    findings: Vec<NamespacedFinding>,
    metadata: BTreeMap<String, BTreeMap<String, String>>,
    invocations: Vec<HttpRequestInvocation>,
    session_admission: Option<MiddlewareSessionPermit>,
    declared_body_length: Option<u64>,
    pending_input: Vec<Vec<u8>>,
}

impl HttpRequestSession {
    pub fn take_diagnostics(&mut self) -> HttpRequestDiagnostics {
        HttpRequestDiagnostics {
            findings: std::mem::take(&mut self.findings),
            metadata: std::mem::take(&mut self.metadata),
            invocations: std::mem::take(&mut self.invocations),
        }
    }

    #[must_use]
    pub fn stream_unit_limit(&self) -> usize {
        self.stages
            .iter()
            .filter(|stage| stage.mode == StageMode::Stream)
            .map(|stage| {
                stage
                    .entry
                    .max_payload_bytes()
                    .clamp(1, MAX_HTTP_REQUEST_STREAM_UNIT_BYTES)
            })
            .min()
            .unwrap_or(MAX_HTTP_REQUEST_STREAM_UNIT_BYTES)
    }

    #[must_use]
    pub fn requires_withholding(&self) -> bool {
        self.stages
            .iter()
            .any(|stage| matches!(stage.mode, StageMode::Buffered { .. }))
    }

    /// Run all body stages as a bounded pipeline. The caller must pump input
    /// and drain output concurrently with this future.
    pub async fn run(
        mut self,
        mut input: mpsc::Receiver<HttpRequestBodyInput>,
        output: mpsc::Sender<HttpRequestBodyOutput>,
    ) -> Result<HttpRequestFinish, HttpRequestMiddlewareFailure> {
        let stage_count = self.stages.len();
        if stage_count == 0 {
            return Err(failure("request_pipeline_without_stages", None));
        }

        let mut links = Vec::with_capacity(stage_count + 1);
        for _ in 0..=stage_count {
            links.push(mpsc::channel::<StageFrame>(STREAM_CHANNEL_CAPACITY));
        }
        let mut receivers: Vec<Option<mpsc::Receiver<StageFrame>>> = links
            .iter_mut()
            .map(|(_, receiver)| Some(std::mem::replace(receiver, mpsc::channel(1).1)))
            .collect();
        let source = links[0].0.clone();
        let source_limit = self.stream_unit_limit();
        let source_declared = self.declared_body_length;
        let source_task = tokio::spawn(async move {
            source
                .send(StageFrame::Start {
                    output_body_bytes: source_declared,
                })
                .await
                .map_err(|_| failure("request_pipeline_closed", None))?;
            let mut ended = false;
            while let Some(item) = input.recv().await {
                match item {
                    HttpRequestBodyInput::Chunk(data) => {
                        if ended || data.is_empty() || data.len() > source_limit {
                            return Err(failure("request_stream_chunk_invalid", None));
                        }
                        source
                            .send(StageFrame::Chunk(data))
                            .await
                            .map_err(|_| failure("request_pipeline_closed", None))?;
                    }
                    HttpRequestBodyInput::End(trailers) => {
                        if ended {
                            return Err(failure("request_input_end_duplicate", None));
                        }
                        ended = true;
                        source
                            .send(StageFrame::End(trailers))
                            .await
                            .map_err(|_| failure("request_pipeline_closed", None))?;
                        break;
                    }
                }
            }
            if !ended {
                return Err(failure("request_input_end_missing", None));
            }
            Ok::<(), HttpRequestMiddlewareFailure>(())
        });

        let chain_deadline = Instant::now() + MAX_MIDDLEWARE_CHAIN_TIMEOUT;
        let downstream_limits = self
            .stages
            .iter()
            .skip(1)
            .map(|stage| match stage.mode {
                StageMode::Buffered { max_body_bytes } => max_body_bytes,
                StageMode::Stream => stage.entry.max_payload_bytes(),
            })
            .chain(std::iter::once(MAX_HTTP_REQUEST_STREAM_UNIT_BYTES))
            .map(|limit| limit.clamp(1, MAX_HTTP_REQUEST_STREAM_UNIT_BYTES))
            .collect::<Vec<_>>();
        let mut stage_tasks = Vec::with_capacity(stage_count);
        for (index, mut stage) in self.stages.drain(..).enumerate() {
            stage.output_unit_limit = downstream_limits[index];
            stage.deadline = chain_deadline;
            let receiver = receivers[index]
                .take()
                .expect("stage input receiver must exist");
            let sender = links[index + 1].0.clone();
            stage_tasks.push(tokio::spawn(run_stage(stage, receiver, sender)));
        }
        drop(links);

        let mut final_receiver = receivers[stage_count]
            .take()
            .expect("final output receiver must exist");
        let mut started = false;
        let mut ended = false;
        let mut trailers = Vec::new();
        while let Some(frame) = final_receiver.recv().await {
            match frame {
                StageFrame::Start { output_body_bytes } if !started => {
                    started = true;
                    output
                        .send(HttpRequestBodyOutput::Start { output_body_bytes })
                        .await
                        .map_err(|_| failure("request_output_closed", None))?;
                }
                StageFrame::Chunk(data) if started && !ended => {
                    output
                        .send(HttpRequestBodyOutput::Chunk(data))
                        .await
                        .map_err(|_| failure("request_output_closed", None))?;
                }
                StageFrame::End(value) if started && !ended => {
                    ended = true;
                    trailers = value.clone();
                    output
                        .send(HttpRequestBodyOutput::End { trailers: value })
                        .await
                        .map_err(|_| failure("request_output_closed", None))?;
                    break;
                }
                _ => return Err(failure("request_pipeline_event_order_invalid", None)),
            }
        }
        drop(output);

        source_task
            .await
            .map_err(|_| failure("request_input_task_failed", None))??;

        let mut body_transformed = false;
        let mut stage_tasks = stage_tasks.into_iter();
        while let Some(task) = stage_tasks.next() {
            let report = match task.await {
                Ok(Ok(report)) => report,
                Ok(Err(mut error)) => {
                    for task in stage_tasks {
                        task.abort();
                        let _ = task.await;
                    }
                    error.diagnostics.findings.splice(0..0, self.findings);
                    let mut metadata = self.metadata;
                    metadata.extend(std::mem::take(&mut error.diagnostics.metadata));
                    error.diagnostics.metadata = metadata;
                    error.diagnostics.invocations.splice(0..0, self.invocations);
                    return Err(error);
                }
                Err(_) => {
                    for task in stage_tasks {
                        task.abort();
                        let _ = task.await;
                    }
                    return Err(failure("request_stage_task_failed", None));
                }
            };
            body_transformed |= report.transformed;
            self.findings.extend(report.findings);
            self.metadata.extend(report.metadata);
            self.invocations.extend(report.invocations);
        }
        if !started || !ended {
            return Err(failure("request_pipeline_incomplete", None));
        }
        self.session_admission.take();
        Ok(HttpRequestFinish {
            body_units: Vec::new(),
            trailers,
            body_transformed,
            findings: self.findings,
            metadata: self.metadata,
            invocations: self.invocations,
        })
    }

    /// Compatibility helper for complete-body callers. Network relays use
    /// [`Self::run`] so input and output remain independent.
    pub fn push_body(
        &mut self,
        data: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, HttpRequestMiddlewareFailure> {
        if data.is_empty() || data.len() > self.stream_unit_limit() {
            return Err(failure("request_stream_chunk_invalid", None));
        }
        self.pending_input.push(data);
        Ok(Vec::new())
    }

    pub async fn finish(
        self,
        trailers: Vec<HttpHeader>,
    ) -> Result<HttpRequestFinish, HttpRequestMiddlewareFailure> {
        let (output_tx, mut output_rx) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
        let (body_tx, body_rx) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
        let pending = self.pending_input.clone();
        let run = self.run(body_rx, output_tx);
        let feed = async move {
            for chunk in pending {
                body_tx
                    .send(HttpRequestBodyInput::Chunk(chunk))
                    .await
                    .map_err(|_| failure("request_pipeline_closed", None))?;
            }
            body_tx
                .send(HttpRequestBodyInput::End(trailers))
                .await
                .map_err(|_| failure("request_pipeline_closed", None))
        };
        let collect = async move {
            let mut units = Vec::new();
            let mut retained = 0usize;
            while let Some(event) = output_rx.recv().await {
                if let HttpRequestBodyOutput::Chunk(data) = event {
                    retained = retained.saturating_add(data.len());
                    if retained > MAX_HTTP_REQUEST_DEFERRED_BYTES {
                        return Err(failure("request_output_over_capacity", None));
                    }
                    units.push(data);
                }
            }
            Ok::<_, HttpRequestMiddlewareFailure>(units)
        };
        let (finish, feed, units) = tokio::join!(run, feed, collect);
        let units = units?;
        let mut finish = finish?;
        feed?;
        finish.body_units = units;
        Ok(finish)
    }

    pub async fn finish_to(
        self,
        trailers: Vec<HttpHeader>,
        output: mpsc::Sender<Vec<u8>>,
    ) -> Result<HttpRequestFinish, HttpRequestMiddlewareFailure> {
        let (event_tx, mut event_rx) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
        let (body_tx, body_rx) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
        let pending = self.pending_input.clone();
        let run = self.run(body_rx, event_tx);
        let feed = async move {
            for chunk in pending {
                body_tx
                    .send(HttpRequestBodyInput::Chunk(chunk))
                    .await
                    .map_err(|_| failure("request_pipeline_closed", None))?;
            }
            body_tx
                .send(HttpRequestBodyInput::End(trailers))
                .await
                .map_err(|_| failure("request_pipeline_closed", None))
        };
        let forward = async move {
            while let Some(event) = event_rx.recv().await {
                if let HttpRequestBodyOutput::Chunk(data) = event {
                    output
                        .send(data)
                        .await
                        .map_err(|_| failure("request_output_closed", None))?;
                }
            }
            Ok::<(), HttpRequestMiddlewareFailure>(())
        };
        let (finish, feed, forward) = tokio::join!(run, feed, forward);
        feed?;
        forward?;
        finish
    }

    pub async fn end(mut self, reason: MiddlewareSessionEndReason) {
        for stage in &mut self.stages {
            stage.transport.end(reason).await;
        }
        self.session_admission.take();
    }
}

async fn run_stage(
    mut stage: HttpRequestStage,
    input: mpsc::Receiver<StageFrame>,
    output: mpsc::Sender<StageFrame>,
) -> Result<StageReport, HttpRequestMiddlewareFailure> {
    send_event_for_entry(
        &stage.entry,
        stage.deadline,
        stage.transport.sender(),
        HttpEvent {
            event: Some(http_event::Event::Begin(HttpBegin {})),
        },
    )
    .await?;
    let result = match stage.mode {
        StageMode::Buffered { max_body_bytes } => {
            run_buffered_stage(&mut stage, input, output, max_body_bytes).await
        }
        StageMode::Stream => run_stream_stage(&mut stage, input, output).await,
    };
    let terminal_reason = match &result {
        Ok(_) => MiddlewareSessionEndReason::Normal,
        Err(error) if error.denial.is_some() => MiddlewareSessionEndReason::MiddlewareDenial,
        Err(_) => MiddlewareSessionEndReason::MiddlewareFailure,
    };
    stage.transport.end(terminal_reason).await;
    result
}

async fn run_buffered_stage(
    stage: &mut HttpRequestStage,
    mut input: mpsc::Receiver<StageFrame>,
    output: mpsc::Sender<StageFrame>,
    max_body_bytes: usize,
) -> Result<StageReport, HttpRequestMiddlewareFailure> {
    let mut body = Vec::new();
    let mut trailers = None;
    let mut saw_start = false;
    while let Some(frame) = input.recv().await {
        match frame {
            StageFrame::Start { .. } if !saw_start => saw_start = true,
            StageFrame::Chunk(data) if saw_start && trailers.is_none() => {
                if body.len().saturating_add(data.len()) > max_body_bytes {
                    return Err(stage_failure(stage, "buffered_input_over_capacity"));
                }
                body.extend_from_slice(&data);
            }
            StageFrame::End(value) if saw_start && trailers.is_none() => {
                trailers = Some(value);
                break;
            }
            _ => return Err(stage_failure(stage, "buffered_input_order_invalid")),
        }
    }
    let mut trailers =
        trailers.ok_or_else(|| stage_failure(stage, "buffered_input_end_missing"))?;
    let original_len = body.len();
    let result = exchange(
        stage,
        HttpEvent {
            event: Some(http_event::Event::BufferedBody(HttpBufferedBody {
                data: body.clone(),
                visible_trailers: trailers.clone(),
            })),
        },
    )
    .await?;
    let buffered = match result.result {
        Some(http_result::Result::BufferedResult(result)) => result,
        Some(http_result::Result::Reject(reject)) => {
            return Err(rejection(stage, reject.diagnostics));
        }
        _ => return Err(stage_failure(stage, "buffered_result_expected")),
    };
    let diagnostics = validate_diagnostics_message(buffered.diagnostics.as_ref())?;
    if !buffered.header_mutations.is_empty() {
        return Err(stage_failure(stage, "late_header_mutations_not_permitted"));
    }
    trailers = headers::apply(
        headers::HeaderAuthority::RequestTrailers,
        &trailers,
        &stage.connection_nominated_headers,
        &buffered.trailer_mutations,
    )
    .map_err(|error| mutation_failure(stage, &error))?;
    let (body, outcome, transformed) = match buffered.body {
        Some(http_buffered_result::Body::Unchanged(HttpUnchanged {})) => {
            (body, HttpRequestInvocationOutcome::Unchanged, false)
        }
        Some(http_buffered_result::Body::Replacement(replacement)) => {
            if replacement.len() > max_body_bytes {
                return Err(stage_failure(stage, "buffered_output_over_capacity"));
            }
            (replacement, HttpRequestInvocationOutcome::Replacement, true)
        }
        None => return Err(stage_failure(stage, "buffered_body_result_missing")),
    };
    output
        .send(StageFrame::Start {
            output_body_bytes: Some(body.len() as u64),
        })
        .await
        .map_err(|_| stage_failure(stage, "request_output_closed"))?;
    for chunk in body.chunks(stage.output_unit_limit) {
        output
            .send(StageFrame::Chunk(chunk.to_vec()))
            .await
            .map_err(|_| stage_failure(stage, "request_output_closed"))?;
    }
    output
        .send(StageFrame::End(trailers))
        .await
        .map_err(|_| stage_failure(stage, "request_output_closed"))?;
    Ok(report_from_diagnostics(
        stage,
        diagnostics,
        outcome,
        original_len,
        Some(body.len()),
        transformed,
    ))
}

async fn run_stream_stage(
    stage: &mut HttpRequestStage,
    mut input: mpsc::Receiver<StageFrame>,
    output: mpsc::Sender<StageFrame>,
) -> Result<StageReport, HttpRequestMiddlewareFailure> {
    let output_unit_limit = stage.output_unit_limit;
    let input_ended = Arc::new(AtomicBool::new(false));
    let input_trailers = Arc::new(Mutex::new(None::<Vec<HttpHeader>>));
    let input_bytes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let output_bytes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (input_delivered, mut input_delivered_rx) = watch::channel(false);

    let sender = stage.transport.sender().clone();
    let deadline = stage.deadline;
    let input_entry = stage.entry.clone();
    let input_ended_for_pump = Arc::clone(&input_ended);
    let trailers_for_pump = Arc::clone(&input_trailers);
    let input_bytes_for_pump = Arc::clone(&input_bytes);
    let input_pump = async move {
        let mut saw_start = false;
        while let Some(frame) = input.recv().await {
            match frame {
                StageFrame::Start { .. } if !saw_start => saw_start = true,
                StageFrame::Chunk(data) if saw_start => {
                    if data.is_empty()
                        || data.len()
                            > input_entry
                                .max_payload_bytes()
                                .min(MAX_HTTP_REQUEST_STREAM_UNIT_BYTES)
                    {
                        return Err(failure_for_entry(
                            &input_entry,
                            "stream_input_chunk_invalid",
                        ));
                    }
                    input_bytes_for_pump.fetch_add(data.len(), Ordering::Relaxed);
                    send_event_for_entry(
                        &input_entry,
                        deadline,
                        &sender,
                        HttpEvent {
                            event: Some(http_event::Event::InputChunk(HttpInputChunk { data })),
                        },
                    )
                    .await?;
                }
                StageFrame::End(trailers) if saw_start => {
                    *trailers_for_pump.lock().expect("trailer lock poisoned") =
                        Some(trailers.clone());
                    // A Finish can race the sender task as soon as the peer
                    // consumes InputEnd. Publish the state before enqueueing
                    // the event; a failed send still fails the joined pump.
                    input_ended_for_pump.store(true, Ordering::Release);
                    send_event_for_entry(
                        &input_entry,
                        deadline,
                        &sender,
                        HttpEvent {
                            event: Some(http_event::Event::InputEnd(HttpInputEnd {
                                visible_trailers: trailers,
                            })),
                        },
                    )
                    .await?;
                    input_delivered.send_replace(true);
                    return Ok::<(), HttpRequestMiddlewareFailure>(());
                }
                _ => {
                    return Err(failure_for_entry(
                        &input_entry,
                        "stream_input_order_invalid",
                    ));
                }
            }
        }
        Err(failure_for_entry(&input_entry, "stream_input_end_missing"))
    };

    let entry = stage.entry.clone();
    let diagnostic_policy = stage
        .entry
        .service
        .as_ref()
        .map_or(MiddlewareDiagnosticPolicy::Preserve, |service| {
            service.diagnostic_policy
        });
    let responses = &mut stage.transport.responses;
    let connection_nominated = stage.connection_nominated_headers.clone();
    let output_bytes_for_pump = Arc::clone(&output_bytes);
    let output_pump = async move {
        let mut started = false;
        let mut declared_output = None;
        loop {
            // STREAM output is independent of input. A whole-body service may
            // legitimately withhold OutputStart until it has consumed all
            // input, so apply the response idle timeout only after InputEnd has
            // been delivered. Transport closure and early output remain
            // observable while the input pump is active.
            let result = loop {
                if *input_delivered_rx.borrow() {
                    break next_result_for_entry(&entry, deadline, diagnostic_policy, responses)
                        .await?;
                }
                tokio::select! {
                    result = responses.next() => {
                        break validate_next_result_for_entry(
                            &entry,
                            diagnostic_policy,
                            result,
                        )?;
                    }
                    changed = input_delivered_rx.changed() => {
                        if changed.is_err() {
                            return Err(failure_for_entry(
                                &entry,
                                "stream_input_end_missing",
                            ));
                        }
                    }
                }
            };
            match result.result {
                Some(http_result::Result::OutputStart(start)) if !started => {
                    if !start.header_mutations.is_empty() {
                        return Err(failure_for_entry(
                            &entry,
                            "late_header_mutations_not_permitted",
                        ));
                    }
                    declared_output = start.output_body_bytes;
                    started = true;
                    output
                        .send(StageFrame::Start {
                            output_body_bytes: declared_output,
                        })
                        .await
                        .map_err(|_| failure_for_entry(&entry, "request_output_closed"))?;
                }
                Some(http_result::Result::OutputChunk(chunk)) if started => {
                    if chunk.data.is_empty()
                        || chunk.data.len()
                            > entry
                                .max_payload_bytes()
                                .min(MAX_HTTP_REQUEST_STREAM_UNIT_BYTES)
                    {
                        return Err(failure_for_entry(&entry, "stream_output_chunk_invalid"));
                    }
                    let total = output_bytes_for_pump
                        .fetch_add(chunk.data.len(), Ordering::Relaxed)
                        + chunk.data.len();
                    if declared_output.is_some_and(|declared| total as u64 > declared) {
                        return Err(failure_for_entry(&entry, "stream_output_length_mismatch"));
                    }
                    for unit in chunk.data.chunks(output_unit_limit) {
                        output
                            .send(StageFrame::Chunk(unit.to_vec()))
                            .await
                            .map_err(|_| failure_for_entry(&entry, "request_output_closed"))?;
                    }
                }
                Some(http_result::Result::Finish(finish)) if started => {
                    if !input_ended.load(Ordering::Acquire) {
                        return Err(failure_for_entry(&entry, "stream_finish_before_input_end"));
                    }
                    let total = output_bytes_for_pump.load(Ordering::Relaxed) as u64;
                    if declared_output.is_some_and(|declared| declared != total) {
                        return Err(failure_for_entry(&entry, "stream_output_length_mismatch"));
                    }
                    let diagnostics = validate_diagnostics_message(finish.diagnostics.as_ref())?;
                    let trailers = input_trailers
                        .lock()
                        .expect("trailer lock poisoned")
                        .clone()
                        .ok_or_else(|| failure_for_entry(&entry, "stream_input_end_missing"))?;
                    let trailers = headers::apply(
                        headers::HeaderAuthority::RequestTrailers,
                        &trailers,
                        &connection_nominated,
                        &finish.trailer_mutations,
                    )
                    .map_err(|error| {
                        mutation_failure_for_entry(&entry, diagnostic_policy, &error)
                    })?;
                    output
                        .send(StageFrame::End(trailers))
                        .await
                        .map_err(|_| failure_for_entry(&entry, "request_output_closed"))?;
                    return Ok::<MiddlewareDiagnostics, HttpRequestMiddlewareFailure>(diagnostics);
                }
                Some(http_result::Result::Reject(reject)) => {
                    return Err(rejection_for_entry(&entry, reject.diagnostics));
                }
                _ => return Err(failure_for_entry(&entry, "stream_result_order_invalid")),
            }
        }
    };

    let ((), diagnostics) = tokio::try_join!(input_pump, output_pump)?;
    let input_size = input_bytes.load(Ordering::Relaxed);
    let output_size = output_bytes.load(Ordering::Relaxed);
    Ok(report_from_diagnostics(
        stage,
        diagnostics,
        HttpRequestInvocationOutcome::Finish,
        input_size,
        Some(output_size),
        true,
    ))
}

impl ChainRunner {
    pub async fn preflight_http_request(
        &self,
        entries: &[ChainEntry],
        input: HttpRequestPreflightInput,
    ) -> miette::Result<HttpRequestPreflightOutcome> {
        let described = self.describe_chain(entries).await?;
        self.preflight_described_http_request(described, input)
            .await
    }

    pub async fn preflight_described_http_request(
        &self,
        described: Vec<DescribedChainEntry>,
        input: HttpRequestPreflightInput,
    ) -> miette::Result<HttpRequestPreflightOutcome> {
        if described.is_empty() {
            return Ok(empty_preflight_outcome(input.headers));
        }
        if validate_preflight_input(&input).is_err() {
            return Ok(failed_preflight_outcome(
                input.headers,
                Vec::new(),
                "middleware_failed: request_input_over_capacity".into(),
                Vec::new(),
                BTreeMap::new(),
                described
                    .iter()
                    .map(|entry| failed_invocation(entry, "request_input_over_capacity"))
                    .collect(),
            ));
        }
        let session_admission = match self.try_reserve_middleware_session() {
            MiddlewareSessionAdmission::Admitted(admission) => admission,
            MiddlewareSessionAdmission::AtCapacity => {
                return Ok(session_capacity_exhausted(described, input.headers));
            }
        };
        let mut headers = input.headers.clone();
        let mut header_mutations = Vec::new();
        let mut stages = Vec::new();
        let mut findings = Vec::new();
        let mut metadata = BTreeMap::new();
        let mut invocations = Vec::new();
        let chain_deadline = Instant::now() + MAX_MIDDLEWARE_CHAIN_TIMEOUT;

        for entry in described {
            if entry.on_error() == OnError::FailOpen {
                end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure).await;
                invocations.push(failed_invocation(&entry, "http_fail_open_unsupported"));
                return Ok(failed_preflight_outcome(
                    headers,
                    header_mutations,
                    "middleware_failed: HTTP middleware no longer supports on_error=fail_open; use fail_closed or remove on_error".into(),
                    findings,
                    metadata,
                    invocations,
                ));
            }
            let Some(service) = entry.service.as_ref() else {
                end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure).await;
                invocations.push(failed_invocation(&entry, "binding_not_described"));
                return Ok(failed_preflight_outcome(
                    headers,
                    header_mutations,
                    "middleware_failed: binding_not_described".into(),
                    findings,
                    metadata,
                    invocations,
                ));
            };
            let supported = entry.binding.as_ref().map_or(&[][..], |binding| {
                binding.supported_http_body_modes.as_slice()
            });
            let permitted_modes = permitted_body_modes(&input, &entry, supported);
            let limits = body_limits(&entry);
            let (sender, receiver) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
            let preflight = HttpPreflight {
                head: Some(http_preflight::Head::Request(HttpRequestPreflightHead {
                    context: Some(input.context.clone()),
                    target: Some(input.target.clone()),
                    headers: headers.clone(),
                    middleware_name: entry.entry.implementation.clone(),
                    config: Some(entry.entry.config.clone()),
                })),
                permitted_body_modes: permitted_modes.clone(),
                late_header_modes: Vec::new(),
                limits: Some(limits),
                declared_input_bytes: input.declared_body_length,
            };
            let stage_timeout = Instant::now() + entry.timeout();
            let stage_deadline = chain_deadline.min(stage_timeout);
            let timeout_reason = if chain_deadline <= stage_timeout {
                "middleware_chain_timeout"
            } else {
                "middleware_timeout"
            };
            let opened = tokio::time::timeout_at(stage_deadline, async {
                sender
                    .send(HttpEvent {
                        event: Some(http_event::Event::Preflight(preflight)),
                    })
                    .await
                    .map_err(|_| tonic::Status::unavailable("middleware request stream closed"))?;
                let mut responses = service
                    .service
                    .open_http_request_pre_credentials(receiver)
                    .await?;
                let result = responses.next().await.ok_or_else(|| {
                    tonic::Status::unavailable("middleware result stream closed")
                })??;
                Ok::<_, tonic::Status>((responses, result))
            })
            .await;
            let (responses, result) = match opened {
                Ok(Ok(value)) => value,
                Ok(Err(error)) => {
                    let reason = service.diagnostic_policy.error_reason(&error);
                    end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure).await;
                    invocations.push(failed_invocation(&entry, &reason));
                    return Ok(failed_preflight_outcome(
                        headers,
                        header_mutations,
                        format!("middleware_failed: {reason}"),
                        findings,
                        metadata,
                        invocations,
                    ));
                }
                Err(_) => {
                    end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure).await;
                    invocations.push(failed_invocation(&entry, timeout_reason));
                    return Ok(failed_preflight_outcome(
                        headers,
                        header_mutations,
                        format!("middleware_failed: {timeout_reason}"),
                        findings,
                        metadata,
                        invocations,
                    ));
                }
            };
            let mut stage = HttpRequestStage {
                entry: entry.clone(),
                transport: HttpStageTransport {
                    sender: Some(sender),
                    responses,
                    terminal_sent: false,
                },
                mode: StageMode::Stream,
                connection_nominated_headers: input.connection_nominated_headers.clone(),
                output_unit_limit: MAX_HTTP_REQUEST_STREAM_UNIT_BYTES,
                deadline: chain_deadline,
            };
            match result.result {
                Some(http_result::Result::PreflightResult(result)) => {
                    let diagnostics =
                        match validate_diagnostics_message(result.diagnostics.as_ref()) {
                            Ok(value) => value,
                            Err(error) => {
                                stage
                                    .transport
                                    .end(MiddlewareSessionEndReason::MiddlewareFailure)
                                    .await;
                                end_stages(
                                    &mut stages,
                                    MiddlewareSessionEndReason::MiddlewareFailure,
                                )
                                .await;
                                invocations.push(failed_invocation(&entry, &error.reason));
                                return Ok(failed_preflight_outcome(
                                    headers,
                                    header_mutations,
                                    error.reason,
                                    findings,
                                    metadata,
                                    invocations,
                                ));
                            }
                        };
                    let updated = match headers::apply(
                        headers::HeaderAuthority::Request,
                        &headers,
                        &input.connection_nominated_headers,
                        &result.header_mutations,
                    ) {
                        Ok(value) => value,
                        Err(error) => {
                            let reason = service
                                .diagnostic_policy
                                .header_mutation_error_reason(&error);
                            stage
                                .transport
                                .end(MiddlewareSessionEndReason::MiddlewareFailure)
                                .await;
                            end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure)
                                .await;
                            invocations.push(failed_invocation(&entry, &reason));
                            return Ok(failed_preflight_outcome(
                                headers,
                                header_mutations,
                                format!("middleware_failed: {reason}"),
                                findings,
                                metadata,
                                invocations,
                            ));
                        }
                    };
                    headers = updated;
                    header_mutations.extend(result.header_mutations);
                    collect_diagnostics(&entry, diagnostics.clone(), &mut findings, &mut metadata);
                    let reason_code = nonempty(&diagnostics.reason_code);
                    match result.decision {
                        Some(http_preflight_result::Decision::ContinueWithoutBody(_)) => {
                            invocations.push(preflight_invocation(
                                &entry,
                                HttpRequestInvocationOutcome::Continue,
                                reason_code,
                            ));
                            stage
                                .transport
                                .end(MiddlewareSessionEndReason::StageSkipped)
                                .await;
                        }
                        Some(http_preflight_result::Decision::Inspect(inspect)) => {
                            let mode = match validate_inspect(
                                &inspect,
                                &permitted_modes,
                                entry.max_payload_bytes(),
                            ) {
                                Ok(value) => value,
                                Err(reason) => {
                                    stage
                                        .transport
                                        .end(MiddlewareSessionEndReason::MiddlewareFailure)
                                        .await;
                                    end_stages(
                                        &mut stages,
                                        MiddlewareSessionEndReason::MiddlewareFailure,
                                    )
                                    .await;
                                    invocations.push(failed_invocation(&entry, reason));
                                    return Ok(failed_preflight_outcome(
                                        headers,
                                        header_mutations,
                                        format!("middleware_failed: {reason}"),
                                        findings,
                                        metadata,
                                        invocations,
                                    ));
                                }
                            };
                            stage.mode = mode;
                            invocations.push(preflight_invocation(
                                &entry,
                                match mode {
                                    StageMode::Buffered { .. } => {
                                        HttpRequestInvocationOutcome::Buffered
                                    }
                                    StageMode::Stream => HttpRequestInvocationOutcome::Stream,
                                },
                                reason_code,
                            ));
                            stages.push(stage);
                        }
                        None => {
                            stage
                                .transport
                                .end(MiddlewareSessionEndReason::MiddlewareFailure)
                                .await;
                            end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure)
                                .await;
                            invocations
                                .push(failed_invocation(&entry, "preflight_decision_missing"));
                            return Ok(failed_preflight_outcome(
                                headers,
                                header_mutations,
                                "middleware_failed: preflight_decision_missing".into(),
                                findings,
                                metadata,
                                invocations,
                            ));
                        }
                    }
                }
                Some(http_result::Result::Reject(reject)) => {
                    let diagnostics =
                        match validate_diagnostics_message(reject.diagnostics.as_ref()) {
                            Ok(value) => value,
                            Err(error) => {
                                stage
                                    .transport
                                    .end(MiddlewareSessionEndReason::MiddlewareFailure)
                                    .await;
                                end_stages(
                                    &mut stages,
                                    MiddlewareSessionEndReason::MiddlewareFailure,
                                )
                                .await;
                                invocations.push(failed_invocation(&entry, &error.reason));
                                return Ok(failed_preflight_outcome(
                                    headers,
                                    header_mutations,
                                    error.reason,
                                    findings,
                                    metadata,
                                    invocations,
                                ));
                            }
                        };
                    collect_diagnostics(&entry, diagnostics.clone(), &mut findings, &mut metadata);
                    let reason_code = nonempty(&diagnostics.reason_code);
                    invocations.push(preflight_invocation(
                        &entry,
                        HttpRequestInvocationOutcome::Reject,
                        reason_code.clone(),
                    ));
                    stage
                        .transport
                        .end(MiddlewareSessionEndReason::MiddlewareDenial)
                        .await;
                    end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareDenial).await;
                    let denial = super::MiddlewareDenial {
                        config_name: entry.entry.name.clone(),
                        reason_code,
                    };
                    return Ok(HttpRequestPreflightOutcome {
                        allowed: false,
                        reason: middleware_denial_reason(
                            &denial.config_name,
                            denial.reason_code.as_deref(),
                        ),
                        denial: Some(denial),
                        headers,
                        header_mutations,
                        session: None,
                        findings,
                        metadata,
                        invocations,
                        session_capacity_exhausted: false,
                    });
                }
                _ => {
                    stage
                        .transport
                        .end(MiddlewareSessionEndReason::MiddlewareFailure)
                        .await;
                    end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure).await;
                    invocations.push(failed_invocation(&entry, "preflight_result_expected"));
                    return Ok(failed_preflight_outcome(
                        headers,
                        header_mutations,
                        "middleware_failed: preflight_result_expected".into(),
                        findings,
                        metadata,
                        invocations,
                    ));
                }
            }
        }

        let session = (!stages.is_empty()).then(|| HttpRequestSession {
            stages,
            findings: Vec::new(),
            metadata: BTreeMap::new(),
            invocations: Vec::new(),
            session_admission: Some(session_admission),
            declared_body_length: input.declared_body_length,
            pending_input: Vec::new(),
        });
        Ok(HttpRequestPreflightOutcome {
            allowed: true,
            reason: String::new(),
            denial: None,
            headers,
            header_mutations,
            session,
            findings,
            metadata,
            invocations,
            session_capacity_exhausted: false,
        })
    }
}

async fn send_event_for_entry(
    entry: &DescribedChainEntry,
    chain_deadline: Instant,
    sender: &mpsc::Sender<HttpEvent>,
    event: HttpEvent,
) -> Result<(), HttpRequestMiddlewareFailure> {
    let stage_deadline = Instant::now() + entry.timeout();
    let (deadline, timeout_reason) = if chain_deadline <= stage_deadline {
        (chain_deadline, "middleware_chain_timeout")
    } else {
        (stage_deadline, "middleware_timeout")
    };
    tokio::time::timeout_at(deadline, sender.send(event))
        .await
        .map_err(|_| failure_for_entry(entry, timeout_reason))?
        .map_err(|_| failure_for_entry(entry, "middleware_stream_closed"))
}

async fn exchange(
    stage: &mut HttpRequestStage,
    event: HttpEvent,
) -> Result<HttpResult, HttpRequestMiddlewareFailure> {
    send_event_for_entry(
        &stage.entry,
        stage.deadline,
        stage.transport.sender(),
        event,
    )
    .await?;
    let policy = stage
        .entry
        .service
        .as_ref()
        .map_or(MiddlewareDiagnosticPolicy::Preserve, |service| {
            service.diagnostic_policy
        });
    next_result_for_entry(
        &stage.entry,
        stage.deadline,
        policy,
        &mut stage.transport.responses,
    )
    .await
}

async fn next_result_for_entry(
    entry: &DescribedChainEntry,
    chain_deadline: Instant,
    diagnostic_policy: MiddlewareDiagnosticPolicy,
    responses: &mut super::HttpResultStream,
) -> Result<HttpResult, HttpRequestMiddlewareFailure> {
    let stage_deadline = Instant::now() + entry.timeout();
    let (deadline, timeout_reason) = if chain_deadline <= stage_deadline {
        (chain_deadline, "middleware_chain_timeout")
    } else {
        (stage_deadline, "middleware_timeout")
    };
    tokio::time::timeout_at(deadline, responses.next())
        .await
        .map_or_else(
            |_| Err(failure_for_entry(entry, timeout_reason)),
            |result| validate_next_result_for_entry(entry, diagnostic_policy, result),
        )
}

fn validate_next_result_for_entry(
    entry: &DescribedChainEntry,
    diagnostic_policy: MiddlewareDiagnosticPolicy,
    result: Option<Result<HttpResult, tonic::Status>>,
) -> Result<HttpResult, HttpRequestMiddlewareFailure> {
    match result {
        Some(Ok(result)) => Ok(result),
        Some(Err(error)) => Err(failure_for_entry(
            entry,
            &diagnostic_policy.error_reason(&error),
        )),
        None => Err(failure_for_entry(entry, "middleware_result_stream_closed")),
    }
}

fn body_limits(entry: &DescribedChainEntry) -> HttpBodyLimits {
    let max_chunk = entry
        .max_payload_bytes()
        .min(MAX_HTTP_REQUEST_STREAM_UNIT_BYTES) as u64;
    HttpBodyLimits {
        max_chunk_bytes: max_chunk,
        max_buffered_body_bytes: entry.max_payload_bytes() as u64,
        max_input_queue_bytes: max_chunk.saturating_mul(STREAM_CHANNEL_CAPACITY as u64),
        max_input_queue_messages: STREAM_CHANNEL_CAPACITY as u64,
        max_output_queue_bytes: max_chunk.saturating_mul(STREAM_CHANNEL_CAPACITY as u64),
        max_output_queue_messages: STREAM_CHANNEL_CAPACITY as u64,
        max_total_input_bytes: None,
        max_total_output_bytes: None,
        idle_timeout: Some(duration_to_proto(entry.timeout())),
        session_timeout: None,
    }
}

fn duration_to_proto(duration: Duration) -> prost_types::Duration {
    prost_types::Duration {
        seconds: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        nanos: i32::try_from(duration.subsec_nanos()).expect("nanoseconds fit in i32"),
    }
}

fn permitted_body_modes(
    input: &HttpRequestPreflightInput,
    entry: &DescribedChainEntry,
    supported: &[i32],
) -> Vec<i32> {
    let mut modes = Vec::new();
    if supported.contains(&(HttpBodyMode::Buffered as i32))
        && input
            .declared_body_length
            .is_none_or(|length| length <= entry.max_payload_bytes() as u64)
    {
        modes.push(HttpBodyMode::Buffered as i32);
    }
    if supported.contains(&(HttpBodyMode::Stream as i32)) && entry.max_payload_bytes() > 0 {
        modes.push(HttpBodyMode::Stream as i32);
    }
    modes
}

fn validate_inspect(
    inspect: &openshell_core::proto::HttpInspect,
    permitted_modes: &[i32],
    max_payload_bytes: usize,
) -> Result<StageMode, &'static str> {
    match inspect.mode.as_ref() {
        Some(http_inspect::Mode::Buffered(mode))
            if permitted_modes.contains(&(HttpBodyMode::Buffered as i32))
                && mode.max_body_bytes > 0
                && mode.max_body_bytes <= max_payload_bytes as u64 =>
        {
            Ok(StageMode::Buffered {
                max_body_bytes: usize::try_from(mode.max_body_bytes)
                    .map_err(|_| "request_body_mode_not_permitted")?,
            })
        }
        Some(http_inspect::Mode::Stream(_))
            if permitted_modes.contains(&(HttpBodyMode::Stream as i32)) =>
        {
            Ok(StageMode::Stream)
        }
        Some(_) => Err("request_body_mode_not_permitted"),
        None => Err("request_body_mode_missing"),
    }
}

fn validate_preflight_input(input: &HttpRequestPreflightInput) -> miette::Result<()> {
    if input.context.encoded_len() > MAX_MIDDLEWARE_CONTEXT_BYTES {
        return Err(miette::miette!("request context exceeds platform limit"));
    }
    if input.target.encoded_len() > MAX_MIDDLEWARE_TARGET_BYTES {
        return Err(miette::miette!("request target exceeds platform limit"));
    }
    if input.headers.len() > MAX_MIDDLEWARE_HEADERS {
        return Err(miette::miette!(
            "request header count exceeds platform limit"
        ));
    }
    if input
        .headers
        .iter()
        .map(prost::Message::encoded_len)
        .sum::<usize>()
        > MAX_MIDDLEWARE_HEADER_BYTES
    {
        return Err(miette::miette!("request headers exceed platform limit"));
    }
    Ok(())
}

fn validate_diagnostics_message(
    diagnostics: Option<&MiddlewareDiagnostics>,
) -> Result<MiddlewareDiagnostics, HttpRequestMiddlewareFailure> {
    let diagnostics = diagnostics.cloned().unwrap_or_default();
    if diagnostics.reason.len() > MAX_MIDDLEWARE_REASON_BYTES {
        return Err(failure(
            "middleware_failed: request_reason_over_capacity",
            None,
        ));
    }
    if !diagnostics.reason_code.is_empty()
        && (diagnostics.reason_code.len() > MAX_MIDDLEWARE_REASON_CODE_BYTES
            || !is_stable_reason_code(&diagnostics.reason_code))
    {
        return Err(failure(
            "middleware_failed: request_reason_code_invalid",
            None,
        ));
    }
    if diagnostics.findings.len() > MAX_MIDDLEWARE_FINDINGS_PER_STAGE
        || diagnostics
            .findings
            .iter()
            .any(|finding| finding.encoded_len() > MAX_MIDDLEWARE_FINDING_BYTES)
    {
        return Err(failure(
            "middleware_failed: request_findings_over_capacity",
            None,
        ));
    }
    if diagnostics.metadata.len() > MAX_MIDDLEWARE_METADATA_ENTRIES
        || diagnostics
            .metadata
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum::<usize>()
            > MAX_MIDDLEWARE_METADATA_BYTES
    {
        return Err(failure(
            "middleware_failed: request_metadata_over_capacity",
            None,
        ));
    }
    Ok(diagnostics)
}

fn collect_diagnostics(
    entry: &DescribedChainEntry,
    mut diagnostics: MiddlewareDiagnostics,
    all_findings: &mut Vec<NamespacedFinding>,
    all_metadata: &mut BTreeMap<String, BTreeMap<String, String>>,
) {
    if entry
        .service
        .as_ref()
        .is_some_and(|service| service.diagnostic_policy == MiddlewareDiagnosticPolicy::Normalize)
    {
        diagnostics.metadata.clear();
        for finding in &mut diagnostics.findings {
            finding.r#type = format!("{}.finding", entry.entry.implementation);
            finding.label = EXTERNAL_FINDING_LABEL.to_string();
            finding.confidence.clear();
            finding.severity = "medium".into();
        }
    }
    all_findings.extend(
        diagnostics
            .findings
            .into_iter()
            .map(|finding| NamespacedFinding {
                middleware: entry.entry.name.clone(),
                finding,
            }),
    );
    if !diagnostics.metadata.is_empty() {
        all_metadata.insert(
            entry.entry.name.clone(),
            diagnostics.metadata.into_iter().collect(),
        );
    }
}

fn report_from_diagnostics(
    stage: &HttpRequestStage,
    diagnostics: MiddlewareDiagnostics,
    outcome: HttpRequestInvocationOutcome,
    input_size: usize,
    output_size: Option<usize>,
    transformed: bool,
) -> StageReport {
    let mut report = StageReport {
        transformed,
        ..StageReport::default()
    };
    collect_diagnostics(
        &stage.entry,
        diagnostics.clone(),
        &mut report.findings,
        &mut report.metadata,
    );
    record_request_invocation(
        &mut report.invocations,
        HttpRequestInvocation {
            config_name: stage.entry.entry.name.clone(),
            implementation: stage.entry.entry.implementation.clone(),
            outcome,
            sequence: None,
            input_size,
            output_size,
            failed: false,
            stage_disabled: false,
            reason_code: nonempty(&diagnostics.reason_code),
            failure_category: None,
        },
    );
    report
}

fn preflight_invocation(
    entry: &DescribedChainEntry,
    outcome: HttpRequestInvocationOutcome,
    reason_code: Option<String>,
) -> HttpRequestInvocation {
    HttpRequestInvocation {
        config_name: entry.entry.name.clone(),
        implementation: entry.entry.implementation.clone(),
        outcome,
        sequence: None,
        input_size: 0,
        output_size: None,
        failed: false,
        stage_disabled: false,
        reason_code,
        failure_category: None,
    }
}

fn failed_invocation(entry: &DescribedChainEntry, reason: &str) -> HttpRequestInvocation {
    HttpRequestInvocation {
        config_name: entry.entry.name.clone(),
        implementation: entry.entry.implementation.clone(),
        outcome: HttpRequestInvocationOutcome::FailClosed,
        sequence: None,
        input_size: 0,
        output_size: None,
        failed: true,
        stage_disabled: true,
        reason_code: None,
        failure_category: Some(request_failure_category(reason).into()),
    }
}

fn record_request_invocation(
    invocations: &mut Vec<HttpRequestInvocation>,
    invocation: HttpRequestInvocation,
) {
    if invocations.len() < MAX_RECORDED_REQUEST_INVOCATIONS {
        invocations.push(invocation);
    } else if let Some(existing) = invocations
        .iter_mut()
        .find(|item| item.config_name == invocation.config_name)
    {
        existing.input_size = existing.input_size.saturating_add(invocation.input_size);
        existing.output_size = match (existing.output_size, invocation.output_size) {
            (Some(left), Some(right)) => Some(left.saturating_add(right)),
            (left, right) => left.or(right),
        };
        existing.failed |= invocation.failed;
        existing.outcome = invocation.outcome;
    }
}

fn rejection(
    stage: &HttpRequestStage,
    diagnostics: Option<MiddlewareDiagnostics>,
) -> HttpRequestMiddlewareFailure {
    rejection_for_entry(&stage.entry, diagnostics)
}

fn rejection_for_entry(
    entry: &DescribedChainEntry,
    diagnostics: Option<MiddlewareDiagnostics>,
) -> HttpRequestMiddlewareFailure {
    match validate_diagnostics_message(diagnostics.as_ref()) {
        Ok(diagnostics) => {
            let denial = super::MiddlewareDenial {
                config_name: entry.entry.name.clone(),
                reason_code: nonempty(&diagnostics.reason_code),
            };
            let mut retained = HttpRequestDiagnostics::default();
            collect_diagnostics(
                entry,
                diagnostics.clone(),
                &mut retained.findings,
                &mut retained.metadata,
            );
            retained.invocations.push(HttpRequestInvocation {
                config_name: entry.entry.name.clone(),
                implementation: entry.entry.implementation.clone(),
                outcome: HttpRequestInvocationOutcome::Reject,
                sequence: None,
                input_size: 0,
                output_size: None,
                failed: false,
                stage_disabled: false,
                reason_code: nonempty(&diagnostics.reason_code),
                failure_category: None,
            });
            HttpRequestMiddlewareFailure {
                reason: middleware_denial_reason(
                    &denial.config_name,
                    denial.reason_code.as_deref(),
                ),
                denial: Some(denial),
                diagnostics: Box::new(retained),
            }
        }
        Err(error) => error,
    }
}

fn mutation_failure(
    stage: &HttpRequestStage,
    error: &headers::HeaderMutationError,
) -> HttpRequestMiddlewareFailure {
    let policy = stage
        .entry
        .service
        .as_ref()
        .map_or(MiddlewareDiagnosticPolicy::Preserve, |service| {
            service.diagnostic_policy
        });
    mutation_failure_for_entry(&stage.entry, policy, error)
}

fn mutation_failure_for_entry(
    entry: &DescribedChainEntry,
    policy: MiddlewareDiagnosticPolicy,
    error: &headers::HeaderMutationError,
) -> HttpRequestMiddlewareFailure {
    failure_for_entry(entry, &policy.header_mutation_error_reason(error))
}

fn stage_failure(stage: &HttpRequestStage, reason: &str) -> HttpRequestMiddlewareFailure {
    failure_for_entry(&stage.entry, reason)
}

fn failure_for_entry(entry: &DescribedChainEntry, reason: &str) -> HttpRequestMiddlewareFailure {
    let mut diagnostics = HttpRequestDiagnostics::default();
    diagnostics
        .invocations
        .push(failed_invocation(entry, reason));
    HttpRequestMiddlewareFailure {
        reason: format!("middleware_failed: {reason}"),
        denial: None,
        diagnostics: Box::new(diagnostics),
    }
}

fn failure(reason: &str, denial: Option<super::MiddlewareDenial>) -> HttpRequestMiddlewareFailure {
    HttpRequestMiddlewareFailure {
        reason: reason.into(),
        denial,
        diagnostics: Box::default(),
    }
}

fn nonempty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}

fn empty_preflight_outcome(headers: Vec<HttpHeader>) -> HttpRequestPreflightOutcome {
    HttpRequestPreflightOutcome {
        allowed: true,
        reason: String::new(),
        denial: None,
        headers,
        header_mutations: Vec::new(),
        session: None,
        findings: Vec::new(),
        metadata: BTreeMap::new(),
        invocations: Vec::new(),
        session_capacity_exhausted: false,
    }
}

fn failed_preflight_outcome(
    headers: Vec<HttpHeader>,
    header_mutations: Vec<HeaderMutation>,
    reason: String,
    findings: Vec<NamespacedFinding>,
    metadata: BTreeMap<String, BTreeMap<String, String>>,
    invocations: Vec<HttpRequestInvocation>,
) -> HttpRequestPreflightOutcome {
    HttpRequestPreflightOutcome {
        allowed: false,
        reason,
        denial: None,
        headers,
        header_mutations,
        session: None,
        findings,
        metadata,
        invocations,
        session_capacity_exhausted: false,
    }
}

fn session_capacity_exhausted(
    entries: Vec<DescribedChainEntry>,
    headers: Vec<HttpHeader>,
) -> HttpRequestPreflightOutcome {
    let invocations = entries
        .iter()
        .map(|entry| failed_invocation(entry, "session_capacity_exhausted"))
        .collect();
    HttpRequestPreflightOutcome {
        session_capacity_exhausted: true,
        invocations,
        ..failed_preflight_outcome(
            headers,
            Vec::new(),
            "middleware_failed: session_capacity_exhausted".into(),
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
        )
    }
}

async fn end_stages(stages: &mut [HttpRequestStage], reason: MiddlewareSessionEndReason) {
    for stage in stages {
        stage.transport.end(reason).await;
    }
}

fn request_failure_category(reason: &str) -> &'static str {
    if reason.contains("timeout") {
        "timeout"
    } else if reason.contains("capacity") {
        "capacity"
    } else if reason.contains("header") {
        "header_mutation"
    } else if reason.contains("order")
        || reason.contains("result")
        || reason.contains("protocol")
        || reason.contains("mode")
        || reason.contains("stream_")
    {
        "protocol"
    } else {
        "service"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preflight_only_binding_cannot_select_a_body_mode() {
        let buffered = openshell_core::proto::HttpInspect {
            mode: Some(http_inspect::Mode::Buffered(
                openshell_core::proto::HttpBufferedMode {
                    max_body_bytes: 1024,
                },
            )),
        };
        let stream = openshell_core::proto::HttpInspect {
            mode: Some(http_inspect::Mode::Stream(
                openshell_core::proto::HttpStreamMode {},
            )),
        };

        assert_eq!(
            validate_inspect(&buffered, &[], 0),
            Err("request_body_mode_not_permitted")
        );
        assert_eq!(
            validate_inspect(&stream, &[], 0),
            Err("request_body_mode_not_permitted")
        );
    }

    #[test]
    fn diagnostics_reject_unknown_reason_codes() {
        let diagnostics = MiddlewareDiagnostics {
            reason_code: "Not-Stable".into(),
            ..MiddlewareDiagnostics::default()
        };
        assert!(validate_diagnostics_message(Some(&diagnostics)).is_err());
    }

    #[test]
    fn rejection_preserves_diagnostics_and_denial_invocation() {
        let entry = DescribedChainEntry {
            entry: ChainEntry {
                name: "guard".into(),
                implementation: "test/guard".into(),
                order: 0,
                config: prost_types::Struct::default(),
                on_error: OnError::FailClosed,
            },
            service: None,
            binding: None,
            max_payload_bytes: 1024,
            timeout: Duration::from_millis(500),
        };
        let failure = rejection_for_entry(
            &entry,
            Some(MiddlewareDiagnostics {
                reason_code: "content_match".into(),
                findings: vec![openshell_core::proto::Finding {
                    r#type: "secret".into(),
                    label: "Secret".into(),
                    count: 1,
                    confidence: "high".into(),
                    severity: "high".into(),
                }],
                metadata: std::iter::once(("rule".into(), "configured".into())).collect(),
                ..Default::default()
            }),
        );

        assert_eq!(
            failure.denial.unwrap().reason_code.as_deref(),
            Some("content_match")
        );
        assert_eq!(failure.diagnostics.findings.len(), 1);
        assert_eq!(failure.diagnostics.metadata["guard"]["rule"], "configured");
        assert_eq!(
            failure.diagnostics.invocations[0].outcome,
            HttpRequestInvocationOutcome::Reject
        );
    }
}
