// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP response pre-return middleware chain execution.

mod preflight;
mod validation;

#[cfg(test)]
use validation::permitted_body_modes;
use validation::{
    BodyAction, CurrentBodyAction, encoded_header_bytes, strip_stale_integrity,
    validate_body_result, validate_trailers_result,
};

use std::collections::BTreeMap;
use std::time::Duration;

use futures::StreamExt as _;
use prost::Message as _;
use tokio::sync::mpsc;
use tokio::time::Instant;

use openshell_core::proto::{
    Finding, HttpHeader, HttpRequestTarget, HttpResponseBodyMode, HttpResponseBodyPassThrough,
    HttpResponseBodyUnit, HttpResponseEvent, HttpResponseEventResult, HttpResponsePreflight,
    HttpResponseTrailers, MiddlewareSessionEnd, MiddlewareSessionEndReason, RequestContext,
    http_response_body_result, http_response_body_skip_remaining, http_response_body_transform,
    http_response_body_unit, http_response_event, http_response_event_result,
    http_response_preflight_result,
};

use super::{
    ChainEntry, ChainRunner, DescribedChainEntry, MAX_MIDDLEWARE_CHAIN_TIMEOUT,
    MAX_MIDDLEWARE_CONTEXT_BYTES, MAX_MIDDLEWARE_FINDING_BYTES, MAX_MIDDLEWARE_FINDINGS_PER_STAGE,
    MAX_MIDDLEWARE_HEADER_BYTES, MAX_MIDDLEWARE_HEADER_MUTATION_WIRE_BYTES, MAX_MIDDLEWARE_HEADERS,
    MAX_MIDDLEWARE_METADATA_BYTES, MAX_MIDDLEWARE_METADATA_ENTRIES, MAX_MIDDLEWARE_REASON_BYTES,
    MAX_MIDDLEWARE_REASON_CODE_BYTES, MAX_MIDDLEWARE_TARGET_BYTES, MiddlewareDiagnosticPolicy,
    MiddlewareSessionAdmission, MiddlewareSessionPermit, NamespacedFinding, OnError, headers,
    is_stable_reason_code, middleware_denial_reason,
};

const STREAM_CHANNEL_CAPACITY: usize = 4;
const SESSION_END_TIMEOUT: Duration = Duration::from_millis(10);
pub const MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES: usize = 64 * 1024;
/// Maximum logical body bytes retained across a session's stage buffers and
/// pending output. Temporary exchange copies have the per-binding payload cap.
pub const MAX_HTTP_RESPONSE_RETAINED_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Return whether a response metadata field becomes stale after body changes.
#[must_use]
pub fn is_stale_http_response_integrity_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "accept-ranges"
            | "etag"
            | "content-md5"
            | "digest"
            | "content-digest"
            | "repr-digest"
            | "signature"
            | "signature-input"
    )
}

#[derive(Debug, Clone)]
pub struct HttpResponsePreflightInput {
    pub context: RequestContext,
    pub target: HttpRequestTarget,
    pub status_code: u16,
    /// Parsed upstream Content-Length when present and valid.
    pub declared_body_length: Option<u64>,
    /// Sanitized, lowercased final response headers in wire order.
    pub headers: Vec<HttpHeader>,
    /// Lowercased names nominated by the original response's `Connection`
    /// fields. Their values are not exposed to middleware.
    pub connection_nominated_headers: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpResponseInvocationOutcome {
    Skip,
    BlockDelivery,
    HeadersOnly,
    WholeBody,
    Stream,
    Trailers,
    PassThrough,
    Transform,
    SkipRemaining,
    FailOpen,
    FailClosed,
}

#[derive(Debug, Clone)]
pub struct HttpResponseInvocation {
    pub config_name: String,
    pub implementation: String,
    pub outcome: HttpResponseInvocationOutcome,
    pub sequence: Option<u64>,
    pub input_size: usize,
    pub output_size: Option<usize>,
    pub failed: bool,
    pub stage_disabled: bool,
    pub reason_code: Option<String>,
    pub failure_category: Option<String>,
}

pub struct HttpResponsePreflightOutcome {
    pub allowed: bool,
    pub reason: String,
    pub denial: Option<super::MiddlewareDenial>,
    pub headers: Vec<HttpHeader>,
    pub session: Option<HttpResponseSession>,
    pub findings: Vec<NamespacedFinding>,
    pub metadata: BTreeMap<String, BTreeMap<String, String>>,
    pub invocations: Vec<HttpResponseInvocation>,
    pub session_capacity_exhausted: bool,
}

#[derive(Debug)]
pub struct HttpResponseMiddlewareFailure {
    pub reason: String,
    pub denial: Option<super::MiddlewareDenial>,
    /// Exchange diagnostics collected before a consuming operation failed.
    pub diagnostics: HttpResponseDiagnostics,
}

impl std::fmt::Display for HttpResponseMiddlewareFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl std::error::Error for HttpResponseMiddlewareFailure {}

impl HttpResponseMiddlewareFailure {
    fn with_diagnostics(mut self, diagnostics: HttpResponseDiagnostics) -> Self {
        self.diagnostics = diagnostics;
        self
    }
}

#[derive(Debug)]
pub struct HttpResponseFinish {
    /// Units released while whole-body stages were finalized.
    pub body_units: Vec<Vec<u8>>,
    pub trailers: Vec<HttpHeader>,
    /// True when a whole-body stage transformed or deleted body bytes. The
    /// caller must strip stale representation validators before commitment.
    pub strip_stale_integrity_headers: bool,
    pub findings: Vec<NamespacedFinding>,
    pub metadata: BTreeMap<String, BTreeMap<String, String>>,
    pub invocations: Vec<HttpResponseInvocation>,
}

#[derive(Debug, Default)]
pub struct HttpResponseDiagnostics {
    pub findings: Vec<NamespacedFinding>,
    pub metadata: BTreeMap<String, BTreeMap<String, String>>,
    pub invocations: Vec<HttpResponseInvocation>,
}

struct HttpResponseStageTransport {
    sender: mpsc::Sender<HttpResponseEvent>,
    responses: super::HttpResponseResultStream,
}

impl HttpResponseStageTransport {
    async fn end(self, reason: MiddlewareSessionEndReason) {
        let _ = tokio::time::timeout(SESSION_END_TIMEOUT, self.end_inner(reason)).await;
    }

    async fn end_inner(self, reason: MiddlewareSessionEndReason) {
        if self.sender.send(session_end_event(reason)).await.is_err() {
            return;
        }
        self.drain().await;
    }

    async fn drain(self) {
        let Self {
            sender,
            mut responses,
        } = self;
        // Keep the response stream alive while half-closing the request side.
        // Dropping both handles together schedules an HTTP/2 CANCEL and can
        // discard the terminal event before remote middleware receives it.
        drop(sender);
        while responses.next().await.is_some() {}
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StageMode {
    HeadersOnly,
    WholeBody,
    Stream,
}

struct HttpResponseStage {
    entry: DescribedChainEntry,
    transport: Option<HttpResponseStageTransport>,
    mode: StageMode,
    next_sequence: u64,
    whole_body: Vec<u8>,
}

impl HttpResponseStage {
    fn is_active(&self) -> bool {
        self.transport.is_some()
    }

    fn is_body_active(&self) -> bool {
        self.is_active() && self.mode != StageMode::HeadersOnly
    }

    async fn end(&mut self, reason: MiddlewareSessionEndReason) {
        if let Some(transport) = self.transport.take() {
            transport.end(reason).await;
        }
    }
}

pub struct HttpResponseSession {
    runner: ChainRunner,
    stages: Vec<HttpResponseStage>,
    findings: Vec<NamespacedFinding>,
    metadata: BTreeMap<String, BTreeMap<String, String>>,
    invocations: Vec<HttpResponseInvocation>,
    session_admission: Option<MiddlewareSessionPermit>,
    body_transformed: bool,
    retained_body_bytes: usize,
    defer_output_until_finish: bool,
    deferred_output: Vec<Vec<u8>>,
    connection_nominated_headers: Vec<String>,
    whole_body_deadline: Option<Instant>,
}

impl HttpResponseSession {
    pub fn take_diagnostics(&mut self) -> HttpResponseDiagnostics {
        HttpResponseDiagnostics {
            findings: std::mem::take(&mut self.findings),
            metadata: std::mem::take(&mut self.metadata),
            invocations: std::mem::take(&mut self.invocations),
        }
    }

    #[must_use]
    pub fn requires_whole_body(&self) -> bool {
        self.stages.iter().any(|stage| {
            stage.is_active() && stage.mode == StageMode::WholeBody && stage.next_sequence == 1
        })
    }

    /// Start the platform-owned whole-body wall-clock deadline.
    pub fn start_whole_body_deadline(&mut self, timeout: Duration) {
        self.whole_body_deadline = self.requires_whole_body().then(|| Instant::now() + timeout);
    }

    #[must_use]
    pub fn whole_body_deadline(&self) -> Option<Instant> {
        self.requires_whole_body()
            .then_some(self.whole_body_deadline)
            .flatten()
    }

    /// Fail each still-buffering whole-body stage in policy order.
    ///
    /// Fail-open stages release their retained input through the remaining
    /// chain. A fail-closed stage stops the response with a typed failure.
    pub async fn expire_whole_body_deadline(
        &mut self,
    ) -> Result<Vec<Vec<u8>>, HttpResponseMiddlewareFailure> {
        self.whole_body_deadline = None;
        let mut released = std::mem::take(&mut self.deferred_output);
        let chain_deadline = Instant::now() + MAX_MIDDLEWARE_CHAIN_TIMEOUT;
        for index in 0..self.stages.len() {
            if !self.stages[index].is_active()
                || self.stages[index].mode != StageMode::WholeBody
                || self.stages[index].next_sequence != 1
            {
                continue;
            }
            let original = std::mem::take(&mut self.stages[index].whole_body);
            let output = self
                .handle_stage_failure(index, "whole_body_accumulation_timeout", None, original)
                .await?;
            if !output.is_empty() {
                released.extend(
                    self.process_units_from(index + 1, output, chain_deadline)
                        .await?,
                );
            }
        }
        self.defer_output_until_finish = false;
        self.release_body_bytes(&released);
        Ok(released)
    }

    #[must_use]
    pub fn stream_unit_limit(&self) -> usize {
        self.stages
            .iter()
            .filter(|stage| stage.is_active() && stage.mode == StageMode::Stream)
            .map(|stage| {
                stage
                    .entry
                    .max_payload_bytes
                    .clamp(1, MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES)
            })
            .min()
            .unwrap_or(MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES)
    }

    /// Process one normalized body unit through the active chain.
    ///
    /// The caller must provide no more than [`Self::stream_unit_limit`] bytes.
    /// A whole-body barrier retains output until [`Self::finish`] is called.
    pub async fn push_body(
        &mut self,
        data: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, HttpResponseMiddlewareFailure> {
        if data.len() > self.stream_unit_limit() {
            return Err(HttpResponseMiddlewareFailure {
                reason: "response_stream_unit_over_capacity".into(),
                denial: None,
                diagnostics: HttpResponseDiagnostics::default(),
            });
        }
        let _work = self
            .runner
            .reserve_middleware_work_admission()
            .await
            .map_err(|error| HttpResponseMiddlewareFailure {
                reason: format!("middleware_failed: {error}"),
                denial: None,
                diagnostics: HttpResponseDiagnostics::default(),
            })?;
        let deadline = Instant::now() + MAX_MIDDLEWARE_CHAIN_TIMEOUT;
        // Between pushes, the first active whole-body barrier owns all input
        // not returned to the relay (at most the 4 MiB binding cap). Later
        // barriers cannot receive bytes until it finishes or disables itself;
        // finish consumes the session and expiry disables all such barriers.
        // Replacement admission reserves an additional upstream unit below.
        self.retained_body_bytes += data.len();
        debug_assert!(self.retained_body_bytes <= MAX_HTTP_RESPONSE_RETAINED_BODY_BYTES);
        let output = self.process_units_from(0, vec![data], deadline).await?;
        if !self.defer_output_until_finish {
            self.release_body_bytes(&output);
            return Ok(output);
        }
        if self.requires_whole_body() {
            self.deferred_output.extend(output);
            return Ok(Vec::new());
        }

        self.defer_output_until_finish = false;
        let mut released = std::mem::take(&mut self.deferred_output);
        released.extend(output);
        self.release_body_bytes(&released);
        Ok(released)
    }

    /// Finalize every body stage, preserve normalized trailers, and end streams.
    pub async fn finish(
        mut self,
        mut trailers: Vec<HttpHeader>,
    ) -> Result<HttpResponseFinish, HttpResponseMiddlewareFailure> {
        let _work = match self.runner.reserve_middleware_work_admission().await {
            Ok(work) => work,
            Err(error) => {
                return Err(HttpResponseMiddlewareFailure {
                    reason: format!("middleware_failed: {error}"),
                    denial: None,
                    diagnostics: self.take_diagnostics(),
                });
            }
        };
        let deadline = Instant::now() + MAX_MIDDLEWARE_CHAIN_TIMEOUT;
        let mut released = std::mem::take(&mut self.deferred_output);
        for index in 0..self.stages.len() {
            let stage_output = match self.finish_stage(index, deadline).await {
                Ok(output) => output,
                Err(failure) => {
                    self.end_all(MiddlewareSessionEndReason::MiddlewareFailure)
                        .await;
                    return Err(failure.with_diagnostics(self.take_diagnostics()));
                }
            };
            if !stage_output.is_empty() {
                let output = match self
                    .process_units_from(index + 1, stage_output, deadline)
                    .await
                {
                    Ok(output) => output,
                    Err(failure) => {
                        self.end_all(MiddlewareSessionEndReason::MiddlewareFailure)
                            .await;
                        return Err(failure.with_diagnostics(self.take_diagnostics()));
                    }
                };
                released.extend(output);
            }
        }

        if self.body_transformed {
            strip_stale_integrity(&mut trailers);
        }
        let trailers = match self.process_trailers(trailers, deadline).await {
            Ok(trailers) => trailers,
            Err(failure) => {
                self.end_all(MiddlewareSessionEndReason::MiddlewareFailure)
                    .await;
                return Err(failure.with_diagnostics(self.take_diagnostics()));
            }
        };
        self.end_all(MiddlewareSessionEndReason::Normal).await;
        self.session_admission.take();
        Ok(HttpResponseFinish {
            body_units: released,
            trailers,
            strip_stale_integrity_headers: self.body_transformed,
            findings: self.findings,
            metadata: self.metadata,
            invocations: self.invocations,
        })
    }

    pub async fn end(mut self, reason: MiddlewareSessionEndReason) {
        self.end_all(reason).await;
    }

    fn release_body_bytes(&mut self, units: &[Vec<u8>]) {
        self.retained_body_bytes -= units.iter().map(Vec::len).sum::<usize>();
    }

    async fn process_units_from(
        &mut self,
        start: usize,
        mut units: Vec<Vec<u8>>,
        deadline: Instant,
    ) -> Result<Vec<Vec<u8>>, HttpResponseMiddlewareFailure> {
        for index in start..self.stages.len() {
            let mut next = Vec::new();
            for unit in units {
                let chunk_limit = if self.stages[index].mode == StageMode::Stream {
                    self.stages[index]
                        .entry
                        .max_payload_bytes
                        .min(MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES)
                } else {
                    unit.len().max(1)
                };
                if unit.is_empty() {
                    next.extend(self.process_stage_unit(index, unit, deadline).await?);
                } else {
                    for chunk in unit.chunks(chunk_limit) {
                        next.extend(
                            self.process_stage_unit(index, chunk.to_vec(), deadline)
                                .await?,
                        );
                    }
                }
            }
            units = next;
            if units.is_empty()
                && self.stages[index + 1..]
                    .iter()
                    .all(|stage| stage.mode != StageMode::WholeBody)
            {
                break;
            }
        }
        Ok(units)
    }

    async fn process_stage_unit(
        &mut self,
        index: usize,
        data: Vec<u8>,
        deadline: Instant,
    ) -> Result<Vec<Vec<u8>>, HttpResponseMiddlewareFailure> {
        let deadline = self.exchange_deadline(deadline);
        let stage = &mut self.stages[index];
        if !stage.is_active() || stage.mode == StageMode::HeadersOnly {
            return Ok(vec![data]);
        }
        if stage.mode == StageMode::WholeBody {
            if stage.whole_body.len().saturating_add(data.len()) > stage.entry.max_payload_bytes {
                let mut original = std::mem::take(&mut stage.whole_body);
                original.extend_from_slice(&data);
                return self
                    .handle_stage_failure(index, "whole_body_over_capacity", None, original)
                    .await;
            }
            stage.whole_body.extend_from_slice(&data);
            return Ok(Vec::new());
        }

        let sequence = stage.next_sequence;
        stage.next_sequence += 1;
        let event = body_event(sequence, data.clone(), false);
        let result = match exchange(stage, event, deadline).await {
            Ok(result) => result,
            Err(reason) => {
                let reason = self.classify_timeout_reason(reason);
                return self
                    .handle_stage_failure(index, &reason, Some(sequence), data)
                    .await;
            }
        };
        self.apply_body_result(index, result, sequence, data).await
    }

    async fn finish_stage(
        &mut self,
        index: usize,
        deadline: Instant,
    ) -> Result<Vec<Vec<u8>>, HttpResponseMiddlewareFailure> {
        if !self.stages[index].is_body_active() {
            return Ok(Vec::new());
        }
        let deadline = self.exchange_deadline(deadline);
        let mode = self.stages[index].mode;
        let mut output = Vec::new();
        if mode == StageMode::WholeBody {
            let data = std::mem::take(&mut self.stages[index].whole_body);
            let sequence = 1;
            self.stages[index].next_sequence = 2;
            let result = match exchange(
                &mut self.stages[index],
                body_event(sequence, data.clone(), true),
                deadline,
            )
            .await
            {
                Ok(result) => result,
                Err(reason) => {
                    let reason = self.classify_timeout_reason(reason);
                    return self
                        .handle_stage_failure(index, &reason, Some(sequence), data)
                        .await;
                }
            };
            output.extend(
                self.apply_body_result(index, result, sequence, data)
                    .await?,
            );
        }

        if mode == StageMode::Stream {
            let sequence = self.stages[index].next_sequence;
            self.stages[index].next_sequence += 1;
            let result = match exchange(
                &mut self.stages[index],
                body_event(sequence, Vec::new(), true),
                deadline,
            )
            .await
            {
                Ok(result) => result,
                Err(reason) => {
                    let reason = self.classify_timeout_reason(reason);
                    return self
                        .handle_stage_failure(index, &reason, Some(sequence), Vec::new())
                        .await;
                }
            };
            output.extend(
                self.apply_body_result(index, result, sequence, Vec::new())
                    .await?,
            );
        }
        Ok(output)
    }

    async fn apply_body_result(
        &mut self,
        index: usize,
        result: HttpResponseEventResult,
        sequence: u64,
        original: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, HttpResponseMiddlewareFailure> {
        let max_payload_bytes = self.stages[index].entry.max_payload_bytes;
        let decision = match validate_body_result(result, sequence, max_payload_bytes) {
            Ok(decision) => decision,
            Err(reason) => {
                return self
                    .handle_stage_failure(index, reason, Some(sequence), original)
                    .await;
            }
        };
        let input_size = original.len();
        let replacement_size = match &decision.action {
            BodyAction::Transform(replacement)
            | BodyAction::SkipRemaining(CurrentBodyAction::Transform(replacement)) => {
                Some(replacement.len())
            }
            _ => None,
        };
        if let Some(replacement_size) = replacement_size {
            let retained = self.retained_body_bytes - input_size + replacement_size;
            // Reserve room for one more normalized upstream unit. Whole-body
            // barriers bound the input retained between calls to push_body.
            if retained
                > MAX_HTTP_RESPONSE_RETAINED_BODY_BYTES - MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES
            {
                return self
                    .handle_stage_failure(
                        index,
                        "response_body_aggregate_over_capacity",
                        Some(sequence),
                        original,
                    )
                    .await;
            }
            self.retained_body_bytes = retained;
        }
        let stage = &mut self.stages[index];
        collect_diagnostics(
            stage,
            decision.findings,
            decision.metadata,
            &mut self.findings,
            &mut self.metadata,
        );
        let reason_code = (!decision.reason_code.is_empty()).then_some(decision.reason_code);
        match decision.action {
            BodyAction::PassThrough => {
                let output_size = original.len();
                self.invocations.push(body_invocation_with_reason(
                    stage,
                    HttpResponseInvocationOutcome::PassThrough,
                    sequence,
                    input_size,
                    output_size,
                    reason_code,
                ));
                Ok((!original.is_empty())
                    .then_some(original)
                    .into_iter()
                    .collect())
            }
            BodyAction::Transform(replacement) => {
                self.body_transformed = true;
                self.invocations.push(body_invocation_with_reason(
                    stage,
                    HttpResponseInvocationOutcome::Transform,
                    sequence,
                    input_size,
                    replacement.len(),
                    reason_code,
                ));
                Ok((!replacement.is_empty())
                    .then_some(replacement)
                    .into_iter()
                    .collect())
            }
            BodyAction::SkipRemaining(action) => {
                let output = match action {
                    CurrentBodyAction::PassThrough => original,
                    CurrentBodyAction::Transform(replacement) => {
                        self.body_transformed = true;
                        replacement
                    }
                };
                stage.mode = StageMode::HeadersOnly;
                self.invocations.push(body_invocation_with_reason(
                    stage,
                    HttpResponseInvocationOutcome::SkipRemaining,
                    sequence,
                    input_size,
                    output.len(),
                    reason_code,
                ));
                stage.end(MiddlewareSessionEndReason::Normal).await;
                self.release_admission_if_idle();
                Ok((!output.is_empty()).then_some(output).into_iter().collect())
            }
            BodyAction::BlockDelivery => {
                let config_name = stage.entry.entry.name.clone();
                let denial_reason = middleware_denial_reason(&config_name, reason_code.as_deref());
                self.invocations.push(body_invocation_with_reason(
                    stage,
                    HttpResponseInvocationOutcome::BlockDelivery,
                    sequence,
                    input_size,
                    0,
                    reason_code.clone(),
                ));
                self.end_all(MiddlewareSessionEndReason::MiddlewareDenial)
                    .await;
                Err(HttpResponseMiddlewareFailure {
                    reason: denial_reason,
                    denial: Some(super::MiddlewareDenial {
                        config_name,
                        reason_code,
                    }),
                    diagnostics: HttpResponseDiagnostics::default(),
                })
            }
        }
    }

    async fn handle_stage_failure(
        &mut self,
        index: usize,
        reason: &str,
        sequence: Option<u64>,
        original: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, HttpResponseMiddlewareFailure> {
        let stage = &mut self.stages[index];
        let fail_open = stage.entry.on_error() == OnError::FailOpen;
        let outcome = if fail_open {
            HttpResponseInvocationOutcome::FailOpen
        } else {
            HttpResponseInvocationOutcome::FailClosed
        };
        self.invocations.push(HttpResponseInvocation {
            config_name: stage.entry.entry.name.clone(),
            implementation: stage.entry.entry.implementation.clone(),
            outcome,
            sequence,
            input_size: original.len(),
            output_size: None,
            failed: true,
            stage_disabled: true,
            reason_code: None,
            failure_category: Some(response_failure_category(reason).into()),
        });
        stage
            .end(MiddlewareSessionEndReason::MiddlewareFailure)
            .await;
        self.release_admission_if_idle();
        if fail_open {
            if original.is_empty() {
                Ok(Vec::new())
            } else {
                Ok(vec![original])
            }
        } else {
            Err(HttpResponseMiddlewareFailure {
                reason: format!("middleware_failed: {reason}"),
                denial: None,
                diagnostics: HttpResponseDiagnostics::default(),
            })
        }
    }

    async fn end_all(&mut self, reason: MiddlewareSessionEndReason) {
        for stage in &mut self.stages {
            stage.end(reason).await;
        }
    }

    fn release_admission_if_idle(&mut self) {
        if self.stages.iter().all(|stage| !stage.is_active()) {
            self.session_admission.take();
        }
    }

    fn exchange_deadline(&self, chain_deadline: Instant) -> Instant {
        self.whole_body_deadline()
            .map_or(chain_deadline, |deadline| deadline.min(chain_deadline))
    }

    fn classify_timeout_reason(&self, reason: String) -> String {
        if reason == "middleware_timeout"
            && self
                .whole_body_deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
        {
            "whole_body_accumulation_timeout".into()
        } else {
            reason
        }
    }

    async fn process_trailers(
        &mut self,
        mut trailers: Vec<HttpHeader>,
        deadline: Instant,
    ) -> Result<Vec<HttpHeader>, HttpResponseMiddlewareFailure> {
        for index in 0..self.stages.len() {
            if !self.stages[index].is_body_active() {
                continue;
            }
            let event = HttpResponseEvent {
                event: Some(http_response_event::Event::Trailers(HttpResponseTrailers {
                    headers: trailers.clone(),
                })),
            };
            let result = match exchange(&mut self.stages[index], event, deadline).await {
                Ok(result) => result,
                Err(reason) => {
                    trailers = self
                        .handle_trailer_failure(index, &reason, trailers)
                        .await?;
                    continue;
                }
            };
            let decision = match validate_trailers_result(
                result,
                &trailers,
                &self.stages[index].entry,
                &self.connection_nominated_headers,
            ) {
                Ok(decision) => decision,
                Err(reason) => {
                    trailers = self
                        .handle_trailer_failure(index, &reason, trailers)
                        .await?;
                    continue;
                }
            };
            let input_size = encoded_header_bytes(&trailers);
            trailers = decision.headers;
            let output_size = encoded_header_bytes(&trailers);
            let reason_code = (!decision.reason_code.is_empty()).then_some(decision.reason_code);
            let stage = &mut self.stages[index];
            collect_diagnostics(
                stage,
                decision.findings,
                decision.metadata,
                &mut self.findings,
                &mut self.metadata,
            );
            self.invocations.push(HttpResponseInvocation {
                config_name: stage.entry.entry.name.clone(),
                implementation: stage.entry.entry.implementation.clone(),
                outcome: HttpResponseInvocationOutcome::Trailers,
                sequence: None,
                input_size,
                output_size: Some(output_size),
                failed: false,
                stage_disabled: false,
                reason_code,
                failure_category: None,
            });
        }
        Ok(trailers)
    }

    async fn handle_trailer_failure(
        &mut self,
        index: usize,
        reason: &str,
        original: Vec<HttpHeader>,
    ) -> Result<Vec<HttpHeader>, HttpResponseMiddlewareFailure> {
        let stage = &mut self.stages[index];
        let fail_open = stage.entry.on_error() == OnError::FailOpen;
        self.invocations.push(HttpResponseInvocation {
            config_name: stage.entry.entry.name.clone(),
            implementation: stage.entry.entry.implementation.clone(),
            outcome: if fail_open {
                HttpResponseInvocationOutcome::FailOpen
            } else {
                HttpResponseInvocationOutcome::FailClosed
            },
            sequence: None,
            input_size: encoded_header_bytes(&original),
            output_size: None,
            failed: true,
            stage_disabled: true,
            reason_code: None,
            failure_category: Some(response_failure_category(reason).into()),
        });
        stage
            .end(MiddlewareSessionEndReason::MiddlewareFailure)
            .await;
        self.release_admission_if_idle();
        if fail_open {
            Ok(original)
        } else {
            Err(HttpResponseMiddlewareFailure {
                reason: format!("middleware_failed: {reason}"),
                denial: None,
                diagnostics: HttpResponseDiagnostics::default(),
            })
        }
    }
}

async fn exchange(
    stage: &mut HttpResponseStage,
    event: HttpResponseEvent,
    chain_deadline: Instant,
) -> Result<HttpResponseEventResult, String> {
    let remaining = chain_deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err("middleware_chain_timeout".into());
    }
    let timeout = stage.entry.timeout.min(remaining);
    let Some(transport) = stage.transport.as_mut() else {
        return Err("middleware_stream_closed".into());
    };
    match tokio::time::timeout(timeout, async {
        transport
            .sender
            .send(event)
            .await
            .map_err(|_| tonic::Status::unavailable("middleware request stream closed"))?;
        transport
            .responses
            .next()
            .await
            .ok_or_else(|| tonic::Status::unavailable("middleware result stream closed"))?
    })
    .await
    {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(error)) => {
            let policy = stage
                .entry
                .service
                .as_ref()
                .map_or(MiddlewareDiagnosticPolicy::Preserve, |service| {
                    service.diagnostic_policy
                });
            Err(policy.error_reason(&error))
        }
        Err(_) => Err("middleware_timeout".into()),
    }
}

fn body_event(sequence: u64, data: Vec<u8>, end_of_stream: bool) -> HttpResponseEvent {
    HttpResponseEvent {
        event: Some(http_response_event::Event::Body(HttpResponseBodyUnit {
            sequence,
            payload: Some(http_response_body_unit::Payload::Data(data)),
            end_of_stream,
        })),
    }
}

fn session_end_event(reason: MiddlewareSessionEndReason) -> HttpResponseEvent {
    HttpResponseEvent {
        event: Some(http_response_event::Event::SessionEnd(
            MiddlewareSessionEnd {
                reason: reason as i32,
                protocol_error: None,
            },
        )),
    }
}

fn body_invocation_with_reason(
    stage: &HttpResponseStage,
    outcome: HttpResponseInvocationOutcome,
    sequence: u64,
    input_size: usize,
    output_size: usize,
    reason_code: Option<String>,
) -> HttpResponseInvocation {
    HttpResponseInvocation {
        config_name: stage.entry.entry.name.clone(),
        implementation: stage.entry.entry.implementation.clone(),
        outcome,
        sequence: Some(sequence),
        input_size,
        output_size: Some(output_size),
        failed: false,
        stage_disabled: false,
        reason_code,
        failure_category: None,
    }
}

fn collect_diagnostics(
    stage: &HttpResponseStage,
    mut findings: Vec<Finding>,
    mut metadata: std::collections::HashMap<String, String>,
    all_findings: &mut Vec<NamespacedFinding>,
    all_metadata: &mut BTreeMap<String, BTreeMap<String, String>>,
) {
    if stage
        .entry
        .service
        .as_ref()
        .is_some_and(|service| service.diagnostic_policy == MiddlewareDiagnosticPolicy::Normalize)
    {
        metadata.clear();
        for finding in &mut findings {
            finding.r#type = format!("{}.finding", stage.entry.entry.implementation);
            finding.label = super::EXTERNAL_FINDING_LABEL.to_string();
            finding.confidence.clear();
            finding.severity = "medium".into();
        }
    }
    all_findings.extend(findings.into_iter().map(|finding| NamespacedFinding {
        middleware: stage.entry.entry.name.clone(),
        finding,
    }));
    if !metadata.is_empty() {
        all_metadata.insert(
            stage.entry.entry.name.clone(),
            metadata.into_iter().collect(),
        );
    }
}

fn collect_preflight_diagnostics(
    entry: &DescribedChainEntry,
    findings: Vec<Finding>,
    metadata: std::collections::HashMap<String, String>,
    all_findings: &mut Vec<NamespacedFinding>,
    all_metadata: &mut BTreeMap<String, BTreeMap<String, String>>,
) {
    let stage = HttpResponseStage {
        entry: entry.clone(),
        transport: None,
        mode: StageMode::HeadersOnly,
        next_sequence: 1,
        whole_body: Vec::new(),
    };
    collect_diagnostics(&stage, findings, metadata, all_findings, all_metadata);
}

fn collect_preflight_failure(
    entry: &DescribedChainEntry,
    reason: &str,
    invocations: &mut Vec<HttpResponseInvocation>,
) -> Option<String> {
    let fail_closed = entry.on_error() == OnError::FailClosed;
    invocations.push(HttpResponseInvocation {
        config_name: entry.entry.name.clone(),
        implementation: entry.entry.implementation.clone(),
        outcome: if fail_closed {
            HttpResponseInvocationOutcome::FailClosed
        } else {
            HttpResponseInvocationOutcome::FailOpen
        },
        sequence: None,
        input_size: 0,
        output_size: None,
        failed: true,
        stage_disabled: true,
        reason_code: None,
        failure_category: Some(response_failure_category(reason).into()),
    });
    fail_closed.then(|| format!("middleware_failed: {reason}"))
}

fn response_failure_category(reason: &str) -> &'static str {
    if reason == "middleware_session_capacity_exhausted" {
        "session_capacity"
    } else if reason.contains("over_capacity") {
        "payload_capacity"
    } else if reason.contains("timeout") {
        "timeout"
    } else if reason.contains("stream_closed")
        || reason.contains("stream closed")
        || reason.contains("transport")
        || reason.contains("unavailable")
    {
        "transport"
    } else if matches!(
        reason,
        "bodyless_response"
            | "response_input_unrepresentable"
            | "partial_response"
            | "content_coding_not_identity"
            | "cache_control_no_transform"
    ) {
        "response_not_inspectable"
    } else {
        "invalid_result"
    }
}

fn empty_preflight_outcome(headers: Vec<HttpHeader>) -> HttpResponsePreflightOutcome {
    HttpResponsePreflightOutcome {
        allowed: true,
        reason: String::new(),
        denial: None,
        headers,
        session: None,
        findings: Vec::new(),
        metadata: BTreeMap::new(),
        invocations: Vec::new(),
        session_capacity_exhausted: false,
    }
}

fn failed_preflight_outcome(
    headers: Vec<HttpHeader>,
    reason: String,
    findings: Vec<NamespacedFinding>,
    metadata: BTreeMap<String, BTreeMap<String, String>>,
    invocations: Vec<HttpResponseInvocation>,
) -> HttpResponsePreflightOutcome {
    HttpResponsePreflightOutcome {
        allowed: false,
        reason,
        denial: None,
        headers,
        session: None,
        findings,
        metadata,
        invocations,
        session_capacity_exhausted: false,
    }
}

fn blocked_preflight_outcome(
    headers: Vec<HttpHeader>,
    denial: super::MiddlewareDenial,
    findings: Vec<NamespacedFinding>,
    metadata: BTreeMap<String, BTreeMap<String, String>>,
    invocations: Vec<HttpResponseInvocation>,
) -> HttpResponsePreflightOutcome {
    HttpResponsePreflightOutcome {
        allowed: false,
        reason: middleware_denial_reason(&denial.config_name, denial.reason_code.as_deref()),
        denial: Some(denial),
        headers,
        session: None,
        findings,
        metadata,
        invocations,
        session_capacity_exhausted: false,
    }
}

fn response_preflight_input_failure(
    entries: &[DescribedChainEntry],
    headers: Vec<HttpHeader>,
    reason: &str,
) -> HttpResponsePreflightOutcome {
    let mut outcome = empty_preflight_outcome(headers);
    for entry in entries {
        if let Some(reason) = collect_preflight_failure(entry, reason, &mut outcome.invocations) {
            outcome.allowed = false;
            outcome.reason = reason;
            break;
        }
    }
    outcome
}

fn response_session_capacity_exhausted(
    entries: Vec<DescribedChainEntry>,
    headers: Vec<HttpHeader>,
) -> HttpResponsePreflightOutcome {
    let mut invocations = Vec::new();
    let fail_closed = entries.iter().any(|entry| {
        collect_preflight_failure(
            entry,
            "middleware_session_capacity_exhausted",
            &mut invocations,
        )
        .is_some()
    });
    HttpResponsePreflightOutcome {
        allowed: !fail_closed,
        reason: if fail_closed {
            "middleware_failed: middleware_session_capacity_exhausted".into()
        } else {
            String::new()
        },
        denial: None,
        headers,
        session: None,
        findings: Vec::new(),
        metadata: BTreeMap::new(),
        invocations,
        session_capacity_exhausted: true,
    }
}

async fn end_stages(stages: &mut [HttpResponseStage], reason: MiddlewareSessionEndReason) {
    for stage in stages {
        stage.end(reason).await;
    }
}

async fn handle_opened_preflight_failure(
    entry: &DescribedChainEntry,
    current_stage: &mut HttpResponseStage,
    prior_stages: &mut [HttpResponseStage],
    reason: &str,
    invocations: &mut Vec<HttpResponseInvocation>,
) -> Option<String> {
    current_stage
        .end(MiddlewareSessionEndReason::MiddlewareFailure)
        .await;
    let failure = collect_preflight_failure(entry, reason, invocations);
    if failure.is_some() {
        end_stages(prior_stages, MiddlewareSessionEndReason::MiddlewareFailure).await;
    }
    failure
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use openshell_core::middleware::{HttpRequestView, InProcessMiddleware};
    use openshell_core::proto::{
        Decision, ExistingHeaderAction, HeaderMutation, HttpRequestResult, HttpResponseBodyResult,
        HttpResponseBodyTransform, HttpResponsePreflightInspect, HttpResponsePreflightResult,
        HttpResponsePreflightSkip, HttpResponseTrailersResult, MiddlewareBinding,
        MiddlewareManifest, WriteHeader, header_mutation, http_response_preflight_result,
    };
    use tokio_stream::wrappers::ReceiverStream;
    use tokio_stream::wrappers::TcpListenerStream;

    use super::*;

    #[derive(Clone, Copy)]
    enum Script {
        HeadersOnly,
        Stream,
        WholeBody,
        InvalidSequence,
        Configured,
        HangBody,
        LargeStream,
        Expansion,
        DeleteBody,
        SkipBody,
        Skip,
        InvalidSkipReason,
        TrailerMutation,
        InvalidTrailerMutation,
    }

    struct ResponseService {
        script: Script,
    }

    struct PreflightLifecycleService {
        completion_tx: mpsc::UnboundedSender<(String, Vec<MiddlewareSessionEndReason>)>,
    }

    #[derive(Clone)]
    struct RemoteResponseService {
        session_end_tx: Option<mpsc::UnboundedSender<MiddlewareSessionEndReason>>,
    }

    #[tonic::async_trait]
    impl openshell_core::proto::middleware::v1::supervisor_middleware_server::SupervisorMiddleware
        for RemoteResponseService
    {
        type EvaluateWebSocketSessionStream = super::super::WebSocketResponseStream;

        async fn describe(
            &self,
            _request: tonic::Request<()>,
        ) -> Result<tonic::Response<MiddlewareManifest>, tonic::Status> {
            Ok(tonic::Response::new(response_manifest(
                "test/remote-response",
            )))
        }

        async fn validate_config(
            &self,
            _request: tonic::Request<openshell_core::proto::ValidateConfigRequest>,
        ) -> Result<tonic::Response<openshell_core::proto::ValidateConfigResponse>, tonic::Status>
        {
            Ok(tonic::Response::new(
                openshell_core::proto::ValidateConfigResponse {
                    valid: true,
                    reason: String::new(),
                },
            ))
        }

        async fn evaluate_http_request(
            &self,
            _request: tonic::Request<openshell_core::proto::HttpRequestEvaluation>,
        ) -> Result<tonic::Response<HttpRequestResult>, tonic::Status> {
            Ok(tonic::Response::new(HttpRequestResult {
                decision: Decision::Allow as i32,
                ..Default::default()
            }))
        }

        async fn evaluate_web_socket_session(
            &self,
            _request: tonic::Request<
                tonic::Streaming<openshell_core::proto::WebSocketSessionEvent>,
            >,
        ) -> Result<tonic::Response<Self::EvaluateWebSocketSessionStream>, tonic::Status> {
            Err(tonic::Status::unimplemented("HTTP response-only service"))
        }
    }

    #[tonic::async_trait]
    impl openshell_core::proto::middleware::v1::http_response_pre_return_server::HttpResponsePreReturn
        for RemoteResponseService
    {
        type EvaluateStream = super::super::HttpResponseResultStream;

        async fn evaluate(
            &self,
            request: tonic::Request<tonic::Streaming<HttpResponseEvent>>,
        ) -> Result<tonic::Response<Self::EvaluateStream>, tonic::Status> {
            let mut requests = request.into_inner();
            // Exercise servers that inspect the initial request before sending
            // response headers, rather than returning a stream immediately.
            let first = requests.next().await.expect("initial request");
            assert!(matches!(&first, Ok(HttpResponseEvent {
                event: Some(http_response_event::Event::Preflight(_))
            })));
            let mut requests = futures::stream::iter([first]).chain(requests);
            let (sender, receiver) = mpsc::channel(4);
            let session_end_tx = self.session_end_tx.clone();
            tokio::spawn(async move {
                while let Some(Ok(event)) = requests.next().await {
                    match event.event {
                        Some(http_response_event::Event::Preflight(_)) => {
                            let result = HttpResponseEventResult {
                                result: Some(
                                    http_response_event_result::Result::PreflightResult(
                                        HttpResponsePreflightResult {
                                            action: Some(
                                                http_response_preflight_result::Action::Inspect(
                                                    HttpResponsePreflightInspect {
                                                        body_mode:
                                                            HttpResponseBodyMode::HeadersOnly as i32,
                                                        header_mutations: vec![write_header(
                                                            "cache-control",
                                                            "remote",
                                                        )],
                                                    },
                                                ),
                                            ),
                                            ..Default::default()
                                        },
                                    ),
                                ),
                            };
                            if sender.send(Ok(result)).await.is_err() {
                                break;
                            }
                        }
                        Some(http_response_event::Event::SessionEnd(end)) => {
                            if let Some(sender) = &session_end_tx
                                && let Ok(reason) = MiddlewareSessionEndReason::try_from(end.reason)
                            {
                                let _ = sender.send(reason);
                            }
                            break;
                        }
                        None => break,
                        _ => {}
                    }
                }
            });
            Ok(tonic::Response::new(Box::pin(ReceiverStream::new(receiver))))
        }
    }

    #[tonic::async_trait]
    impl InProcessMiddleware for ResponseService {
        async fn describe(&self) -> MiddlewareManifest {
            MiddlewareManifest {
                name: "test/response".into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: openshell_core::proto::SupervisorMiddlewareOperation::HttpResponse
                        as i32,
                    phase: openshell_core::proto::SupervisorMiddlewarePhase::PreReturn as i32,
                    max_payload_bytes: if matches!(
                        self.script,
                        Script::LargeStream | Script::Expansion
                    ) {
                        128 * 1024
                    } else {
                        4096
                    },
                    timeout: if matches!(self.script, Script::HangBody) {
                        "10ms".into()
                    } else {
                        String::new()
                    },
                }],
                expected_audience: String::new(),
            }
        }

        async fn validate_config(
            &self,
            _middleware_name: &str,
            _config: &prost_types::Struct,
        ) -> miette::Result<()> {
            Ok(())
        }

        async fn evaluate_http_request(
            &self,
            _request: HttpRequestView<'_>,
        ) -> miette::Result<HttpRequestResult> {
            Ok(HttpRequestResult {
                decision: Decision::Allow as i32,
                ..Default::default()
            })
        }

        async fn open_http_response_pre_return(
            &self,
            mut requests: mpsc::Receiver<HttpResponseEvent>,
        ) -> Result<super::super::HttpResponseResultStream, tonic::Status> {
            let (sender, receiver) = mpsc::channel(4);
            let script = self.script;
            tokio::spawn(async move {
                let mut selected_script = script;
                while let Some(event) = requests.recv().await {
                    let Some(event) = event.event else {
                        break;
                    };
                    let result = match event {
                        http_response_event::Event::Preflight(preflight) => {
                            if matches!(script, Script::Configured) {
                                selected_script = match preflight
                                    .config
                                    .as_ref()
                                    .and_then(|config| config.fields.get("mode"))
                                    .and_then(|value| value.kind.as_ref())
                                {
                                    Some(prost_types::value::Kind::StringValue(mode))
                                        if mode == "whole" =>
                                    {
                                        Script::WholeBody
                                    }
                                    Some(prost_types::value::Kind::StringValue(mode))
                                        if mode == "stream" =>
                                    {
                                        Script::Stream
                                    }
                                    _ => Script::HeadersOnly,
                                };
                            }
                            if matches!(selected_script, Script::Skip | Script::InvalidSkipReason) {
                                HttpResponseEventResult {
                                    result: Some(
                                        http_response_event_result::Result::PreflightResult(
                                            HttpResponsePreflightResult {
                                                action: Some(
                                                    http_response_preflight_result::Action::Skip(
                                                        HttpResponsePreflightSkip {},
                                                    ),
                                                ),
                                                reason: if matches!(
                                                    selected_script,
                                                    Script::InvalidSkipReason
                                                ) {
                                                    "x".repeat(MAX_MIDDLEWARE_REASON_BYTES + 1)
                                                } else {
                                                    "not selected".into()
                                                },
                                                reason_code: "path_not_selected".into(),
                                                ..Default::default()
                                            },
                                        ),
                                    ),
                                }
                            } else {
                                let (body_mode, header_mutations) = match selected_script {
                                    Script::HeadersOnly => (
                                        HttpResponseBodyMode::HeadersOnly,
                                        vec![write_header("cache-control", "private")],
                                    ),
                                    Script::Stream
                                    | Script::InvalidSequence
                                    | Script::HangBody
                                    | Script::LargeStream
                                    | Script::Expansion
                                    | Script::DeleteBody
                                    | Script::SkipBody
                                    | Script::TrailerMutation
                                    | Script::InvalidTrailerMutation => {
                                        (HttpResponseBodyMode::StreamBytes, Vec::new())
                                    }
                                    Script::WholeBody => {
                                        (HttpResponseBodyMode::WholeBodyBytes, Vec::new())
                                    }
                                    Script::Configured
                                    | Script::Skip
                                    | Script::InvalidSkipReason => unreachable!(),
                                };
                                HttpResponseEventResult {
                                    result: Some(
                                        http_response_event_result::Result::PreflightResult(
                                            HttpResponsePreflightResult {
                                                action: Some(
                                                    http_response_preflight_result::Action::Inspect(
                                                        HttpResponsePreflightInspect {
                                                            body_mode: body_mode as i32,
                                                            header_mutations,
                                                        },
                                                    ),
                                                ),
                                                ..Default::default()
                                            },
                                        ),
                                    ),
                                }
                            }
                        }
                        http_response_event::Event::Body(body) => {
                            if matches!(selected_script, Script::HangBody) {
                                continue;
                            }
                            let Some(http_response_body_unit::Payload::Data(data)) = body.payload
                            else {
                                break;
                            };
                            let replacement = match selected_script {
                                Script::Expansion => vec![b'x'; 128 * 1024],
                                Script::DeleteBody => Vec::new(),
                                Script::SkipBody => b"replacement".to_vec(),
                                Script::Stream
                                | Script::InvalidSequence
                                | Script::LargeStream
                                | Script::TrailerMutation
                                | Script::InvalidTrailerMutation => data.to_ascii_uppercase(),
                                Script::WholeBody => [b"whole:".as_slice(), &data].concat(),
                                Script::HeadersOnly
                                | Script::Configured
                                | Script::HangBody
                                | Script::Skip
                                | Script::InvalidSkipReason => break,
                            };
                            let transform = HttpResponseBodyTransform {
                                replacement: Some(http_response_body_transform::Replacement::Data(
                                    replacement,
                                )),
                            };
                            let action = if matches!(selected_script, Script::SkipBody) {
                                http_response_body_result::Action::SkipRemaining(
                                    openshell_core::proto::HttpResponseBodySkipRemaining {
                                        current: Some(
                                            http_response_body_skip_remaining::Current::Transform(
                                                transform,
                                            ),
                                        ),
                                    },
                                )
                            } else {
                                http_response_body_result::Action::Transform(transform)
                            };
                            HttpResponseEventResult {
                                result: Some(http_response_event_result::Result::BodyResult(
                                    HttpResponseBodyResult {
                                        sequence: if matches!(
                                            selected_script,
                                            Script::InvalidSequence
                                        ) {
                                            body.sequence + 1
                                        } else {
                                            body.sequence
                                        },
                                        action: Some(action),
                                        ..Default::default()
                                    },
                                )),
                            }
                        }
                        http_response_event::Event::Trailers(_) => HttpResponseEventResult {
                            result: Some(http_response_event_result::Result::TrailersResult(
                                HttpResponseTrailersResult {
                                    trailer_mutations: match selected_script {
                                        Script::TrailerMutation => {
                                            vec![write_header("x-upstream", "changed")]
                                        }
                                        Script::InvalidTrailerMutation => vec![
                                            write_header("x-upstream", "changed"),
                                            write_header("x-new", "not-allowed"),
                                        ],
                                        _ => Vec::new(),
                                    },
                                    ..Default::default()
                                },
                            )),
                        },
                        http_response_event::Event::SessionEnd(_) => break,
                    };
                    if sender.send(Ok(result)).await.is_err() {
                        break;
                    }
                }
            });
            Ok(Box::pin(ReceiverStream::new(receiver)))
        }
    }

    #[tonic::async_trait]
    impl InProcessMiddleware for PreflightLifecycleService {
        async fn describe(&self) -> MiddlewareManifest {
            response_manifest("test/preflight-lifecycle")
        }

        async fn validate_config(
            &self,
            _middleware_name: &str,
            _config: &prost_types::Struct,
        ) -> miette::Result<()> {
            Ok(())
        }

        async fn evaluate_http_request(
            &self,
            _request: HttpRequestView<'_>,
        ) -> miette::Result<HttpRequestResult> {
            unreachable!()
        }

        async fn open_http_response_pre_return(
            &self,
            mut requests: mpsc::Receiver<HttpResponseEvent>,
        ) -> Result<super::super::HttpResponseResultStream, tonic::Status> {
            let (sender, receiver) = mpsc::channel(4);
            let completion_tx = self.completion_tx.clone();
            tokio::spawn(async move {
                let Some(HttpResponseEvent {
                    event: Some(http_response_event::Event::Preflight(preflight)),
                }) = requests.recv().await
                else {
                    return;
                };
                let config_value = |name: &str| {
                    preflight
                        .config
                        .as_ref()
                        .and_then(|config| config.fields.get(name))
                        .and_then(|value| value.kind.as_ref())
                        .and_then(|kind| match kind {
                            prost_types::value::Kind::StringValue(value) => Some(value.clone()),
                            _ => None,
                        })
                        .unwrap_or_default()
                };
                let label = config_value("label");
                let behavior = config_value("behavior");
                let inspect = |body_mode, header_mutations| HttpResponsePreflightResult {
                    action: Some(http_response_preflight_result::Action::Inspect(
                        HttpResponsePreflightInspect {
                            body_mode,
                            header_mutations,
                        },
                    )),
                    ..Default::default()
                };
                let result = match behavior.as_str() {
                    "stream" => http_response_event_result::Result::PreflightResult(inspect(
                        HttpResponseBodyMode::StreamBytes as i32,
                        Vec::new(),
                    )),
                    "wrong-envelope" => http_response_event_result::Result::BodyResult(
                        HttpResponseBodyResult::default(),
                    ),
                    "invalid-diagnostics" => {
                        let mut result =
                            inspect(HttpResponseBodyMode::HeadersOnly as i32, Vec::new());
                        result.reason = "x".repeat(MAX_MIDDLEWARE_REASON_BYTES + 1);
                        http_response_event_result::Result::PreflightResult(result)
                    }
                    "unsupported-body-mode" => http_response_event_result::Result::PreflightResult(
                        inspect(i32::MAX, Vec::new()),
                    ),
                    "invalid-header-mutation" => {
                        http_response_event_result::Result::PreflightResult(inspect(
                            HttpResponseBodyMode::HeadersOnly as i32,
                            vec![write_header("content-length", "1")],
                        ))
                    }
                    "no-action" => http_response_event_result::Result::PreflightResult(
                        HttpResponsePreflightResult::default(),
                    ),
                    behavior => panic!("unknown lifecycle test behavior: {behavior}"),
                };
                if sender
                    .send(Ok(HttpResponseEventResult {
                        result: Some(result),
                    }))
                    .await
                    .is_err()
                {
                    return;
                }

                let mut terminal_reasons = Vec::new();
                while let Some(event) = requests.recv().await {
                    if let Some(http_response_event::Event::SessionEnd(end)) = event.event
                        && let Ok(reason) = MiddlewareSessionEndReason::try_from(end.reason)
                    {
                        terminal_reasons.push(reason);
                    }
                }
                let _ = completion_tx.send((label, terminal_reasons));
            });
            Ok(Box::pin(ReceiverStream::new(receiver)))
        }
    }

    fn write_header(name: &str, value: &str) -> HeaderMutation {
        HeaderMutation {
            operation: Some(header_mutation::Operation::Write(WriteHeader {
                name: name.into(),
                value: value.into(),
                on_existing: ExistingHeaderAction::Overwrite as i32,
            })),
        }
    }

    fn response_manifest(name: &str) -> MiddlewareManifest {
        MiddlewareManifest {
            name: name.into(),
            service_version: "test".into(),
            bindings: vec![MiddlewareBinding {
                operation: openshell_core::proto::SupervisorMiddlewareOperation::HttpResponse
                    as i32,
                phase: openshell_core::proto::SupervisorMiddlewarePhase::PreReturn as i32,
                max_payload_bytes: 4096,
                timeout: String::new(),
            }],
            expected_audience: String::new(),
        }
    }

    fn entry(on_error: OnError) -> ChainEntry {
        ChainEntry {
            name: "response".into(),
            implementation: "test/response".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error,
        }
    }

    fn configured_entry(name: &str, order: i32, mode: &str) -> ChainEntry {
        ChainEntry {
            name: name.into(),
            implementation: "test/response".into(),
            order,
            config: prost_types::Struct {
                fields: [(
                    "mode".into(),
                    prost_types::Value {
                        kind: Some(prost_types::value::Kind::StringValue(mode.into())),
                    },
                )]
                .into(),
            },
            on_error: OnError::FailClosed,
        }
    }

    fn lifecycle_entry(name: &str, order: i32, behavior: &str, on_error: OnError) -> ChainEntry {
        let string_value = |value: &str| prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue(value.into())),
        };
        ChainEntry {
            name: name.into(),
            implementation: "test/preflight-lifecycle".into(),
            order,
            config: prost_types::Struct {
                fields: [
                    ("label".into(), string_value(name)),
                    ("behavior".into(), string_value(behavior)),
                ]
                .into(),
            },
            on_error,
        }
    }

    fn input(status_code: u16) -> HttpResponsePreflightInput {
        HttpResponsePreflightInput {
            context: RequestContext {
                request_id: "req-1".into(),
                sandbox_id: "sandbox-1".into(),
                ..Default::default()
            },
            target: HttpRequestTarget {
                scheme: "https".into(),
                host: "example.com".into(),
                port: 443,
                method: "GET".into(),
                path: "/data".into(),
                query: String::new(),
            },
            status_code,
            declared_body_length: None,
            headers: vec![HttpHeader {
                name: "content-type".into(),
                value: "text/plain".into(),
            }],
            connection_nominated_headers: Vec::new(),
        }
    }

    #[tokio::test]
    async fn response_preflight_envelope_limits_obey_selected_stage_policies() {
        let runner = ChainRunner::new(Arc::new(ResponseService {
            script: Script::HeadersOnly,
        }));
        for limit in 0..4 {
            let mut input = input(200);
            match limit {
                0 => input.context.request_id = "x".repeat(MAX_MIDDLEWARE_CONTEXT_BYTES + 1),
                1 => input.target.path = "x".repeat(MAX_MIDDLEWARE_TARGET_BYTES + 1),
                2 => input.headers = vec![input.headers[0].clone(); MAX_MIDDLEWARE_HEADERS + 1],
                _ => input.headers[0].value = "x".repeat(MAX_MIDDLEWARE_HEADER_BYTES + 1),
            }
            for last_policy in [OnError::FailOpen, OnError::FailClosed] {
                let entries = [entry(OnError::FailOpen), entry(last_policy)];
                let outcome = runner
                    .preflight_http_response(&entries, input.clone())
                    .await
                    .unwrap();
                assert_eq!(outcome.allowed, last_policy == OnError::FailOpen);
                assert_eq!(outcome.headers, input.headers);
                assert!(outcome.session.is_none());
                assert_eq!(outcome.invocations.len(), 2);
                assert!(
                    outcome
                        .invocations
                        .iter()
                        .all(|invocation| invocation.failed && invocation.stage_disabled)
                );
                assert_eq!(
                    outcome.invocations[1].failure_category.as_deref(),
                    Some("payload_capacity")
                );
            }
        }
        let described = runner
            .describe_http_response_chain(&[entry(OnError::FailOpen), entry(OnError::FailClosed)])
            .await
            .unwrap();
        let outcome = runner.http_response_input_unrepresentable(&described);
        assert!(!outcome.allowed);
        assert_eq!(outcome.invocations.len(), 2);
        assert!(outcome.invocations.iter().all(|invocation| {
            invocation.failure_category.as_deref() == Some("response_not_inspectable")
        }));
    }

    #[tokio::test]
    async fn invalid_opened_preflight_stages_receive_one_failure_terminal_event() {
        for behavior in [
            "wrong-envelope",
            "invalid-diagnostics",
            "unsupported-body-mode",
            "invalid-header-mutation",
            "no-action",
        ] {
            for on_error in [OnError::FailOpen, OnError::FailClosed] {
                let (completion_tx, mut completion_rx) = mpsc::unbounded_channel();
                let runner =
                    ChainRunner::new(Arc::new(PreflightLifecycleService { completion_tx }));
                let entries = [
                    lifecycle_entry("prior", 0, "stream", OnError::FailClosed),
                    lifecycle_entry("invalid", 1, behavior, on_error),
                ];
                let mut outcome = runner
                    .preflight_http_response(&entries, input(200))
                    .await
                    .expect("invalid preflight response");
                assert_eq!(outcome.allowed, on_error == OnError::FailOpen);
                if let Some(session) = outcome.session.take() {
                    session.end(MiddlewareSessionEndReason::Normal).await;
                }

                let mut completions = BTreeMap::new();
                for _ in 0..2 {
                    let (label, reasons) =
                        tokio::time::timeout(Duration::from_secs(1), completion_rx.recv())
                            .await
                            .expect("bounded terminal event delivery")
                            .expect("opened stage completion");
                    assert!(completions.insert(label, reasons).is_none());
                }
                assert_eq!(
                    completions.get("invalid").map(Vec::as_slice),
                    Some([MiddlewareSessionEndReason::MiddlewareFailure].as_slice()),
                    "invalid behavior: {behavior}, policy: {on_error:?}"
                );
                let prior_reason = if on_error == OnError::FailOpen {
                    MiddlewareSessionEndReason::Normal
                } else {
                    MiddlewareSessionEndReason::MiddlewareFailure
                };
                assert_eq!(
                    completions.get("prior").map(Vec::as_slice),
                    Some([prior_reason].as_slice()),
                    "invalid behavior: {behavior}, policy: {on_error:?}"
                );
                assert!(completion_rx.try_recv().is_err());
            }
        }
    }

    #[test]
    fn stream_mode_requires_only_one_byte_of_payload_capacity() {
        let mut described = DescribedChainEntry {
            entry: entry(OnError::FailClosed),
            service: None,
            binding: None,
            max_payload_bytes: 1,
            timeout: Duration::from_millis(500),
        };

        let modes = permitted_body_modes(&input(200), &described, None);
        assert!(modes.contains(&(HttpResponseBodyMode::StreamBytes as i32)));

        described.max_payload_bytes = 0;
        let modes = permitted_body_modes(&input(200), &described, None);
        assert!(!modes.contains(&(HttpResponseBodyMode::StreamBytes as i32)));
    }

    struct ReadPreflightBeforeOpening {
        failure: Option<bool>,
    }

    #[tonic::async_trait]
    impl InProcessMiddleware for ReadPreflightBeforeOpening {
        async fn describe(&self) -> MiddlewareManifest {
            let mut manifest = response_manifest("test/response");
            manifest.bindings[0].timeout = "10ms".into();
            manifest
        }

        async fn validate_config(&self, _: &str, _: &prost_types::Struct) -> miette::Result<()> {
            Ok(())
        }

        async fn evaluate_http_request(
            &self,
            _: HttpRequestView<'_>,
        ) -> miette::Result<HttpRequestResult> {
            unreachable!()
        }

        async fn open_http_response_pre_return(
            &self,
            mut requests: mpsc::Receiver<HttpResponseEvent>,
        ) -> Result<super::super::HttpResponseResultStream, tonic::Status> {
            let first = requests.recv().await.expect("initial preflight");
            assert!(matches!(
                first.event,
                Some(http_response_event::Event::Preflight(_))
            ));
            if let Some(hang) = self.failure {
                if hang {
                    futures::future::pending::<()>().await;
                }
                return Err(tonic::Status::unavailable("startup failed"));
            }
            let response = HttpResponseEventResult {
                result: Some(http_response_event_result::Result::PreflightResult(
                    HttpResponsePreflightResult {
                        action: Some(http_response_preflight_result::Action::Inspect(
                            HttpResponsePreflightInspect {
                                body_mode: HttpResponseBodyMode::HeadersOnly as i32,
                                header_mutations: Vec::new(),
                            },
                        )),
                        ..Default::default()
                    },
                )),
            };
            Ok(Box::pin(futures::stream::iter([Ok(response)])))
        }
    }

    #[tokio::test]
    async fn preflight_can_be_read_before_open_returns() {
        let runner = ChainRunner::new(Arc::new(ReadPreflightBeforeOpening { failure: None }));
        let outcome = tokio::time::timeout(
            Duration::from_secs(1),
            runner.preflight_http_response(&[entry(OnError::FailClosed)], input(200)),
        )
        .await
        .expect("bounded startup")
        .expect("preflight");
        assert!(outcome.allowed, "{}", outcome.reason);
    }

    #[tokio::test]
    async fn preflight_opening_failure_obeys_policy_and_releases_admission() {
        for hang in [false, true] {
            for on_error in [OnError::FailOpen, OnError::FailClosed] {
                let runner = ChainRunner::new(Arc::new(ReadPreflightBeforeOpening {
                    failure: Some(hang),
                }));
                let permits = runner.registry.session_admission.available_permits();
                let outcome = tokio::time::timeout(
                    Duration::from_secs(1),
                    runner.preflight_http_response(&[entry(on_error)], input(200)),
                )
                .await
                .expect("bounded opening failure")
                .unwrap();
                assert_eq!(outcome.allowed, on_error == OnError::FailOpen);
                assert!(outcome.session.is_none());
                assert_eq!(
                    runner.registry.session_admission.available_permits(),
                    permits
                );
                assert!(outcome.invocations[0].failed);
            }
        }
    }

    #[tokio::test]
    async fn multiple_whole_body_barriers_preserve_accounting_on_overflow_and_expiry() {
        for expire in [false, true] {
            let runner = ChainRunner::new(Arc::new(ResponseService {
                script: Script::Configured,
            }));
            let mut entries = vec![
                configured_entry("first", 0, "whole"),
                configured_entry("second", 1, "whole"),
                configured_entry("stream", 2, "stream"),
            ];
            for entry in &mut entries {
                entry.on_error = OnError::FailOpen;
            }
            let mut outcome = runner
                .preflight_http_response(&entries, input(200))
                .await
                .unwrap();
            let mut session = outcome.session.take().unwrap();
            for _ in 0..2 {
                assert!(
                    session
                        .push_body(vec![b'a'; 2048])
                        .await
                        .unwrap()
                        .is_empty()
                );
                assert!(session.retained_body_bytes <= 4096);
                assert_eq!(
                    session
                        .stages
                        .iter()
                        .filter(|stage| !stage.whole_body.is_empty())
                        .count(),
                    1
                );
            }
            let output = if expire {
                session.start_whole_body_deadline(Duration::ZERO);
                session.expire_whole_body_deadline().await.unwrap()
            } else {
                session.push_body(vec![b'a'; 2048]).await.unwrap()
            };
            assert_eq!(
                output.concat(),
                vec![b'A'; if expire { 4096 } else { 6144 }]
            );
            assert_eq!(session.retained_body_bytes, 0);
            assert_eq!(
                session.push_body(b"next".to_vec()).await.unwrap().concat(),
                b"NEXT"
            );
            assert_eq!(session.retained_body_bytes, 0);
            assert!(
                session
                    .finish(Vec::new())
                    .await
                    .unwrap()
                    .body_units
                    .is_empty()
            );
        }
    }

    #[tokio::test]
    async fn deleted_and_skip_remaining_units_release_body_accounting() {
        for script in [Script::DeleteBody, Script::SkipBody] {
            let runner = ChainRunner::new(Arc::new(ResponseService { script }));
            let mut outcome = runner
                .preflight_http_response(&[entry(OnError::FailClosed)], input(200))
                .await
                .unwrap();
            let mut session = outcome.session.take().unwrap();
            for index in 0..3 {
                let output = session.push_body(b"original".to_vec()).await.unwrap();
                let expected = match script {
                    Script::DeleteBody => Vec::new(),
                    Script::SkipBody if index == 0 => b"replacement".to_vec(),
                    Script::SkipBody => b"original".to_vec(),
                    _ => unreachable!(),
                };
                assert_eq!(output.concat(), expected);
                assert_eq!(session.retained_body_bytes, 0);
            }
            assert!(
                session
                    .finish(Vec::new())
                    .await
                    .unwrap()
                    .body_units
                    .is_empty()
            );
        }
    }

    #[tokio::test]
    async fn expanding_stages_obey_aggregate_budget_and_failure_policy() {
        for on_error in [OnError::FailClosed, OnError::FailOpen] {
            let runner = ChainRunner::new(Arc::new(ResponseService {
                script: Script::Expansion,
            }));
            let permits = runner.registry.session_admission.available_permits();
            let entries = (0..9)
                .map(|order| {
                    let mut entry = entry(on_error);
                    entry.name = format!("expand-{order}");
                    entry.order = order;
                    entry
                })
                .collect::<Vec<_>>();
            let mut outcome = runner
                .preflight_http_response(&entries, input(200))
                .await
                .unwrap();
            let mut session = outcome.session.take().unwrap();
            let result = tokio::time::timeout(Duration::from_secs(5), session.push_body(vec![1]))
                .await
                .expect("bounded expansion");
            match result {
                Ok(output) => {
                    assert_eq!(on_error, OnError::FailOpen);
                    assert!(
                        output.iter().map(Vec::len).sum::<usize>()
                            < MAX_HTTP_RESPONSE_RETAINED_BODY_BYTES
                    );
                    assert!(output.iter().flatten().all(|byte| *byte == b'x'));
                    assert_eq!(session.retained_body_bytes, 0);
                    assert!(
                        session
                            .invocations
                            .iter()
                            .any(|invocation| invocation.outcome
                                == HttpResponseInvocationOutcome::FailOpen)
                    );
                    // Holding returned output applies backpressure: subsequent
                    // stage work starts only when the relay calls again.
                    drop(output);
                    for _ in 0..3 {
                        let output = session.push_body(vec![1]).await.unwrap();
                        assert!(
                            output.iter().map(Vec::len).sum::<usize>()
                                < MAX_HTTP_RESPONSE_RETAINED_BODY_BYTES
                        );
                        assert_eq!(session.retained_body_bytes, 0);
                    }
                    let finish = session.finish(Vec::new()).await.unwrap();
                    assert!(
                        finish.body_units.iter().map(Vec::len).sum::<usize>()
                            < MAX_HTTP_RESPONSE_RETAINED_BODY_BYTES
                    );
                }
                Err(failure) => {
                    assert_eq!(on_error, OnError::FailClosed);
                    assert!(
                        failure
                            .reason
                            .contains("response_body_aggregate_over_capacity")
                    );
                    session
                        .end(MiddlewareSessionEndReason::MiddlewareFailure)
                        .await;
                }
            }
            assert_eq!(
                runner.registry.session_admission.available_permits(),
                permits
            );
        }
    }

    #[tokio::test]
    async fn headers_only_preflight_applies_end_to_end_mutation() {
        let runner = ChainRunner::new(Arc::new(ResponseService {
            script: Script::HeadersOnly,
        }));
        let outcome = runner
            .preflight_http_response(&[entry(OnError::FailClosed)], input(200))
            .await
            .expect("response preflight");

        assert!(outcome.allowed);
        assert_eq!(
            outcome
                .headers
                .iter()
                .find(|header| header.name == "cache-control")
                .map(|header| header.value.as_str()),
            Some("private")
        );
        assert!(outcome.session.is_none());
    }

    #[tokio::test]
    async fn stream_mode_transforms_lockstep_units_and_preserves_trailers() {
        let runner = ChainRunner::new(Arc::new(ResponseService {
            script: Script::Stream,
        }));
        let mut outcome = runner
            .preflight_http_response(&[entry(OnError::FailClosed)], input(200))
            .await
            .expect("response preflight");
        let mut session = outcome.session.take().expect("streaming session");

        assert_eq!(
            session
                .push_body(b"hello".to_vec())
                .await
                .expect("transform stream unit"),
            vec![b"HELLO".to_vec()]
        );
        let original_trailers = vec![HttpHeader {
            name: "x-upstream".into(),
            value: "retained".into(),
        }];
        let finish = session
            .finish(original_trailers.clone())
            .await
            .expect("finish stream");
        assert!(finish.body_units.is_empty());
        assert_eq!(finish.trailers, original_trailers);
    }

    #[tokio::test]
    async fn whole_body_mode_releases_replacement_only_at_finish() {
        let runner = ChainRunner::new(Arc::new(ResponseService {
            script: Script::WholeBody,
        }));
        let mut outcome = runner
            .preflight_http_response(&[entry(OnError::FailClosed)], input(200))
            .await
            .expect("response preflight");
        let mut session = outcome.session.take().expect("whole-body session");
        assert!(session.requires_whole_body());
        assert!(
            session
                .push_body(b"one".to_vec())
                .await
                .expect("buffer first unit")
                .is_empty()
        );
        assert!(
            session
                .push_body(b"two".to_vec())
                .await
                .expect("buffer second unit")
                .is_empty()
        );

        let finish = session.finish(Vec::new()).await.expect("finish whole body");
        assert_eq!(finish.body_units, vec![b"whole:onetwo".to_vec()]);
    }

    #[tokio::test]
    async fn mixed_profile_chain_respects_policy_order_and_whole_body_barrier() {
        let runner = ChainRunner::new(Arc::new(ResponseService {
            script: Script::Configured,
        }));
        let entries = vec![
            configured_entry("stream", 20, "stream"),
            configured_entry("whole", 10, "whole"),
        ];
        let mut outcome = runner
            .preflight_http_response(&entries, input(200))
            .await
            .expect("mixed response preflight");
        let mut session = outcome.session.take().expect("mixed response session");
        assert!(session.requires_whole_body());
        assert!(
            session
                .push_body(b"hello".to_vec())
                .await
                .expect("buffer mixed response")
                .is_empty()
        );
        let finish = session
            .finish(Vec::new())
            .await
            .expect("finish mixed chain");
        assert_eq!(finish.body_units, vec![b"WHOLE:HELLO".to_vec()]);
    }

    #[tokio::test]
    async fn whole_body_overflow_obeys_fail_open_and_fail_closed() {
        for (on_error, allowed) in [(OnError::FailOpen, true), (OnError::FailClosed, false)] {
            let runner = ChainRunner::new(Arc::new(ResponseService {
                script: Script::WholeBody,
            }));
            let mut outcome = runner
                .preflight_http_response(&[entry(on_error)], input(200))
                .await
                .expect("whole-body response preflight");
            let mut session = outcome.session.take().expect("whole-body session");
            let original = vec![b'a'; 4097];
            let pushed = session.push_body(original.clone()).await;
            assert_eq!(pushed.is_ok(), allowed);
            if allowed {
                assert_eq!(pushed.unwrap(), vec![original]);
                assert!(!session.requires_whole_body());
                for fill in [b'b', b'c'] {
                    let unit = vec![fill; MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES];
                    assert_eq!(
                        session
                            .push_body(unit.clone())
                            .await
                            .expect("fail-open stage must release later units"),
                        vec![unit]
                    );
                }
                let finish = session.finish(Vec::new()).await.expect("fail-open finish");
                assert!(finish.body_units.is_empty());
            }
        }
    }

    #[tokio::test]
    async fn response_body_timeout_obeys_fail_open_and_fail_closed() {
        for (on_error, allowed) in [(OnError::FailOpen, true), (OnError::FailClosed, false)] {
            let runner = ChainRunner::new(Arc::new(ResponseService {
                script: Script::HangBody,
            }));
            let mut outcome = runner
                .preflight_http_response(&[entry(on_error)], input(200))
                .await
                .expect("timed response preflight");
            let mut session = outcome.session.take().expect("timed response session");
            let result = session.push_body(b"unchanged".to_vec()).await;
            assert_eq!(result.is_ok(), allowed);
            if let Ok(units) = result {
                assert_eq!(units, vec![b"unchanged".to_vec()]);
            }
        }
    }

    #[tokio::test]
    async fn stream_unit_limit_never_exceeds_platform_cap() {
        let runner = ChainRunner::new(Arc::new(ResponseService {
            script: Script::LargeStream,
        }));
        let mut outcome = runner
            .preflight_http_response(&[entry(OnError::FailClosed)], input(200))
            .await
            .expect("large stream preflight");
        let mut session = outcome.session.take().expect("large stream session");
        assert_eq!(
            session.stream_unit_limit(),
            MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES
        );
        let maximum_unit = vec![b'A'; MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES];
        assert_eq!(
            session
                .push_body(maximum_unit.clone())
                .await
                .expect("maximum stream unit"),
            vec![maximum_unit]
        );
        assert_eq!(
            session
                .push_body(vec![b'b'; MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES + 1])
                .await
                .expect_err("oversized stream unit")
                .reason,
            "response_stream_unit_over_capacity"
        );
        session
            .finish(Vec::new())
            .await
            .expect("finish large stream");
    }

    #[tokio::test]
    async fn skip_reason_code_is_retained_and_oversized_reason_obeys_on_error() {
        let runner = ChainRunner::new(Arc::new(ResponseService {
            script: Script::Skip,
        }));
        let outcome = runner
            .preflight_http_response(&[entry(OnError::FailClosed)], input(200))
            .await
            .expect("skip response preflight");
        assert!(outcome.allowed);
        assert!(outcome.session.is_none());
        assert_eq!(
            outcome.invocations[0].reason_code.as_deref(),
            Some("path_not_selected")
        );

        for (on_error, allowed) in [(OnError::FailOpen, true), (OnError::FailClosed, false)] {
            let runner = ChainRunner::new(Arc::new(ResponseService {
                script: Script::InvalidSkipReason,
            }));
            let outcome = runner
                .preflight_http_response(&[entry(on_error)], input(200))
                .await
                .expect("invalid skip response preflight");
            assert_eq!(outcome.allowed, allowed);
            assert!(outcome.session.is_none());
        }
    }

    #[tokio::test]
    async fn response_trailers_are_mutated_by_body_stage() {
        let runner = ChainRunner::new(Arc::new(ResponseService {
            script: Script::TrailerMutation,
        }));
        let mut outcome = runner
            .preflight_http_response(&[entry(OnError::FailClosed)], input(200))
            .await
            .expect("trailer response preflight");
        let mut session = outcome.session.take().expect("trailer response session");
        session
            .push_body(b"body".to_vec())
            .await
            .expect("transform response body");
        let trailers = vec![HttpHeader {
            name: "x-upstream".into(),
            value: "retained".into(),
        }];
        let finish = session
            .finish(trailers.clone())
            .await
            .expect("finish response");
        assert_eq!(
            finish.trailers,
            vec![HttpHeader {
                name: "x-upstream".into(),
                value: "changed".into(),
            }]
        );
    }

    #[tokio::test]
    async fn invalid_trailer_mutations_are_atomic_and_keep_failure_diagnostics() {
        let trailers = vec![HttpHeader {
            name: "x-upstream".into(),
            value: "retained".into(),
        }];
        for on_error in [OnError::FailOpen, OnError::FailClosed] {
            let runner = ChainRunner::new(Arc::new(ResponseService {
                script: Script::InvalidTrailerMutation,
            }));
            let mut outcome = runner
                .preflight_http_response(&[entry(on_error)], input(200))
                .await
                .expect("invalid trailer response preflight");
            let mut session = outcome.session.take().expect("trailer response session");
            session
                .push_body(b"body".to_vec())
                .await
                .expect("response body exchange");
            session.take_diagnostics();

            match session.finish(trailers.clone()).await {
                Ok(finish) => {
                    assert_eq!(on_error, OnError::FailOpen);
                    assert_eq!(finish.trailers, trailers);
                    assert_eq!(
                        finish.invocations.last().map(|entry| entry.outcome),
                        Some(HttpResponseInvocationOutcome::FailOpen)
                    );
                }
                Err(failure) => {
                    assert_eq!(on_error, OnError::FailClosed);
                    assert_eq!(
                        failure
                            .diagnostics
                            .invocations
                            .last()
                            .map(|entry| entry.outcome),
                        Some(HttpResponseInvocationOutcome::FailClosed)
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn invalid_sequence_obeys_fail_open_and_fail_closed() {
        for (on_error, allowed) in [(OnError::FailOpen, true), (OnError::FailClosed, false)] {
            let runner = ChainRunner::new(Arc::new(ResponseService {
                script: Script::InvalidSequence,
            }));
            let mut outcome = runner
                .preflight_http_response(&[entry(on_error)], input(200))
                .await
                .expect("response preflight");
            let mut session = outcome.session.take().expect("stream session");
            let result = session.push_body(b"unchanged".to_vec()).await;
            assert_eq!(result.is_ok(), allowed);
            if let Ok(units) = result {
                assert_eq!(units, vec![b"unchanged".to_vec()]);
            }
        }
    }

    #[tokio::test]
    async fn body_inspection_restrictions_obey_fail_open_and_fail_closed() {
        let mut cases = Vec::new();
        cases.push(input(206));
        for (name, value) in [
            ("content-range", "bytes 0-3/10"),
            ("content-type", "multipart/byteranges; boundary=test"),
            ("cache-control", "private, no-transform"),
            ("content-encoding", "gzip"),
        ] {
            let mut candidate = input(200);
            candidate.headers.push(HttpHeader {
                name: name.into(),
                value: value.into(),
            });
            cases.push(candidate);
        }
        for status in [204, 304] {
            cases.push(input(status));
        }
        let mut head = input(200);
        head.target.method = "HEAD".into();
        cases.push(head);

        for candidate in cases {
            for (on_error, allowed) in [(OnError::FailOpen, true), (OnError::FailClosed, false)] {
                let runner = ChainRunner::new(Arc::new(ResponseService {
                    script: Script::Stream,
                }));
                let outcome = runner
                    .preflight_http_response(&[entry(on_error)], candidate.clone())
                    .await
                    .expect("restricted response preflight");
                assert_eq!(outcome.allowed, allowed);
                assert!(outcome.session.is_none());
            }
        }
    }

    #[tokio::test]
    async fn remote_service_executes_through_http_response_pre_return_rpc() {
        use openshell_core::proto::middleware::v1::http_response_pre_return_server::HttpResponsePreReturnServer;
        use openshell_core::proto::middleware::v1::supervisor_middleware_server::SupervisorMiddlewareServer;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind response middleware");
        let address = listener.local_addr().expect("response middleware address");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let (session_end_tx, mut session_end_rx) = mpsc::unbounded_channel();
        let service = RemoteResponseService {
            session_end_tx: Some(session_end_tx),
        };
        let server = tonic::transport::Server::builder()
            .add_service(SupervisorMiddlewareServer::new(service.clone()))
            .add_service(HttpResponsePreReturnServer::new(service))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            });
        let server_task = tokio::spawn(server);
        let registry = super::super::MiddlewareRegistry::connect_services(
            Vec::new(),
            vec![openshell_core::proto::SupervisorMiddlewareService {
                name: "remote-response".into(),
                grpc_endpoint: format!("http://{address}"),
                max_payload_bytes: 4096,
                allow_insecure_transport: true,
                ..Default::default()
            }],
        )
        .await
        .expect("connect remote response middleware");
        let runner = ChainRunner::from_registry(registry);
        let outcome = runner
            .preflight_http_response(
                &[ChainEntry {
                    name: "response".into(),
                    implementation: "remote-response".into(),
                    order: 0,
                    config: prost_types::Struct::default(),
                    on_error: OnError::FailClosed,
                }],
                input(200),
            )
            .await
            .expect("remote response preflight");

        assert!(outcome.allowed);
        assert_eq!(
            outcome
                .headers
                .iter()
                .find(|header| header.name == "cache-control")
                .map(|header| header.value.as_str()),
            Some("remote")
        );
        assert!(outcome.session.is_none());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), session_end_rx.recv())
                .await
                .expect("bounded session end delivery"),
            Some(MiddlewareSessionEndReason::Normal)
        );
        assert!(session_end_rx.try_recv().is_err());

        let _ = shutdown_tx.send(());
        tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .expect("bounded server shutdown")
            .expect("join response middleware server")
            .expect("serve response middleware");
    }
}
