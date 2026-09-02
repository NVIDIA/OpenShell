// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP response pre-return middleware chain execution.

use std::collections::BTreeMap;
use std::time::Duration;

use futures::StreamExt as _;
use prost::Message as _;
use tokio::sync::mpsc;
use tokio::time::Instant;

use openshell_core::proto::{
    Finding, HttpHeader, HttpRequestTarget, HttpResponseBodyMode, HttpResponseBodyPassThrough,
    HttpResponseBodyUnit, HttpResponseEvent, HttpResponseEventResult, HttpResponsePreflight,
    MiddlewareSessionEnd, MiddlewareSessionEndReason, RequestContext, http_response_body_result,
    http_response_body_skip_remaining, http_response_body_transform, http_response_body_unit,
    http_response_event, http_response_event_result, http_response_preflight_decision,
};

use super::{
    ChainEntry, ChainRunner, DescribedChainEntry, MAX_MIDDLEWARE_CHAIN_TIMEOUT,
    MAX_MIDDLEWARE_CONTEXT_BYTES, MAX_MIDDLEWARE_FINDING_BYTES, MAX_MIDDLEWARE_FINDINGS_PER_STAGE,
    MAX_MIDDLEWARE_HEADER_BYTES, MAX_MIDDLEWARE_HEADER_MUTATION_WIRE_BYTES, MAX_MIDDLEWARE_HEADERS,
    MAX_MIDDLEWARE_METADATA_BYTES, MAX_MIDDLEWARE_METADATA_ENTRIES,
    MAX_MIDDLEWARE_PREFLIGHT_TIMEOUT, MAX_MIDDLEWARE_REASON_BYTES,
    MAX_MIDDLEWARE_REASON_CODE_BYTES, MAX_MIDDLEWARE_TARGET_BYTES, MiddlewareDiagnosticPolicy,
    MiddlewareSessionAdmission, MiddlewareSessionPermit, NamespacedFinding, OnError, headers,
    is_stable_reason_code, middleware_denial_reason,
};

const STREAM_CHANNEL_CAPACITY: usize = 4;
pub const MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES: usize = 64 * 1024;

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
    pub headers: Vec<HttpHeader>,
    pub declared_trailer_names: Vec<String>,
    pub session: Option<HttpResponseSession>,
    pub findings: Vec<NamespacedFinding>,
    pub metadata: BTreeMap<String, BTreeMap<String, String>>,
    pub invocations: Vec<HttpResponseInvocation>,
    pub session_capacity_exhausted: bool,
}

#[derive(Debug)]
pub struct HttpResponseMiddlewareFailure {
    pub reason: String,
}

impl std::fmt::Display for HttpResponseMiddlewareFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl std::error::Error for HttpResponseMiddlewareFailure {}

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

struct HttpResponseStageTransport {
    sender: mpsc::Sender<HttpResponseEvent>,
    responses: super::HttpResponseResultStream,
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
            let _ = tokio::time::timeout(
                Duration::from_millis(10),
                transport.sender.send(session_end_event(reason)),
            )
            .await;
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
    defer_output_until_finish: bool,
    deferred_output: Vec<Vec<u8>>,
}

impl HttpResponseSession {
    #[must_use]
    pub fn requires_whole_body(&self) -> bool {
        self.stages
            .iter()
            .any(|stage| stage.is_active() && stage.mode == StageMode::WholeBody)
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
                    .checked_div(2)
                    .unwrap_or_default()
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
            });
        }
        let _work = self
            .runner
            .reserve_middleware_work_admission()
            .await
            .map_err(|error| HttpResponseMiddlewareFailure {
                reason: format!("middleware_failed: {error}"),
            })?;
        let deadline = Instant::now() + MAX_MIDDLEWARE_CHAIN_TIMEOUT;
        let output = self.process_units_from(0, vec![data], deadline).await?;
        if !self.defer_output_until_finish {
            return Ok(output);
        }
        if self.requires_whole_body() {
            self.deferred_output.extend(output);
            return Ok(Vec::new());
        }

        self.defer_output_until_finish = false;
        let mut released = std::mem::take(&mut self.deferred_output);
        released.extend(output);
        Ok(released)
    }

    /// Finalize every body stage, preserve normalized trailers, and end streams.
    pub async fn finish(
        mut self,
        trailers: Vec<HttpHeader>,
    ) -> Result<HttpResponseFinish, HttpResponseMiddlewareFailure> {
        let _work = self
            .runner
            .reserve_middleware_work_admission()
            .await
            .map_err(|error| HttpResponseMiddlewareFailure {
                reason: format!("middleware_failed: {error}"),
            })?;
        let deadline = Instant::now() + MAX_MIDDLEWARE_CHAIN_TIMEOUT;
        let mut released = std::mem::take(&mut self.deferred_output);
        for index in 0..self.stages.len() {
            let stage_output = match self.finish_stage(index, deadline).await {
                Ok(output) => output,
                Err(failure) => {
                    self.end_all(MiddlewareSessionEndReason::MiddlewareFailure)
                        .await;
                    return Err(failure);
                }
            };
            if !stage_output.is_empty() {
                let output = self
                    .process_units_from(index + 1, stage_output, deadline)
                    .await?;
                released.extend(output);
            }
        }

        let mut trailers = trailers;
        if self.body_transformed {
            strip_stale_integrity(&mut trailers);
        }
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
                Ok((!output.is_empty()).then_some(output).into_iter().collect())
            }
            BodyAction::BlockDelivery => {
                let denial_reason =
                    middleware_denial_reason(&stage.entry.entry.name, reason_code.as_deref());
                self.invocations.push(body_invocation_with_reason(
                    stage,
                    HttpResponseInvocationOutcome::BlockDelivery,
                    sequence,
                    input_size,
                    0,
                    reason_code,
                ));
                self.end_all(MiddlewareSessionEndReason::MiddlewareDenial)
                    .await;
                Err(HttpResponseMiddlewareFailure {
                    reason: denial_reason,
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
        let outcome = if stage.entry.on_error() == OnError::FailOpen {
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
        if stage.entry.on_error() == OnError::FailOpen {
            if original.is_empty() {
                Ok(Vec::new())
            } else {
                Ok(vec![original])
            }
        } else {
            Err(HttpResponseMiddlewareFailure {
                reason: format!("middleware_failed: {reason}"),
            })
        }
    }

    async fn end_all(&mut self, reason: MiddlewareSessionEndReason) {
        for stage in &mut self.stages {
            stage.end(reason).await;
        }
    }
}

impl ChainRunner {
    pub async fn preflight_http_response(
        &self,
        entries: &[ChainEntry],
        input: HttpResponsePreflightInput,
    ) -> miette::Result<HttpResponsePreflightOutcome> {
        validate_preflight_input(&input)?;
        let described = self.describe_http_response_chain(entries).await?;
        if described.is_empty() {
            return Ok(empty_preflight_outcome(input.headers));
        }
        let session_admission = match self.try_reserve_middleware_session() {
            MiddlewareSessionAdmission::Admitted(admission) => admission,
            MiddlewareSessionAdmission::AtCapacity => {
                return Ok(response_session_capacity_exhausted(
                    described,
                    input.headers,
                ));
            }
        };
        let _work = self.reserve_middleware_work_admission().await?;
        let original_restriction = body_restriction(&input);
        let mut headers = input.headers.clone();
        let mut stages = Vec::new();
        let mut findings = Vec::new();
        let mut metadata = BTreeMap::new();
        let mut invocations = Vec::new();

        for entry in described {
            let Some(service) = entry.service.as_ref() else {
                if let Some(reason) =
                    collect_preflight_failure(&entry, "binding_not_described", &mut invocations)
                {
                    end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure).await;
                    return Ok(failed_preflight_outcome(
                        headers,
                        reason,
                        findings,
                        metadata,
                        invocations,
                    ));
                }
                continue;
            };
            let (sender, receiver) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
            let preflight = HttpResponsePreflight {
                context: Some(input.context.clone()),
                target: Some(input.target.clone()),
                status_code: u32::from(input.status_code),
                headers: headers.clone(),
                middleware_name: entry.entry.implementation.clone(),
                config: Some(entry.entry.config.clone()),
                max_payload_bytes: entry.max_payload_bytes as u64,
                permitted_body_modes: permitted_body_modes(
                    &input,
                    &entry,
                    original_restriction.as_deref(),
                ),
                deferral_permitted: entry.on_error() == OnError::FailClosed,
            };
            let timeout = entry.timeout.min(MAX_MIDDLEWARE_PREFLIGHT_TIMEOUT);
            let opened = tokio::time::timeout(timeout, async {
                let mut responses = service
                    .service
                    .open_http_response_pre_return(receiver)
                    .await?;
                sender
                    .send(HttpResponseEvent {
                        event: Some(http_response_event::Event::Preflight(preflight)),
                    })
                    .await
                    .map_err(|_| tonic::Status::unavailable("middleware request stream closed"))?;
                let response = responses.next().await.ok_or_else(|| {
                    tonic::Status::unavailable("middleware result stream closed")
                })??;
                Ok::<_, tonic::Status>((responses, response))
            })
            .await;
            let (responses, response) = match opened {
                Ok(Ok(opened)) => opened,
                Ok(Err(error)) => {
                    let reason = if error.code() == tonic::Code::DeadlineExceeded {
                        "middleware_timeout".to_string()
                    } else {
                        service.diagnostic_policy.error_reason(&error)
                    };
                    if let Some(reason) =
                        collect_preflight_failure(&entry, &reason, &mut invocations)
                    {
                        end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure)
                            .await;
                        return Ok(failed_preflight_outcome(
                            headers,
                            reason,
                            findings,
                            metadata,
                            invocations,
                        ));
                    }
                    continue;
                }
                Err(_) => {
                    if let Some(reason) =
                        collect_preflight_failure(&entry, "middleware_timeout", &mut invocations)
                    {
                        end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure)
                            .await;
                        return Ok(failed_preflight_outcome(
                            headers,
                            reason,
                            findings,
                            metadata,
                            invocations,
                        ));
                    }
                    continue;
                }
            };
            let Some(http_response_event_result::Result::PreflightDecision(decision)) =
                response.result
            else {
                if let Some(reason) = collect_preflight_failure(
                    &entry,
                    "unexpected_response_result",
                    &mut invocations,
                ) {
                    end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure).await;
                    return Ok(failed_preflight_outcome(
                        headers,
                        reason,
                        findings,
                        metadata,
                        invocations,
                    ));
                }
                continue;
            };
            if let Err(reason) = validate_diagnostics(
                &decision.reason,
                &decision.reason_code,
                &decision.findings,
                &decision.metadata,
            ) {
                if let Some(reason) = collect_preflight_failure(&entry, reason, &mut invocations) {
                    end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure).await;
                    return Ok(failed_preflight_outcome(
                        headers,
                        reason,
                        findings,
                        metadata,
                        invocations,
                    ));
                }
                continue;
            }
            let reason_code =
                (!decision.reason_code.is_empty()).then(|| decision.reason_code.clone());
            let decision_findings = decision.findings;
            let decision_metadata = decision.metadata;
            match decision.action {
                Some(http_response_preflight_decision::Action::Skip(_)) => {
                    collect_preflight_diagnostics(
                        &entry,
                        decision_findings,
                        decision_metadata,
                        &mut findings,
                        &mut metadata,
                    );
                    invocations.push(HttpResponseInvocation {
                        config_name: entry.entry.name.clone(),
                        implementation: entry.entry.implementation.clone(),
                        outcome: HttpResponseInvocationOutcome::Skip,
                        sequence: None,
                        input_size: 0,
                        output_size: None,
                        failed: false,
                        stage_disabled: false,
                        reason_code,
                        failure_category: None,
                    });
                    let mut skipped = HttpResponseStage {
                        entry,
                        transport: Some(HttpResponseStageTransport { sender, responses }),
                        mode: StageMode::HeadersOnly,
                        next_sequence: 1,
                        whole_body: Vec::new(),
                    };
                    skipped.end(MiddlewareSessionEndReason::StageSkipped).await;
                }
                Some(http_response_preflight_decision::Action::Inspect(inspect)) => {
                    let permitted_modes =
                        permitted_body_modes(&input, &entry, original_restriction.as_deref());
                    let mode = match validate_inspect(&entry, &inspect, &permitted_modes) {
                        Ok(mode) => mode,
                        Err(reason) => {
                            if let Some(reason) =
                                collect_preflight_failure(&entry, &reason, &mut invocations)
                            {
                                end_stages(
                                    &mut stages,
                                    MiddlewareSessionEndReason::MiddlewareFailure,
                                )
                                .await;
                                return Ok(failed_preflight_outcome(
                                    headers,
                                    reason,
                                    findings,
                                    metadata,
                                    invocations,
                                ));
                            }
                            continue;
                        }
                    };
                    let updated = match headers::apply(
                        headers::HeaderAuthority::Response,
                        &headers,
                        &input.connection_nominated_headers,
                        &inspect.header_mutations,
                    ) {
                        Ok(updated) => updated,
                        Err(error) => {
                            let reason = service
                                .diagnostic_policy
                                .header_mutation_error_reason(&error);
                            if let Some(reason) =
                                collect_preflight_failure(&entry, &reason, &mut invocations)
                            {
                                end_stages(
                                    &mut stages,
                                    MiddlewareSessionEndReason::MiddlewareFailure,
                                )
                                .await;
                                return Ok(failed_preflight_outcome(
                                    headers,
                                    reason,
                                    findings,
                                    metadata,
                                    invocations,
                                ));
                            }
                            continue;
                        }
                    };
                    headers = updated;
                    if mode == StageMode::Stream {
                        strip_stale_integrity(&mut headers);
                    }
                    collect_preflight_diagnostics(
                        &entry,
                        decision_findings,
                        decision_metadata,
                        &mut findings,
                        &mut metadata,
                    );
                    invocations.push(HttpResponseInvocation {
                        config_name: entry.entry.name.clone(),
                        implementation: entry.entry.implementation.clone(),
                        outcome: match mode {
                            StageMode::HeadersOnly => HttpResponseInvocationOutcome::HeadersOnly,
                            StageMode::WholeBody => HttpResponseInvocationOutcome::WholeBody,
                            StageMode::Stream => HttpResponseInvocationOutcome::Stream,
                        },
                        sequence: None,
                        input_size: 0,
                        output_size: None,
                        failed: false,
                        stage_disabled: false,
                        reason_code,
                        failure_category: None,
                    });
                    stages.push(HttpResponseStage {
                        entry,
                        transport: Some(HttpResponseStageTransport { sender, responses }),
                        mode,
                        next_sequence: 1,
                        whole_body: Vec::new(),
                    });
                }
                Some(http_response_preflight_decision::Action::BlockDelivery(_)) => {
                    collect_preflight_diagnostics(
                        &entry,
                        decision_findings,
                        decision_metadata,
                        &mut findings,
                        &mut metadata,
                    );
                    invocations.push(HttpResponseInvocation {
                        config_name: entry.entry.name.clone(),
                        implementation: entry.entry.implementation.clone(),
                        outcome: HttpResponseInvocationOutcome::BlockDelivery,
                        sequence: None,
                        input_size: 0,
                        output_size: None,
                        failed: false,
                        stage_disabled: false,
                        reason_code: reason_code.clone(),
                        failure_category: None,
                    });
                    stages.push(HttpResponseStage {
                        entry: entry.clone(),
                        transport: Some(HttpResponseStageTransport { sender, responses }),
                        mode: StageMode::HeadersOnly,
                        next_sequence: 1,
                        whole_body: Vec::new(),
                    });
                    end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareDenial).await;
                    return Ok(failed_preflight_outcome(
                        headers,
                        middleware_denial_reason(&entry.entry.name, reason_code.as_deref()),
                        findings,
                        metadata,
                        invocations,
                    ));
                }
                None => {
                    if let Some(reason) = collect_preflight_failure(
                        &entry,
                        "invalid_preflight_decision",
                        &mut invocations,
                    ) {
                        end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure)
                            .await;
                        return Ok(failed_preflight_outcome(
                            headers,
                            reason,
                            findings,
                            metadata,
                            invocations,
                        ));
                    }
                }
            }
        }

        if stages.is_empty() {
            drop(session_admission);
            return Ok(HttpResponsePreflightOutcome {
                allowed: true,
                reason: String::new(),
                headers,
                declared_trailer_names: Vec::new(),
                session: None,
                findings,
                metadata,
                invocations,
                session_capacity_exhausted: false,
            });
        }
        let defer_output_until_finish = stages
            .iter()
            .any(|stage| stage.is_active() && stage.mode == StageMode::WholeBody);
        Ok(HttpResponsePreflightOutcome {
            allowed: true,
            reason: String::new(),
            headers,
            declared_trailer_names: Vec::new(),
            session: Some(HttpResponseSession {
                runner: self.clone(),
                stages,
                findings: Vec::new(),
                metadata: BTreeMap::new(),
                invocations: Vec::new(),
                session_admission: Some(session_admission),
                body_transformed: false,
                defer_output_until_finish,
                deferred_output: Vec::new(),
            }),
            findings,
            metadata,
            invocations,
            session_capacity_exhausted: false,
        })
    }
}

enum BodyAction {
    PassThrough,
    Transform(Vec<u8>),
    BlockDelivery,
    SkipRemaining(CurrentBodyAction),
}

enum CurrentBodyAction {
    PassThrough,
    Transform(Vec<u8>),
}

struct BodyDecision {
    action: BodyAction,
    reason_code: String,
    findings: Vec<Finding>,
    metadata: std::collections::HashMap<String, String>,
}

fn validate_body_result(
    result: HttpResponseEventResult,
    sequence: u64,
    max_payload_bytes: usize,
) -> Result<BodyDecision, &'static str> {
    let Some(http_response_event_result::Result::BodyResult(body)) = result.result else {
        return Err("unexpected_response_result");
    };
    if body.sequence != sequence {
        return Err("response_body_sequence_mismatch");
    }
    validate_diagnostics(
        &body.reason,
        &body.reason_code,
        &body.findings,
        &body.metadata,
    )?;
    let action = match body.action {
        Some(http_response_body_result::Action::PassThrough(HttpResponseBodyPassThrough {})) => {
            BodyAction::PassThrough
        }
        Some(http_response_body_result::Action::Transform(transform)) => BodyAction::Transform(
            validate_replacement(transform.replacement, max_payload_bytes)?,
        ),
        Some(http_response_body_result::Action::BlockDelivery(_)) => BodyAction::BlockDelivery,
        Some(http_response_body_result::Action::SkipRemaining(skip)) => {
            let current = match skip.current {
                Some(http_response_body_skip_remaining::Current::PassThrough(
                    HttpResponseBodyPassThrough {},
                )) => CurrentBodyAction::PassThrough,
                Some(http_response_body_skip_remaining::Current::Transform(transform)) => {
                    CurrentBodyAction::Transform(validate_replacement(
                        transform.replacement,
                        max_payload_bytes,
                    )?)
                }
                None => return Err("invalid_response_body_skip_remaining_action"),
            };
            BodyAction::SkipRemaining(current)
        }
        None => return Err("invalid_response_body_decision"),
    };
    Ok(BodyDecision {
        action,
        reason_code: body.reason_code,
        findings: body.findings,
        metadata: body.metadata,
    })
}

fn validate_replacement(
    replacement: Option<http_response_body_transform::Replacement>,
    max_payload_bytes: usize,
) -> Result<Vec<u8>, &'static str> {
    let Some(http_response_body_transform::Replacement::Data(replacement)) = replacement else {
        return Err("response_body_replacement_missing");
    };
    if replacement.len() > max_payload_bytes {
        return Err("response_body_replacement_over_capacity");
    }
    Ok(replacement)
}

fn validate_inspect(
    entry: &DescribedChainEntry,
    inspect: &openshell_core::proto::HttpResponsePreflightInspect,
    permitted_modes: &[i32],
) -> Result<StageMode, String> {
    let mode = match HttpResponseBodyMode::try_from(inspect.body_mode) {
        Ok(HttpResponseBodyMode::HeadersOnly) => StageMode::HeadersOnly,
        Ok(HttpResponseBodyMode::WholeBodyBytes) => StageMode::WholeBody,
        Ok(HttpResponseBodyMode::StreamBytes) => StageMode::Stream,
        Ok(HttpResponseBodyMode::Unspecified) | Err(_) => {
            return Err("invalid_response_body_mode".into());
        }
    };
    if !permitted_modes.contains(&inspect.body_mode) {
        return Err("response_body_mode_not_permitted".into());
    }
    if inspect.header_mutations.len() > headers::MAX_HEADER_MUTATIONS {
        return Err("header_mutation_count_over_capacity".into());
    }
    let encoded_mutations = inspect
        .header_mutations
        .iter()
        .fold(0usize, |total, mutation| {
            total.saturating_add(mutation.encoded_len())
        });
    if encoded_mutations > MAX_MIDDLEWARE_HEADER_MUTATION_WIRE_BYTES {
        return Err("header_mutation_bytes_over_capacity".into());
    }
    if entry.max_payload_bytes == 0 && mode != StageMode::HeadersOnly {
        return Err("response_payload_limit_invalid".into());
    }
    Ok(mode)
}

fn validate_preflight_input(input: &HttpResponsePreflightInput) -> miette::Result<()> {
    if input.context.encoded_len() > MAX_MIDDLEWARE_CONTEXT_BYTES {
        return Err(miette::miette!("response context exceeds platform limit"));
    }
    if input.target.encoded_len() > MAX_MIDDLEWARE_TARGET_BYTES {
        return Err(miette::miette!("response target exceeds platform limit"));
    }
    if input.headers.len() > MAX_MIDDLEWARE_HEADERS {
        return Err(miette::miette!(
            "response header count exceeds platform limit"
        ));
    }
    if input.headers.iter().fold(0usize, |total, header| {
        total.saturating_add(header.encoded_len())
    }) > MAX_MIDDLEWARE_HEADER_BYTES
    {
        return Err(miette::miette!("response headers exceed platform limit"));
    }
    Ok(())
}

fn validate_diagnostics(
    reason: &str,
    reason_code: &str,
    findings: &[Finding],
    metadata: &std::collections::HashMap<String, String>,
) -> Result<(), &'static str> {
    if reason.len() > MAX_MIDDLEWARE_REASON_BYTES {
        return Err("response_reason_over_capacity");
    }
    if !reason_code.is_empty()
        && (reason_code.len() > MAX_MIDDLEWARE_REASON_CODE_BYTES
            || !is_stable_reason_code(reason_code))
    {
        return Err("response_reason_code_invalid");
    }
    if findings.len() > MAX_MIDDLEWARE_FINDINGS_PER_STAGE {
        return Err("response_findings_over_capacity");
    }
    if findings
        .iter()
        .any(|finding| finding.encoded_len() > MAX_MIDDLEWARE_FINDING_BYTES)
    {
        return Err("response_finding_over_capacity");
    }
    if metadata.len() > MAX_MIDDLEWARE_METADATA_ENTRIES {
        return Err("response_metadata_count_over_capacity");
    }
    if metadata.iter().fold(0usize, |total, (key, value)| {
        total.saturating_add(key.len()).saturating_add(value.len())
    }) > MAX_MIDDLEWARE_METADATA_BYTES
    {
        return Err("response_metadata_bytes_over_capacity");
    }
    Ok(())
}

fn body_restriction(input: &HttpResponsePreflightInput) -> Option<String> {
    if input.target.method.eq_ignore_ascii_case("HEAD")
        || input.status_code == 204
        || input.status_code == 304
    {
        return Some("bodyless_response".into());
    }
    if input.status_code == 206
        || input
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("content-range"))
        || input.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("content-type")
                && header
                    .value
                    .split(';')
                    .next()
                    .is_some_and(|value| value.trim().eq_ignore_ascii_case("multipart/byteranges"))
        })
    {
        return Some("unsupported_partial_response".into());
    }
    if input.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("cache-control")
            && header.value.split(',').any(|directive| {
                directive
                    .split('=')
                    .next()
                    .is_some_and(|name| name.trim().eq_ignore_ascii_case("no-transform"))
            })
    }) {
        return Some("response_no_transform".into());
    }
    if input.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("content-encoding")
            && header
                .value
                .split(',')
                .any(|coding| !coding.trim().eq_ignore_ascii_case("identity"))
    }) {
        return Some("unsupported_content_encoding".into());
    }
    None
}

fn permitted_body_modes(
    input: &HttpResponsePreflightInput,
    entry: &DescribedChainEntry,
    body_restriction: Option<&str>,
) -> Vec<i32> {
    let mut modes = vec![HttpResponseBodyMode::HeadersOnly as i32];
    if body_restriction.is_some() {
        return modes;
    }
    if input
        .declared_body_length
        .is_none_or(|length| length <= entry.max_payload_bytes as u64)
        && !is_open_ended_response(input)
    {
        modes.push(HttpResponseBodyMode::WholeBodyBytes as i32);
    }
    if entry.max_payload_bytes >= 2 {
        modes.push(HttpResponseBodyMode::StreamBytes as i32);
    }
    modes
}

fn is_open_ended_response(input: &HttpResponsePreflightInput) -> bool {
    input.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("content-type")
            && matches!(
                header.value.split(';').next().map(str::trim),
                Some(value)
                    if value.eq_ignore_ascii_case("text/event-stream")
                        || value.eq_ignore_ascii_case("multipart/x-mixed-replace")
            )
    })
}

fn strip_stale_integrity(headers: &mut Vec<HttpHeader>) {
    headers.retain(|header| {
        !matches!(
            header.name.to_ascii_lowercase().as_str(),
            "accept-ranges"
                | "etag"
                | "content-md5"
                | "digest"
                | "content-digest"
                | "repr-digest"
                | "signature"
                | "signature-input"
        )
    });
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
        headers,
        declared_trailer_names: Vec::new(),
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
        headers,
        declared_trailer_names: Vec::new(),
        session: None,
        findings,
        metadata,
        invocations,
        session_capacity_exhausted: false,
    }
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
        headers,
        declared_trailer_names: Vec::new(),
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use openshell_core::middleware::{HttpRequestView, InProcessMiddleware};
    use openshell_core::proto::{
        Decision, ExistingHeaderAction, HeaderMutation, HttpRequestResult, HttpResponseBodyResult,
        HttpResponseBodyTransform, HttpResponsePreflightDecision, HttpResponsePreflightInspect,
        HttpResponsePreflightSkip, MiddlewareBinding, MiddlewareManifest, WriteHeader,
        header_mutation, http_response_preflight_decision,
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
        Skip,
        InvalidSkipReason,
        UndeclaredTrailer,
    }

    struct ResponseService {
        script: Script,
    }

    #[derive(Clone)]
    struct RemoteResponseService;

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
            let (sender, receiver) = mpsc::channel(4);
            tokio::spawn(async move {
                while let Some(Ok(event)) = requests.next().await {
                    match event.event {
                        Some(http_response_event::Event::Preflight(_)) => {
                            let result = HttpResponseEventResult {
                                result: Some(
                                    http_response_event_result::Result::PreflightDecision(
                                        HttpResponsePreflightDecision {
                                            action: Some(
                                                http_response_preflight_decision::Action::Inspect(
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
                        Some(http_response_event::Event::SessionEnd(_)) | None => break,
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
                    max_payload_bytes: if matches!(self.script, Script::LargeStream) {
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
                                        http_response_event_result::Result::PreflightDecision(
                                            HttpResponsePreflightDecision {
                                                action: Some(
                                                    http_response_preflight_decision::Action::Skip(
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
                                    | Script::UndeclaredTrailer => {
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
                                    http_response_event_result::Result::PreflightDecision(
                                        HttpResponsePreflightDecision {
                                            action: Some(
                                                http_response_preflight_decision::Action::Inspect(
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
                                Script::Stream
                                | Script::InvalidSequence
                                | Script::LargeStream
                                | Script::UndeclaredTrailer => data.to_ascii_uppercase(),
                                Script::WholeBody => [b"whole:".as_slice(), &data].concat(),
                                Script::HeadersOnly
                                | Script::Configured
                                | Script::HangBody
                                | Script::Skip
                                | Script::InvalidSkipReason => break,
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
                                        action: Some(http_response_body_result::Action::Transform(
                                            HttpResponseBodyTransform {
                                                replacement: Some(
                                                    http_response_body_transform::Replacement::Data(
                                                        replacement,
                                                    ),
                                                ),
                                            },
                                        )),
                                        ..Default::default()
                                    },
                                )),
                            }
                        }
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
        outcome
            .session
            .expect("headers-only session")
            .finish(Vec::new())
            .await
            .expect("finish headers-only session");
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
        assert!(outcome.declared_trailer_names.is_empty());
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
        let session = outcome.session.take().expect("large stream session");
        assert_eq!(
            session.stream_unit_limit(),
            MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES
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
    async fn response_trailers_bypass_middleware_in_v1() {
        let runner = ChainRunner::new(Arc::new(ResponseService {
            script: Script::UndeclaredTrailer,
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
        assert_eq!(finish.trailers, trailers);
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
        let server = tonic::transport::Server::builder()
            .add_service(SupervisorMiddlewareServer::new(RemoteResponseService))
            .add_service(HttpResponsePreReturnServer::new(RemoteResponseService))
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
        outcome
            .session
            .expect("remote response session")
            .finish(Vec::new())
            .await
            .expect("finish remote response session");

        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("join response middleware server")
            .expect("serve response middleware");
    }
}
