// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Legacy HTTP response protocol (0.1). Removed in 0.2.0.
//!
//! [`LegacyResponseStage`] presents one legacy `HttpResponsePreReturn.Evaluate`
//! stream as a version 2 response stage. Preflight opens the legacy stream
//! with the 0.1.x body-mode offer, which is derived from the original response
//! head and ignores the version 2 eligibility rules:
//!
//! - `SKIP` and `HEADERS_ONLY` become `Continue`, with the `HEADERS_ONLY`
//!   mutations as preflight mutations. `BLOCK_DELIVERY` becomes `Reject`.
//! - `WHOLE_BODY_BYTES` becomes BUFFERED. The body is one unit with
//!   `end_of_stream` set, followed by the trailers exchange, and both results
//!   merge into one `HttpBufferedResult`.
//! - `STREAM_BYTES` becomes STREAM. Output starts at `Begin`, so the head
//!   commits after preflight, unless an earlier stage buffered the whole body
//!   ([`LegacyResponseControl::withhold_output_until_end`]). Each input chunk is
//!   exchanged in lockstep, and `InputEnd` sends the empty final unit and the
//!   trailers before `Finish`. After `skip_remaining` or a `fail_open`
//!   failure, the rest of the body passes through locally.
//!
//! The pipeline must offer every legacy response stage both body modes
//! whenever the response body may be inspected. The adapter ends the legacy
//! stream itself wherever 0.1.x ended a stage on that stage's own outcome,
//! with the 0.1.x reason, and forwards the pipeline's `session_end`
//! otherwise. It reports every 0.1.x invocation record, with the findings and
//! metadata of its step, as [`StageReport::LegacyResponseInvocation`] when
//! the step completes, so version 2 results carry no legacy diagnostics
//! except a block's reason code.
//!
//! Differences from 0.1.x are timing and ordering only:
//!
//! - The pipeline may read ahead of the stage up to its queue limit, while the
//!   service still sees one unit at a time. Each exchange is bounded by the
//!   entry timeout rather than by a 30-second deadline shared by all stages.
//! - Input is split into units by this stage's limit. 0.1.x split relay input
//!   by the smallest limit among all stream stages first.
//! - Each stage exchanges its trailers right after its own final unit, and
//!   strips stale integrity trailers after its own transform. 0.1.x ran every
//!   stage's final unit before any trailers exchange, and stripped them
//!   before any stage saw them once any stage had transformed the body.
//! - A `session_end` that arrives during a legacy exchange reaches the service
//!   when the exchange ends.
//! - Contract failures fail closed.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures::StreamExt as _;
use tokio::sync::mpsc;

use openshell_core::proto::{
    Finding, HeaderMutation, HttpBodyMode, HttpBufferedBody, HttpBufferedMode, HttpBufferedResult,
    HttpContinue, HttpEvent, HttpFinish, HttpHeader, HttpInputChunk, HttpInputEnd, HttpInspect,
    HttpOutputChunk, HttpOutputStart, HttpPreflight, HttpPreflightResult, HttpReject,
    HttpResponseBodyUnit, HttpResponseEvent, HttpResponseEventResult, HttpResponsePreflight,
    HttpResponseTrailers, HttpStreamMode, HttpUnchanged, MiddlewareSessionEnd,
    MiddlewareSessionEndReason, RemoveHeader, SupervisorMiddlewareOperation, header_mutation,
    http_buffered_result, http_event, http_inspect, http_preflight, http_preflight_result,
    http_response_body_unit, http_response_event, http_response_event_result,
    http_response_preflight_result, http_result,
};

use super::validation::{
    BodyAction, CurrentBodyAction, StageMode, encoded_header_bytes, permitted_body_modes,
    strip_stale_integrity, validate_body_result, validate_diagnostics, validate_inspect,
    validate_trailers_result,
};
use super::{
    HttpResponseInvocation, HttpResponseInvocationOutcome, MAX_HTTP_RESPONSE_RETAINED_BODY_BYTES,
    MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES,
};
use crate::legacy::codec::{
    LegacyStageFailure, Results, diagnostics, event_order_failure, invariant_failure, next_event,
    spawn_stage,
};
use crate::legacy::hooks::LegacyResponseControl;
use crate::response::validate_preflight_input;
use crate::{
    ChainRunner, ContractFailureKind, DescribedChainEntry, HttpProtocol,
    HttpResponsePreflightInput, HttpResponseResultStream, HttpResultStream, HttpStageTransport,
    MiddlewareDiagnosticPolicy, MiddlewareServiceState, MiddlewareWorkAdmissionOutcome, OnError,
    StageReport, StageReportSink, headers, is_stale_http_response_integrity_header,
};

/// Most output a stage withholding its output may retain, as 0.1.x reserved
/// room for one more upstream unit within its retained-body budget.
const WITHHELD_OUTPUT_LIMIT: usize =
    MAX_HTTP_RESPONSE_RETAINED_BODY_BYTES - MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES;

/// Per-exchange inputs of a legacy response stage.
#[derive(Clone)]
pub struct LegacyResponseExchange {
    /// Receives this exchange's [`StageReport::LegacyResponseInvocation`] and
    /// [`StageReport::LegacyFailOpen`] reports as the stage produces them.
    /// A long stream reports one record per unit, so the sink should emit or
    /// forward them rather than retain them for the whole response.
    pub reports: Arc<dyn StageReportSink>,
    /// Final upstream response head before any stage ran. 0.1.x derived every
    /// stage's body modes from it, and validated mutations against its
    /// `Connection`-nominated names.
    pub original: Arc<HttpResponsePreflightInput>,
    /// Owner of the shared middleware work queue. A stage holds a slot only
    /// during each body or trailers exchange, so a long stream holds none
    /// between units.
    pub runner: ChainRunner,
}

/// HTTP protocol 1 (0.1). Removed in 0.2.0.
///
/// One legacy `HttpResponsePreReturn.Evaluate` stage presented as a version 2
/// response stage.
#[derive(Clone)]
pub struct LegacyResponseStage {
    entry: DescribedChainEntry,
    service: Arc<MiddlewareServiceState>,
    exchange: LegacyResponseExchange,
    withhold_output: Arc<AtomicBool>,
}

impl LegacyResponseStage {
    /// Adapter for a resolved legacy `HTTP_RESPONSE` entry, or `None` for any
    /// other entry.
    #[must_use]
    pub fn new(entry: &DescribedChainEntry, exchange: LegacyResponseExchange) -> Option<Self> {
        let response = entry.binding.as_ref().is_some_and(|binding| {
            binding.operation == SupervisorMiddlewareOperation::HttpResponse as i32
        });
        if !response || entry.http_protocol() != Some(HttpProtocol::Legacy) {
            return None;
        }
        Some(Self {
            service: Arc::clone(entry.service.as_ref()?),
            entry: entry.clone(),
            exchange,
            withhold_output: Arc::default(),
        })
    }

    fn record(
        &self,
        invocation: HttpResponseInvocation,
        findings: Vec<Finding>,
        metadata: HashMap<String, String>,
    ) {
        self.exchange.reports.report(
            &self.entry.entry.name,
            StageReport::LegacyResponseInvocation {
                invocation,
                findings,
                metadata: metadata.into_iter().collect::<BTreeMap<_, _>>(),
            },
        );
    }

    fn record_success(
        &self,
        step: Step,
        findings: Vec<Finding>,
        metadata: HashMap<String, String>,
    ) {
        self.record(
            HttpResponseInvocation {
                config_name: self.entry.entry.name.clone(),
                implementation: self.entry.entry.implementation.clone(),
                outcome: step.outcome,
                sequence: step.sequence,
                input_size: step.sizes.map_or(0, |(input, _)| input),
                output_size: step.sizes.map(|(_, output)| output),
                failed: false,
                stage_disabled: false,
                reason_code: step.reason_code,
                failure_category: None,
            },
            findings,
            metadata,
        );
    }

    fn record_failure(
        &self,
        fail_open: bool,
        reason: &str,
        sequence: Option<u64>,
        input_size: usize,
    ) {
        self.record(
            HttpResponseInvocation {
                config_name: self.entry.entry.name.clone(),
                implementation: self.entry.entry.implementation.clone(),
                outcome: if fail_open {
                    HttpResponseInvocationOutcome::FailOpen
                } else {
                    HttpResponseInvocationOutcome::FailClosed
                },
                sequence,
                input_size,
                output_size: None,
                failed: true,
                stage_disabled: true,
                reason_code: None,
                failure_category: Some(super::failure_category(reason).into()),
            },
            Vec::new(),
            HashMap::new(),
        );
    }

    fn report_fail_open(&self, reason: &str) {
        self.exchange.reports.report(
            &self.entry.entry.name,
            StageReport::LegacyFailOpen {
                reason: reason.to_string(),
            },
        );
    }
}

impl LegacyResponseControl for LegacyResponseStage {
    /// The pipeline holds the input of a BUFFERED stage, so it calls this when
    /// the body outgrows the selected limit (`whole_body_over_capacity`) or
    /// the whole-body deadline expires (`whole_body_accumulation_timeout`).
    /// The stage records the 0.1.x outcome and fails open under `fail_open`.
    fn buffered_input_failed(&self, reason: &str, input_size: usize) -> bool {
        let fail_open = self.entry.on_error() == OnError::FailOpen;
        self.record_failure(fail_open, reason, None, input_size);
        if fail_open {
            self.report_fail_open(reason);
        }
        fail_open
    }

    /// 0.1.x withheld all output while a whole-body stage buffered, so a
    /// later stream stage ran over the whole body before the head committed:
    /// its block was the canonical denial and its failure a failure response,
    /// not an abort. The stage then holds its output until its input ends
    /// and starts output with the final length when no trailers remain. Held
    /// output that would pass the 0.1.x retained-body budget starts streaming
    /// instead.
    fn withhold_output_until_end(&self) {
        self.withhold_output.store(true, Ordering::Release);
    }
}

#[tonic::async_trait]
impl HttpStageTransport for LegacyResponseStage {
    async fn open(
        &self,
        events: mpsc::Receiver<HttpEvent>,
    ) -> Result<HttpResultStream, tonic::Status> {
        let stage = self.clone();
        Ok(spawn_stage(move |results| async move {
            ResponseCodec::new(stage, results).run(events).await;
        }))
    }
}

/// One successful 0.1.x invocation record.
struct Step {
    outcome: HttpResponseInvocationOutcome,
    sequence: Option<u64>,
    /// Input and output sizes. Preflight records carry none.
    sizes: Option<(usize, usize)>,
    reason_code: Option<String>,
}

impl Step {
    const fn preflight(
        outcome: HttpResponseInvocationOutcome,
        reason_code: Option<String>,
    ) -> Self {
        Self {
            outcome,
            sequence: None,
            sizes: None,
            reason_code,
        }
    }
}

/// Body lifecycle after an accepted inspect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Buffered,
    Stream,
    /// `skip_remaining` or a `fail_open` failure ended inspection. The rest of
    /// the body passes through unchanged.
    PassThrough,
}

/// How one legacy exchange ended without a result.
enum ExchangeError {
    /// A 0.1.x failure, handled by `on_error`.
    Failed(String),
    /// A contract failure, passed to the pipeline unchanged.
    Contract(ContractFailureKind, tonic::Status),
    /// The shared middleware work queue was full. 0.1.x failed the response
    /// whatever `on_error` said.
    AdmissionExhausted,
    /// The pipeline stopped reading results.
    Abandoned,
}

struct ResponseCodec {
    stage: LegacyResponseStage,
    results: Results,
    /// Open legacy stream. `None` once the stage ended it.
    legacy: Option<HttpResponseStageTransport>,
    mode: Mode,
    next_sequence: u64,
    /// Largest legacy unit for this stage.
    unit_limit: usize,
    /// Largest version 2 output chunk.
    output_limit: usize,
    /// Largest BUFFERED body this stage selected.
    buffered_limit: usize,
    transformed: bool,
    /// Output held back until the input ends.
    withheld: Option<Vec<u8>>,
    /// The stage returned its last result and its legacy stream waits for the
    /// pipeline's `session_end`.
    completed: bool,
}

impl ResponseCodec {
    fn new(stage: LegacyResponseStage, results: Results) -> Self {
        let unit_limit = stage
            .entry
            .max_payload_bytes
            .clamp(1, MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES);
        Self {
            stage,
            results,
            legacy: None,
            mode: Mode::PassThrough,
            next_sequence: 1,
            unit_limit,
            output_limit: unit_limit,
            buffered_limit: 0,
            transformed: false,
            withheld: None,
            completed: false,
        }
    }

    async fn run(mut self, mut events: mpsc::Receiver<HttpEvent>) {
        self.process(&mut events).await;
        // 0.1.x ended every stage it opened. A pipeline that ended this one
        // during an exchange and stopped reading results left its reason
        // queued; otherwise it went away without ending this one.
        let reason = queued_session_end(&mut events).unwrap_or(if self.completed {
            MiddlewareSessionEndReason::Normal
        } else {
            MiddlewareSessionEndReason::Cancellation
        });
        self.end_legacy(reason).await;
    }

    async fn process(&mut self, events: &mut mpsc::Receiver<HttpEvent>) {
        let Some(http_event::Event::Preflight(preflight)) = next_event(events).await else {
            self.results.fail(event_order_failure()).await;
            return;
        };
        let Some(mode) = self.preflight(preflight).await else {
            return;
        };
        self.mode = mode;
        if mode == Mode::Buffered {
            self.run_buffered(events).await;
        } else {
            self.run_stream(events).await;
        }
        if !self.completed {
            return;
        }
        // 0.1.x ended a completed stage with the chain's outcome.
        loop {
            match next_event(events).await {
                Some(http_event::Event::SessionEnd(end)) => {
                    self.forward_session_end(&end).await;
                    return;
                }
                Some(_) => {}
                None => return,
            }
        }
    }

    async fn run_buffered(&mut self, events: &mut mpsc::Receiver<HttpEvent>) {
        loop {
            match next_event(events).await {
                Some(http_event::Event::Begin(_)) => {}
                Some(http_event::Event::BufferedBody(HttpBufferedBody {
                    data,
                    visible_trailers,
                })) => {
                    self.buffered(data, visible_trailers).await;
                    return;
                }
                Some(http_event::Event::SessionEnd(end)) => {
                    self.forward_session_end(&end).await;
                    return;
                }
                Some(_) => {
                    self.order_failure().await;
                    return;
                }
                None => return,
            }
        }
    }

    async fn run_stream(&mut self, events: &mut mpsc::Receiver<HttpEvent>) {
        let mut started = false;
        loop {
            match next_event(events).await {
                Some(http_event::Event::Begin(_)) if !started => {
                    started = true;
                    if self.stage.withhold_output.load(Ordering::Acquire) {
                        self.withheld = Some(Vec::new());
                    } else if !self.results.send(output_start(None)).await {
                        return;
                    }
                }
                Some(http_event::Event::InputChunk(HttpInputChunk { data })) if started => {
                    if !self.input(data).await {
                        return;
                    }
                }
                Some(http_event::Event::InputEnd(HttpInputEnd { visible_trailers })) if started => {
                    self.input_end(visible_trailers).await;
                    return;
                }
                Some(http_event::Event::SessionEnd(end)) => {
                    self.forward_session_end(&end).await;
                    return;
                }
                Some(_) => {
                    self.order_failure().await;
                    return;
                }
                None => return,
            }
        }
    }

    /// Run the legacy preflight. Returns the selected body mode, or `None`
    /// when the stage ended at preflight.
    async fn preflight(&mut self, preflight: HttpPreflight) -> Option<Mode> {
        let Some(http_preflight::Head::Response(head)) = preflight.head else {
            self.results.fail(event_order_failure()).await;
            return None;
        };
        let stage = self.stage.clone();
        let entry = &stage.entry;
        let original = &stage.exchange.original;
        if validate_preflight_input(original).is_err() {
            return self.preflight_failure("response_input_over_capacity").await;
        }
        let legacy_modes = permitted_body_modes(original, entry);
        let limits = preflight.limits.unwrap_or_default();
        if let Ok(limit) = usize::try_from(limits.max_chunk_bytes)
            && limit > 0
        {
            self.output_limit = limit;
        }
        self.buffered_limit = usize::try_from(limits.max_buffered_body_bytes)
            .unwrap_or(usize::MAX)
            .min(entry.max_payload_bytes);
        let legacy_preflight = HttpResponseEvent {
            event: Some(http_response_event::Event::Preflight(
                HttpResponsePreflight {
                    context: head.context,
                    target: head.target,
                    status_code: head.status_code,
                    headers: head.headers.clone(),
                    middleware_name: entry.entry.implementation.clone(),
                    config: Some(entry.entry.config.clone()),
                    max_payload_bytes: entry.max_payload_bytes as u64,
                    permitted_body_modes: legacy_modes.clone(),
                },
            )),
        };
        let (sender, receiver) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
        let opened =
            self.results
                .unless_closed(tokio::time::timeout(entry.timeout, async {
                    sender.send(legacy_preflight).await.map_err(|_| {
                        tonic::Status::unavailable("middleware request stream closed")
                    })?;
                    let mut responses = stage
                        .service
                        .service
                        .open_http_response_pre_return(receiver)
                        .await?;
                    let response = responses.next().await.ok_or_else(|| {
                        tonic::Status::unavailable("middleware result stream closed")
                    })??;
                    Ok::<_, tonic::Status>((responses, response))
                }))
                .await?;
        let response = match opened {
            Ok(Ok((responses, response))) => {
                self.legacy = Some(HttpResponseStageTransport { sender, responses });
                response
            }
            Ok(Err(status)) if let Some(kind) = ContractFailureKind::from_status(&status) => {
                self.contract_failure(kind, status, None, 0).await;
                return None;
            }
            Ok(Err(status)) => {
                let reason = if status.code() == tonic::Code::DeadlineExceeded {
                    "middleware_timeout".to_string()
                } else {
                    stage.service.diagnostic_policy.error_reason(&status)
                };
                return self.preflight_failure(&reason).await;
            }
            Err(_) => return self.preflight_failure("middleware_timeout").await,
        };
        let Some(http_response_event_result::Result::PreflightResult(decision)) = response.result
        else {
            return self.preflight_failure("unexpected_response_result").await;
        };
        if let Err(reason) = validate_diagnostics(
            &decision.reason,
            &decision.reason_code,
            &decision.findings,
            &decision.metadata,
        ) {
            return self.preflight_failure(reason).await;
        }
        let reason_code = (!decision.reason_code.is_empty()).then_some(decision.reason_code);
        let mut findings = decision.findings;
        let mut metadata = decision.metadata;
        normalize_diagnostics(entry, &mut findings, &mut metadata);
        match decision.action {
            Some(http_response_preflight_result::Action::Skip(_)) => {
                stage.record_success(
                    Step::preflight(HttpResponseInvocationOutcome::Skip, reason_code),
                    findings,
                    metadata,
                );
                self.end_legacy(MiddlewareSessionEndReason::StageSkipped)
                    .await;
                self.results.send(continue_without_body(Vec::new())).await;
                None
            }
            Some(http_response_preflight_result::Action::Inspect(inspect)) => {
                let mode = match validate_inspect(entry, &inspect, &legacy_modes) {
                    Ok(mode) => mode,
                    Err(reason) => return self.preflight_failure(&reason).await,
                };
                if let Err(error) = headers::apply(
                    headers::HeaderAuthority::Response,
                    &head.headers,
                    &original.connection_nominated_headers,
                    &inspect.header_mutations,
                ) {
                    let reason = stage
                        .service
                        .diagnostic_policy
                        .header_mutation_error_reason(&error);
                    return self.preflight_failure(&reason).await;
                }
                let (outcome, selected) = match mode {
                    StageMode::HeadersOnly => (HttpResponseInvocationOutcome::HeadersOnly, None),
                    StageMode::WholeBody => (
                        HttpResponseInvocationOutcome::WholeBody,
                        Some((
                            Mode::Buffered,
                            HttpBodyMode::Buffered,
                            http_inspect::Mode::Buffered(HttpBufferedMode {
                                max_body_bytes: self.buffered_limit as u64,
                            }),
                        )),
                    ),
                    StageMode::Stream => (
                        HttpResponseInvocationOutcome::Stream,
                        Some((
                            Mode::Stream,
                            HttpBodyMode::Stream,
                            http_inspect::Mode::Stream(HttpStreamMode {}),
                        )),
                    ),
                };
                if let Some((mode, body_mode, _)) = &selected
                    && (!preflight
                        .permitted_body_modes
                        .contains(&(*body_mode as i32))
                        || (*mode == Mode::Buffered && self.buffered_limit == 0))
                {
                    self.end_legacy(MiddlewareSessionEndReason::MiddlewareFailure)
                        .await;
                    self.results
                        .fail(invariant_failure("legacy_stage_offer_invalid"))
                        .await;
                    return None;
                }
                stage.record_success(Step::preflight(outcome, reason_code), findings, metadata);
                let Some((mode, _, inspect_mode)) = selected else {
                    self.end_legacy(MiddlewareSessionEndReason::Normal).await;
                    self.results
                        .send(continue_without_body(inspect.header_mutations))
                        .await;
                    return None;
                };
                let result = http_result::Result::PreflightResult(HttpPreflightResult {
                    decision: Some(http_preflight_result::Decision::Inspect(HttpInspect {
                        mode: Some(inspect_mode),
                    })),
                    header_mutations: inspect.header_mutations,
                    diagnostics: None,
                });
                self.results.send(result).await.then_some(mode)
            }
            Some(http_response_preflight_result::Action::BlockDelivery(_)) => {
                stage.record_success(
                    Step::preflight(
                        HttpResponseInvocationOutcome::BlockDelivery,
                        reason_code.clone(),
                    ),
                    findings,
                    metadata,
                );
                self.end_legacy(MiddlewareSessionEndReason::MiddlewareDenial)
                    .await;
                self.results.send(reject(reason_code)).await;
                None
            }
            None => self.preflight_failure("invalid_preflight_decision").await,
        }
    }

    /// Apply `on_error` to a preflight failure. `fail_open` continues without
    /// the stage.
    async fn preflight_failure(&mut self, reason: &str) -> Option<Mode> {
        let fail_open = self.stage.entry.on_error() == OnError::FailOpen;
        self.stage.record_failure(fail_open, reason, None, 0);
        self.end_legacy(MiddlewareSessionEndReason::MiddlewareFailure)
            .await;
        if fail_open {
            self.stage.report_fail_open(reason);
            self.results.send(continue_without_body(Vec::new())).await;
        } else {
            self.results
                .fail(LegacyStageFailure::new(reason).into_status())
                .await;
        }
        None
    }

    /// Exchange the whole body as one final unit, then the trailers, and
    /// return one buffered result.
    async fn buffered(&mut self, data: Vec<u8>, visible_trailers: Vec<HttpHeader>) {
        let output = if data.len() > self.buffered_limit {
            self.body_failure("whole_body_over_capacity", None, data)
                .await
        } else {
            match self.exchange(body_event(1, data.clone(), true)).await {
                Ok(result) => self.body_result(result, 1, data).await,
                Err(error) => self.exchange_failure(error, Some(1), data).await,
            }
        };
        let Some(output) = output else {
            return;
        };
        let Some((trailer_mutations, _)) = self.trailers(visible_trailers).await else {
            return;
        };
        let body = if self.transformed {
            http_buffered_result::Body::Replacement(output)
        } else {
            http_buffered_result::Body::Unchanged(HttpUnchanged {})
        };
        let result = http_result::Result::BufferedResult(HttpBufferedResult {
            body: Some(body),
            header_mutations: Vec::new(),
            trailer_mutations,
            diagnostics: None,
        });
        self.completed = self.results.send(result).await;
    }

    /// Exchange one input chunk as lockstep units. False when the stage
    /// ended.
    async fn input(&mut self, data: Vec<u8>) -> bool {
        for unit in data.chunks(self.unit_limit) {
            let output = if self.mode == Mode::PassThrough {
                unit.to_vec()
            } else {
                let sequence = self.next_sequence;
                self.next_sequence += 1;
                let result = match self
                    .exchange(body_event(sequence, unit.to_vec(), false))
                    .await
                {
                    Ok(result) => self.body_result(result, sequence, unit.to_vec()).await,
                    Err(error) => {
                        self.exchange_failure(error, Some(sequence), unit.to_vec())
                            .await
                    }
                };
                let Some(output) = result else {
                    return false;
                };
                output
            };
            if !self.emit(output).await {
                return false;
            }
        }
        true
    }

    /// Send the empty final unit and the trailers, then release any withheld
    /// output and finish.
    async fn input_end(&mut self, visible_trailers: Vec<HttpHeader>) {
        if self.mode == Mode::Stream {
            let sequence = self.next_sequence;
            self.next_sequence += 1;
            let output = match self.exchange(body_event(sequence, Vec::new(), true)).await {
                Ok(result) => self.body_result(result, sequence, Vec::new()).await,
                Err(error) => {
                    self.exchange_failure(error, Some(sequence), Vec::new())
                        .await
                }
            };
            let Some(output) = output else {
                return;
            };
            if !self.emit(output).await {
                return;
            }
        }
        let Some((trailer_mutations, trailers)) = self.trailers(visible_trailers).await else {
            return;
        };
        if let Some(withheld) = self.withheld.take() {
            let length = trailers.is_empty().then_some(withheld.len() as u64);
            if !self.results.send(output_start(length)).await
                || !send_output(&self.results, self.output_limit, &withheld).await
            {
                return;
            }
        }
        let finish = http_result::Result::Finish(HttpFinish {
            trailer_mutations,
            diagnostics: None,
        });
        self.completed = self.results.send(finish).await;
    }

    /// Run the trailers exchange for a stage still inspecting the body.
    /// Returns the trailer mutations to report and the resulting trailers, or
    /// `None` when the stage ended.
    async fn trailers(
        &mut self,
        visible: Vec<HttpHeader>,
    ) -> Option<(Vec<HeaderMutation>, Vec<HttpHeader>)> {
        // 0.1.x stripped stale integrity trailers after a transformed body
        // before the stage saw them.
        let mut stale = Vec::new();
        let mut trailers = visible;
        if self.transformed {
            for trailer in &trailers {
                if is_stale_http_response_integrity_header(&trailer.name)
                    && !stale.contains(&trailer.name)
                {
                    stale.push(trailer.name.clone());
                }
            }
            strip_stale_integrity(&mut trailers);
        }
        let mut mutations: Vec<HeaderMutation> = stale
            .into_iter()
            .map(|name| HeaderMutation {
                operation: Some(header_mutation::Operation::Remove(RemoveHeader { name })),
            })
            .collect();
        if self.mode == Mode::PassThrough {
            return Some((mutations, trailers));
        }
        let input_size = encoded_header_bytes(&trailers);
        let event = HttpResponseEvent {
            event: Some(http_response_event::Event::Trailers(HttpResponseTrailers {
                headers: trailers.clone(),
            })),
        };
        let result = match self.exchange(event).await {
            Ok(result) => result,
            Err(error) => {
                return self
                    .trailer_failure(error, input_size, mutations, trailers)
                    .await;
            }
        };
        let legacy_mutations = match &result.result {
            Some(http_response_event_result::Result::TrailersResult(result)) => {
                result.trailer_mutations.clone()
            }
            _ => Vec::new(),
        };
        let decision = match validate_trailers_result(
            result,
            &trailers,
            &self.stage.entry,
            &self.stage.exchange.original.connection_nominated_headers,
        ) {
            Ok(decision) => decision,
            Err(reason) => {
                return self
                    .trailer_failure(
                        ExchangeError::Failed(reason),
                        input_size,
                        mutations,
                        trailers,
                    )
                    .await;
            }
        };
        let (findings, metadata) = self.normalized(decision.findings, decision.metadata);
        self.stage.record_success(
            Step {
                outcome: HttpResponseInvocationOutcome::Trailers,
                sequence: None,
                sizes: Some((input_size, encoded_header_bytes(&decision.headers))),
                reason_code: (!decision.reason_code.is_empty()).then_some(decision.reason_code),
            },
            findings,
            metadata,
        );
        mutations.extend(legacy_mutations);
        Some((mutations, decision.headers))
    }

    async fn trailer_failure(
        &mut self,
        error: ExchangeError,
        input_size: usize,
        mutations: Vec<HeaderMutation>,
        trailers: Vec<HttpHeader>,
    ) -> Option<(Vec<HeaderMutation>, Vec<HttpHeader>)> {
        let reason = match error {
            ExchangeError::Failed(reason) => reason,
            ExchangeError::Contract(kind, status) => {
                self.contract_failure(kind, status, None, input_size).await;
                return None;
            }
            ExchangeError::AdmissionExhausted => {
                self.admission_exhausted().await;
                return None;
            }
            ExchangeError::Abandoned => return None,
        };
        let fail_open = self.stage.entry.on_error() == OnError::FailOpen;
        self.stage
            .record_failure(fail_open, &reason, None, input_size);
        self.end_legacy(MiddlewareSessionEndReason::MiddlewareFailure)
            .await;
        if fail_open {
            self.stage.report_fail_open(&reason);
            self.mode = Mode::PassThrough;
            Some((mutations, trailers))
        } else {
            self.results
                .fail(LegacyStageFailure::new(&reason).into_status())
                .await;
            None
        }
    }

    /// Apply one validated body result. Returns the bytes to release, or
    /// `None` when the stage ended.
    async fn body_result(
        &mut self,
        result: HttpResponseEventResult,
        sequence: u64,
        original: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let decision =
            match validate_body_result(result, sequence, self.stage.entry.max_payload_bytes) {
                Ok(decision) => decision,
                Err(reason) => return self.body_failure(reason, Some(sequence), original).await,
            };
        let replacement_size = match &decision.action {
            BodyAction::Transform(replacement)
            | BodyAction::SkipRemaining(CurrentBodyAction::Transform(replacement)) => {
                Some(replacement.len())
            }
            _ => None,
        };
        if let (Some(withheld), Some(replacement_size)) = (&self.withheld, replacement_size)
            && withheld.len().saturating_add(replacement_size) > WITHHELD_OUTPUT_LIMIT
        {
            return self
                .body_failure(
                    "response_body_aggregate_over_capacity",
                    Some(sequence),
                    original,
                )
                .await;
        }
        let input_size = original.len();
        let (findings, metadata) = self.normalized(decision.findings, decision.metadata);
        let reason_code = (!decision.reason_code.is_empty()).then_some(decision.reason_code);
        let (outcome, output) = match decision.action {
            BodyAction::PassThrough => (HttpResponseInvocationOutcome::PassThrough, original),
            BodyAction::Transform(replacement) => {
                self.transformed = true;
                (HttpResponseInvocationOutcome::Transform, replacement)
            }
            BodyAction::SkipRemaining(current) => {
                let output = match current {
                    CurrentBodyAction::PassThrough => original,
                    CurrentBodyAction::Transform(replacement) => {
                        self.transformed = true;
                        replacement
                    }
                };
                self.stage.record_success(
                    Step {
                        outcome: HttpResponseInvocationOutcome::SkipRemaining,
                        sequence: Some(sequence),
                        sizes: Some((input_size, output.len())),
                        reason_code,
                    },
                    findings,
                    metadata,
                );
                self.mode = Mode::PassThrough;
                self.end_legacy(MiddlewareSessionEndReason::Normal).await;
                return Some(output);
            }
            BodyAction::BlockDelivery => {
                self.stage.record_success(
                    Step {
                        outcome: HttpResponseInvocationOutcome::BlockDelivery,
                        sequence: Some(sequence),
                        sizes: Some((input_size, 0)),
                        reason_code: reason_code.clone(),
                    },
                    findings,
                    metadata,
                );
                self.end_legacy(MiddlewareSessionEndReason::MiddlewareDenial)
                    .await;
                self.results.send(reject(reason_code)).await;
                return None;
            }
        };
        self.stage.record_success(
            Step {
                outcome,
                sequence: Some(sequence),
                sizes: Some((input_size, output.len())),
                reason_code,
            },
            findings,
            metadata,
        );
        Some(output)
    }

    async fn exchange_failure(
        &mut self,
        error: ExchangeError,
        sequence: Option<u64>,
        original: Vec<u8>,
    ) -> Option<Vec<u8>> {
        match error {
            ExchangeError::Failed(reason) => self.body_failure(&reason, sequence, original).await,
            ExchangeError::Contract(kind, status) => {
                self.contract_failure(kind, status, sequence, original.len())
                    .await;
                None
            }
            ExchangeError::AdmissionExhausted => {
                self.admission_exhausted().await;
                None
            }
            ExchangeError::Abandoned => None,
        }
    }

    /// Apply `on_error` to a body failure. `fail_open` releases the unit the
    /// stage was given and passes the rest of the body through.
    async fn body_failure(
        &mut self,
        reason: &str,
        sequence: Option<u64>,
        original: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let fail_open = self.stage.entry.on_error() == OnError::FailOpen;
        self.stage
            .record_failure(fail_open, reason, sequence, original.len());
        self.end_legacy(MiddlewareSessionEndReason::MiddlewareFailure)
            .await;
        if fail_open {
            self.stage.report_fail_open(reason);
            self.mode = Mode::PassThrough;
            Some(original)
        } else {
            self.results
                .fail(LegacyStageFailure::new(reason).into_status())
                .await;
            None
        }
    }

    /// Record a contract failure, which fails closed whatever `on_error` says,
    /// and pass the status on for the pipeline to classify.
    async fn contract_failure(
        &mut self,
        kind: ContractFailureKind,
        status: tonic::Status,
        sequence: Option<u64>,
        input_size: usize,
    ) {
        self.stage
            .record_failure(false, kind.reason(), sequence, input_size);
        self.end_legacy(MiddlewareSessionEndReason::MiddlewareFailure)
            .await;
        self.results.fail(status).await;
    }

    /// Fail closed without recording an invocation, as 0.1.x failed a
    /// response it could not admit.
    async fn admission_exhausted(&mut self) {
        self.end_legacy(MiddlewareSessionEndReason::MiddlewareFailure)
            .await;
        self.results
            .fail(LegacyStageFailure::new("admission_exhausted").into_status())
            .await;
    }

    async fn order_failure(&mut self) {
        self.end_legacy(MiddlewareSessionEndReason::MiddlewareFailure)
            .await;
        self.results.fail(event_order_failure()).await;
    }

    /// One legacy body or trailers exchange under the entry timeout, holding
    /// a slot of the shared middleware work queue. 0.1.x held one slot while
    /// every stage of the chain exchanged one body unit; stages here run
    /// concurrently, so a chain may hold one slot per stage.
    async fn exchange(
        &mut self,
        event: HttpResponseEvent,
    ) -> Result<HttpResponseEventResult, ExchangeError> {
        if self.legacy.is_none() {
            return Err(ExchangeError::Failed("middleware_stream_closed".into()));
        }
        let _work = match self
            .results
            .unless_closed(self.stage.exchange.runner.reserve_middleware_work())
            .await
        {
            None => return Err(ExchangeError::Abandoned),
            Some(Ok(MiddlewareWorkAdmissionOutcome::Admitted(work))) => work,
            Some(Ok(MiddlewareWorkAdmissionOutcome::QueueExhausted) | Err(_)) => {
                return Err(ExchangeError::AdmissionExhausted);
            }
        };
        let Some(transport) = self.legacy.as_mut() else {
            return Err(ExchangeError::Failed("middleware_stream_closed".into()));
        };
        let exchanged = tokio::time::timeout(self.stage.entry.timeout, async {
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
        });
        match self.results.unless_closed(exchanged).await {
            None => Err(ExchangeError::Abandoned),
            Some(Ok(Ok(result))) => Ok(result),
            Some(Ok(Err(status))) if let Some(kind) = ContractFailureKind::from_status(&status) => {
                Err(ExchangeError::Contract(kind, status))
            }
            Some(Ok(Err(status))) => Err(ExchangeError::Failed(
                self.stage.service.diagnostic_policy.error_reason(&status),
            )),
            Some(Err(_)) => Err(ExchangeError::Failed("middleware_timeout".into())),
        }
    }

    /// Release `output`, or hold it back while the stage withholds output.
    /// Output that would take what is held past the 0.1.x retained-body
    /// budget starts the output with what is held instead, and the rest of the
    /// body streams: that much input passed through an earlier whole-body
    /// stage only after it failed open, and 0.1.x resumed streaming then.
    /// False when the pipeline stopped reading.
    async fn emit(&mut self, output: Vec<u8>) -> bool {
        if let Some(withheld) = &mut self.withheld
            && withheld.len().saturating_add(output.len()) <= WITHHELD_OUTPUT_LIMIT
        {
            withheld.extend_from_slice(&output);
            return true;
        }
        if let Some(withheld) = self.withheld.take()
            && (!self.results.send(output_start(None)).await
                || !send_output(&self.results, self.output_limit, &withheld).await)
        {
            return false;
        }
        send_output(&self.results, self.output_limit, &output).await
    }

    /// Normalize one result's diagnostics as 0.1.x did for this stage.
    fn normalized(
        &self,
        mut findings: Vec<Finding>,
        mut metadata: HashMap<String, String>,
    ) -> (Vec<Finding>, HashMap<String, String>) {
        normalize_diagnostics(&self.stage.entry, &mut findings, &mut metadata);
        (findings, metadata)
    }

    /// End the legacy stream with the pipeline's reason.
    async fn forward_session_end(&mut self, end: &MiddlewareSessionEnd) {
        self.end_legacy(
            MiddlewareSessionEndReason::try_from(end.reason)
                .unwrap_or(MiddlewareSessionEndReason::Cancellation),
        )
        .await;
    }

    async fn end_legacy(&mut self, reason: MiddlewareSessionEndReason) {
        if let Some(transport) = self.legacy.take() {
            transport.end(reason).await;
        }
    }
}

/// Reason of a `session_end` still queued behind the events the stage read.
fn queued_session_end(
    events: &mut mpsc::Receiver<HttpEvent>,
) -> Option<MiddlewareSessionEndReason> {
    while let Ok(event) = events.try_recv() {
        if let Some(http_event::Event::SessionEnd(end)) = event.event {
            return Some(
                MiddlewareSessionEndReason::try_from(end.reason)
                    .unwrap_or(MiddlewareSessionEndReason::Cancellation),
            );
        }
    }
    None
}

fn continue_without_body(header_mutations: Vec<HeaderMutation>) -> http_result::Result {
    http_result::Result::PreflightResult(HttpPreflightResult {
        decision: Some(http_preflight_result::Decision::ContinueWithoutBody(
            HttpContinue {},
        )),
        header_mutations,
        diagnostics: None,
    })
}

fn output_start(output_body_bytes: Option<u64>) -> http_result::Result {
    http_result::Result::OutputStart(HttpOutputStart {
        header_mutations: Vec::new(),
        output_body_bytes,
    })
}

/// A block, carrying only its reason code. The stage reported its findings
/// with the block's invocation record.
fn reject(reason_code: Option<String>) -> http_result::Result {
    http_result::Result::Reject(HttpReject {
        diagnostics: diagnostics(reason_code.unwrap_or_default(), Vec::new(), HashMap::new()),
    })
}

/// Release `output` as version 2 output chunks of at most `limit` bytes.
/// False when the pipeline stopped reading.
async fn send_output(results: &Results, limit: usize, output: &[u8]) -> bool {
    for chunk in output.chunks(limit) {
        let chunk = http_result::Result::OutputChunk(HttpOutputChunk {
            data: chunk.to_vec(),
        });
        if !results.send(chunk).await {
            return false;
        }
    }
    true
}

/// Legacy events a stage may queue before the service reads them.
const STREAM_CHANNEL_CAPACITY: usize = 4;
/// Longest a stage waits to deliver its legacy `session_end`.
const SESSION_END_TIMEOUT: Duration = Duration::from_millis(10);

/// One open `HttpResponsePreReturn.Evaluate` stream.
struct HttpResponseStageTransport {
    sender: mpsc::Sender<HttpResponseEvent>,
    responses: HttpResponseResultStream,
}

impl HttpResponseStageTransport {
    async fn end(self, reason: MiddlewareSessionEndReason) {
        let _ = tokio::time::timeout(SESSION_END_TIMEOUT, self.end_inner(reason)).await;
    }

    async fn end_inner(self, reason: MiddlewareSessionEndReason) {
        let Self {
            sender,
            mut responses,
        } = self;
        let end = HttpResponseEvent {
            event: Some(http_response_event::Event::SessionEnd(
                MiddlewareSessionEnd {
                    reason: reason as i32,
                    protocol_error: None,
                },
            )),
        };
        if sender.send(end).await.is_err() {
            return;
        }
        // Keep the response stream alive while half-closing the request side.
        // Dropping both handles together schedules an HTTP/2 CANCEL and can
        // discard the terminal event before remote middleware receives it.
        drop(sender);
        while responses.next().await.is_some() {}
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

/// Replace service-provided diagnostic text from operator services with
/// platform-owned values, as 0.1.x did. Built-in diagnostics are kept.
fn normalize_diagnostics(
    entry: &DescribedChainEntry,
    findings: &mut [Finding],
    metadata: &mut HashMap<String, String>,
) {
    if entry
        .service
        .as_ref()
        .is_some_and(|service| service.diagnostic_policy == MiddlewareDiagnosticPolicy::Normalize)
    {
        metadata.clear();
        for finding in findings {
            finding.r#type = format!("{}.finding", entry.entry.implementation);
            finding.label = crate::EXTERNAL_FINDING_LABEL.to_string();
            finding.confidence.clear();
            finding.severity = "medium".into();
        }
    }
}
