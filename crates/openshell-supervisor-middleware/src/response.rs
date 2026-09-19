// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP response pre-return middleware execution.
//!
//! Request and response hooks use the same wire protocol. The first rollout
//! intentionally offers BUFFERED only for responses; STREAM remains in the
//! shared schema but is not advertised until the response relay can preserve
//! its independent input/output guarantees end to end.

use std::collections::BTreeMap;
use std::time::Duration;

use futures::StreamExt as _;
use prost::Message as _;
use tokio::sync::mpsc;
use tokio::time::Instant;

use openshell_core::proto::{
    HttpBegin, HttpBodyLimits, HttpBodyMode, HttpBufferedBody, HttpEvent, HttpHeader,
    HttpPreflight, HttpRequestTarget, HttpResponsePreflightHead, HttpResult, HttpUnchanged,
    MiddlewareDiagnostics, MiddlewareSessionEnd, MiddlewareSessionEndReason, RequestContext,
    http_buffered_result, http_event, http_inspect, http_preflight, http_preflight_result,
    http_result,
};

use super::{
    ChainEntry, ChainRunner, DescribedChainEntry, EXTERNAL_FINDING_LABEL,
    MAX_MIDDLEWARE_CONTEXT_BYTES, MAX_MIDDLEWARE_FINDING_BYTES, MAX_MIDDLEWARE_FINDINGS_PER_STAGE,
    MAX_MIDDLEWARE_HEADER_BYTES, MAX_MIDDLEWARE_HEADERS, MAX_MIDDLEWARE_METADATA_BYTES,
    MAX_MIDDLEWARE_METADATA_ENTRIES, MAX_MIDDLEWARE_REASON_BYTES, MAX_MIDDLEWARE_REASON_CODE_BYTES,
    MAX_MIDDLEWARE_TARGET_BYTES, MiddlewareDiagnosticPolicy, MiddlewareSessionAdmission,
    MiddlewareSessionPermit, NamespacedFinding, OnError, headers, is_stable_reason_code,
    middleware_denial_reason,
};

const STREAM_CHANNEL_CAPACITY: usize = 4;
const SESSION_END_TIMEOUT: Duration = Duration::from_millis(10);
pub const MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES: usize = 64 * 1024;
pub const MAX_HTTP_RESPONSE_RETAINED_BODY_BYTES: usize = 8 * 1024 * 1024;

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
    pub declared_body_length: Option<u64>,
    pub headers: Vec<HttpHeader>,
    pub connection_nominated_headers: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpResponseInvocationOutcome {
    BlockDelivery,
    HeadersOnly,
    WholeBody,
    PassThrough,
    Transform,
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
    pub diagnostics: Box<HttpResponseDiagnostics>,
}

impl std::fmt::Display for HttpResponseMiddlewareFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl std::error::Error for HttpResponseMiddlewareFailure {}

#[derive(Debug)]
pub struct HttpResponseFinish {
    pub body_units: Vec<Vec<u8>>,
    pub trailers: Vec<HttpHeader>,
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
    sender: mpsc::Sender<HttpEvent>,
    responses: super::HttpResultStream,
    terminal_sent: bool,
}

impl HttpResponseStageTransport {
    async fn end(&mut self, reason: MiddlewareSessionEndReason) {
        if self.terminal_sent {
            return;
        }
        self.terminal_sent = true;
        let _ = tokio::time::timeout(
            SESSION_END_TIMEOUT,
            self.sender.send(HttpEvent {
                event: Some(http_event::Event::SessionEnd(MiddlewareSessionEnd {
                    reason: reason as i32,
                    protocol_error: None,
                })),
            }),
        )
        .await;
    }
}

impl Drop for HttpResponseStageTransport {
    fn drop(&mut self) {
        if !self.terminal_sent {
            let _ = self.sender.try_send(HttpEvent {
                event: Some(http_event::Event::SessionEnd(MiddlewareSessionEnd {
                    reason: MiddlewareSessionEndReason::Cancellation as i32,
                    protocol_error: None,
                })),
            });
        }
    }
}

struct HttpResponseStage {
    entry: DescribedChainEntry,
    transport: HttpResponseStageTransport,
    max_body_bytes: usize,
    connection_nominated_headers: Vec<String>,
}

pub struct HttpResponseSession {
    stages: Vec<HttpResponseStage>,
    body: Vec<u8>,
    findings: Vec<NamespacedFinding>,
    metadata: BTreeMap<String, BTreeMap<String, String>>,
    invocations: Vec<HttpResponseInvocation>,
    session_admission: Option<MiddlewareSessionPermit>,
    body_transformed: bool,
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
        !self.stages.is_empty()
    }

    #[must_use]
    pub fn stream_unit_limit(&self) -> usize {
        MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES
    }

    pub fn start_whole_body_deadline(&mut self, timeout: Duration) {
        self.whole_body_deadline = Some(Instant::now() + timeout);
    }

    #[must_use]
    pub fn whole_body_deadline(&self) -> Option<Instant> {
        self.whole_body_deadline
    }

    pub async fn expire_whole_body_deadline(
        &mut self,
    ) -> Result<Vec<Vec<u8>>, HttpResponseMiddlewareFailure> {
        self.end_all(MiddlewareSessionEndReason::MiddlewareFailure)
            .await;
        Err(self.failure("middleware_timeout", None))
    }

    pub fn push_body(
        &mut self,
        data: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, HttpResponseMiddlewareFailure> {
        if data.is_empty() || data.len() > MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES {
            return Err(self.failure("response_body_unit_invalid", None));
        }
        let limit = self
            .stages
            .iter()
            .map(|stage| stage.max_body_bytes)
            .min()
            .unwrap_or(MAX_HTTP_RESPONSE_RETAINED_BODY_BYTES)
            .min(MAX_HTTP_RESPONSE_RETAINED_BODY_BYTES);
        if self.body.len().saturating_add(data.len()) > limit {
            return Err(self.failure("buffered_input_over_capacity", None));
        }
        self.body.extend_from_slice(&data);
        Ok(Vec::new())
    }

    pub async fn finish(
        self,
        trailers: Vec<HttpHeader>,
    ) -> Result<HttpResponseFinish, HttpResponseMiddlewareFailure> {
        let deadline = self.whole_body_deadline;
        let finish = self.finish_inner(trailers);
        if let Some(deadline) = deadline {
            return tokio::time::timeout_at(deadline, finish)
                .await
                .unwrap_or_else(|_| Err(response_failure("middleware_timeout", None)));
        }
        finish.await
    }

    async fn finish_inner(
        mut self,
        mut trailers: Vec<HttpHeader>,
    ) -> Result<HttpResponseFinish, HttpResponseMiddlewareFailure> {
        let mut body = std::mem::take(&mut self.body);
        for index in 0..self.stages.len() {
            let stage = &mut self.stages[index];
            send_event(
                &stage.entry,
                &stage.transport.sender,
                HttpEvent {
                    event: Some(http_event::Event::Begin(HttpBegin {})),
                },
            )
            .await?;
            let input_size = body.len();
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
                    let diagnostics = validate_diagnostics(reject.diagnostics.as_ref())?;
                    let denial = super::MiddlewareDenial {
                        config_name: stage.entry.entry.name.clone(),
                        reason_code: nonempty(&diagnostics.reason_code),
                    };
                    return Err(self.failure(
                        &middleware_denial_reason(
                            &denial.config_name,
                            denial.reason_code.as_deref(),
                        ),
                        Some(denial),
                    ));
                }
                _ => return Err(self.failure("buffered_result_expected", None)),
            };
            if !buffered.header_mutations.is_empty() {
                return Err(self.failure("late_header_mutations_not_permitted", None));
            }
            let diagnostics = validate_diagnostics(buffered.diagnostics.as_ref())?;
            trailers = headers::apply(
                headers::HeaderAuthority::ResponseTrailers,
                &trailers,
                &stage.connection_nominated_headers,
                &buffered.trailer_mutations,
            )
            .map_err(|error| {
                let policy = stage
                    .entry
                    .service
                    .as_ref()
                    .map_or(MiddlewareDiagnosticPolicy::Preserve, |service| {
                        service.diagnostic_policy
                    });
                response_failure(&policy.header_mutation_error_reason(&error), None)
            })?;
            let (next_body, outcome, transformed) = match buffered.body {
                Some(http_buffered_result::Body::Unchanged(HttpUnchanged {})) => {
                    (body, HttpResponseInvocationOutcome::PassThrough, false)
                }
                Some(http_buffered_result::Body::Replacement(replacement)) => {
                    if replacement.len() > stage.max_body_bytes {
                        return Err(self.failure("buffered_output_over_capacity", None));
                    }
                    (replacement, HttpResponseInvocationOutcome::Transform, true)
                }
                None => return Err(self.failure("buffered_body_result_missing", None)),
            };
            collect_diagnostics(
                &stage.entry,
                &diagnostics,
                &mut self.findings,
                &mut self.metadata,
            );
            self.invocations.push(invocation(
                &stage.entry,
                outcome,
                input_size,
                Some(next_body.len()),
                nonempty(&diagnostics.reason_code),
            ));
            self.body_transformed |= transformed;
            body = next_body;
            stage
                .transport
                .end(MiddlewareSessionEndReason::Normal)
                .await;
        }
        self.session_admission.take();
        let body_units = body
            .chunks(MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES)
            .map(<[u8]>::to_vec)
            .collect();
        Ok(HttpResponseFinish {
            body_units,
            trailers,
            strip_stale_integrity_headers: self.body_transformed,
            findings: self.findings,
            metadata: self.metadata,
            invocations: self.invocations,
        })
    }

    pub async fn finish_to(
        self,
        trailers: Vec<HttpHeader>,
        output: mpsc::Sender<Vec<u8>>,
    ) -> Result<HttpResponseFinish, HttpResponseMiddlewareFailure> {
        let mut finish = self.finish(trailers).await?;
        for unit in std::mem::take(&mut finish.body_units) {
            output
                .send(unit)
                .await
                .map_err(|_| response_failure("response_output_closed", None))?;
        }
        Ok(finish)
    }

    pub async fn end(mut self, reason: MiddlewareSessionEndReason) {
        self.end_all(reason).await;
    }

    async fn end_all(&mut self, reason: MiddlewareSessionEndReason) {
        for stage in &mut self.stages {
            stage.transport.end(reason).await;
        }
        self.session_admission.take();
    }

    fn failure(
        &mut self,
        reason: &str,
        denial: Option<super::MiddlewareDenial>,
    ) -> HttpResponseMiddlewareFailure {
        HttpResponseMiddlewareFailure {
            reason: reason.to_string(),
            denial,
            diagnostics: Box::new(self.take_diagnostics()),
        }
    }
}

impl ChainRunner {
    pub fn http_response_input_unrepresentable(
        &self,
        entries: &[DescribedChainEntry],
    ) -> HttpResponsePreflightOutcome {
        failed_preflight(
            entries,
            Vec::new(),
            "middleware_failed: response_input_unrepresentable",
        )
    }

    pub async fn preflight_http_response(
        &self,
        entries: &[ChainEntry],
        input: HttpResponsePreflightInput,
    ) -> miette::Result<HttpResponsePreflightOutcome> {
        let described = self.describe_http_response_chain(entries).await?;
        self.preflight_described_http_response(described, input)
            .await
    }

    pub async fn preflight_described_http_response(
        &self,
        described: Vec<DescribedChainEntry>,
        input: HttpResponsePreflightInput,
    ) -> miette::Result<HttpResponsePreflightOutcome> {
        if described.is_empty() {
            return Ok(empty_preflight(input.headers));
        }
        if validate_preflight_input(&input).is_err() {
            return Ok(failed_preflight(
                &described,
                input.headers,
                "middleware_failed: response_input_over_capacity",
            ));
        }
        let admission = match self.try_reserve_middleware_session() {
            MiddlewareSessionAdmission::Admitted(admission) => admission,
            MiddlewareSessionAdmission::AtCapacity => {
                let mut outcome = failed_preflight(
                    &described,
                    input.headers,
                    "middleware_failed: middleware_session_capacity_exhausted",
                );
                outcome.session_capacity_exhausted = true;
                return Ok(outcome);
            }
        };
        let mut headers = input.headers.clone();
        let mut stages = Vec::new();
        let mut findings = Vec::new();
        let mut metadata = BTreeMap::new();
        let mut invocations = Vec::new();

        for entry in described {
            if entry.on_error() == OnError::FailOpen {
                end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure).await;
                invocations.push(failed_invocation(&entry, "http_fail_open_unsupported"));
                return Ok(HttpResponsePreflightOutcome {
                    allowed: false,
                    reason: "middleware_failed: HTTP middleware no longer supports on_error=fail_open; use fail_closed or remove on_error".into(),
                    denial: None,
                    headers,
                    session: None,
                    findings,
                    metadata,
                    invocations,
                    session_capacity_exhausted: false,
                });
            }
            let Some(service) = entry.service.as_ref() else {
                end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure).await;
                invocations.push(failed_invocation(&entry, "binding_not_described"));
                return Ok(HttpResponsePreflightOutcome {
                    allowed: false,
                    reason: "middleware_failed: binding_not_described".into(),
                    denial: None,
                    headers,
                    session: None,
                    findings,
                    metadata,
                    invocations,
                    session_capacity_exhausted: false,
                });
            };
            let supports_buffered = entry.binding.as_ref().is_some_and(|binding| {
                binding
                    .supported_http_body_modes
                    .contains(&(HttpBodyMode::Buffered as i32))
            });
            let permitted = if supports_buffered
                && body_restriction(&input).is_none()
                && input
                    .declared_body_length
                    .is_none_or(|length| length <= entry.max_payload_bytes() as u64)
            {
                vec![HttpBodyMode::Buffered as i32]
            } else {
                Vec::new()
            };
            let (sender, receiver) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
            let preflight = HttpPreflight {
                head: Some(http_preflight::Head::Response(HttpResponsePreflightHead {
                    context: Some(input.context.clone()),
                    target: Some(input.target.clone()),
                    status_code: u32::from(input.status_code),
                    headers: headers.clone(),
                    middleware_name: entry.entry.implementation.clone(),
                    config: Some(entry.entry.config.clone()),
                })),
                permitted_body_modes: permitted.clone(),
                late_header_modes: Vec::new(),
                limits: Some(body_limits(&entry)),
                declared_input_bytes: input.declared_body_length,
            };
            let opened = tokio::time::timeout(entry.timeout(), async {
                sender
                    .send(HttpEvent {
                        event: Some(http_event::Event::Preflight(preflight)),
                    })
                    .await
                    .map_err(|_| tonic::Status::unavailable("middleware request stream closed"))?;
                let mut responses = service
                    .service
                    .open_http_response_pre_return(receiver)
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
                    end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure).await;
                    let reason = service.diagnostic_policy.error_reason(&error);
                    invocations.push(failed_invocation(&entry, &reason));
                    return Ok(failed_outcome(
                        headers,
                        findings,
                        metadata,
                        invocations,
                        &reason,
                    ));
                }
                Err(_) => {
                    end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure).await;
                    invocations.push(failed_invocation(&entry, "middleware_timeout"));
                    return Ok(failed_outcome(
                        headers,
                        findings,
                        metadata,
                        invocations,
                        "middleware_timeout",
                    ));
                }
            };
            let mut stage = HttpResponseStage {
                entry: entry.clone(),
                transport: HttpResponseStageTransport {
                    sender,
                    responses,
                    terminal_sent: false,
                },
                max_body_bytes: entry.max_payload_bytes(),
                connection_nominated_headers: input.connection_nominated_headers.clone(),
            };
            match result.result {
                Some(http_result::Result::PreflightResult(result)) => {
                    let diagnostics = match validate_diagnostics(result.diagnostics.as_ref()) {
                        Ok(value) => value,
                        Err(error) => {
                            stage
                                .transport
                                .end(MiddlewareSessionEndReason::MiddlewareFailure)
                                .await;
                            end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure)
                                .await;
                            invocations.push(failed_invocation(&entry, &error.reason));
                            return Ok(failed_outcome(
                                headers,
                                findings,
                                metadata,
                                invocations,
                                &error.reason,
                            ));
                        }
                    };
                    headers = match headers::apply(
                        headers::HeaderAuthority::Response,
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
                            return Ok(failed_outcome(
                                headers,
                                findings,
                                metadata,
                                invocations,
                                &reason,
                            ));
                        }
                    };
                    collect_diagnostics(&entry, &diagnostics, &mut findings, &mut metadata);
                    match result.decision {
                        Some(http_preflight_result::Decision::ContinueWithoutBody(_)) => {
                            invocations.push(invocation(
                                &entry,
                                HttpResponseInvocationOutcome::HeadersOnly,
                                0,
                                None,
                                nonempty(&diagnostics.reason_code),
                            ));
                            stage
                                .transport
                                .end(MiddlewareSessionEndReason::StageSkipped)
                                .await;
                        }
                        Some(http_preflight_result::Decision::Inspect(inspect)) => {
                            let max_body_bytes = match inspect.mode {
                                Some(http_inspect::Mode::Buffered(mode))
                                    if permitted.contains(&(HttpBodyMode::Buffered as i32))
                                        && mode.max_body_bytes > 0
                                        && mode.max_body_bytes
                                            <= entry.max_payload_bytes() as u64 =>
                                {
                                    usize::try_from(mode.max_body_bytes)
                                        .expect("validated response body limit fits usize")
                                }
                                _ => {
                                    stage
                                        .transport
                                        .end(MiddlewareSessionEndReason::MiddlewareFailure)
                                        .await;
                                    end_stages(
                                        &mut stages,
                                        MiddlewareSessionEndReason::MiddlewareFailure,
                                    )
                                    .await;
                                    invocations.push(failed_invocation(
                                        &entry,
                                        "response_body_mode_not_permitted",
                                    ));
                                    return Ok(failed_outcome(
                                        headers,
                                        findings,
                                        metadata,
                                        invocations,
                                        "response_body_mode_not_permitted",
                                    ));
                                }
                            };
                            stage.max_body_bytes = max_body_bytes;
                            invocations.push(invocation(
                                &entry,
                                HttpResponseInvocationOutcome::WholeBody,
                                0,
                                None,
                                nonempty(&diagnostics.reason_code),
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
                            return Ok(failed_outcome(
                                headers,
                                findings,
                                metadata,
                                invocations,
                                "preflight_decision_missing",
                            ));
                        }
                    }
                }
                Some(http_result::Result::Reject(reject)) => {
                    let diagnostics = match validate_diagnostics(reject.diagnostics.as_ref()) {
                        Ok(value) => value,
                        Err(error) => {
                            stage
                                .transport
                                .end(MiddlewareSessionEndReason::MiddlewareFailure)
                                .await;
                            end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure)
                                .await;
                            invocations.push(failed_invocation(&entry, &error.reason));
                            return Ok(failed_outcome(
                                headers,
                                findings,
                                metadata,
                                invocations,
                                &error.reason,
                            ));
                        }
                    };
                    collect_diagnostics(&entry, &diagnostics, &mut findings, &mut metadata);
                    let denial = super::MiddlewareDenial {
                        config_name: entry.entry.name.clone(),
                        reason_code: nonempty(&diagnostics.reason_code),
                    };
                    stage
                        .transport
                        .end(MiddlewareSessionEndReason::MiddlewareDenial)
                        .await;
                    end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareDenial).await;
                    invocations.push(invocation(
                        &entry,
                        HttpResponseInvocationOutcome::BlockDelivery,
                        0,
                        None,
                        denial.reason_code.clone(),
                    ));
                    return Ok(HttpResponsePreflightOutcome {
                        allowed: false,
                        reason: middleware_denial_reason(
                            &denial.config_name,
                            denial.reason_code.as_deref(),
                        ),
                        denial: Some(denial),
                        headers,
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
                    return Ok(failed_outcome(
                        headers,
                        findings,
                        metadata,
                        invocations,
                        "preflight_result_expected",
                    ));
                }
            }
        }

        let session = (!stages.is_empty()).then(|| HttpResponseSession {
            stages,
            body: Vec::new(),
            findings: Vec::new(),
            metadata: BTreeMap::new(),
            invocations: Vec::new(),
            session_admission: Some(admission),
            body_transformed: false,
            whole_body_deadline: None,
        });
        Ok(HttpResponsePreflightOutcome {
            allowed: true,
            reason: String::new(),
            denial: None,
            headers,
            session,
            findings,
            metadata,
            invocations,
            session_capacity_exhausted: false,
        })
    }
}

async fn send_event(
    entry: &DescribedChainEntry,
    sender: &mpsc::Sender<HttpEvent>,
    event: HttpEvent,
) -> Result<(), HttpResponseMiddlewareFailure> {
    tokio::time::timeout(entry.timeout(), sender.send(event))
        .await
        .map_err(|_| response_failure("middleware_timeout", None))?
        .map_err(|_| response_failure("middleware_stream_closed", None))
}

async fn exchange(
    stage: &mut HttpResponseStage,
    event: HttpEvent,
) -> Result<HttpResult, HttpResponseMiddlewareFailure> {
    tokio::time::timeout(stage.entry.timeout(), stage.transport.sender.send(event))
        .await
        .map_err(|_| response_failure("middleware_timeout", None))?
        .map_err(|_| response_failure("middleware_stream_closed", None))?;
    let policy = stage
        .entry
        .service
        .as_ref()
        .map_or(MiddlewareDiagnosticPolicy::Preserve, |service| {
            service.diagnostic_policy
        });
    match tokio::time::timeout(stage.entry.timeout(), stage.transport.responses.next()).await {
        Ok(Some(Ok(result))) => Ok(result),
        Ok(Some(Err(error))) => Err(response_failure(&policy.error_reason(&error), None)),
        Ok(None) => Err(response_failure("middleware_result_stream_closed", None)),
        Err(_) => Err(response_failure("middleware_timeout", None)),
    }
}

async fn end_stages(stages: &mut [HttpResponseStage], reason: MiddlewareSessionEndReason) {
    for stage in stages {
        stage.transport.end(reason).await;
    }
}

fn body_limits(entry: &DescribedChainEntry) -> HttpBodyLimits {
    let max_chunk = entry
        .max_payload_bytes()
        .min(MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES) as u64;
    HttpBodyLimits {
        max_chunk_bytes: max_chunk,
        max_buffered_body_bytes: entry.max_payload_bytes() as u64,
        max_input_queue_bytes: max_chunk.saturating_mul(STREAM_CHANNEL_CAPACITY as u64),
        max_input_queue_messages: STREAM_CHANNEL_CAPACITY as u64,
        max_output_queue_bytes: max_chunk.saturating_mul(STREAM_CHANNEL_CAPACITY as u64),
        max_output_queue_messages: STREAM_CHANNEL_CAPACITY as u64,
        max_total_input_bytes: None,
        max_total_output_bytes: None,
        idle_timeout: Some(prost_types::Duration {
            seconds: i64::try_from(entry.timeout().as_secs()).unwrap_or(i64::MAX),
            nanos: i32::try_from(entry.timeout().subsec_nanos()).expect("nanoseconds fit in i32"),
        }),
        session_timeout: None,
    }
}

fn validate_preflight_input(input: &HttpResponsePreflightInput) -> miette::Result<()> {
    if input.context.encoded_len() > MAX_MIDDLEWARE_CONTEXT_BYTES
        || input.target.encoded_len() > MAX_MIDDLEWARE_TARGET_BYTES
        || input.headers.len() > MAX_MIDDLEWARE_HEADERS
        || input
            .headers
            .iter()
            .map(prost::Message::encoded_len)
            .sum::<usize>()
            > MAX_MIDDLEWARE_HEADER_BYTES
    {
        return Err(miette::miette!("response preflight exceeds platform limit"));
    }
    Ok(())
}

/// Return why middleware may inspect response headers but must not transform
/// the representation body. These restrictions preserve HTTP semantics that
/// cannot be safely reconstructed by the initial BUFFERED-only response path.
fn body_restriction(input: &HttpResponsePreflightInput) -> Option<&'static str> {
    if input.target.method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&input.status_code)
        || matches!(input.status_code, 204 | 304)
    {
        return Some("bodyless_response");
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
        return Some("unsupported_partial_response");
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
        return Some("response_no_transform");
    }
    if input.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("content-encoding")
            && header
                .value
                .split(',')
                .any(|coding| !coding.trim().eq_ignore_ascii_case("identity"))
    }) {
        return Some("unsupported_content_encoding");
    }
    None
}

fn validate_diagnostics(
    diagnostics: Option<&MiddlewareDiagnostics>,
) -> Result<MiddlewareDiagnostics, HttpResponseMiddlewareFailure> {
    let diagnostics = diagnostics.cloned().unwrap_or_default();
    if diagnostics.reason.len() > MAX_MIDDLEWARE_REASON_BYTES
        || (!diagnostics.reason_code.is_empty()
            && (diagnostics.reason_code.len() > MAX_MIDDLEWARE_REASON_CODE_BYTES
                || !is_stable_reason_code(&diagnostics.reason_code)))
        || diagnostics.findings.len() > MAX_MIDDLEWARE_FINDINGS_PER_STAGE
        || diagnostics
            .findings
            .iter()
            .any(|finding| finding.encoded_len() > MAX_MIDDLEWARE_FINDING_BYTES)
        || diagnostics.metadata.len() > MAX_MIDDLEWARE_METADATA_ENTRIES
        || diagnostics
            .metadata
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum::<usize>()
            > MAX_MIDDLEWARE_METADATA_BYTES
    {
        return Err(response_failure("response_diagnostics_invalid", None));
    }
    Ok(diagnostics)
}

fn collect_diagnostics(
    entry: &DescribedChainEntry,
    diagnostics: &MiddlewareDiagnostics,
    findings: &mut Vec<NamespacedFinding>,
    metadata: &mut BTreeMap<String, BTreeMap<String, String>>,
) {
    let normalize = entry
        .service
        .as_ref()
        .is_some_and(|service| service.diagnostic_policy == MiddlewareDiagnosticPolicy::Normalize);
    findings.extend(diagnostics.findings.iter().cloned().map(|mut finding| {
        if normalize {
            finding.r#type = format!("{}.finding", entry.entry.implementation);
            finding.label = EXTERNAL_FINDING_LABEL.to_string();
            finding.confidence.clear();
            finding.severity = "medium".into();
        }
        NamespacedFinding {
            middleware: entry.entry.name.clone(),
            finding,
        }
    }));
    if !normalize && !diagnostics.metadata.is_empty() {
        metadata.insert(
            entry.entry.name.clone(),
            diagnostics.metadata.clone().into_iter().collect(),
        );
    }
}

fn invocation(
    entry: &DescribedChainEntry,
    outcome: HttpResponseInvocationOutcome,
    input_size: usize,
    output_size: Option<usize>,
    reason_code: Option<String>,
) -> HttpResponseInvocation {
    HttpResponseInvocation {
        config_name: entry.entry.name.clone(),
        implementation: entry.entry.implementation.clone(),
        outcome,
        sequence: None,
        input_size,
        output_size,
        failed: false,
        stage_disabled: false,
        reason_code,
        failure_category: None,
    }
}

fn failed_invocation(entry: &DescribedChainEntry, reason: &str) -> HttpResponseInvocation {
    HttpResponseInvocation {
        config_name: entry.entry.name.clone(),
        implementation: entry.entry.implementation.clone(),
        outcome: HttpResponseInvocationOutcome::FailClosed,
        sequence: None,
        input_size: 0,
        output_size: None,
        failed: true,
        stage_disabled: true,
        reason_code: None,
        failure_category: Some(reason.to_string()),
    }
}

fn failed_outcome(
    headers: Vec<HttpHeader>,
    findings: Vec<NamespacedFinding>,
    metadata: BTreeMap<String, BTreeMap<String, String>>,
    invocations: Vec<HttpResponseInvocation>,
    reason: &str,
) -> HttpResponsePreflightOutcome {
    HttpResponsePreflightOutcome {
        allowed: false,
        reason: format!("middleware_failed: {reason}"),
        denial: None,
        headers,
        session: None,
        findings,
        metadata,
        invocations,
        session_capacity_exhausted: false,
    }
}

fn failed_preflight(
    entries: &[DescribedChainEntry],
    headers: Vec<HttpHeader>,
    reason: &str,
) -> HttpResponsePreflightOutcome {
    HttpResponsePreflightOutcome {
        allowed: false,
        reason: reason.to_string(),
        denial: None,
        headers,
        session: None,
        findings: Vec::new(),
        metadata: BTreeMap::new(),
        invocations: entries
            .iter()
            .map(|entry| failed_invocation(entry, reason))
            .collect(),
        session_capacity_exhausted: false,
    }
}

fn empty_preflight(headers: Vec<HttpHeader>) -> HttpResponsePreflightOutcome {
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

fn response_failure(
    reason: &str,
    denial: Option<super::MiddlewareDenial>,
) -> HttpResponseMiddlewareFailure {
    HttpResponseMiddlewareFailure {
        reason: reason.to_string(),
        denial,
        diagnostics: Box::default(),
    }
}

fn nonempty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}
