// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Legacy HTTP request protocol (0.1). Removed in 0.2.0.
//!
//! [`LegacyRequestStage`] presents one legacy `EvaluateHttpRequest`
//! middleware as a version 2 BUFFERED request stage:
//!
//! - It answers preflight itself with `Inspect{Buffered}` at the offered
//!   buffering limit, which the pipeline sets to the largest legacy limit in
//!   the chain ([`legacy_request_collection_limit`]). A declared body over
//!   that limit was never buffered by 0.1.x, so the stage is skipped or fails
//!   at preflight according to `on_error`. The pipeline must offer BUFFERED,
//!   with late header mutations, to every legacy request stage, including for
//!   a bodyless request: 0.1.x called every stage with the body, even an
//!   empty one.
//! - It makes one unary call with the `Begin` head and the buffered body,
//!   applying the 0.1.x per-stage checks to the body it actually receives:
//!   a body over the stage's own limit is skipped or fails like 0.1.x.
//! - `ALLOW` becomes `HttpBufferedResult`, with header mutations as late
//!   mutations, and `DENY` becomes `HttpReject`.

use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::time::Instant;

use openshell_core::proto::{
    Decision, HttpBegin, HttpBodyMode, HttpBufferedBody, HttpBufferedMode, HttpBufferedResult,
    HttpContinue, HttpEvent, HttpHeader, HttpInspect, HttpPreflight, HttpPreflightResult,
    HttpReject, HttpRequestPreflightHead, HttpUnchanged, SupervisorMiddlewareOperation,
    http_buffered_result, http_event, http_inspect, http_preflight, http_preflight_result,
    http_result,
};

use super::codec::{
    LegacyStageFailure, Results, diagnostics, event_order_failure, invariant_failure, next_event,
    spawn_stage,
};
use super::hooks::LegacyChainClock;
use crate::{
    ContractFailureKind, DescribedChainEntry, HttpProtocol, HttpRequestView, HttpResultStream,
    HttpStageTransport, MiddlewareServiceState, OnError, PRE_CREDENTIALS_PHASE, StageReport,
    StageReportSink, call_with_timeout, headers, validate_request_view, validate_response_envelope,
};

/// Per-exchange inputs of a legacy request stage.
#[derive(Clone)]
pub struct LegacyRequestExchange {
    /// Receives this exchange's [`StageReport::LegacyFailOpen`] reports.
    pub reports: Arc<dyn StageReportSink>,
    /// Lowercased names nominated by the request's `Connection` headers.
    /// Mutations may not touch them, as in 0.1.x.
    pub connection_nominated_headers: Arc<[String]>,
    /// The exchange's 0.1.x chain deadline, shared by its legacy stages.
    /// 0.1.x started it once the body was buffered, so the first body
    /// evaluation starts it and a slow upload never counts against it. A
    /// stage evaluated after it expires fails with `middleware_chain_timeout`,
    /// and each call is capped by it.
    pub chain_clock: LegacyChainClock,
}

/// Largest payload limit among resolved legacy request entries: the most
/// 0.1.x buffered for a chain. The pipeline offers it to every legacy request
/// stage as `max_buffered_body_bytes`, denies a body that outgrows it before
/// contacting the upstream, and passes a declared body over it through only
/// when every entry is `fail_open`. `None` when no legacy request entry
/// resolved.
#[must_use]
pub fn legacy_request_collection_limit(entries: &[DescribedChainEntry]) -> Option<usize> {
    entries
        .iter()
        .filter(|entry| is_legacy_request(entry))
        .map(DescribedChainEntry::max_payload_bytes)
        .max()
}

fn is_legacy_request(entry: &DescribedChainEntry) -> bool {
    entry.http_protocol() == Some(HttpProtocol::Legacy)
        && entry.binding.as_ref().is_some_and(|binding| {
            binding.operation == SupervisorMiddlewareOperation::HttpRequest as i32
        })
}

/// HTTP protocol 1 (0.1). Removed in 0.2.0.
///
/// One legacy `EvaluateHttpRequest` stage presented as a version 2 BUFFERED
/// request stage.
#[derive(Clone)]
pub struct LegacyRequestStage {
    entry: DescribedChainEntry,
    service: Arc<MiddlewareServiceState>,
    exchange: LegacyRequestExchange,
}

impl LegacyRequestStage {
    /// Adapter for a resolved legacy `HTTP_REQUEST` entry, or `None` for any
    /// other entry.
    #[must_use]
    pub fn new(entry: &DescribedChainEntry, exchange: LegacyRequestExchange) -> Option<Self> {
        if !is_legacy_request(entry) {
            return None;
        }
        Some(Self {
            service: Arc::clone(entry.service.as_ref()?),
            entry: entry.clone(),
            exchange,
        })
    }
}

#[tonic::async_trait]
impl HttpStageTransport for LegacyRequestStage {
    async fn open(
        &self,
        events: mpsc::Receiver<HttpEvent>,
    ) -> Result<HttpResultStream, tonic::Status> {
        let stage = self.clone();
        Ok(spawn_stage(move |results| stage.run(events, results)))
    }
}

/// How one evaluation ended before the stage's `on_error` applies.
enum Evaluation {
    Result(http_result::Result),
    /// A 0.1.x failure, handled by `on_error`.
    Failed(String),
    /// A contract or invariant failure, passed to the pipeline unchanged. The
    /// stage fails closed whatever `on_error` says.
    Abort(tonic::Status),
}

impl LegacyRequestStage {
    async fn run(self, mut events: mpsc::Receiver<HttpEvent>, results: Results) {
        let Some(http_event::Event::Preflight(preflight)) = next_event(&mut events).await else {
            results.fail(event_order_failure()).await;
            return;
        };
        let Some(http_preflight::Head::Request(head)) = preflight.head.clone() else {
            results.fail(event_order_failure()).await;
            return;
        };
        let Some(max_body_bytes) = buffered_offer(&preflight) else {
            results
                .fail(invariant_failure("legacy_stage_offer_invalid"))
                .await;
            return;
        };
        if !preflight
            .late_header_modes
            .contains(&(HttpBodyMode::Buffered as i32))
        {
            results
                .fail(invariant_failure("legacy_stage_late_mutations_not_offered"))
                .await;
            return;
        }
        if preflight
            .declared_input_bytes
            .is_some_and(|declared| declared > max_body_bytes)
        {
            // 0.1.x never buffered a declared body over the chain's largest
            // limit. The stage cannot see it, like a stage whose own limit
            // the body exceeds.
            self.on_error("request_body_over_capacity", &results, || {
                http_result::Result::PreflightResult(HttpPreflightResult {
                    decision: Some(http_preflight_result::Decision::ContinueWithoutBody(
                        HttpContinue {},
                    )),
                    ..Default::default()
                })
            })
            .await;
            return;
        }
        let inspect = http_result::Result::PreflightResult(HttpPreflightResult {
            decision: Some(http_preflight_result::Decision::Inspect(HttpInspect {
                mode: Some(http_inspect::Mode::Buffered(HttpBufferedMode {
                    max_body_bytes,
                })),
            })),
            ..Default::default()
        });
        if !results.send(inspect).await {
            return;
        }

        let mut begin_headers = None;
        loop {
            match next_event(&mut events).await {
                Some(http_event::Event::Begin(HttpBegin { headers }))
                    if begin_headers.is_none() =>
                {
                    begin_headers = Some(headers);
                }
                Some(http_event::Event::BufferedBody(HttpBufferedBody { data, .. })) => {
                    let headers = begin_headers.unwrap_or_else(|| head.headers.clone());
                    let Some(evaluation) = results
                        .unless_closed(self.evaluate(&head, headers, data))
                        .await
                    else {
                        return;
                    };
                    match evaluation {
                        Evaluation::Result(result) => {
                            results.send(result).await;
                        }
                        Evaluation::Failed(reason) => {
                            self.on_error(&reason, &results, || {
                                http_result::Result::BufferedResult(HttpBufferedResult {
                                    body: Some(http_buffered_result::Body::Unchanged(
                                        HttpUnchanged {},
                                    )),
                                    ..Default::default()
                                })
                            })
                            .await;
                        }
                        Evaluation::Abort(status) => results.fail(status).await,
                    }
                    return;
                }
                Some(http_event::Event::SessionEnd(_)) | None => return,
                Some(_) => {
                    results.fail(event_order_failure()).await;
                    return;
                }
            }
        }
    }

    /// Apply 0.1.x `on_error` to a failure: `fail_open` reports it and passes
    /// the input on with `pass_on`, and `fail_closed` ends the stage.
    async fn on_error(
        &self,
        reason: &str,
        results: &Results,
        pass_on: impl FnOnce() -> http_result::Result,
    ) {
        match self.entry.on_error() {
            OnError::FailOpen => {
                self.exchange.reports.report(
                    &self.entry.entry.name,
                    StageReport::LegacyFailOpen {
                        reason: reason.to_string(),
                    },
                );
                results.send(pass_on()).await;
            }
            OnError::FailClosed => {
                results
                    .fail(LegacyStageFailure::new(reason).into_status())
                    .await;
            }
        }
    }

    /// One 0.1.x evaluation of the buffered request, in the order the 0.1.x
    /// chain checked it.
    async fn evaluate(
        &self,
        head: &HttpRequestPreflightHead,
        headers: Vec<HttpHeader>,
        body: Vec<u8>,
    ) -> Evaluation {
        let entry = &self.entry;
        let chain_deadline = self.exchange.chain_clock.deadline();
        if body.len() > entry.max_payload_bytes {
            return Evaluation::Failed("request_body_over_capacity".into());
        }
        let context = head.context.clone().unwrap_or_default();
        let target = head.target.clone().unwrap_or_default();
        let request = HttpRequestView::new(
            PRE_CREDENTIALS_PHASE,
            &context,
            &entry.entry.config,
            &target,
            &headers,
            &body,
            &entry.entry.implementation,
        );
        if let Err(reason) = validate_request_view(request) {
            return Evaluation::Failed(reason.into());
        }
        let remaining = chain_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Evaluation::Failed("middleware_chain_timeout".into());
        }
        let timeout = entry.timeout.min(remaining);
        let policy = self.service.diagnostic_policy;
        let mut result = match call_with_timeout(
            timeout,
            "EvaluateHttpRequest",
            self.service.service.evaluate_http_request(request),
        )
        .await
        {
            Ok(result) => result.into_inner(),
            Err(status) if ContractFailureKind::from_status(&status).is_some() => {
                return Evaluation::Abort(status);
            }
            Err(status) if status.code() == tonic::Code::DeadlineExceeded => {
                return Evaluation::Failed("middleware_timeout".into());
            }
            Err(status) => return Evaluation::Failed(policy.error_reason(&status)),
        };
        if let Err(reason) = validate_response_envelope(&result) {
            return Evaluation::Failed(reason.into());
        }
        policy.process_result(&entry.entry.implementation, &mut result);
        let diagnostics = diagnostics(
            std::mem::take(&mut result.reason_code),
            std::mem::take(&mut result.findings),
            std::mem::take(&mut result.metadata),
        );
        match Decision::try_from(result.decision) {
            Ok(Decision::Allow) => {}
            Ok(Decision::Deny) => {
                return Evaluation::Result(http_result::Result::Reject(HttpReject { diagnostics }));
            }
            Ok(Decision::Unspecified) | Err(_) => {
                return Evaluation::Failed("invalid_response_decision".into());
            }
        }
        if result.has_body && result.body.len() > entry.max_payload_bytes {
            return Evaluation::Failed("response_body_over_capacity".into());
        }
        if !result.header_mutations.is_empty()
            && let Err(error) = headers::apply(
                headers::HeaderAuthority::Request,
                &headers,
                &self.exchange.connection_nominated_headers,
                &result.header_mutations,
            )
        {
            return Evaluation::Failed(policy.header_mutation_error_reason(&error));
        }
        Evaluation::Result(http_result::Result::BufferedResult(HttpBufferedResult {
            body: Some(if result.has_body {
                http_buffered_result::Body::Replacement(result.body)
            } else {
                http_buffered_result::Body::Unchanged(HttpUnchanged {})
            }),
            header_mutations: result.header_mutations,
            trailer_mutations: Vec::new(),
            diagnostics,
        }))
    }
}

/// The offered buffering limit, or `None` when the pipeline did not offer
/// BUFFERED with a limit.
fn buffered_offer(preflight: &HttpPreflight) -> Option<u64> {
    if !preflight
        .permitted_body_modes
        .contains(&(HttpBodyMode::Buffered as i32))
    {
        return None;
    }
    preflight
        .limits
        .as_ref()
        .map(|limits| limits.max_buffered_body_bytes)
        .filter(|limit| *limit > 0)
}
