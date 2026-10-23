// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP session hook request middleware at `PRE_CREDENTIALS`.
//!
//! Initial preflight stops at the first inspecting stage. The returned
//! [`HttpRequestSession`] opens later stages as their input headers become
//! available. A chain whose stages all continue forwards the body untouched.

use std::sync::Arc;

use openshell_core::proto::{
    HeaderMutation, HttpBodyMode, HttpBodyUnavailableReason, HttpHeader, HttpRequestPreflightHead,
    HttpRequestTarget, MiddlewareSessionEndReason, RequestContext,
};
use tokio::sync::mpsc;
use tokio::time::Instant;

use super::pipeline::{
    self, BodyModeOffer, HttpBodyInput, HttpBodyOutput, HttpMiddlewareFailure, HttpPipelineFinish,
    HttpStageDiagnostics, MiddlewareFailureDetail, Pipeline, PipelineSpec, PipelineTimeouts,
    PreflightFields, StageHead, StagePreflight,
};
use super::{has_content_coding, validate_head_input};
use crate::headers::HeaderAuthority;
use crate::{
    ChainRunner, DescribedChainEntry, MAX_MIDDLEWARE_CHAIN_TIMEOUT, MAX_MIDDLEWARE_PAYLOAD_BYTES,
    MiddlewareDenial, TransformedBodyPolicy, ensure_chain_capacity,
};

/// Default largest request body output withheld before upstream contact.
///
/// The supervisor holds this output in memory. A route with its own buffering
/// limit, such as `SigV4` body signing, may withhold up to that limit instead.
pub const MAX_HTTP_REQUEST_WITHHELD_BYTES: usize = MAX_MIDDLEWARE_PAYLOAD_BYTES;

/// Request head and framing offered to request middleware.
#[derive(Debug, Clone)]
pub struct HttpRequestPreflightInput {
    pub context: RequestContext,
    pub target: HttpRequestTarget,
    /// Declared body length; `Some(0)` for a request without a body and
    /// `None` for a chunked body.
    pub declared_body_length: Option<u64>,
    /// Middleware-visible request headers in wire order.
    pub headers: Vec<HttpHeader>,
    /// Lowercased names nominated by the request's `Connection` fields.
    pub connection_nominated_headers: Vec<String>,
    /// Lowercased names of headers whose values carry a credential
    /// placeholder. `headers` omits them, and stages cannot change them.
    pub credential_reference_headers: Vec<String>,
    /// Largest final body output the caller accepts when it withholds the
    /// output until the chain finishes. `None` when output streams to the
    /// upstream. Advertised to STREAM stages as `max_output_body_bytes`.
    pub max_output_body_bytes: Option<u64>,
}

/// Outcome of request preflight across a chain.
pub struct HttpRequestPreflightOutcome {
    pub allowed: bool,
    pub reason: String,
    pub denial: Option<MiddlewareDenial>,
    /// Present when the chain failed closed for a reason the sandbox may see.
    pub failure: Option<MiddlewareFailureDetail>,
    /// Head after the initial preflight prefix.
    pub headers: Vec<HttpHeader>,
    /// Preflight mutations in chain order, to replay on the raw request head.
    pub header_mutations: Vec<HeaderMutation>,
    /// Present when a stage selected a body mode.
    pub session: Option<HttpRequestSession>,
    pub diagnostics: HttpStageDiagnostics,
    /// No HTTP session hook slot freed up within the chain deadline. Platform
    /// load shedding, not a stage failure.
    pub session_capacity_exhausted: bool,
}

/// Request stages, including deferred preflights.
///
/// The session holds its HTTP session hook budget slots while its body
/// stages run.
pub struct HttpRequestSession {
    pipeline: Pipeline,
}

impl HttpRequestSession {
    /// Largest body chunk to feed as input.
    #[must_use]
    pub fn input_unit_limit(&self) -> usize {
        self.pipeline.input_unit_limit()
    }

    /// True when final output is known to be buffered. A chain with deferred
    /// decisions uses incremental delivery because a later stage may stream.
    #[must_use]
    pub fn buffers_final_output(&self) -> bool {
        self.pipeline.buffers_final_output()
    }

    /// True when a stage runs or may later select STREAM. The caller bounds
    /// how long the sandbox may pause its upload.
    #[must_use]
    pub fn may_stream(&self) -> bool {
        self.pipeline.may_stream()
    }

    #[cfg(test)]
    pub fn set_timeouts(&mut self, timeouts: PipelineTimeouts) {
        self.pipeline.set_timeouts(timeouts);
    }

    /// Run the body stages, re-checking every replaced body against
    /// `body_policy` before the next stage or the output sees it. The caller
    /// feeds `input` and drains `output` concurrently with this future, and
    /// commits the upstream head on the output `Start`. Dropping the future
    /// cancels every stage.
    pub async fn run_with_body_policy(
        self,
        input: mpsc::Receiver<HttpBodyInput>,
        output: mpsc::Sender<HttpBodyOutput>,
        body_policy: TransformedBodyPolicy<'_>,
    ) -> Result<HttpPipelineFinish, HttpMiddlewareFailure> {
        self.pipeline
            .run_with_body_policy(input, output, body_policy)
            .await
    }

    /// End every stage without sending the body.
    pub async fn end(self, reason: MiddlewareSessionEndReason) {
        self.pipeline.end(reason).await;
    }
}

struct RequestHead {
    input: HttpRequestPreflightInput,
}

impl StageHead for RequestHead {
    fn context(&self) -> &RequestContext {
        &self.input.context
    }

    fn preflight(&self, headers: &[HttpHeader], fields: PreflightFields) -> StagePreflight {
        fields.request(HttpRequestPreflightHead {
            target: Some(self.input.target.clone()),
            headers: headers.to_vec(),
        })
    }

    fn body_modes(
        &self,
        entry: &DescribedChainEntry,
        headers: &[HttpHeader],
        declared_body_bytes: Option<u64>,
    ) -> BodyModeOffer {
        let limit = entry.max_payload_bytes();
        let mut offer = BodyModeOffer::default();
        if limit == 0 {
            return offer;
        }
        // The original head decides: no stage sees an encoded body, so none
        // can decode it for the next.
        if has_content_coding(headers) {
            offer.withhold(HttpBodyMode::Buffered, HttpBodyUnavailableReason::Encoded);
            offer.withhold(HttpBodyMode::Stream, HttpBodyUnavailableReason::Encoded);
            return offer;
        }
        if declared_body_bytes.is_none_or(|length| length <= limit as u64) {
            offer.permit(HttpBodyMode::Buffered);
        } else {
            offer.withhold(HttpBodyMode::Buffered, HttpBodyUnavailableReason::OverLimit);
        }
        offer.permit(HttpBodyMode::Stream);
        offer
    }

    fn max_output_body_bytes(&self) -> Option<u64> {
        self.input.max_output_body_bytes
    }
}

fn request_spec(input: &HttpRequestPreflightInput) -> PipelineSpec {
    PipelineSpec {
        head_authority: HeaderAuthority::SessionRequest,
        trailer_authority: HeaderAuthority::RequestTrailers,
        connection_nominated: input.connection_nominated_headers.clone(),
        credential_reference_headers: input.credential_reference_headers.clone(),
        timeouts: PipelineTimeouts::default(),
        output_trailers: true,
    }
}

impl ChainRunner {
    /// Prepare a described chain through its first inspecting stage. Returns
    /// an error only for a chain over platform capacity.
    ///
    /// Preflight waits for an HTTP session hook slot within the chain
    /// deadline, and the slot is released once no stage inspects the body.
    pub async fn preflight_described_http_request(
        &self,
        described: Vec<DescribedChainEntry>,
        input: HttpRequestPreflightInput,
    ) -> miette::Result<HttpRequestPreflightOutcome> {
        ensure_chain_capacity(described.len())?;
        if described.is_empty() {
            return Ok(outcome(input.headers, HttpStageDiagnostics::default()));
        }
        if let Err(reason) = validate_head_input(&input.context, &input.target, &input.headers) {
            let failure = pipeline::entry_failure(&described[0], reason);
            return Ok(HttpRequestPreflightOutcome {
                allowed: false,
                reason: failure.reason,
                failure: failure.failure.map(|failure| *failure),
                ..outcome(input.headers, *failure.diagnostics)
            });
        }
        let chain_deadline = Instant::now() + MAX_MIDDLEWARE_CHAIN_TIMEOUT;
        let slot = if described.iter().any(DescribedChainEntry::is_resolved) {
            let Some(slot) = self.reserve_http_session(chain_deadline).await else {
                return Ok(capacity_exhausted(input.headers));
            };
            Some(slot)
        } else {
            None
        };
        let preflight = pipeline::preflight(
            &described,
            request_spec(&input),
            input.headers.clone(),
            input.declared_body_length,
            Arc::new(RequestHead {
                input: input.clone(),
            }),
            chain_deadline,
        )
        .await;
        let session = match preflight.pipeline {
            Some(pipeline) => {
                let slot = slot.expect("a selected stage implies a resolved entry");
                let Some(pipeline) = self.admit_body(pipeline, slot, chain_deadline).await else {
                    return Ok(capacity_exhausted(input.headers));
                };
                Some(HttpRequestSession { pipeline })
            }
            // No stage inspects the body, so the slot is released here.
            None => None,
        };
        Ok(HttpRequestPreflightOutcome {
            allowed: preflight.allowed,
            reason: preflight.reason,
            denial: preflight.denial,
            failure: preflight.failure,
            headers: preflight.headers,
            header_mutations: preflight.header_mutations,
            session,
            diagnostics: preflight.diagnostics,
            session_capacity_exhausted: false,
        })
    }
}

/// No HTTP session hook slot freed up within the chain deadline.
fn capacity_exhausted(headers: Vec<HttpHeader>) -> HttpRequestPreflightOutcome {
    HttpRequestPreflightOutcome {
        allowed: false,
        reason: "middleware_failed: session_capacity_exhausted".into(),
        session_capacity_exhausted: true,
        ..outcome(headers, HttpStageDiagnostics::default())
    }
}

fn outcome(
    headers: Vec<HttpHeader>,
    diagnostics: HttpStageDiagnostics,
) -> HttpRequestPreflightOutcome {
    HttpRequestPreflightOutcome {
        allowed: true,
        reason: String::new(),
        denial: None,
        failure: None,
        headers,
        header_mutations: Vec::new(),
        session: None,
        diagnostics,
        session_capacity_exhausted: false,
    }
}
