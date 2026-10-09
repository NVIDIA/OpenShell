// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP protocol 2 request middleware at `PRE_CREDENTIALS`.
//!
//! Preflight runs before any request body byte is read. A chain whose stages
//! all continue at preflight forwards the body untouched; otherwise the
//! returned [`HttpRequestSession`] runs the body stages.

use openshell_core::proto::{
    HeaderMutation, HttpBodyMode, HttpBodyUnavailableReason, HttpHeader, HttpRequestPreflightHead,
    HttpRequestTarget, MiddlewareSessionEndReason, RequestContext, http_preflight,
};
use tokio::sync::mpsc;

use super::pipeline::{
    self, BodyModeOffer, HttpBodyInput, HttpBodyOutput, HttpDirection, HttpMiddlewareFailure,
    HttpPipelineFinish, HttpStageDiagnostics, Pipeline, PipelineSpec, PipelineTimeouts, StageHead,
};
use super::validate_head_input;
use crate::headers::HeaderAuthority;
use crate::{
    ChainRunner, DescribedChainEntry, MAX_MIDDLEWARE_PAYLOAD_BYTES, MiddlewareDenial,
    MiddlewareSessionAdmission, MiddlewareSessionPermit, TransformedBodyPolicy,
    ensure_chain_capacity,
};

/// Largest request body middleware output the supervisor withholds in memory
/// before it contacts the upstream.
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
}

/// Outcome of request preflight across a chain.
pub struct HttpRequestPreflightOutcome {
    pub allowed: bool,
    pub reason: String,
    pub denial: Option<MiddlewareDenial>,
    /// Head after every preflight mutation.
    pub headers: Vec<HttpHeader>,
    /// Preflight mutations in chain order, to replay on the raw request head.
    pub header_mutations: Vec<HeaderMutation>,
    /// Present when a stage selected a body mode.
    pub session: Option<HttpRequestSession>,
    pub diagnostics: HttpStageDiagnostics,
    /// Every persistent middleware session was in use. Platform load
    /// shedding, not a stage failure.
    pub session_capacity_exhausted: bool,
}

/// Request body stages selected at preflight.
///
/// The session holds one slot of the persistent middleware session budget
/// until it ends.
pub struct HttpRequestSession {
    pipeline: Pipeline,
    _session: MiddlewareSessionPermit,
}

impl HttpRequestSession {
    /// Largest body chunk to feed as input.
    #[must_use]
    pub fn input_unit_limit(&self) -> usize {
        self.pipeline.input_unit_limit()
    }

    /// True when a BUFFERED stage withholds the head until its body result.
    #[must_use]
    pub fn withholds_output(&self) -> bool {
        self.pipeline.withholds_output()
    }

    /// True when a STREAM stage runs. STREAM has no total deadline, so the
    /// caller bounds how long the sandbox may pause its upload.
    #[must_use]
    pub fn streams(&self) -> bool {
        self.pipeline.streams()
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

struct RequestHead<'a> {
    input: &'a HttpRequestPreflightInput,
}

impl StageHead for RequestHead<'_> {
    fn context(&self) -> &RequestContext {
        &self.input.context
    }

    fn preflight_subject(&self, headers: &[HttpHeader]) -> http_preflight::Subject {
        http_preflight::Subject::Request(HttpRequestPreflightHead {
            target: Some(self.input.target.clone()),
            headers: headers.to_vec(),
        })
    }

    fn body_modes(&self, entry: &DescribedChainEntry) -> BodyModeOffer {
        let limit = entry.max_payload_bytes();
        let mut offer = BodyModeOffer::default();
        if limit == 0 {
            return offer;
        }
        if entry.supports_http_body_mode(HttpBodyMode::Buffered) {
            if self
                .input
                .declared_body_length
                .is_none_or(|length| length <= limit as u64)
            {
                offer.permit(HttpBodyMode::Buffered);
            } else {
                offer.withhold(HttpBodyMode::Buffered, HttpBodyUnavailableReason::OverLimit);
            }
        }
        if entry.supports_http_body_mode(HttpBodyMode::Stream) {
            offer.permit(HttpBodyMode::Stream);
        }
        offer
    }
}

fn request_spec(input: &HttpRequestPreflightInput) -> PipelineSpec {
    PipelineSpec {
        direction: HttpDirection::Request,
        head_authority: HeaderAuthority::Request,
        trailer_authority: HeaderAuthority::RequestTrailers,
        connection_nominated: input.connection_nominated_headers.clone(),
        timeouts: PipelineTimeouts::default(),
        output_trailers: true,
    }
}

impl ChainRunner {
    /// Run HTTP protocol 2 request preflight over a described chain. Returns
    /// an error only for a chain over platform capacity.
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
            let mut diagnostics = HttpStageDiagnostics::default();
            diagnostics.extend(*pipeline::entry_failure(&described[0], reason).diagnostics);
            return Ok(HttpRequestPreflightOutcome {
                allowed: false,
                reason: format!("middleware_failed: {reason}"),
                ..outcome(input.headers, diagnostics)
            });
        }
        let session = if described.iter().any(DescribedChainEntry::is_resolved) {
            match self.try_reserve_middleware_session() {
                MiddlewareSessionAdmission::Admitted(permit) => Some(permit),
                MiddlewareSessionAdmission::AtCapacity => {
                    return Ok(HttpRequestPreflightOutcome {
                        allowed: false,
                        reason: "middleware_failed: session_capacity_exhausted".into(),
                        session_capacity_exhausted: true,
                        ..outcome(input.headers, HttpStageDiagnostics::default())
                    });
                }
            }
        } else {
            None
        };
        let preflight = pipeline::preflight(
            &described,
            request_spec(&input),
            input.headers.clone(),
            input.declared_body_length,
            &RequestHead { input: &input },
        )
        .await;
        let session = preflight.pipeline.map(|pipeline| HttpRequestSession {
            pipeline,
            _session: session.expect("a selected stage implies a resolved entry"),
        });
        Ok(HttpRequestPreflightOutcome {
            allowed: preflight.allowed,
            reason: preflight.reason,
            denial: preflight.denial,
            headers: preflight.headers,
            header_mutations: preflight.header_mutations,
            session,
            diagnostics: preflight.diagnostics,
            session_capacity_exhausted: false,
        })
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
        headers,
        header_mutations: Vec::new(),
        session: None,
        diagnostics,
        session_capacity_exhausted: false,
    }
}
