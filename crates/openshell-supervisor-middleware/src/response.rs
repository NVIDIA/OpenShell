// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Version 2 HTTP response middleware at `PRE_RETURN`.
//!
//! Preflight runs on the final upstream response head before the relay reads
//! any body byte. A chain whose stages all continue at preflight delivers the
//! body untouched; otherwise the returned [`HttpResponsePipelineSession`]
//! runs the body stages, and the relay commits the response head on the
//! output `Start`.
//!
//! Message eligibility narrows the body modes offered to each version 2
//! stage, in this order:
//!
//! 1. A bodyless, partial, `no-transform`, or content-coded response offers
//!    no body mode.
//! 2. STREAM needs chunked delivery, the only framing in which the client can
//!    detect a truncated body: both the client request and the response
//!    status line use HTTP/1.1.
//! 3. An open-ended response, such as server-sent events, is never offered
//!    BUFFERED.
//!
//! HTTP protocol 1 (0.1): legacy entries run as response adapter stages
//! in chain order with version 2 entries, and keep 0.1.x eligibility.

use std::sync::Arc;
use std::time::Duration;

use openshell_core::proto::{
    HttpBodyMode, HttpBodyUnavailableReason, HttpHeader, HttpRequestTarget,
    HttpResponsePreflightHead, MiddlewareSessionEndReason, RequestContext, http_preflight,
};
use prost::Message as _;
use tokio::sync::mpsc;

use crate::headers::HeaderAuthority;
use crate::legacy::hooks;
use crate::pipeline::{
    self, BodyModeOffer, HTTP_BUFFERED_BODY_TIMEOUT, HttpBodyInput, HttpBodyOutput,
    HttpMiddlewareFailure, HttpPipelineFinish, HttpStageDiagnostics, Pipeline, PipelineSpec,
    PipelineTimeouts, StageHead,
};
use crate::{
    ChainRunner, DescribedChainEntry, HttpDirection, HttpProtocol, MAX_MIDDLEWARE_CONTEXT_BYTES,
    MAX_MIDDLEWARE_HEADER_BYTES, MAX_MIDDLEWARE_HEADERS, MAX_MIDDLEWARE_TARGET_BYTES,
    MiddlewareDenial, MiddlewareSessionAdmission, MiddlewareSessionPermit,
    MiddlewareWorkAdmissionOutcome, OnError, StageReportSink, ensure_chain_capacity,
};

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

/// How the relay delivers one response.
#[derive(Clone)]
pub struct HttpResponseDelivery {
    /// The relay can frame the body chunked: both the client request and the
    /// response status line use HTTP/1.1. Only chunked framing lets the client
    /// detect a truncated body, so STREAM is offered only then. Otherwise
    /// BUFFERED output declares its length and trailers are dropped.
    pub chunked: bool,
    /// Whole-body deadline of each BUFFERED stage.
    pub buffered_body_timeout: Duration,
    /// Receives stage reports as stages produce them.
    pub reports: Option<Arc<dyn StageReportSink>>,
}

impl HttpResponseDelivery {
    #[must_use]
    pub fn new(chunked: bool) -> Self {
        Self {
            chunked,
            buffered_body_timeout: HTTP_BUFFERED_BODY_TIMEOUT,
            reports: None,
        }
    }
}

/// Outcome of response preflight on the stage pipeline.
pub struct HttpResponsePipelinePreflight {
    pub allowed: bool,
    pub reason: String,
    pub denial: Option<MiddlewareDenial>,
    /// Head after every preflight mutation.
    pub headers: Vec<HttpHeader>,
    /// Present when a stage selected a body mode.
    pub session: Option<HttpResponsePipelineSession>,
    pub diagnostics: HttpStageDiagnostics,
    /// The shared middleware work queue was full. Platform load shedding,
    /// not a stage failure.
    pub admission_exhausted: bool,
    /// Every persistent middleware session was in use. Each stage's
    /// `on_error` decided the outcome, so version 2 stages failed closed.
    pub session_capacity_exhausted: bool,
}

/// Response body stages selected at preflight.
///
/// The session holds one slot of the persistent middleware session budget
/// until it ends.
pub struct HttpResponsePipelineSession {
    pipeline: Pipeline,
    _session: MiddlewareSessionPermit,
}

impl HttpResponsePipelineSession {
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

    /// True when a STREAM stage runs. STREAM has no total deadline, and
    /// upstream silence never fails it.
    #[must_use]
    pub fn streams(&self) -> bool {
        self.pipeline.streams()
    }

    #[cfg(test)]
    pub fn set_timeouts(&mut self, timeouts: PipelineTimeouts) {
        self.pipeline.set_timeouts(timeouts);
    }

    /// Run the body stages. The caller feeds `input` and drains `output`
    /// concurrently with this future, commits the response head on the
    /// output `Start`, and resolves `abort` with the reason when the
    /// upstream or the client goes away. Dropping the future cancels every
    /// stage.
    pub async fn run_until(
        self,
        input: mpsc::Receiver<HttpBodyInput>,
        output: mpsc::Sender<HttpBodyOutput>,
        abort: impl Future<Output = MiddlewareSessionEndReason>,
    ) -> Result<HttpPipelineFinish, HttpMiddlewareFailure> {
        self.pipeline.run_until(input, output, abort).await
    }

    /// End every stage without running the body.
    pub async fn end(self, reason: MiddlewareSessionEndReason) {
        self.pipeline.end(reason).await;
    }
}

/// Why a response body cannot be inspected at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyRestriction {
    /// A HEAD response, or status 1xx, 204, or 304.
    Bodyless,
    /// Status 206, `Content-Range`, or `multipart/byteranges`.
    Partial,
    /// `Cache-Control: no-transform`.
    NoTransform,
    /// A content coding other than `identity`.
    Encoded,
}

impl BodyRestriction {
    const fn reason(self) -> HttpBodyUnavailableReason {
        match self {
            Self::Bodyless => HttpBodyUnavailableReason::Bodyless,
            Self::Partial => HttpBodyUnavailableReason::Partial,
            Self::NoTransform => HttpBodyUnavailableReason::NoTransform,
            Self::Encoded => HttpBodyUnavailableReason::Encoded,
        }
    }
}

pub fn body_restriction(input: &HttpResponsePreflightInput) -> Option<BodyRestriction> {
    let headers = |name: &'static str| {
        input
            .headers
            .iter()
            .filter(move |header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_str())
    };
    if input.target.method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&input.status_code)
        || matches!(input.status_code, 204 | 304)
    {
        return Some(BodyRestriction::Bodyless);
    }
    if input.status_code == 206
        || headers("content-range").next().is_some()
        || headers("content-type").any(|value| media_type_is(value, "multipart/byteranges"))
    {
        return Some(BodyRestriction::Partial);
    }
    if headers("cache-control").any(|value| {
        value.split(',').any(|directive| {
            directive
                .split('=')
                .next()
                .is_some_and(|name| name.trim().eq_ignore_ascii_case("no-transform"))
        })
    }) {
        return Some(BodyRestriction::NoTransform);
    }
    if headers("content-encoding").any(|value| {
        value
            .split(',')
            .any(|coding| !coding.trim().eq_ignore_ascii_case("identity"))
    }) {
        return Some(BodyRestriction::Encoded);
    }
    None
}

/// True for a response with no complete body to buffer, such as server-sent
/// events.
pub fn is_open_ended(input: &HttpResponsePreflightInput) -> bool {
    input.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("content-type")
            && (media_type_is(&header.value, "text/event-stream")
                || media_type_is(&header.value, "multipart/x-mixed-replace"))
    })
}

fn media_type_is(content_type: &str, media_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case(media_type))
}

struct ResponseHead<'a> {
    input: &'a HttpResponsePreflightInput,
    restriction: Option<BodyRestriction>,
    open_ended: bool,
    chunked: bool,
}

impl ResponseHead<'_> {
    /// Why `mode` is not offered to a stage with payload limit `limit`, by
    /// the first eligibility rule that removes it.
    fn unavailable(&self, mode: HttpBodyMode, limit: usize) -> Option<HttpBodyUnavailableReason> {
        if let Some(restriction) = self.restriction {
            return Some(restriction.reason());
        }
        match mode {
            HttpBodyMode::Stream if !self.chunked => {
                Some(HttpBodyUnavailableReason::TruncationUndetectable)
            }
            HttpBodyMode::Buffered if self.open_ended => Some(HttpBodyUnavailableReason::OpenEnded),
            HttpBodyMode::Buffered
                if self
                    .input
                    .declared_body_length
                    .is_some_and(|length| length > limit as u64) =>
            {
                Some(HttpBodyUnavailableReason::OverLimit)
            }
            _ => None,
        }
    }
}

impl StageHead for ResponseHead<'_> {
    fn preflight_head(
        &self,
        entry: &DescribedChainEntry,
        headers: &[HttpHeader],
    ) -> http_preflight::Head {
        http_preflight::Head::Response(HttpResponsePreflightHead {
            context: Some(self.input.context.clone()),
            target: Some(self.input.target.clone()),
            status_code: u32::from(self.input.status_code),
            headers: headers.to_vec(),
            middleware_name: entry.entry.implementation.clone(),
            config: Some(entry.entry.config.clone()),
        })
    }

    fn body_modes(&self, entry: &DescribedChainEntry) -> BodyModeOffer {
        let limit = entry.max_payload_bytes();
        let mut offer = BodyModeOffer::default();
        if limit == 0 {
            return offer;
        }
        for mode in [HttpBodyMode::Buffered, HttpBodyMode::Stream] {
            if !entry.supports_http_body_mode(mode) {
                continue;
            }
            match self.unavailable(mode, limit) {
                Some(reason) => offer.withhold(mode, reason),
                None => offer.permit(mode),
            }
        }
        offer
    }

    fn legacy_body_modes(&self, direction: HttpDirection) -> Vec<HttpBodyMode> {
        if self.restriction.is_some() {
            Vec::new()
        } else {
            hooks::permitted_body_modes(direction)
        }
    }
}

impl ChainRunner {
    /// Run response preflight over a described chain on the stage pipeline.
    /// Returns an error only for a chain over platform capacity or a closed
    /// admission semaphore.
    pub async fn preflight_http_response_pipeline(
        &self,
        described: Vec<DescribedChainEntry>,
        input: HttpResponsePreflightInput,
        delivery: HttpResponseDelivery,
    ) -> miette::Result<HttpResponsePipelinePreflight> {
        ensure_chain_capacity(described.len())?;
        if described.is_empty() {
            return Ok(outcome(input.headers, HttpStageDiagnostics::default()));
        }
        if validate_preflight_input(&input).is_err() {
            return Ok(stage_failures(
                &described,
                input.headers,
                "response_input_over_capacity",
            ));
        }
        let session = if described.iter().any(DescribedChainEntry::is_resolved) {
            match self.try_reserve_middleware_session() {
                MiddlewareSessionAdmission::Admitted(permit) => Some(permit),
                MiddlewareSessionAdmission::AtCapacity => {
                    // The 0.1.x reason, whose fail_open finding category is
                    // `session_capacity`.
                    return Ok(HttpResponsePipelinePreflight {
                        session_capacity_exhausted: true,
                        ..stage_failures(
                            &described,
                            input.headers,
                            "middleware_session_capacity_exhausted",
                        )
                    });
                }
            }
        } else {
            None
        };
        // HTTP protocol 1 (0.1): legacy stages keep 0.1.x work
        // admission, after the session budget as in 0.1.x: one reservation
        // for the chain's preflight here, and one for each body exchange in
        // the adapter.
        let _work = if hooks::requires_work_admission(&described) {
            let admission = self.reserve_middleware_work().await?;
            match admission {
                MiddlewareWorkAdmissionOutcome::Admitted(work) => Some(work),
                MiddlewareWorkAdmissionOutcome::QueueExhausted => {
                    return Ok(HttpResponsePipelinePreflight {
                        allowed: false,
                        reason: "middleware_failed: admission_exhausted".into(),
                        admission_exhausted: true,
                        ..outcome(input.headers, HttpStageDiagnostics::default())
                    });
                }
            }
        } else {
            None
        };
        let legacy = described
            .iter()
            .any(|entry| entry.http_protocol() == Some(HttpProtocol::Legacy));
        let spec = PipelineSpec {
            direction: HttpDirection::Response,
            head_authority: HeaderAuthority::Response,
            trailer_authority: HeaderAuthority::ResponseTrailers,
            connection_nominated: input.connection_nominated_headers.clone(),
            timeouts: PipelineTimeouts {
                buffered_body: delivery.buffered_body_timeout,
                ..PipelineTimeouts::default()
            },
            output_trailers: delivery.chunked,
            reports: delivery.reports,
            original_response: legacy.then(|| Arc::new(input.clone())),
        };
        let head = ResponseHead {
            input: &input,
            restriction: body_restriction(&input),
            open_ended: is_open_ended(&input),
            chunked: delivery.chunked,
        };
        let preflight = pipeline::preflight(
            self,
            &described,
            spec,
            input.headers.clone(),
            input.declared_body_length,
            &head,
        )
        .await;
        let session = preflight
            .pipeline
            .map(|pipeline| HttpResponsePipelineSession {
                pipeline,
                _session: session.expect("a selected stage implies a resolved entry"),
            });
        Ok(HttpResponsePipelinePreflight {
            allowed: preflight.allowed,
            reason: preflight.reason,
            denial: preflight.denial,
            headers: preflight.headers,
            session,
            diagnostics: preflight.diagnostics,
            admission_exhausted: false,
            session_capacity_exhausted: false,
        })
    }

    /// Apply each stage's `on_error` to a response head that valid HTTP
    /// allows but the middleware protocol cannot encode. The caller
    /// validates HTTP safety first.
    #[must_use]
    pub fn http_response_pipeline_input_unrepresentable(
        &self,
        described: &[DescribedChainEntry],
    ) -> HttpResponsePipelinePreflight {
        stage_failures(described, Vec::new(), "response_input_unrepresentable")
    }
}

fn outcome(
    headers: Vec<HttpHeader>,
    diagnostics: HttpStageDiagnostics,
) -> HttpResponsePipelinePreflight {
    HttpResponsePipelinePreflight {
        allowed: true,
        reason: String::new(),
        denial: None,
        headers,
        session: None,
        diagnostics,
        admission_exhausted: false,
        session_capacity_exhausted: false,
    }
}

/// Every stage failed for `reason` before preflight. Each entry's `on_error`
/// applies in chain order; version 2 entries always fail closed.
fn stage_failures(
    entries: &[DescribedChainEntry],
    headers: Vec<HttpHeader>,
    reason: &str,
) -> HttpResponsePipelinePreflight {
    let mut diagnostics = HttpStageDiagnostics::default();
    for entry in entries {
        if entry.on_error() == OnError::FailOpen {
            diagnostics
                .invocations
                .push(pipeline::fail_open_invocation(entry, reason));
            continue;
        }
        diagnostics.extend(*pipeline::entry_failure(entry, reason).diagnostics);
        return HttpResponsePipelinePreflight {
            allowed: false,
            reason: format!("middleware_failed: {reason}"),
            ..outcome(headers, diagnostics)
        };
    }
    outcome(headers, diagnostics)
}

pub fn validate_preflight_input(input: &HttpResponsePreflightInput) -> Result<(), ()> {
    if input.context.encoded_len() > MAX_MIDDLEWARE_CONTEXT_BYTES
        || input.target.encoded_len() > MAX_MIDDLEWARE_TARGET_BYTES
        || input.headers.len() > MAX_MIDDLEWARE_HEADERS
        || input
            .headers
            .iter()
            .map(prost::Message::encoded_len)
            .fold(0usize, usize::saturating_add)
            > MAX_MIDDLEWARE_HEADER_BYTES
    {
        return Err(());
    }
    Ok(())
}
