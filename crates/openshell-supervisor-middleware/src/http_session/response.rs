// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP session hook response middleware at `PRE_RETURN`.
//!
//! Preflight runs on the final upstream response head before the relay reads
//! any body byte. A chain whose stages all continue at preflight delivers the
//! body untouched; otherwise the returned [`HttpResponsePipelineSession`]
//! runs the body stages, and the relay commits the response head on the
//! output `Start`.
//!
//! Message eligibility narrows the body modes offered to each stage, in this
//! order:
//!
//! 1. A bodyless, partial, `no-transform`, or content-coded response offers
//!    no body mode.
//! 2. STREAM needs chunked delivery, the only framing in which the client can
//!    detect a truncated body: both the client request and the response
//!    status line use HTTP/1.1.
//! 3. An open-ended response, such as server-sent events, is never offered
//!    BUFFERED, and a declared length over the stage's limit removes
//!    BUFFERED.

use std::future::Future;
use std::time::Duration;

use openshell_core::proto::{
    HttpBodyMode, HttpBodyUnavailableReason, HttpHeader, HttpResponsePreflightHead,
    MiddlewareSessionEndReason, RequestContext,
};
use tokio::sync::mpsc;
use tokio::time::Instant;

use super::pipeline::{
    self, BodyModeOffer, HTTP_BUFFERED_BODY_TIMEOUT, HttpBodyInput, HttpBodyOutput,
    HttpFailureCode, HttpMiddlewareFailure, HttpPipelineFinish, HttpStageDiagnostics,
    MiddlewareFailureDetail, Pipeline, PipelineSpec, PipelineTimeouts, PreflightFields, StageHead,
    StagePreflight,
};
use super::{has_content_coding, validate_head_input};
use crate::headers::HeaderAuthority;
use crate::{
    ChainRunner, DescribedChainEntry, HttpResponsePreflightInput, MAX_MIDDLEWARE_CHAIN_TIMEOUT,
    MiddlewareDenial, ensure_chain_capacity,
};

/// How the relay delivers one response.
#[derive(Debug, Clone, Copy)]
pub struct HttpResponseDelivery {
    /// The relay can frame the body chunked: both the client request and the
    /// response status line use HTTP/1.1. Only chunked framing lets the client
    /// detect a truncated body, so STREAM is offered only then. Otherwise
    /// BUFFERED output declares its length and trailers are dropped.
    pub chunked: bool,
    /// Whole-body deadline of each BUFFERED stage.
    pub buffered_body_timeout: Duration,
}

impl HttpResponseDelivery {
    #[must_use]
    pub fn new(chunked: bool) -> Self {
        Self {
            chunked,
            buffered_body_timeout: HTTP_BUFFERED_BODY_TIMEOUT,
        }
    }
}

/// Outcome of HTTP session hook response preflight.
pub struct HttpResponsePipelinePreflight {
    pub allowed: bool,
    pub reason: String,
    pub denial: Option<MiddlewareDenial>,
    /// Present when the chain failed closed for a reason the sandbox may see.
    pub failure: Option<MiddlewareFailureDetail>,
    /// Head after every preflight mutation.
    pub headers: Vec<HttpHeader>,
    /// Present when a stage selected a body mode.
    pub session: Option<HttpResponsePipelineSession>,
    pub diagnostics: HttpStageDiagnostics,
    /// No HTTP session hook slot freed up within the chain deadline, so the
    /// response failed closed.
    pub session_capacity_exhausted: bool,
}

/// Response body stages selected at preflight.
///
/// The session holds its HTTP session hook budget slots while its body
/// stages run.
pub struct HttpResponsePipelineSession {
    pipeline: Pipeline,
}

impl HttpResponsePipelineSession {
    /// Largest body chunk to feed as input.
    #[must_use]
    pub fn input_unit_limit(&self) -> usize {
        self.pipeline.input_unit_limit()
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
enum BodyRestriction {
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

fn body_restriction(input: &HttpResponsePreflightInput) -> Option<BodyRestriction> {
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
    if has_content_coding(&input.headers) {
        return Some(BodyRestriction::Encoded);
    }
    None
}

/// True for a response with no complete body to buffer, such as server-sent
/// events.
fn is_open_ended(input: &HttpResponsePreflightInput) -> bool {
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

impl<'a> ResponseHead<'a> {
    fn new(input: &'a HttpResponsePreflightInput, chunked: bool) -> Self {
        Self {
            input,
            restriction: body_restriction(input),
            open_ended: is_open_ended(input),
            chunked,
        }
    }

    /// Why `mode` is not offered to a stage with payload limit `limit` that
    /// receives a body of `declared_body_bytes`, by the first eligibility
    /// rule that removes it.
    fn unavailable(
        &self,
        mode: HttpBodyMode,
        limit: usize,
        declared_body_bytes: Option<u64>,
    ) -> Option<HttpBodyUnavailableReason> {
        if let Some(restriction) = self.restriction {
            return Some(restriction.reason());
        }
        match mode {
            HttpBodyMode::Stream if !self.chunked => {
                Some(HttpBodyUnavailableReason::TruncationUndetectable)
            }
            HttpBodyMode::Buffered if self.open_ended => Some(HttpBodyUnavailableReason::OpenEnded),
            HttpBodyMode::Buffered
                if declared_body_bytes.is_some_and(|length| length > limit as u64) =>
            {
                Some(HttpBodyUnavailableReason::OverLimit)
            }
            _ => None,
        }
    }
}

impl StageHead for ResponseHead<'_> {
    fn context(&self) -> &RequestContext {
        &self.input.context
    }

    fn preflight(&self, headers: &[HttpHeader], fields: PreflightFields) -> StagePreflight {
        fields.response(HttpResponsePreflightHead {
            target: Some(self.input.target.clone()),
            status_code: u32::from(self.input.status_code),
            headers: headers.to_vec(),
        })
    }

    fn body_modes(
        &self,
        entry: &DescribedChainEntry,
        declared_body_bytes: Option<u64>,
    ) -> BodyModeOffer {
        let limit = entry.max_payload_bytes();
        let mut offer = BodyModeOffer::default();
        if limit == 0 {
            return offer;
        }
        for mode in [HttpBodyMode::Buffered, HttpBodyMode::Stream] {
            match self.unavailable(mode, limit, declared_body_bytes) {
                Some(reason) => offer.withhold(mode, reason),
                None => offer.permit(mode),
            }
        }
        offer
    }
}

impl ChainRunner {
    /// Run HTTP session hook response preflight over a described chain.
    /// Returns an error only for a chain over platform capacity.
    ///
    /// Preflight waits for an HTTP session hook slot within the chain
    /// deadline, and the slot is released once no stage inspects the body.
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
        if let Err(reason) = validate_head_input(&input.context, &input.target, &input.headers) {
            return Ok(chain_failure(&described, input.headers, reason));
        }
        let chain_deadline = Instant::now() + MAX_MIDDLEWARE_CHAIN_TIMEOUT;
        let slot = if described.iter().any(DescribedChainEntry::is_resolved) {
            let Some(slot) = self.reserve_http_session(chain_deadline).await else {
                return Ok(capacity_exhausted(&described, input.headers));
            };
            Some(slot)
        } else {
            None
        };
        let spec = PipelineSpec {
            head_authority: HeaderAuthority::SessionResponse,
            trailer_authority: HeaderAuthority::ResponseTrailers,
            connection_nominated: input.connection_nominated_headers.clone(),
            timeouts: PipelineTimeouts {
                buffered_body: delivery.buffered_body_timeout,
                ..PipelineTimeouts::default()
            },
            output_trailers: delivery.chunked,
        };
        let head = ResponseHead::new(&input, delivery.chunked);
        let preflight = pipeline::preflight(
            &described,
            spec,
            input.headers.clone(),
            input.declared_body_length,
            &head,
            chain_deadline,
        )
        .await;
        let session = match preflight.pipeline {
            Some(pipeline) => {
                let slot = slot.expect("a selected stage implies a resolved entry");
                let Some(pipeline) = self.admit_body(pipeline, slot, chain_deadline).await else {
                    return Ok(capacity_exhausted(&described, input.headers));
                };
                Some(HttpResponsePipelineSession { pipeline })
            }
            // No stage inspects the body, so the slot is released here.
            None => None,
        };
        Ok(HttpResponsePipelinePreflight {
            allowed: preflight.allowed,
            reason: preflight.reason,
            denial: preflight.denial,
            failure: preflight.failure,
            headers: preflight.headers,
            session,
            diagnostics: preflight.diagnostics,
            session_capacity_exhausted: false,
        })
    }

    /// Fail an HTTP session hook response chain whose head valid HTTP allows
    /// but the middleware protocol cannot encode.
    #[must_use]
    pub fn http_response_pipeline_input_unrepresentable(
        &self,
        described: &[DescribedChainEntry],
    ) -> HttpResponsePipelinePreflight {
        chain_failure(described, Vec::new(), "response_input_unrepresentable")
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
        failure: None,
        headers,
        session: None,
        diagnostics,
        session_capacity_exhausted: false,
    }
}

/// The chain failed closed for `reason` before preflight.
fn chain_failure(
    entries: &[DescribedChainEntry],
    headers: Vec<HttpHeader>,
    reason: &str,
) -> HttpResponsePipelinePreflight {
    let Some(entry) = entries.first() else {
        return HttpResponsePipelinePreflight {
            allowed: false,
            reason: format!("middleware_failed: {reason}"),
            ..outcome(headers, HttpStageDiagnostics::default())
        };
    };
    let failure = pipeline::entry_failure(entry, reason);
    HttpResponsePipelinePreflight {
        allowed: false,
        reason: failure.reason,
        failure: failure.failure.map(|failure| *failure),
        ..outcome(headers, *failure.diagnostics)
    }
}

/// No HTTP session hook slot freed up within the chain deadline. No stage
/// owns this failure.
fn capacity_exhausted(
    entries: &[DescribedChainEntry],
    headers: Vec<HttpHeader>,
) -> HttpResponsePipelinePreflight {
    HttpResponsePipelinePreflight {
        session_capacity_exhausted: true,
        failure: Some(MiddlewareFailureDetail {
            config_name: None,
            code: HttpFailureCode::Unavailable,
        }),
        ..chain_failure(entries, headers, "session_capacity_exhausted")
    }
}

#[cfg(test)]
mod tests {
    use openshell_core::proto::{
        HttpBodyMode, HttpBodyModeUnavailable, HttpBodyUnavailableReason, HttpHeader,
        HttpRequestTarget, MiddlewareBinding, RequestContext, SupervisorMiddlewareOperation,
        SupervisorMiddlewarePhase,
    };

    use super::ResponseHead;
    use crate::http_session::pipeline::StageHead;
    use crate::{
        ChainEntry, DescribedChainEntry, HttpHookVersion, HttpResponsePreflightInput, OnError,
    };

    fn entry(limit: usize) -> DescribedChainEntry {
        DescribedChainEntry {
            entry: ChainEntry {
                name: "guard".into(),
                implementation: "example/guard".into(),
                order: 0,
                config: prost_types::Struct::default(),
                on_error: OnError::FailClosed,
            },
            service: None,
            binding: Some(MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpResponse as i32,
                phase: SupervisorMiddlewarePhase::PreReturn as i32,
                max_payload_bytes: limit as u64,
                ..Default::default()
            }),
            max_payload_bytes: limit,
            timeout: std::time::Duration::from_millis(500),
            http_hook_version: Some(HttpHookVersion::Session),
        }
    }

    fn response(
        method: &str,
        status_code: u16,
        headers: &[(&str, &str)],
        length: Option<u64>,
    ) -> HttpResponsePreflightInput {
        HttpResponsePreflightInput {
            context: RequestContext::default(),
            target: HttpRequestTarget {
                method: method.into(),
                ..Default::default()
            },
            status_code,
            declared_body_length: length,
            headers: headers
                .iter()
                .map(|(name, value)| HttpHeader {
                    name: (*name).into(),
                    value: (*value).into(),
                })
                .collect(),
            connection_nominated_headers: Vec::new(),
        }
    }

    /// Case name, response, chunked delivery, permitted modes, and withheld
    /// modes with their reasons.
    type EligibilityCase = (
        &'static str,
        HttpResponsePreflightInput,
        bool,
        Vec<HttpBodyMode>,
        Vec<(HttpBodyMode, HttpBodyUnavailableReason)>,
    );

    #[test]
    fn response_eligibility_offers_only_body_modes_the_message_supports() {
        use HttpBodyMode::{Buffered, Stream};
        use HttpBodyUnavailableReason as Reason;
        let json = [("content-type", "application/json")];
        let cases: Vec<EligibilityCase> = vec![
            (
                "ordinary body",
                response("GET", 200, &json, Some(10)),
                true,
                vec![Buffered, Stream],
                vec![],
            ),
            (
                "HEAD",
                response("HEAD", 200, &json, Some(10)),
                true,
                vec![],
                vec![(Buffered, Reason::Bodyless), (Stream, Reason::Bodyless)],
            ),
            (
                "204",
                response("GET", 204, &[], None),
                true,
                vec![],
                vec![(Buffered, Reason::Bodyless), (Stream, Reason::Bodyless)],
            ),
            (
                "304",
                response("GET", 304, &[], None),
                true,
                vec![],
                vec![(Buffered, Reason::Bodyless), (Stream, Reason::Bodyless)],
            ),
            (
                "partial",
                response("GET", 206, &json, Some(10)),
                true,
                vec![],
                vec![(Buffered, Reason::Partial), (Stream, Reason::Partial)],
            ),
            (
                "content-range",
                response("GET", 200, &[("content-range", "bytes 0-9/20")], Some(10)),
                true,
                vec![],
                vec![(Buffered, Reason::Partial), (Stream, Reason::Partial)],
            ),
            (
                "no-transform",
                response(
                    "GET",
                    200,
                    &[("cache-control", "max-age=60, no-transform")],
                    Some(10),
                ),
                true,
                vec![],
                vec![
                    (Buffered, Reason::NoTransform),
                    (Stream, Reason::NoTransform),
                ],
            ),
            (
                "encoded",
                response("GET", 200, &[("content-encoding", "gzip")], Some(10)),
                true,
                vec![],
                vec![(Buffered, Reason::Encoded), (Stream, Reason::Encoded)],
            ),
            (
                "identity coding",
                response("GET", 200, &[("content-encoding", "identity")], Some(10)),
                true,
                vec![Buffered, Stream],
                vec![],
            ),
            (
                "over the limit",
                response("GET", 200, &json, Some(4096)),
                true,
                vec![Stream],
                vec![(Buffered, Reason::OverLimit)],
            ),
            (
                "server-sent events",
                response(
                    "GET",
                    200,
                    &[("content-type", "text/event-stream; charset=utf-8")],
                    None,
                ),
                true,
                vec![Stream],
                vec![(Buffered, Reason::OpenEnded)],
            ),
            (
                "multipart replace",
                response(
                    "GET",
                    200,
                    &[("content-type", "multipart/x-mixed-replace; boundary=x")],
                    None,
                ),
                true,
                vec![Stream],
                vec![(Buffered, Reason::OpenEnded)],
            ),
            (
                "HTTP/1.0 client",
                response("GET", 200, &json, Some(10)),
                false,
                vec![Buffered],
                vec![(Stream, Reason::TruncationUndetectable)],
            ),
            (
                "SSE to an HTTP/1.0 client",
                response("GET", 200, &[("content-type", "text/event-stream")], None),
                false,
                vec![],
                vec![
                    (Buffered, Reason::OpenEnded),
                    (Stream, Reason::TruncationUndetectable),
                ],
            ),
        ];
        for (case, input, chunked, permitted, unavailable) in cases {
            let offer = ResponseHead::new(&input, chunked)
                .body_modes(&entry(1024), input.declared_body_length);
            assert_eq!(offer.permitted, permitted, "{case}");
            assert_eq!(
                offer.unavailable,
                unavailable
                    .into_iter()
                    .map(|(mode, reason)| HttpBodyModeUnavailable {
                        mode: mode as i32,
                        reason: reason as i32,
                    })
                    .collect::<Vec<_>>(),
                "{case}"
            );
        }
    }
}
