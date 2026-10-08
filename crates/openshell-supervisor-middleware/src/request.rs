// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Version 2 HTTP request middleware at `PRE_CREDENTIALS`.
//!
//! Preflight runs before any request body byte is read. A chain whose stages
//! all continue at preflight forwards the body untouched; otherwise the
//! returned [`HttpRequestSession`] runs the body stages. The compatibility
//! collector runs one version 2 stage over a fully buffered request for
//! body-aware protocols and chains that still contain legacy entries.

use openshell_core::proto::{
    HeaderMutation, HttpBodyMode, HttpHeader, HttpRequestPreflightHead, HttpRequestTarget,
    MiddlewareSessionEndReason, RequestContext, http_preflight,
};
use prost::Message as _;
use tokio::sync::mpsc;

use crate::headers::{self, HeaderAuthority};
use crate::legacy::hooks;
use crate::pipeline::{
    self, HttpBodyInput, HttpBodyOutput, HttpMiddlewareFailure, HttpPipelineFinish,
    HttpStageDiagnostics, Pipeline, PipelineSpec, PipelineTimeouts, STAGE_QUEUE_MESSAGES,
    StageHead,
};
use crate::{
    ChainEntry, ChainRunner, DescribedChainEntry, HttpDirection, MAX_MIDDLEWARE_CONTEXT_BYTES,
    MAX_MIDDLEWARE_HEADER_BYTES, MAX_MIDDLEWARE_HEADERS, MAX_MIDDLEWARE_PAYLOAD_BYTES,
    MAX_MIDDLEWARE_TARGET_BYTES, MiddlewareDenial, MiddlewareSessionAdmission,
    MiddlewareSessionPermit, MiddlewareWorkAdmission, MiddlewareWorkAdmissionOutcome,
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
    /// The shared middleware work queue was full. Platform load shedding,
    /// not a stage failure.
    pub admission_exhausted: bool,
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
    _work: Option<MiddlewareWorkAdmission>,
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

    /// Run the body stages. The caller feeds `input` and drains `output`
    /// concurrently with this future, and commits the upstream head on the
    /// output `Start`. Dropping the future cancels every stage.
    pub async fn run(
        self,
        input: mpsc::Receiver<HttpBodyInput>,
        output: mpsc::Sender<HttpBodyOutput>,
    ) -> Result<HttpPipelineFinish, HttpMiddlewareFailure> {
        self.pipeline.run(input, output).await
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
    fn preflight_head(
        &self,
        entry: &DescribedChainEntry,
        headers: &[HttpHeader],
    ) -> http_preflight::Head {
        http_preflight::Head::Request(HttpRequestPreflightHead {
            context: Some(self.input.context.clone()),
            target: Some(self.input.target.clone()),
            headers: headers.to_vec(),
            middleware_name: entry.entry.implementation.clone(),
            config: Some(entry.entry.config.clone()),
        })
    }

    fn permitted_body_modes(&self, entry: &DescribedChainEntry) -> Vec<HttpBodyMode> {
        let limit = entry.max_payload_bytes();
        let mut modes = Vec::new();
        if limit == 0 {
            return modes;
        }
        if entry.supports_http_body_mode(HttpBodyMode::Buffered)
            && self
                .input
                .declared_body_length
                .is_none_or(|length| length <= limit as u64)
        {
            modes.push(HttpBodyMode::Buffered);
        }
        if entry.supports_http_body_mode(HttpBodyMode::Stream) {
            modes.push(HttpBodyMode::Stream);
        }
        modes
    }
}

fn request_spec(input: &HttpRequestPreflightInput) -> PipelineSpec {
    PipelineSpec {
        direction: HttpDirection::Request,
        head_authority: HeaderAuthority::Request,
        trailer_authority: HeaderAuthority::RequestTrailers,
        connection_nominated: input.connection_nominated_headers.clone(),
        timeouts: PipelineTimeouts::default(),
    }
}

impl ChainRunner {
    /// Describe `entries` and run request preflight.
    pub async fn preflight_http_request(
        &self,
        entries: &[ChainEntry],
        input: HttpRequestPreflightInput,
    ) -> miette::Result<HttpRequestPreflightOutcome> {
        let described = self.describe_chain(entries).await?;
        self.preflight_described_http_request(described, input)
            .await
    }

    /// Run request preflight over a described chain. Returns an error only
    /// for a chain over platform capacity.
    pub async fn preflight_described_http_request(
        &self,
        described: Vec<DescribedChainEntry>,
        input: HttpRequestPreflightInput,
    ) -> miette::Result<HttpRequestPreflightOutcome> {
        self.preflight_request(described, input, true).await
    }

    /// Request preflight. `reserve_work` is false when the caller already
    /// holds work admission for the whole chain, as the collector does.
    async fn preflight_request(
        &self,
        described: Vec<DescribedChainEntry>,
        input: HttpRequestPreflightInput,
        reserve_work: bool,
    ) -> miette::Result<HttpRequestPreflightOutcome> {
        ensure_chain_capacity(described.len())?;
        if described.is_empty() {
            return Ok(outcome(input.headers, HttpStageDiagnostics::default()));
        }
        if let Err(reason) = validate_preflight_input(&input) {
            let mut diagnostics = HttpStageDiagnostics::default();
            diagnostics.invocations = described
                .iter()
                .map(|entry| {
                    let failure = pipeline::entry_failure(entry, reason);
                    failure
                        .diagnostics
                        .invocations
                        .into_iter()
                        .next()
                        .expect("stage failure records an invocation")
                })
                .collect();
            return Ok(HttpRequestPreflightOutcome {
                allowed: false,
                reason: format!("middleware_failed: {reason}"),
                ..outcome(input.headers, diagnostics)
            });
        }
        let work = if reserve_work && hooks::requires_work_admission(&described) {
            let reservation = self.reserve_middleware_work().await?;
            match reservation {
                MiddlewareWorkAdmissionOutcome::Admitted(admission) => Some(admission),
                MiddlewareWorkAdmissionOutcome::QueueExhausted => {
                    return Ok(HttpRequestPreflightOutcome {
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
            self,
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
            _work: work,
        });
        Ok(HttpRequestPreflightOutcome {
            allowed: preflight.allowed,
            reason: preflight.reason,
            denial: preflight.denial,
            headers: preflight.headers,
            header_mutations: preflight.header_mutations,
            session,
            diagnostics: preflight.diagnostics,
            admission_exhausted: false,
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
        admission_exhausted: false,
        session_capacity_exhausted: false,
    }
}

fn validate_preflight_input(input: &HttpRequestPreflightInput) -> Result<(), &'static str> {
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
        return Err("request_input_over_capacity");
    }
    Ok(())
}

/// One version 2 stage run over a fully buffered request.
pub struct CollectedRequestStage {
    pub allowed: bool,
    pub reason: String,
    pub denial: Option<MiddlewareDenial>,
    /// Head after the stage's preflight and late mutations.
    pub headers: Vec<HttpHeader>,
    /// The stage's preflight mutations, then its late mutations.
    pub header_mutations: Vec<HeaderMutation>,
    /// The stage's output, or the input when the stage did not run its body.
    pub body: Vec<u8>,
    pub body_transformed: bool,
    pub diagnostics: HttpStageDiagnostics,
}

impl CollectedRequestStage {
    fn failed(
        reason: String,
        denial: Option<MiddlewareDenial>,
        headers: Vec<HttpHeader>,
        body: Vec<u8>,
        diagnostics: HttpStageDiagnostics,
    ) -> Self {
        Self {
            allowed: false,
            reason,
            denial,
            headers,
            header_mutations: Vec::new(),
            body,
            body_transformed: false,
            diagnostics,
        }
    }
}

impl ChainRunner {
    /// Run one version 2 request stage over a complete body, for the
    /// compatibility collector. Request trailers are not collected there, so
    /// the stage sees none and its trailer output is dropped, as 0.1.x drops
    /// trailers when it rebuilds a request.
    pub async fn collect_request_stage(
        &self,
        entry: &DescribedChainEntry,
        context: &RequestContext,
        target: &HttpRequestTarget,
        headers: &[HttpHeader],
        connection_nominated: &[String],
        body: Vec<u8>,
    ) -> CollectedRequestStage {
        let input = HttpRequestPreflightInput {
            context: context.clone(),
            target: target.clone(),
            declared_body_length: Some(body.len() as u64),
            headers: headers.to_vec(),
            connection_nominated_headers: connection_nominated.to_vec(),
        };
        let Ok(preflight) = self
            .preflight_request(vec![entry.clone()], input, false)
            .await
        else {
            let failure = pipeline::entry_failure(entry, "request_chain_over_capacity");
            return CollectedRequestStage::failed(
                failure.reason,
                None,
                headers.to_vec(),
                body,
                *failure.diagnostics,
            );
        };
        if !preflight.allowed {
            let mut diagnostics = preflight.diagnostics;
            if preflight.admission_exhausted || preflight.session_capacity_exhausted {
                diagnostics.extend(
                    *pipeline::entry_failure(entry, "session_capacity_exhausted").diagnostics,
                );
            }
            return CollectedRequestStage::failed(
                preflight.reason,
                preflight.denial,
                preflight.headers,
                body,
                diagnostics,
            );
        }
        let mut diagnostics = preflight.diagnostics;
        let Some(session) = preflight.session else {
            return CollectedRequestStage {
                allowed: true,
                reason: String::new(),
                denial: None,
                headers: preflight.headers,
                header_mutations: preflight.header_mutations,
                body,
                body_transformed: false,
                diagnostics,
            };
        };

        let limit = session.input_unit_limit();
        let (input_tx, input_rx) = mpsc::channel(STAGE_QUEUE_MESSAGES);
        let (output_tx, mut output_rx) = mpsc::channel(STAGE_QUEUE_MESSAGES);
        let feed = async {
            for unit in body.chunks(limit) {
                if input_tx
                    .send(HttpBodyInput::Chunk(unit.to_vec()))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            let _ = input_tx
                .send(HttpBodyInput::End {
                    trailers: Vec::new(),
                })
                .await;
        };
        let collect = async move {
            let mut late = Vec::new();
            let mut output = Vec::new();
            while let Some(event) = output_rx.recv().await {
                match event {
                    HttpBodyOutput::Start {
                        header_mutations, ..
                    } => late = header_mutations,
                    HttpBodyOutput::Chunk(data) => {
                        if output.len().saturating_add(data.len()) > MAX_HTTP_REQUEST_WITHHELD_BYTES
                        {
                            return None;
                        }
                        output.extend_from_slice(&data);
                    }
                    HttpBodyOutput::End { .. } => {}
                }
            }
            Some((late, output))
        };
        let (finish, (), collected) = tokio::join!(session.run(input_rx, output_tx), feed, collect);
        let finish = match (finish, collected) {
            (_, None) => {
                let failure = pipeline::entry_failure(entry, "request_output_over_capacity");
                diagnostics.extend(*failure.diagnostics);
                return CollectedRequestStage::failed(
                    failure.reason,
                    None,
                    preflight.headers,
                    body,
                    diagnostics,
                );
            }
            (Err(failure), _) => {
                diagnostics.extend(*failure.diagnostics);
                return CollectedRequestStage::failed(
                    failure.reason,
                    failure.denial,
                    preflight.headers,
                    body,
                    diagnostics,
                );
            }
            (Ok(finish), Some(collected)) => (finish, collected),
        };
        let (finish, (late, output)) = finish;
        diagnostics.extend(finish.diagnostics);
        let headers = match headers::apply(
            HeaderAuthority::Request,
            &preflight.headers,
            connection_nominated,
            &late,
        ) {
            Ok(headers) => headers,
            Err(error) => {
                let failure = pipeline::entry_failure(entry, error.code());
                diagnostics.extend(*failure.diagnostics);
                return CollectedRequestStage::failed(
                    failure.reason,
                    None,
                    preflight.headers,
                    body,
                    diagnostics,
                );
            }
        };
        let mut header_mutations = preflight.header_mutations;
        header_mutations.extend(late);
        let body_transformed = output != body;
        CollectedRequestStage {
            allowed: true,
            reason: String::new(),
            denial: None,
            headers,
            header_mutations,
            body: output,
            body_transformed,
            diagnostics,
        }
    }
}
