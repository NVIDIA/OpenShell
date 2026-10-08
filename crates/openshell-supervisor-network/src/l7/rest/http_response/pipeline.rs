// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Duplex response relay for HTTP response middleware on the stage pipeline.
//!
//! The upstream body feeds the stages while their output streams to the
//! client. The response head commits on the pipeline's output `Start`, with
//! `Content-Length` when the output declares its length, chunked framing
//! otherwise, or close-delimited framing where the client cannot use chunked
//! framing. A version 2 chain never streams without a length or chunked
//! framing, so its truncation stays detectable; legacy stages keep 0.1.x
//! close-delimited STREAM delivery.
//!
//! A failure before commit returns the canonical 403 or 502 response. After
//! commit, delivery aborts: no terminating chunk, trailers, or error body,
//! and the connection closes. A policy reload stops delivery at once: before
//! commit the connection closes without a response, and after it delivery
//! aborts unless the client already received the whole body. STREAM has no
//! total deadline, and upstream silence never fails a response. As for an
//! uninspected response, an upstream body without framing ends when the
//! upstream closes, or, except for server-sent events, after the relay's idle
//! timeout.

use std::sync::{Arc, Mutex};

use openshell_core::proto::{Finding, MiddlewareSessionEndReason};
use openshell_supervisor_middleware::{
    HttpBodyInput, HttpBodyOutput, HttpProtocol, HttpResponseDelivery, HttpResponseInvocation,
    HttpStageDiagnostics, HttpStageOutcome, NamespacedFinding, StageReport, StageReportSink,
};
use tokio::sync::{mpsc, oneshot};

use super::*;

/// Messages the input and output links between the relay and the stage
/// pipeline hold.
const LINK_MESSAGES: usize = 4;

/// Downstream framing of a committed response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFraming {
    ContentLength { remaining: u64 },
    Chunked,
    CloseDelimited,
}

impl OutputFraming {
    const fn name(self) -> &'static str {
        match self {
            Self::ContentLength { .. } => "content_length",
            Self::Chunked => "chunked",
            Self::CloseDelimited => "close_delimited",
        }
    }
}

/// Why relaying a response body through the stage pipeline stopped.
#[derive(Debug)]
enum BodyRelayError {
    /// Reading or decoding the upstream body failed.
    Upstream(miette::Report),
    /// Writing to the client failed.
    Downstream(std::io::Error),
    /// The policy generation changed.
    PolicyReload(miette::Report),
    /// The stages' output could not be delivered as it declared.
    Output(miette::Report),
}

impl BodyRelayError {
    const fn end_reason(&self) -> MiddlewareSessionEndReason {
        match self {
            Self::Upstream(_) => MiddlewareSessionEndReason::UpstreamDisconnect,
            Self::Downstream(_) => MiddlewareSessionEndReason::DownstreamDisconnect,
            Self::PolicyReload(_) => MiddlewareSessionEndReason::PolicyReload,
            Self::Output(_) => MiddlewareSessionEndReason::MiddlewareFailure,
        }
    }

    fn into_report(self) -> miette::Report {
        match self {
            Self::Upstream(error) | Self::PolicyReload(error) | Self::Output(error) => error,
            Self::Downstream(error) => miette!("HTTP response client write failed: {error}"),
        }
    }
}

/// Relay a response whose chain runs on the stage pipeline.
#[allow(clippy::too_many_arguments)]
pub(super) async fn relay_response_through_pipeline<U, C>(
    request_method: &str,
    upstream: &mut U,
    client: &mut C,
    middleware: HttpResponseMiddlewareRelay<'_>,
    described: Vec<openshell_supervisor_middleware::DescribedChainEntry>,
    parsed: ParsedResponseHead,
    buffered: &[u8],
    header_end: usize,
    status_code: u16,
    body_length: BodyLength,
    server_wants_close: bool,
    event_stream: bool,
) -> Result<Option<RelayOutcome>>
where
    U: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    let status_line = response_status_line(&buffered[..header_end])?;
    let chunked = middleware.client_accepts_chunked && !status_line.starts_with("HTTP/1.0 ");
    let original_headers = parsed.headers.clone();
    let input = openshell_supervisor_middleware::HttpResponsePreflightInput {
        context: middleware.request_context.clone(),
        target: middleware.target.clone(),
        status_code,
        declared_body_length: match body_length {
            BodyLength::ContentLength(length) => Some(length),
            BodyLength::Chunked | BodyLength::None => None,
        },
        headers: parsed.headers.clone(),
        connection_nominated_headers: parsed.connection_nominated.clone(),
    };
    let legacy_reports = Arc::new(LegacyResponseReports {
        policy_name: middleware.policy_name.to_string(),
        target: middleware.target.clone(),
        status_code,
        failed: Mutex::default(),
    });
    let delivery = HttpResponseDelivery {
        buffered_body_timeout: middleware.whole_body_timeout,
        reports: Some(legacy_reports.clone()),
        ..HttpResponseDelivery::new(chunked)
    };
    let preflight = if parsed.representable {
        middleware
            .runner
            .preflight_http_response_pipeline(described, input, delivery)
            .await
    } else {
        Ok(middleware
            .runner
            .http_response_pipeline_input_unrepresentable(&described))
    };
    let mut preflight = match preflight {
        Ok(preflight) => preflight,
        Err(error) => {
            debug!(error = %error, "HTTP response middleware preflight failed");
            emit_http_response_middleware_failure(
                middleware.policy_name,
                &middleware.target,
                status_code,
                false,
            );
            send_response_delivery_failure(
                client,
                request_method,
                middleware.policy_name,
                &middleware.target,
            )
            .await?;
            return Ok(Some(RelayOutcome::Consumed));
        }
    };
    if let Some(guard) = middleware.generation_guard
        && let Err(error) = guard.ensure_current()
    {
        if let Some(session) = preflight.session.take() {
            session.end(MiddlewareSessionEndReason::PolicyReload).await;
        }
        return Err(error);
    }
    emit_http_response_stage_events(
        middleware.policy_name,
        &middleware.target,
        status_code,
        &preflight.diagnostics,
        &legacy_reports,
    );
    for event in
        http_response_capacity_events(middleware.policy_name, &middleware.target, &preflight)
    {
        openshell_ocsf::ocsf_emit!(event);
    }
    if !preflight.allowed {
        debug!(reason = %preflight.reason, "HTTP response middleware preflight denied delivery");
        if let Some(denial) = preflight.denial.as_ref() {
            send_response_middleware_denial(
                client,
                request_method,
                middleware.policy_name,
                &middleware.target,
                denial,
            )
            .await?;
        } else {
            emit_http_response_middleware_failure(
                middleware.policy_name,
                &middleware.target,
                status_code,
                false,
            );
            send_response_delivery_failure(
                client,
                request_method,
                middleware.policy_name,
                &middleware.target,
            )
            .await?;
        }
        return Ok(Some(RelayOutcome::Consumed));
    }

    let Some(session) = preflight.session.take() else {
        if preflight.headers == original_headers {
            return Ok(None);
        }
        let outcome = relay_headers_only_response(
            request_method,
            upstream,
            client,
            &status_line,
            &preflight.headers,
            &parsed.preserved_credential_headers,
            &parsed.declared_trailers,
            &buffered[header_end..],
            status_code,
            body_length,
            server_wants_close,
            event_stream,
        )
        .await?;
        return Ok(Some(outcome));
    };
    // Eligibility offers a bodyless response no body mode, so no stage can
    // have selected one.
    if is_bodiless_response(request_method, status_code) {
        session
            .end(MiddlewareSessionEndReason::MiddlewareFailure)
            .await;
        emit_http_response_middleware_failure(
            middleware.policy_name,
            &middleware.target,
            status_code,
            false,
        );
        send_response_delivery_failure(
            client,
            request_method,
            middleware.policy_name,
            &middleware.target,
        )
        .await?;
        return Ok(Some(RelayOutcome::Consumed));
    }

    let unit_limit = session.input_unit_limit();
    let (input, inputs) = mpsc::channel(LINK_MESSAGES);
    let (output, mut outputs) = mpsc::channel(LINK_MESSAGES);
    let (abort, aborted) = oneshot::channel();
    let run = session.run_until(inputs, output, async move {
        match aborted.await {
            Ok(reason) => reason,
            // The relay finished without aborting.
            Err(_) => std::future::pending().await,
        }
    });
    let mut reader = BufferedResponseReader::new(upstream, &buffered[header_end..]);
    let mut writer = ResponseWriter {
        client,
        status_line: &status_line,
        headers: &preflight.headers,
        parsed: &parsed,
        chunked,
        connection_close: server_wants_close,
        generation_guard: middleware.generation_guard,
        framing: None,
    };
    let relay = async {
        let feed = feed_response_body(
            &mut reader,
            body_length,
            server_wants_close || event_stream,
            event_stream,
            unit_limit,
            middleware.generation_guard,
            &parsed.connection_nominated,
            input,
        );
        let write = async {
            while let Some(event) = outputs.recv().await {
                writer.write(event).await?;
                // Server-sent events reach the client one by one.
                if event_stream || outputs.is_empty() {
                    writer.flush().await?;
                }
            }
            Ok(())
        };
        // The policy may change while the upstream is silent.
        let relayed = tokio::select! {
            biased;
            relayed = async { tokio::try_join!(feed, write).map(drop) } => relayed,
            error = policy_reloaded(middleware.generation_guard) => {
                Err(BodyRelayError::PolicyReload(error))
            }
        };
        if let Err(error) = &relayed {
            let _ = abort.send(error.end_reason());
        }
        relayed
    };
    let (finish, relayed) = tokio::join!(run, relay);
    let framing = writer.framing;

    let failure = match (finish, relayed) {
        (Ok(finish), Ok(())) => {
            emit_http_response_stage_events(
                middleware.policy_name,
                &middleware.target,
                status_code,
                &finish.diagnostics,
                &legacy_reports,
            );
            if let Some(guard) = middleware.generation_guard {
                guard.ensure_current()?;
            }
            return Ok(Some(
                if server_wants_close
                    || framing == Some(OutputFraming::CloseDelimited)
                    || (matches!(body_length, BodyLength::None) && event_stream)
                {
                    RelayOutcome::Consumed
                } else {
                    RelayOutcome::Reusable
                },
            ));
        }
        (Err(failure), relayed) => {
            emit_http_response_stage_events(
                middleware.policy_name,
                &middleware.target,
                status_code,
                &failure.diagnostics,
                &legacy_reports,
            );
            match relayed {
                // The stages failed or rejected the response.
                Ok(()) => Ok(failure),
                Err(error) => Err(error),
            }
        }
        (Ok(finish), Err(error)) => {
            emit_http_response_stage_events(
                middleware.policy_name,
                &middleware.target,
                status_code,
                &finish.diagnostics,
                &legacy_reports,
            );
            Err(error)
        }
    };
    let committed = framing.is_some();
    match failure {
        Err(error @ BodyRelayError::Downstream(_)) => Err(error.into_report()),
        // A stale policy ends the connection without a response, as it does
        // before preflight.
        Err(error @ BodyRelayError::PolicyReload(_)) if !committed => Err(error.into_report()),
        Err(error) if committed => {
            emit_http_response_middleware_abort(
                middleware.policy_name,
                &middleware.target,
                status_code,
                framing.expect("a committed response has framing"),
            );
            Err(error.into_report())
        }
        Err(error) => {
            debug!(error = %error.into_report(), "HTTP response relay failed before commitment");
            emit_http_response_middleware_failure(
                middleware.policy_name,
                &middleware.target,
                status_code,
                false,
            );
            send_response_delivery_failure(
                &mut *writer.client,
                request_method,
                middleware.policy_name,
                &middleware.target,
            )
            .await?;
            Ok(Some(RelayOutcome::Consumed))
        }
        Ok(failure) if committed => {
            emit_http_response_middleware_abort(
                middleware.policy_name,
                &middleware.target,
                status_code,
                framing.expect("a committed response has framing"),
            );
            Err(miette!(
                "HTTP response middleware failed after commitment: {}",
                failure.reason
            ))
        }
        Ok(failure) => {
            debug!(reason = %failure.reason, "HTTP response middleware failed before commitment");
            if let Some(denial) = failure.denial.as_ref() {
                send_response_middleware_denial(
                    &mut *writer.client,
                    request_method,
                    middleware.policy_name,
                    &middleware.target,
                    denial,
                )
                .await?;
            } else {
                emit_http_response_middleware_failure(
                    middleware.policy_name,
                    &middleware.target,
                    status_code,
                    false,
                );
                send_response_delivery_failure(
                    &mut *writer.client,
                    request_method,
                    middleware.policy_name,
                    &middleware.target,
                )
                .await?;
            }
            Ok(Some(RelayOutcome::Consumed))
        }
    }
}

/// Resolves with the stale-generation error once the policy changes.
async fn policy_reloaded(generation_guard: Option<&PolicyGenerationGuard>) -> miette::Report {
    match generation_guard {
        Some(guard) => guard.reloaded().await,
        None => std::future::pending().await,
    }
}

/// Feed the upstream body to the stages in units of at most `limit` bytes.
/// Upstream silence is never a failure: a stream ends when its framing ends.
#[allow(clippy::too_many_arguments)]
async fn feed_response_body<R: AsyncRead + Unpin>(
    reader: &mut BufferedResponseReader<'_, R>,
    body_length: BodyLength,
    close_delimited: bool,
    event_stream: bool,
    limit: usize,
    generation_guard: Option<&PolicyGenerationGuard>,
    connection_nominated: &[String],
    input: mpsc::Sender<HttpBodyInput>,
) -> std::result::Result<(), BodyRelayError> {
    let current = || {
        generation_guard
            .map_or(Ok(()), PolicyGenerationGuard::ensure_current)
            .map_err(BodyRelayError::PolicyReload)
    };
    // A closed input means the stages stopped; their result says why.
    let send = |unit: Vec<u8>| input.send(HttpBodyInput::Chunk(unit));
    let feed = async {
        let trailers = match body_length {
            BodyLength::ContentLength(length) => {
                let mut remaining = length;
                while remaining > 0 {
                    let want = usize::try_from(remaining).unwrap_or(limit).min(limit);
                    let unit = reader
                        .read_some(want)
                        .await
                        .map_err(BodyRelayError::Upstream)?
                        .ok_or_else(|| {
                            BodyRelayError::Upstream(miette!(
                                "HTTP response body ended unexpectedly"
                            ))
                        })?;
                    current()?;
                    remaining -= unit.len() as u64;
                    if send(unit).await.is_err() {
                        return Ok(());
                    }
                }
                Vec::new()
            }
            BodyLength::Chunked => loop {
                let line = reader.read_line().await.map_err(BodyRelayError::Upstream)?;
                let size = std::str::from_utf8(&line)
                    .ok()
                    .and_then(|line| line.split(';').next())
                    .and_then(|size| usize::from_str_radix(size.trim(), 16).ok())
                    .ok_or_else(|| {
                        BodyRelayError::Upstream(miette!("Invalid HTTP response chunk size"))
                    })?;
                if size == 0 {
                    break read_trailer_fields(reader, connection_nominated)
                        .await
                        .map_err(BodyRelayError::Upstream)?;
                }
                let mut remaining = size;
                while remaining > 0 {
                    let unit = reader
                        .read_some(remaining.min(limit))
                        .await
                        .map_err(BodyRelayError::Upstream)?
                        .ok_or_else(|| {
                            BodyRelayError::Upstream(miette!(
                                "HTTP response body ended unexpectedly"
                            ))
                        })?;
                    current()?;
                    remaining -= unit.len();
                    if send(unit).await.is_err() {
                        return Ok(());
                    }
                }
                if reader
                    .read_exact_vec(2)
                    .await
                    .map_err(BodyRelayError::Upstream)?
                    != b"\r\n"
                {
                    return Err(BodyRelayError::Upstream(miette!(
                        "HTTP response chunk is missing its terminator"
                    )));
                }
            },
            BodyLength::None if close_delimited => {
                loop {
                    let read = reader.read_some(limit);
                    // Without explicit framing, an idle connection other than an
                    // event stream ends the body, as for an uninspected response.
                    let unit = if event_stream {
                        read.await
                    } else {
                        tokio::time::timeout(RELAY_EOF_IDLE_TIMEOUT, read)
                            .await
                            .unwrap_or(Ok(None))
                    }
                    .map_err(BodyRelayError::Upstream)?;
                    let Some(unit) = unit else {
                        break;
                    };
                    current()?;
                    if send(unit).await.is_err() {
                        return Ok(());
                    }
                }
                Vec::new()
            }
            BodyLength::None => Vec::new(),
        };
        let _ = input.send(HttpBodyInput::End { trailers }).await;
        Ok(())
    };
    // The stages may stop while the upstream is silent.
    tokio::select! {
        result = feed => result,
        () = input.closed() => Ok(()),
    }
}

async fn read_trailer_fields<R: AsyncRead + Unpin>(
    reader: &mut BufferedResponseReader<'_, R>,
    connection_nominated: &[String],
) -> Result<Vec<HttpHeader>> {
    let mut trailers = Vec::new();
    loop {
        let line = reader.read_line().await?;
        if !push_response_trailer(&line, connection_nominated, &mut trailers)? {
            return Ok(trailers);
        }
    }
}

/// Writes the stages' output to the client, committing the head on `Start`.
struct ResponseWriter<'c, 'a, C> {
    client: &'c mut C,
    status_line: &'a str,
    /// Head after every preflight mutation.
    headers: &'a [HttpHeader],
    parsed: &'a ParsedResponseHead,
    /// The client can decode chunked framing.
    chunked: bool,
    connection_close: bool,
    generation_guard: Option<&'a PolicyGenerationGuard>,
    /// Set once the head is committed.
    framing: Option<OutputFraming>,
}

impl<C: AsyncWrite + Unpin> ResponseWriter<'_, '_, C> {
    async fn write(&mut self, event: HttpBodyOutput) -> std::result::Result<(), BodyRelayError> {
        // Output the stages produced under a stale policy is never delivered.
        // The end of a body framed by its length or by the connection writes
        // nothing, so a body the client already received in full is complete
        // rather than aborted.
        let writes_nothing = matches!(
            (&event, self.framing),
            (
                HttpBodyOutput::End { .. },
                Some(OutputFraming::ContentLength { remaining: 0 } | OutputFraming::CloseDelimited)
            )
        );
        if !writes_nothing {
            self.ensure_current()?;
        }
        match (event, self.framing) {
            (
                HttpBodyOutput::Start {
                    header_mutations,
                    output_body_bytes,
                    body_transformed,
                },
                None,
            ) => {
                self.commit(&header_mutations, output_body_bytes, body_transformed)
                    .await
            }
            (HttpBodyOutput::Chunk(data), Some(framing)) => self.chunk(framing, &data).await,
            (HttpBodyOutput::End { trailers }, Some(framing)) => match framing {
                OutputFraming::ContentLength { remaining: 0 } | OutputFraming::CloseDelimited => {
                    Ok(())
                }
                OutputFraming::ContentLength { .. } => Err(BodyRelayError::Output(miette!(
                    "HTTP response middleware output is shorter than its declared length"
                ))),
                OutputFraming::Chunked => {
                    let mut terminator = b"0\r\n".to_vec();
                    for trailer in &trailers {
                        terminator.extend_from_slice(
                            format!("{}: {}\r\n", trailer.name, trailer.value).as_bytes(),
                        );
                    }
                    terminator.extend_from_slice(b"\r\n");
                    self.send(&terminator).await
                }
            },
            (event, _) => Err(BodyRelayError::Output(miette!(
                "HTTP response middleware output is out of order: {event:?}"
            ))),
        }
    }

    async fn commit(
        &mut self,
        late_mutations: &[HeaderMutation],
        output_body_bytes: Option<u64>,
        body_transformed: bool,
    ) -> std::result::Result<(), BodyRelayError> {
        // A changed body makes the upstream's representation validators
        // stale.
        let mut headers = self.headers.to_vec();
        let mut declared_trailers = self.parsed.declared_trailers.clone();
        if body_transformed {
            strip_response_integrity_headers(&mut headers);
            declared_trailers.retain(|name| {
                !openshell_supervisor_middleware::is_stale_http_response_integrity_header(name)
            });
        }
        let headers = openshell_supervisor_middleware::headers::apply_accumulated(
            openshell_supervisor_middleware::headers::HeaderAuthority::Response,
            &headers,
            &self.parsed.connection_nominated,
            late_mutations,
        )
        .map_err(|error| BodyRelayError::Output(miette!("{error}")))?;
        let framing = match output_body_bytes {
            Some(length) => OutputFraming::ContentLength { remaining: length },
            None if self.chunked => OutputFraming::Chunked,
            None => OutputFraming::CloseDelimited,
        };
        let head = serialize_response_head(
            self.status_line,
            &headers,
            &self.parsed.preserved_credential_headers,
            match framing {
                OutputFraming::ContentLength { remaining } => {
                    ResponseFraming::ContentLength(remaining)
                }
                OutputFraming::Chunked => ResponseFraming::Chunked,
                OutputFraming::CloseDelimited => ResponseFraming::Preserve(BodyLength::None),
            },
            self.connection_close || framing == OutputFraming::CloseDelimited,
            if framing == OutputFraming::Chunked {
                &declared_trailers
            } else {
                &[]
            },
        );
        // A partial write commits the response too: no canonical error
        // response may follow any byte of this head.
        self.framing = Some(framing);
        self.send(&head).await?;
        self.flush().await
    }

    async fn chunk(
        &mut self,
        framing: OutputFraming,
        data: &[u8],
    ) -> std::result::Result<(), BodyRelayError> {
        match framing {
            OutputFraming::ContentLength { remaining } => {
                let Some(remaining) = remaining.checked_sub(data.len() as u64) else {
                    return Err(BodyRelayError::Output(miette!(
                        "HTTP response middleware output exceeds its declared length"
                    )));
                };
                self.framing = Some(OutputFraming::ContentLength { remaining });
                self.send(data).await
            }
            // An empty chunk would terminate the body.
            OutputFraming::Chunked if data.is_empty() => Ok(()),
            OutputFraming::Chunked => {
                self.send(format!("{:X}\r\n", data.len()).as_bytes())
                    .await?;
                self.send(data).await?;
                self.send(b"\r\n").await
            }
            OutputFraming::CloseDelimited => self.send(data).await,
        }
    }

    fn ensure_current(&self) -> std::result::Result<(), BodyRelayError> {
        self.generation_guard
            .map_or(Ok(()), PolicyGenerationGuard::ensure_current)
            .map_err(BodyRelayError::PolicyReload)
    }

    async fn send(&mut self, bytes: &[u8]) -> std::result::Result<(), BodyRelayError> {
        self.client
            .write_all(bytes)
            .await
            .map_err(BodyRelayError::Downstream)
    }

    async fn flush(&mut self) -> std::result::Result<(), BodyRelayError> {
        self.client
            .flush()
            .await
            .map_err(BodyRelayError::Downstream)
    }
}

/// HTTP protocol 1 (0.1). Removed in 0.2.0.
///
/// Emits the OCSF events of legacy response stages from the 0.1.x invocation
/// records their adapters report as each step completes, as the 0.1.x engine
/// emitted them after each body unit.
pub(super) struct LegacyResponseReports {
    pub(super) policy_name: String,
    pub(super) target: HttpRequestTarget,
    pub(super) status_code: u16,
    /// Stages whose adapter recorded a failure, by config name. Config names
    /// are the keys of the policy's middleware map, so each names exactly one
    /// stage of this response's chain.
    pub(super) failed: Mutex<HashSet<String>>,
}

impl LegacyResponseReports {
    /// True when the adapter of `config_name` recorded a failure itself.
    fn recorded_failure(&self, config_name: &str) -> bool {
        self.failed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(config_name)
    }
}

impl StageReportSink for LegacyResponseReports {
    fn report(&self, config_name: &str, report: StageReport) {
        // A `LegacyFailOpen` report qualifies a failed invocation record the
        // adapter already reported.
        let StageReport::LegacyResponseInvocation {
            invocation,
            findings,
            ..
        } = report
        else {
            return;
        };
        if invocation.failed {
            self.failed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(config_name.to_string());
        }
        for event in legacy_response_invocation_events(
            &self.policy_name,
            &self.target,
            self.status_code,
            config_name,
            &invocation,
            findings,
        ) {
            openshell_ocsf::ocsf_emit!(event);
        }
    }
}

/// Events of one 0.1.x invocation record: the invocation, its `fail_open` or
/// block finding, and the findings of its step.
pub(super) fn legacy_response_invocation_events(
    policy_name: &str,
    target: &HttpRequestTarget,
    status_code: u16,
    config_name: &str,
    invocation: &HttpResponseInvocation,
    findings: Vec<Finding>,
) -> Vec<openshell_ocsf::OcsfEvent> {
    let mut events = http_response_middleware_invocation_events(
        policy_name,
        target,
        status_code,
        std::slice::from_ref(invocation),
    );
    events.extend(http_response_middleware_fail_open_finding_event(
        policy_name,
        target,
        invocation,
    ));
    events.extend(http_response_middleware_block_finding_event(
        policy_name,
        target,
        invocation,
    ));
    let findings: Vec<_> = findings
        .into_iter()
        .map(|finding| NamespacedFinding {
            middleware: config_name.to_string(),
            finding,
        })
        .collect();
    events.extend(crate::l7::middleware::middleware_finding_events(&findings));
    events
}

/// OCSF events for one phase of a response through the stage pipeline.
fn emit_http_response_stage_events(
    policy_name: &str,
    target: &HttpRequestTarget,
    status_code: u16,
    diagnostics: &HttpStageDiagnostics,
    legacy_reports: &LegacyResponseReports,
) {
    for event in http_response_stage_events(
        policy_name,
        target,
        status_code,
        diagnostics,
        legacy_reports,
    ) {
        openshell_ocsf::ocsf_emit!(event);
    }
}

pub(super) fn http_response_stage_events(
    policy_name: &str,
    target: &HttpRequestTarget,
    status_code: u16,
    diagnostics: &HttpStageDiagnostics,
    legacy_reports: &LegacyResponseReports,
) -> Vec<openshell_ocsf::OcsfEvent> {
    let mut events = Vec::new();
    for invocation in &diagnostics.invocations {
        // HTTP protocol 1 (0.1): the adapter reported this stage's
        // invocation records. Only a failure the pipeline recorded without
        // the adapter, such as an exhausted session budget, is emitted here.
        if invocation.protocol == Some(HttpProtocol::Legacy)
            && (!invocation.failed || legacy_reports.recorded_failure(&invocation.config_name))
        {
            continue;
        }
        let blocked = invocation.outcome == HttpStageOutcome::Reject;
        events.push(http_response_invocation_event(
            policy_name,
            target,
            status_code,
            &ResponseInvocationRecord {
                config_name: &invocation.config_name,
                implementation: &invocation.implementation,
                outcome: format!("{:?}", invocation.outcome).to_ascii_lowercase(),
                sequence: None,
                input_bytes: invocation.input_bytes,
                failed: invocation.failed,
                blocked,
                failure_reason: invocation.failure_reason.as_deref(),
            },
        ));
        if blocked {
            events.push(http_response_blocked_finding(
                policy_name,
                target,
                &invocation.config_name,
                &invocation.implementation,
            ));
        }
        // HTTP protocol 1 (0.1): only entries without a version 2
        // binding fail open, and their finding keeps the 0.1.x category.
        if let Some(category) = invocation.fail_open_category() {
            events.push(http_response_fail_open_finding(
                policy_name,
                target,
                &invocation.config_name,
                &invocation.implementation,
                category,
            ));
        }
    }
    events.extend(crate::l7::middleware::middleware_finding_events(
        &diagnostics.findings,
    ));
    events
}

/// Findings for platform capacity that refused a response's middleware, as
/// requests and WebSocket sessions report it.
pub(super) fn http_response_capacity_events(
    policy_name: &str,
    target: &HttpRequestTarget,
    preflight: &openshell_supervisor_middleware::HttpResponsePipelinePreflight,
) -> Vec<openshell_ocsf::OcsfEvent> {
    let mut events = Vec::new();
    if preflight.session_capacity_exhausted {
        events.push(
            crate::l7::middleware::middleware_session_capacity_exhausted_event(
                policy_name,
                &target.host,
                openshell_supervisor_middleware::HttpDirection::Response.as_str(),
            ),
        );
    }
    if preflight.admission_exhausted {
        events.push(crate::l7::middleware::middleware_admission_exhausted_event(
            policy_name,
            &target.host,
            openshell_supervisor_middleware::HttpDirection::Response,
        ));
    }
    events
}

/// The response was committed when the stages failed or rejected it, or its
/// upstream failed, so delivery was aborted.
fn emit_http_response_middleware_abort(
    policy_name: &str,
    target: &HttpRequestTarget,
    status_code: u16,
    framing: OutputFraming,
) {
    let status_code = status_code.to_string();
    let event = openshell_ocsf::DetectionFindingBuilder::new(ocsf_ctx())
        .severity(openshell_ocsf::SeverityId::High)
        .finding_info(openshell_ocsf::FindingInfo::new(
            "openshell.middleware.http_response_failure",
            "HTTP response middleware delivery failure",
        ))
        .evidence_pairs(&[
            ("policy", policy_name),
            ("host", target.host.as_str()),
            ("commitment", "after_commit"),
            ("upstream_status", status_code.as_str()),
            ("downstream_framing", framing.name()),
        ])
        .message("HTTP response middleware failed after response commitment; delivery aborted")
        .build();
    openshell_ocsf::ocsf_emit!(event);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A policy reload after the stages delivered a body in full aborts
    /// nothing: the end of a body framed by its length or by the connection
    /// writes no stale output. The end of a chunked body writes its
    /// terminator, so it fails.
    #[tokio::test]
    async fn the_end_of_a_delivered_body_writes_nothing_under_a_reloaded_policy() {
        const TEST_POLICY: &str = include_str!("../../../../data/sandbox-policy.rego");
        let parsed = parse_response_head_for_middleware(b"HTTP/1.1 200 OK\r\n\r\n").expect("head");
        for (output_body_bytes, chunked, completes) in [
            (Some(5), true, true),
            (None, false, true),
            (None, true, false),
        ] {
            let engine = crate::opa::OpaEngine::from_strings(TEST_POLICY, "network_policies: {}\n")
                .expect("policy");
            let guard = engine
                .generation_guard(engine.current_generation())
                .expect("generation guard");
            let (mut relay_side, _client) = tokio::io::duplex(1024);
            let mut writer = ResponseWriter {
                client: &mut relay_side,
                status_line: "HTTP/1.1 200 OK",
                headers: &parsed.headers,
                parsed: &parsed,
                chunked,
                connection_close: false,
                generation_guard: Some(&guard),
                framing: None,
            };
            writer
                .write(HttpBodyOutput::Start {
                    header_mutations: Vec::new(),
                    output_body_bytes,
                    body_transformed: false,
                })
                .await
                .expect("head");
            writer
                .write(HttpBodyOutput::Chunk(b"hello".to_vec()))
                .await
                .expect("body");
            engine
                .reload(TEST_POLICY, "network_policies: {}\n")
                .expect("policy reload");
            let ended = writer
                .write(HttpBodyOutput::End {
                    trailers: Vec::new(),
                })
                .await;
            assert_eq!(
                ended.is_ok(),
                completes,
                "declared length {output_body_bytes:?}, chunked {chunked}: {ended:?}"
            );
        }
    }
}
