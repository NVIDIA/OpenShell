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
//! and the connection closes. STREAM has no total deadline, and upstream
//! silence never fails a response. As for an uninspected response, an
//! upstream body without framing ends when the upstream closes, or, except for
//! server-sent events, after the relay's idle timeout.

use openshell_core::proto::MiddlewareSessionEndReason;
use openshell_supervisor_middleware::{
    HttpBodyInput, HttpBodyOutput, HttpResponseDelivery, HttpStageDiagnostics, HttpStageOutcome,
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
    let delivery = HttpResponseDelivery {
        buffered_body_timeout: middleware.whole_body_timeout,
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
    );
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
        let relayed = tokio::try_join!(feed, write).map(drop);
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
            );
            Err(error)
        }
    };
    let committed = framing.is_some();
    match failure {
        Err(error @ BodyRelayError::Downstream(_)) => Err(error.into_report()),
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
        if let Some(guard) = self.generation_guard {
            guard
                .ensure_current()
                .map_err(BodyRelayError::PolicyReload)?;
        }
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

/// OCSF events for one phase of a response through the stage pipeline.
fn emit_http_response_stage_events(
    policy_name: &str,
    target: &HttpRequestTarget,
    status_code: u16,
    diagnostics: &HttpStageDiagnostics,
) {
    for event in http_response_stage_events(policy_name, target, status_code, diagnostics) {
        openshell_ocsf::ocsf_emit!(event);
    }
}

fn http_response_stage_events(
    policy_name: &str,
    target: &HttpRequestTarget,
    status_code: u16,
    diagnostics: &HttpStageDiagnostics,
) -> Vec<openshell_ocsf::OcsfEvent> {
    let mut events = Vec::new();
    for invocation in &diagnostics.invocations {
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
        // HTTP protocol 1 (0.1): an adapter that reported its fail-open
        // outcome emits the finding with its own invocation record.
        let reported = diagnostics.reports.iter().any(|(config_name, report)| {
            config_name == &invocation.config_name && report.fail_open_reason().is_some()
        });
        if invocation.outcome == HttpStageOutcome::FailOpen && !reported {
            events.push(http_response_fail_open_finding(
                policy_name,
                target,
                &invocation.config_name,
                &invocation.implementation,
                invocation
                    .failure_reason
                    .as_deref()
                    .unwrap_or("middleware_failure"),
            ));
        }
    }
    events.extend(crate::l7::middleware::middleware_finding_events(
        &diagnostics.findings,
    ));
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
