// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP response relay and pre-return middleware integration.

mod pipeline;
#[cfg(test)]
mod pipeline_tests;

use super::*;

/// Default wall-clock bound of each whole-body stage in one response.
pub const DEFAULT_HTTP_RESPONSE_WHOLE_BODY_TIMEOUT: std::time::Duration =
    std::time::Duration::from_mins(2);

/// Context retained from request evaluation for the matching response hook.
pub struct HttpResponseMiddlewareRelay<'a> {
    pub(crate) chain: &'a [openshell_supervisor_middleware::ChainEntry],
    pub(crate) runner: &'a openshell_supervisor_middleware::ChainRunner,
    pub(crate) request_context: RequestContext,
    pub(crate) target: HttpRequestTarget,
    pub(crate) policy_name: &'a str,
    pub(crate) generation_guard: Option<&'a PolicyGenerationGuard>,
    pub(crate) whole_body_timeout: std::time::Duration,
    /// The client request used HTTP/1.1, so a re-framed response may be
    /// chunked. An HTTP/1.0 client cannot decode chunked framing.
    pub(crate) client_accepts_chunked: bool,
}

#[derive(Clone)]
pub(super) struct RelayResponseOptions<'a> {
    pub(super) websocket_extensions: WebSocketExtensionMode,
    pub(super) client_requested_upgrade: bool,
    pub(super) websocket: Option<WebSocketResponseValidation>,
    pub(super) observer: Option<&'a EndpointObserver>,
}

impl Default for RelayResponseOptions<'_> {
    fn default() -> Self {
        Self {
            websocket_extensions: WebSocketExtensionMode::Preserve,
            client_requested_upgrade: true,
            websocket: None,
            observer: None,
        }
    }
}

/// Relay the response to a request whose body has been read, ending it when
/// the client goes away (see `client_link`).
pub(super) async fn relay_response<U, C>(
    request_method: &str,
    upstream: &mut U,
    client: &mut C,
    options: RelayResponseOptions<'_>,
    response_middleware: Option<HttpResponseMiddlewareRelay<'_>>,
) -> Result<RelayOutcome>
where
    U: AsyncRead + Unpin,
    C: AsyncBufRead + AsyncWrite + Unpin,
{
    let link = ClientLink::new(client);
    link.arm();
    relay_response_to(
        request_method,
        upstream,
        &link,
        options,
        response_middleware,
    )
    .await
}

/// Relay the response to `link`'s client. The caller arms the watch once the
/// request body has been read.
pub(super) async fn relay_response_to<U, C>(
    request_method: &str,
    upstream: &mut U,
    link: &ClientLink<'_, C>,
    options: RelayResponseOptions<'_>,
    response_middleware: Option<HttpResponseMiddlewareRelay<'_>>,
) -> Result<RelayOutcome>
where
    U: AsyncRead + Unpin,
    C: AsyncBufRead + AsyncWrite + Unpin,
{
    let mut upstream = ProgressReader {
        upstream,
        progress: link.progress(),
    };
    let outcome = Box::pin(relay_watched_response(
        request_method,
        &mut upstream,
        link,
        options,
        response_middleware,
    ))
    .await
    .map_err(|error| link.downstream_closed_or(error))?;
    // A half-closed client sends no further request.
    if link.half_closed() && matches!(outcome, RelayOutcome::Reusable) {
        return finish_response(&mut link.writer(), true)
            .await
            .map_err(|error| link.downstream_closed_or(error));
    }
    Ok(outcome)
}

/// Run one phase of the response relay until it ends or the client is gone.
/// Only phases that hold no middleware session may be cut this way.
async fn until_client_gone<C, T>(
    link: &ClientLink<'_, C>,
    relay: impl Future<Output = Result<T>>,
) -> Result<T>
where
    C: AsyncBufRead + Unpin,
{
    tokio::select! {
        biased;
        relayed = relay => relayed,
        gone = link.gone() => {
            debug!(%gone, "HTTP response relay stopped");
            Err(miette::Report::new(DownstreamClosed { gone }))
        }
    }
}

async fn relay_watched_response<U, C>(
    request_method: &str,
    upstream: &mut U,
    link: &ClientLink<'_, C>,
    options: RelayResponseOptions<'_>,
    response_middleware: Option<HttpResponseMiddlewareRelay<'_>>,
) -> Result<RelayOutcome>
where
    U: AsyncRead + Unpin,
    C: AsyncBufRead + AsyncWrite + Unpin,
{
    let started_at = std::time::Instant::now();
    let mut client = link.writer();
    let Some((buf, header_end)) = until_client_gone(
        link,
        read_final_response_head(upstream, &mut client, options.observer),
    )
    .await?
    else {
        return Ok(RelayOutcome::Consumed);
    };

    // Parse response framing
    let header_str = String::from_utf8_lossy(&buf[..header_end]);
    let observed_status = parse_observed_http_status_code(&header_str);
    if let Some(observer) = options.observer.as_ref() {
        match observed_status {
            Some(status_code) if status_code < 400 => {
                observer.observe(EndpointResult::HttpResponseReceived);
            }
            Some(_) => observer.observe(EndpointResult::UpstreamRejected),
            None => observer.observe(EndpointResult::TransportFailed),
        }
    }
    let status_code = parse_status_code(&header_str).unwrap_or(200);
    let server_wants_close = parse_connection_close(&header_str);
    let http_10_closes_by_default =
        response_is_http_10(&header_str) && !parse_connection_keep_alive(&header_str);
    let event_stream = response_is_event_stream(&header_str);
    let body_length = parse_body_length(&header_str)?;

    debug!(
        status_code,
        ?body_length,
        server_wants_close,
        request_method,
        overflow_bytes = buf.len() - header_end,
        "relay_response framing"
    );

    // 101 Switching Protocols: the connection has been upgraded (e.g. to
    // WebSocket).  Forward the 101 headers to the client and signal the
    // caller to switch to raw bidirectional TCP relay.  Any bytes read
    // from upstream beyond the headers are overflow that belong to the
    // upgraded protocol and must be forwarded before switching.
    if status_code == 101 {
        if !options.client_requested_upgrade {
            return Ok(RelayOutcome::Consumed);
        }
        let (websocket_permessage_deflate, websocket_subprotocol) = validate_websocket_response(
            &header_str,
            options.websocket_extensions,
            options.websocket.as_ref(),
        )?;
        client
            .write_all(&buf[..header_end])
            .await
            .into_diagnostic()?;
        client.flush().await.into_diagnostic()?;
        let overflow = buf[header_end..].to_vec();
        debug!(
            request_method,
            overflow_bytes = overflow.len(),
            "101 Switching Protocols — signaling protocol upgrade"
        );
        return Ok(RelayOutcome::Upgraded {
            overflow,
            websocket_permessage_deflate,
            websocket_subprotocol,
        });
    }

    if let Some(response_middleware) = response_middleware
        && let Some(outcome) = Box::pin(relay_response_through_middleware(
            request_method,
            upstream,
            link,
            response_middleware,
            &buf,
            header_end,
            status_code,
            body_length,
            server_wants_close || http_10_closes_by_default,
            event_stream,
        ))
        .await?
    {
        return if matches!(outcome, RelayOutcome::Consumed) {
            finish_response(&mut client, true).await
        } else {
            Ok(outcome)
        };
    }

    until_client_gone(
        link,
        Box::pin(relay_uninspected_response(
            request_method,
            upstream,
            &mut client,
            &buf,
            header_end,
            body_length,
            status_code,
            server_wants_close || http_10_closes_by_default,
            event_stream,
            started_at,
        )),
    )
    .await
}

/// Read the upstream response up to its final head, forwarding interim
/// responses unchanged. Returns the bytes read and the end of the final
/// head, or `None` when the upstream closed first.
async fn read_final_response_head<U, C>(
    upstream: &mut U,
    client: &mut ClientWriter<'_, '_, C>,
    observer: Option<&EndpointObserver>,
) -> Result<Option<(Vec<u8>, usize)>>
where
    U: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];
    // Retain the final response head until response middleware preflight
    // completes.
    let mut informational_header_bytes = 0;
    loop {
        let header_end = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|end| end + 4);
        let remaining_header_bytes = MAX_HEADER_BYTES - informational_header_bytes;
        if header_end.is_some_and(|end| end > remaining_header_bytes)
            || (header_end.is_none() && buf.len() >= remaining_header_bytes)
        {
            if let Some(observer) = observer {
                observer.observe(EndpointResult::TransportFailed);
            }
            return Err(miette!("HTTP response headers exceed limit"));
        }

        if let Some(header_end) = header_end {
            let header_str = String::from_utf8_lossy(&buf[..header_end]);
            if matches!(
                parse_observed_http_status_code(&header_str),
                Some(100 | 102..=199)
            ) {
                informational_header_bytes += header_end;
                client
                    .write_all(&buf[..header_end])
                    .await
                    .into_diagnostic()?;
                client.flush().await.into_diagnostic()?;
                buf.drain(..header_end);
                continue;
            }
            return Ok(Some((buf, header_end)));
        }

        let n = upstream.read(&mut tmp).await.into_diagnostic()?;
        if n == 0 {
            if let Some(observer) = observer {
                observer.observe(EndpointResult::TransportFailed);
            }
            if !buf.is_empty() {
                client.write_all(&buf).await.into_diagnostic()?;
            }
            return Ok(None);
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// Relay a response no middleware session inspects.
#[allow(clippy::too_many_arguments)]
async fn relay_uninspected_response<U, C>(
    request_method: &str,
    upstream: &mut U,
    client: &mut ClientWriter<'_, '_, C>,
    buf: &[u8],
    header_end: usize,
    body_length: BodyLength,
    status_code: u16,
    closes: bool,
    event_stream: bool,
    started_at: std::time::Instant,
) -> Result<RelayOutcome>
where
    U: AsyncRead + Unpin,
    C: AsyncBufRead + AsyncWrite + Unpin,
{
    // Bodiless responses (HEAD, 1xx, 204, 304): forward headers only, skip body
    if is_bodiless_response(request_method, status_code) {
        client
            .write_all(&buf[..header_end])
            .await
            .into_diagnostic()?;
        client.head_delivered();
        return finish_response(client, closes).await;
    }

    // No explicit framing (no Content-Length, no Transfer-Encoding).
    // Per RFC 7230 §3.3.3 the body is delimited by connection close.
    if matches!(body_length, BodyLength::None) {
        if closes || event_stream {
            // Server indicated it will close, or this is a streaming response
            // such as SSE where the body is intentionally delimited by EOF.
            let before_end = &buf[..header_end - 2];
            client.write_all(before_end).await.into_diagnostic()?;
            if closes {
                client
                    .write_all(b"Connection: close\r\n\r\n")
                    .await
                    .into_diagnostic()?;
            } else {
                client.write_all(b"\r\n").await.into_diagnostic()?;
            }
            client.head_delivered();
            let overflow = &buf[header_end..];
            if !overflow.is_empty() {
                client.write_all(overflow).await.into_diagnostic()?;
                client.flush().await.into_diagnostic()?;
            }
            if event_stream {
                relay_until_eof_without_idle_timeout(upstream, client).await?;
            } else {
                relay_until_eof(upstream, client).await?;
            }
            client.flush().await.into_diagnostic()?;
            client.shutdown().await.into_diagnostic()?;
            return Ok(RelayOutcome::Consumed);
        }
        // No Connection: close — an HTTP/1.1 keep-alive server that omits
        // framing headers has an empty body.  Forward headers and continue
        // the relay loop instead of blocking on relay_until_eof.
        debug!("BodyLength::None without Connection: close — treating body as empty");
        client
            .write_all(&buf[..header_end])
            .await
            .into_diagnostic()?;
        client.head_delivered();
        client.flush().await.into_diagnostic()?;
        return Ok(RelayOutcome::Reusable);
    }

    // Forward response headers + any overflow body bytes
    client.write_all(buf).await.into_diagnostic()?;
    client.head_delivered();
    let overflow_len = (buf.len() - header_end) as u64;

    // Forward remaining response body
    match body_length {
        BodyLength::ContentLength(len) => {
            let remaining = len.saturating_sub(overflow_len);
            if remaining > 0 {
                relay_fixed(upstream, client, remaining, None).await?;
            }
        }
        BodyLength::Chunked => {
            relay_chunked(upstream, client, &buf[header_end..], None).await?;
        }
        BodyLength::None => unreachable!(),
    }
    client.flush().await.into_diagnostic()?;
    debug!(
        request_method,
        elapsed_ms = started_at.elapsed().as_millis(),
        "relay_response complete (explicit framing)"
    );

    finish_response(client, closes).await
}

/// Body framing determines when delivery finishes, not whether another
/// request is permitted. Signal EOF (including TLS `close_notify`) before the
/// caller tears down a closing CONNECT tunnel; waiting for another request
/// deadlocks clients that are themselves waiting for EOF.
pub(super) async fn finish_response<C>(client: &mut C, close: bool) -> Result<RelayOutcome>
where
    C: AsyncWrite + Unpin,
{
    client.flush().await.into_diagnostic()?;
    if close {
        client.shutdown().await.into_diagnostic()?;
        Ok(RelayOutcome::Consumed)
    } else {
        Ok(RelayOutcome::Reusable)
    }
}

#[allow(clippy::too_many_arguments)]
async fn relay_response_through_middleware<U, C>(
    request_method: &str,
    upstream: &mut U,
    link: &ClientLink<'_, C>,
    middleware: HttpResponseMiddlewareRelay<'_>,
    buffered: &[u8],
    header_end: usize,
    status_code: u16,
    body_length: BodyLength,
    server_wants_close: bool,
    event_stream: bool,
) -> Result<Option<RelayOutcome>>
where
    U: AsyncRead + Unpin,
    C: AsyncBufRead + AsyncWrite + Unpin,
{
    if let Some(guard) = middleware.generation_guard {
        guard.ensure_current()?;
    }
    let header_bytes = &buffered[..header_end];
    // Ordinary responses retain the HTTP parser's byte-preserving behavior.
    // Response-specific normalization and limits apply only to selected hooks.
    if middleware.chain.is_empty() {
        return Ok(None);
    }
    let parsed = match middleware
        .runner
        .describe_http_response_chain(middleware.chain)
        .await
    {
        Ok(described) if described.is_empty() => return Ok(None),
        Ok(described) => {
            parse_response_head_for_middleware(header_bytes).map(|parsed| (described, parsed))
        }
        Err(error) => Err(error),
    };
    if let Some(guard) = middleware.generation_guard {
        guard.ensure_current()?;
    }
    let (described, parsed) = match parsed {
        Ok(parsed) => parsed,
        Err(error) => {
            debug!(error = %error, "HTTP response head normalization failed");
            emit_http_response_middleware_failure(
                middleware.policy_name,
                &middleware.target,
                status_code,
                false,
            );
            send_response_delivery_failure(
                &mut link.writer(),
                request_method,
                middleware.policy_name,
                &middleware.target,
            )
            .await?;
            return Ok(Some(RelayOutcome::Consumed));
        }
    };
    Box::pin(pipeline::relay_response_through_pipeline(
        request_method,
        upstream,
        link,
        middleware,
        described,
        parsed,
        buffered,
        header_end,
        status_code,
        body_length,
        server_wants_close,
        event_stream,
    ))
    .await
}

#[allow(clippy::too_many_arguments)]
async fn relay_headers_only_response<U, C>(
    request_method: &str,
    upstream: &mut U,
    client: &mut ClientWriter<'_, '_, C>,
    status_line: &str,
    headers: &[HttpHeader],
    preserved_credential_headers: &[String],
    declared_trailers: &[String],
    overflow: &[u8],
    status_code: u16,
    body_length: BodyLength,
    server_wants_close: bool,
    event_stream: bool,
) -> Result<RelayOutcome>
where
    U: AsyncRead + Unpin,
    C: AsyncBufRead + AsyncWrite + Unpin,
{
    let head = serialize_response_head(
        status_line,
        headers,
        preserved_credential_headers,
        ResponseFraming::Preserve(body_length),
        server_wants_close,
        declared_trailers,
    );
    client.write_all(&head).await.into_diagnostic()?;
    client.head_delivered();

    if is_bodiless_response(request_method, status_code) {
        client.flush().await.into_diagnostic()?;
        return Ok(if server_wants_close {
            RelayOutcome::Consumed
        } else {
            RelayOutcome::Reusable
        });
    }

    client.write_all(overflow).await.into_diagnostic()?;
    match body_length {
        BodyLength::ContentLength(length) => {
            let remaining = length.saturating_sub(overflow.len() as u64);
            if remaining > 0 {
                relay_fixed(upstream, client, remaining, None).await?;
            }
        }
        BodyLength::Chunked => relay_chunked(upstream, client, overflow, None).await?,
        BodyLength::None if server_wants_close || event_stream => {
            if event_stream {
                relay_until_eof_without_idle_timeout(upstream, client).await?;
            } else {
                relay_until_eof(upstream, client).await?;
            }
            client.flush().await.into_diagnostic()?;
            return Ok(RelayOutcome::Consumed);
        }
        BodyLength::None => {}
    }
    client.flush().await.into_diagnostic()?;
    Ok(if server_wants_close {
        RelayOutcome::Consumed
    } else {
        RelayOutcome::Reusable
    })
}

/// One stage invocation as a response middleware OCSF event records it.
struct ResponseInvocationRecord<'a> {
    config_name: &'a str,
    implementation: &'a str,
    outcome: String,
    /// HTTP protocol 1 (0.1): the body unit the record describes.
    sequence: Option<u64>,
    input_bytes: usize,
    failed: bool,
    blocked: bool,
    /// Platform-owned reason of a failed or cancelled stage.
    failure_reason: Option<&'a str>,
}

fn http_response_invocation_event(
    policy_name: &str,
    target: &HttpRequestTarget,
    status_code: u16,
    record: &ResponseInvocationRecord<'_>,
) -> openshell_ocsf::OcsfEvent {
    let ResponseInvocationRecord {
        config_name,
        implementation,
        outcome,
        sequence,
        input_bytes,
        failed,
        blocked,
        failure_reason,
    } = record;
    let (failed, blocked) = (*failed, *blocked);
    let mut message = format!(
        "HTTP_RESPONSE_MIDDLEWARE config={config_name} implementation={implementation} outcome={outcome}"
    );
    if let Some(sequence) = sequence {
        write!(&mut message, " sequence={sequence}").expect("writing to a String cannot fail");
    }
    write!(&mut message, " input_bytes={input_bytes} failed={failed}")
        .expect("writing to a String cannot fail");
    if let Some(reason) = failure_reason {
        write!(&mut message, " reason={reason}").expect("writing to a String cannot fail");
    }
    let mut builder = openshell_ocsf::HttpActivityBuilder::new(ocsf_ctx())
        .activity(openshell_ocsf::ActivityId::Other)
        .action(if blocked {
            openshell_ocsf::ActionId::Denied
        } else if failed {
            openshell_ocsf::ActionId::Other
        } else {
            openshell_ocsf::ActionId::Allowed
        })
        .disposition(if blocked {
            openshell_ocsf::DispositionId::Blocked
        } else if failed {
            openshell_ocsf::DispositionId::Error
        } else {
            openshell_ocsf::DispositionId::Allowed
        })
        .severity(if failed || blocked {
            openshell_ocsf::SeverityId::Medium
        } else {
            openshell_ocsf::SeverityId::Informational
        })
        .status(if failed || blocked || failure_reason.is_some() {
            openshell_ocsf::StatusId::Failure
        } else {
            openshell_ocsf::StatusId::Success
        })
        .http_request(openshell_ocsf::HttpRequest::new(
            &target.method,
            openshell_ocsf::Url::new(
                &target.scheme,
                &target.host,
                &target.path,
                u16::try_from(target.port).unwrap_or_default(),
            ),
        ))
        .http_response(openshell_ocsf::HttpResponse { code: status_code })
        .dst_endpoint(openshell_ocsf::Endpoint::from_domain(
            &target.host,
            u16::try_from(target.port).unwrap_or_default(),
        ))
        .firewall_rule(policy_name, "supervisor-middleware")
        .unmapped("middleware_config", *config_name)
        .unmapped("middleware_implementation", *implementation)
        .unmapped("response_middleware_outcome", outcome.as_str());
    if let Some(sequence) = sequence {
        builder = builder.unmapped("sequence", *sequence);
    }
    builder = builder
        .unmapped("input_bytes", *input_bytes)
        .unmapped("failed", failed);
    if let Some(reason) = failure_reason {
        builder = builder.unmapped("failure_reason", *reason);
    }
    builder.message(message).build()
}

pub(super) fn http_response_middleware_invocation_events(
    policy_name: &str,
    target: &HttpRequestTarget,
    status_code: u16,
    invocations: &[openshell_supervisor_middleware::HttpResponseInvocation],
) -> Vec<openshell_ocsf::OcsfEvent> {
    invocations
        .iter()
        .map(|invocation| {
            http_response_invocation_event(
                policy_name,
                target,
                status_code,
                &ResponseInvocationRecord {
                    config_name: &invocation.config_name,
                    implementation: &invocation.implementation,
                    outcome: format!("{:?}", invocation.outcome).to_ascii_lowercase(),
                    sequence: Some(invocation.sequence.unwrap_or_default()),
                    input_bytes: invocation.input_size,
                    failed: invocation.failed,
                    blocked: invocation.outcome
                        == openshell_supervisor_middleware::HttpResponseInvocationOutcome::BlockDelivery,
                    failure_reason: None,
                },
            )
        })
        .collect()
}

fn http_response_middleware_block_finding_event(
    policy_name: &str,
    target: &HttpRequestTarget,
    invocation: &openshell_supervisor_middleware::HttpResponseInvocation,
) -> Option<openshell_ocsf::OcsfEvent> {
    (invocation.outcome
        == openshell_supervisor_middleware::HttpResponseInvocationOutcome::BlockDelivery)
        .then(|| {
            http_response_blocked_finding(
                policy_name,
                target,
                &invocation.config_name,
                &invocation.implementation,
            )
        })
}

fn http_response_blocked_finding(
    policy_name: &str,
    target: &HttpRequestTarget,
    config_name: &str,
    implementation: &str,
) -> openshell_ocsf::OcsfEvent {
    openshell_ocsf::DetectionFindingBuilder::new(ocsf_ctx())
        .severity(openshell_ocsf::SeverityId::Medium)
        .finding_info(openshell_ocsf::FindingInfo::new(
            "openshell.middleware.http_response_blocked",
            "HTTP response blocked by middleware",
        ))
        .evidence_pairs(&[
            ("policy", policy_name),
            ("middleware_config", config_name),
            ("middleware_implementation", implementation),
            ("host", target.host.as_str()),
            ("phase", "pre_return"),
        ])
        .unmapped("middleware_config", config_name)
        .unmapped("middleware_implementation", implementation)
        .unmapped("phase", "pre_return")
        .message("HTTP response delivery blocked by middleware")
        .build()
}

pub(super) fn http_response_middleware_fail_open_finding_event(
    policy_name: &str,
    target: &HttpRequestTarget,
    invocation: &openshell_supervisor_middleware::HttpResponseInvocation,
) -> Option<openshell_ocsf::OcsfEvent> {
    if !invocation.failed
        || invocation.outcome
            != openshell_supervisor_middleware::HttpResponseInvocationOutcome::FailOpen
    {
        return None;
    }
    Some(http_response_fail_open_finding(
        policy_name,
        target,
        &invocation.config_name,
        &invocation.implementation,
        invocation
            .failure_category
            .as_deref()
            .unwrap_or("middleware_failure"),
    ))
}

fn http_response_fail_open_finding(
    policy_name: &str,
    target: &HttpRequestTarget,
    config_name: &str,
    implementation: &str,
    failure_category: &str,
) -> openshell_ocsf::OcsfEvent {
    openshell_ocsf::DetectionFindingBuilder::new(ocsf_ctx())
        .severity(openshell_ocsf::SeverityId::Medium)
        .finding_info(openshell_ocsf::FindingInfo::new(
            "openshell.middleware.http_response_fail_open",
            "HTTP response middleware failed open",
        ))
        .evidence_pairs(&[
            ("policy", policy_name),
            ("middleware_config", config_name),
            ("middleware_implementation", implementation),
            ("host", target.host.as_str()),
            ("phase", "pre_return"),
            ("failure_category", failure_category),
        ])
        .unmapped("middleware_config", config_name)
        .unmapped("middleware_implementation", implementation)
        .unmapped("phase", "pre_return")
        .unmapped("failure_category", failure_category)
        .message("HTTP response middleware failed and response inspection was bypassed")
        .build()
}

fn emit_http_response_middleware_failure(
    policy_name: &str,
    target: &HttpRequestTarget,
    status_code: u16,
    committed: bool,
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
            (
                "commitment",
                if committed {
                    "after_commit"
                } else {
                    "before_commit"
                },
            ),
            ("upstream_status", status_code.as_str()),
        ])
        .message(if committed {
            "HTTP response middleware failed after response commitment"
        } else {
            "HTTP response middleware failed before response commitment"
        })
        .build();
    openshell_ocsf::ocsf_emit!(event);
}

#[derive(Debug)]
struct ParsedResponseHead {
    representable: bool,
    headers: Vec<HttpHeader>,
    preserved_credential_headers: Vec<String>,
    connection_nominated: Vec<String>,
    declared_trailers: Vec<String>,
}

fn parse_response_head_for_middleware(header_bytes: &[u8]) -> Result<ParsedResponseHead> {
    // Lossy decoding preserves ASCII syntax and control bytes for validation.
    // Never pass replacement text to middleware or use it for delivery.
    let header = String::from_utf8_lossy(header_bytes);
    let representable = std::str::from_utf8(header_bytes).is_ok();
    if parse_status_code(&header).is_none() {
        return Err(miette!("HTTP response status line is malformed"));
    }
    let mut nominated = HashSet::new();
    let mut declared_trailers = Vec::new();
    for line in header.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        validate_http_field_name(name)?;
        validate_http_field_value(value.trim())?;
        if name.eq_ignore_ascii_case("connection") {
            for token in value
                .split(',')
                .map(str::trim)
                .filter(|token| !token.is_empty())
            {
                nominated.insert(token.to_ascii_lowercase());
            }
        } else if name.eq_ignore_ascii_case("trailer") {
            for token in parse_http_token_list(value)? {
                let token = token.to_ascii_lowercase();
                if !declared_trailers.contains(&token) {
                    declared_trailers.push(token);
                }
            }
        }
    }
    for trailer in &declared_trailers {
        if is_protected_response_field(trailer) || nominated.contains(trailer) {
            return Err(miette!("HTTP response declares a protected trailer field"));
        }
    }
    let mut headers = Vec::new();
    let mut preserved_credential_headers = Vec::new();
    for line in header.split("\r\n").skip(1).filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| miette!("Malformed HTTP response header field"))?;
        validate_http_field_name(name)?;
        validate_http_field_value(value.trim())?;
        let name = name.to_ascii_lowercase();
        if openshell_supervisor_middleware::headers::is_response_credential_header(&name) {
            // Middleware must not observe credential-bearing response fields.
            // Keep the original line separately so downstream delivery retains
            // its exact name, whitespace, and value bytes.
            preserved_credential_headers.push(line.to_string());
            continue;
        }
        if nominated.contains(&name) || is_hidden_response_field(&name) {
            continue;
        }
        headers.push(HttpHeader {
            name,
            value: value.trim().to_string(),
        });
    }
    let mut connection_nominated: Vec<_> = nominated.into_iter().collect();
    connection_nominated.sort();
    Ok(ParsedResponseHead {
        representable,
        headers: if representable { headers } else { Vec::new() },
        preserved_credential_headers: if representable {
            preserved_credential_headers
        } else {
            Vec::new()
        },
        connection_nominated,
        declared_trailers,
    })
}

fn validate_http_field_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
    {
        return Err(miette!("HTTP response field name is malformed"));
    }
    Ok(())
}

fn validate_http_field_value(value: &str) -> Result<()> {
    if value
        .bytes()
        .any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
    {
        return Err(miette!("HTTP response field value contains a control byte"));
    }
    Ok(())
}

fn is_protected_response_field(name: &str) -> bool {
    name.eq_ignore_ascii_case("content-length")
        || is_hidden_response_field(name)
        || openshell_supervisor_middleware::headers::is_response_credential_header(name)
}

fn is_hidden_response_field(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn response_status_line(header_bytes: &[u8]) -> Result<String> {
    let line_end = header_bytes
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or_else(|| miette!("HTTP response status line is incomplete"))?;
    std::str::from_utf8(&header_bytes[..line_end])
        .map(str::to_string)
        .map_err(|_| miette!("HTTP response status line contains invalid UTF-8"))
}

#[derive(Clone, Copy)]
enum ResponseFraming {
    Preserve(BodyLength),
    ContentLength(u64),
    Chunked,
}

fn serialize_response_head(
    status_line: &str,
    headers: &[HttpHeader],
    preserved_credential_headers: &[String],
    framing: ResponseFraming,
    connection_close: bool,
    trailer_names: &[String],
) -> Vec<u8> {
    let mut output = format!("{status_line}\r\n");
    for header in headers {
        // Content-Length is read-only middleware metadata. The relay emits the
        // final framing exactly once from `framing` below.
        if header.name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        output.push_str(&header.name);
        output.push_str(": ");
        output.push_str(&header.value);
        output.push_str("\r\n");
    }
    for header in preserved_credential_headers {
        output.push_str(header);
        output.push_str("\r\n");
    }
    match framing {
        ResponseFraming::Preserve(BodyLength::ContentLength(length))
        | ResponseFraming::ContentLength(length) => {
            write!(&mut output, "Content-Length: {length}\r\n")
                .expect("writing to a String cannot fail");
        }
        ResponseFraming::Preserve(BodyLength::Chunked) | ResponseFraming::Chunked => {
            output.push_str("Transfer-Encoding: chunked\r\n");
        }
        ResponseFraming::Preserve(BodyLength::None) => {}
    }
    if !trailer_names.is_empty() {
        output.push_str("Trailer: ");
        output.push_str(&trailer_names.join(", "));
        output.push_str("\r\n");
    }
    if connection_close {
        output.push_str("Connection: close\r\n");
    }
    output.push_str("\r\n");
    output.into_bytes()
}

pub(super) fn strip_response_integrity_headers(headers: &mut Vec<HttpHeader>) {
    headers.retain(|header| {
        !openshell_supervisor_middleware::is_stale_http_response_integrity_header(&header.name)
    });
}

struct BufferedResponseReader<'a, R> {
    upstream: &'a mut R,
    buffered: &'a [u8],
    position: usize,
    exact_buffer: Vec<u8>,
    exact_target: Option<usize>,
    line_buffer: Vec<u8>,
}

impl<'a, R: AsyncRead + Unpin> BufferedResponseReader<'a, R> {
    fn new(upstream: &'a mut R, buffered: &'a [u8]) -> Self {
        Self {
            upstream,
            buffered,
            position: 0,
            exact_buffer: Vec::new(),
            exact_target: None,
            line_buffer: Vec::new(),
        }
    }

    async fn read_some(&mut self, limit: usize) -> Result<Option<Vec<u8>>> {
        if self.position < self.buffered.len() {
            let end = self.position.saturating_add(limit).min(self.buffered.len());
            let data = self.buffered[self.position..end].to_vec();
            self.position = end;
            return Ok(Some(data));
        }
        let mut data = vec![0u8; limit.max(1)];
        let count = self.upstream.read(&mut data).await.into_diagnostic()?;
        if count == 0 {
            return Ok(None);
        }
        data.truncate(count);
        Ok(Some(data))
    }

    async fn read_exact_vec(&mut self, length: usize) -> Result<Vec<u8>> {
        match self.exact_target {
            Some(target) if target != length => {
                return Err(miette!("HTTP response reader exact-read state mismatch"));
            }
            None => {
                self.exact_target = Some(length);
                self.exact_buffer.reserve(length);
            }
            Some(_) => {}
        }
        while self.exact_buffer.len() < length {
            let remaining = length - self.exact_buffer.len();
            let Some(data) = self.read_some(remaining).await? else {
                return Err(miette!("HTTP response body ended unexpectedly"));
            };
            self.exact_buffer.extend_from_slice(&data);
        }
        self.exact_target = None;
        Ok(std::mem::take(&mut self.exact_buffer))
    }

    async fn read_line(&mut self) -> Result<Vec<u8>> {
        loop {
            let Some(byte) = self.read_some(1).await? else {
                return Err(miette!("HTTP response ended before line terminator"));
            };
            self.line_buffer.push(byte[0]);
            if self.line_buffer.len() > MAX_HEADER_BYTES {
                return Err(miette!("HTTP response line exceeds limit"));
            }
            if self.line_buffer.ends_with(b"\r\n") {
                self.line_buffer.truncate(self.line_buffer.len() - 2);
                return Ok(std::mem::take(&mut self.line_buffer));
            }
        }
    }
}

/// Validate one trailer section line and add its field to `trailers`.
/// Returns false for the empty line that ends the section.
fn push_response_trailer(
    line: &[u8],
    connection_nominated_headers: &[String],
    trailers: &mut Vec<HttpHeader>,
) -> Result<bool> {
    if line.is_empty() {
        return Ok(false);
    }
    let line = std::str::from_utf8(line)
        .map_err(|_| miette!("HTTP response trailer contains invalid UTF-8"))?;
    let (name, value) = line
        .split_once(':')
        .ok_or_else(|| miette!("Malformed HTTP response trailer"))?;
    validate_http_field_name(name)?;
    validate_http_field_value(value.trim())?;
    let name = name.to_ascii_lowercase();
    if is_protected_response_field(&name) || connection_nominated_headers.contains(&name) {
        return Err(miette!("HTTP response trailer uses a protected field name"));
    }
    trailers.push(HttpHeader {
        name,
        value: value.trim().to_string(),
    });
    if trailers.len() > openshell_supervisor_middleware::MAX_MIDDLEWARE_HEADERS {
        return Err(miette!("HTTP response trailer count exceeds limit"));
    }
    Ok(true)
}

async fn send_response_middleware_denial<C: AsyncWrite + Unpin>(
    client: &mut C,
    request_method: &str,
    policy_name: &str,
    target: &HttpRequestTarget,
    denial: &openshell_supervisor_middleware::MiddlewareDenial,
) -> Result<()> {
    let mut body = serde_json::Map::new();
    body.insert("error".into(), serde_json::json!("middleware_denied"));
    body.insert(
        "detail".into(),
        serde_json::json!("Response blocked by configured middleware"),
    );
    body.insert("policy".into(), serde_json::json!(policy_name));
    body.insert("middleware".into(), serde_json::json!(denial.config_name));
    if let Some(reason_code) = &denial.reason_code {
        body.insert("reason_code".into(), serde_json::json!(reason_code));
    }
    body.insert(
        "layer".into(),
        serde_json::json!("http_response_pre_return"),
    );
    body.insert("method".into(), serde_json::json!(target.method));
    body.insert("path".into(), serde_json::json!(target.path));
    body.insert("host".into(), serde_json::json!(target.host));
    body.insert("port".into(), serde_json::json!(target.port));
    let body = serde_json::to_vec(&serde_json::Value::Object(body)).into_diagnostic()?;
    let head = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-OpenShell-Policy: {policy_name}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    client.write_all(head.as_bytes()).await.into_diagnostic()?;
    if !request_method.eq_ignore_ascii_case("HEAD") {
        client.write_all(&body).await.into_diagnostic()?;
    }
    client.flush().await.into_diagnostic()?;
    Ok(())
}

async fn send_response_delivery_failure<C: AsyncWrite + Unpin>(
    client: &mut C,
    request_method: &str,
    policy_name: &str,
    target: &HttpRequestTarget,
) -> Result<()> {
    let body = serde_json::to_vec(&serde_json::json!({
        "error": "response_delivery_failed",
        "detail": "The upstream request may have completed, but OpenShell could not deliver its response. Retrying may repeat upstream side effects.",
        "policy": policy_name,
        "layer": "http_response_pre_return",
        "method": target.method,
        "path": target.path,
        "host": target.host,
        "port": target.port,
    }))
    .into_diagnostic()?;
    let head = format!(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-OpenShell-Policy: {policy_name}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    client.write_all(head.as_bytes()).await.into_diagnostic()?;
    if !request_method.eq_ignore_ascii_case("HEAD") {
        client.write_all(&body).await.into_diagnostic()?;
    }
    client.flush().await.into_diagnostic()?;
    Ok(())
}

/// Parse the HTTP status code from a response status line.
///
/// Expects the first line to look like `HTTP/1.1 200 OK`.
pub(super) fn parse_status_code(headers: &str) -> Option<u16> {
    let status_line = headers.lines().next()?;
    let code_str = status_line.split_whitespace().nth(1)?;
    code_str.parse().ok()
}

/// Parse a syntactically valid HTTP/1.x response status for endpoint reporting.
pub(super) fn parse_observed_http_status_code(headers: &str) -> Option<u16> {
    let status_line = headers.lines().next()?;
    let mut fields = status_line.split_whitespace();
    match fields.next()? {
        "HTTP/1.0" | "HTTP/1.1" => {}
        _ => return None,
    }
    let code = fields.next()?;
    if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    code.parse()
        .ok()
        .filter(|status| (100..=999).contains(status))
}

/// Check if the response headers contain `Connection: close`.
pub(super) fn parse_connection_close(headers: &str) -> bool {
    for line in headers.lines().skip(1) {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("connection:") {
            let val = lower.split_once(':').map_or("", |(_, v)| v.trim());
            return val.contains("close");
        }
    }
    false
}

/// Check if an HTTP/1.0 response opts into a persistent connection.
pub(super) fn parse_connection_keep_alive(headers: &str) -> bool {
    headers.lines().skip(1).any(|line| {
        let lower = line.to_ascii_lowercase();
        lower
            .strip_prefix("connection:")
            .is_some_and(|value| value.split(',').any(|token| token.trim() == "keep-alive"))
    })
}

pub(super) fn response_is_http_10(headers: &str) -> bool {
    headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().next())
        == Some("HTTP/1.0")
}

pub(super) fn response_is_event_stream(headers: &str) -> bool {
    headers.lines().skip(1).any(|line| {
        let lower = line.to_ascii_lowercase();
        let Some(value) = lower.strip_prefix("content-type:") else {
            return false;
        };
        value
            .split(';')
            .next()
            .is_some_and(|mime| mime.trim() == "text/event-stream")
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ResponseFraming, parse_connection_keep_alive, parse_response_head_for_middleware,
        response_is_http_10, serialize_response_head,
    };
    use crate::l7::provider::BodyLength;
    use openshell_core::proto::HttpHeader;

    #[test]
    fn http_10_connection_persistence() {
        let default_close = "HTTP/1.0 200 OK\r\nServer: test\r\n\r\n";
        assert!(response_is_http_10(default_close));
        assert!(!parse_connection_keep_alive(default_close));

        let keep_alive = "HTTP/1.0 200 OK\r\nConnection: keep-alive\r\n\r\n";
        assert!(response_is_http_10(keep_alive));
        assert!(parse_connection_keep_alive(keep_alive));
    }

    #[test]
    fn response_middleware_preflight_keeps_read_only_content_length() {
        let parsed = parse_response_head_for_middleware(
            b"HTTP/1.1 206 Partial Content\r\n\
              Content-Length: 5\r\n\
              Content-Encoding: gzip\r\n\
              Content-Range: bytes 0-4/10\r\n\
              Connection: x-hop\r\n\
              X-Hop: omitted\r\n\r\n",
        )
        .expect("parse response head");

        assert_eq!(
            parsed.headers,
            vec![
                HttpHeader {
                    name: "content-length".into(),
                    value: "5".into(),
                },
                HttpHeader {
                    name: "content-encoding".into(),
                    value: "gzip".into(),
                },
                HttpHeader {
                    name: "content-range".into(),
                    value: "bytes 0-4/10".into(),
                },
            ]
        );

        let nominated = parse_response_head_for_middleware(
            b"HTTP/1.1 200 OK\r\nConnection: Content-Length\r\nContent-Length: 5\r\n\r\n",
        )
        .expect("parse nominated response head");
        assert!(nominated.headers.is_empty());
    }

    #[test]
    fn response_middleware_serializes_only_relay_owned_framing() {
        let headers = vec![
            HttpHeader {
                name: "content-length".into(),
                value: "999".into(),
            },
            HttpHeader {
                name: "Content-Length".into(),
                value: "998".into(),
            },
            HttpHeader {
                name: "content-type".into(),
                value: "text/plain".into(),
            },
        ];

        for (framing, expected) in [
            (
                ResponseFraming::Preserve(BodyLength::ContentLength(5)),
                Some("Content-Length: 5\r\n"),
            ),
            (
                ResponseFraming::ContentLength(9),
                Some("Content-Length: 9\r\n"),
            ),
            (ResponseFraming::Chunked, None),
            (ResponseFraming::Preserve(BodyLength::None), None),
        ] {
            let serialized = String::from_utf8(serialize_response_head(
                "HTTP/1.1 200 OK",
                &headers,
                &[],
                framing,
                false,
                &[],
            ))
            .expect("serialized response head");

            assert_eq!(
                serialized
                    .lines()
                    .filter(|line| line.to_ascii_lowercase().starts_with("content-length:"))
                    .count(),
                usize::from(expected.is_some())
            );
            if let Some(expected) = expected {
                assert!(serialized.contains(expected));
            }
            if matches!(framing, ResponseFraming::Chunked) {
                assert!(serialized.contains("Transfer-Encoding: chunked\r\n"));
            }
        }
    }
}
