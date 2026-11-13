// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP response relay and pre-return middleware integration.

mod http_hooks;

use super::*;
use crate::l7::correlation::{HttpOutcome, RequestCorrelation, RequestStage};

/// Default wall-clock bound shared by whole-body stages in one response.
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
    /// The client request used HTTP/1.1, so an HTTP hook response may
    /// be re-framed chunked. An HTTP/1.0 client cannot decode chunked framing.
    pub(crate) client_accepts_chunked: bool,
    /// The request head as request middleware forwarded it, before
    /// credentials. HTTP hook response stages receive its headers, and
    /// fail closed without it.
    pub(crate) request_head: Option<crate::l7::middleware::ForwardedRequestHead>,
}

impl HttpResponseMiddlewareRelay<'_> {
    /// Whether an HTTP hook stage of this response chain may inspect bodies.
    ///
    /// A chain that cannot be described fails when the response arrives, so
    /// the request is left unchanged.
    pub(super) async fn inspects_bodies(&self) -> bool {
        if self.chain.is_empty() {
            return false;
        }
        self.runner
            .describe_http_response_chain(self.chain)
            .await
            .is_ok_and(|described| {
                openshell_supervisor_middleware::chain_inspects_http_response_bodies(&described)
            })
    }
}

#[derive(Clone)]
pub(super) struct RelayResponseOptions<'a> {
    pub(super) websocket_extensions: WebSocketExtensionMode,
    pub(super) client_requested_upgrade: bool,
    pub(super) websocket: Option<WebSocketResponseValidation>,
    pub(super) observer: Option<&'a EndpointObserver>,
    pub(super) correlation: Option<&'a RequestCorrelation>,
}

impl Default for RelayResponseOptions<'_> {
    fn default() -> Self {
        Self {
            websocket_extensions: WebSocketExtensionMode::Preserve,
            client_requested_upgrade: true,
            websocket: None,
            observer: None,
            correlation: None,
        }
    }
}

pub(super) async fn relay_response<U, C>(
    request_method: &str,
    upstream: &mut U,
    client: &mut C,
    options: RelayResponseOptions<'_>,
    response_middleware: Option<HttpResponseMiddlewareRelay<'_>>,
) -> Result<RelayOutcome>
where
    U: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    let started_at = std::time::Instant::now();
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];

    // Forward interim responses unchanged, but retain the final response head
    // until response middleware preflight completes.
    let mut informational_header_bytes = 0;
    let mut header_end = loop {
        let header_end = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|end| end + 4);
        let remaining_header_bytes = MAX_HEADER_BYTES - informational_header_bytes;
        if header_end.is_some_and(|end| end > remaining_header_bytes)
            || (header_end.is_none() && buf.len() >= remaining_header_bytes)
        {
            if let Some(observer) = options.observer.as_ref() {
                observer.observe(EndpointResult::TransportFailed);
            }
            return Err(miette!("HTTP response headers exceed limit"));
        }

        if let Some(header_end) = header_end {
            if options.correlation.is_some()
                && let Err(error) = validate_http_response_header_block(&buf[..header_end])
            {
                if let Some(observer) = options.observer.as_ref() {
                    observer.observe(EndpointResult::TransportFailed);
                }
                record_upstream_response_error(options.correlation, "upstream_response_headers");
                return Err(error);
            }
            let header_str = String::from_utf8_lossy(&buf[..header_end]);
            if matches!(
                parse_observed_http_status_code(&header_str),
                Some(100 | 102..=199)
            ) {
                informational_header_bytes += header_end;
                let sanitized = if options.correlation.is_some() {
                    strip_platform_request_id_from_head(&buf[..header_end])
                } else {
                    Cow::Borrowed(&buf[..header_end])
                };
                client.write_all(&sanitized).await.into_diagnostic()?;
                client.flush().await.into_diagnostic()?;
                buf.drain(..header_end);
                continue;
            }
            break header_end;
        }

        let n = upstream.read(&mut tmp).await.into_diagnostic()?;
        if n == 0 {
            if let Some(observer) = options.observer.as_ref() {
                observer.observe(EndpointResult::TransportFailed);
            }
            record_upstream_response_error(options.correlation, "upstream_response_incomplete");
            if !buf.is_empty() {
                client.write_all(&buf).await.into_diagnostic()?;
            }
            return Ok(RelayOutcome::Consumed);
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    if options.correlation.is_some()
        && let Cow::Owned(sanitized) = strip_platform_request_id_from_head(&buf[..header_end])
    {
        let overflow = buf.split_off(header_end);
        buf = sanitized;
        header_end = buf.len();
        buf.extend_from_slice(&overflow);
    }

    // Parse response framing
    let header_str = String::from_utf8_lossy(&buf[..header_end]);
    let observed_status = parse_observed_http_status_code(&header_str);
    if let (Some(correlation), Some(status_code)) = (options.correlation, observed_status) {
        correlation.record_upstream_status(status_code);
    }
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
        let final_head = final_response_head(&buf[..header_end], options.correlation);
        client.write_all(&final_head).await.into_diagnostic()?;
        client.flush().await.into_diagnostic()?;
        let overflow = buf[header_end..].to_vec();
        debug!(
            request_method,
            overflow_bytes = overflow.len(),
            "101 Switching Protocols — signaling protocol upgrade"
        );
        record_allowed_response(options.correlation);
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
            client,
            response_middleware,
            &buf,
            header_end,
            status_code,
            body_length,
            server_wants_close || http_10_closes_by_default,
            event_stream,
            options.correlation,
        ))
        .await?
    {
        return if matches!(outcome, RelayOutcome::Consumed) {
            finish_response(client, true).await
        } else {
            Ok(outcome)
        };
    }

    let final_head = final_response_head(&buf[..header_end], options.correlation);

    // Bodiless responses (HEAD, 1xx, 204, 304): forward headers only, skip body
    if is_bodiless_response(request_method, status_code) {
        client.write_all(&final_head).await.into_diagnostic()?;
        let outcome =
            finish_response(client, server_wants_close || http_10_closes_by_default).await?;
        record_allowed_response(options.correlation);
        return Ok(outcome);
    }

    // No explicit framing (no Content-Length, no Transfer-Encoding).
    // Per RFC 7230 §3.3.3 the body is delimited by connection close.
    if matches!(body_length, BodyLength::None) {
        if server_wants_close || http_10_closes_by_default || event_stream {
            // Server indicated it will close, or this is a streaming response
            // such as SSE where the body is intentionally delimited by EOF.
            let before_end = &final_head[..final_head.len() - 2];
            client.write_all(before_end).await.into_diagnostic()?;
            if server_wants_close || http_10_closes_by_default {
                client
                    .write_all(b"Connection: close\r\n\r\n")
                    .await
                    .into_diagnostic()?;
            } else {
                client.write_all(b"\r\n").await.into_diagnostic()?;
            }
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
            record_allowed_response(options.correlation);
            return Ok(RelayOutcome::Consumed);
        }
        // No Connection: close — an HTTP/1.1 keep-alive server that omits
        // framing headers has an empty body.  Forward headers and continue
        // the relay loop instead of blocking on relay_until_eof.
        debug!("BodyLength::None without Connection: close — treating body as empty");
        client.write_all(&final_head).await.into_diagnostic()?;
        client.flush().await.into_diagnostic()?;
        record_allowed_response(options.correlation);
        return Ok(RelayOutcome::Reusable);
    }

    // Hold buffered chunk framing until relay_chunked validates it.
    client.write_all(&final_head).await.into_diagnostic()?;
    let overflow = &buf[header_end..];
    let overflow_len = (buf.len() - header_end) as u64;

    // Forward remaining response body
    match body_length {
        BodyLength::ContentLength(len) => {
            if !overflow.is_empty() {
                client.write_all(overflow).await.into_diagnostic()?;
            }
            let remaining = len.saturating_sub(overflow_len);
            if remaining > 0 {
                relay_fixed(upstream, client, remaining, None).await?;
            }
        }
        BodyLength::Chunked => {
            relay_chunked_with_receipt_protection(
                upstream,
                client,
                overflow,
                None,
                options.correlation.is_some(),
            )
            .await?;
        }
        BodyLength::None => unreachable!(),
    }
    client.flush().await.into_diagnostic()?;
    debug!(
        request_method,
        elapsed_ms = started_at.elapsed().as_millis(),
        "relay_response complete (explicit framing)"
    );

    let outcome = finish_response(client, server_wants_close || http_10_closes_by_default).await?;
    record_allowed_response(options.correlation);
    Ok(outcome)
}

fn record_allowed_response(correlation: Option<&RequestCorrelation>) {
    if let Some(correlation) = correlation {
        correlation.record_outcome(HttpOutcome::Allowed);
    }
}

fn record_denied_response(correlation: Option<&RequestCorrelation>, stage: &'static str) {
    if let Some(correlation) = correlation {
        correlation.record_rejection(403, HttpOutcome::Denied, Some(stage));
    }
}

fn record_upstream_response_error(correlation: Option<&RequestCorrelation>, stage: &'static str) {
    if let Some(correlation) = correlation {
        correlation.record_failure(HttpOutcome::UpstreamError, stage);
    }
}

fn record_committed_response_error(
    correlation: Option<&RequestCorrelation>,
    outcome: HttpOutcome,
    stage: &'static str,
) {
    if let Some(correlation) = correlation {
        correlation.record_failure(outcome, stage);
    }
}

fn validate_http_response_header_block(headers: &[u8]) -> Result<()> {
    if !headers.ends_with(b"\r\n\r\n") {
        return Err(miette!("HTTP response header block is incomplete"));
    }

    for (index, byte) in headers.iter().copied().enumerate() {
        match byte {
            b'\r' if headers.get(index + 1) != Some(&b'\n') => {
                return Err(miette!("HTTP response headers contain a bare CR"));
            }
            b'\n' if index == 0 || headers.get(index - 1) != Some(&b'\r') => {
                return Err(miette!("HTTP response headers contain a bare LF"));
            }
            _ => {}
        }
    }

    let header_lines = &headers[..headers.len() - 2];
    let mut lines = header_lines
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line));
    let status_line = lines
        .next()
        .ok_or_else(|| miette!("HTTP response status line is missing"))?;
    validate_http_response_status_line(status_line)?;

    while let Some(line) = lines.next() {
        if line.is_empty() {
            if lines.next().is_some() {
                return Err(miette!(
                    "HTTP response header block contains an unexpected empty line"
                ));
            }
            break;
        }
        if line
            .first()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            return Err(miette!(
                "HTTP response header continuation lines are not supported"
            ));
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| miette!("HTTP response header field is malformed"))?;
        let name = &line[..colon];
        if name.last().is_some_and(|byte| matches!(byte, b' ' | b'\t')) {
            return Err(miette!(
                "HTTP response header field contains whitespace before the colon"
            ));
        }
        http::HeaderName::from_bytes(name)
            .map_err(|_| miette!("HTTP response field name is malformed"))?;
        http::HeaderValue::from_bytes(&line[colon + 1..])
            .map_err(|_| miette!("HTTP response field value is malformed"))?;
    }
    Ok(())
}

fn validate_http_response_status_line(status_line: &[u8]) -> Result<()> {
    let remainder = if let Some(remainder) = status_line.strip_prefix(b"HTTP/1.0 ") {
        remainder
    } else if let Some(remainder) = status_line.strip_prefix(b"HTTP/1.1 ") {
        remainder
    } else {
        return Err(miette!(
            "HTTP response status line must use HTTP/1.0 or HTTP/1.1"
        ));
    };
    if remainder.len() < 3 || (remainder.len() > 3 && remainder[3] != b' ') {
        return Err(miette!("HTTP response status line is malformed"));
    }
    http::StatusCode::from_bytes(&remainder[..3])
        .map_err(|_| miette!("HTTP response status code is invalid"))?;
    http::HeaderValue::from_bytes(remainder.get(4..).unwrap_or_default())
        .map_err(|_| miette!("HTTP response reason phrase is malformed"))?;
    Ok(())
}

fn final_response_head<'a>(
    headers: &'a [u8],
    correlation: Option<&RequestCorrelation>,
) -> Cow<'a, [u8]> {
    let Some(correlation) = correlation else {
        return Cow::Borrowed(headers);
    };
    let stripped =
        strip_platform_request_id_from_connection(strip_platform_request_id_from_head(headers));
    let Some(header_end) = stripped.windows(4).position(|window| window == b"\r\n\r\n") else {
        return stripped;
    };
    let name = openshell_core::token_grant_failure::REQUEST_ID_HEADER;
    let request_id = correlation.request_id();
    let mut output = Vec::with_capacity(stripped.len() + name.len() + request_id.len() + 4);
    output.extend_from_slice(&stripped[..header_end + 2]);
    output.extend_from_slice(name.as_bytes());
    output.extend_from_slice(b": ");
    output.extend_from_slice(request_id.as_bytes());
    output.extend_from_slice(b"\r\n\r\n");
    output.extend_from_slice(&stripped[header_end + 4..]);
    Cow::Owned(output)
}

fn strip_platform_request_id_from_connection(headers: Cow<'_, [u8]>) -> Cow<'_, [u8]> {
    let header_end = headers
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map_or(headers.len(), |position| position + 4);
    let (header_block, buffered_suffix) = headers.split_at(header_end);
    let protected = openshell_core::token_grant_failure::REQUEST_ID_HEADER.as_bytes();
    let mut output: Option<Vec<u8>> = None;
    let mut position = 0usize;

    while position < header_block.len() {
        let line_end = header_block[position..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .map_or(header_block.len(), |end| position + end);
        let line = &header_block[position..line_end];
        if line.is_empty() {
            if position + 2 < header_block.len() {
                output.get_or_insert_with(|| header_block[..position].to_vec());
            }
            if let Some(output) = &mut output {
                output.extend_from_slice(b"\r\n");
            }
            break;
        }

        if let Some(colon) = line.iter().position(|byte| *byte == b':')
            && trim_ascii_ows(&line[..colon]).eq_ignore_ascii_case(b"connection")
            && line[colon + 1..]
                .split(|byte| *byte == b',')
                .any(|value| trim_ascii_ows(value).eq_ignore_ascii_case(protected))
        {
            let output = output.get_or_insert_with(|| {
                let mut output = Vec::with_capacity(headers.len());
                output.extend_from_slice(&header_block[..position]);
                output
            });
            let mut retained = line[colon + 1..]
                .split(|byte| *byte == b',')
                .map(trim_ascii_ows)
                .filter(|token| !token.is_empty() && !token.eq_ignore_ascii_case(protected));
            if let Some(first) = retained.next() {
                output.extend_from_slice(&line[..=colon]);
                output.push(b' ');
                output.extend_from_slice(first);
                for token in retained {
                    output.extend_from_slice(b", ");
                    output.extend_from_slice(token);
                }
                output.extend_from_slice(b"\r\n");
            }
            position = line_end.saturating_add(2);
            continue;
        }
        if line_end + 2 > header_block.len() {
            output.get_or_insert_with(|| header_block[..position].to_vec());
        }
        if let Some(output) = &mut output {
            output.extend_from_slice(line);
            output.extend_from_slice(b"\r\n");
        }
        position = line_end.saturating_add(2);
    }

    if let Some(output) = &mut output {
        output.extend_from_slice(buffered_suffix);
    }
    output.map_or(headers, Cow::Owned)
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
    client: &mut C,
    middleware: HttpResponseMiddlewareRelay<'_>,
    buffered: &[u8],
    header_end: usize,
    status_code: u16,
    body_length: BodyLength,
    server_wants_close: bool,
    event_stream: bool,
    response_correlation: Option<&RequestCorrelation>,
) -> Result<Option<RelayOutcome>>
where
    U: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
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
    let span = response_correlation.map_or_else(tracing::Span::none, |correlation| {
        correlation.stage(RequestStage::ResponseMiddleware)
    });
    relay_described_response_through_middleware(
        request_method,
        upstream,
        client,
        middleware,
        buffered,
        header_end,
        status_code,
        body_length,
        server_wants_close,
        event_stream,
        response_correlation,
        parsed,
    )
    .instrument(span)
    .await
}

#[allow(clippy::too_many_arguments)]
async fn relay_described_response_through_middleware<U, C>(
    request_method: &str,
    upstream: &mut U,
    client: &mut C,
    middleware: HttpResponseMiddlewareRelay<'_>,
    buffered: &[u8],
    header_end: usize,
    status_code: u16,
    body_length: BodyLength,
    server_wants_close: bool,
    event_stream: bool,
    response_correlation: Option<&RequestCorrelation>,
    parsed: Result<(
        Vec<openshell_supervisor_middleware::DescribedChainEntry>,
        ParsedResponseHead,
    )>,
) -> Result<Option<RelayOutcome>>
where
    U: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    let header_bytes = &buffered[..header_end];
    if let Some(guard) = middleware.generation_guard {
        guard.ensure_current()?;
    }
    let (described, parsed) = match parsed {
        Ok(parsed) => parsed,
        Err(error) => {
            debug!(error = %error, "HTTP response head normalization failed");
            emit_http_response_middleware_failure(
                response_correlation,
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
                None,
                HttpOutcome::PlatformError,
                "response_middleware_headers",
                response_correlation,
            )
            .await?;
            return Ok(Some(RelayOutcome::Consumed));
        }
    };
    match openshell_supervisor_middleware::chain_http_hook_version(&described) {
        openshell_supervisor_middleware::ChainHttpHookVersion::Legacy => {}
        openshell_supervisor_middleware::ChainHttpHookVersion::Current => {
            return Box::pin(http_hooks::relay_response_through_pipeline(
                request_method,
                upstream,
                client,
                middleware,
                described,
                parsed,
                buffered,
                header_end,
                status_code,
                body_length,
                server_wants_close,
                event_stream,
                response_correlation,
            ))
            .await;
        }
        openshell_supervisor_middleware::ChainHttpHookVersion::Mixed => {
            debug!(
                reason = openshell_supervisor_middleware::MIDDLEWARE_HOOK_VERSIONS_MIXED,
                "HTTP response middleware chain mixes HTTP hook versions"
            );
            emit_http_response_middleware_failure(
                response_correlation,
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
                None,
                HttpOutcome::PlatformError,
                "response_middleware_hook_version",
                response_correlation,
            )
            .await?;
            return Ok(Some(RelayOutcome::Consumed));
        }
    }
    let original_headers = parsed.headers.clone();
    let preserved_credential_headers = parsed.preserved_credential_headers;
    let upstream_declared_trailers = parsed.declared_trailers.clone();
    let connection_nominated_headers = parsed.connection_nominated.clone();
    let input = openshell_supervisor_middleware::HttpResponsePreflightInput {
        context: middleware.request_context,
        target: middleware.target.clone(),
        status_code,
        declared_body_length: match body_length {
            BodyLength::ContentLength(length) => Some(length),
            BodyLength::Chunked | BodyLength::None => None,
        },
        headers: parsed.headers,
        connection_nominated_headers: parsed.connection_nominated,
        // Legacy response hooks do not receive request headers.
        request_headers: Vec::new(),
    };
    let preflight_result = if parsed.representable {
        middleware
            .runner
            .preflight_described_http_response(described, input)
            .await
    } else {
        Ok(middleware
            .runner
            .http_response_input_unrepresentable(&described))
    };
    let mut preflight = match preflight_result {
        Ok(preflight) => preflight,
        Err(error) => {
            debug!(error = %error, "HTTP response middleware preflight failed");
            emit_http_response_middleware_failure(
                response_correlation,
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
                None,
                HttpOutcome::PlatformError,
                "response_middleware_preflight",
                response_correlation,
            )
            .await?;
            return Ok(Some(RelayOutcome::Consumed));
        }
    };
    if let Some(guard) = middleware.generation_guard
        && let Err(error) = guard.ensure_current()
    {
        if let Some(session) = preflight.session.take() {
            session
                .end(openshell_core::proto::MiddlewareSessionEndReason::PolicyReload)
                .await;
        }
        return Err(error);
    }
    debug!(
        configured_stage_count = middleware.chain.len(),
        active_session = preflight.session.is_some(),
        allowed = preflight.allowed,
        "HTTP response middleware preflight completed"
    );
    let mut preflight_events =
        crate::l7::middleware::middleware_finding_events(&preflight.findings);
    if !preflight.allowed {
        preflight_events.extend(http_response_decision_events(
            middleware.policy_name,
            &middleware.target,
            status_code,
            &preflight.invocations,
        ));
        if preflight.denial.is_none() {
            preflight_events.push(http_response_middleware_failure_event(
                middleware.policy_name,
                &middleware.target,
                status_code,
                false,
                true,
            ));
        }
    }
    crate::l7::correlation::emit_request_events(response_correlation, preflight_events);
    if !preflight.allowed {
        if let Some(denial) = preflight.denial.as_ref() {
            send_response_middleware_denial(
                client,
                request_method,
                middleware.policy_name,
                &middleware.target,
                denial,
                "response_middleware_preflight",
                response_correlation,
            )
            .await?;
        } else {
            send_response_delivery_failure(
                client,
                request_method,
                middleware.policy_name,
                &middleware.target,
                None,
                HttpOutcome::PlatformError,
                "response_middleware_preflight",
                response_correlation,
            )
            .await?;
        }
        return Ok(Some(RelayOutcome::Consumed));
    }
    crate::l7::correlation::emit_request_events(
        response_correlation,
        http_response_decision_events(
            middleware.policy_name,
            &middleware.target,
            status_code,
            &preflight.invocations,
        ),
    );

    let Some(mut session) = preflight.session else {
        if preflight.headers == original_headers {
            return Ok(None);
        }
        let status_line = response_status_line(header_bytes)?;
        let outcome = relay_headers_only_response(
            request_method,
            upstream,
            client,
            &status_line,
            &preflight.headers,
            &preserved_credential_headers,
            &upstream_declared_trailers,
            &buffered[header_end..],
            status_code,
            body_length,
            server_wants_close,
            event_stream,
            response_correlation,
        )
        .await?;
        record_allowed_response(response_correlation);
        return Ok(Some(outcome));
    };

    let status_line = response_status_line(header_bytes)?;
    let supports_chunked_response = !status_line.starts_with("HTTP/1.0 ");
    let bodiless = is_bodiless_response(request_method, status_code);
    if bodiless {
        let finish = match session.finish(Vec::new()).await {
            Ok(finish) => finish,
            Err(error) => {
                debug!(error = %error, "HTTP response middleware finalization failed");
                let mut events = http_response_diagnostic_events(
                    middleware.policy_name,
                    &middleware.target,
                    status_code,
                    &error.diagnostics.invocations,
                    &error.diagnostics.findings,
                );
                events.push(http_response_middleware_failure_event(
                    middleware.policy_name,
                    &middleware.target,
                    status_code,
                    false,
                    true,
                ));
                crate::l7::correlation::emit_request_events(response_correlation, events);
                send_response_delivery_failure(
                    client,
                    request_method,
                    middleware.policy_name,
                    &middleware.target,
                    None,
                    HttpOutcome::PlatformError,
                    "response_middleware_finish",
                    response_correlation,
                )
                .await?;
                return Ok(Some(RelayOutcome::Consumed));
            }
        };
        if let Some(guard) = middleware.generation_guard {
            guard.ensure_current()?;
        }
        let mut headers = preflight.headers;
        crate::l7::correlation::emit_request_events(
            response_correlation,
            http_response_diagnostic_events(
                middleware.policy_name,
                &middleware.target,
                status_code,
                &finish.invocations,
                &finish.findings,
            ),
        );
        if finish.strip_stale_integrity_headers {
            strip_response_integrity_headers(&mut headers);
        }
        let head = serialize_response_head(
            &status_line,
            &headers,
            &preserved_credential_headers,
            ResponseFraming::Preserve(body_length),
            server_wants_close,
            &[],
        );
        let head = final_response_head(&head, response_correlation);
        client.write_all(&head).await.into_diagnostic()?;
        client.flush().await.into_diagnostic()?;
        record_allowed_response(response_correlation);
        return Ok(Some(if server_wants_close {
            RelayOutcome::Consumed
        } else {
            RelayOutcome::Reusable
        }));
    }

    let whole_body = session.requires_whole_body();
    if whole_body {
        session.start_whole_body_deadline(middleware.whole_body_timeout);
    }
    let unit_limit = session.stream_unit_limit().max(1);
    let chunked_output = supports_chunked_response;
    let close_delimited_output = !supports_chunked_response;
    let declared_trailers = upstream_declared_trailers;
    let downstream_trailers = if chunked_output {
        declared_trailers.as_slice()
    } else {
        &[]
    };
    let streaming_head = serialize_response_head(
        &status_line,
        &preflight.headers,
        &preserved_credential_headers,
        if chunked_output {
            ResponseFraming::Chunked
        } else {
            ResponseFraming::Preserve(BodyLength::None)
        },
        server_wants_close || close_delimited_output,
        downstream_trailers,
    );
    let streaming_head = final_response_head(&streaming_head, response_correlation);
    let mut committed = !whole_body;
    if committed {
        if let Err(error) = client.write_all(&streaming_head).await {
            session
                .end(openshell_core::proto::MiddlewareSessionEndReason::DownstreamDisconnect)
                .await;
            return Err(error).into_diagnostic();
        }
        if let Err(error) = client.flush().await {
            session
                .end(openshell_core::proto::MiddlewareSessionEndReason::DownstreamDisconnect)
                .await;
            return Err(error).into_diagnostic();
        }
    }

    let mut reader = BufferedResponseReader::new(upstream, &buffered[header_end..]);
    let body_result = relay_normalized_response_body(
        &mut reader,
        &mut session,
        client,
        body_length,
        server_wants_close,
        event_stream,
        &mut committed,
        chunked_output,
        &streaming_head,
        unit_limit,
        middleware.generation_guard,
        middleware.policy_name,
        &middleware.target,
        status_code,
        &connection_nominated_headers,
        response_correlation,
    )
    .await;
    let trailers = match body_result {
        Ok(trailers) => trailers,
        Err(error) => {
            let middleware_stop = error.downcast_ref::<ResponseMiddlewareStop>();
            let end_reason = if middleware
                .generation_guard
                .is_some_and(PolicyGenerationGuard::is_stale)
            {
                openshell_core::proto::MiddlewareSessionEndReason::PolicyReload
            } else if error.downcast_ref::<ResponseDownstreamWrite>().is_some() {
                openshell_core::proto::MiddlewareSessionEndReason::DownstreamDisconnect
            } else if middleware_stop.is_some_and(|stop| stop.failure.denial.is_some()) {
                openshell_core::proto::MiddlewareSessionEndReason::MiddlewareDenial
            } else if middleware_stop.is_some() {
                openshell_core::proto::MiddlewareSessionEndReason::MiddlewareFailure
            } else {
                openshell_core::proto::MiddlewareSessionEndReason::UpstreamDisconnect
            };
            session.end(end_reason).await;
            // Diagnostics from a middleware stop and its terminal finding are
            // one decision. Transport/framing errors still record delivery
            // failure, but do not imply an enforced middleware refusal.
            let mut events = middleware_stop.map_or_else(Vec::new, |stop| {
                http_response_diagnostic_events(
                    middleware.policy_name,
                    &middleware.target,
                    status_code,
                    &stop.diagnostics.invocations,
                    &stop.diagnostics.findings,
                )
            });
            // A denial sent before commitment is reported by its invocation.
            if committed || middleware_stop.is_none_or(|stop| stop.failure.denial.is_none()) {
                events.push(http_response_middleware_failure_event(
                    middleware.policy_name,
                    &middleware.target,
                    status_code,
                    committed,
                    middleware_stop.is_some(),
                ));
            }
            crate::l7::correlation::emit_request_events(response_correlation, events);
            if committed {
                if middleware_stop.is_some_and(|stop| stop.failure.denial.is_some()) {
                    record_committed_response_error(
                        response_correlation,
                        HttpOutcome::Denied,
                        "response_middleware_body",
                    );
                } else {
                    record_committed_response_error(
                        response_correlation,
                        HttpOutcome::PlatformError,
                        "response_middleware_body",
                    );
                }
                return Err(error);
            }
            debug!(error = %error, "HTTP response processing failed before commitment");
            if let Some(denial) = middleware_stop.and_then(|stop| stop.failure.denial.as_ref()) {
                send_response_middleware_denial(
                    client,
                    request_method,
                    middleware.policy_name,
                    &middleware.target,
                    denial,
                    "response_middleware_body",
                    response_correlation,
                )
                .await?;
            } else {
                send_response_delivery_failure(
                    client,
                    request_method,
                    middleware.policy_name,
                    &middleware.target,
                    None,
                    HttpOutcome::PlatformError,
                    "response_middleware_body",
                    response_correlation,
                )
                .await?;
            }
            return Ok(Some(RelayOutcome::Consumed));
        }
    };

    if let Some(guard) = middleware.generation_guard
        && let Err(error) = guard.ensure_current()
    {
        session
            .end(openshell_core::proto::MiddlewareSessionEndReason::PolicyReload)
            .await;
        return Err(error);
    }

    let finish = match session.finish(trailers).await {
        Ok(finish) => finish,
        Err(error) => {
            let mut events = http_response_diagnostic_events(
                middleware.policy_name,
                &middleware.target,
                status_code,
                &error.diagnostics.invocations,
                &error.diagnostics.findings,
            );
            if committed || error.denial.is_none() {
                events.push(http_response_middleware_failure_event(
                    middleware.policy_name,
                    &middleware.target,
                    status_code,
                    committed,
                    true,
                ));
            }
            crate::l7::correlation::emit_request_events(response_correlation, events);
            if committed {
                if error.denial.is_some() {
                    record_committed_response_error(
                        response_correlation,
                        HttpOutcome::Denied,
                        "response_middleware_finish",
                    );
                } else {
                    record_committed_response_error(
                        response_correlation,
                        HttpOutcome::PlatformError,
                        "response_middleware_finish",
                    );
                }
                return Err(miette!(
                    "HTTP response middleware failed after commitment: {error}"
                ));
            }
            debug!(error = %error, "HTTP response middleware failed before commitment");
            if let Some(denial) = error.denial.as_ref() {
                send_response_middleware_denial(
                    client,
                    request_method,
                    middleware.policy_name,
                    &middleware.target,
                    denial,
                    "response_middleware_finish",
                    response_correlation,
                )
                .await?;
            } else {
                send_response_delivery_failure(
                    client,
                    request_method,
                    middleware.policy_name,
                    &middleware.target,
                    None,
                    HttpOutcome::PlatformError,
                    "response_middleware_finish",
                    response_correlation,
                )
                .await?;
            }
            return Ok(Some(RelayOutcome::Consumed));
        }
    };
    if let Some(guard) = middleware.generation_guard {
        guard.ensure_current()?;
    }
    crate::l7::correlation::emit_request_events(
        response_correlation,
        http_response_diagnostic_events(
            middleware.policy_name,
            &middleware.target,
            status_code,
            &finish.invocations,
            &finish.findings,
        ),
    );

    if whole_body && !committed {
        let mut headers = preflight.headers;
        if finish.strip_stale_integrity_headers {
            strip_response_integrity_headers(&mut headers);
        }
        let output_length = finish
            .body_units
            .iter()
            .try_fold(0usize, |total, unit| total.checked_add(unit.len()))
            .ok_or_else(|| miette!("HTTP response middleware output length overflow"))?;
        let framing = if finish.trailers.is_empty() || !supports_chunked_response {
            ResponseFraming::ContentLength(output_length as u64)
        } else {
            ResponseFraming::Chunked
        };
        let trailer_names: Vec<String> = if supports_chunked_response {
            finish
                .trailers
                .iter()
                .map(|header| header.name.clone())
                .collect()
        } else {
            Vec::new()
        };
        let head = serialize_response_head(
            &status_line,
            &headers,
            &preserved_credential_headers,
            framing,
            server_wants_close,
            &trailer_names,
        );
        let head = final_response_head(&head, response_correlation);
        client.write_all(&head).await.into_diagnostic()?;
        if matches!(framing, ResponseFraming::Chunked) {
            for unit in &finish.body_units {
                write_downstream_response_chunk(client, unit).await?;
            }
            write_response_trailers(client, &finish.trailers).await?;
        } else {
            for unit in &finish.body_units {
                client.write_all(unit).await.into_diagnostic()?;
            }
        }
    } else {
        for unit in &finish.body_units {
            if chunked_output {
                write_downstream_response_chunk(client, unit).await?;
            } else {
                client.write_all(unit).await.into_diagnostic()?;
            }
        }
        if chunked_output {
            write_response_trailers(client, &finish.trailers).await?;
        }
    }
    client.flush().await.into_diagnostic()?;
    record_allowed_response(response_correlation);
    Ok(Some(
        if server_wants_close
            || (committed && close_delimited_output)
            || (matches!(body_length, BodyLength::None) && event_stream)
        {
            RelayOutcome::Consumed
        } else {
            RelayOutcome::Reusable
        },
    ))
}

#[allow(clippy::too_many_arguments)]
async fn relay_headers_only_response<U, C>(
    request_method: &str,
    upstream: &mut U,
    client: &mut C,
    status_line: &str,
    headers: &[HttpHeader],
    preserved_credential_headers: &[String],
    declared_trailers: &[String],
    overflow: &[u8],
    status_code: u16,
    body_length: BodyLength,
    server_wants_close: bool,
    event_stream: bool,
    response_correlation: Option<&RequestCorrelation>,
) -> Result<RelayOutcome>
where
    U: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    let head = serialize_response_head(
        status_line,
        headers,
        preserved_credential_headers,
        ResponseFraming::Preserve(body_length),
        server_wants_close,
        declared_trailers,
    );
    let head = final_response_head(&head, response_correlation);
    client.write_all(&head).await.into_diagnostic()?;

    if is_bodiless_response(request_method, status_code) {
        client.flush().await.into_diagnostic()?;
        return Ok(if server_wants_close {
            RelayOutcome::Consumed
        } else {
            RelayOutcome::Reusable
        });
    }

    match body_length {
        BodyLength::ContentLength(length) => {
            if !overflow.is_empty() {
                client.write_all(overflow).await.into_diagnostic()?;
            }
            let remaining = length.saturating_sub(overflow.len() as u64);
            if remaining > 0 {
                relay_fixed(upstream, client, remaining, None).await?;
            }
        }
        BodyLength::Chunked => {
            relay_chunked_with_receipt_protection(
                upstream,
                client,
                overflow,
                None,
                response_correlation.is_some(),
            )
            .await?;
        }
        BodyLength::None if server_wants_close || event_stream => {
            if !overflow.is_empty() {
                client.write_all(overflow).await.into_diagnostic()?;
            }
            if event_stream {
                relay_until_eof_without_idle_timeout(upstream, client).await?;
            } else {
                relay_until_eof(upstream, client).await?;
            }
            client.flush().await.into_diagnostic()?;
            return Ok(RelayOutcome::Consumed);
        }
        BodyLength::None => {
            if !overflow.is_empty() {
                client.write_all(overflow).await.into_diagnostic()?;
            }
        }
    }
    client.flush().await.into_diagnostic()?;
    Ok(if server_wants_close {
        RelayOutcome::Consumed
    } else {
        RelayOutcome::Reusable
    })
}

fn http_response_decision_events(
    policy_name: &str,
    target: &HttpRequestTarget,
    status_code: u16,
    invocations: &[openshell_supervisor_middleware::HttpResponseInvocation],
) -> Vec<openshell_ocsf::OcsfEvent> {
    let mut events =
        http_response_middleware_invocation_events(policy_name, target, status_code, invocations);
    for invocation in invocations {
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
    }
    events
}

fn http_response_diagnostic_events(
    policy_name: &str,
    target: &HttpRequestTarget,
    status_code: u16,
    invocations: &[openshell_supervisor_middleware::HttpResponseInvocation],
    findings: &[openshell_supervisor_middleware::NamespacedFinding],
) -> Vec<openshell_ocsf::OcsfEvent> {
    let mut events = http_response_decision_events(policy_name, target, status_code, invocations);
    events.extend(crate::l7::middleware::middleware_finding_events(findings));
    events
}

fn emit_http_response_diagnostics(
    correlation: Option<&RequestCorrelation>,
    policy_name: &str,
    target: &HttpRequestTarget,
    status_code: u16,
    diagnostics: &openshell_supervisor_middleware::HttpResponseDiagnostics,
) {
    crate::l7::correlation::emit_request_events(
        correlation,
        http_response_diagnostic_events(
            policy_name,
            target,
            status_code,
            &diagnostics.invocations,
            &diagnostics.findings,
        ),
    );
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
            let outcome = format!("{:?}", invocation.outcome).to_ascii_lowercase();
            let failed = invocation.failed;
            let blocked = matches!(
                invocation.outcome,
                openshell_supervisor_middleware::HttpResponseInvocationOutcome::BlockDelivery
                    | openshell_supervisor_middleware::HttpResponseInvocationOutcome::FailClosed
            );
            openshell_ocsf::HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
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
            .status(if failed || blocked {
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
            .unmapped("http_event_kind", "middleware_invocation")
            .unmapped("middleware_phase", "response")
            .unmapped("middleware_config", invocation.config_name.as_str())
            .unmapped(
                "middleware_implementation",
                invocation.implementation.as_str(),
            )
            .unmapped("response_middleware_outcome", outcome.as_str())
            .unmapped("sequence", invocation.sequence.unwrap_or_default())
            .unmapped("input_bytes", invocation.input_size)
            .unmapped("failed", failed)
            .message(format!(
                "HTTP_RESPONSE_MIDDLEWARE config={} implementation={} outcome={} sequence={} input_bytes={} failed={failed}",
                invocation.config_name,
                invocation.implementation,
                outcome,
                invocation.sequence.unwrap_or_default(),
                invocation.input_size,
            ))
                .build()
        })
        .collect()
}

fn http_response_middleware_block_finding_event(
    policy_name: &str,
    target: &HttpRequestTarget,
    invocation: &openshell_supervisor_middleware::HttpResponseInvocation,
) -> Option<openshell_ocsf::OcsfEvent> {
    if invocation.outcome
        != openshell_supervisor_middleware::HttpResponseInvocationOutcome::BlockDelivery
    {
        return None;
    }
    Some(
        openshell_ocsf::DetectionFindingBuilder::new(ocsf_ctx())
            .action(openshell_ocsf::ActionId::Denied)
            .severity(openshell_ocsf::SeverityId::Medium)
            .finding_info(openshell_ocsf::FindingInfo::new(
                "openshell.middleware.http_response_blocked",
                "HTTP response blocked by middleware",
            ))
            .evidence_pairs(&[
                ("policy", policy_name),
                ("middleware_config", invocation.config_name.as_str()),
                (
                    "middleware_implementation",
                    invocation.implementation.as_str(),
                ),
                ("host", target.host.as_str()),
                ("phase", "pre_return"),
            ])
            .unmapped("middleware_config", invocation.config_name.as_str())
            .unmapped(
                "middleware_implementation",
                invocation.implementation.as_str(),
            )
            .unmapped("phase", "pre_return")
            .message("HTTP response delivery blocked by middleware")
            .build(),
    )
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
    let failure_category = invocation
        .failure_category
        .as_deref()
        .unwrap_or("middleware_failure");
    Some(
        openshell_ocsf::DetectionFindingBuilder::new(ocsf_ctx())
            .severity(openshell_ocsf::SeverityId::Medium)
            .finding_info(openshell_ocsf::FindingInfo::new(
                "openshell.middleware.http_response_fail_open",
                "HTTP response middleware failed open",
            ))
            .evidence_pairs(&[
                ("policy", policy_name),
                ("middleware_config", invocation.config_name.as_str()),
                (
                    "middleware_implementation",
                    invocation.implementation.as_str(),
                ),
                ("host", target.host.as_str()),
                ("phase", "pre_return"),
                ("failure_category", failure_category),
            ])
            .unmapped("middleware_config", invocation.config_name.as_str())
            .unmapped(
                "middleware_implementation",
                invocation.implementation.as_str(),
            )
            .unmapped("phase", "pre_return")
            .unmapped("failure_category", failure_category)
            .message("HTTP response middleware failed and response inspection was bypassed")
            .build(),
    )
}

fn emit_http_response_middleware_failure(
    correlation: Option<&RequestCorrelation>,
    policy_name: &str,
    target: &HttpRequestTarget,
    status_code: u16,
    committed: bool,
) {
    crate::l7::correlation::emit_request_events(
        correlation,
        [http_response_middleware_failure_event(
            policy_name,
            target,
            status_code,
            committed,
            true,
        )],
    );
}

fn http_response_middleware_failure_event(
    policy_name: &str,
    target: &HttpRequestTarget,
    status_code: u16,
    committed: bool,
    denied: bool,
) -> openshell_ocsf::OcsfEvent {
    let status_code = status_code.to_string();
    let mut builder = openshell_ocsf::DetectionFindingBuilder::new(ocsf_ctx());
    if denied {
        builder = builder.action(openshell_ocsf::ActionId::Denied);
    }
    builder
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
        .build()
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
    name.eq_ignore_ascii_case(openshell_core::token_grant_failure::REQUEST_ID_HEADER)
        || name.eq_ignore_ascii_case("content-length")
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

#[allow(clippy::too_many_arguments)]
async fn relay_normalized_response_body<R, C>(
    reader: &mut BufferedResponseReader<'_, R>,
    session: &mut openshell_supervisor_middleware::HttpResponseSession,
    client: &mut C,
    body_length: BodyLength,
    server_wants_close: bool,
    event_stream: bool,
    committed: &mut bool,
    chunked_output: bool,
    commit_head: &[u8],
    unit_limit: usize,
    generation_guard: Option<&PolicyGenerationGuard>,
    policy_name: &str,
    target: &HttpRequestTarget,
    status_code: u16,
    connection_nominated_headers: &[String],
    correlation: Option<&RequestCorrelation>,
) -> Result<Vec<HttpHeader>>
where
    R: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    let mut pending = Vec::with_capacity(unit_limit);
    let mut framing = ResponseOutputState {
        committed,
        chunked: chunked_output,
        commit_head,
        generation_guard,
        policy_name,
        target,
        status_code,
        correlation,
    };
    match body_length {
        BodyLength::ContentLength(mut remaining) => {
            while remaining > 0 {
                let length = usize::try_from(remaining)
                    .unwrap_or(unit_limit)
                    .min(unit_limit);
                let unit = read_response_payload_with_deadline(
                    reader,
                    length,
                    !pending.is_empty(),
                    session,
                    client,
                    &mut framing,
                )
                .await?;
                if let Some(guard) = generation_guard {
                    guard.ensure_current()?;
                }
                let partial = unit.len() < length;
                remaining -= unit.len() as u64;
                buffer_normalized_response_bytes(
                    session,
                    client,
                    &mut pending,
                    unit,
                    &mut framing,
                    unit_limit,
                )
                .await?;
                if partial {
                    flush_normalized_response_bytes(
                        session,
                        client,
                        std::mem::take(&mut pending),
                        &mut framing,
                    )
                    .await?;
                }
            }
            flush_normalized_response_bytes(session, client, pending, &mut framing).await?;
            Ok(Vec::new())
        }
        BodyLength::Chunked => {
            let mut size_line =
                read_response_line_with_deadline(reader, session, client, &mut framing).await?;
            loop {
                let chunk_size = parse_chunk_size_line(&size_line)?;
                if chunk_size == 0 {
                    flush_normalized_response_bytes(session, client, pending, &mut framing).await?;
                    return read_response_trailers(
                        reader,
                        session,
                        client,
                        &mut framing,
                        connection_nominated_headers,
                    )
                    .await;
                }
                let mut remaining = chunk_size;
                while remaining > 0 {
                    let length = remaining.min(unit_limit);
                    let unit = read_response_payload_with_deadline(
                        reader,
                        length,
                        !pending.is_empty(),
                        session,
                        client,
                        &mut framing,
                    )
                    .await?;
                    if let Some(guard) = generation_guard {
                        guard.ensure_current()?;
                    }
                    let partial = unit.len() < length;
                    remaining -= unit.len();
                    buffer_normalized_response_bytes(
                        session,
                        client,
                        &mut pending,
                        unit,
                        &mut framing,
                        unit_limit,
                    )
                    .await?;
                    if partial {
                        flush_normalized_response_bytes(
                            session,
                            client,
                            std::mem::take(&mut pending),
                            &mut framing,
                        )
                        .await?;
                    }
                }
                let terminator = if let Ok(result) =
                    tokio::time::timeout(RESPONSE_UNIT_COALESCE_TIMEOUT, reader.read_exact_vec(2))
                        .await
                {
                    result?
                } else {
                    flush_normalized_response_bytes(
                        session,
                        client,
                        std::mem::take(&mut pending),
                        &mut framing,
                    )
                    .await?;
                    read_exact_response_with_deadline(reader, 2, session, client, &mut framing)
                        .await?
                };
                if terminator != b"\r\n" {
                    return Err(miette!("HTTP response chunk is missing its terminator"));
                }
                size_line = if let Ok(line) =
                    tokio::time::timeout(RESPONSE_UNIT_COALESCE_TIMEOUT, reader.read_line()).await
                {
                    line?
                } else {
                    flush_normalized_response_bytes(
                        session,
                        client,
                        std::mem::take(&mut pending),
                        &mut framing,
                    )
                    .await?;
                    read_response_line_with_deadline(reader, session, client, &mut framing).await?
                };
            }
        }
        BodyLength::None if server_wants_close || event_stream => loop {
            // Cancel only input acquisition, never expiry or client writes.
            let wait = if pending.is_empty() {
                if event_stream {
                    None
                } else {
                    Some(RELAY_EOF_IDLE_TIMEOUT)
                }
            } else {
                Some(RESPONSE_UNIT_COALESCE_TIMEOUT)
            };
            let read_deadline = wait.map(|wait| tokio::time::Instant::now() + wait);
            let whole_deadline = session.whole_body_deadline();
            let deadline = match (read_deadline, whole_deadline) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            let next = if let Some(deadline) = deadline {
                if let Ok(result) =
                    tokio::time::timeout_at(deadline, reader.read_some(unit_limit)).await
                {
                    result?
                } else {
                    if whole_deadline.is_some_and(|d| d <= tokio::time::Instant::now()) {
                        expire_whole_body_deadline(session, client, &mut framing).await?;
                    } else if pending.is_empty() {
                        return Ok(Vec::new());
                    } else {
                        flush_normalized_response_bytes(
                            session,
                            client,
                            std::mem::take(&mut pending),
                            &mut framing,
                        )
                        .await?;
                    }
                    continue;
                }
            } else {
                reader.read_some(unit_limit).await?
            };
            let Some(unit) = next else {
                flush_normalized_response_bytes(session, client, pending, &mut framing).await?;
                return Ok(Vec::new());
            };
            if let Some(guard) = generation_guard {
                guard.ensure_current()?;
            }
            buffer_normalized_response_bytes(
                session,
                client,
                &mut pending,
                unit,
                &mut framing,
                unit_limit,
            )
            .await?;
        },
        BodyLength::None => {
            flush_normalized_response_bytes(session, client, pending, &mut framing).await?;
            Ok(Vec::new())
        }
    }
}

struct ResponseOutputState<'a> {
    committed: &'a mut bool,
    chunked: bool,
    commit_head: &'a [u8],
    generation_guard: Option<&'a PolicyGenerationGuard>,
    policy_name: &'a str,
    target: &'a HttpRequestTarget,
    status_code: u16,
    correlation: Option<&'a RequestCorrelation>,
}

#[derive(Debug)]
struct ResponseMiddlewareStop {
    failure: openshell_supervisor_middleware::HttpResponseMiddlewareFailure,
    diagnostics: openshell_supervisor_middleware::HttpResponseDiagnostics,
}

impl ResponseMiddlewareStop {
    fn new(
        failure: openshell_supervisor_middleware::HttpResponseMiddlewareFailure,
        diagnostics: openshell_supervisor_middleware::HttpResponseDiagnostics,
    ) -> Self {
        Self {
            failure,
            diagnostics,
        }
    }
}

impl fmt::Display for ResponseMiddlewareStop {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "HTTP response middleware stopped delivery: {}",
            self.failure
        )
    }
}

impl std::error::Error for ResponseMiddlewareStop {}

impl miette::Diagnostic for ResponseMiddlewareStop {}

#[derive(Debug)]
struct ResponseDownstreamWrite(std::io::Error);

impl fmt::Display for ResponseDownstreamWrite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "HTTP response client write failed: {}", self.0)
    }
}

impl std::error::Error for ResponseDownstreamWrite {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

impl miette::Diagnostic for ResponseDownstreamWrite {}

async fn expire_whole_body_deadline<C: AsyncWrite + Unpin>(
    session: &mut openshell_supervisor_middleware::HttpResponseSession,
    client: &mut C,
    framing: &mut ResponseOutputState<'_>,
) -> Result<()> {
    let output = session.expire_whole_body_deadline().await;
    if let Some(guard) = framing.generation_guard {
        guard.ensure_current()?;
    }
    let diagnostics = session.take_diagnostics();
    if output.is_ok() {
        emit_http_response_diagnostics(
            framing.correlation,
            framing.policy_name,
            framing.target,
            framing.status_code,
            &diagnostics,
        );
    }
    let output = output.map_err(|failure| ResponseMiddlewareStop::new(failure, diagnostics))?;
    deliver_response_units(client, output, framing, session.requires_whole_body()).await
}

// Unit size is a maximum. Coalesce available payload without waiting for
// the rest of a transfer chunk, and finish expiry outside read timeouts.
async fn read_response_payload_with_deadline<R, C>(
    reader: &mut BufferedResponseReader<'_, R>,
    limit: usize,
    has_pending: bool,
    session: &mut openshell_supervisor_middleware::HttpResponseSession,
    client: &mut C,
    framing: &mut ResponseOutputState<'_>,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    let mut payload = Vec::new();
    let mut coalesce_deadline =
        has_pending.then(|| tokio::time::Instant::now() + RESPONSE_UNIT_COALESCE_TIMEOUT);
    loop {
        let whole_deadline = session.whole_body_deadline();
        let deadline = match (coalesce_deadline, whole_deadline) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let read = reader.read_some(limit - payload.len());
        let result = if let Some(deadline) = deadline {
            if let Ok(result) = tokio::time::timeout_at(deadline, read).await {
                result
            } else {
                if whole_deadline.is_some_and(|d| d <= tokio::time::Instant::now()) {
                    expire_whole_body_deadline(session, client, framing).await?;
                }
                if coalesce_deadline.is_some_and(|d| d <= tokio::time::Instant::now()) {
                    return Ok(payload);
                }
                continue;
            }
        } else {
            read.await
        };
        let data = result?.ok_or_else(|| miette!("HTTP response body ended unexpectedly"))?;
        payload.extend_from_slice(&data);
        if payload.len() == limit {
            return Ok(payload);
        }
        coalesce_deadline
            .get_or_insert_with(|| tokio::time::Instant::now() + RESPONSE_UNIT_COALESCE_TIMEOUT);
    }
}

async fn read_exact_response_with_deadline<R, C>(
    reader: &mut BufferedResponseReader<'_, R>,
    length: usize,
    session: &mut openshell_supervisor_middleware::HttpResponseSession,
    client: &mut C,
    framing: &mut ResponseOutputState<'_>,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    loop {
        let Some(deadline) = session.whole_body_deadline() else {
            return reader.read_exact_vec(length).await;
        };
        match tokio::time::timeout_at(deadline, reader.read_exact_vec(length)).await {
            Ok(result) => return result,
            Err(_) => expire_whole_body_deadline(session, client, framing).await?,
        }
    }
}

async fn read_response_line_with_deadline<R, C>(
    reader: &mut BufferedResponseReader<'_, R>,
    session: &mut openshell_supervisor_middleware::HttpResponseSession,
    client: &mut C,
    framing: &mut ResponseOutputState<'_>,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    loop {
        let Some(deadline) = session.whole_body_deadline() else {
            return reader.read_line().await;
        };
        match tokio::time::timeout_at(deadline, reader.read_line()).await {
            Ok(result) => return result,
            Err(_) => expire_whole_body_deadline(session, client, framing).await?,
        }
    }
}

async fn buffer_normalized_response_bytes<C: AsyncWrite + Unpin>(
    session: &mut openshell_supervisor_middleware::HttpResponseSession,
    client: &mut C,
    pending: &mut Vec<u8>,
    data: Vec<u8>,
    framing: &mut ResponseOutputState<'_>,
    unit_limit: usize,
) -> Result<()> {
    pending.extend_from_slice(&data);
    while pending.len() >= unit_limit {
        let remainder = pending.split_off(unit_limit);
        let unit = std::mem::replace(pending, remainder);
        process_response_unit(session, client, unit, framing).await?;
    }
    Ok(())
}

async fn flush_normalized_response_bytes<C: AsyncWrite + Unpin>(
    session: &mut openshell_supervisor_middleware::HttpResponseSession,
    client: &mut C,
    pending: Vec<u8>,
    framing: &mut ResponseOutputState<'_>,
) -> Result<()> {
    if pending.is_empty() {
        return Ok(());
    }
    process_response_unit(session, client, pending, framing).await
}

async fn process_response_unit<C: AsyncWrite + Unpin>(
    session: &mut openshell_supervisor_middleware::HttpResponseSession,
    client: &mut C,
    unit: Vec<u8>,
    framing: &mut ResponseOutputState<'_>,
) -> Result<()> {
    let output = session.push_body(unit).await;
    if let Some(guard) = framing.generation_guard {
        guard.ensure_current()?;
    }
    let diagnostics = session.take_diagnostics();
    if output.is_ok() {
        emit_http_response_diagnostics(
            framing.correlation,
            framing.policy_name,
            framing.target,
            framing.status_code,
            &diagnostics,
        );
    }
    let output = output.map_err(|failure| ResponseMiddlewareStop::new(failure, diagnostics))?;
    deliver_response_units(client, output, framing, session.requires_whole_body()).await
}

async fn deliver_response_units<C: AsyncWrite + Unpin>(
    client: &mut C,
    output: Vec<Vec<u8>>,
    framing: &mut ResponseOutputState<'_>,
    whole_body_pending: bool,
) -> Result<()> {
    if !*framing.committed && !output.is_empty() {
        if whole_body_pending {
            return Err(miette!(
                "whole-body response middleware released output before finalization"
            ));
        }
        // `write_all` may return an error after a partial write. Treat the
        // response as committed before the attempt so callers never append a
        // canonical error response behind a partially delivered upstream head.
        *framing.committed = true;
        client
            .write_all(framing.commit_head)
            .await
            .map_err(ResponseDownstreamWrite)?;
        client.flush().await.map_err(ResponseDownstreamWrite)?;
    }
    if *framing.committed {
        for unit in output {
            if framing.chunked {
                write_downstream_response_chunk(client, &unit).await?;
            } else {
                client
                    .write_all(&unit)
                    .await
                    .map_err(ResponseDownstreamWrite)?;
            }
        }
        client.flush().await.map_err(ResponseDownstreamWrite)?;
    }
    Ok(())
}

async fn write_downstream_response_chunk<C: AsyncWrite + Unpin>(
    client: &mut C,
    payload: &[u8],
) -> Result<()> {
    if payload.is_empty() {
        return Ok(());
    }
    client
        .write_all(format!("{:X}\r\n", payload.len()).as_bytes())
        .await
        .map_err(ResponseDownstreamWrite)?;
    client
        .write_all(payload)
        .await
        .map_err(ResponseDownstreamWrite)?;
    client
        .write_all(b"\r\n")
        .await
        .map_err(ResponseDownstreamWrite)?;
    Ok(())
}

async fn read_response_trailers<R, C>(
    reader: &mut BufferedResponseReader<'_, R>,
    session: &mut openshell_supervisor_middleware::HttpResponseSession,
    client: &mut C,
    framing: &mut ResponseOutputState<'_>,
    connection_nominated_headers: &[String],
) -> Result<Vec<HttpHeader>>
where
    R: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    let mut trailers = Vec::new();
    loop {
        let line = read_response_line_with_deadline(reader, session, client, framing).await?;
        validate_chunk_trailer_line(&line)?;
        if line.is_empty() {
            return Ok(trailers);
        }
        let line = std::str::from_utf8(&line)
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
    }
}

async fn write_response_trailers<C: AsyncWrite + Unpin>(
    client: &mut C,
    trailers: &[HttpHeader],
) -> Result<()> {
    client.write_all(b"0\r\n").await.into_diagnostic()?;
    for trailer in trailers {
        client
            .write_all(format!("{}: {}\r\n", trailer.name, trailer.value).as_bytes())
            .await
            .into_diagnostic()?;
    }
    client.write_all(b"\r\n").await.into_diagnostic()?;
    Ok(())
}

async fn send_response_middleware_denial<C: AsyncWrite + Unpin>(
    client: &mut C,
    request_method: &str,
    policy_name: &str,
    target: &HttpRequestTarget,
    denial: &openshell_supervisor_middleware::MiddlewareDenial,
    stage: &'static str,
    correlation: Option<&RequestCorrelation>,
) -> Result<()> {
    record_denied_response(correlation, stage);
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
    let head = final_response_head(head.as_bytes(), correlation);
    client.write_all(&head).await.into_diagnostic()?;
    if !request_method.eq_ignore_ascii_case("HEAD") {
        client.write_all(&body).await.into_diagnostic()?;
    }
    client.flush().await.into_diagnostic()?;
    Ok(())
}

/// Answer a response that middleware failed before its head was committed.
/// An HTTP hook failure carries its platform-owned code and stage.
#[allow(clippy::too_many_arguments)]
async fn send_response_delivery_failure<C: AsyncWrite + Unpin>(
    client: &mut C,
    request_method: &str,
    policy_name: &str,
    target: &HttpRequestTarget,
    failure: Option<&openshell_supervisor_middleware::MiddlewareFailureDetail>,
    outcome: HttpOutcome,
    stage: &'static str,
    correlation: Option<&RequestCorrelation>,
) -> Result<()> {
    if let Some(correlation) = correlation {
        if outcome == HttpOutcome::UpstreamError {
            correlation.record_response_status(502);
            correlation.record_failure(outcome, stage);
        } else {
            correlation.record_rejection(502, outcome, Some(stage));
        }
    }
    let mut body = serde_json::json!({
        "error": "response_delivery_failed",
        "detail": "The upstream request may have completed, but OpenShell could not deliver its response. Retrying may repeat upstream side effects.",
        "policy": policy_name,
        "layer": "http_response_pre_return",
        "method": target.method,
        "path": target.path,
        "host": target.host,
        "port": target.port,
    });
    if let Some(failure) = failure {
        insert_middleware_failure(&mut body, failure);
    }
    let body = body_with_request_id(body, correlation.map(RequestCorrelation::request_id));
    let body = serde_json::to_vec(&body).into_diagnostic()?;
    let head = format!(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-OpenShell-Policy: {policy_name}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let head = final_response_head(head.as_bytes(), correlation);
    client.write_all(&head).await.into_diagnostic()?;
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
    use super::{final_response_head, strip_platform_request_id_from_connection};
    use crate::l7::correlation::HttpOutcome;
    use crate::l7::rest::strip_platform_request_id_from_head;
    use openshell_supervisor_middleware::{
        HttpResponseInvocation, HttpResponseInvocationOutcome as Outcome, NamespacedFinding,
    };
    use std::borrow::Cow;

    fn invocation(outcome: Outcome, failed: bool) -> HttpResponseInvocation {
        HttpResponseInvocation {
            config_name: "guard".to_string(),
            implementation: "test/guard".to_string(),
            outcome,
            sequence: None,
            input_size: 0,
            output_size: None,
            failed,
            stage_disabled: false,
            reason_code: None,
            failure_category: None,
        }
    }

    fn finding() -> NamespacedFinding {
        NamespacedFinding {
            middleware: "guard".to_string(),
            finding: openshell_core::proto::Finding {
                r#type: "test.finding".to_string(),
                label: "Test finding".to_string(),
                count: 1,
                severity: "high".to_string(),
                ..Default::default()
            },
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn response_terminal_failure_without_diagnostics_has_no_deny_trace() {
        use crate::telemetry::tests::{assert_no_deny, exported};

        // Platform refusals can lack invocation diagnostics, but must retain
        // their terminal failure record. Without an HTTP record, no deny span.
        for committed in [false, true] {
            let (events, received) = exported("warn", || {
                super::emit_http_response_middleware_failure(
                    None,
                    "response-policy",
                    &HttpRequestTarget::default(),
                    200,
                    committed,
                );
            })
            .await;

            assert_eq!(events.len(), 1, "only the terminal failure is emitted");
            assert_eq!(
                events[0]["finding_info"]["uid"],
                "openshell.middleware.http_response_failure"
            );
            assert_no_deny(&events, &received);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn response_diagnostic_findings_share_a_deny_span_only_when_delivery_is_denied() {
        use crate::telemetry::tests::{assert_deny_resolves, assert_no_deny, exported};

        for denied in [false, true] {
            let (events, received) = exported("warn", || {
                let outcome = if denied {
                    Outcome::BlockDelivery
                } else {
                    Outcome::PassThrough
                };
                let diagnostics = openshell_supervisor_middleware::HttpResponseDiagnostics {
                    invocations: vec![invocation(outcome, false)],
                    findings: vec![finding()],
                    ..Default::default()
                };
                super::emit_http_response_diagnostics(
                    None,
                    "response-policy",
                    &HttpRequestTarget::default(),
                    200,
                    &diagnostics,
                );
            })
            .await;
            // A blocking invocation adds its own block finding.
            assert_eq!(events.len(), if denied { 3 } else { 2 });
            if denied {
                let blocked = events
                    .iter()
                    .find(|event| {
                        event["finding_info"]["uid"] == "openshell.middleware.http_response_blocked"
                    })
                    .expect("blocked delivery emits its refusal finding");
                assert_eq!(blocked["action_id"], 2);
                assert_eq!(blocked["action"], "Denied");
                assert_eq!(received.spans.len(), 1);
                assert_deny_resolves(&events, &received, true);
            } else {
                assert_no_deny(&events, &received);
            }
        }
    }

    #[test]
    fn fail_closed_invocations_and_enforced_failures_record_the_denial() {
        let target = HttpRequestTarget::default();
        for (outcome, failed, action_id) in [
            (Outcome::BlockDelivery, false, 2),
            (Outcome::FailClosed, true, 2),
            (Outcome::FailOpen, true, 99),
            (Outcome::PassThrough, false, 1),
        ] {
            let events = super::http_response_middleware_invocation_events(
                "p",
                &target,
                200,
                &[invocation(outcome, failed)],
            );
            assert_eq!(
                events[0].to_json().unwrap()["action_id"],
                action_id,
                "{outcome:?}"
            );
        }
        for denied in [false, true] {
            let failure =
                super::http_response_middleware_failure_event("p", &target, 200, false, denied)
                    .to_json()
                    .unwrap();
            assert_eq!(failure["action_id"] == 2, denied);
        }
    }

    #[test]
    fn late_fail_open_invocation_does_not_hide_block_delivery() {
        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let _subscriber = capture.install();
        let correlation = test_correlation("late-response-receipt");
        let target = HttpRequestTarget {
            method: "GET".into(),
            scheme: "https".into(),
            host: "example.test".into(),
            path: "/data".into(),
            port: 443,
            ..Default::default()
        };
        correlation.emit(
            openshell_ocsf::HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .http_request(openshell_ocsf::HttpRequest::new(
                    "GET",
                    openshell_ocsf::Url::new("https", "example.test", "/data", 443),
                ))
                .action(openshell_ocsf::ActionId::Allowed)
                .status(openshell_ocsf::StatusId::Success)
                .build(),
        );
        correlation.response_selected(200);
        for (outcome, failed) in [(Outcome::FailOpen, true), (Outcome::BlockDelivery, false)] {
            for event in super::http_response_middleware_invocation_events(
                "response-policy",
                &target,
                200,
                &[invocation(outcome, failed)],
            ) {
                correlation.emit(event);
            }
        }
        drop(correlation);
        let events: Vec<_> = capture
            .json_events()
            .into_iter()
            .filter(|event| event["class_uid"] == 4002)
            .collect();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0]["unmapped"]["http_event_kind"], "request");
        assert_eq!(events[0]["action"], "Allowed");
        assert_eq!(events[1]["action"], "Other");
        assert_eq!(
            events[1]["unmapped"]["response_middleware_outcome"],
            "failopen"
        );
        assert_eq!(events[2]["action"], "Denied");
        for event in &events[1..] {
            assert_eq!(
                event["unmapped"]["http_event_kind"],
                "middleware_invocation"
            );
            assert_eq!(event["unmapped"]["middleware_phase"], "response");
            assert_eq!(event["http_response"]["code"], 200);
        }
        assert_eq!(
            events[2]["unmapped"]["response_middleware_outcome"],
            "blockdelivery"
        );
        assert!(
            events
                .iter()
                .all(|event| event["metadata"]["correlation_uid"] == "late-response-receipt")
        );
    }

    use super::{
        DEFAULT_HTTP_RESPONSE_WHOLE_BODY_TIMEOUT, HttpResponseMiddlewareRelay,
        RelayResponseOptions, ResponseFraming, parse_connection_keep_alive,
        parse_response_head_for_middleware, relay_response, response_is_http_10,
        serialize_response_head, validate_http_response_header_block,
    };
    use crate::l7::provider::{BodyLength, L7Request, RelayOutcome};
    use crate::l7::relay::L7EvalContext;
    use openshell_core::proto::{
        Decision, HttpHeader, HttpRequestResult, HttpRequestTarget, HttpResponseBlockDelivery,
        HttpResponseBodyMode, HttpResponseBodyResult, HttpResponseBodyTransform, HttpResponseEvent,
        HttpResponseEventResult, HttpResponsePreflightInspect, HttpResponsePreflightResult,
        HttpResponseTrailersResult, MiddlewareBinding, MiddlewareManifest, RequestContext,
        SupervisorMiddlewareOperation, SupervisorMiddlewarePhase, http_response_body_result,
        http_response_body_transform, http_response_body_unit, http_response_event,
        http_response_event_result, http_response_preflight_result,
    };
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;

    struct StreamingResponseMiddleware;

    struct BlockingResponseMiddleware;

    #[tonic::async_trait]
    impl openshell_supervisor_middleware::InProcessMiddleware for BlockingResponseMiddleware {
        async fn describe(&self) -> MiddlewareManifest {
            MiddlewareManifest {
                name: "test/blocking-response".into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpResponse as i32,
                    phase: SupervisorMiddlewarePhase::PreReturn as i32,
                    max_payload_bytes: 4096,
                    request_timeout: None,
                }],
                expected_audience: String::new(),
                extension: Some(openshell_core::extension_protocol::extension_metadata(
                    openshell_core::extension_protocol::ExtensionFamily::SupervisorMiddleware,
                    "openshell/test-blocking-response",
                    "test",
                    [],
                )),
            }
        }

        async fn validate_config(
            &self,
            _middleware_name: &str,
            _config: &prost_types::Struct,
        ) -> miette::Result<()> {
            Ok(())
        }

        async fn evaluate_http_request(
            &self,
            _request: openshell_supervisor_middleware::HttpRequestView<'_>,
        ) -> miette::Result<HttpRequestResult> {
            Ok(HttpRequestResult {
                decision: Decision::Allow as i32,
                ..Default::default()
            })
        }

        async fn open_http_response_pre_return(
            &self,
            mut requests: mpsc::Receiver<HttpResponseEvent>,
        ) -> Result<openshell_supervisor_middleware::HttpResponseResultStream, tonic::Status>
        {
            let first = requests
                .recv()
                .await
                .ok_or_else(|| tonic::Status::invalid_argument("missing response preflight"))?;
            if !matches!(first.event, Some(http_response_event::Event::Preflight(_))) {
                return Err(tonic::Status::invalid_argument(
                    "expected response preflight",
                ));
            }
            let result = HttpResponseEventResult {
                result: Some(http_response_event_result::Result::PreflightResult(
                    HttpResponsePreflightResult {
                        action: Some(http_response_preflight_result::Action::BlockDelivery(
                            HttpResponseBlockDelivery {},
                        )),
                        reason_code: "test_block".into(),
                        ..Default::default()
                    },
                )),
            };
            Ok(Box::pin(futures::stream::iter([Ok(result)])))
        }
    }

    #[tonic::async_trait]
    impl openshell_supervisor_middleware::InProcessMiddleware for StreamingResponseMiddleware {
        async fn describe(&self) -> MiddlewareManifest {
            MiddlewareManifest {
                name: "test/streaming-response".into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpResponse as i32,
                    phase: SupervisorMiddlewarePhase::PreReturn as i32,
                    max_payload_bytes: 4096,
                    request_timeout: None,
                }],
                expected_audience: String::new(),
                extension: Some(openshell_core::extension_protocol::extension_metadata(
                    openshell_core::extension_protocol::ExtensionFamily::SupervisorMiddleware,
                    "openshell/test-streaming-response",
                    "test",
                    [],
                )),
            }
        }

        async fn validate_config(
            &self,
            _middleware_name: &str,
            _config: &prost_types::Struct,
        ) -> miette::Result<()> {
            Ok(())
        }

        async fn evaluate_http_request(
            &self,
            _request: openshell_supervisor_middleware::HttpRequestView<'_>,
        ) -> miette::Result<HttpRequestResult> {
            Ok(HttpRequestResult {
                decision: Decision::Allow as i32,
                ..Default::default()
            })
        }

        async fn open_http_response_pre_return(
            &self,
            mut requests: mpsc::Receiver<HttpResponseEvent>,
        ) -> Result<openshell_supervisor_middleware::HttpResponseResultStream, tonic::Status>
        {
            let (sender, receiver) = mpsc::channel(4);
            tokio::spawn(async move {
                while let Some(event) = requests.recv().await {
                    let Some(event) = event.event else {
                        break;
                    };
                    let result = match event {
                        http_response_event::Event::Preflight(_) => HttpResponseEventResult {
                            result: Some(http_response_event_result::Result::PreflightResult(
                                HttpResponsePreflightResult {
                                    action: Some(http_response_preflight_result::Action::Inspect(
                                        HttpResponsePreflightInspect {
                                            body_mode: HttpResponseBodyMode::StreamBytes as i32,
                                            header_mutations: Vec::new(),
                                        },
                                    )),
                                    ..Default::default()
                                },
                            )),
                        },
                        http_response_event::Event::Body(body) => {
                            let Some(http_response_body_unit::Payload::Data(data)) = body.payload
                            else {
                                break;
                            };
                            HttpResponseEventResult {
                                result: Some(http_response_event_result::Result::BodyResult(
                                    HttpResponseBodyResult {
                                        sequence: body.sequence,
                                        action: Some(http_response_body_result::Action::Transform(
                                            HttpResponseBodyTransform {
                                                replacement: Some(
                                                    http_response_body_transform::Replacement::Data(
                                                        data,
                                                    ),
                                                ),
                                            },
                                        )),
                                        ..Default::default()
                                    },
                                )),
                            }
                        }
                        http_response_event::Event::Trailers(_) => HttpResponseEventResult {
                            result: Some(http_response_event_result::Result::TrailersResult(
                                HttpResponseTrailersResult::default(),
                            )),
                        },
                        http_response_event::Event::SessionEnd(_) => break,
                    };
                    if sender.send(Ok(result)).await.is_err() {
                        break;
                    }
                }
            });
            Ok(Box::pin(ReceiverStream::new(receiver)))
        }
    }

    fn test_correlation_for_method(
        request_id: &str,
        method: &str,
    ) -> crate::l7::correlation::RequestCorrelation {
        let request = L7Request {
            action: method.into(),
            target: "/data".into(),
            query_params: HashMap::new(),
            raw_header: b"GET /data HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec(),
            body_length: BodyLength::None,
        };
        crate::l7::correlation::RequestCorrelation::with_request_id(
            &request,
            &L7EvalContext {
                host: "example.test".into(),
                port: 443,
                ..Default::default()
            },
            request_id.into(),
        )
    }

    fn test_correlation(request_id: &str) -> crate::l7::correlation::RequestCorrelation {
        test_correlation_for_method(request_id, "GET")
    }

    #[test]
    fn untouched_receipt_heads_remain_borrowed() {
        let head = b"HTTP/1.1 200\r\nX-Opaque: \xff\xfe\r\nX-Duplicate: first\r\nX-Duplicate: second\r\nConnection: keep-alive\r\nTrailer: X-Checksum\r\n\r\nbody";
        let uncorrelated = final_response_head(head, None);
        assert!(matches!(uncorrelated, Cow::Borrowed(_)));
        assert_eq!(uncorrelated.as_ref(), head);

        let stripped = strip_platform_request_id_from_head(head);
        assert!(matches!(stripped, Cow::Borrowed(_)));
        let stripped = strip_platform_request_id_from_connection(stripped);
        assert!(matches!(stripped, Cow::Borrowed(_)));
        assert_eq!(stripped.as_ref(), head);
    }

    #[test]
    fn receipt_head_rewrite_preserves_unrelated_bytes_and_buffered_body() {
        let correlation = test_correlation("receipt-cow");
        let head = b"HTTP/1.1 200\r\nX-Opaque: \xff\xfe\r\nX-Duplicate: first\r\nX-Duplicate: second\r\nX-OpenShell-Request-ID: forged\r\nx-openshell-request-id: forged-again\r\nConnection: keep-alive, X-OpenShell-Request-ID, , Upgrade\r\nTrailer: X-OpenShell-Request-ID, X-Checksum\r\n\r\n\x00\xffbody";

        let rewritten = final_response_head(head, Some(&correlation));
        assert!(matches!(rewritten, Cow::Owned(_)));
        assert_eq!(
            rewritten.as_ref(),
            b"HTTP/1.1 200\r\nX-Opaque: \xff\xfe\r\nX-Duplicate: first\r\nX-Duplicate: second\r\nConnection: keep-alive, Upgrade\r\nTrailer: X-Checksum\r\nx-openshell-request-id: receipt-cow\r\n\r\n\x00\xffbody"
        );
    }

    #[test]
    fn clean_correlated_head_adds_only_the_receipt() {
        let correlation = test_correlation("receipt-clean");
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody";

        let rewritten = final_response_head(head, Some(&correlation));
        assert_eq!(
            rewritten.as_ref(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nx-openshell-request-id: receipt-clean\r\n\r\nbody"
        );
    }

    fn request_id_header_count(response: &[u8]) -> usize {
        String::from_utf8_lossy(response)
            .lines()
            .filter(|line| {
                line.split_once(':').is_some_and(|(name, _)| {
                    name.eq_ignore_ascii_case(
                        openshell_core::token_grant_failure::REQUEST_ID_HEADER,
                    )
                })
            })
            .count()
    }

    #[tokio::test]
    async fn allowed_final_response_carries_platform_receipt() {
        let correlation = test_correlation("receipt-1");
        let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"[..];
        let mut client = Vec::new();

        let outcome = relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("relay response");

        assert!(matches!(outcome, RelayOutcome::Reusable));
        assert_eq!(request_id_header_count(&client), 1);
        assert!(String::from_utf8_lossy(&client).contains("x-openshell-request-id: receipt-1\r\n"));
    }

    #[tokio::test]
    async fn delivery_failure_receipt_distinguishes_upstream_error_from_local_block() {
        for outcome in [HttpOutcome::UpstreamError, HttpOutcome::PlatformError] {
            let capture = openshell_ocsf::test_support::OcsfCapture::default();
            let _subscriber = capture.install();
            let correlation = test_correlation("delivery-failure");
            let target = HttpRequestTarget {
                scheme: "https".into(),
                host: "example.test".into(),
                port: 443,
                method: "GET".into(),
                path: "/data".into(),
                query: String::new(),
            };
            let mut client = Vec::new();
            {
                let mut client = correlation.observe_response(&mut client);
                super::send_response_delivery_failure(
                    &mut client,
                    "GET",
                    "policy",
                    &target,
                    None,
                    outcome,
                    "response_body",
                    Some(&correlation),
                )
                .await
                .unwrap();
            }
            drop(correlation);
            assert_eq!(request_id_header_count(&client), 1);
            let events = capture.json_events();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0]["http_response"]["code"], 502);
            assert_eq!(events[0]["metadata"]["correlation_uid"], "delivery-failure");
            assert_eq!(
                events[0]["action"] == "Denied",
                outcome == HttpOutcome::PlatformError
            );
        }
    }

    #[tokio::test]
    async fn correlated_upstream_eof_preserves_transport_close_and_audits_failure() {
        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let _subscriber = capture.install();
        let correlation = test_correlation("eof-request");
        let mut upstream = tokio::io::empty();
        let mut client = Vec::new();
        let outcome = relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("upstream close");
        assert!(matches!(outcome, RelayOutcome::Consumed));
        assert!(
            client.is_empty(),
            "EOF must not become a synthetic HTTP response"
        );
        drop(correlation);
        let records = capture.json_events();
        let primary: Vec<_> = records
            .iter()
            .filter(|event| event["class_uid"] == 4002)
            .collect();
        assert_eq!(primary.len(), 1, "{records:?}");
        assert_eq!(primary[0]["status"], "Failure");
        assert_eq!(primary[0]["metadata"]["correlation_uid"], "eof-request");
        assert!(primary[0].get("http_response").is_none());
    }

    #[tokio::test]
    async fn correlated_response_without_reason_phrase_retains_legacy_tolerance() {
        let correlation = test_correlation("empty-reason");
        let mut upstream = b"HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n".as_slice();
        let mut client = Vec::new();
        relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("tolerated status line");
        assert!(client.starts_with(b"HTTP/1.1 200\r\n"));
        assert_eq!(request_id_header_count(&client), 1);
    }

    #[tokio::test]
    async fn uncorrelated_response_preserves_application_owned_request_id() {
        let response =
            b"HTTP/1.1 200\r\nContent-Length: 0\r\nX-OpenShell-Request-ID: application\r\n\r\n";
        let mut upstream = response.as_slice();
        let mut client = Vec::new();
        relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions::default(),
            None,
        )
        .await
        .expect("legacy response");
        assert_eq!(client, response);
    }

    #[tokio::test]
    async fn response_middleware_denial_has_one_correlated_primary_without_tracing() {
        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let _subscriber = capture.install();
        exercise_response_middleware_block().await;

        assert_response_middleware_block_record(&capture.json_events(), false);
    }

    async fn exercise_response_middleware_block() {
        let correlation = test_correlation_for_method("response-denied", "POST");
        correlation.emit(
            openshell_ocsf::HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .http_request(openshell_ocsf::HttpRequest::new(
                    "POST",
                    openshell_ocsf::Url::new("https", "example.test", "/mutate", 443),
                ))
                .firewall_rule("test-policy", "l7-rest")
                .action(openshell_ocsf::ActionId::Allowed)
                .status(openshell_ocsf::StatusId::Success)
                .build(),
        );
        let runner =
            openshell_supervisor_middleware::ChainRunner::new(Arc::new(BlockingResponseMiddleware));
        let chain = vec![openshell_supervisor_middleware::ChainEntry {
            name: "response".into(),
            implementation: "test/blocking-response".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: openshell_supervisor_middleware::OnError::FailClosed,
        }];
        let middleware = HttpResponseMiddlewareRelay {
            chain: &chain,
            runner: &runner,
            request_context: RequestContext {
                request_id: "response-denied".into(),
                sandbox_id: "sandbox-1".into(),
                ..Default::default()
            },
            target: HttpRequestTarget {
                scheme: "https".into(),
                host: "example.test".into(),
                port: 443,
                method: "POST".into(),
                path: "/mutate".into(),
                query: String::new(),
            },
            policy_name: "test-policy",
            generation_guard: None,
            whole_body_timeout: DEFAULT_HTTP_RESPONSE_WHOLE_BODY_TIMEOUT,
            client_accepts_chunked: true,
            request_head: None,
        };
        let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[..];
        let mut client = Vec::new();

        let outcome = relay_response(
            "POST",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            Some(middleware),
        )
        .await
        .expect("middleware denial response");

        assert!(matches!(outcome, RelayOutcome::Consumed));
        assert!(client.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));
        assert!(
            String::from_utf8_lossy(&client)
                .contains("x-openshell-request-id: response-denied\r\n")
        );
        drop(correlation);
    }

    fn assert_response_middleware_block_record(records: &[serde_json::Value], traced: bool) {
        let http: Vec<_> = records
            .iter()
            .filter(|event| event["class_uid"] == 4002)
            .collect();
        assert_eq!(http.len(), 2);
        let companions: Vec<_> = http
            .iter()
            .filter(|event| event["unmapped"]["http_event_kind"] == "middleware_invocation")
            .collect();
        assert_eq!(companions.len(), 1);
        assert_eq!(companions[0]["http_response"]["code"], 200);
        assert_eq!(companions[0]["unmapped"]["middleware_phase"], "response");
        assert_eq!(
            companions[0]["unmapped"]["response_middleware_outcome"],
            "blockdelivery"
        );
        assert_eq!(companions[0]["action"], "Denied");
        assert_eq!(
            companions[0]["metadata"]["correlation_uid"],
            "response-denied"
        );
        let primary: Vec<_> = records
            .iter()
            .filter(|event| {
                event["class_uid"] == 4002 && event["unmapped"]["http_event_kind"] == "request"
            })
            .collect();
        assert_eq!(primary.len(), 1, "{records:?}");
        assert_eq!(primary[0]["action"], "Denied");
        assert_eq!(primary[0]["status"], "Failure");
        assert_eq!(primary[0]["http_response"]["code"], 403);
        assert_eq!(primary[0]["http_request"]["url"]["path"], "/mutate");
        assert_eq!(primary[0]["firewall_rule"]["type"], "l7-rest");
        assert_eq!(primary[0]["metadata"]["correlation_uid"], "response-denied");
        assert_eq!(primary[0].get("trace").is_some(), traced);
    }

    #[tokio::test]
    async fn response_middleware_block_never_creates_a_denial_only_span() {
        use crate::l7::relay::correlation_dispatch_tests::capture_request_spans;

        for sampled in [true, false] {
            let evidence = Box::pin(capture_request_spans(
                sampled,
                exercise_response_middleware_block(),
            ))
            .await;
            evidence.assert_no_deny_span(sampled);
            assert_response_middleware_block_record(&evidence.events, sampled);
            if sampled {
                assert_eq!(
                    evidence
                        .spans
                        .iter()
                        .filter(|span| span.name == "openshell.middleware.response")
                        .count(),
                    1
                );
            }
        }
    }

    #[tokio::test]
    async fn upstream_receipt_is_replaced_by_platform_receipt() {
        let correlation = test_correlation("trusted");
        let mut upstream =
            &b"HTTP/1.1 200 OK\r\nX-OpenShell-Request-ID: forged\r\nContent-Length: 0\r\n\r\n"[..];
        let mut client = Vec::new();

        relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("relay response");

        assert!(!String::from_utf8_lossy(&client).contains("forged"));
        assert!(String::from_utf8_lossy(&client).contains("x-openshell-request-id: trusted\r\n"));
        assert_eq!(request_id_header_count(&client), 1);
    }

    #[tokio::test]
    async fn ordinary_response_removes_receipt_connection_nomination() {
        let correlation = test_correlation("trusted");
        let mut upstream = &b"HTTP/1.1 200 OK\r\n\
            Connection: X-OpenShell-Request-ID\r\n\
            cOnNeCtIoN: keep-alive, x-OpEnShElL-rEqUeSt-Id\r\n\
            X-OpenShell-Request-ID: forged-head\r\n\
            Trailer: x-openshell-request-id, X-Checksum\r\n\
            Transfer-Encoding: chunked\r\n\r\n\
            4\r\nbody\r\n\
            0\r\n\
            x-OPENshell-request-ID: forged-trailer\r\n\
            X-Checksum: ok\r\n\r\n"[..];
        let mut client = Vec::new();

        let outcome = relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("relay response");

        assert!(matches!(outcome, RelayOutcome::Reusable));
        let delivered = String::from_utf8(client).expect("HTTP response is UTF-8");
        let head = delivered
            .split_once("\r\n\r\n")
            .expect("response head terminator")
            .0;
        let connection_headers: Vec<_> = head
            .lines()
            .filter(|line| {
                line.split_once(':')
                    .is_some_and(|(name, _)| name.eq_ignore_ascii_case("connection"))
            })
            .collect();
        assert_eq!(connection_headers, ["cOnNeCtIoN: keep-alive"]);
        assert!(!delivered.contains("forged"), "{delivered}");
        assert!(head.contains("Trailer: X-Checksum"), "{head}");
        assert!(delivered.contains("0\r\nX-Checksum: ok\r\n\r\n"));
        assert!(head.contains("x-openshell-request-id: trusted"), "{head}");
        assert_eq!(request_id_header_count(delivered.as_bytes()), 1);
    }

    #[tokio::test]
    async fn ordinary_response_rejects_folded_receipt_connection_nomination() {
        let correlation = test_correlation("trusted");
        let mut upstream = &b"HTTP/1.1 200 OK\r\nConnection: keep-alive,\r\n X-OpenShell-Request-ID\r\nContent-Length: 0\r\n\r\n"[..];
        let mut client = Vec::new();

        let error = relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("folded response fields must fail closed");

        assert!(
            error
                .to_string()
                .contains("response header continuation lines are not supported"),
            "{error}"
        );
        assert!(client.is_empty());
    }

    #[tokio::test]
    async fn ordinary_response_rejects_bare_lf_receipt_smuggling() {
        let correlation = test_correlation("trusted");
        let mut upstream = &b"HTTP/1.1 200 OK\r\nX-Safe: yes\nX-OpenShell-Request-ID: forged\r\nContent-Length: 0\r\n\r\n"[..];
        let mut client = Vec::new();

        let error = relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("bare LF response fields must fail closed");

        assert!(error.to_string().contains("bare LF"), "{error}");
        assert!(client.is_empty());
    }

    #[test]
    fn response_head_validation_rejects_malformed_syntax() {
        let cases: &[(&str, &[u8])] = &[
            ("incomplete block", b"HTTP/1.1 200 OK\r\nX-Test: yes\r\n"),
            ("bare LF", b"HTTP/1.1 200 OK\r\nX-Test: yes\n\r\n"),
            ("bare CR", b"HTTP/1.1 200 OK\r\nX-Test: yes\rX: no\r\n\r\n"),
            (
                "obsolete fold",
                b"HTTP/1.1 200 OK\r\nX-Test: yes\r\n continued\r\n\r\n",
            ),
            ("unsupported protocol", b"HTTP/2 200 OK\r\n\r\n"),
            ("invalid status range", b"HTTP/1.1 099 Nope\r\n\r\n"),
            ("non-numeric status", b"HTTP/1.1 2O0 Nope\r\n\r\n"),
            ("four-digit status", b"HTTP/1.1 2000 Nope\r\n\r\n"),
            ("malformed field", b"HTTP/1.1 200 OK\r\nX-Test\r\n\r\n"),
            ("empty field name", b"HTTP/1.1 200 OK\r\n: value\r\n\r\n"),
            (
                "non-token field name",
                b"HTTP/1.1 200 OK\r\nBad Name: value\r\n\r\n",
            ),
            (
                "whitespace before colon",
                b"HTTP/1.1 200 OK\r\nX-Test : value\r\n\r\n",
            ),
            (
                "field control byte",
                b"HTTP/1.1 200 OK\r\nX-Test: value\x0bmore\r\n\r\n",
            ),
            (
                "field delete byte",
                b"HTTP/1.1 200 OK\r\nX-Test: value\x7f\r\n\r\n",
            ),
            ("reason control byte", b"HTTP/1.1 200 O\x00K\r\n\r\n"),
            (
                "early empty line",
                b"HTTP/1.1 200 OK\r\n\r\nX-Smuggled: yes\r\n\r\n",
            ),
        ];

        for (name, input) in cases {
            assert!(
                validate_http_response_header_block(input).is_err(),
                "{name} unexpectedly passed validation"
            );
        }
    }

    #[test]
    fn response_head_validation_accepts_supported_informational_and_upgrade_responses() {
        for response in [
            &b"HTTP/1.0 200 OK\r\nX-Test: yes\r\n\r\n"[..],
            &b"HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n"[..],
            &b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n"[..],
            &b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"[..],
        ] {
            validate_http_response_header_block(response).expect("valid HTTP/1.x response head");
        }
    }

    #[tokio::test]
    async fn response_middleware_rejects_forged_request_id_trailer() {
        let correlation = test_correlation("trusted");
        let runner = openshell_supervisor_middleware::ChainRunner::new(Arc::new(
            StreamingResponseMiddleware,
        ));
        let chain = vec![openshell_supervisor_middleware::ChainEntry {
            name: "response".into(),
            implementation: "test/streaming-response".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: openshell_supervisor_middleware::OnError::FailClosed,
        }];
        let middleware = HttpResponseMiddlewareRelay {
            chain: &chain,
            runner: &runner,
            request_context: RequestContext {
                request_id: "middleware-request".into(),
                sandbox_id: "sandbox-1".into(),
                ..Default::default()
            },
            target: HttpRequestTarget {
                scheme: "https".into(),
                host: "example.test".into(),
                port: 443,
                method: "GET".into(),
                path: "/data".into(),
                query: String::new(),
            },
            policy_name: "test-policy",
            generation_guard: None,
            whole_body_timeout: DEFAULT_HTTP_RESPONSE_WHOLE_BODY_TIMEOUT,
            client_accepts_chunked: true,
            request_head: None,
        };
        let mut upstream = &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\nX-OpenShell-Request-ID: forged\r\n\r\n"[..];
        let mut client = Vec::new();

        let error = relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            Some(middleware),
        )
        .await
        .expect_err("platform correlation trailers must fail closed");

        assert!(
            error.to_string().contains("protected field name"),
            "{error}"
        );
        let delivered = String::from_utf8_lossy(&client);
        assert!(!delivered.contains("forged"), "{delivered}");
        assert!(
            delivered.contains("x-openshell-request-id: trusted\r\n"),
            "{delivered}"
        );
        assert_eq!(request_id_header_count(&client), 1);
    }

    #[test]
    fn response_middleware_rejects_declared_request_id_trailer() {
        let error = parse_response_head_for_middleware(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-OpenShell-Request-ID\r\n\r\n",
        )
        .expect_err("platform correlation trailer declarations must fail closed");

        assert!(
            error.to_string().contains("protected trailer field"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn informational_responses_are_not_decorated_but_upgrade_receives_a_receipt() {
        let correlation = test_correlation("receipt-1");
        let mut upstream =
            &b"HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[..];
        let mut client = Vec::new();

        relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("relay response");
        assert!(client.starts_with(b"HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\n"));
        assert_eq!(request_id_header_count(&client), 1);

        let mut upstream = &b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-OpenShell-Request-ID: forged\r\n\r\n"[..];
        let mut client = Vec::new();
        let outcome = relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("relay response");
        assert!(matches!(outcome, RelayOutcome::Upgraded { .. }));
        assert_eq!(request_id_header_count(&client), 1);
        assert!(!String::from_utf8_lossy(&client).contains("forged"));
        assert!(String::from_utf8_lossy(&client).contains("x-openshell-request-id: receipt-1\r\n"));
    }

    #[tokio::test]
    async fn switching_protocols_removes_receipt_connection_nomination() {
        let correlation = test_correlation("trusted-upgrade");
        let mut upstream = &b"HTTP/1.1 101 Switching Protocols\r\n\
            Connection: X-OpenShell-Request-ID\r\n\
            cOnNeCtIoN: keep-alive, x-OpEnShElL-rEqUeSt-Id, UpGrAdE\r\n\
            Upgrade: websocket\r\n\
            X-OpenShell-Request-ID: forged\r\n\r\n"[..];
        let mut client = Vec::new();

        let outcome = relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("relay response");

        assert!(matches!(outcome, RelayOutcome::Upgraded { .. }));
        let delivered = String::from_utf8(client).expect("HTTP response is UTF-8");
        let connection_headers: Vec<_> = delivered
            .lines()
            .filter(|line| {
                line.split_once(':')
                    .is_some_and(|(name, _)| name.eq_ignore_ascii_case("connection"))
            })
            .collect();
        assert_eq!(connection_headers, ["cOnNeCtIoN: keep-alive, UpGrAdE"]);
        assert!(!delivered.contains("forged"), "{delivered}");
        assert!(
            delivered.contains("x-openshell-request-id: trusted-upgrade\r\n"),
            "{delivered}"
        );
        assert_eq!(request_id_header_count(delivered.as_bytes()), 1);
    }

    #[tokio::test]
    async fn switching_protocols_rejects_folded_receipt_connection_nomination() {
        let correlation = test_correlation("trusted-upgrade");
        let mut upstream = &b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade,\r\n\tX-OpenShell-Request-ID\r\nUpgrade: websocket\r\n\r\n"[..];
        let mut client = Vec::new();

        let error = relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("folded upgrade fields must fail closed");

        assert!(
            error
                .to_string()
                .contains("response header continuation lines are not supported"),
            "{error}"
        );
        assert!(client.is_empty());
    }

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
