// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! REST (HTTP/1.1) L7 provider.
//!
//! Parses HTTP/1.1 request lines and headers, evaluates method+path against
//! policy, and relays allowed requests to upstream. Handles Content-Length
//! and chunked transfer encoding for body framing.

use crate::l7::provider::{BodyLength, L7Provider, L7Request, RelayOutcome};
use crate::secrets::rewrite_http_header_block;
use miette::{IntoDiagnostic, Result, miette};
use std::collections::HashMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, warn};

const MAX_HEADER_BYTES: usize = 16384; // 16 KiB for HTTP headers
const RELAY_BUF_SIZE: usize = 8192;
/// Idle timeout for `relay_until_eof`.  If no data arrives within this window
/// the body is considered complete.  Prevents blocking on servers that keep
/// the TCP connection alive after the response body (common with CDN keep-alive).
const RELAY_EOF_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// HTTP/1.1 REST protocol provider.
pub struct RestProvider;

impl L7Provider for RestProvider {
    async fn parse_request<C: AsyncRead + AsyncWrite + Unpin + Send>(
        &self,
        client: &mut C,
    ) -> Result<Option<L7Request>> {
        parse_http_request(client).await
    }

    async fn relay<C, U>(
        &self,
        req: &L7Request,
        client: &mut C,
        upstream: &mut U,
    ) -> Result<RelayOutcome>
    where
        C: AsyncRead + AsyncWrite + Unpin + Send,
        U: AsyncRead + AsyncWrite + Unpin + Send,
    {
        relay_http_request(req, client, upstream).await
    }

    async fn deny<C: AsyncRead + AsyncWrite + Unpin + Send>(
        &self,
        req: &L7Request,
        policy_name: &str,
        reason: &str,
        client: &mut C,
    ) -> Result<()> {
        send_deny_response(req, policy_name, reason, client, None).await
    }
}

impl RestProvider {
    /// Deny with a redacted target for the response body.
    pub(crate) async fn deny_with_redacted_target<C: AsyncRead + AsyncWrite + Unpin + Send>(
        &self,
        req: &L7Request,
        policy_name: &str,
        reason: &str,
        client: &mut C,
        redacted_target: Option<&str>,
    ) -> Result<()> {
        send_deny_response(req, policy_name, reason, client, redacted_target).await
    }
}

/// Parse one HTTP/1.1 request from the stream.
///
/// Reads one byte at a time to stop exactly at the `\r\n\r\n` header
/// terminator.  A multi-byte read could consume bytes belonging to a
/// subsequent pipelined request, and those overflow bytes would be
/// forwarded upstream without L7 policy evaluation -- a request
/// smuggling vulnerability.  Byte-at-a-time overhead is negligible for
/// the typical 200-800 byte headers on L7-inspected REST endpoints.
async fn parse_http_request<C: AsyncRead + Unpin>(client: &mut C) -> Result<Option<L7Request>> {
    let mut buf = Vec::with_capacity(4096);

    loop {
        if buf.len() > MAX_HEADER_BYTES {
            return Err(miette!(
                "HTTP request headers exceed {MAX_HEADER_BYTES} bytes"
            ));
        }

        let byte = match client.read_u8().await {
            Ok(b) => b,
            Err(e) if buf.is_empty() && is_benign_close(&e) => return Ok(None),
            Err(e) if buf.is_empty() && e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(None); // Clean close before any data
            }
            Err(e) => return Err(miette::miette!("{e}")),
        };
        buf.push(byte);

        // Check for end of headers -- `ends_with` is sufficient because
        // we append exactly one byte per iteration.
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    // Parse request line
    let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;

    // Reject bare LF in headers (must use \r\n line endings per RFC 7230).
    // Bare LF can cause parsing discrepancies between this proxy and upstream
    // servers, enabling request smuggling via header injection.
    for i in 0..header_end {
        if buf[i] == b'\n' && (i == 0 || buf[i - 1] != b'\r') {
            return Err(miette!(
                "HTTP headers contain bare LF (line feed without carriage return)"
            ));
        }
    }

    // Strict UTF-8 validation. from_utf8_lossy would silently replace invalid
    // bytes with U+FFFD, creating an interpretation gap between this proxy
    // (which parses the lossy string) and upstream servers (which receive the
    // raw bytes). This gap enables request smuggling via mutated header names.
    let header_str = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| miette!("HTTP headers contain invalid UTF-8"))?;

    let request_line = header_str
        .lines()
        .next()
        .ok_or_else(|| miette!("Empty HTTP request"))?;

    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| miette!("Missing HTTP method"))?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| miette!("Missing HTTP path"))?
        .to_string();
    let version = parts
        .next()
        .ok_or_else(|| miette!("Missing HTTP version"))?;
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(miette!("Unsupported HTTP version: {version}"));
    }

    // Determine body framing from headers
    let body_length = parse_body_length(header_str)?;
    let (path, query_params) = parse_target_query(&target)?;

    Ok(Some(L7Request {
        action: method,
        target: path,
        query_params,
        raw_header: buf, // exact header bytes up to and including \r\n\r\n
        body_length,
    }))
}

pub(crate) fn parse_target_query(target: &str) -> Result<(String, HashMap<String, Vec<String>>)> {
    match target.split_once('?') {
        Some((path, query)) => Ok((path.to_string(), parse_query_params(query)?)),
        None => Ok((target.to_string(), HashMap::new())),
    }
}

fn parse_query_params(query: &str) -> Result<HashMap<String, Vec<String>>> {
    let mut params: HashMap<String, Vec<String>> = HashMap::new();
    if query.is_empty() {
        return Ok(params);
    }

    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }

        let (raw_key, raw_value) = match pair.split_once('=') {
            Some((key, value)) => (key, value),
            None => (pair, ""),
        };
        let key = decode_query_component(raw_key)?;
        let value = decode_query_component(raw_value)?;
        params.entry(key).or_default().push(value);
    }

    Ok(params)
}

/// Decode a single query string component (key or value).
///
/// Handles both RFC 3986 percent-encoding (`%20` → space) and the
/// `application/x-www-form-urlencoded` convention (`+` → space).
/// Decoding `+` as space matches the behavior of Python's `urllib.parse`,
/// JavaScript's `URLSearchParams`, Go's `url.ParseQuery`, and most HTTP
/// frameworks. Callers that need a literal `+` should send `%2B`.
fn decode_query_component(input: &str) -> Result<String> {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'+' {
            decoded.push(b' ');
            i += 1;
            continue;
        }

        if bytes[i] != b'%' {
            decoded.push(bytes[i]);
            i += 1;
            continue;
        }

        if i + 2 >= bytes.len() {
            return Err(miette!("Invalid percent-encoding in query component"));
        }

        let hi = decode_hex_nibble(bytes[i + 1])
            .ok_or_else(|| miette!("Invalid percent-encoding in query component"))?;
        let lo = decode_hex_nibble(bytes[i + 2])
            .ok_or_else(|| miette!("Invalid percent-encoding in query component"))?;
        decoded.push((hi << 4) | lo);
        i += 3;
    }

    String::from_utf8(decoded).map_err(|_| miette!("Query component is not valid UTF-8"))
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Forward an allowed HTTP request to upstream and relay the response back.
///
/// Returns the relay outcome indicating whether the connection is reusable,
/// consumed, or has been upgraded (e.g. WebSocket via 101 Switching Protocols).
async fn relay_http_request<C, U>(
    req: &L7Request,
    client: &mut C,
    upstream: &mut U,
) -> Result<RelayOutcome>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    relay_http_request_with_resolver(req, client, upstream, None).await
}

pub(crate) async fn relay_http_request_with_resolver<C, U>(
    req: &L7Request,
    client: &mut C,
    upstream: &mut U,
    resolver: Option<&crate::secrets::SecretResolver>,
) -> Result<RelayOutcome>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let header_end = req
        .raw_header
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(req.raw_header.len(), |p| p + 4);

    let rewrite_result = rewrite_http_header_block(&req.raw_header[..header_end], resolver)
        .map_err(|e| miette!("credential injection failed: {e}"))?;

    upstream
        .write_all(&rewrite_result.rewritten)
        .await
        .into_diagnostic()?;

    let overflow = &req.raw_header[header_end..];
    if !overflow.is_empty() {
        upstream.write_all(overflow).await.into_diagnostic()?;
    }
    let overflow_len = overflow.len() as u64;

    match req.body_length {
        BodyLength::ContentLength(len) => {
            let remaining = len.saturating_sub(overflow_len);
            if remaining > 0 {
                relay_fixed(client, upstream, remaining).await?;
            }
        }
        BodyLength::Chunked => {
            relay_chunked(client, upstream, &req.raw_header[header_end..]).await?;
        }
        BodyLength::None => {}
    }
    upstream.flush().await.into_diagnostic()?;

    let outcome = relay_response(&req.action, upstream, client).await?;

    // Validate that the client actually requested an upgrade before accepting
    // a 101 from upstream. Per RFC 9110 Section 7.8, the server MUST NOT send
    // 101 unless the client sent Upgrade + Connection: Upgrade headers. A
    // non-compliant or malicious upstream could send an unsolicited 101 to
    // bypass L7 inspection.
    if matches!(outcome, RelayOutcome::Upgraded { .. }) {
        let header_str = String::from_utf8_lossy(&req.raw_header[..header_end]);
        if !client_requested_upgrade(&header_str) {
            warn!(
                method = %req.action,
                target = %req.target,
                "upstream sent unsolicited 101 without client Upgrade request — closing connection"
            );
            return Ok(RelayOutcome::Consumed);
        }
    }

    Ok(outcome)
}

/// Send a 403 Forbidden JSON deny response.
///
/// When `redacted_target` is provided, it is used instead of `req.target`
/// in the response body to avoid leaking resolved credential values.
async fn send_deny_response<C: AsyncWrite + Unpin>(
    req: &L7Request,
    policy_name: &str,
    reason: &str,
    client: &mut C,
    redacted_target: Option<&str>,
) -> Result<()> {
    let target = redacted_target.unwrap_or(&req.target);
    let body = serde_json::json!({
        "error": "policy_denied",
        "policy": policy_name,
        "rule": format!("{} {}", req.action, target),
        "detail": reason
    });
    let body_bytes = body.to_string();
    let response = format!(
        "HTTP/1.1 403 Forbidden\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         X-OpenShell-Policy: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        body_bytes.len(),
        policy_name,
        body_bytes,
    );
    client
        .write_all(response.as_bytes())
        .await
        .into_diagnostic()?;
    client.flush().await.into_diagnostic()?;
    Ok(())
}

/// Parse Content-Length or Transfer-Encoding from HTTP headers.
///
/// Per RFC 7230 Section 3.3.3, rejects requests containing both
/// `Content-Length` and `Transfer-Encoding` headers to prevent request
/// smuggling via CL/TE ambiguity.
fn parse_body_length(headers: &str) -> Result<BodyLength> {
    let mut has_te_chunked = false;
    let mut cl_value: Option<u64> = None;

    for line in headers.lines().skip(1) {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("transfer-encoding:") {
            let val = lower.split_once(':').map_or("", |(_, v)| v.trim());
            if val.split(',').any(|enc| enc.trim() == "chunked") {
                has_te_chunked = true;
            }
        }
        if lower.starts_with("content-length:") {
            let val = lower.split_once(':').map_or("", |(_, v)| v.trim());
            let len: u64 = val
                .parse()
                .map_err(|_| miette!("Request contains invalid Content-Length value"))?;
            if let Some(prev) = cl_value {
                if prev != len {
                    return Err(miette!(
                        "Request contains multiple Content-Length headers with differing values ({prev} vs {len})"
                    ));
                }
            }
            cl_value = Some(len);
        }
    }

    if has_te_chunked && cl_value.is_some() {
        return Err(miette!(
            "Request contains both Transfer-Encoding and Content-Length headers"
        ));
    }

    if has_te_chunked {
        return Ok(BodyLength::Chunked);
    }
    if let Some(len) = cl_value {
        return Ok(BodyLength::ContentLength(len));
    }
    Ok(BodyLength::None)
}

/// Relay exactly `len` bytes from reader to writer.
async fn relay_fixed<R, W>(reader: &mut R, writer: &mut W, len: u64) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut remaining = len;
    let mut buf = [0u8; RELAY_BUF_SIZE];
    while remaining > 0 {
        let to_read = usize::try_from(remaining)
            .unwrap_or(buf.len())
            .min(buf.len());
        let n = reader.read(&mut buf[..to_read]).await.into_diagnostic()?;
        if n == 0 {
            return Err(miette!(
                "Connection closed with {remaining} bytes remaining"
            ));
        }
        writer.write_all(&buf[..n]).await.into_diagnostic()?;
        remaining -= n as u64;
    }
    Ok(())
}

/// Relay chunked transfer encoding from reader to writer.
///
/// Copies bytes verbatim (preserving chunk framing) while parsing the stream
/// boundaries so we can stop exactly at the end of the current message body.
/// Handles chunk extensions and trailers per RFC 7230.
///
/// `already_forwarded` are overflow bytes that were already written to the
/// writer during header parsing. They are seeded into the parser buffer so
/// termination can still be detected when boundaries span reads.
async fn relay_chunked<R, W>(reader: &mut R, writer: &mut W, already_forwarded: &[u8]) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let started_at = std::time::Instant::now();
    let mut read_buf = [0u8; RELAY_BUF_SIZE];
    let mut parse_buf = Vec::from(already_forwarded);
    let mut pos = 0usize;
    let mut chunk_count = 0usize;
    let mut chunk_payload_bytes = 0usize;

    // Parse chunk-size lines + chunk payloads until final 0-size chunk, then
    // parse trailers until the terminating empty trailer line.
    loop {
        // Parse one chunk size line: "<hex>[;extensions]\r\n"
        let size_line_end = loop {
            if let Some(end) = find_crlf(&parse_buf, pos) {
                break end;
            }
            let n = reader.read(&mut read_buf).await.into_diagnostic()?;
            if n == 0 {
                return Err(miette!("Chunked body ended before chunk-size line"));
            }
            writer.write_all(&read_buf[..n]).await.into_diagnostic()?;
            parse_buf.extend_from_slice(&read_buf[..n]);
        };

        let size_line = std::str::from_utf8(&parse_buf[pos..size_line_end])
            .into_diagnostic()
            .map_err(|_| miette!("Invalid UTF-8 in chunk-size line"))?;
        let size_token = size_line
            .split(';')
            .next()
            .map(str::trim)
            .unwrap_or_default();
        let chunk_size = usize::from_str_radix(size_token, 16)
            .into_diagnostic()
            .map_err(|_| miette!("Invalid chunk size token: {size_token:?}"))?;
        pos = size_line_end + 2;

        if chunk_size == 0 {
            // Parse trailers (if any). Terminates on empty trailer line.
            let mut trailer_count = 0usize;
            loop {
                let trailer_end = loop {
                    if let Some(end) = find_crlf(&parse_buf, pos) {
                        break end;
                    }
                    let n = reader.read(&mut read_buf).await.into_diagnostic()?;
                    if n == 0 {
                        return Err(miette!("Chunked body ended before trailer terminator"));
                    }
                    writer.write_all(&read_buf[..n]).await.into_diagnostic()?;
                    parse_buf.extend_from_slice(&read_buf[..n]);
                };

                let trailer_line = &parse_buf[pos..trailer_end];
                pos = trailer_end + 2;
                if trailer_line.is_empty() {
                    debug!(
                        chunk_count,
                        chunk_payload_bytes,
                        trailer_count,
                        elapsed_ms = started_at.elapsed().as_millis(),
                        "relay_chunked complete"
                    );
                    return Ok(());
                }
                trailer_count += 1;
            }
        }

        // Ensure the full chunk payload + trailing CRLF is available.
        let chunk_end = pos
            .checked_add(chunk_size)
            .ok_or_else(|| miette!("Chunk size overflow"))?;
        let chunk_with_crlf_end = chunk_end
            .checked_add(2)
            .ok_or_else(|| miette!("Chunk size overflow"))?;

        while parse_buf.len() < chunk_with_crlf_end {
            let n = reader.read(&mut read_buf).await.into_diagnostic()?;
            if n == 0 {
                return Err(miette!("Chunked body ended mid-chunk"));
            }
            writer.write_all(&read_buf[..n]).await.into_diagnostic()?;
            parse_buf.extend_from_slice(&read_buf[..n]);
        }
        if &parse_buf[chunk_end..chunk_with_crlf_end] != b"\r\n" {
            return Err(miette!("Chunk missing terminating CRLF"));
        }
        pos = chunk_with_crlf_end;
        chunk_count += 1;
        chunk_payload_bytes = chunk_payload_bytes.saturating_add(chunk_size);

        // Keep parser memory bounded for long streams.
        if pos > RELAY_BUF_SIZE * 4 {
            parse_buf.drain(..pos);
            pos = 0;
        }
    }
}

fn find_crlf(buf: &[u8], start: usize) -> Option<usize> {
    buf.get(start..)?
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|offset| start + offset)
}

/// Read and relay a full HTTP response (headers + body) from upstream to client.
///
/// Returns a [`RelayOutcome`] indicating whether the connection is reusable,
/// consumed, or has been upgraded (101 Switching Protocols).
///
/// Note: callers that receive `Upgraded` are responsible for switching to
/// raw bidirectional relay and forwarding the overflow bytes.
pub(crate) async fn relay_response_to_client<U, C>(
    upstream: &mut U,
    client: &mut C,
    request_method: &str,
) -> Result<RelayOutcome>
where
    U: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    relay_response(request_method, upstream, client).await
}

async fn relay_response<U, C>(
    request_method: &str,
    upstream: &mut U,
    client: &mut C,
) -> Result<RelayOutcome>
where
    U: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    let started_at = std::time::Instant::now();
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];

    // Read response headers
    loop {
        if buf.len() > MAX_HEADER_BYTES {
            return Err(miette!("HTTP response headers exceed limit"));
        }

        let n = upstream.read(&mut tmp).await.into_diagnostic()?;
        if n == 0 {
            // Upstream closed — forward whatever we have
            if !buf.is_empty() {
                client.write_all(&buf).await.into_diagnostic()?;
            }
            return Ok(RelayOutcome::Consumed);
        }
        buf.extend_from_slice(&tmp[..n]);

        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;

    // Parse response framing
    let header_str = String::from_utf8_lossy(&buf[..header_end]);
    let status_code = parse_status_code(&header_str).unwrap_or(200);
    let server_wants_close = parse_connection_close(&header_str);
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
        return Ok(RelayOutcome::Upgraded { overflow });
    }

    // Bodiless responses (HEAD, 1xx, 204, 304): forward headers only, skip body
    if is_bodiless_response(request_method, status_code) {
        client
            .write_all(&buf[..header_end])
            .await
            .into_diagnostic()?;
        client.flush().await.into_diagnostic()?;
        return if server_wants_close {
            Ok(RelayOutcome::Consumed)
        } else {
            Ok(RelayOutcome::Reusable)
        };
    }

    // No explicit framing (no Content-Length, no Transfer-Encoding).
    // Per RFC 7230 §3.3.3 the body is delimited by connection close.
    if matches!(body_length, BodyLength::None) {
        if server_wants_close {
            // Server indicated it will close — read until EOF.
            let before_end = &buf[..header_end - 2];
            client.write_all(before_end).await.into_diagnostic()?;
            client
                .write_all(b"Connection: close\r\n\r\n")
                .await
                .into_diagnostic()?;
            let overflow = &buf[header_end..];
            if !overflow.is_empty() {
                client.write_all(overflow).await.into_diagnostic()?;
            }
            relay_until_eof(upstream, client).await?;
            client.flush().await.into_diagnostic()?;
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
        client.flush().await.into_diagnostic()?;
        return Ok(RelayOutcome::Reusable);
    }

    // Forward response headers + any overflow body bytes
    client.write_all(&buf).await.into_diagnostic()?;
    let overflow_len = (buf.len() - header_end) as u64;

    // Forward remaining response body
    match body_length {
        BodyLength::ContentLength(len) => {
            let remaining = len.saturating_sub(overflow_len);
            if remaining > 0 {
                relay_fixed(upstream, client, remaining).await?;
            }
        }
        BodyLength::Chunked => {
            relay_chunked(upstream, client, &buf[header_end..]).await?;
        }
        BodyLength::None => unreachable!(),
    }
    client.flush().await.into_diagnostic()?;
    debug!(
        request_method,
        elapsed_ms = started_at.elapsed().as_millis(),
        "relay_response complete (explicit framing)"
    );

    // When body framing is explicit (Content-Length / Chunked), always report
    // the connection as reusable so the relay loop continues.  If the server
    // sent `Connection: close`, the *next* upstream write will fail and the
    // loop will exit via the normal error path.  Exiting early here would
    // tear down the CONNECT tunnel before the client can detect the close,
    // causing ~30 s retry delays in clients like `gh`.
    Ok(RelayOutcome::Reusable)
}

/// Parse the HTTP status code from a response status line.
///
/// Expects the first line to look like `HTTP/1.1 200 OK`.
fn parse_status_code(headers: &str) -> Option<u16> {
    let status_line = headers.lines().next()?;
    let code_str = status_line.split_whitespace().nth(1)?;
    code_str.parse().ok()
}

/// Check if the response headers contain `Connection: close`.
fn parse_connection_close(headers: &str) -> bool {
    for line in headers.lines().skip(1) {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("connection:") {
            let val = lower.split_once(':').map_or("", |(_, v)| v.trim());
            return val.contains("close");
        }
    }
    false
}

/// Check if the client request headers contain both `Upgrade` and
/// `Connection: Upgrade` headers, indicating the client requested a
/// protocol upgrade (e.g. WebSocket).
///
/// Per RFC 9110 Section 7.8, a server MUST NOT send 101 Switching Protocols
/// unless the client sent these headers.
fn client_requested_upgrade(headers: &str) -> bool {
    let mut has_upgrade_header = false;
    let mut connection_contains_upgrade = false;

    for line in headers.lines().skip(1) {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("upgrade:") {
            has_upgrade_header = true;
        }
        if lower.starts_with("connection:") {
            let val = lower.split_once(':').map_or("", |(_, v)| v.trim());
            // Connection header can have comma-separated values
            if val.split(',').any(|tok| tok.trim() == "upgrade") {
                connection_contains_upgrade = true;
            }
        }
    }

    has_upgrade_header && connection_contains_upgrade
}

/// Returns true for responses that MUST NOT contain a message body per RFC 7230 §3.3.3:
/// HEAD responses, 1xx informational, 204 No Content, 304 Not Modified.
fn is_bodiless_response(request_method: &str, status_code: u16) -> bool {
    request_method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status_code)
        || status_code == 204
        || status_code == 304
}

/// Relay all bytes from reader to writer until EOF or idle timeout.
///
/// Used for HTTP responses with no explicit framing (no Content-Length,
/// no Transfer-Encoding) where the body is delimited by connection close.
/// An idle timeout prevents blocking when servers keep the TCP connection
/// alive longer than expected (e.g. CDN keep-alive timers).
async fn relay_until_eof<R, W>(reader: &mut R, writer: &mut W) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; RELAY_BUF_SIZE];
    loop {
        match tokio::time::timeout(RELAY_EOF_IDLE_TIMEOUT, reader.read(&mut buf)).await {
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(n)) => writer.write_all(&buf[..n]).await.into_diagnostic()?,
            Ok(Err(e)) => return Err(miette::miette!("{e}")),
            Err(_) => {
                debug!(
                    "relay_until_eof idle timeout after {:?}",
                    RELAY_EOF_IDLE_TIMEOUT
                );
                return Ok(());
            }
        }
    }
}

/// Detect if the first bytes look like an HTTP request.
///
/// Checks for common HTTP methods at the start of the stream.
pub fn looks_like_http(peek: &[u8]) -> bool {
    const METHODS: &[&[u8]] = &[
        b"GET ",
        b"HEAD ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"PATCH ",
        b"OPTIONS ",
        b"CONNECT ",
        b"TRACE ",
    ];
    METHODS.iter().any(|m| peek.starts_with(m))
}

/// Check if an IO error represents a benign connection close.
///
/// TLS peers commonly close the socket without sending a `close_notify` alert.
/// Rustls reports this as `UnexpectedEof`, but it's functionally equivalent
/// to a clean close when no request data has been received yet.
fn is_benign_close(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::SecretResolver;
    use base64::Engine as _;

    #[test]
    fn parse_content_length() {
        let headers = "POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 42\r\n\r\n";
        match parse_body_length(headers).unwrap() {
            BodyLength::ContentLength(42) => {}
            other => panic!("Expected ContentLength(42), got {other:?}"),
        }
    }

    #[test]
    fn parse_chunked() {
        let headers =
            "POST /api HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n";
        match parse_body_length(headers).unwrap() {
            BodyLength::Chunked => {}
            other => panic!("Expected Chunked, got {other:?}"),
        }
    }

    #[test]
    fn parse_no_body() {
        let headers = "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n";
        match parse_body_length(headers).unwrap() {
            BodyLength::None => {}
            other => panic!("Expected None, got {other:?}"),
        }
    }

    #[test]
    fn parse_target_query_parses_duplicate_values() {
        let (path, query) = parse_target_query("/download?tag=a&tag=b").expect("parse");
        assert_eq!(path, "/download");
        assert_eq!(
            query.get("tag").cloned(),
            Some(vec!["a".into(), "b".into()])
        );
    }

    #[test]
    fn parse_target_query_decodes_percent_and_plus() {
        let (path, query) = parse_target_query("/download?slug=my%2Fskill&name=Foo+Bar").unwrap();
        assert_eq!(path, "/download");
        assert_eq!(
            query.get("slug").cloned(),
            Some(vec!["my/skill".to_string()])
        );
        // `+` is decoded as space per application/x-www-form-urlencoded.
        // Literal `+` should be sent as `%2B`.
        assert_eq!(
            query.get("name").cloned(),
            Some(vec!["Foo Bar".to_string()])
        );
    }

    #[test]
    fn parse_target_query_literal_plus_via_percent_encoding() {
        let (_path, query) = parse_target_query("/search?q=a%2Bb").unwrap();
        assert_eq!(
            query.get("q").cloned(),
            Some(vec!["a+b".to_string()]),
            "%2B should decode to literal +"
        );
    }

    #[test]
    fn parse_target_query_empty_value() {
        let (_path, query) = parse_target_query("/api?tag=").unwrap();
        assert_eq!(
            query.get("tag").cloned(),
            Some(vec!["".to_string()]),
            "key with empty value should produce empty string"
        );
    }

    #[test]
    fn parse_target_query_key_without_value() {
        let (_path, query) = parse_target_query("/api?verbose").unwrap();
        assert_eq!(
            query.get("verbose").cloned(),
            Some(vec!["".to_string()]),
            "key without = should produce empty string value"
        );
    }

    #[test]
    fn parse_target_query_unicode_after_decoding() {
        // "café" = c a f %C3%A9
        let (_path, query) = parse_target_query("/search?q=caf%C3%A9").unwrap();
        assert_eq!(
            query.get("q").cloned(),
            Some(vec!["café".to_string()]),
            "percent-encoded UTF-8 should decode correctly"
        );
    }

    #[test]
    fn parse_target_query_empty_query_string() {
        let (path, query) = parse_target_query("/api?").unwrap();
        assert_eq!(path, "/api");
        assert!(
            query.is_empty(),
            "empty query after ? should produce empty map"
        );
    }

    #[test]
    fn parse_target_query_rejects_malformed_percent_encoding() {
        let err = parse_target_query("/download?slug=bad%2").expect_err("expected parse error");
        assert!(
            err.to_string().contains("percent-encoding"),
            "unexpected error: {err}"
        );
    }

    /// SEC-009: Reject requests with both Content-Length and Transfer-Encoding
    /// to prevent CL/TE request smuggling (RFC 7230 Section 3.3.3).
    #[test]
    fn reject_dual_content_length_and_transfer_encoding() {
        let headers = "POST /api HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(
            parse_body_length(headers).is_err(),
            "Must reject request with both CL and TE"
        );
    }

    /// SEC-009: Same rejection regardless of header order.
    #[test]
    fn reject_dual_transfer_encoding_and_content_length() {
        let headers = "POST /api HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n";
        assert!(
            parse_body_length(headers).is_err(),
            "Must reject request with both TE and CL"
        );
    }

    /// SEC: Reject differing duplicate Content-Length headers.
    #[test]
    fn reject_differing_duplicate_content_length() {
        let headers =
            "POST /api HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nContent-Length: 50\r\n\r\n";
        assert!(
            parse_body_length(headers).is_err(),
            "Must reject differing duplicate Content-Length"
        );
    }

    /// SEC: Accept identical duplicate Content-Length headers.
    #[test]
    fn accept_identical_duplicate_content_length() {
        let headers =
            "POST /api HTTP/1.1\r\nHost: x\r\nContent-Length: 42\r\nContent-Length: 42\r\n\r\n";
        match parse_body_length(headers).unwrap() {
            BodyLength::ContentLength(42) => {}
            other => panic!("Expected ContentLength(42), got {other:?}"),
        }
    }

    /// SEC: Reject non-numeric Content-Length values.
    #[test]
    fn reject_non_numeric_content_length() {
        let headers = "POST /api HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\n";
        assert!(
            parse_body_length(headers).is_err(),
            "Must reject non-numeric Content-Length"
        );
    }

    /// SEC: Reject when second Content-Length is non-numeric (bypass test).
    #[test]
    fn reject_valid_then_invalid_content_length() {
        let headers =
            "POST /api HTTP/1.1\r\nHost: x\r\nContent-Length: 42\r\nContent-Length: abc\r\n\r\n";
        assert!(
            parse_body_length(headers).is_err(),
            "Must reject when any Content-Length is non-numeric"
        );
    }

    /// SEC: Transfer-Encoding substring match must not match partial tokens.
    #[test]
    fn te_substring_not_chunked() {
        let headers = "POST /api HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunkedx\r\n\r\n";
        match parse_body_length(headers).unwrap() {
            BodyLength::None => {}
            other => panic!("Expected None for non-matching TE, got {other:?}"),
        }
    }

    /// SEC-009: Bare LF in headers enables header injection.
    #[tokio::test]
    async fn reject_bare_lf_in_headers() {
        let (mut client, mut writer) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            // Bare \n between two header values creates a parsing discrepancy
            writer
                .write_all(
                    b"GET /api HTTP/1.1\r\nX-Injected: value\nEvil: header\r\nHost: x\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let result = parse_http_request(&mut client).await;
        assert!(result.is_err(), "Must reject headers with bare LF");
    }

    /// SEC-009: Invalid UTF-8 in headers creates interpretation gap.
    #[tokio::test]
    async fn reject_invalid_utf8_in_headers() {
        let (mut client, mut writer) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut raw = Vec::new();
            raw.extend_from_slice(b"GET /api HTTP/1.1\r\nHost: x\r\nX-Bad: \xc0\xaf\r\n\r\n");
            writer.write_all(&raw).await.unwrap();
        });
        let result = parse_http_request(&mut client).await;
        assert!(result.is_err(), "Must reject headers with invalid UTF-8");
    }

    /// SEC-009: Reject unsupported HTTP versions.
    #[tokio::test]
    async fn reject_invalid_http_version() {
        let (mut client, mut writer) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            writer
                .write_all(b"GET /api JUNK/9.9\r\nHost: x\r\n\r\n")
                .await
                .unwrap();
        });
        let result = parse_http_request(&mut client).await;
        assert!(result.is_err(), "Must reject unsupported HTTP version");
    }

    #[tokio::test]
    async fn parse_http_request_splits_path_and_query_params() {
        let (mut client, mut writer) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            writer
                .write_all(
                    b"GET /download?slug=my%2Fskill&tag=foo&tag=bar HTTP/1.1\r\nHost: x\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let req = parse_http_request(&mut client)
            .await
            .expect("request should parse")
            .expect("request should exist");
        assert_eq!(req.target, "/download");
        assert_eq!(
            req.query_params.get("slug").cloned(),
            Some(vec!["my/skill".to_string()])
        );
        assert_eq!(
            req.query_params.get("tag").cloned(),
            Some(vec!["foo".to_string(), "bar".to_string()])
        );
    }

    /// Regression test: two pipelined requests in a single write must be
    /// parsed independently.  Before the fix, the 1024-byte `read()` buffer
    /// could capture bytes from the second request, which were forwarded
    /// upstream as body overflow of the first -- bypassing L7 policy checks.
    #[tokio::test]
    async fn parse_http_request_does_not_overread_next_request() {
        let (mut client, mut writer) = tokio::io::duplex(4096);

        tokio::spawn(async move {
            writer
                .write_all(
                    b"GET /allowed HTTP/1.1\r\nHost: example.com\r\n\r\n\
                      POST /blocked HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
                )
                .await
                .unwrap();
        });

        let first = parse_http_request(&mut client)
            .await
            .expect("first request should parse")
            .expect("expected first request");
        assert_eq!(first.action, "GET");
        assert_eq!(first.target, "/allowed");
        assert!(first.query_params.is_empty());
        assert_eq!(
            first.raw_header, b"GET /allowed HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "raw_header must contain only the first request's headers"
        );

        let second = parse_http_request(&mut client)
            .await
            .expect("second request should parse")
            .expect("expected second request");
        assert_eq!(second.action, "POST");
        assert_eq!(second.target, "/blocked");
        assert!(second.query_params.is_empty());
    }

    #[test]
    fn http_method_detection() {
        assert!(looks_like_http(b"GET / HTTP/1.1\r\n"));
        assert!(looks_like_http(b"POST /api HTTP/1.1\r\n"));
        assert!(looks_like_http(b"DELETE /foo HTTP/1.1\r\n"));
        assert!(!looks_like_http(b"\x00\x00\x00\x08")); // Postgres
        assert!(!looks_like_http(b"HELLO")); // Unknown
    }

    #[test]
    fn test_parse_status_code() {
        assert_eq!(
            parse_status_code("HTTP/1.1 200 OK\r\nHost: x\r\n\r\n"),
            Some(200)
        );
        assert_eq!(
            parse_status_code("HTTP/1.1 204 No Content\r\n\r\n"),
            Some(204)
        );
        assert_eq!(
            parse_status_code("HTTP/1.1 304 Not Modified\r\n\r\n"),
            Some(304)
        );
        assert_eq!(
            parse_status_code("HTTP/1.1 100 Continue\r\n\r\n"),
            Some(100)
        );
        assert_eq!(parse_status_code(""), None);
    }

    #[test]
    fn test_parse_connection_close() {
        assert!(parse_connection_close(
            "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"
        ));
        assert!(!parse_connection_close(
            "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\n"
        ));
        assert!(!parse_connection_close(
            "HTTP/1.1 200 OK\r\nHost: x\r\n\r\n"
        ));
    }

    #[test]
    fn test_is_bodiless_response() {
        assert!(is_bodiless_response("HEAD", 200));
        assert!(is_bodiless_response("GET", 100));
        assert!(is_bodiless_response("GET", 199));
        assert!(is_bodiless_response("GET", 204));
        assert!(is_bodiless_response("GET", 304));
        assert!(!is_bodiless_response("GET", 200));
        assert!(!is_bodiless_response("POST", 201));
    }

    #[tokio::test]
    async fn relay_response_no_framing_with_connection_close_reads_until_eof() {
        // Response with Connection: close but no Content-Length/TE: body is
        // delimited by connection close — relay_until_eof should forward it.
        let response = b"HTTP/1.1 200 OK\r\nConnection: close\r\nServer: test\r\n\r\nhello world";

        let (mut upstream_read, mut upstream_write) = tokio::io::duplex(4096);
        let (mut client_read, mut client_write) = tokio::io::duplex(4096);

        tokio::spawn(async move {
            upstream_write.write_all(response).await.unwrap();
            upstream_write.shutdown().await.unwrap();
        });

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            relay_response("GET", &mut upstream_read, &mut client_write),
        )
        .await
        .expect("relay_response should not deadlock");

        let outcome = result.expect("relay_response should succeed");
        assert!(
            matches!(outcome, RelayOutcome::Consumed),
            "connection consumed by read-until-EOF"
        );

        client_write.shutdown().await.unwrap();
        let mut received = Vec::new();
        client_read.read_to_end(&mut received).await.unwrap();
        let received_str = String::from_utf8_lossy(&received);
        assert!(
            received_str.contains("Connection: close"),
            "should preserve Connection: close"
        );
        assert!(
            received_str.contains("hello world"),
            "body should be forwarded"
        );
    }

    #[tokio::test]
    async fn relay_response_no_framing_without_connection_close_treats_as_empty() {
        // Response without Content-Length, TE, or Connection: close.
        // HTTP/1.1 keep-alive implies empty body — must not block.
        let response = b"HTTP/1.1 200 OK\r\nServer: test\r\n\r\n";

        let (mut upstream_read, mut upstream_write) = tokio::io::duplex(4096);
        let (mut client_read, mut client_write) = tokio::io::duplex(4096);

        tokio::spawn(async move {
            upstream_write.write_all(response).await.unwrap();
            // Do NOT close — if relay blocks on read it will hang
        });

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            relay_response("GET", &mut upstream_read, &mut client_write),
        )
        .await
        .expect("must not block when no Connection: close");

        let outcome = result.expect("relay_response should succeed");
        assert!(
            matches!(outcome, RelayOutcome::Reusable),
            "keep-alive implied, connection reusable"
        );

        client_write.shutdown().await.unwrap();
        let mut received = Vec::new();
        client_read.read_to_end(&mut received).await.unwrap();
        let received_str = String::from_utf8_lossy(&received);
        assert!(
            received_str.contains("200 OK"),
            "headers should be forwarded"
        );
    }

    #[tokio::test]
    async fn relay_response_head_with_content_length_no_body() {
        // HEAD response with Content-Length must NOT try to read body bytes.
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n";

        let (mut upstream_read, mut upstream_write) = tokio::io::duplex(4096);
        let (mut client_read, mut client_write) = tokio::io::duplex(4096);

        tokio::spawn(async move {
            upstream_write.write_all(response).await.unwrap();
            // Do NOT close — if relay tries to read body it will block forever
        });

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            relay_response("HEAD", &mut upstream_read, &mut client_write),
        )
        .await
        .expect("HEAD relay must not deadlock waiting for body");

        let outcome = result.expect("relay_response should succeed");
        assert!(
            matches!(outcome, RelayOutcome::Reusable),
            "HEAD response should be reusable"
        );

        client_write.shutdown().await.unwrap();
        let mut received = Vec::new();
        client_read.read_to_end(&mut received).await.unwrap();
        let received_str = String::from_utf8_lossy(&received);
        assert!(received_str.contains("200 OK"));
        // Should NOT contain body bytes
        assert!(!received_str.contains('\0'));
    }

    #[tokio::test]
    async fn relay_response_204_no_body() {
        let response = b"HTTP/1.1 204 No Content\r\nServer: test\r\n\r\n";

        let (mut upstream_read, mut upstream_write) = tokio::io::duplex(4096);
        let (mut client_read, mut client_write) = tokio::io::duplex(4096);

        tokio::spawn(async move {
            upstream_write.write_all(response).await.unwrap();
        });

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            relay_response("GET", &mut upstream_read, &mut client_write),
        )
        .await
        .expect("204 relay must not deadlock");

        let outcome = result.expect("relay_response should succeed");
        assert!(
            matches!(outcome, RelayOutcome::Reusable),
            "204 response should be reusable"
        );

        client_write.shutdown().await.unwrap();
        let mut received = Vec::new();
        client_read.read_to_end(&mut received).await.unwrap();
        assert!(String::from_utf8_lossy(&received).contains("204 No Content"));
    }

    #[tokio::test]
    async fn relay_response_chunked_body_complete_in_overflow() {
        // Entire chunked body (including terminal 0\r\n\r\n) arrives with
        // headers in the same read.  relay_chunked must NOT be called or it
        // will block forever waiting for data that was already consumed.
        let response =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";

        let (mut upstream_read, mut upstream_write) = tokio::io::duplex(4096);
        let (mut client_read, mut client_write) = tokio::io::duplex(4096);

        tokio::spawn(async move {
            upstream_write.write_all(response).await.unwrap();
            // Do NOT close — if relay_chunked is called it will block forever
        });

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            relay_response("GET", &mut upstream_read, &mut client_write),
        )
        .await
        .expect("must not block when chunked body is complete in overflow");

        let outcome = result.expect("relay_response should succeed");
        assert!(
            matches!(outcome, RelayOutcome::Reusable),
            "connection should be reusable"
        );

        client_write.shutdown().await.unwrap();
        let mut received = Vec::new();
        client_read.read_to_end(&mut received).await.unwrap();
        let received_str = String::from_utf8_lossy(&received);
        assert!(
            received_str.contains("hello"),
            "chunked body should be forwarded"
        );
    }

    #[tokio::test]
    async fn relay_response_chunked_with_trailers_does_not_wait_for_eof() {
        // Last-chunk can be followed by trailers, so body terminator is not
        // always literal "0\r\n\r\n". We must stop at final empty trailer
        // line without waiting for upstream connection close.
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nx-checksum: abc123\r\n\r\n";

        let (mut upstream_read, mut upstream_write) = tokio::io::duplex(4096);
        let (mut client_read, mut client_write) = tokio::io::duplex(4096);

        tokio::spawn(async move {
            upstream_write.write_all(response).await.unwrap();
            // Keep stream open to ensure relay terminates by framing, not EOF.
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        });

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            relay_response("GET", &mut upstream_read, &mut client_write),
        )
        .await
        .expect("must not block when chunked response has trailers");

        let outcome = result.expect("relay_response should succeed");
        assert!(
            matches!(outcome, RelayOutcome::Reusable),
            "chunked response should be reusable"
        );

        client_write.shutdown().await.unwrap();
        let mut received = Vec::new();
        client_read.read_to_end(&mut received).await.unwrap();
        let received_str = String::from_utf8_lossy(&received);
        assert!(
            received_str.contains("hello"),
            "chunked body should be forwarded"
        );
        assert!(
            received_str.contains("x-checksum: abc123"),
            "trailers should be forwarded"
        );
    }

    #[tokio::test]
    async fn relay_response_normal_content_length() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

        let (mut upstream_read, mut upstream_write) = tokio::io::duplex(4096);
        let (mut client_read, mut client_write) = tokio::io::duplex(4096);

        tokio::spawn(async move {
            upstream_write.write_all(response).await.unwrap();
        });

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            relay_response("GET", &mut upstream_read, &mut client_write),
        )
        .await
        .expect("normal relay must not deadlock");

        let outcome = result.expect("relay_response should succeed");
        assert!(
            matches!(outcome, RelayOutcome::Reusable),
            "Content-Length response should be reusable"
        );

        client_write.shutdown().await.unwrap();
        let mut received = Vec::new();
        client_read.read_to_end(&mut received).await.unwrap();
        let received_str = String::from_utf8_lossy(&received);
        assert!(received_str.contains("hello"));
    }

    #[tokio::test]
    async fn relay_response_connection_close_with_content_length() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";

        let (mut upstream_read, mut upstream_write) = tokio::io::duplex(4096);
        let (mut client_read, mut client_write) = tokio::io::duplex(4096);

        tokio::spawn(async move {
            upstream_write.write_all(response).await.unwrap();
        });

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            relay_response("GET", &mut upstream_read, &mut client_write),
        )
        .await
        .expect("relay must not deadlock");

        let outcome = result.expect("relay_response should succeed");
        // With explicit framing, Connection: close is still reported as reusable
        // so the relay loop continues.  The *next* upstream write will fail and
        // exit the loop via the normal error path.
        assert!(
            matches!(outcome, RelayOutcome::Reusable),
            "explicit framing keeps loop alive despite Connection: close"
        );

        client_write.shutdown().await.unwrap();
        let mut received = Vec::new();
        client_read.read_to_end(&mut received).await.unwrap();
        assert!(String::from_utf8_lossy(&received).contains("hello"));
    }

    #[tokio::test]
    async fn relay_response_101_switching_protocols_returns_upgraded_with_overflow() {
        // Build a 101 response followed by WebSocket frame data (overflow).
        let mut response = Vec::new();
        response.extend_from_slice(b"HTTP/1.1 101 Switching Protocols\r\n");
        response.extend_from_slice(b"Upgrade: websocket\r\n");
        response.extend_from_slice(b"Connection: Upgrade\r\n");
        response.extend_from_slice(b"\r\n");
        response.extend_from_slice(b"\x81\x05hello"); // WebSocket frame

        let (upstream_read, mut upstream_write) = tokio::io::duplex(4096);
        let (mut client_read, client_write) = tokio::io::duplex(4096);

        upstream_write.write_all(&response).await.unwrap();
        drop(upstream_write);

        let mut upstream_read = upstream_read;
        let mut client_write = client_write;

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            relay_response("GET", &mut upstream_read, &mut client_write),
        )
        .await
        .expect("relay_response should not deadlock");

        let outcome = result.expect("relay_response should succeed");
        match outcome {
            RelayOutcome::Upgraded { overflow } => {
                assert_eq!(
                    &overflow, b"\x81\x05hello",
                    "overflow should contain WebSocket frame data"
                );
            }
            other => panic!("Expected Upgraded, got {other:?}"),
        }

        client_write.shutdown().await.unwrap();
        let mut received = Vec::new();
        client_read.read_to_end(&mut received).await.unwrap();
        let received_str = String::from_utf8_lossy(&received);
        assert!(
            received_str.contains("101 Switching Protocols"),
            "client should receive the 101 response headers"
        );
    }

    #[tokio::test]
    async fn relay_response_101_no_overflow() {
        // 101 response with no trailing bytes — overflow should be empty.
        let response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";

        let (upstream_read, mut upstream_write) = tokio::io::duplex(4096);
        let (_client_read, client_write) = tokio::io::duplex(4096);

        upstream_write.write_all(response).await.unwrap();
        drop(upstream_write);

        let mut upstream_read = upstream_read;
        let mut client_write = client_write;

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            relay_response("GET", &mut upstream_read, &mut client_write),
        )
        .await
        .expect("relay_response should not deadlock");

        match result.expect("should succeed") {
            RelayOutcome::Upgraded { overflow } => {
                assert!(overflow.is_empty(), "no overflow expected");
            }
            other => panic!("Expected Upgraded, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn relay_rejects_unsolicited_101_without_client_upgrade_header() {
        // Client sends a normal GET without Upgrade headers.
        // Upstream responds with 101 (non-compliant). The relay should
        // reject the upgrade and return Consumed instead.
        let (mut proxy_to_upstream, mut upstream_side) = tokio::io::duplex(8192);
        let (mut _app_side, mut proxy_to_client) = tokio::io::duplex(8192);

        let req = L7Request {
            action: "GET".to_string(),
            target: "/api".to_string(),
            query_params: HashMap::new(),
            raw_header: b"GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
            body_length: BodyLength::None,
        };

        let upstream_task = tokio::spawn(async move {
            // Read the request
            let mut buf = vec![0u8; 4096];
            let mut total = 0;
            loop {
                let n = upstream_side.read(&mut buf[total..]).await.unwrap();
                if n == 0 {
                    break;
                }
                total += n;
                if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            // Send unsolicited 101
            upstream_side
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                )
                .await
                .unwrap();
            upstream_side.flush().await.unwrap();
        });

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            relay_http_request_with_resolver(
                &req,
                &mut proxy_to_client,
                &mut proxy_to_upstream,
                None,
            ),
        )
        .await
        .expect("relay must not deadlock");

        let outcome = result.expect("relay should succeed");
        assert!(
            matches!(outcome, RelayOutcome::Consumed),
            "unsolicited 101 should be rejected as Consumed, got {outcome:?}"
        );

        upstream_task.await.expect("upstream task should complete");
    }

    #[tokio::test]
    async fn relay_accepts_101_with_client_upgrade_header() {
        // Client sends a proper upgrade request with Upgrade + Connection headers.
        let (mut proxy_to_upstream, mut upstream_side) = tokio::io::duplex(8192);
        let (mut _app_side, mut proxy_to_client) = tokio::io::duplex(8192);

        let req = L7Request {
            action: "GET".to_string(),
            target: "/ws".to_string(),
            query_params: HashMap::new(),
            raw_header: b"GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n".to_vec(),
            body_length: BodyLength::None,
        };

        let upstream_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let mut total = 0;
            loop {
                let n = upstream_side.read(&mut buf[total..]).await.unwrap();
                if n == 0 {
                    break;
                }
                total += n;
                if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            upstream_side
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                )
                .await
                .unwrap();
            upstream_side.flush().await.unwrap();
        });

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            relay_http_request_with_resolver(
                &req,
                &mut proxy_to_client,
                &mut proxy_to_upstream,
                None,
            ),
        )
        .await
        .expect("relay must not deadlock");

        let outcome = result.expect("relay should succeed");
        assert!(
            matches!(outcome, RelayOutcome::Upgraded { .. }),
            "proper upgrade request should be accepted, got {outcome:?}"
        );

        upstream_task.await.expect("upstream task should complete");
    }

    #[test]
    fn client_requested_upgrade_detects_websocket_headers() {
        let headers = "GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        assert!(client_requested_upgrade(headers));
    }

    #[test]
    fn client_requested_upgrade_rejects_missing_upgrade_header() {
        let headers = "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(!client_requested_upgrade(headers));
    }

    #[test]
    fn client_requested_upgrade_rejects_upgrade_without_connection() {
        let headers = "GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\r\n";
        assert!(!client_requested_upgrade(headers));
    }

    #[test]
    fn client_requested_upgrade_handles_comma_separated_connection() {
        let headers = "GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n\r\n";
        assert!(client_requested_upgrade(headers));
    }

    #[test]
    fn rewrite_header_block_resolves_placeholder_auth_headers() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("ANTHROPIC_API_KEY".to_string(), "sk-test".to_string())]
                .into_iter()
                .collect(),
        );
        let raw = b"GET /v1/messages HTTP/1.1\r\nAuthorization: Bearer openshell:resolve:env:ANTHROPIC_API_KEY\r\nHost: example.com\r\n\r\n";

        let result = rewrite_http_header_block(raw, resolver.as_ref()).expect("should succeed");
        let rewritten = String::from_utf8(result.rewritten).expect("utf8");

        assert!(rewritten.contains("Authorization: Bearer sk-test\r\n"));
        assert!(!rewritten.contains("openshell:resolve:env:ANTHROPIC_API_KEY"));
    }

    /// Verifies that `relay_http_request_with_resolver` rewrites credential
    /// placeholders in request headers before forwarding to upstream.
    ///
    /// This is the code path exercised when an endpoint has `protocol: rest`
    /// and `tls: terminate` — the proxy terminates TLS, sees plaintext HTTP,
    /// and replaces placeholder tokens with real secrets.
    ///
    /// Without this test, a misconfigured endpoint (missing `tls: terminate`)
    /// silently leaks placeholder strings like `openshell:resolve:env:NVIDIA_API_KEY`
    /// to the upstream API, causing 401 Unauthorized errors.
    #[tokio::test]
    async fn relay_request_with_resolver_rewrites_credential_placeholders() {
        let provider_env: HashMap<String, String> = [(
            "NVIDIA_API_KEY".to_string(),
            "nvapi-real-secret-key".to_string(),
        )]
        .into_iter()
        .collect();

        let (child_env, resolver) = SecretResolver::from_provider_env(provider_env);
        let placeholder = child_env.get("NVIDIA_API_KEY").unwrap();

        let (mut proxy_to_upstream, mut upstream_side) = tokio::io::duplex(8192);
        let (mut _app_side, mut proxy_to_client) = tokio::io::duplex(8192);

        let req = L7Request {
            action: "POST".to_string(),
            target: "/v1/chat/completions".to_string(),
            query_params: HashMap::new(),
            raw_header: format!(
                "POST /v1/chat/completions HTTP/1.1\r\n\
                 Host: integrate.api.nvidia.com\r\n\
                 Authorization: Bearer {placeholder}\r\n\
                 Content-Length: 2\r\n\r\n{{}}"
            )
            .into_bytes(),
            body_length: BodyLength::ContentLength(2),
        };

        // Mock upstream: read the forwarded request, capture it, send response
        let upstream_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let mut total = 0;
            loop {
                let n = upstream_side.read(&mut buf[total..]).await.unwrap();
                if n == 0 {
                    break;
                }
                total += n;
                if let Some(hdr_end) = buf[..total].windows(4).position(|w| w == b"\r\n\r\n") {
                    if total >= hdr_end + 4 + 2 {
                        break;
                    }
                }
            }
            upstream_side
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            upstream_side.flush().await.unwrap();
            String::from_utf8_lossy(&buf[..total]).to_string()
        });

        // Run the relay with a resolver — simulates the TLS-terminate path
        let relay = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            relay_http_request_with_resolver(
                &req,
                &mut proxy_to_client,
                &mut proxy_to_upstream,
                resolver.as_ref(),
            ),
        )
        .await
        .expect("relay must not deadlock");
        relay.expect("relay should succeed");

        let forwarded = upstream_task.await.expect("upstream task should complete");

        // The real secret must appear in what upstream received
        assert!(
            forwarded.contains("Authorization: Bearer nvapi-real-secret-key\r\n"),
            "Expected real API key in upstream request, got: {forwarded}"
        );
        // The placeholder must NOT appear
        assert!(
            !forwarded.contains("openshell:resolve:env:"),
            "Placeholder leaked to upstream: {forwarded}"
        );
        // Other headers must be preserved
        assert!(forwarded.contains("Host: integrate.api.nvidia.com\r\n"));
    }

    /// Verifies that without a `SecretResolver` (i.e. the L4-only raw tunnel
    /// path, or no TLS termination), credential placeholders pass through
    /// unmodified. This documents the behavior that causes 401 errors when
    /// `tls: terminate` is missing from the endpoint config.
    #[tokio::test]
    async fn relay_request_without_resolver_leaks_placeholders() {
        let (child_env, _resolver) = SecretResolver::from_provider_env(
            [("NVIDIA_API_KEY".to_string(), "nvapi-secret".to_string())]
                .into_iter()
                .collect(),
        );
        let placeholder = child_env.get("NVIDIA_API_KEY").unwrap();

        let (mut proxy_to_upstream, mut upstream_side) = tokio::io::duplex(8192);
        let (mut _app_side, mut proxy_to_client) = tokio::io::duplex(8192);

        let req = L7Request {
            action: "POST".to_string(),
            target: "/v1/chat/completions".to_string(),
            query_params: HashMap::new(),
            raw_header: format!(
                "POST /v1/chat/completions HTTP/1.1\r\n\
                 Host: integrate.api.nvidia.com\r\n\
                 Authorization: Bearer {placeholder}\r\n\
                 Content-Length: 2\r\n\r\n{{}}"
            )
            .into_bytes(),
            body_length: BodyLength::ContentLength(2),
        };

        let upstream_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let mut total = 0;
            loop {
                let n = upstream_side.read(&mut buf[total..]).await.unwrap();
                if n == 0 {
                    break;
                }
                total += n;
                if let Some(hdr_end) = buf[..total].windows(4).position(|w| w == b"\r\n\r\n") {
                    if total >= hdr_end + 4 + 2 {
                        break;
                    }
                }
            }
            upstream_side
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            upstream_side.flush().await.unwrap();
            String::from_utf8_lossy(&buf[..total]).to_string()
        });

        // Pass `None` for the resolver — simulates the L4 path where no
        // rewriting occurs.
        let relay = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            relay_http_request_with_resolver(
                &req,
                &mut proxy_to_client,
                &mut proxy_to_upstream,
                None, // <-- No resolver, as in the L4 raw tunnel path
            ),
        )
        .await
        .expect("relay must not deadlock");
        relay.expect("relay should succeed");

        let forwarded = upstream_task.await.expect("upstream task should complete");

        // Without a resolver, the placeholder LEAKS to upstream — this is the
        // documented behavior that causes 401s when `tls: terminate` is missing.
        assert!(
            forwarded.contains("openshell:resolve:env:NVIDIA_API_KEY"),
            "Expected placeholder to leak without resolver, got: {forwarded}"
        );
        assert!(
            !forwarded.contains("nvapi-secret"),
            "Real secret should NOT appear without resolver, got: {forwarded}"
        );
    }

    // =========================================================================
    // Credential injection integration tests
    //
    // Each test exercises a different injection location through the full
    // relay_http_request_with_resolver pipeline: child builds an HTTP request
    // with a placeholder, the relay rewrites it, and we verify what upstream
    // receives.
    // =========================================================================

    /// Helper: run a request through the relay and capture what upstream receives.
    async fn relay_and_capture(
        raw_header: Vec<u8>,
        body_length: BodyLength,
        resolver: Option<&SecretResolver>,
    ) -> Result<String> {
        let (mut proxy_to_upstream, mut upstream_side) = tokio::io::duplex(8192);
        let (mut _app_side, mut proxy_to_client) = tokio::io::duplex(8192);

        // Parse the request line to extract action and target for L7Request
        let header_str = String::from_utf8_lossy(&raw_header);
        let first_line = header_str.lines().next().unwrap_or("");
        let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
        let action = parts.first().unwrap_or(&"GET").to_string();
        let target = parts.get(1).unwrap_or(&"/").to_string();

        let req = L7Request {
            action,
            target,
            query_params: HashMap::new(),
            raw_header,
            body_length,
        };

        let content_len = match body_length {
            BodyLength::ContentLength(n) => n,
            _ => 0,
        };

        let upstream_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let mut total = 0;
            loop {
                let n = upstream_side.read(&mut buf[total..]).await.unwrap();
                if n == 0 {
                    break;
                }
                total += n;
                if let Some(hdr_end) = buf[..total].windows(4).position(|w| w == b"\r\n\r\n") {
                    if total >= hdr_end + 4 + content_len as usize {
                        break;
                    }
                }
            }
            upstream_side
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            upstream_side.flush().await.unwrap();
            String::from_utf8_lossy(&buf[..total]).to_string()
        });

        let relay = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            relay_http_request_with_resolver(
                &req,
                &mut proxy_to_client,
                &mut proxy_to_upstream,
                resolver,
            ),
        )
        .await
        .map_err(|_| miette!("relay timed out"))?;
        relay?;

        let forwarded = upstream_task
            .await
            .map_err(|e| miette!("upstream task failed: {e}"))?;
        Ok(forwarded)
    }

    #[tokio::test]
    async fn relay_injects_bearer_header_credential() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("API_KEY".to_string(), "sk-real-secret-key".to_string())]
                .into_iter()
                .collect(),
        );
        let placeholder = child_env.get("API_KEY").unwrap();

        let raw = format!(
            "POST /v1/chat HTTP/1.1\r\n\
             Host: api.example.com\r\n\
             Authorization: Bearer {placeholder}\r\n\
             Content-Length: 2\r\n\r\n{{}}"
        );

        let forwarded = relay_and_capture(
            raw.into_bytes(),
            BodyLength::ContentLength(2),
            resolver.as_ref(),
        )
        .await
        .expect("relay should succeed");

        assert!(
            forwarded.contains("Authorization: Bearer sk-real-secret-key\r\n"),
            "Upstream should see real Bearer token, got: {forwarded}"
        );
        assert!(
            !forwarded.contains("openshell:resolve:env:"),
            "Placeholder leaked to upstream: {forwarded}"
        );
    }

    #[tokio::test]
    async fn relay_injects_exact_header_credential() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("CUSTOM_TOKEN".to_string(), "tok-12345".to_string())]
                .into_iter()
                .collect(),
        );
        let placeholder = child_env.get("CUSTOM_TOKEN").unwrap();

        let raw = format!(
            "GET /api/data HTTP/1.1\r\n\
             Host: api.example.com\r\n\
             x-api-key: {placeholder}\r\n\
             Content-Length: 0\r\n\r\n"
        );

        let forwarded = relay_and_capture(
            raw.into_bytes(),
            BodyLength::ContentLength(0),
            resolver.as_ref(),
        )
        .await
        .expect("relay should succeed");

        assert!(
            forwarded.contains("x-api-key: tok-12345\r\n"),
            "Upstream should see real x-api-key, got: {forwarded}"
        );
        assert!(!forwarded.contains("openshell:resolve:env:"));
    }

    #[tokio::test]
    async fn relay_injects_basic_auth_credential() {
        let b64 = base64::engine::general_purpose::STANDARD;

        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("REGISTRY_PASS".to_string(), "hunter2".to_string())]
                .into_iter()
                .collect(),
        );
        let placeholder = child_env.get("REGISTRY_PASS").unwrap();
        let encoded = b64.encode(format!("deploy:{placeholder}").as_bytes());

        let raw = format!(
            "GET /v2/_catalog HTTP/1.1\r\n\
             Host: registry.example.com\r\n\
             Authorization: Basic {encoded}\r\n\
             Content-Length: 0\r\n\r\n"
        );

        let forwarded = relay_and_capture(
            raw.into_bytes(),
            BodyLength::ContentLength(0),
            resolver.as_ref(),
        )
        .await
        .expect("relay should succeed");

        // Extract and decode the Basic auth token from what upstream received
        let auth_line = forwarded
            .lines()
            .find(|l| l.starts_with("Authorization: Basic"))
            .expect("upstream should have Authorization header");
        let token = auth_line
            .strip_prefix("Authorization: Basic ")
            .unwrap()
            .trim();
        let decoded = b64.decode(token).expect("valid base64");
        let decoded_str = std::str::from_utf8(&decoded).expect("valid utf8");

        assert_eq!(
            decoded_str, "deploy:hunter2",
            "Decoded Basic auth should contain real password"
        );
        assert!(!forwarded.contains("openshell:resolve:env:"));
    }

    #[tokio::test]
    async fn relay_injects_query_param_credential() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("YOUTUBE_KEY".to_string(), "AIzaSy-secret".to_string())]
                .into_iter()
                .collect(),
        );
        let placeholder = child_env.get("YOUTUBE_KEY").unwrap();

        let raw = format!(
            "GET /v3/search?part=snippet&key={placeholder} HTTP/1.1\r\n\
             Host: www.googleapis.com\r\n\
             Content-Length: 0\r\n\r\n"
        );

        let forwarded = relay_and_capture(
            raw.into_bytes(),
            BodyLength::ContentLength(0),
            resolver.as_ref(),
        )
        .await
        .expect("relay should succeed");

        assert!(
            forwarded.contains("key=AIzaSy-secret"),
            "Upstream should see real API key in query param, got: {forwarded}"
        );
        assert!(
            forwarded.contains("part=snippet"),
            "Non-secret query params should be preserved, got: {forwarded}"
        );
        assert!(!forwarded.contains("openshell:resolve:env:"));
    }

    #[tokio::test]
    async fn relay_injects_url_path_credential_telegram_style() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [(
                "TELEGRAM_TOKEN".to_string(),
                "123456:ABC-DEF1234ghIkl".to_string(),
            )]
            .into_iter()
            .collect(),
        );
        let placeholder = child_env.get("TELEGRAM_TOKEN").unwrap();

        let raw = format!(
            "POST /bot{placeholder}/sendMessage HTTP/1.1\r\n\
             Host: api.telegram.org\r\n\
             Content-Length: 2\r\n\r\n{{}}"
        );

        let forwarded = relay_and_capture(
            raw.into_bytes(),
            BodyLength::ContentLength(2),
            resolver.as_ref(),
        )
        .await
        .expect("relay should succeed");

        assert!(
            forwarded.contains("POST /bot123456:ABC-DEF1234ghIkl/sendMessage HTTP/1.1"),
            "Upstream should see real token in URL path, got: {forwarded}"
        );
        assert!(!forwarded.contains("openshell:resolve:env:"));
    }

    #[tokio::test]
    async fn relay_injects_url_path_credential_standalone_segment() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("ORG_TOKEN".to_string(), "org-abc-789".to_string())]
                .into_iter()
                .collect(),
        );
        let placeholder = child_env.get("ORG_TOKEN").unwrap();

        let raw = format!(
            "GET /api/{placeholder}/resources HTTP/1.1\r\n\
             Host: api.example.com\r\n\
             Content-Length: 0\r\n\r\n"
        );

        let forwarded = relay_and_capture(
            raw.into_bytes(),
            BodyLength::ContentLength(0),
            resolver.as_ref(),
        )
        .await
        .expect("relay should succeed");

        assert!(
            forwarded.contains("GET /api/org-abc-789/resources HTTP/1.1"),
            "Upstream should see real token in path segment, got: {forwarded}"
        );
        assert!(!forwarded.contains("openshell:resolve:env:"));
    }

    #[tokio::test]
    async fn relay_injects_combined_path_and_header_credentials() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [
                ("PATH_TOKEN".to_string(), "tok-path-123".to_string()),
                ("HEADER_KEY".to_string(), "sk-header-456".to_string()),
            ]
            .into_iter()
            .collect(),
        );
        let path_ph = child_env.get("PATH_TOKEN").unwrap();
        let header_ph = child_env.get("HEADER_KEY").unwrap();

        let raw = format!(
            "POST /bot{path_ph}/send HTTP/1.1\r\n\
             Host: api.example.com\r\n\
             x-api-key: {header_ph}\r\n\
             Content-Length: 2\r\n\r\n{{}}"
        );

        let forwarded = relay_and_capture(
            raw.into_bytes(),
            BodyLength::ContentLength(2),
            resolver.as_ref(),
        )
        .await
        .expect("relay should succeed");

        assert!(
            forwarded.contains("/bottok-path-123/send"),
            "Upstream should see real token in path, got: {forwarded}"
        );
        assert!(
            forwarded.contains("x-api-key: sk-header-456\r\n"),
            "Upstream should see real token in header, got: {forwarded}"
        );
        assert!(!forwarded.contains("openshell:resolve:env:"));
    }

    #[tokio::test]
    async fn relay_fail_closed_rejects_unresolved_placeholder() {
        // Create a resolver that knows about KEY1 but not UNKNOWN_KEY
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("KEY1".to_string(), "secret1".to_string())]
                .into_iter()
                .collect(),
        );
        let _ = child_env;

        // The request references a placeholder that the resolver doesn't know
        let raw = b"GET /api HTTP/1.1\r\n\
             Host: example.com\r\n\
             x-api-key: openshell:resolve:env:UNKNOWN_KEY\r\n\
             Content-Length: 0\r\n\r\n"
            .to_vec();

        let result = relay_and_capture(raw, BodyLength::ContentLength(0), resolver.as_ref()).await;

        assert!(
            result.is_err(),
            "Relay should fail when placeholder cannot be resolved"
        );
    }

    #[tokio::test]
    async fn relay_fail_closed_rejects_unresolved_path_placeholder() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("KEY1".to_string(), "secret1".to_string())]
                .into_iter()
                .collect(),
        );

        let raw =
            b"GET /api/openshell:resolve:env:UNKNOWN_KEY/data HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"
                .to_vec();

        let result = relay_and_capture(raw, BodyLength::ContentLength(0), resolver.as_ref()).await;

        assert!(
            result.is_err(),
            "Relay should fail when path placeholder cannot be resolved"
        );
    }
}
