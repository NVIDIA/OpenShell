// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! REST (HTTP/1.1) L7 provider.
//!
//! Parses HTTP/1.1 request lines and headers, evaluates method+path against
//! policy, and relays allowed requests to upstream. Handles Content-Length
//! and chunked transfer encoding for body framing.

use crate::l7::provider::{BodyLength, L7Provider, L7Request};
use crate::secrets::rewrite_http_header_block;
use miette::{IntoDiagnostic, Result, miette};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

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

    async fn relay<C, U>(&self, req: &L7Request, client: &mut C, upstream: &mut U) -> Result<bool>
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
        send_deny_response(req, policy_name, reason, client).await
    }
}

/// Parse one HTTP/1.1 request from the stream.
async fn parse_http_request<C: AsyncRead + Unpin>(client: &mut C) -> Result<Option<L7Request>> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];

    loop {
        if buf.len() > MAX_HEADER_BYTES {
            return Err(miette!(
                "HTTP request headers exceed {MAX_HEADER_BYTES} bytes"
            ));
        }

        let n = match client.read(&mut tmp).await {
            Ok(n) => n,
            Err(e) if buf.is_empty() && is_benign_close(&e) => return Ok(None),
            Err(e) => return Err(miette::miette!("{e}")),
        };
        if n == 0 {
            if buf.is_empty() {
                return Ok(None); // Clean connection close
            }
            return Err(miette!(
                "Client disconnected mid-request after {} bytes",
                buf.len()
            ));
        }
        buf.extend_from_slice(&tmp[..n]);

        // Check for end of headers
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    // Parse request line
    let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;

    let header_str = String::from_utf8_lossy(&buf[..header_end]);
    let request_line = header_str
        .lines()
        .next()
        .ok_or_else(|| miette!("Empty HTTP request"))?;

    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| miette!("Missing HTTP method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| miette!("Missing HTTP path"))?
        .to_string();

    // Determine body framing from headers
    let body_length = parse_body_length(&header_str);

    Ok(Some(L7Request {
        action: method,
        target: path,
        raw_header: buf, // includes header bytes + any overflow body bytes
        body_length,
    }))
}

/// Forward an allowed HTTP request to upstream and relay the response back.
///
/// Returns `true` if the upstream connection is reusable, `false` if consumed.
async fn relay_http_request<C, U>(req: &L7Request, client: &mut C, upstream: &mut U) -> Result<bool>
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
) -> Result<bool>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let header_end = req
        .raw_header
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(req.raw_header.len(), |p| p + 4);

    let rewritten_header = rewrite_http_header_block(&req.raw_header[..header_end], resolver);

    upstream
        .write_all(&rewritten_header)
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
    relay_response(&req.action, upstream, client).await
}

/// Send a 403 Forbidden JSON deny response.
async fn send_deny_response<C: AsyncWrite + Unpin>(
    req: &L7Request,
    policy_name: &str,
    reason: &str,
    client: &mut C,
) -> Result<()> {
    let body = serde_json::json!({
        "error": "policy_denied",
        "policy": policy_name,
        "rule": format!("{} {}", req.action, req.target),
        "detail": reason
    });
    let body_bytes = body.to_string();
    let response = format!(
        "HTTP/1.1 403 Forbidden\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         X-Navigator-Policy: {}\r\n\
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
fn parse_body_length(headers: &str) -> BodyLength {
    for line in headers.lines().skip(1) {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("transfer-encoding:") {
            let val = lower.split_once(':').map_or("", |(_, v)| v.trim());
            if val.contains("chunked") {
                return BodyLength::Chunked;
            }
        }
        if lower.starts_with("content-length:")
            && let Some(val) = lower.split_once(':').map(|(_, v)| v.trim())
            && let Ok(len) = val.parse::<u64>()
        {
            return BodyLength::ContentLength(len);
        }
    }
    BodyLength::None
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
/// Returns `true` if the upstream connection is reusable (keep-alive),
/// `false` if it was consumed (read-until-EOF or `Connection: close`).
async fn relay_response<U, C>(
    request_method: &str,
    upstream: &mut U,
    client: &mut C,
) -> Result<bool>
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
            return Ok(false);
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
    let body_length = parse_body_length(&header_str);

    debug!(
        status_code,
        ?body_length,
        server_wants_close,
        request_method,
        overflow_bytes = buf.len() - header_end,
        "relay_response framing"
    );

    // Bodiless responses (HEAD, 1xx, 204, 304): forward headers only, skip body
    if is_bodiless_response(request_method, status_code) {
        client
            .write_all(&buf[..header_end])
            .await
            .into_diagnostic()?;
        client.flush().await.into_diagnostic()?;
        return Ok(!server_wants_close);
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
            return Ok(false);
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
        return Ok(true);
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
    Ok(true)
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

    #[test]
    fn parse_content_length() {
        let headers = "POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 42\r\n\r\n";
        match parse_body_length(headers) {
            BodyLength::ContentLength(42) => {}
            other => panic!("Expected ContentLength(42), got {other:?}"),
        }
    }

    #[test]
    fn parse_chunked() {
        let headers =
            "POST /api HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n";
        match parse_body_length(headers) {
            BodyLength::Chunked => {}
            other => panic!("Expected Chunked, got {other:?}"),
        }
    }

    #[test]
    fn parse_no_body() {
        let headers = "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n";
        match parse_body_length(headers) {
            BodyLength::None => {}
            other => panic!("Expected None, got {other:?}"),
        }
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

        let reusable = result.expect("relay_response should succeed");
        assert!(!reusable, "connection consumed by read-until-EOF");

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

        let reusable = result.expect("relay_response should succeed");
        assert!(reusable, "keep-alive implied, connection reusable");

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

        let reusable = result.expect("relay_response should succeed");
        assert!(reusable, "HEAD response should be reusable");

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

        let reusable = result.expect("relay_response should succeed");
        assert!(reusable, "204 response should be reusable");

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

        let reusable = result.expect("relay_response should succeed");
        assert!(reusable, "connection should be reusable");

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

        let reusable = result.expect("relay_response should succeed");
        assert!(reusable, "chunked response should be reusable");

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

        let reusable = result.expect("relay_response should succeed");
        assert!(reusable, "Content-Length response should be reusable");

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

        let reusable = result.expect("relay_response should succeed");
        // With explicit framing, Connection: close is still reported as reusable
        // so the relay loop continues.  The *next* upstream write will fail and
        // exit the loop via the normal error path.
        assert!(
            reusable,
            "explicit framing keeps loop alive despite Connection: close"
        );

        client_write.shutdown().await.unwrap();
        let mut received = Vec::new();
        client_read.read_to_end(&mut received).await.unwrap();
        assert!(String::from_utf8_lossy(&received).contains("hello"));
    }

    #[test]
    fn rewrite_header_block_resolves_placeholder_auth_headers() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("ANTHROPIC_API_KEY".to_string(), "sk-test".to_string())]
                .into_iter()
                .collect(),
        );
        let raw = b"GET /v1/messages HTTP/1.1\r\nAuthorization: Bearer openshell:resolve:env:ANTHROPIC_API_KEY\r\nHost: example.com\r\n\r\n";

        let rewritten = rewrite_http_header_block(raw, resolver.as_ref());
        let rewritten = String::from_utf8(rewritten).expect("utf8");

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
        let provider_env: std::collections::HashMap<String, String> = [(
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
}
