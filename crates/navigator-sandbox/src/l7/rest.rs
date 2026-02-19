//! REST (HTTP/1.1) L7 provider.
//!
//! Parses HTTP/1.1 request lines and headers, evaluates method+path against
//! policy, and relays allowed requests to upstream. Handles Content-Length
//! and chunked transfer encoding for body framing.

use crate::l7::provider::{BodyLength, L7Provider, L7Request};
use miette::{IntoDiagnostic, Result, miette};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_HEADER_BYTES: usize = 16384; // 16 KiB for HTTP headers
const RELAY_BUF_SIZE: usize = 8192;

/// HTTP/1.1 REST protocol provider.
pub struct RestProvider;

impl L7Provider for RestProvider {
    async fn parse_request<C: AsyncRead + AsyncWrite + Unpin + Send>(
        &self,
        client: &mut C,
    ) -> Result<Option<L7Request>> {
        parse_http_request(client).await
    }

    async fn relay<C, U>(&self, req: &L7Request, client: &mut C, upstream: &mut U) -> Result<()>
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
async fn relay_http_request<C, U>(req: &L7Request, client: &mut C, upstream: &mut U) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    // Find the actual header end in raw_header
    let header_end = req
        .raw_header
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(req.raw_header.len(), |p| p + 4);

    // Forward request headers to upstream
    upstream
        .write_all(&req.raw_header[..header_end])
        .await
        .into_diagnostic()?;

    // Forward any overflow body bytes that were read with headers
    let overflow = &req.raw_header[header_end..];
    if !overflow.is_empty() {
        upstream.write_all(overflow).await.into_diagnostic()?;
    }
    let overflow_len = overflow.len() as u64;

    // Forward remaining request body
    match req.body_length {
        BodyLength::ContentLength(len) => {
            let remaining = len.saturating_sub(overflow_len);
            if remaining > 0 {
                relay_fixed(client, upstream, remaining).await?;
            }
        }
        BodyLength::Chunked => {
            relay_chunked(client, upstream).await?;
        }
        BodyLength::None => {}
    }
    upstream.flush().await.into_diagnostic()?;

    // Read and forward response from upstream back to client
    relay_response(upstream, client).await?;

    Ok(())
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
/// Copies chunks verbatim (preserving the chunked framing) until the
/// terminal `0\r\n\r\n` chunk is seen.
async fn relay_chunked<R, W>(reader: &mut R, writer: &mut W) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; RELAY_BUF_SIZE];
    let mut tail = Vec::new();

    loop {
        let n = reader.read(&mut buf).await.into_diagnostic()?;
        if n == 0 {
            return Ok(());
        }

        writer.write_all(&buf[..n]).await.into_diagnostic()?;

        // Track tail bytes to detect terminal chunk: 0\r\n\r\n
        tail.extend_from_slice(&buf[..n]);
        if tail.len() > 16 {
            let keep_from = tail.len() - 7;
            tail.drain(..keep_from);
        }

        if tail.windows(5).any(|w| w == b"0\r\n\r\n") {
            return Ok(());
        }
    }
}

/// Read and relay a full HTTP response (headers + body) from upstream to client.
async fn relay_response<U, C>(upstream: &mut U, client: &mut C) -> Result<()>
where
    U: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
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
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);

        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;

    // Parse response body framing
    let header_str = String::from_utf8_lossy(&buf[..header_end]);
    let body_length = parse_body_length(&header_str);

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
            relay_chunked(upstream, client).await?;
        }
        BodyLength::None => {}
    }
    client.flush().await.into_diagnostic()?;

    Ok(())
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
}
