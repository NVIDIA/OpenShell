// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! REST (HTTP/1.1) L7 provider.
//!
//! Parses HTTP/1.1 request lines and headers, evaluates method+path against
//! policy, and relays allowed requests to upstream. Handles Content-Length
//! and chunked transfer encoding for body framing.

use crate::l7::provider::{BodyLength, L7Provider, L7Request, RelayOutcome};
use crate::opa::PolicyGenerationGuard;
use crate::secrets::{
    SecretResolver, contains_reserved_credential_marker, rewrite_http_header_block,
};
use base64::Engine as _;
use miette::{IntoDiagnostic, Result, miette};
use sha1::{Digest, Sha1};
use std::collections::{HashMap, HashSet};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

const MAX_HEADER_BYTES: usize = 16384; // 16 KiB for HTTP headers
const MAX_REWRITE_BODY_BYTES: usize = 256 * 1024;
const RELAY_BUF_SIZE: usize = 8192;
/// Idle timeout for `relay_until_eof`.  If no data arrives within this window
/// the body is considered complete.  Prevents blocking on servers that keep
/// the TCP connection alive after the response body (common with CDN keep-alive).
const RELAY_EOF_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// HTTP/1.1 REST protocol provider.
///
/// Carries the path-canonicalization options derived from the endpoint
/// config so that different endpoints (e.g. one backed by GitLab that needs
/// `%2F` in paths and one backed by a strict API) can apply different
/// canonicalization strictness to the same `RestProvider` call surface.
#[derive(Debug, Clone, Default)]
pub struct RestProvider {
    canonicalize_options: crate::l7::path::CanonicalizeOptions,
}

impl RestProvider {
    /// Construct a provider with explicit canonicalization options. Used by
    /// `relay_rest` so endpoint config can opt in to looser behavior such
    /// as `allow_encoded_slash`.
    pub fn with_options(canonicalize_options: crate::l7::path::CanonicalizeOptions) -> Self {
        Self {
            canonicalize_options,
        }
    }
}

impl L7Provider for RestProvider {
    async fn parse_request<C: AsyncRead + AsyncWrite + Unpin + Send>(
        &self,
        client: &mut C,
    ) -> Result<Option<L7Request>> {
        parse_http_request(client, &self.canonicalize_options).await
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
        send_deny_response(req, policy_name, reason, client, None, None).await
    }
}

/// Extra sandbox-side context included in agent-readable deny responses when
/// the relay has it available.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct DenyResponseContext<'a> {
    pub(crate) host: Option<&'a str>,
    pub(crate) port: Option<u16>,
    pub(crate) binary: Option<&'a str>,
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
        context: Option<DenyResponseContext<'_>>,
    ) -> Result<()> {
        send_deny_response(req, policy_name, reason, client, redacted_target, context).await
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
async fn parse_http_request<C: AsyncRead + Unpin>(
    client: &mut C,
    canonicalize_options: &crate::l7::path::CanonicalizeOptions,
) -> Result<Option<L7Request>> {
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

    // Canonicalize the request-target before OPA evaluation AND before
    // forwarding. This closes the parser-differential between the policy
    // engine (which matches on segments) and the upstream server (which
    // resolves `..` / `%2e%2e` / `%2F` before dispatch). If canonicalization
    // fails, the request is rejected as a protocol violation — consistent
    // with how duplicate Content-Length, bare LF, and invalid UTF-8 are
    // handled by this parser.
    let (canonical, raw_query) =
        crate::l7::path::canonicalize_request_target(&target, canonicalize_options)
            .map_err(|e| miette!("HTTP request-target rejected: {e}"))?;

    let query_params = match raw_query.as_deref() {
        Some(q) => parse_query_params(q)?,
        None => HashMap::new(),
    };

    if canonical.rewritten {
        buf = rewrite_request_line_target(
            &buf,
            &method,
            &canonical.path,
            raw_query.as_deref(),
            version,
        )?;
    }

    Ok(Some(L7Request {
        action: method,
        target: canonical.path,
        query_params,
        raw_header: buf, // exact header bytes up to and including \r\n\r\n
        body_length,
    }))
}

/// Rebuild the request line in a raw HTTP header block with a canonicalized
/// target. Called when the canonical path differs from what the client sent,
/// so the upstream dispatches on the exact bytes the policy engine evaluated.
fn rewrite_request_line_target(
    raw: &[u8],
    method: &str,
    canonical_path: &str,
    raw_query: Option<&str>,
    version: &str,
) -> Result<Vec<u8>> {
    let eol = raw
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or_else(|| miette!("request line missing CRLF"))?;
    let rest = &raw[eol..];
    let new_target = match raw_query {
        Some(q) if !q.is_empty() => format!("{canonical_path}?{q}"),
        _ => canonical_path.to_string(),
    };
    let new_request_line = format!("{method} {new_target} {version}");
    let mut out = Vec::with_capacity(new_request_line.len() + rest.len());
    out.extend_from_slice(new_request_line.as_bytes());
    out.extend_from_slice(rest);
    Ok(out)
}

pub(crate) fn parse_target_query(target: &str) -> Result<(String, HashMap<String, Vec<String>>)> {
    match target.split_once('?') {
        Some((path, query)) => Ok((path.to_string(), parse_query_params(query)?)),
        None => Ok((target.to_string(), HashMap::new())),
    }
}

pub(crate) fn parse_query_params(query: &str) -> Result<HashMap<String, Vec<String>>> {
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
    resolver: Option<&SecretResolver>,
) -> Result<RelayOutcome>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    relay_http_request_with_resolver_guarded(req, client, upstream, resolver, None).await
}

pub(crate) async fn relay_http_request_with_resolver_guarded<C, U>(
    req: &L7Request,
    client: &mut C,
    upstream: &mut U,
    resolver: Option<&SecretResolver>,
    generation_guard: Option<&PolicyGenerationGuard>,
) -> Result<RelayOutcome>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    relay_http_request_with_options_guarded(
        req,
        client,
        upstream,
        RelayRequestOptions {
            resolver,
            generation_guard,
            websocket_extensions: WebSocketExtensionMode::Preserve,
            request_body_credential_rewrite: false,
        },
    )
    .await
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum WebSocketExtensionMode {
    #[default]
    Preserve,
    PermessageDeflate,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct RelayRequestOptions<'a> {
    pub(crate) resolver: Option<&'a SecretResolver>,
    pub(crate) generation_guard: Option<&'a PolicyGenerationGuard>,
    pub(crate) websocket_extensions: WebSocketExtensionMode,
    pub(crate) request_body_credential_rewrite: bool,
}

pub(crate) async fn relay_http_request_with_options_guarded<C, U>(
    req: &L7Request,
    client: &mut C,
    upstream: &mut U,
    options: RelayRequestOptions<'_>,
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
    let header_str = std::str::from_utf8(&req.raw_header[..header_end])
        .map_err(|_| miette!("HTTP headers contain invalid UTF-8"))?;
    let client_requested_upgrade = client_requested_upgrade(header_str);
    let websocket_request = if options.websocket_extensions == WebSocketExtensionMode::Preserve {
        None
    } else {
        parse_websocket_upgrade_request(&req.raw_header[..header_end])?
    };

    let (header_bytes, expected_websocket_extension) = rewrite_websocket_extensions_for_mode(
        &req.raw_header[..header_end],
        options.websocket_extensions,
        websocket_request.is_some(),
    )?;
    let websocket_response =
        websocket_request
            .as_ref()
            .map(|request| WebSocketResponseValidation {
                expected_accept: websocket_accept_for_key(&request.sec_key),
                expected_extension: expected_websocket_extension.clone(),
                offered_subprotocols: request.subprotocols.clone(),
            });

    let rewrite_result = rewrite_http_header_block(&header_bytes, options.resolver)
        .map_err(|e| miette!("credential injection failed: {e}"))?;

    if let Some(guard) = options.generation_guard {
        guard.ensure_current()?;
    }

    if options.request_body_credential_rewrite {
        let body = collect_and_rewrite_request_body(
            req,
            client,
            &rewrite_result.rewritten,
            header_str,
            &req.raw_header[header_end..],
            options.resolver,
            options.generation_guard,
        )
        .await?;
        upstream.write_all(&body.headers).await.into_diagnostic()?;
        if !body.body.is_empty() {
            upstream.write_all(&body.body).await.into_diagnostic()?;
        }
    } else {
        upstream
            .write_all(&rewrite_result.rewritten)
            .await
            .into_diagnostic()?;

        let overflow = &req.raw_header[header_end..];
        if !overflow.is_empty() {
            if let Some(guard) = options.generation_guard {
                guard.ensure_current()?;
            }
            upstream.write_all(overflow).await.into_diagnostic()?;
        }
        let overflow_len = overflow.len() as u64;

        match req.body_length {
            BodyLength::ContentLength(len) => {
                let remaining = len.saturating_sub(overflow_len);
                if remaining > 0 {
                    relay_fixed(client, upstream, remaining, options.generation_guard).await?;
                }
            }
            BodyLength::Chunked => {
                relay_chunked(
                    client,
                    upstream,
                    &req.raw_header[header_end..],
                    options.generation_guard,
                )
                .await?;
            }
            BodyLength::None => {}
        }
    }
    upstream.flush().await.into_diagnostic()?;

    let outcome = relay_response(
        &req.action,
        upstream,
        client,
        RelayResponseOptions {
            websocket_extensions: options.websocket_extensions,
            websocket: websocket_response,
            client_requested_upgrade,
        },
    )
    .await?;

    Ok(outcome)
}

struct PreparedRequestBody {
    headers: Vec<u8>,
    body: Vec<u8>,
}

async fn collect_and_rewrite_request_body<C: AsyncRead + Unpin>(
    req: &L7Request,
    client: &mut C,
    rewritten_headers: &[u8],
    original_header_str: &str,
    already_read: &[u8],
    resolver: Option<&SecretResolver>,
    generation_guard: Option<&PolicyGenerationGuard>,
) -> Result<PreparedRequestBody> {
    match req.body_length {
        BodyLength::None => {
            if body_bytes_contain_reserved_marker(already_read) {
                return Err(miette!(
                    "request body credential rewrite cannot resolve placeholders without explicit body framing"
                ));
            }
            Ok(PreparedRequestBody {
                headers: rewritten_headers.to_vec(),
                body: already_read.to_vec(),
            })
        }
        BodyLength::ContentLength(len) => {
            let len = usize::try_from(len)
                .map_err(|_| miette!("request body is too large for credential rewrite"))?;
            if len > MAX_REWRITE_BODY_BYTES {
                return Err(miette!(
                    "request body credential rewrite buffers at most {MAX_REWRITE_BODY_BYTES} bytes"
                ));
            }
            let mut body = Vec::with_capacity(len);
            let initial_len = already_read.len().min(len);
            body.extend_from_slice(&already_read[..initial_len]);
            let mut remaining = len.saturating_sub(initial_len);
            let mut buf = [0u8; RELAY_BUF_SIZE];
            while remaining > 0 {
                let to_read = remaining.min(buf.len());
                let n = client.read(&mut buf[..to_read]).await.into_diagnostic()?;
                if n == 0 {
                    return Err(miette!(
                        "Connection closed with {remaining} body bytes remaining"
                    ));
                }
                if let Some(guard) = generation_guard {
                    guard.ensure_current()?;
                }
                body.extend_from_slice(&buf[..n]);
                remaining -= n;
            }
            let (headers, body) =
                rewrite_buffered_body(rewritten_headers, original_header_str, body, resolver)?;
            Ok(PreparedRequestBody { headers, body })
        }
        BodyLength::Chunked => {
            let body = collect_chunked_body(client, already_read, generation_guard).await?;
            if body_bytes_contain_reserved_marker(&body) {
                return Err(miette!(
                    "request body credential rewrite does not support chunked bodies containing credential placeholders"
                ));
            }
            Ok(PreparedRequestBody {
                headers: rewritten_headers.to_vec(),
                body,
            })
        }
    }
}

fn rewrite_buffered_body(
    headers: &[u8],
    original_header_str: &str,
    body: Vec<u8>,
    resolver: Option<&SecretResolver>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    if body.is_empty() {
        return Ok((headers.to_vec(), body));
    }

    let content_type = content_type(original_header_str);
    if !is_rewritable_content_type(content_type.as_deref()) {
        if body_bytes_contain_reserved_marker(&body) {
            return Err(miette!(
                "request body credential rewrite found placeholders in an unsupported content type"
            ));
        }
        return Ok((headers.to_vec(), body));
    }

    let mut text = String::from_utf8(body)
        .map_err(|_| miette!("request body credential rewrite requires UTF-8 text bodies"))?;
    if !contains_reserved_credential_marker(&text) {
        return Ok((headers.to_vec(), text.into_bytes()));
    }

    let Some(resolver) = resolver else {
        return Err(miette!(
            "request body credential rewrite found placeholders but no resolver is available"
        ));
    };

    let replacements = if content_type.as_deref() == Some("application/x-www-form-urlencoded") {
        let (rewritten, replacements) = rewrite_form_urlencoded_body(&text, resolver)?;
        text = rewritten;
        replacements
    } else {
        resolver
            .rewrite_text_placeholders(&mut text, "request_body")
            .map_err(|e| miette!("credential injection failed: {e}"))?
    };
    if replacements == 0 || contains_reserved_credential_marker(&text) {
        return Err(miette!(
            "request body credential rewrite left unresolved credential placeholders"
        ));
    }

    let body = text.into_bytes();
    let headers = set_content_length(headers, body.len())?;
    Ok((headers, body))
}

fn rewrite_form_urlencoded_body(body: &str, resolver: &SecretResolver) -> Result<(String, usize)> {
    let mut rewritten = String::with_capacity(body.len());
    let mut replacements = 0usize;

    for (idx, field) in body.split('&').enumerate() {
        if idx > 0 {
            rewritten.push('&');
        }

        let (name, value) = field
            .split_once('=')
            .map_or((field, None), |(name, value)| (name, Some(value)));
        let decoded_name = form_url_decode(name)?;
        if contains_reserved_credential_marker(&decoded_name) {
            return Err(miette!(
                "request body credential rewrite does not support placeholders in form field names"
            ));
        }

        rewritten.push_str(name);
        let Some(value) = value else {
            continue;
        };

        rewritten.push('=');
        let decoded_value = form_url_decode(value)?;
        if !contains_reserved_credential_marker(&decoded_value) {
            rewritten.push_str(value);
            continue;
        }

        let mut rewritten_value = decoded_value;
        let field_replacements = resolver
            .rewrite_text_placeholders(&mut rewritten_value, "request_body")
            .map_err(|e| miette!("credential injection failed: {e}"))?;
        if field_replacements == 0 || contains_reserved_credential_marker(&rewritten_value) {
            return Err(miette!(
                "request body credential rewrite left unresolved credential placeholders"
            ));
        }
        replacements += field_replacements;
        rewritten.push_str(&form_url_encode(&rewritten_value));
    }

    Ok((rewritten, replacements))
}

fn form_url_decode(input: &str) -> Result<String> {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut pos = 0usize;

    while pos < bytes.len() {
        match bytes[pos] {
            b'+' => {
                decoded.push(b' ');
                pos += 1;
            }
            b'%' if pos + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (hex_value(bytes[pos + 1]), hex_value(bytes[pos + 2]))
                {
                    decoded.push((hi << 4) | lo);
                    pos += 3;
                } else {
                    decoded.push(bytes[pos]);
                    pos += 1;
                }
            }
            byte => {
                decoded.push(byte);
                pos += 1;
            }
        }
    }

    String::from_utf8(decoded).map_err(|_| {
        miette!("request body credential rewrite requires UTF-8 form-url-encoded fields")
    })
}

fn form_url_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'*' => {
                encoded.push(byte as char);
            }
            b' ' => encoded.push('+'),
            _ => {
                use std::fmt::Write as _;
                let _ = write!(encoded, "%{byte:02X}");
            }
        }
    }
    encoded
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

async fn collect_chunked_body<C: AsyncRead + Unpin>(
    client: &mut C,
    already_read: &[u8],
    generation_guard: Option<&PolicyGenerationGuard>,
) -> Result<Vec<u8>> {
    let mut read_buf = [0u8; RELAY_BUF_SIZE];
    let mut parse_buf = Vec::from(already_read);
    let mut pos = 0usize;

    loop {
        if parse_buf.len() > MAX_REWRITE_BODY_BYTES {
            return Err(miette!(
                "request body credential rewrite buffers at most {MAX_REWRITE_BODY_BYTES} bytes"
            ));
        }

        let size_line_end = loop {
            if let Some(end) = find_crlf(&parse_buf, pos) {
                break end;
            }
            let n = client.read(&mut read_buf).await.into_diagnostic()?;
            if n == 0 {
                return Err(miette!("Chunked body ended before chunk-size line"));
            }
            if let Some(guard) = generation_guard {
                guard.ensure_current()?;
            }
            parse_buf.extend_from_slice(&read_buf[..n]);
            if parse_buf.len() > MAX_REWRITE_BODY_BYTES {
                return Err(miette!(
                    "request body credential rewrite buffers at most {MAX_REWRITE_BODY_BYTES} bytes"
                ));
            }
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
            loop {
                let trailer_end = loop {
                    if let Some(end) = find_crlf(&parse_buf, pos) {
                        break end;
                    }
                    let n = client.read(&mut read_buf).await.into_diagnostic()?;
                    if n == 0 {
                        return Err(miette!("Chunked body ended before trailer terminator"));
                    }
                    if let Some(guard) = generation_guard {
                        guard.ensure_current()?;
                    }
                    parse_buf.extend_from_slice(&read_buf[..n]);
                    if parse_buf.len() > MAX_REWRITE_BODY_BYTES {
                        return Err(miette!(
                            "request body credential rewrite buffers at most {MAX_REWRITE_BODY_BYTES} bytes"
                        ));
                    }
                };
                let trailer_line = &parse_buf[pos..trailer_end];
                pos = trailer_end + 2;
                if trailer_line.is_empty() {
                    return Ok(parse_buf);
                }
            }
        }

        let chunk_end = pos
            .checked_add(chunk_size)
            .ok_or_else(|| miette!("Chunk size overflow"))?;
        let chunk_with_crlf_end = chunk_end
            .checked_add(2)
            .ok_or_else(|| miette!("Chunk size overflow"))?;
        while parse_buf.len() < chunk_with_crlf_end {
            let n = client.read(&mut read_buf).await.into_diagnostic()?;
            if n == 0 {
                return Err(miette!("Chunked body ended mid-chunk"));
            }
            if let Some(guard) = generation_guard {
                guard.ensure_current()?;
            }
            parse_buf.extend_from_slice(&read_buf[..n]);
            if parse_buf.len() > MAX_REWRITE_BODY_BYTES {
                return Err(miette!(
                    "request body credential rewrite buffers at most {MAX_REWRITE_BODY_BYTES} bytes"
                ));
            }
        }
        if &parse_buf[chunk_end..chunk_with_crlf_end] != b"\r\n" {
            return Err(miette!("Chunk missing terminating CRLF"));
        }
        pos = chunk_with_crlf_end;
    }
}

fn content_type(headers: &str) -> Option<String> {
    headers.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim().eq_ignore_ascii_case("content-type").then(|| {
            value
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
    })
}

fn is_rewritable_content_type(content_type: Option<&str>) -> bool {
    let Some(content_type) = content_type else {
        return false;
    };
    content_type == "application/json"
        || content_type == "application/x-www-form-urlencoded"
        || content_type.starts_with("text/")
}

fn body_bytes_contain_reserved_marker(body: &[u8]) -> bool {
    if body.is_empty() {
        return false;
    }
    String::from_utf8_lossy(body)
        .split('\0')
        .any(contains_reserved_credential_marker)
}

fn set_content_length(headers: &[u8], len: usize) -> Result<Vec<u8>> {
    use std::fmt::Write as _;

    let header_str =
        std::str::from_utf8(headers).map_err(|_| miette!("HTTP headers contain invalid UTF-8"))?;
    let mut out = String::with_capacity(header_str.len() + 32);
    let mut inserted = false;
    for line in header_str.split("\r\n") {
        if line.is_empty() {
            if !inserted {
                let _ = write!(out, "Content-Length: {len}\r\n");
            }
            out.push_str("\r\n");
            break;
        }
        if line
            .split_once(':')
            .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        {
            if !inserted {
                let _ = write!(out, "Content-Length: {len}\r\n");
                inserted = true;
            }
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    Ok(out.into_bytes())
}

pub(crate) fn request_is_websocket_upgrade(raw_header: &[u8]) -> bool {
    let header_end = raw_header
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(raw_header.len(), |p| p + 4);
    validate_websocket_upgrade_request(&raw_header[..header_end]).unwrap_or(false)
}

fn rewrite_websocket_extensions_for_mode(
    raw_header: &[u8],
    mode: WebSocketExtensionMode,
    websocket_request: bool,
) -> Result<(Vec<u8>, Option<String>)> {
    if !websocket_request || mode == WebSocketExtensionMode::Preserve {
        return Ok((raw_header.to_vec(), None));
    }
    match mode {
        WebSocketExtensionMode::Preserve => Ok((raw_header.to_vec(), None)),
        WebSocketExtensionMode::PermessageDeflate => {
            rewrite_websocket_extensions_for_permessage_deflate(raw_header)
        }
    }
}

fn rewrite_websocket_extensions_for_permessage_deflate(
    raw_header: &[u8],
) -> Result<(Vec<u8>, Option<String>)> {
    let header_str = std::str::from_utf8(raw_header)
        .map_err(|_| miette!("HTTP headers contain invalid UTF-8"))?;
    let safe_offer = supported_permessage_deflate_offer(header_str)?;
    let mut out = Vec::with_capacity(raw_header.len());
    let mut inserted = false;

    for line in header_str.split_inclusive("\r\n") {
        let bare = line.strip_suffix("\r\n").unwrap_or(line);
        if bare
            .to_ascii_lowercase()
            .starts_with("sec-websocket-extensions:")
        {
            continue;
        }
        if bare.is_empty() && !inserted {
            if let Some(offer) = safe_offer.as_deref() {
                out.extend_from_slice(b"Sec-WebSocket-Extensions: ");
                out.extend_from_slice(offer.as_bytes());
                out.extend_from_slice(b"\r\n");
            }
            inserted = true;
        }
        out.extend_from_slice(line.as_bytes());
    }
    Ok((out, safe_offer))
}

fn supported_permessage_deflate_offer(header_str: &str) -> Result<Option<String>> {
    for offer in websocket_extension_offers(header_str)? {
        if !offer.name.eq_ignore_ascii_case("permessage-deflate") {
            continue;
        }
        let mut client_no_context_takeover = false;
        let mut server_no_context_takeover = false;
        let mut unsupported = false;
        let mut seen = HashSet::new();
        for param in &offer.params {
            let name = param.name.to_ascii_lowercase();
            if param.value.is_some() || !seen.insert(name.clone()) {
                unsupported = true;
                break;
            }
            if name == "client_no_context_takeover" {
                client_no_context_takeover = true;
            } else if name == "server_no_context_takeover" {
                server_no_context_takeover = true;
            } else {
                unsupported = true;
                break;
            }
        }
        if client_no_context_takeover && !unsupported {
            let mut offer = "permessage-deflate; client_no_context_takeover".to_string();
            if server_no_context_takeover {
                offer.push_str("; server_no_context_takeover");
            }
            return Ok(Some(offer));
        }
    }
    Ok(None)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WebSocketExtensionOffer {
    name: String,
    params: Vec<WebSocketExtensionParam>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WebSocketExtensionParam {
    name: String,
    value: Option<String>,
}

fn websocket_extension_offers(header_str: &str) -> Result<Vec<WebSocketExtensionOffer>> {
    let mut offers = Vec::new();
    for line in header_str.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("sec-websocket-extensions") {
            continue;
        }
        for extension in value.split(',') {
            let mut parts = extension.split(';').map(str::trim);
            let Some(extension_name) = parts.next().filter(|name| !name.is_empty()) else {
                return Err(miette!("invalid WebSocket extension offer"));
            };
            if !is_http_token(extension_name) {
                return Err(miette!("invalid WebSocket extension token"));
            }
            let mut params = Vec::new();
            for param in parts {
                if param.is_empty() {
                    return Err(miette!("invalid WebSocket extension parameter"));
                }
                let (param_name, param_value) = match param.split_once('=') {
                    Some((name, value)) => {
                        let value = value.trim();
                        if value.is_empty() || value.starts_with('"') || !is_http_token(value) {
                            return Err(miette!("unsupported WebSocket extension parameter value"));
                        }
                        (name.trim(), Some(value.to_string()))
                    }
                    None => (param, None),
                };
                if param_name.is_empty() || !is_http_token(param_name) {
                    return Err(miette!("invalid WebSocket extension parameter"));
                }
                params.push(WebSocketExtensionParam {
                    name: param_name.to_string(),
                    value: param_value,
                });
            }
            offers.push(WebSocketExtensionOffer {
                name: extension_name.to_string(),
                params,
            });
        }
    }
    Ok(offers)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WebSocketUpgradeRequest {
    sec_key: String,
    subprotocols: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WebSocketResponseValidation {
    expected_accept: String,
    expected_extension: Option<String>,
    offered_subprotocols: Vec<String>,
}

fn validate_websocket_upgrade_request(raw_header: &[u8]) -> Result<bool> {
    parse_websocket_upgrade_request(raw_header).map(|request| request.is_some())
}

fn parse_websocket_upgrade_request(raw_header: &[u8]) -> Result<Option<WebSocketUpgradeRequest>> {
    let header_str = std::str::from_utf8(raw_header)
        .map_err(|_| miette!("HTTP headers contain invalid UTF-8"))?;
    let mut lines = header_str.lines();
    let Some(request_line) = lines.next() else {
        return Ok(None);
    };
    let method = request_line.split_whitespace().next().unwrap_or_default();
    let mut headers = WebSocketUpgradeHeaders::default();

    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "upgrade" if header_value_contains_token(value, "websocket") => {
                headers.upgrade_websocket = true;
            }
            "connection" if header_value_contains_token(value, "upgrade") => {
                headers.connection_upgrade = true;
            }
            "sec-websocket-key" => {
                headers.sec_key_count += 1;
                headers.sec_key = Some(value.to_string());
            }
            "sec-websocket-version" => {
                headers.version_count += 1;
                headers.version = Some(value.to_string());
            }
            "sec-websocket-protocol" => {
                headers.subprotocols.extend(parse_http_token_list(value)?);
            }
            _ => {}
        }
    }

    if !headers.is_attempt() {
        return Ok(None);
    }
    if !method.eq_ignore_ascii_case("GET") {
        return Err(miette!("websocket upgrade request must use GET"));
    }
    if !headers.upgrade_websocket {
        return Err(miette!(
            "websocket upgrade request missing Upgrade: websocket"
        ));
    }
    if !headers.connection_upgrade {
        return Err(miette!(
            "websocket upgrade request missing Connection: Upgrade"
        ));
    }
    if headers.sec_key_count != 1 {
        return Err(miette!(
            "websocket upgrade request must include exactly one Sec-WebSocket-Key"
        ));
    }
    let key = headers.sec_key.as_deref().unwrap_or_default();
    let decoded_key = base64::engine::general_purpose::STANDARD
        .decode(key.as_bytes())
        .map_err(|_| miette!("websocket upgrade request has invalid Sec-WebSocket-Key"))?;
    if decoded_key.len() != 16 {
        return Err(miette!(
            "websocket upgrade request has invalid Sec-WebSocket-Key length"
        ));
    }
    if headers.version_count != 1 || headers.version.as_deref() != Some("13") {
        return Err(miette!(
            "websocket upgrade request must use Sec-WebSocket-Version: 13"
        ));
    }
    Ok(Some(WebSocketUpgradeRequest {
        sec_key: key.to_string(),
        subprotocols: headers.subprotocols,
    }))
}

fn websocket_accept_for_key(sec_key: &str) -> String {
    const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut hasher = Sha1::new();
    hasher.update(sec_key.as_bytes());
    hasher.update(WEBSOCKET_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

fn header_value_contains_token(value: &str, expected: &str) -> bool {
    value
        .split(',')
        .any(|token| token.trim().eq_ignore_ascii_case(expected))
}

fn parse_http_token_list(value: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    for token in value.split(',') {
        let token = token.trim();
        if token.is_empty() || !is_http_token(token) {
            return Err(miette!("invalid HTTP token list"));
        }
        tokens.push(token.to_string());
    }
    Ok(tokens)
}

fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.as_bytes().iter().all(|byte| {
            matches!(
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
                    | b'0'..=b'9'
                    | b'A'..=b'Z'
                    | b'a'..=b'z'
            )
        })
}

#[derive(Default)]
struct WebSocketUpgradeHeaders {
    upgrade_websocket: bool,
    connection_upgrade: bool,
    sec_key: Option<String>,
    sec_key_count: usize,
    version: Option<String>,
    version_count: usize,
    subprotocols: Vec<String>,
}

impl WebSocketUpgradeHeaders {
    fn is_attempt(&self) -> bool {
        self.upgrade_websocket || self.sec_key.is_some() || self.version.is_some()
    }
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
    context: Option<DenyResponseContext<'_>>,
) -> Result<()> {
    let body = deny_response_body(req, policy_name, reason, redacted_target, context);
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

fn deny_response_body(
    req: &L7Request,
    policy_name: &str,
    reason: &str,
    redacted_target: Option<&str>,
    context: Option<DenyResponseContext<'_>>,
) -> serde_json::Value {
    let target = redacted_target.unwrap_or(&req.target);
    let context = context.unwrap_or_default();
    let host = non_empty(context.host);
    let binary = non_empty(context.binary);

    let mut rule_missing = serde_json::Map::new();
    rule_missing.insert("type".to_string(), serde_json::json!("rest_allow"));
    rule_missing.insert("layer".to_string(), serde_json::json!("l7"));
    rule_missing.insert("method".to_string(), serde_json::json!(req.action));
    rule_missing.insert("path".to_string(), serde_json::json!(target));
    if let Some(host) = host {
        rule_missing.insert("host".to_string(), serde_json::json!(host));
    }
    if let Some(port) = context.port {
        rule_missing.insert("port".to_string(), serde_json::json!(port));
    }
    if let Some(binary) = binary {
        rule_missing.insert("binary".to_string(), serde_json::json!(binary));
    }

    let mut body = serde_json::Map::new();
    body.insert("error".to_string(), serde_json::json!("policy_denied"));
    body.insert("policy".to_string(), serde_json::json!(policy_name));
    body.insert(
        "rule".to_string(),
        serde_json::json!(format!("{} {}", req.action, target)),
    );
    body.insert("detail".to_string(), serde_json::json!(reason));
    body.insert("layer".to_string(), serde_json::json!("l7"));
    body.insert("protocol".to_string(), serde_json::json!("rest"));
    body.insert("method".to_string(), serde_json::json!(req.action));
    body.insert("path".to_string(), serde_json::json!(target));
    if let Some(host) = host {
        body.insert("host".to_string(), serde_json::json!(host));
    }
    if let Some(port) = context.port {
        body.insert("port".to_string(), serde_json::json!(port));
    }
    if let Some(binary) = binary {
        body.insert("binary".to_string(), serde_json::json!(binary));
    }
    body.insert(
        "rule_missing".to_string(),
        serde_json::Value::Object(rule_missing),
    );
    // `next_steps` is generated by the policy_local module so the wire URLs
    // and the on-disk skill path stay in sync with the route table. Adding
    // or renaming a route only requires touching the constants in that
    // module; this side picks up the change automatically.
    body.insert(
        "next_steps".to_string(),
        crate::policy_local::agent_next_steps(),
    );

    serde_json::Value::Object(body)
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

/// Parse Content-Length or Transfer-Encoding from HTTP headers.
///
/// Per RFC 7230 Section 3.3.3, rejects requests containing both
/// `Content-Length` and `Transfer-Encoding` headers to prevent request
/// smuggling via CL/TE ambiguity.
pub(crate) fn parse_body_length(headers: &str) -> Result<BodyLength> {
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
            if let Some(prev) = cl_value
                && prev != len
            {
                return Err(miette!(
                    "Request contains multiple Content-Length headers with differing values ({prev} vs {len})"
                ));
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
async fn relay_fixed<R, W>(
    reader: &mut R,
    writer: &mut W,
    len: u64,
    generation_guard: Option<&PolicyGenerationGuard>,
) -> Result<()>
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
        if let Some(guard) = generation_guard {
            guard.ensure_current()?;
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
async fn relay_chunked<R, W>(
    reader: &mut R,
    writer: &mut W,
    already_forwarded: &[u8],
    generation_guard: Option<&PolicyGenerationGuard>,
) -> Result<()>
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
            if let Some(guard) = generation_guard {
                guard.ensure_current()?;
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
                    if let Some(guard) = generation_guard {
                        guard.ensure_current()?;
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
            if let Some(guard) = generation_guard {
                guard.ensure_current()?;
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

#[derive(Clone)]
struct RelayResponseOptions {
    websocket_extensions: WebSocketExtensionMode,
    client_requested_upgrade: bool,
    websocket: Option<WebSocketResponseValidation>,
}

impl Default for RelayResponseOptions {
    fn default() -> Self {
        Self {
            websocket_extensions: WebSocketExtensionMode::Preserve,
            client_requested_upgrade: true,
            websocket: None,
        }
    }
}

async fn relay_response<U, C>(
    request_method: &str,
    upstream: &mut U,
    client: &mut C,
    options: RelayResponseOptions,
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
        if !options.client_requested_upgrade {
            return Ok(RelayOutcome::Consumed);
        }
        let websocket_permessage_deflate = validate_websocket_response(
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
        });
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

fn validate_websocket_response(
    headers: &str,
    mode: WebSocketExtensionMode,
    websocket: Option<&WebSocketResponseValidation>,
) -> Result<bool> {
    let Some(validation) = websocket else {
        return validate_websocket_response_extensions_preserved(headers, mode);
    };

    let mut upgrade_websocket = false;
    let mut connection_upgrade = false;
    let mut accept_count = 0usize;
    let mut accept_matches = false;
    let mut subprotocol_count = 0usize;
    let mut selected_subprotocol = None;

    for line in headers.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "upgrade" if header_value_contains_token(value, "websocket") => {
                upgrade_websocket = true;
            }
            "connection" if header_value_contains_token(value, "upgrade") => {
                connection_upgrade = true;
            }
            "sec-websocket-accept" => {
                accept_count += 1;
                accept_matches = value == validation.expected_accept;
            }
            "sec-websocket-protocol" => {
                subprotocol_count += 1;
                if !is_http_token(value) {
                    return Err(miette!(
                        "websocket upgrade response has invalid Sec-WebSocket-Protocol"
                    ));
                }
                selected_subprotocol = Some(value.to_string());
            }
            _ => {}
        }
    }

    if !upgrade_websocket {
        return Err(miette!(
            "websocket upgrade response missing Upgrade: websocket"
        ));
    }
    if !connection_upgrade {
        return Err(miette!(
            "websocket upgrade response missing Connection: Upgrade"
        ));
    }
    if accept_count != 1 || !accept_matches {
        return Err(miette!(
            "websocket upgrade response has invalid Sec-WebSocket-Accept"
        ));
    }
    if subprotocol_count > 1 {
        return Err(miette!(
            "websocket upgrade response has multiple Sec-WebSocket-Protocol headers"
        ));
    }
    if let Some(protocol) = selected_subprotocol
        && !validation
            .offered_subprotocols
            .iter()
            .any(|offered| offered == &protocol)
    {
        return Err(miette!(
            "upstream selected WebSocket subprotocol that was not offered"
        ));
    }

    let actual_extension = normalized_websocket_extension(headers)?;
    match (&validation.expected_extension, actual_extension.as_deref()) {
        (None, Some(_)) => Err(miette!(
            "upstream negotiated WebSocket extension that was not offered"
        )),
        (None | Some(_), None) => Ok(false),
        (Some(expected), Some(actual)) if expected.eq_ignore_ascii_case(actual) => Ok(true),
        (Some(_), Some(_)) => Err(miette!(
            "upstream negotiated WebSocket extension that does not match the safe offer"
        )),
    }
}

fn validate_websocket_response_extensions_preserved(
    headers: &str,
    mode: WebSocketExtensionMode,
) -> Result<bool> {
    match mode {
        WebSocketExtensionMode::Preserve => Ok(false),
        WebSocketExtensionMode::PermessageDeflate => {
            let offers = websocket_extension_offers(headers)?;
            if offers.is_empty() {
                Ok(false)
            } else {
                Err(miette!(
                    "upstream negotiated WebSocket extension that was not offered"
                ))
            }
        }
    }
}

fn normalized_websocket_extension(headers: &str) -> Result<Option<String>> {
    let offers = websocket_extension_offers(headers)?;
    if offers.is_empty() {
        return Ok(None);
    }
    if offers.len() != 1 {
        return Err(miette!("upstream negotiated multiple WebSocket extensions"));
    }
    let offer = &offers[0];
    if !offer.name.eq_ignore_ascii_case("permessage-deflate") {
        return Err(miette!(
            "upstream negotiated unsupported WebSocket extension"
        ));
    }
    let mut client_no_context_takeover = false;
    let mut server_no_context_takeover = false;
    let mut seen = HashSet::new();
    for param in &offer.params {
        let name = param.name.to_ascii_lowercase();
        if param.value.is_some() || !seen.insert(name.clone()) {
            return Err(miette!(
                "upstream negotiated unsupported permessage-deflate parameter"
            ));
        }
        if name == "client_no_context_takeover" {
            client_no_context_takeover = true;
        } else if name == "server_no_context_takeover" {
            server_no_context_takeover = true;
        } else {
            return Err(miette!(
                "upstream negotiated unsupported permessage-deflate parameter"
            ));
        }
    }
    let mut normalized = String::from("permessage-deflate");
    if client_no_context_takeover {
        normalized.push_str("; client_no_context_takeover");
    }
    if server_no_context_takeover {
        normalized.push_str("; server_no_context_takeover");
    }
    Ok(Some(normalized))
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
#[allow(
    clippy::iter_on_single_items,
    clippy::manual_string_new,
    clippy::collapsible_if,
    clippy::cast_possible_truncation,
    reason = "Test code: test fixtures and explicit value-shape assertions are idiomatic in tests."
)]
mod tests {
    use super::*;
    use crate::opa::OpaEngine;
    use crate::secrets::SecretResolver;
    use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
    use std::sync::Arc;

    const TEST_POLICY: &str = include_str!("../../data/sandbox-policy.rego");
    const VALID_WS_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
    const VALID_WS_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
    const TEXT_OPCODE: u8 = 0x1;

    #[derive(Debug)]
    struct CapturedFrame {
        fin_opcode: u8,
        masked: bool,
        payload: Vec<u8>,
    }

    async fn read_http_header_block<R: AsyncRead + Unpin>(reader: &mut R) -> Vec<u8> {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let mut header = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                reader.read_exact(&mut byte).await.unwrap();
                header.push(byte[0]);
                if header.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            header
        })
        .await
        .expect("HTTP header block should arrive")
    }

    async fn read_websocket_frame<R: AsyncRead + Unpin>(reader: &mut R) -> CapturedFrame {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let mut prefix = [0u8; 2];
            reader.read_exact(&mut prefix).await.unwrap();
            let masked = prefix[1] & 0x80 != 0;
            let mut payload_len = u64::from(prefix[1] & 0x7f);
            if payload_len == 126 {
                let mut extended = [0u8; 2];
                reader.read_exact(&mut extended).await.unwrap();
                payload_len = u64::from(u16::from_be_bytes(extended));
            } else if payload_len == 127 {
                let mut extended = [0u8; 8];
                reader.read_exact(&mut extended).await.unwrap();
                payload_len = u64::from_be_bytes(extended);
            }
            let mut mask_key = [0u8; 4];
            if masked {
                reader.read_exact(&mut mask_key).await.unwrap();
            }
            let payload_len = usize::try_from(payload_len).unwrap();
            let mut payload = vec![0u8; payload_len];
            reader.read_exact(&mut payload).await.unwrap();
            if masked {
                apply_test_mask(&mut payload, mask_key);
            }
            CapturedFrame {
                fin_opcode: prefix[0],
                masked,
                payload,
            }
        })
        .await
        .expect("WebSocket frame should arrive")
    }

    fn masked_frame_with_rsv(opcode: u8, rsv: u8, payload: &[u8]) -> Vec<u8> {
        let mask_key = [0x37, 0xfa, 0x21, 0x3d];
        let mut frame = Vec::new();
        frame.push(0x80 | rsv | opcode);
        write_test_payload_len(&mut frame, 0x80, payload.len());
        frame.extend_from_slice(&mask_key);
        let mut masked = payload.to_vec();
        apply_test_mask(&mut masked, mask_key);
        frame.extend_from_slice(&masked);
        frame
    }

    fn unmasked_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.push(0x80 | opcode);
        write_test_payload_len(&mut frame, 0, payload.len());
        frame.extend_from_slice(payload);
        frame
    }

    fn write_test_payload_len(frame: &mut Vec<u8>, mask_bit: u8, payload_len: usize) {
        if payload_len < 126 {
            frame.push(mask_bit | payload_len as u8);
        } else if u16::try_from(payload_len).is_ok() {
            frame.push(mask_bit | 0x7e);
            frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
        } else {
            frame.push(mask_bit | 0x7f);
            frame.extend_from_slice(&(payload_len as u64).to_be_bytes());
        }
    }

    fn apply_test_mask(payload: &mut [u8], mask_key: [u8; 4]) {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask_key[index % 4];
        }
    }

    fn compress_test_permessage_deflate(payload: &[u8]) -> Vec<u8> {
        let mut compressor = Compress::new(Compression::fast(), false);
        let mut out = Vec::with_capacity(payload.len().saturating_add(128));
        loop {
            let consumed = usize::try_from(compressor.total_in()).unwrap();
            if consumed >= payload.len() {
                break;
            }
            let before_in = compressor.total_in();
            let before_out = compressor.total_out();
            let status = compressor
                .compress_vec(&payload[consumed..], &mut out, FlushCompress::None)
                .unwrap();
            if matches!(status, Status::BufError)
                || (compressor.total_in() == before_in && compressor.total_out() == before_out)
            {
                out.reserve(out.capacity().max(1024));
            }
        }
        loop {
            out.reserve(64);
            let before_out = compressor.total_out();
            compressor
                .compress_vec(&[], &mut out, FlushCompress::Sync)
                .unwrap();
            if out.ends_with(&[0x00, 0x00, 0xff, 0xff]) {
                break;
            }
            if compressor.total_out() == before_out {
                out.reserve(out.capacity().max(1024));
            }
        }
        out.truncate(out.len() - 4);
        out
    }

    fn decompress_test_permessage_deflate(payload: &[u8]) -> Vec<u8> {
        let mut decoder = Decompress::new(false);
        let mut input = Vec::with_capacity(payload.len() + 4);
        input.extend_from_slice(payload);
        input.extend_from_slice(&[0x00, 0x00, 0xff, 0xff]);
        let mut out = Vec::new();
        let mut input_pos = 0usize;
        let mut scratch = [0u8; RELAY_BUF_SIZE];
        loop {
            let before_in = decoder.total_in();
            let before_out = decoder.total_out();
            let status = decoder
                .decompress(&input[input_pos..], &mut scratch, FlushDecompress::Sync)
                .unwrap();
            let read = usize::try_from(decoder.total_in() - before_in).unwrap();
            let written = usize::try_from(decoder.total_out() - before_out).unwrap();
            input_pos += read;
            out.extend_from_slice(&scratch[..written]);
            if matches!(status, Status::StreamEnd) {
                break;
            }
            if input_pos >= input.len() && written < scratch.len() {
                break;
            }
            assert!(
                read != 0 || written != 0,
                "test permessage-deflate decompression did not make progress"
            );
        }
        out
    }

    fn websocket_request(extension: Option<&str>) -> L7Request {
        let mut raw_header = format!(
            "GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {VALID_WS_KEY}\r\n"
        );
        if let Some(extension) = extension {
            raw_header.push_str("Sec-WebSocket-Extensions: ");
            raw_header.push_str(extension);
            raw_header.push_str("\r\n");
        }
        raw_header.push_str("Sec-WebSocket-Version: 13\r\n\r\n");
        L7Request {
            action: "GET".to_string(),
            target: "/ws".to_string(),
            query_params: HashMap::new(),
            raw_header: raw_header.into_bytes(),
            body_length: BodyLength::None,
        }
    }

    async fn run_upgraded_websocket_case(
        request_extension: Option<&'static str>,
        response_extension: Option<&'static str>,
        extension_mode: WebSocketExtensionMode,
        resolver: Option<Arc<SecretResolver>>,
        client_frame: Vec<u8>,
    ) -> (String, CapturedFrame) {
        let (mut proxy_to_upstream, mut upstream_side) = tokio::io::duplex(16384);
        let (mut client_app, mut proxy_to_client) = tokio::io::duplex(16384);
        let req = websocket_request(request_extension);
        let resolver_for_header = resolver.clone();
        let resolver_for_upgrade = resolver.clone();

        let upstream_task = tokio::spawn(async move {
            let forwarded = read_http_header_block(&mut upstream_side).await;
            let forwarded = String::from_utf8(forwarded).unwrap();
            let mut response = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {VALID_WS_ACCEPT}\r\n"
            );
            if let Some(extension) = response_extension {
                response.push_str("Sec-WebSocket-Extensions: ");
                response.push_str(extension);
                response.push_str("\r\n");
            }
            response.push_str("\r\n");
            upstream_side.write_all(response.as_bytes()).await.unwrap();
            upstream_side.flush().await.unwrap();
            let frame = read_websocket_frame(&mut upstream_side).await;
            (forwarded, frame)
        });

        let relay_task = tokio::spawn(async move {
            let outcome = relay_http_request_with_options_guarded(
                &req,
                &mut proxy_to_client,
                &mut proxy_to_upstream,
                RelayRequestOptions {
                    resolver: resolver_for_header.as_deref(),
                    websocket_extensions: extension_mode,
                    ..Default::default()
                },
            )
            .await
            .expect("handshake relay should succeed");
            let RelayOutcome::Upgraded {
                overflow,
                websocket_permessage_deflate,
            } = outcome
            else {
                panic!("expected upgraded relay outcome");
            };
            let credential_rewrite = resolver_for_upgrade.is_some();
            crate::l7::relay::handle_upgrade(
                &mut proxy_to_client,
                &mut proxy_to_upstream,
                overflow,
                "example.com",
                443,
                crate::l7::relay::UpgradeRelayOptions {
                    websocket_request: true,
                    websocket: crate::l7::relay::WebSocketUpgradeBehavior {
                        credential_rewrite,
                        permessage_deflate: websocket_permessage_deflate,
                        ..Default::default()
                    },
                    secret_resolver: resolver_for_upgrade,
                    target: "/ws".to_string(),
                    policy_name: "test-policy".to_string(),
                    ..Default::default()
                },
            )
            .await
        });

        let response = read_http_header_block(&mut client_app).await;
        assert!(
            String::from_utf8_lossy(&response).contains("101 Switching Protocols"),
            "client must receive the upgrade before frame relay starts"
        );
        client_app.write_all(&client_frame).await.unwrap();
        client_app.flush().await.unwrap();

        let result = upstream_task.await.expect("upstream task should complete");
        drop(client_app);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), relay_task).await;
        result
    }

    #[test]
    fn deny_response_body_is_agent_readable_and_redacted() {
        // Agent-readable next_steps is gated on the proposals feature flag.
        let _proposals = crate::test_helpers::ProposalsFlagGuard::set_blocking(true);
        let req = L7Request {
            action: "PUT".to_string(),
            target: "/repos/NVIDIA/OpenShell/contents/README.md?access_token=secret-token"
                .to_string(),
            query_params: HashMap::new(),
            raw_header: Vec::new(),
            body_length: BodyLength::ContentLength(128),
        };

        let body = deny_response_body(
            &req,
            "github-readonly",
            "no matching L7 allow rule",
            Some("/repos/NVIDIA/OpenShell/contents/README.md"),
            Some(DenyResponseContext {
                host: Some("api.github.com"),
                port: Some(443),
                binary: Some("/usr/bin/gh"),
            }),
        );

        assert_eq!(body["error"], "policy_denied");
        assert_eq!(body["policy"], "github-readonly");
        assert_eq!(body["layer"], "l7");
        assert_eq!(body["protocol"], "rest");
        assert_eq!(body["method"], "PUT");
        assert_eq!(body["host"], "api.github.com");
        assert_eq!(body["port"], 443);
        assert_eq!(body["binary"], "/usr/bin/gh");
        assert_eq!(body["path"], "/repos/NVIDIA/OpenShell/contents/README.md");
        assert_eq!(
            body["rule"],
            "PUT /repos/NVIDIA/OpenShell/contents/README.md"
        );
        assert_eq!(body["rule_missing"]["type"], "rest_allow");
        assert_eq!(body["rule_missing"]["layer"], "l7");
        assert_eq!(body["rule_missing"]["method"], "PUT");
        assert_eq!(
            body["rule_missing"]["path"],
            "/repos/NVIDIA/OpenShell/contents/README.md"
        );
        assert_eq!(body["rule_missing"]["host"], "api.github.com");
        assert_eq!(body["rule_missing"]["port"], 443);
        assert_eq!(body["rule_missing"]["binary"], "/usr/bin/gh");
        assert_eq!(body["next_steps"][0]["action"], "read_skill");
        assert_eq!(
            body["next_steps"][0]["path"],
            "/etc/openshell/skills/policy_advisor.md"
        );
        assert_eq!(body["next_steps"][3]["body_type"], "PolicyMergeOperation");
        assert!(
            !body.to_string().contains("secret-token"),
            "deny body must not leak query params or credential values"
        );
    }

    #[tokio::test]
    async fn send_deny_response_writes_structured_json_403() {
        // Agent-readable next_steps is gated on the proposals feature flag.
        let _proposals = crate::test_helpers::ProposalsFlagGuard::set(true).await;
        let (mut client, mut server) = tokio::io::duplex(4096);
        let send = tokio::spawn(async move {
            let req = L7Request {
                action: "POST".to_string(),
                target: "/user/repos".to_string(),
                query_params: HashMap::new(),
                raw_header: Vec::new(),
                body_length: BodyLength::ContentLength(64),
            };
            send_deny_response(
                &req,
                "github-readonly",
                "no matching L7 allow rule",
                &mut server,
                None,
                Some(DenyResponseContext {
                    host: Some("api.github.com"),
                    port: Some(443),
                    binary: Some("/usr/bin/gh"),
                }),
            )
            .await
            .unwrap();
        });

        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        send.await.unwrap();

        let response = String::from_utf8(received).unwrap();
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(response.contains("Content-Type: application/json"));
        assert!(response.contains("X-OpenShell-Policy: github-readonly"));

        let (_, body) = response.split_once("\r\n\r\n").unwrap();
        let body: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(body["error"], "policy_denied");
        assert_eq!(body["method"], "POST");
        assert_eq!(body["path"], "/user/repos");
        assert_eq!(body["rule_missing"]["host"], "api.github.com");
        assert_eq!(body["next_steps"][2]["action"], "inspect_recent_denials");
    }

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
        let result = parse_http_request(
            &mut client,
            &crate::l7::path::CanonicalizeOptions::default(),
        )
        .await;
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
        let result = parse_http_request(
            &mut client,
            &crate::l7::path::CanonicalizeOptions::default(),
        )
        .await;
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
        let result = parse_http_request(
            &mut client,
            &crate::l7::path::CanonicalizeOptions::default(),
        )
        .await;
        assert!(result.is_err(), "Must reject unsupported HTTP version");
    }

    #[tokio::test]
    async fn parse_http_request_canonicalizes_target_and_rewrites_raw_header() {
        let (mut client, mut writer) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            writer
                .write_all(b"GET /public/../secret HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
                .await
                .unwrap();
        });
        let req = parse_http_request(
            &mut client,
            &crate::l7::path::CanonicalizeOptions::default(),
        )
        .await
        .expect("request should parse")
        .expect("request should exist");
        // Path fed to OPA evaluation is canonical.
        assert_eq!(req.target, "/secret");
        // raw_header (forwarded byte-for-byte to upstream) is also canonical
        // — this is the invariant the L7 canonicalization PR must uphold.
        assert_eq!(
            req.raw_header, b"GET /secret HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            "outbound request line must carry the canonical path"
        );
    }

    #[tokio::test]
    async fn parse_http_request_canonicalization_preserves_query_string() {
        let (mut client, mut writer) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            writer
                .write_all(b"GET /public/../v1/list?limit=10&sort=asc HTTP/1.1\r\nHost: h\r\n\r\n")
                .await
                .unwrap();
        });
        let req = parse_http_request(
            &mut client,
            &crate::l7::path::CanonicalizeOptions::default(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(req.target, "/v1/list");
        assert_eq!(
            req.raw_header, b"GET /v1/list?limit=10&sort=asc HTTP/1.1\r\nHost: h\r\n\r\n",
            "canonical rewrite must preserve the query string verbatim"
        );
    }

    #[tokio::test]
    async fn parse_http_request_leaves_canonical_input_byte_for_byte() {
        // When the input is already canonical, the raw_header must pass
        // through unchanged — otherwise legitimate traffic pays a rewrite
        // cost on every request.
        let (mut client, mut writer) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            writer
                .write_all(b"GET /api/v1/users HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
                .await
                .unwrap();
        });
        let req = parse_http_request(
            &mut client,
            &crate::l7::path::CanonicalizeOptions::default(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(req.target, "/api/v1/users");
        assert_eq!(
            req.raw_header,
            b"GET /api/v1/users HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
        );
    }

    #[tokio::test]
    async fn parse_http_request_rejects_traversal_above_root() {
        let (mut client, mut writer) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            writer
                .write_all(b"GET /.. HTTP/1.1\r\nHost: h\r\n\r\n")
                .await
                .unwrap();
        });
        let result = parse_http_request(
            &mut client,
            &crate::l7::path::CanonicalizeOptions::default(),
        )
        .await;
        assert!(
            result.is_err(),
            "a target that escapes the path root must be rejected at the parser"
        );
    }

    #[tokio::test]
    async fn parse_http_request_accepts_encoded_slash_when_endpoint_opts_in() {
        // GitLab-style endpoints legitimately embed `%2F` in path segments
        // (e.g. `/api/v4/projects/group%2Fproject`). Passing a provider
        // constructed with `allow_encoded_slash: true` models the
        // endpoint-config wiring that flows from `L7EndpointConfig`.
        let (mut client, mut writer) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            writer
                .write_all(b"GET /api/v4/projects/group%2Fproject HTTP/1.1\r\nHost: g\r\n\r\n")
                .await
                .unwrap();
        });
        let options = crate::l7::path::CanonicalizeOptions {
            allow_encoded_slash: true,
            ..Default::default()
        };
        let req = parse_http_request(&mut client, &options)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(req.target, "/api/v4/projects/group%2Fproject");
    }

    #[tokio::test]
    async fn parse_http_request_rejects_encoded_slash_by_default() {
        // Default strict options must reject `%2F` — this is the security
        // posture for endpoints where an encoded slash would let an
        // attacker disagree with the upstream on segment boundaries.
        let (mut client, mut writer) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            writer
                .write_all(b"GET /api/v4/projects/group%2Fproject HTTP/1.1\r\nHost: g\r\n\r\n")
                .await
                .unwrap();
        });
        let result = parse_http_request(
            &mut client,
            &crate::l7::path::CanonicalizeOptions::default(),
        )
        .await;
        assert!(
            result.is_err(),
            "default options must reject encoded slashes in the path"
        );
    }

    #[tokio::test]
    async fn parse_http_request_preserves_http_10_version_on_rewrite() {
        let (mut client, mut writer) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            writer
                .write_all(b"GET /a/./b HTTP/1.0\r\nHost: h\r\n\r\n")
                .await
                .unwrap();
        });
        let req = parse_http_request(
            &mut client,
            &crate::l7::path::CanonicalizeOptions::default(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(req.target, "/a/b");
        assert!(
            req.raw_header.starts_with(b"GET /a/b HTTP/1.0\r\n"),
            "rewrite must preserve the original HTTP version, got: {:?}",
            String::from_utf8_lossy(&req.raw_header)
        );
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
        let req = parse_http_request(
            &mut client,
            &crate::l7::path::CanonicalizeOptions::default(),
        )
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

        let first = parse_http_request(
            &mut client,
            &crate::l7::path::CanonicalizeOptions::default(),
        )
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

        let second = parse_http_request(
            &mut client,
            &crate::l7::path::CanonicalizeOptions::default(),
        )
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
            relay_response(
                "GET",
                &mut upstream_read,
                &mut client_write,
                RelayResponseOptions::default(),
            ),
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
            relay_response(
                "GET",
                &mut upstream_read,
                &mut client_write,
                RelayResponseOptions::default(),
            ),
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
            relay_response(
                "HEAD",
                &mut upstream_read,
                &mut client_write,
                RelayResponseOptions::default(),
            ),
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
            relay_response(
                "GET",
                &mut upstream_read,
                &mut client_write,
                RelayResponseOptions::default(),
            ),
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
            relay_response(
                "GET",
                &mut upstream_read,
                &mut client_write,
                RelayResponseOptions::default(),
            ),
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
            relay_response(
                "GET",
                &mut upstream_read,
                &mut client_write,
                RelayResponseOptions::default(),
            ),
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
            relay_response(
                "GET",
                &mut upstream_read,
                &mut client_write,
                RelayResponseOptions::default(),
            ),
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
            relay_response(
                "GET",
                &mut upstream_read,
                &mut client_write,
                RelayResponseOptions::default(),
            ),
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
            relay_response(
                "GET",
                &mut upstream_read,
                &mut client_write,
                RelayResponseOptions::default(),
            ),
        )
        .await
        .expect("relay_response should not deadlock");

        let outcome = result.expect("relay_response should succeed");
        match outcome {
            RelayOutcome::Upgraded { overflow, .. } => {
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
            relay_response(
                "GET",
                &mut upstream_read,
                &mut client_write,
                RelayResponseOptions::default(),
            ),
        )
        .await
        .expect("relay_response should not deadlock");

        match result.expect("should succeed") {
            RelayOutcome::Upgraded { overflow, .. } => {
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

    #[tokio::test]
    async fn opted_in_websocket_relay_rejects_invalid_upgrade_before_upstream_write() {
        let (mut proxy_to_upstream, mut upstream_side) = tokio::io::duplex(8192);
        let (mut _app_side, mut proxy_to_client) = tokio::io::duplex(8192);

        let req = L7Request {
            action: "GET".to_string(),
            target: "/ws".to_string(),
            query_params: HashMap::new(),
            raw_header: b"GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n".to_vec(),
            body_length: BodyLength::None,
        };

        let result = relay_http_request_with_options_guarded(
            &req,
            &mut proxy_to_client,
            &mut proxy_to_upstream,
            RelayRequestOptions {
                websocket_extensions: WebSocketExtensionMode::PermessageDeflate,
                ..Default::default()
            },
        )
        .await;

        assert!(
            result.is_err(),
            "missing Sec-WebSocket-Key must fail closed"
        );
        drop(proxy_to_upstream);
        let mut forwarded = Vec::new();
        upstream_side.read_to_end(&mut forwarded).await.unwrap();
        assert!(
            forwarded.is_empty(),
            "invalid opted-in upgrade must not reach upstream"
        );
    }

    #[tokio::test]
    async fn opted_in_websocket_relay_strips_request_extensions_and_rejects_response_extensions() {
        let (mut proxy_to_upstream, mut upstream_side) = tokio::io::duplex(8192);
        let (mut app_side, mut proxy_to_client) = tokio::io::duplex(8192);

        let req = L7Request {
            action: "GET".to_string(),
            target: "/ws".to_string(),
            query_params: HashMap::new(),
            raw_header: format!(
                "GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {VALID_WS_KEY}\r\nSec-WebSocket-Extensions: permessage-deflate\r\nSec-WebSocket-Version: 13\r\n\r\n"
            )
            .into_bytes(),
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
            let forwarded = String::from_utf8_lossy(&buf[..total]);
            assert!(
                !forwarded
                    .to_ascii_lowercase()
                    .contains("sec-websocket-extensions"),
                "opted-in request must strip extension negotiation"
            );
            upstream_side
                .write_all(
                    format!(
                        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {VALID_WS_ACCEPT}\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            upstream_side.flush().await.unwrap();
        });

        let result = relay_http_request_with_options_guarded(
            &req,
            &mut proxy_to_client,
            &mut proxy_to_upstream,
            RelayRequestOptions {
                websocket_extensions: WebSocketExtensionMode::PermessageDeflate,
                ..Default::default()
            },
        )
        .await;

        let err = result.expect_err("upstream extension negotiation must fail closed");
        assert!(err.to_string().contains("not offered"));
        upstream_task.await.expect("upstream task should complete");

        drop(proxy_to_client);
        let mut received = Vec::new();
        app_side.read_to_end(&mut received).await.unwrap();
        assert!(
            received.is_empty(),
            "rejected extension negotiation must not forward 101 headers"
        );
    }

    #[tokio::test]
    async fn permessage_deflate_mode_allows_supported_no_context_takeover() {
        let (mut proxy_to_upstream, mut upstream_side) = tokio::io::duplex(8192);
        let (mut _app_side, mut proxy_to_client) = tokio::io::duplex(8192);

        let req = L7Request {
            action: "GET".to_string(),
            target: "/ws".to_string(),
            query_params: HashMap::new(),
            raw_header: format!(
                "GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {VALID_WS_KEY}\r\nSec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; server_no_context_takeover\r\nSec-WebSocket-Version: 13\r\n\r\n"
            )
            .into_bytes(),
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
            let forwarded = String::from_utf8_lossy(&buf[..total]).to_ascii_lowercase();
            assert!(forwarded.contains(
                "sec-websocket-extensions: permessage-deflate; client_no_context_takeover; server_no_context_takeover"
            ));
            upstream_side
                .write_all(
                    format!(
                        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {VALID_WS_ACCEPT}\r\nSec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; server_no_context_takeover\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            upstream_side.flush().await.unwrap();
        });

        let outcome = relay_http_request_with_options_guarded(
            &req,
            &mut proxy_to_client,
            &mut proxy_to_upstream,
            RelayRequestOptions {
                websocket_extensions: WebSocketExtensionMode::PermessageDeflate,
                ..Default::default()
            },
        )
        .await
        .expect("safe permessage-deflate negotiation should pass");

        assert!(
            matches!(
                outcome,
                RelayOutcome::Upgraded {
                    websocket_permessage_deflate: true,
                    ..
                }
            ),
            "safe permessage-deflate must be marked negotiated"
        );
        upstream_task.await.expect("upstream task should complete");
    }

    #[tokio::test]
    async fn websocket_conformance_preserve_mode_relays_raw_frames_without_validation() {
        let (forwarded, frame) = run_upgraded_websocket_case(
            None,
            None,
            WebSocketExtensionMode::Preserve,
            None,
            unmasked_frame(TEXT_OPCODE, b"raw-unmasked"),
        )
        .await;

        assert!(
            forwarded.contains("Upgrade: websocket"),
            "raw preserve path should still forward the upgrade request"
        );
        assert!(
            !frame.masked,
            "raw preserve path must not validate or rewrite client frame masking"
        );
        assert_eq!(frame.fin_opcode & 0x0f, TEXT_OPCODE);
        assert_eq!(frame.payload, b"raw-unmasked");
    }

    #[tokio::test]
    async fn websocket_conformance_rewrite_mode_rewrites_text_after_upgrade() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("DISCORD_BOT_TOKEN".to_string(), "real-token".to_string())]
                .into_iter()
                .collect(),
        );
        let placeholder = child_env.get("DISCORD_BOT_TOKEN").unwrap();
        let payload = format!(r#"{{"op":2,"d":{{"token":"{placeholder}"}}}}"#);

        let (forwarded, frame) = run_upgraded_websocket_case(
            None,
            None,
            WebSocketExtensionMode::PermessageDeflate,
            resolver.map(Arc::new),
            masked_frame_with_rsv(TEXT_OPCODE, 0, payload.as_bytes()),
        )
        .await;

        assert!(
            !forwarded
                .to_ascii_lowercase()
                .contains("sec-websocket-extensions"),
            "plain rewrite path should not offer compression when the client did not offer a safe subset"
        );
        assert!(frame.masked, "parsed relay must preserve client masking");
        assert_eq!(frame.fin_opcode & 0x0f, TEXT_OPCODE);
        assert_eq!(
            String::from_utf8(frame.payload).unwrap(),
            r#"{"op":2,"d":{"token":"real-token"}}"#
        );
    }

    #[tokio::test]
    async fn websocket_conformance_deflate_rewrites_compressed_text_after_upgrade() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("DISCORD_BOT_TOKEN".to_string(), "real-token".to_string())]
                .into_iter()
                .collect(),
        );
        let placeholder = child_env.get("DISCORD_BOT_TOKEN").unwrap();
        let payload = format!(r#"{{"op":2,"d":{{"token":"{placeholder}"}}}}"#);
        let compressed = compress_test_permessage_deflate(payload.as_bytes());

        let (forwarded, frame) = run_upgraded_websocket_case(
            Some("permessage-deflate; server_no_context_takeover; client_no_context_takeover"),
            Some("permessage-deflate; server_no_context_takeover; client_no_context_takeover"),
            WebSocketExtensionMode::PermessageDeflate,
            resolver.map(Arc::new),
            masked_frame_with_rsv(TEXT_OPCODE, 0x40, &compressed),
        )
        .await;

        assert!(
            forwarded.to_ascii_lowercase().contains(
                "sec-websocket-extensions: permessage-deflate; client_no_context_takeover; server_no_context_takeover"
            ),
            "safe extension offer should be canonicalized before forwarding"
        );
        assert!(frame.masked, "parsed relay must preserve client masking");
        assert_eq!(frame.fin_opcode & 0x0f, TEXT_OPCODE);
        assert!(
            frame.fin_opcode & 0x40 != 0,
            "rewritten compressed text must retain RSV1"
        );
        assert_eq!(
            String::from_utf8(decompress_test_permessage_deflate(&frame.payload)).unwrap(),
            r#"{"op":2,"d":{"token":"real-token"}}"#
        );
    }

    #[tokio::test]
    async fn opted_in_websocket_relay_rejects_invalid_accept_before_forwarding_101() {
        let (mut proxy_to_upstream, mut upstream_side) = tokio::io::duplex(8192);
        let (mut app_side, mut proxy_to_client) = tokio::io::duplex(8192);

        let req = L7Request {
            action: "GET".to_string(),
            target: "/ws".to_string(),
            query_params: HashMap::new(),
            raw_header: format!(
                "GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {VALID_WS_KEY}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            )
            .into_bytes(),
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
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: invalid\r\n\r\n",
                )
                .await
                .unwrap();
            upstream_side.flush().await.unwrap();
        });

        let result = relay_http_request_with_options_guarded(
            &req,
            &mut proxy_to_client,
            &mut proxy_to_upstream,
            RelayRequestOptions {
                websocket_extensions: WebSocketExtensionMode::PermessageDeflate,
                ..Default::default()
            },
        )
        .await;

        let err = result.expect_err("invalid Sec-WebSocket-Accept must fail closed");
        assert!(err.to_string().contains("Sec-WebSocket-Accept"));
        upstream_task.await.expect("upstream task should complete");

        drop(proxy_to_client);
        let mut received = Vec::new();
        app_side.read_to_end(&mut received).await.unwrap();
        assert!(
            received.is_empty(),
            "invalid websocket response must not forward 101 headers"
        );
    }

    #[test]
    fn websocket_accept_matches_rfc_6455_sample() {
        assert_eq!(websocket_accept_for_key(VALID_WS_KEY), VALID_WS_ACCEPT);
    }

    #[test]
    fn strict_response_validation_rejects_missing_upgrade_headers() {
        let validation = WebSocketResponseValidation {
            expected_accept: VALID_WS_ACCEPT.to_string(),
            expected_extension: None,
            offered_subprotocols: Vec::new(),
        };

        let err = validate_websocket_response(
            "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
            WebSocketExtensionMode::PermessageDeflate,
            Some(&validation),
        )
        .expect_err("missing Upgrade/Connection must fail");

        assert!(err.to_string().contains("Upgrade: websocket"));
    }

    #[test]
    fn permessage_deflate_response_must_match_exact_safe_offer() {
        let validation = WebSocketResponseValidation {
            expected_accept: VALID_WS_ACCEPT.to_string(),
            expected_extension: Some(
                "permessage-deflate; client_no_context_takeover; server_no_context_takeover"
                    .to_string(),
            ),
            offered_subprotocols: Vec::new(),
        };

        let err = validate_websocket_response(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover\r\n\r\n",
            WebSocketExtensionMode::PermessageDeflate,
            Some(&validation),
        )
        .expect_err("extension response must exactly match the safe offer");

        assert!(err.to_string().contains("safe offer"));
    }

    #[test]
    fn permessage_deflate_offer_requires_client_no_context_takeover() {
        let raw = format!(
            "GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {VALID_WS_KEY}\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        assert!(
            supported_permessage_deflate_offer(&raw)
                .expect("valid unsupported extension offer should parse")
                .is_none()
        );
    }

    #[test]
    fn permessage_deflate_offer_canonicalizes_safe_params() {
        let raw = format!(
            "GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {VALID_WS_KEY}\r\nSec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );

        assert_eq!(
            supported_permessage_deflate_offer(&raw)
                .expect("safe extension offer should parse")
                .as_deref(),
            Some("permessage-deflate; client_no_context_takeover; server_no_context_takeover")
        );
    }

    #[test]
    fn permessage_deflate_offer_rejects_duplicate_safe_params() {
        let raw = format!(
            "GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {VALID_WS_KEY}\r\nSec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; client_no_context_takeover\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );

        assert!(
            supported_permessage_deflate_offer(&raw)
                .expect("duplicate safe param should parse but not be supported")
                .is_none()
        );
    }

    #[test]
    fn permessage_deflate_offer_rejects_quoted_values() {
        let raw = format!(
            "GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {VALID_WS_KEY}\r\nSec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover=\"true\"\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );

        let err = supported_permessage_deflate_offer(&raw)
            .expect_err("quoted permessage-deflate parameter values should fail closed");
        assert!(err.to_string().contains("parameter value"));
    }

    #[test]
    fn permessage_deflate_response_accepts_reordered_safe_params() {
        let validation = WebSocketResponseValidation {
            expected_accept: VALID_WS_ACCEPT.to_string(),
            expected_extension: Some(
                "permessage-deflate; client_no_context_takeover; server_no_context_takeover"
                    .to_string(),
            ),
            offered_subprotocols: Vec::new(),
        };

        let negotiated = validate_websocket_response(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n\r\n",
            WebSocketExtensionMode::PermessageDeflate,
            Some(&validation),
        )
        .expect("reordered safe extension params should canonicalize");

        assert!(negotiated);
    }

    #[test]
    fn permessage_deflate_response_rejects_duplicate_safe_params() {
        let validation = WebSocketResponseValidation {
            expected_accept: VALID_WS_ACCEPT.to_string(),
            expected_extension: Some("permessage-deflate; client_no_context_takeover".to_string()),
            offered_subprotocols: Vec::new(),
        };

        let err = validate_websocket_response(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; client_no_context_takeover\r\n\r\n",
            WebSocketExtensionMode::PermessageDeflate,
            Some(&validation),
        )
        .expect_err("duplicate extension params should fail closed");

        assert!(err.to_string().contains("unsupported permessage-deflate"));
    }

    #[test]
    fn preserve_mode_leaves_malformed_extension_response_raw() {
        let negotiated = validate_websocket_response(
            "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover=\"true\"\r\n\r\n",
            WebSocketExtensionMode::Preserve,
            None,
        )
        .expect("preserve mode should not parse or reject raw extension negotiation");

        assert!(!negotiated);
    }

    #[test]
    fn parse_websocket_upgrade_request_tracks_subprotocols() {
        let raw = format!(
            "GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {VALID_WS_KEY}\r\nSec-WebSocket-Protocol: chat, superchat\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );

        let request = parse_websocket_upgrade_request(raw.as_bytes())
            .expect("request should parse")
            .expect("request should be websocket");

        assert_eq!(request.subprotocols, ["chat", "superchat"]);
    }

    #[test]
    fn strict_response_validation_allows_offered_subprotocol() {
        let validation = WebSocketResponseValidation {
            expected_accept: VALID_WS_ACCEPT.to_string(),
            expected_extension: None,
            offered_subprotocols: vec!["chat".to_string(), "superchat".to_string()],
        };

        let negotiated = validate_websocket_response(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: superchat\r\n\r\n",
            WebSocketExtensionMode::PermessageDeflate,
            Some(&validation),
        )
        .expect("offered subprotocol should validate");

        assert!(!negotiated);
    }

    #[test]
    fn strict_response_validation_rejects_unoffered_subprotocol() {
        let validation = WebSocketResponseValidation {
            expected_accept: VALID_WS_ACCEPT.to_string(),
            expected_extension: None,
            offered_subprotocols: vec!["chat".to_string()],
        };

        let err = validate_websocket_response(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: admin\r\n\r\n",
            WebSocketExtensionMode::PermessageDeflate,
            Some(&validation),
        )
        .expect_err("unoffered subprotocol should fail closed");

        assert!(err.to_string().contains("subprotocol"));
    }

    #[test]
    fn strict_response_validation_rejects_multiple_subprotocol_headers() {
        let validation = WebSocketResponseValidation {
            expected_accept: VALID_WS_ACCEPT.to_string(),
            expected_extension: None,
            offered_subprotocols: vec!["chat".to_string(), "superchat".to_string()],
        };

        let err = validate_websocket_response(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: chat\r\nSec-WebSocket-Protocol: superchat\r\n\r\n",
            WebSocketExtensionMode::PermessageDeflate,
            Some(&validation),
        )
        .expect_err("multiple selected subprotocols should fail closed");

        assert!(err.to_string().contains("Sec-WebSocket-Protocol"));
    }

    #[tokio::test]
    async fn relay_request_guard_blocks_stale_generation_before_upstream_write() {
        let policy_data = "network_policies: {}\n";
        let engine = OpaEngine::from_strings(TEST_POLICY, policy_data).unwrap();
        let guard = engine
            .generation_guard(engine.current_generation())
            .unwrap();
        engine.reload(TEST_POLICY, policy_data).unwrap();

        let req = L7Request {
            action: "GET".to_string(),
            target: "/api".to_string(),
            query_params: HashMap::new(),
            raw_header: b"GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
            body_length: BodyLength::None,
        };
        let (mut proxy_to_upstream, mut upstream_side) = tokio::io::duplex(8192);
        let (mut _app_side, mut proxy_to_client) = tokio::io::duplex(8192);

        let result = relay_http_request_with_resolver_guarded(
            &req,
            &mut proxy_to_client,
            &mut proxy_to_upstream,
            None,
            Some(&guard),
        )
        .await;
        assert!(
            result.is_err(),
            "stale generation must stop relay before upstream write"
        );

        drop(proxy_to_upstream);
        let mut forwarded = Vec::new();
        upstream_side.read_to_end(&mut forwarded).await.unwrap();
        assert!(
            forwarded.is_empty(),
            "stale request bytes must not reach upstream"
        );
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
    fn request_is_websocket_upgrade_detects_websocket_upgrade() {
        let raw = format!(
            "GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: {VALID_WS_KEY}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        assert!(request_is_websocket_upgrade(raw.as_bytes()));
    }

    #[test]
    fn request_is_websocket_upgrade_rejects_missing_key() {
        let raw = b"GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n";
        assert!(!request_is_websocket_upgrade(raw));
        assert!(validate_websocket_upgrade_request(raw).is_err());
    }

    #[test]
    fn request_is_websocket_upgrade_rejects_wrong_method() {
        let raw = format!(
            "POST /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {VALID_WS_KEY}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        assert!(!request_is_websocket_upgrade(raw.as_bytes()));
        assert!(validate_websocket_upgrade_request(raw.as_bytes()).is_err());
    }

    #[test]
    fn request_is_websocket_upgrade_rejects_wrong_version() {
        let raw = format!(
            "GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {VALID_WS_KEY}\r\nSec-WebSocket-Version: 12\r\n\r\n"
        );
        assert!(!request_is_websocket_upgrade(raw.as_bytes()));
        assert!(validate_websocket_upgrade_request(raw.as_bytes()).is_err());
    }

    #[test]
    fn validate_websocket_upgrade_ignores_plain_rest_request() {
        let raw = b"GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(!request_is_websocket_upgrade(raw));
        assert!(!validate_websocket_upgrade_request(raw).expect("plain request should parse"));
    }

    #[test]
    fn validate_websocket_upgrade_ignores_non_websocket_upgrade() {
        let raw = b"GET /h2c HTTP/1.1\r\nHost: example.com\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n";
        assert!(!request_is_websocket_upgrade(raw));
        assert!(!validate_websocket_upgrade_request(raw).expect("h2c request should parse"));
    }

    #[test]
    fn strip_websocket_extensions_removes_extension_negotiation() {
        let raw = format!(
            "GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {VALID_WS_KEY}\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );

        let (stripped, offered) = rewrite_websocket_extensions_for_mode(
            raw.as_bytes(),
            WebSocketExtensionMode::PermessageDeflate,
            true,
        )
        .expect("strip should succeed");
        assert!(offered.is_none());
        let stripped = String::from_utf8(stripped).unwrap();

        assert!(stripped.contains("Upgrade: websocket\r\n"));
        assert!(stripped.contains("Sec-WebSocket-Key: "));
        assert!(stripped.contains("Sec-WebSocket-Version: 13\r\n"));
        assert!(
            !stripped
                .to_ascii_lowercase()
                .contains("sec-websocket-extensions")
        );
        assert!(stripped.ends_with("\r\n\r\n"));
    }

    #[test]
    fn strip_websocket_extensions_leaves_non_websocket_request_unchanged() {
        let raw = b"GET /api HTTP/1.1\r\nHost: example.com\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n";

        let (stripped, offered) = rewrite_websocket_extensions_for_mode(
            raw,
            WebSocketExtensionMode::PermessageDeflate,
            false,
        )
        .expect("strip should succeed");

        assert!(offered.is_none());
        assert_eq!(stripped, raw);
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

    async fn relay_and_capture_with_options(
        raw_header: Vec<u8>,
        body_length: BodyLength,
        resolver: Option<&SecretResolver>,
        request_body_credential_rewrite: bool,
    ) -> Result<String> {
        let (mut proxy_to_upstream, mut upstream_side) = tokio::io::duplex(8192);
        let (mut _app_side, mut proxy_to_client) = tokio::io::duplex(8192);

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

        let upstream_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let mut total = 0usize;
            let mut header_end = None;
            let mut expected_total = None;
            loop {
                let n = upstream_side.read(&mut buf[total..]).await.unwrap();
                if n == 0 {
                    break;
                }
                total += n;
                if header_end.is_none()
                    && let Some(end) = buf[..total].windows(4).position(|w| w == b"\r\n\r\n")
                {
                    let end = end + 4;
                    let headers = String::from_utf8_lossy(&buf[..end]);
                    let len = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    header_end = Some(end);
                    expected_total = Some(end + len);
                }
                if expected_total.is_some_and(|expected| total >= expected) {
                    break;
                }
            }
            upstream_side
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            upstream_side.flush().await.unwrap();
            String::from_utf8_lossy(&buf[..total]).to_string()
        });

        relay_http_request_with_options_guarded(
            &req,
            &mut proxy_to_client,
            &mut proxy_to_upstream,
            RelayRequestOptions {
                resolver,
                request_body_credential_rewrite,
                ..Default::default()
            },
        )
        .await?;

        upstream_task
            .await
            .map_err(|e| miette!("upstream task failed: {e}"))
    }

    #[tokio::test]
    async fn relay_request_body_rewrites_provider_alias_header_and_urlencoded_token() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("API_TOKEN".to_string(), "provider-real-token".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");
        let alias = "provider.v1-OPENSHELL-RESOLVE-ENV-API_TOKEN";
        let body = format!("token={alias}&channel=C123");
        let raw = format!(
            "POST /api/messages HTTP/1.1\r\n\
             Host: api.example.com\r\n\
             Authorization: Bearer {alias}\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );

        let forwarded = relay_and_capture_with_options(
            raw.into_bytes(),
            BodyLength::ContentLength(body.len() as u64),
            Some(&resolver),
            true,
        )
        .await
        .expect("relay should succeed");

        let expected_body = "token=provider-real-token&channel=C123";
        assert!(forwarded.contains("Authorization: Bearer provider-real-token\r\n"));
        assert!(forwarded.contains(&format!("Content-Length: {}\r\n", expected_body.len())));
        assert!(forwarded.ends_with(expected_body));
        assert!(!forwarded.contains("OPENSHELL-RESOLVE-ENV"));
    }

    #[tokio::test]
    async fn relay_request_body_rewrites_percent_encoded_canonical_urlencoded_token() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("API_TOKEN".to_string(), "provider-real-token".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");
        let body = "token=openshell%3Aresolve%3Aenv%3AAPI_TOKEN&note=hello+world";
        let raw = format!(
            "POST /api/messages HTTP/1.1\r\n\
             Host: api.example.com\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );

        let forwarded = relay_and_capture_with_options(
            raw.into_bytes(),
            BodyLength::ContentLength(body.len() as u64),
            Some(&resolver),
            true,
        )
        .await
        .expect("relay should succeed");

        let expected_body = "token=provider-real-token&note=hello+world";
        assert!(forwarded.contains(&format!("Content-Length: {}\r\n", expected_body.len())));
        assert!(forwarded.ends_with(expected_body));
        assert!(!forwarded.contains("openshell%3Aresolve%3Aenv%3AAPI_TOKEN"));
        assert!(!forwarded.contains("openshell:resolve:env:API_TOKEN"));
    }

    #[tokio::test]
    async fn relay_request_body_unresolved_alias_fails_before_upstream_write() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("API_TOKEN".to_string(), "provider-real-token".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");
        let body = "token=provider-OPENSHELL-RESOLVE-ENV-APP_TOKEN";
        let raw = format!(
            "POST /api/connections.open HTTP/1.1\r\n\
             Host: api.example.com\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let req = L7Request {
            action: "POST".to_string(),
            target: "/api/connections.open".to_string(),
            query_params: HashMap::new(),
            raw_header: raw.into_bytes(),
            body_length: BodyLength::ContentLength(body.len() as u64),
        };
        let (mut proxy_to_upstream, mut upstream_side) = tokio::io::duplex(8192);
        let (mut _app_side, mut proxy_to_client) = tokio::io::duplex(8192);

        let err = relay_http_request_with_options_guarded(
            &req,
            &mut proxy_to_client,
            &mut proxy_to_upstream,
            RelayRequestOptions {
                resolver: Some(&resolver),
                request_body_credential_rewrite: true,
                ..Default::default()
            },
        )
        .await
        .expect_err("unknown body alias should fail closed");

        assert!(!err.to_string().contains("provider-real-token"));
        drop(proxy_to_upstream);
        let mut forwarded = Vec::new();
        upstream_side.read_to_end(&mut forwarded).await.unwrap();
        assert!(
            forwarded.is_empty(),
            "failed body rewrite must not reach upstream"
        );
    }

    #[tokio::test]
    async fn relay_request_body_unresolved_encoded_canonical_fails_before_upstream_write() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("API_TOKEN".to_string(), "provider-real-token".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");
        let body = "token=openshell%3Aresolve%3Aenv%3AMISSING_TOKEN";
        let raw = format!(
            "POST /api/messages HTTP/1.1\r\n\
             Host: api.example.com\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let req = L7Request {
            action: "POST".to_string(),
            target: "/api/messages".to_string(),
            query_params: HashMap::new(),
            raw_header: raw.into_bytes(),
            body_length: BodyLength::ContentLength(body.len() as u64),
        };
        let (mut proxy_to_upstream, mut upstream_side) = tokio::io::duplex(8192);
        let (mut _app_side, mut proxy_to_client) = tokio::io::duplex(8192);

        let err = relay_http_request_with_options_guarded(
            &req,
            &mut proxy_to_client,
            &mut proxy_to_upstream,
            RelayRequestOptions {
                resolver: Some(&resolver),
                request_body_credential_rewrite: true,
                ..Default::default()
            },
        )
        .await
        .expect_err("unknown encoded body placeholder should fail closed");

        assert!(!err.to_string().contains("provider-real-token"));
        assert!(!err.to_string().contains("MISSING_TOKEN"));
        drop(proxy_to_upstream);
        let mut forwarded = Vec::new();
        upstream_side.read_to_end(&mut forwarded).await.unwrap();
        assert!(
            forwarded.is_empty(),
            "failed body rewrite must not reach upstream"
        );
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
