// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Inference API pattern detection and gateway rerouting.
//!
//! For requests targeting `inference.local`, this module detects whether the
//! HTTP request is a known inference API call and routes it through the local
//! sandbox router.

/// An inference API pattern for detecting inference calls in intercepted traffic.
#[derive(Debug, Clone)]
pub struct InferenceApiPattern {
    pub method: String,
    pub path_glob: String,
    pub protocol: String,
    pub kind: String,
}

/// Default patterns for known inference APIs (`OpenAI`, Anthropic).
pub fn default_patterns() -> Vec<InferenceApiPattern> {
    vec![
        InferenceApiPattern {
            method: "POST".to_string(),
            path_glob: "/v1/chat/completions".to_string(),
            protocol: "openai_chat_completions".to_string(),
            kind: "chat_completion".to_string(),
        },
        InferenceApiPattern {
            method: "POST".to_string(),
            path_glob: "/v1/completions".to_string(),
            protocol: "openai_completions".to_string(),
            kind: "completion".to_string(),
        },
        InferenceApiPattern {
            method: "POST".to_string(),
            path_glob: "/v1/responses".to_string(),
            protocol: "openai_responses".to_string(),
            kind: "responses".to_string(),
        },
        InferenceApiPattern {
            method: "POST".to_string(),
            path_glob: "/v1/messages".to_string(),
            protocol: "anthropic_messages".to_string(),
            kind: "messages".to_string(),
        },
        InferenceApiPattern {
            method: "GET".to_string(),
            path_glob: "/v1/models".to_string(),
            protocol: "model_discovery".to_string(),
            kind: "models_list".to_string(),
        },
        InferenceApiPattern {
            method: "GET".to_string(),
            path_glob: "/v1/models/*".to_string(),
            protocol: "model_discovery".to_string(),
            kind: "models_get".to_string(),
        },
    ]
}

/// Check if an HTTP request matches a known inference API pattern.
pub fn detect_inference_pattern<'a>(
    method: &str,
    path: &str,
    patterns: &'a [InferenceApiPattern],
) -> Option<&'a InferenceApiPattern> {
    // Strip query string for matching
    let path_only = path.split('?').next().unwrap_or(path);
    patterns.iter().find(|p| {
        if !method.eq_ignore_ascii_case(&p.method) {
            return false;
        }

        if let Some(prefix) = p.path_glob.strip_suffix("/*") {
            return path_only == prefix
                || path_only
                    .strip_prefix(prefix)
                    .is_some_and(|suffix| suffix.starts_with('/'));
        }

        path_only == p.path_glob
    })
}

/// A parsed HTTP request from the intercepted tunnel.
pub struct ParsedHttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Result of attempting to parse an HTTP request from a buffer.
pub enum ParseResult {
    /// A complete request was parsed, along with the byte count consumed.
    Complete(ParsedHttpRequest, usize),
    /// Headers are incomplete — caller should read more data.
    Incomplete,
    /// The request is malformed and must be rejected (e.g., duplicate Content-Length).
    Invalid(String),
}

/// Try to parse an HTTP/1.1 request from raw bytes.
///
/// Returns [`ParseResult::Complete`] with the parsed request and bytes consumed,
/// or [`ParseResult::Incomplete`] if more data is needed.
pub fn try_parse_http_request(buf: &[u8]) -> ParseResult {
    let Some(header_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return ParseResult::Incomplete;
    };
    let headers_bytes = &buf[..header_end];
    let Ok(header_str) = std::str::from_utf8(headers_bytes) else {
        return ParseResult::Incomplete;
    };
    let body_start = header_end + 4;

    let mut lines = header_str.split("\r\n");
    let Some(request_line) = lines.next() else {
        return ParseResult::Incomplete;
    };
    let mut parts = request_line.split_whitespace();
    let (Some(method), Some(path)) = (parts.next(), parts.next()) else {
        return ParseResult::Incomplete;
    };
    let method = method.to_string();
    let path = path.to_string();

    let mut headers = Vec::new();
    let mut content_length: usize = 0;
    let mut has_content_length = false;
    let mut is_chunked = false;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_string();
            let value = value.trim().to_string();
            if name.eq_ignore_ascii_case("content-length") {
                let new_len: usize = match value.parse() {
                    Ok(v) => v,
                    Err(_) => {
                        return ParseResult::Invalid(format!(
                            "invalid Content-Length value: {value}"
                        ));
                    }
                };
                if has_content_length && new_len != content_length {
                    return ParseResult::Invalid(format!(
                        "duplicate Content-Length headers with differing values ({content_length} vs {new_len})"
                    ));
                }
                content_length = new_len;
                has_content_length = true;
            }
            if name.eq_ignore_ascii_case("transfer-encoding")
                && value
                    .split(',')
                    .any(|enc| enc.trim().eq_ignore_ascii_case("chunked"))
            {
                is_chunked = true;
            }
            headers.push((name, value));
        }
    }

    if is_chunked && has_content_length {
        return ParseResult::Invalid(
            "Request contains both Transfer-Encoding and Content-Length headers".to_string(),
        );
    }

    let (body, consumed) = if is_chunked {
        let Some((decoded_body, consumed)) = parse_chunked_body(buf, body_start) else {
            return ParseResult::Incomplete;
        };
        (decoded_body, consumed)
    } else {
        let total_len = body_start + content_length;
        if buf.len() < total_len {
            return ParseResult::Incomplete;
        }
        (buf[body_start..total_len].to_vec(), total_len)
    };

    ParseResult::Complete(
        ParsedHttpRequest {
            method,
            path,
            headers,
            body,
        },
        consumed,
    )
}

/// Maximum decoded body size from chunked transfer encoding (10 MiB).
/// Matches the caller's `MAX_INFERENCE_BUF` limit.
const MAX_CHUNKED_BODY: usize = 10 * 1024 * 1024;

/// Maximum number of chunks to process.  Normal HTTP clients send the body
/// in a handful of large chunks; thousands of tiny chunks indicate abuse.
const MAX_CHUNK_COUNT: usize = 4096;

/// Parse an HTTP chunked body from `buf[start..]`.
///
/// Returns `(decoded_body, total_consumed_bytes_from_buf_start)` when complete,
/// or `None` if more bytes are needed or resource limits are exceeded.
fn parse_chunked_body(buf: &[u8], start: usize) -> Option<(Vec<u8>, usize)> {
    let mut pos = start;
    let mut body = Vec::new();
    let mut chunk_count: usize = 0;

    loop {
        chunk_count += 1;
        if chunk_count > MAX_CHUNK_COUNT {
            return None;
        }

        let size_line_end = find_crlf(buf, pos)?;
        let size_line = std::str::from_utf8(&buf[pos..size_line_end]).ok()?;
        let size_token = size_line.split(';').next()?.trim();
        let chunk_size = usize::from_str_radix(size_token, 16).ok()?;
        pos = size_line_end.checked_add(2)?;

        if chunk_size == 0 {
            // Parse trailers (if any). Terminates on empty trailer line.
            loop {
                let trailer_end = find_crlf(buf, pos)?;
                let trailer_line = &buf[pos..trailer_end];
                pos = trailer_end.checked_add(2)?;
                if trailer_line.is_empty() {
                    return Some((body, pos));
                }
            }
        }

        // Early reject: chunk cannot possibly fit in remaining buffer.
        let remaining = buf.len().saturating_sub(pos);
        if chunk_size > remaining {
            return None;
        }

        // Reject if decoded body would exceed size limit.
        if body.len().saturating_add(chunk_size) > MAX_CHUNKED_BODY {
            return None;
        }

        let chunk_end = pos.checked_add(chunk_size)?;
        let chunk_crlf_end = chunk_end.checked_add(2)?;
        if buf.len() < chunk_crlf_end {
            return None;
        }
        if &buf[chunk_end..chunk_crlf_end] != b"\r\n" {
            return None;
        }

        body.extend_from_slice(&buf[pos..chunk_end]);
        pos = chunk_crlf_end;
    }
}

fn find_crlf(buf: &[u8], start: usize) -> Option<usize> {
    buf.get(start..)?
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|offset| start + offset)
}

/// Format an HTTP/1.1 response from status, headers, and body.
pub fn format_http_response(status: u16, headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    use std::fmt::Write;

    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        411 => "Length Required",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "Unknown",
    };

    let mut response = format!("HTTP/1.1 {status} {status_text}\r\n");
    let mut has_content_length = false;
    for (name, value) in headers {
        let _ = write!(response, "{name}: {value}\r\n");
        if name.eq_ignore_ascii_case("content-length") {
            has_content_length = true;
        }
    }
    if !has_content_length {
        let _ = write!(response, "content-length: {}\r\n", body.len());
    }
    response.push_str("\r\n");

    let mut bytes = response.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// Format HTTP/1.1 response headers for a chunked (streaming) response.
///
/// Emits the status line, supplied headers (stripping any `content-length` or
/// `transfer-encoding` the upstream may have sent), and a
/// `transfer-encoding: chunked` header. The body is **not** included — the
/// caller writes chunks separately via [`format_chunk`] and
/// [`format_chunk_terminator`].
pub fn format_http_response_header(status: u16, headers: &[(String, String)]) -> Vec<u8> {
    use std::fmt::Write;

    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        411 => "Length Required",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Unknown",
    };

    let mut response = format!("HTTP/1.1 {status} {status_text}\r\n");
    for (name, value) in headers {
        // Skip framing headers — we always emit chunked TE.
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        let _ = write!(response, "{name}: {value}\r\n");
    }
    let _ = write!(response, "transfer-encoding: chunked\r\n");
    response.push_str("\r\n");
    response.into_bytes()
}

/// Format a single HTTP chunked transfer-encoding segment.
///
/// Returns `<hex-length>\r\n<data>\r\n`.
pub fn format_chunk(data: &[u8]) -> Vec<u8> {
    let mut buf = format!("{:x}\r\n", data.len()).into_bytes();
    buf.extend_from_slice(data);
    buf.extend_from_slice(b"\r\n");
    buf
}

/// The HTTP chunked transfer-encoding terminator: `0\r\n\r\n`.
pub fn format_chunk_terminator() -> &'static [u8] {
    b"0\r\n\r\n"
}

/// Format an SSE error event for injection into a streaming response.
///
/// Sent just before the chunked terminator when the proxy truncates a stream
/// due to timeout, byte limit, or upstream error. Clients parsing SSE events
/// can detect this and surface the error instead of silently losing data.
///
/// The `reason` must NOT contain internal URLs, hostnames, or credentials —
/// the OCSF log captures full detail server-side.
pub fn format_sse_error(reason: &str) -> Vec<u8> {
    // Use serde_json to escape control characters, quotes, and backslashes
    // correctly. A handwritten escape can't safely cover \u0000-\u001F, and
    // an unescaped \n\n in `reason` would split the SSE event into two
    // frames, allowing a malicious upstream to inject a forged event.
    let payload = serde_json::json!({
        "error": {
            "message": reason,
            "type": "proxy_stream_error",
        }
    });
    let mut out = Vec::with_capacity(reason.len() + 64);
    out.extend_from_slice(b"data: ");
    // serde_json::to_writer is infallible for in-memory Vec<u8>.
    serde_json::to_writer(&mut out, &payload).expect("serializing static schema cannot fail");
    out.extend_from_slice(b"\n\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_openai_chat_completions() {
        let patterns = default_patterns();
        let result = detect_inference_pattern("POST", "/v1/chat/completions", &patterns);
        assert!(result.is_some());
        assert_eq!(result.unwrap().protocol, "openai_chat_completions");
    }

    #[test]
    fn detect_openai_responses() {
        let patterns = default_patterns();
        let result = detect_inference_pattern("POST", "/v1/responses", &patterns);
        assert!(result.is_some());
        assert_eq!(result.unwrap().protocol, "openai_responses");
    }

    #[test]
    fn detect_anthropic_messages() {
        let patterns = default_patterns();
        let result = detect_inference_pattern("POST", "/v1/messages", &patterns);
        assert!(result.is_some());
        assert_eq!(result.unwrap().protocol, "anthropic_messages");
    }

    #[test]
    fn detect_with_query_string() {
        let patterns = default_patterns();
        let result =
            detect_inference_pattern("POST", "/v1/chat/completions?stream=true", &patterns);
        assert!(result.is_some());
    }

    #[test]
    fn no_match_for_get() {
        let patterns = default_patterns();
        let result = detect_inference_pattern("GET", "/v1/chat/completions", &patterns);
        assert!(result.is_none());
    }

    #[test]
    fn detect_get_models() {
        let patterns = default_patterns();
        let result = detect_inference_pattern("GET", "/v1/models", &patterns);
        assert!(result.is_some());
        assert_eq!(result.unwrap().protocol, "model_discovery");
    }

    #[test]
    fn detect_get_model_details() {
        let patterns = default_patterns();
        let result = detect_inference_pattern("GET", "/v1/models/gpt-4.1", &patterns);
        assert!(result.is_some());
        assert_eq!(result.unwrap().protocol, "model_discovery");
    }

    #[test]
    fn no_match_for_embeddings() {
        let patterns = default_patterns();
        let result = detect_inference_pattern("POST", "/v1/embeddings", &patterns);
        assert!(result.is_none());
    }

    #[test]
    fn parse_simple_post_request() {
        let body = b"{\"hello\":true}";
        let header = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut request = header.into_bytes();
        request.extend_from_slice(body);
        let ParseResult::Complete(parsed, consumed) = try_parse_http_request(&request) else {
            panic!("expected Complete");
        };
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.path, "/v1/chat/completions");
        assert_eq!(parsed.body, body);
        assert_eq!(consumed, request.len());
    }

    #[test]
    fn parse_incomplete_headers() {
        let request = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\n";
        assert!(matches!(
            try_parse_http_request(request),
            ParseResult::Incomplete
        ));
    }

    #[test]
    fn parse_chunked_decodes_body() {
        let request = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nTransfer-Encoding: chunked\r\n\r\nA\r\n{\"a\":true}\r\n0\r\n\r\n";
        let ParseResult::Complete(parsed, consumed) = try_parse_http_request(request) else {
            panic!("expected Complete");
        };
        assert_eq!(parsed.body, br#"{"a":true}"#);
        assert_eq!(consumed, request.len());
    }

    #[test]
    fn parse_chunked_incomplete() {
        let request = b"POST /v1/chat/completions HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\r\n";
        assert!(matches!(
            try_parse_http_request(request),
            ParseResult::Incomplete
        ));
    }

    #[test]
    fn format_response_basic() {
        let body = b"{\"ok\":true}";
        let response = format_http_response(200, &[], body);
        let response_str = String::from_utf8_lossy(&response);
        assert!(response_str.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response_str.contains("content-length: 11\r\n"));
        assert!(response_str.ends_with("{\"ok\":true}"));
    }

    #[test]
    fn format_response_header_chunked() {
        let headers = vec![
            ("content-type".to_string(), "text/event-stream".to_string()),
            ("x-request-id".to_string(), "abc123".to_string()),
        ];
        let header = format_http_response_header(200, &headers);
        let header_str = String::from_utf8_lossy(&header);
        assert!(header_str.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(header_str.contains("content-type: text/event-stream\r\n"));
        assert!(header_str.contains("x-request-id: abc123\r\n"));
        assert!(header_str.contains("transfer-encoding: chunked\r\n"));
        assert!(header_str.ends_with("\r\n"));
        // Must NOT contain content-length
        assert!(!header_str.to_lowercase().contains("content-length"));
    }

    #[test]
    fn format_response_header_strips_upstream_framing() {
        let headers = vec![
            ("content-length".to_string(), "9999".to_string()),
            ("transfer-encoding".to_string(), "chunked".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
        ];
        let header = format_http_response_header(200, &headers);
        let header_str = String::from_utf8_lossy(&header);
        // Should not contain the upstream content-length or transfer-encoding values
        assert!(!header_str.contains("content-length: 9999"));
        // Should contain exactly one transfer-encoding: chunked (ours)
        assert_eq!(header_str.matches("transfer-encoding: chunked").count(), 1);
    }

    #[test]
    fn format_chunk_basic() {
        let data = b"hello";
        let chunk = format_chunk(data);
        assert_eq!(chunk, b"5\r\nhello\r\n");
    }

    #[test]
    fn format_chunk_empty() {
        // Empty chunk is NOT the terminator — it's a zero-length data segment
        let chunk = format_chunk(b"");
        assert_eq!(chunk, b"0\r\n\r\n");
    }

    #[test]
    fn format_chunk_terminator_value() {
        assert_eq!(format_chunk_terminator(), b"0\r\n\r\n");
    }

    #[test]
    fn format_chunk_large_hex() {
        let data = vec![0x41u8; 256]; // 0x100 bytes
        let chunk = format_chunk(&data);
        assert!(chunk.starts_with(b"100\r\n"));
        assert!(chunk.ends_with(b"\r\n"));
        assert_eq!(chunk.len(), 3 + 2 + 256 + 2); // "100" + \r\n + data + \r\n
    }

    // ---- SEC-010: parse_chunked_body resource limits ----

    #[test]
    fn parse_chunked_multi_chunk_body() {
        // Two chunks: 5 bytes + 6 bytes
        let request = b"POST /v1/chat HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let ParseResult::Complete(parsed, _) = try_parse_http_request(request) else {
            panic!("expected Complete");
        };
        assert_eq!(parsed.body, b"hello world");
    }

    #[test]
    fn parse_chunked_rejects_too_many_chunks() {
        // Build a request with MAX_CHUNK_COUNT + 1 tiny chunks
        let mut buf = Vec::new();
        buf.extend_from_slice(b"POST /v1/chat HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n");
        for _ in 0..=MAX_CHUNK_COUNT {
            buf.extend_from_slice(b"1\r\nX\r\n");
        }
        buf.extend_from_slice(b"0\r\n\r\n");
        assert!(matches!(
            try_parse_http_request(&buf),
            ParseResult::Incomplete
        ));
    }

    #[test]
    fn parse_chunked_within_chunk_count_limit() {
        // MAX_CHUNK_COUNT chunks should succeed
        let mut buf = Vec::new();
        buf.extend_from_slice(b"POST /v1/chat HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n");
        for _ in 0..100 {
            buf.extend_from_slice(b"1\r\nX\r\n");
        }
        buf.extend_from_slice(b"0\r\n\r\n");
        let ParseResult::Complete(parsed, _) = try_parse_http_request(&buf) else {
            panic!("expected Complete for 100 chunks");
        };
        assert_eq!(parsed.body.len(), 100);
    }

    /// SEC: Transfer-Encoding substring match must not match partial tokens.
    #[test]
    fn te_substring_not_chunked() {
        let body = r#"{"model":"m","messages":[]}"#;
        let request = format!(
            "POST /v1/chat/completions HTTP/1.1\r\n\
             Host: x\r\n\
             Transfer-Encoding: chunkedx\r\n\
             Content-Length: {}\r\n\
             \r\n{body}",
            body.len(),
        );
        let ParseResult::Complete(parsed, _) = try_parse_http_request(request.as_bytes()) else {
            panic!("expected Complete for non-matching TE with valid CL");
        };
        assert_eq!(parsed.body.len(), body.len());
    }

    // ---- SEC: Content-Length validation ----

    #[test]
    fn reject_differing_duplicate_content_length() {
        let request = b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nContent-Length: 50\r\n\r\n";
        assert!(matches!(
            try_parse_http_request(request),
            ParseResult::Invalid(reason) if reason.contains("differing values")
        ));
    }

    #[test]
    fn accept_identical_duplicate_content_length() {
        let request = b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello";
        let ParseResult::Complete(parsed, _) = try_parse_http_request(request) else {
            panic!("expected Complete for identical duplicate CL");
        };
        assert_eq!(parsed.body, b"hello");
    }

    #[test]
    fn reject_non_numeric_content_length() {
        let request =
            b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\n";
        assert!(matches!(
            try_parse_http_request(request),
            ParseResult::Invalid(reason) if reason.contains("invalid Content-Length")
        ));
    }

    #[test]
    fn reject_two_non_numeric_content_lengths() {
        let request = b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\nContent-Length: def\r\n\r\n";
        assert!(matches!(
            try_parse_http_request(request),
            ParseResult::Invalid(_)
        ));
    }

    // ---- SEC-009: CL/TE desynchronisation ----

    /// Reject requests with both Content-Length and Transfer-Encoding to
    /// prevent CL/TE request smuggling (RFC 7230 Section 3.3.3).
    #[test]
    fn reject_dual_content_length_and_transfer_encoding() {
        let request = b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(
            matches!(
                try_parse_http_request(request),
                ParseResult::Invalid(reason)
                    if reason.contains("Transfer-Encoding")
                        && reason.contains("Content-Length")
            ),
            "Must reject request with both CL and TE"
        );
    }

    /// Same rejection regardless of header order.
    #[test]
    fn reject_dual_transfer_encoding_and_content_length() {
        let request = b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n";
        assert!(
            matches!(
                try_parse_http_request(request),
                ParseResult::Invalid(reason)
                    if reason.contains("Transfer-Encoding")
                        && reason.contains("Content-Length")
            ),
            "Must reject request with both TE and CL"
        );
    }

    #[test]
    fn format_sse_error_produces_valid_sse_json() {
        let output = format_sse_error("chunk idle timeout exceeded");
        let text = std::str::from_utf8(&output).expect("should be valid utf8");

        // Must start with "data: " (SSE format)
        assert!(text.starts_with("data: "), "must be an SSE data line");

        // Must end with double newline (SSE event boundary)
        assert!(text.ends_with("\n\n"), "must end with SSE event boundary");

        // The JSON payload between "data: " and "\n\n" must parse
        let json_str = text.trim_start_matches("data: ").trim_end();
        let parsed: serde_json::Value = serde_json::from_str(json_str).expect("must be valid JSON");

        assert_eq!(parsed["error"]["type"], "proxy_stream_error");
        assert_eq!(parsed["error"]["message"], "chunk idle timeout exceeded");
    }

    #[test]
    fn format_sse_error_escapes_quotes_in_reason() {
        let output = format_sse_error("error: \"bad\" response");
        let text = std::str::from_utf8(&output).unwrap();
        let json_str = text.trim_start_matches("data: ").trim_end();
        let parsed: serde_json::Value =
            serde_json::from_str(json_str).expect("must produce valid JSON with escaped quotes");
        assert_eq!(parsed["error"]["message"], "error: \"bad\" response");
    }

    #[test]
    fn format_sse_error_escapes_control_characters_in_reason() {
        // A future caller passing a dynamic upstream error message (containing
        // \n, \r, or \t — common in connection-reset errors and tracebacks)
        // must still produce parseable SSE JSON.
        let output = format_sse_error("upstream error: connection\nreset\tafter 0 bytes");
        let text = std::str::from_utf8(&output).unwrap();
        let json_str = text.trim_start_matches("data: ").trim_end();
        let parsed: serde_json::Value = serde_json::from_str(json_str)
            .expect("must produce valid JSON when reason contains control characters");
        assert_eq!(
            parsed["error"]["message"],
            "upstream error: connection\nreset\tafter 0 bytes"
        );
    }

    #[test]
    fn format_sse_error_does_not_inject_extra_sse_events() {
        // SSE events are separated by `\n\n`. If the reason string contains
        // `\n\n`, an unescaped formatter would split the single error event
        // into two SSE frames, allowing a malicious upstream to inject a
        // forged event into the client's perceived stream
        // (e.g. a fake tool_call delta).
        let output = format_sse_error(
            "safe prefix\n\ndata: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"id\":\"FORGED\"}]}}]}",
        );
        let text = std::str::from_utf8(&output).unwrap();

        // Exactly one SSE event boundary (the trailing one) — the reason
        // string must not introduce additional `\n\n` sequences.
        let boundary_count = text.matches("\n\n").count();
        assert_eq!(
            boundary_count, 1,
            "format_sse_error must emit exactly one SSE event boundary; \
             reason string must not be able to inject extra events"
        );
    }
}
