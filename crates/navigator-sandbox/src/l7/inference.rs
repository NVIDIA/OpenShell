// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Inference API pattern detection and gateway rerouting.
//!
//! When the proxy intercepts a connection (action = `InspectForInference`),
//! this module detects whether the HTTP request is a known inference API call
//! and reroutes it through the gateway's `ProxyInference` gRPC endpoint
//! instead of forwarding to the original upstream.

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
    patterns
        .iter()
        .find(|p| method.eq_ignore_ascii_case(&p.method) && path_only == p.path_glob)
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
    let mut is_chunked = false;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_string();
            let value = value.trim().to_string();
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().unwrap_or(0);
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

/// Parse an HTTP chunked body from `buf[start..]`.
///
/// Returns `(decoded_body, total_consumed_bytes_from_buf_start)` when complete,
/// or `None` if more bytes are needed.
fn parse_chunked_body(buf: &[u8], start: usize) -> Option<(Vec<u8>, usize)> {
    let mut pos = start;
    let mut body = Vec::new();

    loop {
        let size_line_end = find_crlf(buf, pos)?;
        let size_line = std::str::from_utf8(&buf[pos..size_line_end]).ok()?;
        let size_token = size_line.split(';').next()?.trim();
        let chunk_size = usize::from_str_radix(size_token, 16).ok()?;
        pos = size_line_end + 2;

        if chunk_size == 0 {
            // Parse trailers (if any). Terminates on empty trailer line.
            loop {
                let trailer_end = find_crlf(buf, pos)?;
                let trailer_line = &buf[pos..trailer_end];
                pos = trailer_end + 2;
                if trailer_line.is_empty() {
                    return Some((body, pos));
                }
            }
        }

        let chunk_end = pos.checked_add(chunk_size)?;
        if buf.len() < chunk_end + 2 {
            return None;
        }
        if &buf[chunk_end..chunk_end + 2] != b"\r\n" {
            return None;
        }

        body.extend_from_slice(&buf[pos..chunk_end]);
        pos = chunk_end + 2;
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
    fn no_match_for_unknown_path() {
        let patterns = default_patterns();
        let result = detect_inference_pattern("POST", "/v1/models", &patterns);
        assert!(result.is_none());
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
}
