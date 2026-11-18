// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP requests for [`crate::http`] and the replies it reads.

use std::fmt;
use std::time::Duration;

use crate::probe::{ConnectOutcome, Probe, ReadEnd};

/// An HTTP/1.1 request for [`crate::http`].
///
/// It sends `Host` for the target host and port, `Content-Length` for a body
/// or a method that takes one, and `Connection: close`, unless the request
/// sets those headers itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    /// `GET target`.
    pub fn get(target: impl Into<String>) -> Self {
        Self::new("GET", target)
    }

    /// `method target`. The target is usually a path, such as `/allowed`,
    /// but may be absolute, such as `http://host:port/allowed`.
    pub fn new(method: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            target: target.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Add a header. A header added more than once is sent more than once.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Send `body` with the request.
    #[must_use]
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    pub(crate) fn is_head(&self) -> bool {
        self.method.eq_ignore_ascii_case("HEAD")
    }

    /// The request as bytes on the wire to `host:port`.
    pub(crate) fn encode(&self, host: &str, port: u16) -> Vec<u8> {
        let has = |name: &str| {
            self.headers
                .iter()
                .any(|(header, _)| header.eq_ignore_ascii_case(name))
        };
        let mut head = format!("{} {} HTTP/1.1\r\n", self.method, self.target);
        if !has("Host") {
            if host.contains(':') {
                head.push_str(&format!("Host: [{host}]:{port}\r\n"));
            } else {
                head.push_str(&format!("Host: {host}:{port}\r\n"));
            }
        }
        for (name, value) in &self.headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        let takes_body = ["POST", "PUT", "PATCH"]
            .iter()
            .any(|method| self.method.eq_ignore_ascii_case(method));
        if (takes_body || !self.body.is_empty())
            && !has("Content-Length")
            && !has("Transfer-Encoding")
        {
            head.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        }
        if !has("Connection") {
            head.push_str("Connection: close\r\n");
        }
        head.push_str("\r\n");
        let mut bytes = head.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }
}

/// The result of [`crate::http`] or [`crate::http_raw`].
#[derive(Clone, PartialEq, Eq)]
pub struct Http {
    pub connect: ConnectOutcome,
    /// How long the connect took.
    pub elapsed: Duration,
    /// How reading the reply ended, or none if the connect failed.
    pub read_end: Option<ReadEnd>,
    /// Every byte that came back.
    pub received: Vec<u8>,
    /// The reply parsed as an HTTP response, or none if nothing came back or
    /// it isn't one. Only the first response is parsed.
    pub response: Option<Response>,
}

impl Http {
    pub(crate) fn from_probe(probe: Probe, head: bool) -> Self {
        let response = parse_response(&probe.received, head);
        Self {
            connect: probe.connect,
            elapsed: probe.connect_elapsed,
            read_end: probe.read_end,
            received: probe.received,
            response,
        }
    }

    /// The response's status, if one came back.
    pub fn status(&self) -> Option<u16> {
        self.response.as_ref().map(|response| response.status)
    }

    /// [`Http::received`] as text, with invalid UTF-8 replaced.
    pub fn received_text(&self) -> String {
        String::from_utf8_lossy(&self.received).into_owned()
    }
}

impl fmt::Debug for Http {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Http")
            .field("connect", &self.connect)
            .field("elapsed", &self.elapsed)
            .field("read_end", &self.read_end)
            .field("received", &self.received_text())
            .field("response", &self.response)
            .finish()
    }
}

/// An HTTP response.
#[derive(Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    /// The headers, in order, as they arrived.
    pub headers: Vec<(String, String)>,
    /// The body, with chunked transfer encoding removed.
    pub body: Vec<u8>,
}

impl Response {
    /// The first header named `name`, ignoring case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The body as text, with invalid UTF-8 replaced.
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("body", &self.body_text())
            .finish()
    }
}

/// The first HTTP response in `bytes`, or none if they don't start with a
/// complete status line and headers. `head` says the request was `HEAD`, so
/// the response has no body.
///
/// The body ends where chunked encoding or `Content-Length` says, or at the
/// end of `bytes` without either. A truncated body is returned as far as it
/// arrived.
fn parse_response(bytes: &[u8], head: bool) -> Option<Response> {
    let end = find(bytes, b"\r\n\r\n")?;
    let text = std::str::from_utf8(&bytes[..end]).ok()?;
    let mut lines = text.split("\r\n");
    let status = parse_status_line(lines.next()?)?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_string(), value.trim().to_string()))
        })
        .collect();
    let rest = &bytes[end + 4..];
    let mut response = Response {
        status,
        headers,
        body: Vec::new(),
    };
    let bodiless = head || (100..200).contains(&status) || status == 204 || status == 304;
    if !bodiless {
        response.body = if response
            .header("Transfer-Encoding")
            .is_some_and(|encoding| encoding.to_ascii_lowercase().contains("chunked"))
        {
            dechunk(rest)
        } else if let Some(length) = response
            .header("Content-Length")
            .and_then(|length| length.parse::<usize>().ok())
        {
            rest[..length.min(rest.len())].to_vec()
        } else {
            rest.to_vec()
        };
    }
    Some(response)
}

/// The status code in `HTTP/1.x NNN reason`.
fn parse_status_line(line: &str) -> Option<u16> {
    let mut parts = line.splitn(3, ' ');
    let version = parts.next()?;
    let code = parts.next()?;
    if !version.starts_with("HTTP/1.") || code.len() != 3 {
        return None;
    }
    code.parse().ok()
}

/// The data in a chunked body, up to the last complete chunk if it is cut
/// short.
fn dechunk(mut rest: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    while let Some(line_end) = find(rest, b"\r\n") {
        let size_line = String::from_utf8_lossy(&rest[..line_end]);
        let size = size_line.split(';').next().unwrap_or_default().trim();
        let Ok(size) = usize::from_str_radix(size, 16) else {
            break;
        };
        rest = &rest[line_end + 2..];
        if size == 0 {
            break;
        }
        let available = size.min(rest.len());
        body.extend_from_slice(&rest[..available]);
        if available < size {
            break;
        }
        rest = rest.get(size + 2..).unwrap_or_default();
    }
    body
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(bytes: &[u8]) -> &str {
        std::str::from_utf8(bytes).expect("UTF-8")
    }

    #[test]
    fn a_get_asks_the_server_to_close() {
        let request = Request::get("/allowed").encode("host.openshell.internal", 8080);
        assert_eq!(
            text(&request),
            "GET /allowed HTTP/1.1\r\nHost: host.openshell.internal:8080\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn a_post_sends_its_length_and_body() {
        let request = Request::new("POST", "/token")
            .header("Content-Type", "text/plain")
            .body("secret")
            .encode("10.0.0.1", 80);
        assert_eq!(
            text(&request),
            "POST /token HTTP/1.1\r\nHost: 10.0.0.1:80\r\nContent-Type: text/plain\r\n\
             Content-Length: 6\r\nConnection: close\r\n\r\nsecret"
        );
        let empty = Request::new("post", "/").encode("h", 1);
        assert!(text(&empty).contains("Content-Length: 0\r\n"));
    }

    #[test]
    fn headers_the_request_sets_replace_the_defaults() {
        let request = Request::get("http://h:1/x")
            .header("host", "other")
            .header("connection", "keep-alive")
            .encode("h", 1);
        assert_eq!(
            text(&request),
            "GET http://h:1/x HTTP/1.1\r\nhost: other\r\nconnection: keep-alive\r\n\r\n"
        );
        let chunked = Request::new("POST", "/")
            .header("Transfer-Encoding", "chunked")
            .body("0\r\n\r\n")
            .encode("h", 1);
        assert!(!text(&chunked).contains("Content-Length"));
    }

    #[test]
    fn an_ipv6_host_is_bracketed() {
        let request = Request::get("/").encode("::1", 80);
        assert!(text(&request).contains("Host: [::1]:80\r\n"));
    }

    #[test]
    fn a_response_with_content_length() {
        let response = parse_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\ncontent-length: 5\r\n\r\nhello extra",
            false,
        )
        .expect("a response");
        assert_eq!(response.status, 200);
        assert_eq!(response.header("Content-Type"), Some("text/plain"));
        assert_eq!(response.header("CONTENT-LENGTH"), Some("5"));
        assert_eq!(response.body, b"hello");
    }

    #[test]
    fn a_response_without_content_length_reads_to_the_end() {
        let response =
            parse_response(b"HTTP/1.0 200 OK\r\n\r\nall of it", false).expect("a response");
        assert_eq!(response.body, b"all of it");
    }

    #[test]
    fn a_chunked_response_is_decoded() {
        let response = parse_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
            false,
        )
        .expect("a response");
        assert_eq!(response.body, b"hello world");
    }

    #[test]
    fn a_truncated_body_is_kept_as_far_as_it_arrived() {
        let chunked = parse_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\na\r\nworl",
            false,
        )
        .expect("a response");
        assert_eq!(chunked.body, b"helloworl");
        let sized = parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhel", false)
            .expect("a response");
        assert_eq!(sized.body, b"hel");
    }

    #[test]
    fn proxy_denials_without_a_body() {
        let empty = parse_response(
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
            false,
        )
        .expect("a response");
        assert_eq!(empty.status, 403);
        assert!(empty.body.is_empty());
        let closed =
            parse_response(b"HTTP/1.1 502 Bad Gateway\r\n\r\n", false).expect("a response");
        assert_eq!(closed.status, 502);
        assert!(closed.body.is_empty());
    }

    #[test]
    fn bodiless_statuses_and_head_have_no_body() {
        for status in [
            "101 Switching Protocols",
            "204 No Content",
            "304 Not Modified",
        ] {
            let bytes = format!("HTTP/1.1 {status}\r\nContent-Length: 4\r\n\r\nnext");
            let response = parse_response(bytes.as_bytes(), false).expect("a response");
            assert!(response.body.is_empty(), "{status}");
        }
        let head = parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n", true)
            .expect("a response");
        assert!(head.body.is_empty());
    }

    #[test]
    fn non_http_or_incomplete_bytes_are_not_a_response() {
        assert_eq!(parse_response(b"", false), None);
        assert_eq!(parse_response(b"HTTP/1.1 200 OK\r\nContent-", false), None);
        assert_eq!(
            parse_response(b"\x00\xff\x13\x37not-http\r\n\r\n", false),
            None
        );
        assert_eq!(parse_response(b"SSH-2.0-OpenSSH\r\n\r\n", false), None);
        assert_eq!(parse_response(b"HTTP/1.1 20 OK\r\n\r\n", false), None);
        assert_eq!(parse_response(b"HTTP/2 200\r\n\r\n", false), None);
    }

    #[test]
    fn http_parses_what_the_probe_received() {
        let probe = Probe {
            connect: ConnectOutcome::Connected,
            connect_elapsed: Duration::from_millis(3),
            read_end: Some(ReadEnd::Closed),
            received: b"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nno".to_vec(),
        };
        let http = Http::from_probe(probe, false);
        assert_eq!(http.status(), Some(403));
        assert_eq!(
            http.response.as_ref().expect("a response").body_text(),
            "no"
        );
        assert!(http.received_text().starts_with("HTTP/1.1 403"));

        let reset = Http::from_probe(
            Probe {
                connect: ConnectOutcome::Connected,
                connect_elapsed: Duration::ZERO,
                read_end: Some(ReadEnd::Reset),
                received: Vec::new(),
            },
            false,
        );
        assert_eq!(reset.status(), None);
        assert_eq!(reset.read_end, Some(ReadEnd::Reset));
    }
}
