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
    /// The body, with chunked transfer encoding removed. A body cut short is
    /// returned as far as it arrived; [`Http::read_end`] says why reading
    /// stopped.
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
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut headers);
    let httparse::Status::Complete(end) = parsed.parse(bytes).ok()? else {
        return None;
    };
    let status = parsed.code?;
    let headers = parsed
        .headers
        .iter()
        .map(|header| {
            let value = String::from_utf8_lossy(header.value).into_owned();
            (header.name.to_string(), value)
        })
        .collect();
    let rest = &bytes[end..];
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

/// The data in a chunked body, up to the last complete chunk if it is cut
/// short.
fn dechunk(mut rest: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    while let Ok(httparse::Status::Complete((start, size))) = httparse::parse_chunk_size(rest) {
        let size = usize::try_from(size).unwrap_or(usize::MAX);
        rest = &rest[start..];
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
