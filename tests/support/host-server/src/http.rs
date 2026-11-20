// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};

use testkit::{Poll, Result};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use crate::{MAX_REQUEST, READ_TIMEOUT, Server, WAIT_INTERVAL, WAIT_TIMEOUT, find, header};

/// A request an [`HttpRecorder`] read. A chunked body arrives decoded.
#[derive(Clone, Debug)]
pub struct Request {
    /// The request line and headers.
    pub head: String,
    pub body: String,
    /// The server's address on the connection the request arrived on: the
    /// address of the test host the client reached it by.
    pub local_addr: Option<SocketAddr>,
}

impl Request {
    pub fn method(&self) -> &str {
        self.request_line().0
    }

    /// The request target, such as `/path?query`.
    pub fn path(&self) -> &str {
        self.request_line().1
    }

    /// The value of the first header named `name`, in any case.
    pub fn header(&self, name: &str) -> Option<String> {
        header(&self.head, name)
    }

    fn request_line(&self) -> (&str, &str) {
        let line = self.head.lines().next().unwrap_or_default();
        let mut parts = line.split(' ');
        (
            parts.next().unwrap_or_default(),
            parts.next().unwrap_or_default(),
        )
    }
}

/// A response an [`HttpRecorder`] handler returns. The server adds
/// `Content-Length`, except to an informational response, and `Connection`,
/// unless the handler set one.
#[derive(Clone, Debug)]
pub struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    keep_alive: bool,
}

impl Response {
    /// A response with `status` and no body, that closes the connection.
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
            keep_alive: false,
        }
    }

    /// A `200` response with a `text/plain` body.
    pub fn text(body: impl Into<String>) -> Self {
        Self::new(200)
            .header("Content-Type", "text/plain")
            .body(body.into())
    }

    /// A `200` response with an `application/json` body.
    pub fn json(body: &serde_json::Value) -> Self {
        Self::new(200)
            .header("Content-Type", "application/json")
            .body(body.to_string())
    }

    #[must_use]
    pub fn status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }

    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    #[must_use]
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Keep the connection open for another request, unless the request
    /// asked to close it.
    #[must_use]
    pub fn keep_alive(mut self) -> Self {
        self.keep_alive = true;
        self
    }

    fn encode(&self, close: bool) -> Vec<u8> {
        let mut head = format!("HTTP/1.1 {} {}\r\n", self.status, reason(self.status));
        for (name, value) in &self.headers {
            let _ = write!(head, "{name}: {value}\r\n");
        }
        if self.status >= 200 {
            let _ = write!(head, "Content-Length: {}\r\n", self.body.len());
        }
        if !self
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("connection"))
        {
            let connection = if close { "close" } else { "keep-alive" };
            let _ = write!(head, "Connection: {connection}\r\n");
        }
        head.push_str("\r\n");
        let mut bytes = head.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        101 => "Switching Protocols",
        200 => "OK",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        418 => "I'm a teapot",
        _ => "Status",
    }
}

type Handler = dyn Fn(&Request) -> Response + Send + Sync;

/// An HTTP server that records each request it read and answers it with a
/// handler's response. A connection stays open for another request while
/// the responses keep it alive and the requests don't close it.
pub struct HttpRecorder {
    pub port: u16,
    requests: Arc<Mutex<Vec<Request>>>,
    server: Server,
}

impl HttpRecorder {
    /// Answer every request with `200` and `body`.
    pub async fn start(body: impl Into<String>) -> Result<Self> {
        let body = body.into();
        Self::serve(move |_| Response::text(body.clone())).await
    }

    /// Answer every request with `handler`'s response.
    pub async fn serve(
        handler: impl Fn(&Request) -> Response + Send + Sync + 'static,
    ) -> Result<Self> {
        let handler: Arc<Handler> = Arc::new(handler);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let task_requests = Arc::clone(&requests);
        let server = Server::start(move |stream| {
            respond(stream, Arc::clone(&handler), Arc::clone(&task_requests))
        })
        .await?;
        Ok(Self {
            port: server.port,
            requests,
            server,
        })
    }

    /// The requests the server has read so far.
    pub fn requests(&self) -> Vec<Request> {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The number of connections the server has accepted.
    pub fn connections(&self) -> usize {
        self.server.connections()
    }

    /// The requests the server has read, once there are at least `count`.
    pub async fn wait_for_requests(&self, count: usize) -> Result<Vec<Request>> {
        testkit::poll_until(
            &format!(
                "{count} request(s) at the host server on port {}",
                self.port
            ),
            WAIT_TIMEOUT,
            WAIT_INTERVAL,
            async || {
                let requests = self.requests();
                Ok(if requests.len() >= count {
                    Poll::Ready(requests)
                } else {
                    Poll::Pending(format!("{} request(s)", requests.len()))
                })
            },
        )
        .await
    }
}

/// Read requests, record each, and answer with `handler` until a response
/// or request closes the connection.
async fn respond(mut stream: TcpStream, handler: Arc<Handler>, requests: Arc<Mutex<Vec<Request>>>) {
    let _ = stream.set_nodelay(true);
    let mut buffer = Vec::new();
    while let Some(request) = read_request(&mut stream, &mut buffer).await {
        let response = handler(&request);
        let close = !response.keep_alive
            || request
                .header("connection")
                .is_some_and(|value| value.eq_ignore_ascii_case("close"));
        requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(request);
        if stream.write_all(&response.encode(close)).await.is_err() || close {
            break;
        }
    }
    let _ = stream.shutdown().await;
}

/// Read one request from `stream`, starting with the bytes already in
/// `buffer`, and leave any bytes after it in `buffer`.
pub(crate) async fn read_request(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Option<Request> {
    let mut chunk = [0_u8; 4096];
    loop {
        if let Some((mut request, length)) = parse_request(buffer) {
            buffer.drain(..length);
            request.local_addr = stream.local_addr().ok();
            return Some(request);
        }
        match tokio::time::timeout(READ_TIMEOUT, stream.read(&mut chunk)).await {
            Ok(Ok(read)) if read > 0 && buffer.len() < MAX_REQUEST => {
                buffer.extend_from_slice(&chunk[..read]);
            }
            _ => return None,
        }
    }
}

/// A complete request at the start of `bytes`, and its length.
fn parse_request(bytes: &[u8]) -> Option<(Request, usize)> {
    let end = find(bytes, b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&bytes[..end]).into_owned();
    let rest = &bytes[end + 4..];
    let chunked = header(&head, "transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"));
    let (body, length) = if chunked {
        decode_chunked(rest)?
    } else {
        let length = header(&head, "content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        (rest.get(..length)?.to_vec(), length)
    };
    let body = String::from_utf8_lossy(&body).into_owned();
    Some((
        Request {
            head,
            body,
            local_addr: None,
        },
        end + 4 + length,
    ))
}

/// A complete chunked body at the start of `bytes`, decoded, and its encoded
/// length.
fn decode_chunked(bytes: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut body = Vec::new();
    let mut position = 0;
    loop {
        let line_end = position + find(&bytes[position..], b"\r\n")?;
        let size = std::str::from_utf8(&bytes[position..line_end]).ok()?;
        let size = size.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size, 16).ok()?;
        position = line_end + 2;
        if size == 0 {
            // Skip trailers up to the blank line that ends the body.
            loop {
                let line_end = position + find(&bytes[position..], b"\r\n")?;
                let blank = line_end == position;
                position = line_end + 2;
                if blank {
                    return Some((body, position));
                }
            }
        }
        body.extend_from_slice(bytes.get(position..position + size)?);
        position += size;
        if bytes.get(position..position + 2)? != b"\r\n" {
            return None;
        }
        position += 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn connect(port: u16) -> TcpStream {
        #[allow(
            clippy::disallowed_methods,
            reason = "standalone test support has no openshell-core dependency and enables TCP_NODELAY below"
        )]
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream.set_nodelay(true).unwrap();
        stream
    }

    async fn read_to_end(stream: &mut TcpStream) -> String {
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8_lossy(&response).into_owned()
    }

    #[test]
    fn parse_request_decodes_a_chunked_body_and_leaves_the_next_request() {
        let bytes = b"POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
                      3;ext=1\r\nabc\r\nA\r\n0123456789\r\n0\r\nTrailer: x\r\n\r\nGET /b";
        let (request, length) = parse_request(bytes).unwrap();
        assert_eq!(request.method(), "POST");
        assert_eq!(request.path(), "/a");
        assert_eq!(request.body, "abc0123456789");
        assert_eq!(&bytes[length..], b"GET /b");
    }

    #[test]
    fn parse_request_waits_for_the_whole_body() {
        assert!(parse_request(b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabc").is_none());
        assert!(
            parse_request(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n")
                .is_none()
        );
        let (request, _) =
            parse_request(b"POST / HTTP/1.1\r\ncontent-length: 4\r\n\r\nabcd").unwrap();
        assert_eq!(request.body, "abcd");
        assert_eq!(request.header("Content-Length").as_deref(), Some("4"));
    }

    #[test]
    fn response_encodes_length_and_connection_unless_set() {
        let encoded = String::from_utf8(Response::text("ok").encode(true)).unwrap();
        assert_eq!(
            encoded,
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        );
        let upgrade = Response::new(101)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .encode(true);
        assert_eq!(
            String::from_utf8(upgrade).unwrap(),
            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn http_recorder_keeps_a_connection_alive_until_the_request_closes_it() {
        let recorder =
            HttpRecorder::serve(|request| Response::text(request.path().to_string()).keep_alive())
                .await
                .unwrap();
        let mut stream = connect(recorder.port).await;
        stream
            .write_all(
                b"GET /one HTTP/1.1\r\nHost: test\r\n\r\n\
                  GET /two HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let response = read_to_end(&mut stream).await;
        assert!(
            response.contains("Connection: keep-alive\r\n\r\n/one"),
            "{response}"
        );
        assert!(
            response.ends_with("Connection: close\r\n\r\n/two"),
            "{response}"
        );
        let paths: Vec<_> = recorder
            .wait_for_requests(2)
            .await
            .unwrap()
            .iter()
            .map(|request| request.path().to_string())
            .collect();
        assert_eq!(paths, ["/one", "/two"]);
        assert_eq!(recorder.connections(), 1);
    }

    #[tokio::test]
    async fn http_recorder_closes_after_a_response_that_is_not_kept_alive() {
        let recorder = HttpRecorder::start("body").await.unwrap();
        let mut stream = connect(recorder.port).await;
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: test\r\n\r\nGET /ignored HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let response = read_to_end(&mut stream).await;
        assert!(
            response.ends_with("Connection: close\r\n\r\nbody"),
            "{response}"
        );
        assert_eq!(recorder.requests().len(), 1);
    }
}
