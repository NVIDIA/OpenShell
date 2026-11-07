// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Servers on the test host that sandboxes reach through
//! `host.openshell.internal`, and that record what arrived, so a test can
//! check what the supervisor forwarded upstream.
//!
//! The servers listen on every host address, since drivers map
//! `host.openshell.internal` to different ones, and stop when dropped. They
//! run where the tests run, so a gateway whose sandboxes can't reach the test
//! host, such as one on a remote cluster, can't run tests that use them.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use base64::Engine as _;
use sha1::{Digest as _, Sha1};
use testkit::{Error, Poll, Result, ResultExt as _};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

const WAIT_TIMEOUT: Duration = Duration::from_secs(10);
const WAIT_INTERVAL: Duration = Duration::from_millis(100);
const READ_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REQUEST: usize = 1024 * 1024;

/// A request an [`HttpRecorder`] read.
#[derive(Clone, Debug)]
pub struct Request {
    /// The request line and headers.
    pub head: String,
    pub body: String,
}

/// An HTTP server that answers every request with `200` and a fixed body,
/// and records each request it read. It reads a body by `Content-Length`
/// only, not a chunked one.
pub struct HttpRecorder {
    pub port: u16,
    requests: Arc<Mutex<Vec<Request>>>,
    task: JoinHandle<()>,
}

impl HttpRecorder {
    pub async fn start(body: impl Into<String>) -> Result<Self> {
        let (listener, port) = bind().await?;
        let body: Arc<str> = body.into().into();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let task_requests = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(respond(
                    stream,
                    Arc::clone(&body),
                    Arc::clone(&task_requests),
                ));
            }
        });
        Ok(Self {
            port,
            requests,
            task,
        })
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
                let requests = self
                    .requests
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone();
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

impl Drop for HttpRecorder {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A WebSocket server that completes the handshake, then reads frames until
/// the connection closes, and records whether any was a binary frame.
pub struct WebSocketRecorder {
    pub port: u16,
    state: Arc<WebSocketState>,
    task: JoinHandle<()>,
}

#[derive(Default)]
struct WebSocketState {
    handshake_seen: AtomicBool,
    binary_seen: AtomicBool,
    finished: AtomicBool,
}

impl WebSocketRecorder {
    pub async fn start() -> Result<Self> {
        let (listener, port) = bind().await?;
        let state = Arc::new(WebSocketState::default());
        let task_state = Arc::clone(&state);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(accept_websocket(stream, Arc::clone(&task_state)));
            }
        });
        Ok(Self { port, state, task })
    }

    /// Wait until a client completed the handshake.
    pub async fn wait_for_handshake(&self) -> Result {
        testkit::poll_until(
            &format!(
                "a WebSocket handshake at the host server on port {}",
                self.port
            ),
            WAIT_TIMEOUT,
            WAIT_INTERVAL,
            async || {
                Ok(if self.state.handshake_seen.load(Ordering::Acquire) {
                    Poll::Ready(())
                } else {
                    Poll::Pending("no handshake".to_string())
                })
            },
        )
        .await
    }

    /// Wait until a connection that completed the handshake has ended, by a
    /// close frame, the client closing it, or [`READ_TIMEOUT`] passing, and
    /// return whether a binary frame arrived on it.
    pub async fn wait_until_finished(&self) -> Result<bool> {
        testkit::poll_until(
            &format!(
                "the WebSocket connection at the host server on port {} to end",
                self.port
            ),
            READ_TIMEOUT + WAIT_TIMEOUT,
            WAIT_INTERVAL,
            async || {
                Ok(if self.state.finished.load(Ordering::Acquire) {
                    Poll::Ready(self.state.binary_seen.load(Ordering::Acquire))
                } else {
                    Poll::Pending("the connection is open".to_string())
                })
            },
        )
        .await
    }
}

impl Drop for WebSocketRecorder {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn bind() -> Result<(TcpListener, u16)> {
    let listener = TcpListener::bind(("0.0.0.0", 0))
        .await
        .map_err(|error| Error::from_error(&error))
        .context("bind a host server")?;
    let port = listener
        .local_addr()
        .map_err(|error| Error::from_error(&error))
        .context("read the host server's address")?
        .port();
    Ok((listener, port))
}

/// Read one request, headers and `Content-Length` body, record it, and
/// answer with `body`.
async fn respond(mut stream: TcpStream, body: Arc<str>, requests: Arc<Mutex<Vec<Request>>>) {
    let _ = stream.set_nodelay(true);
    let Some(request) = read_request(&mut stream).await else {
        return;
    };
    requests
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(request);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

async fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        if let Some(end) = find(&request, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&request[..end]).into_owned();
            let length = header(&head, "content-length")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            if request.len() >= end + 4 + length {
                let body =
                    String::from_utf8_lossy(&request[end + 4..end + 4 + length]).into_owned();
                return Some(Request { head, body });
            }
        }
        match tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buffer)).await {
            Ok(Ok(read)) if read > 0 && request.len() < MAX_REQUEST => {
                request.extend_from_slice(&buffer[..read]);
            }
            _ => return None,
        }
    }
}

async fn accept_websocket(mut stream: TcpStream, state: Arc<WebSocketState>) {
    let _ = stream.set_nodelay(true);
    let Some(request) = read_request(&mut stream).await else {
        return;
    };
    let Some(key) = header(&request.head, "sec-websocket-key") else {
        return;
    };
    // The supervisor checks Sec-WebSocket-Accept, so compute it properly.
    // SHA-1 is what RFC 6455 specifies for it; it protects nothing here.
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let accept = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    if stream.write_all(response.as_bytes()).await.is_err() {
        return;
    }
    state.handshake_seen.store(true, Ordering::Release);

    let _ = tokio::time::timeout(READ_TIMEOUT, read_frames(&mut stream, &state)).await;
    state.finished.store(true, Ordering::Release);
}

/// Read frames until a close frame or the end of the stream, and record a
/// binary frame.
async fn read_frames(stream: &mut TcpStream, state: &WebSocketState) -> std::io::Result<()> {
    loop {
        let mut frame_header = [0_u8; 2];
        stream.read_exact(&mut frame_header).await?;
        let opcode = frame_header[0] & 0x0f;
        let length = match frame_header[1] & 0x7f {
            126 => u64::from(stream.read_u16().await?),
            127 => stream.read_u64().await?,
            length => u64::from(length),
        };
        if opcode == 0x02 {
            state.binary_seen.store(true, Ordering::Release);
        }
        if opcode == 0x08 {
            return Ok(());
        }
        let mask = if frame_header[1] & 0x80 == 0 { 0 } else { 4 };
        let skipped = tokio::io::copy(
            &mut (&mut *stream).take(mask + length),
            &mut tokio::io::sink(),
        )
        .await?;
        if skipped < mask + length {
            return Ok(());
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn header(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|line| {
        let (header, value) = line.split_once(':')?;
        header
            .trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}
