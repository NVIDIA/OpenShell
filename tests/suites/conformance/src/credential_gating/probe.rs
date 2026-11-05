// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Servers on the host that the sandbox clients reach through
//! `host.openshell.internal`, recording what arrived upstream.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use base64::Engine as _;
use sha1::{Digest as _, Sha1};
use testkit::{Error, Poll, Result, ResultExt as _};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use super::{PLACEHOLDER_PREFIX, TEST_SECRET};

const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const OBSERVE_TIMEOUT: Duration = Duration::from_secs(10);
const OBSERVE_INTERVAL: Duration = Duration::from_millis(100);

/// What one request body that reached the HTTP probe contained.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct BodyObservation {
    pub(super) saw_placeholder: bool,
    pub(super) saw_secret: bool,
}

/// An HTTP server that records whether each request carried the credential
/// placeholder or the secret, and answers with `BODY_TEXT`,
/// `BODY_REWRITTEN`, or `BODY_BAD`. It stops when dropped.
pub(super) struct HttpProbeServer {
    pub(super) port: u16,
    observations: Arc<Mutex<Vec<BodyObservation>>>,
    task: JoinHandle<()>,
}

impl HttpProbeServer {
    pub(super) async fn start() -> Result<Self> {
        let (listener, port) = bind("HTTP probe").await?;
        let observations = Arc::new(Mutex::new(Vec::new()));
        let task_observations = Arc::clone(&observations);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let observations = Arc::clone(&task_observations);
                tokio::spawn(async move {
                    let _ = handle_http_probe(stream, observations).await;
                });
            }
        });
        Ok(Self {
            port,
            observations,
            task,
        })
    }

    /// The requests the server has seen, once there are at least `count`.
    pub(super) async fn wait_for_observations(&self, count: usize) -> Result<Vec<BodyObservation>> {
        testkit::poll_until(
            &format!("{count} request(s) at the HTTP probe"),
            OBSERVE_TIMEOUT,
            OBSERVE_INTERVAL,
            async || {
                let observations = self
                    .observations
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone();
                Ok(if observations.len() >= count {
                    Poll::Ready(observations)
                } else {
                    Poll::Pending(format!("{observations:?}"))
                })
            },
        )
        .await
    }
}

impl Drop for HttpProbeServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A WebSocket server that completes the handshake and records whether a
/// binary frame followed. It stops when dropped.
pub(super) struct BinaryWebSocketProbeServer {
    pub(super) port: u16,
    handshake_seen: Arc<AtomicBool>,
    binary_seen: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

impl BinaryWebSocketProbeServer {
    pub(super) async fn start() -> Result<Self> {
        let (listener, port) = bind("WebSocket probe").await?;
        let handshake_seen = Arc::new(AtomicBool::new(false));
        let binary_seen = Arc::new(AtomicBool::new(false));
        let task_handshake_seen = Arc::clone(&handshake_seen);
        let task_binary_seen = Arc::clone(&binary_seen);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let handshake_seen = Arc::clone(&task_handshake_seen);
                let binary_seen = Arc::clone(&task_binary_seen);
                tokio::spawn(async move {
                    let _ =
                        handle_binary_websocket_probe(stream, handshake_seen, binary_seen).await;
                });
            }
        });
        Ok(Self {
            port,
            handshake_seen,
            binary_seen,
            task,
        })
    }

    /// Wait until a client completed the WebSocket handshake.
    pub(super) async fn wait_for_handshake(&self) -> Result {
        testkit::poll_until(
            "the WebSocket handshake at the probe",
            OBSERVE_TIMEOUT,
            OBSERVE_INTERVAL,
            async || {
                Ok(if self.handshake_seen.load(Ordering::Acquire) {
                    Poll::Ready(())
                } else {
                    Poll::Pending("no handshake".to_string())
                })
            },
        )
        .await
    }

    pub(super) fn binary_seen(&self) -> bool {
        self.binary_seen.load(Ordering::Acquire)
    }
}

impl Drop for BinaryWebSocketProbeServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Listen on every host address, since drivers map
/// `host.openshell.internal` to different ones.
async fn bind(what: &str) -> Result<(TcpListener, u16)> {
    let listener = TcpListener::bind(("0.0.0.0", 0))
        .await
        .map_err(|error| Error::from_error(&error))
        .context(format!("bind the {what}"))?;
    let port = listener
        .local_addr()
        .map_err(|error| Error::from_error(&error))
        .context(format!("read the {what}'s address"))?
        .port();
    Ok((listener, port))
}

async fn recv_until(stream: &mut TcpStream, marker: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut received = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            return Ok(received);
        }
        received.extend_from_slice(&buffer[..read]);
        if received
            .windows(marker.len())
            .any(|window| window == marker)
        {
            return Ok(received);
        }
    }
}

fn header_value(request: &str, name: &str) -> Option<String> {
    request.lines().find_map(|line| {
        let (header, value) = line.split_once(':')?;
        header
            .trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

/// The `Sec-WebSocket-Accept` value for `key`, which the supervisor checks.
fn websocket_accept(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WEBSOCKET_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

async fn handle_binary_websocket_probe(
    mut stream: TcpStream,
    handshake_seen: Arc<AtomicBool>,
    binary_seen: Arc<AtomicBool>,
) -> std::io::Result<()> {
    let _ = stream.set_nodelay(true);
    let request_bytes = recv_until(&mut stream, b"\r\n\r\n").await?;
    let request = String::from_utf8_lossy(&request_bytes);
    let key = header_value(&request, "Sec-WebSocket-Key").ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "missing WebSocket key")
    })?;
    let accept = websocket_accept(&key);
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\
         \r\n"
    );
    stream.write_all(response.as_bytes()).await?;
    handshake_seen.store(true, Ordering::Release);

    let mut header = [0_u8; 2];
    if tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut header))
        .await
        .is_ok_and(|result| result.is_ok())
        && header[0] & 0x0f == 0x02
    {
        binary_seen.store(true, Ordering::Release);
    }
    Ok(())
}

async fn handle_http_probe(
    mut stream: TcpStream,
    observations: Arc<Mutex<Vec<BodyObservation>>>,
) -> std::io::Result<()> {
    let _ = stream.set_nodelay(true);
    let mut received = Vec::new();
    let mut buffer = [0_u8; 4096];
    let mut expected_total = None;
    loop {
        let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buffer)).await;
        let Ok(Ok(read)) = read else {
            break;
        };
        if read == 0 {
            break;
        }
        received.extend_from_slice(&buffer[..read]);
        if expected_total.is_none()
            && let Some(header_end) = received.windows(4).position(|window| window == b"\r\n\r\n")
        {
            let header_end = header_end + 4;
            let headers = String::from_utf8_lossy(&received[..header_end]);
            let content_length = header_value(&headers, "content-length")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            expected_total = Some(header_end + content_length);
        }
        if expected_total.is_some_and(|expected| received.len() >= expected) {
            break;
        }
    }

    let observation = BodyObservation {
        saw_placeholder: contains(&received, PLACEHOLDER_PREFIX),
        saw_secret: contains(&received, TEST_SECRET),
    };
    observations
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(observation);
    if expected_total.is_some_and(|expected| received.len() >= expected) {
        let result = if observation.saw_secret && !observation.saw_placeholder {
            "BODY_REWRITTEN"
        } else if observation.saw_placeholder && !observation.saw_secret {
            "BODY_TEXT"
        } else {
            "BODY_BAD"
        };
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{result}",
            result.len()
        );
        stream.write_all(response.as_bytes()).await?;
    }
    Ok(())
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}
