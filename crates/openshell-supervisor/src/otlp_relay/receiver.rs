// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OTLP/HTTP receiver served on supervisor-mediated streams.
//!
//! The agent exports to the reserved relay address. The sandbox's seccomp
//! broker stages that connect for the supervisor, whose proxy hands the
//! resulting duplex stream to [`OtlpConnectionServer::serve`] instead of
//! dialing upstream. The server speaks HTTP/1.1 on that stream and accepts
//! `POST /v1/traces` with an uncompressed protobuf body. No socket is ever
//! bound.

use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use bytes::Bytes;
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, RETRY_AFTER};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::{GracefulShutdown, Watcher};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tracing::{debug, warn};

use super::buffer::{BatchSender, SendError};
use prost::Message as _;
use tonic_types::Status as RpcStatus;

use super::{
    BODY_READ_TIMEOUT, ENRICHMENT_CONCURRENCY, HEADER_READ_TIMEOUT, MAX_BODY_BYTES,
    MAX_CONCURRENT_CONNECTIONS, MAX_ENRICHED_BYTES, RECEIVER_SHUTDOWN_TIMEOUT, RETRY_AFTER_SECS,
    RelayCounters, enrichment,
};

/// Reservation for one relay connection.
///
/// Taken before the sandbox commits the workload socket, so an exhausted
/// server can refuse the open instead of resetting it after `RelayReady`.
pub struct ConnectionPermit {
    _permit: OwnedSemaphorePermit,
}

/// Serves OTLP/HTTP on streams handed over by the mediation path.
///
/// One instance lives for the sandbox lifetime. Each stream is served on the
/// caller's task through [`OtlpConnectionServer::serve`]; the paired
/// [`ReceiverHandle`] owns shutdown.
pub struct OtlpConnectionServer {
    /// `None` once the buffer was closed at shutdown.
    buffer_tx: Mutex<Option<BatchSender>>,
    sandbox_id: String,
    counters: Arc<RelayCounters>,
    connections: Arc<Semaphore>,
    /// Bounds how many bodies are being enriched at once.
    enrichment_slots: Semaphore,
    accepting: AtomicBool,
    /// `None` once shutdown has started. Watchers are minted under this lock,
    /// so none can be created after the shutdown signal is sent.
    graceful: Mutex<Option<GracefulShutdown>>,
    abort_rx: watch::Receiver<bool>,
}

/// Owns receiver shutdown.
pub struct ReceiverHandle {
    server: Arc<OtlpConnectionServer>,
    abort_tx: watch::Sender<bool>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl OtlpConnectionServer {
    /// Creates a server and its shutdown handle.
    pub fn new(
        buffer_tx: BatchSender,
        sandbox_id: String,
        counters: Arc<RelayCounters>,
    ) -> (Arc<Self>, ReceiverHandle) {
        let (abort_tx, abort_rx) = watch::channel(false);
        let server = Arc::new(Self {
            buffer_tx: Mutex::new(Some(buffer_tx)),
            sandbox_id,
            counters,
            connections: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
            enrichment_slots: Semaphore::new(ENRICHMENT_CONCURRENCY),
            accepting: AtomicBool::new(true),
            graceful: Mutex::new(Some(GracefulShutdown::new())),
            abort_rx,
        });
        let handle = ReceiverHandle {
            server: Arc::clone(&server),
            abort_tx,
        };
        (server, handle)
    }

    /// Reserves a connection slot. `None` once [`Self::stop_accepting`] was
    /// called or while [`MAX_CONCURRENT_CONNECTIONS`] streams are served.
    pub fn try_reserve(&self) -> Option<ConnectionPermit> {
        if !self.accepting.load(Ordering::SeqCst) {
            return None;
        }
        let permit = Arc::clone(&self.connections).try_acquire_owned().ok()?;
        Some(ConnectionPermit { _permit: permit })
    }

    /// Makes every later [`Self::try_reserve`] return `None`.
    pub fn stop_accepting(&self) {
        self.accepting.store(false, Ordering::SeqCst);
    }

    /// Drops the buffer sender so the export task observes end of input once
    /// the buffer drains. Requests still in flight answer 503.
    pub fn close_buffer(&self) {
        lock(&self.buffer_tx).take();
    }

    /// Number of connection slots currently in use.
    fn open_connections(&self) -> usize {
        MAX_CONCURRENT_CONNECTIONS - self.connections.available_permits()
    }

    /// Number of enrichment slots currently free.
    #[cfg(test)]
    pub(crate) fn available_enrichment_slots(&self) -> usize {
        self.enrichment_slots.available_permits()
    }

    fn watcher(&self) -> Option<Watcher> {
        lock(&self.graceful).as_ref().map(GracefulShutdown::watcher)
    }

    /// Serves one HTTP/1.1 connection on `stream` until the peer closes it,
    /// the header-read timeout fires, graceful shutdown drains it, or the
    /// abort deadline cuts it. Runs on the caller's task and releases
    /// `permit` when it returns.
    pub async fn serve<S>(self: &Arc<Self>, permit: ConnectionPermit, stream: S)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let Some(watcher) = self.watcher() else {
            debug!("OTLP relay: stream arrived during shutdown, dropping");
            return;
        };

        let server = Arc::clone(self);
        let service = service_fn(move |request| {
            let server = Arc::clone(&server);
            async move { server.handle_request(request).await }
        });

        let mut builder = http1::Builder::new();
        // A timer is mandatory once any timeout is configured; hyper panics in
        // `serve_connection` otherwise.
        builder
            .timer(TokioTimer::new())
            .header_read_timeout(HEADER_READ_TIMEOUT);
        let connection = watcher.watch(builder.serve_connection(TokioIo::new(stream), service));

        let mut abort_rx = self.abort_rx.clone();
        tokio::select! {
            result = connection => {
                if let Err(error) = result {
                    debug!(%error, "OTLP relay connection ended with an error");
                }
            }
            _ = abort_rx.wait_for(|aborted| *aborted) => {
                debug!("OTLP relay: aborting connection after graceful timeout");
            }
        }
        drop(permit);
    }

    async fn handle_request(
        &self,
        request: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        if request.method() != Method::POST || request.uri().path() != "/v1/traces" {
            return Ok(rejected(
                StatusCode::NOT_FOUND,
                "not found",
                "not found; the relay serves POST /v1/traces only",
            ));
        }
        if request.headers().contains_key(CONTENT_ENCODING) {
            return Ok(rejected(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "compressed body",
                "compression is not supported; send an uncompressed application/x-protobuf body",
            ));
        }
        // Media types are case-insensitive and may carry parameters.
        let protobuf = request
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|media_type| {
                media_type
                    .trim()
                    .eq_ignore_ascii_case("application/x-protobuf")
            });
        if !protobuf {
            return Ok(rejected(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported content type",
                "unsupported content type; send application/x-protobuf",
            ));
        }
        let declared_length = request
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok());

        let body = match tokio::time::timeout(
            BODY_READ_TIMEOUT,
            read_body(request.into_body(), declared_length),
        )
        .await
        {
            Ok(BodyRead::Complete(body)) => body,
            Ok(BodyRead::TooLarge) => {
                return Ok(rejected(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "body exceeds limit",
                    "request body exceeds the 2 MiB limit",
                ));
            }
            Ok(BodyRead::Failed(error)) => {
                debug!(%error, "OTLP relay failed to read a request body");
                return Ok(rejected(
                    StatusCode::BAD_REQUEST,
                    "unreadable body",
                    "failed to read request body",
                ));
            }
            // Returning drops the half-read body; hyper closes the connection
            // because the request was not consumed, which frees the slot.
            Err(_) => {
                return Ok(rejected(
                    StatusCode::REQUEST_TIMEOUT,
                    "body read timed out",
                    "request body was not received in time",
                ));
            }
        };

        let enriched = {
            let _slot = self
                .enrichment_slots
                .acquire()
                .await
                .expect("the enrichment semaphore is never closed");
            enrichment::enrich(&body, &self.sandbox_id)
        };
        // The raw body is no longer needed once the enriched copy exists.
        drop(body);
        let enriched = match enriched {
            Ok(enriched) => enriched,
            Err(error @ enrichment::EnrichError::Malformed(_)) => {
                return Ok(rejected(
                    StatusCode::BAD_REQUEST,
                    "protobuf decode failed",
                    &error.to_string(),
                ));
            }
            Err(
                error @ (enrichment::EnrichError::TooManyResourceSpans
                | enrichment::EnrichError::TooManyResourceAttributes
                | enrichment::EnrichError::ResourceTooLarge),
            ) => {
                return Ok(rejected(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request exceeds structural limits",
                    &error.to_string(),
                ));
            }
        };
        // The buffer bound is sized for MAX_ENRICHED_BYTES per batch. The
        // structural limits above keep every request under it for the sandbox
        // id lengths the attribution budget assumes; this guards that
        // assumption.
        if enriched.len() > MAX_ENRICHED_BYTES {
            return Ok(rejected(
                StatusCode::PAYLOAD_TOO_LARGE,
                "enriched body exceeds limit",
                "request body exceeds the 2 MiB limit after attribution",
            ));
        }

        let sent = lock(&self.buffer_tx)
            .as_ref()
            .map_or(Err(SendError::BufferClosed), |tx| tx.try_send(enriched));
        match sent {
            Ok(()) => {
                self.counters.record_accepted();
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "application/x-protobuf")
                    .body(Full::new(Bytes::new()))
                    .expect("static response builds"))
            }
            Err(SendError::BufferFull) => {
                self.counters.record_rejection();
                Ok(unavailable())
            }
            Err(SendError::BufferClosed) => {
                debug!("OTLP relay refused an export: relay is shutting down");
                Ok(unavailable())
            }
        }
    }
}

/// Bytes of an oversize body the receiver reads and discards so the 413
/// reaches a client that is still sending. Beyond this the connection is
/// closed and the client sees a reset instead.
const OVERSIZE_DRAIN_CAP: usize = 8 * MAX_BODY_BYTES;

enum BodyRead {
    Complete(Bytes),
    TooLarge,
    Failed(hyper::Error),
}

/// Reads the body up to [`MAX_BODY_BYTES`]. Once the limit is crossed, or
/// when the declared length already exceeds it, the rest is discarded up
/// to [`OVERSIZE_DRAIN_CAP`] so the response can be delivered on a
/// connection the client has finished writing to.
async fn read_body(mut body: Incoming, declared_length: Option<usize>) -> BodyRead {
    let mut too_large = declared_length.is_some_and(|length| length > MAX_BODY_BYTES);
    // Size the buffer once from the declared length when the first bytes
    // arrive, so growth never leaves a body-sized slack behind and a client
    // that declares a length but sends nothing reserves nothing; chunked
    // bodies are shrunk at the end instead.
    let reserve = if too_large {
        0
    } else {
        declared_length.unwrap_or(0)
    };
    let mut buffered = Vec::new();
    let mut total = 0usize;
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(_) if too_large => break,
            Err(error) => return BodyRead::Failed(error),
        };
        let Some(data) = frame.data_ref() else {
            continue;
        };
        total += data.len();
        if too_large {
            if total > OVERSIZE_DRAIN_CAP {
                break;
            }
            continue;
        }
        if total > MAX_BODY_BYTES {
            too_large = true;
            buffered = Vec::new();
            continue;
        }
        // Grow in doubling steps capped at the body limit, so a chunked body
        // that stalls mid-way never holds more than MAX_BODY_BYTES of
        // capacity; declared lengths are reserved exactly on the first frame.
        let needed = buffered.len() + data.len();
        if needed > buffered.capacity() {
            let target = if buffered.capacity() == 0 {
                reserve.max(data.len())
            } else {
                (buffered.capacity() * 2).min(MAX_BODY_BYTES).max(needed)
            };
            buffered.reserve_exact(target - buffered.len());
        }
        buffered.extend_from_slice(data);
    }
    if too_large {
        BodyRead::TooLarge
    } else {
        buffered.shrink_to_fit();
        BodyRead::Complete(Bytes::from(buffered))
    }
}

/// Builds an error response the way OTLP/HTTP specifies: a protobuf-encoded
/// `google.rpc.Status` in the request's content type, so collectors and SDKs
/// that decode it surface `message` instead of a bare status code.
fn rejected(status: StatusCode, reason: &str, message: &str) -> Response<Full<Bytes>> {
    debug!(
        status = status.as_u16(),
        reason, "OTLP relay rejected request"
    );
    let code = match status {
        StatusCode::NOT_FOUND => tonic::Code::NotFound,
        StatusCode::PAYLOAD_TOO_LARGE => tonic::Code::ResourceExhausted,
        StatusCode::REQUEST_TIMEOUT => tonic::Code::DeadlineExceeded,
        _ => tonic::Code::InvalidArgument,
    };
    status_response(status, code, message)
}

fn unavailable() -> Response<Full<Bytes>> {
    let mut response = status_response(
        StatusCode::SERVICE_UNAVAILABLE,
        tonic::Code::Unavailable,
        "relay buffer is full; retry after the Retry-After interval",
    );
    response.headers_mut().insert(
        RETRY_AFTER,
        RETRY_AFTER_SECS.to_string().parse().expect("ascii"),
    );
    response
}

fn status_response(status: StatusCode, code: tonic::Code, message: &str) -> Response<Full<Bytes>> {
    let body = RpcStatus {
        code: code as i32,
        message: message.to_string(),
        details: Vec::new(),
    }
    .encode_to_vec();
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/x-protobuf")
        .body(Full::new(Bytes::from(body)))
        .expect("static response builds")
}

impl ReceiverHandle {
    /// Stops accepting new streams, disables keep-alive on every open
    /// connection, waits up to [`RECEIVER_SHUTDOWN_TIMEOUT`] for in-flight
    /// requests, then cuts stragglers. Always returns within roughly the
    /// timeout. Consumes the handle, so it runs exactly once.
    pub async fn shutdown(self) {
        self.server.stop_accepting();
        let graceful = lock(&self.server.graceful)
            .take()
            .expect("graceful shutdown is taken exactly once, by this method");
        if tokio::time::timeout(RECEIVER_SHUTDOWN_TIMEOUT, graceful.shutdown())
            .await
            .is_err()
        {
            warn!(
                open_connections = self.server.open_connections(),
                "OTLP relay: aborting connections still open after graceful timeout"
            );
            self.abort_tx.send_replace(true);
        }
    }
}

/// In-memory HTTP helpers shared by the receiver and lifecycle tests. They
/// stand in for the boundary duplex stream the proxy hands over in
/// production.
#[cfg(test)]
pub mod test_util {
    use std::fmt::Write as _;
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

    use super::OtlpConnectionServer;

    /// A complete HTTP/1.1 request with a `Content-Length` body.
    pub fn request(method: &str, path: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
        request_with_headers(method, path, &[("Content-Type", content_type)], body)
    }

    pub fn request_with_headers(
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Vec<u8> {
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: relay\r\n");
        for (name, value) in headers {
            let _ = write!(req, "{name}: {value}\r\n");
        }
        let _ = write!(req, "Content-Length: {}\r\n\r\n", body.len());
        let mut req = req.into_bytes();
        req.extend_from_slice(body);
        req
    }

    /// Opens a client stream whose server half is served on a spawned task,
    /// the way the proxy hook serves a staged boundary stream.
    pub fn connect(server: &Arc<OtlpConnectionServer>) -> DuplexStream {
        let (client, server_half) = tokio::io::duplex(64 * 1024);
        let permit = server.try_reserve().expect("connection slot");
        let server = Arc::clone(server);
        tokio::spawn(async move { server.serve(permit, server_half).await });
        client
    }

    /// Parsed response head: status code and headers.
    pub struct Head {
        pub status: u16,
        pub headers: Vec<(String, String)>,
        /// The response body, which every relay response declares with a
        /// `Content-Length`.
        pub body: Vec<u8>,
    }

    impl Head {
        pub fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        }

        /// Decodes the `google.rpc.Status` body every error response carries.
        pub fn rpc_status(&self) -> tonic_types::Status {
            assert_eq!(
                self.header("content-type"),
                Some("application/x-protobuf"),
                "error bodies use the request's content type"
            );
            prost::Message::decode(self.body.as_slice()).expect("google.rpc.Status body")
        }
    }

    /// Writes `req` and reads until the response head is complete. Returns
    /// the parsed head; the stream stays open.
    pub async fn send<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, req: &[u8]) -> Head {
        stream.write_all(req).await.expect("write request");
        read_head(stream).await
    }

    pub async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> Head {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        let head_end = loop {
            let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
                .await
                .expect("response within 5s")
                .expect("read response");
            assert!(n > 0, "connection closed before response head");
            buf.extend_from_slice(&chunk[..n]);
            if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break end;
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
        let mut lines = head.lines();
        let status_line = lines.next().unwrap_or_default();
        let status = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or_else(|| panic!("status line: {status_line}"));
        let headers: Vec<(String, String)> = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
            .collect();
        // Read the body so a keep-alive connection is ready for the next
        // request. Every relay response is either empty or has a declared
        // Content-Length.
        let body_len: usize = headers
            .iter()
            .find(|(name, _): &&(String, String)| name.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| value.parse().ok())
            .unwrap_or(0);
        let mut body = buf[head_end + 4..].to_vec();
        while body.len() < body_len {
            let n = stream.read(&mut chunk).await.expect("read body");
            assert!(n > 0, "connection closed inside the body");
            body.extend_from_slice(&chunk[..n]);
        }
        body.truncate(body_len);
        Head {
            status,
            headers,
            body,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::super::buffer::{BatchReceiver, new_buffer};
    use super::super::enrichment::test_util::{
        encoded_request, encoded_request_with_large_span, resource_attributes,
    };
    use super::super::{BUFFER_CAPACITY, enrichment};
    use super::test_util::{connect, read_head, request, request_with_headers, send};
    use super::*;

    const PROTOBUF: &str = "application/x-protobuf";

    fn start(capacity: usize) -> (Arc<OtlpConnectionServer>, ReceiverHandle, BatchReceiver) {
        let (tx, rx) = new_buffer(capacity);
        let counters = Arc::new(RelayCounters::default());
        let (server, handle) = OtlpConnectionServer::new(tx, "sb-test".into(), counters);
        (server, handle, rx)
    }

    fn body() -> Vec<u8> {
        encoded_request("test-span", &[("service.name", "unit-agent")])
    }

    #[tokio::test]
    async fn valid_request_is_accepted_and_enriched() {
        let (server, _handle, mut rx) = start(BUFFER_CAPACITY);
        let mut client = connect(&server);
        let head = send(
            &mut client,
            &request("POST", "/v1/traces", PROTOBUF, &body()),
        )
        .await;
        assert_eq!(head.status, 200);
        assert_eq!(head.header("content-type"), Some(PROTOBUF));

        let buffered = rx.recv().await.expect("one batch buffered");
        let attributes = resource_attributes(&buffered);
        assert!(attributes.contains(&("service.name".to_string(), "unit-agent".to_string())));
        assert!(attributes.contains(&(
            enrichment::SANDBOX_ID_KEY.to_string(),
            "sb-test".to_string()
        )));
        assert!(attributes.contains(&(
            enrichment::SOURCE_KEY.to_string(),
            enrichment::SOURCE_VALUE.to_string()
        )));
    }

    #[tokio::test]
    async fn other_paths_and_methods_are_not_found() {
        let (server, _handle, _rx) = start(BUFFER_CAPACITY);
        let mut client = connect(&server);
        let head = send(&mut client, &request("POST", "/v1/metrics", PROTOBUF, b"")).await;
        assert_eq!(head.status, 404);
        let head = send(&mut client, &request("GET", "/v1/traces", PROTOBUF, b"")).await;
        assert_eq!(head.status, 404);
    }

    #[tokio::test]
    async fn json_body_is_unsupported() {
        let (server, _handle, _rx) = start(BUFFER_CAPACITY);
        let mut client = connect(&server);
        let head = send(
            &mut client,
            &request("POST", "/v1/traces", "application/json", b"{}"),
        )
        .await;
        assert_eq!(head.status, 415);
        // The spec requires the body to state the supported content type, as
        // a google.rpc.Status in the request's content type.
        let status = head.rpc_status();
        assert_eq!(status.code, tonic::Code::InvalidArgument as i32);
        assert!(
            status.message.contains("application/x-protobuf"),
            "415 body must name the supported content type: {}",
            status.message
        );
    }

    #[tokio::test]
    async fn mixed_case_protobuf_content_type_with_parameters_is_accepted() {
        let (server, _handle, mut rx) = start(BUFFER_CAPACITY);
        let mut client = connect(&server);
        let head = send(
            &mut client,
            &request(
                "POST",
                "/v1/traces",
                "Application/X-Protobuf; charset=binary",
                &body(),
            ),
        )
        .await;
        assert_eq!(head.status, 200);
        assert!(rx.recv().await.is_some());
    }

    #[tokio::test]
    async fn compressed_body_is_unsupported() {
        let (server, _handle, _rx) = start(BUFFER_CAPACITY);
        let mut client = connect(&server);
        let head = send(
            &mut client,
            &request_with_headers(
                "POST",
                "/v1/traces",
                &[("Content-Type", PROTOBUF), ("Content-Encoding", "gzip")],
                &body(),
            ),
        )
        .await;
        assert_eq!(head.status, 415);
        // The spec requires the body to state that compression is unsupported.
        let status = head.rpc_status();
        assert!(
            status.message.contains("compression is not supported"),
            "415 body must say compression is unsupported: {}",
            status.message
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_body_is_timed_out_and_frees_its_slot() {
        let (server, _handle, _rx) = start(BUFFER_CAPACITY);
        let mut client = connect(&server);
        // Complete headers, then only a fraction of the declared body.
        let req = format!(
            "POST /v1/traces HTTP/1.1\r\nHost: relay\r\nContent-Type: {PROTOBUF}\r\nContent-Length: 4096\r\n\r\n"
        );
        client.write_all(req.as_bytes()).await.unwrap();
        client.write_all(&[0u8; 16]).await.unwrap();
        // Let the server parse the headers and start its body timer.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert_eq!(server.open_connections(), 1);

        // Jump past the body deadline (the read helper's own 5 s timer would
        // otherwise fire first under paused time); the server answers 408 and
        // closes the connection.
        tokio::time::advance(BODY_READ_TIMEOUT + Duration::from_secs(1)).await;
        let head = read_head(&mut client).await;
        assert_eq!(head.status, 408);
        assert_eq!(head.rpc_status().code, tonic::Code::DeadlineExceeded as i32);
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(BODY_READ_TIMEOUT, client.read(&mut buf))
            .await
            .expect("server closes the stalled connection")
            .unwrap_or(0);
        assert_eq!(n, 0, "expected EOF after the body timeout");
        tokio::task::yield_now().await;
        assert_eq!(server.open_connections(), 0);
    }

    #[tokio::test]
    async fn structurally_abusive_bodies_are_too_large_and_never_buffered() {
        let (server, _handle, mut rx) = start(BUFFER_CAPACITY);
        let mut client = connect(&server);

        // One more empty `ResourceSpans` entry than the cap: far under the
        // wire limit, so the 413 can only come from the structural check.
        let many_entries: Vec<u8> = [0x0a, 0x00].repeat(enrichment::MAX_RESOURCE_SPANS + 1);
        let head = send(
            &mut client,
            &request("POST", "/v1/traces", PROTOBUF, &many_entries),
        )
        .await;
        assert_eq!(head.status, 413);

        // One resource larger than the decode bound.
        let huge_resource = encoded_request(
            "r",
            &[("blob", &"x".repeat(enrichment::MAX_RESOURCE_BYTES))],
        );
        let head = send(
            &mut client,
            &request("POST", "/v1/traces", PROTOBUF, &huge_resource),
        )
        .await;
        assert_eq!(head.status, 413);

        // The connection still serves, and the first buffered batch is the
        // valid one: neither refused body was buffered ahead of it.
        let head = send(
            &mut client,
            &request("POST", "/v1/traces", PROTOBUF, &body()),
        )
        .await;
        assert_eq!(head.status, 200);
        let buffered = rx.recv().await.expect("the valid batch is buffered");
        let attributes = resource_attributes(&buffered);
        assert!(attributes.contains(&("service.name".to_string(), "unit-agent".to_string())));
        let rejections = server.counters.snapshot().rejected;
        assert_eq!(rejections, 0, "limit refusals are not back-pressure");
    }

    #[tokio::test]
    async fn sixteen_simultaneous_requests_are_all_served() {
        let (server, _handle, mut rx) = start(BUFFER_CAPACITY);
        let valid = Arc::new(request(
            "POST",
            "/v1/traces",
            PROTOBUF,
            &encoded_request_with_large_span("burst", 256 * 1024),
        ));
        let garbage = Arc::new(request("POST", "/v1/traces", PROTOBUF, &[0xff, 0xfe, 0xfd]));
        // Every connection writes its whole request before any response is
        // read. Enrichment is synchronous, so on the test runtime the two
        // enrichment slots never actually queue a request; this pins that
        // sixteen concurrent requests are all answered, that malformed
        // bodies release their slot on the error path, and that none of them
        // is buffered.
        let mut tasks = Vec::new();
        for i in 0..MAX_CONCURRENT_CONNECTIONS {
            let mut client = connect(&server);
            let req = if i % 5 == 0 {
                Arc::clone(&garbage)
            } else {
                Arc::clone(&valid)
            };
            tasks.push(tokio::spawn(
                async move { send(&mut client, &req).await.status },
            ));
        }
        let statuses =
            tokio::time::timeout(Duration::from_secs(10), futures::future::join_all(tasks))
                .await
                .expect("all sixteen requests answered");
        let mut accepted = 0;
        let mut malformed = 0;
        for status in statuses {
            match status.expect("request task completes") {
                200 => accepted += 1,
                400 => malformed += 1,
                other => panic!("unexpected status {other}"),
            }
        }
        assert_eq!(malformed, 4);
        assert_eq!(accepted, MAX_CONCURRENT_CONNECTIONS - 4);
        for _ in 0..accepted {
            let batch = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("accepted batch is buffered within 5s");
            assert!(batch.is_some());
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), rx.recv())
                .await
                .is_err(),
            "malformed bodies were buffered"
        );
        assert_eq!(
            server.available_enrichment_slots(),
            ENRICHMENT_CONCURRENCY,
            "every enrichment permit is released"
        );
    }

    #[tokio::test]
    async fn enriched_body_over_the_bound_is_too_large_and_never_buffered() {
        // A sandbox id far longer than ATTRIBUTION_BYTES_PER_ENTRY accounts
        // for: 512 resource-less entries near the wire limit grow past
        // MAX_ENRICHED_BYTES, and the receiver must refuse rather than buffer
        // an oversize batch.
        let (tx, mut rx) = new_buffer(BUFFER_CAPACITY);
        let counters = Arc::new(RelayCounters::default());
        let (server, _handle) = OtlpConnectionServer::new(tx, "x".repeat(200), counters);
        let mut client = connect(&server);
        let entry = {
            let scope = [0x12u8, 0x00].repeat(2000); // ~4 KiB of empty spans
            let mut scope_field = vec![0x12u8]; // ResourceSpans.scope_spans
            scope_field.extend_from_slice(&encode_len(scope.len()));
            scope_field.extend_from_slice(&scope);
            let mut entry = vec![0x0au8]; // resource_spans
            entry.extend_from_slice(&encode_len(scope_field.len()));
            entry.extend_from_slice(&scope_field);
            entry
        };
        let body: Vec<u8> = entry.repeat(enrichment::MAX_RESOURCE_SPANS);
        assert!(body.len() <= MAX_BODY_BYTES);
        // Positive control: the same body is accepted with an ordinary id,
        // so the 413 below can only come from the attribution bound.
        let (control, _control_handle, mut control_rx) = start(BUFFER_CAPACITY);
        let mut control_client = connect(&control);
        let head = send(
            &mut control_client,
            &request("POST", "/v1/traces", PROTOBUF, &body),
        )
        .await;
        assert_eq!(head.status, 200);
        assert!(control_rx.recv().await.is_some());

        let head = send(&mut client, &request("POST", "/v1/traces", PROTOBUF, &body)).await;
        assert_eq!(head.status, 413);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), rx.recv())
                .await
                .is_err(),
            "an oversize enriched batch was buffered"
        );
        let rejections = server.counters.snapshot().rejected;
        assert_eq!(rejections, 0, "limit refusals are not back-pressure");
    }

    /// Protobuf varint length prefix.
    fn encode_len(len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        prost::encoding::encode_varint(len as u64, &mut out);
        out
    }

    #[tokio::test]
    async fn garbage_body_is_a_bad_request() {
        let (server, _handle, _rx) = start(BUFFER_CAPACITY);
        let mut client = connect(&server);
        let head = send(
            &mut client,
            &request("POST", "/v1/traces", PROTOBUF, &[0xff, 0xfe, 0xfd]),
        )
        .await;
        assert_eq!(head.status, 400);
    }

    #[tokio::test]
    async fn keep_alive_serves_a_second_request_on_the_same_connection() {
        let (server, _handle, mut rx) = start(BUFFER_CAPACITY);
        let mut client = connect(&server);
        for _ in 0..2 {
            let head = send(
                &mut client,
                &request("POST", "/v1/traces", PROTOBUF, &body()),
            )
            .await;
            assert_eq!(head.status, 200);
        }
        assert!(rx.recv().await.is_some());
        assert!(rx.recv().await.is_some());
        assert_eq!(server.open_connections(), 1);
    }

    #[tokio::test]
    async fn declared_oversize_body_is_too_large() {
        let (server, _handle, _rx) = start(BUFFER_CAPACITY);
        let mut client = connect(&server);
        let req = format!(
            "POST /v1/traces HTTP/1.1\r\nHost: relay\r\nContent-Type: {PROTOBUF}\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        client.write_all(req.as_bytes()).await.unwrap();
        // The server drains the oversize body so the client, which keeps
        // sending, still receives the 413 on an intact connection.
        client
            .write_all(&vec![b'x'; MAX_BODY_BYTES + 1])
            .await
            .unwrap();
        let head = read_head(&mut client).await;
        assert_eq!(head.status, 413);
        // The connection stays usable afterwards.
        let head = send(
            &mut client,
            &request("POST", "/v1/traces", PROTOBUF, &body()),
        )
        .await;
        assert_eq!(head.status, 200);
    }

    #[tokio::test]
    async fn chunked_oversize_body_is_too_large() {
        let (server, _handle, _rx) = start(BUFFER_CAPACITY);
        let mut client = connect(&server);
        let req = format!(
            "POST /v1/traces HTTP/1.1\r\nHost: relay\r\nContent-Type: {PROTOBUF}\r\nTransfer-Encoding: chunked\r\n\r\n"
        );
        client.write_all(req.as_bytes()).await.unwrap();
        let chunk = vec![b'x'; 64 * 1024];
        let chunk_head = format!("{:x}\r\n", chunk.len());
        let mut sent = 0;
        // Write chunks past the limit, then terminate the body. The server
        // discards the excess and answers once the body ends.
        while sent <= MAX_BODY_BYTES + chunk.len() {
            client.write_all(chunk_head.as_bytes()).await.unwrap();
            client.write_all(&chunk).await.unwrap();
            client.write_all(b"\r\n").await.unwrap();
            sent += chunk.len();
        }
        client.write_all(b"0\r\n\r\n").await.unwrap();
        assert_eq!(read_head(&mut client).await.status, 413);
    }

    #[tokio::test]
    async fn oversize_body_beyond_the_drain_cap_closes_the_connection() {
        let (server, _handle, _rx) = start(BUFFER_CAPACITY);
        let mut client = connect(&server);
        let req = format!(
            "POST /v1/traces HTTP/1.1\r\nHost: relay\r\nContent-Type: {PROTOBUF}\r\nContent-Length: {}\r\n\r\n",
            OVERSIZE_DRAIN_CAP * 2
        );
        client.write_all(req.as_bytes()).await.unwrap();
        let chunk = vec![b'x'; 256 * 1024];
        let mut sent = 0;
        // Writes fail once the server stops draining and closes; the receiver
        // never buffers more than the cap.
        while sent <= OVERSIZE_DRAIN_CAP * 2 {
            if client.write_all(&chunk).await.is_err() {
                break;
            }
            sent += chunk.len();
        }
        assert!(sent <= OVERSIZE_DRAIN_CAP * 2, "sent {sent} bytes");
        assert!(server.try_reserve().is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn idle_connection_is_closed_after_the_header_timeout_and_frees_its_slot() {
        let (server, _handle, _rx) = start(BUFFER_CAPACITY);
        let mut client = connect(&server);
        tokio::task::yield_now().await;
        assert_eq!(server.open_connections(), 1);

        // Nothing is written. The header-read timeout closes the connection.
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(HEADER_READ_TIMEOUT * 2, client.read(&mut buf))
            .await
            .expect("server closes the idle connection")
            .unwrap_or(0);
        assert_eq!(n, 0, "expected EOF after the header-read timeout");
        tokio::task::yield_now().await;
        assert_eq!(server.open_connections(), 0);
        assert!(server.try_reserve().is_some());
    }

    #[tokio::test]
    async fn connection_cap_refuses_the_seventeenth_and_recovers() {
        let (server, _handle, _rx) = start(BUFFER_CAPACITY);
        let mut permits: Vec<ConnectionPermit> = (0..MAX_CONCURRENT_CONNECTIONS)
            .map(|i| server.try_reserve().unwrap_or_else(|| panic!("slot {i}")))
            .collect();
        assert!(server.try_reserve().is_none());
        drop(permits.pop());
        assert!(server.try_reserve().is_some());
    }

    #[tokio::test]
    async fn try_reserve_refuses_after_stop_accepting() {
        let (server, _handle, _rx) = start(BUFFER_CAPACITY);
        assert!(server.try_reserve().is_some());
        server.stop_accepting();
        assert!(server.try_reserve().is_none());
    }

    #[tokio::test]
    async fn two_connections_are_served_concurrently() {
        let (server, _handle, mut rx) = start(BUFFER_CAPACITY);
        let mut first = connect(&server);
        let mut second = connect(&server);
        let first_req = request("POST", "/v1/traces", PROTOBUF, &encoded_request("one", &[]));
        let second_req = request("POST", "/v1/traces", PROTOBUF, &encoded_request("two", &[]));
        // Interleave: write the first request's head only, then the whole
        // second request, then finish the first.
        let split = first_req.len() / 2;
        first.write_all(&first_req[..split]).await.unwrap();
        let second_head = send(&mut second, &second_req).await;
        assert_eq!(second_head.status, 200);
        first.write_all(&first_req[split..]).await.unwrap();
        let first_head = read_head(&mut first).await;
        assert_eq!(first_head.status, 200);

        let a = resource_attributes(&rx.recv().await.unwrap());
        let b = resource_attributes(&rx.recv().await.unwrap());
        let id = |attrs: &Vec<(String, String)>| {
            attrs
                .iter()
                .find(|(key, _)| key == enrichment::SANDBOX_ID_KEY)
                .map(|(_, value)| value.clone())
        };
        assert_eq!(id(&a), Some("sb-test".to_string()));
        assert_eq!(id(&a), id(&b));
    }

    #[tokio::test]
    async fn full_buffer_answers_503_with_retry_after_and_counts_the_rejection() {
        let (server, _handle, mut rx) = start(1);
        let mut client = connect(&server);
        let accepted = send(
            &mut client,
            &request("POST", "/v1/traces", PROTOBUF, &body()),
        )
        .await;
        assert_eq!(accepted.status, 200);

        let rejected = send(
            &mut client,
            &request("POST", "/v1/traces", PROTOBUF, &body()),
        )
        .await;
        assert_eq!(rejected.status, 503);
        assert_eq!(
            rejected.header("retry-after"),
            Some(RETRY_AFTER_SECS.to_string().as_str())
        );
        assert_eq!(
            rejected.rpc_status().code,
            tonic::Code::Unavailable as i32,
            "503 carries a google.rpc.Status so SDKs can surface the reason"
        );
        let rejections = server.counters.snapshot().rejected;
        assert_eq!(rejections, 1);

        // Draining the buffer makes the same connection usable again.
        assert!(rx.recv().await.is_some());
        let again = send(
            &mut client,
            &request("POST", "/v1/traces", PROTOBUF, &body()),
        )
        .await;
        assert_eq!(again.status, 200);
    }

    #[tokio::test]
    async fn shutdown_completes_with_idle_keepalive_connection() {
        let (server, handle, _rx) = start(BUFFER_CAPACITY);
        let mut client = connect(&server);
        let head = send(
            &mut client,
            &request("POST", "/v1/traces", PROTOBUF, &body()),
        )
        .await;
        assert_eq!(head.status, 200);

        let deadline = RECEIVER_SHUTDOWN_TIMEOUT + Duration::from_secs(1);
        tokio::time::timeout(deadline, handle.shutdown())
            .await
            .expect("shutdown completes despite an open keep-alive connection");

        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .expect("server close within 2s")
            .unwrap_or(0);
        assert_eq!(n, 0, "expected EOF from server after shutdown");
        assert!(server.try_reserve().is_none());
    }

    #[tokio::test]
    async fn shutdown_completes_with_half_sent_headers() {
        let (server, handle, _rx) = start(BUFFER_CAPACITY);
        let mut client = connect(&server);
        client
            .write_all(b"POST /v1/traces HTTP/1.1\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let deadline = RECEIVER_SHUTDOWN_TIMEOUT + Duration::from_secs(1);
        tokio::time::timeout(deadline, handle.shutdown())
            .await
            .expect("shutdown completes with an in-progress request");
    }

    #[tokio::test]
    async fn closed_buffer_answers_503() {
        let (server, _handle, _rx) = start(BUFFER_CAPACITY);
        server.close_buffer();
        let mut client = connect(&server);
        let head = send(
            &mut client,
            &request("POST", "/v1/traces", PROTOBUF, &body()),
        )
        .await;
        assert_eq!(head.status, 503);
        let rejections = server.counters.snapshot().rejected;
        assert_eq!(rejections, 0, "shutdown refusals are not back-pressure");
    }
}
