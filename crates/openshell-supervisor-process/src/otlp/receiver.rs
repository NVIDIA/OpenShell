// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OTLP HTTP receiver served on supervisor-mediated streams.
//!
//! The agent exports to the reserved relay address. The sandbox's seccomp
//! broker stages that connect for the supervisor, whose proxy hands the
//! resulting duplex stream to [`OtlpConnectionServer::serve`] instead of
//! dialing upstream. The server speaks HTTP/1.1 on that stream and accepts
//! `POST /v1/traces` with protobuf or JSON bodies. No socket is ever bound.

use std::convert::Infallible;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::{GracefulShutdown, Watcher};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tracing::{debug, warn};

use super::buffer::TelemetrySender;
use super::enrichment::{self, ContentType, EnrichmentError};
use super::{RECEIVER_SHUTDOWN_TIMEOUT, SandboxMetadata};

/// Upper bound on concurrently served relay connections.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 64;
const MAX_BODY_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

/// Time a client has to send request headers before the connection is closed.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Reservation for one relay connection.
///
/// Taken before the sandbox commits the workload socket, so an exhausted
/// server can refuse the open instead of resetting it after `RelayReady`.
pub struct ConnectionPermit {
    _permit: OwnedSemaphorePermit,
}

/// Serves OTLP HTTP on streams handed over by the mediation path.
///
/// One instance lives for the sandbox lifetime. Each stream is served on the
/// caller's task through [`OtlpConnectionServer::serve`]; the paired
/// [`ReceiverHandle`] owns shutdown.
pub struct OtlpConnectionServer {
    buf_tx: TelemetrySender,
    metadata: SandboxMetadata,
    enrichment_enabled: bool,
    connections: Arc<Semaphore>,
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
    /// Create a server and its shutdown handle.
    pub fn new(
        buf_tx: TelemetrySender,
        metadata: SandboxMetadata,
        enrichment_enabled: bool,
    ) -> (Arc<Self>, ReceiverHandle) {
        let (abort_tx, abort_rx) = watch::channel(false);
        let server = Arc::new(Self {
            buf_tx,
            metadata,
            enrichment_enabled,
            connections: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
            graceful: Mutex::new(Some(GracefulShutdown::new())),
            abort_rx,
        });
        let handle = ReceiverHandle {
            server: Arc::clone(&server),
            abort_tx,
        };
        (server, handle)
    }

    /// Sender side of the relay buffer, for additional producers such as the
    /// OCSF sink.
    pub fn sender(&self) -> &TelemetrySender {
        &self.buf_tx
    }

    /// Reserve a connection slot. `None` when the server is shutting down or
    /// already serving [`MAX_CONCURRENT_CONNECTIONS`] streams.
    pub fn try_reserve(&self) -> Option<ConnectionPermit> {
        if lock(&self.graceful).is_none() {
            return None;
        }
        let permit = Arc::clone(&self.connections).try_acquire_owned().ok()?;
        Some(ConnectionPermit { _permit: permit })
    }

    fn watcher(&self) -> Option<Watcher> {
        lock(&self.graceful).as_ref().map(GracefulShutdown::watcher)
    }

    /// Serve one HTTP/1.1 connection on `stream` until the peer closes it,
    /// graceful shutdown drains it, or the abort deadline cuts it. Runs on the
    /// caller's task and releases `permit` when it returns.
    pub async fn serve<S>(&self, permit: ConnectionPermit, stream: S)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let Some(watcher) = self.watcher() else {
            debug!("OTLP receiver: stream arrived during shutdown, dropping");
            return;
        };

        let buf_tx = self.buf_tx.clone();
        let metadata = self.metadata.clone();
        let enrichment_enabled = self.enrichment_enabled;
        let svc = service_fn(move |req| {
            let buf_tx = buf_tx.clone();
            let metadata = metadata.clone();
            async move { handle_request(req, &buf_tx, &metadata, enrichment_enabled).await }
        });

        let mut builder = http1::Builder::new();
        // A timer is mandatory once any timeout is configured; hyper panics in
        // `serve_connection` otherwise.
        builder
            .timer(TokioTimer::new())
            .header_read_timeout(HEADER_READ_TIMEOUT);
        let conn = watcher.watch(builder.serve_connection(TokioIo::new(stream), svc));

        let mut abort_rx = self.abort_rx.clone();
        tokio::select! {
            result = conn => {
                if let Err(e) = result {
                    debug!(error = %e, "OTLP HTTP connection error");
                }
            }
            _ = abort_rx.wait_for(|aborted| *aborted) => {
                debug!("OTLP receiver: aborting connection after graceful timeout");
            }
        }
        drop(permit);
    }
}

impl ReceiverHandle {
    /// Stop accepting new streams, disable keep-alive on every open
    /// connection, wait up to [`RECEIVER_SHUTDOWN_TIMEOUT`] for in-flight
    /// requests, then cut stragglers. Always returns within roughly the
    /// timeout. A second call is a no-op.
    pub async fn shutdown(self) {
        let Some(graceful) = lock(&self.server.graceful).take() else {
            return;
        };
        if tokio::time::timeout(RECEIVER_SHUTDOWN_TIMEOUT, graceful.shutdown())
            .await
            .is_err()
        {
            warn!(
                open_connections =
                    MAX_CONCURRENT_CONNECTIONS - self.server.connections.available_permits(),
                "OTLP receiver: aborting connections still open after graceful timeout"
            );
            self.abort_tx.send_replace(true);
        }
    }
}

async fn handle_request(
    req: Request<Incoming>,
    buf_tx: &TelemetrySender,
    metadata: &SandboxMetadata,
    enrichment_enabled: bool,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.method() != Method::POST || req.uri().path() != "/v1/traces" {
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("{\"error\":\"not found\"}")))
            .unwrap());
    }

    let Some(content_type) = parse_content_type(req.headers()) else {
        return Ok(Response::builder()
            .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
            .body(Full::new(Bytes::from(
                "{\"error\":\"unsupported content type\"}",
            )))
            .unwrap());
    };

    let limited = http_body_util::Limited::new(req.into_body(), MAX_BODY_SIZE);
    let body = match http_body_util::BodyExt::collect(limited).await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            let status = if e.to_string().contains("length limit exceeded") {
                warn!("OTLP request body exceeds 4 MiB limit");
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                warn!(error = %e, "failed to read OTLP request body");
                StatusCode::BAD_REQUEST
            };
            return Ok(Response::builder()
                .status(status)
                .body(Full::new(Bytes::from(
                    "{\"error\":\"failed to read body\"}",
                )))
                .unwrap());
        }
    };

    match enrichment::enrich_spans(&body, content_type, metadata, enrichment_enabled) {
        Ok(enriched) => {
            buf_tx.send_trace(enriched);
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/x-protobuf")
                .body(Full::new(Bytes::new()))
                .unwrap())
        }
        Err(EnrichmentError::ProtobufDecode(e)) => {
            warn!(error = %e, "malformed protobuf OTLP request");
            Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from(
                    "{\"error\":\"malformed protobuf request\"}",
                )))
                .unwrap())
        }
        Err(EnrichmentError::JsonDecode(e)) => {
            warn!(error = %e, "malformed JSON OTLP request");
            Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from(
                    "{\"error\":\"malformed JSON request\"}",
                )))
                .unwrap())
        }
    }
}

fn parse_content_type(headers: &hyper::HeaderMap) -> Option<ContentType> {
    let ct = headers.get("content-type")?.to_str().ok()?;
    if ct.starts_with("application/x-protobuf") {
        Some(ContentType::Protobuf)
    } else if ct.starts_with("application/json") {
        Some(ContentType::Json)
    } else {
        None
    }
}

/// In-memory HTTP helpers shared by the receiver and lifecycle tests. They
/// stand in for the boundary duplex stream the proxy hands over in
/// production.
#[cfg(test)]
pub(crate) mod test_util {
    use std::sync::Arc;
    use std::time::Duration;

    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
    use prost::Message;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

    use super::OtlpConnectionServer;
    use crate::otlp::SandboxMetadata;

    pub fn metadata() -> SandboxMetadata {
        SandboxMetadata {
            sandbox_id: "sb-test".into(),
            workspace_id: "ws-test".into(),
            policy: "policy".into(),
            user: "1000".into(),
            image: "image".into(),
            driver: "docker".into(),
        }
    }

    /// A minimal but non-empty protobuf `ExportTraceServiceRequest`.
    pub fn sample_trace_body() -> Vec<u8> {
        ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                scope_spans: vec![ScopeSpans {
                    spans: vec![Span {
                        name: "test-span".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
        .encode_to_vec()
    }

    pub fn request(method: &str, path: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        req.extend_from_slice(body);
        req
    }

    /// Open a client stream whose server half is served on a spawned task,
    /// the way the proxy hook serves a staged boundary stream.
    pub fn connect(server: &Arc<OtlpConnectionServer>) -> DuplexStream {
        let (client, server_half) = tokio::io::duplex(64 * 1024);
        let permit = server.try_reserve().expect("connection slot");
        let server = Arc::clone(server);
        tokio::spawn(async move { server.serve(permit, server_half).await });
        client
    }

    /// Write `req` and read until the response head is complete. Returns the
    /// status line; the stream stays open.
    pub async fn send<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, req: &[u8]) -> String {
        stream.write_all(req).await.expect("write request");
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
                .await
                .expect("response within 5s")
                .expect("read response");
            assert!(n > 0, "connection closed before response head");
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let head = String::from_utf8_lossy(&buf);
        head.lines().next().unwrap_or_default().to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::test_util::{connect, metadata, request, sample_trace_body, send};
    use super::*;
    use crate::otlp::buffer::{TelemetryReceiver, new_telemetry_buffer};

    fn start() -> (Arc<OtlpConnectionServer>, ReceiverHandle, TelemetryReceiver) {
        let (buf_tx, buf_rx) = new_telemetry_buffer(16);
        let (server, handle) = OtlpConnectionServer::new(buf_tx, metadata(), true);
        (server, handle, buf_rx)
    }

    #[tokio::test]
    async fn shutdown_completes_with_idle_keepalive_connection() {
        let (server, handle, buf_rx) = start();

        let mut client = connect(&server);
        let status = send(
            &mut client,
            &request(
                "POST",
                "/v1/traces",
                "application/x-protobuf",
                &sample_trace_body(),
            ),
        )
        .await;
        assert!(status.contains("200"), "unexpected status: {status}");
        assert_eq!(buf_rx.metrics().depth(), 1);

        // The client keeps the HTTP/1.1 connection open. Shutdown must not
        // wait for it to go away on its own.
        let deadline = RECEIVER_SHUTDOWN_TIMEOUT + Duration::from_secs(1);
        tokio::time::timeout(deadline, handle.shutdown())
            .await
            .expect("shutdown must complete despite an open keep-alive connection");

        // The server closed the idle connection.
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .expect("server close within 2s")
            .unwrap_or(0);
        assert_eq!(n, 0, "expected EOF from server after shutdown");
    }

    #[tokio::test]
    async fn shutdown_completes_with_half_sent_headers() {
        let (server, handle, _buf_rx) = start();

        let mut client = connect(&server);
        client
            .write_all(b"POST /v1/traces HTTP/1.1\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let deadline = RECEIVER_SHUTDOWN_TIMEOUT + Duration::from_secs(1);
        tokio::time::timeout(deadline, handle.shutdown())
            .await
            .expect("shutdown must complete with an in-progress request");
    }

    #[tokio::test]
    async fn status_codes_for_not_found_unsupported_media_type_and_ok() {
        let (server, handle, buf_rx) = start();

        let mut client = connect(&server);
        let status = send(
            &mut client,
            &request("GET", "/v1/traces", "application/x-protobuf", b""),
        )
        .await;
        assert!(status.contains("404"), "GET should be 404, got {status}");

        let mut client = connect(&server);
        let status = send(
            &mut client,
            &request("POST", "/v1/traces", "text/plain", b"x"),
        )
        .await;
        assert!(
            status.contains("415"),
            "text/plain should be 415, got {status}"
        );

        let mut client = connect(&server);
        let status = send(
            &mut client,
            &request(
                "POST",
                "/v1/traces",
                "application/x-protobuf",
                &sample_trace_body(),
            ),
        )
        .await;
        assert!(
            status.contains("200"),
            "valid protobuf should be 200, got {status}"
        );
        assert_eq!(buf_rx.metrics().depth(), 1);

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn try_reserve_refuses_beyond_max_connections_and_recovers() {
        let (server, _handle, _buf_rx) = start();

        let mut permits: Vec<ConnectionPermit> = (0..MAX_CONCURRENT_CONNECTIONS)
            .map(|i| server.try_reserve().unwrap_or_else(|| panic!("slot {i}")))
            .collect();
        assert!(
            server.try_reserve().is_none(),
            "slot beyond the maximum must be refused"
        );

        drop(permits.pop());
        assert!(
            server.try_reserve().is_some(),
            "a released slot is available again"
        );
    }

    #[tokio::test]
    async fn try_reserve_refuses_after_shutdown() {
        let (server, handle, _buf_rx) = start();
        assert!(server.try_reserve().is_some());

        handle.shutdown().await;
        assert!(
            server.try_reserve().is_none(),
            "no new streams once shutdown has started"
        );
    }
}
