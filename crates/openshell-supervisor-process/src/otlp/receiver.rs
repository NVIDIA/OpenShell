// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OTLP HTTP receiver: accepts `POST /v1/traces` with protobuf or JSON.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tracing::{debug, warn};

use super::buffer::TelemetrySender;
use super::enrichment::{self, ContentType, EnrichmentError};
use super::{RECEIVER_SHUTDOWN_TIMEOUT, SandboxMetadata};

const MAX_CONCURRENT_CONNECTIONS: usize = 64;
const MAX_BODY_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

/// Time a client has to send request headers before the connection is closed.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Handle to the running receiver task.
pub struct ReceiverHandle {
    shutdown_tx: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl ReceiverHandle {
    /// Stop accepting, disable keep-alive on every open connection, wait up to
    /// [`RECEIVER_SHUTDOWN_TIMEOUT`] for in-flight requests, then abort
    /// stragglers. Always returns within roughly the timeout.
    pub async fn shutdown(self) {
        let abort = self.task.abort_handle();
        let _ = self.shutdown_tx.send(());
        let grace = RECEIVER_SHUTDOWN_TIMEOUT + Duration::from_millis(500);
        if tokio::time::timeout(grace, self.task).await.is_err() {
            warn!(
                ?grace,
                "OTLP receiver did not stop within grace period; aborting"
            );
            abort.abort();
        }
    }
}

/// Spawn the OTLP HTTP receiver on a pre-bound listener.
pub fn spawn_receiver(
    listener: TcpListener,
    buf_tx: TelemetrySender,
    metadata: SandboxMetadata,
    enrichment_enabled: bool,
) -> ReceiverHandle {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(run_receiver(
        listener,
        buf_tx,
        metadata,
        enrichment_enabled,
        shutdown_rx,
    ));
    ReceiverHandle { shutdown_tx, task }
}

async fn run_receiver(
    listener: TcpListener,
    buf_tx: TelemetrySender,
    metadata: SandboxMetadata,
    enrichment_enabled: bool,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    let conn_semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    // Every accepted connection is watched by `graceful`, so shutdown can
    // disable keep-alive on all of them at once, and tracked in `conns`, so
    // stragglers can be aborted once the grace period is over.
    let graceful = GracefulShutdown::new();
    let mut conns: JoinSet<()> = JoinSet::new();
    let mut builder = http1::Builder::new();
    // A timer is mandatory once any timeout is configured; hyper panics in
    // `serve_connection` otherwise.
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _peer)) => {
                        openshell_core::net::set_tcp_nodelay_best_effort(&stream);
                        let Ok(permit) = conn_semaphore.clone().try_acquire_owned() else {
                            debug!("OTLP receiver: max concurrent connections reached, dropping");
                            drop(stream);
                            continue;
                        };
                        let buf_tx = buf_tx.clone();
                        let metadata = metadata.clone();
                        let svc = service_fn(move |req| {
                            let buf_tx = buf_tx.clone();
                            let metadata = metadata.clone();
                            async move {
                                handle_request(req, &buf_tx, &metadata, enrichment_enabled).await
                            }
                        });
                        let conn = builder.serve_connection(TokioIo::new(stream), svc);
                        let watched = graceful.watcher().watch(conn);
                        conns.spawn(async move {
                            if let Err(e) = watched.await {
                                debug!(error = %e, "OTLP HTTP connection error");
                            }
                            drop(permit);
                        });
                    }
                    Err(e) => {
                        warn!(error = %e, "OTLP receiver accept error");
                    }
                }
            }
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
            _ = &mut shutdown_rx => {
                debug!("OTLP receiver shutting down");
                break;
            }
        }
    }

    drop(listener);
    if tokio::time::timeout(RECEIVER_SHUTDOWN_TIMEOUT, graceful.shutdown())
        .await
        .is_err()
    {
        warn!(
            open_connections = conns.len(),
            "OTLP receiver: aborting connections still open after graceful timeout"
        );
        conns.abort_all();
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

/// Raw-socket HTTP helpers shared by the receiver and lifecycle tests.
#[cfg(test)]
pub(crate) mod test_util {
    use std::net::SocketAddr;
    use std::time::Duration;

    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
    use prost::Message;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

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

    /// Write `req` and read until the response head is complete. Returns the
    /// open stream and the status line.
    pub async fn send(addr: SocketAddr, req: &[u8]) -> (TcpStream, String) {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
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
        let status = head.lines().next().unwrap_or_default().to_string();
        (stream, status)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::test_util::{metadata, request, sample_trace_body, send};
    use super::*;
    use crate::otlp::buffer::{TelemetryReceiver, new_telemetry_buffer};

    async fn start() -> (ReceiverHandle, SocketAddr, TelemetryReceiver) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (buf_tx, buf_rx) = new_telemetry_buffer(16);
        let handle = spawn_receiver(listener, buf_tx, metadata(), true);
        (handle, addr, buf_rx)
    }

    #[tokio::test]
    async fn shutdown_completes_with_idle_keepalive_connection() {
        let (handle, addr, buf_rx) = start().await;

        let body = sample_trace_body();
        let (mut stream, status) = send(
            addr,
            &request("POST", "/v1/traces", "application/x-protobuf", &body),
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
        let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
            .await
            .expect("server close within 2s")
            .unwrap_or(0);
        assert_eq!(n, 0, "expected EOF from server after shutdown");
    }

    #[tokio::test]
    async fn shutdown_completes_with_half_sent_headers() {
        let (handle, addr, _buf_rx) = start().await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
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
        let (handle, addr, buf_rx) = start().await;

        let (_s, status) = send(
            addr,
            &request("GET", "/v1/traces", "application/x-protobuf", b""),
        )
        .await;
        assert!(status.contains("404"), "GET should be 404, got {status}");

        let (_s, status) = send(addr, &request("POST", "/v1/traces", "text/plain", b"x")).await;
        assert!(
            status.contains("415"),
            "text/plain should be 415, got {status}"
        );

        let (_s, status) = send(
            addr,
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
}
