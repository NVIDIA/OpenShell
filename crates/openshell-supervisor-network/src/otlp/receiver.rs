// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OTLP HTTP receiver: accepts `POST /v1/traces` with protobuf or JSON.

use std::convert::Infallible;
use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tracing::{debug, warn};

use super::SandboxMetadata;
use super::buffer::TelemetrySender;
use super::enrichment::{self, ContentType, EnrichmentError};

/// Spawn the OTLP HTTP receiver using a pre-bound listener.
///
/// Used for netns topologies where the listener is bound inside the namespace.
pub fn spawn_receiver_with_listener(
    listener: TcpListener,
    buf_tx: TelemetrySender,
    metadata: SandboxMetadata,
    enrichment_enabled: bool,
    shutdown_rx: oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    spawn_receiver_inner(listener, buf_tx, metadata, enrichment_enabled, shutdown_rx)
}

/// Spawn the OTLP HTTP receiver by binding to the given address directly.
pub async fn spawn_receiver(
    bind_addr: SocketAddr,
    buf_tx: TelemetrySender,
    metadata: SandboxMetadata,
    enrichment_enabled: bool,
    shutdown_rx: oneshot::Receiver<()>,
) -> Result<tokio::task::JoinHandle<()>, std::io::Error> {
    let listener = TcpListener::bind(bind_addr).await?;
    Ok(spawn_receiver_inner(
        listener,
        buf_tx,
        metadata,
        enrichment_enabled,
        shutdown_rx,
    ))
}

fn spawn_receiver_inner(
    listener: TcpListener,
    buf_tx: TelemetrySender,
    metadata: SandboxMetadata,
    enrichment_enabled: bool,
    shutdown_rx: oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut shutdown_rx = shutdown_rx;

        loop {
            tokio::select! {
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, _peer)) => {
                            openshell_core::net::set_tcp_nodelay_best_effort(&stream);
                            let buf_tx = buf_tx.clone();
                            let metadata = metadata.clone();
                            tokio::spawn(async move {
                                let svc = service_fn(move |req| {
                                    let buf_tx = buf_tx.clone();
                                    let metadata = metadata.clone();
                                    async move {
                                        handle_request(req, &buf_tx, &metadata, enrichment_enabled).await
                                    }
                                });
                                if let Err(e) = http1::Builder::new()
                                    .serve_connection(TokioIo::new(stream), svc)
                                    .await
                                {
                                    debug!(error = %e, "OTLP HTTP connection error");
                                }
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "OTLP receiver accept error");
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    debug!("OTLP receiver shutting down");
                    break;
                }
            }
        }
    })
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

    let body = match http_body_util::BodyExt::collect(req.into_body()).await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            warn!(error = %e, "failed to read OTLP request body");
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
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
