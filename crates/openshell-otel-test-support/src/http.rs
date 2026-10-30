// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Loopback OTLP/HTTP collector that records every request.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt as _;

/// One request received by [`OtlpHttpTestServer`].
#[derive(Clone, Debug)]
pub struct HttpExport {
    pub method: http::Method,
    pub path: String,
    pub headers: http::HeaderMap,
    pub body: Bytes,
}

/// A loopback OTLP/HTTP collector that records every request and answers
/// each with a fixed status.
pub struct OtlpHttpTestServer {
    endpoint: String,
    exports: tokio::sync::mpsc::UnboundedReceiver<HttpExport>,
    task: tokio::task::JoinHandle<()>,
}

impl OtlpHttpTestServer {
    /// Starts the collector on an ephemeral loopback port, answering 200.
    pub async fn start() -> Self {
        Self::start_with_status(http::StatusCode::OK).await
    }

    /// Starts the collector, answering every request with `status`.
    pub async fn start_with_status(status: http::StatusCode) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("OTLP/HTTP test collector should bind a loopback listener");
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (tx, exports) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let tx = tx.clone();
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(
                        move |request: http::Request<hyper::body::Incoming>| {
                            let tx = tx.clone();
                            async move {
                                let (parts, body) = request.into_parts();
                                let body = body.collect().await?.to_bytes();
                                let _ = tx.send(HttpExport {
                                    method: parts.method,
                                    path: parts.uri.path().to_string(),
                                    headers: parts.headers,
                                    body,
                                });
                                let mut response =
                                    http::Response::new(http_body_util::Full::new(Bytes::new()));
                                *response.status_mut() = status;
                                Ok::<_, hyper::Error>(response)
                            }
                        },
                    );
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self {
            endpoint,
            exports,
            task,
        }
    }

    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The next request, waiting up to five seconds for it.
    pub async fn next_export(&mut self) -> HttpExport {
        tokio::time::timeout(Duration::from_secs(5), self.exports.recv())
            .await
            .expect("OTLP/HTTP export should arrive")
            .expect("OTLP/HTTP test collector is running")
    }
}

impl Drop for OtlpHttpTestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
