// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Collector transport shared by every OTLP exporter.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use opentelemetry_http::{HttpClient, HttpError};

/// TCP connect deadline for a collector.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// TCP keepalive idle time, probe interval, and probe count, so a collector
/// that vanished without a FIN is noticed on an idle connection.
const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(15);
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
const TCP_KEEPALIVE_RETRIES: u32 = 3;
/// Largest collector response body read.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Per-request export deadline when the environment sets none, as for the
/// SDK's own HTTP clients.
const DEFAULT_EXPORT_TIMEOUT: Duration = Duration::from_secs(10);

/// The export deadline from `signal_var` (such as
/// `OTEL_EXPORTER_OTLP_TRACES_TIMEOUT`), else `OTEL_EXPORTER_OTLP_TIMEOUT`,
/// in milliseconds.
pub fn export_timeout(signal_var: &str) -> Duration {
    [signal_var, "OTEL_EXPORTER_OTLP_TIMEOUT"]
        .into_iter()
        .find_map(|name| std::env::var(name).ok()?.trim().parse().ok())
        .map_or(DEFAULT_EXPORT_TIMEOUT, Duration::from_millis)
}

/// The URL of `signal_path` (such as `v1/traces`) under `endpoint`, treated
/// as a base URL the way SDKs treat `OTEL_EXPORTER_OTLP_ENDPOINT`. A query
/// string is kept.
pub fn signal_url(endpoint: &str, signal_path: &str) -> Result<http::Uri, http::Error> {
    let mut parts = endpoint.parse::<http::Uri>()?.into_parts();
    let (base, query) = parts
        .path_and_query
        .as_ref()
        .map_or(("", None), |path| (path.path(), path.query()));
    let base = base.trim_end_matches('/');
    let query = query.map_or_else(String::new, |query| format!("?{query}"));
    parts.path_and_query = Some(format!("{base}/{signal_path}{query}").parse()?);
    Ok(http::Uri::from_parts(parts)?)
}

/// HTTP client for OTLP/HTTP collectors.
///
/// Requests run on the tokio runtime the client was created in, so SDK
/// exporters can use it from their own export threads.
#[derive(Clone, Debug)]
pub struct OtlpHttpClient {
    client: Client<HttpConnector, Full<Bytes>>,
    runtime: tokio::runtime::Handle,
    timeout: Duration,
}

impl OtlpHttpClient {
    /// Creates a client bound to the current tokio runtime whose requests
    /// fail after `timeout`. Fails outside a runtime.
    pub fn new(timeout: Duration) -> Result<Self, crate::SetupError> {
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| crate::SetupError::NoRuntime)?;
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(CONNECT_TIMEOUT));
        connector.set_keepalive(Some(TCP_KEEPALIVE_IDLE));
        connector.set_keepalive_interval(Some(TCP_KEEPALIVE_INTERVAL));
        connector.set_keepalive_retries(Some(TCP_KEEPALIVE_RETRIES));
        connector.set_nodelay(true);
        Ok(Self {
            client: Client::builder(TokioExecutor::new()).build(connector),
            runtime,
            timeout,
        })
    }

    /// Sends `request` and returns the response with its body, which fails
    /// the request when it is incomplete or larger than 64 KiB. The request
    /// stops when the timeout passes or the returned future is dropped.
    pub async fn send(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        let (client, timeout) = (self.client.clone(), self.timeout);
        let mut task = AbortOnDrop(self.runtime.spawn(async move {
            tokio::time::timeout(timeout, async move {
                let response = client.request(request.map(Full::new)).await?;
                let (parts, body) = response.into_parts();
                let body = Limited::new(body, MAX_RESPONSE_BYTES)
                    .collect()
                    .await?
                    .to_bytes();
                Ok(http::Response::from_parts(parts, body))
            })
            .await
            .map_err(|_| HttpError::from(format!("no response within {timeout:?}")))?
        }));
        (&mut task.0).await?
    }
}

/// Aborts the task when dropped, unlike a bare `JoinHandle`, which detaches.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[async_trait::async_trait]
impl HttpClient for OtlpHttpClient {
    async fn send_bytes(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        self.send(request).await
    }
}

#[cfg(test)]
mod tests {
    use openshell_otel_test_support::OtlpHttpTestServer;
    use opentelemetry::logs::{AnyValue, LogRecord as _, Logger as _, LoggerProvider as _};
    use opentelemetry::trace::{Tracer as _, TracerProvider as _};
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use prost::Message as _;

    use super::*;
    use crate::{OtlpExportConfig, OtlpTarget, Protocol, ServiceName};

    /// A loopback listener that accepts connections and never answers.
    async fn silent_collector() -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            #[allow(clippy::collection_is_never_read)]
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        (endpoint, task)
    }

    /// A collector that answers each request with `head` and `body`, then
    /// closes the connection.
    async fn answering_collector(
        head: &'static str,
        body: Vec<u8>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut request = [0; 4096];
                let _ = stream.read(&mut request).await;
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(&body).await;
            }
        });
        (endpoint, task)
    }

    fn post(endpoint: &str) -> http::Request<Bytes> {
        http::Request::post(signal_url(endpoint, "v1/traces").unwrap())
            .body(Bytes::new())
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn requests_fail_after_the_timeout() {
        let (endpoint, collector) = silent_collector().await;
        let client = OtlpHttpClient::new(Duration::from_millis(200)).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), client.send(post(&endpoint)))
            .await
            .expect("the client gives up on its own");
        assert!(result.is_err());
        collector.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn truncated_responses_fail() {
        let (endpoint, collector) = answering_collector(
            "HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n",
            b"partial".to_vec(),
        )
        .await;
        let client = OtlpHttpClient::new(Duration::from_secs(5)).unwrap();
        assert!(client.send(post(&endpoint)).await.is_err());
        collector.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn oversized_responses_fail() {
        let body = vec![b'x'; MAX_RESPONSE_BYTES + 1];
        let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", body.len());
        let (endpoint, collector) = answering_collector(head.leak(), body).await;
        let client = OtlpHttpClient::new(Duration::from_secs(5)).unwrap();
        assert!(client.send(post(&endpoint)).await.is_err());
        collector.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn abandoned_requests_stop() {
        let (endpoint, collector) = silent_collector().await;
        let client = OtlpHttpClient::new(Duration::from_mins(1)).unwrap();
        let alive = || {
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks()
        };
        let before = alive();
        for _ in 0..3 {
            let abandoned =
                tokio::time::timeout(Duration::from_millis(100), client.send(post(&endpoint)))
                    .await;
            assert!(abandoned.is_err(), "the collector never answers");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            alive() <= before,
            "{} tasks outlived their callers",
            alive() - before
        );
        collector.abort();
    }

    fn http_target(endpoint: &str) -> OtlpTarget {
        OtlpTarget::new(&OtlpExportConfig {
            endpoint,
            service_name: ServiceName::Fixed("openshell-test"),
            service_version: None,
            resource_attributes: Vec::new(),
        })
        .unwrap()
        .with_protocol(Protocol::HttpProtobuf)
    }

    #[test]
    fn signal_urls_extend_the_endpoint_path() {
        for (endpoint, url) in [
            ("http://collector:4318", "http://collector:4318/v1/traces"),
            ("http://collector:4318/", "http://collector:4318/v1/traces"),
            ("https://host/prefix", "https://host/prefix/v1/traces"),
            ("https://host/prefix/", "https://host/prefix/v1/traces"),
            (
                "http://host:4318/p?key=v",
                "http://host:4318/p/v1/traces?key=v",
            ),
        ] {
            assert_eq!(signal_url(endpoint, "v1/traces").unwrap().to_string(), url);
        }
        assert!(signal_url("not a uri", "v1/traces").is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn trace_provider_exports_over_http_from_the_batch_thread() {
        let mut collector = OtlpHttpTestServer::start().await;
        let provider = http_target(collector.endpoint())
            .with_headers(crate::parse_otlp_headers("x-mlflow-experiment-id=7"))
            .tracer_provider()
            .unwrap();
        provider.tracer("test").in_span("http-span", |_| {});
        let flush = tokio::task::spawn_blocking(move || provider.force_flush());

        let export = collector.next_export().await;
        assert_eq!(export.method, http::Method::POST);
        assert_eq!(export.headers["x-mlflow-experiment-id"], "7");
        assert_eq!(export.path, "/v1/traces");
        assert_eq!(
            export.headers[http::header::CONTENT_TYPE],
            "application/x-protobuf"
        );
        let request = ExportTraceServiceRequest::decode(export.body).unwrap();
        let span = &request.resource_spans[0].scope_spans[0].spans[0];
        assert_eq!(span.name, "http-span");
        flush.await.unwrap().expect("flush succeeds");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn log_exporter_sends_headers_over_http_from_a_blocking_thread() {
        let mut collector = OtlpHttpTestServer::start().await;
        let exporter = http_target(collector.endpoint())
            .with_headers(crate::parse_otlp_headers("authorization=Bearer%20token"))
            .log_exporter()
            .unwrap();
        let provider = opentelemetry_sdk::logs::SdkLoggerProvider::builder()
            .with_simple_exporter(exporter)
            .build();
        let emit = tokio::task::spawn_blocking(move || {
            let logger = provider.logger("test");
            let mut record = logger.create_log_record();
            record.set_body(AnyValue::from("ocsf-event"));
            logger.emit(record);
        });

        let export = collector.next_export().await;
        assert_eq!(export.path, "/v1/logs");
        assert_eq!(export.headers["authorization"], "Bearer token");
        let request = ExportLogsServiceRequest::decode(export.body).unwrap();
        let record = &request.resource_logs[0].scope_logs[0].log_records[0];
        assert!(format!("{:?}", record.body).contains("ocsf-event"));
        emit.await.unwrap();
    }
}
