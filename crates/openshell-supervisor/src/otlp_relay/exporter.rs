// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OTLP/gRPC forwarder for enriched agent batches.
//!
//! The channel connects lazily so an unreachable collector never fails
//! startup, and tonic re-establishes it on later attempts. Batches are sent
//! as the already-encoded bytes the receiver produced: the agent-controlled
//! payload is never decoded into a span tree on the export path.

use std::time::Duration;

use bytes::{BufMut as _, Bytes};
use http::uri::PathAndQuery;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceResponse;
use prost::Message;
use tonic::client::Grpc;
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::transport::{Channel, Endpoint};
use tonic::{GrpcMethod, Status};

use super::EXPORT_TIMEOUT;

/// TCP connect deadline, applied per resolved address by hyper, kept well
/// under [`EXPORT_TIMEOUT`] so the batch that triggers a failed connect
/// usually observes the connect error rather than a request timeout. DNS
/// resolution is bounded only by [`EXPORT_TIMEOUT`].
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// HTTP/2 PING cadence while an export is in flight. Pings are never sent on
/// an idle connection: stock collectors (grpc-go) close connections that
/// ping without an open stream.
const HTTP2_PING_INTERVAL: Duration = Duration::from_secs(2);
/// Unanswered-PING deadline; together with the interval it closes a dead
/// connection inside [`EXPORT_TIMEOUT`] so the next export redials.
const HTTP2_PING_TIMEOUT: Duration = Duration::from_secs(2);
/// TCP keepalive idle time, probe interval, and probe count for idle
/// connections, where HTTP/2 pings are not allowed. Detects a vanished peer
/// in about 30 seconds on Linux.
const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(15);
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
const TCP_KEEPALIVE_RETRIES: u32 = 3;

const SERVICE: &str = "opentelemetry.proto.collector.trace.v1.TraceService";
const METHOD: &str = "Export";
const PATH: &str = "/opentelemetry.proto.collector.trace.v1.TraceService/Export";

/// One export attempt failed. The batch is discarded by the caller.
#[derive(Debug)]
pub enum ExportError {
    /// The collector answered with an error or the transport failed.
    Status(Status),
    /// No answer within [`EXPORT_TIMEOUT`].
    Timeout,
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Status(status) => write!(f, "{}: {}", status.code(), status.message()),
            Self::Timeout => write!(f, "no response within {EXPORT_TIMEOUT:?}"),
        }
    }
}

impl std::error::Error for ExportError {}

/// Forwards encoded `ExportTraceServiceRequest` batches to one collector.
pub struct Exporter {
    client: Grpc<Channel>,
    endpoint: String,
}

impl Exporter {
    /// Prepares a lazy channel to `endpoint`. Fails only when the endpoint is
    /// not a valid URI; no I/O happens here.
    pub fn new(endpoint: &str) -> Result<Self, tonic::transport::Error> {
        // Liveness detection for a collector that accepted the TCP connection
        // and then went silent or vanished without a FIN, so the lazy channel
        // redials instead of timing out every batch on a dead connection for
        // the sandbox lifetime. HTTP/2 pings run only while an export is in
        // flight; TCP keepalive covers idle connections. Detection of a dead
        // connection during an export is covered by the silent-collector
        // test; idle detection runs on the TCP keepalive timers and has no
        // unit test, because those intervals are real-time constants.
        //
        // Deliberately not built on `openshell_extension_core::transport`:
        // that recipe connects eagerly, pings idle connections, and carries a
        // first-party TLS trust policy, none of which fit a third-party
        // collector that must not gate supervisor startup.
        let channel = Endpoint::from_shared(endpoint.to_string())?
            .connect_timeout(CONNECT_TIMEOUT)
            .tcp_keepalive(Some(TCP_KEEPALIVE_IDLE))
            .tcp_keepalive_interval(Some(TCP_KEEPALIVE_INTERVAL))
            .tcp_keepalive_retries(Some(TCP_KEEPALIVE_RETRIES))
            .http2_keep_alive_interval(HTTP2_PING_INTERVAL)
            .keep_alive_timeout(HTTP2_PING_TIMEOUT)
            .connect_lazy();
        Ok(Self {
            client: Grpc::new(channel),
            endpoint: endpoint.to_string(),
        })
    }

    /// The collector URI this exporter targets.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Sends one encoded batch, bounded by [`EXPORT_TIMEOUT`].
    pub async fn export(&self, batch: Bytes) -> Result<(), ExportError> {
        let mut client = self.client.clone();
        let send = async move {
            client.ready().await.map_err(|error| {
                Status::unavailable(format!("collector channel not ready: {error}"))
            })?;
            let mut request = tonic::Request::new(batch);
            request
                .extensions_mut()
                .insert(GrpcMethod::new(SERVICE, METHOD));
            client
                .unary(request, PathAndQuery::from_static(PATH), PassthroughCodec)
                .await
        };
        match tokio::time::timeout(EXPORT_TIMEOUT, send).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(status)) => Err(ExportError::Status(status)),
            Err(_) => Err(ExportError::Timeout),
        }
    }
}

/// gRPC codec that writes a pre-encoded request body as-is and decodes the
/// collector's `ExportTraceServiceResponse`.
struct PassthroughCodec;

impl Codec for PassthroughCodec {
    type Encode = Bytes;
    type Decode = ExportTraceServiceResponse;
    type Encoder = PassthroughEncoder;
    type Decoder = ResponseDecoder;

    fn encoder(&mut self) -> Self::Encoder {
        PassthroughEncoder
    }

    fn decoder(&mut self) -> Self::Decoder {
        ResponseDecoder
    }
}

struct PassthroughEncoder;

impl Encoder for PassthroughEncoder {
    type Item = Bytes;
    type Error = Status;

    fn encode(&mut self, item: Bytes, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
        dst.put(item);
        Ok(())
    }
}

struct ResponseDecoder;

impl Decoder for ResponseDecoder {
    type Item = ExportTraceServiceResponse;
    type Error = Status;

    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Status> {
        ExportTraceServiceResponse::decode(src)
            .map(Some)
            .map_err(|error| Status::internal(format!("malformed export response: {error}")))
    }
}

/// Collector doubles shared with the lifecycle tests in the parent module.
#[cfg(test)]
pub mod test_util {
    /// A loopback listener that accepts TCP connections and never answers,
    /// so an export's HTTP/2 PING goes unanswered. Deterministic on every
    /// platform, unlike an unroutable address.
    pub struct SilentCollector {
        pub endpoint: String,
        task: tokio::task::JoinHandle<()>,
    }

    impl SilentCollector {
        pub async fn start() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let task = tokio::spawn(async move {
                // Accepted streams are kept open, never read, so the peer's
                // HTTP/2 handshake waits forever.
                #[allow(clippy::collection_is_never_read)]
                let mut held = Vec::new();
                loop {
                    if let Ok((stream, _)) = listener.accept().await {
                        held.push(stream);
                    }
                }
            });
            Self { endpoint, task }
        }
    }

    impl Drop for SilentCollector {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use openshell_otel_test_support::OtlpTestServer;

    use super::super::enrichment::test_util::encoded_request;
    use super::test_util::SilentCollector;
    use super::*;

    #[test]
    fn new_rejects_an_invalid_uri() {
        assert!(Exporter::new("not a uri").is_err());
    }

    #[tokio::test]
    async fn export_reaches_the_collector_with_attributes_intact() {
        let collector = OtlpTestServer::start().await;
        let exporter = Exporter::new(collector.endpoint()).unwrap();
        let batch = Bytes::from(encoded_request(
            "exported-span",
            &[("service.name", "unit-agent"), ("custom", "kept")],
        ));

        exporter.export(batch).await.expect("export succeeds");
        collector.wait_for_export().await;
        let received = collector.shutdown().await;

        assert!(
            received
                .spans
                .iter()
                .any(|span| span.name == "exported-span")
        );
        assert_eq!(received.resource_attributes.len(), 1);
        let attributes = &received.resource_attributes[0];
        assert_eq!(
            attributes.get("service.name").map(String::as_str),
            Some("unit-agent")
        );
        assert_eq!(attributes.get("custom").map(String::as_str), Some("kept"));
    }

    #[tokio::test]
    async fn export_to_a_closed_port_returns_status_promptly() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let exporter = Exporter::new(&endpoint).unwrap();

        let started = Instant::now();
        let error = exporter
            .export(Bytes::from(encoded_request("s", &[])))
            .await
            .expect_err("closed port fails");
        assert!(matches!(error, ExportError::Status(_)), "{error}");
        assert!(started.elapsed() < EXPORT_TIMEOUT);
    }

    #[tokio::test]
    async fn export_to_a_silent_collector_fails_when_its_ping_goes_unanswered() {
        // The collector accepts TCP and never speaks. With an export in
        // flight, hyper pings after HTTP2_PING_INTERVAL and closes the
        // connection after HTTP2_PING_TIMEOUT, so the failure is a transport
        // error inside the export deadline rather than a 5 s timeout, and
        // the lazy channel is left closed for the next export to redial.
        let collector = SilentCollector::start().await;
        let exporter = Exporter::new(&collector.endpoint).unwrap();
        let started = Instant::now();
        let error = exporter
            .export(Bytes::from(encoded_request("s", &[])))
            .await
            .expect_err("silent collector fails");
        assert!(matches!(error, ExportError::Status(_)), "{error}");
        let elapsed = started.elapsed();
        assert!(
            elapsed >= HTTP2_PING_INTERVAL && elapsed < EXPORT_TIMEOUT,
            "elapsed {elapsed:?}"
        );
    }
}
