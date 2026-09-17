// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Binds the OTLP relay server to the proxy's reserved-destination hook.

use std::net::SocketAddr;
use std::sync::Arc;

use openshell_isolation_interface::contract::BoundaryDuplexStream;
use openshell_supervisor_network::proxy::{
    ReservedDestination, ReservedStreamFuture, ReservedStreamHandler,
};
use openshell_supervisor_process::otlp::OtlpConnectionServer;

/// Serves staged workload connections to the relay address with the OTLP
/// connection server.
struct OtlpRelayHandler(Arc<OtlpConnectionServer>);

impl ReservedStreamHandler for OtlpRelayHandler {
    fn serve(&self, stream: BoundaryDuplexStream) -> Option<ReservedStreamFuture> {
        // Reserve before the proxy answers `RelayReady`, so an exhausted or
        // stopped server refuses the open instead of resetting it later.
        let permit = self.0.try_reserve()?;
        let server = Arc::clone(&self.0);
        Some(Box::pin(async move { server.serve(permit, stream).await }))
    }
}

/// The reserved destination the proxy serves with `server`.
pub fn reserved_destination(server: Arc<OtlpConnectionServer>) -> ReservedDestination {
    let addr: SocketAddr = openshell_core::sandbox_env::OTLP_RELAY_ADDR
        .parse()
        .expect("OTLP_RELAY_ADDR is a valid socket address");
    ReservedDestination {
        addr,
        handler: Arc::new(OtlpRelayHandler(server)),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
    use prost::Message;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use openshell_supervisor_process::otlp::{RelayConfig, SandboxMetadata};

    use super::*;

    fn metadata() -> SandboxMetadata {
        SandboxMetadata {
            sandbox_id: "sb-test".into(),
            workspace_id: "ws-test".into(),
            policy: "policy".into(),
            user: "1000".into(),
            image: String::new(),
            driver: "kubernetes".into(),
        }
    }

    /// A minimal but non-empty protobuf `ExportTraceServiceRequest`.
    fn sample_trace_body() -> Vec<u8> {
        ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                scope_spans: vec![ScopeSpans {
                    spans: vec![Span {
                        name: "relay-span".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
        .encode_to_vec()
    }

    #[tokio::test]
    async fn reserved_destination_serves_otlp_over_a_boundary_stream() {
        let (server, relay) =
            openshell_supervisor_process::otlp::start(&RelayConfig::default(), metadata());
        let reserved = reserved_destination(server);
        assert_eq!(
            reserved.addr.to_string(),
            openshell_core::sandbox_env::OTLP_RELAY_ADDR
        );

        let (mut client, boundary) = tokio::io::duplex(64 * 1024);
        let serve_future = reserved
            .handler
            .serve(Box::new(boundary))
            .expect("a fresh server accepts a stream");
        let conn = tokio::spawn(serve_future);

        let body = sample_trace_body();
        let request = format!(
            "POST /v1/traces HTTP/1.1\r\nHost: relay\r\nContent-Type: application/x-protobuf\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        client.write_all(request.as_bytes()).await.unwrap();
        client.write_all(&body).await.unwrap();

        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response))
            .await
            .expect("response within 5s")
            .unwrap();
        let head = String::from_utf8_lossy(&response);
        assert!(
            head.starts_with("HTTP/1.1 200"),
            "expected 200 from the relay, got: {head}"
        );
        assert_eq!(relay.buffer_metrics().unwrap().depth(), 1);

        tokio::time::timeout(Duration::from_secs(5), conn)
            .await
            .expect("connection task ends after Connection: close")
            .unwrap();
    }

    #[tokio::test]
    async fn reserved_destination_refuses_streams_once_the_relay_is_drained() {
        let (server, mut relay) =
            openshell_supervisor_process::otlp::start(&RelayConfig::default(), metadata());
        let reserved = reserved_destination(server);
        let (tx, _rx) = tokio::sync::mpsc::channel(4);
        relay.stop_and_drain("sb-test", &tx).await;

        let (_client, boundary) = tokio::io::duplex(1024);
        assert!(
            reserved.handler.serve(Box::new(boundary)).is_none(),
            "the proxy must refuse the open rather than reset it after RelayReady"
        );
    }
}
