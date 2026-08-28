// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared OTLP collector fixture for `OpenShell` tracing tests.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
    trace_service_server::{TraceService, TraceServiceServer},
};
use opentelemetry_proto::tonic::trace::v1::Span;

#[derive(Clone, Debug, Default)]
pub struct ReceivedTraces {
    pub spans: Vec<Span>,
    pub service_names: Vec<String>,
    pub gateway_names: Vec<String>,
}

#[derive(Clone)]
struct Collector {
    received: Arc<Mutex<ReceivedTraces>>,
    exported: Arc<tokio::sync::Notify>,
}

#[tonic::async_trait]
impl TraceService for Collector {
    async fn export(
        &self,
        request: tonic::Request<ExportTraceServiceRequest>,
    ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
        {
            let mut received = self
                .received
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for resource_span in request.into_inner().resource_spans {
                if let Some(resource) = resource_span.resource {
                    for attribute in resource.attributes {
                        let Some(value) = attribute.value.and_then(|value| value.value) else {
                            continue;
                        };
                        let opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(
                            value,
                        ) = value
                        else {
                            continue;
                        };
                        match attribute.key.as_str() {
                            "service.name" => received.service_names.push(value),
                            "openshell.gateway.name" => received.gateway_names.push(value),
                            _ => {}
                        }
                    }
                }
                for scope_span in resource_span.scope_spans {
                    received.spans.extend(scope_span.spans);
                }
            }
        }
        self.exported.notify_one();
        Ok(tonic::Response::new(ExportTraceServiceResponse::default()))
    }
}

/// Loopback OTLP/gRPC server that captures exported spans and resources.
pub struct OtlpTestServer {
    endpoint: String,
    received: Arc<Mutex<ReceivedTraces>>,
    exported: Arc<tokio::sync::Notify>,
    shutdown: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
}

impl OtlpTestServer {
    pub async fn start() -> Self {
        let received = Arc::new(Mutex::new(ReceivedTraces::default()));
        let exported = Arc::new(tokio::sync::Notify::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("OTLP test collector should bind a loopback listener");
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let collector = Collector {
            received: Arc::clone(&received),
            exported: Arc::clone(&exported),
        };
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(TraceServiceServer::new(collector))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = shutdown_rx.await;
                    },
                )
                .await
        });
        Self {
            endpoint,
            received,
            exported,
            shutdown,
            task,
        }
    }

    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub async fn wait_for_export(&self) {
        tokio::time::timeout(Duration::from_secs(5), self.exported.notified())
            .await
            .expect("OTLP export should complete");
    }

    pub async fn shutdown(self) -> ReceivedTraces {
        self.shutdown
            .send(())
            .expect("OTLP test collector should still be running");
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .expect("OTLP test collector shutdown should not deadlock")
            .expect("OTLP test collector task should not panic")
            .expect("OTLP test collector should shut down cleanly");
        self.received
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}
