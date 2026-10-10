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

/// Serialize tracing tests and keep their callsites enabled process-wide.
pub async fn tracing_test_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    static INITIALIZED: std::sync::LazyLock<()> = std::sync::LazyLock::new(|| {
        tracing::subscriber::set_global_default(tracing_subscriber::registry())
            .expect("test tracing subscriber installs once");
    });

    let guard = LOCK.lock().await;
    std::sync::LazyLock::force(&INITIALIZED);
    guard
}

/// Verify one compute-driver descriptor exports spans and shared resources.
pub async fn assert_compute_driver_tracing(
    descriptor: openshell_otel::ComputeDriverTracing,
    service_version: &'static str,
    span_name: &'static str,
) {
    use tracing_subscriber::layer::SubscriberExt as _;

    let _tracing_lock = tracing_test_lock().await;
    let collector = OtlpTestServer::start().await;
    let (provider, error) = descriptor.provider_for(
        Some(collector.endpoint()),
        service_version,
        Some("test-gateway"),
        Some(descriptor.compute_driver()),
    );
    assert!(error.is_none(), "valid OTLP endpoint should configure");
    let provider = provider.expect("provider");
    let subscriber = tracing_subscriber::registry().with(descriptor.layer(&provider));
    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::info_span!("driver.test", otel.name = span_name);
        drop(span.enter());
        drop(span);
    });
    provider.force_flush().unwrap();
    collector.wait_for_export().await;
    provider.shutdown().unwrap();
    let received = collector.shutdown().await;

    assert!(received.spans.iter().any(|span| span.name == span_name));
    assert_eq!(received.gateway_names, ["test-gateway"]);
    assert_eq!(received.compute_drivers, [descriptor.compute_driver()]);
    assert!(
        received
            .service_names
            .iter()
            .any(|name| name == descriptor.service_name())
    );
}

#[derive(Clone, Debug, Default)]
pub struct ReceivedTraces {
    pub spans: Vec<Span>,
    pub service_names: Vec<String>,
    pub gateway_names: Vec<String>,
    pub compute_drivers: Vec<String>,
    pub encodings: Vec<String>,
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
            if let Some(encoding) = request
                .metadata()
                .get("grpc-encoding")
                .and_then(|value| value.to_str().ok())
            {
                received.encodings.push(encoding.to_string());
            }
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
                            "openshell.gateway.compute_driver" => {
                                received.compute_drivers.push(value);
                            }
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
        Self::start_with(None).await
    }

    /// Serve over TLS at `https://localhost:<port>` using `identity`.
    pub async fn start_tls(identity: tonic::transport::Identity) -> Self {
        Self::start_with(Some(identity)).await
    }

    async fn start_with(identity: Option<tonic::transport::Identity>) -> Self {
        let received = Arc::new(Mutex::new(ReceivedTraces::default()));
        let exported = Arc::new(tokio::sync::Notify::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("OTLP test collector should bind a loopback listener");
        let port = listener.local_addr().unwrap().port();
        let endpoint = if identity.is_some() {
            format!("https://localhost:{port}")
        } else {
            format!("http://127.0.0.1:{port}")
        };
        let collector = Collector {
            received: Arc::clone(&received),
            exported: Arc::clone(&exported),
        };
        let mut server = tonic::transport::Server::builder();
        if let Some(identity) = identity {
            server = server
                .tls_config(tonic::transport::ServerTlsConfig::new().identity(identity))
                .expect("OTLP test collector should accept its TLS identity");
        }
        let service = TraceServiceServer::new(collector)
            .accept_compressed(tonic::codec::CompressionEncoding::Gzip);
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            server
                .add_service(service)
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
