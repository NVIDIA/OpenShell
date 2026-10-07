// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared OTLP collector fixture for `OpenShell` tracing tests.

/// Helpers for tests that exercise the supervisor's agent trace relay from
/// the agent side: the attribution keys the relay sets and a builder for the
/// protobuf export request an SDK would send.
pub mod relay {
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
    use opentelemetry_proto::tonic::resource::v1::Resource;
    use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
    use prost::Message;

    /// Resource attribute the relay sets to the sandbox id.
    pub const SANDBOX_ID_KEY: &str = "openshell.sandbox.id";
    /// Resource attribute the relay sets to mark agent-originated traces.
    pub const SOURCE_KEY: &str = "openshell.telemetry.source";
    /// Value of [`SOURCE_KEY`] on relayed traces.
    pub const SOURCE_VALUE: &str = "agent";

    /// A string resource or span attribute.
    #[must_use]
    pub fn string_attribute(key: &str, value: &str) -> KeyValue {
        KeyValue {
            key: key.to_string(),
            value: Some(AnyValue {
                value: Some(any_value::Value::StringValue(value.to_string())),
            }),
            key_strindex: 0,
        }
    }

    /// Protobuf-encoded `ExportTraceServiceRequest` with one span named
    /// `span_name` and the given string resource attributes.
    #[must_use]
    pub fn encoded_trace_request(span_name: &str, attributes: &[(&str, &str)]) -> Vec<u8> {
        ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(Resource {
                    attributes: attributes
                        .iter()
                        .map(|(key, value)| string_attribute(key, value))
                        .collect(),
                    ..Default::default()
                }),
                scope_spans: vec![ScopeSpans {
                    spans: vec![Span {
                        name: span_name.to_string(),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
        .encode_to_vec()
    }
}

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
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
    /// One map per received `ResourceSpans`, holding its string-valued
    /// resource attributes.
    pub resource_attributes: Vec<HashMap<String, String>>,
    /// The resource attributes of the batch each entry of `spans` arrived
    /// in, aligned index by index with `spans`.
    pub span_resources: Vec<HashMap<String, String>>,
    /// Resource attribute keys that appeared more than once within a single
    /// resource. The maps above keep only the last value for such a key, so
    /// tests that assert a value was replaced rather than appended must also
    /// assert this list is empty.
    pub duplicate_resource_keys: Vec<String>,
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
                let mut attributes = HashMap::new();
                let mut seen_keys = HashSet::new();
                if let Some(resource) = resource_span.resource {
                    for attribute in resource.attributes {
                        // Track duplicates for every value type; the string
                        // map below keeps only the last value per key.
                        if !seen_keys.insert(attribute.key.clone()) {
                            received.duplicate_resource_keys.push(attribute.key.clone());
                        }
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
                            "service.name" => received.service_names.push(value.clone()),
                            "openshell.gateway.name" => received.gateway_names.push(value.clone()),
                            "openshell.gateway.compute_driver" => {
                                received.compute_drivers.push(value.clone());
                            }
                            _ => {}
                        }
                        attributes.insert(attribute.key, value);
                    }
                }
                for scope_span in resource_span.scope_spans {
                    for span in scope_span.spans {
                        received.spans.push(span);
                        received.span_resources.push(attributes.clone());
                    }
                }
                received.resource_attributes.push(attributes);
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
    /// Starts the collector on an ephemeral loopback port.
    pub async fn start() -> Self {
        Self::start_on(SocketAddr::from(([127, 0, 0, 1], 0))).await
    }

    /// Starts the collector on a fixed address, for tests whose peer learned
    /// the collector endpoint before the collector existed.
    pub async fn start_on(addr: SocketAddr) -> Self {
        Self::try_start_on(addr)
            .await
            .expect("OTLP test collector should bind its listener")
    }

    /// [`Self::start_on`] that reports a bind failure instead of panicking,
    /// so a test can retry with another port when a parallel test took it.
    pub async fn try_start_on(addr: SocketAddr) -> std::io::Result<Self> {
        let received = Arc::new(Mutex::new(ReceivedTraces::default()));
        let exported = Arc::new(tokio::sync::Notify::new());
        let listener = tokio::net::TcpListener::bind(addr).await?;
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
        Ok(Self {
            endpoint,
            received,
            exported,
            shutdown,
            task,
        })
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

    /// Snapshot of everything received so far, without stopping the server.
    #[must_use]
    pub fn received(&self) -> ReceivedTraces {
        self.received
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
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
