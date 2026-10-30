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

use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, ExportLogsServiceResponse,
    logs_service_server::{LogsService, LogsServiceServer},
};
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
    trace_service_server::{TraceService, TraceServiceServer},
};
use opentelemetry_proto::tonic::common::v1::any_value::Value;
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::trace::v1::Span;

const LOOPBACK_EPHEMERAL: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);

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
    /// String bodies of exported log records.
    pub log_bodies: Vec<String>,
    /// `authorization` metadata of each log export request.
    pub log_authorizations: Vec<String>,
    pub service_names: Vec<String>,
    pub gateway_names: Vec<String>,
    pub compute_drivers: Vec<String>,
    pub encodings: Vec<String>,
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

impl ReceivedTraces {
    /// Records the well-known resource attributes and returns all
    /// string-valued ones, keeping the last value of a duplicated key.
    fn record_resource(&mut self, resource: Option<Resource>) -> HashMap<String, String> {
        let mut attributes = HashMap::new();
        let mut seen_keys = HashSet::new();
        for attribute in resource
            .into_iter()
            .flat_map(|resource| resource.attributes)
        {
            // Track duplicates for every value type; the string map keeps
            // only the last value per key.
            if !seen_keys.insert(attribute.key.clone()) {
                self.duplicate_resource_keys.push(attribute.key.clone());
            }
            let Some(Value::StringValue(value)) = attribute.value.and_then(|value| value.value)
            else {
                continue;
            };
            match attribute.key.as_str() {
                "service.name" => self.service_names.push(value.clone()),
                "openshell.gateway.name" => self.gateway_names.push(value.clone()),
                "openshell.gateway.compute_driver" => self.compute_drivers.push(value.clone()),
                _ => {}
            }
            attributes.insert(attribute.key, value);
        }
        attributes
    }
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
                let attributes = received.record_resource(resource_span.resource);
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

#[tonic::async_trait]
impl LogsService for Collector {
    async fn export(
        &self,
        request: tonic::Request<ExportLogsServiceRequest>,
    ) -> Result<tonic::Response<ExportLogsServiceResponse>, tonic::Status> {
        {
            let mut received = self
                .received
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(authorization) = request
                .metadata()
                .get("authorization")
                .and_then(|value| value.to_str().ok())
            {
                received.log_authorizations.push(authorization.to_string());
            }
            for resource_logs in request.into_inner().resource_logs {
                received.record_resource(resource_logs.resource);
                for scope_logs in resource_logs.scope_logs {
                    for record in scope_logs.log_records {
                        if let Some(Value::StringValue(body)) =
                            record.body.and_then(|body| body.value)
                        {
                            received.log_bodies.push(body);
                        }
                    }
                }
            }
        }
        self.exported.notify_one();
        Ok(tonic::Response::new(ExportLogsServiceResponse::default()))
    }
}

/// Loopback OTLP/gRPC server that captures exported spans, logs, and resources.
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
        Self::start_on(LOOPBACK_EPHEMERAL).await
    }

    /// Serve over TLS at `https://localhost:<port>` using `identity`.
    pub async fn start_tls(identity: tonic::transport::Identity) -> Self {
        Self::try_start_with(LOOPBACK_EPHEMERAL, Some(identity))
            .await
            .expect("OTLP test collector should bind a loopback listener")
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
        Self::try_start_with(addr, None).await
    }

    async fn try_start_with(
        addr: SocketAddr,
        identity: Option<tonic::transport::Identity>,
    ) -> std::io::Result<Self> {
        let received = Arc::new(Mutex::new(ReceivedTraces::default()));
        let exported = Arc::new(tokio::sync::Notify::new());
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        let endpoint = if identity.is_some() {
            format!("https://localhost:{}", local_addr.port())
        } else {
            format!("http://{local_addr}")
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
        let trace_service = TraceServiceServer::new(collector.clone())
            .accept_compressed(tonic::codec::CompressionEncoding::Gzip);
        let logs_service = LogsServiceServer::new(collector)
            .accept_compressed(tonic::codec::CompressionEncoding::Gzip);
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            server
                .add_service(trace_service)
                .add_service(logs_service)
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
