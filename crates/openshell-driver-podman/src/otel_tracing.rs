// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenTelemetry trace exporting for the Podman compute driver.

use http::Request;
use openshell_otel::{
    HeaderMapExtractor, OtlpTraceConfig, RecordGrpcFailure, RecordGrpcStatus, SdkTracerProvider,
    ServiceName, SetupError,
};
use opentelemetry::propagation::TextMapPropagator as _;
use opentelemetry::trace::TraceContextExt as _;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tower_http::trace::{GrpcMakeClassifier, MakeSpan, TraceLayer};
use tracing::{Span, Subscriber};
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use tracing_subscriber::registry::LookupSpan;

const SERVICE_NAME: &str = "openshell-driver-podman";
const INSTRUMENTATION_SCOPE: &str = "openshell-driver-podman";
const COMPUTE_DRIVER_SERVICE: &str = "openshell.compute.v1.ComputeDriver";
pub const IN_PROCESS_TARGET_PREFIX: &str = "openshell_driver_podman";

pub fn compute_driver_rpc_layer() -> TraceLayer<
    GrpcMakeClassifier,
    ComputeDriverRpcSpan,
    (),
    RecordGrpcStatus,
    (),
    RecordGrpcStatus,
    RecordGrpcFailure,
> {
    TraceLayer::new_for_grpc()
        .make_span_with(ComputeDriverRpcSpan)
        .on_request(())
        .on_response(RecordGrpcStatus)
        .on_body_chunk(())
        .on_eos(RecordGrpcStatus)
        .on_failure(RecordGrpcFailure)
}

#[derive(Debug, Clone, Copy)]
pub struct ComputeDriverRpcSpan;

impl<B> MakeSpan<B> for ComputeDriverRpcSpan {
    fn make_span(&mut self, request: &Request<B>) -> Span {
        let (operation, method) = compute_driver_rpc_operation(request.uri().path());
        let span = tracing::info_span!(
            "driver_rpc",
            otel.name = operation,
            otel.kind = "server",
            otel.status_code = tracing::field::Empty,
            rpc.system = "grpc",
            rpc.service = COMPUTE_DRIVER_SERVICE,
            rpc.method = method,
            rpc.grpc.status_code = tracing::field::Empty,
        );
        let parent = TraceContextPropagator::new().extract_with_context(
            &opentelemetry::Context::new(),
            &HeaderMapExtractor::new(request.headers()),
        );
        if parent.span().span_context().is_valid() {
            let _ = span.set_parent(parent);
        }
        span
    }
}

pub(crate) fn compute_driver_rpc_operation(path: &str) -> (&'static str, &'static str) {
    match path.rsplit('/').next() {
        Some("GetCapabilities") => ("driver.get_capabilities", "get_capabilities"),
        Some("GetGatewayListenerRequirements") => (
            "driver.get_gateway_listener_requirements",
            "get_gateway_listener_requirements",
        ),
        Some("ValidateSandboxCreate") => {
            ("driver.validate_sandbox_create", "validate_sandbox_create")
        }
        Some("CreateSandbox") => ("driver.create_sandbox", "create_sandbox"),
        Some("GetSandbox") => ("driver.get_sandbox", "get_sandbox"),
        Some("ListSandboxes") => ("driver.list_sandboxes", "list_sandboxes"),
        Some("StopSandbox") => ("driver.stop_sandbox", "stop_sandbox"),
        Some("StartSandbox") => ("driver.start_sandbox", "start_sandbox"),
        Some("DeleteSandbox") => ("driver.delete_sandbox", "delete_sandbox"),
        Some("WatchSandboxes") => ("driver.watch_sandboxes", "watch_sandboxes"),
        Some("EnsureWorkspace") => ("driver.ensure_workspace", "ensure_workspace"),
        Some("DeleteWorkspace") => ("driver.delete_workspace", "delete_workspace"),
        _ => ("driver.unknown", "unknown"),
    }
}

#[must_use]
pub fn provider_for(endpoint: Option<&str>) -> (Option<SdkTracerProvider>, Option<SetupError>) {
    openshell_otel::provider_for(endpoint.map(|endpoint| OtlpTraceConfig {
        endpoint,
        service_name: ServiceName::Fixed(SERVICE_NAME),
        service_version: Some(openshell_core::VERSION),
        resource_attributes: Vec::new(),
    }))
}

pub fn layer<S>(provider: &SdkTracerProvider) -> openshell_otel::OtlpLayer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    openshell_otel::layer(provider, INSTRUMENTATION_SCOPE)
}

pub fn in_process_layer<S>(provider: &SdkTracerProvider) -> openshell_otel::TargetOtlpLayer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    openshell_otel::layer_for_target_prefix(
        provider,
        INSTRUMENTATION_SCOPE,
        IN_PROCESS_TARGET_PREFIX,
    )
}

#[cfg(test)]
pub(crate) async fn test_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    static INITIALIZED: std::sync::LazyLock<()> = std::sync::LazyLock::new(|| {
        tracing::subscriber::set_global_default(tracing_subscriber::registry())
            .expect("test tracing subscriber installs once");
    });

    let guard = LOCK.lock().await;
    std::sync::LazyLock::force(&INITIALIZED);
    guard
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use opentelemetry_proto::tonic::collector::trace::v1::{
        ExportTraceServiceRequest, ExportTraceServiceResponse,
        trace_service_server::{TraceService, TraceServiceServer},
    };
    use opentelemetry_proto::tonic::trace::v1::Span;
    use tracing_subscriber::layer::SubscriberExt as _;

    #[derive(Default)]
    struct Received {
        spans: Vec<Span>,
        service_names: Vec<String>,
    }

    #[derive(Clone)]
    struct Collector {
        received: Arc<Mutex<Received>>,
        exported: Arc<tokio::sync::Notify>,
    }

    #[tonic::async_trait]
    impl TraceService for Collector {
        async fn export(
            &self,
            request: tonic::Request<ExportTraceServiceRequest>,
        ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
            let mut received = self.received.lock().unwrap();
            for resource_span in request.into_inner().resource_spans {
                if let Some(resource) = resource_span.resource {
                    received.service_names.extend(
                        resource
                            .attributes
                            .into_iter()
                            .filter(|attribute| attribute.key == "service.name")
                            .filter_map(|attribute| attribute.value)
                            .filter_map(|value| value.value)
                            .filter_map(|value| match value {
                                opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(value) => Some(value),
                                _ => None,
                            }),
                    );
                }
                for scope_span in resource_span.scope_spans {
                    received.spans.extend(scope_span.spans);
                }
            }
            drop(received);
            self.exported.notify_one();
            Ok(tonic::Response::new(ExportTraceServiceResponse::default()))
        }
    }

    #[test]
    fn compute_driver_rpc_names_are_explicitly_mapped_and_schema_bounded() {
        for (rpc, operation, method) in [
            (
                "GetCapabilities",
                "driver.get_capabilities",
                "get_capabilities",
            ),
            (
                "GetGatewayListenerRequirements",
                "driver.get_gateway_listener_requirements",
                "get_gateway_listener_requirements",
            ),
            (
                "ValidateSandboxCreate",
                "driver.validate_sandbox_create",
                "validate_sandbox_create",
            ),
            ("CreateSandbox", "driver.create_sandbox", "create_sandbox"),
            ("GetSandbox", "driver.get_sandbox", "get_sandbox"),
            ("ListSandboxes", "driver.list_sandboxes", "list_sandboxes"),
            ("StopSandbox", "driver.stop_sandbox", "stop_sandbox"),
            ("StartSandbox", "driver.start_sandbox", "start_sandbox"),
            ("DeleteSandbox", "driver.delete_sandbox", "delete_sandbox"),
            (
                "WatchSandboxes",
                "driver.watch_sandboxes",
                "watch_sandboxes",
            ),
            (
                "EnsureWorkspace",
                "driver.ensure_workspace",
                "ensure_workspace",
            ),
            (
                "DeleteWorkspace",
                "driver.delete_workspace",
                "delete_workspace",
            ),
        ] {
            assert_eq!(
                super::compute_driver_rpc_operation(&format!(
                    "/openshell.compute.v1.ComputeDriver/{rpc}"
                )),
                (operation, method),
            );
        }
        assert_eq!(
            super::compute_driver_rpc_operation(
                "/openshell.compute.v1.ComputeDriver/AttackerControlled12345"
            ),
            ("driver.unknown", "unknown"),
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn podman_driver_spans_reach_otlp_collector_with_distinct_service_name() {
        let _tracing_lock = super::test_lock().await;
        let received = Arc::new(Mutex::new(Received::default()));
        let exported = Arc::new(tokio::sync::Notify::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let collector = Collector {
            received: Arc::clone(&received),
            exported: Arc::clone(&exported),
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
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

        let (provider, error) = super::provider_for(Some(&format!("http://{address}")));
        assert!(error.is_none());
        let provider = provider.expect("provider");
        let subscriber = tracing_subscriber::registry().with(super::layer(&provider));
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("podman.create_sandbox", sandbox.id = "sb-otlp");
            drop(span.enter());
            drop(span);
        });
        let export_completed = exported.notified();
        provider.force_flush().unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), export_completed)
            .await
            .expect("OTLP export should complete");
        provider.shutdown().unwrap();
        shutdown_tx.send(()).unwrap();
        server.await.unwrap().unwrap();

        let received = received.lock().unwrap();
        assert!(
            received
                .spans
                .iter()
                .any(|span| span.name == "podman.create_sandbox")
        );
        assert!(
            received
                .service_names
                .iter()
                .any(|name| name == "openshell-driver-podman")
        );
    }
}
