// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::result_large_err)] // gRPC handlers return Result<_, tonic::Status>

use futures::{Stream, StreamExt};
use openshell_core::proto::compute::v1::{
    CreateSandboxRequest, CreateSandboxResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    DeleteWorkspaceRequest, DeleteWorkspaceResponse, EnsureWorkspaceRequest,
    EnsureWorkspaceResponse, GetCapabilitiesRequest, GetCapabilitiesResponse,
    GetGatewayListenerRequirementsRequest, GetGatewayListenerRequirementsResponse,
    GetSandboxRequest, GetSandboxResponse, ListSandboxesRequest, ListSandboxesResponse,
    StartSandboxRequest, StartSandboxResponse, StopSandboxRequest, StopSandboxResponse,
    ValidateSandboxCreateRequest, ValidateSandboxCreateResponse, WatchSandboxesEvent,
    WatchSandboxesRequest, compute_driver_server::ComputeDriver,
};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tonic::{Request, Response, Status};
use tracing::Instrument as _;

use crate::KubernetesComputeDriver;
use crate::WorkspaceMode;

type ComputeDriverWatchStream =
    Pin<Box<dyn Stream<Item = Result<WatchSandboxesEvent, Status>> + Send + 'static>>;

struct TracedWatchStream {
    inner: ComputeDriverWatchStream,
    span: tracing::Span,
}

impl Stream for TracedWatchStream {
    type Item = Result<WatchSandboxesEvent, Status>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let span = self.span.clone();
        let _entered = span.enter();
        let result = self.inner.as_mut().poll_next(cx);
        match &result {
            Poll::Ready(Some(Err(status))) => {
                openshell_otel::mark_error(&self.span);
                self.span
                    .record("rpc.grpc.status_code", status.code() as i32);
            }
            Poll::Ready(None) => {
                self.span
                    .record("rpc.grpc.status_code", tonic::Code::Ok as i32);
            }
            Poll::Pending | Poll::Ready(Some(Ok(_))) => {}
        }
        result
    }
}

#[derive(Debug, Clone)]
pub struct ComputeDriverService {
    driver: KubernetesComputeDriver,
    trace_in_process_rpc: bool,
}

impl ComputeDriverService {
    #[must_use]
    pub fn new(driver: KubernetesComputeDriver) -> Self {
        Self {
            driver,
            trace_in_process_rpc: false,
        }
    }

    #[must_use]
    pub fn new_in_process(driver: KubernetesComputeDriver) -> Self {
        Self {
            driver,
            trace_in_process_rpc: true,
        }
    }

    fn in_process_rpc_span(
        &self,
        operation: &'static str,
        method: &'static str,
    ) -> Option<tracing::Span> {
        self.trace_in_process_rpc.then(|| {
            tracing::info_span!(
                target: "openshell_driver_kubernetes::otel_tracing",
                "driver_rpc",
                otel.name = operation,
                otel.kind = "server",
                otel.status_code = tracing::field::Empty,
                rpc.system = "grpc",
                rpc.service = "openshell.compute.v1.ComputeDriver",
                rpc.method = method,
                rpc.grpc.status_code = tracing::field::Empty,
            )
        })
    }

    async fn trace_rpc<T>(
        &self,
        operation: &'static str,
        method: &'static str,
        future: impl Future<Output = Result<T, Status>>,
    ) -> Result<T, Status> {
        let Some(span) = self.in_process_rpc_span(operation, method) else {
            return future.await;
        };
        let result = future.instrument(span.clone()).await;
        match &result {
            Ok(_) => {
                span.record("rpc.grpc.status_code", tonic::Code::Ok as i32);
            }
            Err(status) => {
                openshell_otel::mark_error(&span);
                span.record("rpc.grpc.status_code", status.code() as i32);
            }
        }
        result
    }
}

#[tonic::async_trait]
impl ComputeDriver for ComputeDriverService {
    async fn get_capabilities(
        &self,
        _request: Request<GetCapabilitiesRequest>,
    ) -> Result<Response<GetCapabilitiesResponse>, Status> {
        self.trace_rpc("driver.get_capabilities", "get_capabilities", async {
            self.driver
                .capabilities()
                .map(Response::new)
                .map_err(Status::internal)
        })
        .await
    }

    async fn get_gateway_listener_requirements(
        &self,
        _request: Request<GetGatewayListenerRequirementsRequest>,
    ) -> Result<Response<GetGatewayListenerRequirementsResponse>, Status> {
        self.trace_rpc(
            "driver.get_gateway_listener_requirements",
            "get_gateway_listener_requirements",
            async {
                Ok(Response::new(GetGatewayListenerRequirementsResponse {
                    requirements: Vec::new(),
                }))
            },
        )
        .await
    }

    async fn validate_sandbox_create(
        &self,
        request: Request<ValidateSandboxCreateRequest>,
    ) -> Result<Response<ValidateSandboxCreateResponse>, Status> {
        self.trace_rpc(
            "driver.validate_sandbox_create",
            "validate_sandbox_create",
            async {
                let sandbox = request
                    .into_inner()
                    .sandbox
                    .ok_or_else(|| Status::invalid_argument("sandbox is required"))?;
                self.driver.validate_sandbox_create(&sandbox).await?;
                Ok(Response::new(ValidateSandboxCreateResponse {}))
            },
        )
        .await
    }

    async fn get_sandbox(
        &self,
        request: Request<GetSandboxRequest>,
    ) -> Result<Response<GetSandboxResponse>, Status> {
        self.trace_rpc("driver.get_sandbox", "get_sandbox", async {
            let request = request.into_inner();
            if request.sandbox_id.is_empty() {
                return Err(Status::invalid_argument("sandbox_id is required"));
            }
            let sandbox = self
                .driver
                .get_sandbox(&request.sandbox_id)
                .await
                .map_err(Status::internal)?
                .ok_or_else(|| Status::not_found("sandbox not found"))?;
            Ok(Response::new(GetSandboxResponse {
                sandbox: Some(sandbox),
            }))
        })
        .await
    }

    async fn list_sandboxes(
        &self,
        _request: Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        self.trace_rpc("driver.list_sandboxes", "list_sandboxes", async {
            let sandboxes = self
                .driver
                .list_sandboxes()
                .await
                .map_err(Status::internal)?;
            Ok(Response::new(ListSandboxesResponse { sandboxes }))
        })
        .await
    }

    async fn create_sandbox(
        &self,
        request: Request<CreateSandboxRequest>,
    ) -> Result<Response<CreateSandboxResponse>, Status> {
        self.trace_rpc("driver.create_sandbox", "create_sandbox", async {
            let sandbox = request
                .into_inner()
                .sandbox
                .ok_or_else(|| Status::invalid_argument("sandbox is required"))?;
            self.driver
                .create_sandbox(&sandbox)
                .await
                .map_err(|e| Status::from(openshell_core::ComputeDriverError::from(e)))?;
            Ok(Response::new(CreateSandboxResponse {}))
        })
        .await
    }

    async fn stop_sandbox(
        &self,
        request: Request<StopSandboxRequest>,
    ) -> Result<Response<StopSandboxResponse>, Status> {
        self.trace_rpc("driver.stop_sandbox", "stop_sandbox", async {
            let request = request.into_inner();
            if request.sandbox_id.is_empty() {
                return Err(Status::invalid_argument("sandbox_id is required"));
            }
            self.driver
                .stop_sandbox(&request.sandbox_id)
                .await
                .map_err(|error| Status::from(openshell_core::ComputeDriverError::from(error)))?;
            Ok(Response::new(StopSandboxResponse {}))
        })
        .await
    }

    async fn start_sandbox(
        &self,
        request: Request<StartSandboxRequest>,
    ) -> Result<Response<StartSandboxResponse>, Status> {
        self.trace_rpc("driver.start_sandbox", "start_sandbox", async {
            let request = request.into_inner();
            if request.sandbox_id.is_empty() {
                return Err(Status::invalid_argument("sandbox_id is required"));
            }
            self.driver
                .start_sandbox(&request.sandbox_id)
                .await
                .map_err(|error| Status::from(openshell_core::ComputeDriverError::from(error)))?;
            Ok(Response::new(StartSandboxResponse {}))
        })
        .await
    }

    async fn delete_sandbox(
        &self,
        request: Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        self.trace_rpc("driver.delete_sandbox", "delete_sandbox", async {
            let request = request.into_inner();
            if request.sandbox_id.is_empty() {
                return Err(Status::invalid_argument("sandbox_id is required"));
            }
            let deleted = self
                .driver
                .delete_sandbox(&request.sandbox_id)
                .await
                .map_err(Status::internal)?;
            Ok(Response::new(DeleteSandboxResponse { deleted }))
        })
        .await
    }

    type WatchSandboxesStream = ComputeDriverWatchStream;

    async fn watch_sandboxes(
        &self,
        _request: Request<WatchSandboxesRequest>,
    ) -> Result<Response<Self::WatchSandboxesStream>, Status> {
        let create_stream = async {
            let stream = self
                .driver
                .watch_sandboxes()
                .await
                .map_err(Status::internal)?;
            let stream = stream.map(|item| item.map_err(|err| Status::internal(err.to_string())));
            Ok::<ComputeDriverWatchStream, Status>(Box::pin(stream))
        };
        let Some(span) = self.in_process_rpc_span("driver.watch_sandboxes", "watch_sandboxes")
        else {
            return create_stream.await.map(Response::new);
        };
        match create_stream.instrument(span.clone()).await {
            Ok(stream) => Ok(Response::new(Box::pin(TracedWatchStream {
                inner: stream,
                span,
            }))),
            Err(status) => {
                openshell_otel::mark_error(&span);
                span.record("rpc.grpc.status_code", status.code() as i32);
                Err(status)
            }
        }
    }

    async fn ensure_workspace(
        &self,
        request: Request<EnsureWorkspaceRequest>,
    ) -> Result<Response<EnsureWorkspaceResponse>, Status> {
        self.trace_rpc("driver.ensure_workspace", "ensure_workspace", async {
            let workspace = request.into_inner().workspace;
            if workspace.is_empty() {
                return Err(Status::invalid_argument("workspace is required"));
            }
            self.driver
                .validate_workspace_namespace(&workspace)
                .map_err(|error| Status::from(openshell_core::ComputeDriverError::from(error)))?;
            match self.driver.workspace_mode() {
                WorkspaceMode::Managed => {
                    self.driver
                        .ensure_namespace(&workspace)
                        .await
                        .map_err(|e| Status::internal(e.to_string()))?;
                }
                WorkspaceMode::Operator => {
                    if let Some(allowlist) = self.driver.operator_allowlist()
                        && !allowlist.contains(&workspace)
                    {
                        return Err(Status::permission_denied(format!(
                            "workspace '{workspace}' is not in the operator namespace allowlist"
                        )));
                    }
                }
                WorkspaceMode::Shared => {}
            }
            Ok(Response::new(EnsureWorkspaceResponse {}))
        })
        .await
    }

    async fn delete_workspace(
        &self,
        request: Request<DeleteWorkspaceRequest>,
    ) -> Result<Response<DeleteWorkspaceResponse>, Status> {
        self.trace_rpc("driver.delete_workspace", "delete_workspace", async {
            let workspace = request.into_inner().workspace;
            if workspace.is_empty() {
                return Err(Status::invalid_argument("workspace is required"));
            }
            if workspace_delete_requires_namespace_access(self.driver.workspace_mode()) {
                self.driver
                    .validate_workspace_namespace(&workspace)
                    .map_err(|error| {
                        Status::from(openshell_core::ComputeDriverError::from(error))
                    })?;
                self.driver
                    .delete_namespace(&workspace)
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?;
            }
            Ok(Response::new(DeleteWorkspaceResponse {}))
        })
        .await
    }
}

fn workspace_delete_requires_namespace_access(mode: WorkspaceMode) -> bool {
    matches!(mode, WorkspaceMode::Managed)
}

#[cfg(test)]
mod tests {
    use super::{WorkspaceMode, workspace_delete_requires_namespace_access};
    use crate::KubernetesDriverError;
    use openshell_core::ComputeDriverError;
    use tonic::Status;

    #[tokio::test]
    async fn tracing_in_process_service_preserves_the_driver_rpc_server_boundary() {
        use super::*;
        use crate::KubernetesComputeConfig;
        use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
        use tracing::instrument::WithSubscriber as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        let _tracing_lock = crate::otel_tracing::test_lock().await;
        let gateway_exporter = InMemorySpanExporterBuilder::new().build();
        let gateway_provider = SdkTracerProvider::builder()
            .with_simple_exporter(gateway_exporter.clone())
            .build();
        let driver_exporter = InMemorySpanExporterBuilder::new().build();
        let driver_provider = SdkTracerProvider::builder()
            .with_simple_exporter(driver_exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer_excluding_target_prefix(
                &gateway_provider,
                "gateway-test",
                Some(crate::otel_tracing::IN_PROCESS_TARGET_PREFIX),
            ))
            .with(crate::otel_tracing::in_process_layer(&driver_provider));
        let service = ComputeDriverService::new_in_process(KubernetesComputeDriver::new_for_test(
            KubernetesComputeConfig::default(),
        ));

        async {
            let gateway_span = tracing::info_span!(
                target: "openshell_server::compute",
                "driver",
                otel.name = "driver.get_capabilities",
                otel.kind = "client"
            );
            ComputeDriver::get_capabilities(&service, Request::new(GetCapabilitiesRequest {}))
                .instrument(gateway_span)
                .await?;

            ComputeDriver::validate_sandbox_create(
                &service,
                Request::new(ValidateSandboxCreateRequest { sandbox: None }),
            )
            .await
        }
        .with_subscriber(subscriber)
        .await
        .expect_err("missing sandbox should fail");
        gateway_provider.force_flush().unwrap();
        driver_provider.force_flush().unwrap();

        let gateway_spans = gateway_exporter.get_finished_spans().unwrap();
        let driver_spans = driver_exporter.get_finished_spans().unwrap();
        let client = gateway_spans
            .iter()
            .find(|span| span.name == "driver.get_capabilities")
            .expect("gateway client span");
        let server = driver_spans
            .iter()
            .find(|span| span.name == "driver.get_capabilities")
            .expect("in-process server span");
        assert_eq!(
            server.span_context.trace_id(),
            client.span_context.trace_id()
        );
        assert_eq!(server.parent_span_id, client.span_context.span_id());
        assert_eq!(server.span_kind, opentelemetry::trace::SpanKind::Server);
        assert!(server.attributes.iter().any(|attribute| {
            attribute.key.as_str() == "rpc.grpc.status_code"
                && attribute.value.to_string() == (tonic::Code::Ok as i32).to_string()
        }));
        let failed = driver_spans
            .iter()
            .find(|span| span.name == "driver.validate_sandbox_create")
            .expect("failed in-process server span");
        assert!(matches!(
            failed.status,
            opentelemetry::trace::Status::Error { .. }
        ));
        gateway_provider.shutdown().unwrap();
        driver_provider.shutdown().unwrap();
    }

    #[tokio::test]
    async fn tracing_in_process_stream_span_lives_until_stream_failure() {
        use super::*;
        use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
        use tracing::instrument::WithSubscriber as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        let _tracing_lock = crate::otel_tracing::test_lock().await;
        let exporter = InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber =
            tracing_subscriber::registry().with(crate::otel_tracing::in_process_layer(&provider));

        async {
            let span = tracing::info_span!(
                target: "openshell_driver_kubernetes::otel_tracing",
                "driver_rpc",
                otel.name = "driver.watch_sandboxes",
                otel.kind = "server",
                otel.status_code = tracing::field::Empty,
                rpc.grpc.status_code = tracing::field::Empty,
            );
            let inner: ComputeDriverWatchStream = Box::pin(futures::stream::iter([Err(
                Status::internal("watch failed"),
            )]));
            let mut stream = TracedWatchStream { inner, span };

            provider.force_flush().unwrap();
            assert!(
                exporter.get_finished_spans().unwrap().is_empty(),
                "server span must remain open while the response stream is alive"
            );
            stream
                .next()
                .await
                .expect("stream item")
                .expect_err("stream should fail");
            drop(stream);
        }
        .with_subscriber(subscriber)
        .await;
        provider.force_flush().unwrap();

        let spans = exporter.get_finished_spans().unwrap();
        let span = spans
            .iter()
            .find(|span| span.name == "driver.watch_sandboxes")
            .expect("watch server span should be exported when the stream ends");
        assert!(matches!(
            span.status,
            opentelemetry::trace::Status::Error { .. }
        ));
        provider.shutdown().unwrap();
    }

    #[tokio::test]
    async fn tracing_in_process_stream_records_ok_when_stream_completes() {
        use super::*;
        use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
        use tracing::instrument::WithSubscriber as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        let _tracing_lock = crate::otel_tracing::test_lock().await;
        let exporter = InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber =
            tracing_subscriber::registry().with(crate::otel_tracing::in_process_layer(&provider));

        async {
            let span = tracing::info_span!(
                target: "openshell_driver_kubernetes::otel_tracing",
                "driver_rpc",
                otel.name = "driver.watch_sandboxes",
                otel.kind = "server",
                otel.status_code = tracing::field::Empty,
                rpc.grpc.status_code = tracing::field::Empty,
            );
            let inner: ComputeDriverWatchStream = Box::pin(futures::stream::empty());
            let mut stream = TracedWatchStream { inner, span };

            assert!(stream.next().await.is_none());
            drop(stream);
        }
        .with_subscriber(subscriber)
        .await;
        provider.force_flush().unwrap();

        let spans = exporter.get_finished_spans().unwrap();
        let span = spans
            .iter()
            .find(|span| span.name == "driver.watch_sandboxes")
            .expect("watch server span should be exported when the stream completes");
        assert!(span.attributes.iter().any(|attribute| {
            attribute.key.as_str() == "rpc.grpc.status_code"
                && attribute.value.to_string() == (tonic::Code::Ok as i32).to_string()
        }));
        provider.shutdown().unwrap();
    }

    #[test]
    fn precondition_driver_errors_map_to_failed_precondition_status() {
        let status: Status = ComputeDriverError::from(KubernetesDriverError::Precondition(
            "sandbox agent pod IP is not available".to_string(),
        ))
        .into();

        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_eq!(status.message(), "sandbox agent pod IP is not available");
    }

    #[test]
    fn invalid_workspace_driver_errors_map_to_invalid_argument_status() {
        let status: Status = ComputeDriverError::from(KubernetesDriverError::InvalidArgument(
            "managed namespace is invalid".to_string(),
        ))
        .into();

        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert_eq!(status.message(), "managed namespace is invalid");
    }

    #[test]
    fn already_exists_driver_errors_map_to_already_exists_status() {
        let status: Status = ComputeDriverError::from(KubernetesDriverError::AlreadyExists).into();

        assert_eq!(status.code(), tonic::Code::AlreadyExists);
        assert_eq!(status.message(), "sandbox already exists");
    }

    #[test]
    fn not_found_driver_errors_map_to_not_found_status() {
        let status: Status = ComputeDriverError::from(KubernetesDriverError::NotFound).into();

        assert_eq!(status.code(), tonic::Code::NotFound);
        assert_eq!(status.message(), "sandbox not found");
    }

    #[test]
    fn only_managed_workspace_delete_accesses_the_namespace() {
        assert!(workspace_delete_requires_namespace_access(
            WorkspaceMode::Managed
        ));
        assert!(!workspace_delete_requires_namespace_access(
            WorkspaceMode::Operator
        ));
        assert!(!workspace_delete_requires_namespace_access(
            WorkspaceMode::Shared
        ));
    }
}
