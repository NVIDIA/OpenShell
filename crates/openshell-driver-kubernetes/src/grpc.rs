// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::result_large_err)] // gRPC handlers return Result<_, tonic::Status>

use futures::{Stream, StreamExt};
use openshell_core::proto::compute::v1::{
    AuthenticateSandboxRequest, AuthenticateSandboxResponse, CreateSandboxRequest,
    CreateSandboxResponse, DeleteSandboxRequest, DeleteSandboxResponse, DeleteWorkspaceRequest,
    DeleteWorkspaceResponse, EnsureWorkspaceRequest, EnsureWorkspaceResponse,
    GetCapabilitiesRequest, GetCapabilitiesResponse, GetGatewayListenerRequirementsRequest,
    GetGatewayListenerRequirementsResponse, GetSandboxRequest, GetSandboxResponse,
    ListSandboxesRequest, ListSandboxesResponse, StartSandboxRequest, StartSandboxResponse,
    StopSandboxRequest, StopSandboxResponse, ValidateSandboxCreateRequest,
    ValidateSandboxCreateResponse, WatchSandboxesEvent, WatchSandboxesRequest,
    compute_driver_server::ComputeDriver,
};
use std::pin::Pin;
use tonic::{Request, Response, Status};

use crate::KubernetesComputeDriver;
use crate::WorkspaceMode;

type ComputeDriverWatchStream =
    Pin<Box<dyn Stream<Item = Result<WatchSandboxesEvent, Status>> + Send + 'static>>;

#[cfg(test)]
type TracedWatchStream = openshell_otel::TracedGrpcStream<ComputeDriverWatchStream>;

#[derive(Debug, Clone)]
pub struct ComputeDriverService {
    driver: KubernetesComputeDriver,
    rpc_tracer: openshell_otel::InProcessRpcTracer,
}

impl ComputeDriverService {
    #[must_use]
    pub fn new(driver: KubernetesComputeDriver) -> Self {
        Self {
            driver,
            rpc_tracer: openshell_otel::InProcessRpcTracer::disabled(),
        }
    }

    #[must_use]
    pub fn new_in_process(driver: KubernetesComputeDriver) -> Self {
        Self {
            driver,
            rpc_tracer: openshell_otel::InProcessRpcTracer::enabled(),
        }
    }
}

#[tonic::async_trait]
impl ComputeDriver for ComputeDriverService {
    async fn authenticate_sandbox(
        &self,
        request: Request<AuthenticateSandboxRequest>,
    ) -> Result<Response<AuthenticateSandboxResponse>, Status> {
        self.rpc_tracer
            .trace(openshell_otel::rpc::AUTHENTICATE_SANDBOX, async {
                let credential = request.into_inner().credential;
                if credential.is_empty() {
                    return Err(Status::invalid_argument("credential is required"));
                }
                let sandbox_id = self.driver.authenticate_sandbox(&credential).await?;
                Ok(Response::new(AuthenticateSandboxResponse { sandbox_id }))
            })
            .await
    }

    async fn get_capabilities(
        &self,
        _request: Request<GetCapabilitiesRequest>,
    ) -> Result<Response<GetCapabilitiesResponse>, Status> {
        self.rpc_tracer
            .trace(openshell_otel::rpc::GET_CAPABILITIES, async {
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
        self.rpc_tracer
            .trace(
                openshell_otel::rpc::GET_GATEWAY_LISTENER_REQUIREMENTS,
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
        self.rpc_tracer
            .trace(openshell_otel::rpc::VALIDATE_SANDBOX_CREATE, async {
                let sandbox = request
                    .into_inner()
                    .sandbox
                    .ok_or_else(|| Status::invalid_argument("sandbox is required"))?;
                self.driver.validate_sandbox_create(&sandbox).await?;
                Ok(Response::new(ValidateSandboxCreateResponse {}))
            })
            .await
    }

    async fn get_sandbox(
        &self,
        request: Request<GetSandboxRequest>,
    ) -> Result<Response<GetSandboxResponse>, Status> {
        self.rpc_tracer
            .trace(openshell_otel::rpc::GET_SANDBOX, async {
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
        self.rpc_tracer
            .trace(openshell_otel::rpc::LIST_SANDBOXES, async {
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
        self.rpc_tracer
            .trace(openshell_otel::rpc::CREATE_SANDBOX, async {
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
        self.rpc_tracer
            .trace(openshell_otel::rpc::STOP_SANDBOX, async {
                let request = request.into_inner();
                if request.sandbox_id.is_empty() {
                    return Err(Status::invalid_argument("sandbox_id is required"));
                }
                self.driver
                    .stop_sandbox(&request.sandbox_id)
                    .await
                    .map_err(|error| {
                        Status::from(openshell_core::ComputeDriverError::from(error))
                    })?;
                Ok(Response::new(StopSandboxResponse {}))
            })
            .await
    }

    async fn start_sandbox(
        &self,
        request: Request<StartSandboxRequest>,
    ) -> Result<Response<StartSandboxResponse>, Status> {
        self.rpc_tracer
            .trace(openshell_otel::rpc::START_SANDBOX, async {
                let request = request.into_inner();
                if request.sandbox_id.is_empty() {
                    return Err(Status::invalid_argument("sandbox_id is required"));
                }
                self.driver
                    .start_sandbox(&request.sandbox_id)
                    .await
                    .map_err(|error| {
                        Status::from(openshell_core::ComputeDriverError::from(error))
                    })?;
                Ok(Response::new(StartSandboxResponse {}))
            })
            .await
    }

    async fn delete_sandbox(
        &self,
        request: Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        self.rpc_tracer
            .trace(openshell_otel::rpc::DELETE_SANDBOX, async {
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
        self.rpc_tracer
            .trace_stream(openshell_otel::rpc::WATCH_SANDBOXES, create_stream)
            .await
            .map(Response::new)
    }

    async fn ensure_workspace(
        &self,
        request: Request<EnsureWorkspaceRequest>,
    ) -> Result<Response<EnsureWorkspaceResponse>, Status> {
        self.rpc_tracer
            .trace(openshell_otel::rpc::ENSURE_WORKSPACE, async {
                let workspace = request.into_inner().workspace;
                if workspace.is_empty() {
                    return Err(Status::invalid_argument("workspace is required"));
                }
                self.driver
                    .validate_workspace_namespace(&workspace)
                    .map_err(|error| {
                        Status::from(openshell_core::ComputeDriverError::from(error))
                    })?;
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
        self.rpc_tracer
            .trace(openshell_otel::rpc::DELETE_WORKSPACE, async {
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
        use tracing::{Instrument as _, instrument::WithSubscriber as _};
        use tracing_subscriber::layer::SubscriberExt as _;

        let _tracing_lock = openshell_otel_test_support::tracing_test_lock().await;
        let gateway_exporter = InMemorySpanExporterBuilder::new().build();
        let gateway_provider = SdkTracerProvider::builder()
            .with_simple_exporter(gateway_exporter.clone())
            .build();
        let driver_exporter = InMemorySpanExporterBuilder::new().build();
        let driver_provider = SdkTracerProvider::builder()
            .with_simple_exporter(driver_exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer_excluding_target_prefixes(
                &gateway_provider,
                "gateway-test",
                crate::otel_tracing::TRACING.in_process_targets(),
            ))
            .with(crate::otel_tracing::TRACING.in_process_layer(&driver_provider));
        let service = ComputeDriverService::new_in_process(KubernetesComputeDriver::new_for_test(
            KubernetesComputeConfig::default(),
        ));

        async {
            let gateway_span = tracing::info_span!(
                target: "openshell_server::compute",
                "driver",
                otel.name = "openshell.compute.v1.ComputeDriver/GetCapabilities",
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
            .find(|span| span.name == "openshell.compute.v1.ComputeDriver/GetCapabilities")
            .expect("gateway client span");
        let server = driver_spans
            .iter()
            .find(|span| span.name == "openshell.compute.v1.ComputeDriver/GetCapabilities")
            .expect("in-process server span");
        assert_eq!(
            server.span_context.trace_id(),
            client.span_context.trace_id()
        );
        assert_eq!(server.parent_span_id, client.span_context.span_id());
        assert_eq!(server.span_kind, opentelemetry::trace::SpanKind::Server);
        assert!(server.attributes.iter().any(|attribute| {
            attribute.key.as_str() == "rpc.method"
                && attribute.value.to_string()
                    == "openshell.compute.v1.ComputeDriver/GetCapabilities"
        }));
        assert!(
            server
                .attributes
                .iter()
                .all(|attribute| attribute.key.as_str() != "rpc.service"),
            "the current RPC semantic conventions integrate the service into rpc.method"
        );
        assert!(server.attributes.iter().any(|attribute| {
            attribute.key.as_str() == "rpc.response.status_code"
                && attribute.value.to_string() == "OK"
        }));
        let failed = driver_spans
            .iter()
            .find(|span| span.name == "openshell.compute.v1.ComputeDriver/ValidateSandboxCreate")
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

        let _tracing_lock = openshell_otel_test_support::tracing_test_lock().await;
        let exporter = InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(crate::otel_tracing::TRACING.in_process_layer(&provider));

        async {
            let span = tracing::info_span!(
                target: crate::otel_tracing::TRACING.in_process_target(),
                "driver_rpc",
                otel.name = "openshell.compute.v1.ComputeDriver/WatchSandboxes",
                otel.kind = "server",
                otel.status_code = tracing::field::Empty,
                rpc.response.status_code = tracing::field::Empty,
            );
            let inner: ComputeDriverWatchStream = Box::pin(futures::stream::iter([Err(
                Status::internal("watch failed"),
            )]));
            let mut stream = TracedWatchStream::new(inner, span);

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
            .find(|span| span.name == "openshell.compute.v1.ComputeDriver/WatchSandboxes")
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

        let _tracing_lock = openshell_otel_test_support::tracing_test_lock().await;
        let exporter = InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(crate::otel_tracing::TRACING.in_process_layer(&provider));

        async {
            let span = tracing::info_span!(
                target: crate::otel_tracing::TRACING.in_process_target(),
                "driver_rpc",
                otel.name = "openshell.compute.v1.ComputeDriver/WatchSandboxes",
                otel.kind = "server",
                otel.status_code = tracing::field::Empty,
                rpc.response.status_code = tracing::field::Empty,
            );
            let inner: ComputeDriverWatchStream = Box::pin(futures::stream::empty());
            let mut stream = TracedWatchStream::new(inner, span);

            assert!(stream.next().await.is_none());
            drop(stream);
        }
        .with_subscriber(subscriber)
        .await;
        provider.force_flush().unwrap();

        let spans = exporter.get_finished_spans().unwrap();
        let span = spans
            .iter()
            .find(|span| span.name == "openshell.compute.v1.ComputeDriver/WatchSandboxes")
            .expect("watch server span should be exported when the stream completes");
        assert!(span.attributes.iter().any(|attribute| {
            attribute.key.as_str() == "rpc.response.status_code"
                && attribute.value.to_string() == "OK"
        }));
        provider.shutdown().unwrap();
    }

    #[tokio::test]
    async fn tracing_in_process_stream_leaves_status_unset_when_dropped() {
        use super::*;
        use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
        use tracing::instrument::WithSubscriber as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        let _tracing_lock = openshell_otel_test_support::tracing_test_lock().await;
        let exporter = InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(crate::otel_tracing::TRACING.in_process_layer(&provider));

        async {
            let span = tracing::info_span!(
                target: crate::otel_tracing::TRACING.in_process_target(),
                "driver_rpc",
                otel.name = "openshell.compute.v1.ComputeDriver/WatchSandboxes",
                otel.kind = "server",
                otel.status_code = tracing::field::Empty,
                rpc.response.status_code = tracing::field::Empty,
                error.type = tracing::field::Empty,
            );
            let inner: ComputeDriverWatchStream = Box::pin(futures::stream::pending());
            let stream = TracedWatchStream::new(inner, span);

            drop(stream);
        }
        .with_subscriber(subscriber)
        .await;
        provider.force_flush().unwrap();

        let spans = exporter.get_finished_spans().unwrap();
        let span = spans
            .iter()
            .find(|span| span.name == "openshell.compute.v1.ComputeDriver/WatchSandboxes")
            .expect("watch server span should be exported when the stream is dropped");
        assert!(matches!(span.status, opentelemetry::trace::Status::Unset));
        assert!(
            span.attributes
                .iter()
                .all(|attribute| attribute.key.as_str() != "rpc.response.status_code")
        );
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
