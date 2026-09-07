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
use std::pin::Pin;
use tonic::{Request, Response, Status};

use crate::PodmanComputeDriver;

type ComputeDriverWatchStream =
    Pin<Box<dyn Stream<Item = Result<WatchSandboxesEvent, Status>> + Send + 'static>>;

#[cfg(test)]
type TracedWatchStream = openshell_otel::TracedGrpcStream<ComputeDriverWatchStream>;

#[derive(Debug, Clone)]
pub struct ComputeDriverService {
    driver: PodmanComputeDriver,
    rpc_tracer: openshell_otel::InProcessRpcTracer,
}

impl ComputeDriverService {
    #[must_use]
    pub fn new(driver: PodmanComputeDriver) -> Self {
        Self {
            driver,
            rpc_tracer: openshell_otel::InProcessRpcTracer::disabled(),
        }
    }

    #[must_use]
    pub fn new_in_process(driver: PodmanComputeDriver) -> Self {
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
        _request: Request<openshell_core::proto::compute::v1::AuthenticateSandboxRequest>,
    ) -> Result<Response<openshell_core::proto::compute::v1::AuthenticateSandboxResponse>, Status>
    {
        self.rpc_tracer
            .trace(openshell_otel::rpc::AUTHENTICATE_SANDBOX, async {
                Err(Status::unimplemented(
                    "podman does not authenticate sandbox credentials",
                ))
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
                    .map_err(Status::from)
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
                        requirements: self
                            .driver
                            .gateway_listener_requirements()
                            .map_err(Status::from)?,
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
                self.driver
                    .validate_sandbox_create(&sandbox)
                    .await
                    .map_err(Status::from)?;
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
                    .map_err(Status::from)?
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
                let sandboxes = self.driver.list_sandboxes().await.map_err(Status::from)?;
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
                    .map_err(Status::from)?;
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
                    .map_err(Status::from)?;
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
                    .map_err(Status::from)?;
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
                    .map_err(Status::from)?;
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
            let stream = self.driver.watch_sandboxes().await.map_err(Status::from)?;
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
        _request: Request<EnsureWorkspaceRequest>,
    ) -> Result<Response<EnsureWorkspaceResponse>, Status> {
        self.rpc_tracer
            .trace(openshell_otel::rpc::ENSURE_WORKSPACE, async {
                Ok(Response::new(EnsureWorkspaceResponse {}))
            })
            .await
    }

    async fn delete_workspace(
        &self,
        _request: Request<DeleteWorkspaceRequest>,
    ) -> Result<Response<DeleteWorkspaceResponse>, Status> {
        self.rpc_tracer
            .trace(openshell_otel::rpc::DELETE_WORKSPACE, async {
                Ok(Response::new(DeleteWorkspaceResponse {}))
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PodmanComputeConfig;
    use crate::container;
    use crate::test_utils::{StubResponse, spawn_podman_stub, unique_socket_path};
    use hyper::StatusCode;
    use openshell_core::ComputeDriverError;
    use std::path::PathBuf;

    type TestDriverClient =
        openshell_core::proto::compute::v1::compute_driver_client::ComputeDriverClient<
            tonic::transport::Channel,
        >;

    fn request_with_traceparent<T>(message: T) -> Request<T> {
        let mut request = Request::new(message);
        request.metadata_mut().insert(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                .parse()
                .unwrap(),
        );
        request
    }

    async fn standalone_traced_client() -> (
        TestDriverClient,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
    ) {
        use openshell_core::proto::compute::v1::compute_driver_server::ComputeDriverServer;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
        let service = ComputeDriverService::new(PodmanComputeDriver::for_tests(
            PodmanComputeConfig::default(),
        ));
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .layer(openshell_otel::compute_driver_rpc_layer())
                .add_service(ComputeDriverServer::new(service))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = shutdown_rx.await;
                    },
                )
                .await
        });
        let client = TestDriverClient::connect(format!("http://{address}"))
            .await
            .unwrap();
        (client, shutdown, server)
    }

    #[test]
    fn precondition_driver_errors_map_to_failed_precondition_status() {
        let status: Status =
            ComputeDriverError::Precondition("sandbox container is not running".to_string()).into();

        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_eq!(status.message(), "sandbox container is not running");
    }

    #[test]
    fn already_exists_driver_errors_map_to_already_exists_status() {
        let status: Status = ComputeDriverError::AlreadyExists.into();
        assert_eq!(status.code(), tonic::Code::AlreadyExists);
    }

    #[test]
    fn not_found_driver_errors_map_to_not_found_status() {
        let status: Status = ComputeDriverError::NotFound.into();
        assert_eq!(status.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn in_process_service_preserves_the_driver_rpc_server_boundary() {
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
        let service = ComputeDriverService::new_in_process(PodmanComputeDriver::for_tests(
            PodmanComputeConfig::default(),
        ));

        async {
            let gateway_span = tracing::info_span!(target: "openshell_server::compute", "driver", otel.name = "openshell.compute.v1.ComputeDriver/GetCapabilities", otel.kind = "client");
            ComputeDriver::get_capabilities(&service, Request::new(GetCapabilitiesRequest {}))
                .instrument(gateway_span)
                .await
        }
            .with_subscriber(subscriber)
            .await
            .expect("capabilities should succeed");
        gateway_provider.force_flush().unwrap();
        driver_provider.force_flush().unwrap();

        let gateway_spans = gateway_exporter.get_finished_spans().unwrap();
        let driver_spans = driver_exporter.get_finished_spans().unwrap();
        let client = gateway_spans
            .iter()
            .find(|span| span.name == "openshell.compute.v1.ComputeDriver/GetCapabilities")
            .unwrap();
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
        gateway_provider.shutdown().unwrap();
        driver_provider.shutdown().unwrap();
    }

    #[tokio::test]
    async fn standalone_rpc_layer_propagates_context_and_records_errors() {
        use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
        use tracing_subscriber::layer::SubscriberExt as _;

        let _tracing_lock = openshell_otel_test_support::tracing_test_lock().await;
        let exporter = InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let dispatch = tracing::Dispatch::new(
            tracing_subscriber::registry().with(crate::otel_tracing::TRACING.layer(&provider)),
        );
        let _dispatch = tracing::dispatcher::set_default(&dispatch);
        let (mut client, shutdown, server) = standalone_traced_client().await;

        client
            .get_capabilities(request_with_traceparent(GetCapabilitiesRequest {}))
            .await
            .expect("capabilities should succeed");
        client
            .validate_sandbox_create(request_with_traceparent(ValidateSandboxCreateRequest {
                sandbox: None,
            }))
            .await
            .expect_err("missing sandbox should fail");
        drop(client);
        shutdown.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("standalone test server should stop")
            .expect("standalone test server should not panic")
            .expect("standalone test server should stop cleanly");
        provider.force_flush().unwrap();

        let spans = exporter.get_finished_spans().unwrap();
        let capabilities = spans
            .iter()
            .filter(|span| span.name == "openshell.compute.v1.ComputeDriver/GetCapabilities")
            .collect::<Vec<_>>();
        assert_eq!(capabilities.len(), 1, "exactly one RPC span is expected");
        assert_eq!(
            capabilities[0].span_context.trace_id().to_string(),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
        assert_eq!(
            capabilities[0].parent_span_id.to_string(),
            "00f067aa0ba902b7"
        );
        assert_eq!(
            capabilities[0].span_kind,
            opentelemetry::trace::SpanKind::Server
        );
        assert!(capabilities[0].attributes.iter().any(|attribute| {
            attribute.key.as_str() == "rpc.response.status_code"
                && attribute.value.to_string() == "OK"
        }));

        let failed = spans
            .iter()
            .find(|span| span.name == "openshell.compute.v1.ComputeDriver/ValidateSandboxCreate")
            .expect("failed RPC span should be exported");
        assert!(matches!(
            failed.status,
            opentelemetry::trace::Status::Error { .. }
        ));
        assert!(failed.attributes.iter().any(|attribute| {
            attribute.key.as_str() == "rpc.response.status_code"
                && attribute.value.to_string() == "INVALID_ARGUMENT"
        }));
        provider.shutdown().unwrap();
    }

    #[tokio::test]
    async fn in_process_stream_span_lives_until_stream_failure() {
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
    async fn in_process_stream_records_ok_when_stream_completes() {
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
    async fn in_process_stream_leaves_status_unset_when_dropped() {
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

    fn test_service(socket_path: PathBuf) -> ComputeDriverService {
        let config = PodmanComputeConfig {
            socket_path: Some(socket_path),
            stop_timeout_secs: 10,
            ..PodmanComputeConfig::default()
        };
        ComputeDriverService::new(PodmanComputeDriver::for_tests(config))
    }

    fn api_path(path: &str) -> String {
        format!("/v5.0.0{path}")
    }

    #[tokio::test]
    async fn delete_sandbox_rejects_missing_sandbox_id() {
        let service = test_service(unique_socket_path("missing-id"));

        let err = ComputeDriver::delete_sandbox(
            &service,
            Request::new(DeleteSandboxRequest {
                sandbox_id: String::new(),
                sandbox_name: "demo".to_string(),
            }),
        )
        .await
        .expect_err("missing sandbox_id should fail");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(err.message(), "sandbox_id is required");
    }

    #[tokio::test]
    async fn delete_sandbox_forwards_request_sandbox_id_to_driver_cleanup() {
        let sandbox_id = "sandbox-abc";
        let volume_name = container::volume_name(sandbox_id);
        let (socket_path, request_log, handle) = spawn_podman_stub(
            "forward-id",
            vec![
                // list_containers returns empty (container already gone)
                StubResponse::new(StatusCode::OK, "[]"),
                // remove_volume
                StubResponse::new(StatusCode::NO_CONTENT, ""),
            ],
        );
        let service = test_service(socket_path.clone());

        let response = ComputeDriver::delete_sandbox(
            &service,
            Request::new(DeleteSandboxRequest {
                sandbox_id: sandbox_id.to_string(),
                sandbox_name: "demo".to_string(),
            }),
        )
        .await
        .expect("delete should succeed")
        .into_inner();

        assert!(
            !response.deleted,
            "already-removed containers should still report deleted=false"
        );
        handle.await.expect("stub task should finish");
        let requests = request_log
            .lock()
            .expect("request log lock should not be poisoned")
            .clone();
        assert!(requests[0].contains("/libpod/containers/json"));
        assert_eq!(
            requests[1],
            format!(
                "DELETE {}",
                api_path(&format!("/libpod/volumes/{volume_name}"))
            )
        );
        let _ = std::fs::remove_file(socket_path);
    }
}
