// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use futures::{Stream, StreamExt};
use openshell_core::proto::compute::v1::{
    CreateSandboxRequest, CreateSandboxResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    GetCapabilitiesRequest, GetCapabilitiesResponse, GetSandboxRequest, GetSandboxResponse,
    ListSandboxesRequest, ListSandboxesResponse, StopSandboxRequest, StopSandboxResponse,
    ValidateSandboxCreateRequest, ValidateSandboxCreateResponse, WatchSandboxesEvent,
    WatchSandboxesRequest, compute_driver_server::ComputeDriver,
};
use std::pin::Pin;
use tonic::{Request, Response, Status};

use crate::PodmanComputeDriver;
use openshell_core::ComputeDriverError;

#[derive(Debug, Clone)]
pub struct ComputeDriverService {
    driver: PodmanComputeDriver,
}

impl ComputeDriverService {
    #[must_use]
    pub fn new(driver: PodmanComputeDriver) -> Self {
        Self { driver }
    }
}

#[tonic::async_trait]
impl ComputeDriver for ComputeDriverService {
    async fn get_capabilities(
        &self,
        _request: Request<GetCapabilitiesRequest>,
    ) -> Result<Response<GetCapabilitiesResponse>, Status> {
        self.driver
            .capabilities()
            .await
            .map(Response::new)
            .map_err(status_from_driver_error)
    }

    async fn validate_sandbox_create(
        &self,
        request: Request<ValidateSandboxCreateRequest>,
    ) -> Result<Response<ValidateSandboxCreateResponse>, Status> {
        let sandbox = request
            .into_inner()
            .sandbox
            .ok_or_else(|| Status::invalid_argument("sandbox is required"))?;
        self.driver
            .validate_sandbox_create(&sandbox)
            .await
            .map_err(status_from_driver_error)?;
        Ok(Response::new(ValidateSandboxCreateResponse {}))
    }

    async fn get_sandbox(
        &self,
        request: Request<GetSandboxRequest>,
    ) -> Result<Response<GetSandboxResponse>, Status> {
        let request = request.into_inner();
        if request.sandbox_name.is_empty() {
            return Err(Status::invalid_argument("sandbox_name is required"));
        }

        let sandbox = self
            .driver
            .get_sandbox(&request.sandbox_name)
            .await
            .map_err(status_from_driver_error)?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;

        if !request.sandbox_id.is_empty() && request.sandbox_id != sandbox.id {
            return Err(Status::failed_precondition(
                "sandbox_id did not match the fetched sandbox",
            ));
        }

        Ok(Response::new(GetSandboxResponse {
            sandbox: Some(sandbox),
        }))
    }

    async fn list_sandboxes(
        &self,
        _request: Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        let sandboxes = self
            .driver
            .list_sandboxes()
            .await
            .map_err(status_from_driver_error)?;
        Ok(Response::new(ListSandboxesResponse { sandboxes }))
    }

    async fn create_sandbox(
        &self,
        request: Request<CreateSandboxRequest>,
    ) -> Result<Response<CreateSandboxResponse>, Status> {
        let sandbox = request
            .into_inner()
            .sandbox
            .ok_or_else(|| Status::invalid_argument("sandbox is required"))?;
        self.driver
            .create_sandbox(&sandbox)
            .await
            .map_err(status_from_driver_error)?;
        Ok(Response::new(CreateSandboxResponse {}))
    }

    async fn stop_sandbox(
        &self,
        request: Request<StopSandboxRequest>,
    ) -> Result<Response<StopSandboxResponse>, Status> {
        let request = request.into_inner();
        if request.sandbox_name.is_empty() {
            return Err(Status::invalid_argument("sandbox_name is required"));
        }
        self.driver
            .stop_sandbox(&request.sandbox_name)
            .await
            .map_err(status_from_driver_error)?;
        Ok(Response::new(StopSandboxResponse {}))
    }

    async fn delete_sandbox(
        &self,
        request: Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        let request = request.into_inner();
        if request.sandbox_id.is_empty() {
            return Err(Status::invalid_argument("sandbox_id is required"));
        }
        if request.sandbox_name.is_empty() {
            return Err(Status::invalid_argument("sandbox_name is required"));
        }
        let deleted = self
            .driver
            .delete_sandbox(&request.sandbox_id, &request.sandbox_name)
            .await
            .map_err(status_from_driver_error)?;
        Ok(Response::new(DeleteSandboxResponse { deleted }))
    }

    type WatchSandboxesStream =
        Pin<Box<dyn Stream<Item = Result<WatchSandboxesEvent, Status>> + Send + 'static>>;

    async fn watch_sandboxes(
        &self,
        _request: Request<WatchSandboxesRequest>,
    ) -> Result<Response<Self::WatchSandboxesStream>, Status> {
        let stream = self
            .driver
            .watch_sandboxes()
            .await
            .map_err(status_from_driver_error)?;
        let stream = stream.map(|item| item.map_err(|err| Status::internal(err.to_string())));
        Ok(Response::new(Box::pin(stream)))
    }
}

fn status_from_driver_error(err: ComputeDriverError) -> Status {
    match err {
        ComputeDriverError::AlreadyExists => Status::already_exists("sandbox already exists"),
        ComputeDriverError::Precondition(message) => Status::failed_precondition(message),
        ComputeDriverError::Message(message) => Status::internal(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PodmanComputeConfig;
    use crate::container;
    use http_body_util::Full;
    use hyper::body::Bytes;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Response as HyperResponse, StatusCode};
    use hyper_util::rt::TokioIo;
    use std::collections::VecDeque;
    use std::convert::Infallible;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn precondition_driver_errors_map_to_failed_precondition_status() {
        let status = status_from_driver_error(ComputeDriverError::Precondition(
            "sandbox container is not running".to_string(),
        ));

        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_eq!(status.message(), "sandbox container is not running");
    }

    #[test]
    fn already_exists_driver_errors_map_to_already_exists_status() {
        let status = status_from_driver_error(ComputeDriverError::AlreadyExists);
        assert_eq!(status.code(), tonic::Code::AlreadyExists);
    }

    #[derive(Clone)]
    struct StubResponse {
        status: StatusCode,
        body: String,
    }

    impl StubResponse {
        fn new(status: StatusCode, body: impl Into<String>) -> Self {
            Self {
                status,
                body: body.into(),
            }
        }
    }

    fn unique_socket_path(test_name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        PathBuf::from(format!(
            "/tmp/openshell-podman-grpc-{test_name}-{}-{nanos}.sock",
            std::process::id()
        ))
    }

    fn spawn_podman_stub(
        test_name: &str,
        responses: Vec<StubResponse>,
    ) -> (
        PathBuf,
        Arc<Mutex<Vec<String>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let socket_path = unique_socket_path(test_name);
        let _ = std::fs::remove_file(&socket_path);
        let listener =
            tokio::net::UnixListener::bind(&socket_path).expect("test socket should bind");
        let request_log = Arc::new(Mutex::new(Vec::new()));
        let response_queue = Arc::new(Mutex::new(VecDeque::from(responses)));
        let expected = response_queue
            .lock()
            .expect("response queue lock should not be poisoned")
            .len();
        let socket_path_for_task = socket_path.clone();
        let log_for_task = request_log.clone();
        let queue_for_task = response_queue.clone();
        let handle = tokio::spawn(async move {
            for _ in 0..expected {
                let (stream, _) = listener.accept().await.expect("test stub should accept");
                let log = log_for_task.clone();
                let queue = queue_for_task.clone();
                http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |req| {
                            let log = log.clone();
                            let queue = queue.clone();
                            async move {
                                let path = req
                                    .uri()
                                    .path_and_query()
                                    .map(|pq| pq.as_str().to_string())
                                    .unwrap_or_else(|| req.uri().path().to_string());
                                log.lock()
                                    .expect("request log lock should not be poisoned")
                                    .push(format!("{} {}", req.method(), path));
                                let response = queue
                                    .lock()
                                    .expect("response queue lock should not be poisoned")
                                    .pop_front()
                                    .expect("stub response should exist");
                                Ok::<_, Infallible>(
                                    HyperResponse::builder()
                                        .status(response.status)
                                        .body(Full::new(Bytes::from(response.body)))
                                        .expect("stub response should build"),
                                )
                            }
                        }),
                    )
                    .await
                    .expect("test stub should serve request");
            }
            let _ = std::fs::remove_file(&socket_path_for_task);
        });
        (socket_path, request_log, handle)
    }

    fn test_service(socket_path: PathBuf) -> ComputeDriverService {
        let config = PodmanComputeConfig {
            socket_path,
            stop_timeout_secs: 10,
            ..PodmanComputeConfig::default()
        };
        ComputeDriverService::new(PodmanComputeDriver::for_tests(config))
    }

    fn api_path(path: &str) -> String {
        format!("/v5.0.0{path}")
    }

    #[tokio::test]
    async fn delete_sandbox_rejects_missing_sandbox_name() {
        let service = test_service(unique_socket_path("missing-name"));

        let err = ComputeDriver::delete_sandbox(
            &service,
            Request::new(DeleteSandboxRequest {
                sandbox_id: "sandbox-123".to_string(),
                sandbox_name: String::new(),
            }),
        )
        .await
        .expect_err("missing sandbox_name should fail");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(err.message(), "sandbox_name is required");
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
        let sandbox_name = "demo";
        let container_name = container::container_name(sandbox_name);
        let volume_name = container::volume_name(sandbox_id);
        let secret_name = container::secret_name(sandbox_id);
        let (socket_path, request_log, handle) = spawn_podman_stub(
            "forward-id",
            vec![
                StubResponse::new(StatusCode::NOT_FOUND, r#"{"message":"gone"}"#),
                StubResponse::new(StatusCode::NOT_FOUND, r#"{"message":"gone"}"#),
                StubResponse::new(StatusCode::NOT_FOUND, r#"{"message":"gone"}"#),
                StubResponse::new(StatusCode::NO_CONTENT, ""),
                StubResponse::new(StatusCode::NO_CONTENT, ""),
            ],
        );
        let service = test_service(socket_path.clone());

        let response = ComputeDriver::delete_sandbox(
            &service,
            Request::new(DeleteSandboxRequest {
                sandbox_id: sandbox_id.to_string(),
                sandbox_name: sandbox_name.to_string(),
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
        assert_eq!(
            requests,
            vec![
                format!(
                    "GET {}",
                    api_path(&format!("/libpod/containers/{container_name}/json"))
                ),
                format!(
                    "POST {}",
                    api_path(&format!(
                        "/libpod/containers/{container_name}/stop?timeout=10"
                    ))
                ),
                format!(
                    "DELETE {}",
                    api_path(&format!(
                        "/libpod/containers/{container_name}?force=true&v=true"
                    ))
                ),
                format!(
                    "DELETE {}",
                    api_path(&format!("/libpod/volumes/{volume_name}"))
                ),
                format!(
                    "DELETE {}",
                    api_path(&format!("/libpod/secrets/{secret_name}"))
                ),
            ]
        );
        let _ = std::fs::remove_file(socket_path);
    }
}
