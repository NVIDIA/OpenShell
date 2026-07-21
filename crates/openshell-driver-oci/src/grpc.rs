// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::result_large_err)] // gRPC handlers return Result<_, tonic::Status>

use futures::StreamExt;
use openshell_core::proto::compute::v1::{
    CreateSandboxRequest, CreateSandboxResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    GetCapabilitiesRequest, GetCapabilitiesResponse, GetSandboxRequest, GetSandboxResponse,
    ListSandboxesRequest, ListSandboxesResponse, StopSandboxRequest, StopSandboxResponse,
    ValidateSandboxCreateRequest, ValidateSandboxCreateResponse, WatchSandboxesEvent,
    WatchSandboxesRequest, compute_driver_server::ComputeDriver,
};
use std::pin::Pin;
use tonic::{Request, Response, Status};

use crate::driver::OciComputeDriver;

#[derive(Debug, Clone)]
pub struct ComputeDriverService {
    driver: OciComputeDriver,
}

impl ComputeDriverService {
    #[must_use]
    pub fn new(driver: OciComputeDriver) -> Self {
        Self { driver }
    }
}

#[tonic::async_trait]
impl ComputeDriver for ComputeDriverService {
    async fn get_capabilities(
        &self,
        _request: Request<GetCapabilitiesRequest>,
    ) -> Result<Response<GetCapabilitiesResponse>, Status> {
        Ok(Response::new(self.driver.capabilities()))
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
            .map_err(Status::from)?;
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
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;
        Ok(Response::new(GetSandboxResponse {
            sandbox: Some(sandbox),
        }))
    }

    async fn list_sandboxes(
        &self,
        _request: Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        let sandboxes = self.driver.list_sandboxes().map_err(Status::from)?;
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
            .map_err(Status::from)?;
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
            .map_err(Status::from)?;
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
            .map_err(Status::from)?;
        Ok(Response::new(DeleteSandboxResponse { deleted }))
    }

    type WatchSandboxesStream =
        Pin<Box<dyn futures::Stream<Item = Result<WatchSandboxesEvent, Status>> + Send>>;

    async fn watch_sandboxes(
        &self,
        _request: Request<WatchSandboxesRequest>,
    ) -> Result<Response<Self::WatchSandboxesStream>, Status> {
        let stream = self.driver.watch_sandboxes().map_err(Status::from)?;
        let stream = stream.map(|item| item.map_err(|err| Status::internal(err.to_string())));
        Ok(Response::new(Box::pin(stream)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn delete_sandbox_rejects_missing_sandbox_name() {
        let config = crate::config::OciComputeConfig {
            containerd_socket_path: std::path::PathBuf::from("/nonexistent/containerd.sock"),
            ..crate::config::OciComputeConfig::default()
        };
        // Constructing a real driver requires dialing containerd; these
        // request-validation checks happen before any driver method is
        // called, on the raw request, so a not-yet-connected provider
        // isn't needed for them. `tonic`'s `Channel` is lazy (it does not
        // dial until first use), so building the service here does not
        // require a reachable containerd socket.
        let channel = tonic::transport::Endpoint::try_from("http://[::]:0")
            .unwrap()
            .connect_lazy();
        let rootfs = openshell_rootfs::ContainerdRootfsProvider::from_channel(
            channel,
            config.containerd_namespace.clone(),
            config.snapshotter.clone(),
        );
        let driver = OciComputeDriver::for_tests(config, rootfs);
        let service = ComputeDriverService::new(driver);

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
        let config = crate::config::OciComputeConfig::default();
        let channel = tonic::transport::Endpoint::try_from("http://[::]:0")
            .unwrap()
            .connect_lazy();
        let rootfs = openshell_rootfs::ContainerdRootfsProvider::from_channel(
            channel,
            config.containerd_namespace.clone(),
            config.snapshotter.clone(),
        );
        let driver = OciComputeDriver::for_tests(config, rootfs);
        let service = ComputeDriverService::new(driver);

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
}
