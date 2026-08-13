// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::result_large_err)] // gRPC handlers return Result<_, tonic::Status>

use futures::{Stream, StreamExt};
use openshell_core::proto::compute::v1::{
    CreateSandboxRequest, CreateSandboxResponse, DeleteSandboxRequest, DeleteSandboxResponse,
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

#[derive(Debug, Clone)]
pub struct ComputeDriverService {
    driver: KubernetesComputeDriver,
}

impl ComputeDriverService {
    #[must_use]
    pub fn new(driver: KubernetesComputeDriver) -> Self {
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
            .map(Response::new)
            .map_err(Status::internal)
    }

    async fn get_gateway_listener_requirements(
        &self,
        _request: Request<GetGatewayListenerRequirementsRequest>,
    ) -> Result<Response<GetGatewayListenerRequirementsResponse>, Status> {
        Ok(Response::new(GetGatewayListenerRequirementsResponse {
            requirements: Vec::new(),
        }))
    }

    async fn validate_sandbox_create(
        &self,
        request: Request<ValidateSandboxCreateRequest>,
    ) -> Result<Response<ValidateSandboxCreateResponse>, Status> {
        let sandbox = request
            .into_inner()
            .sandbox
            .ok_or_else(|| Status::invalid_argument("sandbox is required"))?;
        self.driver.validate_sandbox_create(&sandbox).await?;
        Ok(Response::new(ValidateSandboxCreateResponse {}))
    }

    async fn get_sandbox(
        &self,
        request: Request<GetSandboxRequest>,
    ) -> Result<Response<GetSandboxResponse>, Status> {
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
    }

    async fn list_sandboxes(
        &self,
        _request: Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        let sandboxes = self
            .driver
            .list_sandboxes()
            .await
            .map_err(Status::internal)?;
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
            .map_err(|e| Status::from(openshell_core::ComputeDriverError::from(e)))?;
        Ok(Response::new(CreateSandboxResponse {}))
    }

    async fn stop_sandbox(
        &self,
        request: Request<StopSandboxRequest>,
    ) -> Result<Response<StopSandboxResponse>, Status> {
        let request = request.into_inner();
        if request.sandbox_id.is_empty() {
            return Err(Status::invalid_argument("sandbox_id is required"));
        }
        self.driver
            .stop_sandbox(&request.sandbox_id)
            .await
            .map_err(kubernetes_lifecycle_status)?;
        Ok(Response::new(StopSandboxResponse {}))
    }

    async fn start_sandbox(
        &self,
        request: Request<StartSandboxRequest>,
    ) -> Result<Response<StartSandboxResponse>, Status> {
        let request = request.into_inner();
        if request.sandbox_id.is_empty() {
            return Err(Status::invalid_argument("sandbox_id is required"));
        }
        self.driver
            .start_sandbox(&request.sandbox_id)
            .await
            .map_err(kubernetes_lifecycle_status)?;
        Ok(Response::new(StartSandboxResponse {}))
    }

    async fn delete_sandbox(
        &self,
        request: Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
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
            .map_err(Status::internal)?;
        let stream = stream.map(|item| item.map_err(|err| Status::internal(err.to_string())));
        Ok(Response::new(Box::pin(stream)))
    }
}

fn kubernetes_lifecycle_status(message: String) -> Status {
    if message == "sandbox not found" {
        Status::not_found(message)
    } else {
        Status::internal(message)
    }
}

#[cfg(test)]
mod tests {
    use crate::KubernetesDriverError;
    use openshell_core::ComputeDriverError;
    use tonic::Status;

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
    fn already_exists_driver_errors_map_to_already_exists_status() {
        let status: Status = ComputeDriverError::from(KubernetesDriverError::AlreadyExists).into();

        assert_eq!(status.code(), tonic::Code::AlreadyExists);
        assert_eq!(status.message(), "sandbox already exists");
    }
}
