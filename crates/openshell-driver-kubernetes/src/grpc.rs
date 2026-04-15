// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use futures::{Stream, StreamExt};
use openshell_core::proto::compute::v1::{
    CreateSandboxRequest, CreateSandboxResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    GetCapabilitiesRequest, GetCapabilitiesResponse, GetSandboxRequest, GetSandboxResponse,
    ListSandboxesRequest, ListSandboxesResponse, ResolveSandboxEndpointRequest,
    ResolveSandboxEndpointResponse, StopSandboxRequest, StopSandboxResponse,
    ValidateSandboxCreateRequest, ValidateSandboxCreateResponse, WatchSandboxesEvent,
    WatchSandboxesRequest, compute_driver_server::ComputeDriver,
};
use std::pin::Pin;
use tonic::{Request, Response, Status};

use crate::{KubernetesComputeDriver, KubernetesDriverError};

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
            .await
            .map(Response::new)
            .map_err(Status::internal)
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
        if request.sandbox_name.is_empty() {
            return Err(Status::invalid_argument("sandbox_name is required"));
        }

        let sandbox = self
            .driver
            .get_sandbox(&request.sandbox_name)
            .await
            .map_err(Status::internal)?
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
            .map_err(status_from_driver_error)?;
        Ok(Response::new(CreateSandboxResponse {}))
    }

    async fn stop_sandbox(
        &self,
        _request: Request<StopSandboxRequest>,
    ) -> Result<Response<StopSandboxResponse>, Status> {
        Err(Status::unimplemented(
            "stop sandbox is not implemented by the kubernetes compute driver",
        ))
    }

    async fn delete_sandbox(
        &self,
        request: Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        let request = request.into_inner();
        let deleted = self
            .driver
            .delete_sandbox(&request.sandbox_name)
            .await
            .map_err(Status::internal)?;
        Ok(Response::new(DeleteSandboxResponse { deleted }))
    }

    async fn resolve_sandbox_endpoint(
        &self,
        request: Request<ResolveSandboxEndpointRequest>,
    ) -> Result<Response<ResolveSandboxEndpointResponse>, Status> {
        let sandbox = request
            .into_inner()
            .sandbox
            .ok_or_else(|| Status::invalid_argument("sandbox is required"))?;
        self.driver
            .resolve_sandbox_endpoint(&sandbox)
            .await
            .map(Response::new)
            .map_err(status_from_driver_error)
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

fn status_from_driver_error(err: KubernetesDriverError) -> Status {
    match err {
        KubernetesDriverError::AlreadyExists => Status::already_exists("sandbox already exists"),
        KubernetesDriverError::Precondition(message) => Status::failed_precondition(message),
        KubernetesDriverError::Message(message) => Status::internal(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precondition_driver_errors_map_to_failed_precondition_status() {
        let status = status_from_driver_error(KubernetesDriverError::Precondition(
            "sandbox agent pod IP is not available".to_string(),
        ));

        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_eq!(status.message(), "sandbox agent pod IP is not available");
    }

    #[test]
    fn already_exists_driver_errors_map_to_already_exists_status() {
        let status = status_from_driver_error(KubernetesDriverError::AlreadyExists);

        assert_eq!(status.code(), tonic::Code::AlreadyExists);
        assert_eq!(status.message(), "sandbox already exists");
    }
}
