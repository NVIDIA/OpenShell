// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use futures::{Stream, StreamExt};
use openshell_core::proto::compute_driver_server::ComputeDriver;
use openshell_core::proto::{
    ComputeCreateSandboxRequest, ComputeCreateSandboxResponse, ComputeDeleteSandboxRequest,
    ComputeDeleteSandboxResponse, GetCapabilitiesRequest, GetCapabilitiesResponse,
    ResolveSandboxEndpointRequest, ResolveSandboxEndpointResponse, ValidateSandboxCreateRequest,
    ValidateSandboxCreateResponse, WatchSandboxesEvent, WatchSandboxesRequest,
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

    async fn create_sandbox(
        &self,
        request: Request<ComputeCreateSandboxRequest>,
    ) -> Result<Response<ComputeCreateSandboxResponse>, Status> {
        let sandbox = request
            .into_inner()
            .sandbox
            .ok_or_else(|| Status::invalid_argument("sandbox is required"))?;
        self.driver
            .create_sandbox(&sandbox)
            .await
            .map_err(|err| Status::internal(err.to_string()))?;
        Ok(Response::new(ComputeCreateSandboxResponse {}))
    }

    async fn delete_sandbox(
        &self,
        request: Request<ComputeDeleteSandboxRequest>,
    ) -> Result<Response<ComputeDeleteSandboxResponse>, Status> {
        let request = request.into_inner();
        let deleted = self
            .driver
            .delete_sandbox(&request.sandbox_name)
            .await
            .map_err(Status::internal)?;
        Ok(Response::new(ComputeDeleteSandboxResponse { deleted }))
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
            .map_err(Status::internal)
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
