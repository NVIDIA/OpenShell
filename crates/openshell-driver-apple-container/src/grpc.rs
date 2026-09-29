// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::result_large_err)] // gRPC handlers return Result<_, tonic::Status>

//! gRPC service adapter for the Apple Container compute driver.

use futures::{Stream, StreamExt};
use openshell_core::proto::compute::v1::{
    CreateSandboxRequest, CreateSandboxResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    DeleteWorkspaceRequest, DeleteWorkspaceResponse, EnsureWorkspaceRequest,
    EnsureWorkspaceResponse, GetCapabilitiesRequest, GetCapabilitiesResponse, GetSandboxRequest,
    GetSandboxResponse, ListSandboxesRequest, ListSandboxesResponse, StartSandboxRequest,
    StartSandboxResponse, StopSandboxRequest, StopSandboxResponse, ValidateSandboxCreateRequest,
    ValidateSandboxCreateResponse, WatchSandboxesEvent, WatchSandboxesRequest,
    compute_driver_server::ComputeDriver,
};
use std::pin::Pin;
use std::sync::Arc;
use tonic::{Request, Response, Status};

use crate::AppleContainerComputeDriver;

/// Tonic service wrapper around [`AppleContainerComputeDriver`].
#[derive(Debug, Clone)]
pub struct ComputeDriverService {
    driver: Arc<AppleContainerComputeDriver>,
}

impl ComputeDriverService {
    /// Create a new gRPC service.
    #[must_use]
    pub fn new(driver: Arc<AppleContainerComputeDriver>) -> Self {
        Self { driver }
    }

    /// Create a new in-process gRPC service.
    ///
    /// The Apple-container driver is always composed in-process by the
    /// gateway; this constructor mirrors the Podman driver's
    /// `new_in_process` entry point so the gateway composition can pick the
    /// same shape for both drivers.
    #[must_use]
    pub fn new_in_process(driver: Arc<AppleContainerComputeDriver>) -> Self {
        Self { driver }
    }
}

#[tonic::async_trait]
impl ComputeDriver for ComputeDriverService {
    async fn authenticate_sandbox(
        &self,
        _request: Request<openshell_core::proto::compute::v1::AuthenticateSandboxRequest>,
    ) -> Result<Response<openshell_core::proto::compute::v1::AuthenticateSandboxResponse>, Status>
    {
        Err(Status::unimplemented(
            "apple-container does not authenticate sandbox credentials",
        ))
    }

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
        self.driver.validate_sandbox_create(&sandbox)?;
        Ok(Response::new(ValidateSandboxCreateResponse {}))
    }

    async fn get_sandbox(
        &self,
        request: Request<GetSandboxRequest>,
    ) -> Result<Response<GetSandboxResponse>, Status> {
        let request = request.into_inner();
        if request.sandbox_id.is_empty() && request.name.is_empty() {
            return Err(Status::invalid_argument("sandbox_id or name is required"));
        }
        let sandbox = self
            .driver
            .get_sandbox(&request.sandbox_id, &request.name)
            .await?
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
        Ok(Response::new(ListSandboxesResponse {
            sandboxes: self.driver.list_sandboxes().await?,
        }))
    }

    async fn create_sandbox(
        &self,
        request: Request<CreateSandboxRequest>,
    ) -> Result<Response<CreateSandboxResponse>, Status> {
        let sandbox = request
            .into_inner()
            .sandbox
            .ok_or_else(|| Status::invalid_argument("sandbox is required"))?;
        self.driver.create_sandbox(&sandbox).await?;
        Ok(Response::new(CreateSandboxResponse {
            runtime_identity: String::new(),
        }))
    }

    async fn stop_sandbox(
        &self,
        request: Request<StopSandboxRequest>,
    ) -> Result<Response<StopSandboxResponse>, Status> {
        let request = request.into_inner();
        self.driver
            .stop_sandbox(&request.sandbox_id, &request.name)
            .await?;
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
            .start_sandbox(
                &request.sandbox_id,
                &request.generation_id,
                &request.launch_authentication,
            )
            .await?;
        Ok(Response::new(StartSandboxResponse {
            runtime_identity: String::new(),
        }))
    }

    async fn delete_sandbox(
        &self,
        request: Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        let request = request.into_inner();
        let deleted = self
            .driver
            .delete_sandbox(&request.sandbox_id, &request.name)
            .await?;
        Ok(Response::new(DeleteSandboxResponse { deleted }))
    }

    async fn ensure_workspace(
        &self,
        _request: Request<EnsureWorkspaceRequest>,
    ) -> Result<Response<EnsureWorkspaceResponse>, Status> {
        Ok(Response::new(EnsureWorkspaceResponse {}))
    }

    async fn delete_workspace(
        &self,
        _request: Request<DeleteWorkspaceRequest>,
    ) -> Result<Response<DeleteWorkspaceResponse>, Status> {
        Ok(Response::new(DeleteWorkspaceResponse {}))
    }

    type WatchSandboxesStream =
        Pin<Box<dyn Stream<Item = Result<WatchSandboxesEvent, Status>> + Send + 'static>>;

    async fn watch_sandboxes(
        &self,
        _request: Request<WatchSandboxesRequest>,
    ) -> Result<Response<Self::WatchSandboxesStream>, Status> {
        let stream = self.driver.watch_sandboxes()?;
        let stream = stream.map(|item| item.map_err(Status::internal));
        Ok(Response::new(Box::pin(stream)))
    }
}
