// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Thin tonic adapter: delegates to `MxcComputeBackend` and maps errors to
//! gRPC `Status`.

#![allow(clippy::result_large_err)]

use crate::driver::MxcComputeBackend;
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

#[derive(Debug)]
pub struct ComputeDriverService {
    backend: MxcComputeBackend,
}

impl ComputeDriverService {
    pub fn new(backend: MxcComputeBackend) -> Self {
        Self { backend }
    }
}

#[tonic::async_trait]
impl ComputeDriver for ComputeDriverService {
    async fn get_capabilities(
        &self,
        _request: Request<GetCapabilitiesRequest>,
    ) -> Result<Response<GetCapabilitiesResponse>, Status> {
        Ok(Response::new(self.backend.capabilities()))
    }

    async fn authenticate_sandbox(
        &self,
        _request: Request<AuthenticateSandboxRequest>,
    ) -> Result<Response<AuthenticateSandboxResponse>, Status> {
        Err(Status::unimplemented(
            "mxc does not authenticate sandbox credentials",
        ))
    }

    async fn get_gateway_listener_requirements(
        &self,
        _request: Request<GetGatewayListenerRequirementsRequest>,
    ) -> Result<Response<GetGatewayListenerRequirementsResponse>, Status> {
        // MXC is an in-process, single-host driver: it needs no extra gateway
        // listeners (no relay/surrogate/remote endpoint), so it reports none.
        Ok(Response::new(GetGatewayListenerRequirementsResponse {
            requirements: Vec::new(),
        }))
    }

    async fn validate_sandbox_create(
        &self,
        request: Request<ValidateSandboxCreateRequest>,
    ) -> Result<Response<ValidateSandboxCreateResponse>, Status> {
        let request = request.into_inner();
        let sandbox = request
            .sandbox
            .ok_or_else(|| Status::invalid_argument("sandbox is required"))?;
        self.backend.validate_sandbox_create(&sandbox)?;
        Ok(Response::new(ValidateSandboxCreateResponse {}))
    }

    async fn get_sandbox(
        &self,
        request: Request<GetSandboxRequest>,
    ) -> Result<Response<GetSandboxResponse>, Status> {
        let req = request.into_inner();
        if req.sandbox_name.is_empty() {
            return Err(Status::invalid_argument("sandbox_name is required"));
        }
        let sandbox = self
            .backend
            .get_sandbox(&req.sandbox_name)
            .await
            .ok_or_else(|| Status::not_found(format!("sandbox {} not found", req.sandbox_name)))?;
        if !req.sandbox_id.is_empty() && req.sandbox_id != sandbox.id {
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
        let sandboxes = self.backend.list_sandboxes().await;
        Ok(Response::new(ListSandboxesResponse { sandboxes }))
    }

    async fn create_sandbox(
        &self,
        request: Request<CreateSandboxRequest>,
    ) -> Result<Response<CreateSandboxResponse>, Status> {
        let request = request.into_inner();
        let sandbox = request
            .sandbox
            .ok_or_else(|| Status::invalid_argument("sandbox is required"))?;
        self.backend.create_sandbox(&sandbox).await?;
        Ok(Response::new(CreateSandboxResponse {}))
    }

    async fn stop_sandbox(
        &self,
        request: Request<StopSandboxRequest>,
    ) -> Result<Response<StopSandboxResponse>, Status> {
        let req = request.into_inner();
        if req.sandbox_name.is_empty() {
            return Err(Status::invalid_argument("sandbox_name is required"));
        }
        self.backend.stop_sandbox(&req.sandbox_name).await?;
        Ok(Response::new(StopSandboxResponse {}))
    }

    async fn start_sandbox(
        &self,
        _request: Request<StartSandboxRequest>,
    ) -> Result<Response<StartSandboxResponse>, Status> {
        Err(Status::unimplemented(
            "mxc driver does not support restarting stopped sandboxes",
        ))
    }

    async fn delete_sandbox(
        &self,
        request: Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        let req = request.into_inner();
        if req.sandbox_id.is_empty() {
            return Err(Status::invalid_argument("sandbox_id is required"));
        }
        if req.sandbox_name.is_empty() {
            return Err(Status::invalid_argument("sandbox_name is required"));
        }
        let deleted = self
            .backend
            .delete_sandbox(&req.sandbox_id, &req.sandbox_name)
            .await?;
        Ok(Response::new(DeleteSandboxResponse { deleted }))
    }

    type WatchSandboxesStream =
        Pin<Box<dyn Stream<Item = Result<WatchSandboxesEvent, Status>> + Send + 'static>>;

    async fn watch_sandboxes(
        &self,
        _request: Request<WatchSandboxesRequest>,
    ) -> Result<Response<Self::WatchSandboxesStream>, Status> {
        let stream = self.backend.watch_sandboxes().await;
        let mapped = stream.map(|item| item.map_err(|e| Status::internal(e.to_string())));
        Ok(Response::new(Box::pin(mapped)))
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::MxcComputeConfig;

    #[tokio::test]
    async fn start_sandbox_reports_one_shot_lifecycle() {
        let service =
            ComputeDriverService::new(MxcComputeBackend::new(MxcComputeConfig::default()));

        let error = service
            .start_sandbox(Request::new(StartSandboxRequest::default()))
            .await
            .expect_err("MXC must not restart a stopped one-shot workload");

        assert_eq!(error.code(), tonic::Code::Unimplemented);
        assert!(error.message().contains("does not support restarting"));
    }

    #[tokio::test]
    async fn workspace_lifecycle_is_an_idempotent_no_op() {
        let service =
            ComputeDriverService::new(MxcComputeBackend::new(MxcComputeConfig::default()));

        service
            .ensure_workspace(Request::new(EnsureWorkspaceRequest::default()))
            .await
            .expect("MXC has no driver-owned workspace resource to provision");
        service
            .delete_workspace(Request::new(DeleteWorkspaceRequest::default()))
            .await
            .expect("MXC workspace deletion must remain idempotent");
    }
}
