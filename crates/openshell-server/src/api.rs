// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Public Rust API surfaced to in-process consumers.
//!
//! Currently consumed only by the `openshell-controller` crate. External
//! clients should use the gRPC service — this module exists so the in-tree
//! CRD controller can call the gateway's create-sandbox core function
//! without a localhost gRPC hop.

use std::sync::Arc;

use openshell_core::proto::{CreateSandboxRequest, Sandbox};
use tonic::Status;

use crate::ServerState;

/// In-process handle to the gateway.
///
/// Holds an `Arc<ServerState>` and exposes only the methods the CRD
/// controller needs. `ServerState` itself stays crate-private so the rest
/// of the gateway's internals aren't accidentally surfaced.
#[derive(Clone)]
pub struct GatewayHandle {
    state: Arc<ServerState>,
}

impl GatewayHandle {
    pub(crate) fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }

    /// Create a sandbox via the same path the gRPC handler takes.
    /// Validation, persistence, telemetry, JWT minting, and compute
    /// driver dispatch all apply.
    ///
    /// # Errors
    ///
    /// See [`crate::grpc::sandbox::create_sandbox_core`].
    pub async fn create_sandbox(&self, req: CreateSandboxRequest) -> Result<Sandbox, Status> {
        crate::grpc::create_sandbox_core(&self.state, req).await
    }

    /// Delete a sandbox by name. Returns whether the sandbox existed.
    ///
    /// # Errors
    ///
    /// See [`crate::grpc::sandbox::delete_sandbox_core`].
    pub async fn delete_sandbox(&self, name: &str) -> Result<bool, Status> {
        crate::grpc::delete_sandbox_core(&self.state, name).await
    }

    /// Find at most one sandbox tagged with a given label.
    ///
    /// Used by the CRD controller for cr-uid based idempotency: before
    /// creating a sandbox for a CR, look up whether one already exists
    /// for that CR's unforgeable uid. Returns `None` if no match.
    ///
    /// # Errors
    ///
    /// See [`crate::grpc::sandbox::find_sandbox_by_label`].
    pub async fn find_sandbox_by_label(
        &self,
        key: &str,
        value: &str,
    ) -> Result<Option<Sandbox>, Status> {
        crate::grpc::find_sandbox_by_label(&self.state, key, value).await
    }

    /// Fetch a sandbox by name. The returned `Sandbox` carries the
    /// gateway's current view including the driver-observed phase.
    ///
    /// # Errors
    ///
    /// See [`crate::grpc::sandbox::get_sandbox_core`].
    pub async fn get_sandbox(&self, name: &str) -> Result<Sandbox, Status> {
        crate::grpc::get_sandbox_core(&self.state, name).await
    }
}

#[async_trait::async_trait]
impl openshell_controller::GatewayClient for GatewayHandle {
    async fn create_sandbox(&self, req: CreateSandboxRequest) -> Result<Sandbox, Status> {
        Self::create_sandbox(self, req).await
    }

    async fn delete_sandbox(&self, name: &str) -> Result<bool, Status> {
        Self::delete_sandbox(self, name).await
    }

    async fn find_sandbox_by_label(
        &self,
        key: &str,
        value: &str,
    ) -> Result<Option<Sandbox>, Status> {
        Self::find_sandbox_by_label(self, key, value).await
    }

    async fn get_sandbox(&self, name: &str) -> Result<Sandbox, Status> {
        Self::get_sandbox(self, name).await
    }
}
