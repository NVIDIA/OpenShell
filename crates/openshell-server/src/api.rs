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

    /// Create a sandbox.
    ///
    /// Delegates to `create_sandbox_core` — same path the gRPC handler
    /// takes, so validation, persistence, telemetry, JWT minting, and
    /// compute driver dispatch all apply.
    ///
    /// # Errors
    ///
    /// See [`crate::grpc::sandbox::create_sandbox_core`].
    pub async fn create_sandbox(&self, req: CreateSandboxRequest) -> Result<Sandbox, Status> {
        crate::grpc::create_sandbox_core(&self.state, req).await
    }

    /// Delete a sandbox by name. Returns whether the sandbox existed.
    ///
    /// Delegates to `delete_sandbox_core` — same path the gRPC handler
    /// takes.
    ///
    /// # Errors
    ///
    /// See [`crate::grpc::sandbox::delete_sandbox_core`].
    pub async fn delete_sandbox(&self, name: &str) -> Result<bool, Status> {
        crate::grpc::delete_sandbox_core(&self.state, name).await
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
}
