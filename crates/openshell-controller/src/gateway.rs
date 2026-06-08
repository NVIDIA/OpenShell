// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway client trait — abstraction over "how the reconciler talks to
//! the gateway."
//!
//! In production (`openshell-server` spawns the controller in-process) the
//! implementation is a direct Rust call into the gateway's create-sandbox
//! core. The trait keeps the controller code free of a hard dependency on
//! `openshell-server` and lets the standalone dev example inject a stub.

use async_trait::async_trait;
use openshell_core::proto::{CreateSandboxRequest, Sandbox};
use tonic::Status;

/// What the reconciler needs from the gateway.
///
/// Implemented in `openshell-server::api::GatewayHandle` for the in-process
/// production path. The standalone dev example provides a [`NoopGateway`]
/// stub so the reconciler can run end-to-end without a real gateway
/// attached.
#[async_trait]
pub trait GatewayClient: Send + Sync + 'static {
    async fn create_sandbox(&self, req: CreateSandboxRequest) -> Result<Sandbox, Status>;

    /// Delete a sandbox by name. Returns whether the sandbox existed; a
    /// `false` is a successful no-op (the gateway side was already gone).
    async fn delete_sandbox(&self, name: &str) -> Result<bool, Status>;

    /// Find at most one sandbox tagged with a given label.
    ///
    /// Used by the reconciler to discover whether a sandbox for the
    /// current CR's uid already exists, so create can be skipped on
    /// re-reconcile (cross-namespace name collisions, spec edits,
    /// controller crash recovery).
    async fn find_sandbox_by_label(
        &self,
        key: &str,
        value: &str,
    ) -> Result<Option<Sandbox>, Status>;
}

/// Stub implementation used by the standalone dev example and unit tests.
///
/// Create returns `Status::unimplemented` so the reconciler can still
/// drive the watch loop and patch a Failed status. Delete returns
/// `Ok(false)` so the finalizer cleanly removes itself — exercising the
/// deletion path without a real gateway behind it.
pub struct NoopGateway;

#[async_trait]
impl GatewayClient for NoopGateway {
    async fn create_sandbox(&self, req: CreateSandboxRequest) -> Result<Sandbox, Status> {
        tracing::info!(
            request_name = %req.name,
            "NoopGateway::create_sandbox — request received but not forwarded"
        );
        Err(Status::unimplemented(
            "NoopGateway: standalone dev mode — no real gateway attached",
        ))
    }

    async fn delete_sandbox(&self, name: &str) -> Result<bool, Status> {
        tracing::info!(
            sandbox_name = %name,
            "NoopGateway::delete_sandbox — no-op"
        );
        Ok(false)
    }

    async fn find_sandbox_by_label(
        &self,
        _key: &str,
        _value: &str,
    ) -> Result<Option<Sandbox>, Status> {
        Ok(None)
    }
}
