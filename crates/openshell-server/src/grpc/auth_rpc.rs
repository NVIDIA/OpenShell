// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Authentication-related RPC handlers.
//!
//! Currently hosts the `IssueSandboxToken` exchange used by the Kubernetes
//! driver to convert a projected `ServiceAccount` token into a
//! gateway-minted JWT bound to a specific sandbox.

use crate::ServerState;
use crate::auth::principal::{Principal, SandboxIdentitySource};
use openshell_core::proto::{IssueSandboxTokenRequest, IssueSandboxTokenResponse};
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

#[allow(clippy::result_large_err, clippy::unused_async)]
pub async fn handle_issue_sandbox_token(
    state: &Arc<ServerState>,
    request: Request<IssueSandboxTokenRequest>,
) -> Result<Response<IssueSandboxTokenResponse>, Status> {
    let principal = request
        .extensions()
        .get::<Principal>()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("missing principal"))?;

    let Principal::Sandbox(sandbox) = principal else {
        return Err(Status::permission_denied(
            "IssueSandboxToken requires a sandbox principal",
        ));
    };

    // Only the bootstrap K8s ServiceAccount path can mint a fresh
    // gateway JWT — gateway-issued JWTs already exist and refreshing them
    // is a future capability (PR 5). Reject re-exchange attempts.
    if !matches!(
        sandbox.source,
        SandboxIdentitySource::K8sServiceAccount { .. }
    ) {
        debug!(
            sandbox_id = %sandbox.sandbox_id,
            "IssueSandboxToken rejected: non-bootstrap principal source"
        );
        return Err(Status::permission_denied(
            "this principal cannot mint a sandbox token",
        ));
    }

    let issuer = state.sandbox_jwt_issuer.as_ref().ok_or_else(|| {
        warn!(
            sandbox_id = %sandbox.sandbox_id,
            "IssueSandboxToken called but sandbox JWT issuer is not configured"
        );
        Status::unavailable("sandbox JWT minting is not configured on this gateway")
    })?;

    let minted = issuer.mint(&sandbox.sandbox_id)?;
    info!(
        sandbox_id = %sandbox.sandbox_id,
        jti = %minted.jti,
        "issued gateway sandbox JWT"
    );
    Ok(Response::new(IssueSandboxTokenResponse {
        token: minted.token,
        expires_at_ms: minted.expires_at_ms,
    }))
}
