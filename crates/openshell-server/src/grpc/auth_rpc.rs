// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Authentication-related RPC handlers.
//!
//! Hosts the two sandbox-identity RPCs:
//! - `IssueSandboxToken` — bootstrap exchange (K8s SA token → gateway JWT)
//! - `RefreshSandboxToken` — rotate a still-valid gateway JWT
//!
//! Both end in a fresh gateway-signed JWT minted by
//! [`crate::auth::sandbox_jwt::SandboxJwtIssuer`]. `RefreshSandboxToken`
//! additionally revokes the previous JWT's `jti` so the old token
//! becomes unusable as soon as the new one is handed back.

use crate::ServerState;
use crate::auth::principal::{Principal, SandboxIdentitySource};
use openshell_core::proto::{
    IssueSandboxTokenRequest, IssueSandboxTokenResponse, RefreshSandboxTokenRequest,
    RefreshSandboxTokenResponse,
};
use std::sync::Arc;
use std::time::SystemTime;
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
    // gateway JWT via this RPC. Sandboxes already holding a gateway JWT
    // use `RefreshSandboxToken` instead, which also revokes the old jti.
    if !matches!(
        sandbox.source,
        SandboxIdentitySource::K8sServiceAccount { .. }
    ) {
        debug!(
            sandbox_id = %sandbox.sandbox_id,
            "IssueSandboxToken rejected: non-bootstrap principal source"
        );
        return Err(Status::permission_denied(
            "this principal cannot mint a sandbox token; use RefreshSandboxToken",
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

#[allow(clippy::result_large_err, clippy::unused_async)]
pub async fn handle_refresh_sandbox_token(
    state: &Arc<ServerState>,
    request: Request<RefreshSandboxTokenRequest>,
) -> Result<Response<RefreshSandboxTokenResponse>, Status> {
    let principal = request
        .extensions()
        .get::<Principal>()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("missing principal"))?;

    let Principal::Sandbox(sandbox) = principal else {
        return Err(Status::permission_denied(
            "RefreshSandboxToken requires a sandbox principal",
        ));
    };

    // Only callers already holding a gateway-minted JWT may refresh; the
    // K8s bootstrap path must use `IssueSandboxToken`.
    let SandboxIdentitySource::BootstrapJwt { jti: old_jti, .. } = &sandbox.source else {
        debug!(
            sandbox_id = %sandbox.sandbox_id,
            "RefreshSandboxToken rejected: non-gateway-JWT principal source"
        );
        return Err(Status::permission_denied(
            "this principal cannot refresh; use IssueSandboxToken for bootstrap",
        ));
    };

    let issuer = state.sandbox_jwt_issuer.as_ref().ok_or_else(|| {
        warn!(
            sandbox_id = %sandbox.sandbox_id,
            "RefreshSandboxToken called but sandbox JWT issuer is not configured"
        );
        Status::unavailable("sandbox JWT minting is not configured on this gateway")
    })?;

    // Mint the new token first; only revoke the old jti after we have a
    // replacement so a failure here doesn't leave the sandbox stranded.
    let minted = issuer.mint(&sandbox.sandbox_id)?;

    // Best-effort revocation of the old token. The plan calls for the
    // jti deny-list to live in memory in PR 2; PR 5 only needs to drop
    // the old jti into it. We use the new token's expiry as a safe upper
    // bound for the revocation entry — the old jti can't outlive its own
    // `exp`, and on TTL pruning the entry drops out cleanly.
    state
        .sandbox_jwt_revocation
        .revoke(old_jti, minted.expires_at_ms.max(now_ms()));
    info!(
        sandbox_id = %sandbox.sandbox_id,
        revoked_jti = %old_jti,
        new_jti = %minted.jti,
        "refreshed gateway sandbox JWT"
    );

    Ok(Response::new(RefreshSandboxTokenResponse {
        token: minted.token,
        expires_at_ms: minted.expires_at_ms,
    }))
}

fn now_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis()),
    )
    .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ServerState;
    use crate::auth::principal::{Principal, SandboxPrincipal, UserPrincipal};
    use crate::auth::revocation::RevocationSet;
    use crate::auth::sandbox_jwt::SandboxJwtIssuer;
    use crate::compute::new_test_runtime;
    use crate::persistence::Store;
    use crate::sandbox_index::SandboxIndex;
    use crate::sandbox_watch::SandboxWatchBus;
    use crate::supervisor_session::SupervisorSessionRegistry;
    use crate::tracing_bus::TracingLogBus;
    use openshell_bootstrap::jwt::generate_jwt_key;
    use openshell_core::Config;
    use std::time::Duration;

    async fn state_with_issuer() -> (Arc<ServerState>, SandboxJwtIssuer, Arc<RevocationSet>) {
        let mat = generate_jwt_key().expect("jwt key");
        let revocation = Arc::new(RevocationSet::new());
        let issuer = SandboxJwtIssuer::from_pem(
            mat.signing_key_pem.as_bytes(),
            mat.kid,
            "test-gateway",
            Duration::from_secs(3600),
        )
        .expect("issuer");
        let store = Arc::new(
            Store::connect("sqlite::memory:?cache=shared")
                .await
                .unwrap(),
        );
        let compute = new_test_runtime(store.clone()).await;
        let mut state = ServerState::new(
            Config::new(None).with_database_url("sqlite::memory:?cache=shared"),
            store,
            compute,
            SandboxIndex::new(),
            SandboxWatchBus::new(),
            TracingLogBus::new(),
            Arc::new(SupervisorSessionRegistry::new()),
            None,
        );
        state.sandbox_jwt_revocation = revocation.clone();
        // We don't need the authenticator for these tests; only the issuer.
        // The handler tests only exercise the mint+revoke path; they
        // don't need the issuer to be the same instance that produced
        // `issuer` above. A fresh keypair is fine.
        let issuer_clone = SandboxJwtIssuer::from_pem(
            generate_jwt_key().unwrap().signing_key_pem.as_bytes(),
            "kid".to_string(),
            "test-gateway",
            Duration::from_secs(3600),
        )
        .unwrap();
        state.sandbox_jwt_issuer = Some(Arc::new(issuer_clone));
        (Arc::new(state), issuer, revocation)
    }

    fn sandbox_principal(sandbox_id: &str, jti: &str) -> Principal {
        use crate::auth::principal::SandboxIdentitySource;
        Principal::Sandbox(SandboxPrincipal {
            sandbox_id: sandbox_id.to_string(),
            source: SandboxIdentitySource::BootstrapJwt {
                issuer: "openshell-gateway:test-gateway".to_string(),
                jti: jti.to_string(),
            },
            trust_domain: Some("openshell".to_string()),
        })
    }

    #[tokio::test]
    async fn refresh_revokes_old_jti_and_returns_new_token() {
        let (state, _issuer, revocation) = state_with_issuer().await;
        let old_jti = "j-original";
        let mut req = Request::new(RefreshSandboxTokenRequest {});
        req.extensions_mut()
            .insert(sandbox_principal("sandbox-a", old_jti));
        let resp = handle_refresh_sandbox_token(&state, req)
            .await
            .expect("refresh OK")
            .into_inner();
        assert!(!resp.token.is_empty());
        assert!(revocation.is_revoked(old_jti), "old jti must be revoked");
    }

    #[tokio::test]
    async fn refresh_rejects_user_principal() {
        use crate::auth::identity::{Identity, IdentityProvider};
        let (state, _, _) = state_with_issuer().await;
        let mut req = Request::new(RefreshSandboxTokenRequest {});
        req.extensions_mut().insert(Principal::User(UserPrincipal {
            identity: Identity {
                subject: "alice".to_string(),
                display_name: None,
                roles: vec![],
                scopes: vec![],
                provider: IdentityProvider::Oidc,
            },
        }));
        let err = handle_refresh_sandbox_token(&state, req)
            .await
            .expect_err("user must not refresh");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn refresh_rejects_k8s_sa_principal() {
        // K8s SA-bootstrap principals must use IssueSandboxToken, not
        // RefreshSandboxToken — the refresh path assumes a still-valid
        // gateway-minted JWT exists.
        use crate::auth::principal::SandboxIdentitySource;
        let (state, _, _) = state_with_issuer().await;
        let mut req = Request::new(RefreshSandboxTokenRequest {});
        req.extensions_mut()
            .insert(Principal::Sandbox(SandboxPrincipal {
                sandbox_id: "sandbox-a".to_string(),
                source: SandboxIdentitySource::K8sServiceAccount {
                    pod_name: "pod-a".to_string(),
                    pod_uid: "uid-a".to_string(),
                },
                trust_domain: Some("openshell".to_string()),
            }));
        let err = handle_refresh_sandbox_token(&state, req)
            .await
            .expect_err("K8s SA principal must not refresh");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn refresh_fails_when_issuer_not_configured() {
        // Build a ServerState without the issuer to confirm the handler
        // returns Unavailable.
        let store = Arc::new(
            Store::connect("sqlite::memory:?cache=shared")
                .await
                .unwrap(),
        );
        let compute = new_test_runtime(store.clone()).await;
        let state = Arc::new(ServerState::new(
            Config::new(None).with_database_url("sqlite::memory:?cache=shared"),
            store,
            compute,
            SandboxIndex::new(),
            SandboxWatchBus::new(),
            TracingLogBus::new(),
            Arc::new(SupervisorSessionRegistry::new()),
            None,
        ));
        let mut req = Request::new(RefreshSandboxTokenRequest {});
        req.extensions_mut()
            .insert(sandbox_principal("sandbox-a", "j-1"));
        let err = handle_refresh_sandbox_token(&state, req)
            .await
            .expect_err("missing issuer must yield unavailable");
        assert_eq!(err.code(), tonic::Code::Unavailable);
    }
}
