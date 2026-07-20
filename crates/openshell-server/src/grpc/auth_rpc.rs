// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Authentication-related RPC handlers.
//!
//! Hosts the sandbox-identity RPCs:
//! - `RegisterSupervisorPod` — Kubernetes pod registration and activation
//! - `IssueSandboxToken` — legacy bootstrap compatibility shim
//! - `RefreshSandboxToken` — renew a still-valid gateway JWT
//!
//! Both end in a fresh gateway-signed JWT minted by
//! [`crate::auth::sandbox_jwt::SandboxJwtIssuer`]. Older tokens remain valid
//! until their own `exp` and are bounded by the configured short TTL.

use crate::ServerState;
use crate::auth::principal::{
    Principal, RegisteredPodIdentity, SandboxIdentitySource, SandboxPrincipal,
};
use crate::warm_pod_activation::{load_sandbox, mint_pod_activation};
use openshell_core::proto::{
    IssueSandboxTokenRequest, IssueSandboxTokenResponse, PodActivationMessage,
    RefreshSandboxTokenRequest, RefreshSandboxTokenResponse, RegisterSupervisorPodRequest,
};
use std::sync::Arc;
use std::{pin::Pin, result::Result as StdResult};
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

pub type RegisterSupervisorPodStream =
    Pin<Box<dyn Stream<Item = StdResult<PodActivationMessage, Status>> + Send + 'static>>;

#[allow(clippy::result_large_err, clippy::unused_async)]
pub async fn handle_issue_sandbox_token(
    state: &Arc<ServerState>,
    request: Request<IssueSandboxTokenRequest>,
) -> Result<Response<IssueSandboxTokenResponse>, Status> {
    // Compatibility shim for older supervisor images. New Kubernetes
    // supervisors should use RegisterSupervisorPod so warm-pool activation can
    // later remain pending on the same bootstrap stream.
    let sandbox = require_k8s_bootstrap_sandbox(request.extensions(), "IssueSandboxToken")?;
    let activation = mint_pod_activation(state, &sandbox.sandbox_id, "IssueSandboxToken").await?;
    Ok(Response::new(IssueSandboxTokenResponse {
        token: activation.token,
        expires_at_ms: activation.token_expires_at_ms,
    }))
}

#[allow(clippy::result_large_err, clippy::unused_async)]
pub async fn handle_register_supervisor_pod(
    state: &Arc<ServerState>,
    request: Request<RegisterSupervisorPodRequest>,
) -> Result<Response<RegisterSupervisorPodStream>, Status> {
    let pod = require_registered_pod(request.extensions())?;
    if let Some(sandbox_id) = pod.sandbox_id.as_deref() {
        let activation = mint_pod_activation(state, sandbox_id, "RegisterSupervisorPod").await?;
        info!(
            sandbox_id = %activation.sandbox_id,
            pod = %pod.pod_name,
            pod_uid = %pod.pod_uid,
            "activated bound supervisor pod"
        );
        return Ok(Response::new(Box::pin(tokio_stream::once(Ok(activation)))));
    }

    let stream = state.supervisor_pod_registrations.register_pending(pod)?;
    Ok(Response::new(Box::pin(stream)))
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

    // Only callers already holding a gateway-minted JWT may refresh; the K8s
    // bootstrap path must use RegisterSupervisorPod.
    let SandboxIdentitySource::BootstrapJwt { .. } = &sandbox.source else {
        debug!(
            sandbox_id = %sandbox.sandbox_id,
            "RefreshSandboxToken rejected: non-gateway-JWT principal source"
        );
        return Err(Status::permission_denied(
            "this principal cannot refresh; use RegisterSupervisorPod for bootstrap",
        ));
    };

    let issuer = state.sandbox_jwt_issuer.as_ref().ok_or_else(|| {
        warn!(
            sandbox_id = %sandbox.sandbox_id,
            "RefreshSandboxToken called but sandbox JWT issuer is not configured"
        );
        Status::unavailable("sandbox JWT minting is not configured on this gateway")
    })?;

    load_sandbox(state, &sandbox.sandbox_id).await?;

    let minted = issuer.mint(&sandbox.sandbox_id)?;
    info!(
        sandbox_id = %sandbox.sandbox_id,
        "renewed gateway sandbox JWT"
    );

    Ok(Response::new(RefreshSandboxTokenResponse {
        token: minted.token,
        expires_at_ms: minted.expires_at_ms,
    }))
}

fn require_k8s_bootstrap_sandbox(
    extensions: &tonic::Extensions,
    rpc_name: &'static str,
) -> Result<SandboxPrincipal, Status> {
    let principal = extensions
        .get::<Principal>()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("missing principal"))?;

    let Principal::Sandbox(sandbox) = principal else {
        return Err(Status::permission_denied(format!(
            "{rpc_name} requires a sandbox principal"
        )));
    };

    if !matches!(
        sandbox.source,
        SandboxIdentitySource::K8sServiceAccount { .. }
    ) {
        debug!(
            sandbox_id = %sandbox.sandbox_id,
            rpc = rpc_name,
            "bootstrap RPC rejected: non-K8s ServiceAccount principal source"
        );
        return Err(Status::permission_denied(
            "this principal cannot mint a sandbox token; use RefreshSandboxToken",
        ));
    }

    Ok(sandbox)
}

fn require_registered_pod(extensions: &tonic::Extensions) -> Result<RegisteredPodIdentity, Status> {
    if let Some(pod) = extensions.get::<RegisteredPodIdentity>().cloned() {
        return Ok(pod);
    }

    let principal = extensions
        .get::<Principal>()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("missing principal"))?;

    let Principal::K8sPod(pod) = principal else {
        return Err(Status::permission_denied(
            "RegisterSupervisorPod requires a Kubernetes pod registration principal",
        ));
    };

    Ok(pod)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ServerState;
    use crate::auth::principal::{Principal, SandboxPrincipal, UserPrincipal};
    use crate::auth::sandbox_jwt::SandboxJwtIssuer;
    use crate::compute::new_test_runtime;
    use crate::persistence::Store;
    use crate::sandbox_index::SandboxIndex;
    use crate::sandbox_watch::SandboxWatchBus;
    use crate::supervisor_session::SupervisorSessionRegistry;
    use crate::tracing_bus::TracingLogBus;
    use openshell_bootstrap::jwt::generate_jwt_key;
    use openshell_core::Config;
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use openshell_core::proto::{Sandbox, SandboxPhase, SandboxSpec};
    use std::collections::HashMap;
    use std::time::Duration;
    use tokio_stream::StreamExt;

    async fn state_with_issuer() -> Arc<ServerState> {
        let mat = generate_jwt_key().expect("jwt key");
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
        // We don't need the authenticator for these tests; only the issuer.
        let issuer = SandboxJwtIssuer::from_pem(
            mat.signing_key_pem.as_bytes(),
            mat.kid,
            "test-gateway",
            Duration::from_secs(3600),
        )
        .unwrap();
        state.sandbox_jwt_issuer = Some(Arc::new(issuer));
        let state = Arc::new(state);
        insert_sandbox(&state, "sandbox-a").await;
        state
    }

    async fn insert_sandbox(state: &Arc<ServerState>, sandbox_id: &str) {
        let mut sandbox = Sandbox {
            metadata: Some(ObjectMeta {
                id: sandbox_id.to_string(),
                name: sandbox_id.to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::default(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            spec: Some(SandboxSpec {
                policy: None,
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();
    }

    fn sandbox_principal(sandbox_id: &str) -> Principal {
        use crate::auth::principal::SandboxIdentitySource;
        Principal::Sandbox(SandboxPrincipal {
            sandbox_id: sandbox_id.to_string(),
            source: SandboxIdentitySource::BootstrapJwt {
                issuer: "openshell-gateway:test-gateway".to_string(),
            },
            trust_domain: Some("openshell".to_string()),
        })
    }

    fn registered_pod(sandbox_id: Option<&str>) -> RegisteredPodIdentity {
        RegisteredPodIdentity {
            pod_name: "pod-a".to_string(),
            pod_uid: "uid-a".to_string(),
            sandbox_id: sandbox_id.map(str::to_string),
            sandbox_owner_name: "sandbox-owner-a".to_string(),
            sandbox_owner_uid: "owner-uid-a".to_string(),
        }
    }

    #[tokio::test]
    async fn refresh_returns_new_token() {
        let state = state_with_issuer().await;
        let mut req = Request::new(RefreshSandboxTokenRequest {});
        req.extensions_mut().insert(sandbox_principal("sandbox-a"));
        let resp = handle_refresh_sandbox_token(&state, req)
            .await
            .expect("refresh OK")
            .into_inner();
        assert!(!resp.token.is_empty());
        assert!(resp.expires_at_ms > 0);
    }

    #[tokio::test]
    async fn refresh_rejects_missing_sandbox() {
        let state = state_with_issuer().await;
        let mut req = Request::new(RefreshSandboxTokenRequest {});
        req.extensions_mut()
            .insert(sandbox_principal("sandbox-deleted"));
        let err = handle_refresh_sandbox_token(&state, req)
            .await
            .expect_err("missing sandbox must not refresh");
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn issue_returns_token_for_existing_sandbox() {
        use crate::auth::principal::SandboxIdentitySource;

        let state = state_with_issuer().await;
        let mut req = Request::new(IssueSandboxTokenRequest {});
        req.extensions_mut()
            .insert(Principal::Sandbox(SandboxPrincipal {
                sandbox_id: "sandbox-a".to_string(),
                source: SandboxIdentitySource::K8sServiceAccount {
                    pod_name: "pod-a".to_string(),
                    pod_uid: "uid-a".to_string(),
                },
                trust_domain: Some("openshell".to_string()),
            }));
        let resp = handle_issue_sandbox_token(&state, req)
            .await
            .expect("issue OK")
            .into_inner();
        assert!(!resp.token.is_empty());
        assert!(resp.expires_at_ms > 0);
    }

    #[tokio::test]
    async fn register_supervisor_pod_returns_immediate_activation_for_existing_sandbox() {
        let state = state_with_issuer().await;
        let mut req = Request::new(RegisterSupervisorPodRequest {});
        req.extensions_mut()
            .insert(Principal::K8sPod(registered_pod(Some("sandbox-a"))));

        let mut stream = handle_register_supervisor_pod(&state, req)
            .await
            .expect("register OK")
            .into_inner();
        let activation = stream
            .next()
            .await
            .expect("activation message")
            .expect("activation OK");
        assert_eq!(activation.sandbox_id, "sandbox-a");
        assert_eq!(activation.sandbox_name, "sandbox-a");
        assert!(!activation.token.is_empty());
        assert!(activation.token_expires_at_ms > 0);
        assert!(activation.startup_metadata.is_empty());
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn register_supervisor_pod_keeps_unbound_warm_pod_pending() {
        let state = state_with_issuer().await;
        let mut req = Request::new(RegisterSupervisorPodRequest {});
        req.extensions_mut()
            .insert(Principal::K8sPod(registered_pod(None)));

        let mut stream = handle_register_supervisor_pod(&state, req)
            .await
            .expect("register OK")
            .into_inner();
        assert_eq!(state.supervisor_pod_registrations.pending_count(), 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), stream.next())
                .await
                .is_err(),
            "unbound warm pod must wait for later activation"
        );
        drop(stream);
        assert_eq!(state.supervisor_pod_registrations.pending_count(), 0);
    }

    #[tokio::test]
    async fn issue_rejects_missing_sandbox() {
        use crate::auth::principal::SandboxIdentitySource;

        let state = state_with_issuer().await;
        let mut req = Request::new(IssueSandboxTokenRequest {});
        req.extensions_mut()
            .insert(Principal::Sandbox(SandboxPrincipal {
                sandbox_id: "sandbox-deleted".to_string(),
                source: SandboxIdentitySource::K8sServiceAccount {
                    pod_name: "pod-a".to_string(),
                    pod_uid: "uid-a".to_string(),
                },
                trust_domain: Some("openshell".to_string()),
            }));
        let err = handle_issue_sandbox_token(&state, req)
            .await
            .expect_err("missing sandbox must not receive a token");
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn refresh_rejects_user_principal() {
        use crate::auth::identity::{Identity, IdentityProvider};
        let state = state_with_issuer().await;
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
        // K8s SA-bootstrap principals must use RegisterSupervisorPod, not
        // RefreshSandboxToken. The refresh path assumes a still-valid
        // gateway-minted JWT already exists.
        use crate::auth::principal::SandboxIdentitySource;
        let state = state_with_issuer().await;
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
        insert_sandbox(&state, "sandbox-a").await;
        let mut req = Request::new(RefreshSandboxTokenRequest {});
        req.extensions_mut().insert(sandbox_principal("sandbox-a"));
        let err = handle_refresh_sandbox_token(&state, req)
            .await
            .expect_err("missing issuer must yield unavailable");
        assert_eq!(err.code(), tonic::Code::Unavailable);
    }
}
