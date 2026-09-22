// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Authentication-related RPC handlers.
//!
//! Hosts authenticated identity RPCs:
//! - `GetCurrentUser` — report the gateway-validated caller identity
//! - `IssueSandboxToken` — driver-native bootstrap exchange → gateway JWT
//! - `RefreshSandboxToken` — renew a still-valid gateway JWT
//!
//! Both end in a fresh gateway-signed JWT minted by
//! [`crate::auth::sandbox_jwt::SandboxJwtIssuer`]. Refresh atomically advances
//! the sandbox's credential lineage. The immediately consumed bearer may only
//! replay the same refresh for a short recovery window; it cannot authorize
//! ordinary RPCs or select another successor.

use crate::ServerState;
use crate::auth::identity::IdentityProvider;
use crate::auth::principal::{Principal, SandboxIdentitySource};
use openshell_core::proto::{
    ExtensionServiceCredential, GetCurrentUserRequest, GetCurrentUserResponse,
    GetSandboxConfigRequest, IssueSandboxTokenRequest, IssueSandboxTokenResponse,
    RefreshSandboxTokenRequest, RefreshSandboxTokenResponse, Sandbox,
};
use openshell_extension_core::{ExtensionAudience, ExtensionCallerKind, MAX_EXTENSION_TOKEN_TTL};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

#[allow(clippy::result_large_err, clippy::unused_async)]
pub async fn handle_get_current_user(
    request: Request<GetCurrentUserRequest>,
) -> Result<Response<GetCurrentUserResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let Principal::User(user) = principal else {
        return Err(Status::permission_denied(
            "GetCurrentUser requires a user principal",
        ));
    };

    let identity = user.identity;
    Ok(Response::new(GetCurrentUserResponse {
        subject: identity.subject,
        display_name: identity.display_name.unwrap_or_default(),
        roles: identity.roles,
        scopes: identity.scopes,
        identity_provider: match identity.provider {
            IdentityProvider::Oidc => "oidc",
            IdentityProvider::Mtls => "mtls",
            IdentityProvider::CloudflareAccess => "cloudflare_access",
            IdentityProvider::LocalDev => "local_dev",
        }
        .to_string(),
    }))
}

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

    // Only a selected compute driver may establish the bootstrap sandbox
    // identity. Sandboxes already holding a gateway JWT use refresh instead.
    let SandboxIdentitySource::ComputeDriver {
        driver_name,
        runtime_identity,
    } = &sandbox.source
    else {
        debug!(
            sandbox_id = %sandbox.sandbox_id,
            "IssueSandboxToken rejected: non-bootstrap principal source"
        );
        return Err(Status::permission_denied(
            "this principal cannot mint a sandbox token; use RefreshSandboxToken",
        ));
    };

    let session_authority = state
        .sandbox_session_jwt_authority
        .as_ref()
        .ok_or_else(|| {
            warn!(
                sandbox_id = %sandbox.sandbox_id,
                "IssueSandboxToken called but sandbox session minting is not configured"
            );
            Status::unavailable("sandbox session minting is not configured on this gateway")
        })?;

    let sandbox_record = ensure_sandbox_exists(state, &sandbox.sandbox_id).await?;
    let metadata = sandbox_record
        .metadata
        .as_ref()
        .ok_or_else(|| Status::permission_denied("sandbox runtime identity is unavailable"))?;
    let expected_driver = metadata
        .annotations
        .get(crate::compute::COMPUTE_DRIVER_ANNOTATION);
    let expected_runtime_identity = metadata
        .annotations
        .get(crate::compute::COMPUTE_RUNTIME_IDENTITY_ANNOTATION);
    if expected_driver != Some(driver_name) || expected_runtime_identity != Some(runtime_identity) {
        warn!(
            sandbox_id = %sandbox.sandbox_id,
            driver_name,
            "IssueSandboxToken rejected: compute runtime identity mismatch"
        );
        return Err(Status::permission_denied(
            "compute runtime identity does not match the sandbox",
        ));
    }

    let identity =
        crate::auth::sandbox_session::PersistedSandboxIdentity::read(&metadata.annotations)
            .map_err(|_| Status::permission_denied("sandbox runtime identity is invalid"))?;
    let authentication = session_authority.mint_persisted_launch(&sandbox.sandbox_id, &identity)?;
    let token = authentication
        .supervisor
        .gateway_token
        .expose_secret()
        .to_string();
    info!(
        sandbox_id = %sandbox.sandbox_id,
        "issued generation-bound gateway sandbox JWT"
    );
    Ok(Response::new(IssueSandboxTokenResponse {
        token,
        expiration_time: openshell_core::time::optional_timestamp_from_legacy_millis(
            authentication
                .supervisor
                .gateway_expires_at
                .saturating_mul(1000),
        )
        .map_err(|error| Status::internal(error.to_string()))?,
    }))
}

#[allow(clippy::result_large_err, clippy::unused_async)]
pub async fn handle_refresh_sandbox_token(
    state: &Arc<ServerState>,
    request: Request<RefreshSandboxTokenRequest>,
) -> Result<Response<RefreshSandboxTokenResponse>, Status> {
    let requested_extension_services = request.get_ref().extension_service_names.clone();
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
    let SandboxIdentitySource::BootstrapJwt { .. } = &sandbox.source else {
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
    let session_authority = state
        .sandbox_session_jwt_authority
        .as_ref()
        .ok_or_else(|| Status::unavailable("sandbox session minting is not configured"))?;

    let authorization_values = request.metadata().get_all("authorization");
    let mut authorization_values = authorization_values.iter();
    let authorization = authorization_values
        .next()
        .ok_or_else(|| Status::unauthenticated("missing authorization metadata"))?;
    if authorization_values.next().is_some() {
        return Err(Status::unauthenticated("duplicate authorization metadata"));
    }
    let gateway_token = authorization
        .to_str()
        .ok()
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| Status::unauthenticated("invalid bearer authorization metadata"))?;
    let principal = session_authority.verify_gateway_token(gateway_token)?;
    if principal.sandbox_id.as_str() != sandbox.sandbox_id {
        return Err(Status::unauthenticated(
            "gateway token does not match the authenticated sandbox",
        ));
    }
    let request_hash = crate::auth::sandbox_session::RefreshRequestHash::from_extension_services(
        &requested_extension_services,
    );
    let issued_at = current_unix_seconds();
    let authorization = crate::auth::sandbox_session::authorize_refresh(
        &state.store,
        &principal,
        &request_hash,
        issued_at,
    )
    .await?;
    let (successor, should_rotate) = match authorization {
        crate::auth::sandbox_session::RefreshAuthorization::Current(identity) => (
            identity.next_gateway_token(
                request_hash,
                issued_at,
                REFRESH_REPLAY_GRACE
                    .as_secs()
                    .try_into()
                    .unwrap_or(i64::MAX),
            ),
            true,
        ),
        crate::auth::sandbox_session::RefreshAuthorization::Replay(identity) => (identity, false),
    };
    let authentication =
        session_authority.mint_persisted_launch(&sandbox.sandbox_id, &successor)?;
    let sandbox_record = ensure_sandbox_exists(state, &sandbox.sandbox_id).await?;
    let extension_credentials = if requested_extension_services.is_empty() {
        Vec::new()
    } else if !state
        .extension_mint_limiter
        .try_acquire(&sandbox.sandbox_id)
    {
        // Minting resolves the sandbox's effective policy, so an unbounded
        // caller could impose real gateway cost from inside a sandbox. The
        // supervisor keeps its last-known-good slots on error and retries at
        // its normal cadence, so refusing is safe.
        warn!(
            sandbox_id = %sandbox.sandbox_id,
            "extension credential minting rate limit exceeded"
        );
        return Err(Status::resource_exhausted(
            "extension credential minting rate limit exceeded for this sandbox",
        ));
    } else {
        let mut config_request = Request::new(GetSandboxConfigRequest {
            name: sandbox_record
                .metadata
                .as_ref()
                .map_or_else(String::new, |metadata| metadata.name.clone()),
            workspace_scope: None,
        });
        config_request
            .extensions_mut()
            .insert(Principal::Sandbox(sandbox.clone()));
        let available = super::policy::handle_get_sandbox_config(state, config_request)
            .await?
            .into_inner()
            .supervisor_middleware_services;
        mint_extension_credentials(
            issuer,
            &sandbox.sandbox_id,
            &requested_extension_services,
            &available,
            successor.refresh_replay.as_ref(),
        )?
    };
    if should_rotate {
        crate::auth::sandbox_session::rotate_gateway_token(&state.store, &principal, &successor)
            .await?;
    }
    info!(
        sandbox_id = %sandbox.sandbox_id,
        "renewed gateway sandbox JWT"
    );

    Ok(Response::new(RefreshSandboxTokenResponse {
        token: authentication
            .supervisor
            .gateway_token
            .expose_secret()
            .to_string(),
        expiration_time: openshell_core::time::optional_timestamp_from_legacy_millis(
            authentication
                .supervisor
                .gateway_expires_at
                .saturating_mul(1000),
        )
        .map_err(|error| Status::internal(error.to_string()))?,
        extension_credentials,
        sandbox_token: authentication
            .supervisor
            .sandbox_token
            .expose_secret()
            .to_string(),
        sandbox_expiration_time: Some(
            openshell_core::time::timestamp_from_millis(
                authentication
                    .supervisor
                    .sandbox_expires_at
                    .saturating_mul(1000),
            )
            .map_err(|error| Status::internal(error.to_string()))?,
        ),
        session_id: authentication.supervisor.runtime_generation.to_string(),
        credential_epoch: authentication.supervisor.auth_epoch.get(),
    }))
}

const MAX_EXTENSION_CREDENTIALS_PER_REFRESH: usize = 64;
const DEFAULT_EXTENSION_TOKEN_TTL: Duration = Duration::from_mins(15);
const REFRESH_REPLAY_GRACE: Duration = Duration::from_secs(30);

fn current_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
        })
}

#[allow(clippy::result_large_err)]
fn mint_extension_credentials(
    issuer: &crate::auth::sandbox_jwt::SandboxJwtIssuer,
    sandbox_id: &str,
    requested_names: &[String],
    available_services: &[openshell_core::proto::SupervisorMiddlewareService],
    refresh_replay: Option<&crate::auth::sandbox_session::GatewayRefreshReplay>,
) -> Result<Vec<ExtensionServiceCredential>, Status> {
    if requested_names.len() > MAX_EXTENSION_CREDENTIALS_PER_REFRESH {
        return Err(Status::invalid_argument(format!(
            "at most {MAX_EXTENSION_CREDENTIALS_PER_REFRESH} extension credentials may be requested"
        )));
    }
    let mut unique = HashSet::with_capacity(requested_names.len());
    for name in requested_names {
        if name.is_empty() {
            return Err(Status::invalid_argument(
                "extension service names must not be empty",
            ));
        }
        if !unique.insert(name.as_str()) {
            return Err(Status::invalid_argument(format!(
                "duplicate extension service name '{name}'"
            )));
        }
    }

    let available: HashMap<&str, &openshell_core::proto::SupervisorMiddlewareService> =
        available_services
            .iter()
            .map(|service| (service.name.as_str(), service))
            .collect();
    let ttl = issuer
        .sandbox_token_ttl()
        .map_or(DEFAULT_EXTENSION_TOKEN_TTL, |ttl| {
            ttl.min(MAX_EXTENSION_TOKEN_TTL)
        });

    requested_names
        .iter()
        .map(|name| {
            let service = available.get(name.as_str()).ok_or_else(|| {
                Status::permission_denied(format!(
                    "extension service '{name}' is not selected by the sandbox policy"
                ))
            })?;
            if service.allow_insecure_transport {
                return Err(Status::failed_precondition(format!(
                    "extension service '{name}' opted out of extension authentication; \
                     no credential is minted for it"
                )));
            }
            let audience = ExtensionAudience::new(service.audience.clone())
                .map_err(|error| Status::failed_precondition(error.to_string()))?;
            let minted = refresh_replay.map_or_else(
                || {
                    issuer.mint_extension_token(
                        &audience,
                        ExtensionCallerKind::Supervisor,
                        Some(sandbox_id),
                        ttl,
                    )
                },
                |replay| {
                    issuer.mint_extension_token_with_metadata(
                        &audience,
                        ExtensionCallerKind::Supervisor,
                        Some(sandbox_id),
                        ttl,
                        replay.issued_at,
                        replay.extension_token_id(name, audience.as_str()),
                    )
                },
            )?;
            Ok(ExtensionServiceCredential {
                service_name: name.clone(),
                token: minted.token,
                expiration_time: openshell_core::time::optional_timestamp_from_legacy_millis(
                    minted.expires_at_ms,
                )
                .map_err(|error| Status::internal(error.to_string()))?,
            })
        })
        .collect()
}

async fn ensure_sandbox_exists(
    state: &Arc<ServerState>,
    sandbox_id: &str,
) -> Result<Sandbox, Status> {
    if sandbox_id.is_empty() {
        return Err(Status::invalid_argument("sandbox_id is required"));
    }

    state
        .store
        .get_message::<Sandbox>(sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ServerState;
    use crate::auth::identity::Identity;
    use crate::auth::principal::{Principal, SandboxPrincipal, UserPrincipal};
    use crate::auth::sandbox_jwt::{SandboxJwtIssuer, SandboxSessionJwtAuthority};
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

    async fn state_with_issuer() -> Arc<ServerState> {
        let mat = generate_jwt_key().expect("jwt key");
        let store = Arc::new(
            Store::connect("sqlite::memory:?cache=shared")
                .await
                .unwrap(),
        );
        let compute = new_test_runtime(store.clone()).await;
        let mut state = ServerState::new(
            Config::new(None)
                .with_database_url("sqlite::memory:?cache=shared")
                .with_credential_drivers(["test-static"]),
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
            mat.kid.clone(),
            "test-gateway",
            Some(Duration::from_hours(1)),
        )
        .unwrap();
        state.sandbox_jwt_issuer = Some(Arc::new(issuer));
        let authority = Arc::new(
            SandboxSessionJwtAuthority::from_pem(
                mat.signing_key_pem.as_bytes(),
                mat.public_key_pem.as_bytes(),
                mat.kid,
                "test-gateway",
                Duration::from_hours(1),
            )
            .expect("session authority"),
        );
        let identity = crate::auth::sandbox_session::PersistedSandboxIdentity::new()
            .expect("runtime identity");
        state.sandbox_session_jwt_authority = Some(authority);
        let state = Arc::new(state);
        insert_sandbox(&state, "sandbox-a", &identity).await;
        state
    }

    async fn insert_sandbox(
        state: &Arc<ServerState>,
        sandbox_id: &str,
        identity: &crate::auth::sandbox_session::PersistedSandboxIdentity,
    ) {
        let mut sandbox = Sandbox {
            metadata: Some(ObjectMeta {
                id: sandbox_id.to_string(),
                name: sandbox_id.to_string(),
                created_time: openshell_core::time::timestamp_from_millis(1_000_000).ok(),
                labels: HashMap::default(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_time: None,
            }),
            spec: Some(SandboxSpec {
                policy: None,
                ..Default::default()
            }),
            ..Default::default()
        };
        identity.write(&mut sandbox.metadata.as_mut().expect("metadata").annotations);
        let annotations = &mut sandbox.metadata.as_mut().expect("metadata").annotations;
        annotations.insert(
            crate::compute::COMPUTE_DRIVER_ANNOTATION.to_string(),
            "kubernetes".to_string(),
        );
        annotations.insert(
            crate::compute::COMPUTE_RUNTIME_IDENTITY_ANNOTATION.to_string(),
            "test-runtime".to_string(),
        );
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

    async fn authorize_refresh(
        state: &ServerState,
        request: &mut Request<RefreshSandboxTokenRequest>,
    ) -> String {
        let sandbox = state
            .store
            .get_message::<Sandbox>("sandbox-a")
            .await
            .expect("load sandbox")
            .expect("sandbox");
        let identity = crate::auth::sandbox_session::PersistedSandboxIdentity::read(
            &sandbox.metadata.expect("metadata").annotations,
        )
        .expect("persisted identity");
        let authentication = state
            .sandbox_session_jwt_authority
            .as_ref()
            .expect("session authority")
            .mint_persisted_launch("sandbox-a", &identity)
            .expect("active authentication");
        let token = authentication
            .supervisor
            .gateway_token
            .expose_secret()
            .to_string();
        set_refresh_authorization(request, &token);
        token
    }

    fn set_refresh_authorization(request: &mut Request<RefreshSandboxTokenRequest>, token: &str) {
        let value = format!("Bearer {token}")
            .parse()
            .expect("authorization metadata");
        request.metadata_mut().insert("authorization", value);
    }

    #[tokio::test]
    async fn current_user_returns_gateway_validated_identity() {
        let mut req = Request::new(GetCurrentUserRequest {});
        req.extensions_mut().insert(Principal::User(UserPrincipal {
            identity: Identity {
                subject: "oidc-subject-123".to_string(),
                display_name: Some("Alice".to_string()),
                roles: vec!["openshell-user".to_string()],
                scopes: vec!["sandbox:read".to_string()],
                provider: IdentityProvider::Oidc,
            },
        }));

        let response = handle_get_current_user(req)
            .await
            .expect("current user")
            .into_inner();
        assert_eq!(response.subject, "oidc-subject-123");
        assert_eq!(response.display_name, "Alice");
        assert_eq!(response.roles, ["openshell-user"]);
        assert_eq!(response.scopes, ["sandbox:read"]);
        assert_eq!(response.identity_provider, "oidc");
    }

    #[tokio::test]
    async fn refresh_returns_new_token() {
        let state = state_with_issuer().await;
        let mut req = Request::new(RefreshSandboxTokenRequest {
            extension_service_names: Vec::new(),
        });
        req.extensions_mut().insert(sandbox_principal("sandbox-a"));
        let _ = authorize_refresh(&state, &mut req).await;
        let resp = handle_refresh_sandbox_token(&state, req)
            .await
            .expect("refresh OK")
            .into_inner();
        assert!(!resp.token.is_empty());
        assert!(resp.expiration_time.is_some());
        assert!(resp.sandbox_expiration_time.is_some());
    }

    #[tokio::test]
    async fn refresh_replays_one_successor_then_rejects_older_bearers() {
        let state = state_with_issuer().await;
        let request = || {
            let mut request = Request::new(RefreshSandboxTokenRequest {
                extension_service_names: Vec::new(),
            });
            request
                .extensions_mut()
                .insert(sandbox_principal("sandbox-a"));
            request
        };

        let mut first_request = request();
        let first = authorize_refresh(&state, &mut first_request).await;
        let second = handle_refresh_sandbox_token(&state, first_request)
            .await
            .expect("first refresh")
            .into_inner();

        let mut lost_response_retry = request();
        set_refresh_authorization(&mut lost_response_retry, &first);
        let replayed = handle_refresh_sandbox_token(&state, lost_response_retry)
            .await
            .expect("lost response retry")
            .into_inner();
        assert_eq!(replayed.token, second.token);
        assert_eq!(replayed.sandbox_token, second.sandbox_token);
        assert_eq!(replayed.expiration_time, second.expiration_time);
        assert_eq!(
            replayed.sandbox_expiration_time,
            second.sandbox_expiration_time
        );

        let mut changed_retry = request();
        changed_retry.get_mut().extension_service_names = vec!["content-guard".to_string()];
        set_refresh_authorization(&mut changed_retry, &first);
        let error = handle_refresh_sandbox_token(&state, changed_retry)
            .await
            .expect_err("retry request shape must match the committed refresh");
        assert_eq!(error.code(), tonic::Code::Unauthenticated);

        let mut second_request = request();
        set_refresh_authorization(&mut second_request, &second.token);
        handle_refresh_sandbox_token(&state, second_request)
            .await
            .expect("successor refresh");

        let mut replay = request();
        set_refresh_authorization(&mut replay, &first);
        let error = handle_refresh_sandbox_token(&state, replay)
            .await
            .expect_err("consumed predecessor must not mint fresh credentials");
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn failed_refresh_does_not_consume_the_gateway_bearer() {
        let state = state_with_issuer().await;
        let mut rejected = Request::new(RefreshSandboxTokenRequest {
            extension_service_names: vec!["unknown-service".to_string()],
        });
        rejected
            .extensions_mut()
            .insert(sandbox_principal("sandbox-a"));
        let current = authorize_refresh(&state, &mut rejected).await;

        let error = handle_refresh_sandbox_token(&state, rejected)
            .await
            .expect_err("unknown extension service must be rejected");
        assert_eq!(error.code(), tonic::Code::PermissionDenied);

        let mut retry = Request::new(RefreshSandboxTokenRequest {
            extension_service_names: Vec::new(),
        });
        retry
            .extensions_mut()
            .insert(sandbox_principal("sandbox-a"));
        set_refresh_authorization(&mut retry, &current);
        handle_refresh_sandbox_token(&state, retry)
            .await
            .expect("failed refresh must leave its bearer current");
    }

    #[tokio::test]
    async fn extension_credentials_are_minted_only_for_selected_registration_names() {
        let state = state_with_issuer().await;
        let issuer = state.sandbox_jwt_issuer.as_deref().expect("issuer");
        let available = vec![openshell_core::proto::SupervisorMiddlewareService {
            name: "content-guard".to_string(),
            audience: "urn:example:content-guard".to_string(),
            ..Default::default()
        }];

        let credentials = mint_extension_credentials(
            issuer,
            "sandbox-a",
            &["content-guard".to_string()],
            &available,
            None,
        )
        .expect("selected service credential");
        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0].service_name, "content-guard");
        assert!(!credentials[0].token.is_empty());
        assert!(credentials[0].expiration_time.is_some());

        let error = mint_extension_credentials(
            issuer,
            "sandbox-a",
            &["attacker-chosen-audience".to_string()],
            &available,
            None,
        )
        .expect_err("unselected name must be rejected");
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn refresh_refuses_extension_credentials_past_the_per_sandbox_bound() {
        let state = state_with_issuer().await;
        // The gateway credential path is unaffected; only requests that carry
        // extension service names consume the bound.
        for _ in 0..10 {
            assert!(state.extension_mint_limiter.try_acquire("sandbox-a"));
        }
        assert!(!state.extension_mint_limiter.try_acquire("sandbox-a"));
        assert!(state.extension_mint_limiter.try_acquire("sandbox-b"));
    }

    #[tokio::test]
    async fn opted_out_registrations_never_receive_a_minted_credential() {
        let state = state_with_issuer().await;
        let issuer = state.sandbox_jwt_issuer.as_deref().expect("issuer");
        let available = vec![openshell_core::proto::SupervisorMiddlewareService {
            name: "legacy-guard".to_string(),
            audience: "urn:example:legacy-guard".to_string(),
            allow_insecure_transport: true,
            ..Default::default()
        }];

        // The registration is policy-selected, so authorization passes; the
        // opt-out is what withholds the credential. A supervisor must not be
        // able to obtain a bearer token it would then send over plaintext.
        let error = mint_extension_credentials(
            issuer,
            "sandbox-a",
            &["legacy-guard".to_string()],
            &available,
            None,
        )
        .expect_err("opted-out registration must not mint a credential");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn extension_credential_request_rejects_duplicate_names_atomically() {
        let state = state_with_issuer().await;
        let issuer = state.sandbox_jwt_issuer.as_deref().expect("issuer");
        let available = vec![openshell_core::proto::SupervisorMiddlewareService {
            name: "content-guard".to_string(),
            audience: "urn:example:content-guard".to_string(),
            ..Default::default()
        }];
        let error = mint_extension_credentials(
            issuer,
            "sandbox-a",
            &["content-guard".to_string(), "content-guard".to_string()],
            &available,
            None,
        )
        .expect_err("duplicates must be rejected");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn refresh_rejects_missing_sandbox() {
        let state = state_with_issuer().await;
        let mut req = Request::new(RefreshSandboxTokenRequest {
            extension_service_names: Vec::new(),
        });
        req.extensions_mut()
            .insert(sandbox_principal("sandbox-deleted"));
        let err = handle_refresh_sandbox_token(&state, req)
            .await
            .expect_err("missing sandbox must not refresh");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn issue_returns_generation_bound_token_and_rejects_it_after_runtime_replacement() {
        use crate::auth::authenticator::Authenticator;
        use crate::auth::principal::SandboxIdentitySource;
        use crate::auth::sandbox_jwt::SandboxSessionJwtAuthenticator;

        let state = state_with_issuer().await;
        let mut req = Request::new(IssueSandboxTokenRequest {});
        req.extensions_mut()
            .insert(Principal::Sandbox(SandboxPrincipal {
                sandbox_id: "sandbox-a".to_string(),
                source: SandboxIdentitySource::ComputeDriver {
                    driver_name: "kubernetes".to_string(),
                    runtime_identity: "test-runtime".to_string(),
                },
                trust_domain: Some("openshell".to_string()),
            }));
        let resp = handle_issue_sandbox_token(&state, req)
            .await
            .expect("issue OK")
            .into_inner();
        assert!(!resp.token.is_empty());
        assert!(resp.expiration_time.is_some());

        let authenticator = SandboxSessionJwtAuthenticator::new(
            state
                .sandbox_session_jwt_authority
                .clone()
                .expect("session authority"),
            state.store.clone(),
        );
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Bearer {}", resp.token)
                .parse()
                .expect("bearer header"),
        );
        let provider_path = "/openshell.v1.OpenShell/GetSandboxProviderEnvironment";
        let principal = authenticator
            .authenticate(&headers, provider_path)
            .await
            .expect("active runtime token must authenticate")
            .expect("session authenticator must recognize its token");
        assert!(matches!(principal, Principal::Sandbox(_)));

        let replacement = crate::auth::sandbox_session::PersistedSandboxIdentity::new()
            .expect("replacement identity");
        state
            .store
            .update_message_cas::<Sandbox, _>("sandbox-a", 0, move |sandbox| {
                replacement.write(&mut sandbox.metadata.as_mut().expect("metadata").annotations);
            })
            .await
            .expect("replace runtime identity");
        let error = authenticator
            .authenticate(&headers, provider_path)
            .await
            .expect_err("obsolete runtime token must not reach provider access");
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn issue_rejects_mismatched_compute_runtime_identity() {
        use crate::auth::principal::SandboxIdentitySource;

        let state = state_with_issuer().await;
        let mut req = Request::new(IssueSandboxTokenRequest {});
        req.extensions_mut()
            .insert(Principal::Sandbox(SandboxPrincipal {
                sandbox_id: "sandbox-a".to_string(),
                source: SandboxIdentitySource::ComputeDriver {
                    driver_name: "kubernetes".to_string(),
                    runtime_identity: "replacement-runtime".to_string(),
                },
                trust_domain: Some("openshell".to_string()),
            }));

        let err = handle_issue_sandbox_token(&state, req)
            .await
            .expect_err("mismatched runtime must not receive a token");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn issue_rejects_missing_sandbox() {
        use crate::auth::principal::SandboxIdentitySource;

        let state = state_with_issuer().await;
        let mut req = Request::new(IssueSandboxTokenRequest {});
        req.extensions_mut()
            .insert(Principal::Sandbox(SandboxPrincipal {
                sandbox_id: "sandbox-deleted".to_string(),
                source: SandboxIdentitySource::ComputeDriver {
                    driver_name: "kubernetes".to_string(),
                    runtime_identity: "test-runtime".to_string(),
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
        let mut req = Request::new(RefreshSandboxTokenRequest {
            extension_service_names: Vec::new(),
        });
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
    async fn refresh_rejects_compute_driver_principal() {
        // Driver-bootstrap principals must use IssueSandboxToken, not
        // RefreshSandboxToken — the refresh path assumes a still-valid
        // gateway-minted JWT exists.
        use crate::auth::principal::SandboxIdentitySource;
        let state = state_with_issuer().await;
        let mut req = Request::new(RefreshSandboxTokenRequest {
            extension_service_names: Vec::new(),
        });
        req.extensions_mut()
            .insert(Principal::Sandbox(SandboxPrincipal {
                sandbox_id: "sandbox-a".to_string(),
                source: SandboxIdentitySource::ComputeDriver {
                    driver_name: "kubernetes".to_string(),
                    runtime_identity: "test-runtime".to_string(),
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
            Config::new(None)
                .with_database_url("sqlite::memory:?cache=shared")
                .with_credential_drivers(["test-static"]),
            store,
            compute,
            SandboxIndex::new(),
            SandboxWatchBus::new(),
            TracingLogBus::new(),
            Arc::new(SupervisorSessionRegistry::new()),
            None,
        ));
        insert_sandbox(
            &state,
            "sandbox-a",
            &crate::auth::sandbox_session::PersistedSandboxIdentity {
                runtime_generation: openshell_core::sandbox_generation::SandboxGenerationId::parse(
                    "generation-1",
                )
                .expect("runtime generation"),
                auth_epoch: openshell_core::jwt::CredentialEpoch::new(1).expect("auth epoch"),
                gateway_token_id: uuid::Uuid::new_v4(),
                refresh_replay: None,
            },
        )
        .await;
        let mut req = Request::new(RefreshSandboxTokenRequest {
            extension_service_names: Vec::new(),
        });
        req.extensions_mut().insert(sandbox_principal("sandbox-a"));
        let err = handle_refresh_sandbox_token(&state, req)
            .await
            .expect_err("missing issuer must yield unavailable");
        assert_eq!(err.code(), tonic::Code::Unavailable);
    }
}
