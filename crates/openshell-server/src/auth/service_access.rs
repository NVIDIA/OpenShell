// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Authentication for gateway-mediated application traffic. Direct supervisor
//! ingress has its own ingress-provider authentication contract.

use super::{
    audit::{self, AuthzDenial, ConnectionSource, RequestOrigin},
    authenticator::{AuthFailureReason, AuthMechanism, Authentication, AuthenticatorChain},
    authz::AuthzPolicy,
    identity::{Identity, IdentityProvider},
    principal::{OperatorPrincipal, Principal, UserPrincipal},
    workspace_authz::{MinWorkspaceRole, authorize_workspace},
};
use crate::ServerState;
use http::{HeaderMap, header};
use tonic::Status;

const APPLICATION_PATH: &str = "/openshell/application";
// Application requests can perform arbitrary operations, just like a TCP
// forward. Reuse that operation's global role and sandbox:write scope policy.
const ACCESS_POLICY: &str = "/openshell.v1.OpenShell/ForwardTcp";

/// Only populated from a verified TLS connection, never forwarded HTTP headers.
#[derive(Clone, Default)]
pub struct ServicePeer {
    pub secure: bool,
    pub identity: Option<Identity>,
    pub certificate_sha256: Option<String>,
    pub source: Option<ConnectionSource>,
}

pub async fn authorize(
    state: &ServerState,
    headers: &HeaderMap,
    peer: &ServicePeer,
    workspace: &str,
) -> Result<Principal, Status> {
    audit::with_request(
        APPLICATION_PATH.to_string(),
        RequestOrigin::new(peer.source, headers),
        authorize_with_chain(
            state,
            headers,
            peer,
            workspace,
            crate::multiplex::build_authenticator_chain(state),
        ),
    )
    .await
}

async fn authorize_with_chain(
    state: &ServerState,
    headers: &HeaderMap,
    peer: &ServicePeer,
    workspace: &str,
    chain: Option<AuthenticatorChain>,
) -> Result<Principal, Status> {
    let origin = RequestOrigin::new(peer.source, headers);
    let principal = authenticate(state, headers, peer, chain).await.map_err(
        |(status, mechanism, reason)| {
            audit::emit_authentication_failure(APPLICATION_PATH, &origin, mechanism, reason);
            status
        },
    )?;
    if (state.config.mtls_auth.enabled || state.config.mtls_auth.operator_enabled)
        && let Some(fingerprint) = &peer.certificate_sha256
    {
        super::service_session::check_certificate(state, fingerprint).await?;
    }
    if let Some(token) = super::authenticator::bearer_credential(headers) {
        super::service_session::check_token(state, token).await?;
    }
    audit::emit_logon(
        &state.logons,
        APPLICATION_PATH,
        &origin,
        &principal,
        headers,
        peer.certificate_sha256.as_deref(),
    );
    match &principal {
        Principal::User(user) => {
            if let Some(oidc) = &state.config.oidc {
                let policy = AuthzPolicy {
                    admin_role: oidc.admin_role.clone(),
                    user_role: oidc.user_role.clone(),
                    scopes_enabled: !oidc.scopes_claim.is_empty(),
                };
                if let Err(denial) = policy.check(&user.identity, ACCESS_POLICY) {
                    audit::emit_authorization_denial(&principal, denial.denial);
                    return Err(denial.status);
                }
            }
        }
        Principal::Operator(_) => {}
        _ => {
            return Err(audit::deny(
                &principal,
                AuthzDenial::MethodNotPermitted,
                "application access requires a user identity",
            ));
        }
    }
    authorize_workspace(
        &state.store,
        &state.admin_role,
        &principal,
        workspace,
        MinWorkspaceRole::User,
    )
    .await?;
    Ok(principal)
}

type AuthenticationError = (Status, Option<AuthMechanism>, AuthFailureReason);

async fn authenticate(
    state: &ServerState,
    headers: &HeaderMap,
    peer: &ServicePeer,
    chain: Option<AuthenticatorChain>,
) -> Result<Principal, AuthenticationError> {
    let reject = |message, reason| (Status::unauthenticated(message), None, reason);
    let has_authorization = headers.contains_key(header::AUTHORIZATION);
    if headers
        .get_all(header::AUTHORIZATION)
        .iter()
        .any(|value| value.as_bytes().len() > 16384)
    {
        return Err(reject(
            "authorization header exceeds limit",
            AuthFailureReason::MalformedCredential,
        ));
    }
    // Reject ambiguous credentials before any authenticator can select one.
    if headers.get_all(header::AUTHORIZATION).iter().count() > 1 {
        return Err(reject(
            "ambiguous authorization headers",
            AuthFailureReason::ConflictingCredentials,
        ));
    }
    if state.config.mtls_auth.operator_enabled
        && let Some(identity) = peer.identity.as_ref().filter(|identity| {
            identity.provider == IdentityProvider::Mtls
                && identity.roles.iter().any(|role| role == "operator")
        })
        && let Some(certificate_sha256) = &peer.certificate_sha256
    {
        if has_authorization {
            return Err(reject(
                "operator certificates must not be combined with authorization headers",
                AuthFailureReason::ConflictingCredentials,
            ));
        }
        return Ok(Principal::Operator(OperatorPrincipal {
            identity: identity.clone(),
            certificate_sha256: certificate_sha256.clone(),
        }));
    }
    if let Some(chain) = chain {
        match chain.authenticate(headers, APPLICATION_PATH).await {
            Ok(Authentication::Accepted(principal)) => return Ok(principal),
            Err(rejection) => {
                return Err((
                    rejection.status,
                    Some(rejection.mechanism),
                    rejection.reason,
                ));
            }
            Ok(Authentication::Declined(decline)) => {
                return Err((
                    Status::unauthenticated("invalid application access credential"),
                    Some(decline.mechanism),
                    decline.reason,
                ));
            }
            Ok(Authentication::NotApplicable) => {}
        }
    }
    if has_authorization {
        return Err(reject(
            "invalid authorization header",
            AuthFailureReason::MalformedCredential,
        ));
    }
    if state.config.mtls_auth.enabled {
        if let Some(identity) = &peer.identity {
            return Ok(Principal::User(UserPrincipal {
                identity: identity.clone(),
            }));
        }
        // Match the configured gateway's explicit local-development bypass.
        if !state.config.auth.allow_unauthenticated_users {
            return Err(reject(
                "missing client certificate",
                AuthFailureReason::MissingCredential,
            ));
        }
    }
    if state.config.auth.allow_unauthenticated_users {
        return Ok(crate::multiplex::unauthenticated_dev_user_principal());
    }
    Err(reject(
        "authentication required",
        AuthFailureReason::MissingCredential,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::authenticator::{AuthRejection, Authenticator};
    use crate::grpc::test_support::test_server_state;
    use async_trait::async_trait;
    use openshell_core::proto::{WorkspaceMember, WorkspaceRole, datamodel::v1::ObjectMeta};
    use std::sync::Arc;

    #[derive(Clone)]
    struct TestAuth(Result<Authentication, AuthRejection>);

    #[async_trait]
    impl Authenticator for TestAuth {
        async fn authenticate(
            &self,
            _headers: &HeaderMap,
            path: &str,
        ) -> Result<Authentication, AuthRejection> {
            assert_eq!(path, APPLICATION_PATH);
            self.0.clone()
        }
    }

    fn chain(outcome: Result<Authentication, AuthRejection>) -> AuthenticatorChain {
        AuthenticatorChain::new(vec![Arc::new(TestAuth(outcome))])
    }

    fn identity() -> Identity {
        Identity {
            subject: "alice".into(),
            display_name: None,
            roles: vec!["openshell-user".into()],
            scopes: vec!["sandbox:write".into()],
            provider: IdentityProvider::Oidc,
        }
    }

    async fn state() -> Arc<ServerState> {
        let mut state = test_server_state().await;
        let inner = Arc::get_mut(&mut state).unwrap();
        inner.config.auth.allow_unauthenticated_users = false;
        inner.admin_role = "openshell-admin".into();
        inner.config.oidc = Some(serde_json::from_value(serde_json::json!({
            "issuer": "https://issuer.example.com", "audience": "openshell", "scopes_claim": "scope"
        })).unwrap());
        state
    }

    async fn member(state: &ServerState) {
        state
            .store
            .put_message(&WorkspaceMember {
                metadata: Some(ObjectMeta {
                    id: uuid::Uuid::new_v4().to_string(),
                    name: "alice".into(),
                    workspace: "default".into(),
                    ..Default::default()
                }),
                principal_subject: "alice".into(),
                role: WorkspaceRole::User.into(),
            })
            .await
            .unwrap();
    }

    async fn access(
        state: &ServerState,
        identity: Identity,
        workspace: &str,
    ) -> Result<Principal, Status> {
        authorize_with_chain(
            state,
            &HeaderMap::new(),
            &ServicePeer::default(),
            workspace,
            Some(chain(Ok(Authentication::Accepted(Principal::User(
                UserPrincipal { identity },
            ))))),
        )
        .await
    }

    #[tokio::test]
    async fn service_access_enforces_workspace_role_and_scope() {
        let state = state().await;
        assert_eq!(
            access(&state, identity(), "default")
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        member(&state).await;
        access(&state, identity(), "default").await.unwrap();
        assert_eq!(
            access(&state, identity(), "other")
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        let mut user = identity();
        user.scopes = vec!["sandbox:read".into()];
        assert_eq!(
            access(&state, user, "default").await.unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
        let mut user = identity();
        user.roles.clear();
        assert_eq!(
            access(&state, user, "default").await.unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
    }

    #[tokio::test]
    async fn service_access_rejects_internal_principals_even_with_workspace_access() {
        let state = state().await;
        for principal in [
            crate::auth::principal::test_support::sandbox("sandbox-id"),
            Principal::Peer(crate::auth::principal::PeerPrincipal {
                replica_id: "peer".into(),
                pod_uid: "uid".into(),
            }),
            Principal::Anonymous,
        ] {
            let error = authorize_with_chain(
                &state,
                &HeaderMap::new(),
                &ServicePeer::default(),
                "default",
                Some(chain(Ok(Authentication::Accepted(principal)))),
            )
            .await
            .unwrap_err();
            assert_eq!(error.code(), tonic::Code::PermissionDenied);
        }
    }

    #[tokio::test]
    async fn service_access_rejects_missing_invalid_expired_and_duplicate_credentials() {
        let mut state = state().await;
        let peer = ServicePeer::default();
        assert_eq!(
            authorize_with_chain(
                &state,
                &HeaderMap::new(),
                &peer,
                "default",
                Some(chain(Ok(Authentication::NotApplicable)))
            )
            .await
            .unwrap_err()
            .code(),
            tonic::Code::Unauthenticated
        );
        // Invalid credentials never become a local-development identity.
        Arc::get_mut(&mut state)
            .unwrap()
            .config
            .auth
            .allow_unauthenticated_users = true;
        for reason in [
            AuthFailureReason::InvalidCredential,
            AuthFailureReason::ExpiredCredential,
        ] {
            assert_eq!(
                authorize_with_chain(
                    &state,
                    &HeaderMap::new(),
                    &peer,
                    "default",
                    Some(chain(Err(AuthRejection::new(
                        AuthMechanism::Oidc,
                        reason,
                        Status::unauthenticated("rejected")
                    ))))
                )
                .await
                .unwrap_err()
                .code(),
                tonic::Code::Unauthenticated
            );
        }
        let mut headers = HeaderMap::new();
        headers.append(header::AUTHORIZATION, "Bearer first".parse().unwrap());
        headers.append(header::AUTHORIZATION, "Bearer second".parse().unwrap());
        assert_eq!(
            authorize_with_chain(
                &state,
                &headers,
                &peer,
                "default",
                Some(chain(Ok(Authentication::Accepted(Principal::User(
                    UserPrincipal {
                        identity: identity()
                    }
                )))))
            )
            .await
            .unwrap_err()
            .code(),
            tonic::Code::Unauthenticated
        );
    }

    #[tokio::test]
    async fn service_access_uses_only_verified_mtls_identity_and_operator_fingerprint() {
        let mut state = state().await;
        Arc::get_mut(&mut state).unwrap().config.mtls_auth.enabled = true;
        member(&state).await;
        let mut user = identity();
        user.provider = IdentityProvider::Mtls;
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-client-cert", "alice".parse().unwrap());
        assert!(
            authorize_with_chain(&state, &headers, &ServicePeer::default(), "default", None)
                .await
                .is_err()
        );
        let peer = ServicePeer {
            identity: Some(user.clone()),
            ..Default::default()
        };
        authorize_with_chain(&state, &headers, &peer, "default", None)
            .await
            .unwrap();
        user.roles = vec!["operator".into()];
        Arc::get_mut(&mut state)
            .unwrap()
            .config
            .mtls_auth
            .operator_enabled = true;
        let peer = ServicePeer {
            identity: Some(user),
            certificate_sha256: Some("verified-fingerprint".into()),
            source: None,
            secure: true,
        };
        assert!(matches!(
            authorize_with_chain(&state, &HeaderMap::new(), &peer, "other", None)
                .await
                .unwrap(),
            Principal::Operator(_)
        ));
        headers.insert(header::AUTHORIZATION, "Bearer user".parse().unwrap());
        assert_eq!(
            authorize_with_chain(&state, &headers, &peer, "other", None)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
    }
}
