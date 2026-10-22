// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-owned sandbox identity and provider-token acquisition.
//! The caller selects an attached configured credential, never grant parameters.
use super::{
    Arc, HashMap, IntermediateTokenCache, LazyLock, Message, ObjectId, ObjectWorkspace, Principal,
    Provider, ProviderCredentialTokenGrantType, Request, Response, Sandbox, ServerState, Status,
    TokenExchangeParams, TokenGrantFailure, canonical_request_id, effective_jwt_svid_audience,
    fetch_gateway_jwt_svid, get_provider_type_profile_for_scope,
    insert_dynamic_credentials_for_profile, log_token_grant_failure, oauth,
    perform_intermediate_token_exchange, provider_credential_expiration_ms,
    resolve_subject_token_credential, sanitize_token_grant_status, token_exchange_http_client,
    token_grant_configuration_status, token_grant_dependency_status, token_grant_identity_rejected,
    token_grant_store_status,
};
use openshell_core::jwt::AuthenticatedSandboxSession;
use openshell_core::proto::{
    GetSandboxProviderAccessTokenRequest, GetSandboxProviderAccessTokenResponse,
    ProviderCredentialTokenGrant,
};

static ACCESS_TOKENS: LazyLock<IntermediateTokenCache> = LazyLock::new(IntermediateTokenCache::new);

pub(in crate::grpc) async fn handle(
    state: &Arc<ServerState>,
    request: Request<GetSandboxProviderAccessTokenRequest>,
) -> Result<Response<GetSandboxProviderAccessTokenResponse>, Status> {
    let request_id = canonical_request_id(request.metadata());
    let result = obtain(state, request, request_id.as_deref()).await;
    result.map_err(|status| {
        let status = sanitize_token_grant_status(status);
        log_token_grant_failure(
            None,
            request_id.as_deref(),
            TokenGrantFailure::from_status(&status),
        );
        status
    })
}

/// Verify the original bearer again after asynchronous work, including expiry
/// and the persisted generation, epoch, active phase, and current token lineage.
async fn authorize(
    state: &ServerState,
    bearer: &str,
) -> Result<AuthenticatedSandboxSession, Status> {
    let authority = state
        .sandbox_session_jwt_authority
        .as_ref()
        .ok_or_else(|| token_grant_identity_rejected(tonic::Code::Unauthenticated))?;
    let session = authority
        .verify_gateway_token(bearer)
        .map_err(|error| error.status)?;
    if session.expires_at == 0 {
        return Err(token_grant_identity_rejected(tonic::Code::Unauthenticated));
    }
    crate::auth::sandbox_session::authorize_persisted(&state.store, &session)
        .await
        .map_err(|error| error.status)?;
    Ok(session)
}

/// Resolve the exact endpoint selector from the gateway's approved profile.
/// Audience and scopes (including endpoint overrides) never come from the caller.
async fn grant_configuration(
    state: &ServerState,
    sandbox_id: &str,
    key: &str,
) -> Result<(Provider, ProviderCredentialTokenGrant), Status> {
    let invalid = || token_grant_configuration_status(tonic::Code::PermissionDenied);
    let identity =
        openshell_core::dynamic_credential_key::credential_identity(key).ok_or_else(invalid)?;
    let (provider_name, _) = identity.split_once(':').ok_or_else(invalid)?;
    let selector =
        openshell_core::dynamic_credential_key::endpoint_selector(key).ok_or_else(invalid)?;
    let sandbox = state
        .store
        .get_message::<Sandbox>(sandbox_id)
        .await
        .map_err(|_| token_grant_store_status())?
        .ok_or_else(invalid)?;
    let spec = sandbox.spec.as_ref().ok_or_else(invalid)?;
    if !spec.providers.iter().any(|name| name == provider_name) {
        return Err(invalid());
    }
    let provider = state
        .store
        .get_message_by_name::<Provider>(sandbox.object_workspace(), provider_name)
        .await
        .map_err(|_| token_grant_store_status())?
        .ok_or_else(invalid)?;
    let catalog = state
        .provider_profile_sources
        .snapshot_catalog(&state.store, sandbox.object_workspace())
        .await
        .map_err(token_grant_dependency_status)?;
    let profile = get_provider_type_profile_for_scope(
        &catalog,
        &provider.r#type,
        &provider.profile_workspace,
    )
    .ok_or_else(invalid)?;
    let mut configured = HashMap::new();
    insert_dynamic_credentials_for_profile(
        &mut configured,
        &profile,
        provider_name,
        provider.object_id(),
    )?;
    let mut matching = configured.iter().filter(|(candidate, _)| {
        let Some(endpoint) = openshell_core::dynamic_credential_key::endpoint_selector(candidate)
        else {
            return false;
        };
        endpoint.host == selector.host
            && endpoint.port == selector.port
            && endpoint.path == selector.path
            && openshell_core::dynamic_credential_key::credential_identity(candidate)
                == Some(identity)
    });
    let (_, credential) = matching.next().ok_or_else(invalid)?;
    if matching.next().is_some() {
        return Err(invalid());
    }
    let grant = credential.token_grant.clone().ok_or_else(invalid)?;
    oauth::parse_token_endpoint_url(&grant.token_endpoint).map_err(TokenGrantFailure::to_status)?;
    Ok((provider, grant))
}

fn cache_key(
    session: &AuthenticatedSandboxSession,
    provider: &Provider,
    grant: &ProviderCredentialTokenGrant,
    credential_key: &str,
    gateway_id: &str,
) -> Result<String, Status> {
    use sha2::{Digest as _, Sha256};
    let binding = serde_json::to_vec(&(
        gateway_id,
        session.sandbox_id.as_str(),
        session.runtime_generation.as_str(),
        session.auth_epoch.get(),
        provider.object_id(),
        provider
            .metadata
            .as_ref()
            .map(|metadata| metadata.resource_version),
        credential_key,
        Message::encode_to_vec(grant),
    ))
    .map_err(|_| token_grant_configuration_status(tonic::Code::Internal))?;
    Ok(hex::encode(Sha256::digest(binding)))
}

#[allow(clippy::too_many_lines)]
async fn obtain(
    state: &Arc<ServerState>,
    request: Request<GetSandboxProviderAccessTokenRequest>,
    request_id: Option<&str>,
) -> Result<Response<GetSandboxProviderAccessTokenResponse>, Status> {
    let Some(Principal::Sandbox(principal)) = request.extensions().get::<Principal>() else {
        return Err(token_grant_identity_rejected(tonic::Code::PermissionDenied));
    };
    let mut values = request.metadata().get_all("authorization").iter();
    let bearer = values
        .next()
        .and_then(|value| value.to_str().ok())
        .and_then(openshell_core::auth::strip_bearer_scheme)
        .ok_or_else(|| token_grant_identity_rejected(tonic::Code::Unauthenticated))?
        .to_string();
    if values.next().is_some() {
        return Err(token_grant_identity_rejected(tonic::Code::Unauthenticated));
    }
    let session = authorize(state, &bearer).await?;
    if principal.sandbox_id != session.sandbox_id.as_str() {
        return Err(token_grant_identity_rejected(tonic::Code::PermissionDenied));
    }
    let delegation = state
        .spiffe_delegation
        .as_ref()
        .ok_or_else(|| token_grant_configuration_status(tonic::Code::FailedPrecondition))?;
    if state.compute.configured_driver_name() != "kubernetes" {
        return Err(token_grant_configuration_status(
            tonic::Code::FailedPrecondition,
        ));
    }
    let gateway_id = delegation.gateway_id();
    let key = &request.get_ref().credential_key;
    let (provider, grant) = grant_configuration(state, session.sandbox_id.as_str(), key).await?;
    let fingerprint = cache_key(&session, &provider, &grant, key, gateway_id)?;
    let ttl_override = grant
        .cache_ttl
        .as_ref()
        .map(openshell_core::time::duration_to_std)
        .transpose()
        .map_err(|_| token_grant_configuration_status(tonic::Code::InvalidArgument))?;
    let grant_type = ProviderCredentialTokenGrantType::try_from(grant.grant_type)
        .map_err(|_| token_grant_configuration_status(tonic::Code::FailedPrecondition))?;
    let mut subject_expiry = None;
    let subject = if grant_type == ProviderCredentialTokenGrantType::TokenExchange {
        let subject = grant
            .subject_token
            .as_ref()
            .filter(|subject| subject.source == "provider_credential")
            .ok_or_else(|| token_grant_configuration_status(tonic::Code::FailedPrecondition))?;
        subject_expiry = provider_credential_expiration_ms(&provider, &subject.credential)?;
        Some(
            resolve_subject_token_credential(&state.credentials, &provider, &subject.credential)
                .await?,
        )
    } else {
        None
    };
    let cached = if ttl_override == Some(std::time::Duration::ZERO) {
        None
    } else {
        ACCESS_TOKENS.get(&fingerprint)
    };
    // A miss also yields when its token may be cached; it is inserted only
    // after the final validation below, which a hit passes as well.
    let (response, cache_until) = if let Some(cached) = cached {
        (cached, None)
    } else {
        authorize(state, &bearer).await?;
        let audience = effective_jwt_svid_audience(&grant.token_endpoint, &grant.jwt_svid_audience);
        let (svid, svid_expiry) = delegation
            .fetch_jwt_svid(session.sandbox_id.as_str(), &audience)
            .await
            .map_err(TokenGrantFailure::to_status)?;
        authorize(state, &bearer).await?;
        let client = token_exchange_http_client()?;
        let token = if let Some(subject) = subject {
            let component_svid = fetch_gateway_jwt_svid(&audience).await?;
            let stable_id = delegation
                .sandbox_spiffe_id(session.sandbox_id.as_str())
                .map_err(|_| token_grant_configuration_status(tonic::Code::FailedPrecondition))?;
            let intermediate = perform_intermediate_token_exchange(
                &grant.token_endpoint,
                &TokenExchangeParams {
                    client_assertion: &component_svid,
                    client_assertion_type: &grant.client_assertion_type,
                    subject_token: &subject,
                    subject_token_type: &grant
                        .subject_token
                        .as_ref()
                        .ok_or_else(|| {
                            token_grant_configuration_status(tonic::Code::FailedPrecondition)
                        })?
                        .subject_token_type,
                    audience: &stable_id,
                    scopes: &[],
                    requested_token_type: &grant.requested_token_type,
                },
                request_id,
            )
            .await?;
            authorize(state, &bearer).await?;
            oauth::post_oauth_token_exchange(
                client,
                &grant.token_endpoint,
                &TokenExchangeParams {
                    client_assertion: &svid,
                    client_assertion_type: &grant.client_assertion_type,
                    subject_token: &intermediate.access_token,
                    subject_token_type: oauth::ACCESS_TOKEN_TYPE,
                    audience: &grant.audience,
                    scopes: &grant.scopes,
                    requested_token_type: &grant.requested_token_type,
                },
                request_id,
            )
            .await
            .map_err(TokenGrantFailure::to_status)?
        } else {
            oauth::post_oauth_token_grant(
                client,
                &grant.token_endpoint,
                &oauth::TokenGrantParams {
                    client_assertion: &svid,
                    client_assertion_type: &grant.client_assertion_type,
                    audience: &grant.audience,
                    scopes: &grant.scopes,
                },
                request_id,
            )
            .await
            .map_err(TokenGrantFailure::to_status)?
        };
        authorize(state, &bearer).await?;
        let cache_ttl = oauth::token_cache_ttl(ttl_override, token.expires_in);
        let now = crate::persistence::current_time_ms();
        // Stop serving the token a second before the session, SVID, or subject expires.
        let identity_expiry = session
            .expires_at
            .saturating_mul(1000)
            .min(svid_expiry.saturating_mul(1000))
            .min(subject_expiry.unwrap_or(i64::MAX))
            .saturating_sub(1000);
        let expires_at = now
            .saturating_add(i64::try_from(cache_ttl.as_millis()).unwrap_or(i64::MAX))
            .min(identity_expiry);
        (token, (expires_at > now).then_some(expires_at))
    };
    // Re-read attachment, provider revision, and profile, then the session,
    // before serving or caching any token.
    let (current_provider, current_grant) =
        grant_configuration(state, session.sandbox_id.as_str(), key).await?;
    if cache_key(&session, &current_provider, &current_grant, key, gateway_id)? != fingerprint {
        return Err(token_grant_configuration_status(
            tonic::Code::FailedPrecondition,
        ));
    }
    authorize(state, &bearer).await?;
    if let Some(expires_at) = cache_until {
        ACCESS_TOKENS.set(fingerprint, &response, expires_at);
    }
    Ok(Response::new(GetSandboxProviderAccessTokenResponse {
        access_token: response.access_token,
        token_type: response.token_type,
        expires_after: openshell_core::time::duration_from_std(std::time::Duration::from_secs(
            u64::try_from(response.expires_in).unwrap_or_default(),
        ))
        .ok(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::principal::{SandboxIdentitySource, SandboxPrincipal};
    #[tokio::test]
    async fn broker_requires_a_signed_session_even_with_a_sandbox_principal() {
        let state = crate::grpc::test_support::test_server_state().await;
        for principal in [
            Principal::Anonymous,
            Principal::Sandbox(SandboxPrincipal {
                sandbox_id: uuid::Uuid::new_v4().to_string(),
                source: SandboxIdentitySource::BootstrapJwt {
                    issuer: "launch-session".into(),
                },
                trust_domain: Some("openshell".into()),
            }),
        ] {
            let mut request = Request::new(GetSandboxProviderAccessTokenRequest {
                credential_key: "untrusted".into(),
            });
            request.extensions_mut().insert(principal);
            let error = handle(&state, request).await.unwrap_err();
            assert!(matches!(
                error.code(),
                tonic::Code::Unauthenticated | tonic::Code::PermissionDenied
            ));
        }
    }
}
