// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-owned sandbox identity and provider-token acquisition.
//! The caller selects an attached configured credential, never grant parameters.
use super::{
    Arc, HashMap, IntermediateTokenCache, LazyLock, Message, ObjectId, ObjectWorkspace, Principal,
    Provider, ProviderCredentialTokenGrantType, Request, Response, Sandbox, ServerState, Status,
    TokenExchangeParams, TokenGrantFailure, TokenGrantFailureKind, TokenGrantStage,
    canonical_request_id, effective_jwt_svid_audience, fetch_gateway_jwt_svid,
    get_provider_type_profile_for_scope, insert_dynamic_credentials_for_profile, jwt_exp_ms,
    log_token_grant_failure, oauth, perform_intermediate_token_exchange,
    provider_credential_expiration_ms, resolve_subject_token_credential,
    sanitize_token_grant_status, token_exchange_http_client, token_grant_configuration_status,
    token_grant_dependency_status, token_grant_identity_rejected, token_grant_store_status,
};
use openshell_core::jwt::AuthenticatedSandboxSession;
use openshell_core::proto::{
    GetSandboxProviderAccessTokenRequest, GetSandboxProviderAccessTokenResponse,
    ProviderCredentialTokenGrant,
};
use openshell_core::token_grant_failure::BROKERED_TOKEN_GATEWAY_DEADLINE;
use openshell_spiffe::SandboxIdentityProvider;
use std::time::Duration;

static ACCESS_TOKENS: LazyLock<IntermediateTokenCache> = LazyLock::new(IntermediateTokenCache::new);
static ACQUISITIONS: LazyLock<Acquisitions> = LazyLock::new(Acquisitions::default);

pub(in crate::grpc) async fn handle(
    state: &Arc<ServerState>,
    request: Request<GetSandboxProviderAccessTokenRequest>,
) -> Result<Response<GetSandboxProviderAccessTokenResponse>, Status> {
    let request_id = canonical_request_id(request.metadata());
    // Failures go to the authenticated sandbox's log stream; other callers
    // are logged on the gateway only.
    let log_sandbox_id = match request.extensions().get::<Principal>() {
        Some(Principal::Sandbox(principal)) => Some(principal.sandbox_id.clone()),
        _ => None,
    };
    // The deadline also bounds waiting for a concurrent acquisition.
    let result = tokio::time::timeout(
        BROKERED_TOKEN_GATEWAY_DEADLINE,
        obtain(state, request, request_id.as_deref()),
    )
    .await
    .unwrap_or_else(|_| {
        Err(
            TokenGrantFailure::new(TokenGrantFailureKind::Timeout, TokenGrantStage::GatewayRpc)
                .to_status(),
        )
    });
    result.map_err(|status| {
        let status = sanitize_token_grant_status(status);
        log_token_grant_failure(
            log_sandbox_id.as_deref(),
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

/// One configured credential of an attached provider.
struct ConfiguredGrant {
    provider: Provider,
    grant: ProviderCredentialTokenGrant,
    /// The gateway's exact key for the credential, including its endpoint owner.
    key: String,
}

/// Resolve the exact configured credential from the gateway's approved profile.
/// Audience and scopes (including endpoint overrides) never come from the caller.
///
/// The caller's key must name a configured key exactly, apart from the
/// generation a supervisor adds; a different or missing owner matches nothing.
async fn grant_configuration(
    state: &ServerState,
    sandbox_id: &str,
    key: &str,
) -> Result<ConfiguredGrant, Status> {
    let invalid = || token_grant_configuration_status(tonic::Code::PermissionDenied);
    let key =
        openshell_core::dynamic_credential_key::unscoped_owned_key(key).ok_or_else(invalid)?;
    let identity =
        openshell_core::dynamic_credential_key::credential_identity(&key).ok_or_else(invalid)?;
    let (provider_name, _) = identity.split_once(':').ok_or_else(invalid)?;
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
    let credential = configured.remove(&key).ok_or_else(invalid)?;
    let grant = credential.token_grant.ok_or_else(invalid)?;
    oauth::parse_token_endpoint_url(&grant.token_endpoint).map_err(TokenGrantFailure::to_status)?;
    Ok(ConfiguredGrant {
        provider,
        grant,
        key,
    })
}

/// Bind a cached token to its runtime, configured credential, and subject.
///
/// Include the provider revision and resolved subject token, so an in-place
/// rotation of a handle-backed subject never serves a token minted from the
/// previous one. The digest is an in-memory map key and is never exposed.
fn cache_key(
    session: &AuthenticatedSandboxSession,
    configured: &ConfiguredGrant,
    subject: Option<&str>,
    gateway_id: &str,
) -> Result<String, Status> {
    let resource_version = configured
        .provider
        .metadata
        .as_ref()
        .map_or(0, |metadata| metadata.resource_version);
    let fields: [&[u8]; 11] = [
        b"openshell-provider-access-token-v1",
        gateway_id.as_bytes(),
        session.sandbox_id.as_str().as_bytes(),
        session.runtime_generation.as_str().as_bytes(),
        &session.auth_epoch.get().to_be_bytes(),
        configured.provider.object_id().as_bytes(),
        &resource_version.to_be_bytes(),
        configured.key.as_bytes(),
        &Message::encode_to_vec(&configured.grant),
        &[u8::from(subject.is_some())],
        subject.map_or(&[], str::as_bytes),
    ];
    digest_fields(&fields)
        .map(hex::encode)
        .map_err(|_| token_grant_configuration_status(tonic::Code::Internal))
}

/// SHA-256 of length-prefixed fields, so no two field lists share an encoding.
fn digest_fields(fields: &[&[u8]]) -> Result<[u8; 32], openshell_crypto::CryptoError> {
    let mut digest = openshell_crypto::sha256_digest()?;
    for field in fields {
        digest.update(&u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes())?;
        digest.update(field)?;
    }
    digest.finish()
}

/// The subject token of a token exchange grant, resolved for this request.
struct Subject {
    value: String,
    token_type: String,
    expires_at_ms: Option<i64>,
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
    // Startup enables an identity provider only with gateway session JWTs.
    let (Some(identity), Some(gateway_jwt)) = (
        state.sandbox_identity.as_deref(),
        state.config.gateway_jwt.as_ref(),
    ) else {
        return Err(token_grant_configuration_status(
            tonic::Code::FailedPrecondition,
        ));
    };
    if state.compute.configured_driver_name() != "kubernetes" {
        return Err(token_grant_configuration_status(
            tonic::Code::FailedPrecondition,
        ));
    }
    let gateway_id = gateway_jwt.gateway_id.as_str();
    let key = &request.get_ref().credential_key;
    let configured = grant_configuration(state, session.sandbox_id.as_str(), key).await?;
    let grant = &configured.grant;
    let ttl_override = grant
        .cache_ttl
        .as_ref()
        .map(openshell_core::time::duration_to_std)
        .transpose()
        .map_err(|_| token_grant_configuration_status(tonic::Code::InvalidArgument))?;
    let grant_type = ProviderCredentialTokenGrantType::try_from(grant.grant_type)
        .map_err(|_| token_grant_configuration_status(tonic::Code::FailedPrecondition))?;
    // Resolve the subject before any cache lookup, so its revocation or
    // expiry also denies cached tokens.
    let subject = if grant_type == ProviderCredentialTokenGrantType::TokenExchange {
        let subject = grant
            .subject_token
            .as_ref()
            .filter(|subject| subject.source == "provider_credential")
            .ok_or_else(|| token_grant_configuration_status(tonic::Code::FailedPrecondition))?;
        Some(Subject {
            expires_at_ms: provider_credential_expiration_ms(
                &configured.provider,
                &subject.credential,
            )?,
            value: resolve_subject_token_credential(
                &state.credentials,
                &configured.provider,
                &subject.credential,
            )
            .await?,
            token_type: subject.subject_token_type.clone(),
        })
    } else {
        None
    };
    let subject_value = subject.as_ref().map(|subject| subject.value.as_str());
    let fingerprint = cache_key(&session, &configured, subject_value, gateway_id)?;
    // A zero override disables caching, and with it shared acquisition.
    let caching = ttl_override != Some(Duration::ZERO);
    let cached = || {
        caching
            .then(|| ACCESS_TOKENS.get_until(&fingerprint))
            .flatten()
    };
    // A miss holds its fingerprint's turn until its token is cached, so
    // concurrent misses wait and then find it. A miss is cached only after
    // the final validation below, which a hit passes as well.
    let mut turn = None;
    let (response, serve_until_ms, acquired) = if let Some((token, until)) = cached() {
        (token, until, false)
    } else {
        let waited = if caching {
            Some(ACQUISITIONS.turn(&fingerprint).await)
        } else {
            None
        };
        if let Some((token, until)) = cached() {
            (token, until, false)
        } else {
            turn = waited;
            let (token, until) = acquire(
                state,
                &bearer,
                &session,
                identity,
                gateway_id,
                grant,
                subject.as_ref(),
                ttl_override,
                request_id,
            )
            .await?;
            (token, until, true)
        }
    };
    // Re-read attachment, provider revision, and profile, then the session,
    // before serving or caching any token.
    let current = grant_configuration(state, session.sandbox_id.as_str(), key).await?;
    if cache_key(&session, &current, subject_value, gateway_id)? != fingerprint {
        return Err(token_grant_configuration_status(
            tonic::Code::FailedPrecondition,
        ));
    }
    authorize(state, &bearer).await?;
    // The lifetime runs from when the token service answered, so time spent
    // in the final validation counts against it.
    let remaining_ms = serve_until_ms.saturating_sub(crate::persistence::current_time_ms());
    if remaining_ms <= 0 {
        return Err(TokenGrantFailure::new(
            TokenGrantFailureKind::Timeout,
            TokenGrantStage::GatewayRpc,
        )
        .to_status());
    }
    if acquired && caching {
        ACCESS_TOKENS.set(fingerprint, &response, serve_until_ms);
    }
    drop(turn);
    Ok(Response::new(GetSandboxProviderAccessTokenResponse {
        access_token: response.access_token,
        token_type: response.token_type,
        expires_after: openshell_core::time::duration_from_std(Duration::from_millis(
            u64::try_from(remaining_ms).unwrap_or_default(),
        ))
        .ok(),
    }))
}

/// Acquire a final token, re-authorizing the session between network calls.
/// Returns the token and when to stop serving it.
#[allow(clippy::too_many_arguments)]
async fn acquire(
    state: &ServerState,
    bearer: &str,
    session: &AuthenticatedSandboxSession,
    identity: &dyn SandboxIdentityProvider<Error = TokenGrantFailure>,
    gateway_id: &str,
    grant: &ProviderCredentialTokenGrant,
    subject: Option<&Subject>,
    ttl_override: Option<Duration>,
    request_id: Option<&str>,
) -> Result<(oauth::OAuthTokenResponse, i64), Status> {
    authorize(state, bearer).await?;
    let audience = effective_jwt_svid_audience(&grant.token_endpoint, &grant.jwt_svid_audience);
    let svid = identity
        .fetch_jwt_svid(gateway_id, session.sandbox_id.as_str(), &audience)
        .await
        .map_err(TokenGrantFailure::to_status)?;
    authorize(state, bearer).await?;
    let client = token_exchange_http_client()?;
    let subject_expiry = subject.and_then(|subject| subject.expires_at_ms);
    let token = if let Some(subject) = subject {
        let component_svid = fetch_gateway_jwt_svid(&audience).await?;
        let intermediate = perform_intermediate_token_exchange(
            &grant.token_endpoint,
            &TokenExchangeParams {
                client_assertion: &component_svid,
                client_assertion_type: &grant.client_assertion_type,
                subject_token: &subject.value,
                subject_token_type: &subject.token_type,
                audience: &svid.spiffe_id,
                scopes: &[],
                requested_token_type: &grant.requested_token_type,
            },
            request_id,
        )
        .await?;
        authorize(state, bearer).await?;
        oauth::post_oauth_token_exchange(
            client,
            &grant.token_endpoint,
            &TokenExchangeParams {
                client_assertion: &svid.token,
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
                client_assertion: &svid.token,
                client_assertion_type: &grant.client_assertion_type,
                audience: &grant.audience,
                scopes: &grant.scopes,
            },
            request_id,
        )
        .await
        .map_err(TokenGrantFailure::to_status)?
    };
    let obtained_at_ms = crate::persistence::current_time_ms();
    let identity_expires_at_ms = session
        .expires_at
        .saturating_mul(1000)
        .min(svid.expires_at.saturating_mul(1000))
        .min(subject_expiry.unwrap_or(i64::MAX));
    let serve_until_ms =
        serve_until_ms(&token, ttl_override, obtained_at_ms, identity_expires_at_ms).ok_or_else(
            || {
                TokenGrantFailure::new(
                    TokenGrantFailureKind::Unclassified,
                    TokenGrantStage::TokenEndpoint,
                )
                .to_status()
            },
        )?;
    authorize(state, bearer).await?;
    Ok((token, serve_until_ms))
}

/// When to stop serving a token the token service issued at `obtained_at_ms`,
/// or `None` when it is already expired.
///
/// The issuer's `expires_in`, a parseable JWT `exp` of the access token, and
/// the session, SVID, and subject expiries each bound the token; `exp` can
/// only shorten it. Serving stops the usual skew before the earliest bound,
/// after at least one second, and never later than the default cache lifetime
/// (whose fallback applies when the issuer omits `expires_in`). A configured
/// cache TTL may shorten that lifetime but, unlike a dedicated supervisor's
/// cache, never extends it.
fn serve_until_ms(
    token: &oauth::OAuthTokenResponse,
    ttl_override: Option<Duration>,
    obtained_at_ms: i64,
    identity_expires_at_ms: i64,
) -> Option<i64> {
    let issuer_expires_at_ms = (token.expires_in > 0)
        .then(|| obtained_at_ms.saturating_add(token.expires_in.saturating_mul(1000)));
    let expires_at_ms = [issuer_expires_at_ms, jwt_exp_ms(&token.access_token)]
        .into_iter()
        .flatten()
        .fold(identity_expires_at_ms, i64::min);
    if expires_at_ms <= obtained_at_ms {
        return None;
    }
    let default_ttl = oauth::token_cache_ttl(None, token.expires_in);
    let ttl = ttl_override
        .filter(|ttl| !ttl.is_zero())
        .map_or(default_ttl, |ttl| ttl.min(default_ttl));
    let skewed_expiry_ms = expires_at_ms
        .saturating_sub(oauth::TOKEN_CACHE_EXPIRY_SKEW_SECONDS.saturating_mul(1000))
        .max(obtained_at_ms.saturating_add(1000).min(expires_at_ms));
    Some(
        obtained_at_ms
            .saturating_add(i64::try_from(ttl.as_millis()).unwrap_or(i64::MAX))
            .min(skewed_expiry_ms),
    )
}

type AcquisitionSlots = HashMap<String, (Arc<tokio::sync::Mutex<()>>, usize)>;

/// Coordinate token acquisition separately for each cache fingerprint.
///
/// Concurrent misses share a single acquisition without locking unrelated
/// tokens. An entry exists only
/// while a request holds or awaits its turn, including a cancelled wait.
#[derive(Default)]
struct Acquisitions {
    slots: std::sync::Mutex<AcquisitionSlots>,
}

impl Acquisitions {
    async fn turn(&self, key: &str) -> AcquisitionTurn<'_> {
        let registration = {
            let mut slots = self.lock();
            let (slot, users) = slots.entry(key.to_string()).or_default();
            *users += 1;
            Registration {
                acquisitions: self,
                key: key.to_string(),
                slot: slot.clone(),
            }
        };
        AcquisitionTurn {
            _guard: registration.slot.clone().lock_owned().await,
            _registration: registration,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, AcquisitionSlots> {
        self.slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

struct Registration<'a> {
    acquisitions: &'a Acquisitions,
    key: String,
    slot: Arc<tokio::sync::Mutex<()>>,
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        let mut slots = self.acquisitions.lock();
        if let Some((_, users)) = slots.get_mut(&self.key) {
            *users -= 1;
            if *users == 0 {
                slots.remove(&self.key);
            }
        }
    }
}

/// Fields drop in order: the turn is released before its registration.
struct AcquisitionTurn<'a> {
    _guard: tokio::sync::OwnedMutexGuard<()>,
    _registration: Registration<'a>,
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

    #[test]
    fn fingerprint_binds_the_runtime_configured_key_and_resolved_subject() {
        use openshell_core::jwt::{CredentialEpoch, SandboxId};
        let session = AuthenticatedSandboxSession {
            sandbox_id: SandboxId::parse(uuid::Uuid::new_v4().to_string()).unwrap(),
            runtime_generation: openshell_core::sandbox_generation::SandboxGenerationId::parse(
                "g1",
            )
            .unwrap(),
            auth_epoch: CredentialEpoch::new(1).unwrap(),
            token_id: uuid::Uuid::new_v4(),
            issued_at: 1,
            expires_at: 2,
        };
        let configured = |key: &str| ConfiguredGrant {
            provider: Provider::default(),
            grant: ProviderCredentialTokenGrant::default(),
            key: key.to_string(),
        };
        let owned = "api.example.com\t443\t/v1/**\towner\tprovider:access";
        let fingerprint = |session, key, subject| {
            cache_key(session, &configured(key), subject, "gateway").unwrap()
        };
        let base = fingerprint(&session, owned, Some("subject-a"));
        // A renewed session token of the same runtime shares cached tokens.
        let renewed = AuthenticatedSandboxSession {
            token_id: uuid::Uuid::new_v4(),
            expires_at: 3,
            ..session.clone()
        };
        assert_eq!(fingerprint(&renewed, owned, Some("subject-a")), base);
        // A rotated subject, another credential, or another epoch does not.
        assert_ne!(fingerprint(&session, owned, Some("subject-b")), base);
        let spoofed = owned.replace("owner", "other");
        assert_ne!(fingerprint(&session, &spoofed, Some("subject-a")), base);
        let rotated = AuthenticatedSandboxSession {
            auth_epoch: CredentialEpoch::new(2).unwrap(),
            ..session.clone()
        };
        assert_ne!(fingerprint(&rotated, owned, Some("subject-a")), base);
        assert_ne!(
            fingerprint(&session, owned, None),
            fingerprint(&session, owned, Some(""))
        );
    }

    #[test]
    fn served_lifetime_never_exceeds_the_token_or_identity() {
        const NOW: i64 = 1_700_000_000_000;
        let token = |expires_in, access_token: &str| oauth::OAuthTokenResponse {
            access_token: access_token.to_string(),
            expires_in,
            token_type: String::new(),
        };
        let jwt = |exp_ms: i64| {
            use base64::Engine as _;
            let claims = format!(r#"{{"exp":{}}}"#, exp_ms / 1000);
            let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims);
            format!("e30.{claims}.sig")
        };
        let hour = Some(Duration::from_hours(1));
        let identity = NOW + 86_400_000;
        let serve = |token, ttl, identity| serve_until_ms(&token, ttl, NOW, identity);
        // A longer cache override is capped by the issuer's lifetime and skew.
        assert_eq!(
            serve(token(300, "opaque"), hour, identity),
            Some(NOW + 270_000)
        );
        // A shorter override still applies.
        let minute = Some(Duration::from_mins(1));
        assert_eq!(
            serve(token(300, "opaque"), minute, identity),
            Some(NOW + 60_000)
        );
        // A JWT exp only shortens the lifetime.
        let short = jwt(NOW + 120_000);
        assert_eq!(
            serve(token(300, &short), hour, identity),
            Some(NOW + 90_000)
        );
        let long = jwt(NOW + 7_200_000);
        assert_eq!(
            serve(token(300, &long), None, identity),
            Some(NOW + 270_000)
        );
        // An omitted expires_in keeps the default fallback, even with an override.
        assert_eq!(
            serve(token(0, "opaque"), hour, identity),
            Some(NOW + 270_000)
        );
        // Zero disables caching, not the bound on serving.
        let zero = Some(Duration::ZERO);
        assert_eq!(
            serve(token(300, "opaque"), zero, identity),
            Some(NOW + 270_000)
        );
        // Identity expiry caps the lifetime with skew but still serves briefly.
        assert_eq!(
            serve(token(300, "opaque"), None, NOW + 60_000),
            Some(NOW + 30_000)
        );
        assert_eq!(
            serve(token(300, "opaque"), None, NOW + 10_000),
            Some(NOW + 1_000)
        );
        assert_eq!(
            serve(token(300, "opaque"), None, NOW + 500),
            Some(NOW + 500)
        );
        // An already expired acquisition is never served.
        assert_eq!(serve(token(300, &jwt(NOW)), None, identity), None);
        assert_eq!(serve(token(300, "opaque"), None, NOW), None);
    }

    #[tokio::test]
    async fn concurrent_misses_take_turns_per_fingerprint_and_leave_no_entries() {
        let acquisitions: &'static Acquisitions = Box::leak(Box::default());
        let first = acquisitions.turn("a").await;
        // Another fingerprint is independent.
        drop(acquisitions.turn("b").await);
        // A waiter for the same fingerprint blocks; cancelling it leaves only
        // the holder's entry.
        let waiting = tokio::time::timeout(Duration::from_millis(50), acquisitions.turn("a"));
        assert!(waiting.await.is_err());
        assert_eq!(
            acquisitions.lock().get("a").map(|(_, users)| *users),
            Some(1)
        );
        assert_eq!(acquisitions.lock().len(), 1);
        let waiter = tokio::spawn(async move { drop(acquisitions.turn("a").await) });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        drop(first);
        waiter.await.unwrap();
        assert!(acquisitions.lock().is_empty());
    }
}
