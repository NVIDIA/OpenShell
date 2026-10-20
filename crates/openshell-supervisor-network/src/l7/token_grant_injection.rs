// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Endpoint-bound dynamic token grant injection for HTTP relay paths.

#[cfg(test)]
mod multiple_grants;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use openshell_core::dynamic_credential_key::{credential_identity, endpoint_selector};
use openshell_core::endpoint_failure::EndpointFailure;
use openshell_core::endpoint_status::EndpointObservationContext;
use openshell_core::proto::{ProviderCredentialTokenGrant, ProviderProfileCredential};
use openshell_core::provider_credentials::{ProviderCredentialSnapshot, ProviderCredentialState};
use openshell_core::token_grant_failure::{
    TokenGrantFailure, TokenGrantFailureKind, TokenGrantStage,
};
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, Endpoint, HttpActivityBuilder, HttpRequest, SeverityId,
    StatusId, ctx::ctx as ocsf_ctx, ocsf_emit,
};
use tracing::warn;

use crate::l7::provider::L7Request;
use crate::l7::relay::L7EvalContext;

/// Borrowed grant configuration for one endpoint-bound provider credential.
pub struct TokenGrantRequest<'a> {
    pub provider_key: &'a str,
    pub token_endpoint: &'a str,
    pub jwt_svid_audience: &'a str,
    pub client_assertion_type: &'a str,
    pub audience: &'a str,
    pub scopes: &'a [String],
    pub cache_ttl: Option<std::time::Duration>,
    pub grant_type: i32,
    pub requested_token_type: &'a str,
    /// Supervisor-minted ID of the HTTP exchange that needs the token.
    pub request_id: &'a str,
}

/// Resolves credentials without retaining arbitrary upstream diagnostics in failures.
pub trait TokenGrantResolver: Send + Sync {
    /// Obtain a token or a bounded failure whose classification survives injection.
    fn obtain<'a>(
        &'a self,
        request: TokenGrantRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<String, TokenGrantFailure>> + Send + 'a>>;
}

/// Resolves provider tokens using the supervisor's authenticated grant flow.
#[derive(Default)]
pub struct SpiffeTokenGrantResolver;

impl TokenGrantResolver for SpiffeTokenGrantResolver {
    fn obtain<'a>(
        &'a self,
        request: TokenGrantRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<String, TokenGrantFailure>> + Send + 'a>> {
        Box::pin(async move {
            crate::token_grant::obtain_provider_token(
                crate::token_grant::ObtainProviderTokenRequest {
                    provider_name: request.provider_key,
                    token_endpoint: request.token_endpoint,
                    jwt_svid_audience: request.jwt_svid_audience,
                    client_assertion_type: request.client_assertion_type,
                    audience: request.audience,
                    scopes: request.scopes,
                    cache_ttl_override: request.cache_ttl,
                    grant_type: request.grant_type,
                    requested_token_type: request.requested_token_type,
                    request_id: request.request_id,
                },
            )
            .await
        })
    }
}

/// Construct the production SPIFFE-backed resolver.
pub fn default_resolver() -> Arc<dyn TokenGrantResolver> {
    Arc::new(SpiffeTokenGrantResolver)
}

/// A refused request: the grant failure and the credential whose grant failed.
///
/// The credential is the `provider:credential` name pair of the selected
/// binding, absent when the failure happened before a binding was selected.
/// Display and Debug print only the fixed grant failure message, so callers
/// can log this error without classifying it.
pub struct TokenGrantInjectionError {
    failure: TokenGrantFailure,
    credential: Option<String>,
}

impl TokenGrantInjectionError {
    fn new(failure: TokenGrantFailure) -> Self {
        Self {
            failure,
            credential: None,
        }
    }

    fn for_binding(failure: TokenGrantFailure, binding_key: &str) -> Self {
        Self {
            failure,
            credential: credential_identity(binding_key).map(str::to_string),
        }
    }

    /// Return the bounded classification for trusted status reporting.
    pub fn failure(&self) -> TokenGrantFailure {
        self.failure
    }

    /// Return the provider and credential names of the failed grant, if known.
    pub fn credential(&self) -> Option<(&str, &str)> {
        self.credential.as_deref()?.split_once(':')
    }

    /// Return the bounded status cause of this refusal for one request.
    pub fn endpoint_failure(&self, request_id: &str) -> EndpointFailure {
        let (provider, credential) = self.credential().unwrap_or_default();
        EndpointFailure::token_grant(self.failure, provider, credential, request_id)
    }
}

impl fmt::Display for TokenGrantInjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.failure, formatter)
    }
}

impl fmt::Debug for TokenGrantInjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.failure, formatter)
    }
}

impl std::error::Error for TokenGrantInjectionError {}

impl miette::Diagnostic for TokenGrantInjectionError {}

/// Pin `ctx` to the live provider installation and return its snapshot.
///
/// A connection can sit idle across a refresh before its first request, so a
/// grant always uses the installation current when the request arrives. The
/// pinned revision then scopes the injected keys, the status report and the
/// credential generation guard for the upstream write.
pub fn pin_live_credentials(ctx: &mut L7EvalContext) -> Option<Arc<ProviderCredentialSnapshot>> {
    let snapshot = ctx
        .provider_credentials
        .as_ref()
        .map(ProviderCredentialState::snapshot)?;
    ctx.provider_credential_revision = Some(snapshot.revision);
    ctx.provider_credential_installation_id = Some(snapshot.installation_id.clone());
    Some(snapshot)
}

/// Inject the grants whose endpoint selectors match the request.
///
/// L4-only forwarding uses this selector contract; it has no per-request L7
/// admission decision. Each header independently uses its most-specific
/// matching binding, and every selected grant must succeed: callers must not
/// forward the request when this returns an error. `ctx` must be pinned to
/// `snapshot` by [`pin_live_credentials`]. `request_id` is the supervisor-minted
/// ID of this exchange; it is sent to the token service and gateway and
/// recorded on the refusal event.
pub async fn inject_for_selectors(
    req: L7Request,
    ctx: &L7EvalContext,
    snapshot: &ProviderCredentialSnapshot,
    request_id: &str,
    observation_context: Option<&EndpointObservationContext>,
) -> Result<L7Request, TokenGrantInjectionError> {
    let selected = select_scoped(snapshot, ctx, request_path(&req.target), None);
    inject_or_report(req, ctx, selected, request_id, observation_context).await
}

/// Inject only grants owned by endpoints that admitted the inspected request.
/// An empty owner set permits no acquisition, including audit-only forwarding.
/// L4-only forwarding uses [`inject_for_selectors`] instead.
///
/// Credentials come from the pinned `snapshot`, and each selected key is scoped
/// to its revision and installation after selection so the one-grant-per-header
/// ambiguity check still compares the original credential identities.
pub(super) async fn inject_for_admitted_owners(
    req: L7Request,
    ctx: &L7EvalContext,
    snapshot: &ProviderCredentialSnapshot,
    admitted_owners: &HashSet<String>,
    request_id: &str,
    observation_context: Option<&EndpointObservationContext>,
) -> Result<L7Request, TokenGrantInjectionError> {
    let request_path = request_path(&req.target);
    let unowned = snapshot
        .dynamic_credentials
        .iter()
        .find(|(key, credential)| {
            credential.token_grant.is_some()
                && credential.token_grant_owners.is_empty()
                && dynamic_credential_key_match_score(key, &ctx.host, ctx.port, request_path)
                    .is_some()
        });
    let selected = if let Some((key, _)) = unowned {
        // A gateway that predates endpoint ownership metadata must be upgraded
        // before the supervisor; without owners no grant is admitted.
        Err(TokenGrantInjectionError::for_binding(
            injection_configuration_failure(),
            key,
        ))
    } else {
        select_scoped(snapshot, ctx, request_path, Some(admitted_owners))
    };
    inject_or_report(req, ctx, selected, request_id, observation_context).await
}

fn select_scoped(
    snapshot: &ProviderCredentialSnapshot,
    ctx: &L7EvalContext,
    request_path: &str,
    admitted_owners: Option<&HashSet<String>>,
) -> Result<Vec<(String, ProviderProfileCredential)>, TokenGrantInjectionError> {
    let candidates = token_grant_candidates(
        &snapshot.dynamic_credentials,
        ctx,
        request_path,
        admitted_owners,
    )?;
    Ok(select_token_grants(candidates)?
        .into_iter()
        .map(|(key, credential)| (snapshot.scoped_key(&key), credential))
        .collect())
}

/// Inject the selected grants, or record why the request was refused.
///
/// Every refusal emits one generic event that carries the request ID. The
/// classification stays in the returned error for trusted status reporting.
async fn inject_or_report(
    req: L7Request,
    ctx: &L7EvalContext,
    selected: Result<Vec<(String, ProviderProfileCredential)>, TokenGrantInjectionError>,
    request_id: &str,
    observation_context: Option<&EndpointObservationContext>,
) -> Result<L7Request, TokenGrantInjectionError> {
    if selected.as_ref().is_ok_and(Vec::is_empty) {
        // Most requests need no grant; keep that path free of allocation.
        return Ok(req);
    }
    let method = req.action.clone();
    let request_path = request_path(&req.target).to_string();
    let observation_context = observation_context
        .filter(|context| context.matches_provider_revision(ctx.provider_credential_revision));
    let successful_credentials: Vec<_> = if observation_context.is_some() {
        selected
            .as_ref()
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|(key, _)| {
                credential_identity(key)?
                    .split_once(':')
                    .map(|(provider, credential)| (provider.to_string(), credential.to_string()))
            })
            .collect()
    } else {
        Vec::new()
    };
    let result = match selected {
        Ok(credentials) => inject_selected(req, ctx, credentials, request_id).await,
        Err(error) => Err(error),
    };
    if let Err(error) = &result {
        report_refused_grant(ctx, &method, &request_path, request_id, error);
    }
    if let Some((sender, context)) = ctx
        .endpoint_observation_tx
        .as_ref()
        .zip(observation_context)
    {
        match &result {
            Err(error) => {
                let _ = sender.try_observe_token_grant(
                    context.clone(),
                    &ctx.host,
                    ctx.port,
                    Err(error.endpoint_failure(request_id)),
                );
            }
            Ok(_) => {
                for credential in successful_credentials {
                    let _ = sender.try_observe_token_grant(
                        context.clone(),
                        &ctx.host,
                        ctx.port,
                        Ok(credential),
                    );
                }
            }
        }
    }
    result
}

/// Record a refused grant.
///
/// The OCSF event's shorthand form can reach the sandboxed agent through
/// `policy.local` denials, so it names only the credential, the destination,
/// and the opaque request ID. The classification goes only into structured
/// fields of the operator log line, which the shorthand log never renders.
fn report_refused_grant(
    ctx: &L7EvalContext,
    method: &str,
    request_path: &str,
    request_id: &str,
    error: &TokenGrantInjectionError,
) {
    let credential = error
        .credential
        .as_deref()
        .map_or_else(|| "a dynamic credential".to_string(), ocsf_message_field);
    let failure = error.failure();
    warn!(
        host = %ctx.host,
        port = ctx.port,
        provider = %credential,
        request_id = %request_id,
        code = failure.code(),
        stage = failure.stage().code(),
        upstream_http_status = %failure
            .upstream_status()
            .map_or_else(|| "none".to_string(), |status| status.to_string()),
        "Token grant failed"
    );
    ocsf_emit!(
        HttpActivityBuilder::new(ocsf_ctx())
            .activity(ActivityId::Fail)
            .action(ActionId::Denied)
            .disposition(DispositionId::Blocked)
            .severity(SeverityId::Medium)
            .status(StatusId::Failure)
            .http_request(HttpRequest::new(method, ctx.ocsf_url(request_path)))
            .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
            .message(format!(
                "Token grant failed for {credential} to {}:{}",
                ctx.host, ctx.port
            ))
            .unmapped("request_id", request_id)
            .build()
    );
}

/// Acquires every selected grant and rewrites the request headers.
///
/// Any failed acquisition returns an error before any header is written.
async fn inject_selected(
    req: L7Request,
    ctx: &L7EvalContext,
    credentials: Vec<(String, ProviderProfileCredential)>,
    request_id: &str,
) -> Result<L7Request, TokenGrantInjectionError> {
    let resolver = ctx
        .token_grant_resolver
        .as_ref()
        .ok_or_else(|| TokenGrantInjectionError::new(injection_configuration_failure()))?;
    // A request that cannot carry a header never acquires a credential.
    parse_header_block(&req.raw_header).map_err(TokenGrantInjectionError::new)?;

    // Release the credential snapshot lock before acquisition. Keep all token values
    // local until every selected grant and header has been validated, so a later
    // failure cannot expose a partially authenticated request to a relay caller.
    let mut headers = Vec::with_capacity(credentials.len());
    for (provider_key, cred) in &credentials {
        let refused = |failure| TokenGrantInjectionError::for_binding(failure, provider_key);
        let token_grant = cred
            .token_grant
            .as_ref()
            .ok_or_else(|| refused(injection_configuration_failure()))?;
        let request =
            token_grant_request(provider_key, token_grant, request_id).map_err(refused)?;
        let access_token = resolver.obtain(request).await.map_err(refused)?;
        crate::token_grant::validate_access_token(&access_token)
            .map_err(|failure| refused(failure.at_stage(TokenGrantStage::Injection)))?;
        headers.push(token_grant_header(cred, &access_token).map_err(refused)?);
    }

    let mut raw_header = req.raw_header;
    for (name, value) in headers {
        raw_header =
            inject_header(&raw_header, &name, &value).map_err(TokenGrantInjectionError::new)?;
    }
    for (provider_key, _) in credentials {
        ocsf_emit!(
            HttpActivityBuilder::new(ocsf_ctx())
                .activity(ActivityId::Other)
                .action(ActionId::Allowed)
                .disposition(DispositionId::Allowed)
                .severity(SeverityId::Informational)
                .http_request(HttpRequest::new(
                    &req.action,
                    ctx.ocsf_url(request_path(&req.target)),
                ))
                .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                .message(format!(
                    "Token grant successful for {} to {}:{}",
                    ocsf_message_field(
                        credential_identity(&provider_key).unwrap_or("a dynamic credential")
                    ),
                    ctx.host,
                    ctx.port
                ))
                .build()
        );
    }
    Ok(L7Request { raw_header, ..req })
}

fn request_path(target: &str) -> &str {
    target.split('?').next().unwrap_or(target)
}

fn injection_configuration_failure() -> TokenGrantFailure {
    TokenGrantFailure::new(
        TokenGrantFailureKind::Configuration,
        TokenGrantStage::Injection,
    )
}

fn select_token_grants(
    mut candidates: Vec<(u32, String, ProviderProfileCredential)>,
) -> Result<Vec<(String, ProviderProfileCredential)>, TokenGrantInjectionError> {
    // Examine the strongest bindings first. The complete binding key stays with
    // its grant because the resolver uses it to separate cache entries and revisions.
    candidates.sort_unstable_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
    let mut selected = BTreeMap::<String, (u32, String, ProviderProfileCredential)>::new();
    for (score, key, credential) in candidates {
        let refused =
            || TokenGrantInjectionError::for_binding(injection_configuration_failure(), &key);
        let identity = credential_identity(&key).ok_or_else(refused)?;
        let header = token_grant_header_name(&credential)
            .map_err(|_| refused())?
            .to_ascii_lowercase();
        if let Some((selected_score, selected_key, _)) = selected.get(&header) {
            // Equal-specificity selectors of the same credential can overlap. A
            // different credential cannot win a tie for the same protected header.
            let selected_identity = credential_identity(selected_key);
            if score == *selected_score && Some(identity) != selected_identity {
                return Err(refused());
            }
            continue;
        }
        selected.insert(header, (score, key, credential));
    }
    Ok(selected
        .into_values()
        .map(|(_, key, cred)| (key, cred))
        .collect())
}

/// Collects token-grant credentials whose endpoint binding matches the request.
///
/// With `admitted_owners`, a credential is a candidate only when one of its
/// owners admitted the request. Filtering happens before specificity ranking, so
/// a narrower sibling cannot lend its grant to an allow from another endpoint.
fn token_grant_candidates(
    credentials: &HashMap<String, ProviderProfileCredential>,
    ctx: &L7EvalContext,
    request_path: &str,
    admitted_owners: Option<&HashSet<String>>,
) -> Result<Vec<(u32, String, ProviderProfileCredential)>, TokenGrantInjectionError> {
    credentials
        .iter()
        .filter_map(|(key, cred)| {
            if cred.token_grant.is_none()
                || admitted_owners.is_some_and(|owners| {
                    !cred
                        .token_grant_owners
                        .iter()
                        .any(|owner| owners.contains(owner))
                })
            {
                return None;
            }
            if endpoint_selector(key).is_none() {
                return Some(Err(TokenGrantInjectionError::for_binding(
                    injection_configuration_failure(),
                    key,
                )));
            }
            let score = dynamic_credential_key_match_score(key, &ctx.host, ctx.port, request_path)?;
            Some(Ok((score, key.clone(), cred.clone())))
        })
        .collect()
}

fn ocsf_message_field(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_control() { '_' } else { ch })
        .collect()
}

fn token_grant_request<'a>(
    provider_key: &'a str,
    token_grant: &'a ProviderCredentialTokenGrant,
    request_id: &'a str,
) -> Result<TokenGrantRequest<'a>, TokenGrantFailure> {
    let cache_ttl = token_grant
        .cache_ttl
        .as_ref()
        .map(openshell_core::time::duration_to_std)
        .transpose()
        .map_err(|_| {
            TokenGrantFailure::new(
                TokenGrantFailureKind::Configuration,
                TokenGrantStage::Configuration,
            )
        })?;
    Ok(TokenGrantRequest {
        provider_key,
        token_endpoint: &token_grant.token_endpoint,
        jwt_svid_audience: &token_grant.jwt_svid_audience,
        client_assertion_type: &token_grant.client_assertion_type,
        audience: &token_grant.audience,
        scopes: &token_grant.scopes,
        cache_ttl,
        grant_type: token_grant.grant_type,
        requested_token_type: &token_grant.requested_token_type,
        request_id,
    })
}

#[cfg(test)]
fn dynamic_credential_key_matches(key: &str, host: &str, port: u16, request_path: &str) -> bool {
    dynamic_credential_key_match_score(key, host, port, request_path).is_some()
}

fn dynamic_credential_key_match_score(
    key: &str,
    host: &str,
    port: u16,
    request_path: &str,
) -> Option<u32> {
    let selector = endpoint_selector(key)?;

    if selector.port.parse::<u16>().ok() != Some(port) {
        return None;
    }

    if !openshell_core::host_pattern::host_matches(selector.host, host).unwrap_or(false)
        || !crate::l7::endpoint_path_matches(selector.path, request_path)
    {
        return None;
    }

    Some(
        host_pattern_specificity(&selector.host.to_ascii_lowercase())
            + endpoint_path_specificity(selector.path),
    )
}

fn host_pattern_specificity(pattern: &str) -> u32 {
    let wildcard_penalty = count_as_u32(pattern.matches('*').count());
    let label_count = count_as_u32(pattern.split('.').filter(|label| !label.is_empty()).count());
    let literal_chars = count_as_u32(pattern.chars().filter(|ch| *ch != '*').count());
    100_000u32
        .saturating_sub(wildcard_penalty.saturating_mul(10_000))
        .saturating_add(label_count.saturating_mul(100))
        .saturating_add(literal_chars)
}

fn endpoint_path_specificity(path: &str) -> u32 {
    if path.is_empty() || path == "**" {
        return 0;
    }
    1_000_000u32.saturating_add(count_as_u32(path.chars().filter(|ch| *ch != '*').count()))
}

fn count_as_u32(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

#[cfg(test)]
fn inject_token_grant_header(
    raw_header: &[u8],
    credential: &ProviderProfileCredential,
    access_token: &str,
) -> Result<Vec<u8>, TokenGrantFailure> {
    crate::token_grant::validate_access_token(access_token)
        .map_err(|failure| failure.at_stage(TokenGrantStage::Injection))?;
    let (header_name, header_value) = token_grant_header(credential, access_token)?;
    inject_header(raw_header, &header_name, &header_value)
}

fn token_grant_header(
    credential: &ProviderProfileCredential,
    access_token: &str,
) -> Result<(String, String), TokenGrantFailure> {
    let header_name = token_grant_header_name(credential)?;
    let header_value = if credential.auth_style.trim().eq_ignore_ascii_case("header") {
        access_token.to_string()
    } else {
        format!("Bearer {access_token}")
    };
    Ok((header_name.to_string(), header_value))
}

fn token_grant_header_name(
    credential: &ProviderProfileCredential,
) -> Result<&str, TokenGrantFailure> {
    let header_name = match credential.auth_style.trim().to_ascii_lowercase().as_str() {
        "" | "bearer" => {
            if credential.header_name.trim().is_empty() {
                "Authorization"
            } else {
                credential.header_name.trim()
            }
        }
        // Header auth names its own header; there is no default to fall back to.
        "header" if !credential.header_name.trim().is_empty() => credential.header_name.trim(),
        _ => return Err(injection_configuration_failure()),
    };
    validate_header_name(header_name)?;
    Ok(header_name)
}

fn validate_header_name(header_name: &str) -> Result<(), TokenGrantFailure> {
    let valid = !header_name.is_empty()
        && header_name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        });
    // A grant may not override HTTP framing or connection headers.
    if !valid
        || matches!(
            header_name.to_ascii_lowercase().as_str(),
            "host" | "content-length" | "transfer-encoding" | "connection"
        )
    {
        return Err(injection_configuration_failure());
    }
    Ok(())
}

fn parse_header_block(raw_header: &[u8]) -> Result<(&str, usize), TokenGrantFailure> {
    let header_end = raw_header
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(injection_configuration_failure)?;
    let header_block = std::str::from_utf8(&raw_header[..header_end])
        .map_err(|_| injection_configuration_failure())?;
    if header_block.split("\r\n").next().is_none_or(str::is_empty) {
        return Err(injection_configuration_failure());
    }
    Ok((header_block, header_end))
}

fn inject_header(
    raw_header: &[u8],
    header_name: &str,
    header_value: &str,
) -> Result<Vec<u8>, TokenGrantFailure> {
    let (header_block, header_end) = parse_header_block(raw_header)?;
    let mut lines = header_block.split("\r\n");
    let request_line = lines.next().ok_or_else(injection_configuration_failure)?;

    let inserted_header = format!("{header_name}: {header_value}");
    let mut new_raw_header = Vec::with_capacity(raw_header.len() + inserted_header.len() + 2);
    new_raw_header.extend_from_slice(request_line.as_bytes());
    new_raw_header.extend_from_slice(b"\r\n");

    for line in lines {
        if line.is_empty() {
            break;
        }
        if line
            .split_once(':')
            .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case(header_name))
        {
            continue;
        }
        new_raw_header.extend_from_slice(line.as_bytes());
        new_raw_header.extend_from_slice(b"\r\n");
    }

    new_raw_header.extend_from_slice(inserted_header.as_bytes());
    new_raw_header.extend_from_slice(&raw_header[header_end..]);

    Ok(new_raw_header)
}

#[cfg(test)]
pub mod test_support {
    use super::*;
    use openshell_core::endpoint_status::EndpointObservationSender;
    use openshell_core::proto::{
        ProviderCredentialTokenGrant, ProviderCredentialTokenGrantSubjectToken,
        ProviderCredentialTokenGrantType, ProviderProfileCredential,
    };
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    type ScriptedResponse = Result<String, TokenGrantFailure>;

    struct FakeTokenGrantResolver {
        requests: Arc<Mutex<Vec<OwnedTokenGrantRequest>>>,
        responses: Arc<Mutex<HashMap<String, ScriptedResponse>>>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct OwnedTokenGrantRequest {
        provider_key: String,
        token_endpoint: String,
        jwt_svid_audience: String,
        client_assertion_type: String,
        audience: String,
        scopes: Vec<String>,
        cache_ttl: Option<std::time::Duration>,
        grant_type: i32,
        requested_token_type: String,
        request_id: String,
    }

    pub struct TokenGrantTestFixture {
        dynamic_credentials: Arc<std::sync::RwLock<HashMap<String, ProviderProfileCredential>>>,
        resolver: Arc<dyn TokenGrantResolver>,
        requests: Arc<Mutex<Vec<OwnedTokenGrantRequest>>>,
        responses: Arc<Mutex<HashMap<String, ScriptedResponse>>>,
        /// Revision-scoped key -> installed key, so assertions can name the key a
        /// test installed even when injection requests its scoped form.
        scoped_keys: Mutex<HashMap<String, String>>,
    }

    impl TokenGrantTestFixture {
        fn installed_key(&self, requested: &str) -> String {
            self.scoped_keys
                .lock()
                .unwrap()
                .get(requested)
                .map_or_else(|| requested.to_string(), Clone::clone)
        }

        pub fn success(key: &str, token: &str) -> Self {
            Self::new(key, Ok(token))
        }

        pub fn success_token_exchange(key: &str, token: &str) -> Self {
            Self::new_with_grant(key, Ok(token), token_exchange_grant())
        }

        pub fn failure(key: &str, failure: TokenGrantFailure) -> Self {
            Self::new(key, Err(failure))
        }

        pub fn failure_token_exchange(key: &str, failure: TokenGrantFailure) -> Self {
            Self::new_with_grant(key, Err(failure), token_exchange_grant())
        }

        fn new(key: &str, response: Result<&str, TokenGrantFailure>) -> Self {
            Self::new_with_grant(key, response, token_grant())
        }

        fn new_with_grant(
            key: &str,
            response: Result<&str, TokenGrantFailure>,
            token_grant: ProviderCredentialTokenGrant,
        ) -> Self {
            let requests = Arc::new(Mutex::new(Vec::new()));
            let responses = Arc::new(Mutex::new(HashMap::from([(
                key.to_string(),
                response.map(str::to_string),
            )])));
            let resolver = Arc::new(FakeTokenGrantResolver {
                requests: requests.clone(),
                responses: responses.clone(),
            });

            let mut dynamic_credentials = HashMap::new();
            dynamic_credentials.insert(
                key.to_string(),
                ProviderProfileCredential {
                    token_grant_owners: vec!["test-owner".to_string()],
                    name: "access_token".to_string(),
                    auth_style: "bearer".to_string(),
                    header_name: "Authorization".to_string(),
                    token_grant: Some(token_grant),
                    ..Default::default()
                },
            );

            Self {
                dynamic_credentials: Arc::new(std::sync::RwLock::new(dynamic_credentials)),
                resolver,
                requests,
                responses,
                scoped_keys: Mutex::new(HashMap::new()),
            }
        }

        pub fn add_credential(
            &self,
            key: &str,
            credential: ProviderProfileCredential,
            response: Result<&str, TokenGrantFailure>,
        ) {
            self.dynamic_credentials
                .write()
                .unwrap()
                .insert(key.to_string(), credential);
            self.responses
                .lock()
                .unwrap()
                .insert(key.to_string(), response.map(str::to_string));
        }

        /// Return the request IDs the resolver received, in acquisition order.
        pub fn requested_ids(&self) -> Vec<String> {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .map(|request| request.request_id.clone())
                .collect()
        }

        pub fn assert_requested_keys(&self, expected: &[&str]) {
            let requests = self.requests.lock().unwrap();
            assert_eq!(
                requests
                    .iter()
                    .map(|r| self.installed_key(&r.provider_key))
                    .collect::<Vec<_>>(),
                expected
            );
        }

        pub fn assert_request_configuration(
            &self,
            key: &str,
            grant: &ProviderCredentialTokenGrant,
        ) {
            let requests = self.requests.lock().unwrap();
            let request = requests
                .iter()
                .find(|r| self.installed_key(&r.provider_key) == key)
                .expect("grant was requested");
            assert_eq!(request.token_endpoint, grant.token_endpoint);
            assert_eq!(request.jwt_svid_audience, grant.jwt_svid_audience);
            assert_eq!(request.client_assertion_type, grant.client_assertion_type);
            assert_eq!(request.audience, grant.audience);
            assert_eq!(request.scopes, grant.scopes);
            assert_eq!(
                request.cache_ttl,
                grant
                    .cache_ttl
                    .as_ref()
                    .map(openshell_core::time::duration_to_std)
                    .transpose()
                    .unwrap()
            );
            assert_eq!(request.grant_type, grant.grant_type);
            assert_eq!(request.requested_token_type, grant.requested_token_type);
        }

        pub fn dynamic_credentials(
            &self,
        ) -> Arc<std::sync::RwLock<HashMap<String, ProviderProfileCredential>>> {
            self.dynamic_credentials.clone()
        }

        pub fn resolver(&self) -> Arc<dyn TokenGrantResolver> {
            self.resolver.clone()
        }

        /// Installs this fixture's credentials as a pinned provider-credential
        /// snapshot. Admission-gated injection requests grants by revision-scoped
        /// key, so each scripted response is also registered under that key.
        pub fn provider_credentials(&self) -> ProviderCredentialState {
            let credentials = self.dynamic_credentials.read().unwrap().clone();
            let state = ProviderCredentialState::from_environment(
                1,
                HashMap::new(),
                HashMap::new(),
                credentials.clone(),
            );
            let snapshot = state.snapshot();
            let mut responses = self.responses.lock().unwrap();
            for key in credentials.keys() {
                let scoped = snapshot.scoped_key(key);
                if let Some(response) = responses.get(key).cloned() {
                    responses.insert(scoped.clone(), response);
                }
                self.scoped_keys.lock().unwrap().insert(scoped, key.clone());
            }
            state
        }

        pub fn assert_no_requests(&self) {
            let requests = self
                .requests
                .lock()
                .expect("fake token grant requests lock poisoned");
            assert!(requests.is_empty(), "unexpected token grant requests");
        }

        pub fn assert_one_request(&self, expected_provider_key: &str) {
            let requests = self
                .requests
                .lock()
                .expect("fake token grant requests lock poisoned");
            assert_eq!(requests.len(), 1);

            let request = &requests[0];
            assert_eq!(
                self.installed_key(&request.provider_key),
                expected_provider_key
            );
            assert_eq!(request.token_endpoint, "https://auth.example.com/token");
            assert_eq!(request.jwt_svid_audience, "https://auth.example.com");
            assert_eq!(
                request.client_assertion_type,
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            );
            assert_eq!(request.audience, "api://example");
            assert_eq!(request.scopes, ["read"]);
            assert_eq!(request.cache_ttl, Some(std::time::Duration::from_mins(5)));
            assert_eq!(
                request.grant_type,
                ProviderCredentialTokenGrantType::ClientCredentials as i32
            );
            assert!(request.requested_token_type.is_empty());
        }

        pub fn assert_one_token_exchange_request(&self, expected_provider_key: &str) {
            let requests = self
                .requests
                .lock()
                .expect("fake token grant requests lock poisoned");
            assert_eq!(requests.len(), 1);

            let request = &requests[0];
            assert_eq!(
                self.installed_key(&request.provider_key),
                expected_provider_key
            );
            assert_eq!(request.token_endpoint, "https://auth.example.com/token");
            assert_eq!(request.jwt_svid_audience, "https://auth.example.com");
            assert_eq!(
                request.client_assertion_type,
                "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe"
            );
            assert_eq!(request.audience, "api://example");
            assert_eq!(request.scopes, ["read"]);
            assert_eq!(request.cache_ttl, Some(std::time::Duration::from_mins(5)));
            assert_eq!(
                request.grant_type,
                ProviderCredentialTokenGrantType::TokenExchange as i32
            );
            assert_eq!(
                request.requested_token_type,
                "urn:ietf:params:oauth:token-type:access_token"
            );
        }
    }

    fn token_grant() -> ProviderCredentialTokenGrant {
        ProviderCredentialTokenGrant {
            token_endpoint: "https://auth.example.com/token".to_string(),
            audience: "api://example".to_string(),
            jwt_svid_audience: "https://auth.example.com".to_string(),
            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                .to_string(),
            scopes: vec!["read".to_string()],
            cache_ttl: Some(prost_types::Duration {
                seconds: 300,
                nanos: 0,
            }),
            audience_overrides: Vec::new(),
            grant_type: ProviderCredentialTokenGrantType::ClientCredentials as i32,
            subject_token: None,
            requested_token_type: String::new(),
        }
    }

    fn token_exchange_grant() -> ProviderCredentialTokenGrant {
        ProviderCredentialTokenGrant {
            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe"
                .to_string(),
            grant_type: ProviderCredentialTokenGrantType::TokenExchange as i32,
            subject_token: Some(ProviderCredentialTokenGrantSubjectToken {
                source: "provider_credential".to_string(),
                credential: "user_oidc_token".to_string(),
                subject_token_type: "urn:ietf:params:oauth:token-type:id_token".to_string(),
            }),
            requested_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
            ..token_grant()
        }
    }

    impl TokenGrantResolver for FakeTokenGrantResolver {
        fn obtain<'a>(
            &'a self,
            request: TokenGrantRequest<'a>,
        ) -> Pin<Box<dyn Future<Output = Result<String, TokenGrantFailure>> + Send + 'a>> {
            let owned = OwnedTokenGrantRequest {
                provider_key: request.provider_key.to_string(),
                token_endpoint: request.token_endpoint.to_string(),
                jwt_svid_audience: request.jwt_svid_audience.to_string(),
                client_assertion_type: request.client_assertion_type.to_string(),
                audience: request.audience.to_string(),
                scopes: request.scopes.to_vec(),
                cache_ttl: request.cache_ttl,
                grant_type: request.grant_type,
                requested_token_type: request.requested_token_type.to_string(),
                request_id: request.request_id.to_string(),
            };
            Box::pin(async move {
                self.requests
                    .lock()
                    .expect("fake token grant requests lock poisoned")
                    .push(owned);
                // Keep acquisition pending once so joined request tests exercise
                // overlapping grants instead of completing each branch in one poll.
                tokio::task::yield_now().await;
                self.responses
                    .lock()
                    .unwrap()
                    .get(request.provider_key)
                    .expect("fake grant response configured")
                    .clone()
            })
        }
    }

    /// Pin a copy of `ctx` and inject selector-matched grants, as the
    /// fallback forwarding path does, capturing the context's own authority.
    pub async fn inject_if_needed(
        req: L7Request,
        ctx: &L7EvalContext,
        request_id: &str,
    ) -> Result<L7Request, TokenGrantInjectionError> {
        let observation_context = ctx
            .endpoint_observation_tx
            .as_ref()
            .and_then(EndpointObservationSender::capture);
        let mut pinned = ctx.clone();
        let Some(snapshot) = pin_live_credentials(&mut pinned) else {
            return Ok(req);
        };
        inject_for_selectors(
            req,
            &pinned,
            &snapshot,
            request_id,
            observation_context.as_ref(),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l7::provider::{BodyLength, L7Request};
    use crate::l7::token_grant_injection::test_support::{TokenGrantTestFixture, inject_if_needed};
    use openshell_core::endpoint_status::{
        EndpointConfigVersion, EndpointObservationSender, EndpointStatusReceiver,
        EndpointStatusTracker, endpoint_status_channel,
    };

    const REQUEST_ID: &str = "6a1f0e2d-3c4b-4a59-8e7f-0123456789ab";

    fn credential(auth_style: &str, header_name: &str) -> ProviderProfileCredential {
        ProviderProfileCredential {
            auth_style: auth_style.to_string(),
            header_name: header_name.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn dynamic_credential_key_matches_endpoint_host_port_and_path() {
        let key = "api.example.com\t443\t/repos/**\tgithub:access_token";

        assert!(dynamic_credential_key_matches(
            key,
            "api.example.com",
            443,
            "/repos/owner/repo"
        ));
        assert!(dynamic_credential_key_matches(
            "api.example.com\t443\t/repos/**\trev:42\tgithub:access_token",
            "api.example.com",
            443,
            "/repos/owner/repo"
        ));
        assert!(!dynamic_credential_key_matches(
            key,
            "uploads.example.com",
            443,
            "/repos/owner/repo"
        ));
        assert!(!dynamic_credential_key_matches(
            key,
            "api.example.com",
            80,
            "/repos/owner/repo"
        ));
        assert!(!dynamic_credential_key_matches(
            key,
            "api.example.com",
            443,
            "/orgs/owner"
        ));
    }

    #[test]
    fn dynamic_credential_key_matches_wildcard_hosts_and_empty_path() {
        let key = "*.example.com\t443\t\tprovider:access_token";

        assert!(dynamic_credential_key_matches(
            key,
            "api.example.com",
            443,
            "/anything"
        ));
        assert!(!dynamic_credential_key_matches(
            key,
            "api.other.com",
            443,
            "/anything"
        ));
        assert!(!dynamic_credential_key_matches(
            key,
            "nested.api.example.com",
            443,
            "/anything"
        ));
    }

    #[test]
    fn dynamic_credential_key_matches_case_insensitive_intra_label_wildcard() {
        let key = "*-API.Example.COM\t443\t\tprovider:access_token";

        assert!(dynamic_credential_key_matches(
            key,
            "tenant-api.example.com",
            443,
            "/anything"
        ));
        assert!(!dynamic_credential_key_matches(
            key,
            "api.deep.example.com",
            443,
            "/anything"
        ));
    }

    #[test]
    fn dynamic_credential_key_matches_double_wildcard_hosts() {
        let key = "**.example.com\t443\t\tprovider:access_token";

        assert!(dynamic_credential_key_matches(
            key,
            "api.example.com",
            443,
            "/anything"
        ));
        assert!(dynamic_credential_key_matches(
            key,
            "nested.api.example.com",
            443,
            "/anything"
        ));
    }

    #[test]
    fn dynamic_credential_match_score_prefers_path_specific_key() {
        let default_key = "alpha.default.svc.cluster.local\t80\t\tprovider:access_token";
        let path_key = "alpha.default.svc.cluster.local\t80\t/admin/**\tprovider:access_token";
        let request_path = "/admin/users";

        let default_score = dynamic_credential_key_match_score(
            default_key,
            "alpha.default.svc.cluster.local",
            80,
            request_path,
        )
        .expect("default key should match");
        let path_score = dynamic_credential_key_match_score(
            path_key,
            "alpha.default.svc.cluster.local",
            80,
            request_path,
        )
        .expect("path key should match");

        assert!(path_score > default_score);
    }

    #[test]
    fn inject_token_grant_header_replaces_existing_authorization() {
        let raw = b"GET /v1 HTTP/1.1\r\nHost: api.example.com\r\nauthorization: Bearer stale-token\r\nAccept: application/json\r\n\r\n";

        let rewritten =
            inject_token_grant_header(raw, &credential("bearer", "Authorization"), "grant-token")
                .expect("header should rewrite");
        let rewritten = String::from_utf8(rewritten).expect("rewritten header should be UTF-8");

        assert!(rewritten.contains("Authorization: Bearer grant-token\r\n"));
        assert!(!rewritten.contains("stale-token"));
        assert_eq!(
            rewritten
                .lines()
                .filter(|line| line
                    .split_once(':')
                    .is_some_and(|(name, _)| name.eq_ignore_ascii_case("authorization")))
                .count(),
            1
        );
    }

    #[test]
    fn inject_token_grant_header_replaces_existing_authorization_with_ows_before_colon() {
        let raw = b"GET /v1 HTTP/1.1\r\nHost: api.example.com\r\nAuthorization : Bearer stale-token\r\nAccept: application/json\r\n\r\n";

        let rewritten =
            inject_token_grant_header(raw, &credential("bearer", "Authorization"), "grant-token")
                .expect("header should rewrite");
        let rewritten = String::from_utf8(rewritten).expect("rewritten header should be UTF-8");

        assert!(rewritten.contains("Authorization: Bearer grant-token\r\n"));
        assert!(!rewritten.contains("stale-token"));
        assert_eq!(
            rewritten
                .lines()
                .filter(|line| line
                    .split_once(':')
                    .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case("authorization")))
                .count(),
            1
        );
    }

    #[test]
    fn token_grant_header_rejects_framing_and_connection_headers() {
        for header_name in ["Host", "Content-Length", "Transfer-Encoding", "Connection"] {
            let err = token_grant_header(&credential("header", header_name), "grant-token")
                .expect_err("framing header override should be rejected");
            assert_eq!(err, injection_configuration_failure());
        }
    }

    #[test]
    fn inject_token_grant_header_preserves_header_terminator_before_body() {
        let raw = b"POST /v1 HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 2\r\n\r\nOK";

        let rewritten = inject_token_grant_header(raw, &credential("bearer", ""), "grant-token")
            .expect("header should rewrite");

        assert_eq!(
            rewritten,
            b"POST /v1 HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 2\r\nAuthorization: Bearer grant-token\r\n\r\nOK"
        );
    }

    #[test]
    fn inject_token_grant_header_uses_custom_header_style() {
        let raw = b"GET /v1 HTTP/1.1\r\nHost: api.example.com\r\nX-Api-Token: stale-token\r\n\r\n";

        let rewritten =
            inject_token_grant_header(raw, &credential("header", "X-Api-Token"), "grant-token")
                .expect("header should rewrite");
        let rewritten = String::from_utf8(rewritten).expect("rewritten header should be UTF-8");

        assert!(rewritten.contains("X-Api-Token: grant-token\r\n"));
        assert!(!rewritten.contains("stale-token"));
        assert!(!rewritten.contains("Bearer grant-token"));
    }

    #[test]
    fn inject_token_grant_header_rejects_malformed_access_token() {
        let raw = b"GET /v1 HTTP/1.1\r\nHost: api.example.com\r\n\r\n";

        let err = inject_token_grant_header(
            raw,
            &credential("bearer", "Authorization"),
            "grant-token\r\nX-Injected: yes",
        )
        .expect_err("malformed token must not be injected");

        assert_eq!(err.stage(), TokenGrantStage::Injection);
    }

    #[tokio::test]
    async fn inject_if_needed_uses_configured_resolver() {
        let fixture = TokenGrantTestFixture::success(
            "api.example.com\t443\t/v1/**\tprovider:access_token",
            "grant-token",
        );

        let ctx = L7EvalContext {
            host: "api.example.com".into(),
            port: 443,
            policy_name: "api".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            provider_credentials: Some(fixture.provider_credentials()),
            token_grant_resolver: Some(fixture.resolver()),
            ..Default::default()
        };
        let req = L7Request {
            action: "GET".to_string(),
            target: "/v1/projects".to_string(),
            query_params: HashMap::new(),
            raw_header: b"GET /v1/projects HTTP/1.1\r\nHost: api.example.com\r\n\r\n".to_vec(),
            body_length: BodyLength::None,
        };

        let rewritten = inject_if_needed(req, &ctx, REQUEST_ID)
            .await
            .expect("fake token grant should inject");
        let rewritten =
            String::from_utf8(rewritten.raw_header).expect("rewritten request should be UTF-8");

        assert!(rewritten.contains("Authorization: Bearer grant-token\r\n"));
        fixture.assert_one_request("api.example.com\t443\t/v1/**\tprovider:access_token");
        assert_eq!(fixture.requested_ids(), [REQUEST_ID]);
    }

    #[tokio::test]
    async fn inject_if_needed_passes_token_exchange_grant_to_resolver() {
        let fixture = TokenGrantTestFixture::success_token_exchange(
            "api.example.com\t443\t/v1/**\tprovider:access_token",
            "grant-token",
        );

        let ctx = L7EvalContext {
            host: "api.example.com".into(),
            port: 443,
            policy_name: "api".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            activity_tx: None,
            provider_credentials: Some(fixture.provider_credentials()),
            token_grant_resolver: Some(fixture.resolver()),
            ..Default::default()
        };
        let req = L7Request {
            action: "GET".to_string(),
            target: "/v1/projects".to_string(),
            query_params: HashMap::new(),
            raw_header: b"GET /v1/projects HTTP/1.1\r\nHost: api.example.com\r\n\r\n".to_vec(),
            body_length: BodyLength::None,
        };

        let rewritten = inject_if_needed(req, &ctx, REQUEST_ID)
            .await
            .expect("fake token exchange grant should inject");
        let rewritten =
            String::from_utf8(rewritten.raw_header).expect("rewritten request should be UTF-8");

        assert!(rewritten.contains("Authorization: Bearer grant-token\r\n"));
        fixture.assert_one_token_exchange_request(
            "api.example.com\t443\t/v1/**\tprovider:access_token",
        );
    }

    #[tokio::test]
    async fn inject_if_needed_rejects_malformed_resolver_token() {
        let fixture = TokenGrantTestFixture::success(
            "api.example.com\t443\t/v1/**\tprovider:access_token",
            "grant-token\r\nX-Injected: yes",
        );

        let ctx = L7EvalContext {
            host: "api.example.com".into(),
            port: 443,
            policy_name: "api".into(),
            binary_path: "/usr/bin/curl".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            provider_credentials: Some(fixture.provider_credentials()),
            token_grant_resolver: Some(fixture.resolver()),
            ..Default::default()
        };
        let req = L7Request {
            action: "GET".to_string(),
            target: "/v1/projects".to_string(),
            query_params: HashMap::new(),
            raw_header: b"GET /v1/projects HTTP/1.1\r\nHost: api.example.com\r\n\r\n".to_vec(),
            body_length: BodyLength::None,
        };

        let err = inject_if_needed(req, &ctx, REQUEST_ID)
            .await
            .expect_err("malformed resolver token should fail closed");

        assert_eq!(err.failure().stage(), TokenGrantStage::Injection);
        assert_eq!(err.credential(), Some(("provider", "access_token")));
        fixture.assert_one_request("api.example.com\t443\t/v1/**\tprovider:access_token");
    }

    const KEY: &str = "api.example.com\t443\t/v1/**\tprovider:access_token";

    fn refusal() -> TokenGrantFailure {
        TokenGrantFailure::new(
            TokenGrantFailureKind::ProviderAuthorizationRequired,
            TokenGrantStage::TokenEndpoint,
        )
    }

    fn grant_context(fixture: &TokenGrantTestFixture) -> L7EvalContext {
        L7EvalContext {
            host: "api.example.com".into(),
            port: 443,
            provider_credentials: Some(fixture.provider_credentials()),
            token_grant_resolver: Some(fixture.resolver()),
            ..Default::default()
        }
    }

    fn grant_request() -> L7Request {
        L7Request {
            action: "GET".to_string(),
            target: "/v1/projects".to_string(),
            query_params: HashMap::new(),
            raw_header: b"GET /v1/projects HTTP/1.1\r\nHost: api.example.com\r\n\r\n".to_vec(),
            body_length: BodyLength::None,
        }
    }

    async fn installed_status(
        revision: u64,
    ) -> (
        EndpointObservationSender,
        EndpointStatusReceiver,
        EndpointStatusTracker,
        EndpointObservationContext,
    ) {
        let (sender, mut receiver) = endpoint_status_channel();
        let mut tracker = receiver.tracker();
        reset_status(&sender, revision).await;
        assert!(tracker.apply(receiver.try_recv().unwrap()));
        let authority = sender.capture().unwrap();
        (sender, receiver, tracker, authority)
    }

    async fn reset_status(sender: &EndpointObservationSender, revision: u64) {
        let version = EndpointConfigVersion {
            policy_hash: "policy".into(),
            provider_env_revision: revision,
        };
        sender.reset(version, Vec::new()).await.unwrap();
    }

    /// Apply the next status command and return the recorded grant failure.
    fn next_grant_failure(
        tracker: &mut EndpointStatusTracker,
        receiver: &mut EndpointStatusReceiver,
    ) -> Option<openshell_core::proto::TokenGrantFailureObservation> {
        assert!(tracker.apply(receiver.try_recv().expect("status command sent")));
        tracker.snapshot().unwrap().last_token_grant_failure
    }

    #[tokio::test]
    async fn missing_resolver_refuses_without_naming_a_credential() {
        let fixture = TokenGrantTestFixture::success(KEY, "grant-token");
        let (sender, mut receiver, mut tracker, _) = installed_status(1).await;
        let mut ctx = grant_context(&fixture);
        ctx.token_grant_resolver = None;
        ctx.endpoint_observation_tx = Some(sender);

        let err = inject_if_needed(grant_request(), &ctx, REQUEST_ID)
            .await
            .expect_err("a grant without a resolver refuses the request");

        assert_eq!(err.credential(), None);
        fixture.assert_no_requests();
        let failure = next_grant_failure(&mut tracker, &mut receiver)
            .unwrap()
            .failure
            .unwrap();
        assert_eq!(failure.code, injection_configuration_failure().code());
        assert_eq!(failure.request_id, REQUEST_ID);
        assert!(failure.provider.is_empty());
    }

    async fn inject_pinned(
        ctx: &mut L7EvalContext,
        authority: &EndpointObservationContext,
    ) -> Result<L7Request, TokenGrantInjectionError> {
        let snapshot = pin_live_credentials(ctx).expect("live provider credentials");
        inject_for_selectors(grant_request(), ctx, &snapshot, REQUEST_ID, Some(authority)).await
    }

    #[tokio::test]
    async fn fallback_reports_live_credential_refusal() {
        const CURRENT_KEY: &str = "api.example.com\t443\t/v1/**\tcurrent-provider:access_token";
        let fixture = TokenGrantTestFixture::failure(CURRENT_KEY, refusal());
        let mut ctx = grant_context(&fixture);
        let snapshot = ctx.provider_credentials.as_ref().unwrap().snapshot();
        let (sender, mut receiver, mut tracker, authority) =
            installed_status(snapshot.revision).await;
        ctx.endpoint_observation_tx = Some(sender);

        let error = inject_pinned(&mut ctx, &authority)
            .await
            .expect_err("the live credential refuses");

        assert_eq!(
            error.credential(),
            Some(("current-provider", "access_token"))
        );
        assert_eq!(ctx.provider_credential_revision, Some(snapshot.revision));
        fixture.assert_requested_keys(&[CURRENT_KEY]);
        let cause = next_grant_failure(&mut tracker, &mut receiver)
            .expect("live refusal is reported")
            .failure
            .unwrap();
        assert_eq!(cause.provider, "current-provider");
        assert_eq!(cause.credential_key, "access_token");
        assert_eq!(cause.request_id, REQUEST_ID);
    }

    #[tokio::test]
    async fn fallback_live_credential_success_clears_its_failure() {
        const CURRENT_KEY: &str = "api.example.com\t443\t/v1/projects\tprovider:access_token";
        let fixture = TokenGrantTestFixture::failure(CURRENT_KEY, refusal());
        let mut ctx = grant_context(&fixture);
        let snapshot = ctx.provider_credentials.as_ref().unwrap().snapshot();
        let (sender, mut receiver, mut tracker, authority) =
            installed_status(snapshot.revision).await;
        ctx.endpoint_observation_tx = Some(sender);

        inject_pinned(&mut ctx, &authority)
            .await
            .expect_err("current grant first records its failure");
        assert!(next_grant_failure(&mut tracker, &mut receiver).is_some());

        fixture.add_credential(
            &snapshot.scoped_key(CURRENT_KEY),
            snapshot.dynamic_credentials[CURRENT_KEY].clone(),
            Ok("current-token"),
        );
        let injected = inject_pinned(&mut ctx, &authority)
            .await
            .expect("the live credential now succeeds");
        assert!(
            String::from_utf8(injected.raw_header)
                .unwrap()
                .contains("Authorization: Bearer current-token\r\n")
        );
        assert!(next_grant_failure(&mut tracker, &mut receiver).is_none());
    }

    #[tokio::test]
    async fn fallback_rejects_telemetry_authority_captured_before_provider_refresh() {
        let fixture = TokenGrantTestFixture::failure(KEY, refusal());
        let mut ctx = grant_context(&fixture);
        let (sender, mut receiver, _, stale_authority) = installed_status(0).await;
        reset_status(&sender, 1).await;
        receiver.try_recv().unwrap();
        ctx.endpoint_observation_tx = Some(sender);

        inject_pinned(&mut ctx, &stale_authority)
            .await
            .expect_err("the live grant still fails closed under old reporting authority");

        fixture.assert_requested_keys(&[KEY]);
        assert!(receiver.try_recv().is_err(), "stale observation is dropped");
    }
}
