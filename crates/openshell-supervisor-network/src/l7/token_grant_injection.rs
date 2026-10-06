// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Endpoint-bound dynamic token grant injection for HTTP relay paths.

#[cfg(test)]
mod multiple_grants;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use miette::{Result, miette};
use openshell_core::dynamic_credential_key::{credential_identity, endpoint_selector};
use openshell_core::proto::{ProviderCredentialTokenGrant, ProviderProfileCredential};
use openshell_core::provider_credentials::ProviderCredentialSnapshot;
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, Endpoint, HttpActivityBuilder, HttpRequest, SeverityId,
    StatusId, Url as OcsfUrl, ctx::ctx as ocsf_ctx, ocsf_emit,
};
use tracing::warn;

use crate::l7::provider::L7Request;
use crate::l7::relay::L7EvalContext;

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
}

pub trait TokenGrantResolver: Send + Sync {
    fn obtain<'a>(
        &'a self,
        request: TokenGrantRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<String>> + Send + 'a>>;
}

#[derive(Default)]
pub struct SpiffeTokenGrantResolver;

impl TokenGrantResolver for SpiffeTokenGrantResolver {
    fn obtain<'a>(
        &'a self,
        request: TokenGrantRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<String>> + Send + 'a>> {
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
                },
            )
            .await
        })
    }
}

pub fn default_resolver() -> Arc<dyn TokenGrantResolver> {
    Arc::new(SpiffeTokenGrantResolver)
}

/// Resolves one endpoint-bound grant per protected header before rewriting a request.
///
/// Each header independently uses its most-specific matching binding. Every selected
/// grant must succeed; callers must not forward the request when this returns an error.
pub async fn inject_if_needed(req: L7Request, ctx: &L7EvalContext) -> Result<L7Request> {
    let request_path = req.target.split('?').next().unwrap_or(req.target.as_str());
    let credentials = match ctx.dynamic_credentials.as_ref() {
        Some(dynamic_credentials) => {
            let credentials = dynamic_credentials
                .read()
                .map_err(|_| miette!("dynamic credential snapshot unavailable"))?;
            select_token_grants(token_grant_candidates(
                &credentials,
                ctx,
                request_path,
                None,
            ))?
        }
        None => Vec::new(),
    };
    inject_selected(req, ctx, credentials).await
}

/// Inject only grants owned by endpoints that admitted the inspected request.
/// An empty owner set permits no acquisition, including audit-only forwarding.
/// L4-only forwarding continues to use `inject_if_needed` with its existing
/// endpoint-selector contract; it has no per-request L7 admission decision.
///
/// Credentials come from the pinned `snapshot`, and each selected key is scoped
/// to its revision and installation after selection so the one-grant-per-header
/// ambiguity check still compares the original credential identities.
pub(super) async fn inject_for_admitted_owners(
    req: L7Request,
    ctx: &L7EvalContext,
    snapshot: &ProviderCredentialSnapshot,
    admitted_owners: &HashSet<String>,
) -> Result<L7Request> {
    let request_path = req.target.split('?').next().unwrap_or(req.target.as_str());
    if snapshot
        .dynamic_credentials
        .iter()
        .any(|(key, credential)| {
            credential.token_grant.is_some()
                && credential.token_grant_owners.is_empty()
                && dynamic_credential_key_match_score(key, &ctx.host, ctx.port, request_path)
                    .is_some()
        })
    {
        return Err(miette!(
            "dynamic token grant is missing endpoint ownership metadata; upgrade the gateway before the supervisor"
        ));
    }
    let candidates = token_grant_candidates(
        &snapshot.dynamic_credentials,
        ctx,
        request_path,
        Some(admitted_owners),
    );
    let credentials = select_token_grants(candidates)?
        .into_iter()
        .map(|(key, cred)| (snapshot.scoped_key(&key), cred))
        .collect();
    inject_selected(req, ctx, credentials).await
}

/// Acquires every selected grant and rewrites the request headers.
///
/// An empty selection forwards the request unchanged. Any failed acquisition
/// returns an error before any header is written.
async fn inject_selected(
    req: L7Request,
    ctx: &L7EvalContext,
    credentials: Vec<(String, ProviderProfileCredential)>,
) -> Result<L7Request> {
    let request_path = req.target.split('?').next().unwrap_or(req.target.as_str());
    if credentials.is_empty() {
        return Ok(req);
    }
    let resolver = ctx
        .token_grant_resolver
        .as_ref()
        .ok_or_else(|| miette!("token grant resolver unavailable"))?;

    // Release the credential snapshot lock before acquisition. Keep all token values
    // local until every selected grant and header has been validated, so a later
    // failure cannot expose a partially authenticated request to a relay caller.
    let mut headers = Vec::with_capacity(credentials.len());
    for (provider_key, cred) in &credentials {
        let token_grant = cred
            .token_grant
            .as_ref()
            .ok_or_else(|| miette!("selected credential has no token grant"))?;
        let request = token_grant_request(provider_key, token_grant)?;
        if let Ok(access_token) = resolver.obtain(request).await {
            crate::token_grant::validate_access_token(&access_token)?;
            headers.push(token_grant_header(cred, &access_token)?);
        } else {
            // An issuer may echo credentials in its error description. Only the
            // binding identity is safe to include in diagnostics or relay errors.
            let provider_key = ocsf_message_field(provider_key);
            warn!(
                host = %ctx.host,
                port = ctx.port,
                provider = %provider_key,
                "Token grant failed"
            );
            ocsf_emit!(
                HttpActivityBuilder::new(ocsf_ctx())
                    .activity(ActivityId::Fail)
                    .action(ActionId::Denied)
                    .disposition(DispositionId::Blocked)
                    .severity(SeverityId::Medium)
                    .status(StatusId::Failure)
                    .http_request(HttpRequest::new(
                        &req.action,
                        OcsfUrl::new("http", &ctx.host, request_path, ctx.port),
                    ))
                    .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                    .message(format!(
                        "Token grant failed for {} to {}:{}",
                        provider_key, ctx.host, ctx.port
                    ))
                    .build()
            );
            return Err(miette!("Token grant failed"));
        }
    }

    let mut raw_header = req.raw_header;
    for (name, value) in headers {
        raw_header = inject_header(&raw_header, &name, &value)?;
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
                    OcsfUrl::new("http", &ctx.host, request_path, ctx.port),
                ))
                .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                .message(format!(
                    "Token grant successful for {} to {}:{}",
                    ocsf_message_field(&provider_key),
                    ctx.host,
                    ctx.port
                ))
                .build()
        );
    }
    Ok(L7Request { raw_header, ..req })
}

fn select_token_grants(
    mut candidates: Vec<(u32, String, ProviderProfileCredential)>,
) -> Result<Vec<(String, ProviderProfileCredential)>> {
    // Examine the strongest bindings first. The complete binding key stays with
    // its grant because the resolver uses it to separate cache entries and revisions.
    candidates.sort_unstable_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
    let mut selected = BTreeMap::<String, (u32, String, ProviderProfileCredential)>::new();
    for (score, key, credential) in candidates {
        let header = token_grant_header_name(&credential)?.to_ascii_lowercase();
        if let Some((selected_score, selected_key, _)) = selected.get(&header) {
            // Equal-specificity selectors of the same credential can overlap. A
            // different credential cannot win a tie for the same protected header.
            if score == *selected_score
                && credential_identity(&key) != credential_identity(selected_key)
            {
                return Err(miette!("ambiguous dynamic token grants for one header"));
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
) -> Vec<(u32, String, ProviderProfileCredential)> {
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
            let score = dynamic_credential_key_match_score(key, &ctx.host, ctx.port, request_path)?;
            Some((score, key.clone(), cred.clone()))
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
) -> Result<TokenGrantRequest<'a>> {
    let cache_ttl = token_grant
        .cache_ttl
        .as_ref()
        .map(openshell_core::time::duration_to_std)
        .transpose()
        .map_err(|error| miette!("invalid token grant cache_ttl: {error}"))?;
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
) -> Result<Vec<u8>> {
    crate::token_grant::validate_access_token(access_token)?;
    let (header_name, header_value) = token_grant_header(credential, access_token)?;
    inject_header(raw_header, &header_name, &header_value)
}

fn token_grant_header(
    credential: &ProviderProfileCredential,
    access_token: &str,
) -> Result<(String, String)> {
    let header_name = token_grant_header_name(credential)?;
    let header_value = if credential.auth_style.trim().eq_ignore_ascii_case("header") {
        access_token.to_string()
    } else {
        format!("Bearer {access_token}")
    };
    Ok((header_name.to_string(), header_value))
}

fn token_grant_header_name(credential: &ProviderProfileCredential) -> Result<&str> {
    match credential.auth_style.trim().to_ascii_lowercase().as_str() {
        "" | "bearer" => {
            let header_name = if credential.header_name.trim().is_empty() {
                "Authorization"
            } else {
                credential.header_name.trim()
            };
            validate_header_name(header_name)?;
            Ok(header_name)
        }
        "header" => {
            let header_name = credential.header_name.trim();
            if header_name.is_empty() {
                return Err(miette!(
                    "token grant auth_style header requires header_name"
                ));
            }
            validate_header_name(header_name)?;
            Ok(header_name)
        }
        other => Err(miette!(
            "token grant auth_style '{other}' is not supported; use bearer or header"
        )),
    }
}

fn validate_header_name(header_name: &str) -> Result<()> {
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
    if !valid {
        return Err(miette!(
            "token grant header_name is not a valid HTTP header name"
        ));
    }
    match header_name.to_ascii_lowercase().as_str() {
        "host" | "content-length" | "transfer-encoding" | "connection" => Err(miette!(
            "token grant header_name may not override HTTP framing or connection headers"
        )),
        _ => Ok(()),
    }
}

fn inject_header(raw_header: &[u8], header_name: &str, header_value: &str) -> Result<Vec<u8>> {
    let header_end = raw_header
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| miette!("HTTP headers missing final CRLF CRLF"))?;

    let header_block = std::str::from_utf8(&raw_header[..header_end])
        .map_err(|_| miette!("HTTP headers contain invalid UTF-8"))?;
    let mut lines = header_block.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| miette!("HTTP headers missing request line"))?;

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
    use openshell_core::proto::{
        ProviderCredentialTokenGrant, ProviderCredentialTokenGrantSubjectToken,
        ProviderCredentialTokenGrantType, ProviderProfileCredential,
    };
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    struct FakeTokenGrantResolver {
        requests: Arc<Mutex<Vec<OwnedTokenGrantRequest>>>,
        responses: Arc<Mutex<HashMap<String, std::result::Result<String, String>>>>,
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
    }

    pub struct TokenGrantTestFixture {
        dynamic_credentials: Arc<std::sync::RwLock<HashMap<String, ProviderProfileCredential>>>,
        resolver: Arc<dyn TokenGrantResolver>,
        requests: Arc<Mutex<Vec<OwnedTokenGrantRequest>>>,
        responses: Arc<Mutex<HashMap<String, std::result::Result<String, String>>>>,
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

        pub fn failure(key: &str, error: &str) -> Self {
            Self::new(key, Err(error))
        }

        pub fn failure_token_exchange(key: &str, error: &str) -> Self {
            Self::new_with_grant(key, Err(error), token_exchange_grant())
        }

        fn new(key: &str, response: std::result::Result<&str, &str>) -> Self {
            Self::new_with_grant(key, response, token_grant())
        }

        fn new_with_grant(
            key: &str,
            response: std::result::Result<&str, &str>,
            token_grant: ProviderCredentialTokenGrant,
        ) -> Self {
            let requests = Arc::new(Mutex::new(Vec::new()));
            let responses = Arc::new(Mutex::new(HashMap::from([(
                key.to_string(),
                response.map(str::to_string).map_err(str::to_string),
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
            response: std::result::Result<&str, &str>,
        ) {
            self.dynamic_credentials
                .write()
                .unwrap()
                .insert(key.to_string(), credential);
            self.responses.lock().unwrap().insert(
                key.to_string(),
                response.map(str::to_string).map_err(str::to_string),
            );
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
        pub fn provider_credentials(
            &self,
        ) -> openshell_core::provider_credentials::ProviderCredentialState {
            let credentials = self.dynamic_credentials.read().unwrap().clone();
            let state =
                openshell_core::provider_credentials::ProviderCredentialState::from_environment(
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
        ) -> Pin<Box<dyn Future<Output = Result<String>> + Send + 'a>> {
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
                    .map_err(|err| miette!("{err}"))
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l7::provider::{BodyLength, L7Request};
    use crate::l7::token_grant_injection::test_support::TokenGrantTestFixture;

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
            assert_eq!(
                err.to_string(),
                "token grant header_name may not override HTTP framing or connection headers"
            );
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

        assert_eq!(
            err.to_string(),
            "token grant returned a malformed access token"
        );
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
            dynamic_credentials: Some(fixture.dynamic_credentials()),
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

        let rewritten = inject_if_needed(req, &ctx)
            .await
            .expect("fake token grant should inject");
        let rewritten =
            String::from_utf8(rewritten.raw_header).expect("rewritten request should be UTF-8");

        assert!(rewritten.contains("Authorization: Bearer grant-token\r\n"));
        fixture.assert_one_request("api.example.com\t443\t/v1/**\tprovider:access_token");
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
            dynamic_credentials: Some(fixture.dynamic_credentials()),
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

        let rewritten = inject_if_needed(req, &ctx)
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
            dynamic_credentials: Some(fixture.dynamic_credentials()),
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

        let err = inject_if_needed(req, &ctx)
            .await
            .expect_err("malformed resolver token should fail closed");

        assert_eq!(
            err.to_string(),
            "token grant returned a malformed access token"
        );
        fixture.assert_one_request("api.example.com\t443\t/v1/**\tprovider:access_token");
    }
}
