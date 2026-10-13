// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OAuth2` JWT client assertion token grant using SPIFFE JWT-SVID.
//!
//! When a provider profile includes a `token_grant` configuration, the
//! supervisor obtains `OAuth2` access tokens on-demand by authenticating to the
//! token service using the sandbox's SPIFFE JWT-SVID as the client assertion.
//!
//! ## Flow
//!
//! 1. HTTP proxy intercepts outbound request to provider endpoint
//! 2. Check token cache for unexpired access token
//! 3. On cache miss or expiry:
//!    a. Fetch JWT-SVID from SPIRE agent (via Workload API)
//!    b. POST to token service with JWT client assertion grant
//!    c. Cache the returned access token with TTL
//! 4. Inject `Authorization: Bearer <access_token>` header
//!
//! ## Configuration
//!
//! Token grant parameters come from the provider profile `token_grant` field:
//! - `token_endpoint` — `OAuth2` token service URL
//! - `jwt_svid_audience` — SPIRE JWT-SVID audience override (optional)
//! - `client_assertion_type` — `OAuth2` client assertion type (optional)
//! - `audience` — Resource audience to request from the token service
//! - `scopes` — `OAuth2` scopes to request (optional)
//! - `cache_ttl` — Optional exact cache override; zero disables caching
//!
//! ## Environment
//!
//! Requires `OPENSHELL_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET` to be set (path to
//! the SPIFFE Workload API socket).

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openshell_core::oauth::{
    self, ACCESS_TOKEN_TYPE, OAuthTokenResponse, TokenExchangeParams, TokenGrantClient,
    TokenGrantParams, effective_client_assertion_type, effective_token_type,
};
use openshell_core::proto::ProviderCredentialTokenGrantType;
use openshell_core::sandbox_env;
use openshell_core::token_grant_failure::{
    TokenGrantFailure, TokenGrantFailureKind, TokenGrantStage,
};
use spiffe::{WorkloadApiClient, WorkloadApiError};

/// Token cache shared across all provider token grants.
static TOKEN_CACHE: LazyLock<TokenCache> = LazyLock::new(TokenCache::new);
// Initialization failures stay bounded and typed; credential acquisition must not panic.
static TOKEN_GRANT_HTTP_CLIENT: LazyLock<Result<TokenGrantClient, TokenGrantFailure>> =
    LazyLock::new(TokenGrantClient::new);
const DEFAULT_TOKEN_CACHE_TTL_SECONDS: i64 = 300;
const TOKEN_CACHE_EXPIRY_SKEW_SECONDS: i64 = 30;
const MAX_TOKEN_EXPIRES_IN_SECONDS: i64 = 3600;

/// Cached access token with expiration metadata.
#[derive(Clone)]
struct CachedToken {
    access_token: String,
    expires_at_ms: i64,
}

/// Thread-safe token cache keyed by provider name.
struct TokenCache {
    tokens: Arc<RwLock<HashMap<String, CachedToken>>>,
}

impl TokenCache {
    fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get a cached token if it exists and is not expired.
    fn get(&self, provider_name: &str) -> Option<String> {
        let now_ms = current_time_ms();
        let tokens = self.tokens.read().ok()?;
        let cached = tokens.get(provider_name)?;
        if cached.expires_at_ms > now_ms {
            Some(cached.access_token.clone())
        } else {
            None
        }
    }

    /// Store a token with expiration time.
    fn set(&self, provider_name: String, access_token: String, expires_at_ms: i64) {
        if let Ok(mut tokens) = self.tokens.write() {
            tokens.insert(
                provider_name,
                CachedToken {
                    access_token,
                    expires_at_ms,
                },
            );
        }
    }
}

/// Obtain an `OAuth2` access token for a provider using JWT client assertion grant.
///
/// This function fetches the sandbox's SPIFFE JWT-SVID from the local SPIRE
/// agent, then exchanges it for an access token with a POST request to the provider's
/// token endpoint with the JWT client assertion grant flow (RFC 7523).
///
/// Tokens are cached per provider name with TTL. Subsequent calls return the
/// cached token if it has not expired.
///
/// # Arguments
///
/// * `provider_name` — Unique provider identifier (used as cache key)
/// * `token_endpoint` — `OAuth2` token service URL
/// * `jwt_svid_audience` — Optional audience to request when fetching the JWT-SVID
/// * `client_assertion_type` — Optional `OAuth2` client assertion type
/// * `audience` — Resource audience to request in the token request
/// * `scopes` — `OAuth2` scopes to request (may be empty)
/// * `cache_ttl_override` — Exact cache TTL; absence uses `expires_in` and zero disables caching
///
/// # Errors
///
/// Returns an error if:
/// - SPIFFE Workload API socket is not configured
/// - SPIRE agent is unreachable
/// - JWT-SVID fetch fails
/// - Token service request fails
/// - Token response is invalid
pub struct ObtainProviderTokenRequest<'a> {
    pub provider_name: &'a str,
    pub token_endpoint: &'a str,
    pub jwt_svid_audience: &'a str,
    pub client_assertion_type: &'a str,
    pub audience: &'a str,
    pub scopes: &'a [String],
    pub cache_ttl_override: Option<Duration>,
    pub grant_type: i32,
    pub requested_token_type: &'a str,
    /// Supervisor-minted ID of the HTTP exchange that needs the token. It is
    /// sent to the gateway and token service; a cache hit sends nothing.
    pub request_id: &'a str,
}

/// Obtain and cache a provider token, retaining only bounded grant failures.
pub async fn obtain_provider_token(
    request: ObtainProviderTokenRequest<'_>,
) -> Result<String, TokenGrantFailure> {
    let grant_type = ProviderCredentialTokenGrantType::try_from(request.grant_type)
        .map_err(|_| configuration_failure())?;
    obtain_provider_token_with_grant(
        ObtainProviderTokenInput {
            cache: &TOKEN_CACHE,
            provider_name: request.provider_name,
            token_endpoint: request.token_endpoint,
            jwt_svid_audience: request.jwt_svid_audience,
            client_assertion_type: request.client_assertion_type,
            audience: request.audience,
            scopes: request.scopes,
            cache_ttl_override: request.cache_ttl_override,
            grant_type,
            requested_token_type: request.requested_token_type,
        },
        |jwt_audience| async move {
            // Resolve local exchange prerequisites before fetching any workload credential.
            let exchange_context = match grant_type {
                ProviderCredentialTokenGrantType::ClientCredentials
                | ProviderCredentialTokenGrantType::Unspecified => None,
                ProviderCredentialTokenGrantType::TokenExchange => {
                    let (provider, credential_key) =
                        parse_provider_credential_key(request.provider_name)?;
                    let endpoint = supervisor_gateway_endpoint_from_env()?;
                    openshell_core::grpc_client::token_grant_gateway_endpoint(&endpoint)?;
                    Some((
                        provider,
                        credential_key,
                        endpoint,
                        supervisor_sandbox_id_from_env()?,
                    ))
                }
            };
            // Fetch JWT-SVID with authorization server as audience
            // For RFC 7523, the JWT assertion's aud claim identifies the issuer/realm
            let jwt_svid = fetch_jwt_svid_for_token_grant(&jwt_audience).await?;

            match exchange_context {
                None => {
                    // Perform OAuth2 JWT client assertion grant. The audience
                    // parameter in the token request specifies the resource server.
                    perform_token_grant(
                        request.token_endpoint,
                        &jwt_svid,
                        request.client_assertion_type,
                        request.audience,
                        request.scopes,
                        request.request_id,
                    )
                    .await
                }
                Some((provider, credential_key, endpoint, sandbox_id)) => {
                    let intermediate =
                        openshell_core::grpc_client::exchange_provider_subject_token(
                            &endpoint,
                            &sandbox_id,
                            provider,
                            credential_key,
                            &jwt_svid,
                            Some(request.request_id),
                        )
                        .await?;
                    validate_access_token(&intermediate.access_token).map_err(|failure| {
                        failure.at_stage(TokenGrantStage::IntermediateExchange)
                    })?;
                    perform_token_exchange(
                        request.token_endpoint,
                        &TokenExchangeParams {
                            client_assertion: &jwt_svid,
                            client_assertion_type: request.client_assertion_type,
                            subject_token: &intermediate.access_token,
                            subject_token_type: ACCESS_TOKEN_TYPE,
                            audience: request.audience,
                            scopes: request.scopes,
                            requested_token_type: request.requested_token_type,
                        },
                        request.request_id,
                    )
                    .await
                }
            }
        },
    )
    .await
}

struct ObtainProviderTokenInput<'a> {
    cache: &'a TokenCache,
    provider_name: &'a str,
    token_endpoint: &'a str,
    jwt_svid_audience: &'a str,
    client_assertion_type: &'a str,
    audience: &'a str,
    scopes: &'a [String],
    cache_ttl_override: Option<Duration>,
    grant_type: ProviderCredentialTokenGrantType,
    requested_token_type: &'a str,
}

async fn obtain_provider_token_with_grant<F, Fut>(
    input: ObtainProviderTokenInput<'_>,
    grant: F,
) -> Result<String, TokenGrantFailure>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<OAuthTokenResponse, TokenGrantFailure>>,
{
    let jwt_audience = effective_jwt_svid_audience(input.token_endpoint, input.jwt_svid_audience);
    let cache_key = token_cache_key(TokenCacheKeyInput {
        provider_name: input.provider_name,
        token_endpoint: input.token_endpoint,
        jwt_svid_audience: &jwt_audience,
        client_assertion_type: effective_client_assertion_type(input.client_assertion_type),
        audience: input.audience,
        scopes: input.scopes,
        grant_type: input.grant_type,
        requested_token_type: effective_token_type(input.requested_token_type),
    });

    if input.cache_ttl_override != Some(Duration::ZERO)
        && let Some(cached) = input.cache.get(&cache_key)
    {
        return Ok(cached);
    }

    oauth::parse_token_endpoint_url(input.token_endpoint)?;
    if input
        .cache_ttl_override
        .is_some_and(|ttl| i64::try_from(ttl.as_millis()).is_err())
    {
        return Err(configuration_failure());
    }
    let token_response = grant(jwt_audience).await?;
    validate_access_token(&token_response.access_token)?;

    let cache_ttl = token_cache_ttl(input.cache_ttl_override, token_response.expires_in);
    if !cache_ttl.is_zero() {
        let ttl_ms = i64::try_from(cache_ttl.as_millis()).unwrap_or(i64::MAX);
        let expires_at_ms = current_time_ms().saturating_add(ttl_ms);
        input.cache.set(
            cache_key,
            token_response.access_token.clone(),
            expires_at_ms,
        );
    }

    Ok(token_response.access_token)
}

/// Fetch JWT-SVID from SPIRE agent for token grant authentication.
///
/// This function connects to the local SPIRE agent via the Workload API and
/// requests a JWT-SVID with the specified audience. The JWT-SVID is used as
/// the client assertion in the `OAuth2` grant request.
async fn fetch_jwt_svid_for_token_grant(audience: &str) -> Result<String, TokenGrantFailure> {
    let socket_path = provider_spiffe_workload_api_socket_from_env()?;
    fetch_jwt_svid_from_socket(&socket_path, audience).await
}

async fn fetch_jwt_svid_from_socket(
    socket_path: &str,
    audience: &str,
) -> Result<String, TokenGrantFailure> {
    let endpoint = openshell_core::spiffe::workload_api_endpoint(std::path::Path::new(socket_path));

    // Connect to SPIRE agent
    let client = WorkloadApiClient::connect_to(&endpoint)
        .await
        .map_err(workload_api_failure)?;

    // Fetch JWT-SVID with token service audience
    // None = use the sandbox's default SPIFFE ID
    client
        .fetch_jwt_token([audience], None)
        .await
        .map_err(workload_api_failure)
}

fn workload_api_failure(error: WorkloadApiError) -> TokenGrantFailure {
    // Classify the local Workload API's typed rejection without retaining its
    // endpoint, response text, JWT parsing details, or transport source.
    let kind = match error {
        WorkloadApiError::Endpoint(_) => TokenGrantFailureKind::Configuration,
        WorkloadApiError::NoIdentityIssued | WorkloadApiError::PermissionDenied(_) => {
            TokenGrantFailureKind::WorkloadIdentityRejected
        }
        WorkloadApiError::Transport(spiffe::transport::TransportError::Status(status)) => {
            match status.code() {
                tonic::Code::DeadlineExceeded => TokenGrantFailureKind::Timeout,
                tonic::Code::Unavailable => TokenGrantFailureKind::Unavailable,
                tonic::Code::InvalidArgument => TokenGrantFailureKind::Configuration,
                _ => TokenGrantFailureKind::Unclassified,
            }
        }
        WorkloadApiError::Transport(spiffe::transport::TransportError::Tonic(_)) => {
            TokenGrantFailureKind::Unavailable
        }
        _ => TokenGrantFailureKind::Unclassified,
    };
    TokenGrantFailure::new(kind, TokenGrantStage::WorkloadIdentity)
}

fn configuration_failure() -> TokenGrantFailure {
    TokenGrantFailure::new(
        TokenGrantFailureKind::Configuration,
        TokenGrantStage::Configuration,
    )
}

fn provider_spiffe_workload_api_socket_from_env() -> Result<String, TokenGrantFailure> {
    std::env::var(sandbox_env::PROVIDER_SPIFFE_WORKLOAD_API_SOCKET)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(configuration_failure)
}

async fn perform_token_grant(
    token_endpoint: &str,
    jwt_svid: &str,
    client_assertion_type: &str,
    audience: &str,
    scopes: &[String],
    request_id: &str,
) -> Result<OAuthTokenResponse, TokenGrantFailure> {
    oauth::post_oauth_token_grant(
        TOKEN_GRANT_HTTP_CLIENT
            .as_ref()
            .map_err(|failure| *failure)?,
        token_endpoint,
        &TokenGrantParams {
            client_assertion: jwt_svid,
            client_assertion_type,
            audience,
            scopes,
        },
        Some(request_id),
    )
    .await
}

async fn perform_token_exchange(
    token_endpoint: &str,
    params: &TokenExchangeParams<'_>,
    request_id: &str,
) -> Result<OAuthTokenResponse, TokenGrantFailure> {
    oauth::post_oauth_token_exchange(
        TOKEN_GRANT_HTTP_CLIENT
            .as_ref()
            .map_err(|failure| *failure)?,
        token_endpoint,
        params,
        Some(request_id),
    )
    .await
}

pub use oauth::validate_access_token;

fn token_cache_ttl(cache_ttl_override: Option<Duration>, expires_in: i64) -> Duration {
    if let Some(cache_ttl_override) = cache_ttl_override {
        return cache_ttl_override;
    }

    let ttl = if expires_in > 0 {
        expires_in.min(MAX_TOKEN_EXPIRES_IN_SECONDS)
    } else {
        DEFAULT_TOKEN_CACHE_TTL_SECONDS
    };

    Duration::from_secs(
        u64::try_from(ttl.saturating_sub(TOKEN_CACHE_EXPIRY_SKEW_SECONDS).max(1))
            .unwrap_or(u64::MAX),
    )
}

/// Derive the issuer/realm URL from a token endpoint URL.
///
/// For Keycloak token endpoints like:
///   `https://auth.example.com/realms/openshell/protocol/openid-connect/token`
/// Returns:
///   `https://auth.example.com/realms/openshell`
///
/// This is used as the JWT-SVID audience claim when authenticating to the
/// authorization server via JWT client assertion (RFC 7523).
fn derive_issuer_from_token_endpoint(token_endpoint: &str) -> String {
    // For Keycloak, strip everything after /realms/{realm-name}
    if let Some(realms_idx) = token_endpoint.find("/realms/") {
        // Find the next path segment after the realm name
        let after_realms = &token_endpoint[realms_idx + "/realms/".len()..];
        if let Some(slash_idx) = after_realms.find('/') {
            // Return everything up to (but not including) the next slash
            let realm_end = realms_idx + "/realms/".len() + slash_idx;
            return token_endpoint[..realm_end].to_string();
        }
    }

    // Fallback: if we can't parse it, use the full token endpoint
    // This works for some OAuth2 servers that accept the token endpoint as aud
    token_endpoint.to_string()
}

fn effective_jwt_svid_audience(token_endpoint: &str, jwt_svid_audience: &str) -> String {
    if jwt_svid_audience.is_empty() {
        derive_issuer_from_token_endpoint(token_endpoint)
    } else {
        jwt_svid_audience.to_string()
    }
}

fn supervisor_gateway_endpoint_from_env() -> Result<String, TokenGrantFailure> {
    std::env::var(sandbox_env::ENDPOINT)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(configuration_failure)
}

fn supervisor_sandbox_id_from_env() -> Result<String, TokenGrantFailure> {
    std::env::var(sandbox_env::SANDBOX_ID)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(configuration_failure)
}

fn parse_provider_credential_key(key: &str) -> Result<(&str, &str), TokenGrantFailure> {
    openshell_core::dynamic_credential_key::credential_identity(key)
        .and_then(|identity| identity.split_once(':'))
        .ok_or_else(configuration_failure)
}

struct TokenCacheKeyInput<'a> {
    provider_name: &'a str,
    token_endpoint: &'a str,
    jwt_svid_audience: &'a str,
    client_assertion_type: &'a str,
    audience: &'a str,
    scopes: &'a [String],
    grant_type: ProviderCredentialTokenGrantType,
    requested_token_type: &'a str,
}

fn token_cache_key(input: TokenCacheKeyInput<'_>) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        input.provider_name,
        input.token_endpoint,
        input.jwt_svid_audience,
        input.client_assertion_type,
        input.audience,
        input.scopes.join(" "),
        input.grant_type as i32,
        input.requested_token_type
    )
}

/// Get current Unix timestamp in milliseconds.
fn current_time_ms() -> i64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis();
    i64::try_from(millis).unwrap_or(i64::MAX)
}

#[cfg(test)]
pub mod test_support {
    //! Relay fixtures using the production token cache.
    //!
    //! Each resolver owns its cache. Only acquisition is synthetic: no SPIFFE
    //! socket or OAuth service is contacted, and no process-wide cache is used.

    use super::*;
    use crate::l7::token_grant_injection::{TokenGrantRequest, TokenGrantResolver};
    use std::collections::HashSet;
    use std::pin::Pin;
    use std::sync::Mutex;

    /// One actual acquisition, excluding requests served from the cache.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct CacheAcquisition {
        pub(crate) provider_key: String,
        pub(crate) audience: String,
    }

    struct RecordedAcquisition {
        request: CacheAcquisition,
        cache_key: String,
    }

    /// A private production cache with deterministic synthetic token acquisition.
    ///
    /// Misses return `inert-{audience}-{acquisition ordinal}`. The ordinal makes
    /// reacquisition observable even when the provider and audience stay the same.
    pub struct CachedTokenGrantResolver {
        cache: TokenCache,
        acquisitions: Mutex<Vec<RecordedAcquisition>>,
    }

    impl CachedTokenGrantResolver {
        pub(crate) fn new() -> Self {
            Self {
                cache: TokenCache::new(),
                acquisitions: Mutex::new(Vec::new()),
            }
        }

        pub(crate) fn acquisitions(&self) -> Vec<CacheAcquisition> {
            self.acquisitions
                .lock()
                .expect("cached resolver acquisitions lock")
                .iter()
                .map(|acquisition| acquisition.request.clone())
                .collect()
        }

        /// Expire acquired entries for `provider:credential` and audience.
        ///
        /// This changes only the timestamp, preserving the cached value so the
        /// next request must pass the production expiry check to obtain a new
        /// token. The returned count proves an entry was present; no sleep or
        /// modification of the shared production cache is needed.
        pub(crate) fn expire(&self, provider_identity: &str, audience: &str) -> usize {
            let acquisitions = self
                .acquisitions
                .lock()
                .expect("cached resolver acquisitions lock");
            let keys = acquisitions
                .iter()
                .filter(|acquisition| {
                    openshell_core::dynamic_credential_key::credential_identity(
                        &acquisition.request.provider_key,
                    ) == Some(provider_identity)
                        && acquisition.request.audience == audience
                })
                .map(|acquisition| acquisition.cache_key.as_str())
                .collect::<HashSet<_>>();
            let mut cached = self.cache.tokens.write().expect("test token cache lock");
            let mut expired = 0;
            for key in keys {
                if let Some(token) = cached.get_mut(key) {
                    token.expires_at_ms = 0;
                    expired += 1;
                }
            }
            expired
        }
    }

    impl TokenGrantResolver for CachedTokenGrantResolver {
        fn obtain<'a>(
            &'a self,
            request: TokenGrantRequest<'a>,
        ) -> Pin<Box<dyn Future<Output = Result<String, TokenGrantFailure>> + Send + 'a>> {
            Box::pin(async move {
                let grant_type = ProviderCredentialTokenGrantType::try_from(request.grant_type)
                    .map_err(|_| configuration_failure())?;
                obtain_provider_token_with_grant(
                    ObtainProviderTokenInput {
                        cache: &self.cache,
                        provider_name: request.provider_key,
                        token_endpoint: request.token_endpoint,
                        jwt_svid_audience: request.jwt_svid_audience,
                        client_assertion_type: request.client_assertion_type,
                        audience: request.audience,
                        scopes: request.scopes,
                        cache_ttl_override: request.cache_ttl,
                        grant_type,
                        requested_token_type: request.requested_token_type,
                    },
                    |jwt_audience| async move {
                        let cache_key = token_cache_key(TokenCacheKeyInput {
                            provider_name: request.provider_key,
                            token_endpoint: request.token_endpoint,
                            jwt_svid_audience: &jwt_audience,
                            client_assertion_type: effective_client_assertion_type(
                                request.client_assertion_type,
                            ),
                            audience: request.audience,
                            scopes: request.scopes,
                            grant_type,
                            requested_token_type: effective_token_type(
                                request.requested_token_type,
                            ),
                        });
                        let mut acquisitions = self
                            .acquisitions
                            .lock()
                            .expect("cached resolver acquisitions lock");
                        let ordinal = acquisitions.len() + 1;
                        acquisitions.push(RecordedAcquisition {
                            request: CacheAcquisition {
                                provider_key: request.provider_key.to_owned(),
                                audience: request.audience.to_owned(),
                            },
                            cache_key,
                        });
                        Ok(OAuthTokenResponse {
                            access_token: format!("inert-{}-{ordinal}", request.audience),
                            token_type: "Bearer".to_owned(),
                            expires_in: MAX_TOKEN_EXPIRES_IN_SECONDS,
                        })
                    },
                )
                .await
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::oauth::{ACCESS_TOKEN_TYPE, DEFAULT_CLIENT_ASSERTION_TYPE};
    use std::collections::HashMap;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const TEST_REQUEST_ID: &str = "4f1c2b3a-9d8e-4c7b-a6f5-e4d3c2b1a098";

    #[derive(Debug)]
    struct CapturedTokenRequest {
        request_line: String,
        headers: HashMap<String, String>,
        form: HashMap<String, String>,
    }

    async fn token_endpoint_once(
        status: &str,
        body: &str,
    ) -> (String, tokio::task::JoinHandle<CapturedTokenRequest>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind token endpoint");
        let addr = listener.local_addr().expect("token endpoint local addr");
        let status = status.to_string();
        let body = body.to_string();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept token request");
            let mut buf = Vec::new();
            let mut chunk = [0u8; 512];
            let mut expected_len = None;

            loop {
                let n = stream.read(&mut chunk).await.expect("read token request");
                assert!(n > 0, "token request stream closed before headers");
                buf.extend_from_slice(&chunk[..n]);

                if expected_len.is_none()
                    && let Some(header_end) = header_end(&buf)
                {
                    let headers = String::from_utf8_lossy(&buf[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    expected_len = Some(header_end + content_length);
                }

                if expected_len.is_some_and(|len| buf.len() >= len) {
                    break;
                }
            }

            let captured = parse_token_request(&buf);
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len(),
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write token response");
            captured
        });

        (format!("http://{addr}/token"), handle)
    }

    async fn token_endpoint_redirect_once(
        location: &str,
    ) -> (String, tokio::task::JoinHandle<CapturedTokenRequest>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind token endpoint");
        let addr = listener.local_addr().expect("token endpoint local addr");
        let location = location.to_string();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept token request");
            let mut buf = Vec::new();
            let mut chunk = [0u8; 512];
            let mut expected_len = None;

            loop {
                let n = stream.read(&mut chunk).await.expect("read token request");
                assert!(n > 0, "token request stream closed before headers");
                buf.extend_from_slice(&chunk[..n]);

                if expected_len.is_none()
                    && let Some(header_end) = header_end(&buf)
                {
                    let headers = String::from_utf8_lossy(&buf[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    expected_len = Some(header_end + content_length);
                }

                if expected_len.is_some_and(|len| buf.len() >= len) {
                    break;
                }
            }

            let captured = parse_token_request(&buf);
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write token response");
            captured
        });

        (format!("http://{addr}/token"), handle)
    }

    fn header_end(buf: &[u8]) -> Option<usize> {
        buf.windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|idx| idx + 4)
    }

    fn parse_token_request(buf: &[u8]) -> CapturedTokenRequest {
        let header_end = header_end(buf).expect("request should contain header terminator");
        let headers = String::from_utf8_lossy(&buf[..header_end]);
        let mut lines = headers.lines();
        let request_line = lines.next().expect("request line").to_string();
        let headers = lines
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                Some((name.to_ascii_lowercase(), value.trim().to_string()))
            })
            .collect();
        let body = String::from_utf8_lossy(&buf[header_end..]).to_string();

        CapturedTokenRequest {
            request_line,
            headers,
            form: parse_form_body(&body),
        }
    }

    fn parse_form_body(body: &str) -> HashMap<String, String> {
        body.split('&')
            .filter(|part| !part.is_empty())
            .filter_map(|part| {
                let (name, value) = part.split_once('=')?;
                Some((decode_form_component(name), decode_form_component(value)))
            })
            .collect()
    }

    fn decode_form_component(value: &str) -> String {
        let bytes = value.as_bytes();
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut idx = 0;
        while idx < bytes.len() {
            match bytes[idx] {
                b'+' => {
                    decoded.push(b' ');
                    idx += 1;
                }
                b'%' if idx + 2 < bytes.len() => {
                    let hex = &value[idx + 1..idx + 3];
                    if let Ok(byte) = u8::from_str_radix(hex, 16) {
                        decoded.push(byte);
                        idx += 3;
                    } else {
                        decoded.push(bytes[idx]);
                        idx += 1;
                    }
                }
                byte => {
                    decoded.push(byte);
                    idx += 1;
                }
            }
        }
        String::from_utf8(decoded).expect("form body should be UTF-8")
    }

    struct CountedTokenGrantInput<'a> {
        cache: &'a TokenCache,
        provider_name: &'a str,
        token_endpoint: &'a str,
        jwt_svid_audience: &'a str,
        audience: &'a str,
        scopes: &'a [String],
        cache_ttl_override: Option<Duration>,
        expires_in: i64,
        grant_calls: Arc<AtomicUsize>,
    }

    async fn obtain_counted_test_token(
        input: CountedTokenGrantInput<'_>,
    ) -> Result<String, TokenGrantFailure> {
        obtain_provider_token_with_grant(
            ObtainProviderTokenInput {
                cache: input.cache,
                provider_name: input.provider_name,
                token_endpoint: input.token_endpoint,
                jwt_svid_audience: input.jwt_svid_audience,
                client_assertion_type: DEFAULT_CLIENT_ASSERTION_TYPE,
                audience: input.audience,
                scopes: input.scopes,
                cache_ttl_override: input.cache_ttl_override,
                grant_type: ProviderCredentialTokenGrantType::ClientCredentials,
                requested_token_type: "",
            },
            move |_| {
                let grant_calls = input.grant_calls.clone();
                async move {
                    let call = grant_calls.fetch_add(1, Ordering::SeqCst) + 1;
                    Ok(OAuthTokenResponse {
                        access_token: format!("token-{call}"),
                        token_type: "Bearer".to_string(),
                        expires_in: input.expires_in,
                    })
                }
            },
        )
        .await
    }

    async fn obtain_token_without_grant_call(
        cache: &TokenCache,
        provider_name: &str,
        token_endpoint: &str,
        jwt_svid_audience: &str,
        audience: &str,
        scopes: &[String],
        cache_ttl_override: Option<Duration>,
    ) -> Result<String, TokenGrantFailure> {
        obtain_provider_token_with_grant(
            ObtainProviderTokenInput {
                cache,
                provider_name,
                token_endpoint,
                jwt_svid_audience,
                client_assertion_type: DEFAULT_CLIENT_ASSERTION_TYPE,
                audience,
                scopes,
                cache_ttl_override,
                grant_type: ProviderCredentialTokenGrantType::ClientCredentials,
                requested_token_type: "",
            },
            |_| async { panic!("grant should not be called on cache hit") },
        )
        .await
    }

    #[tokio::test]
    async fn invalid_endpoint_and_cache_ttl_fail_before_credential_acquisition() {
        let cache = TokenCache::new();
        let grant_calls = Arc::new(AtomicUsize::new(0));
        for (endpoint, ttl) in [
            ("https://secret-endpoint-canary@", None),
            ("https://auth.example.com/token", Some(Duration::MAX)),
        ] {
            let failure = obtain_counted_test_token(CountedTokenGrantInput {
                cache: &cache,
                provider_name: "provider:access_token",
                token_endpoint: endpoint,
                jwt_svid_audience: "https://auth.example.com",
                audience: "api://resource",
                scopes: &[],
                cache_ttl_override: ttl,
                expires_in: 60,
                grant_calls: grant_calls.clone(),
            })
            .await
            .expect_err("invalid local configuration must fail closed");
            assert_eq!(failure, configuration_failure());
        }
        assert_eq!(grant_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn workload_api_failures_are_classified() {
        for (raw, kind) in [
            (
                WorkloadApiError::PermissionDenied("secret-spiffe-canary".to_string()),
                TokenGrantFailureKind::WorkloadIdentityRejected,
            ),
            (
                WorkloadApiError::from(tonic::Status::deadline_exceeded("secret-canary")),
                TokenGrantFailureKind::Timeout,
            ),
            (
                WorkloadApiError::from(tonic::Status::unavailable("secret-canary")),
                TokenGrantFailureKind::Unavailable,
            ),
        ] {
            let failure = workload_api_failure(raw);
            assert_eq!(failure.kind(), kind);
            assert_eq!(failure.stage(), TokenGrantStage::WorkloadIdentity);
        }
    }

    #[test]
    fn test_derive_issuer_from_keycloak_token_endpoint() {
        let token_endpoint =
            "https://auth.example.com/realms/openshell/protocol/openid-connect/token";
        let issuer = derive_issuer_from_token_endpoint(token_endpoint);
        assert_eq!(issuer, "https://auth.example.com/realms/openshell");
    }

    #[test]
    fn test_derive_issuer_from_https_keycloak_endpoint() {
        let token_endpoint =
            "https://auth.example.com/realms/production/protocol/openid-connect/token";
        let issuer = derive_issuer_from_token_endpoint(token_endpoint);
        assert_eq!(issuer, "https://auth.example.com/realms/production");
    }

    #[test]
    fn test_derive_issuer_fallback_for_non_keycloak() {
        let token_endpoint = "https://oauth.example.com/token";
        let issuer = derive_issuer_from_token_endpoint(token_endpoint);
        // Fallback: returns the full token endpoint
        assert_eq!(issuer, "https://oauth.example.com/token");
    }

    #[test]
    fn effective_jwt_svid_audience_prefers_explicit_override() {
        let audience = effective_jwt_svid_audience(
            "https://auth.example.com/realms/openshell/protocol/openid-connect/token",
            "spiffe://custom-audience",
        );

        assert_eq!(audience, "spiffe://custom-audience");
    }

    #[test]
    fn token_cache_key_varies_by_resource_audience_and_scopes() {
        let provider_name = "alpha.default.svc.cluster.local\t80\t\tprovider:access_token";
        let token_endpoint =
            "https://auth.example.com/realms/openshell/protocol/openid-connect/token";
        let jwt_svid_audience = "https://auth.example.com/realms/openshell";
        let alpha_scopes = ["alpha".to_string()];
        let delta_scopes = ["delta".to_string()];
        let base = token_cache_key(TokenCacheKeyInput {
            provider_name,
            token_endpoint,
            jwt_svid_audience,
            client_assertion_type: DEFAULT_CLIENT_ASSERTION_TYPE,
            audience: "alpha",
            scopes: &alpha_scopes,
            grant_type: ProviderCredentialTokenGrantType::ClientCredentials,
            requested_token_type: ACCESS_TOKEN_TYPE,
        });
        let different_audience = token_cache_key(TokenCacheKeyInput {
            provider_name,
            token_endpoint,
            jwt_svid_audience,
            client_assertion_type: DEFAULT_CLIENT_ASSERTION_TYPE,
            audience: "delta",
            scopes: &alpha_scopes,
            grant_type: ProviderCredentialTokenGrantType::ClientCredentials,
            requested_token_type: ACCESS_TOKEN_TYPE,
        });
        let different_scopes = token_cache_key(TokenCacheKeyInput {
            provider_name,
            token_endpoint,
            jwt_svid_audience,
            client_assertion_type: DEFAULT_CLIENT_ASSERTION_TYPE,
            audience: "alpha",
            scopes: &delta_scopes,
            grant_type: ProviderCredentialTokenGrantType::ClientCredentials,
            requested_token_type: ACCESS_TOKEN_TYPE,
        });
        let different_assertion_type = token_cache_key(TokenCacheKeyInput {
            provider_name,
            token_endpoint,
            jwt_svid_audience,
            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe",
            audience: "alpha",
            scopes: &alpha_scopes,
            grant_type: ProviderCredentialTokenGrantType::ClientCredentials,
            requested_token_type: ACCESS_TOKEN_TYPE,
        });

        assert_ne!(base, different_audience);
        assert_ne!(base, different_scopes);
        assert_ne!(base, different_assertion_type);
    }

    #[test]
    fn token_cache_key_varies_by_provider_env_revision_prefix() {
        let token_endpoint =
            "https://auth.example.com/realms/openshell/protocol/openid-connect/token";
        let jwt_svid_audience = "https://auth.example.com/realms/openshell";
        let scopes = ["alpha".to_string()];
        let revision_one = token_cache_key(TokenCacheKeyInput {
            provider_name: "api.example.test\t443\t/v1/**\trev:1\tprovider:access_token",
            token_endpoint,
            jwt_svid_audience,
            client_assertion_type: DEFAULT_CLIENT_ASSERTION_TYPE,
            audience: "alpha",
            scopes: &scopes,
            grant_type: ProviderCredentialTokenGrantType::TokenExchange,
            requested_token_type: ACCESS_TOKEN_TYPE,
        });
        let revision_two = token_cache_key(TokenCacheKeyInput {
            provider_name: "api.example.test\t443\t/v1/**\trev:2\tprovider:access_token",
            token_endpoint,
            jwt_svid_audience,
            client_assertion_type: DEFAULT_CLIENT_ASSERTION_TYPE,
            audience: "alpha",
            scopes: &scopes,
            grant_type: ProviderCredentialTokenGrantType::TokenExchange,
            requested_token_type: ACCESS_TOKEN_TYPE,
        });

        assert_ne!(revision_one, revision_two);
    }

    #[test]
    fn provider_credential_key_parser_preserves_identity_and_rejects_extra_fields() {
        assert_eq!(
            parse_provider_credential_key(
                "api.example.test\t443\t/v1/**\trev:42\tprovider:access_token"
            )
            .expect("parse provider credential key"),
            ("provider", "access_token")
        );
        assert!(
            parse_provider_credential_key(
                "api.example.test\t443\t/v1/**\towner\tprovider:a\tother:access_token"
            )
            .is_err()
        );
    }

    #[test]
    fn token_cache_ttl_uses_override_without_endpoint_skew() {
        assert_eq!(
            token_cache_ttl(Some(Duration::from_mins(2)), 10),
            Duration::from_mins(2)
        );
        assert_eq!(
            token_cache_ttl(Some(Duration::from_mins(2)), i64::MAX),
            Duration::from_mins(2)
        );
    }

    #[test]
    fn token_cache_ttl_preserves_fractional_and_zero_overrides() {
        assert_eq!(
            token_cache_ttl(Some(Duration::from_millis(500)), 60),
            Duration::from_millis(500)
        );
        assert_eq!(token_cache_ttl(Some(Duration::ZERO), 60), Duration::ZERO);
    }

    #[test]
    fn token_cache_ttl_skews_default_and_response_expires_in() {
        assert_eq!(
            token_cache_ttl(None, 0),
            Duration::from_secs(
                u64::try_from(DEFAULT_TOKEN_CACHE_TTL_SECONDS - TOKEN_CACHE_EXPIRY_SKEW_SECONDS)
                    .unwrap()
            )
        );
        assert_eq!(token_cache_ttl(None, 60), Duration::from_secs(30));
        assert_eq!(token_cache_ttl(None, 10), Duration::from_secs(1));
    }

    #[test]
    fn token_cache_ttl_clamps_large_response_expires_in() {
        assert_eq!(
            token_cache_ttl(None, i64::MAX),
            Duration::from_secs(
                u64::try_from(MAX_TOKEN_EXPIRES_IN_SECONDS - TOKEN_CACHE_EXPIRY_SKEW_SECONDS)
                    .unwrap()
            )
        );
    }

    #[tokio::test]
    async fn multiple_credentials_cache_and_expire_independently() {
        let cache = TokenCache::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let scopes = vec!["read".to_string()];
        let service = "api.example.test\t443\t/v1/**\trev:1\tprovider:service";
        let identity = "api.example.test\t443\t/v1/**\trev:1\tprovider:identity";
        for (key, expected) in [(service, "token-1"), (identity, "token-2")] {
            let token = obtain_counted_test_token(CountedTokenGrantInput {
                cache: &cache,
                provider_name: key,
                token_endpoint: "https://auth.example.com/token",
                jwt_svid_audience: "https://auth.example.com",
                audience: "api://resource",
                scopes: &scopes,
                cache_ttl_override: None,
                expires_in: 120,
                grant_calls: calls.clone(),
            })
            .await
            .unwrap();
            assert_eq!(token, expected);
        }
        let identity_cache_key = token_cache_key(TokenCacheKeyInput {
            provider_name: identity,
            token_endpoint: "https://auth.example.com/token",
            jwt_svid_audience: "https://auth.example.com",
            client_assertion_type: DEFAULT_CLIENT_ASSERTION_TYPE,
            audience: "api://resource",
            scopes: &scopes,
            grant_type: ProviderCredentialTokenGrantType::ClientCredentials,
            requested_token_type: ACCESS_TOKEN_TYPE,
        });
        cache.set(identity_cache_key, "expired".into(), current_time_ms() - 1);
        let service_token = obtain_token_without_grant_call(
            &cache,
            service,
            "https://auth.example.com/token",
            "https://auth.example.com",
            "api://resource",
            &scopes,
            None,
        )
        .await
        .unwrap();
        assert_eq!(service_token, "token-1");
        let identity_token = obtain_counted_test_token(CountedTokenGrantInput {
            cache: &cache,
            provider_name: identity,
            token_endpoint: "https://auth.example.com/token",
            jwt_svid_audience: "https://auth.example.com",
            audience: "api://resource",
            scopes: &scopes,
            cache_ttl_override: None,
            expires_in: 120,
            grant_calls: calls.clone(),
        })
        .await
        .unwrap();
        assert_eq!(identity_token, "token-3");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn obtain_provider_token_uses_cache_for_same_key() {
        let cache = TokenCache::new();
        let grant_calls = Arc::new(AtomicUsize::new(0));
        let scopes = vec!["read".to_string()];

        let first = obtain_counted_test_token(CountedTokenGrantInput {
            cache: &cache,
            provider_name: "api.example.test\t443\t/v1/**\tprovider:access_token",
            token_endpoint: "https://auth.example.com/token",
            jwt_svid_audience: "https://auth.example.com",
            audience: "api://resource",
            scopes: &scopes,
            cache_ttl_override: None,
            expires_in: 60,
            grant_calls: grant_calls.clone(),
        })
        .await
        .expect("first call should grant token");
        let second = obtain_token_without_grant_call(
            &cache,
            "api.example.test\t443\t/v1/**\tprovider:access_token",
            "https://auth.example.com/token",
            "https://auth.example.com",
            "api://resource",
            &scopes,
            None,
        )
        .await
        .expect("second call should use cache");

        assert_eq!(first, "token-1");
        assert_eq!(second, "token-1");
        assert_eq!(grant_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn obtain_provider_token_separates_cache_by_audience_and_scopes() {
        let cache = TokenCache::new();
        let grant_calls = Arc::new(AtomicUsize::new(0));
        let read_scope = vec!["read".to_string()];
        let write_scope = vec!["write".to_string()];

        let first = obtain_counted_test_token(CountedTokenGrantInput {
            cache: &cache,
            provider_name: "api.example.test\t443\t/v1/**\tprovider:access_token",
            token_endpoint: "https://auth.example.com/token",
            jwt_svid_audience: "https://auth.example.com",
            audience: "api://resource-one",
            scopes: &read_scope,
            cache_ttl_override: None,
            expires_in: 60,
            grant_calls: grant_calls.clone(),
        })
        .await
        .expect("first audience should grant token");
        let different_audience = obtain_counted_test_token(CountedTokenGrantInput {
            cache: &cache,
            provider_name: "api.example.test\t443\t/v1/**\tprovider:access_token",
            token_endpoint: "https://auth.example.com/token",
            jwt_svid_audience: "https://auth.example.com",
            audience: "api://resource-two",
            scopes: &read_scope,
            cache_ttl_override: None,
            expires_in: 60,
            grant_calls: grant_calls.clone(),
        })
        .await
        .expect("different audience should grant token");
        let different_scope = obtain_counted_test_token(CountedTokenGrantInput {
            cache: &cache,
            provider_name: "api.example.test\t443\t/v1/**\tprovider:access_token",
            token_endpoint: "https://auth.example.com/token",
            jwt_svid_audience: "https://auth.example.com",
            audience: "api://resource-one",
            scopes: &write_scope,
            cache_ttl_override: None,
            expires_in: 60,
            grant_calls: grant_calls.clone(),
        })
        .await
        .expect("different scope should grant token");

        assert_eq!(first, "token-1");
        assert_eq!(different_audience, "token-2");
        assert_eq!(different_scope, "token-3");
        assert_eq!(grant_calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn obtain_provider_token_regrants_after_expired_cache_entry() {
        let cache = TokenCache::new();
        let grant_calls = Arc::new(AtomicUsize::new(0));
        let scopes = vec!["read".to_string()];
        let provider_name = "api.example.test\t443\t/v1/**\tprovider:access_token";
        let token_endpoint = "https://auth.example.com/token";
        let jwt_svid_audience = "https://auth.example.com";
        let audience = "api://resource";

        let cache_key = token_cache_key(TokenCacheKeyInput {
            provider_name,
            token_endpoint,
            jwt_svid_audience,
            client_assertion_type: DEFAULT_CLIENT_ASSERTION_TYPE,
            audience,
            scopes: &scopes,
            grant_type: ProviderCredentialTokenGrantType::ClientCredentials,
            requested_token_type: ACCESS_TOKEN_TYPE,
        });
        cache.set(
            cache_key,
            "expired-token".to_string(),
            current_time_ms() - 1,
        );

        let token = obtain_counted_test_token(CountedTokenGrantInput {
            cache: &cache,
            provider_name,
            token_endpoint,
            jwt_svid_audience,
            audience,
            scopes: &scopes,
            cache_ttl_override: None,
            expires_in: 60,
            grant_calls: grant_calls.clone(),
        })
        .await
        .expect("expired cache entry should grant token again");

        assert_eq!(token, "token-1");
        assert_eq!(grant_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn obtain_provider_token_cache_ttl_override_extends_zero_expires_in() {
        let cache = TokenCache::new();
        let grant_calls = Arc::new(AtomicUsize::new(0));
        let scopes = vec!["read".to_string()];

        let first = obtain_counted_test_token(CountedTokenGrantInput {
            cache: &cache,
            provider_name: "api.example.test\t443\t/v1/**\tprovider:access_token",
            token_endpoint: "https://auth.example.com/token",
            jwt_svid_audience: "https://auth.example.com",
            audience: "api://resource",
            scopes: &scopes,
            cache_ttl_override: Some(Duration::from_mins(1)),
            expires_in: 0,
            grant_calls: grant_calls.clone(),
        })
        .await
        .expect("first override call should grant token");
        let second = obtain_token_without_grant_call(
            &cache,
            "api.example.test\t443\t/v1/**\tprovider:access_token",
            "https://auth.example.com/token",
            "https://auth.example.com",
            "api://resource",
            &scopes,
            Some(Duration::from_mins(1)),
        )
        .await
        .expect("override should keep token cached");

        assert_eq!(first, "token-1");
        assert_eq!(second, "token-1");
        assert_eq!(grant_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn obtain_provider_token_zero_cache_ttl_does_not_cache() {
        let cache = TokenCache::new();
        let grant_calls = Arc::new(AtomicUsize::new(0));
        let scopes = vec!["read".to_string()];
        let input = || CountedTokenGrantInput {
            cache: &cache,
            provider_name: "api.example.test\t443\t/v1/**\tprovider:access_token",
            token_endpoint: "https://auth.example.com/token",
            jwt_svid_audience: "https://auth.example.com",
            audience: "api://resource",
            scopes: &scopes,
            cache_ttl_override: Some(Duration::ZERO),
            expires_in: 60,
            grant_calls: grant_calls.clone(),
        };

        assert_eq!(obtain_counted_test_token(input()).await.unwrap(), "token-1");
        assert_eq!(obtain_counted_test_token(input()).await.unwrap(), "token-2");
        assert_eq!(grant_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn perform_token_grant_posts_jwt_assertion_and_parses_success_response() {
        let (endpoint, request) = token_endpoint_once(
            "200 OK",
            r#"{"access_token":"access-123","token_type":"Bearer","expires_in":42,"scope":"read write"}"#,
        )
        .await;
        let scopes = vec!["read".to_string(), "write".to_string()];

        let response = perform_token_grant(
            &endpoint,
            "jwt-svid-token",
            "",
            "api://resource",
            &scopes,
            TEST_REQUEST_ID,
        )
        .await
        .expect("token grant should succeed");
        let request = request.await.expect("token endpoint task should finish");

        assert_eq!(response.access_token, "access-123");
        assert_eq!(response.expires_in, 42);
        assert_eq!(request.request_line, "POST /token HTTP/1.1");
        assert_eq!(
            request.headers.get("content-type").map(String::as_str),
            Some("application/x-www-form-urlencoded")
        );
        assert_eq!(
            request
                .headers
                .get(openshell_core::token_grant_failure::REQUEST_ID_HEADER)
                .map(String::as_str),
            Some(TEST_REQUEST_ID)
        );
        assert_eq!(
            request.form.get("grant_type").map(String::as_str),
            Some("client_credentials")
        );
        assert_eq!(
            request
                .form
                .get("client_assertion_type")
                .map(String::as_str),
            Some(DEFAULT_CLIENT_ASSERTION_TYPE)
        );
        assert_eq!(
            request.form.get("client_assertion").map(String::as_str),
            Some("jwt-svid-token")
        );
        assert_eq!(
            request.form.get("audience").map(String::as_str),
            Some("api://resource")
        );
        assert_eq!(
            request.form.get("scope").map(String::as_str),
            Some("read write")
        );
        assert!(
            !request.form.contains_key("client_id"),
            "JWT-SVID subject should identify the client"
        );
    }

    #[tokio::test]
    async fn perform_token_grant_uses_configured_client_assertion_type() {
        let (endpoint, request) =
            token_endpoint_once("200 OK", r#"{"access_token":"access-123"}"#).await;

        let response = perform_token_grant(
            &endpoint,
            "jwt-svid-token",
            "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe",
            "",
            &[],
            TEST_REQUEST_ID,
        )
        .await
        .expect("token grant should succeed");
        let request = request.await.expect("token endpoint task should finish");

        assert_eq!(response.access_token, "access-123");
        assert_eq!(
            request
                .form
                .get("client_assertion_type")
                .map(String::as_str),
            Some("urn:ietf:params:oauth:client-assertion-type:jwt-spiffe")
        );
    }

    #[tokio::test]
    async fn perform_token_grant_rejects_malformed_access_token() {
        let (endpoint, request) = token_endpoint_once(
            "200 OK",
            r#"{"access_token":"access-123\r\nX-Injected: yes"}"#,
        )
        .await;

        let err = perform_token_grant(&endpoint, "jwt-svid-token", "", "", &[], TEST_REQUEST_ID)
            .await
            .expect_err("malformed access token should fail closed");
        let _request = request.await.expect("token endpoint task should finish");

        assert_eq!(err.upstream_status(), Some(200));
    }

    #[tokio::test]
    async fn perform_token_grant_does_not_follow_redirects() {
        let (endpoint, request) = token_endpoint_redirect_once("http://127.0.0.1:1/stolen").await;

        let err = perform_token_grant(&endpoint, "jwt-svid-token", "", "", &[], TEST_REQUEST_ID)
            .await
            .expect_err("redirect response should fail closed");
        let _request = request.await.expect("token endpoint task should finish");

        assert_eq!(err.upstream_status(), Some(302));
    }

    #[tokio::test]
    async fn perform_token_grant_omits_empty_audience_and_scope() {
        let (endpoint, request) =
            token_endpoint_once("200 OK", r#"{"access_token":"access-123"}"#).await;

        let response =
            perform_token_grant(&endpoint, "jwt-svid-token", "", "", &[], TEST_REQUEST_ID)
                .await
                .expect("token grant should succeed without audience or scopes");
        let request = request.await.expect("token endpoint task should finish");

        assert_eq!(response.access_token, "access-123");
        assert_eq!(
            request.form.get("client_assertion").map(String::as_str),
            Some("jwt-svid-token")
        );
        assert!(!request.form.contains_key("audience"));
        assert!(!request.form.contains_key("scope"));
    }

    #[tokio::test]
    async fn perform_token_grant_reports_sanitized_oauth_error_response() {
        let (endpoint, request) = token_endpoint_once(
            "401 Unauthorized",
            r#"{"error":"invalid_client","error_description":"bad jwt assertion"}"#,
        )
        .await;

        let err = perform_token_grant(
            &endpoint,
            "jwt-svid-token",
            "",
            "api://resource",
            &[],
            TEST_REQUEST_ID,
        )
        .await
        .expect_err("token grant should fail on OAuth error");
        let request = request.await.expect("token endpoint task should finish");

        assert_eq!(
            request.form.get("audience").map(String::as_str),
            Some("api://resource")
        );
        assert_eq!(err.upstream_status(), Some(401));
        assert!(!format!("{err:?}").contains("bad jwt assertion"));
    }

    #[tokio::test]
    async fn perform_token_grant_does_not_echo_unstructured_error_body() {
        let (endpoint, request) = token_endpoint_once(
            "500 Internal Server Error",
            "internal stack trace with implementation details",
        )
        .await;

        let err = perform_token_grant(&endpoint, "jwt-svid-token", "", "", &[], TEST_REQUEST_ID)
            .await
            .expect_err("token grant should fail on server error");
        let _request = request.await.expect("token endpoint task should finish");
        let message = err.to_string();

        assert_eq!(message, "dynamic token grant failed");
        assert_eq!(err.kind(), TokenGrantFailureKind::Unavailable);
        assert_eq!(err.upstream_status(), Some(500));
        assert!(!message.contains("stack trace"));
        assert!(!message.contains("implementation details"));
    }

    #[tokio::test]
    async fn perform_token_grant_reports_malformed_success_json() {
        let (endpoint, request) = token_endpoint_once("200 OK", r#"{"access_token":42"#).await;

        let err = perform_token_grant(&endpoint, "jwt-svid-token", "", "", &[], TEST_REQUEST_ID)
            .await
            .expect_err("malformed token response should fail");
        let _request = request.await.expect("token endpoint task should finish");

        assert_eq!(err.upstream_status(), Some(200));
    }
}
