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
//! - `audience` — Resource audience to request from the token service
//! - `scopes` — `OAuth2` scopes to request (optional)
//! - `cache_ttl_seconds` — Cache override (0 = use `expires_in` from response)
//!
//! ## Environment
//!
//! Requires `OPENSHELL_SPIFFE_WORKLOAD_API_SOCKET` to be set (path to SPIRE
//! agent socket). This is configured by the SPIRE `DaemonSet` in Kubernetes or
//! mounted by the compute driver in standalone deployments.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_core::sandbox_env;
use serde::Deserialize;
use spiffe::WorkloadApiClient;

/// Token cache shared across all provider token grants.
static TOKEN_CACHE: LazyLock<TokenCache> = LazyLock::new(TokenCache::new);
const MAX_OAUTH_ERROR_FIELD_LEN: usize = 256;

/// `OAuth2` token response from the authorization server.
#[derive(Debug, Clone, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    #[allow(dead_code)]
    token_type: String,
    #[serde(default)]
    expires_in: i64,
    #[serde(default)]
    #[allow(dead_code)]
    scope: String,
}

#[derive(Debug, Deserialize)]
struct OAuthErrorResponse {
    error: Option<String>,
    error_description: Option<String>,
}

/// Cached access token with expiration metadata.
#[derive(Debug, Clone)]
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
/// * `audience` — Resource audience to request in the token request
/// * `scopes` — `OAuth2` scopes to request (may be empty)
/// * `cache_ttl_override` — Cache TTL in seconds (0 = use `expires_in` from response)
///
/// # Errors
///
/// Returns an error if:
/// - SPIFFE Workload API socket is not configured
/// - SPIRE agent is unreachable
/// - JWT-SVID fetch fails
/// - Token service request fails
/// - Token response is invalid
pub async fn obtain_provider_token(
    provider_name: &str,
    token_endpoint: &str,
    jwt_svid_audience: &str,
    audience: &str,
    scopes: &[String],
    cache_ttl_override: i64,
) -> Result<String> {
    obtain_provider_token_with_grant(
        ObtainProviderTokenInput {
            cache: &TOKEN_CACHE,
            provider_name,
            token_endpoint,
            jwt_svid_audience,
            audience,
            scopes,
            cache_ttl_override,
        },
        |jwt_audience| async move {
            // Fetch JWT-SVID with authorization server as audience
            // For RFC 7523, the JWT assertion's aud claim identifies the issuer/realm
            let jwt_svid = fetch_jwt_svid_for_token_grant(&jwt_audience).await?;

            // Perform OAuth2 JWT client assertion grant
            // The audience parameter in the token request specifies the resource server
            perform_token_grant(token_endpoint, &jwt_svid, audience, scopes).await
        },
    )
    .await
}

struct ObtainProviderTokenInput<'a> {
    cache: &'a TokenCache,
    provider_name: &'a str,
    token_endpoint: &'a str,
    jwt_svid_audience: &'a str,
    audience: &'a str,
    scopes: &'a [String],
    cache_ttl_override: i64,
}

async fn obtain_provider_token_with_grant<F, Fut>(
    input: ObtainProviderTokenInput<'_>,
    grant: F,
) -> Result<String>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<TokenResponse>>,
{
    // Derive authorization server audience from token endpoint
    // For Keycloak: http://keycloak/realms/openshell/protocol/openid-connect/token
    //           -> http://keycloak/realms/openshell
    let jwt_audience = effective_jwt_svid_audience(input.token_endpoint, input.jwt_svid_audience);
    let cache_key = token_cache_key(
        input.provider_name,
        input.token_endpoint,
        &jwt_audience,
        input.audience,
        input.scopes,
    );

    // Check cache first
    if let Some(cached) = input.cache.get(&cache_key) {
        return Ok(cached);
    }

    let token_response = grant(jwt_audience).await?;

    // Calculate expiration time
    let expires_at_ms = if input.cache_ttl_override > 0 {
        current_time_ms() + (input.cache_ttl_override * 1000)
    } else if token_response.expires_in > 0 {
        current_time_ms() + (token_response.expires_in * 1000)
    } else {
        // Default to 5 minutes if no expiry provided
        current_time_ms() + (300 * 1000)
    };

    // Cache the token
    input.cache.set(
        cache_key,
        token_response.access_token.clone(),
        expires_at_ms,
    );

    Ok(token_response.access_token)
}

/// Fetch JWT-SVID from SPIRE agent for token grant authentication.
///
/// This function connects to the local SPIRE agent via the Workload API and
/// requests a JWT-SVID with the specified audience. The JWT-SVID is used as
/// the client assertion in the `OAuth2` grant request.
async fn fetch_jwt_svid_for_token_grant(audience: &str) -> Result<String> {
    // Get SPIFFE Workload API socket path from environment
    let socket_path = std::env::var(sandbox_env::SPIFFE_WORKLOAD_API_SOCKET)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "{} not set — SPIFFE authentication unavailable for token grant",
                sandbox_env::SPIFFE_WORKLOAD_API_SOCKET
            )
        })?;

    let endpoint =
        crate::spiffe_endpoint::workload_api_endpoint(std::path::Path::new(&socket_path));

    // Connect to SPIRE agent
    let client = WorkloadApiClient::connect_to(&endpoint)
        .await
        .into_diagnostic()
        .wrap_err_with(|| {
            format!("failed to connect to SPIFFE Workload API endpoint {endpoint}")
        })?;

    // Fetch JWT-SVID with token service audience
    // None = use the sandbox's default SPIFFE ID
    client
        .fetch_jwt_token([audience], None)
        .await
        .into_diagnostic()
        .wrap_err("failed to fetch JWT-SVID for token grant")
}

/// Perform `OAuth2` JWT client assertion grant.
///
/// POSTs to the token endpoint with:
/// - `grant_type=client_credentials`
/// - `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-spiffe`
/// - `client_assertion=<JWT-SVID>` (client identity is in the JWT's `sub` claim)
/// - `audience=<audience>` (if provided)
/// - `scope=<scopes>` (if provided)
///
/// Note: `client_id` is NOT included - the client is identified by the `sub` claim
/// in the JWT-SVID itself.
async fn perform_token_grant(
    token_endpoint: &str,
    jwt_svid: &str,
    audience: &str,
    scopes: &[String],
) -> Result<TokenResponse> {
    let mut form_params = vec![
        ("grant_type", "client_credentials"),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe",
        ),
        ("client_assertion", jwt_svid),
    ];

    // Add audience if provided
    let audience_param;
    if !audience.is_empty() {
        audience_param = audience.to_string();
        form_params.push(("audience", &audience_param));
    }

    // Add scopes if provided
    let scope_param;
    if !scopes.is_empty() {
        scope_param = scopes.join(" ");
        form_params.push(("scope", &scope_param));
    }

    // POST to token endpoint
    let client = reqwest::Client::new();
    let response = client
        .post(token_endpoint)
        .form(&form_params)
        .send()
        .await
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to POST to token endpoint {token_endpoint}"))?;

    // Check response status
    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<failed to read response body>".to_string());
        return Err(miette::miette!(
            "{}",
            token_grant_failure_message(status, &body)
        ));
    }

    // Parse token response
    response
        .json::<TokenResponse>()
        .await
        .into_diagnostic()
        .wrap_err("failed to parse token response as JSON")
}

/// Derive the issuer/realm URL from a token endpoint URL.
///
/// For Keycloak token endpoints like:
///   `http://keycloak/realms/openshell/protocol/openid-connect/token`
/// Returns:
///   `http://keycloak/realms/openshell`
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

fn token_cache_key(
    provider_name: &str,
    token_endpoint: &str,
    jwt_svid_audience: &str,
    audience: &str,
    scopes: &[String],
) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}",
        provider_name,
        token_endpoint,
        jwt_svid_audience,
        audience,
        scopes.join(" ")
    )
}

fn token_grant_failure_message(status: reqwest::StatusCode, body: &str) -> String {
    let Ok(error_response) = serde_json::from_str::<OAuthErrorResponse>(body) else {
        return format!("token grant failed with status {status}");
    };

    let error = error_response
        .error
        .as_deref()
        .map(sanitize_oauth_error_field)
        .filter(|value| !value.is_empty());
    let description = error_response
        .error_description
        .as_deref()
        .map(sanitize_oauth_error_field)
        .filter(|value| !value.is_empty());

    match (error, description) {
        (Some(error), Some(description)) => {
            format!(
                "token grant failed with status {status}: error={error}; error_description={description}"
            )
        }
        (Some(error), None) => {
            format!("token grant failed with status {status}: error={error}")
        }
        (None, Some(description)) => {
            format!("token grant failed with status {status}: error_description={description}")
        }
        (None, None) => format!("token grant failed with status {status}"),
    }
}

fn sanitize_oauth_error_field(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .take(MAX_OAUTH_ERROR_FIELD_LEN)
        .collect::<String>()
        .trim()
        .to_string()
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
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

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
        cache_ttl_override: i64,
        expires_in: i64,
        grant_calls: Arc<AtomicUsize>,
    }

    async fn obtain_counted_test_token(input: CountedTokenGrantInput<'_>) -> Result<String> {
        obtain_provider_token_with_grant(
            ObtainProviderTokenInput {
                cache: input.cache,
                provider_name: input.provider_name,
                token_endpoint: input.token_endpoint,
                jwt_svid_audience: input.jwt_svid_audience,
                audience: input.audience,
                scopes: input.scopes,
                cache_ttl_override: input.cache_ttl_override,
            },
            move |_| {
                let grant_calls = input.grant_calls.clone();
                async move {
                    let call = grant_calls.fetch_add(1, Ordering::SeqCst) + 1;
                    Ok(TokenResponse {
                        access_token: format!("token-{call}"),
                        token_type: "Bearer".to_string(),
                        expires_in: input.expires_in,
                        scope: input.scopes.join(" "),
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
        cache_ttl_override: i64,
    ) -> Result<String> {
        obtain_provider_token_with_grant(
            ObtainProviderTokenInput {
                cache,
                provider_name,
                token_endpoint,
                jwt_svid_audience,
                audience,
                scopes,
                cache_ttl_override,
            },
            |_| async { Err(miette::miette!("grant should not be called on cache hit")) },
        )
        .await
    }

    #[test]
    fn test_derive_issuer_from_keycloak_token_endpoint() {
        let token_endpoint = "http://keycloak/realms/openshell/protocol/openid-connect/token";
        let issuer = derive_issuer_from_token_endpoint(token_endpoint);
        assert_eq!(issuer, "http://keycloak/realms/openshell");
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
            "http://keycloak/realms/openshell/protocol/openid-connect/token",
            "spiffe://custom-audience",
        );

        assert_eq!(audience, "spiffe://custom-audience");
    }

    #[test]
    fn token_cache_key_varies_by_resource_audience_and_scopes() {
        let base = token_cache_key(
            "alpha.default.svc.cluster.local\t80\t\tprovider:access_token",
            "http://keycloak/realms/openshell/protocol/openid-connect/token",
            "http://keycloak/realms/openshell",
            "alpha",
            &["alpha".to_string()],
        );
        let different_audience = token_cache_key(
            "alpha.default.svc.cluster.local\t80\t\tprovider:access_token",
            "http://keycloak/realms/openshell/protocol/openid-connect/token",
            "http://keycloak/realms/openshell",
            "delta",
            &["alpha".to_string()],
        );
        let different_scopes = token_cache_key(
            "alpha.default.svc.cluster.local\t80\t\tprovider:access_token",
            "http://keycloak/realms/openshell/protocol/openid-connect/token",
            "http://keycloak/realms/openshell",
            "alpha",
            &["delta".to_string()],
        );

        assert_ne!(base, different_audience);
        assert_ne!(base, different_scopes);
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
            cache_ttl_override: 0,
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
            0,
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
            cache_ttl_override: 0,
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
            cache_ttl_override: 0,
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
            cache_ttl_override: 0,
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

        let cache_key = token_cache_key(
            provider_name,
            token_endpoint,
            jwt_svid_audience,
            audience,
            &scopes,
        );
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
            cache_ttl_override: 0,
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
            cache_ttl_override: 60,
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
            60,
        )
        .await
        .expect("override should keep token cached");

        assert_eq!(first, "token-1");
        assert_eq!(second, "token-1");
        assert_eq!(grant_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn perform_token_grant_posts_jwt_assertion_and_parses_success_response() {
        let (endpoint, request) = token_endpoint_once(
            "200 OK",
            r#"{"access_token":"access-123","token_type":"Bearer","expires_in":42,"scope":"read write"}"#,
        )
        .await;
        let scopes = vec!["read".to_string(), "write".to_string()];

        let response = perform_token_grant(&endpoint, "jwt-svid-token", "api://resource", &scopes)
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
            request.form.get("grant_type").map(String::as_str),
            Some("client_credentials")
        );
        assert_eq!(
            request
                .form
                .get("client_assertion_type")
                .map(String::as_str),
            Some("urn:ietf:params:oauth:client-assertion-type:jwt-spiffe")
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
    async fn perform_token_grant_omits_empty_audience_and_scope() {
        let (endpoint, request) =
            token_endpoint_once("200 OK", r#"{"access_token":"access-123"}"#).await;

        let response = perform_token_grant(&endpoint, "jwt-svid-token", "", &[])
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

        let err = perform_token_grant(&endpoint, "jwt-svid-token", "api://resource", &[])
            .await
            .expect_err("token grant should fail on OAuth error");
        let request = request.await.expect("token endpoint task should finish");

        assert_eq!(
            request.form.get("audience").map(String::as_str),
            Some("api://resource")
        );
        assert_eq!(
            err.to_string(),
            "token grant failed with status 401 Unauthorized: error=invalid_client; error_description=bad jwt assertion"
        );
    }

    #[tokio::test]
    async fn perform_token_grant_does_not_echo_unstructured_error_body() {
        let (endpoint, request) = token_endpoint_once(
            "500 Internal Server Error",
            "internal stack trace with implementation details",
        )
        .await;

        let err = perform_token_grant(&endpoint, "jwt-svid-token", "", &[])
            .await
            .expect_err("token grant should fail on server error");
        let _request = request.await.expect("token endpoint task should finish");
        let message = err.to_string();

        assert_eq!(
            message,
            "token grant failed with status 500 Internal Server Error"
        );
        assert!(!message.contains("stack trace"));
        assert!(!message.contains("implementation details"));
    }

    #[tokio::test]
    async fn perform_token_grant_reports_malformed_success_json() {
        let (endpoint, request) = token_endpoint_once("200 OK", r#"{"access_token":42"#).await;

        let err = perform_token_grant(&endpoint, "jwt-svid-token", "", &[])
            .await
            .expect_err("malformed token response should fail");
        let _request = request.await.expect("token endpoint task should finish");

        assert!(
            err.to_string()
                .contains("failed to parse token response as JSON")
        );
    }

    #[test]
    fn token_grant_failure_message_reports_oauth_error_fields() {
        let message = token_grant_failure_message(
            reqwest::StatusCode::UNAUTHORIZED,
            r#"{"error":"invalid_client","error_description":"Invalid client credentials"}"#,
        );

        assert_eq!(
            message,
            "token grant failed with status 401 Unauthorized: error=invalid_client; error_description=Invalid client credentials"
        );
    }

    #[test]
    fn token_grant_failure_message_omits_unstructured_response_body() {
        let message = token_grant_failure_message(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            "internal error containing implementation details",
        );

        assert_eq!(
            message,
            "token grant failed with status 500 Internal Server Error"
        );
    }

    #[test]
    fn token_grant_failure_message_sanitizes_oauth_error_fields() {
        let long_description = "a".repeat(MAX_OAUTH_ERROR_FIELD_LEN + 20);
        let body =
            format!(r#"{{"error":"invalid_client\n","error_description":"{long_description}"}}"#);
        let message = token_grant_failure_message(reqwest::StatusCode::UNAUTHORIZED, &body);

        assert!(!message.contains('\n'));
        assert!(message.contains("error=invalid_client"));
        assert!(message.contains(&"a".repeat(MAX_OAUTH_ERROR_FIELD_LEN)));
        assert!(!message.contains(&"a".repeat(MAX_OAUTH_ERROR_FIELD_LEN + 1)));
    }
}
