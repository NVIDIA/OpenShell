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
//! - `cache_ttl_seconds` — Cache override (0 = use `expires_in` from response)
//!
//! ## Environment
//!
//! Requires `OPENSHELL_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET` to be set (path to
//! the SPIFFE Workload API socket).

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_core::sandbox_env;
use serde::Deserialize;
use spiffe::WorkloadApiClient;

/// Token cache shared across all provider token grants.
static TOKEN_CACHE: LazyLock<TokenCache> = LazyLock::new(TokenCache::new);
static TOKEN_GRANT_HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(30))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("token grant HTTP client configuration should be valid")
});
const MAX_OAUTH_ERROR_FIELD_LEN: usize = 256;
const DEFAULT_TOKEN_CACHE_TTL_SECONDS: i64 = 300;
const TOKEN_CACHE_EXPIRY_SKEW_SECONDS: i64 = 30;
const MAX_TOKEN_EXPIRES_IN_SECONDS: i64 = 3600;
const DEFAULT_CLIENT_ASSERTION_TYPE: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

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
/// * `client_assertion_type` — Optional `OAuth2` client assertion type
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
    client_assertion_type: &str,
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
            client_assertion_type,
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
            perform_token_grant(
                token_endpoint,
                &jwt_svid,
                client_assertion_type,
                audience,
                scopes,
            )
            .await
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
    // For Keycloak: https://auth.example.com/realms/openshell/protocol/openid-connect/token
    //           -> https://auth.example.com/realms/openshell
    let jwt_audience = effective_jwt_svid_audience(input.token_endpoint, input.jwt_svid_audience);
    let cache_key = token_cache_key(
        input.provider_name,
        input.token_endpoint,
        &jwt_audience,
        effective_client_assertion_type(input.client_assertion_type),
        input.audience,
        input.scopes,
    );

    // Check cache first
    if let Some(cached) = input.cache.get(&cache_key) {
        return Ok(cached);
    }

    let token_response = grant(jwt_audience).await?;
    validate_access_token(&token_response.access_token)?;

    let cache_ttl_seconds =
        token_cache_ttl_seconds(input.cache_ttl_override, token_response.expires_in);
    let expires_at_ms = current_time_ms().saturating_add(cache_ttl_seconds.saturating_mul(1000));

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
    let socket_path = provider_spiffe_workload_api_socket_from_env()?;

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

fn provider_spiffe_workload_api_socket_from_env() -> Result<String> {
    std::env::var(sandbox_env::PROVIDER_SPIFFE_WORKLOAD_API_SOCKET)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            miette::miette!(
                "{} not set — SPIFFE authentication unavailable for token grant",
                sandbox_env::PROVIDER_SPIFFE_WORKLOAD_API_SOCKET
            )
        })
}

/// Perform `OAuth2` JWT client assertion grant.
///
/// POSTs to the token endpoint with:
/// - `grant_type=client_credentials`
/// - `client_assertion_type=<configured assertion type>`
/// - `client_assertion=<JWT-SVID>` (client identity is in the JWT's `sub` claim)
/// - `audience=<audience>` (if provided)
/// - `scope=<scopes>` (if provided)
///
/// Note: `client_id` is NOT included - the client is identified by the `sub` claim
/// in the JWT-SVID itself.
async fn perform_token_grant(
    token_endpoint: &str,
    jwt_svid: &str,
    client_assertion_type: &str,
    audience: &str,
    scopes: &[String],
) -> Result<TokenResponse> {
    let token_endpoint_url = parse_token_endpoint_url(token_endpoint)?;
    let client_assertion_type = effective_client_assertion_type(client_assertion_type);
    let mut form_params = vec![
        ("grant_type", "client_credentials"),
        ("client_assertion_type", client_assertion_type),
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
    let response = TOKEN_GRANT_HTTP_CLIENT
        .post(token_endpoint_url)
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
    let token_response = response
        .json::<TokenResponse>()
        .await
        .into_diagnostic()
        .wrap_err("failed to parse token response as JSON")?;
    validate_access_token(&token_response.access_token)?;
    Ok(token_response)
}

fn parse_token_endpoint_url(token_endpoint: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(token_endpoint)
        .into_diagnostic()
        .wrap_err("token_endpoint must be an absolute URL")?;
    if token_endpoint_transport_allowed(&url) {
        return Ok(url);
    }

    Err(miette::miette!(
        "token_endpoint must use https, except http for loopback or in-cluster service hosts"
    ))
}

fn token_endpoint_transport_allowed(url: &reqwest::Url) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => url
            .host_str()
            .is_some_and(|host| is_loopback_host(host) || is_kubernetes_service_host(host)),
        _ => false,
    }
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_matches(['[', ']']);
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(IpAddr::V6(v6)) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
        Err(_) => false,
    }
}

fn is_kubernetes_service_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let labels = host.split('.').collect::<Vec<_>>();
    let is_service_name = labels.len() == 3 && labels[2] == "svc";
    let is_cluster_local_service =
        labels.len() == 5 && labels[2] == "svc" && labels[3] == "cluster" && labels[4] == "local";
    (is_service_name || is_cluster_local_service) && labels.iter().all(|label| !label.is_empty())
}

pub fn validate_access_token(token: &str) -> Result<()> {
    if token.is_empty() || !is_token68(token) {
        return Err(miette::miette!(
            "token grant returned a malformed access token"
        ));
    }
    Ok(())
}

fn is_token68(token: &str) -> bool {
    let mut padding_started = false;
    let mut saw_value = false;
    for byte in token.bytes() {
        if byte == b'=' {
            padding_started = true;
            continue;
        }
        if padding_started || !is_token68_value_byte(byte) {
            return false;
        }
        saw_value = true;
    }
    saw_value
}

fn is_token68_value_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
}

fn token_cache_ttl_seconds(cache_ttl_override: i64, expires_in: i64) -> i64 {
    if cache_ttl_override > 0 {
        return cache_ttl_override;
    }

    let ttl = if expires_in > 0 {
        expires_in.min(MAX_TOKEN_EXPIRES_IN_SECONDS)
    } else {
        DEFAULT_TOKEN_CACHE_TTL_SECONDS
    };

    ttl.saturating_sub(TOKEN_CACHE_EXPIRY_SKEW_SECONDS).max(1)
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

fn effective_client_assertion_type(client_assertion_type: &str) -> &str {
    if client_assertion_type.trim().is_empty() {
        DEFAULT_CLIENT_ASSERTION_TYPE
    } else {
        client_assertion_type
    }
}

fn token_cache_key(
    provider_name: &str,
    token_endpoint: &str,
    jwt_svid_audience: &str,
    client_assertion_type: &str,
    audience: &str,
    scopes: &[String],
) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}",
        provider_name,
        token_endpoint,
        jwt_svid_audience,
        client_assertion_type,
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
                client_assertion_type: DEFAULT_CLIENT_ASSERTION_TYPE,
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
                client_assertion_type: DEFAULT_CLIENT_ASSERTION_TYPE,
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
    fn validate_access_token_accepts_token68_values() {
        for token in [
            "abcXYZ123-._~+/",
            "eyJhbGciOiJSUzI1NiJ9.payload.sig",
            "token==",
        ] {
            validate_access_token(token).expect("token68 bearer token should be accepted");
        }
    }

    #[test]
    fn validate_access_token_rejects_header_injection_and_non_token68_values() {
        for token in [
            "",
            "token with spaces",
            "token\r\nX-Injected: yes",
            "token\u{7f}",
            "tokené",
            "token=continued",
            "==",
        ] {
            let err = validate_access_token(token)
                .expect_err("malformed bearer token should be rejected");
            assert_eq!(
                err.to_string(),
                "token grant returned a malformed access token"
            );
        }
    }

    #[test]
    fn token_endpoint_url_allows_https_loopback_and_in_cluster_http() {
        for endpoint in [
            "https://auth.example.com/token",
            "http://127.0.0.1:8080/token",
            "http://[::1]:8080/token",
            "http://token-issuer.default.svc.cluster.local/token",
            "http://token-issuer.default.svc/token",
        ] {
            parse_token_endpoint_url(endpoint).expect("token endpoint should be allowed");
        }
    }

    #[test]
    fn token_endpoint_url_rejects_plain_http_non_cluster_hosts() {
        for endpoint in [
            "http://auth.example.com/token",
            "http://keycloak/realms/openshell/protocol/openid-connect/token",
            "http://token-issuer.default.svc.evil.com/token",
            "ftp://auth.example.com/token",
            "/relative/token",
        ] {
            assert!(
                parse_token_endpoint_url(endpoint).is_err(),
                "token endpoint should be rejected: {endpoint}"
            );
        }
    }

    #[test]
    fn token_cache_key_varies_by_resource_audience_and_scopes() {
        let base = token_cache_key(
            "alpha.default.svc.cluster.local\t80\t\tprovider:access_token",
            "https://auth.example.com/realms/openshell/protocol/openid-connect/token",
            "https://auth.example.com/realms/openshell",
            DEFAULT_CLIENT_ASSERTION_TYPE,
            "alpha",
            &["alpha".to_string()],
        );
        let different_audience = token_cache_key(
            "alpha.default.svc.cluster.local\t80\t\tprovider:access_token",
            "https://auth.example.com/realms/openshell/protocol/openid-connect/token",
            "https://auth.example.com/realms/openshell",
            DEFAULT_CLIENT_ASSERTION_TYPE,
            "delta",
            &["alpha".to_string()],
        );
        let different_scopes = token_cache_key(
            "alpha.default.svc.cluster.local\t80\t\tprovider:access_token",
            "https://auth.example.com/realms/openshell/protocol/openid-connect/token",
            "https://auth.example.com/realms/openshell",
            DEFAULT_CLIENT_ASSERTION_TYPE,
            "alpha",
            &["delta".to_string()],
        );
        let different_assertion_type = token_cache_key(
            "alpha.default.svc.cluster.local\t80\t\tprovider:access_token",
            "https://auth.example.com/realms/openshell/protocol/openid-connect/token",
            "https://auth.example.com/realms/openshell",
            "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe",
            "alpha",
            &["alpha".to_string()],
        );

        assert_ne!(base, different_audience);
        assert_ne!(base, different_scopes);
        assert_ne!(base, different_assertion_type);
    }

    #[test]
    fn token_cache_ttl_uses_override_without_endpoint_skew() {
        assert_eq!(token_cache_ttl_seconds(120, 10), 120);
        assert_eq!(token_cache_ttl_seconds(120, i64::MAX), 120);
    }

    #[test]
    fn token_cache_ttl_skews_default_and_response_expires_in() {
        assert_eq!(
            token_cache_ttl_seconds(0, 0),
            DEFAULT_TOKEN_CACHE_TTL_SECONDS - TOKEN_CACHE_EXPIRY_SKEW_SECONDS
        );
        assert_eq!(token_cache_ttl_seconds(0, 60), 30);
        assert_eq!(token_cache_ttl_seconds(0, 10), 1);
    }

    #[test]
    fn token_cache_ttl_clamps_large_response_expires_in() {
        assert_eq!(
            token_cache_ttl_seconds(0, i64::MAX),
            MAX_TOKEN_EXPIRES_IN_SECONDS - TOKEN_CACHE_EXPIRY_SKEW_SECONDS
        );
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
            DEFAULT_CLIENT_ASSERTION_TYPE,
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
    async fn obtain_provider_token_rejects_malformed_token_before_cache() {
        let cache = TokenCache::new();
        let scopes = vec!["read".to_string()];
        let provider_name = "api.example.test\t443\t/v1/**\tprovider:access_token";
        let token_endpoint = "https://auth.example.com/token";
        let jwt_svid_audience = "https://auth.example.com";
        let audience = "api://resource";

        let err = obtain_provider_token_with_grant(
            ObtainProviderTokenInput {
                cache: &cache,
                provider_name,
                token_endpoint,
                jwt_svid_audience,
                client_assertion_type: DEFAULT_CLIENT_ASSERTION_TYPE,
                audience,
                scopes: &scopes,
                cache_ttl_override: 0,
            },
            |_| async {
                Ok(TokenResponse {
                    access_token: "access-123\r\nX-Injected: yes".to_string(),
                    token_type: "Bearer".to_string(),
                    expires_in: 60,
                    scope: "read".to_string(),
                })
            },
        )
        .await
        .expect_err("malformed access token should fail before caching");

        let cache_key = token_cache_key(
            provider_name,
            token_endpoint,
            jwt_svid_audience,
            DEFAULT_CLIENT_ASSERTION_TYPE,
            audience,
            &scopes,
        );

        assert_eq!(
            err.to_string(),
            "token grant returned a malformed access token"
        );
        assert!(
            cache.get(&cache_key).is_none(),
            "malformed access token must not be cached"
        );
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

        let response =
            perform_token_grant(&endpoint, "jwt-svid-token", "", "api://resource", &scopes)
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

        let err = perform_token_grant(&endpoint, "jwt-svid-token", "", "", &[])
            .await
            .expect_err("malformed access token should fail closed");
        let _request = request.await.expect("token endpoint task should finish");

        assert_eq!(
            err.to_string(),
            "token grant returned a malformed access token"
        );
    }

    #[tokio::test]
    async fn perform_token_grant_does_not_follow_redirects() {
        let (endpoint, request) = token_endpoint_redirect_once("http://127.0.0.1:1/stolen").await;

        let err = perform_token_grant(&endpoint, "jwt-svid-token", "", "", &[])
            .await
            .expect_err("redirect response should fail closed");
        let _request = request.await.expect("token endpoint task should finish");

        assert_eq!(err.to_string(), "token grant failed with status 302 Found");
    }

    #[tokio::test]
    async fn perform_token_grant_omits_empty_audience_and_scope() {
        let (endpoint, request) =
            token_endpoint_once("200 OK", r#"{"access_token":"access-123"}"#).await;

        let response = perform_token_grant(&endpoint, "jwt-svid-token", "", "", &[])
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

        let err = perform_token_grant(&endpoint, "jwt-svid-token", "", "api://resource", &[])
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

        let err = perform_token_grant(&endpoint, "jwt-svid-token", "", "", &[])
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

        let err = perform_token_grant(&endpoint, "jwt-svid-token", "", "", &[])
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
