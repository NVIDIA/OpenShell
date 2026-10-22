// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared `OAuth2` token request helpers.
//!
//! Provides [`post_oauth_token_grant`] (client credentials) and
//! [`post_oauth_token_exchange`] (RFC 8693 token exchange) — typed functions
//! that assemble form parameters, POST to a validated `OAuth2` token endpoint,
//! parse the JSON response, and validate the returned access token.

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use serde::Deserialize;

use crate::token_grant_failure::{
    REQUEST_ID_HEADER, TokenGrantFailure, TokenGrantFailureKind, TokenGrantStage,
};

pub const DEFAULT_CLIENT_ASSERTION_TYPE: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ERROR_CONTRACT: &str = "openshell.token-grant.v1";
const MAX_TOKEN_RESPONSE_BYTES: usize = 64 * 1024;
pub const DEFAULT_TOKEN_CACHE_TTL_SECONDS: i64 = 300;
pub const TOKEN_CACHE_EXPIRY_SKEW_SECONDS: i64 = 30;
pub const MAX_TOKEN_EXPIRES_IN_SECONDS: i64 = 3600;

/// HTTP client that authenticates HTTPS endpoints and never redirects assertions.
///
/// The private client fixes certificate/hostname verification, proxy policy and
/// redirects so callers cannot label an unverified response as authenticated.
pub struct TokenGrantClient {
    client: reqwest::Client,
}

impl TokenGrantClient {
    /// Build a verified client with a bounded request and connection lifetime.
    ///
    /// Construction errors contain no TLS configuration or dependency source.
    pub fn new() -> Result<Self, TokenGrantFailure> {
        Self::builder()
            .build()
            .map(|client| Self { client })
            .map_err(|_| {
                TokenGrantFailure::new(
                    TokenGrantFailureKind::Configuration,
                    TokenGrantStage::Configuration,
                )
            })
    }

    fn builder() -> reqwest::ClientBuilder {
        // A process may already have installed this provider. Installation is
        // idempotent for this caller and never relaxes peer authentication.
        openshell_crypto::tls::ensure_default_provider();
        reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(30))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
    }
}

/// `OAuth2` token response.
#[derive(Clone)]
pub struct OAuthTokenResponse {
    /// Validated token68 credential; never include this field in diagnostics.
    pub access_token: String,
    /// Lifetime in seconds, or zero when the endpoint omits the expiration.
    pub expires_in: i64,
    /// Token type returned by the endpoint, or empty when omitted.
    pub token_type: String,
}

impl fmt::Debug for OAuthTokenResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthTokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .field("token_type", &self.token_type)
            .finish()
    }
}

#[derive(Deserialize)]
struct RawTokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: i64,
    #[serde(default)]
    token_type: String,
}

#[derive(Deserialize)]
struct OAuthErrorResponse {
    error: Option<String>,
    openshell_error_contract: Option<String>,
}

async fn post_oauth_token_request(
    client: &TokenGrantClient,
    token_endpoint: &str,
    mut form_params: Vec<(&str, &str)>,
    audience: &str,
    scopes: &[String],
    request_id: Option<&str>,
) -> Result<OAuthTokenResponse, TokenGrantFailure> {
    let token_endpoint_url = parse_token_endpoint_url(token_endpoint)?;
    // The owned client verifies certificates and cannot follow a redirect to
    // another service. Plain HTTP is never evidence of service identity.
    let authenticated = token_endpoint_url.scheme() == "https";

    let audience_param;
    if !audience.is_empty() {
        audience_param = audience.to_string();
        form_params.push(("audience", &audience_param));
    }

    let scope_param;
    if !scopes.is_empty() {
        scope_param = scopes.join(" ");
        form_params.push(("scope", &scope_param));
    }

    let mut request = client.client.post(token_endpoint_url).form(&form_params);
    // The correlation ID is minted by the supervisor, never read from the
    // workload. A value that is not a valid header is omitted, not rewritten.
    if let Some(request_id) =
        request_id.and_then(|value| reqwest::header::HeaderValue::from_str(value).ok())
    {
        request = request.header(REQUEST_ID_HEADER, request_id);
    }
    let response = request
        .send()
        .await
        .map_err(|error| transport_failure(&error))?;
    let status = response.status();
    let body = read_bounded_body(response).await?;
    if !status.is_success() {
        let failure = classify_http_failure(status, &body, authenticated);
        // A token service can echo submitted credentials in `error` or
        // `error_description`, so the log keeps only the closed classification.
        tracing::warn!(
            request_id = request_id.unwrap_or("none"),
            upstream_http_status = status.as_u16(),
            failure_code = failure.code(),
            "token service rejected the grant"
        );
        return Err(failure);
    }

    // Raw parse failures can quote response bytes. Retain only a closed failure
    // value and never attach serde or HTTP errors as a diagnostic source.
    let raw = serde_json::from_slice::<RawTokenResponse>(&body)
        .map_err(|_| endpoint_failure(TokenGrantFailureKind::Unclassified, status))?;
    validate_access_token(&raw.access_token)
        .map_err(|error| error.with_upstream_status(status.as_u16()))?;
    Ok(OAuthTokenResponse {
        access_token: raw.access_token,
        expires_in: raw.expires_in,
        token_type: raw.token_type,
    })
}

/// Client credentials grant form fields.
pub struct TokenGrantParams<'a> {
    /// Secret JWT client assertion sent only to the configured endpoint.
    pub client_assertion: &'a str,
    pub client_assertion_type: &'a str,
    pub audience: &'a str,
    pub scopes: &'a [String],
}

/// POST a client credentials grant request to an `OAuth2` token endpoint.
///
/// Applies the default for `client_assertion_type` and conditionally includes
/// `audience` and `scope`. A `request_id` is sent as the
/// `x-openshell-request-id` header so the token service can log the exchange.
pub async fn post_oauth_token_grant(
    client: &TokenGrantClient,
    token_endpoint: &str,
    params: &TokenGrantParams<'_>,
    request_id: Option<&str>,
) -> Result<OAuthTokenResponse, TokenGrantFailure> {
    let client_assertion_type = effective_client_assertion_type(params.client_assertion_type);
    let form_params = vec![
        ("grant_type", "client_credentials"),
        ("client_assertion_type", client_assertion_type),
        ("client_assertion", params.client_assertion),
    ];
    post_oauth_token_request(
        client,
        token_endpoint,
        form_params,
        params.audience,
        params.scopes,
        request_id,
    )
    .await
}

/// RFC 8693 token-exchange form fields.
pub struct TokenExchangeParams<'a> {
    /// Secret JWT client assertion sent only to the configured endpoint.
    pub client_assertion: &'a str,
    pub client_assertion_type: &'a str,
    /// Secret subject credential to exchange for a resource token.
    pub subject_token: &'a str,
    pub subject_token_type: &'a str,
    pub audience: &'a str,
    pub scopes: &'a [String],
    pub requested_token_type: &'a str,
}

/// POST an RFC 8693 token-exchange request to an `OAuth2` token endpoint.
///
/// Assembles the standard token-exchange form fields, applies defaults for
/// `client_assertion_type`, `subject_token_type`, and `requested_token_type`,
/// and conditionally includes `audience` and `scope`. A `request_id` is sent
/// as the `x-openshell-request-id` header.
pub async fn post_oauth_token_exchange(
    client: &TokenGrantClient,
    token_endpoint: &str,
    params: &TokenExchangeParams<'_>,
    request_id: Option<&str>,
) -> Result<OAuthTokenResponse, TokenGrantFailure> {
    let client_assertion_type = effective_client_assertion_type(params.client_assertion_type);
    let subject_token_type = effective_token_type(params.subject_token_type);
    let requested_token_type = effective_token_type(params.requested_token_type);
    let form_params = vec![
        ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
        ("client_assertion_type", client_assertion_type),
        ("client_assertion", params.client_assertion),
        ("subject_token", params.subject_token),
        ("subject_token_type", subject_token_type),
        ("requested_token_type", requested_token_type),
    ];
    post_oauth_token_request(
        client,
        token_endpoint,
        form_params,
        params.audience,
        params.scopes,
        request_id,
    )
    .await
}

pub fn effective_client_assertion_type(client_assertion_type: &str) -> &str {
    if client_assertion_type.trim().is_empty() {
        DEFAULT_CLIENT_ASSERTION_TYPE
    } else {
        client_assertion_type
    }
}

pub fn effective_token_type(token_type: &str) -> &str {
    if token_type.trim().is_empty() {
        ACCESS_TOKEN_TYPE
    } else {
        token_type
    }
}

/// Cache lifetime for a granted access token.
///
/// A configured override is used exactly, including zero to disable caching.
/// Otherwise the response lifetime (capped, or a default when omitted) is
/// shortened by a fixed expiry skew, with a one-second floor.
pub fn token_cache_ttl(cache_ttl_override: Option<Duration>, expires_in: i64) -> Duration {
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

/// Validate the configured endpoint before acquiring any workload credentials.
///
/// HTTPS is accepted; plain HTTP is limited to loopback and Kubernetes service
/// hosts and never authenticates a precise token-service error classification.
pub fn parse_token_endpoint_url(token_endpoint: &str) -> Result<reqwest::Url, TokenGrantFailure> {
    let invalid = TokenGrantFailure::new(
        TokenGrantFailureKind::Configuration,
        TokenGrantStage::Configuration,
    );
    let url = reqwest::Url::parse(token_endpoint).map_err(|_| invalid)?;
    if token_endpoint_transport_allowed(&url) {
        return Ok(url);
    }
    Err(invalid)
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

/// Reject credentials that cannot safely occupy a token68 HTTP header value.
pub fn validate_access_token(token: &str) -> Result<(), TokenGrantFailure> {
    if token.is_empty() || !is_token68(token) {
        return Err(TokenGrantFailure::new(
            TokenGrantFailureKind::Unclassified,
            TokenGrantStage::TokenEndpoint,
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

fn endpoint_failure(kind: TokenGrantFailureKind, status: reqwest::StatusCode) -> TokenGrantFailure {
    TokenGrantFailure::new(kind, TokenGrantStage::TokenEndpoint)
        .with_upstream_status(status.as_u16())
}

fn transport_failure(error: &reqwest::Error) -> TokenGrantFailure {
    let kind = if error.is_timeout() {
        TokenGrantFailureKind::Timeout
    } else if error.is_connect() {
        TokenGrantFailureKind::Unavailable
    } else {
        TokenGrantFailureKind::Unclassified
    };
    TokenGrantFailure::new(kind, TokenGrantStage::TokenEndpoint)
}

async fn read_bounded_body(mut response: reqwest::Response) -> Result<Vec<u8>, TokenGrantFailure> {
    let status = response.status();
    let oversized = endpoint_failure(TokenGrantFailureKind::Unclassified, status);
    if response
        .content_length()
        .is_some_and(|length| length > MAX_TOKEN_RESPONSE_BYTES as u64)
    {
        return Err(oversized);
    }
    let mut body = Vec::with_capacity(MAX_TOKEN_RESPONSE_BYTES);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| transport_failure(&error).with_upstream_status(status.as_u16()))?
    {
        // Content-Length may be absent or inaccurate. Check before allocation
        // so a streamed response cannot grow our retained buffer past the cap.
        if chunk.len() > MAX_TOKEN_RESPONSE_BYTES.saturating_sub(body.len()) {
            return Err(oversized);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn classify_http_failure(
    status: reqwest::StatusCode,
    body: &[u8],
    authenticated: bool,
) -> TokenGrantFailure {
    let default = if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        TokenGrantFailureKind::Unavailable
    } else {
        TokenGrantFailureKind::Unclassified
    };
    let Ok(response) = serde_json::from_slice::<OAuthErrorResponse>(body) else {
        return endpoint_failure(default, status);
    };
    if response.openshell_error_contract.as_deref() != Some(ERROR_CONTRACT) {
        return endpoint_failure(default, status);
    }
    let (kind, expected_status) = match response.error.as_deref() {
        Some("provider_authorization_required") => (
            TokenGrantFailureKind::ProviderAuthorizationRequired,
            status == reqwest::StatusCode::CONFLICT,
        ),
        Some("workload_identity_rejected") => (
            TokenGrantFailureKind::WorkloadIdentityRejected,
            matches!(status.as_u16(), 401 | 403),
        ),
        Some("configuration_error") => (
            TokenGrantFailureKind::Configuration,
            status == reqwest::StatusCode::BAD_REQUEST,
        ),
        _ => return endpoint_failure(default, status),
    };
    // An adopted extension is meaningful only from an authenticated service and
    // with its defined status. Contradictions cannot claim availability either.
    if !authenticated || !expected_status {
        return endpoint_failure(TokenGrantFailureKind::Unclassified, status);
    }
    endpoint_failure(kind, status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[derive(Debug)]
    struct CapturedRequest {
        form: HashMap<String, String>,
        request_id: Option<String>,
    }

    fn test_client() -> TokenGrantClient {
        TokenGrantClient {
            client: TokenGrantClient::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("test client"),
        }
    }

    async fn capture_request<S: AsyncRead + Unpin>(stream: &mut S) -> CapturedRequest {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 512];
        let mut expected_len = None;
        loop {
            let n = stream.read(&mut chunk).await.expect("read");
            assert!(n > 0);
            buf.extend_from_slice(&chunk[..n]);
            if expected_len.is_none()
                && let Some(header_end) = header_end(&buf)
            {
                let headers = String::from_utf8_lossy(&buf[..header_end]);
                let cl = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                expected_len = Some(header_end + cl);
            }
            if expected_len.is_some_and(|len| buf.len() >= len) {
                break;
            }
        }
        let header_end = header_end(&buf).expect("request headers");
        let headers = String::from_utf8_lossy(&buf[..header_end]);
        let request_id = headers.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case(REQUEST_ID_HEADER)
                .then(|| value.trim().to_string())
        });
        let form_body = String::from_utf8_lossy(&buf[header_end..]);
        CapturedRequest {
            form: parse_form_body(&form_body),
            request_id,
        }
    }

    async fn send_response<S: AsyncWrite + Unpin>(stream: &mut S, status: &str, body: &str) {
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len(),
        );
        stream.write_all(response.as_bytes()).await.expect("write");
        stream.shutdown().await.expect("shutdown response");
    }

    async fn token_endpoint_once(
        status: &str,
        body: &str,
    ) -> (String, tokio::task::JoinHandle<CapturedRequest>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind token endpoint");
        let addr = listener.local_addr().expect("token endpoint local addr");
        let status = status.to_string();
        let body = body.to_string();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let request = capture_request(&mut stream).await;
            send_response(&mut stream, &status, &body).await;
            request
        });
        (format!("http://{addr}/token"), handle)
    }

    async fn tls_token_endpoint_once(
        status: &str,
        body: &str,
    ) -> (
        String,
        TokenGrantClient,
        tokio::task::JoinHandle<CapturedRequest>,
    ) {
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = openshell_crypto::pki::generate_keypair().expect("CA key");
        let ca = openshell_crypto::pki::self_signed(ca_params, &ca_key).expect("CA certificate");
        let key = openshell_crypto::pki::generate_keypair().expect("server key");
        let params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
        let certificate = openshell_crypto::pki::signed_by(params, &key, &ca, &ca_key)
            .expect("server certificate");
        let config = openshell_crypto::tls::server_builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.der().clone()],
                rustls::pki_types::PrivateKeyDer::try_from(
                    key.serialize_der().expect("export server key"),
                )
                .expect("server key"),
            )
            .expect("server config");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("TLS bind");
        let port = listener.local_addr().expect("TLS addr").port();
        let status = status.to_string();
        let body = body.to_string();
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("TLS accept");
            let mut stream = acceptor.accept(socket).await.expect("TLS handshake");
            let request = capture_request(&mut stream).await;
            send_response(&mut stream, &status, &body).await;
            request
        });
        let client = TokenGrantClient::builder()
            .add_root_certificate(reqwest::Certificate::from_der(ca.der()).expect("CA"))
            .build()
            .expect("trusted test client");
        (
            format!("https://localhost:{port}/token"),
            TokenGrantClient { client },
            task,
        )
    }

    async fn token_endpoint_redirect_once(location: &str) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind token endpoint");
        let addr = listener.local_addr().expect("token endpoint local addr");
        let location = location.to_string();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 512];
            let _ = stream.read(&mut buf).await;
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
            stream.write_all(response.as_bytes()).await.expect("write");
        });
        (format!("http://{addr}/token"), handle)
    }

    fn header_end(buf: &[u8]) -> Option<usize> {
        buf.windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|idx| idx + 4)
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

    fn empty_grant_params() -> TokenGrantParams<'static> {
        TokenGrantParams {
            client_assertion: "jwt-svid-token",
            client_assertion_type: "",
            audience: "",
            scopes: &[],
        }
    }

    fn adopted_failure_body(code: &str) -> String {
        format!(r#"{{"error":"{code}","openshell_error_contract":"{ERROR_CONTRACT}"}}"#)
    }

    #[tokio::test]
    async fn adopted_signal_requires_verified_https() {
        let body = adopted_failure_body("provider_authorization_required");
        let (endpoint, client, request) = tls_token_endpoint_once("409 Conflict", &body).await;
        let failure = post_oauth_token_grant(&client, &endpoint, &empty_grant_params(), None)
            .await
            .expect_err("adopted failure");
        request.await.expect("TLS fixture");
        assert_eq!(
            failure.kind(),
            TokenGrantFailureKind::ProviderAuthorizationRequired
        );

        // An untrusted certificate never reaches the body: the client refuses
        // the handshake, so the service cannot assert any cause.
        let (endpoint, _, request) = tls_token_endpoint_once("409 Conflict", &body).await;
        let failure =
            post_oauth_token_grant(&test_client(), &endpoint, &empty_grant_params(), None)
                .await
                .expect_err("untrusted certificate");
        request.abort();
        assert_eq!(failure.kind(), TokenGrantFailureKind::Unavailable);
        assert_eq!(failure.upstream_status(), None);

        // Plain HTTP carries no service identity, so the same body is unclassified.
        let (endpoint, request) = token_endpoint_once("409 Conflict", &body).await;
        let failure =
            post_oauth_token_grant(&test_client(), &endpoint, &empty_grant_params(), None)
                .await
                .expect_err("unauthenticated failure");
        request.await.expect("HTTP fixture");
        assert_eq!(failure.kind(), TokenGrantFailureKind::Unclassified);
        assert_eq!(failure.upstream_status(), Some(409));
    }

    #[test]
    fn successful_token_response_debug_redacts_the_access_token() {
        let response = OAuthTokenResponse {
            access_token: "TOKEN_SECRET_CANARY".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 60,
        };
        assert!(!format!("{response:?}").contains("TOKEN_SECRET_CANARY"));
    }

    #[tokio::test]
    async fn request_and_body_timeouts_keep_observed_status() {
        for after_headers in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let address = listener.local_addr().expect("addr");
            let (release, wait) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("accept");
                capture_request(&mut stream).await;
                if after_headers {
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")
                        .await
                        .expect("response headers");
                }
                let _ = wait.await;
            });
            let client = TokenGrantClient {
                client: TokenGrantClient::builder()
                    .timeout(Duration::from_millis(100))
                    .build()
                    .expect("timeout client"),
            };
            let endpoint = format!("http://{address}/token");
            let failure = post_oauth_token_grant(&client, &endpoint, &empty_grant_params(), None)
                .await
                .expect_err("bounded timeout");
            release.send(()).expect("release fixture");
            server.await.expect("timeout fixture");
            assert_eq!(failure.kind(), TokenGrantFailureKind::Timeout);
            assert_eq!(failure.upstream_status(), after_headers.then_some(200));
        }
    }

    #[tokio::test]
    async fn response_body_is_bounded_for_declared_and_chunked_lengths() {
        let body = "X".repeat(MAX_TOKEN_RESPONSE_BYTES + 1);
        for response in [
            // The declared length alone must suffice for rejection.
            format!(
                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            ),
            format!(
                "HTTP/1.1 503 Service Unavailable\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
                body.len()
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let endpoint = format!("http://{}/token", listener.local_addr().expect("addr"));
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("accept");
                capture_request(&mut stream).await;
                // Rejection can close the reader before the fixture finishes.
                let _ = stream.write_all(response.as_bytes()).await;
            });
            let failure =
                post_oauth_token_grant(&test_client(), &endpoint, &empty_grant_params(), None)
                    .await
                    .expect_err("bounded response");
            server.await.expect("bound fixture");
            assert_eq!(failure.kind(), TokenGrantFailureKind::Unclassified);
            assert_eq!(failure.upstream_status(), Some(503));
        }

        // Pad to the exact bound. A format width cannot exceed u16::MAX.
        let mut body = r#"{"access_token":"access-token"}"#.to_string();
        body.extend(std::iter::repeat_n(
            ' ',
            MAX_TOKEN_RESPONSE_BYTES - body.len(),
        ));
        let (endpoint, server) = token_endpoint_once("200 OK", &body).await;
        post_oauth_token_grant(&test_client(), &endpoint, &empty_grant_params(), None)
            .await
            .expect("exact bound is accepted");
        server.await.expect("bound fixture");
    }

    #[tokio::test]
    async fn posts_form_params_and_parses_success_response() {
        let (endpoint, request) = token_endpoint_once(
            "200 OK",
            r#"{"access_token":"access-123","token_type":"Bearer","expires_in":42}"#,
        )
        .await;
        let client = test_client();

        let response = post_oauth_token_grant(&client, &endpoint, &empty_grant_params(), None)
            .await
            .expect("should succeed");
        let request = request.await.expect("endpoint task");

        assert_eq!(response.access_token, "access-123");
        assert_eq!(response.expires_in, 42);
        assert_eq!(response.token_type, "Bearer");
        assert_eq!(
            request.form.get("grant_type").map(String::as_str),
            Some("client_credentials")
        );
        assert_eq!(
            request.form.get("client_assertion").map(String::as_str),
            Some("jwt-svid-token")
        );
    }

    #[tokio::test]
    async fn rejects_malformed_access_token() {
        for body in [
            r#"{"access_token":"access-123\r\nX-Injected: yes"}"#,
            r#"{"access_token":42"#,
            r#"{"access_token":"TOKEN_SECRET_CANARY","access_token":"SECOND_SECRET_CANARY"}"#,
        ] {
            let (endpoint, request) = token_endpoint_once("200 OK", body).await;
            let err =
                post_oauth_token_grant(&test_client(), &endpoint, &empty_grant_params(), None)
                    .await
                    .expect_err("malformed token should fail");
            let _ = request.await;

            assert_eq!(err.kind(), TokenGrantFailureKind::Unclassified);
            assert_eq!(err.upstream_status(), Some(200));
        }
    }

    #[tokio::test]
    async fn does_not_follow_redirects() {
        let (endpoint, handle) = token_endpoint_redirect_once("http://127.0.0.1:1/stolen").await;
        let client = test_client();

        let err = post_oauth_token_grant(&client, &endpoint, &empty_grant_params(), None)
            .await
            .expect_err("redirect should fail");
        let _ = handle.await;

        assert_eq!(err.to_string(), "dynamic token grant failed");
        assert_eq!(err.upstream_status(), Some(302));
    }

    #[tokio::test]
    async fn does_not_echo_unstructured_error_body() {
        let (endpoint, request) = token_endpoint_once(
            "500 Internal Server Error",
            "internal stack trace with implementation details",
        )
        .await;
        let client = test_client();

        let err = post_oauth_token_grant(&client, &endpoint, &empty_grant_params(), None)
            .await
            .expect_err("should fail on server error");
        let _ = request.await;
        let message = err.to_string();

        assert_eq!(message, "dynamic token grant failed");
        assert_eq!(err.kind(), TokenGrantFailureKind::Unavailable);
        assert_eq!(err.upstream_status(), Some(500));
        assert!(!message.contains("stack trace"));
    }

    #[tokio::test]
    async fn token_exchange_posts_rfc8693_form_fields() {
        let (endpoint, request) = token_endpoint_once(
            "200 OK",
            r#"{"access_token":"exchanged-token","token_type":"Bearer","expires_in":60}"#,
        )
        .await;
        let client = test_client();
        let scopes = vec!["read".to_string(), "write".to_string()];

        let response = post_oauth_token_exchange(
            &client,
            &endpoint,
            &TokenExchangeParams {
                client_assertion: "jwt-svid-token",
                client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe",
                subject_token: "subject-access-token",
                subject_token_type: ACCESS_TOKEN_TYPE,
                audience: "api://resource",
                scopes: &scopes,
                requested_token_type: "urn:ietf:params:oauth:token-type:id_token",
            },
            Some("0b6e9c3a-5d4f-4b1e-9a2c-7f8e1d2c3b4a"),
        )
        .await
        .expect("token exchange should succeed");
        let request = request.await.expect("endpoint task");

        assert_eq!(response.access_token, "exchanged-token");
        assert_eq!(response.expires_in, 60);
        assert_eq!(
            request.request_id.as_deref(),
            Some("0b6e9c3a-5d4f-4b1e-9a2c-7f8e1d2c3b4a")
        );
        assert_eq!(
            request.form.get("grant_type").map(String::as_str),
            Some(TOKEN_EXCHANGE_GRANT_TYPE)
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
            request.form.get("subject_token").map(String::as_str),
            Some("subject-access-token")
        );
        assert_eq!(
            request.form.get("subject_token_type").map(String::as_str),
            Some(ACCESS_TOKEN_TYPE)
        );
        assert_eq!(
            request.form.get("audience").map(String::as_str),
            Some("api://resource")
        );
        assert_eq!(
            request.form.get("scope").map(String::as_str),
            Some("read write")
        );
        assert_eq!(
            request.form.get("requested_token_type").map(String::as_str),
            Some("urn:ietf:params:oauth:token-type:id_token")
        );
    }

    #[tokio::test]
    async fn token_exchange_applies_defaults_for_empty_type_fields() {
        let (endpoint, request) =
            token_endpoint_once("200 OK", r#"{"access_token":"exchanged-token"}"#).await;
        let client = test_client();

        post_oauth_token_exchange(
            &client,
            &endpoint,
            &TokenExchangeParams {
                client_assertion: "jwt-svid-token",
                client_assertion_type: "",
                subject_token: "subject-token",
                subject_token_type: "",
                audience: "",
                scopes: &[],
                requested_token_type: "",
            },
            // A value that is not a valid header is omitted, not rewritten.
            Some("invalid\nrequest-id"),
        )
        .await
        .expect("token exchange should succeed");
        let request = request.await.expect("endpoint task");

        assert_eq!(
            request
                .form
                .get("client_assertion_type")
                .map(String::as_str),
            Some(DEFAULT_CLIENT_ASSERTION_TYPE)
        );
        assert_eq!(
            request.form.get("subject_token_type").map(String::as_str),
            Some(ACCESS_TOKEN_TYPE)
        );
        assert_eq!(
            request.form.get("requested_token_type").map(String::as_str),
            Some(ACCESS_TOKEN_TYPE)
        );
        assert!(!request.form.contains_key("audience"));
        assert!(!request.form.contains_key("scope"));
        assert_eq!(request.request_id, None);
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
            parse_token_endpoint_url(endpoint).expect("should be allowed");
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
                "should be rejected: {endpoint}"
            );
        }
    }

    #[test]
    fn validate_access_token_accepts_token68_values() {
        for token in [
            "abcXYZ123-._~+/",
            "eyJhbGciOiJSUzI1NiJ9.payload.sig",
            "token==",
        ] {
            validate_access_token(token).expect("should be accepted");
        }
    }

    #[test]
    fn validate_access_token_rejects_non_token68_values() {
        for token in [
            "",
            "token with spaces",
            "token\r\nX-Injected: yes",
            "token\u{7f}",
            "tokené",
            "token=continued",
            "==",
        ] {
            let err = validate_access_token(token).expect_err("should be rejected");
            assert_eq!(err.to_string(), "dynamic token grant failed");
            assert_eq!(err.kind(), TokenGrantFailureKind::Unclassified);
        }
    }

    #[test]
    fn http_failures_classify_only_consistent_authenticated_contracts() {
        use TokenGrantFailureKind as Kind;
        let not_json = "not JSON".to_string();
        let bare = r#"{"error":"invalid_client"}"#.to_string();
        let unadopted = r#"{"error":"provider_authorization_required"}"#.to_string();
        let provider = adopted_failure_body("provider_authorization_required");
        let workload = adopted_failure_body("workload_identity_rejected");
        let configuration = adopted_failure_body("configuration_error");
        let cases = [
            // Contract codes with their defined status over verified HTTPS.
            (&provider, 409, true, Kind::ProviderAuthorizationRequired),
            (&workload, 401, true, Kind::WorkloadIdentityRejected),
            (&workload, 403, true, Kind::WorkloadIdentityRejected),
            (&configuration, 400, true, Kind::Configuration),
            // Without verified HTTPS or with a contradicting status, nothing is claimed.
            (&provider, 409, false, Kind::Unclassified),
            (&provider, 503, true, Kind::Unclassified),
            (&workload, 409, true, Kind::Unclassified),
            // Without the contract, only availability survives.
            (&bare, 401, true, Kind::Unclassified),
            (&unadopted, 409, true, Kind::Unclassified),
            (&not_json, 403, true, Kind::Unclassified),
            (&not_json, 429, true, Kind::Unavailable),
            (&bare, 500, true, Kind::Unavailable),
            (&unadopted, 503, false, Kind::Unavailable),
        ];
        for (body, status, authenticated, expected) in cases {
            let failure = classify_http_failure(
                reqwest::StatusCode::from_u16(status).expect("status"),
                body.as_bytes(),
                authenticated,
            );
            assert_eq!(failure.kind(), expected, "body={body}, status={status}");
            assert_eq!(failure.upstream_status(), Some(status));
            assert_eq!(failure.stage(), TokenGrantStage::TokenEndpoint);
        }
    }
}
