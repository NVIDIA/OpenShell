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

/// JWT bearer client-assertion type used when the caller supplies no override.
pub const DEFAULT_CLIENT_ASSERTION_TYPE: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/// RFC 8693 access-token type used for unspecified exchange token types.
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ERROR_CONTRACT: &str = "openshell.token-grant.v1";
const MAX_TOKEN_RESPONSE_BYTES: usize = 64 * 1024;

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
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
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
        return Err(classify_http_failure(status, &body, authenticated));
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
    /// Assertion format; an empty value selects the JWT bearer default.
    pub client_assertion_type: &'a str,
    /// Optional resource audience carried in the grant form.
    pub audience: &'a str,
    /// Optional scopes carried in the grant form.
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
    /// Assertion format; an empty value selects the JWT bearer default.
    pub client_assertion_type: &'a str,
    /// Secret subject credential to exchange for a resource token.
    pub subject_token: &'a str,
    /// Subject format; an empty value selects the access-token default.
    pub subject_token_type: &'a str,
    /// Optional resource audience carried in the exchange form.
    pub audience: &'a str,
    /// Optional scopes carried in the exchange form.
    pub scopes: &'a [String],
    /// Requested result format; an empty value selects the access-token default.
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

/// Select the JWT bearer assertion type when no nonblank override is supplied.
pub fn effective_client_assertion_type(client_assertion_type: &str) -> &str {
    if client_assertion_type.trim().is_empty() {
        DEFAULT_CLIENT_ASSERTION_TYPE
    } else {
        client_assertion_type
    }
}

/// Select the RFC 8693 access-token type when no nonblank override is supplied.
pub fn effective_token_type(token_type: &str) -> &str {
    if token_type.trim().is_empty() {
        ACCESS_TOKEN_TYPE
    } else {
        token_type
    }
}

fn parse_token_endpoint_url(token_endpoint: &str) -> Result<reqwest::Url, TokenGrantFailure> {
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

/// Validate the configured endpoint before acquiring any workload credentials.
///
/// HTTPS is accepted; plain HTTP is limited to loopback and Kubernetes service
/// hosts and never authenticates a precise token-service error classification.
pub fn validate_token_endpoint(token_endpoint: &str) -> Result<(), TokenGrantFailure> {
    parse_token_endpoint_url(token_endpoint).map(|_| ())
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
    use std::error::Error;
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
        reqwest::Certificate,
        tokio::task::JoinHandle<Option<CapturedRequest>>,
    ) {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().expect("CA key");
        let ca = ca_params.self_signed(&ca_key).expect("CA certificate");
        let key = rcgen::KeyPair::generate().expect("server key");
        let certificate = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("server params")
            .signed_by(&key, &ca, &ca_key)
            .expect("server certificate");
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.der().clone()],
                rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der())
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
            // A rejected trust root/hostname must fail during the handshake,
            // before the server can receive the secret-bearing grant request.
            let Ok(mut stream) = acceptor.accept(socket).await else {
                return None;
            };
            let request = capture_request(&mut stream).await;
            send_response(&mut stream, &status, &body).await;
            Some(request)
        });
        (
            format!("https://localhost:{port}/token"),
            reqwest::Certificate::from_der(ca.der()).expect("trusted CA"),
            task,
        )
    }

    fn trusted_test_client(root: reqwest::Certificate) -> TokenGrantClient {
        TokenGrantClient {
            client: TokenGrantClient::builder()
                .timeout(Duration::from_secs(5))
                .add_root_certificate(root)
                .build()
                .expect("trusted test client"),
        }
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

    fn exchange_params() -> TokenExchangeParams<'static> {
        TokenExchangeParams {
            client_assertion: "ASSERTION_SECRET_CANARY",
            client_assertion_type: "",
            subject_token: "SUBJECT_SECRET_CANARY",
            subject_token_type: "",
            audience: "",
            scopes: &[],
            requested_token_type: "",
        }
    }

    fn assert_generic_failure(failure: TokenGrantFailure) {
        assert_eq!(failure.to_string(), "dynamic token grant failed");
        assert_eq!(format!("{failure:?}"), "dynamic token grant failed");
        assert!(failure.source().is_none());
        let report = miette::Report::new(failure);
        let rendered = format!("{report:?}");
        for forbidden in [
            "CANARY",
            "provider_authorization_required",
            "workload_identity_rejected",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "diagnostics must stay generic"
            );
        }
    }

    #[tokio::test]
    async fn verified_https_signal_is_preserved_for_both_grants() {
        let cases = [
            (
                "409 Conflict",
                "provider_authorization_required",
                TokenGrantFailureKind::ProviderAuthorizationRequired,
            ),
            (
                "401 Unauthorized",
                "workload_identity_rejected",
                TokenGrantFailureKind::WorkloadIdentityRejected,
            ),
            (
                "403 Forbidden",
                "workload_identity_rejected",
                TokenGrantFailureKind::WorkloadIdentityRejected,
            ),
            (
                "400 Bad Request",
                "configuration_error",
                TokenGrantFailureKind::Configuration,
            ),
        ];
        for (status, code, expected) in cases {
            for exchange in [false, true] {
                let body = format!(
                    r#"{{"error":"{code}","openshell_error_contract":"{ERROR_CONTRACT}","error_description":"DESCRIPTION_SECRET_CANARY"}}"#
                );
                let (endpoint, root, request) = tls_token_endpoint_once(status, &body).await;
                let client = trusted_test_client(root);
                let failure = if exchange {
                    post_oauth_token_exchange(&client, &endpoint, &exchange_params(), None).await
                } else {
                    post_oauth_token_grant(&client, &endpoint, &empty_grant_params(), None).await
                }
                .expect_err("adopted failure");
                let request = request
                    .await
                    .expect("TLS fixture")
                    .expect("authenticated request");
                assert_eq!(request.form.contains_key("subject_token"), exchange);
                assert_eq!(failure.kind(), expected);
                assert_eq!(failure.stage(), TokenGrantStage::TokenEndpoint);
                assert_generic_failure(failure);
            }
        }
    }

    #[tokio::test]
    async fn plain_http_cannot_assert_adopted_failure_for_either_grant() {
        for (status, code) in [
            ("409 Conflict", "provider_authorization_required"),
            ("401 Unauthorized", "workload_identity_rejected"),
            ("400 Bad Request", "configuration_error"),
        ] {
            for exchange in [false, true] {
                let body = format!(
                    r#"{{"error":"{code}","openshell_error_contract":"{ERROR_CONTRACT}","error_description":"DESCRIPTION_SECRET_CANARY"}}"#
                );
                let (endpoint, request) = token_endpoint_once(status, &body).await;
                let client = test_client();
                let failure = if exchange {
                    post_oauth_token_exchange(&client, &endpoint, &exchange_params(), None).await
                } else {
                    post_oauth_token_grant(&client, &endpoint, &empty_grant_params(), None).await
                }
                .expect_err("unauthenticated failure");
                request.await.expect("HTTP fixture");
                assert_eq!(failure.kind(), TokenGrantFailureKind::Unclassified);
                assert_generic_failure(failure);
            }
        }
    }

    #[tokio::test]
    async fn tls_requires_a_trusted_certificate_and_matching_hostname() {
        for trust_certificate in [false, true] {
            let body = r#"{"error":"provider_authorization_required","openshell_error_contract":"openshell.token-grant.v1"}"#;
            let (endpoint, root, request) = tls_token_endpoint_once("409 Conflict", body).await;
            let (client, endpoint) = if trust_certificate {
                (
                    trusted_test_client(root),
                    endpoint.replace("localhost", "127.0.0.1"),
                )
            } else {
                (test_client(), endpoint)
            };
            let failure = post_oauth_token_exchange(&client, &endpoint, &exchange_params(), None)
                .await
                .expect_err("TLS must authenticate the configured server");
            assert_eq!(failure.kind(), TokenGrantFailureKind::Unavailable);
            assert_eq!(failure.upstream_status(), None);
            assert!(request.await.expect("TLS fixture").is_none());
            assert_generic_failure(failure);
        }
    }

    #[tokio::test]
    async fn secret_canaries_in_errors_and_endpoint_components_never_survive() {
        for body in [
            r#"{"error":"ERROR_SECRET_CANARY","error_description":"DESCRIPTION_SECRET_CANARY"}"#,
            r#"{"error":"invalid_client","error_description":"ASSERTION_SECRET_CANARY TOKEN_SECRET_CANARY"}"#,
            "RAW_BODY_SECRET_CANARY",
        ] {
            let (endpoint, request) = token_endpoint_once("401 Unauthorized", body).await;
            let endpoint = endpoint.replace(
                "http://",
                "http://USER_SECRET_CANARY:PASSWORD_SECRET_CANARY@",
            ) + "?credential=QUERY_SECRET_CANARY#FRAGMENT_SECRET_CANARY";
            let failure =
                post_oauth_token_exchange(&test_client(), &endpoint, &exchange_params(), None)
                    .await
                    .expect_err("safe endpoint failure");
            request.await.expect("HTTP fixture");
            assert_eq!(failure.kind(), TokenGrantFailureKind::Unclassified);
            assert_generic_failure(failure);
        }
        for endpoint in [
            "not a URL ENDPOINT_SECRET_CANARY",
            "ftp://USER_SECRET_CANARY:PASSWORD_SECRET_CANARY@localhost/token?QUERY_SECRET_CANARY",
        ] {
            let failure =
                post_oauth_token_grant(&test_client(), endpoint, &empty_grant_params(), None)
                    .await
                    .expect_err("invalid endpoint");
            assert_eq!(failure.kind(), TokenGrantFailureKind::Configuration);
            assert_generic_failure(failure);
        }
    }

    #[tokio::test]
    async fn malformed_success_fields_are_generic_and_never_return_a_token() {
        for body in [
            "{}",
            r#"{"access_token":"TOKEN_SECRET_CANARY","token_type":null}"#,
            r#"{"access_token":"TOKEN_SECRET_CANARY","token_type":"Bearer","expires_in":"DURATION_SECRET_CANARY"}"#,
            r#"{"access_token":"TOKEN_SECRET_CANARY","access_token":"SECOND_SECRET_CANARY","token_type":"Bearer"}"#,
            r#"{"access_token":"TOKEN_SECRET_CANARY","token_type":"Bearer","token_type":"Bearer"}"#,
            r#"{"access_token":"TOKEN_SECRET_CANARY","token_type":"Bearer","expires_in":1,"expires_in":1}"#,
            r#"{"access_token":"","token_type":"Bearer"}"#,
        ] {
            let (endpoint, request) = token_endpoint_once("200 OK", body).await;
            let failure =
                post_oauth_token_grant(&test_client(), &endpoint, &empty_grant_params(), None)
                    .await
                    .expect_err("malformed success");
            request.await.expect("HTTP fixture");
            assert_eq!(failure.kind(), TokenGrantFailureKind::Unclassified);
            assert_eq!(failure.upstream_status(), Some(200));
            assert_generic_failure(failure);
        }
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
    async fn request_and_body_timeouts_drop_sources_and_keep_observed_status() {
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
            let endpoint = format!("http://{address}/token?QUERY_SECRET_CANARY");
            let failure = post_oauth_token_grant(&client, &endpoint, &empty_grant_params(), None)
                .await
                .expect_err("bounded timeout");
            release.send(()).expect("release fixture");
            server.await.expect("timeout fixture");
            assert_eq!(failure.kind(), TokenGrantFailureKind::Timeout);
            assert_eq!(failure.upstream_status(), after_headers.then_some(200));
            assert_generic_failure(failure);
        }
    }

    async fn raw_token_endpoint_once(response: Vec<u8>) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            capture_request(&mut stream).await;
            // Bound rejection can close the reader before an oversized fixture
            // finishes writing. That is the behavior this fixture exercises.
            let _ = stream.write_all(&response).await;
        });
        (format!("http://{address}/token"), server)
    }

    #[tokio::test]
    async fn response_body_bound_applies_to_success_errors_and_chunked_bodies() {
        let body = "X".repeat(MAX_TOKEN_RESPONSE_BYTES + 1);
        for status in ["200 OK", "409 Conflict", "503 Service Unavailable"] {
            for chunked in [false, true] {
                let response = if chunked {
                    format!(
                        "HTTP/1.1 {status}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
                        body.len()
                    )
                } else {
                    // The oversized declared length must suffice for rejection,
                    // without waiting for a body the server does not provide.
                    format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                };
                let (endpoint, server) = raw_token_endpoint_once(response.into_bytes()).await;
                let failure =
                    post_oauth_token_grant(&test_client(), &endpoint, &empty_grant_params(), None)
                        .await
                        .expect_err("bounded response");
                server.await.expect("bound fixture");
                assert_eq!(failure.kind(), TokenGrantFailureKind::Unclassified);
                assert!(failure.upstream_status().is_some());
                assert_generic_failure(failure);
            }
        }
    }

    #[tokio::test]
    async fn exact_body_bound_preserves_success_and_default_expiration() {
        let mut body = r#"{"access_token":"access-token","token_type":"Bearer"}"#.to_string();
        body.extend(std::iter::repeat_n(
            ' ',
            MAX_TOKEN_RESPONSE_BYTES - body.len(),
        ));
        let (endpoint, server) = token_endpoint_once("200 OK", &body).await;
        let response =
            post_oauth_token_grant(&test_client(), &endpoint, &empty_grant_params(), None)
                .await
                .expect("exact bound is accepted");
        server.await.expect("bound fixture");
        assert_eq!(response.access_token, "access-token");
        assert_eq!(response.expires_in, 0);
    }

    #[tokio::test]
    async fn body_read_errors_discard_partial_secret_content() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\nPARTIAL_BODY_SECRET_CANARY".to_vec();
        let (endpoint, server) = raw_token_endpoint_once(response).await;
        let failure =
            post_oauth_token_grant(&test_client(), &endpoint, &empty_grant_params(), None)
                .await
                .expect_err("truncated body");
        server.await.expect("read fixture");
        assert_eq!(failure.kind(), TokenGrantFailureKind::Unclassified);
        assert_eq!(failure.upstream_status(), Some(200));
        assert_generic_failure(failure);
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
        let (endpoint, request) = token_endpoint_once(
            "200 OK",
            r#"{"access_token":"access-123\r\nX-Injected: yes"}"#,
        )
        .await;
        let client = test_client();

        let err = post_oauth_token_grant(&client, &endpoint, &empty_grant_params(), None)
            .await
            .expect_err("malformed token should fail");
        let _ = request.await;

        assert_eq!(err.to_string(), "dynamic token grant failed");
        assert_eq!(err.kind(), TokenGrantFailureKind::Unclassified);
        assert_eq!(err.upstream_status(), Some(200));
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
    async fn discards_oauth_error_descriptions_and_unrecognized_codes() {
        let (endpoint, request) = token_endpoint_once(
            "401 Unauthorized",
            r#"{"error":"invalid_client","error_description":"bad assertion"}"#,
        )
        .await;
        let client = test_client();

        let err = post_oauth_token_grant(&client, &endpoint, &empty_grant_params(), None)
            .await
            .expect_err("should fail on OAuth error");
        let _ = request.await;

        assert_eq!(err.to_string(), "dynamic token grant failed");
        assert_eq!(err.kind(), TokenGrantFailureKind::Unclassified);
        assert_eq!(err.upstream_status(), Some(401));
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
    async fn success_accepts_any_token_type_and_lifetime() {
        // The supervisor and gateway place the token by the profile's auth
        // style, so token_type and a nonpositive lifetime never block a grant.
        for body in [
            r#"{"access_token":"access-123"}"#,
            r#"{"access_token":"access-123","token_type":"N_A"}"#,
            r#"{"access_token":"access-123","token_type":"Bearer","expires_in":-1}"#,
        ] {
            let (endpoint, server) = token_endpoint_once("200 OK", body).await;
            let response =
                post_oauth_token_grant(&test_client(), &endpoint, &empty_grant_params(), None)
                    .await
                    .expect(body);
            server.await.expect("token endpoint task");
            assert_eq!(response.access_token, "access-123");
        }
    }

    #[tokio::test]
    async fn reports_malformed_success_json() {
        let (endpoint, request) = token_endpoint_once("200 OK", r#"{"access_token":42"#).await;
        let client = test_client();

        let err = post_oauth_token_grant(&client, &endpoint, &empty_grant_params(), None)
            .await
            .expect_err("should fail on malformed JSON");
        let _ = request.await;

        assert_eq!(err.to_string(), "dynamic token grant failed");
        assert_eq!(err.kind(), TokenGrantFailureKind::Unclassified);
        assert_eq!(err.upstream_status(), Some(200));
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
            None,
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
    fn response_matrix_requires_consistent_authenticated_extension() {
        let cases = [
            (
                "provider_authorization_required",
                409,
                TokenGrantFailureKind::ProviderAuthorizationRequired,
            ),
            (
                "workload_identity_rejected",
                401,
                TokenGrantFailureKind::WorkloadIdentityRejected,
            ),
            (
                "workload_identity_rejected",
                403,
                TokenGrantFailureKind::WorkloadIdentityRejected,
            ),
            (
                "configuration_error",
                400,
                TokenGrantFailureKind::Configuration,
            ),
        ];
        for (code, valid_status, expected) in cases {
            let body =
                format!(r#"{{"error":"{code}","openshell_error_contract":"{ERROR_CONTRACT}"}}"#);
            for status in [300, 400, 401, 403, 409, 429, 500, 503, 599] {
                for authenticated in [false, true] {
                    let failure = classify_http_failure(
                        reqwest::StatusCode::from_u16(status).expect("status"),
                        body.as_bytes(),
                        authenticated,
                    );
                    // Workload rejection permits both authentication denial codes.
                    let status_matches = status == valid_status
                        || (code == "workload_identity_rejected" && matches!(status, 401 | 403));
                    assert_eq!(
                        failure.kind(),
                        if authenticated && status_matches {
                            expected
                        } else {
                            TokenGrantFailureKind::Unclassified
                        },
                        "code={code}, status={status}, authenticated={authenticated}"
                    );
                    assert_eq!(failure.upstream_status(), Some(status));
                    assert_eq!(failure.stage(), TokenGrantStage::TokenEndpoint);
                }
            }
        }
    }

    #[test]
    fn malformed_ambiguous_and_unknown_signals_preserve_only_availability() {
        let bodies = [
            "not JSON",
            "{}",
            r#"{"error":null}"#,
            r#"{"error":42}"#,
            r#"{"error":"invalid_client"}"#,
            r#"{"error":"invalid_grant","error_description":"provider_authorization_required"}"#,
            r#"{"error":"provider_authorization_required"}"#,
            r#"{"error":"provider_authorization_required","openshell_error_contract":"unknown"}"#,
            r#"{"error":"unknown","openshell_error_contract":"openshell.token-grant.v1"}"#,
            r#"{"error":"provider_authorization_required","error":"provider_authorization_required","openshell_error_contract":"openshell.token-grant.v1"}"#,
            r#"{"error":"provider_authorization_required","openshell_error_contract":"openshell.token-grant.v1","openshell_error_contract":"openshell.token-grant.v1"}"#,
            r#"{"error":"provider_authorization_required","openshell_error_contract":true}"#,
            r#"{"error":"provider_authorization_required","openshell_error_contract":"openshell.token-grant.v1"} trailing"#,
        ];
        for body in bodies {
            for status in [302, 400, 401, 403, 409, 422, 429, 500, 503, 599] {
                for authenticated in [false, true] {
                    let failure = classify_http_failure(
                        reqwest::StatusCode::from_u16(status).expect("status"),
                        body.as_bytes(),
                        authenticated,
                    );
                    let expected = if status == 429 || (500..600).contains(&status) {
                        TokenGrantFailureKind::Unavailable
                    } else {
                        TokenGrantFailureKind::Unclassified
                    };
                    assert_eq!(failure.kind(), expected, "body={body}, status={status}");
                    assert_eq!(failure.upstream_status(), Some(status));
                }
            }
        }
    }
}
