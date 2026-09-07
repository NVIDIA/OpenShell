// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared `OAuth2` token request helpers.
//!
//! Provides [`post_oauth_token_grant`] (client credentials) and
//! [`post_oauth_token_exchange`] (RFC 8693 token exchange) — typed functions
//! that assemble form parameters, POST to a validated `OAuth2` token endpoint,
//! parse the JSON response, and validate the returned access token.

use std::net::IpAddr;

use miette::{IntoDiagnostic, Result, WrapErr};
use serde::Deserialize;

pub const DEFAULT_CLIENT_ASSERTION_TYPE: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

const MAX_OAUTH_ERROR_FIELD_LEN: usize = 256;

/// `OAuth2` token response.
#[derive(Debug, Clone)]
pub struct OAuthTokenResponse {
    pub access_token: String,
    pub expires_in: i64,
    pub token_type: String,
}

#[derive(Debug, Deserialize)]
struct RawTokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: i64,
    #[serde(default)]
    token_type: String,
}

#[derive(Debug, Deserialize)]
struct OAuthErrorResponse {
    error: Option<String>,
    error_description: Option<String>,
}

async fn post_oauth_token_request(
    client: &reqwest::Client,
    token_endpoint: &str,
    mut form_params: Vec<(&str, &str)>,
    audience: &str,
    scopes: &[String],
) -> Result<OAuthTokenResponse> {
    let token_endpoint_url = parse_token_endpoint_url(token_endpoint)?;

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

    let response = client
        .post(token_endpoint_url)
        .form(&form_params)
        .send()
        .await
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to POST to token endpoint {token_endpoint}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<failed to read response body>".to_string());
        return Err(miette::miette!("{}", failure_message(status, &body)));
    }

    let raw = response
        .json::<RawTokenResponse>()
        .await
        .into_diagnostic()
        .wrap_err("failed to parse token response as JSON")?;
    validate_access_token(&raw.access_token)?;
    Ok(OAuthTokenResponse {
        access_token: raw.access_token,
        expires_in: raw.expires_in,
        token_type: raw.token_type,
    })
}

/// Client credentials grant form fields.
pub struct TokenGrantParams<'a> {
    pub client_assertion: &'a str,
    pub client_assertion_type: &'a str,
    pub audience: &'a str,
    pub scopes: &'a [String],
}

/// POST a client credentials grant request to an `OAuth2` token endpoint.
///
/// Applies the default for `client_assertion_type` and conditionally includes
/// `audience` and `scope`.
pub async fn post_oauth_token_grant(
    client: &reqwest::Client,
    token_endpoint: &str,
    params: &TokenGrantParams<'_>,
) -> Result<OAuthTokenResponse> {
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
    )
    .await
}

/// RFC 8693 token-exchange form fields.
pub struct TokenExchangeParams<'a> {
    pub client_assertion: &'a str,
    pub client_assertion_type: &'a str,
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
/// and conditionally includes `audience` and `scope`.
pub async fn post_oauth_token_exchange(
    client: &reqwest::Client,
    token_endpoint: &str,
    params: &TokenExchangeParams<'_>,
) -> Result<OAuthTokenResponse> {
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

fn failure_message(status: reqwest::StatusCode, body: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[derive(Debug)]
    struct CapturedRequest {
        form: HashMap<String, String>,
    }

    fn test_client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("test client")
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
            let header_end = header_end(&buf).unwrap();
            let form_body = String::from_utf8_lossy(&buf[header_end..]).to_string();
            let form = parse_form_body(&form_body);
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len(),
            );
            stream.write_all(response.as_bytes()).await.expect("write");
            CapturedRequest { form }
        });
        (format!("http://{addr}/token"), handle)
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

    #[tokio::test]
    async fn posts_form_params_and_parses_success_response() {
        let (endpoint, request) = token_endpoint_once(
            "200 OK",
            r#"{"access_token":"access-123","token_type":"Bearer","expires_in":42}"#,
        )
        .await;
        let client = test_client();

        let response = post_oauth_token_grant(&client, &endpoint, &empty_grant_params())
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

        let err = post_oauth_token_grant(&client, &endpoint, &empty_grant_params())
            .await
            .expect_err("malformed token should fail");
        let _ = request.await;

        assert_eq!(
            err.to_string(),
            "token grant returned a malformed access token"
        );
    }

    #[tokio::test]
    async fn does_not_follow_redirects() {
        let (endpoint, handle) = token_endpoint_redirect_once("http://127.0.0.1:1/stolen").await;
        let client = test_client();

        let err = post_oauth_token_grant(&client, &endpoint, &empty_grant_params())
            .await
            .expect_err("redirect should fail");
        let _ = handle.await;

        assert_eq!(err.to_string(), "token grant failed with status 302 Found");
    }

    #[tokio::test]
    async fn reports_sanitized_oauth_error() {
        let (endpoint, request) = token_endpoint_once(
            "401 Unauthorized",
            r#"{"error":"invalid_client","error_description":"bad assertion"}"#,
        )
        .await;
        let client = test_client();

        let err = post_oauth_token_grant(&client, &endpoint, &empty_grant_params())
            .await
            .expect_err("should fail on OAuth error");
        let _ = request.await;

        assert_eq!(
            err.to_string(),
            "token grant failed with status 401 Unauthorized: error=invalid_client; error_description=bad assertion"
        );
    }

    #[tokio::test]
    async fn does_not_echo_unstructured_error_body() {
        let (endpoint, request) = token_endpoint_once(
            "500 Internal Server Error",
            "internal stack trace with implementation details",
        )
        .await;
        let client = test_client();

        let err = post_oauth_token_grant(&client, &endpoint, &empty_grant_params())
            .await
            .expect_err("should fail on server error");
        let _ = request.await;
        let message = err.to_string();

        assert_eq!(
            message,
            "token grant failed with status 500 Internal Server Error"
        );
        assert!(!message.contains("stack trace"));
    }

    #[tokio::test]
    async fn reports_malformed_success_json() {
        let (endpoint, request) = token_endpoint_once("200 OK", r#"{"access_token":42"#).await;
        let client = test_client();

        let err = post_oauth_token_grant(&client, &endpoint, &empty_grant_params())
            .await
            .expect_err("should fail on malformed JSON");
        let _ = request.await;

        assert!(
            err.to_string()
                .contains("failed to parse token response as JSON")
        );
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
        )
        .await
        .expect("token exchange should succeed");
        let request = request.await.expect("endpoint task");

        assert_eq!(response.access_token, "exchanged-token");
        assert_eq!(response.expires_in, 60);
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
            assert_eq!(
                err.to_string(),
                "token grant returned a malformed access token"
            );
        }
    }

    #[test]
    fn failure_message_reports_oauth_error_fields() {
        let message = failure_message(
            reqwest::StatusCode::UNAUTHORIZED,
            r#"{"error":"invalid_client","error_description":"Invalid client credentials"}"#,
        );
        assert_eq!(
            message,
            "token grant failed with status 401 Unauthorized: error=invalid_client; error_description=Invalid client credentials"
        );
    }

    #[test]
    fn failure_message_omits_unstructured_response_body() {
        let message = failure_message(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            "internal error containing implementation details",
        );
        assert_eq!(
            message,
            "token grant failed with status 500 Internal Server Error"
        );
    }

    #[test]
    fn failure_message_sanitizes_oauth_error_fields() {
        let long_description = "a".repeat(MAX_OAUTH_ERROR_FIELD_LEN + 20);
        let body =
            format!(r#"{{"error":"invalid_client\n","error_description":"{long_description}"}}"#);
        let message = failure_message(reqwest::StatusCode::UNAUTHORIZED, &body);
        assert!(!message.contains('\n'));
        assert!(message.contains("error=invalid_client"));
        assert!(message.contains(&"a".repeat(MAX_OAUTH_ERROR_FIELD_LEN)));
        assert!(!message.contains(&"a".repeat(MAX_OAUTH_ERROR_FIELD_LEN + 1)));
    }
}
