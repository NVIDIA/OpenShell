// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! GitHub App installation credentials. Signing material never leaves the gateway.

use super::{
    MintedCredential, RefreshFailure, StoredProviderCredentialRefreshState, current_time_ms,
    is_loopback_host, max_lifetime_seconds, required_material,
};
use reqwest::{StatusCode, Url, header::HeaderMap};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;
use tonic::Status;

const INSTALLATION_PATH: &str = "/app/installations/{installation_id}/access_tokens";
const INSTALLATION_ID_PLACEHOLDER: &str = "{installation_id}";
// GitHub may include metadata for up to 500 repositories in its response.
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Serialize)]
struct InstallationRequest {
    repository_ids: Vec<u64>,
    permissions: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct AppClaims<'a> {
    iss: &'a str,
    iat: i64,
    exp: i64,
}

#[derive(Deserialize)]
struct InstallationResponse {
    token: String,
    expires_at: String,
}

fn installation_request(material: &HashMap<String, String>) -> Result<InstallationRequest, Status> {
    let repository_ids: Vec<u64> =
        serde_json::from_str(&required_material(material, "repository_ids")?).map_err(|_| {
            Status::invalid_argument("repository_ids must be a JSON array of positive integers")
        })?;
    if repository_ids.is_empty()
        || repository_ids.len() > 500
        || repository_ids
            .iter()
            .any(|id| *id == 0 || *id > i64::MAX as u64)
        || repository_ids.iter().collect::<HashSet<_>>().len() != repository_ids.len()
    {
        return Err(Status::invalid_argument(
            "repository_ids must contain 1 to 500 distinct positive int64 IDs",
        ));
    }
    let permissions: BTreeMap<String, String> =
        serde_json::from_str(&required_material(material, "permissions")?).map_err(|_| {
            Status::invalid_argument(
                "permissions must be a JSON object of permission names and levels",
            )
        })?;
    if permissions.is_empty()
        || permissions.iter().any(|(name, level)| {
            name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
                || !matches!(level.as_str(), "read" | "write" | "admin")
        })
    {
        return Err(Status::invalid_argument(
            "permissions must explicitly name permissions with read, write, or admin levels",
        ));
    }
    Ok(InstallationRequest {
        repository_ids,
        permissions,
    })
}

fn installation_url(token_url: &str, material: &HashMap<String, String>) -> Result<Url, Status> {
    let installation_id = required_material(material, "installation_id")?
        .parse::<u64>()
        .ok()
        .filter(|id| *id > 0 && i64::try_from(*id).is_ok())
        .ok_or_else(|| Status::invalid_argument("installation_id must be a positive int64 ID"))?;
    if !token_url.ends_with(INSTALLATION_PATH)
        || token_url.matches(INSTALLATION_ID_PLACEHOLDER).count() != 1
    {
        return Err(Status::invalid_argument(format!(
            "profile token_url must end with {INSTALLATION_PATH}"
        )));
    }
    let url =
        Url::parse(&token_url.replace(INSTALLATION_ID_PLACEHOLDER, &installation_id.to_string()))
            .map_err(|_| Status::invalid_argument("profile token_url must be an absolute URL"))?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https"
            || (url.scheme() == "http" && url.host_str().is_some_and(is_loopback_host)))
    {
        return Err(Status::invalid_argument(
            "profile token_url requires HTTPS without userinfo, query, or fragment (loopback HTTP is allowed for tests)",
        ));
    }
    Ok(url)
}

pub fn validate_configuration(
    material: &HashMap<String, String>,
    token_url: &str,
) -> Result<(), Status> {
    // Reject misspelled scope fields and endpoint overrides rather than silently
    // ignoring them. Repository and permission restrictions are always explicit.
    if material.keys().any(|key| {
        !matches!(
            key.as_str(),
            "client_id"
                | "installation_id"
                | "private_key"
                | "repository_ids"
                | "permissions"
                | "refresh_before_seconds"
                | "max_lifetime_seconds"
        )
    }) {
        return Err(Status::invalid_argument(
            "unsupported github_app_installation material key",
        ));
    }
    required_material(material, "client_id")?;
    installation_request(material)?;
    installation_url(token_url, material)?;
    let private_key = required_material(material, "private_key")?;
    jsonwebtoken::EncodingKey::from_rsa_pem(private_key.as_bytes()).map_err(|_| {
        Status::invalid_argument("github_app_installation private_key must be RSA PEM")
    })?;
    Ok(())
}

pub(super) async fn mint(
    state: &StoredProviderCredentialRefreshState,
) -> Result<MintedCredential, RefreshFailure> {
    validate_configuration(&state.material, &state.token_url)?;
    let url = installation_url(&state.token_url, &state.material)?;
    let body = installation_request(&state.material)?;
    let client_id = required_material(&state.material, "client_id")?;
    let private_key = required_material(&state.material, "private_key")?;
    crate::install_jsonwebtoken_crypto_provider();
    let now_secs = current_time_ms() / 1000;
    let assertion = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        &AppClaims {
            iss: &client_id,
            iat: now_secs - 60,
            exp: now_secs + 540,
        },
        &jsonwebtoken::EncodingKey::from_rsa_pem(private_key.as_bytes()).map_err(|_| {
            Status::invalid_argument("github_app_installation private_key must be RSA PEM")
        })?,
    )
    .map_err(|_| Status::invalid_argument("could not sign GitHub App JWT with private_key"))?;

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("OpenShell")
        .build()
        .map_err(|_| Status::internal("build GitHub App HTTP client failed"))?;
    let mut response = client
        .post(url)
        .bearer_auth(assertion)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2026-03-10")
        .json(&body)
        .send()
        .await
        .map_err(transport_failure)?;
    if response.status() != StatusCode::CREATED {
        // Do not retain upstream prose: it can contain echoed credentials.
        return Err(classify_error(response.status(), response.headers()));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| {
        RefreshFailure::retryable(
            Status::unavailable("could not read GitHub installation token response"),
            "github_token_endpoint_unavailable",
        )
    })? {
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(invalid_response());
        }
        bytes.extend_from_slice(&chunk);
    }
    let token: InstallationResponse =
        serde_json::from_slice(&bytes).map_err(|_| invalid_response())?;
    // Treat tokens as opaque and accept the longer stateless installation token
    // format. Reject whitespace/control characters before header substitution.
    if token.token.is_empty() || !token.token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(invalid_response());
    }
    let expires_at_ms = chrono::DateTime::parse_from_rfc3339(&token.expires_at)
        .map_err(|_| invalid_response())?
        .timestamp_millis();
    let now_ms = current_time_ms();
    if expires_at_ms <= now_ms {
        return Err(invalid_response());
    }
    Ok(MintedCredential {
        access_token: token.token,
        expires_at_ms: expires_at_ms
            .min(now_ms.saturating_add(max_lifetime_seconds(state).min(3600).saturating_mul(1000))),
        refresh_token: None,
        additional_credentials: HashMap::new(),
    })
}

fn transport_failure(error: reqwest::Error) -> RefreshFailure {
    // Inspect typed causes only. Formatting the source chain can expose endpoint
    // or proxy URLs and peer-controlled text. io::Error can wrap a rustls error
    // without exposing that wrapper's inner error through Error::source().
    let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    let mut tls_error = None;
    while let Some(current) = cause {
        if let Some(tls) = current.downcast_ref::<rustls::Error>() {
            tls_error = Some(tls);
            break;
        }
        cause = current
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
            .map_or_else(|| current.source(), |inner| Some(inner));
    }
    let (error_kind, message) = if error.is_timeout() {
        (
            "timeout",
            "GitHub installation token request timed out; check gateway outbound connectivity and proxy settings",
        )
    } else if matches!(tls_error, Some(rustls::Error::InvalidCertificate(_))) {
        (
            "tls_certificate",
            "GitHub installation token TLS certificate validation failed; check the gateway CA trust store and endpoint certificate",
        )
    } else if tls_error.is_some() {
        (
            "tls",
            "GitHub installation token TLS handshake failed; check gateway TLS and proxy settings",
        )
    } else if error.is_connect() {
        (
            "connect",
            "GitHub installation token connection failed; check gateway DNS, outbound connectivity, proxy settings, and CA trust",
        )
    } else {
        (
            "request",
            "GitHub installation token request failed before an HTTP response; check gateway outbound connectivity and proxy settings",
        )
    };
    tracing::warn!(error_kind, "GitHub installation token transport failed");
    RefreshFailure::retryable(
        Status::unavailable(message),
        "github_token_endpoint_unavailable",
    )
}

fn invalid_response() -> RefreshFailure {
    RefreshFailure::investigate(
        Status::failed_precondition("GitHub returned an invalid installation token or expiry"),
        "github_invalid_success_response",
    )
}

fn classify_error(status: StatusCode, headers: &HeaderMap) -> RefreshFailure {
    if status == StatusCode::TOO_MANY_REQUESTS
        || (status == StatusCode::FORBIDDEN
            && (headers.contains_key("retry-after")
                || headers
                    .get("x-ratelimit-remaining")
                    .is_some_and(|value| value == "0")))
        || status.is_server_error()
    {
        return RefreshFailure::retryable(
            Status::unavailable("GitHub token minting is temporarily unavailable or rate limited"),
            "github_token_endpoint_retryable",
        );
    }
    let (message, code) = match status {
        StatusCode::UNAUTHORIZED => (
            "GitHub rejected the app JWT; check client ID, private key, and gateway clock",
            "github_app_authentication_failed",
        ),
        StatusCode::FORBIDDEN => (
            "GitHub denied installation token minting; check installation access and permissions",
            "github_installation_forbidden",
        ),
        StatusCode::NOT_FOUND => (
            "GitHub installation was not found or is inaccessible to this app",
            "github_installation_not_found",
        ),
        StatusCode::UNPROCESSABLE_ENTITY | StatusCode::BAD_REQUEST => (
            "GitHub rejected the requested repositories or permissions",
            "github_installation_scope_invalid",
        ),
        _ => (
            "GitHub returned an unexpected token endpoint status; check the profile endpoint",
            "github_token_endpoint_invalid",
        ),
    };
    RefreshFailure::fix_configuration(Status::failed_precondition(message), code)
}

#[cfg(test)]
mod tests {
    use super::super::tests::TEST_RSA_PRIVATE_KEY;
    use super::*;
    use openshell_core::proto::ProviderCredentialRefreshRecoveryAction as Recovery;
    use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn material() -> HashMap<String, String> {
        HashMap::from([
            ("client_id".into(), "Iv1.test-client".into()),
            ("installation_id".into(), "123".into()),
            ("private_key".into(), TEST_RSA_PRIVATE_KEY.into()),
            ("repository_ids".into(), "[42,43]".into()),
            ("permissions".into(), r#"{"contents":"read"}"#.into()),
        ])
    }

    fn state(base: &str) -> StoredProviderCredentialRefreshState {
        StoredProviderCredentialRefreshState {
            material: material(),
            token_url: format!("{base}{INSTALLATION_PATH}"),
            ..Default::default()
        }
    }

    #[test]
    fn github_app_requires_explicit_valid_scope_and_key() {
        let url = format!("https://api.github.com{INSTALLATION_PATH}");
        validate_configuration(&material(), &url).unwrap();
        for key in [
            "client_id",
            "installation_id",
            "private_key",
            "repository_ids",
            "permissions",
        ] {
            let mut input = material();
            input.remove(key);
            assert!(
                validate_configuration(&input, &url).is_err(),
                "missing {key}"
            );
        }
        for (key, value) in [
            ("installation_id", "../1"),
            ("installation_id", "0"),
            ("private_key", "secret-invalid-pem"),
            ("repository_ids", "[]"),
            ("repository_ids", "[0]"),
            ("repository_ids", "[42,42]"),
            ("repository_ids", "[-1]"),
            ("repository_ids", "[1.5]"),
            ("repository_ids", "[\"42\"]"),
            ("permissions", "{}"),
            ("permissions", "null"),
            ("permissions", r#"{"contents":"all"}"#),
            ("api_base_url", "https://other.example"),
        ] {
            let mut input = material();
            input.insert(key.into(), value.into());
            let error = validate_configuration(&input, &url).unwrap_err();
            assert!(!error.message().contains("secret-invalid-pem"));
        }
        let mut input = material();
        input.insert(
            "repository_ids".into(),
            serde_json::to_string(&(1..=501).collect::<Vec<_>>()).unwrap(),
        );
        assert!(validate_configuration(&input, &url).is_err());
    }

    #[test]
    fn github_app_endpoint_is_profile_owned_and_keeps_enterprise_prefix() {
        assert_eq!(
            installation_url(
                &format!("https://github.example/api/v3{INSTALLATION_PATH}"),
                &material()
            )
            .unwrap()
            .path(),
            "/api/v3/app/installations/123/access_tokens"
        );
        for base in [
            "http://github.example",
            "https://user:password@github.example",
            "https://github.example?query=",
            "https://github.example#",
        ] {
            assert!(installation_url(&format!("{base}{INSTALLATION_PATH}"), &material()).is_err());
        }
        assert!(installation_url("https://api.github.com/token", &material()).is_err());
    }

    #[tokio::test]
    async fn github_app_mints_scoped_token_with_verified_app_jwt() {
        let server = MockServer::start().await;
        let expiry = chrono::Utc::now() + chrono::Duration::minutes(30);
        let token = format!("ghs_123_{}", "opaque".repeat(100));
        Mock::given(method("POST"))
            .and(path("/app/installations/123/access_tokens"))
            .and(header("accept", "application/vnd.github+json"))
            .and(header("user-agent", "OpenShell"))
            .and(body_json(
                serde_json::json!({"repository_ids": [42,43], "permissions": {"contents":"read"}}),
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(
                serde_json::json!({"token": token, "expires_at": expiry.to_rfc3339()}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        let before = current_time_ms() / 1000;
        let minted = mint(&state(&server.uri())).await.unwrap();
        assert_eq!(minted.access_token, token);
        assert_eq!(minted.expires_at_ms, expiry.timestamp_millis());
        assert!(minted.refresh_token.is_none());
        assert!(minted.additional_credentials.is_empty());
        let requests = server.received_requests().await.unwrap();
        let jwt = requests[0].headers["authorization"]
            .to_str()
            .unwrap()
            .strip_prefix("Bearer ")
            .unwrap();
        let key = rsa::RsaPrivateKey::from_pkcs8_pem(TEST_RSA_PRIVATE_KEY).unwrap();
        let public = key
            .to_public_key()
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();
        let claims = jsonwebtoken::decode::<serde_json::Value>(
            jwt,
            &jsonwebtoken::DecodingKey::from_rsa_pem(public.as_bytes()).unwrap(),
            &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256),
        )
        .unwrap()
        .claims;
        assert_eq!(claims["iss"], "Iv1.test-client");
        assert!(claims["iat"].as_i64().unwrap() >= before - 60);
        assert!(claims["iat"].as_i64().unwrap() <= current_time_ms() / 1000 - 60);
        assert!(claims["exp"].as_i64().unwrap() <= current_time_ms() / 1000 + 600);
        assert!(!String::from_utf8_lossy(&requests[0].body).contains("PRIVATE KEY"));
    }

    #[tokio::test]
    async fn github_app_reports_untrusted_tls_without_exposing_request_material() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    certificate.key_pair.serialize_der().into(),
                ),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            openshell_core::net::set_tcp_nodelay_best_effort(&stream);
            assert!(acceptor.accept(stream).await.is_err());
        });
        let failure = mint(&state(&format!("https://{address}")))
            .await
            .unwrap_err();
        assert_eq!(failure.failure_code, "github_token_endpoint_unavailable");
        assert_eq!(failure.recovery_action, Recovery::Retry);
        assert_eq!(
            failure.status.message(),
            "GitHub installation token TLS certificate validation failed; check the gateway CA trust store and endpoint certificate"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn github_app_distinguishes_connection_failures_and_timeouts() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        // A bound socket that never serves HTTP produces a real request timeout.
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_millis(50))
            .build()
            .unwrap();
        let url = format!("http://{address}/secret-path?secret-query=value");
        let failure = transport_failure(client.get(&url).send().await.unwrap_err());
        assert_eq!(failure.recovery_action, Recovery::Retry);
        assert!(failure.status.message().contains("timed out"));
        assert!(!failure.status.message().contains("secret"));

        drop(listener);
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let failure = transport_failure(client.get(&url).send().await.unwrap_err());
        assert_eq!(failure.failure_code, "github_token_endpoint_unavailable");
        assert_eq!(failure.recovery_action, Recovery::Retry);
        assert!(failure.status.message().contains("connection failed"));
        assert!(!failure.status.message().contains("secret"));
    }

    #[tokio::test]
    async fn github_app_rejects_invalid_success_without_echoing_secrets() {
        let server = MockServer::start().await;
        for body in [
            serde_json::json!({"token":"secret-token", "expires_at":"2000-01-01T00:00:00Z"}),
            serde_json::json!({"token":"secret-token", "expires_at":"invalid"}),
            serde_json::json!({"token":"secret-token\r\nInjected: value", "expires_at":"2099-01-01T00:00:00Z"}),
            serde_json::json!({"token":"", "expires_at":"2099-01-01T00:00:00Z"}),
            serde_json::json!({"token":"secret-token"}),
        ] {
            server.reset().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(201).set_body_json(body))
                .mount(&server)
                .await;
            let error = mint(&state(&server.uri())).await.unwrap_err();
            assert_eq!(error.failure_code, "github_invalid_success_response");
            assert!(!error.status.message().contains("secret-token"));
        }
    }

    #[tokio::test]
    async fn github_app_caps_lifetime_and_never_follows_redirects() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(201).set_body_json(
                serde_json::json!({"token":"token", "expires_at":"2099-01-01T00:00:00Z"}),
            ))
            .mount(&server)
            .await;
        let mut input = state(&server.uri());
        input.max_lifetime = Some(prost_types::Duration {
            seconds: 120,
            nanos: 0,
        });
        let minted = mint(&input).await.unwrap();
        assert!(minted.expires_at_ms <= current_time_ms() + 120_000);
        assert!(minted.expires_at_ms > current_time_ms());
        server.reset().await;
        let redirect_target = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(307).insert_header("location", redirect_target.uri()),
            )
            .mount(&server)
            .await;
        assert_eq!(
            mint(&input).await.unwrap_err().failure_code,
            "github_token_endpoint_invalid"
        );
        assert!(
            redirect_target
                .received_requests()
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn github_app_classifies_errors_without_provider_prose() {
        for code in [400, 401, 403, 404, 422] {
            assert_eq!(
                classify_error(StatusCode::from_u16(code).unwrap(), &HeaderMap::new())
                    .recovery_action,
                Recovery::FixConfiguration
            );
        }
        for code in [429, 500, 503] {
            assert_eq!(
                classify_error(StatusCode::from_u16(code).unwrap(), &HeaderMap::new())
                    .recovery_action,
                Recovery::Retry
            );
        }
        let mut headers = HeaderMap::new();
        headers.insert("x-ratelimit-remaining", "0".parse().unwrap());
        assert_eq!(
            classify_error(StatusCode::FORBIDDEN, &headers).recovery_action,
            Recovery::Retry
        );
    }
}
