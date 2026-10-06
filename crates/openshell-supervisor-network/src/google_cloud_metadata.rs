// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! GCE metadata server emulator for sandbox credential injection.
//!
//! Implements a subset of the GCE instance metadata API so that GCP client
//! libraries (Go, Python, Node.js) can obtain `OAuth2` tokens natively inside
//! sandboxes. Tokens are served from the existing `ProviderCredentialState`
//! store — no separate refresh mechanism is needed.
//!
//! The sandbox broker relays the reserved loopback metadata destination to
//! this supervisor-owned handler. SDKs discover it through `GCE_METADATA_HOST`;
//! real credentials remain outside the workload boundary.

use http::StatusCode;
use miette::{IntoDiagnostic, Result};
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_ocsf::{
    ActivityId, HttpActivityBuilder, HttpRequest, SeverityId, StatusId, ocsf_emit,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

type MetadataResponse = (u16, &'static str, String);

const PATH_SERVICE_ACCOUNTS: &str = "/computeMetadata/v1/instance/service-accounts";
const PATH_SERVICE_ACCOUNT_DEFAULT: &str = "/computeMetadata/v1/instance/service-accounts/default";
const PATH_TOKEN: &str = "/computeMetadata/v1/instance/service-accounts/default/token";
const PATH_EMAIL: &str = "/computeMetadata/v1/instance/service-accounts/default/email";
const PATH_SCOPES: &str = "/computeMetadata/v1/instance/service-accounts/default/scopes";
const PATH_ALIASES: &str = "/computeMetadata/v1/instance/service-accounts/default/aliases";
const PATH_PROJECT_ID: &str = "/computeMetadata/v1/project/project-id";

const ENV_GCP_PROJECT_ID: &str = openshell_core::google_cloud::PROJECT_ID_ENV_VARS[0];
const ENV_GCP_SERVICE_ACCOUNT_EMAIL: &str =
    openshell_core::google_cloud::SERVICE_ACCOUNT_EMAIL_ENV_VARS[0];

const METADATA_FLAVOR_HEADER: &str = "metadata-flavor";
const METADATA_FLAVOR_VALUE: &str = "Google";
const X_FORWARDED_FOR_HEADER: &str = "x-forwarded-for";

#[derive(Debug, Clone)]
pub struct MetadataContext {
    credentials: ProviderCredentialState,
}

impl MetadataContext {
    pub fn new(credentials: ProviderCredentialState) -> Self {
        Self { credentials }
    }
}

pub async fn handle_forward_request<S>(
    ctx: &MetadataContext,
    method: &str,
    path: &str,
    initial_request: &[u8],
    client: &mut S,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let headers = parse_request_headers(initial_request);
    let (status, content_type, body) = route_request(ctx, method, path, &headers);
    write_metadata_response(client, status, content_type, &body).await
}

fn route_request(
    ctx: &MetadataContext,
    method: &str,
    path: &str,
    headers: &[(String, String)],
) -> MetadataResponse {
    if method != "GET" {
        let status = StatusCode::METHOD_NOT_ALLOWED.as_u16();
        emit_metadata_event(
            method,
            status,
            SeverityId::Low,
            StatusId::Failure,
            &format!("metadata: unsupported method {method}"),
        );
        return (status, "text/html", "Method Not Allowed".to_string());
    }

    if let Err(resp) = validate_metadata_headers(headers) {
        emit_metadata_event(
            method,
            resp.0,
            SeverityId::Medium,
            StatusId::Failure,
            &format!(
                "metadata: header validation failed for {}",
                path.split('?').next().unwrap_or(path)
            ),
        );
        return resp;
    }

    let (route, query) = path.split_once('?').map_or((path, ""), |(r, q)| (r, q));
    let route = route.strip_suffix('/').unwrap_or(route);
    let recursive = query.split('&').any(|p| p == "recursive=true");
    let account_route = ctx
        .credentials
        .current_non_secret_environment_value(ENV_GCP_SERVICE_ACCOUNT_EMAIL)
        .filter(|email| !email.is_empty() && !email.contains('/'))
        .and_then(|email| {
            let suffix = route.strip_prefix(&format!("{PATH_SERVICE_ACCOUNTS}/{email}"))?;
            (suffix.is_empty() || suffix.starts_with('/'))
                .then(|| format!("{PATH_SERVICE_ACCOUNT_DEFAULT}{suffix}"))
        });
    let route = account_route.as_deref().unwrap_or(route);

    match route {
        PATH_TOKEN => handle_token(ctx, method),
        PATH_EMAIL => handle_env(ctx, method, ENV_GCP_SERVICE_ACCOUNT_EMAIL),
        PATH_PROJECT_ID => handle_env(ctx, method, ENV_GCP_PROJECT_ID),
        PATH_ALIASES => (200, "text/plain", "default\n".to_string()),
        PATH_SCOPES => (
            200,
            "text/plain",
            "https://www.googleapis.com/auth/cloud-platform".to_string(),
        ),
        PATH_SERVICE_ACCOUNT_DEFAULT => {
            if recursive {
                handle_service_account_recursive(ctx)
            } else {
                (
                    200,
                    "text/plain",
                    "aliases\nemail\nscopes\ntoken\n".to_string(),
                )
            }
        }
        PATH_SERVICE_ACCOUNTS => (200, "text/plain", "default/\n".to_string()),
        "" | "/" | "/computeMetadata" | "/computeMetadata/v1" => {
            (200, "text/plain", "computeMetadata/\n".to_string())
        }
        "/computeMetadata/v1/instance" => (200, "text/plain", "service-accounts/\n".to_string()),
        _ => {
            let status = StatusCode::NOT_FOUND.as_u16();
            emit_metadata_event(
                method,
                status,
                SeverityId::Low,
                StatusId::Failure,
                &format!("metadata: unknown path {route}"),
            );
            (
                status,
                "application/json",
                serde_json::json!({"error": "not_found"}).to_string(),
            )
        }
    }
}

fn handle_token(ctx: &MetadataContext, method: &str) -> MetadataResponse {
    let Some((placeholder, expires_in)) = ctx.credentials.gcp_token_response() else {
        let status = StatusCode::SERVICE_UNAVAILABLE.as_u16();
        let has_resolver = ctx.credentials.resolver().is_some();
        let (msg, error_key) = if has_resolver {
            (
                "metadata: no GCP access token available or expired",
                "token_unavailable",
            )
        } else {
            (
                "metadata: token request but no credentials configured",
                "credentials_unavailable",
            )
        };
        emit_metadata_event(method, status, SeverityId::Medium, StatusId::Failure, msg);
        return (
            status,
            "application/json",
            serde_json::json!({"error": error_key}).to_string(),
        );
    };

    let status = StatusCode::OK.as_u16();
    emit_metadata_event(
        method,
        status,
        SeverityId::Informational,
        StatusId::Success,
        "metadata: token placeholder served",
    );

    let body = serde_json::json!({
        "access_token": placeholder,
        "expires_in": expires_in,
        "token_type": "Bearer"
    });
    (status, "application/json", body.to_string())
}

fn handle_service_account_recursive(ctx: &MetadataContext) -> MetadataResponse {
    let email = ctx
        .credentials
        .current_non_secret_environment_value(ENV_GCP_SERVICE_ACCOUNT_EMAIL)
        .filter(|email| !email.is_empty())
        .unwrap_or_else(|| "default".to_string());

    let scopes = "https://www.googleapis.com/auth/cloud-platform";

    let body = serde_json::json!({
        "aliases": ["default"],
        "email": email,
        "scopes": [scopes],
    });
    (200, "application/json", body.to_string())
}

/// Serve a non-secret config value (project ID, SA email) as plain text.
///
/// Unlike `handle_token` which serves placeholders, this resolves to the real
/// value. This matches real GCE metadata server behavior and is safe because
/// these values are non-secret configuration (project IDs, email addresses).
fn handle_env(ctx: &MetadataContext, method: &str, env_key: &str) -> MetadataResponse {
    ctx.credentials
        .current_non_secret_environment_value(env_key)
        .map_or_else(
            || {
                let status = StatusCode::NOT_FOUND.as_u16();
                emit_metadata_event(
                    method,
                    status,
                    SeverityId::Low,
                    StatusId::Failure,
                    &format!("metadata: {env_key} not configured as non-secret"),
                );
                (
                    status,
                    "application/json",
                    serde_json::json!({"error": "not_found"}).to_string(),
                )
            },
            |value| (200, "text/plain", value),
        )
}

fn validate_metadata_headers(headers: &[(String, String)]) -> Result<(), MetadataResponse> {
    if headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(X_FORWARDED_FOR_HEADER))
    {
        return Err((403, "text/html", "Forbidden".to_string()));
    }

    let has_flavor = headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case(METADATA_FLAVOR_HEADER)
            && value.trim().eq_ignore_ascii_case(METADATA_FLAVOR_VALUE)
    });
    if !has_flavor {
        return Err((403, "text/html", "Forbidden".to_string()));
    }

    Ok(())
}

fn parse_request_headers(raw: &[u8]) -> Vec<(String, String)> {
    let request = String::from_utf8_lossy(raw);
    let mut headers = Vec::new();
    for line in request.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    headers
}

fn status_text(status: u16) -> &'static str {
    match status {
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        _ => "OK",
    }
}

async fn write_metadata_response<S>(
    client: &mut S,
    status: u16,
    content_type: &str,
    body: &str,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let response = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {content_type}\r\nMetadata-Flavor: Google\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        status_text(status),
        body.len(),
    );
    client
        .write_all(response.as_bytes())
        .await
        .into_diagnostic()?;
    client.flush().await.into_diagnostic()?;
    Ok(())
}

fn emit_metadata_event(
    method: &str,
    response_code: u16,
    severity: SeverityId,
    status: StatusId,
    message: &str,
) {
    ocsf_emit!(build_metadata_event(
        method,
        response_code,
        severity,
        status,
        message
    ));
}

fn build_metadata_event(
    method: &str,
    response_code: u16,
    severity: SeverityId,
    status: StatusId,
    message: &str,
) -> openshell_ocsf::OcsfEvent {
    HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::for_http_method(method))
        .http_request(HttpRequest {
            http_method: method.parse().expect("HTTP method parsing is infallible"),
            url: None,
        })
        .http_response(openshell_ocsf::HttpResponse {
            code: response_code,
        })
        .severity(severity)
        .status(status)
        .message(message.to_string())
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn token_binding() -> openshell_core::proto::StaticCredentialBinding {
        openshell_core::proto::StaticCredentialBinding {
            endpoints: vec![openshell_core::proto::StaticCredentialEndpointBinding {
                host: "storage.googleapis.com".into(),
                port: 443,
                path: "/**".into(),
            }],
            credential_identity: "test-google:token".into(),
            workload_credential_handle: String::new(),
        }
    }

    fn make_context(env: HashMap<String, String>) -> MetadataContext {
        let config_keys = [ENV_GCP_PROJECT_ID, ENV_GCP_SERVICE_ACCOUNT_EMAIL]
            .into_iter()
            .filter(|key| env.contains_key(*key))
            .map(str::to_string)
            .collect();
        let bindings = openshell_core::google_cloud::TOKEN_ENV_KEYS
            .iter()
            .filter(|key| env.contains_key(**key))
            .map(|key| ((*key).to_string(), token_binding()))
            .collect();
        let state = ProviderCredentialState::from_bound_environment(
            0,
            env,
            HashMap::new(),
            HashMap::new(),
            bindings,
            config_keys,
        )
        .unwrap();
        MetadataContext::new(state)
    }

    fn make_context_with_expiry(
        env: HashMap<String, String>,
        expires: HashMap<String, i64>,
    ) -> MetadataContext {
        let state = ProviderCredentialState::from_environment(0, env, expires, HashMap::new());
        MetadataContext::new(state)
    }

    fn flavor_headers() -> Vec<(String, String)> {
        vec![("Metadata-Flavor".to_string(), "Google".to_string())]
    }

    #[test]
    fn metadata_events_include_response_for_ocsf18() {
        use openshell_ocsf::tracing_layers::OcsfJsonlLayer;
        use openshell_ocsf::validation::{
            load_class_schema, validate_enum_value, validate_required_fields,
        };
        use tracing_subscriber::prelude::*;

        let schema = load_class_schema("http_activity");
        for (method, path, headers, expected_code, expected_activity_id) in [
            ("GET", PATH_TOKEN, flavor_headers(), 200, 3),
            ("GET", "/?token=secret-query", Vec::new(), 403, 3),
            ("GET", "/unknown", flavor_headers(), 404, 3),
            ("POST", PATH_TOKEN, flavor_headers(), 405, 6),
            ("GET", PATH_TOKEN, flavor_headers(), 503, 3),
            ("GET", PATH_EMAIL, flavor_headers(), 404, 3),
        ] {
            let env = if expected_code == 503 {
                HashMap::new()
            } else {
                HashMap::from([("GCP_ADC_ACCESS_TOKEN".to_string(), "test-token".to_string())])
            };
            let ctx = make_context(env);
            let log = tempfile::NamedTempFile::new().unwrap();
            let subscriber =
                tracing_subscriber::registry().with(OcsfJsonlLayer::new(log.reopen().unwrap()));
            let response = tracing::subscriber::with_default(subscriber, || {
                route_request(&ctx, method, path, &headers)
            });
            assert_eq!(response.0, expected_code);
            let output = std::fs::read_to_string(log.path()).unwrap();
            let json: serde_json::Value = serde_json::from_str(&output).unwrap();
            assert_eq!(json["http_response"]["code"], response.0);
            assert!(!output.contains("secret-query"), "{output}");
            assert_eq!(
                json["activity_id"], expected_activity_id,
                "method: {method}"
            );
            assert_eq!(json["http_request"]["http_method"], method);
            assert!(json["http_request"].get("url").is_none());
            validate_required_fields(&json, &schema);
            validate_enum_value(&json, "activity_id", &schema);
        }
    }

    #[test]
    fn metadata_tracks_current_credentials_and_provider_removal() {
        let ctx = make_context(HashMap::from([
            ("GCP_ADC_ACCESS_TOKEN".into(), "old-secret".into()),
            ("GCP_PROJECT_ID".into(), "old-project".into()),
            ("GCP_SERVICE_ACCOUNT_EMAIL".into(), "old@example.com".into()),
        ]));
        let (_, _, old_body) = route_request(&ctx, "GET", PATH_TOKEN, &flavor_headers());
        ctx.credentials
            .install_bound_environment(
                2,
                HashMap::from([
                    ("GCP_ADC_ACCESS_TOKEN".into(), "new-secret".into()),
                    ("GCP_PROJECT_ID".into(), "new-project".into()),
                    ("GCP_SERVICE_ACCOUNT_EMAIL".into(), "new@example.com".into()),
                ]),
                HashMap::new(),
                HashMap::new(),
                HashMap::from([("GCP_ADC_ACCESS_TOKEN".into(), token_binding())]),
                vec![
                    ENV_GCP_PROJECT_ID.into(),
                    ENV_GCP_SERVICE_ACCOUNT_EMAIL.into(),
                ],
            )
            .unwrap();
        let (_, _, new_body) = route_request(&ctx, "GET", PATH_TOKEN, &flavor_headers());
        assert_ne!(old_body, new_body);
        assert!(!new_body.contains("new-secret"));
        assert_eq!(
            route_request(&ctx, "GET", PATH_PROJECT_ID, &flavor_headers()).2,
            "new-project"
        );
        let (_, _, recursive) = route_request(
            &ctx,
            "GET",
            &format!("{PATH_SERVICE_ACCOUNT_DEFAULT}/?recursive=true"),
            &flavor_headers(),
        );
        let recursive: serde_json::Value = serde_json::from_str(&recursive).unwrap();
        assert_eq!(recursive["email"], "new@example.com");
        assert_eq!(
            recursive["scopes"][0],
            "https://www.googleapis.com/auth/cloud-platform"
        );
        assert!(recursive.get("token").is_none());
        ctx.credentials
            .install_environment(3, HashMap::new(), HashMap::new(), HashMap::new());
        assert_eq!(
            route_request(&ctx, "GET", PATH_TOKEN, &flavor_headers()).0,
            503
        );
        assert_eq!(
            route_request(&ctx, "GET", PATH_PROJECT_ID, &flavor_headers()).0,
            404
        );
        assert_eq!(
            route_request(&ctx, "GET", PATH_EMAIL, &flavor_headers()).0,
            404
        );
        let (_, _, recursive) = route_request(
            &ctx,
            "GET",
            &format!("{PATH_SERVICE_ACCOUNT_DEFAULT}?recursive=true"),
            &flavor_headers(),
        );
        assert!(!recursive.contains("new@example.com"));
    }

    #[test]
    fn metadata_does_not_unwrap_config_names_classified_as_credentials() {
        let ctx = MetadataContext::new(ProviderCredentialState::from_environment(
            0,
            HashMap::from([
                (ENV_GCP_PROJECT_ID.into(), "secret-project".into()),
                (ENV_GCP_SERVICE_ACCOUNT_EMAIL.into(), "secret-email".into()),
            ]),
            HashMap::new(),
            HashMap::new(),
        ));
        assert_eq!(
            route_request(&ctx, "GET", PATH_PROJECT_ID, &flavor_headers()).0,
            404
        );
        assert_eq!(
            route_request(&ctx, "GET", PATH_EMAIL, &flavor_headers()).0,
            404
        );
        let (_, _, body) = route_request(
            &ctx,
            "GET",
            &format!("{PATH_SERVICE_ACCOUNT_DEFAULT}?recursive=true"),
            &flavor_headers(),
        );
        assert!(!body.contains("secret-email"));
    }

    #[test]
    fn configured_email_alias_supports_repeated_sdk_refresh() {
        let ctx = make_context(HashMap::from([
            (
                ENV_GCP_SERVICE_ACCOUNT_EMAIL.into(),
                "sdk@project.iam.gserviceaccount.com".into(),
            ),
            ("GCP_ADC_ACCESS_TOKEN".into(), "real-secret".into()),
        ]));
        for suffix in ["?recursive=true", "/token", "/email", "/scopes"] {
            let alias =
                format!("{PATH_SERVICE_ACCOUNTS}/sdk@project.iam.gserviceaccount.com{suffix}");
            let default = format!("{PATH_SERVICE_ACCOUNT_DEFAULT}{suffix}");
            assert_eq!(
                route_request(&ctx, "GET", &alias, &flavor_headers()),
                route_request(&ctx, "GET", &default, &flavor_headers())
            );
        }
        let other = format!("{PATH_SERVICE_ACCOUNTS}/other@project.iam.gserviceaccount.com/token");
        assert_eq!(route_request(&ctx, "GET", &other, &flavor_headers()).0, 404);
    }

    #[test]
    fn missing_or_empty_email_keeps_a_usable_account_for_repeated_sdk_refresh() {
        for email in [None, Some("")] {
            let mut env = HashMap::from([("GCP_ADC_ACCESS_TOKEN".into(), "real-secret".into())]);
            if let Some(email) = email {
                env.insert(ENV_GCP_SERVICE_ACCOUNT_EMAIL.into(), email.into());
            }
            let ctx = make_context(env);
            let mut account = "default".to_string();
            for _ in 0..2 {
                let path = format!("{PATH_SERVICE_ACCOUNTS}/{account}?recursive=true");
                let (status, _, body) = route_request(&ctx, "GET", &path, &flavor_headers());
                assert_eq!(status, 200);
                let info: serde_json::Value = serde_json::from_str(&body).unwrap();
                account = info["email"].as_str().unwrap().to_string();
                assert_eq!(account, "default");
                assert_eq!(
                    route_request(&ctx, "GET", PATH_TOKEN, &flavor_headers()).0,
                    200
                );
            }
        }
    }

    #[test]
    fn expired_token_is_unavailable() {
        let ctx = make_context_with_expiry(
            HashMap::from([("GCP_ADC_ACCESS_TOKEN".into(), "expired-secret".into())]),
            HashMap::from([(
                "GCP_ADC_ACCESS_TOKEN".into(),
                openshell_core::time::now_ms() - 1000,
            )]),
        );
        assert_eq!(
            route_request(&ctx, "GET", PATH_TOKEN, &flavor_headers()).0,
            503
        );
    }

    #[test]
    fn token_returns_placeholder_not_real_value() {
        let ctx = make_context(HashMap::from([(
            "GCP_ADC_ACCESS_TOKEN".to_string(),
            "ya29.test-token".to_string(),
        )]));
        let (status, ct, body) = route_request(&ctx, "GET", PATH_TOKEN, &flavor_headers());
        assert_eq!(status, 200);
        assert_eq!(ct, "application/json");
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let token = json["access_token"].as_str().unwrap();
        assert!(
            token.starts_with("openshell:resolve:env:"),
            "token should be a placeholder, got: {token}"
        );
        assert!(!token.contains("ya29"), "real token must not be served");
        assert_eq!(json["token_type"], "Bearer");
        assert!(json["expires_in"].is_number());
    }

    #[test]
    fn token_expires_in_computed_from_credential_expiry() {
        let now_ms = openshell_core::time::now_ms();
        let expires_at = now_ms + 1_800_000; // 30 minutes from now
        let ctx = make_context_with_expiry(
            HashMap::from([("GCP_ADC_ACCESS_TOKEN".to_string(), "ya29.tok".to_string())]),
            HashMap::from([("GCP_ADC_ACCESS_TOKEN".to_string(), expires_at)]),
        );
        let (status, _, body) = route_request(&ctx, "GET", PATH_TOKEN, &flavor_headers());
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let expires_in = json["expires_in"].as_i64().unwrap();
        assert!(
            expires_in > 1700 && expires_in <= 1800,
            "expires_in={expires_in}"
        );
    }

    #[test]
    fn token_no_expiry_defaults_to_3600() {
        let ctx = make_context(HashMap::from([(
            "GCP_ADC_ACCESS_TOKEN".to_string(),
            "ya29.tok".to_string(),
        )]));
        let (_, _, body) = route_request(&ctx, "GET", PATH_TOKEN, &flavor_headers());
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["expires_in"], 3600);
    }

    #[test]
    fn missing_metadata_flavor_header_403() {
        let ctx = make_context(HashMap::new());
        let (status, _, _) = route_request(&ctx, "GET", PATH_TOKEN, &[]);
        assert_eq!(status, 403);
    }

    #[test]
    fn x_forwarded_for_header_403() {
        let ctx = make_context(HashMap::new());
        let headers = vec![
            ("Metadata-Flavor".to_string(), "Google".to_string()),
            ("X-Forwarded-For".to_string(), "10.0.0.1".to_string()),
        ];
        let (status, _, _) = route_request(&ctx, "GET", PATH_TOKEN, &headers);
        assert_eq!(status, 403);
    }

    #[test]
    fn unknown_path_404() {
        let ctx = make_context(HashMap::new());
        let (status, _, _) = route_request(
            &ctx,
            "GET",
            "/computeMetadata/v1/unknown",
            &flavor_headers(),
        );
        assert_eq!(status, 404);
    }

    #[test]
    fn no_credentials_503() {
        let ctx = make_context(HashMap::new());
        let (status, _, _) = route_request(&ctx, "GET", PATH_TOKEN, &flavor_headers());
        assert_eq!(status, 503);
    }

    #[test]
    fn post_method_405() {
        let ctx = make_context(HashMap::new());
        let (status, _, _) = route_request(&ctx, "POST", PATH_TOKEN, &flavor_headers());
        assert_eq!(status, 405);
    }

    #[test]
    fn project_id_served_as_plain_text() {
        let ctx = make_context(HashMap::from([(
            "GCP_PROJECT_ID".to_string(),
            "my-project-123".to_string(),
        )]));
        let (status, ct, body) = route_request(&ctx, "GET", PATH_PROJECT_ID, &flavor_headers());
        assert_eq!(status, 200);
        assert_eq!(ct, "text/plain");
        assert_eq!(body, "my-project-123");
    }

    #[test]
    fn email_served_as_plain_text() {
        let ctx = make_context(HashMap::from([(
            "GCP_SERVICE_ACCOUNT_EMAIL".to_string(),
            "sa@project.iam.gserviceaccount.com".to_string(),
        )]));
        let (status, ct, body) = route_request(&ctx, "GET", PATH_EMAIL, &flavor_headers());
        assert_eq!(status, 200);
        assert_eq!(ct, "text/plain");
        assert_eq!(body, "sa@project.iam.gserviceaccount.com");
    }

    #[test]
    fn scopes_returns_cloud_platform() {
        let ctx = make_context(HashMap::new());
        let (status, _, body) = route_request(&ctx, "GET", PATH_SCOPES, &flavor_headers());
        assert_eq!(status, 200);
        assert_eq!(body, "https://www.googleapis.com/auth/cloud-platform");
    }

    #[test]
    fn query_parameters_ignored_for_routing() {
        let ctx = make_context(HashMap::from([(
            "GCP_ADC_ACCESS_TOKEN".to_string(),
            "ya29.tok".to_string(),
        )]));
        let path = format!("{PATH_TOKEN}?scopes=cloud-platform");
        let (status, _, _) = route_request(&ctx, "GET", &path, &flavor_headers());
        assert_eq!(status, 200);
    }

    #[test]
    fn metadata_flavor_case_insensitive() {
        let ctx = make_context(HashMap::from([(
            "GCP_ADC_ACCESS_TOKEN".to_string(),
            "ya29.tok".to_string(),
        )]));
        let headers = vec![("metadata-FLAVOR".to_string(), "google".to_string())];
        let (status, _, _) = route_request(&ctx, "GET", PATH_TOKEN, &headers);
        assert_eq!(status, 200);
    }

    #[test]
    fn missing_env_var_returns_404() {
        let ctx = make_context(HashMap::from([(
            "GCP_ADC_ACCESS_TOKEN".to_string(),
            "ya29.tok".to_string(),
        )]));
        // project-id not set
        let (status, _, _) = route_request(&ctx, "GET", PATH_PROJECT_ID, &flavor_headers());
        assert_eq!(status, 404);
    }

    #[test]
    fn trailing_slash_handled_for_service_account_default() {
        let ctx = make_context(HashMap::from([(
            "GCP_ADC_ACCESS_TOKEN".to_string(),
            "ya29.tok".to_string(),
        )]));
        let with_slash = route_request(
            &ctx,
            "GET",
            "/computeMetadata/v1/instance/service-accounts/default/",
            &flavor_headers(),
        );
        let without_slash = route_request(
            &ctx,
            "GET",
            "/computeMetadata/v1/instance/service-accounts/default",
            &flavor_headers(),
        );
        assert_eq!(with_slash.0, 200);
        assert_eq!(without_slash.0, 200);
        assert_eq!(with_slash.2, without_slash.2);
    }

    #[test]
    fn parse_request_headers_extracts_correctly() {
        let raw = b"GET /path HTTP/1.1\r\nHost: example.com\r\nMetadata-Flavor: Google\r\n\r\n";
        let headers = parse_request_headers(raw);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, "example.com");
        assert_eq!(headers[1].0, "Metadata-Flavor");
        assert_eq!(headers[1].1, "Google");
    }
}
