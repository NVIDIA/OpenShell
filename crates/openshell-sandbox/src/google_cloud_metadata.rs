// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! GCE metadata server emulator for sandbox credential injection.
//!
//! Implements a subset of the GCE instance metadata API so that GCP client
//! libraries (Go, Python, Node.js) can obtain `OAuth2` tokens natively inside
//! sandboxes. Tokens are served from the existing `ProviderCredentialState`
//! store — no separate refresh mechanism is needed.
//!
//! The emulator runs as a loopback HTTP server inside the sandbox network
//! namespace (see [`metadata_server`](crate::metadata_server)). GCP SDKs
//! discover it via the `GCE_METADATA_HOST` environment variable, which is
//! set to the loopback address by `child_env_resolved()`.

use crate::provider_credentials::ProviderCredentialState;
use crate::secrets;
use miette::{IntoDiagnostic, Result};
use openshell_ocsf::{ActivityId, HttpActivityBuilder, SeverityId, StatusId, ocsf_emit};
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

impl crate::metadata_server::MetadataHandler for MetadataContext {
    async fn handle<S: AsyncRead + AsyncWrite + Unpin + Send>(
        &self,
        method: &str,
        path: &str,
        request: &[u8],
        stream: &mut S,
    ) -> Result<()> {
        handle_forward_request(self, method, path, request, stream).await
    }
}

async fn handle_forward_request<S>(
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
        emit_metadata_event(
            ActivityId::Refuse,
            SeverityId::Low,
            StatusId::Failure,
            &format!("metadata: unsupported method {method}"),
        );
        return (405, "text/html", "Method Not Allowed".to_string());
    }

    if let Err(resp) = validate_metadata_headers(headers) {
        emit_metadata_event(
            ActivityId::Refuse,
            SeverityId::Medium,
            StatusId::Failure,
            &format!("metadata: header validation failed for {path}"),
        );
        return resp;
    }

    let (route, query) = path.split_once('?').map_or((path, ""), |(r, q)| (r, q));
    let route = route.strip_suffix('/').unwrap_or(route);
    let recursive = query.split('&').any(|p| p == "recursive=true");

    match route {
        PATH_TOKEN => handle_token(ctx),
        PATH_EMAIL => handle_env(ctx, ENV_GCP_SERVICE_ACCOUNT_EMAIL),
        PATH_PROJECT_ID => handle_env(ctx, ENV_GCP_PROJECT_ID),
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
            emit_metadata_event(
                ActivityId::Refuse,
                SeverityId::Low,
                StatusId::Failure,
                &format!("metadata: unknown path {route}"),
            );
            (
                404,
                "application/json",
                serde_json::json!({"error": "not_found"}).to_string(),
            )
        }
    }
}

fn handle_token(ctx: &MetadataContext) -> MetadataResponse {
    let Some((placeholder, expires_in)) = ctx.credentials.gcp_token_response() else {
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
        emit_metadata_event(ActivityId::Fail, SeverityId::Medium, StatusId::Failure, msg);
        return (
            503,
            "application/json",
            serde_json::json!({"error": error_key}).to_string(),
        );
    };

    emit_metadata_event(
        ActivityId::Open,
        SeverityId::Informational,
        StatusId::Success,
        "metadata: token placeholder served",
    );

    let body = serde_json::json!({
        "access_token": placeholder,
        "expires_in": expires_in,
        "token_type": "Bearer"
    });
    (200, "application/json", body.to_string())
}

fn handle_service_account_recursive(ctx: &MetadataContext) -> MetadataResponse {
    let resolver = ctx.credentials.resolver();
    let email = resolver
        .as_ref()
        .and_then(|r| {
            let p = secrets::placeholder_for_env_key(ENV_GCP_SERVICE_ACCOUNT_EMAIL);
            r.resolve_placeholder(&p).map(str::to_string)
        })
        .unwrap_or_default();

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
fn handle_env(ctx: &MetadataContext, env_key: &str) -> MetadataResponse {
    let Some(resolver) = ctx.credentials.resolver() else {
        emit_metadata_event(
            ActivityId::Fail,
            SeverityId::Medium,
            StatusId::Failure,
            &format!("metadata: {env_key} request but no credentials configured"),
        );
        return (503, "text/plain", String::new());
    };

    let placeholder = secrets::placeholder_for_env_key(env_key);
    resolver.resolve_placeholder(&placeholder).map_or_else(
        || {
            emit_metadata_event(
                ActivityId::Fail,
                SeverityId::Low,
                StatusId::Failure,
                &format!("metadata: {env_key} not configured"),
            );
            (
                404,
                "application/json",
                serde_json::json!({"error": "not_found"}).to_string(),
            )
        },
        |value| (200, "text/plain", value.to_string()),
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
    activity: ActivityId,
    severity: SeverityId,
    status: StatusId,
    message: &str,
) {
    let event = HttpActivityBuilder::new(crate::ocsf_ctx())
        .activity(activity)
        .severity(severity)
        .status(status)
        .message(message.to_string())
        .build();
    ocsf_emit!(event);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_context(env: HashMap<String, String>) -> MetadataContext {
        let state = ProviderCredentialState::from_environment(0, env, HashMap::new());
        MetadataContext::new(state)
    }

    fn make_context_with_expiry(
        env: HashMap<String, String>,
        expires: HashMap<String, i64>,
    ) -> MetadataContext {
        let state = ProviderCredentialState::from_environment(0, env, expires);
        MetadataContext::new(state)
    }

    fn flavor_headers() -> Vec<(String, String)> {
        vec![("Metadata-Flavor".to_string(), "Google".to_string())]
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
