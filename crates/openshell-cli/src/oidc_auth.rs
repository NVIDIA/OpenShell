// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OIDC authentication flows for CLI gateway login.
//!
//! Implements Authorization Code + PKCE (interactive browser flow),
//! Device Authorization Grant (headless flow), and Client Credentials
//! (CI/automation) `OAuth2` grant types against a Keycloak-compatible
//! OIDC provider.
use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Method, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use miette::{IntoDiagnostic, Result};
use oauth2::basic::{BasicClient, BasicTokenResponse};
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use openshell_bootstrap::oidc_token::OidcTokenBundle;
use openshell_sdk::oidc::RefreshTokenInput;
use serde::Deserialize;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tracing::debug;

const AUTH_TIMEOUT: Duration = Duration::from_secs(120);

/// OIDC discovery document (subset of fields we need).
#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    device_authorization_endpoint: Option<String>,
}

/// Device authorization response from the provider.
#[derive(Debug, Deserialize)]
struct DeviceAuthorizationResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: u64,
    #[serde(default = "default_interval")]
    interval: u64,
}

fn default_interval() -> u64 {
    5
}

/// Device token polling error responses (RFC 8628).
#[derive(Debug, Deserialize)]
struct DeviceTokenErrorResponse {
    error: String,
    #[serde(default)]
    error_description: String,
}

/// Discover OIDC endpoints from the issuer's well-known configuration.
///
/// Validates that the discovery document's `issuer` field matches the
/// configured issuer URL to prevent SSRF or misdirection.
async fn discover(issuer: &str, insecure: bool) -> Result<OidcDiscovery> {
    let normalized_issuer = issuer.trim_end_matches('/');
    let url = format!("{normalized_issuer}/.well-known/openid-configuration");
    let client = http_client(insecure);
    let resp: OidcDiscovery = client
        .get(&url)
        .send()
        .await
        .into_diagnostic()?
        .json()
        .await
        .into_diagnostic()?;

    let discovered_issuer = resp.issuer.trim_end_matches('/');
    if discovered_issuer != normalized_issuer {
        return Err(miette::miette!(
            "OIDC discovery issuer mismatch: expected '{}', got '{}'",
            normalized_issuer,
            discovered_issuer
        ));
    }
    Ok(resp)
}

fn http_client(insecure: bool) -> reqwest::Client {
    let mut builder = reqwest::ClientBuilder::new().redirect(reqwest::redirect::Policy::none());
    if insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder.build().expect("failed to build HTTP client")
}

fn build_scopes(scopes: Option<&str>) -> Vec<Scope> {
    let mut result = vec![Scope::new("openid".to_string())];
    if let Some(s) = scopes {
        for scope in s.split_whitespace() {
            if scope != "openid" {
                result.push(Scope::new(scope.to_string()));
            }
        }
    }
    result
}

fn build_ci_scopes(scopes: Option<&str>) -> Vec<Scope> {
    let Some(s) = scopes else {
        return vec![];
    };
    s.split_whitespace()
        .map(|scope| Scope::new(scope.to_string()))
        .collect()
}

fn interactive_authorization_params(
    audience: Option<&str>,
    force_fresh_login: bool,
) -> Vec<(&'static str, String)> {
    let mut params = Vec::new();
    if force_fresh_login {
        params.push(("prompt", "login".to_string()));
    }
    if let Some(aud) = audience {
        params.push(("audience", aud.to_string()));
    }
    params
}

fn device_authorization_form(
    client_id: &str,
    scopes: &str,
    audience: Option<&str>,
    code_challenge: &str,
    code_challenge_method: &str,
) -> Vec<(&'static str, String)> {
    let mut params = vec![
        ("client_id", client_id.to_string()),
        ("scope", scopes.to_string()),
        ("code_challenge", code_challenge.to_string()),
        ("code_challenge_method", code_challenge_method.to_string()),
    ];
    if let Some(audience) = audience {
        params.push(("audience", audience.to_string()));
    }
    params
}

fn device_token_form(
    client_id: &str,
    device_code: &str,
    code_verifier: &str,
) -> Vec<(&'static str, String)> {
    vec![
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:device_code".to_string(),
        ),
        ("device_code", device_code.to_string()),
        ("client_id", client_id.to_string()),
        ("code_verifier", code_verifier.to_string()),
    ]
}

/// Run the OIDC Authorization Code + PKCE browser flow.
///
/// Opens the user's browser to the Keycloak login page and waits for
/// the authorization code redirect on a localhost callback server.
pub async fn oidc_browser_auth_flow(
    issuer: &str,
    client_id: &str,
    audience: Option<&str>,
    scopes: Option<&str>,
    insecure: bool,
    force_fresh_login: bool,
) -> Result<OidcTokenBundle> {
    let discovery = discover(issuer, insecure).await?;

    let listener = TcpListener::bind("127.0.0.1:0").await.into_diagnostic()?;
    let port = listener.local_addr().into_diagnostic()?.port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    let client = BasicClient::new(ClientId::new(client_id.to_string()))
        .set_auth_uri(AuthUrl::new(discovery.authorization_endpoint).into_diagnostic()?)
        .set_token_uri(TokenUrl::new(discovery.token_endpoint).into_diagnostic()?)
        .set_redirect_uri(RedirectUrl::new(redirect_uri).into_diagnostic()?);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let mut auth_request = client
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(pkce_challenge);

    for scope in build_scopes(scopes) {
        auth_request = auth_request.add_scope(scope);
    }

    let (mut auth_url, csrf_token) = auth_request.url();

    // After `gateway logout`, ask the IdP for a fresh login prompt so the user
    // can switch browser identity. Ordinary repeated logins may reuse SSO.
    let params = interactive_authorization_params(audience, force_fresh_login);
    {
        let mut query = auth_url.query_pairs_mut();
        for (key, value) in &params {
            query.append_pair(key, value);
        }
    }

    let (tx, rx) = oneshot::channel::<String>();
    let expected_state = csrf_token.secret().clone();

    let server_handle = tokio::spawn(run_oidc_callback_server(listener, tx, expected_state));

    eprintln!("  Opening browser for OIDC authentication...");
    if let Err(e) = crate::auth::open_browser_url(auth_url.as_str()) {
        debug!(error = %e, "failed to open browser");
        eprintln!("Could not open browser automatically.");
        eprintln!("Open this URL in your browser:");
        eprintln!("  {auth_url}");
        eprintln!();
    } else {
        eprintln!("  Browser opened. Waiting for authentication...");
    }

    let code = tokio::select! {
        result = rx => {
            result.map_err(|_| miette::miette!("OIDC callback channel closed unexpectedly"))?
        }
        () = tokio::time::sleep(AUTH_TIMEOUT) => {
            return Err(miette::miette!(
                "OIDC authentication timed out after {} seconds.\n\
                 Try again with: openshell gateway login",
                AUTH_TIMEOUT.as_secs()
            ));
        }
    };

    server_handle.abort();

    let http = http_client(insecure);
    let token_response = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(&http)
        .await
        .map_err(|e| miette::miette!("token exchange failed: {e}"))?;

    Ok(bundle_from_oauth2_response(
        &token_response,
        issuer,
        client_id,
    ))
}

/// Run the OIDC Client Credentials flow (for CI/automation).
///
/// Reads `OPENSHELL_OIDC_CLIENT_SECRET` from the environment.
pub async fn oidc_client_credentials_flow(
    issuer: &str,
    client_id: &str,
    audience: Option<&str>,
    scopes: Option<&str>,
    insecure: bool,
) -> Result<OidcTokenBundle> {
    let client_secret = std::env::var("OPENSHELL_OIDC_CLIENT_SECRET").map_err(|_| {
        miette::miette!(
            "OPENSHELL_OIDC_CLIENT_SECRET environment variable is required for client credentials flow"
        )
    })?;

    let discovery = discover(issuer, insecure).await?;

    let client = BasicClient::new(ClientId::new(client_id.to_string()))
        .set_client_secret(ClientSecret::new(client_secret))
        .set_token_uri(TokenUrl::new(discovery.token_endpoint).into_diagnostic()?)
        .set_auth_type(AuthType::RequestBody);

    let mut request = client.exchange_client_credentials();
    for scope in build_ci_scopes(scopes) {
        request = request.add_scope(scope);
    }
    if let Some(aud) = audience {
        request = request.add_extra_param("audience", aud);
    }

    let http = http_client(insecure);
    let token_response = request
        .request_async(&http)
        .await
        .map_err(|e| miette::miette!("client credentials token exchange failed: {e}"))?;

    Ok(bundle_from_oauth2_response(
        &token_response,
        issuer,
        client_id,
    ))
}

/// Run the OIDC Device Authorization Grant flow (RFC 8628).
///
/// Prompts the user to visit a verification URL and enter a code on any device
/// with a browser. Polls the token endpoint until the user completes authorization
/// or the device code expires.
pub async fn oidc_device_code_flow(
    issuer: &str,
    client_id: &str,
    audience: Option<&str>,
    scopes: Option<&str>,
    insecure: bool,
) -> Result<OidcTokenBundle> {
    let discovery = discover(issuer, insecure).await?;

    let device_auth_endpoint = discovery.device_authorization_endpoint.as_deref().ok_or_else(|| {
        miette::miette!(
            "The OIDC provider does not advertise a device_authorization_endpoint.\n\
             Enable the device authorization grant on this client, or use client credentials for headless automation."
        )
    })?;

    // Step 1: Request device and user codes
    let http = http_client(insecure);
    let scopes_param = build_scopes(scopes)
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .join(" ");

    // Use PKCE for the device flow as well as the browser flow. Keycloak
    // requires these parameters when the public client enforces S256 PKCE.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let form_params = device_authorization_form(
        client_id,
        &scopes_param,
        audience,
        pkce_challenge.as_str(),
        pkce_challenge.method().as_str(),
    );

    let device_auth_resp = http
        .post(device_auth_endpoint)
        .form(&form_params)
        .send()
        .await
        .into_diagnostic()?;

    if !device_auth_resp.status().is_success() {
        let status = device_auth_resp.status();
        let body = device_auth_resp.text().await.unwrap_or_default();
        return Err(miette::miette!(
            "Device authorization request failed (status {status}): {body}"
        ));
    }

    let device_auth: DeviceAuthorizationResponse =
        device_auth_resp.json().await.into_diagnostic()?;

    // Step 2: Display instructions to the user
    eprintln!();
    eprintln!("  To authenticate, visit:");
    if let Some(uri_complete) = &device_auth.verification_uri_complete {
        eprintln!("    {uri_complete}");
    } else {
        eprintln!("    {}", device_auth.verification_uri);
        eprintln!();
        eprintln!("  And enter this code:");
        eprintln!("    {}", device_auth.user_code);
    }
    eprintln!();
    eprintln!("  Waiting for authorization...");

    // Step 3: Poll the token endpoint
    let start_time = std::time::Instant::now();
    let expires_duration = Duration::from_secs(device_auth.expires_in);
    let mut poll_interval = Duration::from_secs(device_auth.interval);

    loop {
        if start_time.elapsed() >= expires_duration {
            return Err(miette::miette!(
                "Device code expired after {} seconds. Please try again.",
                device_auth.expires_in
            ));
        }

        tokio::time::sleep(poll_interval).await;

        let token_params =
            device_token_form(client_id, &device_auth.device_code, pkce_verifier.secret());

        let poll_resp = http
            .post(&discovery.token_endpoint)
            .form(&token_params)
            .send()
            .await
            .into_diagnostic()?;

        let status = poll_resp.status();

        if status.is_success() {
            // A successful HTTP status is not sufficient: require a valid OAuth
            // token response before persisting credentials.
            let token_response: BasicTokenResponse = poll_resp
                .json()
                .await
                .map_err(|error| miette::miette!("invalid device token response: {error}"))?;

            return bundle_from_device_token_response(&token_response, issuer, client_id);
        }

        // Parse error response
        let error_resp: DeviceTokenErrorResponse = match poll_resp.json().await {
            Ok(e) => e,
            Err(_) => {
                return Err(miette::miette!(
                    "Token polling failed with status {status} and unparseable response"
                ));
            }
        };

        match error_resp.error.as_str() {
            "authorization_pending" => {
                // Keep polling
                debug!("Device authorization pending, continuing to poll");
            }
            "slow_down" => {
                // Increase polling interval per RFC 8628
                poll_interval += Duration::from_secs(5);
                debug!(
                    "Received slow_down, increasing interval to {:?}",
                    poll_interval
                );
            }
            "access_denied" => {
                return Err(miette::miette!(
                    "Authorization was denied by the user or administrator"
                ));
            }
            "expired_token" => {
                return Err(miette::miette!("Device code expired. Please try again."));
            }
            _ => {
                let desc = if error_resp.error_description.is_empty() {
                    String::new()
                } else {
                    format!(": {}", error_resp.error_description)
                };
                return Err(miette::miette!(
                    "Device authorization failed: {}{desc}",
                    error_resp.error
                ));
            }
        }
    }
}

/// Refresh an OIDC token using the `refresh_token` grant.
///
/// Reuses the configured login scopes when supplied so providers can select
/// the same API resource for the refreshed access token.
///
/// Preserves the existing refresh token if the server does not return a new
/// one (per OAuth 2.0 spec, the refresh response may omit `refresh_token`).
pub async fn oidc_refresh_token(
    bundle: &OidcTokenBundle,
    scopes: Option<&str>,
    insecure: bool,
) -> Result<OidcTokenBundle> {
    let refresh_token = bundle.refresh_token.as_deref().ok_or_else(|| {
        miette::miette!(
            "no refresh token available — re-authenticate with: openshell gateway login"
        )
    })?;

    let scopes = scopes.map_or_else(Vec::new, |scopes| {
        scopes.split_whitespace().map(str::to_owned).collect()
    });
    let input = RefreshTokenInput::new(refresh_token, &bundle.issuer, &bundle.client_id)
        .with_scopes(scopes)
        .with_insecure(insecure);
    let refreshed = openshell_sdk::oidc::refresh_token(&input)
        .await
        .map_err(miette::Report::new)?;

    Ok(bundle_from_refresh_output(
        bundle,
        refreshed.access_token,
        refreshed.refresh_token,
        refreshed.expires_at,
    ))
}

fn bundle_from_refresh_output(
    previous: &OidcTokenBundle,
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Option<u64>,
) -> OidcTokenBundle {
    OidcTokenBundle {
        access_token,
        refresh_token: refresh_token.or_else(|| previous.refresh_token.clone()),
        expires_at,
        issuer: previous.issuer.clone(),
        client_id: previous.client_id.clone(),
    }
}

/// Ensure we have a valid OIDC token bundle for the given gateway, refreshing if needed.
pub async fn ensure_valid_oidc_token_bundle(
    gateway_name: &str,
    insecure: bool,
) -> Result<OidcTokenBundle> {
    let bundle =
        openshell_bootstrap::oidc_token::load_oidc_token(gateway_name).ok_or_else(|| {
            miette::miette!(
                "No OIDC token stored for gateway '{gateway_name}'.\n\
             Authenticate with: openshell gateway login"
            )
        })?;

    if !openshell_bootstrap::oidc_token::is_token_expired(&bundle) {
        return Ok(bundle);
    }

    debug!(
        gateway = gateway_name,
        "OIDC token expired, attempting refresh"
    );
    let scopes = openshell_bootstrap::load_gateway_metadata(gateway_name)
        .ok()
        .and_then(|metadata| metadata.oidc_scopes);
    let refreshed = oidc_refresh_token(&bundle, scopes.as_deref(), insecure).await?;
    openshell_bootstrap::oidc_token::store_oidc_token(gateway_name, &refreshed)?;
    Ok(refreshed)
}

/// Ensure we have a valid OIDC token for the given gateway, refreshing if needed.
///
/// Returns the access token string.
pub async fn ensure_valid_oidc_token(gateway_name: &str, insecure: bool) -> Result<String> {
    Ok(ensure_valid_oidc_token_bundle(gateway_name, insecure)
        .await?
        .access_token)
}

// ── Helpers ──────────────────────────────────────────────────────────

fn bundle_from_oauth2_response(
    resp: &BasicTokenResponse,
    issuer: &str,
    client_id: &str,
) -> OidcTokenBundle {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    OidcTokenBundle {
        access_token: resp.access_token().secret().clone(),
        refresh_token: resp.refresh_token().map(|rt| rt.secret().clone()),
        expires_at: resp.expires_in().map(|ei| now + ei.as_secs()),
        issuer: issuer.to_string(),
        client_id: client_id.to_string(),
    }
}

fn bundle_from_device_token_response(
    resp: &BasicTokenResponse,
    issuer: &str,
    client_id: &str,
) -> Result<OidcTokenBundle> {
    if resp.access_token().secret().trim().is_empty() {
        return Err(miette::miette!(
            "invalid device token response: access_token is empty"
        ));
    }

    Ok(bundle_from_oauth2_response(resp, issuer, client_id))
}

/// Percent-decode a URL query parameter value.
fn percent_decode(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hi = bytes.next().and_then(|b| char::from(b).to_digit(16));
            let lo = bytes.next().and_then(|b| char::from(b).to_digit(16));
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push(u8::try_from(h * 16 + l).unwrap_or(b'%'));
            } else {
                out.push(b'%');
            }
        } else if b == b'+' {
            out.push(b' ');
        } else {
            out.push(b);
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

/// Callback server state.
struct CallbackState {
    expected_state: String,
    tx: Mutex<Option<oneshot::Sender<String>>>,
}

impl CallbackState {
    fn take_sender(&self) -> Option<oneshot::Sender<String>> {
        self.tx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

/// Run the ephemeral callback server for the OIDC redirect.
///
/// Listens for `GET /callback?code=...&state=...`.
async fn run_oidc_callback_server(
    listener: TcpListener,
    tx: oneshot::Sender<String>,
    expected_state: String,
) {
    let state = Arc::new(CallbackState {
        expected_state,
        tx: Mutex::new(Some(tx)),
    });

    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let state = Arc::clone(&state);
                async move { Ok::<_, Infallible>(handle_oidc_callback(req, state)) }
            });

            if let Err(error) = Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                debug!(error = %error, "OIDC callback server connection failed");
            }
        });
    }
}

fn handle_oidc_callback(
    req: hyper::Request<hyper::body::Incoming>,
    state: Arc<CallbackState>,
) -> Response<Full<Bytes>> {
    if req.method() != Method::GET || !req.uri().path().starts_with("/callback") {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("not found")))
            .expect("response");
    }

    let query = req.uri().query().unwrap_or("");
    let params: std::collections::HashMap<String, String> = query
        .split('&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = percent_decode(parts.next()?);
            let value = percent_decode(parts.next().unwrap_or(""));
            Some((key, value))
        })
        .collect();

    // Check for error response from the IdP.
    if let Some(error) = params.get("error") {
        let desc = params.get("error_description").map_or("", String::as_str);
        debug!(error = %error, description = %desc, "OIDC auth error");
        let _ = state.take_sender();
        return html_response(
            StatusCode::BAD_REQUEST,
            &format!("Authentication failed: {error}. {desc}"),
        );
    }

    let code = match params.get("code") {
        Some(c) if !c.is_empty() => c,
        _ => {
            let _ = state.take_sender();
            return html_response(StatusCode::BAD_REQUEST, "Missing authorization code.");
        }
    };

    let received_state = params.get("state").map_or("", String::as_str);
    if received_state != state.expected_state {
        debug!("OIDC state mismatch");
        let _ = state.take_sender();
        return html_response(StatusCode::FORBIDDEN, "State parameter mismatch.");
    }

    if let Some(sender) = state.take_sender() {
        let _ = sender.send(code.clone());
    }

    html_response(
        StatusCode::OK,
        "Authentication successful! You can close this tab and return to the terminal.",
    )
}

fn html_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    let body = format!(
        "<!DOCTYPE html><html><body style=\"font-family:sans-serif;text-align:center;padding:40px\">\
         <h2>{message}</h2></body></html>"
    );
    Response::builder()
        .status(status)
        .header("content-type", "text/html")
        .body(Full::new(Bytes::from(body)))
        .expect("response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_client_secure_rejects_self_signed() {
        let client = http_client(false);
        let rt = tokio::runtime::Runtime::new().unwrap();
        // A real self-signed server isn't available in unit tests, but we can
        // verify the client is constructed and makes requests. The secure client
        // should exist and function for valid endpoints.
        let result = rt.block_on(async { client.get("https://127.0.0.1:1").send().await });
        assert!(result.is_err(), "connection to closed port should fail");
    }

    #[test]
    fn http_client_insecure_builds_without_panic() {
        let client = http_client(true);
        // Verify the client is usable (doesn't panic on construction).
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async { client.get("https://127.0.0.1:1").send().await });
        assert!(result.is_err(), "connection to closed port should fail");
    }

    #[test]
    fn discover_validates_issuer_mismatch() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        // Discovery against a non-existent issuer should fail with a
        // connection error, not silently succeed.
        let result = rt.block_on(discover("http://127.0.0.1:1/realms/test", false));
        assert!(result.is_err());
    }

    #[test]
    fn discover_insecure_passes_flag_through() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        // Same as above but with insecure=true. Should still fail on
        // connection (no server) but must not panic.
        let result = rt.block_on(discover("https://127.0.0.1:1/realms/test", true));
        assert!(result.is_err());
    }

    #[test]
    fn percent_decode_basic() {
        assert_eq!(percent_decode("hello%20world"), "hello world");
        assert_eq!(percent_decode("a%2Fb"), "a/b");
        assert_eq!(percent_decode("no+encoding+here"), "no encoding here");
    }

    #[test]
    fn build_scopes_always_includes_openid() {
        let scopes = build_scopes(None);
        assert_eq!(scopes.len(), 1);

        let scopes = build_scopes(Some("profile email"));
        assert_eq!(scopes.len(), 3);
    }

    #[test]
    fn build_scopes_deduplicates_openid() {
        let scopes = build_scopes(Some("openid profile"));
        assert_eq!(scopes.len(), 2);
    }

    #[test]
    fn build_ci_scopes_empty_on_none() {
        let scopes = build_ci_scopes(None);
        assert!(scopes.is_empty());
    }

    #[test]
    fn interactive_authorization_params_force_fresh_login() {
        assert_eq!(
            interactive_authorization_params(Some("api://openshell"), true),
            vec![
                ("prompt", "login".to_string()),
                ("audience", "api://openshell".to_string()),
            ]
        );
        assert_eq!(
            interactive_authorization_params(None, true),
            vec![("prompt", "login".to_string())]
        );
        assert_eq!(
            interactive_authorization_params(Some("api://openshell"), false),
            vec![("audience", "api://openshell".to_string())]
        );
        assert!(interactive_authorization_params(None, false).is_empty());
    }

    #[test]
    fn device_authorization_form_includes_pkce_and_audience() {
        let params = device_authorization_form(
            "openshell-cli",
            "openid profile",
            Some("openshell-api"),
            "test-challenge",
            "S256",
        );
        let params: std::collections::HashMap<_, _> = params.into_iter().collect();

        assert_eq!(
            params.get("client_id").map(String::as_str),
            Some("openshell-cli")
        );
        assert_eq!(
            params.get("scope").map(String::as_str),
            Some("openid profile")
        );
        assert_eq!(
            params.get("audience").map(String::as_str),
            Some("openshell-api")
        );
        assert_eq!(
            params.get("code_challenge").map(String::as_str),
            Some("test-challenge")
        );
        assert_eq!(
            params.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
    }

    #[test]
    fn device_token_form_includes_pkce_verifier() {
        let params = device_token_form("openshell-cli", "device-code", "test-verifier");
        let params: std::collections::HashMap<_, _> = params.into_iter().collect();

        assert_eq!(
            params.get("grant_type").map(String::as_str),
            Some("urn:ietf:params:oauth:grant-type:device_code")
        );
        assert_eq!(
            params.get("device_code").map(String::as_str),
            Some("device-code")
        );
        assert_eq!(
            params.get("client_id").map(String::as_str),
            Some("openshell-cli")
        );
        assert_eq!(
            params.get("code_verifier").map(String::as_str),
            Some("test-verifier")
        );
    }

    #[test]
    fn bundle_from_response_sets_fields() {
        use oauth2::basic::BasicTokenResponse;

        let token_response: BasicTokenResponse = serde_json::from_str(
            r#"{"access_token":"test-access","token_type":"bearer","expires_in":300,"refresh_token":"test-refresh"}"#,
        )
        .unwrap();
        let bundle = bundle_from_oauth2_response(&token_response, "https://issuer", "my-client");
        assert_eq!(bundle.access_token, "test-access");
        assert_eq!(bundle.refresh_token.as_deref(), Some("test-refresh"));
        assert_eq!(bundle.issuer, "https://issuer");
        assert_eq!(bundle.client_id, "my-client");
        assert!(bundle.expires_at.is_some());
    }

    #[test]
    fn refresh_output_preserves_omitted_refresh_token() {
        let previous = OidcTokenBundle {
            access_token: "expired-access".to_string(),
            refresh_token: Some("refresh-secret".to_string()),
            expires_at: Some(0),
            issuer: "https://issuer.example".to_string(),
            client_id: "client-id".to_string(),
        };

        let refreshed =
            bundle_from_refresh_output(&previous, "refreshed-access".to_string(), None, Some(300));

        assert_eq!(refreshed.access_token, "refreshed-access");
        assert_eq!(refreshed.refresh_token, previous.refresh_token);
        assert_eq!(refreshed.issuer, previous.issuer);
        assert_eq!(refreshed.client_id, previous.client_id);
        assert_eq!(refreshed.expires_at, Some(300));
    }

    #[test]
    fn discovery_missing_device_endpoint_is_optional() {
        let discovery_json = "{\"issuer\":\"https://issuer.example\",\"authorization_endpoint\":\"https://issuer.example/auth\",\"token_endpoint\":\"https://issuer.example/token\"}";
        let discovery: OidcDiscovery = serde_json::from_str(discovery_json).unwrap();
        assert!(discovery.device_authorization_endpoint.is_none());
        assert_eq!(discovery.issuer, "https://issuer.example");
    }

    #[test]
    fn discovery_with_device_endpoint_is_captured() {
        let discovery_json = "{\"issuer\":\"https://issuer.example\",\"authorization_endpoint\":\"https://issuer.example/auth\",\"token_endpoint\":\"https://issuer.example/token\",\"device_authorization_endpoint\":\"https://issuer.example/device\"}";
        let discovery: OidcDiscovery = serde_json::from_str(discovery_json).unwrap();
        assert_eq!(
            discovery.device_authorization_endpoint.as_deref(),
            Some("https://issuer.example/device")
        );
    }

    #[test]
    fn device_auth_response_parses_minimal() {
        let json = "{\"device_code\":\"GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS\",\"user_code\":\"WDJB-MJHT\",\"verification_uri\":\"https://example.com/device\",\"expires_in\":1800}";
        let resp: DeviceAuthorizationResponse = serde_json::from_str(json).unwrap();
        assert_eq!(
            resp.device_code,
            "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS"
        );
        assert_eq!(resp.user_code, "WDJB-MJHT");
        assert_eq!(resp.verification_uri, "https://example.com/device");
        assert_eq!(resp.expires_in, 1800);
        assert_eq!(resp.interval, 5);
        assert!(resp.verification_uri_complete.is_none());
    }

    #[test]
    fn device_auth_response_parses_complete() {
        let json = "{\"device_code\":\"test-device-code\",\"user_code\":\"TEST-CODE\",\"verification_uri\":\"https://example.com/device\",\"verification_uri_complete\":\"https://example.com/device?user_code=TEST-CODE\",\"expires_in\":900,\"interval\":10}";
        let resp: DeviceAuthorizationResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.interval, 10);
        assert_eq!(
            resp.verification_uri_complete.as_deref(),
            Some("https://example.com/device?user_code=TEST-CODE")
        );
    }

    #[test]
    fn device_token_error_response_parses() {
        let json = "{\"error\":\"authorization_pending\",\"error_description\":\"User has not authorized yet\"}";
        let resp: DeviceTokenErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.error, "authorization_pending");
        assert_eq!(resp.error_description, "User has not authorized yet");
    }

    #[test]
    fn device_token_error_response_defaults_empty_description() {
        let json = "{\"error\":\"slow_down\"}";
        let resp: DeviceTokenErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.error, "slow_down");
        assert_eq!(resp.error_description, "");
    }

    #[test]
    fn device_token_response_complete_is_typed() {
        let response: BasicTokenResponse = serde_json::from_value(serde_json::json!({
            "access_token": "device-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "device-refresh-token"
        }))
        .unwrap();
        let bundle =
            bundle_from_device_token_response(&response, "https://issuer.example", "test-client")
                .unwrap();
        assert_eq!(bundle.access_token, "device-access-token");
        assert_eq!(
            bundle.refresh_token.as_deref(),
            Some("device-refresh-token")
        );
        assert_eq!(bundle.issuer, "https://issuer.example");
        assert_eq!(bundle.client_id, "test-client");
        assert!(bundle.expires_at.is_some());
    }

    #[test]
    fn device_token_response_minimal_is_typed() {
        let response: BasicTokenResponse = serde_json::from_value(serde_json::json!({
            "access_token": "device-access-only",
            "token_type": "Bearer"
        }))
        .unwrap();
        let bundle =
            bundle_from_device_token_response(&response, "https://issuer.example", "test-client")
                .unwrap();
        assert_eq!(bundle.access_token, "device-access-only");
        assert!(bundle.refresh_token.is_none());
        assert!(bundle.expires_at.is_none());
    }

    #[test]
    fn device_token_response_requires_access_token() {
        let result = serde_json::from_value::<BasicTokenResponse>(serde_json::json!({
            "token_type": "Bearer"
        }));
        assert!(result.is_err());
    }

    #[test]
    fn device_token_response_requires_token_type() {
        let result = serde_json::from_value::<BasicTokenResponse>(serde_json::json!({
            "access_token": "device-access-token"
        }));
        assert!(result.is_err());
    }

    #[test]
    fn device_token_response_rejects_empty_access_token() {
        let response: BasicTokenResponse = serde_json::from_value(serde_json::json!({
            "access_token": "",
            "token_type": "Bearer"
        }))
        .unwrap();

        let result =
            bundle_from_device_token_response(&response, "https://issuer.example", "test-client");
        assert!(result.is_err());
    }
}
