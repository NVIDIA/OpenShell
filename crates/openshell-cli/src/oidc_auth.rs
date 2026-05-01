// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OIDC authentication flows for CLI gateway login.
//!
//! Implements Authorization Code + PKCE (interactive browser flow) and
//! Client Credentials (CI/automation) `OAuth2` grant types against a
//! Keycloak-compatible OIDC provider.

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Method, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use miette::{IntoDiagnostic, Result};
use oauth2::basic::BasicClient;
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    RedirectUrl, RefreshToken, Scope, TokenResponse, TokenUrl,
};
use openshell_bootstrap::oidc_token::OidcTokenBundle;
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
}

/// Discover OIDC endpoints from the issuer's well-known configuration.
///
/// Validates that the discovery document's `issuer` field matches the
/// configured issuer URL to prevent SSRF or misdirection.
async fn discover(issuer: &str) -> Result<OidcDiscovery> {
    let normalized_issuer = issuer.trim_end_matches('/');
    let url = format!("{normalized_issuer}/.well-known/openid-configuration");
    let resp: OidcDiscovery = reqwest::get(&url)
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

fn http_client() -> reqwest::Client {
    reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to build HTTP client")
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

/// Run the OIDC Authorization Code + PKCE browser flow.
///
/// Opens the user's browser to the Keycloak login page and waits for
/// the authorization code redirect on a localhost callback server.
pub async fn oidc_browser_auth_flow(
    issuer: &str,
    client_id: &str,
    audience: Option<&str>,
    scopes: Option<&str>,
) -> Result<OidcTokenBundle> {
    let discovery = discover(issuer).await?;

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

    // Append audience parameter for providers like Entra ID where the API
    // audience differs from the client ID.
    if let Some(aud) = audience {
        auth_url.query_pairs_mut().append_pair("audience", aud);
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

    let http = http_client();
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
) -> Result<OidcTokenBundle> {
    let client_secret = std::env::var("OPENSHELL_OIDC_CLIENT_SECRET").map_err(|_| {
        miette::miette!(
            "OPENSHELL_OIDC_CLIENT_SECRET environment variable is required for client credentials flow"
        )
    })?;

    let discovery = discover(issuer).await?;

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

    let http = http_client();
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

/// Refresh an OIDC token using the `refresh_token` grant.
///
/// Preserves the existing refresh token if the server does not return a new
/// one (per OAuth 2.0 spec, the refresh response may omit `refresh_token`).
pub async fn oidc_refresh_token(bundle: &OidcTokenBundle) -> Result<OidcTokenBundle> {
    let refresh_token = bundle.refresh_token.as_deref().ok_or_else(|| {
        miette::miette!(
            "no refresh token available — re-authenticate with: openshell gateway login"
        )
    })?;

    let discovery = discover(&bundle.issuer).await?;

    let client = BasicClient::new(ClientId::new(bundle.client_id.clone()))
        .set_token_uri(TokenUrl::new(discovery.token_endpoint).into_diagnostic()?);

    let http = http_client();
    let token_response = client
        .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
        .request_async(&http)
        .await
        .map_err(|e| miette::miette!("token refresh failed: {e}"))?;

    let mut refreshed =
        bundle_from_oauth2_response(&token_response, &bundle.issuer, &bundle.client_id);
    if refreshed.refresh_token.is_none() {
        refreshed.refresh_token.clone_from(&bundle.refresh_token);
    }
    Ok(refreshed)
}

/// Ensure we have a valid OIDC token for the given gateway, refreshing if needed.
///
/// Returns the access token string.
pub async fn ensure_valid_oidc_token(gateway_name: &str) -> Result<String> {
    let bundle =
        openshell_bootstrap::oidc_token::load_oidc_token(gateway_name).ok_or_else(|| {
            miette::miette!(
                "No OIDC token stored for gateway '{gateway_name}'.\n\
             Authenticate with: openshell gateway login"
            )
        })?;

    if !openshell_bootstrap::oidc_token::is_token_expired(&bundle) {
        return Ok(bundle.access_token);
    }

    debug!(
        gateway = gateway_name,
        "OIDC token expired, attempting refresh"
    );
    let refreshed = oidc_refresh_token(&bundle).await?;
    openshell_bootstrap::oidc_token::store_oidc_token(gateway_name, &refreshed)?;
    Ok(refreshed.access_token)
}

// ── Helpers ──────────────────────────────────────────────────────────

fn bundle_from_oauth2_response(
    resp: &oauth2::basic::BasicTokenResponse,
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
