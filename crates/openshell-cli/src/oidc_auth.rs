// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OIDC authentication flows for CLI gateway login.
//!
//! Implements Authorization Code + PKCE (interactive browser flow) and
//! Client Credentials (CI/automation) OAuth2 grant types against a
//! Keycloak-compatible OIDC provider.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Method, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use miette::{IntoDiagnostic, Result};
use openshell_bootstrap::oidc_token::OidcTokenBundle;
use serde::Deserialize;
use sha2::{Digest, Sha256};
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

/// Token endpoint response.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
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

/// Generate a random PKCE code verifier (43-128 unreserved chars).
fn generate_code_verifier() -> String {
    let mut buf = [0u8; 32];
    csprng_fill(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// Compute the S256 code challenge from a code verifier.
fn compute_code_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// Generate a random state parameter.
fn generate_state() -> String {
    let mut buf = [0u8; 16];
    csprng_fill(&mut buf);
    hex::encode(buf)
}

/// Fill a buffer with cryptographically secure random bytes from the OS.
fn csprng_fill(buf: &mut [u8]) {
    getrandom::fill(buf).expect("OS RNG failed");
}

/// Run the OIDC Authorization Code + PKCE browser flow.
///
/// Opens the user's browser to the Keycloak login page and waits for
/// the authorization code redirect on a localhost callback server.
pub async fn oidc_browser_auth_flow(
    issuer: &str,
    client_id: &str,
    audience: Option<&str>,
) -> Result<OidcTokenBundle> {
    let discovery = discover(issuer).await?;

    let code_verifier = generate_code_verifier();
    let code_challenge = compute_code_challenge(&code_verifier);
    let state = generate_state();

    let listener = TcpListener::bind("127.0.0.1:0").await.into_diagnostic()?;
    let port = listener.local_addr().into_diagnostic()?.port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    let mut auth_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state={}&scope=openid",
        discovery.authorization_endpoint,
        urlencoded(client_id),
        urlencoded(&redirect_uri),
        urlencoded(&code_challenge),
        urlencoded(&state),
    );
    // Request a specific API audience when configured (needed for providers
    // like Entra ID where the API audience differs from the client ID).
    if let Some(aud) = audience {
        auth_url.push_str(&format!("&audience={}", urlencoded(aud)));
    }

    let (tx, rx) = oneshot::channel::<String>();
    let expected_state = state.clone();

    let server_handle = tokio::spawn(run_oidc_callback_server(listener, tx, expected_state));

    eprintln!("  Opening browser for OIDC authentication...");
    if let Err(e) = crate::auth::open_browser_url(&auth_url) {
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

    // Exchange the authorization code for tokens.
    let token_response = exchange_code(
        &discovery.token_endpoint,
        client_id,
        &code,
        &redirect_uri,
        &code_verifier,
    )
    .await?;

    Ok(bundle_from_response(token_response, issuer, client_id))
}

/// Run the OIDC Client Credentials flow (for CI/automation).
///
/// Reads `OPENSHELL_OIDC_CLIENT_SECRET` from the environment.
pub async fn oidc_client_credentials_flow(
    issuer: &str,
    client_id: &str,
    audience: Option<&str>,
) -> Result<OidcTokenBundle> {
    let client_secret = std::env::var("OPENSHELL_OIDC_CLIENT_SECRET").map_err(|_| {
        miette::miette!(
            "OPENSHELL_OIDC_CLIENT_SECRET environment variable is required for client credentials flow"
        )
    })?;

    let discovery = discover(issuer).await?;

    let mut params = vec![
        ("grant_type", "client_credentials"),
        ("client_id", client_id),
        ("client_secret", client_secret.as_str()),
    ];
    if let Some(aud) = audience {
        params.push(("audience", aud));
    }

    let client = reqwest::Client::new();
    let resp: TokenResponse = client
        .post(&discovery.token_endpoint)
        .form(&params)
        .send()
        .await
        .into_diagnostic()?
        .json()
        .await
        .into_diagnostic()?;

    Ok(bundle_from_response(resp, issuer, client_id))
}

/// Refresh an OIDC token using the refresh_token grant.
///
/// Preserves the existing refresh token if the server does not return a new
/// one (per OAuth 2.0 spec, the refresh response may omit `refresh_token`).
pub async fn oidc_refresh_token(bundle: &OidcTokenBundle) -> Result<OidcTokenBundle> {
    let refresh_token = bundle.refresh_token.as_deref().ok_or_else(|| {
        miette::miette!("no refresh token available — re-authenticate with: openshell gateway login")
    })?;

    let discovery = discover(&bundle.issuer).await?;

    let params = [
        ("grant_type", "refresh_token"),
        ("client_id", bundle.client_id.as_str()),
        ("refresh_token", refresh_token),
    ];

    let client = reqwest::Client::new();
    let resp: TokenResponse = client
        .post(&discovery.token_endpoint)
        .form(&params)
        .send()
        .await
        .into_diagnostic()?
        .json()
        .await
        .into_diagnostic()?;

    let mut refreshed = bundle_from_response(resp, &bundle.issuer, &bundle.client_id);
    // Preserve the old refresh token if the server didn't return a new one.
    if refreshed.refresh_token.is_none() {
        refreshed.refresh_token = bundle.refresh_token.clone();
    }
    Ok(refreshed)
}

/// Ensure we have a valid OIDC token for the given gateway, refreshing if needed.
///
/// Returns the access token string.
pub async fn ensure_valid_oidc_token(gateway_name: &str) -> Result<String> {
    let bundle = openshell_bootstrap::oidc_token::load_oidc_token(gateway_name).ok_or_else(|| {
        miette::miette!(
            "No OIDC token stored for gateway '{gateway_name}'.\n\
             Authenticate with: openshell gateway login"
        )
    })?;

    if !openshell_bootstrap::oidc_token::is_token_expired(&bundle) {
        return Ok(bundle.access_token);
    }

    // Token expired — try to refresh.
    debug!(gateway = gateway_name, "OIDC token expired, attempting refresh");
    let refreshed = oidc_refresh_token(&bundle).await?;
    openshell_bootstrap::oidc_token::store_oidc_token(gateway_name, &refreshed)?;
    Ok(refreshed.access_token)
}

// ── Helpers ──────────────────────────────────────────────────────────

fn bundle_from_response(resp: TokenResponse, issuer: &str, client_id: &str) -> OidcTokenBundle {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    OidcTokenBundle {
        access_token: resp.access_token,
        refresh_token: resp.refresh_token,
        expires_at: resp.expires_in.map(|ei| now + ei),
        issuer: issuer.to_string(),
        client_id: client_id.to_string(),
    }
}

async fn exchange_code(
    token_endpoint: &str,
    client_id: &str,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<TokenResponse> {
    let params = [
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", code_verifier),
    ];

    let client = reqwest::Client::new();
    let resp: TokenResponse = client
        .post(token_endpoint)
        .form(&params)
        .send()
        .await
        .into_diagnostic()?
        .json()
        .await
        .into_diagnostic()?;

    Ok(resp)
}

/// Minimal percent-encoding for URL query parameter values.
fn urlencoded(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
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
                out.push((h * 16 + l) as u8);
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
                async move {
                    Ok::<_, Infallible>(handle_oidc_callback(req, state).await)
                }
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

async fn handle_oidc_callback(
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
