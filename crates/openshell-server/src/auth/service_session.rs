// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Browser login happens on the control-plane origin. Only a single-use,
//! host-bound code reaches the application origin. Session secrets live in the
//! configured credential driver; the shared store contains non-secret metadata.

use super::{
    principal::Principal,
    service_access::{self, ServicePeer},
};
use crate::{
    ServerState,
    persistence::{ObjectRecord, WriteCondition},
};
use axum::{
    body::{Body, to_bytes},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use openshell_core::proto::CredentialHandle;
use prost::Message;
use serde::{Deserialize, Serialize};
use tonic::Status;

pub const PREFIX: &str = "/.openshell/service-auth";
pub const CONTROL: &str = "/auth/services";
pub const COOKIE: &str = "__Host-openshell-service-session";
pub const GATEWAY_AUTH: &str = "x-openshell-authorization";
const LOGIN_COOKIE: &str = "__Host-openshell-service-login";
const SESSION: &str = "gateway_application_session";
const REVOKED: &str = "gateway_application_revocation";
const REVOCATION_SCOPE: &str = "__gateway_application_auth";

#[derive(Serialize, Deserialize)]
struct Session {
    host: String,
    expires: u64,
    pending_until: u64,
    login_state: String,
    handle: String,
    credential_id: String,
    cookie_key: String,
    redeemed: bool,
    revoked: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    service_origin: String,
    state: String,
}

fn now() -> u64 {
    openshell_core::time::now_ms().max(0).cast_unsigned() / 1000
}
fn internal() -> Status {
    Status::unavailable("application authentication unavailable")
}
fn digest(value: &str) -> Result<String, Status> {
    openshell_crypto::sha256(value.as_bytes())
        .map(|hash| URL_SAFE_NO_PAD.encode(hash))
        .map_err(|_| internal())
}
fn random() -> Result<String, Status> {
    openshell_crypto::random_bytes::<32>()
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|_| internal())
}
fn session(record: &ObjectRecord) -> Result<Session, Status> {
    serde_json::from_slice(&record.payload).map_err(|_| internal())
}
fn credential_handle(value: &Session) -> Result<CredentialHandle, Status> {
    CredentialHandle::decode(
        URL_SAFE_NO_PAD
            .decode(&value.handle)
            .map_err(|_| internal())?
            .as_slice(),
    )
    .map_err(|_| internal())
}

// Parsing only, after the configured authenticator verifies the credential.
// Expiration is also checked here without the JWT library's clock-skew leeway.
fn token_expiry(token: &str) -> Result<u64, Status> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| Status::unauthenticated("invalid token"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| Status::unauthenticated("invalid token"))?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| Status::unauthenticated("invalid token"))?;
    value
        .get("exp")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| Status::unauthenticated("token expiration required"))
}

pub async fn check_token(state: &ServerState, token: &str) -> Result<(), Status> {
    if token.len() > 16384 || token_expiry(token)? <= now() {
        return Err(Status::unauthenticated("expired or invalid credential"));
    }
    if state
        .store
        .get(REVOKED, &digest(token)?)
        .await
        .map_err(|_| internal())?
        .is_some()
    {
        return Err(Status::unauthenticated(
            "revoked application access credential",
        ));
    }
    Ok(())
}

pub async fn check_certificate(state: &ServerState, fingerprint: &str) -> Result<(), Status> {
    if state
        .store
        .get(REVOKED, &format!("mtls-{fingerprint}"))
        .await
        .map_err(|_| internal())?
        .is_some()
    {
        return Err(Status::unauthenticated(
            "revoked application client certificate",
        ));
    }
    Ok(())
}

fn cookie(headers: &HeaderMap, wanted: &str) -> Result<Option<String>, Status> {
    let mut found = None;
    for value in headers.get_all(header::COOKIE) {
        for item in value
            .to_str()
            .map_err(|_| Status::unauthenticated("invalid cookie"))?
            .split(';')
        {
            if let Some((name, value)) = item.trim().split_once('=')
                && name == wanted
            {
                if found.is_some() || value.len() != 43 {
                    return Err(Status::unauthenticated(
                        "ambiguous or invalid session cookie",
                    ));
                }
                found = Some(value.to_string());
            }
        }
    }
    Ok(found)
}

fn origin(value: &str) -> Result<url::Url, Status> {
    let url = url::Url::parse(value).map_err(|_| Status::invalid_argument("invalid origin"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Status::invalid_argument("HTTPS origin required"));
    }
    Ok(url)
}
fn request_origin(req: &Request<Body>) -> Result<url::Url, Status> {
    origin(&format!(
        "https://{}",
        crate::service_routing::request_host(req)
            .ok_or_else(|| Status::invalid_argument("missing host"))?
    ))
}
fn secure(req: &Request<Body>) -> Result<(), Status> {
    if req
        .extensions()
        .get::<ServicePeer>()
        .is_some_and(|p| p.secure)
    {
        Ok(())
    } else {
        Err(Status::permission_denied(
            "browser authentication requires gateway HTTPS",
        ))
    }
}
fn browser_origin(req: &Request<Body>, required: bool) -> Result<(), Status> {
    if req
        .headers()
        .get("sec-fetch-site")
        .is_some_and(|v| v != "same-origin" && v != "none")
    {
        return Err(Status::permission_denied(
            "cross-origin application request",
        ));
    }
    match req.headers().get(header::ORIGIN) {
        Some(value)
            if value
                .to_str()
                .ok()
                .and_then(|s| origin(s).ok())
                .is_some_and(|u| {
                    request_origin(req).is_ok_and(|ours| ours.origin() == u.origin())
                }) =>
        {
            Ok(())
        }
        None if !required => Ok(()),
        _ => Err(Status::permission_denied("same-origin request required")),
    }
}
fn ambient_request(req: &Request<Body>) -> Result<(), Status> {
    browser_origin(
        req,
        !matches!(*req.method(), Method::GET | Method::HEAD)
            || req.headers().contains_key(header::UPGRADE),
    )
}

async fn active_token(
    state: &ServerState,
    host: &str,
    workspace: &str,
    value: &str,
) -> Result<String, Status> {
    let key = digest(value)?;
    let record = state
        .store
        .get(SESSION, &key)
        .await
        .map_err(|_| internal())?
        .ok_or_else(|| Status::unauthenticated("session expired or revoked"))?;
    let session = session(&record)?;
    if !session.redeemed
        || session.cookie_key != key
        || session.revoked
        || session.host != host
        || record.workspace != workspace
        || session.expires <= now()
    {
        return Err(Status::unauthenticated("session expired or wrong host"));
    }
    state
        .credentials
        .resolve_application_token(
            workspace,
            &session.credential_id,
            credential_handle(&session)?,
        )
        .await
}

pub async fn authorize_request(
    state: &ServerState,
    req: &mut Request<Body>,
    workspace: &str,
) -> Result<Option<String>, Status> {
    let peer = req
        .extensions()
        .get::<ServicePeer>()
        .cloned()
        .unwrap_or_default();
    let session = cookie(req.headers(), COOKIE)?;
    let explicit = req.headers().get(GATEWAY_AUTH).cloned();
    if req.headers().get_all(GATEWAY_AUTH).iter().count() > 1
        || (explicit.is_some() && session.is_some())
    {
        return Err(Status::unauthenticated("ambiguous gateway credentials"));
    }
    let mut headers = req.headers().clone();
    let mut consumed = false;
    let token = if let Some(value) = session {
        secure(req)?;
        ambient_request(req)?;
        let host = request_origin(req)?.origin().ascii_serialization();
        let token = active_token(state, &host, workspace, &value).await?;
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| internal())?,
        );
        Some(token)
    } else if let Some(value) = explicit {
        headers.insert(header::AUTHORIZATION, value);
        super::authenticator::bearer_credential(&headers).map(str::to_string)
    } else if peer.identity.is_some()
        && (state.config.mtls_auth.enabled || state.config.mtls_auth.operator_enabled)
    {
        ambient_request(req)?;
        headers.remove(header::AUTHORIZATION);
        None
    } else if state.config.auth.allow_unauthenticated_users
        && state.config.oidc.is_none()
        && !state.config.mtls_auth.enabled
    {
        // Explicit local development has no gateway user bearer in this header.
        headers.remove(header::AUTHORIZATION);
        None
    } else {
        consumed = true;
        super::authenticator::bearer_credential(&headers).map(str::to_string)
    };
    service_access::authorize(state, &headers, &peer, workspace).await?;
    if consumed
        || token.as_deref().is_some_and(|gateway| {
            super::authenticator::bearer_credential(req.headers()) == Some(gateway)
        })
    {
        req.headers_mut().remove(header::AUTHORIZATION);
    }
    Ok(token)
}

async fn cleanup(state: &ServerState, workspace: &str) -> Result<(), Status> {
    for record in state
        .store
        .list(SESSION, workspace, 1024, 0)
        .await
        .map_err(|_| internal())?
    {
        let value = session(&record)?;
        if value.revoked
            || value.expires <= now()
            || !value.redeemed && value.pending_until <= now()
        {
            state
                .credentials
                .delete_application_token(
                    workspace,
                    &value.credential_id,
                    credential_handle(&value)?,
                )
                .await?;
            state
                .store
                .delete(SESSION, &record.id)
                .await
                .map_err(|_| internal())?;
        }
    }
    for record in state
        .store
        .list(REVOKED, REVOCATION_SCOPE, 1024, 0)
        .await
        .map_err(|_| internal())?
    {
        if serde_json::from_slice::<u64>(&record.payload).map_err(|_| internal())? <= now() {
            state
                .store
                .delete(REVOKED, &record.id)
                .await
                .map_err(|_| internal())?;
        }
    }
    Ok(())
}

async fn service_origin(state: &ServerState, value: &str) -> Result<(url::Url, String), Status> {
    let origin = origin(value)?;
    let target =
        crate::service_routing::resolve_service_host(state, origin.host_str().unwrap_or_default())
            .await
            .ok_or_else(|| Status::invalid_argument("unknown service origin"))?;
    Ok((origin, target.workspace))
}
fn parameters(req: &Request<Body>) -> Result<std::collections::HashMap<String, String>, Status> {
    let mut params = std::collections::HashMap::new();
    for (key, value) in
        url::form_urlencoded::parse(req.uri().query().unwrap_or_default().as_bytes())
    {
        if params
            .insert(key.into_owned(), value.into_owned())
            .is_some()
        {
            return Err(Status::invalid_argument("duplicate parameter"));
        }
    }
    Ok(params)
}
fn redirect(url: &url::Url) -> Result<Response, Status> {
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(url.as_str()).map_err(|_| internal())?,
    );
    Ok(no_cache(response))
}

pub async fn control(state: &ServerState, mut req: Request<Body>) -> Result<Response, Status> {
    secure(&req)?;
    let control_origin = request_origin(&req)?;
    if req.method() == Method::GET {
        let params = parameters(&req)?;
        let (mut target, _) = service_origin(
            state,
            params.get("service_origin").map_or("", String::as_str),
        )
        .await?;
        let Some(login_state) = params.get("state") else {
            target.set_path(&format!("{PREFIX}/start"));
            target.query_pairs_mut().append_pair(
                "login_origin",
                &control_origin.origin().ascii_serialization(),
            );
            return redirect(&target);
        };
        if login_state.len() != 43 {
            return Err(Status::invalid_argument("invalid login state"));
        }
        let nonce = random()?;
        let body = serde_json::to_string(&LoginBody {
            service_origin: target.origin().ascii_serialization(),
            state: login_state.clone(),
        })
        .map_err(|_| internal())?
        .replace('<', "\\u003c");
        let html = format!(
            r#"<!doctype html><meta charset="utf-8"><title>OpenShell service sign in</title><h1>Sign in to a sandbox service</h1><p id="target"></p><p>Use a gateway access token from your configured identity provider. The service receives only a host-bound browser session.</p><form id="login"><label>Gateway token <input id="token" type="password" autocomplete="off" required></label><button>Sign in</button></form><p id="status"></p><script nonce="{nonce}">document.getElementById('target').textContent='Service: '+({body}).service_origin;document.getElementById('login').onsubmit=async e=>{{e.preventDefault();let t=document.getElementById('token');let v=t.value;t.value='';let r=await fetch('/auth/services',{{method:'POST',headers:{{Authorization:'Bearer '+v,'Content-Type':'application/json'}},body:JSON.stringify({body})}});v='';if(r.ok)location.replace((await r.json()).redirect);else document.getElementById('status').textContent='Sign in failed';}};</script>"#
        );
        let mut response = html.into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        response.headers_mut().insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_str(&format!("default-src 'none'; script-src 'nonce-{nonce}'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")).map_err(|_| internal())?);
        return Ok(no_cache(response));
    }
    browser_origin(&req, true)?;
    let peer = req
        .extensions()
        .get::<ServicePeer>()
        .cloned()
        .unwrap_or_default();
    let bytes = to_bytes(std::mem::replace(req.body_mut(), Body::empty()), 4096)
        .await
        .map_err(|_| Status::invalid_argument("invalid login request"))?;
    let login: Login = serde_json::from_slice(&bytes)
        .map_err(|_| Status::invalid_argument("invalid login request"))?;
    let (mut target, workspace) = service_origin(state, &login.service_origin).await?;
    if login.state.len() != 43 {
        return Err(Status::invalid_argument("invalid login state"));
    }
    let principal = service_access::authorize(state, req.headers(), &peer, &workspace).await?;
    if !matches!(principal, Principal::User(ref user) if user.identity.provider == super::identity::IdentityProvider::Oidc)
    {
        return Err(Status::permission_denied(
            "browser token sessions require an OIDC user",
        ));
    }
    let token = super::authenticator::bearer_credential(req.headers())
        .ok_or_else(|| Status::unauthenticated("gateway token required"))?;
    cleanup(state, &workspace).await?;
    let value = random()?;
    let key = digest(&value)?;
    let credential = state
        .credentials
        .store_application_token(&workspace, &key, token)
        .await?;
    let record = Session {
        host: target.origin().ascii_serialization(),
        expires: token_expiry(token)?.min(now() + 600),
        pending_until: now() + 120,
        login_state: digest(&login.state)?,
        handle: URL_SAFE_NO_PAD.encode(credential.encode_to_vec()),
        credential_id: key.clone(),
        cookie_key: String::new(),
        redeemed: false,
        revoked: false,
    };
    let payload = serde_json::to_vec(&record).map_err(|_| internal())?;
    let result = state
        .store
        .create_if_workspace_count_below(SESSION, &key, &key, &workspace, &payload, None, 1024)
        .await;
    if !matches!(result, Ok(Some(_))) {
        state
            .credentials
            .delete_application_token(&workspace, &key, credential)
            .await?;
        return Err(Status::resource_exhausted("browser session unavailable"));
    }
    target.set_path(&format!("{PREFIX}/redeem"));
    target.query_pairs_mut().append_pair("code", &value);
    Ok(no_cache(
        axum::Json(serde_json::json!({"redirect": target.as_str()})).into_response(),
    ))
}

#[derive(Serialize)]
struct LoginBody {
    service_origin: String,
    state: String,
}

pub async fn handle(
    state: &ServerState,
    req: &mut Request<Body>,
    workspace: &str,
) -> Result<Response, Status> {
    secure(req)?;
    let path = req.uri().path().to_string();
    if path == format!("{PREFIX}/start") && req.method() == Method::GET {
        let params = parameters(req)?;
        let mut login = origin(params.get("login_origin").map_or("", String::as_str))?;
        if crate::service_routing::resolve_service_host(state, login.host_str().unwrap_or_default())
            .await
            .is_some()
        {
            return Err(Status::invalid_argument(
                "login must use the control-plane origin",
            ));
        }
        login.set_path(CONTROL);
        let nonce = random()?;
        login
            .query_pairs_mut()
            .append_pair(
                "service_origin",
                &request_origin(req)?.origin().ascii_serialization(),
            )
            .append_pair("state", &nonce);
        return with_cookie(redirect(&login)?, LOGIN_COOKIE, &nonce, 120, "Lax");
    }
    if path == format!("{PREFIX}/redeem") && req.method() == Method::GET {
        let params = parameters(req)?;
        let code = params
            .get("code")
            .filter(|c| c.len() == 43)
            .ok_or_else(|| Status::unauthenticated("invalid login code"))?;
        let key = digest(code)?;
        let record = state
            .store
            .get(SESSION, &key)
            .await
            .map_err(|_| internal())?
            .ok_or_else(|| Status::unauthenticated("expired login code"))?;
        let mut value = session(&record)?;
        let nonce = cookie(req.headers(), LOGIN_COOKIE)?
            .ok_or_else(|| Status::unauthenticated("missing login state"))?;
        if record.workspace != workspace
            || value.host != request_origin(req)?.origin().ascii_serialization()
            || value.redeemed
            || value.revoked
            || value.pending_until <= now()
            || value.expires <= now()
            || value.login_state != digest(&nonce)?
        {
            return Err(Status::unauthenticated("invalid login code or state"));
        }
        let token = state
            .credentials
            .resolve_application_token(workspace, &value.credential_id, credential_handle(&value)?)
            .await?;
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| internal())?,
        );
        service_access::authorize(state, &headers, &ServicePeer::default(), workspace).await?;
        value.redeemed = true;
        let session_cookie = random()?;
        let session_key = digest(&session_cookie)?;
        value.cookie_key.clone_from(&session_key);
        let payload = serde_json::to_vec(&value).map_err(|_| internal())?;
        state
            .store
            .put_if(
                SESSION,
                &key,
                &key,
                workspace,
                &payload,
                None,
                WriteCondition::MatchResourceVersion(record.resource_version),
            )
            .await
            .map_err(|_| Status::unauthenticated("login code already consumed"))?;
        if state
            .store
            .create_if_workspace_count_below(
                SESSION,
                &session_key,
                &session_key,
                workspace,
                &payload,
                None,
                1024,
            )
            .await
            .map_err(|_| internal())?
            .is_none()
        {
            return Err(Status::resource_exhausted("browser session limit reached"));
        }
        state
            .store
            .delete(SESSION, &key)
            .await
            .map_err(|_| internal())?;
        let response = with_cookie(
            browser_complete()?,
            COOKIE,
            &session_cookie,
            value.expires.saturating_sub(now()),
            "Strict",
        )?;
        return with_cookie(response, LOGIN_COOKIE, "", 0, "Lax");
    }
    browser_origin(req, true)?;
    if path == format!("{PREFIX}/session") && req.method() == Method::DELETE {
        if let Some(cookie) = cookie(req.headers(), COOKIE)? {
            let key = digest(&cookie)?;
            if let Some(record) = state
                .store
                .get(SESSION, &key)
                .await
                .map_err(|_| internal())?
            {
                let mut value = session(&record)?;
                if record.workspace != workspace
                    || value.host != request_origin(req)?.origin().ascii_serialization()
                {
                    return Err(Status::permission_denied("wrong session host"));
                }
                value.revoked = true;
                state
                    .store
                    .put_if(
                        SESSION,
                        &key,
                        &key,
                        workspace,
                        &serde_json::to_vec(&value).map_err(|_| internal())?,
                        None,
                        WriteCondition::MatchResourceVersion(record.resource_version),
                    )
                    .await
                    .map_err(|_| internal())?;
                state
                    .credentials
                    .delete_application_token(
                        workspace,
                        &value.credential_id,
                        credential_handle(&value)?,
                    )
                    .await?;
                state
                    .store
                    .delete(SESSION, &key)
                    .await
                    .map_err(|_| internal())?;
            }
        }
        return with_cookie(
            StatusCode::NO_CONTENT.into_response(),
            COOKIE,
            "",
            0,
            "Strict",
        );
    }
    if path == format!("{PREFIX}/credential") && req.method() == Method::DELETE {
        // A service-scoped browser session must not administer the underlying
        // gateway credential's access to other services.
        if cookie(req.headers(), COOKIE)?.is_some() {
            return Err(Status::permission_denied(
                "explicit gateway credential required for credential revocation",
            ));
        }
        let token = authorize_request(state, req, workspace).await?;
        let (key, expires) = if let Some(token) = token {
            (digest(&token)?, token_expiry(&token)?)
        } else {
            let fingerprint = req
                .extensions()
                .get::<ServicePeer>()
                .and_then(|p| p.certificate_sha256.as_ref())
                .ok_or_else(|| Status::invalid_argument("gateway credential required"))?;
            (format!("mtls-{fingerprint}"), u64::MAX)
        };
        cleanup(state, workspace).await?;
        if state
            .store
            .create_if_workspace_count_below(
                REVOKED,
                &key,
                &key,
                REVOCATION_SCOPE,
                &serde_json::to_vec(&expires).map_err(|_| internal())?,
                None,
                1024,
            )
            .await
            .map_err(|_| internal())?
            .is_none()
        {
            return Err(Status::resource_exhausted("revocation limit reached"));
        }
        return with_cookie(
            StatusCode::NO_CONTENT.into_response(),
            COOKIE,
            "",
            0,
            "Strict",
        );
    }
    Ok(StatusCode::NOT_FOUND.into_response())
}

fn no_cache(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn browser_complete() -> Result<Response, Status> {
    // A document on the service origin starts a fresh navigation, so Strict
    // cookies are sent even when login began on a different site. A chain of
    // HTTP redirects would retain the original cross-site navigation context.
    let nonce = random()?;
    let mut response = format!("<!doctype html><meta charset=\"utf-8\"><title>OpenShell sign in complete</title><p>Signed in.</p><a href=\"/\">Open service</a><script nonce=\"{nonce}\">location.replace('/');</script>").into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response.headers_mut().insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_str(&format!("default-src 'none'; script-src 'nonce-{nonce}'; frame-ancestors 'none'; base-uri 'none'")).map_err(|_| internal())?);
    Ok(no_cache(response))
}
fn with_cookie(
    mut response: Response,
    name: &str,
    value: &str,
    seconds: u64,
    same_site: &str,
) -> Result<Response, Status> {
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{name}={value}; Path=/; Secure; HttpOnly; SameSite={same_site}; Max-Age={seconds}"
        ))
        .map_err(|_| internal())?,
    );
    Ok(no_cache(response))
}
pub fn strip_response_cookies(headers: &mut HeaderMap) {
    let allowed: Vec<_> = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter(|value| {
            value
                .to_str()
                .ok()
                .and_then(|v| v.split_once('='))
                .is_some_and(|(name, _)| !name.trim().starts_with("__Host-openshell-"))
        })
        .cloned()
        .collect();
    headers.remove(header::SET_COOKIE);
    for value in allowed {
        headers.append(header::SET_COOKIE, value);
    }
}

pub fn error(status: &Status) -> Response {
    let code = match status.code() {
        tonic::Code::Unauthenticated => StatusCode::UNAUTHORIZED,
        tonic::Code::PermissionDenied => StatusCode::FORBIDDEN,
        tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,
        tonic::Code::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };
    let mut response =
        crate::service_routing::service_error_response(code, "Application authentication failed");
    if code == StatusCode::UNAUTHORIZED {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    no_cache(response)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::auth::oidc::tests::{cache_with_mock_issuer, claims_for, mint_rs256};
    use crate::grpc::test_support::test_server_state;
    use http_body_util::BodyExt;
    use openshell_core::proto::{WorkspaceMember, WorkspaceRole, datamodel::v1::ObjectMeta};
    use std::sync::Arc;
    use tower::ServiceExt;

    const APP: &str = "https://default--demo--web.services.example.com";
    const GATEWAY: &str = "https://gateway.example.com";

    pub async fn fixture() -> (wiremock::MockServer, Arc<ServerState>, String) {
        let server = wiremock::MockServer::start().await;
        let cache = Arc::new(cache_with_mock_issuer(&server).await);
        let mut state = test_server_state().await;
        let inner = Arc::get_mut(&mut state).unwrap();
        inner.config.auth.allow_unauthenticated_users = false;
        inner.config.service_routing.base_domains = vec!["services.example.com".into()];
        inner.config.oidc = Some(serde_json::from_value(serde_json::json!({"issuer":server.uri(),"audience":"openshell-cli","scopes_claim":"scope"})).unwrap());
        inner.admin_role = "openshell-admin".into();
        inner.oidc_cache = Some(cache);
        state
            .store
            .put_message(&WorkspaceMember {
                metadata: Some(ObjectMeta {
                    id: "member-user-42".into(),
                    name: "user-42".into(),
                    workspace: "default".into(),
                    ..Default::default()
                }),
                principal_subject: "user-42".into(),
                role: WorkspaceRole::User.into(),
            })
            .await
            .unwrap();
        let token = mint_rs256(
            &claims_for(
                &server.uri(),
                "openshell-cli",
                i64::try_from(now() + 3600).unwrap(),
            ),
            "test-signing-key",
        );
        (server, state, token)
    }

    fn request(method: Method, url: &str) -> Request<Body> {
        let url = url::Url::parse(url).unwrap();
        let mut request = Request::builder()
            .method(method)
            .uri(url.as_str())
            .header(header::HOST, url.authority())
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(ServicePeer {
            secure: true,
            ..Default::default()
        });
        request
    }
    async fn send(state: &Arc<ServerState>, request: Request<Body>) -> Response {
        crate::http::http_router(state.clone())
            .oneshot(request)
            .await
            .unwrap()
    }
    fn location(response: &Response) -> String {
        response.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .to_string()
    }
    fn response_cookie(response: &Response, name: &str) -> String {
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|v| v.starts_with(&format!("{name}=")))
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }
    pub async fn browser_login(state: &Arc<ServerState>, token: &str) -> String {
        browser_login_for(state, token, APP).await
    }

    async fn browser_login_for(state: &Arc<ServerState>, token: &str, app_origin: &str) -> String {
        let mut url = url::Url::parse(&format!("{GATEWAY}{CONTROL}")).unwrap();
        url.query_pairs_mut()
            .append_pair("service_origin", app_origin);
        let redirect = send(state, request(Method::GET, url.as_str())).await;
        assert_eq!(redirect.status(), StatusCode::SEE_OTHER);
        let start = send(state, request(Method::GET, &location(&redirect))).await;
        let nonce_cookie = response_cookie(&start, LOGIN_COOKIE);
        let login_url = location(&start);
        let login_url = url::Url::parse(&login_url).unwrap();
        let params: std::collections::HashMap<_, _> =
            login_url.query_pairs().into_owned().collect();
        let page = send(state, request(Method::GET, login_url.as_str())).await;
        assert_eq!(page.status(), StatusCode::OK);
        assert!(
            page.headers()[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'")
        );
        let mut login = request(Method::POST, &format!("{GATEWAY}{CONTROL}"));
        login
            .headers_mut()
            .insert(header::ORIGIN, GATEWAY.parse().unwrap());
        login.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        *login.body_mut() = Body::from(
            serde_json::to_vec(
                &serde_json::json!({"service_origin":app_origin,"state":params["state"]}),
            )
            .unwrap(),
        );
        let response = send(state, login).await;
        assert_eq!(response.status(), StatusCode::OK);
        let json: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        let redeem_url = json["redirect"].as_str().unwrap();
        assert!(!redeem_url.contains(token));
        let missing = send(state, request(Method::GET, redeem_url)).await;
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
        let mut redeem = request(Method::GET, redeem_url);
        redeem
            .headers_mut()
            .insert(header::COOKIE, nonce_cookie.parse().unwrap());
        let mut racing = request(Method::GET, redeem_url);
        racing
            .headers_mut()
            .insert(header::COOKIE, nonce_cookie.parse().unwrap());
        let (left, right) = tokio::join!(send(state, redeem), send(state, racing));
        let response = if left.status() == StatusCode::OK {
            assert_eq!(right.status(), StatusCode::UNAUTHORIZED);
            left
        } else {
            assert_eq!(left.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(right.status(), StatusCode::OK);
            right
        };
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response_cookie(&response, COOKIE);
        let flags = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .next()
            .unwrap()
            .to_str()
            .unwrap();
        assert!(flags.contains("Secure; HttpOnly; SameSite=Strict"));
        let mut replay = request(Method::GET, redeem_url);
        replay
            .headers_mut()
            .insert(header::COOKIE, nonce_cookie.parse().unwrap());
        assert_eq!(send(state, replay).await.status(), StatusCode::UNAUTHORIZED);
        let code = url::Url::parse(redeem_url)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned();
        let mut leaked_code = request(Method::GET, &format!("{app_origin}/"));
        leaked_code
            .headers_mut()
            .insert(header::COOKIE, format!("{COOKIE}={code}").parse().unwrap());
        assert_eq!(
            send(state, leaked_code).await.status(),
            StatusCode::UNAUTHORIZED,
            "bootstrap code is never an active cookie"
        );
        let records = state.store.list(SESSION, "default", 1024, 0).await.unwrap();
        assert_eq!(records.len(), 1);
        assert!(!String::from_utf8_lossy(&records[0].payload).contains(token));
        cookie
    }

    #[tokio::test]
    async fn hashed_service_browser_login_preserves_origin_and_authentication() {
        use openshell_core::config::ServiceHostnameFormat;
        let (_issuer, mut state, token) = fixture().await;
        let inner = Arc::get_mut(&mut state).unwrap();
        inner.config.name = "gateway-a".into();
        inner.config.service_routing.service_hostname_format = ServiceHostnameFormat::Hashed;
        inner.service_route_index = Arc::new(crate::service_routing::ServiceRouteIndex::new(Some(
            "gateway-a".into(),
        )));
        inner
            .service_route_index
            .register("default", "demo", "web")
            .unwrap();
        state
            .store
            .put_message(&openshell_core::proto::ServiceEndpoint {
                metadata: Some(ObjectMeta {
                    id: "hashed-web".into(),
                    name: "demo--web".into(),
                    workspace: "default".into(),
                    ..Default::default()
                }),
                sandbox_id: "sandbox-demo".into(),
                sandbox: "demo".into(),
                name: "web".into(),
                target_port: 8080,
                domain: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let label = crate::service_routing::service_route_hash_label(
            "gateway-a",
            "default",
            "demo",
            Some("web"),
        );
        let app_origin = format!("https://{label}.services.example.com");
        assert_eq!(
            service_origin(&state, &app_origin).await.unwrap().1,
            "default"
        );
        // Hashes from another installation must not resolve on this gateway.
        let other = crate::service_routing::service_route_hash_label(
            "gateway-b",
            "default",
            "demo",
            Some("web"),
        );
        assert!(
            service_origin(&state, &format!("https://{other}.services.example.com"))
                .await
                .is_err()
        );
        let mut start = request(
            Method::GET,
            &format!("{app_origin}{PREFIX}/start?login_origin={app_origin}"),
        );
        assert_eq!(
            handle(&state, &mut start, "default")
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        let cookie = browser_login_for(&state, &token, &app_origin).await;
        let mut application = request(Method::GET, &format!("{app_origin}/"));
        application
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        authorize_request(&state, &mut application, "default")
            .await
            .unwrap();
        let anonymous = send(&state, request(Method::GET, &format!("{app_origin}/"))).await;
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn browser_login_separates_gateway_and_application_credentials_and_checks_csrf() {
        let (_issuer, state, token) = fixture().await;
        let cookie = browser_login(&state, &token).await;
        let mut app = request(Method::GET, &format!("{APP}/"));
        app.headers_mut().insert(
            header::COOKIE,
            format!("{cookie}; application_session=app-secret")
                .parse()
                .unwrap(),
        );
        app.headers_mut().insert(
            header::AUTHORIZATION,
            "Bearer application-token".parse().unwrap(),
        );
        authorize_request(&state, &mut app, "default")
            .await
            .unwrap();
        assert_eq!(
            app.headers()[header::AUTHORIZATION],
            "Bearer application-token"
        );
        // Authenticated request reaches endpoint lookup; no such endpoint exists.
        assert_eq!(send(&state, app).await.status(), StatusCode::NOT_FOUND);
        for (method, upgrade) in [(Method::POST, false), (Method::GET, true)] {
            for origin in [None, Some("https://evil.example.com"), Some("null")] {
                let mut req = request(method.clone(), &format!("{APP}/"));
                req.headers_mut()
                    .insert(header::COOKIE, cookie.parse().unwrap());
                if upgrade {
                    req.headers_mut()
                        .insert(header::UPGRADE, "websocket".parse().unwrap());
                }
                if let Some(origin) = origin {
                    req.headers_mut()
                        .insert(header::ORIGIN, origin.parse().unwrap());
                }
                assert_eq!(send(&state, req).await.status(), StatusCode::FORBIDDEN);
            }
            let mut req = request(method, &format!("{APP}/"));
            req.headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
            req.headers_mut()
                .insert(header::ORIGIN, APP.parse().unwrap());
            if upgrade {
                req.headers_mut()
                    .insert(header::UPGRADE, "websocket".parse().unwrap());
            }
            assert_eq!(send(&state, req).await.status(), StatusCode::NOT_FOUND);
        }
    }

    #[tokio::test]
    async fn gateway_headers_authenticate_without_forwarding_tokens_and_discovery_scope_is_rejected()
     {
        let (issuer, state, token) = fixture().await;
        let mut direct = request(Method::GET, &format!("{APP}/"));
        direct.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        authorize_request(&state, &mut direct, "default")
            .await
            .unwrap();
        assert!(!direct.headers().contains_key(header::AUTHORIZATION));
        let mut separate = request(Method::GET, &format!("{APP}/"));
        separate
            .headers_mut()
            .insert(GATEWAY_AUTH, format!("Bearer {token}").parse().unwrap());
        separate.headers_mut().insert(
            header::AUTHORIZATION,
            "Bearer application-token".parse().unwrap(),
        );
        authorize_request(&state, &mut separate, "default")
            .await
            .unwrap();
        assert_eq!(
            separate.headers()[header::AUTHORIZATION],
            "Bearer application-token"
        );
        let mut claims = claims_for(
            &issuer.uri(),
            "openshell-cli",
            i64::try_from(now() + 3600).unwrap(),
        );
        claims["scope"] = serde_json::json!("sandbox:read");
        let discovery = mint_rs256(&claims, "test-signing-key");
        separate
            .headers_mut()
            .insert(GATEWAY_AUTH, format!("Bearer {discovery}").parse().unwrap());
        assert_eq!(send(&state, separate).await.status(), StatusCode::FORBIDDEN);
        for invalid in [
            "not-a-token".to_string(),
            mint_rs256(
                &claims_for(
                    &issuer.uri(),
                    "openshell-cli",
                    i64::try_from(now()).unwrap() - 1,
                ),
                "test-signing-key",
            ),
        ] {
            let mut req = request(Method::GET, &format!("{APP}/"));
            req.headers_mut().insert(
                header::AUTHORIZATION,
                format!("Bearer {invalid}").parse().unwrap(),
            );
            assert_eq!(send(&state, req).await.status(), StatusCode::UNAUTHORIZED);
        }
    }

    async fn replica(state: &Arc<ServerState>) -> Arc<ServerState> {
        Arc::new(ServerState::new_with_credentials(
            state.config.clone(),
            state.store.clone(),
            crate::compute::new_test_runtime(state.store.clone()).await,
            crate::sandbox_index::SandboxIndex::new(),
            crate::sandbox_watch::SandboxWatchBus::new(),
            crate::tracing_bus::TracingLogBus::new(),
            Arc::new(crate::supervisor_session::SupervisorSessionRegistry::new()),
            state.oidc_cache.clone(),
            state.credentials.clone(),
        ))
    }
    fn application(cookie: &str) -> Request<Body> {
        let mut req = request(Method::GET, &format!("{APP}/"));
        req.headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        req
    }

    #[tokio::test]
    async fn sessions_recheck_workspace_and_logout_and_token_revocation_across_replicas() {
        let (_issuer, state, token) = fixture().await;
        let cookie = browser_login(&state, &token).await;
        let other = replica(&state).await;
        assert_eq!(
            send(&other, application(&cookie)).await.status(),
            StatusCode::NOT_FOUND
        );
        let mut logout = request(Method::DELETE, &format!("{APP}{PREFIX}/session"));
        logout
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        logout
            .headers_mut()
            .insert(header::ORIGIN, APP.parse().unwrap());
        assert_eq!(send(&state, logout).await.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            send(&other, application(&cookie)).await.status(),
            StatusCode::UNAUTHORIZED
        );
        let cookie = browser_login(&state, &token).await;
        let mut revoke = request(Method::DELETE, &format!("{APP}{PREFIX}/credential"));
        revoke.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        revoke
            .headers_mut()
            .insert(header::ORIGIN, APP.parse().unwrap());
        assert_eq!(send(&state, revoke).await.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            send(&other, application(&cookie)).await.status(),
            StatusCode::UNAUTHORIZED
        );
        let mut replay = request(Method::GET, &format!("{APP}/"));
        replay.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        assert_eq!(
            send(&other, replay).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn sessions_reject_wrong_hosts_expiry_removed_membership_and_spoofed_headers() {
        let (_issuer, state, token) = fixture().await;
        let cookie = browser_login(&state, &token).await;
        let mut wrong = application(&cookie);
        wrong.headers_mut().insert(
            header::HOST,
            "default--other--web.services.example.com".parse().unwrap(),
        );
        assert_eq!(send(&state, wrong).await.status(), StatusCode::UNAUTHORIZED);
        state
            .store
            .delete("workspace_member", "member-user-42")
            .await
            .unwrap();
        assert_eq!(
            send(&state, application(&cookie)).await.status(),
            StatusCode::FORBIDDEN
        );
        let record = state
            .store
            .list(SESSION, "default", 1, 0)
            .await
            .unwrap()
            .remove(0);
        let mut value = session(&record).unwrap();
        value.expires = now();
        state
            .store
            .put_if(
                SESSION,
                &record.id,
                &record.name,
                "default",
                &serde_json::to_vec(&value).unwrap(),
                None,
                WriteCondition::Unconditional,
            )
            .await
            .unwrap();
        assert_eq!(
            send(&state, application(&cookie)).await.status(),
            StatusCode::UNAUTHORIZED
        );
        let mut spoof = request(Method::GET, &format!("{APP}/"));
        spoof
            .headers_mut()
            .insert("x-forwarded-client-cert", "forged".parse().unwrap());
        spoof
            .headers_mut()
            .insert("x-openshell-auth-source", "oidc".parse().unwrap());
        assert_eq!(send(&state, spoof).await.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn mtls_revocation_and_explicit_development_auth_work_with_either_listener_mode() {
        use crate::auth::identity::{Identity, IdentityProvider};
        let mut state = test_server_state().await;
        let inner = Arc::get_mut(&mut state).unwrap();
        inner.config.service_routing.base_domains = vec!["services.example.com".into()];
        inner.config.auth.allow_unauthenticated_users = false;
        inner.config.mtls_auth.enabled = true;
        let peer = ServicePeer {
            secure: true,
            identity: Some(Identity {
                subject: "mtls-user".into(),
                display_name: None,
                roles: vec![],
                scopes: vec![],
                provider: IdentityProvider::Mtls,
            }),
            certificate_sha256: Some("verified-certificate-digest".into()),
            source: None,
        };
        for enabled in [false, true] {
            Arc::get_mut(&mut state)
                .unwrap()
                .config
                .supervisor_app_listener
                .enabled = enabled;
            let mut req = request(Method::GET, &format!("{APP}/"));
            req.extensions_mut().insert(peer.clone());
            assert_eq!(send(&state, req).await.status(), StatusCode::NOT_FOUND);
            assert_eq!(
                send(&state, request(Method::GET, &format!("{APP}/")))
                    .await
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
        let other = replica(&state).await;
        let mut revoke = request(Method::DELETE, &format!("{APP}{PREFIX}/credential"));
        revoke.extensions_mut().insert(peer.clone());
        revoke
            .headers_mut()
            .insert(header::ORIGIN, APP.parse().unwrap());
        assert_eq!(send(&state, revoke).await.status(), StatusCode::NO_CONTENT);
        let mut req = request(Method::GET, &format!("{APP}/"));
        req.extensions_mut().insert(peer);
        assert_eq!(send(&other, req).await.status(), StatusCode::UNAUTHORIZED);
        drop(other);
        let inner = Arc::get_mut(&mut state).unwrap();
        inner.config.mtls_auth.enabled = false;
        inner.config.auth.allow_unauthenticated_users = true;
        assert_eq!(
            send(&state, request(Method::GET, &format!("{APP}/")))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        let mut invalid = request(Method::GET, &format!("{APP}/"));
        invalid
            .headers_mut()
            .insert(GATEWAY_AUTH, "Bearer invalid".parse().unwrap());
        assert_eq!(
            send(&state, invalid).await.status(),
            StatusCode::UNAUTHORIZED
        );
        let mut application = request(Method::GET, &format!("{APP}/"));
        application.headers_mut().insert(
            header::AUTHORIZATION,
            "Bearer application-token".parse().unwrap(),
        );
        authorize_request(&state, &mut application, "default")
            .await
            .unwrap();
        assert_eq!(
            application.headers()[header::AUTHORIZATION],
            "Bearer application-token"
        );
    }
}
