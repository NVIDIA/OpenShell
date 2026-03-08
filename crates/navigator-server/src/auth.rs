// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Auth endpoint for Cloudflare Access browser-based login.
//!
//! When the CLI runs `gateway add` or `gateway login`, it opens the user's
//! browser to `GET /auth/connect?callback_port=<port>`. Cloudflare Access
//! intercepts the request and shows its IdP login page. After authentication,
//! CF sets the `CF_Authorization` cookie and proxies the request to this
//! endpoint.
//!
//! The handler reads the `CF_Authorization` cookie from the request headers
//! (required because the cookie is typically `HttpOnly`) and serves a styled
//! confirmation page. When the user clicks "Connect", JavaScript redirects
//! to `http://127.0.0.1:<callback_port>/callback?token=<jwt>`, where the
//! CLI's ephemeral localhost server captures and stores the token.

use axum::{
    Router,
    extract::{Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse},
    routing::get,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::ServerState;

#[derive(Deserialize)]
struct ConnectParams {
    callback_port: u16,
}

/// Create the auth router.
pub fn router(state: Arc<ServerState>) -> Router {
    Router::new()
        .route("/auth/connect", get(auth_connect))
        .with_state(state)
}

/// Handle the auth connect request.
///
/// Reads `CF_Authorization` from the cookie header (server-side extraction
/// handles `HttpOnly` cookies) and serves either a waiting page or a
/// styled confirmation page with the token embedded.
async fn auth_connect(
    State(state): State<Arc<ServerState>>,
    Query(params): Query<ConnectParams>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let cf_token = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| extract_cookie(cookies, "CF_Authorization"));

    // Prefer the Host header (set by Cloudflare Tunnel / reverse proxies)
    // so the page shows the external URL the user actually connected through
    // rather than the internal bind address (e.g. 0.0.0.0:8080).
    let gateway_display = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get("host"))
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| state.config.bind_address.to_string());

    match cf_token {
        Some(token) => Html(render_connect_page(
            &gateway_display,
            params.callback_port,
            &token,
        )),
        None => Html(render_waiting_page(params.callback_port)),
    }
}

/// Extract a named cookie value from a `Cookie` header string.
fn extract_cookie(cookies: &str, name: &str) -> Option<String> {
    cookies.split(';').find_map(|c| {
        let mut parts = c.trim().splitn(2, '=');
        let key = parts.next()?.trim();
        let val = parts.next()?.trim();
        if key == name {
            Some(val.to_string())
        } else {
            None
        }
    })
}

/// Render the styled confirmation page with the CF token embedded.
fn render_connect_page(gateway_addr: &str, callback_port: u16, cf_token: &str) -> String {
    // Escape the token for safe embedding in a JS string literal.
    let escaped_token = cf_token
        .replace('\\', "\\\\")
        .replace('\'', "\\'")
        .replace('"', "\\\"")
        .replace('<', "\\x3c")
        .replace('>', "\\x3e");

    let version = env!("CARGO_PKG_VERSION");

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>NemoClaw — Connect to Gateway</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'SF Mono', 'Fira Code', 'JetBrains Mono', monospace;
            background: #0a0a0a;
            color: #e0e0e0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .card {{
            background: #141414;
            border: 1px solid #2a2a2a;
            border-radius: 12px;
            padding: 48px;
            max-width: 480px;
            width: 100%;
            text-align: center;
        }}
        .logo {{
            font-size: 28px;
            font-weight: 700;
            color: #76b900;
            margin-bottom: 8px;
            letter-spacing: -0.5px;
        }}
        .subtitle {{
            color: #888;
            font-size: 14px;
            margin-bottom: 32px;
        }}
        .info {{
            background: #1a1a1a;
            border: 1px solid #222;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 32px;
            text-align: left;
        }}
        .info-row {{
            display: flex;
            justify-content: space-between;
            padding: 6px 0;
            font-size: 13px;
        }}
        .info-label {{ color: #666; }}
        .info-value {{
            color: #ccc;
            font-weight: 500;
            word-break: break-all;
            text-align: right;
            max-width: 60%;
        }}
        .connect-btn {{
            background: #76b900;
            color: #0a0a0a;
            border: none;
            border-radius: 8px;
            padding: 14px 32px;
            font-size: 15px;
            font-weight: 600;
            font-family: inherit;
            cursor: pointer;
            width: 100%;
            transition: background 0.15s;
        }}
        .connect-btn:hover {{ background: #8ad100; }}
        .connect-btn:active {{ background: #6aa000; }}
        .hint {{
            color: #555;
            font-size: 12px;
            margin-top: 16px;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">NemoClaw</div>
        <div class="subtitle">Connect to Gateway</div>
        <div class="info">
            <div class="info-row">
                <span class="info-label">Gateway</span>
                <span class="info-value">{gateway_addr}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Version</span>
                <span class="info-value">v{version}</span>
            </div>
        </div>
        <button class="connect-btn" onclick="connect()">
            Connect to Gateway
        </button>
        <div class="hint">
            This will authorize the NemoClaw CLI to connect to this gateway.
        </div>
    </div>
    <script>
        var token = '{escaped_token}';
        var port = {callback_port};
        function connect() {{
            window.location.href =
                'http://127.0.0.1:' + port + '/callback?token=' + encodeURIComponent(token);
        }}
    </script>
</body>
</html>"#,
        gateway_addr = gateway_addr,
        version = version,
        escaped_token = escaped_token,
        callback_port = callback_port,
    )
}

/// Render a waiting page shown when the CF Access cookie is not yet present.
///
/// This can happen if CF Access hasn't completed authentication yet. The page
/// auto-reloads after a short delay to pick up the cookie once login finishes.
fn render_waiting_page(callback_port: u16) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="refresh" content="2;url=/auth/connect?callback_port={callback_port}">
    <title>NemoClaw — Authenticating</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'SF Mono', 'Fira Code', 'JetBrains Mono', monospace;
            background: #0a0a0a;
            color: #e0e0e0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .card {{
            background: #141414;
            border: 1px solid #2a2a2a;
            border-radius: 12px;
            padding: 48px;
            max-width: 480px;
            width: 100%;
            text-align: center;
        }}
        .logo {{
            font-size: 28px;
            font-weight: 700;
            color: #76b900;
            margin-bottom: 8px;
        }}
        .message {{
            color: #888;
            font-size: 14px;
            margin-top: 16px;
        }}
        .spinner {{
            margin: 24px auto;
            width: 32px;
            height: 32px;
            border: 3px solid #2a2a2a;
            border-top-color: #76b900;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }}
        @keyframes spin {{
            to {{ transform: rotate(360deg); }}
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">NemoClaw</div>
        <div class="spinner"></div>
        <div class="message">Authenticating with Cloudflare Access...</div>
    </div>
</body>
</html>"#,
        callback_port = callback_port,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_cookie_finds_value() {
        let cookies = "other=foo; CF_Authorization=eyJhbGciOiJSUzI1NiJ9.test; bar=baz";
        assert_eq!(
            extract_cookie(cookies, "CF_Authorization"),
            Some("eyJhbGciOiJSUzI1NiJ9.test".to_string())
        );
    }

    #[test]
    fn extract_cookie_returns_none_when_missing() {
        let cookies = "other=foo; bar=baz";
        assert_eq!(extract_cookie(cookies, "CF_Authorization"), None);
    }

    #[test]
    fn extract_cookie_handles_single_cookie() {
        let cookies = "CF_Authorization=my-token";
        assert_eq!(
            extract_cookie(cookies, "CF_Authorization"),
            Some("my-token".to_string())
        );
    }

    #[test]
    fn render_connect_page_contains_token() {
        let html = render_connect_page("gateway.example.com:8080", 12345, "test-jwt-token");
        assert!(html.contains("test-jwt-token"));
        assert!(html.contains("12345"));
        assert!(html.contains("gateway.example.com:8080"));
        assert!(html.contains("NemoClaw"));
    }

    #[test]
    fn render_connect_page_escapes_special_chars() {
        let html = render_connect_page("gw", 1234, "token<script>alert('xss')</script>");
        // < and > should be escaped
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("\\x3c"));
    }

    #[test]
    fn render_waiting_page_has_auto_refresh() {
        let html = render_waiting_page(12345);
        assert!(html.contains("meta http-equiv=\"refresh\""));
        assert!(html.contains("callback_port=12345"));
    }
}
