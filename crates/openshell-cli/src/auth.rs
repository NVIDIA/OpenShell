// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Browser-based Cloudflare Access authentication flow.
//!
//! Opens the user's browser to the gateway's `/auth/connect` page, which
//! (after Cloudflare Access login) extracts the `CF_Authorization` cookie
//! and sends it via an XHR POST to a localhost callback server running here.
//! A confirmation code binds the browser session to this CLI session,
//! preventing port-redirection attacks.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Incoming,
    header::{
        ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
        ACCESS_CONTROL_MAX_AGE, CONTENT_TYPE, ORIGIN, VARY,
    },
    service::service_fn,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use miette::{IntoDiagnostic, Result};
use serde::Deserialize;
use std::convert::Infallible;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tracing::debug;

/// Timeout for the browser auth flow.
const AUTH_TIMEOUT: Duration = Duration::from_secs(120);

/// Length of the confirmation code (alphanumeric characters).
const CODE_LENGTH: usize = 7;

/// Generate a random alphanumeric confirmation code (e.g. "A7X-3KPX").
///
/// Uses a dash separator in the middle for readability.
fn generate_confirmation_code() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let charset = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no 0/O/1/I ambiguity
    let mut code = String::with_capacity(CODE_LENGTH + 1); // +1 for dash

    // Use two independent RandomState instances as entropy sources. Each
    // `RandomState::new()` is seeded from the OS. We combine both hashers'
    // output per character to avoid depending on a single seed, and mix in
    // the character index plus the previous hash for avalanche diffusion.
    let state_a = RandomState::new();
    let state_b = RandomState::new();
    let mut prev_hash: u64 = 0;
    for i in 0..CODE_LENGTH {
        if i == 3 {
            code.push('-');
        }
        let mut hasher_a = state_a.build_hasher();
        hasher_a.write_usize(i);
        hasher_a.write_u64(prev_hash);
        let hash_a = hasher_a.finish();

        let mut hasher_b = state_b.build_hasher();
        hasher_b.write_u64(hash_a);
        hasher_b.write_usize(i);
        let hash_b = hasher_b.finish();

        prev_hash = hash_b;
        let idx = (hash_b as usize) % charset.len();
        code.push(charset[idx] as char);
    }
    code
}

/// Run the browser-based CF Access auth flow.
///
/// 1. Generates a one-time confirmation code
/// 2. Starts an ephemeral localhost HTTP server
/// 3. Opens the browser to the gateway's `/auth/connect` page
/// 4. Waits for the XHR POST callback with the CF JWT and matching code
/// 5. Returns the token
pub async fn browser_auth_flow(gateway_endpoint: &str) -> Result<String> {
    // Short-circuit when the browser is suppressed (CI, e2e tests, headless
    // environments).  Without this early return the function still binds a TCP
    // listener, spawns a callback server, and waits the full AUTH_TIMEOUT
    // (120 s) for a POST that will never arrive.
    let no_browser = std::env::var("OPENSHELL_NO_BROWSER")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if no_browser {
        return Err(miette::miette!(
            "authentication skipped (OPENSHELL_NO_BROWSER is set).\n\
             Authenticate later with: openshell gateway login"
        ));
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.into_diagnostic()?;
    let local_addr = listener.local_addr().into_diagnostic()?;
    let callback_port = local_addr.port();

    let code = generate_confirmation_code();

    let auth_url = format!(
        "{}/auth/connect?callback_port={callback_port}&code={code}",
        gateway_endpoint.trim_end_matches('/')
    );

    // Channel to receive the token from the callback handler.
    let (tx, rx) = oneshot::channel::<String>();

    // Spawn the callback server.
    let server_handle = tokio::spawn(run_callback_server(
        listener,
        tx,
        code.clone(),
        gateway_endpoint.to_string(),
    ));

    // Prompt the user before opening the browser.
    eprintln!("  Confirmation code: {code}");
    eprintln!("  Verify this code matches your browser before clicking Connect.");
    eprintln!();

    eprint!("Press Enter to open the browser for authentication...");
    std::io::stderr().flush().ok();
    let mut _input = String::new();
    std::io::stdin().read_line(&mut _input).ok();

    if let Err(e) = open_browser(&auth_url) {
        debug!(error = %e, "failed to open browser");
        eprintln!("Could not open browser automatically.");
        eprintln!("Open this URL in your browser:");
        eprintln!("  {auth_url}");
        eprintln!();
    } else {
        eprintln!("Browser opened.");
    }

    // Wait for the callback or timeout.
    let token = tokio::select! {
        result = rx => {
            result.map_err(|_| miette::miette!("auth callback channel closed unexpectedly"))?
        }
        () = tokio::time::sleep(AUTH_TIMEOUT) => {
            return Err(miette::miette!(
                "authentication timed out after {} seconds.\n\
                 Try again with: openshell gateway login",
                AUTH_TIMEOUT.as_secs()
            ));
        }
    };

    // Abort the server task (it may still be running if the OS reuses the
    // listener after the first accepted connection).
    server_handle.abort();

    Ok(token)
}

/// Open a URL in the default browser.
fn open_browser(url: &str) -> std::result::Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(url)
            .spawn()
            .map_err(|e| format!("failed to run `open`: {e}"))?;
    }

    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(url)
            .spawn()
            .map_err(|e| format!("failed to run `xdg-open`: {e}"))?;
    }

    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", url])
            .spawn()
            .map_err(|e| format!("failed to open browser: {e}"))?;
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        return Err("unsupported platform for browser opening".to_string());
    }

    Ok(())
}

/// Extract the origin (scheme + host) from a gateway endpoint URL.
///
/// For example, `https://8080-3vdegyusg.brevlab.com/some/path` → `https://8080-3vdegyusg.brevlab.com`.
/// Returns `None` if the URL cannot be parsed.
fn extract_origin(gateway_endpoint: &str) -> Option<String> {
    // Split on "://" to get scheme and the rest.
    let (scheme, rest) = gateway_endpoint.split_once("://")?;
    // The host (with optional port) is everything before the first '/'.
    let host = rest.split('/').next().unwrap_or(rest);
    Some(format!("{scheme}://{host}"))
}

#[derive(Deserialize)]
struct CallbackPayload {
    token: String,
    code: String,
}

struct CallbackServerState {
    allowed_origin: Option<String>,
    expected_code: String,
    tx: Mutex<Option<oneshot::Sender<String>>>,
}

impl CallbackServerState {
    fn take_sender(&self) -> Option<oneshot::Sender<String>> {
        self.tx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

type CallbackResponse = Response<Full<Bytes>>;

fn callback_response(
    status: StatusCode,
    allowed_origin: Option<&str>,
    content_type: Option<&str>,
    body: impl Into<Bytes>,
) -> CallbackResponse {
    let mut response = Response::new(Full::new(body.into()));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    if let Some(origin) = allowed_origin {
        headers.insert(
            ACCESS_CONTROL_ALLOW_ORIGIN,
            hyper::header::HeaderValue::from_str(origin).expect("callback origin is valid"),
        );
        headers.insert(
            ACCESS_CONTROL_ALLOW_METHODS,
            hyper::header::HeaderValue::from_static("POST, OPTIONS"),
        );
        headers.insert(
            ACCESS_CONTROL_ALLOW_HEADERS,
            hyper::header::HeaderValue::from_static("Content-Type"),
        );
        headers.insert(
            ACCESS_CONTROL_MAX_AGE,
            hyper::header::HeaderValue::from_static("60"),
        );
        headers.insert(VARY, hyper::header::HeaderValue::from_static("Origin"));
    }
    if let Some(content_type) = content_type {
        headers.insert(
            CONTENT_TYPE,
            hyper::header::HeaderValue::from_str(content_type)
                .expect("callback content type is valid"),
        );
    }
    response
}

fn empty_response(status: StatusCode, allowed_origin: Option<&str>) -> CallbackResponse {
    callback_response(status, allowed_origin, None, Bytes::new())
}

fn json_response(
    status: StatusCode,
    allowed_origin: Option<&str>,
    body: &'static str,
) -> CallbackResponse {
    callback_response(status, allowed_origin, Some("application/json"), body)
}

async fn handle_callback_request(
    req: Request<Incoming>,
    state: Arc<CallbackServerState>,
) -> CallbackResponse {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    debug!(method = %method, path = %path, "callback request received");

    let allowed_origin = state.allowed_origin.as_deref();
    if path != "/callback" {
        return empty_response(StatusCode::NOT_FOUND, allowed_origin);
    }

    if let Some(expected_origin) = allowed_origin {
        let request_origin = req
            .headers()
            .get(ORIGIN)
            .and_then(|value| value.to_str().ok());
        if request_origin != Some(expected_origin) {
            debug!(
                request_origin = ?request_origin,
                allowed_origin = expected_origin,
                "callback origin mismatch"
            );
            let _ = state.take_sender();
            return json_response(
                StatusCode::FORBIDDEN,
                allowed_origin,
                r#"{"ok":false,"error":"origin not allowed"}"#,
            );
        }
    }

    if method == Method::OPTIONS {
        return empty_response(StatusCode::NO_CONTENT, allowed_origin);
    }

    if method != Method::POST {
        return json_response(
            StatusCode::METHOD_NOT_ALLOWED,
            allowed_origin,
            r#"{"error":"method not allowed"}"#,
        );
    }

    let body = match req.into_body().collect().await {
        Ok(body) => body.to_bytes(),
        Err(error) => {
            debug!(error = %error, "failed to read callback body");
            let _ = state.take_sender();
            return json_response(
                StatusCode::BAD_REQUEST,
                allowed_origin,
                r#"{"ok":false,"error":"invalid request body"}"#,
            );
        }
    };

    let payload: CallbackPayload = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(error) => {
            debug!(error = %error, "failed to decode callback JSON");
            let _ = state.take_sender();
            return json_response(
                StatusCode::BAD_REQUEST,
                allowed_origin,
                r#"{"ok":false,"error":"missing token or code"}"#,
            );
        }
    };

    if payload.token.is_empty() || payload.code.is_empty() {
        let _ = state.take_sender();
        return json_response(
            StatusCode::BAD_REQUEST,
            allowed_origin,
            r#"{"ok":false,"error":"missing token or code"}"#,
        );
    }

    if payload.code != state.expected_code {
        let _ = state.take_sender();
        return json_response(
            StatusCode::FORBIDDEN,
            allowed_origin,
            r#"{"ok":false,"error":"confirmation code mismatch"}"#,
        );
    }

    if let Some(sender) = state.take_sender() {
        let _ = sender.send(payload.token);
    }

    json_response(StatusCode::OK, allowed_origin, r#"{"ok":true}"#)
}

/// Run the ephemeral callback server.
///
/// Handles two request types:
/// - `OPTIONS /callback` — CORS preflight, returns 204 with CORS headers.
/// - `POST /callback`    — JSON body `{"token":"...","code":"..."}`, validates
///   the confirmation code, sends the token through the channel, and returns
///   a JSON success/error response.
///
/// CORS is restricted to the gateway origin. Requests with a missing or
/// non-matching `Origin` header are rejected with 403.
async fn run_callback_server(
    listener: TcpListener,
    tx: oneshot::Sender<String>,
    expected_code: String,
    gateway_endpoint: String,
) {
    let state = Arc::new(CallbackServerState {
        allowed_origin: extract_origin(&gateway_endpoint),
        expected_code,
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
                async move { Ok::<_, Infallible>(handle_callback_request(req, state).await) }
            });

            if let Err(error) = Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                debug!(error = %error, "callback server connection failed");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // ---------------------------------------------------------------
    // Confirmation code generation
    // ---------------------------------------------------------------

    #[test]
    fn confirmation_code_format() {
        let code = generate_confirmation_code();
        // Format: XXX-XXXX (3 chars, dash, 4 chars) = 8 chars total
        assert_eq!(code.len(), 8, "code should be 8 chars: {code}");
        assert_eq!(
            code.chars().nth(3),
            Some('-'),
            "code should have dash at position 3: {code}"
        );
        assert!(
            code.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "code should be alphanumeric + dash: {code}"
        );
    }

    #[test]
    fn confirmation_codes_are_unique() {
        let codes: Vec<_> = (0..10).map(|_| generate_confirmation_code()).collect();
        // While theoretically possible to collide, 10 codes from a 32^7 space
        // should practically never collide.
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert!(
            unique.len() > 1,
            "codes should be random, got all identical: {codes:?}"
        );
    }

    // ---------------------------------------------------------------
    // Origin extraction
    // ---------------------------------------------------------------

    #[test]
    fn extract_origin_https() {
        assert_eq!(
            extract_origin("https://gateway.example.com"),
            Some("https://gateway.example.com".to_string())
        );
    }

    #[test]
    fn extract_origin_with_port() {
        assert_eq!(
            extract_origin("https://8080-abc.brevlab.com:8080/some/path"),
            Some("https://8080-abc.brevlab.com:8080".to_string())
        );
    }

    #[test]
    fn extract_origin_strips_path() {
        assert_eq!(
            extract_origin("https://gateway.example.com/auth/connect?foo=bar"),
            Some("https://gateway.example.com".to_string())
        );
    }

    #[test]
    fn extract_origin_no_scheme() {
        assert_eq!(extract_origin("gateway.example.com"), None);
    }

    // ---------------------------------------------------------------
    // Callback server integration tests
    // ---------------------------------------------------------------

    const TEST_GATEWAY: &str = "https://gateway.example.com";

    #[tokio::test]
    async fn callback_server_captures_token_with_valid_code() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();

        tokio::spawn(run_callback_server(
            listener,
            tx,
            "ABC-1234".to_string(),
            TEST_GATEWAY.to_string(),
        ));

        // Simulate a browser XHR POST.
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let body = r#"{"token":"test-jwt-123","code":"ABC-1234"}"#;
        let request = format!(
            "POST /callback HTTP/1.1\r\n\
             Host: 127.0.0.1\r\n\
             Origin: {TEST_GATEWAY}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n\
             {}",
            body.len(),
            body,
        );
        stream.write_all(request.as_bytes()).await.unwrap();

        let token = rx.await.unwrap();
        assert_eq!(token, "test-jwt-123");
    }

    #[tokio::test]
    async fn callback_server_cors_reflects_gateway_origin() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, _rx) = oneshot::channel();

        tokio::spawn(run_callback_server(
            listener,
            tx,
            "ABC-1234".to_string(),
            TEST_GATEWAY.to_string(),
        ));

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let body = r#"{"token":"jwt","code":"ABC-1234"}"#;
        let request = format!(
            "POST /callback HTTP/1.1\r\n\
             Host: 127.0.0.1\r\n\
             Origin: {TEST_GATEWAY}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n\
             {}",
            body.len(),
            body,
        );
        stream.write_all(request.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        let expected_header = format!("access-control-allow-origin: {TEST_GATEWAY}");
        assert!(
            response
                .lines()
                .any(|line| line.eq_ignore_ascii_case(&expected_header)),
            "response should reflect gateway origin:\n{response}"
        );
        assert!(
            !response
                .lines()
                .any(|line| line.eq_ignore_ascii_case("access-control-allow-origin: *")),
            "response should NOT use wildcard origin:\n{response}"
        );
    }

    #[tokio::test]
    async fn callback_server_rejects_wrong_origin() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();

        tokio::spawn(run_callback_server(
            listener,
            tx,
            "ABC-1234".to_string(),
            TEST_GATEWAY.to_string(),
        ));

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let body = r#"{"token":"jwt","code":"ABC-1234"}"#;
        let request = format!(
            "POST /callback HTTP/1.1\r\n\
             Host: 127.0.0.1\r\n\
             Origin: https://evil.example.com\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n\
             {}",
            body.len(),
            body,
        );
        stream.write_all(request.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.contains("403 Forbidden"),
            "wrong origin should return 403:\n{response}"
        );
        assert!(
            response.contains("origin not allowed"),
            "should explain the error:\n{response}"
        );

        // Token channel should not receive a value.
        assert!(
            rx.await.is_err(),
            "token channel should not receive a value with wrong origin"
        );
    }

    #[tokio::test]
    async fn callback_server_rejects_missing_origin() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();

        tokio::spawn(run_callback_server(
            listener,
            tx,
            "ABC-1234".to_string(),
            TEST_GATEWAY.to_string(),
        ));

        // POST without Origin header.
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let body = r#"{"token":"jwt","code":"ABC-1234"}"#;
        let request = format!(
            "POST /callback HTTP/1.1\r\n\
             Host: 127.0.0.1\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n\
             {}",
            body.len(),
            body,
        );
        stream.write_all(request.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.contains("403 Forbidden"),
            "missing origin should return 403:\n{response}"
        );
        assert!(
            response.contains("origin not allowed"),
            "should explain the error:\n{response}"
        );

        assert!(
            rx.await.is_err(),
            "token channel should not receive a value without origin"
        );
    }

    #[tokio::test]
    async fn callback_server_rejects_wrong_code() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();

        tokio::spawn(run_callback_server(
            listener,
            tx,
            "ABC-1234".to_string(),
            TEST_GATEWAY.to_string(),
        ));

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let body = r#"{"token":"test-jwt","code":"WRONG-CODE"}"#;
        let request = format!(
            "POST /callback HTTP/1.1\r\n\
             Host: 127.0.0.1\r\n\
             Origin: {TEST_GATEWAY}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n\
             {}",
            body.len(),
            body,
        );
        stream.write_all(request.as_bytes()).await.unwrap();

        // Read the response — should be 403.
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.contains("403 Forbidden"),
            "wrong code should return 403:\n{response}"
        );
        assert!(
            response.contains("confirmation code mismatch"),
            "should explain the error:\n{response}"
        );

        // Token channel should not receive a value.
        assert!(
            rx.await.is_err(),
            "token channel should not receive a value with wrong code"
        );
    }

    #[tokio::test]
    async fn callback_server_rejects_missing_fields() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();

        tokio::spawn(run_callback_server(
            listener,
            tx,
            "ABC-1234".to_string(),
            TEST_GATEWAY.to_string(),
        ));

        // POST with no body.
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request = format!(
            "POST /callback HTTP/1.1\r\n\
             Host: 127.0.0.1\r\n\
             Origin: {TEST_GATEWAY}\r\n\
             Content-Length: 0\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.contains("400 Bad Request"),
            "missing fields should return 400:\n{response}"
        );

        assert!(
            rx.await.is_err(),
            "token channel should not receive a value when fields are missing"
        );
    }

    #[tokio::test]
    async fn callback_server_handles_cors_preflight() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();

        tokio::spawn(run_callback_server(
            listener,
            tx,
            "ABC-1234".to_string(),
            TEST_GATEWAY.to_string(),
        ));

        // Send OPTIONS preflight with correct origin.
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let preflight = format!(
            "OPTIONS /callback HTTP/1.1\r\n\
             Host: 127.0.0.1\r\n\
             Origin: {TEST_GATEWAY}\r\n\r\n"
        );
        stream.write_all(preflight.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        let expected_header = format!("access-control-allow-origin: {TEST_GATEWAY}");
        assert!(
            response.contains("204 No Content"),
            "preflight should return 204:\n{response}"
        );
        assert!(
            response
                .lines()
                .any(|line| line.eq_ignore_ascii_case(&expected_header)),
            "preflight should reflect gateway origin:\n{response}"
        );

        // Now send the actual POST — the server should still be listening.
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let body = r#"{"token":"jwt-after-preflight","code":"ABC-1234"}"#;
        let request = format!(
            "POST /callback HTTP/1.1\r\n\
             Host: 127.0.0.1\r\n\
             Origin: {TEST_GATEWAY}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n\
             {}",
            body.len(),
            body,
        );
        stream.write_all(request.as_bytes()).await.unwrap();

        let token = rx.await.unwrap();
        assert_eq!(token, "jwt-after-preflight");
    }

    #[tokio::test]
    async fn callback_server_handles_fragmented_post_body() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();

        tokio::spawn(run_callback_server(
            listener,
            tx,
            "ABC-1234".to_string(),
            TEST_GATEWAY.to_string(),
        ));

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let body = r#"{"token":"fragmented-jwt","code":"ABC-1234"}"#;
        let headers = format!(
            "POST /callback HTTP/1.1\r\n\
             Host: 127.0.0.1\r\n\
             Origin: {TEST_GATEWAY}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n",
            body.len(),
        );

        stream.write_all(headers.as_bytes()).await.unwrap();
        stream.write_all(&body.as_bytes()[..18]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        stream.write_all(&body.as_bytes()[18..]).await.unwrap();

        let token = rx.await.unwrap();
        assert_eq!(token, "fragmented-jwt");
    }

    #[tokio::test]
    async fn callback_server_rejects_get_method() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, _rx) = oneshot::channel();

        tokio::spawn(run_callback_server(
            listener,
            tx,
            "ABC-1234".to_string(),
            TEST_GATEWAY.to_string(),
        ));

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request = format!(
            "GET /callback?token=jwt&code=ABC-1234 HTTP/1.1\r\n\
             Host: 127.0.0.1\r\n\
             Origin: {TEST_GATEWAY}\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.contains("405 Method Not Allowed"),
            "GET should return 405:\n{response}"
        );
    }
}
