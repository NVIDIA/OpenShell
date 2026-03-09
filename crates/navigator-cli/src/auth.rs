// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Browser-based Cloudflare Access authentication flow.
//!
//! Opens the user's browser to the gateway's `/auth/connect` page, which
//! (after Cloudflare Access login) extracts the `CF_Authorization` cookie
//! and sends it via an XHR POST to a localhost callback server running here.
//! A confirmation code binds the browser session to this CLI session,
//! preventing port-redirection attacks.

use miette::{IntoDiagnostic, Result};
use std::io::Write;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tracing::debug;

/// Timeout for the browser auth flow.
const AUTH_TIMEOUT: Duration = Duration::from_secs(120);

/// Length of the confirmation code (alphanumeric characters).
const CODE_LENGTH: usize = 7;

/// Generate a random alphanumeric confirmation code (e.g. "A7X-3KP").
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
        _ = tokio::time::sleep(AUTH_TIMEOUT) => {
            return Err(miette::miette!(
                "authentication timed out after {} seconds.\n\
                 Try again with: nemoclaw gateway login",
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

/// Build CORS headers for the given allowed origin.
fn cors_headers(allowed_origin: &str) -> String {
    format!(
        "Access-Control-Allow-Origin: {allowed_origin}\r\n\
         Access-Control-Allow-Methods: POST, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type\r\n\
         Access-Control-Max-Age: 60\r\n\
         Vary: Origin"
    )
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
    let allowed_origin = extract_origin(&gateway_endpoint).unwrap_or_default();
    // We may need to handle up to two requests: one OPTIONS preflight, then
    // the actual POST. Use a loop with a request limit.
    let mut tx = Some(tx);
    for _ in 0..2 {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };

        let mut buf = vec![0u8; 16384];
        let Ok(n) = stream.read(&mut buf).await else {
            continue;
        };

        let request = String::from_utf8_lossy(&buf[..n]);
        let request_line = request.lines().next().unwrap_or("");
        debug!(request_line = %request_line, "callback request received");

        let method = request_line.split_whitespace().next().unwrap_or("");
        let path = request_line.split_whitespace().nth(1).unwrap_or("");
        let cors = cors_headers(&allowed_origin);

        if !path.starts_with("/callback") {
            let response = format!(
                "HTTP/1.1 404 Not Found\r\n\
                 {cors}\r\n\
                 Content-Length: 0\r\n\
                 Connection: close\r\n\r\n"
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
            continue;
        }

        // Validate the Origin header — only the gateway origin is allowed.
        // A mismatch terminates the server: if the origin is wrong, no
        // subsequent request from that browser session will be valid either.
        let request_origin = extract_header(&request, "Origin");
        if !allowed_origin.is_empty() {
            match request_origin {
                Some(ref origin) if origin == &allowed_origin => {}
                _ => {
                    debug!(
                        request_origin = ?request_origin,
                        allowed_origin = %allowed_origin,
                        "CORS origin mismatch — rejecting request"
                    );
                    let body = r#"{"ok":false,"error":"origin not allowed"}"#;
                    let response = format!(
                        "HTTP/1.1 403 Forbidden\r\n\
                         {cors}\r\n\
                         Content-Type: application/json\r\n\
                         Content-Length: {}\r\n\
                         Connection: close\r\n\r\n\
                         {body}",
                        body.len(),
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                    return;
                }
            }
        }

        if method == "OPTIONS" {
            // CORS preflight response.
            let response = format!(
                "HTTP/1.1 204 No Content\r\n\
                 {cors}\r\n\
                 Content-Length: 0\r\n\
                 Connection: close\r\n\r\n"
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
            continue;
        }

        if method != "POST" {
            let body = r#"{"error":"method not allowed"}"#;
            let response = format!(
                "HTTP/1.1 405 Method Not Allowed\r\n\
                 {cors}\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n\
                 {}",
                body.len(),
                body,
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
            // Non-POST, non-OPTIONS request — continue loop (could be a
            // stray request before the real POST arrives).
            continue;
        }

        // Parse the JSON body from the POST request.
        let body = extract_body(&request);
        let (token, code) = parse_callback_json(body);

        let (status, response_body) = match (token, code) {
            (Some(ref t), Some(ref c)) if !t.is_empty() && c == &expected_code => {
                if let Some(sender) = tx.take() {
                    let _ = sender.send(t.clone());
                }
                ("200 OK", r#"{"ok":true}"#)
            }
            (Some(_), Some(_)) => {
                // Code mismatch — possible port-redirection attack.
                (
                    "403 Forbidden",
                    r#"{"ok":false,"error":"confirmation code mismatch"}"#,
                )
            }
            _ => (
                "400 Bad Request",
                r#"{"ok":false,"error":"missing token or code"}"#,
            ),
        };

        let response = format!(
            "HTTP/1.1 {status}\r\n\
             {cors}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n\
             {}",
            response_body.len(),
            response_body,
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;

        // POST always terminates the loop — whether success or failure.
        // On success, `tx` is consumed. On failure, dropping `tx` signals
        // the receiver that auth failed.
        return;
    }
}

/// Extract a header value from a raw HTTP request string (case-insensitive).
fn extract_header<'a>(request: &'a str, name: &str) -> Option<String> {
    let lower_name = name.to_ascii_lowercase();
    for line in request.lines() {
        if let Some((key, value)) = line.split_once(':') {
            if key.trim().to_ascii_lowercase() == lower_name {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

/// Extract the HTTP body from a raw request string.
///
/// Finds the `\r\n\r\n` header/body boundary and returns the body portion.
fn extract_body(request: &str) -> &str {
    request
        .find("\r\n\r\n")
        .map(|i| &request[i + 4..])
        .unwrap_or("")
}

/// Parse `{"token":"...","code":"..."}` from a JSON body.
///
/// Uses a minimal hand-written parser to avoid pulling in serde for the CLI
/// callback server. Only extracts the `token` and `code` string fields.
fn parse_callback_json(body: &str) -> (Option<String>, Option<String>) {
    let token = extract_json_string(body, "token");
    let code = extract_json_string(body, "code");
    (token, code)
}

/// Extract a string value for the given key from a JSON object body.
///
/// Handles JSON string escapes (`\"`, `\\`). This is intentionally minimal —
/// it only needs to handle well-formed requests from our own JavaScript.
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    // Look for `"key":"` pattern.
    let pattern = format!("\"{}\"", key);
    let key_pos = json.find(&pattern)?;
    let after_key = &json[key_pos + pattern.len()..];

    // Skip optional whitespace and the colon.
    let after_colon = after_key.trim_start().strip_prefix(':')?;
    let after_colon = after_colon.trim_start();

    // Expect opening quote.
    let value_start = after_colon.strip_prefix('"')?;

    // Read until unescaped closing quote.
    let mut result = String::new();
    let mut chars = value_start.chars();
    loop {
        match chars.next()? {
            '\\' => {
                // Handle escaped character.
                match chars.next()? {
                    '"' => result.push('"'),
                    '\\' => result.push('\\'),
                    '/' => result.push('/'),
                    'n' => result.push('\n'),
                    't' => result.push('\t'),
                    other => {
                        result.push('\\');
                        result.push(other);
                    }
                }
            }
            '"' => break,
            c => result.push(c),
        }
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    // JSON parsing
    // ---------------------------------------------------------------

    #[test]
    fn parse_callback_json_basic() {
        let body = r#"{"token":"my-jwt-123","code":"ABC-1234"}"#;
        let (token, code) = parse_callback_json(body);
        assert_eq!(token.as_deref(), Some("my-jwt-123"));
        assert_eq!(code.as_deref(), Some("ABC-1234"));
    }

    #[test]
    fn parse_callback_json_with_escapes() {
        let body = r#"{"token":"jwt-with-\"quotes\"","code":"XY7-9KLM"}"#;
        let (token, code) = parse_callback_json(body);
        assert_eq!(token.as_deref(), Some("jwt-with-\"quotes\""));
        assert_eq!(code.as_deref(), Some("XY7-9KLM"));
    }

    #[test]
    fn parse_callback_json_missing_fields() {
        let body = r#"{"token":"jwt"}"#;
        let (token, code) = parse_callback_json(body);
        assert_eq!(token.as_deref(), Some("jwt"));
        assert_eq!(code, None);
    }

    #[test]
    fn parse_callback_json_empty_body() {
        let (token, code) = parse_callback_json("");
        assert_eq!(token, None);
        assert_eq!(code, None);
    }

    #[test]
    fn extract_body_finds_content() {
        let request =
            "POST /callback HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"token\":\"x\"}";
        assert_eq!(extract_body(request), "{\"token\":\"x\"}");
    }

    #[test]
    fn extract_body_no_boundary() {
        assert_eq!(extract_body("no boundary here"), "");
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
    // Header extraction
    // ---------------------------------------------------------------

    #[test]
    fn extract_header_finds_origin() {
        let request =
            "POST /callback HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://gw.example.com\r\n\r\n";
        assert_eq!(
            extract_header(request, "Origin"),
            Some("https://gw.example.com".to_string())
        );
    }

    #[test]
    fn extract_header_case_insensitive() {
        let request = "POST /callback HTTP/1.1\r\norigin: https://gw.example.com\r\n\r\n";
        assert_eq!(
            extract_header(request, "Origin"),
            Some("https://gw.example.com".to_string())
        );
    }

    #[test]
    fn extract_header_missing() {
        let request = "POST /callback HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        assert_eq!(extract_header(request, "Origin"), None);
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
        assert!(
            response.contains(&format!("Access-Control-Allow-Origin: {TEST_GATEWAY}")),
            "response should reflect gateway origin:\n{response}"
        );
        assert!(
            !response.contains("Access-Control-Allow-Origin: *"),
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
        assert!(
            response.contains("204 No Content"),
            "preflight should return 204:\n{response}"
        );
        assert!(
            response.contains(&format!("Access-Control-Allow-Origin: {TEST_GATEWAY}")),
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
