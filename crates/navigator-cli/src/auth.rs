// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Browser-based Cloudflare Access authentication flow.
//!
//! Opens the user's browser to the gateway's `/auth/connect` page, which
//! (after Cloudflare Access login) extracts the `CF_Authorization` cookie
//! and redirects to a localhost callback server running here. The callback
//! captures the JWT and returns it to the caller.

use miette::{IntoDiagnostic, Result};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tracing::debug;

/// Timeout for the browser auth flow.
const AUTH_TIMEOUT: Duration = Duration::from_secs(120);

/// Run the browser-based CF Access auth flow.
///
/// 1. Starts an ephemeral localhost HTTP server
/// 2. Opens the browser to the gateway's `/auth/connect` page
/// 3. Waits for the redirect callback with the CF JWT
/// 4. Returns the token
pub async fn browser_auth_flow(gateway_endpoint: &str) -> Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0").await.into_diagnostic()?;
    let local_addr = listener.local_addr().into_diagnostic()?;
    let callback_port = local_addr.port();

    let auth_url = format!(
        "{}/auth/connect?callback_port={callback_port}",
        gateway_endpoint.trim_end_matches('/')
    );

    // Channel to receive the token from the callback handler.
    let (tx, rx) = oneshot::channel::<String>();

    // Spawn the callback server.
    let server_handle = tokio::spawn(run_callback_server(listener, tx));

    // Open the browser.
    eprintln!("Opening browser for authentication...");
    if let Err(e) = open_browser(&auth_url) {
        debug!(error = %e, "failed to open browser");
        eprintln!();
        eprintln!("Could not open browser automatically.");
        eprintln!("Open this URL in your browser:");
        eprintln!("  {auth_url}");
        eprintln!();
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

/// Run the ephemeral callback server. Accepts a single connection, parses
/// the `?token=` query parameter, sends it through the channel, and returns
/// a success HTML page.
async fn run_callback_server(listener: TcpListener, tx: oneshot::Sender<String>) {
    // We only need to handle one request.
    let Ok((mut stream, _)) = listener.accept().await else {
        return;
    };

    let mut buf = vec![0u8; 8192];
    let Ok(n) = stream.read(&mut buf).await else {
        return;
    };

    let request = String::from_utf8_lossy(&buf[..n]);
    debug!(request_line = %request.lines().next().unwrap_or(""), "callback request received");

    // Parse the request line: GET /callback?token=<jwt> HTTP/1.1
    let token = request.lines().next().and_then(|line| {
        let path = line.split_whitespace().nth(1)?;
        if !path.starts_with("/callback") {
            return None;
        }
        let query = path.split('?').nth(1)?;
        query.split('&').find_map(|param| {
            let (key, val) = param.split_once('=')?;
            if key == "token" {
                Some(url_decode(val))
            } else {
                None
            }
        })
    });

    let response_body = match token {
        Some(ref t) if !t.is_empty() => {
            let _ = tx.send(t.clone());
            SUCCESS_HTML
        }
        _ => ERROR_HTML,
    };

    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        response_body.len(),
        response_body,
    );

    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Minimal URL decoding (handles `%xx` escapes and `+` as space).
fn url_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.bytes();
    while let Some(b) = chars.next() {
        match b {
            b'%' => {
                let hi = chars.next().unwrap_or(b'0');
                let lo = chars.next().unwrap_or(b'0');
                let byte = hex_val(hi) << 4 | hex_val(lo);
                result.push(byte as char);
            }
            b'+' => result.push(' '),
            _ => result.push(b as char),
        }
    }
    result
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

const SUCCESS_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>NemoClaw — Connected</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'SF Mono', 'Fira Code', 'JetBrains Mono', monospace;
            background: #0a0a0a;
            color: #e0e0e0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .card {
            background: #141414;
            border: 1px solid #2a2a2a;
            border-radius: 12px;
            padding: 48px;
            max-width: 480px;
            width: 100%;
            text-align: center;
        }
        .logo { font-size: 28px; font-weight: 700; color: #76b900; margin-bottom: 8px; }
        .check { font-size: 48px; margin: 24px 0; }
        .message { color: #888; font-size: 14px; }
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">NemoClaw</div>
        <div class="check">&#10003;</div>
        <div class="message">Connected! You can close this tab.</div>
    </div>
</body>
</html>"#;

const ERROR_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>NemoClaw — Error</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'SF Mono', 'Fira Code', 'JetBrains Mono', monospace;
            background: #0a0a0a;
            color: #e0e0e0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .card {
            background: #141414;
            border: 1px solid #2a2a2a;
            border-radius: 12px;
            padding: 48px;
            max-width: 480px;
            width: 100%;
            text-align: center;
        }
        .logo { font-size: 28px; font-weight: 700; color: #76b900; margin-bottom: 8px; }
        .error { font-size: 48px; margin: 24px 0; color: #ff4444; }
        .message { color: #888; font-size: 14px; }
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">NemoClaw</div>
        <div class="error">&#10007;</div>
        <div class="message">Authentication failed. No token received.<br>Please try again.</div>
    </div>
</body>
</html>"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_decode_basic() {
        assert_eq!(url_decode("hello%20world"), "hello world");
        assert_eq!(url_decode("hello+world"), "hello world");
        assert_eq!(url_decode("no%2Fescapes"), "no/escapes");
    }

    #[test]
    fn url_decode_passthrough() {
        assert_eq!(
            url_decode("eyJhbGciOiJSUzI1NiJ9.test.sig"),
            "eyJhbGciOiJSUzI1NiJ9.test.sig"
        );
    }

    #[test]
    fn url_decode_percent_encoded_equals() {
        assert_eq!(url_decode("token%3Dvalue"), "token=value");
    }

    #[tokio::test]
    async fn callback_server_captures_token() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();

        tokio::spawn(run_callback_server(listener, tx));

        // Simulate a browser callback.
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /callback?token=test-jwt-123 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();

        let token = rx.await.unwrap();
        assert_eq!(token, "test-jwt-123");
    }
}
