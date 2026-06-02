// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for SigV4 signing against real AWS endpoints.
//!
//! These tests are `#[ignore]`d by default — they require real AWS credentials
//! in `~/.aws/credentials` and network access.
//!
//! Run with:
//!   cargo test -p openshell-sandbox --test sigv4_real_aws -- --ignored --nocapture
//!
//! For S3 tests, also set:
//!   S3_TEST_BUCKET=your-bucket-name

use std::io::BufRead;
use std::net::TcpStream;
use std::sync::Arc;

fn load_aws_credentials() -> Option<(String, String, Option<String>)> {
    let home = std::env::var("HOME").ok()?;
    let path = std::path::Path::new(&home).join(".aws/credentials");
    let file = std::fs::File::open(path).ok()?;
    let reader = std::io::BufReader::new(file);

    let mut access_key = None;
    let mut secret_key = None;
    let mut session_token = None;
    let mut in_default = false;

    for line in reader.lines().map_while(Result::ok) {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_default = trimmed == "[default]";
            continue;
        }
        if !in_default {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            match k.trim() {
                "aws_access_key_id" => access_key = Some(v.trim().to_string()),
                "aws_secret_access_key" => secret_key = Some(v.trim().to_string()),
                "aws_session_token" => session_token = Some(v.trim().to_string()),
                _ => {}
            }
        }
    }

    Some((access_key?, secret_key?, session_token))
}

/// Send raw signed HTTP bytes over TLS and return (status_code, response_body).
fn send_https_request(host: &str, signed_request: &[u8]) -> (u16, String) {
    use std::io::{Read, Write};

    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name: rustls::pki_types::ServerName<'_> = host.to_string().try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect(format!("{host}:443")).expect("TCP connect");
    sock.set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .ok();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    tls.write_all(signed_request).expect("write request");
    tls.flush().expect("flush");

    // Read response headers + body. We read in chunks and stop when we've
    // read Content-Length bytes of body, or on connection close / timeout.
    let mut response = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => {
                // ConnectionAborted / UnexpectedEof are normal for Connection: close
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::UnexpectedEof
                ) {
                    break;
                }
                panic!("read error: {e}");
            }
        }
        // Check if we have the full response (headers + content-length body)
        let resp_str = String::from_utf8_lossy(&response);
        if let Some(header_end) = resp_str.find("\r\n\r\n") {
            let headers = &resp_str[..header_end];
            let body_start = header_end + 4;
            if let Some(cl) = headers.lines().find_map(|l| {
                let lower = l.to_ascii_lowercase();
                lower
                    .strip_prefix("content-length:")
                    .and_then(|v| v.trim().parse::<usize>().ok())
            }) {
                if response.len() >= body_start + cl {
                    break;
                }
            }
        }
    }

    let response_str = String::from_utf8_lossy(&response);
    let status = response_str
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    let body = response_str
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or("")
        .to_string();

    (status, body)
}

#[test]
#[ignore]
fn bedrock_invoke_with_signed_body() {
    let (access_key, secret_key, session_token) =
        load_aws_credentials().expect("AWS credentials not found in ~/.aws/credentials");

    let host = "bedrock-runtime.us-east-2.amazonaws.com";
    let body = r#"{"anthropic_version":"bedrock-2023-05-31","max_tokens":10,"messages":[{"role":"user","content":"Say exactly: sigv4_ok"}]}"#;

    let raw_request = format!(
        "POST /model/us.anthropic.claude-haiku-4-5-20251001-v1%3A0/invoke HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );

    let signed = openshell_sandbox::sigv4::apply_sigv4_to_request(
        raw_request.as_bytes(),
        host,
        "us-east-2",
        "bedrock",
        &access_key,
        &secret_key,
        session_token.as_deref(),
    )
    .expect("signing failed");

    let signed_str = String::from_utf8_lossy(&signed);
    assert!(
        signed_str.contains("x-amz-content-sha256: "),
        "should contain body hash header"
    );
    assert!(
        !signed_str.contains("UNSIGNED-PAYLOAD"),
        "should NOT contain UNSIGNED-PAYLOAD"
    );

    let (status, body) = send_https_request(host, &signed);
    println!("Bedrock signed-body response: status={status}");
    println!("  body: {}", &body[..body.len().min(200)]);

    assert_eq!(status, 200, "Bedrock should accept signed payload");
}

#[test]
#[ignore]
fn bedrock_rejects_unsigned_body() {
    let (access_key, secret_key, session_token) =
        load_aws_credentials().expect("AWS credentials not found in ~/.aws/credentials");

    let host = "bedrock-runtime.us-east-2.amazonaws.com";
    let body = r#"{"anthropic_version":"bedrock-2023-05-31","max_tokens":10,"messages":[{"role":"user","content":"test"}]}"#;

    let raw_headers = format!(
        "POST /model/us.anthropic.claude-haiku-4-5-20251001-v1%3A0/invoke HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );

    let signed_headers = openshell_sandbox::sigv4::apply_sigv4_headers_only(
        raw_headers.as_bytes(),
        host,
        "us-east-2",
        "bedrock",
        &access_key,
        &secret_key,
        session_token.as_deref(),
    )
    .expect("signing failed");

    let signed_str = String::from_utf8_lossy(&signed_headers);
    assert!(signed_str.contains("x-amz-content-sha256: UNSIGNED-PAYLOAD"));

    let mut full_request = signed_headers;
    full_request.extend_from_slice(body.as_bytes());

    let (status, resp_body) = send_https_request(host, &full_request);
    println!("Bedrock unsigned-body response: status={status}");
    println!("  body: {}", &resp_body[..resp_body.len().min(200)]);

    assert_eq!(status, 403, "Bedrock should reject UNSIGNED-PAYLOAD");
}

#[test]
#[ignore]
fn s3_put_get_delete_with_unsigned_body() {
    let bucket =
        std::env::var("S3_TEST_BUCKET").expect("Set S3_TEST_BUCKET env var to run this test");
    let (access_key, secret_key, session_token) =
        load_aws_credentials().expect("AWS credentials not found in ~/.aws/credentials");

    let host = format!("{bucket}.s3.us-east-2.amazonaws.com");
    let key = format!(
        "openshell-sigv4-test-{}.txt",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );
    let body = b"Hello from OpenShell SigV4 unsigned payload test";

    // --- PUT ---
    let raw_put = format!(
        "PUT /{key} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );

    let signed_put = openshell_sandbox::sigv4::apply_sigv4_headers_only(
        raw_put.as_bytes(),
        &host,
        "us-east-2",
        "s3",
        &access_key,
        &secret_key,
        session_token.as_deref(),
    )
    .expect("signing PUT failed");

    let signed_str = String::from_utf8_lossy(&signed_put);
    assert!(signed_str.contains("x-amz-content-sha256: UNSIGNED-PAYLOAD"));

    let mut full_put = signed_put;
    full_put.extend_from_slice(body);

    let (put_status, _) = send_https_request(&host, &full_put);
    println!("S3 PUT unsigned-body: status={put_status}");
    assert_eq!(put_status, 200, "S3 should accept UNSIGNED-PAYLOAD PUT");

    // --- GET ---
    let raw_get = format!(
        "GET /{key} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Connection: close\r\n\
         \r\n"
    );

    let signed_get = openshell_sandbox::sigv4::apply_sigv4_headers_only(
        raw_get.as_bytes(),
        &host,
        "us-east-2",
        "s3",
        &access_key,
        &secret_key,
        session_token.as_deref(),
    )
    .expect("signing GET failed");

    let (get_status, get_body) = send_https_request(&host, &signed_get);
    println!("S3 GET: status={get_status}");
    println!("  body: {}", &get_body[..get_body.len().min(200)]);
    assert_eq!(get_status, 200, "S3 GET should succeed");
    assert!(
        get_body.contains("Hello from OpenShell"),
        "GET body should contain uploaded content"
    );

    // --- DELETE cleanup ---
    let raw_del = format!(
        "DELETE /{key} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Connection: close\r\n\
         \r\n"
    );

    let signed_del = openshell_sandbox::sigv4::apply_sigv4_headers_only(
        raw_del.as_bytes(),
        &host,
        "us-east-2",
        "s3",
        &access_key,
        &secret_key,
        session_token.as_deref(),
    )
    .expect("signing DELETE failed");

    let (del_status, _) = send_https_request(&host, &signed_del);
    println!("S3 DELETE: status={del_status}");
}
