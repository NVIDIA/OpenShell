// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration test for SigV4 proxy-side re-signing.
//!
//! Simulates what the proxy does: takes a raw HTTP request (like the AWS SDK
//! would generate with placeholder credentials), strips the invalid AWS auth
//! headers, re-signs with real credentials, and sends to Bedrock.
//!
//! Run with real AWS credentials:
//!   AWS_ACCESS_KEY_ID=AKIAxxx AWS_SECRET_ACCESS_KEY=xxx cargo test \
//!     -p openshell-sandbox --test sigv4_signing -- --ignored --nocapture

use std::io::{Read, Write};
use std::net::TcpStream;

#[test]
#[ignore] // requires real AWS credentials
fn sigv4_resign_and_call_bedrock() {
    let access_key = std::env::var("AWS_ACCESS_KEY_ID").expect("AWS_ACCESS_KEY_ID must be set");
    let secret_key =
        std::env::var("AWS_SECRET_ACCESS_KEY").expect("AWS_SECRET_ACCESS_KEY must be set");
    let session_token = std::env::var("AWS_SESSION_TOKEN").ok();
    let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-2".to_string());
    let host = format!("bedrock.{region}.amazonaws.com");

    // Build a raw HTTP request as if the AWS SDK generated it with fake creds.
    // This is what arrives at the proxy from inside the sandbox.
    let fake_signed_request = format!(
        "GET /foundation-models HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/json\r\n\
         Authorization: AWS4-HMAC-SHA256 Credential=FAKEFAKEFAKE/20260101/us-east-2/bedrock/aws4_request, SignedHeaders=host, Signature=0000000000000000000000000000000000000000000000000000000000000000\r\n\
         X-Amz-Date: 20260101T000000Z\r\n\
         X-Amz-Content-Sha256: fake-hash\r\n\
         Accept: application/json\r\n\
         Connection: keep-alive\r\n\
         \r\n"
    );

    // Step 1: Strip invalid AWS auth headers (proxy does this before
    // the fail-closed placeholder scan)
    let stripped = openshell_sandbox::sigv4::strip_aws_headers(fake_signed_request.as_bytes());
    let stripped_str = String::from_utf8_lossy(&stripped);
    assert!(
        !stripped_str.contains("FAKEFAKEFAKE"),
        "old auth should be stripped"
    );
    assert!(
        !stripped_str.contains("fake-hash"),
        "old hash should be stripped"
    );

    // Step 2: Re-sign with real credentials
    let signed = openshell_sandbox::sigv4::apply_sigv4_to_request(
        &stripped,
        &host,
        &region,
        "bedrock",
        &access_key,
        &secret_key,
        session_token.as_deref(),
    )
    .expect("SigV4 signing should succeed");

    let signed_str = String::from_utf8_lossy(&signed);
    eprintln!("--- Signed request headers ---");
    if let Some(end) = signed_str.find("\r\n\r\n") {
        eprintln!("{}", &signed_str[..end]);
    }

    // Step 3: Send to Bedrock over TLS
    let mut tcp = TcpStream::connect(format!("{host}:443")).expect("TCP connect");
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let server_name: rustls::pki_types::ServerName = host.clone().try_into().unwrap();
    let mut tls = rustls::ClientConnection::new(std::sync::Arc::new(config), server_name).unwrap();
    let mut stream = rustls::Stream::new(&mut tls, &mut tcp);

    stream.write_all(&signed).expect("TLS write");
    stream.flush().expect("TLS flush");

    let mut response = vec![0u8; 4096];
    let n = stream.read(&mut response).expect("TLS read");
    let response_str = String::from_utf8_lossy(&response[..n]);

    eprintln!("\n--- Response (first {n} bytes) ---");
    eprintln!("{response_str}");

    // Verify we got HTTP 200, not 403 InvalidSignatureException
    assert!(
        response_str.starts_with("HTTP/1.1 200"),
        "Expected 200 OK but got: {}",
        response_str.lines().next().unwrap_or("(empty)")
    );
}
