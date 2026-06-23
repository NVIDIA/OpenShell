// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Local-only integration test — not checked in.
// Requires LocalStack running on localhost:4566.
// Run with: cargo test -p openshell-supervisor-network --test sigv4_localstack -- --ignored --nocapture

use openshell_supervisor_network::sigv4::{apply_sigv4_headers_only, apply_sigv4_to_request};
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const LOCALSTACK: &str = "127.0.0.1:4566";
const ACCESS_KEY: &str = "test";
const SECRET_KEY: &str = "test";
const REGION: &str = "us-east-1";
const OBJECT_BODY: &str = "hello from sigv4 integration test";

static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

fn unique_bucket() -> String {
    let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("sigv4-test-{n}-{}", std::process::id())
}

fn s3_host() -> String {
    format!("s3.{REGION}.amazonaws.com")
}

async fn send_raw(raw: &[u8]) -> (u16, String) {
    let mut stream = TcpStream::connect(LOCALSTACK)
        .await
        .expect("connect to LocalStack");
    stream.write_all(raw).await.expect("write request");

    let mut buf = Vec::with_capacity(16384);
    let mut tmp = [0u8; 4096];
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut tmp)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
            Ok(Err(e)) => panic!("read error: {e}"),
        }
    }

    let response = String::from_utf8_lossy(&buf).to_string();
    let status = response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    (status, response)
}

async fn signed_request(raw: &str, host: &str, service: &str) -> (u16, String) {
    let signed = apply_sigv4_to_request(
        raw.as_bytes(),
        host,
        REGION,
        service,
        ACCESS_KEY,
        SECRET_KEY,
        None,
    )
    .expect("signing failed");
    send_raw(&signed).await
}

async fn create_bucket(bucket: &str) {
    let raw = format!(
        "PUT /{bucket} HTTP/1.1\r\nHost: {LOCALSTACK}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    );
    let (status, body) = signed_request(&raw, &s3_host(), "s3").await;
    assert!(
        status == 200 || status == 409,
        "CreateBucket: expected 200 or 409, got {status}\n{body}"
    );
}

async fn put_object(bucket: &str, key: &str, body: &str) {
    let raw = format!(
        "PUT /{bucket}/{key} HTTP/1.1\r\nHost: {LOCALSTACK}\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let (status, response) = signed_request(&raw, &s3_host(), "s3").await;
    assert!(
        status == 200 || status == 204,
        "PutObject: expected 200/204, got {status}\n{response}"
    );
}

async fn delete_object(bucket: &str, key: &str) {
    let raw = format!(
        "DELETE /{bucket}/{key} HTTP/1.1\r\nHost: {LOCALSTACK}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    );
    let (status, response) = signed_request(&raw, &s3_host(), "s3").await;
    assert!(
        status == 200 || status == 204,
        "DeleteObject: expected 200/204, got {status}\n{response}"
    );
}

async fn delete_bucket(bucket: &str) {
    let raw = format!(
        "DELETE /{bucket} HTTP/1.1\r\nHost: {LOCALSTACK}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    );
    let (status, response) = signed_request(&raw, &s3_host(), "s3").await;
    assert!(
        status == 200 || status == 204,
        "DeleteBucket: expected 200/204, got {status}\n{response}"
    );
}

#[tokio::test]
#[ignore = "requires LocalStack on localhost:4566"]
async fn sigv4_s3_create_bucket() {
    let bucket = unique_bucket();
    create_bucket(&bucket).await;
    delete_bucket(&bucket).await;
    println!("PASS: S3 CreateBucket with SigV4 signed body");
}

#[tokio::test]
#[ignore = "requires LocalStack on localhost:4566"]
async fn sigv4_s3_put_and_delete_object() {
    let bucket = unique_bucket();
    create_bucket(&bucket).await;
    put_object(&bucket, "test.txt", OBJECT_BODY).await;
    delete_object(&bucket, "test.txt").await;
    delete_bucket(&bucket).await;
    println!("PASS: S3 PutObject + DeleteObject with SigV4 signed body");
}

#[tokio::test]
#[ignore = "requires LocalStack on localhost:4566"]
async fn sigv4_s3_get_object_unsigned_payload() {
    let bucket = unique_bucket();
    create_bucket(&bucket).await;
    put_object(&bucket, "get-test.txt", OBJECT_BODY).await;

    let raw = format!(
        "GET /{bucket}/get-test.txt HTTP/1.1\r\nHost: {LOCALSTACK}\r\nConnection: close\r\n\r\n"
    );
    let signed = apply_sigv4_headers_only(
        raw.as_bytes(),
        &s3_host(),
        REGION,
        "s3",
        ACCESS_KEY,
        SECRET_KEY,
        None,
    )
    .expect("signing failed");

    let (status, response) = send_raw(&signed).await;
    assert_eq!(
        status, 200,
        "GetObject: expected 200, got {status}\n{response}"
    );
    assert!(
        response.contains(OBJECT_BODY),
        "GetObject: body should contain '{OBJECT_BODY}'\n{response}"
    );

    delete_object(&bucket, "get-test.txt").await;
    delete_bucket(&bucket).await;
    println!("PASS: S3 GetObject with UNSIGNED-PAYLOAD (apply_sigv4_headers_only)");
}

#[tokio::test]
#[ignore = "requires LocalStack on localhost:4566"]
async fn sigv4_sts_get_caller_identity() {
    let body = "Action=GetCallerIdentity&Version=2011-06-15";
    let raw = format!(
        "POST / HTTP/1.1\r\nHost: {LOCALSTACK}\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );

    let signed = apply_sigv4_to_request(
        raw.as_bytes(),
        &format!("sts.{REGION}.amazonaws.com"),
        REGION,
        "sts",
        ACCESS_KEY,
        SECRET_KEY,
        None,
    )
    .expect("signing failed");

    let (status, response) = send_raw(&signed).await;
    assert_eq!(
        status, 200,
        "GetCallerIdentity: expected 200, got {status}\n{response}"
    );
    assert!(
        response.contains("GetCallerIdentityResult"),
        "GetCallerIdentity: response should contain result\n{response}"
    );
    println!("PASS: STS GetCallerIdentity with SigV4 signed body");
}

#[tokio::test]
#[ignore = "requires LocalStack on localhost:4566"]
async fn sigv4_s3_put_with_session_token() {
    let bucket = unique_bucket();
    create_bucket(&bucket).await;

    let raw = format!(
        "PUT /{bucket}/session-test.txt HTTP/1.1\r\nHost: {LOCALSTACK}\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n\r\nsession-data"
    );
    let signed = apply_sigv4_to_request(
        raw.as_bytes(),
        &s3_host(),
        REGION,
        "s3",
        ACCESS_KEY,
        SECRET_KEY,
        Some("FakeSessionToken"),
    )
    .expect("signing with session token failed");

    let signed_str = String::from_utf8_lossy(&signed);
    assert!(
        signed_str.contains("x-amz-security-token: FakeSessionToken"),
        "signed request should include session token header"
    );

    let (status, response) = send_raw(&signed).await;
    assert!(
        status == 200 || status == 204,
        "PutObject with session token: expected 200/204, got {status}\n{response}"
    );

    delete_object(&bucket, "session-test.txt").await;
    delete_bucket(&bucket).await;
    println!("PASS: S3 PutObject with session token");
}
