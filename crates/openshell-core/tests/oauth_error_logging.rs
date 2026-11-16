// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Token-service error text must never reach logs.
//!
//! This test captures a scoped subscriber. It lives in its own binary because a
//! parallel test can register the shared `warn!` callsite as disabled first.

#![cfg(feature = "oauth")]

use std::io::Write;
use std::sync::{Arc, Mutex};

use openshell_core::oauth::{TokenExchangeParams, TokenGrantClient, post_oauth_token_exchange};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const CANARY: &str = "SUBJECT_SECRET_CANARY";

#[derive(Clone, Default)]
struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

impl Write for CapturedLogs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log buffer").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Serve one request with HTTP 400 and `body`, after reading the whole request.
async fn rejecting_endpoint_once(body: String) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut request = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let read = stream.read(&mut chunk).await.expect("read");
            assert!(read > 0, "request ended early");
            request.extend_from_slice(&chunk[..read]);
            let text = String::from_utf8_lossy(&request);
            let Some((headers, form)) = text.split_once("\r\n\r\n") else {
                continue;
            };
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            if form.len() >= length {
                break;
            }
        }
        let response = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len(),
        );
        stream.write_all(response.as_bytes()).await.expect("write");
        stream.shutdown().await.expect("shutdown");
    });
    (format!("http://{addr}/token"), task)
}

#[tokio::test]
async fn rejected_grant_log_omits_token_service_error_text() {
    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer({
            let logs = logs.clone();
            move || logs.clone()
        })
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let client = TokenGrantClient::new().expect("client");
    let echoes = [
        format!(r#"{{"error":"invalid_grant","error_description":"subject_token={CANARY}"}}"#),
        format!(r#"{{"error":"subject_token={CANARY}"}}"#),
    ];
    for body in echoes {
        let (endpoint, task) = rejecting_endpoint_once(body).await;
        let failure = post_oauth_token_exchange(
            &client,
            &endpoint,
            &TokenExchangeParams {
                client_assertion: "jwt-svid-token",
                client_assertion_type: "",
                subject_token: CANARY,
                subject_token_type: "",
                audience: "",
                scopes: &[],
                requested_token_type: "",
            },
            Some("request-1"),
        )
        .await
        .expect_err("token service rejected the exchange");
        task.await.expect("endpoint task");
        assert_eq!(failure.code(), "unclassified");
    }

    let output = String::from_utf8(logs.0.lock().expect("log buffer").clone()).expect("UTF-8");
    assert_eq!(
        output.matches("token service rejected the grant").count(),
        2,
        "{output}"
    );
    assert!(output.contains("upstream_http_status=400"), "{output}");
    assert!(output.contains("failure_code=\"unclassified\""), "{output}");
    assert!(!output.contains(CANARY), "{output}");
}
