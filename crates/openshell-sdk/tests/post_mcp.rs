// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OpenShellClient::post_mcp` against a local HTTP/2 server standing in for
//! the gateway's `/mcp`.

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use openshell_sdk::{
    AuthConfig, ClientConfig, OpenShellClient, Refresh, RefreshError, RefreshedToken,
};
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::net::TcpListener;

/// How the stand-in gateway answers.
#[derive(Clone, Copy)]
enum Answer {
    /// 200 for `Bearer fresh-token`, 401 for anything else.
    FreshTokenOnly,
    Always(StatusCode),
}

#[derive(Default)]
struct Seen {
    requests: AtomicU32,
    authorization: Mutex<Vec<String>>,
    workspace: Mutex<Vec<String>>,
}

async fn start(answer: Answer) -> (String, Arc<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Seen::default());
    let server_seen = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let seen = Arc::clone(&server_seen);
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                    let seen = Arc::clone(&seen);
                    async move {
                        let header = |name: &str| {
                            request
                                .headers()
                                .get(name)
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or_default()
                                .to_string()
                        };
                        if request.uri().path() == "/mcp" {
                            seen.requests.fetch_add(1, Ordering::SeqCst);
                            seen.authorization
                                .lock()
                                .unwrap()
                                .push(header("authorization"));
                            seen.workspace
                                .lock()
                                .unwrap()
                                .push(header("x-openshell-workspace"));
                        }
                        let status = match answer {
                            Answer::FreshTokenOnly
                                if header("authorization") == "Bearer fresh-token" =>
                            {
                                StatusCode::OK
                            }
                            Answer::FreshTokenOnly => StatusCode::UNAUTHORIZED,
                            Answer::Always(status) => status,
                        };
                        let mut response = Response::new(Full::new(Bytes::from_static(b"{}")));
                        *response.status_mut() = status;
                        Ok::<_, Infallible>(response)
                    }
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (endpoint, seen)
}

/// Hands out `fresh-token` and counts how often it is asked.
struct CountingRefresher {
    calls: Arc<AtomicU32>,
}

#[async_trait::async_trait]
impl Refresh for CountingRefresher {
    async fn refresh(&self) -> Result<RefreshedToken, RefreshError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(RefreshedToken::new("fresh-token").with_expires_at(now() + 3600))
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn client(endpoint: &str, token_expires_at: u64) -> (OpenShellClient, Arc<AtomicU32>) {
    let calls = Arc::new(AtomicU32::new(0));
    let mut config = ClientConfig::new(endpoint);
    config.auth = Some(AuthConfig::Oidc {
        token: "stale-token".to_string(),
        expires_at: Some(token_expires_at),
        refresh: Some(Arc::new(CountingRefresher {
            calls: Arc::clone(&calls),
        })),
    });
    (OpenShellClient::connect(config).await.unwrap(), calls)
}

#[tokio::test]
async fn a_401_is_retried_once_after_a_refresh() {
    let (endpoint, seen) = start(Answer::FreshTokenOnly).await;
    let (client, refreshes) = client(&endpoint, now() + 3600).await;

    let reply = client.post_mcp(b"{}", "team").await.unwrap();

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(seen.requests.load(Ordering::SeqCst), 2);
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
    assert_eq!(
        *seen.authorization.lock().unwrap(),
        ["Bearer stale-token", "Bearer fresh-token"]
    );
    assert_eq!(*seen.workspace.lock().unwrap(), ["team", "team"]);
}

#[tokio::test]
async fn a_token_near_expiry_is_refreshed_before_sending() {
    let (endpoint, seen) = start(Answer::FreshTokenOnly).await;
    let (client, refreshes) = client(&endpoint, now()).await;

    let reply = client.post_mcp(b"{}", "default").await.unwrap();

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(seen.requests.load(Ordering::SeqCst), 1);
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn only_one_retry_and_only_after_a_401() {
    for (answer, requests) in [
        (StatusCode::UNAUTHORIZED, 2),
        (StatusCode::INTERNAL_SERVER_ERROR, 1),
        (StatusCode::BAD_GATEWAY, 1),
        (StatusCode::FORBIDDEN, 1),
    ] {
        let (endpoint, seen) = start(Answer::Always(answer)).await;
        let (client, _) = client(&endpoint, now() + 3600).await;

        let reply = client.post_mcp(b"{}", "default").await.unwrap();

        assert_eq!(reply.status, answer);
        assert_eq!(seen.requests.load(Ordering::SeqCst), requests, "{answer}");
    }
}
