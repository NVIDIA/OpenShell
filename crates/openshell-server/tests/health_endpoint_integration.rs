// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use openshell_server::{Store, health_router};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

async fn start_health_server(
    store: Arc<Store>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral health test listener");
    let addr = listener
        .local_addr()
        .expect("resolve local address for health test listener");

    let router = health_router(store);
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, router.into_make_service()).await;
    });

    (addr, server)
}

async fn http_get_json(addr: std::net::SocketAddr, path: &str) -> (StatusCode, Value) {
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect test HTTP client");
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .handshake(TokioIo::new(stream))
        .await
        .expect("handshake HTTP/1 test client");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method("GET")
        .uri(format!("http://{addr}{path}"))
        .body(Empty::<Bytes>::new())
        .expect("build HTTP request");
    let resp = sender.send_request(req).await.expect("send HTTP request");
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect response body")
        .to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("response body must be valid JSON")
    };
    (status, body)
}

#[tokio::test]
async fn readyz_reports_healthy_when_database_is_reachable() {
    let store = Arc::new(
        Store::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite store for health integration test"),
    );
    let (addr, server) = start_health_server(store.clone()).await;

    // `health_router` does not block on the first poll, so /readyz starts in
    // `Initializing → 503` until the background monitor publishes the first
    // healthy state (sub-millisecond for in-memory SQLite, but still a race).
    let (status, body) = wait_for_status(addr, StatusCode::OK, Duration::from_secs(2))
        .await
        .expect("/readyz did not become healthy within 2s");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "healthy");
    assert_eq!(body["checks"]["database"]["status"], "healthy");

    server.abort();
}

#[cfg(feature = "test-support")]
#[tokio::test]
async fn readyz_reports_database_health_transition_after_close() {
    let store = Arc::new(
        Store::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite store for health integration test"),
    );
    let (addr, server) = start_health_server(store.clone()).await;

    let (status, body) = wait_for_status(addr, StatusCode::OK, Duration::from_secs(2))
        .await
        .expect("/readyz did not become healthy within 2s");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "healthy");
    assert_eq!(body["checks"]["database"]["status"], "healthy");

    store.close().await;

    // The handler reads the cached state published by the background
    // readiness monitor, so the transition to Unhealthy can only show up
    // after the monitor's next tick. With the default 5s interval the
    // outage surfaces within ~5s; poll with a generous deadline so the
    // assertion never races the polling cycle.
    let (status, body) = wait_for_status(
        addr,
        StatusCode::SERVICE_UNAVAILABLE,
        Duration::from_secs(10),
    )
    .await
    .expect("/readyz did not transition to 503 after store.close() within 10s");
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["status"], "unhealthy");
    assert_eq!(body["checks"]["database"]["status"], "unhealthy");
    assert_eq!(body["checks"]["database"]["error"], "database unavailable");

    server.abort();
}

/// Poll `/readyz` until it returns `expected`, or give up after `timeout`.
///
/// Used to bridge the gap between `health_router`'s non-blocking startup
/// and the background monitor publishing its first probe outcome.
async fn wait_for_status(
    addr: std::net::SocketAddr,
    expected: StatusCode,
    timeout: Duration,
) -> Option<(StatusCode, Value)> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let observation = http_get_json(addr, "/readyz").await;
        if observation.0 == expected {
            return Some(observation);
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
