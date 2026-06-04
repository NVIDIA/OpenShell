// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes")]

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::rt::TokioIo;
use serde_json::Value;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

fn health_port_from_env() -> u16 {
    let raw = std::env::var("OPENSHELL_E2E_HEALTH_PORT").unwrap_or_else(|_| {
        panic!(
            "OPENSHELL_E2E_HEALTH_PORT is not set. The Kubernetes e2e wrapper \
             (e2e/with-kube-gateway.sh) must export this variable so the \
             /readyz test can reach the gateway health listener."
        )
    });
    raw.parse::<u16>().unwrap_or_else(|err| {
        panic!("OPENSHELL_E2E_HEALTH_PORT=\"{raw}\" is not a valid u16 port: {err}")
    })
}

async fn http_get_json(port: u16, path: &str) -> Result<(u16, Value), String> {
    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|err| format!("connect health endpoint :{port}: {err}"))?;
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .handshake(TokioIo::new(stream))
        .await
        .map_err(|err| format!("handshake health HTTP/1 client :{port}: {err}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method("GET")
        .uri(format!("http://127.0.0.1:{port}{path}"))
        .body(Empty::<Bytes>::new())
        .map_err(|err| format!("build health request {path}: {err}"))?;
    let resp = sender
        .send_request(req)
        .await
        .map_err(|err| format!("send health request {path} to :{port}: {err}"))?;
    let status_code = resp.status().as_u16();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|err| format!("read health response body {path}: {err}"))?
        .to_bytes();
    let json = serde_json::from_slice::<Value>(&bytes)
        .map_err(|err| format!("health endpoint {path} did not return valid JSON: {err}"))?;

    Ok((status_code, json))
}

#[tokio::test]
async fn readyz_reports_healthy_database_check() {
    let port = health_port_from_env();

    let deadline = Instant::now() + Duration::from_secs(20);
    let timeout_detail = loop {
        let observation = match http_get_json(port, "/readyz").await {
            Ok((status, payload)) => {
                let ready = status == 200
                    && payload["status"] == "healthy"
                    && payload["checks"]["database"]["status"] == "healthy";
                if ready {
                    assert!(
                        payload["checks"]["database"]["latency_ms"].is_number(),
                        "readyz payload should include checks.database.latency_ms: {payload}"
                    );
                    assert!(
                        payload["checks"]["database"]["error"].is_null(),
                        "readyz payload should not include checks.database.error when healthy: {payload}"
                    );
                    return;
                }
                format!("unexpected /readyz response status={status} payload={payload}")
            }
            Err(err) => err,
        };

        if Instant::now() >= deadline {
            break observation;
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    };
    panic!("timed out waiting for /readyz healthy response after 20s: {timeout_detail}");
}
