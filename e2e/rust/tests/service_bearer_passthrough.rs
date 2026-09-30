// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-docker")]

//! Verifies application bearer authorization behavior through an exposed
//! `OpenShell` service.

use std::net::Ipv4Addr;
use std::process::Stdio;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Empty};
use hyper::client::conn::http1;
use hyper::{Request, StatusCode, header};
use hyper_util::rt::TokioIo;
use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::sandbox::{E2E_WORKLOAD_IMAGE, SandboxGuard};
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use url::Position;

const SERVICE_PORT: &str = "4500";
const BEARER_TOKEN: &str = "Bearer openshell-e2e-application-token";
const READY_TIMEOUT: Duration = Duration::from_secs(60);
const HEADER_ECHO_SERVER: &str = r#"
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.headers.get("Authorization", "").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass

ThreadingHTTPServer(("127.0.0.1", 4500), Handler).serve_forever()
"#;

async fn run_cli(args: &[&str]) -> Result<std::process::Output, String> {
    let mut command = openshell_cmd();
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
        .output()
        .await
        .map_err(|error| format!("failed to run openshell: {error}"))
}

async fn request_service(url: &str, authorization: &str) -> Result<(StatusCode, String), String> {
    let url = url::Url::parse(url).map_err(|error| format!("invalid service URL: {error}"))?;
    if url.scheme() != "http" {
        return Err(format!(
            "test requires the loopback plaintext service listener, got {}",
            url.scheme()
        ));
    }
    url.host_str()
        .ok_or_else(|| "service URL omitted its host".to_string())?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "service URL omitted its port".to_string())?;
    // The service hostname is a virtual routing authority. Dial the loopback
    // gateway directly so the test does not depend on the host resolver
    // recognizing arbitrary subdomains of `.localhost`.
    let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .map_err(|error| format!("connect to loopback service gateway: {error}"))?;
    let _ = stream.set_nodelay(true);
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|error| format!("start HTTP connection: {error}"))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let authority = &url[Position::BeforeHost..Position::AfterPort];
    let path = url.query().map_or_else(
        || url.path().to_string(),
        |query| format!("{}?{query}", url.path()),
    );
    let request = Request::builder()
        .uri(path)
        .header(header::HOST, authority)
        .header(header::AUTHORIZATION, authorization)
        .body(Empty::<Bytes>::new())
        .map_err(|error| format!("build service request: {error}"))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|error| format!("send service request: {error}"))?;
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|error| format!("read service response: {error}"))?
        .to_bytes();
    let body = String::from_utf8(body.to_vec())
        .map_err(|error| format!("service returned non-UTF-8 data: {error}"))?;
    Ok((status, body))
}

async fn wait_for_authorization(url: &str, expected: &str) -> Result<(), String> {
    let mut last_observation = "no request attempted".to_string();
    let result = timeout(READY_TIMEOUT, async {
        loop {
            match request_service(url, BEARER_TOKEN).await {
                Ok((StatusCode::OK, body)) if body == expected => return Ok(()),
                Ok((StatusCode::OK, body)) => {
                    return Err(format!(
                        "service received unexpected Authorization value: {body:?}"
                    ));
                }
                Ok((status, body))
                    if matches!(
                        status,
                        StatusCode::BAD_GATEWAY
                            | StatusCode::PRECONDITION_FAILED
                            | StatusCode::SERVICE_UNAVAILABLE
                    ) =>
                {
                    last_observation =
                        format!("service returned retryable status {status} with body {body:?}");
                    sleep(Duration::from_millis(250)).await;
                }
                Err(error) => {
                    last_observation = error;
                    sleep(Duration::from_millis(250)).await;
                }
                Ok((status, body)) => {
                    return Err(format!(
                        "service returned unexpected status {status} with body {body:?}"
                    ));
                }
            }
        }
    })
    .await;

    match result {
        Ok(result) => result,
        Err(_) => Err(format!(
            "timed out waiting for the exposed service; last observation: {last_observation}"
        )),
    }
}

#[tokio::test]
async fn service_bearer_passthrough_preserves_authorization_header() {
    let sandbox_name = format!("service-auth-{}", std::process::id());
    let create = run_cli(&[
        "sandbox",
        "create",
        "--name",
        &sandbox_name,
        "--from",
        E2E_WORKLOAD_IMAGE,
        "--expose",
        SERVICE_PORT,
        "--output",
        "json",
        "--detach",
        "--no-tty",
        "--",
        "python3",
        "-c",
        HEADER_ECHO_SERVER,
    ])
    .await
    .expect("run sandbox create");
    assert!(
        create.status.success(),
        "sandbox create failed with exit {:?}: {}",
        create.status.code(),
        String::from_utf8_lossy(&create.stderr)
    );
    let mut sandbox = SandboxGuard::manage_existing(sandbox_name.clone());

    let created: Value = serde_json::from_slice(&create.stdout).expect("parse sandbox create JSON");
    let service_url = created
        .get("service_urls")
        .and_then(|urls| urls.get(""))
        .and_then(Value::as_str)
        .expect("unnamed service URL in create response");

    wait_for_authorization(service_url, "")
        .await
        .expect("default mode should strip Authorization");

    let expose = run_cli(&[
        "service",
        "expose",
        &sandbox_name,
        SERVICE_PORT,
        "--authorization-mode",
        "bearer-passthrough",
    ])
    .await
    .expect("run service re-expose");
    assert!(
        expose.status.success(),
        "service re-expose failed with exit {:?}: {}",
        expose.status.code(),
        String::from_utf8_lossy(&expose.stderr)
    );

    wait_for_authorization(service_url, BEARER_TOKEN)
        .await
        .expect("passthrough mode should preserve Authorization");

    sandbox.cleanup().await;
}
