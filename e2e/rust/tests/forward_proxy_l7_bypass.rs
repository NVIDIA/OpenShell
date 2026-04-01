// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Regression tests: the forward proxy path must evaluate L7 rules for
//! endpoints that have them configured.  Allowed requests (e.g. GET on a
//! read-only endpoint) should succeed; denied requests (e.g. POST) should
//! receive 403.

#![cfg(feature = "e2e")]

use std::io::Write;
use std::process::Command;
use std::time::Duration;

use openshell_e2e::harness::port::find_free_port;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;
use tokio::time::{interval, timeout};

const TEST_SERVER_IMAGE: &str = "public.ecr.aws/docker/library/python:3.13-alpine";

struct DockerServer {
    port: u16,
    container_id: String,
}

impl DockerServer {
    async fn start() -> Result<Self, String> {
        let port = find_free_port();
        let script = r#"from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')
    def do_DELETE(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')
    def log_message(self, format, *args):
        pass

HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
"#;

        let output = Command::new("docker")
            .args([
                "run",
                "--detach",
                "--rm",
                "-p",
                &format!("{port}:8000"),
                TEST_SERVER_IMAGE,
                "python3",
                "-c",
                script,
            ])
            .output()
            .map_err(|e| format!("start docker test server: {e}"))?;

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            return Err(format!(
                "docker run failed (exit {:?}):\n{stderr}",
                output.status.code()
            ));
        }

        let server = Self {
            port,
            container_id: stdout,
        };
        server.wait_until_ready().await?;
        Ok(server)
    }

    async fn wait_until_ready(&self) -> Result<(), String> {
        let container_id = self.container_id.clone();
        timeout(Duration::from_secs(60), async move {
            let mut tick = interval(Duration::from_millis(500));
            loop {
                tick.tick().await;
                let output = Command::new("docker")
                    .args([
                        "exec",
                        &container_id,
                        "python3",
                        "-c",
                        "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000', timeout=1).read()",
                    ])
                    .output()
                    .ok();
                if output.is_some_and(|o| o.status.success()) {
                    return;
                }
            }
        })
        .await
        .map_err(|_| "docker test server did not become ready within 60s".to_string())
    }
}

impl Drop for DockerServer {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.container_id])
            .output();
    }
}

fn write_policy_with_l7_rules(port: u16) -> Result<NamedTempFile, String> {
    let mut file = NamedTempFile::new().map_err(|e| format!("create temp policy file: {e}"))?;
    let policy = format!(
        r#"version: 1

filesystem_policy:
  include_workdir: true
  read_only:
    - /usr
    - /lib
    - /proc
    - /dev/urandom
    - /app
    - /etc
    - /var/log
  read_write:
    - /sandbox
    - /tmp
    - /dev/null

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox

network_policies:
  test_l7:
    name: test_l7
    endpoints:
      - host: host.openshell.internal
        port: {port}
        protocol: rest
        enforcement: enforce
        allowed_ips:
          - "172.0.0.0/8"
        rules:
          - allow:
              method: GET
              path: /allowed
    binaries:
      - path: /usr/bin/curl
      - path: /usr/bin/python*
      - path: /usr/local/bin/python*
      - path: /sandbox/.uv/python/*/bin/python*
"#
    );
    file.write_all(policy.as_bytes())
        .map_err(|e| format!("write temp policy file: {e}"))?;
    file.flush()
        .map_err(|e| format!("flush temp policy file: {e}"))?;
    Ok(file)
}

/// GET /allowed should succeed — the L7 policy explicitly allows it.
#[tokio::test]
async fn forward_proxy_allows_l7_permitted_request() {
    let server = DockerServer::start()
        .await
        .expect("start docker test server");
    let policy =
        write_policy_with_l7_rules(server.port)
            .expect("write custom policy");
    let policy_path = policy
        .path()
        .to_str()
        .expect("temp policy path should be utf-8")
        .to_string();

    let script = format!(
        r#"
import urllib.request, urllib.error, json, sys
url = "http://host.openshell.internal:{port}/allowed"
try:
    resp = urllib.request.urlopen(url, timeout=15)
    print(json.dumps({{"status": resp.status, "error": None}}))
except urllib.error.HTTPError as e:
    print(json.dumps({{"status": e.code, "error": str(e)}}))
except Exception as e:
    print(json.dumps({{"status": -1, "error": str(e)}}))
"#,
        port = server.port,
    );

    let guard = SandboxGuard::create(&[
        "--policy",
        &policy_path,
        "--",
        "python3",
        "-c",
        &script,
    ])
    .await
    .expect("sandbox create");

    // L7 policy allows GET /allowed — should succeed.
    assert!(
        guard.create_output.contains("\"status\": 200"),
        "expected 200 for L7-allowed GET, got:\n{}",
        guard.create_output
    );
}

/// POST /allowed should be denied — the L7 policy only allows GET.
#[tokio::test]
async fn forward_proxy_denies_l7_blocked_request() {
    let server = DockerServer::start()
        .await
        .expect("start docker test server");
    let policy =
        write_policy_with_l7_rules(server.port)
            .expect("write custom policy");
    let policy_path = policy
        .path()
        .to_str()
        .expect("temp policy path should be utf-8")
        .to_string();

    let script = format!(
        r#"
import urllib.request, urllib.error, json, sys
url = "http://host.openshell.internal:{port}/allowed"
req = urllib.request.Request(url, data=b"test", method="POST")
try:
    resp = urllib.request.urlopen(req, timeout=15)
    print(json.dumps({{"status": resp.status, "error": None}}))
except urllib.error.HTTPError as e:
    print(json.dumps({{"status": e.code, "error": str(e)}}))
except Exception as e:
    print(json.dumps({{"status": -1, "error": str(e)}}))
"#,
        port = server.port,
    );

    let guard = SandboxGuard::create(&[
        "--policy",
        &policy_path,
        "--",
        "python3",
        "-c",
        &script,
    ])
    .await
    .expect("sandbox create");

    // L7 policy denies POST — should return 403.
    assert!(
        guard.create_output.contains("\"status\": 403"),
        "expected 403 for L7-denied POST, got:\n{}",
        guard.create_output
    );
}
