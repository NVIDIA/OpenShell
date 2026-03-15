// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

use std::io::Write;
use std::process::Command;
use std::process::Stdio;
use std::sync::Mutex;
use std::time::Duration;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::port::{find_free_port, wait_for_port};
use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;

const INFERENCE_PROVIDER_NAME: &str = "e2e-host-inference";
const TEST_SERVER_IMAGE: &str = "python:3.13-alpine";
static INFERENCE_ROUTE_LOCK: Mutex<()> = Mutex::new(());

async fn run_cli(args: &[&str]) -> Result<String, String> {
    let mut cmd = openshell_cmd();
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd
        .output()
        .await
        .map_err(|e| format!("failed to spawn openshell {}: {e}", args.join(" ")))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");

    if !output.status.success() {
        return Err(format!(
            "openshell {} failed (exit {:?}):\n{combined}",
            args.join(" "),
            output.status.code()
        ));
    }

    Ok(combined)
}

struct DockerServer {
    port: u16,
    container_id: String,
}

impl DockerServer {
    async fn start(response_body: &str) -> Result<Self, String> {
        let port = find_free_port();
        let script = r#"from http.server import BaseHTTPRequestHandler, HTTPServer
import os

BODY = os.environ["RESPONSE_BODY"].encode()

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length:
            self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, format, *args):
        pass

HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
"#;

        let output = Command::new("docker")
            .args([
                "run",
                "--detach",
                "--rm",
                "-e",
                &format!("RESPONSE_BODY={response_body}"),
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

        wait_for_port("127.0.0.1", port, Duration::from_secs(30)).await?;

        Ok(Self {
            port,
            container_id: stdout,
        })
    }
}

impl Drop for DockerServer {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.container_id])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

async fn provider_exists(name: &str) -> bool {
    let mut cmd = openshell_cmd();
    cmd.arg("provider")
        .arg("get")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd.status().await.is_ok_and(|status| status.success())
}

async fn delete_provider(name: &str) {
    let mut cmd = openshell_cmd();
    cmd.arg("provider")
        .arg("delete")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let _ = cmd.status().await;
}

fn write_policy(port: u16) -> Result<NamedTempFile, String> {
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
  host_echo:
    name: host_echo
    endpoints:
      - host: host.openshell.internal
        port: {port}
        allowed_ips:
          - "172.0.0.0/8"
    binaries:
      - path: /usr/bin/curl
"#
    );
    file.write_all(policy.as_bytes())
        .map_err(|e| format!("write temp policy file: {e}"))?;
    file.flush()
        .map_err(|e| format!("flush temp policy file: {e}"))?;
    Ok(file)
}

#[tokio::test]
async fn sandbox_reaches_host_openshell_internal_via_host_gateway_alias() {
    let server = DockerServer::start(r#"{"message":"hello-from-host"}"#)
        .await
        .expect("start host echo server");
    let policy = write_policy(server.port).expect("write custom policy");
    let policy_path = policy
        .path()
        .to_str()
        .expect("temp policy path should be utf-8")
        .to_string();

    let guard = SandboxGuard::create(&[
        "--policy",
        &policy_path,
        "--",
        "curl",
        "--silent",
        "--show-error",
        "--max-time",
        "15",
        &format!("http://host.openshell.internal:{}/", server.port),
    ])
    .await
    .expect("sandbox create with host.openshell.internal echo request");

    assert!(
        guard
            .create_output
            .contains("\"message\":\"hello-from-host\""),
        "expected sandbox to receive host echo response:\n{}",
        guard.create_output
    );
}

#[tokio::test]
async fn sandbox_inference_local_routes_to_host_openshell_internal() {
    let _inference_lock = INFERENCE_ROUTE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let current_inference = run_cli(&["inference", "get"])
        .await
        .expect("read current inference config");
    if !current_inference.contains("Not configured") {
        eprintln!("Skipping test: existing inference config would make shared state unsafe");
        return;
    }

    let server = DockerServer::start(
        r#"{"id":"chatcmpl-test","object":"chat.completion","created":1,"model":"host-echo","choices":[{"index":0,"message":{"role":"assistant","content":"hello-from-host"},"finish_reason":"stop"}]}"#,
    )
    .await
    .expect("start host inference echo server");

    if provider_exists(INFERENCE_PROVIDER_NAME).await {
        delete_provider(INFERENCE_PROVIDER_NAME).await;
    }

    run_cli(&[
        "provider",
        "create",
        "--name",
        INFERENCE_PROVIDER_NAME,
        "--type",
        "openai",
        "--credential",
        "OPENAI_API_KEY=dummy",
        "--config",
        &format!(
            "OPENAI_BASE_URL=http://host.openshell.internal:{}/v1",
            server.port
        ),
    ])
    .await
    .expect("create host-backed OpenAI provider");

    run_cli(&[
        "inference",
        "set",
        "--provider",
        INFERENCE_PROVIDER_NAME,
        "--model",
        "host-echo-model",
        "--no-verify",
    ])
    .await
    .expect("point inference.local at host-backed provider");

    let guard = SandboxGuard::create(&[
        "--",
        "curl",
        "--silent",
        "--show-error",
        "--max-time",
        "15",
        "https://inference.local/v1/chat/completions",
        "--json",
        r#"{"messages":[{"role":"user","content":"hello"}]}"#,
    ])
    .await
    .expect("sandbox create with inference.local request");

    assert!(
        guard
            .create_output
            .contains("\"object\":\"chat.completion\""),
        "expected sandbox to receive inference response:\n{}",
        guard.create_output
    );
    assert!(
        guard.create_output.contains("hello-from-host"),
        "expected sandbox to receive echoed inference content:\n{}",
        guard.create_output
    );
}
