// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

use std::io::Write;
use std::process::Stdio;
use std::sync::Mutex;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const INFERENCE_PROVIDER_NAME: &str = "e2e-host-inference";
const INFERENCE_PROVIDER_UNREACHABLE_NAME: &str = "e2e-host-inference-unreachable";
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

struct HostServer {
    port: u16,
    task: JoinHandle<()>,
}

impl HostServer {
    async fn start(response_body: &str) -> Result<Self, String> {
        let listener = TcpListener::bind(("0.0.0.0", 0))
            .await
            .map_err(|e| format!("bind host test server: {e}"))?;
        let port = listener
            .local_addr()
            .map_err(|e| format!("read host test server address: {e}"))?
            .port();
        let response_body = response_body.as_bytes().to_vec();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let body = response_body.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buf = [0_u8; 1024];
                    loop {
                        let Ok(read) = stream.read(&mut buf).await else {
                            return;
                        };
                        if read == 0 {
                            return;
                        }
                        request.extend_from_slice(&buf[..read]);
                        if request.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }

                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    if stream.write_all(response.as_bytes()).await.is_err() {
                        return;
                    }
                    let _ = stream.write_all(&body).await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        Ok(Self { port, task })
    }
}

impl Drop for HostServer {
    fn drop(&mut self) {
        self.task.abort();
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

async fn create_openai_provider(name: &str, base_url: &str) -> Result<String, String> {
    run_cli(&[
        "provider",
        "create",
        "--name",
        name,
        "--type",
        "openai",
        "--credential",
        "OPENAI_API_KEY=dummy",
        "--config",
        &format!("OPENAI_BASE_URL={base_url}"),
    ])
    .await
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
          - "10.0.0.0/8"
          - "172.0.0.0/8"
          - "192.168.0.0/16"
          - "fc00::/7"
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
    let server = HostServer::start(r#"{"message":"hello-from-host"}"#)
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

    let server = HostServer::start(
        r#"{"id":"chatcmpl-test","object":"chat.completion","created":1,"model":"host-echo","choices":[{"index":0,"message":{"role":"assistant","content":"hello-from-host"},"finish_reason":"stop"}]}"#,
    )
    .await
    .expect("start host inference echo server");

    if provider_exists(INFERENCE_PROVIDER_NAME).await {
        delete_provider(INFERENCE_PROVIDER_NAME).await;
    }

    create_openai_provider(
        INFERENCE_PROVIDER_NAME,
        &format!("http://host.openshell.internal:{}/v1", server.port),
    )
    .await
    .expect("create host-backed OpenAI provider");

    let inference_output = run_cli(&[
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

    assert!(
        !inference_output.contains("Validated Endpoints:"),
        "did not expect local CLI verification for host-only alias:\n{inference_output}"
    );

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

#[tokio::test]
async fn inference_set_supports_no_verify_for_unreachable_endpoint() {
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

    if provider_exists(INFERENCE_PROVIDER_UNREACHABLE_NAME).await {
        delete_provider(INFERENCE_PROVIDER_UNREACHABLE_NAME).await;
    }

    create_openai_provider(
        INFERENCE_PROVIDER_UNREACHABLE_NAME,
        "http://host.openshell.internal:9/v1",
    )
    .await
    .expect("create unreachable OpenAI provider");

    let verify_err = run_cli(&[
        "inference",
        "set",
        "--provider",
        INFERENCE_PROVIDER_UNREACHABLE_NAME,
        "--model",
        "host-echo-model",
    ])
    .await
    .expect_err("default verification should fail for unreachable endpoint");

    assert!(
        verify_err.contains("failed to verify inference endpoint"),
        "expected verification failure output:\n{verify_err}"
    );
    let normalized_verify_err: String = verify_err
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '│')
        .collect();
    assert!(
        normalized_verify_err.contains("--no-verify"),
        "expected retry hint in failure output:\n{verify_err}"
    );

    let no_verify_output = run_cli(&[
        "inference",
        "set",
        "--provider",
        INFERENCE_PROVIDER_UNREACHABLE_NAME,
        "--model",
        "host-echo-model",
        "--no-verify",
    ])
    .await
    .expect("no-verify should bypass validation");

    assert!(
        !no_verify_output.contains("Validated Endpoints:"),
        "did not expect validation output when bypassing verification:\n{no_verify_output}"
    );
}
