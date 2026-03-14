// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Stdio;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;

const INFERENCE_PROVIDER_NAME: &str = "e2e-host-inference";
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

fn spawn_server(
    response_body: fn(&str) -> String,
) -> Result<(u16, thread::JoinHandle<()>), String> {
    let listener = TcpListener::bind("0.0.0.0:0")
        .map_err(|e| format!("bind echo server on 0.0.0.0:0: {e}"))?;
    listener
        .set_nonblocking(false)
        .map_err(|e| format!("configure echo server blocking mode: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("read echo server address: {e}"))?
        .port();

    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept echo request");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("set read timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .expect("set write timeout");

        let mut request = Vec::new();
        let mut buf = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buf).expect("read echo request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buf[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }

        let request_text = String::from_utf8_lossy(&request);
        let body = response_body(&request_text);
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .expect("write echo response");
        stream.flush().expect("flush echo response");
    });

    Ok((port, handle))
}

fn spawn_echo_server() -> Result<(u16, thread::JoinHandle<()>), String> {
    spawn_server(|request_text| {
        let request_line = request_text.lines().next().unwrap_or_default();
        format!(r#"{{"message":"hello-from-host","request_line":"{request_line}"}}"#)
    })
}

fn spawn_inference_server() -> Result<(u16, thread::JoinHandle<()>), String> {
    spawn_server(|_| {
        r#"{"id":"chatcmpl-test","object":"chat.completion","created":1,"model":"host-echo","choices":[{"index":0,"message":{"role":"assistant","content":"hello-from-host"},"finish_reason":"stop"}]}"#.to_string()
    })
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
    let (port, server) = spawn_echo_server().expect("start host echo server");
    let policy = write_policy(port).expect("write custom policy");
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
        &format!("http://host.openshell.internal:{port}/"),
    ])
    .await
    .expect("sandbox create with host.openshell.internal echo request");

    server
        .join()
        .expect("echo server thread should exit cleanly");

    assert!(
        guard
            .create_output
            .contains("\"message\":\"hello-from-host\""),
        "expected sandbox to receive host echo response:\n{}",
        guard.create_output
    );
    assert!(
        guard
            .create_output
            .contains("\"request_line\":\"GET / HTTP/1.1\""),
        "expected host echo server to receive sandbox HTTP request:\n{}",
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

    let (port, server) = spawn_inference_server().expect("start host inference echo server");

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
        &format!("OPENAI_BASE_URL=http://host.openshell.internal:{port}/v1"),
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
        "https://inference.local/v1/chat/completions",
        "--json",
        r#"{"messages":[{"role":"user","content":"hello"}]}"#,
    ])
    .await
    .expect("sandbox create with inference.local request");

    server
        .join()
        .expect("inference echo server thread should exit cleanly");

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
