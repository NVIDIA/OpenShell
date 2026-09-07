// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

use std::io::Write;
use std::process::Stdio;
use std::sync::Mutex;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::{Builder as TempFileBuilder, NamedTempFile};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const INFERENCE_PROVIDER_NAME: &str = "e2e-host-inference";
const INFERENCE_PROVIDER_UNREACHABLE_NAME: &str = "e2e-host-inference-unreachable";
const BINDING_PROVIDER_A_NAME: &str = "e2e-static-endpoint-binding-provider-a";
const BINDING_PROVIDER_B_NAME: &str = "e2e-static-endpoint-binding-provider-b";
const BINDING_PROFILE_A_ID: &str = "e2e-static-endpoint-binding-a";
const BINDING_PROFILE_B_ID: &str = "e2e-static-endpoint-binding-b";
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

async fn wait_for_sandbox_logs(
    sandbox_name: &str,
    expected: impl Fn(&str) -> bool,
) -> Result<String, String> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);

    loop {
        let logs = run_cli(&[
            "logs",
            sandbox_name,
            "-n",
            "500",
            "--since",
            "2m",
            "--source",
            "sandbox",
        ])
        .await?;
        if expected(&logs) {
            return Ok(logs);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for expected sandbox logs:\n{logs}"
            ));
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

struct HostServer {
    port: u16,
    task: JoinHandle<()>,
}

impl HostServer {
    async fn start(response_body: &str) -> Result<Self, String> {
        Self::start_with_auth_check(response_body, None).await
    }

    async fn start_with_auth_check(
        response_body: &str,
        expected_authorization: Option<&str>,
    ) -> Result<Self, String> {
        let listener = TcpListener::bind(("0.0.0.0", 0))
            .await
            .map_err(|e| format!("bind host test server: {e}"))?;
        let port = listener
            .local_addr()
            .map_err(|e| format!("read host test server address: {e}"))?
            .port();
        let response_body = response_body.as_bytes().to_vec();
        let expected_authorization = expected_authorization.map(str::to_string);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let body = response_body.clone();
                let expected_authorization = expected_authorization.clone();
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

                    let body = expected_authorization.map_or(body, |expected| {
                        let request = String::from_utf8_lossy(&request);
                        format!(
                            r#"{{"authorized":{}}}"#,
                            request.lines().any(|line| {
                                line.eq_ignore_ascii_case(&format!("Authorization: {expected}"))
                            })
                        )
                        .into_bytes()
                    });
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

fn write_binding_profile(
    id: &str,
    display_name: &str,
    env_var: &str,
    host: &str,
    port: u16,
) -> Result<NamedTempFile, String> {
    let mut file = TempFileBuilder::new()
        .suffix(".yaml")
        .tempfile()
        .map_err(|e| format!("create provider profile: {e}"))?;
    let profile = format!(
        r#"id: {id}
display_name: {display_name}
category: other
credentials:
  - name: bound_token
    env_vars: [{env_var}]
    required: true
    auth_style: bearer
    header_name: authorization
endpoints:
  - host: {host}
    port: {port}
    path: /allowed/**
    protocol: rest
    access: full
    enforcement: enforce
binaries: [/usr/bin/curl]
"#
    );
    file.write_all(profile.as_bytes())
        .map_err(|e| format!("write provider profile: {e}"))?;
    file.flush()
        .map_err(|e| format!("flush provider profile: {e}"))?;
    Ok(file)
}

fn write_binding_policy(port: u16) -> Result<NamedTempFile, String> {
    let mut file = NamedTempFile::new().map_err(|e| format!("create binding policy: {e}"))?;
    let policy = format!(
        r#"version: 1

filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox

network_policies:
  binding_test:
    name: binding_test
    endpoints:
      - host: host.openshell.internal
        port: {port}
        path: /**
        protocol: rest
        access: full
        enforcement: enforce
      - host: host.docker.internal
        port: {port}
        path: /**
        protocol: rest
        access: full
        enforcement: enforce
    binaries:
      - path: /usr/bin/curl
"#
    );
    file.write_all(policy.as_bytes())
        .map_err(|e| format!("write binding policy: {e}"))?;
    file.flush()
        .map_err(|e| format!("flush binding policy: {e}"))?;
    Ok(file)
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

async fn delete_provider_profile(id: &str) {
    let mut cmd = openshell_cmd();
    cmd.arg("provider")
        .arg("profile")
        .arg("delete")
        .arg(id)
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
async fn static_provider_credentials_are_bound_to_profile_endpoints() {
    let server = HostServer::start_with_auth_check("", Some("Bearer e2e-bound-secret"))
        .await
        .expect("start credential echo server");
    let profile_a = write_binding_profile(
        BINDING_PROFILE_A_ID,
        "E2E static endpoint binding A",
        "BOUND_TOKEN_A",
        "host.openshell.internal",
        server.port,
    )
    .expect("write provider A binding profile");
    let profile_b = write_binding_profile(
        BINDING_PROFILE_B_ID,
        "E2E static endpoint binding B",
        "BOUND_TOKEN_B",
        "host.docker.internal",
        server.port,
    )
    .expect("write provider B binding profile");
    let policy = write_binding_policy(server.port).expect("write binding policy");
    let profile_a_path = profile_a.path().to_string_lossy().into_owned();
    let profile_b_path = profile_b.path().to_string_lossy().into_owned();
    let policy_path = policy.path().to_string_lossy().into_owned();

    delete_provider(BINDING_PROVIDER_A_NAME).await;
    delete_provider(BINDING_PROVIDER_B_NAME).await;
    delete_provider_profile(BINDING_PROFILE_A_ID).await;
    delete_provider_profile(BINDING_PROFILE_B_ID).await;
    run_cli(&["provider", "profile", "import", "--file", &profile_a_path])
        .await
        .expect("import provider A endpoint-binding profile");
    run_cli(&["provider", "profile", "import", "--file", &profile_b_path])
        .await
        .expect("import provider B endpoint-binding profile");
    run_cli(&[
        "provider",
        "create",
        "--name",
        BINDING_PROVIDER_A_NAME,
        "--type",
        BINDING_PROFILE_A_ID,
        "--credential",
        "BOUND_TOKEN_A=e2e-bound-secret",
    ])
    .await
    .expect("create endpoint-bound provider A");
    run_cli(&[
        "provider",
        "create",
        "--name",
        BINDING_PROVIDER_B_NAME,
        "--type",
        BINDING_PROFILE_B_ID,
        "--credential",
        "BOUND_TOKEN_B=e2e-provider-b-secret",
    ])
    .await
    .expect("create endpoint-bound provider B");

    let command = format!(
        r#"allowed=$(curl --silent --show-error --max-time 15 -H "Authorization: Bearer $BOUND_TOKEN_A" http://host.openshell.internal:{}/allowed/check); host_denied=$(curl --silent --show-error --max-time 15 -o /tmp/host-denied-body -w "%{{http_code}}" -H "Authorization: Bearer $BOUND_TOKEN_A" http://host.docker.internal:{}/allowed/check); path_denied=$(curl --silent --show-error --max-time 15 -o /tmp/path-denied-body -w "%{{http_code}}" -H "Authorization: Bearer $BOUND_TOKEN_A" http://host.openshell.internal:{}/other/check); printf 'ALLOWED=%s HOST_DENIED=%s PATH_DENIED=%s\n' "$allowed" "$host_denied" "$path_denied""#,
        server.port, server.port, server.port
    );
    let mut guard = SandboxGuard::create(&[
        "--policy",
        &policy_path,
        "--provider",
        BINDING_PROVIDER_A_NAME,
        "--provider",
        BINDING_PROVIDER_B_NAME,
        "--no-auto-providers",
        "--",
        "sh",
        "-c",
        &command,
    ])
    .await
    .expect("run endpoint-binding requests");

    let logs = wait_for_sandbox_logs(&guard.name, |logs| {
        logs.contains("openshell.provider_credential.endpoint_mismatch")
            && logs.contains("credential_endpoint_mismatch")
    })
    .await
    .expect("fetch endpoint mismatch logs");
    assert!(
        guard
            .create_output
            .contains(r#"ALLOWED={"authorized":true}"#),
        "credential should resolve at the bound endpoint:\n{}\nlogs:\n{logs}",
        guard.create_output,
    );
    assert!(
        guard.create_output.contains("HOST_DENIED=403"),
        "same placeholder must be denied at an unbound host:\n{}",
        guard.create_output
    );
    assert!(
        guard.create_output.contains("PATH_DENIED=403"),
        "same placeholder must be denied at an unbound path on its bound host:\n{}",
        guard.create_output
    );

    assert!(
        logs.contains("openshell.provider_credential.endpoint_mismatch")
            && logs.contains("credential_endpoint_mismatch"),
        "OCSF logs should explain the endpoint-binding denial without secret material:\n{logs}"
    );
    assert!(
        !logs.contains("e2e-bound-secret")
            && !logs.contains("e2e-provider-b-secret")
            && !logs.contains("BOUND_TOKEN_A")
            && !logs.contains("BOUND_TOKEN_B"),
        "OCSF logs must not contain credential values or environment keys:\n{logs}"
    );

    guard.cleanup().await;
    delete_provider(BINDING_PROVIDER_A_NAME).await;
    delete_provider(BINDING_PROVIDER_B_NAME).await;
    delete_provider_profile(BINDING_PROFILE_A_ID).await;
    delete_provider_profile(BINDING_PROFILE_B_ID).await;
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
