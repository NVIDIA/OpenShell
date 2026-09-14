// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-podman")]

//! Podman E2E coverage for refresh-managed workload credential handles.
//!
//! A fake issuer invalidates every prior access token. One long-running shell
//! retains its original environment while the gateway rotates the provider 12
//! times. The shell must continue reaching the resource with the newest token,
//! and explicit refresh reconfiguration must revoke its old handle.

use std::io::Write;
use std::process::Stdio;
use std::time::Duration;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::container::HostSupportContainer;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::{Builder as TempFileBuilder, NamedTempFile};

const PROVIDER_NAME: &str = "e2e-stable-refresh-handle";
const PROFILE_ID: &str = "e2e-stable-refresh-handle";
const TOKEN_ENV: &str = "REFRESH_E2E_ACCESS_TOKEN";
const READY_MARKER: &str = "stable-refresh-parent-ready";

const FIXTURE_SCRIPT: &str = r#"
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

current_token = "bootstrap-token"
generation = 0

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        global current_token, generation
        if self.path != "/token":
            self.send_response(404)
            self.end_headers()
            return
        generation += 1
        current_token = f"access-token-{generation}"
        body = json.dumps({
            "access_token": current_token,
            "expires_in": 300,
            "token_type": "Bearer",
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            self.send_response(204)
        elif self.path == "/probe" and self.headers.get("Authorization") == f"Bearer {current_token}":
            self.send_response(204)
        else:
            self.send_response(401)
        self.end_headers()

    def log_message(self, *_args):
        pass

ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
"#;

async fn run_cli(args: &[&str]) -> Result<String, String> {
    run_cli_with_env(args, &[]).await
}

async fn run_cli_with_env(args: &[&str], env: &[(&str, &str)]) -> Result<String, String> {
    let mut command = openshell_cmd();
    command
        .args(args)
        .envs(env.iter().copied())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = command
        .output()
        .await
        .map_err(|error| format!("run openshell command: {error}"))?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success() {
        return Err(format!(
            "openshell command failed (exit {:?}):\n{combined}",
            output.status.code()
        ));
    }
    Ok(combined)
}

async fn delete_provider_resources() {
    let _ = run_cli(&["provider", "delete", PROVIDER_NAME]).await;
    let _ = run_cli(&["provider", "profile", "delete", PROFILE_ID]).await;
}

fn write_profile(resource_port: u16, token_port: u16) -> Result<NamedTempFile, String> {
    let mut file = TempFileBuilder::new()
        .suffix(".yaml")
        .tempfile()
        .map_err(|error| format!("create profile: {error}"))?;
    let profile = format!(
        r#"id: {PROFILE_ID}
display_name: Stable refresh handle E2E
category: other
credentials:
  - name: access_token
    env_vars: [{TOKEN_ENV}]
    required: true
    auth_style: bearer
    header_name: authorization
    refresh:
      strategy: oauth2_client_credentials
      token_url: http://127.0.0.1:{token_port}/token
      refresh_before_seconds: 30
      max_lifetime_seconds: 300
      material:
        - name: client_id
          required: true
        - name: client_secret
          required: true
          secret: true
endpoints:
  - host: host.openshell.internal
    port: {resource_port}
    path: /probe
    protocol: rest
    access: full
    enforcement: enforce
    allowed_ips:
      - 10.0.0.0/8
      - 169.254.0.0/16
      - 172.0.0.0/8
      - 192.168.0.0/16
binaries:
  - /usr/bin/curl
"#
    );
    file.write_all(profile.as_bytes())
        .map_err(|error| format!("write profile: {error}"))?;
    file.flush()
        .map_err(|error| format!("flush profile: {error}"))?;
    Ok(file)
}

fn write_policy(resource_port: u16) -> Result<NamedTempFile, String> {
    let mut file = TempFileBuilder::new()
        .suffix(".yaml")
        .tempfile()
        .map_err(|error| format!("create policy: {error}"))?;
    let policy = format!(
        r#"version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /etc, /dev/urandom]
  read_write: [/sandbox, /tmp, /dev/null]
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_policies:
  refresh_probe:
    name: refresh_probe
    endpoints:
      - host: host.openshell.internal
        port: {resource_port}
        path: /probe
        protocol: rest
        access: full
        enforcement: enforce
        allowed_ips:
          - 10.0.0.0/8
          - 169.254.0.0/16
          - 172.0.0.0/8
          - 192.168.0.0/16
    binaries:
      - path: /usr/bin/curl
"#
    );
    file.write_all(policy.as_bytes())
        .map_err(|error| format!("write policy: {error}"))?;
    file.flush()
        .map_err(|error| format!("flush policy: {error}"))?;
    Ok(file)
}

async fn configure_refresh(profile: &NamedTempFile) -> Result<(), String> {
    let profile_path = profile.path().to_string_lossy().into_owned();
    run_cli(&["provider", "profile", "import", "--file", &profile_path]).await?;
    run_cli_with_env(
        &[
            "provider",
            "create",
            "--name",
            PROVIDER_NAME,
            "--type",
            PROFILE_ID,
            "--credential",
            TOKEN_ENV,
        ],
        &[(TOKEN_ENV, "bootstrap-token")],
    )
    .await?;
    reconfigure_refresh().await
}

async fn reconfigure_refresh() -> Result<(), String> {
    run_cli_with_env(
        &[
            "provider",
            "refresh",
            "configure",
            PROVIDER_NAME,
            "--credential-key",
            TOKEN_ENV,
            "--strategy",
            "oauth2-client-credentials",
            "--material",
            "client_id=e2e-client",
            "--secret-material-env",
            "client_secret=REFRESH_E2E_CLIENT_SECRET",
        ],
        &[("REFRESH_E2E_CLIENT_SECRET", "e2e-client-secret")],
    )
    .await
    .map(|_| ())
}

async fn rotate() -> Result<(), String> {
    run_cli(&[
        "provider",
        "refresh",
        "rotate",
        PROVIDER_NAME,
        "--credential-key",
        TOKEN_ENV,
    ])
    .await
    .map(|_| ())
}

async fn trigger_probe(sandbox: &SandboxGuard) -> Result<String, String> {
    sandbox
        .exec(&[
            "sh",
            "-c",
            "rm -f /sandbox/probe-result; touch /sandbox/probe-trigger",
        ])
        .await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(result) = sandbox.exec(&["cat", "/sandbox/probe-result"]).await {
            return Ok(result.trim().to_string());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("timed out waiting for long-running credential probe".to_string());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_probe_success(sandbox: &SandboxGuard) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    loop {
        if trigger_probe(sandbox).await? == "ok" {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("long-running process never resolved the latest rotated token".to_string());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn wait_for_probe_failure(sandbox: &SandboxGuard) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    loop {
        if trigger_probe(sandbox).await? == "failed" {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("old workload handle survived explicit reconfiguration".to_string());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test]
async fn long_running_process_survives_rotations_and_reconfigure_revokes() -> Result<(), String> {
    delete_provider_resources().await;
    let fixture = HostSupportContainer::start_python(FIXTURE_SCRIPT, 8000).await?;
    let profile = write_profile(fixture.port, fixture.port)?;
    let policy = write_policy(fixture.port)?;
    configure_refresh(&profile).await?;

    let policy_path = policy.path().to_string_lossy().into_owned();
    let resource_url = format!("http://host.openshell.internal:{}/probe", fixture.port);
    let parent_script = format!(
        r#"case "$REFRESH_E2E_ACCESS_TOKEN" in
  openshell:resolve:env:s*_REFRESH_E2E_ACCESS_TOKEN) ;;
  *) exit 64 ;;
esac
echo {READY_MARKER}
while true; do
  if [ -f /sandbox/probe-trigger ]; then
    rm -f /sandbox/probe-trigger
    if curl --fail --silent --output /dev/null \
      --header "Authorization: Bearer $REFRESH_E2E_ACCESS_TOKEN" \
      {resource_url}; then
      echo ok > /sandbox/probe-result
    else
      echo failed > /sandbox/probe-result
    fi
  fi
  sleep 0.1
done"#
    );
    let mut sandbox = SandboxGuard::create_keep_with_args(
        &["--provider", PROVIDER_NAME, "--policy", &policy_path],
        &["sh", "-c", &parent_script],
        READY_MARKER,
    )
    .await?;

    let result = async {
        if trigger_probe(&sandbox).await? != "ok" {
            return Err("initial long-running credential probe failed".to_string());
        }

        for _ in 0..12 {
            rotate().await?;
        }
        wait_for_probe_success(&sandbox).await?;

        reconfigure_refresh().await?;
        wait_for_probe_failure(&sandbox).await?;

        let fresh_probe = format!(
            "curl --fail --silent --output /dev/null --header \"Authorization: Bearer $REFRESH_E2E_ACCESS_TOKEN\" {resource_url}"
        );
        sandbox.exec(&["sh", "-c", &fresh_probe]).await?;
        Ok(())
    }
    .await;

    sandbox.cleanup().await;
    delete_provider_resources().await;
    result
}
