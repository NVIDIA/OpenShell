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
use openshell_e2e::harness::container::{HostSupportContainer, ImageGuard};
use openshell_e2e::harness::port::find_free_port;
use openshell_e2e::harness::sandbox::{E2E_WORKLOAD_IMAGE, SandboxGuard};
use tempfile::{Builder as TempFileBuilder, NamedTempFile};

use super::{PROFILE_ID, PROVIDER_NAME};

#[path = "github_app_tls.rs"]
mod github_app_tls;

const TOKEN_ENV: &str = "REFRESH_E2E_ACCESS_TOKEN";
const READY_MARKER: &str = "stable-refresh-parent-ready";

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
    let _ = run_cli(&["profile", "delete", PROFILE_ID]).await;
}

fn write_profile(
    resource_host: &str,
    resource_port: u16,
    token_port: u16,
    github: bool,
) -> Result<NamedTempFile, String> {
    let mut file = TempFileBuilder::new()
        .suffix(".yaml")
        .tempfile()
        .map_err(|error| format!("create profile: {error}"))?;
    let profile = format!(
        r"id: {PROFILE_ID}
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
  - host: {resource_host}
    port: {resource_port}
    path: /probe
    protocol: rest
    access: full
    enforcement: enforce
    allowed_ips:
      - {resource_host}/32
binaries:
  - /usr/bin/python3.12
"
    );
    let profile = if github {
        profile
            .replace("oauth2_client_credentials", "github_app_installation")
            .replace(
                "/token\n",
                "/app/installations/{installation_id}/access_tokens\n",
            )
            .replace("name: client_secret", "name: private_key")
            .replace("path: /probe", "path: /**")
            .replace(
                "  - /usr/bin/python3.12",
                "  - /usr/bin/gh\n  - /usr/bin/git",
            )
    } else {
        profile
    };
    file.write_all(profile.as_bytes())
        .map_err(|error| format!("write profile: {error}"))?;
    file.flush()
        .map_err(|error| format!("flush profile: {error}"))?;
    Ok(file)
}

fn write_policy(
    resource_host: &str,
    resource_port: u16,
    github: bool,
) -> Result<NamedTempFile, String> {
    let mut file = TempFileBuilder::new()
        .suffix(".yaml")
        .tempfile()
        .map_err(|error| format!("create policy: {error}"))?;
    let policy = format!(
        r"version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /etc, /dev/urandom]
  read_write: [/sandbox, /tmp, /dev/null]
landlock:
  compatibility: best_effort
process:
  run_as_user: '1000'
  run_as_group: '1000'
network_policies:
  refresh_probe:
    name: refresh_probe
    endpoints:
      - host: {resource_host}
        port: {resource_port}
        path: /probe
        protocol: rest
        access: full
        enforcement: enforce
        allowed_ips:
          - {resource_host}/32
    binaries:
      - path: /usr/bin/python3.12
"
    );
    let policy = if github {
        policy.replace("path: /probe", "path: /**").replace(
            "      - path: /usr/bin/python3.12",
            "      - path: /usr/bin/gh\n      - path: /usr/bin/git",
        )
    } else {
        policy
    };
    file.write_all(policy.as_bytes())
        .map_err(|error| format!("write policy: {error}"))?;
    file.flush()
        .map_err(|error| format!("flush policy: {error}"))?;
    Ok(file)
}

async fn configure_refresh(
    profile: &NamedTempFile,
    github_key: Option<&str>,
) -> Result<(), String> {
    let profile_path = profile.path().to_string_lossy().into_owned();
    run_cli(&["profile", "import", "--file", &profile_path]).await?;
    run_cli_with_env(
        &[
            "provider",
            "create",
            "--name",
            PROVIDER_NAME,
            "--type",
            PROFILE_ID,
            "--runtime-credentials",
        ],
        &[(TOKEN_ENV, "bootstrap-token")],
    )
    .await?;
    reconfigure_refresh(github_key).await?;
    rotate().await
}

async fn reconfigure_refresh(github_key: Option<&str>) -> Result<(), String> {
    if let Some(key) = github_key {
        return run_cli_with_env(
            &[
                "provider",
                "refresh",
                "configure",
                PROVIDER_NAME,
                "--credential-key",
                TOKEN_ENV,
                "--strategy",
                "github-app-installation",
                "--material",
                "client_id=e2e-client",
                "--material",
                "installation_id=123",
                "--material",
                "repository_ids=[42]",
                "--material",
                "permissions={\"contents\":\"read\"}",
                "--secret-material-env",
                "private_key=REFRESH_E2E_PRIVATE_KEY",
            ],
            &[("REFRESH_E2E_PRIVATE_KEY", key)],
        )
        .await
        .map(|_| ());
    }
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
    // Poll inside one exec rather than opening an SSH relay for every poll.
    let output = tokio::time::timeout(Duration::from_secs(60), sandbox.exec(&[
        "sh", "-c",
        "rm -f /sandbox/probe-result; touch /sandbox/probe-trigger; for i in $(seq 1 180); do if [ -f /sandbox/probe-result ]; then cat /sandbox/probe-result; exit 0; fi; sleep 0.25; done; echo 'timed out waiting for credential probe' >&2; exit 1",
    ])).await.map_err(|_| "credential probe exec timed out".to_string())??;
    Ok(output.trim().to_string())
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

pub async fn exercise_refresh_handles(github_key: Option<&str>) -> Result<(), String> {
    delete_provider_resources().await;
    // The host-networked supervisor reaches the published fixture directly.
    // UDP connect selects an interface without sending packets or requiring DNS.
    let route = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    route.connect("192.0.2.1:80").map_err(|e| e.to_string())?;
    let resource_host = route
        .local_addr()
        .map_err(|e| e.to_string())?
        .ip()
        .to_string();
    let tools = if github_key.is_some() {
        let context = tempfile::tempdir().map_err(|e| e.to_string())?;
        let dockerfile = context.path().join("Dockerfile");
        std::fs::write(&dockerfile, format!(
            "FROM {E2E_WORKLOAD_IMAGE}\nUSER root\nRUN apt-get update && apt-get install -y --no-install-recommends gh git openssl ca-certificates && rm -rf /var/lib/apt/lists/*\nUSER sandbox:sandbox\n"
        )).map_err(|e| e.to_string())?;
        Some(ImageGuard::build(
            "github-app-tools",
            &dockerfile,
            context.path(),
        )?)
    } else {
        None
    };
    let resource_port = find_free_port();
    let (fixture, trust) = if let Some(tools) = &tools {
        let fixture = HostSupportContainer::start_python_image_with_host_bindings(
            tools.tag(),
            &include_str!("github_app_fixture.py").replace("FIXTURE_HOST", &resource_host),
            &[(find_free_port(), 8000), (resource_port, 8443)],
            8000,
            &[],
        )
        .await?;
        let logs = fixture.logs()?;
        let start = logs
            .find("-----BEGIN CERTIFICATE-----")
            .ok_or("fixture did not emit its CA")?;
        let end = logs[start..]
            .find("-----END CERTIFICATE-----")
            .ok_or("incomplete fixture CA")?
            + start
            + "-----END CERTIFICATE-----".len();
        let trust = github_app_tls::SupervisorTrust::install(&logs[start..end]).await?;
        (fixture, Some(trust))
    } else {
        // OAuth also runs against an existing gateway, whose supervisor image
        // and lifecycle are outside the test's control. Keep its fixture HTTP.
        let fixture = HostSupportContainer::start_python_on_host_port(
            include_str!("oauth_refresh_fixture.py"),
            8000,
            resource_port,
        )
        .await?;
        (fixture, None)
    };
    let profile = write_profile(
        &resource_host,
        resource_port,
        fixture.port,
        github_key.is_some(),
    )?;
    let policy = write_policy(&resource_host, resource_port, github_key.is_some())?;
    configure_refresh(&profile, github_key).await?;

    let policy_path = policy.path().to_string_lossy().into_owned();
    let probe = if github_key.is_some() {
        format!(
            r#"export GH_ENTERPRISE_TOKEN="$REFRESH_E2E_ACCESS_TOKEN"
api_ok=0
git_ok=0
if [ "$(timeout 15s gh api -H "Authorization: Bearer $REFRESH_E2E_ACCESS_TOKEN" https://{resource_host}:{resource_port}/repos/e2e/repo/contents/README.md --jq .name)" = README.md ]; then api_ok=1; fi
auth="Authorization: Basic $(printf 'x-access-token:%s' "$REFRESH_E2E_ACCESS_TOKEN" | base64 -w0)"
if [ -d /sandbox/repo/.git ]; then
  timeout 15s git -c protocol.version=0 -c http.extraHeader="$auth" -C /sandbox/repo fetch --quiet origin && git_ok=1
else
  timeout 15s git -c protocol.version=0 -c http.extraHeader="$auth" clone --quiet https://{resource_host}:{resource_port}/repo.git /sandbox/repo && git_ok=1
fi
if [ "$api_ok:$git_ok" = 1:1 ] && [ "$(cat /sandbox/repo/README.md)" = 'GitHub App installation token E2E' ]; then
  echo ok
elif [ "$api_ok:$git_ok" = 0:0 ]; then
  echo failed
else
  echo mixed-result
fi"#
        )
    } else {
        format!(
            r#"if /usr/bin/python3.12 -c 'import os, base64, urllib.request; token = os.environ["REFRESH_E2E_ACCESS_TOKEN"]; auths = ["Bearer " + token, "Basic " + base64.b64encode(("x-access-token:" + token).encode()).decode()]; [urllib.request.urlopen(urllib.request.Request("http://{resource_host}:{resource_port}/probe", headers=dict(Authorization=auth)), timeout=5).read() for auth in auths]'; then echo ok; else echo failed; fi"#
        )
    };
    let parent_script = format!(
        r#"case "$REFRESH_E2E_ACCESS_TOKEN" in
  openshell:resolve:env:s*_REFRESH_E2E_ACCESS_TOKEN) ;;
  *) exit 64 ;;
esac
test -z "${{REFRESH_E2E_PRIVATE_KEY+x}}" || exit 65
echo {READY_MARKER}
while true; do
  if [ -f /sandbox/probe-trigger ]; then
    rm -f /sandbox/probe-trigger
    (
{probe}
    ) > /sandbox/probe-result.tmp 2> /sandbox/probe-error
    mv /sandbox/probe-result.tmp /sandbox/probe-result
  fi
  sleep 0.1
done"#
    );
    let create_args = [
        "--provider",
        PROVIDER_NAME,
        "--policy",
        &policy_path,
        "--from",
        tools.as_ref().map_or(E2E_WORKLOAD_IMAGE, ImageGuard::tag),
    ];
    let mut sandbox = SandboxGuard::create_keep_with_args(
        &create_args,
        &["sh", "-c", &parent_script],
        READY_MARKER,
    )
    .await?;

    let result = async {
        let initial = trigger_probe(&sandbox).await?;
        if initial != "ok" {
            return Err(format!(
                "initial long-running credential probe failed: {initial}"
            ));
        }

        for _ in 0..12 {
            rotate().await?;
            wait_for_probe_success(&sandbox).await?;
        }

        reconfigure_refresh(github_key).await?;
        wait_for_probe_failure(&sandbox).await?;

        rotate().await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
        loop {
            // Each exec gets a fresh environment after configuration sync.
            let fresh = sandbox.exec(&["sh", "-c", &probe]).await?;
            if fresh.trim() == "ok" {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "fresh workload failed after reconfiguration: {fresh}"
                ));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        if trigger_probe(&sandbox).await? != "failed" {
            return Err("old workload handle revived after replacement token mint".into());
        }
        Ok(())
    }
    .await;

    if result.is_err() {
        eprintln!(
            "probe diagnostics: {:?}",
            sandbox.exec(&["cat", "/sandbox/probe-error"]).await
        );
        eprintln!(
            "sandbox diagnostics: {:?}",
            run_cli(&["logs", &sandbox.name, "-n", "100"]).await
        );
        eprintln!("hosts: {:?}", sandbox.exec(&["cat", "/etc/hosts"]).await);
    }
    sandbox.cleanup().await;
    delete_provider_resources().await;
    if result.is_err() {
        eprintln!(
            "fixture diagnostics: {}",
            fixture.logs().unwrap_or_default()
        );
    }
    if let Some(trust) = trust {
        trust.restore().await?;
    }
    result
}
