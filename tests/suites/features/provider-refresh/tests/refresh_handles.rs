// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Refresh-managed workload credential handles.
//!
//! The test serves a token issuer and a resource from one host server. The
//! gateway calls the issuer on `127.0.0.1`, so the gateway must run on the
//! machine that runs the tests; the sandbox reaches the resource through
//! `host.openshell.internal`.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use host_server_support::{HttpRecorder, Request, Response, TEST_HOST};
use serde_json::json;
use testkit::{Context, PYTHON_BINARIES, Poll, Result, Sandbox, policy, poll_until};

const TOKEN_ENV: &str = "REFRESH_E2E_ACCESS_TOKEN";
const BOOTSTRAP_TOKEN: &str = "bootstrap-token";
const ROTATIONS: usize = 12;
const PROBE_TIMEOUT: Duration = Duration::from_secs(45);

/// The main process keeps the environment it started with. It checks that
/// its credential is a stable handle, then runs the probe in [`probe`]
/// whenever `/sandbox/probe-trigger` appears and writes `ok` or `failed`
/// to `/sandbox/probe-result`.
fn main_process(resource_url: &str) -> String {
    format!(
        r#"case "${TOKEN_ENV}" in
  openshell:resolve:env:s*_{TOKEN_ENV}) ;;
  *) exit 64 ;;
esac
while true; do
  if [ -f /sandbox/probe-trigger ]; then
    rm -f /sandbox/probe-trigger
    if {probe}; then
      echo ok > /sandbox/probe-result
    else
      echo failed > /sandbox/probe-result
    fi
  fi
  sleep 0.1
done"#,
        probe = probe(resource_url)
    )
}

/// A shell command that requests `resource_url` with the credential from the
/// environment as a bearer token, and fails unless the resource accepts it.
fn probe(resource_url: &str) -> String {
    format!(
        r#"python3 -c 'import os, urllib.request; urllib.request.urlopen(urllib.request.Request("{resource_url}", headers={{"Authorization": "Bearer " + os.environ["{TOKEN_ENV}"]}}), timeout=5).read()'"#
    )
}

/// One long-running process keeps its original environment while the
/// gateway rotates the credential 12 times, each rotation invalidating the
/// last token. The process still reaches the resource with the newest token.
/// Reconfiguring the refresh revokes the process's handle, and a new process
/// gets a working one.
#[testkit::test]
async fn long_running_process_survives_rotations_and_reconfigure_revokes(
    cx: &mut Context,
) -> testkit::Result {
    let issuer = Issuer::start().await?;
    let provider = cx.name("refresh");
    let profile = profile(&provider, issuer.port());
    let provider_type = cx.import_profile(&profile).await?;
    cx.create_provider(&provider, &provider_type, &[(TOKEN_ENV, BOOTSTRAP_TOKEN)])
        .await?;
    let refresh = cx.provider_refresh(&provider, TOKEN_ENV);
    let configure = async || {
        refresh
            .configure(
                "oauth2-client-credentials",
                &[("client_id", "e2e-client")],
                &[("client_secret", "e2e-client-secret")],
            )
            .await?
            .success()
    };
    configure().await?;

    let resource_url = format!("http://{TEST_HOST}:{}/probe", issuer.port());
    let sandbox = cx
        .sandbox("rfh")
        .image(testkit::python_image())
        .providers([provider.as_str()])
        .policy(probe_policy(issuer.port())?)
        .command(["sh", "-c", &main_process(&resource_url)])
        .create_ready()
        .await?;

    let first = trigger_probe(&sandbox).await?;
    testkit::ensure!(
        first == "ok",
        "the first probe from the long-running process returned {first:?}; issuer saw {}",
        issuer.summary()
    );

    for _ in 0..ROTATIONS {
        refresh.rotate().await?.success()?;
    }
    wait_for_probe(
        &sandbox,
        "ok",
        "the long-running process to use the latest rotated token",
    )
    .await
    .map_err(|error| error.context(format!("issuer saw {}", issuer.summary())))?;

    configure().await?;
    wait_for_probe(
        &sandbox,
        "failed",
        "reconfiguring the refresh to revoke the long-running process's handle",
    )
    .await?;

    sandbox
        .exec(["sh", "-c", &probe(&resource_url)])
        .await?
        .success()?;
    Ok(())
}

/// Ask the main process to run its probe, and return what it wrote.
async fn trigger_probe(sandbox: &Sandbox) -> Result<String> {
    let output = sandbox
        .exec([
            "sh",
            "-c",
            "rm -f /sandbox/probe-result; touch /sandbox/probe-trigger; \
             for _ in $(seq 100); do \
               if [ -f /sandbox/probe-result ]; then cat /sandbox/probe-result; exit 0; fi; \
               sleep 0.1; \
             done; exit 1",
        ])
        .await?
        .success()?;
    Ok(output.stdout.trim().to_string())
}

async fn wait_for_probe(sandbox: &Sandbox, expected: &str, what: &str) -> Result {
    poll_until(
        what,
        PROBE_TIMEOUT,
        Duration::from_millis(500),
        async || {
            let result = trigger_probe(sandbox).await?;
            Ok(if result == expected {
                Poll::Ready(())
            } else {
                Poll::Pending(format!("the probe returned {result:?}"))
            })
        },
    )
    .await
}

/// An OAuth issuer and the resource it guards. Each `POST /token` issues a
/// new token and invalidates the last. `GET /probe` answers `204` to the
/// current token and `401` to anything else.
struct Issuer {
    server: HttpRecorder,
}

impl Issuer {
    async fn start() -> Result<Self> {
        let state = Arc::new(Mutex::new((0_u32, BOOTSTRAP_TOKEN.to_string())));
        let server = HttpRecorder::serve(move |request: &Request| {
            let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
            match (request.method(), request.path()) {
                ("POST", "/token") => {
                    state.0 += 1;
                    state.1 = format!("access-token-{}", state.0);
                    Response::json(&json!({
                        "access_token": state.1,
                        "expires_in": 300,
                        "token_type": "Bearer",
                    }))
                }
                ("GET", "/probe")
                    if request.header("authorization").as_deref()
                        == Some(&format!("Bearer {}", state.1)) =>
                {
                    Response::new(204)
                }
                _ => Response::new(401),
            }
        })
        .await?;
        Ok(Self { server })
    }

    fn port(&self) -> u16 {
        self.server.port
    }

    /// The requests so far, without their headers, for a failure report.
    fn summary(&self) -> String {
        let requests: Vec<String> = self
            .server
            .requests()
            .iter()
            .map(|request| format!("{} {}", request.method(), request.path()))
            .collect();
        format!("{requests:?}")
    }
}

/// A profile whose credential refreshes with OAuth client credentials from
/// the issuer on `port`, and is bound to the resource on the same port.
fn profile(id: &str, port: u16) -> String {
    let binaries = PYTHON_BINARIES
        .iter()
        .map(|binary| format!("\"{binary}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "id: {id}
display_name: Provider refresh handle test
category: other
credentials:
  - name: access_token
    env_vars: [{TOKEN_ENV}]
    required: true
    auth_style: bearer
    header_name: authorization
    refresh:
      strategy: oauth2_client_credentials
      token_url: http://127.0.0.1:{port}/token
      refresh_before_seconds: 30
      max_lifetime_seconds: 300
      material:
        - name: client_id
          required: true
        - name: client_secret
          required: true
          secret: true
endpoints:
  - {{host: {TEST_HOST}, port: {port}, path: /probe, protocol: rest, access: full, enforcement: enforce}}
binaries: [{binaries}]
"
    )
}

fn probe_policy(port: u16) -> Result<testkit::sdk::raw::proto::SandboxPolicy> {
    policy::base_with(&format!(
        "network_policies:
  refresh_probe:
    name: refresh_probe
    endpoints:
      - {{host: {TEST_HOST}, port: {port}, path: /probe, protocol: rest, access: full, enforcement: enforce}}
    binaries: {binaries}
",
        binaries = policy::binaries_yaml(PYTHON_BINARIES),
    ))
}
