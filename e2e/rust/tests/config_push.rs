// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! E2E coverage for pushed configuration (`config_delivery_mode = "push"`).
//!
//! The push lane (`mise run e2e:rust:push`) runs the whole Docker suite with a
//! push-mode gateway. This test adds what the rest of the suite cannot see:
//! a pushing supervisor never polls `GetSandboxConfig`, live policy changes
//! still reach it, and it keeps receiving them after the gateway restarts.
//! It skips itself in the poll lane.

#![cfg(feature = "e2e")]

use std::io::Write as _;
use std::time::{Duration, Instant};

use openshell_e2e::harness::cli::{run_cli, wait_for_healthy, wait_for_sandbox_phase};
use openshell_e2e::harness::gateway::ManagedGateway;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

fn push_lane() -> bool {
    std::env::var("OPENSHELL_E2E_CONFIG_DELIVERY_MODE").is_ok_and(|mode| mode == "push")
}

/// Fetch the gateway's Prometheus text exposition.
async fn metrics() -> String {
    let url = std::env::var("OPENSHELL_E2E_GATEWAY_METRICS_URL")
        .expect("the Docker e2e wrapper exports OPENSHELL_E2E_GATEWAY_METRICS_URL");
    let authority = url
        .strip_prefix("http://")
        .and_then(|rest| rest.split('/').next())
        .expect("metrics URL is http://host:port/metrics");
    let mut stream = tokio::net::TcpStream::connect(authority)
        .await
        .expect("connect to gateway metrics");
    stream
        .write_all(format!("GET /metrics HTTP/1.0\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .expect("request metrics");
    let mut body = String::new();
    stream
        .read_to_string(&mut body)
        .await
        .expect("read metrics");
    body
}

/// Sum of every series of `name` whose labels contain all of `labels`.
async fn metric_sum(name: &str, labels: &[&str]) -> f64 {
    metrics()
        .await
        .lines()
        .filter(|line| {
            line.strip_prefix(name)
                .is_some_and(|rest| rest.starts_with('{') || rest.starts_with(' '))
                && labels.iter().all(|label| line.contains(label))
        })
        .filter_map(|line| line.rsplit(' ').next()?.parse::<f64>().ok())
        .sum()
}

async fn config_polls() -> f64 {
    metric_sum(
        "openshell_server_grpc_requests_total",
        &["method=\"GetSandboxConfig\""],
    )
    .await
}

async fn wait_for_push_session() {
    let deadline = Instant::now() + Duration::from_secs(120);
    while metric_sum("openshell_server_config_push_sessions", &[]).await < 1.0 {
        assert!(
            Instant::now() < deadline,
            "no supervisor session received pushed configuration"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// A policy whose only network rule allows `host`. Filesystem access is the
/// same in every version, because it cannot change on a live sandbox.
fn policy_file(host: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("create policy file");
    write!(
        file,
        r#"version: 1

filesystem_policy:
  include_workdir: true
  read_only:
    - /bin
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

network_policies:
  pushed:
    name: pushed
    endpoints:
      - host: {host}
        port: 443
    binaries:
      - path: "/**"
"#
    )
    .expect("write policy file");
    file.flush().expect("flush policy file");
    file
}

/// Replace the policy and wait until the supervisor reports it loaded.
async fn set_policy_and_wait(sandbox: &str, host: &str) -> Duration {
    let policy = policy_file(host);
    let path = policy.path().to_str().expect("UTF-8 policy path");
    let started = Instant::now();
    let (output, code) = run_cli(&[
        "policy",
        "set",
        sandbox,
        "--policy",
        path,
        "--wait",
        "--timeout",
        "60",
    ])
    .await;
    assert_eq!(code, 0, "policy set --wait failed: {output}");
    started.elapsed()
}

#[tokio::test]
async fn pushed_configuration_reaches_sandboxes_without_polling() {
    if !push_lane() {
        eprintln!("skipping: the gateway does not push configuration in this lane");
        return;
    }
    let initial = policy_file("one.example.com");
    let path = initial.path().to_str().expect("UTF-8 policy path");
    let mut sandbox = SandboxGuard::create_keep_with_args(
        &["--policy", path, "--no-tty"],
        &["sh", "-c", "echo Ready && sleep infinity"],
        "Ready",
    )
    .await
    .expect("create sandbox");
    wait_for_push_session().await;

    // A pushing supervisor does not poll. Its poll interval is 10 seconds,
    // so a quiet window longer than that proves it stopped.
    let polls = config_polls().await;
    tokio::time::sleep(Duration::from_secs(15)).await;
    assert_eq!(
        config_polls().await,
        polls,
        "a pushing supervisor polled GetSandboxConfig"
    );

    // A live change is pushed and loaded.
    let pushed = metric_sum(
        "openshell_server_config_updates_sent_total",
        &["part=\"sandbox_config\""],
    )
    .await;
    let elapsed = set_policy_and_wait(&sandbox.name, "two.example.com").await;
    eprintln!("policy change loaded in {elapsed:?}");
    assert!(
        metric_sum(
            "openshell_server_config_updates_sent_total",
            &["part=\"sandbox_config\""],
        )
        .await
            > pushed,
        "the policy change was not pushed"
    );

    // After a gateway restart the supervisor reconnects, receives a fresh
    // initial snapshot, and keeps receiving changes.
    if let Some(gateway) = ManagedGateway::from_env().expect("gateway metadata") {
        gateway.stop().expect("stop gateway");
        gateway.start().expect("start gateway");
        wait_for_healthy(Duration::from_secs(120))
            .await
            .expect("gateway healthy after restart");
        wait_for_sandbox_phase(&sandbox.name, "Ready", Duration::from_secs(120))
            .await
            .expect("sandbox ready after restart");
        wait_for_push_session().await;
        set_policy_and_wait(&sandbox.name, "three.example.com").await;
        let polls = config_polls().await;
        tokio::time::sleep(Duration::from_secs(15)).await;
        assert_eq!(
            config_polls().await,
            polls,
            "the reconnected supervisor polled GetSandboxConfig"
        );
    } else {
        eprintln!("skipping the restart check: this run uses an existing gateway");
    }

    sandbox.cleanup().await;
}
