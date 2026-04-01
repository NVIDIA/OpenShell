// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E tests for gateway resume from existing state.
//!
//! All scenarios run inside a **single** `#[tokio::test]` so they execute
//! in a deterministic order and share a known-good gateway state.  Each
//! scenario restores the gateway to a healthy state before the next one
//! begins, preventing cascading failures.
//!
//! **Requires a running gateway** — the `e2e:rust` mise task bootstraps one.

use std::process::{Command, Stdio};
use std::time::Duration;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::output::strip_ansi;
use tokio::time::sleep;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve the gateway name from the `OPENSHELL_GATEWAY` env var (the same
/// variable the CLI reads), falling back to `"openshell"` which matches CI.
fn gateway_name() -> String {
    std::env::var("OPENSHELL_GATEWAY").unwrap_or_else(|_| "openshell".to_string())
}

/// Docker container name for the e2e gateway.
fn container_name() -> String {
    format!("openshell-cluster-{}", gateway_name())
}

/// Run `openshell <args>` and return (combined output, exit code).
async fn run_cli(args: &[&str]) -> (String, i32) {
    let mut cmd = openshell_cmd();
    cmd.args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd.output().await.expect("spawn openshell");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");
    let code = output.status.code().unwrap_or(-1);
    (combined, code)
}

/// Run `docker <args>` synchronously and return (stdout, exit code).
fn docker_cmd(args: &[&str]) -> (String, i32) {
    let output = Command::new("docker")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn docker");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let code = output.status.code().unwrap_or(-1);
    (stdout, code)
}

/// Wait for the gateway to become healthy by polling `openshell status`.
async fn wait_for_healthy(timeout: Duration) {
    let start = std::time::Instant::now();
    loop {
        let (output, code) = run_cli(&["status"]).await;
        let clean = strip_ansi(&output).to_lowercase();
        if code == 0
            && (clean.contains("healthy")
                || clean.contains("running")
                || clean.contains("connected")
                || clean.contains("✓"))
        {
            return;
        }
        if start.elapsed() > timeout {
            panic!(
                "gateway did not become healthy within {}s. Last output:\n{}",
                timeout.as_secs(),
                strip_ansi(&output)
            );
        }
        sleep(Duration::from_secs(3)).await;
    }
}

/// Read the SSH handshake secret from the K8s secret inside the cluster.
fn read_ssh_handshake_secret() -> Option<String> {
    let cname = container_name();
    let (output, code) = docker_cmd(&[
        "exec",
        &cname,
        "sh",
        "-c",
        "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n openshell get secret openshell-ssh-handshake -o jsonpath='{.data.secret}' 2>/dev/null",
    ]);
    if code == 0 && !output.trim().is_empty() {
        Some(output.trim().to_string())
    } else {
        None
    }
}

/// Extract the sandbox name from `openshell sandbox create` output.
fn extract_sandbox_name(output: &str) -> String {
    strip_ansi(output)
        .lines()
        .find_map(|line| {
            if let Some((_, rest)) = line.split_once("Created sandbox:") {
                rest.split_whitespace().next().map(ToOwned::to_owned)
            } else if let Some((_, rest)) = line.split_once("Name:") {
                rest.split_whitespace().next().map(ToOwned::to_owned)
            } else {
                None
            }
        })
        .expect("should extract sandbox name from create output")
}

/// Run `gateway start` and log the output if it fails (non-fatal — the
/// test relies on [`wait_for_healthy`] for the real assertion).
async fn start_gateway() {
    let (output, code) = run_cli(&["gateway", "start"]).await;
    if code != 0 {
        eprintln!(
            "gateway start exited {code} (may still recover):\n{}",
            strip_ansi(&output)
        );
    }
}

// ---------------------------------------------------------------------------
// Orchestrated test suite
// ---------------------------------------------------------------------------

/// Single entry-point that runs every resume scenario in a fixed order.
///
/// Running as one `#[tokio::test]` gives us:
///   - **Deterministic ordering** — no async-mutex races.
///   - **Cascade prevention** — each scenario starts only after the previous
///     one left the gateway healthy.
///   - **No task-runner hacks** — no `--test-threads`, `--skip`, or split
///     cargo invocations.
#[tokio::test]
async fn gateway_resume_scenarios() {
    // The gateway must already be running (bootstrapped by the `cluster` task).
    wait_for_healthy(Duration::from_secs(30)).await;

    // Warm the sandbox base image by creating (and deleting) a throwaway
    // sandbox.  On a fresh cluster the ~1 GB image pull can take minutes;
    // doing it once up-front keeps the actual scenarios snappy.
    eprintln!("--- warmup: pulling sandbox base image ---");
    let (output, code) =
        run_cli(&["sandbox", "create", "--", "echo", "warmup"]).await;
    if code == 0 {
        let name = extract_sandbox_name(&output);
        let _ = run_cli(&["sandbox", "delete", &name]).await;
    } else {
        eprintln!(
            "warmup sandbox create failed (non-fatal, image may already be cached):\n{}",
            strip_ansi(&output)
        );
    }

    scenario_start_on_running_gateway().await;
    scenario_ssh_secret_persists_across_restart().await;
    scenario_stop_start_resumes_with_sandbox().await;
    scenario_container_kill_resumes().await;
    scenario_container_removal_resumes().await;
}

// ---------------------------------------------------------------------------
// Scenario: `gateway start` on an already-running gateway
// ---------------------------------------------------------------------------

async fn scenario_start_on_running_gateway() {
    eprintln!("--- scenario: start on running gateway ---");

    let (output, code) = run_cli(&["gateway", "start"]).await;
    let clean = strip_ansi(&output);

    assert_eq!(
        code, 0,
        "gateway start on running gateway should exit 0:\n{clean}"
    );
    assert!(
        clean.to_lowercase().contains("already running"),
        "output should indicate gateway is already running:\n{clean}"
    );
}

// ---------------------------------------------------------------------------
// Scenario: SSH handshake secret persists across restart
// ---------------------------------------------------------------------------

async fn scenario_ssh_secret_persists_across_restart() {
    eprintln!("--- scenario: SSH secret persists across restart ---");

    let secret_before =
        read_ssh_handshake_secret().expect("SSH handshake secret should exist before restart");
    assert!(
        !secret_before.is_empty(),
        "SSH handshake secret should not be empty"
    );

    // Stop → start.
    let (_, stop_code) = run_cli(&["gateway", "stop"]).await;
    assert_eq!(stop_code, 0, "gateway stop should succeed");
    sleep(Duration::from_secs(3)).await;

    start_gateway().await;
    wait_for_healthy(Duration::from_secs(300)).await;

    let secret_after =
        read_ssh_handshake_secret().expect("SSH handshake secret should exist after restart");
    assert_eq!(
        secret_before, secret_after,
        "SSH handshake secret should be identical before and after restart"
    );
}

// ---------------------------------------------------------------------------
// Scenario: stop → start resumes, sandbox survives
// ---------------------------------------------------------------------------

async fn scenario_stop_start_resumes_with_sandbox() {
    eprintln!("--- scenario: stop/start resumes with sandbox ---");

    // Create a sandbox.
    let (output, code) =
        run_cli(&["sandbox", "create", "--", "echo", "resume-test"]).await;
    assert_eq!(
        code, 0,
        "sandbox create should succeed:\n{}",
        strip_ansi(&output)
    );
    let sandbox_name = extract_sandbox_name(&output);

    // Stop → start.
    let (stop_output, stop_code) = run_cli(&["gateway", "stop"]).await;
    assert_eq!(
        stop_code, 0,
        "gateway stop should succeed:\n{}",
        strip_ansi(&stop_output)
    );
    sleep(Duration::from_secs(3)).await;

    // Verify container is stopped.
    let (inspect_out, _) = docker_cmd(&[
        "inspect",
        "-f",
        "{{.State.Running}}",
        &container_name(),
    ]);
    assert_eq!(
        inspect_out.trim(),
        "false",
        "container should be stopped after gateway stop"
    );

    start_gateway().await;
    wait_for_healthy(Duration::from_secs(300)).await;

    // Verify sandbox survived.
    let (list_output, list_code) = run_cli(&["sandbox", "list", "--names"]).await;
    let clean_list = strip_ansi(&list_output);
    assert_eq!(
        list_code, 0,
        "sandbox list should succeed:\n{clean_list}"
    );
    assert!(
        clean_list.contains(&sandbox_name),
        "sandbox '{sandbox_name}' should survive stop/start.\nList:\n{clean_list}"
    );

    let _ = run_cli(&["sandbox", "delete", &sandbox_name]).await;
}

// ---------------------------------------------------------------------------
// Scenario: container killed → resume with stale network
// ---------------------------------------------------------------------------

async fn scenario_container_kill_resumes() {
    eprintln!("--- scenario: container kill resumes ---");

    let cname = container_name();
    let net_name = format!("openshell-cluster-{}", gateway_name());

    // Kill the container.
    let (_, kill_code) = docker_cmd(&["kill", &cname]);
    assert_eq!(kill_code, 0, "docker kill should succeed");
    sleep(Duration::from_secs(3)).await;

    // Remove the network to simulate a stale network reference.
    // The bootstrap `ensure_network` always destroys and recreates, so
    // after this the container's stored network ID will be invalid.
    let _ = docker_cmd(&["network", "disconnect", "-f", &net_name, &cname]);
    let (_, net_rm_code) = docker_cmd(&["network", "rm", &net_name]);
    assert_eq!(
        net_rm_code, 0,
        "docker network rm should succeed"
    );

    // Resume — must handle stale network + reuse existing PKI.
    start_gateway().await;
    wait_for_healthy(Duration::from_secs(300)).await;
}

// ---------------------------------------------------------------------------
// Scenario: container removed → resume from volume
// ---------------------------------------------------------------------------

async fn scenario_container_removal_resumes() {
    eprintln!("--- scenario: container removal resumes ---");

    // Force-remove the container.
    let (_, rm_code) = docker_cmd(&["rm", "-f", &container_name()]);
    assert_eq!(rm_code, 0, "docker rm -f should succeed");

    // Volume should survive.
    let (vol_out, vol_code) = docker_cmd(&[
        "volume",
        "inspect",
        &format!("openshell-cluster-{}", gateway_name()),
    ]);
    assert_eq!(
        vol_code, 0,
        "volume should still exist after container removal:\n{vol_out}"
    );

    // Resume from volume.
    start_gateway().await;
    wait_for_healthy(Duration::from_secs(300)).await;
}
