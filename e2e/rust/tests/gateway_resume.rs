// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E tests for gateway resume from existing state.
//!
//! These tests verify that `openshell gateway start` resumes from existing
//! Docker volume state (after stop or container removal) and that the SSH
//! handshake secret persists across container restarts.
//!
//! **Requires a running gateway** — the `e2e:rust` mise task bootstraps one.

use std::process::{Command, Stdio};
use std::time::Duration;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::output::strip_ansi;
use tokio::time::sleep;

/// Default gateway name used by the e2e cluster.
const GATEWAY_NAME: &str = "openshell";

/// Docker container name for the default gateway.
fn container_name() -> String {
    format!("openshell-cluster-{GATEWAY_NAME}")
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
        if code == 0 && (clean.contains("healthy") || clean.contains("running") || clean.contains("✓")) {
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

// -------------------------------------------------------------------
// Test: `gateway start` on an already-running gateway succeeds
// -------------------------------------------------------------------

/// When the gateway is already running, `openshell gateway start` should
/// return immediately with exit code 0 and indicate it's already running.
#[tokio::test]
async fn gateway_start_on_running_gateway_succeeds() {
    // Precondition: gateway is running (e2e cluster is up).
    wait_for_healthy(Duration::from_secs(30)).await;

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

// -------------------------------------------------------------------
// Test: gateway stop → start resumes, sandbox survives
// -------------------------------------------------------------------

/// After `gateway stop` then `gateway start`, the gateway should resume
/// from existing state. A sandbox created before the stop should still
/// appear in the sandbox list after restart.
#[tokio::test]
async fn gateway_stop_start_resumes_with_sandbox() {
    // Precondition: gateway is healthy.
    wait_for_healthy(Duration::from_secs(30)).await;

    // Create a sandbox that we'll check for after restart.
    let (create_output, create_code) =
        run_cli(&["sandbox", "create", "--", "echo", "resume-test"]).await;
    let clean_create = strip_ansi(&create_output);
    assert_eq!(
        create_code, 0,
        "sandbox create should succeed:\n{clean_create}"
    );

    // Extract sandbox name from output.
    let sandbox_name = clean_create
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
        .expect("should extract sandbox name from create output");

    // Stop the gateway.
    let (stop_output, stop_code) = run_cli(&["gateway", "stop"]).await;
    assert_eq!(
        stop_code, 0,
        "gateway stop should succeed:\n{}",
        strip_ansi(&stop_output)
    );

    // Wait a moment for the container to fully stop.
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

    // Start the gateway again — should resume from existing state.
    let (start_output, start_code) = run_cli(&["gateway", "start"]).await;
    let clean_start = strip_ansi(&start_output);
    assert_eq!(
        start_code, 0,
        "gateway start after stop should succeed:\n{clean_start}"
    );

    // Wait for the gateway to become healthy again.
    wait_for_healthy(Duration::from_secs(180)).await;

    // Verify the sandbox still exists.
    let (list_output, list_code) = run_cli(&["sandbox", "list", "--names"]).await;
    let clean_list = strip_ansi(&list_output);
    assert_eq!(
        list_code, 0,
        "sandbox list should succeed after resume:\n{clean_list}"
    );
    assert!(
        clean_list.contains(&sandbox_name),
        "sandbox '{sandbox_name}' should survive gateway stop/start.\nList output:\n{clean_list}"
    );

    // Cleanup: delete the test sandbox.
    let _ = run_cli(&["sandbox", "delete", &sandbox_name]).await;
}

// -------------------------------------------------------------------
// Test: container removed → gateway start resumes
// -------------------------------------------------------------------

/// After the Docker container is force-removed (simulating Docker restart),
/// `openshell gateway start` should resume from the existing volume.
#[tokio::test]
async fn gateway_start_resumes_after_container_removal() {
    // Precondition: gateway is healthy.
    wait_for_healthy(Duration::from_secs(30)).await;

    // Create a sandbox to verify state persistence.
    let (create_output, create_code) =
        run_cli(&["sandbox", "create", "--", "echo", "container-rm-test"]).await;
    let clean_create = strip_ansi(&create_output);
    assert_eq!(
        create_code, 0,
        "sandbox create should succeed:\n{clean_create}"
    );

    let sandbox_name = clean_create
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
        .expect("should extract sandbox name from create output");

    // Force-remove the container (simulates Docker restart / OOM kill).
    let (_, rm_code) = docker_cmd(&["rm", "-f", &container_name()]);
    assert_eq!(rm_code, 0, "docker rm -f should succeed");

    // Verify the volume still exists.
    let (vol_out, vol_code) = docker_cmd(&[
        "volume",
        "inspect",
        &format!("openshell-cluster-{GATEWAY_NAME}"),
    ]);
    assert_eq!(
        vol_code, 0,
        "volume should still exist after container removal:\n{vol_out}"
    );

    // Start the gateway — should resume from the volume.
    let (start_output, start_code) = run_cli(&["gateway", "start"]).await;
    let clean_start = strip_ansi(&start_output);
    assert_eq!(
        start_code, 0,
        "gateway start after container removal should succeed:\n{clean_start}"
    );

    // Wait for healthy.
    wait_for_healthy(Duration::from_secs(180)).await;

    // Verify sandbox survived.
    let (list_output, list_code) = run_cli(&["sandbox", "list", "--names"]).await;
    let clean_list = strip_ansi(&list_output);
    assert_eq!(
        list_code, 0,
        "sandbox list should succeed after resume:\n{clean_list}"
    );
    assert!(
        clean_list.contains(&sandbox_name),
        "sandbox '{sandbox_name}' should survive container removal + resume.\nList output:\n{clean_list}"
    );

    // Cleanup.
    let _ = run_cli(&["sandbox", "delete", &sandbox_name]).await;
}

// -------------------------------------------------------------------
// Test: container killed → gateway start resumes, sandboxes survive,
//       new sandbox create works
// -------------------------------------------------------------------

/// When a container is killed (stopped but NOT removed), `gateway start`
/// should resume from existing state. This validates three things:
///
/// 1. The stale Docker network reference is reconciled (ensure_network
///    destroys and recreates the network with a new ID).
/// 2. Existing sandboxes created before the kill survive the restart.
/// 3. New `sandbox create` works after resume — the TLS certificates
///    are reused (not needlessly regenerated), so the CLI's mTLS certs
///    still match the server.
#[tokio::test]
async fn gateway_start_resumes_after_container_kill() {
    // Precondition: gateway is healthy.
    wait_for_healthy(Duration::from_secs(30)).await;

    let cname = container_name();
    let net_name = format!("openshell-cluster-{GATEWAY_NAME}");

    // Create a sandbox before the kill to verify state persistence.
    let (create_output, create_code) =
        run_cli(&["sandbox", "create", "--", "echo", "kill-resume-test"]).await;
    let clean_create = strip_ansi(&create_output);
    assert_eq!(
        create_code, 0,
        "sandbox create should succeed:\n{clean_create}"
    );

    let sandbox_before = clean_create
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
        .expect("should extract sandbox name from create output");

    // Kill the container (it remains as a stopped container, unlike `docker rm`).
    let (_, kill_code) = docker_cmd(&["kill", &cname]);
    assert_eq!(kill_code, 0, "docker kill should succeed");

    sleep(Duration::from_secs(3)).await;

    // Remove the Docker network to simulate a stale network reference.
    // The bootstrap `ensure_network` always destroys and recreates, so
    // after this the container's stored network ID will be invalid.
    let _ = docker_cmd(&["network", "disconnect", "-f", &net_name, &cname]);
    let (_, net_rm_code) = docker_cmd(&["network", "rm", &net_name]);
    assert_eq!(
        net_rm_code, 0,
        "docker network rm should succeed (or network already gone)"
    );

    // Start the gateway — must handle stale network + reuse existing PKI.
    let (start_output, start_code) = run_cli(&["gateway", "start"]).await;
    let clean_start = strip_ansi(&start_output);
    assert_eq!(
        start_code, 0,
        "gateway start after kill should succeed:\n{clean_start}"
    );

    // Wait for the gateway to become healthy again.
    wait_for_healthy(Duration::from_secs(180)).await;

    // Verify the pre-existing sandbox survived.
    let (list_output, list_code) = run_cli(&["sandbox", "list", "--names"]).await;
    let clean_list = strip_ansi(&list_output);
    assert_eq!(
        list_code, 0,
        "sandbox list should succeed after resume:\n{clean_list}"
    );
    assert!(
        clean_list.contains(&sandbox_before),
        "sandbox '{sandbox_before}' should survive container kill + resume.\nList output:\n{clean_list}"
    );

    // Create a new sandbox to verify TLS is working end-to-end.
    let (new_create_output, new_create_code) =
        run_cli(&["sandbox", "create", "--", "echo", "post-resume-test"]).await;
    let clean_new = strip_ansi(&new_create_output);
    assert_eq!(
        new_create_code, 0,
        "sandbox create after resume should succeed (TLS must work):\n{clean_new}"
    );

    let sandbox_after = clean_new
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
        .expect("should extract sandbox name from post-resume create output");

    // Cleanup.
    let _ = run_cli(&["sandbox", "delete", &sandbox_before]).await;
    let _ = run_cli(&["sandbox", "delete", &sandbox_after]).await;
}

// -------------------------------------------------------------------
// Test: SSH handshake secret persists across container restart
// -------------------------------------------------------------------

/// The SSH handshake K8s secret should persist across gateway stop/start
/// cycles — the same base64-encoded value should be returned before and
/// after the restart.
#[tokio::test]
async fn ssh_handshake_secret_persists_across_restart() {
    // Precondition: gateway is healthy.
    wait_for_healthy(Duration::from_secs(30)).await;

    // Read the SSH handshake secret before restart.
    let secret_before = read_ssh_handshake_secret()
        .expect("SSH handshake secret should exist before restart");
    assert!(
        !secret_before.is_empty(),
        "SSH handshake secret should not be empty"
    );

    // Stop the gateway.
    let (_, stop_code) = run_cli(&["gateway", "stop"]).await;
    assert_eq!(stop_code, 0, "gateway stop should succeed");

    sleep(Duration::from_secs(3)).await;

    // Start the gateway.
    let (start_output, start_code) = run_cli(&["gateway", "start"]).await;
    assert_eq!(
        start_code, 0,
        "gateway start should succeed:\n{}",
        strip_ansi(&start_output)
    );

    // Wait for healthy.
    wait_for_healthy(Duration::from_secs(180)).await;

    // Read the secret after restart.
    let secret_after = read_ssh_handshake_secret()
        .expect("SSH handshake secret should exist after restart");

    assert_eq!(
        secret_before, secret_after,
        "SSH handshake secret should be identical before and after restart"
    );
}
