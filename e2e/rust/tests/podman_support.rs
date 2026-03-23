// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Podman-specific E2E tests for macOS support.
//!
//! These tests verify the Podman socket discovery, runtime detection, and
//! container configuration logic introduced for macOS Podman support.
//!
//! Gated behind the `e2e` feature flag (same as other E2E tests) and
//! automatically skipped when Podman is not installed or not running.

#![cfg(feature = "e2e")]

use std::process::Stdio;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::output::strip_ansi;

/// Check whether Podman is available and a machine is running.
/// Returns the socket path if available, None otherwise.
async fn podman_socket() -> Option<String> {
    let output = tokio::process::Command::new("podman")
        .args([
            "machine",
            "inspect",
            "--format",
            "{{.ConnectionInfo.PodmanSocket.Path}}",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() || !path.starts_with('/') {
        return None;
    }

    // Verify socket actually exists
    if !std::path::Path::new(&path).exists() {
        return None;
    }

    Some(path)
}

/// Run `openshell <args>` with DOCKER_HOST pointing at the Podman socket.
/// Uses an isolated XDG_CONFIG_HOME per call (stateless).
async fn run_with_podman(args: &[&str], socket: &str) -> (String, i32) {
    let tmpdir = tempfile::tempdir().expect("create config dir");
    run_with_podman_config(args, socket, tmpdir.path()).await
}

/// Run `openshell <args>` with a shared config directory so gateway metadata
/// persists across calls.
async fn run_with_podman_config(
    args: &[&str],
    socket: &str,
    config_dir: &std::path::Path,
) -> (String, i32) {
    let mut cmd = openshell_cmd();
    cmd.args(args)
        .env("DOCKER_HOST", format!("unix://{socket}"))
        .env("XDG_CONFIG_HOME", config_dir)
        .env_remove("OPENSHELL_GATEWAY")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd.output().await.expect("spawn openshell");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");
    let code = output.status.code().unwrap_or(-1);
    (combined, code)
}

// -------------------------------------------------------------------
// doctor check — verifies Podman is detected as a reachable runtime
// -------------------------------------------------------------------

/// `openshell doctor check` should succeed when DOCKER_HOST points at a
/// running Podman socket.
#[tokio::test]
async fn doctor_check_succeeds_with_podman() {
    let Some(socket) = podman_socket().await else {
        eprintln!("SKIP: Podman not available");
        return;
    };

    let (output, code) = run_with_podman(&["doctor", "check"], &socket).await;
    let clean = strip_ansi(&output);

    assert_eq!(
        code, 0,
        "doctor check should succeed with Podman socket:\n{clean}"
    );
    // The output should mention the Docker/Podman version
    assert!(
        clean.contains("Docker") || clean.contains("Podman") || clean.contains("version"),
        "doctor check should report runtime info:\n{clean}"
    );
}

// -------------------------------------------------------------------
// Podman socket discovery — verifies auto-detection without DOCKER_HOST
// -------------------------------------------------------------------

/// `openshell doctor check` should auto-discover the Podman socket when
/// DOCKER_HOST is not set (macOS only).
#[tokio::test]
async fn doctor_check_auto_discovers_podman_socket() {
    if !cfg!(target_os = "macos") {
        eprintln!("SKIP: Podman auto-discovery is macOS only");
        return;
    }

    let Some(_socket) = podman_socket().await else {
        eprintln!("SKIP: Podman not available");
        return;
    };

    // Run WITHOUT DOCKER_HOST — should auto-discover via `podman machine inspect`.
    // Preserve HOME and XDG_CONFIG_HOME so both Podman (machine config) and
    // OpenShell (gateway metadata) can find their config directories.
    let mut cmd = openshell_cmd();
    cmd.args(["doctor", "check"])
        .env_remove("DOCKER_HOST")
        .env_remove("CONTAINER_HOST")
        .env_remove("OPENSHELL_GATEWAY")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd.output().await.expect("spawn openshell");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let clean = strip_ansi(&combined);

    assert_eq!(
        output.status.code().unwrap_or(-1),
        0,
        "doctor check should auto-discover Podman socket:\n{clean}"
    );
}

// -------------------------------------------------------------------
// CONTAINER_HOST fallback — Podman convention
// -------------------------------------------------------------------

/// `openshell doctor check` should respect CONTAINER_HOST when DOCKER_HOST
/// is not set.
#[tokio::test]
async fn doctor_check_respects_container_host() {
    let Some(socket) = podman_socket().await else {
        eprintln!("SKIP: Podman not available");
        return;
    };

    let tmpdir = tempfile::tempdir().expect("create config dir");
    let mut cmd = openshell_cmd();
    cmd.args(["doctor", "check"])
        .env_remove("DOCKER_HOST")
        .env("CONTAINER_HOST", format!("unix://{socket}"))
        .env("XDG_CONFIG_HOME", tmpdir.path())
        .env("HOME", tmpdir.path())
        .env_remove("OPENSHELL_GATEWAY")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd.output().await.expect("spawn openshell");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let clean = strip_ansi(&combined);

    assert_eq!(
        output.status.code().unwrap_or(-1),
        0,
        "doctor check should work with CONTAINER_HOST:\n{clean}"
    );
}

// -------------------------------------------------------------------
// Gateway lifecycle — start, verify, destroy with Podman
// -------------------------------------------------------------------

/// Full gateway lifecycle: start → status → destroy using Podman.
/// This is the core E2E test that validates k3s runs correctly under Podman
/// with the KubeletInUserNamespace and cgroups-per-qos flags.
#[tokio::test]
async fn gateway_lifecycle_with_podman() {
    let Some(socket) = podman_socket().await else {
        eprintln!("SKIP: Podman not available");
        return;
    };

    let gw_name = "podman-e2e-test";

    // Use a shared config dir so gateway metadata persists across commands
    let config_dir = tempfile::tempdir().expect("create shared config dir");
    let cfg = config_dir.path();

    // Clean up any leftover from a previous run
    let _ = run_with_podman_config(&["gateway", "destroy", "-g", gw_name], &socket, cfg).await;

    // Start gateway
    let (output, code) =
        run_with_podman_config(&["gateway", "start", "--name", gw_name], &socket, cfg).await;
    let clean = strip_ansi(&output);

    if code != 0 {
        let _ =
            run_with_podman_config(&["gateway", "destroy", "-g", gw_name], &socket, cfg).await;
        panic!("gateway start failed with Podman:\n{clean}");
    }

    // Verify gateway is healthy
    let (status_output, status_code) =
        run_with_podman_config(&["status", "-g", gw_name], &socket, cfg).await;
    let status_clean = strip_ansi(&status_output);

    // Destroy gateway (always, even if status check fails)
    let _ = run_with_podman_config(&["gateway", "destroy", "-g", gw_name], &socket, cfg).await;

    assert_eq!(
        status_code, 0,
        "gateway status should succeed:\n{status_clean}"
    );
    assert!(
        status_clean.contains("Connected"),
        "gateway should be connected:\n{status_clean}"
    );
}
