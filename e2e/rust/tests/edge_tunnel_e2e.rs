// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E tests for edge tunnel auth flow against a running gateway.
//!
//! Prerequisites:
//! - A running openshell gateway
//! - For WS tunnel coverage, the gateway's HTTP endpoint is accessible (no TLS)
//! - The `openshell` binary (built automatically from the workspace)
//!
//! These tests exercise the full CLI → WS tunnel → gRPC flow.
//!
//! Environment variables:
//! - `OPENSHELL_GATEWAY`: Name of the active gateway (standard e2e var)
//! - `OPENSHELL_GATEWAY_ENDPOINT`: Optional direct plaintext endpoint.
//!
//! The edge-tunnel path requires a gateway endpoint that accepts plaintext HTTP.

use std::process::Stdio;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::output::strip_ansi;

/// Run `openshell <args>` using the system's configured gateway.
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

/// Run `openshell <args>` with a custom config directory so the CLI reads
/// our seeded gateway metadata and edge token instead of the real config.
async fn run_cli_with_config(config_dir: &std::path::Path, args: &[&str]) -> (String, i32) {
    let mut cmd = openshell_cmd();
    cmd.args(args)
        .env("XDG_CONFIG_HOME", config_dir)
        .env("HOME", config_dir)
        .env_remove("OPENSHELL_GATEWAY")
        .env_remove("OPENSHELL_GATEWAY_ENDPOINT")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd.output().await.expect("spawn openshell");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");
    let code = output.status.code().unwrap_or(-1);
    (combined, code)
}

/// Seed a temporary config directory with gateway metadata that has
/// `auth_mode: "cloudflare_jwt"`, a stored edge token, and an active gateway
/// pointing at the given endpoint.
fn seed_edge_gateway_config(
    config_dir: &std::path::Path,
    gateway_name: &str,
    gateway_endpoint: &str,
    edge_token: &str,
) {
    let openshell_dir = config_dir.join("openshell");
    let gateways_dir = openshell_dir.join("gateways");

    std::fs::create_dir_all(&openshell_dir).expect("create openshell config dir");
    std::fs::write(openshell_dir.join("active_gateway"), gateway_name)
        .expect("write active_gateway");

    // Write gateway metadata JSON.
    let gateway_dir = gateways_dir.join(gateway_name);
    std::fs::create_dir_all(&gateway_dir).expect("create gateway dir");
    let metadata = serde_json::json!({
        "name": gateway_name,
        "gateway_endpoint": gateway_endpoint,
        "is_remote": false,
        "gateway_port": 0,
        "auth_mode": "cloudflare_jwt"
    });
    std::fs::write(
        gateway_dir.join("metadata.json"),
        serde_json::to_string_pretty(&metadata).unwrap(),
    )
    .expect("write gateway metadata");

    // Write edge token file.
    std::fs::write(gateway_dir.join("edge_token"), edge_token).expect("write edge_token");
}

// -------------------------------------------------------------------
// Test 12: gRPC health check against a gateway
// -------------------------------------------------------------------

/// `openshell status` should report a healthy gateway when connected to a
/// configured gateway.
///
/// This test verifies the normal gateway path:
/// - CLI resolves gateway metadata
/// - gRPC client connects
/// - Server responds to health check
#[tokio::test]
async fn gateway_status_reports_healthy() {
    let (output, code) = run_cli(&["status"]).await;
    let clean = strip_ansi(&output);

    assert_eq!(
        code, 0,
        "openshell status should exit 0 against gateway:\n{clean}"
    );

    // The status output should show the gateway as healthy/connected.
    assert!(
        clean.to_lowercase().contains("healthy")
            || clean.to_lowercase().contains("running")
            || clean.to_lowercase().contains("connected")
            || clean.contains("✓"),
        "status should report healthy gateway:\n{clean}"
    );
}

// -------------------------------------------------------------------
// Test 13: gRPC through the WS tunnel proxy (edge token path)
// -------------------------------------------------------------------

/// When a gateway's metadata has `auth_mode == "cloudflare_jwt"` and a
/// stored edge token, the CLI routes gRPC through the WebSocket tunnel proxy.
/// This test verifies the full tunnel path:
///
/// CLI → local TCP proxy → WebSocket → /_ws_tunnel → loopback TCP → gRPC
///
/// The test seeds a temporary config directory with edge auth metadata and a
/// dummy token, then runs `openshell status` against the live plaintext
/// gateway.
///
/// Note: The dummy token won't be validated (no edge auth middleware on
/// the plaintext gateway), but it triggers the CLI's tunnel proxy codepath.
#[tokio::test]
async fn ws_tunnel_status_through_edge_proxy() {
    let (original_status, _) = run_cli(&["status"]).await;
    let clean_status = strip_ansi(&original_status);

    // Only run this test if we have a healthy gateway to test against.
    if !clean_status.to_lowercase().contains("healthy")
        && !clean_status.to_lowercase().contains("running")
        && !clean_status.to_lowercase().contains("connected")
        && !clean_status.contains("✓")
    {
        eprintln!("Skipping ws_tunnel test: no healthy gateway available");
        return;
    }

    // Get the gateway endpoint from the gateway metadata.
    let (info_output, info_code) = run_cli(&["gateway", "info"]).await;
    assert_eq!(info_code, 0, "gateway info should succeed:\n{info_output}");

    let info_clean = strip_ansi(&info_output);

    // Extract the gateway endpoint from the info output.
    // The format varies, but it should contain a URL-like string.
    let endpoint = info_clean
        .lines()
        .find_map(|line| {
            if line.to_lowercase().contains("endpoint")
                || line.to_lowercase().contains("gateway")
            {
                // Try to extract a URL from the line
                line.split_whitespace()
                    .find(|word| word.starts_with("http://") || word.starts_with("https://"))
                    .map(String::from)
            } else {
                None
            }
        });

    let Some(endpoint) = endpoint else {
        eprintln!(
            "Skipping ws_tunnel test: could not extract gateway endpoint from:\n{info_clean}"
        );
        return;
    };

    // For the WS tunnel test, we need the endpoint to be HTTP (plaintext).
    // If it's HTTPS, the WS tunnel test requires TLS negotiation which
    // complicates things. Skip if the gateway isn't plaintext.
    if !endpoint.starts_with("http://") {
        eprintln!(
            "Skipping ws_tunnel test: gateway endpoint is not plaintext HTTP: {endpoint}\n\
             Use a plaintext local gateway such as `mise run gateway:docker` for this test."
        );
        return;
    }

    // Seed a temporary config directory with edge auth metadata pointing at
    // the live gateway. The dummy token triggers the WS tunnel codepath
    // without requiring real edge auth middleware.
    let tmpdir = tempfile::tempdir().expect("create temp config dir");
    seed_edge_gateway_config(
        tmpdir.path(),
        "edge-tunnel-test",
        &endpoint,
        "dummy-test-jwt",
    );

    let (output, code) = run_cli_with_config(tmpdir.path(), &[
        "--gateway",
        "edge-tunnel-test",
        "status",
    ])
    .await;

    let clean = strip_ansi(&output);
    assert_eq!(
        code, 0,
        "openshell status through WS tunnel should exit 0:\n{clean}"
    );
    assert!(
        clean.to_lowercase().contains("healthy")
            || clean.to_lowercase().contains("running")
            || clean.to_lowercase().contains("connected")
            || clean.contains("✓"),
        "status through WS tunnel should report healthy:\n{clean}"
    );
}
