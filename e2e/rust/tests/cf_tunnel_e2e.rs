// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E tests for Cloudflare tunnel auth flow against a running cluster.
//!
//! Prerequisites:
//! - A running nemoclaw gateway deployed with `--plaintext`
//! - The gateway's HTTP endpoint accessible (no TLS)
//! - The `nemoclaw` binary (built automatically from the workspace)
//!
//! These tests exercise the full CLI → WS tunnel → gRPC flow.
//!
//! Environment variables:
//! - `NEMOCLAW_CLUSTER`: Name of the active cluster (standard e2e var)
//!
//! The cluster must have been deployed with `nemoclaw gateway start --plaintext`
//! so that the server accepts plaintext HTTP connections.

use std::process::Stdio;

use nemoclaw_e2e::harness::binary::nemoclaw_cmd;
use nemoclaw_e2e::harness::output::strip_ansi;

/// Run `nemoclaw <args>` using the system's configured gateway.
async fn run_cli(args: &[&str]) -> (String, i32) {
    let mut cmd = nemoclaw_cmd();
    cmd.args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd.output().await.expect("spawn nemoclaw");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");
    let code = output.status.code().unwrap_or(-1);
    (combined, code)
}

// -------------------------------------------------------------------
// Test 12: gRPC health check against a plaintext cluster
// -------------------------------------------------------------------

/// `nemoclaw status` should report a healthy gateway when connected to a
/// plaintext cluster (deployed with `--plaintext`/`--disable-tls`).
///
/// This test verifies the entire plaintext path:
/// - CLI resolves cluster metadata with `http://` scheme
/// - gRPC client connects over plaintext
/// - Server responds to health check
#[tokio::test]
async fn plaintext_cluster_status_reports_healthy() {
    let (output, code) = run_cli(&["status"]).await;
    let clean = strip_ansi(&output);

    assert_eq!(
        code, 0,
        "nemoclaw status should exit 0 against plaintext cluster:\n{clean}"
    );

    // The status output should show the gateway as healthy.
    assert!(
        clean.to_lowercase().contains("healthy")
            || clean.to_lowercase().contains("running")
            || clean.contains("✓"),
        "status should report healthy gateway:\n{clean}"
    );
}

// -------------------------------------------------------------------
// Test 13: gRPC through the WS tunnel proxy (CF token path)
// -------------------------------------------------------------------

/// When a gateway is registered with `gateway add` (CF auth mode), the CLI
/// routes gRPC through the WebSocket tunnel proxy.  This test verifies the
/// full tunnel path:
///
/// CLI → local TCP proxy → WebSocket → /_ws_tunnel → loopback TCP → gRPC
///
/// This test registers the current cluster's endpoint as a CF gateway,
/// provides a dummy CF token, and verifies that `nemoclaw status` can
/// reach the server through the WS tunnel.
///
/// Note: This test modifies the active gateway config (creates a new CF
/// gateway entry). It cleans up afterward but may interfere with other
/// tests if run in parallel.
#[tokio::test]
async fn ws_tunnel_status_through_cf_proxy() {
    // Read the current cluster name to restore it later.
    let (original_status, _) = run_cli(&["status"]).await;
    let clean_status = strip_ansi(&original_status);

    // Only run this test if we have a healthy cluster to test against.
    if !clean_status.to_lowercase().contains("healthy")
        && !clean_status.to_lowercase().contains("running")
        && !clean_status.contains("✓")
    {
        eprintln!("Skipping ws_tunnel test: no healthy cluster available");
        return;
    }

    // Get the gateway endpoint from the cluster metadata.
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
        eprintln!("Skipping ws_tunnel test: could not extract gateway endpoint from:\n{info_clean}");
        return;
    };

    // For the WS tunnel test, we need the endpoint to be HTTP (plaintext).
    // If it's HTTPS, the WS tunnel test requires TLS negotiation which
    // complicates things. Skip if the cluster isn't plaintext.
    if !endpoint.starts_with("http://") {
        eprintln!(
            "Skipping ws_tunnel test: gateway endpoint is not plaintext HTTP: {endpoint}\n\
             Deploy with `nemoclaw gateway start --plaintext` for this test."
        );
        return;
    }

    // Use --cf-token + --gateway-endpoint to force the CF tunnel path.
    // The dummy token won't be validated (no CF Access middleware), but
    // it triggers the CLI's tunnel proxy codepath.
    let (output, code) = run_cli(&[
        "--cf-token",
        "dummy-test-jwt",
        "--gateway-endpoint",
        &endpoint,
        "status",
    ])
    .await;

    let clean = strip_ansi(&output);
    assert_eq!(
        code, 0,
        "nemoclaw status through WS tunnel should exit 0:\n{clean}"
    );
    assert!(
        clean.to_lowercase().contains("healthy")
            || clean.to_lowercase().contains("running")
            || clean.contains("✓"),
        "status through WS tunnel should report healthy:\n{clean}"
    );
}
