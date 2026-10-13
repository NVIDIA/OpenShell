// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E tests for edge tunnel auth flow against a running gateway.
//!
//! `gateway_status_reports_healthy` runs wherever the common `e2e` suite runs.
//! The tunnel test needs a gateway with special configuration, so it is a
//! feature test behind `e2e-edge-tunnel`, which the Docker and Podman lanes
//! enable.
//!
//! Prerequisites for the tunnel test:
//! - A running openshell gateway started with the WebSocket tunnel enabled
//!   (`--enable-websocket-tunnel true`) and reachable over `https://`. The CLI
//!   only routes through the tunnel for `https://` gateways, so a plaintext
//!   gateway cannot exercise it.
//! - The `openshell` binary (built automatically from the workspace)
//!
//! The tunnel test reads the active gateway's endpoint from the user config
//! the target registered (`$XDG_CONFIG_HOME/openshell/gateways/<name>`), not
//! from the system gateway directory. When that gateway has a registered CA
//! (`mtls/ca.crt`) the test trusts it by pointing the CLI at it with
//! `SSL_CERT_FILE`, because the tunnel client uses the system trust store.
//! Without one it relies on the system trust store, as a gateway with a
//! publicly trusted certificate would.
//!
//! The tunnel client presents no client certificate. The gateway only requests
//! client certificates, so the WebSocket upgrade does not need one.
//!
//! Environment variables:
//! - `OPENSHELL_GATEWAY`: Name of the active gateway (standard e2e var)
//! - `XDG_CONFIG_HOME`: Config home holding the registered gateways

#[cfg(feature = "e2e-edge-tunnel")]
use std::path::{Path, PathBuf};
use std::process::Stdio;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::output::strip_ansi;

/// Run `openshell <args>` using the system's configured gateway.
async fn run_cli(args: &[&str]) -> (String, i32) {
    let mut cmd = openshell_cmd();
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd.output().await.expect("spawn openshell");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");
    let code = output.status.code().unwrap_or(-1);
    (combined, code)
}

/// Run `openshell <args>` with a custom config directory so the CLI reads
/// our seeded gateway metadata and edge token instead of the real config.
///
/// Debug logging is on so the CLI records the tunnel handshake. When
/// `ssl_cert_file` is set, the CLI trusts that CA bundle instead of the system
/// store.
#[cfg(feature = "e2e-edge-tunnel")]
async fn run_cli_with_config(
    config_dir: &Path,
    ssl_cert_file: Option<&Path>,
    args: &[&str],
) -> (String, i32) {
    let mut cmd = openshell_cmd();
    cmd.args(args)
        .env("XDG_CONFIG_HOME", config_dir)
        .env("HOME", config_dir)
        .env("RUST_LOG", "openshell_cli=debug,openshell_sdk=debug")
        .env_remove("OPENSHELL_GATEWAY")
        .env_remove("OPENSHELL_GATEWAY_ENDPOINT")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(ca) = ssl_cert_file {
        cmd.env("SSL_CERT_FILE", ca);
    }

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
#[cfg(feature = "e2e-edge-tunnel")]
fn seed_edge_gateway_config(
    config_dir: &Path,
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

/// Where the active e2e gateway is and how to trust it.
#[cfg(feature = "e2e-edge-tunnel")]
struct GatewayTarget {
    endpoint: String,
    /// CA that signed the gateway's server certificate, when the target
    /// registered one. Gateways with a publicly trusted certificate have none.
    ca_cert: Option<PathBuf>,
}

/// Resolve the active gateway from the config the target registered, rather
/// than scraping `gateway info` output.
#[cfg(feature = "e2e-edge-tunnel")]
fn active_gateway_target() -> GatewayTarget {
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .expect("XDG_CONFIG_HOME or HOME must be set");
    let openshell_dir = config_home.join("openshell");

    let name = std::env::var("OPENSHELL_GATEWAY")
        .ok()
        .filter(|name| !name.is_empty())
        .or_else(|| {
            std::fs::read_to_string(openshell_dir.join("active_gateway"))
                .ok()
                .map(|name| name.trim().to_string())
        })
        .expect("no active gateway: set OPENSHELL_GATEWAY or register one");
    let gateway_dir = openshell_dir.join("gateways").join(&name);

    let metadata_path = gateway_dir.join("metadata.json");
    let metadata = std::fs::read_to_string(&metadata_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", metadata_path.display()));
    let metadata: serde_json::Value =
        serde_json::from_str(&metadata).expect("parse gateway metadata");
    let endpoint = metadata["gateway_endpoint"]
        .as_str()
        .unwrap_or_else(|| panic!("no gateway_endpoint in {}", metadata_path.display()))
        .to_string();

    let ca_cert = Some(gateway_dir.join("mtls").join("ca.crt")).filter(|ca| ca.is_file());
    GatewayTarget { endpoint, ca_cert }
}

/// Whether `openshell status` output reports a healthy gateway: a `Status:`
/// line whose value is exactly "Connected" or "Healthy". Substring matches
/// would accept "Disconnected" and "unhealthy".
#[cfg(feature = "e2e-edge-tunnel")]
fn reports_healthy(output: &str) -> bool {
    output.lines().any(|line| {
        line.trim().strip_prefix("Status:").is_some_and(|value| {
            matches!(
                value.trim().to_lowercase().as_str(),
                "connected" | "healthy"
            )
        })
    })
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
/// dummy token, then runs `openshell status` against the live `https://`
/// gateway.
///
/// Note: The dummy token won't be validated (no edge auth middleware on the
/// gateway), but it triggers the CLI's tunnel proxy codepath. The CLI only
/// tunnels over `https://`, so the test fails for a plaintext gateway instead
/// of passing without using the tunnel. It also requires the CLI's debug log
/// to show the completed WebSocket handshake, so a healthy status that did not
/// use the tunnel cannot pass. That depends on a diagnostic line, which the
/// testing strategy RFC (0016) discourages for conformance tests; it is kept
/// here because nothing else observable separates the two paths.
#[cfg(feature = "e2e-edge-tunnel")]
#[tokio::test]
async fn ws_tunnel_status_through_edge_proxy() {
    let (original_status, status_code) = run_cli(&["status"]).await;
    let clean_status = strip_ansi(&original_status);

    // This test needs a healthy gateway to test against.
    assert_eq!(
        status_code, 0,
        "ws_tunnel test needs a healthy gateway, but status failed:\n{clean_status}"
    );
    assert!(
        reports_healthy(&clean_status),
        "ws_tunnel test needs a healthy gateway:\n{clean_status}"
    );

    let GatewayTarget { endpoint, ca_cert } = active_gateway_target();

    // The CLI only routes through the tunnel for https:// gateways.
    assert!(
        endpoint.starts_with("https://"),
        "ws_tunnel test needs an https:// gateway with the WebSocket tunnel enabled, got: {endpoint}\n\
         A plaintext gateway, such as one reused through OPENSHELL_GATEWAY_ENDPOINT endpoint mode, \
         cannot exercise the tunnel. Use a lane-started gateway."
    );

    // A gateway with a lane-local CA is not trusted by the system store, and
    // the tunnel client uses the system store, so point it at that CA. With no
    // registered CA, rely on the system store.
    let tmpdir = tempfile::tempdir().expect("create temp config dir");

    // Seed a temporary config directory with edge auth metadata pointing at
    // the live gateway. The dummy token triggers the WS tunnel codepath
    // without requiring real edge auth middleware.
    seed_edge_gateway_config(
        tmpdir.path(),
        "edge-tunnel-test",
        &endpoint,
        "dummy-test-jwt",
    );

    let (output, code) = run_cli_with_config(
        tmpdir.path(),
        ca_cert.as_deref(),
        &["--gateway", "edge-tunnel-test", "status"],
    )
    .await;

    let clean = strip_ansi(&output);
    assert_eq!(
        code,
        0,
        "openshell status through WS tunnel should exit 0 (trusted CA: {}):\n{clean}",
        ca_cert
            .as_deref()
            .map_or_else(|| "system store".to_string(), |ca| ca.display().to_string())
    );
    // A healthy status alone does not show the tunnel carried it, so require
    // the CLI's own record of the completed WebSocket handshake.
    assert!(
        clean.contains("WebSocket connected to edge"),
        "status should have gone through the WS tunnel:\n{clean}"
    );
    assert!(
        reports_healthy(&clean),
        "status through WS tunnel should report healthy:\n{clean}"
    );
}
