// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::Ordering;
use std::time::Duration;

use openshell_e2e::harness::binary::openshell_tty_cmd;
use openshell_e2e::harness::certs::{generate_test_certs, install_rustls_provider};
use openshell_e2e::harness::mock_gateway::{
    start_gateway, start_gateway_with_edge_token, start_gateway_with_mtls,
    start_gateway_with_tls_and_bearer,
};
use openshell_e2e::harness::output::strip_ansi;
use tokio::time::{sleep, timeout};

fn normalize_output(output: &str) -> String {
    let stripped = strip_ansi(output).replace('\r', "");
    let mut cleaned = String::with_capacity(stripped.len());

    for ch in stripped.chars() {
        match ch {
            '\u{8}' => {
                cleaned.pop();
            }
            '\u{4}' => {}
            _ => cleaned.push(ch),
        }
    }

    cleaned
}

#[derive(Clone)]
struct GatewayConfig<'a> {
    name: &'a str,
    endpoint: &'a str,
    auth_mode: Option<&'a str>,
    edge_token: Option<&'a str>,
}

fn seed_gateway_config(config_dir: &Path, active_gateway: &str, gateways: &[GatewayConfig<'_>]) {
    let openshell_dir = config_dir.join("openshell");
    let gateways_root = openshell_dir.join("gateways");
    std::fs::create_dir_all(&gateways_root).expect("create gateways dir");
    std::fs::write(openshell_dir.join("active_gateway"), active_gateway)
        .expect("write active gateway");

    for gateway in gateways {
        let gateway_path = gateways_root.join(gateway.name);
        std::fs::create_dir_all(&gateway_path).expect("create gateway dir");
        let mut metadata = serde_json::json!({
            "name": gateway.name,
            "gateway_endpoint": gateway.endpoint,
            "is_remote": false,
            "gateway_port": 0,
        });
        if let Some(auth_mode) = gateway.auth_mode {
            metadata["auth_mode"] = serde_json::Value::from(auth_mode);
        }
        std::fs::write(
            gateway_path.join("metadata.json"),
            serde_json::to_vec_pretty(&metadata).expect("serialize metadata"),
        )
        .expect("write metadata");

        if let Some(token) = gateway.edge_token {
            std::fs::write(gateway_path.join("edge_token"), token).expect("write edge token");
        }
    }
}
/// Write mTLS material into the gateway's mtls/ subdirectory.
/// `client_cert_pem`/`client_key_pem` are `None` for OIDC (server-TLS only).
fn write_gateway_certs(
    config_dir: &Path,
    gateway_name: &str,
    ca_pem: &str,
    client_cert_pem: Option<&str>,
    client_key_pem: Option<&str>,
) {
    let mtls_dir = config_dir
        .join("openshell")
        .join("gateways")
        .join(gateway_name)
        .join("mtls");
    std::fs::create_dir_all(&mtls_dir).unwrap();
    std::fs::write(mtls_dir.join("ca.crt"), ca_pem).unwrap();
    if let (Some(cert), Some(key)) = (client_cert_pem, client_key_pem) {
        std::fs::write(mtls_dir.join("tls.crt"), cert).unwrap();
        std::fs::write(mtls_dir.join("tls.key"), key).unwrap();
    }
}

/// Write an OIDC token JSON file for the gateway.
fn write_oidc_token(config_dir: &Path, gateway_name: &str, access_token: &str) {
    let gateway_dir = config_dir.join("openshell").join("gateways").join(gateway_name);
    std::fs::create_dir_all(&gateway_dir).unwrap();
    let token = serde_json::json!({
        "access_token": access_token,
        "issuer": "https://test.example.com",
        "client_id": "test-client",
        "expires_at": 9_999_999_999u64,
    });
    std::fs::write(
        gateway_dir.join("oidc_token.json"),
        serde_json::to_vec_pretty(&token).unwrap(),
    )
    .unwrap();
}

async fn run_tui_connect(config_dir: &Path, gateway_name: &str) -> String {
    let mut cmd = openshell_tty_cmd(&["--gateway", gateway_name, "term", "--theme", "dark"]);
    cmd.env("XDG_CONFIG_HOME", config_dir)
        .env("HOME", config_dir)
        .env("TERM", "xterm-256color")
        .env("COLUMNS", "140")
        .env("LINES", "40")
        .env_remove("OPENSHELL_GATEWAY")
        .env_remove("OPENSHELL_GATEWAY_ENDPOINT")
        // stdin kept piped so script does not see EOF and close the PTY
        // master prematurely before the TUI has connected.
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn openshell term");

    // The TUI calls refresh_data (health + providers + sandboxes) on startup
    // before entering the event loop.  A few seconds is ample for a loopback
    // gRPC connection to complete that sequence.
    sleep(Duration::from_secs(3)).await;

    // Kill rather than sending `q`: crossterm's event::poll is a blocking
    // call that starves other tasks on a single-thread runtime, so the event
    // loop may never process the keystroke.  We only need proof of connection
    // (provider_calls > 0), not graceful exit.
    child.kill().await.ok();

    let output = timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .expect("openshell term should exit after kill")
        .expect("collect openshell term output");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    normalize_output(&combined)
}

#[tokio::test]
async fn tui_connects_to_plaintext_gateway() {
    let gw = start_gateway("provider-plaintext").await;

    let tmpdir = tempfile::tempdir().expect("create temp config dir");
    seed_gateway_config(
        tmpdir.path(),
        "my-gw",
        &[GatewayConfig {
            name: "my-gw",
            endpoint: &gw.endpoint,
            auth_mode: Some("plaintext"),
            edge_token: None,
        }],
    );

    let output = run_tui_connect(tmpdir.path(), "my-gw").await;

    gw.task.abort();

    assert!(
        gw.provider_calls.load(Ordering::SeqCst) > 0,
        "TUI should query providers from the plaintext gateway:\n{output}"
    );
}

#[tokio::test]
async fn tui_connects_to_edge_gateway_with_token() {
    let gw = start_gateway_with_edge_token("provider-edge", "dummy-edge-token").await;

    let tmpdir = tempfile::tempdir().expect("create temp config dir");
    seed_gateway_config(
        tmpdir.path(),
        "my-gw",
        &[GatewayConfig {
            name: "my-gw",
            endpoint: &gw.endpoint,
            auth_mode: Some("cloudflare_jwt"),
            edge_token: Some("dummy-edge-token"),
        }],
    );

    let output = run_tui_connect(tmpdir.path(), "my-gw").await;

    gw.task.abort();

    assert!(
        gw.provider_calls.load(Ordering::SeqCst) > 0,
        "TUI should query providers from the edge-auth gateway:\n{output}"
    );
}

#[tokio::test]
async fn tui_connects_to_http_endpoint_without_auth_mode() {
    let gw = start_gateway("provider-http").await;

    let tmpdir = tempfile::tempdir().expect("create temp config dir");
    seed_gateway_config(
        tmpdir.path(),
        "my-gw",
        &[GatewayConfig {
            name: "my-gw",
            endpoint: &gw.endpoint,
            auth_mode: None,
            edge_token: None,
        }],
    );

    let output = run_tui_connect(tmpdir.path(), "my-gw").await;

    gw.task.abort();

    assert!(
        gw.provider_calls.load(Ordering::SeqCst) > 0,
        "TUI should query providers from the http-endpoint gateway:\n{output}"
    );
}

#[tokio::test]
async fn tui_connects_to_oidc_gateway() {
    install_rustls_provider();
    let certs = generate_test_certs();
    let gw = start_gateway_with_tls_and_bearer(
        "provider-oidc",
        &certs.server_cert_pem,
        &certs.server_key_pem,
        "dummy-oidc-token",
    )
    .await;

    let tmpdir = tempfile::tempdir().expect("create temp config dir");
    seed_gateway_config(
        tmpdir.path(),
        "my-gw",
        &[GatewayConfig {
            name: "my-gw",
            endpoint: &gw.endpoint,
            auth_mode: Some("oidc"),
            edge_token: None,
        }],
    );
    write_gateway_certs(tmpdir.path(), "my-gw", &certs.ca_pem, None, None);
    write_oidc_token(tmpdir.path(), "my-gw", "dummy-oidc-token");

    let output = run_tui_connect(tmpdir.path(), "my-gw").await;
    gw.task.abort();

    assert!(
        gw.provider_calls.load(Ordering::SeqCst) > 0,
        "TUI should authenticate and query providers from the OIDC gateway:\n{output}"
    );
}

#[tokio::test]
async fn tui_connects_to_mtls_gateway() {
    install_rustls_provider();
    let certs = generate_test_certs();
    let gw = start_gateway_with_mtls(
        "provider-mtls",
        &certs.ca_pem,
        &certs.server_cert_pem,
        &certs.server_key_pem,
    )
    .await;

    let tmpdir = tempfile::tempdir().expect("create temp config dir");
    seed_gateway_config(
        tmpdir.path(),
        "my-gw",
        &[GatewayConfig {
            name: "my-gw",
            endpoint: &gw.endpoint,
            auth_mode: None,
            edge_token: None,
        }],
    );
    write_gateway_certs(
        tmpdir.path(),
        "my-gw",
        &certs.ca_pem,
        Some(&certs.client_cert_pem),
        Some(&certs.client_key_pem),
    );

    let output = run_tui_connect(tmpdir.path(), "my-gw").await;
    gw.task.abort();

    assert!(
        gw.provider_calls.load(Ordering::SeqCst) > 0,
        "TUI should complete mTLS handshake and query providers:\n{output}"
    );
}
