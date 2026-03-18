// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! CLI smoke tests for Cloudflare tunnel auth commands.
//!
//! These tests do NOT require a running gateway — they exercise the CLI binary
//! directly, validating that the new Cloudflare-related commands and flags
//! parse correctly and behave as expected.

use std::process::Stdio;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::output::strip_ansi;

/// Run `openshell <args>` with an isolated (empty) config directory so it
/// cannot discover any real gateway.  Returns (combined stdout+stderr, exit code).
async fn run_isolated(args: &[&str]) -> (String, i32) {
    let tmpdir = tempfile::tempdir().expect("create isolated config dir");
    let mut cmd = openshell_cmd();
    cmd.args(args)
        .env("XDG_CONFIG_HOME", tmpdir.path())
        .env("HOME", tmpdir.path())
        .env_remove("OPENSHELL_GATEWAY")
        // Suppress browser popup during auth flow.
        .env("OPENSHELL_NO_BROWSER", "1")
        // Use a closed stdin so auth prompts don't hang the test.
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd.output().await.expect("spawn openshell");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");
    let code = output.status.code().unwrap_or(-1);
    (combined, code)
}

/// Run `openshell <args>` with a given tmpdir as config (for persisting state
/// across multiple commands).  Returns (combined stdout+stderr, exit code).
async fn run_with_config(tmpdir: &std::path::Path, args: &[&str]) -> (String, i32) {
    let mut cmd = openshell_cmd();
    cmd.args(args)
        .env("XDG_CONFIG_HOME", tmpdir)
        .env("HOME", tmpdir)
        .env_remove("OPENSHELL_GATEWAY")
        // Suppress browser popup during auth flow.
        .env("OPENSHELL_NO_BROWSER", "1")
        // Use a closed stdin so auth prompts don't hang the test.
        .stdin(Stdio::null())
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
// Test 8: `--plaintext` flag is recognized
// -------------------------------------------------------------------

/// `openshell gateway start --help` must show `--plaintext`.
#[tokio::test]
async fn gateway_start_help_shows_plaintext() {
    let (output, code) = run_isolated(&["gateway", "start", "--help"]).await;
    assert_eq!(code, 0, "gateway start --help should exit 0:\n{output}");

    let clean = strip_ansi(&output);
    assert!(
        clean.contains("--plaintext"),
        "expected '--plaintext' in gateway start --help output:\n{clean}"
    );
}

// -------------------------------------------------------------------
// Test 9: `gateway add` and `gateway login` are recognized
// -------------------------------------------------------------------

/// `openshell gateway --help` must list `add` and `login` subcommands.
#[tokio::test]
async fn gateway_help_shows_add_and_login() {
    let (output, code) = run_isolated(&["gateway", "--help"]).await;
    assert_eq!(code, 0, "gateway --help should exit 0:\n{output}");

    let clean = strip_ansi(&output);
    assert!(
        clean.contains("add"),
        "expected 'add' in gateway --help output:\n{clean}"
    );
    assert!(
        clean.contains("login"),
        "expected 'login' in gateway --help output:\n{clean}"
    );
}

/// `openshell gateway add --help` must show the endpoint arg and gateway-type flags.
#[tokio::test]
async fn gateway_add_help_shows_flags() {
    let (output, code) = run_isolated(&["gateway", "add", "--help"]).await;
    assert_eq!(code, 0, "gateway add --help should exit 0:\n{output}");

    let clean = strip_ansi(&output);
    assert!(
        clean.contains("--name"),
        "expected '--name' in gateway add --help:\n{clean}"
    );
    assert!(
        clean.contains("--remote"),
        "expected '--remote' in gateway add --help:\n{clean}"
    );
    assert!(
        clean.contains("--ssh-key"),
        "expected '--ssh-key' in gateway add --help:\n{clean}"
    );
    assert!(
        clean.contains("--local"),
        "expected '--local' in gateway add --help:\n{clean}"
    );
    assert!(
        // The positional argument for the endpoint
        clean.contains("endpoint") || clean.contains("<ENDPOINT>"),
        "expected endpoint argument in gateway add --help:\n{clean}"
    );
}

/// `openshell gateway login --help` is recognized.
#[tokio::test]
async fn gateway_login_help_is_recognized() {
    let (output, code) = run_isolated(&["gateway", "login", "--help"]).await;
    assert_eq!(code, 0, "gateway login --help should exit 0:\n{output}");

    let clean = strip_ansi(&output);
    // Should mention authenticating or Cloudflare
    assert!(
        clean.to_lowercase().contains("authenticat") || clean.to_lowercase().contains("cloudflare")
            || clean.to_lowercase().contains("login") || clean.to_lowercase().contains("browser"),
        "expected auth-related text in gateway login --help:\n{clean}"
    );
}

// -------------------------------------------------------------------
// Test 10: `gateway add` creates metadata with cloudflare_jwt
// -------------------------------------------------------------------

/// `openshell gateway add <endpoint>` (cloud gateway) should:
/// - Create cluster metadata with auth_mode = "cloudflare_jwt"
/// - Set the gateway as active
/// - Attempt browser authentication (which will fail in CI — non-fatal)
#[tokio::test]
async fn gateway_add_creates_cf_metadata() {
    let tmpdir = tempfile::tempdir().expect("create config dir");

    let (output, code) = run_with_config(
        tmpdir.path(),
        &[
            "gateway",
            "add",
            "https://my-gateway.example.com",
            "--name",
            "test-cf-gw",
        ],
    )
    .await;

    assert_eq!(
        code, 0,
        "gateway add should exit 0 (auth failure is non-fatal):\n{output}"
    );

    // Verify the metadata file was written.
    let metadata_path = tmpdir
        .path()
        .join("openshell")
        .join("gateways")
        .join("test-cf-gw")
        .join("metadata.json");
    assert!(
        metadata_path.exists(),
        "metadata file should exist at {}",
        metadata_path.display()
    );

    let metadata_content = std::fs::read_to_string(&metadata_path).expect("read metadata");
    let metadata: serde_json::Value =
        serde_json::from_str(&metadata_content).expect("parse metadata JSON");

    assert_eq!(
        metadata["auth_mode"].as_str(),
        Some("cloudflare_jwt"),
        "auth_mode should be 'cloudflare_jwt', got: {metadata_content}"
    );
    assert_eq!(
        metadata["gateway_endpoint"].as_str(),
        Some("https://my-gateway.example.com"),
        "gateway_endpoint should match the provided URL"
    );
    assert_eq!(
        metadata["name"].as_str(),
        Some("test-cf-gw"),
        "name should match --name flag"
    );
    assert_eq!(
        metadata["is_remote"].as_bool(),
        Some(true),
        "CF gateway should be marked as remote"
    );

    // Verify the gateway was set as active.
    let active_path = tmpdir
        .path()
        .join("openshell")
        .join("active_gateway");
    assert!(
        active_path.exists(),
        "active_gateway file should exist at {}",
        active_path.display()
    );
    let active = std::fs::read_to_string(&active_path).expect("read active_gateway");
    assert_eq!(
        active.trim(),
        "test-cf-gw",
        "active gateway should be 'test-cf-gw'"
    );

    // Verify the output mentions the gateway was added.
    let clean = strip_ansi(&output);
    assert!(
        clean.contains("test-cf-gw") && clean.contains("added"),
        "output should confirm gateway was added:\n{clean}"
    );
}

/// `gateway add` without `--name` should derive a name from the hostname.
#[tokio::test]
async fn gateway_add_derives_name_from_hostname() {
    let tmpdir = tempfile::tempdir().expect("create config dir");

    let (output, code) = run_with_config(
        tmpdir.path(),
        &[
            "gateway",
            "add",
            "https://my-special-gateway.brevlab.com",
        ],
    )
    .await;

    assert_eq!(
        code, 0,
        "gateway add should exit 0:\n{output}"
    );

    // The derived name should be the hostname.
    let metadata_path = tmpdir
        .path()
        .join("openshell")
        .join("gateways")
        .join("my-special-gateway.brevlab.com")
        .join("metadata.json");
    assert!(
        metadata_path.exists(),
        "metadata file should exist with hostname-derived name at {}",
        metadata_path.display()
    );
}

// -------------------------------------------------------------------
// Test 11: `gateway add` flag constraints
// -------------------------------------------------------------------

/// `--remote` and `--local` are mutually exclusive.
#[tokio::test]
async fn gateway_add_remote_and_local_conflict() {
    let (output, code) = run_isolated(&[
        "gateway",
        "add",
        "https://example.com",
        "--remote",
        "user@host",
        "--local",
    ])
    .await;

    assert_ne!(
        code, 0,
        "--remote and --local together should fail:\n{output}"
    );
}

/// `--ssh-key` requires `--remote`.
#[tokio::test]
async fn gateway_add_ssh_key_requires_remote() {
    let (output, code) = run_isolated(&[
        "gateway",
        "add",
        "https://example.com",
        "--ssh-key",
        "/tmp/fake-key",
    ])
    .await;

    assert_ne!(
        code, 0,
        "--ssh-key without --remote should fail:\n{output}"
    );
}

// -------------------------------------------------------------------
// Test 12: `gateway add` rejects duplicate names
// -------------------------------------------------------------------

/// Adding a gateway with a name that already exists should fail.
#[tokio::test]
async fn gateway_add_rejects_duplicate_name() {
    let tmpdir = tempfile::tempdir().expect("create config dir");

    // First add should succeed.
    let (output, code) = run_with_config(
        tmpdir.path(),
        &[
            "gateway",
            "add",
            "https://first.example.com",
            "--name",
            "my-gw",
        ],
    )
    .await;
    assert_eq!(code, 0, "first gateway add should succeed:\n{output}");

    // Second add with the same name should fail.
    let (output, code) = run_with_config(
        tmpdir.path(),
        &[
            "gateway",
            "add",
            "https://second.example.com",
            "--name",
            "my-gw",
        ],
    )
    .await;
    assert_ne!(
        code, 0,
        "duplicate gateway add should fail:\n{output}"
    );

    let clean = strip_ansi(&output);
    assert!(
        clean.contains("already exists"),
        "error should mention 'already exists':\n{clean}"
    );
}

// -------------------------------------------------------------------
// Test 13: `gateway add ssh://` shorthand constraints
// -------------------------------------------------------------------

/// `ssh://` endpoint with `--local` should fail.
#[tokio::test]
async fn gateway_add_ssh_url_conflicts_with_local() {
    let (output, code) = run_isolated(&[
        "gateway",
        "add",
        "ssh://user@host:8080",
        "--local",
    ])
    .await;

    assert_ne!(
        code, 0,
        "ssh:// with --local should fail:\n{output}"
    );
}

/// `ssh://` endpoint with `--remote` should fail (redundant).
#[tokio::test]
async fn gateway_add_ssh_url_conflicts_with_remote() {
    let (output, code) = run_isolated(&[
        "gateway",
        "add",
        "ssh://user@host:8080",
        "--remote",
        "user@host",
    ])
    .await;

    assert_ne!(
        code, 0,
        "ssh:// with --remote should fail:\n{output}"
    );
}

/// `ssh://` endpoint without a port should fail.
#[tokio::test]
async fn gateway_add_ssh_url_requires_port() {
    let (output, code) = run_isolated(&[
        "gateway",
        "add",
        "ssh://user@host",
    ])
    .await;

    assert_ne!(
        code, 0,
        "ssh:// without port should fail:\n{output}"
    );

    let clean = strip_ansi(&output);
    assert!(
        clean.contains("port"),
        "error should mention port:\n{clean}"
    );
}

