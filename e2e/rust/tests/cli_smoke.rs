// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! CLI smoke tests that verify command structure and graceful error handling.
//!
//! These tests do NOT require a running gateway — they exercise the CLI binary
//! directly, validating that the restructured command tree parses correctly and
//! handles edge cases like missing gateway configuration.

use std::process::Stdio;

use nemoclaw_e2e::harness::binary::nemoclaw_cmd;
use nemoclaw_e2e::harness::output::strip_ansi;

/// Run `nemoclaw <args>` with an isolated (empty) config directory so it
/// cannot discover any real gateway.
async fn run_isolated(args: &[&str]) -> (String, i32) {
    let tmpdir = tempfile::tempdir().expect("create isolated config dir");
    let mut cmd = nemoclaw_cmd();
    cmd.args(args)
        .env("XDG_CONFIG_HOME", tmpdir.path())
        .env("HOME", tmpdir.path())
        .env_remove("NEMOCLAW_CLUSTER")
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
// Top-level --help shows the restructured command tree
// -------------------------------------------------------------------

/// `nemoclaw --help` must list the new top-level commands: gateway, status,
/// forward, logs, policy.
#[tokio::test]
async fn help_shows_restructured_commands() {
    let (output, code) = run_isolated(&["--help"]).await;
    assert_eq!(code, 0, "nemoclaw --help should exit 0");

    let clean = strip_ansi(&output);
    for cmd in ["gateway", "status", "sandbox", "forward", "logs", "policy"] {
        assert!(
            clean.contains(cmd),
            "expected '{cmd}' in --help output:\n{clean}"
        );
    }
}

/// `nemoclaw gateway --help` must list start, stop, destroy, select, info.
#[tokio::test]
async fn gateway_help_shows_subcommands() {
    let (output, code) = run_isolated(&["gateway", "--help"]).await;
    assert_eq!(code, 0, "nemoclaw gateway --help should exit 0");

    let clean = strip_ansi(&output);
    for sub in ["start", "stop", "destroy", "select", "info"] {
        assert!(
            clean.contains(sub),
            "expected '{sub}' in gateway --help output:\n{clean}"
        );
    }
}

/// `nemoclaw sandbox --help` must list upload and download alongside create,
/// get, list, delete, connect.
#[tokio::test]
async fn sandbox_help_shows_upload_download() {
    let (output, code) = run_isolated(&["sandbox", "--help"]).await;
    assert_eq!(code, 0, "nemoclaw sandbox --help should exit 0");

    let clean = strip_ansi(&output);
    for sub in ["upload", "download", "create", "get", "list", "delete", "connect"] {
        assert!(
            clean.contains(sub),
            "expected '{sub}' in sandbox --help output:\n{clean}"
        );
    }
}

/// `nemoclaw sandbox create --help` must show `--upload`, `--no-git-ignore`,
/// `--bootstrap`/`--no-bootstrap`, and `--auto-providers`/`--no-auto-providers`.
#[tokio::test]
async fn sandbox_create_help_shows_new_flags() {
    let (output, code) = run_isolated(&["sandbox", "create", "--help"]).await;
    assert_eq!(code, 0, "nemoclaw sandbox create --help should exit 0");

    let clean = strip_ansi(&output);
    for flag in [
        "--upload",
        "--no-git-ignore",
        "--bootstrap",
        "--no-bootstrap",
        "--auto-providers",
        "--no-auto-providers",
    ] {
        assert!(
            clean.contains(flag),
            "expected '{flag}' in sandbox create --help:\n{clean}"
        );
    }
}

/// `nemoclaw gateway start --help` must show `--recreate`.
#[tokio::test]
async fn gateway_start_help_shows_recreate() {
    let (output, code) = run_isolated(&["gateway", "start", "--help"]).await;
    assert_eq!(code, 0, "nemoclaw gateway start --help should exit 0");

    let clean = strip_ansi(&output);
    assert!(
        clean.contains("--recreate"),
        "expected '--recreate' in gateway start --help:\n{clean}"
    );
}

// -------------------------------------------------------------------
// Graceful handling: `nemoclaw status` without a gateway
// -------------------------------------------------------------------

/// `nemoclaw status` with no gateway configured should exit 0 and print a
/// friendly message instead of erroring.
#[tokio::test]
async fn status_without_gateway_prints_friendly_message() {
    let (output, code) = run_isolated(&["status"]).await;
    assert_eq!(
        code, 0,
        "nemoclaw status should exit 0 even without a gateway, got output:\n{output}"
    );

    let clean = strip_ansi(&output);
    assert!(
        clean.contains("No gateway configured"),
        "expected 'No gateway configured' in status output:\n{clean}"
    );
    assert!(
        clean.contains("nemoclaw gateway start"),
        "expected hint to run 'nemoclaw gateway start':\n{clean}"
    );
}

// -------------------------------------------------------------------
// Hidden backwards-compat: `cluster admin deploy` is still parseable
// -------------------------------------------------------------------

/// `nemoclaw cluster admin deploy --help` should still work (hidden alias).
#[tokio::test]
async fn cluster_admin_deploy_help_is_accessible() {
    let (output, code) = run_isolated(&["cluster", "admin", "deploy", "--help"]).await;
    assert_eq!(
        code, 0,
        "cluster admin deploy --help should exit 0:\n{output}"
    );

    let clean = strip_ansi(&output);
    // Should show the deploy options (name, remote, ssh-key, etc.)
    assert!(
        clean.contains("--name") || clean.contains("--remote"),
        "expected deploy flags in cluster admin deploy --help:\n{clean}"
    );
}
