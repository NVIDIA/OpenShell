// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! CLI smoke tests that verify command structure and graceful error handling.
//!
//! These tests do NOT require a running gateway — they exercise the CLI binary
//! directly, validating that the restructured command tree parses correctly and
//! handles edge cases like missing gateway configuration.

use std::process::Stdio;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::output::strip_ansi;

/// Run `openshell <args>` with an isolated (empty) config directory so it
/// cannot discover any real gateway.
async fn run_isolated(args: &[&str]) -> (String, i32) {
    let tmpdir = tempfile::tempdir().expect("create isolated config dir");
    let mut cmd = openshell_cmd();
    cmd.args(args)
        .env("XDG_CONFIG_HOME", tmpdir.path())
        .env("HOME", tmpdir.path())
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

// -------------------------------------------------------------------
// Top-level --help shows the restructured command tree
// -------------------------------------------------------------------

/// `openshell --help` must list the new top-level commands: gateway, status,
/// forward, logs, policy.
#[tokio::test]
async fn help_shows_restructured_commands() {
    let (output, code) = run_isolated(&["--help"]).await;
    assert_eq!(code, 0, "openshell --help should exit 0");

    let clean = strip_ansi(&output);
    for cmd in ["gateway", "status", "sandbox", "forward", "logs", "policy"] {
        assert!(
            clean.contains(cmd),
            "expected '{cmd}' in --help output:\n{clean}"
        );
    }
}

/// `openshell gateway --help` must list registration/auth commands, not
/// service lifecycle commands.
#[tokio::test]
async fn gateway_help_shows_subcommands() {
    let (output, code) = run_isolated(&["gateway", "--help"]).await;
    assert_eq!(code, 0, "openshell gateway --help should exit 0");

    let clean = strip_ansi(&output);
    for sub in ["add", "remove", "login", "logout", "select", "info", "list"] {
        assert!(
            clean.contains(sub),
            "expected '{sub}' in gateway --help output:\n{clean}"
        );
    }

    for removed in ["start", "stop", "destroy"] {
        assert!(
            !clean.contains(removed),
            "did not expect removed gateway lifecycle subcommand '{removed}' in help:\n{clean}"
        );
    }
}

/// `openshell sandbox --help` must list upload and download alongside create,
/// get, list, delete, connect.
#[tokio::test]
async fn sandbox_help_shows_upload_download() {
    let (output, code) = run_isolated(&["sandbox", "--help"]).await;
    assert_eq!(code, 0, "openshell sandbox --help should exit 0");

    let clean = strip_ansi(&output);
    for sub in ["upload", "download", "create", "get", "list", "delete", "connect"] {
        assert!(
            clean.contains(sub),
            "expected '{sub}' in sandbox --help output:\n{clean}"
        );
    }
}

/// `openshell sandbox create --help` must show `--gpu`, `--upload`,
/// `--no-git-ignore`, `--editor`, and `--auto-providers`/`--no-auto-providers`.
#[tokio::test]
async fn sandbox_create_help_shows_new_flags() {
    let (output, code) = run_isolated(&["sandbox", "create", "--help"]).await;
    assert_eq!(code, 0, "openshell sandbox create --help should exit 0");

    let clean = strip_ansi(&output);
    for flag in [
        "--gpu",
        "--upload",
        "--no-git-ignore",
        "--editor",
        "--auto-providers",
        "--no-auto-providers",
    ] {
        assert!(
            clean.contains(flag),
            "expected '{flag}' in sandbox create --help:\n{clean}"
        );
    }
}

/// `openshell sandbox connect --help` must show `--editor`.
#[tokio::test]
async fn sandbox_connect_help_shows_editor_flag() {
    let (output, code) = run_isolated(&["sandbox", "connect", "--help"]).await;
    assert_eq!(code, 0, "openshell sandbox connect --help should exit 0");

    let clean = strip_ansi(&output);
    assert!(
        clean.contains("--editor"),
        "expected '--editor' in sandbox connect --help:\n{clean}"
    );
}

/// Removed gateway lifecycle subcommands should fail during parsing.
#[tokio::test]
async fn gateway_lifecycle_subcommands_are_removed() {
    for subcommand in ["start", "stop", "destroy"] {
        let (output, code) = run_isolated(&["gateway", subcommand, "--help"]).await;
        assert!(
            code != 0,
            "openshell gateway {subcommand} should fail after lifecycle command removal"
        );

        let clean = strip_ansi(&output);
        assert!(
            clean.contains("unrecognized subcommand") || clean.contains("error:"),
            "expected parser error for removed gateway subcommand '{subcommand}':\n{clean}"
        );
    }
}

// -------------------------------------------------------------------
// Graceful handling: `openshell status` without a gateway
// -------------------------------------------------------------------

/// `openshell status` with no gateway configured should exit 0 and print a
/// friendly message instead of erroring.
#[tokio::test]
async fn status_without_gateway_prints_friendly_message() {
    let (output, code) = run_isolated(&["status"]).await;
    assert_eq!(
        code, 0,
        "openshell status should exit 0 even without a gateway, got output:\n{output}"
    );

    let clean = strip_ansi(&output);
    assert!(
        clean.contains("No gateway configured"),
        "expected 'No gateway configured' in status output:\n{clean}"
    );
    assert!(
        clean.contains("openshell gateway add <endpoint>"),
        "expected hint to register a gateway:\n{clean}"
    );
}
