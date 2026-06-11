// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! CLI smoke tests that verify command structure and graceful error handling.
//!
//! These tests do NOT require a running gateway — they exercise the CLI binary
//! directly, validating that the restructured command tree parses correctly and
//! handles edge cases like missing gateway configuration.

use std::fs;
use std::path::Path;
use std::process::Stdio;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::output::strip_ansi;

async fn run_with_config(
    config_dir: &Path,
    system_dir: Option<&Path>,
    args: &[&str],
) -> (String, i32) {
    let mut cmd = openshell_cmd();
    cmd.args(args)
        .env("XDG_CONFIG_HOME", config_dir)
        .env("HOME", config_dir)
        .env_remove("OPENSHELL_GATEWAY")
        .env_remove("OPENSHELL_GATEWAY_ENDPOINT")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(system_dir) = system_dir {
        cmd.env("OPENSHELL_SYSTEM_GATEWAY_DIR", system_dir);
    } else {
        cmd.env_remove("OPENSHELL_SYSTEM_GATEWAY_DIR");
    }

    let output = cmd.output().await.expect("spawn openshell");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");
    let code = output.status.code().unwrap_or(-1);
    (combined, code)
}

/// Run `openshell <args>` with an isolated (empty) config directory so it
/// cannot discover any real gateway.
async fn run_isolated(args: &[&str]) -> (String, i32) {
    let tmpdir = tempfile::tempdir().expect("create isolated config dir");
    let system_dir = tempfile::tempdir().expect("create isolated system config dir");
    run_with_config(tmpdir.path(), Some(system_dir.path()), args).await
}

fn write_gateway_metadata(
    root: &Path,
    name: &str,
    endpoint: &str,
    gateway_port: u16,
    is_remote: bool,
    auth_mode: &str,
) {
    let gateway_dir = root.join("gateways").join(name);
    fs::create_dir_all(&gateway_dir).expect("create gateway dir");
    let metadata = serde_json::json!({
        "name": name,
        "gateway_endpoint": endpoint,
        "gateway_port": gateway_port,
        "is_remote": is_remote,
        "auth_mode": auth_mode,
    });
    fs::write(
        gateway_dir.join("metadata.json"),
        serde_json::to_vec_pretty(&metadata).expect("serialize gateway metadata"),
    )
    .expect("write gateway metadata");
}

fn write_user_gateway_metadata(
    config_dir: &Path,
    name: &str,
    endpoint: &str,
    gateway_port: u16,
    is_remote: bool,
    auth_mode: &str,
) {
    write_gateway_metadata(
        &config_dir.join("openshell"),
        name,
        endpoint,
        gateway_port,
        is_remote,
        auth_mode,
    );
}

fn write_system_gateway_metadata(
    system_dir: &Path,
    name: &str,
    endpoint: &str,
    gateway_port: u16,
    is_remote: bool,
    auth_mode: &str,
) {
    write_gateway_metadata(
        system_dir,
        name,
        endpoint,
        gateway_port,
        is_remote,
        auth_mode,
    );
}

fn write_active_gateway(config_dir: &Path, name: &str) {
    let active_path = config_dir.join("openshell").join("active_gateway");
    fs::create_dir_all(active_path.parent().expect("active gateway parent"))
        .expect("create active gateway parent");
    fs::write(active_path, format!("{name}\n")).expect("write active gateway");
}

fn seed_gateway_sources(config_dir: &Path, system_dir: &Path) {
    write_user_gateway_metadata(
        config_dir,
        "alpha",
        "https://alpha.example.com",
        443,
        true,
        "cloudflare_jwt",
    );
    write_system_gateway_metadata(
        system_dir,
        "beta",
        "http://127.0.0.1:17670",
        17670,
        false,
        "plaintext",
    );
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
    for sub in [
        "upload", "download", "create", "get", "list", "delete", "connect",
    ] {
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

// -------------------------------------------------------------------
// Gateway list source indicators
// -------------------------------------------------------------------

#[tokio::test]
async fn gateway_list_table_shows_user_and_system_sources() {
    let config_dir = tempfile::tempdir().expect("create config dir");
    let system_dir = tempfile::tempdir().expect("create system dir");
    seed_gateway_sources(config_dir.path(), system_dir.path());
    write_active_gateway(config_dir.path(), "alpha");

    let (output, code) = run_with_config(
        config_dir.path(),
        Some(system_dir.path()),
        &["gateway", "list"],
    )
    .await;
    assert_eq!(code, 0, "gateway list should exit 0:\n{output}");

    let clean = strip_ansi(&output);
    assert!(clean.contains("SOURCE"), "expected SOURCE column:\n{clean}");

    let alpha_line = clean
        .lines()
        .find(|line| line.contains("alpha"))
        .expect("find alpha row");
    assert!(
        alpha_line.contains("user"),
        "expected alpha row to show user source:\n{clean}"
    );

    let beta_line = clean
        .lines()
        .find(|line| line.contains("beta"))
        .expect("find beta row");
    assert!(
        beta_line.contains("system"),
        "expected beta row to show system source:\n{clean}"
    );
}

#[tokio::test]
async fn gateway_list_json_includes_user_and_system_sources() {
    let config_dir = tempfile::tempdir().expect("create config dir");
    let system_dir = tempfile::tempdir().expect("create system dir");
    seed_gateway_sources(config_dir.path(), system_dir.path());

    let (output, code) = run_with_config(
        config_dir.path(),
        Some(system_dir.path()),
        &["gateway", "list", "-o", "json"],
    )
    .await;
    assert_eq!(code, 0, "gateway list -o json should exit 0:\n{output}");

    let items: serde_json::Value = serde_json::from_str(&output).expect("parse gateway list json");
    let items = items.as_array().expect("gateway list json array");
    assert_eq!(items.len(), 2, "expected two gateways in json output");

    let alpha = items
        .iter()
        .find(|item| item["name"] == "alpha")
        .expect("find alpha entry");
    assert_eq!(alpha["source"], "user");

    let beta = items
        .iter()
        .find(|item| item["name"] == "beta")
        .expect("find beta entry");
    assert_eq!(beta["source"], "system");
}

#[tokio::test]
async fn gateway_add_can_shadow_system_gateway_with_user_registration() {
    let config_dir = tempfile::tempdir().expect("create config dir");
    let system_dir = tempfile::tempdir().expect("create system dir");
    write_system_gateway_metadata(
        system_dir.path(),
        "beta",
        "http://127.0.0.1:17670",
        17670,
        false,
        "plaintext",
    );

    let (add_output, add_code) = run_with_config(
        config_dir.path(),
        Some(system_dir.path()),
        &[
            "gateway",
            "add",
            "http://127.0.0.1:17671",
            "--name",
            "beta",
        ],
    )
    .await;
    assert_eq!(
        add_code, 0,
        "gateway add should allow a user registration to shadow a system gateway:\n{add_output}"
    );

    let (list_output, list_code) = run_with_config(
        config_dir.path(),
        Some(system_dir.path()),
        &["gateway", "list", "-o", "json"],
    )
    .await;
    assert_eq!(
        list_code, 0,
        "gateway list -o json should exit 0:\n{list_output}"
    );

    let items: serde_json::Value =
        serde_json::from_str(&list_output).expect("parse gateway list json");
    let beta = items
        .as_array()
        .expect("gateway list json array")
        .iter()
        .find(|item| item["name"] == "beta")
        .expect("find beta entry");
    assert_eq!(beta["source"], "user");
    assert_eq!(beta["endpoint"], "http://127.0.0.1:17671");
}

#[tokio::test]
async fn gateway_remove_rejects_system_only_registration_and_preserves_entry() {
    let config_dir = tempfile::tempdir().expect("create config dir");
    let system_dir = tempfile::tempdir().expect("create system dir");
    write_system_gateway_metadata(
        system_dir.path(),
        "beta",
        "http://127.0.0.1:17670",
        17670,
        false,
        "plaintext",
    );

    let (remove_output, remove_code) = run_with_config(
        config_dir.path(),
        Some(system_dir.path()),
        &["gateway", "remove", "beta"],
    )
    .await;
    assert_ne!(
        remove_code, 0,
        "gateway remove should reject system-only registrations:\n{remove_output}"
    );
    let clean_remove = strip_ansi(&remove_output);
    let normalized_remove = clean_remove
        .replace(['│', '×'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        normalized_remove
            .contains("installed by the system and cannot be removed from user config"),
        "expected system-only removal guidance:\n{clean_remove}"
    );

    let (list_output, list_code) = run_with_config(
        config_dir.path(),
        Some(system_dir.path()),
        &["gateway", "list", "-o", "json"],
    )
    .await;
    assert_eq!(
        list_code, 0,
        "gateway list -o json should still succeed:\n{list_output}"
    );

    let items: serde_json::Value =
        serde_json::from_str(&list_output).expect("parse gateway list json");
    let beta = items
        .as_array()
        .expect("gateway list json array")
        .iter()
        .find(|item| item["name"] == "beta")
        .expect("find beta entry after failed remove");
    assert_eq!(beta["source"], "system");
    assert_eq!(beta["endpoint"], "http://127.0.0.1:17670");
}
