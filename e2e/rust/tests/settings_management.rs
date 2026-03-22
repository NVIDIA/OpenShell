// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E tests for sandbox/global settings CLI workflows.
//!
//! Covers:
//! - Sandbox settings start as `<unset>`
//! - Sandbox setting set + read
//! - Global override blocks sandbox writes for that key
//! - Global get + global delete
//! - Sandbox-level control resumes after global delete

use std::process::Stdio;
use std::sync::Mutex;
use std::time::Duration;

use openshell_e2e::harness::binary::{openshell_bin, openshell_cmd};
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tokio::time::{Instant, sleep};

const TEST_KEY: &str = "dummy_bool";
static SETTINGS_E2E_LOCK: Mutex<()> = Mutex::new(());

struct CliResult {
    clean_output: String,
    success: bool,
    exit_code: Option<i32>,
}

/// Best-effort global setting cleanup that runs even on test panic.
struct GlobalSettingCleanup {
    key: &'static str,
}

impl GlobalSettingCleanup {
    fn new(key: &'static str) -> Self {
        Self { key }
    }
}

impl Drop for GlobalSettingCleanup {
    fn drop(&mut self) {
        let _ = std::process::Command::new(openshell_bin())
            .args([
                "settings",
                "delete",
                "--global",
                "--key",
                self.key,
                "--yes",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

async fn run_cli(args: &[&str]) -> CliResult {
    let mut cmd = openshell_cmd();
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd.output().await.expect("spawn openshell command");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");

    CliResult {
        clean_output: strip_ansi(&combined),
        success: output.status.success(),
        exit_code: output.status.code(),
    }
}

fn assert_setting_line(output: &str, key: &str, expected: &str) {
    let needle = format!("{key} = {expected}");
    assert!(
        output.contains(&needle),
        "expected setting line '{needle}' in output:\n{output}"
    );
}

fn assert_setting_line_with_scope(output: &str, key: &str, expected: &str, scope: &str) {
    let needle = format!("{key} = {expected} ({scope})");
    assert!(
        output.contains(&needle),
        "expected setting line '{needle}' in output:\n{output}"
    );
}

/// Poll `settings get` until the expected value and scope appear for a key.
async fn wait_for_setting_value(
    sandbox_name: &str,
    key: &str,
    expected_value: &str,
    expected_scope: &str,
    timeout_duration: Duration,
) {
    let needle = format!("{key} = {expected_value} ({expected_scope})");
    let start = Instant::now();
    loop {
        let result = run_cli(&["settings", "get", sandbox_name]).await;
        if result.success && result.clean_output.contains(&needle) {
            return;
        }
        if start.elapsed() > timeout_duration {
            panic!(
                "timed out after {:?} waiting for setting line '{needle}' in output:\n{}",
                timeout_duration, result.clean_output
            );
        }
        sleep(Duration::from_secs(1)).await;
    }
}

#[tokio::test]
async fn settings_global_override_round_trip() {
    let _settings_lock = SETTINGS_E2E_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _global_cleanup = GlobalSettingCleanup::new(TEST_KEY);

    let cleanup_before = run_cli(&[
        "settings",
        "delete",
        "--global",
        "--key",
        TEST_KEY,
        "--yes",
    ])
    .await;
    assert!(
        cleanup_before.success,
        "initial global setting cleanup should succeed (exit {:?}):\n{}",
        cleanup_before.exit_code,
        cleanup_before.clean_output
    );

    let mut guard =
        SandboxGuard::create_keep(&["sh", "-c", "echo Ready && sleep infinity"], "Ready")
            .await
            .expect("create keep sandbox");

    let initial = run_cli(&["settings", "get", &guard.name]).await;
    assert!(
        initial.success,
        "settings get should succeed (exit {:?}):\n{}",
        initial.exit_code,
        initial.clean_output
    );
    assert_setting_line_with_scope(&initial.clean_output, TEST_KEY, "<unset>", "unset");

    let set_sandbox = run_cli(&[
        "settings", "set", &guard.name, "--key", TEST_KEY, "--value", "true",
    ])
    .await;
    assert!(
        set_sandbox.success,
        "sandbox setting set should succeed (exit {:?}):\n{}",
        set_sandbox.exit_code,
        set_sandbox.clean_output
    );

    // Wait for the gateway to reflect the setting change. The setting is stored
    // server-side, so `settings get` reads it immediately. Poll to ensure the
    // config_revision has been updated (visible in the output).
    wait_for_setting_value(&guard.name, TEST_KEY, "true", "sandbox", Duration::from_secs(10))
        .await;

    let after_sandbox_set = run_cli(&["settings", "get", &guard.name]).await;
    assert!(
        after_sandbox_set.success,
        "settings get after sandbox set should succeed (exit {:?}):\n{}",
        after_sandbox_set.exit_code,
        after_sandbox_set.clean_output
    );
    assert_setting_line_with_scope(&after_sandbox_set.clean_output, TEST_KEY, "true", "sandbox");

    // Sandbox-scoped delete should succeed when not globally managed.
    let sandbox_delete = run_cli(&[
        "settings", "delete", &guard.name, "--key", TEST_KEY,
    ])
    .await;
    assert!(
        sandbox_delete.success,
        "sandbox setting delete should succeed (exit {:?}):\n{}",
        sandbox_delete.exit_code,
        sandbox_delete.clean_output
    );
    assert!(
        sandbox_delete
            .clean_output
            .contains("Deleted sandbox setting"),
        "expected sandbox delete confirmation:\n{}",
        sandbox_delete.clean_output
    );

    // After delete, the key should be unset again.
    let after_sandbox_delete = run_cli(&["settings", "get", &guard.name]).await;
    assert!(
        after_sandbox_delete.success,
        "settings get after sandbox delete should succeed:\n{}",
        after_sandbox_delete.clean_output
    );
    assert_setting_line_with_scope(
        &after_sandbox_delete.clean_output,
        TEST_KEY,
        "<unset>",
        "unset",
    );

    // Re-set at sandbox scope so we can test global override next.
    let re_set = run_cli(&[
        "settings", "set", &guard.name, "--key", TEST_KEY, "--value", "true",
    ])
    .await;
    assert!(re_set.success, "re-set should succeed:\n{}", re_set.clean_output);

    let set_global = run_cli(&[
        "settings", "set", "--global", "--key", TEST_KEY, "--value", "false", "--yes",
    ])
    .await;
    assert!(
        set_global.success,
        "global setting set should succeed (exit {:?}):\n{}",
        set_global.exit_code,
        set_global.clean_output
    );
    assert!(
        set_global
            .clean_output
            .contains("Set global setting dummy_bool=false"),
        "expected global set output:\n{}",
        set_global.clean_output
    );

    let blocked_sandbox_set = run_cli(&[
        "settings", "set", &guard.name, "--key", TEST_KEY, "--value", "true",
    ])
    .await;
    assert!(
        !blocked_sandbox_set.success,
        "sandbox setting should fail while key is global-managed:\n{}",
        blocked_sandbox_set.clean_output
    );
    assert!(
        blocked_sandbox_set.clean_output.contains("is managed"),
        "expected 'managed globally' error:\n{}",
        blocked_sandbox_set.clean_output
    );

    // Sandbox-scoped delete should also be blocked while globally managed.
    let blocked_sandbox_delete = run_cli(&[
        "settings", "delete", &guard.name, "--key", TEST_KEY,
    ])
    .await;
    assert!(
        !blocked_sandbox_delete.success,
        "sandbox delete should fail while key is global-managed:\n{}",
        blocked_sandbox_delete.clean_output
    );

    let global_get = run_cli(&["settings", "get", "--global"]).await;
    assert!(
        global_get.success,
        "global settings get should succeed (exit {:?}):\n{}",
        global_get.exit_code,
        global_get.clean_output
    );
    assert_setting_line(&global_get.clean_output, TEST_KEY, "false");

    let delete_global = run_cli(&[
        "settings",
        "delete",
        "--global",
        "--key",
        TEST_KEY,
        "--yes",
    ])
    .await;
    assert!(
        delete_global.success,
        "global settings delete should succeed (exit {:?}):\n{}",
        delete_global.exit_code,
        delete_global.clean_output
    );
    assert!(
        delete_global
            .clean_output
            .contains("Deleted global setting dummy_bool"),
        "expected global delete confirmation in output:\n{}",
        delete_global.clean_output
    );

    let global_after_delete = run_cli(&["settings", "get", "--global"]).await;
    assert!(
        global_after_delete.success,
        "global settings get after delete should succeed (exit {:?}):\n{}",
        global_after_delete.exit_code,
        global_after_delete.clean_output
    );
    assert_setting_line(&global_after_delete.clean_output, TEST_KEY, "<unset>");

    let sandbox_set_after_delete = run_cli(&[
        "settings", "set", &guard.name, "--key", TEST_KEY, "--value", "false",
    ])
    .await;
    assert!(
        sandbox_set_after_delete.success,
        "sandbox setting set after global delete should succeed (exit {:?}):\n{}",
        sandbox_set_after_delete.exit_code,
        sandbox_set_after_delete.clean_output
    );

    let sandbox_after_delete = run_cli(&["settings", "get", &guard.name]).await;
    assert!(
        sandbox_after_delete.success,
        "settings get after global delete should succeed (exit {:?}):\n{}",
        sandbox_after_delete.exit_code,
        sandbox_after_delete.clean_output
    );
    assert_setting_line_with_scope(&sandbox_after_delete.clean_output, TEST_KEY, "false", "sandbox");

    guard.cleanup().await;
}
