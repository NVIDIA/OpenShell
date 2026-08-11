// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

use std::process::Stdio;
use std::time::Duration;

use openshell_e2e::harness::binary::{openshell_cmd, openshell_tty_cmd};
use openshell_e2e::harness::output::{extract_field, strip_ansi};
use openshell_e2e::harness::sandbox::SandboxGuard;
use tokio::time::{Instant, sleep};

const SANDBOX_PRESENCE_TIMEOUT: Duration = Duration::from_secs(30);
const SANDBOX_LIST_POLL_INTERVAL: Duration = Duration::from_millis(500);

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

fn extract_sandbox_name(output: &str) -> Option<String> {
    if let Some((_, rest)) = output.split_once("Created sandbox:") {
        return rest.split_whitespace().next().map(ToOwned::to_owned);
    }

    extract_field(output, "Created sandbox").or_else(|| extract_field(output, "Name"))
}

async fn sandbox_list_names(deadline: Instant) -> Option<Vec<String>> {
    if Instant::now() >= deadline {
        return None;
    }

    let mut cmd = openshell_cmd();
    cmd.args(["sandbox", "list", "--names"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = match tokio::time::timeout_at(deadline, cmd.output()).await {
        Ok(output) => output.expect("spawn openshell sandbox list"),
        Err(_) => return None,
    };
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = normalize_output(&format!("{stdout}{stderr}"));
    assert!(
        output.status.success(),
        "sandbox list should succeed (exit {:?}):\n{combined}",
        output.status.code()
    );

    Some(
        combined
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
    )
}

async fn assert_sandbox_presence_eventually(
    sandbox_name: &str,
    should_exist: bool,
) -> Result<(), Vec<String>> {
    let deadline = Instant::now() + SANDBOX_PRESENCE_TIMEOUT;
    let mut last_sandbox_names = Vec::new();

    loop {
        let Some(sandbox_names) = sandbox_list_names(deadline).await else {
            return Err(last_sandbox_names);
        };
        let exists = sandbox_names.iter().any(|name| name == sandbox_name);
        if exists == should_exist {
            return Ok(());
        }

        let now = Instant::now();
        if now >= deadline {
            return Err(sandbox_names);
        }

        last_sandbox_names = sandbox_names;
        sleep(SANDBOX_LIST_POLL_INTERVAL.min(deadline - now)).await;
    }
}

async fn delete_sandbox(name: &str) {
    let mut cmd = openshell_cmd();
    cmd.args(["sandbox", "delete", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let _ = cmd.status().await;
}

async fn run_sandbox_lifecycle_command(operation: &str, name: &str) -> String {
    let mut cmd = openshell_cmd();
    cmd.args(["sandbox", operation, name])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd
        .output()
        .await
        .unwrap_or_else(|error| panic!("spawn openshell sandbox {operation}: {error}"));
    let combined = normalize_output(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    ));
    assert!(
        output.status.success(),
        "sandbox {operation} should succeed (exit {:?}):\n{combined}",
        output.status.code(),
    );
    combined
}

#[tokio::test]
async fn sandbox_stop_start_preserves_workspace() {
    const SENTINEL: &str = "openshell-stop-start-sentinel";
    const SENTINEL_PATH: &str = "/sandbox/.openshell-stop-start-e2e";
    let write_sentinel = format!("printf '%s\\n' '{SENTINEL}' > '{SENTINEL_PATH}'");

    let mut sandbox = SandboxGuard::create(&["--", "sh", "-lc", &write_sentinel])
        .await
        .expect("sandbox create should write the workspace sentinel");

    let stop_output = run_sandbox_lifecycle_command("stop", &sandbox.name).await;
    assert!(
        stop_output.contains("Stopped sandbox"),
        "expected stop confirmation in:\n{stop_output}",
    );

    let mut exec_cmd = openshell_cmd();
    exec_cmd
        .args([
            "sandbox",
            "exec",
            "--name",
            &sandbox.name,
            "--no-tty",
            "--",
            "cat",
            SENTINEL_PATH,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let stopped_exec = exec_cmd
        .output()
        .await
        .expect("spawn openshell sandbox exec while stopped");
    assert!(
        !stopped_exec.status.success(),
        "sandbox exec should fail while stopped"
    );

    let start_output = run_sandbox_lifecycle_command("start", &sandbox.name).await;
    assert!(
        start_output.contains("Started sandbox"),
        "expected start confirmation in:\n{start_output}",
    );

    let sentinel = sandbox
        .exec(&["cat", SENTINEL_PATH])
        .await
        .expect("sandbox exec should succeed after start");
    assert!(
        sentinel.lines().any(|line| line.trim() == SENTINEL),
        "workspace sentinel should survive stop and start:\n{sentinel}",
    );

    sandbox.cleanup().await;
}

#[tokio::test]
async fn sandbox_can_be_deleted_while_stopped() {
    let mut sandbox = SandboxGuard::create(&["--", "true"])
        .await
        .expect("sandbox create should succeed");

    let stop_output = run_sandbox_lifecycle_command("stop", &sandbox.name).await;
    assert!(
        stop_output.contains("Stopped sandbox"),
        "expected stop confirmation in:\n{stop_output}",
    );

    let delete_output = run_sandbox_lifecycle_command("delete", &sandbox.name).await;
    assert!(
        delete_output.contains("Deleted sandbox"),
        "expected delete confirmation in:\n{delete_output}",
    );

    if let Err(last_sandbox_list) = assert_sandbox_presence_eventually(&sandbox.name, false).await {
        sandbox.cleanup().await;
        panic!(
            "stopped sandbox {} should be deleted without starting after \
             {SANDBOX_PRESENCE_TIMEOUT:?}; last observed sandbox list: {last_sandbox_list:?}",
            sandbox.name,
        );
    }

    // Mark the guard cleaned up. Its idempotent delete is harmless now that
    // the lifecycle operation above has removed the sandbox.
    sandbox.cleanup().await;
}

#[tokio::test]
async fn sandbox_create_keeps_sandbox_after_tty_command_by_default() {
    let mut cmd = openshell_tty_cmd(&["sandbox", "create", "--", "echo", "OK"]);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd.output().await.expect("spawn openshell sandbox create");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = normalize_output(&format!("{stdout}{stderr}"));

    assert!(
        output.status.success(),
        "sandbox create should succeed (exit {:?}):\n{combined}",
        output.status.code()
    );
    assert!(
        combined.contains("OK"),
        "expected command output in:\n{combined}"
    );

    let sandbox_name =
        extract_sandbox_name(&combined).expect("sandbox name should be present in output");

    if let Err(last_sandbox_list) = assert_sandbox_presence_eventually(&sandbox_name, true).await {
        delete_sandbox(&sandbox_name).await;
        panic!(
            "sandbox {sandbox_name} should still exist by default after {SANDBOX_PRESENCE_TIMEOUT:?}; \
             last observed sandbox list: {last_sandbox_list:?}"
        );
    }

    delete_sandbox(&sandbox_name).await;
}

#[tokio::test]
async fn sandbox_create_with_no_keep_cleans_up_after_tty_command() {
    let mut cmd = openshell_tty_cmd(&["sandbox", "create", "--no-keep", "--", "echo", "OK"]);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd.output().await.expect("spawn openshell sandbox create");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = normalize_output(&format!("{stdout}{stderr}"));

    assert!(
        output.status.success(),
        "sandbox create should succeed (exit {:?}):\n{combined}",
        output.status.code()
    );
    assert!(
        combined.contains("OK"),
        "expected command output in:\n{combined}"
    );

    let sandbox_name =
        extract_sandbox_name(&combined).expect("sandbox name should be present in output");

    if let Err(last_sandbox_list) = assert_sandbox_presence_eventually(&sandbox_name, false).await {
        delete_sandbox(&sandbox_name).await;
        panic!(
            "sandbox {sandbox_name} should have been deleted automatically after \
             {SANDBOX_PRESENCE_TIMEOUT:?}; last observed sandbox list: {last_sandbox_list:?}"
        );
    }
}
