// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::process::Stdio;
use std::time::Duration;

use openshell_e2e::harness::binary::{openshell_cmd, openshell_tty_cmd};
use openshell_e2e::harness::output::{extract_field, strip_ansi};
use tokio::time::sleep;

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

async fn sandbox_list_names() -> Vec<String> {
    let mut cmd = openshell_cmd();
    cmd.args(["sandbox", "list", "--names"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd.output().await.expect("spawn openshell sandbox list");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = normalize_output(&format!("{stdout}{stderr}"));
    assert!(
        output.status.success(),
        "sandbox list should succeed (exit {:?}):\n{combined}",
        output.status.code()
    );

    combined
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

async fn delete_sandbox(name: &str) {
    let mut cmd = openshell_cmd();
    cmd.args(["sandbox", "delete", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let _ = cmd.status().await;
}

#[tokio::test]
async fn sandbox_create_without_keep_cleans_up_after_tty_command() {
    let mut cmd = openshell_tty_cmd(&["sandbox", "create", "--", "echo", "OK"]);
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd.output().await.expect("spawn openshell sandbox create");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = normalize_output(&format!("{stdout}{stderr}"));

    assert!(
        output.status.success(),
        "sandbox create should succeed (exit {:?}):\n{combined}",
        output.status.code()
    );
    assert!(combined.contains("OK"), "expected command output in:\n{combined}");

    let sandbox_name = extract_sandbox_name(&combined).expect("sandbox name should be present in output");

    for _ in 0..20 {
        if !sandbox_list_names().await.contains(&sandbox_name) {
            return;
        }
        sleep(Duration::from_millis(500)).await;
    }

    delete_sandbox(&sandbox_name).await;
    panic!("sandbox {sandbox_name} should have been deleted automatically");
}
