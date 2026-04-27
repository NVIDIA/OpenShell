// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::process::Stdio;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::output::{extract_field, strip_ansi};

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

async fn create_sandbox_with_labels(name: &str, labels: &[(&str, &str)]) -> String {
    let mut cmd = openshell_cmd();
    cmd.args(["sandbox", "create", "--name", name]);

    for (key, value) in labels {
        cmd.arg("--label").arg(format!("{key}={value}"));
    }

    cmd.args(["--", "echo", "test"])
        .stdout(Stdio::piped())
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

    extract_sandbox_name(&combined).expect("sandbox name should be present in output")
}

async fn list_sandboxes_with_selector(selector: &str) -> Vec<String> {
    let mut cmd = openshell_cmd();
    cmd.args(["sandbox", "list", "--names"]);

    if !selector.is_empty() {
        cmd.arg("--selector").arg(selector);
    }

    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

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

async fn get_sandbox_details(name: &str) -> String {
    let mut cmd = openshell_cmd();
    cmd.args(["sandbox", "get", name])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd.output().await.expect("spawn openshell sandbox get");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = normalize_output(&format!("{stdout}{stderr}"));

    assert!(
        output.status.success(),
        "sandbox get should succeed (exit {:?}):\n{combined}",
        output.status.code()
    );

    combined
}

async fn delete_sandbox(name: &str) {
    let mut cmd = openshell_cmd();
    cmd.args(["sandbox", "delete", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let _ = cmd.status().await;
}

#[tokio::test]
async fn sandbox_labels_are_stored_and_filterable() {
    // Create sandboxes with different labels
    let name1 = create_sandbox_with_labels(
        "e2e-label-test-dev-backend",
        &[("env", "dev"), ("team", "backend")],
    )
    .await;

    let name2 = create_sandbox_with_labels(
        "e2e-label-test-staging-backend",
        &[("env", "staging"), ("team", "backend")],
    )
    .await;

    let name3 = create_sandbox_with_labels(
        "e2e-label-test-prod-frontend",
        &[("env", "prod"), ("team", "frontend")],
    )
    .await;

    let name4 = create_sandbox_with_labels(
        "e2e-label-test-dev-data",
        &[("env", "dev"), ("team", "data")],
    )
    .await;

    // Test 1: Verify labels are stored in sandbox metadata
    let details = get_sandbox_details(&name1).await;
    assert!(
        details.contains("env: dev"),
        "sandbox should have env=dev label in details:\n{details}"
    );
    assert!(
        details.contains("team: backend"),
        "sandbox should have team=backend label in details:\n{details}"
    );

    // Test 2: Filter by single label (env=dev)
    let dev_sandboxes = list_sandboxes_with_selector("env=dev").await;
    assert!(
        dev_sandboxes.contains(&name1),
        "env=dev filter should include {name1}, got: {dev_sandboxes:?}"
    );
    assert!(
        dev_sandboxes.contains(&name4),
        "env=dev filter should include {name4}, got: {dev_sandboxes:?}"
    );
    assert!(
        !dev_sandboxes.contains(&name2),
        "env=dev filter should not include staging sandbox {name2}, got: {dev_sandboxes:?}"
    );
    assert!(
        !dev_sandboxes.contains(&name3),
        "env=dev filter should not include prod sandbox {name3}, got: {dev_sandboxes:?}"
    );

    // Test 3: Filter by single label (team=backend)
    let backend_sandboxes = list_sandboxes_with_selector("team=backend").await;
    assert!(
        backend_sandboxes.contains(&name1),
        "team=backend filter should include {name1}, got: {backend_sandboxes:?}"
    );
    assert!(
        backend_sandboxes.contains(&name2),
        "team=backend filter should include {name2}, got: {backend_sandboxes:?}"
    );
    assert!(
        !backend_sandboxes.contains(&name3),
        "team=backend filter should not include frontend sandbox {name3}, got: {backend_sandboxes:?}"
    );
    assert!(
        !backend_sandboxes.contains(&name4),
        "team=backend filter should not include data sandbox {name4}, got: {backend_sandboxes:?}"
    );

    // Test 4: Filter by multiple labels (AND logic: env=dev,team=backend)
    let dev_backend_sandboxes = list_sandboxes_with_selector("env=dev,team=backend").await;
    assert_eq!(
        dev_backend_sandboxes
            .iter()
            .filter(|name| [&name1, &name2, &name3, &name4].contains(&name))
            .count(),
        1,
        "env=dev,team=backend filter should return exactly 1 sandbox, got: {dev_backend_sandboxes:?}"
    );
    assert!(
        dev_backend_sandboxes.contains(&name1),
        "env=dev,team=backend filter should include {name1}, got: {dev_backend_sandboxes:?}"
    );

    // Test 5: Filter by non-existent label value
    let qa_sandboxes = list_sandboxes_with_selector("team=qa").await;
    assert!(
        !qa_sandboxes.contains(&name1)
            && !qa_sandboxes.contains(&name2)
            && !qa_sandboxes.contains(&name3)
            && !qa_sandboxes.contains(&name4),
        "team=qa filter should not return any of our test sandboxes, got: {qa_sandboxes:?}"
    );

    // Test 6: List all sandboxes (no filter)
    let all_sandboxes = list_sandboxes_with_selector("").await;
    assert!(
        all_sandboxes.contains(&name1),
        "list without filter should include all test sandboxes"
    );
    assert!(
        all_sandboxes.contains(&name2),
        "list without filter should include all test sandboxes"
    );
    assert!(
        all_sandboxes.contains(&name3),
        "list without filter should include all test sandboxes"
    );
    assert!(
        all_sandboxes.contains(&name4),
        "list without filter should include all test sandboxes"
    );

    // Cleanup
    delete_sandbox(&name1).await;
    delete_sandbox(&name2).await;
    delete_sandbox(&name3).await;
    delete_sandbox(&name4).await;
}
