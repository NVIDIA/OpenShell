// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E test: `--provider <type>` auto-creates a provider from local credentials.
//!
//! When `--provider claude` is passed and no provider named "claude" exists,
//! the CLI should discover `ANTHROPIC_API_KEY` from the local environment,
//! auto-create a provider, and inject a supervisor-managed placeholder into the
//! sandbox child process environment.
//!
//! The sandbox command (`printenv ANTHROPIC_API_KEY`) verifies that the
//! placeholder made it all the way through to the sandbox process environment.
//!
//! Prerequisites:
//! - A running openshell gateway (`openshell gateway start`)
//! - The `openshell` binary (built automatically from the workspace)

use std::process::Stdio;
use std::sync::Mutex;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::output::{extract_field, strip_ansi};

const TEST_API_KEY: &str = "sk-e2e-auto-provider-test-key";
const TEST_API_KEY_PLACEHOLDER: &str = "openshell:resolve:env:ANTHROPIC_API_KEY";
static CLAUDE_PROVIDER_LOCK: Mutex<()> = Mutex::new(());

/// Helper: delete a provider by name, ignoring errors.
async fn delete_provider(name: &str) {
    let mut cmd = openshell_cmd();
    cmd.arg("provider")
        .arg("delete")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let _ = cmd.status().await;
}

/// Helper: check whether a provider already exists.
async fn provider_exists(name: &str) -> bool {
    let mut cmd = openshell_cmd();
    cmd.arg("provider")
        .arg("get")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd.status().await.is_ok_and(|status| status.success())
}

/// Helper: delete a sandbox by name, ignoring errors.
async fn delete_sandbox(name: &str) {
    let mut cmd = openshell_cmd();
    cmd.arg("sandbox")
        .arg("delete")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let _ = cmd.status().await;
}

/// `--provider claude --auto-providers` with `ANTHROPIC_API_KEY` set should
/// auto-create a "claude" provider and inject a placeholder into the sandbox.
#[tokio::test]
async fn auto_created_provider_credential_available_in_sandbox() {
    let _provider_lock = CLAUDE_PROVIDER_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    if provider_exists("claude").await {
        eprintln!("Skipping test: existing provider 'claude' would make shared state unsafe");
        return;
    }

    // Clean up any leftover from a previous run.
    delete_provider("claude").await;

    // Create a sandbox that prints the ANTHROPIC_API_KEY env var.
    // --auto-providers skips the interactive prompt.
    let mut cmd = openshell_cmd();
    cmd.arg("sandbox")
        .arg("create")
        .arg("--provider")
        .arg("claude")
        .arg("--auto-providers")
        .arg("--no-bootstrap")
        .arg("--")
        .arg("printenv")
        .arg("ANTHROPIC_API_KEY")
        .env("ANTHROPIC_API_KEY", TEST_API_KEY)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd
        .output()
        .await
        .expect("failed to spawn openshell sandbox create");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");
    let clean = strip_ansi(&combined);

    // Parse sandbox name for cleanup.
    let sandbox_name = extract_field(&combined, "Name");

    // Always clean up, even if assertions fail.
    if let Some(ref name) = sandbox_name {
        delete_sandbox(name).await;
    }
    delete_provider("claude").await;

    // Now assert.
    assert!(
        output.status.success(),
        "sandbox create should succeed (exit {:?}):\n{clean}",
        output.status.code()
    );

    assert!(
        clean.contains("Created provider claude"),
        "output should confirm provider auto-creation:\n{clean}"
    );

    assert!(
        clean.contains(TEST_API_KEY_PLACEHOLDER),
        "sandbox should have placeholder ANTHROPIC_API_KEY in its environment:\n{clean}"
    );

    assert!(
        !clean.contains(TEST_API_KEY),
        "sandbox should not expose the raw ANTHROPIC_API_KEY secret:\n{clean}"
    );
}
