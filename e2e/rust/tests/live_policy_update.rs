// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! E2E tests for live policy updates on a running sandbox.
//!
//! Covers the full round-trip:
//! - Create sandbox with policy A
//! - Verify initial policy version via `policy get`
//! - Push same policy A again -> no version bump (idempotent)
//! - Push different policy B -> new version, `--wait` for sandbox to load it
//! - Verify policy history via `policy list`
//!
//! These tests replace the Python e2e tests `test_live_policy_update_and_logs`
//! and `test_live_policy_update_from_empty_network_policies`, which were flaky
//! due to hard-coded 90s poll timeouts. The Rust tests use the CLI's built-in
//! `--wait` flag for reliable synchronization.
//!
//! Note: the removed Python tests also covered `GetSandboxLogs` RPC and
//! verified actual proxy connectivity after policy update. Those are tracked
//! as follow-up coverage gaps -- the proxy enforcement path is covered by the
//! existing L4/L7/SSRF Python e2e tests, and log fetching needs a dedicated
//! test.

#![cfg(feature = "e2e")]

use std::fmt::Write as _;
use std::io::Write;
use std::process::Stdio;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::output::{extract_field, strip_ansi};
use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;

// ---------------------------------------------------------------------------
// Policy YAML builders
// ---------------------------------------------------------------------------

/// Build a policy YAML that allows any binary to reach the given hosts on
/// port 443.
///
/// NOTE: The indentation in the format string is load-bearing YAML structure.
fn write_policy(hosts: &[&str]) -> Result<NamedTempFile, String> {
    let mut file = NamedTempFile::new().map_err(|e| format!("create temp policy file: {e}"))?;

    let mut network_rules = String::new();
    for (i, host) in hosts.iter().enumerate() {
        let _ = write!(
            network_rules,
            r#"  rule_{i}:
    name: rule_{i}
    endpoints:
      - host: {host}
        port: 443
    binaries:
      - path: "/**"
"#
        );
    }

    let policy = format!(
        r"version: 1

filesystem_policy:
  include_workdir: true
  read_only:
    - /usr
    - /lib
    - /proc
    - /dev/urandom
    - /app
    - /etc
    - /var/log
  read_write:
    - /sandbox
    - /tmp
    - /dev/null

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox

network_policies:
{network_rules}"
    );

    file.write_all(policy.as_bytes())
        .map_err(|e| format!("write temp policy file: {e}"))?;
    file.flush()
        .map_err(|e| format!("flush temp policy file: {e}"))?;
    Ok(file)
}

/// Build a minimal policy YAML with no network rules.
fn write_empty_network_policy() -> Result<NamedTempFile, String> {
    let mut file = NamedTempFile::new().map_err(|e| format!("create temp policy file: {e}"))?;

    let policy = r"version: 1

filesystem_policy:
  include_workdir: true
  read_only:
    - /usr
    - /lib
    - /proc
    - /dev/urandom
    - /app
    - /etc
    - /var/log
  read_write:
    - /sandbox
    - /tmp
    - /dev/null

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox
";

    file.write_all(policy.as_bytes())
        .map_err(|e| format!("write temp policy file: {e}"))?;
    file.flush()
        .map_err(|e| format!("flush temp policy file: {e}"))?;
    Ok(file)
}

// ---------------------------------------------------------------------------
// CLI helpers
// ---------------------------------------------------------------------------

struct CliResult {
    success: bool,
    output: String,
    exit_code: Option<i32>,
}

/// Run an `openshell` CLI command and return the result.
async fn run_cli(args: &[&str]) -> CliResult {
    let mut cmd = openshell_cmd();
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd.output().await.expect("spawn openshell command");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = strip_ansi(&format!("{stdout}{stderr}"));

    CliResult {
        success: output.status.success(),
        output: combined,
        exit_code: output.status.code(),
    }
}

/// Extract the policy version number from `policy get` output.
///
/// Uses the shared `extract_field` helper to find `Version: <n>` or
/// `Revision: <n>` in CLI tabular output.
fn extract_version(output: &str) -> Option<u32> {
    extract_field(output, "Version")
        .or_else(|| extract_field(output, "Revision"))
        .and_then(|v| v.parse::<u32>().ok())
}

/// Extract the policy hash from `policy get` output.
fn extract_hash(output: &str) -> Option<String> {
    extract_field(output, "Hash")
        .or_else(|| extract_field(output, "Policy hash"))
}

/// Check that a version number appears in `policy list` output as a
/// distinct field value (not just a substring of some other number).
///
/// Looks for the version number preceded by whitespace or at the start
/// of a line, to avoid matching "2" inside "12" or timestamps.
fn list_output_contains_version(output: &str, version: u32) -> bool {
    let v = version.to_string();
    output.lines().any(|line| {
        line.split_whitespace()
            .any(|word| word == v || word.starts_with(&format!("{v} ")))
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Test the full live policy update lifecycle:
///
/// 1. Create sandbox with `--keep`
/// 2. Set policy A, verify initial version >= 1
/// 3. Push same policy A -> version unchanged (idempotent)
/// 4. Push policy B (adds example.com) with `--wait` -> new version
/// 5. Push policy B again -> idempotent
/// 6. Verify policy list shows both versions
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn live_policy_update_round_trip() {
    // --- Write two distinct policy files ---
    let policy_a = write_policy(&["api.anthropic.com"]).expect("write policy A");
    let policy_b =
        write_policy(&["api.anthropic.com", "example.com"]).expect("write policy B");

    let policy_a_path = policy_a
        .path()
        .to_str()
        .expect("policy A path should be utf-8")
        .to_string();
    let policy_b_path = policy_b
        .path()
        .to_str()
        .expect("policy B path should be utf-8")
        .to_string();

    // --- Create a long-running sandbox ---
    let mut guard = SandboxGuard::create_keep(
        &["sh", "-c", "echo Ready && sleep infinity"],
        "Ready",
    )
    .await
    .expect("create keep sandbox");

    // --- Set initial policy A ---
    let r = run_cli(&[
        "policy", "set", &guard.name, "--policy", &policy_a_path, "--wait", "--timeout", "120",
    ])
    .await;
    assert!(
        r.success,
        "policy set A should succeed (exit {:?}):\n{}",
        r.exit_code, r.output
    );

    // --- Verify initial policy version ---
    let r = run_cli(&["policy", "get", &guard.name]).await;
    assert!(
        r.success,
        "policy get should succeed (exit {:?}):\n{}",
        r.exit_code, r.output
    );

    let initial_version = extract_version(&r.output)
        .unwrap_or_else(|| panic!("could not parse version from policy get output:\n{}", r.output));
    assert!(
        initial_version >= 1,
        "initial policy version should be >= 1, got {initial_version}"
    );

    let initial_hash = extract_hash(&r.output);

    // --- Push same policy A again -> should be idempotent ---
    let r = run_cli(&[
        "policy", "set", &guard.name, "--policy", &policy_a_path, "--wait", "--timeout", "120",
    ])
    .await;
    assert!(
        r.success,
        "policy set A (repeat) should succeed (exit {:?}):\n{}",
        r.exit_code, r.output
    );

    let r = run_cli(&["policy", "get", &guard.name]).await;
    assert!(r.success, "policy get after repeat should succeed:\n{}", r.output);

    let repeat_version = extract_version(&r.output)
        .unwrap_or_else(|| panic!("could not parse version after repeat:\n{}", r.output));
    assert_eq!(
        repeat_version, initial_version,
        "same policy should not bump version: expected {initial_version}, got {repeat_version}"
    );

    if let (Some(ih), Some(rh)) = (&initial_hash, &extract_hash(&r.output)) {
        assert_eq!(ih, rh, "same policy should produce same hash");
    }

    // --- Push policy B -> should create new version ---
    let r = run_cli(&[
        "policy", "set", &guard.name, "--policy", &policy_b_path, "--wait", "--timeout", "120",
    ])
    .await;
    assert!(
        r.success,
        "policy set B should succeed (exit {:?}):\n{}",
        r.exit_code, r.output
    );

    let r = run_cli(&["policy", "get", &guard.name]).await;
    assert!(r.success, "policy get after B should succeed:\n{}", r.output);

    let new_version = extract_version(&r.output)
        .unwrap_or_else(|| panic!("could not parse version after B:\n{}", r.output));
    assert!(
        new_version > initial_version,
        "different policy should bump version: expected > {initial_version}, got {new_version}"
    );

    if let (Some(ih), Some(nh)) = (&initial_hash, &extract_hash(&r.output)) {
        assert_ne!(ih, nh, "different policy should produce different hash");
    }

    // --- Push policy B again -> idempotent ---
    let r = run_cli(&[
        "policy", "set", &guard.name, "--policy", &policy_b_path, "--wait", "--timeout", "120",
    ])
    .await;
    assert!(
        r.success,
        "policy set B (repeat) should succeed (exit {:?}):\n{}",
        r.exit_code, r.output
    );

    let r = run_cli(&["policy", "get", &guard.name]).await;
    assert!(r.success, "policy get after B repeat should succeed:\n{}", r.output);

    let repeat_b_version = extract_version(&r.output)
        .unwrap_or_else(|| panic!("could not parse version after B repeat:\n{}", r.output));
    assert_eq!(
        repeat_b_version, new_version,
        "same policy B should not bump version: expected {new_version}, got {repeat_b_version}"
    );

    // --- Verify policy list shows revision history ---
    let r = run_cli(&["policy", "list", &guard.name]).await;
    assert!(
        r.success,
        "policy list should succeed (exit {:?}):\n{}",
        r.exit_code, r.output
    );

    // Both versions should appear in the list output.
    assert!(
        list_output_contains_version(&r.output, new_version),
        "policy list should contain version {new_version}:\n{}",
        r.output
    );
    assert!(
        list_output_contains_version(&r.output, initial_version),
        "policy list should contain initial version {initial_version}:\n{}",
        r.output
    );

    guard.cleanup().await;
}

/// Test live policy update from an initially empty network policy:
///
/// 1. Create sandbox with `--keep`
/// 2. Set policy with no network rules
/// 3. Push policy with a network rule using `--wait`
/// 4. Verify the version bumped
#[tokio::test]
async fn live_policy_update_from_empty_network_policies() {
    let empty_policy = write_empty_network_policy().expect("write empty network policy");
    let full_policy = write_policy(&["example.com"]).expect("write full policy");

    let empty_path = empty_policy
        .path()
        .to_str()
        .expect("empty policy path should be utf-8")
        .to_string();
    let full_path = full_policy
        .path()
        .to_str()
        .expect("full policy path should be utf-8")
        .to_string();

    // Create sandbox with empty network policy.
    let mut guard = SandboxGuard::create_keep(
        &["sh", "-c", "echo Ready && sleep infinity"],
        "Ready",
    )
    .await
    .expect("create keep sandbox");

    // Set initial empty policy.
    let r = run_cli(&[
        "policy", "set", &guard.name, "--policy", &empty_path, "--wait", "--timeout", "120",
    ])
    .await;
    assert!(
        r.success,
        "policy set (empty) should succeed (exit {:?}):\n{}",
        r.exit_code, r.output
    );

    let r = run_cli(&["policy", "get", &guard.name]).await;
    assert!(r.success, "policy get (empty) should succeed:\n{}", r.output);

    let initial_version = extract_version(&r.output)
        .unwrap_or_else(|| panic!("could not parse version from empty policy:\n{}", r.output));

    // Push policy with network rules.
    let r = run_cli(&[
        "policy", "set", &guard.name, "--policy", &full_path, "--wait", "--timeout", "120",
    ])
    .await;
    assert!(
        r.success,
        "policy set (full) should succeed (exit {:?}):\n{}",
        r.exit_code, r.output
    );

    let r = run_cli(&["policy", "get", &guard.name]).await;
    assert!(r.success, "policy get (full) should succeed:\n{}", r.output);

    let new_version = extract_version(&r.output).unwrap_or_else(|| {
        panic!(
            "could not parse version after adding network rules:\n{}",
            r.output
        )
    });
    assert!(
        new_version > initial_version,
        "adding network rules should create new version > {initial_version}, got {new_version}"
    );

    guard.cleanup().await;
}
