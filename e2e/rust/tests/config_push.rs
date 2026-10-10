// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! E2E tests for configuration delivered over the supervisor session.
//!
//! Runs only in the `e2e:rust:push` lane, where the gateway starts with
//! `config_delivery_mode = "push"`. Only a supervisor that receives its
//! bootstrap over the session logs loading it, so these tests fail if the lane
//! silently falls back to polling.

#![cfg(feature = "e2e-config-push")]

use std::io::Write;
use std::process::Stdio;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::output::{extract_field, strip_ansi};
use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;

const BASE_POLICY: &str = r"version: 1

filesystem_policy:
  include_workdir: true
  read_only:
    - /bin
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
";

const NETWORK_RULE: &str = r"
network_policies:
  example:
    name: example
    endpoints:
      - host: example.com
        port: 443
    binaries:
      - path: /**
";

fn write_policy(network_rules: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("create temp policy file");
    file.write_all(format!("{BASE_POLICY}{network_rules}").as_bytes())
        .expect("write temp policy file");
    file.flush().expect("flush temp policy file");
    file
}

struct CliResult {
    success: bool,
    output: String,
}

async fn run_cli(args: &[&str]) -> CliResult {
    let output = openshell_cmd()
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("spawn openshell command");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    CliResult {
        success: output.status.success(),
        output: strip_ansi(&format!("{stdout}{stderr}")),
    }
}

async fn policy_version(sandbox: &str) -> u32 {
    let result = run_cli(&["policy", "get", sandbox]).await;
    assert!(result.success, "policy get failed:\n{}", result.output);
    extract_field(&result.output, "Version")
        .or_else(|| extract_field(&result.output, "Revision"))
        .and_then(|version| version.parse().ok())
        .unwrap_or_else(|| panic!("no policy version in:\n{}", result.output))
}

/// Wait until the sandbox's supervisor reports loading a pushed bootstrap.
async fn assert_push_session(sandbox: &str) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let logs = run_cli(&["logs", sandbox, "-n", "500", "--source", "sandbox"]).await;
        if logs.success
            && logs
                .output
                .contains("Loading sandbox policy from supervisor bootstrap")
        {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "supervisor never reported a pushed-configuration session; is the gateway in push mode?\n{}",
            logs.output
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

async fn set_policy_and_wait(sandbox: &str, policy: &NamedTempFile) {
    let path = policy.path().to_str().expect("UTF-8 policy path");
    let result = run_cli(&[
        "policy",
        "set",
        sandbox,
        "--policy",
        path,
        "--wait",
        "--timeout",
        "120",
    ])
    .await;
    assert!(
        result.success,
        "policy set --wait failed:\n{}",
        result.output
    );
}

/// A live policy change reaches the supervisor over its session, and the wait
/// completes once the supervisor reports that exact revision loaded.
#[tokio::test]
async fn streamed_policy_update_reaches_the_supervisor() {
    let base = write_policy("");
    let mut guard = SandboxGuard::create_keep_with_args(
        &[
            "--policy",
            base.path().to_str().expect("UTF-8 policy path"),
            "--no-tty",
        ],
        &["sh", "-c", "echo Ready && sleep infinity"],
        "Ready",
    )
    .await
    .expect("create sandbox");
    assert_push_session(&guard.name).await;
    let initial_version = policy_version(&guard.name).await;

    let updated = write_policy(NETWORK_RULE);
    set_policy_and_wait(&guard.name, &updated).await;
    let updated_version = policy_version(&guard.name).await;
    assert!(
        updated_version > initial_version,
        "a new network rule should create a revision after {initial_version}, got {updated_version}"
    );

    let list = run_cli(&["policy", "list", &guard.name]).await;
    assert!(list.success, "policy list failed:\n{}", list.output);
    assert!(
        !list.output.to_lowercase().contains("pending"),
        "the acknowledged revision must not remain pending:\n{}",
        list.output
    );

    // Resubmitting the effective policy creates no revision.
    let path = updated.path().to_str().expect("UTF-8 policy path");
    let unchanged = run_cli(&[
        "policy",
        "set",
        &guard.name,
        "--policy",
        path,
        "--wait",
        "--timeout",
        "120",
    ])
    .await;
    assert!(
        unchanged.success && unchanged.output.contains("Policy unchanged"),
        "resubmitting the effective policy should complete unchanged:\n{}",
        unchanged.output
    );
    assert_eq!(policy_version(&guard.name).await, updated_version);

    guard.cleanup().await;
}
