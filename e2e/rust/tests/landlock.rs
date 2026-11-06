// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! End-to-end coverage for Landlock filesystem enforcement.

use std::io::Write;
use std::time::Duration;

use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;

const SUCCESS_MARKER: &str = "landlock-hard-requirement-ok";

fn write_hard_requirement_policy() -> Result<NamedTempFile, String> {
    write_policy("hard_requirement", "/sandbox")
}

fn write_policy(compatibility: &str, extra_path: &str) -> Result<NamedTempFile, String> {
    let mut file =
        NamedTempFile::new().map_err(|error| format!("create temporary policy: {error}"))?;
    let policy = r#"version: 1

filesystem_policy:
  include_workdir: true
  read_only:
    - /usr
    - /lib
    - /etc
    - /proc
  read_write:
    - /sandbox
    - /tmp

landlock:
  compatibility: hard_requirement

process:
  run_as_user: sandbox
  run_as_group: sandbox

network_policies:
  landlock_regression:
    name: landlock_regression
    endpoints:
      - host: example.com
        port: 443
    binaries:
      - path: "/**"
"#;

    let policy = policy
        .replace(
            "compatibility: hard_requirement",
            &format!("compatibility: {compatibility}"),
        )
        .replace(
            "    - /sandbox\n",
            &format!("    - /sandbox\n    - {extra_path}\n"),
        );
    file.write_all(policy.as_bytes())
        .map_err(|error| format!("write temporary policy: {error}"))?;
    file.flush()
        .map_err(|error| format!("flush temporary policy: {error}"))?;
    Ok(file)
}

#[tokio::test]
async fn hard_requirement_accepts_enriched_device_path() {
    let policy = write_hard_requirement_policy().expect("write hard-requirement policy");
    let policy_path = policy.path().to_string_lossy().into_owned();
    let script = concat!(
        "set -eu; ",
        "bytes=$(head -c 16 /dev/urandom | wc -c); ",
        "test \"$bytes\" -eq 16; ",
        "printf landlock-ok > /tmp/landlock-check; ",
        "test \"$(cat /tmp/landlock-check)\" = landlock-ok; ",
        "echo landlock-hard-requirement-ok",
    );

    let mut sandbox = SandboxGuard::create(&["--policy", &policy_path, "--", "sh", "-lc", script])
        .await
        .expect("hard_requirement should accept the enriched /dev/urandom path");

    assert!(sandbox.create_output.contains(SUCCESS_MARKER));
    sandbox.cleanup().await;
}

async fn check_policy_path_replacement(compatibility: &str, replace_ancestor: bool) {
    let policy = write_policy(compatibility, "/sandbox/policy-parent/leaf")
        .expect("write filesystem policy");
    let policy_path = policy.path().to_string_lossy().into_owned();
    let mut sandbox = SandboxGuard::create(&["--policy", &policy_path])
        .await
        .expect("create sandbox with filesystem policy");

    sandbox
        .exec(&["sh", "-c", "mkdir -p /sandbox/policy-parent/leaf"])
        .await
        .expect("create declared directory under writable workspace");
    sandbox
        .exec(&[
            "sh",
            "-c",
            "echo allowed > /sandbox/policy-parent/leaf/check",
        ])
        .await
        .expect("normal directory should remain usable on the next exec");

    let script = if replace_ancestor {
        "mv /sandbox/policy-parent /sandbox/original-parent; ln -s /var/tmp /sandbox/policy-parent"
    } else {
        "mv /sandbox/policy-parent/leaf /sandbox/original-leaf; ln -s /var/tmp /sandbox/policy-parent/leaf"
    };
    sandbox
        .exec(&["sh", "-c", script])
        .await
        .expect("replace workspace directory");
    let result = tokio::time::timeout(Duration::from_secs(20), sandbox.exec(&["true"])).await;
    // Delete through the control plane even when further workload launches fail.
    sandbox.cleanup().await;
    let error = result
        .expect("rejected launch must close its SSH channel promptly")
        .expect_err("mutable policy symlink must prevent the next launch");
    assert!(
        error.to_lowercase().contains("symlink"),
        "unexpected launch error: {error}"
    );
}

#[tokio::test]
async fn best_effort_rejects_replaced_policy_path() {
    check_policy_path_replacement("best_effort", false).await;
}

#[tokio::test]
async fn hard_requirement_rejects_replaced_policy_path() {
    check_policy_path_replacement("hard_requirement", false).await;
}

#[tokio::test]
async fn best_effort_rejects_replaced_policy_ancestor() {
    check_policy_path_replacement("best_effort", true).await;
}

#[tokio::test]
async fn hard_requirement_rejects_replaced_policy_ancestor() {
    check_policy_path_replacement("hard_requirement", true).await;
}
