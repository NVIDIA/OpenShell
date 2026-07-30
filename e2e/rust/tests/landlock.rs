// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! End-to-end coverage for Landlock filesystem enforcement.

use std::io::Write;

use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;

const SUCCESS_MARKER: &str = "landlock-hard-requirement-ok";

fn write_hard_requirement_policy() -> Result<NamedTempFile, String> {
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
