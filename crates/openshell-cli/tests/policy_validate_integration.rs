// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Local policy validation through `openshell policy validate`.

mod common;

use std::path::PathBuf;

use common::run_isolated;

const READ_ONLY_POLICY: &str = r"version: 1
network_policies:
  github_api:
    name: github_api
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-only
    binaries:
      - { path: /usr/bin/curl }
";

fn write_policy(dir: &tempfile::TempDir, contents: &str) -> PathBuf {
    let path = dir.path().join("policy.yaml");
    std::fs::write(&path, contents).expect("write policy file");
    path
}

#[test]
fn policy_validate_accepts_a_valid_policy_without_a_gateway() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = write_policy(&dir, READ_ONLY_POLICY);
    let path = path.to_str().expect("utf-8 path");

    let output = run_isolated(&["policy", "validate", "--policy", path]);

    assert_eq!(output.code, 0, "policy validate:\n{}", output.combined);
    assert!(
        output.stdout.contains(&format!("{path}: valid")),
        "expected a valid verdict:\n{}",
        output.combined
    );
}

#[test]
fn policy_validate_reports_every_violation() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let invalid = READ_ONLY_POLICY.replace(
        "        access: read-only\n",
        "        access: read-only\n        rules:\n          - allow: { method: POST, path: /issues }\n",
    ) + "process:\n  run_as_user: \"0\"\n";
    let path = write_policy(&dir, &invalid);
    let path = path.to_str().expect("utf-8 path");

    let output = run_isolated(&["policy", "validate", "--policy", path]);

    assert_ne!(output.code, 0, "policy validate:\n{}", output.combined);
    for expected in [
        "rules and access are mutually exclusive",
        "run_as_user must be 'sandbox' or a numeric UID/GID",
        "has 2 policy violation(s)",
    ] {
        assert!(
            output.combined.contains(expected),
            "expected '{expected}':\n{}",
            output.combined
        );
    }
}

#[test]
fn policy_validate_rejects_unparseable_policy() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let invalid = READ_ONLY_POLICY.replace(
        "        enforcement: enforce\n",
        "        enforcement: enforce\n        tls: passthrough\n",
    );
    let path = write_policy(&dir, &invalid);
    let path = path.to_str().expect("utf-8 path");

    let output = run_isolated(&["policy", "validate", "--policy", path]);

    assert_ne!(output.code, 0, "policy validate:\n{}", output.combined);
    assert!(
        output.combined.contains("unknown tls value"),
        "expected the tls error:\n{}",
        output.combined
    );
}
