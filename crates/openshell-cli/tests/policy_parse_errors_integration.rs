// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! User-facing policy parse failures must happen before the CLI connects to a
//! gateway, with enough context to identify the protobuf shape violation.

use std::process::Command;

#[test]
fn policy_set_reports_legacy_matcher_shape_before_connecting() {
    let directory = tempfile::tempdir().expect("create temp directory");
    let policy_path = directory.path().join("legacy-policy.yaml");
    std::fs::write(
        &policy_path,
        r"
version: 1
network_policies:
  mcp:
    endpoints:
      - host: mcp.example.com
        ports: [443]
        protocol: mcp
        rules:
          - allow:
              method: tools/call
              tool: search_*
",
    )
    .expect("write legacy policy");

    let output = Command::new(env!("CARGO_BIN_EXE_openshell"))
        .args([
            "policy",
            "set",
            "test-sandbox",
            "--policy",
            policy_path.to_str().expect("UTF-8 temp path"),
            "--gateway-endpoint",
            "http://127.0.0.1:1",
            "--color",
            "never",
        ])
        .output()
        .expect("run openshell policy set");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to decode proto-shaped sandbox policy YAML"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !stderr.contains("127.0.0.1") && !stderr.contains("transport error"),
        "the CLI connected before rejecting the local file: {stderr}"
    );
}
