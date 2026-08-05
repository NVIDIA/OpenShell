// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

#[test]
fn startup_logs_go_to_stderr_not_stdout() {
    let output = Command::new(env!("CARGO_BIN_EXE_openshell-sandbox"))
        .arg("--")
        .arg("/usr/bin/printf")
        .arg("hello")
        .env("OPENSHELL_LOG_LEVEL", "info")
        .env_remove("RUST_LOG")
        .env_remove("OPENSHELL_POLICY_RULES")
        .env_remove("OPENSHELL_POLICY_DATA")
        .env_remove("OPENSHELL_SANDBOX_ID")
        .env_remove("OPENSHELL_ENDPOINT")
        .output()
        .expect("spawn openshell-sandbox");

    assert!(
        !output.status.success(),
        "expected sandbox startup to fail without a policy source"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stdout.trim().is_empty(),
        "expected startup logs on stderr only, got stdout: {stdout}"
    );
    assert!(
        stderr.contains("Starting sandbox"),
        "expected startup log on stderr, got: {stderr}"
    );
    assert!(
        stderr.contains("Sandbox policy required"),
        "expected missing-policy error on stderr, got: {stderr}"
    );
}
