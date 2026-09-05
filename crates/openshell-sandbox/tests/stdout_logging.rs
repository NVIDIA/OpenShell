// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

#[test]
fn startup_logs_go_to_stderr_not_stdout() {
    let output = Command::new(env!("CARGO_BIN_EXE_openshell-sandbox"))
        .arg("--bootstrap")
        .arg("/does/not/exist/openshell-boundary.json")
        .env("OPENSHELL_LOG_LEVEL", "info")
        .env_remove("RUST_LOG")
        .output()
        .expect("spawn openshell-sandbox");

    assert!(
        !output.status.success(),
        "expected sandbox startup to fail without bootstrap material"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stdout.trim().is_empty(),
        "expected startup logs on stderr only, got stdout: {stdout}"
    );
    assert!(
        stderr.contains("capability-free sandbox probe") || stderr.contains("read boundary config"),
        "expected startup qualification or bootstrap error on stderr, got: {stderr}"
    );
}
