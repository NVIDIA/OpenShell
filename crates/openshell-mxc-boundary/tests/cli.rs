// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Real executable checks, without starting a mock MXC runtime.

use std::process::Command;

#[test]
fn help_and_version_identify_dedicated_boundary() {
    for argument in ["--help", "--version"] {
        let output = Command::new(env!("CARGO_BIN_EXE_openshell-windows-sandbox"))
            .arg(argument)
            .output()
            .expect("run dedicated boundary executable");
        assert!(output.status.success());
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains("openshell-windows-sandbox"));
    }
}

#[test]
fn bootstrap_is_required_and_missing_bootstrap_fails_closed() {
    let binary = env!("CARGO_BIN_EXE_openshell-windows-sandbox");
    let output = Command::new(binary)
        .output()
        .expect("run without arguments");
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "startup errors must stay on stderr"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("--bootstrap"));

    // Unique absent path: never create bootstrap material or launch a workload.
    let absent = std::env::temp_dir().join(format!(
        "openshell-mxc-absent-bootstrap-{}.json",
        std::process::id()
    ));
    assert!(!absent.exists());
    let output = Command::new(binary)
        .arg("--bootstrap")
        .arg(absent)
        .env("OPENSHELL_LOG_LEVEL", "info")
        .env_remove("RUST_LOG")
        .output()
        .expect("run with absent bootstrap");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "startup logs must stay on stderr");
    #[cfg(target_os = "windows")]
    assert!(String::from_utf8_lossy(&output.stderr).contains("read boundary config"));
    #[cfg(not(target_os = "windows"))]
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires Windows MXC"));
}
