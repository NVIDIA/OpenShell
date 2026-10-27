// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Standalone driver smoke test for the Podman-unavailable diagnostic path.
//!
//! Retry timing and connection failures are covered deterministically by unit
//! tests. This test retains only the executable boundary: argument wiring,
//! process exit status, and the rendered error shown to operators.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

#[tokio::test]
async fn missing_podman_socket_exits_with_actionable_diagnostic() {
    let tmpdir = tempfile::tempdir().expect("create isolated socket dir");
    // Use a short relative path so miette cannot insert a line-wrap gutter
    // inside it on platforms with long temporary-directory paths.
    let missing_socket = PathBuf::from("missing-podman.sock");

    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_openshell-driver-podman"));
    cmd.arg("--podman-socket")
        .arg(&missing_socket)
        .current_dir(tmpdir.path())
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = tokio::time::timeout(Duration::from_secs(30), cmd.output())
        .await
        .expect("driver should stop after its bounded retry window")
        .expect("spawn openshell-driver-podman");

    assert!(
        !output.status.success(),
        "driver should exit non-zero when Podman is unreachable"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("connection error"),
        "driver error should describe a connection failure:\n{combined}"
    );
    assert!(
        combined.contains(missing_socket.to_str().expect("socket path is utf-8")),
        "driver error should name the unreachable socket path {}:\n{combined}",
        missing_socket.display()
    );
}
