// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-podman")]

//! Podman driver daemon-unavailable e2e tests.
//!
//! These tests verify that `openshell-driver-podman` fails fast with an
//! actionable error when it cannot reach a Podman API socket, instead of
//! hanging or silently serving gRPC against a dead connection.
//!
//! The tests do NOT require a running Podman daemon or gateway — they point
//! `--podman-socket` at a path that is guaranteed not to exist to simulate
//! the daemon being unavailable.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use openshell_e2e::harness::output::strip_ansi;

/// Locate the workspace root by walking up from this crate's manifest directory.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("failed to resolve workspace root from CARGO_MANIFEST_DIR")
        .to_path_buf()
}

/// Return the path to the `openshell-driver-podman` binary.
///
/// Uses `OPENSHELL_EXTERNAL_DRIVER_BIN` when set (the same env var the shell
/// e2e harness uses for prebuilt standalone driver artifacts), otherwise
/// expects the binary at `<workspace>/target/debug/openshell-driver-podman`.
fn driver_podman_bin() -> PathBuf {
    let bin = std::env::var_os("OPENSHELL_EXTERNAL_DRIVER_BIN").map_or_else(
        || workspace_root().join("target/debug/openshell-driver-podman"),
        PathBuf::from,
    );
    assert!(
        bin.is_file(),
        "openshell-driver-podman binary not found at {} — set OPENSHELL_EXTERNAL_DRIVER_BIN \
         or run `cargo build -p openshell-driver-podman` first",
        bin.display()
    );
    bin
}

/// Run `openshell-driver-podman` pointed at a Podman socket that does not
/// exist, and wait for it to exit.
///
/// The driver retries a handful of times before giving up (to tolerate the
/// socket briefly re-activating), so this can take several seconds.
async fn run_with_unreachable_podman_socket() -> (String, i32, Duration, PathBuf) {
    let tmpdir = tempfile::tempdir().expect("create isolated socket dir");
    let missing_socket = tmpdir.path().join("openshell-e2e-nonexistent-podman.sock");

    let start = Instant::now();
    let mut cmd = tokio::process::Command::new(driver_podman_bin());
    cmd.arg("--podman-socket")
        .arg(&missing_socket)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let output = tokio::time::timeout(Duration::from_secs(60), cmd.output())
        .await
        .expect("openshell-driver-podman should exit instead of hanging")
        .expect("spawn openshell-driver-podman");
    let elapsed = start.elapsed();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");
    let code = output.status.code().unwrap_or(-1);
    (combined, code, elapsed, missing_socket)
}

/// `openshell-driver-podman` should exit non-zero, not hang, when its
/// configured Podman socket does not exist.
#[tokio::test]
async fn driver_exits_when_podman_socket_unreachable() {
    let (output, code, elapsed, _) = run_with_unreachable_podman_socket().await;

    assert_ne!(
        code, 0,
        "driver should exit non-zero when Podman is unreachable, output:\n{output}"
    );

    assert!(
        elapsed < Duration::from_secs(30),
        "driver should give up retrying and exit within its bounded retry \
         window (took {}s), output:\n{output}",
        elapsed.as_secs()
    );
}

/// The error surfaced when the Podman socket is unreachable should name the
/// configured socket path and describe a connection failure, not a generic
/// panic or timeout with no actionable detail.
#[tokio::test]
async fn driver_error_names_unreachable_socket() {
    let (output, code, _, missing_socket) = run_with_unreachable_podman_socket().await;

    assert_ne!(code, 0);
    let clean = strip_ansi(&output);

    assert!(
        clean.contains("connection error"),
        "driver error should describe a connection failure:\n{clean}"
    );
    assert!(
        clean.contains(missing_socket.to_str().expect("socket path is utf-8")),
        "driver error should name the unreachable socket path {}:\n{clean}",
        missing_socket.display()
    );
}
