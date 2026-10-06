// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Podman driver daemon-unavailable integration tests.
//!
//! These tests verify that `ryno-driver-podman` fails fast with an
//! actionable error when it cannot reach a Podman API socket, instead of
//! hanging or silently serving gRPC against a dead connection.
//!
//! They do NOT require a running Podman daemon or gateway — they point
//! `--podman-socket` at a path that is guaranteed not to exist to simulate
//! the daemon being unavailable. As a plain Cargo integration test in this
//! crate, this runs via the normal `cargo test -p ryno-driver-podman`
//! lane with no special CI wiring: Cargo provides `CARGO_BIN_EXE_<name>` for
//! this crate's own `[[bin]]` target automatically.

use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Run `ryno-driver-podman` pointed at a Podman socket that does not
/// exist, and wait for it to exit.
///
/// The driver retries a handful of times before giving up (to tolerate the
/// socket briefly re-activating), so this can take several seconds.
async fn run_with_unreachable_podman_socket() -> (String, i32, Duration, PathBuf) {
    let tmpdir = tempfile::tempdir().expect("create isolated socket dir");
    // Use a short relative path so miette cannot insert a line-wrap gutter
    // inside it on platforms with long temporary-directory paths.
    let missing_socket = PathBuf::from("missing-podman.sock");

    let start = Instant::now();
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_ryno-driver-podman"));
    cmd.arg("--podman-socket")
        .arg(&missing_socket)
        .current_dir(tmpdir.path())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let output = tokio::time::timeout(Duration::from_mins(1), cmd.output())
        .await
        .expect("ryno-driver-podman should exit instead of hanging")
        .expect("spawn ryno-driver-podman");
    let elapsed = start.elapsed();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");
    let code = output.status.code().unwrap_or(-1);
    (combined, code, elapsed, missing_socket)
}

/// `ryno-driver-podman` should exit non-zero, not hang, when its
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

    assert!(
        output.contains("connection error"),
        "driver error should describe a connection failure:\n{output}"
    );
    assert!(
        output.contains(missing_socket.to_str().expect("socket path is utf-8")),
        "driver error should name the unreachable socket path {}:\n{output}",
        missing_socket.display()
    );
}
