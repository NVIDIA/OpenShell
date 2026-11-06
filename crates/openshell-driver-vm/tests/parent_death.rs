// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn managed_driver_rejects_a_missing_gateway_parent() {
    let state = tempfile::tempdir().expect("create driver state directory");
    let socket = state.path().join("driver.sock");
    let stale_gateway_pid = std::process::id().wrapping_add(1);

    let mut child = Command::new(env!("CARGO_BIN_EXE_openshell-driver-vm"))
        .arg("--bind-socket")
        .arg(&socket)
        .arg("--expected-peer-pid")
        .arg(stale_gateway_pid.to_string())
        .arg("--grpc-endpoint")
        .arg("http://127.0.0.1:9")
        .arg("--bootstrap-image")
        .arg("example.invalid/bootstrap:latest")
        .arg("--state-dir")
        .arg(state.path())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start managed driver");

    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll driver") {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().expect("stop driver after timeout");
            child.wait().expect("reap driver after timeout");
            panic!("driver kept running after its expected gateway parent was absent");
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("driver stderr")
        .read_to_string(&mut stderr)
        .expect("read driver stderr");
    assert!(!status.success(), "driver unexpectedly succeeded: {stderr}");
    assert!(
        stderr.contains("expected gateway parent PID"),
        "driver did not reject the stale gateway parent: {stderr}"
    );
    assert!(!socket.exists(), "driver created a socket after rejection");
}
