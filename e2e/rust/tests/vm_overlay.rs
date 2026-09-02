// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! VM-driver-specific assertions for the sandbox root filesystem.

use std::process::Stdio;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;

#[tokio::test]
async fn vm_overlay() {
    let mut sandbox = SandboxGuard::create_keep(
        &["sh", "-c", "echo vm-sandbox-ready; exec sleep infinity"],
        "vm-sandbox-ready",
    )
    .await
    .expect("sandbox create should start a durable main process");

    let script = concat!(
        "set -eu; ",
        "test \"$(stat -f -c %T /)\" = \"overlayfs\"; ",
        "printf \"overlay-write\\n\" > /sandbox/overlay-check; ",
        "test \"$(cat /sandbox/overlay-check)\" = \"overlay-write\"; ",
        "if [ -e /opt/openshell/tls/tls.key ]; then ",
        "test \"$(stat -c %a /opt/openshell/tls/tls.key)\" = \"600\"; ",
        "fi; ",
        "echo vm-overlay-ok",
    );

    let mut exec_cmd = openshell_cmd();
    exec_cmd
        .args(["sandbox", "exec", "--name", &sandbox.name, "--no-tty", "--"])
        .arg("sh")
        .arg("-lc")
        .arg(script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = exec_cmd
        .output()
        .await
        .expect("failed to run VM overlay assertion");
    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    ));
    assert!(
        output.status.success() && combined.contains("vm-overlay-ok"),
        "VM overlay assertion failed (status {:?}):\n{combined}",
        output.status.code(),
    );

    sandbox.cleanup().await;
}
