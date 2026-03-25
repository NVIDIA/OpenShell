// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! Smoke test: verify the gateway is healthy, create a sandbox, exec a
//! command inside it, and tear it down.
//!
//! This test is cluster-agnostic — it works against any running gateway
//! (Docker-based cluster or openshell-vm microVM).  The `e2e:vm` mise
//! task uses it to validate the VM gateway after boot.

use std::process::Stdio;
use std::time::Duration;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;

/// End-to-end smoke test: status → create → exec → list → delete.
#[tokio::test]
async fn gateway_smoke() {
    // ── 1. Gateway must be reachable ──────────────────────────────────
    let mut clean_status = String::new();
    let mut status_ok = false;
    for _ in 0..15 {
        let mut status_cmd = openshell_cmd();
        status_cmd
            .arg("status")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let status_out = status_cmd
            .output()
            .await
            .expect("failed to run openshell status");

        let status_text = format!(
            "{}{}",
            String::from_utf8_lossy(&status_out.stdout),
            String::from_utf8_lossy(&status_out.stderr),
        );
        clean_status = strip_ansi(&status_text);

        if status_out.status.success() && clean_status.contains("Connected") {
            status_ok = true;
            break;
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    assert!(
        status_ok,
        "openshell status never became healthy:\n{clean_status}",
    );

    // ── 2. Create a sandbox and exec a command ───────────────────────
    // Default behaviour keeps the sandbox alive after the command exits,
    // so we can verify it in the list before cleaning up.
    let mut sb = SandboxGuard::create(&["--", "echo", "smoke-ok"])
        .await
        .expect("sandbox create should succeed");

    assert!(
        sb.create_output.contains("smoke-ok"),
        "expected 'smoke-ok' in sandbox output:\n{}",
        sb.create_output,
    );

    // ── 3. Verify the sandbox appeared in the list ───────────────────
    let mut list_cmd = openshell_cmd();
    list_cmd
        .args(["sandbox", "list", "--names"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let list_out = list_cmd
        .output()
        .await
        .expect("failed to run openshell sandbox list");

    let list_text = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&list_out.stdout),
        String::from_utf8_lossy(&list_out.stderr),
    ));

    assert!(
        list_text.contains(&sb.name),
        "sandbox '{}' should appear in list output:\n{list_text}",
        sb.name,
    );

    // ── 4. Cleanup ───────────────────────────────────────────────────
    sb.cleanup().await;
}
