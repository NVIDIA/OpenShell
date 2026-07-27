// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-podman")]

use std::process::Stdio;
use std::time::{Duration, Instant};

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;

const DELETE_ATTEMPTS: usize = 1;
const MAX_DELETE_DURATION: Duration = Duration::from_secs(55);

#[tokio::test]
async fn podman_shutdown_transport_closes_are_expected() {
    assert_eq!(
        std::env::var("OPENSHELL_E2E_MODE").as_deref(),
        Ok("vm"),
        "Podman shutdown regression must run through the VM-backed runner"
    );
    assert!(
        std::env::var("OPENSHELL_E2E_WITH")
            .unwrap_or_default()
            .split_ascii_whitespace()
            .any(|configuration| configuration == "podman"),
        "Podman shutdown regression requires the Podman VM configuration"
    );

    for attempt in 1..=DELETE_ATTEMPTS {
        let mut sandbox = SandboxGuard::create_keep(
            &["sh", "-lc", "echo shutdown-ready; exec sleep infinity"],
            "shutdown-ready",
        )
        .await
        .unwrap_or_else(|error| panic!("attempt {attempt}: sandbox create failed: {error}"));
        let sandbox_name = sandbox.name.clone();

        let started = Instant::now();
        let mut delete = openshell_cmd();
        delete
            .args(["sandbox", "delete", &sandbox_name])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = delete
            .output()
            .await
            .unwrap_or_else(|error| panic!("attempt {attempt}: failed to spawn delete: {error}"));
        let elapsed = started.elapsed();
        let combined = strip_ansi(&format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));

        assert!(
            output.status.success(),
            "attempt {attempt}: sandbox delete failed after {elapsed:?} (exit {:?}):\n{combined}",
            output.status.code()
        );
        assert!(
            elapsed < MAX_DELETE_DURATION,
            "attempt {attempt}: sandbox delete took {elapsed:?}; expected Podman shutdown within the 45-second grace period plus overhead, in less than {MAX_DELETE_DURATION:?}"
        );

        // Reap the attached CLI process. Its best-effort second delete is a no-op.
        sandbox.cleanup().await;
    }
}
