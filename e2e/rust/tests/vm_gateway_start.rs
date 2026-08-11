// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-vm")]

//! VM-specific E2E coverage for starting sandboxes after a standalone gateway
//! restart.
//!
//! This test is gated behind the `e2e-vm` feature because it requires the VM
//! driver runtime prepared by `e2e/rust/e2e-vm.sh`.

use std::time::Duration;

use openshell_e2e::harness::cli::{
    sandbox_names, wait_for_healthy, wait_for_sandbox_exec_contains,
};
use openshell_e2e::harness::gateway::ManagedGateway;
use openshell_e2e::harness::sandbox::SandboxGuard;

const READY_MARKER: &str = "vm-gateway-start-ready";
const START_FILE: &str = "/sandbox/vm-gateway-start-state";

#[tokio::test]
async fn vm_gateway_restart_starts_running_sandbox() {
    if std::env::var("OPENSHELL_E2E_DRIVER").as_deref() != Ok("vm") {
        eprintln!("Skipping VM gateway start test: e2e driver is not vm");
        return;
    }
    let Some(gateway) = ManagedGateway::from_env().expect("load managed e2e gateway metadata")
    else {
        eprintln!("Skipping VM gateway start test: e2e gateway is not managed by this test run");
        return;
    };

    wait_for_healthy(Duration::from_secs(30))
        .await
        .expect("gateway should start healthy");

    // The gateway restart terminates the VM process before re-adopting its
    // overlay. Flush the marker before reporting readiness so the assertion
    // verifies durable overlay state rather than guest page-cache timing.
    let script = format!(
        "echo before-restart > {START_FILE}; sync; echo {READY_MARKER}; while true; do sleep 1; done"
    );
    let mut sandbox = SandboxGuard::create_keep(&["sh", "-lc", &script], READY_MARKER)
        .await
        .expect("create long-running VM sandbox");

    let before_restart = sandbox
        .exec(&["cat", START_FILE])
        .await
        .expect("read VM sandbox state before restart");
    assert!(
        before_restart.contains("before-restart"),
        "VM sandbox state was not written before restart:\n{before_restart}"
    );

    gateway.stop().expect("stop e2e gateway");
    gateway.start().expect("restart e2e gateway");
    wait_for_healthy(Duration::from_secs(120))
        .await
        .expect("gateway should become healthy after restart");

    let names = sandbox_names().await.expect("list sandboxes after restart");
    assert!(
        names.contains(&sandbox.name),
        "sandbox '{}' should still be listed after gateway restart. Names: {names:?}",
        sandbox.name
    );

    wait_for_sandbox_exec_contains(
        &sandbox.name,
        &["cat", START_FILE],
        "before-restart",
        Duration::from_secs(240),
    )
    .await
    .expect("VM sandbox should become ready again with its overlay state preserved");

    sandbox.cleanup().await;
}
