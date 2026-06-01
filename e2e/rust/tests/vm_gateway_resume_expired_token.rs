// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-vm")]

//! VM e2e coverage for gateway-owned sandbox JWT reissue before startup resume.

use std::time::Duration;

use openshell_e2e::harness::cli::{sandbox_names, wait_for_healthy, wait_for_sandbox_exec_contains};
use openshell_e2e::harness::gateway::ManagedGateway;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tokio::time::sleep;

const READY_MARKER: &str = "vm-gateway-resume-expired-token-ready";
const RESUME_FILE: &str = "/sandbox/vm-gateway-resume-expired-token-state";

fn short_sandbox_jwt_ttl_secs() -> Option<u64> {
    std::env::var("OPENSHELL_E2E_SANDBOX_JWT_TTL_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|ttl| (1..=10).contains(ttl))
}

#[tokio::test]
async fn vm_gateway_restart_reissues_expired_sandbox_token_before_resume() {
    if std::env::var("OPENSHELL_E2E_DRIVER").as_deref() != Ok("vm") {
        eprintln!("Skipping VM expired-token resume test: e2e driver is not vm");
        return;
    }
    let Some(ttl_secs) = short_sandbox_jwt_ttl_secs() else {
        eprintln!(
            "Skipping VM expired-token resume test: set OPENSHELL_E2E_SANDBOX_JWT_TTL_SECS to 1..=10"
        );
        return;
    };
    let Some(gateway) = ManagedGateway::from_env().expect("load managed e2e gateway metadata")
    else {
        eprintln!(
            "Skipping VM expired-token resume test: e2e gateway is not managed by this test run"
        );
        return;
    };

    wait_for_healthy(Duration::from_secs(30))
        .await
        .expect("gateway should start healthy");

    let script = format!(
        "echo before-token-expiry > {RESUME_FILE}; echo {READY_MARKER}; while true; do sleep 1; done"
    );
    let mut sandbox = SandboxGuard::create_keep(&["sh", "-lc", &script], READY_MARKER)
        .await
        .expect("create long-running VM sandbox");

    wait_for_sandbox_exec_contains(
        &sandbox.name,
        &["cat", RESUME_FILE],
        "before-token-expiry",
        Duration::from_secs(240),
    )
    .await
    .expect("VM sandbox should be ready before gateway stop");

    gateway.stop().expect("stop e2e gateway");
    sleep(Duration::from_secs(ttl_secs.saturating_add(2).max(5))).await;

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
        &["cat", RESUME_FILE],
        "before-token-expiry",
        Duration::from_secs(240),
    )
    .await
    .expect("VM sandbox should reconnect after startup resume with a reissued token");

    sandbox.cleanup().await;
}
