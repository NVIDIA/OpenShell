// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E coverage for Docker startup resume after a sandbox JWT expires while
//! its container is stopped during a gateway restart.

use std::time::Duration;

use openshell_e2e::harness::cli::{
    sandbox_names, wait_for_healthy, wait_for_sandbox_exec_contains,
};
use openshell_e2e::harness::docker::wait_for_container_running;
use openshell_e2e::harness::gateway::ManagedGateway;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tokio::time::sleep;

const READY_MARKER: &str = "gateway-resume-expired-token-ready";
const RESUME_FILE: &str = "/sandbox/gateway-resume-expired-token-state";

fn short_sandbox_jwt_ttl_secs() -> Option<u64> {
    std::env::var("OPENSHELL_E2E_SANDBOX_JWT_TTL_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|ttl| (1..=10).contains(ttl))
}

#[tokio::test]
async fn docker_gateway_restart_reissues_expired_sandbox_token_before_resume() {
    let Some(ttl_secs) = short_sandbox_jwt_ttl_secs() else {
        eprintln!(
            "Skipping expired-token gateway resume test: set OPENSHELL_E2E_SANDBOX_JWT_TTL_SECS to 1..=10"
        );
        return;
    };
    let Some(gateway) = ManagedGateway::from_env().expect("load managed e2e gateway metadata")
    else {
        eprintln!(
            "Skipping expired-token gateway resume test: e2e gateway is not managed by this test run"
        );
        return;
    };
    let Some(namespace) = std::env::var("OPENSHELL_E2E_DOCKER_NETWORK_NAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        eprintln!("Skipping expired-token gateway resume test: Docker e2e namespace is unavailable");
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
        .expect("create long-running sandbox");

    wait_for_sandbox_exec_contains(
        &sandbox.name,
        &["cat", RESUME_FILE],
        "before-token-expiry",
        Duration::from_secs(60),
    )
    .await
    .expect("sandbox should be ready before gateway stop");
    wait_for_container_running(&namespace, &sandbox.name, true, Duration::from_secs(60))
        .await
        .expect("sandbox container should be running before gateway restart");

    gateway.stop().expect("stop e2e gateway");
    wait_for_container_running(&namespace, &sandbox.name, false, Duration::from_secs(120))
        .await
        .expect("gateway shutdown should stop managed Docker sandboxes");
    sleep(Duration::from_secs(ttl_secs.saturating_add(2).max(5))).await;

    gateway.start().expect("restart e2e gateway");
    wait_for_healthy(Duration::from_secs(120))
        .await
        .expect("gateway should become healthy after restart");
    wait_for_container_running(&namespace, &sandbox.name, true, Duration::from_secs(120))
        .await
        .expect("gateway startup should resume the Docker sandbox container");

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
    .expect("sandbox should reconnect after startup resume with a reissued token");

    sandbox.cleanup().await;
}
