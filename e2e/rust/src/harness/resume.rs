// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared application-level contract for gateway restart and sandbox resume.

use std::time::Duration;

use super::cli::{sandbox_names, wait_for_healthy, wait_for_sandbox_exec_contains};
use super::gateway::ManagedGateway;
use super::sandbox::SandboxGuard;

const READY_MARKER: &str = "gateway-resume-ready";
const RESUME_FILE: &str = "/sandbox/gateway-resume-state";

/// Driver-specific observations around the shared gateway restart sequence.
#[allow(async_fn_in_trait)] // Internal e2e hook; callers do not require Send bounds.
pub trait GatewayResumeHooks {
    fn flush_state_before_ready(&self) -> bool {
        false
    }

    async fn before_gateway_stop(&self, _sandbox_name: &str) -> Result<(), String> {
        Ok(())
    }

    async fn after_gateway_stop(&self, _sandbox_name: &str) -> Result<(), String> {
        Ok(())
    }

    async fn after_gateway_start(&self, _sandbox_name: &str) -> Result<(), String> {
        Ok(())
    }
}

/// Hooks for drivers that need only the application-level resume assertions.
pub struct NoopGatewayResumeHooks;

impl GatewayResumeHooks for NoopGatewayResumeHooks {}

/// Run the common gateway restart and sandbox state-preservation contract.
pub async fn run_gateway_resume_scenario(
    gateway: &ManagedGateway,
    driver_name: &str,
    hooks: &impl GatewayResumeHooks,
) {
    wait_for_healthy(Duration::from_secs(30))
        .await
        .unwrap_or_else(|error| panic!("{driver_name} gateway should start healthy: {error}"));

    let flush = if hooks.flush_state_before_ready() {
        "sync; "
    } else {
        ""
    };
    let script = format!(
        "echo before-restart > {RESUME_FILE}; {flush}echo {READY_MARKER}; while true; do sleep 1; done"
    );
    let mut sandbox = SandboxGuard::create_keep(&["sh", "-lc", &script], READY_MARKER)
        .await
        .unwrap_or_else(|error| panic!("create long-running {driver_name} sandbox: {error}"));

    let before_restart = sandbox
        .exec(&["cat", RESUME_FILE])
        .await
        .unwrap_or_else(|error| panic!("read {driver_name} sandbox state before restart: {error}"));
    assert!(
        before_restart.contains("before-restart"),
        "{driver_name} sandbox state was not written before restart:\n{before_restart}"
    );

    hooks
        .before_gateway_stop(&sandbox.name)
        .await
        .unwrap_or_else(|error| panic!("{driver_name} pre-stop observation failed: {error}"));
    gateway
        .stop()
        .unwrap_or_else(|error| panic!("stop {driver_name} e2e gateway: {error}"));
    hooks
        .after_gateway_stop(&sandbox.name)
        .await
        .unwrap_or_else(|error| panic!("{driver_name} post-stop observation failed: {error}"));

    gateway
        .start()
        .unwrap_or_else(|error| panic!("restart {driver_name} e2e gateway: {error}"));
    wait_for_healthy(Duration::from_secs(120))
        .await
        .unwrap_or_else(|error| {
            panic!("{driver_name} gateway should become healthy after restart: {error}")
        });
    hooks
        .after_gateway_start(&sandbox.name)
        .await
        .unwrap_or_else(|error| panic!("{driver_name} post-start observation failed: {error}"));

    let names = sandbox_names()
        .await
        .unwrap_or_else(|error| panic!("list {driver_name} sandboxes after restart: {error}"));
    assert!(
        names.contains(&sandbox.name),
        "{} sandbox '{}' should still be listed after gateway restart. Names: {names:?}",
        driver_name,
        sandbox.name,
    );

    wait_for_sandbox_exec_contains(
        &sandbox.name,
        &["cat", RESUME_FILE],
        "before-restart",
        Duration::from_secs(240),
    )
    .await
    .unwrap_or_else(|error| {
        panic!("{driver_name} sandbox should resume with its state preserved: {error}")
    });

    sandbox.cleanup().await;
}
