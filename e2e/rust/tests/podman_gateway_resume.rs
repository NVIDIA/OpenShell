// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-podman")]

//! Podman-specific E2E coverage for resuming sandboxes after a standalone
//! gateway restart.
//!
//! Unlike the Docker driver, Podman does not stop sandbox containers when the
//! gateway process exits — the containers keep running and the restarted
//! gateway re-adopts them. This test follows the `vm_gateway_resume.rs`
//! pattern: verify sandbox survival at the application level without asserting
//! intermediate container-state transitions.

use openshell_e2e::harness::gateway::ManagedGateway;
use openshell_e2e::harness::resume::{NoopGatewayResumeHooks, run_gateway_resume_scenario};

#[tokio::test]
async fn podman_gateway_restart_resumes_running_sandbox() {
    if std::env::var("OPENSHELL_E2E_DRIVER").as_deref() != Ok("podman") {
        eprintln!("Skipping Podman gateway resume test: e2e driver is not podman");
        return;
    }
    let Some(gateway) = ManagedGateway::from_env().expect("load managed e2e gateway metadata")
    else {
        eprintln!(
            "Skipping Podman gateway resume test: e2e gateway is not managed by this test run"
        );
        return;
    };

    run_gateway_resume_scenario(&gateway, "Podman", &NoopGatewayResumeHooks).await;
}
