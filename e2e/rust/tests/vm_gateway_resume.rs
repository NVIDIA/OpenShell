// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-vm")]

//! VM-specific E2E coverage for resuming sandboxes after a standalone gateway
//! restart.
//!
//! This test is gated behind the `e2e-vm` feature because it requires the VM
//! driver runtime prepared by `e2e/rust/e2e-vm.sh`.

use openshell_e2e::harness::gateway::ManagedGateway;
use openshell_e2e::harness::resume::{GatewayResumeHooks, run_gateway_resume_scenario};

struct VmResumeHooks;

impl GatewayResumeHooks for VmResumeHooks {
    fn flush_state_before_ready(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn vm_gateway_restart_resumes_running_sandbox() {
    if std::env::var("OPENSHELL_E2E_DRIVER").as_deref() != Ok("vm") {
        eprintln!("Skipping VM gateway resume test: e2e driver is not vm");
        return;
    }
    let Some(gateway) = ManagedGateway::from_env().expect("load managed e2e gateway metadata")
    else {
        eprintln!("Skipping VM gateway resume test: e2e gateway is not managed by this test run");
        return;
    };

    // The gateway restart terminates the VM process before re-adopting its
    // overlay. The VM hook flushes the marker before reporting readiness so
    // the assertion verifies durable overlay state rather than page-cache timing.
    run_gateway_resume_scenario(&gateway, "VM", &VmResumeHooks).await;
}
