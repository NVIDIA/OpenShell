// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Compile-time fixture for the public status shape with execution identity.

use openshell_sdk::raw::proto::SandboxStatus;

#[test]
fn exhaustive_sandbox_status_literal_includes_execution_identity() {
    // The additive wire field changes exhaustive generated Rust literals.
    // Keep this fixture current so future additions are reviewed explicitly.
    let status = SandboxStatus {
        agent_pod: String::new(),
        agent_fd: String::new(),
        sandbox_fd: String::new(),
        conditions: Vec::new(),
        phase: 0,
        current_policy_version: 0,
        main_process_instance_id: String::new(),
        exit_code: None,
        endpoint_statuses: Vec::new(),
        configuration_admission: None,
        configuration_activated: None,
        provisioning: None,
        restart_count: 0,
        next_restart_time: None,
        main_process_started_time: None,
        last_token_grant_failure: None,
        execution_id: String::new(),
    };
    assert_eq!(status, SandboxStatus::default());
}
