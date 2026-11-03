// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Exhaustive raw status fixture for the documented next-minor API transition.
//!
//! This intentionally advances the v0.1.5 source baseline. Legacy wire payloads
//! still decode; complete raw Rust literals need the new optional field.
//! See the SDK README migration notice. Do not backport into a 0.1.x patch train.

use openshell_sdk::raw::proto::SandboxStatus;

#[test]
fn next_minor_exhaustive_sandbox_status_literal_compiles() {
    // Intentionally no `..Default::default()`: future shape changes must be
    // reviewed against this declared minor baseline, never silently accepted.
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
        launch_policy: None,
    };
    assert_eq!(status, SandboxStatus::default());
}
