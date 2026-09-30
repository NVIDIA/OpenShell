// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Driver-agnostic sandbox lifecycle conformance tests.

use openshell_conformance::{
    OpenShellRunner, SANDBOX_LIFECYCLE_CONTROL_PLANE_SCENARIO,
    SANDBOX_LIFECYCLE_RESTART_PERSISTENCE_SCENARIO, Scenario,
};

/// Exercise stop and stopped-deletion behavior through the candidate CLI.
#[tokio::test]
async fn control_plane() {
    run_scenario(&SANDBOX_LIFECYCLE_CONTROL_PLANE_SCENARIO).await;
}

/// Exercise restart and workspace persistence through the candidate CLI.
#[tokio::test]
async fn restart_persistence() {
    run_scenario(&SANDBOX_LIFECYCLE_RESTART_PERSISTENCE_SCENARIO).await;
}

async fn run_scenario(scenario: &'static Scenario) {
    let mut runner =
        OpenShellRunner::from_env(scenario.name).expect("candidate openshell CLI is available");

    let result = async {
        runner.check_gateway_status().await?;
        scenario.run(&mut runner).await
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("{} conformance scenario failed:\n{error}", scenario.name);
    }
}
