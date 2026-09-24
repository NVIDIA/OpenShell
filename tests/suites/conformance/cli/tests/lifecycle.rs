// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Driver-agnostic sandbox lifecycle conformance tests.

use openshell_conformance::{
    OpenShellRunner, SANDBOX_LIFECYCLE_RELAY_READINESS_SCENARIO,
    SANDBOX_LIFECYCLE_RELAY_RECONNECT_SCENARIO, SANDBOX_LIFECYCLE_STATE_TRANSITIONS_SCENARIO,
    Scenario,
};

/// Exercise stop, start, and stopped-deletion behavior through the candidate CLI.
#[tokio::test]
async fn state_transitions() {
    run(SANDBOX_LIFECYCLE_STATE_TRANSITIONS_SCENARIO).await;
}

/// Exercise relay readiness during sandbox startup reconnects.
#[tokio::test]
async fn relay_readiness() {
    run(SANDBOX_LIFECYCLE_RELAY_READINESS_SCENARIO).await;
}

/// Exercise an in-flight relay across a deterministic supervisor reconnect when supported.
#[tokio::test]
async fn relay_reconnect() {
    run(SANDBOX_LIFECYCLE_RELAY_RECONNECT_SCENARIO).await;
}

async fn run(scenario: Scenario) {
    let mut runner = OpenShellRunner::from_env(scenario.name)
        .expect("candidate openshell CLI is available");

    let result = async {
        runner.check_gateway_status().await?;
        scenario.run(&mut runner).await
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("{} conformance scenario failed:\n{error}", scenario.name);
    }
}
