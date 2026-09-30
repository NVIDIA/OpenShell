// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Driver-agnostic `OpenShell` CLI conformance tests.

use openshell_conformance::{
    OpenShellRunner, SMOKE_CONTROL_PLANE_SCENARIO, SMOKE_EXEC_SCENARIO, Scenario,
};

/// Exercise the public CLI against a provisioned `OpenShell` gateway.
///
/// The test runner supplies the candidate CLI explicitly so the same archive
/// can validate artifacts installed into any supported test guest.
#[tokio::test]
async fn control_plane() {
    run_scenario(&SMOKE_CONTROL_PLANE_SCENARIO).await;
}

/// Exercise sandbox exec separately so failures identify this capability gap.
#[tokio::test]
async fn exec() {
    run_scenario(&SMOKE_EXEC_SCENARIO).await;
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
