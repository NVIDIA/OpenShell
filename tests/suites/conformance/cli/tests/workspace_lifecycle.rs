// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Driver-agnostic workspace lifecycle conformance tests.

use openshell_conformance::{
    OpenShellRunner, Scenario, WORKSPACE_LIFECYCLE_SCENARIO, WORKSPACE_TERMINATING_SCENARIO,
};

/// Exercise workspace and workspace-scoped provider CRUD through the candidate CLI.
#[tokio::test]
async fn full_crud_lifecycle() {
    run(WORKSPACE_LIFECYCLE_SCENARIO).await;
}

/// Exercise terminating-workspace create rejection through the candidate CLI.
#[tokio::test]
async fn terminating_rejects_creates() {
    run(WORKSPACE_TERMINATING_SCENARIO).await;
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
