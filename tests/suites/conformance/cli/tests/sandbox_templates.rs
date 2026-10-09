// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Driver-agnostic sandbox workload template conformance tests.

use openshell_conformance::{
    OpenShellRunner, SANDBOX_TEMPLATE_DUPLICATE_NAME_SCENARIO,
    SANDBOX_TEMPLATE_GET_AFTER_DELETE_SCENARIO, SANDBOX_TEMPLATE_LIFECYCLE_SCENARIO,
    SANDBOX_TEMPLATE_MISSING_TEMPLATE_SCENARIO, Scenario,
};

/// Exercise template create/get/list and template-backed sandbox creation.
#[tokio::test]
async fn lifecycle() {
    run(SANDBOX_TEMPLATE_LIFECYCLE_SCENARIO).await;
}

/// Exercise that a deleted template returns not-found.
#[tokio::test]
async fn get_after_delete() {
    run(SANDBOX_TEMPLATE_GET_AFTER_DELETE_SCENARIO).await;
}

/// Exercise that duplicate template creation is rejected.
#[tokio::test]
async fn duplicate_name() {
    run(SANDBOX_TEMPLATE_DUPLICATE_NAME_SCENARIO).await;
}

/// Exercise that sandbox creation from a missing template returns not-found.
#[tokio::test]
async fn missing_template() {
    run(SANDBOX_TEMPLATE_MISSING_TEMPLATE_SCENARIO).await;
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
