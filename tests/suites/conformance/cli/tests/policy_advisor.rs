// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Installed-artifact policy advisor conformance.

use openshell_conformance::{
    MECHANISTIC_PROPOSAL_SCENARIO, OpenShellRunner, POLICY_LOCAL_SCENARIO, Scenario,
};

async fn run(scenario: &'static Scenario) {
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

#[tokio::test]
async fn mechanistic_proposal() {
    run(&MECHANISTIC_PROPOSAL_SCENARIO).await;
}

#[tokio::test]
async fn policy_local() {
    run(&POLICY_LOCAL_SCENARIO).await;
}
