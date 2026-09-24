// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Driver-agnostic sandbox file-transfer conformance tests.

use openshell_conformance::{
    FILE_TRANSFER_GIT_FILTERING_SCENARIO, FILE_TRANSFER_PATH_SAFETY_SCENARIO,
    FILE_TRANSFER_ROUND_TRIP_SCENARIO, OpenShellRunner, Scenario,
};

/// Exercise file and directory round trips through the candidate CLI.
#[tokio::test]
async fn round_trip() {
    run(FILE_TRANSFER_ROUND_TRIP_SCENARIO).await;
}

/// Exercise Git-aware upload filtering through the candidate CLI.
#[tokio::test]
async fn git_filtering() {
    run(FILE_TRANSFER_GIT_FILTERING_SCENARIO).await;
}

/// Exercise workspace boundary and filename safety through the candidate CLI.
#[tokio::test]
async fn path_safety() {
    run(FILE_TRANSFER_PATH_SAFETY_SCENARIO).await;
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
