// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Driver-agnostic sandbox/global settings conformance test.

use openshell_conformance::{OpenShellRunner, SETTINGS_MANAGEMENT_SCENARIO};

/// Exercise sandbox/global settings precedence and override through the candidate CLI.
#[tokio::test]
async fn global_override_round_trip() {
    let mut runner = OpenShellRunner::from_env(SETTINGS_MANAGEMENT_SCENARIO.name)
        .expect("candidate openshell CLI is available");
    let result = async {
        runner.check_gateway_status().await?;
        SETTINGS_MANAGEMENT_SCENARIO.run(&mut runner).await
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("settings-management conformance scenario failed:\n{error}");
    }
}
