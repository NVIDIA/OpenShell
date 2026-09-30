// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Driver-agnostic sandbox environment conformance tests.

use openshell_conformance::{OpenShellRunner, SANDBOX_ENVIRONMENT_SCENARIO};

/// Exercise declared environment propagation through the candidate CLI.
#[tokio::test]
async fn declared_environment() {
    let mut runner = OpenShellRunner::from_env(SANDBOX_ENVIRONMENT_SCENARIO.name)
        .expect("candidate openshell CLI is available");

    let result = async {
        runner.check_gateway_status().await?;
        SANDBOX_ENVIRONMENT_SCENARIO.run(&mut runner).await
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("sandbox environment conformance scenario failed:\n{error}");
    }
}
