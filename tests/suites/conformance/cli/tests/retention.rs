// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Driver-agnostic sandbox retention conformance tests.

use openshell_conformance::{OpenShellRunner, SANDBOX_RETENTION_SCENARIO};

/// Exercise ephemeral deletion and retained access after the main process exits.
#[tokio::test]
async fn sandbox_retention() {
    let mut runner = OpenShellRunner::from_env(SANDBOX_RETENTION_SCENARIO.name)
        .expect("candidate openshell CLI is available");

    let result = async {
        runner.check_gateway_status().await?;
        SANDBOX_RETENTION_SCENARIO.run(&mut runner).await
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("sandbox retention conformance scenario failed:\n{error}");
    }
}
