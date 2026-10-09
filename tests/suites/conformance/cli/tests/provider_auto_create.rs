// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Driver-agnostic provider auto-creation conformance test.

use openshell_conformance::{OpenShellRunner, PROVIDER_AUTO_CREATE_SCENARIO};

/// Exercise `--provider` auto-creation through the candidate CLI.
#[tokio::test]
async fn auto_create() {
    let mut runner = OpenShellRunner::from_env(PROVIDER_AUTO_CREATE_SCENARIO.name)
        .expect("candidate openshell CLI is available");
    let result = async {
        runner.check_gateway_status().await?;
        PROVIDER_AUTO_CREATE_SCENARIO.run(&mut runner).await
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("provider-auto-create conformance scenario failed:\n{error}");
    }
}
