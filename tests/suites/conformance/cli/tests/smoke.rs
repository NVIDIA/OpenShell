// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Driver-agnostic `OpenShell` CLI conformance tests.

use openshell_conformance::{OpenShellRunner, SMOKE_SCENARIO};

/// Exercise the public CLI against a provisioned `OpenShell` gateway.
///
/// The test runner supplies the candidate CLI explicitly so the same archive
/// can validate artifacts installed into any supported test guest.
#[tokio::test]
async fn smoke() {
    let mut runner = OpenShellRunner::from_env(SMOKE_SCENARIO.name)
        .expect("candidate openshell CLI is available");
    let result = async {
        runner.check_gateway_status().await?;
        SMOKE_SCENARIO.run(&mut runner).await
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("conformance smoke scenario failed:\n{error}");
    }
}
