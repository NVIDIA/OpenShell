// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Driver-agnostic sandbox lifecycle conformance tests.

use ryno_conformance::{RynoRunner, SANDBOX_LIFECYCLE_SCENARIO};

/// Exercise stop, start, and stopped-deletion behavior through the candidate CLI.
#[tokio::test]
async fn sandbox_lifecycle() {
    let mut runner = RynoRunner::from_env(SANDBOX_LIFECYCLE_SCENARIO.name)
        .expect("candidate ryno CLI is available");

    let result = async {
        runner.check_gateway_status().await?;
        SANDBOX_LIFECYCLE_SCENARIO.run(&mut runner).await
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("sandbox lifecycle conformance scenario failed:\n{error}");
    }
}
