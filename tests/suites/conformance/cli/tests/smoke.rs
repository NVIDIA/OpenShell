// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Driver-agnostic `Ryno` CLI conformance tests.

use ryno_conformance::{RynoRunner, SMOKE_SCENARIO};

/// Exercise the public CLI against a provisioned `Ryno` gateway.
///
/// The test runner supplies the candidate CLI explicitly so the same archive
/// can validate artifacts installed into any supported test guest.
#[tokio::test]
async fn smoke() {
    let mut runner = RynoRunner::from_env(SMOKE_SCENARIO.name)
        .expect("candidate ryno CLI is available");
    let result = async {
        runner.check_gateway_status().await?;
        SMOKE_SCENARIO.run(&mut runner).await
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("conformance smoke scenario failed:\n{error}");
    }
}
