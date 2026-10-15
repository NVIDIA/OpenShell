// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::helpers::{expect_terminal_result, run_gated_main};
use openshell_e2e_support::OpenShellRunner;

/// Verify a detached main process that exits 0 leaves the sandbox in Completed.
#[tokio::test]
async fn detached_canonical_main_exit_zero_reaches_completed() {
    let mut runner = OpenShellRunner::from_env("sandbox-lifecycle/detached-exit-zero")
        .expect("candidate openshell CLI is available");
    let result = async {
        runner.check_gateway_status().await?;
        let runner = &mut runner;
        let sandbox_name = format!("ct-{}-dz", runner.id());
        run_gated_main(runner, &sandbox_name, 0, "detached-exit-zero").await?;
        expect_terminal_result(
            runner,
            &sandbox_name,
            "Completed",
            0,
            "detached-exit-zero/completed",
        )
        .await?;
        Ok(())
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("sandbox-lifecycle/detached-exit-zero conformance story failed:\n{error}");
    }
}
