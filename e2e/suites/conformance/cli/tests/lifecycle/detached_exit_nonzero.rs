// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::helpers::{expect_terminal_result, run_gated_main};
use openshell_e2e_support::OpenShellRunner;

/// Verify a detached main process that exits nonzero leaves the sandbox in Error
/// with the code recorded.
#[tokio::test]
async fn detached_canonical_main_nonzero_exit_reaches_error() {
    let mut runner = OpenShellRunner::from_env("sandbox-lifecycle/detached-exit-nonzero")
        .expect("candidate openshell CLI is available");
    let result = async {
        runner.check_gateway_status().await?;
        let runner = &mut runner;
        let sandbox_name = format!("ct-{}-dn", runner.id());
        run_gated_main(runner, &sandbox_name, 11, "detached-exit-nonzero").await?;
        expect_terminal_result(
            runner,
            &sandbox_name,
            "Error",
            11,
            "detached-exit-nonzero/error",
        )
        .await?;
        Ok(())
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("sandbox-lifecycle/detached-exit-nonzero conformance story failed:\n{error}");
    }
}
