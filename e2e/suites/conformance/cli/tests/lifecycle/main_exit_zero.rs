// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::helpers::{create_with_main, expect_terminal_result, require_output_line};
use openshell_e2e_support::OpenShellRunner;

/// Verify a main process that exits 0 leaves a retained sandbox in Completed.
#[tokio::test]
async fn canonical_main_exit_zero_completes_persistent_sandbox() {
    let mut runner = OpenShellRunner::from_env("sandbox-lifecycle/main-exit-zero")
        .expect("candidate openshell CLI is available");
    let result = async {
        runner.check_gateway_status().await?;
        let runner = &mut runner;
        let sandbox_name = format!("ct-{}-mz", runner.id());
        let create = create_with_main(
            runner,
            &sandbox_name,
            &[],
            &["echo", "OK"],
            "main-exit-zero/create",
        )
        .await?;
        create.require_success()?;
        require_output_line(&create, "OK")?;
        expect_terminal_result(
            runner,
            &sandbox_name,
            "Completed",
            0,
            "main-exit-zero/completed",
        )
        .await?;
        Ok(())
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("sandbox-lifecycle/main-exit-zero conformance story failed:\n{error}");
    }
}
