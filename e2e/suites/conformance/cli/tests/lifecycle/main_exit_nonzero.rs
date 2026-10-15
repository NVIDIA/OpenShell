// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::helpers::{create_with_main, expect_terminal_result, require_output_line};
use openshell_e2e_support::OpenShellRunner;

/// Verify a main process that exits nonzero fails the create command with that
/// code and leaves the sandbox in Error with the code recorded.
#[tokio::test]
async fn canonical_main_nonzero_exit_preserves_status() {
    let mut runner = OpenShellRunner::from_env("sandbox-lifecycle/main-exit-nonzero")
        .expect("candidate openshell CLI is available");
    let result = async {
        runner.check_gateway_status().await?;
        let runner = &mut runner;
        let sandbox_name = format!("ct-{}-mn", runner.id());
        let create = create_with_main(
            runner,
            &sandbox_name,
            &[],
            &["sh", "-c", "echo failed-main; exit 7"],
            "main-exit-nonzero/create",
        )
        .await?;
        if create.exit_code() != Some(7) {
            return Err(create.failure_diagnostic("create exits with the main process code 7"));
        }
        require_output_line(&create, "failed-main")?;
        expect_terminal_result(runner, &sandbox_name, "Error", 7, "main-exit-nonzero/error")
            .await?;
        Ok(())
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("sandbox-lifecycle/main-exit-nonzero conformance story failed:\n{error}");
    }
}
