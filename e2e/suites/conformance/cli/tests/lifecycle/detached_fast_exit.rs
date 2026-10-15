// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::helpers::{create_with_main, expect_terminal_result};
use openshell_e2e_support::OpenShellRunner;

/// Verify a detached main process that exits while the sandbox is still
/// provisioning is reported as a workload result, not a provisioning failure.
#[tokio::test]
async fn detached_main_exit_during_provisioning_is_classified_as_workload_result() {
    let mut runner = OpenShellRunner::from_env("sandbox-lifecycle/detached-fast-exit")
        .expect("candidate openshell CLI is available");
    let result = async {
        runner.check_gateway_status().await?;
        let runner = &mut runner;
        let sandbox_name = format!("ct-{}-fx", runner.id());
        create_with_main(
            runner,
            &sandbox_name,
            &["--detach"],
            &["sh", "-c", "exit 11"],
            "detached-fast-exit/create",
        )
        .await?
        .require_success()?;
        let state = expect_terminal_result(
            runner,
            &sandbox_name,
            "Error",
            11,
            "detached-fast-exit/error",
        )
        .await?;
        // Error alone does not separate a workload result from a provisioning
        // failure; the documented Ready reason does.
        let ready = state
            .conditions
            .iter()
            .find(|condition| condition.kind == "Ready");
        if ready.map(|condition| condition.reason.as_str()) != Some("MainProcessFailed") {
            return Err(format!(
                "sandbox '{sandbox_name}' Ready condition is {ready:?}; expected reason MainProcessFailed"
            ));
        }
        Ok(())
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("sandbox-lifecycle/detached-fast-exit conformance story failed:\n{error}");
    }
}
