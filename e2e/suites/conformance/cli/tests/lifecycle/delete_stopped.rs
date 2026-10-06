// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::helpers::{
    create_running_sandbox, run_lifecycle_command, wait_for_absence, wait_for_phase,
};
use openshell_e2e_support::OpenShellRunner;

/// Verify a stopped sandbox can be deleted.
#[tokio::test]
async fn deletes_a_stopped_sandbox() {
    let mut runner = OpenShellRunner::from_env("sandbox-lifecycle/delete-stopped")
        .expect("candidate openshell CLI is available");
    let result = async {
        runner.check_gateway_status().await?;
        let runner = &mut runner;
        let sandbox_name = format!("ct-{}-sd", runner.id());
        create_running_sandbox(
            runner,
            &sandbox_name,
            "exec sleep infinity",
            "stopped-delete",
        )
        .await?;

        run_lifecycle_command(runner, "stop", &sandbox_name, "stopped-delete/stop").await?;
        let sandbox =
            wait_for_phase(runner, &sandbox_name, "Stopped", "stopped-delete/stopped").await?;
        run_lifecycle_command(runner, "delete", &sandbox_name, "stopped-delete/delete").await?;
        wait_for_absence(runner, &sandbox.id, &sandbox_name, "stopped-delete/deleted").await?;
        runner.forget_sandbox(&sandbox_name);
        Ok(())
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("sandbox-lifecycle/delete-stopped conformance story failed:\n{error}");
    }
}
