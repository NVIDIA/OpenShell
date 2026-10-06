// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::helpers::{
    COMMAND_TIMEOUT, create_running_sandbox, exec_expect_exact, run_lifecycle_command,
    wait_for_phase,
};
use openshell_e2e_support::OpenShellRunner;

/// Verify stop/start preserves the workspace and restarts the main process.
#[tokio::test]
async fn preserves_workspace_and_restarts_main_process() {
    let mut runner = OpenShellRunner::from_env("sandbox-lifecycle/stop-start")
        .expect("candidate openshell CLI is available");
    let result = async {
        runner.check_gateway_status().await?;
        let runner = &mut runner;
        let sandbox_name = format!("ct-{}-ss", runner.id());
        let sentinel = format!("openshell-stop-start-{}", runner.id());
        let sentinel_path = "/sandbox/.openshell-stop-start-sentinel";
        let run_count_path = "/sandbox/.openshell-main-run-count";
        let main = format!(
            "count=0; test ! -f '{run_count_path}' || count=$(cat '{run_count_path}'); \
         count=$((count + 1)); printf '%s\\n' \"$count\" > '{run_count_path}'; \
         exec sleep infinity"
        );

        create_running_sandbox(runner, &sandbox_name, &main, "stop-start").await?;
        exec_expect_exact(
            runner,
            &sandbox_name,
            "write-sentinel",
            &[
                "sh",
                "-lc",
                &format!("printf '%s\\n' '{sentinel}' > '{sentinel_path}' && sync"),
            ],
            "",
        )
        .await?;

        run_lifecycle_command(runner, "stop", &sandbox_name, "stop-start/stop").await?;
        wait_for_phase(runner, &sandbox_name, "Stopped", "stop-start/stopped").await?;

        let stopped_exec = runner
            .step("stop-start/exec-while-stopped")
            .description(format!(
                "sandbox '{sandbox_name}' rejects exec while stopped"
            ))
            .with_timeout(COMMAND_TIMEOUT)
            .run(&[
                "sandbox",
                "exec",
                "--name",
                &sandbox_name,
                "--no-tty",
                "--",
                "cat",
                sentinel_path,
            ])
            .await
            .map_err(|error| error.to_string())?;
        if stopped_exec.success() {
            return Err(
                stopped_exec.failure_diagnostic("sandbox exec fails while the sandbox is stopped")
            );
        }

        run_lifecycle_command(runner, "start", &sandbox_name, "stop-start/start").await?;
        wait_for_phase(runner, &sandbox_name, "Ready", "stop-start/restarted").await?;

        exec_expect_exact(
            runner,
            &sandbox_name,
            "read-sentinel",
            &["cat", sentinel_path],
            &format!("{sentinel}\n"),
        )
        .await?;
        exec_expect_exact(
            runner,
            &sandbox_name,
            "read-main-run-count",
            &["cat", run_count_path],
            "2\n",
        )
        .await
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("sandbox-lifecycle/stop-start conformance story failed:\n{error}");
    }
}
