// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Portable sandbox lifecycle conformance scenarios.

use std::time::Duration;

use serde::Deserialize;

use crate::{OpenShellRunner, PlanRun, Poll, Scenario, ScenarioCollection, ScenarioFuture};

const CREATE_TIMEOUT: Duration = Duration::from_secs(600);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
const TRANSITION_TIMEOUT: Duration = Duration::from_secs(240);
const TRANSITION_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Deserialize)]
struct SandboxState {
    name: String,
    phase: String,
}

struct StopStartPreservesWorkspaceScenario;
struct StoppedCanBeDeletedScenario;

static STOP_START_PRESERVES_WORKSPACE_SCENARIO: StopStartPreservesWorkspaceScenario =
    StopStartPreservesWorkspaceScenario;
static STOPPED_CAN_BE_DELETED_SCENARIO: StoppedCanBeDeletedScenario = StoppedCanBeDeletedScenario;

static SANDBOX_LIFECYCLE_CHILDREN: &[&dyn Scenario] = &[
    &STOP_START_PRESERVES_WORKSPACE_SCENARIO,
    &STOPPED_CAN_BE_DELETED_SCENARIO,
];

static SANDBOX_LIFECYCLE_COLLECTION: ScenarioCollection = ScenarioCollection::new(
    "sandbox-lifecycle",
    "Verify sandbox stop, start, and deletion lifecycle behavior.",
    SANDBOX_LIFECYCLE_CHILDREN,
);

/// Certify portable sandbox lifecycle behavior as one conformance scenario.
pub static SANDBOX_LIFECYCLE_SCENARIO: &dyn Scenario = &SANDBOX_LIFECYCLE_COLLECTION;

impl Scenario for StopStartPreservesWorkspaceScenario {
    fn name(&self) -> &'static str {
        "stop-start-preserves-workspace"
    }

    fn description(&self) -> &'static str {
        "Stopping and starting a sandbox preserves its workspace and restarts its main process."
    }

    fn run<'a>(
        &self,
        runner: &'a mut OpenShellRunner,
        plan_run: &'a PlanRun,
    ) -> ScenarioFuture<'a> {
        let validation = self.validate_plan_run(plan_run);
        Box::pin(async move {
            validation?;
            stop_start_preserves_workspace(runner).await
        })
    }
}

impl Scenario for StoppedCanBeDeletedScenario {
    fn name(&self) -> &'static str {
        "stopped-can-be-deleted"
    }

    fn description(&self) -> &'static str {
        "A stopped sandbox can be deleted without being started again."
    }

    fn run<'a>(
        &self,
        runner: &'a mut OpenShellRunner,
        plan_run: &'a PlanRun,
    ) -> ScenarioFuture<'a> {
        let validation = self.validate_plan_run(plan_run);
        Box::pin(async move {
            validation?;
            stopped_can_be_deleted(runner).await
        })
    }
}

async fn stop_start_preserves_workspace(runner: &mut OpenShellRunner) -> Result<(), String> {
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
            &format!("printf '%s\\n' '{sentinel}' > '{sentinel_path}'"),
        ],
        "",
    )
    .await?;

    run_lifecycle_command(runner, "stop", &sandbox_name, "stop").await?;
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

    run_lifecycle_command(runner, "start", &sandbox_name, "start").await?;
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

async fn stopped_can_be_deleted(runner: &mut OpenShellRunner) -> Result<(), String> {
    let sandbox_name = format!("ct-{}-sd", runner.id());
    create_running_sandbox(
        runner,
        &sandbox_name,
        "exec sleep infinity",
        "stopped-delete",
    )
    .await?;

    run_lifecycle_command(runner, "stop", &sandbox_name, "stopped-delete/stop").await?;
    wait_for_phase(runner, &sandbox_name, "Stopped", "stopped-delete/stopped").await?;
    run_lifecycle_command(runner, "delete", &sandbox_name, "stopped-delete/delete").await?;
    wait_for_absence(runner, &sandbox_name, "stopped-delete/deleted").await?;
    runner.forget_sandbox(&sandbox_name);
    Ok(())
}

async fn create_running_sandbox(
    runner: &mut OpenShellRunner,
    sandbox_name: &str,
    main: &str,
    step: &str,
) -> Result<(), String> {
    runner.track_sandbox(sandbox_name);
    let create = runner
        .step(format!("{step}/create"))
        .description(format!("sandbox '{sandbox_name}' is created"))
        .with_timeout(CREATE_TIMEOUT)
        .run(&[
            "sandbox",
            "create",
            "--name",
            sandbox_name,
            "--from",
            "base",
            "--detach",
            "--no-tty",
            "--",
            "sh",
            "-lc",
            main,
        ])
        .await
        .map_err(|error| error.to_string())?;
    create.require_success()?;
    wait_for_phase(runner, sandbox_name, "Ready", &format!("{step}/ready")).await
}

async fn run_lifecycle_command(
    runner: &OpenShellRunner,
    operation: &str,
    sandbox_name: &str,
    step: &str,
) -> Result<(), String> {
    let result = runner
        .step(step)
        .description(format!("sandbox '{sandbox_name}' {operation} succeeds"))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["sandbox", operation, sandbox_name])
        .await
        .map_err(|error| error.to_string())?;
    result.require_success()
}

async fn exec_expect_exact(
    runner: &OpenShellRunner,
    sandbox_name: &str,
    step: &str,
    command: &[&str],
    expected_stdout: &str,
) -> Result<(), String> {
    let mut args = vec!["sandbox", "exec", "--name", sandbox_name, "--no-tty", "--"];
    args.extend_from_slice(command);
    let result = runner
        .step(format!("stop-start/{step}"))
        .description(format!("sandbox '{sandbox_name}' exec {step} succeeds"))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&args)
        .await
        .map_err(|error| error.to_string())?;
    result.require_success()?;
    if result.stdout() == expected_stdout {
        Ok(())
    } else {
        Err(result.failure_diagnostic(&format!("stdout is exactly {expected_stdout:?}")))
    }
}

async fn wait_for_phase(
    runner: &mut OpenShellRunner,
    sandbox_name: &str,
    expected_phase: &str,
    step: &str,
) -> Result<(), String> {
    let sandbox_name = sandbox_name.to_string();
    let expected_phase = expected_phase.to_string();
    let step = step.to_string();
    let poll_step = step.clone();
    runner
        .poll_until(
            &poll_step,
            TRANSITION_TIMEOUT,
            TRANSITION_INTERVAL,
            async move |runner| {
                let result = runner
                    .step(format!("{step}/get"))
                    .description(format!(
                        "sandbox '{sandbox_name}' reaches phase {expected_phase}"
                    ))
                    .with_timeout(COMMAND_TIMEOUT)
                    .run(&["sandbox", "get", &sandbox_name, "--output", "json"])
                    .await;
                match result {
                    Ok(result) if !result.success() => {
                        Poll::Pending(result.failure_diagnostic(&format!(
                            "sandbox '{sandbox_name}' can be retrieved"
                        )))
                    }
                    Ok(result) => match result.json::<SandboxState>() {
                        Ok(state) if state.name != sandbox_name => Poll::Failed(format!(
                            "sandbox get returned {:?}; expected '{sandbox_name}'",
                            state.name
                        )),
                        Ok(state) if state.phase == expected_phase => Poll::Ready(()),
                        Ok(state) => Poll::Pending(format!(
                            "sandbox '{sandbox_name}' phase is {:?}; expected {expected_phase:?}",
                            state.phase
                        )),
                        Err(error) => Poll::Failed(error.to_string()),
                    },
                    Err(error) => Poll::Pending(error.to_string()),
                }
            },
        )
        .await
        .map_err(|error| error.to_string())
}

async fn wait_for_absence(
    runner: &mut OpenShellRunner,
    sandbox_name: &str,
    step: &str,
) -> Result<(), String> {
    let sandbox_name = sandbox_name.to_string();
    let step = step.to_string();
    let poll_step = step.clone();
    runner
        .poll_until(
            &poll_step,
            TRANSITION_TIMEOUT,
            TRANSITION_INTERVAL,
            async move |runner| {
                let result = runner
                    .step(format!("{step}/get"))
                    .description(format!("sandbox '{sandbox_name}' is no longer retrievable"))
                    .with_timeout(COMMAND_TIMEOUT)
                    .run(&["sandbox", "get", &sandbox_name, "--output", "json"])
                    .await;
                match result {
                    Ok(result) if !result.success() => Poll::Ready(()),
                    Ok(_) => {
                        Poll::Pending(format!("sandbox '{sandbox_name}' is still retrievable"))
                    }
                    Err(error) => Poll::Pending(error.to_string()),
                }
            },
        )
        .await
        .map_err(|error| error.to_string())
}
