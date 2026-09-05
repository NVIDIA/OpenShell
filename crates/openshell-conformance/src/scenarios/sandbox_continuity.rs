// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Product-visible sandbox continuity across host-side actions.

use std::time::Duration;

use serde::Deserialize;

use crate::{
    HostAction, OpenShellRunner, PlanRun, Poll, Scenario, ScenarioFuture, WorkloadExpectation,
};

const CREATE_TIMEOUT: Duration = Duration::from_secs(600);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
const RECOVERY_TIMEOUT: Duration = Duration::from_secs(240);
const RECOVERY_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Deserialize)]
struct SandboxState {
    name: String,
    phase: String,
}

/// Certify sandbox state and workspace continuity across host-side actions.
pub const SANDBOX_CONTINUITY_SCENARIO: Scenario = Scenario {
    name: "sandbox-continuity",
    description: "Verify sandbox state and workspace continuity across planned host actions.",
    requires_plan: true,
    run: run_sandbox_continuity,
    validate_plan_run: Some(validate_plan_run),
};

fn run_sandbox_continuity<'a>(
    runner: &'a mut OpenShellRunner,
    plan_run: &'a PlanRun,
) -> ScenarioFuture<'a> {
    Box::pin(async move { run_sandbox_continuity_inner(runner, plan_run).await })
}

fn validate_plan_run(plan_run: &PlanRun) -> Result<(), String> {
    if plan_run.workload_expectation != Some(WorkloadExpectation::Reconciled) {
        return Err(
            "scenario 'sandbox-continuity' requires workload_expectation = \"reconciled\""
                .to_string(),
        );
    }
    if plan_run.actions.is_empty() {
        return Err("scenario 'sandbox-continuity' requires at least one action".to_string());
    }
    Ok(())
}

async fn run_sandbox_continuity_inner(
    runner: &mut OpenShellRunner,
    plan_run: &PlanRun,
) -> Result<(), String> {
    // The VM driver permits at most 19 characters in a sandbox name.
    let running_name = format!("ct-{}-r", runner.id());
    let stopped_name = format!("ct-{}-s", runner.id());
    let marker = format!("openshell-sandbox-continuity-{}", runner.id());
    let marker_path = "/sandbox/.openshell-sandbox-continuity";
    let running_script =
        format!("printf '%s\\n' '{marker}' > {marker_path}; while true; do sleep 1; done");

    create_retained_sandbox(runner, &running_name, &running_script, "running").await?;
    assert_marker(runner, &running_name, marker_path, &marker, "pre-action").await?;

    create_retained_sandbox(
        runner,
        &stopped_name,
        "while true; do sleep 1; done",
        "stopped",
    )
    .await?;
    let stop = runner
        .step("stop")
        .description(format!("sandbox '{stopped_name}' stops"))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["sandbox", "stop", &stopped_name])
        .await
        .map_err(|error| error.to_string())?;
    stop.require_success()?;
    wait_for_phase(runner, &stopped_name, "Stopped", "stopped-before-actions").await?;

    for action in &plan_run.actions {
        apply_action_and_assert(
            runner,
            action,
            &running_name,
            &stopped_name,
            marker_path,
            &marker,
        )
        .await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn apply_action_and_assert(
    runner: &mut OpenShellRunner,
    action: &HostAction,
    running_name: &str,
    stopped_name: &str,
    marker_path: &str,
    marker: &str,
) -> Result<(), String> {
    let step = format!("after-{}", action.name);
    runner.execute_host_action(action).await?;
    runner.check_gateway_status().await?;
    wait_for_phase(runner, running_name, "Ready", &format!("running-{step}")).await?;
    wait_for_phase(runner, stopped_name, "Stopped", &format!("stopped-{step}")).await?;
    assert_marker(runner, running_name, marker_path, marker, &step).await
}

async fn create_retained_sandbox(
    runner: &mut OpenShellRunner,
    name: &str,
    script: &str,
    step: &str,
) -> Result<(), String> {
    runner.track_sandbox(name);
    let create = runner
        .step(format!("create-{step}"))
        .description(format!("retained sandbox '{name}' is created"))
        .with_timeout(CREATE_TIMEOUT)
        .run(&[
            "sandbox", "create", "--name", name, "--from", "base", "--detach", "--no-tty", "--",
            "sh", "-lc", script,
        ])
        .await
        .map_err(|error| error.to_string())?;
    create.require_success()
}

async fn assert_marker(
    runner: &OpenShellRunner,
    name: &str,
    path: &str,
    marker: &str,
    step: &str,
) -> Result<(), String> {
    let result = runner
        .step(format!("marker-{step}"))
        .description(format!("sandbox '{name}' retains its workspace marker"))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&[
            "sandbox", "exec", "--name", name, "--no-tty", "--", "cat", path,
        ])
        .await
        .map_err(|error| error.to_string())?;
    result.require_success()?;
    if result.stdout().lines().any(|line| line.trim() == marker) {
        Ok(())
    } else {
        Err(result.failure_diagnostic(&format!(
            "sandbox '{name}' stdout contains marker {marker:?}"
        )))
    }
}

async fn wait_for_phase(
    runner: &mut OpenShellRunner,
    name: &str,
    expected_phase: &str,
    step: &str,
) -> Result<(), String> {
    let name = name.to_string();
    let expected_phase = expected_phase.to_string();
    let step = step.to_string();
    let poll_step = step.clone();
    runner
        .poll_until(
            &poll_step,
            RECOVERY_TIMEOUT,
            RECOVERY_INTERVAL,
            async move |runner| {
                let result = runner
                    .step(format!("{step}/get"))
                    .description(format!("sandbox '{name}' reaches phase {expected_phase}"))
                    .with_timeout(COMMAND_TIMEOUT)
                    .run(&["sandbox", "get", &name, "--output", "json"])
                    .await;
                match result {
                    Ok(result) if !result.success() => Poll::Pending(
                        result.failure_diagnostic(&format!("sandbox '{name}' can be retrieved")),
                    ),
                    Ok(result) => match result.json::<SandboxState>() {
                        Ok(state) if state.name != name => Poll::Failed(format!(
                            "sandbox get returned {:?}; expected '{name}'",
                            state.name
                        )),
                        Ok(state) if state.phase == expected_phase => Poll::Ready(()),
                        Ok(state) => Poll::Pending(format!(
                            "sandbox '{name}' phase is {:?}; expected {expected_phase:?}",
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
