// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Portable sandbox lifecycle conformance scenarios.

use std::time::Duration;

use serde::Deserialize;

use crate::platform::{self, CommandExpectation, SandboxFixture};
use crate::{OpenShellRunner, Poll, Scenario, ScenarioFuture};

const CREATE_TIMEOUT: Duration = Duration::from_mins(10);
const COMMAND_TIMEOUT: Duration = Duration::from_mins(2);
const TRANSITION_TIMEOUT: Duration = Duration::from_mins(4);
const TRANSITION_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Deserialize)]
struct SandboxState {
    name: String,
    phase: String,
}

#[derive(Debug, Deserialize)]
struct SandboxListPage {
    sandboxes: Vec<SandboxState>,
    next_page_token: String,
}

/// Certify lifecycle operations that do not require an interactive exec channel.
pub const SANDBOX_LIFECYCLE_CONTROL_PLANE_SCENARIO: Scenario = Scenario {
    name: "sandbox/lifecycle/control-plane",
    description: "Verify sandbox stop and deletion through control-plane operations.",
    run: run_lifecycle_control_plane,
};

/// Certify that restarting a sandbox preserves its workspace and reruns its command.
pub const SANDBOX_LIFECYCLE_RESTART_PERSISTENCE_SCENARIO: Scenario = Scenario {
    name: "sandbox/lifecycle/restart-persistence",
    description: "Verify sandbox restart preserves workspace state and reruns the workload.",
    run: run_lifecycle_restart_persistence,
};

fn run_lifecycle_control_plane(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(stopped_can_be_deleted(runner))
}

fn run_lifecycle_restart_persistence(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(stop_start_preserves_workspace(runner))
}

async fn stop_start_preserves_workspace(runner: &mut OpenShellRunner) -> Result<(), String> {
    let sandbox_name = format!("ct-{}-ss", runner.id());
    let sentinel = format!("openshell-stop-start-{}", runner.id());
    let fixture = platform::lifecycle_fixture()?;
    let sentinel_path = fixture.path(".openshell-stop-start-sentinel");
    let run_count_path = fixture.path(".openshell-main-run-count");
    let main = platform::increment_then_wait(&run_count_path);

    create_running_sandbox(runner, &sandbox_name, &fixture, &main, "stop-start").await?;
    exec_expect_exact(
        runner,
        &sandbox_name,
        "write-sentinel",
        &platform::write_text(&sentinel_path, &sentinel),
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
        .run(&exec_args(
            &sandbox_name,
            platform::read_text(&sentinel_path, &sentinel).argv(),
        ))
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
        &platform::read_text(&sentinel_path, &sentinel),
    )
    .await?;
    exec_expect_exact(
        runner,
        &sandbox_name,
        "read-main-run-count",
        &platform::read_text(&run_count_path, "2"),
    )
    .await
}

async fn stopped_can_be_deleted(runner: &mut OpenShellRunner) -> Result<(), String> {
    let sandbox_name = format!("ct-{}-sd", runner.id());
    let fixture = platform::lifecycle_fixture()?;
    let main = platform::keep_alive(&fixture);
    create_running_sandbox(runner, &sandbox_name, &fixture, &main, "stopped-delete").await?;

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
    fixture: &SandboxFixture,
    main: &[String],
    step: &str,
) -> Result<(), String> {
    runner.track_sandbox(sandbox_name);
    let mut args = vec![
        "sandbox".to_string(),
        "create".to_string(),
        "--name".to_string(),
        sandbox_name.to_string(),
        "--detach".to_string(),
        "--no-tty".to_string(),
    ];
    args.extend(fixture.create_args().iter().cloned());
    args.push("--".to_string());
    args.extend(main.iter().cloned());
    let args = args.iter().map(String::as_str).collect::<Vec<_>>();
    let create = runner
        .step(format!("{step}/create"))
        .description(format!("sandbox '{sandbox_name}' is created"))
        .with_timeout(CREATE_TIMEOUT)
        .run(&args)
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
    command: &CommandExpectation,
) -> Result<(), String> {
    let result = runner
        .step(format!("stop-start/{step}"))
        .description(format!("sandbox '{sandbox_name}' exec {step} succeeds"))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&exec_args(sandbox_name, command.argv()))
        .await
        .map_err(|error| error.to_string())?;
    result.require_success()?;
    if result.stdout() == command.expected_stdout() {
        Ok(())
    } else {
        Err(result.failure_diagnostic(&format!(
            "stdout is exactly {:?}",
            command.expected_stdout()
        )))
    }
}

fn exec_args<'a>(sandbox_name: &'a str, command: &'a [String]) -> Vec<&'a str> {
    let mut args = vec!["sandbox", "exec", "--name", sandbox_name, "--no-tty", "--"];
    args.extend(command.iter().map(String::as_str));
    args
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
            async move |runner| match sandbox_is_listed(runner, &sandbox_name, &step).await {
                Ok(false) => Poll::Ready(()),
                Ok(true) => Poll::Pending(format!("sandbox '{sandbox_name}' is still retrievable")),
                Err(error) => Poll::Pending(error),
            },
        )
        .await
        .map_err(|error| error.to_string())
}

async fn sandbox_is_listed(
    runner: &OpenShellRunner,
    sandbox_name: &str,
    step: &str,
) -> Result<bool, String> {
    let mut page_token = String::new();
    let mut page = 0u32;
    loop {
        let result = runner
            .step(format!("{step}/list/{page}"))
            .description(format!(
                "sandbox list confirms whether '{sandbox_name}' still exists"
            ))
            .with_timeout(COMMAND_TIMEOUT)
            .run(&[
                "sandbox",
                "list",
                "--page-size",
                "1000",
                "--page-token",
                &page_token,
                "--output",
                "json",
            ])
            .await
            .map_err(|error| error.to_string())?;
        result.require_success()?;

        let response = result
            .json::<SandboxListPage>()
            .map_err(|error| error.to_string())?;
        if response
            .sandboxes
            .iter()
            .any(|sandbox| sandbox.name == sandbox_name)
        {
            return Ok(true);
        }
        if response.next_page_token.is_empty() {
            return Ok(false);
        }
        page_token = response.next_page_token;
        page = page
            .checked_add(1)
            .ok_or_else(|| "sandbox list page counter overflowed".to_string())?;
    }
}
