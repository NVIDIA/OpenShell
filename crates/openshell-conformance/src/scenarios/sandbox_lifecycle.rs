// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Portable sandbox lifecycle conformance scenarios.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::{OpenShellRunner, Poll, Scenario, ScenarioFuture};

const CREATE_TIMEOUT: Duration = Duration::from_mins(10);
const COMMAND_TIMEOUT: Duration = Duration::from_mins(2);
const TRANSITION_TIMEOUT: Duration = Duration::from_mins(4);
const TRANSITION_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Deserialize)]
struct SandboxState {
    id: String,
    name: String,
    phase: String,
    #[serde(default)]
    exit_code: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct SandboxListPage {
    sandboxes: Vec<SandboxState>,
    next_page_token: String,
}

/// Certify sandbox stop, start, and deletion lifecycle behavior.
pub const SANDBOX_LIFECYCLE_SCENARIO: Scenario = Scenario {
    name: "sandbox-lifecycle",
    run: run_sandbox_lifecycle,
};

fn run_sandbox_lifecycle(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move {
        stop_start_preserves_workspace(runner).await?;
        stopped_can_be_deleted(runner).await
    })
}

/// Certify what happens to a sandbox after its main process exits.
///
/// An ephemeral sandbox is deleted whether the main process succeeds or
/// fails. A retained sandbox records the result and stays reachable through
/// exec, because the supervisor keeps its access plane after the exit.
pub const SANDBOX_RETENTION_SCENARIO: Scenario = Scenario {
    name: "sandbox-retention",
    run: run_sandbox_retention,
};

fn run_sandbox_retention(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move {
        for exit_code in [0, 3] {
            ephemeral_is_deleted_after_exit(runner, exit_code).await?;
            retained_accepts_exec_after_exit(runner, exit_code).await?;
        }
        Ok(())
    })
}

async fn ephemeral_is_deleted_after_exit(
    runner: &mut OpenShellRunner,
    exit_code: i32,
) -> Result<(), String> {
    let sandbox_name = format!("ct-{}-e{exit_code}", runner.id());
    let step = format!("ephemeral-exit-{exit_code}");
    runner.track_sandbox(&sandbox_name);
    let create = runner
        .step(format!("{step}/create"))
        .description(format!(
            "ephemeral sandbox '{sandbox_name}' runs its main process and returns exit code {exit_code}"
        ))
        .with_timeout(CREATE_TIMEOUT)
        .run(&[
            "sandbox",
            "create",
            "--name",
            &sandbox_name,
            "--no-keep",
            "--no-tty",
            "--",
            "sh",
            "-c",
            &format!("echo ephemeral-done; exit {exit_code}"),
        ])
        .await
        .map_err(|error| error.to_string())?;
    if create.exit_code() != Some(exit_code) {
        return Err(create.failure_diagnostic(&format!("create exits with code {exit_code}")));
    }
    if !create.stdout().contains("ephemeral-done") {
        return Err(create.failure_diagnostic("main process stdout is streamed to the caller"));
    }

    wait_for_name_absence(runner, &sandbox_name, &format!("{step}/deleted")).await?;
    runner.forget_sandbox(&sandbox_name);
    Ok(())
}

async fn retained_accepts_exec_after_exit(
    runner: &mut OpenShellRunner,
    exit_code: i32,
) -> Result<(), String> {
    let sandbox_name = format!("ct-{}-r{exit_code}", runner.id());
    let step = format!("retained-exit-{exit_code}");
    let result_path = "/sandbox/.openshell-retained-result";
    let result = format!("openshell-retained-{}-{exit_code}", runner.id());
    runner.track_sandbox(&sandbox_name);
    let create = runner
        .step(format!("{step}/create"))
        .description(format!("retained sandbox '{sandbox_name}' is created"))
        .with_timeout(CREATE_TIMEOUT)
        .run(&[
            "sandbox",
            "create",
            "--name",
            &sandbox_name,
            "--detach",
            "--no-tty",
            "--",
            "sh",
            "-c",
            &format!("printf '%s\\n' '{result}' > '{result_path}' && sync; exit {exit_code}"),
        ])
        .await
        .map_err(|error| error.to_string())?;
    create.require_success()?;

    let expected_phase = if exit_code == 0 { "Completed" } else { "Error" };
    let state = wait_for_phase(
        runner,
        &sandbox_name,
        expected_phase,
        &format!("{step}/{}", expected_phase.to_lowercase()),
    )
    .await?;
    if state.exit_code != Some(exit_code) {
        return Err(format!(
            "sandbox '{sandbox_name}' recorded exit code {:?}; expected {exit_code}",
            state.exit_code
        ));
    }

    exec_expect_exact(
        runner,
        &sandbox_name,
        &format!("{step}/exec-after-exit"),
        &["cat", result_path],
        &format!("{result}\n"),
    )
    .await?;

    run_lifecycle_command(runner, "delete", &sandbox_name, &format!("{step}/delete")).await?;
    wait_for_absence(runner, &state.id, &sandbox_name, &format!("{step}/deleted")).await?;
    runner.forget_sandbox(&sandbox_name);
    Ok(())
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
        "stop-start/write-sentinel",
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
        "stop-start/read-sentinel",
        &["cat", sentinel_path],
        &format!("{sentinel}\n"),
    )
    .await?;
    exec_expect_exact(
        runner,
        &sandbox_name,
        "stop-start/read-main-run-count",
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
    let sandbox =
        wait_for_phase(runner, &sandbox_name, "Stopped", "stopped-delete/stopped").await?;
    run_lifecycle_command(runner, "delete", &sandbox_name, "stopped-delete/delete").await?;
    wait_for_absence(runner, &sandbox.id, &sandbox_name, "stopped-delete/deleted").await?;
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
    wait_for_phase(runner, sandbox_name, "Ready", &format!("{step}/ready"))
        .await
        .map(|_| ())
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
        .step(step)
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
) -> Result<SandboxState, String> {
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
                        Ok(state) if state.phase == expected_phase => Poll::Ready(state),
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
    sandbox_id: &str,
    sandbox_name: &str,
    step: &str,
) -> Result<(), String> {
    let sandbox_id = sandbox_id.to_string();
    let sandbox_name = sandbox_name.to_string();
    let step = step.to_string();
    let poll_step = step.clone();
    runner
        .poll_until(
            &poll_step,
            TRANSITION_TIMEOUT,
            TRANSITION_INTERVAL,
            async move |runner| match sandbox_is_listed(runner, &sandbox_id, &sandbox_name, &step)
                .await
            {
                Ok(false) => Poll::Ready(()),
                Ok(true) => Poll::Pending(format!(
                    "sandbox '{sandbox_name}' with ID '{sandbox_id}' is still listed"
                )),
                Err(error) => Poll::Pending(error),
            },
        )
        .await
        .map_err(|error| error.to_string())
}

/// Wait until `sandbox get` reports that the name no longer exists. Used
/// when the gateway deletes the sandbox on its own, so the caller may never
/// observe its ID.
async fn wait_for_name_absence(
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
                    .description(format!("sandbox '{sandbox_name}' no longer exists"))
                    .with_timeout(COMMAND_TIMEOUT)
                    .run(&["sandbox", "get", &sandbox_name, "--output", "json"])
                    .await;
                match result {
                    Ok(result) if result.success() => match result.json::<SandboxState>() {
                        Ok(state) => Poll::Pending(format!(
                            "sandbox '{sandbox_name}' still exists in phase {:?}",
                            state.phase
                        )),
                        Err(error) => Poll::Failed(error.to_string()),
                    },
                    Ok(result) if result.stderr().to_lowercase().contains("not found") => {
                        Poll::Ready(())
                    }
                    Ok(result) => Poll::Pending(result.failure_diagnostic(&format!(
                        "sandbox get reports that '{sandbox_name}' was not found"
                    ))),
                    Err(error) => Poll::Pending(error.to_string()),
                }
            },
        )
        .await
        .map_err(|error| error.to_string())
}

async fn sandbox_is_listed(
    runner: &OpenShellRunner,
    sandbox_id: &str,
    sandbox_name: &str,
    step: &str,
) -> Result<bool, String> {
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    let mut seen_page_tokens = HashSet::new();
    let mut page_token = String::new();
    let mut page = 0u32;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "sandbox list observation for '{sandbox_name}' exceeded its {COMMAND_TIMEOUT:?} deadline"
            ));
        }

        let result = runner
            .step(format!("{step}/list/{page}"))
            .description(format!(
                "sandbox list confirms whether '{sandbox_name}' with ID '{sandbox_id}' still exists"
            ))
            .with_timeout(remaining)
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
            .any(|sandbox| sandbox.id == sandbox_id)
        {
            return Ok(true);
        }
        if response.next_page_token.is_empty() {
            return Ok(false);
        }
        if !seen_page_tokens.insert(response.next_page_token.clone()) {
            return Err(format!(
                "sandbox list returned a repeated page token while looking for '{sandbox_name}'"
            ));
        }
        page_token = response.next_page_token;
        page = page
            .checked_add(1)
            .ok_or_else(|| "sandbox list page counter overflowed".to_string())?;
    }
}
