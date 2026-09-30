// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Portable sandbox environment conformance scenarios.

use std::time::Duration;

use serde::Deserialize;

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

/// Certify declared environment propagation to the canonical main and exec.
pub const SANDBOX_ENVIRONMENT_SCENARIO: Scenario = Scenario {
    name: "sandbox-environment/declared",
    description: "Verify declared environment propagation to canonical-main and exec processes.",
    run: run_sandbox_environment,
};

fn run_sandbox_environment(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move {
        let sandbox_name = format!("ct-{}-env", runner.id());
        let sentinel_path = "/sandbox/.openshell-declared-environment";
        let main = format!(
            "printf '%s\\n' \"${{REPRO_SENTINEL:-missing}}\" > '{sentinel_path}'; exec sleep infinity"
        );

        create_sandbox(runner, &sandbox_name, &main).await?;
        exec_expect_exact(
            runner,
            &sandbox_name,
            "read-main-environment",
            &[
                "sh",
                "-c",
                &format!(
                    "while [ ! -f '{sentinel_path}' ]; do sleep 0.05; done; cat '{sentinel_path}'"
                ),
            ],
            "present\n",
        )
        .await?;
        let exec_environment = format!("printf '%s\\n' \"${{{}:-missing}}\"", "REPRO_SENTINEL");
        exec_expect_exact(
            runner,
            &sandbox_name,
            "read-exec-environment",
            &["sh", "-c", &exec_environment],
            "present\n",
        )
        .await?;
        delete_and_confirm_absent(runner, &sandbox_name).await
    })
}

async fn create_sandbox(
    runner: &mut OpenShellRunner,
    sandbox_name: &str,
    main: &str,
) -> Result<(), String> {
    runner.track_sandbox(sandbox_name);
    let create = runner
        .step("create")
        .description(format!(
            "sandbox '{sandbox_name}' is created with a declared environment"
        ))
        .with_timeout(CREATE_TIMEOUT)
        .run(&[
            "sandbox",
            "create",
            "--name",
            sandbox_name,
            "--detach",
            "--no-tty",
            "--no-auto-providers",
            "--env",
            "REPRO_SENTINEL=present",
            "--",
            "sh",
            "-lc",
            main,
        ])
        .await
        .map_err(|error| error.to_string())?;
    create.require_success()?;
    wait_for_phase(runner, sandbox_name, "Ready", "ready").await
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

async fn delete_and_confirm_absent(
    runner: &mut OpenShellRunner,
    sandbox_name: &str,
) -> Result<(), String> {
    let delete = runner
        .step("delete")
        .description(format!("sandbox '{sandbox_name}' deletion succeeds"))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["sandbox", "delete", sandbox_name])
        .await
        .map_err(|error| error.to_string())?;
    delete.require_success()?;
    wait_for_absence(runner, sandbox_name, "deleted").await?;
    runner.forget_sandbox(sandbox_name);
    Ok(())
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
