// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_e2e_support::OpenShellRunner;
use openshell_e2e_support::Poll;
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;
use std::time::Instant;

pub const CREATE_TIMEOUT: Duration = Duration::from_mins(10);
pub const COMMAND_TIMEOUT: Duration = Duration::from_mins(2);
pub const TRANSITION_TIMEOUT: Duration = Duration::from_mins(4);
pub const TRANSITION_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Deserialize)]
pub struct SandboxState {
    pub id: String,
    pub name: String,
    pub phase: String,
}

#[derive(Debug, Deserialize)]
pub struct SandboxListPage {
    pub sandboxes: Vec<SandboxState>,
    pub next_page_token: String,
}

pub async fn create_running_sandbox(
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

pub async fn run_lifecycle_command(
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

pub async fn exec_expect_exact(
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

pub async fn wait_for_phase(
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

pub async fn wait_for_absence(
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

pub async fn sandbox_is_listed(
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
