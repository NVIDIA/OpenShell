// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Portable sandbox lifecycle conformance scenarios.

use std::time::Duration;

use serde::Deserialize;

use crate::{OpenShellRunner, Poll, Scenario, ScenarioFuture};

const CREATE_TIMEOUT: Duration = Duration::from_mins(10);
const COMMAND_TIMEOUT: Duration = Duration::from_mins(2);
const TRANSITION_TIMEOUT: Duration = Duration::from_mins(4);
const TRANSITION_INTERVAL: Duration = Duration::from_secs(2);
const RELAY_ATTACHMENT_TIMEOUT: Duration = Duration::from_secs(30);
const RELAY_SANDBOX_ATTEMPTS: usize = 6;
const RELAY_SCENARIO_CONCURRENCY: usize = 2;

#[derive(Debug, Deserialize)]
struct SandboxState {
    name: String,
    phase: String,
}

/// Certify sandbox stop, start, and deletion lifecycle behavior.
pub const SANDBOX_LIFECYCLE_SCENARIO: Scenario = Scenario {
    name: "sandbox-lifecycle",
    description: "Verify sandbox state transitions and relay readiness across reconnects.",
    run: run_sandbox_lifecycle,
};

/// Certify sandbox stop, start, workspace preservation, and deletion behavior.
pub const SANDBOX_LIFECYCLE_STATE_TRANSITIONS_SCENARIO: Scenario = Scenario {
    name: "sandbox-lifecycle/state-transitions",
    description: "Verify sandbox stop, start, workspace preservation, and deletion behavior.",
    run: run_state_transitions,
};

/// Certify that relay-backed commands remain available across startup reconnects.
pub const SANDBOX_LIFECYCLE_RELAY_READINESS_SCENARIO: Scenario = Scenario {
    name: "sandbox-lifecycle/relay-readiness",
    description: "Verify attachments survive supervisor reconnects during sandbox startup.",
    run: run_relay_readiness,
};

/// Certify that an in-flight relay is replayed after a forced supervisor reconnect.
pub const SANDBOX_LIFECYCLE_RELAY_RECONNECT_SCENARIO: Scenario = Scenario {
    name: "sandbox-lifecycle/relay-reconnect",
    description: "Verify an in-flight attachment survives a forced supervisor reconnect.",
    run: run_relay_reconnect,
};

fn run_sandbox_lifecycle(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move {
        SANDBOX_LIFECYCLE_STATE_TRANSITIONS_SCENARIO
            .run(runner)
            .await?;
        SANDBOX_LIFECYCLE_RELAY_READINESS_SCENARIO
            .run(runner)
            .await?;
        SANDBOX_LIFECYCLE_RELAY_RECONNECT_SCENARIO.run(runner).await
    })
}

fn run_state_transitions(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move {
        stop_start_preserves_workspace(runner).await?;
        stopped_can_be_deleted(runner).await
    })
}

fn run_relay_readiness(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move { relay_readiness_survives_reconnects(runner).await })
}

fn run_relay_reconnect(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move {
        let Some(helper) = std::env::var_os("OPENSHELL_RELAY_RECONNECT_HELPER")
            .filter(|helper| !helper.is_empty())
        else {
            return Ok(());
        };
        relay_reconnect(runner, &helper).await
    })
}

async fn relay_reconnect(
    runner: &mut OpenShellRunner,
    helper: &std::ffi::OsStr,
) -> Result<(), String> {
    let sandbox_name = format!("ct-{}-rr-fi", runner.id());
    let marker = format!("relay-reconnected-{}", runner.id());
    create_running_sandbox(
        runner,
        &sandbox_name,
        "exec sleep infinity",
        "relay-reconnect/create",
    )
    .await?;

    run_reconnect_helper(helper, "pause", &sandbox_name).await?;

    let relay_command = runner
        .step("relay-reconnect/exec")
        .description(format!(
            "in-flight attachment reaches sandbox '{sandbox_name}' after its supervisor reconnects"
        ))
        .with_timeout(RELAY_ATTACHMENT_TIMEOUT);
    let relay_args = [
        "sandbox",
        "exec",
        "--name",
        &sandbox_name,
        "--no-tty",
        "--",
        "printf",
        "%s\\n",
        &marker,
    ];
    let relay = relay_command.run(&relay_args);
    let reconnect = async {
        // Allow the gateway to queue RelayOpen while the helper blocks its
        // delivery, then sever only the control connection. The same process
        // and workload remain alive while the supervisor reconnects.
        tokio::time::sleep(Duration::from_millis(500)).await;
        run_reconnect_helper(helper, "disconnect-resume", &sandbox_name).await
    };
    let (relay, reconnect) = tokio::join!(relay, reconnect);
    reconnect?;
    let relay = relay.map_err(|error| error.to_string())?;
    relay.require_success()?;
    if !relay.stdout().lines().any(|line| line == marker) {
        return Err(relay.failure_diagnostic(&format!("stdout contains marker {marker:?}")));
    }

    run_lifecycle_command(runner, "delete", &sandbox_name, "relay-reconnect/delete").await?;
    wait_for_absence(runner, &sandbox_name, "relay-reconnect/deleted").await?;
    runner.forget_sandbox(&sandbox_name);
    Ok(())
}

async fn run_reconnect_helper(
    helper: &std::ffi::OsStr,
    action: &str,
    sandbox_name: &str,
) -> Result<(), String> {
    let output = tokio::process::Command::new(helper)
        .args([action, sandbox_name])
        .output()
        .await
        .map_err(|error| format!("failed to run relay reconnect helper: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "relay reconnect helper {action:?} failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    ))
}

async fn relay_readiness_survives_reconnects(runner: &mut OpenShellRunner) -> Result<(), String> {
    for first_attempt in (1..=RELAY_SANDBOX_ATTEMPTS).step_by(RELAY_SCENARIO_CONCURRENCY) {
        let second_attempt = first_attempt + 1;
        let first_name = relay_sandbox_name(runner, first_attempt);
        let second_name = relay_sandbox_name(runner, second_attempt);
        runner.track_sandbox(&first_name);
        runner.track_sandbox(&second_name);

        let (first, second) = tokio::join!(
            relay_readiness_attempt(runner, first_attempt, &first_name),
            relay_readiness_attempt(runner, second_attempt, &second_name),
        );
        first?;
        second?;
        wait_for_absence(
            runner,
            &first_name,
            &format!("relay-readiness/attempt-{first_attempt}/deleted"),
        )
        .await?;
        wait_for_absence(
            runner,
            &second_name,
            &format!("relay-readiness/attempt-{second_attempt}/deleted"),
        )
        .await?;
        runner.forget_sandbox(&first_name);
        runner.forget_sandbox(&second_name);
    }
    Ok(())
}

fn relay_sandbox_name(runner: &OpenShellRunner, attempt: usize) -> String {
    format!("ct-{}-rr-{attempt}", runner.id())
}

async fn relay_readiness_attempt(
    runner: &OpenShellRunner,
    attempt: usize,
    sandbox_name: &str,
) -> Result<(), String> {
    let marker = format!("relay-ready-{}-{attempt}", runner.id());
    // Match the ordering that exposed the original race: detached creation
    // returns while the sandbox is still starting, then the attachment opens
    // against the first supervisor session before its startup reconnect.
    let main = format!("printf '%s\\n' '{marker}'; sleep 5");
    let create_command = runner
        .step(format!("relay-readiness/attempt-{attempt}/create"))
        .description(format!("sandbox '{sandbox_name}' is created"))
        .with_timeout(CREATE_TIMEOUT);
    let create_args = [
        "sandbox",
        "create",
        "--name",
        sandbox_name,
        "--detach",
        "--",
        "sh",
        "-c",
        &main,
    ];
    create_command
        .run(&create_args)
        .await
        .map_err(|error| error.to_string())?
        .require_success()?;
    relay_connect(
        runner,
        sandbox_name,
        &format!("attempt-{attempt}/initial"),
        &marker,
    )
    .await?;

    run_lifecycle_command(
        runner,
        "delete",
        sandbox_name,
        &format!("relay-readiness/attempt-{attempt}/delete"),
    )
    .await?;
    Ok(())
}

async fn relay_connect(
    runner: &OpenShellRunner,
    sandbox_name: &str,
    cycle: &str,
    marker: &str,
) -> Result<(), String> {
    let result = runner
        .step(format!("relay-readiness/{cycle}/connect"))
        .description(format!(
            "attachment reaches sandbox '{sandbox_name}' during its startup reconnect window"
        ))
        .with_timeout(RELAY_ATTACHMENT_TIMEOUT)
        .run(&["sandbox", "connect", sandbox_name])
        .await
        .map_err(|error| error.to_string())?;
    result.require_success()?;
    if result.stdout().lines().any(|line| line == marker) {
        Ok(())
    } else {
        Err(result.failure_diagnostic(&format!("stdout contains marker {marker:?}")))
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
