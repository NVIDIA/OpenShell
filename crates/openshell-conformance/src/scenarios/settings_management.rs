// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Portable sandbox/global settings conformance scenario.

use std::time::Duration;

use serde::Deserialize;

use crate::{CommandResult, OpenShellRunner, Poll, Scenario, ScenarioFuture};

const CREATE_TIMEOUT: Duration = Duration::from_mins(10);
const COMMAND_TIMEOUT: Duration = Duration::from_mins(2);
const TRANSITION_TIMEOUT: Duration = Duration::from_mins(2);
const TRANSITION_INTERVAL: Duration = Duration::from_secs(1);

// "ocsf_json_enabled" is a specific, recognized settings key, not an
// arbitrary name this scenario can scope per run, so it is cleaned up
// explicitly (hard pre-cleanup, best-effort post-cleanup) rather than
// tracked like a uniquely-named resource.
const TEST_KEY: &str = "ocsf_json_enabled";

#[derive(Debug, Deserialize)]
struct SandboxState {
    name: String,
    phase: String,
}

/// Certify sandbox/global settings precedence: sandbox-scoped set/get/delete,
/// a global override blocking sandbox writes for that key, global get/delete,
/// and sandbox-level control resuming after the global override is removed.
pub const SETTINGS_MANAGEMENT_SCENARIO: Scenario = Scenario {
    name: "settings-management",
    description: "Verify sandbox/global settings precedence, override, and delete semantics.",
    run: run_settings_management,
};

fn run_settings_management(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move {
        let result = settings_global_override_round_trip(runner).await;
        cleanup_global_setting(runner).await;
        result
    })
}

async fn settings_global_override_round_trip(runner: &mut OpenShellRunner) -> Result<(), String> {
    runner
        .step("preflight/global-delete")
        .description(format!(
            "initial global setting '{TEST_KEY}' cleanup succeeds"
        ))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["settings", "delete", "--global", "--key", TEST_KEY, "--yes"])
        .await
        .map_err(|error| error.to_string())?
        .require_success()?;

    let sandbox_name = format!("ct-{}-sm", runner.id());
    runner.track_sandbox(&sandbox_name);
    runner
        .step("create")
        .description(format!("sandbox '{sandbox_name}' is created"))
        .with_timeout(CREATE_TIMEOUT)
        .run(&[
            "sandbox",
            "create",
            "--name",
            &sandbox_name,
            "--detach",
            "--",
            "sh",
            "-c",
            "exec sleep infinity",
        ])
        .await
        .map_err(|error| error.to_string())?
        .require_success()?;
    wait_for_ready(runner, &sandbox_name).await?;

    let initial = settings_get(runner, &sandbox_name, "initial").await?;
    require_setting_line(
        &initial,
        "<unset>",
        Some("unset"),
        "initial sandbox setting is unset",
    )?;

    settings_set(runner, &sandbox_name, "true", "sandbox-set").await?;
    wait_for_setting_value(runner, &sandbox_name, "true", "sandbox").await?;

    let after_sandbox_set = settings_get(runner, &sandbox_name, "after-sandbox-set").await?;
    require_setting_line(
        &after_sandbox_set,
        "true",
        Some("sandbox"),
        "setting reflects the sandbox-scoped value",
    )?;

    let sandbox_delete = settings_delete(runner, &sandbox_name, "sandbox-delete", true).await?;
    if !sandbox_delete.output_contains("Deleted sandbox setting") {
        return Err(sandbox_delete.failure_diagnostic("sandbox delete confirms removal"));
    }

    let after_sandbox_delete = settings_get(runner, &sandbox_name, "after-sandbox-delete").await?;
    require_setting_line(
        &after_sandbox_delete,
        "<unset>",
        Some("unset"),
        "setting is unset again after sandbox delete",
    )?;

    settings_set(runner, &sandbox_name, "true", "re-set").await?;
    wait_for_setting_value(runner, &sandbox_name, "true", "sandbox").await?;

    let set_global = runner
        .step("global-set")
        .description("global setting set succeeds")
        .with_timeout(COMMAND_TIMEOUT)
        .run(&[
            "settings", "set", "--global", "--key", TEST_KEY, "--value", "false", "--yes",
        ])
        .await
        .map_err(|error| error.to_string())?;
    set_global.require_success()?;
    if !set_global.output_contains(&format!("Set global setting {TEST_KEY}=false")) {
        return Err(set_global.failure_diagnostic("global set output confirms the new value"));
    }

    let blocked_set = runner
        .step("blocked-sandbox-set")
        .description("sandbox setting set is blocked while the key is global-managed")
        .with_timeout(COMMAND_TIMEOUT)
        .run(&[
            "settings",
            "set",
            &sandbox_name,
            "--key",
            TEST_KEY,
            "--value",
            "true",
        ])
        .await
        .map_err(|error| error.to_string())?;
    if blocked_set.success() {
        return Err(
            blocked_set.failure_diagnostic("sandbox setting set is blocked while globally managed")
        );
    }
    if !blocked_set.output_contains("is managed") {
        return Err(blocked_set.failure_diagnostic("blocked set error mentions global management"));
    }

    // `settings_delete`'s own `expect_success` check already enforces that
    // this command fails while the key is globally managed.
    settings_delete(runner, &sandbox_name, "blocked-sandbox-delete", false).await?;

    let global_get = runner
        .step("global-get")
        .description("global settings get succeeds")
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["settings", "get", "--global"])
        .await
        .map_err(|error| error.to_string())?;
    global_get.require_success()?;
    require_setting_line(
        &global_get,
        "false",
        None,
        "global setting reflects the override value",
    )?;

    let delete_global = runner
        .step("global-delete")
        .description("global settings delete succeeds")
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["settings", "delete", "--global", "--key", TEST_KEY, "--yes"])
        .await
        .map_err(|error| error.to_string())?;
    delete_global.require_success()?;
    if !delete_global.output_contains(&format!("Deleted global setting {TEST_KEY}")) {
        return Err(delete_global.failure_diagnostic("global delete output confirms removal"));
    }

    let global_after_delete = runner
        .step("global-get-after-delete")
        .description("global settings get after delete succeeds")
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["settings", "get", "--global"])
        .await
        .map_err(|error| error.to_string())?;
    global_after_delete.require_success()?;
    require_setting_line(
        &global_after_delete,
        "<unset>",
        None,
        "global setting is unset after delete",
    )?;

    settings_set(
        runner,
        &sandbox_name,
        "false",
        "sandbox-set-after-global-delete",
    )
    .await?;
    wait_for_setting_value(runner, &sandbox_name, "false", "sandbox").await?;

    let sandbox_after_delete = settings_get(runner, &sandbox_name, "after-global-delete").await?;
    require_setting_line(
        &sandbox_after_delete,
        "false",
        Some("sandbox"),
        "sandbox-level control resumes after global delete",
    )?;

    runner
        .step("sandbox-delete")
        .description(format!("sandbox '{sandbox_name}' is deleted"))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["sandbox", "delete", &sandbox_name])
        .await
        .map_err(|error| error.to_string())?
        .require_success()?;
    runner.forget_sandbox(&sandbox_name);
    Ok(())
}

async fn wait_for_ready(runner: &mut OpenShellRunner, sandbox_name: &str) -> Result<(), String> {
    let sandbox_name = sandbox_name.to_string();
    runner
        .poll_until(
            "create/ready",
            TRANSITION_TIMEOUT,
            TRANSITION_INTERVAL,
            async move |runner| {
                let result = runner
                    .step("create/get")
                    .description(format!("sandbox '{sandbox_name}' reaches phase Ready"))
                    .with_timeout(COMMAND_TIMEOUT)
                    .run(&["sandbox", "get", &sandbox_name, "--output", "json"])
                    .await;
                match result {
                    Ok(result) if !result.success() => {
                        Poll::Pending(result.failure_diagnostic("sandbox can be retrieved"))
                    }
                    Ok(result) => match result.json::<SandboxState>() {
                        Ok(state) if state.name != sandbox_name => Poll::Failed(format!(
                            "sandbox get returned {:?}; expected '{sandbox_name}'",
                            state.name
                        )),
                        Ok(state) if state.phase == "Ready" => Poll::Ready(()),
                        Ok(state) => Poll::Pending(format!(
                            "sandbox phase is {:?}; expected \"Ready\"",
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

async fn wait_for_setting_value(
    runner: &mut OpenShellRunner,
    sandbox_name: &str,
    expected_value: &str,
    expected_scope: &str,
) -> Result<(), String> {
    let needle = format!("{TEST_KEY} = {expected_value} ({expected_scope})");
    let sandbox_name = sandbox_name.to_string();
    runner
        .poll_until(
            "settings-converge",
            TRANSITION_TIMEOUT,
            TRANSITION_INTERVAL,
            async move |runner| {
                let result = runner
                    .step("settings-converge/get")
                    .description(format!(
                        "sandbox '{sandbox_name}' setting converges to {needle:?}"
                    ))
                    .with_timeout(COMMAND_TIMEOUT)
                    .run(&["settings", "get", &sandbox_name])
                    .await;
                match result {
                    Ok(result) if result.success() && result.stdout().contains(&needle) => {
                        Poll::Ready(())
                    }
                    Ok(result) if result.success() => Poll::Pending(format!(
                        "settings get output does not yet contain {needle:?}:\n{}",
                        result.stdout()
                    )),
                    Ok(result) => Poll::Pending(result.failure_diagnostic("settings get succeeds")),
                    Err(error) => Poll::Pending(error.to_string()),
                }
            },
        )
        .await
        .map_err(|error| error.to_string())
}

async fn settings_get(
    runner: &OpenShellRunner,
    sandbox_name: &str,
    step: &str,
) -> Result<CommandResult, String> {
    let result = runner
        .step(format!("settings-get/{step}"))
        .description(format!(
            "settings get for sandbox '{sandbox_name}' succeeds"
        ))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["settings", "get", sandbox_name])
        .await
        .map_err(|error| error.to_string())?;
    result.require_success()?;
    Ok(result)
}

async fn settings_set(
    runner: &OpenShellRunner,
    sandbox_name: &str,
    value: &str,
    step: &str,
) -> Result<(), String> {
    runner
        .step(format!("settings-set/{step}"))
        .description(format!(
            "sandbox '{sandbox_name}' setting set to {value:?} succeeds"
        ))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&[
            "settings",
            "set",
            sandbox_name,
            "--key",
            TEST_KEY,
            "--value",
            value,
        ])
        .await
        .map_err(|error| error.to_string())?
        .require_success()
}

async fn settings_delete(
    runner: &OpenShellRunner,
    sandbox_name: &str,
    step: &str,
    expect_success: bool,
) -> Result<CommandResult, String> {
    let result = runner
        .step(format!("settings-delete/{step}"))
        .description(format!(
            "sandbox '{sandbox_name}' setting delete {}",
            if expect_success {
                "succeeds"
            } else {
                "is rejected"
            }
        ))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["settings", "delete", sandbox_name, "--key", TEST_KEY])
        .await
        .map_err(|error| error.to_string())?;
    result.require_outcome(expect_success)?;
    Ok(result)
}

/// Best-effort teardown. Mirrors a `Drop`-guard cleanup: ignore failures since
/// the key may already be absent as part of a successful scenario run.
async fn cleanup_global_setting(runner: &OpenShellRunner) {
    let _ = runner
        .step("cleanup/global-delete")
        .description(format!(
            "global setting '{TEST_KEY}' is deleted or already absent"
        ))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["settings", "delete", "--global", "--key", TEST_KEY, "--yes"])
        .await;
}

fn require_setting_line(
    result: &CommandResult,
    expected: &str,
    scope: Option<&str>,
    expectation: &str,
) -> Result<(), String> {
    let needle = match scope {
        Some(scope) => format!("{TEST_KEY} = {expected} ({scope})"),
        None => format!("{TEST_KEY} = {expected}"),
    };
    if result.output_contains(&needle) {
        Ok(())
    } else {
        Err(result.failure_diagnostic(expectation))
    }
}
