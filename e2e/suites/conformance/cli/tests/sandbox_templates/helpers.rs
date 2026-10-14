// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_e2e_support::{CommandResult, OpenShellRunner};
use serde_json::Value;
use std::time::Duration;

const COMMAND_TIMEOUT: Duration = Duration::from_mins(2);
pub const CREATE_TIMEOUT: Duration = Duration::from_mins(10);

/// Run a CLI command and return its result without judging the outcome.
pub async fn run(
    runner: &OpenShellRunner,
    step: &str,
    expectation: &str,
    args: &[&str],
) -> Result<CommandResult, String> {
    runner
        .step(step)
        .description(expectation)
        .with_timeout(COMMAND_TIMEOUT)
        .run(args)
        .await
        .map_err(|error| error.to_string())
}

/// Run a CLI command that must succeed.
pub async fn succeeds(
    runner: &OpenShellRunner,
    step: &str,
    expectation: &str,
    args: &[&str],
) -> Result<(), String> {
    run(runner, step, expectation, args)
        .await?
        .require_success()
}

/// Run a CLI command that must fail.
pub async fn fails(
    runner: &OpenShellRunner,
    step: &str,
    expectation: &str,
    args: &[&str],
) -> Result<(), String> {
    let result = run(runner, step, expectation, args).await?;
    if result.success() {
        return Err(result.failure_diagnostic(expectation));
    }
    Ok(())
}

/// Return the template's definition from `sandbox template get --output json`.
pub async fn template_json(
    runner: &OpenShellRunner,
    step: &str,
    name: &str,
) -> Result<Value, String> {
    let args = ["sandbox", "template", "get", name, "--output", "json"];
    let result = run(runner, step, "template can be retrieved", &args).await?;
    result.require_success()?;
    result.json().map_err(|error| error.to_string())
}

/// Require whether `name` appears in the template listing.
pub async fn require_listed(
    runner: &OpenShellRunner,
    step: &str,
    name: &str,
    listed: bool,
) -> Result<(), String> {
    let args = ["sandbox", "template", "list", "--names"];
    let result = run(runner, step, "template list succeeds", &args).await?;
    result.require_success()?;
    if result.stdout().lines().any(|line| line.trim() == name) == listed {
        return Ok(());
    }
    Err(result.failure_diagnostic(&format!("template '{name}' listed: {listed}")))
}

/// Finish a story. A passing story already removed what it created, so
/// templates are deleted only after a failure; both failures are kept. The
/// runner then removes the sandboxes it tracks.
pub async fn finish(
    runner: OpenShellRunner,
    result: Result<(), String>,
    templates: &[&str],
) -> Result<(), String> {
    let mut cleanup = Vec::new();
    if result.is_err() {
        for template in templates {
            let args = ["sandbox", "template", "delete", template];
            match run(
                &runner,
                "cleanup",
                "template is deleted or already absent",
                &args,
            )
            .await
            {
                Ok(deleted) if deleted.success() || reports_not_found(&deleted) => {}
                Ok(deleted) => cleanup.push(deleted.failure_diagnostic("cleanup delete succeeds")),
                Err(error) => cleanup.push(error),
            }
        }
    }
    let result = if cleanup.is_empty() {
        result
    } else {
        let error = result.err().unwrap_or_default();
        Err(format!(
            "{error}\n\ncleanup also failed:\n{}",
            cleanup.join("\n\n")
        ))
    };
    runner.finish(result).await
}

fn reports_not_found(result: &CommandResult) -> bool {
    let output = format!("{}{}", result.stdout(), result.stderr());
    output
        .to_ascii_lowercase()
        .contains("sandbox template not found")
}
