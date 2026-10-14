// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_e2e_support::{CommandResult, OpenShellRunner};
use serde_json::Value;
use std::time::Duration;

const COMMAND_TIMEOUT: Duration = Duration::from_mins(2);
const MAX_PAGES: u32 = 100;

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

pub fn create_template_args<'a>(workspace: &'a str, name: &'a str) -> [&'a str; 6] {
    [
        "sandbox",
        "template",
        "create",
        name,
        "--workspace",
        workspace,
    ]
}

/// Find the entry called `name` in a paginated `--output json` listing, where
/// `collection` is the JSON key that holds the entries.
async fn find_entry(
    runner: &OpenShellRunner,
    step: &str,
    list: &[&str],
    collection: &str,
    name: &str,
) -> Result<Option<Value>, String> {
    let mut token = String::new();
    for page in 0..MAX_PAGES {
        let mut args = list.to_vec();
        args.extend(["--page-token", &token, "--output", "json"]);
        let result = run(runner, &format!("{step}/{page}"), "list succeeds", &args).await?;
        result.require_success()?;
        let listing: Value = result.json().map_err(|error| error.to_string())?;
        let Some(entries) = listing[collection].as_array() else {
            return Err(format!("{step}: list output has no '{collection}' array"));
        };
        if let Some(entry) = entries.iter().find(|entry| entry["name"] == name) {
            return Ok(Some(entry.clone()));
        }
        token = listing["next_page_token"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        if token.is_empty() {
            return Ok(None);
        }
    }
    Err(format!(
        "{step}: listing did not finish within {MAX_PAGES} pages"
    ))
}

/// Require the workspace's listed status to be `expected`, where `None` means
/// the workspace is not listed.
pub async fn require_status(
    runner: &OpenShellRunner,
    step: &str,
    workspace: &str,
    expected: Option<&str>,
) -> Result<(), String> {
    let entry = find_entry(
        runner,
        step,
        &["workspace", "list"],
        "workspaces",
        workspace,
    )
    .await?;
    let actual = entry.as_ref().and_then(|entry| entry["status"].as_str());
    if actual == expected {
        return Ok(());
    }
    Err(format!(
        "{step}: workspace '{workspace}' is {actual:?}, expected {expected:?}"
    ))
}

/// Return the workspace that owns `template` in the listing selected by `scope`
/// (`--workspace <name>`, `--all-workspaces`, or nothing for the default
/// workspace), or `None` when it is not listed.
pub async fn template_owner(
    runner: &OpenShellRunner,
    step: &str,
    scope: &[&str],
    template: &str,
) -> Result<Option<String>, String> {
    let mut list = vec!["sandbox", "template", "list"];
    list.extend_from_slice(scope);
    let entry = find_entry(runner, step, &list, "templates", template).await?;
    Ok(entry.map(|entry| entry["workspace"].as_str().unwrap_or_default().to_string()))
}

/// Delete a story's templates and workspace. Resources a successful story
/// already removed report "not found", which is fine; any other failure is
/// returned so cleanup problems stay visible.
async fn cleanup_workspace(
    runner: &OpenShellRunner,
    workspace: &str,
    templates: &[&str],
) -> Result<(), String> {
    let mut commands: Vec<Vec<&str>> = templates
        .iter()
        .map(|template| {
            vec![
                "sandbox",
                "template",
                "delete",
                template,
                "--workspace",
                workspace,
            ]
        })
        .collect();
    commands.push(vec!["workspace", "delete", workspace]);
    let mut failures = Vec::new();
    for args in commands {
        match run(
            runner,
            "cleanup",
            "resource is deleted or already absent",
            &args,
        )
        .await
        {
            Ok(result) if result.success() || reports_not_found(&result) => {}
            Ok(result) => failures.push(result.failure_diagnostic("cleanup delete succeeds")),
            Err(error) => failures.push(error),
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n\n"))
    }
}

fn reports_not_found(result: &CommandResult) -> bool {
    let output = format!("{}{}", result.stdout(), result.stderr());
    let output = output.to_ascii_lowercase();
    output.contains("sandbox template not found")
        || output.contains("workspace not found")
        || (output.contains("workspace '") && output.contains("' not found"))
}

/// Combine a story result with its cleanup result, keeping both failures.
fn merge(result: Result<(), String>, cleanup: Result<(), String>) -> Result<(), String> {
    match (result, cleanup) {
        (Err(error), Err(cleanup)) => Err(format!("{error}\n\ncleanup also failed:\n{cleanup}")),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

/// Finish a story. A passing story already removed its resources, so cleanup
/// runs only after a failure; both failures are kept. The runner then cleans up
/// its own tracked resources.
pub async fn finish(
    runner: OpenShellRunner,
    result: Result<(), String>,
    workspace: &str,
    templates: &[&str],
) -> Result<(), String> {
    let cleanup = if result.is_err() {
        cleanup_workspace(&runner, workspace, templates).await
    } else {
        Ok(())
    };
    runner.finish(merge(result, cleanup)).await
}
