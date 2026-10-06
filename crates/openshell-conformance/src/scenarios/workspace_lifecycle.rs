// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Portable workspace lifecycle conformance scenarios.

use std::time::Duration;

use crate::{CommandResult, OpenShellRunner, Scenario, ScenarioFuture};

const COMMAND_TIMEOUT: Duration = Duration::from_mins(2);
const PROVIDER_TYPE: &str = "openai";
const PROVIDER_CREDENTIAL: &str = "OPENAI_API_KEY=test-value";

/// Certify workspace and workspace-scoped provider CRUD, isolation from the
/// default workspace, and the deletion guard that blocks removing a
/// workspace while resources still exist in it.
pub const WORKSPACE_LIFECYCLE_SCENARIO: Scenario = Scenario {
    name: "workspace-lifecycle",
    description: "Verify workspace and workspace-scoped provider CRUD, isolation, and deletion guards.",
    run: run_workspace_lifecycle,
};

/// Certify that a terminating workspace rejects new resource creation while
/// still allowing deletion of its existing resources.
pub const WORKSPACE_TERMINATING_SCENARIO: Scenario = Scenario {
    name: "workspace-terminating",
    description: "Verify a terminating workspace rejects creates but allows deletes.",
    run: run_workspace_terminating,
};

fn run_workspace_lifecycle(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move {
        let workspace = format!("ws-{}-cr", runner.id());
        let provider = format!("pv-{}-cr", runner.id());

        let result = workspace_full_crud_lifecycle(runner, &workspace, &provider).await;
        cleanup_workspace(runner, &workspace, &[&provider]).await;
        result
    })
}

fn run_workspace_terminating(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move {
        let workspace = format!("ws-{}-tm", runner.id());
        let provider = format!("pv-{}-tm", runner.id());
        let blocked_provider = format!("pv-{}-bl", runner.id());

        let result =
            workspace_terminating_rejects_creates(runner, &workspace, &provider, &blocked_provider)
                .await;
        cleanup_workspace(runner, &workspace, &[&provider, &blocked_provider]).await;
        result
    })
}

async fn workspace_full_crud_lifecycle(
    runner: &OpenShellRunner,
    workspace: &str,
    provider: &str,
) -> Result<(), String> {
    run_cli(
        runner,
        "create",
        format!("workspace '{workspace}' is created"),
        &["workspace", "create", "--name", workspace],
        true,
    )
    .await?;

    let get = run_cli(
        runner,
        "get",
        format!("workspace '{workspace}' can be retrieved"),
        &["workspace", "get", workspace],
        true,
    )
    .await?;
    require_contains(&get, workspace, "workspace get output names the workspace")?;

    run_cli(
        runner,
        "provider-create",
        format!("provider '{provider}' is created in workspace '{workspace}'"),
        &[
            "provider",
            "create",
            "--name",
            provider,
            "--type",
            PROVIDER_TYPE,
            "--credential",
            PROVIDER_CREDENTIAL,
            "--workspace",
            workspace,
        ],
        true,
    )
    .await?;

    let scoped_list = run_cli(
        runner,
        "provider-list-scoped",
        format!("provider list scoped to '{workspace}' succeeds"),
        &["provider", "list", "--workspace", workspace],
        true,
    )
    .await?;
    require_contains(
        &scoped_list,
        provider,
        "workspace-scoped provider list includes the provider",
    )?;

    let default_list = run_cli(
        runner,
        "provider-list-default",
        "provider list in the default workspace succeeds",
        &["provider", "list"],
        true,
    )
    .await?;
    require_not_contains(
        &default_list,
        provider,
        "default workspace excludes the workspace-scoped provider",
    )?;

    let all_list = run_cli(
        runner,
        "provider-list-all",
        "provider list --all-workspaces succeeds",
        &["provider", "list", "--all-workspaces"],
        true,
    )
    .await?;
    require_contains(
        &all_list,
        provider,
        "--all-workspaces includes the workspace-scoped provider",
    )?;

    let blocked_delete = run_cli(
        runner,
        "delete-blocked",
        format!("workspace '{workspace}' delete is blocked while resources exist"),
        &["workspace", "delete", workspace],
        false,
    )
    .await?;
    require_contains(
        &blocked_delete,
        "still contains resources",
        "blocked deletion error names the blocking resources",
    )?;

    run_cli(
        runner,
        "provider-delete",
        format!("provider '{provider}' is deleted"),
        &["provider", "delete", provider, "--workspace", workspace],
        true,
    )
    .await?;

    run_cli(
        runner,
        "delete",
        format!("workspace '{workspace}' delete succeeds once empty"),
        &["workspace", "delete", workspace],
        true,
    )
    .await?;

    run_cli(
        runner,
        "get-after-delete",
        format!("workspace '{workspace}' get fails after deletion"),
        &["workspace", "get", workspace],
        false,
    )
    .await
    .map(|_| ())
}

async fn workspace_terminating_rejects_creates(
    runner: &OpenShellRunner,
    workspace: &str,
    provider: &str,
    blocked_provider: &str,
) -> Result<(), String> {
    run_cli(
        runner,
        "create",
        format!("workspace '{workspace}' is created"),
        &["workspace", "create", "--name", workspace],
        true,
    )
    .await?;

    run_cli(
        runner,
        "provider-create",
        format!("provider '{provider}' is created"),
        &[
            "provider",
            "create",
            "--name",
            provider,
            "--type",
            PROVIDER_TYPE,
            "--credential",
            PROVIDER_CREDENTIAL,
            "--workspace",
            workspace,
        ],
        true,
    )
    .await?;

    run_cli(
        runner,
        "delete-blocked",
        format!("workspace '{workspace}' delete is blocked by '{provider}'"),
        &["workspace", "delete", workspace],
        false,
    )
    .await?;

    let list = run_cli(
        runner,
        "list-terminating",
        "workspace list succeeds",
        &["workspace", "list"],
        true,
    )
    .await?;
    require_contains(
        &list,
        "Terminating",
        "workspace list shows the Terminating status",
    )?;

    let blocked_create = run_cli(
        runner,
        "create-blocked",
        format!("provider create in terminating workspace '{workspace}' fails"),
        &[
            "provider",
            "create",
            "--name",
            blocked_provider,
            "--type",
            PROVIDER_TYPE,
            "--credential",
            PROVIDER_CREDENTIAL,
            "--workspace",
            workspace,
        ],
        false,
    )
    .await?;
    require_contains(
        &blocked_create,
        "being deleted",
        "blocked create error names the terminating workspace",
    )?;

    run_cli(
        runner,
        "provider-delete",
        format!("provider '{provider}' is deleted"),
        &["provider", "delete", provider, "--workspace", workspace],
        true,
    )
    .await?;

    run_cli(
        runner,
        "delete-retry",
        format!("workspace '{workspace}' delete succeeds once empty"),
        &["workspace", "delete", workspace],
        true,
    )
    .await
    .map(|_| ())
}

/// Best-effort teardown. Mirrors a `Drop`-guard cleanup: ignore failures since
/// the resources may already be gone as part of a successful scenario run.
async fn cleanup_workspace(runner: &OpenShellRunner, workspace: &str, providers: &[&str]) {
    for provider in providers {
        let _ = runner
            .step("cleanup/provider-delete")
            .description(format!(
                "provider '{provider}' is deleted or already absent"
            ))
            .with_timeout(COMMAND_TIMEOUT)
            .run(&["provider", "delete", provider, "--workspace", workspace])
            .await;
    }
    let _ = runner
        .step("cleanup/workspace-delete")
        .description(format!(
            "workspace '{workspace}' is deleted or already absent"
        ))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["workspace", "delete", workspace])
        .await;
}

async fn run_cli(
    runner: &OpenShellRunner,
    step: &str,
    description: impl Into<String>,
    args: &[&str],
    expect_success: bool,
) -> Result<CommandResult, String> {
    let result = runner
        .step(step)
        .description(description)
        .with_timeout(COMMAND_TIMEOUT)
        .run(args)
        .await
        .map_err(|error| error.to_string())?;
    if result.success() == expect_success {
        Ok(result)
    } else {
        Err(result.failure_diagnostic(if expect_success {
            "command succeeds"
        } else {
            "command fails"
        }))
    }
}

fn output_contains(result: &CommandResult, needle: &str) -> bool {
    normalize_wrapping(result.stdout()).contains(needle)
        || normalize_wrapping(result.stderr()).contains(needle)
}

/// Collapse miette's line-wrapped, `│`-continued diagnostic text back into a
/// single line so phrase matches don't depend on the terminal width the CLI
/// detected when it rendered the error.
fn normalize_wrapping(text: &str) -> String {
    text.replace(['\n', '│'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn require_contains(result: &CommandResult, needle: &str, expectation: &str) -> Result<(), String> {
    if output_contains(result, needle) {
        Ok(())
    } else {
        Err(result.failure_diagnostic(expectation))
    }
}

fn require_not_contains(
    result: &CommandResult,
    needle: &str,
    expectation: &str,
) -> Result<(), String> {
    if output_contains(result, needle) {
        Err(result.failure_diagnostic(expectation))
    } else {
        Ok(())
    }
}
