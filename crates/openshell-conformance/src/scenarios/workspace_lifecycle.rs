// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Portable workspace lifecycle conformance scenarios.

use std::time::Duration;

use serde::Deserialize;

use crate::{
    CommandResult, OpenShellRunner, Scenario, ScenarioFuture, combine_results,
    output_reports_not_found,
};

const COMMAND_TIMEOUT: Duration = Duration::from_mins(2);
const PROVIDER_TYPE: &str = "openai";
const PROVIDER_CREDENTIAL: &str = "OPENAI_API_KEY=test-value";

/// Certify workspace and workspace-scoped provider CRUD, isolation from the
/// default workspace, and the deletion guard that blocks removing a
/// workspace while resources still exist in it.
///
/// - **Behavior:** a created workspace is retrievable and listed as `Active`. A provider created in it appears in its own workspace listing and in the all-workspaces listing (owned by that workspace), and not in the default workspace. Deleting the workspace is refused while the provider exists and succeeds once it is removed, after which the workspace can no longer be retrieved.
/// - **Preconditions:** a reachable gateway that can create workspaces and providers. The provider uses the `openai` type with a placeholder credential and is never contacted.
/// - **Permissions:** an identity allowed to create and delete workspaces and providers.
/// - **Side effects:** creates one workspace and one provider named from the run id. Both are deleted on success and on failure; a cleanup failure fails the scenario.
/// - **Known limitation:** `workspace get` has no structured output, so only its exit status is checked, and the deletion-guard error is matched by phrase because the CLI exposes no structured error.
pub const WORKSPACE_LIFECYCLE_SCENARIO: Scenario = Scenario {
    name: "workspace-lifecycle",
    run: run_workspace_lifecycle,
};

/// Certify that a terminating workspace rejects new resource creation while
/// still allowing deletion of its existing resources.
///
/// - **Behavior:** after deleting a workspace that still holds a resource, the workspace is listed as `Terminating`. While it is terminating, creating another resource in it is rejected, deleting its existing resource succeeds, and deleting the workspace then succeeds.
/// - **Preconditions:** a reachable gateway that can create workspaces and providers. The provider uses the `openai` type with a placeholder credential and is never contacted.
/// - **Permissions:** an identity allowed to create and delete workspaces and providers.
/// - **Side effects:** creates one workspace and up to two providers named from the run id. All are deleted on success and on failure; a cleanup failure fails the scenario.
/// - **Known limitation:** the rejected create is matched by phrase because the CLI exposes no structured error.
pub const WORKSPACE_TERMINATING_SCENARIO: Scenario = Scenario {
    name: "workspace-terminating",
    run: run_workspace_terminating,
};

fn run_workspace_lifecycle(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move {
        let workspace = format!("ws-{}-cr", runner.id());
        let provider = format!("pv-{}-cr", runner.id());

        let result = workspace_full_crud_lifecycle(runner, &workspace, &provider).await;
        let cleanup = cleanup_workspace(runner, &workspace, &[&provider]).await;
        combine_results(result, cleanup)
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
        let cleanup = cleanup_workspace(runner, &workspace, &[&provider, &blocked_provider]).await;
        combine_results(result, cleanup)
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

    run_cli(
        runner,
        "get",
        format!("workspace '{workspace}' can be retrieved"),
        &["workspace", "get", workspace],
        true,
    )
    .await?;
    require_workspace_status(runner, "list-created", workspace, "Active").await?;

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

    require_provider_listed(
        runner,
        "provider-list-scoped",
        &["--workspace", workspace],
        provider,
        workspace,
    )
    .await?;
    require_provider_not_listed(runner, "provider-list-default", &[], provider).await?;
    require_provider_listed(
        runner,
        "provider-list-all",
        &["--all-workspaces"],
        provider,
        workspace,
    )
    .await?;

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

    require_workspace_status(runner, "list-terminating", workspace, "Terminating").await?;

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

/// Delete the scenario's providers and workspace. A successful run has already
/// removed them, so "not found" is fine; any other failure is returned so the
/// scenario fails instead of leaking resources silently.
async fn cleanup_workspace(
    runner: &OpenShellRunner,
    workspace: &str,
    providers: &[&str],
) -> Result<(), String> {
    let mut failures = Vec::new();
    for provider in providers {
        cleanup_delete(
            runner,
            "cleanup/provider-delete",
            format!("provider '{provider}' is deleted or already absent"),
            &["provider", "delete", provider, "--workspace", workspace],
            &mut failures,
        )
        .await;
    }
    cleanup_delete(
        runner,
        "cleanup/workspace-delete",
        format!("workspace '{workspace}' is deleted or already absent"),
        &["workspace", "delete", workspace],
        &mut failures,
    )
    .await;

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n\n"))
    }
}

async fn cleanup_delete(
    runner: &OpenShellRunner,
    step: &str,
    expectation: String,
    args: &[&str],
    failures: &mut Vec<String>,
) {
    match runner
        .step(step)
        .description(expectation.clone())
        .with_timeout(COMMAND_TIMEOUT)
        .run(args)
        .await
    {
        Ok(result) if result.success() || output_reports_not_found(&result) => {}
        Ok(result) => failures.push(result.failure_diagnostic(&expectation)),
        Err(error) => failures.push(error.to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct WorkspaceListPage {
    workspaces: Vec<WorkspaceEntry>,
    next_page_token: String,
}

#[derive(Debug, Deserialize)]
struct WorkspaceEntry {
    name: String,
    status: String,
}

#[derive(Debug, Deserialize)]
struct ProviderListPage {
    providers: Vec<ProviderEntry>,
    next_page_token: String,
}

#[derive(Debug, Deserialize)]
struct ProviderEntry {
    name: String,
    #[serde(default)]
    workspace: String,
}

/// Find `workspace` in the paginated `workspace list --output json` listing.
async fn find_workspace(
    runner: &OpenShellRunner,
    step: &str,
    workspace: &str,
) -> Result<Option<WorkspaceEntry>, String> {
    let mut page_token = String::new();
    let mut page = 0u32;
    loop {
        let result = run_cli(
            runner,
            &format!("{step}/{page}"),
            format!("workspace list page {page} succeeds"),
            &[
                "workspace",
                "list",
                "--page-token",
                &page_token,
                "--output",
                "json",
            ],
            true,
        )
        .await?;
        let listing = result
            .json::<WorkspaceListPage>()
            .map_err(|error| error.to_string())?;
        if let Some(entry) = listing
            .workspaces
            .into_iter()
            .find(|entry| entry.name == workspace)
        {
            return Ok(Some(entry));
        }
        if listing.next_page_token.is_empty() {
            return Ok(None);
        }
        page_token = listing.next_page_token;
        page = page
            .checked_add(1)
            .ok_or_else(|| "workspace list page counter overflowed".to_string())?;
    }
}

/// Require that the workspace listing shows `workspace` itself with `status`,
/// not merely that some workspace has that status.
async fn require_workspace_status(
    runner: &OpenShellRunner,
    step: &str,
    workspace: &str,
    status: &str,
) -> Result<(), String> {
    match find_workspace(runner, step, workspace).await? {
        Some(entry) if entry.status == status => Ok(()),
        Some(entry) => Err(format!(
            "{step}: workspace '{workspace}' has status '{}', expected '{status}'",
            entry.status
        )),
        None => Err(format!(
            "{step}: workspace '{workspace}' is not in the workspace list"
        )),
    }
}

/// Find `provider` in the paginated `provider list --output json` listing
/// selected by `scope` (`--workspace <name>`, `--all-workspaces`, or none for
/// the default workspace).
async fn find_provider(
    runner: &OpenShellRunner,
    step: &str,
    scope: &[&str],
    provider: &str,
) -> Result<Option<ProviderEntry>, String> {
    let mut page_token = String::new();
    let mut page = 0u32;
    loop {
        let mut args = vec![
            "provider",
            "list",
            "--page-token",
            page_token.as_str(),
            "--output",
            "json",
        ];
        args.extend_from_slice(scope);
        let result = run_cli(
            runner,
            &format!("{step}/{page}"),
            format!("provider list page {page} succeeds"),
            &args,
            true,
        )
        .await?;
        let listing = result
            .json::<ProviderListPage>()
            .map_err(|error| error.to_string())?;
        if let Some(entry) = listing
            .providers
            .into_iter()
            .find(|entry| entry.name == provider)
        {
            return Ok(Some(entry));
        }
        if listing.next_page_token.is_empty() {
            return Ok(None);
        }
        page_token = listing.next_page_token;
        page = page
            .checked_add(1)
            .ok_or_else(|| "provider list page counter overflowed".to_string())?;
    }
}

/// Require that `provider` appears in the selected listing, owned by `workspace`.
async fn require_provider_listed(
    runner: &OpenShellRunner,
    step: &str,
    scope: &[&str],
    provider: &str,
    workspace: &str,
) -> Result<(), String> {
    match find_provider(runner, step, scope, provider).await? {
        Some(entry) if entry.workspace == workspace => Ok(()),
        Some(entry) => Err(format!(
            "{step}: provider '{provider}' is listed in workspace '{}', expected '{workspace}'",
            entry.workspace
        )),
        None => Err(format!("{step}: provider '{provider}' is not listed")),
    }
}

/// Require that `provider` does not appear in the selected listing.
async fn require_provider_not_listed(
    runner: &OpenShellRunner,
    step: &str,
    scope: &[&str],
    provider: &str,
) -> Result<(), String> {
    match find_provider(runner, step, scope, provider).await? {
        None => Ok(()),
        Some(entry) => Err(format!(
            "{step}: provider '{provider}' (workspace '{}') is listed but should not be",
            entry.workspace
        )),
    }
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
    result.require_outcome(expect_success)?;
    Ok(result)
}

fn require_contains(result: &CommandResult, needle: &str, expectation: &str) -> Result<(), String> {
    if result.output_contains(needle) {
        Ok(())
    } else {
        Err(result.failure_diagnostic(expectation))
    }
}
