// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Workspaces suite: workspace create, inspect, scope and delete through the
//! `openshell` CLI.
//!
//! Ported from the legacy `workspace_lifecycle` e2e test. Workspace behavior is
//! not driver-specific, so it runs against any prepared gateway.
//!
//! The scoped resource is a sandbox template, not a provider: a template is
//! workspace-scoped and covered by the workspace delete guard, and needs no
//! provider profile, credential or image.
//!
//! Assertions check exit status and listed state from `--output json`, not
//! error message text, per "What a test may assert" in the conformance README.

use testkit::Context;

/// `["sandbox", "template", "create", name, "--workspace", workspace]`.
fn template_create<'a>(workspace: &'a str, name: &'a str) -> [&'a str; 6] {
    [
        "sandbox",
        "template",
        "create",
        name,
        "--workspace",
        workspace,
    ]
}

fn template_delete<'a>(workspace: &'a str, name: &'a str) -> [&'a str; 6] {
    [
        "sandbox",
        "template",
        "delete",
        name,
        "--workspace",
        workspace,
    ]
}

/// Create workspace `name`. A cleanup deletes it after the test; it is
/// registered first, so it runs after the cleanups of its templates. A
/// workspace the test already deleted is not an error.
async fn create_workspace(cx: &Context, name: &str) -> testkit::Result {
    let cli = cx.cli_handle();
    let owned = name.to_string();
    cx.on_cleanup(format!("delete workspace {name}"), async move || {
        let out = cli.run(["workspace", "delete", &owned]).await?;
        if out.exit_code != 0 && !is_not_found(&out.report_text()) {
            out.success()?;
        }
        Ok(())
    });
    cx.cli(["workspace", "create", "--name", name])
        .await?
        .success()?;
    Ok(())
}

/// Create template `name` in `workspace`, deleted after the test unless the
/// test deleted it already.
async fn create_template(cx: &Context, workspace: &str, name: &str) -> testkit::Result {
    let cli = cx.cli_handle();
    let (ws, owned) = (workspace.to_string(), name.to_string());
    cx.on_cleanup(format!("delete template {name}"), async move || {
        let out = cli.run(template_delete(&ws, &owned)).await?;
        if out.exit_code != 0 && !is_not_found(&out.report_text()) {
            out.success()?;
        }
        Ok(())
    });
    cx.cli(template_create(workspace, name)).await?.success()?;
    Ok(())
}

fn is_not_found(report: &str) -> bool {
    report.to_ascii_lowercase().contains("not found")
}

/// Require workspace `name`'s listed status to be `expected`, where `None`
/// means it is not listed.
async fn expect_status(cx: &Context, name: &str, expected: Option<&str>) -> testkit::Result {
    let entry = cx
        .cli_find_listed(&["workspace", "list"], "workspaces", name)
        .await?;
    let actual = entry.as_ref().and_then(|entry| entry["status"].as_str());
    testkit::ensure!(
        actual == expected,
        "workspace {name} is {actual:?} in workspace list; expected {expected:?}"
    );
    Ok(())
}

/// The workspace that owns `template` in the listing selected by `scope`
/// (`--workspace <name>`, `--all-workspaces`, or nothing for the test's
/// workspace), or `None` when it is not listed.
async fn template_owner(
    cx: &Context,
    scope: &[&str],
    template: &str,
) -> testkit::Result<Option<String>> {
    let mut list = vec!["sandbox", "template", "list"];
    list.extend_from_slice(scope);
    let entry = cx.cli_find_listed(&list, "templates", template).await?;
    Ok(entry.map(|entry| entry["workspace"].as_str().unwrap_or_default().to_string()))
}

/// A workspace can be created and is listed Active, cannot be deleted
/// while it holds a resource, can be deleted once empty, and is gone afterwards.
#[testkit::test]
async fn workspace_full_crud_lifecycle(cx: &mut Context) -> testkit::Result {
    let workspace = cx.name("wc");
    let template = cx.name("tc");

    create_workspace(cx, &workspace).await?;
    cx.cli(["workspace", "get", &workspace]).await?.success()?;
    expect_status(cx, &workspace, Some("Active")).await?;

    create_template(cx, &workspace, &template).await?;
    cx.cli(["workspace", "delete", &workspace])
        .await?
        .failure()?;
    // A refused delete leaves the workspace Terminating, so the failure is the
    // resource guard rather than an unrelated error.
    expect_status(cx, &workspace, Some("Terminating")).await?;

    cx.cli(template_delete(&workspace, &template))
        .await?
        .success()?;
    cx.cli(["workspace", "delete", &workspace])
        .await?
        .success()?;
    cx.cli(["workspace", "get", &workspace]).await?.failure()?;
    expect_status(cx, &workspace, None).await
}

/// A template is listed in its own workspace and in the all-workspaces view
/// with its owner, and is not visible in the test's workspace (the one
/// testkit pins the CLI to with `OPENSHELL_WORKSPACE`).
#[testkit::test]
async fn template_is_scoped_to_its_workspace(cx: &mut Context) -> testkit::Result {
    let workspace = cx.name("ws");
    let template = cx.name("ts");

    create_workspace(cx, &workspace).await?;
    create_template(cx, &workspace, &template).await?;

    let scoped = template_owner(cx, &["--workspace", &workspace], &template).await?;
    let unscoped = template_owner(cx, &[], &template).await?;
    let all = template_owner(cx, &["--all-workspaces"], &template).await?;
    testkit::ensure!(
        scoped.as_deref() == Some(workspace.as_str()),
        "{template} is owned by {scoped:?} in its workspace; expected {workspace}"
    );
    testkit::ensure!(
        all.as_deref() == Some(workspace.as_str()),
        "{template} is owned by {all:?} across workspaces; expected {workspace}"
    );
    testkit::ensure!(
        unscoped.is_none(),
        "{template} is visible in the test's workspace as {unscoped:?}"
    );

    cx.cli(template_delete(&workspace, &template))
        .await?
        .success()?;
    cx.cli(["workspace", "delete", &workspace])
        .await?
        .success()
        .map(|_| ())
}

/// Deleting a workspace that still holds a resource is refused and leaves it
/// Terminating. While Terminating, new resources are rejected and existing
/// ones can still be deleted; retrying the delete then succeeds.
#[testkit::test]
async fn workspace_terminating_rejects_creates(cx: &mut Context) -> testkit::Result {
    let workspace = cx.name("wt");
    let template = cx.name("tt");
    let blocked = cx.name("tb");

    create_workspace(cx, &workspace).await?;
    create_template(cx, &workspace, &template).await?;

    // Control: the same template can be created and deleted while the workspace
    // is Active, so the later rejection can only be about the Terminating state.
    create_template(cx, &workspace, &blocked).await?;
    cx.cli(template_delete(&workspace, &blocked))
        .await?
        .success()?;

    cx.cli(["workspace", "delete", &workspace])
        .await?
        .failure()?;
    expect_status(cx, &workspace, Some("Terminating")).await?;

    cx.cli(template_create(&workspace, &blocked))
        .await?
        .failure()?;
    let leaked = template_owner(cx, &["--workspace", &workspace], &blocked).await?;
    testkit::ensure!(
        leaked.is_none(),
        "rejected template {blocked} exists in workspace {workspace}"
    );

    cx.cli(template_delete(&workspace, &template))
        .await?
        .success()?;
    cx.cli(["workspace", "delete", &workspace])
        .await?
        .success()?;
    expect_status(cx, &workspace, None).await
}
