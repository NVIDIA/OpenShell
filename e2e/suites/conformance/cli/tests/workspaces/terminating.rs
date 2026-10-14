// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::helpers::{
    create_template_args, fails, finish, require_status, succeeds, template_owner,
};
use openshell_e2e_support::OpenShellRunner;

/// Verify the deletion guard and the Terminating phase. Deleting a workspace
/// that still holds a resource is refused and leaves it Terminating; while it
/// is Terminating new resources are rejected and existing ones can still be
/// deleted; retrying the delete then succeeds.
///
/// Known limitation: the CLI exposes no structured error, so rejections are
/// checked by exit status and by the resulting state, not by message.
#[tokio::test]
async fn workspace_terminating_rejects_creates() {
    let mut runner = OpenShellRunner::from_env("workspaces/terminating")
        .expect("candidate openshell CLI is available");
    let workspace = format!("ws-{}-tm", runner.id());
    let template = format!("ct-{}-tm", runner.id());
    let blocked = format!("ct-{}-bl", runner.id());
    let result = async {
        runner.check_gateway_status().await?;
        let r = &runner;
        let (ws, tpl, bl) = (workspace.as_str(), template.as_str(), blocked.as_str());
        succeeds(
            r,
            "create",
            "workspace is created",
            &["workspace", "create", "--name", ws],
        )
        .await?;
        succeeds(
            r,
            "template-create",
            "template is created in the workspace",
            &create_template_args(ws, tpl),
        )
        .await?;

        succeeds(
            r,
            "control-create",
            "the same template can be created while the workspace is Active",
            &create_template_args(ws, bl),
        )
        .await?;
        succeeds(
            r,
            "control-delete",
            "and deleted again",
            &["sandbox", "template", "delete", bl, "--workspace", ws],
        )
        .await?;

        fails(
            r,
            "delete-blocked",
            "delete is refused while the workspace holds a resource",
            &["workspace", "delete", ws],
        )
        .await?;
        require_status(r, "list-terminating", ws, Some("Terminating")).await?;

        fails(
            r,
            "create-rejected",
            "a new template is rejected while Terminating",
            &create_template_args(ws, bl),
        )
        .await?;
        if template_owner(r, "list-rejected", &["--workspace", ws], bl)
            .await?
            .is_some()
        {
            return Err(format!(
                "rejected template '{bl}' exists in workspace '{ws}'"
            ));
        }

        succeeds(
            r,
            "template-delete",
            "an existing template can still be deleted",
            &["sandbox", "template", "delete", tpl, "--workspace", ws],
        )
        .await?;
        succeeds(
            r,
            "delete-retry",
            "retrying the delete succeeds once empty",
            &["workspace", "delete", ws],
        )
        .await?;
        require_status(r, "list-absent", ws, None).await
    }
    .await;
    if let Err(error) = finish(runner, result, &workspace, &[&template, &blocked]).await {
        panic!("workspaces/terminating conformance story failed:\n{error}");
    }
}
