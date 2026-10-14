// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::helpers::{create_template_args, finish, succeeds, template_owner};
use openshell_e2e_support::OpenShellRunner;

/// Verify a template created in a workspace is listed in that workspace and in
/// the all-workspaces view with its owner, and is not visible in the default
/// workspace.
#[tokio::test]
async fn template_is_scoped_to_its_workspace() {
    let mut runner = OpenShellRunner::from_env("workspaces/resource-scoping")
        .expect("candidate openshell CLI is available");
    let workspace = format!("ws-{}-sc", runner.id());
    let template = format!("ct-{}-sc", runner.id());
    let result = async {
        runner.check_gateway_status().await?;
        let r = &runner;
        let (ws, tpl) = (workspace.as_str(), template.as_str());
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

        let scoped = template_owner(r, "list-scoped", &["--workspace", ws], tpl).await?;
        let default = template_owner(r, "list-default", &[], tpl).await?;
        let all = template_owner(r, "list-all", &["--all-workspaces"], tpl).await?;
        if scoped.as_deref() != Some(ws) {
            return Err(format!(
                "{tpl} is owned by {scoped:?} in its workspace, not {ws}"
            ));
        }
        if all.as_deref() != Some(ws) {
            return Err(format!(
                "{tpl} is owned by {all:?} across workspaces, not {ws}"
            ));
        }
        if let Some(owner) = default {
            return Err(format!(
                "{tpl} is visible in the default workspace as {owner}"
            ));
        }

        succeeds(
            r,
            "template-delete",
            "template is deleted",
            &["sandbox", "template", "delete", tpl, "--workspace", ws],
        )
        .await?;
        succeeds(
            r,
            "delete",
            "workspace is deleted once empty",
            &["workspace", "delete", ws],
        )
        .await
    }
    .await;
    if let Err(error) = finish(runner, result, &workspace, &[&template]).await {
        panic!("workspaces/resource-scoping conformance story failed:\n{error}");
    }
}
