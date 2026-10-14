// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::helpers::{fails, finish, require_status, succeeds};
use openshell_e2e_support::OpenShellRunner;

/// Verify a workspace can be created, inspected, listed as Active, deleted when
/// empty, and is gone afterwards.
#[tokio::test]
async fn workspace_full_crud_lifecycle() {
    let mut runner =
        OpenShellRunner::from_env("workspaces/crud").expect("candidate openshell CLI is available");
    let workspace = format!("ws-{}-cr", runner.id());
    let result = async {
        runner.check_gateway_status().await?;
        let r = &runner;
        let name = workspace.as_str();
        succeeds(
            r,
            "create",
            "workspace is created",
            &["workspace", "create", "--name", name],
        )
        .await?;
        succeeds(
            r,
            "get",
            "workspace can be retrieved",
            &["workspace", "get", name],
        )
        .await?;
        require_status(r, "list-active", name, Some("Active")).await?;
        succeeds(
            r,
            "delete",
            "empty workspace is deleted",
            &["workspace", "delete", name],
        )
        .await?;
        fails(
            r,
            "get-after-delete",
            "deleted workspace is gone",
            &["workspace", "get", name],
        )
        .await?;
        require_status(r, "list-absent", name, None).await
    }
    .await;
    if let Err(error) = finish(runner, result, &workspace, &[]).await {
        panic!("workspaces/crud conformance story failed:\n{error}");
    }
}
