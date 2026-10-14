// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::helpers::{fails, finish, require_listed, succeeds};
use openshell_e2e_support::OpenShellRunner;

/// Verify a deleted template cannot be retrieved and is no longer listed.
#[tokio::test]
async fn sandbox_template_get_after_delete_returns_not_found() {
    let mut runner = OpenShellRunner::from_env("sandbox-templates/get-after-delete")
        .expect("candidate openshell CLI is available");
    let template = format!("ct-{}-gd", runner.id());
    let result = async {
        runner.check_gateway_status().await?;
        let r = &runner;
        succeeds(
            r,
            "create",
            "template is created",
            &["sandbox", "template", "create", &template],
        )
        .await?;
        succeeds(
            r,
            "delete",
            "template is deleted",
            &["sandbox", "template", "delete", &template],
        )
        .await?;
        fails(
            r,
            "get",
            "deleted template is gone",
            &["sandbox", "template", "get", &template],
        )
        .await?;
        require_listed(r, "list", &template, false).await
    }
    .await;
    if let Err(error) = finish(runner, result, &[&template]).await {
        panic!("sandbox-templates/get-after-delete conformance story failed:\n{error}");
    }
}
