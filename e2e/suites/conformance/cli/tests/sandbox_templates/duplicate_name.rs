// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::helpers::{fails, finish, succeeds, template_json};
use openshell_e2e_support::OpenShellRunner;

/// Verify creating a template with an existing name is rejected and leaves the
/// original definition unchanged.
#[tokio::test]
async fn sandbox_template_create_rejects_duplicate_name() {
    let mut runner = OpenShellRunner::from_env("sandbox-templates/duplicate-name")
        .expect("candidate openshell CLI is available");
    let template = format!("ct-{}-dn", runner.id());
    let result = async {
        runner.check_gateway_status().await?;
        let r = &runner;
        let first = [
            "sandbox",
            "template",
            "create",
            &template,
            "--label",
            "e2e=first",
        ];
        succeeds(r, "create", "template is created", &first).await?;
        let second = [
            "sandbox",
            "template",
            "create",
            &template,
            "--label",
            "e2e=second",
        ];
        fails(
            r,
            "duplicate",
            "a second template with the same name is rejected",
            &second,
        )
        .await?;

        let json = template_json(r, "get", &template).await?;
        if json["labels"]["e2e"].as_str() != Some("first") {
            return Err(format!(
                "duplicate create changed the template: {}",
                json["labels"]
            ));
        }
        succeeds(
            r,
            "delete",
            "template is deleted",
            &["sandbox", "template", "delete", &template],
        )
        .await
    }
    .await;
    if let Err(error) = finish(runner, result, &[&template]).await {
        panic!("sandbox-templates/duplicate-name conformance story failed:\n{error}");
    }
}
