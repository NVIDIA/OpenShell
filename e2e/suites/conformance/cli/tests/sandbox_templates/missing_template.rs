// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::helpers::{CREATE_TIMEOUT, fails, finish};
use openshell_e2e_support::OpenShellRunner;

/// Verify creating a sandbox from a template that does not exist is rejected
/// and leaves no sandbox behind. The same flags succeed for an existing
/// template in the from-template story, so the rejection is about the template.
#[tokio::test]
async fn sandbox_create_from_missing_template_returns_not_found() {
    let mut runner = OpenShellRunner::from_env("sandbox-templates/missing-template")
        .expect("candidate openshell CLI is available");
    let template = format!("ct-{}-mt", runner.id());
    let sandbox = format!("ct-{}-ms", runner.id());
    let result = async {
        runner.check_gateway_status().await?;
        let r = &mut runner;
        r.track_sandbox(&sandbox);
        let create = [
            "sandbox",
            "create",
            "--name",
            &sandbox,
            "--detach",
            "--template",
            &template,
        ];
        let rejected = r
            .step("create")
            .description("sandbox create from a missing template is rejected")
            .with_timeout(CREATE_TIMEOUT)
            .run(&create)
            .await
            .map_err(|error| error.to_string())?;
        if rejected.success() {
            return Err(rejected.failure_diagnostic("create from a missing template fails"));
        }
        let get = ["sandbox", "get", &sandbox];
        fails(r, "get", "no sandbox was created", &get).await
    }
    .await;
    if let Err(error) = finish(runner, result, &[]).await {
        panic!("sandbox-templates/missing-template conformance story failed:\n{error}");
    }
}
