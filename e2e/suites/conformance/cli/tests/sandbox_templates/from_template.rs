// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::helpers::{CREATE_TIMEOUT, finish, run, succeeds};
use openshell_e2e_support::OpenShellRunner;

/// Verify a sandbox created from a template gets the template's environment.
///
/// Side effects: creates one sandbox and one template, and deletes both.
#[tokio::test]
async fn sandbox_create_from_template_uses_reusable_workload() {
    let mut runner = OpenShellRunner::from_env("sandbox-templates/from-template")
        .expect("candidate openshell CLI is available");
    let template = format!("ct-{}-ft", runner.id());
    let sandbox = format!("ct-{}-fs", runner.id());
    let result = async {
        runner.check_gateway_status().await?;
        let r = &mut runner;
        let create = [
            "sandbox",
            "template",
            "create",
            &template,
            "--env",
            "FEATURE_FLAG=on",
        ];
        succeeds(r, "template-create", "template is created", &create).await?;

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
        r.step("sandbox-create")
            .description("sandbox is created from the template")
            .with_timeout(CREATE_TIMEOUT)
            .run(&create)
            .await
            .map_err(|error| error.to_string())?
            .require_success()?;

        let exec = ["sandbox", "exec", "--name", &sandbox, "--no-tty", "--"];
        let read = [
            exec.as_slice(),
            &["sh", "-c", "printf %s \"$FEATURE_FLAG\""],
        ]
        .concat();
        let flag = run(
            r,
            "read-env",
            "sandbox sees the template environment",
            &read,
        )
        .await?;
        flag.require_success()?;
        if flag.stdout() != "on" {
            return Err(flag.failure_diagnostic("FEATURE_FLAG is on in the sandbox"));
        }
        succeeds(
            r,
            "sandbox-delete",
            "sandbox is deleted",
            &["sandbox", "delete", &sandbox],
        )
        .await?;
        r.forget_sandbox(&sandbox);
        succeeds(
            r,
            "template-delete",
            "template is deleted",
            &["sandbox", "template", "delete", &template],
        )
        .await
    }
    .await;
    if let Err(error) = finish(runner, result, &[&template]).await {
        panic!("sandbox-templates/from-template conformance story failed:\n{error}");
    }
}
