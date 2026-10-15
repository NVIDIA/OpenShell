// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::helpers::{finish, require_listed, succeeds, template_json};
use openshell_e2e_support::OpenShellRunner;

/// Verify a template's name, labels, environment and resources survive a
/// create and get, and that it is listed.
///
/// Resources are metadata here. Enforcing them is driver-specific.
#[tokio::test]
async fn sandbox_template_round_trips_its_definition() {
    let mut runner = OpenShellRunner::from_env("sandbox-templates/round-trip")
        .expect("candidate openshell CLI is available");
    let template = format!("ct-{}-tr", runner.id());
    let result = async {
        runner.check_gateway_status().await?;
        let r = &runner;
        let create = [
            "sandbox",
            "template",
            "create",
            &template,
            "--cpu",
            "500m",
            "--memory",
            "512Mi",
            "--label",
            "e2e=sandbox-template",
            "--env",
            "FEATURE_FLAG=on",
        ];
        succeeds(r, "create", "template is created", &create).await?;

        let json = template_json(r, "get", &template).await?;
        let checks = [
            ("name", &json["name"], template.as_str()),
            ("label e2e", &json["labels"]["e2e"], "sandbox-template"),
            (
                "env FEATURE_FLAG",
                &json["environment"]["FEATURE_FLAG"],
                "on",
            ),
            ("cpu", &json["resources"]["cpu"], "500m"),
            ("memory", &json["resources"]["memory"], "512Mi"),
        ];
        for (label, actual, expected) in checks {
            if actual.as_str() != Some(expected) {
                return Err(format!("template {label} is {actual}, expected {expected}"));
            }
        }
        require_listed(r, "list", &template, true).await?;
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
        panic!("sandbox-templates/round-trip conformance story failed:\n{error}");
    }
}
