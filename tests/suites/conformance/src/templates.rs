// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox templates suite: reusable workload templates and sandboxes created
//! from them.

use std::collections::HashMap;

use testkit::sdk::raw::proto::datamodel::v1::ObjectMeta;
use testkit::sdk::{
    DeleteOptions, SandboxResources, SandboxTemplateCreateSpec, SandboxTemplateListOptions,
    SandboxWorkloadConfig, SandboxWorkloadTemplate, SandboxWorkloadTemplateSpec, SdkError,
};
use testkit::{Context, ResultExt as _};

/// Create template `name`, and delete it after the test. The cleanup is
/// registered before the create, so it also covers a create the gateway
/// applied but reported as failed.
async fn create_template(
    cx: &Context,
    name: &str,
    labels: HashMap<String, String>,
    workload: SandboxWorkloadConfig,
) -> Result<SandboxWorkloadTemplate, SdkError> {
    let client = cx.client().clone();
    let owned = name.to_string();
    cx.on_cleanup(format!("delete sandbox template {name}"), async move || {
        client
            .delete_sandbox_template(
                &owned,
                DeleteOptions {
                    allow_missing: true,
                },
            )
            .await?;
        Ok(())
    });
    cx.client()
        .create_sandbox_template(SandboxWorkloadTemplate {
            metadata: Some(ObjectMeta {
                name: name.to_string(),
                labels,
                ..ObjectMeta::default()
            }),
            spec: Some(SandboxWorkloadTemplateSpec {
                workload: Some(workload),
                ..SandboxWorkloadTemplateSpec::default()
            }),
        })
        .await
}

/// A template stores its labels, environment and resources, is listed, and a
/// sandbox created from it runs with its environment and records which
/// template it came from.
#[testkit::test]
async fn sandbox_from_template_uses_its_workload(cx: &mut Context) -> testkit::Result {
    let template_name = cx.name("tp");
    let labels = HashMap::from([("e2e".to_string(), "sandbox-template".to_string())]);
    let workload = SandboxWorkloadConfig {
        environment: HashMap::from([("FEATURE_FLAG".to_string(), "on".to_string())]),
        resources: Some(SandboxResources {
            cpu: "500m".to_string(),
            memory: "512Mi".to_string(),
            ..SandboxResources::default()
        }),
        ..SandboxWorkloadConfig::default()
    };
    create_template(cx, &template_name, labels.clone(), workload.clone()).await?;

    let stored = cx.client().get_sandbox_template(&template_name).await?;
    let meta = stored.metadata.clone().unwrap_or_default();
    testkit::ensure!(
        meta.name == template_name && meta.labels.get("e2e") == labels.get("e2e"),
        "template get returned name {:?} with labels {:?}; expected {template_name:?} with {labels:?}",
        meta.name,
        meta.labels
    );
    let stored_workload = stored
        .spec
        .as_ref()
        .and_then(|spec| spec.workload.clone())
        .unwrap_or_default();
    // Field by field: the gateway may fill in fields the template left unset.
    let sent = workload.resources.clone().unwrap_or_default();
    let resources = stored_workload.resources.clone().unwrap_or_default();
    testkit::ensure!(
        stored_workload.environment == workload.environment
            && resources.cpu == sent.cpu
            && resources.memory == sent.memory,
        "template get returned workload {stored_workload:?}; expected environment {:?}, cpu {:?}, memory {:?}",
        workload.environment,
        sent.cpu,
        sent.memory
    );

    let listed = cx
        .client()
        .list_all_sandbox_templates(SandboxTemplateListOptions::default())
        .await?;
    testkit::ensure!(
        listed.iter().any(|entry| entry
            .metadata
            .as_ref()
            .is_some_and(|m| m.name == template_name)),
        "template list does not include {template_name}"
    );

    let sandbox_name = cx.name("ts");
    cx.track(&sandbox_name);
    cx.client()
        .create_sandbox_from_template(SandboxTemplateCreateSpec {
            name: Some(sandbox_name.clone()),
            template_name: template_name.clone(),
            command: vec!["sleep".to_string(), "infinity".to_string()],
            ..SandboxTemplateCreateSpec::default()
        })
        .await?;
    let sandbox = cx.adopt(&sandbox_name).await?;
    let ready = sandbox.wait_ready().await?;
    let provenance = ready.created_from_workload_template.as_ref();
    testkit::ensure!(
        provenance.is_some_and(|p| p.name == template_name),
        "sandbox {sandbox_name} records template {provenance:?}; expected {template_name:?}"
    );

    sandbox
        .exec(["sh", "-c", "printf '%s' \"${FEATURE_FLAG:-missing}\""])
        .await?
        .expect_stdout(&workload.environment["FEATURE_FLAG"])
        .context("FEATURE_FLAG in a sandbox from the template")?;
    Ok(())
}

/// Template operations fail with the right status: a duplicate name is
/// `AlreadyExists`, a deleted template is `NotFound`, and creating a sandbox
/// from a missing template is `NotFound`.
#[testkit::test]
async fn template_crud_errors(cx: &mut Context) -> testkit::Result {
    let name = cx.name("te");
    let empty =
        async || create_template(cx, &name, HashMap::new(), SandboxWorkloadConfig::default()).await;

    empty().await?;
    let again = empty().await;
    testkit::ensure!(
        matches!(again, Err(SdkError::AlreadyExists { .. })),
        "creating template {name} again returned {again:?}; expected AlreadyExists"
    );

    cx.client()
        .delete_sandbox_template(&name, DeleteOptions::default())
        .await?;
    let deleted = cx.client().get_sandbox_template(&name).await;
    testkit::ensure!(
        matches!(deleted, Err(SdkError::NotFound { .. })),
        "getting deleted template {name} returned {deleted:?}; expected NotFound"
    );

    let sandbox_name = cx.name("tm");
    cx.track(&sandbox_name);
    let missing = cx.name("tx");
    let from_missing = cx
        .client()
        .create_sandbox_from_template(SandboxTemplateCreateSpec {
            name: Some(sandbox_name),
            template_name: missing.clone(),
            command: vec!["true".to_string()],
            ..SandboxTemplateCreateSpec::default()
        })
        .await;
    testkit::ensure!(
        matches!(from_missing, Err(SdkError::NotFound { .. })),
        "creating a sandbox from missing template {missing} returned {from_missing:?}; expected NotFound"
    );
    Ok(())
}
