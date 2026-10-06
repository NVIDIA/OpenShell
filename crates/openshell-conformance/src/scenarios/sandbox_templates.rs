// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Portable sandbox workload template conformance scenarios.

use std::time::Duration;

use serde_json::Value;

use crate::{
    CommandResult, OpenShellRunner, Scenario, ScenarioFuture, combine_results,
    output_reports_not_found,
};

const CREATE_TIMEOUT: Duration = Duration::from_mins(10);
const COMMAND_TIMEOUT: Duration = Duration::from_mins(2);

/// Certify reusable sandbox workload template behavior through the public CLI.
///
/// - **Behavior:** runs the four template scenarios below in sequence.
/// - **Preconditions:** a reachable gateway whose compute driver can create sandboxes from the default image (supplied by target preparation, not pulled from a public service by the test).
/// - **Permissions:** an identity allowed to create and delete sandbox templates and sandboxes.
/// - **Side effects:** each scenario creates the resources it names from the run id and removes them on success and on failure; a cleanup failure fails the scenario.
pub const SANDBOX_TEMPLATES_SCENARIO: Scenario = Scenario {
    name: "sandbox-templates",
    run: run_sandbox_templates,
};

/// Certify that a sandbox created from a template inherits its resources,
/// labels, and environment.
///
/// - **Behavior:** a template created with resource limits, a label, and an environment variable can be retrieved with those values and appears in the template list. A sandbox created from it carries the template's resources, labels, and environment.
/// - **Preconditions:** a reachable gateway whose compute driver can create sandboxes from the default image (supplied by target preparation, not pulled from a public service by the test).
/// - **Permissions:** an identity allowed to create and delete sandbox templates and sandboxes.
/// - **Side effects:** creates one template and one sandbox named from the run id. The sandbox is removed by the runner's tracked cleanup and the template by the scenario; a cleanup failure fails the scenario.
pub const SANDBOX_TEMPLATE_LIFECYCLE_SCENARIO: Scenario = Scenario {
    name: "sandbox-templates/lifecycle",
    run: run_lifecycle,
};

/// Certify that a deleted template is no longer fetchable.
///
/// - **Behavior:** after a template is deleted, retrieving it fails with a template-not-found error.
/// - **Preconditions:** a reachable gateway. No sandbox is created.
/// - **Permissions:** an identity allowed to create and delete sandbox templates and sandboxes.
/// - **Side effects:** creates one template named from the run id and removes it; a cleanup failure fails the scenario.
pub const SANDBOX_TEMPLATE_GET_AFTER_DELETE_SCENARIO: Scenario = Scenario {
    name: "sandbox-templates/get-after-delete",
    run: run_get_after_delete,
};

/// Certify that creating a template with a name already in use fails.
///
/// - **Behavior:** creating a second template with a name already in use is rejected.
/// - **Preconditions:** a reachable gateway. No sandbox is created.
/// - **Permissions:** an identity allowed to create and delete sandbox templates and sandboxes.
/// - **Side effects:** creates one template named from the run id and removes it; a cleanup failure fails the scenario.
pub const SANDBOX_TEMPLATE_DUPLICATE_NAME_SCENARIO: Scenario = Scenario {
    name: "sandbox-templates/duplicate-name",
    run: run_duplicate_name,
};

/// Certify that creating a sandbox from a nonexistent template fails.
///
/// - **Behavior:** creating a sandbox from a template that does not exist fails with a template-not-found error.
/// - **Preconditions:** a reachable gateway.
/// - **Permissions:** an identity allowed to create sandboxes.
/// - **Side effects:** the sandbox name is tracked so a sandbox that was unexpectedly created is removed; a cleanup failure fails the scenario.
pub const SANDBOX_TEMPLATE_MISSING_TEMPLATE_SCENARIO: Scenario = Scenario {
    name: "sandbox-templates/missing-template",
    run: run_missing_template,
};

fn run_sandbox_templates(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move {
        SANDBOX_TEMPLATE_LIFECYCLE_SCENARIO.run(runner).await?;
        SANDBOX_TEMPLATE_GET_AFTER_DELETE_SCENARIO
            .run(runner)
            .await?;
        SANDBOX_TEMPLATE_DUPLICATE_NAME_SCENARIO.run(runner).await?;
        SANDBOX_TEMPLATE_MISSING_TEMPLATE_SCENARIO.run(runner).await
    })
}

fn run_lifecycle(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move {
        let template_name = format!("ct-{}-tl", runner.id());
        let sandbox_name = format!("ct-{}-stl", runner.id());

        let result = lifecycle(runner, &template_name, &sandbox_name).await;
        let cleanup = cleanup_template(runner, &template_name).await;
        combine_results(result, cleanup)
    })
}

async fn lifecycle(
    runner: &mut OpenShellRunner,
    template_name: &str,
    sandbox_name: &str,
) -> Result<(), String> {
    runner
        .step("lifecycle/create")
        .description(format!("template '{template_name}' is created"))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&[
            "sandbox",
            "template",
            "create",
            template_name,
            "--cpu",
            "500m",
            "--memory",
            "512Mi",
            "--label",
            "e2e=sandbox-template",
            "--env",
            "FEATURE_FLAG=on",
        ])
        .await
        .map_err(|error| error.to_string())?
        .require_success()?;

    let get = runner
        .step("lifecycle/get")
        .description(format!("template '{template_name}' can be retrieved"))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&[
            "sandbox",
            "template",
            "get",
            template_name,
            "--output",
            "json",
        ])
        .await
        .map_err(|error| error.to_string())?;
    get.require_success()?;
    let template_json: Value = get.json().map_err(|error| error.to_string())?;
    require_eq(&template_json["name"], template_name, "template name")?;
    require_eq(
        &template_json["labels"]["e2e"],
        "sandbox-template",
        "template label e2e",
    )?;
    require_eq(
        &template_json["environment"]["FEATURE_FLAG"],
        "on",
        "template environment FEATURE_FLAG",
    )?;
    require_eq(&template_json["resources"]["cpu"], "500m", "template cpu")?;
    require_eq(
        &template_json["resources"]["memory"],
        "512Mi",
        "template memory",
    )?;

    let list = runner
        .step("lifecycle/list")
        .description("template list includes the created template")
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["sandbox", "template", "list", "--names"])
        .await
        .map_err(|error| error.to_string())?;
    list.require_success()?;
    if !list
        .stdout()
        .lines()
        .any(|line| line.trim() == template_name)
    {
        return Err(list.failure_diagnostic(&format!("template list includes '{template_name}'")));
    }

    runner.track_sandbox(sandbox_name);
    let create_sandbox = runner
        .step("lifecycle/sandbox-create")
        .description(format!(
            "sandbox '{sandbox_name}' is created from template '{template_name}'"
        ))
        .with_timeout(CREATE_TIMEOUT)
        .run(&[
            "sandbox",
            "create",
            "--name",
            sandbox_name,
            "--template",
            template_name,
            "--",
            "sh",
            "-lc",
            "test \"$FEATURE_FLAG\" = on && echo template-env-ok",
        ])
        .await
        .map_err(|error| error.to_string())?;
    create_sandbox.require_success()?;
    if !create_sandbox.output_contains_ignore_case("template-env-ok") {
        return Err(create_sandbox.failure_diagnostic("sandbox inherits template environment"));
    }

    runner
        .step("lifecycle/sandbox-delete")
        .description(format!("sandbox '{sandbox_name}' is deleted"))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["sandbox", "delete", sandbox_name])
        .await
        .map_err(|error| error.to_string())?
        .require_success()?;
    runner.forget_sandbox(sandbox_name);
    Ok(())
}

fn run_get_after_delete(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move {
        let template_name = format!("ct-{}-tgd", runner.id());
        let result = get_after_delete(runner, &template_name).await;
        let cleanup = cleanup_template(runner, &template_name).await;
        combine_results(result, cleanup)
    })
}

async fn get_after_delete(runner: &OpenShellRunner, template_name: &str) -> Result<(), String> {
    runner
        .step("get-after-delete/create")
        .description(format!("template '{template_name}' is created"))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["sandbox", "template", "create", template_name])
        .await
        .map_err(|error| error.to_string())?
        .require_success()?;

    runner
        .step("get-after-delete/delete")
        .description(format!("template '{template_name}' is deleted"))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["sandbox", "template", "delete", template_name])
        .await
        .map_err(|error| error.to_string())?
        .require_success()?;

    let get_deleted = runner
        .step("get-after-delete/get")
        .description(format!(
            "deleted template '{template_name}' is not fetchable"
        ))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["sandbox", "template", "get", template_name])
        .await
        .map_err(|error| error.to_string())?;
    if get_deleted.success() {
        return Err(get_deleted.failure_diagnostic("deleted template is not fetchable"));
    }
    if !output_mentions_template_not_found(&get_deleted) {
        return Err(get_deleted.failure_diagnostic("deleted template returns not-found"));
    }
    Ok(())
}

fn run_duplicate_name(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move {
        let template_name = format!("ct-{}-tdn", runner.id());
        let result = duplicate_name(runner, &template_name).await;
        let cleanup = cleanup_template(runner, &template_name).await;
        combine_results(result, cleanup)
    })
}

async fn duplicate_name(runner: &OpenShellRunner, template_name: &str) -> Result<(), String> {
    runner
        .step("duplicate-name/create")
        .description(format!("template '{template_name}' is created"))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["sandbox", "template", "create", template_name])
        .await
        .map_err(|error| error.to_string())?
        .require_success()?;

    let duplicate = runner
        .step("duplicate-name/duplicate")
        .description(format!(
            "duplicate template '{template_name}' creation is rejected"
        ))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["sandbox", "template", "create", template_name])
        .await
        .map_err(|error| error.to_string())?;
    if duplicate.success() {
        return Err(duplicate.failure_diagnostic("duplicate template creation is rejected"));
    }
    if !duplicate.output_contains_ignore_case("already exists") {
        return Err(duplicate.failure_diagnostic("duplicate template error reports already-exists"));
    }
    Ok(())
}

fn run_missing_template(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move {
        let template_name = format!("ct-{}-tmt", runner.id());
        let sandbox_name = format!("ct-{}-smt", runner.id());
        missing_template(runner, &template_name, &sandbox_name).await
    })
}

async fn missing_template(
    runner: &mut OpenShellRunner,
    template_name: &str,
    sandbox_name: &str,
) -> Result<(), String> {
    runner.track_sandbox(sandbox_name);
    let create_sandbox = runner
        .step("missing-template/create")
        .description(format!(
            "sandbox create from missing template '{template_name}' fails"
        ))
        .with_timeout(CREATE_TIMEOUT)
        .run(&[
            "sandbox",
            "create",
            "--name",
            sandbox_name,
            "--template",
            template_name,
            "--",
            "true",
        ])
        .await
        .map_err(|error| error.to_string())?;

    if create_sandbox.success() {
        return Err(create_sandbox.failure_diagnostic("sandbox create from missing template fails"));
    }
    runner.forget_sandbox(sandbox_name);
    if !output_mentions_template_not_found(&create_sandbox) {
        return Err(create_sandbox
            .failure_diagnostic("sandbox create from missing template reports not-found"));
    }
    Ok(())
}

/// Delete the scenario's template. A successful run has already removed it, so
/// "not found" is fine; any other failure is returned so the scenario fails
/// instead of leaking the template silently.
async fn cleanup_template(runner: &OpenShellRunner, template_name: &str) -> Result<(), String> {
    let expectation = format!("template '{template_name}' is deleted or already absent");
    match runner
        .step("cleanup/template-delete")
        .description(expectation.clone())
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["sandbox", "template", "delete", template_name])
        .await
    {
        Ok(result) if result.success() || output_reports_not_found(&result) => Ok(()),
        Ok(result) => Err(result.failure_diagnostic(&expectation)),
        Err(error) => Err(error.to_string()),
    }
}

fn output_mentions_template_not_found(result: &CommandResult) -> bool {
    result.output_contains_ignore_case("sandbox template")
        && result.output_contains_ignore_case("not found")
}

fn require_eq(actual: &Value, expected: &str, label: &str) -> Result<(), String> {
    if actual.as_str() == Some(expected) {
        Ok(())
    } else {
        Err(format!(
            "{label} mismatch: expected {expected:?}, got {actual:?}"
        ))
    }
}
