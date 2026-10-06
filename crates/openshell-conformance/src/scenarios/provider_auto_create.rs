// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Portable provider auto-creation conformance scenario.

use std::time::Duration;

use crate::{CommandResult, OpenShellRunner, Scenario, ScenarioFuture};

const CREATE_TIMEOUT: Duration = Duration::from_mins(10);
const COMMAND_TIMEOUT: Duration = Duration::from_mins(2);

// "claude-code" is a recognized auto-provider type, not an arbitrary name:
// the CLI names the auto-created provider after the `--provider` value, so
// this scenario cannot scope it per run like other tracked resources.
const PROVIDER_NAME: &str = "claude-code";
const CREDENTIAL_ENV_VAR: &str = "ANTHROPIC_API_KEY";
const TEST_API_KEY: &str = "sk-e2e-auto-provider-test-key";

/// Certify that `--provider claude-code --auto-providers` discovers a local
/// credential, auto-creates the provider, and injects a redacted placeholder
/// into the sandbox environment rather than the raw secret.
pub const PROVIDER_AUTO_CREATE_SCENARIO: Scenario = Scenario {
    name: "provider-auto-create",
    description: "Verify --provider auto-creation injects a redacted credential placeholder.",
    run: run_provider_auto_create,
};

fn run_provider_auto_create(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move {
        if provider_exists(runner).await? {
            eprintln!(
                "skipping provider-auto-create: existing provider '{PROVIDER_NAME}' would make shared state unsafe"
            );
            return Ok(());
        }

        // Defensive cleanup of any leftover from a previous crashed run.
        delete_provider(runner).await;

        let sandbox_name = format!("ct-{}-pa", runner.id());
        runner.track_sandbox(&sandbox_name);
        runner.track_provider(PROVIDER_NAME);
        auto_created_provider_credential_available_in_sandbox(runner, &sandbox_name).await
    })
}

async fn provider_exists(runner: &OpenShellRunner) -> Result<bool, String> {
    let result = runner
        .step("preflight/provider-get")
        .description(format!(
            "check whether provider '{PROVIDER_NAME}' already exists"
        ))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["provider", "get", PROVIDER_NAME])
        .await
        .map_err(|error| error.to_string())?;
    Ok(result.success())
}

async fn delete_provider(runner: &OpenShellRunner) {
    let _ = runner
        .step("preflight/provider-delete")
        .description(format!(
            "provider '{PROVIDER_NAME}' is deleted or already absent"
        ))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["provider", "delete", PROVIDER_NAME])
        .await;
}

async fn auto_created_provider_credential_available_in_sandbox(
    runner: &OpenShellRunner,
    sandbox_name: &str,
) -> Result<(), String> {
    let create = runner
        .step("create")
        .description(format!(
            "sandbox '{sandbox_name}' is created with provider auto-creation"
        ))
        .with_timeout(CREATE_TIMEOUT)
        .run_with_env(
            &[
                "sandbox",
                "create",
                "--name",
                sandbox_name,
                "--detach",
                "--provider",
                PROVIDER_NAME,
                "--auto-providers",
                "--",
                "sh",
                "-c",
                "exec sleep infinity",
            ],
            &[(CREDENTIAL_ENV_VAR, TEST_API_KEY)],
        )
        .await
        .map_err(|error| error.to_string())?;
    create.require_success()?;
    if !output_contains(&create, "Created provider claude-code") {
        return Err(create.failure_diagnostic("output confirms provider auto-creation"));
    }

    let exec = runner
        .step("exec")
        .description(format!(
            "sandbox '{sandbox_name}' exec reads the injected credential placeholder"
        ))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&[
            "sandbox",
            "exec",
            "--name",
            sandbox_name,
            "--no-tty",
            "--",
            "printenv",
            CREDENTIAL_ENV_VAR,
        ])
        .await
        .map_err(|error| error.to_string())?;
    exec.require_success()?;

    if !contains_placeholder_for_env_key(exec.stdout(), CREDENTIAL_ENV_VAR)
        && !contains_placeholder_for_env_key(exec.stderr(), CREDENTIAL_ENV_VAR)
    {
        return Err(exec.failure_diagnostic(&format!(
            "sandbox environment contains a resolve placeholder for {CREDENTIAL_ENV_VAR}"
        )));
    }
    if output_contains(&exec, TEST_API_KEY) {
        return Err(exec.failure_diagnostic(&format!(
            "sandbox environment does not expose the raw {CREDENTIAL_ENV_VAR} secret"
        )));
    }

    Ok(())
}

fn output_contains(result: &CommandResult, needle: &str) -> bool {
    result.stdout().contains(needle) || result.stderr().contains(needle)
}

/// Matches the supervisor's credential-resolution placeholder token, which is
/// either the legacy fixed form or a versioned `openshell:resolve:env:v<N>_<KEY>`.
fn contains_placeholder_for_env_key(output: &str, key: &str) -> bool {
    let legacy = format!("openshell:resolve:env:{key}");
    let revision_prefix = "openshell:resolve:env:v";
    let revision_suffix = format!("_{key}");
    output.split_whitespace().any(|token| {
        token == legacy || (token.starts_with(revision_prefix) && token.ends_with(&revision_suffix))
    })
}
