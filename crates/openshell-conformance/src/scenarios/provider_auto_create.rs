// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Portable provider auto-creation conformance scenario.

use std::fs;
use std::time::Duration;

use crate::{OpenShellRunner, Poll, Scenario, ScenarioFuture};

// Avoid inheriting the default image's network rules, which may be
// incompatible with the attached credential provider's startup validation.
// This test only reads the injected environment placeholder.
const TEST_POLICY: &str = r"version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /etc, /proc]
  read_write: [/sandbox, /tmp, /dev/null]
landlock:
  compatibility: best_effort
network_policies: {}
";

const CREATE_TIMEOUT: Duration = Duration::from_mins(10);
const COMMAND_TIMEOUT: Duration = Duration::from_mins(2);
// Must comfortably exceed COMMAND_TIMEOUT: poll_until only checks elapsed
// time between attempts, so a single slow attempt must not be able to
// consume the whole retry budget before a second attempt gets a chance.
const PROVIDER_DETACH_TIMEOUT: Duration = Duration::from_mins(3);
const PROVIDER_DETACH_INTERVAL: Duration = Duration::from_secs(1);

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
        delete_provider_best_effort(runner).await;

        let sandbox_name = format!("ct-{}-pa", runner.id());
        // Tracked as a safety net for runner.finish()'s generic sweep (and the
        // Drop-impl warning) if a panic skips the explicit cleanup() below;
        // the ordered, poll-retried delete in cleanup() is what actually
        // avoids the sandbox/provider detach race in the common case.
        runner.track_sandbox(&sandbox_name);
        let result =
            auto_created_provider_credential_available_in_sandbox(runner, &sandbox_name).await;
        cleanup(runner, &sandbox_name).await;
        runner.forget_sandbox(&sandbox_name);
        result
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

async fn delete_provider_best_effort(runner: &OpenShellRunner) {
    let _ = runner
        .step("preflight/provider-delete")
        .description(format!(
            "provider '{PROVIDER_NAME}' is deleted or already absent"
        ))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["provider", "delete", PROVIDER_NAME])
        .await;
}

/// Best-effort teardown. Deletes the sandbox first, then polls the provider
/// delete: the gateway can briefly still report the provider as attached to
/// the just-deleted sandbox, since sandbox deletion isn't synchronous with
/// detaching its providers.
async fn cleanup(runner: &mut OpenShellRunner, sandbox_name: &str) {
    let _ = runner
        .step("cleanup/sandbox-delete")
        .description(format!(
            "sandbox '{sandbox_name}' is deleted or already absent"
        ))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["sandbox", "delete", sandbox_name])
        .await;

    let _ = runner
        .poll_until(
            "cleanup/provider-delete",
            PROVIDER_DETACH_TIMEOUT,
            PROVIDER_DETACH_INTERVAL,
            async move |runner| {
                let result = runner
                    .step("cleanup/provider-delete/attempt")
                    .description(format!(
                        "provider '{PROVIDER_NAME}' is deleted or already absent"
                    ))
                    .with_timeout(COMMAND_TIMEOUT)
                    .run(&["provider", "delete", PROVIDER_NAME])
                    .await;
                match result {
                    Ok(result) if result.success() => Poll::Ready(()),
                    Ok(result) => {
                        Poll::Pending(result.failure_diagnostic("provider delete succeeds"))
                    }
                    Err(error) => Poll::Pending(error.to_string()),
                }
            },
        )
        .await;
}

async fn auto_created_provider_credential_available_in_sandbox(
    runner: &OpenShellRunner,
    sandbox_name: &str,
) -> Result<(), String> {
    let policy = tempfile::NamedTempFile::new()
        .map_err(|error| format!("create provider test policy: {error}"))?;
    fs::write(policy.path(), TEST_POLICY)
        .map_err(|error| format!("write provider test policy: {error}"))?;
    let policy_path = policy
        .path()
        .to_str()
        .ok_or_else(|| "provider test policy path is not UTF-8".to_string())?;

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
                "--policy",
                policy_path,
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
    if !create.output_contains(&format!("Created provider {PROVIDER_NAME}")) {
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
    if exec.output_contains(TEST_API_KEY) {
        return Err(exec.failure_diagnostic(&format!(
            "sandbox environment does not expose the raw {CREDENTIAL_ENV_VAR} secret"
        )));
    }

    Ok(())
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
