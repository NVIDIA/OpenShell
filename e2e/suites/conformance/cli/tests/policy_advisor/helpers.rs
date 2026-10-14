// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::draft_assertion::{ExpectedDraft, assert_mechanistic_draft};
use openshell_e2e_support::OpenShellRunner;
use serde::Deserialize;
use serde_json::Value;
use std::time::Duration;
use std::time::Instant;
use tokio::time::sleep;

pub const CREATE_TIMEOUT: Duration = Duration::from_mins(10);
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(45);
pub const READY_TIMEOUT: Duration = Duration::from_mins(4);
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);
pub const PROPOSAL_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Deserialize)]
pub struct SandboxState {
    pub name: String,
    pub phase: String,
}

pub const EMPTY_NETWORK_POLICY: &[u8] = br"version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /bin, /lib, /lib64, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]
landlock: { compatibility: best_effort }
network_policies: {}
";

pub async fn sandbox_bash_path(runner: &OpenShellRunner, name: &str) -> Result<String, String> {
    let result = runner
        .step("bash-binary")
        .description("the sandbox's Bash executable has a canonical path")
        .with_timeout(COMMAND_TIMEOUT)
        .run(&[
            "sandbox",
            "exec",
            "--name",
            name,
            "--no-tty",
            "--",
            "bash",
            "-c",
            "printf '%s\\n' \"$(readlink -f /proc/$$/exe)\"",
        ])
        .await
        .map_err(|error| error.to_string())?;
    result.require_success()?;
    let binary = result.stdout().trim();
    if !binary.starts_with('/')
        || binary.contains('\n')
        || binary.rsplit('/').next() != Some("bash")
    {
        return Err(result.failure_diagnostic("one absolute Bash executable path ending in /bash"));
    }
    Ok(binary.to_string())
}

pub async fn enable_proposals(runner: &OpenShellRunner, name: &str) -> Result<(), String> {
    let set = runner
        .step("enable-policy-advisor")
        .description("sandbox-scoped policy advisor setting is enabled")
        .with_timeout(COMMAND_TIMEOUT)
        .run(&[
            "settings",
            "set",
            name,
            "--key",
            "agent_policy_proposals_enabled",
            "--value",
            "true",
        ])
        .await
        .map_err(|error| error.to_string())?;
    set.require_success()?;

    let settings = runner
        .step("effective-settings")
        .description("policy advisor setting is effectively enabled")
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["settings", "get", name, "--json"])
        .await
        .map_err(|error| error.to_string())?;
    settings.require_success()?;
    let value: Value = settings.json().map_err(|error| error.to_string())?;
    if value["settings"]["agent_policy_proposals_enabled"]["value"] != "true" {
        return Err(settings.failure_diagnostic(
            "effective agent_policy_proposals_enabled is true; check for a global override",
        ));
    }
    Ok(())
}

pub async fn await_mechanistic_draft(
    runner: &OpenShellRunner,
    sandbox: &str,
    expected: &ExpectedDraft<'_>,
    probe_stderr: &str,
) -> Result<(), String> {
    let started = Instant::now();
    loop {
        let draft = runner
            .step("mechanistic-draft")
            .description("a single scoped mechanistic draft appears")
            .with_timeout(COMMAND_TIMEOUT)
            .run(&["rule", "get", sandbox])
            .await
            .map_err(|error| error.to_string())?;
        if !draft.success() {
            if started.elapsed() >= PROPOSAL_TIMEOUT {
                return Err(draft.failure_diagnostic("the reviewer inbox is readable"));
            }
            sleep(POLL_INTERVAL).await;
            continue;
        }
        if !draft.stdout().contains("Chunk:") {
            if started.elapsed() >= PROPOSAL_TIMEOUT {
                return Err(draft.failure_diagnostic(&format!(
                    "one mechanistic draft for {} and {}; probe stderr:\n{probe_stderr}",
                    expected.endpoint, expected.binary
                )));
            }
            sleep(POLL_INTERVAL).await;
            continue;
        }
        return assert_mechanistic_draft(draft.stdout(), expected)
            .map_err(|error| draft.failure_diagnostic(&error));
    }
}

pub async fn create_sandbox(
    runner: &mut OpenShellRunner,
    name: &str,
    policy_path: Option<&str>,
) -> Result<(), String> {
    runner.track_sandbox(name);
    let mut args = vec![
        "sandbox",
        "create",
        "--name",
        name,
        "--detach",
        "--no-tty",
        "--no-auto-providers",
    ];
    if let Some(path) = policy_path {
        args.extend(["--policy", path]);
    }
    args.extend(["--", "sh", "-c", "exec sleep infinity"]);
    let create = runner
        .step("create")
        .description(format!("sandbox '{name}' is created"))
        .with_timeout(CREATE_TIMEOUT)
        .run(&args)
        .await
        .map_err(|error| error.to_string())?;
    create.require_success()?;

    let started = Instant::now();
    loop {
        let get = runner
            .step("ready")
            .description(format!("sandbox '{name}' reaches Ready"))
            .with_timeout(COMMAND_TIMEOUT)
            .run(&["sandbox", "get", name, "--output", "json"])
            .await
            .map_err(|error| error.to_string())?;
        if get.success() {
            let state: SandboxState = get.json().map_err(|error| error.to_string())?;
            if state.name != name {
                return Err(get.failure_diagnostic("sandbox get returns the created name"));
            }
            if state.phase == "Ready" {
                return Ok(());
            }
            if state.phase == "Failed" {
                return Err(get.failure_diagnostic("sandbox reaches Ready instead of Failed"));
            }
        }
        if started.elapsed() >= READY_TIMEOUT {
            return Err(get.failure_diagnostic("sandbox reaches Ready before timeout"));
        }
        sleep(POLL_INTERVAL).await;
    }
}
