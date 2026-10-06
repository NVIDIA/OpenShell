// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::draft_assertion::ExpectedDraft;
use super::helpers::{
    COMMAND_TIMEOUT, EMPTY_NETWORK_POLICY, await_mechanistic_draft, create_sandbox,
    enable_proposals,
};
use openshell_e2e_support::OpenShellRunner;
use serde_json::Value;
use std::io::Write as _;
use tempfile::NamedTempFile;

/// Turn a denied transparent TCP open into a scoped policy draft.
#[tokio::test]
async fn creates_a_scoped_draft_for_a_denied_endpoint() {
    let mut runner = OpenShellRunner::from_env("mechanistic-proposal")
        .expect("candidate openshell CLI is available");
    let result = async {
        runner.check_gateway_status().await?;
        let runner = &mut runner;
    let mut policy = NamedTempFile::new().map_err(|error| error.to_string())?;
    policy
        .write_all(EMPTY_NETWORK_POLICY)
        .map_err(|error| error.to_string())?;
    let policy_path = policy
        .path()
        .to_str()
        .ok_or("temporary policy path is not UTF-8")?;
    let name = format!("ct-{}-mp", runner.id());
    create_sandbox(runner, &name, Some(policy_path)).await?;
    enable_proposals(runner, &name).await?;

    let effective = runner
        .step("effective-policy")
        .description("sandbox has no network allow rules before the probe")
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["policy", "get", &name, "--full", "--output", "json"])
        .await
        .map_err(|error| error.to_string())?;
    effective.require_success()?;
    let value: Value = effective.json().map_err(|error| error.to_string())?;
    let network_rules = &value["policy"]["network_policies"];
    if !network_rules.is_null()
        && !network_rules
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
    {
        return Err(effective.failure_diagnostic("effective network_policies is empty"));
    }

    let probe = runner
        .step("denied-tcp-open")
        .description("one Bash TCP open to 1.1.1.1:443 is denied by policy")
        .with_timeout(COMMAND_TIMEOUT)
        .run(&[
            "sandbox",
            "exec",
            "--name",
            &name,
            "--no-tty",
            "--",
            "bash",
            "-c",
            "printf 'BINARY=%s\\n' \"$(readlink -f /proc/$$/exe)\"; if exec 3<>/dev/tcp/1.1.1.1/443; then echo UNEXPECTED_ALLOWED; exit 1; else echo DENIED; fi",
        ])
        .await
        .map_err(|error| error.to_string())?;
    probe.require_success()?;
    let binary = probe
        .stdout()
        .lines()
        .find_map(|line| line.strip_prefix("BINARY="))
        .filter(|binary| binary.starts_with('/') && binary.rsplit('/').next() == Some("bash"))
        .ok_or_else(|| probe.failure_diagnostic("canonical Bash executable path is reported"))?
        .to_string();
    if !probe.stdout().lines().any(|line| line == "DENIED") {
        return Err(probe.failure_diagnostic("TCP open is denied before any upstream dial"));
    }

    await_mechanistic_draft(
        runner,
        &name,
        &ExpectedDraft {
            rule: "allow_1_1_1_1_443",
            endpoint: "1.1.1.1:443",
            binary: &binary,
        },
        probe.stderr(),
    )
    .await
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("mechanistic-proposal conformance story failed:\n{error}");
    }
}
