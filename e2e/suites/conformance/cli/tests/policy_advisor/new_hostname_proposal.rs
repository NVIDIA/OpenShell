// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::draft_assertion::ExpectedDraft;
use super::helpers::{
    COMMAND_TIMEOUT, EMPTY_NETWORK_POLICY, await_mechanistic_draft, create_sandbox,
    sandbox_bash_path,
};
use openshell_e2e_support::OpenShellRunner;
use std::io::Write as _;
use tempfile::NamedTempFile;

/// Turn a denied TCP open to a hostname absent from policy into a scoped draft.
#[tokio::test]
async fn creates_a_scoped_draft_for_a_new_hostname() {
    let mut runner = OpenShellRunner::from_env("new-hostname-proposal")
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
    let name = format!("ct-{}-nh", runner.id());
    create_sandbox(runner, &name, Some(policy_path)).await?;
    let binary = sandbox_bash_path(runner, &name).await?;

    let probe = runner
        .step("denied-new-hostname")
        .description("Bash cannot connect to pypi.org:80 before approval")
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
            "if exec 3<>/dev/tcp/pypi.org/80; then echo UNEXPECTED_ALLOWED; exit 1; else echo DENIED; fi",
        ])
        .await
        .map_err(|error| error.to_string())?;
    probe.require_success()?;
    if !probe.stdout().lines().any(|line| line == "DENIED") {
        return Err(probe.failure_diagnostic("new hostname stays denied before approval"));
    }

    await_mechanistic_draft(
        runner,
        &name,
        &ExpectedDraft {
            rule: "allow_pypi_org_80",
            endpoint: "pypi.org:80",
            binary: &binary,
        },
        probe.stderr(),
    )
    .await
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("new-hostname-proposal conformance story failed:\n{error}");
    }
}
