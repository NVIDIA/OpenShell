// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Portable phase-1 CLI conformance scenario.

use std::time::{Duration, Instant};

use crate::{OpenShellRunner, STATUS_TIMEOUT, Scenario, ScenarioFuture};
use serde::Deserialize;
use tokio::time::sleep;

const CREATE_TIMEOUT: Duration = Duration::from_secs(600);
const LIST_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);
const LIST_PAGE_SIZE: u32 = 1_000;
const EXEC_TIMEOUT: Duration = Duration::from_secs(120);
const DELETE_TIMEOUT: Duration = Duration::from_secs(120);
const DELETE_POLL_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Deserialize)]
struct SandboxListEntry {
    name: String,
    phase: String,
}

/// Certify status -> create -> list Ready -> exec -> delete -> list empty.
pub const SMOKE_SCENARIO: Scenario = Scenario {
    name: "smoke",
    description: "Create, inspect, execute in, and delete a base sandbox.",
    run: run_smoke,
};

fn run_smoke(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move { run_smoke_inner(runner).await })
}

async fn run_smoke_inner(runner: &mut OpenShellRunner) -> Result<(), String> {
    let status = runner
        .step("status")
        .description("openshell status succeeds")
        .with_timeout(STATUS_TIMEOUT)
        .run(&["status"])
        .await
        .map_err(|error| error.to_string())?;
    status.require_success()?;

    let sandbox_name = format!("ct-{}-01", runner.id());
    runner.track_sandbox(&sandbox_name);
    let create = runner
        .step("create")
        .description("sandbox creation succeeds")
        .with_timeout(CREATE_TIMEOUT)
        .run(&[
            "sandbox",
            "create",
            "--name",
            &sandbox_name,
            "--from",
            "base",
            "--detach",
        ])
        .await
        .map_err(|error| error.to_string())?;
    create.require_success()?;

    let get = runner
        .step("get-ready")
        .description(format!("sandbox '{sandbox_name}' can be retrieved"))
        .with_timeout(LIST_ATTEMPT_TIMEOUT)
        .run(&["sandbox", "get", &sandbox_name, "--output", "json"])
        .await
        .map_err(|error| error.to_string())?;
    get.require_success()?;

    let sandbox = get
        .json::<SandboxListEntry>()
        .map_err(|error| error.to_string())?;
    if sandbox.name != sandbox_name {
        return Err(format!(
            "sandbox get returned {:?}; expected sandbox '{sandbox_name}'",
            sandbox.name
        ));
    }
    if sandbox.phase != "Ready" {
        return Err(format!(
            "sandbox '{sandbox_name}' is in phase {:?}; expected Ready",
            sandbox.phase
        ));
    }

    check_sandbox_listed(runner, &sandbox_name).await?;

    let marker = format!("openshell-conformance-{}", runner.id());
    let exec = runner
        .step("exec")
        .description("sandbox exec exits successfully")
        .with_timeout(EXEC_TIMEOUT)
        .run(&[
            "sandbox",
            "exec",
            "--name",
            &sandbox_name,
            "--no-tty",
            "--",
            "echo",
            &marker,
        ])
        .await
        .map_err(|error| error.to_string())?;
    exec.require_success()?;
    let expected_stdout = format!("{marker}\n");
    if exec.stdout() != expected_stdout {
        return Err(exec.failure_diagnostic(&format!("stdout is exactly {expected_stdout:?}")));
    }

    let delete = runner
        .step("delete")
        .description("sandbox deletion succeeds")
        .with_timeout(DELETE_TIMEOUT)
        .run(&["sandbox", "delete", &sandbox_name])
        .await
        .map_err(|error| error.to_string())?;
    delete.require_success()?;

    check_empty_list(runner, &sandbox_name).await?;
    runner.forget_sandbox(&sandbox_name);
    Ok(())
}

async fn check_sandbox_listed(runner: &OpenShellRunner, sandbox_name: &str) -> Result<(), String> {
    if find_sandbox(runner, sandbox_name, "list-visible")
        .await?
        .is_some()
    {
        return Ok(());
    }
    Err(format!(
        "sandbox '{sandbox_name}' does not appear in sandbox list"
    ))
}

async fn check_empty_list(runner: &OpenShellRunner, sandbox_name: &str) -> Result<(), String> {
    let started = Instant::now();

    loop {
        match find_sandbox(runner, sandbox_name, "list-empty/query").await? {
            None => return Ok(()),
            Some(sandbox) if started.elapsed() >= DELETE_TIMEOUT => {
                return Err(format!(
                    "sandbox '{sandbox_name}' remains listed in phase {:?} after {DELETE_TIMEOUT:.1?}",
                    sandbox.phase
                ));
            }
            Some(_) => sleep(DELETE_POLL_INTERVAL).await,
        }
    }
}

async fn find_sandbox(
    runner: &OpenShellRunner,
    sandbox_name: &str,
    step: &str,
) -> Result<Option<SandboxListEntry>, String> {
    let mut offset = 0u32;

    loop {
        let limit = LIST_PAGE_SIZE.to_string();
        let page_offset = offset.to_string();
        let result = runner
            .step(format!("{step}/{offset}"))
            .description(format!("sandbox list page at offset {offset} succeeds"))
            .with_timeout(LIST_ATTEMPT_TIMEOUT)
            .run(&[
                "sandbox",
                "list",
                "--limit",
                &limit,
                "--offset",
                &page_offset,
                "--output",
                "json",
            ])
            .await
            .map_err(|error| error.to_string())?;
        result.require_success()?;

        let sandboxes = result
            .json::<Vec<SandboxListEntry>>()
            .map_err(|error| error.to_string())?;
        if let Some(sandbox) = sandboxes
            .iter()
            .find(|sandbox| sandbox.name == sandbox_name)
        {
            return Ok(Some(SandboxListEntry {
                name: sandbox.name.clone(),
                phase: sandbox.phase.clone(),
            }));
        }
        if sandboxes.len() < LIST_PAGE_SIZE as usize {
            return Ok(None);
        }

        offset = offset
            .checked_add(LIST_PAGE_SIZE)
            .ok_or_else(|| "sandbox list pagination offset overflowed".to_string())?;
    }
}
