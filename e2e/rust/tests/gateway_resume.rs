// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E coverage for resuming Docker sandboxes after a standalone gateway restart.
//!
//! This intentionally targets the Docker-driver gateway started by
//! `e2e/with-docker-gateway.sh`. Existing-endpoint E2E runs do not own the
//! gateway process, so they skip this restart-only coverage.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::gateway::ManagedGateway;
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tokio::time::sleep;

const MANAGED_BY_LABEL_FILTER: &str = "label=openshell.ai/managed-by=openshell";
const READY_MARKER: &str = "gateway-resume-ready";
const SANDBOX_NAMESPACE_LABEL: &str = "openshell.ai/sandbox-namespace";
const SANDBOX_NAME_LABEL: &str = "openshell.ai/sandbox-name";

async fn run_cli(args: &[&str]) -> (String, i32) {
    let mut cmd = openshell_cmd();
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd.output().await.expect("spawn openshell");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    let code = output.status.code().unwrap_or(-1);
    (combined, code)
}

async fn wait_for_healthy(timeout: Duration) -> Result<(), String> {
    let start = Instant::now();
    let mut last_output: String;

    loop {
        let (output, code) = run_cli(&["status"]).await;
        let clean = strip_ansi(&output);
        let lower = clean.to_lowercase();
        if code == 0
            && (lower.contains("healthy")
                || lower.contains("running")
                || lower.contains("connected"))
        {
            return Ok(());
        }
        last_output = clean;

        if start.elapsed() > timeout {
            return Err(format!(
                "gateway did not become healthy within {}s. Last output:\n{last_output}",
                timeout.as_secs()
            ));
        }
        sleep(Duration::from_secs(2)).await;
    }
}

async fn sandbox_names() -> Result<Vec<String>, String> {
    let (output, code) = run_cli(&["sandbox", "list", "--names"]).await;
    let clean = strip_ansi(&output);
    if code != 0 {
        return Err(format!("sandbox list failed (exit {code}):\n{clean}"));
    }

    Ok(clean
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

fn sandbox_container_id(namespace: &str, sandbox_name: &str) -> Result<String, String> {
    let namespace_filter = format!("label={SANDBOX_NAMESPACE_LABEL}={namespace}");
    let sandbox_name_filter = format!("label={SANDBOX_NAME_LABEL}={sandbox_name}");
    let output = Command::new("docker")
        .args(["ps", "-aq", "--filter", MANAGED_BY_LABEL_FILTER, "--filter"])
        .arg(namespace_filter)
        .args(["--filter"])
        .arg(sandbox_name_filter)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|err| format!("failed to run docker ps: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    if !output.status.success() {
        return Err(format!(
            "docker ps failed (exit {:?}):\n{combined}",
            output.status.code()
        ));
    }

    let ids = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    match ids.as_slice() {
        [id] => Ok((*id).to_string()),
        [] => Err(format!(
            "no Docker container found for sandbox '{sandbox_name}' in namespace '{namespace}'"
        )),
        _ => Err(format!(
            "multiple Docker containers found for sandbox '{sandbox_name}' in namespace '{namespace}': {ids:?}"
        )),
    }
}

fn sandbox_container_running(namespace: &str, sandbox_name: &str) -> Result<bool, String> {
    let container_id = sandbox_container_id(namespace, sandbox_name)?;
    let output = Command::new("docker")
        .args(["inspect", "-f", "{{.State.Running}}", &container_id])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|err| format!("failed to run docker inspect: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    if !output.status.success() {
        return Err(format!(
            "docker inspect failed (exit {:?}):\n{combined}",
            output.status.code()
        ));
    }

    match stdout.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(format!(
            "unexpected Docker running state for container {container_id}: {other}"
        )),
    }
}

async fn wait_for_container_running(
    namespace: &str,
    sandbox_name: &str,
    expected: bool,
    timeout: Duration,
) -> Result<(), String> {
    let start = Instant::now();
    let mut last_state: String;

    loop {
        match sandbox_container_running(namespace, sandbox_name) {
            Ok(running) if running == expected => return Ok(()),
            Ok(running) => last_state = format!("running={running}"),
            Err(err) => last_state = err,
        }

        if start.elapsed() > timeout {
            return Err(format!(
                "sandbox container '{sandbox_name}' did not reach running={expected} within {}s. Last state: {last_state}",
                timeout.as_secs()
            ));
        }
        sleep(Duration::from_secs(1)).await;
    }
}

#[tokio::test]
async fn docker_gateway_restart_resumes_running_sandbox() {
    let Some(gateway) = ManagedGateway::from_env().expect("load managed e2e gateway metadata")
    else {
        eprintln!("Skipping gateway resume test: e2e gateway is not managed by this test run");
        return;
    };
    let Some(namespace) = std::env::var("OPENSHELL_E2E_DOCKER_NETWORK_NAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        eprintln!("Skipping gateway resume test: Docker e2e namespace is unavailable");
        return;
    };

    wait_for_healthy(Duration::from_secs(30))
        .await
        .expect("gateway should start healthy");

    let mut sandbox = SandboxGuard::create_keep(
        &[
            "sh",
            "-c",
            "echo gateway-resume-ready; while true; do sleep 1; done",
        ],
        READY_MARKER,
    )
    .await
    .expect("create long-running sandbox");

    wait_for_container_running(&namespace, &sandbox.name, true, Duration::from_secs(60))
        .await
        .expect("sandbox container should be running before gateway restart");

    gateway.stop().expect("stop e2e gateway");
    wait_for_container_running(&namespace, &sandbox.name, false, Duration::from_secs(120))
        .await
        .expect("gateway shutdown should stop managed Docker sandboxes");

    gateway.start().expect("restart e2e gateway");
    wait_for_healthy(Duration::from_secs(120))
        .await
        .expect("gateway should become healthy after restart");
    wait_for_container_running(&namespace, &sandbox.name, true, Duration::from_secs(120))
        .await
        .expect("gateway startup should resume the Docker sandbox container");

    let names = sandbox_names().await.expect("list sandboxes after restart");
    assert!(
        names.contains(&sandbox.name),
        "sandbox '{}' should still be listed after gateway restart. Names: {names:?}",
        sandbox.name
    );

    sandbox.cleanup().await;
}
