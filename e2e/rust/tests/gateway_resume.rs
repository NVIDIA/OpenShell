// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E coverage for resuming Docker sandboxes after a standalone gateway restart.
//!
//! This intentionally targets the Docker-driver gateway started by
//! `e2e/with-docker-gateway.sh`. Existing-endpoint E2E runs do not own the
//! gateway process, so they skip this restart-only coverage.

use std::process::{Command, Stdio};
use std::time::Duration;

use openshell_e2e::harness::gateway::ManagedGateway;
use openshell_e2e::harness::resume::{GatewayResumeHooks, run_gateway_resume_scenario};
use tokio::time::sleep;

const MANAGED_BY_LABEL_FILTER: &str = "label=openshell.ai/managed-by=openshell";
const SANDBOX_NAMESPACE_LABEL: &str = "openshell.ai/sandbox-namespace";
const SANDBOX_NAME_LABEL: &str = "openshell.ai/sandbox-name";

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
    let start = std::time::Instant::now();
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

struct DockerResumeHooks<'a> {
    namespace: &'a str,
}

impl GatewayResumeHooks for DockerResumeHooks<'_> {
    async fn before_gateway_stop(&self, sandbox_name: &str) -> Result<(), String> {
        wait_for_container_running(self.namespace, sandbox_name, true, Duration::from_secs(60))
            .await
    }

    async fn after_gateway_stop(&self, sandbox_name: &str) -> Result<(), String> {
        wait_for_container_running(
            self.namespace,
            sandbox_name,
            false,
            Duration::from_secs(120),
        )
        .await
    }

    async fn after_gateway_start(&self, sandbox_name: &str) -> Result<(), String> {
        wait_for_container_running(self.namespace, sandbox_name, true, Duration::from_secs(120))
            .await
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

    run_gateway_resume_scenario(
        &gateway,
        "Docker",
        &DockerResumeHooks {
            namespace: &namespace,
        },
    )
    .await;
}
