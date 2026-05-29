// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Docker-specific helpers for Docker-driver e2e tests.

use std::process::{Command, Stdio};
use std::time::Duration;

use tokio::time::sleep;

const MANAGED_BY_LABEL_FILTER: &str = "label=openshell.ai/managed-by=openshell";
const SANDBOX_NAMESPACE_LABEL: &str = "openshell.ai/sandbox-namespace";
const SANDBOX_NAME_LABEL: &str = "openshell.ai/sandbox-name";

/// Resolve the Docker container id for one `OpenShell` sandbox.
///
/// # Errors
///
/// Returns an error if Docker is unavailable, command output is ambiguous, or
/// no matching managed sandbox container exists.
pub fn sandbox_container_id(namespace: &str, sandbox_name: &str) -> Result<String, String> {
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

/// Return whether one managed Docker sandbox container is currently running.
///
/// # Errors
///
/// Returns an error if Docker cannot inspect the container or reports an
/// unexpected state value.
pub fn sandbox_container_running(namespace: &str, sandbox_name: &str) -> Result<bool, String> {
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

/// Wait for a Docker sandbox container to reach the expected running state.
///
/// # Errors
///
/// Returns the last observed Docker state/error if the timeout elapses.
pub async fn wait_for_container_running(
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
