// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-podman")]

//! Podman-specific E2E coverage for stopping and starting sandboxes across a
//! standalone gateway restart.

use std::process::{Command, Stdio};
use std::time::Duration;

use openshell_e2e::harness::cli::{
    run_cli, sandbox_names, wait_for_healthy, wait_for_sandbox_exec_contains,
    wait_for_sandbox_phase,
};
use openshell_e2e::harness::gateway::ManagedGateway;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tokio::time::sleep;

const READY_MARKER: &str = "podman-gateway-start-ready";
const STOPPED_READY_MARKER: &str = "podman-gateway-start-stopped-ready";
const START_FILE: &str = "/sandbox/podman-gateway-start-state";
const MANAGED_BY_LABEL_FILTER: &str = "label=openshell.managed=true";
const SANDBOX_NAME_LABEL: &str = "openshell.ai/sandbox-name";

/// Build a `podman` command that targets the same API socket the gateway uses.
///
/// The e2e harness (`e2e/with-podman-gateway.sh`) exports
/// `OPENSHELL_PODMAN_SOCKET` (discovered via `podman machine inspect` on macOS,
/// or the rootless socket on Linux) and also clobbers `XDG_CONFIG_HOME` with an
/// empty directory to isolate CLI/SDK gateway metadata. On macOS the podman
/// client resolves its VM connection through `XDG_CONFIG_HOME`, so a bare
/// `podman ps` here falls back to a nonexistent native rootless socket and
/// fails. Pinning `--url` to the exported socket bypasses connection-config
/// resolution entirely and mirrors the shell's `podman_cmd` helper.
///
/// When `OPENSHELL_PODMAN_SOCKET` is unset (e.g. running this test outside the
/// harness), fall back to plain `podman`, leaving Linux behavior unchanged.
fn podman_command() -> Command {
    let mut command = Command::new("podman");
    if let Ok(socket) = std::env::var("OPENSHELL_PODMAN_SOCKET") {
        if !socket.is_empty() {
            command.arg("--url").arg(format!("unix://{socket}"));
        }
    }
    command
}

fn sandbox_container_running(sandbox_name: &str) -> Result<bool, String> {
    let sandbox_name_filter = format!("label={SANDBOX_NAME_LABEL}={sandbox_name}");
    let output = podman_command()
        .args(["ps", "-aq", "--filter", MANAGED_BY_LABEL_FILTER, "--filter"])
        .arg(sandbox_name_filter)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|err| format!("failed to run podman ps: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "podman ps failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let ids = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    let [container_id] = ids.as_slice() else {
        return Err(format!(
            "expected one Podman container for sandbox '{sandbox_name}', found {ids:?}"
        ));
    };
    let output = podman_command()
        .args(["inspect", "-f", "{{.State.Running}}", container_id])
        .output()
        .map_err(|err| format!("failed to run podman inspect: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "podman inspect failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    match String::from_utf8_lossy(&output.stdout).trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        state => Err(format!("unexpected Podman running state: {state}")),
    }
}

async fn wait_for_container_running(
    sandbox_name: &str,
    expected: bool,
    timeout: Duration,
) -> Result<(), String> {
    let start = std::time::Instant::now();
    let mut last_state;
    loop {
        match sandbox_container_running(sandbox_name) {
            Ok(running) if running == expected => return Ok(()),
            Ok(running) => last_state = format!("running={running}"),
            Err(err) => last_state = err,
        }
        if start.elapsed() > timeout {
            return Err(format!(
                "Podman container for '{sandbox_name}' did not reach running={expected}: {last_state}"
            ));
        }
        sleep(Duration::from_secs(1)).await;
    }
}

#[tokio::test]
async fn podman_gateway_restart_preserves_running_and_stopped_intent() {
    if std::env::var("OPENSHELL_E2E_DRIVER").as_deref() != Ok("podman") {
        eprintln!("Skipping Podman gateway start test: e2e driver is not podman");
        return;
    }
    let Some(gateway) = ManagedGateway::from_env().expect("load managed e2e gateway metadata")
    else {
        eprintln!(
            "Skipping Podman gateway start test: e2e gateway is not managed by this test run"
        );
        return;
    };

    wait_for_healthy(Duration::from_secs(30))
        .await
        .expect("gateway should start healthy");

    let script = format!(
        "echo before-restart > {START_FILE}; echo {READY_MARKER}; while true; do sleep 1; done"
    );
    let mut sandbox = SandboxGuard::create_keep(&["sh", "-lc", &script], READY_MARKER)
        .await
        .expect("create long-running Podman sandbox");
    wait_for_container_running(&sandbox.name, true, Duration::from_secs(60))
        .await
        .expect("Podman sandbox container should initially be running");

    let before_restart = sandbox
        .exec(&["cat", START_FILE])
        .await
        .expect("read Podman sandbox state before restart");
    assert!(
        before_restart.contains("before-restart"),
        "sandbox state was not written before restart:\n{before_restart}"
    );

    let stopped_script = format!("echo {STOPPED_READY_MARKER}; while true; do sleep 1; done");
    let mut stopped_sandbox =
        SandboxGuard::create_keep(&["sh", "-lc", &stopped_script], STOPPED_READY_MARKER)
            .await
            .expect("create Podman sandbox that will remain stopped");
    let (stop_output, stop_code) = run_cli(&["sandbox", "stop", &stopped_sandbox.name]).await;
    assert_eq!(stop_code, 0, "sandbox stop should succeed:\n{stop_output}");
    wait_for_sandbox_phase(&stopped_sandbox.name, "Stopped", Duration::from_secs(120))
        .await
        .expect("Podman sandbox should be stopped before gateway restart");

    gateway.stop().expect("stop e2e gateway");
    wait_for_container_running(&sandbox.name, false, Duration::from_secs(60))
        .await
        .expect("gateway shutdown should stop the running-intent Podman sandbox");
    gateway.start().expect("restart e2e gateway");
    wait_for_healthy(Duration::from_secs(120))
        .await
        .expect("gateway should become healthy after restart");
    wait_for_container_running(&sandbox.name, true, Duration::from_secs(120))
        .await
        .expect("gateway startup should restart the running-intent Podman sandbox");

    let names = sandbox_names().await.expect("list sandboxes after restart");
    assert!(
        names.contains(&sandbox.name),
        "sandbox '{}' should still be listed after gateway restart. Names: {names:?}",
        sandbox.name
    );
    wait_for_sandbox_phase(&stopped_sandbox.name, "Stopped", Duration::from_secs(120))
        .await
        .expect("explicitly stopped Podman sandbox should remain stopped after restart");

    wait_for_sandbox_exec_contains(
        &sandbox.name,
        &["cat", START_FILE],
        "before-restart",
        Duration::from_secs(240),
    )
    .await
    .expect("Podman sandbox should become ready again with its state preserved");

    sandbox.cleanup().await;
    stopped_sandbox.cleanup().await;
}
