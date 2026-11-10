// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Detached ephemeral lifecycle coverage shared by supervisor-based drivers.

#![cfg(feature = "e2e")]

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use openshell_e2e::harness::binary::{openshell_bin, openshell_cmd};
use openshell_e2e::harness::cli::run_cli;
use openshell_e2e::harness::container::{ContainerEngine, e2e_driver};
use openshell_e2e::harness::sandbox::{E2E_WORKLOAD_IMAGE, unique_sandbox_name};
use serial_test::serial;
use tokio::time::{Instant, sleep};

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(90);

struct DeleteOnFailure {
    name: String,
    armed: bool,
}

impl Drop for DeleteOnFailure {
    fn drop(&mut self) {
        if self.armed {
            let _ = Command::new(openshell_bin())
                .args(["sandbox", "delete", &self.name])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

fn command_output(mut command: Command) -> Result<String, String> {
    let output = command
        .output()
        .map_err(|error| format!("run driver resource query: {error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        return Err(format!(
            "driver resource query failed ({}): {stdout}{stderr}",
            output.status
        ));
    }
    Ok(stdout.trim().to_string())
}

fn driver_resources_present(sandbox_id: &str) -> Result<bool, String> {
    match e2e_driver().as_deref() {
        Some("docker" | "podman") => {
            let engine = ContainerEngine::from_env()?;
            let mut command = engine.command();
            command.args([
                "ps",
                "-aq",
                "--filter",
                &format!("label=openshell.ai/sandbox-id={sandbox_id}"),
            ]);
            Ok(!command_output(command)?.is_empty())
        }
        Some("kubernetes") => {
            let mut command = Command::new("kubectl");
            command.args([
                "get",
                "pods,sandboxes.agents.x-k8s.io",
                "--all-namespaces",
                "--selector",
                &format!("openshell.ai/sandbox-id={sandbox_id}"),
                "--output=name",
            ]);
            Ok(!command_output(command)?.is_empty())
        }
        Some("vm") => {
            let state_dir = std::env::var_os("OPENSHELL_E2E_VM_STATE_DIR")
                .map(PathBuf::from)
                .ok_or("OPENSHELL_E2E_VM_STATE_DIR must be set for VM resource checks")?;
            Ok(state_dir.join("sandboxes").join(sandbox_id).exists())
        }
        other => Err(format!(
            "unsupported e2e driver for ephemeral cleanup: {other:?}"
        )),
    }
}

async fn run_detached_ephemeral_cleanup(exit_code: i32) -> Result<(), String> {
    let name = unique_sandbox_name();
    let mut cleanup = DeleteOnFailure {
        name: name.clone(),
        armed: true,
    };
    let release_path = format!("/sandbox/.ephemeral-release-{name}");
    let script =
        format!("while [ ! -e '{release_path}' ]; do sleep 0.1; done; sleep 1; exit {exit_code}");
    let mut create = openshell_cmd();
    create.args([
        "sandbox",
        "create",
        "--name",
        &name,
        "--from",
        E2E_WORKLOAD_IMAGE,
        "--no-keep",
        "--detach",
        "--",
        "sh",
        "-c",
        &script,
    ]);
    let created = create
        .output()
        .await
        .map_err(|error| format!("create detached ephemeral sandbox: {error}"))?;
    if !created.status.success() {
        return Err(format!(
            "create detached ephemeral sandbox failed ({}): {}{}",
            created.status,
            String::from_utf8_lossy(&created.stdout),
            String::from_utf8_lossy(&created.stderr)
        ));
    }

    let (details, get_code) = run_cli(&["sandbox", "get", &name, "--output", "json"]).await;
    if get_code != 0 {
        return Err(format!("get detached sandbox failed: {details}"));
    }
    let details: serde_json::Value =
        serde_json::from_str(&details).map_err(|error| format!("parse sandbox JSON: {error}"))?;
    let sandbox_id = details["id"]
        .as_str()
        .ok_or_else(|| format!("sandbox has no id: {details}"))?;
    if !driver_resources_present(sandbox_id)? {
        return Err(format!(
            "driver resources were never observed for sandbox {name} ({sandbox_id})"
        ));
    }

    let (release, release_code) = run_cli(&[
        "sandbox",
        "exec",
        "--name",
        &name,
        "--no-tty",
        "--no-login-shell",
        "--",
        "touch",
        &release_path,
    ])
    .await;
    if release_code != 0 {
        return Err(format!("release canonical process failed: {release}"));
    }

    let deadline = Instant::now() + CLEANUP_TIMEOUT;
    loop {
        let (names, list_code) = run_cli(&["sandbox", "list", "--names"]).await;
        if list_code != 0 {
            return Err(format!("list sandboxes failed: {names}"));
        }
        let record_present = names.lines().any(|line| line.trim() == name);
        let resources_present = driver_resources_present(sandbox_id)?;
        if !record_present && !resources_present {
            cleanup.armed = false;
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "ephemeral sandbox {name} ({sandbox_id}) remained after {CLEANUP_TIMEOUT:?}: record_present={record_present}, resources_present={resources_present}"
            ));
        }
        sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test]
#[serial(ephemeral_cleanup)]
async fn detached_ephemeral_success_removes_sandbox_and_driver_resources() {
    run_detached_ephemeral_cleanup(0).await.unwrap();
}

#[tokio::test]
#[serial(ephemeral_cleanup)]
async fn detached_ephemeral_failure_removes_sandbox_and_driver_resources() {
    run_detached_ephemeral_cleanup(17).await.unwrap();
}
