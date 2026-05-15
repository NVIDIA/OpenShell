// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-vm")]

//! VM-specific E2E coverage for resuming sandboxes after a standalone gateway
//! restart.
//!
//! This test is gated behind the `e2e-vm` feature because it requires the VM
//! driver runtime prepared by `e2e/rust/e2e-vm.sh`.

use std::process::Stdio;
use std::time::{Duration, Instant};

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::gateway::ManagedGateway;
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tokio::time::sleep;

const READY_MARKER: &str = "vm-gateway-resume-ready";
const RESUME_FILE: &str = "/sandbox/vm-gateway-resume-state";

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

async fn wait_for_sandbox_exec_contains(
    sandbox_name: &str,
    command: &[&str],
    expected: &str,
    timeout: Duration,
) -> Result<(), String> {
    let start = Instant::now();
    let mut last_output: String;

    loop {
        let mut cmd = openshell_cmd();
        cmd.args(["sandbox", "exec", "--name", sandbox_name, "--no-tty", "--"])
            .args(command)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        match cmd.output().await {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                last_output = strip_ansi(&format!("{stdout}{stderr}"));
                if output.status.success() && last_output.contains(expected) {
                    return Ok(());
                }
            }
            Err(err) => {
                last_output = format!("failed to spawn openshell sandbox exec: {err}");
            }
        }

        if start.elapsed() > timeout {
            return Err(format!(
                "sandbox '{sandbox_name}' exec did not produce '{expected}' within {}s. Last output:\n{last_output}",
                timeout.as_secs()
            ));
        }
        sleep(Duration::from_secs(2)).await;
    }
}

#[tokio::test]
async fn vm_gateway_restart_resumes_running_sandbox() {
    if std::env::var("OPENSHELL_E2E_DRIVER").as_deref() != Ok("vm") {
        eprintln!("Skipping VM gateway resume test: e2e driver is not vm");
        return;
    }
    let Some(gateway) = ManagedGateway::from_env().expect("load managed e2e gateway metadata")
    else {
        eprintln!("Skipping VM gateway resume test: e2e gateway is not managed by this test run");
        return;
    };

    wait_for_healthy(Duration::from_secs(30))
        .await
        .expect("gateway should start healthy");

    let script = format!(
        "echo before-restart > {RESUME_FILE}; echo {READY_MARKER}; while true; do sleep 1; done"
    );
    let mut sandbox = SandboxGuard::create_keep(
        &["sh", "-lc", &script],
        READY_MARKER,
    )
    .await
    .expect("create long-running VM sandbox");

    let before_restart = sandbox
        .exec(&["cat", RESUME_FILE])
        .await
        .expect("read VM sandbox state before restart");
    assert!(
        before_restart.contains("before-restart"),
        "VM sandbox state was not written before restart:\n{before_restart}"
    );

    gateway.stop().expect("stop e2e gateway");
    gateway.start().expect("restart e2e gateway");
    wait_for_healthy(Duration::from_secs(120))
        .await
        .expect("gateway should become healthy after restart");

    let names = sandbox_names().await.expect("list sandboxes after restart");
    assert!(
        names.contains(&sandbox.name),
        "sandbox '{}' should still be listed after gateway restart. Names: {names:?}",
        sandbox.name
    );

    wait_for_sandbox_exec_contains(
        &sandbox.name,
        &["cat", RESUME_FILE],
        "before-restart",
        Duration::from_secs(240),
    )
    .await
    .expect("VM sandbox should become ready again with its overlay state preserved");

    sandbox.cleanup().await;
}
