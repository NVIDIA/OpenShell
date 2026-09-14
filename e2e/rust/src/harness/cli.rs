// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared CLI helpers for e2e tests that need to invoke `openshell` commands
//! and poll for readiness.

use std::future::Future;
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::time::sleep;

use super::binary::openshell_cmd;
use super::output::strip_ansi;

async fn poll_with_diagnostics<F, Fut>(timeout: Duration, mut attempt: F) -> Result<(), String>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = (bool, String)>,
{
    let start = Instant::now();
    loop {
        let (ready, last_output) = attempt().await;
        if ready {
            return Ok(());
        }
        if start.elapsed() > timeout {
            return Err(last_output);
        }
        sleep(Duration::from_secs(2)).await;
    }
}

pub async fn run_cli(args: &[&str]) -> (String, i32) {
    let mut cmd = openshell_cmd();
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd.output().await.expect("spawn openshell");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    let code = output.status.code().unwrap_or(-1);
    (combined, code)
}

pub async fn wait_for_healthy(timeout: Duration) -> Result<(), String> {
    poll_with_diagnostics(timeout, || async {
        let (output, code) = run_cli(&["status"]).await;
        let clean = strip_ansi(&output);
        let lower = clean.to_lowercase();
        let ready = code == 0
            && (lower.contains("healthy")
                || lower.contains("running")
                || lower.contains("connected"));
        (ready, clean)
    })
    .await
    .map_err(|last_output| {
        format!(
            "gateway did not become healthy within {}s. Last output:\n{last_output}",
            timeout.as_secs()
        )
    })
}

pub async fn sandbox_names() -> Result<Vec<String>, String> {
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

pub async fn wait_for_sandbox_phase(
    sandbox_name: &str,
    expected_phase: &str,
    timeout: Duration,
) -> Result<(), String> {
    poll_with_diagnostics(timeout, || async {
        let (output, code) = run_cli(&["sandbox", "get", sandbox_name, "--output", "json"]).await;
        let clean = strip_ansi(&output);
        let phase_matches = serde_json::from_str::<serde_json::Value>(&clean)
            .ok()
            .and_then(|value| {
                value
                    .get("phase")
                    .and_then(|phase| phase.as_str())
                    .map(str::to_owned)
            })
            .is_some_and(|phase| phase == expected_phase);
        (code == 0 && phase_matches, clean)
    })
    .await
    .map_err(|last_output| {
        format!(
            "sandbox '{sandbox_name}' did not reach phase '{expected_phase}' within {}s. Last output:\n{last_output}",
            timeout.as_secs()
        )
    })
}

pub async fn wait_for_sandbox_exec_contains(
    sandbox_name: &str,
    command: &[&str],
    expected: &str,
    timeout: Duration,
) -> Result<(), String> {
    poll_with_diagnostics(timeout, || async {
        let mut cmd = openshell_cmd();
        cmd.args(["sandbox", "exec", "--name", sandbox_name, "--no-tty", "--"])
            .args(command)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let (ready, last_output) = match cmd.output().await {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                let clean = strip_ansi(&format!("{stdout}{stderr}"));
                (output.status.success() && clean.contains(expected), clean)
            }
            Err(err) => (
                false,
                format!("failed to spawn openshell sandbox exec: {err}"),
            ),
        };
        (ready, last_output)
    })
    .await
    .map_err(|last_output| {
        format!(
            "sandbox '{sandbox_name}' exec did not produce '{expected}' within {}s. Last output:\n{last_output}",
            timeout.as_secs()
        )
    })
}
