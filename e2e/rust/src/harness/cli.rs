// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared CLI helpers for e2e tests that need to invoke `openshell` commands
//! and poll for readiness.

use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::time::sleep;

use super::binary::openshell_cmd;
use super::output::strip_ansi;

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

pub async fn wait_for_sandbox_exec_contains(
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
