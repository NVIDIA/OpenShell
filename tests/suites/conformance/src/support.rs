// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Helpers the network and policy suites share. Not a suite.
//!
//! Their clients are Python scripts in `src/scripts/` that take the server's
//! host and port as arguments, run in a long-running sandbox from
//! [`testkit::python_image`], and print their result as one JSON line.

use serde_json::Value;
use testkit::sdk::raw::proto;
use testkit::{Context, ExecOutput, PYTHON_BINARIES, Result, ResultExt as _, Sandbox};

/// The name sandboxes reach the test host's servers by.
pub const TEST_HOST: &str = "host.openshell.internal";

/// A long-running sandbox from the Python image with `policy`, Ready.
pub async fn python_sandbox(
    cx: &Context,
    suffix: &str,
    policy: proto::SandboxPolicy,
) -> Result<Sandbox> {
    cx.sandbox(suffix)
        .policy(policy)
        .image(testkit::python_image())
        .command(["sleep", "infinity"])
        .create_ready()
        .await
}

/// Run `script` with the image's Python and `args`, and fail unless it
/// exits 0.
pub async fn run_python(sandbox: &Sandbox, script: &str, args: &[&str]) -> Result<ExecOutput> {
    let mut command = vec!["python3", "-c", script];
    command.extend_from_slice(args);
    sandbox
        .exec(command)
        .await?
        .success()
        .context("run the client in the sandbox")
}

/// The last line of `output`'s stdout that parses as JSON.
pub fn json_result(output: &ExecOutput) -> Result<Value> {
    output
        .stdout
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str(line.trim()).ok())
        .ok_or_else(|| {
            testkit::Error::msg(format!(
                "no JSON result in the client's output:\n{}\n{}",
                output.stdout, output.stderr
            ))
        })
}

/// Fail unless each key in `expected` has its value in `result`.
pub fn expect_values<K: AsRef<str>>(result: &Value, expected: &[(K, Value)]) -> Result {
    let wrong: Vec<String> = expected
        .iter()
        .filter(|(key, value)| result[key.as_ref()] != *value)
        .map(|(key, value)| {
            let key = key.as_ref();
            format!("{key}: expected {value}, got {}", result[key])
        })
        .collect();
    testkit::ensure!(wrong.is_empty(), "{}\nresult: {result}", wrong.join("\n"));
    Ok(())
}

/// The sandbox's policy revisions, from `policy list --output json`.
pub async fn policy_revisions(cx: &Context, sandbox: &Sandbox) -> Result<Value> {
    cx.cli(["policy", "list", sandbox.name(), "--output", "json"])
        .await?
        .success()?
        .json()
}

/// `binaries:` for policy YAML that lets the image's Python connect.
pub fn python_binaries_yaml() -> String {
    let paths: Vec<String> = PYTHON_BINARIES
        .iter()
        .map(|path| format!("{{path: \"{path}\"}}"))
        .collect();
    format!("[{}]", paths.join(", "))
}
