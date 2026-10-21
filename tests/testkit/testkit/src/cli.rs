// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Driving the installed `openshell` CLI.
//!
//! Some promised behavior exists only in the CLI: file upload and download,
//! interactive connect, and port forwarding. Tests act through the CLI for
//! those and observe through the SDK where they can. Rely on the CLI's exit
//! code and structured output (`--output json`), not on its table text.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::de::DeserializeOwned;

use crate::error::{Error, Result, ResultExt};
use crate::gateway::{ENDPOINT_ENV, GATEWAY_ENV, Gateway, WORKSPACE_ENV};

/// How long one CLI invocation may take.
pub const CLI_TIMEOUT: Duration = Duration::from_mins(5);
/// The CLI binary to run. Defaults to `openshell` on PATH.
pub const BIN_ENV: &str = "OPENSHELL_BIN";

/// Runs the CLI against the gateway and workspace the tests use.
#[derive(Clone, Debug)]
pub struct Cli {
    binary: PathBuf,
    gateway: Gateway,
}

/// The buffered result of one CLI invocation.
#[derive(Debug)]
pub struct CliOutput {
    pub command: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Cli {
    /// The CLI named by [`BIN_ENV`], pointed at `gateway`.
    pub fn from_env(gateway: &Gateway) -> Self {
        let binary = std::env::var_os(BIN_ENV)
            .filter(|value| !value.is_empty())
            .map_or_else(|| PathBuf::from("openshell"), PathBuf::from);
        Self {
            binary,
            gateway: gateway.clone(),
        }
    }

    /// Check that the CLI reaches the gateway: `openshell status` must report
    /// it connected.
    pub async fn check_connected(&self) -> Result {
        let output = self.run(["status", "--output", "json"]).await?.success()?;
        let status: serde_json::Value = output.json()?;
        crate::ensure!(
            status["status"] == "connected",
            "`{}` reports {}",
            output.command,
            status
        );
        Ok(())
    }

    /// Run the CLI with `args` and buffer its output. A non-zero exit is
    /// returned, not raised; use [`CliOutput::success`] to require success.
    pub async fn run<I, S>(&self, args: I) -> Result<CliOutput>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.run_in(None, args).await
    }

    /// Like [`Cli::run`], with `dir` as the working directory.
    pub async fn run_in<I, S>(&self, dir: Option<&Path>, args: I) -> Result<CliOutput>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let args: Vec<_> = args
            .into_iter()
            .map(|arg| arg.as_ref().to_os_string())
            .collect();
        let command = std::iter::once(self.binary.as_os_str())
            .chain(args.iter().map(std::ffi::OsString::as_os_str))
            .map(|part| part.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");

        let mut process = tokio::process::Command::new(&self.binary);
        process
            .args(&args)
            .env("NO_COLOR", "1")
            .env(WORKSPACE_ENV, &self.gateway.workspace)
            .stdin(Stdio::null())
            .kill_on_drop(true);
        // Select exactly the gateway the SDK connected to.
        match &self.gateway.name {
            Some(name) => process.env(GATEWAY_ENV, name),
            None => process.env_remove(GATEWAY_ENV),
        };
        if self.gateway.endpoint_from_env {
            process.env(ENDPOINT_ENV, &self.gateway.endpoint);
        } else {
            process.env_remove(ENDPOINT_ENV);
        }
        if let Some(dir) = dir {
            process.current_dir(dir);
        }

        let output = tokio::time::timeout(CLI_TIMEOUT, process.output())
            .await
            .map_err(|_| Error::msg(format!("timed out after {CLI_TIMEOUT:?}")))
            .context(format!("run {command}"))?
            .map_err(|error| Error::from_error(&error))
            .context(format!("run {command}"))?;
        Ok(CliOutput {
            command,
            // A signal-terminated CLI has no code; report it as a failure.
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

impl CliOutput {
    /// Fail unless the command exited 0.
    pub fn success(self) -> Result<Self> {
        crate::ensure!(
            self.exit_code == 0,
            "`{}` exited with {}; stderr: {}",
            self.command,
            self.exit_code,
            self.stderr.trim()
        );
        Ok(self)
    }

    /// Fail unless the command exited non-zero, e.g. when a request must be
    /// rejected.
    pub fn failure(self) -> Result<Self> {
        crate::ensure!(
            self.exit_code != 0,
            "`{}` succeeded but was expected to fail; stdout: {}",
            self.command,
            self.stdout.trim()
        );
        Ok(self)
    }

    /// Parse stdout as JSON, from a command run with `--output json`.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_str(&self.stdout)
            .map_err(|error| Error::from_error(&error))
            .context(format!("parse JSON output of `{}`", self.command))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli(binary: &str) -> Cli {
        Cli {
            binary: PathBuf::from(binary),
            gateway: Gateway::named_for_test("tmachine"),
        }
    }

    #[tokio::test]
    async fn runs_with_the_gateway_selected() {
        let output = cli("sh")
            .run([
                "-c",
                "echo \"$OPENSHELL_GATEWAY|${OPENSHELL_GATEWAY_ENDPOINT-unset}|$OPENSHELL_WORKSPACE\"; exit 3",
            ])
            .await
            .unwrap();
        assert_eq!(output.stdout, "tmachine|unset|default\n");
        assert_eq!(output.exit_code, 3);
        let err = output.success().unwrap_err();
        assert!(err.to_string().contains("exited with 3"), "{err}");
    }

    #[tokio::test]
    async fn runs_with_a_raw_endpoint_selected() {
        let cli = Cli {
            binary: PathBuf::from("sh"),
            gateway: Gateway::endpoint_for_test("http://127.0.0.1:1"),
        };
        let output = cli
            .run([
                "-c",
                "echo \"${OPENSHELL_GATEWAY-unset}|$OPENSHELL_GATEWAY_ENDPOINT\"",
            ])
            .await
            .unwrap();
        assert_eq!(output.stdout, "unset|http://127.0.0.1:1\n");
    }

    #[tokio::test]
    async fn parses_json_output() {
        let output = cli("sh")
            .run(["-c", "echo '{\"status\": \"connected\"}'"])
            .await
            .unwrap()
            .success()
            .unwrap();
        let value: serde_json::Value = output.json().unwrap();
        assert_eq!(value["status"], "connected");
    }

    #[tokio::test]
    async fn reports_a_missing_binary() {
        let err = cli("/nonexistent/openshell")
            .run(["status"])
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("run /nonexistent/openshell status"),
            "{err}"
        );
    }
}
