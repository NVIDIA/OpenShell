// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Driving the `openshell` CLI the environment installed.
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
use crate::target::CliTarget;

/// How long one CLI invocation may take.
pub const CLI_TIMEOUT: Duration = Duration::from_mins(5);

/// Runs the target's CLI against the target's gateway.
#[derive(Clone, Debug)]
pub struct Cli {
    binary: PathBuf,
    gateway: Option<String>,
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
    pub(crate) fn new(target: &CliTarget, binary: PathBuf) -> Self {
        Self {
            binary,
            gateway: target.gateway.clone(),
        }
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
            // Select the target's gateway, never one from the caller's
            // environment.
            .env_remove("OPENSHELL_GATEWAY_ENDPOINT")
            .stdin(Stdio::null())
            .kill_on_drop(true);
        match &self.gateway {
            Some(gateway) => process.env("OPENSHELL_GATEWAY", gateway),
            None => process.env_remove("OPENSHELL_GATEWAY"),
        };
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
            gateway: Some("tmachine".to_string()),
        }
    }

    #[tokio::test]
    async fn runs_with_the_target_gateway_selected() {
        let output = cli("sh")
            .run(["-c", "echo \"$OPENSHELL_GATEWAY\"; exit 3"])
            .await
            .unwrap();
        assert_eq!(output.stdout, "tmachine\n");
        assert_eq!(output.exit_code, 3);
        let err = output.success().unwrap_err();
        assert!(err.to_string().contains("exited with 3"), "{err}");
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
