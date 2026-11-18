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

use crate::cli_child::CliChild;
use crate::error::{Error, Result, ResultExt};
use crate::gateway::{ENDPOINT_ENV, GATEWAY_ENV, Gateway, WORKSPACE_ENV};
use crate::output::Outcome;

/// How long one CLI invocation may take.
pub const CLI_TIMEOUT: Duration = Duration::from_mins(5);
/// The CLI binary to run. Defaults to `openshell` on PATH.
pub(crate) const BIN_ENV: &str = "OPENSHELL_BIN";

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

    /// `binary` in place of the CLI, pointed at an unregistered gateway.
    #[cfg(test)]
    pub(crate) fn with_binary(binary: &str) -> Self {
        Self {
            binary: PathBuf::from(binary),
            gateway: Gateway::from_endpoint(
                "http://127.0.0.1:1".to_string(),
                "default".to_string(),
            ),
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
        self.run_with_env(dir, &[], args).await
    }

    /// Like [`Cli::run_in`], with extra environment variables for the CLI,
    /// such as a credential it reads by name. Values are not included in
    /// [`CliOutput::command`] or in errors, so they can hold secrets. They
    /// can't change which gateway or workspace the CLI uses.
    pub async fn run_with_env<I, S>(
        &self,
        dir: Option<&Path>,
        env: &[(&str, &str)],
        args: I,
    ) -> Result<CliOutput>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let (command, mut process) = self.command(args);
        // Set first, so the gateway and workspace selection wins over
        // anything the caller passes.
        process.envs(env.iter().copied()).stdin(Stdio::null());
        self.apply_env(&mut process);
        if let Some(dir) = dir {
            process.current_dir(dir);
        }

        let output = tokio::time::timeout(CLI_TIMEOUT, process.output())
            .await
            .map_err(|_| Error::msg(format!("timed out after {CLI_TIMEOUT:?}")))
            .context(format!("run {command}"))?
            .context(format!("run {command}"))?;
        Ok(CliOutput {
            command,
            exit_code: exit_code(output.status),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    /// Start the CLI with `args` and keep it running, with stdin, stdout,
    /// and stderr piped to the test. Use it for commands that stream or
    /// read input, such as `sandbox connect`.
    pub fn spawn<I, S>(&self, args: I) -> Result<CliChild>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.spawn_with_stdin(args, Stdio::piped())
    }

    /// Like [`Cli::spawn`], with `stdin` as the CLI's stdin, such as
    /// [`Stdio::null`], a file, or a pseudo-terminal. Stdout and stderr are
    /// still piped.
    pub fn spawn_with_stdin<I, S>(&self, args: I, stdin: impl Into<Stdio>) -> Result<CliChild>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let (command, mut process) = self.command(args);
        process
            .stdin(stdin)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        self.apply_env(&mut process);
        CliChild::spawn(command, &mut process)
    }

    /// The gateway and workspace the CLI is pointed at.
    pub fn gateway(&self) -> &Gateway {
        &self.gateway
    }

    /// Point `process` at the CLI's gateway and workspace, as every CLI
    /// invocation is. Use it for a program that runs the CLI itself, such as
    /// `ssh` with the `ProxyCommand` from `sandbox ssh-config`.
    pub fn apply_env(&self, process: &mut tokio::process::Command) {
        process
            .env("NO_COLOR", "1")
            .env(WORKSPACE_ENV, &self.gateway.workspace);
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
    }

    /// The command line for reports, and a process for it that is killed
    /// when dropped.
    fn command<I, S>(&self, args: I) -> (String, tokio::process::Command)
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
        process.args(&args).kill_on_drop(true);
        (command, process)
    }
}

/// The exit code of a finished CLI. A signal-terminated CLI has no code;
/// report it as a failure.
pub(crate) fn exit_code(status: std::process::ExitStatus) -> i32 {
    status.code().unwrap_or(-1)
}

/// The characters the CLI's error reports draw around wrapped lines: the
/// gutter, the error marker, and the box corners.
const REPORT_GUTTER: [char; 6] = ['│', '×', '╰', '─', '╭', '├'];

impl CliOutput {
    /// Fail unless the command exited 0.
    pub fn success(self) -> Result<Self> {
        self.check(|outcome| outcome.success())?;
        Ok(self)
    }

    /// Fail unless the command exited non-zero, e.g. when a request must be
    /// rejected.
    pub fn failure(self) -> Result<Self> {
        self.check(|outcome| outcome.failure())?;
        Ok(self)
    }

    /// Fail unless the command exited 0 and printed exactly `expected`.
    pub fn expect_stdout(self, expected: &str) -> Result<Self> {
        self.check(|outcome| outcome.stdout_is(expected))?;
        Ok(self)
    }

    fn check(&self, check: impl FnOnce(&Outcome<'_>) -> Result) -> Result {
        let what = format!("`{}`", self.command);
        check(&Outcome {
            what: &what,
            exit_code: self.exit_code,
            stdout: &self.stdout,
            stderr: &self.stderr,
        })
    }

    /// Stdout and stderr as one line of words, for matching an error report.
    /// The CLI wraps reports to the terminal width and draws a gutter, so
    /// match against this rather than the raw output.
    pub fn report_text(&self) -> String {
        format!("{} {}", self.stdout, self.stderr)
            .replace(REPORT_GUTTER, " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Parse stdout as JSON, from a command run with `--output json`.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_str(&self.stdout)
            .context(format!("parse JSON output of `{}`", self.command))
    }
}
