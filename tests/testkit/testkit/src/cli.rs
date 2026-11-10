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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;

use serde::de::DeserializeOwned;

use crate::error::{Error, Result, ResultExt};
use crate::gateway::{ENDPOINT_ENV, GATEWAY_ENV, Gateway, WORKSPACE_ENV};

/// How long one CLI invocation may take.
pub const CLI_TIMEOUT: Duration = Duration::from_mins(5);
/// A command that takes longer than this is reported when it finishes.
const SLOW_COMMAND: Duration = Duration::from_secs(10);
/// How often a command that is still running is reported.
const STILL_RUNNING_EVERY: Duration = Duration::from_secs(30);
/// How much of a timed-out command's output the error includes.
const TIMEOUT_OUTPUT_BYTES: usize = 2048;
/// How long to wait for a stopped command's output to close.
const CAPTURE_CLOSE: Duration = Duration::from_secs(2);
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
        self.run_limited(crate::budget::cap(CLI_TIMEOUT), dir, env, args)
            .await
    }

    async fn run_limited<I, S>(
        &self,
        limit: Duration,
        dir: Option<&Path>,
        env: &[(&str, &str)],
        args: I,
    ) -> Result<CliOutput>
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
        // Set first, so the gateway and workspace selection below wins over
        // anything the caller passes.
        process
            .args(&args)
            .envs(env.iter().copied())
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

        let started = Instant::now();
        let mut child = process
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| Error::from_error(&error))
            .context(format!("run {command}"))?;
        let stdout = Capture::start(child.stdout.take());
        let stderr = Capture::start(child.stderr.take());

        // Say so while a command is still running, so a hang shows in the
        // test's output instead of only in nextest's generic timeout.
        let mut next_note = STILL_RUNNING_EVERY;
        let status = loop {
            let elapsed = started.elapsed();
            if elapsed >= limit {
                break None;
            }
            let wait = next_note.min(limit).saturating_sub(elapsed);
            tokio::select! {
                status = child.wait() => break Some(status),
                () = tokio::time::sleep(wait) => {}
            }
            if started.elapsed() >= next_note && started.elapsed() < limit {
                eprintln!(
                    "still running after {}s: {command}",
                    started.elapsed().as_secs()
                );
                next_note += STILL_RUNNING_EVERY;
            }
        };

        let Some(status) = status else {
            // Stop it, and report what it printed so far.
            let _ = child.kill().await;
            let (stdout, stderr) = (stdout.finish().await, stderr.finish().await);
            let budget = if limit < CLI_TIMEOUT {
                " (the test's time budget)"
            } else {
                ""
            };
            return Err(Error::msg(format!(
                "timed out after {limit:?}{budget}; stdout: {}; stderr: {}",
                tail(&stdout),
                tail(&stderr)
            ))
            .context(format!("run {command}")));
        };
        let status = status
            .map_err(|error| Error::from_error(&error))
            .context(format!("run {command}"))?;
        let stdout = stdout.finish().await;
        let stderr = stderr.finish().await;

        // A signal-terminated CLI has no code; report it as a failure.
        let exit_code = status.code().unwrap_or(-1);
        let took = started.elapsed();
        if exit_code != 0 {
            eprintln!(
                "`{command}` exited with {exit_code} after {}s",
                took.as_secs()
            );
        } else if took >= SLOW_COMMAND {
            eprintln!("`{command}` took {}s", took.as_secs());
        }
        Ok(CliOutput {
            command,
            exit_code,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
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

/// A child's output, collected as it arrives so that what a command printed
/// before it was stopped is not lost.
struct Capture {
    buffer: Arc<Mutex<Vec<u8>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Capture {
    fn start<R>(stream: Option<R>) -> Self
    where
        R: tokio::io::AsyncRead + Unpin + Send + 'static,
    {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&buffer);
        let task = tokio::spawn(async move {
            let Some(mut stream) = stream else { return };
            let mut chunk = [0u8; 8192];
            while let Ok(n) = stream.read(&mut chunk).await {
                if n == 0 {
                    break;
                }
                sink.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .extend_from_slice(&chunk[..n]);
            }
        });
        Self { buffer, task }
    }

    /// Wait for the stream to close, up to [`CAPTURE_CLOSE`], and return what
    /// was read. A grandchild that keeps the pipe open does not hold this up.
    async fn finish(self) -> Vec<u8> {
        let Self { buffer, mut task } = self;
        if tokio::time::timeout(CAPTURE_CLOSE, &mut task)
            .await
            .is_err()
        {
            task.abort();
        }
        std::mem::take(
            &mut *buffer
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }
}

/// The end of `output`, trimmed, for an error message.
fn tail(output: &[u8]) -> String {
    let start = output.len().saturating_sub(TIMEOUT_OUTPUT_BYTES);
    let text = String::from_utf8_lossy(&output[start..]);
    let text = text.trim();
    if text.is_empty() {
        "(none)".to_string()
    } else if start > 0 {
        format!("...{text}")
    } else {
        text.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh() -> Cli {
        Cli {
            binary: PathBuf::from("sh"),
            gateway: Gateway::from_endpoint(
                "http://127.0.0.1:1".to_string(),
                "default".to_string(),
            ),
        }
    }

    #[tokio::test]
    async fn a_command_past_its_limit_fails_with_its_name_and_output() {
        let error = sh()
            .run_limited(
                Duration::from_millis(500),
                None,
                &[],
                ["-c", "echo partial; echo oops >&2; sleep 30"],
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("run sh -c echo partial"), "{error}");
        assert!(error.contains("timed out after"), "{error}");
        assert!(error.contains("stdout: partial"), "{error}");
        assert!(error.contains("stderr: oops"), "{error}");
    }

    #[tokio::test]
    async fn a_fast_command_returns_its_output() {
        let output = sh()
            .run_limited(
                Duration::from_secs(30),
                None,
                &[],
                ["-c", "echo hi; exit 3"],
            )
            .await
            .unwrap();
        assert_eq!(output.exit_code, 3);
        assert_eq!(output.stdout.trim(), "hi");
    }

    #[test]
    fn tail_keeps_the_end_of_long_output() {
        let long = "x".repeat(TIMEOUT_OUTPUT_BYTES + 10);
        assert!(tail(long.as_bytes()).starts_with("..."));
        assert_eq!(tail(b"  "), "(none)");
    }
}
