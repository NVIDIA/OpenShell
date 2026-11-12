// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A CLI process the test keeps running, for commands that stream output or
//! read input, such as `sandbox connect` or a piped `sandbox exec`.

use std::process::ExitStatus;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt as _, AsyncRead, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::cli::{CliOutput, exit_code};
use crate::error::{Error, Result, ResultExt};

/// A running CLI started by [`crate::Cli::spawn`].
///
/// Stdout and stderr are read in the background as they arrive, so a CLI that
/// writes a lot never blocks on a full pipe while the test does something
/// else. Read them line by line with [`CliChild::stdout_line`] and
/// [`CliChild::stdout_until`] (and the `stderr` forms), or all at once with
/// [`CliChild::output`].
///
/// The process is killed when the handle is dropped, so a failing test
/// doesn't leave it running.
#[derive(Debug)]
pub struct CliChild {
    command: String,
    child: Child,
    pid: u32,
    stdin: Option<ChildStdin>,
    stdout: Stream,
    stderr: Stream,
}

/// One output stream: the lines read so far and not yet taken.
#[derive(Debug)]
struct Stream {
    name: &'static str,
    lines: mpsc::UnboundedReceiver<Vec<u8>>,
    reader: JoinHandle<()>,
}

impl CliChild {
    pub(crate) fn spawn(command: String, process: &mut Command) -> Result<Self> {
        let mut child = process
            .spawn()
            .map_err(|error| Error::from_error(&error))
            .context(format!("start {command}"))?;
        let pid = child
            .id()
            .ok_or_else(|| Error::msg(format!("{command} exited before it was watched")))?;
        let stdout = Stream::read("stdout", child.stdout.take().expect("stdout is piped"));
        let stderr = Stream::read("stderr", child.stderr.take().expect("stderr is piped"));
        Ok(Self {
            command,
            stdin: child.stdin.take(),
            child,
            pid,
            stdout,
            stderr,
        })
    }

    /// The command line, for messages.
    pub fn command(&self) -> &str {
        &self.command
    }

    /// The process ID of the CLI.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Write `bytes` to the CLI's stdin and flush it. The error is the
    /// I/O error itself, so a test can accept `BrokenPipe` from a command that
    /// exits before it reads all its input.
    pub async fn write_stdin(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let stdin = self.stdin.as_mut().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "stdin is closed or not piped",
            )
        })?;
        stdin.write_all(bytes).await?;
        stdin.flush().await
    }

    /// Close the CLI's stdin, so it reads end of file.
    pub fn close_stdin(&mut self) {
        self.stdin = None;
    }

    /// The next line of stdout, without its line ending. Fails if none
    /// arrives within `timeout` or stdout closes.
    pub async fn stdout_line(&mut self, timeout: Duration) -> Result<String> {
        let command = &self.command;
        self.stdout.next_line(command, timeout).await
    }

    /// The next line of stderr, like [`CliChild::stdout_line`].
    pub async fn stderr_line(&mut self, timeout: Duration) -> Result<String> {
        let command = &self.command;
        self.stderr.next_line(command, timeout).await
    }

    /// Read stdout until a line matches `found`, and return the lines read,
    /// the matching one last. Fails if no line matches within `timeout` or
    /// stdout closes first.
    pub async fn stdout_until(
        &mut self,
        timeout: Duration,
        found: impl FnMut(&str) -> bool,
    ) -> Result<Vec<String>> {
        let command = &self.command;
        self.stdout.until(command, timeout, found).await
    }

    /// Read stderr until a line matches `found`, like
    /// [`CliChild::stdout_until`].
    pub async fn stderr_until(
        &mut self,
        timeout: Duration,
        found: impl FnMut(&str) -> bool,
    ) -> Result<Vec<String>> {
        let command = &self.command;
        self.stderr.until(command, timeout, found).await
    }

    /// Send a Unix signal, such as `libc::SIGTERM`, to the CLI process only.
    #[cfg(unix)]
    pub fn signal(&self, signal: i32) -> Result {
        let pid = libc::pid_t::try_from(self.pid).map_err(Error::from_display)?;
        // SAFETY: kill(2) takes plain integers and has no memory effects.
        if unsafe { libc::kill(pid, signal) } != 0 {
            let error = std::io::Error::last_os_error();
            return Err(Error::from_error(&error)
                .context(format!("send signal {signal} to {}", self.command)));
        }
        Ok(())
    }

    /// Kill the CLI and wait for it to exit.
    pub async fn kill(&mut self) -> Result {
        self.child
            .kill()
            .await
            .map_err(|error| Error::from_error(&error))
            .context(format!("kill {}", self.command))
    }

    /// The CLI's exit code if it has exited, without waiting.
    pub fn try_wait(&mut self) -> Result<Option<i32>> {
        Ok(self
            .child
            .try_wait()
            .map_err(|error| Error::from_error(&error))
            .context(format!("check {}", self.command))?
            .map(exit_code))
    }

    /// Wait for the CLI to exit and return its exit code. Fails if it is
    /// still running after `timeout`; it then keeps running until killed or
    /// dropped.
    pub async fn wait(&mut self, timeout: Duration) -> Result<i32> {
        Ok(exit_code(self.wait_status(timeout).await?))
    }

    /// Close stdin, wait for the CLI to exit, and return its exit code with
    /// the output not yet read as lines. Fails if the CLI, or a process that
    /// inherited its stdout or stderr, is still running after `timeout`.
    pub async fn output(mut self, timeout: Duration) -> Result<CliOutput> {
        self.close_stdin();
        let deadline = tokio::time::Instant::now() + timeout;
        let status = self.wait_status(timeout).await?;
        let stdout = self.stdout.rest(&self.command, deadline).await?;
        let stderr = self.stderr.rest(&self.command, deadline).await?;
        Ok(CliOutput {
            command: self.command,
            exit_code: exit_code(status),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    }

    async fn wait_status(&mut self, timeout: Duration) -> Result<ExitStatus> {
        tokio::time::timeout(timeout, self.child.wait())
            .await
            .map_err(|_| Error::msg(format!("still running after {timeout:?}")))
            .context(format!("wait for {}", self.command))?
            .map_err(|error| Error::from_error(&error))
            .context(format!("wait for {}", self.command))
    }
}

impl Stream {
    fn read(name: &'static str, pipe: impl AsyncRead + Unpin + Send + 'static) -> Self {
        let (sender, lines) = mpsc::unbounded_channel();
        let reader = tokio::spawn(async move {
            let mut pipe = BufReader::new(pipe);
            loop {
                let mut line = Vec::new();
                match pipe.read_until(b'\n', &mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if sender.send(line).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Self {
            name,
            lines,
            reader,
        }
    }

    async fn next_line(&mut self, command: &str, timeout: Duration) -> Result<String> {
        match tokio::time::timeout(timeout, self.lines.recv()).await {
            Ok(Some(line)) => Ok(trim_line_ending(&line)),
            Ok(None) => Err(Error::msg(format!("{} of {command} closed", self.name))),
            Err(_) => Err(Error::msg(format!(
                "no line on {} of {command} within {timeout:?}",
                self.name
            ))),
        }
    }

    async fn until(
        &mut self,
        command: &str,
        timeout: Duration,
        mut found: impl FnMut(&str) -> bool,
    ) -> Result<Vec<String>> {
        let mut read = Vec::new();
        let outcome = tokio::time::timeout(timeout, async {
            while let Some(line) = self.lines.recv().await {
                let line = trim_line_ending(&line);
                let matched = found(&line);
                read.push(line);
                if matched {
                    return true;
                }
            }
            false
        })
        .await;
        match outcome {
            Ok(true) => Ok(read),
            Ok(false) => Err(Error::msg(format!(
                "{} of {command} closed before the expected line; read {read:?}",
                self.name
            ))),
            Err(_) => Err(Error::msg(format!(
                "no expected line on {} of {command} within {timeout:?}; read {read:?}",
                self.name
            ))),
        }
    }

    /// Everything not yet taken, once the pipe has closed.
    async fn rest(&mut self, command: &str, deadline: tokio::time::Instant) -> Result<Vec<u8>> {
        tokio::time::timeout_at(deadline, &mut self.reader)
            .await
            .map_err(|_| {
                Error::msg(format!(
                    "{} of {command} is still open after the CLI exited",
                    self.name
                ))
            })?
            .map_err(|error| Error::from_error(&error))?;
        let mut bytes = Vec::new();
        while let Ok(line) = self.lines.try_recv() {
            bytes.extend(line);
        }
        Ok(bytes)
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

fn trim_line_ending(line: &[u8]) -> String {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    String::from_utf8_lossy(line).into_owned()
}

#[cfg(all(test, unix))]
mod tests {
    use std::time::Duration;

    use crate::cli::Cli;

    const TIMEOUT: Duration = Duration::from_secs(10);

    /// `sh` in place of the CLI, so the tests need no gateway.
    fn sh() -> Cli {
        Cli::with_binary("/bin/sh")
    }

    #[tokio::test]
    async fn reads_lines_and_writes_stdin() {
        let mut child = sh()
            .spawn([
                "-c",
                "echo ready; echo warning >&2; read line; echo \"got=$line\"; exit 3",
            ])
            .unwrap();
        assert_eq!(child.stdout_line(TIMEOUT).await.unwrap(), "ready");
        assert_eq!(child.stderr_line(TIMEOUT).await.unwrap(), "warning");
        child.write_stdin(b"hello\n").await.unwrap();
        let read = child
            .stdout_until(TIMEOUT, |line| line.starts_with("got="))
            .await
            .unwrap();
        assert_eq!(read, ["got=hello"]);
        assert_eq!(child.wait(TIMEOUT).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn output_keeps_unread_bytes_exactly() {
        let mut child = sh()
            .spawn(["-c", "echo first; printf 'a\\r\\nb'; cat >&2"])
            .unwrap();
        assert_eq!(child.stdout_line(TIMEOUT).await.unwrap(), "first");
        child.write_stdin(b"input").await.unwrap();
        let output = child.output(TIMEOUT).await.unwrap();
        assert_eq!(output.exit_code, 0);
        assert_eq!(output.stdout, "a\r\nb");
        assert_eq!(output.stderr, "input");
    }

    #[tokio::test]
    async fn until_reports_what_it_read_when_the_stream_closes() {
        let mut child = sh().spawn(["-c", "echo one; echo two"]).unwrap();
        let error = child
            .stdout_until(TIMEOUT, |line| line == "three")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("closed before the expected line"), "{error}");
        assert!(error.contains(r#"["one", "two"]"#), "{error}");
    }

    #[tokio::test]
    async fn signal_reaches_the_process() {
        let mut child = sh()
            .spawn([
                "-c",
                "trap 'exit 42' TERM; echo ready; while :; do sleep 0.1; done",
            ])
            .unwrap();
        assert_eq!(child.stdout_line(TIMEOUT).await.unwrap(), "ready");
        assert_eq!(child.try_wait().unwrap(), None);
        child.signal(libc::SIGTERM).unwrap();
        assert_eq!(child.wait(TIMEOUT).await.unwrap(), 42);
    }

    #[tokio::test]
    async fn wait_times_out_on_a_running_process() {
        let mut child = sh().spawn(["-c", "sleep 30"]).unwrap();
        let error = child
            .wait(Duration::from_millis(100))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("still running"), "{error}");
        child.kill().await.unwrap();
    }
}
