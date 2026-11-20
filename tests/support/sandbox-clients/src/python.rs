// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The Python a client runs under.

use testkit::{ExecOutput, Result, Sandbox};

use crate::message::{Http, Request};
use crate::probe::{self, Connect};
use crate::resolve::{self, Resolve};

/// The interpreter that runs a client, and the environment it runs with.
///
/// [`Python::default`] is the image's `python3`, which the free functions
/// such as [`crate::connect`] use. Name another to check what the policy
/// allows a particular binary, such as a copy of `python3`:
///
/// ```ignore
/// let copy = Python::new("/sandbox/copied-python").env("PYTHONHOME", prefix);
/// let reply = copy.http_raw(&sandbox, host, port, b"hello").await?;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Python {
    executable: String,
    env: Vec<(String, String)>,
}

impl Default for Python {
    fn default() -> Self {
        Self::new("python3")
    }
}

impl Python {
    /// Run clients with `executable`, a path or a name on the sandbox's
    /// `PATH`.
    pub fn new(executable: impl Into<String>) -> Self {
        Self {
            executable: executable.into(),
            env: Vec::new(),
        }
    }

    /// Set `name` to `value` in the client's environment. A copied
    /// interpreter, for example, needs `PYTHONHOME` to find its standard
    /// library.
    #[must_use]
    pub fn env(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((name.into(), value.into()));
        self
    }

    /// [`crate::connect`] under this Python.
    pub async fn connect(&self, sandbox: &Sandbox, host: &str, port: u16) -> Result<Connect> {
        probe::connect_with(self, sandbox, host, port).await
    }

    /// [`crate::http`] under this Python.
    pub async fn http(
        &self,
        sandbox: &Sandbox,
        host: &str,
        port: u16,
        request: &Request,
    ) -> Result<Http> {
        probe::http_with(self, sandbox, host, port, request).await
    }

    /// [`crate::http_raw`] under this Python.
    pub async fn http_raw(
        &self,
        sandbox: &Sandbox,
        host: &str,
        port: u16,
        bytes: &[u8],
    ) -> Result<Http> {
        probe::http_raw_with(self, sandbox, host, port, bytes).await
    }

    /// [`crate::resolve`] under this Python.
    pub async fn resolve(&self, sandbox: &Sandbox, host: &str, port: u16) -> Result<Resolve> {
        resolve::resolve_with(self, sandbox, host, port).await
    }

    /// Run `script` with `args` in `sandbox`. A non-zero exit is an error.
    pub(crate) async fn run(
        &self,
        sandbox: &Sandbox,
        script: &str,
        args: &[&str],
    ) -> Result<ExecOutput> {
        if *self == Self::default() {
            return sandbox.run_python(script, args).await;
        }
        let mut output = sandbox.exec(self.command(script, args)).await?;
        output.description = format!(
            "{} client with {args:?} and env {:?} in sandbox {}",
            self.executable,
            self.env,
            sandbox.name()
        );
        output.success()
    }

    /// `env NAME=value ... <executable> -c <script> <args>`.
    fn command(&self, script: &str, args: &[&str]) -> Vec<String> {
        let mut command = Vec::new();
        if !self.env.is_empty() {
            command.push("env".to_string());
            command.extend(
                self.env
                    .iter()
                    .map(|(name, value)| format!("{name}={value}")),
            );
        }
        command.extend([
            self.executable.clone(),
            "-c".to_string(),
            script.to_string(),
        ]);
        command.extend(args.iter().map(|arg| (*arg).to_string()));
        command
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_runs_the_executable_without_env() {
        assert_eq!(
            Python::new("/sandbox/py").command("print(1)", &["a", "b"]),
            ["/sandbox/py", "-c", "print(1)", "a", "b"]
        );
    }

    #[test]
    fn command_sets_env_through_env() {
        let python = Python::new("/sandbox/py")
            .env("PYTHONHOME", "/opt/python")
            .env("A", "b c");
        assert_eq!(
            python.command("s", &["x"]),
            [
                "env",
                "PYTHONHOME=/opt/python",
                "A=b c",
                "/sandbox/py",
                "-c",
                "s",
                "x"
            ]
        );
    }
}
