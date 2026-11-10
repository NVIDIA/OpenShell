// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandboxes created through `openshell sandbox create`, for tests of what
//! only the CLI offers, such as `--policy` files, `--no-keep`, or an attached
//! main command.

use crate::cli::CliOutput;
use crate::context::{Context, Sandbox};
use crate::error::{Error, Result, ResultExt};

/// A sandbox to create with `openshell sandbox create`. Start one with
/// [`Context::cli_sandbox`].
///
/// The sandbox is tracked for cleanup before the CLI runs, so a create the
/// gateway accepted but the CLI reported as failed is still cleaned up. The
/// CLI runs with `--no-tty`: tests never have a terminal.
pub struct CliSandboxBuilder<'a> {
    cx: &'a Context,
    name: String,
    args: Vec<String>,
    policy: Option<String>,
    command: Vec<String>,
}

impl<'a> CliSandboxBuilder<'a> {
    pub(crate) fn new(cx: &'a Context, name: String) -> Self {
        Self {
            cx,
            name,
            args: Vec::new(),
            policy: None,
            command: Vec::new(),
        }
    }

    /// The sandbox's name, for building the command before the create.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Create the sandbox from `image` (`--from`).
    #[must_use]
    pub fn image(self, image: &str) -> Self {
        self.args(["--from", image])
    }

    /// Create the sandbox with this policy YAML (`--policy`). It is written
    /// to a temporary file that lives until the CLI exits.
    #[must_use]
    pub fn policy(mut self, yaml: &str) -> Self {
        self.policy = Some(yaml.to_string());
        self
    }

    /// Other `sandbox create` arguments, such as `--no-keep` or `--label`.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// The sandbox's main command. Empty selects the gateway's default.
    #[must_use]
    pub fn command<I, S>(mut self, command: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.command = command.into_iter().map(Into::into).collect();
        self
    }

    /// Create the sandbox with `--detach`, require the CLI to succeed, and
    /// return the sandbox. It need not be Ready yet.
    pub async fn create(mut self) -> Result<Sandbox> {
        self.args.push("--detach".to_string());
        self.run()
            .await?
            .success()
            .context(format!("create sandbox {}", self.name))?;
        self.cx.adopt(&self.name).await
    }

    /// Create the sandbox attached to its main command and return the CLI's
    /// output, whatever its exit code. For a test of the main command's
    /// result, or of a create that must fail.
    pub async fn run(&self) -> Result<CliOutput> {
        self.cx.track(&self.name);
        let policy = self.policy.as_deref().map(PolicyFile::new).transpose()?;
        let mut args = vec!["sandbox", "create", "--name", &self.name, "--no-tty"];
        if let Some(policy) = &policy {
            args.extend(["--policy", policy.path()?]);
        }
        args.extend(self.args.iter().map(String::as_str));
        if !self.command.is_empty() {
            args.push("--");
            args.extend(self.command.iter().map(String::as_str));
        }
        self.cx.cli(args).await
    }
}

/// A policy written to a temporary file for `sandbox create --policy`.
struct PolicyFile(tempfile::NamedTempFile);

impl PolicyFile {
    fn new(contents: &str) -> Result<Self> {
        let file = tempfile::NamedTempFile::new().context("create policy file")?;
        std::fs::write(file.path(), contents)
            .context(format!("write {}", file.path().display()))?;
        Ok(Self(file))
    }

    fn path(&self) -> Result<&str> {
        let path = self.0.path();
        path.to_str()
            .ok_or_else(|| Error::msg(format!("{} is not UTF-8", path.display())))
    }
}
