// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandboxes created through `openshell sandbox create`, for tests of what
//! only the CLI offers, such as `--policy` files, `--no-keep`, or an attached
//! main command.

use crate::cli::CliOutput;
use crate::context::{Handles, Sandbox};
use crate::error::{Result, ResultExt};
use crate::yaml_file::YamlFile;

/// A sandbox to create with `openshell sandbox create`. Start one with
/// [`Context::cli_sandbox`](crate::Context::cli_sandbox).
///
/// The sandbox is tracked for cleanup before the CLI runs, so a create the
/// gateway accepted but the CLI reported as failed is still cleaned up. The
/// CLI runs with `--no-tty`: tests never have a terminal.
#[must_use = "a CliSandboxBuilder does nothing until create(), create_ready() or run()"]
pub struct CliSandboxBuilder {
    handles: Handles,
    name: String,
    args: Vec<String>,
    policy: Option<String>,
    command: Vec<String>,
}

impl CliSandboxBuilder {
    pub(crate) fn new(handles: Handles, name: String) -> Self {
        Self {
            handles,
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
    pub fn image(self, image: impl Into<String>) -> Self {
        self.args(["--from".to_string(), image.into()])
    }

    /// Create the sandbox with this policy YAML (`--policy`). It is written
    /// to a temporary file that lives until the CLI exits.
    pub fn policy_yaml(mut self, yaml: impl Into<String>) -> Self {
        self.policy = Some(yaml.into());
        self
    }

    /// Other `sandbox create` arguments, such as `--no-keep` or `--label`.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// The sandbox's main command. Empty selects the gateway's default.
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
        self.invoke()
            .await?
            .success()
            .context(format!("create sandbox {}", self.name))?;
        self.handles.adopt(&self.name).await
    }

    /// Create the sandbox and wait until it is Ready.
    pub async fn create_ready(self) -> Result<Sandbox> {
        let sandbox = self.create().await?;
        sandbox.wait_ready().await?;
        Ok(sandbox)
    }

    /// Create the sandbox attached to its main command and return the CLI's
    /// output, whatever its exit code. For a test of the main command's
    /// result, or of a create that must fail.
    pub async fn run(self) -> Result<CliOutput> {
        self.invoke().await
    }

    async fn invoke(&self) -> Result<CliOutput> {
        self.handles.track(&self.name);
        let policy = self.policy.as_deref().map(YamlFile::new).transpose()?;
        let mut args = vec!["sandbox", "create", "--name", &self.name, "--no-tty"];
        if let Some(policy) = &policy {
            args.extend(["--policy", policy.path()?]);
        }
        args.extend(self.args.iter().map(String::as_str));
        if !self.command.is_empty() {
            args.push("--");
            args.extend(self.command.iter().map(String::as_str));
        }
        self.handles.cli().run(args).await
    }
}
