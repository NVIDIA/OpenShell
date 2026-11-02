// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The container engine behind a Docker or Podman gateway.
//!
//! Some suites check what the driver did in the engine: they build images the
//! gateway then runs, or inspect the containers it created. The environment
//! names the command that reaches the gateway's engine and image store in
//! `OPENSHELL_TEST_CONTAINER_ENGINE`:
//!
//! | Gateway | Value |
//! |---|---|
//! | Docker | `docker` |
//! | Rootless Podman, running as the test user | `podman` |
//! | Rootful Podman | `sudo -n podman` |
//!
//! The value is split on whitespace, so it can't hold arguments with spaces.
//! Under `openshell-test-runner`, the tmachine environment's setup publishes
//! it. A missing variable fails the test; it never skips it.

use std::path::Path;

use testkit::{Error, Result, ResultExt as _};
use tokio::process::Command;

pub const ENGINE_ENV: &str = "OPENSHELL_TEST_CONTAINER_ENGINE";
/// The label the Docker and Podman drivers put on a sandbox's containers.
pub const SANDBOX_NAME_LABEL: &str = "openshell.ai/sandbox-name";
/// The label that tells a sandbox's workload (`sandbox`) and `supervisor`
/// containers apart.
pub const ISOLATION_ROLE_LABEL: &str = "openshell.ai/isolation-role";

/// The gateway's container engine.
#[derive(Clone, Debug)]
pub struct Engine {
    command: Vec<String>,
}

/// An image built for a test: its tag and the image ID it had when built.
#[derive(Clone, Debug)]
pub struct Image {
    pub tag: String,
    pub id: String,
}

impl Engine {
    /// Read [`ENGINE_ENV`].
    pub fn from_env() -> Result<Self> {
        let value = std::env::var(ENGINE_ENV).unwrap_or_default();
        Self::new(value.split_whitespace())
    }

    /// An engine run as `command`, e.g. `["sudo", "-n", "podman"]`.
    pub fn new<I, S>(command: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let command: Vec<String> = command.into_iter().map(Into::into).collect();
        testkit::ensure!(
            !command.is_empty(),
            "{ENGINE_ENV} is not set; this suite needs the gateway's container engine, such as docker, podman or `sudo -n podman` (see the container-engine-support crate docs)"
        );
        Ok(Self { command })
    }

    /// Build `containerfile` as `tag`. The build context is empty. Remove
    /// the image with [`Engine::remove_image`], for example in a cleanup
    /// hook registered right after the build.
    pub async fn build_image(&self, tag: &str, containerfile: &str) -> Result {
        let context = tempfile::tempdir()
            .map_err(|error| Error::from_error(&error))
            .context("create build context")?;
        let file = context.path().join("Containerfile");
        std::fs::write(&file, containerfile)
            .map_err(|error| Error::from_error(&error))
            .context("write Containerfile")?;
        self.output([
            "build",
            "--file",
            utf8(&file)?,
            "--tag",
            tag,
            utf8(context.path())?,
        ])
        .await
        .map(drop)
    }

    /// Image `tag` and the ID it has now.
    pub async fn image(&self, tag: &str) -> Result<Image> {
        let id = self
            .output(["image", "inspect", "--format", "{{.Id}}", tag])
            .await?;
        Ok(Image {
            tag: tag.to_string(),
            id,
        })
    }

    /// Remove image `tag`. Removal isn't forced: delete the sandboxes that
    /// use the image first, so an image still in use is reported rather than
    /// pulled from under the gateway.
    pub async fn remove_image(&self, tag: &str) -> Result {
        self.output(["image", "rm", tag]).await.map(drop)
    }

    /// The one container with isolation `role` (`sandbox` or `supervisor`)
    /// that the driver created for `sandbox`.
    pub async fn container_for_role(&self, sandbox: &str, role: &str) -> Result<String> {
        let ids = self
            .output([
                "ps",
                "--all",
                "--quiet",
                "--filter",
                &format!("label={SANDBOX_NAME_LABEL}={sandbox}"),
                "--filter",
                &format!("label={ISOLATION_ROLE_LABEL}={role}"),
            ])
            .await?;
        match ids.split_whitespace().collect::<Vec<_>>().as_slice() {
            [id] => Ok((*id).to_string()),
            ids => Err(Error::msg(format!(
                "expected one {role} container for sandbox {sandbox}, found {ids:?}"
            ))),
        }
    }

    /// `container inspect --format format` for one container.
    pub async fn inspect_container(&self, id: &str, format: &str) -> Result<String> {
        self.output(["container", "inspect", "--format", format, id])
            .await
    }

    /// Run the engine with `args` and return its trimmed standard output.
    /// A non-zero exit is an error that includes the engine's output.
    pub async fn output<I, S>(&self, args: I) -> Result<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let args: Vec<String> = args
            .into_iter()
            .map(|arg| arg.as_ref().to_string())
            .collect();
        let command = self
            .command
            .iter()
            .chain(&args)
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(" ");
        let output = Command::new(&self.command[0])
            .args(&self.command[1..])
            .args(&args)
            .kill_on_drop(true)
            .output()
            .await
            .map_err(|error| Error::from_error(&error))
            .context(format!("run {command}"))?;
        testkit::ensure!(
            output.status.success(),
            "{command} failed ({}):\n{}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }
}

fn utf8(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| Error::msg(format!("{} is not UTF-8", path.display())))
}
