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
//!
//! Podman environments also publish `OPENSHELL_TEST_CONTAINER_NETWORK`, the
//! network the gateway attaches sandboxes to, so a test can start a fixture
//! container there, such as an [`EchoContainer`], and reach it by its network
//! alias. Docker environments don't: their tests reach fixtures on
//! the host instead.

mod echo;
mod tar;

use std::path::Path;
use std::time::{Duration, Instant};

use testkit::{Context, Error, Result, ResultExt as _};
use tokio::process::Command;

pub use echo::EchoContainer;

pub const ENGINE_ENV: &str = "OPENSHELL_TEST_CONTAINER_ENGINE";
/// The container network the gateway attaches sandboxes to.
pub const NETWORK_ENV: &str = "OPENSHELL_TEST_CONTAINER_NETWORK";
/// The label the Docker and Podman drivers put on a sandbox's containers.
pub const SANDBOX_NAME_LABEL: &str = "openshell.ai/sandbox-name";
/// The label with the ID of the sandbox a container belongs to.
pub const SANDBOX_ID_LABEL: &str = "openshell.ai/sandbox-id";
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

    /// The network named by [`NETWORK_ENV`]. A missing variable is an error.
    pub fn network_from_env() -> Result<String> {
        std::env::var(NETWORK_ENV)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                Error::msg(format!(
                    "{NETWORK_ENV} is not set; this test needs the container network the gateway attaches sandboxes to"
                ))
            })
    }

    /// Start a detached container named `openshell-test-<name>-<run id>`
    /// with `args`: `run` options, then the image and its command. The
    /// container is removed when the test ends, after the sandboxes created
    /// later. Returns its ID.
    pub async fn run_test_container<I, S>(
        &self,
        cx: &Context,
        name: &str,
        args: I,
    ) -> Result<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let container = format!("openshell-test-{name}-{}", cx.run_id());
        let mut command = vec![
            "run".to_string(),
            "--detach".to_string(),
            "--name".to_string(),
            container.clone(),
        ];
        command.extend(args.into_iter().map(|arg| arg.as_ref().to_string()));
        let id = self.output(command).await?;
        let (engine, started) = (self.clone(), container.clone());
        cx.on_cleanup(format!("remove container {container}"), async move || {
            engine.output(["rm", "--force", &started]).await.map(drop)
        });
        Ok(id)
    }

    /// The address container `id` has on `network`.
    pub async fn container_ip(&self, id: &str, network: &str) -> Result<String> {
        let ip = self
            .inspect_container(
                id,
                &format!(
                    "{{{{with index .NetworkSettings.Networks \"{network}\"}}}}{{{{.IPAddress}}}}{{{{end}}}}"
                ),
            )
            .await?;
        testkit::ensure!(
            !ip.is_empty(),
            "container {id} has no address on network {network}"
        );
        Ok(ip)
    }

    /// Build `containerfile` as `tag`. The build context is empty.
    async fn build_image(&self, tag: &str, containerfile: &str) -> Result {
        let context = tempfile::tempdir().context("create build context")?;
        let file = context.path().join("Containerfile");
        std::fs::write(&file, containerfile).context("write Containerfile")?;
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

    /// Build `containerfile` as `localhost/openshell-test-<name>:<run id>`
    /// and remove the image when the test ends. Cleanup runs last registered
    /// first, so sandboxes created from the image afterwards are deleted
    /// before it is removed.
    pub async fn build_test_image(
        &self,
        cx: &Context,
        name: &str,
        containerfile: &str,
    ) -> Result<Image> {
        let tag = format!("localhost/openshell-test-{name}:{}", cx.run_id());
        self.build_image(&tag, containerfile).await?;
        let (engine, built) = (self.clone(), tag.clone());
        cx.on_cleanup(format!("remove image {tag}"), async move || {
            engine.remove_image(&built).await
        });
        self.image(&tag).await
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

    /// The IDs of every container, running or not, that the driver labeled
    /// with sandbox ID `sandbox_id`. Sandbox IDs are unique, so this finds
    /// only the containers of the sandbox the test created.
    pub async fn containers_for_sandbox_id(&self, sandbox_id: &str) -> Result<Vec<String>> {
        let ids = self
            .output([
                "ps",
                "--all",
                "--quiet",
                "--filter",
                &format!("label={SANDBOX_ID_LABEL}={sandbox_id}"),
            ])
            .await?;
        Ok(ids.split_whitespace().map(str::to_string).collect())
    }

    /// Whether container `id` is running.
    pub async fn is_running(&self, id: &str) -> Result<bool> {
        match self
            .inspect_container(id, "{{.State.Running}}")
            .await?
            .as_str()
        {
            "true" => Ok(true),
            "false" => Ok(false),
            other => Err(Error::msg(format!(
                "container {id} has running state {other:?}; expected true or false"
            ))),
        }
    }

    /// Wait until container `id` is running (`running`) or stopped.
    pub async fn wait_running(&self, id: &str, running: bool, timeout: Duration) -> Result {
        let deadline = Instant::now() + timeout;
        loop {
            let last = match self.is_running(id).await {
                Ok(now) if now == running => return Ok(()),
                Ok(now) => format!("running={now}"),
                Err(err) => err.to_string(),
            };
            testkit::ensure!(
                Instant::now() < deadline,
                "container {id} did not reach running={running} within {timeout:?}; last state: {last}"
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Copy file `path` out of container `id` and return its contents.
    ///
    /// The engine writes the file to stdout as a tar archive. A copy to a host
    /// path would belong to the engine's user, which under rootful Podman the
    /// test can't read.
    pub async fn copy_from(&self, id: &str, path: &str) -> Result<Vec<u8>> {
        let output = self.run(["cp", &format!("{id}:{path}"), "-"]).await?;
        tar::first_file(&output.stdout).context(format!("read {path} copied from container {id}"))
    }

    /// The standard output and standard error container `id` has logged so
    /// far, kept apart.
    pub async fn logs(&self, id: &str) -> Result<ContainerLogs> {
        let output = self.run(["logs", id]).await?;
        Ok(ContainerLogs {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    /// Create volume `openshell-test-<name>-<run id>` with `labels` and
    /// remove it when the test ends. Sandboxes created after it that mount it
    /// are deleted first, because cleanup runs last registered first.
    pub async fn create_test_volume(
        &self,
        cx: &Context,
        name: &str,
        labels: &[(&str, &str)],
    ) -> Result<String> {
        let volume = format!("openshell-test-{name}-{}", cx.run_id());
        let mut args = vec!["volume".to_string(), "create".to_string()];
        for (key, value) in labels {
            args.extend(["--label".to_string(), format!("{key}={value}")]);
        }
        args.push(volume.clone());
        self.output(args).await?;
        let (engine, created) = (self.clone(), volume.clone());
        cx.on_cleanup(format!("remove volume {volume}"), async move || {
            engine.output(["volume", "rm", &created]).await.map(drop)
        });
        Ok(volume)
    }

    /// Run the engine with `args` and return its trimmed standard output.
    /// A non-zero exit is an error that includes the engine's output.
    pub async fn output<I, S>(&self, args: I) -> Result<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let output = self.run(args).await?;
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Run the engine with `args`. A non-zero exit is an error that includes
    /// the engine's output.
    async fn run<I, S>(&self, args: I) -> Result<std::process::Output>
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
            .context(format!("run {command}"))?;
        testkit::ensure!(
            output.status.success(),
            "{command} failed ({}):\n{}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(output)
    }
}

/// What a container logged, by stream.
#[derive(Clone, Debug, Default)]
pub struct ContainerLogs {
    pub stdout: String,
    pub stderr: String,
}

fn utf8(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| Error::msg(format!("{} is not UTF-8", path.display())))
}
