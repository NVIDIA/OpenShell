// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The caller must use a disposable tmachine guest with passwordless sudo.
//! A lock spans profile setup, assertions, sandbox cleanup, and restoration.
//! A dirty marker survives panic/termination or failed restoration: later tests
//! refuse to adopt a changed configuration as their baseline.

use futures_util::FutureExt;
use openshell_e2e_support::OpenShellRunner;
use serde::Deserialize;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::{sleep, timeout};
use toml_edit::{DocumentMut, value};

use super::support::assert_podman_gateway;

const CONFIG: &str = "/etc/openshell/gateway.toml";
const SERVICE: &str = "openshell-gateway.service";
const FIXTURE_DIR: &str = "/var/lib/openshell-driver-tests/podman";
const DEFAULT_IMAGE: &str = "nvcr.io/nvidia/base/ubuntu:24.04";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug)]
pub enum Profile {
    Default,
    Auto,
    KeepId,
    Private,
}

impl Profile {
    fn arguments(self) -> &'static [&'static str] {
        match self {
            Self::Default => &[],
            Self::Auto => &["--userns", "auto"],
            Self::KeepId => &["--userns", "keep-id"],
            // Podman infers private from explicit maps, and rejects combining
            // --userns private with --uidmap/--gidmap.
            Self::Private => &[
                "--uidmap",
                "0:0:1",
                "--uidmap",
                "1:1:65535",
                "--gidmap",
                "0:0:1",
                "--gidmap",
                "1:1:65535",
            ],
        }
    }

    fn configuration(self, original: &str) -> Result<String, String> {
        let mut config = original
            .parse::<DocumentMut>()
            .map_err(|error| error.to_string())?;
        let driver = &mut config["openshell"]["drivers"]["podman"];
        if !driver.is_table() {
            return Err("gateway configuration has no Podman driver table".into());
        }
        match self {
            Self::Default => {}
            Self::Auto => driver["userns"] = value("auto"),
            Self::KeepId => driver["userns"] = value("keep-id"),
            Self::Private => {
                driver["userns"] = value("private");
                driver["uidmap"] = value(
                    ["0:0:1", "1:1:65535"]
                        .into_iter()
                        .collect::<toml_edit::Array>(),
                );
                driver["gidmap"] = value(
                    ["0:0:1", "1:1:65535"]
                        .into_iter()
                        .collect::<toml_edit::Array>(),
                );
            }
        }
        Ok(config.to_string())
    }
}

pub struct GatewayFixture {
    _lock: File,
    original: String,
    dirty: PathBuf,
    profile: Profile,
    user: String,
    home: String,
    uid: String,
    image: String,
}

impl GatewayFixture {
    async fn acquire(profile: Profile) -> Result<Self, String> {
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(PathBuf::from(FIXTURE_DIR).join("gateway.lock"))
            .map_err(|error| {
                format!("open gateway lock (tmachine preparation required): {error}")
            })?;
        let started = Instant::now();
        loop {
            match lock.try_lock() {
                Ok(()) => break,
                Err(TryLockError::WouldBlock) if started.elapsed() < COMMAND_TIMEOUT => {
                    sleep(Duration::from_millis(100)).await;
                }
                Err(error) => return Err(format!("acquire shared gateway lock: {error}")),
            }
        }
        let dirty = PathBuf::from(FIXTURE_DIR).join("gateway-dirty");
        if dirty.exists() {
            return Err(
                "previous test did not restore the gateway; start a fresh tmachine invocation"
                    .into(),
            );
        }
        let original = fs::read_to_string(CONFIG).map_err(|error| error.to_string())?;
        let parsed = original
            .parse::<DocumentMut>()
            .map_err(|error| error.to_string())?;
        let driver = &parsed["openshell"]["drivers"]["podman"];
        if !driver.is_table()
            || ["userns", "uidmap", "gidmap"]
                .iter()
                .any(|key| driver.get(key).is_some())
        {
            return Err("shared gateway baseline must omit userns, uidmap, and gidmap".into());
        }
        let user = command(
            "systemctl",
            &["show", SERVICE, "--property=User", "--value"],
            None,
        )
        .await?;
        let user: String = if user.trim().is_empty() {
            "root".into()
        } else {
            user.trim().into()
        };
        let account = command("getent", &["passwd", &user], None).await?;
        let fields: Vec<_> = account.trim().split(':').collect();
        if fields.len() != 7 {
            return Err("gateway service user has no valid passwd entry".into());
        }
        let fixture = Self {
            _lock: lock,
            original,
            dirty,
            profile,
            uid: fields[2].into(),
            home: fields[5].into(),
            user,
            image: std::env::var("OPENSHELL_PODMAN_TEST_IMAGE")
                .ok()
                .filter(|image| !image.trim().is_empty())
                .unwrap_or_else(|| DEFAULT_IMAGE.into()),
        };
        normal_gateway().await?;
        Ok(fixture)
    }

    async fn apply(&self, runner: &mut OpenShellRunner) -> Result<(), String> {
        // Set the marker before changing the gateway. The lock releases on
        // process exit, but this marker must not be cleared by Drop.
        fs::write(&self.dirty, format!("{:?}\n", self.profile))
            .map_err(|error| error.to_string())?;
        let config = self.profile.configuration(&self.original)?;
        command("sudo", &["-n", "tee", CONFIG], Some(&config)).await?;
        restart_gateway(runner).await
    }

    pub fn image(&self) -> &str {
        &self.image
    }

    async fn podman(&self, arguments: &[&str]) -> Result<String, String> {
        let home = format!("HOME={}", self.home);
        let runtime = format!("XDG_RUNTIME_DIR=/run/user/{}", self.uid);
        let mut args = vec!["-n", "-u", &self.user, "env", &home, &runtime, "podman"];
        args.extend_from_slice(arguments);
        command("sudo", &args, None).await
    }

    pub async fn reference_uid_map(&self) -> Result<String, String> {
        self.podman(&["pull", self.image()]).await?;
        let mut args = vec!["run", "--rm", "--pull", "never"];
        args.extend_from_slice(self.profile.arguments());
        args.extend([
            "--entrypoint",
            "/bin/cat",
            self.image(),
            "/proc/self/uid_map",
        ]);
        self.podman(&args).await
    }

    async fn restore(&self) -> Result<(), String> {
        // Deletion may be accepted while the gateway's cleanup worker is still
        // running. Let it finish under the scenario profile before restarting.
        // Even if that wait fails, attempt configuration restoration below.
        if let Err(error) = normal_gateway().await {
            eprintln!("gateway before restoration: {error}");
        }
        command("sudo", &["-n", "tee", CONFIG], Some(&self.original)).await?;
        command("sudo", &["-n", "systemctl", "restart", SERVICE], None).await?;
        if fs::read_to_string(CONFIG).map_err(|error| error.to_string())? != self.original {
            return Err("restored gateway configuration differs from the original".into());
        }
        normal_gateway().await?;
        fs::remove_file(&self.dirty).map_err(|error| error.to_string())?;
        eprintln!("gateway restored: original configuration, healthy Podman gateway, no sandboxes");
        Ok(())
    }
}

pub async fn with_profile<F>(profile: Profile, scenario: F) -> Result<(), String>
where
    F: AsyncFnOnce(&GatewayFixture, &mut OpenShellRunner) -> Result<(), String>,
{
    let fixture = GatewayFixture::acquire(profile).await?;
    let mut runner = OpenShellRunner::from_env(&format!("podman-userns/{profile:?}"))
        .map_err(|error| error.to_string())?;
    let scenario_result = AssertUnwindSafe(async {
        fixture.apply(&mut runner).await?;
        scenario(&fixture, &mut runner).await
    })
    .catch_unwind()
    .await
    .unwrap_or_else(|panic| {
        let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .unwrap_or("non-string panic");
        Err(format!("scenario panicked: {message}"))
    });
    let result = runner.finish(scenario_result).await;
    let restored = fixture.restore().await;
    if result.is_err() || restored.is_err() {
        let journal = command(
            "sudo",
            &[
                "-n",
                "journalctl",
                "--unit",
                SERVICE,
                "--no-pager",
                "--lines",
                "100",
            ],
            None,
        )
        .await;
        eprintln!(
            "gateway failure diagnostics:\n{}",
            journal.unwrap_or_else(|error| error)
        );
    }
    match (result, restored) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(format!("gateway restoration failed: {error}")),
        (Err(error), Err(restore)) => Err(format!(
            "{error}\ngateway restoration also failed: {restore}"
        )),
    }
}

async fn restart_gateway(runner: &mut OpenShellRunner) -> Result<(), String> {
    command("sudo", &["-n", "systemctl", "restart", SERVICE], None).await?;
    runner.check_gateway_status().await?;
    assert_podman_gateway(runner).await
}

#[derive(Deserialize)]
struct SandboxPage {
    sandboxes: Vec<serde::de::IgnoredAny>,
    next_page_token: String,
}

async fn normal_gateway() -> Result<(), String> {
    let mut runner =
        OpenShellRunner::from_env("podman-userns/baseline").map_err(|error| error.to_string())?;
    let result = async {
        runner.check_gateway_status().await?;
        assert_podman_gateway(&runner).await?;
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("timed out waiting for dedicated Podman test gateway to have no remaining sandboxes".into());
            }
            let result = runner
                .step("baseline/sandboxes")
                .with_timeout(remaining.min(Duration::from_secs(10)))
                .run(&["sandbox", "list", "--output", "json"])
                .await
                .map_err(|error| error.to_string())?;
            result.require_success()?;
            let page = result
                .json::<SandboxPage>()
                .map_err(|error| error.to_string())?;
            if page.sandboxes.is_empty() && page.next_page_token.is_empty() {
                break;
            }
            eprintln!("waiting for sandbox cleanup: {} entries remain on the first page", page.sandboxes.len());
            sleep(Duration::from_millis(250)).await;
        }
        Ok(())
    }
    .await;
    runner.finish(result).await
}

async fn command(program: &str, arguments: &[&str], input: Option<&str>) -> Result<String, String> {
    let operation = async {
        let mut child = Command::new(program)
            .args(arguments)
            .kill_on_drop(true)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| error.to_string())?;
        if let Some(input) = input {
            let mut stdin = child.stdin.take().ok_or("command stdin was not piped")?;
            stdin
                .write_all(input.as_bytes())
                .await
                .map_err(|error| error.to_string())?;
        }
        let output = child
            .wait_with_output()
            .await
            .map_err(|error| error.to_string())?;
        if !output.status.success() {
            return Err(format!(
                "{program} {arguments:?} exited {}:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    };
    timeout(COMMAND_TIMEOUT, operation)
        .await
        .map_err(|_| format!("{program} {arguments:?} timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_only_change_podman_user_namespace_settings() {
        let baseline = "[openshell.drivers.podman]\nsocket_path = '/run/podman/podman.sock'\n[other]\nvalue = 7\n";
        for profile in [
            Profile::Default,
            Profile::Auto,
            Profile::KeepId,
            Profile::Private,
        ] {
            let config = profile
                .configuration(baseline)
                .unwrap()
                .parse::<DocumentMut>()
                .unwrap();
            assert_eq!(config["other"]["value"].as_integer(), Some(7));
            assert_eq!(
                config["openshell"]["drivers"]["podman"]["socket_path"].as_str(),
                Some("/run/podman/podman.sock")
            );
        }
        let private = Profile::Private
            .configuration(baseline)
            .unwrap()
            .parse::<DocumentMut>()
            .unwrap();
        assert_eq!(
            private["openshell"]["drivers"]["podman"]["uidmap"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
}

// Executed explicitly during fixture validation, not normal qualification.
#[cfg(feature = "fixture-validation")]
#[tokio::test]
async fn deliberate_panic_after_sandbox_creation() {
    with_profile(Profile::Auto, async |gateway, runner| {
        super::helpers::assert_workspace_and_uid_map(gateway, runner).await?;
        panic!("injected scenario assertion failure");
    })
    .await
    .expect("injected failure must remain a failed test");
}
