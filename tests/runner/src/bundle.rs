// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Building a family's test bundle for the guest, on the host.
//!
//! A bundle is a tar holding a nextest archive built for the guest target,
//! the family workspace's `Cargo.toml` files (for `--workspace-remap`), a
//! `nextest` config with the runner's `JUnit` profile, and `testkit-ready`,
//! which waits for the gateway before the tests run. The guest needs only the
//! `cargo-nextest` binary to run it.
//!
//! Building is separate from running, so a prebuilt bundle can be passed in
//! later instead.
//!
//! Adapted from the bundle builder in Evan Lezar's NVIDIA/OpenShell#4629.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use tempfile::TempDir;

/// The nextest profile the runner uses in the guest.
pub const PROFILE: &str = "openshell";

/// The readiness check every bundle carries, at the bundle root.
pub const READY_BINARY: &str = "testkit-ready";

/// Nextest flags a test as slow after the period and terminates it after
/// `terminate-after` periods, so a hung test fails after two minutes instead
/// of holding the lane until the job times out.
const NEXTEST_CONFIG: &str = r#"# Written by the OpenShell test runner.
[profile.openshell]
fail-fast = false
slow-timeout = { period = "30s", terminate-after = 4 }

[profile.openshell.junit]
path = "junit.xml"
"#;

pub struct Bundle {
    pub path: PathBuf,
    _dir: TempDir,
}

/// The Rust target for guests. tmachine only boots guests of the host's
/// architecture, and static musl binaries don't depend on the guest's libc.
pub fn guest_target() -> Result<&'static str> {
    if cfg!(target_arch = "x86_64") {
        Ok("x86_64-unknown-linux-musl")
    } else if cfg!(target_arch = "aarch64") {
        Ok("aarch64-unknown-linux-musl")
    } else {
        bail!("tmachine can't boot guests on this host's architecture")
    }
}

/// Build `testkit-ready` for the guest and return its path.
pub fn build_ready(root: &Path, target: &str) -> Result<PathBuf> {
    let output = Command::new("cargo")
        .args(["build", "--locked", "--manifest-path"])
        .arg(root.join("tests/testkit/Cargo.toml"))
        .args(["-p", "openshell-testkit", "--bin", READY_BINARY])
        .args([
            "--target",
            target,
            "--message-format",
            "json-render-diagnostics",
        ])
        .stderr(std::process::Stdio::inherit())
        .output()
        .context("run cargo build")?;
    ensure!(
        output.status.success(),
        "build {READY_BINARY} exited with {}",
        output.status
    );
    built_executable(&output.stdout, READY_BINARY)
        .with_context(|| format!("cargo build did not report a {READY_BINARY} executable"))
}

/// The executable cargo reports building for the binary target `name`.
fn built_executable(messages: &[u8], name: &str) -> Option<PathBuf> {
    #[derive(Deserialize)]
    struct Message {
        reason: String,
        target: Option<Target>,
        executable: Option<PathBuf>,
    }
    #[derive(Deserialize)]
    struct Target {
        name: String,
    }

    serde_json::Deserializer::from_slice(messages)
        .into_iter::<Message>()
        .filter_map(std::result::Result::ok)
        .filter(|message| message.reason == "compiler-artifact")
        .filter(|message| {
            message
                .target
                .as_ref()
                .is_some_and(|target| target.name == name)
        })
        .find_map(|message| message.executable)
}

/// Build the bundle for a family workspace (`tests/suites/<family>`). With no
/// `packages`, the archive holds every package in the workspace. `ready` is
/// the guest's `testkit-ready`.
pub fn build(workspace: &Path, packages: &[String], target: &str, ready: &Path) -> Result<Bundle> {
    let dir = tempfile::tempdir().context("create bundle directory")?;
    let stage = dir.path().join("stage");
    std::fs::create_dir(&stage)?;
    let manifest = workspace.join("Cargo.toml");
    ensure!(
        manifest.is_file(),
        "{} is not a test family workspace",
        workspace.display()
    );
    let archive = stage.join("tests.tar.zst");

    let mut command = Command::new("cargo");
    command
        .args(["nextest", "archive", "--locked", "--manifest-path"])
        .arg(&manifest)
        .args(["--target", target, "--archive-file"])
        .arg(&archive);
    if packages.is_empty() {
        command.arg("--workspace");
    }
    for package in packages {
        command.args(["-p", package]);
    }
    run(&mut command).with_context(|| format!("build the {} test archive", workspace.display()))?;

    copy_manifests(workspace, &stage)?;
    std::fs::write(stage.join("nextest.toml"), NEXTEST_CONFIG)?;
    std::fs::copy(ready, stage.join(READY_BINARY))
        .with_context(|| format!("copy {}", ready.display()))?;

    let path = dir.path().join("tests.tar");
    run(Command::new("tar")
        .arg("-C")
        .arg(&stage)
        .arg("-cf")
        .arg(&path)
        .arg("."))
    .context("pack test bundle")?;
    Ok(Bundle { path, _dir: dir })
}

/// Copy every `Cargo.toml` under `workspace` into `stage`, keeping relative
/// paths and skipping build output.
fn copy_manifests(workspace: &Path, stage: &Path) -> Result<()> {
    fn walk(root: &Path, dir: &Path, stage: &Path) -> Result<()> {
        for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
            let path = entry?.path();
            let name = path.file_name().unwrap_or_default();
            if path.is_dir() {
                if name != "target" && name != ".git" {
                    walk(root, &path, stage)?;
                }
            } else if name == "Cargo.toml" {
                let dest = stage.join(path.strip_prefix(root)?);
                std::fs::create_dir_all(dest.parent().unwrap_or(stage))?;
                std::fs::copy(&path, &dest).with_context(|| format!("copy {}", path.display()))?;
            }
        }
        Ok(())
    }
    walk(workspace, workspace, stage)
}

fn run(command: &mut Command) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("run {command:?}"))?;
    if !status.success() {
        bail!("{command:?} exited with {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_executable_finds_the_named_binary() {
        let messages = br#"{"reason":"compiler-artifact","target":{"name":"testkit"},"executable":null}
{"reason":"compiler-artifact","target":{"name":"testkit-ready"},"executable":"/t/debug/testkit-ready"}
{"reason":"build-finished","success":true}
"#;
        assert_eq!(
            built_executable(messages, "testkit-ready"),
            Some(PathBuf::from("/t/debug/testkit-ready"))
        );
        assert_eq!(built_executable(messages, "other"), None);
    }
}
