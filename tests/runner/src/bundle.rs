// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Building a family's test bundle for the guest, on the host.
//!
//! A bundle is a directory holding a nextest archive built for the guest target,
//! the family workspace's `Cargo.toml` files (for `--workspace-remap`), a
//! `nextest` config with the runner's `JUnit` profile, and `testkit-ready`,
//! which waits for the gateway before the tests run. The guest needs only the
//! `cargo-nextest` binary to run it.
//!
//! A family that ships a prebuilt test program, such as `openshell-conformance`,
//! can run it instead: the bundle then holds that program alone, built once
//! elsewhere for the guest target, and the runner builds nothing.

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

/// The prebuilt program's name in a program bundle.
pub const PROGRAM_BINARY: &str = "test-program";

/// What a bundle runs the tests with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A nextest archive, run with `cargo-nextest`.
    Nextest,
    /// A prebuilt testkit program (`list`, `ready` and `run`), run directly.
    Program,
}

/// The bundle directory, removed when this is dropped.
pub struct Bundle(TempDir, Kind);

impl Bundle {
    pub fn path(&self) -> &Path {
        self.0.path()
    }

    pub const fn kind(&self) -> Kind {
        self.1
    }
}

/// A bundle holding only `program`, a testkit program already built for the
/// guest target. `program` must be a static binary, as the guest's libc is
/// not known.
pub fn program(program: &Path) -> Result<Bundle> {
    ensure!(
        program.is_file(),
        "--program {} is not a file",
        program.display()
    );
    let dir = tempfile::tempdir().context("create bundle directory")?;
    std::fs::copy(program, dir.path().join(PROGRAM_BINARY))
        .with_context(|| format!("copy {}", program.display()))?;
    Ok(Bundle(dir, Kind::Program))
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
    let stage = dir.path();
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

    copy_manifests(workspace, stage)?;
    std::fs::write(stage.join("nextest.toml"), NEXTEST_CONFIG)?;
    std::fs::copy(ready, stage.join(READY_BINARY))
        .with_context(|| format!("copy {}", ready.display()))?;
    Ok(Bundle(dir, Kind::Nextest))
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
    fn program_bundle_holds_only_the_program() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("openshell-conformance");
        std::fs::write(&path, b"binary").unwrap();
        let bundle = program(&path).unwrap();
        assert_eq!(bundle.kind(), Kind::Program);
        let names: Vec<_> = std::fs::read_dir(bundle.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, [PROGRAM_BINARY]);
        assert!(program(&dir.path().join("missing")).is_err());
    }

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
