// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Building a family's test bundle for the guest.
//!
//! A bundle is a tar holding a nextest archive built for the guest target,
//! the family workspace's `Cargo.toml` files (for `--workspace-remap`), a
//! `nextest` config with the runner's `JUnit` profile, and `testkit-ready`,
//! which waits for the gateway before the tests run. The guest needs only the
//! `cargo-nextest` binary to run it.
//!
//! Adapted from the bundle builder in Evan Lezar's NVIDIA/OpenShell#4629.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use tempfile::TempDir;

use crate::catalog::Family;
use crate::environments::Arch;

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

/// The Rust target for guests of `arch`. Static musl binaries don't depend
/// on the guest's libc.
pub const fn guest_target(arch: Arch) -> &'static str {
    match arch {
        Arch::Amd64 => "x86_64-unknown-linux-musl",
        Arch::Arm64 => "aarch64-unknown-linux-musl",
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

/// Build the bundle for `packages`, and check that the archive contains a
/// binary for every suite in `binaries`. `ready` is the guest's
/// `testkit-ready`.
pub fn build(
    family: &Family,
    packages: &BTreeSet<String>,
    binaries: &BTreeSet<String>,
    target: &str,
    ready: &Path,
) -> Result<Bundle> {
    let dir = tempfile::tempdir().context("create bundle directory")?;
    let stage = dir.path().join("stage");
    std::fs::create_dir(&stage)?;
    let manifest = family.workspace.join("Cargo.toml");
    let archive = stage.join("tests.tar.zst");

    let mut command = Command::new("cargo");
    command
        .args(["nextest", "archive", "--locked", "--manifest-path"])
        .arg(&manifest)
        .args(["--target", target, "--archive-file"])
        .arg(&archive);
    for package in packages {
        command.args(["-p", package]);
    }
    run(&mut command).with_context(|| format!("build {} test archive", family.name))?;

    let archived = archived_binaries(&manifest, &archive)?;
    let missing: Vec<_> = binaries.difference(&archived).collect();
    ensure!(
        missing.is_empty(),
        "the {} catalog lists suites the archive has no test binary for: {missing:?}; archived: {archived:?}",
        family.name
    );

    copy_manifests(&family.workspace, &stage)?;
    std::fs::write(stage.join("nextest.toml"), NEXTEST_CONFIG)?;
    std::fs::copy(ready, stage.join(READY_BINARY))
        .with_context(|| format!("copy {}", ready.display()))?;

    let path = dir.path().join(format!("{}-tests.tar", family.name));
    run(Command::new("tar")
        .arg("-C")
        .arg(&stage)
        .arg("-cf")
        .arg(&path)
        .arg("."))
    .context("pack test bundle")?;
    Ok(Bundle { path, _dir: dir })
}

#[derive(Deserialize)]
struct ListOutput {
    #[serde(rename = "rust-binaries")]
    rust_binaries: std::collections::BTreeMap<String, ListSuite>,
}

#[derive(Deserialize)]
struct ListSuite {
    #[serde(rename = "binary-name")]
    binary_name: String,
    kind: String,
}

/// Names of the test binaries in an archive, read without executing them.
fn archived_binaries(manifest: &Path, archive: &Path) -> Result<BTreeSet<String>> {
    let output = Command::new("cargo")
        .args(["nextest", "list", "--manifest-path"])
        .arg(manifest)
        .arg("--archive-file")
        .arg(archive)
        .args(["--list-type", "binaries-only", "--message-format", "json"])
        .output()
        .context("run cargo nextest list")?;
    ensure!(
        output.status.success(),
        "cargo nextest list exited with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let list: ListOutput =
        serde_json::from_slice(&output.stdout).context("parse cargo nextest list output")?;
    Ok(list
        .rust_binaries
        .into_values()
        .filter(|suite| suite.kind == "test")
        .map(|suite| suite.binary_name)
        .collect())
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
