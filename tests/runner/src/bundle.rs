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
//! `build` writes a bundle to a directory, so CI can build it once and every
//! row can run it (`run --bundle`). A `bundle.json` in it names the family
//! and the packages it was built with.
//!
//! A family that ships a prebuilt test program, such as `openshell-conformance`,
//! can run it instead: the bundle then holds that program alone, built once
//! elsewhere for the guest target, and the runner builds nothing.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
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

/// The nextest archive in a nextest bundle.
const ARCHIVE: &str = "tests.tar.zst";
/// The nextest config in a nextest bundle.
const CONFIG: &str = "nextest.toml";
/// What a nextest bundle was built from.
const MANIFEST: &str = "bundle.json";

/// The family and packages a nextest bundle holds.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Manifest {
    family: String,
    /// Empty when the bundle holds every package in the family.
    packages: Vec<String>,
}

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
fn guest_target() -> Result<&'static str> {
    if cfg!(target_arch = "x86_64") {
        Ok("x86_64-unknown-linux-musl")
    } else if cfg!(target_arch = "aarch64") {
        Ok("aarch64-unknown-linux-musl")
    } else {
        bail!("tmachine can't boot guests on this host's architecture")
    }
}

/// Build `testkit-ready` for the guest and return its path.
fn build_ready(root: &Path, target: &str) -> Result<PathBuf> {
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

/// Build the bundle for `family` into a new temporary directory.
pub fn build_temp(root: &Path, family: &str, packages: &[String]) -> Result<Bundle> {
    let dir = tempfile::tempdir().context("create bundle directory")?;
    build(root, family, packages, dir.path())?;
    Ok(Bundle(dir, Kind::Nextest))
}

/// Build the bundle for `family`, the path of a workspace under
/// `tests/suites/`, into `out`, an empty or missing directory. With no
/// `packages`, the archive holds every package in the workspace.
pub fn build(root: &Path, family: &str, packages: &[String], out: &Path) -> Result<()> {
    let workspace = crate::family_workspace(root, family)?;
    let manifest = workspace.join("Cargo.toml");
    ensure!(
        manifest.is_file(),
        "{} is not a test family workspace",
        workspace.display()
    );
    std::fs::create_dir_all(out).with_context(|| format!("create {}", out.display()))?;
    ensure!(
        std::fs::read_dir(out)?.next().is_none(),
        "{} is not empty",
        out.display()
    );
    let target = guest_target()?;
    eprintln!("==> building {READY_BINARY} for {target}");
    let ready = build_ready(root, target)?;

    eprintln!("==> building the {family} tests for {target}");
    let mut command = Command::new("cargo");
    command
        .args(["nextest", "archive", "--locked", "--manifest-path"])
        .arg(&manifest)
        .args(["--target", target, "--archive-file"])
        .arg(out.join(ARCHIVE));
    if packages.is_empty() {
        command.arg("--workspace");
    }
    for package in packages {
        command.args(["-p", package]);
    }
    run(&mut command).with_context(|| format!("build the {} test archive", workspace.display()))?;

    copy_manifests(&workspace, out)?;
    std::fs::write(out.join(CONFIG), NEXTEST_CONFIG)?;
    std::fs::copy(&ready, out.join(READY_BINARY))
        .with_context(|| format!("copy {}", ready.display()))?;
    let manifest = Manifest {
        family: family.to_string(),
        packages: packages.to_vec(),
    };
    std::fs::write(out.join(MANIFEST), serde_json::to_vec_pretty(&manifest)?)?;
    Ok(())
}

/// A bundle that `build` wrote to `dir`, for running `packages` of `family`
/// (every package in it when empty). The bundle is copied, so `dir` may have
/// lost the executable bits, as a downloaded CI artifact does.
pub fn prebuilt(dir: &Path, family: &str, packages: &[String]) -> Result<Bundle> {
    let read = std::fs::read(dir.join(MANIFEST))
        .with_context(|| format!("{} is not a test bundle: read {MANIFEST}", dir.display()))?;
    let manifest: Manifest = serde_json::from_slice(&read)
        .with_context(|| format!("parse {}", dir.join(MANIFEST).display()))?;
    check_selection(&manifest, family, packages)
        .with_context(|| format!("--bundle {}", dir.display()))?;
    for name in [ARCHIVE, CONFIG, READY_BINARY] {
        ensure!(
            dir.join(name).is_file(),
            "{} is not a test bundle: it has no {name}",
            dir.display()
        );
    }

    let copy = tempfile::tempdir().context("create bundle directory")?;
    copy_tree(dir, copy.path())?;
    let ready = copy.path().join(READY_BINARY);
    std::fs::set_permissions(&ready, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("make {} executable", ready.display()))?;
    Ok(Bundle(copy, Kind::Nextest))
}

/// Check that a bundle built from `manifest` holds `packages` of `family`.
fn check_selection(manifest: &Manifest, family: &str, packages: &[String]) -> Result<()> {
    ensure!(
        manifest.family == family,
        "the bundle holds the {} tests, not {family}",
        manifest.family
    );
    if manifest.packages.is_empty() {
        return Ok(());
    }
    let missing: Vec<_> = if packages.is_empty() {
        vec!["every package"]
    } else {
        packages
            .iter()
            .filter(|package| !manifest.packages.contains(package))
            .map(String::as_str)
            .collect()
    };
    ensure!(
        missing.is_empty(),
        "the bundle holds only {}, not {}",
        manifest.packages.join(", "),
        missing.join(", ")
    );
    Ok(())
}

/// The nextest filtersets that run the tests of `packages` that match any of
/// `filters`. nextest runs the tests that match any `-E`, so the packages and
/// the filters go in one expression.
pub fn narrow(packages: &[String], filters: &[String]) -> Vec<String> {
    if packages.is_empty() {
        return filters.to_vec();
    }
    let packages = packages
        .iter()
        .map(|package| format!("package(={package})"))
        .collect::<Vec<_>>()
        .join(" | ");
    if filters.is_empty() {
        return vec![packages];
    }
    let filters = filters
        .iter()
        .map(|filter| format!("({filter})"))
        .collect::<Vec<_>>()
        .join(" | ");
    vec![format!("({packages}) & ({filters})")]
}

/// Copy the files under `src` into `dst`, keeping relative paths.
fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    for entry in std::fs::read_dir(src).with_context(|| format!("read {}", src.display()))? {
        let path = entry?.path();
        let dest = dst.join(path.file_name().unwrap_or_default());
        if path.is_dir() {
            std::fs::create_dir_all(&dest)?;
            copy_tree(&path, &dest)?;
        } else {
            std::fs::copy(&path, &dest).with_context(|| format!("copy {}", path.display()))?;
        }
    }
    Ok(())
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

    fn write_bundle(dir: &Path, family: &str, packages: &[&str]) {
        std::fs::create_dir_all(dir.join("host-gateway")).unwrap();
        for name in [ARCHIVE, CONFIG, READY_BINARY, "Cargo.toml"] {
            std::fs::write(dir.join(name), name).unwrap();
        }
        std::fs::write(dir.join("host-gateway/Cargo.toml"), "member").unwrap();
        let manifest = Manifest {
            family: family.to_string(),
            packages: packages.iter().map(ToString::to_string).collect(),
        };
        std::fs::write(dir.join(MANIFEST), serde_json::to_vec(&manifest).unwrap()).unwrap();
    }

    #[test]
    fn prebuilt_bundle_is_copied_with_an_executable_ready_check() {
        let dir = tempfile::tempdir().unwrap();
        write_bundle(dir.path(), "features", &[]);
        let bundle = prebuilt(dir.path(), "features", &["host-gateway".to_string()]).unwrap();
        assert_eq!(bundle.kind(), Kind::Nextest);
        assert_ne!(bundle.path(), dir.path());
        assert_eq!(
            std::fs::read(bundle.path().join("host-gateway/Cargo.toml")).unwrap(),
            b"member"
        );
        let mode = std::fs::metadata(bundle.path().join(READY_BINARY))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o111, 0o111);
    }

    #[test]
    fn prebuilt_bundle_must_be_complete_and_of_the_family() {
        let dir = tempfile::tempdir().unwrap();
        assert!(prebuilt(dir.path(), "features", &[]).is_err());
        write_bundle(dir.path(), "features", &[]);
        assert!(prebuilt(dir.path(), "drivers/podman", &[]).is_err());
        std::fs::remove_file(dir.path().join(ARCHIVE)).unwrap();
        assert!(prebuilt(dir.path(), "features", &[]).is_err());
    }

    #[test]
    fn selection_must_be_in_the_bundle() {
        let some = Manifest {
            family: "features".to_string(),
            packages: vec!["oci-image".to_string()],
        };
        let check = |packages: &[&str]| {
            let packages: Vec<_> = packages.iter().map(ToString::to_string).collect();
            check_selection(&some, "features", &packages)
        };
        assert!(check(&["oci-image"]).is_ok());
        assert!(check(&["host-gateway"]).is_err());
        assert!(check(&[]).is_err());
    }

    #[test]
    fn narrow_combines_packages_and_filters() {
        let strings = |items: &[&str]| items.iter().map(ToString::to_string).collect::<Vec<_>>();
        assert_eq!(narrow(&[], &strings(&["test(a)"])), strings(&["test(a)"]));
        assert_eq!(
            narrow(&strings(&["oci-image", "host-gateway"]), &[]),
            strings(&["package(=oci-image) | package(=host-gateway)"])
        );
        assert_eq!(
            narrow(&strings(&["oci-image"]), &strings(&["test(a)", "test(b)"])),
            strings(&["(package(=oci-image)) & ((test(a)) | (test(b)))"])
        );
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
