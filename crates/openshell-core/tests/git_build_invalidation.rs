// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Exercise Cargo's actual invalidation with the production Git/version helper.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

struct Fixture {
    temp: tempfile::TempDir,
    repo: PathBuf,
    checkout: PathBuf,
    target: PathBuf,
}

struct Build {
    version: String,
    runs: usize,
}

fn output(command: &mut Command) -> String {
    let output = command.output().expect("command should start");
    assert!(
        output.status.success(),
        "{command:?} failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8(output.stdout)
        .expect("command output should be UTF-8")
        .trim()
        .to_owned()
}

fn git(repo: &Path, args: &[&str]) -> String {
    output(git_command(repo).args(args))
}

fn isolate_git(command: &mut Command) -> &mut Command {
    // Hooks and CI can export Git context. Fixture ref writes must never use
    // the parent checkout's Git directory, object store, config, or hooks.
    for name in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "GIT_TEMPLATE_DIR",
    ] {
        command.env_remove(name);
    }
    command.env("GIT_CONFIG_NOSYSTEM", "1").env(
        "GIT_CONFIG_GLOBAL",
        if cfg!(windows) { "NUL" } else { "/dev/null" },
    )
}

fn git_command(repo: &Path) -> Command {
    let mut command = Command::new("git");
    isolate_git(&mut command).arg("-C").arg(repo);
    command
}

fn object(repo: &Path, kind: &str, body: &str) -> String {
    let mut child = git_command(repo)
        .args(["hash-object", "-t", kind, "-w", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("object writer should start");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(body.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

impl Fixture {
    fn new(linked: bool) -> Self {
        Self::with_ref_format(linked, None)
    }

    fn with_ref_format(linked: bool, ref_format: Option<&str>) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repository with spaces");
        fs::create_dir(&repo).unwrap();
        let mut init = git_command(&repo);
        init.args(["init", "--quiet", "--initial-branch=main"]);
        if let Some(ref_format) = ref_format {
            init.arg(format!("--ref-format={ref_format}"));
        }
        output(&mut init);
        // Inert objects exercise ref movement without user identity, signing,
        // hooks, or a commit command that can prompt for a hardware key.
        let tree = object(&repo, "tree", "");
        let initial = object(
            &repo,
            "commit",
            &format!(
                "tree {tree}\nauthor Fixture <fixture@example.invalid> 1700000000 +0000\ncommitter Fixture <fixture@example.invalid> 1700000000 +0000\n\ninitial\n"
            ),
        );
        git(&repo, &["update-ref", "refs/heads/main", &initial]);
        git(&repo, &["update-ref", "refs/tags/v0.1.0", &initial]);
        let checkout = if linked {
            let checkout = temp.path().join("linked worktree");
            git(
                &repo,
                &[
                    "worktree",
                    "add",
                    "--quiet",
                    "-b",
                    "linked",
                    checkout.to_str().unwrap(),
                ],
            );
            checkout
        } else {
            repo.clone()
        };
        let fixture = Self {
            target: temp.path().join("target"),
            temp,
            repo,
            checkout,
        };
        fixture.install_crate();
        fixture
    }

    fn install_crate(&self) {
        fs::create_dir_all(self.checkout.join("src")).unwrap();
        fs::create_dir_all(self.checkout.join("build_support")).unwrap();
        fs::write(self.checkout.join("Cargo.toml"), "[package]\nname = \"git-version-probe\"\nversion = \"9.8.7\"\nedition = \"2021\"\n[workspace]\n").unwrap();
        fs::write(
            self.checkout.join("src/main.rs"),
            "fn main() { println!(\"{}\", env!(\"PROBE_VERSION\")); }\n",
        )
        .unwrap();
        fs::write(
            self.checkout.join("build_support/git.rs"),
            include_bytes!("../build_support/git.rs"),
        )
        .unwrap();
        fs::write(
            self.checkout.join("build_version.rs"),
            include_bytes!("../build_version.rs"),
        )
        .unwrap();
        fs::write(self.checkout.join("build.rs"), r#"
#[path = "build_support/git.rs"]
mod git;
use std::io::Write;
fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest = std::path::Path::new(&manifest);
    // Stand in for the core build script's explicit protobuf input tracking.
    println!("cargo:rerun-if-changed=build.rs");
    git::emit_rerun_if_changed(manifest);
    let version = git::version(manifest).unwrap_or_else(|| "9.8.7".into());
    println!("cargo:rustc-env=PROBE_VERSION={version}");
    let mut runs = std::fs::OpenOptions::new().create(true).append(true).open(manifest.join("probe-runs")).unwrap();
    writeln!(runs, "run").unwrap();
}
"#).unwrap();
    }

    fn advance(&self) -> String {
        let parent = git(&self.checkout, &["rev-parse", "HEAD"]);
        let tree = git(&self.checkout, &["rev-parse", "HEAD:"]);
        let next = object(
            &self.repo,
            "commit",
            &format!(
                "tree {tree}\nparent {parent}\nauthor Fixture <fixture@example.invalid> 1700000001 +0000\ncommitter Fixture <fixture@example.invalid> 1700000001 +0000\n\nnext\n"
            ),
        );
        git(&self.checkout, &["update-ref", "HEAD", &next]);
        next
    }

    fn build(&self) -> Build {
        // Each fixture has its own target; nested Cargo never contends for the
        // parent test binary's target lock or a sibling worktree's artifacts.
        output(
            isolate_git(&mut Command::new(env!("CARGO")))
                .current_dir(&self.checkout)
                .args(["build", "--offline", "--quiet"])
                .env("CARGO_TARGET_DIR", &self.target)
                .env_remove("RUSTC_WRAPPER")
                .env_remove("RUSTC_WORKSPACE_WRAPPER"),
        );
        let executable = self
            .target
            .join("debug")
            .join(format!("git-version-probe{}", std::env::consts::EXE_SUFFIX));
        Build {
            version: output(&mut Command::new(executable)),
            runs: fs::read_to_string(self.checkout.join("probe-runs"))
                .unwrap()
                .lines()
                .count(),
        }
    }

    fn assert_fresh(&self, previous: &Build) {
        let next = self.build();
        assert_eq!(next.version, previous.version);
        assert_eq!(
            next.runs, previous.runs,
            "unchanged inputs must not rerun the build script"
        );
    }
}

#[test]
fn normal_repository_reuses_build_and_refreshes_revision() {
    let fixture = Fixture::new(false);
    let first = fixture.build();
    assert_eq!(first.version, "0.1.0");
    fixture.assert_fresh(&first);
    fixture.advance();
    let next = fixture.build();
    let sha = git(&fixture.checkout, &["rev-parse", "--short=9", "HEAD"]);
    assert_eq!(next.version, format!("0.1.1-dev.1+g{sha}"));
    assert_eq!(next.runs, first.runs + 1);
    fixture.assert_fresh(&next);
}

#[test]
fn linked_worktree_detects_packed_to_loose_branch_and_tag_changes() {
    assert_branch_and_tag_changes(Fixture::new(true));
}

#[test]
fn linked_reftable_worktree_refreshes_shared_tags() {
    // Older Git installations cannot create reftable repositories. Keep the
    // files-backend regressions active there and report this optional skip.
    let help = isolate_git(&mut Command::new("git"))
        .args(["init", "-h"])
        .output()
        .expect("Git should be installed");
    if !String::from_utf8_lossy(&help.stdout).contains("--ref-format")
        && !String::from_utf8_lossy(&help.stderr).contains("--ref-format")
    {
        eprintln!("skipping reftable regression: Git lacks init --ref-format");
        return;
    }
    assert_branch_and_tag_changes(Fixture::with_ref_format(true, Some("reftable")));
}

fn assert_branch_and_tag_changes(fixture: Fixture) {
    git(&fixture.repo, &["pack-refs", "--all"]);
    let first = fixture.build();
    fixture.assert_fresh(&first);
    fixture.advance();
    let next = fixture.build();
    assert_ne!(next.version, first.version);
    assert_eq!(next.runs, first.runs + 1);
    fixture.assert_fresh(&next);

    git(
        &fixture.checkout,
        &["update-ref", "refs/tags/v0.2.0", "HEAD"],
    );
    let tagged = fixture.build();
    assert_eq!(tagged.version, "0.2.0");
    assert_eq!(tagged.runs, next.runs + 1);
    fixture.assert_fresh(&tagged);
    git(&fixture.repo, &["pack-refs", "--all"]);
    let packed = fixture.build();
    assert_eq!(packed.version, tagged.version);
    fixture.assert_fresh(&packed);
    git(&fixture.repo, &["update-ref", "-d", "refs/tags/v0.2.0"]);
    let removed = fixture.build();
    assert_eq!(removed.version, next.version);
    assert_eq!(removed.runs, packed.runs + 1);
    fixture.assert_fresh(&removed);
}

#[test]
fn branch_switch_and_detached_head_refresh_version() {
    let fixture = Fixture::new(true);
    fixture.advance();
    let first = fixture.build();
    git(
        &fixture.checkout,
        &["switch", "--quiet", "--detach", "v0.1.0"],
    );
    let detached = fixture.build();
    assert_eq!(detached.version, "0.1.0");
    assert_eq!(detached.runs, first.runs + 1);
    fixture.assert_fresh(&detached);
    fixture.advance();
    let advanced = fixture.build();
    assert_ne!(advanced.version, detached.version);
    assert_eq!(advanced.runs, detached.runs + 1);
    fixture.assert_fresh(&advanced);
    git(&fixture.checkout, &["switch", "--quiet", "linked"]);
    let attached = fixture.build();
    assert_eq!(attached.version, first.version);
    assert_eq!(attached.runs, advanced.runs + 1);
    fixture.assert_fresh(&attached);
}

#[test]
fn source_archive_reuses_build_without_git_metadata() {
    let mut fixture = Fixture::new(false);
    fixture.checkout = fixture.temp.path().join("archive");
    fixture.install_crate();
    let first = fixture.build();
    assert_eq!(first.version, "9.8.7");
    fixture.assert_fresh(&first);
}
