// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[path = "../build_support/git.rs"]
mod git;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn run_git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("git output is UTF-8")
        .trim()
        .to_owned()
}

fn init_repository() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().expect("create temp directory");
    let repo = temp.path().join("repo");
    fs::create_dir(&repo).expect("create repository directory");

    run_git(&repo, &["init", "--quiet"]);
    run_git(&repo, &["config", "user.name", "OpenShell Test"]);
    run_git(
        &repo,
        &["config", "user.email", "openshell@example.invalid"],
    );
    fs::write(repo.join("README.md"), "test\n").expect("write tracked file");
    run_git(&repo, &["add", "README.md"]);
    run_git(&repo, &["commit", "--quiet", "-m", "initial"]);
    run_git(&repo, &["tag", "v0.0.1"]);

    (temp, repo)
}

fn git_path(repo: &Path, path: &str) -> PathBuf {
    let path = PathBuf::from(run_git(repo, &["rev-parse", "--git-path", path]));
    if path.is_absolute() {
        path
    } else {
        repo.join(path)
    }
}

#[test]
fn resolves_metadata_paths_in_normal_checkout() {
    let (_temp, repo) = init_repository();

    let paths = git::watch_paths(&repo);
    let head_ref = run_git(&repo, &["symbolic-ref", "HEAD"]);

    assert!(paths.contains(&git_path(&repo, "HEAD")));
    assert!(paths.contains(&git_path(&repo, &head_ref)));
    assert!(paths.contains(&git_path(&repo, "refs/tags")));
    assert!(paths.iter().all(|path| path.exists()));
}

#[test]
fn resolves_metadata_paths_in_linked_worktree() {
    let (temp, repo) = init_repository();
    let worktree = temp.path().join("linked");
    let worktree_arg = worktree.to_str().expect("worktree path is UTF-8");
    run_git(
        &repo,
        &["worktree", "add", "--quiet", "-b", "linked", worktree_arg],
    );

    let paths = git::watch_paths(&worktree);
    let head = git_path(&worktree, "HEAD");
    let head_ref = run_git(&worktree, &["symbolic-ref", "HEAD"]);

    assert!(paths.contains(&head));
    assert_ne!(head, worktree.join(".git/HEAD"));
    assert!(paths.contains(&git_path(&worktree, &head_ref)));
    assert!(paths.contains(&git_path(&worktree, "refs/tags")));
    assert!(paths.iter().all(|path| path.exists()));
}

#[test]
fn watches_packed_refs() {
    let (_temp, repo) = init_repository();
    run_git(&repo, &["pack-refs", "--all"]);

    let paths = git::watch_paths(&repo);

    assert!(paths.contains(&git_path(&repo, "packed-refs")));
}

#[test]
fn detached_head_does_not_require_a_symbolic_ref() {
    let (_temp, repo) = init_repository();
    run_git(&repo, &["checkout", "--quiet", "--detach"]);

    let paths = git::watch_paths(&repo);

    assert!(paths.contains(&git_path(&repo, "HEAD")));
    assert!(paths.iter().all(|path| path.exists()));
}

#[test]
fn ignores_source_tree_without_git_metadata() {
    let temp = tempfile::tempdir().expect("create temp directory");

    assert!(git::watch_paths(temp.path()).is_empty());
}
