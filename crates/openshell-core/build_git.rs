// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use crate::build_version;

/// Track Git's resolved metadata, including creation of previously packed refs.
///
/// `source_root` is the source checkout. Git metadata is used only when that
/// directory has its own `.git`, so an archive nested in another repository
/// neither adopts nor watches that repository.
pub fn emit_rerun_if_changed(source_root: &Path) {
    // Ref directories must be watched whole: a packed branch has no loose file
    // until its next update. Watching only existing individual refs misses it.
    // Only heads and tags feed the version; remotes and stash would rebuild
    // on every fetch or stash. reftable/ covers that ref backend.
    let mut paths = BTreeSet::new();
    for name in [
        "HEAD",
        "refs/heads",
        "refs/tags",
        "packed-refs",
        "reftable",
        "shallow",
    ] {
        let Some(path) = git_output(source_root, &["rev-parse", "--git-path", name]) else {
            continue;
        };
        paths.insert(source_root.join(path));
    }
    // A linked worktree's reftable holds its private refs, including HEAD.
    // Shared branches and tags live in the common directory's separate table.
    if let Some(common_dir) = git_output(source_root, &["rev-parse", "--git-common-dir"]) {
        paths.insert(source_root.join(common_dir).join("reftable"));
    }
    for path in paths {
        // Missing Git metadata is normal in archives and container builds.
        // Cargo reruns indefinitely for a watched file that never exists.
        if path.exists() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

/// Derive the release or development version from git metadata.
///
/// Implements the "guess-next-dev" convention used by the release pipeline
/// (`tasks/scripts/release.py`): exact stable and prerelease tags retain their
/// version. Otherwise, the latest merged stable release gets a patch bump and
/// `-dev.<N>+g<sha>` is appended.
///
/// Examples:
///   on tag v0.1.0-pre.1    → "0.1.0-pre.1"
///   3 commits past v0.0.3  → "0.0.4-dev.3+g2bf9969ab"
///
/// Returns `None` when `source_root` has no `.git` of its own or its metadata
/// cannot be read.
pub fn version(source_root: &Path) -> Option<String> {
    let exact_tags = git_output(source_root, &["tag", "--points-at", "HEAD"])?;
    if let Some(version) = build_version::exact_release_version(exact_tags.lines()) {
        return Some(version);
    }

    let merged_tags = git_output(
        source_root,
        &["tag", "--merged", "HEAD", "--list", "v*.*.*"],
    )?;
    let latest_tag = build_version::latest_stable_tag(merged_tags.lines());
    let revision_range = latest_tag
        .as_deref()
        .map_or_else(|| "HEAD".to_string(), |tag| format!("{tag}..HEAD"));
    let distance = git_output(source_root, &["rev-list", "--count", &revision_range])?
        .parse()
        .ok()?;
    let sha = git_output(source_root, &["rev-parse", "--short=9", "HEAD"])?;

    build_version::next_dev_version(latest_tag.as_deref(), distance, &sha)
}

fn git_output(source_root: &Path, args: &[&str]) -> Option<String> {
    // A linked worktree has a `.git` file and a regular checkout a directory.
    // Without either, Git would search upward into an enclosing repository.
    if !source_root.join(".git").exists() {
        return None;
    }
    let output = Command::new("git")
        .args(args)
        .current_dir(source_root)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|output| output.trim().to_string())
}
