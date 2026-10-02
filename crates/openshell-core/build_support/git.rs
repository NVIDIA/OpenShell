// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

#[path = "../build_version.rs"]
mod build_version;

/// Track Git's resolved metadata, including creation of previously packed refs.
pub fn emit_rerun_if_changed(manifest_dir: &Path) {
    // refs/ must be watched as a directory: a packed branch has no loose file
    // until its next update. Watching only existing individual refs misses it.
    // reftable/ serves the same purpose for repositories using that ref backend.
    let mut paths = BTreeSet::new();
    for name in ["HEAD", "refs", "packed-refs", "reftable", "shallow"] {
        let Some(path) = git_output(manifest_dir, &["rev-parse", "--git-path", name]) else {
            continue;
        };
        paths.insert(manifest_dir.join(path));
    }
    // A linked worktree's reftable holds its private refs, including HEAD.
    // Shared branches and tags live in the common directory's separate table.
    if let Some(common_dir) = git_output(manifest_dir, &["rev-parse", "--git-common-dir"]) {
        paths.insert(manifest_dir.join(common_dir).join("reftable"));
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
/// Returns `None` when git metadata cannot be read.
pub fn version(manifest_dir: &Path) -> Option<String> {
    let exact_tags = git_output(manifest_dir, &["tag", "--points-at", "HEAD"])?;
    if let Some(version) = build_version::exact_release_version(exact_tags.lines()) {
        return Some(version);
    }

    let merged_tags = git_output(
        manifest_dir,
        &["tag", "--merged", "HEAD", "--list", "v*.*.*"],
    )?;
    let latest_tag = build_version::latest_stable_tag(merged_tags.lines());
    let revision_range = latest_tag
        .as_deref()
        .map_or_else(|| "HEAD".to_string(), |tag| format!("{tag}..HEAD"));
    let distance = git_output(manifest_dir, &["rev-list", "--count", &revision_range])?
        .parse()
        .ok()?;
    let sha = git_output(manifest_dir, &["rev-parse", "--short=9", "HEAD"])?;

    build_version::next_dev_version(latest_tag.as_deref(), distance, &sha)
}

fn git_output(manifest_dir: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(manifest_dir)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|output| output.trim().to_string())
}
