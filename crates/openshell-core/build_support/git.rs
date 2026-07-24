// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const WATCH_PATHS: [&str; 2] = ["HEAD", "refs/tags"];

#[cfg(not(test))]
pub fn emit_rerun_if_changed(manifest_dir: &Path) {
    for path in watch_paths(manifest_dir) {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

pub fn watch_paths(manifest_dir: &Path) -> Vec<PathBuf> {
    WATCH_PATHS
        .into_iter()
        .filter_map(|path| resolve_existing_git_path(manifest_dir, path))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn resolve_existing_git_path(manifest_dir: &Path, path: &str) -> Option<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--git-path", path])
        .current_dir(manifest_dir)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let path = PathBuf::from(String::from_utf8(output.stdout).ok()?.trim());
    let path = if path.is_absolute() {
        path
    } else {
        manifest_dir.join(path)
    };

    path.exists().then_some(path)
}
