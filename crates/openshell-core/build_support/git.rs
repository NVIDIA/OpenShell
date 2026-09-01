// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const WATCH_PATHS: [&str; 3] = ["HEAD", "refs/tags", "packed-refs"];

#[cfg(not(test))]
pub fn emit_rerun_if_changed(manifest_dir: &Path) {
    for path in watch_paths(manifest_dir) {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

pub fn watch_paths(manifest_dir: &Path) -> Vec<PathBuf> {
    let mut git_paths = WATCH_PATHS
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();

    if let Some(head_ref) = symbolic_head_ref(manifest_dir) {
        git_paths.push(head_ref);
    }

    git_paths
        .iter()
        .filter_map(|path| resolve_existing_git_path(manifest_dir, path))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn symbolic_head_ref(manifest_dir: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(["symbolic-ref", "--quiet", "HEAD"])
        .current_dir(manifest_dir)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let head_ref = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (!head_ref.is_empty()).then_some(head_ref)
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
