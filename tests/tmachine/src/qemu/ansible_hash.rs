// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{Context, Result, bail};
use blake3::Hasher;

use super::layer::hash_file;

pub(super) fn hash_sources(hasher: &mut Hasher) -> Result<()> {
    let requirements = crate::ansible::requirements_path();
    let root = requirements.parent().unwrap();
    hash_tree(hasher, root, root)
}

fn hash_tree(hasher: &mut Hasher, root: &Path, directory: &Path) -> Result<()> {
    let mut entries = fs::read_dir(directory)
        .with_context(|| format!("failed to read Ansible directory {}", directory.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    // Pinned Galaxy releases are immutable inputs represented by requirements.yaml.
    if directory == root {
        entries.retain(|entry| entry.file_name() != ".roles");
    }
    entries.sort_by_key(|entry| entry.file_name());
    hasher.update(&(entries.len() as u64).to_le_bytes());

    for entry in entries {
        let path = entry.path();
        let relative = path.strip_prefix(root)?.as_os_str().as_encoded_bytes();
        hasher.update(&(relative.len() as u64).to_le_bytes());
        hasher.update(relative);

        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to stat Ansible input {}", path.display()))?;
        if metadata.is_dir() {
            hasher.update(b"d");
            hash_tree(hasher, root, &path)?;
        } else if metadata.is_file() {
            hasher.update(b"f");
            hasher.update(&(metadata.permissions().mode() & 0o111).to_le_bytes());
            hash_file(hasher, &path)?;
        } else {
            bail!(
                "Ansible input {} must be a regular file or directory; symlinks are unsupported",
                path.display()
            );
        }
    }
    Ok(())
}
