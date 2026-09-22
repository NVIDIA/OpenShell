// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Applies extracted OCI layers to a VM root filesystem.

use std::fs;
use std::path::Path;

pub fn apply_layer_dir_to_rootfs(layer_root: &Path, rootfs: &Path) -> Result<(), String> {
    merge_layer_directory(layer_root, rootfs)
}

fn merge_layer_directory(source_dir: &Path, target_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(target_dir)
        .map_err(|err| format!("create {}: {err}", target_dir.display()))?;

    let mut entries = fs::read_dir(source_dir)
        .map_err(|err| format!("read {}: {err}", source_dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("read {}: {err}", source_dir.display()))?;
    entries.sort_by_key(fs::DirEntry::file_name);

    if entries
        .iter()
        .any(|entry| entry.file_name().to_string_lossy() == ".wh..wh..opq")
    {
        clear_directory_contents(target_dir)?;
    }

    for entry in entries {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if name == ".wh..wh..opq" {
            continue;
        }
        if let Some(hidden_name) = name.strip_prefix(".wh.") {
            remove_path_if_exists(&target_dir.join(hidden_name))?;
            continue;
        }

        let source_path = entry.path();
        let dest_path = target_dir.join(&file_name);
        let metadata = fs::symlink_metadata(&source_path)
            .map_err(|err| format!("stat {}: {err}", source_path.display()))?;
        let file_type = metadata.file_type();

        if file_type.is_dir() {
            if let Ok(dest_metadata) = fs::symlink_metadata(&dest_path)
                && !dest_metadata.file_type().is_dir()
                && !path_is_dir_or_symlink_to_dir(&dest_path)?
            {
                remove_path_if_exists(&dest_path)?;
            }
            fs::create_dir_all(&dest_path)
                .map_err(|err| format!("create {}: {err}", dest_path.display()))?;
            merge_layer_directory(&source_path, &dest_path)?;
            if fs::symlink_metadata(&dest_path)
                .map_err(|err| format!("stat {}: {err}", dest_path.display()))?
                .file_type()
                .is_dir()
            {
                fs::set_permissions(&dest_path, metadata.permissions())
                    .map_err(|err| format!("chmod {}: {err}", dest_path.display()))?;
            }
        } else if file_type.is_file() {
            remove_path_if_exists(&dest_path)?;
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|err| format!("create {}: {err}", parent.display()))?;
            }
            fs::copy(&source_path, &dest_path).map_err(|err| {
                format!(
                    "copy {} to {}: {err}",
                    source_path.display(),
                    dest_path.display()
                )
            })?;
            fs::set_permissions(&dest_path, metadata.permissions())
                .map_err(|err| format!("chmod {}: {err}", dest_path.display()))?;
        } else if file_type.is_symlink() {
            copy_symlink(&source_path, &dest_path)?;
        } else {
            return Err(format!(
                "unsupported layer entry type at {}",
                source_path.display()
            ));
        }
    }

    Ok(())
}

fn path_is_dir_or_symlink_to_dir(path: &Path) -> Result<bool, String> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_dir()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!("stat {}: {err}", path.display())),
    }
}

fn clear_directory_contents(dir: &Path) -> Result<(), String> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir).map_err(|err| format!("read {}: {err}", dir.display()))? {
        let entry = entry.map_err(|err| format!("read {}: {err}", dir.display()))?;
        remove_path_if_exists(&entry.path())?;
    }
    Ok(())
}

fn remove_path_if_exists(path: &Path) -> Result<(), String> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if metadata.file_type().is_dir() {
        fs::remove_dir_all(path).map_err(|err| format!("remove {}: {err}", path.display()))
    } else {
        fs::remove_file(path).map_err(|err| format!("remove {}: {err}", path.display()))
    }
}

#[cfg(unix)]
fn copy_symlink(source_path: &Path, dest_path: &Path) -> Result<(), String> {
    let target = fs::read_link(source_path)
        .map_err(|err| format!("readlink {}: {err}", source_path.display()))?;
    remove_path_if_exists(dest_path)?;
    if let Some(parent) = dest_path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("create {}: {err}", parent.display()))?;
    }
    std::os::unix::fs::symlink(&target, dest_path).map_err(|err| {
        format!(
            "symlink {} to {}: {err}",
            target.display(),
            dest_path.display()
        )
    })
}

#[cfg(not(unix))]
fn copy_symlink(_source_path: &Path, _dest_path: &Path) -> Result<(), String> {
    Err("symlink layers are only supported on Unix hosts".to_string())
}
