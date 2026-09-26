// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fs::{File, metadata};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use blake3::Hasher;
use directories::ProjectDirs;

use super::img::QemuImage;
use super::vm::{QemuVm, ShutdownOutcome};

pub(super) async fn cached_layer(
    base_image: &Path,
    hash: &str,
    use_galaxy: bool,
    playbooks: &[PathBuf],
    inputs: &BTreeMap<String, PathBuf>,
    variables: &BTreeMap<String, String>,
) -> Result<PathBuf> {
    let project_dirs = ProjectDirs::from("com", "nvidia", "tmachine").unwrap();
    let disks_dir = project_dirs.cache_dir().join("disks");
    std::fs::create_dir_all(&disks_dir).unwrap();

    let disk = disks_dir.join(format!("{hash}.qcow2"));
    if disk.exists() {
        return Ok(disk);
    }

    if use_galaxy {
        crate::ansible::install_roles().await;
    }

    let temporary_disk = disks_dir.join(format!("{hash}.tmp"));
    if temporary_disk.exists() {
        std::fs::remove_file(&temporary_disk).unwrap();
    }

    let image = QemuImage::create(base_image, temporary_disk.clone()).await;
    let vm = QemuVm::start(&image).await;
    let result = run_playbooks(playbooks, inputs, variables).await;
    let shutdown = vm.stop().await?;
    result?;

    publish_layer(&temporary_disk, &disk, shutdown)?;
    Ok(disk)
}

fn publish_layer(temporary_disk: &Path, disk: &Path, shutdown: ShutdownOutcome) -> Result<()> {
    anyhow::ensure!(
        shutdown == ShutdownOutcome::Graceful,
        "refusing to cache a guest disk after forced shutdown"
    );
    std::fs::rename(temporary_disk, disk).context("publish cached guest disk")
}

pub(super) async fn run_playbooks(
    playbooks: &[PathBuf],
    inputs: &BTreeMap<String, PathBuf>,
    variables: &BTreeMap<String, String>,
) -> Result<()> {
    for playbook in playbooks {
        crate::ansible::run(playbook, inputs, variables)
            .await
            .with_context(|| format!("failed to run playbook {}", playbook.display()))?;
    }
    Ok(())
}

pub(super) fn hash_variables(hasher: &mut Hasher, variables: &BTreeMap<String, String>) {
    hasher.update(&(variables.len() as u64).to_le_bytes());
    for (name, value) in variables {
        hasher.update(&(name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    }
}

pub(super) fn hash_inputs(hasher: &mut Hasher, inputs: &BTreeMap<String, PathBuf>) -> Result<()> {
    hasher.update(&(inputs.len() as u64).to_le_bytes());

    for (name, file) in inputs {
        hasher.update(&(name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
        if file.exists() {
            hash_file(hasher, file).with_context(|| {
                format!("failed to hash input {name:?} from {}", file.display())
            })?;
        } else {
            let value = file.as_os_str().as_encoded_bytes();
            hasher.update(&(value.len() as u64).to_le_bytes());
            hasher.update(value);
        }
    }
    Ok(())
}

pub(super) fn hash_files(hasher: &mut Hasher, files: &[PathBuf]) -> Result<()> {
    hasher.update(&(files.len() as u64).to_le_bytes());

    for file in files {
        let path = file.as_os_str().as_encoded_bytes();
        hasher.update(&(path.len() as u64).to_le_bytes());
        hasher.update(path);
        hash_file(hasher, file)?;
    }
    Ok(())
}

pub(super) fn hash_file(hasher: &mut Hasher, file: &Path) -> Result<()> {
    let size = metadata(file)
        .with_context(|| format!("failed to read metadata for {}", file.display()))?
        .len();
    hasher.update(&size.to_le_bytes());
    let file_handle =
        File::open(file).with_context(|| format!("failed to open {}", file.display()))?;
    hasher
        .update_reader(file_handle)
        .with_context(|| format!("failed to read {} while hashing", file.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::publish_layer;
    use crate::qemu::vm::ShutdownOutcome;

    #[test]
    fn forced_shutdown_does_not_publish_a_cached_layer() {
        let dir = tempdir().unwrap();
        let temporary_disk = dir.path().join("layer.tmp");
        let disk = dir.path().join("layer.qcow2");
        std::fs::write(&temporary_disk, b"unclean guest disk").unwrap();

        let result = publish_layer(&temporary_disk, &disk, ShutdownOutcome::Forced);

        assert!(result.is_err(), "forced shutdown must fail cache creation");
        assert!(
            !disk.exists(),
            "an unclean layer must never become a cache hit"
        );
    }

    #[test]
    fn graceful_shutdown_publishes_the_completed_layer() {
        let dir = tempdir().unwrap();
        let temporary_disk = dir.path().join("layer.tmp");
        let disk = dir.path().join("layer.qcow2");
        std::fs::write(&temporary_disk, b"completed guest disk").unwrap();

        publish_layer(&temporary_disk, &disk, ShutdownOutcome::Graceful).unwrap();

        assert_eq!(std::fs::read(&disk).unwrap(), b"completed guest disk");
        assert!(!temporary_disk.exists());
    }
}
