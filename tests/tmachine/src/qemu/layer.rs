// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fs::{File, metadata};
use std::path::{Path, PathBuf};

use blake3::Hasher;
use directories::ProjectDirs;

use super::img::QemuImage;
use super::vm::QemuVm;

pub(super) async fn cached_layer(
    base_image: &Path,
    hash: &str,
    use_galaxy: bool,
    playbooks: &[PathBuf],
    inputs: &BTreeMap<String, PathBuf>,
) -> PathBuf {
    let project_dirs = ProjectDirs::from("com", "nvidia", "tmachine").unwrap();
    let disks_dir = project_dirs.cache_dir().join("disks");
    std::fs::create_dir_all(&disks_dir).unwrap();

    let disk = disks_dir.join(format!("{hash}.qcow2"));
    if disk.exists() {
        return disk;
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
    run_playbooks(playbooks, inputs).await;
    vm.shutdown().await;
    vm.wait().await;

    std::fs::rename(temporary_disk, &disk).unwrap();
    disk
}

pub(super) async fn run_playbooks(playbooks: &[PathBuf], inputs: &BTreeMap<String, PathBuf>) {
    for playbook in playbooks {
        crate::ansible::run(playbook, inputs).await;
    }
}

pub(super) fn hash_inputs(hasher: &mut Hasher, inputs: &BTreeMap<String, PathBuf>) {
    hasher.update(&(inputs.len() as u64).to_le_bytes());

    for (name, file) in inputs {
        hasher.update(&(name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
        hash_file(hasher, file);
    }
}

pub(super) fn hash_files(hasher: &mut Hasher, files: &[PathBuf]) {
    hasher.update(&(files.len() as u64).to_le_bytes());

    for file in files {
        hash_file(hasher, file);
    }
}

pub(super) fn hash_file(hasher: &mut Hasher, file: &Path) {
    let size = metadata(file).unwrap().len();
    hasher.update(&size.to_le_bytes());
    hasher.update_reader(File::open(file).unwrap()).unwrap();
}
