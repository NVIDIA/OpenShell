// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use blake3::Hasher;

use crate::config::{Environment, Installer, Machine};

use super::ansible_hash::hash_sources;
use super::layer::{cached_layer, hash_file, hash_files, hash_inputs};
use super::setup::setup;

const INSTALL_CACHE_VERSION: &[u8] = b"tmachine-install-blake3-v1";

pub async fn install(
    machine: &Machine,
    environment: &Environment,
    installer: &Installer,
) -> Result<PathBuf> {
    let setup_disk = setup(machine, environment).await?;
    if installer.playbooks.is_empty() && installer.inputs.is_empty() {
        return Ok(setup_disk);
    }

    let hash = install_hash(&setup_disk, installer)?;
    cached_layer(
        &setup_disk,
        &hash,
        installer.use_galaxy,
        &installer.playbooks,
        &installer.inputs,
    )
    .await
}

fn install_hash(setup_disk: &Path, installer: &Installer) -> Result<String> {
    let mut hasher = Hasher::new();
    hasher.update(INSTALL_CACHE_VERSION);
    hash_file(&mut hasher, setup_disk).context("failed to hash setup disk")?;
    hasher.update(&[u8::from(installer.use_galaxy)]);
    hash_sources(&mut hasher).context("failed to hash Ansible sources")?;
    hash_files(&mut hasher, &installer.playbooks).context("failed to hash install playbooks")?;
    hash_inputs(&mut hasher, &installer.inputs)?;
    Ok(hasher.finalize().to_hex().to_string())
}
