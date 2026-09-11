// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use blake3::Hasher;

use crate::config::{Machine, Scenario};

use super::layer::{cached_layer, hash_file, hash_files, hash_inputs};
use super::setup::setup;

const INSTALL_CACHE_VERSION: &[u8] = b"tmachine-install-blake3-v1";

pub async fn install(machine: &Machine, scenario: &Scenario) -> Result<PathBuf> {
    let setup_disk = setup(machine, scenario).await?;
    if scenario.install.playbooks.is_empty() && scenario.install.inputs.is_empty() {
        return Ok(setup_disk);
    }

    let hash = install_hash(&setup_disk, scenario)?;
    cached_layer(
        &setup_disk,
        &hash,
        scenario.install.use_galaxy,
        &scenario.install.playbooks,
        &scenario.install.inputs,
    )
    .await
}

fn install_hash(setup_disk: &Path, scenario: &Scenario) -> Result<String> {
    let mut hasher = Hasher::new();
    hasher.update(INSTALL_CACHE_VERSION);
    hash_file(&mut hasher, setup_disk).context("failed to hash setup disk")?;
    hasher.update(&[u8::from(scenario.install.use_galaxy)]);
    if scenario.install.use_galaxy {
        hash_file(&mut hasher, Path::new(&crate::ansible::requirements_path()))
            .context("failed to hash Ansible Galaxy requirements")?;
    }
    hash_files(&mut hasher, &scenario.install.playbooks)
        .context("failed to hash install playbooks")?;
    hash_inputs(&mut hasher, &scenario.install.inputs)?;
    Ok(hasher.finalize().to_hex().to_string())
}
