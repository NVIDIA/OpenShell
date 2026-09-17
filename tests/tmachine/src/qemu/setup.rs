// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use blake3::Hasher;

use crate::config::{Environment, Machine};

use super::ansible_hash::hash_sources;
use super::layer::{cached_layer, hash_file, hash_files};

const SETUP_CACHE_VERSION: &[u8] = b"tmachine-disk-blake3-v1";

pub async fn setup(machine: &Machine, environment: &Environment) -> Result<PathBuf> {
    if environment.setup.playbooks.is_empty() {
        return Ok(machine.base_image.clone());
    }

    let hash = setup_hash(machine, environment)?;
    cached_layer(
        &machine.base_image,
        &hash,
        environment.setup.use_galaxy,
        &environment.setup.playbooks,
        &BTreeMap::new(),
    )
    .await
}

fn setup_hash(machine: &Machine, environment: &Environment) -> Result<String> {
    let mut hasher = Hasher::new();
    hasher.update(SETUP_CACHE_VERSION);
    hash_file(&mut hasher, &machine.base_image)
        .with_context(|| format!("failed to hash base image for machine {:?}", machine.name))?;
    hasher.update(&[u8::from(environment.setup.use_galaxy)]);
    hash_sources(&mut hasher).context("failed to hash Ansible sources")?;
    hash_files(&mut hasher, &environment.setup.playbooks)
        .context("failed to hash setup playbooks")?;
    Ok(hasher.finalize().to_hex().to_string())
}
