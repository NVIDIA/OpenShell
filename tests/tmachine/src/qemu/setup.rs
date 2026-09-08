// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use blake3::Hasher;

use crate::config::{Machine, Scenario};

use super::layer::{cached_layer, hash_file, hash_files};

const SETUP_CACHE_VERSION: &[u8] = b"tmachine-disk-blake3-v1";

pub async fn setup(machine: &Machine, scenario: &Scenario) -> PathBuf {
    if scenario.setup.playbooks.is_empty() {
        return machine.base_image.clone();
    }

    let hash = setup_hash(machine, scenario);
    cached_layer(
        &machine.base_image,
        &hash,
        scenario.setup.use_galaxy,
        &scenario.setup.playbooks,
        &BTreeMap::new(),
    )
    .await
}

fn setup_hash(machine: &Machine, scenario: &Scenario) -> String {
    let mut hasher = Hasher::new();
    hasher.update(SETUP_CACHE_VERSION);
    hash_file(&mut hasher, &machine.base_image);
    hasher.update(&[u8::from(scenario.setup.use_galaxy)]);
    if scenario.setup.use_galaxy {
        hash_file(&mut hasher, Path::new(&crate::ansible::requirements_path()));
    }
    hash_files(&mut hasher, &scenario.setup.playbooks);
    hasher.finalize().to_hex().to_string()
}
