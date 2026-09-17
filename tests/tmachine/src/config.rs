// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Clone, Deserialize)]
pub struct Config {
    pub machines: Vec<Machine>,
    pub scenarios: Vec<Scenario>,
    pub testsuites: Vec<Testsuite>,
}

#[derive(Clone, Deserialize)]
pub struct Machine {
    pub name: String,
    pub base_image: PathBuf,
}

#[derive(Clone, Deserialize)]
pub struct Scenario {
    pub name: String,
    pub machine: String,
    pub setup: Setup,
    pub install: Install,
}

#[derive(Clone, Deserialize)]
pub struct Setup {
    pub use_galaxy: bool,
    pub playbooks: Vec<PathBuf>,
}

#[derive(Clone, Deserialize)]
pub struct Install {
    pub use_galaxy: bool,
    pub playbooks: Vec<PathBuf>,
    pub inputs: BTreeMap<String, PathBuf>,
}

#[derive(Clone, Deserialize)]
pub struct Testsuite {
    pub name: String,
    pub playbooks: Vec<PathBuf>,
    pub inputs: BTreeMap<String, PathBuf>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let yaml = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read configuration from {}", path.display()))?;
        serde_saphyr::from_str(&yaml)
            .with_context(|| format!("failed to parse configuration from {}", path.display()))
    }
}
