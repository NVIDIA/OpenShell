// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Clone, Deserialize)]
pub struct Config {
    pub machines: Vec<Machine>,
    pub environments: Vec<Environment>,
    pub installers: Vec<Installer>,
    pub testsuites: Vec<Testsuite>,
}

#[derive(Clone, Deserialize)]
pub struct Machine {
    pub name: String,
    pub base_image: PathBuf,
}

#[derive(Clone, Deserialize)]
pub struct Environment {
    pub name: String,
    pub machine: String,
    pub setup: Setup,
}

#[derive(Clone, Deserialize)]
pub struct Setup {
    pub use_galaxy: bool,
    pub playbooks: Vec<PathBuf>,
}

#[derive(Clone, Deserialize)]
pub struct Installer {
    pub name: String,
    pub use_galaxy: bool,
    pub playbooks: Vec<PathBuf>,
    pub inputs: BTreeMap<String, PathBuf>,
    /// Readiness checks run on every test boot, including cached installations.
    #[serde(default)]
    pub prepare_playbooks: Vec<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::Installer;

    #[test]
    fn existing_installers_need_no_boot_preparation() {
        let installer: Installer =
            serde_saphyr::from_str("name: none\nuse_galaxy: false\nplaybooks: []\ninputs: {}\n")
                .unwrap();
        assert!(installer.prepare_playbooks.is_empty());
    }

    #[test]
    fn installer_can_request_boot_preparation() {
        let installer: Installer = serde_saphyr::from_str(
            "name: k3s\nuse_galaxy: false\nplaybooks: []\ninputs: {}\nprepare_playbooks: [ready.yaml]\n",
        )
        .unwrap();
        assert_eq!(
            installer.prepare_playbooks,
            [std::path::PathBuf::from("ready.yaml")]
        );
    }
}

#[derive(Clone, Deserialize)]
pub struct Testsuite {
    pub name: String,
    pub playbooks: Vec<PathBuf>,
    pub inputs: BTreeMap<String, PathBuf>,
    #[serde(default)]
    pub interactive: bool,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let yaml = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read configuration from {}", path.display()))?;
        serde_saphyr::from_str(&yaml)
            .with_context(|| format!("failed to parse configuration from {}", path.display()))
    }
}
