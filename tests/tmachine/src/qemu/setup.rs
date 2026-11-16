// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use blake3::Hasher;

use crate::config::{Environment, Machine};

use super::ansible_hash::hash_sources_in;
use super::layer::{SETUP_DISKS, cached_layer, hash_file, hash_files, hash_inputs};

const SETUP_CACHE_VERSION: &[u8] = b"tmachine-disk-blake3-v1";

pub async fn setup(machine: &Machine, environment: &Environment) -> Result<PathBuf> {
    let Some(hash) = setup_layer_key(machine, environment)? else {
        return Ok(machine.base_image.clone());
    };

    cached_layer(
        SETUP_DISKS,
        &machine.base_image,
        &hash,
        environment.setup.use_galaxy,
        &environment.setup.playbooks,
        &environment.setup.inputs,
    )
    .await
}

/// The hash that names the environment's setup layer (`disks/<hash>.qcow2`),
/// or `None` when it has no setup playbooks and so runs on the base image.
pub fn setup_layer_key(machine: &Machine, environment: &Environment) -> Result<Option<String>> {
    if environment.setup.playbooks.is_empty() {
        return Ok(None);
    }
    let requirements = crate::ansible::requirements_path();
    setup_hash(machine, environment, requirements.parent().unwrap()).map(Some)
}

fn setup_hash(machine: &Machine, environment: &Environment, ansible: &Path) -> Result<String> {
    let mut hasher = Hasher::new();
    hasher.update(SETUP_CACHE_VERSION);
    hash_file(&mut hasher, &machine.base_image)
        .with_context(|| format!("failed to hash base image for machine {:?}", machine.name))?;
    hasher.update(&[u8::from(environment.setup.use_galaxy)]);
    hash_sources_in(&mut hasher, ansible).context("failed to hash Ansible sources")?;
    hash_files(&mut hasher, &environment.setup.playbooks)
        .context("failed to hash setup playbooks")?;
    // Skipped when empty so environments without inputs keep their cache keys.
    if !environment.setup.inputs.is_empty() {
        hash_inputs(&mut hasher, &environment.setup.inputs)?;
    }
    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use super::*;
    use crate::config::Setup;

    fn environment(playbooks: Vec<PathBuf>, inputs: BTreeMap<String, PathBuf>) -> Environment {
        Environment {
            name: "test".into(),
            machine: "test".into(),
            setup: Setup {
                use_galaxy: false,
                playbooks,
                inputs,
            },
        }
    }

    #[test]
    fn an_environment_without_setup_playbooks_has_no_layer() {
        let machine = Machine {
            name: "test".into(),
            base_image: "/nonexistent/base.qcow2".into(),
        };
        let key = setup_layer_key(&machine, &environment(Vec::new(), BTreeMap::new())).unwrap();
        assert_eq!(key, None);
    }

    #[test]
    fn the_setup_hash_follows_every_setup_input() {
        let dir = tempfile::tempdir().unwrap();
        let ansible = dir.path().join("ansible");
        fs::create_dir(&ansible).unwrap();
        fs::write(ansible.join("requirements.yaml"), "[]").unwrap();
        let base_image = dir.path().join("base.qcow2");
        fs::write(&base_image, "base").unwrap();
        let playbook = dir.path().join("setup.yaml");
        fs::write(&playbook, "- hosts: all").unwrap();
        let input = dir.path().join("realm.json");
        fs::write(&input, "{}").unwrap();

        let machine = Machine {
            name: "test".into(),
            base_image: base_image.clone(),
        };
        let environment = environment(
            vec![playbook.clone()],
            BTreeMap::from([("realm".into(), input.clone())]),
        );
        let hash = || setup_hash(&machine, &environment, &ansible).unwrap();

        let original = hash();
        assert_eq!(original.len(), 64);
        assert_eq!(hash(), original);

        let mut seen = vec![original];
        for (file, contents) in [
            (&input, "{\"realm\": 1}"),
            (&playbook, "- hosts: guest"),
            (&ansible.join("requirements.yaml"), "[role]"),
            (&base_image, "rebuilt base"),
        ] {
            fs::write(file, contents).unwrap();
            let changed = hash();
            assert!(
                !seen.contains(&changed),
                "{} did not change the hash",
                file.display()
            );
            seen.push(changed);
        }
    }
}
