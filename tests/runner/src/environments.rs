// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Environment definitions: `tests/environments/*.yaml`.
//!
//! Each entry describes one environment a plan can name: the machine, the
//! container runtime, the installer, how the backend provisions it, and the
//! name the installer registers the gateway under.
//!
//! Adapted from the environment definitions in Evan Lezar's
//! NVIDIA/OpenShell#4629.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;

/// All environments, keyed by ID.
#[derive(Debug, Default)]
pub struct Catalog {
    environments: BTreeMap<String, Environment>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    environments: Vec<Environment>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    pub id: String,
    pub backend: Backend,
    pub machine: Machine,
    pub runtime: String,
    pub installer: String,
    /// Backend parameters when `backend` is `tmachine`.
    #[serde(default)]
    pub tmachine: Option<Tmachine>,
    /// The name the installer registers the gateway under with the CLI, which
    /// the runner passes to tests as `OPENSHELL_GATEWAY`. Without one, tests
    /// use the CLI's active gateway.
    #[serde(default)]
    pub gateway: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    Tmachine,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Machine {
    pub os: String,
    pub version: String,
    pub arch: Arch,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    Amd64,
    Arm64,
}

/// The tmachine environment and installer that provision this environment.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Tmachine {
    pub environment: String,
    pub installer: String,
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tmachine => "tmachine",
        })
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Amd64 => "amd64",
            Self::Arm64 => "arm64",
        })
    }
}

impl Arch {
    /// The architecture of the machine running this process.
    pub const fn host() -> Option<Self> {
        if cfg!(target_arch = "x86_64") {
            Some(Self::Amd64)
        } else if cfg!(target_arch = "aarch64") {
            Some(Self::Arm64)
        } else {
            None
        }
    }
}

impl Environment {
    /// The ID implied by the environment's fields.
    pub fn expected_id(&self) -> String {
        format!(
            "{}.{}{}-{}.{}.{}",
            self.backend,
            self.machine.os,
            self.machine.version.replace('.', ""),
            self.machine.arch,
            self.runtime,
            self.installer
        )
    }

    fn validate(&self) -> Result<()> {
        let expected = self.expected_id();
        ensure!(
            self.id == expected,
            "environment {:?} does not match its fields; expected ID {expected:?}",
            self.id
        );
        match self.backend {
            Backend::Tmachine => ensure!(
                self.tmachine.is_some(),
                "environment {:?} uses the tmachine backend but has no `tmachine` section",
                self.id
            ),
        }
        Ok(())
    }

    /// Why the backend can't provision this environment on this host, if it
    /// can't. tmachine boots guests of the host's architecture only.
    pub fn unsupported_reason(&self, host: Option<Arch>) -> Option<String> {
        match self.backend {
            Backend::Tmachine if host != Some(self.machine.arch) => Some(format!(
                "tmachine boots {} guests only on {} hosts",
                self.machine.arch, self.machine.arch
            )),
            Backend::Tmachine => None,
        }
    }
}

impl Catalog {
    /// Load every `*.yaml` file in `dir`.
    pub fn load_dir(dir: &Path) -> Result<Self> {
        let mut paths: Vec<_> = std::fs::read_dir(dir)
            .with_context(|| format!("read environments directory {}", dir.display()))?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<_>>()
            .with_context(|| format!("read environments directory {}", dir.display()))?;
        paths.retain(|path| path.extension().is_some_and(|ext| ext == "yaml"));
        paths.sort();

        let mut catalog = Self::default();
        for path in paths {
            let yaml = std::fs::read_to_string(&path)
                .with_context(|| format!("read {}", path.display()))?;
            catalog
                .add_yaml(&yaml)
                .with_context(|| format!("load environments from {}", path.display()))?;
        }
        Ok(catalog)
    }

    fn add_yaml(&mut self, yaml: &str) -> Result<()> {
        let file: File = serde_yml::from_str(yaml)?;
        for environment in file.environments {
            environment.validate()?;
            if self.environments.contains_key(&environment.id) {
                bail!("environment {:?} is defined more than once", environment.id);
            }
            self.environments
                .insert(environment.id.clone(), environment);
        }
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&Environment> {
        self.environments.get(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Environment> {
        self.environments.values()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    const UBUNTU_DOCKER: &str = "
environments:
  - id: tmachine.ubuntu2404-amd64.docker-rootful.deb
    backend: tmachine
    machine: { os: ubuntu, version: \"24.04\", arch: amd64 }
    runtime: docker-rootful
    installer: deb
    tmachine: { environment: ubuntu-docker-rootful, installer: deb }
";

    fn catalog(yaml: &str) -> Result<Catalog> {
        let mut catalog = Catalog::default();
        catalog.add_yaml(yaml)?;
        Ok(catalog)
    }

    #[test]
    fn loads_environment() {
        let catalog = catalog(UBUNTU_DOCKER).unwrap();
        let env = catalog
            .get("tmachine.ubuntu2404-amd64.docker-rootful.deb")
            .unwrap();
        assert_eq!(env.machine.arch, Arch::Amd64);
        assert_eq!(
            env.tmachine,
            Some(Tmachine {
                environment: "ubuntu-docker-rootful".to_string(),
                installer: "deb".to_string(),
            })
        );
    }

    #[test]
    fn reads_the_registered_gateway_name() {
        let yaml = UBUNTU_DOCKER.replace("    runtime:", "    gateway: openshell\n    runtime:");
        let catalog = catalog(&yaml).unwrap();
        let env = catalog
            .get("tmachine.ubuntu2404-amd64.docker-rootful.deb")
            .unwrap();
        assert_eq!(env.gateway.as_deref(), Some("openshell"));
    }

    #[test]
    fn rejects_id_that_does_not_match_fields() {
        let yaml = UBUNTU_DOCKER.replace("docker-rootful.deb", "docker-rootless.deb");
        let err = catalog(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("does not match its fields"),
            "{err}"
        );
    }

    #[test]
    fn rejects_tmachine_environment_without_tmachine_section() {
        let yaml = UBUNTU_DOCKER.replace(
            "    tmachine: { environment: ubuntu-docker-rootful, installer: deb }\n",
            "",
        );
        let err = catalog(&yaml).unwrap_err();
        assert!(err.to_string().contains("no `tmachine` section"), "{err}");
    }

    #[test]
    fn rejects_unknown_fields() {
        let yaml = UBUNTU_DOCKER.replace("runtime:", "runtme:");
        assert!(catalog(&yaml).is_err());
    }

    #[test]
    fn rejects_duplicate_ids() {
        let mut catalog = catalog(UBUNTU_DOCKER).unwrap();
        let err = catalog.add_yaml(UBUNTU_DOCKER).unwrap_err();
        assert!(err.to_string().contains("more than once"), "{err}");
    }

    #[test]
    fn reports_arch_mismatch_as_unsupported() {
        let catalog = catalog(UBUNTU_DOCKER).unwrap();
        let env = catalog
            .get("tmachine.ubuntu2404-amd64.docker-rootful.deb")
            .unwrap();
        assert_eq!(env.unsupported_reason(Some(Arch::Amd64)), None);
        assert!(env.unsupported_reason(Some(Arch::Arm64)).is_some());
    }

    #[test]
    fn repository_environments_are_valid() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../environments");
        let catalog = Catalog::load_dir(&dir).unwrap();
        assert!(
            catalog
                .get("tmachine.ubuntu2404-amd64.docker-rootful.deb")
                .is_some()
        );
    }
}
