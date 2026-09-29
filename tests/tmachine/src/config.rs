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
    #[serde(default)]
    pub variables: BTreeMap<String, String>,
    #[serde(default)]
    pub ephemeral: bool,
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

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn environment_cluster_values_are_independent_of_installer_and_testsuite() {
        let config: Config = serde_saphyr::from_str(
            r#"
machines:
  - name: ubuntu
    base_image: /tmp/ubuntu.qcow2
environments:
  - name: ubuntu-k3s
    machine: ubuntu
    ephemeral: true
    variables:
      kubeconfig: /home/tmachine/.kube/config
      kubernetes_namespace: openshell
    setup:
      use_galaxy: false
      playbooks: [k3s.yaml]
installers:
  - name: kubernetes-binaries
    use_galaxy: false
    playbooks: [gateway-kubernetes.yaml]
    inputs: {}
testsuites:
  - name: conformance
    playbooks: [conformance.yaml]
    inputs: {}
"#,
        )
        .unwrap();

        let environment = &config.environments[0];
        assert!(environment.ephemeral);
        assert_eq!(
            environment.variables["kubeconfig"],
            "/home/tmachine/.kube/config"
        );
        assert_eq!(environment.variables["kubernetes_namespace"], "openshell");
        assert_eq!(config.installers[0].name, "kubernetes-binaries");
        assert_eq!(config.testsuites[0].name, "conformance");
    }
}
