// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The expected matrix: every test against every defined environment.
//!
//! A test is expected in every environment that provides the capabilities
//! it requires. Nobody lists combinations: tests say what they need,
//! environments say what they provide. Waivers then skip known bugs, and
//! the host check excludes environments this machine can't boot. Plans only
//! select from the result; they never decide what is expected.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};

use serde::Serialize;

use crate::catalog::{Catalog, Test};
use crate::environments::{Arch, Catalog as Environments, Environment};
use crate::waivers::{Waiver, Waivers};

/// Why a test does not run in an environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Exclusion {
    /// The environment lacks capabilities the test requires.
    Missing(Vec<String>),
    /// A waiver skips the test there.
    Waived(Waiver),
    /// This machine can't provision the environment.
    Host(String),
}

impl fmt::Display for Exclusion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(capabilities) => write!(f, "needs {}", capabilities.join(", ")),
            Self::Waived(waiver) => write!(f, "waived: {} ({})", waiver.reason, waiver.issue),
            Self::Host(reason) => write!(f, "host: {reason}"),
        }
    }
}

/// Capabilities the test requires that the environment doesn't provide.
/// Requirements name boolean capabilities.
pub fn missing_capabilities(test: &Test, environment: &Environment) -> Vec<String> {
    test.requires
        .iter()
        .filter(|capability| {
            environment.capabilities.get(capability.as_str()) != Some(&serde_yml::Value::Bool(true))
        })
        .cloned()
        .collect()
}

/// Why the test doesn't run in the environment, ignoring the host: a missing
/// capability first, then a waiver.
pub fn exclusion(test: &Test, environment: &Environment, waivers: &Waivers) -> Option<Exclusion> {
    let missing = missing_capabilities(test, environment);
    if !missing.is_empty() {
        return Some(Exclusion::Missing(missing));
    }
    waivers
        .find(&test.id, environment)
        .map(|waiver| Exclusion::Waived(waiver.clone()))
}

/// Problems that make the matrix inconsistent, judged by capabilities alone:
/// a test no defined environment can run, and a capability tests require
/// that no environment declares. Waivers and the host don't count; a test
/// only needs to be runnable somewhere in principle.
pub fn problems(catalog: &Catalog, environments: &Environments) -> Vec<String> {
    let declared: BTreeSet<&str> = environments
        .iter()
        .flat_map(|env| {
            env.capabilities
                .iter()
                .filter(|(_, value)| **value == serde_yml::Value::Bool(true))
                .map(|(name, _)| name.as_str())
        })
        .collect();

    let mut undeclared: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut problems = Vec::new();
    for (family, suite, test) in catalog.tests() {
        let location = format!(
            "{}/{}/{} ({})",
            family.name, suite.suite, test.name, test.id
        );
        for capability in &test.requires {
            if !declared.contains(capability.as_str()) {
                undeclared
                    .entry(capability)
                    .or_default()
                    .push(location.clone());
            }
        }
        if !environments
            .iter()
            .any(|env| missing_capabilities(test, env).is_empty())
        {
            problems.push(format!(
                "{location} runs in no defined environment; requires {}",
                test.requires.join(", ")
            ));
        }
    }
    for (capability, tests) in undeclared {
        problems.push(format!(
            "capability {capability} is required by {} but no environment declares it",
            tests.join(", ")
        ));
    }
    problems
}

/// Every test against every environment.
#[derive(Debug, Serialize)]
pub struct Matrix {
    pub environments: Vec<String>,
    pub tests: Vec<Row>,
}

#[derive(Debug, Serialize)]
pub struct Row {
    pub family: String,
    pub suite: String,
    pub name: String,
    pub id: String,
    /// Keyed by environment ID: `run`, or why the test doesn't run there.
    pub cells: BTreeMap<String, String>,
}

impl Matrix {
    /// Build the matrix. With `host`, also exclude environments that machine
    /// can't provision.
    pub fn build(
        catalog: &Catalog,
        environments: &Environments,
        waivers: &Waivers,
        host: Option<Option<Arch>>,
    ) -> Self {
        let tests = catalog
            .tests()
            .map(|(family, suite, test)| Row {
                family: family.name.clone(),
                suite: suite.suite.clone(),
                name: test.name.clone(),
                id: test.id.clone(),
                cells: environments
                    .iter()
                    .map(|env| {
                        let exclusion = exclusion(test, env, waivers).or_else(|| {
                            host.and_then(|host| env.unsupported_reason(host).map(Exclusion::Host))
                        });
                        let cell = exclusion.map_or_else(|| "run".to_string(), |e| e.to_string());
                        (env.id.clone(), cell)
                    })
                    .collect(),
            })
            .collect();
        Self {
            environments: environments.iter().map(|env| env.id.clone()).collect(),
            tests,
        }
    }

    /// The matrix as text: each test, then where it runs or why not.
    pub fn render(&self) -> String {
        let width = self.environments.iter().map(String::len).max().unwrap_or(0);
        let mut out = String::new();
        let mut runs = 0;
        let mut excluded = 0;
        for row in &self.tests {
            let _ = writeln!(
                out,
                "{}/{}/{} ({})",
                row.family, row.suite, row.name, row.id
            );
            for (env, cell) in &row.cells {
                let _ = writeln!(out, "  {env:width$}  {cell}");
                if cell == "run" {
                    runs += 1;
                } else {
                    excluded += 1;
                }
            }
        }
        let _ = writeln!(
            out,
            "\n{} tests x {} environments: {runs} run, {excluded} excluded",
            self.tests.len(),
            self.environments.len()
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::catalog::{Family, Suite};

    fn environments(capabilities: &str) -> Environments {
        let yaml = format!(
            "environments:\n  - id: tmachine.ubuntu2404-amd64.docker-rootful.deb\n    backend: tmachine\n    machine: {{ os: ubuntu, version: \"24.04\", arch: amd64 }}\n    runtime: docker-rootful\n    installer: deb\n    tmachine: {{ environment: ubuntu-docker-rootful, installer: deb }}\n    capabilities: {capabilities}\n"
        );
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("docker.yaml"), yaml).unwrap();
        Environments::load_dir(dir.path()).unwrap()
    }

    fn catalog(tests: &[(&str, &[&str])]) -> Catalog {
        let suite = Suite {
            suite: "s".to_string(),
            binary: "s".to_string(),
            package: "p".to_string(),
            tests: tests
                .iter()
                .enumerate()
                .map(|(index, (name, requires))| Test {
                    id: format!("t-{index:08}"),
                    name: (*name).to_string(),
                    description: "d".to_string(),
                    requires: requires.iter().map(ToString::to_string).collect(),
                })
                .collect(),
        };
        let family = Family {
            name: "conformance".to_string(),
            workspace: PathBuf::new(),
            suites: [("s".to_string(), suite)].into(),
        };
        Catalog {
            families: [("conformance".to_string(), family)].into(),
        }
    }

    #[test]
    fn reports_tests_no_environment_can_run() {
        let catalog = catalog(&[("plain", &[]), ("exposed", &["service_exposure"])]);
        let found = problems(&catalog, &environments("{ service_exposure: false }"));
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(
            found[0].contains("conformance/s/exposed (t-00000001) runs in no defined environment")
        );
        assert!(found[1].contains("capability service_exposure is required by"));

        assert!(problems(&catalog, &environments("{ service_exposure: true }")).is_empty());
    }

    #[test]
    fn cells_give_the_reason_a_test_does_not_run() {
        let catalog = catalog(&[("plain", &[]), ("exposed", &["service_exposure"])]);
        let environments = environments("{ compute_driver: docker }");
        let env = "tmachine.ubuntu2404-amd64.docker-rootful.deb";

        let matrix = Matrix::build(&catalog, &environments, &Waivers::default(), None);
        assert_eq!(matrix.tests[0].cells[env], "run");
        assert_eq!(matrix.tests[1].cells[env], "needs service_exposure");

        let on_arm = Matrix::build(
            &catalog,
            &environments,
            &Waivers::default(),
            Some(Some(Arch::Arm64)),
        );
        assert!(
            on_arm.tests[0].cells[env].starts_with("host: "),
            "{:?}",
            on_arm.tests[0].cells
        );
        // A missing capability is reported before the host.
        assert_eq!(on_arm.tests[1].cells[env], "needs service_exposure");

        let text = matrix.render();
        assert!(text.contains("conformance/s/plain (t-00000000)"), "{text}");
        assert!(
            text.contains("2 tests x 1 environments: 1 run, 1 excluded"),
            "{text}"
        );
    }

    #[test]
    fn repository_matrix_is_consistent() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let catalog = Catalog::load(&root).unwrap();
        let environments = Environments::load_dir(&root.join("tests/environments")).unwrap();
        let problems = problems(&catalog, &environments);
        assert!(problems.is_empty(), "{problems:#?}");
    }
}
