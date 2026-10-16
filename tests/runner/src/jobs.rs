// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Expanding a plan into jobs.
//!
//! Jobs are grouped by environment so each environment is provisioned once
//! and runs every family and suite the plan selects for it. Tests whose
//! requirements the environment lacks, or that a waiver skips there, are
//! excluded by exact name and reported with the reason; libtest has no
//! runtime skip, so this is the only place they can be skipped honestly.

use std::collections::BTreeMap;

use anyhow::{Result, bail};

use crate::catalog::{Catalog, Suite};
use crate::environments::{Arch, Catalog as Environments, Environment};
use crate::matrix::{Exclusion, exclusion};
use crate::plan::Plan;
use crate::waivers::Waivers;

/// Everything the plan runs in one environment.
#[derive(Debug)]
pub struct Job {
    pub environment: Environment,
    /// Why the environment can't be provisioned on this host, if it can't.
    pub unsupported: Option<String>,
    pub families: Vec<FamilyJob>,
}

/// The suites of one family selected for an environment.
#[derive(Debug)]
pub struct FamilyJob {
    pub family: String,
    pub suites: Vec<SuiteJob>,
}

#[derive(Debug)]
pub struct SuiteJob {
    pub suite: Suite,
    /// Names of the tests to run.
    pub run: Vec<String>,
    /// Tests excluded in this environment, with the reason.
    pub excluded: Vec<ExcludedTest>,
}

#[derive(Debug)]
pub struct ExcludedTest {
    pub name: String,
    pub reason: Exclusion,
}

/// Filters applied on top of the plan, from the command line.
#[derive(Debug, Default)]
pub struct Narrowing {
    pub environments: Vec<String>,
    pub suites: Vec<String>,
}

/// Validate the plan against the catalogs and expand it into jobs.
pub fn expand(
    plan: &Plan,
    catalog: &Catalog,
    environments: &Environments,
    waivers: &Waivers,
    host: Option<Arch>,
    narrowing: &Narrowing,
) -> Result<Vec<Job>> {
    // environment ID -> family -> suite names, in plan order where it matters.
    let mut selected: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();

    for entry in &plan.matrix {
        let family = catalog.family(&entry.family)?;
        let suites: Vec<String> = match &entry.suites {
            Some(suites) => {
                for suite in suites {
                    family.suite(suite)?;
                }
                suites.clone()
            }
            None => family.suites.keys().cloned().collect(),
        };
        for id in &entry.environments {
            if environments.get(id).is_none() {
                bail!(
                    "unknown environment {id:?}; known environments: {}",
                    environments
                        .iter()
                        .map(|env| env.id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            let family_suites = selected
                .entry(id.clone())
                .or_default()
                .entry(entry.family.clone())
                .or_default();
            for suite in &suites {
                if !family_suites.contains(suite) {
                    family_suites.push(suite.clone());
                }
            }
        }
    }

    for id in &narrowing.environments {
        if !selected.contains_key(id) {
            bail!("--env {id:?} is not in the plan");
        }
    }
    for suite in &narrowing.suites {
        let in_plan = selected
            .values()
            .flat_map(BTreeMap::values)
            .any(|suites| suites.contains(suite));
        if !in_plan {
            bail!("--suite {suite:?} is not in the plan");
        }
    }

    let mut jobs = Vec::new();
    for (id, families) in selected {
        if !narrowing.environments.is_empty() && !narrowing.environments.contains(&id) {
            continue;
        }
        let environment = environments.get(&id).expect("validated above").clone();
        let mut family_jobs = Vec::new();
        for (family_name, suites) in families {
            let family = catalog.family(&family_name)?;
            let suites: Vec<SuiteJob> = suites
                .iter()
                .filter(|suite| narrowing.suites.is_empty() || narrowing.suites.contains(suite))
                .map(|suite| {
                    suite_job(
                        family.suite(suite).expect("validated above"),
                        &environment,
                        waivers,
                    )
                })
                .collect();
            if !suites.is_empty() {
                family_jobs.push(FamilyJob {
                    family: family_name,
                    suites,
                });
            }
        }
        if family_jobs.is_empty() {
            continue;
        }
        jobs.push(Job {
            unsupported: environment.unsupported_reason(host),
            environment,
            families: family_jobs,
        });
    }
    Ok(jobs)
}

fn suite_job(suite: &Suite, environment: &Environment, waivers: &Waivers) -> SuiteJob {
    let mut run = Vec::new();
    let mut excluded = Vec::new();
    for test in &suite.tests {
        match exclusion(test, environment, waivers) {
            None => run.push(test.name.clone()),
            Some(reason) => excluded.push(ExcludedTest {
                name: test.name.clone(),
                reason,
            }),
        }
    }
    SuiteJob {
        suite: suite.clone(),
        run,
        excluded,
    }
}

impl FamilyJob {
    /// Whether any test will run.
    pub fn has_tests(&self) -> bool {
        self.suites.iter().any(|suite| !suite.run.is_empty())
    }

    /// Stable test IDs keyed by nextest `JUnit` `(classname, name)`.
    pub fn test_ids(&self) -> BTreeMap<(String, String), String> {
        self.suites
            .iter()
            .flat_map(|job| {
                let classname = format!("{}::{}", job.suite.package, job.suite.binary);
                job.suite
                    .tests
                    .iter()
                    .map(move |test| ((classname.clone(), test.name.clone()), test.id.clone()))
            })
            .collect()
    }

    /// The nextest filterset selecting exactly the tests to run.
    pub fn filterset(&self) -> String {
        self.suites
            .iter()
            .filter(|suite| !suite.run.is_empty())
            .map(|suite| {
                // Name the package too: other packages in the family can have test
                // binaries with the same name.
                let binary = format!(
                    "binary_id(={}::{})",
                    suite.suite.package, suite.suite.binary
                );
                if suite.excluded.is_empty() {
                    binary
                } else {
                    let tests = suite
                        .run
                        .iter()
                        .map(|id| format!("test(={id})"))
                        .collect::<Vec<_>>()
                        .join(" | ");
                    format!("({binary} & ({tests}))")
                }
            })
            .collect::<Vec<_>>()
            .join(" | ")
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::catalog::{Family, Test};

    fn catalog() -> Catalog {
        let suite = |name: &str, tests: &[(&str, &[&str])]| Suite {
            suite: name.to_string(),
            binary: name.replace('-', "_"),
            package: format!("pkg-{name}"),
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
            suites: [
                suite(
                    "sandbox-lifecycle",
                    &[("long_running", &[]), ("expose", &["service_exposure"])],
                ),
                suite("providers", &[("create_provider", &[])]),
            ]
            .into_iter()
            .map(|suite| (suite.suite.clone(), suite))
            .collect(),
        };
        Catalog {
            families: [("conformance".to_string(), family)].into(),
        }
    }

    fn environments() -> Environments {
        use std::fmt::Write as _;

        let mut yaml = String::from("environments:\n");
        for arch in ["amd64", "arm64"] {
            let _ = write!(
                yaml,
                "  - id: tmachine.ubuntu2404-{arch}.docker-rootful.deb\n    backend: tmachine\n    machine: {{ os: ubuntu, version: \"24.04\", arch: {arch} }}\n    runtime: docker-rootful\n    installer: deb\n    tmachine: {{ environment: ubuntu-docker-rootful, installer: deb }}\n    capabilities: {{ compute_driver: docker }}\n"
            );
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("docker.yaml"), yaml).unwrap();
        Environments::load_dir(dir.path()).unwrap()
    }

    const AMD64: &str = "tmachine.ubuntu2404-amd64.docker-rootful.deb";
    const ARM64: &str = "tmachine.ubuntu2404-arm64.docker-rootful.deb";

    fn expand_plan(yaml: &str, narrowing: &Narrowing) -> Result<Vec<Job>> {
        expand(
            &Plan::parse(yaml).unwrap(),
            &catalog(),
            &environments(),
            &Waivers::default(),
            Some(Arch::Amd64),
            narrowing,
        )
    }

    #[test]
    fn excludes_tests_with_unmet_requirements() {
        let jobs = expand_plan(
            &format!("matrix:\n  - type: conformance\n    suites: [sandbox-lifecycle]\n    environments: [{AMD64}]\n"),
            &Narrowing::default(),
        )
        .unwrap();
        assert_eq!(jobs.len(), 1);
        let suite = &jobs[0].families[0].suites[0];
        assert_eq!(suite.run, ["long_running"]);
        assert_eq!(suite.excluded[0].name, "expose");
        assert_eq!(
            suite.excluded[0].reason,
            Exclusion::Missing(vec!["service_exposure".to_string()])
        );
        assert_eq!(
            jobs[0].families[0].filterset(),
            "(binary_id(=pkg-sandbox-lifecycle::sandbox_lifecycle) & (test(=long_running)))"
        );
    }

    #[test]
    fn omitted_suites_select_the_whole_family() {
        let jobs = expand_plan(
            &format!("matrix:\n  - type: conformance\n    environments: [{AMD64}]\n"),
            &Narrowing::default(),
        )
        .unwrap();
        let suites: Vec<_> = jobs[0].families[0]
            .suites
            .iter()
            .map(|suite| suite.suite.suite.as_str())
            .collect();
        assert_eq!(suites, ["providers", "sandbox-lifecycle"]);
        assert_eq!(
            jobs[0].families[0].filterset(),
            "binary_id(=pkg-providers::providers) | (binary_id(=pkg-sandbox-lifecycle::sandbox_lifecycle) & (test(=long_running)))"
        );
    }

    #[test]
    fn groups_entries_by_environment() {
        let jobs = expand_plan(
            &format!(
                "matrix:\n  - type: conformance\n    suites: [providers]\n    environments: [{AMD64}, {ARM64}]\n  - type: conformance\n    suites: [providers, sandbox-lifecycle]\n    environments: [{AMD64}]\n"
            ),
            &Narrowing::default(),
        )
        .unwrap();
        assert_eq!(jobs.len(), 2);
        let amd64 = jobs.iter().find(|job| job.environment.id == AMD64).unwrap();
        assert_eq!(amd64.families.len(), 1);
        assert_eq!(amd64.families[0].suites.len(), 2);
        assert!(amd64.unsupported.is_none());
        let arm64 = jobs.iter().find(|job| job.environment.id == ARM64).unwrap();
        assert!(arm64.unsupported.is_some());
    }

    #[test]
    fn narrows_to_environment_and_suite() {
        let narrowing = Narrowing {
            environments: vec![AMD64.to_string()],
            suites: vec!["providers".to_string()],
        };
        let jobs = expand_plan(
            &format!("matrix:\n  - type: conformance\n    environments: [{AMD64}, {ARM64}]\n"),
            &narrowing,
        )
        .unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].families[0].suites.len(), 1);
        assert_eq!(
            jobs[0].families[0].filterset(),
            "binary_id(=pkg-providers::providers)"
        );
    }

    #[test]
    fn rejects_unknown_names() {
        let unknown_env = expand_plan(
            "matrix:\n  - type: conformance\n    environments: [nope]\n",
            &Narrowing::default(),
        )
        .unwrap_err();
        assert!(
            unknown_env.to_string().contains("unknown environment"),
            "{unknown_env}"
        );

        let unknown_suite = expand_plan(
            &format!("matrix:\n  - type: conformance\n    suites: [sandbox-lifecyle]\n    environments: [{AMD64}]\n"),
            &Narrowing::default(),
        )
        .unwrap_err();
        assert!(
            unknown_suite
                .to_string()
                .contains("unknown conformance suite"),
            "{unknown_suite}"
        );

        let unknown_family = expand_plan(
            &format!("matrix:\n  - type: features\n    environments: [{AMD64}]\n"),
            &Narrowing::default(),
        )
        .unwrap_err();
        assert!(
            unknown_family.to_string().contains("unknown test family"),
            "{unknown_family}"
        );

        let narrowing = Narrowing {
            environments: vec![ARM64.to_string()],
            suites: vec![],
        };
        let not_in_plan = expand_plan(
            &format!("matrix:\n  - type: conformance\n    environments: [{AMD64}]\n"),
            &narrowing,
        )
        .unwrap_err();
        assert!(
            not_in_plan.to_string().contains("not in the plan"),
            "{not_in_plan}"
        );
    }
}
