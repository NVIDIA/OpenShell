// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Expanding a plan into jobs.
//!
//! Jobs are grouped by environment so each environment is provisioned once
//! and runs every family and suite the plan selects for it. A suite runs every
//! test in it; `#[ignore]`d tests are left out of the catalog.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};

use crate::catalog::{Catalog, Suite};
use crate::environments::{Arch, Catalog as Environments, Environment};
use crate::plan::Plan;

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

    check_conformance_is_uniform(&selected)?;

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
                .map(|suite| suite_job(family.suite(suite).expect("validated above")))
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

/// The family every driver and install must pass. A plan can't run part of it
/// somewhere, or conformance would mean different things in different places.
const CONFORMANCE: &str = "conformance";

/// Every environment the plan runs conformance in must select the same suites.
fn check_conformance_is_uniform(
    selected: &BTreeMap<String, BTreeMap<String, Vec<String>>>,
) -> Result<()> {
    let mut by_suites: BTreeMap<BTreeSet<&str>, Vec<&str>> = BTreeMap::new();
    for (id, families) in selected {
        if let Some(suites) = families.get(CONFORMANCE) {
            by_suites
                .entry(suites.iter().map(String::as_str).collect())
                .or_default()
                .push(id);
        }
    }
    if by_suites.len() > 1 {
        let groups: Vec<String> = by_suites
            .iter()
            .map(|(suites, ids)| {
                format!(
                    "{} select {}",
                    ids.join(", "),
                    suites.iter().copied().collect::<Vec<_>>().join(", ")
                )
            })
            .collect();
        bail!(
            "the plan selects different {CONFORMANCE} suites in different environments, so \
             {CONFORMANCE} would not mean the same thing everywhere; use the same suites \
             everywhere, or move the suite that can't run everywhere to another family:\n  {}",
            groups.join("\n  ")
        );
    }
    Ok(())
}

/// What strict mode (CI) refuses to run: nothing selected at all, an
/// environment this host can't provision, and a family with no tests. Locally these are reported and skipped, because a
/// laptop can't boot every environment; in CI each one means a lane that would
/// pass without testing what it claims to.
pub fn strict_problems(jobs: &[Job]) -> Vec<String> {
    if jobs.is_empty() {
        return vec!["the plan selects no tests".to_string()];
    }
    let mut problems = Vec::new();
    for job in jobs {
        let id = &job.environment.id;
        if let Some(reason) = &job.unsupported {
            problems.push(format!("{id} is unsupported on this host: {reason}"));
            continue;
        }
        for family in &job.families {
            if !family.has_tests() {
                problems.push(format!(
                    "{id} / {}: the selected suites have no tests, so nothing would run",
                    family.family
                ));
            }
        }
    }
    problems
}

fn suite_job(suite: &Suite) -> SuiteJob {
    SuiteJob {
        suite: suite.clone(),
        run: suite.tests.iter().map(|test| test.name.clone()).collect(),
    }
}

/// The `classname` nextest gives a suite's tests in `JUnit` output, which is
/// the suite's nextest binary ID.
fn junit_classname(suite: &Suite) -> String {
    format!("{}::{}", suite.package, suite.binary)
}

impl FamilyJob {
    /// Whether any test will run.
    pub fn has_tests(&self) -> bool {
        self.suites.iter().any(|suite| !suite.run.is_empty())
    }

    /// Stable test IDs keyed by nextest `JUnit` `(classname, name)`, for the
    /// tests that have one.
    pub fn test_ids(&self) -> BTreeMap<(String, String), String> {
        self.suites
            .iter()
            .flat_map(|job| {
                let classname = junit_classname(&job.suite);
                job.suite.tests.iter().filter_map(move |test| {
                    test.id
                        .clone()
                        .map(|id| ((classname.clone(), test.name.clone()), id))
                })
            })
            .collect()
    }

    /// The tests the report must contain, as nextest `JUnit`
    /// `(classname, name)` pairs: every test selected to run. A missing one
    /// fails the job.
    pub fn expected_tests(&self) -> BTreeSet<(String, String)> {
        self.suites
            .iter()
            .flat_map(|job| {
                let classname = junit_classname(&job.suite);
                job.run
                    .iter()
                    .map(move |name| (classname.clone(), name.clone()))
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
                format!(
                    "binary_id(={}::{})",
                    suite.suite.package, suite.suite.binary
                )
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
        let suite = |name: &str, tests: &[&str]| Suite {
            suite: name.to_string(),
            binary: name.replace('-', "_"),
            package: format!("pkg-{name}"),
            tests: tests
                .iter()
                .enumerate()
                .map(|(index, name)| Test {
                    id: Some(format!("t-{index:08}")),
                    name: (*name).to_string(),
                    description: "d".to_string(),
                })
                .collect(),
        };
        let family = Family {
            name: "conformance".to_string(),
            workspace: PathBuf::new(),
            suites: [
                suite("sandbox-lifecycle", &["long_running", "expose"]),
                suite("providers", &["create_provider"]),
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
                "  - id: tmachine.ubuntu2404-{arch}.docker-rootful.deb\n    backend: tmachine\n    machine: {{ os: ubuntu, version: \"24.04\", arch: {arch} }}\n    runtime: docker-rootful\n    installer: deb\n    tmachine: {{ environment: ubuntu-docker-rootful, installer: deb }}\n"
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
            Some(Arch::Amd64),
            narrowing,
        )
    }

    #[test]
    fn a_suite_runs_every_test_in_it() {
        let jobs = expand_plan(
            &format!("matrix:\n  - type: conformance\n    suites: [sandbox-lifecycle]\n    environments: [{AMD64}]\n"),
            &Narrowing::default(),
        )
        .unwrap();
        assert_eq!(jobs.len(), 1);
        let suite = &jobs[0].families[0].suites[0];
        assert_eq!(suite.run, ["long_running", "expose"]);
        assert_eq!(
            jobs[0].families[0].filterset(),
            "binary_id(=pkg-sandbox-lifecycle::sandbox_lifecycle)"
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
            "binary_id(=pkg-providers::providers) | binary_id(=pkg-sandbox-lifecycle::sandbox_lifecycle)"
        );
    }

    #[test]
    fn groups_entries_by_environment() {
        let jobs = expand_plan(
            &format!(
                "matrix:\n  - type: conformance\n    suites: [providers]\n    environments: [{AMD64}, {ARM64}]\n  - type: conformance\n    suites: [sandbox-lifecycle]\n    environments: [{AMD64}, {ARM64}]\n"
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

    #[test]
    fn conformance_must_select_the_same_suites_in_every_environment() {
        let err = expand_plan(
            &format!(
                "matrix:\n  - type: conformance\n    environments: [{AMD64}]\n  - type: conformance\n    suites: [providers]\n    environments: [{ARM64}]\n"
            ),
            &Narrowing::default(),
        )
        .unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("different conformance suites"),
            "{message}"
        );
        assert!(
            message.contains(AMD64) && message.contains(ARM64),
            "{message}"
        );

        // The same suites listed differently are the same selection.
        expand_plan(
            &format!(
                "matrix:\n  - type: conformance\n    suites: [providers, sandbox-lifecycle]\n    environments: [{AMD64}]\n  - type: conformance\n    environments: [{ARM64}]\n"
            ),
            &Narrowing::default(),
        )
        .unwrap();
    }

    #[test]
    fn expected_tests_are_the_ones_in_the_suite() {
        let jobs = expand_plan(
            &format!("matrix:\n  - type: conformance\n    suites: [providers]\n    environments: [{AMD64}]\n"),
            &Narrowing::default(),
        )
        .unwrap();
        let family = &jobs[0].families[0];
        assert_eq!(
            family.expected_tests().into_iter().collect::<Vec<_>>(),
            [(
                "pkg-providers::providers".to_string(),
                "create_provider".to_string()
            )]
        );
    }

    #[test]
    fn strict_mode_rejects_unsupported_environments_and_empty_selections() {
        let plan = format!(
            "matrix:\n  - type: conformance\n    suites: [sandbox-lifecycle]\n    environments: [{AMD64}, {ARM64}]\n"
        );
        let jobs = expand_plan(&plan, &Narrowing::default()).unwrap();
        let problems = strict_problems(&jobs);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains(ARM64), "{problems:?}");
        assert!(
            problems[0].contains("unsupported on this host"),
            "{problems:?}"
        );

        assert_eq!(
            strict_problems(&[]),
            ["the plan selects no tests".to_string()]
        );
    }
}
