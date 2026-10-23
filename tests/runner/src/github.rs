// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The CI matrix, generated from a plan.
//!
//! A workflow runs one job per entry of
//! `openshell-test-runner test --plan <plan> --emit-github-matrix`, so which
//! environments run is decided by the plan, not by a list copied into a
//! workflow.
//! Nothing checks the output in: the plan is the only copy.
//!
//! Adapted from the matrix generation in Evan Lezar's NVIDIA/OpenShell#4629.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::catalog::Catalog;
use crate::environments::{Arch, Catalog as Environments};
use crate::jobs::{self, Narrowing};
use crate::plan::Plan;

/// One CI job: a plan run in one environment.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct GithubJob {
    pub plan: String,
    /// The environment ID, for `openshell-test-runner test --env`.
    pub environment: String,
    /// The GitHub runner label that can boot the environment.
    pub runner: String,
}

/// The strategy matrix a workflow reads with `fromJSON`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct GithubMatrix {
    pub include: Vec<GithubJob>,
}

/// The GitHub-hosted runner that can boot guests of `arch`: tmachine boots
/// guests of the host's architecture only.
pub const fn runner_label(arch: Arch) -> &'static str {
    match arch {
        Arch::Amd64 => "ubuntu-24.04",
        Arch::Arm64 => "ubuntu-24.04-arm",
    }
}

/// Expand a plan the way a lane would and list one job per environment,
/// ignoring which host generates the matrix.
///
/// # Errors
///
/// Fails if the plan names an unknown family, suite or environment, or if the
/// plan selects an environment whose suites have no tests: a CI lane that
/// would pass without testing anything.
pub fn github_matrix(
    plan_name: &str,
    plan: &Plan,
    catalog: &Catalog,
    environments: &Environments,
) -> Result<GithubMatrix> {
    let jobs = jobs::expand(plan, catalog, environments, None, &Narrowing::default())?;
    if jobs.is_empty() {
        bail!("plan {plan_name} selects no tests");
    }

    let mut matrix = GithubMatrix::default();
    for job in &jobs {
        let id = &job.environment.id;
        if let Some(family) = job.families.iter().find(|family| !family.has_tests()) {
            bail!(
                "plan {plan_name} selects {id} / {}, but its suites have no tests",
                family.family
            );
        }
        matrix.include.push(GithubJob {
            plan: plan_name.to_string(),
            environment: id.clone(),
            runner: runner_label(job.environment.machine.arch).to_string(),
        });
    }
    matrix
        .include
        .sort_by(|a, b| a.environment.cmp(&b.environment));
    Ok(matrix)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use super::*;
    use crate::catalog::{Family, Suite, Test};

    const AMD64: &str = "tmachine.ubuntu2404-amd64.docker-rootful.deb";
    const ARM64: &str = "tmachine.ubuntu2404-arm64.docker-rootful.deb";

    fn environments() -> Environments {
        let mut yaml = String::from("environments:\n");
        for arch in ["amd64", "arm64"] {
            yaml.push_str(&format!(
                "  - id: tmachine.ubuntu2404-{arch}.docker-rootful.deb\n    backend: tmachine\n    machine: {{ os: ubuntu, version: \"24.04\", arch: {arch} }}\n    runtime: docker-rootful\n    installer: deb\n    tmachine: {{ environment: ubuntu-docker-rootful, installer: deb }}\n"
            ));
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("docker.yaml"), yaml).unwrap();
        Environments::load_dir(dir.path()).unwrap()
    }

    fn catalog() -> Catalog {
        let suite = Suite {
            suite: "smoke".to_string(),
            binary: "smoke".to_string(),
            package: "pkg".to_string(),
            tests: vec![Test {
                id: None,
                name: "only".to_string(),
                description: "d".to_string(),
            }],
        };
        Catalog {
            families: BTreeMap::from([(
                "conformance".to_string(),
                Family {
                    name: "conformance".to_string(),
                    workspace: PathBuf::new(),
                    suites: BTreeMap::from([("smoke".to_string(), suite)]),
                },
            )]),
        }
    }

    fn plan() -> Plan {
        Plan::parse(&format!(
            "matrix:\n  - type: conformance\n    environments: [{ARM64}, {AMD64}]\n"
        ))
        .unwrap()
    }

    fn generate() -> Result<GithubMatrix> {
        github_matrix("p", &plan(), &catalog(), &environments())
    }

    #[test]
    fn generates_a_job_per_environment_with_its_runner() {
        let matrix = generate().unwrap();
        assert_eq!(
            matrix.include,
            [
                GithubJob {
                    plan: "p".to_string(),
                    environment: AMD64.to_string(),
                    runner: "ubuntu-24.04".to_string(),
                },
                GithubJob {
                    plan: "p".to_string(),
                    environment: ARM64.to_string(),
                    runner: "ubuntu-24.04-arm".to_string(),
                },
            ]
        );
    }

    #[test]
    fn serializes_as_the_include_list_a_workflow_reads() {
        let json = serde_json::to_value(generate().unwrap()).unwrap();
        assert_eq!(json["include"][0]["environment"], AMD64);
        assert_eq!(json["include"][0]["runner"], "ubuntu-24.04");
    }
}
