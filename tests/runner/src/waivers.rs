// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Waivers: `tests/waivers.yaml`.
//!
//! A waiver excludes a test from the environments it selects because of a
//! known bug, tracked by an issue. It is the only explicit exclusion: a
//! feature an environment doesn't have is a missing capability, a machine
//! that can't boot an environment is the host check, and running less on a
//! given occasion is plan selection. Waived tests are skipped in every plan.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;

use crate::catalog::Catalog;
use crate::environments::{Catalog as Environments, Environment, Selector};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    waivers: Vec<Waiver>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Waiver {
    /// The test's stable ID.
    pub test: String,
    /// The environments the test is skipped in. Omit for all.
    #[serde(default)]
    pub environments: Selector,
    /// The issue tracking the bug.
    pub issue: String,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct Waivers {
    waivers: Vec<Waiver>,
}

impl Waivers {
    /// Load and validate waivers. A missing file means no waivers.
    pub fn load(path: &Path, catalog: &Catalog, environments: &Environments) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let yaml =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        Self::parse(&yaml, catalog, environments)
            .with_context(|| format!("load waivers from {}", path.display()))
    }

    fn parse(yaml: &str, catalog: &Catalog, environments: &Environments) -> Result<Self> {
        let file: File = serde_yml::from_str(yaml)?;
        let ids: BTreeSet<&str> = catalog
            .tests()
            .map(|(_, _, test)| test.id.as_str())
            .collect();
        for (index, waiver) in file.waivers.iter().enumerate() {
            let at = format!("waiver for {}", waiver.test);
            ensure!(
                ids.contains(waiver.test.as_str()),
                "{at}: no test has this ID; remove the waiver if the test is gone"
            );
            ensure!(
                environments
                    .iter()
                    .any(|env| waiver.environments.matches(env)),
                "{at}: no environment matches {}",
                waiver.environments
            );
            ensure!(
                waiver.issue.starts_with("https://"),
                "{at}: `issue` must link the issue tracking the bug"
            );
            ensure!(!waiver.reason.trim().is_empty(), "{at}: `reason` is empty");
            if file.waivers[..index]
                .iter()
                .any(|other| other.test == waiver.test && other.environments == waiver.environments)
            {
                bail!("{at}: duplicate waiver for {}", waiver.environments);
            }
        }
        Ok(Self {
            waivers: file.waivers,
        })
    }

    /// The waiver that skips this test in this environment, if any.
    pub fn find(&self, test_id: &str, environment: &Environment) -> Option<&Waiver> {
        self.waivers
            .iter()
            .find(|waiver| waiver.test == test_id && waiver.environments.matches(environment))
    }

    pub fn iter(&self) -> impl Iterator<Item = &Waiver> {
        self.waivers.iter()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn parse(yaml: &str) -> Result<Waivers> {
        let catalog = Catalog::load(&root()).unwrap();
        let environments = Environments::load_dir(&root().join("tests/environments")).unwrap();
        Waivers::parse(yaml, &catalog, &environments)
    }

    // long_running_exec_delete
    const TEST: &str = "t-3tfdx240";

    #[test]
    fn finds_waivers_by_test_and_environment() {
        let waivers = parse(&format!(
            "waivers:\n  - test: {TEST}\n    environments: {{ arch: arm64 }}\n    issue: https://github.com/NVIDIA/OpenShell/issues/1\n    reason: broken on arm64\n"
        ))
        .unwrap();
        let environments = Environments::load_dir(&root().join("tests/environments")).unwrap();
        let amd64 = environments
            .get("tmachine.ubuntu2404-amd64.docker-rootful.deb")
            .unwrap();
        let arm64 = environments
            .get("tmachine.ubuntu2404-arm64.docker-rootful.deb")
            .unwrap();
        assert!(waivers.find(TEST, amd64).is_none());
        assert_eq!(waivers.find(TEST, arm64).unwrap().reason, "broken on arm64");
        assert!(waivers.find("t-00000000", arm64).is_none());
    }

    #[test]
    fn rejects_invalid_waivers() {
        let cases = [
            (
                "waivers:\n  - test: t-00000000\n    issue: https://x\n    reason: r\n".to_string(),
                "no test has this ID",
            ),
            (
                format!(
                    "waivers:\n  - test: {TEST}\n    environments: {{ runtime: nope }}\n    issue: https://x\n    reason: r\n"
                ),
                "no environment matches",
            ),
            (
                format!("waivers:\n  - test: {TEST}\n    issue: '#123'\n    reason: r\n"),
                "must link the issue",
            ),
            (
                format!("waivers:\n  - test: {TEST}\n    issue: https://x\n    reason: ' '\n"),
                "`reason` is empty",
            ),
            (
                format!(
                    "waivers:\n  - test: {TEST}\n    issue: https://x\n    reason: r\n  - test: {TEST}\n    issue: https://y\n    reason: r\n"
                ),
                "duplicate waiver",
            ),
        ];
        for (yaml, expected) in cases {
            let err = format!("{:#}", parse(&yaml).unwrap_err());
            assert!(err.contains(expected), "{expected}: {err}");
        }
        assert!(parse("waivers:\n  - test: x\n    issu: y\n").is_err());
    }

    #[test]
    fn repository_waivers_are_valid() {
        let catalog = Catalog::load(&root()).unwrap();
        let environments = Environments::load_dir(&root().join("tests/environments")).unwrap();
        Waivers::load(&root().join("tests/waivers.yaml"), &catalog, &environments).unwrap();
    }
}
