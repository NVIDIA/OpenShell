// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Test plans: `tests/plans/*.yaml`.
//!
//! ```yaml
//! matrix:
//!   - type: conformance
//!     suites: [smoke]   # omit for every suite in the family
//!     environments: [tmachine.ubuntu2404-amd64.docker-rootful.deb]
//! ```

use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub matrix: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// The test family, e.g. `conformance`.
    #[serde(rename = "type")]
    pub family: String,
    /// Suites to run. `None` selects every suite in the family.
    #[serde(default)]
    pub suites: Option<Vec<String>>,
    pub environments: Vec<String>,
}

impl Plan {
    pub fn load(path: &Path) -> Result<Self> {
        let yaml = std::fs::read_to_string(path)
            .with_context(|| format!("read plan {}", path.display()))?;
        Self::parse(&yaml).with_context(|| format!("load plan {}", path.display()))
    }

    pub fn parse(yaml: &str) -> Result<Self> {
        let plan: Self = serde_yml::from_str(yaml)?;
        ensure!(!plan.matrix.is_empty(), "plan has an empty matrix");
        for (index, entry) in plan.matrix.iter().enumerate() {
            ensure!(
                !entry.environments.is_empty(),
                "matrix entry {index} ({}) names no environments",
                entry.family
            );
            ensure!(
                entry
                    .suites
                    .as_ref()
                    .is_none_or(|suites| !suites.is_empty()),
                "matrix entry {index} ({}) has an empty suite list; omit `suites` to select every suite",
                entry.family
            );
        }
        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plan() {
        let plan = Plan::parse(
            "matrix:\n  - type: conformance\n    suites: [smoke]\n    environments: [e1, e2]\n  - type: conformance\n    environments: [e3]\n",
        )
        .unwrap();
        assert_eq!(plan.matrix.len(), 2);
        assert_eq!(plan.matrix[0].family, "conformance");
        assert_eq!(
            plan.matrix[0].suites.as_deref(),
            Some(&["smoke".to_string()][..])
        );
        assert_eq!(plan.matrix[1].suites, None);
    }

    #[test]
    fn rejects_unknown_fields() {
        let err =
            Plan::parse("matrix:\n  - type: conformance\n    suite: [x]\n    environments: [e]\n")
                .unwrap_err();
        assert!(format!("{err:#}").contains("suite"), "{err:#}");
    }

    #[test]
    fn rejects_entry_without_environments() {
        let err =
            Plan::parse("matrix:\n  - type: conformance\n    environments: []\n").unwrap_err();
        assert!(err.to_string().contains("names no environments"), "{err}");
    }

    #[test]
    fn rejects_empty_suite_list() {
        let err =
            Plan::parse("matrix:\n  - type: conformance\n    suites: []\n    environments: [e]\n")
                .unwrap_err();
        assert!(err.to_string().contains("empty suite list"), "{err}");
    }
}
