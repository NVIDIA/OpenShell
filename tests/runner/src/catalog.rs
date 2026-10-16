// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The test catalog: every family, suite, and test, read from source.
//!
//! A family is a Cargo workspace under `tests/suites/`. A suite is one test
//! binary (`<crate>/tests/<suite_name>.rs`) containing `#[testkit::test]`
//! functions; the suite name is the binary name with `_` replaced by `-`.
//! Tests are parsed with `testkit-spec`, the same parser the macro uses, so
//! the runner never executes test binaries on the host to learn about them.
//! Test IDs are unique across every family, so a test can move between
//! suites and families without changing its ID.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Families the runner knows how to run, and their workspaces relative to
/// the repository root.
const FAMILIES: &[(&str, &str)] = &[("conformance", "tests/suites/conformance")];

#[derive(Debug, Serialize)]
pub struct Family {
    pub name: String,
    #[serde(skip)]
    pub workspace: PathBuf,
    pub suites: BTreeMap<String, Suite>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Suite {
    pub suite: String,
    pub binary: String,
    pub package: String,
    pub tests: Vec<Test>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Test {
    /// The stable test ID.
    pub id: String,
    /// The function name, which is also the nextest test name.
    pub name: String,
    pub description: String,
    pub requires: Vec<String>,
}

/// Every known family, keyed by name.
#[derive(Debug, Serialize)]
pub struct Catalog {
    pub families: BTreeMap<String, Family>,
}

impl Catalog {
    pub fn load(root: &Path) -> Result<Self> {
        let mut families = BTreeMap::new();
        for (name, workspace) in FAMILIES {
            let family = Family::load(name, &root.join(workspace))
                .with_context(|| format!("load {name} test catalog"))?;
            families.insert((*name).to_string(), family);
        }
        let catalog = Self { families };
        catalog.check_unique_ids()?;
        Ok(catalog)
    }

    /// Every test, with its family and suite.
    pub fn tests(&self) -> impl Iterator<Item = (&Family, &Suite, &Test)> {
        self.families.values().flat_map(|family| {
            family
                .suites
                .values()
                .flat_map(move |suite| suite.tests.iter().map(move |test| (family, suite, test)))
        })
    }

    /// Fail if two tests anywhere in the catalog share an ID.
    fn check_unique_ids(&self) -> Result<()> {
        let mut seen: BTreeMap<&str, String> = BTreeMap::new();
        for family in self.families.values() {
            for suite in family.suites.values() {
                for test in &suite.tests {
                    let location = format!("{}/{}/{}", family.name, suite.suite, test.name);
                    if let Some(first) = seen.insert(&test.id, location.clone()) {
                        bail!("test ID {} is used by both {first} and {location}", test.id);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn family(&self, name: &str) -> Result<&Family> {
        self.families.get(name).with_context(|| {
            format!(
                "unknown test family {name:?}; known families: {}",
                self.families.keys().cloned().collect::<Vec<_>>().join(", ")
            )
        })
    }
}

#[derive(Deserialize)]
struct WorkspaceManifest {
    workspace: WorkspaceSection,
}

#[derive(Deserialize)]
struct WorkspaceSection {
    members: Vec<String>,
}

#[derive(Deserialize)]
struct PackageManifest {
    package: PackageSection,
}

#[derive(Deserialize)]
struct PackageSection {
    name: String,
}

impl Family {
    fn load(name: &str, workspace: &Path) -> Result<Self> {
        let manifest: WorkspaceManifest = read_toml(&workspace.join("Cargo.toml"))?;
        let mut suites = BTreeMap::new();
        for member in manifest.workspace.members {
            let member_dir = workspace.join(&member);
            for suite in member_suites(&member_dir)? {
                if let Some(existing) = suites.insert(suite.suite.clone(), suite) {
                    bail!(
                        "suite {:?} is defined more than once (again in {member})",
                        existing.suite
                    );
                }
            }
        }
        Ok(Self {
            name: name.to_string(),
            workspace: workspace.to_path_buf(),
            suites,
        })
    }

    pub fn suite(&self, name: &str) -> Result<&Suite> {
        self.suites.get(name).with_context(|| {
            format!(
                "unknown {} suite {name:?}; known suites: {}",
                self.name,
                self.suites.keys().cloned().collect::<Vec<_>>().join(", ")
            )
        })
    }

    /// Packages containing the given suites.
    pub fn packages<'a>(&self, suites: impl IntoIterator<Item = &'a str>) -> BTreeSet<String> {
        suites
            .into_iter()
            .filter_map(|suite| self.suites.get(suite))
            .map(|suite| suite.package.clone())
            .collect()
    }
}

/// Suites in one workspace member: its `tests/*.rs` files that contain
/// `#[testkit::test]` functions.
fn member_suites(member_dir: &Path) -> Result<Vec<Suite>> {
    let tests_dir = member_dir.join("tests");
    if !tests_dir.is_dir() {
        return Ok(Vec::new());
    }
    let package: PackageManifest = read_toml(&member_dir.join("Cargo.toml"))?;

    let mut files: Vec<_> = std::fs::read_dir(&tests_dir)
        .with_context(|| format!("read {}", tests_dir.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<_>>()?;
    files.retain(|path| path.extension().is_some_and(|ext| ext == "rs"));
    files.sort();

    let mut suites = Vec::new();
    for file in files {
        let source =
            std::fs::read_to_string(&file).with_context(|| format!("read {}", file.display()))?;
        let specs = testkit_spec::scan(&source)
            .map_err(|error| anyhow::anyhow!("{}: {error}", file.display()))?;
        if specs.is_empty() {
            continue;
        }
        let binary = file
            .file_stem()
            .and_then(|stem| stem.to_str())
            .with_context(|| format!("test file name {} is not UTF-8", file.display()))?
            .to_string();
        suites.push(Suite {
            suite: binary.replace('_', "-"),
            binary,
            package: package.package.name.clone(),
            tests: specs
                .into_iter()
                .map(|spec| Test {
                    id: spec.id,
                    name: spec.name.to_string(),
                    description: spec.description,
                    requires: spec.requires.iter().map(ToString::to_string).collect(),
                })
                .collect(),
        });
    }
    Ok(suites)
}

fn read_toml<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parse {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn repository_catalog_has_sandbox_lifecycle() {
        let catalog = Catalog::load(&repo_root()).unwrap();
        let family = catalog.family("conformance").unwrap();
        let suite = family.suite("sandbox-lifecycle").unwrap();
        assert_eq!(suite.binary, "sandbox_lifecycle");
        assert_eq!(suite.package, "openshell-conformance-sandbox-lifecycle");
        assert!(
            suite
                .tests
                .iter()
                .any(|test| test.name == "long_running_exec_delete"
                    && testkit_spec::is_valid_id(&test.id)
                    && !test.description.is_empty())
        );
        // CLI-driven tests in the same workspace are not testkit suites.
        assert!(
            family
                .suites
                .values()
                .all(|suite| suite.package != "openshell-test-conformance-cli")
        );
    }

    #[test]
    fn duplicate_ids_are_rejected_across_families() {
        let test = |name: &str| Test {
            id: "t-00000001".to_string(),
            name: name.to_string(),
            description: "d".to_string(),
            requires: Vec::new(),
        };
        let family = |name: &str, test_name: &str| Family {
            name: name.to_string(),
            workspace: PathBuf::new(),
            suites: BTreeMap::from([(
                "s".to_string(),
                Suite {
                    suite: "s".to_string(),
                    binary: "s".to_string(),
                    package: "p".to_string(),
                    tests: vec![test(test_name)],
                },
            )]),
        };
        let catalog = Catalog {
            families: BTreeMap::from([
                ("a".to_string(), family("a", "first")),
                ("b".to_string(), family("b", "second")),
            ]),
        };
        let err = catalog.check_unique_ids().unwrap_err().to_string();
        assert!(
            err.contains("a/s/first") && err.contains("b/s/second"),
            "{err}"
        );
    }

    #[test]
    fn unknown_names_list_known_ones() {
        let catalog = Catalog::load(&repo_root()).unwrap();
        let err = catalog.family("features").unwrap_err();
        assert!(err.to_string().contains("conformance"), "{err}");
        let err = catalog
            .family("conformance")
            .unwrap()
            .suite("sandbox-lifecyle")
            .unwrap_err();
        assert!(err.to_string().contains("sandbox-lifecycle"), "{err}");
    }
}
