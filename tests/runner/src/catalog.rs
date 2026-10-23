// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The test catalog: every family, suite, and test, read from source.
//!
//! A family is a Cargo workspace directly under `tests/suites/` that has at
//! least one testkit suite. A suite is one test binary
//! (`<crate>/tests/<suite_name>.rs`) containing `#[testkit::test]` functions;
//! the suite name is the binary name with `_` replaced by `-`. Tests are
//! parsed with `testkit-spec`, the same parser the macro uses, so the runner
//! never executes test binaries on the host to learn about them. Workspaces
//! whose tests are plain `#[test]` functions have no testkit suites and are
//! not families. A suite whose tests are all `#[ignore]`d is kept with no
//! tests, so selecting it reports that nothing would run.
//!
//! A test's identity is its optional stable ID, and its function name
//! otherwise. IDs are unique across every family, so a test can move between
//! suites and families without changing its ID.
//!
//! Adapted from the catalog in Evan Lezar's NVIDIA/OpenShell#4629.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Where families live, relative to the repository root.
const SUITES_DIR: &str = "tests/suites";

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
    /// The stable test ID, if the test declares one.
    pub id: Option<String>,
    /// The function name, which is also the nextest test name.
    pub name: String,
    pub description: String,
}

impl Test {
    /// How to name the test to a reader: the function name, with the ID
    /// when there is one.
    pub fn label(&self) -> String {
        match &self.id {
            Some(id) => format!("{} ({id})", self.name),
            None => self.name.clone(),
        }
    }
}

/// Every known family, keyed by name.
#[derive(Debug, Serialize)]
pub struct Catalog {
    pub families: BTreeMap<String, Family>,
}

impl Catalog {
    pub fn load(root: &Path) -> Result<Self> {
        let suites_dir = root.join(SUITES_DIR);
        let mut workspaces: Vec<_> = std::fs::read_dir(&suites_dir)
            .with_context(|| format!("read {}", suites_dir.display()))?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<_>>()
            .with_context(|| format!("read {}", suites_dir.display()))?;
        workspaces.retain(|path| path.join("Cargo.toml").is_file());
        workspaces.sort();

        let mut families = BTreeMap::new();
        for workspace in workspaces {
            let name = workspace
                .file_name()
                .and_then(|name| name.to_str())
                .with_context(|| format!("{} is not a UTF-8 name", workspace.display()))?
                .to_string();
            let family = Family::load(&name, &workspace)
                .with_context(|| format!("load {name} test catalog"))?;
            if !family.suites.is_empty() {
                families.insert(name, family);
            }
        }
        let catalog = Self { families };
        catalog.check_unique()?;
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
    fn check_unique(&self) -> Result<()> {
        let mut seen: BTreeMap<&str, String> = BTreeMap::new();
        for (family, suite, test) in self.tests() {
            let Some(id) = &test.id else { continue };
            let location = format!("{}/{}/{}", family.name, suite.suite, test.name);
            if let Some(first) = seen.insert(id, location.clone()) {
                bail!("test ID {id} is used by both {first} and {location}");
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
    workspace: Option<WorkspaceSection>,
}

#[derive(Deserialize)]
struct WorkspaceSection {
    #[serde(default)]
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
        let members = manifest.workspace.map(|w| w.members).unwrap_or_default();
        let mut suites = BTreeMap::new();
        for member in members {
            // Cargo expands globs in `members`; the catalog doesn't, and would
            // otherwise find no suites in them without saying so.
            if member.contains(['*', '?', '[']) {
                bail!(
                    "{}: list workspace members explicitly; the test catalog doesn't expand {member:?}",
                    workspace.join("Cargo.toml").display()
                );
            }
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
        // Skip files that cannot contain a test before parsing them.
        if !source.contains("testkit::test") {
            continue;
        }
        let specs = testkit_spec::scan(&source)
            .map_err(|error| anyhow::anyhow!("{}: {error}", file.display()))?;
        if specs.is_empty() {
            continue;
        }
        // An `#[ignore]` test only runs with `--run-ignored`, so it is not part
        // of what a lane expects. A suite whose tests are all ignored stays in
        // the catalog with no tests, so a plan that selects it is told that
        // nothing would run rather than that the suite doesn't exist.
        let specs: Vec<_> = specs.into_iter().filter(|spec| !spec.ignored).collect();
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

    fn test(id: Option<&str>, name: &str) -> Test {
        Test {
            id: id.map(str::to_string),
            name: name.to_string(),
            description: "d".to_string(),
        }
    }

    fn catalog_of(tests: Vec<(&str, Test)>) -> Catalog {
        let mut families: BTreeMap<String, Family> = BTreeMap::new();
        for (family, test) in tests {
            let entry = families
                .entry(family.to_string())
                .or_insert_with(|| Family {
                    name: family.to_string(),
                    workspace: PathBuf::new(),
                    suites: BTreeMap::from([(
                        "s".to_string(),
                        Suite {
                            suite: "s".to_string(),
                            binary: "s".to_string(),
                            package: "p".to_string(),
                            tests: Vec::new(),
                        },
                    )]),
                });
            entry.suites.get_mut("s").unwrap().tests.push(test);
        }
        Catalog { families }
    }

    #[test]
    fn repository_catalog_has_the_sandbox_smoke_suite() {
        let catalog = Catalog::load(&repo_root()).unwrap();
        let family = catalog.family("conformance").unwrap();
        let suite = family.suite("smoke").unwrap();
        assert_eq!(suite.binary, "smoke");
        assert_eq!(suite.package, "sandbox");
        assert!(
            suite
                .tests
                .iter()
                .all(|test| !test.name.is_empty() && !test.description.is_empty())
        );
        assert!(!suite.tests.is_empty());
    }

    #[test]
    fn glob_workspace_members_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"suites/*\"]\n",
        )
        .unwrap();
        let err = Family::load("conformance", dir.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("list workspace members explicitly"),
            "{err}"
        );
    }

    #[test]
    fn ignored_tests_are_not_expected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("tests")).unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"pkg\"\nversion = \"0.0.0\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("tests/s.rs"),
            "/// Runs.\n#[testkit::test]\nasync fn runs(cx: &mut Context) -> testkit::Result { Ok(()) }\n\n/// Needs a flag.\n#[ignore]\n#[testkit::test]\nasync fn ignored(cx: &mut Context) -> testkit::Result { Ok(()) }\n",
        )
        .unwrap();
        let suites = member_suites(dir.path()).unwrap();
        let names: Vec<_> = suites[0].tests.iter().map(|test| &test.name[..]).collect();
        assert_eq!(names, ["runs"]);
    }

    #[test]
    fn suites_with_every_test_ignored_have_no_tests() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("tests")).unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"pkg\"\nversion = \"0.0.0\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("tests/all_ignored.rs"),
            "/// Broken.\n#[ignore = \"https://example.com/1\"]\n#[testkit::test]\nasync fn broken(cx: &mut Context) -> testkit::Result { Ok(()) }\n",
        )
        .unwrap();
        let suites = member_suites(dir.path()).unwrap();
        assert_eq!(suites.len(), 1);
        assert_eq!(suites[0].suite, "all-ignored");
        assert!(suites[0].tests.is_empty());
    }

    #[test]
    fn workspaces_without_testkit_suites_are_not_families() {
        let catalog = Catalog::load(&repo_root()).unwrap();
        for family in catalog.families.values() {
            assert!(!family.suites.is_empty(), "{}", family.name);
        }
    }

    #[test]
    fn duplicate_ids_are_rejected_across_families() {
        let catalog = catalog_of(vec![
            ("a", test(Some("t-00000001"), "first")),
            ("b", test(Some("t-00000001"), "second")),
        ]);
        let err = catalog.check_unique().unwrap_err().to_string();
        assert!(
            err.contains("a/s/first") && err.contains("b/s/second"),
            "{err}"
        );
    }

    #[test]
    fn tests_without_ids_may_share_a_name_across_families() {
        let catalog = catalog_of(vec![("a", test(None, "same")), ("b", test(None, "same"))]);
        catalog.check_unique().unwrap();
    }

    #[test]
    fn labels_include_the_id_when_there_is_one() {
        assert_eq!(test(None, "n").label(), "n");
        assert_eq!(test(Some("t-00000001"), "n").label(), "n (t-00000001)");
    }

    #[test]
    fn unknown_names_list_known_ones() {
        let catalog = Catalog::load(&repo_root()).unwrap();
        let err = catalog.family("no-such-family").unwrap_err();
        assert!(err.to_string().contains("conformance"), "{err}");
        let err = catalog
            .family("conformance")
            .unwrap()
            .suite("smok")
            .unwrap_err();
        assert!(err.to_string().contains("smoke"), "{err}");
    }
}
