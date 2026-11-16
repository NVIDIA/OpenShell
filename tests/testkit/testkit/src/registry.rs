// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The tests linked into a program, registered by `#[testkit::test]`.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;

use crate::run::TestInfo;

/// Every `#[testkit::test]` linked into the program.
#[linkme::distributed_slice]
pub static TESTS: [Test];

/// A registered test.
#[derive(Debug)]
pub struct Test {
    pub info: TestInfo,
    /// The directory under `tests/suites/` holding the test's crate, if any.
    pub family: Option<&'static str>,
    /// `module_path!()` where the test is defined.
    pub module_path: &'static str,
    pub ignored: bool,
    /// The reason given in `#[ignore = "..."]`.
    pub ignore_reason: Option<&'static str>,
    /// Runs the test through [`crate::run`]; panics to fail it.
    pub run: fn() -> Pin<Box<dyn Future<Output = ()>>>,
}

impl Test {
    /// The test's name, as libtest and nextest name it: the module path
    /// without the crate, then the function name.
    pub fn name(&self) -> String {
        match self.module_path.split_once("::") {
            Some((_crate, module)) => format!("{module}::{}", self.info.name),
            None => self.info.name.to_string(),
        }
    }

    pub fn family(&self) -> &'static str {
        self.family.unwrap_or("-")
    }
}

/// Names a test cannot have at the top level: the program would read them as
/// its own subcommands, so nextest could not run the test by name.
pub const RESERVED_NAMES: &[&str] = &["help", "list", "ready", "run"];

/// Check the tests can be told apart by name.
pub fn validate(tests: &[Test]) -> Result<(), String> {
    let mut names = BTreeSet::new();
    for test in tests {
        let name = test.name();
        if RESERVED_NAMES.contains(&name.as_str()) {
            return Err(format!(
                "test {name} has the name of a subcommand; rename it or move it into a module"
            ));
        }
        if !names.insert(name.clone()) {
            return Err(format!(
                "two tests are named {name}; test names must be unique in a program"
            ));
        }
    }
    Ok(())
}

/// Which tests to run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Selection {
    /// Run tests whose name contains any of these; all tests if empty.
    pub filters: Vec<String>,
    /// Run `#[ignore]`d tests too, instead of reporting them as skipped.
    pub include_ignored: bool,
}

/// What a selection does with one test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    Run,
    /// Selected, but ignored and not asked for.
    Skip,
}

impl Selection {
    /// The tests this selects, in name order, with what to do with each.
    pub fn apply<'a>(&self, tests: &'a [Test]) -> Vec<(&'a Test, Disposition)> {
        let mut selected: Vec<_> = tests
            .iter()
            .filter_map(|test| {
                self.disposition(test)
                    .map(|disposition| (test, disposition))
            })
            .collect();
        selected.sort_by_cached_key(|(test, _)| test.name());
        selected
    }

    fn disposition(&self, test: &Test) -> Option<Disposition> {
        let name = test.name();
        if !self.filters.is_empty()
            && !self
                .filters
                .iter()
                .any(|filter| name.contains(filter.as_str()))
        {
            return None;
        }
        if test.ignored && !self.include_ignored {
            Some(Disposition::Skip)
        } else {
            Some(Disposition::Run)
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{Disposition, Selection, Test, validate};
    use crate::run::TestInfo;

    pub(crate) const fn test(module_path: &'static str, name: &'static str, ignored: bool) -> Test {
        Test {
            info: TestInfo {
                name,
                description: "A test.",
            },
            family: Some("conformance"),
            module_path,
            ignored,
            ignore_reason: None,
            run: || Box::pin(async {}),
        }
    }

    const TESTS: &[Test] = &[
        test("sandbox::smoke", "create_exec_delete", false),
        test("sandbox::lifecycle", "stop_start", false),
        test("sandbox::lifecycle", "restart_later", true),
        test("smoke", "top_level", false),
    ];

    fn names(selection: &Selection) -> Vec<(String, Disposition)> {
        selection
            .apply(TESTS)
            .into_iter()
            .map(|(test, disposition)| (test.name(), disposition))
            .collect()
    }

    #[test]
    fn names_follow_libtest() {
        assert_eq!(TESTS[0].name(), "smoke::create_exec_delete");
        assert_eq!(TESTS[3].name(), "top_level");
    }

    #[test]
    fn selection_follows_libtest() {
        use Disposition::{Run, Skip};
        let all = Selection::default();
        assert_eq!(
            names(&all),
            [
                ("lifecycle::restart_later".into(), Skip),
                ("lifecycle::stop_start".into(), Run),
                ("smoke::create_exec_delete".into(), Run),
                ("top_level".into(), Run),
            ]
        );

        let filtered = Selection {
            filters: vec!["stop".into(), "top".into()],
            ..Selection::default()
        };
        assert_eq!(
            names(&filtered),
            [
                ("lifecycle::stop_start".into(), Run),
                ("top_level".into(), Run)
            ]
        );

        let include = Selection {
            filters: vec!["lifecycle".into()],
            include_ignored: true,
        };
        assert_eq!(
            names(&include),
            [
                ("lifecycle::restart_later".into(), Run),
                ("lifecycle::stop_start".into(), Run)
            ]
        );
    }

    #[test]
    fn validate_rejects_ambiguous_names() {
        assert!(validate(TESTS).is_ok());
        let duplicate = [test("a::m", "t", false), test("b::m", "t", false)];
        let error = validate(&duplicate).unwrap_err();
        assert!(error.contains("two tests are named m::t"), "{error}");
        let reserved = [test("suite", "run", false)];
        let error = validate(&reserved).unwrap_err();
        assert!(error.contains("name of a subcommand"), "{error}");
        assert!(validate(&[test("suite::m", "run", false)]).is_ok());
    }
}
